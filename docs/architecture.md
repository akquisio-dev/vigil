# Architecture

This page is for people who want to review vigil. The code is small enough to
read in an afternoon; the [threat model](threat-model.md) says what it is
meant to withstand.

## Components

```
cmd/vigil-agent     host sensor
cmd/vigil-server    central node and dashboard
internal/proto      wire format, signing
internal/agent      collectors, canaries, sender
internal/server     ingestion, event log, rules, alerts, notifiers, dashboard API
internal/server/web dashboard (static HTML, CSS, JavaScript; no build step)
tools/gendocs       generates the rule catalogue
```

Both binaries use only the Go standard library.

## Agent

The agent runs as root with a reduced capability set. It never listens on a
socket and runs only these external programs: `journalctl`, `iptables-save`,
`apt list --upgradable`, for response actions that are enabled in
`agent.json` `nft`, and for the self test its own copy of `sleep` in `/tmp`.

| Collector | Source | Interval |
|---|---|---|
| SSH and sudo | `journalctl -f -o json`, resumed from a saved cursor | continuous |
| Files | SHA-256 of the watch list, symlinks by target | `scan_seconds` |
| Keys and accounts | parsed `authorized_keys` and `/etc/passwd` | `scan_seconds` |
| Ports | `/proc/net/{tcp,tcp6,udp,udp6}`, owners via `/proc/*/fd` | `scan_seconds` |
| Docker | DNAT rules in the `DOCKER` chain of `iptables-save -t nat` | `scan_seconds` |
| Canaries | fanotify `FAN_OPEN` marks, notification class only | continuous |
| Processes | kernel process events connector (netlink), details from `/proc/<pid>` | continuous |
| Outbound | established TCP sockets in `/proc/net/{tcp,tcp6}` that are not to a listening port | 10 seconds |
| Web logs | configured access logs, followed across rotation | continuous, one summary per minute |
| Updates | `apt list --upgradable`, `/var/run/reboot-required`, `/boot/vmlinuz-*` | 6 hours |

Program starts are only reported when something about them is suspicious
(see the `process.*` rules); everything else is dropped on the host, and at
most 60 reports per minute leave it. New outbound destinations are reported
once per network (/24 or /48) and port.

Journal entries are only trusted when journald's own `_COMM` and `_UID` fields
say they come from sshd or sudo running as root. `SYSLOG_IDENTIFIER` is chosen
by the sender and is not trusted.

The agent keeps its last known state in `state.json` and compares against it on
start, so changes made while it was not running are reported.

## Protocol

### Enrollment

1. An admin creates a token in the dashboard (random, stored as SHA-256, one
   use, one hour).
2. `vigil-agent enroll` creates an ed25519 key pair and sends the public key,
   hostname and token to `POST /api/agent/enroll`.
3. The server answers with the agent ID and its own ed25519 public key, which
   the agent pins.

### Batches

Every `interval_seconds`, the agent sends `POST /api/agent/events`:

```json
{
  "agent_id": "…",
  "seq": 1760600000000000000,
  "sent_at": "2026-10-16T07:51:24Z",
  "config_version": 3,
  "events": [ { "type": "ssh.login", "ts": "…", "data": { … } } ]
}
```

The header `X-Vigil-Signature` carries the ed25519 signature over the exact
body. The server rejects bad signatures and any `seq` not greater than the last
one, and raises `agent.forged` for both. An empty `events` list is the
heartbeat.

### Configuration

When the agent's `config_version` is behind, the response carries the new
configuration and a signature by the server key:

```json
{ "config_version": 4, "config": { "agent_id": "…", "version": 4,
  "canaries": [ { "id": "…", "type": "env", "path": "/root/.env.bak" } ] },
  "config_sig": "…" }
```

The configuration can only name canaries by type and path. The agent generates
the content and enforces its own limits; see [Canaries](canaries.md).

## Server

### Event log

Events are appended to one file per UTC day in `data_dir/events`. Each line
is

```json
{ "hash": "<sha256(prev + \"\\n\" + rec)>", "prev": "<hash of the line before>", "rec": { … } }
```

The chain runs across files. When old days are pruned, the last hash of the
removed file is written to `ANCHOR`, so the remaining chain still verifies.
Admin actions (logins, acknowledgements, canary changes, maintenance windows)
are written to the same chain.

### Rules and alerts

Each record from an agent passes through the rule set in
`internal/server/rules.go`. A finding becomes an alert, or raises the counter
of an open alert with the same key from the last 24 hours. New alerts go to the
notifiers whose `min_severity` they meet. Alert titles are rendered per
language from the stored parameters, which are stripped of control characters
before they can reach a mail header.

### State

`state.json` holds agents, alerts, canaries, enrollment tokens and known
login sources. `users.json` holds dashboard users and is reread on every login,
so `vigil-server user add` works while the server runs. Both are written
atomically.

### Dashboard

A single page without a build step. Every value from agents is inserted with
`textContent`, never as markup. The server sends a strict Content Security
Policy without inline scripts, cookies are HttpOnly and SameSite=Strict, and
every change needs a CSRF token bound to the session.

## Event types

What agents send, with the fields rules (and [custom rules](custom-rules.md))
can use. Fields in brackets are only present when known.

| Type | Fields |
|---|---|
| `ssh.login` | `user`, `ip`, `port`, `method`, `sshd_pid`, (`fingerprint`, `key_type`, `key_comment`, `key_file`) |
| `ssh.logout` | `user`, `ip`, `port`, `sshd_pid` |
| `ssh.failed` | `ip`, `count`, `users` (list), aggregated per address and interval |
| `sudo.command` | `user`, `tty`, `cwd`, `as`, `command` |
| `ssh.key_added`, `ssh.key_removed` | `file`, `fingerprint`, `key_type`, `comment` |
| `file.added`, `file.changed`, `file.removed` | `path`, `category`, (`hash`, `old_hash`, `mode`, `old_mode`, `uid`, `old_uid`, `size`) |
| `user.added`, `user.removed` | `user`, `uid` |
| `user.uid_changed` | `user`, `uid`, `old_uid` |
| `port.opened`, `port.closed` | `key`, `proto`, `addr`, `port`, `scope`, `via`, (`process`, `target`) |
| `port.snapshot` | `ports` (list) |
| `canary.opened` | `canary_id`, `path`, `pid`, (`exe`, `comm`, `cmdline`, `uid`, `loginuid`, `sessionid`) |
| `canary.placed`, `canary.removed`, `canary.tampered`, `canary.error` | `canary_id`, `path`, (`type`, `hash`, `problem`, `error`) |
| `log.spoofed` | `identifier`, `comm`, `uid`, `message` |
| `process.exec` | `pid`, `ppid`, `uid`, `exe`, `comm`, `cmdline`, `cwd`, `parent_exe`, `parent_comm`, `signals` (list: `tmp_exe`, `deleted_exe`, `shell_socket`, `service_shell`, `cmd_reverse_shell`, `cmd_download_exec`, `cmd_decode_exec`, `cmd_miner`) |
| `process.rate_limited` | `dropped` |
| `net.connection` | `remote_ip`, `remote_port`, `local_port`, `process`, `exe`, `uid`, `private` |
| `web.activity` | `log`, `ip`, `requests`, `status_2xx` … `status_5xx`, `probes`, `exploit_kinds` (list), `exploits_ok`, `shells`, `logins`, `samples` (list), `user_agent` |
| `system.updates` | `pending`, `security`, `security_packages` (list), `security_oldest_days`, `reboot_required`, (`reboot_days`), `reboot_packages`, `kernel_running`, `kernel_newest`, `unattended_upgrades`, `lists_age_days` |
| `agent.started` | `version`, `hostname`, `canary_roots` |
| `agent.stopping`, `agent.dropped`, `agent.warning`, `agent.config_rejected` | details of the agent's own state |
