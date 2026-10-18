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
tools/worldmap      builds the dashboard's world map from Natural Earth
```

Both binaries use only the Go standard library.

## Agent

The agent runs as root with a reduced capability set. It never listens on a
socket and runs only these external programs: `journalctl`, `iptables-save`,
`apt list --upgradable`, `sshd -T`, `nft list ruleset` (or `iptables -S INPUT`), for response actions that are enabled in
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
| SUID and capabilities | walk of local filesystems (not container trees), `security.capability` xattrs, owners from `/var/lib/dpkg/info/*.list`, own inventory in `suid.json` | 6 hours, temp directories 5 minutes |
| Package integrity | MD5 against `/var/lib/dpkg/info/*.md5sums` for programs, PAM modules and core libraries, own SHA-256 inventory in `integrity.json`, rehash only when inode, size or ctime changed; skipped while dpkg runs, findings confirmed after 10 minutes | 6 hours |
| Kernel | `/proc/modules`, `/sys/module/*/initstate`, `/proc/sys/kernel/tainted`, own baseline in `kernel.json` | `scan_seconds` |
| Hardening | `sshd -T` (configuration files as fallback), `/etc/shadow`, `/proc/sys`, owners and modes of files that decide what root runs, `nft list ruleset`, AppArmor/SELinux status | 6 hours |
| Certificates | Let's Encrypt `live/*/fullchain.pem`, `ssl_certificate` in nginx and `SSLCertificateFile` in Apache configuration, `tls_certs` | 6 hours |
| Backups | newest file of each `backups` location | 6 hours |
| Exposed secrets | world-readable files below `secret_roots`, entering only directories every user can enter; files up to 512 KB, vendored code and package data skipped, own list in `secrets.json` | daily |
| SSH sessions | programs whose parent is a shell, sudo or su and whose parent chain or audit session (`/proc/<pid>/sessionid`) leads to the sshd process of a login; 300 per session and hour | continuous |
| Rarity | every program start (host mount namespace only), own lists in `rare.json`; package check against `/var/lib/dpkg/info/*.list` for new programs | continuous, after 7 days of learning |
| Traffic volume | `/proc/net/dev`, physical and VPN interfaces | hourly |
| Change contents | last copy of small text files from the watch list (not `shadow`, `gshadow`, SSH keys) in `content/`, at most 64 KB each and 8 MB in all; a change carries the changed lines with two lines of context, secrets replaced, at most 8 KB | with the file scan |
| Evidence snapshots | `/proc` (processes, the suspect's program, parents, open files, mapped files, names of its environment variables), `/proc/net`, `/run/utmp`, `/proc/modules`, `journalctl -n 60`; on the agent's strongest signals at once, otherwise when the server asks; at most 12 per hour | on demand |
| Packages | source packages and versions from `/var/lib/dpkg/status`, sent to the server for `vuln_lookup` | on change, at least daily |
| Application dependencies | packages and versions from `package-lock.json`, pinned `requirements.txt` and `go.mod` below `app_roots`, read as streams and only when changed | every 3 hours, sent on change, at least daily |
| eBPF | `bpf(BPF_PROG_GET_NEXT_ID)` and `BPF_OBJ_GET_INFO_BY_FD`, hooking program types only, own list in `bpf.json` | `scan_seconds` |

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

`state.json` holds agents, alerts, canaries, enrollment tokens, known
login sources, incidents, suppressions, saved searches, response actions and
self tests. `users.json` holds dashboard users and is reread on every login,
so `vigil-server user add` works while the server runs. Both are written
atomically.

### Threat data

With `vuln_lookup`, `hash_intel`, `threat_intel` and `geoip`, the server
downloads public data (security trackers, malware hashes, block lists, DB-IP
Lite) into `data_dir/vuln`, `intel` and `geo` and matches it locally. Nothing
about the hosts leaves the server. Downloads are size-limited and replace
the copy in memory only once they have been read without errors; when a
download fails, the server keeps working with the copy it has and shows the
error on the settings page.

### Attack statistics

The attackers page reads per-day summaries in `data_dir/attacks` instead of
the whole log. Today is rebuilt from the log on start, past days are written
once and kept for `retention_days`, at most 30. The summaries are derived
data: deleting the directory loses nothing, they are rebuilt from the log.

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
| `file.added`, `file.changed`, `file.removed` | `path`, `category`, (`hash`, `old_hash`, `mode`, `old_mode`, `uid`, `old_uid`, `size`, `diff`, `diff_truncated`, `diff_note`) |
| `session.exec` | `sshd_pid`, `user`, `ip`, `pid`, `ppid`, `uid`, `exe`, `cmdline`, `cwd`, `parent_comm` |
| `session.dropped` | `sshd_pid`, `user`, `count` |
| `process.rare`, `process.rare_child` | `pid`, `uid`, `exe`, `comm`, `cmdline`, `parent_comm`, `parent_exe`, `cwd` |
| `net.volume` | `rx_bytes`, `tx_bytes`, `seconds` |
| `forensics.snapshot` | `trigger`, `pid`, `hostname`, `processes`, `connections`, `sessions`, `modules`, `journal`, `seconds`, `sha256`, (`target`, `request`, `alert`, `error`, `processes_truncated`, `connections_truncated`) |
| `user.added`, `user.removed` | `user`, `uid` |
| `user.uid_changed` | `user`, `uid`, `old_uid` |
| `port.opened`, `port.closed` | `key`, `proto`, `addr`, `port`, `scope`, `via`, (`process`, `target`) |
| `port.snapshot` | `ports` (list) |
| `canary.opened` | `canary_id`, `path`, `pid`, (`exe`, `comm`, `cmdline`, `uid`, `loginuid`, `sessionid`) |
| `canary.placed`, `canary.removed`, `canary.tampered`, `canary.error` | `canary_id`, `path`, (`type`, `hash`, `problem`, `error`) |
| `log.spoofed` | `identifier`, `comm`, `uid`, `message` |
| `process.exec` | `pid`, `ppid`, `uid`, `exe`, `comm`, `cmdline`, `cwd`, `parent_exe`, `parent_comm`, `signals` (list: `tmp_exe`, `deleted_exe`, `shell_socket`, `service_shell`, `cmd_reverse_shell`, `cmd_download_exec`, `cmd_decode_exec`, `cmd_miner`, `memfd_exe`, `ld_preload`), (`ld_preload`) |
| `process.rate_limited` | `dropped` |
| `net.connection` | `remote_ip`, `remote_port`, `local_port`, `process`, `exe`, `uid`, `private` |
| `web.activity` | `log`, `ip`, `requests`, `status_2xx` … `status_5xx`, `probes`, `exploit_kinds` (list), `exploits_ok`, `shells`, `logins`, `samples` (list), `user_agent` |
| `system.updates` | `pending`, `security`, `security_packages` (list), `security_oldest_days`, `reboot_required`, (`reboot_days`), `reboot_packages`, `kernel_running`, `kernel_newest`, `unattended_upgrades`, `lists_age_days` |
| `file.suid` | `path`, `mode`, `bits`, `uid`, `gid`, `where` (`tmp`, `home`, `system`), `dangerous_caps`, (`caps`, `package`, `pkgdb`, `changed_after_install`, `baseline`, `old_mode`, `old_caps`) |
| `file.suid_removed` | `path` |
| `suid.scan` | `files`, `roots`, `seconds` |
| `integrity.mismatch` | `path`, `package`, `version`, `reason`, `sha256`, `size`, `critical`, (`expected_md5`, `md5`, `old_sha256`) |
| `integrity.unowned` | `path`, (`sha256`, `size`, `mode`) |
| `integrity.scan` | `files`, `suspect`, `unowned`, `first`, `seconds` |
| `integrity.many` | `count` |
| `posture.report` | `checks` (`check`, `key`, `ok`, `value`, `want`), `certs` (`path`, `subject`, `names`, `issuer`, `not_after`, `days`, `self_signed`, `error`), `backups` (`name`, `path`, `newest`, `modified`, `age_hours`, `max_age_hours`, `size`, `ok`, `problem`) |
| `secret.exposed` | `path`, `kind`, `line`, `fingerprint` (first 6 bytes of SHA-256 of the secret), `uid`, `mode`, (`baseline`) |
| `secrets.scan` | `files`, `findings`, `seconds` |
| `system.packages` | `os_id`, `os_version`, `os_codename`, `packages` (pairs of source package and version), `hash` |
| `system.apps` | `manifests` (pairs of lock file path and package count), `packages` (ecosystem, name, version, index of the first lock file naming it), `hash`, (`truncated`) |
| `kernel.bpf_loaded` | `id`, `type`, `name`, `tag`, `uid`, (`baseline`) |
| `kernel.baseline` | `modules`, `tainted`, `out_of_tree` (list of `name (flags)`) |
| `kernel.module_loaded` | `name`, `taint`, `size` |
| `kernel.module_unloaded`, `kernel.module_hidden` | `name` |
| `kernel.tainted` | `added`, `tainted` (flag letters), `value` |
| `agent.started` | `version`, `hostname`, `canary_roots` |
| `agent.stopping`, `agent.dropped`, `agent.warning`, `agent.config_rejected` | details of the agent's own state |
