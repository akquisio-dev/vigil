# Configuration

Both programs read one JSON file. Unknown keys are ignored, missing keys take
the defaults below.

## Agent: `/etc/vigil/agent.json`

```json
{
  "server": "http://10.0.0.1:8471",
  "state_dir": "/var/lib/vigil-agent",
  "interval_seconds": 30,
  "scan_seconds": 60,
  "canary_roots": ["/root", "/home", "/opt", "/srv", "/var/backups"],
  "canary_ignore_exe": []
}
```

| Key | Default | Meaning |
|---|---|---|
| `server` | from enrollment | URL of the agent API |
| `state_dir` | `/var/lib/vigil-agent` | identity key and last known state |
| `interval_seconds` | 30 | how often a batch is sent; an empty batch is the heartbeat |
| `scan_seconds` | 60 | how often files, ports and canaries are checked |
| `watch_files` | built-in list | replaces the list of watched files (globs) |
| `extra_watch` | none | adds globs to the watch list |
| `canary_roots` | none | directories the dashboard may place canaries in; empty disables canaries |
| `canary_ignore_exe` | none | executables whose canary opens are not reported |
| `ssh` | true | read SSH and sudo entries from the journal |
| `ports` | true | watch listening sockets |
| `docker` | true | read Docker NAT publications with `iptables-save`; ask the Docker API on `/var/run/docker.sock` (GET requests only) which containers run, to name the container in findings from inside one and to send an overview of the containers when it changes |
| `processes` | true | watch program starts and report suspicious ones |
| `outbound` | true | report new outbound TCP destinations with their process |
| `suid` | true | find SUID/SGID programs and files with capabilities (all local filesystems every 6 hours, temp directories every 5 minutes) |
| `integrity` | true | compare programs, PAM modules and core libraries with their Debian package checksums (every 6 hours; Debian and Ubuntu only) |
| `bpf` | true | report eBPF programs that can hook the kernel or the network path |
| `kernel` | true | watch kernel modules (new, out of tree, hidden from `/proc/modules`) and kernel taint flags |
| `updates` | true | report pending (security) updates and pending reboots, Debian and Ubuntu |
| `posture` | true | hardening checks, TLS certificates and backups (every 6 hours), see below |
| `posture_skip` | none | checks not to run, by name (`"firewall"`) or name and key (`"sysctl:kernel.yama.ptrace_scope"`) |
| `tls_certs` | none | extra certificate files (globs), on top of Let's Encrypt and what nginx and Apache serve |
| `backups` | none | backup locations to watch, see below |
| `secrets` | true | look for private keys, tokens and passwords in files every user can read (daily) |
| `secret_roots` | `/etc`, `/home`, `/root`, `/srv`, `/opt`, `/var/www`, `/var/backups`, `/var/lib`, `/tmp`, `/var/tmp` | replaces the directories searched for exposed secrets |
| `sessions` | true | record commands typed in SSH sessions, see [Operations](operations.md#ssh-sessions) |
| `rarity` | true | report new programs and new children of services after the learning period |
| `rare_learn_days` | 7 | learning period for `rarity` |
| `rare_parents` | none | more process names whose children are learned |
| `rare_ignore` | none | more path parts whose programs are not learned; build outputs (`/.cache/`, `/go-build`, `/node_modules/`, `target/debug`, `target/release`) are left out already |
| `volume` | true | report bytes sent and received per hour |
| `metrics` | true | report CPU, memory, disk and network load once a minute, with the busiest processes (program only, never the command line) and the TCP peers, for the Hosts tab |
| `yara` | true | accept YARA rules from the server and scan suspicious and new programs and new programs in temp directories (every 5 minutes) |
| `forensics` | true | take evidence snapshots (read only), see [Operations](operations.md#investigating) |
| `quarantine` | false | also copy the suspect program into `state_dir/quarantine` (root only, 30 days, 512 MB at most) |
| `packages` | true | send the installed package list to the server for `vuln_lookup` |
| `apps` | true | send the dependencies named in lock files (`package-lock.json`, `requirements.txt` with `==` pins, `go.mod`) to the server for `vuln_lookup`; every 3 hours, sent when changed. `node_modules`, `.git`, caches and test data are skipped, as are other filesystems |
| `app_roots` | `/opt`, `/srv`, `/var/www`, `/home`, `/root` | replaces the directories searched for lock files (8 levels deep) |
| `web_logs` | none | access logs to watch, see below |
| `response` | off | allow response actions from the dashboard, see below |
| `self_update` | false | let admins update this agent from the dashboard to a newer signed release, see [Operations](operations.md#agents-from-the-dashboard) |
| `selftest` | true | accept self tests from the server, see [Operations](operations.md#self-test) |
| `max_queue` | 5000 | events kept while the server is unreachable |
| `fallback` | none | a notifier the agent uses itself when it cannot reach the server, see [Watching the server from outside](#watching-the-server-from-outside) |
| `fallback_minutes` | 15 | how long the server must be unreachable before `fallback` is told (at least 5) |

Everything that limits what the server may ask of an agent lives in this file
and only here. The dashboard cannot widen `canary_roots`.

### Hardening, certificates and backups

The agent checks every six hours:

| Check | Fails when |
|---|---|
| `ssh_root_login` | root may log in with a password |
| `ssh_password` | sshd accepts passwords (or keyboard-interactive with PAM) |
| `ssh_empty_password` | `PermitEmptyPasswords yes` |
| `empty_password` | an account with a login shell has no password |
| `aslr` | `kernel.randomize_va_space` is not 2 |
| `sysctl` | `kptr_restrict`, `dmesg_restrict`, `yama.ptrace_scope`, `unprivileged_bpf_disabled`, `protected_symlinks`, `protected_hardlinks`, `suid_dumpable`, `accept_redirects`, `accept_source_route` or `tcp_syncookies` weaker than the default |
| `permissions` | `/etc/shadow`, sudoers, sshd, PAM, cron, systemd units, root's SSH keys or the system `PATH` directories writable by others (or owned by another user), any world-writable file in `/etc` |
| `firewall` | no input chain drops or rejects anything |
| `mac` | neither AppArmor nor SELinux is active |

Certificates are found by themselves (Let's Encrypt, nginx, Apache); add
others with `tls_certs`. Backups are only watched when you list them:

```json
"backups": [
  {"name": "database", "path": "/var/backups/db/*.sql.gz", "max_age_hours": 26, "min_bytes": 100000},
  {"name": "offsite", "path": "/srv/restic/snapshots", "max_age_hours": 30}
]
```

`path` is a glob; a matching directory counts by its newest file. A failing
check alerts once and the alert closes itself when the check passes again.

### Response actions

```json
"response": {
  "enabled": true,
  "allow": ["block_ip", "kill_session", "kill_process", "remove_key"],
  "never_block": ["10.90.0.0/24", "192.0.2.50"]
}
```

Off unless `enabled` is true. `allow` limits the types (empty: all).
`isolate_allow` lists addresses or networks that stay reachable while the
host is isolated (put the admins' VPN there); `never_lock` lists accounts
that are never locked.
`block_ip` refuses loopback and local addresses, the vigil server and
everything in `never_block`; put your admins' addresses and VPN there.
See [Operations](operations.md#response-actions) for what each action does.

### Web server logs

```json
"web_logs": [
  { "path": "/var/log/nginx/access.log", "login_paths": ["/api/login", "/wp-login.php"] }
]
```

`format` is `combined` (the nginx and Apache default) or `json` with the keys
`remote_addr`, `request_method`, `request_uri`, `status` and
`http_user_agent`. The agent follows the file across rotation and sends, once
a minute, one summary per address that probed for known files, matched an
attack signature, requested a web shell path or posted to a `login_paths`
entry often. Normal visitors are not reported.

Behind a proxy or CDN, make the web server log the client's address (for
nginx: `set_real_ip_from` and `real_ip_header`), or every request looks like
it came from the proxy.

### The built-in watch list

`/etc/passwd`, `shadow`, `group`, `gshadow`, `sudoers` and `sudoers.d`,
`sshd_config` and `sshd_config.d`, `authorized_keys` of root and every user in
`/home`, cron files and crontabs, units in `/etc/systemd/system`,
`ld.so.preload`, `pam.d`, `/etc/profile`, `profile.d`, `bash.bashrc`, root's
`.bashrc` and `.profile`, `rc.local` and `/etc/hosts`.

## Server: `/etc/vigil/server.json`

```json
{
  "listen": "127.0.0.1:8470",
  "agent_listen": "10.0.0.1:8471",
  "agent_url": "http://10.0.0.1:8471",
  "data_dir": "/var/lib/vigil",
  "public_url": "https://soc.example.com",
  "language": "en",
  "trust_proxy": true,
  "retention_days": 90,
  "deadman_seconds": 120,
  "anchor_daily": true,
  "notifiers": []
}
```

| Key | Default | Meaning |
|---|---|---|
| `listen` | `127.0.0.1:8470` | dashboard |
| `agent_listen` | same as `listen` | agent API |
| `agent_url` | | shown in the enrollment command in the dashboard |
| `data_dir` | `/var/lib/vigil` | event log, state, users, server key |
| `public_url` | | base for links in notifications |
| `language` | `en` | language of notifications, `en` or `de` |
| `cookie_secure` | true | set false only for plain HTTP on loopback during development |
| `trust_proxy` | false | take the client address from `X-Forwarded-For` |
| `retention_days` | 90 | days of event log to keep |
| `deadman_seconds` | 120 | silence before an agent counts as gone |
| `recent_events` | 20000 | events held in memory for the dashboard |
| `session_hours` | 12 | dashboard session lifetime |
| `anchor_daily` | false | post the head of the event chain to all notifiers once a day |
| `selftest_days` | 7 | run a self test on every host this often and send the result to all notifiers; `-1` turns the schedule off |
| `heartbeat_url` | | fetched every minute while the server is healthy, for an outside dead man's switch |
| `backup` | none | sealed backups of the server, see [Operations](operations.md#backups) |
| `notifiers` | none | see below |
| `notify_group_minutes` | 10 | collect the follow-up alerts of an incident into one message this often; `-1` sends every alert on its own, see [below](#one-message-per-incident) |
| `summary_time` | none | send a [daily summary](#daily-summary) at this time (`"07:30"`, the server's local time) |
| `brand` | none | your own name and logo, see below |
| `rules_dir` | none | directory with [custom rules](custom-rules.md) |
| `vuln_lookup` | false | match the package lists of Debian and Ubuntu hosts with the distributions' security data (Canonical OVAL per release, about 10 MB; the Debian security tracker, about 14 MB) and CISA's catalogue of exploited vulnerabilities, daily and only when changed. For the lock files agents report (`apps`), also OSV.dev's dumps for npm, PyPI and Go (only the ecosystems in use; npm is about 220 MB, read as a stream into an index of about 5 MB once a week, then brought up to date record by record every 3 hours). Only plain downloads, nothing about the hosts is sent |
| `abusech_key_file` | none | file with a free [abuse.ch Auth-Key](https://auth.abuse.ch/). Since October 2026 ThreatFox (`threat_intel`, `hash_intel`) and MalwareBazaar (`hash_intel`) only answer with a key; without one these sources are skipped and shown as needing it. The key is read on every refresh (no restart needed) and never shown in logs, the dashboard or alerts. Keep the file `0640 root:vigil` |
| `hash_intel` | false | match the SHA-256 of suspicious and new programs against abuse.ch MalwareBazaar and ThreatFox (full list weekly, about 45 MB, newest every six hours; about 10 MB in memory). Only downloads |
| `yara_dir` | none | directory with YARA rules (`*.yar`, `*.yara`, at most 256 KB together) the agents scan programs with; starter rules in `deploy/examples/yara` |
| `sigma_dir` | none | directory with Sigma rules (`*.yml`, also in subdirectories) for Linux process, network and file events |
| `four_eyes` | none | response action types a second admin must approve, `"*"` for all, see [Operations](operations.md#four-eyes) |
| `playbooks` | none | response actions started on their own by alerts, see [Operations](operations.md#playbooks) |
| `forward` | none | send events and alerts to syslog, HTTP or a file, see below |
| `map_home` | none | `[latitude, longitude]` of the hosts, for the live arcs on the attack map, for example `[50.1, 8.7]`; a rough location is enough |
| `geoip` | false | show the country and network of attacking addresses: the free DB-IP Lite country and AS databases (CC BY 4.0, about 12 MB) are downloaded once a month and looked up on the server, about 16 MB in memory. Enabling it accepts the [DB-IP Lite licence](https://db-ip.com/db/lite.php); the dashboard and reports link to DB-IP as it asks. For servers without internet access, place `country.csv.gz` and `asn.csv.gz` from DB-IP in `data_dir/geo` |
| `threat_intel` | false | download public block lists (abuse.ch Feodo Tracker and ThreatFox, Spamhaus DROP, Tor exits) twice a day and match outbound connections against them. Only plain downloads, nothing about this installation is sent |

Only enable `trust_proxy` when the dashboard listener is reachable through the
proxy alone. Otherwise clients can choose their own address for rate limits
and the audit log.

## Your own name and logo

```json
"brand": {
  "name": "Example vigil",
  "logo": "/etc/vigil/brand/logo.svg",
  "icon": "/etc/vigil/brand/icon.svg"
}
```

`logo` is a horizontal SVG with the mark on the left. The collapsed sidebar
shows only its left square, the expanded sidebar and the login page the whole
logo. It is placed inline in the page, so `fill="currentColor"` follows light
and dark mode. `icon` is the browser tab icon. Files with scripts, event
handlers or external references are refused and the vigil logo is used
instead; the server log says why. Restart the server after changing them.

## Notifiers

Each notifier has a `type`, a `name` and a `min_severity` (`info`, `low`,
`medium`, `high`, `critical`; default `high`). Names must be unique; without
one, vigil names it after its type (`discord-1`). An incomplete notifier stops
the server at start, so typos show up during installation.

`"groups": ["Moritz"]` limits a notifier to alerts of hosts in one of these
host groups, for example a Discord channel of the people who run them. Such a
notifier gets nothing that concerns the whole network: no daily summary and
no message about the server itself.

After every change, check each channel from the server:

```
vigil-server notify test -config /etc/vigil/server.json
vigil-server notify test -config /etc/vigil/server.json -name phone
```

The command prints `ok` or `FAIL` with the reason per notifier and exits
non-zero if one failed. The dashboard (Settings) shows when each notifier last
delivered and its last error, and has the same test button for admins. This
status is kept in memory and starts empty after a server restart.

When a notifier loses a message after three attempts, vigil raises
`notify.failed` and sends it through the **other** notifiers, whatever their
`min_severity`. Configure at
least two different channels, for example a chat and a phone push, so a
revoked webhook does not leave you blind. Rate limits (HTTP 429) are retried
after the delay the service asks for.

Notifier URLs and tokens are secrets. Errors in the log and the dashboard
name only the host, never the URL.

### One message per incident

Alerts on one host that belong together form an
[incident](operations.md#incidents). The first alert of an incident is sent at
once, and so is every later alert that is more severe than anything sent for
the incident so far, so a reverse shell after a suspicious login is never held
back. The other alerts that join the incident are collected and sent as one
message every `notify_group_minutes` (default 10), with the most frequent
titles and a link to the incident. Alerts outside incidents, failed
notifiers, self tests and chain anchors are always sent on their own.
Forwarding to a SIEM is not grouped.

The grouping is kept in memory; after a server restart, the next alert of an
open incident is sent on its own again.

### Daily summary

With `summary_time`, vigil sends one message a day about the whole fleet:
alerts of the last 24 hours by severity and the most frequent rules, open
alerts and incidents, hosts that are not reporting, failed self tests,
exploited and fixable vulnerabilities (with `vuln_lookup`), attackers since
the day before with the countries most of them came from, notifiers that fail
and problems with the event log. It goes to every notifier, whatever its
`min_severity`; set `"summary": false` on a notifier to leave it out, for
example a phone push channel. A summary that does not arrive is a sign that
the server is down.

Admins can preview the summary and send it at once from Settings.

### Discord

```json
{ "type": "discord", "name": "soc", "min_severity": "high",
  "url": "https://discord.com/api/webhooks/...",
  "mention": "<@&ROLE_ID>", "mention_min_severity": "critical" }
```

Create the webhook in a private channel (Channel settings, Integrations,
Webhooks). Without `mention`, messages never ping anyone. With it, alerts of
`mention_min_severity` (default `critical`) and above ping that role
(`<@&ROLE_ID>`), user (`<@USER_ID>`), `@here` or `@everyone`; with Discord's
mobile app this is a phone notification.

### Slack, Mattermost, Rocket.Chat

```json
{ "type": "slack", "name": "chat", "min_severity": "high",
  "url": "https://hooks.slack.com/services/..." }
```

Uses the incoming webhook format that all three understand. Text from agents
is escaped, so it cannot form links or mentions.

### ntfy (push to your phone)

```json
{ "type": "ntfy", "name": "phone", "min_severity": "high",
  "url": "https://ntfy.sh/a-long-random-topic-name",
  "token": "tk_..." }
```

[ntfy](https://ntfy.sh) delivers push notifications to the ntfy app on Android
and iOS, and can be self-hosted. `url` is the topic URL, `https://host/topic`; a
server published under a subpath is not supported. On the public server
anyone who knows the topic can read it, so pick a long random name, or use an
access token (`token`) on a reserved topic or your own server. Critical alerts
are sent with the highest priority, which most phones show even in
do-not-disturb.

### Telegram

```json
{ "type": "telegram", "name": "telegram", "min_severity": "high",
  "token": "123456:ABC...", "chat_id": "-1001234567890" }
```

Create a bot with @BotFather, add it to a group or start a chat with it, and
use that chat's id.

### Webhook

```json
{ "type": "webhook", "name": "pager", "min_severity": "critical",
  "url": "https://example.com/hooks/vigil" }
```

vigil posts JSON with `severity`, `title`, `host`, `technique`, `link` and
`text`. Use it for anything not listed here (PagerDuty or Opsgenie through a
small relay, n8n, Home Assistant).

### Mail

```json
{ "type": "smtp", "name": "mail", "min_severity": "critical",
  "smtp_host": "smtp.example.com", "smtp_port": 587,
  "smtp_user": "alerts@example.com", "smtp_pass": "...",
  "from": "alerts@example.com", "to": ["oncall@example.com"] }
```

Port 587 uses STARTTLS, port 465 implicit TLS. Credentials are never sent over
an unencrypted connection to a remote host.

## Watching the server from outside

The server watches the agents, but nothing inside vigil can notice that the
server itself is gone. Set `heartbeat_url` to a check at an outside dead man's
switch service, which alerts you when the pings stop:

```json
"heartbeat_url": "https://hc-ping.com/your-check-uuid"
```

Any service that accepts a periodic GET works: healthchecks.io (free tier,
self-hostable), Uptime Kuma (push monitor), Better Stack, Cronitor. Set the
expected period to one minute and a grace time of a few minutes.

Without an outside service, let the agents watch the server. An agent with
`fallback` sends one message straight to that channel when the server has
not taken a batch for `fallback_minutes`, and one when it does again:

```json
"fallback": {"type": "discord", "url": "https://discord.com/api/webhooks/..."},
"fallback_minutes": 15
```

Check the channel right away with `vigil-agent fallback test`.
`fallback` takes the same fields as a server notifier (`discord`, `slack`,
`ntfy`, `telegram`, `webhook`, `smtp`). It covers a server machine that is
off, a broken network path between host and server, and a server that refuses
the agent. It does not cover a server that takes batches but is otherwise
broken; `heartbeat_url` does. Put it on a host other than the server's own,
and keep `fallback_minutes` longer than an update of the server by hand, or
every release sends two messages. The webhook URL then lives on that host
too; a webhook that may only post into one channel limits what it gives away.

The server pings once a minute, and only while it is healthy. It stops pinging
when the event chain fails verification, the event log or the data directory
cannot be written, or the server's state stays locked for more than ten
seconds. A crashed, hung or tampered server therefore ends in the same outside
alarm. The reason is written to the server log once.

With `anchor_daily`, the head of the event chain is posted to your notifiers
every day, which leaves a copy of the log's state outside the machine.

## Sources and allied networks

Two vigil networks can exchange what they see of attackers, read-only in
both directions. Each side decides on its own what the other may fetch.

```json
"federation": {
  "listen": "10.90.0.2:8472",
  "name": "akquisio",
  "never": ["198.51.100.0/24"]
}
```

- `listen` serves the feed, and only the feed, to partners. Bind it to a
  VPN address (WireGuard), never to a public one. Without it no feed is
  served; fetching other networks works anyway. Give partners their own
  WireGuard interface or subnet, not the one your agents use, and let the
  firewall pass only the partner's address to this port: a partner in the
  agents' network could reach the agent API and every other service there.
  `X-Forwarded-For` is ignored on this listener.
- `name` is how this network calls itself in its feed.
- `never` lists addresses and networks that are never named in a feed and
  never flagged from a source: offices, VPN exits, monitoring services. The
  addresses the agents connect from are always added.

In the dashboard, **Sources** (admins):

- **What we share**: one share per partner with its own token (shown once,
  only its hash is kept), the categories (SSH logins, web attacks, web
  login attempts, web shell requests), counts and times or addresses only,
  tried SSH user names or not, the period, a minimum number of attempts, and
  the partner's own networks. The preview shows exactly what the partner
  would get. Whatever is chosen, a feed never carries host names, agent
  IDs, our own or internal addresses, addresses that logged in, user names
  that exist on our hosts, paths, processes or alert texts: the feed format
  has no fields for them. Never named either: the addresses the agents
  connect from and listen on, every address that ever logged in, and
  `federation.never`.
- **What we fetch**: the partner's feed address, its token and its
  fingerprint (shown under Sources on the partner's dashboard). The feed is
  signed with `data_dir/federation.key`, a key used for nothing else, and
  refused unless it matches the pinned fingerprint. Sources are fetched
  every 15 minutes, redirects are not followed, a feed is at most 16 MB and
  50,000 addresses, and reports are kept for 1 to 90 days.

Reports are untrusted: they never reach the threat lists of
`threat_intel`, and playbooks never act on them. A source of trust
*medium* or *high* raises `source.login` (a successful login from a
reported address) and `source.outbound` (a host connected to one); *low*
only feeds the analytics: overlap, who saw an attacker first, lead time,
time of day and the attackers most sources report.

## Forwarding

```json
"forward": [
  {"name": "graylog", "type": "syslog", "address": "logs.example.com:6514", "protocol": "tls"},
  {"name": "elastic", "type": "http", "url": "https://ingest.example.com/vigil", "headers": {"Authorization": "Bearer ..."}, "what": "alerts", "min_severity": "high"},
  {"name": "vector", "type": "file", "path": "/var/log/vigil/events.jsonl", "what": "events"}
]
```

| Key | Meaning |
|---|---|
| `type` | `syslog` (RFC 5424, facility local0, the message is JSON; UDP, TCP with octet counting, or TLS), `http` (POST of JSON lines in batches of up to 500 every five seconds) or `file` (JSON lines; reopened after log rotation) |
| `what` | `events`, `alerts` or `all` (default) |
| `min_severity` | lowest alert severity to forward |
| `headers` | extra HTTP headers, for tokens; never written to logs |

Every line is `{"vigil": "event", "record": {...}}` or `{"vigil": "alert", "alert": {...}, "params": {...}}`. Evidence snapshots are forwarded without their process and connection lists. Each target has a queue of 10 000 items; a target that fails for ten minutes raises `forward.failed`, and what does not fit is dropped and counted on the rules page.

## YARA rules

vigil reads the part of the YARA language most Linux rules use: text strings
(`nocase`, `wide`, `ascii`, `fullword`), hex strings with `??`, nibble
wildcards, jumps `[n-m]` and alternatives, regular expressions (Go syntax,
for text), and conditions with `and`, `or`, `not`, `any of`, `all of`,
`N of`, `them`, `$a at N`, `$a in (a..b)`, `#a`, `filesize`, `uint8/16/32`
(also `be`) and the `KB`/`MB` suffixes. Modules (`import "pe"`), `xor` and
`base64` strings, private and global rules and for-loops are not supported;
such rules are skipped and listed on the rules page. Files above 16 MB are
hashed but not scanned. vigil never scans its own programs, which contain
the strings many rules look for.

## Sigma rules

Rules with `logsource` `product: linux` and the categories
`process_creation`, `network_connection`, `file_event`, `file_change` or
`file_delete` are matched; rules for other log sources load but stay
inactive. Fields: `Image`, `CommandLine`, `ParentImage`,
`CurrentDirectory`, `User`, `ProcessId`, `ParentProcessId` (processes),
`DestinationIp`, `DestinationPort`, `Image` (connections), `TargetFilename`
(files). Modifiers `contains`, `startswith`, `endswith`, `all`, `re`,
`cidr`, `lt`, `lte`, `gt`, `gte`, `windash`; conditions with `and`, `or`,
`not`, parentheses, `1 of x*`, `all of x*`, `1 of them`, `all of them`.
Aggregations are not supported. vigil sees only suspicious program starts,
commands typed in SSH sessions and new programs, not every program start,
so process rules apply to those. Of the 211 Linux rules in the SigmaHQ
repository, 122 load as active, 75 are for log sources vigil has no events
for (auditd, syslog) and 14 use fields vigil does not have. Start with the
rules of level `high` and `critical`; low ones like system discovery fire on
ordinary admin commands in SSH sessions.

