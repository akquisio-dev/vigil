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
| `docker` | true | read Docker NAT publications with `iptables-save` |
| `processes` | true | watch program starts and report suspicious ones |
| `outbound` | true | report new outbound TCP destinations with their process |
| `updates` | true | report pending (security) updates and pending reboots, Debian and Ubuntu |
| `web_logs` | none | access logs to watch, see below |
| `response` | off | allow response actions from the dashboard, see below |
| `max_queue` | 5000 | events kept while the server is unreachable |

Everything that limits what the server may ask of an agent lives in this file
and only here. The dashboard cannot widen `canary_roots`.

### Response actions

```json
"response": {
  "enabled": true,
  "allow": ["block_ip", "kill_session", "kill_process", "remove_key"],
  "never_block": ["10.90.0.0/24", "192.0.2.50"]
}
```

Off unless `enabled` is true. `allow` limits the types (empty: all four).
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
| `heartbeat_url` | | fetched every minute while the server is healthy, for an outside dead man's switch |
| `notifiers` | none | see below |
| `brand` | none | your own name and logo, see below |
| `rules_dir` | none | directory with [custom rules](custom-rules.md) |
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

After every change, check each channel from the server:

```
vigil-server notify test -config /etc/vigil/server.json
vigil-server notify test -config /etc/vigil/server.json -name phone
```

The command prints `ok` or `FAIL` with the reason per notifier and exits
non-zero if one failed. The dashboard (Settings) shows when each notifier last
delivered and its last error, and has the same test button for admins.

When a notifier loses a message after three attempts, vigil raises
`notify.failed` and sends it through the **other** notifiers. Configure at
least two different channels, for example a chat and a phone push, so a
revoked webhook does not leave you blind. Rate limits (HTTP 429) are retried
after the delay the service asks for.

Notifier URLs and tokens are secrets. Errors in the log and the dashboard
name only the host, never the URL.

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
and iOS, and can be self-hosted. `url` is the topic URL. On the public server
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

The server pings once a minute, and only while it is healthy. It stops pinging
when the event chain fails verification, the event log or the data directory
cannot be written, or the server's state stays locked for more than ten
seconds. A crashed, hung or tampered server therefore ends in the same outside
alarm. The reason is written to the server log once.

With `anchor_daily`, the head of the event chain is posted to your notifiers
every day, which leaves a copy of the log's state outside the machine.
