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
| `max_queue` | 5000 | events kept while the server is unreachable |

Everything that limits what the server may ask of an agent lives in this file
and only here. The dashboard cannot widen `canary_roots`.

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
| `heartbeat_url` | | fetched every minute, for an outside watchdog |
| `notifiers` | none | see below |

Only enable `trust_proxy` when the dashboard listener is reachable through the
proxy alone. Otherwise clients can choose their own address for rate limits
and the audit log.

## Notifiers

Each notifier has a `type`, a `name` and a `min_severity` (`info`, `low`,
`medium`, `high`, `critical`; default `high`).

### Discord

```json
{ "type": "discord", "name": "soc", "min_severity": "high",
  "url": "https://discord.com/api/webhooks/..." }
```

Create the webhook in a private channel. The URL is a secret.

### Webhook

```json
{ "type": "webhook", "name": "pager", "min_severity": "critical",
  "url": "https://example.com/hooks/vigil" }
```

vigil posts JSON with `severity`, `title`, `host`, `technique`, `link` and
`text`.

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

The server watches the agents, but nothing inside vigil watches the server. Set
`heartbeat_url` to a check at an outside service (healthchecks.io or similar)
that alerts when the pings stop. With `anchor_daily`, the head of the event
chain is posted to your notifiers every day, which leaves a copy of the log's
state outside the machine.
