# vigil

A small security operations center for small server fleets.

vigil is for people who run one to a few dozen Linux servers and want real
detection without running Elasticsearch next to their workload. One agent per
host (a static binary, 10 to 20 MB of memory), one central server, no
external dependencies.

> Status: early. The pieces below work and are tested on Ubuntu 24.04, but
> the project has not been audited yet. Run it next to your existing
> controls, not instead of them.

## What it detects

| Area | Examples | ATT&CK |
|---|---|---|
| SSH access | logins with key name and source, password logins, logins with keys outside `authorized_keys`, first login from a new address, brute-force waves | T1078, T1098.004, T1110 |
| Persistence | changes to `authorized_keys`, cron, systemd units, sudoers, PAM, shell init files, `ld.so.preload` | T1098.004, T1053.003, T1543.002, T1548.003, T1556.003, T1546.004, T1574.006 |
| Processes | reverse shells, web servers and databases starting shells, download and run, crypto miners, programs from `/tmp`, from deleted files or **from memory only** (memfd), `LD_PRELOAD` injection | T1059.004, T1505.003, T1105, T1496, T1620, T1574.006 |
| Tampered software | **replaced `sshd`, `sudo`, `ps`, `ls`, PAM modules or `libc`/`liblzma`** (checked against Debian package checksums plus an own SHA-256 inventory), new programs in `/usr/bin` that no package installed | T1554 |
| Privilege escalation | new SUID/SGID programs and file capabilities, **SUID bits set on packaged programs after installation** (GTFOBins backdoors), root programs in temp directories | T1548.001 |
| Prevention | **known vulnerabilities in installed packages, especially those exploited in the wild** (distribution security data and CISA KEV, kernels included), weak SSH settings, accounts without password, weak kernel settings, unsafe permissions, missing firewall, certificates about to expire, backups that stopped arriving, **private keys, tokens and passwords that every user on the host can read** | T1190, T1552.001, T1490 |
| Malware | programs matched against **1.1 million known malware hashes** (MalwareBazaar, ThreatFox) and **YARA rules**; **Sigma rules** for process, network and file events | T1204.002 |
| Investigation | **incident reports for handing on or printing, with chain hashes as proof**, forwarding to syslog, HTTP or files for an existing SIEM, **SSH sessions with every command typed**, a query language over the whole log with export, **retro hunts when a threat list learns an address**, unusual programs, children, login hours and traffic, **timeline around every alert**, pivot pages for addresses, users and file hashes across all hosts, **the changed lines** of configuration files, **evidence snapshots** taken the moment a reverse shell or similar starts (processes, sockets, sessions, the suspect program's hash, optional quarantine copy) | |
| Attackers | **who attacks from where**: country and network of every address on a world map, tried user names and paths, **campaigns** (one botnet instead of hundreds of addresses), **aimed attacks told apart from mass scanning**, logins from addresses that failed before, a report to print | T1110 |
| Accounts | new accounts, accounts that gain uid 0 | T1136.001, T1078.003 |
| Exposure | new listening ports, **Docker publications that bypass host firewalls like ufw** (read from the NAT table, not only from sockets) | |
| Canaries | decoy credentials, `.env` files, SSH keys and SQL dumps; any open is reported with process, user and parent chain | T1552.001, T1070.004 |
| Kernel | new kernel modules, out-of-tree or unsigned modules, **modules hidden from `/proc/modules`** (rootkits), new kernel taint flags, **eBPF programs that hook syscalls or packets** (eBPF rootkits) | T1547.006, T1014 |
| Defense evasion | agents that stop, restart or go silent (dead man's switch), forged or replayed agent traffic, fake `sshd`/`sudo` lines written to the journal by other processes, edits to the event log | T1562.001, T1557, T1070, T1565.001 |

Changes that happen while an agent is down are found on its next start,
because each agent compares against its last known state and resumes the
journal from its saved cursor. Every stop and every restart raises a high
alert with the length of the gap, whatever the agent says about it; planned
work is announced with a maintenance window in the dashboard, which is
recorded in the log.

Detections that never fire look like a quiet host, so vigil tests itself:
every week (and on demand) each agent leaves harmless marked traces that the
real sensors must catch, and the result goes to every notifier. Alerts reach
you through Discord, Slack, Mattermost, ntfy push, Telegram, webhooks or
mail; a channel that stops delivering raises an alert through the others,
and an outside heartbeat stops when the server is down or unhealthy.

## Design

```
 host A                host B
 vigil-agent           vigil-agent        outbound only, signed batches
     \                    /
      \   VPN or HTTPS   /
       v                v
          vigil-server  ─── hash-chained event log
               │        ─── rules → alerts → chat / push / webhook / mail
               │        ─── daily chain anchor to the notifiers
           dashboard (localhost, behind your TLS proxy)
```

Decisions that matter for trust:

- **Agents never listen.** They make outbound requests only. Each batch is
  signed with the agent's ed25519 key and carries a strictly increasing
  sequence number, so forged and replayed batches are rejected and alerted.
- **Canaries cannot be abused as a write primitive.** The dashboard only
  names a canary *type* and a path. The agent generates the content itself,
  accepts only paths below `canary_roots` from its *local* config, walks
  directories with `openat` and `O_NOFOLLOW`, never overwrites a file, never
  sets an exec bit, refuses names like `authorized_keys`, `.bashrc` or
  `*.service`, and deletes only the exact file it created. A compromised
  server can place a decoy, not a backdoor.
- **Notification-only fanotify.** Canary opens are observed with
  `FAN_CLASS_NOTIF`; vigil never sits in the path of a file open, so a hung
  agent cannot freeze anything.
- **The log is tamper-evident.** Every record is chained to the previous one
  by SHA-256. The server verifies the chain on start, daily and on demand,
  and can post the chain head to your notifiers once a day, which leaves a
  copy outside the machine.
- **No dependencies.** Both binaries use only the Go standard library.
- **The dashboard is the crown jewel.** It binds to loopback, requires a
  password plus TOTP for every login, rate-limits attempts, uses strict
  cookies, a CSRF token and a strict Content Security Policy, renders
  agent data only as text, and records every admin action in the chain.

See [docs/threat-model.md](docs/threat-model.md) for what vigil does and
does not protect against.

Full documentation, including the catalogue of all detection rules:
**https://akquisio-dev.github.io/vigil/**

## Quick start

From a signed release (needs [cosign](https://docs.sigstore.dev/cosign/system_config/installation/)):

```sh
curl -fsSLO https://github.com/akquisio-dev/vigil/releases/latest/download/install.sh
less install.sh
sh install.sh server
sh install.sh agent -server http://10.0.0.1:8471 -token vgl_...   # on each host
```

Debian and Ubuntu can also use the
[apt repository](docs/getting-started.md#with-apt-debian-and-ubuntu).
[Getting started](docs/getting-started.md) walks through it step by step. To
build from source instead (Go 1.25+):

```sh
make build        # dist/vigil-agent, dist/vigil-server
make test
```

Server:

```sh
useradd --system --home-dir /var/lib/vigil --shell /usr/sbin/nologin vigil
install -m 0755 dist/vigil-server /usr/local/bin/
install -d -m 0750 -o root -g vigil /etc/vigil
install -m 0640 -o root -g vigil deploy/examples/server.json /etc/vigil/server.json   # edit it
cp deploy/systemd/vigil-server.service /etc/systemd/system/
systemctl enable --now vigil-server
vigil-server user add -config /etc/vigil/server.json alice  # shows the TOTP QR code
```

`user add` works while the server is running; the server rereads the user
file on every login.

Put the dashboard behind a TLS proxy (`deploy/examples/nginx.conf`) and, if
you can, restrict it to known networks. Serve the agent API on a VPN address
with `agent_listen`.

Each host:

```sh
install -m 0755 dist/vigil-agent /usr/local/bin/
install -d -m 0700 /etc/vigil
cp deploy/examples/agent.json /etc/vigil/agent.json         # set server, canary_roots
vigil-agent enroll -server http://10.0.0.1:8471 -token vgl_...   # token from Settings
cp deploy/systemd/vigil-agent.service /etc/systemd/system/
systemctl enable --now vigil-agent
```

The first scan becomes the baseline; nothing is alerted for what already
exists. Open ports seen on the first snapshot count as expected, everything
after that has to be accepted in the dashboard, either one port or all ports
of a process (for programs that pick random ports on every start).

## Configuration

The most used keys; [docs/configuration.md](docs/configuration.md) has all of
them.

`agent.json`

| Key | Default | Meaning |
|---|---|---|
| `server` | from enrollment | server URL |
| `interval_seconds` | 30 | batch interval, also the heartbeat |
| `scan_seconds` | 60 | file, port and canary scan interval |
| `watch_files` / `extra_watch` | built-in list | globs to hash and diff |
| `canary_roots` | none | directories the dashboard may place canaries in; empty disables canaries |
| `canary_ignore_exe` | none | executables whose canary opens are ignored (backup tools) |
| `ssh`, `ports`, `docker` | true | collectors on/off |
| `response` | off | allow response actions (isolate, block, kill) from the dashboard |
| `fallback` | none | a notifier the agent tells itself when the server is unreachable for `fallback_minutes` (15) |

`server.json`

| Key | Default | Meaning |
|---|---|---|
| `listen` | 127.0.0.1:8470 | dashboard |
| `agent_listen` | same as `listen` | agent API, e.g. a VPN address |
| `public_url` | | used for links in notifications |
| `agent_url` | | how agents reach `agent_listen`; shown in the enrollment command |
| `language` | en | notification language, `en` or `de` |
| `trust_proxy` | false | take the client address from `X-Forwarded-For` |
| `deadman_seconds` | 120 | silence before an agent counts as gone |
| `retention_days` | 90 | days of event log to keep |
| `anchor_daily` | false | post the chain head to all notifiers once a day |
| `heartbeat_url` | | fetched every minute, for an outside watchdog |
| `backup` | | `recipient` public key, `dir`, `keep`: daily sealed backups with `vigil-server-backup.timer` |
| `notifiers` | | `discord`, `slack`, `ntfy`, `telegram`, `webhook` or `smtp`, each with `min_severity` |
| `summary_time` | | send a daily summary at this time, e.g. `"07:30"` |
| `vuln_lookup` | false | known and exploited vulnerabilities in installed packages |
| `hash_intel` | false | match programs against known malware hashes |
| `threat_intel` | false | match addresses against public block lists |
| `geoip` | false | country and network of attacking addresses (DB-IP Lite) |
| `forward` | | send events and alerts to syslog, HTTP or a file |

## Limitations

- Linux only; canary watching needs amd64 or arm64.
- Short-lived readers of a canary (`cat`, `head`) are often gone before vigil
  can read their executable path; the process name, user and parent chain
  are still reported.
- The dashboard shows the most recent events from memory (`recent_events`);
  older events stay on disk in the log files.
- A root attacker on a host can stop its agent. vigil cannot prevent that,
  it makes sure you hear about it.

## Maintainers

vigil is led by [Thaddäus Bischoff](https://github.com/TBjunior) (@TBjunior)
and developed under the [akquisio-dev](https://github.com/akquisio-dev)
account. Pull requests are assigned to the project lead for review.

## License

Copyright (C) 2026 akquisio-dev and the vigil contributors.

vigil is free software: you can redistribute it and/or modify it under the
terms of the GNU Affero General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option) any
later version. See [LICENSE](LICENSE).

The dashboard bundles DM Sans and DM Mono (SIL Open Font License 1.1, see
`internal/server/web/fonts/`) and paths from Tabler Icons (MIT, see
`LICENSES/tabler-icons-MIT.txt`).

If you run a modified vigil as a service for others, the AGPL requires you to
offer them the source of your modified version.
