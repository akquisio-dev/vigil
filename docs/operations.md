# Operations

## Working with alerts

An alert is `open` until someone acknowledges or resolves it. The same finding
on the same host within 24 hours raises the counter of the open alert instead
of a new one.

| Status | Meaning |
|---|---|
| open | nobody has looked at it yet |
| acknowledged | someone looked and is on it |
| resolved | closed, by a person or by vigil (for example when a silent agent is back) |

Every alert names its rule. The [rule catalogue](rules.md) explains each one.

### One host or one group

The selector at the top of the overview, hosts, alerts, incidents, events,
sessions and attackers pages narrows them to one host or one group of hosts.
The choice holds across pages and reloads; links can carry it as `?host=ID`
or `?group=NAME`. Groups are tags set on the host page (owner, role, place),
up to eight per host. The attackers page narrows to one host only: it then
lists the addresses that tried that host, with their counts over every host;
hours of day and tried user names are kept for all hosts together and are
left out.

The API takes the same filter as `agent=ID` or `group=NAME` on
`/api/ui/overview`, `/api/ui/alerts`, `/api/ui/incidents` and `/api/ui/events`
(`/api/ui/attacks` takes `agent` only). `/api/ui/alerts` also takes
`severity` (comma separated), `rule` (prefix), `q` (text in title, rule or
host) and `days`.

The alert list filters by severity, rule, period and text, and groups by rule
or host. Analysts can acknowledge or resolve everything the filter shows at
once (`POST /api/ui/alerts/bulk`, at most 1000, each audited).

### The host page

A host's page has seven tabs; the tab and its options are part of the link
(`#/hosts/ID?tab=changes&days=30`).

- **Overview**: one light per area with its number (open alerts, hardening
  findings, security updates and how long the oldest has been open,
  weaknesses, public ports, the last self test, disk and memory); each opens
  the tab with the detail. Below are the host's facts, its admin actions and
  open alerts.
- **Performance**: load, memory, network (also per interface, so VPN traffic
  shows), disk I/O and connections, with marks for alerts, logins, agent
  starts, package changes and reboots (each can be hidden). A click on a
  graph lists the programs of that minute (of that hour beyond the last day),
  with their CPU as a share of one core and of the host. Drag across a graph
  with the mouse to zoom into the minutes of the last day or the hours
  before; the points shown download as CSV. Below: the busiest and the
  largest programs of the span, the outlook (disk trend and the days until
  it is full, the memory trend, both from the last week and only with two
  days of data) and the normal range per hour of the week, drawn as a band
  behind CPU and memory once three samples per hour exist (per hour of the
  day until three weeks are known). Points clearly above it are marked.
- **Security**: alerts per day over 30 days, the rules that fired most, the
  median time until someone looked at an alert of this host, open incidents,
  hardening, containment, response, snapshots, self tests and the latest
  events.
- **Network**: listening ports with the time they opened, outbound
  destinations by first contact with country and network, destinations per
  program, the history of ports that opened and closed, and the data sent and
  received per hour over 14 days.
- **Software**: updates, weaknesses of the system and the applications in one
  table filtered by severity, ecosystem and "exploited or malicious", lock
  files and containers.
- **Access**: SSH logins by user and hour of day, keys and methods, source
  addresses (new ones are marked), failed logins per day on this host, the
  addresses that attacked it with their countries, and its sessions.
- **Changes**: what changed on the host, by day and kind: files, systemd and
  cron, keys, accounts, ports, new programs, packages added, removed or
  updated, kernel modules, containers and agent starts. File contents stay on
  the timeline; each entry links there.

Network, access and changes read the day files on disk for the host
(`GET /api/ui/agents/{id}/activity?days=7`, 1 to 30 days, kept for two
minutes), so they reach back further than the in-memory window.
`/api/ui/overview` takes `days` (1 to 30) for its alert counts.

## Investigating

Every alert tied to a host has a **timeline**: everything the host reported
30 minutes before and after the event behind the alert (the window can be
widened to 12 hours and moved). Events are placed by the time they happened
on the host; events that arrived late (agent offline, queue sent later) show
when they were received. The timeline of a host starts from its page.

Addresses, user names and SHA-256 hashes in alerts and events are links to a
**pivot page**: every event and alert naming that value across all hosts,
over up to the whole retention, with first and last sighting, the hosts and
the event types, and for addresses whether a threat list names them. All of
it is read from the event log on the server; nothing is looked up outside.

Changes to watched configuration files (sudoers, sshd, cron, systemd units,
PAM, shell init, `passwd`, `ld.so.preload`) carry the **changed lines**. The
agent keeps a copy of each file to compare with; the first change after the
copy was made (the first scan, or the upgrade to v0.14.0) says that the
previous content is unknown. Lines that look like secrets are replaced
before they leave the host, and password hashes and SSH keys are never
copied.

**Evidence snapshots** keep what is gone after a reboot or when a process
exits: the process list, network sockets with their processes, logged-in
users, loaded kernel modules, the last journal lines, and for the suspect
process its program hash, parents, children, open and mapped files and the
names (not values) of its environment variables. The agent takes one at once
for reverse shells, miners, programs from memory or deleted files,
`LD_PRELOAD`, services starting shells, download and run, and opened
canaries. For other high and critical alerts about activity the server asks
for one (at most every ten minutes per host), and analysts can ask from an
alert or a host page. With `quarantine` on, the program is copied while it is
hashed, before anything else.

Snapshots travel in the signed agent batches and are part of the hash chain
like every event, so a snapshot shown in the dashboard is the one the agent
sent. The snapshot's own SHA-256 is shown for reference in reports.

Viewers see the timeline and pivot pages without change contents and
snapshot details; those need the analyst role.

### Incident reports

An incident's page offers its report as Markdown or as a page to print or
save as PDF. It holds the figures (time from the first event to the first
alert, to the first acknowledgement and to closing), the ATT&CK tactics,
all alerts, the addresses, users and hashes involved, the notes, the
evidence snapshots with their hashes, the host's timeline around the
alerts with changed lines, and the chain hash of every record the report
relies on together with the chain head at the time of the report. Anyone
can later check with `vigil-server verify` that the log still holds those
records unchanged. Making a report is written to the audit log.

### Searching the log

The query box on the events page searches the stored log of all hosts (up
to the retention). All conditions must hold:

| Condition | Meaning |
|---|---|
| `type:process.*` | event type, `*` as wildcard |
| `host:web`, `agent:<id>` | host name or agent id |
| `uid:0`, `exe:/tmp/*`, `signals:cmd_miner` | a field of the event (lists match any element) |
| `target.exe:/usr/*` | a nested field |
| `count:>10`, `port:<1024` | numbers compared with `>`, `<`, `>=`, `<=` |
| `-user:root` | must not hold |
| `curl`, `"two words"` | text anywhere in the event, any case |

Analysts can save queries for everyone. Results export as CSV (formulas
neutralised) or JSON lines, up to 5000 records; every export is written to
the audit log.

### Hunting

When a threat list (`threat_intel`) gains entries, the server looks through
the last 30 days of outbound connections, SSH logins and web requests for
them and raises `net.retro_hit` once per address and list. The hunt page
does the same on demand for a pasted list of addresses, user names and
SHA-256 hashes, over up to the whole retention.

### SSH sessions

The sessions page lists SSH logins with their source, key, duration, and
what happened in them: the commands typed (programs started by a shell, sudo
or su inside the session, also inside tmux or screen), `sudo` commands, and
watched files changed while the session was open (changed while open, not
necessarily by it). Up to 300 commands per session and hour are recorded;
command lines lose passwords and tokens before they leave the host. Commands
are tied to sessions from the moment the agent saw the login; sessions that
were open before the agent started are not tracked.

### Unusual behaviour

After a learning period of seven days (`rare_learn_days`) the agent reports
programs that never ran on the host before and no package installed
(`process.rare`), and programs a web server, database or runtime never
started before (`process.rare_child`). The server learns when each user
logs in (`ssh.rare_time`) and how much each host sends per hour
(`net.volume_spike`).

### Attackers

The attackers page shows who attacked the hosts over the last 24 hours, 7 or
30 days: failed SSH logins (also on accounts that exist, which sshd only logs
as a closed connection when password login is off) and flagged web requests,
by country and network on a world map (with `geoip`), the user names and
paths tried, the time of day and the day. Each address is put in one class:

| Class | Meaning |
|---|---|
| successful | it logged in over SSH after failing with other user names or with a password, or an attack request was answered with 2xx or reached a web shell (sites that answer every path with their start page also count here) |
| aimed | it tried an account the host really has that is in no word list, or a name from the host names or the brand, and never tried root (every word list has it) |
| persistent | it came back on three or more days with 20 or more attempts |
| noise | mass scanning every server on the internet gets |

Campaigns group addresses that try the same list: three or more names or
paths, at least 60 % of them shared. A botnet working through one list from
hundreds of addresses becomes one entry. Networks are marked as data centre or
cloud by their name; the free data has no network type, so it is an estimate.
The pivot page of an address shows the same for it over 30 days.

A login from an address that failed three or more SSH logins in the week
before raises `ssh.attacker_login` when it tried other user names or logged
in with a password. Addresses that failed only as the user they then logged
in as with a key are the team (an SSH client offers its keys one after the
other) and are left out of the statistics.

The tried user names have their own section:

- a ranking with the attempts as bars, the number of addresses and countries
  per name and its trend per day (per hour for 24 hours);
- a word cloud of the 60 most tried names, names the host has an account for
  in red;
- a heatmap of names by hour of the day, in the viewer's time zone;
- a matrix of names by country, with the attempts in every cell;
- a flow diagram from country to name to "account exists" or not, which shows
  at a glance how much of the guessing hits real accounts;
- a treemap of the attempts by country and network.

Agents from v0.26.0 count the attempts per name. For days reported by older
agents a total for several names is shared out evenly, and the page says so.
These views come from failed SSH logins on port 22: with password login off,
sshd never sees a password, so vigil shows none.

With `map_home` set in `server.json` (`[latitude, longitude]` of the hosts),
the world map is live: every new attack is drawn as an arc from its country to
the hosts, and the newest ones are listed below the map. Agents report every
30 seconds, so an attack appears up to that late. Viewers who prefer reduced
motion get the list and the markers without animation.

The report button saves the page as Markdown or opens it for printing as PDF
(analysts and admins, recorded in the audit log).

The statistics are kept per day in `data_dir/attacks` (a few hundred KB per
day), so 30 days never mean rereading the log. On the first start they are
built from the log.

## Response actions

On an alert, admins can contain an attack on the host directly, if the host's
`agent.json` allows it ([configuration](configuration.md#response-actions)):

| Action | What the agent does | Refuses |
|---|---|---|
| Block address | adds it for 24 hours to an nftables set in its own table `inet vigil`, dropping traffic from and to it (input, forward, output) | loopback, local, the vigil server, `never_block` |
| End SSH session | stops the sshd process of the login (`SIGTERM`, then `SIGKILL`) | anything that is not an sshd session, the SSH daemon itself |
| Stop process | stops the process | a pid that now runs another program, pid 1, the agent |
| Remove key | removes the key from `authorized_keys`, after a backup in the agent's state directory | the last key of a file, files that are not `authorized_keys` |
| Isolate host | drops all traffic in, out and through the host (nftables table `inet vigil_isolate`, before the host's own firewall) except loopback, the vigil server and `isolate_allow`/`never_block`; ends by itself after 1 hour (at most 24) | hosts without an address in `isolate_allow` or `never_block` (nobody could reach them), an unresolvable server |
| End isolation | removes the table | |
| Lock account | locks the password and expires the account (`usermod -L -e 1`, which also stops key logins through PAM), ends the user's SSH sessions; unlocks itself after 24 hours (at most 30 days) and restores the previous expiry | uid 0, `never_lock` |
| Unlock account | `usermod -U` and the previous expiry | accounts vigil did not lock |

Isolation and locks are kept in the agent's state with their end time. The
agent undoes them when the time is up, without the server, and puts an
isolation back after a reboot or when someone removes the table by hand
before the end. The host page shows what is in force and ends it early.
The agent's sandbox keeps `/etc` read only; for `usermod` it asks systemd
to run that one command outside the sandbox (`systemd-run`).

Every action needs a fresh code from the authenticator app, reaches the
agent in the next signed configuration, is valid for ten minutes and runs at
most once. The request and the agent's result are in the event chain, and
the host page lists them. There is no way to run arbitrary commands.

To lift a block early: `nft delete element inet vigil blocked4 { 203.0.113.9 }`,
or remove the whole table with `nft delete table inet vigil`. To end an
isolation by hand on the console: `nft delete table inet vigil_isolate`
(the agent puts it back while its end time has not passed; stop the agent
first, or end it from the dashboard).

### Four-eyes

With `four_eyes` in server.json, the listed action types (or `"*"` for all)
wait for a second admin, who approves with a fresh code of their own. The
requester cannot approve, only withdraw. Unapproved requests expire after
30 minutes. Requests waiting for approval are listed on the overview.

### Playbooks

Playbooks start actions on their own when an alert of their rules is
raised:

```json
"playbooks": [
  {"name": "stop-miners", "rules": ["process.miner", "malware.yara"], "actions": ["kill_process"], "max_per_hour": 5},
  {"name": "contain-reverse-shell", "rules": ["process.reverse_shell"], "actions": ["kill_process", "isolate_host"], "minutes": 30, "hosts": ["web"]}
]
```

| Key | Meaning |
|---|---|
| `rules` | rule ids; `process.*` matches a prefix |
| `min_severity` | lowest alert severity (default `high`) |
| `hosts` | host names it applies to (default all) |
| `actions` | `kill_process`, `kill_session`, `block_ip`, `isolate_host`, `lock_user`, `remove_key`; parameters come from the alert |
| `minutes` | duration for blocks, isolation and locks (default 60, at most 1440) |
| `max_per_hour` | runs per hour (default 3); alerts beyond that are left to people |

Each action must still be allowed in the host's `agent.json`, four-eyes
applies to playbooks as well, every run is in the event chain and goes to
all notifiers. An attacker who can raise alerts can trigger playbooks:
keep the hourly cap low, and prefer measures that end by themselves.

## Accounts and roles

| Role | May |
|---|---|
| viewer | read everything |
| analyst | also acknowledge and resolve alerts, work on incidents, manage suppressions, verify the chain |
| admin | also place canaries, manage hosts, create enrollment tokens, send test notifications, manage users |

Accounts created before roles existed are admins. Under **Settings** every
user can add passkeys and change the password; admins add users (the page
shows the new password and a QR code for the authenticator app once), change
roles and remove users. These changes need a fresh code from the
authenticator app and are written to the event chain. The last admin can
neither be removed nor lowered.

### Roles per group

An account can have a higher role for the hosts of a group than for the
rest: someone can read the whole network as viewer and be admin of the group
of their own servers. Admins set this under **Settings, Users, Roles per
group** (a fresh code is needed, the change is audited).

For everything tied to one host the higher role counts: its alerts (also in
bulk, where alerts of other hosts are skipped and counted as `denied`), its
incidents (including alerts added to one), canaries, response actions,
evidence snapshots, renaming, maintenance and updates. What concerns the
whole network keeps the base role: users, groups, a host's groups and
removing a host, enrollment tokens, sources and shares, rules and
suppressions, the summary, test notifications and the chain. Detail an
analyst may see (command lines, diffs) follows the role for the event's host.

Groups are managed under **Settings, Groups**: create one with its hosts,
rename it on all hosts, remove it (the hosts stay), or set its members.

Passkeys need `public_url` to be set to the address in the browser, because
it is the relying party they are bound to. Changing the domain later makes
existing passkeys unusable; password and TOTP keep working.

## Incidents

Alerts that belong together are grouped into incidents, so an intrusion is
handled as one case:

- An alert joins the newest incident on its host that is not closed, if the
  incident had an alert within two hours before or after it.
- Otherwise a high or critical alert opens a new incident. It takes along the
  host's alerts from the two hours before that are in no incident yet, for
  example the login from a new address that came first.
- Alerts about the agent itself (stopped, restarted, silent) never open an
  incident, but they join one.

An incident page shows its alerts and the host's raw events from 30 minutes
before the first to 30 minutes after the last alert, with the SSH login that
most likely started the session at the top. Take it over, set the status
(open, investigating, contained, closed) and write notes; every change is in
the event chain. **Open incident** on an alert starts one by hand.

Notifications are still sent per alert.

## Suppressions

When a finding is expected (a backup job that rewrites a cron file every night,
a deploy runner that logs in from a fixed address), open the alert and use
**Suppress similar**. Choose which of the alert's parameters must match, whether
it applies to this host only, a reason and a duration (at most 90 days).

A parameter can match a pattern instead of one exact value. The form offers the
pattern that fits the parameter, prefilled from the alert:

| Pattern | For | Example |
|---|---|---|
| program, any pid | `process` | `name:srcds_linux` matches `srcds_linux/3104444` |
| path pattern | paths (`exe`, `path`, `cwd`, ...) | `glob:/tmp/go-build*/b*/exe/*` (`*` never crosses `/`) |
| range | `port`, `uid` | `range:27000-27100` |
| network | addresses | `cidr:10.90.0.0/24` |

Command lines, web request samples and user agents only match exactly: a
pattern over free text could swallow an appended `; curl ... | sh`. Patterns
that name nothing (`*`, `/tmp/*`, a network wider than /8) are refused, and a
path pattern below `/tmp`, `/var/tmp` or `/dev/shm` in a process rule needs the
exact `uid`: anyone can create files there, so the uid is the only part an
intruder can not choose. A value cut at 300 characters never matches a pattern.

Before you save, the form shows how many open alerts the suppression covers and
on which hosts; saving resolves them. A count far higher than expected means the
suppression is too broad.

For new listening ports of a program that picks a random port on every start
(game servers, Wine), **Allow process** on the alert or the host page is the
better tool: it does not expire, and it resolves the open port alerts of that
program's earlier runs too.

- Matching findings raise no alert and no notification. The events that caused
  them stay in the event log, and each suppression counts its hits.
- Creating, renewing, deleting and expiring a suppression are written to the
  event chain with the user's name.
- Expired suppressions stay listed under **Suppressions** for 30 days, so they
  can be renewed.
- Rules an attacker would want silenced cannot be suppressed: every critical
  rule, and all rules about agents, canaries, the event chain, log spoofing,
  notifiers and self tests.
  Use a maintenance window for planned agent restarts instead.
- A server older than v0.25.0 reads a pattern as an exact value that never
  occurs, so after a downgrade a pattern suppression silences nothing rather
  than more.

## Self test

A detection that never fires looks exactly like a quiet host. The self test
proves that each host's sensors, the server's rules and your notifiers still
work, end to end.

On request, the agent leaves three harmless traces, each named after a random
test id:

| Step | Trace | Must raise |
|---|---|---|
| file | a comment-only file in `/var/spool/cron/crontabs` (or `/etc/cron.d`), removed right after the scan | `file.cron` |
| process | a copy of `sleep` started from `/tmp` for one second | `process.tmp_exec` |
| journal | a log line tagged `sshd`, written by the agent | `log.spoofed` |

The server matches findings to the test by that id, never by time, so an
attack during a test still raises its normal alert. Findings of the test raise
no alert; they stay in the event log like everything else. The result goes to
**every** notifier, whatever its `min_severity`, so each channel is tested too.

- **passed**: every trace was detected.
- **passed with warnings**: a step was skipped (for example `/tmp` is mounted
  `noexec`, or a collector is turned off in `agent.json`) or its rule is
  suppressed.
- **failed**: a trace was not detected, a collector stopped, or the agent did
  not run the test within ten minutes. This raises `selftest.failed` (high,
  cannot be suppressed) with the missing steps and, where the agent knows it,
  why the sensor is down.

Every host is tested right after it first connects and then every
`selftest_days` days (default 7). Admins start a test on the host page at any
time. Hosts in a maintenance window, stopped or silent are skipped by the
schedule. An agent with `"selftest": false` in `agent.json` refuses tests.

## Planned work on a host

Every agent stop and restart raises a high alert, because an attacker would do
exactly that before touching a canary. Before planned work, open the host in the
dashboard and start a **maintenance window** (30 to 240 minutes). While it
runs, agent stop, restart and silence alerts for that host are not raised. The
events themselves stay in the log, and the window is recorded with the name of
the person who set it.

The agent cannot announce its own maintenance. Anything the host says about
itself may come from the attacker.

## Ports

The first port snapshot of a host is its baseline. Afterwards:

- **Accept** allows one exact socket (protocol, address, port).
- **Allow process** allows every port of that program with the same protocol
  and scope. Use it for programs with random ports.

## Upgrading

### Agents from the dashboard

Turn it on once per host:

```sh
# in /etc/vigil/agent.json: "self_update": true
systemctl restart vigil-agent
systemctl enable --now vigil-agent-update.path
```

`install.sh` puts `vigil-agent-update.path` and `vigil-agent-update.service`
in place (releases from v0.19.0 on) but does not enable them. Then the host
page has **Update agent**: the server looks up the newest release on GitHub,
and after you confirm, the agent downloads it, checks its signature (see the
[threat model](threat-model.md)), and the update unit installs it. The old
binary stays as `/usr/local/bin/vigil-agent.prev`. If the new agent does not
run for 15 seconds without restarting, the old one is put back and
`agent.update_failed` is raised.

The restart raises no `agent.stopped` or `agent.restarted`, but only during an
update an admin started and only when the agent comes back with exactly the
version asked for. Coming back with another version, not coming back within
three minutes, or no result within 30 minutes is reported. Hosts need to reach
github.com. Agents installed from the Debian package refuse and say to use
apt.

### By hand

Start a maintenance window for the host first, or the restart raises an
alert. Then install the new release (`sh install.sh agent -version vX.Y.Z`,
the `.deb`, or the binary by hand) and restart the service.

```sh
install -m 0755 dist/vigil-agent /usr/local/bin/
systemctl restart vigil-agent
```

The server keeps all state across restarts. Dashboard sessions do not survive a
restart; everyone logs in again.

## Verifying the event log

```sh
vigil-server verify -config /etc/vigil/server.json
```

The server also verifies the chain on start, once a day and when you press
**Verify now** in the settings. A break raises `chain.broken` with the file and
line.

## Backups

`/var/lib/vigil` on the server holds the event log, the state, alerts,
incidents, dashboard users and the server key. Agents pinned that key at
enrollment; if it is lost, every agent has to be enrolled again. `vigil-server
backup` copies all of it, plus the config file and the files it names (logo,
YARA, Sigma and custom rules), and leaves out what the server downloads again
(block lists, geo and vulnerability data).

A backup holds the server key, password hashes and TOTP secrets, so it is
sealed for a public key (X25519, AES-256-GCM in authenticated chunks). The
server only gets the public key. Make the key pair on another machine, and
keep a second copy of the secret key offline; without it no backup opens:

```sh
vigil-server backup keygen -out /root/vigil-backup.key   # not on the server
```

```json
"backup": {"recipient": "vigil-backup-1:...", "dir": "/var/lib/vigil-backups", "keep": 14}
```

```sh
systemctl enable --now vigil-server-backup.timer   # daily at 03:30
```

The timer's unit runs as `vigil` without network and writes to
`/var/lib/vigil-backups`; only complete backups appear there, under a name
with the time, and the oldest beyond `keep` are removed. The server raises
`server.backup_stale` when the newest is older than `max_age_hours` (36).
Backups are safe while the server runs: the event logs are copied after the
state, up to their last complete line, and the copy's hash chain is checked
before it is written.

A backup on the same machine does not survive the machine. Fetch them from
elsewhere, for example from a host with SSH access:

```sh
scp server:/var/lib/vigil-backups/$(ssh server ls /var/lib/vigil-backups | tail -1) /srv/backups/vigil/
vigil-server backup check -key /root/vigil-backup.key /srv/backups/vigil/vigil-backup-*.vbak
```

`backup check` reads the whole file and checks every file against the
manifest and the event chain; a cut off, altered or foreign file fails. It
writes nothing.

### Restoring

On the old or a new machine, with vigil-server installed and stopped:

```sh
systemctl stop vigil-server
vigil-server restore -key vigil-backup.key -config-out /root/restored vigil-backup-....vbak
systemctl start vigil-server
```

Restore unpacks into a new directory next to the data directory, checks it
completely, and only then swaps it in. The previous data directory is kept as
`/var/lib/vigil.before-restore-<time>`, never deleted. It refuses while a
server holds the data directory, and refuses a backup of a newer vigil unless
`-force`. Config files go below `-config-out` (with their full path) for you
to compare and copy; restore never writes `/etc/vigil` itself. Run as root,
the files are handed to the owner of the old data directory, else to `vigil`.

Agents reconnect with their keys; nothing is enrolled again. Whatever
happened after the backup is missing on the server: alerts and events of
that time, and canaries placed since then, which the agents remove at their
next batch. The agents' queues (`max_queue`) still hold what they could not
send while the server was down.

On hosts, `/var/lib/vigil-agent` holds the agent key and its last known state.
After restoring an old copy, the agent reports every change since that copy as
new, which is correct but noisy. Keep the host's clock synchronized: sequence
numbers come from it, and a clock that jumps backwards makes the server reject
batches as replays.

## Removing a host

Remove the host's canaries in the dashboard first and wait until the host page
shows the configuration as applied; the agent has then deleted the files. Then use **Remove host**, which
deletes the agent record from the server. On the host, stop and disable the
service and delete `/var/lib/vigil-agent`. The event log keeps everything the
host reported.

## Resource limits

The systemd units cap the agent at 96 MB of memory (reclaiming caches from
64 MB on) and 15 % CPU with idle I/O priority, and the server at 256 MB and 50 % CPU. Adjust them in a drop-in if a
host needs more.
