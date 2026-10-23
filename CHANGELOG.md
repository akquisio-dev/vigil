# Changelog

## Unreleased

- abuse.ch retired its keyless downloads in October 2026: ThreatFox and MalwareBazaar answered 410 Gone and vigil kept using copies that no longer changed. New option `abusech_key_file` with a free Auth-Key; the exports are fetched from the new addresses with the key in the path, and the key is removed from every error before it reaches a log, the dashboard or an alert. Without a key these sources are not asked at all and show "needs an abuse.ch Auth-Key". Feodo Tracker needs no key.
- `log.spoofed` no longer fires when a user other than root runs `sudo`, or logs in over SSH: both write to the journal with that user's uid. Such entries are recognised by the program journald saw (`/usr/bin/sudo`, `/usr/sbin/sshd`, `sshd-session`), and no login is read from them. Seen on a new host with the `ubuntu` user.
- Connections to a service that is restarting are no longer reported as outgoing (`net.service_outbound`, `net.connection`): a port counts as a service port for ten minutes after its listener was last seen. During a package upgrade sshd stops listening for a moment while its sessions, including the pre-authentication ones of scanners, stay open; each of them was reported as sshd connecting out.
- A kernel update no longer raises `process.download_exec`: `mkinitramfs` opens its build directory in /var/tmp with `chmod 755`. Only that exact command, as root, is let through.
- New rule `intel.stale` (medium): a threat or hash list could not be downloaded for two days. It names the source and the last error and resolves itself with the next good download. A list waiting for an abuse.ch key that is not configured raises nothing. Before, a failing list was only visible in the server log.

## v0.26.0

- Agents count failed SSH logins per tried user name (`user_counts` in `ssh.failed`). The attack statistics keep them per day and hour; days from older agents share a total out evenly and are marked as estimated. Day files written before are rebuilt from the log on the first start, or kept as they are when the log no longer has the day.
- The attackers page has a section on tried user names: ranking with inline bars and trend lines, word cloud, heatmap by hour of day, matrix by country, a flow diagram country, name, account exists, and a treemap of the attempts by country and network.
- Live attack map: with `map_home` in `server.json`, new attacks are drawn as arcs from their country to the hosts, with the newest listed below the map. New endpoint `GET /api/ui/attacks/live?after=SEQ`.

## v0.25.0

- Suppressions can match a parameter by pattern: a program by name whatever its pid, a path with `*`, a port or uid range, a network. Free text (command lines, request samples) still only matches exactly, patterns that name nothing are refused, a path pattern below `/tmp`, `/var/tmp` or `/dev/shm` in a process rule needs the exact uid, and a value cut at 300 characters never matches a pattern. A server without patterns reads them as values that never occur, so a downgrade makes a pattern suppression silence nothing instead of more.
- The suppression form shows how many open alerts it covers, per host, before you save, and saving resolves them. API: `dry_run` and `resolve` on `POST /api/ui/suppressions`, which now answers `{suppression, resolved}`.
- Port alerts have **Allow process** on the alert page. Allowing a process also resolves the open alerts for ports of its earlier runs, which are closed by then (a game server picks new random ports on every start). Port alerts carry `scope`.
- `apt-key` making its GnuPG home (`chmod 700 /tmp/apt-key-gpghome.XXXXXXXXXX`) is no longer `process.download_exec`. Only that exact command is let through; a program started from the directory is still `process.tmp_exec`.

## v0.24.0

- Readable canaries: a canary can be placed with mode 0644 (dashboard checkbox, API field `readable`). A canary readable only by root never fires for an intruder who got in through a web app or game server running as its own user; a readable one does. It is still owned by root, its content is still worthless, and the agent only places it in a directory that already exists. The server refuses the option for agents that do not report support, so an older agent can not silently place a 0600 file instead.
- The agent remembers mode, owner and group of every canary and reports `canary.tampered` with problem `permissions` when they change. Canaries placed by older agents take their current values on the first check.
- `canary.opened` reads the reader's uid and parent chain first, before the slower fields, and the alert says `uid unknown` instead of `uid ` when the reader was already gone.

## v0.23.0

- `sh install.sh try` installs the signed server and agent on one machine, both on 127.0.0.1, creates a dashboard user, connects the agent and prints an SSH tunnel command and a harmless command that raises a first alert. `try-remove` takes the trial out again and refuses on a machine that was not set up by `try`; `try-setup` does the trial setup with binaries already installed. CI runs the trial setup with each build, waits for the alert and checks the removal.
- `vigil-server token` creates an enrollment token without the dashboard. It takes the data directory lock, so it refuses while the server runs, and records `enroll.token_created` in the audit chain.

## v0.22.0

- Containers: with `docker` on (the default) the agent asks the Docker API, with GET requests only, which containers run. Process, malware and connection findings from inside a container name it (`[container NAME]` in the alert). The agent sends an overview when it changes (`container.snapshot`), and the host page lists the containers. New rules `container.privileged` and `container.docker_socket` (high, a container that can take over the host), `container.new_image` (medium, an image never seen on the host, after a baseline) and `container.docker_group` (medium, users other than root in the docker group).

## v0.21.0

- `log.spoofed` no longer fires for sshd entries whose sender exited before journald read its name (an empty `comm` with uid 0, common for connections closed before authentication). Only root can send as uid 0.
- Application dependencies: the agent finds `package-lock.json`, pinned `requirements.txt` and `go.mod` below `app_roots` (`/opt`, `/srv`, `/var/www`, `/home`, `/root`) and sends the packages in them (`system.apps`, option `apps`, default on). With `vuln_lookup` the server matches them against OSV.dev data for npm, PyPI and Go modules, downloaded as OSV's public dumps and kept current record by record, so no package name leaves the server. New rules `vuln.app_malicious` (critical, a package OSV lists as malicious), `vuln.app_exploited` (critical) and `vuln.app_severe` (high), one alert per package and version; the host page lists all findings.
- CI runs the last release and the last release of the previous minor version against the current build (`tools/mixtest`): old server with a new agent, new server on the old data, an old agent enrolling with the new server, an agent replaced on its own state, and a rollback of the server. Each phase checks the agent stays online, takes a signed config and raises no config, forgery or chain alert.

## v0.20.1

- The agent scans programs one at a time and remembers results by file, rule set and change time. Each suspicious program start used to read up to 16 MB of the program in its own goroutine, so a large program started from `/tmp` a few dozen times (any local user can do that) pushed the agent past `MemoryHigh` and froze it until restarted. A burst of starts of one program now reads it once.

## v0.20.0

- Backups of the server: `vigil-server backup` writes the data directory, the config file and the files it names into one file, sealed for a public key from `vigil-server backup keygen` (X25519, AES-256-GCM in authenticated chunks); the secret key stays off the server. `backup check` verifies a file completely, `restore` unpacks, checks and only then swaps the data directory, keeping the old one. New units `vigil-server-backup.service` and `.timer` (daily, as `vigil`, no network) and the rule `server.backup_stale` (high). Existing installations copy both units from the release.
- The server locks its data directory, so a second server or a restore cannot run on it at the same time.
- An agent that holds a newer config than the server, as after a restore, gets the server's config again instead of ignoring it until the counter catches up.
- Agent `fallback`: a notifier the agent uses itself when the server has not taken a batch for `fallback_minutes` (15), and again when it does; `vigil-agent fallback test` checks the channel. It covers a server machine that is gone, without an outside service.
- The notifiers moved to `internal/notify`, shared by server and agent.

## v0.19.2

- The agent unit sets `MemoryHigh=64M`. On hosts with many files the scans filled the unit's 96 MB with reclaimable inode and dentry cache, and filesystem allocations that may not reclaim it got `journalctl` and then the whole unit OOM-killed, which raised `agent.restarted`. Existing installations: add `MemoryHigh=64M` in a drop-in or install the new unit file.
- Agent updates run the new binary first under its final name, not from the update directory, where the agent's scan of unknown programs raised `malware.yara` (vigil contains the strings its own miner rules look for).

## v0.19.1

- The host page offers **Update agent** for every agent from v0.19.0 on. The server also learns from the agent's answer whether `self_update` is on, so agents updated before the server no longer show it as off until their next restart.
- Daily summary: the countries are those with the most addresses, as the line says.

## v0.19.0

- One message per incident: the first alert and every more severe one are sent at once, the other alerts of the incident come as one update every `notify_group_minutes` (default 10; `-1` sends every alert on its own).
- Agent updates from the dashboard: with `self_update` in `agent.json` and `vigil-agent-update.path` enabled, **Update agent** on the host page installs the newest release. The agent checks the Sigstore signature itself (Fulcio chain, workflow identity for the exact tag, Rekor entry), takes only newer releases, keeps `.prev` and puts it back if the new agent does not stay up. The planned restart raises no alert when the agent comes back with the version asked for. New rule `agent.update_failed`.
- apt repository on the documentation site (`https://akquisio-dev.github.io/vigil/apt stable main`), rebuilt after every release from the newest five releases' packages, each checked against the release signature first. Key fingerprint in Getting started.
- The release workflow checks its own signature with the agents' code before publishing, and pins cosign.
- Daily summary (`summary_time`): alerts, open incidents, silent hosts, failed self tests, vulnerabilities, attackers and notifier problems in one message a day, to every notifier unless it sets `"summary": false`. Preview and send it from Settings.

## v0.18.0

- Attackers page: who attacked the hosts over 24 hours, 7 or 30 days, by country and network on a world map (`geoip`: DB-IP Lite, looked up on the server), user names and paths tried, time of day, campaigns of addresses trying the same lists, and a class per address (successful, aimed, persistent, noise) with the reasons. The pivot page of an address shows its origin and class.
- Attack report as Markdown or as a page to print or save as PDF.
- `ssh.attacker_login`: a login from an address that failed three or more SSH logins in the week before, with other user names or a password. A client offering the wrong key first is not an attacker.
- The agent counts attempts on existing accounts: with password login off, sshd only logs them as closed connections, which were not counted before. `ssh.failed` names the tried users that exist (`existing_users`). Each connection counts once, plus each further password try.
- The phone layout scrolls the bottom bar instead of the page.

## v0.17.1

- The server keeps only the vulnerability data of packages installed on its hosts in memory (about 5 % of a release's data, which is mostly kernel flavours nobody runs); the files on disk stay complete, and a newly installed package loads its data.

## v0.17.0

- Response: isolate a host (everything blocked except the vigil server and `isolate_allow`), end isolation, lock and unlock accounts (`usermod -L -e 1`, SSH sessions ended). Isolation and locks end by themselves after their time, also without the server and across reboots, and isolation removed by hand before its end is put back. Agent options `isolate_allow`, `never_lock`.
- Four-eyes (`four_eyes`): listed action types wait for a second admin's approval with a fresh code; the overview lists what waits.
- Playbooks (`playbooks`): actions started by alerts of chosen rules, with an hourly cap, the host's own allow list and four-eyes applying.
- The host page shows isolation and locked accounts and ends them early; alerts suggest isolating and locking.
- Fix: an agent upgraded right after the server got no YARA rules until they changed (the old agent had taken the configuration). Agents without stored rules now ask for the configuration again at start.

## v0.16.0

- Incident reports as Markdown and as a page to print or save as PDF: figures (detection delay, time to acknowledge, time to close), ATT&CK, alerts, involved addresses, users and hashes, notes, evidence, timeline with changed lines and the chain hashes of every record used.
- Malware hashes: suspicious and new programs are hashed by the agent; with `hash_intel` the server matches them against abuse.ch MalwareBazaar and ThreatFox, also for the last 30 days when the lists grow (`malware.known`).
- YARA: rules in `yara_dir` (a subset of the language, no cgo) go to the agents with their signed configuration; agents scan suspicious and new programs, programs in evidence snapshots and new programs in temp directories (`malware.yara`). Starter rules for Linux miners, botnets, reverse shell scripts and packed programs in `deploy/examples/yara`. Agent option `yara`.
- Sigma: rules in `sigma_dir` for Linux process, network and file events.
- Forwarding of events and alerts to syslog (UDP, TCP, TLS), HTTP and files (`forward`), with `forward.failed`.
- The rules page shows the state of Sigma, YARA, hash lists and forwarding.
- SSH sessions no longer list the message-of-the-day scripts PAM runs at every login.

## v0.15.0

- Search: a query language for the stored log (`type:process.* uid:0 exe:/tmp/* -user:root count:>10`), saved searches, export as CSV and JSON lines (audited).
- Retro hunt: when a threat list gains entries, the last 30 days of connections, SSH logins and web requests are searched for them (`net.retro_hit`). Hunt page for pasted addresses, users and hashes.
- SSH sessions: logins with duration, the commands typed (also in tmux and screen), sudo commands and files changed meanwhile. Agent option `sessions`.
- Unusual behaviour: first runs of unpackaged programs (`process.rare`), new children of services (`process.rare_child`) after a learning period, logins at a user's unusual hour (`ssh.rare_time`), unusual outbound traffic per hour (`net.volume_spike`). Agent options `rarity`, `rare_learn_days`, `rare_parents`, `volume`.
- Event tables stack on narrow screens.

## v0.14.0

- Timeline per alert and host: everything the host reported around the event behind an alert, placed by the host's own time, with filters by kind and a movable window.
- Pivot pages for addresses, users and SHA-256 hashes: every event and alert naming them across hosts and the whole retention, with first and last sighting and threat list hits. Values in alerts and events link to them.
- Changes to watched configuration files carry the changed lines (sudoers, sshd, cron, systemd, PAM, shell init, `passwd`); secrets are replaced, password hashes and SSH keys are never copied.
- Evidence snapshots: process list, sockets, logged-in users, modules, journal tail and the suspect process in detail, taken by the agent at once for its strongest signals and on request for other high and critical alerts. Optional quarantine copy of the program. Agent options `forensics`, `quarantine`.
- The alert page shows the events behind the alert with their changes, and the evidence taken for it.
- Command lines in process events, canary events and snapshots have passwords and tokens replaced before they leave the host (`+rcon_password`, `?ServerAdminPassword=`, `--token`, `mysql -p...`, URLs with credentials).
- The agent splits its queue into batches below the server's request limit, so large events (snapshots) cannot block delivery.
- Fix: the alert page failed for admins on alerts without suggested response actions.

## v0.13.1

- Fix: when hosts on two releases sent their package lists at the same time, the second release got no vulnerability data until the next hourly refresh.
- `secret.exposed` raises one alert per file; more secrets in the same file raise its count.

## v0.13.0

- Vulnerabilities: agents send their installed source packages; with `vuln_lookup` the server matches them against Canonical's OVAL data (Ubuntu, kernels included), the Debian security tracker and CISA's catalogue of exploited vulnerabilities. One alert per package for exploited (`vuln.exploited`) and for high or critical fixable vulnerabilities (`vuln.severe`); counts and lists on the host page. Agent option `packages`.
- Hardening checks every six hours: SSH root and password login, empty passwords, ASLR and other kernel settings, permissions of files that decide what root runs, firewall, AppArmor/SELinux (`posture.*`). Agent options `posture`, `posture_skip`.
- Certificates of Let's Encrypt, nginx and Apache (and `tls_certs`) close to expiry or expired (`tls.expiring`, `tls.expired`).
- Backups listed in `backups` that are missing, too old or too small (`backup.missing`, `backup.stale`, `backup.small`).
- Exposed secrets: private keys, API tokens, URLs with passwords, `.env`, `.pgpass` and `.netrc` entries in files every user can read (`secret.exposed`). The secret never leaves the host. Agent options `secrets`, `secret_roots`.
- These conditions alert once when they start and close themselves when they end.

## v0.12.0

- Kernel: new modules (`kernel.module`), out-of-tree or unsigned modules (`kernel.module_unsigned`), modules hidden from `/proc/modules` (`kernel.module_hidden`), new taint flags (`kernel.tainted`), eBPF programs that hook the kernel or packets (`kernel.bpf`). Agent options `kernel`, `bpf`.
- Processes: programs run from memory only (`process.memfd_exec`), `LD_PRELOAD` injection (`process.preload`).
- SUID/SGID programs and file capabilities (`file.suid`, `file.suid_tmp`, `file.suid_packaged`), including SUID bits set on packaged programs after installation. Agent option `suid`.
- Package integrity: programs used to log in or inspect the system, PAM modules and core libraries against Debian package checksums plus an own SHA-256 inventory (`integrity.binary_replaced`, `integrity.modified`, `integrity.unowned`, `integrity.many`). Agent option `integrity`.
- Every new collector keeps its own baseline, so upgrading does not report what was already there (except things that are odd already: out-of-tree modules, hooking eBPF programs, unowned or late SUID files, modified packaged files).

## v0.11.0

- Self test: on request and every `selftest_days` (default 7) each agent leaves three harmless marked traces (crontab spool file, `sleep` from `/tmp`, an sshd-tagged log line) that `file.cron`, `process.tmp_exec` and `log.spoofed` must catch; the result goes to every notifier, failures raise `selftest.failed` with the reason a sensor is down. Agent option `selftest` (default on).
- Notifications: new types `ntfy`, `slack` (also Mattermost, Rocket.Chat) and `telegram`; Discord `mention` for critical alerts; `vigil-server notify test`; delivery status per notifier in the dashboard; a lost message raises `notify.failed` through the other notifiers; HTTP 429 waits for Retry-After; notifiers are validated at start.
- `heartbeat_url` is only pinged while the event chain verifies, the log and data directory are writable and the server is not hung.
- Fix: notifier errors in the log no longer contain the webhook URL with its secret.

## v0.10.0

- Response actions from an alert: block an address (nftables, table `inet vigil`), end an SSH session, stop a process, remove an SSH key. Off unless `response` in agent.json enables them; fresh TOTP code, ten minute validity, at most once, audited.

## v0.9.0

- Reproducible, signed releases (Sigstore keyless) with binaries and Debian packages for amd64 and arm64; `install.sh` checks signature and checksum; `version -verify` compares a running binary with the release.

## v0.8.0

- Agent: suspicious program starts (process events connector), new outbound destinations, web server access logs, pending updates and reboots.
- Server: `threat_intel` matches outbound connections against abuse.ch Feodo Tracker and ThreatFox, Spamhaus DROP and Tor exits. New rules `process.*`, `net.*`, `web.*`, `updates.*`.

## v0.7.0

- Passkeys (WebAuthn, standard library only), roles viewer, analyst and admin, password change, user management with TOTP QR codes; `user add -role`.

## v0.6.0

- Custom rules as JSON in `rules_dir`, with `vigil-server rules check` and `rules test`; rules page in the dashboard; event type reference in the docs.

## v0.5.0

- Incidents: related alerts grouped per host, with timeline, owner, status and notes.

## v0.4.0

- Suppressions with reason and expiry (at most 90 days); critical and self-protection rules cannot be suppressed.

## v0.3.0

- SOC overview (alerts per day, open by severity, ATT&CK tactics, top rules, attacking addresses, host table, logins), light and dark switch, configurable brand.

## v0.2.x

- Dashboard layout following the Akquisio app; content-hashed assets.

## v0.1.0

- First release: agent, server, dashboard, canaries, hash-chained event log.
