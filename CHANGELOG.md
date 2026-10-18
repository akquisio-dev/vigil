# Changelog

## Unreleased

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
