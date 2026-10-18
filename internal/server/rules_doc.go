package server

import "sort"

// ruleDoc explains a rule to the people who receive its alerts. The rule
// catalogue in docs/rules.md is generated from this table, and a test makes
// sure every rule has an entry.
type ruleDoc struct {
	Trigger        string
	FalsePositives string
	Response       string
}

var ruleDocs = map[string]ruleDoc{
	"ssh.password_login": {
		"sshd accepted a password or keyboard-interactive login.",
		"Hosts where password login is still intentionally enabled.",
		"Confirm the person and the source address. If password login should be off, check `PasswordAuthentication` in sshd_config and rotate the password of that account.",
	},
	"ssh.new_source": {
		"A user logged in over SSH from an address that user was never seen on before, on any host.",
		"New home or mobile networks, travel, a teammate's first login. Every user raises it once per address.",
		"Ask the user whether the login was theirs. Unexplained logins from new addresses are the classic sign of stolen credentials.",
	},
	"ssh.unknown_key": {
		"A public-key login used a key that is in none of the watched `authorized_keys` files.",
		"`AuthorizedKeysCommand` or certificates, or an `authorized_keys` file outside the watch list.",
		"Treat as compromise until explained: someone holds a key that the host does not list, or the key was added and removed between two scans.",
	},
	"process.reverse_shell": {
		"A shell started with its input or output connected to a network socket, or a command line that builds a reverse shell (`/dev/tcp/…`, `nc -e`, `socat exec:`, Python `pty.spawn`).",
		"Rare. Some remote administration scripts pipe a shell through `socat` on purpose.",
		"Treat as an active intrusion: note the parent process and the remote address (`ss -tnp`), isolate the host, preserve memory and disk if you can, then kill the process.",
	},
	"process.miner": {
		"A program with a known miner name or miner arguments (`stratum+tcp://`, `--donate-level`, `--randomx`).",
		"None on servers that are not meant to mine.",
		"Find how it got there (the parent process, cron, systemd units, `authorized_keys`), remove the persistence first, then the miner. Assume the credentials on the host are known.",
	},
	"process.service_shell": {
		"A web server, PHP-FPM or a database started a shell or a script interpreter. This is what a web shell or an exploited service does.",
		"CGI setups and some PHP applications that call `exec()` on purpose. Application runtimes like node, java and python are not watched as parents, because they start shells in normal operation.",
		"Look at the command line and the web server's access log at that time; search the web root for recently changed files.",
	},
	"process.download_exec": {
		"A command line that downloads and runs code in one go (`curl … | sh`, `wget … && chmod +x`, `chmod +x /tmp/…`).",
		"Installers that are run this way on purpose, for example during a deploy.",
		"Check who ran it (`uid`, parent) and what was downloaded. If nobody did, treat as an intrusion.",
	},
	"process.deleted_exe": {
		"A program started from a file that was already deleted, a common way to hide a dropped binary.",
		"Rare. A package upgrade that replaces a binary while a service restarts at the same moment.",
		"Copy the binary from `/proc/<pid>/exe` before killing the process, then investigate it.",
	},
	"process.memfd_exec": {
		"A program was started from an anonymous memory file (`memfd_create`), so it never existed on disk. Fileless malware and in-memory loaders work this way.",
		"runc up to 1.1 re-executes itself from a memfd named `runc_cloned` on every container start; that case is excluded. Some packers and sandboxes do the same.",
		"Dump the program from `/proc/<pid>/exe` before killing it, then find the parent that loaded it.",
	},
	"process.preload": {
		"A program started with `LD_PRELOAD` set, which loads a library into it before anything else. Userland rootkits and credential stealers hook functions this way. Reported once per program and library until the agent restarts.",
		"Memory allocators (jemalloc, tcmalloc), libfaketime, libeatmydata, some profilers and sandboxes. Suppress them per library with a reason.",
		"Check the library: who owns it (`dpkg -S`), when it appeared, what it exports. A library in `/tmp`, `/dev/shm` or a home directory is a strong sign of compromise.",
	},
	"process.tmp_exec": {
		"A program started from `/tmp`, `/dev/shm` or `/var/tmp`. Attackers drop tools there because every user can write to them.",
		"Build tools that run test binaries from `/tmp` (for example `go test`), installers. Suppress them per host with a reason.",
		"Check the file (`sha256sum`, `strings`), its owner and how it got there.",
	},
	"process.decode_exec": {
		"Base64-encoded content decoded and piped into a shell, a way to hide commands from logs.",
		"Rare in normal operation.",
		"Decode the payload from the command line and check what it does.",
	},
	"updates.security_pending": {
		"Security updates have been waiting for at least seven days (from `apt list --upgradable`, packages from a `-security` suite).",
		"Updates held back on purpose.",
		"Install them (`apt upgrade`) and reboot if `updates.reboot_pending` follows.",
	},
	"updates.reboot_pending": {
		"`/var/run/reboot-required` has existed for at least seven days, so a patched kernel or library is not in use yet.",
		"Hosts that are rebooted only in planned windows.",
		"Plan the reboot. Start a maintenance window in vigil first, or the agent restart alerts.",
	},
	"updates.disabled": {
		"`APT::Periodic::Unattended-Upgrade` is not enabled, so security updates wait for a person.",
		"Hosts where updates are rolled out by other tooling.",
		"Enable unattended-upgrades (`dpkg-reconfigure -plow unattended-upgrades`) or suppress with the name of the tooling that does it.",
	},
	"updates.lists_stale": {
		"The package lists have not been refreshed for at least seven days, so pending security updates are not even known.",
		"Hosts without internet access that get updates another way.",
		"Check `apt update` and the apt timers (`systemctl list-timers apt*`).",
	},
	"net.c2": {
		"A process connected to an address on the abuse.ch Feodo Tracker or ThreatFox lists, which track botnet command and control and malware delivery servers. Needs `threat_intel`.",
		"Very rare. Lists can be wrong for a short time when an address changes hands.",
		"Treat as an active compromise: find the process (`exe`, `uid`), how it was started, and isolate the host.",
	},
	"net.blocklisted": {
		"A process connected to an address on the Spamhaus DROP list (networks run by criminals). Needs `threat_intel`.",
		"Rare.",
		"Find the process and why it connects there.",
	},
	"net.tor": {
		"A process connected to a Tor exit node. Malware uses Tor to hide its command and control. Needs `threat_intel`.",
		"Hosts that run Tor or talk to services through it on purpose.",
		"Check the process. Suppress for hosts where this is expected.",
	},
	"net.miner_pool": {
		"An outbound connection to a public address on a port typical for mining pools (3333, 14433, 14444, 45560, 45700).",
		"Other software using these ports.",
		"Check the process; look for `process.miner` alerts on the same host.",
	},
	"net.service_outbound": {
		"`sshd` or a database (PostgreSQL, MySQL/MariaDB, Redis, MongoDB, Memcached) opened a connection to a public address. Databases do not do that on their own; an attacker using `REPLICAOF`, `COPY … PROGRAM` or SSH tunneling does.",
		"Database replication to a public address, SSH port forwarding used on purpose.",
		"Check the connection (`ss -tnp`), the service's log and its configuration. For Redis, check `CONFIG GET replicaof` and `dir`.",
	},
	"web.exploit_success": {
		"A request from one address matched an attack signature (SQL injection, path traversal, Log4Shell `${jndi:`, command injection, PHP wrappers, Shellshock) and the server answered with 2xx. Scans that end in 404 do not alert; they show up under attacking addresses.",
		"Applications that answer every path with 200 (single page apps with a catch-all route) turn harmless probes into 2xx. Suppress per log with a reason.",
		"Check the request in the access log and what the application did with it. A real hit usually leaves traces in the application log or the database.",
	},
	"web.shell_access": {
		"A request to a path named like a web shell (`shell.php`, `wso.php`, `c99.php`, …) was answered with 2xx.",
		"Rare. A file with such a name on purpose.",
		"Look at the file on disk, its owner and change time, and search the web root for other recently changed files. Treat as an intrusion until proven otherwise.",
	},
	"web.login_bruteforce": {
		"20 or more POST requests within one minute from one address to a path listed in `login_paths`.",
		"Load tests, or many users behind one address (a company NAT).",
		"Rate limit the login path in the web server or block the address.",
	},
	"process.rate_limited": {
		"The agent saw more suspicious program starts in one minute than it reports (60) and dropped the rest.",
		"A build or a loop that repeatedly matches a process rule.",
		"Look at the process alerts from the same minute; a flood can also hide one real event.",
	},
	"ssh.bruteforce": {
		"30 or more failed SSH logins from one address within one batch interval.",
		"Every server on the internet sees this. It is informational on its own.",
		"Nothing, if password login is off. Correlate with a later `ssh.new_source` from the same address.",
	},
	"ssh.attacker_login": {
		"A successful SSH login from an address that failed 3 or more SSH logins in the 7 days before (on any host), and either tried other user names or logged in with a password. Failures as the same user that then logs in with a key are a client offering the wrong key first and do not count.",
		"A teammate who mistyped a user name before; people behind one company or mobile network address.",
		"Treat as a successful brute force until the person confirms the login. Look at the session's commands, lock the account and block the address if nobody does.",
	},
	"ssh.key_added": {
		"A key appeared in a watched `authorized_keys` file.",
		"Onboarding a teammate or a deploy key.",
		"Check that someone on the team added it on purpose. A key added without a ticket is the most common way attackers keep access.",
	},
	"ssh.key_removed": {
		"A key disappeared from a watched `authorized_keys` file.",
		"Offboarding, key rotation.",
		"None, unless nobody removed it; then someone may be cleaning up after themselves.",
	},
	"user.added": {
		"A new account appeared in `/etc/passwd`.",
		"Package installs that create system users (for example a new service).",
		"Check which package or person created it. Interactive accounts that nobody remembers creating are a persistence mechanism.",
	},
	"user.root": {
		"An account other than root has uid 0, either new or changed to 0.",
		"None known.",
		"Treat as compromise. A second uid 0 account is a hidden root login.",
	},
	"user.removed": {
		"An account disappeared from `/etc/passwd`.",
		"Package removal, offboarding.",
		"None, unless unexpected; removing accounts can also destroy evidence or lock admins out.",
	},
	"file.preload": {
		"`/etc/ld.so.preload` was created or changed.",
		"Almost none. Very few legitimate setups use it.",
		"Treat as compromise. Any library listed there is loaded into every process, a common userland rootkit technique.",
	},
	"file.sudo": {
		"`/etc/sudoers` or a file in `/etc/sudoers.d` changed.",
		"Admin changes, package installs that add sudo rules.",
		"Read the change. New `NOPASSWD` rules for unexpected users are privilege escalation paths.",
	},
	"file.pam": {
		"A PAM configuration file in `/etc/pam.d` changed.",
		"Package updates that touch PAM.",
		"Compare with the package version. A modified PAM stack can log passwords or accept any password.",
	},
	"file.cron": {
		"A crontab or a file in a cron directory was added, changed or removed.",
		"Admins adding jobs, packages installing cron entries.",
		"Read the job. Cron entries that download or run something from `/tmp` or the network are persistence.",
	},
	"file.sshd": {
		"The SSH server configuration changed.",
		"Hardening work, package updates.",
		"Check what changed, especially `PermitRootLogin`, `PasswordAuthentication`, `AuthorizedKeysFile` and `AuthorizedKeysCommand`.",
	},
	"file.systemd": {
		"A unit file in `/etc/systemd/system` was added, changed or removed.",
		"Every service install or `systemctl enable`.",
		"Check that the unit belongs to something you installed. A new unit that runs a script from an odd place is persistence.",
	},
	"file.shell_init": {
		"A shell startup file (`/etc/profile`, `profile.d`, bashrc, `rc.local`) changed.",
		"Admin edits, packages adding environment setup.",
		"Read the change. Code in shell init files runs at every login.",
	},
	"file.accounts": {
		"`/etc/passwd`, `shadow`, `group` or `gshadow` changed without a specific account rule matching.",
		"Password changes, group membership changes.",
		"Check whether someone changed a password or added a user to a privileged group such as `sudo` or `docker`.",
	},
	"file.other": {
		"A file from `extra_watch` or another watched path changed.",
		"Depends on what you added to the watch list.",
		"Review the change.",
	},
	"port.docker": {
		"Docker published a container port on a non-loopback address. Docker writes NAT rules that are evaluated before the host firewall's input rules, so ufw and similar tools do not protect this port.",
		"Containers that are meant to be public.",
		"If the port should not be public, bind it to `127.0.0.1` in the compose file or filter it in the `DOCKER-USER` chain. Then accept the port in the dashboard.",
	},
	"port.public": {
		"A new listening port appeared on a non-loopback address.",
		"New services, programs that pick a random port on every start (game servers, Wine).",
		"Check the process. Accept the port, or all ports of the process, in the dashboard if it is expected. An unknown process listening publicly can be a backdoor.",
	},
	"port.local": {
		"A new listening port appeared on loopback.",
		"Local helper processes, debuggers, language servers.",
		"Usually harmless; check the process name.",
	},
	"canary.opened": {
		"A process opened a canary file. Canaries are decoys that no legitimate workflow touches.",
		"Backup tools, indexers, antivirus scans or an admin who forgot where the canaries are. Add tools to `canary_ignore_exe`.",
		"Treat as an intrusion until explained. The alert names the process, user and parent chain; look for the SSH session behind it.",
	},
	"canary.tampered": {
		"A canary file was deleted, replaced or modified.",
		"Cleanup scripts that delete old files in the canary's directory.",
		"Someone found the canary. Check who was logged in at the time.",
	},
	"canary.remove_failed": {
		"The agent refused to delete a canary because the file is no longer the one it created.",
		"None.",
		"Inspect the file by hand before removing it.",
	},
	"canary.overflow": {
		"The kernel dropped canary events because they arrived faster than the agent could read them.",
		"A tool that opens canaries in a tight loop.",
		"Check what is reading the canaries; some opens were not attributed.",
	},
	"agent.silent": {
		"An agent sent nothing for longer than `deadman_seconds`.",
		"Host reboots, network outages, the VPN going down.",
		"Check whether the host is up. If it is and the agent is gone, someone may have stopped it.",
	},
	"agent.stopped": {
		"An agent reported that it is shutting down.",
		"Planned restarts and updates. Announce them with a maintenance window in the dashboard.",
		"Check who stopped it if no maintenance was planned.",
	},
	"agent.restarted": {
		"An agent started again after it had run before. The alert states how long the host was unwatched.",
		"Reboots and updates outside a maintenance window.",
		"Review what happened on the host during the gap; SSH and sudo entries from the gap are reported after the restart, canary opens are not.",
	},
	"agent.update_failed": {
		"An update an admin started from the dashboard did not finish: the agent refused it (self_update off, installed from a Debian package), the download or its signature check failed, the new version did not stay up and the old one was put back, or nothing happened for 30 minutes.",
		"Hosts without internet access to GitHub; vigil-agent-update.path not enabled.",
		"Read the error. A failed signature check means the download was not the published release: find out why before trying again.",
	},
	"agent.config_rejected": {
		"An agent rejected a configuration because its signature or content did not match.",
		"None known.",
		"Someone is tampering with the traffic between agent and server, or the server key changed.",
	},
	"log.spoofed": {
		"A process other than sshd or sudo wrote a journal entry that claims to come from them.",
		"None known. `logger -t sshd` in a test script would trigger it.",
		"Someone is trying to plant fake log entries. Find the process named in the alert.",
	},
	"agent.dropped": {
		"An agent lost events because its queue was full while the server was unreachable.",
		"Long server outages.",
		"Restore the connection; consider raising `max_queue`.",
	},
	"agent.forged": {
		"The server received a batch for an agent with an invalid signature, or a replayed batch.",
		"A host whose clock jumped backwards by more than the batch interval: sequence numbers are derived from the clock.",
		"Someone is trying to inject events. Check the source address.",
	},
	"file.suid": {
		"A file became SUID or SGID, or got a capability that leads to root (`cap_setuid`, `cap_dac_override`, `cap_sys_admin` and similar), and either no package owns it, or the bit was set after its package was installed (`chmod u+s /usr/bin/find`). Existing such files are named once when the collector first runs.",
		"Software installed by hand (`make install`) that ships SUID helpers; tools that use `setcap` after installation; files below `/home` and `/root`.",
		"Check who changed the file and when (`stat`, `journalctl`). A shell, an interpreter or a GTFOBins program with the SUID bit is a backdoor: remove the bit (`chmod u-s`) and look for how root was reached.",
	},
	"file.suid_tmp": {
		"A root-owned SUID/SGID program, or one with a dangerous capability, appeared in `/tmp`, `/var/tmp` or `/dev/shm`. Nothing legitimate puts root programs there.",
		"None known.",
		"Treat as a root compromise: someone with root left a way back in. Copy the file for analysis, remove it, and investigate how root was reached.",
	},
	"file.suid_packaged": {
		"A package installed a SUID/SGID program or a file with a capability, for example `sudo` or `ping`.",
		"Every package installation that ships one. That is why this rule is low.",
		"Confirm the package installation was planned.",
	},
	"integrity.binary_replaced": {
		"A program used to log in or to inspect the system (`sshd`, `sudo`, `su`, `login`, `ps`, `ss`, `ls`, `find`, shells), a PAM module or a core library (`libc`, `ld-linux`, `libpam`, `liblzma`, `libnss_*`) no longer matches the checksum its Debian package recorded, confirmed on a second look ten minutes later. Also raised when the package's checksum list changed while the package version did not.",
		"None known on systems without prelink. Files changed with `dpkg-divert` are skipped.",
		"Assume a rootkit or a backdoor: the tools on the host may lie to you. Compare `sha256` with a clean copy of the same package version (`apt download`), inspect from a rescue system, and rebuild the host.",
	},
	"integrity.modified": {
		"Any other program in `/usr/bin`, `/usr/sbin`, `/usr/lib/openssh` or `/usr/libexec` differs from its package checksum (confirmed twice), or the checksum list changed without a package update.",
		"Programs patched by hand, files changed by a configuration tool without `dpkg-divert`.",
		"Compare with the package (`apt download`, `debsums -c`) and find out who changed it and when.",
	},
	"integrity.unowned": {
		"A new regular file appeared in `/usr/bin` or `/usr/sbin` that no package lists. Files present when the collector first ran are accepted.",
		"Software installed with `make install` or `curl | sh` into `/usr/bin` instead of `/usr/local/bin`, binaries that a package's install script generates.",
		"Check what it is (`file`, `strings`, the `sha256` on a malware database) and how it got there.",
	},
	"integrity.many": {
		"More than 25 packaged files differed from their checksums in one run. Only the first 25 are reported one by one.",
		"A broken or interrupted package installation (`dpkg --audit`), restoring files from an old backup.",
		"Run `dpkg --audit` and `debsums -c`. If no package operation explains it, treat it like `integrity.binary_replaced`.",
	},
	"posture.ssh_root_login": {
		"sshd lets root log in with a password (`PermitRootLogin yes` while password or keyboard-interactive login is on). Every brute force run on the internet tries root first. Read from `sshd -T`, or the configuration files when that fails. Alerts when the check starts failing and closes itself when it passes again; this applies to every `posture.`, `tls.`, `backup.` and `vuln.` rule.",
		"None; root with a password is never needed when keys are set up.",
		"Set `PermitRootLogin prohibit-password` (or `no`) in `/etc/ssh/sshd_config.d/` and reload sshd. Check first that your key works for root.",
	},
	"posture.ssh_password": {
		"sshd accepts passwords (`PasswordAuthentication yes`, or keyboard-interactive with PAM). Passwords can be guessed; keys cannot.",
		"Hosts where people without keys must log in. Cloud images often turn passwords on in `50-cloud-init.conf`.",
		"Give every user a key, then set `PasswordAuthentication no` and `KbdInteractiveAuthentication no` and reload sshd.",
	},
	"posture.ssh_empty_password": {
		"sshd accepts accounts with an empty password (`PermitEmptyPasswords yes`).",
		"None.",
		"Set `PermitEmptyPasswords no` and reload sshd. Check `posture.empty_password` too.",
	},
	"posture.empty_password": {
		"An account with a login shell has an empty password field in `/etc/shadow`, so `su` and the console accept it without a password.",
		"None on a server.",
		"Lock the account (`passwd -l <user>`) or set a password. Find out who emptied it: this is also how attackers keep a way back in.",
	},
	"posture.aslr": {
		"`kernel.randomize_va_space` is not 2, so memory addresses are predictable and memory corruption exploits get easier.",
		"Debugging sessions that turned it off and forgot.",
		"`sysctl -w kernel.randomize_va_space=2` and remove the setting from `/etc/sysctl.d/`.",
	},
	"posture.sysctl": {
		"A kernel setting is weaker than the usual default: `kptr_restrict`, `dmesg_restrict`, `yama.ptrace_scope`, `unprivileged_bpf_disabled`, `protected_symlinks`, `protected_hardlinks`, `suid_dumpable`, `accept_redirects`, `accept_source_route` or `tcp_syncookies`. One alert per setting.",
		"Hosts where a tool needs one of them (debuggers need `ptrace_scope` 0). Turn single checks off with `posture_skip`, for example `sysctl:kernel.yama.ptrace_scope`, or suppress with a reason.",
		"Set the value from the alert in `/etc/sysctl.d/99-hardening.conf` and run `sysctl --system`.",
	},
	"posture.permissions": {
		"A file or directory that decides what root runs or who may log in can be changed by other users (or is owned by one): `/etc/shadow`, sudoers, sshd and PAM configuration, cron, systemd units, root's SSH keys, the system `PATH` directories, or any world-writable file in `/etc`. For `/etc/shadow` and sudoers, being readable by everyone counts too.",
		"Rare. Some installers leave world-writable files in `/etc`.",
		"Fix the owner and mode (`chown root:root`, `chmod go-w`). If you did not cause it, check what was changed while it was open.",
	},
	"posture.firewall": {
		"No input chain in nftables (or iptables) drops or rejects anything, so every service that listens on a public address is reachable.",
		"Hosts filtered by a cloud firewall or a separate device. Turn the check off with `posture_skip: [\"firewall\"]` there.",
		"Set up ufw or an nftables input chain with `policy drop` and the ports you need.",
	},
	"posture.mac": {
		"Neither AppArmor nor SELinux is active, so a compromised service is not confined beyond its user.",
		"Distributions without either by default.",
		"Enable AppArmor (Debian, Ubuntu) or SELinux in enforcing mode (Red Hat family).",
	},
	"tls.expired": {
		"A certificate that nginx, Apache or Let's Encrypt uses (or one listed in `tls_certs`) has expired.",
		"Old certificates still on disk but no longer served. Remove them from the configuration.",
		"Renew it (`certbot renew`) and reload the web server. Check why automatic renewal failed (`systemctl status certbot.timer`).",
	},
	"tls.expiring": {
		"A certificate expires within 14 days. certbot renews 30 days before expiry, so this means renewal has been failing for two weeks.",
		"Certificates renewed by hand on a schedule.",
		"Run `certbot renew --dry-run` and fix what it reports, then reload the web server.",
	},
	"backup.missing": {
		"No file matches a backup location from `backups` in agent.json.",
		"A path that changed. Update agent.json.",
		"Check the backup job and its logs. A deleted backup can be the start of a ransomware attack.",
	},
	"backup.stale": {
		"The newest file of a backup location is older than its `max_age_hours`.",
		"Backup jobs that were paused on purpose.",
		"Check the backup job (`systemctl list-timers`, cron, its log) and run it by hand once.",
	},
	"backup.small": {
		"The newest backup file is smaller than its `min_bytes`, which usually means the dump failed half way.",
		"A data set that really shrank. Lower `min_bytes`.",
		"Open the file and check it is complete; run the job again and read its errors.",
	},
	"secret.exposed": {
		"A private key, API token, URL with a password, `.env` secret, `.pgpass` or `.netrc` entry is in a file every user on the host can read. A taken over web application or service runs as its own user; this is what it would read first. Only directories every user can enter are searched (daily), so secrets kept in private directories are never read. The secret itself never leaves the host: the alert names the path, the kind, the line and a short hash. One alert per file; more secrets in the same file raise its count.",
		"Sample keys in documentation or test data outside the skipped directories. Suppress per path with a reason.",
		"Make the file private (`chmod 600`, or `640` with the service's group) and rotate the secret: assume it has been read.",
	},
	"vuln.exploited": {
		"An installed package has vulnerabilities on CISA's list of vulnerabilities exploited in the wild, and the distribution has a fix. One alert per package, naming the version that fixes all of them. Needs `vuln_lookup` on the server.",
		"None; when the fix is available, install it.",
		"Update the package now (`apt install --only-upgrade <package>`) and restart what uses it (`needrestart`, or reboot for the kernel).",
	},
	"vuln.severe": {
		"An installed package has vulnerabilities of high or critical priority (the distribution's rating, or CVSS when there is none) with a fix in the archive. One alert per package. Needs `vuln_lookup` on the server; unlike `updates.security_pending` it does not wait seven days.",
		"Packages held back on purpose. The kernel: the newest installed kernel version counts, so a host that was not rebooted shows in `updates.reboot_pending` instead.",
		"Install the update (`apt upgrade`) and restart the services that use the package.",
	},
	"forward.failed": {
		"A forwarding target from `forward` (syslog, HTTP or file) has refused or not answered for ten minutes. Events and alerts wait in its queue (10 000 items) and are dropped past that.",
		"Maintenance of the receiving system.",
		"Check the target (address, certificate, token) with the error in the alert; the forwarding status is on the rules page.",
	},
	"malware.known": {
		"The SHA-256 of a program on the host (from a suspicious or new program start, an evidence snapshot or the package integrity check) is on abuse.ch MalwareBazaar or ThreatFox. Checked when the event arrives and again for the last 30 days whenever the lists grow. Needs `hash_intel` on the server.",
		"None in practice; the lists hold malware samples. A security tool or test file you placed on purpose (EICAR-like samples).",
		"Treat the host as compromised: isolate it, take an evidence snapshot if the process still runs, find how the file got there (timeline, sessions).",
	},
	"malware.yara": {
		"A YARA rule from `yara_dir` matched a suspicious or new program, a program in an evidence snapshot or a new program in a temp directory. The rule names and the description from its meta are in the alert.",
		"Broad rules (packers, generic strings) match legitimate tools. Narrow the rule or suppress it per path with a reason.",
		"Look at the matching file (`sha256sum`, the pivot page of its hash, `strings`), how it was started and what it connected to.",
	},
	"process.rare": {
		"After the learning period (`rare_learn_days`, default 7), a program ran on this host for the first time, and no package installed it. Programs in containers, in temp directories (`process.tmp_exec`) and from memory (`process.memfd_exec`) are left to their own rules.",
		"Software installed by hand, programs built on the host, new releases of tools in `/opt` or a home directory.",
		"Check where the program came from (`ls -l`, `sha256sum`, the pivot page of its hash) and who started it (the timeline around the alert).",
	},
	"process.rare_child": {
		"After the learning period, a web server, database or application runtime (nginx, Apache, PHP-FPM, MySQL, PostgreSQL, Redis, node, java, python, srcds and those in `rare_parents`) started a program it never started before. A taken over web application shows up this way before it does anything else.",
		"A new feature of the application that runs a tool, a deployment.",
		"Look at the command line and the timeline: what did the service receive just before (web log), what did the child do after.",
	},
	"ssh.rare_time": {
		"A user logged in at an hour of the day (UTC) with no logins in the hour before, at, or after it among at least 20 earlier logins. Stolen keys are often used at the attacker's time of day.",
		"Night shifts, travel, an incident.",
		"Ask the person. Check the source address on its pivot page and the session's commands.",
	},
	"net.volume_spike": {
		"A host sent more than 1 GB in one hour, three times more than in 95 % of the hours of the last two weeks and more than ever in them (needs three days of history). Data theft and a host used for attacks or as a file share look like this.",
		"Backups to another machine, large deployments, a popular download.",
		"Find who sent it: outbound connections in the timeline of that hour, the processes in an evidence snapshot.",
	},
	"net.retro_hit": {
		"A threat list now names an address that a host talked to (or that logged in, or sent web requests) in the last 30 days, before it was listed. Each address and list is reported once. Needs `threat_intel`.",
		"Addresses of shared hosting or cloud providers that were listed for someone else later.",
		"Open the event behind the alert in the timeline: which process, what happened around it, and whether the host still talks to that address.",
	},
	"kernel.bpf": {
		"An eBPF program of a type that can hook the kernel or the network path was loaded: kprobe, tracepoint, raw tracepoint, tracing (fentry/fexit), LSM, extension, perf event or XDP. eBPF rootkits such as boopkit, TripleCross and ebpfkit work this way. Programs that were loaded when the collector first ran are reported once as well, since a rootkit may already be there. The same program loaded again (same type, name and tag) stays quiet. cgroup and socket programs from systemd and Docker are not reported.",
		"Observability and security tools: bpftrace, BCC tools, Falco, Tracee, Cilium, Pixie, Parca, Datadog and similar agents, `perf`. Suppress them by name with a reason.",
		"List programs with `bpftool prog show` and find the loading process (`bpftool prog show id <id> --json` shows `pids` on recent kernels). A program nobody can explain is a strong sign of a kernel-level compromise.",
	},
	"kernel.module": {
		"A kernel module from the kernel's own tree was loaded after the agent's baseline.",
		"The kernel loads modules on demand all the time: nf_tables for firewall rules, wireguard, bridge and overlay modules for Docker, filesystem drivers. That is why this rule is low.",
		"Check that the module fits something that happened on the host at that time. A module nobody can explain is worth a closer look at the host.",
	},
	"kernel.module_unsigned": {
		"A kernel module that is out of tree (`O`), unsigned (`E`) or proprietary (`P`) was loaded, or was already loaded when the agent first ran. Kernel rootkits are out-of-tree modules.",
		"DKMS modules: ZFS, VirtualBox, NVIDIA, some VPN and backup drivers. They raise this once per host; suppress them by name with a reason.",
		"Find the module file (`modinfo <name>`) and the package that owns it (`dpkg -S`). An out-of-tree module nobody installed means the kernel is compromised: rebuild the host.",
	},
	"kernel.module_hidden": {
		"A module is live in `/sys/module` but missing from `/proc/modules` on two scans in a row. Rootkits unlink themselves from the module list to hide.",
		"None known. A module that is still loading is in state `coming`, not `live`, and is ignored.",
		"Treat the kernel as compromised. Nothing the host reports can be trusted from here on: take it offline and rebuild it.",
	},
	"kernel.tainted": {
		"New flags appeared in `/proc/sys/kernel/tainted`, for example `O` (out-of-tree module), `E` (unsigned module), `W` (kernel warning) or `D` (kernel oops).",
		"Out-of-tree drivers, kernel warnings from buggy hardware or drivers, live patching (`K`).",
		"Look at `dmesg` for the cause. Taint from a module goes together with a `kernel.module_unsigned` alert.",
	},
	"chain.broken": {
		"Verification of the hash-chained event log failed.",
		"Disk corruption.",
		"Assume someone edited the log on the server. Compare with the daily chain anchors sent to your notifiers.",
	},
	"selftest.failed": {
		"A self test left its harmless traces on a host (a comment-only file in the crontab spool or `/etc/cron.d`, a copy of `sleep` started from `/tmp`, an sshd log line written by the agent), and at least one of them was not detected, or the agent did not run the test at all.",
		"A watch list without the cron directories, the process collector turned off, an agent older than the self test feature.",
		"The alert names the step that went missing. Check the agent log (`journalctl -u vigil-agent`) for collector warnings, then run the test again from the host page. A sensor that stopped working silently, for example after a kernel update, is exactly what this catches.",
	},
	"notify.failed": {
		"A notifier could not deliver a message after three attempts. The alert goes out through all other notifiers, whatever their `min_severity`, and resolves itself with the next successful delivery.",
		"Short outages of the chat or mail service.",
		"Run `vigil-server notify test -name <notifier>` on the server. A revoked webhook, an expired token or a blocked outbound connection are the usual causes. While it fails, alerts reach you only through the dashboard and other notifiers.",
	},
}

// RuleInfo is one entry of the published rule catalogue.
type RuleInfo struct {
	ID, Severity, Technique, Title    string
	Trigger, FalsePositives, Response string
	Custom                            bool   `json:",omitempty"`
	File                              string `json:",omitempty"`
}

// Catalog lists all rules, most severe first, then by id.
func Catalog() []RuleInfo {
	out := make([]RuleInfo, 0, len(rules))
	for id, r := range rules {
		d := ruleDocs[id]
		out = append(out, RuleInfo{ID: id, Severity: r.Severity, Technique: r.Technique, Title: r.En,
			Trigger: d.Trigger, FalsePositives: d.FalsePositives, Response: d.Response})
	}
	sort.Slice(out, func(i, j int) bool {
		if severityRank[out[i].Severity] != severityRank[out[j].Severity] {
			return severityRank[out[i].Severity] > severityRank[out[j].Severity]
		}
		return out[i].ID < out[j].ID
	})
	return out
}
