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
	"ssh.bruteforce": {
		"30 or more failed SSH logins from one address within one batch interval.",
		"Every server on the internet sees this. It is informational on its own.",
		"Nothing, if password login is off. Correlate with a later `ssh.new_source` from the same address.",
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
	"chain.broken": {
		"Verification of the hash-chained event log failed.",
		"Disk corruption.",
		"Assume someone edited the log on the server. Compare with the daily chain anchors sent to your notifiers.",
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
