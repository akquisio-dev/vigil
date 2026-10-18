# Threat model

This document states what vigil is built to withstand and where it stops.
Issues and reviews against it are welcome.

## Assets

1. The truth about what happened on each host (the event log).
2. Timely alerts when something bad happens.
3. The hosts themselves: vigil must not make them weaker.

## Attackers

| Attacker | Example |
|---|---|
| Internet scanner | brute-forces SSH, probes ports |
| Targeted outsider | gains a foothold on one host and tries to stay |
| Insider | has, or had, legitimate access and abuses it |
| Network attacker | sits between agent and server |

## What vigil promises

**An attacker who gets root on a monitored host cannot silently erase what
the agent already sent.** Events leave the host every interval. Editing
state files on the host only changes what the agent compares against next
time.

**Stopping the agent is never quiet.** A clean stop raises a high alert, a
kill raises the dead man's alert, and every restart raises a high alert with
the length of the gap. None of these is softened by anything the agent
reports; only a maintenance window set in the dashboard (and recorded in the
log) suppresses them. SSH and sudo entries written during the gap are read on
restart from the saved journal cursor. Canary opens during the gap are not
seen; the restart alert is the signal.

This holds against an attacker who stops or kills the agent. It does not
hold against one who reads the agent key from `identity.json` and replaces
the agent with an impostor that keeps sending heartbeats. From that point
the host is lying, as with any host-based sensor; see below.

**Log lines cannot be faked by other processes.** Any local user can write
an entry that claims to come from `sshd`. The agent only trusts entries whose
journald-assigned `_COMM` and `_UID` match sshd or sudo running as root, and
reports the rest as spoofed.

**A network attacker cannot forge or replay agent traffic.** Batches are
signed with a per-agent ed25519 key created at enrollment; sequence numbers
only grow. Configurations from the server are signed with the server key the
agent pinned at enrollment. Plain HTTP over a VPN is acceptable for this
reason; confidentiality then depends on the VPN.

**A compromised server cannot use agents to take over hosts.** The only
instruction the server can give is "place canary of type T at path P" or
"remove canary C". The agent enforces locally configured roots, generates
the content, refuses symlinks on the whole path, refuses names and suffixes
that would be executed or used for login, never overwrites and deletes only
its own unchanged files. Agents execute nothing the server sends. A self test
request carries only a random id: the agent writes a fixed comment into a cron
directory (never replacing a file), runs its own copy of `sleep 1` and writes
one log line, then removes both files.

**Edits to the event log are detectable.** Each record carries the hash of
the previous one. Changing, inserting or removing a record breaks every
following hash. With `anchor_daily`, the chain head is posted outside the
server once a day, so even a full rewrite of the chain by a root attacker on
the server conflicts with the anchors already sent.

**The dashboard resists credential attacks.** Passkeys (WebAuthn, with user
verification required, origin, relying party and signature counter checked)
or password plus TOTP for every user, PBKDF2-SHA256 with 600,000 iterations,
constant-time comparison,
equal timing for unknown users, a used TOTP step is never accepted twice,
login rate limiting per address and per user, HttpOnly + SameSite=Strict
cookies, CSRF token on every change, strict CSP, no inline script, and
agent-supplied strings are only rendered as text. Roles limit what an
account can change (viewer, analyst, admin). Adding a passkey, changing the
password and managing users need a fresh TOTP code. Every request checks the
user file, so removing a user or lowering a role ends its access at once, and
a password change ends the user's other sessions.

## What vigil does not promise

- **Prevention.** vigil detects and alerts. It does not block processes or
  network traffic. Pair it with a firewall, fail2ban or CrowdSec.
- **Visibility after a host is fully owned.** Once an attacker has root on a
  host, everything that host reports afterwards may be lies. The value is in
  what was reported before, and in the silence alert.
- **Protection of the server host.** Whoever controls the server sees all
  events and can suppress future alerts. Run it on a separate machine if you
  can, restrict the dashboard to known networks, and use `heartbeat_url`
  with an outside service so a dead server is noticed.
- **Kernel-level rootkits.** A rootkit can hide files, sockets and processes
  from the agent.
- **Every malicious program start.** Process monitoring sees each exec, but
  reports only starts with a known suspicious trait. Code that runs inside an
  existing process (an exploited interpreter, injected shellcode) starts
  nothing new. Reverse shells in containers are found by their command line;
  the socket check only sees the host's network namespace.
- **Every outbound connection.** Connections are sampled every ten seconds,
  so very short ones can be missed, and a destination network already used
  by a legitimate program on the same port is not reported again.
- **Vulnerability matching.** vigil reports pending security updates and
  reboots, not which CVEs apply to the installed versions.
- **Secrecy of the detection logic.** The code is public by design. Canary
  locations, thresholds and ignore lists belong in your private
  configuration; knowing *that* canaries exist does not tell anyone *which*
  file is one.

**Response actions are bounded.** Enabling them lets the dashboard change a
host, so a compromised server could block addresses, end sessions, stop
processes and remove SSH keys there. Each host decides in its own
`agent.json` whether and which actions it accepts; `never_block` protects the
admins' addresses; the last key of an `authorized_keys` file is never
removed; actions expire after ten minutes and run at most once; and none of
them runs arbitrary commands. Hosts where this risk is not acceptable leave
`response` off.

**Updates from the dashboard run only published releases.** With
`self_update` on in its own `agent.json`, an agent accepts a version number
from the server, nothing more. It builds the download address for the
official repository itself, accepts only a release newer than its own (old
releases are signed too, so this stops a rollback to a known weak version),
and checks the Sigstore signature of `SHA256SUMS` itself: the certificate must
chain to the Fulcio root at the time the transparency log recorded it, be
issued to this repository's release workflow for exactly that tag, the
signature must match, and Rekor's signed entry timestamp must be about this
file, this signature and this certificate. The installer
(`vigil-agent-update.service`) is the installed binary and checks everything
again before it replaces itself. A compromised server can make hosts update
to the newest release, which they would also get by hand, and nothing else.

## Known weak spots

- Enrollment tokens are bearer secrets valid for one hour and one use. Hand
  them over on a trusted channel.
- Behind a CDN or a second proxy, make sure the address the dashboard sees
  is the client's (for example nginx `real_ip_header CF-Connecting-IP` with
  the CDN's ranges in `set_real_ip_from`), or rate limits and audit records
  show the CDN.
- `trust_proxy` must only be enabled when the dashboard listener is reachable
  exclusively through the proxy, otherwise clients can spoof their address
  for rate limiting and audit records.
- Dashboard sessions live in memory; restarting the server logs everyone out.
- The agent needs broad privileges (root with a reduced capability set) to
  read what it watches. The systemd unit drops everything it does not need.
- While a self test runs, its random id is visible to local users on the
  host for a few seconds (in `ps` and `/tmp`). Knowing it does not help: the
  server only swallows a finding when its rule is one of the three step rules
  and the event has the exact shape of the agent's own trace (the exact file
  name in a root-only cron directory, `sleep` run as uid 0 from the test
  directory with no other signal, a log line written by root). Every other
  finding, critical ones included, raises its alert as usual. Faking the
  exact traces needs root, and root could stop the agent instead, which is
  never quiet.
- Package integrity trusts the Debian checksum lists on the host. An
  attacker with root who replaces a binary *and* its md5sums entry is caught
  only because the agent keeps its own SHA-256 inventory and reports a
  checksum list that changed without a package update. If that happens
  before the agent's first run, or together with a fake version bump in the
  dpkg status file, it is not seen. For certainty, compare with a clean copy
  from the package mirror.
- The SUID walk runs every six hours (temp directories every five minutes),
  so a SUID file that exists only between two walks is missed. Program starts
  from it are still seen by the process collector.
- Hidden kernel modules are found by comparing `/proc/modules` with sysfs. A
  rootkit that removes itself from both is not found this way; the taint flags
  and the module load itself (`kernel.module_unsigned`) are the remaining
  signals, and only if the agent was running at that moment.
- eBPF programs that the kernel loads itself at boot (`hid_tail_call`, the
  bpf_preload iterators) are ignored when loaded in the first two minutes
  after boot.
- Program starts are read from `/proc` after the kernel reports them. A
  program that exits within a millisecond or two can be gone before the agent
  looks, and is then not reported.
- Notifiers are the only way alerts leave the server on their own. If all of
  them fail, `notify.failed` is visible only in the dashboard; the outside
  heartbeat does not cover delivery.
- Vulnerability matching knows only what the distribution packaged. Software
  installed by hand, from language package managers (npm, pip, Go modules),
  in containers or snaps is not matched. The kernel counts by the newest
  installed version; a host that was not rebooted runs an older one, which
  `updates.reboot_pending` reports.
- The secret search reads only files that every user can read, in
  directories every user can enter, up to 512 KB, and skips vendored code
  (`node_modules`, `vendor`, test fixtures). Secrets readable by a single
  service user or a group are not reported, and neither are formats without
  a recognisable shape.
- Hardening checks describe settings, not what an attacker already changed in
  memory; a weakened sshd that reads another configuration file than the one
  `sshd -T` shows is not seen.
- Evidence snapshots are taken after the fact: for the agent's own signals
  within about a second, for server requests within a minute. A process that
  exited before is described from the process event alone. A snapshot shows
  what `/proc` shows; a rootkit that hides processes from `/proc` hides them
  from the snapshot too.
- Change contents are only as old as the agent's copy of the file. Lines the
  redaction does not recognise as secrets are sent as they are; keep secrets
  out of the watched files or turn the file out of the watch list.
- Session commands are read from `/proc` when the kernel reports the start;
  commands that finish within a millisecond or two (`id`, `uptime`) are
  often gone by then and missing from the session. `sudo` commands come from
  the journal and are always complete.
- Session commands are what was started from the session's shell; what a
  script started further down is not listed, and a session older than the
  agent's start is not tied to its commands. Someone with root in the
  session can detach a process from both the parent chain and the audit
  session.
- Hash matching knows what abuse.ch has seen; new or rebuilt malware has
  hashes no list knows. YARA rules find what they describe and nothing
  else, and only in programs vigil looks at (suspicious, new, in temp
  directories, in snapshots).
- Forwarded data leaves the server as it is, change lines and command lines
  included; the receiving system must be protected like the server.
- Rarity learns what runs during the first seven days. Anything an attacker
  already ran then counts as normal; the other rules still apply to it.
- Response actions are only as safe as the server: with response enabled, a
  taken over server can isolate hosts, lock accounts and stop processes
  (never run commands). Four-eyes needs a second admin's TOTP code, which a
  server compromise alone does not give, but an attacker with root on the
  server can change server.json. Agents limit the damage on their side:
  only the types in `allow`, never root or `never_lock`, never without a
  reachable `isolate_allow`, and everything ends by itself.
- Playbooks act on alerts, and alerts can be provoked. A playbook that
  isolates hosts is a way to take them offline for its duration.
