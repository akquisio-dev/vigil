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
its own unchanged files. Agents execute nothing the server sends.

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
