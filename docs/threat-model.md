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
the agent already sent.** Events leave the host every interval. Stopping the
agent produces a stop event or, if killed, a dead man's alert. Editing state
files on the host only changes what the agent compares against next time.

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

**The dashboard resists credential attacks.** Password plus TOTP for every
user, PBKDF2-SHA256 with 600,000 iterations, constant-time comparison,
equal timing for unknown users, a used TOTP step is never accepted twice,
login rate limiting per address and per user, HttpOnly + SameSite=Strict
cookies, CSRF token on every change, strict CSP, no inline script, and
agent-supplied strings are only rendered as text.

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
- **Secrecy of the detection logic.** The code is public by design. Canary
  locations, thresholds and ignore lists belong in your private
  configuration; knowing *that* canaries exist does not tell anyone *which*
  file is one.

## Known weak spots

- Enrollment tokens are bearer secrets valid for one hour and one use. Hand
  them over on a trusted channel.
- `trust_proxy` must only be enabled when the dashboard listener is reachable
  exclusively through the proxy, otherwise clients can spoof their address
  for rate limiting and audit records.
- Dashboard sessions live in memory; restarting the server logs everyone out.
- The agent needs broad privileges (root with a reduced capability set) to
  read what it watches. The systemd unit drops everything it does not need.
