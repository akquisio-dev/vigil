# vigil

A small security operations center for small server fleets.

vigil watches one to a few dozen Linux servers with one agent per host and one
central server. It has no external dependencies, so it runs next to the workload
it watches instead of needing a cluster of its own.

<div class="grid cards" markdown>

-   **Get started**

    Install the server, enroll the first host, see the first alert.

    [Installation](getting-started.md)

-   **Detection rules**

    Every rule with severity, ATT&CK technique, false positives and what to do.

    [Rule catalogue](rules.md)

-   **Canaries**

    Decoy files that no legitimate workflow opens, and where to place them.

    [Canary guide](canaries.md)

-   **Threat model**

    What vigil protects against, and where it stops.

    [Threat model](threat-model.md)

</div>

## What it watches

| Area | Examples |
|---|---|
| SSH access | logins with key name and source address, password logins, keys outside `authorized_keys`, new source addresses, brute-force waves |
| Persistence | `authorized_keys`, cron, systemd units, sudoers, PAM, shell init files, `ld.so.preload` |
| Accounts | new accounts, accounts that gain uid 0 |
| Exposure | new listening ports, Docker publications that bypass host firewalls |
| Processes and kernel | reverse shells, miners, programs from memory or `/tmp`, `LD_PRELOAD`, hidden kernel modules, eBPF hooks |
| Tampered software | replaced packaged programs, PAM modules and libraries, new SUID programs |
| Prevention | known and exploited vulnerabilities in installed packages, weak SSH and kernel settings, unsafe permissions, missing firewall, expiring certificates, stale backups, secrets every user can read |
| Malware | programs matched against known malware hashes, YARA and Sigma rules |
| Canaries | decoy credentials, `.env` files, SSH keys and SQL dumps |
| Investigation | incident reports, SSH sessions with every command, search over the whole log, timelines, pivots, evidence snapshots |
| Attackers | country and network of every address on a world map, campaigns, aimed attacks told apart from mass scanning |
| vigil itself | agents that stop, restart or go silent, forged agent traffic, fake log lines, edits to the event log |

## Footprint

| | Agent | Server |
|---|---|---|
| Memory | about 10 to 20 MB | about 15 MB plus the event window; about 100 MB with all threat data and `geoip` |
| Network | outbound only | dashboard on loopback, agent API on a VPN address |
| Dependencies | none (Go standard library) | none |

## Status

vigil is young. The features above work and run on Ubuntu 22.04 and 24.04, but the project has not had an external audit. Run it next to your
existing controls, not instead of them.
