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
| Canaries | decoy credentials, `.env` files, SSH keys and SQL dumps |
| vigil itself | agents that stop, restart or go silent, forged agent traffic, fake log lines, edits to the event log |

## Footprint

| | Agent | Server |
|---|---|---|
| Memory | about 10 to 25 MB | about 10 MB plus the event window |
| Network | outbound only | dashboard on loopback, agent API on a VPN address |
| Dependencies | none (Go standard library) | none |

## Status

vigil is young. The features above work and run on Ubuntu 22.04 and 24.04, but the project has not had an external audit. Run it next to your
existing controls, not instead of them.
