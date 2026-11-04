# Platform dependencies

vigil was built and tested on Ubuntu 24.04. This page lists every place where
the code assumes Debian or Ubuntu, so a platform layer can take them over
without changing detection rules. Work happens on branch `nyra-platform`
(for Nyra, a Fedora Atomic based system); Ubuntu behaviour must stay exactly
as it is.

Inventory as of `main` f46ae14 (2026-11-04), found by searching for dpkg,
apt, unattended-upgrades, reboot-required, ufw, iptables, nft, Docker,
AppArmor, SELinux, os-release and `/boot/vmlinuz`, then reading each hit.

## Agent

| File | Function | Depends on | Purpose | Fedora Atomic counterpart |
|---|---|---|---|---|
| `packages.go` | `runPackages` | `/var/lib/dpkg/status`, `dpkgver` | installed source packages for `vuln_lookup` | `rpm -qa` (with source RPM), Flatpaks, Podman images |
| `packages.go` | `osRelease` | `/etc/os-release` | OS id, version, codename | same file, already portable |
| `integrity.go` | `packageFiles`, `dpkgVersions`, `dpkgDiversions`, `dpkgBusy`, `runIntegrity` | `/var/lib/dpkg/info/*.md5sums`, `*.list`, `diversions`, dpkg lock | checksums of packaged programs, PAM modules, core libraries | `/usr` comes read-only from the signed bootc image: compare with the deployed image (composefs/fs-verity or `ostree fsck`), detect `bootc usr-overlay`; RPM digests only outside `/usr` |
| `suid.go` | `lookupDpkg` | `/var/lib/dpkg/info/*.list` | which package owns a SUID/SGID file | owner from the RPM database; the image is the baseline, new SUID files are only possible in `/etc`, `/var`, `/home` |
| `behaviour.go` | (rarity) via `lookupDpkg` | dpkg file lists | is a new program packaged? | RPM database / image content |
| `secrets.go` | `vendoredDir` | `/var/lib/dpkg` path | skip package data in the secret search | skip `/usr` (image) and RPM-owned paths |
| `selfupdate.go` | `dpkgOwner` | dpkg file lists | was the agent installed by the .deb? | not used: on Nyra vigil ships with the image and never updates itself |
| `updates.go` | `checkUpdates`, `unattendedEnabled`, `kernelVersions` | `apt list --upgradable`, `/var/run/reboot-required`, unattended-upgrades config, `/boot/vmlinuz-*` | pending and security updates, reboot needed, automatic updates on | `bootc status --json` (staged, booted, rollback, image age), `flatpak remote-ls --updates`, automatic updates via `bootc-fetch-apply-updates.timer` |
| `ports.go` | `dockerPorts`, `ParseDockerNAT` | `iptables-save -t nat`, chain `DOCKER` | Docker publications that bypass the host firewall | Podman publishes through netavark/nftables or, rootless, through pasta (a listening socket, seen by the socket scan) |
| `posture.go` | `firewallCheck` | `nft list ruleset` or `iptables -S INPUT` | is there a firewall at all | firewalld state (`firewall-cmd --state`, default zone), nftables ruleset |
| `posture.go` | `macCheck` | AppArmor (SELinux already recognised) | mandatory access control on | SELinux enforcing; AVC denials as new events |
| `response.go` | `runNft` | `nft` | isolate and block (response actions) | `nft` works the same; ordering against firewalld's tables to check |
| `containers.go` | (top), `dockerGroup` | `/var/run/docker.sock`, group `docker` | container inventory and risky settings | Podman's Docker-compatible API: `/run/podman/podman.sock` (rootful) and `/run/user/<uid>/podman/podman.sock` (rootless, per user) |
| `behaviour.go` | `skipIface` | `docker0` | ignore Docker bridge traffic | `podman*`, `cni-*`, pasta has no interface |

## Server

| File | Function | Depends on | Purpose | Fedora Atomic counterpart |
|---|---|---|---|---|
| `vuln.go` | `matchAgent` | Canonical OVAL, Debian tracker, `dpkgver` | known vulnerabilities of installed packages | Fedora security advisories (source to be chosen: Bodhi, updateinfo or OSV), RPM version comparison, CISA KEV unchanged |
| `rules.go` | `evaluate`, `dpkgSidecar` | unattended-upgrades field, `.dpkg-new` suffixes, Docker and AppArmor findings | rule logic around the facts above | rules stay; only the facts' source changes. `.rpmnew`/`.rpmsave` join the sidecar list |
| `containers.go` | `dockerSocketPath` | Docker socket path | where the agent reads containers | see agent |
| `rules_doc.go` | (text) | names apt, ufw, iptables, AppArmor | rule catalogue wording | wording per platform where a rule mentions a tool |

## Not platform specific

Journal reading (`journalctl`), process events (netlink connector), sockets
and network (`/proc/net`), canaries (fanotify), kernel modules, eBPF,
SSH sessions, file watching, the protocol and the whole server apart from
`vuln.go`: these use the kernel, systemd or vigil's own state and work on
Fedora as they are. To be confirmed by running the test suite and the self
test on Fedora Atomic.

## Plan

1. A `platform` package with one interface for the rows above; the current
   code moves unchanged into `platform/debian`. Selected from
   `/etc/os-release`, overridable in `agent.json`.
2. Golden tests: the same inputs give the same events before and after the
   move.
3. `platform/fedoraatomic` row by row, each with a probe that must raise the
   matching alert on a Nyra VM.
