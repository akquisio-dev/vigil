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
| `integrity.go` | `packageFiles`, `dpkgVersions`, `dpkgDiversions`, `dpkgBusy`, `runIntegrity` | `/var/lib/dpkg/info/*.md5sums`, `*.list`, `diversions`, dpkg lock | checksums of packaged programs, PAM modules, core libraries | `/usr` comes read-only from the signed bootc image: compare with the deployed image (composefs/fs-verity or `ostree fsck`), detect `bootc usr-overlay`. Done as `rpm -Va` over `/usr` plus the `usr_overlay` posture check, see [Integrity on fedoraatomic](#integrity-on-fedoraatomic) |
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

## Platform layer

`internal/agent/platform.go` defines `Platform`, grouped by what it answers:

| Part | Methods | Rows above |
|---|---|---|
| `Packages` | `PackageDBStamp`, `SourcePackages`, `Busy`, `PackagedFiles`, `NoPackageDB`, `Owners`, `SelfOwner` | packages, integrity, SUID owner, rarity, self update |
| `Updates` | `PendingUpdates`, `RebootRequired`, `KernelVersions`, `AutoUpdates`, `ListsAgeDays` | updates |
| `Posture` | `FirewallCheck`, `MACCheck`, `PublishedPorts` | firewall, MAC, Docker NAT |
| `Containers` | `ContainerSocket`, `ContainerAdmins` | container inventory, docker group |

- `platform_debian.go` is Debian and Ubuntu. It wraps the functions vigil already had, in place, so the diff stays
  small; `platform_golden_test.go` pins their results on a fixture tree (`sysRoot`), written before the layer
  existed.
- `platform_fedoraatomic.go` is image based Fedora (Fedora Atomic, bootc, Nyra), see below.
- Selection: `platform` in `agent.json` if set (an unknown name is a config error), else the first `ID` or
  `ID_LIKE` value of `/etc/os-release` that names a known platform, else `debian`, which is what vigil did before.
  `fedora` names `fedoraatomic` only when `/run/ostree-booted` exists; a classic Fedora with dnf has no platform
  of its own yet and falls back to `debian` (no package inventory, no update facts, as before).
- Left generic on purpose: the interface skip list (`skipIface`) and the secret-search skip lists. The Fedora
  entries (`podman*`, image paths) are added to those lists directly. Trees that only exist on one platform and
  would make every file walk see things twice are the platform's (`fileWalkLayout`, below).

## The fedoraatomic platform

For Fedora bootc and Atomic systems such as Nyra (Fedora bootc 44): `/usr` comes read-only from a signed
image, the rpm database describes that image, bootc stages updates, Podman replaces Docker and SELinux is the
access control. Host tested only so far (fixture tree and canned `rpm` and `bootc` output in
`platform_fedoraatomic_test.go`); every row still needs its probe on a Nyra VM.

| Method | What it does |
|---|---|
| `PackageDBStamp` | mtime of `/usr/lib/sysimage/rpm/rpmdb.sqlite`, else `/var/lib/rpm`. Constant between reboots, since the database only changes with a new deployment |
| `SourcePackages` | `rpm -qa --queryformat '%{SOURCERPM}\t%{EPOCH}:%{VERSION}-%{RELEASE}\n'`, source name cut from the `.src.rpm` file name, newest version per source (installonly kernels), `gpg-pubkey` skipped |
| `Busy` | always false: an image update is written to a new deployment, `/usr` never changes in place |
| `PackagedFiles` | empty: integrity is `rpm -Va` instead (`VerifyPackages`, see below). Only without rpm the platform says integrity is unsupported, and `runIntegrity` sends one `agent.warning` and stops |
| `Owners`, `SelfOwner` | `rpm -qf --queryformat '%{NAME}\n'`, one call per path (a file owned by two packages prints two lines, an unowned one a message). Without an rpm database owners are unknown, not empty. No install time, no stat overrides |
| `PendingUpdates` | `bootc status --json`: a staged deployment, or a fetched but unstaged `cachedUpdate`, is one pending update named `image <version>`, never counted as security. Not supported without bootc or a booted deployment |
| `RebootRequired` | a staged deployment exists; packages `["image <version>"]` |
| `KernelVersions` | running from uname, newest from `/usr/lib/modules/*/vmlinuz` of the booted image |
| `AutoUpdates` | `bootc-fetch-apply-updates.timer` linked in `timers.target.wants` under `/etc` or `/usr/lib`, and not masked |
| `ListsAgeDays` | -1: there are no package lists |
| `FirewallCheck` | `firewallCheck` (firewalld writes nftables rules) |
| `MACCheck` | SELinux only, from `/sys/fs/selinux/enforce`: enforcing, permissive, or disabled when missing. Same values as `macCheck` |
| `PlatformChecks` | posture check `usr_overlay`: fails when `bootc status --json` has a non-null `status.usrOverlay` (after `bootc usr-overlay`), value like `accessMode=readWrite persistence=transient`; raises `posture.usr_overlay` (high). No check without bootc |
| `PublishedPorts` | none yet |
| `ContainerSocket` | `/run/podman/podman.sock` (rootful Podman, Docker-compatible API, needs `podman.socket`) |
| `ContainerAdmins` | none: the rootful socket belongs to root, no group grants it |
| `WalkSkip`, `RootFSTypes` | file walks (`fileWalkLayout`), see below |

### File walks on fedoraatomic

`/sysroot` is the physical root: the ostree repository and every deployment, each a hard linked checkout of an
image's `/usr`; `/ostree` links to it. The SUID scan walked it as a mount point of its own and reported every
setuid and capability program a second time, as `/sysroot/ostree/deploy/default/deploy/<checksum>.0/usr/bin/chage`
and so on, "no package owns it" (Nyra VM, 2026-11-05). On this platform both trees are skipped as roots and below
roots by the SUID and capability scan (full and quick walk) and the secret search; `/usr` is walked through `/`.
With composefs, Fedora bootc's default, `/` is an `overlay` mount, which the scan does not take as a root
elsewhere; here it does, and stops at the other mount points as usual. Entries an older agent recorded under the
skipped trees are dropped from `suid.json` without a `file.suid_removed`. The other walks never reach them: the
application inventory walks `/opt`, `/srv`, `/var/www`, `/home` and `/root` without leaving their file system, the
temp directory scan walks `/tmp`, `/var/tmp`, `/dev/shm`, posture walks `/etc`. On Debian nothing changes.

### Open findings from the clean image

A clean Nyra VM (2026-11-05) raised `process.tmp_exec` three times: `/tmp/.tmpWqNpWy`, `/tmp/.tmpPtoRum`,
`/tmp/.tmp9vOwQ6`, uid 0. `.tmp` and six letters is the naming of Rust's `tempfile` crate, and the path is a file
that was executed, not a directory. Not explained yet and not allowed: the alert stays. Program starts now carry
`cgroup`, `unit` and `mnt_ns_private` (see [architecture](architecture.md)), next to `exe_sha256`, `cmdline`,
`parent_exe` and `parent_comm`, so the next run shows which unit runs it and whether it is a copy of a program
of the image (compare `exe_sha256` with `/usr/bin` and `/usr/libexec`). In a unit with `PrivateTmp=` the file
lies in `/tmp/systemd-private-*-<unit>-*/tmp` on the host while `/proc` shows `/tmp/...`; `mnt_ns_private`
together with a `unit` marks that case.

### Integrity on fedoraatomic

`integrity_rpm.go`. `rpm -Va --nomtime --nodeps --noscripts` verifies every file of every installed package
against the rpm database, which on an image system describes the image. `--noscripts` keeps rpm from running the
packages' `%verifyscript` as root, `--nodeps` from printing dependency problems. The run happens at the usual
integrity times (five minutes after start, then every six hours, a second run ten minutes after one that found
something), with a limit of 30 minutes, at the agent's own priority (the unit sets `Nice=10` and idle I/O). rpm
exits 1 whenever it reports a difference, so an exit status with output is a result; no output with an error, a
kill or the time limit is an `agent.warning`, not a clean run.

What counts, per line (`SM5DLUGTP` flag field, optional one-letter marker such as `c d g l r`, path; or `missing`). Only `c` and `g` change what counts:

| Line | Counts | Why |
|---|---|---|
| path outside `/usr` (`/etc`, `/var`, `/run`, `/boot`) | never | ostree merges `/etc` on every update (old defaults, new defaults, local changes): changed content, modes and owners there are the admin's. `/var` and `/run` are not part of the image |
| `T` (mtime) | never | ostree normalises every timestamp, so without `--nomtime` every file shows `T` (seen on a Nyra VM: the only flag in the whole output). Ignored even if an rpm prints it with `--nomtime` |
| `?` | never | could not be checked (unreadable) |
| marker `g` (ghost) | never | not shipped in the package |
| `S`, `5` | yes, except for config files (`c`) | content of a read-only `/usr` file changed. Config file content is ignored everywhere, as rpm intends |
| `M`, `U`, `G`, `P`, `L`, `D` | yes, config files too | mode, owner, group, capabilities, link target or device of a file the image ships |
| `M` alone on a directory | only if group or world writable now | a clean Nyra image reports `.M` for many directories (`/usr/bin`, `/usr/lib`, `/usr/lib64/...`, `/usr/share/empty`): ostree stores directories with its own permission bits (seen on a Nyra VM, 2026-11-05) |
| `missing` | yes | a file the image ships is gone |

The reference is the image as built, not the rpm database. Image builds remove and change packaged files on
purpose: a clean Nyra image (2026-11-05) still showed 99 suspects after the rules above, 11 `missing` files the
bootc base image removes (grub units, `systemd-firstboot.service` in `sysinit.target.wants`, `tmpfiles.d/home.conf`,
the `systemd-logind.service.d` grub snippet), `S.5` on `/usr/lib/tmpfiles.d/provision.conf` and
`/usr/lib/kernel/install.conf`, and about 85 `S.5`/`..5` on `/usr/lib64/python3.14/__pycache__/*.pyc` (bytecode
compiled again by the build). So the agent keeps a baseline per booted image:

- The image is `status.booted.image.imageDigest` from `bootc status --json`, else `ostree:` and
  `status.booted.ostree.checksum`. Without bootc the image is unknown: an existing baseline is kept, none is taken,
  and every suspect counts as above.
- The first run on an image it has no baseline for records every suspect (path, flags, SHA-256 of the file now)
  as that image's baseline, reports none of them and sends one `integrity.baseline` (info, no alert) with `image`,
  `suspects`, `missing`, `changed` and `seconds`. Findings reported for an earlier image are forgotten.
- Later runs drop a suspect only when the baseline has the same path with the same flags and SHA-256. A new
  suspect, or a baselined file whose flags or content changed, is a finding as before (confirmed by a second run,
  capped, reported once). `integrity.scan` carries `baseline`, the number of baselined files.
- A new image (update, rollback) starts a new baseline. While `usrOverlay` is set no baseline is taken (what was
  changed through the overlay would become the reference) and the old image's baseline does not apply: every
  suspect counts, next to the `usr_overlay` alert.
- Limit: a change made to `/usr` before the first run on a new image is part of its baseline. The image itself is
  signature checked by bootc when it is pulled (Nyra's ADR), `/usr` is read-only, and a writable `/usr` raises
  `posture.usr_overlay`, so such a change needs tampering below the file system before the agent's first run,
  five minutes after start.
- Kept in `integrity-rpm.json`, version 2 (`version`, `image`, `baseline`, `reported`); a file without a version
  keeps its reported findings and gets a baseline on the next run that knows the image. At most 20000 baselined
  files; past that the rest counts as findings.

A finding becomes `integrity.mismatch` (critical names like `sshd`, `ps`, PAM modules and libc via
`integrityIsCritical` give `integrity.binary_replaced`, the rest `integrity.modified`) with `flags`, a reason such
as "differs from the rpm database (size, digest)", the SHA-256 and size of the file now, and package and version
from `rpm -qf`. It is reported only when the second run still shows it, at most 25 per run, then one
`integrity.many`. Each finding is reported once: `integrity-rpm.json` in the state directory remembers its flags
and SHA-256, it is reported again when these change, and forgotten when the file verifies clean. Debian's
`integrity.json` and its loop are untouched. `integrity.unowned` is not raised on this platform yet (see open).

Open:

- Measured on a Nyra VM (Fedora 44, 544 packages) in a transient unit with the agent's limits (`MemoryMax=96M`,
  `MemoryHigh=64M`, `CPUQuota=15%`, idle I/O, `ProtectSystem=full`): rpm opened its database and finished in 92 s
  with 13.8 s CPU, memory peak 64.5M (held at `MemoryHigh`), no OOM kill. Besides directory modes the clean image
  printed `missing /afs`, `missing /var/lib/selinux/tmp`, `.M` on `/boot`, `/opt`, `/root` and a changed
  `/etc/selinux/semanage.conf` (`c`), all outside `/usr`. Still open: the run inside the real vigil-agent unit and
  the shape of a non-null `usrOverlay`.
- New programs in `/usr/bin` that no rpm owns (`integrity.unowned`): needs `rpm -qal` and a baseline that is reset
  when the booted image changes, because images add files outside rpm (`COPY` in the Containerfile).
- The image itself: `ostree fsck` or composefs/fs-verity, which also cover files no rpm owns.
- Rootful Podman publications through netavark's nftables table (they can bypass the input filter like Docker's
  DNAT). Rootless ones go through pasta and are listening sockets the socket scan sees.
- Rootless Podman sockets under `/run/user/<uid>/podman/`.
- Vulnerability matching: the server only knows Ubuntu and Debian data. `releaseKey` gives no release for
  `fedora`, so a Fedora host's RPM list is kept for display and the host shows "unsupported" instead of being
  matched against Debian or Ubuntu data (pinned by `TestVulnFedoraIsNotMatched`). Fedora advisories and an RPM
  version comparison are to be added; the agent picks the newest version per source with dpkg's comparison,
  which differs from rpm's only for `^`.
- Self update refusal still says "Debian package ...; update it with apt" when rpm owns the agent. On Nyra the
  agent ships with the image anyway.
- `.rpmnew`/`.rpmsave` in the sidecar list, `podman*` interfaces in `skipIface`, image paths in the secret search
  skip list, rule wording per platform.

## Plan

1. Done: golden tests, then the `Platform` interface with `debian` behind it, selected as above.
2. Server side (`vuln.go`, `rules.go`) stays as it is until a second platform sends different facts.
3. `fedoraatomic` row by row, each with a probe that must raise the matching alert on a Nyra VM. Done on the
   host (fixtures and canned command output), the probes on a VM are open.
