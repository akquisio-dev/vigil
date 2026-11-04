package agent

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// Platform answers the questions whose answer depends on the distribution:
// where packages come from, how updates arrive, which firewall and access
// control are in use, and which container runtime runs. Detection rules
// stay the same on every platform; only the facts they read change. See
// docs/platform.md.
type Platform interface {
	Name() string
	Packages
	Updates
	Posture
	Containers
}

// Packages is the package database: inventory, checksums, owners.
type Packages interface {
	// PackageDBStamp is when the package database last changed; an error
	// means there is none.
	PackageDBStamp() (time.Time, error)
	// SourcePackages lists source packages with their newest installed
	// version, as the server's vulnerability matching expects them.
	SourcePackages() []srcPkg
	// Busy reports a package transaction in progress or interrupted.
	Busy() bool
	// PackagedFiles maps files in integrity scope to their expected checksum.
	PackagedFiles() map[string]pkgEntry
	// NoPackageDB is the warning text when PackageDBStamp fails.
	NoPackageDB() string
	// Owners names the package of each path that belongs to one.
	Owners(paths []string) dpkgInfo
	// SelfOwner names the package that installed the agent at exe, if any;
	// such an agent is updated by the package manager, not by itself.
	SelfOwner(exe string) string
}

// Updates is how the system gets new software.
type Updates interface {
	// PendingUpdates lists pending updates. supported is false when the
	// tool is missing (then nothing is reported at all).
	PendingUpdates(ctx context.Context) (list []aptPending, supported bool, err error)
	RebootRequired() (required bool, packages []string)
	KernelVersions() (running, newest string)
	AutoUpdates() bool
	// ListsAgeDays is the age of the update metadata, -1 when unknown.
	ListsAgeDays(now time.Time) int
}

// Posture is the host firewall and mandatory access control.
type Posture interface {
	FirewallCheck() []postureCheck
	MACCheck() []postureCheck
	// PublishedPorts are container publications that bypass the host's
	// input firewall and may not show up as listening sockets.
	PublishedPorts() []Port
}

// Containers is the container runtime's API socket and who controls it.
type Containers interface {
	ContainerSocket() string
	// ContainerAdmins are members of the group that may use the socket.
	ContainerAdmins(groupFile string) []string
}

// platforms by name; detect maps os-release ID and ID_LIKE values to them.
var platforms = map[string]func() Platform{
	"debian":       func() Platform { return debianPlatform{} },
	"fedoraatomic": func() Platform { return fedoraAtomicPlatform{} },
}

// detection maps an os-release value to a platform, if when (nil: always)
// holds.
type detection struct {
	name string
	when func() bool
}

// Fedora maps to fedoraatomic only when image based (ostree or bootc). A
// classic Fedora with dnf has no platform of its own yet and falls back to
// debian like any unknown system: no package inventory, no update facts.
var detect = map[string]detection{
	"debian": {"debian", nil}, "ubuntu": {"debian", nil},
	"fedora": {"fedoraatomic", ostreeBooted},
}

// integrityUnsupported is implemented by platforms without file checksums
// in their package database; runIntegrity then warns once and stops.
type integrityUnsupported interface {
	IntegrityUnsupported() string
}

// choosePlatform picks the platform: the configured one if set (it must
// exist), else the first os-release ID or ID_LIKE entry we know, else
// debian, which is what vigil did before platforms existed.
func choosePlatform(configured, id, idLike string) (Platform, error) {
	if configured != "" {
		mk, ok := platforms[configured]
		if !ok {
			return nil, fmt.Errorf("unknown platform %q (known: %s)", configured, strings.Join(platformNames(), ", "))
		}
		return mk(), nil
	}
	for _, cand := range append([]string{id}, strings.Fields(idLike)...) {
		if d, ok := detect[cand]; ok && (d.when == nil || d.when()) {
			return platforms[d.name](), nil
		}
	}
	return platforms["debian"](), nil
}

func platformNames() []string {
	var n []string
	for k := range platforms {
		n = append(n, k)
	}
	sort.Strings(n)
	return n
}

// osReleaseIDs reads ID and ID_LIKE from os-release.
func osReleaseIDs(path string) (id, idLike string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"'`)
		switch k {
		case "ID":
			id = v
		case "ID_LIKE":
			idLike = v
		}
	}
	return id, idLike
}

// platformFor resolves the platform for cfg. A config naming an unknown
// platform is refused by LoadConfig, so this cannot fail here.
func platformFor(cfg *Config) Platform {
	conf := ""
	if cfg != nil {
		conf = cfg.Platform
	}
	id, like := osReleaseIDs(sysPath("etc/os-release"))
	p, err := choosePlatform(conf, id, like)
	if err != nil {
		return debianPlatform{}
	}
	return p
}

// plat is the agent's platform; agents built in tests without New get the
// one detected for their config.
func (a *Agent) plat() Platform {
	if a.platform == nil {
		a.platform = platformFor(a.cfg)
	}
	return a.platform
}
