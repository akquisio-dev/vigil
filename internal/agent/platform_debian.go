package agent

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/akquisio-dev/vigil/internal/dpkgver"
)

// debianPlatform is Debian and Ubuntu: dpkg, apt, unattended-upgrades,
// Docker, iptables or nftables, AppArmor. It wraps the functions vigil had
// before platforms existed; their behaviour is pinned by
// platform_golden_test.go.
type debianPlatform struct{}

func (debianPlatform) Name() string { return "debian" }

func (debianPlatform) PackageDBStamp() (time.Time, error) {
	fi, err := os.Stat(dpkgPath("status"))
	if err != nil {
		return time.Time{}, err
	}
	return fi.ModTime(), nil
}

func (debianPlatform) SourcePackages() []srcPkg {
	return sourcePackages(dpkgPath("status"), func(a, b string) bool { return dpkgver.Compare(a, b) > 0 })
}

func (debianPlatform) Busy() bool                         { return dpkgBusy() }
func (debianPlatform) PackagedFiles() map[string]pkgEntry { return packageFiles() }
func (debianPlatform) Owners(paths []string) dpkgInfo     { return lookupDpkg(paths) }
func (debianPlatform) SelfOwner(exe string) string        { return dpkgOwner(exe) }

func (debianPlatform) NoPackageDB() string {
	return "no dpkg database; package integrity is checked on Debian and Ubuntu only"
}

func (debianPlatform) PendingUpdates(ctx context.Context) ([]aptPending, bool, error) {
	apt, err := exec.LookPath("apt")
	if err != nil {
		return nil, false, nil // not a Debian-like system
	}
	cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(cctx, apt, "list", "--upgradable")
	cmd.Env = []string{"LANG=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	out, err := cmd.Output()
	if err != nil {
		return nil, true, err
	}
	return parseAptUpgradable(out), true, nil
}

func (debianPlatform) RebootRequired() (bool, []string) {
	_, err := os.Stat(sysPath("var/run/reboot-required"))
	if err != nil {
		return false, nil
	}
	var pkgs []string
	if b, err := os.ReadFile(sysPath("var/run/reboot-required.pkgs")); err == nil {
		pkgs = strings.Fields(string(b))
	}
	return true, pkgs
}

func (debianPlatform) KernelVersions() (string, string) { return kernelVersions() }
func (debianPlatform) AutoUpdates() bool                { return unattendedEnabled() }

func (debianPlatform) ListsAgeDays(now time.Time) int {
	if fi, err := os.Stat(sysPath("var/lib/apt/periodic/update-success-stamp")); err == nil {
		return int(now.Sub(fi.ModTime()).Hours() / 24)
	} else if fi, err := os.Stat(sysPath("var/lib/apt/lists")); err == nil {
		return int(now.Sub(fi.ModTime()).Hours() / 24)
	}
	return -1
}

func (debianPlatform) FirewallCheck() []postureCheck { return firewallCheck() }
func (debianPlatform) MACCheck() []postureCheck      { return macCheck() }
func (debianPlatform) PublishedPorts() []Port        { return dockerPorts() }

func (debianPlatform) ContainerSocket() string { return dockerSocket }
func (debianPlatform) ContainerAdmins(groupFile string) []string {
	return dockerGroup(groupFile)
}
