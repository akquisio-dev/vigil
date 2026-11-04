package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/akquisio-dev/vigil/internal/dpkgver"
)

// fedoraAtomicPlatform is Fedora Atomic and bootc systems such as Nyra:
// /usr comes read-only from a signed image, an rpm database describes the
// image, bootc stages image updates, Podman replaces Docker, SELinux is the
// access control. Detected only when the system is image based (see
// ostreeBooted); plain Fedora with dnf is not this platform.
type fedoraAtomicPlatform struct{}

func (fedoraAtomicPlatform) Name() string { return "fedoraatomic" }

// rpmRun runs rpm with fixed arguments and returns its standard output. It
// returns exec.ErrNotFound when rpm is missing. Tests replace it.
var rpmRun = func(ctx context.Context, args ...string) ([]byte, error) {
	return runFixed(ctx, "rpm", args...)
}

// bootcStatus returns `bootc status --json`; exec.ErrNotFound when bootc is
// missing. Tests replace it.
var bootcStatus = func(ctx context.Context) ([]byte, error) {
	return runFixed(ctx, "bootc", "status", "--json")
}

// runFixed runs a program found in the system PATH with LANG=C. A non-zero
// exit status is returned as an error together with what was printed.
func runFixed(ctx context.Context, name string, args ...string) ([]byte, error) {
	bin, err := exec.LookPath(name)
	if err != nil {
		return nil, exec.ErrNotFound
	}
	cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(cctx, bin, args...)
	cmd.Env = []string{"LANG=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	return cmd.Output()
}

// ostreeBooted tells an image based Fedora (ostree or bootc deployment)
// from a classic one.
func ostreeBooted() bool {
	_, err := os.Stat(sysPath("run/ostree-booted"))
	return err == nil
}

func rpmDBPath() string {
	for _, rel := range []string{"usr/lib/sysimage/rpm/rpmdb.sqlite", "var/lib/rpm/rpmdb.sqlite", "var/lib/rpm/Packages"} {
		if _, err := os.Stat(sysPath(rel)); err == nil {
			return sysPath(rel)
		}
	}
	return sysPath("usr/lib/sysimage/rpm/rpmdb.sqlite")
}

// PackageDBStamp is the rpm database's mtime. On an image system the
// database lives in /usr and only changes with a new deployment, which
// takes a reboot (and an agent restart); a constant stamp is expected.
func (fedoraAtomicPlatform) PackageDBStamp() (time.Time, error) {
	fi, err := os.Stat(rpmDBPath())
	if err != nil {
		return time.Time{}, err
	}
	return fi.ModTime(), nil
}

func (fedoraAtomicPlatform) NoPackageDB() string {
	return "no rpm database under /usr/lib/sysimage/rpm or /var/lib/rpm"
}

func (fedoraAtomicPlatform) SourcePackages() []srcPkg {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	out, err := rpmRun(ctx, "-qa", "--queryformat", `%{SOURCERPM}\t%{EPOCH}:%{VERSION}-%{RELEASE}\n`)
	if err != nil {
		return nil
	}
	return parseRPMSources(out)
}

// parseRPMSources reads `rpm -qa --queryformat
// '%{SOURCERPM}\t%{EPOCH}:%{VERSION}-%{RELEASE}\n'`, for example
// "openssl-3.2.2-3.fc41.src.rpm\t1:3.2.2-3.fc41", and keeps the newest
// version of each source package. Packages without a source rpm
// (gpg-pubkey) are skipped; an unset epoch prints "(none)" and is dropped.
// Newest is chosen with dpkg's comparison, which agrees with rpm's for the
// usual versions; rpm's "^" (after) is ordered like any other character
// there. Only installonly packages (kernel) have more than one version.
func parseRPMSources(out []byte) []srcPkg {
	best := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		src, evr, ok := strings.Cut(strings.TrimSpace(sc.Text()), "\t")
		if !ok || evr == "" {
			continue
		}
		name := rpmSourceName(src)
		if name == "" {
			continue
		}
		evr = strings.TrimPrefix(evr, "(none):")
		if cur, ok := best[name]; !ok || dpkgver.Compare(evr, cur) > 0 {
			best[name] = evr
		}
	}
	list := make([]srcPkg, 0, len(best))
	for n, v := range best {
		list = append(list, srcPkg{n, v})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	return list
}

// rpmSourceName is the name part of a source rpm file name:
// "python-requests-2.32.3-4.fc44.src.rpm" -> "python-requests".
func rpmSourceName(file string) string {
	base, ok := strings.CutSuffix(file, ".src.rpm")
	if !ok {
		if base, ok = strings.CutSuffix(file, ".nosrc.rpm"); !ok {
			return ""
		}
	}
	for i := 0; i < 2; i++ {
		j := strings.LastIndexByte(base, '-')
		if j <= 0 {
			return ""
		}
		base = base[:j]
	}
	return base
}

// Busy is always false: an image update is written to a new deployment
// and switched to on reboot, /usr never changes in place, so there is no
// half finished transaction for the inventory to trip over.
func (fedoraAtomicPlatform) Busy() bool { return false }

// PackagedFiles is empty: on an image system the integrity of /usr is the
// comparison with the deployed image (ostree fsck, composefs/fs-verity),
// planned as a later step. IntegrityUnsupported makes runIntegrity skip
// with a warning instead of calling every program unowned.
func (fedoraAtomicPlatform) PackagedFiles() map[string]pkgEntry { return map[string]pkgEntry{} }

func (fedoraAtomicPlatform) IntegrityUnsupported() string {
	return "package checksums are not checked on image based systems; /usr comes from the signed image (image comparison planned)"
}

// Owners asks rpm for each path on its own: a file owned by two packages
// prints two lines and an unowned one prints a message, so one call for
// many paths cannot be matched up line by line. Callers pass few paths
// (new SUID files, one new program). installed stays empty: the image is
// built at once, so "changed after install" has no reference time here.
func (fedoraAtomicPlatform) Owners(paths []string) dpkgInfo {
	info := dpkgInfo{owner: map[string]string{}, installed: map[string]time.Time{}, override: map[string]bool{}}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for _, p := range paths {
		pkg, found := rpmOwner(ctx, p)
		if !found {
			return info // no rpm: ok stays false
		}
		info.ok = true
		if pkg != "" {
			info.owner[p] = pkg
		}
	}
	return info
}

// rpmOwner returns the package owning path ("" when none) and whether rpm
// could be asked at all.
func rpmOwner(ctx context.Context, path string) (string, bool) {
	if !filepath.IsAbs(path) {
		return "", true // never handed to rpm as an option
	}
	out, err := rpmRun(ctx, "-qf", "--queryformat", `%{NAME}\n`, path)
	if errors.Is(err, exec.ErrNotFound) {
		return "", false
	}
	return parseRPMOwner(out), true
}

// parseRPMOwner takes the first package name from `rpm -qf` output and
// ignores "file ... is not owned by any package" and error lines.
func parseRPMOwner(out []byte) string {
	for _, l := range strings.Split(string(out), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.ContainsAny(l, " /:") {
			continue
		}
		return l
	}
	return ""
}

func (fedoraAtomicPlatform) SelfOwner(exe string) string {
	if p, err := filepath.EvalSymlinks(exe); err == nil {
		exe = p
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	pkg, _ := rpmOwner(ctx, exe)
	return pkg
}

// bootcHost is the part of `bootc status --json` vigil reads.
type bootcHost struct {
	Status struct {
		Staged   *bootcEntry `json:"staged"`
		Booted   *bootcEntry `json:"booted"`
		Rollback *bootcEntry `json:"rollback"`
	} `json:"status"`
}

type bootcEntry struct {
	Image       *bootcImage `json:"image"`
	CachedImage *bootcImage `json:"cachedUpdate"`
}

type bootcImage struct {
	Image struct {
		Image string `json:"image"`
	} `json:"image"`
	Version string `json:"version"`
	Digest  string `json:"imageDigest"`
}

func parseBootcStatus(out []byte) (*bootcHost, error) {
	var h bootcHost
	if err := json.Unmarshal(out, &h); err != nil {
		return nil, err
	}
	return &h, nil
}

// imageLabel names a staged or cached image: "image 44.20261104.0".
func imageLabel(im *bootcImage) string {
	if im == nil || im.Version == "" {
		return "image"
	}
	return "image " + im.Version
}

// pendingFromBootc: a staged deployment is one pending update, and so is an
// update bootc has fetched (cachedUpdate, from `bootc upgrade --check`) but
// not staged yet. Image updates carry no security flag; they count as
// regular ones.
func pendingFromBootc(h *bootcHost) []aptPending {
	switch {
	case h.Status.Staged != nil:
		return []aptPending{{name: imageLabel(h.Status.Staged.Image)}}
	case h.Status.Booted != nil && h.Status.Booted.CachedImage != nil:
		c, b := h.Status.Booted.CachedImage, h.Status.Booted.Image
		if b == nil || c.Digest == "" || c.Digest != b.Digest {
			return []aptPending{{name: imageLabel(c)}}
		}
	}
	return nil
}

// PendingUpdates reads bootc. Not supported without bootc, or when the
// system was not booted through it (no booted deployment).
func (fedoraAtomicPlatform) PendingUpdates(ctx context.Context) ([]aptPending, bool, error) {
	out, err := bootcStatus(ctx)
	if errors.Is(err, exec.ErrNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, true, err
	}
	h, err := parseBootcStatus(out)
	if err != nil {
		return nil, true, err
	}
	if h.Status.Booted == nil {
		return nil, false, nil
	}
	return pendingFromBootc(h), true, nil
}

// RebootRequired: a staged deployment becomes active on the next boot.
func (fedoraAtomicPlatform) RebootRequired() (bool, []string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	out, err := bootcStatus(ctx)
	if err != nil {
		return false, nil
	}
	h, err := parseBootcStatus(out)
	if err != nil || h.Status.Staged == nil {
		return false, nil
	}
	return true, []string{imageLabel(h.Status.Staged.Image)}
}

// KernelVersions: the newest kernel is the one in the booted image, a
// directory under /usr/lib/modules that holds a vmlinuz. A new kernel comes
// with a new image and shows up as a staged deployment instead.
func (fedoraAtomicPlatform) KernelVersions() (string, string) {
	var vs []string
	files, _ := filepath.Glob(sysPath("usr/lib/modules/*/vmlinuz"))
	for _, f := range files {
		vs = append(vs, filepath.Base(filepath.Dir(f)))
	}
	sort.Slice(vs, func(i, j int) bool { return versionLess(vs[i], vs[j]) })
	newest := ""
	if len(vs) > 0 {
		newest = vs[len(vs)-1]
	}
	return unameRelease(), newest
}

// AutoUpdates: bootc-fetch-apply-updates.timer is enabled (by the admin in
// /etc or by the image in /usr) and not masked.
func (fedoraAtomicPlatform) AutoUpdates() bool {
	const timer = "bootc-fetch-apply-updates.timer"
	if dst, err := os.Readlink(sysPath("etc/systemd/system/" + timer)); err == nil && dst == "/dev/null" {
		return false
	}
	for _, dir := range []string{"etc/systemd/system/timers.target.wants", "usr/lib/systemd/system/timers.target.wants"} {
		if _, err := os.Lstat(sysPath(filepath.Join(dir, timer))); err == nil {
			return true
		}
	}
	return false
}

// ListsAgeDays: there are no package lists; bootc asks the registry when it
// checks.
func (fedoraAtomicPlatform) ListsAgeDays(time.Time) int { return -1 }

// FirewallCheck: firewalld writes nftables rules, which firewallCheck reads.
func (fedoraAtomicPlatform) FirewallCheck() []postureCheck { return firewallCheck() }

// MACCheck reads SELinux only. macCheck looks at AppArmor first, so a kernel
// that exposes the AppArmor module disabled would hide SELinux.
func (fedoraAtomicPlatform) MACCheck() []postureCheck {
	b, err := os.ReadFile(sysPath("sys/fs/selinux/enforce"))
	if err != nil {
		return []postureCheck{{Check: "mac", OK: false, Value: "selinux disabled"}}
	}
	on := strings.TrimSpace(string(b)) == "1"
	return []postureCheck{{Check: "mac", OK: on, Value: "selinux " + map[bool]string{true: "enforcing", false: "permissive"}[on]}}
}

// PublishedPorts is empty for now. Rootless Podman publishes through pasta,
// a listening socket the socket scan already sees. TODO: rootful Podman
// publishes through netavark's nftables table (inet netavark), which can
// bypass the input filter like Docker's DNAT does.
func (fedoraAtomicPlatform) PublishedPorts() []Port { return nil }

// ContainerSocket is rootful Podman's Docker-compatible API (podman.socket).
// Rootless containers have one socket per user under /run/user; not read yet.
func (fedoraAtomicPlatform) ContainerSocket() string { return "/run/podman/podman.sock" }

// ContainerAdmins is empty: the rootful Podman socket belongs to root, there
// is no group like docker that grants it.
func (fedoraAtomicPlatform) ContainerAdmins(string) []string { return nil }
