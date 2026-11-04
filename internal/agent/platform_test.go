package agent

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/akquisio-dev/vigil/internal/dpkgver"
)

func TestChoosePlatform(t *testing.T) {
	old := sysRoot
	sysRoot = t.TempDir() // no /run/ostree-booted
	t.Cleanup(func() { sysRoot = old })
	for _, c := range []struct{ conf, id, like, want string }{
		{"", "ubuntu", "debian", "debian"},
		{"", "debian", "", "debian"},
		{"", "linuxmint", "ubuntu debian", "debian"},
		{"", "", "", "debian"},       // no os-release: as before platforms existed
		{"", "fedora", "", "debian"}, // classic Fedora: no platform of its own yet
		{"debian", "fedora", "", "debian"},
	} {
		p, err := choosePlatform(c.conf, c.id, c.like)
		if err != nil || p.Name() != c.want {
			t.Fatalf("%+v: %v %v", c, p, err)
		}
	}
	if _, err := choosePlatform("windows", "", ""); err == nil {
		t.Fatal("an unknown configured platform must be refused")
	}
}

func TestConfigRefusesUnknownPlatform(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte(`{"server":"https://x","platform":"windows"}`), 0o600)
	if _, err := LoadConfig(bad); err == nil {
		t.Fatal("unknown platform accepted")
	}
	good := filepath.Join(dir, "good.json")
	os.WriteFile(good, []byte(`{"server":"https://x","platform":"debian"}`), 0o600)
	if c, err := LoadConfig(good); err != nil || c.Platform != "debian" {
		t.Fatalf("debian refused: %v", err)
	}
}

func TestOsReleaseIDs(t *testing.T) {
	p := filepath.Join(t.TempDir(), "os-release")
	os.WriteFile(p, []byte("NAME=\"Ubuntu\"\nID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"24.04\"\n"), 0o644)
	if id, like := osReleaseIDs(p); id != "ubuntu" || like != "debian" {
		t.Fatalf("%q %q", id, like)
	}
}

// The debian platform must give exactly the facts the golden tests pin for
// the functions it wraps.
func TestDebianPlatformMatchesGolden(t *testing.T) {
	root := debianFixture(t)
	p := debianPlatform{}
	if !reflect.DeepEqual(p.SourcePackages(), sourcePackages(dpkgPath("status"), func(a, b string) bool { return dpkgver.Compare(a, b) > 0 })) {
		t.Fatal("source packages differ")
	}
	if !reflect.DeepEqual(p.PackagedFiles(), packageFiles()) || p.Busy() != dpkgBusy() {
		t.Fatal("packaged files or busy differ")
	}
	paths := []string{"/usr/bin/ls", "/usr/bin/crontab"}
	if !reflect.DeepEqual(p.Owners(paths), lookupDpkg(paths)) {
		t.Fatal("owners differ")
	}
	stamp, err := p.PackageDBStamp()
	fi, _ := os.Stat(filepath.Join(root, "var/lib/dpkg/status"))
	if err != nil || !stamp.Equal(fi.ModTime()) {
		t.Fatalf("stamp: %v %v", stamp, err)
	}
	if !p.AutoUpdates() {
		t.Fatal("auto updates")
	}
	if _, newest := p.KernelVersions(); newest != "6.8.0-147-generic" {
		t.Fatal(newest)
	}
	if r, _ := p.RebootRequired(); r {
		t.Fatal("no reboot-required file in the fixture")
	}
	os.MkdirAll(filepath.Join(root, "var/run"), 0o755)
	os.WriteFile(filepath.Join(root, "var/run/reboot-required"), nil, 0o644)
	os.WriteFile(filepath.Join(root, "var/run/reboot-required.pkgs"), []byte("linux-image-6.8.0-147\nlibc6\n"), 0o644)
	if r, pk := p.RebootRequired(); !r || !reflect.DeepEqual(pk, []string{"linux-image-6.8.0-147", "libc6"}) {
		t.Fatalf("reboot: %v %v", r, pk)
	}
	if p.ListsAgeDays(time.Now()) != -1 {
		t.Fatal("no apt lists in the fixture")
	}
	os.MkdirAll(filepath.Join(root, "var/lib/apt/lists"), 0o755)
	old := time.Now().Add(-72 * time.Hour)
	os.Chtimes(filepath.Join(root, "var/lib/apt/lists"), old, old)
	if d := p.ListsAgeDays(time.Now()); d != 3 {
		t.Fatalf("lists age %d", d)
	}
	if p.ContainerSocket() != "/var/run/docker.sock" {
		t.Fatal("docker socket")
	}
}

func TestPlatformDefaultsForBareAgent(t *testing.T) {
	a := &Agent{cfg: &Config{}}
	if a.plat().Name() != "debian" {
		t.Fatal("agents built without New fall back to debian")
	}
}
