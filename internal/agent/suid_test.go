package agent

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
)

func capXattr(bits ...int) []byte {
	b := make([]byte, 20)
	binary.LittleEndian.PutUint32(b[0:], 0x02000001) // revision 2, effective
	var lo, hi uint32
	for _, bit := range bits {
		if bit < 32 {
			lo |= 1 << bit
		} else {
			hi |= 1 << (bit - 32)
		}
	}
	binary.LittleEndian.PutUint32(b[4:], lo)
	binary.LittleEndian.PutUint32(b[12:], hi)
	return b
}

func TestParseCaps(t *testing.T) {
	if s, d := parseCaps(capXattr(13)); s != "cap_net_raw+ep" || d {
		t.Fatalf("ping: %q %v", s, d)
	}
	if s, d := parseCaps(capXattr(7, 39)); s != "cap_setuid,cap_bpf+ep" || !d {
		t.Fatalf("setuid: %q %v", s, d)
	}
	if _, d := parseCapsString("cap_net_bind_service+ep"); d {
		t.Fatal("net_bind_service is not dangerous")
	}
}

func TestSuidWalkAndDiff(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to set SUID bits and capabilities")
	}
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain")
	suid := filepath.Join(dir, "suid")
	capf := filepath.Join(dir, "cap")
	for _, p := range []string{plain, suid, capf} {
		os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755)
	}
	os.Chmod(suid, os.ModeSetuid|0o755)
	if err := syscall.Setxattr(capf, "security.capability", capXattr(21), 0); err != nil {
		t.Skipf("filesystem without capability xattrs: %v", err)
	}
	found, err := walkSuid(context.Background(), []string{dir}, map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 2 || found[suid] == nil || found[capf].Caps != "cap_sys_admin+ep" {
		t.Fatalf("walk: %+v", found)
	}

	a := &Agent{cfg: &Config{MaxQueue: 100}, flushNow: make(chan struct{}, 1)}
	ss := &SuidState{Files: map[string]*SuidFile{}}
	// Baseline: unowned files are named once, marked as baseline.
	a.diffSuid(ss, []string{dir}, found)
	ss.Baselined = true
	ev := eventTypes(a)["file.suid"]
	if len(ev) != 2 || ev[0]["baseline"] != true {
		t.Fatalf("baseline: %v", ev)
	}
	// Nothing changed: nothing reported.
	a.diffSuid(ss, []string{dir}, found)
	if n := len(eventTypes(a)["file.suid"]); n != 0 {
		t.Fatalf("unchanged files reported %d times", n)
	}
	// chmod u+s on a plain file, and one SUID file gone.
	os.Chmod(plain, os.ModeSetuid|0o755)
	os.Remove(suid)
	found, _ = walkSuid(context.Background(), []string{dir}, map[string]bool{})
	a.diffSuid(ss, []string{dir}, found)
	evs := eventTypes(a)
	if len(evs["file.suid"]) != 1 || evs["file.suid"][0]["path"] != plain || evs["file.suid"][0]["bits"] != "setuid" {
		t.Fatalf("new SUID: %v", evs["file.suid"])
	}
	if len(evs["file.suid_removed"]) != 1 {
		t.Fatalf("removed: %v", evs["file.suid_removed"])
	}
}

func TestMountinfoUnescape(t *testing.T) {
	if got := unescapeMount(`/mnt/with\040space`); got != "/mnt/with space" {
		t.Fatal(got)
	}
	if !underAny("/var/lib/docker/x", suidSkip) || underAny("/var/lib/dockerx", suidSkip) || !underAny("/etc", []string{"/"}) {
		t.Fatal("underAny")
	}
}

// nyraMounts is the shape of /proc/self/mountinfo on a Fedora bootc system
// with composefs: "/" is an overlay of the image, /sysroot the physical root
// with the ostree repository and deployments, /etc and /var bind mounts out
// of it.
var nyraMounts = []mount{{"/", "overlay"}, {"/sysroot", "xfs"}, {"/etc", "xfs"}, {"/var", "xfs"}, {"/boot", "xfs"},
	{"/proc", "proc"}, {"/sys", "sysfs"}, {"/dev", "devtmpfs"}, {"/dev/shm", "tmpfs"}, {"/run", "tmpfs"}, {"/tmp", "tmpfs"},
	{"/var/lib/containers/storage/overlay", "xfs"}}

func TestWalkRootsFedoraAtomic(t *testing.T) {
	fedoraAtomicFixture(t)
	a := &Agent{cfg: &Config{MaxQueue: 100}, platform: fedoraAtomicPlatform{}}
	skip, rootTypes := a.walkLayout()
	roots, all := walkRoots(nyraMounts, skip, rootTypes)
	want := []string{"/", "/boot", "/dev/shm", "/etc", "/run", "/tmp", "/var"}
	if !reflect.DeepEqual(roots, want) {
		t.Fatalf("roots %v, want %v", roots, want)
	}
	if !all["/sysroot"] {
		t.Fatal("/sysroot must stay a mount point the walk does not cross into")
	}
	// Debian: no overlay root, no /sysroot skip (none exists there anyway).
	d := &Agent{cfg: &Config{MaxQueue: 100}, platform: debianPlatform{}}
	skip, rootTypes = d.walkLayout()
	roots, _ = walkRoots(nyraMounts, skip, rootTypes)
	if !reflect.DeepEqual(roots, []string{"/boot", "/dev/shm", "/etc", "/run", "/sysroot", "/tmp", "/var"}) || !reflect.DeepEqual(skip, suidSkip) {
		t.Fatalf("debian roots %v skip %v", roots, skip)
	}
}

// The SUID walk sees /usr/bin through "/" and nothing of the deployments
// under /sysroot (hard links of the same /usr) or the /ostree link.
func TestWalkSuidSkipsOstree(t *testing.T) {
	fedoraAtomicFixture(t)
	root := t.TempDir()
	dep := root + "/sysroot/ostree/deploy/default/deploy/6703c47ddb789b5ea6c4cf0e425ed171b4a673b0c53888ee927a462be6ed63db.0/usr/bin"
	for _, d := range []string{root + "/usr/bin", dep} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{root + "/usr/bin/chage", dep + "/chage", root + "/usr/bin/plain"} {
		os.WriteFile(p, []byte("x"), 0o755)
	}
	os.Chmod(root+"/usr/bin/chage", os.ModeSetuid|0o755)
	if err := os.Chmod(dep+"/chage", os.ModeSetuid|0o755); err != nil {
		t.Fatal(err)
	}
	os.Symlink("sysroot/ostree", root+"/ostree")
	a := &Agent{cfg: &Config{MaxQueue: 100}, platform: fedoraAtomicPlatform{}}
	skip, _ := a.walkLayout()
	// The fixture root stands for "/": skip entries are made relative to it.
	var rel []string
	for _, s := range skip {
		rel = append(rel, root+s)
	}
	found, err := walkSuidSkip(context.Background(), []string{root}, map[string]bool{}, rel)
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 || found[root+"/usr/bin/chage"] == nil {
		t.Fatalf("found %v", found)
	}
	// Without the platform's list the deployment's copy shows up.
	found, _ = walkSuidSkip(context.Background(), []string{root}, map[string]bool{}, suidSkip)
	if len(found) != 2 || found[dep+"/chage"] == nil {
		t.Fatalf("control walk: %v", found)
	}
}

// Entries an older agent recorded under /sysroot are dropped without a
// file.suid_removed each.
func TestPruneSkippedSuid(t *testing.T) {
	ss := &SuidState{Baselined: true, Files: map[string]*SuidFile{
		"/usr/bin/chage": {Mode: 0o4755},
		"/sysroot/ostree/deploy/default/deploy/abc.0/usr/bin/chage": {Mode: 0o4755},
	}}
	if !pruneSkipped(ss, fedoraAtomicPlatform{}.WalkSkip()) || len(ss.Files) != 1 || ss.Files["/usr/bin/chage"] == nil {
		t.Fatalf("prune: %v", ss.Files)
	}
	if pruneSkipped(ss, fedoraAtomicPlatform{}.WalkSkip()) {
		t.Fatal("nothing left to prune")
	}
}
