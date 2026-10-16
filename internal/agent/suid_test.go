package agent

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
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
