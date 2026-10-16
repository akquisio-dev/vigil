package agent

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func md5hex(b []byte) string { s := md5.Sum(b); return hex.EncodeToString(s[:]) }

func TestIntegrityCheck(t *testing.T) {
	dir := t.TempDir()
	good, bad := filepath.Join(dir, "ls"), filepath.Join(dir, "tool")
	os.WriteFile(good, []byte("real ls"), 0o755)
	os.WriteFile(bad, []byte("trojan"), 0o755)
	pkgs := map[string]pkgEntry{
		good: {pkg: "coreutils", ver: "9.4", md5: md5hex([]byte("real ls"))},
		bad:  {pkg: "tools", ver: "1", md5: md5hex([]byte("original"))},
	}
	is := &IntegrityState{Files: map[string]*IntegrityFile{}}
	found := checkIntegrity(context.Background(), is, pkgs)
	if len(found) != 1 || found[0].path != bad || found[0].data["reason"] != "differs from the package checksum" {
		t.Fatalf("mismatch: %+v", found)
	}
	if is.Files[bad] != nil {
		t.Fatal("a suspect file must not enter the inventory before it is confirmed")
	}
	if found := checkIntegrity(context.Background(), is, pkgs); len(found) != 1 {
		t.Fatal("the mismatch must still be there on the confirmation run")
	}

	// The attacker replaces ls and rewrites the md5sums entry to match.
	time.Sleep(10 * time.Millisecond)
	os.WriteFile(good, []byte("evil ls"), 0o755)
	pkgs[good] = pkgEntry{pkg: "coreutils", ver: "9.4", md5: md5hex([]byte("evil ls"))}
	found = checkIntegrity(context.Background(), is, map[string]pkgEntry{good: pkgs[good]})
	if len(found) != 1 || found[0].data["reason"] != "checksum list changed without a package update" || found[0].data["critical"] != true {
		t.Fatalf("rewritten md5sums: %+v", found)
	}

	// A real upgrade changes version and checksum together: quiet.
	pkgs[good] = pkgEntry{pkg: "coreutils", ver: "9.5", md5: md5hex([]byte("evil ls"))}
	if found := checkIntegrity(context.Background(), is, map[string]pkgEntry{good: pkgs[good]}); len(found) != 0 {
		t.Fatalf("upgrade reported: %+v", found)
	}
}

func TestIntegrityScope(t *testing.T) {
	in := []string{"usr/bin/ps", "usr/sbin/sshd", "usr/lib/x86_64-linux-gnu/security/pam_unix.so", "usr/lib/x86_64-linux-gnu/liblzma.so.5.4.5", "usr/lib/openssh/sftp-server"}
	out := []string{"usr/share/doc/ps/README", "usr/lib/python3/dist-packages/x.py", "etc/ssh/sshd_config", "usr/lib/modules/6.8.0/kernel/x.ko"}
	for _, p := range in {
		if !integrityScope(p) {
			t.Errorf("%s should be checked", p)
		}
	}
	for _, p := range out {
		if integrityScope(p) {
			t.Errorf("%s should not be checked", p)
		}
	}
	if !integrityIsCritical("/usr/sbin/sshd") || !integrityIsCritical("/usr/lib/x86_64-linux-gnu/security/pam_unix.so") || integrityIsCritical("/usr/bin/zip") {
		t.Fatal("critical list")
	}
}

// TestIntegrityThisHost checks the real system once (VIGIL_LIVE=1).
func TestIntegrityThisHost(t *testing.T) {
	if os.Getenv("VIGIL_LIVE") == "" {
		t.Skip("set VIGIL_LIVE=1")
	}
	start := time.Now()
	pkgs := packageFiles()
	is := &IntegrityState{Files: map[string]*IntegrityFile{}}
	found := checkIntegrity(context.Background(), is, pkgs)
	t.Logf("%d files in scope, %d suspect, %d unowned, %s", len(pkgs), len(found), len(unownedBinaries(pkgs)), time.Since(start))
	for _, f := range found {
		t.Logf("suspect %s %v", f.path, f.data)
	}
	for p := range unownedBinaries(pkgs) {
		t.Logf("unowned %s", p)
	}
	t.Logf("busy=%v", dpkgBusy())
}
