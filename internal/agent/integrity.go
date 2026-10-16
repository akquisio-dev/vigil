package agent

import (
	"bufio"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

// Package integrity: the programs used to log in and to look at a system
// (sshd, sudo, ps, ls, PAM modules, libc) are compared with the checksums
// their Debian packages recorded. A rootkit that replaces ps, or a
// backdoored sshd, no longer matches. The agent also keeps its own SHA-256
// inventory, so an attacker who rewrites the package's md5sums file along
// with the binary is caught when the checksum list changes without a
// package update.

type IntegrityFile struct {
	Package string `json:"pkg"`
	Version string `json:"ver"`
	MD5     string `json:"md5"` // expected, from the package
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
	Inode   uint64 `json:"ino"`
	Ctime   int64  `json:"ctime"`
}

type IntegrityState struct {
	Baselined bool                      `json:"baselined"`
	Files     map[string]*IntegrityFile `json:"files"`
	Unowned   map[string]bool           `json:"unowned"` // regular files in bin dirs no package lists
}

const (
	integrityEvery    = 6 * time.Hour
	integrityConfirm  = 10 * time.Minute
	integrityMaxAlert = 25 // per run; more becomes one summary event
)

var integrityBinDirs = []string{"usr/bin/", "usr/sbin/", "bin/", "sbin/", "usr/lib/openssh/", "usr/libexec/"}

// integrityLibs are the libraries every login and every inspection tool
// loads; the xz backdoor went through liblzma.
var integrityLibs = []string{"libc.so", "ld-linux", "libpam.so", "libpam_misc", "libnss_", "libcrypt.so", "libaudit.so",
	"libselinux.so", "libsystemd.so", "liblzma.so", "libkeyutils.so", "libcrypto.so", "libssl.so", "libz.so", "libprocps.so", "libproc2.so"}

// integrityCritical are the programs a rootkit replaces first. A changed one
// is critical; anything else in scope is high.
var integrityCritical = map[string]bool{"sshd": true, "sshd-session": true, "sudo": true, "su": true, "login": true, "passwd": true,
	"ps": true, "ss": true, "netstat": true, "ls": true, "top": true, "lsof": true, "find": true, "w": true, "who": true,
	"last": true, "crontab": true, "systemctl": true, "journalctl": true, "bash": true, "dash": true, "sh": true, "ip": true,
	"chsh": true, "chfn": true, "newgrp": true, "gpasswd": true, "pgrep": true, "pkill": true, "kill": true, "du": true, "df": true}

func integrityScope(rel string) bool {
	for _, d := range integrityBinDirs {
		if strings.HasPrefix(rel, d) {
			return true
		}
	}
	if !strings.HasPrefix(rel, "usr/lib/") && !strings.HasPrefix(rel, "lib/") {
		return false
	}
	if strings.Contains(rel, "/security/pam_") {
		return true
	}
	base := filepath.Base(rel)
	for _, l := range integrityLibs {
		if strings.HasPrefix(base, l) {
			return true
		}
	}
	return false
}

func integrityIsCritical(path string) bool {
	base := filepath.Base(path)
	if integrityCritical[base] || strings.HasPrefix(base, "pam_") {
		return true
	}
	for _, l := range []string{"libc.so", "ld-linux", "libpam.so", "liblzma.so", "libkeyutils.so", "libnss_", "libcrypt.so"} {
		if strings.HasPrefix(base, l) {
			return true
		}
	}
	return false
}

type pkgEntry struct{ pkg, ver, md5 string }

// dpkgVersions maps installed packages ("name" and "name:arch") to their
// version, from /var/lib/dpkg/status.
func dpkgVersions() map[string]string {
	out := map[string]string{}
	f, err := os.Open("/var/lib/dpkg/status")
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 256<<10), 4<<20)
	var name, arch, ver string
	flush := func() {
		if name != "" {
			out[name] = ver
			out[name+":"+arch] = ver
		}
		name, arch, ver = "", "", ""
	}
	for sc.Scan() {
		l := sc.Text()
		switch {
		case l == "":
			flush()
		case strings.HasPrefix(l, "Package: "):
			name = l[9:]
		case strings.HasPrefix(l, "Architecture: "):
			arch = l[14:]
		case strings.HasPrefix(l, "Version: "):
			ver = l[9:]
		}
	}
	flush()
	return out
}

// dpkgDiversions returns original paths that another package diverted away.
// A package diverting its own file (usrmerge transition) is not a diversion
// of interest.
func dpkgDiversions() map[string]string {
	out := map[string]string{}
	b, err := os.ReadFile("/var/lib/dpkg/diversions")
	if err != nil {
		return out
	}
	l := strings.Split(string(b), "\n")
	for i := 0; i+2 < len(l); i += 3 {
		out[l[i]] = l[i+2]
	}
	return out
}

// canonical resolves the directory part (bin -> usr/bin) but not the file.
func canonical(p string) string {
	dir, err := filepath.EvalSymlinks(filepath.Dir(p))
	if err != nil {
		return p
	}
	return filepath.Join(dir, filepath.Base(p))
}

// packageFiles reads every md5sums file and keeps the entries in scope.
func packageFiles() map[string]pkgEntry {
	vers := dpkgVersions()
	div := dpkgDiversions()
	out := map[string]pkgEntry{}
	sums, _ := filepath.Glob("/var/lib/dpkg/info/*.md5sums")
	for _, sf := range sums {
		pkg := strings.TrimSuffix(filepath.Base(sf), ".md5sums")
		short, _, _ := strings.Cut(pkg, ":")
		f, err := os.Open(sf)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			sum, rel, ok := strings.Cut(sc.Text(), "  ")
			if !ok || len(sum) != 32 || !integrityScope(rel) {
				continue
			}
			p := "/" + rel
			if by, diverted := div[p]; diverted && by != short && by != pkg {
				continue
			}
			c := canonical(p)
			if _, dup := out[c]; dup {
				continue
			}
			out[c] = pkgEntry{pkg: short, ver: vers[pkg], md5: sum}
		}
		f.Close()
	}
	return out
}

// dpkgBusy reports whether dpkg is installing right now, or was
// interrupted: files are then legitimately out of step with md5sums.
func dpkgBusy() bool {
	if ents, err := os.ReadDir("/var/lib/dpkg/updates"); err == nil && len(ents) > 0 {
		return true
	}
	for _, lock := range []string{"/var/lib/dpkg/lock-frontend", "/var/lib/dpkg/lock"} {
		f, err := os.OpenFile(lock, os.O_RDWR, 0)
		if err != nil {
			continue
		}
		lk := syscall.Flock_t{Type: syscall.F_WRLCK, Whence: 0}
		err = syscall.FcntlFlock(f.Fd(), syscall.F_GETLK, &lk)
		f.Close()
		if err == nil && lk.Type != syscall.F_UNLCK {
			return true
		}
	}
	return false
}

func hashFile(p string) (md5hex, shahex string, err error) {
	f, err := os.Open(p)
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	m, s := md5.New(), sha256.New()
	if _, err := io.Copy(io.MultiWriter(m, s), f); err != nil {
		return "", "", err
	}
	return hex.EncodeToString(m.Sum(nil)), hex.EncodeToString(s.Sum(nil)), nil
}

type integrityFinding struct {
	path string
	data map[string]any
	rec  *IntegrityFile // what the file is now, stored once reported
}

// checkIntegrity compares the files in scope with the package checksums and
// the inventory. It returns what looks wrong; the caller confirms it on a
// second run before reporting.
func checkIntegrity(ctx context.Context, is *IntegrityState, pkgs map[string]pkgEntry) []integrityFinding {
	var out []integrityFinding
	paths := make([]string, 0, len(pkgs))
	for p := range pkgs {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		if ctx.Err() != nil {
			return nil
		}
		e := pkgs[p]
		var st syscall.Stat_t
		if syscall.Lstat(p, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG {
			delete(is.Files, p)
			continue
		}
		ctime := st.Ctim.Sec*1e9 + st.Ctim.Nsec
		prev := is.Files[p]
		if prev != nil && prev.Inode == st.Ino && prev.Size == st.Size && prev.Ctime == ctime && prev.MD5 == e.md5 && prev.Version == e.ver {
			continue
		}
		md5hex, shahex, err := hashFile(p)
		if err != nil {
			continue
		}
		rec := &IntegrityFile{Package: e.pkg, Version: e.ver, MD5: e.md5, SHA256: shahex, Size: st.Size, Inode: st.Ino, Ctime: ctime}
		d := map[string]any{"path": p, "package": e.pkg, "version": e.ver, "sha256": shahex, "size": st.Size, "critical": integrityIsCritical(p)}
		switch {
		case md5hex != e.md5:
			d["reason"] = "differs from the package checksum"
			d["expected_md5"], d["md5"] = e.md5, md5hex
			out = append(out, integrityFinding{p, d, rec})
			continue
		case prev != nil && prev.MD5 != e.md5 && prev.Version == e.ver && prev.Package == e.pkg:
			// The package's checksum list changed, its version did not.
			d["reason"] = "checksum list changed without a package update"
			d["old_sha256"] = prev.SHA256
			out = append(out, integrityFinding{p, d, rec})
			continue
		}
		is.Files[p] = rec
	}
	return out
}

// unownedBinaries lists regular files in the bin directories that no
// package lists. Symlinks (alternatives) are skipped.
func unownedBinaries(pkgs map[string]pkgEntry) map[string]bool {
	out := map[string]bool{}
	seen := map[string]bool{}
	for _, d := range []string{"/usr/bin", "/usr/sbin", "/bin", "/sbin"} {
		real, err := filepath.EvalSymlinks(d)
		if err != nil || seen[real] {
			continue
		}
		seen[real] = true
		ents, _ := os.ReadDir(real)
		for _, e := range ents {
			if !e.Type().IsRegular() {
				continue
			}
			p := filepath.Join(real, e.Name())
			if _, ok := pkgs[p]; !ok {
				out[p] = true
			}
		}
	}
	return out
}

func integrityStatePath(dir string) string { return filepath.Join(dir, "integrity.json") }

func loadIntegrityState(dir string) *IntegrityState {
	is := &IntegrityState{}
	if raw, err := os.ReadFile(integrityStatePath(dir)); err == nil {
		json.Unmarshal(raw, is)
	}
	if is.Files == nil {
		is.Files = map[string]*IntegrityFile{}
	}
	if is.Unowned == nil {
		is.Unowned = map[string]bool{}
	}
	return is
}

func (a *Agent) runIntegrity(ctx context.Context) {
	if _, err := os.Stat("/var/lib/dpkg/status"); err != nil {
		a.emit(proto.NewEvent("agent.warning", map[string]any{"collector": "integrity", "error": "no dpkg database; package integrity is checked on Debian and Ubuntu only"}))
		return
	}
	is := loadIntegrityState(a.cfg.StateDir)
	save := func() {
		if raw, err := json.Marshal(is); err == nil {
			writeFileAtomic(integrityStatePath(a.cfg.StateDir), raw, 0o600)
		}
	}
	// Findings wait for a second look, so a package upgrade caught half way
	// is not reported.
	pending := map[string]integrityFinding{}
	t := time.NewTimer(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if dpkgBusy() {
			t.Reset(integrityConfirm)
			continue
		}
		start := time.Now()
		pkgs := packageFiles()
		var found []integrityFinding
		if len(pending) > 0 {
			// Confirmation: hash the pending files again, nothing else.
			sub := map[string]pkgEntry{}
			for p := range pending {
				if e, ok := pkgs[p]; ok {
					sub[p] = e
					if f := is.Files[p]; f != nil {
						f.Ctime = -1 // force a rehash
					}
				}
			}
			again := checkIntegrity(ctx, is, sub)
			reported := 0
			for _, f := range again {
				if _, ok := pending[f.path]; !ok {
					continue
				}
				if reported == integrityMaxAlert {
					a.emit(proto.NewEvent("integrity.many", map[string]any{"count": len(again)}))
					break
				}
				a.emit(proto.NewEvent("integrity.mismatch", f.data))
				is.Files[f.path] = f.rec
				reported++
			}
			pending = map[string]integrityFinding{}
			save()
			t.Reset(integrityEvery)
			continue
		}
		found = checkIntegrity(ctx, is, pkgs)
		if ctx.Err() != nil {
			return
		}
		unowned := unownedBinaries(pkgs)
		if is.Baselined {
			for p := range unowned {
				if !is.Unowned[p] {
					d := map[string]any{"path": p}
					if fi, err := os.Stat(p); err == nil {
						d["size"] = fi.Size()
						d["mode"] = fi.Mode().Perm().String()
					}
					if _, sha, err := hashFile(p); err == nil {
						d["sha256"] = sha
					}
					a.emit(proto.NewEvent("integrity.unowned", d))
				}
			}
		}
		is.Unowned = unowned
		first := !is.Baselined
		is.Baselined = true
		save()
		a.emit(proto.NewEvent("integrity.scan", map[string]any{"files": len(pkgs), "suspect": len(found), "unowned": len(unowned),
			"first": first, "seconds": int(time.Since(start).Seconds())}))
		for _, f := range found {
			pending[f.path] = f
		}
		if len(pending) > 0 {
			t.Reset(integrityConfirm)
		} else {
			t.Reset(integrityEvery)
		}
	}
}
