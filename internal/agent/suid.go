package agent

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

// SUID and SGID programs and file capabilities are how a foothold becomes
// root, and how root keeps a quiet way back in (chmod u+s on a copy of bash
// or on find). The collector walks the local filesystems every few hours,
// the world-writable temp directories every few minutes, and compares with
// its own inventory in suid.json.

type SuidFile struct {
	Mode  uint32 `json:"mode"`
	UID   uint32 `json:"uid"`
	GID   uint32 `json:"gid"`
	Caps  string `json:"caps,omitempty"`
	Size  int64  `json:"size"`
	Inode uint64 `json:"inode"`
}

type SuidState struct {
	Baselined bool                 `json:"baselined"`
	Files     map[string]*SuidFile `json:"files"`
}

const (
	suidFullEvery  = 6 * time.Hour
	suidQuickEvery = 5 * time.Minute
	suidMaxEntries = 2_000_000 // safety stop for one walk
)

var suidTmpDirs = []string{"/tmp", "/var/tmp", "/dev/shm", "/run/shm"}

// suidSkip are trees that belong to container images and snaps. Their SUID
// files are the images' business and change with every pull.
var suidSkip = []string{"/proc", "/sys", "/var/lib/docker", "/var/lib/containerd", "/var/lib/containers", "/snap", "/var/snap", "/var/lib/lxd", "/var/lib/lxc"}

var suidFSTypes = map[string]bool{"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "zfs": true, "f2fs": true, "jfs": true, "reiserfs": true, "tmpfs": true}

// capNames for the bits that matter; others are shown as cap_N.
var capNames = map[int]string{0: "cap_chown", 1: "cap_dac_override", 2: "cap_dac_read_search", 3: "cap_fowner", 6: "cap_setgid",
	7: "cap_setuid", 10: "cap_net_bind_service", 12: "cap_net_admin", 13: "cap_net_raw", 16: "cap_sys_module", 17: "cap_sys_rawio",
	19: "cap_sys_ptrace", 21: "cap_sys_admin", 31: "cap_setfcap", 38: "cap_perfmon", 39: "cap_bpf"}

// dangerousCaps lead to root or to the kernel. cap_net_bind_service,
// cap_net_raw (ping) and friends do not.
var dangerousCaps = map[int]bool{0: true, 1: true, 2: true, 3: true, 6: true, 7: true, 16: true, 17: true, 19: true, 21: true, 31: true, 39: true}

// parseCaps decodes a security.capability xattr (revision 2 or 3) into the
// names of the permitted capabilities and whether any of them is dangerous.
func parseCaps(raw []byte) (string, bool) {
	if len(raw) < 20 {
		return "", false
	}
	le := binary.LittleEndian
	perm := uint64(le.Uint32(raw[4:8])) | uint64(le.Uint32(raw[12:16]))<<32
	var names []string
	danger := false
	for bit := 0; bit < 64; bit++ {
		if perm&(1<<bit) == 0 {
			continue
		}
		n, ok := capNames[bit]
		if !ok {
			n = "cap_" + strconv.Itoa(bit)
		}
		names = append(names, n)
		danger = danger || dangerousCaps[bit]
	}
	if le.Uint32(raw[0:4])&1 != 0 && len(names) > 0 {
		names[len(names)-1] += "+ep"
	} else if len(names) > 0 {
		names[len(names)-1] += "+p"
	}
	return strings.Join(names, ","), danger
}

type mount struct{ point, fstype string }

// mounts reads /proc/self/mountinfo; mount points use octal escapes.
func mounts() []mount {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []mount
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		pre, post, ok := strings.Cut(sc.Text(), " - ")
		pf, qf := strings.Fields(pre), strings.Fields(post)
		if !ok || len(pf) < 5 || len(qf) < 1 {
			continue
		}
		out = append(out, mount{unescapeMount(pf[4]), qf[0]})
	}
	return out
}

func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func underAny(p string, roots []string) bool {
	for _, r := range roots {
		if r == "/" || p == r || strings.HasPrefix(p, r+"/") {
			return true
		}
	}
	return false
}

// walkSuid finds SUID/SGID files and files with capabilities below roots,
// staying on each root's filesystem and skipping other mount points and
// the container trees. Directories are read in small batches and only the
// paths of pending directories are kept, so memory stays flat on hosts
// with millions of files and on directories with huge entry counts.
func walkSuid(ctx context.Context, roots []string, allMounts map[string]bool) (map[string]*SuidFile, error) {
	found := map[string]*SuidFile{}
	entries := 0
	capBuf := make([]byte, 64)
	var st syscall.Stat_t
	for _, root := range roots {
		stack := []string{root}
		for len(stack) > 0 {
			dir := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			f, err := os.Open(dir)
			if err != nil {
				continue
			}
			for {
				if ctx.Err() != nil {
					f.Close()
					return found, ctx.Err()
				}
				batch, err := f.ReadDir(256)
				for _, d := range batch {
					entries++
					p := dir + "/" + d.Name()
					if dir == "/" {
						p = "/" + d.Name()
					}
					switch {
					case d.IsDir():
						if !allMounts[p] && !underAny(p, suidSkip) {
							stack = append(stack, p)
						}
						continue
					case !d.Type().IsRegular():
						continue
					}
					if syscall.Lstat(p, &st) != nil {
						continue
					}
					special := st.Mode&(syscall.S_ISUID|syscall.S_ISGID) != 0
					caps := ""
					if st.Mode&0o111 != 0 {
						if n, err := syscall.Getxattr(p, "security.capability", capBuf); err == nil && n > 0 {
							caps, _ = parseCaps(capBuf[:n])
						}
					}
					if special || caps != "" {
						found[p] = &SuidFile{Mode: st.Mode & 0o7777, UID: st.Uid, GID: st.Gid, Caps: caps, Size: st.Size, Inode: st.Ino}
					}
				}
				if entries > suidMaxEntries {
					f.Close()
					return found, fmt.Errorf("more than %d entries, walk stopped", suidMaxEntries)
				}
				if err != nil || len(batch) == 0 {
					break
				}
			}
			f.Close()
		}
	}
	return found, nil
}

// suidRoots lists the mount points of local filesystems, plus a lookup of
// all mount points so a walk never crosses into another one.
func suidRoots() ([]string, map[string]bool) {
	all := map[string]bool{}
	var roots []string
	for _, m := range mounts() {
		all[m.point] = true
		if !suidFSTypes[m.fstype] || underAny(m.point, suidSkip) {
			continue
		}
		if (m.point == "/dev" || strings.HasPrefix(m.point, "/dev/")) && m.point != "/dev/shm" {
			continue
		}
		roots = append(roots, m.point)
	}
	sort.Strings(roots)
	return roots, all
}

// dpkgInfo answers who owns a path and when that package was last
// installed. On systems without dpkg it knows nothing.
type dpkgInfo struct {
	owner     map[string]string    // path -> package
	installed map[string]time.Time // package -> mtime of its .list
	override  map[string]bool      // dpkg-statoverride paths
	ok        bool
}

// lookupDpkg reads the file lists of all packages once and keeps only the
// paths asked for, so memory stays small.
func lookupDpkg(paths []string) dpkgInfo {
	info := dpkgInfo{owner: map[string]string{}, installed: map[string]time.Time{}, override: map[string]bool{}}
	lists, _ := filepath.Glob("/var/lib/dpkg/info/*.list")
	if len(lists) == 0 {
		return info
	}
	info.ok = true
	want := map[string]string{} // candidate spelling -> real path
	for _, p := range paths {
		want[p] = p
		// usrmerge: dpkg may list /bin/su for /usr/bin/su and the reverse
		if rest, ok := strings.CutPrefix(p, "/usr"); ok {
			want[rest] = p
		} else {
			want["/usr"+p] = p
		}
	}
	for _, l := range lists {
		f, err := os.Open(l)
		if err != nil {
			continue
		}
		pkg := strings.TrimSuffix(filepath.Base(l), ".list")
		pkg, _, _ = strings.Cut(pkg, ":")
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if real, ok := want[sc.Text()]; ok {
				info.owner[real] = pkg
				if fi, err := os.Stat(l); err == nil {
					info.installed[pkg] = fi.ModTime()
				}
			}
		}
		f.Close()
	}
	if b, err := os.ReadFile("/var/lib/dpkg/statoverride"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if f := strings.Fields(line); len(f) == 4 {
				info.override[f[3]] = true
			}
		}
	}
	return info
}

func suidWhere(p string) string {
	switch {
	case underAny(p, suidTmpDirs):
		return "tmp"
	case underAny(p, []string{"/home", "/root"}):
		return "home"
	}
	return "system"
}

// suidEvent describes a new or changed entry, with what makes it odd.
func suidEvent(p string, f *SuidFile, dpkg dpkgInfo) map[string]any {
	d := map[string]any{"path": p, "mode": fmt.Sprintf("%04o", f.Mode), "uid": f.UID, "gid": f.GID, "where": suidWhere(p)}
	if f.Caps != "" {
		d["caps"] = f.Caps
	}
	var bits []string
	if f.Mode&syscall.S_ISUID != 0 {
		bits = append(bits, "setuid")
	}
	if f.Mode&syscall.S_ISGID != 0 {
		bits = append(bits, "setgid")
	}
	d["bits"] = strings.Join(bits, ",")
	_, danger := parseCapsString(f.Caps)
	d["dangerous_caps"] = danger
	if !dpkg.ok {
		return d
	}
	d["pkgdb"] = true
	pkg := dpkg.owner[p]
	d["package"] = pkg
	if pkg != "" && !dpkg.override[p] {
		// Set after the package was installed: chmod u+s on a packaged
		// program, the GTFOBins classic.
		var st syscall.Stat_t
		if syscall.Stat(p, &st) == nil {
			ctime := time.Unix(st.Ctim.Sec, st.Ctim.Nsec)
			if inst := dpkg.installed[pkg]; !inst.IsZero() && ctime.Sub(inst) > 10*time.Minute {
				d["changed_after_install"] = true
			}
		}
	}
	return d
}

// parseCapsString tells whether a caps string from the inventory contains a
// dangerous capability.
func parseCapsString(caps string) (string, bool) {
	if caps == "" {
		return "", false
	}
	for bit, name := range capNames {
		if dangerousCaps[bit] && strings.Contains(caps, name) {
			return caps, true
		}
	}
	return caps, false
}

func suidStatePath(dir string) string { return filepath.Join(dir, "suid.json") }

func loadSuidState(dir string) *SuidState {
	ss := &SuidState{}
	if raw, err := os.ReadFile(suidStatePath(dir)); err == nil {
		json.Unmarshal(raw, ss)
	}
	if ss.Files == nil {
		ss.Files = map[string]*SuidFile{}
	}
	return ss
}

// diffSuid compares a walk below roots with the inventory and emits events.
// Only entries below roots are compared, so a quick walk of /tmp does not
// remove everything else.
func (a *Agent) diffSuid(ss *SuidState, roots []string, found map[string]*SuidFile) bool {
	changed := false
	var fresh []string
	for p, f := range found {
		old := ss.Files[p]
		if old == nil || old.Mode != f.Mode || old.Caps != f.Caps || old.UID != f.UID || old.Inode != f.Inode {
			fresh = append(fresh, p)
		}
	}
	sort.Strings(fresh)
	var dpkg dpkgInfo
	if len(fresh) > 0 {
		dpkg = lookupDpkg(fresh)
	}
	for _, p := range fresh {
		f, old := found[p], ss.Files[p]
		ss.Files[p] = f
		changed = true
		d := suidEvent(p, f, dpkg)
		if old != nil && old.Mode == f.Mode && old.Caps == f.Caps && old.UID == f.UID &&
			d["package"] != nil && d["package"] != "" && d["changed_after_install"] != true {
			continue // the package was upgraded and replaced the file
		}
		if !ss.Baselined {
			// Existing entries are accepted, except the ones that are odd
			// already: they are named once.
			if d["where"] == "system" && (!dpkg.ok || d["package"] != "") && d["changed_after_install"] != true {
				continue
			}
			d["baseline"] = true
		} else if old != nil {
			d["old_mode"] = fmt.Sprintf("%04o", old.Mode)
			if old.Caps != "" {
				d["old_caps"] = old.Caps
			}
		}
		a.emit(proto.NewEvent("file.suid", d))
	}
	for p := range ss.Files {
		if _, ok := found[p]; !ok && underAny(p, roots) {
			delete(ss.Files, p)
			changed = true
			a.emit(proto.NewEvent("file.suid_removed", map[string]any{"path": p}))
		}
	}
	return changed
}

func (a *Agent) runSuid(ctx context.Context) {
	ss := loadSuidState(a.cfg.StateDir)
	save := func() {
		if raw, err := json.Marshal(ss); err == nil {
			writeFileAtomic(suidStatePath(a.cfg.StateDir), raw, 0o600)
		}
	}
	full := time.NewTimer(3 * time.Minute)
	quick := time.NewTicker(suidQuickEvery)
	defer full.Stop()
	defer quick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-full.C:
			roots, all := suidRoots()
			start := time.Now()
			found, err := walkSuid(ctx, roots, all)
			if ctx.Err() != nil {
				return
			}
			if err != nil {
				a.emit(proto.NewEvent("agent.warning", map[string]any{"collector": "suid", "error": err.Error()}))
			} else {
				if a.diffSuid(ss, roots, found) || !ss.Baselined {
					ss.Baselined = true
					save()
				}
				a.emit(proto.NewEvent("suid.scan", map[string]any{"files": len(found), "roots": roots, "seconds": int(time.Since(start).Seconds())}))
			}
			full.Reset(suidFullEvery)
		case <-quick.C:
			if !ss.Baselined {
				continue
			}
			var roots []string
			for _, d := range suidTmpDirs {
				if fi, err := os.Lstat(d); err == nil && fi.IsDir() {
					roots = append(roots, d)
				}
			}
			_, all := suidRoots()
			for _, r := range roots {
				delete(all, r) // a tmpfs on /tmp is still walked
			}
			found, err := walkSuid(ctx, roots, all)
			if err == nil && a.diffSuid(ss, roots, found) {
				save()
			}
		}
	}
}
