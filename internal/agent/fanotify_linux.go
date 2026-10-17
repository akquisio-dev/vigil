//go:build linux && (amd64 || arm64)

package agent

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/akquisio-dev/vigil/internal/proto"
)

// Notification class only. Permission events would make every open of a
// canary wait for this process; if the agent hung, so would the reader.
const (
	fanClassNotif   = 0x0
	fanCloexec      = 0x1
	fanMarkAdd      = 0x1
	fanMarkDontFoll = 0x4
	fanMarkFlush    = 0x80
	fanOpen         = 0x20
	fanQOverflow    = 0x4000
	atFdcwd         = -100
	metaLen         = 24
)

type canaryWatch struct {
	fd int
}

func newCanaryWatch() (*canaryWatch, error) {
	fd, _, errno := syscall.Syscall(syscall.SYS_FANOTIFY_INIT, fanClassNotif|fanCloexec,
		uintptr(syscall.O_RDONLY|syscall.O_LARGEFILE|syscall.O_CLOEXEC), 0)
	if errno != 0 {
		return nil, fmt.Errorf("fanotify_init: %w", errno)
	}
	return &canaryWatch{fd: int(fd)}, nil
}

func (w *canaryWatch) mark(path string) error {
	p, err := syscall.BytePtrFromString(path)
	if err != nil {
		return err
	}
	dirfd := atFdcwd
	_, _, errno := syscall.Syscall6(syscall.SYS_FANOTIFY_MARK, uintptr(w.fd), fanMarkAdd|fanMarkDontFoll,
		fanOpen, uintptr(dirfd), uintptr(unsafe.Pointer(p)), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func (w *canaryWatch) flush() {
	syscall.Syscall6(syscall.SYS_FANOTIFY_MARK, uintptr(w.fd), fanMarkFlush, 0, 0, 0, 0)
}

// remarkCanaries re-adds all marks. Marks sit on inodes, so this also picks
// up canaries that were recreated.
func (a *Agent) remarkCanaries() {
	if a.watch == nil {
		return
	}
	paths := a.activeCanaryPaths()
	a.mu.Lock()
	a.canaryPaths = paths
	a.mu.Unlock()
	a.watch.flush()
	for p := range paths {
		if err := a.watch.mark(p); err != nil {
			log.Printf("canary: mark %s: %v", p, err)
		}
	}
}

func (a *Agent) runCanaryWatch() {
	if a.watch == nil {
		return
	}
	self := int32(os.Getpid())
	seen := map[string]time.Time{}
	buf := make([]byte, 8192)
	for {
		n, err := syscall.Read(a.watch.fd, buf)
		if err != nil {
			if err == syscall.EINTR || err == syscall.EAGAIN {
				continue
			}
			log.Printf("canary: read: %v", err)
			return
		}
		for off := 0; off+metaLen <= n; {
			evLen := int(binary.LittleEndian.Uint32(buf[off:]))
			if evLen < metaLen || off+evLen > n {
				break
			}
			mask := binary.LittleEndian.Uint64(buf[off+8:])
			fd := int32(binary.LittleEndian.Uint32(buf[off+16:]))
			pid := int32(binary.LittleEndian.Uint32(buf[off+20:]))
			off += evLen

			if mask&fanQOverflow != 0 {
				a.emit(proto.NewEvent("canary.overflow", nil))
				continue
			}
			path := ""
			if fd >= 0 {
				path, _ = os.Readlink("/proc/self/fd/" + strconv.Itoa(int(fd)))
				syscall.Close(int(fd))
			}
			if pid == self {
				continue
			}
			a.reportCanaryOpen(path, int(pid), seen)
		}
	}
}

func (a *Agent) reportCanaryOpen(path string, pid int, seen map[string]time.Time) {
	a.mu.Lock()
	id := a.canaryPaths[path]
	a.mu.Unlock()
	info := procInfo(pid)
	for _, ig := range a.cfg.CanaryIgnoreExe {
		if info["exe"] == ig {
			return
		}
	}
	// One report per canary and process within ten minutes; an editor
	// opening the file five times is still one incident.
	key := path + "|" + strconv.Itoa(pid)
	now := time.Now()
	if t, ok := seen[key]; ok && now.Sub(t) < 10*time.Minute {
		return
	}
	seen[key] = now
	if len(seen) > 1000 {
		for k, t := range seen {
			if now.Sub(t) > 10*time.Minute {
				delete(seen, k)
			}
		}
	}
	info["canary_id"] = id
	info["path"] = path
	a.emit(proto.NewEvent("canary.opened", info))
	a.flushSoon()
	go a.snapshot(pid, "canary.opened", "", "")
}

// procInfo collects who touched a canary. The process may already be gone
// (cat exits quickly); whatever could be read is reported.
func procInfo(pid int) map[string]any {
	d := map[string]any{"pid": pid}
	base := "/proc/" + strconv.Itoa(pid)
	if exe, err := os.Readlink(base + "/exe"); err == nil {
		d["exe"] = exe
	}
	// A short-lived reader (cat, head) is often a zombie by now: exe is
	// gone, but comm, status and the parent chain are still readable.
	if comm, err := os.ReadFile(base + "/comm"); err == nil {
		d["comm"] = strings.TrimSpace(string(comm))
	}
	if raw, err := os.ReadFile(base + "/cmdline"); err == nil {
		cmd := strings.TrimSpace(strings.ReplaceAll(string(raw), "\x00", " "))
		if len(cmd) > 300 {
			cmd = cmd[:300]
		}
		d["cmdline"] = cmd
	}
	if v, err := os.ReadFile(base + "/loginuid"); err == nil {
		d["loginuid"] = strings.TrimSpace(string(v))
	}
	if v, err := os.ReadFile(base + "/sessionid"); err == nil {
		d["sessionid"] = strings.TrimSpace(string(v))
	}
	uid, ppid := statusFields(pid)
	if uid != "" {
		d["uid"] = uid
	}
	var chain []string
	for i := 0; i < 10 && ppid > 1; i++ {
		comm, _ := os.ReadFile("/proc/" + strconv.Itoa(ppid) + "/comm")
		chain = append(chain, strings.TrimSpace(string(comm))+"("+strconv.Itoa(ppid)+")")
		_, ppid = statusFields(ppid)
	}
	if len(chain) > 0 {
		d["ancestry"] = chain
	}
	return d
}

func statusFields(pid int) (uid string, ppid int) {
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return "", 0
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if v, ok := strings.CutPrefix(line, "Uid:"); ok {
			if f := strings.Fields(v); len(f) > 0 {
				uid = f[0]
			}
		} else if v, ok := strings.CutPrefix(line, "PPid:"); ok {
			ppid, _ = strconv.Atoi(strings.TrimSpace(v))
		}
	}
	return uid, ppid
}
