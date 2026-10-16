//go:build linux

package agent

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/akquisio-dev/vigil/internal/proto"
)

// The process events connector (NETLINK_CONNECTOR, CN_IDX_PROC) tells the
// agent about every exec on the host. It needs CAP_NET_ADMIN and only works
// in the initial network namespace.
const (
	netlinkConnector = 11
	cnIdxProc        = 1
	cnValProc        = 1
	procCnMcastOn    = 1
	procEventExec    = 0x00000002
	nlmsgDone        = 3
)

func procConnector() (int, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, netlinkConnector)
	if err != nil {
		return -1, err
	}
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Groups: cnIdxProc}); err != nil {
		syscall.Close(fd)
		return -1, err
	}
	// nlmsghdr (16) + cn_msg (20) + op (4)
	msg := make([]byte, 40)
	ne := binary.NativeEndian
	ne.PutUint32(msg[0:], 40)
	ne.PutUint16(msg[4:], nlmsgDone)
	ne.PutUint32(msg[12:], uint32(os.Getpid()))
	ne.PutUint32(msg[16:], cnIdxProc)
	ne.PutUint32(msg[20:], cnValProc)
	ne.PutUint16(msg[32:], 4)
	ne.PutUint32(msg[36:], procCnMcastOn)
	if err := syscall.Sendto(fd, msg, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		syscall.Close(fd)
		return -1, err
	}
	return fd, nil
}

func (a *Agent) runProcesses(ctx context.Context) {
	fd, err := procConnector()
	if err != nil {
		a.emit(proto.NewEvent("agent.warning", map[string]any{"collector": "process", "error": err.Error()}))
		return
	}
	go func() {
		<-ctx.Done()
		syscall.Close(fd)
	}()
	buf := make([]byte, 64<<10)
	ne := binary.NativeEndian
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if errors.Is(err, syscall.ENOBUFS) || errors.Is(err, syscall.EINTR) {
				continue // a burst overflowed the socket; keep going
			}
			a.emit(proto.NewEvent("agent.warning", map[string]any{"collector": "process", "error": err.Error()}))
			return
		}
		for off := 0; off+16 <= n; {
			l := int(ne.Uint32(buf[off:]))
			if l < 16 || off+l > n {
				break
			}
			// nlmsghdr 16, cn_msg 20, proc_event: what 4, cpu 4, timestamp 8, then the event
			ev := buf[off+36 : off+l]
			if len(ev) >= 24 && ne.Uint32(ev) == procEventExec {
				pid, tgid := int(ne.Uint32(ev[16:])), int(ne.Uint32(ev[20:]))
				if pid == tgid {
					if info := readExec(pid); info != nil {
						a.reportExec(info)
					}
				}
			}
			off += (l + 3) &^ 3
		}
	}
}

func readExec(pid int) *ExecInfo {
	dir := "/proc/" + strconv.Itoa(pid)
	exe, err := os.Readlink(dir + "/exe")
	if err != nil {
		return nil // already gone, or a kernel thread
	}
	e := &ExecInfo{PID: pid, Exe: exe}
	if strings.HasSuffix(exe, " (deleted)") {
		e.Exe, e.Deleted = strings.TrimSuffix(exe, " (deleted)"), true
	}
	if b, err := os.ReadFile(dir + "/cmdline"); err == nil {
		if len(b) > 4096 {
			b = b[:4096]
		}
		e.Cmdline = strings.TrimSpace(string(bytes.ReplaceAll(b, []byte{0}, []byte{' '})))
	}
	e.Cwd, _ = os.Readlink(dir + "/cwd")
	if b, err := os.ReadFile(dir + "/status"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			k, v, _ := strings.Cut(line, ":")
			f := strings.Fields(v)
			if len(f) == 0 {
				continue
			}
			switch k {
			case "Name":
				e.Comm = f[0]
			case "PPid":
				e.PPID, _ = strconv.Atoi(f[0])
			case "Uid":
				e.UID, _ = strconv.Atoi(f[0])
			}
		}
	}
	for _, fd := range []string{"0", "1"} {
		if l, err := os.Readlink(dir + "/fd/" + fd); err == nil && strings.HasPrefix(l, "socket:") && isNetSocket(l) {
			e.StdioSocket = true
		}
	}
	if e.PPID > 0 {
		pdir := "/proc/" + strconv.Itoa(e.PPID)
		e.ParentExe, _ = os.Readlink(pdir + "/exe")
		if b, err := os.ReadFile(pdir + "/comm"); err == nil {
			e.ParentComm = strings.TrimSpace(string(b))
		}
	}
	return e
}

// isNetSocket tells TCP and UDP sockets from Unix sockets, which shells get
// from terminals multiplexers and service managers all the time.
func isNetSocket(link string) bool {
	inode := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
	for _, f := range []string{"tcp", "tcp6", "udp", "udp6"} {
		b, err := os.ReadFile("/proc/net/" + f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n")[1:] {
			if fl := strings.Fields(line); len(fl) > 9 && fl[9] == inode {
				return true
			}
		}
	}
	return false
}
