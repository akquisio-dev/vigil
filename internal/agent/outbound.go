package agent

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

// Outbound connections: the agent reports each new combination of program,
// remote network and port once. Inbound connections (to a listening port)
// and loopback traffic are left out, so a busy game or web server stays
// quiet; what remains is what this host itself reaches out to.

type conn struct {
	local, remote net.IP
	lport, rport  int
	inode         string
}

func readEstablished() (out []conn, listening map[int]bool) {
	listening = map[int]bool{}
	for _, f := range []string{"tcp", "tcp6"} {
		fh, err := os.Open("/proc/net/" + f)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fh)
		sc.Scan()
		for sc.Scan() {
			fl := strings.Fields(sc.Text())
			if len(fl) < 10 {
				continue
			}
			lip, lport, err1 := parseProcNetAddr(fl[1])
			rip, rport, err2 := parseProcNetAddr(fl[2])
			if err1 != nil || err2 != nil {
				continue
			}
			switch fl[3] {
			case "0A":
				listening[lport] = true
			case "01":
				out = append(out, conn{local: lip, remote: rip, lport: lport, rport: rport, inode: fl[9]})
			}
		}
		fh.Close()
	}
	return out, listening
}

// netKey groups remote addresses by /24 (IPv4) or /48 (IPv6), so services
// behind rotating addresses of one provider are reported once.
func netKey(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return net.IP(v4.Mask(net.CIDRMask(24, 32))).String() + "/24"
	}
	return ip.Mask(net.CIDRMask(48, 128)).String() + "/48"
}

func remoteWorthIt(ip net.IP) bool {
	return !(ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsMulticast())
}

type procID struct {
	comm, exe, uid string
	pid            int
}

func socketProcs(want map[string]bool) map[string]procID {
	out := map[string]procID{}
	procs, _ := filepath.Glob("/proc/[0-9]*")
	for _, p := range procs {
		fds, err := os.ReadDir(p + "/fd")
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(p + "/fd/" + fd.Name())
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			inode := link[8 : len(link)-1]
			if !want[inode] {
				continue
			}
			if _, done := out[inode]; done {
				continue
			}
			comm, _ := os.ReadFile(p + "/comm")
			exe, _ := os.Readlink(p + "/exe")
			uid := ""
			if b, err := os.ReadFile(p + "/status"); err == nil {
				for _, l := range strings.Split(string(b), "\n") {
					if strings.HasPrefix(l, "Uid:") {
						if f := strings.Fields(l); len(f) > 1 {
							uid = f[1]
						}
					}
				}
			}
			pid, _ := strconv.Atoi(filepath.Base(p))
			out[inode] = procID{comm: strings.TrimSpace(string(comm)), exe: strings.TrimSuffix(exe, " (deleted)"), uid: uid, pid: pid}
		}
	}
	return out
}

const maxOutboundSeen = 5000

// listenGrace keeps a port a service port for a while after its listener
// went away: while a service restarts (sshd during a package upgrade), the
// connections it accepted are still open, and they came in.
const listenGrace = 10 * time.Minute

// servicePort records the ports listening now and tells whether a local
// port listens or did within listenGrace.
func servicePorts(seen map[int]time.Time, listening map[int]bool, now time.Time) func(int) bool {
	for p := range listening {
		seen[p] = now
	}
	for p, t := range seen {
		if now.Sub(t) > listenGrace {
			delete(seen, p)
		}
	}
	return func(p int) bool { _, ok := seen[p]; return ok }
}

func (a *Agent) scanOutbound() {
	conns, listening := readEstablished()
	if a.outSeen == nil {
		a.outSeen = map[string]bool{}
	}
	if a.listenSeen == nil {
		a.listenSeen = map[int]time.Time{}
	}
	inbound := servicePorts(a.listenSeen, listening, time.Now())
	// first pass without process lookup: only walk /proc when something is new
	type cand struct {
		c   conn
		key string
	}
	var fresh []cand
	want := map[string]bool{}
	for _, c := range conns {
		if inbound(c.lport) || !remoteWorthIt(c.remote) {
			continue
		}
		k := netKey(c.remote) + ":" + strconv.Itoa(c.rport)
		if a.outSeen[k] {
			continue
		}
		fresh = append(fresh, cand{c, k})
		want[c.inode] = true
	}
	if len(fresh) == 0 {
		return
	}
	owners := socketProcs(want)
	sent := 0
	for _, f := range fresh {
		if a.outSeen[f.key] {
			continue
		}
		if len(a.outSeen) >= maxOutboundSeen {
			a.outSeen = map[string]bool{} // start over rather than grow without bound
		}
		a.outSeen[f.key] = true
		p := owners[f.c.inode]
		if sent >= 50 {
			continue
		}
		sent++
		private := f.c.remote.IsPrivate()
		d := map[string]any{
			"remote_ip": f.c.remote.String(), "remote_port": f.c.rport, "local_port": f.c.lport,
			"process": p.comm, "exe": p.exe, "uid": p.uid, "private": private,
		}
		a.tagContainer(d, p.pid)
		a.emit(proto.NewEvent("net.connection", d))
	}
}
