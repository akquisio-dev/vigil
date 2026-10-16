package agent

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/akquisio-dev/vigil/internal/proto"
)

// Port is one listening socket or one Docker NAT publication.
type Port struct {
	Proto   string `json:"proto"`
	Addr    string `json:"addr"`
	Port    int    `json:"port"`
	Scope   string `json:"scope"` // loopback | any | address
	Via     string `json:"via"`   // socket | docker
	Process string `json:"process,omitempty"`
	Target  string `json:"target,omitempty"` // docker: container address
}

func (p Port) Key() string { return fmt.Sprintf("%s/%s/%s:%d", p.Via, p.Proto, p.Addr, p.Port) }

func scopeOf(ip net.IP) string {
	switch {
	case ip == nil:
		return "address"
	case ip.IsLoopback():
		return "loopback"
	case ip.IsUnspecified():
		return "any"
	}
	return "address"
}

// parseProcNetAddr decodes "0100007F:1F90" (IPv4) and the 32 hex digit IPv6
// form, both stored as host-endian 32-bit words.
func parseProcNetAddr(s string) (net.IP, int, error) {
	host, port, ok := strings.Cut(s, ":")
	if !ok {
		return nil, 0, fmt.Errorf("bad address %q", s)
	}
	raw, err := hex.DecodeString(host)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return nil, 0, fmt.Errorf("bad address %q", s)
	}
	for i := 0; i < len(raw); i += 4 {
		raw[i], raw[i+1], raw[i+2], raw[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
	}
	p, err := strconv.ParseUint(port, 16, 16)
	if err != nil {
		return nil, 0, err
	}
	return net.IP(raw), int(p), nil
}

type sock struct {
	port  Port
	inode string
}

func readProcNet() []sock {
	var out []sock
	for _, f := range []string{"tcp", "tcp6", "udp", "udp6"} {
		fh, err := os.Open("/proc/net/" + f)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fh)
		sc.Scan() // header
		for sc.Scan() {
			fl := strings.Fields(sc.Text())
			if len(fl) < 10 {
				continue
			}
			isTCP := strings.HasPrefix(f, "tcp")
			if isTCP && fl[3] != "0A" { // LISTEN
				continue
			}
			if !isTCP {
				if fl[3] != "07" {
					continue
				}
				rip, rport, err := parseProcNetAddr(fl[2])
				if err != nil || !rip.IsUnspecified() || rport != 0 {
					continue // connected UDP socket, not a server
				}
			}
			ip, port, err := parseProcNetAddr(fl[1])
			if err != nil {
				continue
			}
			proto := "tcp"
			if !isTCP {
				proto = "udp"
			}
			out = append(out, sock{
				port:  Port{Proto: proto, Addr: ip.String(), Port: port, Scope: scopeOf(ip), Via: "socket"},
				inode: fl[9],
			})
		}
		fh.Close()
	}
	return out
}

// socketOwners maps socket inodes to process names by walking /proc/*/fd.
// Only called when the port list actually changed.
func socketOwners(want map[string]bool) map[string]string {
	owners := map[string]string{}
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
			if !want[inode] || owners[inode] != "" {
				continue
			}
			comm, _ := os.ReadFile(p + "/comm")
			owners[inode] = strings.TrimSpace(string(comm)) + "/" + filepath.Base(p)
		}
	}
	return owners
}

// dockerPorts reads the DNAT rules Docker writes into the nat table. These
// publications are reached through FORWARD, so INPUT rules such as ufw's do
// not apply to them, and with the userland proxy disabled they never show
// up as a listening socket either.
func dockerPorts() []Port {
	bin, err := exec.LookPath("iptables-save")
	if err != nil {
		return nil
	}
	out, err := exec.Command(bin, "-t", "nat").Output()
	if err != nil {
		return nil
	}
	return ParseDockerNAT(string(out))
}

func ParseDockerNAT(dump string) []Port {
	var ports []Port
	for _, line := range strings.Split(dump, "\n") {
		if !strings.HasPrefix(line, "-A DOCKER ") || !strings.Contains(line, "-j DNAT") {
			continue
		}
		f := strings.Fields(line)
		p := Port{Via: "docker", Proto: "tcp", Addr: "0.0.0.0", Scope: "any"}
		for i := 0; i+1 < len(f); i++ {
			switch f[i] {
			case "-d":
				ip, _, err := net.ParseCIDR(f[i+1])
				if err != nil {
					ip = net.ParseIP(f[i+1])
				}
				if ip != nil {
					p.Addr = ip.String()
					p.Scope = scopeOf(ip)
				}
			case "-p":
				p.Proto = f[i+1]
			case "--dport":
				p.Port, _ = strconv.Atoi(f[i+1])
			case "--to-destination":
				p.Target = f[i+1]
			}
		}
		if p.Port > 0 {
			ports = append(ports, p)
		}
	}
	return ports
}

func (a *Agent) scanPorts() {
	if !on(a.cfg.Ports) {
		return
	}
	socks := readProcNet()
	current := map[string]Port{}
	inodes := map[string]string{}
	for _, s := range socks {
		k := s.port.Key()
		if _, dup := current[k]; !dup {
			current[k] = s.port
			inodes[k] = s.inode
		}
	}
	if on(a.cfg.Docker) {
		for _, p := range dockerPorts() {
			current[p.Key()] = p
		}
	}

	old := map[string]Port{}
	for _, p := range a.state.Ports {
		old[p.Key()] = p
	}
	changed := len(old) != len(current)
	for k := range current {
		if _, ok := old[k]; !ok {
			changed = true
		}
	}
	if !changed && a.portsSent {
		return
	}

	// Resolve owners only for new sockets; keep known names otherwise.
	want := map[string]bool{}
	for k, p := range current {
		if o, ok := old[k]; ok {
			p.Process = o.Process
			current[k] = p
		} else if p.Via == "socket" {
			want[inodes[k]] = true
		}
	}
	if len(want) > 0 {
		owners := socketOwners(want)
		for k, p := range current {
			if n := owners[inodes[k]]; n != "" {
				p.Process = n
				current[k] = p
			}
		}
	}

	list := make([]Port, 0, len(current))
	for _, p := range current {
		list = append(list, p)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Key() < list[j].Key() })

	if a.state.Initialized {
		for k, p := range current {
			if _, ok := old[k]; !ok {
				a.emit(proto.NewEvent("port.opened", portData(p)))
			}
		}
		for k, p := range old {
			if _, ok := current[k]; !ok {
				a.emit(proto.NewEvent("port.closed", portData(p)))
			}
		}
	}
	snap := make([]any, len(list))
	for i, p := range list {
		snap[i] = portData(p)
	}
	a.emit(proto.NewEvent("port.snapshot", map[string]any{"ports": snap}))
	a.state.Ports = list
	a.portsSent = true
}

func portData(p Port) map[string]any {
	d := map[string]any{"key": p.Key(), "proto": p.Proto, "addr": p.Addr, "port": p.Port, "scope": p.Scope, "via": p.Via}
	if p.Process != "" {
		d["process"] = p.Process
	}
	if p.Target != "" {
		d["target"] = p.Target
	}
	return d
}
