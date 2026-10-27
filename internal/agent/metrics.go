package agent

import (
	"bufio"
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

// Host load for the dashboard's host view: one sample a minute, read from
// /proc and statfs only (no programs are started, so nothing here looks
// like the agent itself misbehaving). Samples wait beside the event queue,
// at most metricsKeep of them, and go out with the next batch.

const (
	metricsEvery = time.Minute
	metricsKeep  = 30 // half an hour of samples survives a server outage
	metricsPeers = 64
	metricsTop   = 5
)

type cpuTicks struct{ total, idle, iowait, steal uint64 }

// readCPU sums the first line of /proc/stat: user nice system idle iowait
// irq softirq steal (guest time is already part of user).
func readCPU(path string) (cpuTicks, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return cpuTicks{}, false
	}
	line, _, _ := strings.Cut(string(b), "\n")
	fl := strings.Fields(line)
	if len(fl) < 9 || fl[0] != "cpu" {
		return cpuTicks{}, false
	}
	var c cpuTicks
	for i := 1; i <= 8; i++ {
		v, _ := strconv.ParseUint(fl[i], 10, 64)
		c.total += v
		switch i {
		case 4:
			c.idle = v
		case 5:
			c.iowait = v
		case 8:
			c.steal = v
		}
	}
	return c, true
}

// cpuShares turns two readings into percent busy, waiting for disk, and
// taken by the hypervisor.
func cpuShares(prev, cur cpuTicks) (busy, iowait, steal float64) {
	d := float64(cur.total - prev.total)
	if cur.total <= prev.total || d == 0 {
		return 0, 0, 0
	}
	idle := float64(cur.idle-prev.idle) + float64(cur.iowait-prev.iowait)
	pct := func(v float64) float64 { return clampPct(v / d * 100) }
	return pct(d - idle), pct(float64(cur.iowait - prev.iowait)), pct(float64(cur.steal - prev.steal))
}

func clampPct(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return float64(int(v*10+0.5)) / 10
}

// readMeminfo returns the fields in bytes.
func readMeminfo(path string) map[string]uint64 {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	out := map[string]uint64{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, rest, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		fl := strings.Fields(rest)
		if len(fl) == 0 {
			continue
		}
		v, _ := strconv.ParseUint(fl[0], 10, 64)
		if len(fl) > 1 && fl[1] == "kB" {
			v <<= 10
		}
		out[k] = v
	}
	return out
}

func readLoad(path string) (load [3]float64) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	fl := strings.Fields(string(b))
	for i := 0; i < 3 && i < len(fl); i++ {
		load[i], _ = strconv.ParseFloat(fl[i], 64)
	}
	return
}

func readUptime(path string) int64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	fl := strings.Fields(string(b))
	if len(fl) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(fl[0], 64)
	return int64(v)
}

// wholeDisk keeps the devices whose traffic is not counted again on
// another one: partitions, device mapper and RAID sit on top of a disk.
func wholeDisk(name string) bool {
	for _, p := range []string{"loop", "ram", "zram", "sr", "fd", "dm-", "md", "nbd"} {
		if strings.HasPrefix(name, p) {
			return false
		}
	}
	_, err := os.Stat("/sys/block/" + name)
	return err == nil
}

// readDiskstats returns sectors read and written per whole disk; a sector
// in /proc/diskstats is always 512 bytes.
func readDiskstats(path string, whole func(string) bool) map[string][2]uint64 {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	out := map[string][2]uint64{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fl := strings.Fields(sc.Text())
		if len(fl) < 10 || !whole(fl[2]) {
			continue
		}
		r, _ := strconv.ParseUint(fl[5], 10, 64)
		w, _ := strconv.ParseUint(fl[9], 10, 64)
		out[fl[2]] = [2]uint64{r, w}
	}
	return out
}

func diskDelta(prev, cur map[string][2]uint64) (r, w uint64) {
	for n, c := range cur {
		p, ok := prev[n]
		if !ok || c[0] < p[0] || c[1] < p[1] {
			continue
		}
		r += (c[0] - p[0]) * 512
		w += (c[1] - p[1]) * 512
	}
	return
}

var diskFS = map[string]bool{"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "zfs": true, "f2fs": true, "jfs": true, "vfat": true, "reiserfs": true}

// readMounts lists the real file systems, one mount per device.
func readMounts(path string) (out [][2]string) {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fl := strings.Fields(sc.Text())
		if len(fl) < 3 || !diskFS[fl[2]] || seen[fl[0]] {
			continue
		}
		mnt := strings.ReplaceAll(fl[1], `\040`, " ")
		if strings.HasPrefix(mnt, "/snap/") || strings.HasPrefix(mnt, "/var/lib/docker/") {
			continue
		}
		seen[fl[0]] = true
		out = append(out, [2]string{mnt, fl[2]})
	}
	return out
}

func diskUsage(mounts [][2]string) (list []proto.DiskUse, fullest float64) {
	for _, m := range mounts {
		var st syscall.Statfs_t
		if syscall.Statfs(m[0], &st) != nil || st.Blocks == 0 {
			continue
		}
		total := st.Blocks * uint64(st.Bsize)
		used := (st.Blocks - st.Bfree) * uint64(st.Bsize)
		list = append(list, proto.DiskUse{Mount: m[0], FS: m[1], Total: total, Used: used})
		// what users can still write, as df shows it
		if avail := used + st.Bavail*uint64(st.Bsize); avail > 0 {
			if p := clampPct(float64(used) / float64(avail) * 100); p > fullest {
				fullest = p
			}
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Total > list[j].Total })
	if len(list) > 8 {
		list = list[:8]
	}
	return list, fullest
}

type procTicks struct {
	ticks uint64
	comm  string
}

// readProcStat parses /proc/<pid>/stat: the name sits in parentheses and
// may hold spaces, so the fields are counted from the closing one.
func readProcStat(b []byte) (comm string, ticks, rssPages uint64, ok bool) {
	s := string(b)
	open, close := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
	if open < 0 || close < open {
		return "", 0, 0, false
	}
	fl := strings.Fields(s[close+1:])
	// after the name: state(0) ... utime(11) stime(12) ... rss(21)
	if len(fl) < 22 {
		return "", 0, 0, false
	}
	ut, _ := strconv.ParseUint(fl[11], 10, 64)
	st, _ := strconv.ParseUint(fl[12], 10, 64)
	rss, _ := strconv.ParseUint(fl[21], 10, 64)
	return s[open+1 : close], ut + st, rss, true
}

// clockTicks is USER_HZ, 100 on every Linux the agent runs on.
const clockTicks = 100

// topProcs reads every process once and returns the busiest by CPU and by
// memory, the number of processes, and the tick counts for next time.
func topProcs(prev map[int]procTicks, secs float64) ([]proto.ProcLoad, int, map[int]procTicks) {
	paths, _ := filepath.Glob("/proc/[0-9]*")
	cur := make(map[int]procTicks, len(paths))
	all := make([]proto.ProcLoad, 0, len(paths))
	page := uint64(os.Getpagesize())
	for _, p := range paths {
		pid, err := strconv.Atoi(filepath.Base(p))
		if err != nil {
			continue
		}
		b, err := os.ReadFile(p + "/stat")
		if err != nil {
			continue
		}
		comm, ticks, rss, ok := readProcStat(b)
		if !ok {
			continue
		}
		cur[pid] = procTicks{ticks, comm}
		cpu := 0.0
		if old, seen := prev[pid]; seen && old.comm == comm && ticks >= old.ticks && secs > 0 {
			cpu = clampProc(float64(ticks-old.ticks) / clockTicks / secs * 100)
		}
		all = append(all, proto.ProcLoad{PID: pid, Comm: comm, CPU: cpu, RSS: rss * page})
	}
	pick := map[int]bool{}
	sort.Slice(all, func(i, j int) bool { return all[i].CPU > all[j].CPU })
	for i := 0; i < len(all) && i < metricsTop; i++ {
		if all[i].CPU > 0 {
			pick[all[i].PID] = true
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].RSS > all[j].RSS })
	for i := 0; i < len(all) && i < metricsTop; i++ {
		pick[all[i].PID] = true
	}
	var top []proto.ProcLoad
	for _, p := range all {
		if pick[p.PID] {
			p.Exe, _ = os.Readlink("/proc/" + strconv.Itoa(p.PID) + "/exe")
			p.Exe = strings.TrimSuffix(p.Exe, " (deleted)")
			top = append(top, p)
		}
	}
	sort.Slice(top, func(i, j int) bool {
		return top[i].CPU > top[j].CPU || top[i].CPU == top[j].CPU && top[i].RSS > top[j].RSS
	})
	return top, len(paths), cur
}

// clampProc keeps one decimal; a multi-threaded process may use several cores.
func clampProc(v float64) float64 {
	if v < 0 {
		return 0
	}
	return float64(int(v*10+0.5)) / 10
}

// peerList groups established connections by remote address and port and
// names the program of the busiest socket of each group.
func peerList(conns []conn, inbound func(int) bool) (peers []proto.Peer, in, out int, inodes map[string]int) {
	idx := map[string]int{}
	inodes = map[string]int{}
	for _, c := range conns {
		if !remoteWorthIt(c.remote) {
			continue
		}
		p := proto.Peer{IP: c.remote.String(), Port: c.rport, Out: true}
		if inbound(c.lport) {
			p.Port, p.Out = c.lport, false
			in++
		} else {
			out++
		}
		k := p.IP + "|" + strconv.Itoa(p.Port) + "|" + strconv.FormatBool(p.Out)
		i, ok := idx[k]
		if !ok {
			i = len(peers)
			idx[k] = i
			peers = append(peers, p)
			inodes[c.inode] = i
		}
		peers[i].N++
	}
	return
}

func trimPeers(peers []proto.Peer, inodes map[string]int) ([]proto.Peer, map[string]int) {
	if len(peers) <= metricsPeers {
		return peers, inodes
	}
	order := make([]int, len(peers))
	for i := range order {
		order[i] = i
	}
	// private addresses first: links between our own hosts mostly run
	// over a VPN, and a busy public service must not crowd them out
	sort.SliceStable(order, func(a, b int) bool {
		pa, pb := net.ParseIP(peers[order[a]].IP).IsPrivate(), net.ParseIP(peers[order[b]].IP).IsPrivate()
		if pa != pb {
			return pa
		}
		return peers[order[a]].N > peers[order[b]].N
	})
	keep := map[int]int{}
	out := make([]proto.Peer, 0, metricsPeers)
	for _, i := range order[:metricsPeers] {
		keep[i] = len(out)
		out = append(out, peers[i])
	}
	in := map[string]int{}
	for ino, i := range inodes {
		if j, ok := keep[i]; ok {
			in[ino] = j
		}
	}
	return out, in
}

func ifaceAddrs() map[string][]string {
	out := map[string][]string{}
	ifs, _ := net.Interfaces()
	for _, ifc := range ifs {
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.IsLoopback() || ipn.IP.IsLinkLocalUnicast() {
				continue
			}
			if len(out[ifc.Name]) < 8 {
				out[ifc.Name] = append(out[ifc.Name], ipn.IP.String())
			}
		}
	}
	return out
}

type metricsReader struct {
	at     time.Time
	cpu    cpuTicks
	net    map[string]ifaceBytes
	disk   map[string][2]uint64
	procs  map[int]procTicks
	listen map[int]time.Time
}

func newMetricsReader() *metricsReader {
	r := &metricsReader{listen: map[int]time.Time{}}
	r.at = time.Now()
	r.cpu, _ = readCPU("/proc/stat")
	r.net = readNetDev("/proc/net/dev")
	r.disk = readDiskstats("/proc/diskstats", wholeDisk)
	_, _, r.procs = topProcs(nil, 0)
	return r
}

func (r *metricsReader) sample() proto.Metrics {
	now := time.Now()
	secs := now.Sub(r.at).Seconds()
	if secs <= 0 {
		secs = 1
	}
	m := proto.Metrics{TS: now.UTC(), Cores: runtime.NumCPU(), Load: readLoad("/proc/loadavg"), Uptime: readUptime("/proc/uptime")}

	if c, ok := readCPU("/proc/stat"); ok {
		m.CPU, m.IOWait, m.Steal = cpuShares(r.cpu, c)
		r.cpu = c
	}
	mi := readMeminfo("/proc/meminfo")
	m.MemTotal = mi["MemTotal"]
	if avail := mi["MemAvailable"]; avail <= m.MemTotal {
		m.MemUsed = m.MemTotal - avail
	}
	m.MemCache = mi["Cached"] + mi["Buffers"]
	m.SwapTotal = mi["SwapTotal"]
	if mi["SwapFree"] <= m.SwapTotal {
		m.SwapUsed = m.SwapTotal - mi["SwapFree"]
	}

	nd := readNetDev("/proc/net/dev")
	addrs := ifaceAddrs()
	names := make([]string, 0, len(nd))
	for n := range nd {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		rx, tx := volumeDelta(map[string]ifaceBytes{n: r.net[n]}, map[string]ifaceBytes{n: nd[n]})
		if _, seen := r.net[n]; !seen {
			rx, tx = 0, 0
		}
		m.RX += float64(rx) / secs
		m.TX += float64(tx) / secs
		if len(m.Ifaces) < 16 {
			m.Ifaces = append(m.Ifaces, proto.IfaceRate{Name: n, RX: float64(rx) / secs, TX: float64(tx) / secs, Addrs: addrs[n]})
		}
	}
	r.net = nd

	dk := readDiskstats("/proc/diskstats", wholeDisk)
	rd, wr := diskDelta(r.disk, dk)
	m.DiskRead, m.DiskWrite = float64(rd)/secs, float64(wr)/secs
	r.disk = dk
	m.Disks, m.DiskPct = diskUsage(readMounts("/proc/self/mounts"))

	m.Top, m.Procs, r.procs = topProcs(r.procs, secs)

	conns, listening := readEstablished()
	peers, in, out, inodes := peerList(conns, servicePorts(r.listen, listening, now))
	m.ConnIn, m.ConnOut = in, out
	peers, inodes = trimPeers(peers, inodes)
	if len(inodes) > 0 {
		want := map[string]bool{}
		for ino := range inodes {
			want[ino] = true
		}
		for ino, p := range socketProcs(want) {
			peers[inodes[ino]].Process = p.comm
		}
	}
	m.Peers = peers
	r.at = now
	return m
}

func (a *Agent) runMetrics(ctx context.Context) {
	r := newMetricsReader()
	t := time.NewTicker(metricsEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m := r.sample()
			a.mu.Lock()
			a.metrics = keepMetrics(a.metrics, m)
			a.mu.Unlock()
		}
	}
}

// keepMetrics appends a sample, drops the detail of the one before (only
// the newest is shown in full) and keeps at most metricsKeep.
func keepMetrics(list []proto.Metrics, m proto.Metrics) []proto.Metrics {
	if n := len(list); n > 0 {
		list[n-1] = slimMetrics(list[n-1])
	}
	list = append(list, m)
	if over := len(list) - metricsKeep; over > 0 {
		list = append([]proto.Metrics{}, list[over:]...)
	}
	return list
}

func slimMetrics(m proto.Metrics) proto.Metrics {
	m.Disks, m.Ifaces, m.Top, m.Peers = nil, nil, nil, nil
	return m
}
