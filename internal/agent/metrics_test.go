package agent

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

func writeFixture(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCPUShares(t *testing.T) {
	a, ok := readCPU(writeFixture(t, "stat", "cpu  100 0 100 700 50 0 0 50 0 0\ncpu0 1 2 3\n"))
	if !ok || a.total != 1000 || a.idle != 700 || a.iowait != 50 || a.steal != 50 {
		t.Fatalf("readCPU = %+v %v", a, ok)
	}
	b := cpuTicks{total: 2000, idle: 1300, iowait: 150, steal: 100}
	busy, io, st := cpuShares(a, b)
	// 1000 ticks: 600 idle, 100 iowait, so 300 busy (steal is part of busy)
	if busy != 30 || io != 10 || st != 5 {
		t.Fatalf("cpuShares = %v %v %v", busy, io, st)
	}
	if busy, _, _ := cpuShares(b, a); busy != 0 {
		t.Fatalf("counter going back must give 0, got %v", busy)
	}
}

func TestMeminfoAndLoad(t *testing.T) {
	m := readMeminfo(writeFixture(t, "meminfo", "MemTotal:       8000 kB\nMemAvailable:   2000 kB\nHugePages_Total:       0\n"))
	if m["MemTotal"] != 8000<<10 || m["MemAvailable"] != 2000<<10 || m["HugePages_Total"] != 0 {
		t.Fatalf("meminfo = %v", m)
	}
	l := readLoad(writeFixture(t, "loadavg", "0.52 1.10 2.00 3/411 9999\n"))
	if l != [3]float64{0.52, 1.10, 2.00} {
		t.Fatalf("load = %v", l)
	}
	if u := readUptime(writeFixture(t, "uptime", "3600.42 100.0\n")); u != 3600 {
		t.Fatalf("uptime = %d", u)
	}
}

func TestDiskstatsWholeDisks(t *testing.T) {
	body := "   8       0 sda 10 0 2000 0 5 0 4000 0 0 0 0\n   8       1 sda1 10 0 2000 0 5 0 4000 0 0 0 0\n 253       0 dm-0 1 0 99 0 1 0 99 0 0 0 0\n"
	whole := func(n string) bool { return n == "sda" || n == "dm-0" && false }
	a := readDiskstats(writeFixture(t, "ds", body), whole)
	if len(a) != 1 || a["sda"] != [2]uint64{2000, 4000} {
		t.Fatalf("diskstats = %v", a)
	}
	r, w := diskDelta(a, map[string][2]uint64{"sda": {2010, 4020}})
	if r != 10*512 || w != 20*512 {
		t.Fatalf("delta = %d %d", r, w)
	}
}

func TestReadMounts(t *testing.T) {
	body := "/dev/sda1 / ext4 rw 0 0\nproc /proc proc rw 0 0\n/dev/sda1 /var/lib/foo ext4 rw 0 0\n/dev/loop1 /snap/core/1 squashfs ro 0 0\n/dev/sdb1 /mnt/my\\040disk xfs rw 0 0\n"
	m := readMounts(writeFixture(t, "mounts", body))
	if len(m) != 2 || m[0] != [2]string{"/", "ext4"} || m[1] != [2]string{"/mnt/my disk", "xfs"} {
		t.Fatalf("mounts = %v", m)
	}
}

func TestReadProcStat(t *testing.T) {
	comm, ticks, rss, ok := readProcStat([]byte("42 (my (odd) name) S 1 42 42 0 -1 4194560 100 0 0 0 250 50 0 0 20 0 1 0 100 1000000 300 18446744073709551615"))
	if !ok || comm != "my (odd) name" || ticks != 300 || rss != 300 {
		t.Fatalf("procstat = %q %d %d %v", comm, ticks, rss, ok)
	}
}

func TestPeerList(t *testing.T) {
	ip := func(s string) net.IP { return net.ParseIP(s) }
	conns := []conn{
		{local: ip("10.0.0.1"), remote: ip("10.0.0.2"), lport: 3306, rport: 51000, inode: "1"},
		{local: ip("10.0.0.1"), remote: ip("10.0.0.2"), lport: 3306, rport: 51001, inode: "2"},
		{local: ip("10.0.0.1"), remote: ip("10.0.0.3"), lport: 40000, rport: 8471, inode: "3"},
		{local: ip("127.0.0.1"), remote: ip("127.0.0.1"), lport: 1, rport: 2, inode: "4"},
	}
	peers, in, out, inodes := peerList(conns, func(p int) bool { return p == 3306 })
	if in != 2 || out != 1 || len(peers) != 2 {
		t.Fatalf("peers = %+v in %d out %d", peers, in, out)
	}
	if peers[0] != (proto.Peer{IP: "10.0.0.2", Port: 3306, Out: false, N: 2}) || peers[1] != (proto.Peer{IP: "10.0.0.3", Port: 8471, Out: true, N: 1}) {
		t.Fatalf("peers = %+v", peers)
	}
	if len(inodes) != 2 || inodes["1"] != 0 || inodes["3"] != 1 {
		t.Fatalf("inodes = %v", inodes)
	}
}

func TestTrimPeersKeepsPrivate(t *testing.T) {
	var peers []proto.Peer
	inodes := map[string]int{}
	for i := 0; i < metricsPeers+10; i++ {
		peers = append(peers, proto.Peer{IP: "203.0.113." + itoa(i%250), Port: 443 + i, N: 100})
		inodes[itoa(i)] = i
	}
	peers = append(peers, proto.Peer{IP: "10.90.0.3", Port: 8471, Out: true, N: 1})
	inodes["vpn"] = len(peers) - 1
	out, in := trimPeers(peers, inodes)
	if len(out) != metricsPeers || out[0].IP != "10.90.0.3" || out[in["vpn"]].IP != "10.90.0.3" {
		t.Fatalf("private peer lost: %+v", out[0])
	}
}

func TestKeepMetrics(t *testing.T) {
	var list []proto.Metrics
	for i := 0; i < metricsKeep+5; i++ {
		list = keepMetrics(list, proto.Metrics{Cores: i, Top: []proto.ProcLoad{{PID: 1}}})
	}
	if len(list) != metricsKeep || list[0].Cores != 5 || list[len(list)-1].Top == nil || list[len(list)-2].Top != nil {
		t.Fatalf("keepMetrics: %d samples, first %d", len(list), list[0].Cores)
	}
}

// The reader works on the machine running the tests.
func TestMetricsSampleLive(t *testing.T) {
	if _, err := os.Stat("/proc/stat"); err != nil {
		t.Skip("no /proc")
	}
	r := newMetricsReader()
	r.at = r.at.Add(-time.Second)
	m := r.sample()
	if m.Cores < 1 || m.MemTotal == 0 || m.Procs == 0 || m.Uptime == 0 || len(m.Top) == 0 {
		t.Fatalf("sample = %+v", m)
	}
	for _, p := range m.Top {
		if p.Comm == "" {
			t.Fatalf("process without name: %+v", p)
		}
	}
}
