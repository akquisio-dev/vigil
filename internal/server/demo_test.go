package server

import (
	"fmt"
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
	hosts[2].Silent, hosts[2].LastSeen = true, now.Add(-47*time.Minute)
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
				add(at.Add(time.Duration(rng.Intn(3600))*time.Second), h, "ssh.failed", map[string]any{"ip": ip, "count": float64(2 + rng.Intn(18)), "users": us})
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
