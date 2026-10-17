package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestQueryLanguage(t *testing.T) {
	s := forensicServer(t)
	now := time.Now().UTC()
	appendAt(t, s, "a1", now.Add(-time.Hour), "process.exec", map[string]any{"exe": "/tmp/x/miner", "uid": 0.0, "cmdline": "miner --donate-level 1", "signals": []any{"tmp_exe", "cmd_miner"}})
	appendAt(t, s, "a1", now.Add(-50*time.Minute), "process.exec", map[string]any{"exe": "/usr/bin/curl", "uid": 1000.0, "cmdline": "curl x | sh"})
	appendAt(t, s, "a2", now.Add(-40*time.Minute), "ssh.failed", map[string]any{"ip": "198.51.100.4", "count": 40.0})
	appendAt(t, s, "a2", now.Add(-30*time.Minute), "ssh.failed", map[string]any{"ip": "198.51.100.5", "count": 3.0})
	appendAt(t, s, "a2", now.Add(-20*time.Minute), "forensics.snapshot", map[string]any{"target": map[string]any{"exe": "/usr/bin/bash"}})
	appendAt(t, s, "a1", now.AddDate(0, 0, -10), "process.exec", map[string]any{"exe": "/tmp/old", "uid": 0.0})
	run := func(q string, days int) []string {
		conds, err := parseQuery(q)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		recs, _ := s.search(conds, days, 100)
		var out []string
		for _, r := range recs {
			out = append(out, r.Event.Type+":"+str(r.Event.Data, "exe")+str(r.Event.Data, "ip"))
		}
		return out
	}
	cases := []struct {
		q    string
		want string
	}{
		{"type:process.* uid:0", "process.exec:/tmp/x/miner"},
		{"exe:/tmp/*", "process.exec:/tmp/x/miner"},
		{"type:process.exec -uid:0", "process.exec:/usr/bin/curl"},
		{"count:>10", "ssh.failed:198.51.100.4"},
		{"type:ssh.* host:game", "ssh.failed:198.51.100.5 ssh.failed:198.51.100.4"},
		{"\"| sh\"", "process.exec:/usr/bin/curl"},
		{"signals:cmd_miner", "process.exec:/tmp/x/miner"},
		{"target.exe:/usr/bin/bash", "forensics.snapshot:"},
		{"DONATE", "process.exec:/tmp/x/miner"},
	}
	for _, c := range cases {
		if got := strings.Join(run(c.q, 7), " "); got != c.want {
			t.Errorf("%q: got %q want %q", c.q, got, c.want)
		}
	}
	if got := run("exe:/tmp/*", 30); len(got) != 2 {
		t.Errorf("days: %v", got)
	}
	if _, err := parseQuery("count:>abc"); err == nil {
		t.Error("bad number accepted")
	}
	if csvSafe("=cmd|' /C calc'!A0") != "'=cmd|' /C calc'!A0" || csvSafe("ssh.login") != "ssh.login" {
		t.Error("csv formula guard")
	}
}

func TestRetroHuntAndHunt(t *testing.T) {
	s := forensicServer(t)
	s.cfg.ThreatIntel = true
	now := time.Now().UTC()
	conn := appendAt(t, s, "a1", now.AddDate(0, 0, -3), "net.connection", map[string]any{"remote_ip": "192.0.2.66", "remote_port": 443.0, "process": "kworkerd"})
	appendAt(t, s, "a1", now.AddDate(0, 0, -2), "net.connection", map[string]any{"remote_ip": "192.0.2.66", "remote_port": 443.0, "process": "kworkerd"})
	appendAt(t, s, "a2", now.AddDate(0, 0, -1), "ssh.login", map[string]any{"ip": "192.0.2.66", "user": "deploy", "sshd_pid": 10.0})
	// Not listed yet: nothing.
	s.retroHunt()
	if len(s.state.Alerts) != 0 {
		t.Fatal("alert before the address was listed")
	}
	s.intel.set("feodo", []netip.Prefix{netip.MustParsePrefix("192.0.2.66/32")}, now)
	s.retroHunt()
	if len(s.state.Alerts) != 1 {
		t.Fatalf("one alert per address and list: %+v", s.state.Alerts)
	}
	al := s.state.Alerts[0]
	if al.Rule != "net.retro_hit" || al.Agent != "a1" || al.Seqs[0] != conn.Seq || !strings.Contains(al.Title, "kworkerd talked to 192.0.2.66") {
		t.Fatalf("alert: %+v", al)
	}
	s.retroHunt()
	if len(s.state.Alerts) != 1 {
		t.Fatal("reported again")
	}

	w := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]any{"values": []string{"192.0.2.66", "deploy", "not a value!", strings.Repeat("ab", 32)}, "days": 30})
	s.handleHunt(w, httptest.NewRequest("POST", "/api/ui/hunt", bytes.NewReader(body)), &session{User: "ana"})
	var res struct {
		Results []struct {
			Value string
			Count int
			Hosts map[string]int
			Intel string
		}
		Invalid []string
	}
	json.Unmarshal(w.Body.Bytes(), &res)
	if len(res.Results) != 3 || res.Results[0].Value != "192.0.2.66" || res.Results[0].Count != 3 || res.Results[0].Intel != "feodo" ||
		res.Results[1].Value != "deploy" || res.Results[1].Count != 1 || len(res.Invalid) != 1 {
		t.Fatalf("hunt: %s", w.Body.String())
	}
}

func TestSSHSessions(t *testing.T) {
	s := forensicServer(t)
	now := time.Now().UTC()
	t0 := now.Add(-2 * time.Hour)
	appendAt(t, s, "a1", t0, "ssh.login", map[string]any{"user": "joey", "ip": "203.0.113.1", "sshd_pid": 100.0, "method": "publickey", "key_comment": "joey-laptop"})
	appendAt(t, s, "a1", t0.Add(time.Minute), "session.exec", map[string]any{"sshd_pid": 100.0, "cmdline": "vim /etc/sudoers"})
	appendAt(t, s, "a1", t0.Add(2*time.Minute), "sudo.command", map[string]any{"user": "joey", "command": "/usr/bin/systemctl restart nginx"})
	appendAt(t, s, "a1", t0.Add(3*time.Minute), "file.changed", map[string]any{"path": "/etc/sudoers"})
	appendAt(t, s, "a1", t0.Add(4*time.Minute), "session.dropped", map[string]any{"sshd_pid": 100.0, "count": 12.0})
	appendAt(t, s, "a1", t0.Add(10*time.Minute), "ssh.logout", map[string]any{"user": "joey", "sshd_pid": 100.0})
	appendAt(t, s, "a1", t0.Add(20*time.Minute), "session.exec", map[string]any{"sshd_pid": 100.0, "cmdline": "after logout"})
	appendAt(t, s, "a2", t0.Add(30*time.Minute), "ssh.login", map[string]any{"user": "root", "ip": "203.0.113.2", "sshd_pid": 200.0})
	list, events := s.sshSessions("", now.AddDate(0, 0, -1), now)
	if len(list) != 2 || list[1].User != "joey" || list[0].End != nil {
		t.Fatalf("sessions: %+v", list)
	}
	j := list[1]
	if j.Commands != 1 || j.Sudo != 1 || j.Files != 1 || j.Dropped != 12 || j.End == nil || j.Key != "joey-laptop" {
		t.Fatalf("joey: %+v", j)
	}
	if n := len(events[j.Agent+"|100|"+j.Start.Format(time.RFC3339Nano)]); n != 3 {
		t.Fatalf("events: %d", n)
	}
	var out map[string]any
	w := httptest.NewRecorder()
	s.handleSession(w, httptest.NewRequest("GET", "/api/ui/session?agent=a1&pid=100&start="+j.Start.Format(time.RFC3339Nano), nil), &session{User: "x"})
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &out) != nil || len(out["events"].([]any)) != 3 {
		t.Fatalf("session detail: %d %s", w.Code, w.Body.String())
	}
}

func TestLoginHoursAndVolume(t *testing.T) {
	s := forensicServer(t)
	day := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	for i := 0; i < 25; i++ {
		if _, _, rare := s.loginHour("joey", day.AddDate(0, 0, i).Add(time.Duration(i%2)*time.Hour)); rare {
			t.Fatal("usual hours")
		}
	}
	if h, n, rare := s.loginHour("joey", day.Add(18*time.Hour)); !rare || h != 3 || n != 25 {
		t.Fatalf("3 am: %d %d %v", h, n, rare)
	}
	if _, _, rare := s.loginHour("joey", day.Add(17*time.Hour+30*time.Minute)); rare {
		t.Fatal("an hour next to a known one is usual")
	}

	a := &AgentRec{ID: "v"}
	start := time.Now().Add(-100 * time.Hour)
	for i := 0; i < 80; i++ {
		if f := volumeFinding(a, map[string]any{"tx_bytes": float64(200 << 20)}, start.Add(time.Duration(i)*time.Hour)); f != nil {
			t.Fatal("steady traffic")
		}
	}
	if f := volumeFinding(a, map[string]any{"tx_bytes": float64(500 << 20)}, time.Now()); f != nil {
		t.Fatal("below 1 GB")
	}
	f := volumeFinding(a, map[string]any{"tx_bytes": float64(5 << 30)}, time.Now())
	if f == nil || f["sent"] != "5.0 GB" || f["usual"] != "200 MB" {
		t.Fatalf("spike: %v", f)
	}
}
