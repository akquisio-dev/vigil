package server

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

func TestChainDetectsTampering(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenStore(dir, 100)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		st.Append(&Record{Source: "agent", Event: proto.NewEvent("test.event", map[string]any{"i": i})})
	}
	if ok, msg := st.Verify(); !ok {
		t.Fatalf("fresh chain broken: %s", msg)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	raw, _ := os.ReadFile(files[0])
	os.WriteFile(files[0], []byte(strings.Replace(string(raw), `"i":2`, `"i":7`, 1)), 0o600)
	if ok, _ := st.Verify(); ok {
		t.Fatal("edited record not detected")
	}

	os.WriteFile(files[0], raw, 0o600)
	lines := strings.SplitAfter(string(raw), "\n")
	os.WriteFile(files[0], []byte(strings.Join(append(lines[:1], lines[2:]...), "")), 0o600)
	if ok, _ := (&Store{dir: dir, max: 10}).verifyFresh(); ok {
		t.Fatal("deleted record not detected")
	}
}

func (s *Store) verifyFresh() (bool, string) {
	s.verifyAndLoad()
	return s.ChainOK, s.ChainError
}

func TestPasswordAndTOTP(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !checkPassword(h, "correct horse battery") || checkPassword(h, "wrong") {
		t.Fatal("password check")
	}
	u := &User{TOTPSecret: NewTOTPSecret()}
	now := time.Now()
	secret := decodeSecret(t, u.TOTPSecret)
	code := totpAt(secret, now.Unix()/30)
	if !checkTOTP(u, code, now) {
		t.Fatal("valid code refused")
	}
	if checkTOTP(u, code, now) {
		t.Fatal("code accepted twice")
	}
	if checkTOTP(u, totpAt(secret, now.Unix()/30+5), now) {
		t.Fatal("code from the future accepted")
	}
}

func TestRenderTitle(t *testing.T) {
	got := renderTitle("file.cron", map[string]string{"path": "/etc/cron.d/x", "change": "added"}, "de")
	if got != "/etc/cron.d/x: neu angelegt" {
		t.Fatalf("got %q", got)
	}
	got = renderTitle("port.public", map[string]string{"proto": "tcp", "port": "80", "addr": "0.0.0.0"}, "en")
	if got != "New port tcp/80 on 0.0.0.0" {
		t.Fatalf("got %q", got)
	}
}

func TestRulesHaveBothLanguages(t *testing.T) {
	for id, r := range rules {
		if r.En == "" || r.De == "" || severityRank[r.Severity] == 0 && r.Severity != "info" {
			t.Errorf("rule %s incomplete", id)
		}
	}
}

func decodeSecret(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base32NoPad.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAgentStringsCannotInjectHeaders(t *testing.T) {
	s := &Server{state: &State{Agents: map[string]*AgentRec{}, Canaries: map[string]*CanaryRec{}, KnownLogins: map[string]time.Time{}}}
	a := &AgentRec{ID: "a1", Name: "host"}
	rec := &Record{Event: proto.Event{Type: "canary.opened", TS: time.Now(), Data: map[string]any{
		"path": "/root/x", "exe": "/tmp/evil\r\nBcc: victim@example.com", "uid": "0", "pid": float64(1),
	}}}
	alerts := s.raise(s.evaluate(a, rec), a.ID, 1)
	if len(alerts) != 1 {
		t.Fatalf("want 1 alert, got %d", len(alerts))
	}
	title := renderTitle(alerts[0].Rule, decodeParams(alerts[0].Detail), "en")
	if strings.ContainsAny(title, "\r\n") || strings.ContainsAny(alerts[0].Title, "\r\n") {
		t.Fatalf("control characters survived: %q", title)
	}
	if !strings.Contains(title, "/tmp/evilBcc: victim@example.com") {
		t.Fatalf("unexpected title %q", title)
	}
}

func TestRestartAlwaysAlerts(t *testing.T) {
	s := &Server{state: &State{Agents: map[string]*AgentRec{}, Canaries: map[string]*CanaryRec{}, KnownLogins: map[string]time.Time{}}}
	a := &AgentRec{ID: "a1", Name: "host"}
	start := func() []finding {
		return s.evaluate(a, &Record{Event: proto.Event{Type: "agent.started", TS: time.Now()}})
	}
	if f := start(); len(f) != 0 {
		t.Fatal("first start after enrollment must not alert")
	}
	stop := s.evaluate(a, &Record{Event: proto.Event{Type: "agent.stopping", TS: time.Now()}})
	if len(stop) != 1 || rules[stop[0].Rule].Severity != "high" {
		t.Fatalf("stop must raise a high alert: %+v", stop)
	}
	a.prevSeen = time.Now().Add(-3 * time.Minute)
	f := start()
	if len(f) != 1 || f[0].Rule != "agent.restarted" || !strings.HasPrefix(f[0].Params["gap"], "3m") {
		t.Fatalf("restart must alert with the gap: %+v", f)
	}
	a.MaintenanceUntil = time.Now().Add(time.Hour)
	if f := start(); len(f) != 0 {
		t.Fatal("maintenance set from the dashboard suppresses agent alerts")
	}
}

func TestEveryRuleIsDocumented(t *testing.T) {
	for id := range rules {
		d, ok := ruleDocs[id]
		if !ok || d.Trigger == "" || d.FalsePositives == "" || d.Response == "" {
			t.Errorf("rule %s has no complete entry in ruleDocs", id)
		}
	}
	for id := range ruleDocs {
		if _, ok := rules[id]; !ok {
			t.Errorf("ruleDocs has %s, which is not a rule", id)
		}
	}
}

func TestDashboardAggregates(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	acked := now.Add(-time.Hour)
	s := &Server{state: &State{Agents: map[string]*AgentRec{"a1": {ID: "a1", Name: "web"}}}}
	s.state.Alerts = []*Alert{
		{Rule: "ssh.key_added", Severity: "high", Technique: "T1098.004", Created: now.Add(-90 * time.Minute), Acked: &acked},
		{Rule: "ssh.key_added", Severity: "high", Technique: "T1098.004", Created: now.Add(-24 * time.Hour)},
		{Rule: "ssh.bruteforce", Severity: "medium", Technique: "T1110", Created: now.Add(-8 * 24 * time.Hour)},
	}
	ev := func(ago time.Duration, typ string, d map[string]any) Record {
		return Record{Time: now.Add(-ago), Agent: "a1", Source: "agent", Event: proto.Event{Type: typ, TS: now.Add(-ago), Data: d}}
	}
	d := s.dashboard(now, []Record{
		ev(time.Hour, "ssh.failed", map[string]any{"ip": "203.0.113.9", "count": float64(40), "users": []any{"root", "admin"}}),
		ev(2*time.Hour, "ssh.failed", map[string]any{"ip": "203.0.113.9", "count": float64(10), "users": []any{"root"}}),
		ev(3*time.Hour, "ssh.failed", map[string]any{"ip": "198.51.100.7", "count": float64(5)}),
		ev(30*time.Hour, "ssh.failed", map[string]any{"ip": "192.0.2.1", "count": float64(99)}),
		ev(time.Minute, "ssh.login", map[string]any{"user": "root", "ip": "192.0.2.50", "method": "publickey", "key_comment": "joey-pc"}),
	})
	if d["ssh_failed_24h"] != 55 || d["ssh_failed_ips"] != 2 {
		t.Fatalf("failed logins: %v from %v addresses", d["ssh_failed_24h"], d["ssh_failed_ips"])
	}
	top := d["top_attackers"].([]countItem)
	if top[0].Key != "203.0.113.9" || top[0].Count != 50 || top[0].Extra != "SSH: admin, root" {
		t.Fatalf("top attacker: %+v", top[0])
	}
	perDay := d["alerts_per_day"].([]map[string]int)
	if perDay[6]["high"] != 1 || perDay[5]["high"] != 1 {
		t.Fatalf("alerts per day: %v", perDay)
	}
	var persistence int
	for _, it := range d["tactics"].([]countItem) {
		if it.Key == "persistence" {
			persistence = it.Count
		}
	}
	if persistence != 2 {
		t.Fatalf("persistence: %d, old alerts must not count", persistence)
	}
	if d["mtta_seconds"] != 1800 {
		t.Fatalf("mtta: %v", d["mtta_seconds"])
	}
	logins := d["logins"].([]loginView)
	if len(logins) != 1 || logins[0].Host != "web" || logins[0].Key != "joey-pc" {
		t.Fatalf("logins: %+v", logins)
	}
}

func TestTacticsCoverEveryTechnique(t *testing.T) {
	known := map[string]bool{}
	for _, tc := range TacticOrder {
		known[tc] = true
	}
	for id, r := range rules {
		if r.Technique == "" {
			continue
		}
		if !known[tactics[r.Technique]] {
			t.Errorf("rule %s: technique %s has no tactic", id, r.Technique)
		}
	}
}

func TestSuppressions(t *testing.T) {
	s := &Server{state: &State{Agents: map[string]*AgentRec{"a1": {ID: "a1"}, "a2": {ID: "a2"}}, Canaries: map[string]*CanaryRec{}, KnownLogins: map[string]time.Time{}}}
	cron := func(path string) []finding {
		return []finding{{Rule: "file.cron", Key: "file.cron|a1|" + path, Params: map[string]string{"path": path, "change": "changed"}}}
	}
	if _, err := s.newSuppression("u", "canary.opened", "", "noise", nil, 0); err == nil {
		t.Fatal("a critical canary rule must not be suppressible")
	}
	for _, r := range []string{"agent.restarted", "agent.forged", "chain.broken", "log.spoofed", "user.root", "nope"} {
		if Suppressible(r) {
			t.Errorf("%s must not be suppressible", r)
		}
	}
	if _, err := s.newSuppression("u", "file.cron", "", " ", nil, 0); err == nil {
		t.Fatal("a reason is required")
	}
	sp, err := s.newSuppression("u", "file.cron", "a1", "nightly backup job", map[string]string{"path": "/etc/cron.d/backup"}, 400)
	if err != nil {
		t.Fatal(err)
	}
	if d := sp.Expires.Sub(sp.Created); d != suppressMaxDays*24*time.Hour {
		t.Fatalf("expiry not capped: %v", d)
	}
	s.state.Suppressions = []*Suppression{sp}
	if got := s.raise(cron("/etc/cron.d/backup"), "a1", 1); len(got) != 0 || sp.Hits != 1 {
		t.Fatalf("matching finding raised %d alerts, hits %d", len(got), sp.Hits)
	}
	if got := s.raise(cron("/etc/cron.d/other"), "a1", 2); len(got) != 1 {
		t.Fatal("other path must still alert")
	}
	if got := s.raise(cron("/etc/cron.d/backup"), "a2", 3); len(got) != 1 {
		t.Fatal("other host must still alert")
	}
	sp.Expires = time.Now().Add(-time.Minute)
	s.state.Alerts = nil
	if got := s.raise(cron("/etc/cron.d/backup"), "a1", 4); len(got) != 1 {
		t.Fatal("expired suppression must not match")
	}
}

func TestIncidentGrouping(t *testing.T) {
	s := &Server{state: &State{Agents: map[string]*AgentRec{"a1": {ID: "a1"}, "a2": {ID: "a2"}}, Canaries: map[string]*CanaryRec{}, KnownLogins: map[string]time.Time{}}}
	t0 := time.Date(2026, 10, 12, 2, 0, 0, 0, time.UTC)
	n := 0
	alert := func(agent, rule, sev string, at time.Duration) *Alert {
		n++
		al := &Alert{ID: fmt.Sprint("al", n), Agent: agent, Rule: rule, Severity: sev, Created: t0.Add(at), Status: "open"}
		s.state.Alerts = append(s.state.Alerts, al)
		s.correlate([]*Alert{al})
		return al
	}
	login := alert("a1", "ssh.new_source", "medium", 0)
	if login.Incident != "" {
		t.Fatal("a medium alert alone must not open an incident")
	}
	pw := alert("a1", "ssh.password_login", "high", time.Minute)
	unit := alert("a1", "file.systemd", "medium", 4*time.Minute)
	canary := alert("a1", "canary.opened", "critical", 6*time.Minute)
	other := alert("a2", "file.cron", "high", 5*time.Minute)
	later := alert("a1", "file.cron", "high", 5*time.Hour)
	restart := alert("a2", "agent.restarted", "high", 9*time.Hour)

	inc := s.incident(pw.Incident)
	if inc == nil || login.Incident != inc.ID || unit.Incident != inc.ID || canary.Incident != inc.ID {
		t.Fatalf("intrusion not grouped: login=%q pw=%q unit=%q canary=%q", login.Incident, pw.Incident, unit.Incident, canary.Incident)
	}
	if inc.Severity != "critical" || len(inc.Alerts) != 4 || inc.Start != pw.ID {
		t.Fatalf("incident: %+v", inc)
	}
	if other.Incident == inc.ID || other.Incident == "" {
		t.Fatal("another host gets its own incident")
	}
	if later.Incident == inc.ID || later.Incident == "" {
		t.Fatal("an alert hours later opens a new incident")
	}
	if restart.Incident != "" {
		t.Fatal("agent alerts never open an incident")
	}
	inc.Status = "closed"
	if again := alert("a1", "file.sudo", "high", 7*time.Minute); again.Incident == inc.ID {
		t.Fatal("closed incidents take no new alerts")
	}
}

func TestCustomRules(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	example, _ := os.ReadFile("../../deploy/examples/rules/examples.json")
	write("a-examples.json", string(example))
	write("b-broken.json", `{"id": "custom.x", "severity": "high"`)
	write("c-builtin.json", `{"id": "ssh.bruteforce", "severity": "info", "title": {"en": "x"}, "event": "ssh.failed"}`)
	write("d-regex.json", `{"id": "custom.bad", "severity": "low", "title": {"en": "x"}, "event": "ssh.failed", "where": [{"field": "ip", "op": "regex", "value": "("}]}`)
	n, errs := LoadCustomRules(dir)
	defer LoadCustomRules("")
	if n != 3 || len(errs) != 3 {
		t.Fatalf("loaded %d, errors %v", n, errs)
	}
	if d, _ := lookupRule("ssh.bruteforce"); d != rules["ssh.bruteforce"] {
		t.Fatal("a custom file must not replace a built-in rule")
	}
	s := &Server{state: &State{Agents: map[string]*AgentRec{}, Canaries: map[string]*CanaryRec{}, KnownLogins: map[string]time.Time{}}}
	a := &AgentRec{ID: "a1", Name: "web"}
	ev := func(typ string, d map[string]any, at time.Duration) *Record {
		ts := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC).Add(at)
		return &Record{Agent: "a1", Source: "agent", Event: proto.Event{Type: typ, TS: ts, Data: d}}
	}
	f := s.evaluateCustom(a, ev("sudo.command", map[string]any{"user": "alice", "command": "/bin/bash"}, 0))
	if len(f) != 1 || f[0].Rule != "custom.sudo_shell" {
		t.Fatalf("sudo shell: %+v", f)
	}
	if got := renderTitle(f[0].Rule, f[0].Params, "de"); got != "alice hat mit sudo eine Root-Shell gestartet: /bin/bash" {
		t.Fatalf("title: %q", got)
	}
	if f := s.evaluateCustom(a, ev("sudo.command", map[string]any{"user": "alice", "command": "/usr/bin/systemctl restart nginx"}, 0)); len(f) != 0 {
		t.Fatal("a normal sudo command must not match")
	}
	if f := s.evaluateCustom(a, ev("port.opened", map[string]any{"port": float64(2375), "addr": "0.0.0.0"}, 0)); len(f) != 1 {
		t.Fatal("docker api port")
	}
	var fired []finding
	for i := 0; i < 6; i++ {
		fired = append(fired, s.evaluateCustom(a, ev("ssh.failed", map[string]any{"ip": "203.0.113.9", "users": []any{"oracle", "root"}}, time.Duration(i)*5*time.Minute))...)
		s.evaluateCustom(a, ev("ssh.failed", map[string]any{"ip": "198.51.100.1", "users": []any{"root"}}, time.Duration(i)*20*time.Minute))
	}
	if len(fired) != 1 || fired[0].Params["count"] != "5" || fired[0].Params["ip"] != "203.0.113.9" {
		t.Fatalf("threshold: %+v", fired)
	}
	if !Suppressible("custom.sudo_shell") {
		t.Fatal("non-critical custom rules can be suppressed")
	}
}

func TestIntelAndNetRules(t *testing.T) {
	s := &Server{state: &State{Agents: map[string]*AgentRec{}, Canaries: map[string]*CanaryRec{}, KnownLogins: map[string]time.Time{}}}
	set := &s.intel
	set.set("feodo", parseIPLines([]byte("# comment\n203.0.113.9\n")), time.Now())
	set.set("spamhaus-drop", parseSpamhausJSON([]byte(`{"cidr":"198.51.100.0/24","sblid":"SBL1"}`+"\n"+`{"type":"metadata"}`)), time.Now())
	set.set("tor-exit", parseIPLines([]byte("192.0.2.5\n")), time.Now())
	for ip, want := range map[string]string{"203.0.113.9": "feodo", "198.51.100.77": "spamhaus-drop", "192.0.2.5": "tor-exit", "192.0.2.6": "", "::ffff:203.0.113.9": "feodo"} {
		if got, _ := set.lookup(ip); got != want {
			t.Errorf("%s: got %q want %q", ip, got, want)
		}
	}
	a := &AgentRec{ID: "a1", Name: "web"}
	rulesFor := func(d map[string]any) []string {
		var out []string
		for _, f := range s.evaluate(a, &Record{Event: proto.Event{Type: "net.connection", TS: time.Now(), Data: d}}) {
			out = append(out, f.Rule)
		}
		return out
	}
	if r := rulesFor(map[string]any{"remote_ip": "203.0.113.9", "remote_port": float64(443), "process": "kworker"}); len(r) != 1 || r[0] != "net.c2" {
		t.Fatalf("c2: %v", r)
	}
	if r := rulesFor(map[string]any{"remote_ip": "8.8.8.8", "remote_port": float64(6379), "process": "redis-server"}); len(r) != 1 || r[0] != "net.service_outbound" {
		t.Fatalf("redis outbound: %v", r)
	}
	if r := rulesFor(map[string]any{"remote_ip": "10.90.0.1", "remote_port": float64(5432), "process": "postgres"}); len(r) != 0 {
		t.Fatalf("private replication must not alert: %v", r)
	}
	if r := rulesFor(map[string]any{"remote_ip": "8.8.4.4", "remote_port": float64(3333), "process": "x"}); len(r) != 1 || r[0] != "net.miner_pool" {
		t.Fatalf("miner port: %v", r)
	}
}
