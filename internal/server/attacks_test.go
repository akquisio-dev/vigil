package server

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func waitAttacks(t *testing.T, s *Server) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		s.attacks.mu.Lock()
		ready := s.attacks.ready
		s.attacks.mu.Unlock()
		if ready {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("attack rollup not ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func anyList(xs ...string) []any {
	out := make([]any, len(xs))
	for i, x := range xs {
		out[i] = x
	}
	return out
}

func TestAttackStats(t *testing.T) {
	s := forensicServer(t)
	s.cfg.Brand = &BrandConfig{Name: "Zypo Cloud"}
	now := time.Now().UTC()
	fail := func(at time.Time, ip string, n int, users []string, existing ...string) {
		d := map[string]any{"ip": ip, "count": float64(n), "users": anyList(users...)}
		if len(existing) > 0 {
			d["existing_users"] = anyList(existing...)
		}
		appendAt(t, s, "a2", at, "ssh.failed", d)
	}
	// Before the start: rebuilt from the log.
	for i := 0; i < 5; i++ {
		fail(now.Add(-2*time.Hour), fmt.Sprintf("198.51.100.%d", 10+i), 4, []string{"oracle", "hadoop", "spark", "zookeeper"})
	}
	for d := 1; d <= 3; d++ {
		fail(now.AddDate(0, 0, -d), "203.0.113.80", 10, []string{"root"}, "root")
	}
	fail(now.Add(-time.Hour), "203.0.113.50", 2, []string{"root"}, "root")
	s.startAttacks()
	waitAttacks(t, s)

	// After the start: followed through the store hook.
	fail(now.Add(-30*time.Minute), "203.0.113.60", 3, []string{"jsmith2"}, "jsmith2")
	fail(now.Add(-30*time.Minute), "203.0.113.61", 2, []string{"zypo"})
	fail(now.Add(-20*time.Minute), "203.0.113.70", 5, []string{"root"}, "root")
	fail(now.Add(-25*time.Minute), "203.0.113.70", 1, []string{"admin"})
	login := appendAt(t, s, "a2", now.Add(-10*time.Minute), "ssh.login", map[string]any{"ip": "203.0.113.70", "user": "root", "method": "publickey"})
	// A teammate whose client offered the wrong key first: failed as root, then in as root.
	fail(now.Add(-9*time.Minute), "192.0.2.9", 4, []string{"root"}, "root")
	team := appendAt(t, s, "a2", now.Add(-8*time.Minute), "ssh.login", map[string]any{"ip": "192.0.2.9", "user": "root", "method": "publickey"})
	appendAt(t, s, "a1", now.Add(-5*time.Minute), "web.activity", map[string]any{"ip": "203.0.113.90", "requests": 50.0, "probes": 8.0,
		"exploits_ok": 1.0, "exploit_kinds": anyList("lfi"), "samples": anyList("GET /.env?x=1", "GET /[Login](https://evil.example)"), "user_agent": "zgrab"})
	// An admin's ordinary login is no attack.
	appendAt(t, s, "a1", now.Add(-5*time.Minute), "ssh.login", map[string]any{"ip": "192.0.2.5", "user": "joey", "method": "publickey"})

	v := s.attackStats(7)
	if v.Totals.IPs != 11 || v.Totals.SSH != 5*4+30+2+3+2+5+1 || v.Totals.Web != 50 {
		t.Fatalf("totals %+v", v.Totals)
	}
	if txt := s.summaryText(time.Now()); !strings.Contains(txt, "Attacks since yesterday 00:00 UTC: ") || !strings.Contains(txt, " web probes; ") || !strings.Contains(txt, "Most addresses from: ") {
		t.Errorf("summary without attackers:\n%s", txt)
	}
	class := map[string]string{}
	reasons := map[string]string{}
	for _, a := range v.Addresses {
		class[a.IP] = a.Class
		reasons[a.IP] = strings.Join(a.Reasons, ",")
	}
	want := map[string]string{"203.0.113.70": "success", "203.0.113.90": "success", "203.0.113.60": "targeted", "203.0.113.61": "targeted",
		"203.0.113.80": "persistent", "203.0.113.50": "noise", "198.51.100.10": "noise"}
	for ip, c := range want {
		if class[ip] != c {
			t.Errorf("%s: class %s (%s), want %s", ip, class[ip], reasons[ip], c)
		}
	}
	if !strings.Contains(reasons["198.51.100.12"], "campaign") || !strings.Contains(reasons["203.0.113.50"], "wordlist") {
		t.Errorf("reasons: %v", reasons)
	}
	if len(v.Campaigns) != 1 || v.Campaigns[0].Size != 5 || v.Campaigns[0].Kind != "ssh" || len(v.Campaigns[0].Signature) != 4 {
		t.Fatalf("campaigns %+v", v.Campaigns)
	}
	if v.Users[0].IPs != 5 || v.Users[4].User != "root" || !v.Users[4].Existing {
		t.Errorf("users %+v", v.Users)
	}
	if len(v.Paths) != 2 || v.Paths[0].Key != "/.env" {
		t.Errorf("paths %+v", v.Paths)
	}

	// Logging in after failing raises ssh.attacker_login.
	fs := s.evaluate(s.state.Agents["a2"], login)
	found := false
	for _, f := range fs {
		found = found || f.Rule == "ssh.attacker_login" && f.Params["failed"] == "6"
	}
	if !found {
		t.Errorf("no ssh.attacker_login: %+v", fs)
	}
	for _, f := range s.evaluate(s.state.Agents["a2"], team) {
		if f.Rule == "ssh.attacker_login" {
			t.Error("a client offering the wrong key first flagged")
		}
	}
	if _, listed := v.all["192.0.2.9"]; listed {
		t.Error("the team's address listed as an attacker")
	}
	admin := &Record{Agent: "a1", Event: login.Event}
	admin.Event.Data = map[string]any{"ip": "192.0.2.5", "user": "joey", "method": "publickey"}
	for _, f := range s.evaluate(s.state.Agents["a1"], admin) {
		if f.Rule == "ssh.attacker_login" {
			t.Error("ordinary login flagged")
		}
	}

	// Past days are written once and loaded instead of rebuilt.
	s.attacks.persist()
	files, _ := filepath.Glob(filepath.Join(s.cfg.DataDir, "attacks", "*.json"))
	if len(files) != 3 {
		t.Fatalf("day files %v", files)
	}
	s2 := &Server{cfg: s.cfg, store: s.store, state: s.state}
	s2.startAttacks()
	waitAttacks(t, s2)
	v2 := s2.attackStats(7)
	if v2.Totals != v.Totals {
		t.Fatalf("after reload %+v, before %+v", v2.Totals, v.Totals)
	}
	if v1 := s2.attackStats(1); v1.Totals.IPs < 6 || v1.Totals.IPs >= v.Totals.IPs {
		t.Errorf("one day: %+v", v1.Totals)
	}

	// The report names what needs attention, in both languages.
	md := s.attackMarkdown(v, "de", "ana")
	for _, want := range []string{"# Angriffsbericht", "`203.0.113.70`", "nach Fehlversuchen angemeldet", "| `oracle` | 5 |", "## Kampagnen"} {
		if !strings.Contains(md, want) {
			t.Errorf("report lacks %q", want)
		}
	}
	page := mdPage("x", s.attackMarkdown(v, "en", "<b>"), "")
	if strings.Contains(page, "<b>") || strings.Contains(page, "<a") || !strings.Contains(page, "<h2>Needs attention</h2>") {
		t.Error("report page not escaped or incomplete")
	}
	if strings.Contains(md+page, "—") || strings.Contains(md+page, " – ") {
		t.Error("dash in the report")
	}
	os.RemoveAll(filepath.Join(s.cfg.DataDir, "attacks"))
}

func TestCampaignsNeedSharedLists(t *testing.T) {
	var list []*addrView
	merged := map[string]*atkIP{}
	for i := 0; i < 50; i++ {
		ip := fmt.Sprintf("192.0.2.%d", i)
		// everyone tries root and admin, plus names of their own
		users := []string{"root", "admin", fmt.Sprintf("u%d", i), fmt.Sprintf("v%d", i)}
		merged[ip] = &atkIP{SSH: 1, Users: users}
		list = append(list, &addrView{IP: ip, SSH: 1})
	}
	if c := findCampaigns(list, merged); len(c) != 0 {
		t.Fatalf("common names alone made campaigns: %+v", c)
	}
}

// The statistics hold addresses and user names; they follow retention_days.
func TestAttackStatsRetention(t *testing.T) {
	s := forensicServer(t)
	s.cfg.RetentionDays = 2
	now := time.Now().UTC()
	for d := 0; d <= 5; d++ {
		appendAt(t, s, "a2", now.AddDate(0, 0, -d), "ssh.failed", map[string]any{"ip": fmt.Sprintf("198.51.100.%d", d+1), "count": 1.0, "users": anyList("root")})
	}
	os.MkdirAll(filepath.Join(s.cfg.DataDir, "attacks"), 0o700)
	old := filepath.Join(s.cfg.DataDir, "attacks", now.AddDate(0, 0, -5).Format("2006-01-02")+".json")
	os.WriteFile(old, []byte(`{"day":"x"}`), 0o600)
	s.startAttacks()
	waitAttacks(t, s)
	if v := s.attackStats(30); v.Totals.IPs != 3 {
		t.Fatalf("addresses beyond retention: %+v", v.Totals)
	}
	s.attacks.persist()
	if _, err := os.Stat(old); err == nil {
		t.Error("old day file kept")
	}
}

func TestAttackUserStats(t *testing.T) {
	s := forensicServer(t)
	now := time.Now().UTC()
	fail := func(at time.Time, ip string, n int, users []string, counts map[string]any, existing ...string) {
		d := map[string]any{"ip": ip, "count": float64(n), "users": anyList(users...)}
		if counts != nil {
			d["user_counts"] = counts
		}
		if len(existing) > 0 {
			d["existing_users"] = anyList(existing...)
		}
		appendAt(t, s, "a2", at, "ssh.failed", d)
	}
	// an agent before v0.26.0: 5 attempts shared out over 3 users
	fail(now.Add(-2*time.Hour), "198.51.100.1", 5, []string{"admin", "oracle", "root"}, nil, "root")
	// a current agent counts per user
	fail(now.Add(-time.Hour), "198.51.100.2", 7, []string{"root", "ubuntu"}, map[string]any{"root": float64(6), "ubuntu": float64(1)}, "root")
	fail(now.AddDate(0, 0, -1), "198.51.100.2", 4, []string{"root"}, map[string]any{"root": float64(4)}, "root")
	s.startAttacks()
	waitAttacks(t, s)
	v := s.attackStats(7)
	if !v.Estimated {
		t.Error("shared-out counts must be marked as estimated")
	}
	got := map[string]userStat{}
	for _, u := range v.UserStats {
		got[u.User] = u
	}
	if got["admin"].Attempts != 2 || got["oracle"].Attempts != 2 || got["root"].Attempts != 1+6+4 || got["ubuntu"].Attempts != 1 {
		t.Fatalf("attempts per user: %+v", got)
	}
	if r := got["root"]; len(r.Days) != 7 || r.Days[6] != 7 || r.Days[5] != 4 || r.IPs != 2 || !r.Existing {
		t.Fatalf("root: %+v", r)
	}
	hours := 0
	for _, n := range got["root"].Hours {
		hours += n
	}
	if hours != 11 {
		t.Fatalf("root hours sum %d", hours)
	}
	if v.UserStats[0].User != "root" {
		t.Fatalf("ranking: %v", v.UserStats[0].User)
	}
	if len(v.Matrix.Users) != 4 || v.Matrix.Users[0] != "root" || len(v.Matrix.Countries) != 1 || v.Matrix.Cells[0][0] != 11 {
		t.Fatalf("matrix: %+v", v.Matrix)
	}
	flows := 0
	for _, f := range v.Flows {
		flows += f.Count
		if f.User == "root" && !f.Existing || f.User == "admin" && f.Existing {
			t.Fatalf("flow account: %+v", f)
		}
	}
	if flows != 5+7+4 {
		t.Fatalf("flows sum %d", flows)
	}

	// A day saved before per-user counts is rebuilt from the log ...
	s.attacks.persist()
	yday := now.AddDate(0, 0, -1).Format("2006-01-02")
	path := filepath.Join(s.cfg.DataDir, "attacks", yday+".json")
	old := `{"day":"` + yday + `","ips":{"198.51.100.2":{"s":4,"u":["root"],"f":"` + now.AddDate(0, 0, -1).Format(time.RFC3339) + `","t":"` + now.AddDate(0, 0, -1).Format(time.RFC3339) + `"}},"hours":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}`
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	s2 := &Server{cfg: s.cfg, store: s.store, state: s.state}
	s2.startAttacks()
	waitAttacks(t, s2)
	if d := s2.attacks.days[yday]; d == nil || d.UH["root"] == nil || d.UH["root"][now.AddDate(0, 0, -1).Hour()] != 4 {
		t.Fatalf("old day not rebuilt: %+v", d)
	}

	// ... but kept as it is when the log no longer covers it.
	gone := now.AddDate(0, 0, -5)
	gday := gone.Format("2006-01-02")
	old = `{"day":"` + gday + `","ips":{"203.0.113.9":{"s":9,"u":["pi"],"f":"` + gone.Format(time.RFC3339) + `","t":"` + gone.Format(time.RFC3339) + `"}},"hours":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}`
	os.WriteFile(filepath.Join(s.cfg.DataDir, "attacks", gday+".json"), []byte(old), 0o600)
	s3 := &Server{cfg: s.cfg, store: s.store, state: s.state}
	s3.startAttacks()
	waitAttacks(t, s3)
	if d := s3.attacks.days[gday]; d == nil || d.IPs["203.0.113.9"] == nil || d.IPs["203.0.113.9"].SSH != 9 {
		t.Fatalf("old day lost: %+v", d)
	}
}

func TestAttacksLive(t *testing.T) {
	s := forensicServer(t)
	s.cfg.MapHome = &[2]float64{49.0, 8.4}
	now := time.Now().UTC()
	s.startAttacks()
	waitAttacks(t, s)
	var first struct {
		Cursor  uint64       `json:"cursor"`
		Attacks []liveAttack `json:"attacks"`
		Home    *[2]float64  `json:"home"`
	}
	getJSON(t, func(w http.ResponseWriter, r *http.Request) { s.handleAttacksLive(w, r, &session{User: "u"}) }, "/api/ui/attacks/live", nil, &first)
	if len(first.Attacks) != 0 || first.Home == nil || first.Home[0] != 49.0 {
		t.Fatalf("first call: %+v", first)
	}
	appendAt(t, s, "a2", now, "ssh.failed", map[string]any{"ip": "198.51.100.7", "count": float64(3), "users": anyList("root")})
	appendAt(t, s, "a2", now, "ssh.failed", map[string]any{"ip": "10.90.0.1", "count": float64(1), "users": anyList("root")})
	appendAt(t, s, "a1", now, "web.activity", map[string]any{"ip": "198.51.100.8", "requests": float64(9), "probes": float64(0)})
	appendAt(t, s, "a1", now, "web.activity", map[string]any{"ip": "198.51.100.9", "requests": float64(9), "probes": float64(4)})
	appendAt(t, s, "a1", now, "ssh.login", map[string]any{"ip": "198.51.100.10", "user": "root"})
	var next struct {
		Cursor  uint64       `json:"cursor"`
		Attacks []liveAttack `json:"attacks"`
	}
	getJSON(t, func(w http.ResponseWriter, r *http.Request) { s.handleAttacksLive(w, r, &session{User: "u"}) }, fmt.Sprintf("/api/ui/attacks/live?after=%d", first.Cursor), nil, &next)
	if len(next.Attacks) != 2 || next.Attacks[0].IP != "198.51.100.7" || next.Attacks[0].Kind != "ssh" || next.Attacks[0].Host != "game" ||
		next.Attacks[1].IP != "198.51.100.9" || next.Attacks[1].Kind != "web" || next.Cursor <= first.Cursor {
		t.Fatalf("live: %+v", next)
	}
}
