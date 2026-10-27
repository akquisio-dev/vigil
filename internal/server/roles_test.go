package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Moritz: viewer for the network, admin of his group. Every route tied to
// a host must follow the host's group; everything network wide must not.
func TestGroupRoles(t *testing.T) {
	dir := t.TempDir()
	s, err := New(&Config{DataDir: dir, SessionHours: 1})
	if err != nil {
		t.Fatal(err)
	}
	moritz, _, _ := NewUser("moritz", "viewer")
	moritz.GroupRoles = map[string]string{"moritz": "admin"}
	ana, _, _ := NewUser("ana", "viewer")
	ana.GroupRoles = map[string]string{"Moritz": "analyst"}
	joey, _, _ := NewUser("joey", "admin")
	SaveUsers(dir, map[string]*User{"moritz": moritz, "ana": ana, "joey": joey})
	now := time.Now().UTC()
	s.state.Agents["m1"] = &AgentRec{ID: "m1", Name: "cyfort-m", Tags: []string{"Moritz"}, Baseline: map[string]bool{}}
	s.state.Agents["g1"] = &AgentRec{ID: "g1", Name: "game", Tags: []string{"Main"}, Baseline: map[string]bool{}}
	s.state.Alerts = []*Alert{
		{ID: "am", Rule: "file.cron", Severity: "medium", Agent: "m1", Status: "open", Created: now, Updated: now},
		{ID: "ag", Rule: "file.cron", Severity: "medium", Agent: "g1", Status: "open", Created: now, Updated: now},
		{ID: "as", Rule: "chain.broken", Severity: "critical", Status: "open", Created: now, Updated: now},
	}
	s.state.Incidents = []*Incident{{ID: "im", Agent: "m1", Status: "open"}, {ID: "ig", Agent: "g1", Status: "open"}}
	h := s.uiHandler()
	sessions := map[string][2]string{}
	for _, u := range []string{"moritz", "ana", "joey"} {
		tok, ss := s.newSession(u, "1.2.3.4")
		sessions[u] = [2]string{tok, ss.CSRF}
	}
	call := func(user, method, path, body string) int {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.AddCookie(&http.Cookie{Name: cookieName, Value: sessions[user][0]})
		r.Header.Set("X-CSRF", sessions[user][1])
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	for _, c := range []struct {
		user, method, path, body string
		want                     int
	}{
		// his group: admin
		{"moritz", "POST", "/api/ui/agents/m1/rename", `{"name":"cyfort-m2"}`, 200},
		{"moritz", "POST", "/api/ui/agents/m1/maintenance", `{"minutes":30}`, 200},
		{"moritz", "POST", "/api/ui/alerts/am/ack", `{}`, 200},
		{"moritz", "POST", "/api/ui/incidents/im/note", `{"note":"looked"}`, 200},
		{"moritz", "POST", "/api/ui/incidents/new/create", `{"alert":"am"}`, 200},
		// the rest of the network: viewer
		{"moritz", "POST", "/api/ui/agents/g1/rename", `{"name":"x"}`, 403},
		// reading a host's analysis is a viewer's right; the POST of the
		// same path is an unknown host action
		{"moritz", "GET", "/api/ui/agents/g1/activity?days=7", "", 200},
		{"moritz", "POST", "/api/ui/agents/g1/activity", `{}`, 403},
		{"moritz", "POST", "/api/ui/alerts/ag/ack", `{}`, 403},
		{"moritz", "POST", "/api/ui/alerts/as/ack", `{}`, 403}, // the server's own alerts
		{"moritz", "POST", "/api/ui/incidents/ig/note", `{"note":"x"}`, 403},
		{"moritz", "POST", "/api/ui/incidents/new/create", `{"alert":"ag"}`, 403},
		{"moritz", "POST", "/api/ui/incidents/im/add", `{"alert":"ag"}`, 403}, // pulling a foreign alert in
		{"moritz", "POST", "/api/ui/canaries", `{"agent_id":"g1","type":"credentials","path":"/root/x"}`, 403},
		// network wide stays with the base role, even for a group admin
		{"moritz", "POST", "/api/ui/agents/m1/tags", `{"tags":["Main"]}`, 403},
		{"moritz", "POST", "/api/ui/agents/m1/delete", `{}`, 403},
		{"moritz", "POST", "/api/ui/tokens", `{}`, 403},
		{"moritz", "POST", "/api/ui/groups", `{"action":"members","group":"Moritz","hosts":["g1"]}`, 403},
		{"moritz", "POST", "/api/ui/suppressions", `{"rule":"file.cron","reason":"x"}`, 403},
		{"moritz", "GET", "/api/ui/users", ``, 403},
		{"moritz", "GET", "/api/ui/alerts", ``, 200},
		// an analyst of the group: alerts yes, the host itself no
		{"ana", "POST", "/api/ui/alerts/am/resolve", `{}`, 200},
		{"ana", "POST", "/api/ui/agents/m1/maintenance", `{"minutes":30}`, 403},
		// not found stays not found
		{"moritz", "POST", "/api/ui/alerts/nope/ack", `{}`, 404},
		{"joey", "POST", "/api/ui/agents/g1/tags", `{"tags":["Main","game"]}`, 200},
	} {
		if got := call(c.user, c.method, c.path, c.body); got != c.want {
			t.Errorf("%s %s %s: %d, want %d", c.user, c.method, c.path, got, c.want)
		}
	}

	// bulk: only the alerts of his hosts change
	s.state.Alerts[0].Status, s.state.Alerts[1].Status = "open", "open"
	r := httptest.NewRequest("POST", "/api/ui/alerts/bulk", strings.NewReader(`{"ids":["am","ag","as"],"action":"resolve"}`))
	r.AddCookie(&http.Cookie{Name: cookieName, Value: sessions["moritz"][0]})
	r.Header.Set("X-CSRF", sessions["moritz"][1])
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var res map[string]int
	json.Unmarshal(w.Body.Bytes(), &res)
	if w.Code != 200 || res["changed"] != 1 || res["denied"] != 2 || s.state.Alerts[1].Status != "open" || s.state.Alerts[0].Status != "resolved" {
		t.Fatalf("bulk: %d %v", w.Code, res)
	}
}

func TestRoleSetFor(t *testing.T) {
	rs := roleSet{base: "viewer", groups: map[string]string{"moritz": "admin", "main": "analyst"},
		tags: map[string][]string{"m1": {"Moritz"}, "x": {"Main", "Moritz"}, "g": {"Other"}}}
	for agent, want := range map[string]string{"m1": "admin", "x": "admin", "g": "viewer", "": "viewer", "unknown": "viewer"} {
		if got := rs.For(agent); got != want {
			t.Errorf("%q: %s, want %s", agent, got, want)
		}
	}
	if !rs.mayHost("admin", "m1") || rs.mayHost("admin", "m1", "g") || rs.mayHost("analyst") {
		t.Error("mayHost")
	}
	if _, err := cleanGroupRoles(map[string]string{"Moritz": "root"}); err == nil {
		t.Error("unknown role accepted")
	}
	if _, err := cleanGroupRoles(map[string]string{"a/b": "admin"}); err == nil {
		t.Error("bad group name accepted")
	}
}

func TestNotifierGroups(t *testing.T) {
	m := message{Groups: []string{"Moritz"}}
	for _, c := range []struct {
		groups []string
		m      message
		want   bool
	}{
		{nil, m, true},
		{[]string{"moritz"}, m, true},
		{[]string{"Main"}, m, false},
		{[]string{"Moritz"}, message{}, false}, // the server's own messages
	} {
		if got := forGroups(NotifierConfig{Groups: c.groups}, c.m); got != c.want {
			t.Errorf("%v %v: %v", c.groups, c.m.Groups, got)
		}
	}
}

func TestGroupActions(t *testing.T) {
	s := forensicServer(t)
	s.state.Agents["a1"].Tags = []string{"E"}
	s.state.Agents["a2"].Tags = []string{"E", "M"}
	do := func(body string) int {
		w := httptest.NewRecorder()
		s.handleGroupAction(w, httptest.NewRequest("POST", "/api/ui/groups", strings.NewReader(body)), &session{User: "joey"})
		var res map[string]int
		json.Unmarshal(w.Body.Bytes(), &res)
		return res["changed"]
	}
	if n := do(`{"action":"rename","group":"e","to":"Emilian"}`); n != 2 || s.state.Agents["a2"].Tags[0] != "Emilian" {
		t.Fatalf("rename: %d %v", n, s.state.Agents["a2"].Tags)
	}
	if n := do(`{"action":"members","group":"M","hosts":["a1"]}`); n != 2 || !hasTag(s.state.Agents["a1"], "M") || hasTag(s.state.Agents["a2"], "M") {
		t.Fatalf("members: %d", n)
	}
	if n := do(`{"action":"delete","group":"Emilian"}`); n != 2 || hasTag(s.state.Agents["a1"], "Emilian") {
		t.Fatalf("delete: %d", n)
	}
}
