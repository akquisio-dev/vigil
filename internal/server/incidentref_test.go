package server

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestParseIncidentRef(t *testing.T) {
	for in, want := range map[string]int{"INC-0042": 42, "inc-42": 42, "#7": 7, " 12 ": 12, "INC-1234567": 1234567} {
		if n, ok := parseIncidentRef(in); !ok || n != want {
			t.Errorf("%q: %d %v, want %d", in, n, ok, want)
		}
	}
	for _, in := range []string{"", "INC-", "INC-0", "-3", "abc", "1a2b3c4d5e6f7a8b", "INC-x1", "1234567890"} {
		if n, ok := parseIncidentRef(in); ok {
			t.Errorf("%q: read as %d", in, n)
		}
	}
	if IncidentRef(42) != "INC-0042" || IncidentRef(12345) != "INC-12345" || IncidentRef(0) != "" {
		t.Error(IncidentRef(42), IncidentRef(12345))
	}
}

// Incidents from before numbers get theirs in the order they were opened;
// numbers are never given twice, even when old incidents are dropped.
func TestIncidentNumbers(t *testing.T) {
	dir := t.TempDir()
	t0 := time.Now().UTC().Add(-time.Hour)
	old := &State{Agents: map[string]*AgentRec{}, Incidents: []*Incident{
		{ID: "bbbb", Created: t0.Add(time.Minute)}, {ID: "aaaa", Created: t0},
	}}
	if err := old.Save(dir); err != nil {
		t.Fatal(err)
	}
	st, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.findIncident("aaaa").No != 1 || st.findIncident("bbbb").No != 2 || st.NextIncident != 3 {
		t.Fatalf("numbers %d %d, next %d", st.findIncident("aaaa").No, st.findIncident("bbbb").No, st.NextIncident)
	}
	if st.findIncident("INC-0002").ID != "bbbb" || st.findIncident("2").ID != "bbbb" || st.findIncident("INC-0009") != nil {
		t.Fatal("lookup by reference")
	}

	s := forensicServer(t)
	s.state = st
	s.state.Agents["a1"] = &AgentRec{ID: "a1", Name: "web", Hostname: "web.example"}
	al := &Alert{ID: "al1", Rule: "ssh.password_login", Severity: "high", Agent: "a1", Created: time.Now().UTC(), Status: "open",
		Detail: encodeParams(map[string]string{"user": "root", "ip": "198.51.100.7", "host": "web"})}
	s.state.Alerts = append(s.state.Alerts, al)
	s.mu.Lock()
	s.correlate([]*Alert{al})
	s.mu.Unlock()
	c := s.incident(al.Incident)
	if c == nil || c.No != 3 || s.state.NextIncident != 4 {
		t.Fatalf("new incident %+v, next %d", c, s.state.NextIncident)
	}
	// the oldest are dropped, the counter stays
	s.state.Incidents = s.state.Incidents[2:]
	s.state.Save(dir)
	st2, _ := LoadState(dir)
	if st2.NextIncident != 4 {
		t.Fatalf("next %d after dropping old incidents", st2.NextIncident)
	}

	c.Notes = append(c.Notes, Note{By: "joey", At: time.Now().UTC(), Text: "checked\nall fine"})
	text := s.state.incidentText(c, "https://soc.example/", "en")
	for _, want := range []string{"# INC-0003: ", "Host: web (web.example)", "https://soc.example/#/incidents/INC-0003",
		"ssh.password_login", "  - ip: 198.51.100.7", "joey: checked\n  all fine"} {
		if !strings.Contains(text, want) {
			t.Errorf("text lacks %q:\n%s", want, text)
		}
	}

	var v struct {
		Incident incidentView `json:"incident"`
	}
	h := func(w http.ResponseWriter, r *http.Request) { s.handleIncident(w, r, &session{User: "u"}) }
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/ui/incidents/{id}", h)
	if code := getJSON(t, mux.ServeHTTP, "/api/ui/incidents/inc-3", nil, &v); code != 200 || v.Incident.Ref != "INC-0003" || v.Incident.ID != c.ID {
		t.Fatalf("by reference: %d %+v", code, v.Incident)
	}
}
