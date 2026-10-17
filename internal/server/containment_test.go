package server

import (
	"encoding/base32"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

func TestFourEyes(t *testing.T) {
	dir := t.TempDir()
	s, err := New(&Config{DataDir: dir, SessionHours: 1, FourEyes: []string{"isolate_host", "lock_user"}})
	if err != nil {
		t.Fatal(err)
	}
	ada, _, _ := NewUser("ada", "admin")
	bob, _, _ := NewUser("bob", "admin")
	SaveUsers(dir, map[string]*User{"ada": ada, "bob": bob})
	s.state.Agents["a1"] = &AgentRec{ID: "a1", Name: "web", ResponseTypes: []string{"isolate_host", "block_ip"}}
	h := s.uiHandler()
	post := func(tok, csrf, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		r.AddCookie(&http.Cookie{Name: cookieName, Value: tok})
		r.Header.Set("X-CSRF", csrf)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	code := func(u *User, step int64) string {
		b, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(u.TOTPSecret)
		return totpAt(b, time.Now().Unix()/30+step)
	}
	atok, as := s.newSession("ada", "1.2.3.4")
	btok, bs := s.newSession("bob", "1.2.3.5")
	// Not covered by four-eyes: goes out at once.
	w := post(atok, as.CSRF, "/api/ui/agents/a1/respond", `{"type":"block_ip","params":{"ip":"203.0.113.9"},"code":"`+code(ada, 0)+`"}`)
	if w.Code != 200 || len(s.pendingActions("a1")) != 1 {
		t.Fatalf("block_ip: %d %s", w.Code, w.Body.String())
	}
	w = post(atok, as.CSRF, "/api/ui/agents/a1/respond", `{"type":"isolate_host","params":{"minutes":"30"},"code":"`+code(ada, 1)+`"}`)
	var act ActionRec
	json.Unmarshal(w.Body.Bytes(), &act)
	if w.Code != 200 || act.Status != "approval" || len(s.pendingActions("a1")) != 1 {
		t.Fatalf("isolate waits: %d %+v", w.Code, act)
	}
	// The requester cannot approve it.
	if w := post(atok, as.CSRF, "/api/ui/actions/"+act.ID+"/approve", `{"code":"`+code(ada, -1)+`"}`); w.Code != http.StatusForbidden {
		t.Fatalf("self approval: %d", w.Code)
	}
	if w := post(btok, bs.CSRF, "/api/ui/actions/"+act.ID+"/approve", `{"code":"000000"}`); w.Code != http.StatusForbidden {
		t.Fatalf("wrong code: %d", w.Code)
	}
	w = post(btok, bs.CSRF, "/api/ui/actions/"+act.ID+"/approve", `{"code":"`+code(bob, 0)+`"}`)
	if w.Code != 200 {
		t.Fatalf("approve: %d %s", w.Code, w.Body.String())
	}
	pend := s.pendingActions("a1")
	if len(pend) != 2 || pend[1].Type != "isolate_host" || s.state.Actions[1].ApprovedBy != "bob" {
		t.Fatalf("after approval: %+v", pend)
	}
	if w := post(btok, bs.CSRF, "/api/ui/actions/"+act.ID+"/approve", `{"code":"`+code(bob, 1)+`"}`); w.Code != http.StatusConflict {
		t.Fatalf("approved twice: %d", w.Code)
	}
	if err := validAction("lock_user", map[string]string{"user": "root"}); err == nil {
		t.Fatal("lock root")
	}
	if err := validAction("isolate_host", map[string]string{"minutes": "5000"}); err == nil {
		t.Fatal("isolation longer than a day")
	}
}

func TestPlaybooks(t *testing.T) {
	s := forensicServer(t)
	s.cfg.Playbooks = []Playbook{
		{Name: "miner", Rules: []string{"process.miner"}, Actions: []string{"kill_process", "isolate_host"}, Minutes: 30, MaxPerHour: 2},
		{Name: "brute", Rules: []string{"ssh.*"}, MinSeverity: "medium", Actions: []string{"block_ip"}},
		{Name: "bad", Rules: []string{"x"}, Actions: []string{"unlock_user"}},
	}
	a := s.state.Agents["a1"]
	a.ResponseTypes = []string{"kill_process", "block_ip"} // isolate_host not allowed on this host
	mk := func(id, rule, sev, detail string) *Alert {
		return &Alert{ID: id, Agent: "a1", Rule: rule, Severity: sev, Detail: detail, Created: time.Now()}
	}
	runs := s.runPlaybooks([]*Alert{mk("m1", "process.miner", "critical", "pid=4242\nexe=/tmp/xmrig\n")})
	if len(runs) != 1 || len(s.state.Actions) != 1 || s.state.Actions[0].Type != "kill_process" || s.state.Actions[0].By != "playbook:miner" ||
		s.state.Actions[0].Params["pid"] != "4242" {
		t.Fatalf("miner: %v %+v", runs, s.state.Actions)
	}
	// low severity, other rule, no address: nothing
	s.runPlaybooks([]*Alert{mk("b0", "ssh.bruteforce", "low", "ip=198.51.100.7\n"), mk("x", "file.cron", "high", "")})
	if len(s.state.Actions) != 1 {
		t.Fatalf("unexpected: %+v", s.state.Actions)
	}
	s.runPlaybooks([]*Alert{mk("b1", "ssh.password_login", "high", "ip=198.51.100.7\nuser=x\n")})
	if len(s.state.Actions) != 2 || s.state.Actions[1].Params["ip"] != "198.51.100.7" || s.state.Actions[1].Params["minutes"] != "60" {
		t.Fatalf("block: %+v", s.state.Actions[1])
	}
	// The hourly cap.
	s.runPlaybooks([]*Alert{mk("m2", "process.miner", "critical", "pid=5\nexe=/tmp/a\n")})
	s.runPlaybooks([]*Alert{mk("m3", "process.miner", "critical", "pid=6\nexe=/tmp/b\n")})
	n := 0
	for _, x := range s.state.Actions {
		if x.Playbook == "miner" {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("cap: %d miner actions", n)
	}
	// Four-eyes covers playbooks too.
	s.cfg.FourEyes = []string{"*"}
	s.playbookRuns = nil
	s.runPlaybooks([]*Alert{mk("m4", "process.miner", "critical", "pid=7\nexe=/tmp/c\n")})
	if last := s.state.Actions[len(s.state.Actions)-1]; last.Status != "approval" {
		t.Fatalf("four-eyes on playbooks: %+v", last)
	}
	if err := validatePlaybook(s.cfg.Playbooks[2]); err == nil {
		t.Fatal("unlock_user is not automatic")
	}
	// containment state from the agent
	s.evaluate(a, &Record{Event: proto.Event{Type: "response.state", Data: map[string]any{"isolated_until": "2026-10-17T20:00:00Z", "locked": map[string]any{}}}})
	if a.Contain["isolated_until"] != "2026-10-17T20:00:00Z" {
		t.Fatalf("contain: %+v", a.Contain)
	}
}
