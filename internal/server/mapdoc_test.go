package server

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func mapOps(t *testing.T, ops ...string) []mapOp {
	t.Helper()
	var out []mapOp
	for _, o := range ops {
		var op mapOp
		if err := json.Unmarshal([]byte(o), &op); err != nil {
			t.Fatalf("%s: %v", o, err)
		}
		out = append(out, op)
	}
	return out
}

func TestMapRightsAndLimits(t *testing.T) {
	m, err := openMapStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	users := map[string]bool{"ada": true, "vera": true}
	ada := mapActor{user: "ada", admin: true, users: users}
	vera := mapActor{user: "vera", users: users}

	if _, err := m.apply(mapOps(t, `{"op":"put","c":"objects","id":"n1","v":{"kind":"note","x":10,"y":20,"text":"hi","color":"yellow","author":"mallory"}}`), ada, 0, now); err != nil {
		t.Fatal(err)
	}
	if o := m.doc.Objects["n1"]; o == nil || o.Author != "ada" || m.doc.Rev != 1 {
		t.Fatalf("note: %+v rev %d", o, m.doc.Rev)
	}
	if _, err := m.apply(mapOps(t, `{"op":"put","c":"layout","id":"h1","v":[1,2]}`), vera, 0, now); err != errMapForbidden {
		t.Fatalf("a viewer moved a box: %v", err)
	}
	// anyone comments, with mentions of accounts that exist
	if _, err := m.apply(mapOps(t, `{"op":"put","c":"comments","id":"c1","v":{"target":"host:h1","text":"@ada look @nobody"}}`), vera, 0, now); err != nil {
		t.Fatal(err)
	}
	if c := m.doc.Comments["c1"]; c.Author != "vera" || len(c.Mentions) != 1 || c.Mentions[0] != "ada" {
		t.Fatalf("comment: %+v", c)
	}
	// someone else may mark it done, not rewrite it
	resolve := `{"op":"put","c":"comments","id":"c1","v":{"target":"host:h1","text":"@ada look @nobody","resolved":true}}`
	if _, err := m.apply(mapOps(t, `{"op":"put","c":"comments","id":"c1","v":{"target":"host:h1","text":"changed"}}`), mapActor{user: "eve", users: users}, 0, now); err != errMapForbidden {
		t.Fatalf("rewrote another's comment: %v", err)
	}
	if _, err := m.apply(mapOps(t, resolve), mapActor{user: "eve", users: users}, 0, now); err != nil || !m.doc.Comments["c1"].Resolved || m.doc.Comments["c1"].Author != "vera" {
		t.Fatalf("resolve: %v %+v", err, m.doc.Comments["c1"])
	}
	for _, bad := range []string{
		`{"op":"put","c":"objects","id":"x","v":{"kind":"bomb"}}`,
		`{"op":"put","c":"objects","id":"x","v":{"kind":"note","x":1e9}}`,
		`{"op":"put","c":"objects","id":"x","v":{"kind":"note","text":"` + strings.Repeat("a", mapMaxText+1) + `"}}`,
		`{"op":"put","c":"objects","id":"x","v":{"kind":"arrow","from":"host:a;rm","to":"net"}}`,
		`{"op":"put","c":"objects","id":"x","v":{"kind":"note","layer":"nope"}}`,
		`{"op":"put","c":"objects","id":"../x","v":{"kind":"note"}}`,
		`{"op":"put","c":"tasks","id":"t","v":{"title":"x","status":"open","assignee":"ghost"}}`,
		`{"op":"put","c":"secrets","id":"t","v":{}}`,
	} {
		if _, err := m.apply(mapOps(t, bad), ada, 0, now); err == nil {
			t.Errorf("accepted %s", bad[:min(len(bad), 80)])
		}
	}
	// a batch is all or nothing
	if _, err := m.apply(mapOps(t, `{"op":"put","c":"objects","id":"ok","v":{"kind":"text","text":"a"}}`, `{"op":"put","c":"objects","id":"x","v":{"kind":"bomb"}}`), ada, 0, now); err == nil || m.doc.Objects["ok"] != nil {
		t.Fatal("half a batch was applied")
	}
}

func TestMapCascadeUndoRestore(t *testing.T) {
	dir := t.TempDir()
	m, _ := openMapStore(dir)
	now := time.Now()
	ada := mapActor{user: "ada", admin: true, users: map[string]bool{"ada": true}}
	bob := mapActor{user: "bob", admin: true, users: map[string]bool{"bob": true}}
	m.apply(mapOps(t, `{"op":"put","c":"layers","id":"p1","v":{"name":"Umzug","status":"draft"}}`,
		`{"op":"put","c":"objects","id":"a1","v":{"kind":"arrow","layer":"p1","style":"allow","from":"host:h1","to":"host:h2"}}`), ada, 0, now) // rev 1
	m.apply(mapOps(t, `{"op":"put","c":"layout","id":"h1","v":[100,200]}`), ada, 0, now) // rev 2
	m.apply(mapOps(t, `{"op":"put","c":"layout","id":"h1","v":[300,400]}`), ada, 0, now) // rev 3

	undo := func(a mapActor, redo bool) error {
		rev := m.undoTarget(a.user, redo)
		if rev == 0 {
			return errMapForbidden
		}
		ops, err := m.revert(rev)
		if err != nil {
			return err
		}
		_, err = m.apply(ops, a, rev, now)
		return err
	}
	if err := undo(ada, false); err != nil || m.doc.Layout["h1"] != [2]float64{100, 200} {
		t.Fatalf("undo: %v %v", err, m.doc.Layout["h1"])
	}
	if err := undo(ada, false); err != nil || len(m.doc.Layout) != 0 {
		t.Fatalf("second undo: %v %v", err, m.doc.Layout)
	}
	if err := undo(ada, true); err != nil || m.doc.Layout["h1"] != [2]float64{100, 200} {
		t.Fatalf("redo: %v %v", err, m.doc.Layout)
	}
	// someone else moved it since: undo refuses
	m.apply(mapOps(t, `{"op":"put","c":"layout","id":"h1","v":[0,0]}`), bob, 0, now)
	if err := undo(ada, false); err == nil {
		t.Fatal("undo overwrote another's change")
	}
	// removing the plan removes its arrow, as one revision
	before := m.doc.Rev
	m.apply(mapOps(t, `{"op":"del","c":"layers","id":"p1"}`), bob, 0, now)
	if len(m.doc.Objects) != 0 || m.doc.Rev != before+1 {
		t.Fatalf("cascade: %+v", m.doc.Objects)
	}
	// back to revision 1: plan, arrow, no position
	ops, err := m.restoreOps(1)
	if err != nil {
		t.Fatal(err)
	}
	m.apply(ops, bob, 0, now)
	if m.doc.Layers["p1"] == nil || m.doc.Objects["a1"] == nil || len(m.doc.Layout) != 0 {
		t.Fatalf("restore: %+v %+v %+v", m.doc.Layers, m.doc.Objects, m.doc.Layout)
	}
	// it all survives a restart
	again, err := openMapStore(dir)
	if err != nil || again.doc.Rev != m.doc.Rev || again.doc.Objects["a1"] == nil || len(again.log) != len(m.log) {
		t.Fatalf("reopen: %v rev %d/%d log %d/%d", err, again.doc.Rev, m.doc.Rev, len(again.log), len(m.log))
	}
}

func TestUnplannedLinks(t *testing.T) {
	m, _ := openMapStore(t.TempDir())
	ada := mapActor{user: "ada", admin: true}
	m.apply(mapOps(t, `{"op":"put","c":"layers","id":"p","v":{"name":"Soll","status":"active","alert":true}}`,
		`{"op":"put","c":"objects","id":"a","v":{"kind":"arrow","layer":"p","style":"allow","from":"host:web","to":"host:db","meta":{"port":"3306"}}}`,
		`{"op":"put","c":"objects","id":"b","v":{"kind":"arrow","layer":"p","style":"block","from":"host:db","to":"host:web"}}`), ada, 0, time.Now())
	flows := []hostFlow{
		{From: "web", To: "db", Port: 3306, N: 4},                  // planned
		{From: "web", To: "db", Port: 22, N: 1, ClientProc: "ssh"}, // wrong port
		{From: "db", To: "web", Port: 22, N: 1},                    // blocked
		{From: "db", To: "web", Port: 8471, N: 1},                  // the agent
		{From: "other", To: "db", Port: 5432, N: 1},                // not in the plan
	}
	got := unplannedFindings(m.planRules(), flows, map[string]string{"web": "Web", "db": "DB"}, 8471)
	if len(got) != 2 || got[0].f.Params["port"] != "22" || got[0].f.Params["program"] != "ssh" || got[1].agent != "db" {
		t.Fatalf("findings = %+v", got)
	}
	// a draft does not alert
	m.apply(mapOps(t, `{"op":"put","c":"layers","id":"p","v":{"name":"Soll","status":"draft","alert":true}}`), ada, 0, time.Now())
	if len(m.planRules()) != 0 {
		t.Fatal("a draft plan alerts")
	}
}

func TestMapStreamAndRights(t *testing.T) {
	dir := t.TempDir()
	s, err := New(&Config{DataDir: dir, SessionHours: 1})
	if err != nil {
		t.Fatal(err)
	}
	ada, _, _ := NewUser("ada", "admin")
	vera, _, _ := NewUser("vera", "viewer")
	SaveUsers(dir, map[string]*User{"ada": ada, "vera": vera})
	srv := httptest.NewServer(s.uiHandler())
	defer srv.Close()
	atok, as := s.newSession("ada", "1.2.3.4")
	vtok, vs := s.newSession("vera", "1.2.3.5")
	call := func(method, path, body, tok, csrf string) *http.Response {
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		req.AddCookie(&http.Cookie{Name: cookieName, Value: tok})
		req.Header.Set("X-CSRF", csrf)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	// vera watches the map
	res := call("GET", "/api/ui/map/stream", "", vtok, "")
	defer res.Body.Close()
	if res.Header.Get("Content-Type") != "text/event-stream" || res.Header.Get("X-Accel-Buffering") != "no" {
		t.Fatalf("stream headers: %v", res.Header)
	}
	events := make(chan string, 20)
	go func() {
		sc := bufio.NewScanner(res.Body)
		for sc.Scan() {
			if strings.HasPrefix(sc.Text(), "event: ") {
				events <- strings.TrimPrefix(sc.Text(), "event: ")
			}
		}
		close(events)
	}()
	wait := func(want string) {
		t.Helper()
		for {
			select {
			case e, ok := <-events:
				if !ok {
					t.Fatalf("stream closed waiting for %s", want)
				}
				if e == want {
					return
				}
			case <-time.After(3 * time.Second):
				t.Fatalf("no %s event", want)
			}
		}
	}
	wait("hello")
	if r := call("POST", "/api/ui/map/ops", `{"ops":[{"op":"put","c":"layout","id":"h1","v":[1,2]}]}`, vtok, vs.CSRF); r.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer moved a box: %d", r.StatusCode)
	}
	if r := call("POST", "/api/ui/map/ops", `{"ops":[{"op":"put","c":"layout","id":"h1","v":[1,2]}]}`, atok, as.CSRF); r.StatusCode != 200 {
		t.Fatalf("admin move: %d", r.StatusCode)
	}
	wait("ops")
	if r := call("POST", "/api/ui/map/ops", `{"ops":[{"op":"put","c":"comments","id":"c1","v":{"target":"pos","x":5,"y":5,"text":"hier"}}]}`, vtok, vs.CSRF); r.StatusCode != 200 {
		t.Fatalf("viewer comment: %d", r.StatusCode)
	}
	wait("ops")
	if r := call("POST", "/api/ui/map/restore", `{"rev":1}`, vtok, vs.CSRF); r.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer restored: %d", r.StatusCode)
	}
	s.mapAlerts([]*Alert{{ID: "x", Agent: "h1", Severity: "high"}})
	wait("alert")
	var doc struct {
		Doc  MapDoc `json:"doc"`
		Edit bool   `json:"edit"`
	}
	json.NewDecoder(call("GET", "/api/ui/map", "", vtok, "").Body).Decode(&doc)
	if doc.Edit || doc.Doc.Rev != 2 || doc.Doc.Comments["c1"] == nil {
		t.Fatalf("doc: %+v", doc)
	}
}
