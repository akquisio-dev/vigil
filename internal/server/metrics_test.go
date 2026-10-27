package server

import (
	"bytes"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

func TestMetricsRollupAndRing(t *testing.T) {
	hm := &hostMetrics{}
	start := time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 125; i++ { // 10:00 .. 12:04
		hm.add(proto.Metrics{TS: start.Add(time.Duration(i) * time.Minute), CPU: float64(i % 60), MemTotal: 100, MemUsed: 50})
	}
	if len(hm.Hours) != 2 || hm.Hours[0].T != start.Unix() || hm.Hours[1].T != start.Add(time.Hour).Unix() {
		t.Fatalf("hours = %+v", hm.Hours)
	}
	if h := hm.Hours[0]; h.CPU != 29.5 || h.CPUMax != 59 || h.Mem != 50 {
		t.Fatalf("rollup = %+v", h)
	}
	hm.add(proto.Metrics{TS: start, CPU: 99}) // older sample is ignored
	if len(hm.Minutes) != 125 || hm.Minutes[len(hm.Minutes)-1].CPU == 99 {
		t.Fatalf("old sample stored: %d", len(hm.Minutes))
	}
	hm.add(proto.Metrics{TS: start.Add(25 * time.Hour)})
	if hm.Minutes[0].T <= start.Add(time.Hour).Unix() {
		t.Fatalf("minutes older than a day kept: %d", hm.Minutes[0].T)
	}
}

func TestCleanMetrics(t *testing.T) {
	m := cleanMetrics(proto.Metrics{CPU: math.NaN(), RX: math.Inf(1), IOWait: 400,
		Peers:  []proto.Peer{{IP: "::ffff:10.0.0.1", Port: 22, N: 1}, {IP: "nope", Port: 1, N: 1}, {IP: "10.0.0.2", Port: 0, N: 1}},
		Ifaces: []proto.IfaceRate{{Name: "wg0", Addrs: []string{"10.90.0.1", "x"}}}})
	if m.CPU != 0 || m.RX != 0 || m.IOWait != 100 {
		t.Fatalf("numbers = %v %v %v", m.CPU, m.RX, m.IOWait)
	}
	if len(m.Peers) != 1 || m.Peers[0].IP != "10.0.0.1" || len(m.Ifaces[0].Addrs) != 1 {
		t.Fatalf("lists = %+v %+v", m.Peers, m.Ifaces)
	}
}

func TestHostGraph(t *testing.T) {
	agents := map[string]*AgentRec{
		"web":  {ID: "web", LastIP: "127.0.0.1"},
		"game": {ID: "game", LastIP: "10.90.0.2"},
		"o1":   {ID: "o1", LastIP: "10.90.0.3"},
		"o2":   {ID: "o2", LastIP: "10.90.0.4"},
	}
	now := time.Now()
	lat := func(addrs []string, in, out int, peers ...proto.Peer) *hostMetrics {
		return &hostMetrics{Latest: &proto.Metrics{TS: now, ConnIn: in, ConnOut: out, Ifaces: []proto.IfaceRate{{Name: "eth0", Addrs: addrs}}, Peers: peers}}
	}
	metrics := map[string]*hostMetrics{
		// the game server's database is used by the web host; both see it
		// plus its own address and a container: neither is the internet
		"web": lat([]string{"82.165.153.153", "10.90.0.1"}, 10, 5, proto.Peer{IP: "10.90.0.2", Port: 3306, Out: true, N: 2, Process: "node"},
			proto.Peer{IP: "10.90.0.1", Port: 8471, Out: true, N: 1}, proto.Peer{IP: "172.23.0.2", Port: 5432, Out: true, N: 2, Process: "docker-proxy"},
			proto.Peer{IP: "203.0.113.9", Port: 443, N: 7, Process: "nginx"}),
		"game": lat([]string{"87.106.34.84", "10.90.0.2"}, 3, 1, proto.Peer{IP: "10.90.0.1", Port: 3306, N: 2, Process: "mysqld"}, proto.Peer{IP: "10.90.0.1", Port: 8471, Out: true, N: 1, Process: "vigil-agent"}),
		// both Oracle hosts sit behind NAT with the same private address
		"o1": lat([]string{"10.0.0.5"}, 0, 1, proto.Peer{IP: "10.90.0.1", Port: 8471, Out: true, N: 1}),
		"o2": lat([]string{"10.0.0.5"}, 0, 1, proto.Peer{IP: "10.0.0.5", Port: 22, Out: true, N: 1}),
	}
	flows, ext, extPeers, srv := hostGraph(agents, metrics, map[string]bool{"82.165.153.153": true}, now)
	if srv != "web" {
		t.Fatalf("server host = %q", srv)
	}
	want := []hostFlow{
		{From: "game", To: "web", Port: 8471, N: 1, ClientProc: "vigil-agent"},
		{From: "o1", To: "web", Port: 8471, N: 1},
		{From: "web", To: "game", Port: 3306, N: 2, ClientProc: "node", ServerProc: "mysqld"},
	}
	if len(flows) != len(want) {
		t.Fatalf("flows = %+v", flows)
	}
	for i := range want {
		if flows[i] != want[i] {
			t.Fatalf("flow %d = %+v, want %+v", i, flows[i], want[i])
		}
	}
	// o2's connection goes to the ambiguous private address: no host, no internet
	if ext["o2"] != [2]int{0, 0} || ext["web"] != [2]int{10, 0} || ext["game"] != [2]int{1, 0} {
		t.Fatalf("external = %v", ext)
	}
	// only the public address of no host is the internet's
	if len(extPeers["web"]) != 1 || extPeers["web"][0].IP != "203.0.113.9" || len(extPeers["game"]) != 0 || len(extPeers["o2"]) != 0 {
		t.Fatalf("external peers = %+v", extPeers)
	}
	// a host silent for an hour adds no links
	metrics["game"].Latest.TS = now.Add(-time.Hour)
	flows, ext, _, _ = hostGraph(agents, metrics, map[string]bool{"82.165.153.153": true}, now)
	if len(flows) != 2 || ext["game"] != [2]int{} {
		t.Fatalf("stale host linked: %+v %v", flows, ext)
	}
}

func TestSummarizeExt(t *testing.T) {
	cc := map[string]string{"203.0.113.1": "DE", "203.0.113.2": "US", "203.0.113.3": "DE"}
	peers := []proto.Peer{
		{IP: "203.0.113.1", Port: 443, N: 5, Process: "nginx"},
		{IP: "203.0.113.2", Port: 443, N: 2, Process: "nginx"},
		{IP: "203.0.113.3", Port: 443, N: 4, Process: "nginx"},
		{IP: "198.51.100.7", Port: 443, Out: true, N: 3, Process: "node"},
	}
	for i := 0; i < 8; i++ {
		peers = append(peers, proto.Peer{IP: "198.51.100.1", Port: 1000 + i, N: 1})
	}
	got := summarizeExt(peers, func(ip string) string { return cc[ip] })
	if len(got) != 6 {
		t.Fatalf("want the top 6, got %d", len(got))
	}
	if g := got[0]; g.Out || g.Port != 443 || g.N != 11 || g.Addrs != 3 || len(g.Countries) != 2 || g.Countries[0] != "DE" {
		t.Fatalf("top = %+v", g)
	}
	if g := got[1]; !g.Out || g.N != 3 || g.Proc != "node" || g.Countries != nil && len(g.Countries) != 0 {
		t.Fatalf("second = %+v", g)
	}
}

func TestTopoLayoutIsPerUser(t *testing.T) {
	dir := t.TempDir()
	s, err := New(&Config{DataDir: dir, SessionHours: 1})
	if err != nil {
		t.Fatal(err)
	}
	vera, _, _ := NewUser("vera", "viewer")
	ada, _, _ := NewUser("ada", "admin")
	if err := SaveUsers(dir, map[string]*User{"vera": vera, "ada": ada}); err != nil {
		t.Fatal(err)
	}
	h := s.uiHandler()
	call := func(method, body, tok, csrf string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/api/ui/account/topology", strings.NewReader(body))
		r.AddCookie(&http.Cookie{Name: cookieName, Value: tok})
		r.Header.Set("X-CSRF", csrf)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	vtok, vs := s.newSession("vera", "1.2.3.4")
	atok, _ := s.newSession("ada", "1.2.3.5")
	if w := call("POST", `{"pos":{"a1":[120.4,-40],"net":[0,0]}}`, vtok, vs.CSRF); w.Code != 200 {
		t.Fatalf("a viewer may place boxes: %d %s", w.Code, w.Body.String())
	}
	time.Sleep(10 * time.Millisecond)
	if w := call("GET", "", vtok, ""); !strings.Contains(w.Body.String(), `"a1":[120,-40]`) {
		t.Fatalf("own layout: %s", w.Body.String())
	}
	if w := call("GET", "", atok, ""); strings.TrimSpace(w.Body.String()) != `{"pos":{}}` {
		t.Fatalf("another user's layout leaked: %s", w.Body.String())
	}
	for _, bad := range []string{`{"pos":{"a1":[1e9,0]}}`, `{"pos":{"../x":[0,0]}}`, `{"pos":{"a1":[0,0]}`} {
		if w := call("POST", bad, vtok, vs.CSRF); w.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d", bad, w.Code)
		}
	}
	if w := call("POST", `{"pos":{"a1":[0,0]}}`, vtok, ""); w.Code == 200 {
		t.Fatal("saving needs the CSRF token")
	}
	call("POST", `{"pos":{}}`, vtok, vs.CSRF)
	time.Sleep(10 * time.Millisecond)
	if w := call("GET", "", vtok, ""); strings.TrimSpace(w.Body.String()) != `{"pos":{}}` {
		t.Fatalf("reset: %s", w.Body.String())
	}
}

func TestMetricsStayOutOfStore(t *testing.T) {
	dir := t.TempDir()
	s, err := New(&Config{DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	s.loadMetrics()
	ta := newTestAgent(t, s)
	before, _ := s.store.Head()
	ta.seq++
	body, _ := json.Marshal(proto.Batch{AgentID: ta.a.ID, Seq: ta.seq, SentAt: time.Now(), Events: []proto.Event{},
		Metrics: []proto.Metrics{{TS: time.Now().Add(-time.Minute), CPU: 12}, {TS: time.Now(), CPU: 34, Top: []proto.ProcLoad{{PID: 1, Comm: "init"}}},
			{TS: time.Now().Add(-3 * time.Hour), CPU: 99}}})
	req := httptest.NewRequest(http.MethodPost, "/api/agent/events", bytes.NewReader(body))
	req.Header.Set(proto.SigHeader, proto.Sign(ta.key, body))
	w := httptest.NewRecorder()
	s.handleEvents(w, req)
	if w.Code != 200 {
		t.Fatalf("batch refused: %d", w.Code)
	}
	if after, _ := s.store.Head(); after != before {
		t.Fatalf("metrics reached the event store: %d -> %d", before, after)
	}
	hm := s.metrics.hosts[ta.a.ID]
	if hm == nil || len(hm.Minutes) != 2 || hm.Latest == nil || hm.Latest.CPU != 34 {
		t.Fatalf("stored = %+v", hm)
	}

	s.saveMetrics(true)
	s2, _ := New(&Config{DataDir: dir})
	s2.loadMetrics()
	if got := s2.metrics.hosts[ta.a.ID]; got == nil || len(got.Minutes) != 2 {
		t.Fatalf("not reloaded: %+v", got)
	}

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/ui/agents/a1/metrics?range=1h", nil)
	r.SetPathValue("id", "a1")
	s.handleAgentMetrics(rec, r, nil)
	var out struct {
		Points []metricPoint `json:"points"`
	}
	if json.Unmarshal(rec.Body.Bytes(), &out) != nil || len(out.Points) != 2 {
		t.Fatalf("metrics endpoint: %s", rec.Body)
	}
}

func TestOwnAddrsFromListen(t *testing.T) {
	own := ownAddrs("10.90.0.2:8471", "127.0.0.1:8470", "0.0.0.0:1", "bad")
	if !own["10.90.0.2"] || own["127.0.0.1"] || own["0.0.0.0"] {
		t.Fatalf("own = %v", own)
	}
}
