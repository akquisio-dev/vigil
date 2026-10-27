package server

import (
	"bytes"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
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
			proto.Peer{IP: "10.90.0.1", Port: 8471, Out: true, N: 1}, proto.Peer{IP: "172.23.0.2", Port: 5432, Out: true, N: 2, Process: "docker-proxy"}),
		"game": lat([]string{"87.106.34.84", "10.90.0.2"}, 3, 1, proto.Peer{IP: "10.90.0.1", Port: 3306, N: 2, Process: "mysqld"}, proto.Peer{IP: "10.90.0.1", Port: 8471, Out: true, N: 1, Process: "vigil-agent"}),
		// both Oracle hosts sit behind NAT with the same private address
		"o1": lat([]string{"10.0.0.5"}, 0, 1, proto.Peer{IP: "10.90.0.1", Port: 8471, Out: true, N: 1}),
		"o2": lat([]string{"10.0.0.5"}, 0, 1, proto.Peer{IP: "10.0.0.5", Port: 22, Out: true, N: 1}),
	}
	flows, ext, srv := hostGraph(agents, metrics, map[string]bool{"82.165.153.153": true}, now)
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
	// a host silent for an hour adds no links
	metrics["game"].Latest.TS = now.Add(-time.Hour)
	flows, ext, _ = hostGraph(agents, metrics, map[string]bool{"82.165.153.153": true}, now)
	if len(flows) != 2 || ext["game"] != [2]int{} {
		t.Fatalf("stale host linked: %+v %v", flows, ext)
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
