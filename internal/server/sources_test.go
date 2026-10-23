package server

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

func postSess(t *testing.T, h func(http.ResponseWriter, *http.Request, *session), url string, body any, sess *session, out any, pv ...string) int {
	t.Helper()
	b, _ := json.Marshal(body)
	r := httptest.NewRequest("POST", url, bytes.NewReader(b))
	for i := 0; i+1 < len(pv); i += 2 {
		r.SetPathValue(pv[i], pv[i+1])
	}
	w := httptest.NewRecorder()
	h(w, r, sess)
	if w.Code == 200 && out != nil {
		json.Unmarshal(w.Body.Bytes(), out)
	}
	return w.Code
}

// sharingServer has attacks of every kind a share must leave out, next to
// the ones it may name.
func sharingServer(t *testing.T) *Server {
	s := forensicServer(t)
	s.limit = &limiter{fails: map[string][]time.Time{}}
	s.cfg.Brand = &BrandConfig{Name: "Zypo Cloud"}
	s.cfg.Federation = &FederationConfig{Name: "net-a", Never: []string{"198.18.0.0/15"}}
	s.state.Agents["a1"].Name = "STRATO alpha"
	s.cfg.TrustProxy = true // as behind the dashboard's proxy; the feed listener must ignore it
	// behind a VPN the agent connects from an internal address; its public
	// one only shows in the ports it listens on
	s.state.Agents["a1"].LastIP = "10.90.0.2"
	s.state.Agents["a1"].Ports = []map[string]any{{"proto": "tcp", "addr": "203.0.113.50", "port": float64(22)}}
	// the team logged in from here three weeks ago, outside any share window
	s.state.KnownLogins["joey|198.51.100.77"] = time.Now().AddDate(0, 0, -21)
	now := time.Now().UTC()
	fail := func(ip string, n int, users []string, existing ...string) {
		d := map[string]any{"ip": ip, "count": float64(n), "users": anyList(users...)}
		if len(existing) > 0 {
			d["existing_users"] = anyList(existing...)
		}
		appendAt(t, s, "a1", now.Add(-time.Hour), "ssh.failed", d)
	}
	fail("198.51.100.10", 30, []string{"root", "joey", "zypo-admin"}, "joey") // attacker; joey exists here
	appendAt(t, s, "a1", now.Add(-time.Hour), "web.activity", map[string]any{"ip": "198.51.100.11", "requests": float64(9), "probes": float64(9),
		"samples": anyList("GET /secret-admin-path/.env"), "user_agent": "zgrab"})
	fail("10.0.0.5", 50, []string{"root"})               // private
	fail("203.0.113.50", 50, []string{"root"})           // one of our hosts
	fail("198.18.0.7", 50, []string{"root"})             // federation.never
	fail("192.0.2.99", 50, []string{"root"})             // the partner's own network
	fail("198.51.100.77", 3, []string{"joey"})           // the team, with the wrong key first
	fail("198.51.100.13", 1, []string{"root"})           // under min_hits
	fail("198.51.100.12", 5, []string{"root", "deploy"}) // and then logged in
	appendAt(t, s, "a1", now.Add(-30*time.Minute), "ssh.login", map[string]any{"ip": "198.51.100.12", "user": "deploy", "method": "publickey"})
	s.startAttacks()
	waitAttacks(t, s)
	return s
}

var admin = &session{User: "admin"}

func TestFederationEndToEnd(t *testing.T) {
	a := sharingServer(t)
	share := shareReq{Name: "Kumpel", Cats: []string{"ssh", "web"}, Users: true, Counts: true, Days: 7, MinHits: 2,
		Exclude: []string{"192.0.2.0/24"}, Enabled: true}

	// the preview is what a fetch gets
	var prev struct {
		Count  int         `json:"count"`
		Sample []feedEntry `json:"sample"`
	}
	pq := share
	pq.Preview = true
	if c := postSess(t, a.handleShareSave, "/", pq, admin, &prev); c != 200 || prev.Count != 2 {
		t.Fatalf("preview %d: %+v", c, prev)
	}
	a.mu.Lock()
	if len(a.state.Shares) != 0 {
		t.Fatal("a preview must not save")
	}
	a.mu.Unlock()

	var made struct {
		Share shareView `json:"share"`
		Token string    `json:"token"`
	}
	if c := postSess(t, a.handleShareSave, "/", share, admin, &made); c != 200 || !strings.HasPrefix(made.Token, "vfs_") {
		t.Fatalf("create %d %+v", c, made)
	}
	a.mu.Lock()
	if a.state.Shares[0].Hash == made.Token || a.state.Shares[0].Hash != sha(made.Token) {
		t.Fatal("only the token's hash is kept")
	}
	a.mu.Unlock()

	ts := httptest.NewServer(a.federationHandler())
	defer ts.Close()
	get := func(tok string) (int, []byte) {
		req, _ := http.NewRequest("GET", ts.URL+"/api/federation/v1/feed", nil)
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, b
	}
	// X-Forwarded-For is the partner's word on this listener: it neither
	// names the fetcher nor gets around the limit
	spoof := func(tok, xff string) int {
		req, _ := http.NewRequest("GET", ts.URL+"/api/federation/v1/feed", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("X-Forwarded-For", xff)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if c := spoof(made.Token, "203.0.113.200"); c != 200 {
		t.Fatalf("feed with XFF: %d", c)
	}
	a.mu.Lock()
	if ip := a.state.Shares[0].PulledIP; ip != "127.0.0.1" {
		t.Fatalf("fetcher recorded as %q", ip)
	}
	a.mu.Unlock()
	defer a.limit.reset("feed:127.0.0.1")
	for i := 0; i < limitFails; i++ {
		spoof("vfs_wrong", fmt.Sprintf("198.18.%d.1", i))
	}
	if c := spoof(made.Token, "198.18.200.1"); c != 429 {
		t.Fatalf("a new X-Forwarded-For got around the limit: %d", c)
	}
	a.limit.reset("feed:127.0.0.1")
	if c, _ := get(""); c != 401 {
		t.Fatalf("no token: %d", c)
	}
	if c, _ := get("vfs_wrong"); c != 401 {
		t.Fatalf("wrong token: %d", c)
	}
	// the feed listener serves the feed and nothing else
	if resp, err := http.Get(ts.URL + "/api/ui/alerts"); err != nil || resp.StatusCode != 404 {
		t.Fatalf("dashboard reachable over the federation listener: %v", resp.StatusCode)
	}
	c, raw := get(made.Token)
	if c != 200 {
		t.Fatalf("feed: %d %s", c, raw)
	}
	var env feedEnvelope
	json.Unmarshal(raw, &env)
	payload, _ := base64.StdEncoding.DecodeString(env.Payload)
	for _, never := range []string{"10.0.0.5", "203.0.113.50", "198.51.100.77", "198.18.0.7", "192.0.2.99", "198.51.100.13", "198.51.100.12",
		"joey", "zypo", "deploy", "STRATO", "alpha", "a1", "secret-admin-path", "zgrab"} {
		if bytes.Contains(payload, []byte(never)) {
			t.Errorf("feed names %q: %s", never, payload)
		}
	}
	for _, want := range []string{"198.51.100.10", "198.51.100.11", `"root"`, `"net-a"`} {
		if !bytes.Contains(payload, []byte(want)) {
			t.Errorf("feed lacks %s: %s", want, payload)
		}
	}

	var cfg struct {
		Fingerprint string `json:"fingerprint"`
	}
	getJSON(t, func(w http.ResponseWriter, r *http.Request) { a.handleSourcesConfig(w, r, admin) }, "/", admin, &cfg)
	if len(normFingerprint(cfg.Fingerprint)) != 32 {
		t.Fatalf("fingerprint %q", cfg.Fingerprint)
	}

	// B fetches A
	b := forensicServer(t)
	appendAt(t, b, "a2", time.Now().UTC().Add(-10*time.Minute), "ssh.failed", map[string]any{"ip": "198.51.100.10", "count": float64(3), "users": anyList("root")})
	b.startAttacks()
	waitAttacks(t, b)
	src := sourceReq{Name: "Kumpel", URL: ts.URL + "/api/federation/v1/feed", Token: made.Token, Fingerprint: cfg.Fingerprint,
		Trust: "medium", TTLDays: 30}
	var saved struct {
		Source sourceView `json:"source"`
	}
	if c := postSess(t, b.handleSourceSave, "/", src, admin, &saved); c != 200 {
		t.Fatalf("source %d", c)
	}
	if err := b.pullSource(saved.Source.ID); err != nil {
		t.Fatal(err)
	}
	if ids := b.sources.lookup("198.51.100.10"); len(ids) != 1 {
		t.Fatalf("lookup: %v", ids)
	}
	b.mu.Lock()
	if x := b.state.Sources[0]; x.Network != "net-a" || x.Entries != 2 || x.LastErr != "" {
		t.Fatalf("source state: %+v", x)
	}
	b.mu.Unlock()
	if _, err := os.Stat(filepath.Join(b.cfg.DataDir, "sources", saved.Source.ID+".json")); err != nil {
		t.Fatal("entries not saved")
	}

	login := &Record{Agent: "a2", Event: proto.Event{Type: "ssh.login", TS: time.Now(), Data: map[string]any{"ip": "198.51.100.10", "user": "root", "method": "publickey"}}}
	hasRule := func(fs []finding, rule string) bool {
		for _, f := range fs {
			if f.Rule == rule {
				return true
			}
		}
		return false
	}
	b.mu.Lock()
	b.state.Sources[0].Enabled = true // saved disabled above, so no background fetch races the one here
	fs := b.evaluate(b.state.Agents["a2"], login)
	b.state.Sources[0].Trust = "low"
	fsLow := b.evaluate(b.state.Agents["a2"], login)
	b.state.Sources[0].Trust = "medium"
	b.mu.Unlock()
	if !hasRule(fs, "source.login") {
		t.Fatal("login from a reported address not flagged")
	}
	if hasRule(fsLow, "source.login") {
		t.Fatal("a low trust source must only feed the analytics")
	}
	conn := &Record{Agent: "a2", Event: proto.Event{Type: "net.connection", TS: time.Now(), Data: map[string]any{"remote_ip": "198.51.100.10", "remote_port": float64(443), "process": "curl"}}}
	b.mu.Lock()
	fsConn := b.evaluate(b.state.Agents["a2"], conn)
	b.mu.Unlock()
	if !hasRule(fsConn, "source.outbound") {
		t.Fatal("connection to a reported address not flagged")
	}

	st := b.sourcesStats(7, time.Now().UTC())
	if st.Us != 1 || len(st.Sources) != 1 || st.Sources[0].Overlap != 1 || st.Sources[0].Active != 2 || st.Matrix[0][1] != 1 {
		t.Fatalf("stats: %+v", st)
	}
	if st.Sources[0].LeadH == nil || *st.Sources[0].LeadH <= 0 || st.Top[0].IP != "198.51.100.10" || st.Top[0].FirstBy != saved.Source.ID {
		t.Fatalf("A saw 198.51.100.10 first: %+v %+v", st.Sources[0], st.Top)
	}

	// a pinned fingerprint that does not match refuses the feed
	b.mu.Lock()
	b.state.Sources[0].Fingerprint = strings.Repeat("ab", 16)
	b.mu.Unlock()
	if err := b.pullSource(saved.Source.ID); err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("wrong fingerprint: %v", err)
	}
	if ids := b.sources.lookup("198.51.100.10"); len(ids) != 1 {
		t.Fatal("a failed fetch must keep the entries it had")
	}

	// a rotated token locks the old one out
	var rot struct {
		Token string `json:"token"`
	}
	postSess(t, a.handleShareAction, "/", nil, admin, &rot, "id", made.Share.ID, "action", "rotate")
	if c, _ := get(made.Token); c != 401 {
		t.Fatal("old token still works")
	}
	if c, _ := get(rot.Token); c != 200 {
		t.Fatal("new token refused")
	}
}

func TestOpenFeedRefusesTampering(t *testing.T) {
	s := &Server{cfg: &Config{DataDir: t.TempDir()}}
	k, err := s.feedKey()
	if err != nil {
		t.Fatal(err)
	}
	fp := fingerprint(k.Public().(ed25519.PublicKey))
	p := feedPayload{V: 1, Network: "x", Entries: []feedEntry{{IP: "198.51.100.1", Cats: []string{"ssh"}}}}
	raw, _ := signFeed(k, p)
	if _, err := openFeed(raw, fp); err != nil {
		t.Fatal(err)
	}
	var env feedEnvelope
	json.Unmarshal(raw, &env)
	body, _ := base64.StdEncoding.DecodeString(env.Payload)
	env.Payload = base64.StdEncoding.EncodeToString(bytes.Replace(body, []byte("198.51.100.1"), []byte("198.51.100.2"), 1))
	bad, _ := json.Marshal(env)
	if _, err := openFeed(bad, fp); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("changed payload: %v", err)
	}
	// a signature over the bare body (no context) is not a feed signature
	json.Unmarshal(raw, &env)
	env.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(k, body))
	bad, _ = json.Marshal(env)
	if _, err := openFeed(bad, fp); err == nil {
		t.Fatal("signature without the feed context accepted")
	}
	json.Unmarshal(raw, &env)
	env.V = 2
	bad, _ = json.Marshal(env)
	if _, err := openFeed(bad, fp); err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("envelope version 2: %v", err)
	}
	p.V = 2
	raw2, _ := signFeed(k, p)
	if _, err := openFeed(raw2, fp); err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("version 2: %v", err)
	}
}

func TestMergeFeedIsBounded(t *testing.T) {
	now := time.Now().UTC()
	future, ancient := now.Add(48*time.Hour), now.AddDate(-5, 0, 0)
	never, _ := parsePrefixes([]string{"203.0.113.0/24"})
	p := &feedPayload{V: 1, Entries: []feedEntry{
		{IP: "198.51.100.1", Cats: []string{"ssh", "ssh", "bogus"}, N: -5, First: &ancient, Last: &future, Users: []string{strings.Repeat("u", 500)}},
		{IP: "10.1.2.3", Cats: []string{"ssh"}},
		{IP: "100.64.1.1", Cats: []string{"ssh"}},
		{IP: "203.0.113.9", Cats: []string{"ssh"}},
		{IP: "198.51.100.2", Cats: []string{"bogus"}},
		{IP: "not an ip", Cats: []string{"ssh"}},
	}}
	f := &srcFile{ID: "x"}
	mergeFeed(f, p, never, 30, now)
	if len(f.Entries) != 1 {
		t.Fatalf("entries: %v", f.Entries)
	}
	e := f.Entries["198.51.100.1"]
	if len(e.Cats) != 1 || e.N != 0 || e.Last.After(now) || now.Sub(e.First) > sourceMaxTTL*24*time.Hour+time.Second || len(e.Users[0]) != 64 {
		t.Fatalf("not normalised: %+v", e)
	}
	// entries no fetch has had for ttl days go
	e.Got = now.AddDate(0, 0, -31)
	mergeFeed(f, &feedPayload{V: 1}, never, 30, now)
	if len(f.Entries) != 0 {
		t.Fatal("expired entry kept")
	}
}

func TestPlaybooksNeverActOnSources(t *testing.T) {
	if err := validatePlaybook(Playbook{Name: "x", Rules: []string{"source.login"}, Actions: []string{"block_ip"}}); err == nil {
		t.Fatal("playbook on source.* accepted")
	}
	pb := Playbook{Name: "all", Rules: []string{"*"}, MinSeverity: "low", Actions: []string{"block_ip"}}
	if pb.matches(&Alert{Rule: "source.login", Severity: "high"}, "h") {
		t.Fatal("\"*\" must not reach source.* alerts")
	}
	if !pb.matches(&Alert{Rule: "ssh.attacker_login", Severity: "high"}, "h") {
		t.Fatal("test playbook broken")
	}
}
