// Package server is the central node: it receives signed agent batches,
// stores them in a hash-chained log, evaluates rules, raises alerts and
// serves the dashboard.
package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

var Version = "dev"

type Server struct {
	cfg   *Config
	store *Store
	key   ed25519.PrivateKey

	mu    sync.Mutex // guards state
	state *State

	smu      sync.Mutex
	sessions map[string]*session
	limit    *limiter
	forged   *limiter

	custom customState // threshold counters of custom rules, guarded by mu

	users      userCache
	challenges challenges
	intel      intelSet
	geodb      geoState
	attacks    attackRollup
	vdb        vulnDB
	hashes     hashSet
	fwd        []*forwarder

	playbookRuns map[string][]time.Time // guarded by mu
	yara         yaraSet
	pkgs         map[string]*agentPackages // latest package list per agent, guarded by mu
	nh           notifierHealth
	incNotes     map[string]*incidentNote // guarded by mu
	groupDelay   time.Duration            // tests only; see groupWindow

	beatWarned string // last reason the heartbeat was withheld, loop goroutine only
}

func New(cfg *Config) (*Server, error) {
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, err
	}
	key, err := loadOrCreateKey(filepath.Join(cfg.DataDir, "server.key"))
	if err != nil {
		return nil, err
	}
	st, err := LoadState(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	store, err := OpenStore(filepath.Join(cfg.DataDir, "events"), cfg.RecentEvents)
	if err != nil {
		return nil, err
	}
	return &Server{
		cfg: cfg, store: store, key: key, state: st,
		sessions: map[string]*session{},
		limit:    &limiter{fails: map[string][]time.Time{}},
		forged:   &limiter{fails: map[string][]time.Time{}},
	}, nil
}

func loadOrCreateKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err == nil {
		if len(raw) != ed25519.SeedSize {
			return nil, errors.New("server.key is damaged")
		}
		return ed25519.NewKeyFromSeed(raw), nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, priv.Seed(), 0o600); err != nil {
		return nil, err
	}
	return priv, nil
}

// State access for the command line (user management) before Run.
func (s *Server) WithState(fn func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := fn(s.state); err != nil {
		return err
	}
	return s.state.Save(s.cfg.DataDir)
}

func (s *Server) saveState() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saveLocked()
}

func (s *Server) saveLocked() {
	if err := s.state.Save(s.cfg.DataDir); err != nil {
		log.Printf("state: %v", err)
	}
}

func (s *Server) Run(ctx context.Context) error {
	// The packaged unit caps memory at 256 MB. Parsing a release's
	// vulnerability feed (vuln_lookup) allocates a lot of short-lived
	// garbage; a soft limit makes the collector run before the cap is near.
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(160 << 20)
	}
	if !s.store.ChainOK {
		s.chainBroken(s.store.ChainError)
	}
	s.record("server", "", "", proto.NewEvent("server.started", map[string]any{"version": Version}))
	go s.refreshIntel()
	go s.refreshGeo()
	s.loadPackages()
	go s.refreshVulns()
	s.loadYara()
	go s.refreshHashes()
	LoadSigma(s.cfg.SigmaDir)
	s.startForwarders()
	s.startAttacks()
	for _, pb := range s.cfg.Playbooks {
		if err := validatePlaybook(pb); err != nil {
			log.Printf("playbook: %v (not used)", err)
		} else {
			log.Printf("playbook %s: %v on %v", pb.Name, pb.Actions, pb.Rules)
		}
	}
	if s.cfg.RulesDir != "" {
		n, errs := LoadCustomRules(s.cfg.RulesDir)
		log.Printf("custom rules: %d loaded from %s", n, s.cfg.RulesDir)
		for _, e := range errs {
			log.Printf("custom rules: %s", e)
		}
	}

	ui := s.uiHandler()
	agentMux := http.NewServeMux()
	agentMux.HandleFunc("POST /api/agent/enroll", s.handleEnroll)
	agentMux.HandleFunc("POST /api/agent/events", s.handleEvents)

	var servers []*http.Server
	if s.cfg.AgentListen == "" {
		mux := http.NewServeMux()
		mux.Handle("/api/agent/", agentMux)
		mux.Handle("/", ui)
		servers = append(servers, newHTTPServer(s.cfg.Listen, mux))
	} else {
		servers = append(servers, newHTTPServer(s.cfg.Listen, ui), newHTTPServer(s.cfg.AgentListen, agentMux))
	}

	errc := make(chan error, len(servers))
	for _, hs := range servers {
		log.Printf("listening on %s", hs.Addr)
		go func(hs *http.Server) { errc <- hs.ListenAndServe() }(hs)
	}
	go s.loop(ctx)

	select {
	case <-ctx.Done():
	case err := <-errc:
		return err
	}
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, hs := range servers {
		hs.Shutdown(sctx)
	}
	s.record("server", "", "", proto.NewEvent("server.stopping", nil))
	s.saveState()
	return nil
}

func newHTTPServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr: addr, Handler: h,
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 120 * time.Second,
		MaxHeaderBytes: 64 << 10,
	}
}

func (s *Server) loop(ctx context.Context) {
	dead := time.NewTicker(15 * time.Second)
	beat := time.NewTicker(time.Minute)
	hourly := time.NewTicker(time.Hour)
	defer dead.Stop()
	defer beat.Stop()
	defer hourly.Stop()
	s.daily()
	for {
		select {
		case <-ctx.Done():
			return
		case <-dead.C:
			s.checkDeadman()
			s.mu.Lock()
			finished, started := s.checkSelfTests(), s.scheduleSelfTests()
			if finished || started {
				s.saveLocked()
			}
			s.mu.Unlock()
		case <-beat.C:
			s.expireSuppressions()
			s.checkSummary()
			if s.cfg.HeartbeatURL != "" {
				s.heartbeat()
			}
		case <-hourly.C:
			s.daily()
			go s.refreshIntel()
			go s.refreshGeo()
			go s.attacks.persist()
			go s.refreshVulns()
			go s.refreshHashes()
			s.loadYara()
			LoadSigma(s.cfg.SigmaDir)
		}
	}
}

// heartbeat pings the outside watchdog only while the server is healthy.
// Withholding the ping is the one signal every dead man's switch service
// understands, so a hung server, a full disk or a broken chain all end in
// the same outside alarm.
func (s *Server) heartbeat() {
	reason := s.unhealthy()
	if reason != "" {
		if reason != s.beatWarned {
			log.Printf("heartbeat withheld: %s", reason)
		}
		s.beatWarned = reason
		return
	}
	s.beatWarned = ""
	go func() {
		c := &http.Client{Timeout: 10 * time.Second}
		res, err := c.Get(s.cfg.HeartbeatURL)
		if err != nil {
			log.Printf("heartbeat: %v", redact(err))
			return
		}
		res.Body.Close()
		if res.StatusCode >= 300 {
			log.Printf("heartbeat: status %s", res.Status)
		}
	}()
}

// unhealthy names the first problem that should silence the heartbeat.
func (s *Server) unhealthy() string {
	if ok, msg := s.store.Health(); !ok {
		return msg
	}
	locked := make(chan struct{})
	go func() {
		s.mu.Lock()
		s.mu.Unlock()
		close(locked)
	}()
	select {
	case <-locked:
	case <-time.After(10 * time.Second):
		return "server state is locked for more than 10 seconds"
	}
	probe := filepath.Join(s.cfg.DataDir, ".health")
	if err := os.WriteFile(probe, []byte(time.Now().UTC().Format(time.RFC3339)), 0o600); err != nil {
		return "data directory not writable: " + err.Error()
	}
	return ""
}

// daily runs housekeeping that is due at most once a day; it is called
// hourly and checks its own clock.
func (s *Server) daily() {
	s.mu.Lock()
	for k, t := range s.state.Tokens {
		if time.Now().After(t.Expires) {
			delete(s.state.Tokens, k)
		}
	}
	due := time.Since(s.state.LastAnchor) >= 24*time.Hour
	if due {
		s.state.LastAnchor = time.Now().UTC()
	}
	s.saveLocked()
	s.mu.Unlock()
	if !due {
		return
	}
	if err := s.store.Prune(s.cfg.RetentionDays); err != nil {
		log.Printf("prune: %v", err)
	}
	if ok, msg := s.store.Verify(); !ok {
		s.chainBroken(msg)
	}
	if s.cfg.AnchorDaily {
		seq, head := s.store.Head()
		s.notify(message{Severity: "info", Text: fmt.Sprintf("vigil chain anchor %s\nseq %d\nsha256 %s", time.Now().UTC().Format("2006-01-02"), seq, head)}, true)
	}
}

func (s *Server) chainBroken(msg string) {
	s.mu.Lock()
	fresh := s.raise([]finding{{Rule: "chain.broken", Key: "chain.broken|" + msg, Params: map[string]string{"error": msg}}}, "", 0)
	s.saveLocked()
	s.notifyAlerts(fresh)
	s.mu.Unlock()
}

func (s *Server) checkDeadman() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	changed := false
	for _, a := range s.state.Agents {
		if a.Silent || a.LastSeen.IsZero() || now.Sub(a.LastSeen) < s.cfg.deadman() || now.Before(a.MaintenanceUntil) {
			continue
		}
		a.Silent = true
		changed = true
		fresh := s.raise([]finding{{Rule: "agent.silent", Key: "agent.silent|" + a.ID + "|", Params: map[string]string{"host": a.Name}}}, a.ID, 0)
		s.correlate(fresh)
		s.notifyAlerts(fresh)
	}
	if changed {
		s.saveLocked()
	}
}

// notifyAlerts expects s.mu held (it reads agent names).
func (s *Server) notifyAlerts(fresh []*Alert) {
	s.forwardAlerts(fresh)
	for _, al := range fresh {
		s.notifyGrouped(al)
	}
}

// record appends a server- or admin-originated event.
func (s *Server) record(source, actor, agentID string, ev proto.Event) {
	if err := s.store.Append(&Record{Source: source, Actor: actor, Agent: agentID, Event: ev}); err != nil {
		log.Printf("store: %v", err)
	}
}

func (s *Server) audit(actor string, typ string, data map[string]any) {
	s.record("admin", actor, "", proto.NewEvent(typ, data))
}

func readBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	return io.ReadAll(http.MaxBytesReader(w, r.Body, proto.MaxBodyBytes))
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	if s.limit.blocked("enroll:" + ip) {
		http.Error(w, errLimited.Error(), http.StatusTooManyRequests)
		return
	}
	body, err := readBody(w, r)
	if err != nil {
		http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
		return
	}
	var req proto.EnrollRequest
	if json.Unmarshal(body, &req) != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if _, err := proto.DecodePublicKey(req.PublicKey); err != nil {
		http.Error(w, "bad public key", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	tok := s.state.Tokens[sha(req.Token)]
	if tok == nil || time.Now().After(tok.Expires) {
		s.mu.Unlock()
		s.limit.fail("enroll:" + ip)
		s.record("server", "", "", proto.NewEvent("agent.enroll_refused", map[string]any{"ip": ip, "hostname": clip(req.Hostname, 100)}))
		http.Error(w, "invalid or expired token", http.StatusForbidden)
		return
	}
	delete(s.state.Tokens, tok.Hash)
	a := &AgentRec{
		ID: newID(8), Name: clip(req.Hostname, 100), Hostname: clip(req.Hostname, 100),
		PublicKey: req.PublicKey, Version: clip(req.Version, 40), Enrolled: time.Now().UTC(),
		LastIP: ip, Baseline: map[string]bool{},
	}
	if a.Name == "" {
		a.Name = a.ID
	}
	s.state.Agents[a.ID] = a
	s.saveLocked()
	s.mu.Unlock()

	s.record("server", tok.By, a.ID, proto.NewEvent("agent.enrolled", map[string]any{"hostname": a.Hostname, "ip": ip}))
	writeJSON(w, proto.EnrollResponse{AgentID: a.ID, ServerKey: proto.EncodeKey(s.key.Public().(ed25519.PublicKey))})
}

var eventType = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9_]+){1,3}$`)

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	body, err := readBody(w, r)
	if err != nil {
		http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
		return
	}
	var b proto.Batch
	if json.Unmarshal(body, &b) != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	a := s.state.Agents[b.AgentID]
	var pub ed25519.PublicKey
	if a != nil {
		pub, _ = proto.DecodePublicKey(a.PublicKey)
	}
	s.mu.Unlock()
	if a == nil {
		http.Error(w, "unknown agent", http.StatusUnauthorized)
		return
	}
	if err := proto.Verify(pub, body, r.Header.Get(proto.SigHeader)); err != nil {
		s.forgedRequest(a, ip, "signature")
		http.Error(w, "bad signature", http.StatusUnauthorized)
		return
	}

	s.mu.Lock()
	if b.Seq <= a.LastSeq {
		s.mu.Unlock()
		s.forgedRequest(a, ip, "replay")
		http.Error(w, "replayed batch", http.StatusConflict)
		return
	}
	a.LastSeq = b.Seq
	a.prevSeen = a.LastSeen
	a.LastSeen = time.Now().UTC()
	a.LastIP = ip
	a.AckedVersion = b.ConfigVersion
	back := a.Silent
	a.Silent = false
	s.mu.Unlock()

	recs := make([]*Record, 0, len(b.Events)+1)
	if back {
		recs = append(recs, &Record{Agent: a.ID, Source: "server", Event: proto.NewEvent("agent.back", nil)})
	}
	for _, ev := range b.Events {
		if !eventType.MatchString(ev.Type) {
			continue
		}
		if ev.TS.IsZero() {
			ev.TS = time.Now().UTC()
		}
		recs = append(recs, &Record{Agent: a.ID, Source: "agent", Event: ev})
	}
	if len(recs) > 0 {
		if err := s.store.Append(recs...); err != nil {
			log.Printf("store: %v", err)
			http.Error(w, "store failed", http.StatusInternalServerError)
			return
		}
	}

	s.mu.Lock()
	if back {
		s.resolve("agent.silent|"+a.ID+"|", "system")
	}
	var fresh []*Alert
	for _, rec := range recs {
		if rec.Source != "agent" {
			continue
		}
		fs := s.selfTestFindings(a, rec, append(append(s.evaluate(a, rec), s.evaluateCustom(a, rec)...), s.evaluateSigma(a, rec)...))
		for _, f := range s.malwareFindings(rec.Event) {
			f.Key = "malware.known|" + a.ID + "|" + f.Params["sha256"]
			f.Params["host"] = a.Name
			fs = append(fs, f)
		}
		fresh = append(fresh, s.raise(fs, a.ID, rec.Seq)...)
	}
	s.correlate(fresh)
	s.autoSnapshots(fresh)
	runs := s.runPlaybooks(fresh)
	resp := proto.BatchResponse{ConfigVersion: a.ConfigVersion}
	if a.ConfigVersion > b.ConfigVersion {
		resp.Config, resp.ConfigSig = s.agentConfig(a)
	}
	s.saveLocked()
	s.notifyAlerts(fresh)
	for _, r := range runs {
		s.notify(message{Severity: "high", Text: "vigil playbook: " + r}, true)
	}
	s.mu.Unlock()
	writeJSON(w, resp)
}

// forgedRequest is rate limited per source so a flood of forged requests
// does not turn into a flood of alerts.
func (s *Server) forgedRequest(a *AgentRec, ip, reason string) {
	s.record("server", "", a.ID, proto.NewEvent("agent.forged", map[string]any{"ip": ip, "reason": reason}))
	if s.forged.blocked("forged:"+ip) && reason != "replay" {
		return
	}
	s.forged.fail("forged:" + ip)
	s.mu.Lock()
	fresh := s.raise([]finding{{Rule: "agent.forged", Key: "agent.forged|" + a.ID + "|" + ip, Params: map[string]string{"agent": a.Name, "ip": ip}}}, a.ID, 0)
	s.correlate(fresh)
	s.saveLocked()
	s.notifyAlerts(fresh)
	s.mu.Unlock()
}

// agentConfig builds and signs the canary set for one agent. Caller holds s.mu.
func (s *Server) agentConfig(a *AgentRec) (json.RawMessage, string) {
	cfg := proto.AgentConfig{AgentID: a.ID, Version: a.ConfigVersion, Canaries: []proto.Canary{}, Actions: s.pendingActions(a.ID), SelfTest: s.pendingSelfTest(a.ID), Snapshots: s.pendingSnapshots(a.ID), Yara: s.yaraConfig()}
	for _, c := range s.state.Canaries {
		if c.AgentID == a.ID {
			cfg.Canaries = append(cfg.Canaries, proto.Canary{ID: c.ID, Type: c.Type, Path: c.Path, Params: c.Params})
		}
	}
	raw, _ := json.Marshal(cfg)
	return raw, proto.Sign(s.key, raw)
}

// resolve closes open alerts whose key starts with prefix. Caller holds s.mu.
func (s *Server) resolve(prefix, by string) {
	for _, al := range s.state.Alerts {
		if al.Status == "open" && strings.HasPrefix(al.Key, prefix) {
			al.Status, al.By, al.Updated = "resolved", by, time.Now().UTC()
		}
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(v)
}

func clip(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > n {
		return s[:n]
	}
	return s
}
