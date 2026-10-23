package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Sources and shares: threat intel exchanged with allied networks.
//
// A share is what this network hands one partner: its own token, the attack
// categories, how much detail and how many days. The partner fetches it from
// federation.listen (a VPN address, never the dashboard), signed with a key
// that is used for nothing else, so the partner can pin its fingerprint.
// Nothing is ever pushed to a partner, and a partner cannot change anything
// here: the federation listener serves the feed and nothing else.
//
// A source is a feed this network fetches. Its entries are untrusted: they
// are normalised, bounded, and never reach the block lists of threat_intel
// or a playbook. They raise only source.* alerts, and the analytics compare
// them with what the agents see.
//
// What may leave is decided by the type: a feed entry has fields for an
// address, categories, counts, times and tried user names, and nothing
// else. Host names, agent IDs, paths, processes and alert texts cannot be
// shared, whatever a share says.

const (
	feedVersion    = 1
	feedSigContext = "vigil-feed-v1\x00"
	feedMaxEntries = 20000
	feedMaxBytes   = 16 << 20
	sourceMaxIPs   = 50000
	sourceMaxTTL   = 90
	sourceUsersMax = 20
	sourcePullLoop = 15 * time.Minute
)

// Categories a share can carry, from the attack rollup.
var shareCats = []string{"ssh", "web", "web_login", "shell"}

func validCat(c string) bool {
	for _, x := range shareCats {
		if x == c {
			return true
		}
	}
	return false
}

type ShareRec struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Hash    string    `json:"hash"` // of the partner's token
	Cats    []string  `json:"cats"`
	Users   bool      `json:"users,omitempty"`  // tried SSH user names
	Counts  bool      `json:"counts,omitempty"` // attempts and first/last seen; else addresses only
	Days    int       `json:"days"`
	MinHits int       `json:"min_hits,omitempty"`
	Exclude []string  `json:"exclude,omitempty"` // the partner's own networks
	Enabled bool      `json:"enabled"`
	Created time.Time `json:"created"`
	By      string    `json:"by"`
	// Last fetch by the partner.
	Pulled   time.Time `json:"pulled,omitempty"`
	PulledIP string    `json:"pulled_ip,omitempty"`
	Pulls    int       `json:"pulls,omitempty"`
	Sent     int       `json:"sent,omitempty"` // entries in the last fetch
}

type SourceRec struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"` // vigil
	URL  string `json:"url"`
	// Token is the partner's token for us; it never leaves the server.
	Token       string    `json:"token"`
	Fingerprint string    `json:"fingerprint"`
	Trust       string    `json:"trust"` // low | medium | high
	TTLDays     int       `json:"ttl_days"`
	Enabled     bool      `json:"enabled"`
	Created     time.Time `json:"created"`
	By          string    `json:"by"`
	LastTry     time.Time `json:"last_try,omitempty"`
	LastOK      time.Time `json:"last_ok,omitempty"`
	LastErr     string    `json:"last_err,omitempty"`
	Network     string    `json:"network,omitempty"` // name the partner gives itself
	Entries     int       `json:"entries,omitempty"`
}

// feedEntry is everything that can leave about one address.
type feedEntry struct {
	IP    string     `json:"ip"`
	Cats  []string   `json:"c"`
	N     int        `json:"n,omitempty"`
	First *time.Time `json:"f,omitempty"`
	Last  *time.Time `json:"l,omitempty"`
	Users []string   `json:"u,omitempty"`
}

type feedPayload struct {
	V         int         `json:"v"`
	Network   string      `json:"network"`
	Generated time.Time   `json:"generated"`
	Days      int         `json:"days"`
	Entries   []feedEntry `json:"entries"`
}

// feedEnvelope carries the payload as bytes, so the signature covers
// exactly what was sent.
type feedEnvelope struct {
	V       int    `json:"v"`
	Key     string `json:"key"`
	Payload string `json:"payload"`
	Sig     string `json:"sig"`
}

func fingerprint(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	s := hex.EncodeToString(h[:16])
	var parts []string
	for i := 0; i < len(s); i += 4 {
		parts = append(parts, s[i:i+4])
	}
	return strings.Join(parts, ":")
}

func normFingerprint(s string) string {
	return strings.ToLower(strings.NewReplacer(":", "", " ", "", "-", "").Replace(strings.TrimSpace(s)))
}

func (s *Server) feedKey() (ed25519.PrivateKey, error) {
	s.fmu.Lock()
	defer s.fmu.Unlock()
	if s.fkey == nil {
		k, err := loadOrCreateKey(filepath.Join(s.cfg.DataDir, "federation.key"))
		if err != nil {
			return nil, err
		}
		s.fkey = k
	}
	return s.fkey, nil
}

// shareable says whether an address may be named to anyone: public
// unicast only, never one of our hosts or a never-list network.
func shareable(a netip.Addr, never []netip.Prefix) bool {
	a = a.Unmap()
	if !a.IsValid() || !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsMulticast() {
		return false
	}
	if cgnat.Contains(a) {
		return false
	}
	for _, p := range never {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

func parsePrefixes(list []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, v := range list {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if p, err := netip.ParsePrefix(v); err == nil {
			out = append(out, p.Masked())
		} else if a, err := netip.ParseAddr(v); err == nil {
			out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
		} else {
			return nil, fmt.Errorf("not an address or network: %q", clip(v, 64))
		}
	}
	return out, nil
}

// neverList is what is never named in a feed nor flagged from a source:
// the configured networks, the addresses our agents connect from and
// listen on (behind a VPN the first is internal, the second has the public
// one), and every address that ever logged in, whenever that was.
func (s *Server) neverList() []netip.Prefix {
	var out []netip.Prefix
	if s.cfg.Federation != nil {
		out, _ = parsePrefixes(s.cfg.Federation.Never)
	}
	add := func(v string) {
		if ip, err := netip.ParseAddr(v); err == nil {
			ip = ip.Unmap()
			out = append(out, netip.PrefixFrom(ip, ip.BitLen()))
		}
	}
	s.mu.Lock()
	for _, a := range s.state.Agents {
		add(a.LastIP)
		for _, p := range a.Ports {
			add(str(p, "addr"))
		}
	}
	for k := range s.state.KnownLogins {
		if i := strings.LastIndexByte(k, '|'); i >= 0 {
			add(k[i+1:])
		}
	}
	s.mu.Unlock()
	return out
}

func (s *Server) networkName() string {
	if s.cfg.Federation != nil && s.cfg.Federation.Name != "" {
		return s.cfg.Federation.Name
	}
	if s.cfg.Brand != nil && s.cfg.Brand.Name != "" {
		return s.cfg.Brand.Name
	}
	return "vigil"
}

// buildFeed projects the attack rollup onto what a share allows. The
// preview in the dashboard uses the same function.
func (s *Server) buildFeed(sh *ShareRec, now time.Time) feedPayload {
	days := sh.Days
	if days < 1 || days > attackDaysMax {
		days = 7
	}
	never := s.neverList()
	excl, _ := parsePrefixes(sh.Exclude)
	never = append(never, excl...)
	own := s.ownTokens()
	cats := map[string]bool{}
	for _, c := range sh.Cats {
		cats[c] = true
	}
	r := &s.attacks
	r.mu.Lock()
	merged, _, _, _, _, _ := r.attackWindow(days, now.UTC())
	r.mu.Unlock()

	// Account names that exist on a host are never named, whichever
	// address tried them.
	real := map[string]bool{}
	for _, x := range merged {
		for _, u := range x.Existing {
			real[u] = true
		}
		for _, u := range x.LoginUsers {
			real[u] = true
		}
	}
	ownUser := func(u string) bool {
		if real[u] {
			return true
		}
		lu := strings.ToLower(u)
		for _, t := range own {
			if strings.Contains(lu, t) {
				return true
			}
		}
		return false
	}

	var out []feedEntry
	for ip, x := range merged {
		// Any successful login marks an address as ours (or as one that
		// got in, which is ours to handle, not to share).
		if x.own() || x.Logins > 0 {
			continue
		}
		a, err := netip.ParseAddr(ip)
		if err != nil || !shareable(a, never) {
			continue
		}
		e := feedEntry{IP: a.Unmap().String()}
		n := 0
		if cats["ssh"] && x.SSH > 0 {
			e.Cats = append(e.Cats, "ssh")
			n += x.SSH
		}
		if cats["web"] && x.Web > 0 {
			e.Cats = append(e.Cats, "web")
			n += x.Web
		}
		if cats["web_login"] && x.WebLogins > 0 {
			e.Cats = append(e.Cats, "web_login")
			if !cats["web"] {
				n += x.WebLogins
			}
		}
		if cats["shell"] && x.Shells > 0 {
			e.Cats = append(e.Cats, "shell")
			if !cats["web"] {
				n += x.Shells
			}
		}
		if len(e.Cats) == 0 || n < sh.MinHits {
			continue
		}
		if sh.Counts {
			e.N = n
			f, l := x.First.UTC(), x.Last.UTC()
			e.First, e.Last = &f, &l
		}
		if sh.Users && cats["ssh"] && x.SSH > 0 {
			for _, u := range x.Users {
				if !ownUser(u) && len(e.Users) < sourceUsersMax {
					e.Users = append(e.Users, clip(u, 64))
				}
			}
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].N != out[j].N {
			return out[i].N > out[j].N
		}
		return out[i].IP < out[j].IP
	})
	if len(out) > feedMaxEntries {
		out = out[:feedMaxEntries]
	}
	return feedPayload{V: feedVersion, Network: s.networkName(), Generated: now.UTC(), Days: days, Entries: out}
}

func signFeed(key ed25519.PrivateKey, p feedPayload) ([]byte, error) {
	body, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(key, append([]byte(feedSigContext), body...))
	return json.Marshal(feedEnvelope{V: feedVersion, Key: base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)),
		Payload: base64.StdEncoding.EncodeToString(body), Sig: base64.StdEncoding.EncodeToString(sig)})
}

// openFeed checks the envelope against the pinned fingerprint and returns
// the payload.
func openFeed(raw []byte, pinned string) (*feedPayload, error) {
	var env feedEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, errors.New("not a vigil feed")
	}
	if env.V != feedVersion {
		return nil, fmt.Errorf("feed version %d is not supported", env.V)
	}
	pub, err := base64.StdEncoding.DecodeString(env.Key)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("feed key is damaged")
	}
	if got := fingerprint(pub); normFingerprint(got) != normFingerprint(pinned) {
		return nil, fmt.Errorf("feed signed by %s, not by the pinned fingerprint", got)
	}
	body, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, errors.New("feed payload is damaged")
	}
	sig, err := base64.StdEncoding.DecodeString(env.Sig)
	if err != nil || !ed25519.Verify(pub, append([]byte(feedSigContext), body...), sig) {
		return nil, errors.New("feed signature does not match")
	}
	var p feedPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, errors.New("feed payload is not JSON")
	}
	if p.V != feedVersion {
		return nil, fmt.Errorf("feed version %d is not supported", p.V)
	}
	return &p, nil
}

// Federation listener: the feed and nothing else.

func (s *Server) federationHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/federation/v1/feed", s.handleFeed)
	return mux
}

func (s *Server) handleFeed(w http.ResponseWriter, r *http.Request) {
	// No proxy stands in front of this listener: X-Forwarded-For would be
	// the partner's word, whatever trust_proxy says for the dashboard.
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	if s.limit.blocked("feed:" + ip) {
		http.Error(w, errLimited.Error(), http.StatusTooManyRequests)
		return
	}
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	var sh *ShareRec
	if ok && tok != "" {
		h := sha(tok)
		s.mu.Lock()
		for _, x := range s.state.Shares {
			if x.Enabled && x.Hash == h {
				c := *x
				sh = &c
			}
		}
		s.mu.Unlock()
	}
	if sh == nil {
		s.limit.fail("feed:" + ip)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	key, kerr := s.feedKey()
	if kerr != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	p := s.buildFeed(sh, time.Now())
	body, err := signFeed(key, p)
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	s.mu.Lock()
	for _, x := range s.state.Shares {
		if x.ID == sh.ID {
			first := x.Pulled.IsZero()
			x.Pulled, x.PulledIP, x.Sent = time.Now().UTC(), clip(ip, 64), len(p.Entries)
			x.Pulls++
			if first {
				s.saveLocked()
			}
		}
	}
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(body)
}

// Incoming entries, per source in data_dir/sources/<id>.json.

type srcEntry struct {
	Cats  []string  `json:"c"`
	N     int       `json:"n,omitempty"`
	First time.Time `json:"f"` // as the source reports it
	Last  time.Time `json:"l"`
	Users []string  `json:"u,omitempty"`
	Seen  time.Time `json:"s"` // first fetch that had it
	Got   time.Time `json:"g"` // last fetch that had it
}

type srcFile struct {
	ID      string               `json:"id"`
	Entries map[string]*srcEntry `json:"entries"`
}

type sourceSet struct {
	mu    sync.RWMutex
	files map[string]*srcFile // by source ID
	index map[string][]string // address -> source IDs
	busy  map[string]bool     // pulls running
}

func (s *Server) sourcesDir() string { return filepath.Join(s.cfg.DataDir, "sources") }

func (s *Server) loadSources() {
	// s.mu before ss.mu, never inside it: evaluate holds s.mu and looks up
	s.mu.Lock()
	var ids []string
	for _, src := range s.state.Sources {
		ids = append(ids, src.ID)
	}
	s.mu.Unlock()
	ss := &s.sources
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.files = map[string]*srcFile{}
	for _, id := range ids {
		raw, err := os.ReadFile(filepath.Join(s.sourcesDir(), id+".json"))
		if err != nil {
			continue
		}
		var f srcFile
		if json.Unmarshal(raw, &f) == nil && f.Entries != nil {
			f.ID = id
			ss.files[id] = &f
		}
	}
	ss.reindexLocked()
}

func (ss *sourceSet) reindexLocked() {
	ss.index = map[string][]string{}
	for id, f := range ss.files {
		for ip := range f.Entries {
			ss.index[ip] = append(ss.index[ip], id)
		}
	}
}

// lookup returns the sources that list an address.
func (ss *sourceSet) lookup(ip string) []string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return nil
	}
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return append([]string(nil), ss.index[a.Unmap().String()]...)
}

func removeSourceFile(dir, id string) {
	os.Remove(filepath.Join(dir, id+".json"))
}

func (s *Server) saveSourceFile(f *srcFile) error {
	if err := os.MkdirAll(s.sourcesDir(), 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	p := filepath.Join(s.sourcesDir(), f.ID+".json")
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// mergeFeed normalises a fetched payload into the source's entries and
// drops what has not been in a fetch for ttl days.
func mergeFeed(f *srcFile, p *feedPayload, never []netip.Prefix, ttl int, now time.Time) {
	if f.Entries == nil {
		f.Entries = map[string]*srcEntry{}
	}
	for i, e := range p.Entries {
		if i >= feedMaxEntries {
			break
		}
		a, err := netip.ParseAddr(e.IP)
		if err != nil || !shareable(a, never) {
			continue
		}
		ip := a.Unmap().String()
		var cats []string
		for _, c := range e.Cats {
			if validCat(c) && !contains(cats, c) {
				cats = append(cats, c)
			}
		}
		if len(cats) == 0 {
			continue
		}
		x := f.Entries[ip]
		if x == nil {
			if len(f.Entries) >= sourceMaxIPs {
				continue
			}
			x = &srcEntry{Seen: now}
			f.Entries[ip] = x
		}
		x.Cats, x.Got = cats, now
		x.N = max(0, min(e.N, 1<<30))
		x.First, x.Last = clampTime(e.First, now), clampTime(e.Last, now)
		if x.First.IsZero() {
			x.First = x.Seen
		}
		if x.Last.Before(x.First) {
			x.Last = x.First
		}
		x.Users = nil // the entry may be a copy that shares the old slice
		for _, u := range e.Users {
			if u = clip(u, 64); u != "" && len(x.Users) < sourceUsersMax {
				x.Users = append(x.Users, u)
			}
		}
	}
	for ip, x := range f.Entries {
		if now.Sub(x.Got) > time.Duration(ttl)*24*time.Hour {
			delete(f.Entries, ip)
		}
	}
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// clampTime keeps a reported time out of the future and out of the far past.
func clampTime(t *time.Time, now time.Time) time.Time {
	if t == nil || t.IsZero() {
		return time.Time{}
	}
	v := t.UTC()
	if v.After(now) {
		return now
	}
	if now.Sub(v) > sourceMaxTTL*24*time.Hour {
		return now.Add(-sourceMaxTTL * 24 * time.Hour)
	}
	return v
}

var feedClient = &http.Client{
	Timeout: 25 * time.Second, // under the dashboard's write timeout, for "fetch now"
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("redirects are not followed")
	},
}

// pullSource fetches one source now. It returns the error it stored.
func (s *Server) pullSource(id string) error {
	ss := &s.sources
	ss.mu.Lock()
	if ss.busy == nil {
		ss.busy = map[string]bool{}
	}
	if ss.busy[id] {
		ss.mu.Unlock()
		return errors.New("already fetching")
	}
	ss.busy[id] = true
	ss.mu.Unlock()
	defer func() { ss.mu.Lock(); delete(ss.busy, id); ss.mu.Unlock() }()

	s.mu.Lock()
	var src SourceRec
	for _, x := range s.state.Sources {
		if x.ID == id {
			src = *x
		}
	}
	s.mu.Unlock()
	if src.ID == "" {
		return errors.New("no such source")
	}
	now := time.Now().UTC()
	p, err := fetchFeed(src)
	var n int
	if err == nil {
		ss.mu.Lock()
		f := ss.files[id]
		if f == nil {
			f = &srcFile{ID: id}
		}
		cp := &srcFile{ID: id, Entries: make(map[string]*srcEntry, len(f.Entries))}
		for k, v := range f.Entries {
			c := *v
			cp.Entries[k] = &c
		}
		ss.mu.Unlock()
		mergeFeed(cp, p, s.neverList(), src.TTLDays, now)
		if err = s.saveSourceFile(cp); err == nil {
			ss.mu.Lock()
			if ss.files == nil {
				ss.files = map[string]*srcFile{}
			}
			ss.files[id] = cp
			ss.reindexLocked()
			ss.mu.Unlock()
			n = len(cp.Entries)
		}
	}
	s.mu.Lock()
	for _, x := range s.state.Sources {
		if x.ID == id {
			x.LastTry = now
			if err != nil {
				x.LastErr = redactKey(err.Error(), x.Token)
			} else {
				x.LastOK, x.LastErr, x.Entries, x.Network = now, "", n, clip(p.Network, 64)
			}
		}
	}
	s.saveLocked()
	s.mu.Unlock()
	if err != nil {
		log.Printf("source %s: %s", src.Name, redactKey(err.Error(), src.Token))
	}
	return err
}

func fetchFeed(src SourceRec) (*feedPayload, error) {
	req, err := http.NewRequest("GET", src.URL, nil)
	if err != nil {
		return nil, errors.New("bad URL")
	}
	req.Header.Set("Authorization", "Bearer "+src.Token)
	req.Header.Set("User-Agent", "vigil/"+Version)
	resp, err := feedClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, feedMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > feedMaxBytes {
		return nil, errors.New("feed larger than 16 MB")
	}
	return openFeed(bytes.TrimSpace(raw), src.Fingerprint)
}

// pullSources runs in the loop: every enabled source every 15 minutes.
func (s *Server) pullSources() {
	s.mu.Lock()
	var due []string
	for _, x := range s.state.Sources {
		if x.Enabled && time.Since(x.LastTry) >= sourcePullLoop-time.Minute {
			due = append(due, x.ID)
		}
	}
	s.mu.Unlock()
	for _, id := range due {
		s.pullSource(id)
	}
}

// sourceHitsLocked names the enabled sources of trust medium or high that
// list an address; low trust sources only feed the analytics. Caller holds
// s.mu.
func (s *Server) sourceHitsLocked(ip string) string {
	ids := s.sources.lookup(ip)
	if len(ids) == 0 {
		return ""
	}
	var names []string
	for _, id := range ids {
		for _, x := range s.state.Sources {
			if x.ID == id && x.Enabled && trustRank[x.Trust] >= trustRank["medium"] {
				names = append(names, x.Name)
			}
		}
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

var trustRank = map[string]int{"low": 1, "medium": 2, "high": 3}

func validSourceURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return errors.New("url must be http(s)://host[:port]/path")
	}
	return nil
}
