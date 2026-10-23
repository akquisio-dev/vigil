package server

import (
	"crypto/ed25519"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Dashboard side of sources and shares: the settings (admins only) and the
// analytics (everyone signed in).

type shareView struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Cats     []string  `json:"cats"`
	Users    bool      `json:"users"`
	Counts   bool      `json:"counts"`
	Days     int       `json:"days"`
	MinHits  int       `json:"min_hits"`
	Exclude  []string  `json:"exclude"`
	Enabled  bool      `json:"enabled"`
	Created  time.Time `json:"created"`
	By       string    `json:"by"`
	Pulled   time.Time `json:"pulled"`
	PulledIP string    `json:"pulled_ip,omitempty"`
	Pulls    int       `json:"pulls"`
	Sent     int       `json:"sent"`
}

type sourceView struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Kind        string    `json:"kind"`
	URL         string    `json:"url"`
	Fingerprint string    `json:"fingerprint"`
	Trust       string    `json:"trust"`
	TTLDays     int       `json:"ttl_days"`
	Enabled     bool      `json:"enabled"`
	Created     time.Time `json:"created"`
	By          string    `json:"by"`
	LastTry     time.Time `json:"last_try"`
	LastOK      time.Time `json:"last_ok"`
	LastErr     string    `json:"last_err,omitempty"`
	Network     string    `json:"network,omitempty"`
	Entries     int       `json:"entries"`
}

func viewShare(x *ShareRec) shareView {
	return shareView{x.ID, x.Name, x.Cats, x.Users, x.Counts, x.Days, x.MinHits, x.Exclude, x.Enabled, x.Created, x.By,
		x.Pulled, x.PulledIP, x.Pulls, x.Sent}
}

func viewSource(x *SourceRec) sourceView {
	return sourceView{x.ID, x.Name, x.Kind, x.URL, x.Fingerprint, x.Trust, x.TTLDays, x.Enabled, x.Created, x.By,
		x.LastTry, x.LastOK, x.LastErr, x.Network, x.Entries}
}

func (s *Server) handleSourcesConfig(w http.ResponseWriter, r *http.Request, sess *session) {
	fp := ""
	if k, err := s.feedKey(); err == nil {
		fp = fingerprint(k.Public().(ed25519.PublicKey))
	}
	s.mu.Lock()
	shares, sources := []shareView{}, []sourceView{}
	for _, x := range s.state.Shares {
		shares = append(shares, viewShare(x))
	}
	for _, x := range s.state.Sources {
		sources = append(sources, viewSource(x))
	}
	s.mu.Unlock()
	listen := ""
	if f := s.cfg.Federation; f != nil {
		listen = f.Listen
	}
	writeJSON(w, map[string]any{"fingerprint": fp, "network": s.networkName(), "listen": listen,
		"path": "/api/federation/v1/feed", "cats": shareCats, "shares": shares, "sources": sources})
}

type shareReq struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Cats    []string `json:"cats"`
	Users   bool     `json:"users"`
	Counts  bool     `json:"counts"`
	Days    int      `json:"days"`
	MinHits int      `json:"min_hits"`
	Exclude []string `json:"exclude"`
	Enabled bool     `json:"enabled"`
	Preview bool     `json:"preview"`
}

// share checks a request and returns the share it describes.
func (q *shareReq) share() (*ShareRec, string) {
	q.Name = strings.TrimSpace(clip(q.Name, 64))
	if q.Name == "" {
		return nil, "name is required"
	}
	var cats []string
	for _, c := range q.Cats {
		if !validCat(c) {
			return nil, "unknown category " + clip(c, 32)
		}
		if !contains(cats, c) {
			cats = append(cats, c)
		}
	}
	if len(cats) == 0 {
		return nil, "choose at least one category"
	}
	if q.Days < 1 || q.Days > attackDaysMax {
		return nil, "days must be 1 to 30"
	}
	if q.MinHits < 0 || q.MinHits > 1000000 {
		return nil, "min_hits must be 0 or more"
	}
	if len(q.Exclude) > 200 {
		return nil, "at most 200 excluded networks"
	}
	if _, err := parsePrefixes(q.Exclude); err != nil {
		return nil, err.Error()
	}
	var excl []string
	for _, e := range q.Exclude {
		if e = strings.TrimSpace(e); e != "" {
			excl = append(excl, e)
		}
	}
	return &ShareRec{Name: q.Name, Cats: cats, Users: q.Users, Counts: q.Counts, Days: q.Days, MinHits: q.MinHits,
		Exclude: excl, Enabled: q.Enabled}, ""
}

func (s *Server) handleShareSave(w http.ResponseWriter, r *http.Request, sess *session) {
	var q shareReq
	if !decode(r, w, &q) {
		return
	}
	sh, msg := q.share()
	if sh == nil {
		http.Error(w, msg, http.StatusBadRequest)
		return
	}
	if q.Preview {
		// the same projection a fetch gets
		p := s.buildFeed(sh, time.Now())
		sample := p.Entries
		if len(sample) > 20 {
			sample = sample[:20]
		}
		writeJSON(w, map[string]any{"count": len(p.Entries), "days": p.Days, "network": p.Network, "sample": sample})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	audit := map[string]any{"name": sh.Name, "cats": sh.Cats, "users": sh.Users, "counts": sh.Counts, "days": sh.Days,
		"min_hits": sh.MinHits, "exclude": sh.Exclude, "enabled": sh.Enabled}
	if q.ID != "" {
		for _, x := range s.state.Shares {
			if x.ID == q.ID {
				x.Name, x.Cats, x.Users, x.Counts, x.Days, x.MinHits, x.Exclude, x.Enabled =
					sh.Name, sh.Cats, sh.Users, sh.Counts, sh.Days, sh.MinHits, sh.Exclude, sh.Enabled
				s.saveLocked()
				audit["id"] = x.ID
				go s.audit(sess.User, "share.changed", audit)
				writeJSON(w, map[string]any{"share": viewShare(x)})
				return
			}
		}
		http.Error(w, "no such share", http.StatusNotFound)
		return
	}
	if len(s.state.Shares) >= 50 {
		http.Error(w, "at most 50 shares", http.StatusBadRequest)
		return
	}
	tok := "vfs_" + newID(24)
	sh.ID, sh.Hash, sh.Created, sh.By = newID(8), sha(tok), time.Now().UTC(), sess.User
	s.state.Shares = append(s.state.Shares, sh)
	s.saveLocked()
	audit["id"] = sh.ID
	go s.audit(sess.User, "share.created", audit)
	// the token is shown once and only its hash is kept
	writeJSON(w, map[string]any{"share": viewShare(sh), "token": tok})
}

func (s *Server) handleShareAction(w http.ResponseWriter, r *http.Request, sess *session) {
	id, action := r.PathValue("id"), r.PathValue("action")
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, x := range s.state.Shares {
		if x.ID != id {
			continue
		}
		res := map[string]any{}
		switch action {
		case "delete":
			s.state.Shares = append(s.state.Shares[:i:i], s.state.Shares[i+1:]...)
		case "rotate":
			tok := "vfs_" + newID(24)
			x.Hash = sha(tok)
			res["token"] = tok
		default:
			http.Error(w, "unknown action", http.StatusBadRequest)
			return
		}
		s.saveLocked()
		go s.audit(sess.User, "share."+action, map[string]any{"id": id, "name": x.Name})
		writeJSON(w, res)
		return
	}
	http.Error(w, "no such share", http.StatusNotFound)
}

type sourceReq struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	URL         string `json:"url"`
	Token       string `json:"token"`
	Fingerprint string `json:"fingerprint"`
	Trust       string `json:"trust"`
	TTLDays     int    `json:"ttl_days"`
	Enabled     bool   `json:"enabled"`
}

func (s *Server) handleSourceSave(w http.ResponseWriter, r *http.Request, sess *session) {
	var q sourceReq
	if !decode(r, w, &q) {
		return
	}
	q.Name, q.URL, q.Token = strings.TrimSpace(clip(q.Name, 64)), strings.TrimSpace(q.URL), strings.TrimSpace(q.Token)
	bad := func(m string) { http.Error(w, m, http.StatusBadRequest) }
	if q.Name == "" {
		bad("name is required")
		return
	}
	if err := validSourceURL(q.URL); err != nil || len(q.URL) > 512 {
		bad("url must be http(s)://host[:port]/path")
		return
	}
	if fp := normFingerprint(q.Fingerprint); len(fp) != 32 || strings.Trim(fp, "0123456789abcdef") != "" {
		bad("fingerprint must be the 32 hex digits the partner's dashboard shows")
		return
	}
	if trustRank[q.Trust] == 0 {
		bad("trust must be low, medium or high")
		return
	}
	if q.TTLDays < 1 || q.TTLDays > sourceMaxTTL {
		bad("ttl_days must be 1 to 90")
		return
	}
	if q.Token != "" && (len(q.Token) > 256 || strings.ContainsAny(q.Token, " \t\r\n")) {
		bad("token looks wrong")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	audit := map[string]any{"name": q.Name, "url": q.URL, "fingerprint": q.Fingerprint, "trust": q.Trust,
		"ttl_days": q.TTLDays, "enabled": q.Enabled, "token_changed": q.Token != ""}
	var x *SourceRec
	if q.ID != "" {
		for _, y := range s.state.Sources {
			if y.ID == q.ID {
				x = y
			}
		}
		if x == nil {
			http.Error(w, "no such source", http.StatusNotFound)
			return
		}
	} else {
		if q.Token == "" {
			bad("token is required")
			return
		}
		if len(s.state.Sources) >= 50 {
			bad("at most 50 sources")
			return
		}
		x = &SourceRec{ID: newID(8), Kind: "vigil", Created: time.Now().UTC(), By: sess.User}
		s.state.Sources = append(s.state.Sources, x)
	}
	if normFingerprint(x.Fingerprint) != normFingerprint(q.Fingerprint) || x.URL != q.URL {
		x.LastErr = ""
	}
	x.Name, x.URL, x.Fingerprint, x.Trust, x.TTLDays, x.Enabled = q.Name, q.URL, q.Fingerprint, q.Trust, q.TTLDays, q.Enabled
	if q.Token != "" {
		x.Token = q.Token
	}
	s.saveLocked()
	audit["id"] = x.ID
	typ := "source.changed"
	if q.ID == "" {
		typ = "source.created"
	}
	go s.audit(sess.User, typ, audit)
	if x.Enabled {
		go s.pullSource(x.ID)
	}
	writeJSON(w, map[string]any{"source": viewSource(x)})
}

func (s *Server) handleSourceAction(w http.ResponseWriter, r *http.Request, sess *session) {
	id, action := r.PathValue("id"), r.PathValue("action")
	switch action {
	case "pull":
		err := s.pullSource(id)
		res := map[string]any{"ok": err == nil}
		if err != nil {
			s.mu.Lock()
			for _, x := range s.state.Sources {
				if x.ID == id {
					res["error"] = x.LastErr
				}
			}
			s.mu.Unlock()
		}
		writeJSON(w, res)
	case "delete":
		s.mu.Lock()
		found := ""
		for i, x := range s.state.Sources {
			if x.ID == id {
				found = x.Name
				s.state.Sources = append(s.state.Sources[:i:i], s.state.Sources[i+1:]...)
				break
			}
		}
		if found != "" {
			s.saveLocked()
		}
		s.mu.Unlock()
		if found == "" {
			http.Error(w, "no such source", http.StatusNotFound)
			return
		}
		ss := &s.sources
		ss.mu.Lock()
		delete(ss.files, id)
		ss.reindexLocked()
		ss.mu.Unlock()
		removeSourceFile(s.sourcesDir(), id)
		go s.audit(sess.User, "source.delete", map[string]any{"id": id, "name": found})
		writeJSON(w, map[string]any{})
	default:
		http.Error(w, "unknown action", http.StatusBadRequest)
	}
}

// Analytics.

type srcStat struct {
	ID      string         `json:"id"`
	Name    string         `json:"name"`
	Network string         `json:"network,omitempty"`
	Trust   string         `json:"trust"`
	Enabled bool           `json:"enabled"`
	LastOK  time.Time      `json:"last_ok"`
	LastErr string         `json:"last_err,omitempty"`
	Entries int            `json:"entries"`
	Active  int            `json:"active"`  // last seen by the source within the window
	Overlap int            `json:"overlap"` // of them, also attacked us in the window
	Earlier int            `json:"earlier"` // of the overlap, the source saw first
	LeadH   *float64       `json:"lead_h"`  // median hours the source was ahead (negative: behind)
	Cats    map[string]int `json:"cats"`
	Hours   [24]int        `json:"hours"` // first seen by the source, UTC
	New     []int          `json:"new"`   // entries first fetched, per day
	Stale   bool           `json:"stale"` // no fetch for a day
}

type srcTop struct {
	IP       string    `json:"ip"`
	Sources  []string  `json:"sources"` // IDs; "us" when the agents saw it
	Ours     int       `json:"ours"`    // our attempts in the window
	Reported int       `json:"reported"`
	Country  string    `json:"country,omitempty"`
	Cats     []string  `json:"cats"`
	FirstBy  string    `json:"first_by"` // who saw it first
	First    time.Time `json:"first"`
}

type srcFlow struct {
	From string `json:"from"`
	Cat  string `json:"cat"`
	To   string `json:"to"`
	N    int    `json:"n"`
}

type sourcesStats struct {
	Days    int       `json:"days"`
	Us      int       `json:"us"`
	Sources []srcStat `json:"sources"`
	Labels  []string  `json:"labels"` // matrix order: "us", then source IDs
	Matrix  [][]int   `json:"matrix"`
	Top     []srcTop  `json:"top"`
	Flows   []srcFlow `json:"flows"`
	Lead    []int     `json:"lead"` // histogram of lead hours, see leadBuckets
	Buckets []string  `json:"buckets"`
}

var leadBuckets = []struct {
	label string
	upTo  float64
}{{"<-24h", -24}, {"-24h", -1}, {"±1h", 1}, {"1h", 6}, {"6h", 24}, {"1d", 72}, {"3d+", 1e9}}

func (s *Server) handleSourcesStats(w http.ResponseWriter, r *http.Request, sess *session) {
	days, _ := strconv.Atoi(r.URL.Query().Get("days"))
	writeJSON(w, s.sourcesStats(days, time.Now().UTC()))
}

func (s *Server) sourcesStats(days int, now time.Time) *sourcesStats {
	if days < 1 || days > attackDaysMax {
		days = 7
	}
	from := now.Add(-time.Duration(days) * 24 * time.Hour)
	ra := &s.attacks
	ra.mu.Lock()
	merged, _, _, _, _, _ := ra.attackWindow(days, now)
	ra.mu.Unlock()
	ours := map[string]*atkIP{}
	for ip, x := range merged {
		if x.attempts() > 0 && !x.own() {
			ours[ip] = x
		}
	}
	s.mu.Lock()
	var recs []SourceRec
	for _, x := range s.state.Sources {
		recs = append(recs, *x)
	}
	s.mu.Unlock()

	st := &sourcesStats{Days: days, Us: len(ours), Labels: []string{"us"}}
	for _, b := range leadBuckets {
		st.Buckets = append(st.Buckets, b.label)
	}
	st.Lead = make([]int, len(leadBuckets))
	type hit struct {
		ids   []string
		cats  map[string]bool
		first time.Time
		by    string
		rep   int
	}
	hits := map[string]*hit{}
	flows := map[[3]string]int{}
	geo := map[string]string{}
	country := func(ip string) string {
		c, ok := geo[ip]
		if !ok {
			c = s.geo(ip).Country
			geo[ip] = c
		}
		if c == "" {
			return "?"
		}
		return c
	}

	ss := &s.sources
	ss.mu.RLock()
	for _, src := range recs {
		f := ss.files[src.ID]
		row := srcStat{ID: src.ID, Name: src.Name, Network: src.Network, Trust: src.Trust, Enabled: src.Enabled,
			LastOK: src.LastOK, LastErr: src.LastErr, Cats: map[string]int{}, New: make([]int, days),
			Stale: src.Enabled && now.Sub(src.LastOK) > 24*time.Hour}
		st.Labels = append(st.Labels, src.ID)
		var leads []float64
		if f != nil {
			row.Entries = len(f.Entries)
			for ip, e := range f.Entries {
				if i := int(e.Seen.Sub(from) / (24 * time.Hour)); i >= 0 && i < days {
					row.New[i]++
				}
				if e.Last.Before(from) {
					continue
				}
				row.Active++
				row.Hours[e.First.Hour()]++
				h := hits[ip]
				if h == nil {
					h = &hit{cats: map[string]bool{}}
					hits[ip] = h
				}
				h.ids = append(h.ids, src.ID)
				h.rep += e.N
				if h.first.IsZero() || e.First.Before(h.first) {
					h.first, h.by = e.First, src.ID
				}
				for _, c := range e.Cats {
					row.Cats[c]++
					h.cats[c] = true
				}
				if len(e.Cats) > 0 {
					flows[[3]string{src.ID, e.Cats[0], country(ip)}]++
				}
				if x := ours[ip]; x != nil {
					row.Overlap++
					lead := x.First.Sub(e.First).Hours()
					leads = append(leads, lead)
					if lead > 0 {
						row.Earlier++
					}
					for i, b := range leadBuckets {
						if lead <= b.upTo {
							st.Lead[i]++
							break
						}
					}
				}
			}
		}
		if len(leads) > 0 {
			sort.Float64s(leads)
			m := leads[len(leads)/2]
			if len(leads)%2 == 0 {
				m = (leads[len(leads)/2-1] + m) / 2
			}
			m = float64(int(m*10)) / 10
			row.LeadH = &m
		}
		st.Sources = append(st.Sources, row)
	}
	ss.mu.RUnlock()

	// overlap matrix: index 0 is us
	n := len(st.Labels)
	st.Matrix = make([][]int, n)
	for i := range st.Matrix {
		st.Matrix[i] = make([]int, n)
	}
	pos := map[string]int{}
	for i, l := range st.Labels {
		pos[l] = i
	}
	st.Matrix[0][0] = len(ours)
	for ip, h := range hits {
		idx := []int{}
		if ours[ip] != nil {
			idx = append(idx, 0)
		}
		for _, id := range h.ids {
			idx = append(idx, pos[id])
		}
		for _, a := range idx {
			for _, b := range idx {
				if a != 0 || b != 0 {
					st.Matrix[a][b]++
				}
			}
		}
	}

	for ip, h := range hits {
		t := srcTop{IP: ip, Sources: h.ids, Reported: h.rep, First: h.first, FirstBy: h.by}
		if x := ours[ip]; x != nil {
			t.Sources = append([]string{"us"}, t.Sources...)
			t.Ours = x.attempts()
			if x.First.Before(h.first) {
				t.First, t.FirstBy = x.First, "us"
			}
		}
		for c := range h.cats {
			t.Cats = append(t.Cats, c)
		}
		sort.Strings(t.Cats)
		st.Top = append(st.Top, t)
	}
	sort.Slice(st.Top, func(i, j int) bool {
		a, b := st.Top[i], st.Top[j]
		if len(a.Sources) != len(b.Sources) {
			return len(a.Sources) > len(b.Sources)
		}
		if a.Ours != b.Ours {
			return a.Ours > b.Ours
		}
		if a.Reported != b.Reported {
			return a.Reported > b.Reported
		}
		return a.IP < b.IP
	})
	if len(st.Top) > 50 {
		st.Top = st.Top[:50]
	}
	for i := range st.Top {
		st.Top[i].Country = country(st.Top[i].IP)
	}

	// flows: keep the 8 biggest countries, fold the rest
	byCC := map[string]int{}
	for k, v := range flows {
		byCC[k[2]] += v
	}
	var ccs []string
	for c := range byCC {
		ccs = append(ccs, c)
	}
	sort.Slice(ccs, func(i, j int) bool {
		if byCC[ccs[i]] != byCC[ccs[j]] {
			return byCC[ccs[i]] > byCC[ccs[j]]
		}
		return ccs[i] < ccs[j]
	})
	keep := map[string]bool{}
	for i, c := range ccs {
		if i < 8 {
			keep[c] = true
		}
	}
	folded := map[[3]string]int{}
	for k, v := range flows {
		if !keep[k[2]] {
			k[2] = "*"
		}
		folded[k] += v
	}
	for k, v := range folded {
		st.Flows = append(st.Flows, srcFlow{k[0], k[1], k[2], v})
	}
	sort.Slice(st.Flows, func(i, j int) bool {
		a, b := st.Flows[i], st.Flows[j]
		if a.N != b.N {
			return a.N > b.N
		}
		return a.From+a.Cat+a.To < b.From+b.Cat+b.To
	})
	return st
}
