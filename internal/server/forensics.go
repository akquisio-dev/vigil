package server

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

// Investigation views: what happened on a host around a moment (timeline),
// and everything the log knows about one address, user or file hash
// (pivot). Both read the day files on disk, so they reach back as far as
// the retention, not only over the in-memory window.

const (
	timelineMax  = 2000
	pivotMax     = 1000
	pivotDaysMax = 400
)

// Between visits the records of the day files from..to (by file date, one
// day of margin on both sides for late or early clocks), oldest first,
// until fn returns false. A line still being written is skipped.
func (s *Store) Between(from, to time.Time, fn func(Record) bool) {
	first := from.UTC().AddDate(0, 0, -1).Format("2006-01-02")
	last := to.UTC().AddDate(0, 0, 1).Format("2006-01-02")
	for _, f := range s.files() {
		day := strings.TrimSuffix(filepath.Base(f), ".jsonl")
		if day < first || day > last {
			continue
		}
		if !s.scanFile(f, fn) {
			return
		}
	}
}

func (s *Store) scanFile(path string, fn func(Record) bool) bool {
	fh, err := os.Open(path)
	if err != nil {
		return true
	}
	defer fh.Close()
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 256*1024), proto.MaxBodyBytes*2)
	for sc.Scan() {
		var cl chainLine
		if json.Unmarshal(sc.Bytes(), &cl) != nil {
			continue
		}
		var r Record
		if json.Unmarshal(cl.Rec, &r) != nil {
			continue
		}
		if !fn(r) {
			return false
		}
	}
	return true
}

// recordTime is when the event happened on the host. Events buffered while
// the server was unreachable arrive later; their own time counts.
func recordTime(r Record) time.Time {
	if !r.Event.TS.IsZero() {
		return r.Event.TS
	}
	return r.Time
}

// An entity is something to pivot on.
type entity struct {
	Kind  string `json:"kind"` // ip | user | hash
	Value string `json:"value"`
}

var (
	ipFields   = []string{"ip", "remote_ip", "addr", "source_ip"}
	userFields = []string{"user", "target_user"}
	hashFields = []string{"sha256", "old_sha256", "hash", "exe_sha256"}
)

func validIP(v string) bool {
	a, err := netip.ParseAddr(v)
	return err == nil && !a.IsUnspecified()
}

func validHash(v string) bool {
	if len(v) != 64 {
		return false
	}
	for _, c := range v {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func validUser(v string) bool {
	if v == "" || len(v) > 64 {
		return false
	}
	for _, c := range v {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._-@$", c)) {
			return false
		}
	}
	return true
}

// entities lists the addresses, users and hashes an event names. It is the
// one place that knows which fields carry them; the pivot scan and the
// links in the dashboard both use it.
func entities(ev proto.Event) []entity {
	d := ev.Data
	if d == nil {
		return nil
	}
	var out []entity
	seen := map[string]bool{}
	add := func(kind, v string) {
		if !seen[kind+v] {
			seen[kind+v] = true
			out = append(out, entity{kind, v})
		}
	}
	for _, f := range ipFields {
		if v := str(d, f); validIP(v) {
			add("ip", v)
		}
	}
	for _, f := range hashFields {
		if v := strings.ToLower(str(d, f)); validHash(v) {
			add("hash", v)
		}
	}
	switch {
	case strings.HasPrefix(ev.Type, "ssh.") || strings.HasPrefix(ev.Type, "sudo.") || strings.HasPrefix(ev.Type, "user."):
		for _, f := range userFields {
			if v := str(d, f); validUser(v) {
				add("user", v)
			}
		}
	}
	if ev.Type == "forensics.snapshot" {
		if t, ok := d["target"].(map[string]any); ok {
			if v := str(t, "exe_sha256"); validHash(v) {
				add("hash", v)
			}
		}
	}
	return out
}

// agentNames maps agent ids to host names; records of the server itself
// (no agent) are named "server".
func (s *Server) agentNames() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	names := map[string]string{"": "server"}
	for id, a := range s.state.Agents {
		names[id] = a.Name
	}
	return names
}

type viewRecord struct {
	Record
	Host     string   `json:"host,omitempty"`
	Entities []entity `json:"entities,omitempty"`
}

// sensitive fields are kept from viewers: file change contents and the
// details of evidence snapshots.
var sensitiveFields = map[string]bool{"diff": true, "processes": true, "target": true, "journal": true, "connections": true}

func (s *Server) view(rec Record, names map[string]string, role string) viewRecord {
	if roleRank[role] < roleRank["analyst"] && rec.Event.Data != nil {
		cp := map[string]any{}
		for k, v := range rec.Event.Data {
			if sensitiveFields[k] {
				v = "(analyst role needed)"
			}
			cp[k] = v
		}
		rec.Event.Data = cp
	}
	v := viewRecord{Record: rec, Entities: entities(rec.Event)}
	if rec.Agent != "" {
		v.Host = names[rec.Agent] // records of the server show their source and actor instead
	}
	return v
}

func (s *Server) roleFor(sess *session) string {
	if u := s.user(sess.User); u != nil {
		return roleOf(u)
	}
	return "viewer"
}

// handleTimeline: GET /api/ui/timeline?agent=&at=&minutes= or ?alert=
func (s *Server) handleTimeline(w http.ResponseWriter, r *http.Request, sess *session) {
	q := r.URL.Query()
	agent := q.Get("agent")
	at, _ := time.Parse(time.RFC3339Nano, q.Get("at"))
	minutes, _ := strconv.Atoi(q.Get("minutes"))
	if minutes <= 0 || minutes > 24*60 {
		minutes = 30
	}
	var anchorSeqs []uint64
	if id := q.Get("alert"); id != "" {
		s.mu.Lock()
		for _, al := range s.state.Alerts {
			if al.ID == id {
				agent, at = al.Agent, al.Created
				anchorSeqs = append([]uint64{}, al.Seqs...)
			}
		}
		s.mu.Unlock()
		if agent == "" {
			http.Error(w, "alert not found or not tied to a host", http.StatusNotFound)
			return
		}
	}
	if agent == "" {
		http.Error(w, "agent missing", http.StatusBadRequest)
		return
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	// The alert's first event decides the moment: the alert is created
	// when the event arrives, which can be much later.
	if len(anchorSeqs) > 0 {
		want := anchorSeqs[0]
		s.store.Between(at.Add(-48*time.Hour), at, func(rec Record) bool {
			if rec.Seq == want {
				at = recordTime(rec)
				return false
			}
			return true
		})
	}
	win := time.Duration(minutes) * time.Minute
	from, to := at.Add(-win), at.Add(win)
	names := s.agentNames()
	role := s.roleFor(sess)
	recs := []viewRecord{}
	truncated := false
	s.store.Between(from, to, func(rec Record) bool {
		if rec.Agent != agent {
			return true
		}
		// The host's own time decides; events that arrived late (agent
		// offline, queue flushed later) still land where they happened.
		if t := recordTime(rec); t.Before(from) || t.After(to) {
			return true
		}
		if len(recs) >= timelineMax {
			truncated = true
			return false
		}
		recs = append(recs, s.view(rec, names, role))
		return true
	})
	sort.SliceStable(recs, func(i, j int) bool { return recordTime(recs[i].Record).Before(recordTime(recs[j].Record)) })
	alerts := []alertView{}
	s.mu.Lock()
	for _, al := range s.state.Alerts {
		if al.Agent == agent && !al.Created.Before(from) && !al.Created.After(to.Add(5*time.Minute)) {
			alerts = append(alerts, s.viewAlert(al, lang(r)))
		}
	}
	s.mu.Unlock()
	writeJSON(w, map[string]any{"agent": agent, "host": names[agent], "at": at, "from": from, "to": to, "minutes": minutes,
		"records": recs, "alerts": alerts, "anchor_seqs": anchorSeqs, "truncated": truncated})
}

// handleRecords: GET /api/ui/records?seq=1,2,3 (at most 20, from the last
// days of the alert they belong to).
func (s *Server) handleRecords(w http.ResponseWriter, r *http.Request, sess *session) {
	want := map[uint64]bool{}
	for _, p := range strings.Split(r.URL.Query().Get("seq"), ",") {
		if n, err := strconv.ParseUint(strings.TrimSpace(p), 10, 64); err == nil && len(want) < 20 {
			want[n] = true
		}
	}
	at, _ := time.Parse(time.RFC3339Nano, r.URL.Query().Get("at"))
	if at.IsZero() {
		at = time.Now().UTC()
	}
	names := s.agentNames()
	role := s.roleFor(sess)
	out := []viewRecord{}
	if len(want) > 0 {
		// from a little before the given moment (the alert's creation) up to now
		s.store.Between(at.Add(-72*time.Hour), time.Now().UTC(), func(rec Record) bool {
			if want[rec.Seq] {
				out = append(out, s.view(rec, names, role))
				delete(want, rec.Seq)
			}
			return len(want) > 0
		})
	}
	writeJSON(w, out)
}

// handlePivot: GET /api/ui/pivot?kind=ip|user|hash&value=&days=
func (s *Server) handlePivot(w http.ResponseWriter, r *http.Request, sess *session) {
	q := r.URL.Query()
	kind, value := q.Get("kind"), strings.TrimSpace(q.Get("value"))
	switch {
	case kind == "ip" && validIP(value):
		value = netip.MustParseAddr(value).String()
	case kind == "hash" && validHash(strings.ToLower(value)):
		value = strings.ToLower(value)
	case kind == "user" && validUser(value):
	default:
		http.Error(w, "kind must be ip, user or hash with a valid value", http.StatusBadRequest)
		return
	}
	days, _ := strconv.Atoi(q.Get("days"))
	if days <= 0 {
		days = 30
	}
	if max := s.cfg.RetentionDays; max > 0 && days > max {
		days = max
	}
	if days > pivotDaysMax {
		days = pivotDaysMax
	}
	now := time.Now().UTC()
	names := s.agentNames()
	role := s.roleFor(sess)
	var recs []viewRecord
	total := 0
	var first, last time.Time
	perHost := map[string]int{}
	perType := map[string]int{}
	s.store.Between(now.AddDate(0, 0, -days), now, func(rec Record) bool {
		hit := false
		for _, e := range entities(rec.Event) {
			if e.Kind == kind && e.Value == value {
				hit = true
				break
			}
		}
		if !hit {
			return true
		}
		total++
		t := recordTime(rec)
		if first.IsZero() || t.Before(first) {
			first = t
		}
		if t.After(last) {
			last = t
		}
		perHost[names[rec.Agent]]++
		perType[rec.Event.Type]++
		recs = append(recs, s.view(rec, names, role))
		if len(recs) > pivotMax {
			recs = recs[1:] // keep the newest
		}
		return true
	})
	// newest first
	for i, j := 0, len(recs)-1; i < j; i, j = i+1, j-1 {
		recs[i], recs[j] = recs[j], recs[i]
	}
	if recs == nil {
		recs = []viewRecord{}
	}
	alerts := []alertView{}
	s.mu.Lock()
	for i := len(s.state.Alerts) - 1; i >= 0 && len(alerts) < 200; i-- {
		al := s.state.Alerts[i]
		for k, v := range decodeParams(al.Detail) {
			if v == value && (kind != "user" || k == "user") {
				alerts = append(alerts, s.viewAlert(al, lang(r)))
				break
			}
		}
	}
	s.mu.Unlock()
	out := map[string]any{"kind": kind, "value": value, "days": days, "total": total, "records": recs, "alerts": alerts,
		"hosts": perHost, "types": perType}
	if !first.IsZero() {
		out["first"], out["last"] = first, last
	}
	if kind == "ip" {
		a := netip.MustParseAddr(value)
		out["public"] = netPublic(value)
		out["private"] = a.IsPrivate() || a.IsLoopback()
		if list, ok := s.intel.lookup(value); ok {
			out["intel"] = list
		}
	}
	writeJSON(w, out)
}
