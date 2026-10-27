package server

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"
)

// Searching the event log. A query is a list of conditions that must all
// hold:
//
//	type:process.*            event type, * as wildcard
//	host:web  agent:<id>      host name or agent id
//	uid:0  exe:/tmp/*         a field of the event, * as wildcard
//	target.exe:/usr/*         nested fields with dots
//	count:>10  port:<1024     numbers compared
//	-user:root                a condition that must not hold
//	curl                      the word anywhere in the event (any case)
//	"two words"               quoted phrases
//
// Results come newest first; the same query exports as CSV or JSON lines.

type SavedSearch struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Query   string    `json:"query"`
	By      string    `json:"by"`
	Created time.Time `json:"created"`
}

type cond struct {
	neg   bool
	key   string // empty: free text
	op    string // "", ">", "<", ">=", "<="
	value string
	num   float64
}

func tokenize(q string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	for _, r := range q {
		switch {
		case r == '"':
			inQuote = !inQuote
		case (r == ' ' || r == '\t') && !inQuote:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

func parseQuery(q string) ([]cond, error) {
	var out []cond
	for _, tok := range tokenize(q) {
		c := cond{}
		if strings.HasPrefix(tok, "-") && len(tok) > 1 {
			c.neg, tok = true, tok[1:]
		}
		if k, v, ok := strings.Cut(tok, ":"); ok && k != "" && !strings.ContainsAny(k, "/ ") {
			c.key, c.value = strings.ToLower(k), v
			for _, op := range []string{">=", "<=", ">", "<"} {
				if rest, ok := strings.CutPrefix(v, op); ok {
					n, err := strconv.ParseFloat(rest, 64)
					if err != nil {
						return nil, fmt.Errorf("%s: %q is not a number", k, rest)
					}
					c.op, c.num, c.value = op, n, rest
					break
				}
			}
		} else {
			c.value = strings.ToLower(tok)
		}
		if len(out) >= 20 {
			return nil, fmt.Errorf("at most 20 conditions")
		}
		out = append(out, c)
	}
	return out, nil
}

func globMatch(pattern, s string) bool {
	if !strings.ContainsAny(pattern, "*?[") {
		return pattern == s
	}
	// path.Match treats / specially only for "*" not crossing it; replace
	// with a matcher where * matches anything.
	ok, err := path.Match(strings.ReplaceAll(pattern, "/", "\x00"), strings.ReplaceAll(s, "/", "\x00"))
	return err == nil && ok
}

func dataPath(d map[string]any, key string) (any, bool) {
	var cur any = d
	for _, part := range strings.Split(key, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = m[part]; !ok {
			return nil, false
		}
	}
	return cur, true
}

func (c cond) match(rec Record, host string, text func() string) bool {
	var ok bool
	switch c.key {
	case "":
		ok = strings.Contains(text(), c.value)
	case "type":
		ok = globMatch(c.value, rec.Event.Type)
	case "host":
		ok = globMatch(c.value, host)
	case "agent":
		ok = rec.Agent == c.value
	case "source":
		ok = rec.Source == c.value
	default:
		v, found := dataPath(rec.Event.Data, c.key)
		if found {
			switch c.op {
			case "":
				switch x := v.(type) {
				case []any:
					for _, e := range x {
						if globMatch(c.value, fmt.Sprint(e)) {
							ok = true
							break
						}
					}
				case float64:
					ok = globMatch(c.value, strconv.FormatFloat(x, 'f', -1, 64))
				default:
					ok = globMatch(c.value, fmt.Sprint(x))
				}
			default:
				n, isNum := v.(float64)
				if !isNum {
					n2, err := strconv.ParseFloat(fmt.Sprint(v), 64)
					n, isNum = n2, err == nil
				}
				if isNum {
					switch c.op {
					case ">":
						ok = n > c.num
					case "<":
						ok = n < c.num
					case ">=":
						ok = n >= c.num
					case "<=":
						ok = n <= c.num
					}
				}
			}
		}
	}
	return ok != c.neg
}

const (
	searchMax = 5000
)

// search runs a query over the log of the last days, newest first.
func (s *Server) search(conds []cond, days, limit int) ([]Record, int) {
	now := time.Now().UTC()
	names := s.agentNames()
	var ring []Record
	total := 0
	deadline := time.Now().Add(scanBudget)
	s.store.Between(now.AddDate(0, 0, -days), now, func(rec Record) bool {
		if time.Now().After(deadline) {
			total = -total - 1 // partial
			return false
		}
		if recordTime(rec).Before(now.AddDate(0, 0, -days)) {
			return true
		}
		var lower string
		text := func() string {
			if lower == "" {
				b, _ := json.Marshal(rec.Event)
				lower = strings.ToLower(string(b))
			}
			return lower
		}
		for _, c := range conds {
			if !c.match(rec, names[rec.Agent], text) {
				return true
			}
		}
		total++
		ring = append(ring, rec)
		if len(ring) > limit {
			ring = ring[1:]
		}
		return true
	})
	for i, j := 0, len(ring)-1; i < j; i, j = i+1, j-1 {
		ring[i], ring[j] = ring[j], ring[i]
	}
	return ring, total
}

// GET /api/ui/search?q=&days=&limit=&format=json|csv|jsonl
func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request, sess *session) {
	q := r.URL.Query()
	conds, err := parseQuery(q.Get("q"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	days, _ := strconv.Atoi(q.Get("days"))
	if days <= 0 {
		days = 7
	}
	if max := s.cfg.RetentionDays; max > 0 && days > max {
		days = max
	}
	if days > pivotDaysMax {
		days = pivotDaysMax
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 200
	}
	if limit > searchMax {
		limit = searchMax
	}
	start := time.Now()
	recs, total := s.search(conds, days, limit)
	partial := total < 0
	if partial {
		total = -total - 1
	}
	names := s.agentNames()
	role := s.rolesFor(sess)
	views := make([]viewRecord, len(recs))
	for i, rec := range recs {
		views[i] = s.view(rec, names, role)
	}
	format := q.Get("format")
	if format == "csv" || format == "jsonl" {
		s.audit(sess.User, "admin.export", map[string]any{"query": clip(q.Get("q"), 300), "days": days, "records": len(views), "format": format})
		name := "vigil-" + time.Now().UTC().Format("20060102-150405") + "." + format
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
		w.Header().Set("Cache-Control", "no-store")
		if format == "jsonl" {
			w.Header().Set("Content-Type", "application/x-ndjson")
			enc := json.NewEncoder(w)
			for _, v := range views {
				enc.Encode(v)
			}
			return
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		cw := csv.NewWriter(w)
		cw.Write([]string{"time", "received", "host", "source", "type", "seq", "data"})
		for _, v := range views {
			data, _ := json.Marshal(v.Event.Data)
			cw.Write([]string{recordTime(v.Record).Format(time.RFC3339Nano), v.Time.Format(time.RFC3339Nano), v.Host, v.Source,
				csvSafe(v.Event.Type), strconv.FormatUint(v.Seq, 10), csvSafe(string(data))})
		}
		cw.Flush()
		return
	}
	writeJSON(w, map[string]any{"records": views, "total": total, "days": days, "limit": limit, "ms": time.Since(start).Milliseconds(), "partial": partial})
}

// csvSafe keeps spreadsheet programs from running agent-controlled text as
// a formula.
func csvSafe(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}

// GET/POST /api/ui/searches, POST /api/ui/searches/{id}/delete
func (s *Server) handleSearches(w http.ResponseWriter, r *http.Request, sess *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.state.Searches
	if out == nil {
		out = []*SavedSearch{}
	}
	writeJSON(w, out)
}

func (s *Server) handleSearchSave(w http.ResponseWriter, r *http.Request, sess *session) {
	var req struct{ Name, Query string }
	if !decode(r, w, &req) {
		return
	}
	req.Name, req.Query = strings.TrimSpace(req.Name), strings.TrimSpace(req.Query)
	if req.Name == "" || len(req.Name) > 100 || req.Query == "" || len(req.Query) > 1000 {
		http.Error(w, "name and query needed", http.StatusBadRequest)
		return
	}
	if _, err := parseQuery(req.Query); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	if len(s.state.Searches) >= 200 {
		s.mu.Unlock()
		http.Error(w, "too many saved searches", http.StatusBadRequest)
		return
	}
	ss := &SavedSearch{ID: newID(6), Name: req.Name, Query: req.Query, By: sess.User, Created: time.Now().UTC()}
	s.state.Searches = append(s.state.Searches, ss)
	s.saveLocked()
	s.mu.Unlock()
	s.audit(sess.User, "admin.search_saved", map[string]any{"name": ss.Name, "query": ss.Query})
	writeJSON(w, ss)
}

func (s *Server) handleSearchDelete(w http.ResponseWriter, r *http.Request, sess *session) {
	id := r.PathValue("id")
	s.mu.Lock()
	kept := s.state.Searches[:0]
	for _, x := range s.state.Searches {
		if x.ID != id {
			kept = append(kept, x)
		}
	}
	s.state.Searches = kept
	s.saveLocked()
	s.mu.Unlock()
	s.audit(sess.User, "admin.search_deleted", map[string]any{"id": id})
	writeJSON(w, map[string]bool{"ok": true})
}
