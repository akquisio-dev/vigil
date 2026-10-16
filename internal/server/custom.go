package server

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Custom rules are JSON files in rules_dir. They add detections without Go
// code. They can never replace or switch off a built-in rule: their ids must
// start with "custom." and a file that fails to load is skipped on its own.
type CustomRule struct {
	ID          string            `json:"id"`
	Severity    string            `json:"severity"`
	Technique   string            `json:"technique,omitempty"`
	Description string            `json:"description,omitempty"`
	Title       map[string]string `json:"title"` // "en" (required), "de"
	// Event is an event type ("ssh.login") or a prefix ending in "*" ("file.*").
	Event string `json:"event"`
	Where []Cond `json:"where,omitempty"`
	// Threshold turns the rule into "at least Count matches within Window
	// minutes", counted separately per value of GroupBy.
	Threshold *Threshold `json:"threshold,omitempty"`
	// Key lists the fields that make two findings the same alert.
	Key  []string `json:"key,omitempty"`
	File string   `json:"-"`
	re   []*regexp.Regexp
}

type Cond struct {
	Field string `json:"field"`
	// Op: equals, not_equals, contains, prefix, suffix, regex, in, gt, lt, exists
	Op    string `json:"op"`
	Value any    `json:"value,omitempty"`
}

type Threshold struct {
	Count   int    `json:"count"`
	Window  int    `json:"window_minutes"`
	GroupBy string `json:"group_by,omitempty"`
}

var (
	customMu    sync.RWMutex
	customRules = map[string]*CustomRule{}
	customOrder []string
	customErrs  []string
)

var customID = regexp.MustCompile(`^custom\.[a-z0-9_.-]{1,60}$`)

func (c *CustomRule) validate() error {
	switch {
	case !customID.MatchString(c.ID):
		return errors.New(`id must match custom.<name> (lower case, digits, "_", ".", "-")`)
	case severityRank[c.Severity] == 0 && c.Severity != "info":
		return fmt.Errorf("unknown severity %q", c.Severity)
	case c.Title["en"] == "":
		return errors.New("title.en is required")
	case c.Event == "" || !eventType.MatchString(strings.TrimSuffix(c.Event, "*")+"x"):
		return errors.New("event must be an event type or a prefix ending in *")
	case len(c.Where) > 20:
		return errors.New("at most 20 conditions")
	}
	if t := c.Threshold; t != nil && (t.Count < 2 || t.Count > 10000 || t.Window < 1 || t.Window > 1440) {
		return errors.New("threshold needs count 2..10000 and window_minutes 1..1440")
	}
	c.re = make([]*regexp.Regexp, len(c.Where))
	for i, w := range c.Where {
		if w.Field == "" {
			return fmt.Errorf("condition %d: field is required", i+1)
		}
		switch w.Op {
		case "equals", "not_equals", "contains", "prefix", "suffix", "exists":
		case "regex":
			s, _ := w.Value.(string)
			re, err := regexp.Compile(s)
			if err != nil || len(s) > 500 {
				return fmt.Errorf("condition %d: bad regex", i+1)
			}
			c.re[i] = re
		case "in":
			if _, ok := w.Value.([]any); !ok {
				return fmt.Errorf("condition %d: in needs a list", i+1)
			}
		case "gt", "lt":
			if _, ok := w.Value.(float64); !ok {
				return fmt.Errorf("condition %d: %s needs a number", i+1, w.Op)
			}
		default:
			return fmt.Errorf("condition %d: unknown op %q", i+1, w.Op)
		}
	}
	return nil
}

// ParseCustomRules reads one file, which holds one rule or a list of rules.
func ParseCustomRules(path string) ([]*CustomRule, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) > 1<<20 {
		return nil, errors.New("file larger than 1 MB")
	}
	var list []*CustomRule
	if t := strings.TrimSpace(string(b)); strings.HasPrefix(t, "[") {
		err = json.Unmarshal(b, &list)
	} else {
		var one CustomRule
		err = json.Unmarshal(b, &one)
		list = []*CustomRule{&one}
	}
	if err != nil {
		return nil, err
	}
	for _, c := range list {
		if err := c.validate(); err != nil {
			return nil, fmt.Errorf("%s: %w", c.ID, err)
		}
		c.File = filepath.Base(path)
	}
	return list, nil
}

// LoadCustomRules replaces the loaded custom rules with the files in dir.
// Errors are collected per file; good files load regardless.
func LoadCustomRules(dir string) (loaded int, errs []string) {
	m := map[string]*CustomRule{}
	var order []string
	if dir != "" {
		files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
		sort.Strings(files)
		for _, f := range files {
			list, err := ParseCustomRules(f)
			if err != nil {
				errs = append(errs, filepath.Base(f)+": "+err.Error())
				continue
			}
			for _, c := range list {
				if _, dup := m[c.ID]; dup {
					errs = append(errs, filepath.Base(f)+": "+c.ID+": defined twice")
					continue
				}
				m[c.ID] = c
				order = append(order, c.ID)
			}
		}
	}
	customMu.Lock()
	customRules, customOrder, customErrs = m, order, errs
	customMu.Unlock()
	return len(m), errs
}

// lookupRule finds a built-in or custom rule definition.
func lookupRule(id string) (ruleDef, bool) {
	if d, ok := rules[id]; ok {
		return d, true
	}
	customMu.RLock()
	defer customMu.RUnlock()
	if c := customRules[id]; c != nil {
		de := c.Title["de"]
		if de == "" {
			de = c.Title["en"]
		}
		return ruleDef{Severity: c.Severity, Technique: c.Technique, En: c.Title["en"], De: de}, true
	}
	return ruleDef{}, false
}

func fieldValue(r *Record, host, field string) (any, bool) {
	switch field {
	case "type":
		return r.Event.Type, true
	case "host":
		return host, true
	}
	v, ok := r.Event.Data[field]
	return v, ok
}

func asString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case nil:
		return ""
	default:
		b, _ := json.Marshal(x)
		return string(b)
	}
}

func (c *CustomRule) condMatch(i int, w Cond, v any, ok bool) bool {
	if w.Op == "exists" {
		return ok
	}
	if !ok {
		return w.Op == "not_equals"
	}
	// A list field (for example the users of ssh.failed) matches if any element does.
	if list, isList := v.([]any); isList {
		for _, el := range list {
			if c.condMatch(i, w, el, true) {
				return true
			}
		}
		return false
	}
	s, want := asString(v), asString(w.Value)
	switch w.Op {
	case "equals":
		return s == want
	case "not_equals":
		return s != want
	case "contains":
		return strings.Contains(s, want)
	case "prefix":
		return strings.HasPrefix(s, want)
	case "suffix":
		return strings.HasSuffix(s, want)
	case "regex":
		return c.re[i].MatchString(s)
	case "in":
		for _, x := range w.Value.([]any) {
			if asString(x) == s {
				return true
			}
		}
	case "gt", "lt":
		n, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return false
		}
		if w.Op == "gt" {
			return n > w.Value.(float64)
		}
		return n < w.Value.(float64)
	}
	return false
}

// Match reports whether a record matches the rule's event and conditions.
func (c *CustomRule) Match(r *Record, host string) bool {
	if strings.HasSuffix(c.Event, "*") {
		if !strings.HasPrefix(r.Event.Type, strings.TrimSuffix(c.Event, "*")) {
			return false
		}
	} else if r.Event.Type != c.Event {
		return false
	}
	for i, w := range c.Where {
		v, ok := fieldValue(r, host, w.Field)
		if !c.condMatch(i, w, v, ok) {
			return false
		}
	}
	return true
}

func (c *CustomRule) finding(r *Record, host, agentID string) finding {
	params := map[string]string{"host": host}
	for k, v := range r.Event.Data {
		if s := asString(v); len(s) <= 300 {
			params[k] = s
		}
	}
	keyFields := c.Key
	if len(keyFields) == 0 && c.Threshold != nil && c.Threshold.GroupBy != "" {
		keyFields = []string{c.Threshold.GroupBy}
	}
	var key []string
	for _, f := range keyFields {
		v, _ := fieldValue(r, host, f)
		key = append(key, asString(v))
	}
	return finding{Rule: c.ID, Key: c.ID + "|" + agentID + "|" + strings.Join(key, "|"), Params: params}
}

// customState counts threshold matches; the caller holds s.mu.
type customState struct {
	hits map[string][]time.Time
}

func (s *Server) evaluateCustom(a *AgentRec, r *Record) []finding {
	customMu.RLock()
	defer customMu.RUnlock()
	var out []finding
	for _, id := range customOrder {
		c := customRules[id]
		if !c.Match(r, a.Name) {
			continue
		}
		if t := c.Threshold; t != nil {
			if s.custom.hits == nil {
				s.custom.hits = map[string][]time.Time{}
			}
			g, _ := fieldValue(r, a.Name, t.GroupBy)
			k := c.ID + "|" + a.ID + "|" + asString(g)
			now, keep := r.Event.TS, []time.Time{}
			for _, at := range s.custom.hits[k] {
				if now.Sub(at) < time.Duration(t.Window)*time.Minute {
					keep = append(keep, at)
				}
			}
			keep = append(keep, now)
			if len(keep) < t.Count {
				s.custom.hits[k] = keep
				continue
			}
			delete(s.custom.hits, k)
			f := c.finding(r, a.Name, a.ID)
			f.Params["count"] = strconv.Itoa(len(keep))
			out = append(out, f)
			continue
		}
		out = append(out, c.finding(r, a.Name, a.ID))
	}
	return out
}

// CustomInfo describes loaded custom rules and load errors for the dashboard.
func CustomInfo() ([]RuleInfo, []string) {
	customMu.RLock()
	defer customMu.RUnlock()
	var out []RuleInfo
	for _, id := range customOrder {
		c := customRules[id]
		out = append(out, RuleInfo{ID: c.ID, Severity: c.Severity, Technique: c.Technique, Title: c.Title["en"],
			Trigger: c.Description, Custom: true, File: c.File})
	}
	return out, append([]string(nil), customErrs...)
}

// TryCustomRules runs the rules in one file against recorded events (lines
// of an event log, records or bare events) and prints every finding. It is
// the backend of `vigil-server rules test`.
func TryCustomRules(file string, events io.Reader, out io.Writer) (int, error) {
	list, err := ParseCustomRules(file)
	if err != nil {
		return 0, err
	}
	m := map[string]*CustomRule{}
	var order []string
	for _, c := range list {
		m[c.ID] = c
		order = append(order, c.ID)
	}
	customMu.Lock()
	customRules, customOrder = m, order
	customMu.Unlock()

	s := &Server{state: &State{Agents: map[string]*AgentRec{}}}
	sc := bufio.NewScanner(events)
	sc.Buffer(make([]byte, 1<<20), 4<<20)
	n, line := 0, 0
	for sc.Scan() {
		line++
		var raw struct {
			Rec   *Record `json:"rec"`
			Event *struct {
				Type string `json:"type"`
			} `json:"event"`
			Type string `json:"type"`
		}
		if json.Unmarshal(sc.Bytes(), &raw) != nil {
			continue
		}
		var rec Record
		switch {
		case raw.Rec != nil:
			rec = *raw.Rec
		case raw.Event != nil:
			json.Unmarshal(sc.Bytes(), &rec)
		case raw.Type != "":
			json.Unmarshal(sc.Bytes(), &rec.Event)
		default:
			continue
		}
		if rec.Source != "" && rec.Source != "agent" {
			continue
		}
		host := rec.Agent
		if host == "" {
			host = "host"
		}
		for _, f := range s.evaluateCustom(&AgentRec{ID: host, Name: host}, &rec) {
			n++
			fmt.Fprintf(out, "line %d  %s  %s\n", line, f.Rule, renderTitle(f.Rule, f.Params, "en"))
		}
	}
	return n, sc.Err()
}
