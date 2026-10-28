package server

import (
	"fmt"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Incidents carry a running number besides their random ID, shown as
// INC-0042: short enough to say on the phone, type into a chat or grep for
// in a message. Numbers are never given twice, also after old incidents
// were dropped (maxIncidents), because the next one is kept in the state.

const incidentPrefix = "INC-"

// IncidentRef is the reference of incident number no.
func IncidentRef(no int) string {
	if no <= 0 {
		return ""
	}
	return fmt.Sprintf("%s%04d", incidentPrefix, no)
}

// parseIncidentRef reads INC-0042, inc-42, #42 or 42.
func parseIncidentRef(s string) (int, bool) {
	s = strings.TrimSpace(s)
	switch {
	case len(s) > len(incidentPrefix) && strings.EqualFold(s[:len(incidentPrefix)], incidentPrefix):
		s = s[len(incidentPrefix):]
	case strings.HasPrefix(s, "#"):
		s = s[1:]
	}
	if s == "" || len(s) > 9 {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	return n, err == nil && n > 0
}

// numberIncidents gives the incidents from before numbers their numbers, in
// the order they were opened, and makes sure the next number is free.
func (st *State) numberIncidents() {
	var bare []*Incident
	for _, c := range st.Incidents {
		if c.No == 0 {
			bare = append(bare, c)
		} else if c.No >= st.NextIncident {
			st.NextIncident = c.No + 1
		}
	}
	if st.NextIncident < 1 {
		st.NextIncident = 1
	}
	sort.SliceStable(bare, func(i, j int) bool { return bare[i].Created.Before(bare[j].Created) })
	for _, c := range bare {
		c.No = st.NextIncident
		st.NextIncident++
	}
}

// newIncident opens an incident with alert al as its start and the next
// number. The caller holds s.mu.
func (s *Server) newIncident(al *Alert) *Incident {
	if s.state.NextIncident < 1 {
		s.state.numberIncidents()
	}
	c := &Incident{ID: newID(8), No: s.state.NextIncident, Agent: al.Agent, Status: "open", Severity: al.Severity, Start: al.ID,
		Created: al.Created, Last: al.Created}
	s.state.NextIncident++
	s.state.Incidents = append(s.state.Incidents, c)
	return c
}

// findIncident finds an incident by its ID or its reference.
func (st *State) findIncident(id string) *Incident {
	for _, c := range st.Incidents {
		if c.ID == id {
			return c
		}
	}
	if no, ok := parseIncidentRef(id); ok {
		for _, c := range st.Incidents {
			if c.No == no {
				return c
			}
		}
	}
	return nil
}

func (st *State) alert(id string) *Alert {
	for _, al := range st.Alerts {
		if al.ID == id {
			return al
		}
	}
	return nil
}

// IncidentList prints the incidents of the data directory, newest first,
// for `vigil-server incident list`. It reads state.json and changes
// nothing, so it can run beside the server.
func IncidentList(dataDir, lang string, all bool) (string, error) {
	st, err := LoadState(dataDir)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	n := 0
	for i := len(st.Incidents) - 1; i >= 0; i-- {
		c := st.Incidents[i]
		if !all && c.Status == "closed" {
			continue
		}
		n++
		// the hostname: names in the dashboard are often long
		host := c.Agent
		if a := st.Agents[c.Agent]; a != nil {
			host = a.Hostname
			if host == "" {
				host = a.Name
			}
		}
		fmt.Fprintf(&b, "%-9s  %-13s  %-8s  %-16s  %s  %s\n", IncidentRef(c.No), c.Status, c.Severity, clip(host, 16),
			c.Last.Local().Format("2006-01-02 15:04"), st.incidentTitle(c, lang))
	}
	if n == 0 {
		if all {
			return "no incidents\n", nil
		}
		return "no open incidents (-all shows the closed ones)\n", nil
	}
	return b.String(), nil
}

// IncidentText is one incident as Markdown, for `vigil-server incident show`
// and to paste into a chat: what it is, its alerts in time order with their
// details, and the notes. ref is INC-0042, 42 or the incident's ID.
func IncidentText(dataDir, publicURL, lang, ref string) (string, error) {
	st, err := LoadState(dataDir)
	if err != nil {
		return "", err
	}
	c := st.findIncident(ref)
	if c == nil {
		return "", fmt.Errorf("no incident %s in %s", ref, filepath.Join(dataDir, "state.json"))
	}
	return st.incidentText(c, publicURL, lang), nil
}

func (st *State) incidentTitle(c *Incident, lang string) string {
	if al := st.alert(c.Start); al != nil {
		return renderTitle(al.Rule, decodeParams(al.Detail), lang)
	}
	return c.ID
}

func (st *State) incidentText(c *Incident, publicURL, lang string) string {
	var b strings.Builder
	p := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }
	host, hostname := c.Agent, ""
	if a := st.Agents[c.Agent]; a != nil {
		host, hostname = a.Name, a.Hostname
	}
	ts := func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05Z") }
	p("# %s: %s\n\n", IncidentRef(c.No), st.incidentTitle(c, lang))
	p("- Host: %s", host)
	if hostname != "" && hostname != host {
		p(" (%s)", hostname)
	}
	p("\n- Status: %s, severity %s, owner %s\n", c.Status, c.Severity, orDash(c.Owner))
	p("- Opened %s, last alert %s", ts(c.Created), ts(c.Last))
	if c.Closed != nil {
		p(", closed %s", ts(*c.Closed))
	}
	p("\n- ID %s", c.ID)
	if publicURL != "" {
		p(", %s/#/incidents/%s", strings.TrimRight(publicURL, "/"), IncidentRef(c.No))
	}
	p("\n\n## Alerts (%d)\n\n", len(c.Alerts))
	var als []*Alert
	for _, id := range c.Alerts {
		if al := st.alert(id); al != nil {
			als = append(als, al)
		}
	}
	sort.SliceStable(als, func(i, j int) bool { return als[i].Created.Before(als[j].Created) })
	for _, al := range als {
		p("- %s  %s  %s: %s", ts(al.Created), al.Severity, al.Rule, renderTitle(al.Rule, decodeParams(al.Detail), lang))
		if al.Count > 1 {
			p(" (%dx until %s)", al.Count, ts(al.Updated))
		}
		p(" [%s", al.Status)
		if al.Technique != "" {
			p(", %s", al.Technique)
		}
		p("]\n")
		// the details, without the title parameters already in the title
		params := decodeParams(al.Detail)
		keys := make([]string, 0, len(params))
		for k, v := range params {
			// the host is named once at the top
			if v != "" && !(k == "host" && v == host) {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		for _, k := range keys {
			p("  - %s: %s\n", k, clip(params[k], 300))
		}
	}
	if missing := len(c.Alerts) - len(als); missing > 0 {
		p("- %d older alerts are no longer kept\n", missing)
	}
	if len(c.Notes) > 0 {
		p("\n## Notes\n\n")
		for _, n := range c.Notes {
			p("- %s, %s: %s\n", ts(n.At), n.By, strings.ReplaceAll(n.Text, "\n", "\n  "))
		}
	}
	return b.String()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// GET /api/ui/incidents/{id}/text: the incident as short Markdown to paste
// into a chat or a ticket (the same text as `vigil-server incident show`).
func (s *Server) handleIncidentText(w http.ResponseWriter, r *http.Request, sess *session) {
	s.mu.Lock()
	c := s.incident(r.PathValue("id"))
	if c == nil {
		s.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	text := s.state.incidentText(c, s.cfg.PublicURL, lang(r))
	id, ref := c.ID, IncidentRef(c.No)
	s.mu.Unlock()
	s.audit(sess.User, "admin.report", map[string]any{"incident": id, "ref": ref, "format": "text"})
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte(text))
}
