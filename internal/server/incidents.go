package server

import (
	"net/http"
	"sort"
	"strings"
	"time"
)

// An Incident groups the alerts of one intrusion (or one false alarm) on a
// host, so they are triaged, owned and closed together.
type Incident struct {
	ID       string    `json:"id"`
	Agent    string    `json:"agent"`
	Status   string    `json:"status"` // open | investigating | contained | closed
	Owner    string    `json:"owner,omitempty"`
	Severity string    `json:"severity"`
	Start    string    `json:"start_alert"` // the alert that opened it; its title names the incident
	Alerts   []string  `json:"alerts"`
	Notes    []Note    `json:"notes,omitempty"`
	Created  time.Time `json:"created"`
	// Last is the time of the newest alert; new alerts join while it is recent.
	Last   time.Time  `json:"last"`
	Closed *time.Time `json:"closed,omitempty"`
}

type Note struct {
	By   string    `json:"by"`
	At   time.Time `json:"at"`
	Text string    `json:"text"`
}

const (
	incidentWindow = 2 * time.Hour
	maxIncidents   = 2000
)

var incidentStatus = map[string]bool{"open": true, "investigating": true, "contained": true, "closed": true}

// correlate puts fresh alerts into incidents. Rules, in this order:
//  1. An alert joins the newest incident on its host that is not closed and
//     had an alert within incidentWindow before it.
//  2. Otherwise a high or critical alert opens a new incident, and takes the
//     host's alerts from incidentWindow before it that are in no incident
//     (the login that came before the damage, for example).
//  3. Alerts about the agent itself never open an incident; planned restarts
//     would otherwise fill the list. They still join one.
//
// The caller holds s.mu. Alerts must be in creation order.
func (s *Server) correlate(fresh []*Alert) {
	for _, al := range fresh {
		if al.Incident != "" || al.Agent == "" {
			continue
		}
		var inc *Incident
		for i := len(s.state.Incidents) - 1; i >= 0; i-- {
			c := s.state.Incidents[i]
			if c.Agent == al.Agent && c.Status != "closed" &&
				!al.Created.Before(c.Created.Add(-incidentWindow)) && !al.Created.After(c.Last.Add(incidentWindow)) {
				inc = c
				break
			}
		}
		if inc == nil {
			if severityRank[al.Severity] < severityRank["high"] || strings.HasPrefix(al.Rule, "agent.") {
				continue
			}
			inc = &Incident{ID: newID(8), Agent: al.Agent, Status: "open", Severity: al.Severity, Start: al.ID,
				Created: al.Created, Last: al.Created}
			s.state.Incidents = append(s.state.Incidents, inc)
			for _, prev := range s.state.Alerts {
				if prev != al && prev.Agent == al.Agent && prev.Incident == "" &&
					!prev.Created.After(al.Created) && al.Created.Sub(prev.Created) <= incidentWindow {
					s.attach(inc, prev)
				}
			}
		}
		s.attach(inc, al)
	}
	if over := len(s.state.Incidents) - maxIncidents; over > 0 {
		s.state.Incidents = append([]*Incident{}, s.state.Incidents[over:]...)
	}
}

func (s *Server) attach(inc *Incident, al *Alert) {
	if al.Incident != "" {
		if old := s.incident(al.Incident); old != nil {
			for i, id := range old.Alerts {
				if id == al.ID {
					old.Alerts = append(old.Alerts[:i:i], old.Alerts[i+1:]...)
					break
				}
			}
		}
	}
	al.Incident = inc.ID
	inc.Alerts = append(inc.Alerts, al.ID)
	if severityRank[al.Severity] > severityRank[inc.Severity] {
		inc.Severity = al.Severity
	}
	if al.Created.After(inc.Last) {
		inc.Last = al.Created
	}
	if al.Created.Before(inc.Created) {
		inc.Created = al.Created
	}
}

func (s *Server) incident(id string) *Incident {
	for _, c := range s.state.Incidents {
		if c.ID == id {
			return c
		}
	}
	return nil
}

func (s *Server) alertByID(id string) *Alert {
	for _, al := range s.state.Alerts {
		if al.ID == id {
			return al
		}
	}
	return nil
}

type incidentView struct {
	*Incident
	Title  string `json:"title"`
	Host   string `json:"host"`
	Count  int    `json:"count"`
	Unread int    `json:"open_alerts"`
}

func (s *Server) viewIncident(c *Incident, lg string) incidentView {
	v := incidentView{Incident: c, Count: len(c.Alerts)}
	if a := s.state.Agents[c.Agent]; a != nil {
		v.Host = a.Name
	}
	if al := s.alertByID(c.Start); al != nil {
		v.Title = renderTitle(al.Rule, decodeParams(al.Detail), lg)
	}
	for _, id := range c.Alerts {
		if al := s.alertByID(id); al != nil && al.Status == "open" {
			v.Unread++
		}
	}
	return v
}

func (s *Server) handleIncidents(w http.ResponseWriter, r *http.Request, sess *session) {
	status := r.URL.Query().Get("status")
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []incidentView{}
	var closeTimes []time.Duration
	for i := len(s.state.Incidents) - 1; i >= 0; i-- {
		c := s.state.Incidents[i]
		if c.Closed != nil && time.Since(*c.Closed) < 30*24*time.Hour {
			closeTimes = append(closeTimes, c.Closed.Sub(c.Created))
		}
		if status == "active" && c.Status == "closed" || status != "" && status != "active" && c.Status != status {
			continue
		}
		if len(out) < 300 {
			out = append(out, s.viewIncident(c, lang(r)))
		}
	}
	var median any
	if len(closeTimes) > 0 {
		sort.Slice(closeTimes, func(i, j int) bool { return closeTimes[i] < closeTimes[j] })
		median = int(closeTimes[len(closeTimes)/2].Seconds())
	}
	writeJSON(w, map[string]any{"incidents": out, "mttc_seconds": median})
}

func (s *Server) handleIncident(w http.ResponseWriter, r *http.Request, sess *session) {
	s.mu.Lock()
	c := s.incident(r.PathValue("id"))
	if c == nil {
		s.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	view := s.viewIncident(c, lang(r))
	alerts := []alertView{}
	var from, to time.Time
	for _, id := range c.Alerts {
		if al := s.alertByID(id); al != nil {
			alerts = append(alerts, s.viewAlert(al, lang(r)))
			if from.IsZero() || al.Created.Before(from) {
				from = al.Created
			}
			if al.Updated.After(to) {
				to = al.Updated
			}
		}
	}
	s.mu.Unlock()
	sort.Slice(alerts, func(i, j int) bool { return alerts[i].Created.Before(alerts[j].Created) })

	// Timeline: the host's events around the alerts, and the SSH login that
	// most likely started the session (the last one before the first alert).
	events := []Record{}
	var login *Record
	s.store.Each(func(rec Record) {
		if rec.Agent != c.Agent {
			return
		}
		if rec.Event.Type == "ssh.login" && !rec.Time.After(from) && from.Sub(rec.Time) < 12*time.Hour {
			cp := rec
			login = &cp
		}
		if !rec.Time.Before(from.Add(-30*time.Minute)) && !rec.Time.After(to.Add(30*time.Minute)) &&
			rec.Event.Type != "port.snapshot" && rec.Event.Type != "agent.heartbeat" && len(events) < 400 {
			events = append(events, rec)
		}
	})
	names := s.agentNames()
	role := s.roleFor(sess)
	evs := make([]viewRecord, len(events))
	for i, rec := range events {
		evs[i] = s.view(rec, names, role)
	}
	var lv *viewRecord
	if login != nil {
		v := s.view(*login, names, role)
		lv = &v
	}
	writeJSON(w, map[string]any{"incident": view, "alerts": alerts, "events": evs, "login": lv})
}

func (s *Server) handleIncidentAction(w http.ResponseWriter, r *http.Request, sess *session) {
	var req struct {
		Status string `json:"status"`
		Note   string `json:"note"`
		Alert  string `json:"alert"`
	}
	if !decode(r, w, &req) {
		return
	}
	action, id := r.PathValue("action"), r.PathValue("id")
	now := time.Now().UTC()
	s.mu.Lock()
	var c *Incident
	if id == "new" {
		al := s.alertByID(req.Alert)
		if al == nil || action != "create" {
			s.mu.Unlock()
			http.NotFound(w, r)
			return
		}
		c = &Incident{ID: newID(8), Agent: al.Agent, Status: "open", Severity: al.Severity, Start: al.ID, Created: al.Created, Last: al.Created}
		s.state.Incidents = append(s.state.Incidents, c)
		s.attach(c, al)
	} else if c = s.incident(id); c == nil {
		s.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	switch action {
	case "create":
	case "status":
		if !incidentStatus[req.Status] {
			s.mu.Unlock()
			http.Error(w, "bad status", http.StatusBadRequest)
			return
		}
		c.Status = req.Status
		c.Closed = nil
		if req.Status == "closed" {
			c.Closed = &now
		}
	case "assign":
		c.Owner = sess.User
		if c.Status == "open" {
			c.Status = "investigating"
		}
	case "note":
		text := strings.TrimSpace(req.Note)
		if text == "" || len(text) > 4000 || len(c.Notes) >= 200 {
			s.mu.Unlock()
			http.Error(w, "bad note", http.StatusBadRequest)
			return
		}
		c.Notes = append(c.Notes, Note{By: sess.User, At: now, Text: text})
	case "add":
		al := s.alertByID(req.Alert)
		if al == nil {
			s.mu.Unlock()
			http.NotFound(w, r)
			return
		}
		s.attach(c, al)
	default:
		s.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	s.saveLocked()
	s.mu.Unlock()
	s.audit(sess.User, "incident."+action, map[string]any{"incident": c.ID, "status": req.Status, "alert": req.Alert})
	writeJSON(w, map[string]string{"id": c.ID})
}
