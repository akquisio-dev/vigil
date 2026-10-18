package server

import (
	"fmt"
	"strings"
	"time"
)

// One incident, one conversation: the first alert of an incident is sent at
// once, and so is every later alert that is more severe than anything sent
// for it so far (a login, then a reverse shell). The other alerts that join
// the incident are collected and sent as one update every few minutes, so
// twenty alerts of one intrusion are three messages instead of twenty.
//
// The state is in memory only. After a restart the next alert of an open
// incident is sent on its own again, which errs on the side of telling.

const defaultGroupMinutes = 10

type incidentNote struct {
	sent    int      // highest severity rank sent for the incident
	pending []string // alert ids waiting for the next update
	timer   *time.Timer
}

// groupWindow is how long follow-up alerts are collected; 0 sends every
// alert on its own.
func (s *Server) groupWindow() time.Duration {
	if s.groupDelay != 0 {
		return s.groupDelay
	}
	switch m := s.cfg.NotifyGroupMinutes; {
	case m < 0:
		return 0
	case m == 0:
		return defaultGroupMinutes * time.Minute
	default:
		return time.Duration(m) * time.Minute
	}
}

// notifyGrouped sends or holds one alert. The caller holds s.mu.
func (s *Server) notifyGrouped(al *Alert) {
	inc := s.incident(al.Incident)
	win := s.groupWindow()
	if inc == nil || win <= 0 {
		s.notify(s.alertMessage(al), false)
		return
	}
	if s.incNotes == nil {
		s.incNotes = map[string]*incidentNote{}
	}
	n := s.incNotes[inc.ID]
	if n == nil {
		n = &incidentNote{}
		s.incNotes[inc.ID] = n
	}
	if rank := severityRank[al.Severity]; rank > n.sent {
		n.sent = rank
		m := s.alertMessage(al)
		if len(n.pending) > 0 {
			// what was waiting is older and less severe; say so with it
			m.Title += s.lang(fmt.Sprintf(" (+%d more in this incident)", len(n.pending)),
				fmt.Sprintf(" (+%d weitere in diesem Vorfall)", len(n.pending)))
			n.pending = nil
			if n.timer != nil {
				n.timer.Stop()
				n.timer = nil
			}
		}
		s.notify(m, false)
		return
	}
	n.pending = append(n.pending, al.ID)
	if n.timer == nil {
		id := inc.ID
		n.timer = time.AfterFunc(win, func() { s.flushIncident(id) })
	}
}

// flushIncident sends the collected alerts of one incident as one message.
func (s *Server) flushIncident(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.incNotes[id]
	if n == nil {
		return
	}
	n.timer = nil
	ids := n.pending
	n.pending = nil
	if len(ids) == 0 {
		return
	}
	if m, ok := s.incidentUpdate(id, ids); ok {
		s.notify(m, false)
	}
}

// incidentUpdate builds the message for the alerts ids of incident id. Its
// severity is the highest among them, so notifiers filter it like the
// alerts themselves would have been.
func (s *Server) incidentUpdate(id string, ids []string) (message, bool) {
	var als []*Alert
	for _, aid := range ids {
		if al := s.alertByID(aid); al != nil {
			als = append(als, al)
		}
	}
	if len(als) == 0 {
		return message{}, false
	}
	sev, host := "info", ""
	counts := map[string]int{}
	var order []string
	for _, al := range als {
		if severityRank[al.Severity] > severityRank[sev] {
			sev = al.Severity
		}
		t := renderTitle(al.Rule, decodeParams(al.Detail), s.cfg.Language)
		if counts[t] == 0 {
			order = append(order, t)
		}
		counts[t]++
	}
	if a := s.state.Agents[als[0].Agent]; a != nil {
		host = a.Name
	}
	var b strings.Builder
	b.WriteString(s.lang(fmt.Sprintf("%d more alerts in the incident", len(als)),
		fmt.Sprintf("%d weitere Alarme im Vorfall", len(als))))
	if len(als) == 1 {
		b.Reset()
		b.WriteString(s.lang("1 more alert in the incident", "1 weiterer Alarm im Vorfall"))
	}
	b.WriteString(": ")
	for i, t := range order {
		if i == 5 {
			b.WriteString(s.lang(fmt.Sprintf("; and %d more", len(order)-5), fmt.Sprintf("; und %d weitere", len(order)-5)))
			break
		}
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString(t)
		if counts[t] > 1 {
			fmt.Fprintf(&b, " (%dx)", counts[t])
		}
	}
	link := ""
	if s.cfg.PublicURL != "" {
		link = strings.TrimRight(s.cfg.PublicURL, "/") + "/#/incidents/" + id
	}
	return message{Severity: sev, Title: clip(b.String(), 1500), Host: host, Link: link}, true
}

func (s *Server) lang(en, de string) string {
	if s.cfg.Language == "de" {
		return de
	}
	return en
}
