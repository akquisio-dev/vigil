package server

import (
	"errors"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/akquisio-dev/vigil/internal/notify"
)

// The senders live in internal/notify, shared with the agent's fallback.
type message = notify.Message
type retryAfter = notify.RetryAfter

func deliver(n NotifierConfig, m message) error { return notify.Deliver(n, m) }
func postJSON(target string, v any, hdr map[string]string) error {
	return notify.PostJSON(target, v, hdr)
}
func redact(err error) error          { return notify.Redact(err) }
func truncate(s string, n int) string { return notify.Truncate(s, n) }

func (s *Server) alertMessage(al *Alert) message {
	host := ""
	var groups []string
	if a := s.state.Agents[al.Agent]; a != nil {
		host, groups = a.Name, append([]string{}, a.Tags...)
	}
	link := ""
	if s.cfg.PublicURL != "" {
		link = strings.TrimRight(s.cfg.PublicURL, "/") + "/#/alerts/" + al.ID
	}
	return message{
		Severity: al.Severity, Title: renderTitle(al.Rule, decodeParams(al.Detail), s.cfg.Language),
		Host: host, Technique: al.Technique, Link: link, Groups: groups,
	}
}

// NotifierStatus is what the dashboard shows per notifier. Errors never
// contain the notifier URL or credentials, see redact.
type NotifierStatus struct {
	Name        string    `json:"name"`
	Type        string    `json:"type"`
	MinSeverity string    `json:"min_severity"`
	LastOK      time.Time `json:"last_ok,omitempty"`
	LastFail    time.Time `json:"last_fail,omitempty"`
	LastError   string    `json:"last_error,omitempty"`
	Failures    int       `json:"failures"` // messages lost in a row
}

type notifierHealth struct {
	mu sync.Mutex
	m  map[string]*NotifierStatus
}

func (s *Server) notifierStatus() []NotifierStatus {
	s.nh.mu.Lock()
	defer s.nh.mu.Unlock()
	out := make([]NotifierStatus, 0, len(s.cfg.Notifiers))
	for _, n := range s.cfg.Notifiers {
		st := NotifierStatus{Name: n.Name, Type: n.Type, MinSeverity: n.MinSeverity}
		if p := s.nh.m[n.Name]; p != nil {
			st = *p
		}
		out = append(out, st)
	}
	return out
}

// forGroups: a notifier limited to groups only gets messages of hosts in
// one of them.
func forGroups(n NotifierConfig, m message) bool {
	if len(n.Groups) == 0 {
		return true
	}
	for _, g := range n.Groups {
		for _, t := range m.Groups {
			if strings.EqualFold(g, t) {
				return true
			}
		}
	}
	return false
}

// notify delivers in the background; a slow mail server must never hold up
// event ingestion. It may be called with s.mu held.
func (s *Server) notify(m message, force bool) { s.notifyExcept(m, force, "") }

func (s *Server) notifyExcept(m message, force bool, skip string) {
	for _, n := range s.cfg.Notifiers {
		if n.Name == skip || !force && severityRank[m.Severity] < severityRank[n.MinSeverity] || !forGroups(n, m) {
			continue
		}
		go func(n NotifierConfig) {
			var err error
			for attempt := 0; attempt < 3; attempt++ {
				if err = deliver(n, m); err == nil {
					break
				}
				wait := time.Duration(attempt+1) * 5 * time.Second
				var ra *retryAfter
				if errors.As(err, &ra) && ra.Wait > wait && ra.Wait <= time.Minute {
					wait = ra.Wait
				}
				time.Sleep(wait)
			}
			s.noteDelivery(n, err)
		}(n)
	}
}

// noteDelivery tracks each notifier's health. A lost message raises
// notify.failed, sent through the other notifiers only, so a broken channel
// cannot feed on itself; the next successful delivery resolves it. It takes
// s.mu, so it must not be called with s.mu held.
func (s *Server) noteDelivery(n NotifierConfig, err error) {
	now := time.Now().UTC()
	s.nh.mu.Lock()
	if s.nh.m == nil {
		s.nh.m = map[string]*NotifierStatus{}
	}
	st := s.nh.m[n.Name]
	if st == nil {
		st = &NotifierStatus{Name: n.Name, Type: n.Type, MinSeverity: n.MinSeverity}
		s.nh.m[n.Name] = st
	}
	failedBefore := st.Failures > 0
	if err == nil {
		st.LastOK, st.Failures = now, 0
	} else {
		st.LastFail, st.LastError = now, clip(err.Error(), 300)
		st.Failures++
	}
	s.nh.mu.Unlock()

	key := "notify.failed|" + n.Name + "|"
	if err == nil {
		if failedBefore {
			s.mu.Lock()
			s.resolve(key, "system")
			s.saveLocked()
			s.mu.Unlock()
		}
		return
	}
	log.Printf("notify %s (%s): %v", n.Name, n.Type, err)
	s.mu.Lock()
	fresh := s.raise([]finding{{Rule: "notify.failed", Key: key, Params: map[string]string{"notifier": n.Name, "type": n.Type, "error": clip(err.Error(), 200)}}}, "", 0)
	s.saveLocked()
	// Forced past min_severity: a phone channel set to critical must hear
	// that the chat channel went dead.
	for _, al := range fresh {
		s.notifyExcept(s.alertMessage(al), true, n.Name)
	}
	s.mu.Unlock()
}

// TestNotifiers sends one message to every notifier (or the one named) and
// waits for the results. Used by `vigil-server notify test` and the
// dashboard.
func TestNotifiers(cfg *Config, name, text string) map[string]error {
	out := map[string]error{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, n := range cfg.Notifiers {
		if name != "" && n.Name != name {
			continue
		}
		wg.Add(1)
		go func(n NotifierConfig) {
			defer wg.Done()
			err := deliver(n, message{Severity: "info", Text: text})
			mu.Lock()
			out[n.Name] = err
			mu.Unlock()
		}(n)
	}
	wg.Wait()
	return out
}
