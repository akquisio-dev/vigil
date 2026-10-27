package server

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// The daily summary is one message about the whole fleet, sent whether or
// not anything happened: a quiet day says so, and a summary that does not
// arrive says that something is wrong with vigil. Plain text, so it works
// on every notifier type.

// summaryAt parses summary_time ("07:30", server local time).
func summaryAt(v string) (h, m int, err error) {
	t, err := time.Parse("15:04", v)
	if err != nil {
		return 0, 0, fmt.Errorf("summary_time %q: want HH:MM", v)
	}
	return t.Hour(), t.Minute(), nil
}

// summaryDue reports whether today's summary is due and not yet sent.
func (s *Server) summaryDue(now time.Time) bool {
	if s.cfg.SummaryTime == "" {
		return false
	}
	h, m, err := summaryAt(s.cfg.SummaryTime)
	if err != nil {
		return false
	}
	slot := time.Date(now.Year(), now.Month(), now.Day(), h, m, 0, 0, now.Location())
	return !now.Before(slot) && s.state.LastSummary.Before(slot)
}

// checkSummary runs every minute.
func (s *Server) checkSummary() {
	now := time.Now()
	s.mu.Lock()
	if !s.summaryDue(now) {
		s.mu.Unlock()
		return
	}
	s.state.LastSummary = now.UTC()
	s.saveLocked()
	s.mu.Unlock()
	s.sendSummary(now)
}

// sendSummary delivers the summary to every notifier that has not turned
// it off, whatever its min_severity.
func (s *Server) sendSummary(now time.Time) {
	text := s.summaryText(now)
	for _, n := range s.cfg.Notifiers {
		// the summary covers the whole network: never to a notifier of some groups
		if n.Summary != nil && !*n.Summary || len(n.Groups) > 0 {
			continue
		}
		go func(n NotifierConfig) {
			err := deliver(n, message{Severity: "info", Text: text})
			if err != nil {
				time.Sleep(30 * time.Second)
				err = deliver(n, message{Severity: "info", Text: text})
			}
			s.noteDelivery(n, err)
		}(n)
	}
}

// summaryText renders the summary for the 24 hours before now.
func (s *Server) summaryText(now time.Time) string {
	de := s.cfg.Language == "de"
	L := func(en, d string) string {
		if de {
			return d
		}
		return en
	}
	num := func(n int) string { return groupDigits(n, de) }
	since := now.Add(-24 * time.Hour)
	sevName := map[string][2]string{"critical": {"critical", "kritisch"}, "high": {"high", "hoch"},
		"medium": {"medium", "mittel"}, "low": {"low", "niedrig"}, "info": {"info", "info"}}
	sev := func(k string) string {
		if de {
			return sevName[k][1]
		}
		return sevName[k][0]
	}

	s.mu.Lock()
	bySev := map[string]int{}
	byRule := map[string]int{}
	openAlerts := 0
	for _, al := range s.state.Alerts {
		if al.Status == "open" {
			openAlerts++
		}
		if al.Created.Before(since) {
			continue
		}
		bySev[al.Severity]++
		if severityRank[al.Severity] >= severityRank["medium"] {
			byRule[al.Rule]++
		}
	}
	openInc := 0
	for _, c := range s.state.Incidents {
		if c.Status != "closed" {
			openInc++
		}
	}
	var hosts, down []string
	kev, fixable := 0, 0
	for _, a := range s.state.Agents {
		hosts = append(hosts, a.Name)
		switch {
		case a.Stopped:
			down = append(down, a.Name+L(" (stopped)", " (gestoppt)"))
		case a.Silent:
			down = append(down, a.Name+L(" (silent since ", " (still seit ")+a.LastSeen.In(now.Location()).Format("02.01. 15:04")+")")
		}
		if a.Vulns != nil {
			kev += len(a.Vulns.Exploited)
			for _, n := range a.Vulns.Fixable {
				fixable += n
			}
		}
	}
	lastTest := map[string]*SelfTest{}
	for _, t := range s.state.SelfTests {
		if t.Finished.IsZero() {
			continue
		}
		if p := lastTest[t.Agent]; p == nil || t.Finished.After(p.Finished) {
			lastTest[t.Agent] = t
		}
	}
	var failedTests []string
	for id, t := range lastTest {
		if t.Status == "failed" {
			name := id
			if a := s.state.Agents[id]; a != nil {
				name = a.Name
			}
			failedTests = append(failedTests, name)
		}
	}
	s.mu.Unlock()
	sort.Strings(down)
	sort.Strings(failedTests)

	var lines []string
	head := L("vigil daily summary ", "vigil Tagesbericht ") + now.Format(L("2006-01-02", "02.01.2006"))
	lines = append(lines, head)

	var parts []string
	for _, k := range []string{"critical", "high", "medium", "low"} {
		if bySev[k] > 0 {
			parts = append(parts, num(bySev[k])+" "+sev(k))
		}
	}
	if len(parts) == 0 {
		parts = []string{L("none", "keine")}
	}
	lines = append(lines, L("Alerts (24 h): ", "Alarme (24 h): ")+strings.Join(parts, ", "))
	if top := topKeys(byRule, 3); len(top) > 0 {
		var t []string
		for _, k := range top {
			t = append(t, fmt.Sprintf("%s (%d)", k, byRule[k]))
		}
		lines = append(lines, L("Most frequent: ", "Am häufigsten: ")+strings.Join(t, ", "))
	}
	plural := func(n int, one, many string) string {
		if n == 1 {
			return num(n) + " " + one
		}
		return num(n) + " " + many
	}
	lines = append(lines, L("Open: ", "Offen: ")+plural(openAlerts, L("alert", "Alarm"), L("alerts", "Alarme"))+", "+
		plural(openInc, L("incident", "Vorfall"), L("incidents", "Vorfälle")))

	hl := fmt.Sprintf(L("Hosts: %d of %d reporting", "Hosts: %d von %d melden sich"), len(hosts)-len(down), len(hosts))
	if len(down) > 0 {
		hl += "; " + L("not reporting: ", "nicht erreichbar: ") + strings.Join(down, ", ")
	}
	lines = append(lines, hl)

	switch {
	case len(lastTest) == 0:
	case len(failedTests) > 0:
		lines = append(lines, L("Self test failed on: ", "Selbsttest fehlgeschlagen auf: ")+strings.Join(failedTests, ", "))
	default:
		lines = append(lines, L("Self test: last run passed on every host", "Selbsttest: letzter Lauf auf allen Hosts bestanden"))
	}

	if s.cfg.VulnLookup {
		lines = append(lines, fmt.Sprintf(L("Vulnerabilities: %s exploited in the wild, %s fixable by updating", "Schwachstellen: %s aktiv ausgenutzt, %s per Update behebbar"), num(kev), num(fixable)))
	}

	if v := s.attackStats(2); v != nil && v.Ready && v.Totals.IPs > 0 {
		t := v.Totals
		al := fmt.Sprintf(L("Attacks since yesterday 00:00 UTC: %s addresses, %s SSH attempts, %s web probes",
			"Angriffe seit gestern 00:00 UTC: %s Adressen, %s SSH-Versuche, %s Web-Abfragen"), num(t.IPs), num(t.SSH), num(t.Web))
		al += fmt.Sprintf(L("; %d aimed, %d successful, %d campaigns", "; %d gezielt, %d erfolgreich, %d Kampagnen"), t.Targeted, t.Success, t.Campaigns)
		lines = append(lines, al)
		if len(v.Countries) > 0 {
			byIPs := append([]geoCount(nil), v.Countries...)
			sort.SliceStable(byIPs, func(i, j int) bool { return byIPs[i].IPs > byIPs[j].IPs })
			var c []string
			for i, g := range byIPs {
				if i == 3 {
					break
				}
				c = append(c, fmt.Sprintf("%s %s", g.Key, num(g.IPs)))
			}
			lines = append(lines, L("Most addresses from: ", "Die meisten Adressen aus: ")+strings.Join(c, ", "))
		}
	} else if v != nil && v.Ready {
		lines = append(lines, L("Attacks since yesterday 00:00 UTC: none seen", "Angriffe seit gestern 00:00 UTC: keine gesehen"))
	}

	var bad []string
	for _, st := range s.notifierStatus() {
		if st.Failures > 0 {
			bad = append(bad, st.Name)
		}
	}
	if len(bad) > 0 {
		lines = append(lines, L("Notifiers failing: ", "Benachrichtigung gestört: ")+strings.Join(bad, ", "))
	}
	if ok, msg := s.store.Health(); !ok {
		lines = append(lines, L("Event log: ", "Ereignisprotokoll: ")+msg)
	}
	if s.cfg.PublicURL != "" {
		lines = append(lines, strings.TrimRight(s.cfg.PublicURL, "/")+"/")
	}
	return truncate(strings.Join(lines, "\n"), 1900)
}

// topKeys returns the n keys with the highest counts, ties by name.
func topKeys(m map[string]int, n int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if m[keys[i]] != m[keys[j]] {
			return m[keys[i]] > m[keys[j]]
		}
		return keys[i] < keys[j]
	})
	if len(keys) > n {
		keys = keys[:n]
	}
	return keys
}

// groupDigits writes 12345 as 12,345 (en) or 12.345 (de).
func groupDigits(n int, de bool) string {
	s := fmt.Sprint(n)
	if n < 0 || len(s) <= 3 {
		return s
	}
	sep := ","
	if de {
		sep = "."
	}
	var b strings.Builder
	pre := len(s) % 3
	if pre > 0 {
		b.WriteString(s[:pre])
	}
	for i := pre; i < len(s); i += 3 {
		if b.Len() > 0 {
			b.WriteString(sep)
		}
		b.WriteString(s[i : i+3])
	}
	return b.String()
}
