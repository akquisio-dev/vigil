package server

import (
	"bufio"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

// Incident reports: everything about one incident in a document that can
// be handed on (Markdown) or printed to PDF (HTML), with the hashes of the
// event chain behind it, so a reader can check later with `vigil-server
// verify` that the log the report was made from has not been changed.

type reportData struct {
	Incident  incidentView
	Generated time.Time
	By        string
	Alerts    []alertView
	Events    []Record
	Snapshots []SnapshotRef
	Hashes    map[uint64]string
	HeadSeq   uint64
	HeadHash  string
	Tactics   []string
	Entities  map[string][]string
	Metrics   [][2]string
	FirstSeen time.Time
}

// hashesFor returns the chain hash of the given records (by seq), read from
// the day files around the given window.
func (s *Store) hashesFor(seqs map[uint64]bool, from, to time.Time) map[uint64]string {
	out := map[uint64]string{}
	if len(seqs) == 0 {
		return out
	}
	first := from.UTC().AddDate(0, 0, -1).Format("2006-01-02")
	last := to.UTC().AddDate(0, 0, 1).Format("2006-01-02")
	for _, f := range s.files() {
		day := strings.TrimSuffix(filepath.Base(f), ".jsonl")
		if day < first || day > last {
			continue
		}
		fh, err := os.Open(f)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 256*1024), proto.MaxBodyBytes*2)
		for sc.Scan() {
			var cl chainLine
			if json.Unmarshal(sc.Bytes(), &cl) != nil {
				continue
			}
			var r struct {
				Seq uint64 `json:"seq"`
			}
			if json.Unmarshal(cl.Rec, &r) == nil && seqs[r.Seq] {
				out[r.Seq] = cl.Hash
			}
		}
		fh.Close()
	}
	return out
}

func fmtDuration(d time.Duration) string {
	if d < 0 {
		return "·"
	}
	d = d.Round(time.Second)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dd %dh", int(d.Hours())/24, int(d.Hours())%24)
}

// reportFor collects the report. It reads the log; the caller does not
// hold s.mu.
func (s *Server) reportFor(id, lg, by string) (*reportData, bool) {
	s.mu.Lock()
	c := s.incident(id)
	if c == nil {
		s.mu.Unlock()
		return nil, false
	}
	rd := &reportData{Incident: s.viewIncident(c, lg), Generated: time.Now().UTC(), By: by, Hashes: map[uint64]string{}}
	cp := *c
	rd.Incident.Incident = &cp
	var from, to time.Time
	var firstAck *time.Time
	seqs := map[uint64]bool{}
	tactic := map[string]bool{}
	for _, aid := range c.Alerts {
		al := s.alertByID(aid)
		if al == nil {
			continue
		}
		rd.Alerts = append(rd.Alerts, s.viewAlert(al, lg))
		if from.IsZero() || al.Created.Before(from) {
			from = al.Created
		}
		if al.Updated.After(to) {
			to = al.Updated
		}
		if al.Acked != nil && (firstAck == nil || al.Acked.Before(*firstAck)) {
			t := *al.Acked
			firstAck = &t
		}
		for _, sq := range al.Seqs {
			seqs[sq] = true
		}
		if tc := tactics[al.Technique]; tc != "" {
			tactic[tc+" ("+al.Technique+")"] = true
		}
	}
	if a := s.state.Agents[c.Agent]; a != nil {
		for _, ref := range a.SnapshotIndex {
			if !ref.Time.Before(from.Add(-30*time.Minute)) && !ref.Time.After(to.Add(30*time.Minute)) {
				rd.Snapshots = append(rd.Snapshots, ref)
				seqs[ref.Seq] = true
			}
		}
	}
	s.mu.Unlock()
	sort.Slice(rd.Alerts, func(i, j int) bool { return rd.Alerts[i].Created.Before(rd.Alerts[j].Created) })
	for t := range tactic {
		rd.Tactics = append(rd.Tactics, t)
	}
	sort.Strings(rd.Tactics)

	// Events of the host around the alerts, and the first event behind the
	// first alert: detection delay is measured from the host's own time.
	if from.IsZero() {
		from, to = c.Created, c.Last
	}
	rd.Entities = map[string][]string{}
	seen := map[string]bool{}
	s.store.Between(from.Add(-30*time.Minute), to.Add(30*time.Minute), func(rec Record) bool {
		if rec.Agent != c.Agent {
			return true
		}
		t := recordTime(rec)
		if seqs[rec.Seq] && (rd.FirstSeen.IsZero() || t.Before(rd.FirstSeen)) {
			rd.FirstSeen = t
		}
		if t.Before(from.Add(-30*time.Minute)) || t.After(to.Add(30*time.Minute)) {
			return true
		}
		switch rec.Event.Type {
		case "port.snapshot", "agent.heartbeat", "posture.report", "system.packages", "system.apps", "secrets.scan", "suid.scan", "integrity.scan", "net.volume":
			return true
		}
		for _, e := range entities(rec.Event) {
			if k := e.Kind + "|" + e.Value; !seen[k] && len(rd.Entities[e.Kind]) < 50 {
				seen[k] = true
				rd.Entities[e.Kind] = append(rd.Entities[e.Kind], e.Value)
			}
		}
		if rec.Event.Type == "forensics.snapshot" {
			rec = slim(rec)
		}
		if len(rd.Events) < 1000 {
			rd.Events = append(rd.Events, rec)
			seqs[rec.Seq] = true
		}
		return true
	})
	sort.SliceStable(rd.Events, func(i, j int) bool { return recordTime(rd.Events[i]).Before(recordTime(rd.Events[j])) })
	rd.Hashes = s.store.hashesFor(seqs, from.Add(-30*time.Minute), to.Add(30*time.Minute))
	rd.HeadSeq, rd.HeadHash = s.store.Head()

	first := from
	m := [][2]string{}
	if !rd.FirstSeen.IsZero() {
		m = append(m, [2]string{"Detection delay (first event to first alert)", fmtDuration(first.Sub(rd.FirstSeen))})
	}
	if firstAck != nil {
		m = append(m, [2]string{"Time to acknowledge (first alert to first acknowledgement)", fmtDuration(firstAck.Sub(first))})
	}
	if c.Closed != nil {
		m = append(m, [2]string{"Time to close (first alert to closed)", fmtDuration(c.Closed.Sub(first))})
	}
	m = append(m, [2]string{"Alerts", fmt.Sprint(len(rd.Alerts))})
	rd.Metrics = m
	return rd, true
}

func mdEscape(s string) string {
	r := strings.NewReplacer("|", "\\|", "\n", " ", "\r", " ", "`", "'")
	return r.Replace(s)
}

func eventSummary(rec Record) string {
	d := rec.Event.Data
	keys := make([]string, 0, len(d))
	for k := range d {
		switch k {
		case "diff", "processes", "connections", "journal", "target", "sessions", "modules", "ports", "checks", "certs", "backups", "packages":
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		v := d[k]
		var s string
		switch x := v.(type) {
		case string:
			s = x
		default:
			raw, _ := json.Marshal(x)
			s = string(raw)
		}
		if len(s) > 200 {
			s = s[:200] + "…"
		}
		b.WriteString(k + "=" + s + "  ")
	}
	out := strings.TrimSpace(b.String())
	if len(out) > 600 {
		out = out[:600] + "…"
	}
	return out
}

func (rd *reportData) markdown() string {
	var b strings.Builder
	c := rd.Incident
	p := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }
	title := c.Title
	if title == "" {
		title = c.ID
	}
	p("# Incident %s: %s\n\n", c.ID, mdEscape(title))
	p("| | |\n|---|---|\n")
	p("| Host | %s |\n| Status | %s |\n| Severity | %s |\n| Owner | %s |\n", mdEscape(c.Host), c.Status, c.Severity, mdEscape(c.Owner))
	p("| Opened | %s |\n", c.Created.UTC().Format(time.RFC3339))
	if c.Closed != nil {
		p("| Closed | %s |\n", c.Closed.UTC().Format(time.RFC3339))
	}
	p("| Report | %s by %s |\n\n", rd.Generated.Format(time.RFC3339), mdEscape(rd.By))
	p("## Figures\n\n| | |\n|---|---|\n")
	for _, m := range rd.Metrics {
		p("| %s | %s |\n", m[0], m[1])
	}
	if len(rd.Tactics) > 0 {
		p("\n## ATT&CK\n\n")
		for _, t := range rd.Tactics {
			p("- %s\n", t)
		}
	}
	p("\n## Alerts\n\n| Time (UTC) | Severity | Rule | Title | Status |\n|---|---|---|---|---|\n")
	for _, a := range rd.Alerts {
		p("| %s | %s | `%s` | %s | %s |\n", a.Created.UTC().Format("2006-01-02 15:04:05"), a.Severity, a.Rule, mdEscape(a.Title), a.Status)
	}
	if len(rd.Entities) > 0 {
		p("\n## Addresses, users and hashes involved\n\n")
		for _, k := range []string{"ip", "user", "hash"} {
			if len(rd.Entities[k]) > 0 {
				p("- %s: %s\n", k, mdEscape(strings.Join(rd.Entities[k], ", ")))
			}
		}
	}
	if len(c.Notes) > 0 {
		p("\n## Notes\n\n")
		for _, n := range c.Notes {
			p("**%s**, %s\n\n%s\n\n", mdEscape(n.By), n.At.UTC().Format(time.RFC3339), strings.ReplaceAll(n.Text, "\n", "\n\n"))
		}
	}
	if len(rd.Snapshots) > 0 {
		p("\n## Evidence snapshots\n\n| Time (UTC) | Trigger | Process | Program SHA-256 | Snapshot SHA-256 | Seq |\n|---|---|---|---|---|---|\n")
		for _, x := range rd.Snapshots {
			p("| %s | %s | %s | `%s` | `%s` | %d |\n", x.Time.UTC().Format("2006-01-02 15:04:05"), mdEscape(x.Trigger), mdEscape(x.Comm),
				x.SHA256, x.Hash, x.Seq)
		}
	}
	p("\n## Timeline (host time, UTC)\n\n| Time | Seq | Type | Details |\n|---|---|---|---|\n")
	var diffs []Record
	for _, r := range rd.Events {
		extra := ""
		if diff, ok := r.Event.Data["diff"].(string); ok && diff != "" {
			diffs = append(diffs, r)
			extra = " (changed lines below)"
		}
		p("| %s | %d | `%s` | %s%s |\n", recordTime(r).UTC().Format("2006-01-02 15:04:05"), r.Seq, r.Event.Type, mdEscape(eventSummary(r)), extra)
	}
	if len(diffs) > 0 {
		p("\n## Changed lines\n")
		for _, r := range diffs {
			diff := strings.ReplaceAll(r.Event.Data["diff"].(string), "`", "'")
			p("\nSeq %d, %s:\n\n```diff\n%s```\n", r.Seq, mdEscape(str(r.Event.Data, "path")), diff)
		}
	}
	p("\n## Integrity\n\nEvery record above is part of the server's hash chain. Hashes of the records this report relies on:\n\n| Seq | Chain hash |\n|---|---|\n")
	keys := make([]uint64, 0, len(rd.Hashes))
	for k := range rd.Hashes {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	for _, k := range keys {
		p("| %d | `%s` |\n", k, rd.Hashes[k])
	}
	p("\nChain head when the report was made: seq %d, `%s`. Check the log with `vigil-server verify -config /etc/vigil/server.json`; the hashes above must still be found at their seq.\n", rd.HeadSeq, rd.HeadHash)
	return b.String()
}

// printable wraps the Markdown in a minimal HTML page for printing to PDF.
func (rd *reportData) printable() string {
	return mdPage("Incident "+rd.Incident.ID, rd.markdown(), "")
}

// mdPage renders the Markdown subset the reports use (headings, tables,
// lists, code) as a page to print or save as PDF. Everything is escaped;
// footer is fixed HTML from the caller, never data.
func mdPage(title, md, footer string) string {
	var b strings.Builder
	b.WriteString(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>` +
		html.EscapeString(title) + `</title><style>
body{font:13px/1.5 -apple-system,Segoe UI,sans-serif;margin:24px auto;max-width:960px;padding:0 16px;color:#1c1c1a;background:#fff}
h1{font-size:20px}h2{font-size:15px;margin-top:28px;border-bottom:1px solid #ddd;padding-bottom:4px}
table{border-collapse:collapse;width:100%;font-size:11.5px;margin:6px 0}td,th{border:1px solid #e3e3e0;padding:4px 6px;text-align:left;vertical-align:top;overflow-wrap:anywhere}
th{background:#f6f6f4}code,pre{font:11px ui-monospace,Menlo,monospace}pre{background:#f6f6f4;padding:8px;white-space:pre-wrap;overflow-wrap:anywhere}
a{color:inherit}
@media print{body{margin:0}h2{break-after:avoid}tr{break-inside:avoid}}
</style></head><body>`)
	inTable := false
	inCode := false
	for _, line := range strings.Split(md, "\n") {
		switch {
		case strings.HasPrefix(line, "```"):
			if inCode {
				b.WriteString("</pre>")
			} else {
				if inTable {
					b.WriteString("</table>")
					inTable = false
				}
				b.WriteString("<pre>")
			}
			inCode = !inCode
		case inCode:
			b.WriteString(html.EscapeString(line) + "\n")
		case strings.HasPrefix(line, "|"):
			if strings.HasPrefix(line, "|---") {
				continue
			}
			if !inTable {
				b.WriteString("<table>")
				inTable = true
			}
			cells := splitMDRow(line)
			if strings.Join(cells, "") == "" {
				continue // the empty header of key/value tables
			}
			b.WriteString("<tr>")
			for _, c := range cells {
				b.WriteString("<td>" + inlineMD(c) + "</td>")
			}
			b.WriteString("</tr>")
		default:
			if inTable {
				b.WriteString("</table>")
				inTable = false
			}
			switch {
			case strings.HasPrefix(line, "# "):
				b.WriteString("<h1>" + inlineMD(line[2:]) + "</h1>")
			case strings.HasPrefix(line, "## "):
				b.WriteString("<h2>" + inlineMD(line[3:]) + "</h2>")
			case strings.HasPrefix(line, "- "):
				b.WriteString("<div>• " + inlineMD(line[2:]) + "</div>")
			case line != "":
				b.WriteString("<p>" + inlineMD(line) + "</p>")
			}
		}
	}
	if inTable {
		b.WriteString("</table>")
	}
	b.WriteString(footer + "</body></html>")
	return b.String()
}

func splitMDRow(line string) []string {
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(strings.TrimSuffix(line, "|"), "|")
	var cells []string
	var cur strings.Builder
	for i := 0; i < len(line); i++ {
		if line[i] == '\\' && i+1 < len(line) && line[i+1] == '|' {
			cur.WriteByte('|')
			i++
			continue
		}
		if line[i] == '|' {
			cells = append(cells, strings.TrimSpace(cur.String()))
			cur.Reset()
			continue
		}
		cur.WriteByte(line[i])
	}
	return append(cells, strings.TrimSpace(cur.String()))
}

// inlineMD escapes and renders `code` and **bold**. Links are not
// rendered: cells hold text attackers chose.
func inlineMD(s string) string {
	s = html.EscapeString(s)
	var b strings.Builder
	for {
		i := strings.Index(s, "`")
		if i < 0 {
			break
		}
		j := strings.Index(s[i+1:], "`")
		if j < 0 {
			break
		}
		b.WriteString(s[:i] + "<code>" + s[i+1:i+1+j] + "</code>")
		s = s[i+2+j:]
	}
	b.WriteString(s)
	out := b.String()
	for strings.Count(out, "**") >= 2 {
		out = strings.Replace(out, "**", "<strong>", 1)
		out = strings.Replace(out, "**", "</strong>", 1)
	}
	return out
}

// GET /api/ui/incidents/{id}/report?format=md|html
func (s *Server) handleIncidentReport(w http.ResponseWriter, r *http.Request, sess *session) {
	rd, ok := s.reportFor(r.PathValue("id"), lang(r), sess.User)
	if !ok {
		http.NotFound(w, r)
		return
	}
	s.audit(sess.User, "admin.report", map[string]any{"incident": rd.Incident.ID, "format": r.URL.Query().Get("format")})
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Query().Get("format") == "html" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
		w.Write([]byte(rd.printable()))
		return
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="incident-`+rd.Incident.ID+`.md"`)
	w.Write([]byte(rd.markdown()))
}
