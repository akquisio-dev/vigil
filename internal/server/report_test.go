package server

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIncidentReport(t *testing.T) {
	s := forensicServer(t)
	now := time.Now().UTC()
	login := appendAt(t, s, "a1", now.Add(-40*time.Minute), "ssh.login", map[string]any{"user": "deploy", "ip": "203.0.113.7", "sshd_pid": 5.0})
	ch := appendAt(t, s, "a1", now.Add(-30*time.Minute), "file.changed", map[string]any{"path": "/etc/sudoers", "diff": "@@ line 1\n+evil ALL=(ALL) NOPASSWD: ALL\n"})
	ack := now.Add(-10 * time.Minute)
	al1 := &Alert{ID: "al1", Agent: "a1", Rule: "ssh.new_source", Severity: "medium", Technique: "T1078", Created: now.Add(-39 * time.Minute), Updated: now.Add(-39 * time.Minute),
		Seqs: []uint64{login.Seq}, Detail: "ip=203.0.113.7\nuser=deploy\n", Status: "acked", Acked: &ack, Title: "deploy logged in from new address 203.0.113.7"}
	al2 := &Alert{ID: "al2", Agent: "a1", Rule: "file.sudo", Severity: "high", Technique: "T1548.003", Created: now.Add(-29 * time.Minute), Updated: now.Add(-29 * time.Minute),
		Seqs: []uint64{ch.Seq}, Detail: "path=/etc/sudoers | <script>\nchange=changed\n", Status: "open", Title: "/etc/sudoers: changed | <script>"}
	s.state.Alerts = append(s.state.Alerts, al1, al2)
	s.correlate([]*Alert{al1, al2})
	if len(s.state.Incidents) != 1 {
		t.Fatalf("incidents: %d", len(s.state.Incidents))
	}
	inc := s.state.Incidents[0]
	inc.Notes = append(inc.Notes, Note{By: "ana", At: now, Text: "Key of deploy rotated."})
	rd, ok := s.reportFor(inc.ID, "en", "ana")
	if !ok {
		t.Fatal("no report")
	}
	md := rd.markdown()
	for _, want := range []string{"# Incident " + inc.ID, "| Host | web |", "Detection delay (first event to first alert) | 1m 0s",
		"Time to acknowledge (first alert to first acknowledgement) | 29m 0s", "privilege-escalation (T1548.003)", "+evil ALL=(ALL) NOPASSWD: ALL",
		"Key of deploy rotated.", "- ip: 203.0.113.7", "| " + itoa(login.Seq) + " | `", "Chain head when the report was made", "sudoers \\| <script>"} {
		if !strings.Contains(md, want) {
			t.Errorf("missing %q in:\n%s", want, md)
		}
	}
	if rd.Hashes[login.Seq] == "" || rd.Hashes[ch.Seq] == "" || len(rd.Hashes[ch.Seq]) != 64 {
		t.Fatalf("hashes: %v", rd.Hashes)
	}
	page := rd.printable()
	if strings.Contains(page, "<script>") || !strings.Contains(page, "&lt;script&gt;") || !strings.Contains(page, "<h2>Changed lines</h2>") {
		t.Fatalf("printable page is not escaped or incomplete: %v %v %v", strings.Contains(page, "<script>"), strings.Contains(page, "&lt;script&gt;"), strings.Contains(page, "<h2>Changed lines</h2>"))
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/ui/incidents/"+inc.ID+"/report?format=html", nil)
	r.SetPathValue("id", inc.ID)
	s.handleIncidentReport(w, r, &session{User: "ana"})
	if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatalf("report endpoint: %d %v", w.Code, w.Header())
	}
}
