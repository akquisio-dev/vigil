package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHostActivity(t *testing.T) {
	s := forensicServer(t)
	now := time.Now().UTC()
	day := 24 * time.Hour
	pkgs := func(list ...string) map[string]any {
		var out []any
		for _, p := range list {
			f := strings.Fields(p)
			out = append(out, []any{f[0], f[1]})
		}
		return map[string]any{"packages": out}
	}
	// the list from before the window is the base of the first difference
	appendAt(t, s, "a1", now.Add(-8*day), "system.packages", pkgs("bash 5.2-1", "curl 8.5-1", "nano 7.2-1"))
	appendAt(t, s, "a1", now.Add(-2*day), "system.packages", pkgs("bash 5.2-1", "curl 8.5-2", "nginx 1.24-1"))
	appendAt(t, s, "a1", now.Add(-1*day), "system.packages", pkgs("bash 5.2-1", "curl 8.5-2", "nginx 1.24-1"))
	appendAt(t, s, "a1", now.Add(-3*time.Hour), "file.changed", map[string]any{"path": "/etc/sudoers", "category": "sudo", "diff": "+evil ALL=(ALL) NOPASSWD: ALL\n"})
	appendAt(t, s, "a1", now.Add(-3*day), "port.opened", map[string]any{"key": "listen/tcp/0.0.0.0:9200", "proto": "tcp", "port": float64(9200), "addr": "0.0.0.0", "process": "java"})
	appendAt(t, s, "a1", now.Add(-1*day), "port.closed", map[string]any{"key": "listen/tcp/0.0.0.0:9200", "proto": "tcp", "port": float64(9200), "addr": "0.0.0.0"})
	appendAt(t, s, "a1", now.Add(-2*time.Hour), "net.connection", map[string]any{"remote_ip": "203.0.113.200", "remote_port": float64(3333), "process": "kworkerd"})
	appendAt(t, s, "a1", now.Add(-1*time.Hour), "net.connection", map[string]any{"remote_ip": "203.0.113.200", "remote_port": float64(3333), "process": "kworkerd"})
	appendAt(t, s, "a1", now.Add(-1*time.Hour), "ssh.failed", map[string]any{"ip": "198.51.100.7", "count": float64(12)})
	appendAt(t, s, "a1", now.Add(-1*time.Hour), "ssh.failed", map[string]any{"ip": "198.51.100.8", "count": float64(3)})
	appendAt(t, s, "a1", now.Add(-1*time.Hour), "posture.report", map[string]any{"checks": []any{}})
	appendAt(t, s, "a1", now.Add(-5*day), "ssh.login", map[string]any{"user": "root", "ip": "192.0.2.50", "method": "publickey", "key_comment": "alice"})
	appendAt(t, s, "a1", now.Add(-2*time.Hour), "ssh.login", map[string]any{"user": "deploy", "ip": "192.0.2.50", "method": "publickey", "key_comment": "alice"})
	appendAt(t, s, "a1", now.Add(-1*time.Hour), "ssh.login", map[string]any{"user": "root", "ip": "203.0.113.9", "method": "password"})
	// another host's events stay out
	appendAt(t, s, "a2", now.Add(-1*time.Hour), "file.changed", map[string]any{"path": "/etc/passwd"})

	v := s.hostActivityFor("a1", 7, roleSet{base: "analyst"})
	var types []string
	for _, c := range v.Changes {
		types = append(types, c.Event.Type)
	}
	if strings.Join(types, ",") != "file.changed,port.closed,packages.changed,port.opened" {
		t.Fatalf("changes: %v", types)
	}
	fc := v.Changes[0].Event.Data
	if _, ok := fc["diff"]; ok || fc["has_diff"] != true {
		t.Fatalf("file contents stay on the timeline: %v", fc)
	}
	pd := v.Changes[2].Event.Data
	if pd["added_n"] != 1 || pd["removed_n"] != 1 || pd["changed_n"] != 1 {
		t.Fatalf("package difference: %v", pd)
	}
	if ch := pd["changed"].([][]string); ch[0][0] != "curl" || ch[0][1] != "8.5-1" || ch[0][2] != "8.5-2" {
		t.Fatalf("changed packages: %v", ch)
	}
	if len(v.Dests) != 1 || v.Dests[0].Count != 2 || v.Dests[0].Process != "kworkerd" || !v.Dests[0].First.Before(v.Dests[0].Last) {
		t.Fatalf("destinations: %+v", v.Dests)
	}
	if len(v.Ports) != 1 || v.Ports[0].Opened == nil || v.Ports[0].Closed == nil || v.Ports[0].Process != "java" || v.Ports[0].Times != 1 {
		t.Fatalf("ports: %+v", v.Ports)
	}
	if len(v.Failed) != 7 || v.Failed[6]+v.Failed[5] != 15 || v.FailedIPs[6]+v.FailedIPs[5] != 2 {
		t.Fatalf("failed per day: %v %v", v.Failed, v.FailedIPs)
	}

	if len(v.LoginHourly) < 2 || v.Logins != 3 || len(v.LoginHours) != 2 || len(v.Keys) != 2 || v.Keys[0].Key != "alice" || v.Keys[0].Count != 2 ||
		len(v.Keys[0].Users) != 2 || v.Keys[1].Key != "password" {
		t.Fatalf("logins: %d %v %+v", v.Logins, v.LoginHours, v.Keys)
	}
	if len(v.Sources) != 2 || v.Sources[0].Key != "203.0.113.9" || !v.Sources[1].First.Before(v.Sources[1].Last) {
		t.Fatalf("sources: %+v", v.Sources)
	}

	// the handler: unknown hosts are not found, days are bounded
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/ui/agents/{id}/activity", func(w http.ResponseWriter, r *http.Request) {
		s.handleHostActivity(w, r, &session{User: "nobody"})
	})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/api/ui/agents/nope/activity", nil))
	if w.Code != 404 {
		t.Fatalf("unknown host: %d", w.Code)
	}
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/api/ui/agents/a1/activity?days=400", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"days":30`) {
		t.Fatalf("days bounded: %d %.200s", w.Code, w.Body.String())
	}
}

func TestPkgDiffNone(t *testing.T) {
	if d := pkgDiff(map[string]string{"a": "1"}, map[string]string{"a": "1"}); d != nil {
		t.Fatalf("no change: %v", d)
	}
}
