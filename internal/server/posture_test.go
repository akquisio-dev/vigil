package server

import (
	"strings"
	"testing"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

func TestConditionsAlertOnceAndResolveThemselves(t *testing.T) {
	s := &Server{state: &State{Agents: map[string]*AgentRec{}, KnownLogins: map[string]time.Time{}}}
	a := &AgentRec{ID: "a1", Name: "host", Baseline: map[string]bool{}, StartedOnce: true}
	s.state.Agents[a.ID] = a
	report := func(checks []any, certs []any, backups []any) []*Alert {
		rec := &Record{Event: proto.Event{Type: "posture.report", TS: time.Now(), Data: map[string]any{"checks": checks, "certs": certs, "backups": backups}}}
		return s.raise(s.evaluate(a, rec), a.ID, 1)
	}
	weak := []any{
		map[string]any{"check": "ssh_root_login", "ok": false, "value": "yes"},
		map[string]any{"check": "ssh_password", "ok": true},
		map[string]any{"check": "sysctl", "key": "kernel.kptr_restrict", "ok": false, "value": "0", "want": "1"},
		map[string]any{"check": "invented", "ok": false},
	}
	certs := []any{map[string]any{"path": "/etc/letsencrypt/live/x/fullchain.pem", "subject": "x.org", "days": 5.0},
		map[string]any{"path": "/etc/ssl/old.pem", "subject": "old.org", "days": -3.0},
		map[string]any{"path": "/etc/ssl/fine.pem", "subject": "ok.org", "days": 60.0}}
	backups := []any{map[string]any{"name": "db", "problem": "old", "age_hours": 40.0, "max_age_hours": 26.0}}
	fresh := report(weak, certs, backups)
	rules := map[string]string{}
	for _, al := range fresh {
		rules[al.Rule] = al.Title
	}
	if len(fresh) != 5 || rules["tls.expiring"] != "Certificate x.org expires in 5 days (/etc/letsencrypt/live/x/fullchain.pem)" ||
		rules["tls.expired"] != "Certificate old.org expired 3 days ago (/etc/ssl/old.pem)" || rules["posture.sysctl"] != "kernel.kptr_restrict = 0, should be 1" {
		t.Fatalf("first report: %v", rules)
	}
	if de := renderTitle("posture.ssh_root_login", map[string]string{"value": "yes"}, "de"); de != "Root kann sich per SSH mit Passwort anmelden (PermitRootLogin yes)" {
		t.Fatal(de)
	}

	// The same report again: nothing new. Resolving by hand stays resolved.
	for _, al := range s.state.Alerts {
		if al.Rule == "backup.stale" {
			al.Status = "resolved"
		}
	}
	if fresh := report(weak, certs, backups); len(fresh) != 0 {
		t.Fatalf("repeated: %d alerts", len(fresh))
	}

	// Fixed: the root login check passes, the backup is back. Their alerts close.
	weak[0] = map[string]any{"check": "ssh_root_login", "ok": true}
	if fresh := report(weak, certs, nil); len(fresh) != 0 {
		t.Fatalf("fix raised %d", len(fresh))
	}
	for _, al := range s.state.Alerts {
		if al.Rule == "posture.ssh_root_login" && (al.Status != "resolved" || al.By != "system") {
			t.Fatalf("not resolved: %+v", al)
		}
		if al.Rule == "posture.sysctl" && al.Status != "open" {
			t.Fatal("still failing check was closed")
		}
	}
	// It comes back: a new alert.
	weak[0] = map[string]any{"check": "ssh_root_login", "ok": false, "value": "yes"}
	if fresh := report(weak, certs, nil); len(fresh) != 1 || fresh[0].Rule != "posture.ssh_root_login" {
		t.Fatalf("regression: %+v", fresh)
	}
	if a.Posture == nil || len(a.Conditions["posture"]) != 4 {
		t.Fatalf("state: %+v", a.Conditions)
	}
}

func TestSecretExposedRule(t *testing.T) {
	s := &Server{state: &State{Agents: map[string]*AgentRec{}, KnownLogins: map[string]time.Time{}}}
	fs := evalOne(s, "secret.exposed", map[string]any{"path": "/srv/app/.env", "kind": "env_secret", "line": 3.0, "fingerprint": "abc", "mode": "0644"})
	if len(fs) != 1 || fs[0].Rule != "secret.exposed" {
		t.Fatalf("%+v", fs)
	}
	if got := renderTitle(fs[0].Rule, fs[0].Params, "en"); got != "env secret readable by every user: /srv/app/.env line 3" {
		t.Fatal(got)
	}
	if fs[0].Key != "secret.exposed|a1|/srv/app/.env" {
		t.Fatalf("one alert per file: %s", fs[0].Key)
	}
	if strings.Contains(encodeParams(fs[0].Params), "hunter") {
		t.Fatal("no secret values in alerts")
	}
}
