package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"
)

func TestCleanTags(t *testing.T) {
	got := cleanTags([]string{" M ", "m", "game", "", "a/b", "Oracle Cloud", "xxxxxxxxxxxxxxxxxxxxxxxxx", "Müller"})
	want := []string{"M", "Müller", "Oracle Cloud", "game"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("cleanTags = %q", got)
	}
	var many []string
	for i := 0; i < 20; i++ {
		many = append(many, string(rune('a'+i)))
	}
	if n := len(cleanTags(many)); n != maxTags {
		t.Fatalf("%d tags kept", n)
	}
}

func TestScope(t *testing.T) {
	s := forensicServer(t)
	s.state.Agents["a1"].Tags = []string{"E", "web"}
	s.state.Agents["a2"].Tags = []string{"M"}
	for q, want := range map[string]map[string]bool{
		"":                   nil,
		"agent=a1":           {"a1": true},
		"group=m":            {"a2": true},
		"group=E&agent=a2":   {},
		"agent=nope":         {},
		"group=unknowngrp":   {},
		"group=web&agent=a1": {"a1": true},
	} {
		v, _ := url.ParseQuery(q)
		if got := s.scope(v); !reflect.DeepEqual(got, want) {
			t.Errorf("%q: %v, want %v", q, got, want)
		}
	}
	if !inScope(nil, "") || inScope(map[string]bool{"a1": true}, "") {
		t.Error("server records belong to no host")
	}
}

func TestAlertFilterAndBulk(t *testing.T) {
	s := forensicServer(t)
	now := time.Now().UTC()
	s.state.Alerts = []*Alert{
		{ID: "x1", Rule: "process.tmp_exec", Severity: "high", Agent: "a1", Status: "open", Title: "Program started from /tmp/x", Created: now, Updated: now},
		{ID: "x2", Rule: "process.tmp_exec", Severity: "high", Agent: "a2", Status: "open", Title: "Program started from /tmp/y", Created: now, Updated: now},
		{ID: "x3", Rule: "ssh.bruteforce", Severity: "medium", Agent: "a2", Status: "open", Title: "Brute force", Created: now, Updated: now.Add(-10 * 24 * time.Hour)},
		{ID: "x4", Rule: "ssh.bruteforce", Severity: "low", Agent: "a1", Status: "resolved", Title: "old", Created: now, Updated: now},
	}
	ids := func(q string) []string {
		w := httptest.NewRecorder()
		s.handleAlerts(w, httptest.NewRequest(http.MethodGet, "/api/ui/alerts?"+q, nil), nil)
		var out []alertView
		json.Unmarshal(w.Body.Bytes(), &out)
		got := []string{}
		for _, a := range out {
			got = append(got, a.ID)
		}
		return got
	}
	for q, want := range map[string][]string{
		"status=open":          {"x3", "x2", "x1"},
		"status=open&agent=a2": {"x3", "x2"},
		"severity=medium,low":  {"x4", "x3"},
		"rule=ssh.":            {"x4", "x3"},
		"q=GAME&rule=process":  {"x2"}, // host name
		"q=BRUTEFORCE":         {"x4", "x3"},
		"status=open&days=7":   {"x2", "x1"},
		"agent=unknown":        {},
	} {
		if got := ids(q); !reflect.DeepEqual(got, want) {
			t.Errorf("%q: %v, want %v", q, got, want)
		}
	}

	body, _ := json.Marshal(map[string]any{"ids": []string{"x1", "x2", "x4", "nope"}, "action": "resolve"})
	w := httptest.NewRecorder()
	s.handleAlertsBulk(w, httptest.NewRequest(http.MethodPost, "/api/ui/alerts/bulk", bytes.NewReader(body)), &session{User: "joey"})
	var res map[string]int
	json.Unmarshal(w.Body.Bytes(), &res)
	if res["changed"] != 2 || s.state.Alerts[0].Status != "resolved" || s.state.Alerts[0].By != "joey" || s.state.Alerts[0].Acked == nil || s.state.Alerts[2].Status != "open" {
		t.Fatalf("bulk: %v %+v", res, s.state.Alerts[0])
	}
	w = httptest.NewRecorder()
	s.handleAlertsBulk(w, httptest.NewRequest(http.MethodPost, "/api/ui/alerts/bulk", bytes.NewReader([]byte(`{"ids":["x3"],"action":"reopen"}`))), &session{User: "joey"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("reopen in bulk allowed: %d", w.Code)
	}
}

func TestOverviewScoped(t *testing.T) {
	s := forensicServer(t)
	now := time.Now().UTC()
	appendAt(t, s, "a1", now, "ssh.failed", map[string]any{"ip": "198.51.100.1", "count": 3.0})
	appendAt(t, s, "a2", now, "ssh.failed", map[string]any{"ip": "198.51.100.2", "count": 5.0})
	appendAt(t, s, "", now, "server.started", nil)
	s.state.Alerts = []*Alert{{ID: "x1", Rule: "r", Severity: "high", Agent: "a2", Status: "open", Created: now, Updated: now}}
	get := func(q string) map[string]any {
		w := httptest.NewRecorder()
		s.handleOverview(w, httptest.NewRequest(http.MethodGet, "/api/ui/overview?"+q, nil), nil)
		var out map[string]any
		json.Unmarshal(w.Body.Bytes(), &out)
		return out
	}
	all, one := get(""), get("agent=a1")
	sum := func(o map[string]any, k string) (n float64) {
		for _, v := range o[k].([]any) {
			n += v.(float64)
		}
		return
	}
	if sum(all, "ssh_failed_per_hour") != 8 || sum(one, "ssh_failed_per_hour") != 3 || sum(one, "events_per_hour") != 1 {
		t.Fatalf("ssh failed all %v one %v", sum(all, "ssh_failed_per_hour"), sum(one, "ssh_failed_per_hour"))
	}
	if len(one["agents"].([]any)) != 1 || len(one["open_by_severity"].(map[string]any)) != 0 || len(all["open_by_severity"].(map[string]any)) != 1 {
		t.Fatalf("scoped overview: %v", one["open_by_severity"])
	}
}

func TestAttackStatsForHost(t *testing.T) {
	s := forensicServer(t)
	now := time.Now().UTC()
	appendAt(t, s, "a1", now, "ssh.failed", map[string]any{"ip": "198.51.100.1", "count": 2.0, "users": anyList("root")})
	appendAt(t, s, "a2", now, "ssh.failed", map[string]any{"ip": "198.51.100.2", "count": 4.0, "users": anyList("root")})
	appendAt(t, s, "a2", now, "ssh.failed", map[string]any{"ip": "198.51.100.1", "count": 1.0, "users": anyList("admin")})
	s.startAttacks()
	waitAttacks(t, s)
	all, a1, a2 := s.attackStats(7), s.attackStatsFor(7, "a1"), s.attackStatsFor(7, "a2")
	if all.Totals.IPs != 2 || a1.Totals.IPs != 1 || a2.Totals.IPs != 2 || a1.Agent != "a1" {
		t.Fatalf("addresses: all %d a1 %d a2 %d", all.Totals.IPs, a1.Totals.IPs, a2.Totals.IPs)
	}
	var h int
	for _, n := range a1.Hours {
		h += n
	}
	if h != 0 {
		t.Fatalf("hours shown for one host: %v", a1.Hours)
	}
}
