package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRedactKeepsWebhookSecretsOutOfErrors(t *testing.T) {
	secret := "https://127.0.0.1:1/api/webhooks/123/SECRETTOKEN"
	err := postJSON(secret, map[string]string{}, nil)
	if err == nil || strings.Contains(err.Error(), "SECRETTOKEN") {
		t.Fatalf("error leaks the url: %v", err)
	}
	tg := deliver(NotifierConfig{Type: "telegram", Token: "123:SECRETSECRETSECRETSECRET", ChatID: "1"}, message{Text: "x"})
	if tg != nil && strings.Contains(tg.Error(), "SECRETSECRET") {
		t.Fatalf("telegram error leaks the bot token: %v", tg)
	}
	if err := postJSON("http://exa mple.com/SECRETTOKEN", nil, nil); err == nil || strings.Contains(err.Error(), "SECRETTOKEN") {
		t.Fatalf("bad url leaks: %v", err)
	}
}

func TestNotifierConfigCheck(t *testing.T) {
	good := []NotifierConfig{
		{Type: "discord", URL: "https://discord.com/api/webhooks/1/x", Mention: "<@&123>"},
		{Type: "slack", URL: "https://hooks.slack.com/services/x"},
		{Type: "ntfy", URL: "https://ntfy.sh/my-topic"},
		{Type: "telegram", Token: "123456:ABCDEFGHIJKLMNOPQRSTUVWXYZ", ChatID: "-100123"},
		{Type: "webhook", URL: "http://10.0.0.1/hook"},
		{Type: "smtp", SMTPHost: "smtp.example.com", From: "a@example.com", To: []string{"b@example.com"}},
	}
	for i := range good {
		if err := good[i].Check(); err != nil {
			t.Errorf("%s refused: %v", good[i].Type, err)
		}
	}
	if good[0].MentionMinSeverity != "critical" || good[0].MinSeverity != "high" {
		t.Error("defaults not filled")
	}
	bad := []NotifierConfig{
		{Type: "discord"},
		{Type: "discord", URL: "ftp://x/y"},
		{Type: "discord", URL: "https://x/y", Mention: "@someone"},
		{Type: "slack", URL: "https://x/y", Mention: "@here"},
		{Type: "ntfy", URL: "https://ntfy.sh/"},
		{Type: "telegram", Token: "nope", ChatID: "1"},
		{Type: "smtp", SMTPHost: "x"},
		{Type: "pager", URL: "https://x/y"},
		{Type: "webhook", URL: "https://x/y", MinSeverity: "urgent"},
	}
	for _, n := range bad {
		if err := n.Check(); err == nil {
			t.Errorf("accepted %+v", n)
		}
	}
}

type sink struct {
	mu     sync.Mutex
	bodies []map[string]any
	status int
}

func (k *sink) handler(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	var v map[string]any
	json.Unmarshal(raw, &v)
	k.mu.Lock()
	k.bodies = append(k.bodies, v)
	st := k.status
	k.mu.Unlock()
	if st != 0 {
		w.WriteHeader(st)
	}
}

func (k *sink) count() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.bodies)
}

func TestFailingNotifierRaisesAlertThroughOthersOnly(t *testing.T) {
	broken := &sink{status: 404}
	good := &sink{}
	bs := httptest.NewServer(http.HandlerFunc(broken.handler))
	gs := httptest.NewServer(http.HandlerFunc(good.handler))
	defer bs.Close()
	defer gs.Close()

	cfg := &Config{DataDir: t.TempDir(), Notifiers: []NotifierConfig{
		{Type: "webhook", Name: "broken", MinSeverity: "info", URL: bs.URL + "/hook"},
		{Type: "webhook", Name: "good", MinSeverity: "info", URL: gs.URL + "/hook"},
	}}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	broken404 := cfg.Notifiers[0]
	s.noteDelivery(broken404, errStatus("404 Not Found"))
	s.noteDelivery(broken404, errStatus("404 Not Found"))

	deadline := time.Now().Add(5 * time.Second)
	for good.count() < 1 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	if good.count() != 1 {
		t.Fatalf("good notifier got %d messages, want exactly one notify.failed", good.count())
	}
	if broken.count() != 0 {
		t.Fatal("the failing notifier was asked to report its own failure")
	}
	if !strings.Contains(good.bodies[0]["title"].(string), "broken") {
		t.Fatalf("unexpected message %v", good.bodies[0])
	}
	open := func() int {
		s.mu.Lock()
		defer s.mu.Unlock()
		n := 0
		for _, al := range s.state.Alerts {
			if al.Rule == "notify.failed" && al.Status == "open" {
				n++
			}
		}
		return n
	}
	if open() != 1 {
		t.Fatal("notify.failed not raised once")
	}
	if st := s.notifierStatus()[0]; st.Failures != 2 || st.LastError == "" {
		t.Fatalf("status not tracked: %+v", st)
	}
	s.noteDelivery(broken404, nil)
	if open() != 0 {
		t.Fatal("a successful delivery must resolve notify.failed")
	}
	if Suppressible("notify.failed") {
		t.Fatal("notify.failed must not be suppressible")
	}
}

type errStatus string

func (e errStatus) Error() string { return "status " + string(e) }

func TestRateLimitIsRetriedAfterTheAskedDelay(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if calls == 1 {
			w.Header().Set("Retry-After", "0.2")
			w.WriteHeader(http.StatusTooManyRequests)
		}
	}))
	defer srv.Close()
	err := postJSON(srv.URL, map[string]string{}, nil)
	ra, ok := err.(*retryAfter)
	if !ok || ra.Wait != 200*time.Millisecond {
		t.Fatalf("429 not recognised: %v", err)
	}
}

func TestNotifierFormats(t *testing.T) {
	k := &sink{}
	srv := httptest.NewServer(http.HandlerFunc(k.handler))
	defer srv.Close()
	m := message{Severity: "critical", Title: "Reverse shell <@everyone> & <https://evil|x>", Host: "web", Technique: "T1059.004", Link: "https://soc/#/alerts/1"}

	if err := deliver(NotifierConfig{Type: "discord", URL: srv.URL, Mention: "<@&42>", MentionMinSeverity: "critical"}, m); err != nil {
		t.Fatal(err)
	}
	if err := deliver(NotifierConfig{Type: "slack", URL: srv.URL}, m); err != nil {
		t.Fatal(err)
	}
	if err := deliver(NotifierConfig{Type: "ntfy", URL: srv.URL + "/alerts"}, m); err != nil {
		t.Fatal(err)
	}
	d, sl, nt := k.bodies[0], k.bodies[1], k.bodies[2]
	if d["content"] != "<@&42>" || d["allowed_mentions"].(map[string]any)["roles"].([]any)[0] != "42" {
		t.Fatalf("discord mention: %v", d)
	}
	if strings.Contains(sl["text"].(string), "<@everyone>") || strings.Contains(sl["text"].(string), "<https://evil") {
		t.Fatalf("slack text not escaped: %s", sl["text"])
	}
	if nt["topic"] != "alerts" || nt["priority"].(float64) != 5 || nt["click"] != m.Link {
		t.Fatalf("ntfy: %v", nt)
	}

	// Below the mention threshold nobody is pinged.
	k.bodies = nil
	m.Severity = "high"
	deliver(NotifierConfig{Type: "discord", URL: srv.URL, Mention: "<@&42>", MentionMinSeverity: "critical"}, m)
	if _, ok := k.bodies[0]["content"]; ok {
		t.Fatal("high alert pinged a critical-only mention")
	}
}

func TestHeartbeatWithheldWhileUnhealthy(t *testing.T) {
	s, err := New(&Config{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if r := s.unhealthy(); r != "" {
		t.Fatalf("fresh server unhealthy: %s", r)
	}
	s.store.mu.Lock()
	s.store.ChainOK, s.store.ChainError = false, "x:1: hash chain broken"
	s.store.mu.Unlock()
	if r := s.unhealthy(); !strings.Contains(r, "chain") {
		t.Fatalf("broken chain not reported: %q", r)
	}
}
