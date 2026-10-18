package agent

import (
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/akquisio-dev/vigil/internal/notify"
)

func TestFallbackNotice(t *testing.T) {
	var mu sync.Mutex
	var sent []string
	fail := true
	f := &fallbackWatch{after: 15 * time.Minute, host: "game", lastOK: time.Now()}
	f.send = func(_ notify.Config, m notify.Message) error {
		mu.Lock()
		defer mu.Unlock()
		if fail {
			return errors.New("discord down")
		}
		sent = append(sent, m.Text)
		return nil
	}
	wait := func() {
		for i := 0; i < 200; i++ {
			f.mu.Lock()
			busy := f.inflight
			f.mu.Unlock()
			if !busy {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatal("notice still in flight")
	}
	start := f.lastOK
	down := errors.New("dial tcp 10.90.0.2:8471: connection refused")

	f.result(down, start.Add(10*time.Minute))
	wait()
	f.result(down, start.Add(16*time.Minute)) // notifier fails: try again
	wait()
	mu.Lock()
	fail = false
	mu.Unlock()
	f.result(down, start.Add(17*time.Minute))
	wait()
	f.result(down, start.Add(30*time.Minute)) // already told
	wait()
	f.result(nil, start.Add(40*time.Minute))
	wait()
	f.result(nil, start.Add(41*time.Minute))
	wait()
	if len(sent) != 2 {
		t.Fatalf("want one outage and one recovery notice, got %q", sent)
	}
	if !strings.Contains(sent[0], "game cannot reach") || !strings.Contains(sent[0], "connection refused") || !strings.Contains(sent[0], "17m") {
		t.Errorf("outage notice: %s", sent[0])
	}
	if !strings.Contains(sent[1], "again, after 40m") {
		t.Errorf("recovery notice: %s", sent[1])
	}

	// A short gap, such as a server update, says nothing.
	sent = nil
	f.result(down, start.Add(50*time.Minute))
	f.result(nil, start.Add(52*time.Minute))
	wait()
	if len(sent) != 0 {
		t.Fatalf("short gap reported: %q", sent)
	}
	var nilWatch *fallbackWatch
	nilWatch.result(down, time.Now())
}

func TestFallbackConfig(t *testing.T) {
	path := t.TempDir() + "/agent.json"
	write := func(s string) {
		if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"fallback":{"type":"discord","url":"https://discord.com/api/webhooks/1/x"},"fallback_minutes":1}`)
	c, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.FallbackMinutes != 5 || c.Fallback.Name != "fallback" {
		t.Fatalf("defaults: %+v", c)
	}
	write(`{"fallback":{"type":"discord","url":"ftp://x"}}`)
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("bad fallback accepted")
	}
}
