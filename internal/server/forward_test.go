package server

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

func TestForwarding(t *testing.T) {
	// syslog over TCP
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var mu sync.Mutex
	var tcpLines []string
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		r := bufio.NewReader(c)
		for {
			var n int
			if _, err := fmtSscan(r, &n); err != nil {
				return
			}
			buf := make([]byte, n)
			if _, err := io.ReadFull(r, buf); err != nil {
				return
			}
			mu.Lock()
			tcpLines = append(tcpLines, string(buf))
			mu.Unlock()
		}
	}()
	// syslog over UDP
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer pc.Close()
	var udpLines []string
	go func() {
		buf := make([]byte, 65536)
		for {
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			mu.Lock()
			udpLines = append(udpLines, string(buf[:n]))
			mu.Unlock()
		}
	}()
	// HTTP, failing at first
	var httpBodies []string
	fail := true
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer secret-token" {
			w.WriteHeader(401)
			return
		}
		if fail {
			w.WriteHeader(503)
			return
		}
		b, _ := io.ReadAll(r.Body)
		httpBodies = append(httpBodies, strings.TrimSpace(string(b)))
	}))
	defer hs.Close()
	file := t.TempDir() + "/vigil.jsonl"

	s := forensicServer(t)
	s.cfg.Forward = []ForwardConfig{
		{Name: "tcp", Type: "syslog", Address: ln.Addr().String(), Protocol: "tcp"},
		{Name: "udp", Type: "syslog", Address: pc.LocalAddr().String(), What: "alerts", MinSeverity: "high"},
		{Name: "siem", Type: "http", URL: hs.URL + "/ingest", Headers: map[string]string{"Authorization": "Bearer secret-token"}},
		{Name: "file", Type: "file", Path: file, What: "events"},
		{Name: "bad", Type: "carrier-pigeon"},
	}
	s.startForwarders()
	if len(s.fwd) != 4 {
		t.Fatalf("forwarders: %d", len(s.fwd))
	}
	appendAt(t, s, "a1", time.Now(), "ssh.login", map[string]any{"user": "joey", "ip": "203.0.113.1"})
	s.notifyAlerts([]*Alert{
		{ID: "x1", Rule: "process.miner", Severity: "critical", Agent: "a1", Created: time.Now(), Detail: "exe=/tmp/xmrig\n"},
		{ID: "x2", Rule: "port.local", Severity: "low", Agent: "a1", Created: time.Now()},
	})
	waitFor(t, "syslog tcp", func() bool { mu.Lock(); defer mu.Unlock(); return len(tcpLines) == 3 })
	waitFor(t, "syslog udp", func() bool { mu.Lock(); defer mu.Unlock(); return len(udpLines) == 1 })
	mu.Lock()
	if !strings.HasPrefix(tcpLines[0], "<134>1 ") || !strings.Contains(tcpLines[0], `"host":"web"`) || !strings.Contains(udpLines[0], "<130>1 ") || !strings.Contains(udpLines[0], "process.miner") {
		t.Fatalf("syslog: %q %q", tcpLines[0], udpLines[0])
	}
	mu.Unlock()
	waitFor(t, "file", func() bool { b, _ := os.ReadFile(file); return strings.Count(string(b), "\n") == 1 })
	b, _ := os.ReadFile(file)
	var line map[string]any
	if json.Unmarshal(b, &line) != nil || line["vigil"] != "event" {
		t.Fatalf("file: %s", b)
	}
	// HTTP failed; it keeps the batch and delivers once the receiver is back.
	waitFor(t, "http error", func() bool { st := s.forwardStatus(); return st[2]["error"] == "HTTP 503" })
	mu.Lock()
	fail = false
	mu.Unlock()
	waitFor(t, "http delivery", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(httpBodies) == 1 && strings.Count(httpBodies[0], "\n") == 2
	})
	for _, st := range s.forwardStatus() {
		if st["error"] != "" {
			t.Fatalf("status: %+v", st)
		}
		if strings.Contains(st["error"].(string), "secret-token") {
			t.Fatal("token in status")
		}
	}
}

func fmtSscan(r *bufio.Reader, n *int) (int, error) {
	s, err := r.ReadString(' ')
	if err != nil {
		return 0, err
	}
	v := 0
	for _, c := range strings.TrimSpace(s) {
		v = v*10 + int(c-'0')
	}
	*n = v
	return 1, nil
}
