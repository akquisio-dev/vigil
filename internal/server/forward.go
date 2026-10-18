package server

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Forwarding sends events and alerts on to other systems as they happen:
// syslog (RFC 5424 over UDP, TCP or TLS, the message is JSON), HTTP (JSON
// lines in batches, for Elastic, Loki, Splunk HEC behind a proxy, Graylog,
// Vector) or a JSON lines file (for Filebeat, Vector, Fluent Bit). Each
// target has its own queue; a slow or unreachable target never slows down
// the agents, and what does not fit in the queue is dropped and counted.

type ForwardConfig struct {
	Name string `json:"name"`
	Type string `json:"type"` // syslog | http | file
	// What is "events", "alerts" or "all" (default).
	What string `json:"what,omitempty"`
	// MinSeverity filters alerts (default: all).
	MinSeverity string `json:"min_severity,omitempty"`
	// syslog
	Address  string `json:"address,omitempty"`  // host:port
	Protocol string `json:"protocol,omitempty"` // udp | tcp | tls
	// http
	URL     string            `json:"url,omitempty"`
	Headers map[string]string `json:"headers,omitempty"` // e.g. Authorization; never logged
	// file
	Path string `json:"path,omitempty"`
}

const (
	forwardQueue = 10000
	forwardBatch = 500
	forwardEvery = 5 * time.Second
)

type fwdItem struct {
	kind string // event | alert
	sev  string
	ts   time.Time
	body []byte
	rec  *Record // events are serialized in the forwarder, outside s.mu
}

type forwarder struct {
	cfg     ForwardConfig
	ch      chan fwdItem
	dropped atomic.Int64
	sent    atomic.Int64
	mu      sync.Mutex
	lastErr string
	lastOK  time.Time
	conn    net.Conn
	file    *os.File
	fileIno uint64
	client  *http.Client
	host    string
}

func (f *forwarder) wants(kind, sev string) bool {
	switch f.cfg.What {
	case "events":
		if kind != "event" {
			return false
		}
	case "alerts":
		if kind != "alert" {
			return false
		}
	}
	return kind != "alert" || f.cfg.MinSeverity == "" || severityRank[sev] >= severityRank[f.cfg.MinSeverity]
}

func (f *forwarder) push(it fwdItem) {
	if !f.wants(it.kind, it.sev) {
		return
	}
	select {
	case f.ch <- it:
	default:
		f.dropped.Add(1)
	}
}

func validateForward(c ForwardConfig) error {
	if c.Name == "" {
		return errors.New("name is required")
	}
	switch c.What {
	case "", "all", "events", "alerts":
	default:
		return fmt.Errorf("%s: what must be events, alerts or all", c.Name)
	}
	if c.MinSeverity != "" && severityRank[c.MinSeverity] == 0 && c.MinSeverity != "info" {
		return fmt.Errorf("%s: unknown min_severity", c.Name)
	}
	switch c.Type {
	case "syslog":
		if _, _, err := net.SplitHostPort(c.Address); err != nil {
			return fmt.Errorf("%s: address must be host:port", c.Name)
		}
		switch c.Protocol {
		case "", "udp", "tcp", "tls":
		default:
			return fmt.Errorf("%s: protocol must be udp, tcp or tls", c.Name)
		}
	case "http":
		u, err := url.Parse(c.URL)
		if err != nil || u.Scheme != "https" && u.Scheme != "http" || u.Host == "" {
			return fmt.Errorf("%s: url must be http(s)://host/...", c.Name)
		}
	case "file":
		if !strings.HasPrefix(c.Path, "/") {
			return fmt.Errorf("%s: path must be absolute", c.Name)
		}
	default:
		return fmt.Errorf("%s: type must be syslog, http or file", c.Name)
	}
	return nil
}

func (s *Server) startForwarders() {
	host, _ := os.Hostname()
	for _, c := range s.cfg.Forward {
		if err := validateForward(c); err != nil {
			log.Printf("forward: %v", err)
			continue
		}
		f := &forwarder{cfg: c, ch: make(chan fwdItem, forwardQueue), host: host,
			client: &http.Client{Timeout: 20 * time.Second}}
		s.fwd = append(s.fwd, f)
		go s.runForwarder(f)
	}
	if len(s.fwd) > 0 {
		s.store.hooks = append(s.store.hooks, s.forwardRecords)
	}
}

// forwardRecords is called by the store after records are written. It may
// run while s.mu is held, so it only queues.
func (s *Server) forwardRecords(recs []*Record) {
	for _, r := range recs {
		cp := *r
		if cp.Event.Type == "forensics.snapshot" {
			cp = slim(cp) // whole snapshots are too large for most receivers
		}
		for _, f := range s.fwd {
			f.push(fwdItem{kind: "event", ts: recordTime(cp), rec: &cp})
		}
	}
}

// encode fills in the body of queued events.
func (s *Server) encode(batch []fwdItem) {
	var names map[string]string
	for i := range batch {
		if batch[i].body != nil || batch[i].rec == nil {
			continue
		}
		if names == nil {
			names = s.agentNames()
		}
		v := viewRecord{Record: *batch[i].rec}
		if v.Agent != "" {
			v.Host = names[v.Agent]
		}
		batch[i].body, _ = json.Marshal(map[string]any{"vigil": "event", "record": v})
		batch[i].rec = nil
	}
}

func (s *Server) forwardAlerts(fresh []*Alert) {
	if len(s.fwd) == 0 {
		return
	}
	for _, al := range fresh {
		v := s.viewAlert(al, s.cfg.Language)
		body, err := json.Marshal(map[string]any{"vigil": "alert", "alert": v, "params": decodeParams(al.Detail)})
		if err != nil {
			continue
		}
		for _, f := range s.fwd {
			f.push(fwdItem{kind: "alert", sev: al.Severity, ts: al.Created, body: body})
		}
	}
}

func (s *Server) runForwarder(f *forwarder) {
	t := time.NewTicker(forwardEvery)
	defer t.Stop()
	var batch []fwdItem
	failedSince := time.Time{}
	flush := func() {
		if len(batch) == 0 {
			return
		}
		s.encode(batch)
		n, err := f.send(batch)
		f.sent.Add(int64(n))
		batch = batch[n:]
		f.mu.Lock()
		if err != nil {
			f.lastErr = fwdRedact(err)
		} else {
			f.lastErr, f.lastOK = "", time.Now().UTC()
		}
		f.mu.Unlock()
		if err == nil {
			failedSince = time.Time{}
			return
		}
		log.Printf("forward %s: %s", f.cfg.Name, fwdRedact(err))
		if failedSince.IsZero() {
			failedSince = time.Now()
		}
		// Keep trying with what is queued; past the queue size the oldest go.
		if over := len(batch) - forwardQueue; over > 0 {
			batch = batch[over:]
			f.dropped.Add(int64(over))
		}
		if time.Since(failedSince) > 10*time.Minute {
			s.mu.Lock()
			fresh := s.raise([]finding{{Rule: "forward.failed", Key: "forward.failed|" + f.cfg.Name,
				Params: map[string]string{"forwarder": f.cfg.Name, "type": f.cfg.Type, "error": clip(fwdRedact(err), 200)}}}, "", 0)
			s.mu.Unlock()
			s.notifyAlerts(fresh)
			failedSince = time.Now()
		}
	}
	for {
		select {
		case it := <-f.ch:
			batch = append(batch, it)
			if len(batch) >= forwardBatch {
				flush()
			}
		case <-t.C:
			flush()
		}
	}
}

var syslogSev = map[string]int{"critical": 2, "high": 3, "medium": 4, "low": 5, "info": 6}

// syslogLine is RFC 5424 with facility local0; the message is the JSON.
func (f *forwarder) syslogLine(it fwdItem) []byte {
	sev := 6
	if it.kind == "alert" {
		sev = syslogSev[it.sev]
	}
	pri := 16*8 + sev
	return []byte(fmt.Sprintf("<%d>1 %s %s vigil - %s - %s", pri, it.ts.UTC().Format(time.RFC3339Nano), f.host, it.kind, it.body))
}

// send returns how many items of the batch went out.
func (f *forwarder) send(batch []fwdItem) (int, error) {
	switch f.cfg.Type {
	case "syslog":
		return f.sendSyslog(batch)
	case "http":
		var buf bytes.Buffer
		for _, it := range batch {
			buf.Write(it.body)
			buf.WriteByte('\n')
		}
		req, err := http.NewRequest("POST", f.cfg.URL, &buf)
		if err != nil {
			return 0, err
		}
		req.Header.Set("Content-Type", "application/x-ndjson")
		req.Header.Set("User-Agent", "vigil/"+Version)
		for k, v := range f.cfg.Headers {
			req.Header.Set(k, v)
		}
		res, err := f.client.Do(req)
		if err != nil {
			return 0, err
		}
		res.Body.Close()
		if res.StatusCode >= 300 {
			return 0, fmt.Errorf("HTTP %d", res.StatusCode)
		}
		return len(batch), nil
	case "file":
		if err := f.sendFile(batch); err != nil {
			return 0, err
		}
		return len(batch), nil
	}
	return len(batch), nil
}

func (f *forwarder) sendSyslog(batch []fwdItem) (int, error) {
	proto := f.cfg.Protocol
	if proto == "" {
		proto = "udp"
	}
	if f.conn == nil {
		var err error
		d := &net.Dialer{Timeout: 10 * time.Second}
		switch proto {
		case "tls":
			host, _, _ := net.SplitHostPort(f.cfg.Address)
			f.conn, err = tls.DialWithDialer(d, "tcp", f.cfg.Address, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
		default:
			f.conn, err = d.Dial(proto, f.cfg.Address)
		}
		if err != nil {
			f.conn = nil
			return 0, err
		}
	}
	f.conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	for i, it := range batch {
		line := f.syslogLine(it)
		var err error
		if proto == "udp" {
			if len(line) > 8000 {
				line = line[:8000]
			}
			_, err = f.conn.Write(line)
		} else {
			// octet counting (RFC 6587)
			_, err = f.conn.Write(append([]byte(fmt.Sprintf("%d ", len(line))), line...))
		}
		if err != nil {
			f.conn.Close()
			f.conn = nil
			return i, err // the ones already written are not sent twice
		}
	}
	return len(batch), nil
}

func (f *forwarder) sendFile(batch []fwdItem) error {
	// Reopen when log rotation moved the file away.
	if f.file != nil {
		if fi, err := os.Stat(f.cfg.Path); err != nil || inode(fi) != f.fileIno {
			f.file.Close()
			f.file = nil
		}
	}
	if f.file == nil {
		fh, err := os.OpenFile(f.cfg.Path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
		if err != nil {
			return err
		}
		fi, _ := fh.Stat()
		f.file, f.fileIno = fh, inode(fi)
	}
	var buf bytes.Buffer
	for _, it := range batch {
		buf.Write(it.body)
		buf.WriteByte('\n')
	}
	_, err := f.file.Write(buf.Bytes())
	return err
}

func (s *Server) forwardStatus() []map[string]any {
	out := []map[string]any{}
	for _, f := range s.fwd {
		f.mu.Lock()
		out = append(out, map[string]any{"name": f.cfg.Name, "type": f.cfg.Type, "what": f.cfg.What, "sent": f.sent.Load(),
			"dropped": f.dropped.Load(), "queued": len(f.ch), "error": f.lastErr, "last_ok": f.lastOK})
		f.mu.Unlock()
	}
	return out
}

func inode(fi os.FileInfo) uint64 {
	if fi == nil {
		return 0
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Ino
	}
	return 0
}

// fwdRedact keeps URLs (which may carry tokens) out of messages; other
// errors name only addresses and status codes.
func fwdRedact(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		return redact(err).Error()
	}
	return err.Error()
}
