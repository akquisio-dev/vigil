// Package agent is the host sensor. It runs as root, opens no listening
// socket, executes only journalctl, iptables-save, nft (response actions,
// when enabled) and its own copy of sleep (self test), and talks to the
// server with outbound, signed requests.
package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

var Version = "dev"

type Agent struct {
	cfg   *Config
	id    *Identity
	state *State
	http  *http.Client
	watch *canaryWatch

	mu            sync.Mutex
	queue         []proto.Event
	dropped       int
	keyNames      map[string]keyRef
	sshFails      map[string]*failures
	canaryPaths   map[string]string
	portsSent     bool
	lastSeq       int64
	cursor        string
	flushNow      chan struct{}
	procLimit     procLimiter
	outSeen       map[string]bool   // remote network:port combinations already reported
	broken        map[string]string // collector -> why it stopped, for the self test
	kernel        *KernelState      // main loop only
	bpf           *BPFState         // main loop only
	content       *contentStore     // main loop only
	contentSeeded bool
	snaps         snapLimiter
	preloadSeen   map[string]bool // exe|LD_PRELOAD pairs already reported
	sessions      sessionTracker
	yara          yaraEngine
	bg            sync.WaitGroup // background scans, waited for in tests
	rare          *RareState
}

func New(cfg *Config) (*Agent, error) {
	id, err := LoadIdentity(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	st, err := LoadState(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	if cfg.Server == "" {
		cfg.Server = id.Server
	}
	return &Agent{
		cfg: cfg, id: id, state: st,
		http:        &http.Client{Timeout: 15 * time.Second},
		keyNames:    map[string]keyRef{},
		sshFails:    map[string]*failures{},
		canaryPaths: map[string]string{},
		flushNow:    make(chan struct{}, 1),
		cursor:      st.JournalCursor,
	}, nil
}

// collectorFailed reports a collector that stopped and remembers why, so a
// self test can say which sensor is down instead of only that a trace was
// missed.
func (a *Agent) collectorFailed(name, why string) {
	a.mu.Lock()
	if a.broken == nil {
		a.broken = map[string]string{}
	}
	a.broken[name] = why
	a.mu.Unlock()
	a.emit(proto.NewEvent("agent.warning", map[string]any{"collector": name, "error": why}))
}

func (a *Agent) collectorDown(name string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.broken[name]
}

// emit queues an event. When the server is unreachable for long, the oldest
// events are dropped and the loss is reported once the link is back.
func (a *Agent) emit(ev proto.Event) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.queue) >= a.cfg.MaxQueue {
		a.queue = a.queue[1:]
		a.dropped++
	}
	a.queue = append(a.queue, ev)
}

func (a *Agent) flushSoon() {
	select {
	case a.flushNow <- struct{}{}:
	default:
	}
}

func (a *Agent) Run(ctx context.Context) error {
	// The packaged unit caps memory at 96 MB. Without a soft limit the
	// garbage collector lets the heap double before collecting, and a
	// filesystem walk on a large host would hit the cap.
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(48 << 20)
	}
	if len(a.cfg.CanaryRoots) > 0 {
		w, err := newCanaryWatch()
		if err != nil {
			a.emit(proto.NewEvent("agent.warning", map[string]any{"collector": "canary", "error": err.Error()}))
		} else {
			a.watch = w
			go a.runCanaryWatch()
		}
	}
	host, _ := os.Hostname()
	// The dashboard only offers response actions this host accepts.
	allowed := []string{}
	for _, t := range proto.ActionTypes {
		if a.cfg.Response.allows(t) {
			allowed = append(allowed, t)
		}
	}
	a.emit(proto.NewEvent("agent.started", map[string]any{"version": Version, "hostname": host, "canary_roots": a.cfg.CanaryRoots, "response": allowed, "selftest": on(a.cfg.SelfTest), "forensics": on(a.cfg.Forensics)}))
	cleanSelfTests()

	a.scan()
	if !a.state.Initialized {
		a.state.Initialized = true
		a.emit(proto.NewEvent("baseline.created", map[string]any{"files": len(a.state.Files), "users": len(a.state.Users), "ports": len(a.state.Ports)}))
	}
	a.remarkCanaries()
	a.saveState()

	if on(a.cfg.SSH) {
		go a.runSSH(ctx)
	}
	if on(a.cfg.Processes) {
		if on(a.cfg.Rarity) {
			a.rare = loadRare(a.cfg.StateDir)
			go a.runRare(ctx)
		}
		go a.runProcesses(ctx)
	}
	if on(a.cfg.Volume) {
		go a.runVolume(ctx)
	}
	if on(a.cfg.Yara) {
		a.loadYaraState()
		go a.runTmpScan(ctx.Done())
	}
	if on(a.cfg.Updates) {
		go a.runUpdates(ctx)
	}
	if on(a.cfg.Suid) {
		go a.runSuid(ctx)
	}
	if on(a.cfg.Integrity) {
		go a.runIntegrity(ctx)
	}
	if on(a.cfg.Posture) {
		go a.runPosture(ctx)
	}
	if on(a.cfg.Secrets) {
		go a.runSecrets(ctx)
	}
	if on(a.cfg.Packages) {
		go a.runPackages(ctx)
	}
	for _, wl := range a.cfg.WebLogs {
		go a.tailWebLog(ctx, wl)
	}

	send := time.NewTicker(a.cfg.interval())
	scan := time.NewTicker(a.cfg.scan())
	// Outbound connections are sampled more often than files, so short-lived
	// ones are seen too; reading /proc/net is cheap.
	out := time.NewTicker(10 * time.Second)
	defer send.Stop()
	defer scan.Stop()
	defer out.Stop()
	a.send(ctx)
	for {
		select {
		case <-ctx.Done():
			a.emit(proto.NewEvent("agent.stopping", nil))
			sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			a.send(sctx)
			cancel()
			a.saveState()
			return nil
		case <-scan.C:
			a.scan()
			a.saveState()
		case <-send.C:
			a.send(ctx)
		case <-out.C:
			if on(a.cfg.Outbound) {
				a.scanOutbound()
			}
		case <-a.flushNow:
			a.send(ctx)
		}
	}
}

func (a *Agent) scan() {
	a.scanFiles()
	a.scanPorts()
	a.checkCanaries()
	a.scanKernel()
	a.scanBPF()
}

func (a *Agent) saveState() {
	// Collectors in other goroutines (web logs, updates) write into state
	// under a.mu, so it is serialized under the same lock.
	a.mu.Lock()
	defer a.mu.Unlock()
	a.state.JournalCursor = a.cursor
	if err := a.state.Save(a.cfg.StateDir); err != nil {
		log.Printf("state: %v", err)
	}
}

func (a *Agent) nextSeq() int64 {
	s := time.Now().UnixNano()
	if s <= a.lastSeq {
		s = a.lastSeq + 1
	}
	a.lastSeq = s
	return s
}

func (a *Agent) send(ctx context.Context) {
	a.flushSSHFailures()
	a.mu.Lock()
	events, rest, tooBig := splitBatch(a.queue, batchMaxBytes)
	a.queue = rest
	dropped := a.dropped
	a.dropped = 0
	a.mu.Unlock()
	for _, typ := range tooBig {
		events = append(events, proto.NewEvent("agent.warning", map[string]any{"collector": "send", "error": "event " + typ + " too large to send, dropped"}))
	}
	if len(rest) > 0 {
		defer a.flushSoon() // the rest goes in the next batch right away
	}
	if dropped > 0 {
		events = append(events, proto.NewEvent("agent.dropped", map[string]any{"count": dropped}))
	}
	if events == nil {
		events = []proto.Event{}
	}

	b := proto.Batch{AgentID: a.id.AgentID, Seq: a.nextSeq(), SentAt: time.Now().UTC(), ConfigVersion: a.state.ConfigVersion, Events: events}
	resp, err := a.post(ctx, "/api/agent/events", b)
	if err != nil {
		log.Printf("send: %v", err)
		a.mu.Lock()
		// Put events back in front, the cap still applies.
		a.queue = append(events, a.queue...)
		if over := len(a.queue) - a.cfg.MaxQueue; over > 0 {
			a.queue = a.queue[over:]
			a.dropped += over
		}
		a.mu.Unlock()
		return
	}
	var br proto.BatchResponse
	if err := json.Unmarshal(resp, &br); err != nil {
		log.Printf("send: bad response: %v", err)
		return
	}
	if len(br.Config) > 0 {
		a.handleConfig(br)
	}
}

func (a *Agent) handleConfig(br proto.BatchResponse) {
	if err := proto.Verify(a.id.ServerKey, br.Config, br.ConfigSig); err != nil {
		a.emit(proto.NewEvent("agent.config_rejected", map[string]any{"reason": "signature"}))
		return
	}
	var cfg proto.AgentConfig
	if err := json.Unmarshal(br.Config, &cfg); err != nil || cfg.AgentID != a.id.AgentID {
		a.emit(proto.NewEvent("agent.config_rejected", map[string]any{"reason": "content"}))
		return
	}
	if cfg.Version <= a.state.ConfigVersion {
		return
	}
	a.applyConfig(cfg)
	a.saveState()
	a.flushSoon()
}

func (a *Agent) post(ctx context.Context, path string, v any) ([]byte, error) {
	body, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(a.cfg.Server, "/")+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(proto.SigHeader, proto.Sign(a.id.PrivateKey, body))
	res, err := a.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	out, err := io.ReadAll(io.LimitReader(res.Body, proto.MaxBodyBytes))
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server answered %s: %s", res.Status, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// Enroll registers this host with a one-time token from the dashboard and
// stores the resulting identity.
func Enroll(cfg *Config, server, token string) (*Identity, error) {
	if _, err := LoadIdentity(cfg.StateDir); err == nil {
		return nil, errors.New("already enrolled; delete identity.json to enroll again")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	host, _ := os.Hostname()
	body, _ := json.Marshal(proto.EnrollRequest{Token: token, Hostname: host, PublicKey: proto.EncodeKey(pub), Version: Version})
	res, err := (&http.Client{Timeout: 15 * time.Second}).Post(strings.TrimRight(server, "/")+"/api/agent/enroll", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("enrollment refused: %s", strings.TrimSpace(string(raw)))
	}
	var er proto.EnrollResponse
	if err := json.Unmarshal(raw, &er); err != nil {
		return nil, err
	}
	sk, err := proto.DecodePublicKey(er.ServerKey)
	if err != nil {
		return nil, err
	}
	id := &Identity{AgentID: er.AgentID, Server: server, PrivateKey: priv, ServerKey: sk}
	if err := SaveIdentity(cfg.StateDir, id); err != nil {
		return nil, err
	}
	return id, nil
}

// batchMaxBytes keeps a batch well below the server's request limit
// (proto.MaxBodyBytes), with room for the envelope and the agent's own
// warnings. Evidence snapshots are up to 400 KB each.
const batchMaxBytes = 800 << 10

// splitBatch takes events from the front of the queue up to max bytes of
// JSON. An event that alone is larger can never be delivered; it is dropped
// and named, so one oversized event cannot block the queue for good.
func splitBatch(queue []proto.Event, max int) (batch, rest []proto.Event, tooBig []string) {
	size := 0
	for i, ev := range queue {
		raw, err := json.Marshal(ev)
		n := len(raw)
		if err != nil || n > max {
			tooBig = append(tooBig, ev.Type)
			continue
		}
		if size+n > max {
			return batch, append([]proto.Event{}, queue[i:]...), tooBig
		}
		size += n
		batch = append(batch, ev)
	}
	return batch, nil, tooBig
}
