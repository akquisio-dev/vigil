package server

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

// A self test asks one agent to leave harmless traces that real detections
// must catch: a comment-only file in a cron directory, a copy of `sleep` started
// from /tmp, and an sshd log line written by the agent instead of sshd. The
// server then checks that each trace came back as the expected finding, and
// sends the result through every notifier, so the whole path from sensor to
// phone is proven, not assumed.
//
// Findings are matched to the test by a random marker in the trace (the test
// id), never by time: an attacker acting while a test runs must still raise
// a normal alert. The marker is not secret (local users see it in `ps` while
// the step runs), so a finding only counts as the test's own when its rule is
// a step rule and its event has the exact shape of the agent's trace, which
// only root can produce. Matched findings raise no alert; they are kept in
// the event log like every other event.

// selfTestSteps maps each step to the rule that must fire for it.
var selfTestSteps = []struct{ Step, Rule string }{
	{"file", "file.cron"},
	{"process", "process.tmp_exec"},
	{"journal", "log.spoofed"},
}

const (
	selfTestWait  = 10 * time.Minute // for the agent to pick the test up
	selfTestGrace = 90 * time.Second // after the agent is done, for late findings
)

type SelfTestStep struct {
	Step   string `json:"step"`
	Rule   string `json:"rule"`
	Status string `json:"status"` // waiting | ok | suppressed | skipped | missing
	Detail string `json:"detail,omitempty"`
}

type SelfTest struct {
	ID       string            `json:"id"`
	Agent    string            `json:"agent"`
	By       string            `json:"by"`
	Created  time.Time         `json:"created"`
	Ran      time.Time         `json:"ran,omitempty"` // agent reported it is done
	Finished time.Time         `json:"finished,omitempty"`
	Status   string            `json:"status"` // pending | running | passed | warning | failed
	Error    string            `json:"error,omitempty"`
	Steps    []*SelfTestStep   `json:"steps"`
	Notified map[string]string `json:"notified,omitempty"` // notifier -> "ok" or error
}

func (t *SelfTest) marker() string { return "vigil-selftest-" + t.ID }

func (t *SelfTest) open() bool { return t.Status == "pending" || t.Status == "running" }

func (t *SelfTest) stepFor(rule string) *SelfTestStep {
	for _, st := range t.Steps {
		if st.Rule == rule {
			return st
		}
	}
	return nil
}

func (t *SelfTest) step(name string) *SelfTestStep {
	for _, st := range t.Steps {
		if st.Step == name {
			return st
		}
	}
	return nil
}

// startSelfTest queues a test for an agent. Caller holds s.mu.
func (s *Server) startSelfTest(a *AgentRec, by string) (*SelfTest, error) {
	if !a.SelfTest {
		return nil, fmt.Errorf("agent %s does not offer self tests (older version, or selftest off in agent.json)", a.Name)
	}
	for _, t := range s.state.SelfTests {
		if t.Agent == a.ID && t.open() {
			return nil, fmt.Errorf("a self test is already running on %s", a.Name)
		}
	}
	t := &SelfTest{ID: newID(8), Agent: a.ID, By: by, Created: time.Now().UTC(), Status: "pending"}
	for _, st := range selfTestSteps {
		t.Steps = append(t.Steps, &SelfTestStep{Step: st.Step, Rule: st.Rule, Status: "waiting"})
	}
	s.state.SelfTests = append(s.state.SelfTests, t)
	if over := len(s.state.SelfTests) - 200; over > 0 {
		s.state.SelfTests = append([]*SelfTest{}, s.state.SelfTests[over:]...)
	}
	a.LastSelfTest = t.Created
	a.ConfigVersion++
	return t, nil
}

// pendingSelfTest is sent to the agent in its signed configuration. Caller
// holds s.mu.
func (s *Server) pendingSelfTest(agentID string) *proto.SelfTest {
	for _, t := range s.state.SelfTests {
		if t.Agent == agentID && t.Status == "pending" {
			return &proto.SelfTest{ID: t.ID, Expires: t.Created.Add(selfTestWait)}
		}
	}
	return nil
}

// selfTestCronDirs must match the agent's list.
var selfTestCronDirs = []string{"/var/spool/cron/crontabs", "/etc/cron.d"}

// ownTrace reports whether a finding is exactly the trace the agent leaves
// for this step. Every check needs root on the host to fake: the cron
// directories are root-only, the program runs as uid 0, the log line is
// written by root.
func ownTrace(rule, marker string, d map[string]any) bool {
	switch rule {
	case "file.cron":
		p := str(d, "path")
		for _, dir := range selfTestCronDirs {
			if p == dir+"/"+marker {
				return true
			}
		}
	case "process.tmp_exec":
		exe := str(d, "exe")
		rest, ok := strings.CutPrefix(exe, "/tmp/"+marker+"-")
		sigs := strSlice(d["signals"])
		return ok && str(d, "uid") == "0" && len(sigs) == 1 && sigs[0] == "tmp_exe" &&
			strings.HasSuffix(rest, "/sleep") && strings.Count(rest, "/") == 1
	case "log.spoofed":
		return str(d, "uid") == "0" && strings.HasPrefix(str(d, "message"), marker+" ")
	}
	return false
}

// selfTestFindings records the findings that are an open test's own traces
// as step results and returns all other findings unchanged. Caller holds
// s.mu.
func (s *Server) selfTestFindings(a *AgentRec, rec *Record, fs []finding) []finding {
	if len(fs) == 0 {
		return fs
	}
	var t *SelfTest
	raw, _ := json.Marshal(rec.Event.Data)
	for _, x := range s.state.SelfTests {
		if x.Agent == a.ID && x.open() && strings.Contains(string(raw), x.marker()) {
			t = x
			break
		}
	}
	if t == nil {
		return fs
	}
	now := time.Now()
	var keep []finding
	for _, f := range fs {
		st := t.stepFor(f.Rule)
		if st == nil || !ownTrace(f.Rule, t.marker(), rec.Event.Data) {
			keep = append(keep, f)
			continue
		}
		if st.Status == "ok" || st.Status == "suppressed" {
			continue // the removal of the test file, a second sighting
		}
		st.Status, st.Detail = "ok", renderTitle(f.Rule, f.Params, s.cfg.Language)
		if sp := s.suppressed(f, a.ID, now); sp != nil {
			st.Status, st.Detail = "suppressed", sp.Reason
		}
	}
	return keep
}

// selfTestEvent handles the agent's own reports. Caller holds s.mu.
func (s *Server) selfTestEvent(a *AgentRec, typ string, d map[string]any) {
	var t *SelfTest
	for _, x := range s.state.SelfTests {
		if x.ID == str(d, "id") && x.Agent == a.ID && x.open() {
			t = x
		}
	}
	if t == nil {
		return
	}
	switch typ {
	case "selftest.started":
		t.Status = "running"
	case "selftest.step":
		st := t.step(str(d, "step"))
		if st == nil || st.Status != "waiting" {
			break
		}
		if why := str(d, "skipped"); why != "" {
			st.Status, st.Detail = "skipped", clip(why, 200)
		} else if why := str(d, "error"); why != "" {
			st.Detail = clip(why, 200) // stays waiting, ends as missing
		}
	case "selftest.done":
		t.Status = "running"
		t.Ran = time.Now().UTC()
		if e := str(d, "error"); e != "" {
			t.Error = clip(e, 200)
		}
	}
}

// checkSelfTests finishes tests whose steps all arrived, or whose time ran
// out. Caller holds s.mu.
func (s *Server) checkSelfTests() bool {
	now := time.Now()
	changed := false
	for _, t := range s.state.SelfTests {
		if !t.open() {
			continue
		}
		waiting := 0
		for _, st := range t.Steps {
			if st.Status == "waiting" {
				waiting++
			}
		}
		switch {
		case !t.Ran.IsZero() && waiting == 0:
		case !t.Ran.IsZero() && now.Sub(t.Ran) > selfTestGrace:
		case t.Ran.IsZero() && now.Sub(t.Created) > selfTestWait+selfTestGrace:
			if t.Error == "" {
				t.Error = "the agent did not run the test"
			}
		default:
			continue
		}
		s.finishSelfTest(t)
		changed = true
	}
	return changed
}

// finishSelfTest grades the test, records it in the event log and sends the
// result through every notifier. Caller holds s.mu.
func (s *Server) finishSelfTest(t *SelfTest) {
	t.Finished = time.Now().UTC()
	t.Status = "passed"
	var missing, warn []string
	for _, st := range t.Steps {
		switch st.Status {
		case "waiting":
			st.Status = "missing"
			if st.Detail != "" {
				missing = append(missing, st.Step+" ("+st.Detail+")")
			} else {
				missing = append(missing, st.Step)
			}
		case "suppressed", "skipped":
			warn = append(warn, st.Step)
		}
	}
	if len(warn) > 0 {
		t.Status = "warning"
	}
	if len(missing) > 0 || t.Error != "" {
		t.Status = "failed"
	}
	host := t.Agent
	if a := s.state.Agents[t.Agent]; a != nil {
		host = a.Name
	}
	steps := map[string]string{}
	for _, st := range t.Steps {
		steps[st.Step] = st.Status
	}
	s.record("server", t.By, t.Agent, proto.NewEvent("selftest.finished", map[string]any{"id": t.ID, "status": t.Status, "steps": steps, "error": t.Error}))

	var m message
	if t.Status == "failed" {
		why := strings.Join(missing, ", ")
		if t.Error != "" {
			why = strings.TrimPrefix(why+", "+t.Error, ", ")
		}
		fresh := s.raise([]finding{{Rule: "selftest.failed", Key: "selftest.failed|" + t.Agent + "|" + t.ID,
			Params: map[string]string{"host": host, "missing": why}}}, t.Agent, 0)
		s.correlate(fresh)
		if len(fresh) == 0 {
			return
		}
		m = s.alertMessage(fresh[0])
	} else {
		m = message{Severity: "info", Text: s.selfTestSummary(t, host)}
	}
	if len(s.cfg.Notifiers) > 0 {
		go s.deliverSelfTest(t.ID, m)
	}
}

func (s *Server) selfTestSummary(t *SelfTest, host string) string {
	de := s.cfg.Language == "de"
	head := "vigil self test on " + host + ": "
	if de {
		head = "vigil Selbsttest auf " + host + ": "
	}
	word := map[string][2]string{
		"passed": {"passed", "bestanden"}, "warning": {"passed with warnings", "bestanden mit Hinweisen"},
		"ok": {"detected", "erkannt"}, "suppressed": {"detected but suppressed", "erkannt, aber unterdrückt"},
		"skipped": {"skipped", "übersprungen"},
	}
	pick := func(k string) string {
		if de {
			return word[k][1]
		}
		return word[k][0]
	}
	lines := []string{head + pick(t.Status)}
	for _, st := range t.Steps {
		l := "  " + st.Rule + ": " + pick(st.Status)
		if st.Status == "skipped" || st.Status == "suppressed" {
			l += " (" + st.Detail + ")"
		}
		lines = append(lines, l)
	}
	return strings.Join(lines, "\n")
}

// deliverSelfTest sends the result to every notifier, whatever its
// min_severity, and stores who got it. Runs without s.mu.
func (s *Server) deliverSelfTest(id string, m message) {
	results := map[string]string{}
	for _, n := range s.cfg.Notifiers {
		err := deliver(n, m)
		if err != nil {
			time.Sleep(5 * time.Second)
			err = deliver(n, m)
		}
		results[n.Name] = "ok"
		if err != nil {
			results[n.Name] = clip(err.Error(), 200)
		}
		s.noteDelivery(n, err)
	}
	s.mu.Lock()
	for _, t := range s.state.SelfTests {
		if t.ID == id {
			t.Notified = results
		}
	}
	s.saveLocked()
	s.mu.Unlock()
}

// scheduleSelfTests starts the periodic test on every agent that is due.
// A host that never ran one is due at once, so a fresh enrollment proves
// the whole path within a minute. Caller holds s.mu.
func (s *Server) scheduleSelfTests() bool {
	days := s.cfg.SelfTestDays
	if days < 0 {
		return false
	}
	now := time.Now()
	changed := false
	for _, a := range s.state.Agents {
		if !a.SelfTest || a.Silent || a.Stopped || now.Before(a.MaintenanceUntil) || now.Sub(a.LastSelfTest) < time.Duration(days)*24*time.Hour {
			continue
		}
		if _, err := s.startSelfTest(a, "schedule"); err == nil {
			changed = true
		}
	}
	return changed
}
