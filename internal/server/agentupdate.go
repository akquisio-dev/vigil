package server

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
	"github.com/akquisio-dev/vigil/internal/release"
)

// Agent updates: an admin asks an agent for a release, the agent downloads
// and checks it, its update unit installs it and restarts the agent. The
// restart is expected, so it raises no agent.stopped or agent.restarted,
// but only while the update an admin asked for is running and only when
// the agent comes back with exactly that version. An agent that announces
// an update on its own lowers nothing (see MaintenanceUntil).

const (
	updateTimeout = 30 * time.Minute // asked until done
	updateGap     = 3 * time.Minute  // stopped until started again
)

type AgentUpdate struct {
	ID      string    `json:"id"`
	Version string    `json:"version"`
	From    string    `json:"from"`
	By      string    `json:"by"`
	Asked   time.Time `json:"asked"`
	Status  string    `json:"status"` // asked | staged | done | failed
	Error   string    `json:"error,omitempty"`
	Done    time.Time `json:"done,omitempty"`
	// Held is when the agent announced its stop during the update; the
	// alert waits for its return.
	Held time.Time `json:"held,omitempty"`
}

func (u *AgentUpdate) running(now time.Time) bool {
	return u != nil && (u.Status == "asked" || u.Status == "staged") && now.Sub(u.Asked) < updateTimeout
}

// askUpdate starts an update of a to version. The caller holds s.mu.
func (s *Server) askUpdate(a *AgentRec, version, by string) error {
	if !release.ValidVersion(version) {
		return fmt.Errorf("%q is not a release version", version)
	}
	if !release.Newer(version, a.Version) {
		return fmt.Errorf("%s is not newer than the agent's %s", version, a.Version)
	}
	if a.Update.running(time.Now()) {
		return fmt.Errorf("an update to %s is already running", a.Update.Version)
	}
	a.Update = &AgentUpdate{ID: newID(8), Version: version, From: a.Version, By: by, Asked: time.Now().UTC(), Status: "asked"}
	a.ConfigVersion++
	return nil
}

func (s *Server) pendingUpdate(a *AgentRec) *proto.UpdateRequest {
	if u := a.Update; u != nil && u.Status == "asked" && u.running(time.Now()) {
		return &proto.UpdateRequest{ID: u.ID, Version: u.Version}
	}
	return nil
}

// updateEvent follows the agent's reports. The caller holds s.mu.
func (s *Server) updateEvent(a *AgentRec, d map[string]any, add func(string, string, map[string]string)) {
	// The agent says whether its agent.json allows updates on every start;
	// a server updated after its agents only learns it here.
	switch st := str(d, "status"); {
	case st == "staged":
		a.SelfUpdate = true
	case st == "refused" && strings.HasPrefix(str(d, "error"), "self_update is off"):
		a.SelfUpdate = false
	}
	u := a.Update
	if u == nil || str(d, "id") != u.ID || u.Status == "done" || u.Status == "failed" {
		return
	}
	switch st := str(d, "status"); st {
	case "staged":
		u.Status = "staged"
	case "applied":
		u.Status, u.Done = "done", time.Now().UTC()
	case "refused", "failed", "rolled_back":
		u.Status, u.Error, u.Done = "failed", clip(st+": "+str(d, "error"), 300), time.Now().UTC()
		add("agent.update_failed", u.ID, map[string]string{"version": u.Version, "error": u.Error})
	}
}

// heldStop reports whether an announced stop is part of the update.
func (s *Server) heldStop(a *AgentRec, at time.Time) bool {
	// "asked" too: the stop may overtake the report that the download is
	// ready. The alert still comes if the agent is not back in time.
	if u := a.Update; u.running(time.Now()) {
		u.Held = at
		return true
	}
	return false
}

// updatedStart reports whether a start is the update coming back.
func (s *Server) updatedStart(a *AgentRec, version string) bool {
	u := a.Update
	if !u.running(time.Now()) {
		return false
	}
	if version != u.Version {
		// Back, but not with the new version (rolled back): the stop is
		// reported as a restart, not again later as a stop.
		u.Held = time.Time{}
		return false
	}
	u.Status, u.Done, u.Held = "done", time.Now().UTC(), time.Time{}
	return true
}

// checkUpdates raises what the update held back once it is clear the
// agent is not coming back, and ends updates that never finished. The
// caller holds s.mu; it returns the new alerts.
func (s *Server) checkUpdates(now time.Time) []*Alert {
	var fresh []*Alert
	for _, a := range s.state.Agents {
		u := a.Update
		if u == nil || u.Status == "done" || u.Status == "failed" {
			continue
		}
		var fs []finding
		if !u.Held.IsZero() && now.Sub(u.Held) > updateGap {
			fs = append(fs, finding{Rule: "agent.stopped", Key: "agent.stopped|" + a.ID + "|", Params: map[string]string{"host": a.Name}})
			u.Status, u.Error, u.Done = "failed", "the agent did not come back after the update", now.UTC()
		} else if now.Sub(u.Asked) >= updateTimeout {
			u.Error = "no result after 30 minutes"
			if u.Status == "staged" {
				u.Error = "downloaded but not installed; is vigil-agent-update.path enabled on the host?"
			}
			u.Status, u.Done = "failed", now.UTC()
		} else {
			continue
		}
		fs = append(fs, finding{Rule: "agent.update_failed", Key: "agent.update_failed|" + a.ID + "|" + u.ID,
			Params: map[string]string{"host": a.Name, "version": u.Version, "error": u.Error}})
		got := s.raise(fs, a.ID, 0)
		s.correlate(got)
		fresh = append(fresh, got...)
	}
	return fresh
}

// latestRelease is asked by the dashboard, at most once an hour.
type latestCache struct {
	mu      sync.Mutex
	version string
	err     string
	at      time.Time
}

func (s *Server) latestRelease() (string, string) {
	c := &s.latest
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Since(c.at) < time.Hour && c.at.After(time.Time{}) {
		return c.version, c.err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	v, err := release.Latest(ctx)
	c.version, c.err, c.at = v, "", time.Now()
	if err != nil {
		c.err = err.Error()
		c.at = time.Now().Add(-50 * time.Minute) // try again in ten minutes
	}
	return c.version, c.err
}

func (s *Server) handleLatestRelease(w http.ResponseWriter, r *http.Request, sess *session) {
	v, err := s.latestRelease()
	writeJSON(w, map[string]any{"version": v, "error": err, "server": Version})
}
