package server

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

func protoEventNow(typ string, d map[string]any) proto.Event { return proto.NewEvent(typ, d) }

// Playbooks start response actions on their own when an alert of one of
// their rules is raised, for example stopping a crypto miner at once. They
// are off unless server.json lists them, every action still has to be
// allowed by the host's agent.json, four-eyes applies to them like to a
// person's request, and each playbook runs at most max_per_hour times, so
// alerts an attacker provokes cannot turn into a flood of measures (for
// example isolating every host). Every run is in the audit log and in the
// notifications.

type Playbook struct {
	Name string `json:"name"`
	// Rules the playbook reacts to, "*" at the end matches a prefix
	// ("process.*").
	Rules []string `json:"rules"`
	// MinSeverity of the alert (default high).
	MinSeverity string `json:"min_severity,omitempty"`
	// Hosts limits the playbook to these host names (default all).
	Hosts []string `json:"hosts,omitempty"`
	// Actions are action types; their parameters come from the alert.
	Actions []string `json:"actions"`
	// Minutes for block_ip, isolate_host and lock_user (default 60).
	Minutes int `json:"minutes,omitempty"`
	// MaxPerHour caps the runs (default 3).
	MaxPerHour int `json:"max_per_hour,omitempty"`
}

var playbookTypes = map[string]bool{"block_ip": true, "kill_process": true, "kill_session": true, "isolate_host": true, "lock_user": true, "remove_key": true}

func validatePlaybook(p Playbook) error {
	if p.Name == "" || len(p.Rules) == 0 || len(p.Actions) == 0 {
		return fmt.Errorf("playbook %q needs name, rules and actions", p.Name)
	}
	for _, t := range p.Actions {
		if !playbookTypes[t] {
			return fmt.Errorf("playbook %s: action %q cannot run automatically", p.Name, t)
		}
	}
	if p.MinSeverity != "" && severityRank[p.MinSeverity] == 0 {
		return fmt.Errorf("playbook %s: unknown min_severity", p.Name)
	}
	if p.Minutes < 0 || p.Minutes > 24*60 {
		return fmt.Errorf("playbook %s: minutes must be 1 to 1440", p.Name)
	}
	return nil
}

func (p Playbook) matches(al *Alert, host string) bool {
	min := p.MinSeverity
	if min == "" {
		min = "high"
	}
	if severityRank[al.Severity] < severityRank[min] {
		return false
	}
	if len(p.Hosts) > 0 {
		ok := false
		for _, h := range p.Hosts {
			ok = ok || h == host
		}
		if !ok {
			return false
		}
	}
	for _, r := range p.Rules {
		if r == al.Rule || strings.HasSuffix(r, "*") && strings.HasPrefix(al.Rule, strings.TrimSuffix(r, "*")) {
			return true
		}
	}
	return false
}

// runPlaybooks reacts to fresh alerts. Caller holds s.mu.
func (s *Server) runPlaybooks(fresh []*Alert) []string {
	var done []string
	now := time.Now().UTC()
	for _, al := range fresh {
		a := s.state.Agents[al.Agent]
		if a == nil {
			continue
		}
		for _, pb := range s.cfg.Playbooks {
			if validatePlaybook(pb) != nil || !pb.matches(al, a.Name) {
				continue
			}
			max := pb.MaxPerHour
			if max <= 0 {
				max = 3
			}
			if s.playbookRuns == nil {
				s.playbookRuns = map[string][]time.Time{}
			}
			var recent []time.Time
			for _, t := range s.playbookRuns[pb.Name] {
				if now.Sub(t) < time.Hour {
					recent = append(recent, t)
				}
			}
			if len(recent) >= max {
				s.playbookRuns[pb.Name] = recent
				log.Printf("playbook %s: limit of %d runs per hour reached, alert %s left to people", pb.Name, max, al.ID)
				continue
			}
			s.playbookRuns[pb.Name] = append(recent, now)
			mins := pb.Minutes
			if mins <= 0 {
				mins = 60
			}
			suggested := s.suggestActions(al)
			for _, t := range pb.Actions {
				allowed := false
				for _, x := range a.ResponseTypes {
					allowed = allowed || x == t
				}
				if !allowed {
					continue // the host does not accept it; people decide
				}
				var params map[string]string
				for _, sg := range suggested {
					if sg.Type == t {
						params = sg.Params
						break
					}
				}
				if params == nil {
					continue // nothing in this alert to act on
				}
				if _, ok := params["minutes"]; ok || t == "isolate_host" {
					params["minutes"] = strconv.Itoa(mins)
				}
				act := s.queueAction(a, t, params, al.ID, "playbook:"+pb.Name, pb.Name)
				done = append(done, fmt.Sprintf("%s %s on %s (%s)", pb.Name, t, a.Name, act.Status))
				s.record("server", "playbook:"+pb.Name, a.ID, protoEventNow("response.requested", map[string]any{"action": act.ID,
					"agent": a.ID, "type": t, "params": act.Params, "alert": al.ID, "playbook": pb.Name, "status": act.Status}))
			}
		}
	}
	return done
}
