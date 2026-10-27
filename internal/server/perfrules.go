package server

import (
	"fmt"
	"math"
	"strings"
	"time"
)

// Load alerts from the metrics: CPU busy for a while, a disk that is full
// or fills up within days, memory pressure with growing swap, and traffic
// that suddenly stopped. They are conditions: an alert when one begins,
// resolved by the system when it ends. Each ends only well below where it
// began, so a value hovering at the threshold does not alert again and
// again.

// PerfConfig sets the thresholds; every field has a default.
type PerfConfig struct {
	CPUPct     float64 `json:"cpu_pct"`     // perf.cpu_high: CPU at or above this, percent of all cores (90)
	CPUMinutes int     `json:"cpu_minutes"` // ... for this many minutes (15)
	DiskPct    float64 `json:"disk_pct"`    // perf.disk_full: fullest file system at or above this (90)
	DiskDays   float64 `json:"disk_days"`   // ... or full within this many days by the trend of the last week (7)
	MemPct     float64 `json:"mem_pct"`     // perf.mem_pressure: memory in use at or above this (92)
	SwapRise   float64 `json:"swap_rise"`   // ... while swap grew by this many points in 30 minutes (5)
	// perf.host_down_load: traffic of the last 10 minutes below 5 % of the
	// day's average, when that average was at least this, bytes per second
	// in and out together (50000)
	TrafficFloor float64 `json:"traffic_floor"`
	// Off lists rules to leave out, for example ["perf.host_down_load"].
	Off []string `json:"off,omitempty"`
}

func (c *Config) perf() PerfConfig {
	p := PerfConfig{CPUPct: 90, CPUMinutes: 15, DiskPct: 90, DiskDays: 7, MemPct: 92, SwapRise: 5, TrafficFloor: 50000}
	if c.Perf == nil {
		return p
	}
	x := *c.Perf
	if x.CPUPct > 0 && x.CPUPct <= 100 {
		p.CPUPct = x.CPUPct
	}
	if x.CPUMinutes > 0 && x.CPUMinutes <= 240 {
		p.CPUMinutes = x.CPUMinutes
	}
	if x.DiskPct > 0 && x.DiskPct <= 100 {
		p.DiskPct = x.DiskPct
	}
	if x.DiskDays > 0 {
		p.DiskDays = x.DiskDays
	}
	if x.MemPct > 0 && x.MemPct <= 100 {
		p.MemPct = x.MemPct
	}
	if x.SwapRise > 0 {
		p.SwapRise = x.SwapRise
	}
	if x.TrafficFloor > 0 {
		p.TrafficFloor = x.TrafficFloor
	}
	p.Off = x.Off
	return p
}

func (p PerfConfig) on(rule string) bool {
	for _, o := range p.Off {
		if o == rule {
			return false
		}
	}
	return true
}

// lastMinutes returns the minute points of the last n minutes before now.
func lastMinutes(hm *hostMetrics, n int, now int64) []metricPoint {
	cut := now - int64(n)*60 - 30
	i := len(hm.Minutes)
	for i > 0 && hm.Minutes[i-1].T > cut {
		i--
	}
	return hm.Minutes[i:]
}

func avgOf(pts []metricPoint, get func(metricPoint) float64) float64 {
	if len(pts) == 0 {
		return 0
	}
	sum := 0.0
	for _, p := range pts {
		sum += get(p)
	}
	return sum / float64(len(pts))
}

// perfConditions decides which load conditions hold. active tells whether
// a rule held before: it then ends only below its lower mark. Caller holds
// metrics.mu.
func perfConditions(hm *hostMetrics, active func(string) bool, c PerfConfig, now time.Time) []condition {
	var out []condition
	t := now.Unix()
	r1 := func(v float64) string { return fmt.Sprintf("%.1f", math.Round(v*10)/10) }
	cpu := func(p metricPoint) float64 { return p.CPU }
	mem := func(p metricPoint) float64 { return p.Mem }
	net := func(p metricPoint) float64 { return p.RX + p.TX }

	// a minute may be missing: a batch late or lost
	if win := lastMinutes(hm, c.CPUMinutes, t); c.on("perf.cpu_high") && len(win) >= c.CPUMinutes-1 {
		all := true
		for _, p := range win {
			all = all && p.CPU >= c.CPUPct
		}
		quiet := true
		for _, p := range lastMinutes(hm, 10, t) {
			quiet = quiet && p.CPU < c.CPUPct-10
		}
		if all || active("perf.cpu_high") && !quiet {
			params := map[string]string{"cpu": r1(avgOf(win, cpu)), "minutes": fmt.Sprint(c.CPUMinutes), "program": ""}
			if n := len(hm.ProcMinutes); n > 0 && len(hm.ProcMinutes[n-1].N) > 0 {
				ps := hm.ProcMinutes[n-1]
				best := 0
				for i := range ps.N {
					if ps.C[i] > ps.C[best] {
						best = i
					}
				}
				params["program"] = ps.N[best] + " " + r1(ps.C[best]) + " %"
			}
			out = append(out, condition{rule: "perf.cpu_high", params: params})
		}
	}

	if c.on("perf.disk_full") && len(hm.Minutes) > 0 {
		f := hm.forecastOf(now)
		soon := f.DiskDays != nil && *f.DiskDays <= c.DiskDays
		ended := f.Disk < c.DiskPct-5 && (f.DiskDays == nil || *f.DiskDays > c.DiskDays+3)
		if f.Disk >= c.DiskPct || soon || active("perf.disk_full") && !ended {
			days := "?"
			if f.DiskDays != nil {
				days = fmt.Sprintf("%.0f", *f.DiskDays)
			}
			out = append(out, condition{rule: "perf.disk_full", params: map[string]string{"disk": r1(f.Disk), "days": days}})
		}
	}

	if win := lastMinutes(hm, 10, t); c.on("perf.mem_pressure") && len(win) >= 8 {
		before := lastMinutes(hm, 35, t)
		var rise float64
		if len(before) > len(win) {
			rise = win[len(win)-1].Swap - before[0].Swap
		}
		m := avgOf(win, mem)
		ended := m < c.MemPct-7 || rise <= 0 && m < c.MemPct
		if m >= c.MemPct && rise >= c.SwapRise || active("perf.mem_pressure") && !ended {
			out = append(out, condition{rule: "perf.mem_pressure", params: map[string]string{"mem": r1(m), "swap": r1(win[len(win)-1].Swap), "rise": r1(rise)}})
		}
	}

	// without a day of hours there is no normal to drop from
	if win := lastMinutes(hm, 10, t); c.on("perf.host_down_load") && len(win) >= 8 && len(hm.Hours) >= 24 {
		base := avgOf(hm.Hours[len(hm.Hours)-24:], net)
		cur := avgOf(win, net)
		if base >= c.TrafficFloor && cur < base*0.05 || active("perf.host_down_load") && cur < base*0.2 {
			out = append(out, condition{rule: "perf.host_down_load", params: map[string]string{
				"now": fmtRateText(cur), "normal": fmtRateText(base)}})
		}
	}
	return out
}

func fmtRateText(b float64) string {
	switch {
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB/s", b/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.0f KB/s", b/(1<<10))
	}
	return fmt.Sprintf("%.0f B/s", b)
}

// checkPerf runs the load rules for a host after its samples came in.
// It takes s.mu and metrics.mu one after the other, never one inside the
// other.
func (s *Server) checkPerf(agent string) {
	c := s.cfg.perf()
	now := time.Now()
	s.mu.Lock()
	a := s.state.Agents[agent]
	if a == nil {
		s.mu.Unlock()
		return
	}
	prev := map[string]bool{}
	for k := range a.Conditions["perf"] {
		prev[strings.SplitN(k, "|", 2)[0]] = true
	}
	quiet := now.Before(a.MaintenanceUntil)
	s.mu.Unlock()
	if quiet {
		return
	}
	s.metrics.mu.Lock()
	var conds []condition
	if hm := s.metrics.hosts[agent]; hm != nil {
		conds = perfConditions(hm, func(r string) bool { return prev[r] }, c, now)
	}
	s.metrics.mu.Unlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	a = s.state.Agents[agent]
	if a == nil {
		return
	}
	before := len(a.Conditions["perf"])
	fresh := s.raise(s.conditionFindings(a, "perf", conds), agent, 0)
	if len(fresh) > 0 || before != len(a.Conditions["perf"]) {
		s.correlate(fresh)
		s.notifyAlerts(fresh)
		s.saveLocked()
	}
}
