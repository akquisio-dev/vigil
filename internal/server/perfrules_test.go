package server

import (
	"testing"
	"time"
)

func perfHost(now time.Time, minutes int, fill func(i int, p *metricPoint)) *hostMetrics {
	hm := &hostMetrics{}
	for i := minutes; i > 0; i-- {
		p := metricPoint{T: now.Add(-time.Duration(i) * time.Minute).Unix(), CPU: 20, Mem: 50, Disk: 40, RX: 1000, TX: 1000}
		fill(minutes-i, &p)
		hm.Minutes = append(hm.Minutes, p)
	}
	return hm
}

func rulesOf(cs []condition) map[string]map[string]string {
	out := map[string]map[string]string{}
	for _, c := range cs {
		out[c.rule] = c.params
	}
	return out
}

func TestPerfConditions(t *testing.T) {
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	c := (&Config{}).perf()
	none := func(string) bool { return false }
	was := func(r string) func(string) bool { return func(x string) bool { return x == r } }

	// CPU at 95 % for the last 16 minutes, one minute missing
	hm := perfHost(now, 30, func(i int, p *metricPoint) {
		if i >= 14 {
			p.CPU = 95
		}
	})
	hm.Minutes = append(hm.Minutes[:20], hm.Minutes[21:]...)
	hm.ProcMinutes = []procSample{{T: now.Unix() - 60, N: []string{"nginx", "kworkerd"}, C: []float64{3, 760}, R: []uint32{50, 10}}}
	got := rulesOf(perfConditions(hm, none, c, now))
	if p := got["perf.cpu_high"]; p == nil || p["cpu"] != "95.0" || p["program"] != "kworkerd 760.0 %" {
		t.Fatalf("cpu_high: %v", got)
	}
	// 14 minutes are not enough
	hm = perfHost(now, 30, func(i int, p *metricPoint) {
		if i >= 16 {
			p.CPU = 95
		}
	})
	if got := rulesOf(perfConditions(hm, none, c, now)); got["perf.cpu_high"] != nil {
		t.Fatalf("14 minutes: %v", got)
	}
	// once on, 85 % keeps it on; 10 minutes below 80 end it
	hm = perfHost(now, 30, func(i int, p *metricPoint) { p.CPU = 85 })
	if got := rulesOf(perfConditions(hm, was("perf.cpu_high"), c, now)); got["perf.cpu_high"] == nil {
		t.Fatal("hysteresis: still on at 85 %")
	}
	hm = perfHost(now, 30, func(i int, p *metricPoint) { p.CPU = 70 })
	if got := rulesOf(perfConditions(hm, was("perf.cpu_high"), c, now)); got["perf.cpu_high"] != nil {
		t.Fatal("ends below 80 %")
	}

	// disk at 93 %
	hm = perfHost(now, 30, func(i int, p *metricPoint) { p.Disk = 93 })
	if got := rulesOf(perfConditions(hm, none, c, now)); got["perf.disk_full"]["disk"] != "93.0" || got["perf.disk_full"]["days"] != "?" {
		t.Fatalf("disk_full: %v", got)
	}
	// 87 %: off unless it was on
	hm = perfHost(now, 30, func(i int, p *metricPoint) { p.Disk = 87 })
	if got := rulesOf(perfConditions(hm, none, c, now)); got["perf.disk_full"] != nil {
		t.Fatal("87 % alone")
	}
	if got := rulesOf(perfConditions(hm, was("perf.disk_full"), c, now)); got["perf.disk_full"] == nil {
		t.Fatal("87 % after 93 % stays on")
	}

	// memory full and swap growing 8 points in half an hour
	hm = perfHost(now, 40, func(i int, p *metricPoint) { p.Mem = 96; p.Swap = 10 + float64(i)/5 })
	if got := rulesOf(perfConditions(hm, none, c, now)); got["perf.mem_pressure"] == nil {
		t.Fatalf("mem_pressure: %v", got)
	}
	// full but swap flat: a database using its memory
	hm = perfHost(now, 40, func(i int, p *metricPoint) { p.Mem = 96; p.Swap = 10 })
	if got := rulesOf(perfConditions(hm, none, c, now)); got["perf.mem_pressure"] != nil {
		t.Fatal("flat swap")
	}

	// traffic: no alert without a day of hours, then a drop from 400 KB/s
	hm = perfHost(now, 20, func(i int, p *metricPoint) { p.RX, p.TX = 300, 200 })
	if got := rulesOf(perfConditions(hm, none, c, now)); got["perf.host_down_load"] != nil {
		t.Fatal("no baseline")
	}
	for i := 24; i > 0; i-- {
		hm.Hours = append(hm.Hours, metricPoint{T: now.Add(-time.Duration(i) * time.Hour).Unix(), RX: 300e3, TX: 100e3})
	}
	if got := rulesOf(perfConditions(hm, none, c, now)); got["perf.host_down_load"]["normal"] != "391 KB/s" {
		t.Fatalf("host_down_load: %v", got)
	}
	// a quiet host never had traffic to lose
	for i := range hm.Hours {
		hm.Hours[i].RX, hm.Hours[i].TX = 3000, 1000
	}
	if got := rulesOf(perfConditions(hm, none, c, now)); got["perf.host_down_load"] != nil {
		t.Fatal("below the floor")
	}

	// a rule turned off
	c.Off = []string{"perf.disk_full"}
	hm = perfHost(now, 30, func(i int, p *metricPoint) { p.Disk = 99 })
	if got := rulesOf(perfConditions(hm, none, c, now)); got["perf.disk_full"] != nil {
		t.Fatal("off")
	}
}

func TestCheckPerfRaisesAndResolves(t *testing.T) {
	s, err := New(&Config{DataDir: t.TempDir(), SessionHours: 1, Perf: &PerfConfig{CPUMinutes: 5}})
	if err != nil {
		t.Fatal(err)
	}
	s.state.Agents["h1"] = &AgentRec{ID: "h1", Name: "game"}
	now := time.Now()
	s.metrics.hosts = map[string]*hostMetrics{"h1": perfHost(now, 10, func(i int, p *metricPoint) { p.CPU = 99 })}
	s.checkPerf("h1")
	s.checkPerf("h1") // the same condition again: no second alert
	var open []*Alert
	for _, al := range s.state.Alerts {
		if al.Rule == "perf.cpu_high" && al.Status == "open" {
			open = append(open, al)
		}
	}
	if len(open) != 1 || open[0].Agent != "h1" {
		t.Fatalf("alerts: %+v", s.state.Alerts)
	}
	s.metrics.hosts["h1"] = perfHost(now, 15, func(i int, p *metricPoint) { p.CPU = 5 })
	s.checkPerf("h1")
	if open[0].Status != "resolved" || open[0].By != "system" {
		t.Fatalf("resolved when it ended: %+v", open[0])
	}
	// in maintenance nothing is raised
	s.state.Agents["h1"].MaintenanceUntil = now.Add(time.Hour)
	s.metrics.hosts["h1"] = perfHost(now, 10, func(i int, p *metricPoint) { p.CPU = 99 })
	s.checkPerf("h1")
	if n := len(s.state.Alerts); n != 1 {
		t.Fatalf("maintenance: %d alerts", n)
	}
}
