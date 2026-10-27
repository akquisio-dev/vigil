package server

import (
	"math"
	"testing"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

func TestProcHistory(t *testing.T) {
	hm := &hostMetrics{}
	start := time.Date(2026, 10, 27, 9, 50, 0, 0, time.UTC)
	for i := 0; i < 15; i++ { // 09:50 to 10:04
		ts := start.Add(time.Duration(i) * time.Minute)
		m := proto.Metrics{TS: ts, CPU: 50, Uptime: 1000 + int64(i)*60,
			Top: []proto.ProcLoad{{PID: 1, Comm: "php-fpm", CPU: 30, RSS: 100 << 20}, {PID: 2, Comm: "php-fpm", CPU: 20, RSS: 50 << 20}, {PID: 3, Comm: "redis", CPU: 1, RSS: 900 << 20}}}
		if i == 3 {
			m.Top = append(m.Top, proto.ProcLoad{PID: 4, Comm: "apache2", CPU: 400, RSS: 10 << 20})
		}
		if i == 12 {
			m.Uptime = 30 // rebooted
		}
		if i == 13 {
			m.Top = nil // a sample without detail
		}
		hm.add(m)
	}
	if len(hm.ProcMinutes) != 14 {
		t.Fatalf("minutes with programs: %d", len(hm.ProcMinutes))
	}
	first := hm.ProcMinutes[0]
	if first.N[0] != "php-fpm" || first.C[0] != 50 || first.R[0] != 150 {
		t.Fatalf("same name added up: %+v", first)
	}
	if len(hm.Boots) != 1 || hm.Boots[0] != start.Add(12*time.Minute).Unix()-30 {
		t.Fatalf("boots: %v", hm.Boots)
	}
	// the hour 09:00 was rolled up when 10:00 began
	if len(hm.ProcHours) != 1 || hm.ProcHours[0].T != start.Truncate(time.Hour).Unix() {
		t.Fatalf("hours: %+v", hm.ProcHours)
	}
	ph := hm.ProcHours[0]
	for i, n := range ph.N {
		if n == "apache2" && (ph.C[i] != 40 || ph.M[i] != 400) {
			t.Fatalf("apache2 average over 10 minutes and peak: %+v", ph)
		}
	}
	// a click at 09:53:20 finds the minute 09:53 with apache2
	ps, step, ok := hm.procsAt(start.Add(3*time.Minute + 20*time.Second).Unix())
	if !ok || step != 60 || len(ps.N) != 3 || ps.N[2] != "apache2" {
		t.Fatalf("procs at: %+v %d %v", ps, step, ok)
	}
	if _, _, ok := hm.procsAt(start.Add(-time.Hour).Unix()); ok {
		t.Fatal("nothing an hour before")
	}
	// a span reaching back before the first minute with programs still
	// uses the minutes
	cpu, mem := hm.consumers(start.Add(-time.Hour).Unix(), start.Add(time.Hour).Unix())
	if cpu[0].Name != "php-fpm" || cpu[0].CPU != 50 || mem[0].Name != "redis" || mem[0].RSS != 900<<20 {
		t.Fatalf("consumers: %+v %+v", cpu, mem)
	}
	// just after an update: minutes with programs, no hours yet
	fresh := &hostMetrics{Minutes: hm.Minutes, ProcMinutes: hm.ProcMinutes}
	if cpu, _ := fresh.consumers(start.Add(-time.Hour).Unix(), start.Add(time.Hour).Unix()); len(cpu) == 0 {
		t.Fatal("no hours yet: the minutes count")
	}
}

func TestForecastAndBand(t *testing.T) {
	hm := &hostMetrics{}
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	// too little history: neither
	for i := 0; i < 10; i++ {
		hm.Hours = append(hm.Hours, metricPoint{T: now.Add(time.Duration(i-10) * time.Hour).Unix(), Disk: 50})
	}
	if f := hm.forecastOf(now); f.DiskDays != nil || f.DiskPerDay != nil {
		t.Fatalf("no forecast from 10 hours: %+v", f)
	}
	if hm.bandOf() != nil {
		t.Fatal("no band from 10 hours")
	}
	// a disk growing two points a day for six days, CPU high at 03:00 UTC
	hm.Hours = nil
	for i := 6 * 24; i > 0; i-- {
		ts := now.Add(-time.Duration(i) * time.Hour)
		cpu := 10.0
		if ts.Hour() == 3 {
			cpu = 90
		}
		hm.Hours = append(hm.Hours, metricPoint{T: ts.Unix(), Disk: 80 + 2*float64(6*24-i)/24, Mem: 40, CPU: cpu, RX: 1000})
	}
	hm.Minutes = []metricPoint{{T: now.Unix(), Disk: 92}}
	f := hm.forecastOf(now)
	if f.DiskPerDay == nil || math.Abs(*f.DiskPerDay-2) > 0.05 || f.DiskDays == nil || math.Abs(*f.DiskDays-4) > 0.1 {
		t.Fatalf("forecast: %+v", f)
	}
	if f.MemPerDay == nil || *f.MemPerDay != 0 {
		t.Fatalf("memory flat: %+v", f)
	}
	b := hm.bandOf()
	if b == nil || b.Kind != "day" || b.N[3] != 6 || b.CPU[3][0] > 90 || b.CPU[3][1] < 90 || b.CPU[4][1] > 20 {
		t.Fatalf("band by hour of day: %+v", b)
	}
}
