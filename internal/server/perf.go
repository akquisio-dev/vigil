package server

import (
	"math"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

// Load analysis on top of the metrics: which programs were busy at a moment
// (the agent sends its busiest processes with every sample), when the host
// booted, where disk and memory are heading, and what load is normal for an
// hour of the week.

const (
	procHoursKeep = 7 * 24
	procHourTop   = 10
	bootsKeep     = 30 * 24 * time.Hour
	// a forecast needs two days of hours, a band three samples per bucket
	forecastMinHours = 48
	bandMinSamples   = 3
)

// procSample is the busiest programs of one minute or hour, in columns to
// keep metrics.json small: program names, CPU (percent of one core; for an
// hour the average), RSS in MiB and, for an hour, the CPU peak.
type procSample struct {
	T int64     `json:"t"`
	N []string  `json:"n"`
	C []float64 `json:"c"`
	R []uint32  `json:"r"`
	M []float64 `json:"m,omitempty"`
}

type procLoad struct {
	Name string  `json:"name"`
	CPU  float64 `json:"cpu"` // percent of one core
	Peak float64 `json:"peak,omitempty"`
	RSS  uint64  `json:"rss"` // bytes
	Seen int     `json:"seen,omitempty"`
}

// addProcs keeps the programs of a sample that carried them; processes of
// the same name are added up (php-fpm, postgres workers).
func (hm *hostMetrics) addProcs(m proto.Metrics) {
	if len(m.Top) == 0 {
		return
	}
	t := m.TS.Unix()
	if n := len(hm.ProcMinutes); n > 0 && hm.ProcMinutes[n-1].T >= t {
		return
	}
	idx := map[string]int{}
	var ps procSample
	ps.T = t
	for _, p := range m.Top {
		name := p.Comm
		if name == "" {
			continue
		}
		i, ok := idx[name]
		if !ok {
			i = len(ps.N)
			idx[name] = i
			ps.N, ps.C, ps.R = append(ps.N, name), append(ps.C, 0), append(ps.R, 0)
		}
		ps.C[i] = math.Round((ps.C[i]+p.CPU)*10) / 10
		ps.R[i] += uint32(min(p.RSS>>20, math.MaxUint32/2))
	}
	hm.ProcMinutes = append(hm.ProcMinutes, ps)
	cut := t - int64(metricsMinutes)*60
	i := 0
	for i < len(hm.ProcMinutes) && hm.ProcMinutes[i].T <= cut {
		i++
	}
	if i > 0 {
		hm.ProcMinutes = append([]procSample{}, hm.ProcMinutes[i:]...)
	}
}

// rollupProcs sums up the minutes of an hour: average CPU over the minutes
// the host reported, the peak, the largest memory. minutes is how many
// load samples the hour had.
func (hm *hostMetrics) rollupProcs(hour int64, minutes int) {
	if n := len(hm.ProcHours); n > 0 && hm.ProcHours[n-1].T >= hour {
		return
	}
	agg := map[string]*procLoad{}
	for _, ps := range hm.ProcMinutes {
		if ps.T < hour || ps.T >= hour+3600 {
			continue
		}
		for i, name := range ps.N {
			x := agg[name]
			if x == nil {
				x = &procLoad{Name: name}
				agg[name] = x
			}
			x.CPU += ps.C[i]
			x.Peak = math.Max(x.Peak, ps.C[i])
			x.RSS = max(x.RSS, uint64(ps.R[i]))
		}
	}
	if len(agg) == 0 {
		return
	}
	list := topLoads(agg, float64(max(minutes, 1)), procHourTop)
	ps := procSample{T: hour}
	for _, x := range list {
		ps.N, ps.C, ps.R, ps.M = append(ps.N, x.Name), append(ps.C, x.CPU), append(ps.R, uint32(x.RSS)), append(ps.M, x.Peak)
	}
	hm.ProcHours = append(hm.ProcHours, ps)
	if over := len(hm.ProcHours) - procHoursKeep; over > 0 {
		hm.ProcHours = append([]procSample{}, hm.ProcHours[over:]...)
	}
}

// topLoads turns sums into averages over n samples and keeps the busiest
// by CPU, then fills up with the largest by memory. RSS stays in the unit
// it came in.
func topLoads(agg map[string]*procLoad, n float64, keep int) []procLoad {
	all := make([]procLoad, 0, len(agg))
	for _, x := range agg {
		cp := *x
		cp.CPU = math.Round(cp.CPU/n*10) / 10
		all = append(all, cp)
	}
	sort.Slice(all, func(i, j int) bool {
		return all[i].CPU > all[j].CPU || all[i].CPU == all[j].CPU && all[i].Name < all[j].Name
	})
	var out []procLoad
	taken := map[string]bool{}
	for _, x := range all {
		if len(out) >= keep*2/3 {
			break
		}
		out, taken[x.Name] = append(out, x), true
	}
	sort.Slice(all, func(i, j int) bool {
		return all[i].RSS > all[j].RSS || all[i].RSS == all[j].RSS && all[i].Name < all[j].Name
	})
	for _, x := range all {
		if len(out) >= keep {
			break
		}
		if !taken[x.Name] {
			out = append(out, x)
		}
	}
	return out
}

// addBoot notes a reboot: the uptime went down.
func (hm *hostMetrics) addBoot(m proto.Metrics) {
	if hm.Last == nil || m.Uptime <= 0 || hm.Last.Uptime <= 0 || m.Uptime >= hm.Last.Uptime-60 {
		return
	}
	at := m.TS.Unix() - m.Uptime
	if n := len(hm.Boots); n > 0 && abs64(hm.Boots[n-1]-at) < 120 {
		return
	}
	hm.Boots = append(hm.Boots, at)
	cut := m.TS.Add(-bootsKeep).Unix()
	i := 0
	for i < len(hm.Boots) && hm.Boots[i] < cut {
		i++
	}
	hm.Boots = hm.Boots[i:]
}

func abs64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

// procsAt is the programs at a moment: the minute with programs nearest to
// it (at most two and a half minutes off) within the last day, the hour
// before that.
func (hm *hostMetrics) procsAt(at int64) (procSample, int64, bool) {
	best, gap := -1, int64(151)
	for i, ps := range hm.ProcMinutes {
		if d := abs64(ps.T - at); d < gap {
			best, gap = i, d
		}
	}
	if best >= 0 {
		return hm.ProcMinutes[best], 60, true
	}
	hour := at / 3600 * 3600
	for _, ps := range hm.ProcHours {
		if ps.T == hour {
			return ps, 3600, true
		}
	}
	return procSample{}, 0, false
}

// consumers are the busiest programs from..to: by average CPU and by memory.
func (hm *hostMetrics) consumers(from, to int64) (cpu, mem []procLoad) {
	// minutes for a span within the last day, even while they only began
	// recently (after an update); hours before that
	src := hm.ProcMinutes
	if n := len(hm.Minutes); n == 0 || from < hm.Minutes[n-1].T-int64(metricsMinutes)*60-60 {
		src = hm.ProcHours
	}
	agg := map[string]*procLoad{}
	n := 0
	for _, ps := range src {
		if ps.T < from || ps.T > to {
			continue
		}
		n++
		for i, name := range ps.N {
			x := agg[name]
			if x == nil {
				x = &procLoad{Name: name}
				agg[name] = x
			}
			x.CPU += ps.C[i]
			peak := ps.C[i]
			if len(ps.M) > i {
				peak = ps.M[i]
			}
			x.Peak = math.Max(x.Peak, peak)
			x.RSS = max(x.RSS, uint64(ps.R[i])<<20)
			x.Seen++
		}
	}
	if n == 0 {
		return []procLoad{}, []procLoad{}
	}
	all := topLoads(agg, float64(n), len(agg))
	sort.Slice(all, func(i, j int) bool {
		return all[i].CPU > all[j].CPU || all[i].CPU == all[j].CPU && all[i].Name < all[j].Name
	})
	cpu = append([]procLoad{}, all[:min(8, len(all))]...)
	sort.Slice(all, func(i, j int) bool {
		return all[i].RSS > all[j].RSS || all[i].RSS == all[j].RSS && all[i].Name < all[j].Name
	})
	mem = append([]procLoad{}, all[:min(8, len(all))]...)
	return cpu, mem
}

// trend fits a line through (t, v) and returns its slope per day and the
// value of the newest point; ok only with enough points over enough time.
func trend(pts []metricPoint, get func(metricPoint) float64, minPoints int) (perDay, last float64, ok bool) {
	if len(pts) < minPoints || pts[len(pts)-1].T-pts[0].T < int64(minPoints-1)*3600 {
		return 0, 0, false
	}
	var sx, sy, sxx, sxy float64
	t0 := float64(pts[0].T)
	for _, p := range pts {
		x, y := (float64(p.T)-t0)/86400, get(p)
		sx, sy, sxx, sxy = sx+x, sy+y, sxx+x*x, sxy+x*y
	}
	n := float64(len(pts))
	d := n*sxx - sx*sx
	if d == 0 {
		return 0, 0, false
	}
	return (n*sxy - sx*sy) / d, get(pts[len(pts)-1]), true
}

type forecast struct {
	Disk       float64  `json:"disk"`                   // fullest file system now, percent
	DiskPerDay *float64 `json:"disk_per_day,omitempty"` // points per day over the last week
	DiskDays   *float64 `json:"disk_full_days,omitempty"`
	MemPerDay  *float64 `json:"mem_per_day,omitempty"`
}

// forecastOf looks at the hours of the last week.
func (hm *hostMetrics) forecastOf(now time.Time) forecast {
	cut := now.Add(-7 * 24 * time.Hour).Unix()
	var pts []metricPoint
	for _, p := range hm.Hours {
		if p.T >= cut {
			pts = append(pts, p)
		}
	}
	var f forecast
	if n := len(hm.Minutes); n > 0 {
		f.Disk = hm.Minutes[n-1].Disk
	}
	r := func(v float64) *float64 { v = math.Round(v*100) / 100; return &v }
	if slope, _, ok := trend(pts, func(p metricPoint) float64 { return p.Disk }, forecastMinHours); ok {
		f.DiskPerDay = r(slope)
		// only a real rise counts: a tenth of a point a day or more
		if slope >= 0.1 {
			f.DiskDays = r(math.Max(0, (100-f.Disk)/slope))
		}
	}
	if slope, _, ok := trend(pts, func(p metricPoint) float64 { return p.Mem }, forecastMinHours); ok {
		f.MemPerDay = r(slope)
	}
	return f
}

// band is the normal range of a value per hour of the week (UTC, Monday
// 00:00 first), from the hours of the last 30 days: mean and two standard
// deviations, at least ten points wide. While fewer than three weeks are
// known, the hour of the day stands in (Kind "day", 24 entries).
type band struct {
	Kind string       `json:"kind"` // week | day
	CPU  [][2]float64 `json:"cpu"`
	Mem  [][2]float64 `json:"mem"`
	Net  [][2]float64 `json:"net"` // bytes per second in and out together
	N    []int        `json:"n"`   // hours behind each entry; fewer than three: no band
}

func weekHour(t int64) int {
	tm := time.Unix(t, 0).UTC()
	return (int(tm.Weekday())+6)%7*24 + tm.Hour()
}

func (hm *hostMetrics) bandOf() *band {
	build := func(buckets int, key func(int64) int) *band {
		b := &band{CPU: make([][2]float64, buckets), Mem: make([][2]float64, buckets), Net: make([][2]float64, buckets), N: make([]int, buckets)}
		vals := make([][3][]float64, buckets)
		for _, p := range hm.Hours {
			k := key(p.T)
			vals[k][0] = append(vals[k][0], p.CPU)
			vals[k][1] = append(vals[k][1], p.Mem)
			vals[k][2] = append(vals[k][2], p.RX+p.TX)
		}
		full := 0
		for k := range vals {
			b.N[k] = len(vals[k][0])
			if b.N[k] < bandMinSamples {
				continue
			}
			full++
			b.CPU[k] = spread(vals[k][0], 10, 100)
			b.Mem[k] = spread(vals[k][1], 10, 100)
			b.Net[k] = spread(vals[k][2], 0, math.Inf(1))
		}
		if full < buckets/2 {
			return nil
		}
		return b
	}
	if b := build(168, weekHour); b != nil {
		b.Kind = "week"
		return b
	}
	if b := build(24, func(t int64) int { return time.Unix(t, 0).UTC().Hour() }); b != nil {
		b.Kind = "day"
		return b
	}
	return nil
}

// spread is mean minus and plus two standard deviations, at least width
// apart, within 0..top.
func spread(v []float64, width, top float64) [2]float64 {
	var sum, sq float64
	for _, x := range v {
		sum += x
	}
	mean := sum / float64(len(v))
	for _, x := range v {
		sq += (x - mean) * (x - mean)
	}
	sd := math.Sqrt(sq / float64(len(v)))
	half := math.Max(2*sd, width/2)
	if width == 0 {
		half = math.Max(2*sd, mean*0.25)
	}
	lo, hi := math.Max(0, mean-half), math.Min(top, mean+half)
	return [2]float64{math.Round(lo*10) / 10, math.Round(hi*10) / 10}
}

// handleAgentProcs: GET /api/ui/agents/{id}/procs?at=UNIX, the programs at
// that moment.
func (s *Server) handleAgentProcs(w http.ResponseWriter, r *http.Request, sess *session) {
	id := r.PathValue("id")
	at, err := strconv.ParseInt(r.URL.Query().Get("at"), 10, 64)
	if err != nil {
		http.Error(w, "at: unix seconds", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	_, ok := s.state.Agents[id]
	s.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	out := map[string]any{"at": at, "found": false, "procs": []procLoad{}}
	s.metrics.mu.Lock()
	if hm := s.metrics.hosts[id]; hm != nil {
		if ps, step, ok := hm.procsAt(at); ok {
			list := make([]procLoad, len(ps.N))
			for i, n := range ps.N {
				list[i] = procLoad{Name: n, CPU: ps.C[i], RSS: uint64(ps.R[i]) << 20}
				if len(ps.M) > i {
					list[i].Peak = ps.M[i]
				}
			}
			sort.Slice(list, func(i, j int) bool { return list[i].CPU > list[j].CPU })
			out["found"], out["t"], out["step"], out["procs"] = true, ps.T, step, list
		}
		if hm.Last != nil {
			out["cores"] = hm.Last.Cores
		}
	}
	s.metrics.mu.Unlock()
	writeJSON(w, out)
}
