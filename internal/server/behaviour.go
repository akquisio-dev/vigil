package server

import (
	"fmt"
	"sort"
	"time"
)

// Behaviour baselines kept by the server: when each user usually logs in,
// and how much each host usually sends.

const (
	loginHoursMin  = 20 // logins of a user before an odd hour counts
	volumeKeep     = 14 * 24
	volumeMinHours = 72
	volumeMinBytes = 1 << 30
	volumeFactor   = 3
)

type VolumeHour struct {
	At time.Time `json:"at"`
	TX uint64    `json:"tx"`
	RX uint64    `json:"rx"`
}

// loginHour records a login and tells whether its hour is unusual for the
// user: enough logins before, none within an hour of this one. Caller
// holds s.mu.
func (s *Server) loginHour(user string, at time.Time) (hour, total int, rare bool) {
	if s.state.LoginHours == nil {
		s.state.LoginHours = map[string]*[24]int{}
	}
	hs := s.state.LoginHours[user]
	if hs == nil {
		if len(s.state.LoginHours) > 1000 {
			return 0, 0, false
		}
		hs = &[24]int{}
		s.state.LoginHours[user] = hs
	}
	hour = at.UTC().Hour()
	for _, n := range hs {
		total += n
	}
	near := hs[hour] + hs[(hour+1)%24] + hs[(hour+23)%24]
	rare = total >= loginHoursMin && near == 0
	hs[hour]++
	return hour, total, rare
}

func humanBytes(b uint64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.0f MB", float64(b)/(1<<20))
	}
	return fmt.Sprintf("%d KB", b>>10)
}

// volumeFinding keeps the hourly history and returns alert parameters when
// this hour sent far more than any usual hour. Caller holds s.mu.
func volumeFinding(a *AgentRec, d map[string]any, at time.Time) map[string]string {
	tx, rx := uint64(num(d, "tx_bytes")), uint64(num(d, "rx_bytes"))
	hist := make([]uint64, 0, len(a.Volume))
	for _, v := range a.Volume {
		hist = append(hist, v.TX)
	}
	a.Volume = append(a.Volume, VolumeHour{At: at, TX: tx, RX: rx})
	if over := len(a.Volume) - volumeKeep; over > 0 {
		a.Volume = append([]VolumeHour{}, a.Volume[over:]...)
	}
	if len(hist) < volumeMinHours || tx < volumeMinBytes {
		return nil
	}
	sort.Slice(hist, func(i, j int) bool { return hist[i] < hist[j] })
	p95 := hist[len(hist)*95/100]
	max := hist[len(hist)-1]
	if tx <= volumeFactor*p95 || tx <= max {
		return nil
	}
	return map[string]string{"sent": humanBytes(tx), "usual": humanBytes(p95), "max": humanBytes(max), "received": humanBytes(rx)}
}
