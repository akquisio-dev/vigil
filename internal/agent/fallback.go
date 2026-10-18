package agent

import (
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/akquisio-dev/vigil/internal/notify"
)

// fallbackWatch tells the fallback notifier when the server has taken no
// batch for a while, and again once it does. The server's own alarms can
// not report the server being gone, a dead network path or a broken
// server key; this one does not depend on the server at all.
type fallbackWatch struct {
	cfg   notify.Config
	after time.Duration
	host  string
	send  func(notify.Config, notify.Message) error

	mu       sync.Mutex
	lastOK   time.Time
	down     bool // the outage notice went out
	inflight bool
}

func newFallbackWatch(cfg *Config) *fallbackWatch {
	if cfg.Fallback == nil {
		return nil
	}
	host, _ := os.Hostname()
	return &fallbackWatch{cfg: *cfg.Fallback, after: time.Duration(cfg.FallbackMinutes) * time.Minute, host: host, send: notify.Deliver, lastOK: time.Now()}
}

// result is called after every attempt to send a batch.
func (f *fallbackWatch) result(err error, now time.Time) {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.inflight {
		return
	}
	var text string
	switch {
	case err == nil && f.down:
		text = fmt.Sprintf("vigil: %s reaches the vigil server again, after %s. Queued events are being delivered now.", f.host, now.Sub(f.lastOK).Round(time.Minute))
	case err == nil:
		f.lastOK = now
		return
	case !f.down && now.Sub(f.lastOK) >= f.after:
		text = fmt.Sprintf("vigil: %s cannot reach the vigil server since %s (%s). Alerts from this host wait in its queue until the server is back. Last error: %s",
			f.host, f.lastOK.UTC().Format("2006-01-02 15:04 UTC"), now.Sub(f.lastOK).Round(time.Minute), notify.Truncate(err.Error(), 300))
	default:
		return
	}
	f.inflight = true
	recovered := err == nil
	go func() {
		serr := f.send(f.cfg, notify.Message{Severity: "high", Text: text})
		if serr != nil {
			log.Printf("fallback notifier: %v", serr) // Deliver already strips URLs
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		f.inflight = false
		// Only a delivered notice changes the state, so a failed one is
		// tried again with the next batch.
		if serr == nil {
			f.down = !recovered
			if recovered {
				f.lastOK = now
			}
		}
	}()
}
