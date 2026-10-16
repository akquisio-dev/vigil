package agent

import (
	"context"
	"os"
	"runtime"
	"testing"
	"time"
)

// TestSuidThisHost walks the real system once (VIGIL_LIVE=1) and reports
// time and peak heap.
func TestSuidThisHost(t *testing.T) {
	if os.Getenv("VIGIL_LIVE") == "" {
		t.Skip("set VIGIL_LIVE=1")
	}
	roots, all := suidRoots()
	stop := make(chan struct{})
	var peak uint64
	go func() {
		var m runtime.MemStats
		for {
			select {
			case <-stop:
				return
			case <-time.After(50 * time.Millisecond):
				runtime.ReadMemStats(&m)
				if m.HeapInuse > peak {
					peak = m.HeapInuse
				}
			}
		}
	}()
	start := time.Now()
	found, err := walkSuid(context.Background(), roots, all)
	close(stop)
	t.Logf("roots %v: %d files, err %v, %s, peak heap %d MB", roots, len(found), err, time.Since(start), peak>>20)
	var paths []string
	for p := range found {
		paths = append(paths, p)
	}
	dpkg := lookupDpkg(paths)
	for p, f := range found {
		d := suidEvent(p, f, dpkg)
		if d["package"] == "" || d["changed_after_install"] == true || d["where"] != "system" {
			t.Logf("odd: %v", d)
		}
	}
}
