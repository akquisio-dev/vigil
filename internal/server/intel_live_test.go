package server

import (
	"net/http"
	"os"
	"testing"
	"time"
)

// TestIntelListsLive downloads every list once and checks it parses:
//
//	VIGIL_LIVE_INTEL=1 go test ./internal/server -run TestIntelListsLive -v
func TestIntelListsLive(t *testing.T) {
	if os.Getenv("VIGIL_LIVE_INTEL") == "" {
		t.Skip("set VIGIL_LIVE_INTEL=1")
	}
	c := &http.Client{Timeout: 30 * time.Second}
	for _, l := range intelLists {
		b, err := download(c, l.URL)
		if err != nil {
			t.Errorf("%s: %v", l.Name, err)
			continue
		}
		t.Logf("%s: %d bytes, %d entries", l.Name, len(b), len(l.parse(b)))
		if len(l.parse(b)) == 0 {
			t.Errorf("%s: no entries", l.Name)
		}
	}
}
