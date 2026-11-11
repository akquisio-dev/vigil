package agent

import (
	"net"
	"testing"
	"time"
)

func countPortEvents(a *Agent) map[string]int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := map[string]int{}
	for _, ev := range a.queue {
		n[ev.Type]++
	}
	a.queue = nil
	return n
}

// Short-lived sockets are reported one by one at once, the whole list only
// on start and then at most every portSnapshotEvery.
func TestPortSnapshotIsSpacedOut(t *testing.T) {
	off := false
	a := &Agent{cfg: &Config{MaxQueue: 100000, Docker: &off}, state: &State{Initialized: true}}
	a.scanPorts()
	if n := countPortEvents(a); n["port.snapshot"] != 1 {
		t.Fatalf("first scan: %v", n)
	}
	for i := 0; i < 5; i++ {
		c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		a.scanPorts()
		c.Close()
		a.scanPorts()
	}
	n := countPortEvents(a)
	if n["port.snapshot"] != 0 || n["port.opened"] < 5 || n["port.closed"] < 5 {
		t.Fatalf("five short sockets: %v", n)
	}
	// Once the spacing has passed, the next scan sends the list even if
	// nothing changed since the last change.
	a.portsSnapAt = time.Now().Add(-portSnapshotEvery - time.Second)
	a.scanPorts()
	if n := countPortEvents(a); n["port.snapshot"] != 1 {
		t.Fatalf("after the spacing: %v", n)
	}
	a.scanPorts()
	if n := countPortEvents(a); n["port.snapshot"] != 0 {
		t.Fatalf("nothing changed, sent again: %v", n)
	}
}
