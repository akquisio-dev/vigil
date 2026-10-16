//go:build linux

package agent

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestProcessConnectorLive listens on the real host for a while, starts a
// harmless copy of `true` from /tmp and checks that it is reported:
//
//	sudo VIGIL_LIVE_PROC=30 go test ./internal/agent -run TestProcessConnectorLive -v
func TestProcessConnectorLive(t *testing.T) {
	secs := os.Getenv("VIGIL_LIVE_PROC")
	if secs == "" {
		t.Skip("set VIGIL_LIVE_PROC=<seconds> and run as root")
	}
	d, _ := time.ParseDuration(secs + "s")
	a := &Agent{cfg: &Config{MaxQueue: 100000}, flushNow: make(chan struct{}, 1)}
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	go a.runProcesses(ctx)
	time.Sleep(500 * time.Millisecond)
	bin := "/tmp/vigil-proc-test"
	data, _ := os.ReadFile("/bin/true")
	os.WriteFile(bin, data, 0o755)
	defer os.Remove(bin)
	exec.Command(bin).Run()
	<-ctx.Done()
	found := false
	for _, ev := range a.queue {
		t.Logf("%s %v", ev.Type, ev.Data)
		if ev.Type == "process.exec" && ev.Data["exe"] == bin {
			found = true
		}
	}
	if !found {
		t.Fatal("the program started from /tmp was not reported")
	}
}

// TestOutboundLive prints what the first outbound scan reports on this host:
//
//	sudo VIGIL_LIVE_NET=1 go test ./internal/agent -run TestOutboundLive -v
func TestOutboundLive(t *testing.T) {
	if os.Getenv("VIGIL_LIVE_NET") == "" {
		t.Skip("set VIGIL_LIVE_NET=1 and run as root")
	}
	a := &Agent{cfg: &Config{MaxQueue: 100000}, flushNow: make(chan struct{}, 1)}
	start := time.Now()
	a.scanOutbound()
	first := len(a.queue)
	a.scanOutbound()
	t.Logf("first scan %d events in %v, second scan %d more", first, time.Since(start), len(a.queue)-first)
	for _, ev := range a.queue {
		t.Logf("%v", ev.Data)
	}
}

// TestBlockIPLive blocks a documentation address (192.0.2.1) for a minute in
// the vigil nftables table, checks it is listed, and removes the table again:
//
//	sudo VIGIL_LIVE_NFT=1 go test ./internal/agent -run TestBlockIPLive -v
func TestBlockIPLive(t *testing.T) {
	if os.Getenv("VIGIL_LIVE_NFT") == "" {
		t.Skip("set VIGIL_LIVE_NFT=1 and run as root")
	}
	if runNft("", "list", "table", "inet", "vigil") == nil {
		t.Skip("table inet vigil exists already; not touching it")
	}
	defer runNft("", "delete", "table", "inet", "vigil")
	a := &Agent{cfg: &Config{Response: &ResponseConfig{Enabled: true}}}
	msg, err := a.blockIP("192.0.2.1", 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(msg)
	if _, err := a.blockIP("192.0.2.2", 1); err != nil {
		t.Fatal("a second block must reuse the table:", err)
	}
	out, _ := exec.Command("nft", "list", "set", "inet", "vigil", "blocked4").Output()
	t.Logf("%s", out)
	if !strings.Contains(string(out), "192.0.2.1") || !strings.Contains(string(out), "192.0.2.2") {
		t.Fatal("addresses not in the set")
	}
}
