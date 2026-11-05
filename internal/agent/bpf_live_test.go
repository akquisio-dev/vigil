package agent

import (
	"os"
	"testing"
)

// TestBPFThisHost lists the programs on the real system (VIGIL_LIVE=1).
func TestBPFThisHost(t *testing.T) {
	if os.Getenv("VIGIL_LIVE") == "" {
		t.Skip("set VIGIL_LIVE=1")
	}
	progs, err := listBPF()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range progs {
		t.Logf("%d %s %q %s uid=%d hooking=%v", p.ID, p.Type, p.Name, p.Tag, p.UID, bpfHooking[p.Type])
	}
}

func TestBPFDiff(t *testing.T) {
	a := &Agent{cfg: &Config{MaxQueue: 100}, flushNow: make(chan struct{}, 1)}
	bs := &BPFState{Known: map[string]bool{}}
	boot := []bpfProg{
		{ID: 2, Type: "tracing", Name: "hid_tail_call", Tag: "aa", LoadTime: 2e9},
		{ID: 3, Type: "cgroup_device", Name: "sd_devices", Tag: "bb", LoadTime: 5e9},
		{ID: 4, Type: "kprobe", Name: "falco", Tag: "cc", LoadTime: 9e11},
	}
	a.diffBPF(bs, boot)
	ev := eventTypes(a)["kernel.bpf_loaded"]
	if len(ev) != 1 || ev[0]["name"] != "falco" || ev[0]["baseline"] != true {
		t.Fatalf("baseline: %v", ev)
	}
	later := append(boot, bpfProg{ID: 90, Type: "tracing", Name: "hid_tail_call", Tag: "dd", LoadTime: 8e12},
		bpfProg{ID: 91, Type: "kprobe", Name: "falco", Tag: "cc", LoadTime: 9e12})
	a.diffBPF(bs, later)
	ev = eventTypes(a)["kernel.bpf_loaded"]
	if len(ev) != 1 || ev[0]["id"] != uint32(90) {
		t.Fatalf("a kernel name loaded late must be reported, a reload must not: %v", ev)
	}
}

// systemd's BPF LSM program for RestrictFileSystems=, as seen on a Nyra VM
// (present at agent start, uid 0), is not reported; a reload with the same
// tag stays quiet, the same name with another tag, from another uid or
// loaded late is reported.
func TestBPFSystemdLSM(t *testing.T) {
	a := &Agent{cfg: &Config{MaxQueue: 100}, flushNow: make(chan struct{}, 1)}
	bs := &BPFState{Known: map[string]bool{}}
	boot := []bpfProg{{ID: 7, Type: "lsm", Name: "restrict_filesy", Tag: "31efb7c56239148b", UID: 0, LoadTime: 3e9}}
	a.diffBPF(bs, boot)
	if ev := eventTypes(a)["kernel.bpf_loaded"]; len(ev) != 0 {
		t.Fatalf("systemd's program at boot reported: %v", ev)
	}
	later := []bpfProg{
		{ID: 70, Type: "lsm", Name: "restrict_filesy", Tag: "31efb7c56239148b", UID: 0, LoadTime: 9e12}, // soft reboot
		{ID: 71, Type: "lsm", Name: "restrict_filesy", Tag: "00000000deadbeef", UID: 0, LoadTime: 9e12},
		{ID: 72, Type: "lsm", Name: "restrict_filesy", Tag: "1111111111111111", UID: 1000, LoadTime: 4e9},
		{ID: 73, Type: "kprobe", Name: "restrict_filesy", Tag: "31efb7c56239148b", UID: 0, LoadTime: 4e9},
	}
	a.diffBPF(bs, later)
	ev := eventTypes(a)["kernel.bpf_loaded"]
	if len(ev) != 3 || ev[0]["id"] != uint32(71) || ev[1]["id"] != uint32(72) || ev[2]["id"] != uint32(73) {
		t.Fatalf("later loads: %v", ev)
	}
}
