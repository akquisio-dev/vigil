package agent

import (
	"testing"
)

func eventTypes(a *Agent) map[string][]map[string]any {
	a.bg.Wait()
	out := map[string][]map[string]any{}
	for _, ev := range a.queue {
		out[ev.Type] = append(out[ev.Type], ev.Data)
	}
	a.queue = nil
	return out
}

func TestKernelModules(t *testing.T) {
	a := &Agent{cfg: &Config{MaxQueue: 100, StateDir: t.TempDir()}, state: &State{}, flushNow: make(chan struct{}, 1)}
	ks := loadKernelState(a.cfg.StateDir)
	mods := parseModules([]byte("nf_tables 1 0 - Live 0x0\nzfs 2 0 - Live 0x0 (POE)\n"))
	if mods["zfs"].taint != "POE" || mods["nf_tables"].taint != "" {
		t.Fatalf("parse: %+v", mods)
	}

	// First run: baseline, existing out-of-tree modules are named once.
	a.kernelDiff(ks, mods, []string{"nf_tables", "zfs"}, 1<<12)
	ev := eventTypes(a)
	if len(ev["kernel.baseline"]) != 1 || len(ev["kernel.module_loaded"]) != 0 {
		t.Fatalf("baseline: %v", ev)
	}
	if odd := ev["kernel.baseline"][0]["out_of_tree"].([]string); len(odd) != 1 || odd[0] != "zfs (POE)" {
		t.Fatalf("out of tree at baseline: %v", odd)
	}

	// A new module, a new taint bit, an unloaded module.
	mods = parseModules([]byte("nf_tables 1 0 - Live 0x0\nwireguard 3 0 - Live 0x0\n"))
	a.kernelDiff(ks, mods, []string{"nf_tables", "wireguard"}, 1<<12|1<<13)
	ev = eventTypes(a)
	if len(ev["kernel.module_loaded"]) != 1 || ev["kernel.module_loaded"][0]["name"] != "wireguard" {
		t.Fatalf("new module: %v", ev)
	}
	if len(ev["kernel.module_unloaded"]) != 1 || len(ev["kernel.tainted"]) != 1 || ev["kernel.tainted"][0]["added"] != "E" {
		t.Fatalf("unload or taint: %v", ev)
	}

	// Hidden: live in sysfs, missing from /proc/modules, on two scans.
	sysfs := []string{"nf_tables", "wireguard", "diamorphine"}
	a.kernelDiff(ks, mods, sysfs, 1<<12|1<<13)
	if ev = eventTypes(a); len(ev["kernel.module_hidden"]) != 0 {
		t.Fatal("hidden module reported on the first sighting")
	}
	a.kernelDiff(ks, mods, sysfs, 1<<12|1<<13)
	if ev = eventTypes(a); len(ev["kernel.module_hidden"]) != 1 || ev["kernel.module_hidden"][0]["name"] != "diamorphine" {
		t.Fatalf("hidden module: %v", ev)
	}
	a.kernelDiff(ks, mods, sysfs, 1<<12|1<<13)
	if ev = eventTypes(a); len(ev["kernel.module_hidden"]) != 0 {
		t.Fatal("hidden module reported again")
	}

	// The state survives a restart: nothing is new.
	a.scanKernelWith(ks)
	ks2 := loadKernelState(a.cfg.StateDir)
	if !ks2.Baselined || ks2.Modules["wireguard"] != "" {
		t.Fatalf("state not saved: %+v", ks2)
	}
}

func (a *Agent) scanKernelWith(ks *KernelState) {
	a.kernel = ks
	a.saveKernel()
}

func TestMemfdAndPreloadSignals(t *testing.T) {
	has := func(e ExecInfo, s string) bool {
		for _, x := range e.signals() {
			if x == s {
				return true
			}
		}
		return false
	}
	mem := ExecInfo{Exe: "/memfd:payload", Deleted: true, Comm: "payload"}
	if !has(mem, "memfd_exe") || has(mem, "deleted_exe") {
		t.Fatalf("memfd: %v", mem.signals())
	}
	runc := ExecInfo{Exe: "/memfd:runc_cloned:/proc/self/exe", Deleted: true, Comm: "runc:[2:INIT]"}
	if len(runc.signals()) != 0 {
		t.Fatalf("runc re-exec must stay quiet: %v", runc.signals())
	}
	fake := ExecInfo{Exe: "/memfd:runc_cloned:/proc/self/exe", Deleted: true, Comm: "kworker"}
	if !has(fake, "memfd_exe") {
		t.Fatal("runc memfd name without runc comm must be reported")
	}
	pre := ExecInfo{Exe: "/usr/bin/ssh", Comm: "ssh", Preload: "/dev/shm/.x.so"}
	if !has(pre, "ld_preload") {
		t.Fatal("LD_PRELOAD not reported")
	}

	a := &Agent{cfg: &Config{MaxQueue: 100}, flushNow: make(chan struct{}, 1)}
	a.reportExec(&pre)
	a.reportExec(&pre)
	if n := len(eventTypes(a)["process.exec"]); n != 1 {
		t.Fatalf("same program and library reported %d times", n)
	}
}
