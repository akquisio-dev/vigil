package server

import (
	"testing"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

func evalOne(s *Server, typ string, d map[string]any) []finding {
	a := &AgentRec{ID: "a1", Name: "host", Baseline: map[string]bool{}, StartedOnce: true}
	return s.evaluate(a, &Record{Event: proto.Event{Type: typ, TS: time.Now(), Data: d}})
}

func TestSuidRules(t *testing.T) {
	s := &Server{state: &State{Agents: map[string]*AgentRec{}, KnownLogins: map[string]time.Time{}}}
	cases := []struct {
		d    map[string]any
		rule string
	}{
		{map[string]any{"path": "/usr/bin/find", "bits": "setuid", "uid": 0, "pkgdb": true, "package": "findutils", "changed_after_install": true, "where": "system"}, "file.suid"},
		{map[string]any{"path": "/usr/bin/sudo", "bits": "setuid", "uid": 0, "pkgdb": true, "package": "sudo", "where": "system"}, "file.suid_packaged"},
		{map[string]any{"path": "/tmp/.x/bash", "bits": "setuid", "uid": 0, "pkgdb": true, "package": "", "where": "tmp"}, "file.suid_tmp"},
		{map[string]any{"path": "/tmp/mine", "bits": "setuid", "uid": 1000, "pkgdb": true, "package": "", "where": "tmp"}, "file.suid"},
		{map[string]any{"path": "/opt/x/python3", "bits": "", "caps": "cap_setuid+ep", "dangerous_caps": true, "uid": 0, "pkgdb": true, "package": "", "where": "system"}, "file.suid"},
		{map[string]any{"path": "/usr/local/bin/srv", "bits": "", "caps": "cap_net_bind_service+ep", "dangerous_caps": false, "uid": 0, "where": "system"}, ""},
	}
	for _, c := range cases {
		fs := evalOne(s, "file.suid", c.d)
		got := ""
		if len(fs) == 1 {
			got = fs[0].Rule
		}
		if got != c.rule {
			t.Errorf("%s: got %q want %q", c.d["path"], got, c.rule)
		}
	}
}

func TestKernelAndProcessRules(t *testing.T) {
	s := &Server{state: &State{Agents: map[string]*AgentRec{}, KnownLogins: map[string]time.Time{}}}
	if fs := evalOne(s, "kernel.module_loaded", map[string]any{"name": "nf_tables", "taint": ""}); len(fs) != 1 || fs[0].Rule != "kernel.module" {
		t.Fatalf("in-tree: %+v", fs)
	}
	if fs := evalOne(s, "kernel.module_loaded", map[string]any{"name": "rk", "taint": "OE"}); len(fs) != 1 || fs[0].Rule != "kernel.module_unsigned" {
		t.Fatalf("out of tree: %+v", fs)
	}
	if fs := evalOne(s, "kernel.baseline", map[string]any{"out_of_tree": []any{"zfs (POE)"}}); len(fs) != 1 || fs[0].Params["taint"] != "POE" {
		t.Fatalf("baseline: %+v", fs)
	}
	fs := evalOne(s, "process.exec", map[string]any{"exe": "/usr/bin/ssh", "ld_preload": "/dev/shm/x.so", "signals": []any{"ld_preload"}})
	if len(fs) != 1 || fs[0].Rule != "process.preload" || fs[0].Key != "process.preload|a1|/usr/bin/ssh|/dev/shm/x.so" {
		t.Fatalf("preload: %+v", fs)
	}
	// Where a program ran is part of the alert's detail when the agent
	// sends it; the key stays the same.
	fs = evalOne(s, "process.exec", map[string]any{"exe": "/tmp/.tmpWqNpWy", "uid": 0.0, "signals": []any{"tmp_exe"},
		"unit": "bootc-fetch-apply-updates.service", "cgroup": "/system.slice/bootc-fetch-apply-updates.service", "mnt_ns_private": true})
	if len(fs) != 1 || fs[0].Params["unit"] != "bootc-fetch-apply-updates.service" || fs[0].Params["mnt_ns_private"] != "true" ||
		fs[0].Key != "process.tmp_exec|a1|/tmp/.tmpWqNpWy|" {
		t.Fatalf("unit: %+v", fs)
	}
	fs = evalOne(s, "process.exec", map[string]any{"exe": "/tmp/x", "uid": 0.0, "signals": []any{"tmp_exe"}})
	if _, ok := fs[0].Params["unit"]; ok {
		t.Fatalf("older agent: %+v", fs[0].Params)
	}
	fs = evalOne(s, "log.spoofed", map[string]any{"identifier": "sshd", "comm": "logger", "exe": "/usr/bin/logger", "uid": "1000"})
	if len(fs) != 1 || fs[0].Params["exe"] != "/usr/bin/logger" || fs[0].Key != "log.spoofed|a1|logger|1000" {
		t.Fatalf("spoofed: %+v", fs)
	}
}
