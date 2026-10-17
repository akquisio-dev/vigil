package server

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

func TestReleaseKey(t *testing.T) {
	cases := map[[3]string]string{
		{"ubuntu", "24.04", "noble"}: "ubuntu:noble", {"ubuntu", "22.04", ""}: "ubuntu:jammy", {"debian", "12", "bookworm"}: "debian:bookworm",
		{"debian", "12.7", ""}: "debian:bookworm", {"fedora", "40", "x"}: "", {"ubuntu", "99.04", ""}: "", {"ubuntu", "24.04", "../x"}: "",
	}
	for in, want := range cases {
		if got := releaseKey(in[0], in[1], in[2]); got != want {
			t.Errorf("%v: %q want %q", in, got, want)
		}
	}
}

const ovalSample = `<?xml version="1.0" encoding="UTF-8"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"><definitions>
<definition id="oval:com.ubuntu.noble:def:100" class="inventory"><metadata><title>Check that Ubuntu 24.04 LTS (noble) is installed.</title></metadata>
 <criteria><criterion test_ref="oval:com.ubuntu.noble:tst:100" comment="The host is part of the unix family." /></criteria></definition>
<definition id="oval:com.ubuntu.noble:def:202463870000000" class="vulnerability" version="1"><metadata>
 <title>CVE-2024-6387 on Ubuntu 24.04 LTS (noble) - high</title>
 <advisory from="security@ubuntu.com"><severity>High</severity>
  <cve href="https://ubuntu.com/security/CVE-2024-6387" priority="high" cvss_score="8.1">CVE-2024-6387</cve></advisory></metadata>
 <criteria><extend_definition definition_ref="oval:com.ubuntu.noble:def:100" comment="Ubuntu 24.04 LTS (noble) is installed" />
  <criterion test_ref="t1" comment="openssh source package in noble, is affected and has been fixed (note: '1:9.6p1-3ubuntu13.3')." /></criteria></definition>
<definition id="d2" class="vulnerability"><metadata><title>CVE-2026-2</title>
 <advisory><cve priority="low">CVE-2026-2</cve></advisory></metadata>
 <criteria><criteria operator="OR">
  <criterion test_ref="t2" comment="openssh source package in noble, might be affected and may need fixing." />
  <criterion test_ref="t3" comment="vim source package in esm-apps/noble, is affected and has been fixed (note: '2:9.1.0016-1ubuntu7.9')." />
 </criteria></criteria></definition>
<definition id="d3" class="vulnerability"><metadata><title>CVE-2026-3</title>
 <advisory><cve priority="" cvss_score="9.8">CVE-2026-3</cve></advisory></metadata>
 <criteria><criterion test_ref="t4" comment="vim source package in noble, is affected and has been fixed (note: '2:9.1.0016-1ubuntu7.9')." /></criteria></definition>
<definition id="d5" class="vulnerability"><metadata><title>CVE-2026-5</title>
 <advisory><cve priority="high">CVE-2026-5</cve></advisory></metadata>
 <criteria><criteria operator="OR"><criteria operator="AND">
  <criterion test_ref="k1" comment="Is kernel 'linux' running?" />
  <criterion test_ref="k2" comment="'linux' kernel in noble was vulnerable but has been fixed (note: '6.8.0-150.150')." />
 </criteria></criteria></criteria></definition>
<definition id="d4" class="vulnerability"><metadata><title>CVE-2026-4</title>
 <advisory><cve priority="medium">CVE-2026-4</cve></advisory></metadata>
 <criteria><criterion test_ref="t5" comment="sudo source package in noble, is affected and has been fixed (note: '1.9.15p5-3ubuntu5.24.04.1')." /></criteria></definition>
</definitions></oval_definitions>`

const debianSample = `{"zlib":{"CVE-2026-10":{"releases":{
   "bookworm":{"status":"resolved","fixed_version":"1:1.2.13.dfsg-1+deb12u1","urgency":"high"},
   "trixie":{"status":"resolved","fixed_version":"0","urgency":"not yet assigned"}}},
  "TEMP-0000000-1":{"releases":{"bookworm":{"status":"open","urgency":"low"}}}},
 "curl":{"CVE-2026-11":{"releases":{"bookworm":{"status":"open","urgency":"unimportant"}}},
  "CVE-2026-12":{"releases":{"bookworm":{"status":"undetermined","urgency":"not yet assigned"}}}}}`

func TestParseFeeds(t *testing.T) {
	vi, err := parseOVAL(strings.NewReader(ovalSample), "ubuntu:noble")
	if err != nil {
		t.Fatal(err)
	}
	vi.build()
	if k := vi.Recs["CVE-2026-5"]; k == nil || k.Pkgs[0].Name != "linux" || k.Pkgs[0].Fixed != "6.8.0-150.150" || len(k.Pkgs) != 1 {
		t.Fatalf("kernel: %+v", vi.Recs["CVE-2026-5"])
	}
	if len(vi.Recs) != 5 || len(vi.byPkg["openssh"]) != 2 || len(vi.byPkg["vim"]) != 2 {
		t.Fatalf("records: %+v", vi.Recs)
	}
	ssh := vi.Recs["CVE-2024-6387"].Pkgs[0]
	if ssh.Fixed != "1:9.6p1-3ubuntu13.3" || ssh.Severity != "high" || ssh.Pro {
		t.Fatalf("openssh: %+v", ssh)
	}
	if p := vi.Recs["CVE-2026-2"].Pkgs; p[0].Fixed != "" || !p[1].Pro || p[1].Severity != "low" {
		t.Fatalf("unfixed and Pro: %+v", p)
	}
	if p := vi.Recs["CVE-2026-3"].Pkgs[0]; p.Severity != "critical" {
		t.Fatalf("CVSS fallback: %+v", p)
	}

	all, err := parseDebian(strings.NewReader(debianSample), map[string]bool{"bookworm": true})
	if err != nil {
		t.Fatal(err)
	}
	b := all["bookworm"]
	if len(b.Recs) != 3 || b.Recs["CVE-2026-10"].Pkgs[0].Fixed != "1:1.2.13.dfsg-1+deb12u1" || b.Recs["CVE-2026-10"].Pkgs[0].Severity != "high" ||
		b.Recs["CVE-2026-11"].Pkgs[0].Severity != "negligible" || b.Recs["CVE-2026-12"].Pkgs[0].Severity != "unknown" {
		t.Fatalf("debian: %+v", b.Recs)
	}
}

func TestVulnMatching(t *testing.T) {
	s := &Server{cfg: &Config{VulnLookup: true, DataDir: t.TempDir()}, state: &State{Agents: map[string]*AgentRec{}, KnownLogins: map[string]time.Time{}}}
	vi, _ := parseOVAL(strings.NewReader(ovalSample), "ubuntu:noble")
	vi.build()
	s.vdb.idx = map[string]*vulnIndex{vi.Release: vi}
	s.vdb.kev = map[string]bool{"CVE-2026-4": true}

	a := &AgentRec{ID: "a1", Name: "host", Baseline: map[string]bool{}, StartedOnce: true}
	s.state.Agents[a.ID] = a
	send := func(pkgs [][2]string) []*Alert {
		list := []any{}
		for _, p := range pkgs {
			list = append(list, []any{p[0], p[1]})
		}
		rec := &Record{Event: proto.Event{Type: "system.packages", TS: time.Now(), Data: map[string]any{"os_id": "ubuntu", "os_version": "24.04", "os_codename": "noble", "packages": list}}}
		return s.raise(s.evaluate(a, rec), a.ID, 1)
	}
	fresh := send([][2]string{{"openssh", "1:9.6p1-3ubuntu13"}, {"vim", "2:9.1.0016-1ubuntu7"}, {"sudo", "1.9.15p5-3ubuntu5"}, {"bash", "5.2"}})
	got := map[string][]*Alert{}
	for _, al := range fresh {
		got[al.Rule] = append(got[al.Rule], al)
	}
	if len(fresh) != 3 || len(got["vuln.severe"]) != 2 || len(got["vuln.exploited"]) != 1 {
		t.Fatalf("alerts: %+v", fresh)
	}
	titles := got["vuln.severe"][0].Title + " / " + got["vuln.severe"][1].Title
	if !strings.Contains(titles, "openssh 1:9.6p1-3ubuntu13: 1 high or critical vulnerabilities (CVE-2024-6387), fixed in 1:9.6p1-3ubuntu13.3") ||
		!strings.Contains(titles, "vim 2:9.1.0016-1ubuntu7: 1 high or critical vulnerabilities (CVE-2026-3), fixed in 2:9.1.0016-1ubuntu7.9") ||
		got["vuln.exploited"][0].Title != "sudo 1.9.15p5-3ubuntu5: 1 vulnerabilities exploited in the wild (CVE-2026-4), fixed in 1.9.15p5-3ubuntu5.24.04.1" {
		t.Fatalf("titles: %s / %s", titles, got["vuln.exploited"][0].Title)
	}
	v := a.Vulns
	if v.Fixable["high"] != 1 || v.Fixable["critical"] != 1 || v.Fixable["medium"] != 1 || v.Unfixed["low"] != 2 || len(v.Exploited) != 1 || v.Top[0].CVE != "CVE-2026-4" {
		t.Fatalf("summary: %+v", v)
	}

	// Same list again: quiet. Updated packages: the alerts close.
	if fresh := send([][2]string{{"openssh", "1:9.6p1-3ubuntu13"}, {"vim", "2:9.1.0016-1ubuntu7"}, {"sudo", "1.9.15p5-3ubuntu5"}}); len(fresh) != 0 {
		t.Fatalf("repeated: %+v", fresh)
	}
	send([][2]string{{"openssh", "1:9.6p1-3ubuntu13.3"}, {"sudo", "1.9.15p5-3ubuntu5.24.04.1"}, {"vim", "2:9.1.0016-1ubuntu7.9"}})
	for _, al := range s.state.Alerts {
		if al.Status != "resolved" {
			t.Fatalf("still open after the update: %+v", al)
		}
	}
	if a.Vulns.Fixable["high"] != 0 || a.Vulns.Unfixed["low"] != 1 {
		t.Fatalf("after update: %+v", a.Vulns)
	}

	// Unsupported systems say so instead of claiming to be clean.
	b := &AgentRec{ID: "b1", Name: "alma"}
	s.packagesReceived(b, map[string]any{"os_id": "almalinux", "os_version": "9.4", "packages": []any{}})
	if b.Vulns == nil || b.Vulns.Error == "" {
		t.Fatalf("unsupported: %+v", b.Vulns)
	}
}

func TestVulnIndexKeepsOnlyInstalledPackages(t *testing.T) {
	s := &Server{cfg: &Config{VulnLookup: true, DataDir: t.TempDir()}, state: &State{Agents: map[string]*AgentRec{}, KnownLogins: map[string]time.Time{}}}
	os.MkdirAll(s.vulnDir(), 0o700)
	full, _ := parseOVAL(strings.NewReader(ovalSample), "ubuntu:noble")
	full.build()
	if err := s.saveIndex(full); err != nil {
		t.Fatal(err)
	}
	a := &AgentRec{ID: "a1", Name: "host"}
	s.state.Agents["a1"] = a
	s.pkgs = map[string]*agentPackages{"a1": {Eco: "ubuntu:noble", List: [][2]string{{"openssh", "1:9.6p1-3ubuntu13"}}}}
	s.setIndex(full)
	vi := s.vdb.idx["ubuntu:noble"]
	if len(vi.byPkg["vim"]) != 0 || len(vi.byPkg["openssh"]) != 2 || vi.kept == nil {
		t.Fatalf("pruned: %v", vi.byPkg)
	}
	if err := s.saveIndex(vi); err == nil {
		t.Fatal("a reduced index must not overwrite the complete file")
	}
	// A host installs vim: its data is loaded from disk.
	s.mu.Lock()
	s.packagesReceived(a, map[string]any{"os_id": "ubuntu", "os_version": "24.04", "os_codename": "noble",
		"packages": []any{[]any{"openssh", "1:9.6p1-3ubuntu13"}, []any{"vim", "2:9.1.0016-1ubuntu7"}}})
	s.mu.Unlock()
	if vi := s.vdb.idx["ubuntu:noble"]; len(vi.byPkg["vim"]) != 2 || a.Vulns.Fixable["critical"] != 1 {
		t.Fatalf("after new package: %v %+v", vi.byPkg["vim"], a.Vulns)
	}
}
