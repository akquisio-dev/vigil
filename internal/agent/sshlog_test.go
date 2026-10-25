package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSpoofedLog(t *testing.T) {
	for _, c := range []struct {
		uid, comm string
		want      bool
	}{
		{"0", "sshd", false},
		{"0", "sshd-session", false},
		{"0", "", false}, // sshd gone before journald read its name
		{"0", "logger", true},
		{"0", "vigil-agent", true}, // the self test's trace
		{"1000", "sshd", true},
		{"1000", "", true},
		{"", "", true},
	} {
		if got := spoofedLog(c.uid, c.comm); got != c.want {
			t.Errorf("uid %q comm %q: %v, want %v", c.uid, c.comm, got, c.want)
		}
	}
}

func TestJournalEntry(t *testing.T) {
	for _, c := range []struct {
		uid, comm, exe, ident string
		use, spoofed          bool
	}{
		{"0", "sshd", "/usr/sbin/sshd", "sshd", true, false},
		// a user's sudo and sshd's process for a user's session
		{"1001", "sudo", "/usr/bin/sudo", "sudo", false, false},
		{"1001", "sshd", "/usr/sbin/sshd", "sshd", false, false},
		{"1001", "sshd-session", "/usr/lib/openssh/sshd-session", "sshd-session", false, false},
		// logger -t sshd, or a copy of sshd elsewhere
		{"1001", "logger", "/usr/bin/logger", "sshd", false, true},
		{"1001", "sshd", "/tmp/sshd", "sshd", false, true},
		{"0", "logger", "/usr/bin/logger", "sudo", false, true},
	} {
		use, spoofed := journalEntry(c.uid, c.comm, c.exe, c.ident)
		if use != c.use || spoofed != c.spoofed {
			t.Errorf("%+v: use %v spoofed %v", c, use, spoofed)
		}
	}
}

func TestServicePortsOutliveARestart(t *testing.T) {
	seen := map[int]time.Time{}
	now := time.Now()
	servicePorts(seen, map[int]bool{22: true}, now)
	// sshd restarts: no listener on 22 for a moment, its sessions stay
	in := servicePorts(seen, map[int]bool{}, now.Add(30*time.Second))
	if !in(22) {
		t.Fatal("connections to port 22 counted as outgoing while sshd restarted")
	}
	if in(40236) {
		t.Fatal("a port that never listened is no service port")
	}
	if in := servicePorts(seen, map[int]bool{}, now.Add(listenGrace+time.Minute)); in(22) {
		t.Fatal("a port gone for good stays a service port")
	}
}

func TestKeyFilesOutsideHome(t *testing.T) {
	p := filepath.Join(t.TempDir(), "passwd")
	os.WriteFile(p, []byte(`root:x:0:0:root:/root:/bin/bash
ubuntu:x:1001:1001::/home/ubuntu:/bin/bash
offsite:x:997:997::/srv/offsite:/bin/sh
postgres:x:114:120::/var/lib/postgresql:/bin/bash
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
odd:x:5:5::relative/home:/bin/sh
glob:x:6:6::/srv/*:/bin/sh
again:x:998:998::/srv/offsite/:/bin/sh
`), 0o600)
	got := strings.Join(keyFilesOutsideHome(p), " ")
	for _, want := range []string{"/srv/offsite/.ssh/authorized_keys", "/srv/offsite/.ssh/authorized_keys2", "/var/lib/postgresql/.ssh/authorized_keys", "/bin/.ssh/authorized_keys"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s in %s", want, got)
		}
	}
	for _, not := range []string{"/root/", "/home/", "/nonexistent", "relative", "*"} {
		if strings.Contains(got, not) {
			t.Errorf("%s must not be listed: %s", not, got)
		}
	}
	if strings.Count(got, "/srv/offsite/.ssh/authorized_keys ") != 1 {
		t.Errorf("a home shared by two accounts listed twice: %s", got)
	}
	if category("/srv/offsite/.ssh/authorized_keys") != "ssh_keys" {
		t.Fatal("not read as a key file")
	}
}
