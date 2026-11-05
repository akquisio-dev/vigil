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
		uid, comm, exe, ident, msg string
		use, spoofed               bool
	}{
		{"0", "sshd", "/usr/sbin/sshd", "sshd", "", true, false},
		// a user's sudo and sshd's process for a user's session
		{"1001", "sudo", "/usr/bin/sudo", "sudo", "", false, false},
		{"1001", "sshd", "/usr/sbin/sshd", "sshd", "", false, false},
		{"1001", "sshd-session", "/usr/lib/openssh/sshd-session", "sshd-session", "", false, false},
		// logger -t sshd, or a copy of sshd elsewhere
		{"1001", "logger", "/usr/bin/logger", "sshd", "", false, true},
		{"1001", "sshd", "/tmp/sshd", "sshd", "", false, true},
		{"0", "logger", "/usr/bin/logger", "sudo", "", false, true},
		// the session process gone before journald read _EXE (Ubuntu 24.04, OpenSSH 9.6)
		{"1001", "sshd", "", "sshd", "Disconnected from user ubuntu 192.0.2.1 port 38660", false, false},
		{"1001", "sshd", "", "sshd", "Received disconnect from 192.0.2.1 port 38660:11: disconnected by user", false, false},
		// but nothing else without _EXE, and never a login line
		{"1001", "sshd", "", "sshd", "Accepted publickey for root from 192.0.2.1 port 22 ssh2", false, true},
		{"1001", "logger", "", "sshd", "Disconnected from user ubuntu 192.0.2.1 port 1", false, true},
		// Fedora 44, OpenSSH 10: sshd-session as the user, logging as
		// sshd-session or sshd, with and without _EXE; sshd-auth as the
		// sshd account before authentication.
		{"1000", "sshd-session", "/usr/libexec/openssh/sshd-session", "sshd-session", "Received disconnect from 10.0.2.2 port 51234:11: disconnected by user", false, false},
		{"1000", "sshd-session", "/usr/libexec/openssh/sshd-session", "sshd", "anything", false, false},
		{"1000", "sshd-session", "", "sshd-session", "Received disconnect from 10.0.2.2 port 51234:11: disconnected by user", false, false},
		{"1000", "sshd-session", "", "sshd-session", "Disconnected from user joey 10.0.2.2 port 51234", false, false},
		{"1000", "sshd-session", "", "sshd", "Disconnected from user joey 10.0.2.2 port 51234", false, false},
		// _COMM gone as well: still only the two closing lines
		{"1000", "", "", "sshd-session", "Received disconnect from 10.0.2.2 port 51234:11: disconnected by user", false, false},
		{"1000", "", "", "sshd-session", "Accepted publickey for root from 192.0.2.1 port 22 ssh2", false, true},
		{"74", "sshd-auth", "/usr/libexec/openssh/sshd-auth", "sshd-auth", "", false, false},
		{"0", "sshd-session", "/usr/libexec/openssh/sshd-session", "sshd-session", "Accepted publickey for joey from 10.0.2.2 port 51234 ssh2", true, false},
		// still no login line without _EXE, and no copy elsewhere or other writer
		{"1000", "sshd-session", "", "sshd-session", "Accepted publickey for root from 192.0.2.1 port 22 ssh2", false, true},
		{"1000", "sshd-session", "/tmp/sshd-session", "sshd-session", "Disconnected from user joey 10.0.2.2 port 51234", false, true},
		{"1000", "logger", "", "sshd-session", "Disconnected from user joey 10.0.2.2 port 51234", false, true},
		{"1000", "sshd-auth", "", "sshd", "Disconnected from user joey 10.0.2.2 port 51234", false, true},
		// the self test: root, written by the agent under sshd. Reported on
		// purpose; the server books it as the test's journal step.
		{"0", "vigil-agent", "/usr/bin/vigil-agent", "sshd", "vigil-selftest-abc (vigil self test, not a real login)", false, true},
	} {
		use, spoofed := journalEntry(c.uid, c.comm, c.exe, c.ident, c.msg)
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
