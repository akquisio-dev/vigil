package agent

import "testing"

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
