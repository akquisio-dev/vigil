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
