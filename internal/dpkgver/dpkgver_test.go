package dpkgver

import "testing"

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "1.1", -1},
		{"1.10", "1.9", 1},
		{"1.0~rc1", "1.0", -1},
		{"1.0~rc1", "1.0~rc2", -1},
		{"1.0~~", "1.0~", -1},
		{"1.0", "1.0+b1", -1},
		{"1.0a", "1.0", 1},
		{"1:1.0", "2.0", 1},
		{"0:1.0", "1.0", 0},
		{"1.0-1", "1.0-1ubuntu1", -1},
		{"1.0-1ubuntu1", "1.0-1ubuntu1.1", -1},
		{"3.0.13-0ubuntu3.4", "3.0.13-0ubuntu3.5", -1},
		{"1:9.6p1-3ubuntu13.3", "1:9.6p1-3ubuntu13.14", -1},
		{"5.4.5-0.3", "5.6.1+really5.4.5-1", -1},
		{"2.39-0ubuntu8", "2.39-0ubuntu8.3", -1},
		{"1.2.3-1~deb12u1", "1.2.3-1", -1},
		{"6.8.0-147.147", "6.8.0-60.63", 1},
		{"1.0.0-0ubuntu1", "1.3.0-1ubuntu0.1+esm3", -1},
		{"1.0-a", "1.0-A", 1},
		{"1.0-+", "1.0-a", 1},
	}
	for _, c := range cases {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
		if got := Compare(c.b, c.a); got != -c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", c.b, c.a, got, -c.want)
		}
	}
}
