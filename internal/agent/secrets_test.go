package agent

import "testing"

func TestVendoredDir(t *testing.T) {
	for p, want := range map[string]bool{
		"/opt/unified-monitoring-agent/embedded/lib/ruby":                      true,
		"/opt/unified-monitoring-agent/embedded/lib/ruby/gems":                 true,
		"/opt/app/node_modules":                                                true,
		"/home/moritz/ruby":                                                    false, // a folder named ruby elsewhere is scanned
		"/srv/app/config":                                                      false,
		"/opt/unified-monitoring-agent/embedded/lib/ruby/3.3.0/net/http_extra": false,
	} {
		name := p[len(p)-len(lastElem(p)):]
		if got := vendoredDir(p, name); got != want {
			t.Errorf("%s: %v, want %v", p, got, want)
		}
	}
}

func lastElem(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[i+1:]
		}
	}
	return p
}
