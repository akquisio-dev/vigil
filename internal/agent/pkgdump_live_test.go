package agent

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/akquisio-dev/vigil/internal/dpkgver"
)

func TestDumpPackagesLive(t *testing.T) {
	out := os.Getenv("VIGIL_DUMP_PACKAGES")
	if out == "" {
		t.Skip("set VIGIL_DUMP_PACKAGES")
	}
	var list [][2]string
	for _, p := range sourcePackages("/var/lib/dpkg/status", func(a, b string) bool { return dpkgver.Compare(a, b) > 0 }) {
		list = append(list, [2]string{p.Name, p.Version})
	}
	b, _ := json.Marshal(list)
	os.WriteFile(out, b, 0o600)
	t.Logf("%d source packages", len(list))
}
