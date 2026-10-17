package agent

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/akquisio-dev/vigil/internal/proto"
)

// TestYaraFalsePositivesLive scans the programs below VIGIL_YARA_SCAN
// (colon separated) with the starter rules and lists every match:
//
//	VIGIL_YARA_SCAN=/usr/bin:/usr/sbin go test ./internal/agent -run YaraFalsePositivesLive -v
func TestYaraFalsePositivesLive(t *testing.T) {
	roots := os.Getenv("VIGIL_YARA_SCAN")
	if roots == "" {
		t.Skip("set VIGIL_YARA_SCAN")
	}
	src, _ := os.ReadFile("../../deploy/examples/yara/linux.yar")
	a := &Agent{cfg: &Config{MaxQueue: 100000, StateDir: t.TempDir()}, flushNow: make(chan struct{}, 1)}
	a.setYara(&proto.YaraRules{Hash: "x", Source: string(src)}, false)
	n := 0
	for _, root := range strings.Split(roots, ":") {
		filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !d.Type().IsRegular() {
				return nil
			}
			fi, err := d.Info()
			if err != nil || fi.Size() > scanMaxBytes || !isProgram(p, fi.Mode()) || ownProgram(p) {
				return nil
			}
			f, err := os.Open(p)
			if err != nil {
				return nil
			}
			_, _, hits := a.scanReader(f)
			f.Close()
			n++
			if names, _ := ruleNames(hits); len(names) > 0 {
				t.Logf("MATCH %s: %v", p, names)
			}
			return nil
		})
	}
	t.Logf("%d programs scanned", n)
}
