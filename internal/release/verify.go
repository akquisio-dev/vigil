// Package release checks that a running binary is a published release.
package release

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"
)

const repo = "akquisio-dev/vigil"

// Verify compares the SHA-256 of the running executable with the release's
// SHA256SUMS on GitHub. It only says that the bytes match what the release
// workflow published; check the signature of SHA256SUMS with cosign to know
// that the workflow made it (see the installation docs).
func Verify(cmd, version string) (string, error) {
	if !strings.HasPrefix(version, "v") || version == "dev" {
		return "", fmt.Errorf("%s is not a release version (built from source)", version)
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	f, err := os.Open(exe)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	sum := hex.EncodeToString(h.Sum(nil))

	name := fmt.Sprintf("%s_%s_linux_%s", cmd, version, runtime.GOARCH)
	url := fmt.Sprintf("https://github.com/%s/releases/download/%s/SHA256SUMS", repo, version)
	c := &http.Client{Timeout: 20 * time.Second}
	res, err := c.Get(url)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return "", fmt.Errorf("%s: HTTP %d", url, res.StatusCode)
	}
	sc := bufio.NewScanner(io.LimitReader(res.Body, 1<<20))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && f[1] == name {
			if f[0] == sum {
				return fmt.Sprintf("%s matches the published %s (sha256 %s)", exe, name, sum), nil
			}
			return "", fmt.Errorf("%s does NOT match %s: sha256 %s, published %s", exe, name, sum, f[0])
		}
	}
	return "", fmt.Errorf("%s is not listed in %s", name, url)
}
