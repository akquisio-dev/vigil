package release

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Repo is the GitHub repository releases come from.
const Repo = repo

var versionRE = regexp.MustCompile(`^v(\d{1,4})\.(\d{1,4})\.(\d{1,4})$`)

// ValidVersion reports whether v is a release tag like v0.19.0.
func ValidVersion(v string) bool { return versionRE.MatchString(v) }

// Newer reports whether release a is newer than b. Anything that is not a
// release (a build from source says "dev") is never newer and never older.
func Newer(a, b string) bool {
	ma, mb := versionRE.FindStringSubmatch(a), versionRE.FindStringSubmatch(b)
	if ma == nil || mb == nil {
		return false
	}
	for i := 1; i <= 3; i++ {
		x, _ := strconv.Atoi(ma[i])
		y, _ := strconv.Atoi(mb[i])
		if x != y {
			return x > y
		}
	}
	return false
}

// Staged file names in an update directory. ready is written last.
const (
	StagedSums    = "SHA256SUMS"
	StagedBundle  = "SHA256SUMS.sigstore.json"
	StagedBinary  = "binary"
	StagedVersion = "version"
	StagedReady   = "ready"
	maxBinary     = 64 << 20
	maxSmall      = 1 << 20
)

// BinaryName is the release asset of cmd for this machine.
func BinaryName(cmd, version string) string {
	return fmt.Sprintf("%s_%s_linux_%s", cmd, version, runtime.GOARCH)
}

// Stage downloads the release binary of cmd into dir and checks it, so that
// a separate, privileged step can install it. Nothing outside dir is
// touched. The files are written in an order that leaves ready last.
func Stage(ctx context.Context, c *http.Client, cmd, version, dir string) error {
	if !ValidVersion(version) {
		return fmt.Errorf("%q is not a release version", version)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	Clear(dir)
	base := fmt.Sprintf("https://github.com/%s/releases/download/%s/", repo, version)
	sums, err := fetch(ctx, c, base+"SHA256SUMS", maxSmall)
	if err != nil {
		return err
	}
	bundle, err := fetch(ctx, c, base+"SHA256SUMS.sigstore.json", maxSmall)
	if err != nil {
		return err
	}
	if err := VerifySums(sums, bundle, repo, version); err != nil {
		return err
	}
	name := BinaryName(cmd, version)
	want, err := sumOf(sums, name)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+name, nil)
	if err != nil {
		return err
	}
	res, err := c.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d", name, res.StatusCode)
	}
	f, err := os.OpenFile(filepath.Join(dir, StagedBinary), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o700)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(res.Body, maxBinary+1))
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n > maxBinary {
		return fmt.Errorf("%s is larger than %d bytes", name, maxBinary)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return fmt.Errorf("%s: sha256 %s, SHA256SUMS says %s", name, got, want)
	}
	for _, w := range []struct {
		name string
		b    []byte
	}{{StagedSums, sums}, {StagedBundle, bundle}, {StagedVersion, []byte(version)}, {StagedReady, []byte(version)}} {
		if err := os.WriteFile(filepath.Join(dir, w.name), w.b, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// CheckStaged checks the staged files in dir again, from scratch: the
// signature of SHA256SUMS for the staged version and the binary's hash.
// It returns the version and the path of the binary.
func CheckStaged(cmd, dir string) (version, binary string, err error) {
	read := func(name string) []byte {
		b, e := os.ReadFile(filepath.Join(dir, name))
		if e != nil && err == nil {
			err = e
		}
		return b
	}
	version = strings.TrimSpace(string(read(StagedVersion)))
	sums, bundle := read(StagedSums), read(StagedBundle)
	if err != nil {
		return "", "", err
	}
	if !ValidVersion(version) {
		return "", "", fmt.Errorf("staged version %q is not a release", version)
	}
	if err := VerifySums(sums, bundle, repo, version); err != nil {
		return "", "", err
	}
	want, err := sumOf(sums, BinaryName(cmd, version))
	if err != nil {
		return "", "", err
	}
	binary = filepath.Join(dir, StagedBinary)
	f, err := os.Open(binary)
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, maxBinary+1)); err != nil {
		return "", "", err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return "", "", fmt.Errorf("staged binary: sha256 %s, SHA256SUMS says %s", got, want)
	}
	return version, binary, nil
}

// Clear removes what Stage writes, and nothing else.
func Clear(dir string) {
	for _, n := range []string{StagedReady, StagedVersion, StagedSums, StagedBundle, StagedBinary} {
		os.Remove(filepath.Join(dir, n))
	}
}

// Latest asks GitHub for the newest release tag, without the API: the
// latest-release page redirects to its tag.
func Latest(ctx context.Context) (string, error) {
	c := &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, "https://github.com/"+repo+"/releases/latest", nil)
	if err != nil {
		return "", err
	}
	res, err := c.Do(req)
	if err != nil {
		return "", err
	}
	res.Body.Close()
	loc := res.Header.Get("Location")
	i := strings.LastIndex(loc, "/tag/")
	if i < 0 {
		return "", fmt.Errorf("no release found (HTTP %d)", res.StatusCode)
	}
	v := loc[i+5:]
	if !ValidVersion(v) {
		return "", fmt.Errorf("latest release %q is not a version", v)
	}
	return v, nil
}

func fetch(ctx context.Context, c *http.Client, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	res, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", url[strings.LastIndex(url, "/")+1:], res.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err == nil && int64(len(b)) > limit {
		err = errors.New("download too large")
	}
	return b, err
}

func sumOf(sums []byte, name string) (string, error) {
	sc := bufio.NewScanner(bytes.NewReader(sums))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && f[1] == name && len(f[0]) == 64 {
			return f[0], nil
		}
	}
	return "", fmt.Errorf("%s is not in SHA256SUMS", name)
}
