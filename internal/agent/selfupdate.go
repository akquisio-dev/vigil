package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
	"github.com/akquisio-dev/vigil/internal/release"
)

// Self-update runs in two halves. The agent, which keeps its sandbox
// (/usr is read-only for it), only downloads a release into its state
// directory and checks the signature. The second half is `vigil-agent
// update`, started by vigil-agent-update.path when the files are ready: it
// is the installed binary, checks everything again from scratch, test-runs
// the new binary, swaps it in (keeping .prev), restarts the agent and puts
// the old binary back if the new one does not stay up.

type updateResult struct {
	ID      string    `json:"id"`
	Version string    `json:"version"`
	From    string    `json:"from"`
	Status  string    `json:"status"` // applied | failed | rolled_back
	Error   string    `json:"error,omitempty"`
	At      time.Time `json:"at"`
}

func updateDir(stateDir string) string { return filepath.Join(stateDir, "update") }

// selfUpdate handles an update request from the server, once per id.
func (a *Agent) selfUpdate(req *proto.UpdateRequest) {
	if req == nil || req.ID == "" || len(req.ID) > 64 {
		return
	}
	if a.state.ActionsDone == nil {
		a.state.ActionsDone = map[string]time.Time{}
	}
	key := "update:" + req.ID
	if _, done := a.state.ActionsDone[key]; done {
		return
	}
	a.state.ActionsDone[key] = time.Now()
	report := func(status, msg string) {
		a.emit(proto.NewEvent("agent.update", map[string]any{"id": req.ID, "version": req.Version, "from": Version, "status": status, "error": msg}))
	}
	switch {
	case !a.cfg.SelfUpdate:
		report("refused", "self_update is off in agent.json")
		return
	case !release.ValidVersion(req.Version):
		report("refused", "not a release version")
		return
	case !release.Newer(req.Version, Version):
		report("refused", "not newer than "+Version)
		return
	}
	if exe, err := os.Executable(); err == nil {
		if pkg := dpkgOwner(exe); pkg != "" {
			report("refused", "installed from the Debian package "+pkg+"; update it with apt")
			return
		}
	}
	dir := updateDir(a.cfg.StateDir)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		err := os.MkdirAll(dir, 0o700)
		if err == nil {
			err = os.WriteFile(filepath.Join(dir, "request"), []byte(req.ID), 0o600)
		}
		if err == nil {
			err = release.Stage(ctx, &http.Client{Timeout: 5 * time.Minute}, "vigil-agent", req.Version, dir)
		}
		if err != nil {
			release.Clear(dir)
			report("failed", err.Error())
			return
		}
		report("staged", "")
		a.flushSoon() // the installer starts at once; tell the server first
	}()
}

// watchUpdates reports the outcome of an installation. The new agent is
// already running while the installer still watches it, so the result
// shows up after the start, not before it.
func (a *Agent) watchUpdates(ctx context.Context) {
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()
	for {
		a.reportUpdate()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (a *Agent) reportUpdate() {
	p := filepath.Join(updateDir(a.cfg.StateDir), "result.json")
	b, err := os.ReadFile(p)
	if err != nil {
		return
	}
	os.Remove(p)
	var r updateResult
	if json.Unmarshal(b, &r) != nil {
		return
	}
	a.emit(proto.NewEvent("agent.update", map[string]any{"id": r.ID, "version": r.Version, "from": r.From, "status": r.Status, "error": r.Error}))
}

// dpkgOwner names the Debian package that installed path, if any.
func dpkgOwner(path string) string {
	if p, err := filepath.EvalSymlinks(path); err == nil {
		path = p
	}
	for _, pkg := range []string{"vigil-agent"} {
		f, err := os.Open("/var/lib/dpkg/info/" + pkg + ".list")
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if sc.Text() == path {
				f.Close()
				return pkg
			}
		}
		f.Close()
	}
	return ""
}

// ApplyUpdate installs a staged release; see the top of this file. It
// returns nil when nothing is staged.
func ApplyUpdate(cfg *Config, unit string) (err error) {
	dir := updateDir(cfg.StateDir)
	if _, e := os.Stat(filepath.Join(dir, release.StagedReady)); errors.Is(e, os.ErrNotExist) {
		return nil
	}
	// Consume the trigger first, so a failure cannot start the path unit
	// over and over.
	os.Remove(filepath.Join(dir, release.StagedReady))
	id, _ := os.ReadFile(filepath.Join(dir, "request"))
	res := updateResult{ID: strings.TrimSpace(string(id)), From: Version}
	defer func() {
		res.At = time.Now().UTC()
		if err != nil && res.Status == "" {
			res.Status = "failed"
		}
		if err != nil {
			res.Error = err.Error()
		}
		if b, e := json.Marshal(res); e == nil {
			os.WriteFile(filepath.Join(dir, "result.json"), b, 0o600)
		}
		release.Clear(dir)
		os.Remove(filepath.Join(dir, "request"))
	}()

	version, bin, err := release.CheckStaged("vigil-agent", dir)
	if err != nil {
		return err
	}
	res.Version = version
	if !release.Newer(version, Version) {
		return fmt.Errorf("%s is not newer than the installed %s", version, Version)
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return err
	}
	if pkg := dpkgOwner(exe); pkg != "" {
		return fmt.Errorf("%s belongs to the Debian package %s; update it with apt", exe, pkg)
	}
	out, err := exec.Command(bin, "version").Output()
	if err != nil {
		return fmt.Errorf("the new binary does not run: %w", err)
	}
	if got := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0]); got != version {
		return fmt.Errorf("the new binary says it is %q, want %s", got, version)
	}

	if err := copyFile(exe, exe+".prev"); err != nil {
		return err
	}
	if err := swapIn(bin, exe); err != nil {
		return err
	}
	if err := restartAndWatch(unit, exe); err != nil {
		res.Status = "rolled_back"
		if rerr := swapIn(exe+".prev", exe); rerr != nil {
			return fmt.Errorf("%v; putting the old binary back failed too: %v", err, rerr)
		}
		exec.Command("systemctl", "restart", unit).Run()
		return err
	}
	res.Status = "applied"
	return nil
}

// swapIn copies src next to dst and renames it over dst, so dst is never
// half written.
func swapIn(src, dst string) error {
	tmp := dst + ".new"
	if err := copyFile(src, tmp); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err = io.Copy(out, in); err == nil {
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(dst, 0o755)
	}
	return err
}

// restartAndWatch restarts the agent and waits until it has run the new
// binary for 15 seconds without restarting.
func restartAndWatch(unit, exe string) error {
	if out, err := exec.Command("systemctl", "restart", unit).CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl restart: %v: %s", err, strings.TrimSpace(string(out)))
	}
	show := func() (active bool, restarts, pid string) {
		out, _ := exec.Command("systemctl", "show", "-p", "ActiveState", "-p", "NRestarts", "-p", "MainPID", unit).Output()
		for _, l := range strings.Split(string(out), "\n") {
			k, v, _ := strings.Cut(l, "=")
			switch k {
			case "ActiveState":
				active = v == "active"
			case "NRestarts":
				restarts = v
			case "MainPID":
				pid = v
			}
		}
		return
	}
	_, base, _ := show()
	var since time.Time
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(time.Second)
		active, restarts, pid := show()
		running, _ := os.Readlink("/proc/" + pid + "/exe")
		if !active || restarts != base || running != exe {
			since = time.Time{}
			if restarts != base {
				return fmt.Errorf("the new agent exited and was restarted by systemd")
			}
			continue
		}
		if since.IsZero() {
			since = time.Now()
		}
		if time.Since(since) >= 15*time.Second {
			return nil
		}
	}
	return errors.New("the new agent did not stay up for 15 seconds")
}
