package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

// Docker containers. The agent asks the Docker Engine API on its local
// socket, with GET requests only, which containers run and how they are
// configured. It names the container in findings about processes inside
// one, and sends an overview of the containers when it changes, so the
// server can flag containers that can take over the host and images that
// were never seen on it.

const dockerSocket = "/var/run/docker.sock"

type mountInfo struct {
	Source string `json:"source"`
	Dest   string `json:"dest"`
	RW     bool   `json:"rw"`
}

type containerInfo struct {
	ID         string      `json:"id"` // 12 characters
	Name       string      `json:"name"`
	Image      string      `json:"image"`
	ImageID    string      `json:"image_id,omitempty"`
	Project    string      `json:"project,omitempty"` // docker compose project
	Privileged bool        `json:"privileged,omitempty"`
	PidHost    bool        `json:"pid_host,omitempty"`
	NetHost    bool        `json:"net_host,omitempty"`
	CapAdd     []string    `json:"cap_add,omitempty"`
	User       string      `json:"user,omitempty"`
	Mounts     []mountInfo `json:"mounts,omitempty"` // bind mounts from the host
	Started    string      `json:"started,omitempty"`
}

type containerIndex struct {
	mu      sync.Mutex
	byID    map[string]*containerInfo // full id
	fetched time.Time
	client  *http.Client
}

func newContainerIndex(cfg *Config) *containerIndex {
	if !on(cfg.Docker) {
		return nil
	}
	return &containerIndex{byID: map[string]*containerInfo{}, client: newDockerClient(dockerSocket)}
}

func newDockerClient(sock string) *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		},
		MaxIdleConns: 1,
	}}
}

func dockerGet(c *http.Client, path string, v any) error {
	res, err := c.Get("http://docker" + path)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("docker %s: HTTP %d", path, res.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(res.Body, 8<<20)).Decode(v)
}

// refresh lists the running containers and inspects the ones not known
// yet. Caller holds ci.mu.
func (ci *containerIndex) refresh() error {
	var list []struct {
		ID string `json:"Id"`
	}
	if err := dockerGet(ci.client, "/containers/json", &list); err != nil {
		return err
	}
	next := map[string]*containerInfo{}
	for _, c := range list {
		if old := ci.byID[c.ID]; old != nil {
			next[c.ID] = old
			continue
		}
		if len(next) >= 500 {
			break
		}
		info, err := inspectContainer(ci.client, c.ID)
		if err != nil {
			continue // gone in between
		}
		next[c.ID] = info
	}
	ci.byID, ci.fetched = next, time.Now()
	return nil
}

func inspectContainer(c *http.Client, id string) (*containerInfo, error) {
	var r struct {
		ID     string `json:"Id"`
		Name   string `json:"Name"`
		Image  string `json:"Image"`
		Config struct {
			Image  string            `json:"Image"`
			User   string            `json:"User"`
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
		HostConfig struct {
			Privileged  bool     `json:"Privileged"`
			PidMode     string   `json:"PidMode"`
			NetworkMode string   `json:"NetworkMode"`
			CapAdd      []string `json:"CapAdd"`
		} `json:"HostConfig"`
		Mounts []struct {
			Type        string `json:"Type"`
			Source      string `json:"Source"`
			Destination string `json:"Destination"`
			RW          bool   `json:"RW"`
		} `json:"Mounts"`
		State struct {
			StartedAt string `json:"StartedAt"`
		} `json:"State"`
	}
	if !containerIDRe.MatchString(id) {
		return nil, fmt.Errorf("bad container id")
	}
	if err := dockerGet(c, "/containers/"+id+"/json", &r); err != nil {
		return nil, err
	}
	info := &containerInfo{ID: short(r.ID), Name: clip(strings.TrimPrefix(r.Name, "/")), Image: clip(r.Config.Image),
		ImageID: short(strings.TrimPrefix(r.Image, "sha256:")), Project: clip(r.Config.Labels["com.docker.compose.project"]),
		Privileged: r.HostConfig.Privileged, PidHost: r.HostConfig.PidMode == "host", NetHost: r.HostConfig.NetworkMode == "host",
		User: clip(r.Config.User), Started: r.State.StartedAt}
	for _, c := range r.HostConfig.CapAdd {
		info.CapAdd = append(info.CapAdd, strings.TrimPrefix(strings.ToUpper(c), "CAP_"))
	}
	sort.Strings(info.CapAdd)
	for _, m := range r.Mounts {
		if m.Type == "bind" && len(info.Mounts) < 50 {
			info.Mounts = append(info.Mounts, mountInfo{Source: clip(m.Source), Dest: clip(m.Destination), RW: m.RW})
		}
	}
	return info, nil
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

var (
	cgroupContainer = regexp.MustCompile(`[0-9a-f]{64}`)
	containerIDRe   = regexp.MustCompile(`^[0-9a-f]{12,64}$`)
)

// pidContainer is the id of the container a process runs in, from its
// cgroup (".../docker-<id>.scope" or "/docker/<id>"), or "" for the host.
// Read it while the process still runs: short-lived ones are gone by the
// time a scan is done.
func (a *Agent) pidContainer(pid int) string {
	if a.containers == nil || pid <= 0 {
		return ""
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return ""
	}
	return cgroupID(string(b))
}

// container looks up a container by full id.
func (a *Agent) container(id string) *containerInfo {
	ci := a.containers
	if ci == nil || id == "" {
		return nil
	}
	ci.mu.Lock()
	defer ci.mu.Unlock()
	if c := ci.byID[id]; c != nil {
		return c
	}
	// Started since the last look: one extra look per few seconds at
	// most, counted from the attempt, so a hung Docker daemon costs one
	// timeout and not one per finding.
	if time.Since(ci.fetched) > 3*time.Second {
		ci.fetched = time.Now()
		if ci.refresh() == nil {
			if c := ci.byID[id]; c != nil {
				return c
			}
		}
	}
	return &containerInfo{ID: short(id)}
}

// cgroupID is the container id in /proc/<pid>/cgroup, or "".
func cgroupID(cgroup string) string {
	ids := cgroupContainer.FindAllString(cgroup, -1)
	if len(ids) == 0 {
		return ""
	}
	return ids[len(ids)-1]
}

// tagContainer adds the container of pid to an event's data.
func (a *Agent) tagContainer(d map[string]any, pid int) {
	a.tagContainerID(d, a.pidContainer(pid))
}

// tagContainerID adds the container with this id to an event's data.
func (a *Agent) tagContainerID(d map[string]any, id string) {
	c := a.container(id)
	if c == nil {
		return
	}
	d["container_id"] = c.ID
	if c.Name != "" {
		d["container"] = c.Name
	}
	if c.Image != "" {
		d["image"] = c.Image
	}
}

// dockerGroup lists the members of the docker group: each of them can
// start a privileged container, so is root in all but name.
func dockerGroup(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Split(l, ":")
		if len(f) == 4 && f[0] == "docker" && f[3] != "" {
			m := strings.Split(f[3], ",")
			sort.Strings(m)
			return m
		}
	}
	return nil
}

func containerSnapshot(byID map[string]*containerInfo, group []string) (map[string]any, string) {
	list := make([]*containerInfo, 0, len(byID))
	for _, c := range byID {
		list = append(list, c)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	h := sha256.New()
	for _, c := range list {
		// Restarts change only the start time; the overview stays the same.
		cp := *c
		cp.Started = ""
		b, _ := json.Marshal(cp)
		h.Write(b)
	}
	h.Write([]byte(strings.Join(group, ",")))
	sum := hex.EncodeToString(h.Sum(nil))[:16]
	return map[string]any{"containers": list, "docker_group": group, "hash": sum}, sum
}

func (a *Agent) runContainers(ctx context.Context) {
	t := time.NewTimer(20 * time.Second)
	defer t.Stop()
	var lastHash string
	var lastSent time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if _, err := os.Stat(dockerSocket); err != nil {
			t.Reset(5 * time.Minute) // Docker may be installed later
			continue
		}
		t.Reset(time.Duration(a.cfg.ScanSeconds) * time.Second)
		ci := a.containers
		ci.mu.Lock()
		err := ci.refresh()
		var snap map[string]any
		var sum string
		if err == nil {
			snap, sum = containerSnapshot(ci.byID, dockerGroup("/etc/group"))
		}
		ci.mu.Unlock()
		if err != nil || (sum == lastHash && time.Since(lastSent) < 24*time.Hour) {
			continue
		}
		a.emit(proto.NewEvent("container.snapshot", snap))
		lastHash, lastSent = sum, time.Now()
	}
}
