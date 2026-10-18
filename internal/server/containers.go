package server

import (
	"encoding/json"
	"sort"
	"strings"
	"time"
)

// Containers. Agents send an overview of the running Docker containers when
// it changes (container.snapshot). Containers that can take over the host
// and members of the docker group are conditions: they alert once and
// resolve when the container or the membership is gone. Images are learned
// per host from the first overview; one never seen before alerts once.

type ContainerMount struct {
	Source string `json:"source"`
	Dest   string `json:"dest"`
	RW     bool   `json:"rw"`
}

type Container struct {
	ID         string           `json:"id"`
	Name       string           `json:"name"`
	Image      string           `json:"image"`
	ImageID    string           `json:"image_id,omitempty"`
	Project    string           `json:"project,omitempty"`
	Privileged bool             `json:"privileged,omitempty"`
	PidHost    bool             `json:"pid_host,omitempty"`
	NetHost    bool             `json:"net_host,omitempty"`
	CapAdd     []string         `json:"cap_add,omitempty"`
	User       string           `json:"user,omitempty"`
	Mounts     []ContainerMount `json:"mounts,omitempty"`
	Started    string           `json:"started,omitempty"`
	// Risks is filled in by the server: why the container can reach the host.
	Risks []string `json:"risks,omitempty"`
}

// Capabilities that let a process leave its container.
var escapeCaps = map[string]bool{"SYS_ADMIN": true, "SYS_PTRACE": true, "SYS_MODULE": true, "DAC_READ_SEARCH": true, "SYS_RAWIO": true, "BPF": true, "ALL": true}

// Host paths that hand over the host when mounted writable ("/" even read
// only). Matched exactly: a single file below /etc (localtime) is fine.
var hostPaths = map[string]bool{"/etc": true, "/root": true, "/boot": true, "/usr": true, "/var/lib/docker": true, "/dev": true,
	"/proc": true, "/sys": true, "/lib/modules": true, "/var/run": true, "/run": true, "/home": true}

func dockerSocketPath(p string) bool {
	return p == "/var/run/docker.sock" || p == "/run/docker.sock" || p == "/var/run/docker" || p == "/run/docker"
}

// containerRisks names what lets the container reach the host, apart from
// the Docker socket, which has its own rule.
func containerRisks(c *Container) []string {
	var out []string
	if c.Privileged {
		out = append(out, "privileged")
	}
	if c.PidHost {
		out = append(out, "host PID namespace")
	}
	for _, cp := range c.CapAdd {
		if escapeCaps[cp] {
			out = append(out, "CAP_"+cp)
		}
	}
	for _, m := range c.Mounts {
		src := strings.TrimSuffix(m.Source, "/")
		switch {
		case src == "" && m.Source == "/":
			out = append(out, "host / mounted")
		case hostPaths[src] && m.RW:
			out = append(out, "host "+src+" writable")
		}
	}
	return out
}

// containersReceived stores a host's containers and evaluates them. Caller
// holds s.mu.
func (s *Server) containersReceived(a *AgentRec, d map[string]any) []finding {
	var list []*Container
	if raw, err := json.Marshal(d["containers"]); err == nil {
		json.Unmarshal(raw, &list)
	}
	if len(list) > 500 {
		list = list[:500]
	}
	var group []string
	for _, u := range strSlice(d["docker_group"]) {
		if u != "root" && u != "" && len(group) < 50 {
			group = append(group, clip(u, 64))
		}
	}
	sort.Strings(group)

	var conds []condition
	var out []finding
	if a.Images == nil {
		a.Images = map[string]time.Time{}
	}
	first := !a.ImagesBaselined
	for _, c := range list {
		c.Name, c.Image = clip(c.Name, 128), clip(c.Image, 200)
		c.Risks = containerRisks(c)
		p := map[string]string{"container": c.Name, "image": c.Image}
		if len(c.Risks) > 0 {
			q := map[string]string{"container": c.Name, "image": c.Image, "reasons": strings.Join(c.Risks, ", ")}
			conds = append(conds, condition{"container.privileged", c.Name, q})
		}
		for _, m := range c.Mounts {
			if dockerSocketPath(m.Source) {
				conds = append(conds, condition{"container.docker_socket", c.Name, p})
				break
			}
		}
		if c.Image == "" {
			continue
		}
		if _, seen := a.Images[c.Image]; !seen {
			if !first && len(a.Images) < 2000 {
				out = append(out, finding{Rule: "container.new_image", Key: "container.new_image|" + a.ID + "|" + c.Image,
					Params: map[string]string{"container": c.Name, "image": c.Image, "host": a.Name}})
			}
			if len(a.Images) < 2000 {
				a.Images[c.Image] = time.Now().UTC()
			}
		}
	}
	a.ImagesBaselined = true
	if len(group) > 0 {
		conds = append(conds, condition{"container.docker_group", "group", map[string]string{"users": strings.Join(group, ", ")}})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	a.Containers, a.DockerGroup = list, group
	return append(out, s.conditionFindings(a, "containers", conds)...)
}
