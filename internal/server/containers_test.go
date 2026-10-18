package server

import (
	"strings"
	"testing"
	"time"

	"github.com/akquisio-dev/vigil/internal/proto"
)

func TestContainerRules(t *testing.T) {
	s := &Server{cfg: &Config{DataDir: t.TempDir()}, state: &State{Agents: map[string]*AgentRec{}, KnownLogins: map[string]time.Time{}}}
	a := &AgentRec{ID: "a1", Name: "host", Baseline: map[string]bool{}, StartedOnce: true}
	s.state.Agents[a.ID] = a
	send := func(typ string, d map[string]any) []*Alert {
		return s.raise(s.evaluate(a, &Record{Event: proto.Event{Type: typ, TS: time.Now(), Data: d}}), a.ID, 1)
	}
	web := map[string]any{"id": "984894826a87", "name": "app-web-1", "image": "nginx:alpine",
		"mounts": []any{map[string]any{"source": "/etc/localtime", "dest": "/etc/localtime", "rw": false}, map[string]any{"source": "/srv/web", "dest": "/html", "rw": true}}}
	priv := map[string]any{"id": "0d2608990af4", "name": "agent", "image": "portainer/agent:2", "privileged": true, "cap_add": []any{"NET_ADMIN", "SYS_ADMIN"},
		"mounts": []any{map[string]any{"source": "/var/run/docker.sock", "dest": "/var/run/docker.sock", "rw": true}, map[string]any{"source": "/", "dest": "/host", "rw": false}}}

	// First overview: the images are the baseline, the risks alert.
	fresh := send("container.snapshot", map[string]any{"containers": []any{web, priv}, "docker_group": []any{"root", "deploy"}})
	got := map[string]string{}
	for _, al := range fresh {
		got[al.Rule] = al.Severity + " " + al.Title
	}
	if len(fresh) != 3 ||
		got["container.privileged"] != "high Container agent (portainer/agent:2) can take over the host: privileged, CAP_SYS_ADMIN, host / mounted" ||
		got["container.docker_socket"] != "high Container agent (portainer/agent:2) has the Docker socket, so it controls the host" ||
		got["container.docker_group"] != "medium Members of the docker group are root in all but name: deploy" {
		t.Fatalf("first: %v", got)
	}
	if len(a.Containers) != 2 || len(a.Containers[0].Risks) != 3 || len(a.Containers[1].Risks) != 0 {
		t.Fatalf("stored: %+v", a.Containers)
	}

	// A new image alerts once; the fixed container resolves.
	miner := map[string]any{"id": "aaaaaaaaaaaa", "name": "x", "image": "evil/miner:latest"}
	delete(priv, "privileged")
	priv["cap_add"] = []any{"NET_ADMIN"}
	priv["mounts"] = []any{}
	fresh = send("container.snapshot", map[string]any{"containers": []any{web, priv, miner}})
	if len(fresh) != 1 || fresh[0].Rule != "container.new_image" || fresh[0].Title != "New image on this host: evil/miner:latest (container x)" {
		t.Fatalf("second: %+v", fresh)
	}
	for _, al := range s.state.Alerts {
		if al.Rule != "container.new_image" && al.Status != "resolved" {
			t.Fatalf("still open: %s", al.Title)
		}
	}
	if fresh := send("container.snapshot", map[string]any{"containers": []any{web, priv, miner}}); len(fresh) != 0 {
		t.Fatalf("third: %+v", fresh)
	}

	// Findings from inside a container name it.
	fresh = send("process.exec", map[string]any{"pid": 7, "uid": "0", "exe": "/tmp/x", "comm": "x", "cmdline": "/tmp/x", "signals": []any{"tmp_exe"},
		"container": "app-web-1", "container_id": "984894826a87", "image": "nginx:alpine"})
	if len(fresh) != 1 || !strings.HasSuffix(fresh[0].Title, "[container app-web-1]") {
		t.Fatalf("process in container: %+v", fresh)
	}
	if de := renderTitle(fresh[0].Rule, decodeParams(fresh[0].Detail), "de"); !strings.HasSuffix(de, "[Container app-web-1]") {
		t.Fatalf("de: %s", de)
	}
}
