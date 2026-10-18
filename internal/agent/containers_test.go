package agent

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const (
	idWeb  = "984894826a87aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	idPriv = "0d2608990af4bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// fakeDocker answers the two GET requests the agent makes, on a unix
// socket, and fails the test on anything else.
func fakeDocker(t *testing.T) (string, *int) {
	sock := filepath.Join(t.TempDir(), "docker.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	inspects := 0
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("agent sent %s %s", r.Method, r.URL.Path)
		}
		switch r.URL.Path {
		case "/containers/json":
			w.Write([]byte(`[{"Id":"` + idWeb + `"},{"Id":"` + idPriv + `"}]`))
		case "/containers/" + idWeb + "/json":
			inspects++
			w.Write([]byte(`{"Id":"` + idWeb + `","Name":"/app-web-1","Image":"sha256:1234567890abcdef","Config":{"Image":"nginx:alpine","Labels":{"com.docker.compose.project":"app"}},
"HostConfig":{"NetworkMode":"app_default"},"Mounts":[{"Type":"volume","Source":"/var/lib/docker/volumes/x","Destination":"/data","RW":true},{"Type":"bind","Source":"/srv/web","Destination":"/usr/share/nginx/html","RW":false}]}`))
		case "/containers/" + idPriv + "/json":
			inspects++
			w.Write([]byte(`{"Id":"` + idPriv + `","Name":"/agent","Image":"sha256:abc","Config":{"Image":"portainer/agent:2","User":"root"},
"HostConfig":{"Privileged":true,"PidMode":"host","NetworkMode":"host","CapAdd":["SYS_ADMIN","cap_net_admin"]},"Mounts":[{"Type":"bind","Source":"/var/run/docker.sock","Destination":"/var/run/docker.sock","RW":true}]}`))
		default:
			t.Errorf("unexpected %s", r.URL.Path)
			http.NotFound(w, r)
		}
	})}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return sock, &inspects
}

func TestContainerIndex(t *testing.T) {
	sock, inspects := fakeDocker(t)
	ci := &containerIndex{byID: map[string]*containerInfo{}, client: newDockerClient(sock)}
	if err := ci.refresh(); err != nil {
		t.Fatal(err)
	}
	web, priv := ci.byID[idWeb], ci.byID[idPriv]
	if web == nil || web.Name != "app-web-1" || web.Image != "nginx:alpine" || web.ImageID != "1234567890ab" || web.Project != "app" ||
		len(web.Mounts) != 1 || web.Mounts[0].Source != "/srv/web" || web.Privileged {
		t.Fatalf("web: %+v", web)
	}
	if priv == nil || !priv.Privileged || !priv.PidHost || !priv.NetHost || strings.Join(priv.CapAdd, ",") != "NET_ADMIN,SYS_ADMIN" || priv.User != "root" {
		t.Fatalf("priv: %+v", priv)
	}
	// Known containers are not inspected again.
	ci.refresh()
	if *inspects != 2 {
		t.Fatalf("%d inspects", *inspects)
	}

	snap, sum := containerSnapshot(ci.byID, []string{"deploy"})
	if l := snap["containers"].([]*containerInfo); len(l) != 2 || l[0].Name != "agent" {
		t.Fatalf("snapshot order: %v", l)
	}
	priv.Started = "2026-10-18T21:00:00Z"
	if _, sum2 := containerSnapshot(ci.byID, []string{"deploy"}); sum2 != sum {
		t.Fatal("a restart changed the overview")
	}
	if _, sum3 := containerSnapshot(ci.byID, nil); sum3 == sum {
		t.Fatal("docker group change not seen")
	}
}

func TestCgroupID(t *testing.T) {
	for in, want := range map[string]string{
		"0::/system.slice/docker-" + idWeb + ".scope\n":            idWeb,
		"12:pids:/docker/" + idPriv + "\n11:cpu:/docker/" + idPriv: idPriv,
		"0::/user.slice/user-0.slice/session-4.scope\n":            "",
	} {
		if got := cgroupID(in); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
}

func TestDockerGroup(t *testing.T) {
	p := filepath.Join(t.TempDir(), "group")
	os.WriteFile(p, []byte("root:x:0:\ndocker:x:988:joey,deploy\nsudo:x:27:joey\n"), 0o644)
	if g := dockerGroup(p); strings.Join(g, ",") != "deploy,joey" {
		t.Fatal(g)
	}
	os.WriteFile(p, []byte("docker:x:988:\n"), 0o644)
	if g := dockerGroup(p); g != nil {
		t.Fatal(g)
	}
}

// A hung Docker daemon costs one timeout per few seconds, not one per
// finding: the time of the attempt counts, not of the last success.
func TestContainerLookupBacksOff(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "docker.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	calls := 0
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		http.Error(w, "busy", http.StatusInternalServerError)
	})}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	a := &Agent{containers: &containerIndex{byID: map[string]*containerInfo{}, client: newDockerClient(sock)}}
	for i := 0; i < 5; i++ {
		if c := a.container(idWeb); c == nil || c.ID != "984894826a87" || c.Name != "" {
			t.Fatalf("lookup %d: %+v", i, c)
		}
	}
	if calls != 1 {
		t.Fatalf("%d requests to a failing daemon, want 1", calls)
	}
	if a.container("") != nil || (&Agent{}).container(idWeb) != nil || (&Agent{}).pidContainer(1) != "" {
		t.Fatal("lookups without an id or with docker off must find nothing")
	}
}
