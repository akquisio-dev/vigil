package agent

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"github.com/akquisio-dev/vigil/internal/proto"
)

// eBPF rootkits (boopkit, TripleCross, ebpfkit) hook syscalls with kprobe,
// tracepoint or tracing programs, or filter packets with XDP. systemd and
// Docker load cgroup programs all the time, so only the types that can hook
// the kernel or the network path are reported, keyed by type, name and tag
// (a hash of the program), so reloading the same program stays quiet.

const (
	bpfProgGetNextID   = 11
	bpfProgGetFDByID   = 13
	bpfObjGetInfoByFD  = 15
	bpfProgInfoReadLen = 84 // up to and including ifindex; stable since 4.15
)

var bpfTypes = map[uint32]string{1: "socket_filter", 2: "kprobe", 3: "sched_cls", 4: "sched_act", 5: "tracepoint", 6: "xdp",
	7: "perf_event", 8: "cgroup_skb", 9: "cgroup_sock", 13: "sock_ops", 14: "sk_skb", 15: "cgroup_device", 16: "sk_msg",
	17: "raw_tracepoint", 18: "cgroup_sock_addr", 23: "cgroup_sysctl", 24: "raw_tracepoint_writable", 25: "cgroup_sockopt",
	26: "tracing", 27: "struct_ops", 28: "ext", 29: "lsm", 30: "sk_lookup", 31: "syscall", 32: "netfilter"}

// bpfHooking are the types that can read or change what the kernel does for
// every process, or every packet before the firewall.
var bpfHooking = map[string]bool{"kprobe": true, "tracepoint": true, "xdp": true, "perf_event": true, "raw_tracepoint": true,
	"raw_tracepoint_writable": true, "tracing": true, "ext": true, "lsm": true}

// bpfKernelPreload are programs the kernel loads itself while booting
// (HID-BPF since 6.3, the bpf_preload iterators). They count as the
// kernel's only when they were loaded in the first two minutes after boot,
// so taking their name later does not help.
var bpfKernelPreload = map[string]bool{"hid_tail_call": true, "dump_bpf_map": true, "dump_bpf_prog": true}

const bpfBootWindow = 120e9 // ns since boot

type bpfProg struct {
	ID       uint32
	Type     string
	Tag      string
	Name     string
	UID      uint32
	LoadTime uint64
}

func (p bpfProg) key() string { return p.Type + "|" + p.Name + "|" + p.Tag }

func bpfCall(cmd int, attr []byte) (uintptr, error) {
	r, _, e := syscall.Syscall(sysBPF, uintptr(cmd), uintptr(unsafe.Pointer(&attr[0])), uintptr(len(attr)))
	if e != 0 {
		return 0, e
	}
	return r, nil
}

// listBPF enumerates loaded programs by id. It needs CAP_SYS_ADMIN (or
// CAP_BPF and CAP_PERFMON).
func listBPF() ([]bpfProg, error) {
	var out []bpfProg
	ne := binary.NativeEndian
	id := uint32(0)
	for i := 0; i < 100000; i++ {
		attr := make([]byte, 16)
		ne.PutUint32(attr[0:], id)
		if _, err := bpfCall(bpfProgGetNextID, attr); err != nil {
			if errors.Is(err, syscall.ENOENT) {
				return out, nil
			}
			return out, err
		}
		id = ne.Uint32(attr[4:])
		attr = make([]byte, 16)
		ne.PutUint32(attr[0:], id)
		fd, err := bpfCall(bpfProgGetFDByID, attr)
		if err != nil {
			continue // unloaded in between
		}
		info := make([]byte, 128)
		attr = make([]byte, 16)
		ne.PutUint32(attr[0:], uint32(fd))
		ne.PutUint32(attr[4:], bpfProgInfoReadLen)
		ne.PutUint64(attr[8:], uint64(uintptr(unsafe.Pointer(&info[0]))))
		_, err = bpfCall(bpfObjGetInfoByFD, attr)
		syscall.Close(int(fd))
		if err != nil {
			continue
		}
		t := ne.Uint32(info[0:])
		name := strings.TrimRight(string(info[64:80]), "\x00")
		typ, ok := bpfTypes[t]
		if !ok {
			typ = "type_" + hexU32(t)
		}
		out = append(out, bpfProg{ID: ne.Uint32(info[4:]), Type: typ, Tag: hex.EncodeToString(info[8:16]), Name: name,
			UID: ne.Uint32(info[48:]), LoadTime: ne.Uint64(info[40:])})
	}
	return out, nil
}

func hexU32(v uint32) string {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return hex.EncodeToString(b)
}

type BPFState struct {
	Baselined bool            `json:"baselined"`
	Known     map[string]bool `json:"known"`
}

func bpfStatePath(dir string) string { return filepath.Join(dir, "bpf.json") }

// scanBPF runs with every scan.
func (a *Agent) scanBPF() {
	if !on(a.cfg.BPF) || a.collectorDown("bpf") != "" {
		return
	}
	progs, err := listBPF()
	if err != nil {
		a.collectorFailed("bpf", err.Error())
		return
	}
	if a.bpf == nil {
		a.bpf = &BPFState{}
		if raw, err := os.ReadFile(bpfStatePath(a.cfg.StateDir)); err == nil {
			json.Unmarshal(raw, a.bpf)
		}
		if a.bpf.Known == nil {
			a.bpf.Known = map[string]bool{}
		}
	}
	if a.diffBPF(a.bpf, progs) {
		if raw, err := json.Marshal(a.bpf); err == nil {
			writeFileAtomic(bpfStatePath(a.cfg.StateDir), raw, 0o600)
		}
	}
}

func (a *Agent) diffBPF(bs *BPFState, progs []bpfProg) bool {
	changed := false
	for _, p := range progs {
		if !bpfHooking[p.Type] || bs.Known[p.key()] || bpfKernelPreload[p.Name] && p.UID == 0 && p.LoadTime < bpfBootWindow {
			continue
		}
		if len(bs.Known) >= 5000 {
			break
		}
		bs.Known[p.key()] = true
		changed = true
		d := map[string]any{"id": p.ID, "type": p.Type, "name": p.Name, "tag": p.Tag, "uid": p.UID}
		if !bs.Baselined {
			d["baseline"] = true
		}
		a.emit(proto.NewEvent("kernel.bpf_loaded", d))
	}
	if !bs.Baselined {
		bs.Baselined = true
		changed = true
	}
	return changed
}
