package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/akquisio-dev/vigil/internal/proto"
)

// Kernel modules are the classic place for rootkits. The collector compares
// /proc/modules with its own baseline, looks for modules that sysfs knows
// but /proc/modules hides, and reports new kernel taint flags.

// KernelState lives in its own file, so it has its own baseline: hosts that
// were enrolled before this collector existed must not report every loaded
// module as new.
type KernelState struct {
	Baselined bool              `json:"baselined"`
	Modules   map[string]string `json:"modules"` // name -> taint letters
	Tainted   uint64            `json:"tainted"`
	// Hidden counts consecutive scans that saw a module only in sysfs, so a
	// module caught half loaded is not reported.
	Hidden map[string]int `json:"hidden,omitempty"`
}

// taintLetters follows the kernel's documentation of /proc/sys/kernel/tainted.
const taintLetters = "PFSRMBUDAWCIOELKXTN"

func taintString(v uint64) string {
	var b strings.Builder
	for i := 0; i < len(taintLetters); i++ {
		if v&(1<<i) != 0 {
			b.WriteByte(taintLetters[i])
		}
	}
	return b.String()
}

type module struct {
	name, taint string
	size        int
}

// parseModules reads /proc/modules: "name size refs deps state addr (OE)".
func parseModules(raw []byte) map[string]module {
	out := map[string]module{}
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		m := module{name: f[0]}
		m.size, _ = strconv.Atoi(f[1])
		if last := f[len(f)-1]; strings.HasPrefix(last, "(") && strings.HasSuffix(last, ")") {
			m.taint = strings.Trim(last, "()")
		}
		out[m.name] = m
	}
	return out
}

// liveInSysfs lists loadable modules that sysfs reports as live. Built-in
// modules have no initstate file.
func liveInSysfs(root string) []string {
	files, _ := filepath.Glob(filepath.Join(root, "*", "initstate"))
	var out []string
	for _, f := range files {
		if b, err := os.ReadFile(f); err == nil && strings.TrimSpace(string(b)) == "live" {
			out = append(out, filepath.Base(filepath.Dir(f)))
		}
	}
	return out
}

func kernelStatePath(dir string) string { return filepath.Join(dir, "kernel.json") }

func loadKernelState(dir string) *KernelState {
	ks := &KernelState{}
	if raw, err := os.ReadFile(kernelStatePath(dir)); err == nil {
		json.Unmarshal(raw, ks)
	}
	if ks.Modules == nil {
		ks.Modules = map[string]string{}
	}
	if ks.Hidden == nil {
		ks.Hidden = map[string]int{}
	}
	return ks
}

// scanKernel runs with every scan; it reads three small files.
func (a *Agent) scanKernel() {
	if !on(a.cfg.Kernel) {
		return
	}
	raw, err := os.ReadFile("/proc/modules")
	if err != nil {
		if a.collectorDown("kernel") == "" {
			a.collectorFailed("kernel", err.Error())
		}
		return
	}
	var tainted uint64
	if b, err := os.ReadFile("/proc/sys/kernel/tainted"); err == nil {
		tainted, _ = strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	}
	if a.kernel == nil {
		a.kernel = loadKernelState(a.cfg.StateDir)
	}
	changed := a.kernelDiff(a.kernel, parseModules(raw), liveInSysfs("/sys/module"), tainted)
	if changed {
		a.saveKernel()
	}
}

func (a *Agent) saveKernel() {
	if raw, err := json.Marshal(a.kernel); err == nil {
		writeFileAtomic(kernelStatePath(a.cfg.StateDir), raw, 0o600)
	}
}

// kernelDiff updates ks and emits events. It returns whether ks changed.
func (a *Agent) kernelDiff(ks *KernelState, mods map[string]module, sysfs []string, tainted uint64) bool {
	changed := false
	if !ks.Baselined {
		for n, m := range mods {
			ks.Modules[n] = m.taint
		}
		ks.Tainted, ks.Baselined = tainted, true
		var odd []string
		for n, m := range mods {
			if strings.ContainsAny(m.taint, "OEP") {
				odd = append(odd, n+" ("+m.taint+")")
			}
		}
		sort.Strings(odd)
		a.emit(proto.NewEvent("kernel.baseline", map[string]any{"modules": len(mods), "tainted": taintString(tainted), "out_of_tree": odd}))
		changed = true
	} else {
		for n, m := range mods {
			if _, known := ks.Modules[n]; !known {
				a.emit(proto.NewEvent("kernel.module_loaded", map[string]any{"name": n, "taint": m.taint, "size": m.size}))
				changed = true
			}
			if ks.Modules[n] != m.taint {
				ks.Modules[n] = m.taint
				changed = true
			}
		}
		for n := range ks.Modules {
			if _, ok := mods[n]; !ok {
				a.emit(proto.NewEvent("kernel.module_unloaded", map[string]any{"name": n}))
				delete(ks.Modules, n)
				changed = true
			}
		}
		if added := tainted &^ ks.Tainted; added != 0 {
			a.emit(proto.NewEvent("kernel.tainted", map[string]any{"added": taintString(added), "tainted": taintString(tainted), "value": tainted}))
		}
		if tainted != ks.Tainted {
			ks.Tainted = tainted
			changed = true
		}
	}

	seen := map[string]bool{}
	for _, n := range sysfs {
		if _, listed := mods[n]; listed {
			continue
		}
		seen[n] = true
		ks.Hidden[n]++
		changed = true
		if ks.Hidden[n] == 2 {
			a.emit(proto.NewEvent("kernel.module_hidden", map[string]any{"name": n}))
		}
	}
	for n := range ks.Hidden {
		if !seen[n] {
			delete(ks.Hidden, n)
			changed = true
		}
	}
	return changed
}
