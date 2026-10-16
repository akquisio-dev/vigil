//go:build !(linux && (amd64 || arm64))

package agent

import "errors"

type canaryWatch struct{}

func newCanaryWatch() (*canaryWatch, error) {
	return nil, errors.New("canary watching needs linux on amd64 or arm64")
}

func (a *Agent) remarkCanaries() {
	a.mu.Lock()
	a.canaryPaths = a.activeCanaryPaths()
	a.mu.Unlock()
}

func (a *Agent) runCanaryWatch() {}
