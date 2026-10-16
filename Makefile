VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/akquisio-dev/vigil/internal/agent.Version=$(VERSION) -X github.com/akquisio-dev/vigil/internal/server.Version=$(VERSION)

.PHONY: build test vet clean
build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/ ./cmd/...

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -rf dist
