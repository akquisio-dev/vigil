VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
PKG := github.com/akquisio-dev/vigil/internal
# Same flags as deploy/release/build.sh, so a local build of a tag matches the release.
LDFLAGS := -s -w -buildid= -X $(PKG)/agent.Version=$(VERSION) -X $(PKG)/server.Version=$(VERSION)

.PHONY: build test vet clean release
build:
	CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags '$(LDFLAGS)' -o dist/ ./cmd/...

release:
	deploy/release/build.sh $(VERSION)

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -rf dist
