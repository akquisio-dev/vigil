#!/bin/sh
# Builds the release binaries and Debian packages for one version into dist/.
# CI runs exactly this, so anyone can rebuild a tag and compare checksums:
#
#   git checkout v0.9.0 && deploy/release/build.sh v0.9.0 && cat dist/SHA256SUMS
#
# Requires the Go toolchain named in go.mod and dpkg-deb.
set -eu
VERSION=${1:?usage: build.sh VERSION}
cd "$(dirname "$0")/../.."
GOVERSION=$(sed -n 's/^toolchain //p' go.mod)
[ "$(go env GOVERSION)" = "$GOVERSION" ] || { echo "need $GOVERSION, have $(go env GOVERSION) (try GOTOOLCHAIN=$GOVERSION)"; exit 1; }
rm -rf dist && mkdir dist
PKG=github.com/akquisio-dev/vigil/internal
LDFLAGS="-s -w -buildid= -X $PKG/agent.Version=$VERSION -X $PKG/server.Version=$VERSION"
for arch in amd64 arm64; do
  for cmd in vigil-agent vigil-server; do
    CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -buildvcs=false -ldflags "$LDFLAGS" \
      -o "dist/${cmd}_${VERSION}_linux_${arch}" "./cmd/$cmd"
  done
  deploy/release/deb.sh "$VERSION" "$arch"
done
cp deploy/systemd/vigil-agent.service deploy/systemd/vigil-server.service deploy/install.sh dist/
(cd dist && sha256sum -- * > SHA256SUMS)
cat dist/SHA256SUMS
