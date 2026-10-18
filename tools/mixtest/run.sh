#!/bin/sh
# Runs mixtest against the last release and the last release of the
# previous minor version, both fetched from GitHub and checked like an
# agent checks an update (signed SHA256SUMS, then the hashes).
#
#   tools/mixtest/run.sh [VERSION ...]     (needs sudo, after make build)
set -eu
cd "$(dirname "$0")/../.."
arch=$(go env GOARCH)
here=$(git describe --tags --always)
if [ $# -eq 0 ]; then
  tags=$(git tag --sort=-v:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$')
  exact=$(git describe --tags --exact-match 2>/dev/null || true)
  last=$(echo "$tags" | grep -vxF "${exact:-none}" | head -1)
  minor=$(echo "$here" | sed -E 's/^(v[0-9]+\.[0-9]+)\..*/\1/')
  prev=$(echo "$tags" | grep -v "^$minor\." | head -1)
  set -- $last
  [ -n "$prev" ] && [ "$prev" != "$last" ] && set -- "$@" "$prev"
fi
cache=${MIXTEST_CACHE:-$HOME/.cache/vigil-mixtest}
go build -o "$cache/verifysums" ./tools/verifysums
go build -o "$cache/mixtest" ./tools/mixtest
mkdir -p "$cache/new"
cp dist/vigil-server dist/vigil-agent "$cache/new/"
for v in "$@"; do
  d="$cache/$v"
  if [ ! -x "$d/vigil-agent" ]; then
    rm -rf "$d" && mkdir -p "$d"
    for f in SHA256SUMS SHA256SUMS.sigstore.json "vigil-server_${v}_linux_$arch" "vigil-agent_${v}_linux_$arch"; do
      curl -fsSL --retry 3 -o "$d/$f" "https://github.com/akquisio-dev/vigil/releases/download/$v/$f"
    done
    "$cache/verifysums" "$d/SHA256SUMS" "$d/SHA256SUMS.sigstore.json" "$v"
    (cd "$d" && sha256sum -c SHA256SUMS --ignore-missing)
    for c in vigil-server vigil-agent; do mv "$d/${c}_${v}_linux_$arch" "$d/$c" && chmod 755 "$d/$c"; done
  fi
  echo "== $v against $here"
  sudo ${MIXTEST_WRAP:-} "$cache/mixtest" -old "$d" -new "$cache/new" ${MIXTEST_FLAGS:-}
done
