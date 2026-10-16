#!/bin/sh
# Installs a signed vigil release.
#
#   curl -fsSLO https://github.com/akquisio-dev/vigil/releases/latest/download/install.sh
#   less install.sh                 # read it first
#   sh install.sh agent             # or: sh install.sh server
#   sh install.sh agent -version v0.9.0 -server http://10.0.0.1:8471 -token vgl_...
#
# The binary is checked against SHA256SUMS, and SHA256SUMS against its
# Sigstore signature made by the release workflow of akquisio-dev/vigil.
# Without cosign (https://docs.sigstore.dev/cosign/system_config/installation/)
# the script stops, unless VIGIL_INSECURE_NO_SIGNATURE=1 is set.
set -eu

REPO=akquisio-dev/vigil
WHAT=${1:-}
[ "$WHAT" = agent ] || [ "$WHAT" = server ] || { echo "usage: sh install.sh agent|server [-version vX.Y.Z] [-server URL -token TOKEN]"; exit 2; }
shift
VERSION="" SERVER="" TOKEN=""
while [ $# -gt 0 ]; do
  case "$1" in
    -version) VERSION=$2; shift 2 ;;
    -server) SERVER=$2; shift 2 ;;
    -token) TOKEN=$2; shift 2 ;;
    *) echo "unknown option $1"; exit 2 ;;
  esac
done
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
case "$(uname -m)" in
  x86_64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "unsupported architecture $(uname -m)"; exit 1 ;;
esac
if [ -z "$VERSION" ]; then
  VERSION=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest" | sed 's#.*/tag/##')
fi
BASE="https://github.com/$REPO/releases/download/$VERSION"
BIN="vigil-${WHAT}_${VERSION}_linux_${ARCH}"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
cd "$TMP"
echo "vigil $WHAT $VERSION ($ARCH)"
for f in "$BIN" SHA256SUMS SHA256SUMS.sigstore.json "vigil-$WHAT.service"; do
  curl -fsSLO "$BASE/$f"
done

if command -v cosign >/dev/null 2>&1; then
  cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
    --certificate-identity "https://github.com/$REPO/.github/workflows/release.yml@refs/tags/$VERSION" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
elif [ "${VIGIL_INSECURE_NO_SIGNATURE:-}" = 1 ]; then
  echo "WARNING: signature not checked (no cosign)"
else
  echo "cosign is needed to check the release signature."
  echo "Install it, or set VIGIL_INSECURE_NO_SIGNATURE=1 to rely on the checksum alone."
  exit 1
fi
grep " $BIN\$" SHA256SUMS | sha256sum -c -
grep " vigil-$WHAT.service\$" SHA256SUMS | sha256sum -c -

install -m 0755 "$BIN" "/usr/local/bin/vigil-$WHAT"
install -m 0644 "vigil-$WHAT.service" "/etc/systemd/system/vigil-$WHAT.service"
install -d -m 0750 /etc/vigil
if [ "$WHAT" = server ]; then
  getent passwd vigil >/dev/null || useradd --system --home-dir /var/lib/vigil --shell /usr/sbin/nologin vigil
  chgrp vigil /etc/vigil
fi
systemctl daemon-reload
echo "installed /usr/local/bin/vigil-$WHAT $(/usr/local/bin/vigil-$WHAT version)"

if [ "$WHAT" = agent ] && [ -n "$SERVER" ] && [ -n "$TOKEN" ]; then
  install -d -m 0700 /var/lib/vigil-agent
  [ -f /etc/vigil/agent.json ] || printf '{\n  "server": "%s",\n  "state_dir": "/var/lib/vigil-agent",\n  "canary_roots": []\n}\n' "$SERVER" > /etc/vigil/agent.json
  /usr/local/bin/vigil-agent enroll -config /etc/vigil/agent.json -server "$SERVER" -token "$TOKEN"
  systemctl enable --now vigil-agent
  echo "agent enrolled and started"
else
  echo "next: write /etc/vigil/$WHAT.json (see https://akquisio-dev.github.io/vigil/configuration/) and run: systemctl enable --now vigil-$WHAT"
fi
