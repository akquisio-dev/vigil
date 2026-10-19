#!/bin/sh
# Installs a signed vigil release.
#
#   curl -fsSLO https://github.com/akquisio-dev/vigil/releases/latest/download/install.sh
#   less install.sh                 # read it first
#   sh install.sh agent             # or: sh install.sh server
#   sh install.sh agent -version v0.9.0 -server http://10.0.0.1:8471 -token vgl_...
#
# To look at vigil on one spare machine, without a VPN or a proxy:
#
#   sh install.sh try               # server and agent here, on 127.0.0.1 only
#   sh install.sh try-remove        # takes the trial out again
#
# try-setup does the same as try with binaries and units already installed
# (built from source, or from apt).
#
# The binary is checked against SHA256SUMS, and SHA256SUMS against its
# Sigstore signature made by the release workflow of akquisio-dev/vigil.
# Without cosign (https://docs.sigstore.dev/cosign/system_config/installation/)
# the script stops, unless VIGIL_INSECURE_NO_SIGNATURE=1 is set.
set -eu

REPO=akquisio-dev/vigil
WHAT=${1:-}
case "$WHAT" in
  agent|server|try|try-setup|try-remove) ;;
  *) echo "usage: sh install.sh agent|server [-version vX.Y.Z] [-server URL -token TOKEN]"
     echo "       sh install.sh try [-version vX.Y.Z] | try-setup | try-remove"
     exit 2 ;;
esac
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

# A trial install is marked, so that try-remove never takes out a real one.
TRY=/etc/vigil/.try-install
TRY_USER=${VIGIL_TRY_USER:-admin}

# install_release WHAT downloads the binary and systemd units of WHAT,
# checks them and installs them.
install_release() {
  case "$(uname -m)" in
    x86_64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) echo "unsupported architecture $(uname -m)"; exit 1 ;;
  esac
  if [ -z "$VERSION" ]; then
    VERSION=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest" | sed 's#.*/tag/##')
  fi
  BASE="https://github.com/$REPO/releases/download/$VERSION"
  BIN="vigil-${1}_${VERSION}_linux_${ARCH}"
  TMP=$(mktemp -d)
  trap 'rm -rf "$TMP"' EXIT
  cd "$TMP"
  echo "vigil $1 $VERSION ($ARCH)"
  for f in "$BIN" SHA256SUMS SHA256SUMS.sigstore.json "vigil-$1.service"; do
    curl -fsSLO "$BASE/$f"
  done
  UNITS="vigil-$1.service"
  if [ "$1" = agent ]; then
    # the units for updates from the dashboard, part of releases since v0.19.0
    for u in vigil-agent-update.service vigil-agent-update.path; do
      if curl -fsSLO "$BASE/$u"; then UNITS="$UNITS $u"; fi
    done
  else
    # the units for daily backups, part of releases since v0.20.0
    for u in vigil-server-backup.service vigil-server-backup.timer; do
      if curl -fsSLO "$BASE/$u"; then UNITS="$UNITS $u"; fi
    done
  fi

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
  for u in $UNITS; do
    grep " $u\$" SHA256SUMS | sha256sum -c -
  done

  install -m 0755 "$BIN" "/usr/local/bin/vigil-$1"
  for u in $UNITS; do
    install -m 0644 "$u" "/etc/systemd/system/$u"
  done
  install -d -m 0750 /etc/vigil
  if [ "$1" = server ]; then
    getent passwd vigil >/dev/null || useradd --system --home-dir /var/lib/vigil --shell /usr/sbin/nologin vigil
    chgrp vigil /etc/vigil
  fi
  systemctl daemon-reload
  cd /
  rm -rf "$TMP"
  echo "installed /usr/local/bin/vigil-$1 $(/usr/local/bin/vigil-$1 version)"
}

# try_check stops before a trial would touch an existing installation.
try_check() {
  for p in /etc/vigil/server.json /etc/vigil/agent.json /var/lib/vigil /var/lib/vigil-agent; do
    if [ -e "$p" ]; then
      echo "$p exists: vigil is already set up on this machine. The trial needs a machine without it."
      exit 1
    fi
  done
  for port in 8470 8471; do
    if curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$port/"; then
      echo "port $port on 127.0.0.1 is in use"
      exit 1
    fi
  done
}

# try_setup configures, starts and connects the installed server and agent,
# both on 127.0.0.1.
try_setup() {
  for b in vigil-server vigil-agent; do
    command -v $b >/dev/null || { echo "$b is not installed"; exit 1; }
    systemctl cat $b.service >/dev/null 2>&1 || { echo "the systemd unit $b.service is not installed"; exit 1; }
  done
  getent passwd vigil >/dev/null || useradd --system --home-dir /var/lib/vigil --shell /usr/sbin/nologin vigil
  install -d -m 0750 -g vigil /etc/vigil
  echo "$1" > "$TRY"
  umask 027
  cat > /etc/vigil/server.json <<'EOF'
{
  "listen": "127.0.0.1:8470",
  "agent_listen": "127.0.0.1:8471",
  "data_dir": "/var/lib/vigil",
  "public_url": "http://127.0.0.1:8470",
  "agent_url": "http://127.0.0.1:8471",
  "cookie_secure": false,
  "trust_proxy": false
}
EOF
  chgrp vigil /etc/vigil/server.json
  umask 077
  cat > /etc/vigil/agent.json <<'EOF'
{
  "server": "http://127.0.0.1:8471",
  "state_dir": "/var/lib/vigil-agent",
  "canary_roots": []
}
EOF
  echo
  echo "Dashboard user \"$TRY_USER\": choose a password, then scan the QR code with an authenticator app."
  vigil-server user add -config /etc/vigil/server.json "$TRY_USER"
  token=$(vigil-server token -config /etc/vigil/server.json 2>/dev/null) || { echo "could not create an enrollment token"; exit 1; }
  systemctl enable --now vigil-server
  i=0
  until curl -s -o /dev/null --max-time 2 http://127.0.0.1:8471/; do
    i=$((i + 1))
    [ $i -lt 30 ] || { echo "the server did not start: journalctl -u vigil-server"; exit 1; }
    sleep 1
  done
  install -d -m 0700 /var/lib/vigil-agent
  vigil-agent enroll -config /etc/vigil/agent.json -server http://127.0.0.1:8471 -token "$token"
  systemctl enable --now vigil-agent
  host=$(hostname -f 2>/dev/null || hostname)
  cat <<EOF

vigil runs on this machine, reachable from here only (127.0.0.1).

  Dashboard:  http://127.0.0.1:8470   user $TRY_USER
  From your computer:  ssh -L 8470:127.0.0.1:8470 root@$host
                       then open http://127.0.0.1:8470 there

The first scan is the baseline: what is on the machine now counts as
expected. To see a finding within a minute, run a program from /tmp:

  cp /bin/sleep /tmp/vigil-try && /tmp/vigil-try 5; rm -f /tmp/vigil-try

It shows up under Alerts as "Program started from a temporary directory".

This is a trial layout, not one for production: see
https://akquisio-dev.github.io/vigil/getting-started/ for that.
To take it out again:  sh install.sh try-remove
EOF
}

try_remove() {
  if [ ! -f "$TRY" ]; then
    echo "no trial install here ($TRY is missing); nothing removed"
    exit 1
  fi
  how=$(cat "$TRY")
  for u in vigil-agent.service vigil-agent-update.path vigil-server.service vigil-server-backup.timer; do
    systemctl disable --now "$u" 2>/dev/null || true
  done
  rm -rf /etc/vigil /var/lib/vigil /var/lib/vigil-agent
  if [ "$how" = release ]; then
    rm -f /usr/local/bin/vigil-server /usr/local/bin/vigil-agent
    for u in vigil-server.service vigil-server-backup.service vigil-server-backup.timer \
      vigil-agent.service vigil-agent-update.service vigil-agent-update.path; do
      rm -f "/etc/systemd/system/$u"
    done
    userdel vigil 2>/dev/null || true
  fi
  systemctl daemon-reload
  echo "trial removed"
}

case "$WHAT" in
  try)
    try_check
    for b in /usr/local/bin/vigil-server /usr/local/bin/vigil-agent; do
      [ ! -e "$b" ] || { echo "$b exists: vigil is already installed on this machine"; exit 1; }
    done
    install_release server
    install_release agent
    try_setup release
    exit 0 ;;
  try-setup)
    try_check
    try_setup installed
    exit 0 ;;
  try-remove)
    try_remove
    exit 0 ;;
esac

install_release "$WHAT"
if [ "$WHAT" = agent ] && [ -n "$SERVER" ] && [ -n "$TOKEN" ]; then
  install -d -m 0700 /var/lib/vigil-agent
  [ -f /etc/vigil/agent.json ] || printf '{\n  "server": "%s",\n  "state_dir": "/var/lib/vigil-agent",\n  "canary_roots": []\n}\n' "$SERVER" > /etc/vigil/agent.json
  /usr/local/bin/vigil-agent enroll -config /etc/vigil/agent.json -server "$SERVER" -token "$TOKEN"
  systemctl enable --now vigil-agent
  echo "agent enrolled and started"
  echo "updates from the dashboard: set \"self_update\": true in /etc/vigil/agent.json, then: systemctl enable --now vigil-agent-update.path"
else
  if [ "$WHAT" = server ]; then
    echo "backups: run vigil-server backup keygen -out KEYFILE on another machine, put the public key into server.json, then: systemctl enable --now vigil-server-backup.timer"
  fi
  echo "next: write /etc/vigil/$WHAT.json (see https://akquisio-dev.github.io/vigil/configuration/) and run: systemctl enable --now vigil-$WHAT"
fi
