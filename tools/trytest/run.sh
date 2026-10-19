#!/bin/sh
# Runs the trial install (install.sh try-setup) with the binaries in dist/,
# triggers one finding and takes the trial out again. With "latest" it runs
# what a new user runs instead: install.sh try of the newest release, with
# its signed binaries (needs cosign). For CI: it installs into /usr/local/bin
# and /etc/systemd/system of the machine it runs on.
#   run.sh [latest]
set -eu
cd "$(dirname "$0")/../.."

fail() {
  echo "::error title=trial install::$1"
  sudo journalctl -u vigil-server -u vigil-agent --no-pager -n 80 || true
  exit 1
}

if [ "${1:-}" = latest ]; then
  inst=$(mktemp -d)/install.sh
  curl -fsSL -o "$inst" https://github.com/akquisio-dev/vigil/releases/latest/download/install.sh
  setup=try
else
  [ -x dist/vigil-server ] && [ -x dist/vigil-agent ] || { echo "run make build first"; exit 1; }
  sudo install -m 0755 dist/vigil-server dist/vigil-agent /usr/local/bin/
  sudo install -m 0644 deploy/systemd/vigil-* /etc/systemd/system/
  sudo systemctl daemon-reload
  inst=deploy/install.sh
  setup=try-setup
fi
# sudo resets PATH; cosign is in the runner's.
try() { printf '%s\n' "$1" | sudo env PATH="$PATH" VIGIL_TRY_USER=ci sh "$inst" $setup; }
# A setup that stops half way (here: a password that is too short) is
# taken out by try-remove and can then run again.
if try short; then fail "accepted a short password"; fi
sudo sh "$inst" try-remove || fail "try-remove after a stopped setup"
try a-trial-password

# The agent reports program starts from /tmp; repeat until it is up.
trigger=$(mktemp -d)/vigil-try
cp /bin/sleep "$trigger"
i=0
until sudo grep -q '"rule":"process.tmp_exec"' /var/lib/vigil/state.json; do
  i=$((i + 1))
  [ $i -le 24 ] || fail "no process.tmp_exec alert after 2 minutes"
  "$trigger" 1
  sleep 4
done
rm -rf "$(dirname "$trigger")"
echo "alert raised"
users=$(mktemp)
sudo cat /var/lib/vigil/users.json > "$users"
python3 -I tools/trytest/login.py "$users" ci a-trial-password process.tmp_exec || fail "the alert is not in the dashboard after logging in"
rm -f "$users"

sudo sh "$inst" try-remove
for p in /etc/vigil /var/lib/vigil /var/lib/vigil-agent $([ $setup = try ] && echo /usr/local/bin/vigil-server /usr/local/bin/vigil-agent); do
  [ ! -e "$p" ] || fail "$p left behind"
done
for u in vigil-server vigil-agent; do
  ! systemctl is-active --quiet $u || fail "$u still running"
done
# A second removal finds nothing to remove and says so.
if sudo sh "$inst" try-remove; then fail "try-remove ran without a trial"; fi
echo "trial install ok"
