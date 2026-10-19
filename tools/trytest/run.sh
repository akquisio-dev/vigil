#!/bin/sh
# Runs the trial install (install.sh try-setup) with the binaries in dist/,
# triggers one finding and takes the trial out again. For CI: it installs
# into /usr/local/bin and /etc/systemd/system of the machine it runs on.
set -eu
cd "$(dirname "$0")/../.."
[ -x dist/vigil-server ] && [ -x dist/vigil-agent ] || { echo "run make build first"; exit 1; }

fail() {
  echo "::error title=trial install::$1"
  sudo journalctl -u vigil-server -u vigil-agent --no-pager -n 80 || true
  exit 1
}

sudo install -m 0755 dist/vigil-server dist/vigil-agent /usr/local/bin/
sudo install -m 0644 deploy/systemd/vigil-* /etc/systemd/system/
sudo systemctl daemon-reload
printf 'a-trial-password\n' | sudo VIGIL_TRY_USER=ci sh deploy/install.sh try-setup

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
curl -fsS -o /dev/null http://127.0.0.1:8470/ || fail "dashboard not reachable"

sudo sh deploy/install.sh try-remove
for p in /etc/vigil /var/lib/vigil /var/lib/vigil-agent; do
  [ ! -e "$p" ] || fail "$p left behind"
done
for u in vigil-server vigil-agent; do
  ! systemctl is-active --quiet $u || fail "$u still running"
done
# A second removal finds nothing to remove and says so.
if sudo sh deploy/install.sh try-remove; then fail "try-remove ran without a trial"; fi
echo "trial install ok"
