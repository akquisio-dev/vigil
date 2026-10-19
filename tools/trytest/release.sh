#!/bin/sh
# Installs server and agent of a published release with install.sh from this
# tree, through the cosign and checksum checks, and removes them again. For
# CI: it installs into /usr/local/bin and /etc/systemd/system.
set -eu
cd "$(dirname "$0")/../.."
v=${1:?release, e.g. v0.22.0}
for w in server agent; do
  # sudo resets PATH; cosign is in the runner's.
  sudo env PATH="$PATH" sh deploy/install.sh $w -version "$v"
  got=$(/usr/local/bin/vigil-$w version)
  [ "$got" = "$v" ] || { echo "::error title=install.sh::vigil-$w reports $got, not $v"; exit 1; }
done
sudo rm -rf /usr/local/bin/vigil-server /usr/local/bin/vigil-agent /etc/systemd/system/vigil-* /etc/vigil
sudo systemctl daemon-reload
echo "release install ok"
