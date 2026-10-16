#!/bin/sh
# Packs the binaries of one architecture as Debian packages. Called by build.sh.
set -eu
VERSION=$1 ARCH=$2
V=${VERSION#v}
cd "$(dirname "$0")/../.."
for cmd in vigil-agent vigil-server; do
  root=$(mktemp -d)
  chmod 0755 "$root"
  mkdir -p "$root/DEBIAN" "$root/usr/bin" "$root/lib/systemd/system" "$root/usr/share/doc/$cmd"
  install -m 0755 "dist/${cmd}_${VERSION}_linux_${ARCH}" "$root/usr/bin/$cmd"
  sed 's#/usr/local/bin/#/usr/bin/#' "deploy/systemd/$cmd.service" > "$root/lib/systemd/system/$cmd.service"
  example=agent.json
  [ "$cmd" = vigil-server ] && example=server.json
  install -m 0644 "deploy/examples/$example" "$root/usr/share/doc/$cmd/$example.example"
  install -m 0644 LICENSE "$root/usr/share/doc/$cmd/copyright"
  desc="vigil host sensor (agent)"
  [ "$cmd" = vigil-server ] && desc="vigil central server and dashboard"
  cat > "$root/DEBIAN/control" <<CTRL
Package: $cmd
Version: $V
Architecture: $ARCH
Maintainer: vigil <noreply@akquisio.eu>
Section: admin
Priority: optional
Homepage: https://github.com/akquisio-dev/vigil
Description: $desc
 A small security operations center for small server fleets.
 Configure /etc/vigil and enable the systemd unit after installing.
CTRL
  if [ "$cmd" = vigil-server ]; then
    cat > "$root/DEBIAN/postinst" <<'POST'
#!/bin/sh
set -e
getent passwd vigil >/dev/null || useradd --system --home-dir /var/lib/vigil --shell /usr/sbin/nologin vigil
systemctl daemon-reload >/dev/null 2>&1 || true
POST
  else
    printf '#!/bin/sh\nset -e\nsystemctl daemon-reload >/dev/null 2>&1 || true\n' > "$root/DEBIAN/postinst"
  fi
  chmod 0755 "$root/DEBIAN/postinst"
  # fixed timestamps so the package is reproducible
  find "$root" -exec touch -h -d "@0" {} +
  SOURCE_DATE_EPOCH=0 dpkg-deb --root-owner-group -Zxz --build "$root" "dist/${cmd}_${V}_${ARCH}.deb" >/dev/null
  rm -rf "$root"
done
