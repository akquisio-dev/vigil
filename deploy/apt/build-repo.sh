#!/bin/sh
# Builds the apt repository from the Debian packages of the newest releases.
# The pages workflow runs it; it needs gh, Go, apt-ftparchive and gpg with
# the signing key imported.
#
#   deploy/apt/build-repo.sh OUTDIR
#
# Every package is taken only after the release's SHA256SUMS passed the same
# signature check agents use (tools/verifysums), so the apt key vouches for
# nothing the release workflow did not build.
set -eu
OUT=${1:?usage: build-repo.sh OUTDIR}
KEEP=${KEEP:-5}
REPO=${GITHUB_REPOSITORY:-akquisio-dev/vigil}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
KEYRING=${KEYRING:-"$ROOT/deploy/apt/vigil-archive-keyring.asc"}

# The secret key must belong to the public key in the repository.
WANT=$(gpg --batch --with-colons --show-keys "$KEYRING" | awk -F: '/^fpr/{print $10; exit}')
gpg --batch --with-colons --list-secret-keys "$WANT" >/dev/null 2>&1 || { echo "signing key $WANT is not imported"; exit 1; }

mkdir -p "$OUT/pool/main"
OUT=$(cd "$OUT" && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
for tag in $(gh release list -R "$REPO" -L "$KEEP" --exclude-drafts --exclude-pre-releases --json tagName -q '.[].tagName'); do
  d="$TMP/$tag"
  mkdir -p "$d"
  gh release download "$tag" -R "$REPO" -D "$d" -p 'SHA256SUMS' -p 'SHA256SUMS.sigstore.json' -p '*.deb'
  (cd "$ROOT" && go run ./tools/verifysums "$d/SHA256SUMS" "$d/SHA256SUMS.sigstore.json" "$tag")
  (cd "$d" && grep '\.deb$' SHA256SUMS | sha256sum -c -)
  mv "$d"/*.deb "$OUT/pool/main/"
done

cd "$OUT"
for arch in amd64 arm64; do
  mkdir -p "dists/stable/main/binary-$arch"
  apt-ftparchive --arch "$arch" packages pool > "dists/stable/main/binary-$arch/Packages"
  gzip -9nkf "dists/stable/main/binary-$arch/Packages"
done
apt-ftparchive \
  -o APT::FTPArchive::Release::Origin=vigil \
  -o APT::FTPArchive::Release::Label=vigil \
  -o APT::FTPArchive::Release::Suite=stable \
  -o APT::FTPArchive::Release::Codename=stable \
  -o APT::FTPArchive::Release::Architectures="amd64 arm64" \
  -o APT::FTPArchive::Release::Components=main \
  -o APT::FTPArchive::Release::Description="vigil releases" \
  release dists/stable > "$TMP/Release"
mv "$TMP/Release" dists/stable/Release
gpg --batch --yes -u "$WANT" --armor --detach-sign -o dists/stable/Release.gpg dists/stable/Release
gpg --batch --yes -u "$WANT" --clearsign -o dists/stable/InRelease dists/stable/Release
gpg --batch --yes --export "$WANT" > vigil-archive-keyring.gpg
cp "$KEYRING" vigil-archive-keyring.asc
echo "apt repository with $(ls pool/main | wc -l) packages, signed by $WANT"
