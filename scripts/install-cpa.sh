#!/bin/sh
set -eu

scripts=$(dirname "$0")
version=$(cat "$scripts/../.cpa-version")
destination=${1:?usage: scripts/install-cpa.sh <directory>}

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) asset=darwin_aarch64 ;;
  Linux-x86_64) asset=linux_amd64 ;;
  Linux-aarch64) asset=linux_aarch64 ;;
  *) echo "install-cpa: no CLIProxyAPI build for $(uname -s) $(uname -m)" >&2; exit 1 ;;
esac

archive="CLIProxyAPI_${version}_$asset.tar.gz"
download=${CPA_DOWNLOADS:-$(mktemp -d)}
mkdir -p "$download"

if [ ! -f "$download/$archive" ]; then
  curl -fsSL "https://github.com/router-for-me/CLIProxyAPI/releases/download/v$version/$archive" -o "$download/$archive.partial"
  mv "$download/$archive.partial" "$download/$archive"
fi

if ! grep "  $archive\$" "$scripts/cpa.sha256" > "$download/expected"; then
  echo "install-cpa: scripts/cpa.sha256 has no checksum for $archive" >&2
  exit 1
fi

if command -v sha256sum > /dev/null; then
  (cd "$download" && sha256sum -c --quiet expected)
else
  (cd "$download" && shasum -a 256 -c --quiet expected)
fi

mkdir -p "$destination"
tar -xzf "$download/$archive" -C "$destination" cli-proxy-api
echo "$destination/cli-proxy-api"
