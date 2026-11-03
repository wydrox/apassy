#!/usr/bin/env bash
# Installs the Go of ../pins.env into DEST/go and prints DEST/go/bin on stdout
# (for "$GITHUB_PATH"). The archive comes from go.dev and must match the pinned
# SHA-256; anything else stops here. Everything except the bin path goes to stderr.
#
#   crates/apassy-tailnet/scripts/install-go.sh "$RUNNER_TEMP/go-toolchain" >> "$GITHUB_PATH"
set -euo pipefail

dest="${1:?usage: install-go.sh DEST}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
pin() { sed -n "s/^$1=//p" "$here/../pins.env" | head -n 1; }

version="$(pin GO_VERSION)"
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) platform=darwin-arm64; sha="$(pin GO_SHA256_DARWIN_ARM64)" ;;
  Linux-x86_64) platform=linux-amd64; sha="$(pin GO_SHA256_LINUX_AMD64)" ;;
  Linux-aarch64) platform=linux-arm64; sha="$(pin GO_SHA256_LINUX_ARM64)" ;;
  *) echo "install-go.sh: no pinned Go for $(uname -s) $(uname -m)" >&2; exit 1 ;;
esac
[ -n "$version" ] && [ -n "$sha" ] || { echo "install-go.sh: pins.env is incomplete" >&2; exit 1; }

file="go${version}.${platform}.tar.gz"
mkdir -p "$dest"
download="$(mktemp -d "${TMPDIR:-/tmp}/go-download.XXXXXX")"
trap 'rm -rf "$download"' EXIT
curl --fail --location --silent --show-error --retry 3 "https://go.dev/dl/$file" -o "$download/$file"
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$download/$file" | awk '{print $1}')"
else
  actual="$(shasum -a 256 "$download/$file" | awk '{print $1}')"
fi
if [ "$actual" != "$sha" ]; then
  echo "install-go.sh: $file has SHA-256 $actual, pinned $sha" >&2
  exit 1
fi
rm -rf "$dest/go"
tar -xzf "$download/$file" -C "$dest"
got="$("$dest/go/bin/go" env GOVERSION)"
[ "$got" = "go$version" ] || { echo "install-go.sh: installed $got, pinned go$version" >&2; exit 1; }
echo "install-go.sh: $got ($platform, SHA-256 $sha) in $dest/go" >&2
echo "$dest/go/bin"
