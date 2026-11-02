#!/usr/bin/env bash
# Install the pinned cargo-nextest release into ~/.cargo/bin for a CI job.
#
# The archive comes from the GitHub release of nextest-rs/nextest. The script checks
# its SHA-256 against the value below before it unpacks it. To update, take the new
# values from the `.sha256` files of the release (they match the asset digests that
# `gh release view cargo-nextest-VERSION -R nextest-rs/nextest --json assets` shows).
set -euo pipefail

VERSION="0.9.150"

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)
    target=x86_64-unknown-linux-gnu
    sha=b0959bc64232974224cf9fb22c915845398c0e8668fa7831eb5b43fb1eef781f
    ;;
  Darwin-arm64 | Darwin-x86_64)
    target=universal-apple-darwin
    sha=82a759b4d218d38359424196ab244c470e8f7c7d149c814fbbeef4d67c3c301a
    ;;
  *)
    echo "::error::No pinned cargo-nextest for $(uname -s) $(uname -m)." >&2
    exit 1
    ;;
esac

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
archive="$work/cargo-nextest.tar.gz"
curl --fail --silent --show-error --location --retry 3 \
  "https://github.com/nextest-rs/nextest/releases/download/cargo-nextest-$VERSION/cargo-nextest-$VERSION-$target.tar.gz" \
  -o "$archive"
printf '%s  %s\n' "$sha" "$archive" | shasum -a 256 -c -
bin="${CARGO_HOME:-$HOME/.cargo}/bin"
mkdir -p "$bin"
tar -xzf "$archive" -C "$work" cargo-nextest
install -m 0755 "$work/cargo-nextest" "$bin/cargo-nextest"
cargo nextest --version | grep -F "cargo-nextest $VERSION"
