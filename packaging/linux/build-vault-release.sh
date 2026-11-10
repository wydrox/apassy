#!/usr/bin/env bash
# Build the Linux vault packages as a release publishes them (ADR 0045, unit L6).
#
# Usage: packaging/linux/build-vault-release.sh --arch x86_64|aarch64 --out DIR
#
# Run it in the Debian 11 (bullseye, glibc 2.31) Rust image, as the node packages are
# built: `rust:1.97.0-bullseye`, on a machine of the architecture. The binaries then
# need no GLIBC symbol newer than 2.31 and run on Debian 12 and 13 and Ubuntu 22.04 and
# 24.04 (docs/reviews/linux-acceptance-2026-11.md, "Release packages"). It
#
#   1. builds `apassy-app` (window, node, owner) and `apassy-browser-host` with
#      `cargo build --release --locked`;
#   2. strips both and packages them with build-vault.sh --max-glibc 2.31, which refuses
#      a newer GLIBC symbol version, an unaccounted shared library, and a version other
#      than the shared release version;
#   3. refuses a package larger than 25 MiB, the largest file that the relay Worker
#      serves from /dl/ (Workers static assets);
#   4. writes into DIR, next to the packages: file-<arch>.txt, ldd-<arch>.txt and
#      glibc-symbols-<arch>.txt (readelf --version-info) of both binaries.
#
# The source commit is APASSY_RELEASE_COMMIT, else HEAD; it must be the checked-out
# commit, never a pull request's merge commit. CARGO_BUILD_JOBS limits the jobs.
set -euo pipefail
fail() { printf 'build-vault-release.sh: %s\n' "$*" >&2; exit 1; }
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$here/../.." && pwd)
arch='' out=''
while [ "$#" -gt 0 ]; do
    case "$1" in
        --arch) arch=${2:?}; shift 2 ;;
        --out) out=${2:?}; shift 2 ;;
        *) fail "unknown argument: $1" ;;
    esac
done
[ -n "$arch" ] && [ -n "$out" ] || fail 'usage: build-vault-release.sh --arch x86_64|aarch64 --out DIR'
case "$arch" in x86_64 | aarch64) ;; *) fail "unsupported architecture: $arch" ;; esac
[ "$(uname -m)" = "$arch" ] || fail "this machine is $(uname -m), not $arch"
# The baseline: the C library this build links against. A newer one would let the
# linker pick newer symbol versions; build-vault.sh would then refuse the binaries.
baseline=2.31
libc=$(getconf GNU_LIBC_VERSION 2>/dev/null | awk '{print $2}')
[ "$libc" = "$baseline" ] || fail "build on glibc $baseline (rust:1.97.0-bullseye), not ${libc:-an unknown C library}"
commit=${APASSY_RELEASE_COMMIT:-$(git -C "$root" rev-parse HEAD)}
[ "$commit" = "$(git -C "$root" rev-parse HEAD)" ] ||
    fail "APASSY_RELEASE_COMMIT $commit is not the checked-out commit $(git -C "$root" rev-parse HEAD)"
export APASSY_RELEASE_COMMIT=$commit
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$root" log -1 --format=%ct "$commit")}
export SOURCE_DATE_EPOCH

cd "$root"
cargo build --release --locked -p apassy-app -p apassy \
    --features apassy-app/window,apassy-app/node,apassy-app/owner \
    --bin apassy-app --bin apassy-browser-host
mkdir -p "$out"
out=$(cd "$out" && pwd)
bin=$(mktemp -d "${TMPDIR:-/tmp}/apassy-vault-release.XXXXXXXX")
trap 'rm -rf "$bin"' EXIT
install -m 0755 target/release/apassy-app "$bin/apassy"
install -m 0755 target/release/apassy-browser-host "$bin/apassy-browser-host"
strip "$bin/apassy" "$bin/apassy-browser-host"
for executable in "$bin/apassy" "$bin/apassy-browser-host"; do
    name=${executable##*/}
    file "$executable" | sed "s|$bin/||" >> "$out/file-$arch.txt"
    { echo "== $name"; ldd "$executable"; } >> "$out/ldd-$arch.txt"
    { echo "== $name"; readelf --version-info "$executable"; } >> "$out/glibc-symbols-$arch.txt"
done
"$here/build-vault.sh" --binary "$bin/apassy" --host "$bin/apassy-browser-host" \
    --arch "$arch" --out "$out" --max-glibc "$baseline"
# Workers static assets serve files up to 25 MiB; /dl/ of the relay Worker is one.
limit=$((25 * 1024 * 1024))
while read -r _ name; do
    size=$(stat -c %s "$out/$name")
    [ "$size" -le "$limit" ] || fail "$name is $size bytes, more than the 25 MiB that /dl/ can serve"
    printf '%s %s bytes\n' "$name" "$size"
done < "$out/SHA256SUMS-vault-$arch"
