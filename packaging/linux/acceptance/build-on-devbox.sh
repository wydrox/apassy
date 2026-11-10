#!/usr/bin/env bash
# Build and package a commit like the CI linux-vault job, on a devbox, in a
# disposable container (same Ubuntu 24.04 base, apt packages, Rust 1.97.0,
# features, debug build stripped before packaging). Run on the Mac:
#
#   packaging/linux/acceptance/build-on-devbox.sh x86|arm [COMMIT] [--test]
#
# The source is the committed tree (git archive), so uncommitted edits are never
# packaged. Artifacts land in ~/work/l4/artifacts/build-<arch>-<short> on the devbox.
# --test also runs the CI Linux browser/passkey test filter in the same container.
set -euo pipefail
fail() { printf 'build-on-devbox.sh: %s\n' "$*" >&2; exit 1; }
box=${1:?usage: build-on-devbox.sh x86|arm [COMMIT] [--test]}
commit=$(git rev-parse "${2:-HEAD}")
run_tests=0
[ "${3:-}" = --test ] && run_tests=1
case "$box" in x86) arch=x86_64 ;; arm) arch=aarch64 ;; *) fail 'box must be x86 or arm' ;; esac
host="dev@devbox-$box"
short=${commit:0:8}
epoch=$(git log -1 --format=%ct "$commit")
remote="work/l4/src-$short"
ssh "$host" "rm -rf ~/$remote && mkdir -p ~/$remote ~/work/l4/artifacts"
git archive --format=tar "$commit" | ssh "$host" "tar -x -C ~/$remote"
# shellcheck disable=SC2087
ssh "$host" bash -s <<REMOTE
set -euo pipefail
cd ~/$remote
out=~/work/l4/artifacts/build-$arch-$short
rm -rf "\$out" && mkdir -p "\$out"
docker run --rm --name l4-build-$short --memory ${L4_MEM:-4500m} --memory-swap ${L4_MEM:-4500m} \
  -v "\$PWD:/src" -v "\$out:/out" -v l4-target:/src/target -v l4-cargo:/root/.cargo \
  -e APASSY_RELEASE_COMMIT=$commit -e SOURCE_DATE_EPOCH=$epoch -e CARGO_INCREMENTAL=0 \
  -e CARGO_BUILD_JOBS=${L4_JOBS:-2} -e RUN_TESTS=$run_tests -w /src ubuntu:24.04 bash -euo pipefail -c '
    export DEBIAN_FRONTEND=noninteractive PATH=/root/.cargo/bin:\$PATH
    test "\$(uname -m)" = $arch
    apt-get update -q >/dev/null
    apt-get install -y -q --no-install-recommends ca-certificates curl build-essential git python3 file \
      pkg-config libssl-dev libxkbcommon-dev libwayland-dev libx11-dev libegl1-mesa-dev libgl1-mesa-dev shellcheck >/dev/null
    if ! command -v rustup >/dev/null; then
      curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain none >/dev/null
    fi
    rustup toolchain install 1.97.0 --profile minimal >/dev/null
    cargo fetch --locked
    if [ "\$RUN_TESTS" = 1 ]; then
      command -v cargo-nextest >/dev/null || bash scripts/ci-install-nextest.sh
      cargo nextest run --offline --locked -p apassy --all-features --lib --test it \
        -E "test(/^browser::/) | test(/^browser_passkeys::/) | test(/^passkeys::/) | test(/^native::linux::/)"
    fi
    cargo build --offline --locked -p apassy-app -p apassy \
      --features apassy-app/window,apassy-app/node,apassy-app/owner --bin apassy-app --bin apassy-browser-host
    install -d /tmp/bin
    cp target/debug/apassy-app target/debug/apassy-browser-host /tmp/bin/
    strip /tmp/bin/apassy-app /tmp/bin/apassy-browser-host
    shellcheck packaging/linux/build-vault.sh packaging/linux/install-vault.sh packaging/linux/verify-vault.sh
    if [ -d packaging/linux/acceptance ]; then shellcheck -x packaging/linux/acceptance/*.sh packaging/linux/acceptance/lib/*.sh; fi
    packaging/linux/build-vault.sh --binary /tmp/bin/apassy-app --host /tmp/bin/apassy-browser-host --arch $arch --out /out
  '
ls -la "\$out"
REMOTE
