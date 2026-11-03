#!/bin/bash
# Build the native parts of the iPhone tailnet spike (plan s8 unit T0, ADR 0040). Spike only.
#
#   ios/Spikes/TailnetSpike/scripts/build-spike-libs.sh            # iPhone and Simulator
#   ios/Spikes/TailnetSpike/scripts/build-spike-libs.sh device     # any of: device, sim
#
# It writes, in ios/Spikes/TailnetSpike/out/ (not committed):
#   LibTailscale.xcframework  libtailscale at the pinned commit (tsnet as a Go c-archive), with
#                             the spike's Go hooks (Native/go/apassy_spike.go) added to package main
#   SpikeRust.xcframework     the Rust probe (Native/rust): rustls with a pin over a dialed stream
#   include/tailscale.h       the C header of the pinned commit
#   build-info.json           the pins, the toolchains, and the size and SHA-256 of each archive
#   licenses.csv              each Go module in the archive, its license, and the allow-list verdict
#   go-licenses.csv           the go-licenses report (SPIKE_GO_LICENSES=0 skips it)
#
# The pins are in pins.env. Needs Xcode, go 1.21 or later on PATH (it fetches the pinned
# toolchain), rustup, and python3. Go and Rust builds are heavy: on the shared Mac mini run it
# through ~/.local/bin/heavy-check. It needs about 2 GB in the Go module cache and out/work.
set -euo pipefail

here=$(cd "$(dirname "$0")/.." && pwd)
root=$(cd "$here/../../.." && pwd)
# shellcheck source=../pins.env
. "$here/pins.env"

slices=("$@")
[ ${#slices[@]} -eq 0 ] && slices=(device sim)

out="$here/out"
work="$out/work"
src="$work/libtailscale"
mkdir -p "$out/include" "$work"

say() { echo "build-spike-libs: $*"; }
fail() {
    echo "build-spike-libs: $*" >&2
    exit 1
}
# Every go command runs in the libtailscale checkout (its go.mod selects the module).
gosrc() { (cd "$src" && go "$@"); }

for slice in "${slices[@]}"; do
    case "$slice" in
    device | sim) ;;
    *) fail "unknown slice $slice (device, sim)" ;;
    esac
done

# One toolchain for every go command below, and no edits to go.mod or go.sum.
export GOTOOLCHAIN="$GO_TOOLCHAIN"
export GOFLAGS=-mod=readonly
export GOWORK=off
export CGO_ENABLED=1
export IPHONEOS_DEPLOYMENT_TARGET="$IOS_DEPLOYMENT_TARGET"

# The pinned libtailscale, with only the spike's file added.
if [ ! -d "$src/.git" ]; then
    git clone --quiet "$LIBTAILSCALE_REPO" "$src"
fi
if ! git -C "$src" cat-file -e "$LIBTAILSCALE_COMMIT^{commit}" 2>/dev/null; then
    git -C "$src" fetch --quiet origin
fi
git -C "$src" reset --quiet --hard "$LIBTAILSCALE_COMMIT"
rm -f "$src/apassy_spike.go"
[ "$(git -C "$src" rev-parse HEAD)" = "$LIBTAILSCALE_COMMIT" ] || fail "libtailscale is not at $LIBTAILSCALE_COMMIT"
/usr/bin/grep -qE "^[[:space:]]*tailscale\.com $TAILSCALE_MODULE_VERSION\$" "$src/go.mod" ||
    fail "libtailscale $LIBTAILSCALE_COMMIT does not require tailscale.com $TAILSCALE_MODULE_VERSION"
cp "$here/Native/go/apassy_spike.go" "$src/apassy_spike.go"
cp "$src/tailscale.h" "$out/include/tailscale.h"

go_version=$(gosrc version)
case "$go_version" in
*"$GO_TOOLCHAIN "*) ;;
*) fail "go runs '$go_version', not $GO_TOOLCHAIN" ;;
esac
say "$go_version"

# cgo calls this wrapper as CC: clang of the right SDK for the iPhone or the Simulator.
cat >"$work/cc-ios.sh" <<'EOF'
#!/bin/sh
exec "$SPIKE_CLANG" -arch arm64 -target "$SPIKE_TRIPLE" -isysroot "$SPIKE_SDK" "$@"
EOF
chmod +x "$work/cc-ios.sh"

slice_dir() {
    case "$1" in
    device) echo ios-arm64 ;;
    sim) echo ios-arm64-simulator ;;
    esac
}

# Sets SPIKE_SDK, SPIKE_CLANG, SPIKE_TRIPLE and RUST_TARGET for a slice.
use_slice() {
    local sdk
    case "$1" in
    device)
        sdk=iphoneos
        SPIKE_TRIPLE="arm64-apple-ios$IOS_DEPLOYMENT_TARGET"
        RUST_TARGET=aarch64-apple-ios
        ;;
    sim)
        sdk=iphonesimulator
        SPIKE_TRIPLE="arm64-apple-ios$IOS_DEPLOYMENT_TARGET-simulator"
        RUST_TARGET=aarch64-apple-ios-sim
        ;;
    esac
    SPIKE_SDK=$(xcrun --sdk "$sdk" --show-sdk-path)
    SPIKE_CLANG=$(xcrun --sdk "$sdk" --find clang)
    export SPIKE_SDK SPIKE_CLANG SPIKE_TRIPLE
}

# The Rust probe has its own workspace. Its lockfile starts as a copy of the repository's, so
# rustls, ring and their dependencies resolve to the versions of the vault core.
rust_dir="$here/Native/rust"
[ -f "$rust_dir/Cargo.lock" ] || cp "$root/Cargo.lock" "$rust_dir/Cargo.lock"
export CARGO_TARGET_DIR="$work/rust-target"
# Xcode 27's strip breaks proc macros in release builds (see scripts/screenshots.sh).
export CARGO_PROFILE_RELEASE_BUILD_OVERRIDE_STRIP=false

for slice in "${slices[@]}"; do
    dir=$(slice_dir "$slice")
    use_slice "$slice"
    mkdir -p "$out/$dir"

    say "libtailscale for $dir"
    CC="$work/cc-ios.sh" GOOS=ios GOARCH=arm64 \
        gosrc build -trimpath -buildvcs=false -tags ios -ldflags=-w \
        -buildmode=c-archive -o "$out/$dir/libtailscale.a" .
    rm -f "$out/$dir/libtailscale.h"

    say "Rust probe for $RUST_TARGET"
    # rustup reads rust-toolchain.toml of the repository from the working directory.
    (
        cd "$root"
        rustup target list --installed | /usr/bin/grep -qx "$RUST_TARGET" || rustup target add "$RUST_TARGET"
        cargo build --manifest-path "$rust_dir/Cargo.toml" --release --target "$RUST_TARGET"
    )
    cp "$CARGO_TARGET_DIR/$RUST_TARGET/release/libtailnet_spike_rs.a" "$out/$dir/libtailnet_spike_rs.a"
done

make_xcframework() {
    local name=$1 lib=$2 args=()
    for slice in "${slices[@]}"; do
        args+=(-library "$out/$(slice_dir "$slice")/$lib")
    done
    rm -rf "${out:?}/$name.xcframework"
    xcodebuild -create-xcframework "${args[@]}" -output "$out/$name.xcframework" >/dev/null
    say "$out/$name.xcframework"
}
make_xcframework LibTailscale libtailscale.a
make_xcframework SpikeRust libtailnet_spike_rs.a

# Licenses: the modules that the device archive actually links (go list -deps for GOOS=ios).
use_slice "${slices[0]}"
CC="$work/cc-ios.sh" GOOS=ios GOARCH=arm64 gosrc list -tags ios -deps \
    -f '{{with .Module}}{{.Path}}|{{.Version}}|{{if .Replace}}{{.Replace.Dir}}{{else}}{{.Dir}}{{end}}{{end}}' . |
    /usr/bin/grep -vE '^$' | sort -u >"$work/modules.txt"
license_verdict=PASS
python3 -I "$here/scripts/licenses.py" "$work/modules.txt" "$(gosrc env GOROOT)" "$out/licenses.csv" ||
    license_verdict=FAIL

if [ "${SPIKE_GO_LICENSES:-1}" = 1 ]; then
    say "go-licenses report"
    if GOFLAGS= GOOS= GOARCH= CGO_ENABLED=0 GOBIN="$work/bin" go install "$GO_LICENSES_MODULE" &&
        (cd "$src" && CC="$work/cc-ios.sh" GOOS=ios GOARCH=arm64 "$work/bin/go-licenses" report \
            --ignore github.com/tailscale/libtailscale . >"$out/go-licenses.csv" 2>"$work/go-licenses.log"); then
        say "$out/go-licenses.csv"
    else
        say "go-licenses did not finish (see $work/go-licenses.log); licenses.csv is the check"
    fi
fi

rustc_version=$(cd "$root" && rustc --version)
python3 -I - "$out" "$here/pins.env" "$go_version" "$rustc_version" "$license_verdict" "${slices[*]}" <<'PY'
import hashlib
import json
import os
import sys
import time

out, pins_path, go_version, rustc_version, licenses, slices = sys.argv[1:7]
pins = {}
with open(pins_path, encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            pins[key] = value
archives = []
for slice_dir in sorted(os.listdir(out)):
    for name in ("libtailscale.a", "libtailnet_spike_rs.a"):
        path = os.path.join(out, slice_dir, name)
        if os.path.isfile(path):
            with open(path, "rb") as f:
                digest = hashlib.sha256(f.read()).hexdigest()
            archives.append({"slice": slice_dir, "name": name, "bytes": os.path.getsize(path), "sha256": digest})
info = {
    "built": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    "slices": slices.split(),
    "pins": pins,
    "go": go_version,
    "rustc": rustc_version,
    "licenses": licenses,
    "archives": archives,
}
with open(os.path.join(out, "build-info.json"), "w", encoding="utf-8") as f:
    json.dump(info, f, indent=2)
for a in archives:
    print(f"build-spike-libs: {a['slice']}/{a['name']}: {a['bytes'] / 1e6:.1f} MB, sha256 {a['sha256']}")
print(f"build-spike-libs: licenses {licenses}")
PY
say "done ($out/build-info.json)"
