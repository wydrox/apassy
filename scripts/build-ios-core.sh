#!/bin/bash
# Build the vault core of the iPhone app (ios/ApassyCore, contract ios-core-v1) as
# ios/ApassyCore/build/ApassyCore.xcframework, for the Swift package ios/ApassyVaultKit.
#
#   scripts/build-ios-core.sh            # iPhone, Simulator, and macOS (for swift test)
#   scripts/build-ios-core.sh device     # iPhone only, for an archive
#   scripts/build-ios-core.sh sim mac    # any of: device, sim, mac
#
# APASSY_CORE_PROFILE=dev builds without optimizations (faster, larger).
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

profile=${APASSY_CORE_PROFILE:-release}
dir=$([ "$profile" = dev ] && echo debug || echo "$profile")
export IPHONEOS_DEPLOYMENT_TARGET=26.0
export MACOSX_DEPLOYMENT_TARGET=15.0

slices=("$@")
[ ${#slices[@]} -eq 0 ] && slices=(device sim mac)

target_dir=$(cargo metadata --format-version 1 --no-deps |
    python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')
headers="$root/ios/ApassyCore/include"
out="$root/ios/ApassyCore/build"
args=()
for slice in "${slices[@]}"; do
    case "$slice" in
    device) target=aarch64-apple-ios ;;
    sim) target=aarch64-apple-ios-sim ;;
    mac) target=aarch64-apple-darwin ;;
    *)
        echo "build-ios-core: unknown slice $slice (device, sim, mac)" >&2
        exit 2
        ;;
    esac
    rustup target list --installed | grep -qx "$target" || rustup target add "$target"
    cargo build -p apassy-core --profile "$profile" --target "$target"
    lib="$target_dir/$target/$dir/libapassy_core.a"
    mkdir -p "$out/$target"
    # No debug symbols in the archive: the app has its own dSYM for Swift.
    strip -S -x -o "$out/$target/libapassy_core.a" "$lib" 2>/dev/null || cp "$lib" "$out/$target/libapassy_core.a"
    args+=(-library "$out/$target/libapassy_core.a" -headers "$headers")
done

rm -rf "$out/ApassyCore.xcframework"
xcodebuild -create-xcframework "${args[@]}" -output "$out/ApassyCore.xcframework" >/dev/null
echo "build-ios-core: $out/ApassyCore.xcframework (${slices[*]}, $profile)"
