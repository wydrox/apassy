#!/bin/bash
# Build the vault core of the iPhone app (ios/ApassyCore, contract ios-core-v1) as
# ios/ApassyCore/build/ApassyCore.xcframework, for the Swift package ios/ApassyVaultKit.
#
#   scripts/build-ios-core.sh                # iPhone, Simulator, macOS, Apple Watch, watch Simulator
#   scripts/build-ios-core.sh device watch   # iPhone and Apple Watch, for an archive
#   scripts/build-ios-core.sh sim mac        # any of: device, sim, mac, watch, watchsim
#
# The mac slice also builds build/questions-macs (two fake Macs on a fake relay) for swift test.
# The watch slices (ADR 0039) build without default features: SQLCipher uses CommonCrypto,
# because OpenSSL cannot be configured for watchOS.
# APASSY_CORE_PROFILE=dev builds without optimizations (faster, larger).
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

profile=${APASSY_CORE_PROFILE:-release}
dir=$([ "$profile" = dev ] && echo debug || echo "$profile")
export IPHONEOS_DEPLOYMENT_TARGET=26.0
export MACOSX_DEPLOYMENT_TARGET=15.0
export WATCHOS_DEPLOYMENT_TARGET=27.0

slices=("$@")
[ ${#slices[@]} -eq 0 ] && slices=(device sim mac watch watchsim)

target_dir=$(cargo metadata --format-version 1 --no-deps |
    python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')
headers="$root/ios/ApassyCore/include"
out="$root/ios/ApassyCore/build"
args=()
for slice in "${slices[@]}"; do
    features=()
    case "$slice" in
    device) target=aarch64-apple-ios ;;
    sim) target=aarch64-apple-ios-sim ;;
    mac) target=aarch64-apple-darwin ;;
    watch)
        target=aarch64-apple-watchos
        features=(--no-default-features)
        ;;
    watchsim)
        target=aarch64-apple-watchos-sim
        features=(--no-default-features)
        ;;
    *)
        echo "build-ios-core: unknown slice $slice (device, sim, mac, watch, watchsim)" >&2
        exit 2
        ;;
    esac
    rustup target list --installed | grep -qx "$target" || rustup target add "$target"
    cargo build -p apassy-core --profile "$profile" --target "$target" ${features[@]+"${features[@]}"}
    lib="$target_dir/$target/$dir/libapassy_core.a"
    mkdir -p "$out/$target"
    # Keep the linker input intact. Apple strip (even -S) removes LLVM's .llvm.*
    # suffixes from private externs. Distinct optimized Rust functions then share
    # a name and ld can coalesce incompatible calling conventions, crashing in
    # e.g. io::Error drop glue during a join/sync. Xcode strips the final app.
    cp "$lib" "$out/$target/libapassy_core.a"
    args+=(-library "$out/$target/libapassy_core.a" -headers "$headers")
    if [ "$slice" = mac ]; then
        cargo build -p apassy-core --profile "$profile" --target "$target" --example questions_macs
        cp "$target_dir/$target/$dir/examples/questions_macs" "$out/questions-macs"
    fi
done

rm -rf "$out/ApassyCore.xcframework"
xcodebuild -create-xcframework "${args[@]}" -output "$out/ApassyCore.xcframework" >/dev/null
echo "build-ios-core: $out/ApassyCore.xcframework (${slices[*]}, $profile)"
