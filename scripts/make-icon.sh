#!/bin/bash
# Render packaging/AppIcon.icns from packaging/AppIcon.svg.
#
# scripts/build-app.sh copies AppIcon.icns into Apassy.app, ApassyNotify.app
# (the icon of the notifications), and ApassyKeychain.app (the icon of its
# Touch ID prompt). Run this script after a change to AppIcon.svg, and commit
# both files. It uses only tools of macOS: qlmanage, sips, and iconutil.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SVG="$ROOT/packaging/AppIcon.svg"
ICNS="$ROOT/packaging/AppIcon.icns"

fail() { printf 'make-icon: FAILED: %s\n' "$*" >&2; exit 1; }
[ "$(uname -s)" = "Darwin" ] || fail "this script runs on macOS only"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/apassy-icon.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

# Quick Look renders SVG with WebKit. The output keeps the alpha channel.
qlmanage -t -s 1024 -o "$TMP" "$SVG" >/dev/null 2>&1 || fail "qlmanage cannot render $SVG"
BASE="$TMP/$(basename "$SVG").png"
[ -f "$BASE" ] || fail "qlmanage wrote no image"
[ "$(sips -g pixelWidth "$BASE" | awk '/pixelWidth/ {print $2}')" = "1024" ] || fail "the render is not 1024 pixels wide"

SET="$TMP/AppIcon.iconset"
mkdir -p "$SET"
for size in 16 32 128 256 512; do
  sips -z "$size" "$size" "$BASE" --out "$SET/icon_${size}x${size}.png" >/dev/null
  double=$((size * 2))
  if [ "$double" = "1024" ]; then
    cp "$BASE" "$SET/icon_${size}x${size}@2x.png"
  else
    sips -z "$double" "$double" "$BASE" --out "$SET/icon_${size}x${size}@2x.png" >/dev/null
  fi
done
iconutil -c icns -o "$ICNS" "$SET"
echo "Icon: $ICNS ($(stat -f %z "$ICNS") bytes)"
