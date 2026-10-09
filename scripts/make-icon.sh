#!/bin/bash
# Render packaging/AppIcon.icns from packaging/AppIcon.svg.
#
# scripts/build-app.sh copies AppIcon.icns into Apassy.app, ApassyNotify.app
# (the icon of the notifications), and ApassyKeychain.app (the icon of its
# Touch ID prompt). Run this script after a change to AppIcon.svg, and commit
# both files. It uses macOS AppKit through Swift, sips, and iconutil.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SVG="$ROOT/packaging/AppIcon.svg"
ICNS="$ROOT/packaging/AppIcon.icns"

fail() { printf 'make-icon: FAILED: %s\n' "$*" >&2; exit 1; }
[ "$(uname -s)" = "Darwin" ] || fail "this script runs on macOS only"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/apassy-icon.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

# Quick Look thumbnails flatten transparent SVG margins onto white. Render
# directly into a transparent AppKit bitmap so Finder does not add a white tile.
BASE="$TMP/AppIcon.png"
cat >"$TMP/render.swift" <<'SWIFT'
import AppKit
let source = URL(fileURLWithPath: CommandLine.arguments[1])
let destination = URL(fileURLWithPath: CommandLine.arguments[2])
guard let image = NSImage(contentsOf: source),
      let bitmap = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: 1024,
        pixelsHigh: 1024, bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true,
        isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0),
      let context = NSGraphicsContext(bitmapImageRep: bitmap) else {
    fatalError("Cannot create the icon bitmap")
}
NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = context
context.cgContext.clear(CGRect(x: 0, y: 0, width: 1024, height: 1024))
image.draw(in: NSRect(x: 0, y: 0, width: 1024, height: 1024))
NSGraphicsContext.restoreGraphicsState()
guard bitmap.colorAt(x: 0, y: 0)?.alphaComponent == 0 else {
    fatalError("The icon margin must be transparent")
}
try bitmap.representation(using: .png, properties: [:])!.write(to: destination)
SWIFT
swift "$TMP/render.swift" "$SVG" "$BASE" || fail "AppKit cannot render $SVG"
[ -f "$BASE" ] || fail "AppKit wrote no image"
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
