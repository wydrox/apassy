#!/bin/bash
# Capture the screenshots of the README and the site (docs/images/app-*.png).
#
# The script seeds a vault with synthetic data in a scratch HOME, opens the real
# desktop app for it (examples/screenshots.rs), and captures the window for each view
# with screencapture, without the shadow (the site and the README add their own).
# The owner's vault, settings, and keychain are not used. The app gets its input from
# the example, not from macOS: no Accessibility permission is needed. screencapture
# needs the Screen Recording permission of the terminal.
#
# macOS can refuse to focus the window while you work in another app. An inactive
# window has gray traffic lights; the script then paints them in their active colors,
# so each image looks the same.
#
# Usage: scripts/screenshots.sh [OUT_DIR]   (default: docs/images)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$(cd "$ROOT" && mkdir -p "${1:-docs/images}" && cd "${1:-docs/images}" && pwd)"
cd "$ROOT"

fail() { printf 'screenshots: FAILED: %s\n' "$*" >&2; exit 1; }
[ "$(uname -s)" = "Darwin" ] || fail "this script runs on macOS only"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/apassy-shots.XXXXXX")"
APP_PID=""
cleanup() {
  [ -z "$APP_PID" ] || kill "$APP_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# The window number of a process, for screencapture -l.
cat >"$WORK/winid.swift" <<'EOF'
import CoreGraphics
import Foundation
let pid = Int32(CommandLine.arguments[1])!
let list = CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID) as? [[String: Any]] ?? []
for w in list where (w[kCGWindowOwnerPID as String] as? Int32) == pid && (w[kCGWindowLayer as String] as? Int) == 0 {
  if let n = w[kCGWindowNumber as String] as? Int { print(n); exit(0) }
}
exit(1)
EOF
xcrun swiftc -O -o "$WORK/winid" "$WORK/winid.swift" || fail "cannot build the window helper"

# Paint gray (inactive) traffic lights in their active colors. The lights are 28 px
# wide at x 32, 78, and 124 px and y 31.5 px of a 2x capture without a shadow.
cat >"$WORK/lights.swift" <<'EOF'
import CoreGraphics
import Foundation
import ImageIO
import UniformTypeIdentifiers
let url = URL(fileURLWithPath: CommandLine.arguments[1]) as CFURL
let image = CGImageSourceCreateImageAtIndex(CGImageSourceCreateWithURL(url, nil)!, 0, nil)!
let (w, h) = (image.width, image.height)
let ctx = CGContext(data: nil, width: w, height: h, bitsPerComponent: 8, bytesPerRow: 0,
                    space: CGColorSpaceCreateDeviceRGB(), bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
ctx.draw(image, in: CGRect(x: 0, y: 0, width: w, height: h))
let px = ctx.data!.assumingMemoryBound(to: UInt8.self)
func rgb(_ hex: UInt32) -> CGColor {
  CGColor(red: CGFloat(hex >> 16 & 255) / 255, green: CGFloat(hex >> 8 & 255) / 255, blue: CGFloat(hex & 255) / 255, alpha: 1)
}
let lights: [(Int, UInt32, UInt32)] = [(32, 0xf97b75, 0xe95e56), (78, 0xfec736, 0xe0a220), (124, 0x81d55a, 0x5eb13b)]
var painted = 0
for (x, fill, edge) in lights {
  let i = 31 * ctx.bytesPerRow + x * 4
  let (r, g, b) = (Int(px[i]), Int(px[i + 1]), Int(px[i + 2]))
  if abs(r - g) > 24 || abs(g - b) > 24 { continue }
  let center = CGPoint(x: CGFloat(x) + 0.5, y: CGFloat(h) - 31.5)
  ctx.setFillColor(rgb(edge))
  ctx.fillEllipse(in: CGRect(x: center.x - 14, y: center.y - 14, width: 28, height: 28))
  ctx.setFillColor(rgb(fill))
  ctx.fillEllipse(in: CGRect(x: center.x - 13, y: center.y - 13, width: 26, height: 26))
  painted += 1
}
if painted > 0 {
  let dest = CGImageDestinationCreateWithURL(url, UTType.png.identifier as CFString, 1, nil)!
  CGImageDestinationAddImage(dest, ctx.makeImage()!, nil)
  if !CGImageDestinationFinalize(dest) { exit(1) }
}
EOF
xcrun swiftc -O -o "$WORK/lights" "$WORK/lights.swift" || fail "cannot build the traffic light helper"

cargo build --release --locked --features desktop,vault --example screenshots
TOUR="$ROOT/target/release/examples/screenshots"

HOME_DIR="$WORK/home"
mkdir -p "$HOME_DIR"
chmod 700 "$HOME_DIR"
"$TOUR" seed "$HOME_DIR"

mkfifo "$WORK/events"
(cd "$WORK" && HOME="$HOME_DIR" exec "$TOUR" run >"$WORK/events" 2>"$WORK/app.log") &
APP_PID=$!

COUNT=0
while IFS= read -r line; do
  case "$line" in
    "SHOT "*)
      name="${line#SHOT }"
      sleep 0.5
      wid="$("$WORK/winid" "$APP_PID")" || fail "no window for the app"
      screencapture -x -o -l "$wid" "$OUT/app-$name.png"
      "$WORK/lights" "$OUT/app-$name.png" || fail "cannot paint the traffic lights"
      echo "captured $OUT/app-$name.png"
      COUNT=$((COUNT + 1))
      touch "$WORK/$name.done"
      ;;
  esac
done <"$WORK/events"
wait "$APP_PID" || { cat "$WORK/app.log" >&2; fail "the app did not end cleanly"; }
APP_PID=""
[ "$COUNT" -gt 0 ] || fail "no screenshot"
echo "Done: $COUNT screenshots in $OUT"
