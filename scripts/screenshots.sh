#!/bin/bash
# The screenshot tour of the desktop app: one image of each view of the window, for UI
# work (ui-<view>.png), and the images of the README and the site (app-*.png).
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
# The example is built from this checkout, and the script runs the binary that this
# build made: it copies the binary out of the target directory at once, so a build of
# another checkout in the same target directory cannot swap it. CARGO_TARGET_DIR
# chooses the target directory (default: target/ of this checkout).
# APASSY_TOUR_BIN=PATH runs a binary that is already built instead.
#
# Usage: scripts/screenshots.sh [OUT_DIR]   (default: docs/images)
#
# Output in OUT_DIR:
#   ui-all-credentials.png ui-folder.png ui-credential.png ui-credential-options.png
#   ui-new-credential.png ui-decisions-question.png ui-decisions-request.png
#   ui-decisions-suggestion.png ui-agents.png ui-sidebar-collapsed.png ui-narrow.png
#   ui-narrow-float.png ui-settings-window.png ui-settings-general.png
#   ui-settings-devices.png ui-settings-security.png ui-settings-advanced.png
#   ui-first-steps.png
#   app-vault.png app-credential.png app-agent.png app-requests.png app-activity.png
#   app-learning.png (copies of ui-* images, for the README and the site)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$(cd "$ROOT" && mkdir -p "${1:-docs/images}" && cd "${1:-docs/images}" && pwd)"
cd "$ROOT"

fail() { printf 'screenshots: FAILED: %s\n' "$*" >&2; exit 1; }
[ "$(uname -s)" = "Darwin" ] || fail "this script runs on macOS only"

# A short path: the broker socket of the scratch HOME must fit in SUN_LEN.
WORK="$(mktemp -d /tmp/apassy-shots.XXXXXX)"
APP_PID=""
AWAKE_PID=""
cleanup() {
  [ -z "$APP_PID" ] || kill "$APP_PID" 2>/dev/null || true
  [ -z "$AWAKE_PID" ] || kill "$AWAKE_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT
# A sleeping display stops the window from drawing, and each capture would show the
# last frame. Keep the display on (and wake it) while the tour runs.
caffeinate -d -u -t 900 &
AWAKE_PID=$!

# The window number of a process, for screencapture -l: the largest window, or the
# window with the title given (a second window).
cat >"$WORK/winid.swift" <<'EOF'
import CoreGraphics
import Foundation
let pid = Int32(CommandLine.arguments[1])!
let title = CommandLine.arguments.count > 2 ? CommandLine.arguments[2] : ""
let list = CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID) as? [[String: Any]] ?? []
var windows: [(Int, Double)] = []
for w in list where (w[kCGWindowOwnerPID as String] as? Int32) == pid && (w[kCGWindowLayer as String] as? Int) == 0 {
  guard let n = w[kCGWindowNumber as String] as? Int else { continue }
  if !title.isEmpty && (w[kCGWindowName as String] as? String) == title { print(n); exit(0) }
  let b = w[kCGWindowBounds as String] as? [String: Double] ?? [:]
  windows.append((n, (b["Width"] ?? 0) * (b["Height"] ?? 0)))
}
windows.sort { $0.1 > $1.1 }
// Without a name (no Screen Recording permission for names), a second window is the
// smaller one.
if !title.isEmpty { if windows.count > 1 { print(windows[1].0); exit(0) } else { FileHandle.standardError.write("windows: \(windows.count)\n".data(using: .utf8)!); exit(1) } }
if let first = windows.first { print(first.0); exit(0) }
exit(1)
EOF
xcrun swiftc -O -o "$WORK/winid" "$WORK/winid.swift" || fail "cannot build the window helper"

# Paint gray (inactive) traffic lights in their active colors. The lights are 28 px
# wide; their centers are at LIGHTS_X and LIGHTS_Y px of a 2x capture without a shadow.
LIGHTS_Y=31
LIGHTS_X=32,78,124
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
let cy = Int(CommandLine.arguments[2])!
let xs = CommandLine.arguments[3].split(separator: ",").map { Int($0)! }
let colors: [(UInt32, UInt32)] = [(0xf97b75, 0xe95e56), (0xfec736, 0xe0a220), (0x81d55a, 0x5eb13b)]
var painted = 0
for (x, (fill, edge)) in zip(xs, colors) {
  let i = cy * ctx.bytesPerRow + x * 4
  let (r, g, b) = (Int(px[i]), Int(px[i + 1]), Int(px[i + 2]))
  if abs(r - g) > 24 || abs(g - b) > 24 { continue }
  let center = CGPoint(x: CGFloat(x) + 0.5, y: CGFloat(h) - CGFloat(cy) - 0.5)
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

# The binary of this checkout.
TOUR="$WORK/screenshots"
if [ -n "${APASSY_TOUR_BIN:-}" ]; then
  cp "$APASSY_TOUR_BIN" "$TOUR"
else
  # Xcode 27: a stripped build script breaks proc macros (build-ios-core.sh).
  BUILT="$(CARGO_PROFILE_RELEASE_BUILD_OVERRIDE_STRIP=false cargo build --release --locked \
    --features desktop,vault --example screenshots --message-format=json-render-diagnostics \
    | sed -n 's/.*"target":{[^}]*"name":"screenshots"[^}]*}.*"executable":"\([^"]*\)".*/\1/p' | tail -1)"
  [ -n "$BUILT" ] && [ -x "$BUILT" ] || fail "cargo did not report the screenshots binary"
  cp "$BUILT" "$TOUR"
fi

# One run of the app on a scratch HOME. $1: the seed command (seed or seed-empty);
# further arguments: environment settings for the tour, such as
# APASSY_TOUR_FIRST_STEPS=1.
COUNT=0
tour() {
  local seed="$1"
  shift
  local home="$WORK/home-$seed"
  mkdir -p "$home"
  chmod 700 "$home"
  "$TOUR" "$seed" "$home"
  rm -f "$WORK/events"
  mkfifo "$WORK/events"
  (cd "$WORK" && exec env HOME="$home" "$@" "$TOUR" run >"$WORK/events" 2>"$WORK/app.log") &
  APP_PID=$!
  local line name wid file
  while IFS= read -r line; do
    case "$line" in
      "SHOT "*)
        name="${line#SHOT }"
        wid=""
        sleep 0.5
        file="$OUT/ui-$name.png"
        if [ "$name" = "settings-window" ]; then
          # The second window can take a moment to show.
          for _ in 1 2 3 4 5 6 7 8 9 10; do
            wid="$("$WORK/winid" "$APP_PID" Settings)" && break
            sleep 0.5
          done
          [ -n "$wid" ] || fail "no Settings window"
          screencapture -x -o -l "$wid" "$file"
        else
          wid="$("$WORK/winid" "$APP_PID")" || fail "no window for the app"
          screencapture -x -o -l "$wid" "$file"
          "$WORK/lights" "$file" "$LIGHTS_Y" "$LIGHTS_X" || fail "cannot paint the traffic lights"
        fi
        echo "captured $file"
        COUNT=$((COUNT + 1))
        touch "$WORK/$name.done"
        ;;
    esac
  done <"$WORK/events"
  wait "$APP_PID" || { cat "$WORK/app.log" >&2; fail "the app did not end cleanly"; }
  [ -z "${APASSY_TOUR_LOG:-}" ] || cp "$WORK/app.log" "$APASSY_TOUR_LOG-$seed.log"
  APP_PID=""
}

tour seed
tour seed-empty APASSY_TOUR_FIRST_STEPS=1
[ "$COUNT" -gt 0 ] || fail "no screenshot"

# The names of the README and the site.
for pair in vault:all-credentials credential:credential agent:agents \
  requests:decisions-question activity:decisions-request learning:decisions-suggestion; do
  cp "$OUT/ui-${pair#*:}.png" "$OUT/app-${pair%%:*}.png"
done
echo "Done: $COUNT screenshots in $OUT"
