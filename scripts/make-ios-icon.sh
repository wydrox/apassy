#!/bin/bash
# Render the icon of the iPhone app from packaging/AppIcon.svg.
#
# The Mac icon sits on a rounded body with a margin and a shadow. iOS wants a full-bleed square
# without transparency and applies its own mask, so this script draws the same dark background and
# the same mark across the whole square. It writes two files under
# ios/ApassyCompanion/Resources/Assets.xcassets:
#
#   AppIcon.appiconset/AppIcon.png   1024x1024, the single-size app icon
#   CoverIcon.imageset/CoverIcon.png 360x360, the mark of the privacy cover
#
# Run this script after a change to AppIcon.svg, and commit both files. It uses only tools of
# macOS: qlmanage and sips.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SVG="$ROOT/packaging/AppIcon.svg"
ASSETS="$ROOT/ios/ApassyCompanion/Resources/Assets.xcassets"
ICON="$ASSETS/AppIcon.appiconset/AppIcon.png"
COVER="$ASSETS/CoverIcon.imageset/CoverIcon.png"

fail() { printf 'make-ios-icon: FAILED: %s\n' "$*" >&2; exit 1; }
[ "$(uname -s)" = "Darwin" ] || fail "this script runs on macOS only"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/apassy-ios-icon.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

# The mark is the <g> element of the Mac icon. It is drawn for a body of 824 points inside 1024,
# so it grows by 1024/824 around the center to fill the square.
MARK="$(grep '^<g transform' "$SVG")"
[ -n "$MARK" ] || fail "the mark is not in $SVG"
BACKGROUND="$(sed -n 's/.*<rect x="100" y="100"[^>]* fill="\(#[0-9a-fA-F]*\)".*/\1/p' "$SVG")"
[ -n "$BACKGROUND" ] || fail "the background color is not in $SVG"

FULL="$TMP/AppIconFullBleed.svg"
cat > "$FULL" <<SVGEOF
<svg xmlns="http://www.w3.org/2000/svg" width="1024" height="1024" viewBox="0 0 1024 1024">
<rect width="1024" height="1024" fill="$BACKGROUND"/>
<g transform="translate(512 512) scale(1.2427) translate(-512 -512)">$MARK</g>
</svg>
SVGEOF

qlmanage -t -s 1024 -o "$TMP" "$FULL" >/dev/null 2>&1 || fail "qlmanage cannot render $FULL"
BASE="$TMP/$(basename "$FULL").png"
[ -f "$BASE" ] || fail "qlmanage wrote no image"
[ "$(sips -g pixelWidth "$BASE" | awk '/pixelWidth/ {print $2}')" = "1024" ] || fail "the render is not 1024 pixels wide"

# A JPEG round trip drops the alpha channel, which an app icon must not have.
sips -s format jpeg -s formatOptions 100 "$BASE" --out "$TMP/flat.jpg" >/dev/null
mkdir -p "$(dirname "$ICON")" "$(dirname "$COVER")"
sips -s format png "$TMP/flat.jpg" --out "$ICON" >/dev/null
sips -z 360 360 -s format png "$TMP/flat.jpg" --out "$COVER" >/dev/null
[ "$(sips -g hasAlpha "$ICON" | awk '/hasAlpha/ {print $2}')" = "no" ] || fail "the icon still has an alpha channel"
echo "Icon:  $ICON ($(stat -f %z "$ICON") bytes)"
echo "Cover: $COVER ($(stat -f %z "$COVER") bytes)"
