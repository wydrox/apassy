#!/bin/bash
# Package target/Apassy.app into a signed disk image, and notarize it.
#
# Output in target/dist:
#   Apassy.dmg    Apassy.app and a link to /Applications
#   latest.json   version, build, commit, date, size, and SHA-256 of the image.
#                 The site serves it at /latest.json (site/worker/index.ts).
#
# Run scripts/build-app.sh first. The script signs the disk image with the
# certificate that signed the app. target/Apassy.app does not change: the
# script staples a copy.
#
# Usage: scripts/build-dmg.sh [--notarize]
#   --notarize   Send the app, then the disk image, to the Apple notary service,
#                and staple both tickets. Needs a "Developer ID Application"
#                signature with a secure timestamp, and notary credentials.
#
# Notary credentials, one of:
#   APASSY_NOTARY_KEY, APASSY_NOTARY_KEY_ID, APASSY_NOTARY_ISSUER
#                an App Store Connect API key: the path to the .p8 file, the
#                key ID, and the issuer ID. The release workflow uses these.
#   APASSY_NOTARY_PROFILE
#                a keychain profile from `xcrun notarytool store-credentials`.
#
# See docs/operations/release.md.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

APP="$ROOT/target/Apassy.app"
OUT="$ROOT/target/dist"
DMG="$OUT/Apassy.dmg"

NOTARIZE=0
for arg in "$@"; do
  case "$arg" in
    --notarize) NOTARIZE=1 ;;
    -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
    *) echo "build-dmg: unknown option: $arg" >&2; exit 2 ;;
  esac
done

step() { printf '\n==> %s\n' "$*"; }
fail() { printf '\nbuild-dmg: FAILED: %s\n' "$*" >&2; exit 1; }

TMP="$(mktemp -d "${TMPDIR:-/tmp}/apassy-dmg.XXXXXX")"
MOUNT="$TMP/mount"
MOUNTED=0
cleanup() {
  if [ "$MOUNTED" = "1" ]; then
    if ! hdiutil detach "$MOUNT" >/dev/null 2>&1; then
      if ! hdiutil detach -force "$MOUNT" >/dev/null 2>&1; then
        printf '\nbuild-dmg: Could not detach %s. Temporary files remain in %s.\n' "$MOUNT" "$TMP" >&2
        return
      fi
    fi
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# ---------------------------------------------------------------- checks
step "Check the app"
[ "$(uname -s)" = "Darwin" ] || fail "this script runs on macOS only"
for tool in codesign ditto git hdiutil openssl plutil security shasum sips xcrun; do
  command -v "$tool" >/dev/null 2>&1 || fail "missing tool: $tool"
done
[ -s "$ROOT/packaging/dmg-background.png" ] || fail "missing packaging/dmg-background.png"
[ -s "$ROOT/packaging/dmg-background.tiff" ] || fail "missing packaging/dmg-background.tiff. Run swift scripts/render-dmg-background.swift."
BACKGROUND_SIZE="$(sips -g pixelWidth -g pixelHeight "$ROOT/packaging/dmg-background.png")"
echo "$BACKGROUND_SIZE" | grep -q 'pixelWidth: 720$' \
  && echo "$BACKGROUND_SIZE" | grep -q 'pixelHeight: 480$' \
  || fail "packaging/dmg-background.png must be 720 by 480 pixels"
bash "$ROOT/scripts/layout-dmg.sh" --check
[ -d "$APP" ] || fail "missing $APP. Run scripts/build-app.sh first."
for tool in apassy apassy-mcp apassy-hook apassy-sandbox apassy-browser-host; do
  [ -x "$APP/Contents/MacOS/$tool" ] || fail "missing $tool in $APP. Run scripts/build-app.sh again."
done
[ -s "$APP/Contents/Resources/apassy-agent-host.sb" ] \
  || fail "missing agent profile in $APP. Run scripts/build-app.sh again."
[ -s "$APP/Contents/Resources/browser-extension/manifest.json" ] \
  || fail "missing browser extension in $APP. Run scripts/build-app.sh again."
codesign --verify --deep --strict "$APP" || fail "the signature of $APP is not valid"
codesign -dvv "$APP" >"$TMP/info.txt" 2>&1
SIGN_NAME="$(sed -n 's/^Authority=//p' "$TMP/info.txt" | head -n 1)"
[ -n "$SIGN_NAME" ] || fail "$APP has no signing certificate"
# Sign the image with the certificate of the app, by SHA-1: a renewed
# certificate can have the same name.
codesign -d --extract-certificates="$TMP/cert" "$APP" 2>/dev/null
SIGN_SHA1="$(openssl x509 -inform DER -in "$TMP/cert0" -noout -fingerprint -sha1 | sed 's/.*=//; s/://g')"
security find-identity -v -p codesigning | grep -q "$SIGN_SHA1" \
  || fail "the keychain has no private key for \"$SIGN_NAME\" ($SIGN_SHA1)"
echo "Signed by: $SIGN_NAME ($SIGN_SHA1)"

VERSION="$(plutil -extract CFBundleShortVersionString raw -o - "$APP/Contents/Info.plist")"
MIN_MACOS="$(plutil -extract LSMinimumSystemVersion raw -o - "$APP/Contents/Info.plist")"
[[ "$VERSION" =~ ^[0-9A-Za-z.+-]+$ ]] || fail "unexpected version: $VERSION"
[[ "$MIN_MACOS" =~ ^[0-9.]+$ ]] || fail "unexpected LSMinimumSystemVersion: $MIN_MACOS"
COMMIT="$(git rev-parse HEAD)"
BUILD="${COMMIT:0:7}"
echo "Version: $VERSION, build $BUILD"

NOTARY=()
if [ "$NOTARIZE" = "1" ]; then
  case "$SIGN_NAME" in
    "Developer ID Application: "*) ;;
    *) fail "notarization needs a \"Developer ID Application\" signature, not \"$SIGN_NAME\"" ;;
  esac
  grep -q '^Timestamp=' "$TMP/info.txt" \
    || fail "the app has no secure timestamp. Build it again with the Developer ID identity."
  if [ -n "${APASSY_NOTARY_PROFILE:-}" ]; then
    NOTARY=(--keychain-profile "$APASSY_NOTARY_PROFILE")
  elif [ -n "${APASSY_NOTARY_KEY:-}" ]; then
    [ -f "$APASSY_NOTARY_KEY" ] || fail "APASSY_NOTARY_KEY does not exist: $APASSY_NOTARY_KEY"
    [ -n "${APASSY_NOTARY_KEY_ID:-}" ] && [ -n "${APASSY_NOTARY_ISSUER:-}" ] \
      || fail "set APASSY_NOTARY_KEY_ID and APASSY_NOTARY_ISSUER with APASSY_NOTARY_KEY"
    NOTARY=(--key "$APASSY_NOTARY_KEY" --key-id "$APASSY_NOTARY_KEY_ID" --issuer "$APASSY_NOTARY_ISSUER")
  else
    fail "--notarize needs APASSY_NOTARY_KEY (with _KEY_ID and _ISSUER) or APASSY_NOTARY_PROFILE"
  fi
fi

# notarize FILE LABEL: submit FILE, wait for the result, and print the log of
# the notary service when it does not accept the file.
notarize() {
  local file="$1" label="$2" id status
  xcrun notarytool submit "$file" "${NOTARY[@]}" --wait --timeout 1h --output-format json \
    >"$TMP/notary.json" || true
  id="$(plutil -extract id raw -o - "$TMP/notary.json" 2>/dev/null || true)"
  status="$(plutil -extract status raw -o - "$TMP/notary.json" 2>/dev/null || true)"
  echo "Notary: $label: ${status:-no result} (submission ${id:-none})"
  if [ "$status" != "Accepted" ]; then
    cat "$TMP/notary.json" >&2
    [ -z "$id" ] || xcrun notarytool log "$id" "${NOTARY[@]}" >&2 || true
    fail "the notary service did not accept $label"
  fi
}

# ---------------------------------------------------------------- app
STAGE="$TMP/stage"
mkdir -p "$STAGE"
ditto "$APP" "$STAGE/Apassy.app"
if [ "$NOTARIZE" = "1" ]; then
  step "Notarize the app"
  ditto -c -k --keepParent "$STAGE/Apassy.app" "$TMP/Apassy.zip"
  notarize "$TMP/Apassy.zip" "Apassy.app"
  # A stapled app opens offline on the first start, also after a copy out of
  # the disk image.
  xcrun stapler staple "$STAGE/Apassy.app"
  xcrun stapler validate "$STAGE/Apassy.app"
  spctl --assess --type exec --verbose=2 "$STAGE/Apassy.app"
fi

# ---------------------------------------------------------------- image
step "Make the disk image"
ln -s /Applications "$STAGE/Applications"
mkdir -p "$STAGE/.background"
ditto "$ROOT/packaging/dmg-background.tiff" "$STAGE/.background/background.tiff"
WRITABLE="$TMP/Apassy-layout.dmg"
# hdiutil sometimes fails with "Resource busy" on a busy host. Try again.
for attempt in 1 2 3; do
  if hdiutil create -volname Apassy -srcfolder "$STAGE" -fs HFS+ -format UDRW -ov "$WRITABLE" >"$TMP/hdiutil.log" 2>&1; then
    break
  fi
  cat "$TMP/hdiutil.log" >&2
  [ "$attempt" != "3" ] || fail "hdiutil create failed"
  sleep 5
done
mkdir -p "$MOUNT"
# Mark the attach attempt before the command, so cleanup also handles an
# interrupted attach. A failed detach never causes removal of mounted files.
MOUNTED=1
hdiutil attach "$WRITABLE" -mountpoint "$MOUNT" -nobrowse -noautoopen -readwrite \
  || fail "could not mount the writable disk image"
step "Save the Finder install window"
bash "$ROOT/scripts/layout-dmg.sh" "$MOUNT"
# Verify the exact copy after Finder writes its metadata.
codesign --verify --deep --strict "$MOUNT/Apassy.app" \
  || fail "the packaged app signature is not valid"
if [ "$NOTARIZE" = "1" ]; then
  xcrun stapler validate "$MOUNT/Apassy.app"
  spctl --assess --type exec --verbose=2 "$MOUNT/Apassy.app"
fi
sync
hdiutil detach "$MOUNT" || fail "could not detach the disk image"
MOUNTED=0
rm -rf "$OUT"
mkdir -p "$OUT"
hdiutil convert "$WRITABLE" -format UDZO -imagekey zlib-level=9 -ov -o "$DMG" \
  || fail "could not compress the disk image"
hdiutil verify "$DMG" >/dev/null || fail "hdiutil verify failed"
# The same timestamp rule as scripts/build-app.sh.
case "$SIGN_NAME" in
  "Developer ID Application: "*) SIGN_TIMESTAMP="--timestamp" ;;
  *) SIGN_TIMESTAMP="--timestamp=none" ;;
esac
codesign --force --sign "$SIGN_SHA1" "$SIGN_TIMESTAMP" "$DMG"
codesign --verify --strict --verbose=2 "$DMG"

if [ "$NOTARIZE" = "1" ]; then
  step "Notarize the disk image"
  notarize "$DMG" "Apassy.dmg"
  xcrun stapler staple "$DMG"
  xcrun stapler validate "$DMG"
  spctl --assess --type open --context context:primary-signature --verbose=2 "$DMG"
fi

# ---------------------------------------------------------------- manifest
step "Write latest.json"
SIZE="$(stat -f %z "$DMG")"
SHA256="$(shasum -a 256 "$DMG" | awk '{print $1}')"
NOTARIZED="$([ "$NOTARIZE" = "1" ] && echo true || echo false)"
cat >"$OUT/latest.json" <<EOF
{
  "version": "$VERSION",
  "build": "$BUILD",
  "commit": "$COMMIT",
  "date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "file": "Apassy.dmg",
  "size": $SIZE,
  "sha256": "$SHA256",
  "notarized": $NOTARIZED,
  "minimum_macos": "$MIN_MACOS",
  "arch": "arm64"
}
EOF
plutil -convert xml1 -o /dev/null "$OUT/latest.json" || fail "latest.json is not valid JSON"
cat "$OUT/latest.json"

step "Done"
echo "Image:     $DMG ($SIZE bytes)"
echo "SHA-256:   $SHA256"
if [ "$NOTARIZE" = "1" ]; then
  echo "Notarized: yes, tickets stapled to the app and the image"
else
  echo "Notarized: NO. Gatekeeper blocks this image on other Macs. Use --notarize for a release."
fi
