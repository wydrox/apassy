#!/bin/bash
# Build, sign, and verify target/Apassy.app.
#
# Layout:
#   Apassy.app/Contents/MacOS/apassy          Rust desktop app (main executable)
#   Apassy.app/Contents/MacOS/apassy-mcp      Rust MCP adapter for agents
#   Apassy.app/Contents/MacOS/apassy-helper   Swift helper: Touch ID, notifications
#   Apassy.app/Contents/Helpers/ApassyKeychain.app
#                                             Swift helper with its own bundle
#                                             and profile: Keychain commands
#
# The keychain helper needs a provisioning profile for the App ID
# com.wydrox.apassy.keychain. Without a profile, the script still builds a
# signed app. Then each keychain command returns keychain_unavailable: Touch ID
# can confirm actions but cannot unlock the vault (ADR 0010, Limits).
#
# Usage: scripts/build-app.sh [--provision]
#   --provision   Before the build, run Xcode automatic signing
#                 (xcodebuild -allowProvisioningUpdates) to register the App ID
#                 and download a development profile. This needs an Apple ID
#                 in Xcode > Settings > Accounts.
#
# Environment:
#   APASSY_SIGN_IDENTITY     codesign identity (SHA-1 or name). Default: the
#                            only valid "Apple Development" identity.
#   APASSY_KEYCHAIN_PROFILE  path to a macOS development profile for
#                            com.wydrox.apassy.keychain. Default: search the
#                            Xcode profile folders.
#   APASSY_TEAM_ID           team for --provision. Default: the team (OU) of
#                            the signing certificate.
#   APASSY_REQUIRE_KEYCHAIN  set to 1 to fail when no valid profile is found.
#   APASSY_KEYCHAIN_BUNDLE_ID  bundle ID and App ID suffix of the keychain
#                            helper. Default: com.wydrox.apassy.keychain.
#   APASSY_BASE_MODEL        path to the base-model checkpoint
#                            (apassy-base-v1.safetensors, goal B8). The script
#                            checks it against tools/basemodel/manifest.json
#                            and copies it with the manifest to
#                            Contents/Resources/models/. Default: no model.
#
# See docs/operations/native-app.md and docs/operations/base-model.md.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

APP_ID="com.wydrox.apassy"
KEYCHAIN_APP_ID="${APASSY_KEYCHAIN_BUNDLE_ID:-com.wydrox.apassy.keychain}"
KEYCHAIN_EXE="ApassyKeychain"
OUT="$ROOT/target/Apassy.app"
STAGE="$ROOT/target/app-stage"
NATIVE_OUT="$ROOT/target/native"
DEPLOYMENT_TARGET="15.0"

PROVISION=0
for arg in "$@"; do
  case "$arg" in
    --provision) PROVISION=1 ;;
    -h|--help) sed -n '2,40p' "$0"; exit 0 ;;
    *) echo "build-app: unknown option: $arg" >&2; exit 2 ;;
  esac
done

[[ "$KEYCHAIN_APP_ID" =~ ^[A-Za-z0-9.-]+$ ]] || { echo "build-app: invalid APASSY_KEYCHAIN_BUNDLE_ID" >&2; exit 2; }

step() { printf '\n==> %s\n' "$*"; }
fail() { printf '\nbuild-app: FAILED: %s\n' "$*" >&2; exit 1; }
warn() { printf 'build-app: WARNING: %s\n' "$*" >&2; }

TMP="$(mktemp -d "${TMPDIR:-/tmp}/apassy-build.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

# ---------------------------------------------------------------- checks
step "Check the host and tools"
[ "$(uname -s)" = "Darwin" ] || fail "this script runs on macOS only"
[ "$(uname -m)" = "arm64" ] || fail "this script builds for arm64 only"
for tool in cargo xcrun codesign security plutil openssl file /usr/libexec/PlistBuddy; do
  command -v "$tool" >/dev/null 2>&1 || fail "missing tool: $tool"
done
# Use the SDK of the selected Xcode. A bare `xcrun` can select a Command
# Line Tools SDK that the Xcode linker cannot read.
SDK="$(xcrun --sdk macosx --show-sdk-path)" || fail "xcrun cannot find the macOS SDK"
echo "SDK: $SDK"

# ---------------------------------------------------------------- identity
step "Select the signing identity"
IDENTITIES="$(security find-identity -v -p codesigning)"
if [ -n "${APASSY_SIGN_IDENTITY:-}" ]; then
  [ "$APASSY_SIGN_IDENTITY" != "-" ] || fail "ad hoc signing is not supported. Use an Apple Development identity."
  SIGN_ID="$APASSY_SIGN_IDENTITY"
else
  MATCHES="$(printf '%s\n' "$IDENTITIES" | grep '"Apple Development: ' || true)"
  COUNT="$(printf '%s' "$MATCHES" | grep -c . || true)"
  [ "$COUNT" = "1" ] || fail "found $COUNT valid \"Apple Development\" identities. Set APASSY_SIGN_IDENTITY to the SHA-1 of one identity."
  SIGN_ID="$(printf '%s\n' "$MATCHES" | awk '{print $2}')"
fi
SIGN_LINE="$(printf '%s\n' "$IDENTITIES" | grep -F "$SIGN_ID" | head -n 1 || true)"
[ -n "$SIGN_LINE" ] || fail "the identity \"$SIGN_ID\" is not a valid code signing identity"
SIGN_SHA1="$(printf '%s\n' "$SIGN_LINE" | awk '{print $2}')"
SIGN_NAME="$(printf '%s\n' "$SIGN_LINE" | sed -E 's/^[^"]*"(.*)"$/\1/')"
# The team ID is the OU of the certificate subject.
security find-certificate -a -Z -p >"$TMP/certs.txt"
awk -v want="$SIGN_SHA1" '
  /^SHA-1 hash:/ { keep = ($3 == want) }
  keep && /-----BEGIN CERTIFICATE-----/ { printing = 1 }
  printing { print }
  printing && /-----END CERTIFICATE-----/ { exit }
' "$TMP/certs.txt" >"$TMP/sign-cert.pem"
[ -s "$TMP/sign-cert.pem" ] || fail "cannot export the certificate $SIGN_SHA1"
CERT_TEAM="$(openssl x509 -in "$TMP/sign-cert.pem" -noout -subject \
  | grep -oE 'OU ?= ?[A-Z0-9]{10}' | grep -oE '[A-Z0-9]{10}$' | head -n 1 || true)"
echo "Identity: $SIGN_NAME ($SIGN_SHA1), team ${CERT_TEAM:-unknown}"

# ---------------------------------------------------------------- profile
MAC_UDID="$(system_profiler SPHardwareDataType | awk -F': ' '/Provisioning UDID/ {print $2}')"
NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

plist_get() { /usr/libexec/PlistBuddy -c "Print :$2" "$1" 2>/dev/null; }

# check_profile FILE: print "TEAM" and return 0 when the profile fits this
# build. Print the reason and return 1 when it does not.
check_profile() {
  local file="$1" decoded="$TMP/profile.plist" team appid expiry groups i found
  security cms -D -i "$file" >"$decoded" 2>/dev/null || { echo "cannot decode the profile"; return 1; }
  plist_get "$decoded" Platform | grep -q OSX || { echo "the profile is not for macOS"; return 1; }
  team="$(plist_get "$decoded" TeamIdentifier:0)" || { echo "the profile has no team"; return 1; }
  appid="$(plist_get "$decoded" Entitlements:com.apple.application-identifier || plist_get "$decoded" Entitlements:application-identifier || true)"
  case "$appid" in
    "$team.$KEYCHAIN_APP_ID"|"$team.*") ;;
    *) echo "the App ID is \"$appid\", not $team.$KEYCHAIN_APP_ID"; return 1 ;;
  esac
  expiry="$(plutil -extract ExpirationDate raw -o - "$decoded")"
  [[ "$expiry" > "$NOW" ]] || { echo "the profile expired at $expiry"; return 1; }
  groups="$(plist_get "$decoded" Entitlements:keychain-access-groups || true)"
  printf '%s\n' "$groups" | grep -Eq "^[[:space:]]*($team\\.\\*|$team\\.$APP_ID)$" \
    || { echo "the profile does not permit the keychain group $team.$APP_ID"; return 1; }
  if [ "$(plist_get "$decoded" ProvisionsAllDevices || true)" != "true" ]; then
    plist_get "$decoded" ProvisionedDevices | grep -q "$MAC_UDID" \
      || { echo "the profile does not include this Mac ($MAC_UDID)"; return 1; }
  fi
  found=0
  i=0
  while plutil -extract "DeveloperCertificates.$i" raw -o - "$decoded" >"$TMP/dev-cert.b64" 2>/dev/null; do
    if [ "$(base64 -d -i "$TMP/dev-cert.b64" | openssl x509 -inform DER -noout -fingerprint -sha1 | sed 's/.*=//; s/://g')" = "$SIGN_SHA1" ]; then
      found=1
    fi
    i=$((i + 1))
  done
  [ "$found" = "1" ] || { echo "the profile does not include the certificate $SIGN_SHA1"; return 1; }
  echo "$team"
}

if [ "$PROVISION" = "1" ]; then
  step "Get a provisioning profile with Xcode automatic signing"
  TEAM_FOR_XCODE="${APASSY_TEAM_ID:-$CERT_TEAM}"
  [ -n "$TEAM_FOR_XCODE" ] || fail "set APASSY_TEAM_ID for --provision"
  command -v xcodebuild >/dev/null 2>&1 || fail "missing tool: xcodebuild"
  if ! xcodebuild -project native/ApassyKeychain/ApassyKeychain.xcodeproj \
      -scheme ApassyKeychain -configuration Debug \
      -derivedDataPath "$ROOT/target/xcode-provision" \
      -allowProvisioningUpdates DEVELOPMENT_TEAM="$TEAM_FOR_XCODE" \
      PRODUCT_BUNDLE_IDENTIFIER="$KEYCHAIN_APP_ID" build >"$TMP/xcodebuild.log" 2>&1; then
    grep -E "error:" "$TMP/xcodebuild.log" >&2 || tail -n 20 "$TMP/xcodebuild.log" >&2
    fail "Xcode automatic signing failed. Add your Apple ID in Xcode > Settings > Accounts (team $TEAM_FOR_XCODE), then run again. See docs/operations/native-app.md."
  fi
  APASSY_KEYCHAIN_PROFILE="$ROOT/target/xcode-provision/Build/Products/Debug/ApassyKeychain.app/Contents/embedded.provisionprofile"
  [ -f "$APASSY_KEYCHAIN_PROFILE" ] || fail "Xcode did not embed a provisioning profile"
fi

step "Find the keychain provisioning profile"
PROFILE=""
TEAM_ID=""
if [ -n "${APASSY_KEYCHAIN_PROFILE:-}" ]; then
  [ -f "$APASSY_KEYCHAIN_PROFILE" ] || fail "APASSY_KEYCHAIN_PROFILE does not exist: $APASSY_KEYCHAIN_PROFILE"
  RESULT="$(check_profile "$APASSY_KEYCHAIN_PROFILE")" || fail "APASSY_KEYCHAIN_PROFILE is not usable: $RESULT"
  PROFILE="$APASSY_KEYCHAIN_PROFILE"
  TEAM_ID="$RESULT"
else
  BEST_EXPIRY=""
  for dir in "$HOME/Library/Developer/Xcode/UserData/Provisioning Profiles" "$HOME/Library/MobileDevice/Provisioning Profiles"; do
    [ -d "$dir" ] || continue
    for file in "$dir"/*.provisionprofile; do
      [ -f "$file" ] || continue
      if RESULT="$(check_profile "$file")"; then
        EXPIRY="$(plutil -extract ExpirationDate raw -o - "$TMP/profile.plist")"
        if [[ "$EXPIRY" > "$BEST_EXPIRY" ]]; then
          PROFILE="$file"
          TEAM_ID="$RESULT"
          BEST_EXPIRY="$EXPIRY"
        fi
      fi
    done
  done
fi
if [ -n "$PROFILE" ]; then
  echo "Profile: $PROFILE (team $TEAM_ID)"
  KEYCHAIN_MODE="enabled"
else
  KEYCHAIN_MODE="disabled"
  [ "${APASSY_REQUIRE_KEYCHAIN:-0}" != "1" ] \
    || fail "APASSY_REQUIRE_KEYCHAIN=1, but no valid profile for $KEYCHAIN_APP_ID was found"
  warn "no provisioning profile for $KEYCHAIN_APP_ID. The keychain helper returns keychain_unavailable."
  warn "Touch ID can confirm actions but cannot unlock the vault. See docs/operations/native-app.md."
fi

# ---------------------------------------------------------------- build
step "Build the Rust binaries (release)"
cargo build --release --locked --features desktop,vault --bin apassy --bin apassy-mcp

step "Build the Swift helper"
mkdir -p "$NATIVE_OUT"
xcrun --sdk macosx swiftc -sdk "$SDK" -O -swift-version 5 -warnings-as-errors \
  -target "arm64-apple-macos$DEPLOYMENT_TARGET" \
  -o "$NATIVE_OUT/apassy-helper" native/ApassyHelper/*.swift

# ---------------------------------------------------------------- assemble
step "Assemble the app bundle"
VERSION="$(awk -F'"' '/^version = / {print $2; exit}' Cargo.toml)"
[ -n "$VERSION" ] || fail "cannot read the package version from Cargo.toml"
rm -rf "$STAGE" "$OUT"
APP="$STAGE/Apassy.app"
KC_APP="$APP/Contents/Helpers/ApassyKeychain.app"
mkdir -p "$APP/Contents/MacOS" "$KC_APP/Contents/MacOS"
# The plist templates use Xcode build-setting names, so the Xcode project in
# native/ApassyKeychain can read the same file.
fill_plist() { # template, output
  sed -e "s/\$(MARKETING_VERSION)/$VERSION/g" \
      -e "s/\$(PRODUCT_BUNDLE_IDENTIFIER)/$KEYCHAIN_APP_ID/g" \
      -e "s/\$(EXECUTABLE_NAME)/$KEYCHAIN_EXE/g" "$1" >"$2"
  plutil -lint "$2" >/dev/null
  if grep -q '\$(' "$2"; then fail "unfilled variable in $2"; fi
}
fill_plist packaging/Info.plist "$APP/Contents/Info.plist"
fill_plist packaging/ApassyKeychain-Info.plist "$KC_APP/Contents/Info.plist"
printf 'APPL????' >"$APP/Contents/PkgInfo"
printf 'APPL????' >"$KC_APP/Contents/PkgInfo"
cp target/release/apassy target/release/apassy-mcp "$APP/Contents/MacOS/"
cp "$NATIVE_OUT/apassy-helper" "$APP/Contents/MacOS/apassy-helper"
cp "$NATIVE_OUT/apassy-helper" "$KC_APP/Contents/MacOS/$KEYCHAIN_EXE"

# Goal B8: the base-model checkpoint goes into the bundle before the signature,
# so the signature seals it. The copy must match tools/basemodel/manifest.json.
MODEL_MODE="none"
if [ -n "${APASSY_BASE_MODEL:-}" ]; then
  step "Copy the base-model checkpoint"
  MANIFEST="$ROOT/tools/basemodel/manifest.json"
  [ -f "$APASSY_BASE_MODEL" ] || fail "APASSY_BASE_MODEL does not exist: $APASSY_BASE_MODEL"
  [ -f "$MANIFEST" ] || fail "missing $MANIFEST"
  command -v shasum >/dev/null 2>&1 || fail "missing tool: shasum"
  manifest_get() { plutil -extract "$1" raw -o - "$MANIFEST" 2>/dev/null || fail "manifest has no $1"; }
  MODEL_FILE="$(manifest_get checkpoint.file)"
  MODEL_SHA="$(manifest_get checkpoint.sha256)"
  MODEL_SIZE="$(manifest_get checkpoint.size_bytes)"
  MODEL_VERSION="$(manifest_get version)"
  [[ "$MODEL_FILE" =~ ^[A-Za-z0-9._-]+\.safetensors$ ]] || fail "invalid checkpoint.file in the manifest: $MODEL_FILE"
  [[ "$MODEL_SHA" =~ ^[0-9a-f]{64}$ ]] || fail "invalid checkpoint.sha256 in the manifest"
  GOT_SIZE="$(stat -f %z "$APASSY_BASE_MODEL")"
  [ "$GOT_SIZE" = "$MODEL_SIZE" ] || fail "checkpoint size $GOT_SIZE does not match the manifest ($MODEL_SIZE)"
  GOT_SHA="$(shasum -a 256 "$APASSY_BASE_MODEL" | awk '{print $1}')"
  [ "$GOT_SHA" = "$MODEL_SHA" ] || fail "checkpoint SHA-256 $GOT_SHA does not match the manifest ($MODEL_SHA)"
  [ "$MODEL_VERSION" = "apassy-base-v1+${MODEL_SHA:0:8}" ] || fail "manifest version $MODEL_VERSION does not match the SHA-256"
  mkdir -p "$APP/Contents/Resources/models"
  cp "$APASSY_BASE_MODEL" "$APP/Contents/Resources/models/$MODEL_FILE"
  cp "$MANIFEST" "$APP/Contents/Resources/models/manifest.json"
  COPY_SHA="$(shasum -a 256 "$APP/Contents/Resources/models/$MODEL_FILE" | awk '{print $1}')"
  [ "$COPY_SHA" = "$MODEL_SHA" ] || fail "the copied checkpoint does not match the manifest"
  MODEL_MODE="$MODEL_VERSION"
  echo "Base model: $MODEL_VERSION ($MODEL_SIZE bytes)"
fi

KC_ENTITLEMENTS="$ROOT/packaging/Apassy.entitlements"
if [ "$KEYCHAIN_MODE" = "enabled" ]; then
  cp "$PROFILE" "$KC_APP/Contents/embedded.provisionprofile"
  KC_ENTITLEMENTS="$TMP/ApassyKeychain.entitlements"
  sed -e "s/__TEAM_ID__/$TEAM_ID/g" -e "s/__KEYCHAIN_BUNDLE_ID__/$KEYCHAIN_APP_ID/g" \
    packaging/ApassyKeychain.entitlements >"$KC_ENTITLEMENTS"
  plutil -lint "$KC_ENTITLEMENTS" >/dev/null
  if grep -q '__' "$KC_ENTITLEMENTS"; then fail "unfilled variable in the keychain entitlements"; fi
fi

# ---------------------------------------------------------------- sign
step "Sign from the inside out (hardened runtime)"
sign() { codesign --force --sign "$SIGN_SHA1" --options runtime --timestamp=none "$@"; }
sign --entitlements "$KC_ENTITLEMENTS" "$KC_APP"
sign --identifier "$APP_ID.helper" --entitlements packaging/Apassy.entitlements "$APP/Contents/MacOS/apassy-helper"
sign --identifier "$APP_ID.mcp" --entitlements packaging/Apassy.entitlements "$APP/Contents/MacOS/apassy-mcp"
sign --entitlements packaging/Apassy.entitlements "$APP"

# ---------------------------------------------------------------- verify
step "Verify the signatures"
codesign --verify --deep --strict --verbose=2 "$APP"
for code in "$APP" "$APP/Contents/MacOS/apassy-mcp" "$APP/Contents/MacOS/apassy-helper" "$KC_APP"; do
  codesign -d --verbose=2 "$code" >"$TMP/info.txt" 2>&1
  grep -q "flags=.*(runtime)" "$TMP/info.txt" || fail "hardened runtime is off for $code"
  grep -q "TeamIdentifier=${CERT_TEAM:-}" "$TMP/info.txt" || fail "unexpected team for $code"
  echo "$(grep '^Identifier=' "$TMP/info.txt") $(grep '^CodeDirectory' "$TMP/info.txt" | grep -o 'flags=[^ ]*')"
done
# Print the entitlements of CODE as JSON. No entitlements blob prints {}.
entitlements_json() {
  local xml
  xml="$(codesign -d --entitlements - --xml "$1" 2>/dev/null || true)"
  if [ -z "$xml" ]; then echo "{}"; else printf '%s' "$xml" | plutil -convert json -o - -; echo; fi
}
echo "Entitlements of ApassyKeychain.app: $(entitlements_json "$KC_APP")"
for code in "$APP" "$APP/Contents/MacOS/apassy-mcp" "$APP/Contents/MacOS/apassy-helper"; do
  ENT="$(entitlements_json "$code")"
  [ "$ENT" = "{}" ] || fail "$code has unexpected entitlements: $ENT"
done
echo "Entitlements of apassy, apassy-mcp, apassy-helper: {}"

# Key-memory review F7: each program in the bundle has the hardened runtime,
# and no program has an entitlement that lets a debugger read its memory or
# lets injected code run in it.
FORBIDDEN_ENTITLEMENTS="com.apple.security.get-task-allow com.apple.security.cs.disable-library-validation com.apple.security.cs.allow-dyld-environment-variables"
# Print each forbidden entitlement of CODE, one per line.
forbidden_entitlements() {
  local json key
  json="$(entitlements_json "$1")"
  for key in $FORBIDDEN_ENTITLEMENTS; do
    if printf '%s' "$json" | grep -qF "\"$key\""; then echo "$key"; fi
  done
}
# The check must find each forbidden entitlement: sign a copy of the helper
# with all of them. The copy stays in $TMP and never runs.
cp "$NATIVE_OUT/apassy-helper" "$TMP/entitlement-probe"
{
  printf '<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0">\n<dict>\n'
  for key in $FORBIDDEN_ENTITLEMENTS; do printf '<key>%s</key><true/>\n' "$key"; done
  printf '</dict>\n</plist>\n'
} >"$TMP/probe.entitlements"
plutil -lint "$TMP/probe.entitlements" >/dev/null
sign --entitlements "$TMP/probe.entitlements" "$TMP/entitlement-probe" \
  || fail "cannot sign the entitlement probe"
[ "$(forbidden_entitlements "$TMP/entitlement-probe" | tr '\n' ' ')" = "$FORBIDDEN_ENTITLEMENTS " ] \
  || fail "the entitlement check does not find the forbidden entitlements"
PROGRAMS=0
while IFS= read -r -d '' code; do
  file -b "$code" | grep -q '^Mach-O' || continue
  PROGRAMS=$((PROGRAMS + 1))
  codesign -d --verbose=2 "$code" >"$TMP/info.txt" 2>&1 || fail "$code is not signed"
  grep -q "flags=.*(runtime)" "$TMP/info.txt" || fail "hardened runtime is off for $code"
  FOUND="$(forbidden_entitlements "$code" | tr '\n' ' ')"
  [ -z "$FOUND" ] || fail "$code has forbidden entitlements: $FOUND"
done < <(find "$APP" -type f -print0)
[ "$PROGRAMS" = "4" ] || fail "expected 4 programs in the bundle, found $PROGRAMS"
echo "Hardened runtime on all $PROGRAMS programs. None has get-task-allow, disable-library-validation, or allow-dyld-environment-variables."

# ---------------------------------------------------------------- self-check
step "Run the signed programs"
check_output() { # label, output, pattern
  printf '%s\n' "$2" | grep -Eq "$3" || fail "$1: unexpected output: $2"
  echo "ok: $1"
}
"$APP/Contents/MacOS/apassy" --smoke-test >"$TMP/smoke.txt" 2>&1 || { cat "$TMP/smoke.txt" >&2; fail "apassy --smoke-test failed"; }
echo "ok: apassy --smoke-test"
check_output "apassy-mcp --version" "$("$APP/Contents/MacOS/apassy-mcp" --version)" "^apassy-mcp $VERSION$"
HELPER_OUT="$(printf '%s\n' '{"cmd":"ping"}' '{"cmd":"notify_status"}' '{"cmd":"bogus"}' | "$APP/Contents/MacOS/apassy-helper")" \
  || fail "apassy-helper did not run"
check_output "helper ping" "$(sed -n 1p <<<"$HELPER_OUT")" "\"bundle_id\":\"$APP_ID\".*\"keychain_access_group\":null.*\"ok\":true"
check_output "helper notify_status" "$(sed -n 2p <<<"$HELPER_OUT")" '"authorization":"[a-z_]+".*"ok":true'
check_output "helper unknown command" "$(sed -n 3p <<<"$HELPER_OUT")" '"error":"invalid_request"'
KC_OUT="$(printf '%s\n' '{"cmd":"ping"}' '{"cmd":"keychain_exists","account":"build-check"}' | "$KC_APP/Contents/MacOS/$KEYCHAIN_EXE")" \
  || fail "the keychain helper did not run. Check: log show --last 2m --predicate 'process == \"amfid\"'"
if [ "$KEYCHAIN_MODE" = "enabled" ]; then
  check_output "keychain helper ping" "$(sed -n 1p <<<"$KC_OUT")" "\"bundle_id\":\"$KEYCHAIN_APP_ID\".*\"keychain_access_group\":\"$TEAM_ID\\.$APP_ID\""
  check_output "keychain_exists" "$(sed -n 2p <<<"$KC_OUT")" '"exists":(true|false).*"ok":true'
else
  check_output "keychain helper ping" "$(sed -n 1p <<<"$KC_OUT")" "\"bundle_id\":\"$KEYCHAIN_APP_ID\".*\"keychain_access_group\":null"
  check_output "keychain_exists" "$(sed -n 2p <<<"$KC_OUT")" '"error":"keychain_unavailable"'
fi

mv "$APP" "$OUT"
rm -rf "$STAGE"

step "Done"
echo "App:      $OUT"
echo "Version:  $VERSION"
echo "Signed:   $SIGN_NAME"
if [ "$MODEL_MODE" = "none" ]; then
  echo "Model:    none (set APASSY_BASE_MODEL to ship the base model)"
else
  echo "Model:    $MODEL_MODE in Contents/Resources/models"
fi
if [ "$KEYCHAIN_MODE" = "enabled" ]; then
  echo "Keychain: enabled (team $TEAM_ID, group $TEAM_ID.$APP_ID)"
else
  echo "Keychain: DISABLED (no provisioning profile). Touch ID can confirm actions but cannot unlock the vault."
fi
