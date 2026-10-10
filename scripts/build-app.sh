#!/bin/bash
# Build, sign, and verify target/Apassy.app.
#
# Layout:
#   Apassy.app/Contents/MacOS/apassy          Rust desktop app (main executable)
#   Apassy.app/Contents/MacOS/apassy-mcp      Rust MCP adapter for agents
#   Apassy.app/Contents/MacOS/apassy-hook     Rust prompt hook for agents
#   Apassy.app/Contents/MacOS/apassy-sandbox  Rust agent sandbox launcher
#   Apassy.app/Contents/MacOS/apassy-browser-host
#                                             Rust native messaging host of
#                                             the browser extension (ADR 0021)
#   Apassy.app/Contents/MacOS/apassy-browser-guard
#                                             Swift caller check of the browser
#                                             host and its signed browser parent
#   Apassy.app/Contents/MacOS/apassy-credential-bridge
#                                             Swift bridge between the AutoFill
#                                             extension and the app (signed, app
#                                             group only). ONLY with the extension
#   Apassy.app/Contents/PlugIns/ApassyAutoFill.appex
#                                             Mac AutoFill credential provider
#                                             (passkeys, passwords, one-time codes).
#                                             ONLY with both provider profiles.
#                                             Both are built by
#                                             scripts/build-credential-provider.sh
#   Apassy.app/Contents/Resources/browser-extension
#                                             The browser extension, for
#                                             "Load unpacked" (extension/)
#   Apassy.app/Contents/Resources/apassy-agent-host.sb
#                                             Seatbelt profile for the launcher
#   Apassy.app/Contents/MacOS/apassy-helper   Swift helper: Touch ID
#   Apassy.app/Contents/Helpers/ApassyKeychain.app
#                                             Swift helper with its own bundle
#                                             and profile: Keychain commands
#   Apassy.app/Contents/Helpers/ApassyNotify.app
#                                             Swift notifier with its own bundle
#                                             (com.wydrox.apassy.notify):
#                                             notifications (goal item N1)
#
# The keychain helper needs a provisioning profile for the App ID
# com.wydrox.apassy.keychain. Without a profile, the script still builds a
# signed app. Then each keychain command returns keychain_unavailable: Touch ID
# can confirm actions but cannot unlock the vault (ADR 0010, Limits).
#
# The helpers and the notifier answer only the signed Apassy app that contains
# them (native/ApassyHelper/Caller.swift). The checks at the end start them through
# a signed probe parent, and check the agent profile with the signed bundle.
#
# The AutoFill extension is a restricted entitlement. It needs a profile for
# com.wydrox.apassy.autofill AND a profile for the main app com.wydrox.apassy
# (the app embeds it as Contents/embedded.provisionprofile). With both valid
# profiles, the app has the extension and signs with the AutoFill entitlement.
# With a missing or invalid profile, the app has NO extension, NO bridge, and the
# empty entitlements, because AMFI stops a program that has a restricted
# entitlement without its profile, and a bridge without the extension does
# nothing. The profile checks are in scripts/build-credential-provider.sh, not here.
#
# Usage: scripts/build-app.sh [--provision]
#   --provision   Before the build, run Xcode automatic signing
#                 (xcodebuild -allowProvisioningUpdates) to register the App ID
#                 and download a development profile. This needs an Apple ID
#                 in Xcode > Settings > Accounts.
#
# Environment:
#   APASSY_SIGN_IDENTITY     codesign identity (SHA-1 or name). Default: the
#                            only valid "Apple Development" identity. A
#                            "Developer ID Application" identity signs with a
#                            secure timestamp, as notarization needs
#                            (scripts/build-dmg.sh).
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
#                            Contents/Resources/models/. Not set: the
#                            checkpoint of this Mac,
#                            $APASSY_LAYA_DIR/models/apassy-base-v1.safetensors,
#                            if it exists (not in GitHub Actions). If it
#                            does not match the manifest, a warning and no
#                            model. Set but empty: no model.
#   APASSY_LAYA_DIR          the Laya folder. Default:
#                            ~/Library/Application Support/Apassy/laya.
#   APASSY_BUILD_DATE        build time for the build identity,
#                            YYYY-MM-DDTHH:MM:SSZ (UTC). Default: now. The
#                            CI workflow sets it before the release build.
#   APASSY_AUTOFILL_PROFILE  path to the profile for the AutoFill extension
#                            (com.wydrox.apassy.autofill). No default search.
#   APASSY_PROVIDER_APP_PROFILE
#                            path to the profile for the main app
#                            (com.wydrox.apassy) with the AutoFill capability.
#   APASSY_REQUIRE_PROVIDER  set to 1 to fail unless the build includes the
#                            extension, signed with both valid profiles.
#   APASSY_PREBUILT_DIR      directory of the verified CI release artifact.
#                            Skips only the Rust build. Requires Python 3.11+,
#                            APASSY_BUILD_DATE, APASSY_BUILD_COMMIT, and
#                            APASSY_PREBUILT_RUN_ID / APASSY_PREBUILT_RUN_ATTEMPT.
#
# The build identity: the release build gets APASSY_BUILD_COMMIT (git HEAD) and
# APASSY_BUILD_DATE. The app compares them with latest.json for updates
# (docs/operations/updates.md).
#
# See docs/operations/native-app.md and docs/operations/base-model.md.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

APP_ID="com.wydrox.apassy"
KEYCHAIN_APP_ID="${APASSY_KEYCHAIN_BUNDLE_ID:-com.wydrox.apassy.keychain}"
KEYCHAIN_EXE="ApassyKeychain"
# The notifier. Its signing identifier must be its bundle ID: macOS refuses a
# notification client with another identifier (docs/operations/native-app.md).
NOTIFY_APP_ID="com.wydrox.apassy.notify"
NOTIFY_EXE="ApassyNotify"
OUT="$ROOT/target/Apassy.app"
STAGE="$ROOT/target/app-stage"
NATIVE_OUT="$ROOT/target/native"
DEPLOYMENT_TARGET="15.0"

PROVISION=0
for arg in "$@"; do
  case "$arg" in
    --provision) PROVISION=1 ;;
    -h|--help) awk 'NR > 1 && /^#/ {print; next} NR > 1 {exit}' "$0"; exit 0 ;;
    *) echo "build-app: unknown option: $arg" >&2; exit 2 ;;
  esac
done

[[ "$KEYCHAIN_APP_ID" =~ ^[A-Za-z0-9.-]+$ ]] || { echo "build-app: invalid APASSY_KEYCHAIN_BUNDLE_ID" >&2; exit 2; }
case "${APASSY_REQUIRE_PROVIDER:-0}" in
  0|1) ;;
  *) echo "build-app: APASSY_REQUIRE_PROVIDER must be 0 or 1" >&2; exit 2 ;;
esac

step() { printf '\n==> %s\n' "$*"; }
fail() { printf '\nbuild-app: FAILED: %s\n' "$*" >&2; exit 1; }
warn() { printf 'build-app: WARNING: %s\n' "$*" >&2; }

TMP="$(mktemp -d "${TMPDIR:-/tmp}/apassy-build.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

# ---------------------------------------------------------------- checks
step "Check the host and tools"
[ "$(uname -s)" = "Darwin" ] || fail "this script runs on macOS only"
[ "$(uname -m)" = "arm64" ] || fail "this script builds for arm64 only"
for tool in xcrun codesign security plutil openssl file python3 /usr/libexec/PlistBuddy; do
  command -v "$tool" >/dev/null 2>&1 || fail "missing tool: $tool"
done
if [ -n "${APASSY_PREBUILT_DIR:-}" ]; then
  command -v python3 >/dev/null 2>&1 || fail "missing tool: python3 (3.11 or later)"
else
  command -v cargo >/dev/null 2>&1 || fail "missing tool: cargo"
fi
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
# Notarization refuses code without a secure timestamp. A development build
# does not go to Apple, so it skips the call to the timestamp server.
case "$SIGN_NAME" in
  "Developer ID Application: "*) SIGN_TIMESTAMP="--timestamp" ;;
  *) SIGN_TIMESTAMP="--timestamp=none" ;;
esac

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

# ---------------------------------------------------------------- provider
# The Mac AutoFill credential provider (docs/operations/mac-passkeys.md).
# scripts/build-credential-provider.sh builds and signs the bridge, checks both
# profiles, and signs the extension only when both are valid. This script does not
# check a profile itself. It reads provider-status.txt and checks the files.
#   included  bridge and extension in the app, main app signed with the AutoFill
#             entitlement and its profile
#   none      no bridge, no extension, main app has no entitlements (no valid
#             profiles, or the team cannot use the provider)
step "Build the Mac AutoFill credential provider"
PROVIDER_TEAM="7S3F9767BM"
PROVIDER_OUT="$ROOT/target/credential-provider"
BRIDGE_ID="$APP_ID.credential-bridge"
APPEX_ID="$APP_ID.autofill"
BRIDGE_EXE="apassy-credential-bridge"
APPEX_NAME="ApassyAutoFill.appex"
PROVIDER_MODE="none"
PROVIDER_REASON=""
PROVIDER_OFFERS=""
if [ "${CERT_TEAM:-}" != "$PROVIDER_TEAM" ]; then
  # The app group, the App IDs, and the code checks of the provider name this team.
  PROVIDER_REASON="the signing certificate is in team ${CERT_TEAM:-unknown}, the provider needs team $PROVIDER_TEAM"
  [ "${APASSY_REQUIRE_PROVIDER:-0}" != "1" ] || fail "APASSY_REQUIRE_PROVIDER=1, but $PROVIDER_REASON"
else
  # The app routes passkeys, passwords, and one-time codes, so the extension offers all three.
  PROVIDER_ARGS=(--sign "$SIGN_SHA1" --with-passwords-and-codes)
  [ -z "${APASSY_AUTOFILL_PROFILE:-}" ] || PROVIDER_ARGS+=(--appex-profile "$APASSY_AUTOFILL_PROFILE")
  [ -z "${APASSY_PROVIDER_APP_PROFILE:-}" ] || PROVIDER_ARGS+=(--app-profile "$APASSY_PROVIDER_APP_PROFILE")
  [ "${APASSY_REQUIRE_PROVIDER:-0}" != "1" ] || PROVIDER_ARGS+=(--require-provider)
  /bin/bash "$ROOT/scripts/build-credential-provider.sh" "${PROVIDER_ARGS[@]}" \
    || fail "scripts/build-credential-provider.sh failed"
  PROVIDER_STATUS="$PROVIDER_OUT/provider-status.txt"
  [ -s "$PROVIDER_STATUS" ] || fail "the provider build wrote no $PROVIDER_STATUS"
  status_get() { sed -n "s/^$1: //p" "$PROVIDER_STATUS" | head -n 1; }
  PROVIDER_OFFERS="$(status_get offers)"
  case "$(status_get provider)" in
    included)
      PROVIDER_MODE="included"
      [ "$PROVIDER_OFFERS" = "passkeys, passwords, one-time codes" ] \
        || fail "provider: included, but it offers \"$PROVIDER_OFFERS\", not passkeys, passwords, and one-time codes"
      for file in "$PROVIDER_OUT/$BRIDGE_EXE" \
          "$PROVIDER_OUT/$APPEX_NAME/Contents/Info.plist" \
          "$PROVIDER_OUT/$APPEX_NAME/Contents/embedded.provisionprofile" \
          "$PROVIDER_OUT/Apassy-provider.provisionprofile" \
          "$PROVIDER_OUT/entitlements/Apassy-provider.entitlements"; do
        [ -s "$file" ] || fail "provider: included, but $file is missing"
      done
      ;;
    "not included")
      PROVIDER_MODE="none"
      PROVIDER_REASON="$(status_get reason)"
      ;;
    *) fail "unreadable provider status in $PROVIDER_STATUS" ;;
  esac
  [ "${APASSY_REQUIRE_PROVIDER:-0}" != "1" ] || [ "$PROVIDER_MODE" = "included" ] \
    || fail "APASSY_REQUIRE_PROVIDER=1, but the provider is not included: $PROVIDER_REASON"
fi
if [ "$PROVIDER_MODE" = "included" ]; then
  echo "Provider: included (AutoFill extension signed with both profiles; offers: $PROVIDER_OFFERS)"
else
  warn "PROVIDER NOT INCLUDED: ${PROVIDER_REASON:-unknown}"
  warn "The app has no AutoFill extension and no credential bridge, so macOS cannot offer Apassy as a passkey, password, or code provider. The main app has no AutoFill entitlement."
fi

# ---------------------------------------------------------------- build
step "Select the Rust release binaries"
# The build identity (docs/operations/updates.md). The app reads both values
# with option_env!. Cargo builds again when a value changes, so the release
# workflow sets the same values for its own first build.
BUILD_COMMIT="$(git rev-parse HEAD 2>/dev/null || true)"
BUILD_DATE="${APASSY_BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
[[ "$BUILD_DATE" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] \
  || fail "APASSY_BUILD_DATE must have the form YYYY-MM-DDTHH:MM:SSZ"
if [[ "$BUILD_COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
  echo "Build:    $BUILD_COMMIT, $BUILD_DATE"
  if [ -n "$(git status --porcelain --untracked-files=no 2>/dev/null)" ]; then
    warn "the working tree has changes. The app names commit $BUILD_COMMIT all the same."
  fi
else
  BUILD_COMMIT=""
  BUILD_DATE=""
  warn "git cannot name the commit. The app has no build identity and updates only to a higher version."
fi
RUST_BIN_DIR="$ROOT/target/release"
verify_prebuilt() {
  [ -n "$BUILD_COMMIT" ] || fail "the prebuilt artifact requires a git commit"
  [ "${APASSY_BUILD_COMMIT:-}" = "$BUILD_COMMIT" ] || fail "APASSY_BUILD_COMMIT does not match git HEAD"
  [ -n "${APASSY_BUILD_DATE:-}" ] || fail "the prebuilt artifact requires APASSY_BUILD_DATE"
  [ -n "${APASSY_PREBUILT_RUN_ID:-}" ] || fail "the prebuilt artifact requires APASSY_PREBUILT_RUN_ID"
  [ -n "${APASSY_PREBUILT_RUN_ATTEMPT:-}" ] || fail "the prebuilt artifact requires APASSY_PREBUILT_RUN_ATTEMPT"
  python3 "$ROOT/scripts/ci-release-artifact.py" verify \
    --directory "$APASSY_PREBUILT_DIR" --commit "$BUILD_COMMIT" --date "$BUILD_DATE" \
    --run-id "$APASSY_PREBUILT_RUN_ID" --run-attempt "$APASSY_PREBUILT_RUN_ATTEMPT" \
    || fail "the prebuilt release artifact did not pass verification"
}
if [ -n "${APASSY_PREBUILT_DIR:-}" ]; then
  verify_prebuilt
  RUST_BIN_DIR="$APASSY_PREBUILT_DIR"
else
  step "Build the Rust binaries (release)"
  APASSY_BUILD_COMMIT="$BUILD_COMMIT" APASSY_BUILD_DATE="$BUILD_DATE" \
    cargo build --release --locked --features desktop,vault --bin apassy --bin apassy-mcp --bin apassy-hook --bin apassy-sandbox --bin apassy-browser-host
fi

step "Build the Swift helper"
mkdir -p "$NATIVE_OUT"
# No `-D APASSY_HELPER_DEV`: a release helper does not contain the development
# override of the caller check.
xcrun --sdk macosx swiftc -sdk "$SDK" -O -swift-version 5 -warnings-as-errors \
  -target "arm64-apple-macos$DEPLOYMENT_TARGET" \
  -o "$NATIVE_OUT/apassy-helper" native/ApassyHelper/*.swift
if LC_ALL=C grep -aq "APASSY_HELPER_DEV_ANY_CALLER" "$NATIVE_OUT/apassy-helper"; then
  fail "the helper contains the development caller override"
fi
echo "ok: the helper has no development caller override"
# The notifier shares the protocol and the caller check with the helper.
xcrun --sdk macosx swiftc -sdk "$SDK" -O -swift-version 5 -warnings-as-errors \
  -target "arm64-apple-macos$DEPLOYMENT_TARGET" \
  -o "$NATIVE_OUT/$NOTIFY_EXE" native/ApassyNotify/*.swift \
  native/ApassyHelper/Protocol.swift native/ApassyHelper/Caller.swift
if LC_ALL=C grep -aq "APASSY_HELPER_DEV_ANY_CALLER" "$NATIVE_OUT/$NOTIFY_EXE"; then
  fail "the notifier contains the development caller override"
fi
echo "ok: the notifier has no development caller override"
# The browser host and the app use this guard to check operating-system audit
# tokens and code signatures. A native-host argument is not a caller proof.
xcrun --sdk macosx swiftc -sdk "$SDK" -O -swift-version 6 -warnings-as-errors \
  -target "arm64-apple-macos$DEPLOYMENT_TARGET" \
  -o "$NATIVE_OUT/apassy-browser-guard" native/ApassyBrowserGuard/*.swift
if LC_ALL=C grep -aq "selftest-" "$NATIVE_OUT/apassy-browser-guard"; then
  fail "the browser guard contains self-test code; build it without APASSY_BROWSER_GUARD_SELFTEST"
fi
# The caller probe starts a helper as its child. It never goes into the bundle.
xcrun --sdk macosx swiftc -sdk "$SDK" -O -swift-version 5 -warnings-as-errors \
  -target "arm64-apple-macos$DEPLOYMENT_TARGET" \
  -o "$TMP/caller-probe" native/ApassyCallerProbe/main.swift

# ---------------------------------------------------------------- assemble
step "Assemble the app bundle"
VERSION="$(awk -F'"' '/^version = / {print $2; exit}' Cargo.toml)"
[ -n "$VERSION" ] || fail "cannot read the package version from Cargo.toml"
rm -rf "$STAGE" "$OUT"
APP="$STAGE/Apassy.app"
KC_APP="$APP/Contents/Helpers/ApassyKeychain.app"
NT_APP="$APP/Contents/Helpers/ApassyNotify.app"
mkdir -p "$APP/Contents/MacOS" "$KC_APP/Contents/MacOS" "$NT_APP/Contents/MacOS"
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
# The build identity in the signed Info.plist. An update of the same version
# must be a later build (docs/operations/updates.md).
if [ -n "$BUILD_COMMIT" ]; then
  /usr/libexec/PlistBuddy -c "Add :ApassyBuildCommit string $BUILD_COMMIT" \
    -c "Add :ApassyBuildDate string $BUILD_DATE" "$APP/Contents/Info.plist" >/dev/null
  plutil -lint "$APP/Contents/Info.plist" >/dev/null
fi
fill_plist packaging/ApassyKeychain-Info.plist "$KC_APP/Contents/Info.plist"
fill_plist packaging/ApassyNotify-Info.plist "$NT_APP/Contents/Info.plist"
[ "$(plutil -extract CFBundleIdentifier raw -o - "$NT_APP/Contents/Info.plist")" = "$NOTIFY_APP_ID" ] \
  || fail "the notifier Info.plist does not have the bundle ID $NOTIFY_APP_ID"
[ "$(plutil -extract CFBundleExecutable raw -o - "$NT_APP/Contents/Info.plist")" = "$NOTIFY_EXE" ] \
  || fail "the notifier Info.plist does not name $NOTIFY_EXE"
printf 'APPL????' >"$APP/Contents/PkgInfo"
printf 'APPL????' >"$KC_APP/Contents/PkgInfo"
printf 'APPL????' >"$NT_APP/Contents/PkgInfo"
if [ -n "${APASSY_PREBUILT_DIR:-}" ]; then
  verify_prebuilt
fi
cp "$RUST_BIN_DIR/apassy" "$RUST_BIN_DIR/apassy-mcp" "$RUST_BIN_DIR/apassy-hook" \
  "$RUST_BIN_DIR/apassy-sandbox" "$RUST_BIN_DIR/apassy-browser-host" "$APP/Contents/MacOS/"
# The launcher reads the profile from Resources without the repository or a
# profile flag. The app signature seals this resource.
mkdir -p "$APP/Contents/Resources"
cp sandbox/apassy-agent-host.sb "$APP/Contents/Resources/"
# The browser extension (ADR 0021). The owner loads this folder with "Load
# unpacked", so an update of the app updates the extension. The app signature
# seals it. A browser refuses a file whose name starts with "_".
EXT_VERSION="$(plutil -extract version raw -o - extension/manifest.json)"
[ "$EXT_VERSION" = "$VERSION" ] \
  || fail "extension/manifest.json has version $EXT_VERSION, Cargo.toml has $VERSION"
cp -R extension "$APP/Contents/Resources/browser-extension"
find "$APP/Contents/Resources/browser-extension" -name .DS_Store -delete
[ -z "$(find "$APP/Contents/Resources/browser-extension" -name '_*')" ] \
  || fail "the browser extension has a file whose name starts with _"
cp "$NATIVE_OUT/apassy-helper" "$APP/Contents/MacOS/apassy-helper"
cp "$NATIVE_OUT/apassy-browser-guard" "$APP/Contents/MacOS/apassy-browser-guard"
# The provider (already signed by scripts/build-credential-provider.sh, so the nested
# code is signed before the app). ditto keeps the signature, the resources, and the
# embedded profile of the extension. The bridge, the extension, and the profile of the main
# app go in only when the builder validated both profiles.
if [ "$PROVIDER_MODE" = "included" ]; then
  if LC_ALL=C grep -aq "APASSY_BRIDGE_DEV" "$PROVIDER_OUT/$BRIDGE_EXE"; then
    fail "the bridge contains a development override"
  fi
  ditto "$PROVIDER_OUT/$BRIDGE_EXE" "$APP/Contents/MacOS/$BRIDGE_EXE" || fail "cannot copy the bridge"
  [ "$(plutil -extract CFBundleShortVersionString raw -o - "$PROVIDER_OUT/$APPEX_NAME/Contents/Info.plist")" = "$VERSION" ] \
    || fail "the extension has another version than $VERSION"
  mkdir -p "$APP/Contents/PlugIns"
  ditto "$PROVIDER_OUT/$APPEX_NAME" "$APP/Contents/PlugIns/$APPEX_NAME" || fail "cannot copy the extension"
  ditto "$PROVIDER_OUT/Apassy-provider.provisionprofile" "$APP/Contents/embedded.provisionprofile" \
    || fail "cannot copy the profile of the main app"
fi
cp "$NATIVE_OUT/apassy-helper" "$KC_APP/Contents/MacOS/$KEYCHAIN_EXE"
cp "$NATIVE_OUT/$NOTIFY_EXE" "$NT_APP/Contents/MacOS/$NOTIFY_EXE"
# The app icon (scripts/make-icon.sh). macOS shows the icon of the notifier on
# each notification, and the icon of the keychain helper on its Touch ID prompt.
[ -f packaging/AppIcon.icns ] || fail "missing packaging/AppIcon.icns. Run scripts/make-icon.sh."
for bundle in "$APP" "$KC_APP" "$NT_APP"; do
  mkdir -p "$bundle/Contents/Resources"
  cp packaging/AppIcon.icns "$bundle/Contents/Resources/AppIcon.icns"
done

# Goal B8: the base-model checkpoint goes into the bundle before the signature,
# so the signature seals it. The copy must match tools/basemodel/manifest.json.
# Without APASSY_BASE_MODEL, a local build ships the checkpoint of this Mac. If
# that checkpoint does not match the manifest (an old or retrained one), the app
# ships no model: scripts/install.sh must not fail on it. A mismatch of
# APASSY_BASE_MODEL stops the build. The release workflow sets APASSY_BASE_MODEL,
# or ships none.
MODEL_MODE="none"
MODEL_SOURCE=""
MODEL_LOCAL=""
MODEL_BAD=""
LOCAL_MODEL="${APASSY_LAYA_DIR:-$HOME/Library/Application Support/Apassy/laya}/models/apassy-base-v1.safetensors"
if [ -n "${APASSY_BASE_MODEL:-}" ]; then
  MODEL_SOURCE="$APASSY_BASE_MODEL"
  [ -f "$MODEL_SOURCE" ] || fail "APASSY_BASE_MODEL does not exist: $MODEL_SOURCE"
elif [ -z "${APASSY_BASE_MODEL+set}" ] && [ -z "${GITHUB_ACTIONS:-}" ] && [ -f "$LOCAL_MODEL" ]; then
  MODEL_SOURCE="$LOCAL_MODEL"
  MODEL_LOCAL=1
fi
if [ -n "$MODEL_SOURCE" ]; then
  step "Copy the base-model checkpoint"
  echo "Checkpoint: $MODEL_SOURCE"
  MANIFEST="$ROOT/tools/basemodel/manifest.json"
  [ -f "$MANIFEST" ] || fail "missing $MANIFEST"
  command -v shasum >/dev/null 2>&1 || fail "missing tool: shasum"
  manifest_get() { plutil -extract "$1" raw -o - "$MANIFEST" 2>/dev/null || fail "manifest has no $1"; }
  MODEL_FILE="$(manifest_get checkpoint.file)"
  MODEL_SHA="$(manifest_get checkpoint.sha256)"
  MODEL_SIZE="$(manifest_get checkpoint.size_bytes)"
  MODEL_VERSION="$(manifest_get version)"
  [[ "$MODEL_FILE" =~ ^[A-Za-z0-9._-]+\.safetensors$ ]] || fail "invalid checkpoint.file in the manifest: $MODEL_FILE"
  [[ "$MODEL_SHA" =~ ^[0-9a-f]{64}$ ]] || fail "invalid checkpoint.sha256 in the manifest"
  [ "$MODEL_VERSION" = "apassy-base-v1+${MODEL_SHA:0:8}" ] || fail "manifest version $MODEL_VERSION does not match the SHA-256"
  GOT_SIZE="$(stat -f %z "$MODEL_SOURCE")"
  if [ "$GOT_SIZE" != "$MODEL_SIZE" ]; then
    MODEL_BAD="checkpoint size $GOT_SIZE does not match the manifest ($MODEL_SIZE)"
  else
    GOT_SHA="$(shasum -a 256 "$MODEL_SOURCE" | awk '{print $1}')"
    [ "$GOT_SHA" = "$MODEL_SHA" ] || MODEL_BAD="checkpoint SHA-256 $GOT_SHA does not match the manifest ($MODEL_SHA)"
  fi
  if [ -n "$MODEL_BAD" ]; then
    [ -n "$MODEL_LOCAL" ] || fail "$MODEL_BAD"
    warn "$MODEL_BAD: $MODEL_SOURCE is the checkpoint of this Mac. The app ships no model. Set APASSY_BASE_MODEL to a checkpoint of the manifest to ship one."
  else
    mkdir -p "$APP/Contents/Resources/models"
    cp "$MODEL_SOURCE" "$APP/Contents/Resources/models/$MODEL_FILE"
    cp "$MANIFEST" "$APP/Contents/Resources/models/manifest.json"
    COPY_SHA="$(shasum -a 256 "$APP/Contents/Resources/models/$MODEL_FILE" | awk '{print $1}')"
    [ "$COPY_SHA" = "$MODEL_SHA" ] || fail "the copied checkpoint does not match the manifest"
    MODEL_MODE="$MODEL_VERSION"
    echo "Base model: $MODEL_VERSION ($MODEL_SIZE bytes) from $MODEL_SOURCE"
  fi
fi
if [ "$MODEL_MODE" = "none" ]; then
  if [ -n "$MODEL_BAD" ]; then
    echo "Base model: none. $MODEL_SOURCE does not match the manifest."
  elif [ -n "${APASSY_BASE_MODEL+set}" ]; then
    echo "Base model: none (APASSY_BASE_MODEL is empty)."
  elif [ -n "${GITHUB_ACTIONS:-}" ]; then
    echo "Base model: none (no APASSY_BASE_MODEL in GitHub Actions)."
  else
    echo "Base model: none. No APASSY_BASE_MODEL, and no $LOCAL_MODEL."
  fi
fi

# The training and serving scripts (goal items B8 and B9). The app starts the local
# trainer from Contents/Resources/tools. The code signature seals these files.
TOOLS_DST="$APP/Contents/Resources/tools"
rm -rf "$TOOLS_DST"
mkdir -p "$TOOLS_DST/basemodel" "$TOOLS_DST/finetune"
for f in "$ROOT"/tools/basemodel/*.py "$ROOT"/tools/basemodel/*.sh "$ROOT"/tools/basemodel/requirements.txt "$ROOT"/tools/basemodel/manifest.json; do
  cp "$f" "$TOOLS_DST/basemodel/"
done
for f in "$ROOT"/tools/finetune/*.py "$ROOT"/tools/finetune/requirements.txt; do
  cp "$f" "$TOOLS_DST/finetune/"
done
[ -f "$TOOLS_DST/finetune/local_train.py" ] || fail "the trainer script is missing in the bundle"
echo "Tools:    Contents/Resources/tools (basemodel, finetune)"

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
sign() { codesign --force --sign "$SIGN_SHA1" --options runtime "$SIGN_TIMESTAMP" "$@"; }
sign --entitlements "$KC_ENTITLEMENTS" "$KC_APP"
# A bundle signature takes the identifier from CFBundleIdentifier.
sign --entitlements packaging/Apassy.entitlements "$NT_APP"
sign --identifier "$APP_ID.helper" --entitlements packaging/Apassy.entitlements "$APP/Contents/MacOS/apassy-helper"
for tool in mcp hook sandbox browser-host; do
  sign --identifier "$APP_ID.$tool" --entitlements packaging/Apassy.entitlements "$APP/Contents/MacOS/apassy-$tool"
done
sign --identifier "$APP_ID.browser-guard" --entitlements packaging/Apassy.entitlements "$APP/Contents/MacOS/apassy-browser-guard"
# The bridge and the extension are already signed by scripts/build-credential-provider.sh,
# and their signatures stay. They are checked below. The main app seals them last.
# The AutoFill entitlement of the main app is valid only with its profile: without both
# profiles, AMFI stops the app at launch. So that branch ships no extension and signs
# with no entitlements.
APP_ENTITLEMENTS="packaging/Apassy.entitlements"
if [ "$PROVIDER_MODE" = "included" ]; then
  APP_ENTITLEMENTS="$PROVIDER_OUT/entitlements/Apassy-provider.entitlements"
fi
sign --entitlements "$APP_ENTITLEMENTS" "$APP"

# ---------------------------------------------------------------- verify
step "Verify the signatures"
codesign --verify --deep --strict --verbose=2 "$APP"
SIGNED_CODE=("$APP" "$APP/Contents/MacOS/apassy-mcp" "$APP/Contents/MacOS/apassy-hook" "$APP/Contents/MacOS/apassy-sandbox" "$APP/Contents/MacOS/apassy-browser-host" "$APP/Contents/MacOS/apassy-browser-guard" "$APP/Contents/MacOS/apassy-helper" "$KC_APP" "$NT_APP")
BRIDGE="$APP/Contents/MacOS/$BRIDGE_EXE"
APPEX="$APP/Contents/PlugIns/$APPEX_NAME"
[ "$PROVIDER_MODE" != "included" ] || SIGNED_CODE+=("$BRIDGE" "$APPEX")
for code in "${SIGNED_CODE[@]}"; do
  codesign --verify --strict "$code" 2>"$TMP/verify.txt" || { cat "$TMP/verify.txt" >&2; fail "$code does not verify (strict)"; }
  codesign -d --verbose=2 "$code" >"$TMP/info.txt" 2>&1
  grep -q "flags=.*(runtime)" "$TMP/info.txt" || fail "hardened runtime is off for $code"
  grep -q "TeamIdentifier=${CERT_TEAM:-}" "$TMP/info.txt" || fail "unexpected team for $code"
  echo "$(grep '^Identifier=' "$TMP/info.txt") $(grep '^CodeDirectory' "$TMP/info.txt" | grep -o 'flags=[^ ]*')"
done
# check_identifier CODE IDENTIFIER: the signing identifier and the exact team.
check_identifier() {
  codesign -d --verbose=2 "$1" >"$TMP/info.txt" 2>&1
  grep -qx "Identifier=$2" "$TMP/info.txt" || fail "the signing identifier of $1 is not $2"
  grep -qx "TeamIdentifier=${CERT_TEAM:-}" "$TMP/info.txt" || fail "the team of $1 is not ${CERT_TEAM:-unknown}"
}
check_identifier "$APP" "$APP_ID"
check_identifier "$NT_APP" "$NOTIFY_APP_ID"
echo "ok: the signing identifier of the notifier is its bundle ID"
if [ "$PROVIDER_MODE" = "included" ]; then
  check_identifier "$BRIDGE" "$BRIDGE_ID"
  echo "ok: the bridge is signed as $BRIDGE_ID"
  check_identifier "$APPEX" "$APPEX_ID"
  echo "ok: the extension is signed as $APPEX_ID"
  cmp -s "$APP/Contents/embedded.provisionprofile" "$PROVIDER_OUT/Apassy-provider.provisionprofile" \
    || fail "the profile of the main app is not the profile that the provider build checked"
  cmp -s "$APPEX/Contents/embedded.provisionprofile" "$PROVIDER_OUT/$APPEX_NAME/Contents/embedded.provisionprofile" \
    || fail "the profile of the extension is not the profile that the provider build checked"
  echo "ok: the profiles of the main app and the extension are the profiles that the provider build checked"
else
  [ ! -e "$APP/Contents/PlugIns" ] || fail "provider: not included, but the app has Contents/PlugIns"
  [ ! -e "$BRIDGE" ] || fail "provider: not included, but the app has the credential bridge"
  [ ! -e "$APP/Contents/embedded.provisionprofile" ] || fail "provider: not included, but the main app embeds a profile"
  echo "ok: provider not included: no extension, no bridge, no profile in the main app"
fi
# Print the entitlements of CODE as JSON. No entitlements blob prints {}.
entitlements_json() {
  local xml
  xml="$(codesign -d --entitlements - --xml "$1" 2>/dev/null || true)"
  if [ -z "$xml" ]; then echo "{}"; else printf '%s' "$xml" | plutil -convert json -o - -; echo; fi
}
# Print the entitlements of CODE as XML with sorted keys. None prints nothing.
entitlements_xml() {
  local xml
  xml="$(codesign -d --entitlements - --xml "$1" 2>/dev/null || true)"
  [ -z "$xml" ] || printf '%s' "$xml" | plutil -convert xml1 -o - -
}
# expected_entitlements FILE PLISTBUDDY-COMMAND...: write the entitlements that the
# code must have, built here and not read from the template, so a wrong template fails.
expected_entitlements() {
  local file="$1" command
  shift
  printf '<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0">\n<dict/>\n</plist>\n' >"$file"
  for command in "$@"; do
    /usr/libexec/PlistBuddy -c "$command" "$file" >/dev/null || fail "cannot build the expected entitlements: $command"
  done
}
# check_exact_entitlements CODE EXPECTED-FILE: the same keys and values, no more.
check_exact_entitlements() {
  entitlements_xml "$1" >"$TMP/got.xml"
  plutil -convert xml1 -o "$TMP/want.xml" "$2"
  diff -q "$TMP/got.xml" "$TMP/want.xml" >/dev/null \
    || { diff "$TMP/got.xml" "$TMP/want.xml" >&2 || true; fail "$1 has other entitlements than expected"; }
}
echo "Entitlements of ApassyKeychain.app: $(entitlements_json "$KC_APP")"
for code in "$APP/Contents/MacOS/apassy-mcp" "$APP/Contents/MacOS/apassy-hook" "$APP/Contents/MacOS/apassy-sandbox" "$APP/Contents/MacOS/apassy-browser-host" "$APP/Contents/MacOS/apassy-browser-guard" "$APP/Contents/MacOS/apassy-helper" "$NT_APP"; do
  ENT="$(entitlements_json "$code")"
  [ "$ENT" = "{}" ] || fail "$code has unexpected entitlements: $ENT"
done
echo "Entitlements of apassy-mcp, apassy-hook, apassy-sandbox, apassy-browser-host, apassy-browser-guard, apassy-helper, ApassyNotify.app: {}"
AUTOFILL_KEY="com.apple.developer.authentication-services.autofill-credential-provider"
GROUP="$PROVIDER_TEAM.$APP_ID"
if [ "$PROVIDER_MODE" = "included" ]; then
  # The main app: the AutoFill entitlement and its identity, and nothing else.
  expected_entitlements "$TMP/expect-app.plist" \
    "Add :com.apple.application-identifier string $PROVIDER_TEAM.$APP_ID" \
    "Add :$AUTOFILL_KEY bool true" \
    "Add :com.apple.developer.team-identifier string $PROVIDER_TEAM"
  check_exact_entitlements "$APP" "$TMP/expect-app.plist"
  echo "Entitlements of apassy (provider included): application-identifier, team-identifier, AutoFill. No others."
  expected_entitlements "$TMP/expect-appex.plist" \
    "Add :com.apple.application-identifier string $PROVIDER_TEAM.$APPEX_ID" \
    "Add :$AUTOFILL_KEY bool true" \
    "Add :com.apple.developer.team-identifier string $PROVIDER_TEAM" \
    "Add :com.apple.security.app-sandbox bool true" \
    "Add :com.apple.security.application-groups array" \
    "Add :com.apple.security.application-groups:0 string $GROUP"
  check_exact_entitlements "$APPEX" "$TMP/expect-appex.plist"
  echo "Entitlements of ApassyAutoFill.appex: application-identifier, team-identifier, AutoFill, sandbox, app group $GROUP. No others."
else
  ENT="$(entitlements_json "$APP")"
  [ "$ENT" = "{}" ] || fail "$APP has unexpected entitlements: $ENT"
  echo "Entitlements of apassy: {} (no AutoFill entitlement without the extension and both profiles)"
fi
if [ "$PROVIDER_MODE" = "included" ]; then
  expected_entitlements "$TMP/expect-bridge.plist" \
    "Add :com.apple.security.application-groups array" \
    "Add :com.apple.security.application-groups:0 string $GROUP"
  check_exact_entitlements "$BRIDGE" "$TMP/expect-bridge.plist"
  echo "Entitlements of apassy-credential-bridge: app group $GROUP only. No AutoFill entitlement, no sandbox."
fi

# Key-memory review F7: each program in the bundle has the hardened runtime,
# and no program has an entitlement that lets a debugger read its memory or
# lets injected code run in it.
FORBIDDEN_ENTITLEMENTS="com.apple.security.get-task-allow com.apple.security.cs.disable-library-validation com.apple.security.cs.allow-dyld-environment-variables com.apple.security.cs.allow-unsigned-executable-memory com.apple.security.cs.allow-jit"
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
# 9 programs of the app and its helpers. The provider adds the bridge and the extension (11).
case "$PROVIDER_MODE" in
  none) EXPECTED_PROGRAMS=9 ;;
  included) EXPECTED_PROGRAMS=11 ;;
esac
[ "$PROGRAMS" = "$EXPECTED_PROGRAMS" ] || fail "expected $EXPECTED_PROGRAMS programs in the bundle (provider $PROVIDER_MODE), found $PROGRAMS"
echo "Hardened runtime on all $PROGRAMS programs. None has get-task-allow, disable-library-validation, allow-dyld-environment-variables, allow-unsigned-executable-memory, or allow-jit."

# ---------------------------------------------------------------- self-check
step "Run the signed programs"
check_output() { # label, output, pattern
  printf '%s\n' "$2" | grep -Eq "$3" || fail "$1: unexpected output: $2"
  echo "ok: $1"
}
"$APP/Contents/MacOS/apassy" --smoke-test >"$TMP/smoke.txt" 2>&1 || { cat "$TMP/smoke.txt" >&2; fail "apassy --smoke-test failed"; }
echo "ok: apassy --smoke-test"
if [ -n "$BUILD_COMMIT" ]; then
  LC_ALL=C grep -aqF "$BUILD_COMMIT" "$APP/Contents/MacOS/apassy" \
    || fail "the app does not contain its build identity ($BUILD_COMMIT)"
  echo "ok: the app names build $BUILD_COMMIT"
fi
for tool in mcp hook; do
  check_output "apassy-$tool --version" "$("$APP/Contents/MacOS/apassy-$tool" --version)" "^apassy-$tool $VERSION$"
done
"$APP/Contents/MacOS/apassy-sandbox" --help >"$TMP/sandbox-help.txt"
check_output "apassy-sandbox --help" "$(cat "$TMP/sandbox-help.txt")" "^apassy-sandbox"
# The browser host (ADR 0021): another caller gets exit status 2. The extension
# must also have a signed browser parent. A message is a 4-byte length, then JSON.
BH_EXE="$APP/Contents/MacOS/apassy-browser-host"
# A shell variable cannot hold the NUL bytes of the length, so a function writes it.
bh_status() { printf '\x16\x00\x00\x00{"v":1,"cmd":"status"}'; }
if bh_status | "$BH_EXE" "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/" >/dev/null 2>&1; then
  fail "apassy-browser-host answered another extension"
fi
echo "ok: apassy-browser-host refuses another extension"
# Keep stdin open until the answer arrives. EOF cancels requests by design.
bh_answer() {
  python3 - "$BH_EXE" "$TMP/none.sock" "$1" <<'PY'
import json, os, selectors, struct, subprocess, sys, time
environment = dict(os.environ, APASSY_BROWSER_SOCKET=sys.argv[2])
process = subprocess.Popen([sys.argv[1], 'chrome-extension://bbnpgnjnfjlbgggmpnhejpmfjhmmhiih/'],
                           stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           env=environment)
selector = selectors.DefaultSelector()
selector.register(process.stdout, selectors.EVENT_READ)
deadline = time.monotonic() + 10
def read_exact(count):
    data = bytearray()
    while len(data) < count:
        if not selector.select(max(0, deadline - time.monotonic())):
            raise RuntimeError('The browser host did not answer.')
        part = os.read(process.stdout.fileno(), count - len(data))
        if not part:
            raise RuntimeError('The browser host ended before its answer.')
        data.extend(part)
    return bytes(data)
try:
    request = json.dumps({'v': 1, 'cmd': sys.argv[3]}).encode()
    process.stdin.write(struct.pack('<I', len(request)) + request)
    process.stdin.flush()
    length, = struct.unpack('<I', read_exact(4))
    if not 0 < length <= 1024 * 1024:
        raise RuntimeError('The browser host sent an invalid length.')
    print(read_exact(length).decode())
finally:
    selector.close()
    process.stdin.close()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
PY
}
check_output "apassy-browser-host without the app" "$(bh_answer status)" '"code":"not_running"'
check_output "apassy-browser-host refuses a shell passkey request" \
  "$(bh_answer passkey_get)" '"code":"unsupported"'

H_EXE="$APP/Contents/MacOS/apassy-helper"
KC_EXE="$KC_APP/Contents/MacOS/$KEYCHAIN_EXE"
NT_EXE="$NT_APP/Contents/MacOS/$NOTIFY_EXE"
REFUSED='"error":"caller_not_allowed".*"ok":false'
# check_lines LABEL OUTPUT PATTERN...: line N of OUTPUT matches PATTERN N.
check_lines() {
  local label="$1" output="$2" n=1
  shift 2
  for pattern in "$@"; do
    check_output "$label, line $n" "$(sed -n "${n}p" <<<"$output")" "$pattern"
    n=$((n + 1))
  done
}

# This shell is not the signed Apassy app. Each helper starts and refuses
# each request, also with the development override in the environment.
HELPER_OUT="$(printf '%s\n' '{"cmd":"ping"}' '{"cmd":"notify_status"}' '{"cmd":"bogus"}' | "$H_EXE")" \
  || fail "apassy-helper did not run"
check_lines "apassy-helper refuses the shell" "$HELPER_OUT" "$REFUSED" "$REFUSED" "$REFUSED"
check_output "apassy-helper ignores APASSY_HELPER_DEV_ANY_CALLER" \
  "$(printf '%s\n' '{"cmd":"ping"}' | APASSY_HELPER_DEV_ANY_CALLER=1 "$H_EXE")" "$REFUSED"
KC_OUT="$(printf '%s\n' '{"cmd":"ping"}' '{"cmd":"keychain_exists","account":"build-check"}' | "$KC_EXE")" \
  || fail "the keychain helper did not run. Check: log show --last 2m --predicate 'process == \"amfid\"'"
check_lines "keychain helper refuses the shell" "$KC_OUT" "$REFUSED" "$REFUSED"
# The notifier requests in these checks never ask for permission and never
# post: a caller that is not Apassy gets a refusal, and the signed parent
# below sends only ping, notify_status, preview, and invalid requests.
NOTIFY_WAITING='{"cmd":"preview","event":"approval_waiting","agent":"build-check"}'
NOTIFY_FREE_TEXT='{"cmd":"notify","id":"build-check","event":"request_blocked","agent":"build-check","title":"free text","body":"free text"}'
NT_OUT="$(printf '%s\n' '{"cmd":"ping"}' '{"cmd":"notify_status"}' "$NOTIFY_WAITING" | "$NT_EXE")" \
  || fail "the notifier did not run"
check_lines "notifier refuses the shell" "$NT_OUT" "$REFUSED" "$REFUSED" "$REFUSED"
check_output "notifier ignores APASSY_HELPER_DEV_ANY_CALLER" \
  "$(printf '%s\n' '{"cmd":"ping"}' | APASSY_HELPER_DEV_ANY_CALLER=1 "$NT_EXE")" "$REFUSED"

# The bridge (docs/operations/mac-passkeys.md) checks its parent before it opens a
# socket. A shell is not the signed Apassy app, so the bridge exits with status 1.
BR_REFUSED='"code":"caller_not_allowed"'
if [ "$PROVIDER_MODE" = "included" ]; then
  BR_STATUS=0
  BR_OUT="$("$BRIDGE" </dev/null 2>/dev/null)" || BR_STATUS=$?
  [ "$BR_STATUS" = "1" ] || fail "the bridge did not refuse the shell (status $BR_STATUS): $BR_OUT"
  check_output "the bridge refuses the shell" "$BR_OUT" "$BR_REFUSED"
fi

# probe_app DIR IDENTIFIER: a scratch copy of the bundle in DIR. The caller
# probe replaces the main program, and the copy is signed with IDENTIFIER. The
# helpers and the bridge in the copy keep their signatures. Print the path of the copy.
# The copy gets only MacOS, Helpers, Resources, Info.plist, and PkgInfo. It has no
# PlugIns and no profile of the main app: a copy with the real extension would
# register a second ApassyAutoFill with LaunchServices, and a fake app with the
# AutoFill entitlement and no valid profile would stop at launch. The copy is signed
# with the empty entitlements.
probe_app() {
  local copy="$1/Apassy.app" ent
  mkdir -p "$copy/Contents" || fail "cannot make $1"
  cp -R "$APP/Contents/MacOS" "$APP/Contents/Helpers" "$APP/Contents/Resources" "$copy/Contents/" \
    || fail "cannot copy the bundle to $1"
  cp "$APP/Contents/Info.plist" "$APP/Contents/PkgInfo" "$copy/Contents/" || fail "cannot copy the bundle to $1"
  cp "$TMP/caller-probe" "$copy/Contents/MacOS/apassy" || fail "cannot copy the probe to $1"
  sign --identifier "$2" --entitlements packaging/Apassy.entitlements "$copy" 2>/dev/null \
    || fail "cannot sign the scratch copy in $1"
  codesign --verify --deep --strict "$copy" 2>/dev/null || fail "the scratch copy in $1 is not valid"
  [ ! -e "$copy/Contents/PlugIns" ] || fail "the scratch copy in $1 has PlugIns"
  [ -z "$(find "$copy" -name '*.appex' -print -quit)" ] || fail "the scratch copy in $1 has an extension"
  [ ! -e "$copy/Contents/embedded.provisionprofile" ] || fail "the scratch copy in $1 has a profile for the main app"
  if plutil -extract NSExtension raw -o - "$copy/Contents/Info.plist" >/dev/null 2>&1; then
    fail "the scratch copy in $1 declares an extension"
  fi
  ent="$(entitlements_json "$copy")"
  [ "$ent" = "{}" ] || fail "the scratch copy in $1 has entitlements: $ent"
  echo "$copy"
}
PROBE_APP="$(probe_app "$TMP/probe-apassy" "$APP_ID")"
PROBE="$PROBE_APP/Contents/MacOS/apassy"
echo "ok: the signed probe copy has no extension, no profile for the main app, and no entitlements"

# The signed parent: the helpers of the copy answer.
HELPER_OUT="$(printf '%s\n' '{"cmd":"ping"}' '{"cmd":"notify_status"}' '{"cmd":"bogus"}' \
  | "$PROBE" "$PROBE_APP/Contents/MacOS/apassy-helper")" || fail "apassy-helper did not run under the signed parent"
check_lines "apassy-helper with the signed parent" "$HELPER_OUT" \
  "\"bundle_id\":\"$APP_ID\".*\"keychain_access_group\":null.*\"ok\":true" \
  '"error":"notifications_unavailable"' \
  '"error":"invalid_request"'
NT_OUT="$(printf '%s\n' '{"cmd":"ping"}' '{"cmd":"notify_status"}' "$NOTIFY_WAITING" "$NOTIFY_FREE_TEXT" '{"cmd":"bogus"}' \
  | "$PROBE" "$PROBE_APP/Contents/Helpers/ApassyNotify.app/Contents/MacOS/$NOTIFY_EXE")" \
  || fail "the notifier did not run under the signed parent"
check_lines "notifier with the signed parent" "$NT_OUT" \
  "\"bundle_id\":\"$NOTIFY_APP_ID\".*\"ok\":true" \
  '"authorization":"[a-z_]+".*"ok":true' \
  '^\{"body":"Agent \\"build-check\\" waits for your decision\. Open Apassy to review\.","ok":true,"title":"Approval waiting"\}$' \
  '"error":"invalid_request"' \
  '"error":"invalid_request"'
KC_OUT="$(printf '%s\n' '{"cmd":"ping"}' '{"cmd":"keychain_exists","account":"build-check"}' \
  | "$PROBE" "$PROBE_APP/Contents/Helpers/ApassyKeychain.app/Contents/MacOS/$KEYCHAIN_EXE")" \
  || fail "the keychain helper did not run under the signed parent"
if [ "$KEYCHAIN_MODE" = "enabled" ]; then
  check_lines "keychain helper with the signed parent" "$KC_OUT" \
    "\"bundle_id\":\"$KEYCHAIN_APP_ID\".*\"keychain_access_group\":\"$TEAM_ID\\.$APP_ID\"" \
    '"exists":(true|false).*"ok":true'
else
  check_lines "keychain helper with the signed parent" "$KC_OUT" \
    "\"bundle_id\":\"$KEYCHAIN_APP_ID\".*\"keychain_access_group\":null" \
    '"error":"keychain_unavailable"'
fi

# Other parents that are signed by the same team: the helpers refuse them.
check_output "helper refuses the signed parent of another bundle" \
  "$(printf '%s\n' '{"cmd":"ping"}' | "$PROBE" "$H_EXE")" "$REFUSED"
check_output "keychain helper refuses the signed parent of another bundle" \
  "$(printf '%s\n' '{"cmd":"ping"}' | "$PROBE" "$KC_EXE")" "$REFUSED"
check_output "notifier refuses the signed parent of another bundle" \
  "$(printf '%s\n' '{"cmd":"ping"}' | "$PROBE" "$NT_EXE")" "$REFUSED"
OTHER_APP="$(probe_app "$TMP/probe-other" "$APP_ID.probe")"
check_output "helper refuses a parent with another identifier" \
  "$(printf '%s\n' '{"cmd":"ping"}' | "$OTHER_APP/Contents/MacOS/apassy" "$OTHER_APP/Contents/MacOS/apassy-helper")" "$REFUSED"
check_output "keychain helper refuses a parent with another identifier" \
  "$(printf '%s\n' '{"cmd":"ping"}' | "$OTHER_APP/Contents/MacOS/apassy" "$OTHER_APP/Contents/Helpers/ApassyKeychain.app/Contents/MacOS/$KEYCHAIN_EXE")" "$REFUSED"
check_output "notifier refuses a parent with another identifier" \
  "$(printf '%s\n' '{"cmd":"ping"}' | "$OTHER_APP/Contents/MacOS/apassy" "$OTHER_APP/Contents/Helpers/ApassyNotify.app/Contents/MacOS/$NOTIFY_EXE")" "$REFUSED"

if [ "$PROVIDER_MODE" = "included" ]; then
  # Each run ends before the bridge opens a socket: the parent is refused, or the copy has
  # no extension. The group container of this Mac stays untouched.
  bridge_under() { # parent probe, bridge: print the answer, ignore the exit status
    "$1" "$2" </dev/null 2>/dev/null || true
  }
  check_output "the bridge refuses the signed parent of another bundle" \
    "$(bridge_under "$PROBE" "$BRIDGE")" "$BR_REFUSED"
  check_output "the bridge refuses a parent with another identifier" \
    "$(bridge_under "$OTHER_APP/Contents/MacOS/apassy" "$OTHER_APP/Contents/MacOS/$BRIDGE_EXE")" "$BR_REFUSED"
  # The signed parent of the copy that contains the bridge passes the parent check. The
  # copy has no extension, so the bridge stops with no_extension. This also shows that the
  # copy has no extension to register.
  check_output "the bridge accepts its signed parent and finds no extension in the probe copy" \
    "$(bridge_under "$PROBE" "$PROBE_APP/Contents/MacOS/$BRIDGE_EXE")" '"code":"no_extension"'
fi

step "Check the agent profile with the signed bundle"
SANDBOX_BIN="$APP/Contents/MacOS/apassy-sandbox"
PROFILE_DIR="$TMP/agent-profile"
mkdir -p "$PROFILE_DIR/d"
chmod 700 "$PROFILE_DIR/d"
in_profile() {
  "$SANDBOX_BIN" --data-dir "$PROFILE_DIR/d" -- "$@"
}
PROFILE_DENIED=("$KC_EXE" "$NT_EXE" "$H_EXE" "$APP/Contents/MacOS/apassy" "$APP/Contents/MacOS/apassy-browser-host" "$APP/Contents/MacOS/apassy-browser-guard")
[ "$PROVIDER_MODE" != "included" ] || PROFILE_DENIED+=("$BRIDGE" "$APPEX/Contents/MacOS/ApassyAutoFill")
for program in "${PROFILE_DENIED[@]}"; do
  if PROFILE_OUT="$(printf '%s\n' '{"cmd":"ping"}' | in_profile "$program" 2>&1)"; then
    fail "${program#"$APP"/} started in the agent profile: $PROFILE_OUT"
  fi
  check_output "the agent profile denies the start of ${program#"$APP"/}" "$PROFILE_OUT" "Operation not permitted"
done
for tool in mcp hook; do
  check_output "apassy-$tool --version in the agent profile" \
    "$(in_profile "$APP/Contents/MacOS/apassy-$tool" --version)" "^apassy-$tool $VERSION$"
done
# LaunchServices is the other way to start the notifier. The profile denies
# each read in the bundle and `lsopen`, so `open` fails before a start.
# tests/isolation/product_profile.rs also checks `open -b` of a registered
# bundle ID.
if PROFILE_OUT="$(in_profile /usr/bin/open -g -j -n "$NT_APP" 2>&1)"; then
  fail "open of ApassyNotify.app worked in the agent profile: $PROFILE_OUT"
fi
check_output "the agent profile denies open of Contents/Helpers/ApassyNotify.app" "$PROFILE_OUT" "(does not exist|-54|failed)"
if in_profile /bin/cp -R "$KC_APP" "$PROFILE_DIR/copy.app" 2>/dev/null; then
  fail "a process in the agent profile copied the keychain helper"
fi
[ -z "$(find "$PROFILE_DIR/copy.app" -type f 2>/dev/null)" ] || fail "a copy of the keychain helper exists"
echo "ok: the agent profile denies a copy of the keychain helper"
# A copy that exists outside the bundle starts in the profile, but the helper
# refuses the caller: its parent is not the signed Apassy app.
cp -R "$KC_APP" "$PROFILE_DIR/ApassyKeychain.app"
KC_OUT="$(printf '%s\n' '{"cmd":"ping"}' '{"cmd":"keychain_exists","account":"build-check"}' \
  | in_profile "$PROFILE_DIR/ApassyKeychain.app/Contents/MacOS/$KEYCHAIN_EXE")" \
  || fail "the keychain helper copy did not start in the agent profile"
check_lines "keychain helper copy in the agent profile refuses the caller" "$KC_OUT" "$REFUSED" "$REFUSED"

mv "$APP" "$OUT"
rm -rf "$STAGE"

step "Done"
echo "App:      $OUT"
echo "Version:  $VERSION"
echo "Build:    ${BUILD_COMMIT:-none (no build identity)}${BUILD_DATE:+, $BUILD_DATE}"
echo "Signed:   $SIGN_NAME"
if [ "$MODEL_MODE" = "none" ]; then
  echo "Model:    none (set APASSY_BASE_MODEL, or put the checkpoint in $LOCAL_MODEL)"
else
  echo "Model:    $MODEL_MODE in Contents/Resources/models, from $MODEL_SOURCE"
fi
case "$PROVIDER_MODE" in
  included)
    echo "Provider: included. AutoFill extension and bridge are signed and in the app; the main app embeds its profile. Offers: $PROVIDER_OFFERS."
    echo "          Not checked by this script: native AutoFill activation and sign-in. Install under /Applications for the sandboxed bridge check."
    ;;
  none)
    echo "Provider: NOT INCLUDED ($PROVIDER_REASON)."
    echo "          The app has no AutoFill extension and no credential bridge: macOS cannot offer Apassy as a passkey, password, or code provider."
    ;;
esac
if [ "$KEYCHAIN_MODE" = "enabled" ]; then
  echo "Keychain: enabled (team $TEAM_ID, group $TEAM_ID.$APP_ID)"
else
  echo "Keychain: DISABLED (no provisioning profile). Touch ID can confirm actions but cannot unlock the vault."
fi
