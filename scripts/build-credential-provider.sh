#!/bin/bash
# Build the Mac AutoFill credential provider of Apassy (docs/operations/mac-passkeys.md):
#
#   target/credential-provider/ApassyAutoFill.appex       the extension
#                                                         (com.wydrox.apassy.autofill)
#   target/credential-provider/apassy-credential-bridge   the bridge
#                                                         (com.wydrox.apassy.credential-bridge)
#   target/credential-provider/entitlements/              the filled entitlements
#   target/credential-provider/provider-status.txt        what the build made
#
# This script does not change target/Apassy.app. scripts/build-app.sh copies the
# products into the bundle: the extension to Contents/PlugIns/, the bridge to
# Contents/MacOS/. Sign order: extension, bridge, then the app.
#
# Usage: scripts/build-credential-provider.sh [options]
#   (none)                 compile both programs unsigned and check the bundle layout
#   --sign IDENTITY        sign the bridge (app group, no profile). With both profiles,
#                          also sign the extension with its restricted entitlements
#   --appex-profile FILE   profile for <team>.com.wydrox.apassy.autofill with the
#                          AutoFill Credential Provider capability
#   --app-profile FILE     profile for <team>.com.wydrox.apassy with the capability (the
#                          main app; checked here, embedded by scripts/build-app.sh)
#   --require-provider     fail unless the extension is signed with valid profiles
#   --with-passwords-and-codes
#                          declare ProvidesPasswords and ProvidesOneTimeCodes. Only when the
#                          app routes autofill_list, autofill_credential, autofill_code, and
#                          credential_identities (mac-passkeys.md, "App routing"). Without
#                          it the extension is a passkey provider only
#   --test                 build and run the synthetic tests. With --sign, also the
#                          signed probe of the code-signing checks (a fake Apassy.app in
#                          target/credential-provider-test, removed at the end; it has no
#                          NSExtension keys, so nothing is registered)
#
# Environment: APASSY_SIGN_IDENTITY, APASSY_AUTOFILL_PROFILE, and
# APASSY_PROVIDER_APP_PROFILE stand for --sign, --appex-profile, and --app-profile.
#
# A profile must be for macOS, for the exact App ID (no wildcard), with the AutoFill
# entitlement, not expired, with the signing certificate, and with this Mac unless it
# provisions all devices (Developer ID). Without both profiles the extension stays
# unsigned and the build reports "provider: not included". With --require-provider
# that is a failure.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

APP_ID="com.wydrox.apassy"
APPEX_ID="com.wydrox.apassy.autofill"
BRIDGE_ID="com.wydrox.apassy.credential-bridge"
TEAM_REQUIRED="7S3F9767BM"
APPEX_EXE="ApassyAutoFill"
BRIDGE_EXE="apassy-credential-bridge"
EXTENSION_POINT="com.apple.authentication-services-credential-provider-ui"
PRINCIPAL_CLASS="ApassyCredentialProviderViewController"
AUTOFILL_KEY="com.apple.developer.authentication-services.autofill-credential-provider"
DEPLOYMENT_TARGET="15.0"
OUT="$ROOT/target/credential-provider"
TEST_OUT="$ROOT/target/credential-provider-test"

SIGN_ID="${APASSY_SIGN_IDENTITY:-}"
APPEX_PROFILE="${APASSY_AUTOFILL_PROFILE:-}"
APP_PROFILE="${APASSY_PROVIDER_APP_PROFILE:-}"
REQUIRE_PROVIDER=0
RUN_TESTS=0
PASSWORDS_AND_CODES="${APASSY_PROVIDER_PASSWORDS_AND_CODES:-0}"
while [ $# -gt 0 ]; do
  case "$1" in
    --sign) SIGN_ID="${2:?--sign needs an identity}"; shift 2 ;;
    --appex-profile) APPEX_PROFILE="${2:?--appex-profile needs a file}"; shift 2 ;;
    --app-profile) APP_PROFILE="${2:?--app-profile needs a file}"; shift 2 ;;
    --require-provider) REQUIRE_PROVIDER=1; shift ;;
    --test) RUN_TESTS=1; shift ;;
    --with-passwords-and-codes) PASSWORDS_AND_CODES=1; shift ;;
    -h|--help) sed -n '2,42p' "$0"; exit 0 ;;
    *) echo "build-credential-provider: unknown option: $1" >&2; exit 2 ;;
  esac
done

step() { printf '\n==> %s\n' "$*"; }
fail() { printf '\nbuild-credential-provider: FAILED: %s\n' "$*" >&2; exit 1; }
warn() { printf 'build-credential-provider: WARNING: %s\n' "$*" >&2; }

TMP="$(mktemp -d "${TMPDIR:-/tmp}/apassy-provider.XXXXXX")"
LSREGISTER=/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister
# The fake Apassy.app of the signed probe never stays on disk or in LaunchServices.
cleanup() {
  if [ -d "$TEST_OUT/Apassy.app" ] && [ -x "$LSREGISTER" ]; then "$LSREGISTER" -u "$TEST_OUT/Apassy.app" >/dev/null 2>&1 || true; fi
  rm -rf "$TMP" "$TEST_OUT"
}
trap cleanup EXIT

# ---------------------------------------------------------------- checks
step "Check the host and tools"
[ "$(uname -s)" = "Darwin" ] || fail "this script runs on macOS only"
[ "$(uname -m)" = "arm64" ] || fail "this script builds for arm64 only"
for tool in xcrun codesign security plutil openssl nm otool /usr/libexec/PlistBuddy; do
  command -v "$tool" >/dev/null 2>&1 || fail "missing tool: $tool"
done
SDK="$(xcrun --sdk macosx --show-sdk-path)" || fail "xcrun cannot find the macOS SDK"
echo "SDK:   $SDK"
echo "Swift: $(xcrun --sdk macosx swiftc --version 2>&1 | head -n 1)"
if [ "$REQUIRE_PROVIDER" = "1" ] && [ -z "$SIGN_ID" ]; then
  fail "--require-provider needs --sign and both profiles"
fi
VERSION="$(awk -F'"' '/^version = / {print $2; exit}' Cargo.toml)"
[ -n "$VERSION" ] || fail "cannot read the package version from Cargo.toml"

SWIFTC=(xcrun --sdk macosx swiftc -sdk "$SDK" -O -swift-version 6 -warnings-as-errors
  -target "arm64-apple-macos$DEPLOYMENT_TARGET")
SHARED=(native/ApassyCredentialBridge/Shared/*.swift)
BRIDGE_SOURCES=(native/ApassyCredentialBridge/*.swift "${SHARED[@]}")
APPEX_SOURCES=(native/ApassyAutoFill/*.swift "${SHARED[@]}")

# ---------------------------------------------------------------- compile
step "Compile the bridge (release, Swift 6, warnings are errors)"
rm -rf "$OUT"
mkdir -p "$OUT/entitlements"
# No `-D APASSY_BRIDGE_DEV`: a release bridge has no development override.
"${SWIFTC[@]}" -o "$OUT/$BRIDGE_EXE" "${BRIDGE_SOURCES[@]}"
if LC_ALL=C grep -aq "APASSY_BRIDGE_DEV" "$OUT/$BRIDGE_EXE"; then
  fail "the bridge contains a development override"
fi
echo "ok: the bridge has no development override"

step "Compile the extension (release, Swift 6, warnings are errors)"
APPEX="$OUT/ApassyAutoFill.appex"
mkdir -p "$APPEX/Contents/MacOS"
# An app extension starts in NSExtensionMain of Foundation, as Xcode links it.
"${SWIFTC[@]}" -parse-as-library -application-extension -module-name ApassyAutoFill \
  -Xlinker -e -Xlinker _NSExtensionMain -Xlinker -application_extension \
  -o "$APPEX/Contents/MacOS/$APPEX_EXE" "${APPEX_SOURCES[@]}"
sed -e "s/\$(MARKETING_VERSION)/$VERSION/g" \
    -e "s/\$(PRODUCT_BUNDLE_IDENTIFIER)/$APPEX_ID/g" \
    -e "s/\$(EXECUTABLE_NAME)/$APPEX_EXE/g" native/ApassyAutoFill/Info.plist >"$APPEX/Contents/Info.plist"
printf 'XPC!????' >"$APPEX/Contents/PkgInfo"
CAPABILITIES="NSExtension:NSExtensionAttributes:ASCredentialProviderExtensionCapabilities"
if [ "$PASSWORDS_AND_CODES" != "1" ]; then
  # The app answers "unsupported" to the password and code calls today: do not offer them.
  /usr/libexec/PlistBuddy -c "Delete :$CAPABILITIES:ProvidesPasswords" \
    -c "Delete :$CAPABILITIES:ProvidesOneTimeCodes" "$APPEX/Contents/Info.plist" >/dev/null
fi

step "Check the extension bundle"
PLIST="$APPEX/Contents/Info.plist"
plutil -lint "$PLIST" >/dev/null
if grep -q '\$(' "$PLIST"; then fail "unfilled variable in $PLIST"; fi
plist_raw() {
  local value
  # Some macOS versions print missing-key errors to stdout. Only return a value
  # when extraction succeeds, so an absent capability stays absent.
  if value="$(plutil -extract "$2" raw -o - "$1" 2>/dev/null)"; then
    printf '%s\n' "$value"
  fi
}
check_value() { # file, key path, expected
  local got
  got="$(plist_raw "$1" "$2")"
  [ "$got" = "$3" ] || fail "$2 is \"$got\", not \"$3\""
}
check_value "$PLIST" CFBundleIdentifier "$APPEX_ID"
check_value "$PLIST" CFBundleExecutable "$APPEX_EXE"
check_value "$PLIST" CFBundlePackageType 'XPC!'
check_value "$PLIST" LSMinimumSystemVersion "$DEPLOYMENT_TARGET"
check_value "$PLIST" NSExtension.NSExtensionPointIdentifier "$EXTENSION_POINT"
check_value "$PLIST" NSExtension.NSExtensionPrincipalClass "$PRINCIPAL_CLASS"
CAPS="NSExtension.NSExtensionAttributes.ASCredentialProviderExtensionCapabilities"
for capability in ProvidesPasskeys ShowsConfigurationUI; do
  check_value "$PLIST" "$CAPS.$capability" true
done
if [ "$PASSWORDS_AND_CODES" = "1" ]; then
  check_value "$PLIST" "$CAPS.ProvidesPasswords" true
  check_value "$PLIST" "$CAPS.ProvidesOneTimeCodes" true
  OFFERS="passkeys, passwords, one-time codes"
else
  for absent in ProvidesPasswords ProvidesOneTimeCodes; do
    [ -z "$(plist_raw "$PLIST" "$CAPS.$absent")" ] || fail "$absent is declared without --with-passwords-and-codes"
  done
  OFFERS="passkeys only"
fi
for absent in SupportsConditionalPasskeyRegistration SupportsCredentialExchange; do
  [ -z "$(plist_raw "$PLIST" "NSExtension.NSExtensionAttributes.ASCredentialProviderExtensionCapabilities.$absent")" ] \
    || fail "the extension must not declare $absent"
done
case "$APPEX_ID" in "$APP_ID".*) ;; *) fail "the extension ID must start with $APP_ID." ;; esac
# Into files first: `grep -q` closes a pipe early, and pipefail would then fail the check.
nm "$APPEX/Contents/MacOS/$APPEX_EXE" >"$TMP/symbols.txt"
nm -u "$APPEX/Contents/MacOS/$APPEX_EXE" >"$TMP/undefined.txt"
grep -q "_OBJC_CLASS_\$_$PRINCIPAL_CLASS\$" "$TMP/symbols.txt" || fail "the extension binary has no class $PRINCIPAL_CLASS"
grep -qx "_NSExtensionMain" "$TMP/undefined.txt" || fail "the extension binary does not start in NSExtensionMain"
for binary in "$APPEX/Contents/MacOS/$APPEX_EXE" "$OUT/$BRIDGE_EXE"; do
  otool -l "$binary" >"$TMP/load.txt"
  grep -q "minos $DEPLOYMENT_TARGET" "$TMP/load.txt" || fail "$binary is not built for macOS $DEPLOYMENT_TARGET"
done
echo "ok: $APPEX_ID, $EXTENSION_POINT, principal class $PRINCIPAL_CLASS, $OFFERS, configuration"
echo "ok: no conditional registration, no credential exchange"

# ---------------------------------------------------------------- identity
SIGN_SHA1=""
TEAM_ID="$TEAM_REQUIRED"
SIGN_TIMESTAMP="--timestamp=none"
if [ -n "$SIGN_ID" ]; then
  step "Select the signing identity"
  [ "$SIGN_ID" != "-" ] || fail "ad hoc signing is not supported: the checks need the team"
  SIGN_LINE="$(security find-identity -v -p codesigning | grep -F "$SIGN_ID" | head -n 1 || true)"
  [ -n "$SIGN_LINE" ] || fail "the identity \"$SIGN_ID\" is not a valid code signing identity"
  SIGN_SHA1="$(printf '%s\n' "$SIGN_LINE" | awk '{print $2}')"
  SIGN_NAME="$(printf '%s\n' "$SIGN_LINE" | sed -E 's/^[^"]*"(.*)"$/\1/')"
  security find-certificate -a -Z -p >"$TMP/certs.txt"
  awk -v want="$SIGN_SHA1" '
    /^SHA-1 hash:/ { keep = ($3 == want) }
    keep && /-----BEGIN CERTIFICATE-----/ { printing = 1 }
    printing { print }
    printing && /-----END CERTIFICATE-----/ { exit }
  ' "$TMP/certs.txt" >"$TMP/sign-cert.pem"
  [ -s "$TMP/sign-cert.pem" ] || fail "cannot export the certificate $SIGN_SHA1"
  TEAM_ID="$(openssl x509 -in "$TMP/sign-cert.pem" -noout -subject \
    | grep -oE 'OU ?= ?[A-Z0-9]{10}' | grep -oE '[A-Z0-9]{10}$' | head -n 1 || true)"
  # The app group and the code checks name this team (BridgeProtocol.swift).
  [ "$TEAM_ID" = "$TEAM_REQUIRED" ] || fail "the identity has team \"$TEAM_ID\", the app group needs $TEAM_REQUIRED"
  case "$SIGN_NAME" in
    "Developer ID Application: "*) SIGN_TIMESTAMP="--timestamp" ;;
  esac
  echo "Identity: $SIGN_NAME ($SIGN_SHA1), team $TEAM_ID"
fi

# ---------------------------------------------------------------- entitlements
step "Fill the entitlements for team $TEAM_ID"
fill_entitlements() { # template, output
  sed -e "s/__TEAM_ID__/$TEAM_ID/g" "$1" >"$2"
  plutil -lint "$2" >/dev/null
  if grep -q '__' "$2"; then fail "unfilled variable in $2"; fi
}
ENT_DIR="$OUT/entitlements"
fill_entitlements packaging/ApassyAutoFill.entitlements "$ENT_DIR/ApassyAutoFill.entitlements"
fill_entitlements packaging/ApassyCredentialBridge.entitlements "$ENT_DIR/ApassyCredentialBridge.entitlements"
fill_entitlements packaging/ApassyProvider.entitlements "$ENT_DIR/Apassy-provider.entitlements"
# check_ent FILE KEY EXPECTED [INDEX]: a top-level entitlement (its dots escaped).
check_ent() { check_value "$1" "${2//./\\.}${4:+.$4}" "$3"; }
check_ent "$ENT_DIR/ApassyAutoFill.entitlements" com.apple.application-identifier "$TEAM_ID.$APPEX_ID"
check_ent "$ENT_DIR/ApassyAutoFill.entitlements" "$AUTOFILL_KEY" true
check_ent "$ENT_DIR/ApassyAutoFill.entitlements" com.apple.security.app-sandbox true
check_ent "$ENT_DIR/ApassyAutoFill.entitlements" com.apple.security.application-groups "$TEAM_ID.$APP_ID" 0
check_ent "$ENT_DIR/ApassyCredentialBridge.entitlements" com.apple.security.application-groups "$TEAM_ID.$APP_ID" 0
check_ent "$ENT_DIR/Apassy-provider.entitlements" com.apple.application-identifier "$TEAM_ID.$APP_ID"
check_ent "$ENT_DIR/Apassy-provider.entitlements" "$AUTOFILL_KEY" true
echo "ok: $ENT_DIR"

# ---------------------------------------------------------------- profiles
MAC_UDID="$(system_profiler SPHardwareDataType | awk -F': ' '/Provisioning UDID/ {print $2}')"
NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# check_profile FILE BUNDLE_ID: return 0 when the profile fits, else print the reason.
check_profile() {
  local file="$1" bundle="$2" decoded="$TMP/profile.plist" team appid expiry i found
  [ -f "$file" ] || { echo "the file does not exist"; return 1; }
  security cms -D -i "$file" >"$decoded" 2>/dev/null || { echo "cannot decode the profile"; return 1; }
  plist_raw "$decoded" Platform.0 | grep -q OSX || { echo "the profile is not for macOS"; return 1; }
  team="$(plist_raw "$decoded" TeamIdentifier.0)"
  [ "$team" = "$TEAM_ID" ] || { echo "the profile is for team \"$team\", not $TEAM_ID"; return 1; }
  appid="$(plist_raw "$decoded" 'Entitlements.com\.apple\.application-identifier')"
  [ "$appid" = "$TEAM_ID.$bundle" ] || { echo "the App ID is \"$appid\", not $TEAM_ID.$bundle (no wildcard)"; return 1; }
  [ "$(plist_raw "$decoded" "Entitlements.${AUTOFILL_KEY//./\\.}")" = "true" ] \
    || { echo "the profile does not have the AutoFill Credential Provider capability"; return 1; }
  expiry="$(plist_raw "$decoded" ExpirationDate)"
  [[ "$expiry" > "$NOW" ]] || { echo "the profile expired at $expiry"; return 1; }
  if [ "$(plist_raw "$decoded" ProvisionsAllDevices)" != "true" ]; then
    /usr/libexec/PlistBuddy -c "Print :ProvisionedDevices" "$decoded" 2>/dev/null | grep -q "$MAC_UDID" \
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
  return 0
}

PROVIDER="not included"
PROVIDER_REASON="no signing identity"
if [ -n "$SIGN_ID" ]; then
  step "Check the provisioning profiles"
  PROVIDER_REASON=""
  for pair in "appex:$APPEX_ID:$APPEX_PROFILE" "app:$APP_ID:$APP_PROFILE"; do
    IFS=: read -r label bundle file <<<"$pair"
    if [ -z "$file" ]; then
      PROVIDER_REASON="${PROVIDER_REASON}no $label profile for $TEAM_ID.$bundle; "
    elif RESULT="$(check_profile "$file" "$bundle")"; then
      echo "ok: $label profile $file"
    else
      PROVIDER_REASON="${PROVIDER_REASON}the $label profile is not usable: $RESULT; "
    fi
  done
  if [ -z "$PROVIDER_REASON" ]; then
    PROVIDER="included"
  fi
fi
if [ "$PROVIDER" != "included" ]; then
  warn "provider: not included (${PROVIDER_REASON%; })"
  [ "$REQUIRE_PROVIDER" != "1" ] || fail "--require-provider: ${PROVIDER_REASON%; }"
fi

# ---------------------------------------------------------------- sign
# Print the entitlements of CODE as canonical XML (sorted keys). None prints nothing.
entitlements_xml() {
  local xml
  xml="$(codesign -d --entitlements - --xml "$1" 2>/dev/null || true)"
  [ -z "$xml" ] || printf '%s' "$xml" | plutil -convert xml1 -o - -
}
FORBIDDEN="com.apple.security.get-task-allow com.apple.security.cs.disable-library-validation com.apple.security.cs.allow-dyld-environment-variables com.apple.security.cs.allow-unsigned-executable-memory com.apple.security.cs.allow-jit"
# verify_signed CODE IDENTIFIER ENTITLEMENTS_FILE
verify_signed() {
  local code="$1" identifier="$2" expected="$3" key
  codesign --verify --strict --verbose=2 "$code" 2>"$TMP/verify.txt" || { cat "$TMP/verify.txt" >&2; fail "$code does not verify"; }
  codesign -d --verbose=2 "$code" >"$TMP/info.txt" 2>&1
  grep -qx "Identifier=$identifier" "$TMP/info.txt" || fail "$code is not signed as $identifier"
  grep -qx "TeamIdentifier=$TEAM_ID" "$TMP/info.txt" || fail "$code is not signed by team $TEAM_ID"
  grep -q "flags=.*(runtime)" "$TMP/info.txt" || fail "hardened runtime is off for $code"
  entitlements_xml "$code" >"$TMP/got.xml"
  plutil -convert xml1 -o "$TMP/want.xml" "$expected"
  diff -q "$TMP/got.xml" "$TMP/want.xml" >/dev/null || { diff "$TMP/got.xml" "$TMP/want.xml" >&2 || true; fail "$code has other entitlements than $expected"; }
  for key in $FORBIDDEN; do
    if grep -qF "<key>$key</key>" "$TMP/got.xml"; then fail "$code has the forbidden entitlement $key"; fi
  done
  echo "ok: $identifier, team $TEAM_ID, hardened runtime, entitlements of $(basename "$expected")"
}
sign() { codesign --force --sign "$SIGN_SHA1" --options runtime "$SIGN_TIMESTAMP" "$@"; }

if [ -n "$SIGN_ID" ]; then
  step "Sign"
  sign --identifier "$BRIDGE_ID" --entitlements "$ENT_DIR/ApassyCredentialBridge.entitlements" "$OUT/$BRIDGE_EXE"
  verify_signed "$OUT/$BRIDGE_EXE" "$BRIDGE_ID" "$ENT_DIR/ApassyCredentialBridge.entitlements"
  if [ "$PROVIDER" = "included" ]; then
    cp "$APPEX_PROFILE" "$APPEX/Contents/embedded.provisionprofile"
    cp "$APP_PROFILE" "$OUT/Apassy-provider.provisionprofile"
    sign --entitlements "$ENT_DIR/ApassyAutoFill.entitlements" "$APPEX"
    verify_signed "$APPEX" "$APPEX_ID" "$ENT_DIR/ApassyAutoFill.entitlements"
  else
    echo "The extension stays unsigned: without both profiles AMFI would stop it."
  fi
fi

{
  echo "provider: $PROVIDER"
  [ "$PROVIDER" = "included" ] || echo "reason: ${PROVIDER_REASON%; }"
  echo "offers: $OFFERS"
  echo "team: $TEAM_ID"
  echo "signed_by: ${SIGN_SHA1:-unsigned}"
  echo "extension: $APPEX"
  echo "bridge: $OUT/$BRIDGE_EXE"
  echo "app_entitlements: $ENT_DIR/Apassy-provider.entitlements"
  [ "$PROVIDER" != "included" ] || echo "app_profile: $OUT/Apassy-provider.provisionprofile"
} >"$OUT/provider-status.txt"

# ---------------------------------------------------------------- tests
if [ "$RUN_TESTS" = "1" ]; then
  step "Build and run the synthetic tests"
  mkdir -p "$TMP/test"
  "${SWIFTC[@]}" -D APASSY_BRIDGE_DEV -o "$TMP/test/bridge-dev" "${BRIDGE_SOURCES[@]}"
  "${SWIFTC[@]}" -D APASSY_BRIDGE_DEV -o "$TMP/test/bridge-tests" \
    native/ApassyCredentialBridge/Tests/*.swift native/ApassyCredentialBridge/BridgeWire.swift \
    native/ApassyCredentialBridge/BridgeServer.swift "${SHARED[@]}" native/ApassyAutoFill/ProviderWire.swift
  "$TMP/test/bridge-tests" "$TMP/test/bridge-dev"

  if [ -n "$SIGN_ID" ]; then
    step "Run the signed probe (real parent, peer, and server checks)"
    # A fake Apassy.app: the probe as the app and as the extension, and a bridge with
    # only the container override. No NSExtension keys: nothing registers it.
    rm -rf "$TEST_OUT"
    FAKE="$TEST_OUT/Apassy.app"
    FAKE_APPEX="$FAKE/Contents/PlugIns/ApassyAutoFill.appex"
    OTHER_APPEX="$FAKE/Contents/PlugIns/Other.appex"
    STRANGER_APPEX="$TEST_OUT/elsewhere/ApassyAutoFill.appex"
    mkdir -p "$FAKE/Contents/MacOS" "$FAKE_APPEX/Contents/MacOS" "$OTHER_APPEX/Contents/MacOS" \
      "$STRANGER_APPEX/Contents/MacOS" "$TEST_OUT/elsewhere/MacOS"
    "${SWIFTC[@]}" -o "$TMP/test/probe" native/ApassyCredentialBridge/Tests/SignedProbe/main.swift \
      native/ApassyAutoFill/BridgeClient.swift native/ApassyAutoFill/ProviderWire.swift "${SHARED[@]}"
    bundle_plist() { # file, id, executable, type
      /usr/libexec/PlistBuddy -c "Add :CFBundleIdentifier string $2" -c "Add :CFBundleExecutable string $3" \
        -c "Add :CFBundlePackageType string $4" -c "Add :CFBundleInfoDictionaryVersion string 6.0" "$1" >/dev/null
    }
    # Its own bundle ID, so LaunchServices never mistakes it for Apassy. The parent check
    # reads the signing identifier, which --identifier sets to com.wydrox.apassy below.
    bundle_plist "$FAKE/Contents/Info.plist" "$APP_ID.probe-test" apassy APPL
    bundle_plist "$FAKE_APPEX/Contents/Info.plist" "$APPEX_ID" "$APPEX_EXE" 'XPC!'
    bundle_plist "$OTHER_APPEX/Contents/Info.plist" "$APP_ID.other" "$APPEX_EXE" 'XPC!'
    bundle_plist "$STRANGER_APPEX/Contents/Info.plist" "$APPEX_ID" "$APPEX_EXE" 'XPC!'
    cp "$TMP/test/probe" "$FAKE/Contents/MacOS/apassy"
    cp "$TMP/test/probe" "$TEST_OUT/elsewhere/MacOS/apassy"
    for appex in "$FAKE_APPEX" "$OTHER_APPEX" "$STRANGER_APPEX"; do cp "$TMP/test/probe" "$appex/Contents/MacOS/$APPEX_EXE"; done
    cp "$TMP/test/bridge-dev" "$FAKE/Contents/MacOS/$BRIDGE_EXE"
    TESTSIGN() { codesign --force --sign "$SIGN_SHA1" --options runtime --timestamp=none "$@" >/dev/null 2>&1; }
    for appex in "$FAKE_APPEX" "$OTHER_APPEX" "$STRANGER_APPEX"; do TESTSIGN "$appex"; done
    TESTSIGN --identifier "$BRIDGE_ID" "$FAKE/Contents/MacOS/$BRIDGE_EXE"
    TESTSIGN --identifier "$APP_ID" "$TEST_OUT/elsewhere/MacOS/apassy"
    TESTSIGN --identifier "$APP_ID" "$FAKE"
    CONTAINER="/tmp/apassy-probe-$$"
    mkdir -p "$CONTAINER"
    PROBE_STATUS=0
    "$FAKE/Contents/MacOS/apassy" parent "$CONTAINER/a" "$FAKE/Contents/MacOS/$BRIDGE_EXE" \
      "answered:client:$FAKE_APPEX/Contents/MacOS/$APPEX_EXE" \
      "answered:raw:$FAKE_APPEX/Contents/MacOS/$APPEX_EXE" \
      "refused:raw:$STRANGER_APPEX/Contents/MacOS/$APPEX_EXE" \
      "refused:raw:$OTHER_APPEX/Contents/MacOS/$APPEX_EXE" || PROBE_STATUS=1
    # The right path with another signing identifier. The app is sealed again around it,
    # so only the extension check can refuse it.
    TESTSIGN --identifier "$APPEX_ID.copy" "$FAKE_APPEX"
    TESTSIGN --identifier "$APP_ID" "$FAKE"
    "$FAKE/Contents/MacOS/apassy" parent "$CONTAINER/b" "$FAKE/Contents/MacOS/$BRIDGE_EXE" \
      "refused:raw:$FAKE_APPEX/Contents/MacOS/$APPEX_EXE" || PROBE_STATUS=1
    TESTSIGN "$FAKE_APPEX"
    TESTSIGN --identifier "$APP_ID" "$FAKE"
    # A program that is not the signed bridge listens: the client refuses it.
    mkdir -p "$CONTAINER/c"
    mkfifo "$TMP/bogus.in"
    APASSY_BRIDGE_DEV_ANY_PARENT=1 APASSY_BRIDGE_DEV_ANY_PEER=1 APASSY_BRIDGE_DEV_CONTAINER="$CONTAINER/c" \
      "$TMP/test/bridge-dev" <"$TMP/bogus.in" >/dev/null 2>&1 &
    BOGUS=$!
    exec 9>"$TMP/bogus.in"
    for _ in 1 2 3 4 5 6 7 8 9 10; do [ -S "$CONTAINER/c/bridge/cp.sock" ] && break; sleep 0.2; done
    STATUS=0
    "$FAKE_APPEX/Contents/MacOS/$APPEX_EXE" client "$CONTAINER/c/bridge/cp.sock" || STATUS=$?
    # A FIFO writer that closes does not wake poll() on macOS, so stop it with a signal.
    kill "$BOGUS" 2>/dev/null || true
    wait "$BOGUS" 2>/dev/null || true
    exec 9>&-
    if [ "$STATUS" = "3" ]; then echo "ok: the extension refuses a server that is not the signed bridge"; else echo "FAIL: the extension accepted another server ($STATUS)"; PROBE_STATUS=1; fi
    # A parent that is not the Apassy app around the bridge: the shell, and a signed copy elsewhere.
    STATUS=0
    APASSY_BRIDGE_DEV_CONTAINER="$CONTAINER/d" "$FAKE/Contents/MacOS/$BRIDGE_EXE" </dev/null >"$TMP/parent.txt" 2>/dev/null || STATUS=$?
    if [ "$STATUS" = "1" ] && grep -q '"code":"caller_not_allowed"' "$TMP/parent.txt"; then
      echo "ok: the bridge refuses an unsigned parent"
    else
      echo "FAIL: the bridge accepted an unsigned parent ($STATUS)"; PROBE_STATUS=1
    fi
    if "$TEST_OUT/elsewhere/MacOS/apassy" parent "$CONTAINER/e" "$FAKE/Contents/MacOS/$BRIDGE_EXE" >"$TMP/elsewhere.txt" 2>&1; then
      echo "FAIL: the bridge accepted a signed parent outside its bundle"; PROBE_STATUS=1
    elif grep -q "FAIL: the bridge accepts its signed parent" "$TMP/elsewhere.txt"; then
      echo "ok: the bridge refuses a signed parent outside its bundle"
    else
      cat "$TMP/elsewhere.txt"; echo "FAIL: unexpected result of the parent outside the bundle"; PROBE_STATUS=1
    fi
    rm -rf "$CONTAINER"
    cleanup
    [ "$PROBE_STATUS" = "0" ] || fail "the signed probe failed"
    echo "ok: signed probe"
  fi
fi

step "Done"
cat "$OUT/provider-status.txt"
