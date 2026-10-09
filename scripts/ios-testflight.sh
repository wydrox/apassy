#!/bin/bash
# Archive the iPhone app (ios/ApassyCompanion, ADR 0023) and upload it to App Store
# Connect, for TestFlight.
#
# Usage: scripts/ios-testflight.sh [--no-upload]
#   --no-upload  Archive and export an .ipa to target/ios, without the upload.
#
# Needs:
#   APASSY_TEAM            the Apple developer team ID that signs the app.
#   APASSY_NOTARY_KEY, APASSY_NOTARY_KEY_ID, APASSY_NOTARY_ISSUER
#                          an App Store Connect API key (the path to the .p8 file, the
#                          key ID, the issuer ID), as for scripts/build-dmg.sh. Xcode
#                          uses it to make the certificates and profiles it needs
#                          (automatic signing) and to upload.
#   The app record in App Store Connect with the bundle ID com.wydrox.apassy.companion.
#   Apple's API cannot make that record: create it once in App Store Connect
#   (Apps > + > New App).
#
# Optional:
#   APASSY_IOS_BUILD       the build number. Default: minutes since 1970, so each run
#                          has a new, higher number.
#   APASSY_IOS_PROFILE, APASSY_IOS_AUTOFILL_PROFILE
#                          the names of App Store provisioning profiles of the app and
#                          the AutoFill extension, made with the "Apple Distribution"
#                          certificate of this Mac. With them, the export signs
#                          manually: an API key without access to cloud-managed
#                          distribution certificates cannot let Xcode make them.
#
# The version is MARKETING_VERSION of ios/ApassyCompanion/project.yml.
# See ios/README.md, "TestFlight".
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "ios-testflight: $*" >&2
  exit 1
}

upload=1
for arg in "$@"; do
  case "$arg" in
  --no-upload) upload=0 ;;
  *) fail "unknown option $arg" ;;
  esac
done

[ -n "${APASSY_TEAM:-}" ] || fail "set APASSY_TEAM to the team ID that signs the app"
[ -n "${APASSY_NOTARY_KEY:-}" ] && [ -f "$APASSY_NOTARY_KEY" ] \
  || fail "set APASSY_NOTARY_KEY to the .p8 file of an App Store Connect API key"
[ -n "${APASSY_NOTARY_KEY_ID:-}" ] && [ -n "${APASSY_NOTARY_ISSUER:-}" ] \
  || fail "set APASSY_NOTARY_KEY_ID and APASSY_NOTARY_ISSUER with APASSY_NOTARY_KEY"
command -v xcodegen >/dev/null || fail "xcodegen is not installed (brew install xcodegen)"

build=${APASSY_IOS_BUILD:-$(($(date +%s) / 60))}
out="$ROOT/target/ios"
archive="$out/Apassy.xcarchive"
derived="$out/DerivedData"
auth=(
  -allowProvisioningUpdates
  -authenticationKeyPath "$APASSY_NOTARY_KEY"
  -authenticationKeyID "$APASSY_NOTARY_KEY_ID"
  -authenticationKeyIssuerID "$APASSY_NOTARY_ISSUER"
)

echo "ios-testflight: the vault core for the iPhone"
scripts/build-ios-core.sh device

echo "ios-testflight: the project"
(cd ios/ApassyCompanion && xcodegen generate --spec project.yml --quiet)

echo "ios-testflight: archive, build $build"
rm -rf "$archive" "$out/export"
mkdir -p "$out"
xcodebuild -project ios/ApassyCompanion/ApassyCompanion.xcodeproj \
  -scheme ApassyCompanion -configuration Release \
  -destination 'generic/platform=iOS' \
  -archivePath "$archive" -derivedDataPath "$derived" \
  DEVELOPMENT_TEAM="$APASSY_TEAM" CURRENT_PROJECT_VERSION="$build" \
  "${auth[@]}" archive -quiet

destination=export
[ "$upload" = 1 ] && destination=upload
signing="<key>signingStyle</key>
  <string>automatic</string>"
if [ -n "${APASSY_IOS_PROFILE:-}" ] && [ -n "${APASSY_IOS_AUTOFILL_PROFILE:-}" ]; then
  signing="<key>signingStyle</key>
  <string>manual</string>
  <key>signingCertificate</key>
  <string>Apple Distribution</string>
  <key>provisioningProfiles</key>
  <dict>
    <key>com.wydrox.apassy.companion</key>
    <string>$APASSY_IOS_PROFILE</string>
    <key>com.wydrox.apassy.companion.autofill</key>
    <string>$APASSY_IOS_AUTOFILL_PROFILE</string>
  </dict>"
fi
options="$out/ExportOptions.plist"
cat >"$options" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>method</key>
  <string>app-store-connect</string>
  <key>destination</key>
  <string>$destination</string>
  <key>teamID</key>
  <string>$APASSY_TEAM</string>
  $signing
  <key>uploadSymbols</key>
  <true/>
  <key>manageAppVersionAndBuildNumber</key>
  <false/>
</dict>
</plist>
PLIST

echo "ios-testflight: export ($destination)"
xcodebuild -exportArchive -archivePath "$archive" -exportOptionsPlist "$options" \
  -exportPath "$out/export" "${auth[@]}" -quiet

version=$(/usr/libexec/PlistBuddy -c 'Print :ApplicationProperties:CFBundleShortVersionString' "$archive/Info.plist")
if [ "$upload" = 1 ]; then
  echo "ios-testflight: uploaded Apassy $version ($build). App Store Connect processes it for TestFlight in a few minutes."
else
  echo "ios-testflight: $out/export/ApassyCompanion.ipa, Apassy $version ($build)"
fi
