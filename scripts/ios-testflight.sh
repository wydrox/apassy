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
#   APASSY_IOS_PROFILE, APASSY_IOS_AUTOFILL_PROFILE, APASSY_IOS_WATCH_PROFILE
#                          the names of App Store provisioning profiles of the app, the
#                          AutoFill extension and the Apple Watch app, made with the
#                          "Apple Distribution" certificate of this Mac. With them, the
#                          export signs manually: an API key without access to
#                          cloud-managed distribution certificates cannot let Xcode
#                          make them. Set all three or none.
#
# The version is MARKETING_VERSION of ios/ApassyCompanion/project.yml.
# See ios/README.md, "TestFlight".
#
# It also writes target/ios/build-record.json: version, build number, commit, Xcode and
# SDK, the SHA-256 of the .ipa when the export wrote one, and the SHA-256 of each Mach-O of
# the archive (scripts/macos-binaries.py). The owner publishes it with the workflow
# ios-build-record.yml, which attests it (docs/operations/release.md, "Attestations and
# SBOMs"). The App Store re-signs and encrypts the app, so the record is a signed claim of
# the build, not a check that a user can repeat.
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

commit="$(git rev-parse --verify HEAD)" || fail "cannot identify the source commit"
if [ "$upload" = 1 ] && [ -n "$(git status --porcelain --untracked-files=normal)" ]; then
  fail "commit the release changes before uploading to TestFlight"
fi
if [ -n "${APASSY_BUILD_COMMIT:-}" ] && [ "$APASSY_BUILD_COMMIT" != "$commit" ]; then
  fail "APASSY_BUILD_COMMIT does not match the checked-out source"
fi

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

echo "ios-testflight: the vault core for the iPhone and the Apple Watch"
scripts/build-ios-core.sh device watch

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
  APASSY_BUILD_COMMIT="$commit" \
  "${auth[@]}" archive -quiet

destination=export
[ "$upload" = 1 ] && destination=upload
signing="<key>signingStyle</key>
  <string>automatic</string>"
if [ -n "${APASSY_IOS_PROFILE:-}" ] || [ -n "${APASSY_IOS_AUTOFILL_PROFILE:-}" ] \
  || [ -n "${APASSY_IOS_WATCH_PROFILE:-}" ]; then
  [ -n "${APASSY_IOS_PROFILE:-}" ] && [ -n "${APASSY_IOS_AUTOFILL_PROFILE:-}" ] \
    && [ -n "${APASSY_IOS_WATCH_PROFILE:-}" ] \
    || fail "set APASSY_IOS_PROFILE, APASSY_IOS_AUTOFILL_PROFILE and APASSY_IOS_WATCH_PROFILE together"
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
    <key>com.wydrox.apassy.companion.watchkitapp</key>
    <string>$APASSY_IOS_WATCH_PROFILE</string>
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

echo "ios-testflight: the build record"
apps=("$archive"/Products/Applications/*.app)
[ "${#apps[@]}" = 1 ] && [ -d "${apps[0]}" ] || fail "expected one app in $archive/Products/Applications"
record="$out/build-record.json"
python3 -I scripts/macos-binaries.py "${apps[0]}" --version "$version" --commit "$commit" \
  --output "$out/archive-binaries.json" >/dev/null
xcode="$(xcodebuild -version | tr '\n' ' ' | sed 's/ *$//')"
sdk="$(xcrun --sdk iphoneos --show-sdk-version)"
python3 -I - "$out/archive-binaries.json" "$out/export/ApassyCompanion.ipa" "$record" \
  "$version" "$build" "$commit" "$xcode" "$sdk" "$upload" <<'PY'
import hashlib, json, sys
from pathlib import Path
binaries, ipa, record, version, build, commit, xcode, sdk, upload = sys.argv[1:]
# With the destination "upload", the export sends the .ipa and may keep no copy.
ipa_sha256 = None
if Path(ipa).is_file():
    digest = hashlib.sha256()
    with open(ipa, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    ipa_sha256 = digest.hexdigest()
data = {
    "format": 1,
    "kind": "apassy-ios-build-record",
    "version": version,
    "build": build,
    "commit": commit,
    "xcode": xcode,
    "sdk": sdk,
    "uploaded": upload == "1",
    "ipa_sha256": ipa_sha256,
    "binaries": json.loads(Path(binaries).read_text())["files"],
}
text = json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n"
if len(text.encode()) > 64 * 1024:
    sys.exit(f"ios-testflight: the build record has {len(text.encode())} bytes, more than 64 KiB")
Path(record).write_text(text)
PY
rm -f "$out/archive-binaries.json"

if [ "$upload" = 1 ]; then
  echo "ios-testflight: uploaded Apassy $version ($build). App Store Connect processes it for TestFlight in a few minutes."
  echo "ios-testflight: when the commit is on main, publish the build record:"
  echo "  gh workflow run ios-build-record.yml --ref main -f record=\"\$(cat $record)\""
else
  echo "ios-testflight: $out/export/ApassyCompanion.ipa, Apassy $version ($build)"
  echo "ios-testflight: $record (a test build: do not publish its record)"
fi
