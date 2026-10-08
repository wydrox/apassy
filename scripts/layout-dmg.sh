#!/bin/bash
# Save the Finder install window in a mounted, writable Apassy disk image.
# Usage: scripts/layout-dmg.sh MOUNT_PATH
#        scripts/layout-dmg.sh --check
set -euo pipefail

fail() { printf '\nlayout-dmg: FAILED: %s\n' "$*" >&2; exit 1; }

[ "$(uname -s)" = "Darwin" ] || fail "this script runs on macOS only"
command -v osascript >/dev/null 2>&1 || fail "missing tool: osascript"
# Build agents can run outside the user's GUI bootstrap context. Route Apple
# Events through that session, or Finder may open a window but queries time out.
finder_script() { launchctl asuser "$(id -u)" /usr/bin/osascript "$@"; }
if ! finder_script -e 'tell application "Finder" to count windows' >/dev/null; then
  fail "Finder is not available. Sign in to a macOS desktop session. Permit Finder control in System Settings > Privacy & Security > Automation. For CI, use a macOS runner with a desktop session."
fi
if [ "${1:-}" = "--check" ] && [ "$#" = "1" ]; then
  exit 0
fi
[ "$#" = "1" ] || fail "usage: scripts/layout-dmg.sh MOUNT_PATH"
MOUNT="$1"
[ -d "$MOUNT/Apassy.app" ] || fail "missing Apassy.app in $MOUNT"
[ -L "$MOUNT/Applications" ] || fail "missing Applications link in $MOUNT"
[ -s "$MOUNT/.background/background.tiff" ] || fail "missing disk image background in $MOUNT"

# Pass paths as arguments. Do not insert them into AppleScript source.
# Finder bounds include the 28-pixel title bar: the content is 720 by 480.
if ! finder_script - "$MOUNT" <<'APPLESCRIPT'
on run argv
  set volumeRoot to POSIX file (item 1 of argv) as alias
  tell application "Finder"
    with timeout of 60 seconds
      open volumeRoot
      set installWindow to container window of volumeRoot
      set current view of installWindow to icon view
      set toolbar visible of installWindow to false
      set statusbar visible of installWindow to false
      set sidebar width of installWindow to 0
      set bounds of installWindow to {120, 100, 840, 608}
      set viewOptions to icon view options of installWindow
      set arrangement of viewOptions to not arranged
      set icon size of viewOptions to 96
      set text size of viewOptions to 13
      set label position of viewOptions to bottom
      set shows item info of viewOptions to false
      set shows icon preview of viewOptions to false
      set background picture of viewOptions to file ".background:background.tiff" of volumeRoot
      set position of item "Apassy.app" of volumeRoot to {190, 260}
      set extension hidden of item "Apassy.app" of volumeRoot to true
      set position of item "Applications" of volumeRoot to {530, 260}
      update volumeRoot without registering applications
      delay 2
      close installWindow
      delay 2
      open volumeRoot
      set installWindow to container window of volumeRoot
      if current view of installWindow is not icon view then error "Finder did not save icon view."
      if icon size of icon view options of installWindow is not 96 then error "Finder did not save the icon size."
      if position of item "Apassy.app" of volumeRoot is not {190, 260} then error "Finder did not save the app position."
      if position of item "Applications" of volumeRoot is not {530, 260} then error "Finder did not save the Applications position."
      close installWindow
      delay 2
    end timeout
  end tell
end run
APPLESCRIPT
then
  fail "Finder could not save the install window. Check Finder control in System Settings > Privacy & Security > Automation. Use a macOS desktop session, then run the build again."
fi

# Finder writes this file after it closes the window. Do not compress an
# image that has no saved layout.
for attempt in 1 2 3 4 5; do
  [ ! -s "$MOUNT/.DS_Store" ] || exit 0
  sleep 1
done
fail "Finder did not write .DS_Store in $MOUNT. Run the build again in a macOS desktop session."
