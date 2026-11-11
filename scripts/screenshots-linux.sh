#!/bin/bash
# The Linux path of the screenshot tour (scripts/screenshots.sh is the macOS path): the
# real window under Xvfb with software rendering, captured with ImageMagick `import`.
# Synthetic data only: a scratch HOME for each run, never the owner's vault, account,
# Stripe or the hosted relay.
#
# Two parts, each with its own binary:
#
#   APASSY_DEMO_BIN   the demo build without a vault (`cargo build --features desktop
#                     --bin apassy`): every frame of the Connect and Devices mockups
#                     (src/desktop/ui/connect/demo.rs, src/desktop/ui/demo.rs), one run
#                     of the window per frame, opened with APASSY_DEMO_CONNECT or
#                     APASSY_DEMO_DEVICES.
#   APASSY_TOUR_BIN   examples/screenshots built with `--features desktop,vault`: the
#                     vault scenes (APASSY_TOUR_SCENE, see examples/screenshots.rs).
#
# A tall view is captured once per page: the script scrolls the detail column and keeps
# NAME-2.png, NAME-3.png … while the picture changes.
#
# Usage: scripts/screenshots-linux.sh OUT_DIR
#   APASSY_TOUR_SIZE=1100x760   the window (default)
#   APASSY_TOUR_ONLY=NAME,...   only these images (names without .png)
#   APASSY_TOUR_PART=demo|vault only one part
#   APASSY_TOUR_SCENES="linux connect-owner"  only these vault scenes
# Needs: Xvfb, xdotool, ImageMagick, Mesa (llvmpipe). scripts/ui-review/Dockerfile has
# them; scripts/ui-review/on-devbox.sh runs everything in a container from the Mac.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$(mkdir -p "${1:?usage: scripts/screenshots-linux.sh OUT_DIR}" && cd "$1" && pwd)"
SIZE="${APASSY_TOUR_SIZE:-1100x760}"
W="${SIZE%x*}"
H="${SIZE#*x}"

fail() { printf 'screenshots-linux: FAILED: %s\n' "$*" >&2; exit 1; }
[ "$(uname -s)" = "Linux" ] || fail "this script runs on Linux only"
for tool in Xvfb xdotool import compare; do
  command -v "$tool" >/dev/null || fail "$tool is missing"
done

WORK="$(mktemp -d /tmp/apassy-shots.XXXXXX)"
XVFB_PID=""
APP_PID=""
cleanup() {
  [ -z "$APP_PID" ] || kill "$APP_PID" 2>/dev/null || true
  [ -z "$XVFB_PID" ] || kill "$XVFB_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# One X server for the whole run, exactly the size of the window: no window manager, so
# the window sits at 0,0 and a capture of the root window is the window.
DISPLAY_NUM=97
while [ -e "/tmp/.X11-unix/X$DISPLAY_NUM" ]; do DISPLAY_NUM=$((DISPLAY_NUM + 1)); done
Xvfb ":$DISPLAY_NUM" -screen 0 "${W}x${H}x24" -nolisten tcp >"$WORK/xvfb.log" 2>&1 &
XVFB_PID=$!
export DISPLAY=":$DISPLAY_NUM"
for _ in $(seq 50); do xdotool getdisplaygeometry >/dev/null 2>&1 && break; sleep 0.1; done
xdotool getdisplaygeometry >/dev/null 2>&1 || fail "Xvfb did not start"
# Software rendering: no GPU in a container or on a build server.
export LIBGL_ALWAYS_SOFTWARE=1
# The app must not find a session bus of the host, or the owner's keyring.
unset DBUS_SESSION_BUS_ADDRESS

COUNT=0
wanted() {
  [ -z "${APASSY_TOUR_ONLY:-}" ] && return 0
  case ",$APASSY_TOUR_ONLY," in *",$1,"*) return 0 ;; esac
  return 1
}

# The window of $APP_PID, at 0,0 and the size of the screen.
place_window() {
  local wid=""
  for _ in $(seq 300); do
    wid="$(xdotool search --onlyvisible --pid "$APP_PID" 2>/dev/null | tail -1 || true)"
    [ -n "$wid" ] && break
    kill -0 "$APP_PID" 2>/dev/null || return 1
    sleep 0.1
  done
  [ -n "$wid" ] || return 1
  xdotool windowmove "$wid" 0 0 windowsize "$wid" "$W" "$H" 2>/dev/null || true
  echo "$wid"
}

capture() {
  import -window root "$1"
  COUNT=$((COUNT + 1))
  echo "captured $1"
}

# The number of pixels that differ between two images (0: the same picture).
differ() { compare -metric AE "$1" "$2" null: 2>&1 | awk '{print $1; exit}' || true; }

# The pointer rests in the right margin of the detail column: it scrolls the column and
# hovers no row or button.
park_pointer() { xdotool mousemove $((W - 14)) $((H / 2)); }

# Capture NAME, then scroll the detail column a page at a time and keep each new page. A
# page counts when more than 2000 pixels changed: a spinner alone is not a new page.
capture_pages() {
  local name="$1" page=1 prev changed
  park_pointer
  sleep 0.3
  capture "$OUT/$name.png"
  prev="$OUT/$name.png"
  while [ "$page" -lt 6 ]; do
    for _ in $(seq 8); do xdotool click 5; done
    sleep 0.8
    import -window root "$WORK/next.png"
    changed="$(differ "$WORK/next.png" "$prev")"
    [ "${changed%.*}" -gt 2000 ] 2>/dev/null || break
    page=$((page + 1))
    prev="$OUT/$name-$page.png"
    cp "$WORK/next.png" "$prev"
    COUNT=$((COUNT + 1))
    echo "captured $prev"
  done
}

# ---------------------------------------------------------------- demo frames

# One run of the demo window. $1: the image name; the rest: environment settings.
demo_frame() {
  local name="$1"
  shift
  wanted "$name" || return 0
  local home="$WORK/home-demo"
  rm -rf "$home"
  mkdir -p "$home"
  chmod 700 "$home"
  (cd "$WORK" && exec env HOME="$home" XDG_CONFIG_HOME="$home/.config" \
    XDG_DATA_HOME="$home/.local/share" "$@" "$DEMO" >"$WORK/demo.log" 2>&1) &
  APP_PID=$!
  if ! place_window >/dev/null; then
    tail -20 "$WORK/demo.log" >&2
    echo "not captured: $name (no window)" | tee -a "$OUT/missing.txt" >&2
    kill "$APP_PID" 2>/dev/null || true
    wait "$APP_PID" 2>/dev/null || true
    APP_PID=""
    return 0
  fi
  sleep 2.5
  capture_pages "$name"
  kill "$APP_PID" 2>/dev/null || true
  wait "$APP_PID" 2>/dev/null || true
  APP_PID=""
}

demo_part() {
  DEMO="$WORK/apassy-demo"
  cp "$APASSY_DEMO_BIN" "$DEMO"
  local code name
  # Settings › Connect: the frames of docs/design/connect-mockup.html, and the states
  # of the vault build without a frame (T1 to T8).
  for code in 1 2a 2b 3 S T1 4a 4b 4c 5a 5b 5c 6a 6b 6c 6d 6e 6f 6g 6h 7a 7b 7c 7d T8 \
    8a 8b 8c 9 9a 9b 9c 9d 9e 10a 10b 10c 11a 11b 13a 13c T2 T3 T4 T5 T6 T7; do
    demo_frame "connect-demo-$code" APASSY_DEMO_DEVICES=1 APASSY_DEMO_CONNECT="$code"
  done
  # Settings › Devices: the frames of docs/design/devices-settings-mockup.html.
  for code in 1 2a 2b 2c 3a 3b 3c 3d 3f 3g 3h 4 4b 4c 4d 4d+ 5a 5b 5c 6a 6b 6d 7 \
    9a 9b 9c 9d 9d+ 9e R; do
    name="devices-demo-${code/+/-later}"
    demo_frame "$name" APASSY_DEMO_DEVICES="$code"
  done
}

# ---------------------------------------------------------------- vault scenes

# One run of the tour example on a scratch HOME. $1: seed, seed-empty or none; the rest:
# environment settings, such as APASSY_TOUR_SCENE=connect-account.
vault_run() {
  local seed="$1"
  shift
  local home="$WORK/home-vault"
  rm -rf "$home"
  mkdir -p "$home"
  chmod 700 "$home"
  [ "$seed" = none ] || HOME="$home" "$TOUR" "$seed" "$home" >/dev/null
  rm -f "$WORK/events"
  mkfifo "$WORK/events"
  (cd "$WORK" && exec env HOME="$home" XDG_CONFIG_HOME="$home/.config" \
    XDG_DATA_HOME="$home/.local/share" APASSY_TOUR_HOME="$home" \
    APASSY_TOUR_SIZE="$W"x"$H" APASSY_SNAP_DIR="$OUT" "$@" "$TOUR" run \
    >"$WORK/events" 2>"$WORK/app.log") &
  APP_PID=$!
  local line name placed="" last=""
  while IFS= read -r line; do
    case "$line" in
      "SNAP "*)
        echo "captured ${line#SNAP }"
        COUNT=$((COUNT + 1))
        ;;
      "SHOT "*)
        name="${line#SHOT }"
        [ -n "$placed" ] || { place_window >/dev/null && placed=1; }
        sleep 0.5
        if wanted "${name%-[0-9]}"; then
          import -window root "$OUT/$name.png"
          # A further page of a tall view (NAME-2 …) that shows the page before again
          # (the end of the column) is dropped.
          if [ "$name" != "${name%-[0-9]}" ] && [ -n "$last" ] \
            && ! [ "$(differ "$OUT/$name.png" "$last")" -gt 2000 ] 2>/dev/null; then
            rm -f "$OUT/$name.png"
          else
            COUNT=$((COUNT + 1))
            echo "captured $OUT/$name.png"
            last="$OUT/$name.png"
          fi
        fi
        touch "$WORK/$name.done"
        ;;
      "SKIP "*) echo "not captured: ${line#SKIP }" | tee -a "$OUT/missing.txt" ;;
    esac
  done <"$WORK/events"
  if ! wait "$APP_PID"; then
    tail -40 "$WORK/app.log" >&2
    APP_PID=""
    fail "the tour ($*) did not end cleanly"
  fi
  [ -z "${APASSY_TOUR_LOG:-}" ] || cp "$WORK/app.log" "$APASSY_TOUR_LOG-${*//[^A-Za-z0-9_-]/_}.log"
  APP_PID=""
}

vault_part() {
  TOUR="$WORK/screenshots"
  cp "$APASSY_TOUR_BIN" "$TOUR"
  local scene
  for scene in ${APASSY_TOUR_SCENES:-$("$TOUR" scenes)}; do
    case "$scene" in
      start-*) vault_run none APASSY_TOUR_SCENE="$scene" APASSY_TOUR_RAW=1 ;;
      *) vault_run seed APASSY_TOUR_SCENE="$scene" ;;
    esac
  done
}

case "${APASSY_TOUR_PART:-}" in
  demo) [ -n "${APASSY_DEMO_BIN:-}" ] || fail "APASSY_DEMO_BIN is not set"; demo_part ;;
  vault) [ -n "${APASSY_TOUR_BIN:-}" ] || fail "APASSY_TOUR_BIN is not set"; vault_part ;;
  "")
    [ -n "${APASSY_DEMO_BIN:-}${APASSY_TOUR_BIN:-}" ] || fail "set APASSY_DEMO_BIN and/or APASSY_TOUR_BIN"
    [ -z "${APASSY_DEMO_BIN:-}" ] || demo_part
    [ -z "${APASSY_TOUR_BIN:-}" ] || vault_part
    ;;
  *) fail "APASSY_TOUR_PART is demo or vault" ;;
esac
[ "$COUNT" -gt 0 ] || fail "no screenshot"
echo "Done: $COUNT screenshots in $OUT"
