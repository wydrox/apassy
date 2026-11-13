#!/bin/bash
# The main walk of the screenshot tour (examples/screenshots.rs, `seed` and `run`) on
# Linux, as scripts/screenshots.sh runs it on macOS: four runs of the window on a
# scratch HOME each (the seeded vault; the empty vault with APASSY_TOUR_FIRST_STEPS=1;
# the seeded vault with APASSY_TOUR_RELAY=on and =old). The tour prints `SHOT NAME`
# before each view and waits for NAME.done in its working directory; this script then
# captures the window from the X server (Xvfb, software rendering) as
# OUT_DIR/walk-NAME.png and creates NAME.done.
#
# When no next line comes from the tour within WALK_SHOT_TIMEOUT seconds (default 60),
# the run stops: the window is closed, the images so far are kept, and LOG_DIR gets the
# last SHOT and the last 40 lines of the tour's output. The other runs still go.
#
# Usage: ui-screenshots-walk.sh OUT_DIR LOG_DIR
#   APASSY_TOUR_BIN     the tour example (cargo build --example screenshots)
#   WALK_SIZE=1180x740  the screen; the default window size of the tour on macOS
#   WALK_RUNS="main first-steps relay-on relay-old"  the runs to make
# Exit status: 0 when every run ended cleanly, 1 otherwise.
set -uo pipefail

OUT="$(mkdir -p "${1:?usage: ui-screenshots-walk.sh OUT_DIR LOG_DIR}" && cd "$1" && pwd)"
LOGS="$(mkdir -p "${2:?usage: ui-screenshots-walk.sh OUT_DIR LOG_DIR}" && cd "$2" && pwd)"
SIZE="${WALK_SIZE:-1180x740}"
W="${SIZE%x*}"
H="${SIZE#*x}"
TIMEOUT="${WALK_SHOT_TIMEOUT:-60}"
STATUS="$LOGS/walk-status.txt"

fail() { printf 'walk: FAILED: %s\n' "$*" >&2; exit 1; }
[ -x "${APASSY_TOUR_BIN:-}" ] || fail "APASSY_TOUR_BIN is not an executable"
for tool in Xvfb xdotool import; do
  command -v "$tool" >/dev/null || fail "$tool is missing"
done

# A short path: the broker socket of the scratch HOME must fit in SUN_LEN.
WORK="$(mktemp -d /tmp/apassy-walk.XXXXXX)"
TOUR="$WORK/screenshots"
cp "$APASSY_TOUR_BIN" "$TOUR"
XVFB_PID=""
APP_PID=""
cleanup() {
  [ -z "$APP_PID" ] || kill "$APP_PID" 2>/dev/null || true
  [ -z "$XVFB_PID" ] || kill "$XVFB_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

DISPLAY_NUM=90
while [ -e "/tmp/.X11-unix/X$DISPLAY_NUM" ]; do DISPLAY_NUM=$((DISPLAY_NUM + 1)); done
# The screen is wider than the window: other windows of the app wait right of it.
Xvfb ":$DISPLAY_NUM" -screen 0 "$((W + 600))x${H}x24" -nolisten tcp >"$WORK/xvfb.log" 2>&1 &
XVFB_PID=$!
export DISPLAY=":$DISPLAY_NUM"
for _ in $(seq 50); do xdotool getdisplaygeometry >/dev/null 2>&1 && break; sleep 0.1; done
xdotool getdisplaygeometry >/dev/null 2>&1 || fail "Xvfb did not start"
export LIBGL_ALWAYS_SOFTWARE=1
unset DBUS_SESSION_BUS_ADDRESS XDG_RUNTIME_DIR WAYLAND_DISPLAY

TOTAL=0
FAILED=0
: >"$STATUS"

# The main window of $APP_PID: its largest visible window (the walk also opens a small
# question window, which a capture of the main window on macOS leaves out). The main
# window goes to 0,0, each other window of the app to the right of it, outside the
# part of the screen that is captured. Sets WID, WW and WH. No window manager: the
# script gives the keyboard focus to the main window once.
WID=""
WW=$W
WH=$H
FOCUSED=""
layout_windows() {
  local ids id geo ww wh best="" area=0
  for _ in $(seq 100); do
    ids="$(xdotool search --onlyvisible --pid "$APP_PID" 2>/dev/null || true)"
    best=""
    area=0
    for id in $ids; do
      geo="$(xdotool getwindowgeometry --shell "$id" 2>/dev/null)" || continue
      ww="$(sed -n 's/^WIDTH=//p' <<<"$geo")"
      wh="$(sed -n 's/^HEIGHT=//p' <<<"$geo")"
      if [ $((ww * wh)) -gt "$area" ]; then
        best="$id" area=$((ww * wh)) WW="$ww" WH="$wh"
      fi
    done
    # The main window is at least half the size of the walk's window.
    [ -n "$best" ] && [ "$area" -ge $((W * H / 2)) ] && break
    sleep 0.1
  done
  [ -n "$best" ] || return 1
  WID="$best"
  xdotool windowmove "$WID" 0 0 2>/dev/null || true
  for id in $ids; do
    [ "$id" = "$WID" ] || xdotool windowmove "$id" $((W + 20)) 0 2>/dev/null || true
  done
  if [ -z "$FOCUSED" ]; then
    xdotool windowfocus "$WID" 2>/dev/null || true
    FOCUSED=1
  fi
  [ "$WW" -le "$W" ] 2>/dev/null || WW=$W
  [ "$WH" -le "$H" ] 2>/dev/null || WH=$H
}

# The main window as a PNG: the root window, cut to the main window (the walk makes it
# narrower for two views).
capture() {
  import -window root -crop "${WW}x${WH}+0+0" +repage "$1"
}

# One run. $1: the run name; $2: seed or seed-empty; the rest: environment settings.
walk_run() {
  local run="$1" seed="$2"
  shift 2
  local home="$WORK/h-$run"
  mkdir -p "$home" "$WORK/snaps"
  chmod 700 "$home"
  if ! HOME="$home" XDG_CONFIG_HOME="$home/.config" XDG_DATA_HOME="$home/.local/share" \
    "$TOUR" "$seed" "$home" >"$LOGS/walk-$run-seed.log" 2>&1; then
    echo "run $run: the $seed command failed" | tee -a "$STATUS"
    tail -40 "$LOGS/walk-$run-seed.log"
    FAILED=$((FAILED + 1))
    return
  fi
  rm -f "$WORK/events" "$WORK"/*.done
  mkfifo "$WORK/events"
  (cd "$WORK" && exec env HOME="$home" XDG_CONFIG_HOME="$home/.config" \
    XDG_DATA_HOME="$home/.local/share" APASSY_TOUR_HOME="$home" \
    APASSY_SNAP_DIR="$WORK/snaps" "$@" "$TOUR" run \
    >"$WORK/events" 2>"$LOGS/walk-$run-app.log") &
  APP_PID=$!
  exec 3<"$WORK/events"
  local line name last="(none)" count=0 rc=0 why=""
  WID=""
  FOCUSED=""
  : >"$LOGS/walk-$run-stdout.log"
  while true; do
    if IFS= read -r -t "$TIMEOUT" line <&3; then
      printf '%s\n' "$line" >>"$LOGS/walk-$run-stdout.log"
      case "$line" in
        "SHOT "*)
          name="${line#SHOT }"
          layout_windows || { why="no window for SHOT $name"; break; }
          sleep 0.5
          capture "$OUT/walk-$name.png"
          echo "captured walk-$name.png"
          count=$((count + 1))
          last="$name"
          touch "$WORK/$name.done"
          ;;
        "SNAP "*)
          name="$(basename "${line#SNAP }")"
          cp "${line#SNAP }" "$OUT/walk-$name" && echo "captured walk-$name"
          count=$((count + 1))
          ;;
        "SKIP "*) echo "not captured: ${line#SKIP }" | tee -a "$STATUS" ;;
      esac
      continue
    fi
    rc=$?
    # read: over 128 when the time ran out, 1 at the end of the output.
    [ "$rc" -gt 128 ] && why="no output from the tour within ${TIMEOUT}s after SHOT $last"
    break
  done
  exec 3<&-
  if [ -n "$why" ]; then
    kill "$APP_PID" 2>/dev/null || true
    wait "$APP_PID" 2>/dev/null || true
    APP_PID=""
    echo "run $run: STOPPED after SHOT $last: $why ($count images)" | tee -a "$STATUS"
  elif ! wait "$APP_PID"; then
    APP_PID=""
    why="the tour did not end cleanly"
    echo "run $run: FAILED after SHOT $last: $why ($count images)" | tee -a "$STATUS"
  else
    APP_PID=""
    echo "run $run: ok ($count images, last SHOT $last)" | tee -a "$STATUS"
  fi
  if [ -n "$why" ]; then
    FAILED=$((FAILED + 1))
    echo "--- last 40 lines of the tour's stderr (run $run)"
    tail -40 "$LOGS/walk-$run-app.log"
    echo "--- last 40 lines of the tour's stdout (run $run)"
    tail -40 "$LOGS/walk-$run-stdout.log"
  fi
  TOTAL=$((TOTAL + count))
}

for run in ${WALK_RUNS:-main first-steps relay-on relay-old}; do
  echo "::group::walk run $run"
  case "$run" in
    main) walk_run main seed ;;
    first-steps) walk_run first-steps seed-empty APASSY_TOUR_FIRST_STEPS=1 ;;
    relay-on) walk_run relay-on seed APASSY_TOUR_RELAY=on ;;
    relay-old) walk_run relay-old seed APASSY_TOUR_RELAY=old ;;
    *) echo "unknown walk run: $run" | tee -a "$STATUS"; FAILED=$((FAILED + 1)) ;;
  esac
  echo "::endgroup::"
done
echo "walk: $TOTAL images, $FAILED runs not clean"
cat "$STATUS"
[ "$FAILED" -eq 0 ]
