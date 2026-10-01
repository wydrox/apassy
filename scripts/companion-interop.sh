#!/bin/bash
# Interop check for the iPhone companion: the Swift client and the Rust listener over the
# real wire, in one session.
#
# Two programs talk to each other on 127.0.0.1:
#   - examples/companion_dev.rs: the Mac side. It makes a synthetic vault with a synthetic
#     passphrase in a temporary directory, so the real vault is never touched. It has the
#     real listener, with TLS and the pin, the real pairing, and the real approval queue.
#   - ios/ApassyCompanionKit, target companion-interop: the phone side. It has the real
#     CompanionClient and the pinned TLS transport, with software keys in memory.
#
# What the script does:
#   1. Builds both programs.
#   2. Starts the server with its stdin on a FIFO, and reads PAIRING_URL.
#   3. Starts the driver with the link. The driver pairs, prints "CODE <digits>", and polls.
#   4. Sends "CODE <digits>" to the server, as the owner types the code on the Mac.
#   5. Waits for the driver, then closes the stdin of the server, which then exits.
#   6. Checks the output of both: every OK step of the driver, and the EVENT lines of the
#      server (approved, approved_and_remembered, denied, and the denied access request),
#      with the IDs that the server announced.
#
# Usage: scripts/companion-interop.sh
# It needs Rust and Xcode 27 (Swift 6.4), and it runs on macOS. It uses only synthetic data
# and no network beyond the loopback address. See docs/operations/companion.md.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KIT="$ROOT/ios/ApassyCompanionKit"
# Seconds to wait for each part of the session.
LIMIT=60

WORK=""
SERVER_PID=""
DRIVER_PID=""

step() { printf '\n==> %s\n' "$*"; }
fail() { printf '\ncompanion-interop: FAILED: %s\n' "$*" >&2; exit 1; }
field() { # line key -> value
  printf '%s\n' "$1" | tr ' ' '\n' | sed -n "s/^$2=//p" | head -n 1
}

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  exec 3>&- 2>/dev/null || true
  local pid
  for pid in "$DRIVER_PID" "$SERVER_PID"; do
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  if [ "$status" -ne 0 ] && [ -n "$WORK" ]; then
    for name in server.out server.err driver.out driver.err; do
      if [ -s "$WORK/$name" ]; then
        printf '\n--- %s ---\n' "$name" >&2
        tail -n 40 "$WORK/$name" >&2 || true
      fi
    done
  fi
  [ -z "$WORK" ] || rm -rf "$WORK"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

[ "$(uname -s)" = "Darwin" ] || fail "this check runs on macOS only"

step "Build the server (cargo) and the driver (swift build)"
(cd "$ROOT" && cargo build --locked --features vault --example companion_dev)
(cd "$KIT" && swift build --product companion-interop)
SERVER="$ROOT/target/debug/examples/companion_dev"
DRIVER="$(cd "$KIT" && swift build --show-bin-path)/companion-interop"
[ -x "$SERVER" ] || fail "the server is not at $SERVER"
[ -x "$DRIVER" ] || fail "the driver is not at $DRIVER"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/apassy-interop.XXXXXX")"
mkfifo "$WORK/server.in"
: > "$WORK/server.out"
: > "$WORK/driver.out"

step "Start the server"
# The shell opens the FIFO for reading in the background job, and it waits there for the
# writer that the next line opens. The server exits when that writer closes.
"$SERVER" --seconds $((LIMIT * 3)) < "$WORK/server.in" > "$WORK/server.out" 2> "$WORK/server.err" &
SERVER_PID=$!
exec 3> "$WORK/server.in"

# Wait until $2 (a file) has a line that starts with $3, while $1 (a pid) runs.
wait_for_line() {
  local pid="$1" file="$2" prefix="$3" waited=0
  while ! grep -q "^$prefix" "$file"; do
    kill -0 "$pid" 2>/dev/null || {
      grep -q "^$prefix" "$file" && break
      fail "the process $pid ended before it printed \"$prefix\""
    }
    [ "$waited" -lt $((LIMIT * 10)) ] || fail "no \"$prefix\" line after $LIMIT s"
    sleep 0.1
    waited=$((waited + 1))
  done
  grep "^$prefix" "$file" | head -n 1
}

PAIRING_LINE="$(wait_for_line "$SERVER_PID" "$WORK/server.out" "PAIRING_URL=")"
PAIRING_URL="${PAIRING_LINE#PAIRING_URL=}"
case "$PAIRING_URL" in
  apassy://pair\?*) ;;
  *) fail "the server printed a link that is not a pairing link" ;;
esac
printf 'link: %s\n' "${PAIRING_URL%%&s=*}&s=..."

step "Start the driver"
"$DRIVER" "$PAIRING_URL" > "$WORK/driver.out" 2> "$WORK/driver.err" &
DRIVER_PID=$!

CODE_LINE="$(wait_for_line "$DRIVER_PID" "$WORK/driver.out" "CODE ")"
[[ "$CODE_LINE" =~ ^CODE\ [0-9]{6}$ ]] || fail "the driver printed a bad code line: $CODE_LINE"
step "Send the code to the server"
wait_for_line "$SERVER_PID" "$WORK/server.out" "PAIR_REQUEST " > /dev/null
printf '%s\n' "$CODE_LINE" >&3

step "Wait for the driver"
waited=0
while kill -0 "$DRIVER_PID" 2>/dev/null; do
  kill -0 "$SERVER_PID" 2>/dev/null || {
    kill -0 "$DRIVER_PID" 2>/dev/null && fail "the server ended while the driver still ran"
  }
  [ "$waited" -lt $((LIMIT * 10)) ] || fail "the driver did not end within $LIMIT s"
  sleep 0.1
  waited=$((waited + 1))
done
DRIVER_STATUS=0
wait "$DRIVER_PID" || DRIVER_STATUS=$?
DRIVER_PID=""

step "Close the stdin of the server"
exec 3>&-
waited=0
while kill -0 "$SERVER_PID" 2>/dev/null; do
  [ "$waited" -lt $((LIMIT * 10)) ] || fail "the server did not end within $LIMIT s after stdin closed"
  sleep 0.1
  waited=$((waited + 1))
done
SERVER_STATUS=0
wait "$SERVER_PID" || SERVER_STATUS=$?
SERVER_PID=""

step "Driver output"
cat "$WORK/driver.out"
step "Server output"
cat "$WORK/server.out"

step "Check the output"
FAIL_LINE="$(grep '^FAIL ' "$WORK/driver.out" || true)"
[ -z "$FAIL_LINE" ] || fail "the driver: $FAIL_LINE"
[ "$DRIVER_STATUS" -eq 0 ] || fail "the driver exited with status $DRIVER_STATUS"
[ "$SERVER_STATUS" -eq 0 ] || fail "the server exited with status $SERVER_STATUS"

for name in link pair pair-status status inbox approve approve-and-remember deny \
  deny-access-request inbox-empty tampered-signature wrong-pin unpair unpaired-request; do
  grep -q "^OK $name\( \|\$\)" "$WORK/driver.out" || fail "the driver did not print \"OK $name\""
done
OK_COUNT="$(grep -c '^OK ' "$WORK/driver.out" || true)"
[ "$OK_COUNT" -eq 14 ] || fail "the driver printed $OK_COUNT OK lines, not 14"

grep -q '^PAIRED device=' "$WORK/server.out" || fail "the server did not print PAIRED"
grep -q '^DONE reason=stdin_closed$' "$WORK/server.out" \
  || fail "the server did not end with DONE reason=stdin_closed"

# The IDs that the driver read from the inbox are the IDs that the server announced.
INBOX_LINE="$(grep '^OK inbox ' "$WORK/driver.out")"
DRIVER_RUNS="$(field "$INBOX_LINE" runs)"
DRIVER_REQUEST="$(field "$INBOX_LINE" access_request)"
SERVER_RUNS="$(sed -n 's/^RUN id=\([0-9]*\) remember=.*/\1/p' "$WORK/server.out" | paste -sd, -)"
SERVER_REQUEST="$(sed -n 's/^ACCESS_REQUEST id=\([0-9]*\)$/\1/p' "$WORK/server.out")"
[ -n "$SERVER_RUNS" ] && [ "$DRIVER_RUNS" = "$SERVER_RUNS" ] \
  || fail "the driver saw the runs \"$DRIVER_RUNS\", the server announced \"$SERVER_RUNS\""
[ -n "$SERVER_REQUEST" ] && [ "$DRIVER_REQUEST" = "$SERVER_REQUEST" ] \
  || fail "the driver saw the access request \"$DRIVER_REQUEST\", the server announced \"$SERVER_REQUEST\""
RUN_REMEMBER="$(sed -n 's/^RUN id=[0-9]* remember=\(.*\)$/\1/p' "$WORK/server.out" | paste -sd, -)"
[ "$RUN_REMEMBER" = "true,false,false" ] || fail "the server announced the runs with remember=$RUN_REMEMBER"

RUN_WITH_OFFER="${SERVER_RUNS%%,*}"
REST="${SERVER_RUNS#*,}"
RUN_APPROVED="${REST%%,*}"
RUN_DENIED="${REST#*,}"
expect_event() { # line
  grep -qx "$1" "$WORK/server.out" || fail "the server did not print \"$1\""
}
expect_event "EVENT run=$RUN_APPROVED outcome=approved"
expect_event "EVENT run=$RUN_WITH_OFFER outcome=approved_and_remembered"
expect_event "EVENT run=$RUN_DENIED outcome=denied"
expect_event "EVENT access_request=$SERVER_REQUEST outcome=denied"
EVENT_COUNT="$(grep -c '^EVENT ' "$WORK/server.out" || true)"
[ "$EVENT_COUNT" -eq 4 ] || fail "the server printed $EVENT_COUNT EVENT lines, not 4"

printf '\ncompanion-interop: PASSED\n'
