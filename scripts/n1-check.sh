#!/bin/bash
# Owner check for goal item N1: a waiting approval and a blocked request cause
# a native macOS notification within 5 seconds.
#
# The script uses the real path of the signed app:
#   Apassy.app/Contents/MacOS/apassy --notify-check STEP
#     -> Contents/Helpers/ApassyNotify.app (child of apassy, caller check)
#     -> UNUserNotificationCenter of com.wydrox.apassy.notify ("Apassy")
#
# Steps:
#   1. Read the notification permission. No prompt.
#   2. If the owner has not decided: ask macOS for permission. macOS shows a
#      prompt for "Apassy" at the top right of the screen. Click "Allow". The
#      script waits up to 120 s. macOS removes an unanswered prompt, and the
#      permission then stays "denied" (measured on macOS 27).
#   2b. If the permission is "denied": macOS does not ask again. The script
#      opens System Settings > Notifications. Select "Apassy" and turn on
#      "Allow notifications". The script waits up to 300 s
#      (N1_SETTINGS_WAIT).
#   3. Post two test notifications with the fixed templates and the agent name
#      "n1-check": "Approval waiting" and "Request blocked".
#   4. Measure the time from each request to the delivery. Sources: the
#      notifier answer (Notification Center lists the notification) and the
#      usernoted "Delivering" event in the unified log.
#
# Usage: scripts/n1-check.sh [APP]
#   APP  the signed app bundle. Default: target/Apassy.app.
#
# Run it from a terminal outside the agent profile. The agent profile denies
# the start of the programs in Apassy.app. See docs/operations/notifications.md.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP="${1:-$ROOT/target/Apassy.app}"
EXE="$APP/Contents/MacOS/apassy"
NOTIFY_ID="com.wydrox.apassy.notify"
SETTINGS_URL="x-apple.systempreferences:com.apple.Notifications-Settings.extension?id=$NOTIFY_ID"
# Seconds to wait for the owner in System Settings. N1_SETTINGS_WAIT changes it.
SETTINGS_WAIT="${N1_SETTINGS_WAIT:-300}"
[[ "$SETTINGS_WAIT" =~ ^[0-9]+$ ]] || { echo "n1-check: N1_SETTINGS_WAIT must be a number" >&2; exit 2; }
LIMIT_MS=5000

step() { printf '\n==> %s\n' "$*"; }
fail() { printf '\nn1-check: FAILED: %s\n' "$*" >&2; exit 1; }
field() { # line key -> value
  printf '%s\n' "$1" | tr ' ' '\n' | sed -n "s/^$2=//p" | head -n 1
}
# Unix time in ms from "1790458888.123".
ms_of() { printf '%s' "${1/./}"; }
# Unix time in ms from a unified log timestamp "2026-09-26 23:36:28.381074+0200".
log_ms() {
  local ts="$1" base frac zone secs
  base="${ts:0:19}"
  frac="${ts:20:6}"
  zone="${ts:26}"
  secs="$(date -j -f "%Y-%m-%d %H:%M:%S%z" "$base$zone" +%s)"
  printf '%s' "$((secs * 1000 + 10#$frac / 1000))"
}

[ "$(uname -s)" = "Darwin" ] || fail "this check runs on macOS only"
[ -x "$EXE" ] || fail "no app at $APP. Run scripts/build-app.sh first."
codesign --verify --deep --strict "$APP" 2>/dev/null || fail "the signature of $APP is not valid"
[ -x "$APP/Contents/Helpers/ApassyNotify.app/Contents/MacOS/ApassyNotify" ] \
  || fail "$APP has no notifier. Run scripts/build-app.sh again."
TMP="$(mktemp -d "${TMPDIR:-/tmp}/apassy-n1.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

step "Read the notification permission of \"Apassy\" ($NOTIFY_ID)"
STATUS="$("$EXE" --notify-check status)" || fail "$STATUS"
echo "$STATUS"
AUTH="$(field "$STATUS" authorization)"

if [ "$AUTH" = "not_determined" ]; then
  step "Ask macOS for permission"
  echo "macOS shows a prompt for \"Apassy\" at the top right of the screen now."
  echo "Click \"Allow\". The script waits up to 120 s."
  SINCE="$(date '+%Y-%m-%d %H:%M:%S')"
  "$EXE" --notify-check authorize >"$TMP/authorize.txt" 2>&1 &
  PID=$!
  # usernoted logs the prompt request. This shows that the prompt is on screen.
  SHOWN=""
  for _ in $(seq 1 20); do
    SHOWN="$(/usr/bin/log show --start "$SINCE" --style compact \
      --predicate "process == \"usernoted\" AND eventMessage CONTAINS \"Sending request for permission for $NOTIFY_ID\"" \
      2>/dev/null | grep "Sending request for permission" | head -n 1 || true)"
    [ -n "$SHOWN" ] && break
    kill -0 "$PID" 2>/dev/null || break
    sleep 0.5
  done
  if [ -n "$SHOWN" ]; then
    echo "prompt: on screen. usernoted: $SHOWN"
  else
    echo "prompt: usernoted did not log a permission request yet."
  fi
  echo "Waiting for your answer..."
  wait "$PID" || true
  RESULT="$(cat "$TMP/authorize.txt")"
  echo "$RESULT"
  case "$RESULT" in authorize\ error=*) fail "the permission request failed: $RESULT" ;; esac
  AUTH="$(field "$RESULT" authorization)"
  WAITED_MS=$(( $(ms_of "$(field "$RESULT" answered_at)") - $(ms_of "$(field "$RESULT" started_at)") ))
  echo "The permission request took $WAITED_MS ms."
  if [ "$AUTH" = "not_determined" ] && [ "$WAITED_MS" -lt 110000 ]; then
    fail "macOS answered in $WAITED_MS ms without a decision. No prompt was on the screen. Check: log show --last 5m --predicate 'process == \"usernoted\"'"
  fi
  if [ "$AUTH" = "not_determined" ]; then
    echo
    echo "You did not answer in 120 s. If the prompt is still on the screen, click \"Allow\","
    echo "then run this script again: scripts/n1-check.sh"
    exit 2
  fi
fi

if [ "$AUTH" = "denied" ]; then
  # macOS shows no new prompt after a denial or after an unanswered prompt.
  # Only System Settings can turn the notifications on.
  step "Turn on notifications for \"Apassy\" in System Settings"
  echo "Notifications for \"Apassy\" are off, and macOS does not ask again."
  echo "The script opens System Settings > Notifications. Select \"Apassy\", turn on"
  echo "\"Allow notifications\", and select the style \"Banners\"."
  echo "The script waits up to $SETTINGS_WAIT s."
  /usr/bin/open "$SETTINGS_URL" || echo "Open System Settings > Notifications > Apassy yourself."
  for _ in $(seq 1 "$SETTINGS_WAIT"); do
    STATUS="$("$EXE" --notify-check status)" || fail "$STATUS"
    AUTH="$(field "$STATUS" authorization)"
    [ "$AUTH" = "denied" ] || break
    sleep 1
  done
  echo "$STATUS"
  if [ "$AUTH" = "denied" ]; then
    echo
    echo "Notifications for \"Apassy\" are still off. Turn them on in System Settings > Notifications > Apassy,"
    echo "then run this script again: scripts/n1-check.sh"
    exit 2
  fi
fi

case "$AUTH" in
  authorized|provisional) ;;
  *) fail "unexpected permission: $AUTH" ;;
esac
[ "$(field "$STATUS" can_deliver)" = "true" ] || [ -z "$(field "$STATUS" can_deliver)" ] \
  || echo "Warning: alerts and Notification Center are off for \"Apassy\". Turn them on in System Settings."

step "Post the two test notifications (agent \"n1-check\")"
SINCE="$(date -v-1S '+%Y-%m-%d %H:%M:%S')"
POST="$("$EXE" --notify-check post)" || true
echo "$POST"
printf '%s\n' "$POST" | grep -q '^post error=' && fail "a notification failed"
[ "$(printf '%s\n' "$POST" | grep -c '^post event=')" = "2" ] || fail "expected two notifications"
sleep 2

step "Measure the time from each request to the delivery"
/usr/bin/log show --start "$SINCE" --style ndjson \
  --predicate 'process == "usernoted" AND eventMessage CONTAINS "Delivering" AND eventMessage CONTAINS "n1-check-"' \
  2>/dev/null >"$TMP/delivered.ndjson" || true
PASS=1
printf '%-17s %-12s %-24s %-9s %s\n' "event" "delivered" "request -> answer" "limit" "request -> usernoted Delivering"
while IFS= read -r line; do
  event="$(field "$line" event)"
  id="$(field "$line" id)"
  requested="$(ms_of "$(field "$line" requested_at)")"
  answered="$(ms_of "$(field "$line" answered_at)")"
  delivered="$(field "$line" delivered)"
  answer_ms=$((answered - requested))
  log_line="$(grep -F "req:\\\"$id\\\"" "$TMP/delivered.ndjson" | head -n 1 || true)"
  if [ -n "$log_line" ]; then
    ts="$(printf '%s' "$log_line" | sed -n 's/.*"timestamp":"\([^"]*\)".*/\1/p')"
    log_delay="$(( $(log_ms "$ts") - requested )) ms (log $ts)"
  else
    log_delay="no usernoted Delivering event found"
  fi
  verdict="PASS"
  if [ "$delivered" != "true" ] || [ "$answer_ms" -gt "$LIMIT_MS" ]; then verdict="FAIL"; PASS=0; fi
  printf '%-17s %-12s %-24s %-9s %s\n' "$event" "$delivered" "$answer_ms ms" "$verdict" "$log_delay"
done < <(printf '%s\n' "$POST" | grep '^post event=')

echo
echo "Look at the screen: two banners from \"Apassy\", \"Approval waiting\" and \"Request blocked\","
echo "with the agent \"n1-check\" and no other text. A Focus mode hides banners; the notifications"
echo "then go to Notification Center only."
if [ "$PASS" = "1" ]; then
  echo "n1-check: PASS. Record the lines above in docs/operations/notifications.md."
else
  fail "a notification was not delivered within $LIMIT_MS ms"
fi
