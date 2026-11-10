#!/usr/bin/env bash
# Caller-check refusals against the installed host and the running Apassy window
# (host mode). Prints one PASS/FAIL line per case into $L4_OUT/refusals.txt.
#
#   refusals.sh api        # no browser needed: wrong parents, users and origins
#   refusals.sh browser    # needs Chrome with the extension and passkeys on
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$here/lib/l4.sh"
. "$here/lib/flows.sh"
what=${1:?usage: refusals.sh api|browser}
out="$L4_OUT/refusals-$what.txt"
: > "$out"
result() { echo "$1 $2 ($3)" >> "$out"; l4_log "$1 refusal $2: $3"; }
expect() { # expect NAME WANT GOT
    if [ "$3" = "$2" ]; then result PASS "$1" "$3"; else result FAIL "$1" "got $3, want $2"; fi
}
sock="/home/$L4_USER/.local/share/apassy/browser.sock"
frame=/tmp/l4-native_frame.py
install -m 0644 "$here/lib/native_frame.py" "$frame"

if [ "$what" = api ]; then
    expect host-under-python-parent unsupported "$(l4_as python3 -I "$frame" host)"
    expect host-under-shell-parent unsupported "$(l4_as bash -c "python3 -I $frame host")"
    expect host-as-root unsupported "$(sudo python3 -I "$frame" host)"
    expect root-peer-on-owner-socket unsupported "$(sudo python3 -I "$frame" socket "$sock" 2>&1 | tail -n 1)"
    expect owner-process-not-host unsupported "$(l4_as python3 -I "$frame" socket "$sock")"
    got=$(python3 -I "$frame" socket "$sock" 2>&1 | tail -n 1 | grep -o 'Permission denied' || true)
    expect other-user-cannot-connect 'Permission denied' "$got"
    set +e
    l4_as /usr/lib/apassy/apassy-browser-host chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/ </dev/null >/dev/null 2>&1
    expect other-extension-origin-exit 2 "$?"
    set -e
fi

if [ "$what" = browser ]; then
    # Each case starts Chrome itself and expects the browser's own dialog instead of
    # an Apassy card: no RP event, and Apassy shows nothing to approve.
    restart_chrome() {
        sudo -u "$L4_USER" pkill -TERM -f "$1" 2>/dev/null || true; sleep 3
        "${T[@]}" kill-window -t l4:chrome 2>/dev/null || true
        shift
        l4_spawn chrome "$@" "http://localhost:$L4_RP_PORT/passkey.html"; sleep 8
        l4_click 1025 125 0.5
    }
    T=(sudo -u "$L4_USER" tmux)
    refused_get() { # NAME: a sign-in must not reach an Apassy card or the RP
        local n; n=$(l4_rp_count)
        l4_activate 'L4 passkey'; l4_click 600 700 0.5; l4_key g; sleep 5
        l4_shot "refusal-$1"
        local events; events=$(l4_rp_status | jq -c --argjson n "$n" '[.events[$n:][] | select(.kind == "authentication" and .ok)] | length')
        l4_key Escape; sleep 1
        if [ "$events" = 0 ]; then result PASS "$1" 'no verified sign-in; see screenshot'; else result FAIL "$1" 'a sign-in verified'; fi
    }
    restart_chrome /opt/google/chrome/chrome /usr/bin/google-chrome-stable --remote-debugging-port=9333
    refused_get chrome-with-remote-debugging-switch
    sudo rm -rf /opt/l4-fakechrome && sudo cp -a /opt/google/chrome /opt/l4-fakechrome
    restart_chrome /opt/google/chrome/chrome /opt/l4-fakechrome/chrome
    refused_get copied-chrome-at-unknown-path
    restart_chrome /opt/l4-fakechrome/chrome /usr/bin/google-chrome-stable
    sudo rm -rf /opt/l4-fakechrome
    sudo chmod o+w /opt/google/chrome/chrome
    refused_get writable-chrome-binary
    sudo chmod 0755 /opt/google/chrome/chrome
fi
l4_log "refusals $what: $(grep -c '^PASS' "$out" || true) PASS, $(grep -c '^FAIL' "$out" || true) FAIL ($out)"
