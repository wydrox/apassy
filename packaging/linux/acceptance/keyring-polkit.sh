#!/usr/bin/env bash
# Optional Secret Service unlock (gnome-keyring on the owner's session bus) and the
# optional polkit auth_self presence check, in the owner's local seat session
# (host mode only; see lib/l4.sh). Keys are typed into real terminals (tmux panes).
#
#   keyring-polkit.sh keyring   # opt-in, refusal, unlock, disable, locked keyring
#   keyring-polkit.sh polkit    # pkcheck through a terminal agent: wrong, cancel, right
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$here/lib/l4.sh"
[ -z "$L4_CONTAINER" ] || l4_die 'keyring/polkit checks need the host seat session'
what=${1:?usage: keyring-polkit.sh keyring|polkit}
out="$L4_OUT/$what.txt"
: > "$out"
T=(sudo -u "$L4_USER" tmux)
pass=$(l4_vault_passphrase)
login=$(l4_login_password)
result() { echo "$1 $2" >> "$out"; l4_log "$1 $what $2"; }
pane() { "${T[@]}" capture-pane -p -J -t "l4:$1" -S -2000; }
win() { # win NAME CMD: a fresh shell window running CMD
    "${T[@]}" kill-window -t "l4:$1" 2>/dev/null || true
    "${T[@]}" new-window -d -t l4 -n "$1" "bash --norc"
    sleep 0.5
    "${T[@]}" send-keys -t "l4:$1" -l "$2"; "${T[@]}" send-keys -t "l4:$1" Enter
}
send() { "${T[@]}" send-keys -t "l4:$1" -l "$2"; "${T[@]}" send-keys -t "l4:$1" Enter; }
wait_in() { # wait_in WINDOW TEXT [COUNT]: wait until TEXT occurs COUNT times
    local i n=${3:-1}
    for i in $(seq 1 100); do
        [ "$(pane "$1" | grep -cF -- "$2")" -ge "$n" ] && return 0
        sleep 0.3
    done
    pane "$1" >> "$out"; l4_die "$what: timed out waiting for '$2' in $1"
}

cur=''
# The text after the latest "==== NAME" marker line of window kr.
section() { pane kr | awk -v m="==== $cur" '$0 == m {buf = ""; f = 1; next} f {buf = buf $0 "\n"} END {printf "%s", buf}'; }
wait_for() {
    local i
    for i in $(seq 1 150); do section | grep -qF -- "$1" && return 0; sleep 0.3; done
    section >> "$out"; l4_die "$what: timed out waiting for '$1' after marker $cur"
}
step() { [ -z "$cur" ] || { printf -- '--- %s\n' "$cur"; section | grep -vF -- "$pass"; } >> "$out"; cur=$1; send kr "echo ==== $1"; wait_for '$'; }
has() { section | grep -qF -- "$1"; }
wait_rc() { local i; for i in $(seq 1 200); do section | grep -qE '^rc:[0-9]+$' && return 0; sleep 0.3; done; section >> "$out"; l4_die "$what: no exit status after marker $cur"; }

if [ "$what" = keyring ]; then
    V="/home/$L4_USER/l4-keyring.db"
    l4_as rm -f "$V"
    # A login keyring unlocked with the synthetic login password, on the user bus.
    l4_as bash -c 'pkill -u "$(id -u)" -x gnome-keyring-d || true'
    printf '%s' "$login" | l4_as gnome-keyring-daemon --unlock --components=secrets --daemonize >/dev/null
    sleep 1
    l4_as secret-tool clear application apassy vault "$V" 2>/dev/null || true
    win kr "echo ready"
    step create
    send kr "apassy owner create $V"
    wait_for "New vault passphrase:"; send kr "$pass"
    wait_for "Repeat passphrase:"; send kr "$pass"
    wait_for "Vault created and locked."
    # 1. Declined consent stores nothing.
    step decline
    send kr "apassy owner keyring-enable $V; echo rc:\$?"
    wait_for "Vault passphrase:"; send kr "$pass"
    wait_for "[y/N]"; send kr "n"
    wait_rc
    if has "Keyring storage cancelled" && [ -z "$(l4_as secret-tool lookup application apassy vault "$V" || true)" ]; then
        result PASS declined-consent-stores-nothing; else result FAIL declined-consent-stores-nothing; fi
    # 2. Explicit consent stores the passphrase through secret-tool's stdin.
    step consent
    send kr "apassy owner keyring-enable $V; echo rc:\$?"
    wait_for "Vault passphrase:"; send kr "$pass"
    wait_for "[y/N]"; send kr "y"
    wait_for "Confirm vault passphrase:"; send kr "$pass"
    wait_rc
    if has "Keyring unlock enabled by explicit consent."; then result PASS consent-stores; else result FAIL consent-stores; fi
    # The documented warning, observed: another same-user client reads the item.
    if [ "$(l4_as secret-tool lookup application apassy vault "$V" || true)" = "$pass" ]; then
        result PASS same-user-client-can-read-item-as-documented; else result FAIL same-user-client-can-read-item-as-documented; fi
    # 3. unlock-keyring opens without a typed passphrase.
    step unlock
    send kr "apassy owner unlock-keyring $V; echo rc:\$?"
    wait_for "apassy owner>"
    send kr "list"; send kr "lock"
    wait_rc
    if has "Vault unlocked for this terminal session" && ! has "passphrase:"; then result PASS unlock-keyring-opens-without-typing; else result FAIL unlock-keyring-opens-without-typing; fi
    # 4. Without the session bus the keyring path fails closed.
    step nobus
    send kr "env -u DBUS_SESSION_BUS_ADDRESS -u XDG_RUNTIME_DIR -u DISPLAY apassy owner unlock-keyring $V; echo rc:\$?"
    wait_rc
    if has "rc:1" && ! has "apassy owner>"; then result PASS no-bus-refuses; else result FAIL no-bus-refuses; fi
    # 5. A locked keyring does not unlock silently (no prompter in this session).
    l4_as bash -c 'pkill -u "$(id -u)" -x gnome-keyring-d || true'; sleep 1
    l4_as gnome-keyring-daemon --components=secrets --daemonize </dev/null >/dev/null; sleep 1
    step locked
    send kr "timeout 60 apassy owner unlock-keyring $V; echo rc:\$?"
    wait_rc
    if ! has "rc:0" && ! has "apassy owner>"; then result PASS locked-keyring-refuses; else result FAIL locked-keyring-refuses; fi
    # 6. keyring-disable removes the item (keyring unlocked again first).
    l4_as bash -c 'pkill -u "$(id -u)" -x gnome-keyring-d || true'; sleep 1
    printf '%s' "$login" | l4_as gnome-keyring-daemon --unlock --components=secrets --daemonize >/dev/null; sleep 1
    step disable
    send kr "apassy owner keyring-disable $V; echo rc:\$?"
    wait_for "Vault passphrase:"; send kr "$pass"
    wait_rc
    if has "Keyring unlock item removed." && [ -z "$(l4_as secret-tool lookup application apassy vault "$V" || true)" ]; then
        result PASS disable-removes; else result FAIL disable-removes; fi
    step end
    pane kr > "$L4_OUT/keyring-terminal.txt"
    if grep -qF -- "$pass" "$L4_OUT/keyring-terminal.txt"; then result FAIL no-echo; else result PASS no-echo; fi
    "${T[@]}" kill-window -t l4:kr
fi

if [ "$what" = polkit ]; then
    # A terminal polkit agent for the Apassy window process (a desktop's session
    # agent would serve the whole session; pkttyagent without --process serves only
    # its parent).
    ap=$(pgrep -u "$L4_USER" -xo apassy) || l4_die 'start the Apassy window first'
    "${T[@]}" kill-window -t l4:pkagent 2>/dev/null || true
    "${T[@]}" new-window -d -t l4 -n pkagent "pkttyagent --process $ap; echo pkttyagent-exit=\$?; sleep 3600"
    sleep 1
    l4_log "polkit agent registered for Apassy pid $ap; drive the owner check with the steps in README.md"
    echo "agent-for-pid $ap" >> "$out"
fi
l4_log "$what: $(grep -c '^PASS' "$out" || true) PASS, $(grep -c '^FAIL' "$out" || true) FAIL ($out)"
