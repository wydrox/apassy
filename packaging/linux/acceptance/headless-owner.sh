#!/usr/bin/env bash
# Headless owner commands: passphrase only, no session bus, no display, no logind
# session, no keyring. A separate synthetic account (L4_HEADLESS_USER) runs the
# installed /usr/bin/apassy in a real pseudo-terminal (a private tmux server of the
# calling user); keys are sent to it as a person would type them.
# Usage: headless-owner.sh   (host mode; or L4_CONTAINER=name for a container)
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$here/lib/l4.sh"
H=${L4_HEADLESS_USER:-l4headless}
T=(tmux -L l4h)
out="$L4_OUT/headless-owner.txt"
: > "$out"
pass=$(l4_vault_passphrase 2>/dev/null || { l4_make_secrets; l4_vault_passphrase; })
new_pass="${pass}-changed"

l4_root bash -c "id $H >/dev/null 2>&1 || useradd -m -s /bin/bash $H"
l4_root bash -c "rm -rf /home/$H/l4 && install -d -o $H -g $H -m 0700 /home/$H/l4"
"${T[@]}" kill-server 2>/dev/null || true
if [ -n "$L4_CONTAINER" ]; then
    inner="docker exec -it -u $H -e HOME=/home/$H -e TERM=xterm-256color -e PATH=/usr/bin:/bin $L4_CONTAINER bash --noprofile --norc"
else
    inner="sudo -u $H env -i HOME=/home/$H TERM=xterm-256color PATH=/usr/bin:/bin bash --noprofile --norc"
fi
"${T[@]}" new-session -d -s h -x 160 -y 48 "$inner"
sleep 1
cur=''
pane() { "${T[@]}" capture-pane -p -J -t h -S -5000; }
# The text printed after the latest "==== NAME" marker line.
section() { pane | awk -v m="==== $cur" '$0 == m {buf = ""; f = 1; next} f {buf = buf $0 "\n"} END {printf "%s", buf}'; }
line() { "${T[@]}" send-keys -t h -l "$1"; "${T[@]}" send-keys -t h Enter; }
wait_for() {
    local i
    for i in $(seq 1 100); do section | grep -qF -- "$1" && return 0; sleep 0.3; done
    section >> "$out"; l4_die "headless: timed out waiting for: $1"
}
result() { echo "$1 $2" >> "$out"; l4_log "$1 headless $2"; }
check() { if section | grep -qF -- "$2"; then result PASS "$1"; else result FAIL "$1"; fi; }
mark() { [ -z "$cur" ] || { printf -- '--- %s\n' "$cur"; section; } >> "$out"; cur=$1; line "echo ==== $1"; wait_for "$"; sleep 0.3; }

mark env
line 'echo "bus=${DBUS_SESSION_BUS_ADDRESS:-none} display=${DISPLAY:-none} wayland=${WAYLAND_DISPLAY:-none} runtime=${XDG_RUNTIME_DIR:-none}"; ls /run/user/$(id -u) 2>&1 | head -1; tty'
sleep 1; check no-session-bus "bus=none display=none wayland=none runtime=none"

V=/home/$H/l4/vault.db
mark create
line "apassy owner create $V"
wait_for "New vault passphrase:"; line "$pass"
wait_for "Repeat passphrase:"; line "$pass"
wait_for "Vault created and locked."
check create "Vault created and locked."

mark add
line "apassy owner add $V"
wait_for "Vault passphrase:"; line "$pass"
wait_for "Item name:"; line "L4 headless item"
wait_for "Secret value:"; line "l4-synthetic-secret-value"
wait_for "Vault locked."
check add "Added item"

mark list
line "apassy owner list $V"
wait_for "Vault passphrase:"; line "$pass"
wait_for "Vault locked."
check list "L4 headless item"

mark wrong
line "apassy owner list $V"
wait_for "Vault passphrase:"; line "not-the-passphrase"
wait_for "apassy owner:"
if section | grep -q "L4 headless item"; then result FAIL wrong-passphrase-refused; else check wrong-passphrase-refused "The passphrase is wrong, or the vault file is damaged."; fi
# One clear line: no SQLCipher log lines (R5 of the first run).
if section | grep -qiE "sqlcipher|hmac|ERROR CORE"; then result FAIL wrong-passphrase-one-line; else result PASS wrong-passphrase-one-line; fi

mark pipe
line "echo piped-input | apassy owner list $V; echo exit=\$?"
wait_for "exit="
check refuses-redirected-input "redirected input is refused"

mark backup
line "apassy owner backup $V /home/$H/l4/backup.db"
wait_for "Vault passphrase:"; line "$pass"
wait_for "Confirm with vault passphrase:"; line "$pass"
wait_for "Vault locked."
check backup "Encrypted backup written."
line "stat -c '%a %n' /home/$H/l4/backup.db $V"
sleep 1; 
mark change
line "apassy owner change-passphrase $V"
wait_for "Current passphrase:"; line "$pass"
wait_for "New passphrase:"; line "$new_pass"
wait_for "Repeat new passphrase:"; line "$new_pass"
wait_for "Vault locked."
check change-passphrase "Passphrase changed."
# One passphrase prompt (R6 of the first run), and no "Vault passphrase:" before it.
if [ "$(section | grep -c "^Current passphrase:")" = 1 ] && ! section | grep -q "Vault passphrase:"; then
    result PASS change-passphrase-asks-once
else
    result FAIL change-passphrase-asks-once
fi

mark shell
line "apassy owner shell $V"
wait_for "Vault passphrase:"; line "$new_pass"
wait_for "apassy owner>"
line "list"; sleep 1
check shell-list "L4 headless item"
line "lock"
wait_for "Vault locked."

mark oldpass
line "apassy owner list /home/$H/l4/backup.db"
wait_for "Vault passphrase:"; line "$pass"
wait_for "Vault locked."
check backup-opens-with-old-passphrase "L4 headless item"

mark end
# The terminal must never have shown a passphrase or the secret value.
pane > "$L4_OUT/headless-owner-terminal.txt"
if grep -qF -- "$pass" "$L4_OUT/headless-owner-terminal.txt" || grep -qF -- "l4-synthetic-secret-value" "$L4_OUT/headless-owner-terminal.txt"; then
    echo "FAIL no-echo" >> "$out"; l4_log "FAIL headless: a secret appeared on the terminal"
else
    echo "PASS no-echo" >> "$out"; l4_log "PASS headless: no secret echoed"
fi
"${T[@]}" kill-server
l4_log "headless: $(grep -c '^PASS' "$out" || true) PASS, $(grep -c '^FAIL' "$out" || true) FAIL ($out)"
