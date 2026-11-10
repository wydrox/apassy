#!/usr/bin/env bash
# Desktop and browser flows, driven with real X input (xdotool) on the private Xvfb
# display, never through DevTools. Coordinates fit a 1600x1000 screen, openbox,
# Apassy 0.5.19, Google Chrome 157 and Debian Chromium 156. Every step saves a
# screenshot: look at them; a moved banner or dialog makes a click miss.
# Source after lib/l4.sh.

l4_activate() {
    local w
    w=$(l4_as xdotool search --name "$1" | head -n 1) || return 1
    l4_as xdotool windowactivate --sync "$w" 2>/dev/null || true
    sleep 0.4
}

# First run of the window: create the vault "L4 <name>" with the synthetic passphrase.
flow_apassy_first_run() {
    l4_spawn apassy /usr/bin/apassy
    l4_wait_window '^Apassy$' 30 || l4_die 'the Apassy window did not appear'
    sleep 3
    l4_shot "${1}-01-first-run"
    l4_click 800 556 1.5                      # Create my first vault
    l4_type "L4 ${1}"
    l4_click 878 460 0.3; l4_type "$(l4_vault_passphrase)"
    l4_click 878 502 0.3; l4_type "$(l4_vault_passphrase)"
    l4_shot "${1}-02-create-vault"
    l4_click 800 758 4                        # Create vault
    l4_shot "${1}-03-item-list"
}

flow_apassy_unlock() {
    l4_activate '^Apassy$'
    l4_click 878 528 0.5
    l4_type "$(l4_vault_passphrase)"
    l4_key Return
    sleep 3
    l4_shot "${1}-unlocked"
}

# Google Chrome first run in the EEA: terms, defaults dialog, sign-in screen.
flow_chrome_first_run() {
    l4_spawn chrome /usr/bin/google-chrome-stable
    sleep 9
    l4_shot "${1}-10-chrome-terms"
    l4_click 1038 714 5                       # Accept
    l4_click 583 448 0.4; l4_click 583 484 0.4  # untick default browser, usage stats
    l4_click 992 541 6                        # OK
    l4_click 1076 836 5                       # Stay signed out
    l4_shot "${1}-11-chrome-ready"
}

# chrome://extensions > Developer mode > Load unpacked > the packaged folder.
# Y is the toolbar-relative offset: 0 for Chrome with its restore banner, -22 for
# Debian Chromium (bookmark bar, no banner), -56 for Chrome without the banner.
flow_load_unpacked() {
    local name=$1 dy=${2:-0}
    l4_key ctrl+l; l4_type 'chrome://extensions'; l4_key Return; sleep 3
    l4_click 1030 $((181 + dy)) 1.5           # Developer mode
    l4_click 99 $((237 + dy)) 3               # Load unpacked
    l4_key ctrl+l; sleep 0.5
    l4_type /usr/share/apassy/browser-extension; sleep 1
    l4_shot "${name}-12-folder-chooser"
    l4_click 1075 894 4                       # Open
    l4_shot "${name}-13-extension-loaded"
}

# Popup > Settings > Use Apassy passkeys > Allow (site access).
flow_enable_passkeys() {
    local name=$1
    l4_key ctrl+l; l4_type "http://localhost:$L4_RP_PORT/passkey.html"; l4_key Return; sleep 2
    l4_click 906 72 2                         # the pinned Apassy button
    l4_shot "${name}-14-popup"
    l4_click 878 507 1.5                      # Settings
    l4_click 590 333 2                        # Use Apassy passkeys in this browser
    l4_shot "${name}-15-permission"
    l4_click 699 266 2                        # Allow
    l4_key F5; sleep 2
}

# One ceremony on the RP page by keyboard (c, g, w, x), approved with the vault
# passphrase in the Apassy card unless APPROVE=no. Prints the new RP events.
flow_ceremony() {
    local name=$1 key=$2 approve=${3:-yes} n
    l4_activate 'L4 passkey'
    l4_click 600 700 0.5
    n=$(l4_rp_count)
    l4_key "$key"; sleep 4
    l4_shot "${name}-ceremony-${key}"
    if [ "$approve" = yes ]; then
        l4_type "$(l4_vault_passphrase)"; l4_key Return; sleep 4
    fi
    l4_rp_status | jq -c --argjson n "$n" '.events[$n:][] | {kind, ok, aaguid, userVerified, negative, name, error}'
}

# Save a typed synthetic login, then fill it into a fresh page and submit it.
flow_save_and_fill() {
    local name=$1 n
    l4_activate 'L4 '
    l4_key ctrl+l; l4_type "http://localhost:$L4_RP_PORT/login.html"; l4_key Return; sleep 2
    l4_click 270 277 0.5; l4_type 'synthetic.login@example.test'; l4_key Escape
    l4_click 266 337 0.5; l4_type "$(cat "$L4_STATE/site-password")"; l4_key Escape
    l4_click 906 72 2
    l4_shot "${name}-20-popup-save"
    echo 'Click "Save this login", then Save, then confirm in Apassy (layout depends on existing logins).' >&2
    n=$(l4_rp_count)
    echo "$n"
}
