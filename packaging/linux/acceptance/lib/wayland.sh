#!/usr/bin/env bash
# Wayland session plumbing for the acceptance kit (host mode). Source after lib/l4.sh.
#
# A headless sway (wlroots, wlr-data-control) runs inside the owner's logind session,
# without X: DISPLAY is unset for every client, so the Apassy window and its Copy use
# Wayland only. Input comes from the virtual keyboard and pointer protocols (wtype,
# wlrctl), screenshots from wlr-screencopy (grim). Needs: sway grim wtype wlrctl
# wl-clipboard.

l4_wl_env() { l4_as cat /tmp/l4/sway.env 2>/dev/null | tr '\n' ' '; }

# Run a command as the owner inside the sway session, without X.
l4_wl() {
    local uid
    uid=$(id -u "$L4_USER")
    # shellcheck disable=SC2046
    sudo -u "$L4_USER" env -u DISPLAY -u XAUTHORITY XDG_RUNTIME_DIR="/run/user/$uid" \
        DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" $(l4_wl_env) "$@"
}

l4_wayland_up() {
    l4_as rm -f /tmp/l4/sway.env
    # The owner cannot read the kit in another home: give it its own copy.
    sudo install -o "$L4_USER" -m 0644 "$L4_KIT/lib/sway.conf" "/home/$L4_USER/.l4-sway.conf"
    l4_spawn sway env -u DISPLAY WLR_BACKENDS=headless WLR_LIBINPUT_NO_DEVICES=1 \
        WLR_RENDERER=pixman sway -c "/home/$L4_USER/.l4-sway.conf"
    local i
    for i in $(seq 1 50); do l4_as test -s /tmp/l4/sway.env && break; sleep 0.2; done
    l4_as test -s /tmp/l4/sway.env || l4_die 'sway did not start'
    l4_log "sway: $(l4_wl_env)"
    l4_wl swaymsg -t get_version | head -n 3 >&2
}

# Start a long-running command in the sway session; output to /tmp/l4/NAME.log.
l4_wl_spawn() {
    local name=$1; shift
    local uid env
    uid=$(id -u "$L4_USER")
    env=$(l4_wl_env)
    sudo -u "$L4_USER" tmux new-window -d -t l4 -n "$name" \
        "unset DISPLAY XAUTHORITY; export XDG_RUNTIME_DIR=/run/user/$uid DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$uid/bus $env; mkdir -p /tmp/l4; $* >>/tmp/l4/$name.log 2>&1; echo exit=\$? >>/tmp/l4/$name.log"
}

l4_wl_shot() {
    l4_wl grim "/tmp/l4-wl-shot.png"
    l4_as cat /tmp/l4-wl-shot.png > "$L4_OUT/shots/$1.png"
    l4_log "screenshot $L4_OUT/shots/$1.png"
}

l4_wl_type() { l4_wl wtype -d 40 -- "$1"; }
l4_wl_key() { local key; for key in "$@"; do l4_wl wtype -k "$key"; sleep 0.1; done; }
# Absolute click: the virtual pointer moves relatively, so go to the top left first.
l4_wl_click() {
    l4_wl wlrctl pointer move -3200 -2000; sleep 0.1
    l4_wl wlrctl pointer move "$1" "$2"; sleep 0.3
    l4_wl wlrctl pointer click left; sleep "${3:-0.6}"
}
