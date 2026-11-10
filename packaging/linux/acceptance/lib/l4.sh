#!/usr/bin/env bash
# Session plumbing for the Linux vault acceptance kit. Source it; do not execute.
#
# Host mode (default, needs systemd-logind, a VT and sudo): a synthetic owner
# account (L4_USER) logs in automatically on a virtual terminal of seat0, so its
# processes run in a local, active logind session, as on a desktop. Everything
# for that account runs inside one tmux server started by that login, on an
# authenticated private Xvfb display. polkit's allow_active therefore applies
# for real, and the session D-Bus is the user's systemd bus.
#
# Container mode (L4_CONTAINER=name): the same commands run through docker exec
# in a disposable container. There is no logind seat, so polkit is not tested.
set -euo pipefail

L4_USER=${L4_USER:-l4owner}
L4_VT=${L4_VT:-3}
L4_DISPLAY=${L4_DISPLAY:-:50}
L4_GEOMETRY=${L4_GEOMETRY:-1600x1000x24}
L4_STATE=${L4_STATE:-$HOME/work/l4/state}
L4_OUT=${L4_OUT:-$HOME/work/l4/out}
L4_CONTAINER=${L4_CONTAINER:-}
L4_KIT=${L4_KIT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
L4_NODE=${L4_NODE:-/opt/l4-node/bin/node}
mkdir -p "$L4_STATE" "$L4_OUT/shots" "$L4_OUT/logs"
chmod 700 "$L4_STATE"

l4_log() { printf '[l4 %s] %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$L4_OUT/logs/driver.log" >&2; }
l4_die() { l4_log "FAIL: $*"; exit 1; }

# Run a command as the owner account, with the session environment.
l4_as() {
    if [ -n "$L4_CONTAINER" ]; then
        docker exec -i -u "$L4_USER" -e DISPLAY="$L4_DISPLAY" -e XAUTHORITY="/home/$L4_USER/.Xauthority" \
            -e DBUS_SESSION_BUS_ADDRESS="unix:path=/home/$L4_USER/.l4-bus" "$L4_CONTAINER" "$@"
    else
        local uid
        uid=$(id -u "$L4_USER")
        sudo -u "$L4_USER" env DISPLAY="$L4_DISPLAY" XAUTHORITY="/home/$L4_USER/.Xauthority" \
            XDG_RUNTIME_DIR="/run/user/$uid" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" "$@"
    fi
}

l4_root() {
    if [ -n "$L4_CONTAINER" ]; then docker exec -i "$L4_CONTAINER" "$@"; else sudo "$@"; fi
}

# Start a long-running command inside the owner's session (host: its tmux server on
# the VT login; container: a detached docker exec). Output goes to /tmp/l4/NAME.log
# of the owner account.
l4_spawn() {
    local name=$1; shift
    # No exec: Chrome started as the pane's own process exited at once in tmux.
    local cmd="mkdir -p /tmp/l4; $* >>/tmp/l4/$name.log 2>&1; echo exit=\$? >>/tmp/l4/$name.log"
    if [ -n "$L4_CONTAINER" ]; then
        docker exec -d -u "$L4_USER" -e DISPLAY="$L4_DISPLAY" -e XAUTHORITY="/home/$L4_USER/.Xauthority" \
            -e DBUS_SESSION_BUS_ADDRESS="unix:path=/home/$L4_USER/.l4-bus" -e HOME="/home/$L4_USER" \
            "$L4_CONTAINER" bash -c "$cmd"
    else
        sudo -u "$L4_USER" tmux new-window -d -t l4 -n "$name" \
            "export DISPLAY=$L4_DISPLAY XAUTHORITY=/home/$L4_USER/.Xauthority; $cmd"
    fi
}

l4_logs() { l4_as cat "/tmp/l4/$1.log" 2>/dev/null || true; }

# The owner's synthetic login password (needed by pkttyagent and gnome-keyring).
l4_login_password() { cat "$L4_STATE/owner-login-password"; }
l4_vault_passphrase() { cat "$L4_STATE/vault-passphrase"; }

l4_make_secrets() {
    umask 077
    [ -s "$L4_STATE/owner-login-password" ] || head -c 18 /dev/urandom | base64 | tr -d '/+=' > "$L4_STATE/owner-login-password"
    [ -s "$L4_STATE/vault-passphrase" ] || printf 'l4-synthetic-%s' "$(head -c 12 /dev/urandom | base64 | tr -d '/+=')" > "$L4_STATE/vault-passphrase"
    [ -s "$L4_STATE/site-password" ] || printf 'Site-%s' "$(head -c 12 /dev/urandom | base64 | tr -d '/+=')" > "$L4_STATE/site-password"
}

# Host mode: the owner account and its automatic VT login.
l4_seat_up() {
    l4_make_secrets
    if ! id "$L4_USER" >/dev/null 2>&1; then
        sudo useradd -m -s /bin/bash "$L4_USER"
    fi
    printf '%s:%s\n' "$L4_USER" "$(l4_login_password)" | sudo chpasswd
    sudo install -d -m 0755 "/etc/systemd/system/getty@tty$L4_VT.service.d"
    printf '[Service]\nExecStart=\nExecStart=-/sbin/agetty --autologin %s --noclear %%I $TERM\n' "$L4_USER" |
        sudo tee "/etc/systemd/system/getty@tty$L4_VT.service.d/l4-autologin.conf" >/dev/null
    # The VT login starts one tmux server; its windows belong to that logind session.
    printf '%s\n' 'if [ "$(tty)" = /dev/tty'"$L4_VT"' ] && [ -z "${TMUX:-}" ]; then exec tmux new-session -A -s l4; fi' |
        sudo -u "$L4_USER" tee "/home/$L4_USER/.bash_profile" >/dev/null
    sudo systemctl daemon-reload
    sudo systemctl restart "getty@tty$L4_VT.service"
    sudo chvt "$L4_VT"
    local i
    for i in $(seq 1 50); do
        sudo -u "$L4_USER" tmux has-session -t l4 2>/dev/null && break
        sleep 0.2
    done
    sudo -u "$L4_USER" tmux has-session -t l4 || l4_die 'the VT login did not start tmux'
    local session
    session=$(loginctl list-sessions --no-legend | awk -v u="$L4_USER" '$3 == u && $5 == "tty'"$L4_VT"'" {print $1}' | head -n 1)
    [ -n "$session" ] || l4_die 'no logind session on the VT'
    loginctl show-session "$session" -p Type -p Class -p Seat -p Active -p Remote -p State | tee "$L4_OUT/logs/logind-session.txt" >&2
}

l4_display_up() {
    l4_as bash -c "rm -f ~/.Xauthority; touch ~/.Xauthority; chmod 600 ~/.Xauthority; xauth -f ~/.Xauthority add $L4_DISPLAY . \$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
    l4_spawn xvfb Xvfb "$L4_DISPLAY" -screen 0 "$L4_GEOMETRY" -nolisten tcp -auth "/home/$L4_USER/.Xauthority"
    local i
    for i in $(seq 1 50); do l4_as xdpyinfo >/dev/null 2>&1 && break; sleep 0.2; done
    l4_as xdpyinfo >/dev/null 2>&1 || l4_die 'Xvfb did not start'
    l4_spawn wm openbox
    sleep 1
}

l4_shot() {
    local name=$1
    l4_as import -window root "/tmp/l4-shot.png"
    l4_as cat /tmp/l4-shot.png > "$L4_OUT/shots/$name.png"
    l4_log "screenshot $L4_OUT/shots/$name.png"
}

l4_x() { l4_as xdotool "$@"; }
l4_type() { l4_as xdotool type --delay 40 -- "$1"; }
l4_key() { l4_as xdotool key --delay 80 "$@"; }
# egui acts on a click only after a frame with the pointer over the widget.
l4_click() { l4_as xdotool mousemove "$1" "$2"; sleep 0.3; l4_as xdotool click 1; sleep "${3:-0.6}"; }
l4_wait_window() {
    local pattern=$1 i
    for i in $(seq 1 "${2:-60}"); do
        l4_as xdotool search --name "$pattern" >/dev/null 2>&1 && return 0
        sleep 1
    done
    return 1
}
l4_focus() { l4_as xdotool search --name "$1" windowactivate --sync 2>/dev/null | head -n 1 || true; }

# The local relying party (runs as the calling account, loopback only).
L4_RP_PORT=${L4_RP_PORT:-4174}
l4_rp_up() {
    l4_rp_down
    local log="$L4_OUT/logs/rp-events.jsonl"
    if [ -n "$L4_CONTAINER" ]; then
        docker exec -d -e L4_LOGIN_PASSWORD="$(cat "$L4_STATE/site-password")" "$L4_CONTAINER" \
            bash -c "exec /opt/l4-node/bin/node /l4/kit/rp/server.mjs --port $L4_RP_PORT --log /l4/out/logs/rp-events.jsonl >>/l4/out/logs/rp.log 2>&1"
    else
        L4_LOGIN_PASSWORD="$(cat "$L4_STATE/site-password")" nohup "$L4_NODE" "$L4_KIT/rp/server.mjs" \
            --port "$L4_RP_PORT" --log "$log" >>"$L4_OUT/logs/rp.log" 2>&1 &
        echo $! > "$L4_STATE/rp.pid"
    fi
    local i
    for i in $(seq 1 50); do l4_rp_status >/dev/null 2>&1 && return 0; sleep 0.2; done
    l4_die 'the relying party did not start'
}
l4_rp_down() {
    if [ -n "$L4_CONTAINER" ]; then docker exec "$L4_CONTAINER" pkill -f rp/server.mjs 2>/dev/null || true
    elif [ -f "$L4_STATE/rp.pid" ]; then kill "$(cat "$L4_STATE/rp.pid")" 2>/dev/null || true; rm -f "$L4_STATE/rp.pid"; fi
}
l4_rp_status() {
    if [ -n "$L4_CONTAINER" ]; then docker exec "$L4_CONTAINER" curl -fsS "http://localhost:$L4_RP_PORT/api/status"
    else curl -fsS "http://localhost:$L4_RP_PORT/api/status"; fi
}
# Wait until the RP recorded an event of KIND; print it.
l4_rp_wait() {
    local kind=$1 since=${2:-0} i
    for i in $(seq 1 "${3:-120}"); do
        local hit
        hit=$(l4_rp_status | jq -c --arg k "$kind" --argjson s "$since" '.events[$s:][] | select(.kind == $k)' | tail -n 1)
        [ -n "$hit" ] && { printf '%s\n' "$hit"; return 0; }
        sleep 1
    done
    return 1
}
l4_rp_count() { l4_rp_status | jq '.events | length'; }
