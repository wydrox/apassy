#!/usr/bin/env bash
# Undo what host mode changed on the devbox: the automatic login on the virtual
# terminal, the synthetic accounts with their processes and homes, the copied Chrome
# of refusals.sh. --packages also removes the Wayland test tools that wayland.sh
# needed (sway grim wtype wlrctl wl-clipboard). The Apassy package, Chrome and the
# distribution packages of setup-host.sh stay.
set -euo pipefail
user=${L4_USER:-l4owner}
headless=${L4_HEADLESS_USER:-l4headless}
vt=${L4_VT:-3}
dir="/etc/systemd/system/getty@tty$vt.service.d"
sudo rm -f "$dir/l4-autologin.conf"
sudo rmdir "$dir" 2>/dev/null || true
sudo systemctl daemon-reload
sudo systemctl restart "getty@tty$vt.service"
for account in "$user" "$headless"; do
    id "$account" >/dev/null 2>&1 || continue
    sudo loginctl terminate-user "$account" 2>/dev/null || true
    sudo pkill -KILL -u "$account" 2>/dev/null || true
    sleep 1
    sudo userdel -r "$account" 2>/dev/null || sudo userdel "$account"
done
sudo rm -rf /opt/l4-fakechrome
if [ "${1:-}" = --packages ]; then
    sudo env DEBIAN_FRONTEND=noninteractive apt-get remove -y -q sway grim wtype wlrctl wl-clipboard >/dev/null
    sudo env DEBIAN_FRONTEND=noninteractive apt-get autoremove -y -q >/dev/null
fi
echo "cleanup-host.sh: removed the automatic login on tty$vt and the accounts $user, $headless"
