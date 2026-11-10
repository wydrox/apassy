#!/usr/bin/env bash
# Prepare a DISPOSABLE Ubuntu 24.04+ or Debian 13+ machine (or container) for the
# Linux vault acceptance kit. It installs system packages, Google Chrome stable
# from Google's apt repository and Chromium (Debian: the chromium deb; Ubuntu:
# only the snap exists), and a private Node.js for the local relying party.
# Never run it on a machine that matters: it changes /usr, /etc and apt sources.
set -euo pipefail
fail() { printf 'setup-host.sh: %s\n' "$*" >&2; exit 1; }
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. /etc/os-release
arch=$(dpkg --print-architecture)
case "$arch" in amd64) node_arch=x64 ;; arm64) node_arch=arm64 ;; *) fail "unsupported architecture $arch" ;; esac
SUDO=sudo
[ "$(id -u)" = 0 ] && SUDO=
export DEBIAN_FRONTEND=noninteractive
$SUDO apt-get update -q
# polkitd/pkexec provide pkcheck and pkttyagent (policykit-1 is transitional).
$SUDO apt-get install -y -q --no-install-recommends \
    ca-certificates curl gnupg xz-utils jq python3 sudo procps psmisc tmux file \
    xvfb xauth x11-utils xdotool imagemagick openbox fonts-dejavu-core \
    dbus dbus-x11 dbus-user-session gnome-keyring libsecret-tools polkitd pkexec \
    libegl1 libgl1 libgl1-mesa-dri
if [ ! -f /usr/share/keyrings/l4-google-chrome.gpg ]; then
    curl -fsSL https://dl.google.com/linux/linux_signing_key.pub | $SUDO gpg --dearmor -o /usr/share/keyrings/l4-google-chrome.gpg
fi
echo "deb [arch=$arch signed-by=/usr/share/keyrings/l4-google-chrome.gpg] https://dl.google.com/linux/chrome/deb/ stable main" |
    $SUDO tee /etc/apt/sources.list.d/l4-google-chrome.list >/dev/null
$SUDO apt-get update -q
$SUDO apt-get install -y -q google-chrome-stable
if [ "$ID" = debian ]; then
    $SUDO apt-get install -y -q chromium chromium-sandbox
elif command -v snap >/dev/null && [ -d /run/systemd/system ]; then
    # Ubuntu ships Chromium only as a snap (chromium-browser is a transitional deb).
    $SUDO snap install chromium
fi
# Private Node.js for the relying party, verified against nodejs.org checksums.
node_dir=${L4_NODE_DIR:-/opt/l4-node}
if [ ! -x "$node_dir/bin/node" ]; then
    work=$(mktemp -d)
    base=https://nodejs.org/dist/latest-v22.x
    curl -fsSL "$base/SHASUMS256.txt" -o "$work/SHASUMS256.txt"
    name=$(grep -oE "node-v22\.[0-9]+\.[0-9]+-linux-$node_arch\.tar\.xz" "$work/SHASUMS256.txt" | head -n 1)
    [ -n "$name" ] || fail 'no Node.js 22 build found'
    curl -fsSL "$base/$name" -o "$work/$name"
    (cd "$work" && grep "  $name\$" SHASUMS256.txt | sha256sum -c -)
    $SUDO mkdir -p "$node_dir"
    $SUDO tar -xJf "$work/$name" -C "$node_dir" --strip-components=1
    rm -rf "$work"
fi
if [ ! -d "$here/rp/node_modules/@simplewebauthn/server" ]; then
    (cd "$here/rp" && PATH="$node_dir/bin:$PATH" npm ci --ignore-scripts --no-audit --no-fund)
fi
printf 'setup-host.sh: ready on %s %s (%s)\n' "$ID" "$VERSION_ID" "$arch"
