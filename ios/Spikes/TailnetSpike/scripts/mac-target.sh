#!/bin/bash
# A throwaway target on this Mac for the spike's probe (plan s8 unit T0). It listens only on the
# Mac's tailnet IPv4 address, answers each GET with a short text, and logs the caller's address.
# With TLS (the default) it makes a fresh self-signed certificate in a temporary directory and
# prints its pin. Ctrl-C stops it; the directory is removed. It changes no Tailscale setting.
#
#   ios/Spikes/TailnetSpike/scripts/mac-target.sh [port]           # TLS, default port 48700
#   ios/Spikes/TailnetSpike/scripts/mac-target.sh --plain [port]   # plain HTTP
#
# macOS may ask whether python3 may accept incoming connections: allow it for the test.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
mode=tls
if [ "${1:-}" = --plain ]; then
    mode=plain
    shift
fi
port=${1:-48700}

ts=""
for candidate in /Applications/Tailscale.app/Contents/MacOS/Tailscale /opt/homebrew/bin/tailscale /usr/local/bin/tailscale; do
    if [ -x "$candidate" ]; then
        ts=$candidate
        break
    fi
done
[ -n "$ts" ] || {
    echo "mac-target: no tailscale command found" >&2
    exit 1
}
ip=$("$ts" ip -4 2>/dev/null | head -n 1)
[ -n "$ip" ] || {
    echo "mac-target: Tailscale has no IPv4 address on this Mac (is it connected?)" >&2
    exit 1
}

dir=$(mktemp -d "${TMPDIR:-/tmp}/apassy-spike-target.XXXXXX")
trap 'rm -rf "$dir"' EXIT

if [ "$mode" = tls ]; then
    /usr/bin/openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=apassy-tailnet-spike" \
        -keyout "$dir/key.pem" -out "$dir/cert.pem" >/dev/null 2>&1
    pin=$(/usr/bin/openssl x509 -in "$dir/cert.pem" -outform DER | /usr/bin/openssl dgst -sha256 -binary |
        base64 | tr '+/' '-_' | tr -d '=')
    echo "In the spike: Mac $ip   Port $port   TLS on   Pin $pin"
    python3 -I "$here/mac-target.py" "$ip" "$port" "$dir/cert.pem" "$dir/key.pem"
else
    echo "In the spike: Mac $ip   Port $port   TLS off"
    python3 -I "$here/mac-target.py" "$ip" "$port"
fi
