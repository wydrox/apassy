#!/usr/bin/env bash
# Create a disposable distribution container on the devbox for the container-mode
# checks (deb/tar install, headless owner, browsers under Xvfb). No logind seat:
# polkit allow_active cannot be tested here.
#
#   container.sh up debian:trixie l4-debian13
#   container.sh down l4-debian13
#
# --privileged lets Chrome's setuid sandbox work under the host's AppArmor
# restriction of unprivileged user namespaces (Ubuntu 24.04 host). The browser is
# still started without any switch.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
action=${1:?usage: container.sh up IMAGE NAME | down NAME}
if [ "$action" = down ]; then docker rm -f "${2:?name}" >/dev/null; exit 0; fi
image=${2:?image} name=${3:?name}
work=${L4_WORK:-$HOME/work/l4}
user=${L4_USER:-l4owner}
out="$work/out-$name"
mkdir -p "$out/shots" "$out/logs" "$work/artifacts"
docker rm -f "$name" >/dev/null 2>&1 || true
docker run -d --name "$name" --privileged --shm-size=1g --memory "${L4_CONTAINER_MEM:-2500m}" \
    -v "$here:/l4/kit:ro" -v "$out:/l4/out" -v "$work/artifacts:/l4/artifacts:ro" \
    -v /opt/l4-node:/opt/l4-node:ro "$image" sleep infinity >/dev/null
docker exec "$name" bash -c 'export DEBIAN_FRONTEND=noninteractive; apt-get update -q >/dev/null && apt-get install -y -q --no-install-recommends sudo ca-certificates curl >/dev/null'
docker exec "$name" bash /l4/kit/setup-host.sh
docker exec "$name" bash -c "id $user >/dev/null 2>&1 || useradd -m -s /bin/bash $user"
docker exec -d -u "$user" -e HOME="/home/$user" "$name" \
    dbus-daemon --session --address="unix:path=/home/$user/.l4-bus" --nofork --nopidfile
docker exec "$name" bash -c '. /etc/os-release; echo "$PRETTY_NAME"; ldd --version | head -1'
