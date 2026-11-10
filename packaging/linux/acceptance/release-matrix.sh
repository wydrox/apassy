#!/usr/bin/env bash
# Release-package matrix (unit L6): one release build of the vault package in minimal
# Debian 12, Debian 13, Ubuntu 22.04 and Ubuntu 24.04 containers on a devbox.
#
#   release-matrix.sh DIST SRC
#
# DIST is the CI artifact apassy-vault-linux-<arch> of the commit under test (deb, tar,
# SHA256SUMS-vault-<arch>); SRC is a checkout of the same commit (install.sh and this
# kit). For each distribution, in fresh containers: the relay install.sh from a file://
# origin installs the deb with apt (no Recommends) and, separately, the tarball;
# `ldd -r` of both executables; the window on a shared Xvfb display (container
# l6-xvfb), with the libraries it loads (LD_DEBUG) and their packages; the headless
# owner checks of headless-owner.sh. Debian 11 and Ubuntu 20.04 must be refused.
# x86_64 only as written (amd64 file names). Output: ~/work/l6/proof/matrix.txt.
set -uo pipefail
dist=$(cd "$1" && pwd) src=$(cd "$2" && pwd)
out=~/work/l6/proof; mkdir -p "$out"
report="$out/matrix.txt"; : > "$report"
res() { printf '%-14s %-34s %s\n' "$1" "$2" "$3" | tee -a "$report"; }
(cd "$dist" && sha256sum -c SHA256SUMS-vault-x86_64) || exit 1
deb=$(cd "$dist" && ls apassy-vault_*_amd64.deb); tar=$(cd "$dist" && ls apassy-vault-*-linux-x86_64.tar.gz)
version=${deb#apassy-vault_}; version=${version%_amd64.deb}
# A file:// download origin like /dl/: the deb and tar of this build and their checksums.
site="$out/site"; rm -rf "$site"; mkdir -p "$site/dl"
cp "$dist/$deb" "$dist/$tar" "$site/dl/"; cp "$dist/SHA256SUMS-vault-x86_64" "$site/dl/SHA256SUMS"
cp "$src/crates/apassy-relay/deploy/worker/public/install.sh" "$site/install.sh"

if ! docker ps --format '{{.Names}}' | grep -qx l6-xvfb; then
  docker rm -f l6-xvfb >/dev/null 2>&1
  docker run -d --name l6-xvfb --memory 400m -v l6-x11:/tmp/.X11-unix debian:12-slim sh -c \
    'apt-get update -q >/dev/null && apt-get install -y -q --no-install-recommends xvfb x11-utils x11-apps >/dev/null && exec Xvfb :99 -ac -nolisten tcp -screen 0 1280x800x24' >/dev/null
  for _ in $(seq 90); do docker exec l6-xvfb test -S /tmp/.X11-unix/X99 2>/dev/null && break; sleep 2; done
fi

window() { # name tag -> starts the window as user l6win on :99, checks it, records libraries
  local name=$1 tag=$2 shown=''
  docker exec "$name" sh -c 'id l6win >/dev/null 2>&1 || useradd -m l6win'
  docker exec -d -u l6win -e DISPLAY=:99 -e HOME=/home/l6win -e LD_DEBUG=libs "$name" \
    sh -c 'exec /usr/bin/apassy >/tmp/window.log 2>&1'
  for _ in $(seq 60); do
    shown=$(docker exec l6-xvfb xwininfo -root -tree -display :99 | grep -F '"Apassy"' || true)
    [ -n "$shown" ] && break; sleep 0.5
  done
  sleep 4
  docker exec l6-xvfb sh -c 'xwd -root -display :99 -silent' > "$out/$tag-window.xwd" 2>/dev/null
  if [ -n "$shown" ] && docker exec "$name" sh -c 'grep -qx apassy /proc/[0-9]*/comm'; then
    res "$tag" "window under Xvfb (X11)" "PASS $(echo "$shown" | awk '{print $2, $NF}')"
  else
    res "$tag" "window under Xvfb (X11)" "FAIL"; docker exec "$name" sh -c 'grep -v "^ *[0-9]*:" /tmp/window.log | tail -20'
  fi
  docker exec "$name" sh -c 'pkill -x apassy 2>/dev/null || for p in /proc/[0-9]*; do [ "$(cat $p/comm 2>/dev/null)" = apassy ] && kill ${p#/proc/}; done; sleep 2; true'
  docker exec "$name" sh -c "sed -n 's/.*calling init: //p' /tmp/window.log | sort -u" > "$out/$tag-loaded.txt"
  docker exec -i "$name" sh -c 'while read -r f; do p=$(dpkg -S "$(readlink -f "$f")" 2>/dev/null | head -n1 | cut -d: -f1); echo "${p:-?} $f"; done' < "$out/$tag-loaded.txt" > "$out/$tag-loaded-packages.txt"
}

for pair in debian:12-slim:d12 debian:13-slim:d13 ubuntu:22.04:u2204 ubuntu:24.04:u2404; do
  image=${pair%:*} tag=${pair##*:}
  name=l6-p-$tag
  docker rm -f "$name" >/dev/null 2>&1
  docker run -d --name "$name" --memory 1200m -v l6-x11:/tmp/.X11-unix -v "$site:/site:ro" "$image" sleep infinity >/dev/null
  docker exec "$name" sh -c '. /etc/os-release; echo "$PRETTY_NAME | $(ldd --version | head -n1)"' > "$out/$tag-os.txt"
  res "$tag" "system" "$(cat "$out/$tag-os.txt")"
  # The download tool for install.sh; minimal images have neither curl nor wget.
  docker exec -e DEBIAN_FRONTEND=noninteractive "$name" sh -c 'apt-get update -q >/dev/null && apt-get install -y -q --no-install-recommends curl ca-certificates >/dev/null'
  docker exec "$name" sh -c 'dpkg-query -W -f "\${Package}\n" | sort' > "$out/$tag-before.txt"
  if docker exec -e DEBIAN_FRONTEND=noninteractive "$name" sh -c \
      'echo "APT::Install-Recommends \"false\";" > /etc/apt/apt.conf.d/99l6-no-recommends; APASSY_COMPONENT=vault APASSY_INSTALL_AS_ROOT=1 APASSY_RELAY_URL=file:///site sh /site/install.sh' > "$out/$tag-install.txt" 2>&1; then
    res "$tag" "install.sh vault (deb, apt)" "PASS $(tail -n1 "$out/$tag-install.txt")"
  else
    res "$tag" "install.sh vault (deb, apt)" "FAIL"; tail -n 8 "$out/$tag-install.txt"; continue
  fi
  docker exec "$name" sh -c 'dpkg-query -W -f "\${Package}\n" | sort' > "$out/$tag-after.txt"
  LC_ALL=C comm -13 "$out/$tag-before.txt" "$out/$tag-after.txt" > "$out/$tag-added-packages.txt"
  res "$tag" "packages apt added" "$(grep -c . "$out/$tag-added-packages.txt")"
  if docker exec "$name" sh -c 'for e in /usr/bin/apassy /usr/lib/apassy/apassy-browser-host; do ldd -r "$e" 2>&1 | grep "not found" && exit 1; done; exit 0'; then
    res "$tag" "ldd -r both executables" "PASS"
  else
    res "$tag" "ldd -r both executables" "FAIL"
  fi
  window "$name" "$tag"
  # Headless owner commands (the acceptance kit, container mode).
  if L4_CONTAINER=$name L4_STATE=~/work/l6/state L4_OUT=$out/headless-$tag L4_HEADLESS_USER=l6headless \
      bash "$src/packaging/linux/acceptance/headless-owner.sh" > "$out/$tag-headless.log" 2>&1; then :; fi
  pass=$(grep -c '^PASS' "$out/headless-$tag/headless-owner.txt" 2>/dev/null); fail=$(grep -c '^FAIL' "$out/headless-$tag/headless-owner.txt" 2>/dev/null)
  res "$tag" "headless owner (acceptance kit)" "PASS ${pass:-0} FAIL ${fail:-0}"
  docker rm -f "$name" >/dev/null
  # The tarball through install.sh, in a fresh container with the deb's Depends installed first.
  name=l6-t-$tag
  docker rm -f "$name" >/dev/null 2>&1
  docker run -d --name "$name" --memory 1200m -v l6-x11:/tmp/.X11-unix -v "$site:/site:ro" "$image" sleep infinity >/dev/null
  depends=$(dpkg-deb --field "$dist/$deb" Depends | tr ',' '\n' | sed 's/(.*)//; s/ //g' | grep -v '^libc6$' | tr '\n' ' ')
  if docker exec -e DEBIAN_FRONTEND=noninteractive "$name" sh -c "apt-get update -q >/dev/null && apt-get install -y -q --no-install-recommends curl ca-certificates $depends >/dev/null && APASSY_COMPONENT=vault APASSY_VAULT_FORMAT=tar APASSY_INSTALL_AS_ROOT=1 APASSY_RELAY_URL=file:///site sh /site/install.sh" > "$out/$tag-tar-install.txt" 2>&1; then
    res "$tag" "install.sh vault (tar)" "PASS $(tail -n1 "$out/$tag-tar-install.txt")"
    window "$name" "$tag-tar"
  else
    res "$tag" "install.sh vault (tar)" "FAIL"; tail -n 8 "$out/$tag-tar-install.txt"
  fi
  docker rm -f "$name" >/dev/null
done

# Refusals: older distributions (glibc 2.31 would load, but they are not tested).
for pair in debian:11-slim:d11 ubuntu:20.04:u2004; do
  image=${pair%:*} tag=${pair##*:}
  msg=$(docker run --rm -v "$site:/site:ro" "$image" sh -c 'APASSY_COMPONENT=vault APASSY_INSTALL_AS_ROOT=1 APASSY_RELAY_URL=file:///site sh /site/install.sh' 2>&1 | tail -n1)
  case "$msg" in *"supports Debian 12 or later"*) res "$tag" "install.sh refuses" "PASS: $msg" ;; *) res "$tag" "install.sh refuses" "FAIL: $msg" ;; esac
done
echo "done: $report"
