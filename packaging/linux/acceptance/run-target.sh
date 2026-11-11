#!/usr/bin/env bash
# One command per acceptance target. Run on the devbox, from this kit directory,
# after setup-host.sh. DIST is a directory with the deb, tar and SHA256SUMS of one
# build (a CI artifact or build-on-devbox.sh output).
#
#   run-target.sh ubuntu DIST deb|tar     # this host (Ubuntu 24.04, seat session)
#   run-target.sh debian13 DIST deb|tar   # disposable debian:trixie container
#   run-target.sh debian12 DIST deb|tar   # disposable debian:bookworm container
#   run-target.sh ubuntu2204 DIST deb|tar # disposable ubuntu:22.04 container
#
# It installs the package as the documents say, runs the scripted checks and
# prepares the desktop session. The browser ceremonies follow in README.md, step
# "Browser", with screenshots to check after each step.
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
target=${1:?usage: run-target.sh ubuntu|debian13|debian12|ubuntu2204 DIST deb|tar}
dist=$(cd "${2:?DIST}" && pwd)
how=${3:-deb}
case "$(uname -m)" in x86_64) arch=x86_64 deb_arch=amd64 ;; aarch64) arch=aarch64 deb_arch=arm64 ;; esac
version=$(find "$dist" -maxdepth 1 -name "apassy-vault_*_${deb_arch}.deb" -printf '%f\n' | sed -E 's/^apassy-vault_([^_]+)_.*/\1/')
[ -n "$version" ] || { echo "no ${deb_arch} deb in $dist" >&2; exit 2; }
echo "target=$target arch=$arch version=$version dist=$dist how=$how"
(cd "$dist" && sha256sum -c "SHA256SUMS-vault-$arch")

install_cmds() { # the documented install, run by root inside the target
    if [ "$how" = deb ]; then
        echo "apt-get install -y ./apassy-vault_${version}_${deb_arch}.deb"
    else
        echo "d=\$(mktemp -d) && tar -xzf apassy-vault-$version-linux-$arch.tar.gz -C \$d && sh \$d/apassy-vault-$version-linux-$arch/install-vault.sh"
    fi
}

if [ "$target" = ubuntu ]; then
    export L4_CONTAINER=''
    (cd "$dist" && sudo bash -c "$(install_cmds)")
    /usr/bin/apassy --version
    . "$here/lib/l4.sh"
    l4_seat_up
    bash "$here/headless-owner.sh"
    bash "$here/keyring-polkit.sh" keyring
    l4_display_up
    l4_rp_up
elif image=$(case "$target" in debian13) echo debian:trixie ;; debian12) echo debian:bookworm ;;
        ubuntu2204) echo ubuntu:22.04 ;; *) exit 1 ;; esac); then
    name=${L4_RUN:-l4}-$target
    bash "$here/container.sh" up "$image" "$name"
    docker cp "$dist/." "$name:/tmp/l4-dist/"
    docker exec -w /tmp/l4-dist "$name" bash -c "$(install_cmds) && apassy --version"
    export L4_CONTAINER=$name L4_OUT=${L4_WORK:-$HOME/work/l4}/out-$name
    . "$here/lib/l4.sh"
    l4_make_secrets
    bash "$here/headless-owner.sh"
    l4_display_up
    l4_rp_up
else
    echo "unknown target $target" >&2; exit 2
fi
. "$here/lib/flows.sh"
flow_apassy_first_run "$target"
l4_as bash -c 'cd ~ && apassy setup browser --browser chrome'
# Ubuntu's Chromium is a snap: setup must refuse it with the reason, write nothing
# and exit 1. Debian's Chromium deb is supported.
l4_as bash -c 'cd ~ && apassy setup browser --browser chromium; echo "exit=$?"' 2>&1 | tee "$L4_OUT/logs/setup-chromium.txt"
l4_as bash -c 'cd ~ && apassy --json setup browser' 2>&1 | tee "$L4_OUT/logs/setup-browser.json" || true
[ -n "${L4_CONTAINER:-}" ] || bash "$here/refusals.sh" api
echo "Scripted checks done. Continue with README.md, step Browser. Screenshots: $L4_OUT/shots"
