#!/usr/bin/env bash
# Package a Linux vault desktop build and its browser host (ADR 0045).
# Usage: build-vault.sh --binary PATH --host PATH --arch x86_64|aarch64 --out DIR
set -euo pipefail
fail() { printf 'build-vault.sh: %s\n' "$*" >&2; exit 1; }
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$here/../.." && pwd)
binary='' host='' arch='' out=''
while [ "$#" -gt 0 ]; do
    case "$1" in
        --binary) binary=${2:?}; shift 2 ;;
        --host) host=${2:?}; shift 2 ;;
        --arch) arch=${2:?}; shift 2 ;;
        --out) out=${2:?}; shift 2 ;;
        *) fail "unknown argument: $1" ;;
    esac
done
[ -n "$binary" ] && [ -n "$host" ] && [ -n "$arch" ] && [ -n "$out" ] ||
    fail 'usage: build-vault.sh --binary PATH --host PATH --arch x86_64|aarch64 --out DIR'
case "$arch" in
    x86_64) deb_arch=amd64; machine='Advanced Micro Devices X86-64' ;;
    aarch64) deb_arch=arm64; machine=AArch64 ;;
    *) fail "unsupported architecture: $arch" ;;
esac
for tool in readelf dpkg-deb python3 tar sha256sum; do
    command -v "$tool" >/dev/null || fail "missing tool: $tool"
done
version=$(awk -F '"' '/^version = / {print $2; exit}' "$root/crates/apassy-app/Cargo.toml")
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail 'invalid application version'
[ "$("$binary" --version)" = "apassy $version" ] || fail 'application version differs'
for executable in "$binary" "$host"; do
    [ -f "$executable" ] && [ -x "$executable" ] || fail "missing executable: $executable"
    readelf -h "$executable" | grep -Eq "Machine:[[:space:]]+$machine\$" || fail "wrong architecture: $executable"
done
commit=${APASSY_RELEASE_COMMIT:-$(git -C "$root" rev-parse HEAD)}
[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || fail 'invalid source commit'
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$root" log -1 --format=%ct "$commit")}
export SOURCE_DATE_EPOCH
# Unlike the glibc 2.31 node download, desktop packages target the CI build's libc.
glibc_max=$({ readelf --version-info "$binary"; readelf --version-info "$host"; } |
    grep -oE 'GLIBC_[0-9]+(\.[0-9]+)+' | sed 's/^GLIBC_//' | sort -uV | tail -n 1)
[ -n "$glibc_max" ] || fail 'no GLIBC requirements found'
# Refuse an unaccounted linked library rather than emit incomplete dependencies.
for executable in "$binary" "$host"; do
    while IFS= read -r library; do
        case "$library" in
            libc.so.6|libm.so.6|libpthread.so.0|libdl.so.2|librt.so.1|libgcc_s.so.1|libstdc++.so.6|\
                ld-linux-x86-64.so.2|ld-linux-aarch64.so.1|libEGL.so.1|libGL.so.1|libX11.so.6|\
                libxcb.so.1|libxkbcommon.so.0|libwayland-client.so.0|libX11-xcb.so.1|libXrandr.so.2|\
                libXi.so.6|libXcursor.so.1|libxkbcommon-x11.so.0|libwayland-cursor.so.0|libwayland-egl.so.1) ;;
            *) fail "unaccounted shared library $library; add its Debian dependency first" ;;
        esac
    done < <(readelf -d "$executable" | sed -n 's/.*(NEEDED).*\[\(.*\)\]$/\1/p')
done
depends="libc6 (>= $glibc_max), libgcc-s1, libstdc++6, libegl1, libgl1, libx11-6, libxcb1, libx11-xcb1, libxrandr2, libxi6, libxcursor1, libxkbcommon0, libxkbcommon-x11-0, libwayland-client0, libwayland-cursor0, libwayland-egl1"
mkdir -p "$out"
out=$(cd "$out" && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/apassy-vault-package.XXXXXXXX")
trap 'rm -rf "$work"' EXIT
umask 022
name="apassy-vault-$version-linux-$arch"
stage="$work/$name"
install -d -m 0755 "$stage/usr/bin" "$stage/usr/lib/apassy" \
    "$stage/usr/share/applications" "$stage/usr/share/apassy/browser-extension" \
    "$stage/usr/share/doc/apassy-vault" "$stage/usr/share/polkit-1/actions" \
    "$stage/usr/share/apassy/native-messaging-hosts/google-chrome" \
    "$stage/usr/share/apassy/native-messaging-hosts/chromium"
install -m 0755 "$binary" "$stage/usr/bin/apassy"
install -m 0755 "$host" "$stage/usr/lib/apassy/apassy-browser-host"
install -m 0755 "$here/apassy-team" "$stage/usr/bin/apassy-team"
install -m 0644 "$here/apassy.desktop" "$stage/usr/share/applications/cc.wyderka.apassy.desktop"
install -m 0644 "$here/com.wydrox.apassy.policy" "$stage/usr/share/polkit-1/actions/com.wydrox.apassy.policy"
for browser in google-chrome chromium; do
    install -m 0644 "$here/com.wydrox.apassy.json" \
        "$stage/usr/share/apassy/native-messaging-hosts/$browser/com.wydrox.apassy.json"
done
# Ship the extension source exactly as reviewed, excluding no runtime assets.
cp -R "$root/extension/." "$stage/usr/share/apassy/browser-extension/"
chmod -R u=rwX,go=rX "$stage/usr/share/apassy/browser-extension"
install -m 0644 "$root/LICENSE" "$stage/usr/share/doc/apassy-vault/LICENSE"
install -m 0644 "$here/NOTICE" "$here/VAULT.md" "$stage/usr/share/doc/apassy-vault/"
cp -R "$root/licenses" "$stage/usr/share/doc/apassy-vault/licenses"
install -m 0755 "$here/install-vault.sh" "$stage/install-vault.sh"
[ -z "$(find "$stage" ! -type d ! -type f -print -quit)" ] || fail 'package contains links or special files'
sh "$here/tarball.sh" "$stage" "$out/$name.tar.gz"
deb_root="$work/deb"
mkdir -p "$deb_root/DEBIAN"
cp -R "$stage/usr" "$deb_root/"
cat > "$deb_root/DEBIAN/control" <<CONTROL
Package: apassy-vault
Version: $version
Architecture: $deb_arch
Maintainer: Apassy authors <apassy@wyderka.cc>
Section: utils
Priority: optional
Depends: $depends
Suggests: libsecret-tools, policykit-1
Conflicts: apassy
Replaces: apassy
Description: Apassy encrypted vault, desktop and browser passkeys
 Local SQLCipher vault, owner commands and browser native messaging host.
 Linux software protection is not equivalent to macOS signing or Secure Enclave.
CONTROL
find "$deb_root" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
deb="apassy-vault_${version}_${deb_arch}.deb"
dpkg-deb --root-owner-group -Zxz --build "$deb_root" "$out/$deb" >/dev/null
dpkg-deb --info "$out/$deb" > "$out/$deb.info.txt"
dpkg-deb --contents "$out/$deb" > "$out/$deb.contents.txt"
(cd "$out" && sha256sum "$name.tar.gz" "$deb") > "$out/SHA256SUMS-vault-$arch"
python3 -I - "$out" "$arch" "$version" "$commit" "$glibc_max" "$depends" "$name.tar.gz" "$deb" <<'PY'
import hashlib, json, pathlib, sys
out, arch, version, commit, glibc, depends, *names = sys.argv[1:]
out = pathlib.Path(out)
record = {"version": version, "commit": commit, "component": "linux-vault",
          "platform": f"linux-{arch}", "glibc_max": glibc, "depends": depends,
          "files": [{"filename": name, "sha256": hashlib.sha256((out/name).read_bytes()).hexdigest(),
                     "size": (out/name).stat().st_size} for name in names]}
(out/f"release-vault-linux-{arch}.json").write_text(json.dumps(record, indent=2) + "\n")
PY
printf '%s\n' "$out/$name.tar.gz" "$out/$deb" "$out/SHA256SUMS-vault-$arch"
