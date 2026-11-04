#!/usr/bin/env bash
# Build the Linux node packages from one built `apassy-app` binary (plan S2-S3, unit L3).
#
# Usage:
#   packaging/linux/build.sh --binary PATH --arch x86_64|aarch64 --out DIR [--max-glibc 2.31]
#
# The binary is `apassy-app` built with `--no-default-features --features node`, already
# stripped. The version is the relay crate's (crates/apassy-relay/Cargo.toml): the node
# commands live in the relay crate, so `apassy --version` prints it. The script writes
# into DIR:
#
#   apassy-<version>-linux-<arch>.tar.gz   apassy, the apassy-team shim, the unit template,
#                                          LICENSE, NOTICE, README.md, licenses/
#   apassy_<version>_<deb arch>.deb        /usr/bin/apassy, /usr/bin/apassy-team,
#                                          /usr/lib/systemd/user/apassy-node.service,
#                                          /usr/share/doc/apassy/
#   SHA256SUMS-node-<arch>                 the SHA-256 of both
#   release-linux-<arch>.json              version, commit, glibc, Depends, files
#   apassy_<version>_<deb arch>.deb.info.txt and .contents.txt   dpkg-deb --info and --contents
#
# It refuses a binary of another version or machine, a glibc newer than --max-glibc, a
# shared library other than glibc's and libgcc_s, and a package whose contents differ
# from what it staged. It needs bash, GNU tar, gzip, dpkg-deb, readelf, python3.
set -euo pipefail

die() {
    printf 'build.sh: %s\n' "$*" >&2
    exit 1
}

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$here/../.." && pwd)

binary=
arch=
out=
max_glibc=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --binary) binary=${2:?--binary needs a path}; shift 2 ;;
        --arch) arch=${2:?--arch needs a value}; shift 2 ;;
        --out) out=${2:?--out needs a directory}; shift 2 ;;
        --max-glibc) max_glibc=${2:?--max-glibc needs a version}; shift 2 ;;
        *) die "unknown argument: $1" ;;
    esac
done
if [ -z "$binary" ] || [ -z "$arch" ] || [ -z "$out" ]; then
    die 'usage: build.sh --binary PATH --arch x86_64|aarch64 --out DIR [--max-glibc 2.31]'
fi
[ -f "$binary" ] || die "no binary at $binary"
case "$arch" in
    x86_64) deb_arch=amd64; machine='Advanced Micro Devices X86-64' ;;
    aarch64) deb_arch=arm64; machine='AArch64' ;;
    *) die "the architecture is x86_64 or aarch64, not $arch" ;;
esac
for tool in tar gzip dpkg-deb readelf python3 sha256sum; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is missing"
done

version=$(awk -F '"' '/^version = / {print $2; exit}' "$root/crates/apassy-relay/Cargo.toml")
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "the relay crate version is not x.y.z: $version"
commit=${APASSY_RELEASE_COMMIT:-$(git -C "$root" rev-parse HEAD)}
[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || die "the commit is not a full SHA: $commit"
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$root" log -1 --format=%ct "$commit")}
[[ "$SOURCE_DATE_EPOCH" =~ ^[0-9]+$ ]] || die 'SOURCE_DATE_EPOCH is not a number'
export SOURCE_DATE_EPOCH

# 1. The binary: the version, the machine, glibc, and the shared libraries.
reported=$("$binary" --version)
[ "$reported" = "apassy $version" ] || die "the binary says '$reported', not 'apassy $version'"
readelf -h "$binary" | grep -Eq "Machine:[[:space:]]+$machine\$" ||
    die "the binary is not for $arch"
glibc_max=$(readelf --version-info "$binary" | grep -oE 'GLIBC_[0-9]+(\.[0-9]+)+' |
    sed 's/^GLIBC_//' | sort -uV | tail -n 1)
[ -n "$glibc_max" ] || die 'the binary has no GLIBC version requirement'
if [ -n "$max_glibc" ]; then
    newest=$(printf '%s\n%s\n' "$glibc_max" "$max_glibc" | sort -V | tail -n 1)
    [ "$newest" = "$max_glibc" ] || die "the binary needs glibc $glibc_max, newer than $max_glibc"
fi
depends="libc6 (>= $glibc_max)"
gcc=0
while IFS= read -r library; do
    case "$library" in
        libc.so.6 | libm.so.6 | libpthread.so.0 | libdl.so.2 | librt.so.1 | \
            ld-linux-x86-64.so.2 | ld-linux-aarch64.so.1) ;;
        libgcc_s.so.1) gcc=1 ;;
        '') ;;
        *) die "the binary needs $library: add its package to Depends first" ;;
    esac
done < <(readelf -d "$binary" | sed -n 's/.*(NEEDED).*\[\(.*\)\]$/\1/p')
if [ "$gcc" = 1 ]; then
    depends="$depends, libgcc-s1"
fi

mkdir -p "$out"
out=$(cd "$out" && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/apassy-package.XXXXXXXX")
trap 'rm -rf "$work"' EXIT
umask 022

docs() {
    # The documents of both packages, into $1.
    install -m 0644 "$root/LICENSE" "$1/LICENSE"
    install -m 0644 "$here/NOTICE" "$1/NOTICE"
    install -m 0644 "$here/README.md" "$1/README.md"
    cp -R "$root/licenses" "$1/licenses"
    chmod -R u=rwX,go=rX "$1/licenses"
}

# 2. The tarball.
name="apassy-$version-linux-$arch"
stage="$work/$name"
mkdir -p "$stage"
install -m 0755 "$binary" "$stage/apassy"
install -m 0755 "$here/apassy-team" "$stage/apassy-team"
install -m 0644 "$here/apassy-node.service" "$stage/apassy-node.service"
docs "$stage"
tarball="$name.tar.gz"
sh "$here/tarball.sh" "$stage" "$out/$tarball"
(cd "$work" && find "$name" -mindepth 1 | LC_ALL=C sort) > "$work/tar-expected.txt"
tar -tzf "$out/$tarball" | sed 's:/$::' | grep -v "^$name\$" | LC_ALL=C sort > "$work/tar-actual.txt"
diff -u "$work/tar-expected.txt" "$work/tar-actual.txt" || die "$tarball holds other files than the stage"

# 3. The .deb.
deb_root="$work/deb"
install -d -m 0755 "$deb_root/DEBIAN" "$deb_root/usr/bin" "$deb_root/usr/lib/systemd/user" \
    "$deb_root/usr/share/doc/apassy"
install -m 0755 "$binary" "$deb_root/usr/bin/apassy"
install -m 0755 "$here/apassy-team" "$deb_root/usr/bin/apassy-team"
install -m 0644 "$here/apassy-node.service" "$deb_root/usr/lib/systemd/user/apassy-node.service"
doc="$deb_root/usr/share/doc/apassy"
docs "$doc"
rm "$doc/LICENSE"
{
    printf '%s\n' \
        'Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/' \
        'Upstream-Name: apassy' \
        'Source: https://github.com/wydrox/apassy' \
        '' \
        'Files: *' \
        'Copyright: 2026 the Apassy authors' \
        'License: Apache-2.0' \
        'Comment: The third-party licenses and notices are in' \
        ' /usr/share/doc/apassy/licenses/ and /usr/share/doc/apassy/NOTICE.' \
        '' \
        'License: Apache-2.0'
    sed -e 's/^[[:space:]]*$/./' -e 's/^/ /' "$root/LICENSE"
} > "$doc/copyright"
chmod 0644 "$doc/copyright"
installed_size=$(du -sk --apparent-size "$deb_root/usr" | cut -f 1)
sed -e "s|@VERSION@|$version|" -e "s|@ARCH@|$deb_arch|" \
    -e "s|@INSTALLED_SIZE@|$installed_size|" -e "s|@DEPENDS@|$depends|" \
    "$here/deb/control.in" > "$deb_root/DEBIAN/control"
chmod 0644 "$deb_root/DEBIAN/control"
if grep -q '@[A-Z_]*@' "$deb_root/DEBIAN/control"; then
    die 'a placeholder is left in DEBIAN/control'
fi
install -m 0755 "$here/deb/postinst" "$deb_root/DEBIAN/postinst"
find "$deb_root" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
deb="apassy_${version}_${deb_arch}.deb"
dpkg-deb --root-owner-group -Zxz --build "$deb_root" "$out/$deb" >/dev/null

# 4. What dpkg-deb says about it.
dpkg-deb --info "$out/$deb" > "$out/$deb.info.txt"
dpkg-deb --contents "$out/$deb" > "$out/$deb.contents.txt"
for field in Package:apassy "Version:$version" "Architecture:$deb_arch" "Depends:$depends"; do
    key=${field%%:*}
    want=${field#*:}
    got=$(dpkg-deb --field "$out/$deb" "$key")
    [ "$got" = "$want" ] || die "$deb has $key '$got', not '$want'"
done
(cd "$deb_root" && find . -mindepth 1 -path ./DEBIAN -prune -o -type f -print | LC_ALL=C sort) \
    > "$work/deb-expected.txt"
awk '$1 ~ /^-/ {print $NF}' "$out/$deb.contents.txt" | LC_ALL=C sort > "$work/deb-actual.txt"
diff -u "$work/deb-expected.txt" "$work/deb-actual.txt" || die "$deb holds other files than the stage"
for entry in './usr/bin/apassy' './usr/bin/apassy-team'; do
    awk -v path="$entry" '$NF == path && $1 == "-rwxr-xr-x" && $2 == "root/root" {found = 1}
        END {exit found ? 0 : 1}' "$out/$deb.contents.txt" || die "$entry is not root's and 0755"
done

# 5. Checksums and the record.
(cd "$out" && sha256sum "$tarball" "$deb") > "$out/SHA256SUMS-node-$arch"
python3 -I - "$out" "$arch" "$version" "$commit" "$glibc_max" "$depends" "$tarball" "$deb" <<'PY'
import hashlib
import json
import pathlib
import sys

out, arch, version, commit, glibc, depends, *names = sys.argv[1:]
out = pathlib.Path(out)
files = []
for name in names:
    blob = (out / name).read_bytes()
    files.append({"filename": name, "sha256": hashlib.sha256(blob).hexdigest(), "size": len(blob)})
record = {
    "version": version, "commit": commit, "platform": f"linux-{arch}",
    "glibc_max": glibc, "depends": depends, "files": files,
}
(out / f"release-linux-{arch}.json").write_text(json.dumps(record, indent=2) + "\n")
PY
printf '%s\n' "$out/$tarball" "$out/$deb" "$out/SHA256SUMS-node-$arch" "$out/release-linux-$arch.json"
