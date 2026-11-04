#!/bin/sh
# Pack one staged directory as a reproducible .tar.gz (plan S2-S3, unit L3).
#
# Usage: packaging/linux/tarball.sh STAGE_DIR OUTPUT.tar.gz
#
# The archive holds the directory STAGE_DIR under its own name. Owner and group are 0,
# entries are sorted, every time is SOURCE_DATE_EPOCH, and gzip writes no name or time:
# the same input gives the same bytes. GNU tar is required (Debian, Ubuntu).
set -eu

fail() {
    printf 'tarball.sh: %s\n' "$*" >&2
    exit 1
}

[ "$#" -eq 2 ] || fail 'usage: tarball.sh STAGE_DIR OUTPUT.tar.gz'
stage=$1
output=$2
[ -d "$stage" ] || fail "not a directory: $stage"
case "$output" in
    *.tar.gz) ;;
    *) fail "the output must end in .tar.gz: $output" ;;
esac
[ -n "${SOURCE_DATE_EPOCH:-}" ] || fail 'set SOURCE_DATE_EPOCH'
tar --version 2>/dev/null | head -n 1 | grep -q 'GNU tar' || fail 'GNU tar is required'

parent=$(dirname -- "$stage")
name=$(basename -- "$stage")
partial="$output.partial"
rm -f "$partial"
tar --sort=name --format=gnu --owner=0 --group=0 --numeric-owner \
    --mtime="@$SOURCE_DATE_EPOCH" -C "$parent" -cf - "$name" | gzip -n -9 > "$partial"
mv -f "$partial" "$output"
