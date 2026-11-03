#!/usr/bin/env bash
# Builds libtailscale.a from go/ exactly as build.rs does, into ARCHIVE_DIR, for
# APASSY_LIBTAILSCALE_DIR. Writes REPORT_DIR/archive.json (Go version, commit, tags,
# size, SHA-256, build time, link flags) and REPORT_DIR/go-modules.txt (the module
# list, for the license inventory). Needs the pinned Go first on PATH.
#
#   crates/apassy-tailnet/scripts/build-archive.sh "$RUNNER_TEMP/libtailscale" spike-out/archive
set -euo pipefail

archive_dir="${1:?usage: build-archive.sh ARCHIVE_DIR REPORT_DIR}"
report_dir="${2:?usage: build-archive.sh ARCHIVE_DIR REPORT_DIR}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
crate="$(cd "$here/.." && pwd)"
pin() { sed -n "s/^$1=//p" "$crate/pins.env" | head -n 1; }

version="$(pin GO_VERSION)"
got="$(GOTOOLCHAIN=local go env GOVERSION)"
[ "$got" = "go$version" ] || { echo "build-archive.sh: go is $got, pinned go$version" >&2; exit 1; }
mkdir -p "$archive_dir" "$report_dir"
archive_dir="$(cd "$archive_dir" && pwd)"
report_dir="$(cd "$report_dir" && pwd)"

export CGO_ENABLED=1 GOTOOLCHAIN=local GOFLAGS=-mod=readonly
if [ "$(uname -s)" = Darwin ]; then
  target="${MACOSX_DEPLOYMENT_TARGET:-$(pin MACOS_DEPLOYMENT_TARGET)}"
  export MACOSX_DEPLOYMENT_TARGET="$target"
  export CGO_CFLAGS="${CGO_CFLAGS:+$CGO_CFLAGS }-mmacosx-version-min=$target"
  export CGO_LDFLAGS="${CGO_LDFLAGS:+$CGO_LDFLAGS }-mmacosx-version-min=$target"
fi
tags="${APASSY_TAILNET_GO_TAGS:-}"
tag_args=()
if [ -n "${tags// /}" ]; then tag_args=(-tags "$tags"); fi

cd "$crate/go"
start="$(date +%s)"
go build -trimpath -buildvcs=false -buildmode=c-archive ${tag_args[@]+"${tag_args[@]}"} -o "$archive_dir/libtailscale.a" .
seconds="$(( $(date +%s) - start ))"
go list -deps ${tag_args[@]+"${tag_args[@]}"} -f '{{join .CgoLDFLAGS "\n"}}' . | sed '/^[[:space:]]*$/d' | sort -u > "$archive_dir/libtailscale.ldflags"
go list -m all > "$report_dir/go-modules.txt" || echo "build-archive.sh: go list -m all failed; no module list" >&2
cp "$archive_dir/libtailscale.ldflags" "$report_dir/libtailscale.ldflags"

python3 - "$archive_dir" "$report_dir" "$got" "$(pin LIBTAILSCALE_COMMIT)" "$(pin TAILSCALE_VERSION)" "$tags" "$seconds" <<'PY'
import hashlib, json, sys
from pathlib import Path
archive_dir, report_dir, go, commit, tailscale, tags, seconds = sys.argv[1:]
archive = Path(archive_dir, "libtailscale.a")
data = archive.read_bytes()
flags = [line for line in Path(archive_dir, "libtailscale.ldflags").read_text().splitlines() if line.strip()]
modules = [line for line in Path(report_dir, "go-modules.txt").read_text().splitlines()[1:] if line.strip()]
report = {
    "go": go, "libtailscale_commit": commit, "tailscale_version": tailscale, "tags": tags,
    "archive_bytes": len(data), "archive_sha256": hashlib.sha256(data).hexdigest(),
    "build_seconds": int(seconds), "cgo_ldflags": flags, "modules_in_graph": len(modules),
}
Path(report_dir, "archive.json").write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps(report))
PY
