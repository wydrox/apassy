#!/usr/bin/env bash
# The static numbers of the spike (docs/design/spike-tsnet.md, "Sizes" and "Link"):
# sizes of the archive and of the binaries before and after strip, the libraries
# that the binary links, the macOS minimum version, and on Linux the newest glibc
# symbol version (at most 2.31, as the Linux CLI; a newer one fails the job).
# Writes OUT_DIR/build.json and prints a Markdown table for the job summary.
#
#   measure-build.sh SPIKE BASELINE ARCHIVE_DIR OUT_DIR
set -euo pipefail

spike="${1:?usage: measure-build.sh SPIKE BASELINE ARCHIVE_DIR OUT_DIR}"
baseline="${2:?}"
archive_dir="${3:?}"
out="${4:?}"
mkdir -p "$out"

cp "$spike" "$out/spike.stripped"
cp "$baseline" "$out/baseline.stripped"
case "$(uname -s)" in
  Darwin)
    strip -x "$out/spike.stripped" "$out/baseline.stripped"
    otool -L "$spike" > "$out/linked-libraries.txt"
    otool -l "$spike" | awk '/LC_BUILD_VERSION/{found=1} found && /minos/{print $2; exit}' > "$out/minos.txt"
    lipo -archs "$spike" > "$out/archs.txt"
    : > "$out/glibc-symbols.txt"
    ;;
  Linux)
    strip "$out/spike.stripped" "$out/baseline.stripped"
    ldd "$spike" > "$out/linked-libraries.txt" || true
    readelf --version-info "$spike" > "$out/glibc-symbols.txt"
    : > "$out/minos.txt"
    uname -m > "$out/archs.txt"
    ;;
esac
file "$spike" > "$out/file.txt"
"$spike" info > "$out/info.json"

python3 - "$spike" "$baseline" "$archive_dir" "$out" <<'PY'
import json, os, re, sys
from pathlib import Path
spike, baseline, archive_dir, out = sys.argv[1:]
out = Path(out)
size = lambda path: os.path.getsize(path)
info = json.loads(out.joinpath("info.json").read_text().splitlines()[0])
report = {
    "platform": f"{info['os']}-{info['arch']}",
    "archive_bytes": size(Path(archive_dir, "libtailscale.a")),
    "spike_bytes": size(spike),
    "spike_stripped_bytes": size(out / "spike.stripped"),
    "baseline_bytes": size(baseline),
    "baseline_stripped_bytes": size(out / "baseline.stripped"),
    "link_flags": info["link_flags"],
    "archive_source": info["archive_source"],
    "go_version": info["go_version"],
    "libtailscale_commit": info["libtailscale_commit"],
    "linked_libraries": [line.strip() for line in out.joinpath("linked-libraries.txt").read_text().splitlines()[1:] if line.strip()],
    "macos_minos": out.joinpath("minos.txt").read_text().strip() or None,
    "archs": out.joinpath("archs.txt").read_text().strip(),
}
report["added_stripped_bytes"] = report["spike_stripped_bytes"] - report["baseline_stripped_bytes"]
symbols = out.joinpath("glibc-symbols.txt").read_text()
versions = {tuple(map(int, v.split("."))) for v in re.findall(r"GLIBC_([0-9]+(?:\.[0-9]+)+)", symbols)}
report["glibc_max"] = ".".join(map(str, max(versions))) if versions else None
out.joinpath("build.json").write_text(json.dumps(report, indent=2) + "\n")
mib = lambda n: f"{n / 1048576:.1f} MiB"
rows = [
    ("Archive libtailscale.a", mib(report["archive_bytes"])),
    ("Spike binary, stripped", mib(report["spike_stripped_bytes"])),
    ("Baseline binary, stripped", mib(report["baseline_stripped_bytes"])),
    ("Added by the archive, stripped", mib(report["added_stripped_bytes"])),
    ("Link flags (build.rs)", f"`{report['link_flags']}`"),
    ("Linked libraries", "<br>".join(f"`{l.split(' (')[0]}`" for l in report["linked_libraries"])),
    ("macOS minimum (LC_BUILD_VERSION)", report["macos_minos"] or "-"),
    ("Newest glibc symbol", report["glibc_max"] or "-"),
]
print(f"### Build: {report['platform']}\n\n| Number | Value |\n| --- | --- |")
for name, value in rows:
    print(f"| {name} | {value} |")
print()
if versions and max(versions) > (2, 31):
    print(f"**glibc {report['glibc_max']} is newer than 2.31**")
    sys.exit(1)
PY
