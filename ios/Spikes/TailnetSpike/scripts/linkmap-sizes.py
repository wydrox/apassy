#!/usr/bin/env python3
"""Sum the bytes that each archive adds to the spike's executable, from the ld link map.

    python3 -I scripts/linkmap-sizes.py out/linkmap-Release-iphoneos.txt

Spike only (plan s8 unit T0). The project writes the map (LD_GENERATE_MAP_FILE). The sums are the
__TEXT and __DATA bytes of the live symbols of each group, after dead stripping. The symbol table
and other __LINKEDIT data are not counted: an App Store build strips them. The libtailscale line is
the size that the embedded node adds to an app; the Rust probe line is code that the Apassy app
already has (rustls and ring are in the vault core).
"""

import collections
import re
import sys

OBJECT = re.compile(r"^\[\s*(\d+)\]\s+(.*)$")
SYMBOL = re.compile(r"^0x[0-9A-Fa-f]+\s+0x([0-9A-Fa-f]+)\s+\[\s*(\d+)\]\s")


def group(path):
    if "libtailscale.a" in path:
        return "libtailscale (Go, tsnet)"
    if "libtailnet_spike_rs.a" in path:
        return "Rust probe (rustls, ring)"
    if path.endswith(".tbd") or ".framework/" in path or "/usr/lib/" in path:
        return "system stubs"
    if "linker synthesized" in path:
        return "linker"
    return "spike Swift code"


def main(path):
    files = {}
    sizes = collections.Counter()
    section = None
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("#"):
                if line.startswith("# Object files:"):
                    section = "objects"
                elif line.startswith("# Symbols:"):
                    section = "symbols"
                elif line.startswith("# Sections:"):
                    section = "sections"
                elif line.startswith("# Dead Stripped Symbols:"):
                    section = "dead"
                continue
            if section == "objects":
                m = OBJECT.match(line.strip())
                if m:
                    files[int(m.group(1))] = m.group(2)
            elif section == "symbols":
                m = SYMBOL.match(line)
                if m:
                    sizes[int(m.group(2))] += int(m.group(1), 16)
    groups = collections.Counter()
    for index, size in sizes.items():
        groups[group(files.get(index, "?"))] += size
    total = sum(groups.values())
    for name, size in groups.most_common():
        print(f"{name:28} {size / 1e6:8.2f} MB")
    print(f"{'total __TEXT and __DATA':28} {total / 1e6:8.2f} MB")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: linkmap-sizes.py LINKMAP", file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
