#!/usr/bin/env python3
"""Name the license of each Go module in the spike archive and check the allow list.

    python3 -I licenses.py MODULES_TXT GOROOT OUT_CSV

Spike only (plan s8 unit T0, ADR 0040 section 5). MODULES_TXT has one line per module,
`path|version|dir`, from `go list -deps` for GOOS=ios (scripts/build-spike-libs.sh). The script
reads the license files at the root of each module directory, names each license by its text,
and writes OUT_CSV. The Go standard library comes from GOROOT/LICENSE.

The allow list is that of ADR 0040 section 5: BSD, MIT, Apache-2.0, ISC, and MPL-2.0. The exit
status is 1 when a module has a license outside the list, an unknown text, or no license file.
The spike only reports it; unit T1 makes the same check fail the CI build.
"""

import csv
import os
import re
import sys

ALLOWED = {"BSD-2-Clause", "BSD-3-Clause", "MIT", "Apache-2.0", "ISC", "MPL-2.0"}

# GNU licenses are matched on their upper-case titles only: MPL-2.0 names them in lower case.
GNU_TITLES = [
    ("AGPL-3.0", "GNU AFFERO GENERAL PUBLIC LICENSE"),
    ("LGPL", "GNU LESSER GENERAL PUBLIC LICENSE"),
    ("LGPL", "GNU LIBRARY GENERAL PUBLIC LICENSE"),
    ("GPL", "GNU GENERAL PUBLIC LICENSE"),
]

# Each entry: a name and phrases that must all appear (lower case, spaces collapsed).
SIGNATURES = [
    ("MPL-2.0", ["mozilla public license", "version 2.0"]),
    ("Apache-2.0", ["apache license", "version 2.0"]),
    ("MIT", ["permission is hereby granted, free of charge"]),
    ("ISC", ["permission to use, copy, modify, and", "distribute this software for any purpose with or without fee"]),
    ("BSD-3-Clause", ["redistribution and use in source and binary forms", "endorse or promote"]),
    ("BSD-2-Clause", ["redistribution and use in source and binary forms"]),
    ("Unlicense", ["this is free and unencumbered software released into the public domain"]),
    ("CC0-1.0", ["cc0 1.0"]),
]

LICENSE_FILE = re.compile(r"^(licen[cs]e|copying|unlicense)([.-].*)?$", re.IGNORECASE)


def names_in(text):
    found = set()
    for name, title in GNU_TITLES:
        if title in text:
            found.add(name)
    flat = re.sub(r"\s+", " ", text).lower()
    for name, phrases in SIGNATURES:
        if all(p in flat for p in phrases):
            found.add(name)
    if "BSD-3-Clause" in found:
        found.discard("BSD-2-Clause")
    return found


def classify(directory):
    if not directory or not os.path.isdir(directory):
        return set(), []
    files = sorted(f for f in os.listdir(directory) if LICENSE_FILE.match(f))
    found = set()
    for name in files:
        path = os.path.join(directory, name)
        if not os.path.isfile(path):
            continue
        with open(path, encoding="utf-8", errors="replace") as f:
            found |= names_in(f.read()) or {"UNKNOWN"}
    return found, files


def main(modules_txt, goroot, out_csv):
    rows = []
    # The toolchain from the module proxy has LICENSE in GOROOT; Homebrew keeps it one level up.
    if not os.path.isfile(os.path.join(goroot, "LICENSE")):
        goroot = os.path.dirname(goroot.rstrip("/"))
    modules = [("go (standard library)", "", goroot)]
    with open(modules_txt, encoding="utf-8") as f:
        for line in f:
            parts = line.strip().split("|")
            if len(parts) == 3 and parts[0]:
                modules.append(tuple(parts))
    failures = []
    for path, version, directory in modules:
        found, files = classify(directory)
        if not found:
            verdict = "no license file"
        elif found <= ALLOWED:
            verdict = "allowed"
        else:
            verdict = "not on the allow list"
        if verdict != "allowed":
            failures.append(f"{path} {version}: {verdict} ({' + '.join(sorted(found)) or '-'})")
        rows.append([path, version, " + ".join(sorted(found)), verdict, " ".join(files)])
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["module", "version", "license", "verdict", "files"])
        writer.writerows(rows)
    counts = {}
    for row in rows:
        counts[row[2] or "-"] = counts.get(row[2] or "-", 0) + 1
    summary = ", ".join(f"{name} {n}" for name, n in sorted(counts.items()))
    print(f"licenses: {len(rows)} modules ({summary}); {out_csv}")
    if failures:
        print("licenses: FAIL, review these modules:")
        for line in failures:
            print(f"  {line}")
        return 1
    print("licenses: PASS, every module is on the allow list")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
        sys.exit(2)
    sys.exit(main(*sys.argv[1:]))
