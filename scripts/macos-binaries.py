#!/usr/bin/env python3
"""List the SHA-256 of each Mach-O file of an app bundle, with and without its signature.

The release workflow writes macos-binaries.json from the app in the signed disk image and
attests it (docs/operations/release.md, "Attestations and SBOMs"). A user can then check
that the notarized app contains the binaries that CI built: copy each listed file, remove
its signature with `codesign --remove-signature`, and compare the SHA-256 with
`sha256_unsigned`. scripts/ios-testflight.sh uses the same listing for the iPhone build
record. Runs on macOS (codesign) with Python 3.9 or later and the standard library only.

Usage: scripts/macos-binaries.py BUNDLE --output FILE [--version V] [--commit SHA]
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

FORMAT = 1
THIN = {b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"}
FAT = {b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"}


def is_macho(path: Path) -> bool:
    with path.open("rb") as handle:
        head = handle.read(8)
    if len(head) < 8:
        return False
    if head[:4] in THIN:
        return True
    # 0xcafebabe is also the magic of a Java class file. A universal binary has a small
    # architecture count where a class file has its version (45 or more).
    return head[:4] in FAT and int.from_bytes(head[4:8], "big") < 45


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def unsigned_sha256(path: Path, work: Path) -> str:
    copy = work / "binary"
    shutil.copyfile(path, copy)
    signed = subprocess.run(["codesign", "--display", str(copy)],
                            capture_output=True, check=False).returncode == 0
    if signed:
        subprocess.run(["codesign", "--remove-signature", str(copy)],
                       capture_output=True, check=True)
    try:
        return sha256(copy)
    finally:
        copy.unlink()


def listing(bundle: Path) -> list:
    files = []
    with tempfile.TemporaryDirectory() as temp:
        for root, dirs, names in os.walk(bundle, followlinks=False):
            dirs.sort()
            for name in sorted(names):
                path = Path(root) / name
                if path.is_symlink() or not path.is_file() or not is_macho(path):
                    continue
                files.append({
                    "path": path.relative_to(bundle).as_posix(),
                    "sha256": sha256(path),
                    "sha256_unsigned": unsigned_sha256(path, Path(temp)),
                })
    return files


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version")
    parser.add_argument("--commit")
    args = parser.parse_args()
    if not args.bundle.is_dir():
        print(f"error: {args.bundle} is not a bundle directory", file=sys.stderr)
        return 1
    files = listing(args.bundle)
    if not files:
        print(f"error: {args.bundle} has no Mach-O file", file=sys.stderr)
        return 1
    record = {
        "format": FORMAT,
        "bundle": args.bundle.name,
        "method": "SHA-256 of each Mach-O file; sha256_unsigned after codesign --remove-signature on a copy",
        "files": files,
    }
    if args.version:
        record["version"] = args.version
    if args.commit:
        record["commit"] = args.commit
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"{args.output}: {len(files)} Mach-O files of {args.bundle.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
