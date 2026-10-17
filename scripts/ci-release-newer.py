#!/usr/bin/env python3
"""Allow a public Mac release only when its version exceeds public latest.json."""

import argparse
import json
from pathlib import Path
import re
import sys
import urllib.error
import urllib.request


LATEST_URL = "https://apassy.wyderka.cc/latest.json"
SEMVER = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
)


def parse_version(value):
    match = SEMVER.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        raise ValueError(f"invalid SemVer version: {value!r}")
    major, minor, patch, prerelease, _ = match.groups()
    identifiers = prerelease.split(".") if prerelease is not None else []
    if any(part.isdigit() and len(part) > 1 and part.startswith("0") for part in identifiers):
        raise ValueError(f"invalid numeric prerelease identifier: {value!r}")
    return (int(major), int(minor), int(patch)), identifiers


def compare_versions(proposed, public):
    """SemVer precedence; build metadata does not make a new release."""
    left, left_pre = parse_version(proposed)
    right, right_pre = parse_version(public)
    if left != right:
        return (left > right) - (left < right)
    if not left_pre or not right_pre:
        return (not left_pre) - (not right_pre)
    for a, b in zip(left_pre, right_pre):
        if a == b:
            continue
        if a.isdigit() and b.isdigit():
            return (int(a) > int(b)) - (int(a) < int(b))
        if a.isdigit() != b.isdigit():
            return -1 if a.isdigit() else 1
        return (a > b) - (a < b)
    return (len(left_pre) > len(right_pre)) - (len(left_pre) < len(right_pre))


def read_public_manifest():
    request = urllib.request.Request(LATEST_URL, headers={
        "Cache-Control": "no-cache", "User-Agent": "apassy-release-version-check/1.0",
    })
    with urllib.request.urlopen(request, timeout=20) as response:
        if response.status != 200 or response.geturl() != LATEST_URL:
            raise ValueError("public latest.json must return HTTP 200 directly from its HTTPS URL")
        body = response.read(65537)
    if len(body) > 65536:
        raise ValueError("public latest.json exceeds 64 KiB")
    return json.loads(body)


def evaluate(proposed, manifest):
    if not isinstance(manifest, dict):
        raise ValueError("public latest.json must be an object")
    public = manifest.get("version")
    commit = manifest.get("commit")
    if not isinstance(commit, str) or re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise ValueError("public latest.json must identify its exact source commit")
    order = compare_versions(proposed, public)
    if order < 0:
        raise ValueError(f"refusing release {proposed}: public version {public} is newer (commit {commit})")
    return order > 0, public, commit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()
    try:
        allowed, public, commit = evaluate(args.version, read_public_manifest())
    except (OSError, ValueError, urllib.error.URLError) as error:
        print(f"::error::Public release guard failed: {error}", file=sys.stderr)
        return 1
    if args.github_output:
        with args.github_output.open("a", encoding="utf-8") as stream:
            stream.write(f"production={'true' if allowed else 'false'}\n")
            stream.write(f"public_version={public}\npublic_commit={commit}\n")
    print(f"Public Mac release: {public}, exact source commit {commit}.")
    if allowed:
        print(f"Release {args.version} is newer; publication may proceed through the remaining gates.")
    else:
        print(f"::notice::Release {args.version} is already public; skipping same-version signing and publication.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
