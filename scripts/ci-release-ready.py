#!/usr/bin/env python3
"""Decide before a release signs anything whether Cargo.toml names a released version.

A production release is eligible only when the version in Cargo.toml is the newest
section of CHANGELOG.md, that section has a version and a real date, and every
Unreleased section above it is empty. Any other state, including a malformed file,
skips the production release. A skip is not an error: it exits 0 with production=false.
"""

import argparse
import datetime
import re
import sys
from pathlib import Path

SEMVER = r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?"
HEADING = re.compile(r"^## \[([^\]\n]*)\](?: - (\S+))?[ \t]*$")
FENCE = re.compile(r"^\s*(?:`{3,}|~{3,})")


def cargo_version(text):
    """The version of the [package] table, or None when it is not a plain string."""
    in_package = False
    for line in text.splitlines():
        table = re.match(r"^\s*\[([^\]]*)\]\s*(?:#.*)?$", line)
        if table:
            in_package = table.group(1).strip() == "package"
            continue
        if in_package:
            match = re.match(r'^version\s*=\s*"([^"]*)"\s*(?:#.*)?$', line)
            if match and re.fullmatch(SEMVER, match.group(1)):
                return match.group(1)
    return None


def sections(text):
    """The level 2 sections of a changelog as (heading, body), outside code fences."""
    found = []
    fenced = False
    for line in text.splitlines():
        if FENCE.match(line):
            fenced = not fenced
        if not fenced and line.startswith("## "):
            found.append((line, []))
        elif found:
            found[-1][1].append(line)
    return [(heading, "\n".join(body)) for heading, body in found]


def evaluate(cargo_text, changelog_text):
    """Return (eligible, version, reason)."""
    version = cargo_version(cargo_text)
    if version is None:
        return False, "", "Cargo.toml has no plain package version"
    unreleased = False
    for heading, body in sections(changelog_text):
        parts = HEADING.match(heading)
        if parts is None:
            return False, version, f"malformed changelog heading: {heading}"
        name, date = parts.groups()
        if name == "Unreleased":
            if date is not None or unreleased:
                return False, version, "malformed Unreleased section"
            if body.strip():
                return False, version, "the changelog has unreleased entries"
            unreleased = True
            continue
        if date is None or not re.fullmatch(SEMVER, name):
            return False, version, f"newest section is not a dated release: {heading}"
        try:
            if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", date):
                raise ValueError(date)
            datetime.date.fromisoformat(date)
        except ValueError:
            return False, version, f"release has an invalid date: {heading}"
        if name != version:
            return False, version, f"Cargo.toml says {version}, the newest release says {name}"
        return True, version, f"{version} is a released version"
    return False, version, "the changelog has no released version"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cargo", required=True, type=Path)
    parser.add_argument("--changelog", required=True, type=Path)
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()
    try:
        eligible, version, reason = evaluate(
            args.cargo.read_text(encoding="utf-8"), args.changelog.read_text(encoding="utf-8")
        )
    except (OSError, UnicodeDecodeError) as error:
        eligible, version, reason = False, "", f"cannot read the version files: {error}"
    if args.github_output:
        with args.github_output.open("a", encoding="utf-8") as stream:
            stream.write(f"production={'true' if eligible else 'false'}\n")
            stream.write(f"version={version}\n")
    if eligible:
        print(f"Production release is eligible: {reason}.")
    else:
        print(f"::notice::Production release skipped: {reason}.")
    sys.exit(0)


if __name__ == "__main__":
    main()
