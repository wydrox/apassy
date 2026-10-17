#!/usr/bin/env python3
"""Check the six-component release version (Python 3.12; source checks only)."""

import argparse
import json
from pathlib import Path
import re
import sys
import tomllib


COMPONENTS = {"ios", "macos", "linux-cli", "extension", "relay", "website"}


def package_version(path):
    return tomllib.loads(path.read_text(encoding="utf-8"))["package"]["version"]


def locked_version(path, name):
    packages = tomllib.loads(path.read_text(encoding="utf-8"))["package"]
    matches = [package["version"] for package in packages if package["name"] == name]
    if len(matches) != 1:
        raise ValueError(f"{path}: expected one locked {name} package")
    return matches[0]


def website_version(root, changelog):
    """Evaluate the site's actual changelog regex, without duplicating its version."""
    source = (root / "site/src/lib/site.ts").read_text(encoding="utf-8")
    if 'import changelog from "../../../CHANGELOG.md?raw";' not in source:
        raise ValueError("website VERSION must derive from the root changelog")
    declaration = re.search(
        r'export const VERSION = changelog\.match\(/(.+)/m\)\?\.\[1\] \?\? "";', source
    )
    if declaration is None:
        raise ValueError("website VERSION must use the checked changelog expression")
    match = re.search(declaration[1], changelog, re.MULTILINE)
    return match[1] if match else ""


def check(root, relay_checkout=None, require_relay=False):
    manifest = json.loads((root / "release-versions.json").read_text(encoding="utf-8"))
    version = manifest["version"]
    if not isinstance(version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("release version must be a plain major.minor.patch version")
    components = manifest["components"]
    if len(components) != 6 or set(components) != COMPONENTS:
        raise ValueError("release manifest must name all six components exactly once")

    versions = {
        "macOS Cargo package": package_version(root / "Cargo.toml"),
        "macOS Cargo.lock": locked_version(root / "Cargo.lock", "apassy"),
        "iOS core package": package_version(root / "ios/ApassyCore/Cargo.toml"),
        "iOS core Cargo.lock": locked_version(root / "Cargo.lock", "apassy-core"),
        "browser extension": json.loads((root / "extension/manifest.json").read_text())["version"],
    }
    project = (root / "ios/ApassyCompanion/project.yml").read_text(encoding="utf-8")
    marketing = re.findall(r'^\s*MARKETING_VERSION:\s*["\']?([0-9.]+)["\']?\s*$', project, re.MULTILINE)
    if len(marketing) != 1:
        raise ValueError("expected exactly one iOS MARKETING_VERSION")
    versions["iOS marketing version"] = marketing[0]

    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    versions["website changelog version"] = website_version(root, changelog)
    errors = [f"{name}: {actual!r}, expected {version}" for name, actual in versions.items() if actual != version]

    if relay_checkout is not None:
        relay = tomllib.loads((relay_checkout / "Cargo.toml").read_text(encoding="utf-8"))
        bins = {binary["name"] for binary in relay.get("bin", [])}
        if not {"apassy-relay", "apassy-team"} <= bins:
            errors.append("relay checkout must build both apassy-relay and the Linux apassy-team CLI")
        for name, actual in {
            "relay and Linux CLI package": relay["package"]["version"],
            "relay and Linux CLI Cargo.lock": locked_version(relay_checkout / "Cargo.lock", "apassy-relay"),
        }.items():
            if actual != version:
                errors.append(f"{name}: {actual!r}, expected {version}")
    elif require_relay:
        errors.append("--relay-checkout is required to check the relay and Linux CLI")
    return version, errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--relay-checkout", type=Path)
    parser.add_argument("--require-relay", action="store_true")
    args = parser.parse_args()
    try:
        version, errors = check(args.root, args.relay_checkout, args.require_relay)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"Release version check failed: {error}", file=sys.stderr)
        return 1
    if errors:
        print("Release version check failed:\n- " + "\n- ".join(errors), file=sys.stderr)
        return 1
    print(f"Release source versions match {version}.")
    if args.relay_checkout is None:
        print("Relay and Linux CLI checkout not checked; pass --relay-checkout PATH --require-relay before publication.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
