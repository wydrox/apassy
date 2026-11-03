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


RELAY = Path("crates/apassy-relay")
APP = Path("crates/apassy-app")
LINUX = Path("packaging/linux")


def linux_node_errors(root):
    """The `linux-cli` component is the Linux node package (plan S2-S3, L3): apassy-app
    built `--no-default-features --features node` and installed as `apassy`. Its version
    is the relay crate's (the node commands are in the relay crate), and the packaging
    takes it from there, never from a literal."""
    errors = []
    app = tomllib.loads((root / APP / "Cargo.toml").read_text(encoding="utf-8"))
    features = app.get("features", {})
    if "node" not in features or "window" not in features:
        errors.append("the app crate must have the features node and window (the Linux node build)")
    elif not {"node", "window"} <= set(features.get("default", [])):
        errors.append("the app crate's default features must be window and node")
    if "apassy-app" not in {binary["name"] for binary in app.get("bin", [])}:
        errors.append("the app crate must build apassy-app, which the Linux node packages install as apassy")
    build = (root / LINUX / "build.sh").read_text(encoding="utf-8")
    if "crates/apassy-relay/Cargo.toml" not in build:
        errors.append("packaging/linux/build.sh must take the node version from the relay crate")
    control = (root / LINUX / "deb/control.in").read_text(encoding="utf-8")
    if re.search(r"^Version: @VERSION@$", control, re.MULTILINE) is None:
        errors.append("packaging/linux/deb/control.in must use Version: @VERSION@, not a literal version")
    return errors


def check(root):
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
        "macOS app package": package_version(root / APP / "Cargo.toml"),
        "macOS app Cargo.lock": locked_version(root / "Cargo.lock", "apassy-app"),
        "iOS core package": package_version(root / "ios/ApassyCore/Cargo.toml"),
        "iOS core Cargo.lock": locked_version(root / "Cargo.lock", "apassy-core"),
        "browser extension": json.loads((root / "extension/manifest.json").read_text())["version"],
        # The relay, the Linux node, and the Linux CLI are one crate of this workspace
        # (ADR 0037); the node is packaged from the app crate, so both must agree.
        "relay, Linux node, and Linux CLI package": package_version(root / RELAY / "Cargo.toml"),
        "relay, Linux node, and Linux CLI Cargo.lock": locked_version(root / "Cargo.lock", "apassy-relay"),
        "relay edge Worker package": json.loads(
            (root / RELAY / "deploy/worker/package.json").read_text(encoding="utf-8")
        )["version"],
    }
    project = (root / "ios/ApassyCompanion/project.yml").read_text(encoding="utf-8")
    marketing = re.findall(r'^\s*MARKETING_VERSION:\s*["\']?([0-9.]+)["\']?\s*$', project, re.MULTILINE)
    if len(marketing) != 1:
        raise ValueError("expected exactly one iOS MARKETING_VERSION")
    versions["iOS marketing version"] = marketing[0]

    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    versions["website changelog version"] = website_version(root, changelog)
    errors = [f"{name}: {actual!r}, expected {version}" for name, actual in versions.items() if actual != version]

    relay = tomllib.loads((root / RELAY / "Cargo.toml").read_text(encoding="utf-8"))
    bins = {binary["name"] for binary in relay.get("bin", [])}
    if not {"apassy-relay", "apassy-team"} <= bins:
        errors.append("the relay crate must build both apassy-relay and the Linux apassy-team CLI")
    errors.extend(linux_node_errors(root))
    return version, errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    # Kept so that an old command fails clearly instead of checking the wrong tree.
    parser.add_argument("--relay-checkout", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--require-relay", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.relay_checkout is not None:
        print(
            "Release version check failed: the relay is crates/apassy-relay in this repository "
            "(ADR 0037); drop --relay-checkout.",
            file=sys.stderr,
        )
        return 1
    try:
        version, errors = check(args.root)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"Release version check failed: {error}", file=sys.stderr)
        return 1
    if errors:
        print("Release version check failed:\n- " + "\n- ".join(errors), file=sys.stderr)
        return 1
    print(f"Release source versions match {version}, the relay and the Linux node included.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
