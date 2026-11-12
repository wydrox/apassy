#!/usr/bin/env python3
"""Check the six-component release version (Python 3.12; source checks only)."""

import argparse
import json
from pathlib import Path
import re
import runpy
import subprocess
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


def linux_vault_errors(root):
    """The Linux vault package `apassy-vault` (ADR 0045, unit L6) is delivered with the
    `linux-cli` component at the shared release version: the desktop, the owner commands
    and the browser host for x86_64 and aarch64, as .tar.gz and .deb on /dl/. These are
    source checks of its release path; publication is verified by
    deploy/worker/scripts/check-public-assets.py (docs/operations/release.md)."""
    errors = []
    build = (root / LINUX / "build-vault.sh").read_text(encoding="utf-8")
    if "release-versions.json" not in build:
        errors.append("packaging/linux/build-vault.sh must take the version from release-versions.json")
    if re.search(r"^Version: \$version$", build, re.MULTILINE) is None:
        errors.append("packaging/linux/build-vault.sh must write Version: $version, not a literal version")
    release = (root / LINUX / "build-vault-release.sh").read_text(encoding="utf-8")
    if "cargo build --release --locked" not in release or "baseline=2.31" not in release:
        errors.append("packaging/linux/build-vault-release.sh must build in release mode against glibc 2.31")
    workflow = (root / ".github/workflows/relay-image.yml").read_text(encoding="utf-8")
    for needle, what in (
        ("packaging/linux/build-vault-release.sh", "build the vault packages with build-vault-release.sh"),
        ("packaging/linux/verify-vault.sh --dist dist", "verify the vault packages"),
        ("> SHA256SUMS-vault\n", "combine the vault checksums into SHA256SUMS-vault"),
        ("rust:1.97.0-bullseye@", "build the vault in the bullseye image"),
    ):
        if needle not in workflow:
            errors.append(f".github/workflows/relay-image.yml must {what}")
    assets = (root / RELAY / "deploy/worker/scripts/verify-assets.mjs").read_text(encoding="utf-8")
    public = (root / RELAY / "deploy/worker/scripts/check-public-assets.py").read_text(encoding="utf-8")
    for path, text in (("verify-assets.mjs", assets), ("check-public-assets.py", public)):
        if "apassy-vault_" not in text or "linux-aarch64.tar.gz" not in text:
            errors.append(f"deploy/worker/scripts/{path} must require the four Linux vault packages")
    installer = (root / RELAY / "deploy/worker/public/install.sh").read_text(encoding="utf-8")
    if "apassy-vault_" not in installer or "APASSY_COMPONENT" not in installer:
        errors.append("deploy/worker/public/install.sh must install the vault package on request")
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
        # The push gateway (push-gateway-v1) is a second Worker of the relay surface.
        "relay push gateway package": json.loads(
            (root / RELAY / "deploy/push-gateway/package.json").read_text(encoding="utf-8")
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
    errors.extend(linux_vault_errors(root))
    return version, errors


def release_errors(root, version):
    """Require a new SemVer above every v* tag; callers must fetch tags first."""
    # Share precedence rules with the public latest.json guard (including prereleases
    # and build metadata), rather than trusting Git's lexicographic/version sorting.
    semver = runpy.run_path(str(Path(__file__).with_name("ci-release-newer.py")))
    compare = semver["compare_versions"]
    semver["parse_version"](version)
    result = subprocess.run(
        ["git", "tag", "-l", "v*"], cwd=root, check=True,
        capture_output=True, text=True,
    )
    latest = None
    for tag in result.stdout.splitlines():
        candidate = tag[1:]
        # A malformed release tag is an error, not permission to publish.
        semver["parse_version"](candidate)
        if latest is None or compare(candidate, latest) > 0:
            latest = candidate
    if latest is not None and compare(version, latest) <= 0:
        return [f"release version {version} must be newer than latest tag v{latest}; "
                "same-version rebuilds are forbidden"]
    return []


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--release", action="store_true",
                        help="require a version above the latest v* tag (fetch tags first)")
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
        if args.release:
            errors.extend(release_errors(args.root, version))
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        print(f"Release version check failed: {error}", file=sys.stderr)
        return 1
    if errors:
        print("Release version check failed:\n- " + "\n- ".join(errors), file=sys.stderr)
        return 1
    print(f"Release source versions match {version}, the relay, the Linux node and the Linux vault package included.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
