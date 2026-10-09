#!/usr/bin/env python3
"""Run one of three or four serial Cargo test groups, or print their target lists."""

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import shlex
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
SHARD_COUNT = 4
LIBRARY_KINDS = {"lib", "rlib", "dylib", "cdylib", "staticlib", "proc-macro"}

# Maximum Linux/macOS harness times from the original CI logs, 2026-10-08.
# These are weights, not a target list. Metadata adds new targets automatically.
# Use at least one second for process overhead and targets without measurements.
ESTIMATED_SECONDS = {
    ("lib", "apassy"): 224.51,
    ("test", "access_model"): 3.22,
    ("test", "agent_path"): 9.24,
    ("test", "agent_run"): 14.56,
    ("test", "analysis_replay"): 20.80,
    ("test", "bouncer_rules"): 25.35,
    ("test", "companion"): 95.18,
    ("test", "companion_activity"): 1.17,
    ("test", "companion_owner"): 4.06,
    ("test", "companion_store"): 10.49,
    ("test", "declaration_suggestions"): 1.78,
    ("test", "folder_sync"): 15.97,
    ("test", "host_hook"): 13.04,
    ("test", "isolation_profile"): 42.74,
    ("test", "item_history"): 1.99,
    ("test", "learning"): 11.29,
    ("test", "learning_replay"): 24.69,
    ("test", "local_finetune"): 12.45,
    ("test", "native_helper"): 12.85,
    ("test", "notifications"): 15.84,
    ("test", "owner_auth"): 4.62,
    ("test", "owner_vault"): 8.99,
    ("test", "provider_hosts"): 4.30,
    ("test", "relay_sync"): 52.44,
    ("test", "rule_packs"): 1.63,
    ("test", "run_proxy"): 4.43,
    ("test", "shadow_mode"): 11.76,
    ("test", "sqlcipher_probe"): 1.41,
    ("test", "vault_lifecycle"): 19.97,
    ("test", "vault_migration"): 18.71,
    ("test", "vault_passphrase"): 15.19,
    ("test", "waiting_restart"): 1.55,
}


@dataclass(frozen=True, order=True)
class Target:
    kind: str
    name: str

    @property
    def seconds(self):
        return max(1.0, ESTIMATED_SECONDS.get((self.kind, self.name), 1.0))

    @property
    def flags(self):
        return ["--lib"] if self.kind == "lib" else [f"--{self.kind}", self.name]


def discover_targets(metadata, root=ROOT):
    """Select all root-package targets that Cargo's --all-targets selects."""
    if not isinstance(metadata, dict) or not isinstance(metadata.get("packages"), list):
        raise ValueError("Cargo metadata has no package list")
    manifest = root / "Cargo.toml"
    packages = [
        package
        for package in metadata["packages"]
        if isinstance(package, dict) and package.get("manifest_path") == str(manifest)
    ]
    if len(packages) != 1:
        raise ValueError("Cargo metadata must contain exactly one root package")
    package = packages[0]
    if not isinstance(package.get("targets"), list) or not package["targets"]:
        raise ValueError("The root package has no target list")
    targets = set()
    for entry in package["targets"]:
        if not isinstance(entry, dict):
            raise ValueError("Cargo metadata contains an invalid target")
        name, kinds = entry.get("name"), entry.get("kind")
        if not isinstance(name, str) or not name or not isinstance(kinds, list) or not kinds:
            raise ValueError("Each Cargo target must have a name and kind")
        if not all(isinstance(kind, str) for kind in kinds):
            raise ValueError(f"Target {name!r} has an invalid kind")
        kinds = set(kinds)
        if kinds == {"custom-build"}:
            # Cargo builds this implicitly for each selected target.
            continue
        if kinds <= LIBRARY_KINDS:
            kind = "lib"
        elif len(kinds) == 1 and kinds <= {"bin", "test", "example", "bench"}:
            kind = next(iter(kinds))
        else:
            raise ValueError(f"Target {name!r} has unsupported kinds: {sorted(kinds)}")
        target = Target(kind, name)
        if target in targets:
            raise ValueError(f"Cargo metadata contains a duplicate target: {kind}:{name}")
        # Do not filter on `test`: explicit --all-targets also selects test=false
        # targets, including examples. Required features use --all-features.
        targets.add(target)
    return sorted(targets)


def assign_shards(targets, shard_count=SHARD_COUNT):
    if shard_count not in (3, 4):
        raise ValueError("The shard count must be 3 or 4")
    if len(set(targets)) != len(targets):
        raise ValueError("The target list contains duplicates")
    libraries = [target for target in targets if target.kind == "lib"]
    if len(libraries) != 1:
        raise ValueError("Group 0 requires exactly one library target")
    groups = [libraries] + [[] for _ in range(shard_count - 1)]
    totals = [libraries[0].seconds] + [0.0] * (shard_count - 1)
    for target in sorted(
        (target for target in targets if target.kind != "lib"),
        key=lambda target: (-target.seconds, target.kind, target.name),
    ):
        shard = min(range(1, shard_count), key=lambda index: (totals[index], index))
        groups[shard].append(target)
        totals[shard] += target.seconds
    if any(not group for group in groups):
        raise ValueError(f"Each of the {shard_count} test groups must contain a target")
    return [sorted(group) for group in groups]


def cargo_command(targets):
    if not targets:
        raise ValueError("Cannot run an empty test group")
    command = ["cargo", "test", "--offline", "--locked", "--all-features"]
    for target in targets:
        command.extend(target.flags)
    return command + ["--", "--test-threads=1"]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shard", type=int, choices=range(SHARD_COUNT))
    parser.add_argument("--shard-count", type=int, choices=(3, 4), default=SHARD_COUNT)
    parser.add_argument("--list", action="store_true", help="Print groups without Cargo tests")
    args = parser.parse_args(argv)
    if args.shard is None and not args.list:
        parser.error("--shard is required unless --list is specified")
    if args.shard is not None and args.shard >= args.shard_count:
        parser.error("--shard must be less than --shard-count")
    try:
        result = subprocess.run(
            ["cargo", "metadata", "--offline", "--locked", "--all-features", "--no-deps", "--format-version", "1"],
            cwd=ROOT,
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        )
        groups = assign_shards(discover_targets(json.loads(result.stdout)), args.shard_count)
        indices = range(args.shard_count) if args.shard is None else [args.shard]
        for shard in indices:
            group = groups[shard]
            seconds = sum(target.seconds for target in group)
            print(f"Group {shard}: {len(group)} targets, estimated {seconds:.2f}s", flush=True)
            print(shlex.join(cargo_command(group)), flush=True)
        if args.list:
            return 0
        return subprocess.run(cargo_command(groups[args.shard]), cwd=ROOT).returncode
    except subprocess.CalledProcessError as error:
        return error.returncode
    except (ValueError, OSError) as error:
        print(f"ci-test-shard: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
