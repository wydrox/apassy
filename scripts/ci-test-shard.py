#!/usr/bin/env python3
"""Run one of three or four serial Cargo test groups, or print their target lists.

The units of the partition are the Cargo targets, except the integration test program
`tests/it.rs`: each of its modules (one per former `tests/<name>.rs` program) is a unit
of its own. A group runs its whole targets with one `cargo test` command and its
modules with `cargo test --test it -- <module>:: ...`. A test filter is a substring
match, so a group also skips each module of another group whose name contains one of
its filters (`passkeys::` is in `browser_passkeys::`). Before a group runs modules, the
script lists the tests of the program and checks that each test is in exactly one group.
The check fails on a test outside every module, or on a nested module with the name of a
top-level module (`relay_sync::companion::x` is in `companion::` too): rename that module.
"""

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
SHARD_COUNT = 4
LIBRARY_KINDS = {"lib", "rlib", "dylib", "cdylib", "staticlib", "proc-macro"}
CARGO_TEST = ["cargo", "test", "--offline", "--locked", "--all-features"]

# Test programs whose root declares one module per area. Their modules are the units,
# also the helper modules: a helper can have tests too (`support::fake_native`).
MODULE_TARGETS = {"it"}
# A module declaration at the top level of the root file: `mod name;` or `mod name {`.
MODULE_LINE = re.compile(r"^(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*[;{]")

# Maximum Linux/macOS harness times from the original CI logs, 2026-10-08, when each
# module was a test program of its own. `# local`: no CI time yet; a local parallel run
# (macOS, 2026-10-16) times 2.41, the median ratio of CI to local times of the measured
# modules. These are weights, not a target list. Metadata and the root file add new
# targets and modules automatically. Use at least one second for targets and modules
# without measurements.
ESTIMATED_SECONDS = {
    ("lib", "apassy"): 224.51,
    ("test", "it::access_model"): 3.22,
    ("test", "it::add_detected"): 5.92,  # local
    ("test", "it::agent_items"): 14.99,  # local
    ("test", "it::agent_path"): 9.24,
    ("test", "it::agent_run"): 14.56,
    ("test", "it::analysis_replay"): 20.80,
    ("test", "it::automatic_access"): 9.95,  # local
    ("test", "it::bouncer_rules"): 25.35,
    ("test", "it::browser_passkeys"): 8.40,  # local
    ("test", "it::cli_ux"): 3.07,  # local
    ("test", "it::companion"): 95.18,
    ("test", "it::companion_activity"): 1.17,
    ("test", "it::companion_owner"): 4.06,
    ("test", "it::companion_store"): 10.49,
    ("test", "it::corrections"): 4.23,  # local
    ("test", "it::declaration_suggestions"): 1.78,
    ("test", "it::detect"): 3.26,  # local
    ("test", "it::exceptions"): 5.09,  # local
    ("test", "it::first_use"): 14.63,  # local
    ("test", "it::folder_sync"): 15.97,
    ("test", "it::host_coverage"): 1.81,  # local
    ("test", "it::host_hook"): 13.04,
    ("test", "it::isolation_profile"): 42.74,
    ("test", "it::item_history"): 1.99,
    ("test", "it::learning"): 11.29,
    ("test", "it::learning_replay"): 24.69,
    ("test", "it::local_finetune"): 12.45,
    ("test", "it::native_auth_cancel"): 1.71,  # local
    ("test", "it::native_helper"): 12.85,
    ("test", "it::notifications"): 15.84,
    ("test", "it::otp_agent_boundary"): 2.46,  # local
    ("test", "it::owner_answers"): 10.96,  # local
    ("test", "it::owner_auth"): 4.62,
    ("test", "it::owner_vault"): 8.99,
    ("test", "it::passkey_conflict_recovery"): 7.44,  # local
    ("test", "it::passkey_export"): 5.65,  # local
    ("test", "it::passkeys"): 5.26,  # local
    ("test", "it::provider_hosts"): 4.30,
    ("test", "it::relay_feed"): 149.80,  # local
    ("test", "it::relay_questions"): 36.19,  # local
    ("test", "it::relay_sync"): 52.44,
    ("test", "it::rule_packs"): 1.63,
    ("test", "it::run_proxy"): 4.43,
    ("test", "it::shadow_mode"): 11.76,
    ("test", "it::sqlcipher_probe"): 1.41,
    ("test", "it::sync_schema_upgrade"): 23.42,  # local
    ("test", "it::trusted_devices"): 5.63,  # local
    ("test", "it::vault_lifecycle"): 19.97,
    ("test", "it::vault_migration"): 18.71,
    ("test", "it::vault_passphrase"): 15.19,
    ("test", "it::waiting_restart"): 1.55,
}


@dataclass(frozen=True, order=True)
class Target:
    kind: str
    name: str
    # A module of a test program in MODULE_TARGETS, or "" for a whole target.
    module: str = ""

    @property
    def key(self):
        return (self.kind, f"{self.name}::{self.module}" if self.module else self.name)

    @property
    def seconds(self):
        return max(1.0, ESTIMATED_SECONDS.get(self.key, 1.0))

    @property
    def flags(self):
        if self.module:
            raise ValueError(f"A module has no target flags: {self.label}")
        return ["--lib"] if self.kind == "lib" else [f"--{self.kind}", self.name]

    @property
    def label(self):
        return ":".join(self.key)


def read_modules(text):
    """The modules that the root file of a test program declares."""
    modules = []
    for line in text.splitlines():
        match = MODULE_LINE.match(line)
        if match:
            modules.append(match.group(1))
    if len(set(modules)) != len(modules):
        raise ValueError("The root file declares a module twice")
    return modules


def read_text(path):
    return Path(path).read_text(encoding="utf-8")


def discover_targets(metadata, root=ROOT, read=None):
    """Select all root-package targets that Cargo's --all-targets selects.

    A test program in MODULE_TARGETS becomes one unit per module of its root file.
    """
    read = read or read_text
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
        if kind == "test" and name in MODULE_TARGETS:
            source = entry.get("src_path")
            if not isinstance(source, str) or not source:
                raise ValueError(f"Test target {name!r} has no source path")
            modules = read_modules(read(source))
            if not modules:
                raise ValueError(f"Test target {name!r} declares no test modules")
            units = [Target(kind, name, module) for module in modules]
        else:
            units = [Target(kind, name)]
        for target in units:
            if target in targets:
                raise ValueError(f"Cargo metadata contains a duplicate target: {target.label}")
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
        key=lambda target: (-target.seconds, target.kind, target.name, target.module),
    ):
        shard = min(range(1, shard_count), key=lambda index: (totals[index], index))
        groups[shard].append(target)
        totals[shard] += target.seconds
    if any(not group for group in groups):
        raise ValueError(f"Each of the {shard_count} test groups must contain a target")
    return [sorted(group) for group in groups]


def module_selection(group, program, targets):
    """The test filters and the skips of `group` in the test program `program`."""
    mine = sorted(target.module for target in group if target.module and target.name == program)
    others = sorted(
        target.module
        for target in targets
        if target.module and target.name == program and target.module not in mine
    )
    filters = [f"{module}::" for module in mine]
    skips = [f"{module}::" for module in others if any(f in f"{module}::" for f in filters)]
    return filters, skips


def selects(test, filters, skips):
    """libtest without --exact: any filter is a substring, and no skip is."""
    return any(f in test for f in filters) and not any(s in test for s in skips)


def cargo_commands(group, targets):
    """The commands of one group: its whole targets, then each test program by modules."""
    if not group:
        raise ValueError("Cannot run an empty test group")
    commands = []
    whole = [target for target in group if not target.module]
    if whole:
        command = list(CARGO_TEST)
        for target in whole:
            command.extend(target.flags)
        commands.append(command + ["--", "--test-threads=1"])
    for program in sorted({target.name for target in group if target.module}):
        filters, skips = module_selection(group, program, targets)
        command = CARGO_TEST + ["--test", program, "--", "--test-threads=1", *filters]
        for skip in skips:
            command.extend(["--skip", skip])
        commands.append(command)
    return commands


def list_command(program):
    return CARGO_TEST + ["--test", program, "--", "--list"]


def parse_test_list(text):
    tests = []
    for line in text.splitlines():
        for suffix in (": test", ": benchmark"):
            if line.endswith(suffix):
                tests.append(line[: -len(suffix)])
    return tests


def check_partition(groups, targets, tests_by_program):
    """Each listed test of each module program runs in exactly one group."""
    problems = []
    for program, tests in sorted(tests_by_program.items()):
        selections = [module_selection(group, program, targets) for group in groups]
        for test in tests:
            hits = [index for index, (f, s) in enumerate(selections) if selects(test, f, s)]
            if len(hits) != 1:
                problems.append(f"{program} {test}: groups {hits}")
    if problems:
        raise ValueError(
            "The groups do not run each test exactly once:\n  " + "\n  ".join(problems)
        )


def list_and_check(groups, targets):
    programs = sorted({target.name for target in targets if target.module})
    tests_by_program = {}
    for program in programs:
        result = subprocess.run(
            list_command(program), cwd=ROOT, check=True, stdout=subprocess.PIPE, text=True
        )
        tests_by_program[program] = parse_test_list(result.stdout)
    check_partition(groups, targets, tests_by_program)
    count = sum(len(tests) for tests in tests_by_program.values())
    print(f"Checked: each of {count} tests of {', '.join(programs)} is in one group", flush=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shard", type=int, choices=range(SHARD_COUNT))
    parser.add_argument("--shard-count", type=int, choices=(3, 4), default=SHARD_COUNT)
    parser.add_argument("--list", action="store_true", help="Print groups without Cargo tests")
    parser.add_argument(
        "--check",
        action="store_true",
        help="With --list: build the module test programs and check the partition",
    )
    args = parser.parse_args(argv)
    if args.shard is None and not args.list:
        parser.error("--shard is required unless --list is specified")
    if args.shard is not None and args.shard >= args.shard_count:
        parser.error("--shard must be less than --shard-count")
    if args.check and not args.list:
        parser.error("--check requires --list")
    try:
        result = subprocess.run(
            ["cargo", "metadata", "--offline", "--locked", "--all-features", "--no-deps", "--format-version", "1"],
            cwd=ROOT,
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        )
        targets = discover_targets(json.loads(result.stdout))
        groups = assign_shards(targets, args.shard_count)
        indices = range(args.shard_count) if args.shard is None else [args.shard]
        for shard in indices:
            group = groups[shard]
            seconds = sum(target.seconds for target in group)
            print(f"Group {shard}: {len(group)} targets, estimated {seconds:.2f}s", flush=True)
            for command in cargo_commands(group, targets):
                print(shlex.join(command), flush=True)
        if args.list:
            if args.check:
                list_and_check(groups, targets)
            return 0
        group = groups[args.shard]
        if any(target.module for target in group):
            list_and_check(groups, targets)
        code = 0
        for command in cargo_commands(group, targets):
            returncode = subprocess.run(command, cwd=ROOT).returncode
            code = code or returncode
        return code
    except subprocess.CalledProcessError as error:
        return error.returncode
    except (ValueError, OSError) as error:
        print(f"ci-test-shard: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
