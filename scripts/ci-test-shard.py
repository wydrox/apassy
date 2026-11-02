#!/usr/bin/env python3
"""Run one of three or four serial Cargo test groups, or print their target lists.

The units of the partition are the Cargo targets, with two exceptions. The library is
one unit for each module of its listed tests (the path of a test without its name), so
the library tests spread over all groups. The integration test program `tests/it.rs`
is one unit for each of its modules (one per former `tests/<name>.rs` program). A
group runs its whole targets with one `cargo test` command, its library tests with
`cargo test --lib -- --exact <name> ...`, and its modules with
`cargo test --test it -- <module>:: ...`. A test filter is a substring
match, so a group also skips each module of another group whose name contains one of
its filters (`passkeys::` is in `browser_passkeys::`). Before a group runs modules, the
script lists the tests of the program and checks that each test is in exactly one group.
The check fails on a test outside every module, or on a nested module with the name of a
top-level module (`relay_sync::companion::x` is in `companion::` too): rename that module.
"""

import argparse
from collections import Counter
from dataclasses import dataclass, field
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

# The measured time of each unit, in seconds: scripts/ci-test-times.py writes the file
# from the logs of green CI runs. Units without a measurement get at least one second;
# a library module gets LIBRARY_SECONDS_PER_TEST for each listed test.
WEIGHTS = ROOT / "scripts" / "ci-test-weights.json"
# The mean time of a library test on Linux CI, 2026-11-02: 920 s for 1307 tests.
LIBRARY_SECONDS_PER_TEST = 0.7
# The module of a library test at the crate root. `crate` is a keyword, so no module
# has this name.
CRATE_ROOT = "crate"


def read_weights(path=WEIGHTS):
    """The seconds of each unit key (kind, name), from the weights file."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    seconds = data.get("seconds") if isinstance(data, dict) else None
    if not isinstance(seconds, dict):
        raise ValueError(f"{path} has no seconds table")
    weights = {}
    for key, value in seconds.items():
        kind, separator, name = key.partition(":")
        if not separator or not kind or not name or isinstance(value, bool) \
                or not isinstance(value, (int, float)) or value < 0:
            raise ValueError(f"{path} has an invalid weight: {key!r}")
        weights[(kind, name)] = float(value)
    return weights


ESTIMATED_SECONDS = read_weights()


@dataclass(frozen=True, order=True)
class Target:
    kind: str
    name: str
    # A module of the library or of a test program in MODULE_TARGETS, or "" for a
    # whole target.
    module: str = ""
    # The number of listed tests of a library module. It estimates the time of a
    # module without a measurement.
    tests: int = field(default=0, compare=False)

    @property
    def key(self):
        return (self.kind, f"{self.name}::{self.module}" if self.module else self.name)

    @property
    def seconds(self):
        if self.key in ESTIMATED_SECONDS:
            return max(1.0, ESTIMATED_SECONDS[self.key])
        return max(1.0, self.tests * LIBRARY_SECONDS_PER_TEST)

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


def module_of(test):
    """The library module of a listed library test: its path without the test name."""
    return test.rpartition("::")[0] or CRATE_ROOT


def split_library(targets, library_tests):
    """Replace the library target by one unit for each module of its listed tests."""
    libraries = [target for target in targets if target.kind == "lib" and not target.module]
    if len(libraries) != 1:
        raise ValueError("The package must have exactly one library target")
    if not library_tests:
        raise ValueError("The library lists no tests")
    if len(set(library_tests)) != len(library_tests):
        raise ValueError("The library test list contains duplicates")
    counts = Counter(module_of(test) for test in library_tests)
    units = [Target("lib", libraries[0].name, name, tests=count) for name, count in counts.items()]
    return sorted([target for target in targets if target not in libraries] + units)


def assign_shards(targets, shard_count=SHARD_COUNT):
    if shard_count not in (3, 4):
        raise ValueError("The shard count must be 3 or 4")
    if len(set(targets)) != len(targets):
        raise ValueError("The target list contains duplicates")
    groups = [[] for _ in range(shard_count)]
    totals = [0.0] * shard_count
    # Longest unit first, each to the group with the least time so far.
    for target in sorted(
        targets,
        key=lambda target: (-target.seconds, target.kind, target.name, target.module),
    ):
        shard = min(range(shard_count), key=lambda index: (totals[index], index))
        groups[shard].append(target)
        totals[shard] += target.seconds
    if any(not group for group in groups):
        raise ValueError(f"Each of the {shard_count} test groups must contain a target")
    return [sorted(group) for group in groups]


def library_selection(group, library_tests):
    """The listed library tests of the library modules of `group`, in list order."""
    modules = {target.module for target in group if target.kind == "lib" and target.module}
    return [test for test in library_tests if module_of(test) in modules]


def module_programs(units):
    """The test programs in MODULE_TARGETS that have units in `units`."""
    return sorted({target.name for target in units if target.module and target.kind != "lib"})


def module_selection(group, program, targets):
    """The test filters and the skips of `group` in the test program `program`."""
    mine = sorted(
        target.module for target in group
        if target.module and target.kind != "lib" and target.name == program
    )
    others = sorted(
        target.module
        for target in targets
        if target.module and target.kind != "lib" and target.name == program
        and target.module not in mine
    )
    filters = [f"{module}::" for module in mine]
    skips = [f"{module}::" for module in others if any(f in f"{module}::" for f in filters)]
    return filters, skips


def selects(test, filters, skips):
    """libtest without --exact: any filter is a substring, and no skip is."""
    return any(f in test for f in filters) and not any(s in test for s in skips)


def cargo_commands(group, targets, library_tests=()):
    """The commands of one group: its whole targets, its library tests by exact name,
    then each test program by modules."""
    if not group:
        raise ValueError("Cannot run an empty test group")
    commands = []
    whole = [target for target in group if not target.module]
    if whole:
        command = list(CARGO_TEST)
        for target in whole:
            command.extend(target.flags)
        commands.append(command + ["--", "--test-threads=1"])
    library = library_selection(group, library_tests)
    if any(target.kind == "lib" and target.module for target in group) and not library:
        raise ValueError("A group with library modules selects no listed library test")
    if library:
        # --exact: a name selects only the test of that name, never a test whose
        # name contains it.
        commands.append(CARGO_TEST + ["--lib", "--", "--test-threads=1", "--exact", *library])
    for program in module_programs(group):
        filters, skips = module_selection(group, program, targets)
        command = CARGO_TEST + ["--test", program, "--", "--test-threads=1", *filters]
        for skip in skips:
            command.extend(["--skip", skip])
        commands.append(command)
    return commands


def list_command(program):
    return CARGO_TEST + ["--test", program, "--", "--list"]


LIBRARY_LIST_COMMAND = CARGO_TEST + ["--lib", "--", "--list"]


def describe(command):
    """A command for the log: the exact library test names as a count."""
    if "--exact" not in command:
        return shlex.join(command)
    index = command.index("--exact") + 1
    return f"{shlex.join(command[:index])} <{len(command) - index} tests by name>"


def parse_test_list(text):
    tests = []
    for line in text.splitlines():
        for suffix in (": test", ": benchmark"):
            if line.endswith(suffix):
                tests.append(line[: -len(suffix)])
    return tests


def check_partition(groups, targets, tests_by_program, library_tests=()):
    """Each listed test of the library and of each module program runs in exactly one group."""
    problems = []
    selections = [set(library_selection(group, library_tests)) for group in groups]
    for test in library_tests:
        hits = [index for index, selection in enumerate(selections) if test in selection]
        if len(hits) != 1:
            problems.append(f"library {test}: groups {hits}")
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


def list_tests(command):
    result = subprocess.run(command, cwd=ROOT, check=True, stdout=subprocess.PIPE, text=True)
    return parse_test_list(result.stdout)


def list_and_check(groups, targets, library_tests, programs):
    tests_by_program = {program: list_tests(list_command(program)) for program in programs}
    check_partition(groups, targets, tests_by_program, library_tests)
    count = len(library_tests) + sum(len(tests) for tests in tests_by_program.values())
    names = ", ".join(["the library", *programs])
    print(f"Checked: each of {count} tests of {names} is in one group", flush=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shard", type=int, choices=range(SHARD_COUNT))
    parser.add_argument("--shard-count", type=int, choices=(3, 4), default=SHARD_COUNT)
    parser.add_argument(
        "--list",
        action="store_true",
        help="Print groups without running tests; this builds and lists the library tests",
    )
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
        # Every group of one OS lists the same library tests, so every group
        # computes the same partition.
        library_tests = list_tests(LIBRARY_LIST_COMMAND)
        targets = split_library(targets, library_tests)
        groups = assign_shards(targets, args.shard_count)
        indices = range(args.shard_count) if args.shard is None else [args.shard]
        for shard in indices:
            group = groups[shard]
            seconds = sum(target.seconds for target in group)
            print(f"Group {shard}: {len(group)} targets, estimated {seconds:.2f}s", flush=True)
            for command in cargo_commands(group, targets, library_tests):
                print(describe(command), flush=True)
        if args.list:
            if args.check:
                list_and_check(groups, targets, library_tests, module_programs(targets))
            return 0
        group = groups[args.shard]
        list_and_check(groups, targets, library_tests, module_programs(group))
        code = 0
        for command in cargo_commands(group, targets, library_tests):
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
