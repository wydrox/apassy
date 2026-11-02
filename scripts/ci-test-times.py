#!/usr/bin/env python3
"""Measure the test times of CI runs and write the weights of ci-test-shard.py.

The script reads the logs of the `tests (...)` jobs of successful CI runs with `gh`.
Each test process runs with --test-threads=1, so the time of a test is the time
between its result line and the line before it. The script adds the times of the
tests of each unit of the partition: a module of the library, a module of a test
program in MODULE_TARGETS, or a whole target. The weight of a unit is its largest
time in the runs, on Linux or macOS.

    python3 scripts/ci-test-times.py RUN_ID [RUN_ID ...] > scripts/ci-test-weights.json

Measure again when a group of a green run takes much longer than the other groups.
"""

import argparse
from collections import defaultdict
from datetime import datetime
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("ci_test_shard", ROOT / "scripts" / "ci-test-shard.py")
SHARDS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SHARDS)

# `     Running unittests src/lib.rs (target/debug/deps/apassy-0123)` or `Running tests/it.rs (...)`.
STAMP = re.compile(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?Z ")
RUNNING = re.compile(r"^\s*Running (?:unittests )?(\S+) \(")
STARTED = re.compile(r"^running \d+ tests?$")
RESULT = re.compile(r"^test (\S+) \.\.\. (?:ok|ignored|FAILED)")


def split_line(line):
    """The time and the text of a log line of `gh run view --log` or of the raw job log."""
    text = line.rstrip("\n").split("\t")[-1].lstrip("﻿")
    match = STAMP.match(text)
    if not match:
        return None, text
    # GitHub writes seven digits of the fraction; datetime reads six.
    fraction = (match.group(2) or "").ljust(6, "0")[:6]
    stamp = datetime.strptime(f"{match.group(1)}.{fraction}", "%Y-%m-%dT%H:%M:%S.%f")
    return stamp, text[match.end():]


def unit_key(target, test):
    """The weight key of the unit of `test` in `target` (kind, name)."""
    kind, name = target
    if kind == "lib":
        return f"lib:{name}::{SHARDS.module_of(test)}"
    if kind == "test" and name in SHARDS.MODULE_TARGETS:
        return f"test:{name}::{test.split('::', 1)[0]}"
    return f"{kind}:{name}"


def parse_log(lines, targets_by_path):
    """The seconds of each unit in one job log."""
    seconds = defaultdict(float)
    target, previous = None, None
    for line in lines:
        stamp, text = split_line(line)
        if stamp is None:
            continue
        match = RUNNING.match(text)
        if match:
            path = match.group(1)
            if path not in targets_by_path:
                raise ValueError(f"The log runs an unknown target: {path}")
            target, previous = targets_by_path[path], None
            continue
        if STARTED.match(text):
            previous = stamp
            continue
        match = RESULT.match(text)
        if match and target is not None and previous is not None:
            seconds[unit_key(target, match.group(1))] += (stamp - previous).total_seconds()
            previous = stamp
    return dict(seconds)


def targets_by_path(metadata):
    """Source paths relative to the repository, mapped to (kind, name) as in ci-test-shard.py."""
    manifest = str(ROOT / "Cargo.toml")
    [package] = [p for p in metadata["packages"] if p.get("manifest_path") == manifest]
    paths = {}
    for entry in package["targets"]:
        kinds = set(entry["kind"])
        if kinds == {"custom-build"}:
            continue
        kind = "lib" if kinds <= SHARDS.LIBRARY_KINDS else next(iter(kinds))
        paths[str(Path(entry["src_path"]).relative_to(ROOT))] = (kind, entry["name"])
    return paths


def merge(measurements):
    """The largest time of each unit."""
    weights = {}
    for seconds in measurements:
        for key, value in seconds.items():
            weights[key] = max(weights.get(key, 0.0), value)
    return {key: round(value, 2) for key, value in sorted(weights.items())}


def gh(*args):
    return subprocess.run(["gh", *args], cwd=ROOT, check=True, stdout=subprocess.PIPE, text=True).stdout


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("runs", nargs="+", type=int, metavar="RUN_ID")
    args = parser.parse_args(argv)
    metadata = json.loads(subprocess.run(
        ["cargo", "metadata", "--offline", "--locked", "--all-features", "--no-deps", "--format-version", "1"],
        cwd=ROOT, check=True, stdout=subprocess.PIPE, text=True,
    ).stdout)
    paths = targets_by_path(metadata)
    measurements = []
    for run in args.runs:
        jobs = json.loads(gh("api", f"repos/{{owner}}/{{repo}}/actions/runs/{run}/jobs?per_page=100"))["jobs"]
        for job in jobs:
            if not job["name"].startswith("tests ("):
                continue
            if job["conclusion"] != "success":
                raise ValueError(f"Run {run} job {job['name']!r} did not succeed")
            seconds = parse_log(gh("run", "view", "--job", str(job["id"]), "--log").splitlines(), paths)
            print(f"{run} {job['name']}: {sum(seconds.values()):.0f}s in {len(seconds)} units", file=sys.stderr)
            measurements.append(seconds)
    if not measurements:
        raise ValueError("The runs have no test jobs")
    json.dump({
        "about": "Written by scripts/ci-test-times.py: the largest Linux or macOS time of each "
                 "test unit, in seconds. ci-test-shard.py balances its groups with these times.",
        "runs": args.runs,
        "seconds": merge(measurements),
    }, sys.stdout, indent=1)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
