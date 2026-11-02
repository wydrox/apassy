#!/usr/bin/env python3
"""Checks for the test time measurement of CI logs; no network, builds, or tests."""

import importlib.util
from pathlib import Path
import sys
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "ci-test-times.py"
SPEC = importlib.util.spec_from_file_location("ci_test_times", SCRIPT)
TIMES = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = TIMES
SPEC.loader.exec_module(TIMES)

PATHS = {
    "src/lib.rs": ("lib", "apassy"),
    "src/main.rs": ("bin", "apassy"),
    "tests/it.rs": ("test", "it"),
}

# A `gh run view --log` excerpt: a BOM, a test list run (no times), a library run, a
# binary with a test, and the module program with a slow-test notice.
LOG = """\
tests (ubuntu-24.04, 0)\tUNKNOWN STEP\t﻿2026-11-02T13:57:31.8159100Z Run python3 scripts/ci-test-shard.py
tests (ubuntu-24.04, 0)\tUNKNOWN STEP\t2026-11-02T13:58:00.0000000Z      Running tests/it.rs (target/debug/deps/it-07b2)
tests (ubuntu-24.04, 0)\tUNKNOWN STEP\t2026-11-02T13:58:01.0000000Z companion::pairs: test
tests (ubuntu-24.04, 0)\tUNKNOWN STEP\t2026-11-02T13:58:10.0000000Z      Running unittests src/lib.rs (target/debug/deps/apassy-618f)
tests (ubuntu-24.04, 0)\tUNKNOWN STEP\t2026-11-02T13:58:10.5000000Z running 3 tests
tests (ubuntu-24.04, 0)\tUNKNOWN STEP\t2026-11-02T13:58:12.5000000Z test desktop::ui::sync_tests::joins ... ok
tests (ubuntu-24.04, 0)\tUNKNOWN STEP\t2026-11-02T13:58:13.0000000Z test desktop::ui::sync_tests::responsive ... ok
tests (ubuntu-24.04, 0)\tUNKNOWN STEP\t2026-11-02T13:58:13.2500000Z test root_test ... ignored
tests (ubuntu-24.04, 0)\tUNKNOWN STEP\t2026-11-02T13:58:14.0000000Z      Running unittests src/main.rs (target/debug/deps/apassy-1a59)
tests (ubuntu-24.04, 0)\tUNKNOWN STEP\t2026-11-02T13:58:14.0000000Z running 1 test
tests (ubuntu-24.04, 0)\tUNKNOWN STEP\t2026-11-02T13:58:14.7500000Z test cli::parses ... ok
tests (ubuntu-24.04, 0)\tUNKNOWN STEP\t2026-11-02T13:58:20.0000000Z      Running tests/it.rs (target/debug/deps/it-07b2)
tests (ubuntu-24.04, 0)\tUNKNOWN STEP\t2026-11-02T13:58:20.0000000Z running 2 tests
tests (ubuntu-24.04, 0)\tUNKNOWN STEP\t2026-11-02T13:59:20.0000000Z test companion::pairs has been running for over 60 seconds
tests (ubuntu-24.04, 0)\tUNKNOWN STEP\t2026-11-02T13:59:30.0000000Z test companion::pairs ... ok
tests (ubuntu-24.04, 0)\tUNKNOWN STEP\t2026-11-02T13:59:33.0000000Z test companion::store::reopens ... ok
"""


class TestLogParsing(unittest.TestCase):
    def test_each_unit_gets_the_time_of_its_tests(self):
        seconds = TIMES.parse_log(LOG.splitlines(), PATHS)
        self.assertEqual(seconds, {
            "lib:apassy::desktop::ui::sync_tests": 2.5,
            "lib:apassy::crate": 0.25,
            "bin:apassy": 0.75,
            "test:it::companion": 73.0,
        })

    def test_raw_job_log_lines_parse_too(self):
        raw = [line.split("\t")[-1] for line in LOG.splitlines()]
        self.assertEqual(TIMES.parse_log(raw, PATHS), TIMES.parse_log(LOG.splitlines(), PATHS))

    def test_an_unknown_target_fails(self):
        with self.assertRaises(ValueError):
            TIMES.parse_log(LOG.splitlines(), {"src/lib.rs": ("lib", "apassy")})

    def test_lines_without_a_time_are_skipped(self):
        self.assertEqual(TIMES.split_line("no time here"), (None, "no time here"))
        stamp, text = TIMES.split_line("2026-11-02T13:58:20Z running 2 tests")
        self.assertEqual((stamp.second, text), (20, "running 2 tests"))

    def test_units_match_the_partition_of_ci_test_shard(self):
        self.assertEqual(TIMES.unit_key(("lib", "apassy"), "a::b::t"), "lib:apassy::a::b")
        self.assertEqual(TIMES.unit_key(("test", "it"), "relay_sync::companion::x"), "test:it::relay_sync")
        self.assertEqual(TIMES.unit_key(("example", "screenshots"), "x::y"), "example:screenshots")
        unit = TIMES.SHARDS.Target("lib", "apassy", TIMES.SHARDS.module_of("a::b::t"))
        self.assertEqual(":".join(unit.key), TIMES.unit_key(("lib", "apassy"), "a::b::t"))

    def test_the_weight_is_the_largest_time(self):
        merged = TIMES.merge([{"a": 1.0, "b": 5.123}, {"a": 3.0}, {"c": 0.0}])
        self.assertEqual(merged, {"a": 3.0, "b": 5.12, "c": 0.0})
        self.assertEqual(list(merged), ["a", "b", "c"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
