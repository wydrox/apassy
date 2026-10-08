#!/usr/bin/env python3
"""Checks for the Cargo target partition; no Rust build or tests are run."""

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "ci-test-shard.py"
SPEC = importlib.util.spec_from_file_location("ci_test_shard", SCRIPT)
SHARDS = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = SHARDS
SPEC.loader.exec_module(SHARDS)


def metadata(targets):
    return {"packages": [{"manifest_path": str(SHARDS.ROOT / "Cargo.toml"), "targets": targets}]}


def entry(kind, name, **extra):
    return {"kind": [kind], "name": name, **extra}


def fixture():
    return metadata([
        entry("lib", "apassy"),
        entry("bin", "apassy", test=True),
        entry("example", "future_example", test=False),
        entry("bench", "future_bench", test=False),
        entry("test", "companion"),
        entry("test", "relay_sync"),
        entry("test", "future_auto_integration"),
        entry("custom-build", "build-script-build"),
    ])


class TestTargetPartition(unittest.TestCase):
    def test_all_target_kinds_form_a_disjoint_complete_partition(self):
        targets = SHARDS.discover_targets(fixture())
        groups = SHARDS.assign_shards(targets)
        flattened = [target for group in groups for target in group]
        self.assertEqual(set(flattened), set(targets))
        self.assertEqual(len(flattened), len(set(flattened)))
        self.assertTrue(all(groups))
        self.assertEqual(groups[0], [SHARDS.Target("lib", "apassy")])
        self.assertEqual({target.kind for target in targets}, {"lib", "bin", "test", "example", "bench"})

    def test_future_targets_and_test_false_examples_are_included(self):
        targets = SHARDS.discover_targets(fixture())
        for target in [SHARDS.Target("example", "future_example"), SHARDS.Target("test", "future_auto_integration")]:
            self.assertIn(target, targets)
            self.assertEqual(target.seconds, 1.0)
            self.assertIn(target, sum(SHARDS.assign_shards(targets), []))

    def test_assignment_is_independent_of_metadata_order(self):
        targets = SHARDS.discover_targets(fixture())
        self.assertEqual(SHARDS.assign_shards(targets), SHARDS.assign_shards(list(reversed(targets))))

    def test_known_heavy_targets_use_different_groups(self):
        groups = SHARDS.assign_shards(SHARDS.discover_targets(fixture()))
        companion = next(i for i, group in enumerate(groups) if SHARDS.Target("test", "companion") in group)
        relay = next(i for i, group in enumerate(groups) if SHARDS.Target("test", "relay_sync") in group)
        self.assertNotEqual(companion, relay)

    def test_library_crate_types_use_one_library_selector(self):
        data = fixture()
        data["packages"][0]["targets"][0]["kind"] = ["rlib", "cdylib"]
        self.assertEqual(sum(target.kind == "lib" for target in SHARDS.discover_targets(data)), 1)
        self.assertEqual(SHARDS.assign_shards(SHARDS.discover_targets(data))[0][0].flags, ["--lib"])

    def test_bad_metadata_fails_instead_of_omitting_a_target(self):
        for data in [
            {},
            {"packages": []},
            metadata([]),
            metadata([{"name": "missing_kind"}]),
            metadata([entry("unknown-kind", "new_target")]),
            metadata([entry("lib", "apassy"), entry("lib", "apassy")]),
        ]:
            with self.subTest(data=data), self.assertRaises(ValueError):
                SHARDS.discover_targets(data)

    def test_missing_library_and_empty_groups_fail(self):
        for targets in [[], [SHARDS.Target("bin", "only_bin")], [SHARDS.Target("lib", "only_lib")]]:
            with self.subTest(targets=targets), self.assertRaises(ValueError):
                SHARDS.assign_shards(targets)
        with self.assertRaises(ValueError):
            SHARDS.cargo_command([])

    def test_command_preserves_features_and_serial_tests(self):
        targets = SHARDS.discover_targets(fixture())
        command = SHARDS.cargo_command(targets)
        self.assertEqual(command[:5], ["cargo", "test", "--offline", "--locked", "--all-features"])
        self.assertEqual(command[-2:], ["--", "--test-threads=1"])
        self.assertNotIn("--no-default-features", command)
        self.assertNotIn("--all-targets", command)
        self.assertIn("--lib", command)
        for kind in ["bin", "test", "example", "bench"]:
            self.assertIn(f"--{kind}", command)


class TestCommandLine(unittest.TestCase):
    def run_main(self, args, results):
        with patch.object(SHARDS.subprocess, "run", side_effect=results) as run:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = SHARDS.main(args)
        return code, run

    def metadata_result(self):
        return subprocess.CompletedProcess([], 0, stdout=json.dumps(fixture()))

    def test_list_only_reads_metadata(self):
        code, run = self.run_main(["--list"], [self.metadata_result()])
        self.assertEqual(code, 0)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[0], ["cargo", "metadata", "--offline", "--locked", "--all-features", "--no-deps", "--format-version", "1"])

    def test_test_failure_exit_code_is_preserved(self):
        code, run = self.run_main(["--shard", "2"], [self.metadata_result(), subprocess.CompletedProcess([], 101)])
        self.assertEqual(code, 101)
        self.assertEqual(run.call_count, 2)
        expected = SHARDS.cargo_command(SHARDS.assign_shards(SHARDS.discover_targets(fixture()))[2])
        self.assertEqual(run.call_args.args[0], expected)
        self.assertEqual(run.call_args.kwargs["cwd"], SHARDS.ROOT)

    def test_metadata_failure_exit_code_is_preserved(self):
        code, run = self.run_main(["--shard", "0"], [subprocess.CalledProcessError(42, ["cargo", "metadata"])])
        self.assertEqual(code, 42)
        self.assertEqual(run.call_count, 1)

    def test_malformed_json_does_not_run_tests(self):
        code, run = self.run_main(["--shard", "0"], [subprocess.CompletedProcess([], 0, stdout="invalid")])
        self.assertEqual(code, 1)
        self.assertEqual(run.call_count, 1)

    def test_invalid_shard_and_missing_shard_fail(self):
        for args in [[], ["--shard", "-1"], ["--shard", "4"]]:
            with self.subTest(args=args), patch.object(SHARDS.subprocess, "run") as run:
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                    SHARDS.main(args)
                self.assertEqual(error.exception.code, 2)
                run.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
