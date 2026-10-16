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

IT_PATH = str(SHARDS.ROOT / "tests" / "it.rs")
# The root file of the integration test program: helpers (units too, a helper can have
# tests), a nested helper with the name of a test module, a #[path] module, gated
# modules, and an inline module.
IT_ROOT = """//! All integration tests.

mod common;

mod support {
    #[cfg(feature = "vault")]
    pub mod companion;
}

mod browser_passkeys;
mod companion;
#[path = "isolation/product_profile.rs"]
mod isolation_profile;
mod passkeys;
mod relay_sync;
#[cfg(feature = "storage-probe")]
mod future_module;

mod layout {
    #[test]
    fn every_test_file_is_a_module() {}
}
"""
IT_MODULES = [
    "common",
    "support",
    "browser_passkeys",
    "companion",
    "isolation_profile",
    "passkeys",
    "relay_sync",
    "future_module",
    "layout",
]


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
        entry("test", "it", src_path=IT_PATH),
        entry("test", "future_auto_integration"),
        entry("custom-build", "build-script-build"),
    ])


def read(path):
    if path != IT_PATH:
        raise OSError(f"unexpected read: {path}")
    return IT_ROOT


def targets():
    return SHARDS.discover_targets(fixture(), read=read)


def module(name):
    return SHARDS.Target("test", "it", name)


class TestTargetPartition(unittest.TestCase):
    def test_all_target_kinds_and_modules_form_a_disjoint_complete_partition(self):
        units = targets()
        for shard_count in (3, 4):
            with self.subTest(shard_count=shard_count):
                groups = SHARDS.assign_shards(units, shard_count)
                flattened = [target for group in groups for target in group]
                self.assertEqual(len(groups), shard_count)
                self.assertEqual(set(flattened), set(units))
                self.assertEqual(len(flattened), len(set(flattened)))
                self.assertTrue(all(groups))
                self.assertEqual(groups[0], [SHARDS.Target("lib", "apassy")])
        self.assertEqual({target.kind for target in units}, {"lib", "bin", "test", "example", "bench"})

    def test_the_module_program_is_split_into_its_modules(self):
        units = targets()
        self.assertNotIn(SHARDS.Target("test", "it"), units)
        self.assertEqual(sorted(t.module for t in units if t.module), sorted(IT_MODULES))
        self.assertIn(SHARDS.Target("test", "future_auto_integration"), units)

    def test_module_lines_are_read_at_the_top_level_only(self):
        self.assertEqual(SHARDS.read_modules(IT_ROOT), IT_MODULES)
        self.assertEqual(SHARDS.read_modules("pub mod a;\npub(crate) mod b {\n    mod c;\n"), ["a", "b"])
        with self.assertRaises(ValueError):
            SHARDS.read_modules("mod a;\nmod a;\n")

    def test_default_shard_count_remains_four(self):
        self.assertEqual(SHARDS.assign_shards(targets()), SHARDS.assign_shards(targets(), 4))

    def test_unsupported_shard_counts_fail(self):
        for shard_count in (0, 1, 2, 5):
            with self.subTest(shard_count=shard_count), self.assertRaises(ValueError):
                SHARDS.assign_shards(targets(), shard_count)

    def test_future_targets_modules_and_test_false_examples_are_included(self):
        units = targets()
        for target in [
            SHARDS.Target("example", "future_example"),
            SHARDS.Target("test", "future_auto_integration"),
            module("future_module"),
        ]:
            self.assertIn(target, units)
            self.assertEqual(target.seconds, 1.0)
            self.assertIn(target, sum(SHARDS.assign_shards(units), []))

    def test_assignment_is_independent_of_metadata_order(self):
        units = targets()
        for shard_count in (3, 4):
            with self.subTest(shard_count=shard_count):
                self.assertEqual(
                    SHARDS.assign_shards(units, shard_count),
                    SHARDS.assign_shards(list(reversed(units)), shard_count),
                )

    def test_known_heavy_modules_use_different_groups(self):
        for shard_count in (3, 4):
            with self.subTest(shard_count=shard_count):
                groups = SHARDS.assign_shards(targets(), shard_count)
                companion = next(i for i, group in enumerate(groups) if module("companion") in group)
                relay = next(i for i, group in enumerate(groups) if module("relay_sync") in group)
                self.assertNotEqual(companion, relay)
                self.assertEqual(module("companion").seconds, SHARDS.ESTIMATED_SECONDS[("test", "it::companion")])

    def test_library_crate_types_use_one_library_selector(self):
        data = fixture()
        data["packages"][0]["targets"][0]["kind"] = ["rlib", "cdylib"]
        units = SHARDS.discover_targets(data, read=read)
        self.assertEqual(sum(target.kind == "lib" for target in units), 1)
        self.assertEqual(SHARDS.assign_shards(units)[0][0].flags, ["--lib"])

    def test_bad_metadata_fails_instead_of_omitting_a_target(self):
        for data in [
            {},
            {"packages": []},
            metadata([]),
            metadata([{"name": "missing_kind"}]),
            metadata([entry("unknown-kind", "new_target")]),
            metadata([entry("lib", "apassy"), entry("lib", "apassy")]),
            metadata([entry("lib", "apassy"), entry("test", "it")]),
        ]:
            with self.subTest(data=data), self.assertRaises(ValueError):
                SHARDS.discover_targets(data, read=read)

    def test_a_module_program_without_modules_fails(self):
        with self.assertRaises(ValueError):
            SHARDS.discover_targets(fixture(), read=lambda path: "//! No modules.\n    mod nested;\n")

    def test_missing_library_and_empty_groups_fail(self):
        for units in [[], [SHARDS.Target("bin", "only_bin")], [SHARDS.Target("lib", "only_lib")]]:
            with self.subTest(units=units), self.assertRaises(ValueError):
                SHARDS.assign_shards(units)
        with self.assertRaises(ValueError):
            SHARDS.cargo_commands([], targets())


class TestCommands(unittest.TestCase):
    def test_whole_targets_preserve_features_and_serial_tests(self):
        units = targets()
        whole = [target for target in units if not target.module]
        [command] = SHARDS.cargo_commands(whole, units)
        self.assertEqual(command[:5], ["cargo", "test", "--offline", "--locked", "--all-features"])
        self.assertEqual(command[-2:], ["--", "--test-threads=1"])
        self.assertNotIn("--no-default-features", command)
        self.assertNotIn("--all-targets", command)
        self.assertIn("--lib", command)
        for kind in ["bin", "test", "example", "bench"]:
            self.assertIn(f"--{kind}", command)
        self.assertNotIn("it", command)

    def test_modules_run_with_filters_after_the_whole_targets(self):
        units = targets()
        group = [SHARDS.Target("bin", "apassy"), module("companion"), module("relay_sync")]
        whole, modules = SHARDS.cargo_commands(group, units)
        self.assertEqual(whole, SHARDS.CARGO_TEST + ["--bin", "apassy", "--", "--test-threads=1"])
        self.assertEqual(
            modules,
            SHARDS.CARGO_TEST + ["--test", "it", "--", "--test-threads=1", "companion::", "relay_sync::"],
        )

    def test_a_filter_skips_the_modules_of_other_groups_that_contain_it(self):
        units = targets()
        [command] = SHARDS.cargo_commands([module("passkeys")], units)
        self.assertEqual(command[-3:], ["passkeys::", "--skip", "browser_passkeys::"])
        [command] = SHARDS.cargo_commands([module("passkeys"), module("browser_passkeys")], units)
        self.assertNotIn("--skip", command)

    def test_each_listed_test_runs_in_exactly_one_group(self):
        units = targets()
        listed = [
            "browser_passkeys::client_data::get",
            "support::fake_native::base64_vectors",
            "companion::pairs",
            "future_module::later",
            "isolation_profile::profile_denies",
            "layout::every_test_file_is_a_module",
            "passkeys::register",
            "relay_sync::push",
        ]
        for shard_count in (3, 4):
            with self.subTest(shard_count=shard_count):
                groups = SHARDS.assign_shards(units, shard_count)
                SHARDS.check_partition(groups, units, {"it": listed})
                for test in listed:
                    hits = [
                        group for group in groups
                        if SHARDS.selects(test, *SHARDS.module_selection(group, "it", units))
                    ]
                    self.assertEqual(len(hits), 1, test)

    def test_a_test_outside_the_modules_or_in_two_groups_fails(self):
        units = targets()
        groups = [
            [SHARDS.Target("lib", "apassy")],
            [module("companion"), module("browser_passkeys")],
            [t for t in units if t.kind != "lib" and t not in (module("companion"), module("browser_passkeys"))],
        ]
        SHARDS.check_partition(groups, units, {"it": ["companion::a", "passkeys::b", "browser_passkeys::c"]})
        for test in ["top_level_test", "relay_sync::companion::nested"]:
            with self.subTest(test=test), self.assertRaises(ValueError):
                SHARDS.check_partition(groups, units, {"it": [test]})

    def test_the_test_list_is_parsed(self):
        text = "companion::a: test\nlayout::b: test\nbench_x: benchmark\n\n3 tests, 1 benchmark\n"
        self.assertEqual(SHARDS.parse_test_list(text), ["companion::a", "layout::b", "bench_x"])


class TestCommandLine(unittest.TestCase):
    def run_main(self, args, results):
        with patch.object(SHARDS, "read_text", side_effect=read), \
                patch.object(SHARDS.subprocess, "run", side_effect=results) as run:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = SHARDS.main(args)
        return code, run

    def metadata_result(self):
        return subprocess.CompletedProcess([], 0, stdout=json.dumps(fixture()))

    def list_result(self):
        tests = "".join(f"{name}::case: test\n" for name in IT_MODULES)
        return subprocess.CompletedProcess([], 0, stdout=tests)

    def groups(self, shard_count):
        return SHARDS.assign_shards(targets(), shard_count)

    def test_list_only_reads_metadata(self):
        code, run = self.run_main(["--list"], [self.metadata_result()])
        self.assertEqual(code, 0)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[0], ["cargo", "metadata", "--offline", "--locked", "--all-features", "--no-deps", "--format-version", "1"])

    def test_list_check_lists_the_module_program(self):
        code, run = self.run_main(["--list", "--check"], [self.metadata_result(), self.list_result()])
        self.assertEqual(code, 0)
        self.assertEqual(run.call_count, 2)
        self.assertEqual(run.call_args.args[0], SHARDS.list_command("it"))

    def test_list_check_fails_on_a_test_outside_the_modules(self):
        listed = subprocess.CompletedProcess([], 0, stdout="top_level: test\n")
        code, _run = self.run_main(["--list", "--check"], [self.metadata_result(), listed])
        self.assertEqual(code, 1)

    def test_list_uses_selected_shard_count(self):
        for shard_count in (3, 4):
            with self.subTest(shard_count=shard_count), contextlib.redirect_stdout(io.StringIO()) as output:
                with patch.object(SHARDS, "read_text", side_effect=read), \
                        patch.object(SHARDS.subprocess, "run", return_value=self.metadata_result()) as run:
                    code = SHARDS.main(["--list", "--shard-count", str(shard_count)])
                self.assertEqual(code, 0)
                self.assertEqual(run.call_count, 1)
                self.assertEqual(output.getvalue().count("Group "), shard_count)

    def test_library_group_runs_without_a_test_list(self):
        code, run = self.run_main(["--shard", "0"], [self.metadata_result(), subprocess.CompletedProcess([], 0)])
        self.assertEqual(code, 0)
        self.assertEqual(run.call_count, 2)
        self.assertEqual(run.call_args.args[0], SHARDS.CARGO_TEST + ["--lib", "--", "--test-threads=1"])

    def test_test_failure_exit_code_is_preserved_and_later_commands_run(self):
        for shard_count in (3, 4):
            with self.subTest(shard_count=shard_count):
                shard = next(
                    index for index, group in enumerate(self.groups(shard_count))
                    if len(SHARDS.cargo_commands(group, targets())) == 2
                )
                expected = SHARDS.cargo_commands(self.groups(shard_count)[shard], targets())
                code, run = self.run_main(
                    ["--shard", str(shard), "--shard-count", str(shard_count)],
                    [
                        self.metadata_result(),
                        self.list_result(),
                        subprocess.CompletedProcess([], 101),
                        subprocess.CompletedProcess([], 0),
                    ],
                )
                self.assertEqual(code, 101)
                self.assertEqual(run.call_count, 4)
                self.assertEqual(run.call_args_list[1].args[0], SHARDS.list_command("it"))
                self.assertEqual([call.args[0] for call in run.call_args_list[2:]], expected)
                self.assertEqual(run.call_args.kwargs["cwd"], SHARDS.ROOT)

    def test_a_broken_partition_does_not_run_tests(self):
        listed = subprocess.CompletedProcess([], 0, stdout="top_level: test\n")
        code, run = self.run_main(["--shard", "1"], [self.metadata_result(), listed])
        self.assertEqual(code, 1)
        self.assertEqual(run.call_count, 2)

    def test_metadata_failure_exit_code_is_preserved(self):
        code, run = self.run_main(["--shard", "0"], [subprocess.CalledProcessError(42, ["cargo", "metadata"])])
        self.assertEqual(code, 42)
        self.assertEqual(run.call_count, 1)

    def test_malformed_json_does_not_run_tests(self):
        code, run = self.run_main(["--shard", "0"], [subprocess.CompletedProcess([], 0, stdout="invalid")])
        self.assertEqual(code, 1)
        self.assertEqual(run.call_count, 1)

    def test_invalid_shard_and_missing_shard_fail(self):
        for args in [
            [],
            ["--shard", "-1"],
            ["--shard", "4"],
            ["--shard", "3", "--shard-count", "3"],
            ["--list", "--shard-count", "2"],
            ["--list", "--shard-count", "5"],
            ["--check"],
            ["--shard", "1", "--check"],
        ]:
            with self.subTest(args=args), patch.object(SHARDS.subprocess, "run") as run:
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                    SHARDS.main(args)
                self.assertEqual(error.exception.code, 2)
                run.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
