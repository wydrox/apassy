import copy
import importlib.util
import json
import subprocess
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "ci_release_run", Path(__file__).resolve().parents[1] / "ci-release-run.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ReleaseRunTests(unittest.TestCase):
    def setUp(self):
        self.commit = "a" * 40
        self.run = {
            "id": 12, "run_attempt": 2, "repository": {"full_name": "owner/app", "id": 99},
            "head_repository": {"full_name": "owner/app", "id": 99},
            "path": ".github/workflows/ci.yml", "event": "push",
            "head_branch": "main", "head_sha": self.commit,
            "status": "completed", "conclusion": "success",
        }

    def check(self, run=None, attempt=None):
        return MODULE.validate_run(
            self.run if run is None else run, "owner/app", self.commit, "12", attempt
        )

    def test_exact_successful_main_ci_run_is_eligible(self):
        self.assertEqual(self.check(), {
            "run_id": "12", "run_attempt": "2",
        })
        self.assertEqual(self.check(attempt="2"), self.check())

    def test_ineligible_runs_are_rejected(self):
        changes = {
            "id": 13, "repository": {"full_name": "foreign/app"},
            "head_repository": {"full_name": "foreign/app"},
            "path": ".github/workflows/other.yml", "event": "pull_request",
            "head_branch": "feature", "head_sha": "b" * 40,
            "status": "in_progress", "conclusion": "failure",
            "run_attempt": 0,
        }
        for field, value in changes.items():
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check({**self.run, field: value})
        for result in ["cancelled", "skipped", None]:
            with self.subTest(result=result), self.assertRaises(ValueError):
                self.check({**self.run, "conclusion": result})

    def test_later_attempt_does_not_substitute_for_event_attempt(self):
        with self.assertRaises(ValueError):
            self.check(attempt="1")

    def artifact(self, number):
        return {"id": 100 + number, "name": f"apassy-release-{self.commit}-{number}",
                "expired": False, "created_at": "2026-11-02T10:00:01Z",
                "workflow_run": {"id": 12, "head_sha": self.commit,
                                 "head_branch": "main", "repository_id": 99,
                                 "head_repository_id": 99}}

    def job(self, number):
        return {"id": 200 + number, "name": "release-binaries", "run_id": 12,
                "run_attempt": number, "head_sha": self.commit,
                "status": "completed", "conclusion": "success",
                "steps": [{"name": "Save the unsigned release binaries",
                           "status": "completed", "conclusion": "success",
                           "started_at": "2026-11-02T10:00:00Z",
                           "completed_at": "2026-11-02T10:00:02Z"}]}

    def resolve(self, numbers=(1, 2), event_attempt=None, artifacts=None, jobs=None,
                source_overrides=None, current=None):
        base = "repos/owner/app/actions/runs/12"
        def api(endpoint):
            if endpoint == base:
                return self.run if current is None else current
            number = int(endpoint.rsplit("/", 1)[1])
            return {**self.run, "run_attempt": number,
                    "conclusion": "failure" if number == 1 else "success",
                    **(source_overrides or {})}
        def listing(endpoint, key):
            if key == "artifacts":
                return [self.artifact(n) for n in numbers] if artifacts is None else artifacts
            number = int(endpoint.split("/")[-2])
            return [self.job(number)] if jobs is None else jobs
        with patch.object(MODULE, "api", side_effect=api), patch.object(
                MODULE, "api_list", side_effect=listing):
            return MODULE.resolve_artifact(self.run, "owner/app", self.commit, "12", event_attempt)

    def test_latest_artifact_is_preferred(self):
        result = self.resolve()
        self.assertEqual(result["artifact_attempt"], "2")
        self.assertEqual(result["artifact_id"], "102")
        self.assertEqual(result["artifact_name"], self.artifact(2)["name"])

    def test_partial_rerun_uses_earlier_successful_job_for_both_entry_paths(self):
        for event_attempt in (None, "2"):
            with self.subTest(event_attempt=event_attempt):
                result = self.resolve(numbers=(1,), event_attempt=event_attempt)
                self.assertEqual(result["run_attempt"], "2")
                self.assertEqual(result["artifact_attempt"], "1")
                self.assertEqual(result["artifact_id"], "101")

    def test_failed_earlier_release_job_is_rejected(self):
        for conclusion in ("failure", "cancelled", "skipped", None):
            with self.subTest(conclusion=conclusion), self.assertRaises(ValueError):
                self.resolve(numbers=(1,), jobs=[{**self.job(1), "conclusion": conclusion}])

    def test_ineligible_run_never_queries_artifacts(self):
        for field, value in (("head_sha", "b" * 40), ("event", "pull_request"),
                             ("repository", {"full_name": "foreign/app"}),
                             ("head_repository", {"full_name": "foreign/app"})):
            with self.subTest(field=field), patch.object(MODULE, "api_list") as listing:
                with self.assertRaises(ValueError):
                    MODULE.resolve_artifact({**self.run, field: value}, "owner/app", self.commit, "12")
                listing.assert_not_called()

    def test_artifact_identity_and_future_attempt_are_rejected(self):
        for key, value in (("id", 13), ("head_sha", "b" * 40),
                           ("head_branch", "feature"), ("repository_id", 100),
                           ("head_repository_id", 100)):
            item = self.artifact(1)
            item["workflow_run"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.resolve(artifacts=[item])
        for item in (self.artifact(3), {**self.artifact(1), "name": f"apassy-release-{'b' * 40}-1"}):
            with self.assertRaises(ValueError):
                self.resolve(artifacts=[item])

    def test_duplicate_artifacts_and_jobs_fail_closed(self):
        with self.assertRaises(ValueError):
            self.resolve(artifacts=[self.artifact(1), {**self.artifact(1), "id": 999}])
        for jobs in ([], [self.job(1), self.job(1)]):
            with self.subTest(jobs=jobs), self.assertRaises(ValueError):
                self.resolve(numbers=(1,), jobs=jobs)

    def test_job_and_attempt_identity_must_match(self):
        for key, value in (("run_id", 13), ("run_attempt", 2), ("head_sha", "b" * 40)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.resolve(numbers=(1,), jobs=[{**self.job(1), key: value}])
        with self.assertRaises(ValueError):
            self.resolve(numbers=(1,), source_overrides={"head_sha": "b" * 40})

    def test_upload_step_and_creation_time_are_bound(self):
        for field, value in (("steps", []), ("steps", self.job(1)["steps"] * 2)):
            with self.assertRaises(ValueError):
                self.resolve(numbers=(1,), jobs=[{**self.job(1), field: value}])
        job = copy.deepcopy(self.job(1))
        job["steps"][0]["conclusion"] = "failure"
        with self.assertRaises(ValueError):
            self.resolve(numbers=(1,), jobs=[job])
        with self.assertRaises(ValueError):
            self.resolve(artifacts=[{**self.artifact(1), "created_at": "2026-11-02T11:00:00Z"}])

    def test_missing_and_expired_artifacts_are_rejected(self):
        for items in ([], [{**self.artifact(1), "expired": True}]):
            with self.assertRaises(ValueError):
                self.resolve(artifacts=items)

    def test_concurrent_rerun_invalidates_selection(self):
        for changes in ({"run_attempt": 3}, {"status": "in_progress"}, {"conclusion": "failure"}):
            with self.assertRaises(ValueError):
                self.resolve(current={**self.run, **changes})

    def test_paginated_api_lists_are_complete_and_unambiguous(self):
        pages = [{"total_count": 2, "artifacts": [{"id": 1}]},
                 {"total_count": 2, "artifacts": [{"id": 2}]}]
        with patch.object(MODULE.subprocess, "check_output", return_value=json.dumps(pages)) as command:
            self.assertEqual(MODULE.api_list("endpoint", "artifacts"), [{"id": 1}, {"id": 2}])
            self.assertEqual(command.call_args.args[0],
                             ["gh", "api", "--paginate", "--slurp", "endpoint?per_page=100"])
        for invalid in (pages[:1], [pages[0], pages[0]], [],
                        [{"total_count": 1, "artifacts": []}]):
            with patch.object(MODULE.subprocess, "check_output", return_value=json.dumps(invalid)):
                with self.assertRaises(ValueError):
                    MODULE.api_list("endpoint", "artifacts")

    def test_cli_exports_resolved_attempt_for_both_entry_paths(self):
        for event_args in ([], ["--run-attempt", "2"]):
            with self.subTest(event_args=event_args), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "output"
                selected = {"run_id": "12", "run_attempt": "2", "artifact_attempt": "1",
                            "artifact_id": "101", "artifact_name": self.artifact(1)["name"]}
                args = ["ci-release-run.py", "--repository", "owner/app", "--commit", self.commit,
                        "--run-id", "12", "--github-output", str(output), *event_args]
                with patch("sys.argv", args), patch.object(MODULE, "api", return_value=self.run), patch.object(
                        MODULE, "resolve_artifact", return_value=selected) as resolve, patch("builtins.print"):
                    MODULE.main()
                self.assertEqual(resolve.call_args.args[-1], "2" if event_args else None)
                self.assertEqual(dict(line.split("=", 1) for line in output.read_text().splitlines()), selected)

    def test_api_errors_write_no_outputs(self):
        for error in (subprocess.CalledProcessError(1, "gh"), ValueError("invalid JSON"),
                      KeyError("missing API field")):
            with self.subTest(error=error), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "output"
                args = ["ci-release-run.py", "--repository", "owner/app", "--commit", self.commit,
                        "--run-id", "12", "--github-output", str(output)]
                with patch("sys.argv", args), patch.object(MODULE, "api", return_value=self.run), patch.object(
                        MODULE, "api_list", side_effect=error):
                    with self.assertRaises(SystemExit) as result:
                        MODULE.main()
                self.assertEqual(result.exception.code, 1)
                self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
