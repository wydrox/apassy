import importlib.util
from pathlib import Path
import unittest


SPEC = importlib.util.spec_from_file_location(
    "ci_release_run", Path(__file__).resolve().parents[1] / "ci-release-run.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ReleaseRunTests(unittest.TestCase):
    def setUp(self):
        self.commit = "a" * 40
        self.run = {
            "id": 12, "run_attempt": 2, "repository": {"full_name": "owner/app"},
            "head_repository": {"full_name": "owner/app"},
            "path": ".github/workflows/ci.yml", "event": "push",
            "head_branch": "main", "head_sha": self.commit,
            "status": "completed", "conclusion": "success",
        }

    def check(self, run=None, attempt=None):
        return MODULE.validate_run(
            self.run if run is None else run, "owner/app", self.commit, "12", attempt
        )

    def test_exact_successful_main_ci_run_selects_its_artifact(self):
        self.assertEqual(self.check(), {
            "run_id": "12", "run_attempt": "2",
            "artifact_name": f"apassy-release-{self.commit}-2",
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


if __name__ == "__main__":
    unittest.main()
