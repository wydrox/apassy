import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "ci_release_ready", Path(__file__).resolve().parents[1] / "ci-release-ready.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

HEAD = "# Changelog\n\nIntro with ## [9.9.9] - 2026-01-01 inside a sentence.\n\n"
OLDER = "## [0.3.6] - 2026-10-09\n\n### Changed\n\n- A change.\n\n## [0.3.5] - 2026-10-09\n\n- Older.\n"


def cargo(version="0.3.6"):
    return f'[package]\nname = "apassy"\nversion = "{version}"\nedition = "2024"\n\n[dependencies]\nserde = {{ version = "1.0.0" }}\n'


def ok(changelog, version="0.3.6"):
    return MODULE.evaluate(cargo(version), changelog)[0]


class ReleaseReadyTests(unittest.TestCase):
    def test_empty_unreleased_and_matching_release_is_eligible(self):
        self.assertEqual(
            MODULE.evaluate(cargo(), HEAD + "## [Unreleased]\n\n" + OLDER)[:2], (True, "0.3.6")
        )

    def test_changelog_without_unreleased_section_is_eligible(self):
        self.assertTrue(ok(HEAD + OLDER))

    def test_filled_unreleased_is_not_eligible_even_when_release_matches(self):
        text = HEAD + "## [Unreleased]\n\n### Added\n\n- Pending.\n\n## [0.4.1] - 2026-10-11\n\n- Done.\n" + OLDER
        self.assertFalse(ok(text, "0.4.1"))
        self.assertIn("unreleased", MODULE.evaluate(cargo("0.4.1"), text)[2])

    def test_unreleased_text_without_a_list_is_not_empty(self):
        self.assertFalse(ok(HEAD + "## [Unreleased]\n\nTarget release 0.4.1.\n\n" + OLDER))

    def test_cargo_version_must_match_the_newest_release(self):
        text = HEAD + "## [Unreleased]\n\n" + OLDER
        self.assertFalse(ok(text, "0.4.1"))
        self.assertFalse(ok(text, "0.3.5"))
        self.assertFalse(ok("## [0.4.0] - 2026-10-10\n\n- New.\n\n" + OLDER, "0.3.6"))

    def test_changelog_without_a_release_is_not_eligible(self):
        self.assertFalse(ok(HEAD + "## [Unreleased]\n"))
        self.assertFalse(ok(HEAD))
        self.assertFalse(ok(""))

    def test_malformed_input_is_not_eligible(self):
        for text in (
            HEAD + "## [0.3.6]\n\n- No date.\n",
            HEAD + "## [0.3.6] - 2026-13-40\n",
            HEAD + "## [0.3.6] - 20261009\n",
            HEAD + "## [0.3.6] - 2026-10-09 [YANKED]\n",
            HEAD + "## 0.3.6 - 2026-10-09\n",
            HEAD + "## [Unreleased] - 2026-10-09\n",
            HEAD + "## [Unreleased]\n\n## [Unreleased]\n\n" + OLDER,
            HEAD + "## [latest] - 2026-10-09\n",
        ):
            with self.subTest(text=text):
                self.assertFalse(ok(text))
        for bad_cargo in ("", "[package]\nname = \"x\"\n", "[package]\nversion.workspace = true\n",
                          '[package]\nversion = "latest"\n', '[dependencies]\nversion = "0.3.6"\n'):
            with self.subTest(cargo=bad_cargo):
                self.assertFalse(MODULE.evaluate(bad_cargo, HEAD + OLDER)[0])

    def test_headings_in_code_fences_are_ignored(self):
        text = HEAD + "## [Unreleased]\n\n```\n## [0.9.9] - 2026-01-01\n```\n\n" + OLDER
        self.assertFalse(ok(text))  # the fenced lines are text, so Unreleased is not empty
        self.assertTrue(ok(HEAD + "## [Unreleased]\n\n" + OLDER))

    def run_cli(self, root, changelog):
        output = root / "output"
        output.write_text("", encoding="utf-8")
        result = subprocess.run(
            [sys.executable, "-I", SPEC.origin, "--cargo", str(root / "Cargo.toml"),
             "--changelog", str(changelog), "--github-output", str(output)],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return output.read_text(encoding="utf-8")

    def test_command_line_writes_outputs_and_never_fails_on_a_skip(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "Cargo.toml").write_text(cargo("0.4.1"), encoding="utf-8")
            changelog = root / "CHANGELOG.md"
            changelog.write_text(HEAD + "## [Unreleased]\n\n- Pending.\n\n" + OLDER, encoding="utf-8")
            self.assertEqual(self.run_cli(root, changelog), "production=false\nversion=0.4.1\n")
            self.assertEqual(self.run_cli(root, root / "missing.md"), "production=false\nversion=\n")
            changelog.write_text(HEAD + "## [Unreleased]\n\n## [0.4.1] - 2026-10-11\n\n- Done.\n", encoding="utf-8")
            self.assertEqual(self.run_cli(root, changelog), "production=true\nversion=0.4.1\n")


if __name__ == "__main__":
    unittest.main()
