import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/check-release-versions.py"
SPEC = importlib.util.spec_from_file_location("release_versions", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
RELAY = "crates/apassy-relay"
APP = "crates/apassy-app"


class ReleaseVersionsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "app"
        self.version = json.loads((ROOT / "release-versions.json").read_text())["version"]
        for relative in (
            "release-versions.json", "Cargo.toml", "Cargo.lock", "ios/ApassyCore/Cargo.toml",
            "ios/ApassyCompanion/project.yml", "extension/manifest.json", "CHANGELOG.md",
            "site/src/lib/site.ts", f"{RELAY}/Cargo.toml", f"{RELAY}/deploy/worker/package.json",
            f"{RELAY}/deploy/push-gateway/package.json", f"{APP}/Cargo.toml", "packaging/linux/build.sh", "packaging/linux/deb/control.in",
        ):
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, destination)

    def test_all_six_matching_pass(self):
        self.assertEqual(MODULE.check(self.root), (self.version, []))

    def test_each_component_drift_is_rejected(self):
        for relative, field in (
            ("Cargo.toml", f'version = "{self.version}"'),
            ("Cargo.lock", f'name = "apassy"\nversion = "{self.version}"'),
            ("Cargo.lock", f'name = "apassy-relay"\nversion = "{self.version}"'),
            ("ios/ApassyCore/Cargo.toml", f'version = "{self.version}"'),
            ("ios/ApassyCompanion/project.yml", f'MARKETING_VERSION: {self.version}'),
            ("extension/manifest.json", f'"version": "{self.version}"'),
            ("CHANGELOG.md", f'## [{self.version}]'),
            (f"{RELAY}/Cargo.toml", f'version = "{self.version}"'),
            (f"{RELAY}/deploy/worker/package.json", f'"version": "{self.version}"'),
            (f"{RELAY}/deploy/push-gateway/package.json", f'"version": "{self.version}"'),
            (f"{APP}/Cargo.toml", f'version = "{self.version}"'),
            ("Cargo.lock", f'name = "apassy-app"\nversion = "{self.version}"'),
        ):
            with self.subTest(file=relative, field=field.splitlines()[0]):
                path = self.root / relative
                original = path.read_text()
                self.assertIn(field, original)
                path.write_text(original.replace(field, field.replace(self.version, "99.0.0"), 1))
                self.assertTrue(MODULE.check(self.root)[1])
                path.write_text(original)

    def test_missing_linux_binary_is_rejected(self):
        path = self.root / RELAY / "Cargo.toml"
        original = path.read_text()
        self.assertIn('name = "apassy-team"', original)
        path.write_text(original.replace('name = "apassy-team"', 'name = "apassy-other"', 1))
        self.assertIn("Linux", " ".join(MODULE.check(self.root)[1]))

    def test_the_linux_node_package_is_checked(self):
        for relative, old, new in (
            (f"{APP}/Cargo.toml", "\nnode = []", "\nnode-less = []"),
            (f"{APP}/Cargo.toml", 'default = ["window", "node"]', 'default = ["window"]'),
            (f"{APP}/Cargo.toml", 'name = "apassy-app"', 'name = "apassy-other"'),
            ("packaging/linux/deb/control.in", "Version: @VERSION@", f"Version: {self.version}"),
            ("packaging/linux/build.sh", "crates/apassy-relay/Cargo.toml", "Cargo.toml"),
        ):
            with self.subTest(file=relative, old=old):
                path = self.root / relative
                original = path.read_text()
                self.assertIn(old, original)
                path.write_text(original.replace(old, new))
                self.assertTrue(MODULE.check(self.root)[1])
                path.write_text(original)

    def test_old_relay_checkout_flag_fails_clearly(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--root", str(self.root), "--relay-checkout", "x"],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("crates/apassy-relay", result.stderr)

    def test_website_cannot_replace_derived_version_with_static_text(self):
        (self.root / "site/src/lib/site.ts").write_text(f'export const VERSION = "{self.version}";\n')
        with self.assertRaisesRegex(ValueError, "website VERSION"):
            MODULE.check(self.root)

    def test_manifest_cannot_omit_a_component(self):
        path = self.root / "release-versions.json"
        manifest = json.loads(path.read_text())
        manifest["components"].remove("linux-cli")
        path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "six components"):
            MODULE.check(self.root)

    def test_build_number_and_unreleased_entries_are_not_version_drift(self):
        path = self.root / "ios/ApassyCompanion/project.yml"
        path.write_text(path.read_text().replace("CURRENT_PROJECT_VERSION: 1", "CURRENT_PROJECT_VERSION: 999"))
        path = self.root / "CHANGELOG.md"
        path.write_text(path.read_text().replace("## [Unreleased]", "## [Unreleased]\n\n- Work in progress."))
        self.assertEqual(MODULE.check(self.root)[1], [])


class ReleaseTagTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.git("init", "--quiet")
        self.git("-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                 "commit", "--quiet", "--allow-empty", "-m", "fixture")

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.root, check=True,
                              capture_output=True, text=True)

    def test_above_equal_and_below_latest_tag(self):
        # SemVer order differs from a plain string sort (10 sorts above 9).
        for tag in ("v0.5.9", "v0.5.10", "image-release-99.0.0"):
            self.git("tag", tag)
        self.assertEqual(MODULE.release_errors(self.root, "0.5.11"), [])
        for version in ("0.5.10", "0.5.9"):
            with self.subTest(version=version):
                errors = MODULE.release_errors(self.root, version)
                self.assertIn("latest tag v0.5.10", errors[0])

    def test_prerelease_ordering(self):
        ordered = ("1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta",
                   "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11",
                   "1.0.0-rc.1", "1.0.0")
        for index, version in enumerate(ordered):
            self.git("tag", "v" + version)
            self.assertTrue(MODULE.release_errors(self.root, version))
            if index:
                self.assertTrue(MODULE.release_errors(self.root, ordered[index - 1]))
            if index + 1 < len(ordered):
                self.assertEqual(MODULE.release_errors(self.root, ordered[index + 1]), [])

    def test_build_metadata_does_not_make_a_new_release(self):
        self.git("tag", "v1.0.0+build.1")
        self.assertTrue(MODULE.release_errors(self.root, "1.0.0+build.2"))

    def test_first_release_without_tags(self):
        self.assertEqual(MODULE.release_errors(self.root, "0.1.0"), [])

    def test_malformed_release_tag_fails_closed(self):
        self.git("tag", "v1.0.0-01")
        with self.assertRaisesRegex(ValueError, "numeric prerelease"):
            MODULE.release_errors(self.root, "2.0.0")

    def test_release_cli_rejects_equal_version_but_default_is_unchanged(self):
        self.git("tag", "v" + json.loads((ROOT / "release-versions.json").read_text())["version"])
        from unittest.mock import patch
        # Keep source consistency checks independent of the temporary tag repository.
        with patch.object(MODULE, "check", return_value=(
            json.loads((ROOT / "release-versions.json").read_text())["version"], []
        )):
            with patch.object(sys, "argv", [str(SCRIPT), "--root", str(self.root)]):
                self.assertEqual(MODULE.main(), 0)
            with patch.object(sys, "argv", [str(SCRIPT), "--root", str(self.root), "--release"]):
                self.assertEqual(MODULE.main(), 1)


if __name__ == "__main__":
    unittest.main()
