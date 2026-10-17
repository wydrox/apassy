import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("release_versions", ROOT / "scripts/check-release-versions.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ReleaseVersionsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "app"
        self.version = json.loads((ROOT / "release-versions.json").read_text())["version"]
        for relative in (
            "release-versions.json", "Cargo.toml", "Cargo.lock", "ios/ApassyCore/Cargo.toml",
            "ios/ApassyCompanion/project.yml", "extension/manifest.json", "CHANGELOG.md",
            "site/src/lib/site.ts",
        ):
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, destination)
        self.relay = Path(self.temporary.name) / "relay"
        self.relay.mkdir()
        (self.relay / "Cargo.toml").write_text(
            f'[package]\nname = "apassy-relay"\nversion = "{self.version}"\n'
            '[[bin]]\nname = "apassy-relay"\n[[bin]]\nname = "apassy-team"\n'
        )
        (self.relay / "Cargo.lock").write_text(
            f'[[package]]\nname = "apassy-relay"\nversion = "{self.version}"\n'
        )

    def test_all_six_matching_and_required_relay_pass(self):
        self.assertEqual(MODULE.check(self.root, self.relay, True), (self.version, []))

    def test_each_local_component_drift_is_rejected(self):
        for relative, field in (
            ("Cargo.toml", f'version = "{self.version}"'),
            ("Cargo.lock", f'version = "{self.version}"'),
            ("ios/ApassyCore/Cargo.toml", f'version = "{self.version}"'),
            ("ios/ApassyCompanion/project.yml", f'MARKETING_VERSION: {self.version}'),
            ("extension/manifest.json", f'"version": "{self.version}"'),
            ("CHANGELOG.md", f'## [{self.version}]'),
        ):
            with self.subTest(file=relative):
                path = self.root / relative
                original = path.read_text()
                self.assertIn(field, original)
                path.write_text(original.replace(field, field.replace(self.version, "99.0.0"), 1))
                self.assertTrue(MODULE.check(self.root, self.relay, True)[1])
                path.write_text(original)

    def test_relay_manifest_and_lock_drift_each_fail(self):
        for filename in ("Cargo.toml", "Cargo.lock"):
            with self.subTest(file=filename):
                path = self.relay / filename
                original = path.read_text()
                path.write_text(original.replace(self.version, "99.0.0"))
                self.assertTrue(MODULE.check(self.root, self.relay, True)[1])
                path.write_text(original)

    def test_missing_linux_binary_is_rejected(self):
        path = self.relay / "Cargo.toml"
        path.write_text(path.read_text().replace('[[bin]]\nname = "apassy-team"\n', ""))
        self.assertIn("Linux", " ".join(MODULE.check(self.root, self.relay, True)[1]))

    def test_required_external_checkout_cannot_silently_pass(self):
        self.assertEqual(MODULE.check(self.root)[1], [])
        self.assertIn("--relay-checkout", " ".join(MODULE.check(self.root, require_relay=True)[1]))

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
        self.assertEqual(MODULE.check(self.root, self.relay, True)[1], [])


if __name__ == "__main__":
    unittest.main()
