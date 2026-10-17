"""Exercise the release packager with isolated copies, never the installed browser."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[2]


class ExtensionPackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        shutil.copytree(ROOT / "extension", self.root / "extension")
        (self.root / "scripts").mkdir()
        shutil.copy2(ROOT / "scripts/build-extension-zip.sh", self.root / "scripts")
        self.manifest_path = self.root / "extension/manifest.json"
        self.manifest = json.loads(self.manifest_path.read_text())
        self.version = self.manifest["version"]
        (self.root / "Cargo.toml").write_text(f'[package]\nversion = "{self.version}"\n')
        self.package = self.root / f"target/dist/apassy-extension-{self.version}.zip"

    def build(self):
        self.manifest_path.write_text(json.dumps(self.manifest))
        return subprocess.run(
            ["bash", "scripts/build-extension-zip.sh"], cwd=self.root,
            capture_output=True, text=True, check=False,
        )

    def assert_rejected(self, diagnostic):
        result = self.build()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(diagnostic, result.stderr)
        self.assertFalse(self.package.exists(), "invalid ZIP must not be published to target/dist")

    def test_current_contract_packages_current_bytes_without_key(self):
        result = self.build()
        self.assertEqual(result.returncode, 0, result.stderr)
        with zipfile.ZipFile(self.package) as archive:
            packaged = json.loads(archive.read("manifest.json"))
            expected = {key: value for key, value in self.manifest.items() if key != "key"}
            self.assertEqual(packaged, expected)
            source_files = {str(path.relative_to(self.root / "extension"))
                            for path in (self.root / "extension").rglob("*") if path.is_file()}
            self.assertEqual(set(archive.namelist()), source_files)
            for name in source_files - {"manifest.json"}:
                self.assertEqual(archive.read(name), (self.root / "extension" / name).read_bytes(), name)
        first = self.package.read_bytes()
        self.assertEqual(self.build().returncode, 0)
        self.assertEqual(self.package.read_bytes(), first, "same input must produce the same ZIP")
        self.assertIn("key", json.loads(self.manifest_path.read_text()), "source key must remain intact")

    def test_unexpected_required_permission_is_rejected(self):
        self.manifest["permissions"].append("tabs")
        self.assert_rejected("unexpected permissions")

    def test_missing_storage_permission_is_rejected(self):
        self.manifest["permissions"].remove("storage")
        self.assert_rejected("unexpected permissions")

    def test_broader_optional_host_permission_is_rejected(self):
        self.manifest["optional_host_permissions"].append("http://*/*")
        self.assert_rejected("unexpected optional host permissions")

    def test_implicit_host_access_and_optional_api_permissions_are_rejected(self):
        for field, value in {
            "host_permissions": ["https://*/*"],
            "content_scripts": [{"matches": ["https://*/*"], "js": ["login-target.js"]}],
            "externally_connectable": {"matches": ["https://*/*"]},
            "optional_permissions": ["tabs"],
        }.items():
            with self.subTest(field=field):
                self.manifest[field] = value
                self.assert_rejected(f"the store manifest has {field}")
                del self.manifest[field]

    def test_missing_login_helpers_are_rejected(self):
        for name in ("login-worker.js", "login-target.js", "login-suggestions.js"):
            with self.subTest(name=name):
                path = self.root / "extension" / name
                original = path.read_bytes()
                path.unlink()
                self.assert_rejected("unexpected archive files")
                path.write_bytes(original)

    def test_unexpected_private_file_is_rejected(self):
        (self.root / "extension/.env").write_text("PRIVATE_BUILD_VALUE=fixture\n")
        self.assert_rejected("unexpected archive files")

    def test_symlink_is_rejected(self):
        (self.root / "extension/linked.js").symlink_to("background.js")
        self.assert_rejected("symbolic link")

    def test_version_mismatch_is_rejected(self):
        self.manifest["version"] = "0.0.0"
        self.assert_rejected("Cargo.toml has")


if __name__ == "__main__":
    unittest.main()
