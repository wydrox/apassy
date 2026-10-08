#!/usr/bin/env python3
"""Tests use inert Mach-O fixtures. No release binary executes."""

import importlib.util
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "ci-release-artifact.py"
SPEC = importlib.util.spec_from_file_location("ci_release_artifact", SCRIPT)
artifact = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(artifact)

COMMIT = "a" * 40
DATE = "2026-10-08T10:20:30Z"
RUN_ID = "123456"
ATTEMPT = "2"


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.addCleanup(patch.stopall)
        patch.object(artifact, "ROOT", self.root).start()
        patch.object(artifact.platform, "system", return_value="Darwin").start()
        patch.object(artifact.platform, "machine", return_value="arm64").start()
        (self.root / "Cargo.toml").write_text('[package]\nversion = "0.3.4"\n')
        source = self.root / "target" / "release"
        source.mkdir(parents=True)
        header = bytes.fromhex("cffaedfe0c000001") + bytes(4) + bytes.fromhex("02000000") + bytes(16)
        for name in artifact.BINARIES:
            data = header + name.encode()
            if name == "apassy":
                data += COMMIT.encode() + DATE.encode()
            (source / name).write_bytes(data)
        self.directory = self.root / "download"
        artifact.create(self.directory, COMMIT, DATE, RUN_ID, ATTEMPT)
        for name in artifact.BINARIES:
            (self.directory / name).chmod(0o644)

    def verify(self, **overrides):
        args = {"directory": self.directory, "commit": COMMIT,
                "run_id": RUN_ID, "run_attempt": ATTEMPT}
        args.update(overrides)
        return artifact.verify(**args)

    def change_manifest(self, change):
        path = self.directory / artifact.MANIFEST
        data = json.loads(path.read_text())
        change(data)
        path.write_text(json.dumps(data))

    def assert_rejected_without_env(self, **overrides):
        env = self.root / "github-env"
        env.write_text("EXISTING=value\n")
        with self.assertRaises((ValueError, OSError)):
            self.verify(github_env=env, **overrides)
        self.assertEqual(env.read_text(), "EXISTING=value\n")
        for name in artifact.BINARIES:
            path = self.directory / name
            if path.is_file() and not path.is_symlink():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)

    def test_verified_download_exports_identity_and_restores_execute_permission(self):
        env = self.root / "github-env"
        manifest = self.verify(github_env=env, date=DATE)
        self.assertEqual(manifest["version"], "0.3.4")
        self.assertEqual(env.read_text().splitlines(), [
            f"APASSY_PREBUILT_DIR={self.directory}", f"APASSY_BUILD_COMMIT={COMMIT}",
            f"APASSY_BUILD_DATE={DATE}", f"APASSY_PREBUILT_RUN_ID={RUN_ID}",
            f"APASSY_PREBUILT_RUN_ATTEMPT={ATTEMPT}",
        ])
        for name in artifact.BINARIES:
            self.assertEqual(stat.S_IMODE((self.directory / name).stat().st_mode), 0o755)

    def test_tampered_binary_is_rejected(self):
        path = self.directory / "apassy-hook"
        path.write_bytes(path.read_bytes() + b"tampered")
        self.assert_rejected_without_env()

    def test_each_trusted_identity_mismatch_is_rejected(self):
        for overrides in ({"commit": "b" * 40}, {"run_id": "98765"},
                          {"run_attempt": "3"}, {"date": "2026-10-08T10:20:31Z"}):
            with self.subTest(overrides=overrides):
                self.assert_rejected_without_env(**overrides)

    def test_wrong_version_is_rejected(self):
        (self.root / "Cargo.toml").write_text('[package]\nversion = "0.3.5"\n')
        self.assert_rejected_without_env()

    def test_wrong_manifest_architecture_is_rejected(self):
        self.change_manifest(lambda data: data["platform"].update(architecture="x86_64"))
        self.assert_rejected_without_env()

    def test_wrong_binary_architecture_is_rejected_even_with_matching_hash(self):
        path = self.directory / "apassy-hook"
        data = path.read_bytes()
        data = data[:4] + bytes.fromhex("07000001") + data[8:]
        path.write_bytes(data)
        self.change_manifest(lambda manifest: manifest["files"]["apassy-hook"].update(
            sha256=artifact.hashlib.sha256(data).hexdigest()))
        self.assert_rejected_without_env()

    def test_manifest_file_path_is_not_accepted(self):
        self.change_manifest(lambda data: data["files"].update({"../apassy": data["files"].pop("apassy")}))
        self.assert_rejected_without_env()

    def test_missing_binary_is_rejected(self):
        (self.directory / "apassy-hook").unlink()
        self.assert_rejected_without_env()

    def test_browser_host_is_required(self):
        (self.directory / "apassy-browser-host").unlink()
        self.assert_rejected_without_env()

    def test_tampered_browser_host_is_rejected(self):
        path = self.directory / "apassy-browser-host"
        path.write_bytes(path.read_bytes() + b"tampered")
        self.assert_rejected_without_env()

    def test_extra_executable_is_rejected(self):
        (self.directory / "surprise").write_bytes(b"do not execute")
        self.assert_rejected_without_env()

    def test_directory_symlink_is_rejected(self):
        link = self.root / "link"
        link.symlink_to(self.directory, target_is_directory=True)
        self.assert_rejected_without_env(directory=link)

    def test_manifest_and_binary_symlinks_are_rejected(self):
        for name in ("apassy-hook", artifact.MANIFEST):
            with self.subTest(name=name):
                path = self.directory / name
                data = path.read_bytes()
                destination = self.root / f"outside-{name}"
                destination.write_bytes(data)
                path.unlink()
                path.symlink_to(destination)
                self.assert_rejected_without_env()
                path.unlink()
                path.write_bytes(data)
                path.chmod(0o644)

    def test_hard_link_is_rejected(self):
        path = self.directory / "apassy-hook"
        artifact.os.link(path, self.root / "hard-link")
        self.assert_rejected_without_env()

    def test_fifo_is_rejected_without_a_blocking_read(self):
        path = self.directory / "apassy-hook"
        path.unlink()
        artifact.os.mkfifo(path)
        self.assert_rejected_without_env()

    def test_oversized_manifest_is_rejected(self):
        (self.directory / artifact.MANIFEST).write_text(" " * 16385)
        self.assert_rejected_without_env()

    def test_date_and_identity_env_injection_are_rejected(self):
        for key, value in (("date", DATE + "\nINJECTED=1"),
                           ("commit", COMMIT + "\nINJECTED=1"),
                           ("run_id", RUN_ID + "\nINJECTED=1"),
                           ("run_attempt", ATTEMPT + "\nINJECTED=1")):
            with self.subTest(key=key):
                self.assert_rejected_without_env(**{key: value})

    def test_manifest_env_injection_is_rejected(self):
        self.change_manifest(lambda data: data.update(date=DATE + "\nINJECTED=1"))
        self.assert_rejected_without_env()

    def test_directory_env_injection_is_rejected(self):
        destination = self.root / "download\nINJECTED=1"
        self.directory.rename(destination)
        self.directory = destination
        self.assert_rejected_without_env()

    def test_invalid_calendar_date_is_rejected(self):
        self.change_manifest(lambda data: data.update(date="2026-02-30T10:20:30Z"))
        self.assert_rejected_without_env()

    def test_duplicate_manifest_fields_are_rejected(self):
        path = self.directory / artifact.MANIFEST
        path.write_text(path.read_text().replace('"schema": 1', '"schema": 1, "schema": 1'))
        self.assert_rejected_without_env()

    def test_invalid_metadata_type_is_rejected(self):
        self.change_manifest(lambda data: data["files"]["apassy-hook"].update(size=True))
        self.assert_rejected_without_env()

    def test_changed_embedded_identity_is_rejected_with_matching_hash(self):
        path = self.directory / "apassy"
        data = path.read_bytes().replace(COMMIT.encode(), b"b" * 40)
        path.write_bytes(data)
        self.change_manifest(lambda manifest: manifest["files"]["apassy"].update(
            sha256=artifact.hashlib.sha256(data).hexdigest()))
        self.assert_rejected_without_env()

    def test_env_file_symlink_is_rejected_before_permissions_change(self):
        destination = self.root / "outside-env"
        destination.write_text("UNCHANGED=1\n")
        env = self.root / "github-env"
        env.symlink_to(destination)
        with self.assertRaises(ValueError):
            self.verify(github_env=env)
        self.assertEqual(destination.read_text(), "UNCHANGED=1\n")
        self.assertEqual(stat.S_IMODE((self.directory / "apassy").stat().st_mode), 0o644)

    def test_env_directory_is_rejected_before_permissions_change(self):
        env = self.root / "env-directory"
        env.mkdir()
        with self.assertRaises(OSError):
            self.verify(github_env=env)
        self.assertEqual(stat.S_IMODE((self.directory / "apassy").stat().st_mode), 0o644)

    def test_create_refuses_a_nonempty_output_directory(self):
        with self.assertRaises(ValueError):
            artifact.create(self.directory, COMMIT, DATE, RUN_ID, ATTEMPT)

    def test_create_rejects_a_build_with_another_embedded_date(self):
        with self.assertRaises(ValueError):
            artifact.create(self.root / "new-output", COMMIT, "2026-10-08T10:20:31Z", RUN_ID, ATTEMPT)
        self.assertFalse((self.root / "new-output").exists())

    def test_nonmacos_host_is_rejected(self):
        with patch.object(artifact.platform, "system", return_value="Linux"):
            self.assert_rejected_without_env()


if __name__ == "__main__":
    unittest.main()
