"""Exercise identity and failure boundaries with inert tools, never Cargo/Xcode."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class MacQualityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'scripts').mkdir()
        shutil.copy2(ROOT / 'scripts/ci-macos-quality.sh', self.root / 'scripts')
        helper = self.root / 'native/ApassyHelper'
        helper.mkdir(parents=True)
        (helper / 'Fixture.swift').write_text('// fixture\n')
        for args in [('init', '-q'), ('add', '.'), ('-c', 'user.name=Fixture', '-c',
                     'user.email=fixture@example.invalid', 'commit', '-qm', 'fixture')]:
            subprocess.run(['git', *args], cwd=self.root, check=True, capture_output=True)
        self.sha = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=self.root, text=True).strip()
        boundary = self.root / 'tests/isolation/test_fixture_boundary.py'
        boundary.parent.mkdir(parents=True)
        boundary.write_text('# inert boundary-script stand-in\n')
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        for name in ['cargo', 'rustc', 'rustfmt', 'rustup', 'xcrun', 'xcode-select', 'xcodebuild', 'curl']:
            tool = self.bin / name
            tool.write_text('''#!/bin/bash
printf '%s %s\\n' "${0##*/}" "$*" >> "$CALLS"
if [[ "${0##*/} $*" == *"${FAIL_MATCH:-never-match}"* ]]; then exit 23; fi
printf 'fixture-tool-version\\n'
''')
            tool.chmod(0o755)
        self.env = dict(os.environ, PATH=f'{self.bin}:{os.environ["PATH"]}',
                        CALLS=str(self.root / 'calls'), APASSY_CI_EXPECTED_SHA=self.sha,
                        APASSY_CI_RECEIPT=str(self.root / 'receipt.json'))

    def run_helper(self, arguments=(), **changes):
        result = subprocess.run(['bash', 'scripts/ci-macos-quality.sh', *arguments], cwd=self.root,
                                env=dict(self.env, **changes), capture_output=True, text=True, timeout=15)
        receipt = json.loads((self.root / 'receipt.json').read_text())
        self.assertLess(len(json.dumps(receipt).encode()), 24576)
        self.assertIn('APASSY_CI_RECEIPT_JSON=', result.stdout)
        return result, receipt

    def test_missing_short_or_mismatched_sha_refuses_all_tooling(self):
        for sha in ['', self.sha[:12], 'f' * 40]:
            with self.subTest(sha=sha):
                result, receipt = self.run_helper(APASSY_CI_EXPECTED_SHA=sha)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(receipt['actual_sha'], self.sha)
                self.assertFalse((self.root / 'calls').exists())

    def test_cloud_missing_identity_refuses_bootstrap(self):
        result, receipt = self.run_helper(arguments=('--cloud',), APASSY_CI_EXPECTED_SHA='')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(receipt['actual_sha'], self.sha)
        self.assertFalse((self.root / 'calls').exists())

    def test_modified_tracked_source_refused_before_tooling(self):
        (self.root / 'native/ApassyHelper/Fixture.swift').write_text('// changed\n')
        result, _ = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'calls').exists())

    def test_matching_source_runs_complete_quality_contract(self):
        result, receipt = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(receipt['exit_status'], 0)
        calls = (self.root / 'calls').read_text().splitlines()
        quality = calls[calls.index('cargo +1.97.0 fetch --locked'):]
        self.assertEqual(quality, [
            'cargo +1.97.0 fetch --locked',
            'xcrun --sdk macosx swiftc -typecheck -swift-version 5 -warnings-as-errors native/ApassyHelper/Fixture.swift',
            'cargo +1.97.0 clippy --offline --locked --all-features --all-targets -- -D warnings',
            'cargo +1.97.0 check --offline --locked --features desktop --bin apassy',
            'cargo +1.97.0 clippy --offline --locked -p apassy-app --all-targets -- -D warnings',
            'cargo +1.97.0 test --offline --locked --features vault --doc',
            'rustup target add --toolchain 1.97.0 aarch64-apple-watchos aarch64-apple-watchos-sim',
            'cargo +1.97.0 check --offline --locked -p apassy-core --no-default-features --target aarch64-apple-watchos-sim',
        ])
        self.assertEqual(receipt['steps'][-1]['name'], 'fixture-boundary')
        self.assertTrue(all(step['exit_status'] == 0 for step in receipt['steps']))
        self.assertTrue(all(step['seconds'] >= 0 for step in receipt['steps']))

    def test_failure_preserves_status_and_stops_later_checks(self):
        result, receipt = self.run_helper(FAIL_MATCH='clippy --offline --locked --all-features')
        self.assertEqual(result.returncode, 23)
        self.assertEqual(receipt['exit_status'], 23)
        self.assertEqual(receipt['steps'][-1]['name'], 'clippy-full')
        self.assertEqual(receipt['steps'][-1]['exit_status'], 23)
        self.assertNotIn('watch-targets', [s['name'] for s in receipt['steps']])

    def test_cloud_hook_rejects_wrong_project_or_action(self):
        hook = ROOT / 'native/ApassyCIPilot/ci_scripts/ci_pre_xcodebuild.sh'
        for action, project in [('archive', str(ROOT / 'native/ApassyCIPilot/ApassyCIPilot.xcodeproj')),
                                ('build', str(ROOT / 'ios/ApassyCompanion/ApassyCompanion.xcodeproj'))]:
            result = subprocess.run(['bash', str(hook)], capture_output=True, text=True,
                                    env=dict(self.env, CI_WORKFLOW='Apassy macOS quality pilot',
                                             CI_PRIMARY_REPOSITORY_PATH=str(ROOT),
                                             CI_XCODEBUILD_ACTION=action, CI_PROJECT_FILE_PATH=project))
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((self.root / 'calls').exists())


if __name__ == '__main__':
    unittest.main()
