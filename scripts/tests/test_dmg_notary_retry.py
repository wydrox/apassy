"""Test real packaging retry functions with fake tools; no signing or DMG work."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "build-dmg.sh"
SOURCE = SCRIPT.read_text()
# Load only the actual retry definitions, without executing packaging preflight.
HELPERS = SOURCE.split("# Retry stapler operations.", 1)[1].split(
    "# ---------------------------------------------------------------- app", 1
)[0]
HELPERS = "# Retry stapler operations." + HELPERS


class DmgNotaryRetryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.log = self.root / "calls"
        self.sleep_log = self.root / "sleeps"
        self.env = dict(os.environ, PATH=f"{self.root}:{os.environ['PATH']}",
                        MOCK_ROOT=str(self.root), FAIL_STAPLE="0", FAIL_VALIDATE="0")
        self.tool("xcrun", """#!/bin/bash
set -euo pipefail
[ "$1" = stapler ]
operation="$2"
printf '%s|%s\\n' "$operation" "$3" >>"$MOCK_ROOT/calls"
counter="$MOCK_ROOT/$operation.count"
count=0
if [ -f "$counter" ]; then read -r count <"$counter"; fi
count=$((count + 1))
echo "$count" >"$counter"
case "$operation" in
  staple) failures="$FAIL_STAPLE" ;;
  validate) failures="$FAIL_VALIDATE" ;;
  *) exit 99 ;;
esac
if [ "$count" -le "$failures" ]; then
  echo 'CloudKit query failed: NSURLErrorDomain -1005 (error 68)' >&2
  exit 68
fi
""")
        self.tool("sleep", """#!/bin/bash
printf '%s\\n' "$1" >>"$MOCK_ROOT/sleeps"
""")

    def tool(self, name, contents):
        path = self.root / name
        path.write_text(contents)
        path.chmod(0o755)

    def run_retry(self, command, **failures):
        result = subprocess.run(
            ["bash", "-euo", "pipefail", "-c",
             'fail() { echo "FAILED: $*" >&2; exit 1; }\n' + HELPERS +
             '\n' + command + '\nprintf "gate-passed\\n"\n'],
            env=dict(self.env, **failures), capture_output=True, text=True,
            timeout=5,
        )
        calls = self.log.read_text().splitlines() if self.log.exists() else []
        waits = self.sleep_log.read_text().splitlines() if self.sleep_log.exists() else []
        return result, calls, waits

    def test_transient_validation_retries_without_restapling(self):
        result, calls, waits = self.run_retry('staple "Apassy fixture.app"', FAIL_VALIDATE="2")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, ["staple|Apassy fixture.app"] + ["validate|Apassy fixture.app"] * 3)
        self.assertEqual(waits, ["15", "30"])
        self.assertIn("gate-passed", result.stdout)

    def test_transient_stapling_retries_then_requires_validation(self):
        result, calls, waits = self.run_retry('staple "fixture.dmg"', FAIL_STAPLE="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, ["staple|fixture.dmg"] * 2 + ["validate|fixture.dmg"])
        self.assertEqual(waits, ["15"])

    def test_persistent_validation_fails_closed_after_six_attempts(self):
        result, calls, waits = self.run_retry('staple "fixture.dmg"', FAIL_VALIDATE="99")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, ["staple|fixture.dmg"] + ["validate|fixture.dmg"] * 6)
        self.assertEqual(waits, ["15", "30", "60", "120", "240"])
        self.assertIn("stapler validate failed for fixture.dmg after 6 attempts", result.stderr)
        self.assertNotIn("gate-passed", result.stdout)

    def test_persistent_stapling_never_reaches_validation(self):
        result, calls, waits = self.run_retry('staple "fixture.dmg"', FAIL_STAPLE="99")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, ["staple|fixture.dmg"] * 6)
        self.assertEqual(len(waits), 5)
        self.assertNotIn("gate-passed", result.stdout)

    def test_mounted_copy_validation_uses_same_retry_gate(self):
        # Exercise the actual mounted-image command rather than another test-only call.
        command = next(line.strip() for line in SOURCE.splitlines()
                       if 'validate "$MOUNT/Apassy.app"' in line)
        result, calls, waits = self.run_retry(
            'MOUNT="mounted image"\n' + command, FAIL_VALIDATE="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, ["validate|mounted image/Apassy.app"] * 2)
        self.assertEqual(waits, ["15"])

    def test_mounted_copy_validation_persistent_failure_fails_closed(self):
        command = next(line.strip() for line in SOURCE.splitlines()
                       if 'validate "$MOUNT/Apassy.app"' in line)
        result, calls, waits = self.run_retry(
            'MOUNT="mounted image"\n' + command, FAIL_VALIDATE="99")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, ["validate|mounted image/Apassy.app"] * 6)
        self.assertEqual(len(waits), 5)
        self.assertNotIn("gate-passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
