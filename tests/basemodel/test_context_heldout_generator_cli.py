"""Closed CLI errors only; no H2 row parsing or candidate access."""
import hashlib
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
GENERATOR = ROOT / 'tests/evals/secret_context_heldout_v2.py'
FIXTURES = (
    ROOT / 'tests/evals/secret-context-heldout-v2.jsonl',
    ROOT / 'tests/evals/secret-context-heldout-v2.manifest.json',
)
ERROR = 'H2 generation failed: invalid arguments.\n'
CANARY = 'PRIVATE_ARGUMENT_CANARY_7ce12d'


class GeneratorCLI(unittest.TestCase):
    def invoke(self, *args):
        before = [hashlib.sha256(p.read_bytes()).digest() for p in FIXTURES]
        result = subprocess.run(
            [sys.executable, '-I', '-B', str(GENERATOR), *args],
            cwd=ROOT, capture_output=True, text=True, timeout=10)
        self.assertEqual(before, [hashlib.sha256(p.read_bytes()).digest()
                                  for p in FIXTURES])
        return result

    def test_argument_errors_have_fixed_output(self):
        for args in ((), ('--check', CANARY), ('--write', '--check'),
                     ('--check=' + CANARY,), ('--' + CANARY,)):
            with self.subTest(args=args):
                result = self.invoke(*args)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, '')
                self.assertEqual(result.stderr, ERROR)
                self.assertNotIn(CANARY, result.stdout + result.stderr)

    def test_help_is_fixed_and_read_only(self):
        result = self.invoke('--help')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, '')
        self.assertTrue(result.stdout.startswith(
            'usage: secret_context_heldout_v2.py '))
        self.assertNotIn(str(ROOT), result.stdout)


if __name__ == '__main__':
    unittest.main()
