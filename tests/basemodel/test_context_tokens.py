"""Opt-in tokenizer-only tests. No encoder instantiation, weights or held-out IO.

Set APASSY_CONTEXT_TOKENIZER_BASE to an isolated public base snapshot directory.
The test reads its tokenizer/config only; absent optional dependencies are SKIP.
"""
import importlib.util
import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools/basemodel'))
import context_v1 as C


class TokenizerParity(unittest.TestCase):
    def test_pinned_tokenizer_additivity_and_full_bound_10000(self):
        base = os.environ.get('APASSY_CONTEXT_TOKENIZER_BASE')
        if not base:
            self.skipTest('APASSY_CONTEXT_TOKENIZER_BASE not explicitly provided')
        if not all(importlib.util.find_spec(m) for m in ('laya', 'transformers')):
            self.skipTest('optional Laya/transformers dependencies unavailable')
        c = C.load_contract()
        proposed, result = C.measure(base, c, fuzz=10000)
        self.assertEqual(result['fuzz_cases'], 10000)
        self.assertEqual(result['tokenizer_sha256'], C.TOKENIZER_SHA256)
        self.assertEqual(set(proposed['budget']['segment_tokens']), set(C.all_segments(c)))
        self.assertEqual(proposed['budget'], c['budget'])


if __name__ == '__main__':
    unittest.main()
