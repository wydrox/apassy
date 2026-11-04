"""Opt-in tokenizer-only tests. No encoder instantiation, weights or held-out IO.

Set APASSY_CONTEXT_TOKENIZER_BASE to an isolated public base snapshot directory.
The test reads its tokenizer/config only; absent optional dependencies are SKIP.
"""
import importlib.util
import os
from pathlib import Path
import sys
import unittest
import types
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools/basemodel'))
import context_v1 as C


class ExactInputSafety(unittest.TestCase):
    def test_score_outage_and_exact_overflow_have_distinct_status(self):
        import contextlib
        import context_train as T
        scorer = object.__new__(T.Scorer)
        scorer.model = types.SimpleNamespace(eval=lambda: None)
        scorer.torch = types.SimpleNamespace(no_grad=contextlib.nullcontext)
        scorer.pad = 0
        row = {'local_rule': None}
        with patch.dict(sys.modules, {'train': types.SimpleNamespace(collate=lambda *args: {})}):
            scorer.item = lambda *args: {}
            def outage(*args):
                raise RuntimeError('synthetic encoder outage')
            scorer.features = outage
            self.assertEqual(scorer.scores([row], facts_blind=True), [None])
            self.assertEqual(scorer.last_overflow, [False])
            self.assertEqual(scorer.last_refusals, [None])
            def overflow(*args):
                raise C.Refusal('ExactOverflow')
            scorer.item = overflow
            self.assertEqual(scorer.scores([row], facts_blind=True), [None])
            self.assertEqual(scorer.last_overflow, [True])
            self.assertEqual(scorer.last_refusals, ['ExactOverflow'])

    def test_control_bypasses_only_bound_and_rejects_exact_overflow_and_truncation(self):
        import context_train as T
        import context_data as D
        c = C.load_contract()
        class Tokenizer:
            mask_token = '<mask>'
            count = 469
            def __call__(self, text, **kwargs):
                return {'input_ids': [1] * self.count}
        tok = Tokenizer()
        agent = types.SimpleNamespace(tok=tok)
        agent._encode_state = lambda *args: [dict(ids=[1] * (tok.count + 43), markers=[0, 1], qtype=0)]
        scorer = object.__new__(T.Scorer)
        scorer.c, scorer.agent, scorer.question, scorer.cache_pins = c, agent, {}, {}
        row = dict(request=dict(user_request='x' * 1000, command='inspect', purpose=''),
                   action='read', secrets=[D.default_secret()], label='allow_ok')
        with patch.dict(sys.modules, {'laya.common': types.SimpleNamespace(serialize_state=lambda x: x)}):
            with self.assertRaisesRegex(C.Refusal, 'OverBudget'):
                scorer.item(row)
            accepted = scorer.item(row, facts_blind=True)
            self.assertEqual(len(accepted['ids']), 512)
            # Labels cannot change feature identities.
            row['label'] = 'must_ask'
            self.assertEqual(accepted['cache_key'], scorer.item(row, facts_blind=True)['cache_key'])
            scorer.cache_pins = {'base': 'different-pin'}
            self.assertNotEqual(accepted['cache_key'], scorer.item(row, facts_blind=True)['cache_key'])
            tok.count = 470
            with self.assertRaisesRegex(C.Refusal, 'ExactOverflow'):
                scorer.item(row, facts_blind=True)
            tok.count = 469
            agent._encode_state = lambda *args: [dict(ids=[1] * 511, markers=[0, 1], qtype=0)]
            with self.assertRaisesRegex(C.Unsupported, 'truncation'):
                scorer.item(row, facts_blind=True)


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
