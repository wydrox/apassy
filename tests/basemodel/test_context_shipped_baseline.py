"""Synthetic scorer/replay only: no checkpoint, tokenizer, or held-out corpus."""
from contextlib import ExitStack
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools/basemodel'))
import context_train as T
import context_eval as E
import context_replay as R
import context_train_rows as TR
from test_context_v1 import evidence


class ShippedBaselineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.heads = self.directory / 'synthetic-heads'
        self.heads.write_bytes(b'fake heads, never loaded')
        self.data = self.directory / 'synthetic-data'
        self.data.write_bytes(b'fake rows')
        self.manifest = self.directory / 'synthetic-manifest'
        self.manifest.write_text(json.dumps({'sha256': T.sha256(self.data)}))
        self.rows, self.scores, self.control, self.reinforced, _, _ = evidence()
        self.c = T.load_contract()
        self.frozen = dict(config={'threads': 1}, threshold=.5, control_threshold=.5000000000000001,
                           base={'weights_sha256': 'fake'}, train={'path': 'train'}, val={'path': 'val'},
                           context={'path': 'context'}, control={'path': 'control'})

    def evaluate(self, replay=None, fail=False, binary='fake-binary', explicit=True, lower_error=False):
        scores = self.scores[:]
        if fail:
            scores[300] = .9
        scorer = SimpleNamespace(model=object(), scores=Mock(side_effect=[scores, self.reinforced, self.control]),
                                 last_overflow=[False] * len(self.rows))
        common = SimpleNamespace(load_checkpoint=Mock(return_value=({}, {})), apply_heads=Mock())
        actual_hash = T.sha256
        with ExitStack() as stack:
            for name, value in [('verify_freeze', self.frozen), ('environment', ({'base': self.frozen['base']}, {})),
                                ('context_meta_ok', True), ('heldout_overlap', {}), ('FeatureCache', Mock()),
                                ('Scorer', scorer)]:
                stack.enter_context(patch.object(T, name, return_value=value))
            stack.enter_context(patch.dict(sys.modules, {'common': common}))
            stack.enter_context(patch.object(T, 'read_rows', side_effect=lambda p, _: self.rows if p == self.data else []))
            stack.enter_context(patch.object(T, 'sha256', side_effect=lambda p: R.SHIPPED_SHA if p == self.heads else actual_hash(p)))
            lower = stack.enter_context(patch.object(R, 'baseline_lower_bound', return_value={'pre_ask': [False] * len(self.rows)}))
            if lower_error:
                lower.side_effect = RuntimeError('PRIVATE lower error')
            full = stack.enter_context(patch.object(R, 'baseline_with_heads', return_value=replay))
            if isinstance(replay, Exception):
                full.side_effect = replay
            gates = stack.enter_context(patch.object(E, 'gates', wraps=E.gates))
            if not isinstance(replay, Exception):
                def full_replay(*args, **kwargs):
                    self.assertEqual(gates.call_count, 1, 'quality must precede shipped replay')
                    return replay
                full.side_effect = full_replay
            report = T.evaluate_frozen('freeze', self.data, self.manifest, 'fake-base', self.c,
                                       baseline_binary=binary, shipped_heads=self.heads if explicit else None)
        return report, full, lower, gates

    def measured(self):
        return dict(status='MEASURED', heads_sha256=R.SHIPPED_SHA,
                    ask=[i % 2 == 0 for i in range(len(self.rows))])

    def test_default_preserves_lower_bound(self):
        report, full, lower, gates = self.evaluate(explicit=False)
        full.assert_not_called()
        lower.assert_called_once()
        self.assertEqual(gates.call_args.kwargs['baseline'], [True] * len(self.rows))
        self.assertTrue(gates.call_args.kwargs['baseline_is_lower_bound'])
        self.assertEqual(report['baseline_evidence'], dict(provenance='lower_bound', status='MEASURED', heads_sha256=None))
        self.assertEqual(report['feasibility_quality'], 'PASS')
        self.assertEqual(report['gates']['baseline_shipped'], None)

    def test_top_level_manifest_hash_allows_a_filename_string(self):
        expected = T.sha256(self.data)
        self.manifest.write_text(json.dumps({'sha256': expected, 'file': self.data.name}))
        report, _, _, _ = self.evaluate(explicit=False)
        self.assertEqual(report['heldout_sha256'], expected)

    def test_legacy_nested_manifest_hash_still_works(self):
        expected = T.sha256(self.data)
        self.manifest.write_text(json.dumps({'file': {'sha256': expected}}))
        report, _, _, _ = self.evaluate(explicit=False)
        self.assertEqual(report['heldout_sha256'], expected)

    def test_invalid_top_level_hash_cannot_fall_back_to_nested_hash(self):
        for invalid in (None, False, '', '0' * 64):
            with self.subTest(hash=invalid):
                self.manifest.write_text(json.dumps({
                    'sha256': invalid, 'file': {'sha256': T.sha256(self.data)}}))
                with self.assertRaisesRegex(T.Unsupported, 'held-out manifest hash'):
                    self.evaluate(explicit=False)

    def test_missing_hash_with_a_filename_string_is_refused(self):
        self.manifest.write_text(json.dumps({'file': self.data.name}))
        with self.assertRaisesRegex(T.Unsupported, 'held-out manifest hash'):
            self.evaluate(explicit=False)

    def test_measured_accepts_exact_boolean_alignment_after_quality(self):
        reply = self.measured()
        report, full, _, gates = self.evaluate(reply)
        self.assertEqual(gates.call_args.kwargs['baseline'], [not a for a in reply['ask']])
        self.assertFalse(gates.call_args.kwargs['baseline_is_lower_bound'])
        self.assertEqual(report['baseline_evidence']['provenance'], 'shipped')
        self.assertEqual(report['baseline_evidence']['heads_sha256'], R.SHIPPED_SHA)
        self.assertNotIn('baseline_shipped', report['evidence_errors'])
        args, kwargs = full.call_args
        self.assertEqual(args[1:], ('fake-binary', 'fake-base'))
        self.assertEqual(kwargs, dict(shipped_heads=self.heads, threads=4))
        self.assertEqual(args[0], [T.visible_view(r) for r in self.rows])
        for row in args[0]:
            self.assertFalse(set(row) & {'label', 'rationale', 'id', 'class', 'family', 'pair_of', 'injection_of'})
        self.assertEqual(len(gates.call_args_list), 2)

    def test_malformed_or_unavailable_full_replay_retains_sound_lower_bound(self):
        bad = [None, [], {}, RuntimeError('PRIVATE file contents'),
               AssertionError('PRIVATE assertion'), AttributeError('PRIVATE attribute')]
        for field, value in [('status', 'UNSUPPORTED'), ('heads_sha256', 'wrong'), ('ask', []),
                             ('ask', [1] * len(self.rows)), ('ask', tuple(self.measured()['ask'])),
                             ('ask', [None] * len(self.rows))]:
            reply = self.measured()
            reply[field] = value
            bad.append(reply)
        for reply in bad:
            with self.subTest(reply=type(reply).__name__):
                report, _, _, gates = self.evaluate(reply)
                self.assertTrue(gates.call_args.kwargs['baseline_is_lower_bound'])
                self.assertEqual(gates.call_args.kwargs['baseline'], [True] * len(self.rows))
                self.assertEqual(report['baseline_evidence']['provenance'], 'lower_bound')
                self.assertEqual(report['baseline_evidence']['shipped_attempt']['status'], 'UNSUPPORTED')
                self.assertEqual(report['evidence_errors']['baseline_shipped'], 'shipped baseline evidence unavailable')
                self.assertNotIn('PRIVATE', json.dumps(report))

    def test_runtime_failure_preserves_measured_quality_fail(self):
        for binary in ('fake-binary', None):
            for error in (RuntimeError('PRIVATE'), AssertionError('PRIVATE'), AttributeError('PRIVATE')):
                with self.subTest(binary=binary, error=type(error).__name__):
                    report, full, _, _ = self.evaluate(error, fail=True, binary=binary)
                    self.assertEqual(report['feasibility_quality'], 'FAIL')
                    self.assertEqual(report['gate_b'], 'FAIL')
                    self.assertEqual(report['outcome'], 'FAIL')
                    self.assertIn('baseline_shipped', report['evidence_errors'])
                    self.assertNotIn('PRIVATE', json.dumps(report))
                    if binary is None:
                        full.assert_not_called()

    def test_full_replay_can_succeed_without_lower_bound(self):
        report, _, _, gates = self.evaluate(self.measured(), lower_error=True)
        self.assertFalse(gates.call_args.kwargs['baseline_is_lower_bound'])
        self.assertEqual(report['baseline_evidence']['provenance'], 'shipped')
        self.assertNotIn('baseline_shipped', report['evidence_errors'])

    def test_explicit_invalid_pin_never_reaches_h1_or_environment(self):
        unsafe = self.directory / 'h1'
        unsafe.symlink_to(self.heads)
        cases = [(unsafe, R.SHIPPED_SHA, R.SHIPPED_SHA, R.SHIPPED_SHA),
                 (self.directory / 'missing', R.SHIPPED_SHA, R.SHIPPED_SHA, R.SHIPPED_SHA),
                 (self.heads, 'wrong', R.SHIPPED_SHA, R.SHIPPED_SHA),
                 (self.heads, R.SHIPPED_SHA, 'replay-mismatch', R.SHIPPED_SHA),
                 (self.heads, R.SHIPPED_SHA, R.SHIPPED_SHA, 'manifest-mismatch')]
        for path, digest, replay_pin, manifest_pin in cases:
            reads = []
            def read_manifest(path):
                self.assertEqual(path, ROOT / 'tools/basemodel/manifest.json')
                reads.append(path)
                return json.dumps({'checkpoint': {'sha256': manifest_pin}})
            with self.subTest(path=path.name, digest=digest), \
                 patch.object(T, 'verify_freeze', return_value=self.frozen), \
                 patch.object(T, 'environment', side_effect=AssertionError('model setup')), \
                 patch.object(T, 'read_rows', side_effect=AssertionError('H1 rows')), \
                 patch.object(T, 'sha256', return_value=digest) as hashed, \
                 patch.object(R, 'SHIPPED_SHA', replay_pin), \
                 patch.object(Path, 'read_text', new=read_manifest):
                with self.assertRaisesRegex(T.Unsupported, '^shipped_heads_pin$'):
                    T.evaluate_frozen('freeze', 'never-data', 'never-manifest', 'base', self.c, shipped_heads=path)
                if path != self.heads:
                    hashed.assert_not_called()
                    self.assertEqual(reads, [])

    def test_valid_pin_order_precedes_first_h1_io(self):
        events = []
        real_safe = TR.safe_path
        real_read = Path.read_text
        def safe(path):
            events.append('safe')
            return real_safe(path)
        def read(path, *args, **kwargs):
            if path == self.manifest:
                self.assertEqual(events, ['safe', 'is_file', 'hash', 'manifest'])
                raise T.Unsupported('synthetic H1 boundary')
            events.append('manifest')
            return real_read(path, *args, **kwargs)
        with patch.object(T, 'verify_freeze', return_value=self.frozen), \
             patch.object(TR, 'safe_path', side_effect=safe), \
             patch.object(Path, 'is_file', side_effect=lambda: events.append('is_file') or True), \
             patch.object(T, 'sha256', side_effect=lambda _: events.append('hash') or R.SHIPPED_SHA), \
             patch.object(Path, 'read_text', new=read), \
             patch.object(T, 'environment', return_value=({'base': self.frozen['base']}, {})), \
             patch.object(T, 'context_meta_ok', return_value=True), \
             patch.dict(sys.modules, {'common': SimpleNamespace(load_checkpoint=lambda _: ({}, {}))}):
            with self.assertRaisesRegex(T.Unsupported, 'synthetic H1 boundary'):
                T.evaluate_frozen('freeze', self.data, self.manifest, 'base', self.c, shipped_heads=self.heads)

    def test_cli_forwards_explicit_heads(self):
        out = self.directory / 'report.json'
        with patch.object(E, 'load_contract', return_value={}), \
             patch.object(T, 'evaluate_frozen', return_value={'outcome': 'UNSUPPORTED'}) as evaluate, \
             patch('builtins.print'):
            self.assertEqual(E.main(['--out', str(out), '--freeze', 'f', '--heldout', 'fake-data',
                                     '--heldout-manifest', 'fake-manifest', '--base-dir', 'base',
                                     '--shipped-heads', str(self.heads)]), 3)
        self.assertEqual(evaluate.call_args.kwargs['shipped_heads'], str(self.heads))

    def test_pure_import_needs_no_model_or_network(self):
        script = """
import builtins, socket, sys
sys.path.insert(0, sys.argv[1])
original = builtins.__import__
def guarded(name, *args, **kwargs):
    if name.split('.')[0] in ('torch', 'transformers', 'tokenizers', 'laya', 'common'):
        raise AssertionError('model import')
    return original(name, *args, **kwargs)
builtins.__import__ = guarded
def denied(*args, **kwargs):
    raise AssertionError('network')
socket.socket.connect = denied
socket.getaddrinfo = denied
import context_train, context_eval
"""
        result = subprocess.run([sys.executable, '-S', '-c', script, str(ROOT / 'tools/basemodel')],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
