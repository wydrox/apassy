"""Model-free glue checks: synthetic G1 and explicit fail-closed fake runtime."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch, Mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools/basemodel'))


import context_existing_freeze as G
import context_data as D
import context_v1 as C
import context_train_rows as R


class GlueTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.c = C.load_contract()
        self.data = self.root / 'data'
        self.data.mkdir()
        # Small synthetic rows; manifest group boundary separately checked below.
        self.sets = {s: D.generate(7, 10, s) for s in ('train', 'val')}
        self.write_source()
        self.out = self.root / 'out'
        self.base = self.root / 'base'
        self.base.mkdir()
        self.frozen = dict(config=dict(G.CONFIG, device='cpu'), base=json.loads((ROOT / 'tools/basemodel/manifest.json').read_bytes())['base'],
                           tokenizer_sha256=self.c['tokenizer']['sha256'], context_contract_sha256=C.contract_hash(self.c),
                           package_versions={k: 'fake' for k in ('torch', 'laya', 'transformers', 'tokenizers')})
        self.frozen.update({key: G.record(self.data / name) for key, name in
                           (('train', 'train.jsonl'), ('val', 'val.jsonl'), ('data_manifest', 'data-manifest.json'))})
        self.frozen['converted'] = {w: G.conversion(self.sets, self.frozen, self.c, w) for w in G.ARMS}
        self.frozen['training_reports'] = {}
        for w in G.ARMS:
            path = self.root / (w + '.safetensors')
            path.write_bytes(b'fake checkpoint, never load')
            self.frozen[w] = G.record(path)
            report = self.report(self.frozen, w)
            path = self.root / (w + '-report.json')
            path.write_bytes(C.canonical(report))
            self.frozen['training_reports'][w] = G.record(path)
        self.subprocess = patch.object(G.subprocess, 'run', side_effect=AssertionError('unmocked subprocess'))
        self.subprocess.start()
        self.addCleanup(self.subprocess.stop)

    def write_source(self):
        manifest = dict(seed=7, groups=400, rubric='v1-R1-text-catalog', files={})
        for s, rows in self.sets.items():
            path = self.data / (s + '.jsonl')
            path.write_bytes(b''.join(C.canonical(r) for r in rows))
            manifest['files'][path.name] = dict(rows=len(rows), sha256=R.digest(path.read_bytes()))
        (self.data / 'data-manifest.json').write_bytes(C.canonical(manifest))

    def report(self, f, w):
        counts = f['converted'][w]['counts']
        cfg = {k: G.CONFIG[k] for k in ('epochs', 'batch', 'lr', 'warmup', 'seed', 'limit', 'max_steps')}
        cfg['weight_decay'] = G.CONFIG['wd']
        rec = f[w]
        return dict(config=cfg, init=None, init_sha256=None, teacher_rows=0, amp_encoder_fp16=False,
                    device='cpu', train_examples=counts['train.jsonl']['selected'],
                    val_examples=counts['val.jsonl']['selected'], versions=f['package_versions'],
                    checkpoint=rec['path'], sha256=rec['sha256'], size_bytes=Path(rec['path']).stat().st_size,
                    version='apassy-context-v1+' + rec['sha256'][:8], best_epoch=2, trainable_parameters=5)

    def test_pure_verify_and_complete_provenance(self):
        before = set(sys.modules)
        G.verify_conversion(self.frozen, self.c)
        for field in ('counts', 'output_sha256', 'source_sha256', 'question'):
            f = copy.deepcopy(self.frozen)
            f['converted']['context'][field] = {}
            with self.assertRaises(C.Unsupported):
                G.verify_conversion(f, self.c)
        self.assertFalse({'common', 'torch', 'numpy', 'laya'} & (set(sys.modules) - before))

    def test_import_guard_is_isolated_from_other_test_modules(self):
        code = '''
import sys
def audit(event, args):
    if event.startswith('socket.'):
        raise AssertionError('network forbidden')
    if event == 'import' and args[0].split('.')[0] in ('torch', 'numpy', 'laya'):
        raise AssertionError('real model import forbidden')
sys.addaudithook(audit)
import context_existing_freeze
assert not any(m in sys.modules for m in ('torch', 'numpy', 'laya'))
'''
        self.subprocess.stop()
        try:
            proc = subprocess.run([sys.executable, '-B', '-c', code], capture_output=True,
                                  env={**os.environ, 'PYTHONPATH': str(ROOT / 'tools/basemodel')})
        finally:
            self.subprocess.start()
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())

    def test_hash_label_and_groups_refusals(self):
        (self.data / 'train.jsonl').write_bytes(b'corrupt')
        with self.assertRaises(C.Unsupported):
            G.verify_conversion(self.frozen, self.c)
        self.sets['train'][0]['label'] = 'allow_ok' if self.sets['train'][0]['label'] != 'allow_ok' else 'must_ask'
        self.write_source()  # Even a newly hashed self-consistent manifest cannot relabel G1.
        for key, name in (('train', 'train.jsonl'), ('data_manifest', 'data-manifest.json')):
            self.frozen[key] = G.record(self.data / name)
        with self.assertRaisesRegex(C.Unsupported, 'rubric label'):
            G.verify_conversion(self.frozen, self.c)
        manifest = json.loads((self.data / 'data-manifest.json').read_bytes())
        manifest['groups'] = 399
        (self.data / 'data-manifest.json').write_bytes(C.canonical(manifest))
        self.frozen['data_manifest'] = G.record(self.data / 'data-manifest.json')
        with self.assertRaisesRegex(C.Unsupported, 'groups'):
            G.verify_conversion(self.frozen, self.c)

    def test_missing_class_and_unknown_source(self):
        sets = {s: [r for r in rows if r['label'] == 'allow_ok'] for s, rows in self.sets.items()}
        with self.assertRaisesRegex(C.Unsupported, 'both classes'):
            G.conversion(sets, self.frozen, self.c, 'context')
        self.sets['train'][0]['family'] = 'H1:synthetic'
        self.write_source()
        for key, name in (('train', 'train.jsonl'), ('data_manifest', 'data-manifest.json')):
            self.frozen[key] = G.record(self.data / name)
        with self.assertRaises(C.Unsupported):
            G.verify_conversion(self.frozen, self.c)

    def test_h1_refused_before_any_read(self):
        for name in ('train', 'val', 'data_manifest'):
            f = copy.deepcopy(self.frozen)
            f[name]['path'] = '/synthetic/H1-unopened'
            with patch.object(Path, 'read_bytes', side_effect=AssertionError('read')):
                with self.assertRaisesRegex(C.Unsupported, 'held-out/H1'):
                    G.verify_conversion(f, self.c)

    def test_report_tampering_even_when_rehashed(self):
        changes = [dict(init='other'), dict(teacher_rows=1), dict(amp_encoder_fp16=True),
                   dict(train_examples=1), dict(versions={}), dict(sha256='bad'),
                   dict(checkpoint='/wrong'), dict(lora_layers=1), dict(config={})]
        path = Path(self.frozen['training_reports']['context']['path'])
        original = self.report(self.frozen, 'context')
        for change in changes:
            with self.subTest(change=change):
                path.write_bytes(C.canonical(dict(original, **change)))
                self.frozen['training_reports']['context'] = G.record(path)
                with self.assertRaises(C.Unsupported):
                    G.verify_conversion(self.frozen, self.c)

    def test_real_freeze_api_refuses_conversion_before_evaluation(self):
        import context_train as core
        f = copy.deepcopy(self.frozen)
        f.update(mode='full', source_commit='fake', source_hashes={}, threshold=.5, control_threshold=.5)
        f['converted']['context']['question'] = {}
        path = self.root / 'freeze.json'
        path.write_bytes(C.canonical(f))
        with patch.object(core, 'source_commit', return_value='fake'), \
             patch.object(core, 'source_identity', return_value={}), \
             patch.object(core, 'package_versions', return_value=f['package_versions']), \
             patch.object(core, 'environment', side_effect=AssertionError('model environment called')):
            with self.assertRaisesRegex(C.Unsupported, 'conversion provenance'):
                core.evaluate_frozen(path, '/synthetic/heldout-unopened', '/synthetic/heldout-manifest-unopened',
                                     self.base, self.c, expect_freeze_sha256=C.sha256(path))

    def fake_scorer(self):
        c = self.c
        class Scorer:
            def __init__(self, base=None, contract=None, threads=4, cache=None):
                self.model = NS(encoder=NS(config=NS(hidden_size=8)))
                self.agent = NS(_to_internal=lambda value: value,
                                _encode_state=lambda text, qs, internal: [dict(ids=list(text.encode()), markers=[1], qtype=1)])
            def item(self, row, facts_blind=False):
                legacy = R.convert_rows([row], c, facts_blind=facts_blind)[0][0]
                return dict(ids=list(legacy['state'].encode()), markers=[1], qtype=1,
                            y=legacy['answer'], teacher=False)
        return Scorer

    def test_exact_selection_duplicates_overflow_mismatch_and_bound(self):
        scorer = self.fake_scorer()()
        # Preserve repeated model text as distinct occurrences.
        rows = [copy.deepcopy(self.sets['train'][0]) for _ in range(2)]
        rows[1]['id'] += ':duplicate'
        calls = Mock(wraps=scorer.item)
        scorer.item = calls
        G.exact_preflight(scorer, dict(train=rows), self.c, 'context')
        self.assertEqual(calls.call_count, 2)
        with patch.object(scorer, 'item', side_effect=C.Refusal('ExactOverflow')):
            with self.assertRaisesRegex(C.Unsupported, 'ExactOverflow'):
                G.exact_preflight(scorer, self.sets, self.c, 'context')
        with patch.object(scorer, 'item', return_value=dict(ids=[], markers=[], qtype=0, y=1., teacher=False)):
            with self.assertRaisesRegex(C.Unsupported, 'mismatch'):
                G.exact_preflight(scorer, self.sets, self.c, 'context')
        with patch.object(G, 'CACHE_BYTES', 1):
            with self.assertRaisesRegex(C.Unsupported, '6 GiB'):
                G.exact_preflight(scorer, self.sets, self.c, 'control')

    def test_subprocess_fixed_flags_offline_timeout_no_retry_cleanup(self):
        cache = self.root / 'cache'
        def fail(*args, **kw):
            cache.mkdir()
            (cache / 'partial').write_bytes(b'x')
            self.assertEqual(kw['timeout'], 5400)
            self.assertEqual(kw['env']['HF_HUB_OFFLINE'], '1')
            cmd = args[0]
            self.assertEqual(cmd[0], sys.executable)
            for flag in ('--metadata', '--base-dir', '--no-amp', '--device', '--require-device'):
                self.assertIn(flag, cmd)
            self.assertEqual(cmd[cmd.index('--name') + 1], 'apassy-context-v1')
            for flag in ('--init', '--limit', '--max-steps', '--keep-cache', '--lora-layers'):
                self.assertNotIn(flag, cmd)
            raise TimeoutError('fake')
        with patch.object(G.subprocess, 'run', side_effect=fail) as call:
            with self.assertRaises(TimeoutError):
                G.train_arm(self.base, self.data, 'cp', 'meta', 'report', cache, 'cpu')
            self.assertEqual(call.call_count, 1)
        self.assertFalse(cache.exists())

    def test_device_and_existing_output_fail_closed(self):
        torch = NS(backends=NS(mps=NS(is_available=lambda: False)), cuda=NS(is_available=lambda: False))
        for device in ('', 'auto', 'mps', 'cuda'):
            with self.assertRaises(C.Unsupported):
                G.require_device(device, torch)
        torch.backends.mps.is_available = lambda: True
        G.require_device('mps', torch)
        self.out.mkdir()
        with self.assertRaisesRegex(C.Unsupported, 'output exists'):
            G.run(self.data, self.out, self.base, 'cpu')

    def fake_runtime(self, *, bad_meta=False, fail_threshold=False):
        scorer_cls = self.fake_scorer()
        meta = dict(trained=['head.'], epoch=2, base_repo=self.frozen['base']['repo'])
        common = NS(head_state=lambda model: {'head.x': NS(numel=lambda: 5)},
                    load_checkpoint=Mock(return_value=({'head.x': 'fake'}, meta)), TRAINED_PREFIXES=('head.',),
                    apply_heads=Mock())
        caches = []
        def cache(**kw):
            self.assertEqual(kw['limit'], 6 * 1024**3)
            value = NS(close=Mock())
            caches.append(value)
            return value
        def fit(scorer, val, which):
            self.assertIs(val, sets_at_run[0]['val'])
            if fail_threshold:
                raise C.Unsupported('fake threshold failure')
            return .5, len(val)
        sets_at_run = []
        original = G.originals
        def remember(*args):
            value = original(*args)
            sets_at_run[:] = [value]
            return value
        core = NS(install_training_audit=Mock(), environment=lambda *a: (dict(base=self.frozen['base']), {}),
                  source_commit=lambda: 'fake', source_identity=lambda: {}, package_versions=lambda: self.frozen['package_versions'],
                  Scorer=scorer_cls, FeatureCache=cache, context_meta_ok=Mock(return_value=not bad_meta),
                  fit_threshold=fit)
        def train(base, data, checkpoint, metadata, report, cache, device):
            m = json.loads(metadata.read_bytes())
            self.assertNotIn('base_revision', m)
            checkpoint.write_bytes(b'fake checkpoint, never load')
            f = dict(self.frozen, **{checkpoint.stem: G.record(checkpoint)})
            report.write_bytes(C.canonical(self.report(f, checkpoint.stem)))
        return core, common, caches, remember, train

    def test_fake_run_cpu_threshold_and_freeze_originals(self):
        core, common, caches, remember, train = self.fake_runtime()
        with patch.dict(sys.modules, {'context_train': core, 'torch': NS(), 'common': common}), \
             patch.object(G, 'originals', side_effect=remember), patch.object(G, 'train_arm', side_effect=train):
            f = G.run(self.data, self.out, self.base, 'cpu')
        self.assertEqual(f['train']['path'], str((self.data / 'train.jsonl').resolve()))
        self.assertEqual(f['threshold'], .5)
        self.assertEqual(len(caches), 2)
        for cache in caches:
            cache.close.assert_called_once()
        self.assertEqual(common.apply_heads.call_count, 2)
        G.verify_conversion(f, self.c)
        self.assertFalse(any('heldout' in k for k in f))

    def test_metadata_and_threshold_failures_never_freeze(self):
        for bad_meta in (True, False):
            core, common, caches, remember, train = self.fake_runtime(bad_meta=bad_meta, fail_threshold=not bad_meta)
            out = self.root / ('bad-meta' if bad_meta else 'bad-threshold')
            with patch.dict(sys.modules, {'context_train': core, 'torch': NS(), 'common': common}), \
                 patch.object(G, 'originals', side_effect=remember), patch.object(G, 'train_arm', side_effect=train):
                with self.assertRaises(C.Unsupported):
                    G.run(self.data, out, self.base, 'cpu')
            self.assertFalse((out / 'freeze.json').exists())
            for cache in caches:
                cache.close.assert_called_once()


if __name__ == '__main__':
    unittest.main()
