"""Pure interfaces only: no import of the tensor-based generic trainer."""
import argparse
import ast
import copy
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools/basemodel'))
import context_train as T
import context_v1 as C


def trainer_functions():
    tree = ast.parse((ROOT / 'tools/basemodel/train.py').read_text())
    nodes = [n for n in tree.body if
             (isinstance(n, ast.FunctionDef) and n.name in ('extra_metadata', 'main')) or
             (isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and
              t.id == 'RESERVED_METADATA' for t in n.targets))]
    ns = dict(json=json, argparse=argparse, os=os,
              common=types.SimpleNamespace(MODEL_NAME='fake'),
              random=Mock(), torch=Mock())
    exec(compile(ast.Module(body=nodes, type_ignores=[]), 'train.py AST', 'exec'), ns)
    return ns


class ExistingCoreTests(unittest.TestCase):
    def setUp(self):
        self.c = C.load_contract()
        audit = patch.object(T, 'install_training_audit')
        self.audit = audit.start()
        self.addCleanup(audit.stop)

    def test_metadata_pins_for_each_arm(self):
        meta = dict(context_contract_sha256=C.contract_hash(self.c),
                    question='owner_accepts_use', facts_blind=False,
                    tokenizer_sha256=self.c['tokenizer']['sha256'],
                    base_revision=C.REVISION, base_weights_sha256='weights')
        for which in ('context', 'control'):
            meta['facts_blind'] = which == 'control'
            self.assertTrue(T.context_meta_ok(meta, which, self.c, 'weights'))
            for key in meta:
                changed = dict(meta, **{key: 'wrong'})
                self.assertFalse(T.context_meta_ok(changed, which, self.c, 'weights'), key)
                changed = dict(meta)
                del changed[key]
                self.assertFalse(T.context_meta_ok(changed, which, self.c, 'weights'), key)
        with self.assertRaises(C.Unsupported):
            T.context_meta_ok(meta, 'unknown', self.c, 'weights')

    def test_reserved_collisions_refused_before_training(self):
        ns = trainer_functions()
        keys = {'name', 'base_repo', 'base_revision', 'trained', 'noul_temperature', 'epoch'}
        self.assertEqual(ns['RESERVED_METADATA'], keys)
        for key in keys:
            with self.assertRaisesRegex(ValueError, 'reserved'):
                ns['main'](['--data', 'unused', '--out', 'unused', '--metadata',
                            json.dumps({key: 'override'})])
        ns['torch'].manual_seed.assert_not_called()
        ns['random'].seed.assert_not_called()
        self.assertEqual(ns['extra_metadata'](None), {})
        self.assertEqual(ns['extra_metadata']('{"facts_blind":false}'), {'facts_blind': False})
        for raw in ('[]', 'null', '1', '"text"', '{'):
            with self.assertRaises(ValueError):
                ns['extra_metadata'](raw)

    def test_metadata_file_interface(self):
        ns = trainer_functions()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'metadata.json'
            path.write_text('{"facts_blind":true}')
            self.assertEqual(ns['extra_metadata'](str(path)), {'facts_blind': True})
            for payload in ('[]', '{"base_revision":"override"}'):
                path.write_text(payload)
                with self.assertRaises(ValueError):
                    ns['main'](['--data', 'unused', '--out', 'unused', '--metadata', str(path)])
        ns['torch'].manual_seed.assert_not_called()

    def test_local_base_path_rejected_before_training(self):
        ns = trainer_functions()
        with tempfile.TemporaryDirectory() as tmp:
            for base in (Path(tmp) / 'missing', Path(tmp) / 'file'):
                if base.name == 'file':
                    base.write_text('synthetic')
                with self.assertRaisesRegex(ValueError, 'existing local directory'):
                    ns['main'](['--data', 'unused', '--out', 'unused', '--base-dir', str(base)])
        ns['torch'].manual_seed.assert_not_called()

    def test_context_child_audit_installed_before_metadata_read(self):
        ns = trainer_functions()
        self.audit.side_effect = ValueError('audit first')
        with patch('builtins.open', side_effect=AssertionError('file read before audit')):
            with self.assertRaisesRegex(ValueError, 'audit first'):
                ns['main'](['--data', 'unused', '--out', 'unused', '--metadata',
                            '/synthetic/heldout-unopened.json'])
        ns['torch'].manual_seed.assert_not_called()

    def test_require_device_refuses_fallback_and_preserves_generic_default(self):
        class Device:
            def __init__(self, name):
                self.type = name
            def __str__(self):
                return self.type
        for available, strict, refused in ((False, True, True), (False, False, False),
                                           (True, True, False)):
            ns = trainer_functions()
            ns['torch'].backends.mps.is_available.return_value = available
            ns['torch'].device.side_effect = Device
            ns['on_ac_power'] = Mock(side_effect=RuntimeError('device selection completed'))
            argv = ['--data', 'unused', '--out', 'unused', '--device', 'mps']
            if strict:
                argv.append('--require-device')
            if refused:
                with self.assertRaisesRegex(ValueError, 'fallback refused'):
                    ns['main'](argv)
                ns['on_ac_power'].assert_not_called()
            else:
                with self.assertRaisesRegex(RuntimeError, 'device selection completed'):
                    ns['main'](argv)

    def test_report_versions_are_installed_versions_only_when_metadata_explicit(self):
        tree = ast.parse((ROOT / 'tools/basemodel/train.py').read_text())
        main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'main')
        block = next(n for n in main.body if isinstance(n, ast.If) and
                     ast.unparse(n.test) == 'args.metadata is not None' and
                     any(isinstance(part, ast.ImportFrom) and
                         any(name.name == 'package_versions' for name in part.names)
                         for part in n.body))
        code = compile(ast.Module(body=[block], type_ignores=[]), 'versions AST', 'exec')
        installed = dict(laya='fake-laya', torch='fake-torch',
                         transformers='fake-transformers', tokenizers='fake-tokenizers')
        for raw in (None, '{"versions":{"torch":"spoof"}}', '{}'):
            report = {'versions': {'torch': 'legacy'}}
            ns = dict(args=types.SimpleNamespace(metadata=raw), report=report)
            with patch.object(T, 'package_versions', return_value=installed) as versions:
                exec(code, ns)
            self.assertEqual(report['versions'], {'torch': 'legacy'} if raw is None else installed)
            self.assertEqual(versions.call_count, 0 if raw is None else 1)

    def freeze(self, directory):
        cfg = dict(mode='full', epochs=4, lr=.0003, wd=.01, warmup=100, threads=4,
                   seed=7, max_steps=0, seconds_per_head=5400, batch=32, limit=0)
        frozen = dict(mode='full', config=cfg, context_contract_sha256=C.contract_hash(self.c),
                      tokenizer_sha256=self.c['tokenizer']['sha256'], base={'revision': C.REVISION},
                      source_hashes={'synthetic': 'sha'}, source_commit='fake',
                      package_versions={'fake': '1'}, threshold=.5, control_threshold=.6)
        for name in ('train', 'val', 'context', 'control'):
            path = directory / name
            path.write_bytes(b'synthetic')
            frozen[name] = dict(path=str(path), sha256=C.sha256(path))
        manifest = directory / 'manifest.json'
        manifest.write_bytes(C.canonical(dict(groups=400, files={n + '.jsonl':
            dict(sha256=frozen[n]['sha256'], rows=10) for n in ('train', 'val')})))
        frozen['data_manifest'] = dict(path=str(manifest), sha256=C.sha256(manifest))
        return frozen

    def verify(self, directory, frozen):
        path = directory / 'freeze.json'
        path.write_bytes(C.canonical(frozen))
        with patch.object(T, 'source_identity', return_value={'synthetic': 'sha'}), \
             patch.object(T, 'source_commit', return_value='fake'), \
             patch.object(T, 'package_versions', return_value={'fake': '1'}):
            return T.verify_freeze(path, self.c, C.sha256(path))

    def test_cpu_legacy_compat_and_explicit_trainer_dispatch(self):
        # A fake helper tests only core dispatch; real helper integration is separate.
        helper = types.ModuleType('context_existing_freeze')
        helper.verify_conversion = Mock()
        with tempfile.TemporaryDirectory() as tmp, patch.dict(sys.modules, {'context_existing_freeze': helper}):
            directory = Path(tmp)
            frozen = self.freeze(directory)
            self.assertEqual(self.verify(directory, frozen), frozen)
            helper.verify_conversion.assert_not_called()
            frozen['config'].update(trainer='train.py', amp=False, device='cpu')
            frozen['training_reports'] = {arm: dict(frozen[arm]) for arm in ('context', 'control')}
            self.assertEqual(self.verify(directory, frozen), frozen)
            helper.verify_conversion.assert_called_once_with(frozen, self.c)
            helper.verify_conversion.side_effect = C.Unsupported('conversion mismatch')
            with self.assertRaisesRegex(C.Unsupported, 'conversion mismatch'):
                self.verify(directory, frozen)
            helper.verify_conversion.reset_mock(side_effect=True)
            for trainer in ('unknown', '', None, False):
                bad = copy.deepcopy(frozen)
                bad['config']['trainer'] = trainer
                with self.assertRaisesRegex(C.Unsupported, 'unknown frozen trainer'):
                    self.verify(directory, bad)
            for key, value in (('amp', True), ('amp', None), ('limit', 1), ('max_steps', 1),
                               ('init', 'checkpoint'), ('lora_layers', 1), ('teacher_rows', 1),
                               ('batch', 16)):
                bad = copy.deepcopy(frozen)
                bad['config'][key] = value
                with self.assertRaises(C.Unsupported):
                    self.verify(directory, bad)
            helper.verify_conversion.assert_not_called()

    def test_all_artifact_paths_checked_before_first_artifact_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for name in ('train', 'val', 'context', 'control', 'data_manifest'):
                frozen = self.freeze(directory)
                frozen[name]['path'] = '/synthetic/H1-unopened'
                path = directory / 'freeze.json'
                path.write_bytes(C.canonical(frozen))
                expected = C.sha256(path)
                def guarded_hash(target):
                    if Path(target) == path:
                        return expected
                    raise AssertionError('artifact read before all paths were checked')
                with patch.object(T, 'sha256', side_effect=guarded_hash), \
                     patch.object(T, 'source_identity', return_value={'synthetic': 'sha'}), \
                     patch.object(T, 'source_commit', return_value='fake'), \
                     patch.object(T, 'package_versions', return_value={'fake': '1'}):
                    with self.assertRaisesRegex(C.Unsupported, 'held-out/H1'):
                        T.verify_freeze(path, self.c, expected)
            with patch.object(T, 'sha256', side_effect=AssertionError('held-out read')):
                with self.assertRaisesRegex(C.Unsupported, 'held-out/H1'):
                    T.verify_freeze('/synthetic/heldout-unopened', self.c, 'f' * 64)

    def test_freeze_pin_and_artifact_mismatches(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            frozen = self.freeze(directory)
            for key, value in (('context_contract_sha256', 'wrong'),
                               ('tokenizer_sha256', 'wrong'), ('source_commit', 'wrong'),
                               ('source_hashes', {}), ('package_versions', {}), ('threshold', 2.)):
                bad = dict(frozen, **{key: value})
                with self.assertRaises(C.Unsupported):
                    self.verify(directory, bad)
            Path(frozen['context']['path']).write_bytes(b'changed')
            with self.assertRaisesRegex(C.Unsupported, 'artifact'):
                self.verify(directory, frozen)

    def test_threshold_semantics_and_refusals(self):
        rows = [dict(label=label, local_rule=None) for label in
                ('must_ask', 'allow_ok', 'deterministic_ask')]
        rows += [dict(label='must_ask', local_rule='ask')]
        scorer = types.SimpleNamespace(scores=Mock(return_value=[.5, .8, .99, 1.]),
                                       last_refusals=[None] * 4)
        for arm in ('context', 'control'):
            tau, count = T.fit_threshold(scorer, rows, arm)
            self.assertEqual(tau, math.nextafter(.5, math.inf))
            self.assertEqual(count, 3)
            scorer.scores.assert_called_with(rows, facts_blind=arm == 'control')
        for value in (None, float('nan'), float('inf'), -.1, 1.1):
            scorer.scores.return_value = [value, .8, .99, 1.]
            with self.assertRaisesRegex(C.Unsupported, 'nonfinite'):
                T.fit_threshold(scorer, rows, 'context')
        scorer.scores.return_value = [.5, .8, None, None]
        scorer.last_refusals = [None, None, 'OverBudget', None]
        self.assertEqual(T.fit_threshold(scorer, rows, 'context'), (math.nextafter(.5, math.inf), 2))
        scorer.scores.return_value = [None, .8, .9, None]
        scorer.last_refusals = ['OverBudget', None, None, None]
        with self.assertRaisesRegex(C.Unsupported, 'denominators'):
            T.fit_threshold(scorer, rows, 'control')

    def test_no_model_import_or_network(self):
        code = '''
import sys
def audit(event, args):
    if event.startswith('socket.'):
        raise AssertionError('network access')
    if event == 'import' and args[0].split('.')[0] in ('torch', 'numpy', 'laya'):
        raise AssertionError('tensor library import')
sys.addaudithook(audit)
import context_train, context_train_rows
assert not any(m in sys.modules for m in ('torch', 'numpy', 'laya'))
'''
        proc = subprocess.run([sys.executable, '-B', '-c', code], capture_output=True,
                              env={**os.environ, 'PYTHONPATH': str(ROOT / 'tools/basemodel')})
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())


if __name__ == '__main__':
    unittest.main()
