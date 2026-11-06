"""Synthetic AST/fake checks; no catalog, corpus, tensor or model imports."""
import ast
import copy
import gc
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'tools/basemodel'
RECIPE = 'context-v1-e20'


class Unsupported(ValueError):
    pass


class Refusal(ValueError):
    pass


def functions(filename, names, namespace):
    """Execute only named source functions/constants, without module imports."""
    tree = ast.parse((SOURCE / filename).read_text())
    nodes = [n for n in tree.body if
             isinstance(n, ast.FunctionDef) and n.name in names or
             isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id in names for t in n.targets)]
    exec(compile(ast.Module(body=nodes, type_ignores=[]), filename + ' synthetic AST', 'exec'), namespace)
    return namespace


def d0_module():
    spec = importlib.util.spec_from_file_location('context_dev_diagnostic', SOURCE / 'context_dev_diagnostic.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # D0 has stdlib imports only.
    return module


class E20Tests(unittest.TestCase):
    def setUp(self):
        self.d0 = d0_module()
        self.evaluation = NS(CLASSES=('synthetic',))
        evaluation_namespace = dict(math=math, Unsupported=Unsupported)
        functions('context_eval.py', {'auroc', 'threshold', 'probability'}, evaluation_namespace)
        self.evaluation.auroc = evaluation_namespace['auroc']
        self.evaluation.threshold = evaluation_namespace['threshold']
        self.evaluation.probability = evaluation_namespace['probability']
        self.c = dict(tokenizer=dict(sha256='synthetic-tokenizer'))
        self.v = NS(serialize=Mock(return_value=('synthetic', {})))
        self.modules = patch.dict(sys.modules, context_dev_diagnostic=self.d0,
                                  context_eval=self.evaluation, context_v1=self.v)
        self.modules.start()
        self.addCleanup(self.modules.stop)
        self.ns = dict(Path=Path, math=math, sys=sys, json=json, os=os, re=re, gc=gc,
                       subprocess=subprocess, Unsupported=Unsupported, Refusal=Refusal,
                       CONTRACT=Path('/synthetic/contract'), REVISION='synthetic-revision',
                       safe_path=Path, contract_hash=lambda _: 'synthetic-contract',
                       canonical=self.d0.canonical, read_json=json.loads,
                       __file__=str(SOURCE / 'context_existing_freeze.py'))
        names = {'CONFIG', 'RECIPES', 'G1_SHA256', 'D0_SAMPLE_SHA256', 'ARMS', 'CACHE_BYTES',
                 'config_for', 'frozen_config', 'model_name', 'trainer_command', 'run',
                 'report_ok', 'development_selection', 'calibration_snapshot',
                 'blind_pair_keys', 'temperature_ok', 'development_reading'}
        functions('context_existing_freeze.py', names, self.ns)

    def config(self, recipe=None):
        return self.ns['config_for'](recipe)

    def test_legacy_and_explicit_exact_recipe(self):
        expected = dict(mode='full', trainer='train.py', amp=False, epochs=4, batch=32,
                        lr=.0003, wd=.01, warmup=100, seed=7, threads=4, limit=0,
                        max_steps=0, seconds_per_head=5400)
        self.assertEqual(self.config(), expected)
        self.assertEqual(self.config(RECIPE), dict(expected, epochs=20, recipe=RECIPE))
        modified = self.config(RECIPE)
        modified['epochs'] = 1
        self.assertEqual(self.config(RECIPE)['epochs'], 20)
        for recipe in ('', 'context-v1', 'context-v1-e21', True, {}):
            with self.assertRaises(Unsupported):
                self.config(recipe)
        for recipe in (None, RECIPE):
            config = dict(self.config(recipe), device='cpu')
            self.assertEqual(self.ns['frozen_config'](dict(config=config)), config)
            for key, value in (('epochs', 4 if recipe else 20), ('batch', 31), ('extra', 1)):
                with self.assertRaises(Unsupported):
                    self.ns['frozen_config'](dict(config=dict(config, **{key: value})))
        with self.assertRaises(Unsupported):
            self.ns['frozen_config'](dict(config=dict(expected, device='cpu')), RECIPE)
        with self.assertRaises(Unsupported):
            self.ns['frozen_config'](dict(config=expected))

    def test_trainer_command_epochs_and_name_are_explicit(self):
        for recipe, epochs, name in ((None, '4', 'apassy-context-v1'),
                                     (RECIPE, '20', 'apassy-context-v1-e20')):
            cmd = self.ns['trainer_command']('b', 'd', 'o', 'm', 'r', 'c', 'cpu', recipe)
            self.assertEqual(cmd[cmd.index('--epochs') + 1], epochs)
            self.assertEqual(cmd[cmd.index('--name') + 1], name)
            self.assertIn('--no-amp', cmd)
            self.assertIn('--require-device', cmd)
            self.assertNotIn('--lora', cmd)

    def test_report_best_epoch_and_recipe_bounds(self):
        with tempfile.TemporaryDirectory() as directory:
            checkpoint = Path(directory) / 'synthetic-checkpoint'
            checkpoint.write_bytes(b'synthetic only')
            for recipe in (None, RECIPE):
                config = self.config(recipe)
                frozen = dict(config=dict(config, device='cpu'), package_versions={},
                    context=dict(path=str(checkpoint), sha256='f' * 64),
                    converted=dict(context=dict(counts={s + '.jsonl': dict(selected=2) for s in ('train', 'val')})))
                report_config = {k: config[k] for k in ('epochs', 'batch', 'lr', 'warmup', 'seed', 'limit', 'max_steps')}
                report_config['weight_decay'] = config['wd']
                report = dict(config=report_config, init=None, init_sha256=None, teacher_rows=0,
                    amp_encoder_fp16=False, device='cpu', train_examples=2, val_examples=2,
                    versions={}, checkpoint=str(checkpoint), sha256='f' * 64,
                    size_bytes=checkpoint.stat().st_size, version=self.ns['model_name'](recipe) + '+ffffffff',
                    trainable_parameters=3, best_epoch=4, noul_temperature=1.)
                self.ns['report_ok'](report, frozen, 'context')
                report['best_epoch'] = 5
                if recipe:
                    self.ns['report_ok'](report, frozen, 'context')
                else:
                    with self.assertRaises(Unsupported):
                        self.ns['report_ok'](report, frozen, 'context')
                report['best_epoch'] = config['epochs'] + 1
                with self.assertRaises(Unsupported):
                    self.ns['report_ok'](report, frozen, 'context')
                if recipe:
                    report['best_epoch'] = 20
                    report['config']['epochs'] = 4
                    with self.assertRaises(Unsupported):
                        self.ns['report_ok'](report, frozen, 'context')

    def test_core_freeze_verification_uses_known_recipe_epochs(self):
        verify_conversion = Mock()
        namespace = dict(Path=Path, json=json, math=math, Unsupported=Unsupported,
            contract_hash=lambda _: 'synthetic-contract', REVISION='synthetic-revision',
            sha256=lambda _: 'f' * 64, source_identity=lambda: {}, source_commit=lambda: 'synthetic-source',
            package_versions=lambda: {})
        functions('context_train.py', {'verify_freeze'}, namespace)
        integration = NS(frozen_config=self.ns['frozen_config'], verify_conversion=verify_conversion)
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            manifest = directory / 'synthetic-manifest.json'
            manifest.write_text(json.dumps(dict(groups=400, files={s + '.jsonl':
                dict(sha256='f' * 64, rows=2) for s in ('train', 'val')})))
            freeze = directory / 'synthetic-freeze.json'
            for recipe in (None, RECIPE):
                frozen = dict(mode='full', config=dict(self.config(recipe), device='cpu'),
                    context_contract_sha256='synthetic-contract', tokenizer_sha256='synthetic-tokenizer',
                    base=dict(revision='synthetic-revision'), source_hashes={}, source_commit='synthetic-source',
                    package_versions={}, threshold=.5, control_threshold=.5,
                    training_reports={arm: dict(path='/synthetic/' + arm) for arm in ('context', 'control')})
                frozen.update({name: dict(path=str(manifest), sha256='f' * 64)
                               for name in ('train', 'val', 'context', 'control', 'data_manifest')})
                freeze.write_text(json.dumps(frozen))
                with patch.dict(sys.modules, context_train_rows=NS(safe_path=Path),
                                context_existing_freeze=integration):
                    self.assertEqual(namespace['verify_freeze'](freeze, self.c, 'f' * 64), frozen)
                    verify_conversion.assert_called_with(frozen, self.c)
                    frozen['config']['epochs'] = 4 if recipe else 20
                    freeze.write_text(json.dumps(frozen))
                    with self.assertRaises(Unsupported):
                        namespace['verify_freeze'](freeze, self.c, 'f' * 64)

    def test_metadata_cross_recipe_and_temperature(self):
        namespace = dict(Unsupported=Unsupported, contract_hash=lambda _: 'synthetic-contract',
                         REVISION='synthetic-revision')
        functions('context_train.py', {'context_meta_ok'}, namespace)
        meta = dict(context_contract_sha256='synthetic-contract', question='owner_accepts_use',
                    facts_blind=False, tokenizer_sha256='synthetic-tokenizer',
                    base_revision='synthetic-revision', base_weights_sha256='synthetic-weights')
        predicate = namespace['context_meta_ok']
        self.assertTrue(predicate(meta, 'context', self.c, 'synthetic-weights'))
        self.assertFalse(predicate(meta, 'context', self.c, 'synthetic-weights', RECIPE))
        meta['recipe'] = RECIPE
        self.assertTrue(predicate(meta, 'context', self.c, 'synthetic-weights', RECIPE))
        self.assertFalse(predicate(meta, 'context', self.c, 'synthetic-weights'))
        check = self.ns['temperature_ok']
        check(dict(noul_temperature=1.), dict(noul_temperature=1.), NS(temperature=1.))
        for values in ((1., 2., 1.), (0., 0., 0.), (math.nan,) * 3,
                       (math.inf,) * 3, (True,) * 3, (None, 1., 1.)):
            with self.assertRaises(Unsupported):
                check(dict(noul_temperature=values[0]), dict(noul_temperature=values[1]), NS(temperature=values[2]))

    def selected(self):
        rows, pairs, unpaired = [], [], []
        for i in range(91):
            a = len(rows)
            rows.extend([dict(id='synthetic-allow-' + str(i), label='allow_ok', **{'class': 'synthetic'}, local_rule=None),
                         dict(id='synthetic-must-' + str(i), label='must_ask', **{'class': 'synthetic'}, local_rule=None)])
            pairs.append((a, a + 1))
        for i in range(85):
            unpaired.append(len(rows))
            rows.append(dict(id='synthetic-normal-' + str(i), label='allow_ok', **{'class': 'synthetic'}, local_rule=None))
        summary = dict(sample_sha256=self.ns['D0_SAMPLE_SHA256'], rows=267, pairs=91, unpaired_allows=85)
        return summary, rows, pairs, unpaired

    def test_data_and_sample_drift_precede_any_model_or_training(self):
        selected = self.selected()
        frozen = {key: dict(path='/synthetic/' + key, sha256=value) for key, value in self.ns['G1_SHA256'].items()}
        self.ns['checked'] = Mock(return_value=b'{"groups":400,"seed":7}')
        with patch.object(self.d0, 'select_rows', return_value=selected) as select:
            self.assertEqual(self.ns['development_selection']({'val': []}, frozen, self.c, RECIPE), selected)
            select.assert_called_once_with([], ('synthetic',), self.v.serialize, Refusal, self.c, {})
            for key in self.ns['G1_SHA256']:
                changed = copy.deepcopy(frozen)
                changed[key]['sha256'] = '0' * 64
                with self.assertRaises(Unsupported):
                    self.ns['development_selection']({'val': []}, changed, self.c, RECIPE)
            for manifest in (b'{"groups":401,"seed":7}', b'{"groups":400,"seed":8}'):
                self.ns['checked'].return_value = manifest
                with self.assertRaises(Unsupported):
                    self.ns['development_selection']({'val': []}, frozen, self.c, RECIPE)
            self.ns['checked'].return_value = b'{"groups":400,"seed":7}'
            selected[0]['sample_sha256'] = '0' * 64
            with self.assertRaises(Unsupported):
                self.ns['development_selection']({'val': []}, frozen, self.c, RECIPE)
            # Exercise actual run control flow up to the guard with no model modules.
            with tempfile.TemporaryDirectory() as directory:
                base = Path(directory) / 'base'
                base.mkdir()
                core = NS(install_training_audit=Mock(), environment=Mock(side_effect=AssertionError('model reached')))
                self.ns['load_contract'] = Mock(return_value=self.c)
                self.ns['record'] = lambda p: frozen[{'train.jsonl': 'train', 'val.jsonl': 'val',
                                                    'data-manifest.json': 'data_manifest'}[p.name]]
                self.ns['originals'] = Mock(return_value={'val': []})
                self.ns['conversion'] = Mock(side_effect=AssertionError('training preparation reached'))
                self.ns['train_arm'] = Mock(side_effect=AssertionError('training reached'))
                with patch.dict(sys.modules, context_train=core):
                    with self.assertRaisesRegex(Unsupported, 'sample differs'):
                        self.ns['run'](directory, Path(directory) / 'out', base, 'cpu', recipe=RECIPE)
                core.environment.assert_not_called()
                self.ns['train_arm'].assert_not_called()
                self.ns['conversion'].assert_not_called()

    def snapshots(self, paired=46, normal=43):
        selected = self.selected()
        _, rows, pairs, unpaired = selected
        context = {r['id']: (.4, None) for r in rows}
        for i, (a, _) in enumerate(pairs):
            context[rows[a]['id']] = (.9 if i < paired else .2, None)
        for i, index in enumerate(unpaired):
            context[rows[index]['id']] = (.9 if i < normal else .2, None)
        control = {r['id']: (.2, None) for r in rows}
        snapshots = dict(context=dict(threshold=.5, by_id=context), control=dict(threshold=.5, by_id=control))
        return selected, rows, snapshots

    def test_goal50_boundaries_serialization_and_aggregate_privacy(self):
        for paired, normal, expected in ((46, 43, 'DEV_50_NOT_RULED_OUT'), (45, 43, 'DEV_50_MISS'),
                                        (46, 42, 'DEV_50_MISS'), (91, 85, 'DEV_50_NOT_RULED_OUT')):
            selected, rows, snapshots = self.snapshots(paired, normal)
            result = self.ns['development_reading'](selected, rows, snapshots, ['identical'] * 91, RECIPE)
            self.assertEqual(result['goal50']['reading'], expected)
            self.assertEqual(result['goal50']['populations']['paired_normal']['selected'], 91)
            self.assertEqual(result['goal50']['populations']['unpaired_normal']['selected'], 85)
            self.assertEqual(result['candidate_attempt'], 2)
            self.assertEqual(result['reading_rule'], self.d0.READING_RULE)
            self.assertEqual(result['sample_sha256'], self.ns['D0_SAMPLE_SHA256'])
            self.assertEqual(result['full_validation']['context']['labels']['allow_ok']['original_rows'], 176)
            raw = self.d0.canonical(dict(development_reading=result))
            self.assertEqual(json.loads(raw)['development_reading'], result)
            self.assertNotIn(b'synthetic-allow-', raw)
            self.assertNotIn(b'synthetic-must-', raw)
            self.assertNotIn(b'synthetic-normal-', raw)
            self.assertEqual(set(result), {'schema', 'recipe', 'candidate_attempt', 'sample_sha256',
                'selection_counts', 'thresholds', 'data_reused_for_calibration', 'independent_quality',
                'independent_safety', 'gate_b', 'activation_authorized', 'reading_rule', 'goal50',
                'full_validation', 'populations', 'histograms'})
            def private_keys(value):
                if isinstance(value, dict):
                    self.assertFalse({'id', 'ids', 'request', 'text', 'scores', 'by_id'} & value.keys())
                    for item in value.values():
                        private_keys(item)
                elif isinstance(value, list):
                    for item in value:
                        private_keys(item)
            private_keys(result)

    def test_full_validation_denominators_and_no_hidden_selected_filter(self):
        selected, rows, snapshots = self.snapshots()
        validation = rows + [dict(id='synthetic-local', label='allow_ok', local_rule='read'),
                             dict(id='synthetic-unavailable', label='allow_ok', local_rule=None),
                             dict(id='synthetic-deterministic', label='deterministic_ask', local_rule=None)]
        for arm in snapshots:
            snapshots[arm]['by_id'].update({'synthetic-local': (None, 'LocalRule'),
                'synthetic-unavailable': (None, None), 'synthetic-deterministic': (.1, None)})
        result = self.ns['development_reading'](selected, validation, snapshots, ['identical'] * 91, RECIPE)
        label = result['full_validation']['context']['labels']['allow_ok']
        self.assertEqual((label['original_rows'], label['eligible_scorer_rows'], label['refused']['LocalRule'],
                          label['unavailable']), (178, 176, 1, 1))
        self.assertEqual(result['full_validation']['context']['labels']['must_ask']['interpretation'],
                         'calibration_safety_tautology')
        deterministic = result['full_validation']['context']['labels']['deterministic_ask']
        self.assertEqual((deterministic['original_rows'], deterministic['eligible_scorer_rows'],
                          deterministic['interpretation']), (1, 1, 'not_in_threshold_fit'))
        rid = rows[-1]['id']
        snapshots['context']['by_id'][rid] = (None, 'ExactOverflow')
        result = self.ns['development_reading'](selected, validation, snapshots, ['identical'] * 91, RECIPE)
        self.assertEqual(result['goal50']['reading'], 'DEV_50_INCOMPLETE')
        self.assertEqual(result['goal50']['populations']['unpaired_normal']['selected'], 85)
        label = result['populations']['unpaired_normal']['overall']['arms']['context']['labels']['allow_ok']
        self.assertEqual((label['selected'], label['refused']['ExactOverflow']), (85, 1))
        del snapshots['control']['by_id'][rid]
        with self.assertRaises(Unsupported):
            self.ns['development_reading'](selected, validation, snapshots, ['identical'] * 91, RECIPE)

    def test_reuses_one_calibration_pass_and_blind_keys_have_no_encoder(self):
        namespace = dict(Unsupported=Unsupported)
        functions('context_train.py', {'fit_threshold'}, namespace)
        rows = [dict(id='synthetic-a', label='allow_ok', local_rule=None),
                dict(id='synthetic-m', label='must_ask', local_rule=None)]
        class FakeScorer:
            def __init__(self):
                self.calls = 0
            def scores(self, rows, facts_blind=False):
                self.calls += 1
                self.last_scores, self.last_refusals = [.8, .4], [None, None]
                return self.last_scores
            def item(self, row, facts_blind=False):
                self.assert_blind = facts_blind
                return dict(cache_key='same')
        scorer = FakeScorer()
        tau, count = namespace['fit_threshold'](scorer, rows, 'context')
        snapshot = self.ns['calibration_snapshot'](scorer, rows, tau)
        keys = self.ns['blind_pair_keys'](scorer, rows, [(0, 1)])
        self.assertEqual((scorer.calls, count, keys), (1, 2, ['identical']))
        self.assertTrue(scorer.assert_blind)
        self.assertEqual(snapshot['by_id']['synthetic-a'], (.8, None))
        scorer.last_scores[0] = .1
        self.assertEqual(snapshot['by_id']['synthetic-a'], (.8, None))
        # The production Scorer method must clear last_scores before any iteration.
        tree = ast.parse((SOURCE / 'context_train.py').read_text())
        scores = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == 'scores')
        assignments = [n for n in scores.body if isinstance(n, ast.Assign)]
        self.assertTrue(any(isinstance(t, ast.Attribute) and t.attr == 'last_scores'
                            for node in assignments for t in node.targets))


class RealRecipePins(unittest.TestCase):
    def test_model_free_generation_and_sample_pins_across_hash_seeds(self):
        self.assertEqual((sys.implementation.name, sys.version_info[:2]), ('cpython', (3, 12)))
        with patch.object(sys, 'path', [str(SOURCE), *sys.path]):
            import context_existing_freeze as integration
            import context_v1 as contract
            c = contract.load_contract()
            with tempfile.TemporaryDirectory() as temporary:
                for seed in ('1', '8675309'):
                    output = Path(temporary) / seed
                    generated = subprocess.run([sys.executable, '-B', str(SOURCE / 'context_data.py'),
                        '--out', str(output), '--groups', '400', '--seed', '7'],
                        env={**os.environ, 'PYTHONHASHSEED': seed},
                        capture_output=True, timeout=60)
                    self.assertEqual(generated.returncode, 0, 'model-free G1 generation failed')
                    frozen = {key: integration.record(output / name) for key, name in
                        (('train', 'train.jsonl'), ('val', 'val.jsonl'), ('data_manifest', 'data-manifest.json'))}
                    self.assertTrue({key: rec['sha256'] for key, rec in frozen.items()} == integration.G1_SHA256,
                                    'model-free G1 hash pins differ')
                    sets = integration.originals(frozen, c)
                    selection = integration.development_selection(sets, frozen, c, RECIPE)[0]
                    self.assertTrue(selection['sample_sha256'] == integration.D0_SAMPLE_SHA256,
                                    'model-free D0 sample pin differs')
                    self.assertEqual((selection['rows'], selection['pairs'], selection['unpaired_allows']), (267, 91, 85))
                    print(json.dumps(dict(e20_model_free_pins=True, hash_seed=int(seed),
                        train_rows=len(sets['train']), validation_rows=len(sets['val']),
                        sample_rows=selection['rows'], pairs=selection['pairs'],
                        unpaired_allows=selection['unpaired_allows']), sort_keys=True))


if __name__ == '__main__':
    unittest.main()
