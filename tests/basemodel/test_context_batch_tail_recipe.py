"""Synthetic wiring coverage for hosted CI; no real CUDA or model execution."""
import copy
import json
import os
import sys
import unittest
from types import SimpleNamespace as NS
from unittest.mock import Mock, patch

import test_context_existing_freeze as fixtures
import test_context_e20_recipe as synthetic

G, C, R = fixtures.G, fixtures.C, fixtures.R
NEW = 'context-v1-e20-batch-tail-v1'
E20 = 'context-v1-e20'
OBJECTIVE = 'bce-plus-batch-tail-v1'
ENV = dict(PYTHONHASHSEED='7', CUBLAS_WORKSPACE_CONFIG=':4096:8', NVIDIA_TF32_OVERRIDE='0')


def seal(packages):
    return dict(schema=1, profile='cuda-deterministic-v1', seed=7,
        effective=dict(environment=dict(ENV), flags=dict(deterministic=True, warn_only=False,
            cudnn_benchmark=False, cudnn_deterministic=True, fill_uninitialized_memory=True,
            fp32_precision=['ieee'] * 5, threads=4)),
        software=dict(torch=packages['torch'], cuda='13.0', cudnn=93000, python='3.12.9', numpy='2.4.0',
            packages={k: packages[k] for k in ('laya', 'transformers', 'tokenizers')},
            device=dict(index=0, name='NVIDIA L4', compute_capability=[8, 9])),
        initial_head_sha256='a' * 64)


def upgrade(report, packages):
    report['config']['epochs'] = 20
    report.update(device='cuda', best_epoch=20, noul_temperature=1.,
        version=G.model_name(NEW) + '+' + report['sha256'][:8],
        training_objective=dict(id=OBJECTIVE, train_loss='ce_plus_tail'), runtime_profile=seal(packages),
        history=[dict(epoch=i, objective=dict(train_ce=.4, train_tail=.2,
            mixed_batches=(report['train_examples'] + 31) // 32,
            positive_only_batches=0, negative_only_batches=0)) for i in range(1, 21)])
    return report


class PureTests(unittest.TestCase):
    setUp = synthetic.E20Tests.setUp
    selected = synthetic.E20Tests.selected
    snapshots = synthetic.E20Tests.snapshots

    def test_exact_recipe_command_and_legacy_argv(self):
        self.assertEqual(G.config_for(NEW), dict(G.CONFIG, epochs=20, recipe=NEW,
            training_objective=OBJECTIVE, runtime_profile='cuda-deterministic-v1'))
        args = ('base', 'data', 'out', 'meta', 'report', 'cache', 'cuda')
        for recipe in (None, E20, 'context-v1-e20-denial-invariance-v1'):
            config = G.config_for(recipe)
            expected = [sys.executable, str(G.Path(G.__file__).with_name('train.py')),
                '--base-dir', 'base', '--metadata', 'meta', '--data', 'data', '--out', 'out',
                '--report', 'report', '--cache-dir', 'cache', '--no-amp', '--device', 'cuda',
                '--require-device', '--name', G.model_name(recipe), '--epochs', str(config['epochs']),
                '--batch', '32', '--lr', '0.0003', '--weight-decay', '0.01', '--warmup', '100', '--seed', '7']
            self.assertEqual(G.trainer_command(*args, recipe=recipe), expected)
        old = G.trainer_command(*args, recipe=E20)
        old[old.index('--name') + 1] = G.model_name(NEW)
        self.assertEqual(G.trainer_command(*args, recipe=NEW), old +
            ['--objective', OBJECTIVE, '--runtime-profile', 'cuda-deterministic-v1'])
        self.assertNotIn('training_views', G.config_for(NEW))

    def test_attempt4_both_boundaries_and_original377_denominator(self):
        for paired, normal, expected in ((46, 43, 'DEV_50_NOT_RULED_OUT'),
                (45, 43, 'DEV_50_MISS'), (46, 42, 'DEV_50_MISS')):
            selection, rows, snapshots = self.snapshots(paired, normal)
            # Synthetic additional original normals exercise the full denominator.
            extra = [dict(id='synthetic-extra-' + str(i), label='allow_ok') for i in range(201)]
            for snapshot in snapshots.values():
                snapshot['by_id'].update({r['id']: (None, 'LocalRule') for r in extra})
            result = G.development_reading(selection, rows + extra, snapshots, ['identical'] * 91, NEW)
            old = G.development_reading(selection, rows + extra, snapshots, ['identical'] * 91, E20)
            self.assertEqual(result, dict(old, recipe=NEW, candidate_attempt=4))
            self.assertEqual(result['sample_sha256'],
                '864ea9c6f39c3c2cc910aa5fa1af2bc0e0f3ce78279b2fc4d8f5c74f8cc8dce4')
            self.assertEqual(result['goal50']['reading'], expected)
            populations = result['goal50']['populations']
            self.assertEqual((populations['unpaired_normal']['selected'], populations['paired_normal']['selected']), (85, 91))
            for arm in G.ARMS:
                self.assertEqual(result['full_validation'][arm]['labels']['allow_ok']['original_rows'], 377)
            self.assertEqual(result['independent_quality'], 'UNKNOWN')
            self.assertEqual(result['independent_safety'], 'UNKNOWN')
            self.assertEqual(result['gate_b'], 'UNSUPPORTED')
            self.assertFalse(result['activation_authorized'])


class GlueTests(unittest.TestCase):
    setUp = fixtures.GlueTests.setUp
    write_source = fixtures.GlueTests.write_source
    report = fixtures.GlueTests.report
    fake_runtime = fixtures.GlueTests.fake_runtime
    fake_scorer = fixtures.GlueTests.fake_scorer

    def prepared(self):
        frozen = copy.deepcopy(self.frozen)
        frozen['config'] = dict(G.config_for(NEW), device='cuda')
        frozen['package_versions']['torch'] = '2.14.0+cu130'
        return frozen, upgrade(self.report(frozen, 'context'), frozen['package_versions'])

    def test_original_conversion_bytes_both_arms(self):
        for arm in G.ARMS:
            expected = self.frozen['converted'][arm]
            with patch.object(G, 'training_view_rows', side_effect=AssertionError('view forbidden')):
                actual = G.conversion(self.sets, self.frozen, self.c, arm, G.config_for(NEW).get('training_views'))
            self.assertEqual(C.canonical(actual), C.canonical(expected))
            self.assertNotIn('training_views', actual)

    def test_train_environment_opt_in_only(self):
        inherited = dict(SYNTHETIC_ENV='unchanged', PYTHONHASHSEED='owner',
                         CUBLAS_WORKSPACE_CONFIG='owner', NVIDIA_TF32_OVERRIDE='owner')
        for recipe in (None, E20, 'context-v1-e20-denial-invariance-v1', NEW):
            with patch.dict(os.environ, inherited, clear=True), patch.object(G.subprocess, 'run') as call:
                G.train_arm(self.base, self.data, 'cp', 'meta', 'report', self.root / 'cache', 'cuda', recipe)
                expected = dict(inherited, HF_HUB_OFFLINE='1', OMP_NUM_THREADS='4', MKL_NUM_THREADS='4')
                if recipe == NEW:
                    expected.update(ENV)
                self.assertEqual(call.call_args.kwargs, dict(env=expected, timeout=5400, check=True))
                self.assertEqual(dict(os.environ), inherited)

    def test_non_cuda_refused_before_output_or_project_import(self):
        for device in ('cpu', 'mps', 'auto'):
            out = self.root / ('no-' + device)
            with patch.object(G, 'originals', side_effect=AssertionError('source reached')):
                with self.assertRaisesRegex(C.Unsupported, 'requires CUDA'):
                    G.run(self.data, out, self.base, device, recipe=NEW)
            self.assertFalse(out.exists())

    def test_report_semantic_tamper_matrix(self):
        frozen, report = self.prepared()
        # An incomplete last batch must still count once.
        frozen['converted']['context']['counts']['train.jsonl']['selected'] = 4427
        report['train_examples'] = 4427
        for row in report['history']:
            row['objective']['mixed_batches'] = 139
        G.report_ok(report, frozen, 'context')
        def changed(path, value):
            bad = copy.deepcopy(report)
            node = bad
            for key in path[:-1]:
                node = node[key]
            node[path[-1]] = value
            return bad
        cases = [(['training_objective'], None), (['training_objective', 'id'], 'other'),
            (['history'], report['history'][:-1]), (['history', 0, 'objective', 'train_tail'], float('nan')),
            (['history', 0, 'objective', 'train_ce'], -1), (['history', 0, 'objective', 'mixed_batches'], 138),
            (['history', 0, 'objective', 'negative_only_batches'], True),
            (['runtime_profile', 'schema'], True), (['runtime_profile', 'seed'], 8),
            (['runtime_profile', 'effective', 'flags', 'warn_only'], True),
            (['runtime_profile', 'effective', 'flags', 'deterministic'], 1),
            (['runtime_profile', 'effective', 'environment', 'PYTHONHASHSEED'], '8'),
            (['runtime_profile', 'software', 'torch'], 'other'),
            (['runtime_profile', 'initial_head_sha256'], 'x' * 64)]
        for path, value in cases:
            with self.subTest(path=path), self.assertRaises(C.Unsupported):
                G.report_ok(changed(path, value), frozen, 'context')
        for recipe in (None, E20, 'context-v1-e20-denial-invariance-v1'):
            legacy = copy.deepcopy(self.frozen)
            legacy['config'] = dict(G.config_for(recipe), device='cpu')
            old = self.report(legacy, 'context')
            old['config']['epochs'] = legacy['config']['epochs']
            old.update(noul_temperature=1., version=G.model_name(recipe) + '+' + legacy['context']['sha256'][:8])
            G.report_ok(old, legacy, 'context')
            for key in ('training_objective', 'runtime_profile'):
                with self.assertRaises(C.Unsupported):
                    G.report_ok(dict(old, **{key: None}), legacy, 'context')

    def test_pure_conversion_checks_both_seals_without_loading_tensors(self):
        frozen, _ = self.prepared()
        frozen.update(threshold=.5, control_threshold=.5,
            development_reading=dict(recipe=NEW, thresholds=dict(context=.5, control=.5)))
        def reports(change=None):
            for arm in G.ARMS:
                report = upgrade(self.report(frozen, arm), frozen['package_versions'])
                if arm == 'control' and change:
                    change(report)
                path = self.root / (arm + '-batch-tail-report.json')
                path.write_bytes(C.canonical(report))
                frozen['training_reports'][arm] = G.record(path)
        loader = Mock(side_effect=AssertionError('pure verification loaded tensors'))
        with patch.object(G, 'development_selection', return_value=None), \
             patch.dict(sys.modules, common=NS(load_checkpoint=loader)):
            reports()
            G.verify_conversion(frozen, self.c)
            def head(report):
                report['runtime_profile']['initial_head_sha256'] = 'b' * 64
            def software(report):
                report['runtime_profile']['software']['device']['name'] = 'NVIDIA A10'
            for change in (head, software):
                reports(change)
                with self.assertRaisesRegex(C.Unsupported, 'cross-arm'):
                    G.verify_conversion(frozen, self.c)
            loader.assert_not_called()

    def test_fake_whole_run_binding_identity_and_no_freeze_on_tamper(self):
        import context_dev_diagnostic as d0
        from context_eval import CLASSES
        for tamper in (None, 'missing_objective', 'swapped_objective', 'runtime_metadata',
                       'head_hash', 'software', 'batch_count', 'report_objective'):
            with self.subTest(tamper=tamper):
                self.frozen['package_versions']['torch'] = '2.14.0+cu130'
                core, common, caches, remember, legacy_train = self.fake_runtime()
                core.Scorer.temperature = 1.
                original_item = core.Scorer.item
                def item(scorer, row, facts_blind=False):
                    value = original_item(scorer, row, facts_blind)
                    value['cache_key'] = tuple(value['ids'])
                    return value
                core.Scorer.item = item
                observed = {}
                def originals(*args):
                    observed['sets'] = remember(*args)
                    return observed['sets']
                def select(sets, *args):
                    self.assertIs(sets, observed['sets'])
                    selected = d0.select_rows(sets['val'], tuple(CLASSES), C.serialize, C.Refusal, self.c, {})
                    observed['selection'] = selected
                    return selected
                original_preflight = G.exact_preflight
                def preflight(scorer, sets, c, arm):
                    self.assertIs(sets, observed['sets'])
                    original_preflight(scorer, sets, c, arm)
                def fit(scorer, rows, arm):
                    self.assertIs(rows, observed['sets']['val'])
                    scorer.last_scores, scorer.last_refusals = [], []
                    for row in rows:
                        converted, counts = R.convert_rows([row], self.c, facts_blind=arm == 'control')
                        refusal = 'LocalRule' if counts['local_rule'] else 'OverBudget' if counts['OverBudget'] else None
                        scorer.last_refusals.append(refusal)
                        scorer.last_scores.append(None if refusal else .8 if arm == 'context' and converted[0]['answer'] == 1 else .2)
                    return .5, len(rows)
                core.fit_threshold = Mock(side_effect=fit)
                def train(*args, recipe=None):
                    self.assertEqual(recipe, NEW)
                    self.assertEqual(args[-1], 'cuda')
                    metadata = json.loads(args[3].read_bytes())
                    self.assertNotIn('training_views', metadata)
                    self.assertNotIn('training_objective', metadata)  # Trainer owns it.
                    legacy_train(*args)
                    report = upgrade(json.loads(args[4].read_bytes()), self.frozen['package_versions'])
                    if args[2].stem == 'control':
                        if tamper == 'head_hash':
                            report['runtime_profile']['initial_head_sha256'] = 'b' * 64
                        elif tamper == 'software':
                            report['runtime_profile']['software']['device']['name'] = 'NVIDIA A10'
                    if tamper == 'batch_count':
                        report['history'][0]['objective']['mixed_batches'] += 1
                    if tamper == 'report_objective':
                        report['training_objective']['id'] = 'other'
                    args[4].write_bytes(C.canonical(report))
                    metadata.update(trained=['head.'], epoch=20, base_repo=self.frozen['base']['repo'],
                        noul_temperature=1., training_objective=OBJECTIVE, runtime_profile=copy.deepcopy(report['runtime_profile']))
                    if tamper == 'missing_objective':
                        metadata.pop('training_objective')
                    elif tamper == 'swapped_objective':
                        metadata['training_objective'] = 'other'
                    elif tamper == 'runtime_metadata':
                        metadata['runtime_profile']['seed'] = 8
                    common.load_checkpoint.return_value = ({'head.x': 'fake'}, metadata)
                original_snapshot, original_reading, original_keys = G.calibration_snapshot, G.development_reading, G.blind_pair_keys
                def snapshot(scorer, rows, tau):
                    self.assertIs(rows, observed['sets']['val'])
                    return original_snapshot(scorer, rows, tau)
                def reading(selection, rows, *args):
                    self.assertIs(selection, observed['selection'])
                    self.assertIs(rows, observed['sets']['val'])
                    return original_reading(selection, rows, *args)
                def keys(scorer, rows, pairs):
                    self.assertIs(rows, observed['selection'][1])
                    self.assertIs(pairs, observed['selection'][2])
                    return original_keys(scorer, rows, pairs)
                out = self.root / ('batch-tail-' + str(tamper))
                with patch.dict(sys.modules, {'context_train': core, 'torch': NS(cuda=NS(is_available=lambda: True)), 'common': common}), \
                     patch.object(G, 'originals', side_effect=originals), \
                     patch.object(G, 'development_selection', side_effect=select), \
                     patch.object(G, 'exact_preflight', side_effect=preflight), \
                     patch.object(G, 'calibration_snapshot', side_effect=snapshot), \
                     patch.object(G, 'development_reading', side_effect=reading), \
                     patch.object(G, 'blind_pair_keys', side_effect=keys), \
                     patch.object(G, 'training_view_rows', side_effect=AssertionError('view forbidden')), \
                     patch.object(G, 'train_arm', side_effect=train):
                    if tamper is None:
                        frozen = G.run(self.data, out, self.base, 'cuda', recipe=NEW)
                        self.assertEqual(json.loads((out / 'freeze.json').read_bytes()), frozen)
                        self.assertEqual(frozen['development_reading']['candidate_attempt'], 4)
                        self.assertEqual(core.fit_threshold.call_count, 2)
                    else:
                        with self.assertRaises(C.Unsupported):
                            G.run(self.data, out, self.base, 'cuda', recipe=NEW)
                        self.assertFalse((out / 'freeze.json').exists())
                for cache in caches:
                    cache.close.assert_called_once()


if __name__ == '__main__':
    unittest.main()
