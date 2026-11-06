"""Synthetic source-preparation coverage; execute only in later hosted CI."""
import copy
import json
import sys
import unittest
from types import SimpleNamespace as NS
from unittest.mock import Mock, patch

import test_context_existing_freeze as fixtures
import test_context_e20_recipe as synthetic

G, C, R = fixtures.G, fixtures.C, fixtures.R
NEW = 'context-v1-e20-denial-invariance-v1'
E20 = 'context-v1-e20'
POLICY = 'denial-balanced-v1'


class DenialPureTests(unittest.TestCase):
    setUp = synthetic.E20Tests.setUp
    selected = synthetic.E20Tests.selected
    snapshots = synthetic.E20Tests.snapshots

    def test_exact_config_command_and_unknown_profile(self):
        old, new = G.config_for(E20), G.config_for(NEW)
        self.assertEqual({k for k in old.keys() | new.keys() if old.get(k) != new.get(k)},
                         {'recipe', 'training_views'})
        self.assertEqual(new, dict(G.CONFIG, epochs=20, recipe=NEW, training_views=POLICY))
        for recipe in (None, E20):
            self.assertNotIn('training_views', G.config_for(recipe))
        for bad in ('denial-balanced-v1', NEW + '-other', {}, True):
            with self.assertRaises(C.Unsupported):
                G.config_for(bad)
        args = ('base', 'data', 'out', 'meta', 'report', 'cache', 'cpu')
        old_cmd, new_cmd = G.trainer_command(*args, recipe=E20), G.trainer_command(*args, recipe=NEW)
        index = old_cmd.index('--name') + 1
        self.assertEqual(new_cmd[index], 'apassy-' + NEW)
        new_cmd[index] = old_cmd[index]
        self.assertEqual(old_cmd, new_cmd)
        for recipe in (None, E20):
            frozen = dict(config=dict(G.config_for(recipe), device='cpu', training_views=POLICY))
            with self.assertRaises(C.Unsupported):
                G.frozen_config(frozen)

    def test_attempt3_fixed_sample_thresholds_and_boundaries(self):
        for paired, normal, reading in ((46, 43, 'DEV_50_NOT_RULED_OUT'),
                                        (45, 43, 'DEV_50_MISS'), (46, 42, 'DEV_50_MISS')):
            selection, rows, snapshots = self.snapshots(paired, normal)
            result = G.development_reading(selection, rows, snapshots, ['identical'] * 91, NEW)
            old = G.development_reading(selection, rows, snapshots, ['identical'] * 91, E20)
            self.assertEqual(result, dict(old, recipe=NEW, candidate_attempt=3))
            self.assertEqual(old['candidate_attempt'], 2)
            self.assertEqual(result['sample_sha256'], G.D0_SAMPLE_SHA256)
            self.assertEqual(result['goal50']['reading'], reading)
            self.assertEqual(result['thresholds'], dict(context=.5, control=.5))
            populations = result['goal50']['populations']
            self.assertEqual((populations['paired_normal']['selected'],
                              populations['paired_normal']['minimum_auto_allow']), (91, 46))
            self.assertEqual((populations['unpaired_normal']['selected'],
                              populations['unpaired_normal']['minimum_auto_allow']), (85, 43))
            self.assertEqual(result['full_validation']['context']['labels']['allow_ok']['original_rows'], 176)
            self.assertEqual(result['gate_b'], 'UNSUPPORTED')
            self.assertFalse(result['activation_authorized'])


class DenialGlueTests(unittest.TestCase):
    setUp = fixtures.GlueTests.setUp
    write_source = fixtures.GlueTests.write_source
    report = fixtures.GlueTests.report
    fake_runtime = fixtures.GlueTests.fake_runtime
    fake_scorer = fixtures.GlueTests.fake_scorer

    def test_conversion_default_bytes_summary_inputs_and_count_guard(self):
        for arm in G.ARMS:
            old = self.frozen['converted'][arm]
            self.assertEqual(C.canonical(G.conversion(self.sets, self.frozen, self.c, arm)), C.canonical(old))
            self.assertEqual(C.canonical(G.conversion(self.sets, self.frozen, self.c, arm, None)), C.canonical(old))
            with patch.object(G, 'training_view_summary', wraps=R.training_view_summary) as summary:
                new = G.conversion(self.sets, self.frozen, self.c, arm, POLICY)
            self.assertIs(summary.call_args.args[0], self.sets['train'])
            selected = R.convert_rows(R.training_view_rows(self.sets['train'], POLICY), self.c,
                                      facts_blind=arm == 'control')[0]
            self.assertEqual(summary.call_args.args[1], selected)
            self.assertEqual(new['training_views'], R.training_view_summary(self.sets['train'], selected, POLICY))
            self.assertEqual(set(new['training_views']), {'policy', 'view_counts', 'distinct_train_states'})
            self.assertEqual(new['counts'], old['counts'])
            self.assertEqual(new['output_sha256']['val.jsonl'], old['output_sha256']['val.jsonl'])
            if arm == 'control':
                self.assertEqual(new['output_sha256'], old['output_sha256'])
        original = R.convert_rows
        def changed_counts(rows, *args, **kwargs):
            selected, counts = original(rows, *args, **kwargs)
            if rows is not self.sets['train']:
                counts = dict(counts, selected=counts['selected'] + 1)
            return selected, counts
        with patch.object(G, 'convert_rows', side_effect=changed_counts):
            with self.assertRaisesRegex(C.Unsupported, 'counts differ'):
                G.conversion(self.sets, self.frozen, self.c, 'context', POLICY)
        with self.assertRaises(C.Unsupported):
            G.conversion(self.sets, self.frozen, self.c, 'context', 'unknown')

    def test_report_4427_slots_best_epoch20(self):
        frozen = copy.deepcopy(self.frozen)
        frozen['config'] = dict(G.config_for(NEW), device='cpu')
        frozen['converted']['context']['counts']['train.jsonl']['selected'] = 4427
        report = self.report(frozen, 'context')
        report['config']['epochs'] = 20
        report.update(best_epoch=20, noul_temperature=1.,
                      version=G.model_name(NEW) + '+' + frozen['context']['sha256'][:8])
        G.report_ok(report, frozen, 'context')
        for change in (dict(best_epoch=21), dict(train_examples=4426)):
            with self.assertRaises(C.Unsupported):
                G.report_ok(dict(report, **change), frozen, 'context')

    def test_policy_removed_swapped_or_source_changed_refuses(self):
        frozen = copy.deepcopy(self.frozen)
        frozen.update(config=dict(G.config_for(NEW), device='cpu'), threshold=.5, control_threshold=.5,
                      development_reading=dict(recipe=NEW, thresholds=dict(context=.5, control=.5)))
        frozen['converted'] = {arm: G.conversion(self.sets, frozen, self.c, arm, POLICY) for arm in G.ARMS}
        for arm in G.ARMS:
            report = self.report(frozen, arm)
            report['config']['epochs'] = 20
            report.update(noul_temperature=1., version=G.model_name(NEW) + '+' + frozen[arm]['sha256'][:8])
            path = self.root / (arm + '-new-report.json')
            path.write_bytes(C.canonical(report))
            frozen['training_reports'][arm] = G.record(path)
        with patch.object(G, 'development_selection', return_value=None):
            G.verify_conversion(frozen, self.c)
            for arm in G.ARMS:
                for kind in ('removed', 'swapped', 'source'):
                    bad = copy.deepcopy(frozen)
                    provenance = bad['converted'][arm]
                    if kind == 'removed':
                        provenance.pop('training_views')
                    elif kind == 'swapped':
                        provenance['training_views']['policy'] = 'other'
                    else:
                        provenance['source_sha256']['train.jsonl'] = '0' * 64
                    with self.assertRaisesRegex(C.Unsupported, 'conversion provenance'):
                        G.verify_conversion(bad, self.c)
            for policy in (None, 'other'):
                bad = copy.deepcopy(frozen)
                if policy is None:
                    bad['config'].pop('training_views')
                else:
                    bad['config']['training_views'] = policy
                with self.assertRaises(C.Unsupported):
                    G.verify_conversion(bad, self.c)

    def test_complete_fake_run_original_validation_and_loaded_metadata_binding(self):
        import context_train as actual_core
        import context_dev_diagnostic as d0
        from context_eval import CLASSES
        for tamper in (None, 'removed', 'swapped', 'recipe'):
            with self.subTest(tamper=tamper):
                core, common, caches, remember, legacy_train = self.fake_runtime()
                core.context_meta_ok = actual_core.context_meta_ok
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
                    value = d0.select_rows(sets['val'], tuple(CLASSES), C.serialize, C.Refusal, self.c, {})
                    observed['selection'] = value
                    return value
                def preflight(scorer, sets, c, arm):
                    self.assertIs(sets['val'], observed['sets']['val'])
                    self.assertIsNot(sets['train'], observed['sets']['train'])
                    self.assertNotEqual(sets['train'], observed['sets']['train'])
                    self.assertEqual(sets['train'], R.training_view_rows(observed['sets']['train'], POLICY))
                    G.exact_preflight(scorer, sets, c, arm)
                def fit(scorer, rows, arm):
                    self.assertIs(rows, observed['sets']['val'])
                    scorer.last_scores, scorer.last_refusals = [], []
                    for row in rows:
                        selected, counts = R.convert_rows([row], self.c, facts_blind=arm == 'control')
                        refusal = 'LocalRule' if counts['local_rule'] else 'OverBudget' if counts['OverBudget'] else None
                        scorer.last_refusals.append(refusal)
                        scorer.last_scores.append(None if refusal else .8 if arm == 'context' and selected[0]['answer'] == 1 else .2)
                    return .5, len(rows)
                core.fit_threshold = Mock(side_effect=fit)
                def train(*args, recipe=None):
                    self.assertEqual(recipe, NEW)
                    metadata = json.loads(args[3].read_bytes())
                    self.assertEqual(metadata['training_views'], POLICY)
                    legacy_train(*args)
                    report = json.loads(args[4].read_bytes())
                    report['config']['epochs'] = 20
                    report.update(best_epoch=20, noul_temperature=1.,
                                  version=G.model_name(NEW) + '+' + report['sha256'][:8])
                    args[4].write_bytes(C.canonical(report))
                    metadata.update(trained=['head.'], epoch=20, base_repo=self.frozen['base']['repo'],
                                    base_revision=C.REVISION, noul_temperature=1.)
                    self.assertTrue(actual_core.context_meta_ok(metadata, args[2].stem, self.c,
                        self.frozen['base']['weights_sha256'], recipe=NEW))
                    self.assertFalse(actual_core.context_meta_ok(metadata, args[2].stem, self.c,
                        self.frozen['base']['weights_sha256'], recipe=E20))
                    if tamper == 'removed':
                        metadata.pop('training_views')
                    elif tamper == 'swapped':
                        metadata['training_views'] = 'other'
                    elif tamper == 'recipe':
                        metadata['recipe'] = E20
                    common.load_checkpoint.return_value = ({'head.x': 'fake'}, metadata)
                original_preflight = G.exact_preflight
                def checked_preflight(*args):
                    with patch.object(G, 'exact_preflight', original_preflight):
                        preflight(*args)
                original_snapshot = G.calibration_snapshot
                def snapshot(scorer, rows, tau):
                    self.assertIs(rows, observed['sets']['val'])
                    return original_snapshot(scorer, rows, tau)
                original_keys = G.blind_pair_keys
                def keys(scorer, rows, pairs):
                    self.assertIs(rows, observed['selection'][1])
                    self.assertIs(pairs, observed['selection'][2])
                    return original_keys(scorer, rows, pairs)
                original_reading = G.development_reading
                def reading(selection, rows, *args):
                    self.assertIs(selection, observed['selection'])
                    self.assertIs(rows, observed['sets']['val'])
                    return original_reading(selection, rows, *args)
                out = self.root / ('run-' + str(tamper))
                # Pin enforcement is separately tested by legacy tests; synthetic selection only here.
                with patch.dict(sys.modules, {'context_train': core, 'torch': NS(), 'common': common}), \
                     patch.object(G, 'originals', side_effect=originals), \
                     patch.object(G, 'development_selection', side_effect=select), \
                     patch.object(G, 'exact_preflight', side_effect=checked_preflight) as exact, \
                     patch.object(G, 'calibration_snapshot', side_effect=snapshot), \
                     patch.object(G, 'blind_pair_keys', side_effect=keys), \
                     patch.object(G, 'development_reading', side_effect=reading), \
                     patch.object(G, 'export_rows', wraps=R.export_rows) as export, \
                     patch.object(G, 'train_arm', side_effect=train):
                    if tamper:
                        with self.assertRaisesRegex(C.Unsupported, 'metadata mismatch'):
                            G.run(self.data, out, self.base, 'cpu', recipe=NEW)
                        self.assertFalse((out / 'freeze.json').exists())
                    else:
                        frozen = G.run(self.data, out, self.base, 'cpu', recipe=NEW)
                        self.assertEqual(json.loads((out / 'freeze.json').read_bytes()), frozen)
                        self.assertEqual(frozen['development_reading']['candidate_attempt'], 3)
                        self.assertEqual(frozen['development_reading']['thresholds'], dict(context=.5, control=.5))
                        self.assertEqual(frozen['development_reading']['sample_sha256'], observed['selection'][0]['sample_sha256'])
                        self.assertEqual(core.fit_threshold.call_count, 2)
                        self.assertEqual(export.call_count, 2)
                        for call in export.call_args_list:
                            self.assertEqual(call.kwargs['training_views'], POLICY)
                    self.assertEqual(exact.call_count, 2)
                for cache in caches:
                    cache.close.assert_called_once()


if __name__ == '__main__':
    unittest.main()
