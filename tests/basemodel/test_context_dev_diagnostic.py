"""Synthetic-only D0 checks; no project imports or irreversible audit hooks."""
import ast
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ENTRY = Path(__file__).resolve().parents[2] / 'tools/basemodel/context_dev_diagnostic.py'


def load_entry():
    # Never insert project directories or stubs into process-global sys.modules.
    spec = importlib.util.spec_from_file_location('_d0_test_entry', ENTRY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Refusal(ValueError):
    pass


def serialize(request, action, secrets, contract):
    if request.get('over'):
        raise Refusal()
    return 'synthetic', 1


def row(name, label='allow_ok', cls='alpha', **updates):
    result = dict(id=name, family='family-' + name, label=label, **{'class': cls},
                  request={'synthetic': True}, action='read', secrets=[],
                  injection_of=None, local_rule=None, pair_of=None)
    result.update(updates)
    return result


def twin(name, cls='alpha', **updates):
    a = row(name + '-allow', cls=cls)
    m = row(name + '-must', label='must_ask', cls=cls, pair_of=a['id'], **updates)
    return [a, m]


def fake_auc(rows, values, indices):
    # Fixtures below only need a definedness marker. Numeric AUROC is the
    # original evaluator's responsibility, not a second implementation here.
    labels = {rows[i]['label'] for i in indices}
    return .5 if len(labels) == 2 else None


class SelectionTests(unittest.TestCase):
    def setUp(self):
        self.d = load_entry()

    def select(self, rows, classes=('alpha',)):
        return self.d.select_rows(rows, classes, serialize, Refusal, {}, {})

    def test_hash_order_caps_disjoint_and_permutation_invariant(self):
        rows = sum((twin(str(i)) for i in range(30)), [])
        rows += [row('unpaired-' + str(i)) for i in range(30)]
        first = self.select(rows)
        second = self.select(list(reversed(rows)))
        self.assertEqual(first[0], second[0])
        self.assertEqual([r['id'] for r in first[1]], [r['id'] for r in second[1]])
        selection, chosen, pairs, unpaired = first
        self.assertEqual((len(chosen), len(pairs), len(unpaired)), (60, 20, 20))
        self.assertEqual(len({r['id'] for r in chosen}), 60)
        expected = sorted((r for r in rows if r['pair_of']),
                          key=lambda r: self.d.sample_key(r['pair_of'], r['id']))[:20]
        self.assertEqual([chosen[m]['id'] for a, m in pairs], [r['id'] for r in expected])
        self.assertEqual(selection['classes']['alpha']['pair_exclusions']['pair_limit'], 10)
        self.assertEqual(selection['classes']['alpha']['unpaired_exclusions']['referenced_by_pair'], 30)

    def test_true_unpaired_excludes_unselected_twins(self):
        rows = sum((twin(str(i)) for i in range(21)), [])
        selection, chosen, _, unpaired = self.select(rows)
        self.assertEqual(unpaired, [])
        self.assertEqual(selection['unpaired_allows'], 0)
        self.assertEqual(selection['classes']['alpha']['unpaired_shortfall'], 20)

    def test_context_budget_both_ends_and_exclusion_reasons(self):
        rows = twin('over')
        for r in rows:
            r['request'] = {'over': True}
        rows += twin('injection', injection_of='synthetic')
        rows += twin('local', local_rule='synthetic')
        rows += twin('cross')
        rows[-1]['class'] = 'beta'
        selection, chosen, _, _ = self.select(rows)
        self.assertEqual(chosen, [])
        for reason in ('context_budget', 'injection', 'local_rule', 'cross_class'):
            self.assertEqual(selection['classes']['alpha']['pair_exclusions'][reason], 1)

    def test_shared_pair_end_never_reused(self):
        rows = twin('shared')
        rows.append(row('extra-must', label='must_ask', pair_of=rows[0]['id']))
        selection, chosen, pairs, _ = self.select(rows)
        self.assertEqual(len(pairs), 1)
        self.assertEqual(len(chosen), 2)
        self.assertEqual(selection['classes']['alpha']['pair_exclusions']['row_reuse'], 1)

    def test_reciprocal_pair_is_deduplicated(self):
        rows = twin('reciprocal')
        rows[0]['pair_of'] = rows[1]['id']
        self.assertEqual(len(self.select(rows)[2]), 1)

    def test_invalid_pair_refuses(self):
        for change in ({'pair_of': 'missing'}, {'label': 'allow_ok'}, {'request': {'different': True}}):
            rows = twin('bad')
            rows[-1].update(change)
            with self.assertRaises(self.d.DiagnosticError):
                self.select(rows)

    def test_300_row_envelope_and_class_families(self):
        classes = tuple('abcde')
        rows = []
        for cls in classes:
            rows.extend(sum((twin(cls + str(i), cls=cls) for i in range(21)), []))
            rows.extend(row(cls + 'u' + str(i), cls=cls) for i in range(21))
        selection, chosen, _, _ = self.select(rows, classes)
        self.assertEqual(len(chosen), 300)
        self.assertEqual(selection['classes']['a']['paired_distinct_families'], 40)
        self.assertEqual(selection['classes']['a']['unpaired_distinct_families'], 20)

    def test_selection_closed_and_private(self):
        selection, _, _, _ = self.select(twin('PRIVATE-ID') + [row('PRIVATE-NORMAL')])
        self.assertEqual(set(selection), {'report_kind', 'identities', 'policy', 'sample_sha256',
                                         'classes', 'rows', 'pairs', 'unpaired_allows'})
        raw = self.d.canonical(selection).decode()
        self.assertNotIn('PRIVATE', raw)
        self.assertNotIn('synthetic', raw)
        self.assertEqual(len(selection['sample_sha256']), 64)


class AggregateTests(unittest.TestCase):
    def setUp(self):
        self.d = load_entry()
        self.rows = twin('private') + [row('private-unpaired')]
        self.scores = dict(context=[.9, .1, .7], control=[.2, .2, .8])
        self.refusals = {a: [None]*3 for a in self.d.ARMS}

    def aggregate(self, keys=('identical',)):
        return self.d.aggregate(self.rows, [(0, 1)], [2], self.scores, self.refusals,
                                list(keys), dict(context=.7, control=.5), ('alpha',), fake_auc)

    def test_separate_denominators_and_structural_labels(self):
        metrics = self.aggregate()
        paired = metrics['populations']['paired']['overall']
        normal = metrics['populations']['unpaired_normal']['overall']
        self.assertEqual((paired['comparable'], paired['complete_pairs']), (2, 1))
        control = paired['arms']['control']
        self.assertEqual(control['auroc_interpretation'], 'structurally_0.5')
        self.assertEqual(control['pair_ordering']['tied'], 1)
        self.assertEqual(control['labels']['allow_ok']['interpretation'], 'identical_control_twins')
        self.assertEqual(control['labels']['must_ask']['interpretation'], 'calibration_reproduction')
        self.assertEqual(normal['arms']['control']['labels']['allow_ok']['auto_allow_rate'], 1.)
        self.assertEqual(normal['arms']['control']['auroc'], None)
        self.assertEqual(normal['arms']['control']['auroc_interpretation'], 'reused_calibration_population')

    def test_different_text_does_not_claim_structure(self):
        control = self.aggregate(('different',))['populations']['paired']['overall']['arms']['control']
        self.assertEqual(control['auroc_interpretation'], 'reused_calibration_population')
        self.assertEqual(control['pair_ordering_interpretation'], 'reused_calibration_population')

    def test_comparable_requires_both_arms_complete_requires_both_ends(self):
        self.scores['control'][1] = None
        self.refusals['control'][1] = 'ExactOverflow'
        p = self.aggregate(('incomparable',))['populations']['paired']['overall']
        self.assertEqual((p['selected'], p['comparable'], p['complete_pairs']), (2, 1, 0))
        self.assertEqual(p['arms']['context']['labels']['must_ask']['comparable'], 0)
        self.assertEqual(p['arms']['control']['labels']['must_ask']['refused']['ExactOverflow'], 1)
        self.assertEqual(p['arms']['context']['pair_ordering']['incomparable'], 0)
        self.assertEqual(p['arms']['context']['complete_pairs'], 1)
        self.assertEqual(p['arms']['control']['complete_pairs'], 0)

    def test_nonfinite_unavailable_and_empty_denominator(self):
        self.scores['context'] = [None, float('nan'), None]
        p = self.aggregate()['populations']['paired']['overall']
        self.assertEqual(p['comparable'], 0)
        self.assertIsNone(p['arms']['context']['labels']['allow_ok']['auto_allow_rate'])
        self.assertEqual(p['arms']['context']['labels']['must_ask']['unavailable'], 1)

    def test_equal_control_keys_unequal_finite_is_fatal(self):
        self.scores['control'][1] = .21
        with self.assertRaisesRegex(self.d.DiagnosticError, '^control_nondeterminism$'):
            self.aggregate()

    def test_ordered_inverted_and_tied(self):
        for values, field in (([.9, .1, .7], 'ordered'), ([.1, .9, .7], 'inverted'), ([.2, .2, .7], 'tied')):
            self.scores['context'] = values
            p = self.aggregate()['populations']['paired']['overall']
            self.assertEqual(p['arms']['context']['pair_ordering'][field], 1)

    def test_histogram_edges(self):
        self.assertEqual(self.d.histogram([0, .099, .1, .2, .3, .4, .5, .6, .7, .8, .9, 1,
                                          None, float('nan'), -.1, 1.1]), [2, 1, 1, 1, 1, 1, 1, 1, 1, 2])

    def test_closed_aggregate_and_privacy(self):
        metrics = self.aggregate()
        self.assertEqual(set(metrics), {'populations', 'histograms'})
        p = metrics['populations']['paired']['overall']
        self.assertEqual(set(p), {'selected', 'comparable', 'selected_pairs', 'complete_pairs', 'blind_cache_keys', 'arms'})
        for arm in self.d.ARMS:
            self.assertEqual(set(p['arms'][arm]), {'labels', 'pair_ordering', 'complete_pairs', 'pair_ordering_rate',
                'pair_ordering_interpretation', 'auroc', 'auroc_interpretation'})
        raw = self.d.canonical(metrics).decode()
        for secret in ('private', 'request', 'secrets', 'cache_key"', 'outcome', 'PASS', 'FAIL', 'quantile', 'delta'):
            self.assertNotIn(secret, raw)

    def test_unknown_refusal_is_fixed_error(self):
        self.refusals['context'][0] = 'private error text'
        with self.assertRaisesRegex(self.d.DiagnosticError, '^refusal_code$'):
            self.aggregate()


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.d = load_entry()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.args = SimpleNamespace(command='score', repo_root=str(self.root), freeze=str(self.root/'freeze.json'),
            expect_freeze_sha256=self.d.FREEZE, binding=str(self.root/'binding.json'),
            selection=str(self.root/'selection.json'), base_dir=str(self.root/'base'), out=str(self.root/'out.json'))
        self.binding = dict(report_kind='development_diagnostic', training_source_sha=self.d.S,
            evaluation_source_sha='a'*40, entry_sha256=self.d.digest(ENTRY.read_bytes()),
            bundle_sha256=self.d.BUNDLE, freeze_sha256=self.d.FREEZE, run_id=self.d.RUN_ID)
        Path(self.args.binding).write_bytes(self.d.canonical(self.binding))

    def fake_git(self, repo, *args):
        if args == ('rev-parse', 'HEAD'):
            return self.d.S.encode()
        if args == ('rev-parse', '--show-toplevel'):
            return str(self.root).encode()
        if args[0] == 'show':
            return ENTRY.read_bytes()
        return b''

    def test_closed_binding_guard_before_import_or_data(self):
        self.binding['extra'] = 'private'
        Path(self.args.binding).write_bytes(self.d.canonical(self.binding))
        with patch.object(self.d, 'source_modules') as source:
            with self.assertRaisesRegex(self.d.DiagnosticError, '^binding_schema$'):
                self.d.prepare(self.args)
            source.assert_not_called()

    def test_output_exists_before_binding_read(self):
        Path(self.args.out).write_bytes(b'preserve')
        Path(self.args.binding).unlink()
        with self.assertRaisesRegex(self.d.DiagnosticError, '^output_exists$'):
            self.d.binding_guard(self.args)
        self.assertEqual(Path(self.args.out).read_bytes(), b'preserve')

    def test_github_sha_remains_actual(self):
        with patch.dict(os.environ, {'GITHUB_SHA': 'b'*40}):
            with self.assertRaisesRegex(self.d.DiagnosticError, '^evaluation_source$'):
                self.d.binding_guard(self.args)
            self.assertEqual(os.environ['GITHUB_SHA'], 'b'*40)

    def test_entry_git_blob_and_source_head(self):
        with patch.dict(os.environ, {'GITHUB_SHA': 'a'*40}), patch.object(self.d, 'git', side_effect=self.fake_git):
            self.assertEqual(self.d.binding_guard(self.args, ENTRY)[0], self.binding)
        def wrong(repo, *args):
            return b'b'*40 if args == ('rev-parse', 'HEAD') else self.fake_git(repo, *args)
        with patch.dict(os.environ, {'GITHUB_SHA': 'a'*40}), patch.object(self.d, 'git', side_effect=wrong):
            with self.assertRaisesRegex(self.d.DiagnosticError, '^source_commit$'):
                self.d.binding_guard(self.args, ENTRY)
        def changed(repo, *args):
            return b'changed entry' if args[0] == 'show' else self.fake_git(repo, *args)
        with patch.dict(os.environ, {'GITHUB_SHA': 'a'*40}), patch.object(self.d, 'git', side_effect=changed):
            with self.assertRaisesRegex(self.d.DiagnosticError, '^entry_binding$'):
                self.d.binding_guard(self.args, ENTRY)

    def test_frozen_source_refusal_precedes_original_data_read(self):
        frozen = {'source_commit': 'wrong-source'}
        Path(self.args.freeze).write_bytes(self.d.canonical(frozen))
        core = SimpleNamespace(verify_freeze=lambda *a: self.fail('data verifier reached'))
        v = SimpleNamespace(load_contract=lambda: self.fail('contract reached'))
        original = SimpleNamespace(originals=lambda *a: self.fail('rows reached'))
        # Override only the hash helper to exercise the next ordered guard.
        with patch.object(self.d, 'binding_guard', return_value=(self.binding, self.root)), \
             patch.object(self.d, 'source_modules', return_value=(core, v, original, object())), \
             patch.object(self.d, 'digest', return_value=self.d.FREEZE):
            with self.assertRaisesRegex(self.d.DiagnosticError, '^freeze_source$'):
                self.d.prepare(self.args)

    def test_module_origin_refusal_restores_test_sys_path(self):
        previous = sys.path[:]
        try:
            with patch.object(self.d.importlib.util, 'find_spec', return_value=SimpleNamespace(origin='/wrong/context_train.py')):
                with self.assertRaisesRegex(self.d.DiagnosticError, '^module_source$'):
                    self.d.source_modules(self.root)
        finally:
            sys.path[:] = previous

    def prepared(self):
        return (object(), object(), SimpleNamespace(CLASSES=('alpha',)), {},
                dict(threshold=.7, control_threshold=.5), {'sample_sha256': 'x', 'identities': {}}, [], [], [])

    def test_selection_mismatch_before_model(self):
        Path(self.args.selection).write_bytes(b'{}\n')
        with patch.object(self.d, 'prepare', return_value=self.prepared()), patch.object(self.d, 'score_selected') as score:
            with self.assertRaisesRegex(self.d.DiagnosticError, '^selection_binding$'):
                self.d.execute(self.args)
            score.assert_not_called()
        self.assertFalse(Path(self.args.out).exists())

    def test_select_does_not_score(self):
        self.args.command = 'select'
        with patch.object(self.d, 'prepare', return_value=self.prepared()), patch.object(self.d, 'score_selected') as score:
            self.d.execute(self.args)
            score.assert_not_called()
        self.assertEqual(json.loads(Path(self.args.out).read_bytes())['sample_sha256'], 'x')

    def test_fatal_emits_no_metrics_or_raw_exception(self):
        prepared = self.prepared()
        Path(self.args.selection).write_bytes(self.d.canonical(prepared[5]))
        err = io.StringIO()
        with patch.object(self.d, 'prepare', return_value=prepared), patch.object(self.d, 'score_selected',
                side_effect=RuntimeError('PRIVATE MODEL ROW')), patch.object(self.d, 'parser') as parser:
            parser.return_value.parse_args.return_value = self.args
            with contextlib.redirect_stderr(err):
                self.assertEqual(self.d.main([]), 2)
        self.assertEqual(err.getvalue(), 'diagnostic_refused\n')
        self.assertFalse(Path(self.args.out).exists())

    def test_report_closed_authority_fields(self):
        prepared = self.prepared()
        Path(self.args.selection).write_bytes(self.d.canonical(prepared[5]))
        with patch.object(self.d, 'prepare', return_value=prepared), patch.object(self.d, 'score_selected',
                return_value=dict(populations={}, histograms={})):
            self.d.execute(self.args)
        report = json.loads(Path(self.args.out).read_bytes())
        self.assertEqual(set(report), {'report_kind', 'identities', 'sample_sha256', 'selection_sha256',
            'thresholds', 'data_reused_for_calibration', 'independent_quality', 'gate_b',
            'activation_authorized', 'reading_rule', 'not_measured', 'populations', 'histograms'})
        self.assertEqual(report['independent_quality'], 'UNKNOWN')
        self.assertEqual(report['gate_b'], 'UNSUPPORTED')
        self.assertIs(report['activation_authorized'], False)
        self.assertEqual(report['reading_rule']['reaching_reference'], 'not ruled out')

    def test_exclusive_atomic_write_cleanup(self):
        path = self.root/'evidence.json'
        self.d.write_exclusive(path, {'one': 1})
        with self.assertRaises(FileExistsError):
            self.d.write_exclusive(path, {'two': 2})
        self.assertEqual(path.read_bytes(), b'{"one":1}\n')
        self.assertEqual(list(self.root.glob('.d0-*')), [])

    def test_cache_closed_on_fatal_score(self):
        events = []
        core = SimpleNamespace(environment=lambda *a: ({'base': {}}, {}),
            FeatureCache=lambda: SimpleNamespace(close=lambda: events.append('closed')),
            Scorer=lambda *a, **kw: (_ for _ in ()).throw(RuntimeError('synthetic')))
        with patch.object(self.d.importlib, 'import_module', return_value=object()), patch.dict(os.environ):
            with self.assertRaises(RuntimeError):
                self.d.score_selected(core, object(), object(), {}, {'base': {}, 'config': {'threads': 4}},
                                      'synthetic', [], [], [], ())
        self.assertEqual(events, ['closed'])

    def test_cli_exact_arguments(self):
        common = ['--repo-root', 'repo', '--freeze', 'freeze', '--expect-freeze-sha256', 'hash',
                  '--binding', 'binding', '--out', 'out']
        self.assertEqual(self.d.parser().parse_args(['select', *common]).command, 'select')
        args = self.d.parser().parse_args(['score', *common, '--base-dir', 'base', '--selection', 'selection'])
        self.assertEqual((args.base_dir, args.selection), ('base', 'selection'))

    def test_import_and_synthetic_selection_without_tensor_libraries(self):
        # Isolated child proves blocked imports without poisoning other tests.
        code = '''
import builtins, importlib.util, sys
original = builtins.__import__
def guarded(name, *args, **kwargs):
    if name.split('.')[0] in {'torch', 'laya', 'numpy', 'transformers', 'tokenizers'}:
        raise AssertionError('tensor import')
    return original(name, *args, **kwargs)
builtins.__import__ = guarded
spec = importlib.util.spec_from_file_location('_isolated_d0', sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
class Refusal(ValueError): pass
r = dict(id='synthetic', family='synthetic', label='allow_ok', request={}, action='read',
         secrets=[], local_rule=None, pair_of=None, injection_of=None, **{'class': 'alpha'})
selection, rows, pairs, unpaired = m.select_rows([r], ('alpha',), lambda *a: ('', 0), Refusal, {}, {})
assert selection['rows'] == 1 and unpaired == [0]
'''
        result = subprocess.run([sys.executable, '-I', '-B', '-c', code, str(ENTRY)],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_cli_error_never_echoes_argument(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(self.d.main(['PRIVATE-ARGUMENT']), 2)
        self.assertEqual(err.getvalue(), 'cli_arguments\n')

    def test_fake_original_scorer_cache_and_metadata_path(self):
        events = []
        rows = twin('private') + [row('private-unpaired')]
        class Scorer:
            def __init__(self, base, c, threads, cache):
                events.append(('scorer', threads, cache is cache_object))
                self.model = object()
            def scores(self, rows, facts_blind=False):
                self.last_refusals = [None] * len(rows)
                events.append(('scores', facts_blind))
                return [.2, .2, .8] if facts_blind else [.9, .1, .7]
            def item(self, row, facts_blind=False):
                assert facts_blind
                return {'cache_key': 'same'}
        cache_object = SimpleNamespace(close=lambda: events.append('closed'))
        base_metadata = {'weights_sha256': '0' * 64}
        core = SimpleNamespace(environment=lambda *a: ({'base': base_metadata}, {}),
            FeatureCache=lambda: cache_object, Scorer=Scorer,
            context_meta_ok=lambda *a: True)
        common = SimpleNamespace(load_checkpoint=lambda path: ({}, {}),
            apply_heads=lambda *a: events.append('apply'))
        frozen = dict(base=base_metadata, config={'threads': 4}, threshold=.7, control_threshold=.5,
                      context={'path': 'context'}, control={'path': 'control'})
        with patch.object(self.d.importlib, 'import_module', return_value=common), patch.dict(os.environ):
            metrics = self.d.score_selected(core, SimpleNamespace(Refusal=Refusal),
                SimpleNamespace(auroc=fake_auc), {}, frozen, 'base', rows, [(0, 1)], [2], ('alpha',))
        self.assertEqual(events, [('scorer', 4, True), 'apply', ('scores', False),
                                  'apply', ('scores', True), 'closed'])
        self.assertEqual(metrics['populations']['paired']['overall']['blind_cache_keys']['identical'], 1)

    def test_ast_no_forbidden_calls_or_top_level_project_imports(self):
        tree = ast.parse(ENTRY.read_text())
        forbidden = {'evaluate_frozen', 'gates', 'threshold', 'fit_threshold', 'heldout_overlap', 'generate', 'train'}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id if isinstance(node.func, ast.Name) else ''
                self.assertNotIn(name, forbidden)
        for node in tree.body:
            if isinstance(node, ast.Import):
                self.assertFalse(any(a.name.startswith(('context_', 'torch', 'numpy', 'laya')) for a in node.names))
        self.assertNotIn("os.environ['GITHUB_SHA'] =", ENTRY.read_text())


if __name__ == '__main__':
    unittest.main()
