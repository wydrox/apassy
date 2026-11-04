"""Synthetic model-free tests. No model, held-out data or Rust build."""
import copy
import contextlib
import io
import itertools
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools/basemodel'))
import context_replay as replay
from context_v1 import load_contract, Unsupported


def view():
    s = {k: next((x for x in ('unknown', 'none', 'not_recorded', '0', 'undeclared', 'no') if x in v), v[0])
         for k, v in load_contract()['secret_facts']}
    s.update(env='development', env_from='owner', scope='read_only', scope_from='owner',
             sensitive='no', provider='none', hosts='none', project='undeclared')
    return dict(request=dict(user_request='Show repository status.', command='git status', purpose=''),
                action='read', secrets=[s], local_rule=None)


def fake_rows(views, verdicts=None):
    # A deliberately independent simple pre-stage for exercising alignment and
    # universal LB math. Rust parity below checks actual route behavior.
    return [dict(pre_ask=v['local_rule'] is not None, pre_reason='local_rule' if v['local_rule'] is not None else None,
                 systemone_body={'state': v['request']['command'], 'questions': {}},
                 ask=(v['local_rule'] is not None or (verdicts or [False]*len(views))[i]))
            for i, v in enumerate(views)]


class ReplayTests(unittest.TestCase):
    def test_label_permutation_invariance(self):
        rows = [dict(view(), label=label, **{'class':'irrelevant'}, rationale='hidden', pair_of='x')
                for label in ('must_ask', 'allow_ok')]
        with patch.object(replay, '_replay', side_effect=lambda vs, _: fake_rows(vs)):
            original = replay.baseline_lower_bound([replay.visible_view(r) for r in rows], 'fake')
            for r in rows:
                r.update(label='deterministic_ask', rationale='different', pair_of=None)
            self.assertEqual(original, replay.baseline_lower_bound([replay.visible_view(r) for r in rows], 'fake'))
        self.assertNotIn('label', json.dumps(original))

    def test_lb_all_fake_model_verdicts(self):
        views = [view() for _ in range(4)]
        views[1]['local_rule'] = ''  # Non-null, including empty string, asks.
        views[3]['local_rule'] = 'Owner rule'
        lower = sum(r['pre_ask'] for r in fake_rows(views))
        for verdicts in itertools.product((False, True), repeat=4):
            rows = fake_rows(views, verdicts)
            self.assertGreaterEqual(sum(r['ask'] for r in rows), lower)
            for r in rows:
                self.assertFalse(r['pre_ask'] and not r['ask'])

    def test_reject_incoherent(self):
        for changes in ({'env':'unknown'}, {'scope':'unknown'}, {'scope_from':'none'},
                        {'env':'production', 'sensitive':'no'}, {'env_from':'none'}):
            v = view()
            v['secrets'][0].update(changes)
            with self.assertRaises(Unsupported):
                replay.validate_view(v, load_contract())
        v = view()
        v['secrets'][0].update(env='unknown', scope='unknown', env_from='none', scope_from='none', sensitive='unknown')
        replay.validate_view(v, load_contract())

    def test_no_labels_accepted_in_api(self):
        v = dict(view(), label='allow_ok')
        with self.assertRaises(Unsupported):
            replay.validate_view(v, load_contract())

    def test_missing_shipped_named(self):
        self.assertEqual(replay.baseline_with_heads([], 'unused', 'unused')['reason'], 'shipped_heads_unavailable')

    def test_measurement_warmups_samples_and_schema(self):
        calls = []
        ticks = iter(i * .01 for i in range(40))
        result = replay.measure_arm([view()], lambda v: calls.append(v), 20,
                                    clock=lambda: next(ticks), rss=lambda: 1000)
        self.assertEqual(len(calls), 23)
        self.assertAlmostEqual(result['p95_ms'], 10)
        record = replay.cost_record(result, result)
        self.assertEqual(set(record), {'context_p50_ms', 'context_p95_ms', 'baseline_p50_ms',
                                      'baseline_p95_ms', 'context_peak_rss_bytes', 'baseline_peak_rss_bytes', 'samples'})
        from context_eval import cost_gate
        self.assertTrue(cost_gate({'1': record, '3': record}))
        boundary = dict(record, context_p95_ms=1.5*record['baseline_p95_ms'],
                        context_peak_rss_bytes=record['baseline_peak_rss_bytes'] + 256*1024**2)
        self.assertTrue(cost_gate({'1': boundary, '3': boundary}))
        self.assertFalse(cost_gate({'1': dict(boundary, context_p95_ms=boundary['context_p95_ms']+.001), '3': record}))
        self.assertFalse(cost_gate({'1': dict(boundary, context_peak_rss_bytes=boundary['context_peak_rss_bytes']+1), '3': record}))
        with self.assertRaises(Unsupported):
            replay.cost_record(result, dict(result, samples=19))

    def test_help_stdlib_only(self):
        code = "import sys; sys.path.insert(0, sys.argv[1]); import context_replay; assert 'torch' not in sys.modules; context_replay.main(['--help'])"
        p = subprocess.run([sys.executable, '-B', '-c', code, str(Path(replay.__file__).parent)], capture_output=True)
        self.assertEqual(p.returncode, 0)
        self.assertIn(b'--context-heads', p.stdout)

    def test_validation_manifest_and_G1_only(self):
        from context_v1 import sha256
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)/'val.jsonl'
            p.write_text(json.dumps(dict(view(), family='G1:synthetic'))+'\n')
            (p.parent/'data-manifest.json').write_text(json.dumps({'files':{'val.jsonl':{'sha256':sha256(p)}}}))
            self.assertEqual(len(replay.validation_views(p, 1)), 1)
            with self.assertRaises(Unsupported):
                replay.validation_views(p, 3)
            p.write_text('{}\n')
            with self.assertRaises(Unsupported):
                replay.validation_views(p, 1)

    def test_tiny_generated_validation_cost_uses_only_fitting_views(self):
        from context_data import main as generate_main, read_rows
        from context_v1 import serialize
        with tempfile.TemporaryDirectory(prefix='synthetic-cost-') as tmp:
            generate_main(['--out', tmp, '--groups', '10', '--seed', '7'])
            path = Path(tmp) / 'val.jsonl'
            rows = read_rows(path, load_contract())
            for n in (1, 3):
                counts = {}
                selected = replay.validation_views(path, n, counts=counts)
                self.assertTrue(selected, n)
                self.assertEqual(counts['candidate_views'], sum(len(r['secrets']) == n for r in rows))
                self.assertEqual(counts['fitting_views'], len(selected))
                self.assertEqual(counts['candidate_views'], counts['fitting_views'] + counts['budget_refusals'])
                if n == 3:
                    self.assertGreater(counts['budget_refusals'], 0)
                for v in selected:
                    self.assertEqual(len(v['secrets']), n)
                    serialize(v['request'], v['action'], v['secrets'], load_contract())
                replay.measure_arm(selected, lambda v: serialize(
                    v['request'], v['action'], v['secrets'], load_contract()), 20, rss=lambda: 0)
            self.assertLess(len(replay.validation_views(path, 3)),
                            sum(len(r['secrets']) == 3 for r in rows))

    def test_safe_child_cost_failure_diagnostics(self):
        with tempfile.TemporaryDirectory(prefix='synthetic-child-') as tmp:
            out = Path(tmp) / 'child.json'
            for reason, expected in (('validation_secret_count', 'validation_secret_count'),
                                     ('PRIVATE_PATH_INPUT_SENTINEL', 'cost_evidence_unavailable')):
                out.write_text(json.dumps({'status': 'UNSUPPORTED', 'reason': reason}))
                with patch.object(replay.subprocess, 'run', return_value=type('Proc', (), {'returncode': 2})()) as run:
                    with self.assertRaises(replay.CostArmFailure) as caught:
                        replay._run_cost_arm(['inert-child'], out, 'context', 3)
                self.assertEqual((caught.exception.arm, caught.exception.n, caught.exception.child_reason),
                                 ('context', 3, expected))
                self.assertIs(run.call_args.kwargs['stderr'], subprocess.DEVNULL)
                self.assertIs(run.call_args.kwargs['stdout'], subprocess.DEVNULL)
            out.unlink()
            with patch.object(replay.subprocess, 'run', return_value=type('Proc', (), {'returncode': 2})()):
                with self.assertRaises(replay.CostArmFailure) as caught:
                    replay._run_cost_arm(['inert-child'], out, 'baseline', 1)
            self.assertEqual(caught.exception.child_reason, 'cost_child_report_unavailable')
            with patch.object(replay.subprocess, 'run', side_effect=subprocess.TimeoutExpired('PRIVATE_SENTINEL', 1)):
                with self.assertRaises(replay.CostArmFailure) as caught:
                    replay._run_cost_arm(['inert-child'], out, 'context', 3)
            self.assertEqual(caught.exception.child_reason, 'cost_arm_timeout')

    def test_parent_and_child_failure_json_is_safe(self):
        with tempfile.TemporaryDirectory(prefix='synthetic-failure-') as tmp:
            out = Path(tmp) / 'failure.json'
            args = ['--val', 'synthetic', '--base', 'PRIVATE_PATH_SENTINEL',
                    '--context-heads', 'synthetic', '--expect-context-sha256', 'synthetic', '--out', str(out)]
            for child in (False, True):
                output = io.StringIO()
                with patch.object(replay, 'offline'), patch.object(replay.sys, 'platform', 'linux'), \
                        patch.dict(os.environ, GITHUB_ACTIONS='true', ImageOS='ubuntu24'), \
                        patch.object(replay, 'validation_views', side_effect=Unsupported('PRIVATE_INPUT_SENTINEL')), \
                        patch.object(replay, '_run_cost_arm', side_effect=replay.CostArmFailure('context', 3, 'heads_pin')), \
                        contextlib.redirect_stdout(output):
                    code = replay.main(args + (['--arm', 'context', '--secrets', '3'] if child else []))
                self.assertEqual(code, 2)
                result = json.loads(output.getvalue())
                self.assertEqual(json.loads(out.read_text()), result)
                self.assertEqual((result['arm'], result['secrets']), ('context', 3))
                self.assertNotIn('PRIVATE', output.getvalue())
                self.assertEqual(result['reason'], 'cost_evidence_unavailable' if child else 'cost_arm_failed')
                if not child:
                    self.assertEqual(result['child_reason'], 'heads_pin')

    def test_rust_source_checks_each_secret_before_decisions(self):
        source = (Path(__file__).resolve().parents[2] / 'examples/context_route_replay.rs').read_text()
        check = source.index('if (secret["hosts"] == "none") != hosts.is_empty()')
        self.assertIn('for secret in &v.secrets', source[:check])
        self.assertIn('return Err("row_incoherent")', source[check:check + 150])
        self.assertLess(source.index('shell_risk::command_hosts(&argv)'), check)
        self.assertLess(check, source.index('shell_risk::analyze_run'))
        self.assertLess(check, source.index('bouncer::before_model'))

    @unittest.skipUnless(os.environ.get('APASSY_CONTEXT_REPLAY_BINARY'), 'Rust binary absent; CI opt-in')
    def test_rust_host_coherence_each_secret_prepare_and_decide(self):
        binary = os.environ['APASSY_CONTEXT_REPLAY_BINARY']
        for destination in (False, True):
            for host in ('none', 'known', 'unknown'):
                for secret_index in range(3):
                    v = view()
                    if destination:
                        v['request'].update(user_request='List remote repository references.',
                                            command='git ls-remote https://repo.example.test/team.git')
                    v['secrets'] = [copy.deepcopy(v['secrets'][0]) for _ in range(3)]
                    for s in v['secrets']:
                        s['hosts'] = 'known' if destination else 'none'
                    v['secrets'][secret_index]['hosts'] = host
                    coherent = (host == 'none') == (not destination)
                    for op in ('prepare', 'decide'):
                        payload = {'op': op, 'views': [view(), v]}
                        if op == 'decide':
                            payload['bodies'] = [{}, {}]
                        p = subprocess.run([binary], input=json.dumps(payload).encode(),
                                           capture_output=True, timeout=120)
                        result = json.loads(p.stdout)
                        self.assertEqual(p.returncode, 0 if coherent else 2,
                                         (destination, host, secret_index, op, result.get('reason')))
                        if not coherent:
                            self.assertEqual(result['reason'], 'row_incoherent')
                        else:
                            self.assertEqual(len(result['rows']), 2)
                            self.assertEqual(result['rows'][1]['actual_host_count'], int(destination))

    @unittest.skipUnless(os.environ.get('APASSY_CONTEXT_REPLAY_BINARY'), 'Rust binary absent; CI opt-in')
    def test_rust_fixture_parity_and_all_verdicts(self):
        binary = os.environ['APASSY_CONTEXT_REPLAY_BINARY']
        views = [view(), view(), view(), view()]
        views[1]['local_rule'] = 'Ask'
        views[2]['request'].update(user_request='List remote repository references.',
                                   command='git ls-remote https://repo.example.test/team.git')
        views[2]['secrets'][0]['hosts'] = 'unknown'
        views[3]['secrets'][0]['project'] = 'other'
        prepared = replay.baseline_lower_bound(views, binary)
        self.assertEqual(prepared['pre_ask'], [False, True, True, True],
                         msg=json.dumps(prepared['diagnostics'], sort_keys=True))
        self.assertEqual(prepared['pre_reason'][2], 'ForeignHost')
        self.assertEqual([d['actual_host_count'] for d in prepared['diagnostics']], [0, 0, 1, 0])
        from context_v1 import state_text
        self.assertEqual(prepared['systemone_body'][0]['state'], state_text(views[0]['request']))
        for probabilities in itertools.product((0., 1.), repeat=5):
            body = {'answers':{name:{'noul':p} for name,p in zip(
                ('task_match','writes','remote','leak','destroy'), probabilities)}}
            rows = replay._replay(views, binary, [body]*len(views))
            self.assertGreaterEqual(sum(r['ask'] for r in rows), sum(prepared['pre_ask']))
        bad = dict(view(), label='PRIVATE_SENTINEL')
        p = subprocess.run([binary], input=json.dumps({'op':'prepare','views':[bad]}).encode(), capture_output=True)
        self.assertEqual(p.returncode, 2)
        self.assertNotIn(b'PRIVATE_SENTINEL', p.stdout+p.stderr)
        self.assertEqual(json.loads(p.stdout)['reason'], 'invalid_input')


if __name__ == '__main__':
    unittest.main()
