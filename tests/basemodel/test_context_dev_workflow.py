"""D0 workflow contracts; stdlib/fakes only, never execute the diagnostic entry."""
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
S = '7a63ffad557ace5e396c4a709ad8453fb611b565'
E = 'e' * 40
BUNDLE = '6de84990fb29a99c8e23eb51b67066d6344c644fbf5e634ea4f23425a85fb974'
FREEZE = '7e8391a63aaba4afb84300788474be8e3ffdfb46b4aa3206801c0dbba550368c'
RUN = 'bouncer-bbee8f21-20261105t124513z'


def jobs(source):
    parts = re.split(r'^  ([a-zA-Z0-9_-]+):\n', source.split('\njobs:\n', 1)[1], flags=re.M)
    return dict(zip(parts[1::2], parts[2::2]))


def field(body, key, indent=4):
    return re.search(r'^' + ' ' * indent + re.escape(key) + r': (.+)$', body, re.M).group(1)


def evaluate(expression, values):
    """Evaluate the actual small Actions guard subset used by these jobs."""
    expression = expression.removeprefix('${{').removesuffix('}}').strip()
    expression = re.sub(r'\b(?:github|inputs|needs|steps)\.[\w.-]+',
                        lambda m: repr(values.get(m[0], '')), expression)
    expression = expression.replace('always()', 'True').replace('cancelled()', 'False')
    expression = expression.replace('&&', ' and ').replace('||', ' or ')
    expression = re.sub(r'!(?!=)', ' not ', expression)
    return eval(expression.strip(), {'__builtins__': {}}, {})


def steps(body):
    parts = body.split('    - name: ')
    return {p.splitlines()[0]: p for p in parts[1:]}


def shell(step):
    return textwrap.dedent(step.split('      run: |\n', 1)[1])


def python_blocks(script):
    return re.findall(r"<<'(PY|PYCODE)'\n(.*?)\n\1(?:\n|$)", script, re.S)


class DevelopmentWorkflow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ci_source = (ROOT / '.github/workflows/ci.yml').read_text()
        cls.source = (ROOT / '.github/workflows/bouncer-context-experiment.yml').read_text()
        cls.ci = jobs(cls.ci_source)
        cls.called = jobs(cls.source)
        cls.job = cls.called['development-diagnostic']
        cls.steps = steps(cls.job)

    def values(self, event, mode, reuse=''):
        return {'github.event_name': event, 'inputs.context_experiment': mode,
                'inputs.mode': mode, 'inputs.transport_only': False,
                'steps.select.outputs.reuse': reuse, 'needs.probe.outputs.groups': '400'}

    def test_actual_guards_over_all_events_and_modes(self):
        ordinary = {'extension', 'macos', 'linux', 'relay', 'relay-worker', 'linux-node',
                    'audit', 'tests', 'linux-isolation'}
        self.assertEqual(set(self.ci), ordinary | {'reuse-pr', 'release-binaries', 'context-experiment'})
        modes = ('', 'off', 'probe', 'full', 'cost-only', 'cuda-preflight',
                 'external-evaluate', 'development-diagnostic')
        for event in ('push', 'pull_request', 'workflow_dispatch'):
            for mode in modes:
                for prior_reuse in ('', 'true', 'false'):
                    with self.subTest(event=event, mode=mode, reuse=prior_reuse):
                        v = self.values(event, mode, prior_reuse)
                        reuse = evaluate(field(self.ci['reuse-pr'], 'reuse', 6), v)
                        self.assertEqual(reuse, 'true' if mode == 'development-diagnostic' else prior_reuse)
                        v['needs.reuse-pr.outputs.reuse'] = reuse
                        active = {name for name, body in self.ci.items()
                                  if name == 'reuse-pr' or evaluate(field(body, 'if'), v)}
                        bridge = event == 'workflow_dispatch' and mode in modes[2:]
                        self.assertEqual('context-experiment' in active, bridge)
                        self.assertEqual(active & ordinary, ordinary if reuse != 'true' else set())
                        self.assertEqual('release-binaries' in active,
                                         event != 'pull_request' and mode != 'development-diagnostic')
                        called = {name for name, body in self.called.items()
                                  if evaluate(field(body, 'if'), v)}
                        if mode == 'development-diagnostic':
                            self.assertEqual(called, {'development-diagnostic'} if event == 'workflow_dispatch' else set())
                            if event == 'workflow_dispatch':
                                self.assertEqual(active, {'reuse-pr', 'context-experiment'})
                        else:
                            expected = set()
                            if mode not in ('cost-only', 'cuda-preflight', 'external-evaluate'):
                                expected.add('probe')
                            if event == 'workflow_dispatch':
                                expected |= {'full': {'train', 'evaluate'}, 'cost-only': {'cost-only'},
                                             'cuda-preflight': {'cuda-preflight'},
                                             'external-evaluate': {'external-evaluate'}}.get(mode, set())
                            self.assertEqual(called, expected)
        v = self.values('workflow_dispatch', 'probe')
        v['inputs.transport_only'] = True
        self.assertFalse(evaluate(field(self.called['probe'], 'if'), v))
        self.assertIn('          - development-diagnostic\n', self.ci_source)
        self.assertIn('uses: ./.github/workflows/bouncer-context-experiment.yml', self.ci['context-experiment'])

    def test_job_envelope_and_action_pins(self):
        self.assertEqual(field(self.job, 'runs-on'), 'ubuntu-24.04')
        self.assertEqual(field(self.job, 'timeout-minutes'), '60')
        self.assertIn('    permissions:\n      contents: read\n', self.job)
        self.assertIn("      CUDA_VISIBLE_DEVICES: ''\n", self.job)
        for key in ('OMP_NUM_THREADS', 'MKL_NUM_THREADS', 'OPENBLAS_NUM_THREADS', 'NUMEXPR_NUM_THREADS'):
            self.assertIn(f"      {key}: '4'\n", self.job)
        self.assertIn('fetch-depth: 0', self.job)
        self.assertIn('persist-credentials: false', self.job)
        for action in re.findall(r'uses: (\S+)', self.job):
            self.assertRegex(action, r'^actions/[a-z-]+@[0-9a-f]{40}$')
        self.assertEqual(len(re.findall(r'uses:', self.job)), 3)
        for forbidden in ('cargo ', 'rustup ', 'context_eval.py', 'context_replay.py', '--heldout',
                          'context_data.py', 'context_train.py', 'unittest', 'SHIPPED_URL', 'R2_',
                          'GH_TOKEN', 'github.token', 'secrets: inherit', 'continue-on-error'):
            self.assertNotIn(forbidden, self.job)

    def test_sequence_cli_pins_and_output_isolation(self):
        names = list(self.steps)
        self.assertEqual(names, [
            'Require exact source and external inputs before setup', 'Install Python 3.12',
            'Isolate experiment paths and credentials', 'Download and restore pinned external bundle',
            'Bind E entry and immutable S source', 'Install pinned CUDA distribution on CPU',
            'Verify original restored bundle at S', 'Select aggregate sample before base weights',
            'Fetch and verify the pinned public base, then go offline',
            'Score development diagnostic offline', 'Retain aggregate diagnostic evidence only'])
        self.assertIn("SHIPPED_BASELINE: 'false'", self.job)
        download = self.steps[names[3]]
        self.assertEqual(self.job.count('secrets.'), 1)
        self.assertEqual(self.job.count('APASSY_CONTEXT_INPUT:'), 1)
        for value in ('APASSY_CONTEXT_INPUT: ${{ secrets.APASSY_CONTEXT_INPUT }}',
                      'CHECKPOINT_ASSET: ${{ inputs.bundle_asset }}',
                      'CHECKPOINT_SHA256: ${{ inputs.bundle_sha256 }}',
                      "TRANSPORT_ONLY: 'true'", 'DESTINATION_NAME: bundle.tar',
                      'tools/basemodel/context_cost_asset.py', '215070720'):
            self.assertIn(value, download)
        self.assertLess(download.index('context_cost_asset.py'), download.index('restore('))
        switch = self.steps[names[4]]
        for value in (S, BUNDLE, FREEZE, RUN, '435195444/714447674',
                      'git show "$GITHUB_SHA:tools/basemodel/context_dev_diagnostic.py"',
                      'git merge-base --is-ancestor "$S" "$GITHUB_SHA"',
                      'git checkout --quiet --detach "$S"',
                      'test "$(git rev-parse HEAD)" = "$S"',
                      'git status --porcelain --untracked-files=no'):
            self.assertIn(value, switch)
        self.assertNotRegex(self.job, r'(?:export |echo [\"\']?)GITHUB_SHA=')
        self.assertIn('assert entry.read_bytes() == original', switch)
        install = self.steps[names[5]]
        for value in ('requirements-cu130.txt -r tools/basemodel/requirements.txt',
                      'assert versions == PACKAGE_VERSIONS', 'assert torch.cuda.is_available() is False',
                      'assert torch.get_num_threads() == 4', 'assert tensor_sum == 64'):
            self.assertIn(value, install)
        self.assertIn("e['RUN_ID'], '" + S + "', e['FREEZE_SHA256'], Path.cwd())", self.steps[names[6]])
        for command, name in (('select', names[7]), ('score', names[9])):
            body = self.steps[name]
            for value in (f'"$PY" -I -B "$EXP/entry/context_dev_diagnostic.py" {command}',
                          '--repo-root "$GITHUB_WORKSPACE"', '--freeze "$CONTEXT_ROOT/full/freeze.json"',
                          '--expect-freeze-sha256 "$FREEZE_SHA256"',
                          '--binding "$EXP/evidence/diagnostic-binding.json"'):
                self.assertIn(value, body)
        self.assertIn('--out "$EXP/evidence/selection.json"', self.steps[names[7]])
        score = self.steps[names[9]]
        for value in ('timeout-minutes: 30', '--selection "$EXP/evidence/selection.json"',
                      '--base-dir "$APASSY_CONTEXT_TOKENIZER_BASE"',
                      '--out "$EXP/evidence/development-diagnostic.json"',
                      'test "$HF_HUB_OFFLINE" = 1', 'test "$TRANSFORMERS_OFFLINE" = 1'):
            self.assertIn(value, score)
        fetch = self.steps[names[8]]
        self.assertIn("common.sha256_file(base / manifest['weights_file']) == manifest['weights_sha256']", fetch)
        self.assertIn('HF_HUB_OFFLINE=1\\nTRANSFORMERS_OFFLINE=1', fetch)
        upload = self.steps[names[10]]
        self.assertIn('if: always()', upload)
        self.assertIn('retention-days: 7', upload)
        self.assertEqual(re.findall(r'^        path: (.+)$', upload, re.M),
                         ['${{ runner.temp }}/bouncer-context/evidence/*.json'])
        self.assertNotIn('base-identity.json', self.job)
        self.assertNotIn('external-receipt.json', self.job)
        for key in ('HF_TOKEN', 'HUGGING_FACE_HUB_TOKEN', 'HUGGINGFACE_HUB_TOKEN', 'HF_TOKEN_PATH',
                    'APASSY_BASE_MODEL', 'LAYA_API_KEY', 'BASH_ENV', 'HF_HOME', 'HF_HUB_CACHE',
                    'XDG_CACHE_HOME', 'PIP_CACHE_DIR'):
            self.assertIn(key, self.steps[names[2]])

    def test_real_embedded_bash_and_python_syntax(self):
        count = 0
        for step in self.steps.values():
            if '      run: |\n' not in step:
                continue
            script = shell(step)
            self.assertNotIn('${{', script)
            result = subprocess.run(['bash', '-n'], input=script, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            for _, code in python_blocks(script):
                ast.parse(code)
                count += 1
        self.assertGreaterEqual(count, 6)

    def test_source_switch_shell_with_fake_git_refuses_identity_and_source_drift(self):
        script = shell(self.steps['Bind E entry and immutable S source'])
        fake_git = r'''import json, os, sys
from pathlib import Path
root = Path(os.environ['EXP'])
a = sys.argv[1:]
with (root / 'git-calls').open('a') as f:
    f.write(json.dumps(a) + '\n')
state = root / 'head'
head = state.read_text()
if a == ['rev-parse', 'HEAD']:
    print(head)
elif a == ['status', '--porcelain', '--untracked-files=no']:
    if os.environ.get('DIRTY_AT') == head:
        print(' M tracked.py')
elif a == ['show', os.environ['GITHUB_SHA'] + ':tools/basemodel/context_dev_diagnostic.py']:
    print('# synthetic changed' if os.environ.get('MUTATE_ENTRY') and head != os.environ['GITHUB_SHA']
          else '# synthetic entry')
elif a == ['merge-base', '--is-ancestor', os.environ['S_EXPECTED'], os.environ['GITHUB_SHA']]:
    sys.exit(1 if os.environ.get('BAD_ANCESTRY') else 0)
elif a == ['checkout', '--quiet', '--detach', os.environ['S_EXPECTED']]:
    state.write_text(os.environ.get('BAD_CHECKOUT', os.environ['S_EXPECTED']))
else:
    sys.exit(2)
'''
        variants = ({}, {'RUN_ID': 'other'}, {'BUNDLE_ASSET': '1/2'},
                    {'BUNDLE_SHA256': '0' * 64}, {'FREEZE_SHA256': '0' * 64},
                    {'DIRTY_AT': E}, {'DIRTY_AT': S}, {'BAD_ANCESTRY': '1'},
                    {'BAD_CHECKOUT': 'b' * 40}, {'MUTATE_ENTRY': '1'})
        for variant in variants:
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / 'evidence').mkdir()
                (root / 'head').write_text(E)
                git = root / 'git'
                git.write_text('#!' + sys.executable + '\n' + fake_git)
                git.chmod(0o700)
                env = dict(os.environ, EXP=tmp, PY=sys.executable, GITHUB_SHA=E,
                           RUN_ID=RUN, BUNDLE_ASSET='435195444/714447674', BUNDLE_SHA256=BUNDLE,
                           FREEZE_SHA256=FREEZE, S_EXPECTED=S, PATH=tmp + os.pathsep + os.defpath)
                env.update(variant)
                result = subprocess.run(['bash', '-c', script], env=env, text=True, capture_output=True)
                binding = root / 'evidence/diagnostic-binding.json'
                if variant:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(binding.exists())
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    report = json.loads(binding.read_text())
                    self.assertEqual(report['evaluation_source_sha'], E)
                    self.assertEqual(report['training_source_sha'], S)
                    self.assertEqual(report['entry_sha256'], hashlib.sha256(b'# synthetic entry\n').hexdigest())
                    calls = [json.loads(line) for line in (root / 'git-calls').read_text().splitlines()]
                    self.assertLess(calls.index(['show', E + ':tools/basemodel/context_dev_diagnostic.py']),
                                    calls.index(['checkout', '--quiet', '--detach', S]))
                    self.assertEqual(calls.count(['status', '--porcelain', '--untracked-files=no']), 2)

    def test_binding_executes_actual_python_with_fake_git_and_entry_only(self):
        script = shell(self.steps['Bind E entry and immutable S source'])
        code = python_blocks(script)[0][1]
        entry_bytes = b'# synthetic entry; never executed\n'
        for tamper in (False, True):
            with self.subTest(tamper=tamper), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / 'entry').mkdir()
                (root / 'evidence').mkdir()
                (root / 'entry/context_dev_diagnostic.py').write_bytes(b'changed' if tamper else entry_bytes)
                env = dict(EXP=tmp, GITHUB_SHA=E, BUNDLE_SHA256=BUNDLE, FREEZE_SHA256=FREEZE, RUN_ID=RUN)
                fake = SimpleNamespace(check_output=lambda args: entry_bytes)
                with patch.dict(os.environ, env, clear=True), patch.dict(sys.modules, subprocess=fake):
                    if tamper:
                        with self.assertRaises(AssertionError):
                            exec(code, {})
                    else:
                        exec(code, {})
                        with self.assertRaises(FileExistsError):
                            exec(code, {})
                output = root / 'evidence/diagnostic-binding.json'
                if tamper:
                    self.assertFalse(output.exists())
                else:
                    self.assertEqual(json.loads(output.read_text()), dict(
                        report_kind='development_diagnostic', training_source_sha=S, evaluation_source_sha=E,
                        entry_sha256=hashlib.sha256(entry_bytes).hexdigest(), bundle_sha256=BUNDLE,
                        freeze_sha256=FREEZE, run_id=RUN))

    def test_precheck_executes_with_fakes_before_download(self):
        code = python_blocks(shell(self.steps['Require exact source and external inputs before setup']))[0][1]
        calls = []
        def require(ok):
            if not ok:
                raise ValueError('refused')
        fake_cost = SimpleNamespace(require=require)
        fake_bundle = SimpleNamespace(check_inputs=lambda env, head: calls.append((env['SOURCE_SHA'], head)),
                                      run_root=lambda run: Path('/tmp/synthetic') / run)
        for transport in ('false', 'true', '', 'yes'):
            with tempfile.TemporaryDirectory() as tmp:
                env = dict(REQUESTED_TRANSPORT_ONLY=transport, SOURCE_SHA=E, RUN_ID=RUN,
                           GITHUB_ENV=str(Path(tmp) / 'env'))
                calls.clear()
                original_path = sys.path[:]
                try:
                    with patch.dict(os.environ, env, clear=True), \
                         patch.dict(sys.modules, context_cost_asset=fake_cost, context_external_bundle=fake_bundle), \
                         patch.object(subprocess, 'check_output', return_value=E + '\n') as head:
                        if transport == 'false':
                            exec(code, {})
                            self.assertEqual(calls, [(E, E)])
                            head.assert_called_once_with(['git', 'rev-parse', 'HEAD'], text=True)
                        else:
                            with self.assertRaises(ValueError):
                                exec(code, {})
                            head.assert_not_called()
                            self.assertEqual(calls, [])
                finally:
                    sys.path[:] = original_path


if __name__ == '__main__':
    unittest.main()
