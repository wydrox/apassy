"""Manual draft-download permission boundaries; stdlib source checks only."""
import ast
from pathlib import Path
import re
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / '.github/workflows'
DOWNLOADS = {
    'cost-only': 'Read draft-release checkpoint (transport preflight required)',
    'external-evaluate': 'Download and restore pinned external bundle',
}


def section(source, name, indent=0):
    """Read one block at a known indentation, without importing a YAML package."""
    pad = ' ' * indent
    match = re.search(rf'^{pad}{re.escape(name)}:\n', source, re.M)
    if match is None:
        raise AssertionError(f'missing section: {name}')
    rest = source[match.end():]
    stop = re.search(rf'^ {{0,{indent}}}[A-Za-z0-9_-]+:', rest, re.M)
    return rest[:stop.start()] if stop else rest


def jobs(source):
    body = section(source, 'jobs')
    names = re.findall(r'^  ([A-Za-z0-9_-]+):\n', body, re.M)
    return {name: section(body, name, 2) for name in names}


def permissions(source, indent):
    pad = ' ' * indent
    if not re.search(rf'^{pad}permissions:\n', source, re.M):
        return None
    body = section(source, 'permissions', indent)
    return dict(re.findall(rf'^{pad}  ([a-z-]+): (read|write|none)\s*$', body, re.M))


def guard(job, event, mode, caller=False):
    """Evaluate the actual isolated job guard on synthetic event/input values."""
    expression = re.search(r'^    if: \$\{\{ (.+) \}\}$', job, re.M).group(1)
    expression = expression.replace('&&', ' and ').replace('||', ' or ')
    tree = ast.parse(expression, mode='eval')
    allowed = (ast.Expression, ast.BoolOp, ast.And, ast.Or, ast.Compare, ast.Eq,
               ast.Attribute, ast.Name, ast.Load, ast.Constant)
    if any(not isinstance(node, allowed) for node in ast.walk(tree)):
        raise AssertionError('unexpected manual guard syntax')
    key = 'context_experiment' if caller else 'mode'
    return eval(compile(tree, '<manual-job-guard>', 'eval'), {'__builtins__': {}}, {
        'github': SimpleNamespace(event_name=event),
        'inputs': SimpleNamespace(**{key: mode}),
    })


class DraftPermissions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ci = (WORKFLOWS / 'ci.yml').read_text()
        cls.experiment = (WORKFLOWS / 'bouncer-context-experiment.yml').read_text()

    def test_workflow_caller_and_all_jobs_have_only_read_permissions(self):
        for source in (self.ci, self.experiment):
            self.assertNotRegex(source, re.compile(r'^\s*permissions:[^\S\n]+\S', re.M))
            self.assertEqual(permissions(source, 0), {'contents': 'read'})
            self.assertNotRegex(source, re.compile(r'^\s+[a-z-]+: write\s*$', re.M))
            for name, job in jobs(source).items():
                grant = permissions(job, 4)
                with self.subTest(job=name):
                    if grant is not None:
                        self.assertEqual(grant.get('contents', 'none'), 'read')
                        self.assertNotIn('write', grant.values())

    def test_actual_guards_allow_only_manual_event_and_matching_modes(self):
        caller = jobs(self.ci)['context-experiment']
        callees = jobs(self.experiment)
        modes = ('off', 'probe', 'full', 'cost-only', 'cuda-preflight',
                 'external-evaluate', '', 'unexpected')
        caller_modes = {'probe', 'full', 'cost-only', 'cuda-preflight', 'external-evaluate'}
        for event in ('workflow_dispatch', 'pull_request', 'pull_request_target',
                      'push', 'workflow_call', 'schedule'):
            for mode in modes:
                with self.subTest(event=event, mode=mode):
                    self.assertEqual(guard(caller, event, mode, caller=True),
                                     event == 'workflow_dispatch' and mode in caller_modes)
                    for name in DOWNLOADS:
                        self.assertEqual(guard(callees[name], event, mode),
                                         event == 'workflow_dispatch' and mode == name)

    def test_input_secret_stays_in_each_manual_download_step_only(self):
        self.assertNotRegex(self.experiment, r'GH_TOKEN|github\.token|GITHUB_TOKEN')
        self.assertEqual(self.experiment.count('${{ secrets.APASSY_CONTEXT_INPUT }}'), 2)
        for name, download in DOWNLOADS.items():
            job = jobs(self.experiment)[name]
            steps = re.split(r'^    - ', section(job, 'steps', 4), flags=re.M)
            input_steps = [step for step in steps if '${{ secrets.APASSY_CONTEXT_INPUT }}' in step]
            with self.subTest(job=name):
                self.assertEqual(len(input_steps), 1)
                step = input_steps[0]
                self.assertEqual(step.splitlines()[0], f'name: {download}')
                self.assertIn('        APASSY_CONTEXT_INPUT: ${{ secrets.APASSY_CONTEXT_INPUT }}\n', step)
                expected = {'APASSY_CONTEXT_INPUT'}
                if name == 'external-evaluate':
                    expected.add('APASSY_CONTEXT_SHIPPED_HEADS_URL')
                self.assertEqual(set(re.findall(r'secrets\.([A-Za-z0-9_]+)', job)), expected)
                self.assertNotRegex(step, r'(?:GITHUB_ENV|GITHUB_OUTPUT|::add-mask::)')
                self.assertNotRegex(step, r'context_cost_asset import download|\bdownload\(')
                for other in steps:
                    if other != step:
                        self.assertNotIn('APASSY_CONTEXT_INPUT', other)
                checkouts = [s for s in steps if s.startswith('uses: actions/checkout@')]
                self.assertEqual(len(checkouts), 1)
                self.assertIn('      with:\n        persist-credentials: false\n', checkouts[0])
                self.assertNotIn('persist-credentials: true', job)
        self.assertNotIn('draft-download', jobs(self.experiment))
        self.assertNotIn('bouncer-context-draft-input-', self.experiment)

    def test_reusable_caller_keeps_explicit_secret_allowlist(self):
        caller = jobs(self.ci)['context-experiment']
        self.assertIn('    uses: ./.github/workflows/bouncer-context-experiment.yml\n', caller)
        self.assertNotRegex(caller, r'github\.token|GH_TOKEN|GITHUB_TOKEN')
        self.assertEqual(section(caller, 'secrets', 4).strip(),
                         'APASSY_CONTEXT_INPUT: ${{ secrets.APASSY_CONTEXT_INPUT }}\n'
                         '      APASSY_CONTEXT_SHIPPED_HEADS_URL: '
                         '${{ secrets.APASSY_CONTEXT_SHIPPED_HEADS_URL }}')
        for source in (self.ci, self.experiment):
            self.assertNotRegex(source, r'secrets:\s*inherit')
        declared = section(section(self.experiment, 'workflow_call', 2), 'secrets', 4)
        self.assertEqual(declared.strip(),
                         'APASSY_CONTEXT_INPUT:\n        required: false\n'
                         '      APASSY_CONTEXT_SHIPPED_HEADS_URL:\n        required: false')


if __name__ == '__main__':
    unittest.main()
