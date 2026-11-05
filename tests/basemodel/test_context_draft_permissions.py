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

    def test_read_defaults_and_only_required_job_write_overrides(self):
        for source, expected in ((self.ci, {'context-experiment'}),
                                 (self.experiment, set(DOWNLOADS))):
            with self.subTest(expected=expected):
                self.assertNotRegex(source, re.compile(r'^\s*permissions:[^\S\n]+\S', re.M))
                self.assertEqual(permissions(source, 0), {'contents': 'read'})
                job_blocks = jobs(source)
                writers = set()
                for name, job in job_blocks.items():
                    grant = permissions(job, 4)
                    if name in expected:
                        self.assertEqual(grant, {'contents': 'write'})
                        writers.add(name)
                    elif grant is not None:
                        self.assertEqual(grant.get('contents', 'none'), 'read')
                        self.assertNotIn('write', grant.values())
                self.assertEqual(writers, expected)
                # Also reject write grants outside the recognized job blocks.
                self.assertEqual(len(re.findall(r'^\s+[a-z-]+: write\s*$', source, re.M)),
                                 len(expected))

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

    def test_ephemeral_token_stays_in_each_download_step_only(self):
        self.assertEqual(self.experiment.count('${{ github.token }}'), len(DOWNLOADS))
        for name, download in DOWNLOADS.items():
            job = jobs(self.experiment)[name]
            steps = re.split(r'^    - ', section(job, 'steps', 4), flags=re.M)
            credential_steps = [step for step in steps if '${{ github.token }}' in step]
            with self.subTest(job=name):
                self.assertEqual(len(credential_steps), 1)
                step = credential_steps[0]
                self.assertEqual(step.splitlines()[0], f'name: {download}')
                self.assertIn('      env:\n        GH_TOKEN: ${{ github.token }}\n', step)
                self.assertEqual(job.count('GH_TOKEN:'), 1)
                self.assertNotRegex(job, r'GITHUB_TOKEN|secrets\.GITHUB_TOKEN')
                self.assertEqual(set(re.findall(r'secrets\.([A-Za-z0-9_]+)', job)),
                                 {'APASSY_CONTEXT_SHIPPED_HEADS_URL'}
                                 if name == 'external-evaluate' else set())
                self.assertNotRegex(step, r'(?:GITHUB_ENV|GITHUB_OUTPUT|::add-mask::)')
                for other in steps:
                    if other != step:
                        self.assertNotRegex(other, r'GH_TOKEN|github\.token|secrets\.GITHUB_TOKEN')
                checkouts = [s for s in steps if s.startswith('uses: actions/checkout@')]
                self.assertEqual(len(checkouts), 1)
                self.assertIn('      with:\n        persist-credentials: false\n', checkouts[0])
                self.assertNotIn('persist-credentials: true', job)

    def test_reusable_caller_keeps_explicit_secret_allowlist(self):
        caller = jobs(self.ci)['context-experiment']
        self.assertIn('    uses: ./.github/workflows/bouncer-context-experiment.yml\n', caller)
        self.assertNotRegex(caller, r'github\.token|GH_TOKEN|GITHUB_TOKEN')
        self.assertEqual(section(caller, 'secrets', 4).strip(),
                         'APASSY_CONTEXT_SHIPPED_HEADS_URL: '
                         '${{ secrets.APASSY_CONTEXT_SHIPPED_HEADS_URL }}')
        for source in (self.ci, self.experiment):
            self.assertNotRegex(source, r'secrets:\s*inherit')
        declared = section(section(self.experiment, 'workflow_call', 2), 'secrets', 4)
        self.assertEqual(declared.strip(),
                         'APASSY_CONTEXT_SHIPPED_HEADS_URL:\n        required: false')


if __name__ == '__main__':
    unittest.main()
