"""Cost-only workflow and transport contracts; synthetic bytes, no network/models."""
import ast
from contextlib import redirect_stderr
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools/basemodel'))
import context_cost_asset as C

BODY = b'fake checkpoint only'
SHA = hashlib.sha256(BODY).hexdigest()


class Response(io.BytesIO):
    def __init__(self, body=b'', status=200, headers=None):
        super().__init__(body)
        self.status = status
        self.headers = headers or {}


class CostAsset(unittest.TestCase):
    def env(self):
        return dict(SOURCE_SHA='a' * 40, GITHUB_SHA='a' * 40, CHECKPOINT_ASSET='12/34',
                    CHECKPOINT_SHA256=SHA, VAL_SHA256='b' * 64, COST_GROUPS='400')

    def metadata(self):
        return dict(id=12, draft=True, assets=[dict(id=34, state='uploaded', size=len(BODY))])

    def run_download(self, metadata=None, responses=None, sha=SHA, existing=False):
        metadata = self.metadata() if metadata is None else metadata
        replies = [Response(json.dumps(metadata).encode())] + (responses or [Response(BODY)])
        requests = []
        def fake(req):
            requests.append(req)
            return replies.pop(0)
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / 'context.safetensors'
            if existing:
                dest.write_bytes(b'preserve')
            try:
                result = C.download('12/34', sha, dest, 'FAKE_TOKEN', fake)
                self.assertEqual(dest.read_bytes(), BODY)
                return result, requests
            except Exception:
                self.assertEqual(dest.read_bytes() if dest.exists() else None,
                                 b'preserve' if existing else None)
                raise

    def test_inputs_exact_identity_and_bounds(self):
        for n in ('400', '800'):
            env = self.env(); env['COST_GROUPS'] = n
            C.inputs(env, 'a' * 40)
        for key, bad in [('SOURCE_SHA', 'A' * 40), ('GITHUB_SHA', 'c' * 40),
                         ('CHECKPOINT_SHA256', 'f' * 63), ('VAL_SHA256', 'Z' * 64),
                         ('COST_GROUPS', '399'), ('COST_GROUPS', '801'),
                         ('COST_GROUPS', '4e2'), ('COST_GROUPS', '400\n')]:
            env = self.env(); env[key] = bad
            with self.subTest(key=key, bad=bad), self.assertRaises(C.Refused):
                C.inputs(env, 'a' * 40)
        with self.assertRaises(C.Refused):
            C.inputs(self.env(), 'c' * 40)

    def test_malicious_asset_ids_make_no_requests(self):
        for asset in ('0/1', '-1/2', '1/0', '1/2/3', '1/2?token=x', '../2',
                      'https://evil/1', '1/2\n', '1/$(id)', '1/2;id', '01/2', '1/'+'9'*21):
            with self.subTest(asset=asset), self.assertRaises(C.Refused):
                C.download(asset, SHA, 'unused', 'FAKE', lambda _: self.fail('network'))

    def test_transport_inputs_need_no_validation_or_model_data(self):
        env = self.env()
        env.update(TRANSPORT_ONLY='true')
        del env['VAL_SHA256'], env['COST_GROUPS']
        C.inputs(env, env['SOURCE_SHA'])
        for key, value in [('TRANSPORT_ONLY', 'yes'), ('TRANSPORT_ONLY', 'false'),
                           ('CHECKPOINT_SHA256', 'bad'), ('GITHUB_SHA', 'c' * 40)]:
            with self.subTest(key=key), self.assertRaises(C.Refused):
                C.inputs(dict(env, **{key: value}), env['SOURCE_SHA'])

    def test_direct_download(self):
        result, reqs = self.run_download()
        self.assertEqual(result, dict(sha256=SHA, size=len(BODY)))
        self.assertTrue(all(r.full_url.startswith(C.API) for r in reqs))
        self.assertTrue(all(r.get_header('Authorization') == 'Bearer FAKE_TOKEN' for r in reqs))

    def test_redirect_strips_authorization_each_hop(self):
        _, reqs = self.run_download(responses=[
            Response(status=302, headers={'Location': 'https://release-assets.githubusercontent.com/a?sig=FAKE'}),
            Response(status=302, headers={'Location': 'https://objects.githubusercontent.com/b'}),
            Response(BODY)])
        self.assertEqual(len(reqs), 4)
        self.assertTrue(all(r.get_header('Authorization') is None for r in reqs[2:]))

    def test_redirect_refusals_and_loop(self):
        for url in ('http://objects.githubusercontent.com/a', 'https://evil.test/a',
                    'https://objects.githubusercontent.com.evil/a',
                    'https://user@objects.githubusercontent.com/a',
                    'https://objects.githubusercontent.com:444/a',
                    'https://objects.githubusercontent.com/a#x', '/relative',
                    'https://objects.githubusercontent.com/\na', 'https://objects.githubusercontent.com\\evil/a'):
            with self.subTest(url=url), self.assertRaises(C.Refused):
                self.run_download(responses=[Response(status=302, headers={'Location': url})])
        url = 'https://objects.githubusercontent.com/a'
        with self.assertRaises(C.Refused):
            self.run_download(responses=[Response(status=302, headers={'Location': url}) for _ in range(2)])
        with self.assertRaises(C.Refused):
            self.run_download(responses=[Response(status=302, headers={})])

    def test_membership_draft_state_size_failures(self):
        for key, value in [('draft', False), ('id', 13), ('assets', [])]:
            md = self.metadata(); md[key] = value
            with self.subTest(key=key), self.assertRaises(C.Refused):
                self.run_download(metadata=md)
        for key, value in [('id', 35), ('state', 'new'), ('size', 0),
                           ('size', C.MAX_SIZE+1), ('size', True)]:
            md = self.metadata(); md['assets'][0][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(C.Refused):
                self.run_download(metadata=md)

    def test_digest_size_failure_cleans_partial_and_no_overwrite(self):
        with self.assertRaises(C.Refused): self.run_download(sha='0' * 64)
        for body in (BODY[:-1], BODY+b'extra'):
            with self.assertRaises(C.Refused): self.run_download(responses=[Response(body)])
        with self.assertRaises(FileExistsError): self.run_download(existing=True)
        with self.assertRaises(C.Refused): self.run_download(responses=[Response(b'private body', 403)])

    def test_no_automatic_redirect_and_redirect_budget(self):
        self.assertIsNone(C.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://evil.test'))
        with self.assertRaises(C.Refused):
            self.run_download(responses=[Response(status=302, headers={
                'Location': f'https://objects.githubusercontent.com/{n}'}) for n in range(4)])
        def denied(req):
            return Response(b'private metadata', status=404)
        with self.assertRaises(C.Refused):
            C.download('12/34', SHA, 'unused', 'FAKE', denied)

    def test_cli_errors_are_generic(self):
        stderr = io.StringIO()
        with patch.dict(os.environ, self.env()), patch.object(C.subprocess, 'check_output', return_value='a'*40), \
             patch.object(C, 'download', side_effect=RuntimeError('FAKE_TOKEN https://private/?secret=raw')), \
             patch.dict(os.environ, EXP='/unused', GH_TOKEN='FAKE_TOKEN'), redirect_stderr(stderr):
            self.assertEqual(C.main(), 1)
        self.assertEqual(stderr.getvalue(), 'cost unmeasured: checkpoint input or transport refused\n')

    def cli_with_responses(self, responses):
        stderr = io.StringIO()
        requests = []
        download = C.download
        def fake(request):
            requests.append(request)
            return responses.pop(0)
        def transport(asset, sha, destination, token):
            return download(asset, sha, destination, token, fake)
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(self.env(), EXP=tmp, GH_TOKEN='CANARY_TOKEN')
            with patch.dict(os.environ, env), \
                 patch.object(C.subprocess, 'check_output', return_value='a'*40), \
                 patch.object(C, 'download', side_effect=transport), redirect_stderr(stderr):
                result = C.main()
            destination = Path(tmp) / 'context.safetensors'
            body = destination.read_bytes() if destination.exists() else None
        return result, stderr.getvalue(), requests, body

    def assert_http_diagnostic(self, responses, phase, status):
        result, stderr, _, body = self.cli_with_responses(responses)
        self.assertEqual(result, 1)
        self.assertIsNone(body)
        lines = stderr.splitlines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[0], 'cost unmeasured: checkpoint input or transport refused')
        self.assertEqual(json.loads(lines[1]), dict(phase=phase, status=status))
        self.assertLess(len(lines[1]), 80)
        for canary in ('CANARY_TOKEN', 'CANARY_URL', 'CANARY_BODY'):
            self.assertNotIn(canary, stderr)

    def test_cli_http_refusals_identify_only_phase_and_status(self):
        metadata = json.dumps(self.metadata()).encode()
        private = b'CANARY_BODY https://private.test/CANARY_URL?token=CANARY_TOKEN'
        for status in (401, 403, 404):
            with self.subTest(status=status, phase='release_metadata'):
                self.assert_http_diagnostic([Response(private, status)], 'release_metadata', status)
            with self.subTest(status=status, phase='asset'):
                self.assert_http_diagnostic([Response(metadata), Response(private, status)], 'asset', status)
            with self.subTest(status=status, phase='cdn'):
                self.assert_http_diagnostic([Response(metadata), Response(status=302, headers={
                    'Location': 'https://objects.githubusercontent.com/CANARY_URL?token=CANARY_TOKEN'}),
                    Response(private, status)], 'asset', status)

    def test_cli_malformed_http_status_is_closed_unknown(self):
        for status in (None, True, 200.0, -1, 600, 'CANARY_TOKEN CANARY_URL CANARY_BODY',
                       {'CANARY_TOKEN': 'CANARY_URL CANARY_BODY'}):
            for phase in ('release_metadata', 'asset'):
                with self.subTest(status=status, phase=phase):
                    responses = [Response(b'CANARY_BODY', status)]
                    if phase == 'asset':
                        responses.insert(0, Response(json.dumps(self.metadata()).encode()))
                    self.assert_http_diagnostic(responses, phase, 'unknown')

    def test_cli_success_preserves_bytes_and_redirect_authorization(self):
        result, stderr, requests, body = self.cli_with_responses([
            Response(json.dumps(self.metadata()).encode()), Response(status=302, headers={
                'Location': 'https://objects.githubusercontent.com/checkpoint?sig=CANARY_URL'}),
            Response(BODY)])
        self.assertEqual(result, 0)
        self.assertEqual(stderr, '')
        self.assertEqual(body, BODY)
        self.assertTrue(all(request.get_header('Authorization') == 'Bearer CANARY_TOKEN'
                            for request in requests[:2]))
        self.assertIsNone(requests[2].get_header('Authorization'))


class Workflow(unittest.TestCase):
    def setUp(self):
        self.source = (ROOT / '.github/workflows/bouncer-context-experiment.yml').read_text()
        self.cost = re.split(r'\n  [a-zA-Z0-9_-]+:\n',
                             self.source.split('\n  cost-only:\n', 1)[1], maxsplit=1)[0]
        self.ci = (ROOT / '.github/workflows/ci.yml').read_text()

    def test_manual_guard_permissions_bridge_and_allowlist(self):
        self.assertIn("if: ${{ github.event_name == 'workflow_dispatch' && inputs.mode == 'cost-only' }}", self.cost)
        probe = self.source.split('\n  probe:\n', 1)[1].split('\n  train:\n', 1)[0]
        guard = re.search(r'^    if: (.+)$', probe, re.M).group(1)
        self.assertIn("inputs.mode != 'cost-only'", guard)
        self.assertIn('!inputs.transport_only', guard)
        self.assertEqual(self.source.count("inputs.mode == 'full'"), 2)
        self.assertIn("inputs.context_experiment == 'cost-only'", self.ci)
        for key in ('source_sha', 'checkpoint_asset', 'checkpoint_sha256', 'val_sha256', 'groups', 'transport_only'):
            self.assertEqual(self.source.count('      '+key+':\n'), 2)
            self.assertIn(f'{key}: ${{{{ inputs.{key} }}}}', self.ci)
        for source in (self.source, self.ci):
            self.assertRegex(source, r'(?m)^permissions:\n  contents: read\n')
        self.assertIn('runs-on: ubuntu-24.04', self.cost)
        self.assertIn('timeout-minutes: ${{ inputs.transport_only && 10 || 120 }}', self.cost)
        self.assertIn('timeout-minutes: 110', self.cost)
        self.assertIn('--mode full --threads 4', self.cost)
        self.assertNotIn('context_train', self.cost)
        self.assertNotIn('context_eval', self.cost)
        self.assertNotIn('tests/evals', self.cost)
        self.assertEqual(self.cost.count('GH_TOKEN:'), 1)
        upload = self.cost.split('        path: |\n')[1].split('    - name:')[0]
        self.assertEqual([x.strip() for x in upload.splitlines() if x.strip()], [
            '${{ runner.temp }}/bouncer-context/evidence/cost-full.json',
            '${{ runner.temp }}/bouncer-context/evidence/cost-receipt.json'])

    def test_transport_stops_before_model_setup_and_uploads_receipt_only(self):
        steps = self.cost.split('    - name: ')
        by_name = {step.splitlines()[0]: step for step in steps[1:]}
        download = 'Read draft-release checkpoint (transport preflight required)'
        model_steps = ('Install existing dependencies with CPU torch first',
                       'Fetch and verify the pinned public base, then go offline',
                       'Recreate G1 and verify external validation hash and manifest',
                       'Measure fresh CPU arms on regenerated G1 (cost evidence only)',
                       'Write compact cost receipt', 'Upload only completed cost evidence and compact receipt')
        for name in model_steps:
            self.assertIn('if: ${{ !inputs.transport_only }}', by_name[name])
            self.assertLess(self.cost.index(download), self.cost.index(name))
        self.assertIn('timeout-minutes: 5', by_name[download])
        for name in ('Record verified transport only', 'Upload transport receipt only'):
            self.assertIn('if: inputs.transport_only', by_name[name])
        upload = by_name['Upload transport receipt only']
        self.assertIn('path: ${{ runner.temp }}/bouncer-context/evidence/transport-receipt.json', upload)
        self.assertNotIn('context.safetensors', upload)
        self.assertNotIn('cost-full.json', upload)
        self.assertIn("models='NOT_RUN'", by_name['Record verified transport only'])

    def test_embedded_shell_and_python_syntax_and_no_input_interpolation(self):
        blocks = re.findall(r'      run: \|\n((?:        .*\n|\n)+)', self.cost)
        self.assertGreater(len(blocks), 7)
        for block in blocks:
            shell = textwrap.dedent(block)
            self.assertNotIn('${{', shell)
            result = subprocess.run(['bash', '-n'], input=shell, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            for code in re.findall(r"<<'PY'\n(.*?)\nPY", shell, re.S):
                ast.parse(code)

    def test_regenerated_validation_check_with_fake_data(self):
        code = self.cost.split("root = Path(os.environ['EXP']) / 'synthetic'\n")[1].split('\n        PY')[0]
        code = "root = Path(os.environ['EXP']) / 'synthetic'\n" + textwrap.dedent(code)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'synthetic'; root.mkdir()
            for name in ('train.jsonl', 'val.jsonl'): (root/name).write_bytes(BODY)
            dm = dict(groups=400, seed=7, rubric='v1-R1-text-catalog', files={
                name: dict(sha256=SHA) for name in ('train.jsonl', 'val.jsonl')})
            def run():
                (root/'data-manifest.json').write_text(json.dumps(dm))
                exec(code, dict(Path=Path, os=os, json=json, hashlib=hashlib))
            with patch.dict(os.environ, EXP=tmp, COST_GROUPS='400', VAL_SHA256=SHA):
                run()
                dm['seed']=8
                with self.assertRaises(AssertionError): run()
                dm['seed']=7; dm['files']['val.jsonl']['sha256']='0'*64
                with self.assertRaises(AssertionError): run()
                dm['files']['val.jsonl']['sha256']=SHA
                with patch.dict(os.environ, VAL_SHA256='0'*64), self.assertRaises(AssertionError): run()


if __name__ == '__main__':
    unittest.main()
