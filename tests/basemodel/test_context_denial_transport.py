"""Synthetic transport checks only; every provider, model and child is a fake."""
import ast
import asyncio
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import AsyncMock, Mock, patch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'tools/basemodel'))
import context_external_bundle as B
import context_modal_existing as M

E20 = 'context-v1-e20'
RECIPE = 'context-v1-e20-denial-invariance-v1'
SHA = 'a' * 40


class DenialTransportTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='context-denial-transport-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.stage = self.root / 'stage'
        self.stage.mkdir()
        self.evidence = self.root / 'evidence'
        # Avoid loading row/data modules: these tests only exercise transport.
        root_patch = patch.object(B, 'run_root', side_effect=lambda run, scratch=B.SCRATCH: Path(scratch) / run)
        root_patch.start()
        self.addCleanup(root_patch.stop)

    def receipt(self, recipe=None):
        inv = {p: 'b' * 64 for p in B.UPLOAD_PATHS}
        config = dict(groups=400, seed=7, device='cuda')
        if recipe is not None:
            config['recipe'] = recipe
        return dict(schema='apassy-context-modal-receipt-v1', run_id='synthetic-run', source_sha=SHA,
                    inventory=inv, inventory_sha256=B.inventory_sha256(inv),
                    package_versions=B.PACKAGE_VERSIONS, torch_wheel_sha256=B.TORCH_SHA256,
                    gpu_name='NVIDIA L4', freeze_sha256='c' * 64, config=config,
                    env={'NVIDIA_TF32_OVERRIDE': '0'}, started_epoch=1000, finished_epoch=1100)

    def test_exact_legacy_and_recipe_receipts(self):
        for recipe in (None, E20, RECIPE):
            receipt = self.receipt(recipe)
            self.assertIs(B._receipt(receipt), receipt)
            self.assertEqual(set(receipt['config']),
                             {'groups', 'seed', 'device'} | ({'recipe'} if recipe else set()))
        bad = [None, [], 'cuda', {}, dict(groups=True, seed=7, device='cuda'),
               dict(groups=400.0, seed=7, device='cuda'),
               dict(groups=400, seed=7, device='cuda', recipe=None),
               dict(groups=400, seed=7, device='cuda', recipe='context-v1-e21'),
               dict(groups=400, seed=7, device='cuda', recipe=RECIPE, epochs=20),
               dict(groups=400, seed=True, device='cuda'),
               dict(groups=400, seed=7.0, device='cuda'),
               dict(groups=400, seed=7, device='cuda', recipe=True)]
        for recipe in (None, E20, RECIPE):
            config = self.receipt(recipe)['config']
            bad.extend([dict(config, training_views='denial-balanced-v1'),
                        dict(config, policy='denial-balanced-v1'), dict(config, extra=1)])
        for config in bad:
            with self.subTest(config=config), patch.object(B, 'run_root') as root:
                receipt = dict(self.receipt(), config=config)
                out = self.root / 'refused.tar'
                with self.assertRaisesRegex(ValueError, 'receipt config'):
                    B.pack(self.stage, receipt, out)
                root.assert_not_called()
                self.assertFalse(out.exists())

    def test_unknown_recipe_before_roots_marker_children_or_provider(self):
        modal = NS(App=Mock(), Dict=NS(from_name=Mock()))
        for recipe in ('', 'unknown', 'denial-balanced-v1', 20, False, True, [], {}):
            with self.subTest(recipe=recipe), patch.dict(sys.modules, {'modal': modal}), \
                 patch.object(M, '_attest_tree') as attest, patch.object(M, '_child') as child, \
                 patch.object(M, '_save') as save, patch.object(B, 'run_root') as root:
                with self.assertRaisesRegex(ValueError, 'unknown training recipe'):
                    M.launch(SHA, 'run', 8, self.evidence, self.stage, recipe=recipe)
                with self.assertRaisesRegex(ValueError, 'unknown training recipe'):
                    M.worker('run', SHA, 2000, 'b' * 64, recipe=recipe)
                with self.assertRaisesRegex(ValueError, 'unknown training recipe'):
                    M._serialized_entry(None)('run', SHA, 2000, 'b' * 64, recipe=recipe)
                with self.assertRaisesRegex(ValueError, 'unknown training recipe'):
                    asyncio.run(M._execute(self.stage, self.evidence, SHA, 'run', 'b' * 64, 1000,
                                           recipe=recipe))
                for call in (attest, child, save, root, modal.App, modal.Dict.from_name):
                    call.assert_not_called()
                self.assertFalse(self.evidence.exists())

    def test_cli_explicit_choice_and_legacy_call_shape(self):
        argv = ['launch', '--source-sha', SHA, '--run-id', 'run', '--approved-budget-usd', '8',
                '--evidence-dir', str(self.evidence)]
        with patch.object(M, 'launch') as launch:
            self.assertEqual(M.main(argv), 0)
            self.assertEqual(launch.call_args.kwargs, {})
            self.assertEqual(len(launch.call_args.args), 5)
            for recipe in (E20, RECIPE):
                self.assertEqual(M.main(argv + ['--recipe', recipe]), 0)
                self.assertEqual(launch.call_args.kwargs, dict(recipe=recipe))
            launch.reset_mock()
            with self.assertRaises(SystemExit), patch('sys.stderr', io.StringIO()):
                M.main(argv + ['--recipe', 'unknown'])
            launch.assert_not_called()

    def test_serialized_entry_forwards_only_opt_in(self):
        (self.stage / 'source.py').write_text('# synthetic attested source\n')
        inv = M._attest_tree(self.stage, B.inventory_sha256({'source.py': B._sha(self.stage / 'source.py')}))
        digest = B.inventory_sha256(inv)
        volume = object()
        for recipe in (None, E20, RECIPE):
            with patch('pathlib.Path', return_value=self.stage), \
                 patch.object(M, 'worker', return_value={'status': 'ok'}) as worker, \
                 patch.object(M, '_export_volume', None, create=True), patch.object(sys, 'path', sys.path.copy()):
                M._serialized_entry(volume)('run', SHA, M.time.time() + 2000, digest, recipe=recipe)
                self.assertIs(M._export_volume, volume)
                self.assertEqual(len(worker.call_args.args), 4)
                self.assertEqual(worker.call_args.kwargs, {} if recipe is None else dict(recipe=recipe))

    def test_worker_recipe_child_marker_receipt_and_cleanup(self):
        for recipe in (None, E20, RECIPE):
            run_root = self.root / ('legacy' if recipe is None else 'e20')
            marker = NS(put=Mock(return_value=True))
            modal = NS(Dict=NS(from_name=Mock(return_value=marker)))
            torch = NS(cuda=NS(is_available=lambda: True, get_device_name=lambda index: 'NVIDIA L4'))
            modules = {'modal': modal, 'torch': torch,
                       'context_train': NS(package_versions=lambda: B.PACKAGE_VERSIONS),
                       'common': NS(base_dir=lambda: self.stage)}
            commands = []
            def child(command, deadline, env):
                commands.append(command)
                if command[1].endswith('context_existing_freeze.py'):
                    (run_root / 'full').mkdir()
                    (run_root / 'full/freeze.json').write_bytes(b'{"development_reading":{}}\n')
            def pack(root, receipt, output):
                self.assertEqual(receipt['config'], self.receipt(recipe)['config'])
                self.assertEqual(set(receipt), B.RECEIPT_KEYS)
                return dict(sha256='f' * 64, size=10240)
            volume = NS(commit=Mock())
            with patch.dict(sys.modules, modules), patch.object(M, '_attest_tree', return_value={}), \
                 patch.object(B, 'run_root', return_value=run_root), patch.object(M, '_child', side_effect=child), \
                 patch.object(B, 'pack', side_effect=pack), \
                 patch.object(M, '_export_volume', volume, create=True), patch.object(M, 'time', NS(time=lambda: 1000)), \
                 patch.object(sys, 'path', sys.path.copy()):
                result = M.worker('run', SHA, 2000, B.inventory_sha256({}), recipe=recipe)
            self.assertEqual(result['status'], 'ok')
            self.assertEqual(len(commands), 2)
            self.assertNotIn('--recipe', commands[0])
            if recipe is None:
                self.assertNotIn('--recipe', commands[1])
            else:
                self.assertEqual(commands[1][-2:], ['--recipe', recipe])
            expected = dict(source_sha=SHA, started_epoch=1000)
            if recipe:
                expected['recipe'] = recipe
            marker.put.assert_called_once_with('run', expected, skip_if_exists=True)
            volume.commit.assert_called_once_with()
            self.assertFalse(run_root.exists())

    def test_new_worker_deadline_guard_is_before_attestation(self):
        with patch.object(M, 'time', NS(time=lambda: 1000)), patch.object(M, '_attest_tree') as attest:
            for deadline in (8200.01, float('inf'), 1800):
                with self.subTest(deadline=deadline), self.assertRaises(TimeoutError):
                    M.worker('run', SHA, deadline, 'b' * 64, recipe=RECIPE)
            attest.assert_not_called()

    def test_launch_binds_attempt_success_and_exact_source_inventory(self):
        blobs = {p: ('synthetic:' + p).encode() for p in B.UPLOAD_PATHS}
        inv = {p: hashlib.sha256(raw).hexdigest() for p, raw in blobs.items()}
        goldens = sorted(p for p in blobs if p.startswith('tests/fixtures/'))
        def git(command, **kwargs):
            if command[1] == 'ls-tree':
                return ('\n'.join(goldens) + '\n').encode()
            return blobs[command[3][41:]]
        async def execute(stage, evidence, sha, run, digest, start, recipe=None):
            self.assertEqual(recipe, RECIPE)
            self.assertEqual(M._attest_tree(stage, digest), inv)
            self.assertFalse((stage / '.git').exists())
            return dict(status='ok')
        with patch.object(M.sys, 'version_info', (3, 12, 0)), \
             patch.object(B, 'git_inventory', return_value=inv), \
             patch.object(M.subprocess, 'check_output', side_effect=git), \
             patch.object(M, '_execute', side_effect=execute), patch.object(M, 'time', NS(time=lambda: 1000)):
            result = M.launch(SHA, 'run', 8, self.evidence, self.stage, recipe=RECIPE)
        for name in ('attempt.json', 'success.json'):
            receipt = json.loads((self.evidence / name).read_text())
            self.assertEqual(receipt['recipe'], RECIPE)
            self.assertEqual(receipt['deadline_epoch'], 8200)
            self.assertEqual(receipt['caller_cutoff_epoch'], 9100)
            self.assertEqual(receipt['envelope_usd'], 8)
        self.assertEqual(result['inventory_sha256'], B.inventory_sha256(inv))
        helper = 'tools/basemodel/context_dev_diagnostic.py'
        self.assertEqual(B.UPLOAD_PATHS.count(helper), 1)
        self.assertEqual(len(B.UPLOAD_PATHS), 38)
        self.assertFalse(any('/H' in p or '.git' in Path(p).parts for p in B.UPLOAD_PATHS))
        self.assertEqual(sum(p.startswith('tests/fixtures/') for p in B.UPLOAD_PATHS), 21)

    def fake_sdk(self, content=b'fake bundle'):
        call = NS(object_id='fc-own', get=NS(aio=AsyncMock(return_value=dict(
            status='ok', bundle_size=len(content), bundle_sha256=hashlib.sha256(content).hexdigest(),
            freeze_sha256='f' * 64))), cancel=NS(aio=AsyncMock()))
        function = NS(spawn=NS(aio=AsyncMock(return_value=call)))
        async def read(name):
            yield content
        volume = NS(object_id='vo-own', read_file=NS(aio=read))
        class Context:
            def __init__(self, value):
                self.value = value
                self.closed = False
            async def __aenter__(self):
                return self.value
            async def __aexit__(self, *args):
                self.closed = True
        volume_context = Context(volume)
        app = NS(app_id='ap-own', function=Mock(return_value=lambda entry: function))
        app_context = Context(app)
        app.run = Mock(return_value=app_context)
        image = NS(build=NS(aio=AsyncMock()))
        modal = NS(__version__='1.5.4', App=Mock(return_value=app),
                   Volume=NS(ephemeral=Mock(return_value=volume_context)))
        return modal, app, call, image, volume, app_context, volume_context

    def test_recipe_deadlines_and_cleanup_with_one_spawn(self):
        self.assertEqual(M.deadline_limits(), dict(function_timeout=14400, remote=14400, caller=15300,
                                                  build=1800, export_reserve=900))
        self.assertEqual(M.deadline_limits(RECIPE), dict(function_timeout=7200, remote=7200, caller=8100,
                                                        build=1800, export_reserve=900))
        self.assertEqual(M.deadline_limits(E20), M.deadline_limits(RECIPE))
        self.assertEqual(len(B.UPLOAD_PATHS), 38)
        self.assertEqual(len(B.BUNDLE_MEMBERS), 9)
        self.assertEqual(B.MAX_BUNDLE_BYTES, 256 * 1024**2)
        modal, app, call, image, volume, app_context, volume_context = self.fake_sdk()
        self.evidence.mkdir()
        waits = []
        real_wait_for = asyncio.wait_for
        async def wait_for(awaitable, timeout):
            phase = awaitable.cr_code.co_name
            waits.append((phase, timeout))
            return await real_wait_for(awaitable, timeout)
        with patch.dict(sys.modules, {'modal': modal}), patch.object(M, '_image', return_value=image), \
             patch.object(M, '_snapshot', AsyncMock(return_value={})), \
             patch.object(M, '_cli', AsyncMock(return_value='')) as cli, \
             patch.object(M, 'time', NS(time=lambda: 1000)), \
             patch.object(M, 'asyncio', NS(wait_for=wait_for, create_task=asyncio.create_task,
                                         sleep=asyncio.sleep, gather=asyncio.gather)):
            asyncio.run(M._execute(self.stage, self.evidence, SHA, 'run', 'b' * 64, 1000, recipe=RECIPE))
        self.assertEqual(waits[:3], [('bounded_attempt', 8100), ('session', 7200), ('build', 1800)])
        options = app.function.call_args.kwargs
        self.assertEqual(options['timeout'], 7200)
        self.assertEqual((options['cpu'], options['memory'], options['gpu']),
                         ((4., 4.), (32768, 32768), ['A10', 'L4']))
        self.assertEqual((options['retries'], options['max_containers'], options['secrets']), (0, 1, []))
        # The registered function has only this one spawn, with the recipe bound.
        function = app.function.return_value(None)
        function.spawn.aio.assert_awaited_once_with('run', SHA, 8200, 'b' * 64, recipe=RECIPE)
        call.cancel.aio.assert_awaited_once_with(terminate_containers=True)
        cli.assert_awaited_once_with('app', 'stop', 'ap-own', '--env', 'main', '--yes')
        self.assertTrue(app_context.closed and volume_context.closed)
        self.assertTrue((self.evidence / 'after.json').is_file())

    def test_receipt_recipe_cannot_be_relabelled_against_freeze(self):
        for receipt_recipe, freeze_recipe in ((E20, RECIPE), (RECIPE, E20),
                                             (None, RECIPE), (RECIPE, None)):
            receipt = self.receipt(receipt_recipe)
            root = self.root / str(receipt_recipe) / str(freeze_recipe) / receipt['run_id']
            path = root / 'full/freeze.json'
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps({'config': {} if freeze_recipe is None else {'recipe': freeze_recipe}}))
            receipt['freeze_sha256'] = B._sha(path)
            core = NS(package_versions=lambda: B.PACKAGE_VERSIONS, verify_freeze=Mock())
            with patch.dict(sys.modules, {'context_train': core}), \
                 patch.object(B, 'git_inventory', return_value=receipt['inventory']):
                with self.assertRaisesRegex(ValueError, 'receipt/freeze recipe differs'):
                    B.verify_restored(root, receipt, receipt['run_id'], SHA, receipt['freeze_sha256'], self.stage)
            core.verify_freeze.assert_not_called()

    def test_serialized_allowlist_is_inline_and_archive_stays_plain_ustar(self):
        tree = ast.parse((REPO / 'tools/basemodel/context_modal_existing.py').read_text())
        closure = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
                       and n.name == '_serialized_entry')
        entry = closure.body[0]
        self.assertIsInstance(entry, ast.FunctionDef)
        self.assertIsInstance(entry.body[0], ast.If)
        choices = [n.comparators[0] for n in ast.walk(entry.body[0].test)
                   if isinstance(n, ast.Compare) and isinstance(n.ops[0], ast.NotIn)]
        self.assertEqual([ast.literal_eval(n) for n in choices], [(E20, RECIPE, 'context-v1-e20-batch-tail-v1')])
        bundle = ast.parse((REPO / 'tools/basemodel/context_external_bundle.py').read_text())
        pack = next(n for n in bundle.body if isinstance(n, ast.FunctionDef) and n.name == 'pack')
        formats = [k.value for n in ast.walk(pack) if isinstance(n, ast.Call)
                   for k in n.keywords if k.arg == 'format']
        self.assertEqual([ast.unparse(n) for n in formats], ['tarfile.USTAR_FORMAT'])


if __name__ == '__main__':
    unittest.main()
