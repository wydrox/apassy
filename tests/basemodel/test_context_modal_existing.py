"""Unpaid, stdlib-only tests; Modal/torch/process execution are always faked."""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import AsyncMock, Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools/basemodel'))
import context_modal_existing as M
import context_external_bundle as B
import context_existing_freeze as W

SHA = 'a' * 40


class Checks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        self.evidence = self.root / 'evidence'

    def test_import_without_dependencies(self):
        script = '''import sys
class Block:
 def find_spec(self, fullname, *args):
  if fullname.split('.')[0] in ('torch', 'modal'):
   raise AssertionError('dependency import')
sys.meta_path.insert(0, Block())
import context_modal_existing, context_external_bundle
'''
        result = subprocess.run([sys.executable, '-B', '-c', script], capture_output=True,
                                env={**os.environ, 'PYTHONPATH': str(ROOT / 'tools/basemodel')})
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_validation_before_sdk(self):
        for sha, budget in [('A'*40, 8), (SHA, 7.99), (SHA, float('inf')),
                            (SHA, float('nan')), (SHA, '8'), (SHA, True)]:
            with self.subTest(sha=sha, budget=budget), self.assertRaises(ValueError):
                M.launch(sha, 'test-run', budget, self.evidence, self.repo)
        for run in ('../bad', 'target', 'H1', ''):
            with self.assertRaises(ValueError):
                M.launch(SHA, run, 8, self.evidence, self.repo)
        self.evidence.mkdir()
        with self.assertRaises(ValueError):
            M.launch(SHA, 'test-run', 8, self.evidence, self.repo)
        with self.assertRaises(ValueError):
            M.launch(SHA, 'test-run', 8, self.repo / 'evidence', self.repo)

    def test_launcher_python_must_match_remote_before_staging(self):
        for name, version in [('cpython', (3, 11, 9)), ('cpython', (3, 13, 0)),
                              ('pypy', (3, 12, 0))]:
            with self.subTest(name=name, version=version), \
                 patch.object(M.sys, 'implementation', NS(name=name)), \
                 patch.object(M.sys, 'version_info', version), \
                 patch.object(B, 'git_inventory') as inventory, \
                 patch.object(M, '_execute') as execute:
                with self.assertRaisesRegex(ValueError, 'CPython 3.12'):
                    M.launch(SHA, 'test-run', 8, self.evidence, self.repo)
            inventory.assert_not_called()
            execute.assert_not_called()
            self.assertFalse(self.evidence.exists())

    def test_git_refusal_before_modal(self):
        for message in ('dirty tracked tree', 'source HEAD mismatch'):
            with patch.object(B, 'git_inventory', side_effect=ValueError(message)):
                with self.assertRaisesRegex(ValueError, message):
                    M.launch(SHA, 'test-run', 8, self.evidence, self.repo)
        self.assertFalse(self.evidence.exists())

    def test_stage_exact_git_blobs(self):
        names = B.UPLOAD_PATHS
        blobs = {p: ('blob:' + p).encode() for p in names}
        inv = {p: hashlib.sha256(raw).hexdigest() for p, raw in blobs.items()}
        goldens = sorted(p for p in names if p.startswith('tests/fixtures/'))
        def git(command, **kwargs):
            if command[1] == 'ls-tree':
                return ('\n'.join(goldens) + '\n').encode()
            self.assertEqual(command[:3], ['git', 'cat-file', 'blob'])
            return blobs[command[3][41:]]
        async def execute(stage, *args):
            self.assertEqual(M._attest_tree(stage, B.inventory_sha256(inv)), inv)
            self.assertFalse((stage / '.git').exists())
            return dict(status='ok')
        with patch.object(B, 'git_inventory', return_value=inv), \
             patch.object(M.subprocess, 'check_output', side_effect=git), \
             patch.object(M, '_execute', side_effect=execute) as call:
            result = M.launch(SHA, 'test-run', 99, self.evidence, self.repo)
        self.assertEqual(result['envelope_usd'], 8)
        call.assert_called_once()
        self.assertTrue((self.evidence / 'attempt.json').is_file())

    def test_worker_refuses_before_subprocess(self):
        inv_sha = B.inventory_sha256({})
        fake_torch = NS(cuda=NS(is_available=Mock(return_value=True), get_device_name=Mock(return_value='NVIDIA L4')))
        marker = NS(put=Mock(return_value=False))
        fake_modal = NS(Dict=NS(from_name=Mock(return_value=marker)))
        core = NS(package_versions=Mock(return_value=B.PACKAGE_VERSIONS))
        for case in ('deadline', 'inventory', 'versions', 'cuda', 'gpu', 'duplicate'):
            core.package_versions.return_value = {} if case == 'versions' else B.PACKAGE_VERSIONS
            fake_torch.cuda.is_available.return_value = case != 'cuda'
            fake_torch.cuda.get_device_name.return_value = 'NVIDIA A100' if case == 'gpu' else 'NVIDIA L4'
            with self.subTest(case=case), patch.dict(sys.modules, {'torch': fake_torch, 'modal': fake_modal, 'context_train': core}), \
                 patch.object(M, 'REMOTE_SRC', str(self.root)), patch.object(M.subprocess, 'Popen') as process:
                with self.assertRaises((ValueError, TimeoutError)):
                    M.worker('test-run', SHA, 0 if case == 'deadline' else M.time.time()+2000,
                             'bad' if case == 'inventory' else inv_sha)
                process.assert_not_called()
        marker.put.assert_called_once()
        self.assertTrue(marker.put.call_args.kwargs['skip_if_exists'])

    def test_worker_rejects_unsupported_gpu_before_marker_root_or_child(self):
        for name in ('NVIDIA A100', 'NVIDIA T4', 'NVIDIA H100', 'NVIDIA L40S',
                     'unknown', 'A10', 'NVIDIA A10 extra', '', None):
            core = NS(package_versions=lambda: B.PACKAGE_VERSIONS)
            torch = NS(cuda=NS(is_available=lambda: True, get_device_name=lambda _: name))
            modal = NS(Dict=NS(from_name=Mock()))
            with self.subTest(gpu_name=name), patch.dict(sys.modules, {
                    'context_train': core, 'torch': torch, 'modal': modal}), \
                 patch.object(M, 'REMOTE_SRC', str(self.repo)), \
                 patch.object(B, 'run_root') as root, patch.object(Path, 'mkdir') as mkdir, \
                 patch.object(M, '_child') as child:
                with self.assertRaisesRegex(ValueError, 'unsupported GPU'):
                    M.worker('run', SHA, M.time.time()+2000, B.inventory_sha256({}))
                modal.Dict.from_name.assert_not_called()
                root.assert_not_called()
                mkdir.assert_not_called()
                child.assert_not_called()

    def test_worker_success_and_timeout_cleanup(self):
        for gpu_name, timeout in [(name, False) for name in B.SUPPORTED_GPU_NAMES] + [('NVIDIA L4', True)]:
            run_root = self.root / ('failed' if timeout else 'success')
            core = NS(package_versions=lambda: B.PACKAGE_VERSIONS)
            torch = NS(cuda=NS(is_available=lambda: True, get_device_name=lambda _: gpu_name))
            marker = NS(put=Mock(return_value=True))
            modal = NS(Dict=NS(from_name=Mock(return_value=marker)))
            volume = NS(commit=Mock())
            calls = []
            def child(command, deadline, env):
                calls.append(command)
                self.assertEqual(env['NVIDIA_TF32_OVERRIDE'], '0')
                self.assertEqual(env['HF_HUB_OFFLINE'], '1')
                self.assertEqual(env['TMPDIR'], str(run_root/'tmp'))
                if len(calls) == 2:
                    if timeout:
                        raise subprocess.TimeoutExpired('fake wrapper', 1)
                    (run_root/'full').mkdir()
                    (run_root/'full/freeze.json').write_bytes(b'fake freeze')
            def pack(root, receipt, output):
                self.assertEqual(receipt['config'], dict(groups=400, seed=7, device='cuda'))
                self.assertEqual(receipt['gpu_name'], gpu_name)
                self.assertEqual(receipt['inventory'], {})
                self.assertEqual(set(receipt), B.RECEIPT_KEYS)
                self.assertEqual(output, Path('/export/bundle.tar'))
                return dict(sha256='c'*64, size=10240)
            with self.subTest(gpu_name=gpu_name, timeout=timeout), patch.dict(sys.modules, {'context_train': core, 'torch': torch,
                    'modal': modal, 'common': NS(base_dir=lambda: '/public/base')}), \
                 patch.object(M, 'REMOTE_SRC', str(self.repo)), patch.object(B, 'run_root', return_value=run_root), \
                 patch.object(M, '_child', side_effect=child), patch.object(B, 'pack', side_effect=pack) as packed, \
                 patch.object(M, '_export_volume', volume, create=True):
                if timeout:
                    with self.assertRaises(subprocess.TimeoutExpired):
                        M.worker('run', SHA, M.time.time()+2000, B.inventory_sha256({}))
                    packed.assert_not_called()
                    volume.commit.assert_not_called()
                else:
                    result = M.worker('run', SHA, M.time.time()+2000, B.inventory_sha256({}))
                    self.assertEqual(result['bundle_sha256'], 'c'*64)
                    volume.commit.assert_called_once()
            self.assertFalse(run_root.exists())
            self.assertEqual(calls[0][-4:], ['--groups', '400', '--seed', '7'])
            self.assertEqual(calls[1][-4:], ['--device', 'cuda', '--source-sha', SHA])

    def test_inventory_covers_extra_and_symlink(self):
        pin = B.inventory_sha256({})
        M._attest_tree(self.root, pin)
        (self.root / 'extra').write_bytes(b'extra')
        with self.assertRaisesRegex(ValueError, 'inventory'):
            M._attest_tree(self.root, pin)
        (self.root / 'extra').unlink()
        (self.root / 'link').symlink_to('/does-not-exist')
        with self.assertRaisesRegex(ValueError, 'symlink'):
            M._attest_tree(self.root, pin)

    def test_timeout_kills_entire_group_no_pack(self):
        proc = NS(pid=1234, wait=Mock(side_effect=[subprocess.TimeoutExpired('fake', 1), None, None]))
        with patch.object(M.subprocess, 'Popen', return_value=proc) as popen, \
             patch.object(M.os, 'killpg') as kill, patch.object(B, 'pack') as pack:
            with self.assertRaises(subprocess.TimeoutExpired):
                M._child(['fake'], M.time.time()+1000, {})
        self.assertTrue(popen.call_args.kwargs['start_new_session'])
        self.assertEqual([c.args for c in kill.call_args_list], [(1234, M.signal.SIGTERM), (1234, M.signal.SIGKILL)])
        pack.assert_not_called()

    def test_wrapper_sha_before_core_and_git_fail_closed(self):
        base = self.root / 'base'
        base.mkdir()
        for sha in ('BAD', 'A'*40, 1):
            with patch.dict(sys.modules, {'context_train': None}), self.assertRaisesRegex(W.Unsupported, 'source SHA'):
                W.run(self.root/'data', self.root/'out', base, 'cpu', source_sha=sha)
        core = NS(source_commit=Mock(return_value='b'*40), install_training_audit=Mock(side_effect=RuntimeError('passed git')))
        with patch.dict(sys.modules, {'context_train': core}):
            with self.assertRaisesRegex(W.Unsupported, 'source commit mismatch'):
                W.run(self.root/'data', self.root/'out', base, 'cpu', source_sha=SHA)
            for error in (OSError('no git'), subprocess.CalledProcessError(1, 'git')):
                core.source_commit.side_effect = error
                with self.assertRaisesRegex(RuntimeError, 'passed git'):
                    W.run(self.root/'data', self.root/'out', base, 'cpu', source_sha=SHA)
            core.source_commit.side_effect = RuntimeError('unexpected git error')
            with self.assertRaisesRegex(RuntimeError, 'unexpected git error'):
                W.run(self.root/'data', self.root/'out', base, 'cpu', source_sha=SHA)

    def fake_sdk(self, *, stalled=False, build_stalled=False, export_stalled=False, content=b'bundle'):
        class Method:
            def __init__(self, func):
                self.aio = AsyncMock(side_effect=func)
        async def get():
            if stalled:
                await asyncio.Future()
            return dict(status='ok', bundle_sha256=hashlib.sha256(content).hexdigest(),
                        bundle_size=len(content), freeze_sha256='f'*64)
        call = NS(object_id='fc-own', get=Method(get), cancel=Method(lambda **kw: None))
        function = NS(spawn=Method(lambda *args: call))
        call.spawn = function.spawn
        class Context:
            def __init__(self, obj): self.obj = obj
            async def __aenter__(self):
                if build_stalled and self.obj is app:
                    await asyncio.Future()
                return self.obj
            async def __aexit__(self, *args): pass
        async def read(path):
            self.assertEqual(path, 'bundle.tar')
            if export_stalled:
                await asyncio.Future()
            yield content[:2]
            yield content[2:]
        volume = NS(object_id='vo-own', read_file=NS(aio=read))
        image = Mock()
        image.add_local_dir.return_value = image
        image.env.return_value = image
        image.run_commands.return_value = image
        image.build = Method(lambda app: image)
        app = NS(app_id='ap-own', function=Mock(return_value=lambda entry: function), run=Mock())
        app.run.return_value = Context(app)
        modal = NS(__version__='1.5.4', App=Mock(return_value=app), Image=NS(debian_slim=Mock(return_value=image)),
                   Volume=NS(ephemeral=Mock(return_value=Context(volume))))
        return modal, app, call, image

    def test_launcher_sdk_refused_before_any_provider_calls(self):
        for version in (None, '1.5.3', '1.6.0'):
            modal, app, call, image = self.fake_sdk()
            modal.__version__ = version
            with self.subTest(version=version), patch.dict(sys.modules, {'modal': modal}), \
                 patch.object(M, '_snapshot', AsyncMock()) as snapshot:
                with self.assertRaisesRegex(ValueError, 'Modal 1.5.4'):
                    asyncio.run(M._execute(self.repo, self.evidence, SHA, 'run', 'c'*64, M.time.time()))
            snapshot.assert_not_awaited()
            modal.App.assert_not_called()
            self.assertFalse(self.evidence.exists())

    def test_one_spawn_fixed_options_and_export(self):
        modal, app, call, image = self.fake_sdk()
        self.evidence.mkdir()
        with patch.dict(sys.modules, {'modal': modal}), patch.object(M, '_snapshot', AsyncMock(return_value={})), \
             patch.object(M, '_cli', AsyncMock(return_value='')):
            result = asyncio.run(M._execute(self.repo, self.evidence, SHA, 'run', 'c'*64, M.time.time()))
        modal.App.assert_called_once_with(M.APP_NAME, include_source=False)
        options = app.function.call_args.kwargs
        self.assertEqual({k: options[k] for k in ('gpu','cpu','memory','timeout','retries','max_containers','secrets','serialized','include_source')},
                         dict(gpu=['A10', 'L4'], cpu=(4.,4.), memory=(32768,32768), timeout=14400,
                              retries=0, max_containers=1, secrets=[], serialized=True, include_source=False))
        self.assertEqual(set(options['volumes']), {'/export'})
        call.get.aio.assert_awaited_once()
        call.spawn.aio.assert_awaited_once()
        image.build.aio.assert_awaited_once()
        self.assertEqual(result['bundle_size'], 6)
        self.assertEqual((self.evidence/'freeze_sha256').read_text().strip(), 'f'*64)
        commands = image.run_commands.call_args.args
        self.assertIn('fetch_weights.py', commands[2])
        # Build env online, runtime env only applied after public fetch.
        self.assertNotIn('HF_HUB_OFFLINE', image.env.call_args_list[0].args[0])
        self.assertEqual(image.env.call_args_list[-1].args[0]['HF_HUB_OFFLINE'], '1')

    def test_export_hash_and_size_refuse_partial_bundle(self):
        for oversize in (False, True):
            modal, app, call, image = self.fake_sdk()
            evidence = self.root / str(oversize)
            evidence.mkdir()
            if not oversize:
                call.get.aio.side_effect = None
                call.get.aio.return_value = dict(status='ok', bundle_sha256='0'*64,
                                                bundle_size=6, freeze_sha256='f'*64)
            with self.subTest(oversize=oversize), patch.dict(sys.modules, {'modal': modal}), \
                 patch.object(M, '_snapshot', AsyncMock(return_value={})), patch.object(M, '_cli', AsyncMock(return_value='')), \
                 patch.object(B, 'MAX_BUNDLE_BYTES', 1 if oversize else 256*1024**2):
                with self.assertRaisesRegex(ValueError, 'limit' if oversize else 'hash/size'):
                    asyncio.run(M._execute(self.repo, evidence, SHA, 'run', 'c'*64, M.time.time()))
            self.assertFalse((evidence/'bundle.tar').exists())
            self.assertFalse((evidence/'freeze_sha256').exists())

    def test_eager_image_build_deadline(self):
        modal, app, call, image = self.fake_sdk()
        async def stalled(*args):
            await asyncio.Future()
        image.build.aio.side_effect = stalled
        self.evidence.mkdir()
        with patch.dict(sys.modules, {'modal': modal}), patch.object(M, '_snapshot', AsyncMock(return_value={})), \
             patch.object(M, '_cli', AsyncMock(return_value='')) as cli, patch.object(M, 'IMAGE_BUILD_LIMIT_S', .01):
            with self.assertRaises(TimeoutError):
                asyncio.run(M._execute(self.repo, self.evidence, SHA, 'run', 'c'*64, M.time.time()))
        call.spawn.aio.assert_not_awaited()
        cli.assert_awaited_once_with('app', 'stop', 'ap-own', '--env', 'main', '--yes')
        self.assertTrue((self.evidence/'after.json').is_file())

    def test_whole_attempt_deadline_covers_stalled_export(self):
        modal, app, call, image = self.fake_sdk(export_stalled=True)
        self.evidence.mkdir()
        with patch.dict(sys.modules, {'modal': modal}), patch.object(M, '_snapshot', AsyncMock(return_value={})), \
             patch.object(M, '_cli', AsyncMock(return_value='')), patch.object(M, 'REMOTE_LIMIT_S', .05):
            with self.assertRaises(TimeoutError):
                asyncio.run(M._execute(self.repo, self.evidence, SHA, 'run', 'c'*64, M.time.time()))
        call.spawn.aio.assert_awaited_once()
        call.cancel.aio.assert_awaited_once_with(terminate_containers=True)
        self.assertFalse((self.evidence/'bundle.tar').exists())
        self.assertFalse((self.evidence/'freeze_sha256').exists())
        self.assertTrue((self.evidence/'after.json').is_file())

    def test_caller_cutoff_cancels_and_build_cutoff_no_spawn(self):
        original_wait_for = asyncio.wait_for
        for build in (False, True):
            modal, app, call, image = self.fake_sdk(stalled=not build, build_stalled=build)
            evidence = self.root / str(build)
            evidence.mkdir()
            start = 1000.

            async def run_case():
                phase_entered = asyncio.Event()
                phase_cancelled = asyncio.Event()
                context = app.run.return_value

                class GatedContext:
                    async def __aenter__(self):
                        if build:
                            phase_entered.set()
                        try:
                            return await context.__aenter__()
                        except asyncio.CancelledError:
                            phase_cancelled.set()
                            raise

                    async def __aexit__(self, *args):
                        return await context.__aexit__(*args)

                app.run.return_value = GatedContext()

                async def get():
                    phase_entered.set()
                    try:
                        await asyncio.Future()
                    except asyncio.CancelledError:
                        phase_cancelled.set()
                        raise

                if not build:
                    call.get.aio.side_effect = get

                budgets = dict(bounded_attempt=M.CALLER_CUTOFF_S,
                               session=M.REMOTE_LIMIT_S,
                               build=min(M.IMAGE_BUILD_LIMIT_S, M.REMOTE_LIMIT_S))
                waits = []
                target = 'build' if build else 'bounded_attempt'

                async def wait_for(awaitable, timeout):
                    phase = awaitable.cr_code.co_name
                    if phase not in budgets:
                        # Use real wait_for for cancel and context-exit cleanup.
                        self.assertEqual(timeout, 60)
                        return await original_wait_for(awaitable, timeout)
                    self.assertEqual(timeout, budgets[phase])
                    waits.append(phase)
                    if phase != target:
                        return await awaitable
                    task = asyncio.create_task(awaitable)
                    try:
                        await phase_entered.wait()
                        if build:
                            call.spawn.aio.assert_not_awaited()
                            call.get.aio.assert_not_awaited()
                        else:
                            call.spawn.aio.assert_awaited_once()
                            call.get.aio.assert_awaited_once()
                        task.cancel()
                        with self.assertRaises(asyncio.CancelledError):
                            await task
                        self.assertTrue(phase_cancelled.is_set())
                        raise TimeoutError('synthetic ' + target + ' cutoff')
                    finally:
                        if not task.done():
                            task.cancel()
                            await asyncio.gather(task, return_exceptions=True)

                # Patch the module reference, not global asyncio/time. The real
                # production budgets are checked without racing disk/fsync work.
                with patch.object(M, 'asyncio', NS(wait_for=wait_for,
                        create_task=asyncio.create_task, sleep=asyncio.sleep,
                        gather=asyncio.gather)), patch.object(M, 'time', NS(time=lambda: start)):
                    with self.assertRaisesRegex(TimeoutError, 'synthetic ' + target + ' cutoff'):
                        await M._execute(self.repo, evidence, SHA, 'run', 'c'*64, start)
                self.assertEqual(waits, ['bounded_attempt', 'session', 'build'])
                self.assertTrue(phase_entered.is_set())

            with self.subTest(build=build), patch.dict(sys.modules, {'modal': modal}), \
                 patch.object(M, '_snapshot', AsyncMock(return_value={})), patch.object(M, '_cli', AsyncMock(return_value='')) as cli:
                async def watchdog():
                    # Fixture hang detection only; never the production cutoff.
                    await original_wait_for(run_case(), 10)
                asyncio.run(watchdog())
            if not build:
                call.cancel.aio.assert_awaited_once_with(terminate_containers=True)
            else:
                call.get.aio.assert_not_awaited()
                call.spawn.aio.assert_not_awaited()
                call.cancel.aio.assert_not_awaited()
            cli.assert_awaited_once_with('app', 'stop', 'ap-own', '--env', 'main', '--yes')
            self.assertTrue(all(c.args[0:3] == ('app','stop','ap-own') for c in cli.call_args_list))
            self.assertFalse((evidence/'bundle.tar').exists())
            self.assertFalse((evidence/'freeze_sha256').exists())
            self.assertTrue((evidence/'after.json').is_file())


if __name__ == '__main__':
    unittest.main()
