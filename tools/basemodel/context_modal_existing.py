"""Owner-invoked, single-attempt existing CUDA trainer. Importing performs no RPC.

The USD 8 envelope is a threshold, not owner approval or a provider-enforced spend cap.
No release upload or evaluation is performed here.
"""
import argparse
import asyncio
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

APP_NAME = 'apassy-context-existing'
MARKER_DICT = 'apassy-context-run-markers'
GPU_PREFERENCES = ['A10', 'L4']
CPU = (4.0, 4.0)
MEMORY_MIB = (32768, 32768)
FUNCTION_TIMEOUT = 14400
REMOTE_LIMIT_S = 14400
IMAGE_BUILD_LIMIT_S = 1800
CALLER_CUTOFF_S = 15300
EXPORT_RESERVE_S = 900
ENVELOPE_USD = 8.0
REMOTE_SRC = '/root/apassy'
RUNTIME_ENV = dict(NVIDIA_TF32_OVERRIDE='0', HF_HUB_OFFLINE='1',
                   TRANSFORMERS_OFFLINE='1', OMP_NUM_THREADS='4', MKL_NUM_THREADS='4',
                   TOKENIZERS_PARALLELISM='false', HF_HOME='/opt/hf',
                   HF_HUB_DISABLE_IMPLICIT_TOKEN='1', PYTHONDONTWRITEBYTECODE='1')


def deadline_limits(recipe=None):
    if recipe is not None and (not isinstance(recipe, str) or recipe != 'context-v1-e20'):
        raise ValueError('unknown training recipe')
    return dict(function_timeout=FUNCTION_TIMEOUT if recipe is None else 7200,
                remote=REMOTE_LIMIT_S if recipe is None else 7200,
                caller=CALLER_CUTOFF_S if recipe is None else 8100,
                build=IMAGE_BUILD_LIMIT_S, export_reserve=EXPORT_RESERVE_S)


def _sha(value):
    if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{40}', value):
        raise ValueError('invalid source SHA')


def _attest_tree(root, expected):
    # Deliberately inline stdlib only: no repository module is trusted yet.
    inv = {}
    for path in Path(root).rglob('*'):
        if path.is_symlink():
            raise ValueError('staged symlink')
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError('staged nonregular file')
        inv[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    actual = hashlib.sha256(json.dumps(inv, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    if actual != expected:
        raise ValueError('staged inventory mismatch')
    return inv


def _child(command, deadline, env):
    remaining = deadline - EXPORT_RESERVE_S - time.time()
    if remaining <= 0:
        raise TimeoutError('export reserve reached')
    proc = subprocess.Popen(command, env=env, start_new_session=True)
    try:
        code = proc.wait(timeout=remaining)
    except BaseException:
        # Kill descendants even when the immediate parent exits after TERM.
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        finally:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
        raise
    if code:
        raise subprocess.CalledProcessError(code, command)


def worker(run_id, source_sha, deadline_epoch, inventory_sha256, recipe=None):
    limits = deadline_limits(recipe)
    started = time.time()
    if not math.isfinite(deadline_epoch) or started >= deadline_epoch - EXPORT_RESERVE_S:
        raise TimeoutError('remote deadline')
    if recipe is not None and deadline_epoch > started + limits['remote']:
        raise TimeoutError('recipe deadline exceeds whole-attempt limit')
    _sha(source_sha)
    inv = _attest_tree(REMOTE_SRC, inventory_sha256)
    sys.path.insert(0, str(Path(REMOTE_SRC) / 'tools/basemodel'))
    import context_external_bundle as bundle
    import context_train as core
    versions = core.package_versions()
    if versions != bundle.PACKAGE_VERSIONS:
        raise ValueError('package versions mismatch')
    import torch
    if not torch.cuda.is_available():
        raise ValueError('CUDA unavailable')
    gpu_name = torch.cuda.get_device_name(0)
    if not isinstance(gpu_name, str) or gpu_name not in bundle.SUPPORTED_GPU_NAMES:
        raise ValueError('unsupported GPU')
    root = bundle.run_root(run_id)
    import modal
    marker = modal.Dict.from_name(MARKER_DICT, create_if_missing=True, environment_name='main')
    marker_value = dict(source_sha=source_sha, started_epoch=started)
    if recipe is not None:
        marker_value['recipe'] = recipe
    if marker.put(run_id, marker_value, skip_if_exists=True) is not True:
        raise ValueError('run marker already consumed; no retry')
    root.parent.mkdir(parents=True, exist_ok=True)
    root.mkdir(mode=0o700)  # Never clean up a root we did not create.
    try:
        (root / 'tmp').mkdir(mode=0o700)
        env = {**os.environ, **RUNTIME_ENV, 'TMPDIR': str(root / 'tmp')}
        import common
        base = common.base_dir()
        scripts = Path(REMOTE_SRC) / 'tools/basemodel'
        _child([sys.executable, str(scripts / 'context_data.py'), '--out', str(root / 'g1'),
                '--groups', '400', '--seed', '7'], deadline_epoch, env)
        command = [sys.executable, str(scripts / 'context_existing_freeze.py'),
                   '--data', str(root / 'g1'), '--out', str(root / 'full'), '--base-dir', str(base),
                   '--device', 'cuda', '--source-sha', source_sha]
        config = dict(groups=400, seed=7, device='cuda')
        if recipe is not None:
            command += ['--recipe', recipe]
            config['recipe'] = recipe
        _child(command, deadline_epoch, env)
        if time.time() >= deadline_epoch:
            raise TimeoutError('remote export deadline')
        freeze_sha = hashlib.sha256((root / 'full/freeze.json').read_bytes()).hexdigest()
        receipt = dict(schema='apassy-context-modal-receipt-v1', run_id=run_id, source_sha=source_sha,
                       inventory=inv, inventory_sha256=inventory_sha256, package_versions=versions,
                       torch_wheel_sha256=bundle.TORCH_SHA256, gpu_name=gpu_name, freeze_sha256=freeze_sha,
                       config=config, env=dict(NVIDIA_TF32_OVERRIDE='0'),
                       started_epoch=started, finished_epoch=time.time())
        result = bundle.pack(root, receipt, Path('/export/bundle.tar'))
        # Mounted Volume handle supplied by the serialized entrypoint, never RPC bytes.
        _export_volume.commit()
        return dict(status='ok', bundle_sha256=result['sha256'], bundle_size=result['size'],
                    freeze_sha256=freeze_sha)
    finally:
        shutil.rmtree(root)


def _serialized_entry(volume):
    # A local closure forces cloudpickle-by-value. It imports the attested entrypoint
    # only after independently hashing every staged regular file (including itself).
    def entry(run_id, source_sha, deadline_epoch, inventory_sha256, recipe=None):
        if recipe is not None and (not isinstance(recipe, str) or recipe != 'context-v1-e20'):
            raise ValueError('unknown training recipe')
        import time
        if time.time() >= deadline_epoch:
            raise TimeoutError('remote deadline')
        import hashlib
        import json
        from pathlib import Path
        import sys
        root = Path('/root/apassy')
        inv = {}
        for path in root.rglob('*'):
            if path.is_symlink():
                raise ValueError('staged symlink')
            if path.is_dir():
                continue
            if not path.is_file():
                raise ValueError('staged nonregular file')
            inv[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
        digest = hashlib.sha256(json.dumps(inv, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        if digest != inventory_sha256:
            raise ValueError('staged inventory mismatch')
        sys.path.insert(0, str(root / 'tools/basemodel'))
        import context_modal_existing as implementation
        implementation._export_volume = volume
        if recipe is None:
            return implementation.worker(run_id, source_sha, deadline_epoch, inventory_sha256)
        return implementation.worker(run_id, source_sha, deadline_epoch, inventory_sha256, recipe=recipe)
    return entry


def _save(directory, name, value):
    path = directory / name
    with path.open('x') as stream:
        json.dump(value, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())


async def _cli(*args):
    proc = await asyncio.create_subprocess_exec('modal', *args, stdout=asyncio.subprocess.PIPE,
                                                stderr=asyncio.subprocess.PIPE)
    try:
        out, err = await asyncio.wait_for(proc.communicate(), 60)
    except BaseException:
        proc.kill()
        await proc.wait()
        raise
    if proc.returncode and not (args[:2] == ('app', 'stop') and b'App is already stopped.' in out + err):
        raise RuntimeError('Modal inventory/cleanup command failed')
    return out.decode()


async def _snapshot():
    return dict(apps=json.loads(await _cli('app', 'list', '--env', 'main', '--json')),
                volumes=json.loads(await _cli('volume', 'list', '--env', 'main', '--json')))


def _image(modal, staging):
    return (modal.Image.debian_slim(python_version='3.12')
            .add_local_dir(str(staging), remote_path=REMOTE_SRC, copy=True)
            .env(dict(HF_HOME='/opt/hf', HF_HUB_DISABLE_IMPLICIT_TOKEN='1', PYTHONDONTWRITEBYTECODE='1'))
            .run_commands(
                'python -m pip install --no-cache-dir -r /root/apassy/tools/basemodel/requirements-cu130.txt '
                '-r /root/apassy/tools/basemodel/requirements.txt',
                'python -m pip check',
                'python -B /root/apassy/tools/basemodel/fetch_weights.py',
                'chmod -R a-w /opt/hf')
            .env(RUNTIME_ENV))


async def _execute(staging, evidence, source_sha, run_id, inv_sha, start, recipe=None):
    limits = deadline_limits(recipe)
    import modal  # Only guarded execution imports the SDK.
    if getattr(modal, '__version__', None) != '1.5.4':
        raise ValueError('Modal 1.5.4 launcher required')
    _save(evidence, 'before.json', await _snapshot())
    app = modal.App(APP_NAME, include_source=False)
    call = None
    own_app_id = None
    try:
        async def session():
            nonlocal call, own_app_id
            async with modal.Volume.ephemeral(environment_name='main') as volume:
                _save(evidence, 'volume.json', dict(volume_id=volume.object_id))
                image = _image(modal, staging)
                function = app.function(image=image, serialized=True, include_source=False,
                                        gpu=GPU_PREFERENCES, cpu=CPU, memory=MEMORY_MIB, timeout=limits['function_timeout'],
                                        retries=0, max_containers=1, volumes={'/export': volume},
                                        secrets=[])(_serialized_entry(volume))
                # App entry eagerly resolves the image. Bound entry AND explicit build,
                # rather than checking elapsed time after a blocking build returns.
                context = app.run(environment_name='main')
                entered = False
                try:
                    def remember_app():
                        nonlocal own_app_id
                        if own_app_id is None and app.app_id:
                            own_app_id = app.app_id
                            _save(evidence, 'app.json', dict(app_id=own_app_id))

                    async def remember_during_build():
                        while own_app_id is None:
                            remember_app()
                            await asyncio.sleep(.05)

                    async def build():
                        nonlocal entered
                        watcher = asyncio.create_task(remember_during_build())
                        try:
                            await context.__aenter__()
                            entered = True
                            remember_app()
                            await image.build.aio(app)
                        finally:
                            remember_app()
                            watcher.cancel()
                            await asyncio.gather(watcher, return_exceptions=True)
                    await asyncio.wait_for(build(), min(limits['build'],
                                                        start + limits['remote'] - time.time()))
                    _save(evidence, 'spawn-intent.json', dict(run_id=run_id, epoch=time.time()))
                    if recipe is None:
                        call = await function.spawn.aio(run_id, source_sha, start + limits['remote'], inv_sha)
                    else:
                        call = await function.spawn.aio(run_id, source_sha, start + limits['remote'], inv_sha,
                                                        recipe=recipe)
                    _save(evidence, 'call.json', dict(call_id=call.object_id))
                    result = await call.get.aio()
                    if result.get('status') != 'ok':
                        raise ValueError('worker failed')
                    import context_external_bundle as bundle
                    size, h = 0, hashlib.sha256()
                    path = evidence / 'bundle.tar'
                    try:
                        with path.open('xb') as output:
                            async for block in volume.read_file.aio('bundle.tar'):
                                size += len(block)
                                if size > bundle.MAX_BUNDLE_BYTES:
                                    raise ValueError('bundle exceeds limit')
                                output.write(block)
                                h.update(block)
                        if size != result['bundle_size'] or h.hexdigest() != result['bundle_sha256']:
                            raise ValueError('bundle hash/size mismatch')
                        if not re.fullmatch('[0-9a-f]{64}', result['freeze_sha256']):
                            raise ValueError('invalid freeze SHA')
                        with (evidence / 'freeze_sha256').open('x') as output:
                            output.write(result['freeze_sha256'] + '\n')
                    except BaseException:
                        path.unlink(missing_ok=True)
                        raise
                    return result
                finally:
                    # Cancel before app/volume teardown so a cutoff cannot wait for training.
                    try:
                        if call is not None:
                            await asyncio.wait_for(call.cancel.aio(terminate_containers=True), 60)
                    finally:
                        try:
                            if own_app_id:
                                _save(evidence, 'cleanup-app.json', dict(app_id=own_app_id))
                                await _cli('app', 'stop', own_app_id, '--env', 'main', '--yes')
                        finally:
                            if entered:
                                await asyncio.wait_for(context.__aexit__(None, None, None), 60)
        async def bounded_attempt():
            # The attempt budget includes build and export, even if either stalls.
            return await asyncio.wait_for(session(), max(0, start + limits['remote'] - time.time()))
        return await asyncio.wait_for(bounded_attempt(), max(0, start + limits['caller'] - time.time()))
    finally:
        _save(evidence, 'after.json', await _snapshot())


def launch(source_sha, run_id, approved_budget_usd, evidence_dir, repo_root, recipe=None):
    limits = deadline_limits(recipe)
    start = time.time()
    if sys.implementation.name != 'cpython' or sys.version_info[:2] != (3, 12):
        raise ValueError('CPython 3.12 launcher required')
    _sha(source_sha)
    if (isinstance(approved_budget_usd, bool) or not isinstance(approved_budget_usd, (int, float))
            or not math.isfinite(approved_budget_usd) or approved_budget_usd < ENVELOPE_USD):
        raise ValueError('finite numeric budget >= 8 required')
    import context_external_bundle as bundle
    bundle.run_root(run_id)
    repo = Path(repo_root).resolve()
    evidence = Path(evidence_dir).absolute()
    if evidence.exists() or evidence.is_symlink() or evidence.resolve().is_relative_to(repo):
        raise ValueError('fresh evidence directory outside repository required')
    inv = bundle.git_inventory(repo, source_sha)
    # Freeze the tracked serializer set, never a filesystem wildcard.
    tracked = subprocess.check_output(['git', 'ls-tree', '-r', '--name-only', source_sha,
                                      '--', 'tests/fixtures/secret-decision-context-v1/serializer/'], cwd=repo).decode().splitlines()
    goldens = sorted(p for p in inv if p.startswith('tests/fixtures/secret-decision-context-v1/serializer/'))
    if len(tracked) != 21 or goldens != sorted(tracked):
        raise ValueError('exact 21 tracked serializer goldens required')
    evidence.mkdir(mode=0o700, parents=True)
    inv_sha = bundle.inventory_sha256(inv)
    receipt = dict(run_id=run_id, source_sha=source_sha, inventory_sha256=inv_sha,
                   approved_budget_usd=approved_budget_usd, envelope_usd=ENVELOPE_USD,
                   started_epoch=start, deadline_epoch=start + limits['remote'],
                   caller_cutoff_epoch=start + limits['caller'], environment='main')
    if recipe is not None:
        receipt['recipe'] = recipe
    _save(evidence, 'attempt.json', receipt)
    try:
        with tempfile.TemporaryDirectory(prefix='apassy-modal-stage-') as temporary:
            staging = Path(temporary)
            for name in bundle.UPLOAD_PATHS:
                path = staging / name
                path.parent.mkdir(parents=True, exist_ok=True)
                raw = subprocess.check_output(['git', 'cat-file', 'blob', source_sha + ':' + name], cwd=repo)
                with path.open('xb') as stream:
                    stream.write(raw)
            if bundle.inventory(staging) != inv:
                raise ValueError('staging differs from git inventory')
            if recipe is None:
                result = _execute(staging, evidence, source_sha, run_id, inv_sha, start)
            else:
                result = _execute(staging, evidence, source_sha, run_id, inv_sha, start, recipe=recipe)
            receipt.update(asyncio.run(result))
        receipt['finished_epoch'] = time.time()
        _save(evidence, 'success.json', receipt)
        return receipt
    except BaseException as exc:
        _save(evidence, 'failure.json', dict(error=type(exc).__name__, finished_epoch=time.time()))
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    launch_parser = sub.add_parser('launch')
    launch_parser.add_argument('--source-sha', required=True)
    launch_parser.add_argument('--run-id', required=True)
    launch_parser.add_argument('--approved-budget-usd', required=True, type=float)
    launch_parser.add_argument('--evidence-dir', required=True)
    launch_parser.add_argument('--recipe', choices=('context-v1-e20',))
    args = parser.parse_args(argv)
    options = {} if args.recipe is None else dict(recipe=args.recipe)
    launch(args.source_sha, args.run_id, args.approved_budget_usd, args.evidence_dir,
           Path(__file__).resolve().parents[2], **options)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
