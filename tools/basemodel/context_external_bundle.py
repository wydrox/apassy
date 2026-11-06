"""Attested existing-trainer transport. Import is stdlib-only and performs no IO."""
import hashlib
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tarfile

SCRATCH = Path('/tmp/apassy-context')
RUN_ID_RE = r'[a-z0-9][a-z0-9-]{0,63}'
TORCH_URL = 'https://download-r2.pytorch.org/whl/cu130/torch-2.14.0%2Bcu130-cp312-cp312-manylinux_2_28_x86_64.whl'
TORCH_SHA256 = '9c5693d3ca91743202034094ad3b3df20b5eb1373d5e0bc8a5d976be12c35302'
PACKAGE_VERSIONS = {'laya': '0.3.20', 'torch': '2.14.0+cu130', 'transformers': '5.17.0', 'tokenizers': '0.23.2'}
UPLOAD_PATHS = tuple(sorted(
    ['tools/basemodel/' + p for p in (
        'common.py', 'context_data.py', 'context_dev_diagnostic.py', 'context_eval.py', 'context_existing_freeze.py',
        'context_external_bundle.py', 'context_modal_existing.py', 'context_replay.py',
        'context_train.py', 'context_train_rows.py', 'context_v1.py', 'fetch_weights.py',
        'manifest.json', 'requirements.txt', 'requirements-cu130.txt', 'train.py',
        'contracts/secret-decision-context-v1.json')]
    + ['tests/fixtures/secret-decision-context-v1/serializer/' + p + '.json' for p in (
        'age-lt1d', 'age-lt30d', 'age-lt7d', 'age-none', 'age-unknown', 'canaries',
        'conflict', 'count-0', 'count-1', 'count-2to4', 'count-5plus', 'count-unknown',
        'four', 'legacy', 'long-request', 'one-unknown', 'owner', 'repeat', 'three',
        'unicode', 'zero')]))
BUNDLE_MEMBERS = ('g1/data-manifest.json', 'g1/train.jsonl', 'g1/val.jsonl',
                  'full/freeze.json', 'full/context.safetensors', 'full/control.safetensors',
                  'full/context-report.json', 'full/control-report.json', 'receipt.json')
SUPPORTED_GPU_NAMES = ('NVIDIA A10', 'NVIDIA A10G', 'NVIDIA L4')
MAX_BUNDLE_BYTES = 256 * 1024**2
RECEIPT_KEYS = frozenset(('schema', 'run_id', 'source_sha', 'inventory', 'inventory_sha256',
                         'package_versions', 'torch_wheel_sha256', 'gpu_name', 'freeze_sha256',
                         'config', 'env', 'started_epoch', 'finished_epoch'))


def require(ok, message='external bundle refused'):
    if not ok:
        raise ValueError(message)


def _hex(value, length=64):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{%d}' % length, value) is not None


def run_root(run_id, scratch=SCRATCH):
    require(isinstance(run_id, str) and re.fullmatch(RUN_ID_RE, run_id) and run_id != 'target', 'invalid run ID')
    from context_train_rows import safe_path
    return safe_path(Path(scratch) / run_id)


def _regular(root, relative):
    require(isinstance(relative, str) and relative.isascii() and
            str(PurePosixPath(relative)) == relative and not relative.startswith('/') and
            '..' not in PurePosixPath(relative).parts)
    path = Path(root)
    require(not path.is_symlink())
    for part in PurePosixPath(relative).parts:
        path = path / part
        require(not path.is_symlink(), 'symlink refused')
    require(stat.S_ISREG(path.stat().st_mode), 'regular file required')
    return path


def _sha(path):
    with Path(path).open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def inventory(repo_root, paths=UPLOAD_PATHS):
    return {p: _sha(_regular(repo_root, p)) for p in paths}


def git_inventory(repo_root, source_sha, paths=UPLOAD_PATHS):
    require(_hex(source_sha, 40), 'invalid source SHA')
    def git(*args):
        return subprocess.check_output(['git', *args], cwd=repo_root)
    require(git('rev-parse', 'HEAD').decode().strip() == source_sha, 'source HEAD mismatch')
    require(not git('status', '--porcelain', '--untracked-files=no'), 'dirty tracked tree')
    result = {}
    for p in paths:
        _regular(repo_root, p)
        entry = git('ls-tree', source_sha, '--', p).decode().split()
        require(len(entry) == 4 and entry[0] in ('100644', '100755') and entry[1] == 'blob')
        result[p] = hashlib.sha256(git('cat-file', 'blob', source_sha + ':' + p)).hexdigest()
    require(inventory(repo_root, paths) == result, 'working source differs')
    return result


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def inventory_sha256(inv):
    return hashlib.sha256(_canonical(inv)).hexdigest()


def _pairs(items):
    result = {}
    for k, v in items:
        require(k not in result, 'duplicate JSON key')
        result[k] = v
    return result


def _json(raw):
    def invalid(_):
        raise ValueError('nonfinite JSON')
    return json.loads(raw, object_pairs_hook=_pairs, parse_constant=invalid)


def _receipt(r):
    require(isinstance(r, dict) and set(r) == RECEIPT_KEYS, 'receipt keys')
    config = r['config']
    legacy = {'groups': 400, 'seed': 7, 'device': 'cuda'}
    require(isinstance(config, dict) and
            (config == legacy or config == dict(legacy, recipe='context-v1-e20') or
             config == dict(legacy, recipe='context-v1-e20-denial-invariance-v1')) and
            all(type(config[k]) is int for k in ('groups', 'seed')), 'receipt config')
    require(r['schema'] == 'apassy-context-modal-receipt-v1')
    run_root(r['run_id'])
    require(_hex(r['source_sha'], 40) and _hex(r['freeze_sha256']))
    require(isinstance(r['inventory'], dict) and set(r['inventory']) == set(UPLOAD_PATHS)
            and all(_hex(v) for v in r['inventory'].values()))
    require(r['inventory_sha256'] == inventory_sha256(r['inventory']))
    require(r['package_versions'] == PACKAGE_VERSIONS and r['torch_wheel_sha256'] == TORCH_SHA256)
    require(isinstance(r['gpu_name'], str) and r['gpu_name'] in SUPPORTED_GPU_NAMES)
    require(r['env'] == {'NVIDIA_TF32_OVERRIDE': '0'})
    require(all(type(r[k]) in (int, float) and math.isfinite(r[k]) and r[k] >= 0
                for k in ('started_epoch', 'finished_epoch')))
    require(r['finished_epoch'] >= r['started_epoch'])
    return r


def _limit(name):
    return (64 if name.endswith('.jsonl') else 128 if name.endswith('.safetensors') else 4) * 1024**2


def pack(root, receipt, out_path):
    _receipt(receipt)
    require(_sha(_regular(root, 'full/freeze.json')) == receipt['freeze_sha256'])
    raw = _canonical(receipt) + b'\n'
    files = {name: _regular(root, name) for name in BUNDLE_MEMBERS[:-1]}
    sizes = {name: path.stat().st_size for name, path in files.items()}
    sizes['receipt.json'] = len(raw)
    require(all(0 <= size <= _limit(name) for name, size in sizes.items()))
    size = sum(512 + ((n + 511) // 512) * 512 for n in sizes.values()) + 1024
    require(((size + 10239) // 10240) * 10240 <= MAX_BUNDLE_BYTES, 'bundle too large')
    created = False
    try:
        with Path(out_path).open('xb') as output:
            created = True
            with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as tar:
                for name in BUNDLE_MEMBERS:
                    info = tarfile.TarInfo(name)
                    info.size, info.mode = sizes[name], 0o644
                    if name == 'receipt.json':
                        tar.addfile(info, io.BytesIO(raw))
                    else:
                        with files[name].open('rb') as f:
                            tar.addfile(info, f)
        require(Path(out_path).stat().st_size <= MAX_BUNDLE_BYTES)
        return {'sha256': _sha(out_path), 'size': Path(out_path).stat().st_size}
    except BaseException:
        if created:
            Path(out_path).unlink(missing_ok=True)
        raise


def check_inputs(env, head):
    require(_hex(head, 40) and env.get('SOURCE_SHA') == env.get('GITHUB_SHA') == head)
    run_root(env.get('RUN_ID'))
    require(re.fullmatch(r'[1-9][0-9]{0,19}/[1-9][0-9]{0,19}', env.get('BUNDLE_ASSET', '')))
    require(all(_hex(env.get(k)) for k in ('BUNDLE_SHA256', 'FREEZE_SHA256')))
    require(env.get('SHIPPED_BASELINE') in ('true', 'false'))


def _headers(f, size):
    """Inspect physical headers, never tarfile's normalized/hidden extension view."""
    require(size % 512 == 0)
    entries = []
    offset = 0
    for name in BUNDLE_MEMBERS:
        f.seek(offset)
        raw = f.read(512)
        require(len(raw) == 512 and raw[257:265] == b'ustar\x0000', 'plain USTAR required')
        require(raw[156:157] in (b'0', b'\0') and not any(raw[157:257])
                and not any(raw[345:500]), 'nonregular or extended header')
        require(raw[:100] == name.encode('ascii').ljust(100, b'\0'), 'member order/name')
        info = tarfile.TarInfo.frombuf(raw, 'ascii', 'strict')
        require(info.name == name and info.isreg() and 0 <= info.size <= _limit(name))
        entries.append((info, offset + 512))
        offset += 512 + ((info.size + 511) // 512) * 512
        require(offset <= size and offset <= MAX_BUNDLE_BYTES)
    require(size - offset >= 1024, 'tar terminator missing')
    f.seek(offset)
    while chunk := f.read(65536):
        require(not any(chunk), 'extra member/trailing data')
    return entries


def restore(bundle, expected_bundle_sha, expected_freeze_sha, run_id, scratch=SCRATCH):
    root = run_root(run_id, scratch)
    require(_hex(expected_bundle_sha) and _hex(expected_freeze_sha))
    require(not root.exists() and not root.is_symlink(), 'run root exists')
    created = False
    try:
        with Path(bundle).open('rb') as f:
            size = os.fstat(f.fileno()).st_size
            require(size <= MAX_BUNDLE_BYTES, 'bundle too large')
            require(hashlib.file_digest(f, 'sha256').hexdigest() == expected_bundle_sha, 'bundle SHA mismatch')
            entries = _headers(f, size)  # Complete prevalidation before mkdir or file writes.
            # Validate the bounded receipt before restoring any payload to disk.
            info, offset = entries[-1]
            f.seek(offset)
            receipt = _receipt(_json(f.read(info.size)))
            require(receipt['freeze_sha256'] == expected_freeze_sha and receipt['run_id'] == run_id)
            root.parent.mkdir(parents=True, exist_ok=True)
            root.mkdir(mode=0o700)
            created = True
            f.seek(0)
            with tarfile.open(fileobj=f, mode='r:') as tar:
                for info, offset in entries:
                    info.offset_data = offset
                    path = root / info.name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    with tar.extractfile(info) as source, path.open('xb') as dest:
                        shutil.copyfileobj(source, dest, length=65536)
                    require(path.stat().st_size == info.size)
        require(_sha(root / 'full/freeze.json') == expected_freeze_sha, 'freeze SHA mismatch')
        receipt = _receipt(_json((root / 'receipt.json').read_bytes()))
        require(receipt['freeze_sha256'] == expected_freeze_sha and receipt['run_id'] == run_id)
        return receipt
    except BaseException:
        if created:
            shutil.rmtree(root)
        raise


def verify_restored(root, receipt, run_id, source_sha, expected_freeze_sha, repo_root):
    root = Path(root)
    _receipt(receipt)
    require(root == run_root(run_id, root.parent))
    require(receipt['run_id'] == run_id and receipt['source_sha'] == source_sha)
    require(receipt['freeze_sha256'] == expected_freeze_sha and _sha(root / 'full/freeze.json') == expected_freeze_sha)
    require(receipt['inventory'] == git_inventory(repo_root, source_sha))
    import context_train as T
    require(T.package_versions() == PACKAGE_VERSIONS, 'package versions differ')
    frozen = _json((root / 'full/freeze.json').read_bytes())
    require(frozen.get('config', {}).get('recipe') == receipt['config'].get('recipe'),
            'receipt/freeze recipe differs')
    expected = {'train': root / 'g1/train.jsonl', 'val': root / 'g1/val.jsonl',
                'data_manifest': root / 'g1/data-manifest.json',
                'context': root / 'full/context.safetensors', 'control': root / 'full/control.safetensors'}
    for name, path in expected.items():
        require(frozen[name]['path'] == str(path), 'freeze path differs')
    for arm in ('context', 'control'):
        require(frozen['training_reports'][arm]['path'] == str(root / ('full/' + arm + '-report.json')),
                'report path differs')
    dm = _json((root / 'g1/data-manifest.json').read_bytes())
    require(type(dm['groups']) is int and dm['groups'] == 400 and type(dm['seed']) is int and dm['seed'] == 7)
    import context_v1 as C
    return T.verify_freeze(root / 'full/freeze.json', C.load_contract(), expected_freeze_sha)
