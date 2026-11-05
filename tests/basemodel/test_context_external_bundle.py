"""Synthetic, stdlib-only transport and source guards; no model/provider imports."""
import ast
import copy
import hashlib
import io
import json
import shutil
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import types
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'tools/basemodel'))
import context_external_bundle as B


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='context-bundle-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / 'source'
        self.root.mkdir()
        self.run = 'synthetic-run'
        inv = {p: 'a' * 64 for p in B.UPLOAD_PATHS}
        self.receipt = dict(schema='apassy-context-modal-receipt-v1', run_id=self.run,
                            source_sha='b' * 40, inventory=inv,
                            inventory_sha256=B.inventory_sha256(inv), package_versions=B.PACKAGE_VERSIONS,
                            torch_wheel_sha256=B.TORCH_SHA256, gpu_name='NVIDIA L4',
                            freeze_sha256='', config=dict(groups=400, seed=7, device='cuda'),
                            env={'NVIDIA_TF32_OVERRIDE': '0'}, started_epoch=1, finished_epoch=2)
        for name in B.BUNDLE_MEMBERS[:-1]:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'{}\n' if name.endswith('.json') else b'synthetic\n')
        self.receipt['freeze_sha256'] = B._sha(self.root / 'full/freeze.json')
        self.bundle = self.base / 'bundle.tar'
        self.packed = B.pack(self.root, self.receipt, self.bundle)
        self.scratch = self.base / 'scratch'

    def restore(self, bundle=None, **kwargs):
        return B.restore(bundle or self.bundle, kwargs.get('sha', B._sha(bundle or self.bundle)),
                         kwargs.get('freeze', self.receipt['freeze_sha256']), self.run, self.scratch)

    def archive(self, names=None, change=None, fmt=tarfile.USTAR_FORMAT):
        output = self.base / 'bad.tar'
        with tarfile.open(output, 'w', format=fmt) as tar:
            for i, name in enumerate(names or B.BUNDLE_MEMBERS):
                raw = json.dumps(self.receipt).encode() if name == 'receipt.json' else b'{}\n'
                info = tarfile.TarInfo(name)
                info.size = len(raw)
                info.mode = 0o644
                if change and i == 0:
                    change(info)
                tar.addfile(info, io.BytesIO(raw))
        return output

    def test_deterministic_roundtrip(self):
        for gpu_name in B.SUPPORTED_GPU_NAMES:
            with self.subTest(gpu_name=gpu_name):
                self.receipt['gpu_name'] = gpu_name
                self.bundle.unlink()
                self.packed = B.pack(self.root, self.receipt, self.bundle)
                other = self.base / 'other.tar'
                self.assertEqual(B.pack(self.root, self.receipt, other), self.packed)
                self.assertEqual(self.restore(), self.receipt)
                root = B.run_root(self.run, self.scratch)
                self.assertEqual(root.stat().st_mode & 0o777, 0o700)
                for name in B.BUNDLE_MEMBERS[:-1]:
                    self.assertEqual((root / name).read_bytes(), (self.root / name).read_bytes())
                with tarfile.open(self.bundle) as tar:
                    self.assertEqual(tuple(t.name for t in tar), B.BUNDLE_MEMBERS)
                    for t in tar.getmembers():
                        self.assertEqual((t.uid, t.gid, t.mtime, t.mode, t.uname, t.gname), (0, 0, 0, 0o644, '', ''))
                other.unlink()
                shutil.rmtree(root)

    def test_hashes_existing_root_and_cleanup(self):
        with self.assertRaises(ValueError):
            self.restore(sha='0' * 64)
        with self.assertRaises(ValueError):
            self.restore(freeze='0' * 64)
        self.assertFalse((self.scratch / self.run).exists())
        root = self.scratch / self.run
        root.mkdir(parents=True)
        sentinel = root / 'sentinel'
        sentinel.write_text('preserve')
        with self.assertRaises(ValueError):
            self.restore()
        self.assertEqual(sentinel.read_text(), 'preserve')

    def test_partial_write_cleanup(self):
        original = Path.open
        def failing(path, *args, **kwargs):
            if path == self.scratch / self.run / 'g1/train.jsonl':
                raise OSError('synthetic write failure')
            return original(path, *args, **kwargs)
        with patch.object(Path, 'open', failing), self.assertRaises(OSError):
            self.restore()
        self.assertFalse((self.scratch / self.run).exists())

    def test_member_names_and_order(self):
        cases = [B.BUNDLE_MEMBERS[:-1], B.BUNDLE_MEMBERS + ('extra.json',),
                 B.BUNDLE_MEMBERS[:1] + B.BUNDLE_MEMBERS,
                 tuple(reversed(B.BUNDLE_MEMBERS))]
        for name in ('../escape', '/absolute', 'g1/../escape', 'é.json'):
            cases.append((name,) + B.BUNDLE_MEMBERS[1:])
        for names in cases:
            with self.subTest(names=names):
                # Non-ASCII names require PAX and must still be rejected.
                path = self.archive(names, fmt=tarfile.PAX_FORMAT if 'é.json' in names else tarfile.USTAR_FORMAT)
                with self.assertRaises((ValueError, tarfile.TarError)):
                    self.restore(path)
                self.assertFalse(self.scratch.exists())

    def test_types_extensions_and_trailing_data(self):
        for kind in (tarfile.DIRTYPE, tarfile.SYMTYPE, tarfile.LNKTYPE,
                     tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE,
                     tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME,
                     tarfile.GNUTYPE_LONGLINK):
            with self.subTest(kind=kind):
                path = self.archive(change=lambda t: setattr(t, 'type', kind))
                with self.assertRaises((ValueError, tarfile.TarError)):
                    self.restore(path)
                self.assertFalse(self.scratch.exists())
        # PAX that normalizes to an otherwise allowed filename must not be hidden.
        path = self.archive(change=lambda t: t.pax_headers.update({'comment': 'hidden'}), fmt=tarfile.PAX_FORMAT)
        with self.assertRaises(ValueError):
            self.restore(path)
        path.write_bytes(self.bundle.read_bytes() + b'x' + b'\0' * 511)
        with self.assertRaises(ValueError):
            self.restore(path)

    def test_corrupt_header_and_compression_refused(self):
        path = self.base / 'corrupt.tar'
        raw = bytearray(self.bundle.read_bytes())
        raw[148:156] = b'0000000\0'
        path.write_bytes(raw)
        with self.assertRaises((ValueError, tarfile.TarError)):
            self.restore(path)
        with tarfile.open(path, 'w:gz') as tar:
            info = tarfile.TarInfo(B.BUNDLE_MEMBERS[0])
            info.size = 3
            tar.addfile(info, io.BytesIO(b'{}\n'))
        with self.assertRaises(ValueError):
            self.restore(path)
        self.assertFalse(self.scratch.exists())

    def test_size_bounds_without_large_payload(self):
        with patch.object(B, 'MAX_BUNDLE_BYTES', self.bundle.stat().st_size - 1):
            with self.assertRaises(ValueError):
                self.restore()
            with self.assertRaises(ValueError):
                B.pack(self.root, self.receipt, self.base / 'oversize.tar')
        for member, limit in (('x.json', 4), ('x.jsonl', 64), ('x.safetensors', 128)):
            self.assertEqual(B._limit(member), limit * 1024**2)
        with patch.object(B, '_limit', return_value=1), self.assertRaises(ValueError):
            self.restore()
        self.assertFalse(self.scratch.exists())

    def test_gpu_names_are_exact_and_refused_before_restore(self):
        self.assertEqual(B.SUPPORTED_GPU_NAMES, ('NVIDIA A10', 'NVIDIA A10G', 'NVIDIA L4'))
        for name in ('NVIDIA A100', 'NVIDIA T4', 'NVIDIA H100', 'NVIDIA L40S',
                     'unknown', 'A10', 'NVIDIA A10 extra', '', None):
            with self.subTest(gpu_name=name):
                receipt = dict(self.receipt, gpu_name=name)
                with self.assertRaises(ValueError):
                    B.pack(self.root, receipt, self.base / 'refused.tar')
                # Forge the transport directly so pack's guard cannot mask restore's.
                self.receipt['gpu_name'] = name
                path = self.archive()
                with patch.object(Path, 'mkdir') as mkdir, \
                     patch.object(tarfile.TarFile, 'extractfile') as extract:
                    with self.assertRaises(ValueError):
                        self.restore(path)
                    mkdir.assert_not_called()
                    extract.assert_not_called()
                self.assertFalse(self.scratch.exists())

    def test_bad_receipt_cleanup(self):
        for mutate in (lambda r: r.update(extra=True), lambda r: r.update(package_versions={}),
                       lambda r: r.update(torch_wheel_sha256='0'*64),
                       lambda r: r.update(inventory_sha256='0'*64),
                       lambda r: r.update(finished_epoch=float('inf'))):
            with self.subTest(mutate=mutate):
                receipt = copy.deepcopy(self.receipt)
                mutate(receipt)
                with self.assertRaises(ValueError):
                    B.pack(self.root, receipt, self.base / 'refused.tar')
        path = self.base / 'receipt-bad.tar'
        raw = self.bundle.read_bytes().replace(b'apassy-context-modal-receipt-v1', b'apassy-context-modal-receipt-v0')
        path.write_bytes(raw)
        with self.assertRaises(ValueError):
            self.restore(path)
        self.assertFalse((self.scratch / self.run).exists())

    def test_inputs_and_paths(self):
        env = dict(SOURCE_SHA='b'*40, GITHUB_SHA='b'*40, RUN_ID=self.run,
                   BUNDLE_ASSET='123/456', BUNDLE_SHA256='a'*64, FREEZE_SHA256='c'*64,
                   SHIPPED_BASELINE='false')
        B.check_inputs(env, 'b'*40)
        for key in env:
            bad = dict(env, **{key: '../invalid' if key == 'RUN_ID' else 'invalid'})
            with self.subTest(key=key), self.assertRaises(ValueError):
                B.check_inputs(bad, 'b'*40)
        for name in ('target', '../x', 'a/b', 'H1', 'h1', 'held-out', '', '-bad'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                B.run_root(name, self.scratch)

    def test_git_inventory(self):
        repo = self.base / 'git'
        repo.mkdir()
        def git(*args):
            return subprocess.check_output(['git', *args], cwd=repo, stderr=subprocess.DEVNULL).decode().strip()
        git('init', '-q')
        git('config', 'user.email', 'synthetic@example.invalid')
        git('config', 'user.name', 'Synthetic')
        (repo / 'one').write_text('one')
        git('add', 'one')
        git('commit', '-qm', 'synthetic')
        sha = git('rev-parse', 'HEAD')
        self.assertEqual(B.git_inventory(repo, sha, ('one',)), B.inventory(repo, ('one',)))
        with self.assertRaises(ValueError):
            B.git_inventory(repo, '0'*40, ('one',))
        (repo / 'one').write_text('dirty')
        with self.assertRaises(ValueError):
            B.git_inventory(repo, sha, ('one',))
        (repo / 'one').unlink()
        (repo / 'one').symlink_to(self.bundle)
        with self.assertRaises(ValueError):
            B.inventory(repo, ('one',))
        with self.assertRaises(FileNotFoundError):
            B.inventory(repo, ('missing',))

    def test_verify_guard_order(self):
        root = self.scratch / self.run
        frozen = {k: {'path': str(root / p)} for k, p in {
            'train':'g1/train.jsonl', 'val':'g1/val.jsonl', 'data_manifest':'g1/data-manifest.json',
            'context':'full/context.safetensors', 'control':'full/control.safetensors'}.items()}
        frozen['training_reports'] = {a: {'path': str(root / ('full/'+a+'-report.json'))} for a in ('context','control')}
        (self.root / 'full/freeze.json').write_text(json.dumps(frozen))
        (self.root / 'g1/data-manifest.json').write_text(json.dumps(dict(groups=400, seed=7)))
        self.receipt['freeze_sha256'] = B._sha(self.root / 'full/freeze.json')
        self.bundle.unlink()
        B.pack(self.root, self.receipt, self.bundle)
        receipt = self.restore()
        calls = []
        fake = types.SimpleNamespace(package_versions=lambda: B.PACKAGE_VERSIONS,
                                     verify_freeze=lambda *args: calls.append(args) or frozen)
        def verify(r=receipt, sha=self.receipt['source_sha']):
            return B.verify_restored(root, r, self.run, sha, receipt['freeze_sha256'], self.base)
        with patch.dict(sys.modules, {'context_train': fake}), patch.object(B, 'git_inventory', return_value=receipt['inventory']):
            self.assertEqual(verify(), frozen)
            calls.clear()
            with patch.object(B, 'git_inventory', return_value={}):
                with self.assertRaises(ValueError):
                    verify()
            with self.assertRaises(ValueError):
                verify(sha='c'*40)
            with patch.object(fake, 'package_versions', return_value={}):
                with self.assertRaises(ValueError):
                    verify()
            for groups, seed in ((401,7),(400,8)):
                (root / 'g1/data-manifest.json').write_text(json.dumps(dict(groups=groups,seed=seed)))
                with self.assertRaises(ValueError):
                    verify()
            (root / 'g1/data-manifest.json').write_text(json.dumps(dict(groups=400,seed=7)))
            # Keep external pin consistent while exercising the path guard.
            frozen['train']['path'] = '/elsewhere'
            (root / 'full/freeze.json').write_text(json.dumps(frozen))
            receipt['freeze_sha256'] = B._sha(root / 'full/freeze.json')
            with self.assertRaises(ValueError):
                verify()
            self.assertEqual(calls, [])


class WorkflowTests(unittest.TestCase):
    def test_import_stdlib_only(self):
        tree = ast.parse((REPO / 'tools/basemodel/context_external_bundle.py').read_text())
        modules = [n.names[0].name if isinstance(n, ast.Import) else n.module
                   for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))]
        self.assertNotIn('torch', modules)
        self.assertNotIn('modal', modules)
        self.assertFalse(any(n.startswith('context_') for n in modules))

    def test_import_without_provider_or_tensor_packages(self):
        code = "import sys; sys.modules['torch']=None; sys.modules['modal']=None; "
        code += "sys.path.insert(0, " + repr(str(REPO / 'tools/basemodel')) + "); "
        code += "import context_external_bundle; assert 'context_train' not in sys.modules"
        subprocess.run([sys.executable, '-B', '-c', code], check=True, cwd=REPO)

    def test_allowlist_and_wheel(self):
        goldens = subprocess.check_output(['git','ls-files','tests/fixtures/secret-decision-context-v1/serializer'], cwd=REPO, text=True).splitlines()
        self.assertEqual(sorted(p for p in B.UPLOAD_PATHS if p.startswith('tests/')), goldens)
        self.assertEqual(len(goldens), 21)
        self.assertEqual(list(B.UPLOAD_PATHS), sorted(set(B.UPLOAD_PATHS)))
        self.assertEqual((REPO / 'tools/basemodel/requirements-cu130.txt').read_text(),
                         'torch @ '+B.TORCH_URL+'#sha256='+B.TORCH_SHA256+'\n')

    def test_workflow_isolation_and_embedded_syntax(self):
        for name in ('ci.yml','bouncer-context-experiment.yml'):
            relative = '.github/workflows/'+name
            current = (REPO / relative).read_text()
            if name == 'ci.yml':
                for mode in ('cuda-preflight','external-evaluate'):
                    self.assertIn('          - '+mode+'\n', current)
                    self.assertIn("inputs.context_experiment == '" + mode + "'", current)
                self.assertIn('permissions:\n  contents: read', current)
                self.assertIn('APASSY_CONTEXT_SHIPPED_HEADS_URL: ${{ secrets.APASSY_CONTEXT_SHIPPED_HEADS_URL }}', current)
            else:
                self.assertIn("inputs.mode != 'cuda-preflight' && inputs.mode != 'external-evaluate'", current)
                for mode in ('cuda-preflight','external-evaluate'):
                    self.assertIn("if: ${{ github.event_name == 'workflow_dispatch' && inputs.mode == '" + mode + "' }}", current)
                self.assertIn('timeout-minutes: 300', current)
                # Compile every Python heredoc in the new jobs, with stdlib only.
                new = current[current.index('  cuda-preflight:\n'):]
                smoke = new[:new.index('  external-evaluate:\n')]
                self.assertNotIn('tests/evals', smoke)
                self.assertNotIn('fetch_weights.py', smoke)
                self.assertNotIn('GH_TOKEN:', smoke)
                self.assertNotIn('SHIPPED_URL:', smoke)
                self.assertNotIn('CLOUDFLARE_API_TOKEN', new)
                for delimiter in ('PY', 'PYCODE'):
                    for chunk in new.split("<<'" + delimiter + "'\n")[1:]:
                        body = chunk.split('        ' + delimiter, 1)[0]
                        ast.parse('\n'.join(line[8:] for line in body.splitlines()))
                ext = current[current.index('  external-evaluate:\n'):]
                self.assertLess(ext.index('rm -rf -- "$RUNNER_TEMP/context-external-route-target"'), ext.index('Fetch and verify the pinned public base'))
                self.assertIn('      continue-on-error: true',ext)
                self.assertIn('      timeout-minutes: 120',ext)
                self.assertNotIn('cache: pip',new)


if __name__ == '__main__':
    unittest.main()
