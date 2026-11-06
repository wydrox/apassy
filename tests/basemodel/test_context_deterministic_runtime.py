"""Stdlib/fake tests of AST-isolated trainer code; no framework/project imports.

Prepared for hosted CI. These tests do not establish CUDA determinism or quality.
"""
import argparse
import ast
import copy
from contextlib import nullcontext, redirect_stdout
import hashlib
import io
import json
import math
import os
from pathlib import Path
import platform
import struct
import sys
from types import ModuleType, SimpleNamespace as NS
import unittest
from unittest.mock import Mock, patch


SOURCE = Path(__file__).resolve().parents[2] / 'tools/basemodel/train.py'
PROFILE = 'cuda-deterministic-v1'
ENV = {'PYTHONHASHSEED': '7'}
HELPERS = {'configure_runtime', 'runtime_settings', 'initial_head_sha256',
           'runtime_identity', 'attest_runtime', 'validate_runtime', 'extra_metadata', 'main',
           'encoder_states'}


def isolated(namespace):
    nodes = [n for n in ast.parse(SOURCE.read_text()).body
             if isinstance(n, ast.FunctionDef) and n.name in HELPERS
             or isinstance(n, ast.Assign) and any(isinstance(t, ast.Name)
                and t.id == 'RESERVED_METADATA' for t in n.targets)]
    exec(compile(ast.Module(body=nodes, type_ignores=[]), 'trainer AST', 'exec'), namespace)
    return namespace


def args(**updates):
    values = dict(runtime_profile=PROFILE, device='cuda', no_amp=True, seed=7)
    values.update(updates)
    return NS(**values)


class FakeTensor:
    def __init__(self, raw=None, shape=(2,), dtype='torch.float32'):
        self.raw = struct.pack('<ff', 1, 2) if raw is None else raw
        self.shape, self.dtype = shape, dtype

    def element_size(self):
        return 8 if self.dtype == 'torch.float64' else 4

    def numpy(self):
        return self

    def tobytes(self, order):
        if order != 'C':
            raise AssertionError('noncanonical array order')
        return self.raw


class Fixture:
    def __init__(self):
        self.events = []
        self.enabled, self.warn, self.threads = False, True, 8
        self.initialized, self.available, self.index = False, True, 0
        cudnn = NS(benchmark=True, deterministic=False, fp32_precision='tf32',
                   conv=NS(fp32_precision='tf32'), rnn=NS(fp32_precision='tf32'),
                   version=lambda: 90100)
        self.torch = NS(__version__='2.14.0+cu130', version=NS(cuda='13.0'),
            backends=NS(fp32_precision='tf32', cudnn=cudnn,
                        cuda=NS(matmul=NS(fp32_precision='tf32')),
                        mps=NS(is_available=lambda: False)),
            utils=NS(deterministic=NS(fill_uninitialized_memory=False)),
            use_deterministic_algorithms=self.deterministic,
            are_deterministic_algorithms_enabled=lambda: self.enabled,
            is_deterministic_algorithms_warn_only_enabled=lambda: self.warn,
            get_num_threads=lambda: self.threads, set_num_threads=self.set_threads,
            cuda=NS(is_initialized=lambda: self.initialized, is_available=self.cuda_available,
                    device_count=lambda: 1,
                    current_device=lambda: self.index, get_device_name=lambda i: 'fake GPU',
                    get_device_capability=lambda i: (8, 6)),
            manual_seed=lambda s: self.events.append('manual_seed'), device=self.device)
        self.heads = {'head.weight': FakeTensor(), 'scorer.bias': FakeTensor()}
        self.common = NS(MODEL_NAME='fake', BASE_REPO='fake', BASE_REVISION='pinned',
                         TRAINED_PREFIXES=('head.', 'type_emb.', 'scorer.'),
                         head_state=Mock(side_effect=lambda _: self.heads),
                         noul_temperature=lambda _: 2, base_dir=lambda: 'base',
                         load_checkpoint=Mock(return_value=({}, {})), apply_heads=Mock(),
                         sha256_file=lambda _: 'digest', save_checkpoint=Mock())
        self.np = NS(__version__='fake-numpy', random=NS(seed=self.numpy_seed))
        self.ns = isolated(dict(torch=self.torch, np=self.np, common=self.common,
            argparse=argparse, os=os, json=json, hashlib=hashlib, math=math,
            platform=platform, importlib=NS(metadata=NS(version=lambda p: 'fake-' + p)),
            random=NS(seed=lambda _: self.events.append('random.seed'),
                      Random=lambda _: self.events.append('batch_rng')),
            time=NS(time=lambda: 0), on_ac_power=lambda: None,
            print=lambda *a, **k: None))

    def deterministic(self, enabled, *, warn_only):
        self.events.append(('deterministic', enabled, warn_only))
        self.enabled, self.warn = enabled, warn_only

    def set_threads(self, threads):
        self.threads = threads

    def cuda_available(self):
        self.events.append('cuda_available')
        # Availability queries occur only after all controls/environment are set.
        self.ns['runtime_settings'](int(os.environ['PYTHONHASHSEED']))
        return self.available

    def numpy_seed(self, seed):
        self.events.append(('numpy_seed', seed))

    def device(self, name):
        self.events.append('device')
        return NS(type=name.split(':')[0], index=int(name.split(':')[1]) if ':' in name else None)

    def configure(self, **updates):
        return self.ns['configure_runtime'](args(**updates))

    def seal(self):
        startup = self.configure()
        return self.ns['attest_runtime'](args(), self.device('cuda'), object(), startup)


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        env = patch.dict(os.environ, ENV, clear=True)
        env.start()
        self.addCleanup(env.stop)
        self.f = Fixture()

    def test_exact_settings_and_new_precision_controls_only(self):
        settings = self.f.configure()
        self.assertEqual(settings['flags'], dict(deterministic=True, warn_only=False,
            cudnn_benchmark=False, cudnn_deterministic=True, fill_uninitialized_memory=True,
            fp32_precision=['ieee'] * 5, threads=4))
        self.assertEqual(settings['environment'], dict(PYTHONHASHSEED='7',
            CUBLAS_WORKSPACE_CONFIG=':4096:8', NVIDIA_TF32_OVERRIDE='0'))
        self.assertEqual(self.f.events, [('deterministic', True, False),
                                       'cuda_available', ('numpy_seed', 7)])
        tree = ast.parse(SOURCE.read_text())
        helpers = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in HELPERS - {'main'}]
        text = ast.unparse(ast.Module(body=helpers, type_ignores=[]))
        self.assertNotIn('allow_tf32', text)
        self.assertNotIn('set_float32_matmul_precision', text)

    def test_refusal_matrix_before_seed_or_agent(self):
        cases = [dict(runtime_profile='unknown'), dict(device='cpu'), dict(device='mps'),
                 dict(device='cuda:bad'), dict(no_amp=False), dict(seed=True),
                 dict(seed=-1), dict(seed=2 ** 32), dict(seed=7.0)]
        for updates in cases:
            with self.subTest(updates=updates):
                f = Fixture()
                with self.assertRaises((ValueError, RuntimeError)):
                    f.configure(**updates)
                self.assertEqual(f.events, [])
        for target, attribute, value in [(self.f.torch, '__version__', '2.15.0+cu130'),
                                         (self.f.torch.version, 'cuda', '12.8')]:
            with patch.object(target, attribute, value):
                with self.assertRaises(ValueError):
                    self.f.configure()
        self.f.initialized = True
        with self.assertRaisesRegex(RuntimeError, 'already initialized'):
            self.f.configure()
        self.assertEqual(self.f.events, [])

    def test_unsigned_seed_boundaries_and_preexisting_valid_environment(self):
        for seed in (0, 2 ** 32 - 1):
            with self.subTest(seed=seed), patch.dict(os.environ,
                    dict(PYTHONHASHSEED=str(seed), CUBLAS_WORKSPACE_CONFIG=':4096:8',
                         NVIDIA_TF32_OVERRIDE='0'), clear=True):
                f = Fixture()
                before = dict(os.environ)
                f.configure(seed=seed)
                self.assertIn(('numpy_seed', seed), f.events)
                self.assertEqual(dict(os.environ), before)

    def test_startup_environment_conflicts_are_never_overwritten(self):
        for key, value in [('PYTHONHASHSEED', None), ('PYTHONHASHSEED', '07'),
                           ('CUBLAS_WORKSPACE_CONFIG', ':16:8'),
                           ('NVIDIA_TF32_OVERRIDE', '1'), ('NVIDIA_TF32_OVERRIDE', '')]:
            with self.subTest(key=key, value=value), patch.dict(os.environ, ENV, clear=True):
                if value is None:
                    del os.environ[key]
                else:
                    os.environ[key] = value
                original = dict(os.environ)
                with self.assertRaises(ValueError):
                    self.f.configure()
                self.assertEqual(dict(os.environ), original)
                self.assertEqual(self.f.events, [])

    def test_ineffective_setter_missing_api_and_errors_fail_closed(self):
        with patch.object(self.f.torch, 'use_deterministic_algorithms', lambda *a, **k: None):
            with self.assertRaises(RuntimeError):
                self.f.configure()
        with patch.object(self.f.torch, 'use_deterministic_algorithms',
                          side_effect=RuntimeError('unsupported deterministic kernel')):
            with self.assertRaisesRegex(RuntimeError, 'unsupported deterministic kernel'):
                self.f.configure()
        with patch.object(self.f.torch, 'get_num_threads', lambda: 8):
            with self.assertRaises(RuntimeError):
                self.f.configure()
        with patch.object(self.f.torch, 'are_deterministic_algorithms_enabled', None):
            with self.assertRaises(RuntimeError):
                self.f.configure()
        self.assertNotIn(('numpy_seed', 7), self.f.events)

    def test_ignored_precision_setter_is_refused(self):
        class Ignored:
            @property
            def fp32_precision(self):
                return 'tf32'
            @fp32_precision.setter
            def fp32_precision(self, value):
                pass
        self.f.torch.backends.cuda.matmul = Ignored()
        with self.assertRaises(RuntimeError):
            self.f.configure()

    def test_actual_encoder_kernel_error_propagates_without_fallback(self):
        self.f.configure()
        self.f.torch.set_grad_enabled = lambda _: nullcontext()
        self.f.torch.autocast = lambda **_: nullcontext()
        model = NS(encoder=Mock(side_effect=RuntimeError('unsupported deterministic kernel')))
        tensor = NS(to=lambda _: object())
        with self.assertRaisesRegex(RuntimeError, 'unsupported deterministic kernel'):
            self.f.ns['encoder_states'](model, dict(input_ids=tensor, attention_mask=tensor),
                                        NS(type='cuda'), False)
        model.encoder.assert_called_once()
        self.assertFalse(self.f.warn)
        self.assertTrue(self.f.enabled)

    def test_no_cuda_runtime_refused_before_numpy_seed(self):
        self.f.available = False
        with self.assertRaisesRegex(RuntimeError, 'CUDA unavailable'):
            self.f.configure()
        self.assertNotIn(('numpy_seed', 7), self.f.events)

    def test_unavailable_device_index_refused_before_numpy_seed(self):
        with self.assertRaisesRegex(ValueError, 'CUDA device unavailable'):
            self.f.configure(device='cuda:1')
        self.assertNotIn(('numpy_seed', 7), self.f.events)

    def test_closed_attestation_initial_hash_retained_without_rehash(self):
        seal = self.f.seal()
        self.assertEqual(set(seal), {'schema', 'profile', 'seed', 'effective',
                                    'software', 'initial_head_sha256'})
        self.assertEqual(set(seal['software']), {'torch', 'cuda', 'cudnn', 'python',
                                               'numpy', 'packages', 'device'})
        self.assertEqual(set(seal['software']['device']), {'index', 'name', 'compute_capability'})
        self.assertEqual(seal['profile'], PROFILE)
        json.dumps(seal, allow_nan=False)
        original = copy.deepcopy(seal)
        self.f.heads = {'head.weight': FakeTensor(struct.pack('<ff', 9, 10))}
        self.f.ns['validate_runtime'](seal, self.f.device('cuda'))
        self.assertEqual(seal, original)
        self.f.common.head_state.assert_called_once()

    def test_flags_environment_device_and_software_drift_fail_closed(self):
        mutations = [lambda f: setattr(f, 'warn', True), lambda f: setattr(f, 'enabled', False),
            lambda f: setattr(f.torch.backends.cudnn, 'benchmark', True),
            lambda f: setattr(f.torch.backends.cudnn, 'deterministic', False),
            lambda f: setattr(f.torch.utils.deterministic, 'fill_uninitialized_memory', False),
            lambda f: setattr(f.torch.backends, 'fp32_precision', 'tf32'),
            lambda f: setattr(f, 'threads', 8),
            lambda f: os.environ.__setitem__('CUBLAS_WORKSPACE_CONFIG', ':16:8'),
            lambda f: os.environ.__setitem__('PYTHONHASHSEED', '8'),
            lambda f: os.environ.__setitem__('NVIDIA_TF32_OVERRIDE', '1'),
            lambda f: setattr(f.torch, '__version__', 'changed'),
            lambda f: setattr(f.torch.version, 'cuda', 'changed'),
            lambda f: setattr(f.np, '__version__', 'changed'),
            lambda f: setattr(f.torch.backends.cudnn, 'version', lambda: 123),
            lambda f: setattr(f.torch.cuda, 'get_device_name', lambda _: 'changed'),
            lambda f: setattr(f.torch.cuda, 'get_device_name', lambda _: None),
            lambda f: setattr(f.torch.cuda, 'get_device_capability', lambda _: (-1, 0)),
            lambda f: setattr(f.torch.cuda, 'get_device_capability', lambda _: (9, 0)),
            lambda f: setattr(f, 'index', 1)]
        for mutate in mutations:
            with self.subTest(mutation=mutate), patch.dict(os.environ, ENV, clear=True):
                f = Fixture()
                seal = f.seal()
                mutate(f)
                with self.assertRaises(RuntimeError):
                    f.ns['validate_runtime'](seal, NS(index=0))

    def test_model_initialization_cannot_silently_change_settings(self):
        startup = self.f.configure()
        self.f.warn = True
        with self.assertRaises(RuntimeError):
            self.f.ns['attest_runtime'](args(), NS(index=None), object(), startup)
        self.f.common.head_state.assert_not_called()


class HeadHashTests(unittest.TestCase):
    def setUp(self):
        self.f = Fixture()
        self.hash = lambda: self.f.ns['initial_head_sha256'](object())

    def test_stable_mapping_order_and_length_framed_identity(self):
        original = self.hash()
        self.f.heads = dict(reversed(list(self.f.heads.items())))
        self.assertEqual(self.hash(), original)
        for state in [{'head.other': FakeTensor(), 'scorer.bias': FakeTensor()},
                      {'head.weight': FakeTensor(shape=(1, 2)), 'scorer.bias': FakeTensor()},
                      {'head.weight': FakeTensor(struct.pack('<ff', 1, 3)), 'scorer.bias': FakeTensor()},
                      {'head.weight': FakeTensor(struct.pack('<dd', 1, 2), dtype='torch.float64'),
                       'scorer.bias': FakeTensor()}]:
            self.f.heads = state
            self.assertNotEqual(self.hash(), original)
        self.assertEqual(len(original), 64)

    def test_invalid_empty_nonhead_shape_dtype_and_bytes_refused(self):
        for state in [{}, [], {'': FakeTensor()}, {1: FakeTensor()},
                      {'encoder.weight': FakeTensor()}, {'head.weight': FakeTensor(shape=(0,))},
                      {'head.weight': FakeTensor(shape=(True, 2))},
                      {'head.weight': FakeTensor(dtype='invalid')},
                      {'head.weight': FakeTensor(raw=b'bad')}]:
            with self.subTest(state=state):
                self.f.heads = state
                with self.assertRaises(ValueError):
                    self.hash()


class MainIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.f = Fixture()
        self.argv = ['--data', 'unused', '--out', 'unused', '--device', 'cuda']
        self.agent_module = ModuleType('laya.agent')
        def agent(*a, **k):
            self.f.events.append('Agent')
            return NS(model=object(), tok=NS(pad_token_id=0))
        self.agent_module.Agent = Mock(side_effect=agent)
        modules = patch.dict(sys.modules, {'laya': ModuleType('laya'), 'laya.agent': self.agent_module})
        modules.start()
        self.addCleanup(modules.stop)
        env = patch.dict(os.environ, ENV, clear=True)
        env.start()
        self.addCleanup(env.stop)

    def test_actual_main_order_initial_attestation_after_init_before_data(self):
        def load_rows(*a):
            self.f.events.append('data')
            raise RuntimeError('stop before data IO')
        self.f.ns['load_rows'] = load_rows
        actual = self.f.ns['attest_runtime']
        def attest(*a):
            self.f.events.append('attest')
            self.f.common.apply_heads.assert_called_once()
            return actual(*a)
        self.f.ns['attest_runtime'] = attest
        with self.assertRaisesRegex(RuntimeError, 'stop before data IO'):
            self.f.ns['main'](self.argv + ['--no-amp', '--runtime-profile', PROFILE, '--init', 'fake'])
        events = self.f.events
        self.assertLess(events.index(('deterministic', True, False)), events.index('cuda_available'))
        self.assertLess(events.index(('numpy_seed', 7)), events.index('random.seed'))
        self.assertLess(events.index('random.seed'), events.index('manual_seed'))
        self.assertLess(events.index('manual_seed'), events.index('batch_rng'))
        self.assertLess(events.index('batch_rng'), events.index('Agent'))
        self.assertLess(events.index('Agent'), events.index('attest'))
        self.assertLess(events.index('attest'), events.index('data'))

    def test_default_never_calls_profile_helpers_or_numpy_backend_mutators(self):
        for name in HELPERS - {'main', 'extra_metadata', 'encoder_states'}:
            self.f.ns[name] = Mock(side_effect=AssertionError('default profile helper'))
        self.f.ns['load_rows'] = Mock(side_effect=RuntimeError('stop before data IO'))
        with self.assertRaisesRegex(RuntimeError, 'stop before data IO'):
            self.f.ns['main'](self.argv)
        self.assertEqual(self.f.events, ['random.seed', 'manual_seed', 'batch_rng', 'device', 'Agent'])
        self.assertFalse(self.f.enabled)
        self.assertEqual(dict(os.environ), ENV)

    def test_invalid_main_options_and_forged_metadata_precede_agent_and_rng(self):
        audit = ModuleType('context_train')
        audit.install_training_audit = Mock()
        with patch.dict(sys.modules, {'context_train': audit}):
            for key in self.f.ns['RESERVED_METADATA']:
                with self.assertRaisesRegex(ValueError, 'reserved'):
                    self.f.ns['main'](self.argv + ['--metadata', json.dumps({key: 'forged'})])
        for extra in [['--runtime-profile', PROFILE],
                      ['--runtime-profile', PROFILE, '--no-amp', '--seed', '-1']]:
            with self.assertRaises(ValueError):
                self.f.ns['main'](self.argv + extra)
        with redirect_stdout(io.StringIO()), patch('sys.stderr', new_callable=io.StringIO):
            with self.assertRaises(SystemExit):
                self.f.ns['main'](self.argv + ['--runtime-profile', 'unknown'])
        self.assertEqual(self.f.events, [])
        self.agent_module.Agent.assert_not_called()

    def writer_code(self, report=False):
        main = next(n for n in ast.parse(SOURCE.read_text()).body
                    if isinstance(n, ast.FunctionDef) and n.name == 'main')
        # Select the actual adjacent profile guard + writer; execute both with fakes.
        blocks = [n.body for n in ast.walk(main) if hasattr(n, 'body') and isinstance(n.body, list)]
        for body in blocks:
            for i, node in enumerate(body):
                text = ast.unparse(node)
                if ((report and isinstance(node, ast.With) and 'json.dump(report' in text)
                        or (not report and isinstance(node, ast.Expr)
                            and text.startswith('common.save_checkpoint('))):
                    return compile(ast.Module(body=body[i - 1:i + 1], type_ignores=[]), 'writer AST', 'exec')
        self.fail('writer not found')

    def test_actual_checkpoint_and_report_guards_block_writers_on_drift(self):
        for report in (False, True):
            with self.subTest(report=report), patch.dict(os.environ, ENV, clear=True):
                f = Fixture()
                seal = f.seal()
                writer = Mock()
                ns = dict(f.ns, args=args(), runtime_seal=seal, device=NS(index=0),
                          meta={'legacy': 1}, report={'legacy': 1}, model=object(), path='unused',
                          open=writer)
                ns['args'].out = 'unused'
                f.warn = True
                with self.assertRaises(RuntimeError):
                    exec(self.writer_code(report), ns)
                writer.assert_not_called()
                f.common.save_checkpoint.assert_not_called()
                self.assertEqual(ns['meta'], {'legacy': 1})
                self.assertEqual(ns['report'], {'legacy': 1})

    def test_both_writers_retain_same_initial_seal_and_default_fieldsets(self):
        for enabled in (False, True):
            for report in (False, True):
                with self.subTest(enabled=enabled, report=report), patch.dict(os.environ, ENV, clear=True):
                    f = Fixture()
                    seal = f.seal() if enabled else None
                    data = {'legacy': 1}
                    sink = io.StringIO()
                    # StringIO is inspected via json.dump mock, before context close.
                    dump = Mock()
                    ns = dict(f.ns, args=args(runtime_profile=PROFILE if enabled else None),
                              runtime_seal=seal, device=NS(index=0), meta=data, report=data,
                              model=object(), path='unused', open=Mock(return_value=sink),
                              json=NS(dump=dump))
                    ns['args'].out = 'unused'
                    exec(self.writer_code(report), ns)
                    self.assertEqual(set(data), {'legacy', 'runtime_profile'} if enabled else {'legacy'})
                    if enabled:
                        self.assertIs(data['runtime_profile'], seal)
                        f.common.head_state.assert_called_once()
                    if report:
                        dump.assert_called_once_with(data, sink, indent=2)
                    else:
                        f.common.save_checkpoint.assert_called_once_with(ns['model'], 'unused', data)


if __name__ == '__main__':
    unittest.main()
