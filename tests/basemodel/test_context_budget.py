"""Synthetic interfaces only: no torch, encoder, tokenizer or model imports."""
import contextlib
import copy
import math
from pathlib import Path
import random
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools/basemodel'))
import context_train as T


def measurements():
    def record(value, batch=8):
        value = float(value)
        return dict(samples=3, p50_seconds=value / 2, p95_seconds=value, batch_size=batch)
    cached = dict(method='batch8x4_max_batch32_spot_v1', projection_batch_size=32,
        sequence_length=512, unit='seconds_per_batch', warmups=2, encoder_in_measured_step=False,
        provenance='frozen_fp16_disk_cache_fp32_head_logits_adamw', threads=2, seconds=100.,
        includes='cache_lookup_collate_forward_loss_backward_clip_optimizer; validation=loss; scoring=softmax',
        training=record(8), validation=record(4), scoring=dict(record(3, 1), p95_seconds_per_row=3.),
        spot32={name: dict(batch_size=32, samples=1, warmups=0, single_sample_seconds=value)
                for name, value in (('training', 30.), ('validation', 15.))})
    refresh(cached)
    return {'1': record(2, 1), 'cache_write': record(.5, 1), 'cached_head': cached}


def refresh(cached):
    cached['scaled_batch8_to32'] = dict(factor=4, **{
        name: 4 * cached[name]['p95_seconds'] for name in ('training', 'validation')})
    cached['projection_step_seconds'] = dict(source='max(scaled_batch8_to32, spot32)', **{
        name: max(cached['scaled_batch8_to32'][name], cached['spot32'][name]['single_sample_seconds'])
        for name in ('training', 'validation')})


def workload(train_rows, validation_rows):
    return dict(train_rows=train_rows, validation_rows=validation_rows,
                encoder_inputs_800_equivalent=2 * (train_rows + validation_rows),
                training_batches_800_equivalent=math.ceil(train_rows / 32),
                validation_batches_800_equivalent=math.ceil(validation_rows / 32),
                scoring_rows_800_equivalent=validation_rows)


class Accounting(unittest.TestCase):
    def test_exact_seconds_and_additive_components(self):
        result = T.project_workload(measurements(), workload(train_rows=64, validation_rows=32))
        self.assertEqual(result['projection_components'], dict(encoder_cache_seconds=480,
                         training_cache_io_seconds=640, inference_seconds=192))
        self.assertEqual(result['projected_full_seconds'], 1312)
        self.assertEqual((result['projection_groups'], result['projection_epochs'], result['projection_heads']), (800, 4, 2))

    def test_partial_batches_round_up(self):
        result = T.project_workload(measurements(), workload(train_rows=65, validation_rows=33))
        self.assertEqual(result['projection_components']['training_cache_io_seconds'], 8 * (3 * 32 + 2 * 16))

    def test_encoder_not_multiplied_by_epochs_or_threshold_passes(self):
        a = measurements()
        b = copy.deepcopy(a)
        b['1']['p95_seconds'] *= 2
        x = T.project_workload(a, workload(train_rows=800, validation_rows=200))
        y = T.project_workload(b, workload(train_rows=800, validation_rows=200))
        self.assertEqual(y['projected_full_seconds'] - x['projected_full_seconds'], 4000)

    def test_exact_g1_dedup_and_conservative_group_scaling(self):
        from context_data import generate
        from context_v1 import load_contract, serialize, blind, Refusal
        c = load_contract()
        counts = T.g1_workload_counts(c, 7)
        for groups in (400, 401, 600, 800):
            keys = set()
            training = generate(7, groups, 'train')
            validation = generate(7, groups // 4, 'val')
            for row in training + validation:
                for control in (False, True):
                    try:
                        text, _ = serialize(row['request'], row['action'],
                            blind(row['secrets'], c) if control else row['secrets'], c,
                            enforce_budget=not control)
                        keys.add(text)
                    except Refusal:
                        pass
            scale = groups / 800
            self.assertGreaterEqual(counts['encoder_inputs_800_equivalent'] * scale + 1e-9, len(keys))
            self.assertGreaterEqual(counts['training_batches_800_equivalent'] * scale + 1e-9, math.ceil(len(training) / 32))
            self.assertGreaterEqual(counts['validation_batches_800_equivalent'] * scale + 1e-9, math.ceil(len(validation) / 32))
            self.assertGreaterEqual(counts['scoring_rows_800_equivalent'] * scale + 1e-9, len(validation))
            if groups == 800:
                self.assertEqual(counts['unique_encoder_inputs'], len(keys))
                self.assertEqual(counts['train_rows'], len(training))
                self.assertEqual(counts['validation_rows'], len(validation))
                self.assertLess(len(keys), 2 * (len(training) + len(validation)))

    def test_invalid_measurements_fail_closed(self):
        for value in (0, -1, float('nan'), float('inf'), '2', None):
            for key in ('training', 'validation', 'scoring'):
                with self.subTest(value=value, key=key):
                    m = measurements()
                    m['cached_head'][key]['p95_seconds'] = value
                    with self.assertRaises(T.Unsupported):
                        T.project_workload(m, workload(train_rows=10, validation_rows=10))
        for change in ({'batch_size': 1}, {'sequence_length': 64}, {'warmups': 0},
                       {'encoder_in_measured_step': True}, {'unit': 'milliseconds'}):
            m = measurements()
            m['cached_head'].update(change)
            with self.assertRaises(T.Unsupported):
                T.project_workload(m, workload(train_rows=10, validation_rows=10))
        with self.assertRaises(T.Unsupported):
            T.project_workload({}, {})

    def test_warmups_excluded(self):
        times = iter([0, 100, 100, 200, 200, 201, 201, 203, 203, 206])
        step, deadline = Mock(), Mock()
        result = T.measure_cached_steps(step, deadline, clock=lambda: next(times))
        self.assertEqual(result, dict(samples=3, p50_seconds=2, p95_seconds=3))
        self.assertEqual(step.call_count, 5)
        self.assertEqual(deadline.call_count, 10)

    def test_deadline_and_invalid_clock_fail_closed(self):
        with self.assertRaises(T.Unsupported):
            T.measure_cached_steps(Mock(), Mock(side_effect=T.Unsupported('timeout')))
        with self.assertRaises(T.Unsupported):
            T.measure_cached_steps(Mock(), Mock(), clock=lambda: 0)


    def test_strict_schema_missing_every_required_field(self):
        def paths(value, prefix=()):
            for key, child in value.items():
                yield prefix + (key,)
                if isinstance(child, dict):
                    yield from paths(child, prefix + (key,))
        for path in paths(measurements()['cached_head']):
            with self.subTest(path=path):
                m = measurements()
                record = m['cached_head']
                for key in path[:-1]:
                    record = record[key]
                del record[path[-1]]
                with self.assertRaises(T.Unsupported):
                    T.project_workload(m, workload(64, 32))

    def test_method_partial_and_old_shape_rejected(self):
        for cached in ({'batch_size': 32}, {'method': 'unknown'}, None):
            m = measurements()
            if cached is None:
                del m['cached_head']
                m['diagnostics'] = {'cached_head_partial': dict(eligibility=False)}
            else:
                m['cached_head'] = cached
            with self.assertRaisesRegex(T.Unsupported, 'cached timing method' if cached is not None else 'invalid budget'):
                T.project_workload(m, workload(64, 32))

    def test_strict_raw_and_derived_values(self):
        paths = [(name, key) for name in ('training', 'validation', 'scoring')
                 for key in ('p50_seconds', 'p95_seconds')]
        paths += [('spot32', name, 'single_sample_seconds') for name in ('training', 'validation')]
        paths += [(kind, name) for kind in ('scaled_batch8_to32', 'projection_step_seconds')
                  for name in ('training', 'validation')]
        paths += [('scoring', 'p95_seconds_per_row'), ('seconds',)]
        for path in paths:
            for value in (True, 1, '1', None, 0., -1., float('inf'), float('nan')):
                with self.subTest(path=path, value=value):
                    m = measurements()
                    record = m['cached_head']
                    for key in path[:-1]:
                        record = record[key]
                    record[path[-1]] = value
                    with self.assertRaises(T.Unsupported):
                        T.project_workload(m, workload(64, 32))
        for name in ('training', 'validation', 'scoring'):
            for key, value in (('samples', 4), ('samples', True), ('batch_size', 32),
                               ('p50_seconds', 100.)):
                m = measurements()
                m['cached_head'][name][key] = value
                with self.assertRaises(T.Unsupported):
                    T.project_workload(m, workload(64, 32))
        for name in ('training', 'validation'):
            for key, value in (('samples', 3), ('warmups', 1), ('batch_size', 8),
                               ('p50_seconds', 1.), ('p95_seconds', 1.)):
                m = measurements()
                m['cached_head']['spot32'][name][key] = value
                with self.assertRaises(T.Unsupported):
                    T.project_workload(m, workload(64, 32))
        for field, value in (('warmups', 3), ('seconds', 120.01), ('threads', True),
                             ('projection_batch_size', 8), ('provenance', 'unknown'), ('includes', ''),
                             ('sequence_length', 512.), ('warmups', True)):
            m = measurements()
            m['cached_head'][field] = value
            with self.assertRaises(T.Unsupported):
                T.project_workload(m, workload(64, 32))
        for kind in ('scaled_batch8_to32', 'projection_step_seconds'):
            m = measurements()
            m['cached_head'][kind]['training'] += .001
            with self.assertRaisesRegex(T.Unsupported, 'derived conflict'):
                T.project_workload(m, workload(64, 32))

    def test_scaling_guard_equality_and_both_max_branches(self):
        for name in ('training', 'validation'):
            for ratio in (1., 1.2, 1.3, 1.300001):
                m = measurements()
                c = m['cached_head']
                c['spot32'][name]['single_sample_seconds'] = ratio * c['scaled_batch8_to32'][name]
                refresh(c)
                if ratio > 1.3:
                    with self.assertRaisesRegex(T.Unsupported, 'batch scaling outside calibrated regime'):
                        T.project_workload(m, workload(64, 32))
                else:
                    result = T.project_workload(m, workload(64, 32))
                    expected = 8 * (2*c['projection_step_seconds']['training'] + c['projection_step_seconds']['validation'])
                    self.assertEqual(result['projection_components']['training_cache_io_seconds'], expected)

    def test_valid_raw_increases_never_reduce_projection(self):
        base = T.project_workload(measurements(), workload(64, 32))['projected_full_seconds']
        paths = [(name, key) for name in ('training', 'validation', 'scoring')
                 for key in ('p50_seconds', 'p95_seconds')]
        paths += [('spot32', name, 'single_sample_seconds') for name in ('training', 'validation')]
        for path in paths:
            m = measurements()
            c = record = m['cached_head']
            for key in path[:-1]:
                record = record[key]
            record[path[-1]] *= 1.1
            c['scoring']['p95_seconds_per_row'] = c['scoring']['p95_seconds']
            refresh(c)
            self.assertGreaterEqual(T.project_workload(m, workload(64, 32))['projected_full_seconds'], base)

    def test_invalid_counts(self):
        for key in workload(64, 32):
            for value in (False, 0, -1, '1', None, float('inf'), float('nan')):
                counts = workload(64, 32)
                counts[key] = value
                with self.assertRaises(T.Unsupported):
                    T.project_workload(measurements(), counts)


class Tensor:
    def __init__(self, value=1., shape=(32, 512, 4)):
        self.value, self.shape = value, shape
        self.requires_grad, self.grad, self.dtype = True, object(), 'float32'
    def detach(self): return self
    def clone(self): return Tensor(self.value, self.shape)
    def copy_(self, other): self.value = other.value
    def requires_grad_(self, flag): self.requires_grad = flag
    def float(self): return self
    def __float__(self): return float(self.value)
    def __truediv__(self, value): return self
    def __getitem__(self, key): return self
    def __setitem__(self, key, value): pass
    def backward(self): pass


class Model:
    def __init__(self):
        self.p, self.encoder_p = Tensor(), Tensor()
        self.training = True
        self.head = types.SimpleNamespace(training=False)
        self.head.train = lambda: setattr(self.head, 'training', True)
        self.type_emb = types.SimpleNamespace(weight=Tensor(shape=(1, 4)))
    def named_parameters(self): return [('head.weight', self.p), ('encoder.weight', self.encoder_p)]
    def modules(self): return [self, self.head]
    def eval(self):
        self.training = self.head.training = False


class CachedTiming(unittest.TestCase):
    def setUp(self):
        self.scorer = T.Scorer.__new__(T.Scorer)
        self.scorer.model, self.scorer.pad, self.scorer.temperature = Model(), 0, 1
        self.scorer.model.encoder_p.dtype = 'half'
        self.items = [dict(cache_key=str(i), ids=[1] * 4, y=i % 2) for i in range(32)]
        self.scorer.cache = types.SimpleNamespace(records={str(i): True for i in range(32)}, get=Mock(return_value=Tensor()))
        self.rng = 'original'
        self.optimizer = Mock()
        self.torch = types.SimpleNamespace(float32='float32',
            no_grad=contextlib.nullcontext, set_grad_enabled=lambda flag: contextlib.nullcontext(),
            get_rng_state=lambda: self.rng, set_rng_state=lambda value: setattr(self, 'rng', value),
            get_num_threads=lambda: 2, zeros=lambda shape: Tensor(shape=shape),
            isfinite=lambda value: True, softmax=lambda *args: Tensor(),
            nn=types.SimpleNamespace(utils=types.SimpleNamespace(clip_grad_norm_=Mock())),
            optim=types.SimpleNamespace(AdamW=Mock(return_value=self.optimizer)))
        self.scorer.torch = self.torch

    def fake_imports(self, train, functional):
        torch = types.ModuleType('torch')
        nn = types.ModuleType('torch.nn')
        torch.nn, nn.functional = nn, functional
        return {'train': train, 'torch': torch, 'torch.nn': nn, 'torch.nn.functional': functional}

    def test_actual_step_path_cache_only_with_fake_interfaces(self):
        # Execute the actual benchmark and Scorer.features implementation. An
        # encoder invocation raises immediately; all tensors are synthetic fakes.
        train = types.ModuleType('train')
        train.collate = Mock(return_value=dict(input_ids=Tensor(shape=(32, 32)), attention_mask=Tensor(), y=Tensor()))
        train.head_logits = Mock(return_value=Tensor())
        train.targets = lambda y: y
        train.encoder_states = Mock(side_effect=AssertionError('encoder in measured head step'))
        functional = types.ModuleType('torch.nn.functional')
        functional.pad = Mock(side_effect=lambda tensor, *args, **kwargs: Tensor(shape=(32, 512)))
        loss = Tensor()
        loss.backward = Mock()
        functional.cross_entropy = Mock(return_value=loss)
        now = [0.]
        def clock():
            now[0] += .01
            return now[0]
        with patch.dict(sys.modules, self.fake_imports(train, functional)), patch.object(
                T.time, 'monotonic', side_effect=clock):
            result = self.scorer.cached_head_timings(self.items)
        self.assertEqual(result['training']['samples'], 3)
        self.assertEqual(result['validation']['samples'], 3)
        self.assertEqual(result['scoring']['batch_size'], 1)
        self.assertEqual(self.optimizer.step.call_count, 6)
        self.assertEqual(train.head_logits.call_count, 17)
        self.assertEqual(self.scorer.cache.get.call_count, 149)
        self.assertEqual([len(call.args[0]) for call in train.collate.call_args_list],
                         [8]*10 + [1]*5 + [32]*2)
        self.assertEqual([result[k]['batch_size'] for k in ('training', 'validation', 'scoring')], [8, 8, 1])
        self.assertNotIn('batch_size', result)
        for name in ('training', 'validation'):
            self.assertEqual(result['spot32'][name]['samples'], 1)
            self.assertEqual(result['spot32'][name]['warmups'], 0)
            self.assertEqual(set(result['spot32'][name]),
                             {'batch_size', 'samples', 'warmups', 'single_sample_seconds'})
        self.assertEqual(loss.backward.call_count, 6)
        measured = measurements()
        measured['cached_head'] = result
        self.assertGreater(T.project_workload(measured, workload(64, 32))['projected_full_seconds'], 0.)
        self.assertEqual(self.optimizer.zero_grad.call_count, 6)
        self.assertEqual(self.torch.nn.utils.clip_grad_norm_.call_count, 6)
        train.encoder_states.assert_not_called()
        self.torch.optim.AdamW.assert_called_once_with([self.scorer.model.p], lr=.0003, weight_decay=.01)

    def test_state_restored_after_success_and_failure(self):
        for fail in (False, True):
            model = self.scorer.model
            before = [(p, p.value, p.requires_grad, p.grad) for _, p in model.named_parameters()]
            modes = [m.training for m in model.modules()]
            py_rng = random.getstate()
            def step(*args):
                model.p.value = 99
                model.eval()
                self.rng = 'changed'
                random.random()
                if fail:
                    raise T.Unsupported('synthetic failure')
            with patch.object(self.scorer, '_cached_head_step', side_effect=step):
                if fail:
                    with self.assertRaises(T.Unsupported):
                        self.scorer.cached_head_timings(self.items)
                else:
                    self.scorer.cached_head_timings(self.items)
            for p, value, flag, grad in before:
                self.assertEqual((p.value, p.requires_grad, p.grad), (value, flag, grad))
            self.assertEqual([m.training for m in model.modules()], modes)
            self.assertEqual(self.rng, 'original')
            self.assertEqual(random.getstate(), py_rng)

    def test_missing_cache_is_unsupported_before_forward(self):
        self.scorer.cache.records.clear()
        with patch.dict(sys.modules, self.fake_imports(types.ModuleType('train'), types.ModuleType('torch.nn.functional'))):
            with self.assertRaisesRegex(T.Unsupported, 'precomputed'):
                self.scorer._cached_head_step(self.items, self.optimizer, [], True)

    def test_encoder_schema_and_disposable_cache_on_success_and_failure(self):
        for fail in (False, True):
            original = self.scorer.cache
            disposable = types.SimpleNamespace(records={}, put=Mock(), close=Mock())
            self.scorer.item = Mock(side_effect=self.items)
            self.torch.device = lambda name: name
            train = types.ModuleType('train')
            train.collate = Mock(return_value={})
            train.encoder_states = Mock(return_value=Tensor())
            rows = [dict(local_rule=None) for _ in range(32)]
            with patch.dict(sys.modules, {'train': train}), patch.object(T, 'FeatureCache', return_value=disposable), patch.object(
                    self.scorer, 'cached_head_timings', side_effect=T.Unsupported('failure') if fail else None,
                    return_value={'synthetic': True}):
                if fail:
                    with self.assertRaises(T.Unsupported):
                        self.scorer.probe_timings(rows)
                else:
                    result = self.scorer.probe_timings(rows)
                    self.assertEqual(result['1']['samples'], 32)
                    self.assertEqual(result['8']['samples'], 4)
                    for key in ('1', '8'):
                        self.assertGreater(result[key]['p95_seconds'], 0)
            self.assertIs(self.scorer.cache, original)
            self.assertEqual(train.encoder_states.call_count, 36)
            self.assertEqual(disposable.put.call_count, 32)
            disposable.close.assert_called_once()

    def test_head_deadline_restores_state(self):
        now = [0.]
        def step(*args):
            self.scorer.model.p.value = 99
            now[0] += 121
        with patch.object(T.time, 'monotonic', side_effect=lambda: now[0]), patch.object(
                self.scorer, '_cached_head_step', side_effect=step):
            with self.assertRaisesRegex(T.Unsupported, 'wall limit'):
                self.scorer.cached_head_timings(self.items)
        self.assertEqual(self.scorer.model.p.value, 1.)

    def test_every_phase_failure_and_deadline_restores_state(self):
        for phase, first_call in (('training8', 1), ('validation8', 6), ('scoring1', 11),
                                  ('spot32.training', 16), ('spot32.validation', 17)):
            for failure in ('primary', 'deadline', 'primary_after_deadline'):
                with self.subTest(phase=phase, failure=failure):
                    now, calls = [0.], [0]
                    model = self.scorer.model
                    before = [(p, p.value, p.requires_grad, p.grad) for _, p in model.named_parameters()]
                    modes, rng = [m.training for m in model.modules()], random.getstate()
                    original_cache = self.scorer.cache
                    primary = RuntimeError('synthetic primary')
                    def step(*args):
                        calls[0] += 1
                        model.p.value = 99
                        model.p.grad = None
                        model.eval()
                        self.rng = 'changed'
                        random.random()
                        now[0] += .1
                        if calls[0] == first_call:
                            if failure != 'primary':
                                now[0] = 121.
                            if failure != 'deadline':
                                raise primary
                    with patch.object(T.time, 'monotonic', side_effect=lambda: now[0]), patch.object(
                            self.scorer, '_cached_head_step', side_effect=step):
                        with self.assertRaises((RuntimeError, T.Unsupported)) as caught:
                            self.scorer.cached_head_timings(self.items)
                    if failure != 'deadline':
                        self.assertIs(caught.exception, primary)
                    else:
                        self.assertIn('wall limit', str(caught.exception))
                    for p, value, flag, grad in before:
                        self.assertEqual((p.value, p.requires_grad, p.grad), (value, flag, grad))
                    self.assertEqual([m.training for m in model.modules()], modes)
                    self.assertEqual(self.rng, 'original')
                    self.assertEqual(random.getstate(), rng)
                    self.assertIs(self.scorer.cache, original_cache)
                    partial = self.scorer.diagnostics['cached_head_partial']
                    self.assertEqual(set(partial), {'phase', 'completed_calls', 'elapsed_seconds', 'eligibility'})
                    self.assertEqual(partial['phase'], phase)
                    self.assertEqual(partial['completed_calls'], first_call if failure == 'deadline' else first_call-1)
                    self.assertIs(partial['eligibility'], False)
                    with self.assertRaises(T.Unsupported):
                        T.project_workload({'diagnostics': self.scorer.diagnostics}, workload(64, 32))

    def test_setup_and_restore_are_inside_deadline(self):
        for location in ('setup', 'restore', 'success'):
            now = [0.]
            def setup(*args, **kwargs):
                now[0] += 121. if location == 'setup' else 1.
                return self.optimizer
            def restore(value):
                self.rng = value
                now[0] += 121. if location == 'restore' else 2.
            def step(*args):
                now[0] += .1
            with patch.object(T.time, 'monotonic', side_effect=lambda: now[0]), patch.object(
                    self.torch.optim, 'AdamW', side_effect=setup), patch.object(
                    self.torch, 'set_rng_state', side_effect=restore), patch.object(
                    self.scorer, '_cached_head_step', side_effect=step):
                if location == 'success':
                    result = self.scorer.cached_head_timings(self.items)
                    self.assertAlmostEqual(result['seconds'], 4.7)
                    self.assertEqual(self.scorer.diagnostics, {})
                else:
                    with self.assertRaisesRegex(T.Unsupported, 'wall limit'):
                        self.scorer.cached_head_timings(self.items)
                    self.assertEqual(self.scorer.diagnostics['cached_head_partial']['phase'], location)
            self.assertEqual(self.rng, 'original')

    def test_real_calibration_failure_cleans_disposable_probe_cache(self):
        for failing_call in (1, 6, 11, 16, 17):
            original = self.scorer.cache
            disposable = types.SimpleNamespace(records={}, put=Mock(), close=Mock())
            self.scorer.item = Mock(side_effect=self.items)
            self.torch.device = lambda name: name
            train = types.ModuleType('train')
            train.collate = Mock(return_value={})
            train.encoder_states = Mock(return_value=Tensor())
            calls = [0]
            def step(*args):
                calls[0] += 1
                if calls[0] == failing_call:
                    raise T.Unsupported('synthetic failure')
            with patch.dict(sys.modules, {'train': train}), patch.object(T, 'FeatureCache', return_value=disposable), patch.object(
                    self.scorer, '_cached_head_step', side_effect=step):
                with self.assertRaisesRegex(T.Unsupported, 'synthetic failure'):
                    self.scorer.probe_timings([dict(local_rule=None) for _ in range(32)])
            disposable.close.assert_called_once()
            self.assertIs(self.scorer.cache, original)
            self.assertFalse(self.scorer.diagnostics['cached_head_partial']['eligibility'])

    def test_main_copies_only_partial_diagnostic_and_handles_uninitialized_scorer(self):
        import json
        for initialized in (False, True):
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                # Synthetic manifest and rows only; main's dependencies are fakes.
                (root / 'data-manifest.json').write_text(json.dumps({'files': {
                    'train.jsonl': {'sha256': 'fake'}, 'val.jsonl': {'sha256': 'fake'}}}))
                cache = Mock()
                scorer = Mock()
                scorer.model = Mock()
                partial = dict(phase='training8', completed_calls=0, elapsed_seconds=121., eligibility=False)
                scorer.diagnostics = {'cached_head_partial': partial}
                scorer.probe_timings.side_effect = T.Unsupported('cached timing wall limit')
                common = types.ModuleType('common')
                common.head_state = lambda model: {}
                torch = types.ModuleType('torch')
                torch.manual_seed = Mock()
                env = Mock(return_value=({}, {}))
                if not initialized:
                    env.side_effect = T.Unsupported('synthetic setup')
                with patch.object(T, 'install_training_audit'), patch.object(T, 'load_contract', return_value={}), patch.object(
                        T, 'environment', env), patch.object(T, 'read_rows', return_value=[]), patch.object(
                        T, 'overlap', return_value={}), patch.object(T, 'sha256', return_value='fake'), patch.object(
                        T, 'FeatureCache', return_value=cache), patch.object(T, 'Scorer', return_value=scorer), patch.dict(
                        sys.modules, {'torch': torch, 'common': common}), patch('builtins.print'):
                    code = T.main(['--data', str(root), '--out', str(root/'out'), '--base-dir', 'fake'])
                self.assertEqual(code, 3)
                report = json.loads((root/'out'/'training-report.json').read_text())
                self.assertEqual(report['outcome'], 'UNSUPPORTED')
                self.assertNotIn('cached_head', report)
                self.assertFalse((root/'out'/'freeze.json').exists())
                self.assertNotIn('training_completed', report)
                if initialized:
                    self.assertEqual(report['diagnostics'], {'cached_head_partial': partial})
                    cache.close.assert_called_once()
                else:
                    self.assertNotIn('diagnostics', report)

    def test_bounds_and_fp32_fail_closed(self):
        for seconds in (0, 121):
            with self.assertRaises(T.Unsupported):
                self.scorer.cached_head_timings(self.items, seconds)
        self.scorer.model.p.dtype = 'half'
        with self.assertRaises(T.Unsupported):
            self.scorer.cached_head_timings(self.items)


if __name__ == '__main__':
    unittest.main()
