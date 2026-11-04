"""Synthetic interfaces only: no torch, encoder, tokenizer or model imports."""
import contextlib
import copy
import math
from pathlib import Path
import random
import sys
import types
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools/basemodel'))
import context_train as T


def measurements():
    def record(value, batch=32):
        return dict(samples=3, p50_seconds=value / 2, p95_seconds=value,
                    batch_size=batch, p95_seconds_per_row=value / batch)
    return {'1': record(2, 1), 'cache_write': record(.5, 1), 'cached_head': dict(batch_size=32, sequence_length=512,
            unit='seconds_per_batch', warmups=2, encoder_in_measured_step=False,
            training=record(32), validation=record(16), scoring=record(3, 1))}


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
        functional.cross_entropy = Mock(return_value=Tensor())
        with patch.dict(sys.modules, self.fake_imports(train, functional)):
            result = self.scorer.cached_head_timings(self.items)
        self.assertEqual(result['training']['samples'], 3)
        self.assertEqual(result['validation']['samples'], 3)
        self.assertEqual(result['scoring']['batch_size'], 1)
        self.assertEqual(self.optimizer.step.call_count, 5)
        self.assertEqual(train.head_logits.call_count, 15)
        self.assertEqual(self.scorer.cache.get.call_count, 325)
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

    def test_bounds_and_fp32_fail_closed(self):
        for seconds in (0, 121):
            with self.assertRaises(T.Unsupported):
                self.scorer.cached_head_timings(self.items, seconds)
        self.scorer.model.p.dtype = 'half'
        with self.assertRaises(T.Unsupported):
            self.scorer.cached_head_timings(self.items)


if __name__ == '__main__':
    unittest.main()
