#!/usr/bin/env python3
"""Tiny real-CPU checks on the pinned CUDA wheel. Never constructs an Agent.

Run only in the isolated hosted preflight, with CUDA hidden at process startup.
Evidence contains identities and case counts, never tensor values or row text.
"""
import argparse
import hashlib
import importlib.metadata
import json
import math
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]


def require(condition):
    if not condition:
        raise ValueError('CPU preflight assertion failed')


def near(actual, expected):
    require(math.isfinite(actual) and math.isclose(actual, expected, rel_tol=2e-10, abs_tol=2e-10))


def softplus(x):
    return max(x, 0.) + math.log1p(math.exp(-abs(x)))


def sigmoid(x):
    if x >= 0:
        return 1. / (1. + math.exp(-x))
    e = math.exp(x)
    return e / (1. + e)


def oracle(rows, labels, temperature):
    """Independent scalar arithmetic, including the two logit derivatives."""
    z = [(b - a) / temperature for a, b in rows]
    n = len(z)
    ce = sum(softplus(v) - y * v for v, y in zip(z, labels)) / n
    ce_grad = [(sigmoid(v) - y) / n for v, y in zip(z, labels)]
    tail_grad = [0.] * n
    positives = [i for i, y in enumerate(labels) if y == 1]
    negatives = [i for i, y in enumerate(labels) if y == 0]
    tail = 0.
    if positives and negatives:
        top = max(z[i] for i in negatives)
        ties = [i for i in negatives if z[i] == top]
        tail = sum(softplus(top - z[i]) for i in positives) / len(positives)
        for i in positives:
            tail_grad[i] = -sigmoid(top - z[i]) / len(positives)
        top_grad = sum(sigmoid(top - z[i]) for i in positives) / len(positives)
        for i in ties:
            tail_grad[i] = top_grad / len(ties)
    def logits_grad(values):
        return [(-g / temperature, g / temperature) for g in values]
    return tail, ce + tail, logits_grad(tail_grad), logits_grad([a+b for a,b in zip(ce_grad, tail_grad)])


def semantics(torch, trainer, cases):
    def tensors(rows, labels):
        return (torch.tensor(rows, dtype=torch.float64, requires_grad=True),
                torch.tensor(labels, dtype=torch.float64))

    def check(rows, labels, temperature, kind):
        logits, y = tensors(rows, labels)
        tail, actual_kind = trainer.batch_tail_term(logits, y, temperature)
        ce = torch.nn.functional.cross_entropy(logits / temperature, trainer.targets(y))
        total = ce + tail
        expected_tail, expected_total, expected_tg, expected_g = oracle(rows, labels, temperature)
        near(float(tail.detach()), expected_tail)
        near(float(total.detach()), expected_total)
        require(actual_kind == kind)
        if kind == 'mixed':
            tg = torch.autograd.grad(tail, logits, retain_graph=True)[0].tolist()
            for got, want in zip(tg, expected_tg):
                for a, b in zip(got, want):
                    near(a, b)
        grad = torch.autograd.grad(total, logits)[0].tolist()
        for got, want in zip(grad, expected_g):
            for a, b in zip(got, want):
                near(a, b)
        return float(tail.detach())

    rows = [[.2, -.3], [0., 2.], [-1., -.5], [.1, 1.1]]
    labels = [1., 0., 0., 1.]
    base = check(rows, labels, 1.98, 'mixed')
    cases.append('numeric_loss_and_gradients')
    check([[0., -900.], [0., 900.], [0., 0.]], [1., 0., 1.], 1., 'mixed')
    cases.append('stable_extremes')
    tied = [[0., 1.], [0., 2.], [0., 2.], [0., -1.]]
    check(tied, [1., 0., 0., 1.], 1.98, 'mixed')
    cases.append('maximum_ties_split')
    logits, y = tensors(rows, labels)
    tail, _ = trainer.batch_tail_term(logits, y, 1.98)
    tg = torch.autograd.grad(tail, logits)[0].tolist()
    require(tg[1][1] > 0 and tg[0][1] < 0 and tg[3][1] < 0 and tg[2] == [0., 0.])
    for index, direction in ((1, 1), (0, -1)):
        changed = [list(r) for r in rows]
        changed[index][1] += .25
        value = check(changed, labels, 1.98, 'mixed')
        require((value - base) * direction > 0)
    cases.append('signs_and_only_top_negative')
    shifted = [[a, b + 3. * 1.98] for a, b in rows]
    near(check(shifted, labels, 1.98, 'mixed'), base)
    cases.append('tail_z_shift_invariance')
    for label, kind in ((0., 'negative_only'), (1., 'positive_only')):
        check(rows, [label] * 4, 1.98, kind)
    cases.append('one_class_ce_equivalence')

    valid_logits, valid_y = tensors(rows, labels)
    invalid = []
    for temperature in (True, False, 0., -1., math.inf, math.nan, '1', None, complex(1, 0)):
        invalid.append((valid_logits, valid_y, temperature))
    for bad in ([], [0., 1.], [[0., 1., 2.]], [[[0., 1.]]], [[math.nan, 0.]], [[0., math.inf]],
                [[-1.7e308, 1.7e308]]):
        t = torch.tensor(bad, dtype=torch.float64)
        invalid.append((t, torch.zeros(t.shape[0], dtype=torch.float64), 1.))
    for bad in ([1., .5, 0., 1.], [1., math.nan, 0., 1.], [1., math.inf, 0., 1.],
                [1., -1., 0., 1.], [1., 2., 0., 1.], [1.], [[1., 0., 0., 1.]]):
        invalid.append((valid_logits, torch.tensor(bad, dtype=torch.float64), 1.))
    invalid.append((torch.tensor([[0., 1.7e308], [0., -1.7e308]], dtype=torch.float64),
                    torch.tensor([0., 1.], dtype=torch.float64), 1.))
    invalid.append((torch.tensor([[0., 1e308], [0., 0.], [0., 0.]], dtype=torch.float64),
                    torch.tensor([0., 1., 1.], dtype=torch.float64), 1.))
    # Equal logits have finite zero z, but their scaled CE logits can overflow.
    invalid.append((torch.full((2, 2), torch.finfo(torch.float32).max / 2),
                    torch.tensor([0., 1.]), 1e-10))
    invalid.extend(((valid_logits, valid_y.clone().requires_grad_(), 1.),
                    (valid_logits, valid_y.to(torch.complex128), 1.),
                    (valid_logits.to(torch.complex128), valid_y, 1.),
                    (None, valid_y, 1.), (valid_logits, None, 1.),
                    (valid_logits, valid_y, 1e-320)))
    for logits, y, temperature in invalid:
        try:
            trainer.batch_tail_term(logits, y, temperature)
        except ValueError:
            pass
        else:
            raise ValueError('invalid input accepted')
    cases.append('invalid_inputs_refused')


def runtime(torch, trainer, cases):
    require(not torch.cuda.is_initialized() and not torch.cuda.is_available())
    try:
        trainer.configure_runtime(SimpleNamespace(runtime_profile='cuda-deterministic-v1',
                                                device='cuda', no_amp=True, seed=7))
    except RuntimeError as exc:
        require(str(exc) == 'CUDA unavailable for deterministic profile')
    else:
        raise ValueError('CPU runtime failed to refuse CUDA profile')
    settings = trainer.runtime_settings(7)
    require(settings == dict(flags=dict(deterministic=True, warn_only=False,
            cudnn_benchmark=False, cudnn_deterministic=True, fill_uninitialized_memory=True,
            fp32_precision=['ieee'] * 5, threads=4), environment=dict(PYTHONHASHSEED='7',
            CUBLAS_WORKSPACE_CONFIG=':4096:8', NVIDIA_TF32_OVERRIDE='0')))
    require(not torch.cuda.is_initialized() and not torch.cuda.is_available())
    cases.append('genuine_runtime_controls_then_cpu_refusal')
    return settings


def head_hash(torch, trainer, cases):
    class Dummy:
        def __init__(self, state):
            self.state = state
        def state_dict(self):
            return self.state

    # Scalar plus noncontiguous float64 input exercises common.head_state's conversion.
    state = {'head.scalar': torch.tensor(.5),
             'scorer.weight': torch.tensor([[1., 2.], [3., 4.]], dtype=torch.float64).t(),
             'encoder.ignored': torch.tensor(9.)}
    def independent(values):
        h = hashlib.sha256()
        for name in sorted(values):
            shape, floats = values[name]
            descriptor = json.dumps([name, shape, 'torch.float32'], separators=(',', ':')).encode('ascii')
            raw = struct.pack('=' + 'f' * len(floats), *floats)
            for part in (descriptor, raw):
                h.update(len(part).to_bytes(8, 'big'))
                h.update(part)
        return h.hexdigest()
    expected = independent({'head.scalar': ([], [.5]), 'scorer.weight': ([2, 2], [1., 3., 2., 4.])})
    require(trainer.initial_head_sha256(Dummy(state)) == expected)
    converted = trainer.common.head_state(Dummy(state))
    require(set(converted) == {'head.scalar', 'scorer.weight'})
    require(all(t.dtype == torch.float32 and t.is_contiguous() and t.device.type == 'cpu'
                and not t.requires_grad for t in converted.values()))
    require(trainer.initial_head_sha256(Dummy(dict(reversed(list(state.items()))))) == expected)
    variants = [dict(state, **{'head.scalar': torch.tensor(.6)}),
                dict(state, **{'scorer.weight': state['scorer.weight'].reshape(4)}),
                {('head.renamed' if k == 'head.scalar' else k): v for k, v in state.items()}]
    for changed in variants:
        require(trainer.initial_head_sha256(Dummy(changed)) != expected)
    cases.append('real_scalar_contiguous_float32_head_hash')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', required=True)
    args = parser.parse_args(argv)
    evidence = dict(schema='bouncer-batch-tail-cpu-preflight-v1', source_head=None,
                    github_sha=os.environ.get('GITHUB_SHA'), versions={}, cases=[], count=0,
                    status='FAIL', failure='cpu_preflight_failed', phase='source_identity',
                    gpu='NOT_RUN', model='NOT_RUN')
    success = False
    try:
        head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
        require(re.fullmatch('[0-9a-f]{40}', head) is not None)
        evidence['source_head'] = head
        for key in ('SOURCE_HEAD_SHA', 'GITHUB_SHA'):
            value = os.environ.get(key)
            require(value is None or re.fullmatch('[0-9a-f]{40}', value) is not None)
        require(os.environ.get('SOURCE_HEAD_SHA', head) == head)
        require(os.environ.get('GITHUB_SHA', head) == head)
        require(os.environ.get('CUDA_VISIBLE_DEVICES') in ('', '-1'))
        require(os.environ.get('PYTHONHASHSEED') == '7')
        evidence['phase'] = 'runtime_identity'
        import torch
        require(str(torch.__version__) == '2.14.0+cu130' and torch.version.cuda == '13.0')
        require(not torch.cuda.is_initialized() and not torch.cuda.is_available())
        evidence['versions'] = {name: importlib.metadata.version(name) for name in
                                ('torch', 'numpy', 'laya', 'transformers', 'tokenizers')}
        evidence['versions']['cuda'] = torch.version.cuda
        sys.path.insert(0, str(ROOT / 'tools/basemodel'))
        import train as trainer
        evidence['phase'] = 'runtime_controls'
        evidence['runtime_settings'] = runtime(torch, trainer, evidence['cases'])
        evidence['phase'] = 'loss_semantics'
        semantics(torch, trainer, evidence['cases'])
        evidence['phase'] = 'head_hash'
        head_hash(torch, trainer, evidence['cases'])
        evidence['phase'] = 'final_cpu_guard'
        require(not torch.cuda.is_initialized() and not torch.cuda.is_available())
        evidence['phase'] = 'complete'
        success = True
    except Exception:
        # Fixed failure only: never serialize exception text or tensors.
        pass
    evidence['count'] = len(evidence['cases'])
    if success:
        evidence.update(status='PASS', failure=None)
    evidence.setdefault('runtime_settings', None)
    encoded = json.dumps(evidence, sort_keys=True, allow_nan=False) + '\n'
    require(len(encoded) < 16384)
    print(encoded, end='', flush=True)
    path = Path(args.evidence)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(encoded)
    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
