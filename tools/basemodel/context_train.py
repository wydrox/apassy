"""Bounded CPU heads-only experiment. No held-out argument or implicit download.

Outputs are isolated experimental heads, never a replacement for shipped heads.
A disposable, bounded fp16 feature cache is removed in finally. Freeze and threshold are published before any
held-out reader may run in a fresh evaluation process.
"""
import argparse
import copy
import json
import math
import random
import time
import hashlib
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from context_v1 import (CONTRACT, REVISION, Unsupported, Refusal, canonical, contract_hash,
                        load_contract, measure, serialize, sha256, blind, visible_view)
from context_data import read_rows, overlap


def environment(base, c):
    from importlib.metadata import version
    if version('laya') != '0.3.20':
        raise Unsupported('Laya version')
    import common
    manifest = json.loads((Path(__file__).parent / 'manifest.json').read_text())
    if (manifest['base']['revision'] != REVISION or manifest['base']['repo'] != c['base']['repo']
            or manifest['base']['package'] != 'laya[serve]==0.3.20'
            or sha256(Path(base) / manifest['base']['weights_file']) != manifest['base']['weights_sha256']):
        raise Unsupported('base weights manifest pin')
    proposed, measurement = measure(base, c)
    if c['budget']['header_tokens'] is None or proposed['budget']['header_tokens'] > c['budget']['header_tokens'] or proposed['budget']['segment_tokens'] != c['budget']['segment_tokens']:
        raise Unsupported('unmeasured or mismatched contract budget')
    from context_eval import golden_check
    measurement['golden_fixtures'] = golden_check(c)
    return manifest, measurement


SOURCE_FILES = ('context_v1.py', 'context_data.py', 'context_train.py', 'context_eval.py', 'train.py', 'common.py',
                'context_train_rows.py', 'context_existing_freeze.py')
CACHE_BYTES = 6 * 1024**3


def source_identity():
    here = Path(__file__).resolve().parent
    names = SOURCE_FILES + (('context_replay.py',) if (here / 'context_replay.py').exists() else ())
    return {name: sha256(here / name) for name in names}


def package_versions():
    from importlib.metadata import version
    return {name: version(name) for name in ('laya', 'torch', 'transformers', 'tokenizers')}


def source_commit():
    return subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=Path(__file__).parent, text=True).strip()


def install_training_audit():
    """Process-local, irreversible guard; call only from the training CLI."""
    def guard(event, args):
        if event == 'open' and isinstance(args[0], (str, bytes, os.PathLike)):
            path = os.fsdecode(args[0]).lower()
            if 'secret-context-heldout' in path or 'secret_context_heldout' in path:
                raise Unsupported('training refuses held-out access')
    sys.addaudithook(guard)


def timing_summary(samples):
    if len(samples) < 3 or any(type(v) not in (int, float) or not math.isfinite(v) or v <= 0 for v in samples):
        raise Unsupported('invalid cached timing measurement')
    ordered = sorted(samples)
    return dict(samples=len(samples), p50_seconds=ordered[len(ordered)//2],
                p95_seconds=ordered[math.ceil(.95*len(ordered))-1])


def measure_cached_steps(step, deadline, clock=time.monotonic, warmups=2, samples=3):
    """Warm-ups consume the deadline but never enter the measured distribution."""
    if warmups < 1 or samples < 3:
        raise Unsupported('cached timing sample coverage')
    values = []
    for i in range(warmups + samples):
        deadline()
        tick = clock()
        step()
        elapsed = clock() - tick
        deadline()
        if i >= warmups:
            values.append(elapsed)
    return timing_summary(values)


def g1_workload_counts(c, seed):
    """Exact serialized cache identities, no tokenizer/encoder and no held-out.

    G1 generation is prefix-stable in its group index. Accumulate both arms in
    one set, as FeatureCache does, then bound *every* candidate after the existing
    g/800 scaling. Never assume unique-text counts scale linearly with groups.
    """
    from context_data import generate
    splits = {}
    for split, groups in (('train', 800), ('val', 200)):
        buckets = [[] for _ in range(groups)]
        for row in generate(seed, groups, split):
            group = int(row['id'].split(':')[3])
            buckets[group].append(row)
        splits[split] = buckets
    keys, counts, candidates = set(), dict(train=0, val=0), []
    for group in range(800):
        for split in ('train', 'val') if group % 4 == 3 else ('train',):
            index = group if split == 'train' else group // 4
            for row in splits[split][index]:
                counts[split] += 1
                for facts_blind in (False, True):
                    secrets = blind(row['secrets'], c) if facts_blind else row['secrets']
                    try:
                        text, _ = serialize(row['request'], row['action'], secrets, c,
                                            enforce_budget=not facts_blind)
                    except Refusal:
                        continue
                    # Question and immutable cache pins are identical for both
                    # arms. Blind overflows/local rules retained as upper bounds.
                    keys.add(hashlib.sha256(text.encode()).digest())
        g = group + 1
        if g >= 400:
            candidates.append((g, len(keys), counts['train'], counts['val']))
    return dict(train_rows=counts['train'], validation_rows=counts['val'],
                unique_encoder_inputs=len(keys), candidate_groups_min=400, candidate_groups_max=800,
                encoder_inputs_800_equivalent=max(u * 800 / g for g, u, _, _ in candidates),
                training_batches_800_equivalent=max(math.ceil(n / 32) * 800 / g for g, _, n, _ in candidates),
                validation_batches_800_equivalent=max(math.ceil(v / 32) * 800 / g for g, _, _, v in candidates),
                scoring_rows_800_equivalent=max(v * 800 / g for g, _, _, v in candidates),
                provenance='G1_exact_serialized_context_control_union_prefixes_400_to_800')


def project_workload(timings, counts):
    """Seconds, conservative at every selectable group count after g/800 scaling.

    counts describe G1 at exactly 800 train / 200 validation groups. Four epochs
    times two heads = eight train+validation passes; threshold scoring is another
    single-row validation pass per head, with no new encoder work.
    """
    try:
        cached = timings['cached_head']
        if cached.get('method') != 'batch8x4_max_batch32_spot_v1':
            raise Unsupported('cached timing method')
        def positive_float(value):
            if type(value) is not float or not math.isfinite(value) or value <= 0:
                raise Unsupported('invalid budget measurement')
            return value
        def exact(value, expected):
            if type(value) is not type(expected) or value != expected:
                raise Unsupported('cached timing provenance')
        for key, value in dict(projection_batch_size=32, sequence_length=512,
                unit='seconds_per_batch', warmups=2, encoder_in_measured_step=False,
                provenance='frozen_fp16_disk_cache_fp32_head_logits_adamw',
                includes='cache_lookup_collate_forward_loss_backward_clip_optimizer; validation=loss; scoring=softmax').items():
            exact(cached[key], value)
        if ('batch_size' in cached or type(cached['threads']) is not int
                or not 1 <= cached['threads'] <= 4 or positive_float(cached['seconds']) > 120):
            raise Unsupported('cached timing provenance')
        def p95(record, batch=None):
            a, b = record['p50_seconds'], record['p95_seconds']
            if batch is not None:
                exact(record['samples'], 3)
                exact(record['batch_size'], batch)
                positive_float(a)
                positive_float(b)
            if (record['samples'] < 3 or any(type(v) not in (int, float) or not math.isfinite(v) or v <= 0 for v in (a, b)) or b < a):
                raise Unsupported('invalid budget measurement')
            return b
        def derived(value, expected):
            if not math.isclose(positive_float(value), expected, rel_tol=1e-12, abs_tol=0.):
                raise Unsupported('cached timing derived conflict')
        encode = p95(timings['1'])
        cache_write = p95(timings['cache_write'])
        exact(cached['scaled_batch8_to32']['factor'], 4)
        exact(cached['projection_step_seconds']['source'], 'max(scaled_batch8_to32, spot32)')
        steps = {}
        for name in ('training', 'validation'):
            scaled = 4 * p95(cached[name], 8)
            spot = cached['spot32'][name]
            for key, value in dict(batch_size=32, samples=1, warmups=0).items():
                exact(spot[key], value)
            if 'p50_seconds' in spot or 'p95_seconds' in spot:
                raise Unsupported('cached timing spot distribution')
            single = positive_float(spot['single_sample_seconds'])
            derived(cached['scaled_batch8_to32'][name], scaled)
            steps[name] = max(scaled, single)
            derived(cached['projection_step_seconds'][name], steps[name])
            if single > 1.3 * scaled:
                raise Unsupported('batch scaling outside calibrated regime')
        train_step, val_step = steps['training'], steps['validation']
        score_step = p95(cached['scoring'], 1)
        derived(cached['scoring']['p95_seconds_per_row'], score_step)
        n, v = counts['train_rows'], counts['validation_rows']
        if any(type(x) is not int or x <= 0 for x in (n, v)):
            raise Unsupported('budget workload counts')
        equivalents = [counts[k] for k in ('encoder_inputs_800_equivalent', 'training_batches_800_equivalent',
                                           'validation_batches_800_equivalent', 'scoring_rows_800_equivalent')]
        if any(type(x) not in (int, float) or not math.isfinite(x) or x <= 0 for x in equivalents):
            raise Unsupported('budget workload equivalents')
        encoder_n, train_batches, val_batches, scoring_n = equivalents
        # Each normalized workload is independently maximized over 400..800.
        # This sum upper-bounds every candidate after the unchanged g/800 scaling.
        components = dict(encoder_cache_seconds=encoder_n * (encode + cache_write),
                          training_cache_io_seconds=8 * (train_batches * train_step + val_batches * val_step),
                          inference_seconds=2 * scoring_n * score_step)
        if any(not math.isfinite(x) or x <= 0 for x in components.values()):
            raise Unsupported('invalid projected cost')
        return dict(projected_full_seconds=sum(components.values()), projection_components=components,
                    projection_groups=800, projection_epochs=4, projection_heads=2,
                    projection_counts=counts)
    except Unsupported:
        raise
    except (KeyError, TypeError, ValueError, OverflowError, AttributeError) as e:
        raise Unsupported('invalid budget measurement') from e


class FeatureCache:
    """Disposable fp16 features keyed by observable text, question and immutable pins."""
    def __init__(self, limit=CACHE_BYTES):
        self.limit, self.used, self.records = limit, 0, {}
        self.temp = tempfile.TemporaryDirectory(prefix='context-features-', dir=os.environ.get('RUNNER_TEMP'))

    def close(self):
        self.records.clear()
        self.temp.cleanup()

    def put(self, key, tensor, torch):
        if key in self.records:
            return
        value = tensor.detach().cpu().half().contiguous()
        # Reserve serialization overhead before writing, then account actual file bytes.
        reserve = value.numel() * 2 + 65536
        if self.used + reserve > self.limit:
            raise Unsupported('feature cache exceeds 6 GiB')
        path = Path(self.temp.name) / (key + '.pt')
        torch.save(value, path)
        size = path.stat().st_size
        if self.used + size > self.limit:
            path.unlink()
            raise Unsupported('feature cache exceeds 6 GiB')
        self.records[key] = path
        self.used += size

    def get(self, key, torch):
        return torch.load(self.records[key], map_location='cpu', weights_only=True)


class Scorer:
    def __init__(self, base, c, threads=2, cache=None):
        import torch
        import common
        from laya.agent import Agent
        torch.set_num_threads(threads)
        self.torch, self.c, self.cache = torch, c, cache
        self.cache_pins = dict(contract=contract_hash(c), base=REVISION, tokenizer=c['tokenizer']['sha256'],
                               base_weights=json.loads((Path(__file__).parent / 'manifest.json').read_text())['base']['weights_sha256'])
        self.agent = Agent(str(base), device='cpu')
        self.model = self.agent.model
        self.model.eval()
        self.temperature = common.noul_temperature(self.agent)
        self.pad = self.agent.tok.pad_token_id
        self.question = Agent._to_internal({k: v for k, v in c['question'].items() if k != 'id'})

    def item(self, row, facts_blind=False, reinforced=False):
        secrets = copy.deepcopy(row['secrets'])
        if facts_blind:
            secrets = blind(secrets, self.c)
        if reinforced:
            for s in secrets:
                s['agent_used'] = 'yes'
        text, _ = serialize(row['request'], row['action'], secrets, self.c, enforce_budget=not facts_blind)
        from laya.common import serialize_state
        if serialize_state(text) != text:
            raise Unsupported('state serialization changed')
        # Refuse before Laya's encoder can silently truncate.
        token_count = len(self.agent.tok(text.replace(self.agent.tok.mask_token, ' '), add_special_tokens=False)['input_ids'])
        if token_count + self.c['budget']['header_tokens'] > 512:
            raise Refusal('ExactOverflow')
        it = self.agent._encode_state(text, ['q'], {'q': self.question})[0]
        if len(it['ids']) != token_count + self.c['budget']['header_tokens']:
            raise Unsupported('encoded sequence truncation or formatter mismatch')
        return dict(ids=it['ids'], markers=it['markers'], qtype=it['qtype'],
                    y=float(row.get('label') == 'allow_ok'), q=0, teacher=False,
                    cache_key=hashlib.sha256(canonical(dict(text=text, question=self.c['question'], pins=self.cache_pins))).hexdigest())

    def features(self, items, b):
        import train
        torch = self.torch
        if self.cache is None:
            return train.encoder_states(self.model, b, torch.device('cpu'), False)
        missing = [it for it in items if it['cache_key'] not in self.cache.records]
        if missing:
            mb = train.collate(missing, self.pad)
            h = train.encoder_states(self.model, mb, torch.device('cpu'), False)
            for i, it in enumerate(missing):
                self.cache.put(it['cache_key'], h[i, :len(it['ids'])], torch)
            del h
        h = torch.zeros((len(items), b['input_ids'].shape[1], self.model.type_emb.weight.shape[1]))
        for i, it in enumerate(items):
            h[i, :len(it['ids'])] = self.cache.get(it['cache_key'], torch).float()
        return h

    def scores(self, rows, facts_blind=False, reinforced=False):
        import train
        out, self.last_overflow, self.last_refusals = [], [], []
        self.model.eval()
        with self.torch.no_grad():
            for row in rows:
                if row['local_rule'] is not None:
                    out.append(None)
                    self.last_overflow.append(False)
                    self.last_refusals.append('LocalRule')
                    continue
                try:
                    it = self.item(row, facts_blind, reinforced)
                except Refusal as e:
                    out.append(None)
                    self.last_overflow.append(e.code == 'ExactOverflow')
                    self.last_refusals.append(e.code)
                    continue
                self.last_overflow.append(False)
                self.last_refusals.append(None)
                b = train.collate([it], self.pad)
                try:
                    h = self.features([it], b)
                    p = self.torch.softmax(train.head_logits(self.model, h, b, 'cpu') / self.temperature, -1)[0, 1]
                    out.append(float(p))
                except RuntimeError:
                    # A model outage is an unavailable score, never a budget refusal.
                    out.append(None)
        return out

    def train(self, rows, epochs, max_steps, batch, lr, seed, seconds, facts_blind=False,
              val=None, wd=.01, warmup=100):
        import common
        import train
        import torch.nn.functional as F
        torch = self.torch
        torch.manual_seed(seed)
        rng = random.Random(seed)
        for p in self.model.parameters():
            p.requires_grad_(False)
        params = [p for n, p in self.model.named_parameters() if n.startswith(common.TRAINED_PREFIXES)]
        for p in params:
            p.requires_grad_(True)
        items, validation, refused = [], [], 0
        for source, target in ((rows, items), (val or [], validation)):
            for row in source:
                if row['local_rule'] is not None:
                    continue
                try:
                    target.append(self.item(row, facts_blind))
                except Refusal:
                    refused += 1
        if not items or not validation or len({it['y'] for it in items}) != 2:
            raise Unsupported('training/validation coverage/labels')
        optimizer = torch.optim.AdamW(params, lr=lr, weight_decay=wd)
        total = epochs * math.ceil(len(items) / batch)
        if max_steps:
            total = min(total, max_steps)
        started, step, loss_total = time.monotonic(), 0, 0.
        best, best_state, best_epoch = math.inf, None, None
        def deadline():
            if time.monotonic() - started > seconds:
                raise Unsupported('training wall limit reached')
        for epoch in range(epochs):
            self.model.eval()
            self.model.head.train()
            for ix in train.batches(items, batch, rng, True):
                deadline()
                selected = [items[i] for i in ix]
                b = train.collate(selected, self.pad)
                with torch.no_grad():
                    h = self.features(selected, b)
                deadline()
                rate = lr * ((step + 1) / warmup if step < warmup else
                             .5 * (1 + math.cos(math.pi * (step - warmup) / max(1, total - warmup))))
                for group in optimizer.param_groups:
                    group['lr'] = rate
                logits = train.head_logits(self.model, h, b, 'cpu') / self.temperature
                loss = F.cross_entropy(logits, train.targets(b['y']))
                if not torch.isfinite(loss):
                    raise Unsupported('nonfinite loss')
                optimizer.zero_grad(set_to_none=True)
                loss.backward()
                torch.nn.utils.clip_grad_norm_(params, 1.)
                optimizer.step()
                step += 1
                loss_total += float(loss.detach())
                if max_steps and step >= max_steps:
                    break
            self.model.eval()
            val_loss = 0.
            with torch.no_grad():
                for ix in train.batches(validation, batch, rng, False):
                    deadline()
                    selected = [validation[i] for i in ix]
                    b = train.collate(selected, self.pad)
                    h = self.features(selected, b)
                    loss = F.cross_entropy(train.head_logits(self.model, h, b, 'cpu') / self.temperature,
                                           train.targets(b['y']))
                    if not torch.isfinite(loss):
                        raise Unsupported('nonfinite validation loss')
                    val_loss += float(loss) * len(ix)
                    deadline()
            val_loss /= len(validation)
            if val_loss < best:
                best, best_epoch = val_loss, epoch + 1
                best_state = {k: v.detach().clone() for k, v in common.head_state(self.model).items()}
            if max_steps and step >= max_steps:
                break
        common.apply_heads(self.model, best_state)
        return dict(steps=step, rows=len(items), refused=refused, seconds=time.monotonic() - started,
                    mean_loss=loss_total / step, best_validation_loss=best, best_epoch=best_epoch,
                    trainable_parameters=sum(p.numel() for p in params))

    def probe_timings(self, rows, seconds=120):
        """Bounded encoder-only measurements; no cache hits are timed as inference."""
        import train
        items = []
        for row in rows:
            if row['local_rule'] is None:
                try:
                    items.append(self.item(row))
                except Refusal:
                    pass
            if len(items) == 32:
                break
        if len(items) != 32:
            raise Unsupported('probe timing coverage')
        original_cache = self.cache
        self.cache = FeatureCache()
        try:
            started, result = time.monotonic(), {}
            cache_writes = []
            with self.torch.no_grad():
                for size in (1, 8):
                    samples = []
                    for offset in range(0, len(items), size):
                        if time.monotonic() - started > seconds:
                            raise Unsupported('probe timing wall limit')
                        chosen = items[offset:offset + size]
                        b = train.collate(chosen, self.pad)
                        tick = time.monotonic()
                        h = train.encoder_states(self.model, b, self.torch.device('cpu'), False)
                        samples.append((time.monotonic() - tick) / len(chosen))
                        if time.monotonic() - started > seconds:
                            raise Unsupported('probe timing wall limit')
                        if size == 8 and self.cache is not None:
                            tick = time.monotonic()
                            for i, it in enumerate(chosen):
                                self.cache.put(it['cache_key'], h[i, :len(it['ids'])], self.torch)
                            cache_writes.append((time.monotonic() - tick) / len(chosen))
                        del h
                    ordered = sorted(samples)
                    result[str(size)] = dict(samples=len(samples), p50_seconds=ordered[len(ordered)//2],
                                            p95_seconds=ordered[math.ceil(.95*len(ordered))-1])
            if time.monotonic() - started > seconds:
                raise Unsupported('probe timing wall limit')
            result['cache_write'] = dict(timing_summary(cache_writes), unit='seconds_per_row',
                                         provenance='fp16_feature_cache_serialization_disk_write')
            result['seconds'] = time.monotonic() - started
            result['cached_head'] = self.cached_head_timings(items)
            return result
        finally:
            try:
                self.cache.close()
            finally:
                self.cache = original_cache

    def _cached_head_step(self, items, optimizer, params, training, scoring=False):
        """Same FP32 head path and disk-cache IO as train/scores; never fill cache."""
        import train
        import torch.nn.functional as F
        torch = self.torch
        if self.cache is None or any(it['cache_key'] not in self.cache.records for it in items):
            raise Unsupported('cached timing requires precomputed features')
        self.model.eval()
        if training:
            self.model.head.train()
        with torch.set_grad_enabled(training):
            b = train.collate(items, self.pad)
            # Maximum supported shape is conservative for all G1 lengths. Preserve
            # the real attention mask and markers while expanding padding only.
            pad = 512 - b['input_ids'].shape[1]
            b['input_ids'] = F.pad(b['input_ids'], (0, pad), value=self.pad)
            b['attention_mask'] = F.pad(b['attention_mask'], (0, pad))
            with torch.no_grad():
                h = self.features(items, b)
            logits = train.head_logits(self.model, h, b, 'cpu') / self.temperature
            if scoring:
                value = float(torch.softmax(logits, -1)[0, 1])
                if not math.isfinite(value):
                    raise Unsupported('nonfinite cached scoring')
            else:
                loss = F.cross_entropy(logits, train.targets(b['y']))
                if not torch.isfinite(loss):
                    raise Unsupported('nonfinite cached loss')
                if training:
                    optimizer.zero_grad(set_to_none=True)
                    loss.backward()
                    torch.nn.utils.clip_grad_norm_(params, 1.)
                    optimizer.step()
                float(loss.detach())

    def cached_head_timings(self, items, seconds=120):
        """Calibration only; restore weights, gradients, modes and CPU/Python RNG.

        Cache must already contain frozen encoder outputs from probe_timings.
        The deadline covers setup, warm-ups and all measured head operations.
        """
        import common
        torch = self.torch
        if not 0 < seconds <= 120 or len(items) != 32:
            raise Unsupported('cached timing bounds/coverage')
        started = time.monotonic()
        def deadline():
            if time.monotonic() - started > seconds:
                raise Unsupported('cached timing wall limit')
        phase, completed_calls = 'setup', 0
        weights, flags, modes = [], [], []
        rng = py_rng = None
        # Clear diagnostics from any previous attempt; never expose partial timings.
        self.diagnostics = {}
        try:
            try:
                rng, py_rng = torch.get_rng_state(), random.getstate()
                named = list(self.model.named_parameters())
                params = [p for n, p in named if n.startswith(common.TRAINED_PREFIXES)]
                modes = [(m, m.training) for m in self.model.modules()]
                flags = [(p, p.requires_grad, p.grad) for _, p in named]
                weights = [(p, p.detach().clone()) for p in params]
                deadline()
                if not params or any(p.dtype != torch.float32 for p in params):
                    raise Unsupported('cached timing requires FP32 heads')
                for _, p in named:
                    p.requires_grad_(False)
                    p.grad = None
                for p in params:
                    p.requires_grad_(True)
                optimizer = torch.optim.AdamW(params, lr=.0003, weight_decay=.01)
                result = dict(method='batch8x4_max_batch32_spot_v1', projection_batch_size=32,
                              sequence_length=512, unit='seconds_per_batch',
                              warmups=2, encoder_in_measured_step=False,
                              provenance='frozen_fp16_disk_cache_fp32_head_logits_adamw',
                              includes='cache_lookup_collate_forward_loss_backward_clip_optimizer; validation=loss; scoring=softmax',
                              threads=torch.get_num_threads())
                deadline()
                for name, training, chosen, scoring in (
                        ('training', True, items[:8], False), ('validation', False, items[:8], False),
                        ('scoring', False, items[:1], True),
                        ('spot32.training', True, items, False), ('spot32.validation', False, items, False)):
                    phase = dict(training='training8', validation='validation8', scoring='scoring1').get(name, name)
                    def step():
                        nonlocal completed_calls
                        self._cached_head_step(chosen, optimizer, params, training, scoring)
                        completed_calls += 1
                    if name.startswith('spot32.'):
                        deadline()
                        tick = time.monotonic()
                        step()
                        elapsed = time.monotonic() - tick
                        deadline()
                        if type(elapsed) is not float or not math.isfinite(elapsed) or elapsed <= 0:
                            raise Unsupported('invalid cached timing measurement')
                        result.setdefault('spot32', {})[name.split('.')[1]] = dict(
                            batch_size=32, samples=1, warmups=0, single_sample_seconds=elapsed)
                    else:
                        result[name] = dict(measure_cached_steps(step, deadline, clock=time.monotonic),
                                            batch_size=len(chosen))
                        if scoring:
                            result[name]['p95_seconds_per_row'] = result[name]['p95_seconds']
                result['scaled_batch8_to32'] = dict(factor=4, **{
                    name: 4 * result[name]['p95_seconds'] for name in ('training', 'validation')})
                result['projection_step_seconds'] = dict(source='max(scaled_batch8_to32, spot32)', **{
                    name: max(result['scaled_batch8_to32'][name], result['spot32'][name]['single_sample_seconds'])
                    for name in ('training', 'validation')})
                deadline()
            finally:
                primary = sys.exc_info()[0] is not None
                if not primary:
                    phase = 'restore'
                try:
                    with torch.no_grad():
                        for p, value in weights:
                            p.copy_(value)
                    for p, flag, grad in flags:
                        p.requires_grad_(flag)
                        p.grad = grad
                    for module, mode in modes:
                        module.training = mode
                    if rng is not None:
                        torch.set_rng_state(rng)
                    if py_rng is not None:
                        random.setstate(py_rng)
                except BaseException:
                    if not primary:
                        raise
                if not primary:
                    deadline()
            result['seconds'] = time.monotonic() - started
            if result['seconds'] > seconds:
                raise Unsupported('cached timing wall limit')
            return result
        except BaseException:
            self.diagnostics['cached_head_partial'] = dict(phase=phase, completed_calls=completed_calls,
                elapsed_seconds=time.monotonic() - started, eligibility=False)
            raise


def context_meta_ok(meta, which, c, weights_sha):
    """Shared checkpoint pin predicate for existing training and evaluation."""
    if which not in ('context', 'control'):
        raise Unsupported('unknown context arm')
    return (meta.get('context_contract_sha256') == contract_hash(c)
            and meta.get('question') == 'owner_accepts_use'
            and meta.get('facts_blind') == (which == 'control')
            and meta.get('tokenizer_sha256') == c['tokenizer']['sha256']
            and meta.get('base_revision') == REVISION
            and meta.get('base_weights_sha256') == weights_sha)


def fit_threshold(scorer, val, which):
    """Fit on validation only with the existing refusal/nonfinite policy."""
    if which not in ('context', 'control'):
        raise Unsupported('unknown context arm')
    validation_scores = scorer.scores(val, facts_blind=which == 'control')
    from context_eval import threshold, probability
    if any((score is None and r['local_rule'] is None and refusal is None)
           or (score is not None and not probability(score))
           for r, score, refusal in zip(val, validation_scores, scorer.last_refusals)):
        raise Unsupported('nonfinite validation scores')
    fitting = [(r, score) for r, score in zip(val, validation_scores)
               if probability(score) and r['local_rule'] is None]
    return threshold([r for r, _ in fitting], [score for _, score in fitting]), len(fitting)


def verify_freeze(freeze_path, c, expect_freeze_sha256):
    """All source, configuration and artifact checks precede any held-out IO."""
    from context_train_rows import safe_path
    if not expect_freeze_sha256:
        raise Unsupported('external freeze SHA required/mismatch')
    safe_path(freeze_path)
    if sha256(freeze_path) != expect_freeze_sha256:
        raise Unsupported('external freeze SHA required/mismatch')
    frozen = json.loads(Path(freeze_path).read_text())
    if frozen.get('mode') != 'full' or frozen.get('config', {}).get('mode') != 'full':
        raise Unsupported('only full freezes may evaluate')
    if (frozen['context_contract_sha256'] != contract_hash(c)
            or frozen['tokenizer_sha256'] != c['tokenizer']['sha256']
            or frozen['base']['revision'] != REVISION):
        raise Unsupported('frozen pins differ')
    if frozen.get('source_hashes') != source_identity() or frozen.get('source_commit') != source_commit():
        raise Unsupported('frozen source differs')
    if frozen.get('package_versions') != package_versions():
        raise Unsupported('frozen package versions differ')
    cfg = frozen['config']
    if 'trainer' in cfg and cfg['trainer'] != 'train.py':
        raise Unsupported('unknown frozen trainer')
    if cfg.get('trainer') == 'train.py':
        if (cfg.get('amp') is not False or cfg.get('batch') != 32
                or cfg.get('limit') != 0 or cfg.get('max_steps') != 0
                or any(cfg.get(k) for k in ('init', 'lora', 'lora_layers', 'lora_rank',
                                            'lora_alpha', 'teacher_rows'))):
            raise Unsupported('existing trainer configuration differs')
    expected = dict(epochs=4, lr=.0003, wd=.01, warmup=100, threads=4, seed=7, max_steps=0, seconds_per_head=5400)
    if any(cfg.get(k) != v for k, v in expected.items()) or not 1 <= cfg['batch'] <= 64:
        raise Unsupported('full configuration differs')
    # Validate the entire path set before hashing even the first artifact.
    for name in ('train', 'val', 'context', 'control', 'data_manifest'):
        safe_path(frozen[name]['path'])
    if cfg.get('trainer') == 'train.py':
        for which in ('context', 'control'):
            safe_path(frozen['training_reports'][which]['path'])
    for name in ('train', 'val', 'context', 'control', 'data_manifest'):
        record = frozen[name]
        if sha256(record['path']) != record['sha256']:
            raise Unsupported('freeze artifact changed')
    data_manifest = json.loads(Path(frozen['data_manifest']['path']).read_text())
    if not 400 <= data_manifest['groups'] <= 800:
        raise Unsupported('full data groups')
    for name in ('train', 'val'):
        entry = data_manifest['files'][name + '.jsonl']
        if entry['sha256'] != frozen[name]['sha256'] or (cfg['limit'] and cfg['limit'] < entry['rows']):
            raise Unsupported('full data truncated/mismatched')
    for name in ('threshold', 'control_threshold'):
        if not math.isfinite(frozen[name]) or not 0 <= frozen[name] <= math.nextafter(1., math.inf):
            raise Unsupported('frozen threshold')
    if cfg.get('trainer') == 'train.py':
        from context_existing_freeze import verify_conversion
        verify_conversion(frozen, c)
    return frozen


def heldout_overlap(development, rows):
    """Programs may generalize; families and identical request/command pairs may not."""
    collision = overlap(development, rows)
    if collision.get('shared_families', 0) or collision.get('shared_request_command_pairs', 0):
        raise Unsupported('held-out overlap')
    return collision


def evaluate_frozen(freeze_path, heldout_path, heldout_manifest, base, c,
                    expect_freeze_sha256=None, baseline_binary=None, cost_path=None, shipped_heads=None):
    frozen = verify_freeze(freeze_path, c, expect_freeze_sha256)
    shipped_sha = None
    if shipped_heads is not None:
        # Explicit pins fail closed before the first held-out IO (or model setup).
        try:
            from context_train_rows import safe_path
            from context_replay import SHIPPED_SHA
            shipped_heads = safe_path(shipped_heads)
            if not shipped_heads.is_file():
                raise Unsupported('shipped_heads_pin')
            shipped_sha = sha256(shipped_heads)
            shipped_manifest = json.loads((Path(__file__).parent / 'manifest.json').read_text())
            if shipped_sha != SHIPPED_SHA or SHIPPED_SHA != shipped_manifest['checkpoint']['sha256']:
                raise Unsupported('shipped_heads_pin')
        except (Unsupported, OSError, ValueError, KeyError, TypeError, ImportError):
            raise Unsupported('shipped_heads_pin') from None
    manifest_base, _ = environment(base, c)
    if manifest_base['base'] != frozen['base']:
        raise Unsupported('frozen base differs')
    import common
    from context_eval import gates, invalid_allow_label
    checkpoints = {}
    for which in ('context', 'control'):
        tensors, meta = common.load_checkpoint(frozen[which]['path'])
        if not context_meta_ok(meta, which, c, frozen['base']['weights_sha256']):
            raise Unsupported('not matching context heads')
        checkpoints[which] = tensors
    # First held-out IO; external freeze identity and all code/pins were checked above.
    manifest = json.loads(Path(heldout_manifest).read_text())
    expected_hash = manifest.get('sha256', manifest.get('file', {}).get('sha256'))
    if expected_hash != sha256(heldout_path):
        raise Unsupported('held-out manifest hash')
    rows = read_rows(heldout_path, c)
    development = read_rows(frozen['train']['path'], c) + read_rows(frozen['val']['path'], c)
    collision = heldout_overlap(development, rows)
    if any(r['label'] == 'allow_ok' and invalid_allow_label(visible_view(r)) for r in rows):
        raise Unsupported('label_audit')
    cache = FeatureCache()
    try:
        scorer = Scorer(base, c, frozen['config']['threads'], cache=cache)
        for which in ('context', 'control'):
            tensors = checkpoints[which]
            common.apply_heads(scorer.model, tensors)
            if which == 'context':
                scores = scorer.scores(rows)
                reinforced = scorer.scores(rows, reinforced=True)
            else:
                control = scorer.scores(rows, facts_blind=True)
                control_overflow = scorer.last_overflow[:]
        fits = []
        for row in rows:
            try:
                serialize(row['request'], row['action'], row['secrets'], c)
                fits.append(True)
            except Refusal:
                fits.append(False)
        # Compute quality first: absent or invalid optional evidence cannot erase measured FAIL.
        report = gates(rows, scores, control, reinforced, fits, frozen['threshold'],
                       control_tau=frozen['control_threshold'], control_overflow=control_overflow)
        baseline, cost, evidence_errors = None, None, {}
        baseline_is_lower_bound = True
        baseline_evidence = dict(provenance='lower_bound', status='UNSUPPORTED', heads_sha256=None)
        if baseline_binary:
            try:
                from context_replay import baseline_lower_bound
                replay = baseline_lower_bound([visible_view(r) for r in rows], baseline_binary)
                pre_ask = replay['pre_ask']
                if len(pre_ask) != len(rows) or any(type(v) is not bool for v in pre_ask):
                    raise Unsupported('baseline alignment')
                baseline = [not v for v in pre_ask]
                baseline_evidence['status'] = 'MEASURED'
            except (Unsupported, OSError, ValueError, KeyError, TypeError, ImportError, RuntimeError):
                evidence_errors['baseline_shipped'] = 'baseline evidence unavailable'
        if shipped_heads is not None:
            baseline_evidence['shipped_attempt'] = dict(status='UNSUPPORTED', heads_sha256=shipped_sha)
            try:
                if not baseline_binary:
                    raise Unsupported('baseline binary unavailable')
                from context_replay import baseline_with_heads
                replay = baseline_with_heads([visible_view(r) for r in rows], baseline_binary,
                                             base, shipped_heads=shipped_heads, threads=4)
                if (not isinstance(replay, dict) or replay.get('status') != 'MEASURED'
                        or replay.get('heads_sha256') != shipped_sha
                        or type(replay.get('ask')) is not list
                        or len(replay['ask']) != len(rows)
                        or any(type(v) is not bool for v in replay['ask'])):
                    raise Unsupported('shipped baseline alignment')
                baseline = [not v for v in replay['ask']]
                baseline_is_lower_bound = False
                baseline_evidence.update(provenance='shipped', status='MEASURED', heads_sha256=shipped_sha,
                                         shipped_attempt=dict(status='MEASURED', heads_sha256=shipped_sha))
                evidence_errors.pop('baseline_shipped', None)
            except (Unsupported, OSError, ValueError, KeyError, TypeError, ImportError, RuntimeError):
                evidence_errors['baseline_shipped'] = 'shipped baseline evidence unavailable'
        if cost_path:
            try:
                from context_eval import validate_cost_evidence
                cost = json.loads(Path(cost_path).read_text())
                validate_cost_evidence(cost, frozen, c)
            except (Unsupported, OSError, ValueError, KeyError, TypeError):
                cost = None
                evidence_errors['cost'] = 'cost evidence unavailable'
        report = gates(rows, scores, control, reinforced, fits, frozen['threshold'], baseline=baseline,
                       cost=cost, control_tau=frozen['control_threshold'], control_overflow=control_overflow,
                       baseline_is_lower_bound=baseline_is_lower_bound)
        report.update(context_contract_sha256=contract_hash(c), freeze_sha256=expect_freeze_sha256,
                      heldout_sha256=expected_hash, overlap=collision, threshold=frozen['threshold'],
                      evidence_errors=evidence_errors, baseline_evidence=baseline_evidence, unlocks_c=False,
                      quality_scope='feasibility quality only; C/D/E require B and supervisor review')
        return report
    finally:
        cache.close()


def main(argv=None):
    install_training_audit()
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--data', required=True)
    p.add_argument('--out', required=True, help='New isolated directory; contains freeze.json')
    p.add_argument('--base-dir', required=True)
    p.add_argument('--contract', default=str(CONTRACT))
    p.add_argument('--mode', choices=['probe', 'full'], default='probe')
    p.add_argument('--limit', type=int, default=0)
    p.add_argument('--epochs', type=int, default=4)
    p.add_argument('--max-steps', type=int, default=0)
    p.add_argument('--batch', type=int, default=32)
    p.add_argument('--threads', type=int, default=4)
    p.add_argument('--seconds-per-head', type=int, default=5400)
    p.add_argument('--lr', type=float, default=.0003)
    p.add_argument('--seed', type=int, default=7)
    p.add_argument('--wd', type=float, default=.01)
    p.add_argument('--warmup', type=int, default=100)
    p.add_argument('--probe-report')
    a = p.parse_args(argv)
    if not (1 <= a.epochs <= 8 and 0 <= a.max_steps <= 10000 and 1 <= a.batch <= 64 and
            1 <= a.threads <= 4 and 0 <= a.limit <= 20000 and 1 <= a.seconds_per_head <= 14400 and 0 < a.lr <= .01 and a.wd == .01 and a.warmup == 100):
        p.error('finite resource bounds exceeded')
    out = Path(a.out).resolve()
    if 'target' in out.parts:
        p.error('output must be outside target')
    out.mkdir(parents=True, exist_ok=False)
    report = {'outcome': 'UNSUPPORTED', 'mode': a.mode}
    cache = None
    scorer = None
    try:
        c = load_contract(a.contract)
        manifest, measurement = environment(a.base_dir, c)
        train_path = (Path(a.data) / 'train.jsonl').resolve()
        val_path = (Path(a.data) / 'val.jsonl').resolve()
        training, val = read_rows(train_path, c), read_rows(val_path, c)
        if (any(not r['family'].startswith('G1:') for r in training + val)
                or any(overlap(training, val).values())):
            raise Unsupported('development split/family')
        data_manifest_path = (Path(a.data) / 'data-manifest.json').resolve()
        data_manifest = json.loads(data_manifest_path.read_text())
        for path in (train_path, val_path):
            if data_manifest['files'][path.name]['sha256'] != sha256(path):
                raise Unsupported('data manifest mismatch')
        if a.mode == 'full':
            if (a.limit and a.limit < max(len(training), len(val))) or a.max_steps or a.epochs != 4 or a.threads != 4 or a.lr != .0003 or a.seed != 7 or a.seconds_per_head != 5400:
                raise Unsupported('full mode must preserve all rows and reviewed configuration')
            if not a.probe_report:
                raise Unsupported('full mode requires bounded probe report')
            probe = json.loads(Path(a.probe_report).read_text())
            projection = probe['projected_full_seconds']
            groups = data_manifest['groups']
            if not 400 <= groups <= 800 or not math.isfinite(projection) or projection <= 0 or projection * groups / 800 * 1.3 > .6 * 300 * 60:
                raise Unsupported('budget')
        elif a.limit:
            training, val = training[:a.limit], val[:a.limit]
        import torch
        import common
        torch.manual_seed(a.seed)
        random.seed(a.seed)
        cache = FeatureCache()
        scorer = Scorer(a.base_dir, c, a.threads, cache=cache)
        initial = {k: v.clone() for k, v in common.head_state(scorer.model).items()}
        config = {k: v for k, v in vars(a).items() if k not in ('out', 'base_dir', 'contract', 'data')}
        artifacts = {}
        summaries, thresholds = {}, {}
        timings = scorer.probe_timings(val) if a.mode == 'probe' else None
        for which in ('context', 'control'):
            common.apply_heads(scorer.model, initial)
            summaries[which] = scorer.train(training, a.epochs, a.max_steps, a.batch, a.lr, a.seed,
                                            a.seconds_per_head, facts_blind=which == 'control', val=val, wd=a.wd, warmup=a.warmup)
            path = out / (which + '.safetensors')
            common.save_checkpoint(scorer.model, str(path), dict(name='apassy-context-v1',
                context_contract_sha256=contract_hash(c), question='owner_accepts_use',
                tokenizer_sha256=c['tokenizer']['sha256'], base_revision=REVISION,
                base_weights_sha256=manifest['base']['weights_sha256'], facts_blind=which == 'control',
                noul_temperature=scorer.temperature, config=config, training=summaries[which]))
            artifacts[which] = {'path': str(path), 'sha256': sha256(path)}
            thresholds[which], fitting_scored = fit_threshold(scorer, val, which)
        tau = thresholds['context']
        frozen = dict(mode=a.mode, source_commit=source_commit(), source_hashes=source_identity(),
                      package_versions=package_versions(),
                      data_manifest={'path': str(data_manifest_path), 'sha256': sha256(data_manifest_path)},
                      context_contract_sha256=contract_hash(c), tokenizer_sha256=c['tokenizer']['sha256'],
                      base=manifest['base'], config=config, threshold=tau, control_threshold=thresholds['control'],
                      measurement=measurement,
                      train={'path': str(train_path), 'sha256': sha256(train_path)},
                      val={'path': str(val_path), 'sha256': sha256(val_path)}, **artifacts)
        if timings:
            counts = g1_workload_counts(c, a.seed)
            report.update(encoder_timings=timings, **project_workload(timings, counts))
        (out / 'freeze.json').write_bytes(canonical(frozen))
        report.update(training_completed=True, reason='training_only_no_heldout_opened', freeze_sha256=sha256(out / 'freeze.json'),
                      threshold=tau, control_threshold=thresholds['control'], validation={'total': len(val), 'fitting_scored': fitting_scored}, training=summaries)
    except (Unsupported, OSError, ValueError, KeyError, ImportError, RuntimeError) as e:
        report['reason'] = str(e) if isinstance(e, Unsupported) else type(e).__name__
        partial = getattr(scorer, 'diagnostics', {}).get('cached_head_partial')
        if partial is not None:
            report['diagnostics'] = {'cached_head_partial': dict(partial)}
    finally:
        if cache is not None:
            cache.close()
    (out / 'training-report.json').write_bytes(canonical(report))
    print(json.dumps(report))
    return 3


if __name__ == '__main__':
    raise SystemExit(main())
