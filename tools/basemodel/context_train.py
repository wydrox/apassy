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


SOURCE_FILES = ('context_v1.py', 'context_data.py', 'context_train.py', 'context_eval.py', 'train.py', 'common.py')
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
        if len(items) < 8:
            raise Unsupported('probe timing coverage')
        started, result = time.monotonic(), {}
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
                    del h
                ordered = sorted(samples)
                result[str(size)] = dict(samples=len(samples), p50_seconds=ordered[len(ordered)//2],
                                        p95_seconds=ordered[math.ceil(.95*len(ordered))-1])
        result['seconds'] = time.monotonic() - started
        return result


def verify_freeze(freeze_path, c, expect_freeze_sha256):
    """All source, configuration and artifact checks precede any held-out IO."""
    if not expect_freeze_sha256 or sha256(freeze_path) != expect_freeze_sha256:
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
    expected = dict(epochs=4, lr=.0003, wd=.01, warmup=100, threads=4, seed=7, max_steps=0, seconds_per_head=5400)
    if any(cfg.get(k) != v for k, v in expected.items()) or not 1 <= cfg['batch'] <= 64:
        raise Unsupported('full configuration differs')
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
    return frozen


def evaluate_frozen(freeze_path, heldout_path, heldout_manifest, base, c,
                    expect_freeze_sha256=None, baseline_binary=None, cost_path=None):
    frozen = verify_freeze(freeze_path, c, expect_freeze_sha256)
    manifest_base, _ = environment(base, c)
    if manifest_base['base'] != frozen['base']:
        raise Unsupported('frozen base differs')
    import common
    from context_eval import gates, fact_clause
    checkpoints = {}
    for which in ('context', 'control'):
        tensors, meta = common.load_checkpoint(frozen[which]['path'])
        if (meta.get('context_contract_sha256') != contract_hash(c) or meta.get('question') != 'owner_accepts_use'
                or meta.get('facts_blind') != (which == 'control')
                or meta.get('tokenizer_sha256') != c['tokenizer']['sha256']
                or meta.get('base_revision') != REVISION
                or meta.get('base_weights_sha256') != frozen['base']['weights_sha256']):
            raise Unsupported('not matching context heads')
        checkpoints[which] = tensors
    # First held-out IO; external freeze identity and all code/pins were checked above.
    manifest = json.loads(Path(heldout_manifest).read_text())
    expected_hash = manifest.get('sha256', manifest.get('file', {}).get('sha256'))
    if expected_hash != sha256(heldout_path):
        raise Unsupported('held-out manifest hash')
    rows = read_rows(heldout_path, c)
    development = read_rows(frozen['train']['path'], c) + read_rows(frozen['val']['path'], c)
    collision = overlap(development, rows)
    if any(collision.values()):
        raise Unsupported('held-out overlap')
    if any(r['label'] == 'allow_ok' and fact_clause(visible_view(r)) for r in rows):
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
        if baseline_binary:
            try:
                from context_replay import baseline_lower_bound
                replay = baseline_lower_bound([visible_view(r) for r in rows], baseline_binary)
                pre_ask = replay['pre_ask']
                if len(pre_ask) != len(rows) or any(type(v) is not bool for v in pre_ask):
                    raise Unsupported('baseline alignment')
                baseline = [not v for v in pre_ask]
            except (Unsupported, OSError, ValueError, KeyError, ImportError, RuntimeError):
                evidence_errors['baseline_shipped'] = 'baseline evidence unavailable'
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
                       baseline_is_lower_bound=True)
        report.update(context_contract_sha256=contract_hash(c), freeze_sha256=expect_freeze_sha256,
                      heldout_sha256=expected_hash, overlap=collision, threshold=frozen['threshold'],
                      evidence_errors=evidence_errors, unlocks_c=False,
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
            validation_scores = scorer.scores(val, facts_blind=which == 'control')
            from context_eval import threshold, probability
            if any((score is None and r['local_rule'] is None and refusal is None)
                   or (score is not None and not probability(score))
                   for r, score, refusal in zip(val, validation_scores, scorer.last_refusals)):
                raise Unsupported('nonfinite validation scores')
            fitting = [(r, score) for r, score in zip(val, validation_scores)
                       if probability(score) and r['local_rule'] is None]
            thresholds[which] = threshold([r for r, _ in fitting], [score for _, score in fitting])
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
            # Deliberately conservative: batch-1 p95, both encodings, eight training passes,
            # cache I/O, validation/inference and observed end-to-end training cost.
            rows_per_group = len(read_rows(train_path, c)) / data_manifest['groups']
            full_rows = rows_per_group * 1000  # 800 train + 200 val groups
            encoder_cache = full_rows * 2 * timings['1']['p95_seconds']
            observed = sum(v['seconds'] for v in summaries.values()) / max(1, len(training))
            head_cache_io = full_rows * 8 * observed
            inference = full_rows * 3 * timings['1']['p95_seconds']
            report.update(encoder_timings=timings, projected_full_seconds=encoder_cache + head_cache_io + inference,
                          projection_components=dict(encoder_cache_seconds=encoder_cache,
                              training_cache_io_seconds=head_cache_io, inference_seconds=inference),
                          projection_groups=800, projection_epochs=4, projection_heads=2)
        (out / 'freeze.json').write_bytes(canonical(frozen))
        report.update(training_completed=True, reason='training_only_no_heldout_opened', freeze_sha256=sha256(out / 'freeze.json'),
                      threshold=tau, control_threshold=thresholds['control'], validation={'total': len(val), 'fitting_scored': len(fitting)}, training=summaries)
    except (Unsupported, OSError, ValueError, KeyError, ImportError, RuntimeError) as e:
        report['reason'] = str(e) if isinstance(e, Unsupported) else type(e).__name__
    finally:
        if cache is not None:
            cache.close()
    (out / 'training-report.json').write_bytes(canonical(report))
    print(json.dumps(report))
    return 3


if __name__ == '__main__':
    raise SystemExit(main())
