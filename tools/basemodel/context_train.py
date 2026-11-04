"""Bounded CPU heads-only experiment. No held-out argument or implicit download.

Outputs are isolated experimental heads, never a replacement for shipped heads.
No feature cache is retained. Freeze and threshold are published before any
held-out reader may run in a fresh evaluation process.
"""
import argparse
import copy
import json
import math
import random
import time
from pathlib import Path
from context_v1 import (CONTRACT, REVISION, Unsupported, Refusal, canonical, contract_hash,
                        load_contract, measure, serialize, sha256, blind)
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


class Scorer:
    def __init__(self, base, c, threads=2):
        import torch
        import common
        from laya.agent import Agent
        torch.set_num_threads(threads)
        self.torch, self.c = torch, c
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
        text, _ = serialize(row['request'], row['action'], secrets, self.c)
        from laya.common import serialize_state
        if serialize_state(text) != text:
            raise Unsupported('state serialization changed')
        # Refuse before Laya's encoder can silently truncate.
        token_count = len(self.agent.tok(text.replace(self.agent.tok.mask_token, ' '), add_special_tokens=False)['input_ids'])
        if token_count + self.c['budget']['header_tokens'] > 512:
            raise Unsupported('full input over bound')
        it = self.agent._encode_state(text, ['q'], {'q': self.question})[0]
        if len(it['ids']) != token_count + self.c['budget']['header_tokens']:
            raise Unsupported('encoded sequence truncation or formatter mismatch')
        return dict(ids=it['ids'], markers=it['markers'], qtype=it['qtype'],
                    y=float(row['label'] == 'allow_ok'), q=0, teacher=False)

    def scores(self, rows, facts_blind=False, reinforced=False):
        import train
        out = []
        self.model.eval()
        with self.torch.no_grad():
            for row in rows:
                try:
                    it = self.item(row, facts_blind, reinforced)
                except Refusal:
                    out.append(None)
                    continue
                b = train.collate([it], self.pad)
                h = train.encoder_states(self.model, b, self.torch.device('cpu'), False)
                p = self.torch.softmax(train.head_logits(self.model, h, b, 'cpu') / self.temperature, -1)[0, 1]
                out.append(float(p))
        return out

    def train(self, rows, epochs, max_steps, batch, lr, seed, seconds, facts_blind=False):
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
        items = []
        refused = 0
        for row in rows:
            if row['local_rule']:
                continue
            try:
                items.append(self.item(row, facts_blind))
            except Refusal:
                refused += 1
        if not items or len({it['y'] for it in items}) != 2:
            raise Unsupported('training coverage/labels')
        optimizer = torch.optim.AdamW(params, lr=lr, weight_decay=.01)
        started, step, loss_total = time.monotonic(), 0, 0.
        for _ in range(epochs):
            self.model.eval()
            self.model.head.train()
            for ix in train.batches(items, batch, rng, True):
                if time.monotonic() - started > seconds:
                    raise Unsupported('training wall limit reached')
                b = train.collate([items[i] for i in ix], self.pad)
                with torch.no_grad():
                    h = train.encoder_states(self.model, b, torch.device('cpu'), False)
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
                if step >= max_steps:
                    break
            if step >= max_steps:
                break
        return dict(steps=step, rows=len(items), refused=refused, seconds=time.monotonic() - started,
                    mean_loss=loss_total / step, trainable_parameters=sum(p.numel() for p in params))


def evaluate_frozen(freeze_path, heldout_path, heldout_manifest, base, c):
    """Only called by evaluator phase, never by training or unit-test discovery."""
    import common
    from context_eval import gates
    frozen = json.loads(Path(freeze_path).read_text())
    if frozen['context_contract_sha256'] != contract_hash(c) or frozen['tokenizer_sha256'] != c['tokenizer']['sha256']:
        raise Unsupported('frozen pins differ')
    environment(base, c)
    for name in ('train', 'val', 'context', 'control'):
        record = frozen[name]
        if sha256(record['path']) != record['sha256']:
            raise Unsupported('freeze artifact changed')
    if not 0 <= frozen['threshold'] <= math.nextafter(1., math.inf):
        raise Unsupported('frozen threshold')
    # Checkpoint/threshold/config already frozen, checked above. First held-out IO below.
    manifest = json.loads(Path(heldout_manifest).read_text())
    expected_hash = manifest.get('sha256', manifest.get('file', {}).get('sha256'))
    if expected_hash != sha256(heldout_path):
        raise Unsupported('held-out manifest hash')
    rows = read_rows(heldout_path, c)
    development = read_rows(frozen['train']['path'], c) + read_rows(frozen['val']['path'], c)
    collision = overlap(development, rows)
    if any(collision.values()):
        raise Unsupported('held-out overlap')
    scorer = Scorer(base, c, frozen['config']['threads'])
    for which in ('context', 'control'):
        tensors, meta = common.load_checkpoint(frozen[which]['path'])
        if (meta.get('context_contract_sha256') != contract_hash(c) or meta.get('question') != 'owner_accepts_use'
                or meta.get('facts_blind') != (which == 'control') or meta.get('tokenizer_sha256') != c['tokenizer']['sha256']):
            raise Unsupported('not matching context heads')
        common.apply_heads(scorer.model, tensors)
        if which == 'context':
            scores = scorer.scores(rows)
            reinforced = scorer.scores(rows, reinforced=True)
        else:
            control = scorer.scores(rows, facts_blind=True)
    fits = []
    for row in rows:
        try:
            serialize(row['request'], row['action'], row['secrets'], c)
            fits.append(True)
        except Refusal:
            fits.append(False)
    report = gates(rows, scores, control, reinforced, fits, frozen['threshold'])
    # No substitute replay from labels/facts: supervised schema lacks old-route inputs.
    report['unsupported_comparisons'] = ['faithful_current_route_and_fact_heads_replay', 'same_device_systemone_latency_and_peak_rss']
    report['measured_gates_failed'] = [k for k, value in report['gates'].items() if value is False]
    # Missing comparisons prevent PASS, but cannot erase a measured failure.
    report['outcome'] = 'FAIL' if report['measured_gates_failed'] else 'UNSUPPORTED'
    report.update(context_contract_sha256=contract_hash(c), freeze_sha256=sha256(freeze_path),
                  heldout_sha256=expected_hash, overlap=collision, threshold=frozen['threshold'])
    return report


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--data', required=True)
    p.add_argument('--out', required=True, help='New isolated directory; contains freeze.json')
    p.add_argument('--base-dir', required=True)
    p.add_argument('--contract', default=str(CONTRACT))
    p.add_argument('--mode', choices=['probe', 'full'], default='probe')
    p.add_argument('--limit', type=int, default=128)
    p.add_argument('--epochs', type=int, default=1)
    p.add_argument('--max-steps', type=int, default=8)
    p.add_argument('--batch', type=int, default=1)
    p.add_argument('--threads', type=int, default=2)
    p.add_argument('--seconds-per-head', type=int, default=600)
    p.add_argument('--lr', type=float, default=.0003)
    p.add_argument('--seed', type=int, default=7)
    a = p.parse_args(argv)
    if not (1 <= a.epochs <= 8 and 1 <= a.max_steps <= 10000 and 1 <= a.batch <= 8 and
            1 <= a.threads <= 4 and 1 <= a.limit <= 20000 and 1 <= a.seconds_per_head <= 14400 and 0 < a.lr <= .01):
        p.error('finite resource bounds exceeded')
    out = Path(a.out).resolve()
    if 'target' in out.parts:
        p.error('output must be outside target')
    out.mkdir(parents=True, exist_ok=False)
    report = {'outcome': 'UNSUPPORTED', 'mode': a.mode}
    try:
        c = load_contract(a.contract)
        manifest, measurement = environment(a.base_dir, c)
        train_path = (Path(a.data) / 'train.jsonl').resolve()
        val_path = (Path(a.data) / 'val.jsonl').resolve()
        training, val = read_rows(train_path, c), read_rows(val_path, c)
        if (any(not r['family'].startswith('G1:') for r in training + val)
                or any(overlap(training, val).values())):
            raise Unsupported('development split/family')
        training = training[:a.limit]
        val = val[:a.limit]
        import torch
        import common
        torch.manual_seed(a.seed)
        random.seed(a.seed)
        scorer = Scorer(a.base_dir, c, a.threads)
        initial = {k: v.clone() for k, v in common.head_state(scorer.model).items()}
        config = {k: v for k, v in vars(a).items() if k not in ('out', 'base_dir', 'contract', 'data')}
        artifacts = {}
        summaries = {}
        for which in ('context', 'control'):
            common.apply_heads(scorer.model, initial)
            summaries[which] = scorer.train(training, a.epochs, a.max_steps, a.batch, a.lr, a.seed,
                                            a.seconds_per_head, facts_blind=which == 'control')
            path = out / (which + '.safetensors')
            common.save_checkpoint(scorer.model, str(path), dict(name='apassy-context-v1',
                context_contract_sha256=contract_hash(c), question='owner_accepts_use',
                tokenizer_sha256=c['tokenizer']['sha256'], base_revision=REVISION,
                base_weights_sha256=manifest['base']['weights_sha256'], facts_blind=which == 'control',
                noul_temperature=scorer.temperature, config=config, training=summaries[which]))
            artifacts[which] = {'path': str(path), 'sha256': sha256(path)}
            if which == 'context':
                validation_scores = scorer.scores(val)
        from context_eval import threshold
        # Non-fitting validation rows count as asks. They cannot justify a threshold.
        fitting = [(r, s) for r, s in zip(val, validation_scores) if s is not None and not r['local_rule']]
        tau = threshold([r for r, _ in fitting], [s for _, s in fitting])
        frozen = dict(context_contract_sha256=contract_hash(c), tokenizer_sha256=c['tokenizer']['sha256'],
                      base=manifest['base'], config=config, threshold=tau, measurement=measurement,
                      train={'path': str(train_path), 'sha256': sha256(train_path)},
                      val={'path': str(val_path), 'sha256': sha256(val_path)}, **artifacts)
        (out / 'freeze.json').write_bytes(canonical(frozen))
        report.update(training_completed=True, reason='training_only_no_heldout_opened', freeze_sha256=sha256(out / 'freeze.json'),
                      threshold=tau, validation={'total': len(val), 'fitting_scored': len(fitting)}, training=summaries)
    except (Unsupported, OSError, ValueError, KeyError, ImportError) as e:
        report['reason'] = str(e) if isinstance(e, Unsupported) else type(e).__name__
    (out / 'training-report.json').write_bytes(canonical(report))
    print(json.dumps(report))
    return 3


if __name__ == '__main__':
    raise SystemExit(main())
