"""Thin, explicit existing-trainer integration. Import/verification are model-free.

Preparation does not authorize execution. A future owner-approved device and
resource budget, identical training/evaluation package versions and supervision
are required. This experiment supplies no W8 eligibility or Gate B evidence.
"""
import argparse
import gc
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys

from context_data import _json_object, _invalid_constant, overlap, rubric
from context_train_rows import convert_rows, digest, export_rows, safe_path, validate_rows
from context_v1 import CONTRACT, REVISION, Unsupported, Refusal, canonical, contract_hash, load_contract

ARMS = ('context', 'control')
CONFIG = dict(mode='full', trainer='train.py', amp=False, epochs=4, batch=32,
              lr=.0003, wd=.01, warmup=100, seed=7, threads=4, limit=0,
              max_steps=0, seconds_per_head=5400)
CACHE_BYTES = 6 * 1024**3


def read_json(raw):
    return json.loads(raw, object_pairs_hook=_json_object, parse_constant=_invalid_constant)


def record(path):
    path = safe_path(path).resolve()
    return dict(path=str(path), sha256=digest(path.read_bytes()))


def checked(record):
    raw = safe_path(record['path']).read_bytes()
    if digest(raw) != record['sha256']:
        raise Unsupported('artifact hash mismatch')
    return raw


def originals(frozen, c):
    # Validate every path before the first read, including a malicious second split.
    for name in ('train', 'val', 'data_manifest'):
        safe_path(frozen[name]['path'])
    manifest = read_json(checked(frozen['data_manifest']))
    if (set(manifest) != {'seed', 'groups', 'rubric', 'files'}
            or type(manifest['seed']) is not int or type(manifest['groups']) is not int
            or not 400 <= manifest['groups'] <= 800
            or manifest['rubric'] != 'v1-R1-text-catalog'
            or set(manifest['files']) != {'train.jsonl', 'val.jsonl'}):
        raise Unsupported('original G1 manifest/groups')
    sets = {}
    for split in ('train', 'val'):
        raw = checked(frozen[split])
        rows = [read_json(line) for line in raw.decode().splitlines() if line.strip()]
        validate_rows(rows, c)
        if manifest['files'][split + '.jsonl'] != dict(sha256=digest(raw), rows=len(rows)):
            raise Unsupported('original G1 source manifest mismatch')
        if any(rubric(r) != r['label'] for r in rows):
            raise Unsupported('original G1 rubric label mismatch')
        sets[split] = rows
    if (any(overlap(sets['train'], sets['val']).values())
            or {r['id'] for r in sets['train']} & {r['id'] for r in sets['val']}):
        raise Unsupported('original G1 disjointness')
    return sets


def conversion(sets, frozen, c, which):
    counts, hashes = {}, {}
    for split, rows in sets.items():
        selected, counts[split + '.jsonl'] = convert_rows(rows, c, facts_blind=which == 'control')
        answers = {r['answer'] for r in selected}
        if answers != {0., 1.}:
            raise Unsupported('selected split requires both classes')
        # Threshold needs these original labels, not just binary targets.
        if split == 'val':
            labels = {r['label'] for r in rows
                      if convert_rows([r], c, facts_blind=which == 'control')[0]}
            if not {'allow_ok', 'must_ask'} <= labels:
                raise Unsupported('validation requires allow_ok and must_ask')
        hashes[split + '.jsonl'] = digest(b''.join(canonical(r) for r in selected))
    return dict(contract_sha256=contract_hash(c), question=c['question'], arm=which,
                source_sha256={name: frozen[key]['sha256'] for name, key in
                               (('data-manifest.json', 'data_manifest'), ('train.jsonl', 'train'), ('val.jsonl', 'val'))},
                output_sha256=hashes, counts=counts, evidence='input data only; not a model freeze')


def report_ok(report, frozen, which):
    cfg = {k: CONFIG[k] for k in ('epochs', 'batch', 'lr', 'warmup', 'seed', 'limit', 'max_steps')}
    cfg['weight_decay'] = CONFIG['wd']  # Generic trainer spelling is deliberate.
    checkpoint = frozen[which]
    counts = frozen['converted'][which]['counts']
    if (report['config'] != cfg or report['init'] is not None or report['init_sha256'] is not None
            or report['teacher_rows'] != 0 or report['amp_encoder_fp16'] is not False
            or report.get('lora_layers', 0) != 0 or report.get('lora', False) or report.get('teacher', False)
            or report['device'] != frozen['config']['device']
            or report['train_examples'] != counts['train.jsonl']['selected']
            or report['val_examples'] != counts['val.jsonl']['selected']
            or report['versions'] != frozen['package_versions']
            or Path(report['checkpoint']).resolve() != Path(checkpoint['path']).resolve()
            or report['sha256'] != checkpoint['sha256']
            or report['size_bytes'] != safe_path(checkpoint['path']).stat().st_size
            or report['version'] != 'apassy-context-v1+' + checkpoint['sha256'][:8]
            or type(report['trainable_parameters']) is not int or report['trainable_parameters'] <= 0
            or not 1 <= report['best_epoch'] <= CONFIG['epochs']):
        raise Unsupported('trainer report configuration/counts/versions/checkpoint mismatch')


def verify_conversion(frozen, c):
    """Recompute full provenance and hashed reports before any held-out IO."""
    try:
        for name in ('train', 'val', 'data_manifest'):
            safe_path(frozen[name]['path'])
        expected = dict(CONFIG, device=frozen['config']['device'])
        if frozen['config'] != expected or expected['device'] not in ('cpu', 'mps', 'cuda'):
            raise Unsupported('existing trainer configuration/device mismatch')
        if (frozen['context_contract_sha256'] != contract_hash(c)
                or frozen['tokenizer_sha256'] != c['tokenizer']['sha256']
                or frozen['base']['revision'] != REVISION):
            raise Unsupported('existing trainer pins mismatch')
        for which in ARMS:
            safe_path(frozen['training_reports'][which]['path'])
            safe_path(frozen[which]['path'])
        manifest = read_json(Path(__file__).with_name('manifest.json').read_bytes())
        if frozen['base'] != manifest['base'] or set(frozen['package_versions']) != {'laya', 'torch', 'transformers', 'tokenizers'}:
            raise Unsupported('existing trainer base/package pins mismatch')
        sets = originals(frozen, c)
        if set(frozen['converted']) != set(ARMS) or set(frozen['training_reports']) != set(ARMS):
            raise Unsupported('conversion arms mismatch')
        reports = []
        for which in ARMS:
            if frozen['converted'][which] != conversion(sets, frozen, c, which):
                raise Unsupported('conversion provenance mismatch')
            checked(frozen[which])
            report = read_json(checked(frozen['training_reports'][which]))
            report_ok(report, frozen, which)
            reports.append(report)
        if reports[0]['trainable_parameters'] != reports[1]['trainable_parameters']:
            raise Unsupported('trainer head parameter mismatch')
    except Unsupported:
        raise
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        raise Unsupported('invalid existing trainer provenance') from exc


def exact_preflight(scorer, sets, c, which):
    """Check every selected occurrence, preserving duplicates and order."""
    total_tokens, total_rows = 0, 0
    for rows in sets.values():
        expected, _ = convert_rows(rows, c, facts_blind=which == 'control')
        actual = []
        for row in rows:
            one, _ = convert_rows([row], c, facts_blind=which == 'control')
            if not one:
                continue  # Only converter's contractual exclusions are allowed.
            try:
                item = scorer.item(row, facts_blind=which == 'control')
            except Refusal as exc:
                raise Unsupported('selected row exact tokenization refusal: ' + exc.code) from exc
            legacy = one[0]
            internal = scorer.agent._to_internal(dict(type='noul', instructions=legacy['instructions']))
            encoded = scorer.agent._encode_state(legacy['state'], ['q'], {'q': internal})[0]
            if (any(item[k] != encoded[k] for k in ('ids', 'markers', 'qtype'))
                    or item['y'] != legacy['answer'] or item['teacher'] is not False):
                raise Unsupported('selected row exact tokenization mismatch')
            actual.extend(one)
            total_tokens += len(item['ids'])
            total_rows += 1
        if actual != expected:
            raise Unsupported('selected sequence mismatch')
    # Existing train.py stores all occurrences (not a unique-text cache).
    # Reserve generous index/NPY overhead before allowing any subprocess.
    required = total_tokens * scorer.model.encoder.config.hidden_size * 2 + total_rows * 1024 + 1024**2
    if required > CACHE_BYTES:
        raise Unsupported('trainer feature cache exceeds 6 GiB')


def require_device(device, torch):
    if device not in ('cpu', 'mps', 'cuda'):
        raise Unsupported('explicit approved device required')
    if ((device == 'mps' and not torch.backends.mps.is_available())
            or (device == 'cuda' and not torch.cuda.is_available())):
        raise Unsupported('approved device unavailable; fallback refused')


def trainer_command(base, data, out, meta, report, cache, device):
    return [sys.executable, str(Path(__file__).with_name('train.py')), '--base-dir', str(base),
            '--metadata', str(meta), '--data', str(data), '--out', str(out), '--report', str(report),
            '--cache-dir', str(cache), '--no-amp', '--device', device, '--require-device',
            '--name', 'apassy-context-v1',
            '--epochs', '4', '--batch', '32', '--lr', '0.0003', '--weight-decay', '0.01',
            '--warmup', '100', '--seed', '7']


def train_arm(base, data, checkpoint, metadata, report, cache, device):
    if cache.exists():
        raise Unsupported('trainer cache must be fresh')
    try:
        subprocess.run(trainer_command(base, data, checkpoint, metadata, report, cache, device),
                       env={**os.environ, 'HF_HUB_OFFLINE': '1', 'OMP_NUM_THREADS': '4',
                            'MKL_NUM_THREADS': '4'}, timeout=5400, check=True)
    finally:
        if cache.exists():
            shutil.rmtree(cache)


def run(data, out, base, device, contract=CONTRACT, source_sha=None):
    """Explicit future run only; caller must obtain resource/owner approval first."""
    # Path checks and exclusive output precede any model imports.
    if source_sha is not None and (not isinstance(source_sha, str) or not re.fullmatch(r'[0-9a-f]{40}', source_sha)):
        raise Unsupported('invalid source SHA')
    paths = [safe_path(p) for p in (data, out, base, contract)]
    if paths[1].exists() or paths[1].is_symlink():
        raise Unsupported('output exists')
    data, out, base, contract = [p.resolve() for p in paths]
    if device not in ('cpu', 'mps', 'cuda') or not base.is_dir() or 'target' in out.parts:
        raise Unsupported('explicit local base/device/output required')
    if out.exists() or out.is_symlink():
        raise Unsupported('output exists')
    import context_train as core
    if source_sha is not None:
        try:
            actual_sha = core.source_commit()
        except (OSError, subprocess.CalledProcessError):
            actual_sha = source_sha
        if actual_sha != source_sha:
            raise Unsupported('source commit mismatch')
    core.install_training_audit()
    for name in ('train.jsonl', 'val.jsonl', 'data-manifest.json'):
        safe_path(data / name)
    c = load_contract(contract)
    frozen = {key: record(data / name) for key, name in
              (('train', 'train.jsonl'), ('val', 'val.jsonl'), ('data_manifest', 'data-manifest.json'))}
    sets = originals(frozen, c)
    provenance = {which: conversion(sets, frozen, c, which) for which in ARMS}
    # The whole run is offline, including environment and CPU tokenizer loading.
    previous = os.environ.get('HF_HUB_OFFLINE')
    os.environ['HF_HUB_OFFLINE'] = '1'
    try:
        import torch
        import common
        require_device(device, torch)
        manifest, measurement = core.environment(base, c)
        out.mkdir()
        frozen.update(mode='full', source_commit=core.source_commit() if source_sha is None else actual_sha, source_hashes=core.source_identity(),
                      package_versions=core.package_versions(), base=manifest['base'], measurement=measurement,
                      context_contract_sha256=contract_hash(c), tokenizer_sha256=c['tokenizer']['sha256'],
                      config=dict(CONFIG, device=device), converted=provenance, training_reports={})
        scorer = core.Scorer(base, c, 4)
        try:
            n_train = sum(t.numel() for t in common.head_state(scorer.model).values())
            for which in ARMS:
                exact_preflight(scorer, sets, c, which)
        finally:
            del scorer
            gc.collect()  # Release CPU encoder before either training subprocess.
        for which in ARMS:
            arm_data = out / (which + '-data')
            if export_rows(data, arm_data, facts_blind=which == 'control', contract_path=contract) != provenance[which]:
                raise Unsupported('source changed during export')
            metadata = dict(context_contract_sha256=contract_hash(c), question=c['question']['id'],
                            facts_blind=which == 'control', tokenizer_sha256=c['tokenizer']['sha256'],
                            base_weights_sha256=manifest['base']['weights_sha256'])
            meta_path = out / (which + '-metadata.json')
            meta_path.write_bytes(canonical(metadata))
            checkpoint, report = out / (which + '.safetensors'), out / (which + '-report.json')
            train_arm(base, arm_data, checkpoint, meta_path, report, out / (which + '-cache'), device)
            frozen[which] = record(checkpoint)
            frozen['training_reports'][which] = record(report)
            trainer_report = read_json(checked(frozen['training_reports'][which]))
            report_ok(trainer_report, frozen, which)
            if trainer_report['trainable_parameters'] != n_train:
                raise Unsupported('trainer head parameters differ from common.head_state')
            tensors, meta = common.load_checkpoint(str(checkpoint))
            if not core.context_meta_ok(meta, which, c, manifest['base']['weights_sha256']):
                raise Unsupported('checkpoint context metadata mismatch')
            if (meta.get('trained') != list(common.TRAINED_PREFIXES)
                    or meta.get('epoch') != trainer_report['best_epoch']
                    or meta.get('base_repo') != manifest['base']['repo']):
                raise Unsupported('checkpoint trainer metadata mismatch')
            cache = core.FeatureCache(limit=CACHE_BYTES)
            scorer = None
            try:
                scorer = core.Scorer(base, c, 4, cache=cache)
                common.apply_heads(scorer.model, tensors)  # Existing prefix/key/shape checks.
                tau, _ = core.fit_threshold(scorer, sets['val'], which)
                frozen['threshold' if which == 'context' else 'control_threshold'] = tau
            finally:
                cache.close()
                del scorer, tensors
                gc.collect()
        verify_conversion(frozen, c)
        # Recheck current source/runtime identities; no approval or evaluation claim.
        if frozen['package_versions'] != core.package_versions() or frozen['source_hashes'] != core.source_identity():
            raise Unsupported('run environment changed')
        (out / 'freeze.json').write_bytes(canonical(frozen))
        return frozen
    finally:
        if previous is None:
            os.environ.pop('HF_HUB_OFFLINE', None)
        else:
            os.environ['HF_HUB_OFFLINE'] = previous


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('data', 'out', 'base-dir', 'device'):
        p.add_argument('--' + name, required=True)
    p.add_argument('--contract', default=str(CONTRACT))
    p.add_argument('--source-sha', default=None)
    a = p.parse_args(argv)
    run(a.data, a.out, a.base_dir, a.device, a.contract, a.source_sha)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
