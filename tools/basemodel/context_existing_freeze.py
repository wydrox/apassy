"""Thin, explicit existing-trainer integration. Import/verification are model-free.

Preparation does not authorize execution. A future owner-approved device and
resource budget, identical training/evaluation package versions and supervision
are required. This experiment supplies no W8 eligibility or Gate B evidence.
"""
import argparse
import gc
import json
import math
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
RECIPES = {'context-v1-e20': dict(CONFIG, epochs=20, recipe='context-v1-e20')}
G1_SHA256 = dict(train='a78f550019b5cfa9ddf9524476ab1ea940f2bd5c91a102c7433e821bdd6cfc5f',
                 val='a3284ff49471406ddde90668812b6715d2bf9c23a3893fbe0b585719352b3aa6',
                 data_manifest='c2478f94f5bea91f0485a0061037d4a36140502c32dd465eea39dd6571bc0efe')
D0_SAMPLE_SHA256 = '864ea9c6f39c3c2cc910aa5fa1af2bc0e0f3ce78279b2fc4d8f5c74f8cc8dce4'
CACHE_BYTES = 6 * 1024**3


def config_for(recipe=None):
    if recipe is None:
        return dict(CONFIG)
    if not isinstance(recipe, str) or recipe not in RECIPES:
        raise Unsupported('unknown existing trainer recipe')
    return dict(RECIPES[recipe])


def frozen_config(frozen, recipe=None):
    config = frozen['config']
    selected = config.get('recipe')
    if recipe is not None and recipe != selected:
        raise Unsupported('existing trainer recipe mismatch')
    expected = dict(config_for(selected), device=config['device'])
    if config != expected or expected['device'] not in ('cpu', 'mps', 'cuda'):
        raise Unsupported('existing trainer configuration/device mismatch')
    return expected


def model_name(recipe=None):
    config_for(recipe)
    return 'apassy-' + (recipe or 'context-v1')


def development_selection(sets, frozen, c, recipe=None):
    """Freeze unchanged D0 membership before any model import or training."""
    config_for(recipe)
    if recipe is None:
        return None
    if any(frozen[key]['sha256'] != value for key, value in G1_SHA256.items()):
        raise Unsupported('development G1 source pins differ')
    manifest = read_json(checked(frozen['data_manifest']))
    if (type(manifest.get('groups')) is not int or manifest['groups'] != 400
            or type(manifest.get('seed')) is not int or manifest['seed'] != 7):
        raise Unsupported('development G1 groups/seed differ')
    import context_dev_diagnostic as d0
    from context_eval import CLASSES
    from context_v1 import serialize
    try:
        selected = d0.select_rows(sets['val'], tuple(CLASSES), serialize, Refusal, c, {})
    except d0.DiagnosticError as exc:
        raise Unsupported('development selection refused') from exc
    selection = selected[0]
    if (selection['sample_sha256'] != D0_SAMPLE_SHA256
            or (selection['rows'], selection['pairs'], selection['unpaired_allows']) != (267, 91, 85)):
        raise Unsupported('development sample differs')
    return selected


def calibration_snapshot(scorer, rows, tau):
    """Copy the sole full-validation calibration vectors; never score again."""
    if (len(scorer.last_scores) != len(rows) or len(scorer.last_refusals) != len(rows)
            or len({r['id'] for r in rows}) != len(rows)):
        raise Unsupported('development calibration alignment')
    return dict(threshold=tau, by_id={r['id']: (p, refusal) for r, p, refusal in
                zip(rows, scorer.last_scores, scorer.last_refusals)})


def blind_pair_keys(scorer, rows, pairs):
    keys = []
    for a, m in pairs:
        try:
            left = scorer.item(rows[a], facts_blind=True)['cache_key']
            right = scorer.item(rows[m], facts_blind=True)['cache_key']
            keys.append('identical' if left == right else 'different')
        except Refusal:
            keys.append('incomparable')
    return keys


def temperature_ok(meta, report, scorer):
    values = (meta.get('noul_temperature'), report.get('noul_temperature'), scorer.temperature)
    if (any(type(v) not in (float, int) or not math.isfinite(v) or v <= 0 for v in values)
            or not values[0] == values[1] == values[2]):
        raise Unsupported('checkpoint/report/scorer temperature mismatch')


def development_reading(selection, validation, snapshots, keys, recipe):
    """Aggregate reused calibration data; no independent quality/safety claim."""
    config_for(recipe)
    if recipe is None:
        raise Unsupported('development reading requires explicit recipe')
    import context_dev_diagnostic as d0
    from context_eval import CLASSES, auroc
    selected, rows, pairs, unpaired = selection
    scores, refusals, thresholds, full = {}, {}, {}, {}
    for arm in ARMS:
        snapshot = snapshots[arm]
        if set(snapshot['by_id']) != {r['id'] for r in validation}:
            raise Unsupported('development calibration alignment')
        scores[arm] = [snapshot['by_id'][r['id']][0] for r in rows]
        refusals[arm] = [snapshot['by_id'][r['id']][1] for r in rows]
        thresholds[arm] = snapshot['threshold']
        labels = {}
        for label in ('allow_ok', 'must_ask'):
            population = [snapshot['by_id'][r['id']] for r in validation if r['label'] == label]
            eligible = [p for p, refusal in population if refusal is None and d0.probability(p)]
            allowed = sum(p >= snapshot['threshold'] for p in eligible)
            labels[label] = dict(original_rows=len(population), eligible_scorer_rows=len(eligible),
                auto_allow=allowed, original_auto_allow_rate=allowed / len(population) if population else None,
                eligible_auto_allow_rate=allowed / len(eligible) if eligible else None,
                refused={code: sum(refusal == code for _, refusal in population) for code in d0.REFUSALS},
                unavailable=sum(refusal is None and not d0.probability(p) for p, refusal in population),
                interpretation='calibration_safety_tautology' if label == 'must_ask' else 'reused_calibration_population')
        full[arm] = dict(rows=len(validation), labels=labels)
    metrics = d0.aggregate(rows, pairs, unpaired, scores, refusals, keys, thresholds, tuple(CLASSES), auroc)
    complete = all(d0.probability(p) and refusal is None for arm in ARMS
                   for p, refusal in zip(scores[arm], refusals[arm]))
    populations = {}
    for name, indices, minimum in (('unpaired_normal', unpaired, 43),
            ('paired_normal', [a for a, _ in pairs], 46)):
        allowed = sum(d0.probability(scores['context'][i]) and refusals['context'][i] is None
                      and scores['context'][i] >= thresholds['context'] for i in indices)
        populations[name] = dict(selected=len(indices), auto_allow=allowed, minimum_auto_allow=minimum,
                                 auto_allow_rate=allowed / len(indices) if indices else None)
    passed = all(p['auto_allow'] >= p['minimum_auto_allow'] for p in populations.values())
    reading = ('DEV_50_INCOMPLETE' if not complete else
               'DEV_50_NOT_RULED_OUT' if passed else 'DEV_50_MISS')
    return dict(schema='context-development-reading-v1', recipe=recipe, candidate_attempt=2,
        sample_sha256=selected['sample_sha256'], selection_counts=dict(rows=selected['rows'],
            pairs=selected['pairs'], unpaired_allows=selected['unpaired_allows']),
        thresholds=thresholds, data_reused_for_calibration=True, independent_quality='UNKNOWN',
        independent_safety='UNKNOWN', gate_b='UNSUPPORTED', activation_authorized=False,
        reading_rule=dict(d0.READING_RULE), goal50=dict(reference=.5, populations=populations,
            complete_selected_coverage=complete, reading=reading),
        full_validation=full, **metrics)


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


def report_ok(report, frozen, which, recipe=None):
    config = frozen_config(frozen, recipe)
    recipe = config.get('recipe')
    cfg = {k: config[k] for k in ('epochs', 'batch', 'lr', 'warmup', 'seed', 'limit', 'max_steps')}
    cfg['weight_decay'] = config['wd']  # Generic trainer spelling is deliberate.
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
            or report['version'] != model_name(recipe) + '+' + checkpoint['sha256'][:8]
            or type(report['trainable_parameters']) is not int or report['trainable_parameters'] <= 0
            or type(report['best_epoch']) is not int or not 1 <= report['best_epoch'] <= config['epochs']):
        raise Unsupported('trainer report configuration/counts/versions/checkpoint mismatch')
    if recipe is not None:
        temperature = report.get('noul_temperature')
        if type(temperature) not in (float, int) or not math.isfinite(temperature) or temperature <= 0:
            raise Unsupported('trainer temperature invalid')


def verify_conversion(frozen, c, recipe=None):
    """Recompute full provenance and hashed reports before any held-out IO."""
    try:
        for name in ('train', 'val', 'data_manifest'):
            safe_path(frozen[name]['path'])
        expected = frozen_config(frozen, recipe)
        recipe = expected.get('recipe')
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
        development_selection(sets, frozen, c, recipe)
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


def trainer_command(base, data, out, meta, report, cache, device, recipe=None):
    config = config_for(recipe)
    return [sys.executable, str(Path(__file__).with_name('train.py')), '--base-dir', str(base),
            '--metadata', str(meta), '--data', str(data), '--out', str(out), '--report', str(report),
            '--cache-dir', str(cache), '--no-amp', '--device', device, '--require-device',
            '--name', model_name(recipe),
            '--epochs', str(config['epochs']), '--batch', '32', '--lr', '0.0003', '--weight-decay', '0.01',
            '--warmup', '100', '--seed', '7']


def train_arm(base, data, checkpoint, metadata, report, cache, device, recipe=None):
    config_for(recipe)
    if cache.exists():
        raise Unsupported('trainer cache must be fresh')
    try:
        subprocess.run(trainer_command(base, data, checkpoint, metadata, report, cache, device, recipe),
                       env={**os.environ, 'HF_HUB_OFFLINE': '1', 'OMP_NUM_THREADS': '4',
                            'MKL_NUM_THREADS': '4'}, timeout=5400, check=True)
    finally:
        if cache.exists():
            shutil.rmtree(cache)


def run(data, out, base, device, contract=CONTRACT, source_sha=None, recipe=None):
    """Explicit future run only; caller must obtain resource/owner approval first."""
    config = config_for(recipe)
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
    selection = development_selection(sets, frozen, c, recipe)
    snapshots, pair_keys = {}, None
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
                      config=dict(config, device=device), converted=provenance, training_reports={})
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
            if recipe is not None:
                metadata['recipe'] = recipe
            meta_path = out / (which + '-metadata.json')
            meta_path.write_bytes(canonical(metadata))
            checkpoint, report = out / (which + '.safetensors'), out / (which + '-report.json')
            train_arm(base, arm_data, checkpoint, meta_path, report, out / (which + '-cache'), device,
                      **({'recipe': recipe} if recipe is not None else {}))
            frozen[which] = record(checkpoint)
            frozen['training_reports'][which] = record(report)
            trainer_report = read_json(checked(frozen['training_reports'][which]))
            report_ok(trainer_report, frozen, which)
            if trainer_report['trainable_parameters'] != n_train:
                raise Unsupported('trainer head parameters differ from common.head_state')
            tensors, meta = common.load_checkpoint(str(checkpoint))
            if not core.context_meta_ok(meta, which, c, manifest['base']['weights_sha256'],
                                        **({'recipe': recipe} if recipe is not None else {})):
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
                if recipe is not None:
                    temperature_ok(meta, trainer_report, scorer)
                tau, _ = core.fit_threshold(scorer, sets['val'], which)
                frozen['threshold' if which == 'context' else 'control_threshold'] = tau
                if recipe is not None:
                    snapshots[which] = calibration_snapshot(scorer, sets['val'], tau)
                    if which == 'control':
                        pair_keys = blind_pair_keys(scorer, selection[1], selection[2])
            finally:
                cache.close()
                del scorer, tensors
                gc.collect()
        if recipe is not None:
            frozen['development_reading'] = development_reading(selection, sets['val'], snapshots, pair_keys, recipe)
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
    p.add_argument('--recipe', choices=tuple(RECIPES), default=None)
    a = p.parse_args(argv)
    run(a.data, a.out, a.base_dir, a.device, a.contract, a.source_sha, recipe=a.recipe)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
