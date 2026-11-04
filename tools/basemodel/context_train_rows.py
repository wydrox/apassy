"""Export synthetic G1 rows for the existing train.py; never train or run a model.

This input-data provenance is NOT a model freeze and cannot activate the bouncer.
Context checkpoint metadata/freeze compatibility needs separate acceptance before
any model execution. No secrets, tensor libraries, or network access are needed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil

from context_data import CLASSES, overlap, _json_object, _invalid_constant
from context_v1 import (CONTRACT, Unsupported, Refusal, blind, canonical,
                        contract_hash, load_contract, serialize, validate_secret)

LABELS = {'allow_ok': 1.0, 'must_ask': 0.0, 'deterministic_ask': 0.0}
FIELDS = set('id family class request action secrets local_rule pair_of injection_of rationale label'.split())


def safe_path(path):
    """Reject held-out/H1 names, including symlink targets, before opening files."""
    path = Path(path)
    for name in (str(path), str(path.resolve())):
        if re.search(r'held[-_]?out|(?:^|[/\\])h1(?:$|[/\\:._-])', name, re.I):
            raise Unsupported('training refuses held-out/H1 path')
    return path


def validate_rows(rows, contract):
    ids = set()
    for r in rows:
        if (not isinstance(r, dict) or set(r) != FIELDS
                or type(r['id']) is not str or r['id'] in ids
                or type(r['family']) is not str
                or not re.fullmatch(r'G1:[a-z0-9_-]+-[0-9a-f]{12}', r['family'])
                or not r['id'].startswith(r['family'] + ':')
                or type(r['class']) is not str or r['class'] not in CLASSES
                or type(r['label']) is not str or r['label'] not in LABELS
                or type(r['action']) is not str or r['action'] not in ('read', 'change', 'deploy', 'delete')
                or not isinstance(r['request'], dict)
                or set(r['request']) != {'user_request', 'command', 'purpose'}
                or any(type(v) is not str for v in r['request'].values())
                or not isinstance(r['secrets'], list) or not 1 <= len(r['secrets']) <= 3
                or (r['local_rule'] is not None and type(r['local_rule']) is not str)
                or any(r[k] is not None and type(r[k]) is not str for k in ('pair_of', 'injection_of'))
                or type(r['rationale']) is not str):
            raise Unsupported('G1 schema/ids/families/labels')
        ids.add(r['id'])
        for secret in r['secrets']:
            validate_secret(secret, contract)


def convert_rows(rows, contract, *, facts_blind=False):
    """Return (legacy rows, counts); only local_rule/OverBudget may be skipped.

    Counts describe this arm independently: input, selected, local_rule, OverBudget.
    State is the serializer's exact model_text, with no added metadata or truncation.
    """
    rows = list(rows)
    validate_rows(rows, contract)
    result = []
    counts = dict(input=len(rows), selected=0, local_rule=0, OverBudget=0)
    for row in rows:
        if row['local_rule'] is not None:
            counts['local_rule'] += 1
            continue
        secrets = blind(row['secrets'], contract) if facts_blind else row['secrets']
        try:
            text, _ = serialize(row['request'], row['action'], secrets, contract,
                                enforce_budget=not facts_blind)
        except Refusal as exc:
            if exc.code != 'OverBudget':
                raise
            counts['OverBudget'] += 1
            continue
        result.append(dict(state=text, question=contract['question']['id'],
                           instructions=contract['question']['instructions'],
                           answer=LABELS[row['label']], teacher=False))
        counts['selected'] += 1
    return result, counts


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def export_rows(data, out, *, facts_blind=False, contract_path=CONTRACT):
    """Validate both source splits before creating a new output directory."""
    data, out, contract_path = [safe_path(p) for p in (data, out, contract_path)]
    paths = [safe_path(data / name) for name in ('data-manifest.json', 'train.jsonl', 'val.jsonl')]
    if out.exists() or out.is_symlink():
        raise Unsupported('output exists')
    contract = load_contract(contract_path)
    raw = paths[0].read_bytes()
    manifest = json.loads(raw, object_pairs_hook=_json_object, parse_constant=_invalid_constant)
    if (not isinstance(manifest, dict) or set(manifest) != {'seed', 'groups', 'rubric', 'files'}
            or manifest['rubric'] != 'v1-R1-text-catalog'
            or type(manifest['seed']) is not int or type(manifest['groups']) is not int
            or not 1 <= manifest['groups'] <= 10000
            or not isinstance(manifest['files'], dict)
            or set(manifest['files']) != {'train.jsonl', 'val.jsonl'}):
        raise Unsupported('G1 source manifest')
    sources, sets = {'data-manifest.json': digest(raw)}, []
    for path in paths[1:]:
        source_raw = path.read_bytes()
        source_hash = digest(source_raw)
        meta = manifest['files'][path.name]
        if (not isinstance(meta, dict) or set(meta) != {'sha256', 'rows'}
                or type(meta['rows']) is not int or meta['rows'] < 1
                or source_hash != meta['sha256']):
            raise Unsupported('source hash/manifest mismatch')
        # Convert the exact bytes whose hash was checked, even if a source writer
        # changes the path between reads.
        try:
            rows = [json.loads(line, object_pairs_hook=_json_object,
                               parse_constant=_invalid_constant)
                    for line in source_raw.decode('utf-8').splitlines() if line.strip()]
        except (json.JSONDecodeError, UnicodeError):
            raise Unsupported('G1 source JSON') from None
        validate_rows(rows, contract)
        if len(rows) != meta['rows'] or digest(path.read_bytes()) != source_hash:
            raise Unsupported('source count/hash changed')
        sets.append(rows)
        sources[path.name] = source_hash
    if any(overlap(*sets).values()) or {r['id'] for r in sets[0]} & {r['id'] for r in sets[1]}:
        raise Unsupported('G1 train/val overlap')
    if digest(paths[0].read_bytes()) != sources['data-manifest.json']:
        raise Unsupported('source manifest changed')
    payloads, counts = {}, {}
    for name, rows in zip(('train.jsonl', 'val.jsonl'), sets):
        converted, counts[name] = convert_rows(rows, contract, facts_blind=facts_blind)
        if not converted:
            raise Unsupported('no trainable rows in split')
        payloads[name] = b''.join(canonical(row) for row in converted)
    provenance = dict(contract_sha256=contract_hash(contract), question=contract['question'],
                      arm='control' if facts_blind else 'context', source_sha256=sources,
                      output_sha256={k: digest(v) for k, v in payloads.items()}, counts=counts,
                      evidence='input data only; not a model freeze')
    payloads['provenance.json'] = canonical(provenance)
    out.mkdir()  # Exclusive creation; never overwrite even an empty existing directory.
    try:
        for name, payload in payloads.items():
            (out / name).write_bytes(payload)
    except BaseException:
        shutil.rmtree(out)
        raise
    return provenance


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data', required=True)
    parser.add_argument('--out', required=True)
    parser.add_argument('--facts-blind', action='store_true')
    parser.add_argument('--contract', default=CONTRACT)
    args = parser.parse_args(argv)
    try:
        result = export_rows(args.data, args.out, facts_blind=args.facts_blind, contract_path=args.contract)
    except (ValueError, OSError, KeyError, TypeError):
        parser.exit(2, 'context training export refused: invalid source, contract, or output\n')
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
