"""D0 calibration-data diagnosis. Import and selection are tensor-free.

Run only as a saved E entry against the immutable S checkout. Exit zero denotes
report completion; it conveys no independent quality or activation authority.
"""
import argparse
import hashlib
import importlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

S = '7a63ffad557ace5e396c4a709ad8453fb611b565'
RUN_ID = 'bouncer-bbee8f21-20261105t124513z'
BUNDLE = '6de84990fb29a99c8e23eb51b67066d6344c644fbf5e634ea4f23425a85fb974'
FREEZE = '7e8391a63aaba4afb84300788474be8e3ffdfb46b4aa3206801c0dbba550368c'
HEADS = dict(context='d53280016026448aad1109e68427a802c1eeca0a7b9c999d1db7bc2331942178',
             control='43d3a39369b4e8a360338a39a84a8e4daf9364222ea7253d8f93bbe70386971c')
ENTRY = 'tools/basemodel/context_dev_diagnostic.py'
ARMS = ('context', 'control')
SALT = b'd0-sample-v1\0'
REFUSALS = ('LocalRule', 'NoSecrets', 'TooManySecrets', 'OverBudget', 'ExactOverflow')
BINDING_KEYS = {'report_kind', 'training_source_sha', 'evaluation_source_sha',
                'entry_sha256', 'bundle_sha256', 'freeze_sha256', 'run_id'}
POLICY = dict(salt='d0-sample-v1', pairs_per_class=20, unpaired_allows_per_class=20,
              unpaired='not_referenced_by_any_original_pair', order='sha256_allow_nul_must',
              eligibility='same_class_noninjection_nonlocal_context_budget')
READING_RULE = dict(pair_ordering_reference=0.90, normal_allow_reference=0.60,
    below_reference='negative development evidence on that population',
    reaching_reference='not ruled out',
    class_comparisons='draw no conclusion from small per-class differences',
    risky_auto_allow='calibration reproduction only; nonzero indicates numerical drift')


class DiagnosticError(ValueError):
    """Fixed, non-sensitive error code only."""


def require(condition, code):
    if not condition:
        raise DiagnosticError(code)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=True, allow_nan=False) + '\n').encode('ascii')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def safe(path):
    path = Path(path)
    for name in (str(path), str(path.resolve())):
        require(not re.search(r'held[-_]?out|(?:^|[/\\])h[123](?:$|[/\\:._-])', name, re.I),
                'forbidden_path')
    return path


def read_json(path):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'json_schema')
            result[key] = value
        return result
    def constant(_):
        raise DiagnosticError('json_schema')
    return json.loads(safe(path).read_bytes(), object_pairs_hook=pairs, parse_constant=constant)


def git(repo, *args):
    return subprocess.check_output(['git', '-C', str(repo), *args], stderr=subprocess.DEVNULL)


def binding_guard(args, entry=None):
    """No source imports, freeze/data reads or model access before this guard."""
    out = safe(args.out)
    require(not out.exists() and not out.is_symlink(), 'output_exists')
    for name in ('repo_root', 'freeze', 'binding', 'selection', 'base_dir'):
        if hasattr(args, name):
            safe(getattr(args, name))
    require(args.expect_freeze_sha256 == FREEZE, 'freeze_binding')
    b = read_json(args.binding)
    require(isinstance(b, dict) and set(b) == BINDING_KEYS, 'binding_schema')
    expected = dict(report_kind='development_diagnostic', training_source_sha=S,
                    bundle_sha256=BUNDLE, freeze_sha256=FREEZE, run_id=RUN_ID)
    require(all(b.get(k) == v for k, v in expected.items()), 'binding_identity')
    e = b['evaluation_source_sha']
    require(isinstance(e, str) and re.fullmatch('[0-9a-f]{40}', e) is not None
            and e == os.environ.get('GITHUB_SHA'), 'evaluation_source')
    require(isinstance(b['entry_sha256'], str) and re.fullmatch('[0-9a-f]{64}', b['entry_sha256'])
            is not None, 'entry_binding')
    repo = safe(args.repo_root).resolve()
    require(git(repo, 'rev-parse', 'HEAD').decode().strip() == S, 'source_commit')
    require(git(repo, 'rev-parse', '--show-toplevel').decode().strip() == str(repo), 'source_root')
    require(not git(repo, 'status', '--porcelain', '--untracked-files=no'), 'source_dirty')
    git(repo, 'merge-base', '--is-ancestor', S, e)
    raw = safe(__file__ if entry is None else entry).read_bytes()
    require(digest(raw) == b['entry_sha256'] == digest(git(repo, 'show', e + ':' + ENTRY)),
            'entry_binding')
    return b, repo


def source_modules(repo):
    """Check actual origins before executing any imported project module."""
    directory = repo / 'tools/basemodel'
    sys.path.insert(0, str(directory))
    names = ('context_train', 'context_v1', 'context_data', 'context_train_rows',
             'context_existing_freeze', 'context_eval', 'common', 'train')
    for name in names:
        spec = importlib.util.find_spec(name)
        require(spec is not None and spec.origin is not None
                and Path(spec.origin).resolve() == directory / (name + '.py'), 'module_source')
        require(digest((directory / (name + '.py')).read_bytes())
                == digest(git(repo, 'show', S + ':tools/basemodel/' + name + '.py')), 'module_source')
    core = importlib.import_module('context_train')
    require(Path(core.__file__).resolve() == directory / 'context_train.py', 'module_source')
    core.install_training_audit()
    require(core.source_commit() == S, 'source_commit')
    loaded = [importlib.import_module(name) for name in
              ('context_v1', 'context_existing_freeze', 'context_eval')]
    for name in names:
        if name in sys.modules:
            require(Path(sys.modules[name].__file__).resolve() == directory / (name + '.py'), 'module_source')
    return core, *loaded


def prepare(args):
    b, repo = binding_guard(args)
    core, v, original, evaluation = source_modules(repo)
    # Check source field before verify_freeze can read any artifact/data path.
    require(digest(safe(args.freeze).read_bytes()) == FREEZE, 'freeze_binding')
    header = read_json(args.freeze)
    require(header.get('source_commit') == S, 'freeze_source')
    require(all(header.get(arm, {}).get('sha256') == HEADS[arm] for arm in ARMS), 'head_binding')
    c = v.load_contract()
    frozen = core.verify_freeze(args.freeze, c, FREEZE)
    dm = read_json(frozen['data_manifest']['path'])
    require(type(dm['groups']) is int and dm['groups'] == 400
            and type(dm['seed']) is int and dm['seed'] == 7, 'data_binding')
    rows = original.originals(frozen, c)['val']
    classes = tuple(evaluation.CLASSES)
    require(len(classes) == 5 and len(set(classes)) == 5, 'class_binding')
    selection, chosen, pairs, unpaired = select_rows(rows, classes, v.serialize, v.Refusal, c, b)
    return core, v, evaluation, c, frozen, selection, chosen, pairs, unpaired


def sample_key(allow, must=''):
    return hashlib.sha256(SALT + allow.encode('utf-8') + b'\0' + must.encode('utf-8')).digest()


def select_rows(rows, classes, serialize, refusal, contract, identities):
    by_id = {r['id']: r for r in rows}
    require(len(by_id) == len(rows), 'duplicate_rows')
    referenced, candidates = set(), set()
    for r in rows:
        if r.get('pair_of'):
            referenced.update((r['id'], r['pair_of']))
            require(r['pair_of'] in by_id, 'pair_schema')
            twin = by_id[r['pair_of']]
            require({r['label'], twin['label']} == {'allow_ok', 'must_ask'}
                    and r['request'] == twin['request'], 'pair_schema')
            a, m = (r, twin) if r['label'] == 'allow_ok' else (twin, r)
            candidates.add((a['id'], m['id']))
    fits = {}
    for r in rows:
        try:
            serialize(r['request'], r['action'], r['secrets'], contract)
            fits[r['id']] = True
        except refusal:
            fits[r['id']] = False
    chosen, selected_pairs, unpaired, stats, used = [], [], [], {}, set()
    for cls in classes:
        exclusions = dict(cross_class=0, injection=0, local_rule=0, context_budget=0,
                          row_reuse=0, pair_limit=0)
        eligible = []
        for aid, mid in sorted(candidates, key=lambda p: (sample_key(*p), p)):
            a, m = by_id[aid], by_id[mid]
            if a['class'] != cls:
                continue
            reason = ('cross_class' if m['class'] != cls else
                      'injection' if any(r['injection_of'] is not None for r in (a, m)) else
                      'local_rule' if any(r['local_rule'] is not None for r in (a, m)) else
                      'context_budget' if not (fits[aid] and fits[mid]) else None)
            if reason:
                exclusions[reason] += 1
            else:
                eligible.append((aid, mid))
        start, n = len(chosen), 0
        for aid, mid in eligible:
            if aid in used or mid in used:
                exclusions['row_reuse'] += 1
            elif n == 20:
                exclusions['pair_limit'] += 1
            else:
                selected_pairs.append((len(chosen), len(chosen) + 1))
                chosen.extend((by_id[aid], by_id[mid]))
                used.update((aid, mid))
                n += 1
        pair_families = len({r['family'] for r in chosen[start:]})
        ux = dict(referenced_by_pair=0, injection=0, local_rule=0, context_budget=0, limit=0)
        normals = []
        for r in sorted((r for r in rows if r['class'] == cls and r['label'] == 'allow_ok'),
                        key=lambda r: (sample_key(r['id']), r['id'])):
            reason = ('referenced_by_pair' if r['id'] in referenced else
                      'injection' if r['injection_of'] is not None else
                      'local_rule' if r['local_rule'] is not None else
                      'context_budget' if not fits[r['id']] else 'limit' if len(normals) == 20 else None)
            if reason:
                ux[reason] += 1
            else:
                require(r['id'] not in used, 'row_reuse')
                unpaired.append(len(chosen))
                chosen.append(r)
                normals.append(r)
                used.add(r['id'])
        stats[cls] = dict(pairs=n, unpaired_allows=len(normals), rows=2*n + len(normals),
                          pair_shortfall=20-n, unpaired_shortfall=20-len(normals),
                          pair_exclusions=exclusions, unpaired_exclusions=ux,
                          paired_distinct_families=pair_families,
                          unpaired_distinct_families=len({r['family'] for r in normals}))
    membership = dict(rows=[r['id'] for r in chosen], pairs=selected_pairs, unpaired=unpaired)
    selection = dict(report_kind='development_diagnostic', identities=dict(identities), policy=dict(POLICY),
                     sample_sha256=digest(canonical(membership)), classes=stats,
                     rows=len(chosen), pairs=len(selected_pairs), unpaired_allows=len(unpaired))
    return selection, chosen, selected_pairs, unpaired


def probability(value):
    return type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 1


def histogram(values):
    bins = [0] * 10
    for value in values:
        if probability(value):
            bins[min(int(value * 10), 9)] += 1
    return bins


def aggregate(rows, pairs, unpaired, scores, refusals, keys, thresholds, classes, auroc):
    """Aggregate only after validating all alignment and determinism constraints."""
    n = len(rows)
    require(len(keys) == len(pairs), 'score_alignment')
    for arm in ARMS:
        require(len(scores[arm]) == n and len(refusals[arm]) == n, 'score_alignment')
        require(all(r is None or r in REFUSALS for r in refusals[arm]), 'refusal_code')
        require(all(r is None or p is None for p, r in zip(scores[arm], refusals[arm])), 'score_alignment')
    for (a, m), kind in zip(pairs, keys):
        require(kind in ('identical', 'different', 'incomparable'), 'key_alignment')
        p, q = scores['control'][a], scores['control'][m]
        if kind == 'identical' and type(p) in (int, float) and type(q) in (int, float):
            require(not (math.isfinite(p) and math.isfinite(q)) or p == q, 'control_nondeterminism')
    result = {}
    for population, indices in (('paired', [i for pair in pairs for i in pair]),
                                ('unpaired_normal', unpaired)):
        groups = {}
        for cls in ('overall', *classes):
            ix = [i for i in indices if cls == 'overall' or rows[i]['class'] == cls]
            comparable = [i for i in ix if all(probability(scores[arm][i]) for arm in ARMS)]
            pp = [(k, a, m) for k, (a, m) in enumerate(pairs) if a in ix and m in ix]
            complete = [(k, a, m) for k, a, m in pp if a in comparable and m in comparable]
            all_identical = bool(pp) and len(complete) == len(pp) and all(keys[k] == 'identical' for k, _, _ in pp)
            arms = {}
            for arm in ARMS:
                values = scores[arm]
                labels = {}
                for label in ('allow_ok', 'must_ask'):
                    li = [i for i in ix if rows[i]['label'] == label]
                    ci = [i for i in comparable if rows[i]['label'] == label]
                    allowed = sum(values[i] >= thresholds[arm] for i in ci)
                    structural = ('calibration_reproduction' if label == 'must_ask' else
                                  'identical_control_twins' if arm == 'control' and all_identical else
                                  'reused_calibration_population')
                    labels[label] = dict(selected=len(li), scored=sum(probability(values[i]) for i in li),
                        refused={code: sum(refusals[arm][i] == code for i in li) for code in REFUSALS},
                        unavailable=sum(not probability(values[i]) and refusals[arm][i] is None for i in li),
                        comparable=len(ci), auto_allow=allowed,
                        auto_allow_rate=allowed / len(ci) if ci else None, interpretation=structural)
                arm_complete = [(k, a, m) for k, a, m in pp
                                if probability(values[a]) and probability(values[m])]
                ordering = dict(ordered=0, tied=0, inverted=0, incomparable=len(pp)-len(arm_complete))
                for _, a, m in arm_complete:
                    ordering['ordered' if values[a] > values[m] else 'tied' if values[a] == values[m] else 'inverted'] += 1
                arms[arm] = dict(labels=labels, pair_ordering=ordering, complete_pairs=len(arm_complete),
                    pair_ordering_rate=ordering['ordered']/len(arm_complete) if arm_complete else None,
                    pair_ordering_interpretation='identical_control_twins' if arm == 'control' and all_identical else 'reused_calibration_population',
                    auroc=auroc(rows, values, comparable),
                    auroc_interpretation='structurally_0.5' if arm == 'control' and all_identical else 'reused_calibration_population')
            groups[cls] = dict(selected=len(ix), comparable=len(comparable), selected_pairs=len(pp),
                complete_pairs=len(complete), blind_cache_keys={kind: sum(keys[k] == kind for k, _, _ in pp)
                for kind in ('identical', 'different', 'incomparable')}, arms=arms)
        result[population] = groups
    histograms = {arm: {label: histogram(scores[arm][i] for i, r in enumerate(rows) if r['label'] == label)
                       for label in ('allow_ok', 'must_ask')} for arm in ARMS}
    return dict(populations=result, histograms=dict(bins=10, range=[0, 1],
                convention='left_closed_right_open_last_includes_one', counts=histograms))


def score_selected(core, v, evaluation, c, frozen, base, rows, pairs, unpaired, classes):
    os.environ['HF_HUB_OFFLINE'] = '1'
    os.environ['TRANSFORMERS_OFFLINE'] = '1'
    manifest, _ = core.environment(base, c)
    require(manifest['base'] == frozen['base'], 'base_binding')
    common = importlib.import_module('common')
    cache = core.FeatureCache()
    try:
        scorer = core.Scorer(base, c, frozen['config']['threads'], cache=cache)
        scores, refusals = {}, {}
        for arm in ARMS:
            tensors, meta = common.load_checkpoint(frozen[arm]['path'])
            require(core.context_meta_ok(meta, arm, c, frozen['base']['weights_sha256']), 'checkpoint_metadata')
            common.apply_heads(scorer.model, tensors)
            scores[arm] = scorer.scores(rows, facts_blind=arm == 'control')
            refusals[arm] = scorer.last_refusals[:]
            del tensors
        keys = []
        for a, m in pairs:
            try:
                left = scorer.item(rows[a], facts_blind=True)['cache_key']
                right = scorer.item(rows[m], facts_blind=True)['cache_key']
                keys.append('identical' if left == right else 'different')
            except v.Refusal:
                keys.append('incomparable')
        thresholds = dict(context=frozen['threshold'], control=frozen['control_threshold'])
        return aggregate(rows, pairs, unpaired, scores, refusals, keys, thresholds, classes, evaluation.auroc)
    finally:
        cache.close()


def write_exclusive(path, value):
    """Publish a complete file atomically, without clobbering prior evidence."""
    path = safe(path)
    raw = canonical(value)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.d0-', delete=False) as f:
            temporary = Path(f.name)
            f.write(raw)
        os.link(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink()


class PrivateParser(argparse.ArgumentParser):
    def error(self, message):
        raise DiagnosticError('cli_arguments')


def parser():
    p = PrivateParser(description=__doc__)
    sub = p.add_subparsers(dest='command', required=True)
    for command in ('select', 'score'):
        s = sub.add_parser(command)
        for name in ('repo-root', 'freeze', 'expect-freeze-sha256', 'binding', 'out'):
            s.add_argument('--' + name, required=True)
        if command == 'score':
            s.add_argument('--base-dir', required=True)
            s.add_argument('--selection', required=True)
    return p


def execute(args):
    core, v, evaluation, c, frozen, selection, rows, pairs, unpaired = prepare(args)
    if args.command == 'select':
        write_exclusive(args.out, selection)
        return
    require(safe(args.selection).read_bytes() == canonical(selection), 'selection_binding')
    metrics = score_selected(core, v, evaluation, c, frozen, args.base_dir, rows, pairs,
                             unpaired, tuple(evaluation.CLASSES))
    report = dict(report_kind='development_diagnostic', identities=selection['identities'],
        sample_sha256=selection['sample_sha256'], selection_sha256=digest(canonical(selection)),
        thresholds=dict(context=frozen['threshold'], control=frozen['control_threshold']),
        data_reused_for_calibration=True, independent_quality='UNKNOWN', gate_b='UNSUPPORTED',
        activation_authorized=False, reading_rule=dict(READING_RULE),
        not_measured=['reinforcement', 'injection', 'deterministic', 'baseline', 'cost'], **metrics)
    write_exclusive(args.out, report)


def main(argv=None):
    try:
        execute(parser().parse_args(argv))
        return 0
    except DiagnosticError as exc:
        print(str(exc), file=sys.stderr)
    except Exception:
        print('diagnostic_refused', file=sys.stderr)
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
