"""sdc-baseline-replay-v1: label-free Rust replay and isolated offline CPU cost.

No held-out reader, download, HTTP, owner configuration or context_train import.
Caller supplies sanitized views. LB rows align exactly with views; caller alone
aggregates by class/normal label. Model can only add asks after pre_ask, so a
context ask count <= sum(pre_ask) proves the baseline gate for *all* heads.
Normal-row use assumes identical sanitized views and A1/A2/host-project fits.
"""
import argparse
import contextlib
import io
import json
import math
import os
from pathlib import Path
import resource
import statistics
import subprocess
import sys
import time
from types import SimpleNamespace

from context_v1 import (Unsupported, load_contract, validate_secret, serialize,
                        contract_hash, sha256, REVISION)

ASSUMPTIONS = [
    'A1: $NAME/${NAME} references else SECRET_1..n; no binding identity in view',
    'A1-hosts: known destinations reconstructed from command_hosts per item; no provider strings in view',
    'A2: remembered answers/patterns absent in both arms; built-in packs only; local brain',
    'A3: public decide_learned with weak task threshold 0.8 can allow weak known-safe reads; favors baseline',
    'sanitized synthetic request; host/project fits use parent-pinned human contract',
    'no hook/cloud/connector/browser/code/answer history beyond visible local_rule',
    'LB is conditional on these route assumptions; model can only add asks',
]
MAX_BYTES = 8 * 1024 * 1024
SHIPPED_SHA = '832249609f0cfd978cc7697326d55bc6d2676507eec13e5fb3f4bc6b35cfe850'


def visible_view(row):
    """Project before validation: labels, classes and pairing never enter replay."""
    return {**{k: row[k] for k in ('action', 'secrets', 'local_rule')},
            'request': {k: row['request'][k] for k in ('user_request', 'command', 'purpose')}}


def validate_view(v, c):
    if (set(v) != {'request', 'action', 'secrets', 'local_rule'}
            or set(v['request']) != {'user_request', 'command', 'purpose'}
            or any(type(x) is not str for x in v['request'].values())
            or v['action'] not in ('read', 'change', 'deploy', 'delete')
            or not isinstance(v['secrets'], list) or not 1 <= len(v['secrets']) <= 3
            or (v['local_rule'] is not None and type(v['local_rule']) is not str)):
        raise Unsupported('row_incoherent')
    for s in v['secrets']:
        validate_secret(s, c)
        if s['env_from'] == 'none':
            if (s['env'], s['scope'], s['scope_from'], s['sensitive'], s['project']) != ('unknown', 'unknown', 'none', 'unknown', 'undeclared'):
                raise Unsupported('row_incoherent')
        elif (s['scope_from'] == 'none' or 'unknown' in (s['env'], s['scope'], s['sensitive'])
              or (s['env'] == 'production' and s['sensitive'] != 'yes')):
            raise Unsupported('row_incoherent')


def _replay(views, binary_path, bodies=None):
    c = load_contract()
    for v in views:
        validate_view(v, c)
    payload = {'op': 'prepare' if bodies is None else 'decide', 'views': views}
    if bodies is not None:
        if len(bodies) != len(views):
            raise Unsupported('replay_alignment')
        payload['bodies'] = bodies
    raw = json.dumps(payload, allow_nan=False).encode()
    if len(raw) > MAX_BYTES or len(views) > 4096:
        raise Unsupported('replay_input_limit')
    if not binary_path or not Path(binary_path).is_file():
        raise Unsupported('route_binary_unavailable')
    try:
        p = subprocess.run([str(binary_path)], input=raw, stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, timeout=120, check=False)
        if len(p.stdout) > 32 * 1024 * 1024:
            raise Unsupported('replay_output_limit')
        reply = json.loads(p.stdout)
        if p.returncode:
            raise Unsupported('row_incoherent' if reply.get('reason') == 'row_incoherent' else 'replay_failed')
        rows = reply['rows']
        if reply['contract'] != 'sdc-baseline-replay-v1' or len(rows) != len(views):
            raise Unsupported('replay_alignment')
        if any(type(r.get('pre_ask')) is not bool or not isinstance(r.get('systemone_body'), dict)
               or (bodies is not None and (type(r.get('ask')) is not bool or (r['pre_ask'] and not r['ask']))) for r in rows):
            raise Unsupported('replay_reply')
        return rows
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError):
        raise Unsupported('replay_failed') from None


def baseline_lower_bound(views, binary_path):
    """No labels accepted. Returns aligned pre_ask, reasons, bodies, assumptions."""
    rows = _replay(views, binary_path)
    return {'pre_ask': [r['pre_ask'] for r in rows],
            'pre_reason': [r['pre_reason'] for r in rows],
            'diagnostics': [{'note': r.get('pre_note'), 'flags': r.get('analysis_flags')} for r in rows],
            'systemone_body': [r['systemone_body'] for r in rows],
            'assumptions': list(ASSUMPTIONS), 'contract': 'sdc-baseline-replay-v1'}


def baseline_with_heads(views, binary_path, base, shipped_heads=None, threads=4):
    """Only explicit shipped path can establish this arm. No stock fallback."""
    if not shipped_heads or not Path(shipped_heads).is_file():
        return {'status': 'UNSUPPORTED', 'reason': 'shipped_heads_unavailable'}
    if sha256(shipped_heads) != SHIPPED_SHA:
        raise Unsupported('shipped_heads_pin')
    prepared = baseline_lower_bound(views, binary_path)
    scorer = Predictor(base, 'baseline', threads, shipped_heads=shipped_heads)
    bodies = [scorer.predict_body(b) if not pre else {} for b, pre in
              zip(prepared['systemone_body'], prepared['pre_ask'])]
    rows = _replay(views, binary_path, bodies)
    return {'status': 'MEASURED', 'ask': [r['ask'] for r in rows],
            'assumptions': ASSUMPTIONS, 'heads_sha256': SHIPPED_SHA}


def offline():
    os.environ.update(HF_HUB_OFFLINE='1', TRANSFORMERS_OFFLINE='1', HF_HUB_DISABLE_TELEMETRY='1')
    def audit(event, args):
        if event in ('socket.connect', 'socket.getaddrinfo', 'socket.bind'):
            raise Unsupported('network_disabled')
        if event == 'open' and args and isinstance(args[0], (str, bytes, os.PathLike)):
            name = os.fsdecode(args[0])
            if 'secret-context-heldout' in name or 'secret_context_heldout' in name:
                raise Unsupported('heldout_forbidden')
    sys.addaudithook(audit)


class Predictor:
    """Pinned Agent + serve HeadSelection/MultiHeads + Laya Router predictor path.

    Context uses its own pinned question and stable context_v1 serializer. Exact
    headers/state are checked before every call; no truncation is permitted.
    """
    def __init__(self, base, arm, threads=4, context_heads=None, expect_context_sha256=None,
                 shipped_heads=None):
        offline()
        from importlib.metadata import version
        if version('laya') != '0.3.20':
            raise Unsupported('laya_version')
        import torch
        import common
        import serve
        from laya.agent import Agent
        from laya.common import DecisionModel
        from laya.router import Router
        self.c, self.arm = load_contract(), arm
        if arm not in ('context', 'baseline'):
            raise Unsupported('invalid_arm')
        self.manifest = json.loads((Path(__file__).parent / 'manifest.json').read_text())
        base = Path(base)
        if (self.manifest['base']['revision'] != REVISION
                or self.manifest['checkpoint']['sha256'] != SHIPPED_SHA
                or sha256(base / 'model.safetensors') != self.manifest['base']['weights_sha256']
                or sha256(base / self.c['tokenizer']['path']) != self.c['tokenizer']['sha256']):
            raise Unsupported('base_pin')
        torch.set_num_threads(threads)
        torch.set_num_interop_threads(1)
        self.agent = Agent(str(base), device='cpu')
        tuned = self.agent.model
        tuned.eval()
        if sum(p.numel() for n, p in tuned.named_parameters() if n.startswith(common.TRAINED_PREFIXES)) != 26248193:
            raise Unsupported('head_parameter_count')
        stock = None
        if arm == 'baseline':
            stock = DecisionModel(tuned.encoder, self.agent.cfg.get('head_layers', 2),
                                  len(self.agent.cfg.get('act_costs', {})) + 1)
            stock.load_state_dict(tuned.state_dict(), strict=True)
            stock.eval()
        checkpoint = shipped_heads if arm == 'baseline' else context_heads
        self.provenance = 'stock_public_informational'
        if checkpoint:
            digest = sha256(checkpoint)
            expected = SHIPPED_SHA if arm == 'baseline' else expect_context_sha256
            if not expected or digest != expected:
                raise Unsupported('heads_pin')
            tensors, meta = common.load_checkpoint(checkpoint)
            if arm == 'context' and (meta.get('context_contract_sha256') != contract_hash(self.c)
                    or meta.get('tokenizer_sha256') != self.c['tokenizer']['sha256']
                    or meta.get('question') != 'owner_accepts_use' or meta.get('facts_blind') is not False
                    or meta.get('base_revision') != REVISION
                    or meta.get('base_weights_sha256') != self.manifest['base']['weights_sha256']):
                raise Unsupported('context_heads_metadata')
            common.apply_heads(tuned, tensors)
            self.provenance = 'shipped' if arm == 'baseline' else 'experimental_context'
            self.heads_sha256 = digest
        elif arm == 'context':
            raise Unsupported('context_heads_unavailable')
        else:
            self.heads_sha256 = self.manifest['base']['weights_sha256']
        self.dual = serve.make_multi_heads(tuned, stock)
        self.agent.model = self.dual.eval()
        self.router = Router(max_loaded=1, default='english')
        self.router.attach('english', self.agent)
        self.serve = serve
        self.selection = SimpleNamespace(default=True, module=tuned,
                                         zero_shot={'leak'} if arm == 'baseline' else set())
        self.torch = torch

    def predict_body(self, body):
        state, questions = body['state'], body['questions']
        self.serve.require_complete_state(self.agent, state, questions)
        self.dual.request = self.serve.HeadSelection(self.selection, None, questions)
        try:
            with self.torch.inference_mode():
                return self.router.predict(state, questions, model='english')
        finally:
            self.dual.request = None

    def __call__(self, view):
        if self.arm == 'context':
            text, _ = serialize(view['request'], view['action'], view['secrets'], self.c)
            questions = {'owner_accepts_use': {k: v for k, v in self.c['question'].items() if k != 'id'}}
            return self.predict_body({'state': text, 'questions': questions})
        # Same five FACTS and state_text as Rust's empty-instruction request_body.
        from bench import FACTS
        from context_v1 import state_text
        return self.predict_body({'state': state_text(view['request']),
                                  'questions': {k: {'type': 'noul', 'instructions': v} for k, v in FACTS}})


def percentile(values, p):
    ordered = sorted(values)
    pos = (len(ordered) - 1) * p
    lo = math.floor(pos)
    return ordered[lo] + (ordered[math.ceil(pos)] - ordered[lo]) * (pos - lo)


def measure_arm(views, scorer, samples, clock=time.perf_counter, rss=None):
    """Injected scorer/clock/RSS support model-free checks. Timed encode+heads."""
    if not views or samples < 20:
        raise Unsupported('cost_samples')
    for i in range(3):
        scorer(views[i % len(views)])
    timings = []
    for i in range(samples):
        start = clock()
        scorer(views[i % len(views)])
        timings.append((clock() - start) * 1000)
    peak = rss() if rss else resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * (1024 if sys.platform.startswith('linux') else 1)
    return {'p50_ms': statistics.median(timings), 'p95_ms': percentile(timings, .95),
            'peak_rss_bytes': peak, 'samples': samples, 'warmups': 3}


def cost_record(baseline, context):
    if baseline['samples'] != context['samples'] or baseline['samples'] < 20:
        raise Unsupported('cost_samples')
    return {**{f'{arm}_{key}': record[key] for arm, record in
               [('context', context), ('baseline', baseline)]
               for key in ('p50_ms', 'p95_ms', 'peak_rss_bytes')}, 'samples': context['samples']}


def validation_views(path, n):
    # CLI accepts only generated validation data, not arbitrary replay/test rows.
    path = Path(path)
    if path.name != 'val.jsonl':
        raise Unsupported('G1_validation_required')
    manifest = json.loads((path.parent / 'data-manifest.json').read_text())
    if manifest['files']['val.jsonl']['sha256'] != sha256(path):
        raise Unsupported('validation_pin')
    views = []
    with open(path) as f:
        for line in f:
            row = json.loads(line)
            if not str(row.get('family', '')).startswith('G1:') or row.get('split', 'val') != 'val':
                raise Unsupported('G1_validation_required')
            v = visible_view(row)
            validate_view(v, load_contract())
            if len(v['secrets']) == n:
                views.append(v)
    if not views:
        raise Unsupported('validation_secret_count')
    return views


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--val', required=True, help='G1 val.jsonl pinned by adjacent data-manifest.json')
    p.add_argument('--base', required=True, help='already fetched pinned base directory')
    p.add_argument('--context-heads', required=True)
    p.add_argument('--expect-context-sha256', required=True)
    p.add_argument('--shipped-heads', help='optional explicit isolated shipped checkpoint; never fetched')
    p.add_argument('--mode', choices=['probe', 'full'], default='probe')
    p.add_argument('--threads', type=int, default=4)
    p.add_argument('--out', required=True)
    p.add_argument('--arm', choices=['baseline', 'context'], help=argparse.SUPPRESS)
    p.add_argument('--secrets', type=int, choices=[1, 3], help=argparse.SUPPRESS)
    a = p.parse_args(argv)
    try:
        offline()
        if not 1 <= a.threads <= 4:
            raise Unsupported('threads_limit')
        if sys.platform != 'linux' or os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('ImageOS') != 'ubuntu24':
            raise Unsupported('github_ubuntu_24_cpu_required')
        samples = 20 if a.mode == 'probe' else 50
        if a.arm:
            views = validation_views(a.val, a.secrets)
            with contextlib.redirect_stdout(io.StringIO()):
                scorer = Predictor(a.base, a.arm, a.threads, a.context_heads,
                                   a.expect_context_sha256, a.shipped_heads)
                result = measure_arm(views, scorer, samples)
            result.update(head_provenance=scorer.provenance, heads_sha256=scorer.heads_sha256)
        else:
            result = {'device': 'github-ubuntu-24.04-cpu', 'mode': a.mode,
                      'threads': a.threads, 'warmups': 3, 'head_provenance': {},
                      'pins': {'context': a.expect_context_sha256, 'base_revision': REVISION,
                               'context_contract_sha256': contract_hash(load_contract()),
                               'tokenizer_sha256': load_contract()['tokenizer']['sha256'],
                               'base_weights_sha256': json.loads((Path(__file__).parent / 'manifest.json').read_text())['base']['weights_sha256']},
                      'combined_process': {'status': 'NOT_RUN', 'informational': True}}
            import tempfile
            with tempfile.TemporaryDirectory(prefix='context-cost-') as tmp:
                for n in (1, 3):
                    arms = {}
                    for arm in ('baseline', 'context'):
                        out = str(Path(tmp) / f'{n}-{arm}.json')
                        args = [sys.executable, '-B', str(Path(__file__).resolve()),
                                '--val', a.val, '--base', a.base, '--context-heads', a.context_heads,
                                '--expect-context-sha256', a.expect_context_sha256, '--mode', a.mode,
                                '--threads', str(a.threads), '--out', out, '--arm', arm, '--secrets', str(n)]
                        if a.shipped_heads:
                            args.extend(['--shipped-heads', a.shipped_heads])
                        proc = subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                              timeout=3600, check=False)
                        if proc.returncode:
                            raise Unsupported('cost_arm_failed')
                        arms[arm] = json.loads(Path(out).read_text())
                        result['head_provenance'][arm] = arms[arm]['head_provenance']
                        result['pins'][arm + '_heads_sha256'] = arms[arm]['heads_sha256']
                    result[str(n)] = cost_record(arms['baseline'], arms['context'])
        Path(a.out).write_text(json.dumps(result, indent=2, allow_nan=False) + '\n')
        return 0
    except Unsupported as error:
        print(json.dumps({'status': 'UNSUPPORTED', 'reason': str(error)}))
        return 2
    except Exception:
        # No path, command, model diagnostic or user text in errors.
        print(json.dumps({'status': 'UNSUPPORTED', 'reason': 'cost_evidence_unavailable'}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
