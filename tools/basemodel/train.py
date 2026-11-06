#!/usr/bin/env python3
"""Fine-tune the decision heads of Laya on the base-model set (goal B8).

The encoder (ModernBERT-large) stays frozen. The heads (`head`, `type_emb`,
`scorer`, about 26M parameters) learn the `noul` answers of the six Apassy
questions. The loss is the cross-entropy of the two noul options after the
division by the noul temperature, the same scale that Laya uses when it returns a
probability. So a trained probability is the served probability.

Input: `train.jsonl` and `val.jsonl` from `gen_data.py`.
Output: one safetensors file with the head tensors and a metadata block, and a
JSON report with the time, the memory, and the validation metrics.

The local fine-tune (goal B9, `tools/finetune/local_train.py`) uses the same
trainer with three options:
- `--init <checkpoint>` starts from the heads of the shipped base model.
- A row can have a soft `answer` from 0 to 1. The loss is the cross-entropy with
  the target distribution (1 - answer, answer). For 0 and 1 it is the same loss.
- A row with `"teacher": true` gets the answer of the starting heads as its
  target, so the fine-tune keeps that answer ("learning without forgetting").

Run inside the Laya virtual environment (see docs/operations/base-model.md):
  TMPDIR=/tmp .venv/bin/python tools/basemodel/train.py --data <dir> --out <file>
"""

import argparse
import hashlib
import importlib.metadata
import json
import math
import os
import platform
import random
import subprocess
import sys
import time

import numpy as np
import torch
import torch.nn.functional as F

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import common  # noqa: E402

QUESTIONS = ["task_match", "writes", "remote", "leak", "destroy", "rule_break", "owner_accepts_use"]


# Every key authored by the trainer is reserved, including the base pin.
RESERVED_METADATA = frozenset(('name', 'base_repo', 'base_revision', 'trained',
                               'noul_temperature', 'epoch', 'runtime_profile', 'training_objective'))


def extra_metadata(raw):
    """Parse caller fields before any training; trainer-owned fields cannot collide."""
    if raw is None:
        return {}
    if os.path.isfile(raw):
        with open(raw, encoding="utf-8") as source:
            fields = json.load(source)
    else:
        fields = json.loads(raw)
    if not isinstance(fields, dict):
        raise ValueError('metadata must be a JSON object')
    if RESERVED_METADATA.intersection(fields):
        raise ValueError('metadata collides with reserved trainer keys')
    return fields


def runtime_settings(seed):
    """Read effective controls; missing APIs and ineffective setters fail closed."""
    try:
        b = torch.backends
        precision = [b, b.cuda.matmul, b.cudnn, b.cudnn.conv, b.cudnn.rnn]
        flags = dict(deterministic=torch.are_deterministic_algorithms_enabled(),
                     warn_only=torch.is_deterministic_algorithms_warn_only_enabled(),
                     cudnn_benchmark=b.cudnn.benchmark, cudnn_deterministic=b.cudnn.deterministic,
                     fill_uninitialized_memory=torch.utils.deterministic.fill_uninitialized_memory,
                     fp32_precision=[p.fp32_precision for p in precision], threads=torch.get_num_threads())
        expected = dict(deterministic=True, warn_only=False, cudnn_benchmark=False,
                        cudnn_deterministic=True, fill_uninitialized_memory=True,
                        fp32_precision=['ieee'] * 5, threads=4)
        env = {k: os.environ.get(k) for k in
               ('PYTHONHASHSEED', 'CUBLAS_WORKSPACE_CONFIG', 'NVIDIA_TF32_OVERRIDE')}
        if flags != expected or env != dict(PYTHONHASHSEED=str(seed),
                                            CUBLAS_WORKSPACE_CONFIG=':4096:8', NVIDIA_TF32_OVERRIDE='0'):
            raise RuntimeError('deterministic runtime controls ineffective or changed')
        if torch.__version__ != '2.14.0+cu130' or torch.version.cuda != '13.0':
            raise RuntimeError('deterministic profile requires torch 2.14.0+cu130 / CUDA 13.0')
        return dict(flags=flags, environment=env)
    except (AttributeError, TypeError) as exc:
        raise RuntimeError('deterministic runtime readback unavailable') from exc


def configure_runtime(args):
    """Opt-in only, before manual_seed, Agent import, or any CUDA initialization.

    PYTHONHASHSEED must be supplied at process startup; assigning it here cannot
    establish Python hash determinism. No cross-hardware equality is promised.
    """
    if args.runtime_profile != 'cuda-deterministic-v1':
        raise ValueError('unsupported runtime profile')
    if (args.device != 'cuda' and not (args.device.startswith('cuda:')
            and args.device[5:].isascii() and args.device[5:].isdigit())) or not args.no_amp:
        raise ValueError('deterministic profile requires CUDA and --no-amp')
    if type(args.seed) is not int or not 0 <= args.seed < 2 ** 32:
        raise ValueError('deterministic profile seed must be an unsigned 32-bit integer')
    if torch.__version__ != '2.14.0+cu130' or torch.version.cuda != '13.0':
        raise ValueError('deterministic profile requires torch 2.14.0+cu130 / CUDA 13.0')
    if torch.cuda.is_initialized():
        raise RuntimeError('CUDA already initialized before runtime configuration')
    required = dict(PYTHONHASHSEED=str(args.seed), CUBLAS_WORKSPACE_CONFIG=':4096:8',
                    NVIDIA_TF32_OVERRIDE='0')
    for key, value in required.items():
        actual = os.environ.get(key)
        if actual != value and (actual is not None or key == 'PYTHONHASHSEED'):
            raise ValueError('conflicting or missing startup environment: ' + key)
    for key, value in required.items():
        if key != 'PYTHONHASHSEED':
            os.environ.setdefault(key, value)
    try:
        torch.use_deterministic_algorithms(True, warn_only=False)
        b = torch.backends
        b.cudnn.benchmark = False
        b.cudnn.deterministic = True
        torch.utils.deterministic.fill_uninitialized_memory = True
        for target in (b, b.cuda.matmul, b.cudnn, b.cudnn.conv, b.cudnn.rnn):
            getattr(target, 'fp32_precision')
            target.fp32_precision = 'ieee'
        if torch.get_num_threads() != 4:
            torch.set_num_threads(4)
        settings = runtime_settings(args.seed)
    except (AttributeError, TypeError) as exc:
        raise RuntimeError('deterministic runtime API unavailable') from exc
    if not torch.cuda.is_available():
        raise RuntimeError('CUDA unavailable for deterministic profile')
    if ':' in args.device and int(args.device[5:]) >= torch.cuda.device_count():
        raise ValueError('requested CUDA device unavailable')
    np.random.seed(args.seed)
    return settings


def initial_head_sha256(model):
    """Length-frame sorted head descriptors and CPU array bytes, never log values."""
    state = common.head_state(model)
    if not isinstance(state, dict) or not state or any(type(k) is not str or not k for k in state):
        raise ValueError('invalid or empty trained-head state')
    digest = hashlib.sha256()
    for name in sorted(state):
        tensor = state[name]
        shape = list(tensor.shape)
        dtype = str(tensor.dtype)
        itemsize = tensor.element_size()
        if (not name.startswith(common.TRAINED_PREFIXES) or not dtype.startswith('torch.')
                or type(itemsize) is not int or itemsize <= 0
                or any(type(n) is not int or n <= 0 for n in shape)):
            raise ValueError('invalid trained-head tensor')
        raw = tensor.numpy().tobytes(order='C')
        if not isinstance(raw, bytes) or len(raw) != math.prod(shape) * itemsize:
            raise ValueError('invalid trained-head bytes')
        descriptor = json.dumps([name, shape, str(tensor.dtype)], ensure_ascii=True,
                                separators=(',', ':')).encode('ascii')
        for part in (descriptor, raw):
            digest.update(len(part).to_bytes(8, 'big'))
            digest.update(part)
    return digest.hexdigest()


def runtime_identity(device):
    index = torch.cuda.current_device() if device.index is None else device.index
    # Resolve exactly the model's selected device, without serial/host identifiers.
    if torch.cuda.current_device() != index:
        raise RuntimeError('profile requires the selected CUDA device to be current')
    name = torch.cuda.get_device_name(index)
    capability = list(torch.cuda.get_device_capability(index))
    if (type(index) is not int or index < 0 or type(name) is not str or not name
            or len(capability) != 2 or any(type(n) is not int or n < 0 for n in capability)):
        raise RuntimeError('CUDA device identity unavailable')
    cudnn = torch.backends.cudnn.version()
    if type(cudnn) is not int or cudnn <= 0:
        raise RuntimeError('cuDNN identity unavailable')
    return dict(torch=str(torch.__version__), cuda=torch.version.cuda, cudnn=cudnn,
                python=platform.python_version(), numpy=np.__version__,
                packages={p: importlib.metadata.version(p) for p in ('laya', 'transformers', 'tokenizers')},
                device=dict(index=index, name=name, compute_capability=capability))


def attest_runtime(args, device, model, startup):
    effective = runtime_settings(args.seed)
    if effective != startup:
        raise RuntimeError('runtime changed during model initialization')
    return dict(schema=1, profile=args.runtime_profile, seed=args.seed, effective=effective,
                software=runtime_identity(device), initial_head_sha256=initial_head_sha256(model))


def validate_runtime(seal, device):
    if (runtime_settings(seal['seed']) != seal['effective']
            or runtime_identity(device) != seal['software']):
        raise RuntimeError('deterministic runtime attestation drift')


def on_ac_power():
    try:
        out = subprocess.run(["pmset", "-g", "batt"], capture_output=True, text=True).stdout
    except OSError:
        return None
    return "AC Power" in out


def load_rows(path, limit=0):
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rows.append(json.loads(line))
    return rows[:limit] if limit else rows


def encode(agent, rows):
    """Tokenize each example with Laya's own pipeline. One item per example."""
    from laya.agent import Agent

    internal_by_text = {}
    items = []
    for r in rows:
        text = r["instructions"]
        if text not in internal_by_text:
            internal_by_text[text] = Agent._to_internal({"type": "noul", "instructions": text})
        it = agent._encode_state(r["state"], ["q"], {"q": internal_by_text[text]})[0]
        items.append({"ids": it["ids"], "markers": it["markers"], "qtype": it["qtype"],
                      "y": float(r["answer"]), "q": QUESTIONS.index(r["question"]),
                      "teacher": bool(r.get("teacher", False))})
    return items


def collate(items, pad):
    n = len(items)
    # Round the length up to a multiple of 32. Fewer tensor shapes keep the MPS
    # allocator cache small.
    length = max(len(it["ids"]) for it in items)
    length = min(512, (length + 31) // 32 * 32)
    ids = torch.full((n, length), pad, dtype=torch.long)
    att = torch.zeros((n, length), dtype=torch.long)
    mpos = torch.zeros((n, 2), dtype=torch.long)
    for i, it in enumerate(items):
        ids[i, :len(it["ids"])] = torch.tensor(it["ids"])
        att[i, :len(it["ids"])] = 1
        mpos[i] = torch.tensor(it["markers"])
    return {
        "input_ids": ids,
        "attention_mask": att,
        "marker_pos": mpos,
        "marker_mask": torch.ones((n, 2), dtype=torch.bool),
        "qtype": torch.tensor([it["qtype"] for it in items]),
        "y": torch.tensor([it["y"] for it in items], dtype=torch.float32),
        "q": torch.tensor([it["q"] for it in items]),
    }


def batch_tail_term(logits, y, temperature):
    """Opt-in hard-label batch tail; amax shares gradients across maximum ties."""
    import numbers
    if not isinstance(temperature, numbers.Real) or isinstance(temperature, bool):
        raise ValueError('invalid batch-tail temperature')
    try:
        temperature = float(temperature)
    except (OverflowError, ValueError) as exc:
        raise ValueError('invalid batch-tail temperature') from exc
    if not math.isfinite(temperature) or temperature <= 0:
        raise ValueError('invalid batch-tail temperature')
    if (not isinstance(logits, torch.Tensor) or not logits.is_floating_point()
            or logits.layout != torch.strided
            or logits.ndim != 2 or logits.shape[0] == 0 or logits.shape[1] != 2
            or not bool(torch.isfinite(logits).all())):
        raise ValueError('invalid batch-tail logits')
    if (not isinstance(y, torch.Tensor) or y.layout != torch.strided or y.is_complex() or y.requires_grad
            or y.ndim != 1 or y.shape[0] != logits.shape[0] or y.device != logits.device
            or not bool(torch.isfinite(y).all()) or not bool(((y == 0) | (y == 1)).all())):
        raise ValueError('invalid batch-tail labels')
    if not bool(torch.isfinite(logits / temperature).all()):
        raise ValueError('nonfinite batch-tail normalized logits')
    z = (logits[:, 1] - logits[:, 0]) / temperature
    if not bool(torch.isfinite(z).all()):
        raise ValueError('nonfinite batch-tail scores')
    positive, negative = y == 1, y == 0
    if not bool(positive.any()) or not bool(negative.any()):
        return logits.new_zeros(()), 'positive_only' if bool(positive.any()) else 'negative_only'
    top = torch.amax(z.masked_fill(positive, -math.inf))
    delta = top - z
    if not bool(torch.isfinite(delta).all()):
        raise ValueError('nonfinite batch-tail differences')
    terms = F.softplus(delta) * positive
    tail = terms.sum() / positive.sum()
    if not bool(torch.isfinite(terms).all()) or not bool(torch.isfinite(tail)):
        raise ValueError('nonfinite batch-tail term')
    return tail, 'mixed'


def objective_items_ok(items):
    """Validate encoded splits without changing labels or teacher targets."""
    if not isinstance(items, (list, tuple)):
        raise ValueError('objective requires encoded items')
    classes = set()
    for item in items:
        if (not isinstance(item, dict) or type(item.get('y')) not in (int, float)
                or item['y'] not in (0, 1) or item.get('teacher') is not False
                or type(item.get('q')) is not int or item['q'] != QUESTIONS.index('owner_accepts_use')):
            raise ValueError('objective requires hard owner_accepts_use non-teacher items')
        classes.add(item['y'])
    if classes != {0, 1}:
        raise ValueError('objective requires both classes in each split')


def targets(y):
    """The two-option target distribution (no, yes) for a soft or hard answer."""
    return torch.stack([1.0 - y, y], -1)


class LoRALinear(torch.nn.Module):
    """A frozen linear layer plus a trainable low-rank update B @ A (LoRA)."""

    def __init__(self, base, rank, alpha):
        super().__init__()
        self.base = base
        self.lora_A = torch.nn.Parameter(torch.randn(rank, base.in_features, device=base.weight.device) / rank)
        self.lora_B = torch.nn.Parameter(torch.zeros(base.out_features, rank, device=base.weight.device))
        self.scale = alpha / rank

    def forward(self, x):
        return self.base(x) + (x @ self.lora_A.t() @ self.lora_B.t()) * self.scale


def add_lora(model, layers, rank, alpha):
    """Wrap the attention and MLP projections of the last `layers` encoder layers."""
    params = []
    for layer in model.encoder.layers[-layers:]:
        for parent, name in ((layer.attn, "Wqkv"), (layer.attn, "Wo"), (layer.mlp, "Wi"), (layer.mlp, "Wo")):
            wrapped = LoRALinear(getattr(parent, name), rank, alpha)
            setattr(parent, name, wrapped)
            params += [wrapped.lora_A, wrapped.lora_B]
    return params


def encoder_states(model, batch, device, amp, grad=False):
    """Encoder output. With LoRA (`grad=True`), autograd records only the adapted layers,
    because the earlier layers have no parameter that needs a gradient."""
    with torch.set_grad_enabled(grad):
        ctx = torch.autocast(device_type=device.type, dtype=torch.float16) if amp else torch.autocast(device_type="cpu", enabled=False)
        with ctx:
            h = model.encoder(input_ids=batch["input_ids"].to(device),
                              attention_mask=batch["attention_mask"].to(device)).last_hidden_state
    return h.float()


class FeatureCache:
    """Frozen encoder outputs on disk (float16), one row per real token.

    The encoder does not change during a heads-only fine-tune, so one encoder pass
    over the data is enough. The head sees padded positions only as masked keys,
    so a zero row for a padded position gives the same answer.
    """

    def __init__(self, folder, name):
        self.path = os.path.join(folder, name + ".f16")
        self.index_path = os.path.join(folder, name + ".json")
        self.index = None
        self.data = None

    def ready(self, fingerprint):
        if not (os.path.exists(self.path) and os.path.exists(self.index_path)):
            return False
        meta = json.load(open(self.index_path))
        return meta.get("fingerprint") == fingerprint

    def build(self, model, items, pad, device, amp, batch_size, fingerprint, hidden):
        model.eval()
        total = sum(len(it["ids"]) for it in items)
        data = np.lib.format.open_memmap(self.path + ".tmp", mode="w+", dtype=np.float16, shape=(total, hidden))
        offsets, pos = [], 0
        for it in items:
            offsets.append(pos)
            pos += len(it["ids"])
        t = time.time()
        with torch.no_grad():
            for n, idx in enumerate(batches(items, batch_size, random.Random(0), False)):
                b = collate([items[i] for i in idx], pad)
                h = encoder_states(model, b, device, amp).half().cpu().numpy()
                for row, i in enumerate(idx):
                    length = len(items[i]["ids"])
                    data[offsets[i]:offsets[i] + length] = h[row, :length]
                if n % 100 == 0:
                    print("cache %s: batch %d, %.0fs" % (os.path.basename(self.path), n, time.time() - t), flush=True)
                    release_cache()
        data.flush()
        del data
        os.replace(self.path + ".tmp", self.path)
        with open(self.index_path, "w") as f:
            json.dump({"fingerprint": fingerprint, "offsets": offsets,
                       "lengths": [len(it["ids"]) for it in items]}, f)

    def open(self):
        meta = json.load(open(self.index_path))
        self.offsets, self.lengths = meta["offsets"], meta["lengths"]
        self.data = np.load(self.path, mmap_mode="r")

    def batch(self, idx, device):
        length = min(512, (max(self.lengths[i] for i in idx) + 31) // 32 * 32)
        out = np.zeros((len(idx), length, self.data.shape[1]), dtype=np.float16)
        for row, i in enumerate(idx):
            n = self.lengths[i]
            out[row, :n] = self.data[self.offsets[i]:self.offsets[i] + n]
        return torch.from_numpy(out).to(device).float()


def head_logits(model, h, batch, device):
    """The head part of `DecisionModel.forward`, on frozen encoder states."""
    attention_mask = batch["attention_mask"].to(device)
    qtype = batch["qtype"].to(device)
    marker_pos = batch["marker_pos"].to(device)
    marker_mask = batch["marker_mask"].to(device)
    h = h + model.type_emb(qtype)[:, None, :]
    pad = ~attention_mask.bool()
    for layer in model.head.layers:
        h = layer(h, src_key_padding_mask=pad)
    idx = marker_pos.clamp(min=0)[:, :, None].expand(-1, -1, h.size(-1))
    m = torch.gather(h, 1, idx)
    logits = model.scorer(m).squeeze(-1).float()
    return logits.masked_fill(~marker_mask, -1e4)


def batches(items, size, rng, shuffle):
    """Batches of similar length, in random order."""
    order = list(range(len(items)))
    if shuffle:
        rng.shuffle(order)
    chunk = size * 50
    out = []
    for start in range(0, len(order), chunk):
        part = sorted(order[start:start + chunk], key=lambda i: len(items[i]["ids"]))
        out.extend(part[i:i + size] for i in range(0, len(part), size))
    if shuffle:
        rng.shuffle(out)
    return out


def ece(p, y, bins=10):
    p, y = np.asarray(p), np.asarray(y)
    edges = np.linspace(0, 1, bins + 1)
    total = 0.0
    for i in range(bins):
        sel = (p >= edges[i]) & (p <= edges[i + 1]) if i == 0 else (p > edges[i]) & (p <= edges[i + 1])
        if sel.any():
            total += sel.mean() * abs(p[sel].mean() - y[sel].mean())
    return float(total)


def validation_operating_point(probabilities, hard_targets):
    """Aggregate development recall above every negative; never filter invalid pairs.

    Inputs are plain lists of probabilities and binary targets. Soft targets remain
    valid for the generic trainer, but cannot support this empirical interpretation.
    No individual score or fitted threshold is returned.
    """
    coverage = dict(probabilities=0, targets=0, aligned=False, valid_pairs=0,
                    invalid_probabilities=0, nonfinite_probabilities=0,
                    invalid_targets=0, nonfinite_targets=0, soft_targets=0)
    result = dict(status="incomplete", coverage=coverage, positive_count=0,
                  negative_count=0, safe_positive_count=None, safe_positive_recall=None,
                  negative_boundary_ties=None, histograms=None)
    if not isinstance(probabilities, (list, tuple)) or not isinstance(hard_targets, (list, tuple)):
        return result
    coverage.update(probabilities=len(probabilities), targets=len(hard_targets),
                    aligned=len(probabilities) == len(hard_targets))

    def classify(value):
        if type(value) not in (int, float):
            return "invalid"
        if type(value) is float and not math.isfinite(value):
            return "nonfinite"
        return "valid" if 0 <= value <= 1 else "invalid"

    for p in probabilities:
        kind = classify(p)
        if kind != "valid":
            coverage[kind + "_probabilities"] += 1
    for y in hard_targets:
        kind = classify(y)
        if kind != "valid":
            coverage[kind + "_targets"] += 1
        elif y not in (0, 1):
            coverage["soft_targets"] += 1
        elif y == 1:
            result["positive_count"] += 1
        else:
            result["negative_count"] += 1
    coverage["valid_pairs"] = sum(classify(p) == "valid" and classify(y) == "valid" and y in (0, 1)
                                  for p, y in zip(probabilities, hard_targets))
    if (not coverage["aligned"] or coverage["invalid_probabilities"]
            or coverage["nonfinite_probabilities"] or coverage["invalid_targets"]
            or coverage["nonfinite_targets"]):
        return result
    if coverage["soft_targets"]:
        result["status"] = "unsupported_soft_targets"
        return result

    counts = {"positive": [0] * 10, "negative": [0] * 10}
    for p, y in zip(probabilities, hard_targets):
        counts["positive" if y == 1 else "negative"][min(9, int(p * 10))] += 1
    result["histograms"] = dict(bins=10, range=[0, 1],
                                convention="left_closed_right_open_last_includes_one", counts=counts)
    if not result["positive_count"] or not result["negative_count"]:
        result["status"] = "unavailable_class"
        return result
    boundary = max(p for p, y in zip(probabilities, hard_targets) if y == 0)
    allowed = sum(p > boundary for p, y in zip(probabilities, hard_targets) if y == 1)
    result.update(status="complete", safe_positive_count=allowed,
                  safe_positive_recall=allowed / result["positive_count"],
                  negative_boundary_ties=dict(
                      positive=sum(p == boundary for p, y in zip(probabilities, hard_targets) if y == 1),
                      negative=sum(p == boundary for p, y in zip(probabilities, hard_targets) if y == 0)))
    return result


def evaluate(model, items, pad, device, amp, temperature, batch_size, cache=None):
    model.eval()
    probs, ys, qs = [], [], []
    with torch.no_grad():
        for idx in batches(items, batch_size, random.Random(0), False):
            b = collate([items[i] for i in idx], pad)
            h = cache.batch(idx, device) if cache else encoder_states(model, b, device, amp)
            logits = head_logits(model, h, b, device)
            p = torch.softmax(logits / temperature, -1)[:, 1]
            probs.extend(p.cpu().tolist())
            ys.extend(b["y"].tolist())
            qs.extend(b["q"].tolist())
    probs, ys, qs = np.array(probs), np.array(ys), np.array(qs)
    report = {}
    for qi, name in enumerate(QUESTIONS):
        sel = qs == qi
        if not sel.any():
            continue
        p, y = probs[sel], ys[sel]
        eps = 1e-6
        nll = float(-np.mean(y * np.log(p + eps) + (1 - y) * np.log(1 - p + eps)))
        yes = y >= 0.5
        report[name] = {
            "n": int(sel.sum()),
            "accuracy": float(np.mean((p >= 0.5) == yes)),
            "nll": nll,
            "brier": float(np.mean((p - y) ** 2)),
            "ece": ece(p, y),
            "mean_p_yes": float(p[yes].mean()) if yes.any() else None,
            "mean_p_no": float(p[~yes].mean()) if (~yes).any() else None,
        }
        if name == "owner_accepts_use":
            operating_point = validation_operating_point(p.tolist(), y.tolist())
            operating_point.update(evidence="trainer_validation_cache", interpretation="development_only")
            report[name]["operating_point"] = operating_point
    report["all_nll"] = float(np.mean([v["nll"] for k, v in report.items() if isinstance(v, dict)]))
    return report


def teacher_targets(model, items, pad, device, amp, temperature, batch_size, cache=None):
    """Give each teacher row the answer of the current heads as its target.

    Call it before the first step, so the target is the answer of the starting
    model. Returns the number of teacher rows.
    """
    rows = [i for i, it in enumerate(items) if it.get("teacher")]
    model.eval()
    with torch.no_grad():
        for start in range(0, len(rows), batch_size):
            idx = rows[start:start + batch_size]
            b = collate([items[i] for i in idx], pad)
            h = cache.batch(idx, device) if cache else encoder_states(model, b, device, amp)
            p = torch.softmax(head_logits(model, h, b, device) / temperature, -1)[:, 1]
            for i, value in zip(idx, p.cpu().tolist()):
                items[i]["y"] = float(value)
    return len(rows)


def mps_memory_gb():
    """Driver memory of the MPS allocator (tensors and cache), in GB."""
    if torch.backends.mps.is_available():
        return torch.mps.driver_allocated_memory() / 1e9
    return 0.0


def mps_tensor_gb():
    """Memory of live MPS tensors, in GB."""
    if torch.backends.mps.is_available():
        return torch.mps.current_allocated_memory() / 1e9
    return 0.0


def release_cache():
    if torch.backends.mps.is_available():
        torch.mps.empty_cache()


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True, help="folder with train.jsonl and val.jsonl")
    ap.add_argument("--out", required=True, help="checkpoint path (.safetensors)")
    ap.add_argument("--base-dir", default="", help="existing local base directory; caller verifies weight pins")
    ap.add_argument("--metadata", default=None, help="extra checkpoint fields: JSON object or local JSON file")
    ap.add_argument("--init", default="", help="start from the heads of this checkpoint (goal B9)")
    ap.add_argument("--name", default=common.MODEL_NAME, help="model name in the version <name>+<hash8>")
    ap.add_argument("--report", default="", help="JSON report path (default: <out>.report.json)")
    ap.add_argument("--epochs", type=int, default=4)
    ap.add_argument("--batch", type=int, default=32)
    ap.add_argument("--lr", type=float, default=3e-4)
    ap.add_argument("--weight-decay", type=float, default=0.01)
    ap.add_argument("--warmup", type=int, default=100)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--device", default="mps")
    ap.add_argument("--require-device", action="store_true", help="refuse device fallback")
    ap.add_argument("--limit", type=int, default=0, help="use only the first N training rows (a probe)")
    ap.add_argument("--max-steps", type=int, default=0)
    ap.add_argument("--no-amp", action="store_true")
    ap.add_argument("--runtime-profile", choices=('cuda-deterministic-v1',), default=None)
    ap.add_argument("--objective", choices=('bce-plus-batch-tail-v1',), default=None)
    ap.add_argument("--skip-baseline", action="store_true")
    ap.add_argument("--lora-layers", type=int, default=0,
                    help="also train LoRA adapters in the last N encoder layers (measurement only, no checkpoint)")
    ap.add_argument("--lora-rank", type=int, default=8)
    ap.add_argument("--lora-alpha", type=float, default=16.0)
    ap.add_argument("--cache-dir", default="", help="folder for the encoder cache (default: next to --out)")
    ap.add_argument("--keep-cache", action="store_true", help="keep the encoder cache after training")
    args = ap.parse_args(argv)

    if args.metadata is not None:
        from context_train import install_training_audit
        install_training_audit()
    metadata = extra_metadata(args.metadata)
    if args.base_dir and not os.path.isdir(args.base_dir):
        raise ValueError('base-dir must be an existing local directory')

    if args.objective is not None:
        if args.init or args.lora_layers:
            raise ValueError('objective does not support --init or --lora-layers')

    if args.runtime_profile is not None:
        runtime_startup = configure_runtime(args)

    random.seed(args.seed)
    torch.manual_seed(args.seed)
    rng = random.Random(args.seed)
    device = torch.device(args.device if (args.device != "mps" or torch.backends.mps.is_available()) else "cpu")
    if args.require_device and str(device) != args.device:
        raise ValueError('requested device unavailable; fallback refused')
    amp = device.type in ("mps", "cuda") and not args.no_amp
    ac = on_ac_power()
    print("AC power: %s" % ac, flush=True)

    from laya.agent import Agent

    t0 = time.time()
    base = args.base_dir or common.base_dir()
    agent = Agent(base, device=str(device))
    model = agent.model
    pad = agent.tok.pad_token_id
    temperature = common.noul_temperature(agent)
    print("base %s@%s loaded in %.1fs on %s, noul temperature %.4f" % (
        common.BASE_REPO, common.BASE_REVISION[:12], time.time() - t0, device, temperature), flush=True)
    init_sha = None
    if args.init:
        tensors, _meta = common.load_checkpoint(args.init)
        common.apply_heads(model, tensors)
        init_sha = common.sha256_file(args.init)
        print("heads from %s (sha256 %s)" % (args.init, init_sha[:8]), flush=True)

    if args.runtime_profile is not None:
        runtime_seal = attest_runtime(args, device, model, runtime_startup)

    train_rows = load_rows(os.path.join(args.data, "train.jsonl"), args.limit)
    val_rows = load_rows(os.path.join(args.data, "val.jsonl"))
    t_enc = time.time()
    train_items = encode(agent, train_rows)
    val_items = encode(agent, val_rows)
    if args.objective is not None:
        objective_items_ok(train_items)
        objective_items_ok(val_items)
    print("encoded %d train and %d val examples in %.1fs" % (len(train_items), len(val_items), time.time() - t_enc), flush=True)

    for p in model.parameters():
        p.requires_grad_(False)
    trainable = [p for n, p in model.named_parameters() if n.startswith(common.TRAINED_PREFIXES)]
    for p in trainable:
        p.requires_grad_(True)
    if args.lora_layers:
        trainable += add_lora(model, args.lora_layers, args.lora_rank, args.lora_alpha)
    n_train = sum(p.numel() for p in trainable)
    print("trainable %.1fM parameters (%s)" % (n_train / 1e6, "heads and LoRA r%d in the last %d layers" % (
        args.lora_rank, args.lora_layers) if args.lora_layers else "heads only"), flush=True)

    # Heads only: one encoder pass over the data, stored on disk in float16.
    train_cache = val_cache = None
    cache_seconds = 0.0
    cache_dir = args.cache_dir or os.path.join(os.path.dirname(os.path.abspath(args.out)), "encoder-cache")
    if not args.lora_layers:
        os.makedirs(cache_dir, exist_ok=True)
        fingerprint = {}
        for name in ("train", "val"):
            digest = common.sha256_file(os.path.join(args.data, name + ".jsonl"))
            limit = args.limit if name == "train" else 0
            fingerprint[name] = "%s:%s:%s:%s:%d" % (digest, common.BASE_REVISION, amp, device.type, limit)
        t_c = time.time()
        caches = {}
        for name, items in (("train", train_items), ("val", val_items)):
            cache = FeatureCache(cache_dir, name)
            if not cache.ready(fingerprint[name]):
                cache.build(model, items, pad, device, amp, args.batch, fingerprint[name],
                            model.encoder.config.hidden_size)
            cache.open()
            caches[name] = cache
        cache_seconds = time.time() - t_c
        train_cache, val_cache = caches["train"], caches["val"]
        # The heads read the cache. Free the GPU memory of the encoder.
        model.encoder.to("cpu")
        release_cache()
        print("encoder cache ready in %.0fs" % cache_seconds, flush=True)

    # Teacher rows get the answer of the starting heads, before any step.
    teachers = teacher_targets(model, train_items, pad, device, amp, temperature, args.batch, train_cache)
    teachers += teacher_targets(model, val_items, pad, device, amp, temperature, args.batch, val_cache)
    if teachers:
        print("teacher targets for %d rows" % teachers, flush=True)

    baseline = None
    if not args.skip_baseline:
        t_b = time.time()
        baseline = evaluate(model, val_items, pad, device, amp, temperature, args.batch, val_cache)
        print("zero-shot val: %s (%.0fs)" % (json.dumps({k: round(v["nll"], 3) for k, v in baseline.items() if isinstance(v, dict)}), time.time() - t_b), flush=True)

    opt = torch.optim.AdamW(trainable, lr=args.lr, weight_decay=args.weight_decay)
    steps_per_epoch = math.ceil(len(train_items) / args.batch)
    total_steps = steps_per_epoch * args.epochs
    if args.max_steps:
        total_steps = min(total_steps, args.max_steps)

    def lr_at(step):
        if step < args.warmup:
            return args.lr * (step + 1) / args.warmup
        progress = (step - args.warmup) / max(1, total_steps - args.warmup)
        return args.lr * 0.5 * (1 + math.cos(math.pi * min(1.0, progress)))

    release_cache()
    peak = mps_memory_gb()
    peak_tensors = mps_tensor_gb()
    history = []
    best = None
    step = 0
    t_train = time.time()
    for epoch in range(args.epochs):
        model.eval()
        model.head.train()
        running, count = 0.0, 0
        window, window_n = 0.0, 0
        if args.objective is not None:
            train_ce = train_tail = 0.0
            objective_batches = dict(mixed=0, positive_only=0, negative_only=0)
        for idx in batches(train_items, args.batch, rng, True):
            b = collate([train_items[i] for i in idx], pad)
            if train_cache:
                h = train_cache.batch(idx, device)
            else:
                h = encoder_states(model, b, device, amp, grad=bool(args.lora_layers))
            logits = head_logits(model, h, b, device)
            loss = F.cross_entropy(logits / temperature, targets(b["y"]).to(device))
            if args.objective is not None:
                tail, kind = batch_tail_term(logits, b["y"].to(device), temperature)
                train_ce += float(loss.detach()) * len(idx)
                train_tail += float(tail.detach()) * len(idx)
                objective_batches[kind] += 1
                loss = loss + tail
            for g in opt.param_groups:
                g["lr"] = lr_at(step)
            opt.zero_grad(set_to_none=True)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(trainable, 1.0)
            opt.step()
            value = float(loss.detach())
            running += value * len(idx)
            count += len(idx)
            window += value * len(idx)
            window_n += len(idx)
            step += 1
            if step % 25 == 0:
                peak = max(peak, mps_memory_gb())
                peak_tensors = max(peak_tensors, mps_tensor_gb())
                release_cache()
            if step % 50 == 0:
                print("epoch %d step %d/%d loss %.4f (last 50: %.4f) lr %.2e %.0fs peak driver %.2f GB, tensors %.2f GB" % (
                    epoch + 1, step, total_steps, running / count, window / window_n, lr_at(step),
                    time.time() - t_train, peak, peak_tensors), flush=True)
                window, window_n = 0.0, 0
            if args.max_steps and step >= args.max_steps:
                break
        peak = max(peak, mps_memory_gb())
        release_cache()
        if args.lora_layers:
            # A LoRA run is a time and memory measurement. serve.py loads heads only.
            print("LORA %d steps in %.1fs (%.2f s/step), peak driver %.2f GB, tensors %.2f GB, last loss %.4f" % (
                step, time.time() - t_train, (time.time() - t_train) / max(1, step), peak, peak_tensors,
                running / max(1, count)), flush=True)
            return
        val = evaluate(model, val_items, pad, device, amp, temperature, args.batch, val_cache)
        release_cache()
        history.append({"epoch": epoch + 1, "train_loss": running / max(1, count), "val": val,
                        "seconds": time.time() - t_train})
        if args.objective is not None:
            history[-1]['objective'] = dict(
                train_ce=train_ce / max(1, count), train_tail=train_tail / max(1, count),
                mixed_batches=objective_batches['mixed'],
                positive_only_batches=objective_batches['positive_only'],
                negative_only_batches=objective_batches['negative_only'])
        print("epoch %d val nll %.4f: %s" % (epoch + 1, val["all_nll"], json.dumps(
            {k: [round(v["accuracy"], 3), round(v["ece"], 3)] for k, v in val.items() if isinstance(v, dict)})), flush=True)
        if best is None or val["all_nll"] < best["all_nll"]:
            best = val
            best_epoch = epoch + 1
            meta = {
                "name": args.name,
                "base_repo": common.BASE_REPO,
                "base_revision": common.BASE_REVISION,
                "trained": list(common.TRAINED_PREFIXES),
                "noul_temperature": temperature,
                "epoch": epoch + 1,
            }
            meta.update(metadata)
            if args.objective is not None:
                meta['training_objective'] = args.objective
            if args.runtime_profile is not None:
                validate_runtime(runtime_seal, device)
                meta["runtime_profile"] = runtime_seal
            common.save_checkpoint(model, args.out, meta)
        if args.max_steps and step >= args.max_steps:
            break
    if torch.backends.mps.is_available():
        torch.mps.synchronize()
    train_seconds = time.time() - t_train
    peak = max(peak, mps_memory_gb())

    digest = common.sha256_file(args.out)
    report = {
        "checkpoint": os.path.abspath(args.out),
        "sha256": digest,
        "size_bytes": os.path.getsize(args.out),
        "version": "%s+%s" % (args.name, digest[:8]),
        "init": os.path.abspath(args.init) if args.init else None,
        "init_sha256": init_sha,
        "teacher_rows": teachers,
        "best_epoch": best_epoch,
        "encoder_cache_seconds": round(cache_seconds, 1),
        "train_seconds": round(train_seconds, 1),
        "total_seconds": round(time.time() - t0, 1),
        "peak_mps_driver_gb": round(peak, 2),
        "peak_mps_tensors_gb": round(peak_tensors, 2),
        "ac_power_at_start": ac,
        "ac_power_at_end": on_ac_power(),
        "device": str(device),
        "amp_encoder_fp16": amp,
        "config": {k: getattr(args, k) for k in ("epochs", "batch", "lr", "weight_decay", "warmup", "seed", "limit", "max_steps")},
        "train_examples": len(train_items),
        "val_examples": len(val_items),
        "trainable_parameters": n_train,
        "noul_temperature": temperature,
        "versions": {"torch": torch.__version__},
        "zero_shot_val": baseline,
        "history": history,
    }
    try:
        import laya
        import transformers
        report["versions"].update({"laya": laya.__version__, "transformers": transformers.__version__})
    except Exception:
        pass
    if args.metadata is not None:
        # Read installed distribution versions, never caller assertions.
        from context_train import package_versions
        report["versions"] = package_versions()
    if args.objective is not None:
        report['training_objective'] = dict(id=args.objective, train_loss='ce_plus_tail')
    path = args.report or args.out + ".report.json"
    if args.runtime_profile is not None:
        validate_runtime(runtime_seal, device)
        report["runtime_profile"] = runtime_seal
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print("CHECKPOINT %s sha256 %s size %.1f MB version %s" % (
        args.out, report["sha256"], report["size_bytes"] / 1e6, report["version"]), flush=True)
    print("TRAIN %.1fs (encoder cache %.1fs), peak MPS driver memory %.2f GB, report %s" % (
        train_seconds, cache_seconds, peak, path), flush=True)
    if train_cache and not args.keep_cache:
        for name in ("train", "val"):
            for suffix in (".f16", ".json"):
                os.remove(os.path.join(cache_dir, name + suffix))
        os.rmdir(cache_dir)
    return report


if __name__ == "__main__":
    main()
