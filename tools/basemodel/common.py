"""Shared parts of the base-model trainer and server (goal B8).

- The pinned base checkpoint: `convaiinnovations/laya` at one Hugging Face revision.
- The trainable parts: the decision heads (`head`, `type_emb`, `scorer`). The
  encoder stays frozen, so the base weights stay as published.
- The checkpoint file: safetensors with the head tensors and a metadata block.
"""

import hashlib
import json
import os

BASE_REPO = "convaiinnovations/laya"
# The revision that `laya-serve` 0.3.20 downloaded on 2026-09-26. The SHA-256 of its
# `model.safetensors` is in manifest.json (`base.weights_sha256`).
BASE_REVISION = "55cf4c4ebb4ebe31b2550e8bdf3bd21b99753851"
BASE_FILES = ["rl_agent_config.json", "model.safetensors", "tokenizer/*", "encoder/*"]
# Tensor name prefixes that the fine-tune changes. The encoder and `act_head` stay.
TRAINED_PREFIXES = ("head.", "type_emb.", "scorer.")
MODEL_NAME = "apassy-base-v1"


def base_dir(token=None):
    """Download (or find in the cache) the pinned base checkpoint. Return its folder."""
    from huggingface_hub import snapshot_download

    return snapshot_download(BASE_REPO, revision=BASE_REVISION, allow_patterns=BASE_FILES,
                             token=token or os.environ.get("HF_TOKEN") or None)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def model_version(checkpoint_path):
    """`apassy-base-v1+<first 8 hex of the checkpoint SHA-256>`."""
    return "%s+%s" % (MODEL_NAME, sha256_file(checkpoint_path)[:8])


def noul_temperature(agent):
    """The temperature that Laya divides the two noul logits by before the softmax."""
    from laya.common import QTYPES, temp_bucket

    return float(agent.temperature_by_options.get(temp_bucket(QTYPES["noul"], 2),
                                                  agent.temperature[QTYPES["noul"]]))


def head_state(model):
    return {k: v.detach().float().cpu().contiguous() for k, v in model.state_dict().items()
            if k.startswith(TRAINED_PREFIXES)}


def save_checkpoint(model, path, metadata):
    from safetensors.torch import save_file

    tmp = path + ".tmp"
    save_file(head_state(model), tmp, metadata={"apassy": json.dumps(metadata, sort_keys=True)})
    os.replace(tmp, path)


def load_checkpoint(path):
    """Return (tensors, metadata). Rejects a file with other tensors than the heads."""
    from safetensors import safe_open

    tensors = {}
    with safe_open(path, framework="pt") as f:
        meta = json.loads((f.metadata() or {}).get("apassy", "{}"))
        for key in f.keys():
            if not key.startswith(TRAINED_PREFIXES):
                raise ValueError("unexpected tensor in the checkpoint: %s" % key)
            tensors[key] = f.get_tensor(key)
    return tensors, meta


def apply_heads(model, tensors):
    """Replace the head tensors of a loaded DecisionModel. Every trained tensor must match."""
    current = model.state_dict()
    expected = {k for k in current if k.startswith(TRAINED_PREFIXES)}
    if set(tensors) != expected:
        missing = sorted(expected - set(tensors))[:3]
        extra = sorted(set(tensors) - expected)[:3]
        raise ValueError("checkpoint does not fit the model: missing %s, extra %s" % (missing, extra))
    for key, value in tensors.items():
        if tuple(value.shape) != tuple(current[key].shape):
            raise ValueError("shape mismatch for %s" % key)
    model.load_state_dict(tensors, strict=False)
