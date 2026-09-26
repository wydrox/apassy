#!/usr/bin/env python3
"""Write `tools/basemodel/manifest.json` for a trained checkpoint (goal B8).

The manifest records the version, the SHA-256, the size, the base model, and
the training configuration. `serve.py` and `scripts/build-app.sh` refuse a
checkpoint that does not match it.

  python3 tools/basemodel/manifest.py --checkpoint <file> --report <file.report.json> \
      --stats <data>/stats.json [--zero-shot leak]
"""

import argparse
import hashlib
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--checkpoint", required=True)
    ap.add_argument("--report", required=True)
    ap.add_argument("--stats", required=True)
    ap.add_argument("--base-weights", default="", help="model.safetensors of the pinned base revision")
    ap.add_argument("--zero-shot", default=None,
                    help="comma list of questions that keep the stock answer; default: keep the current manifest value")
    ap.add_argument("--out", default=os.path.join(HERE, "manifest.json"))
    args = ap.parse_args()

    report = json.load(open(args.report, encoding="utf-8"))
    stats = json.load(open(args.stats, encoding="utf-8"))
    old = json.load(open(args.out, encoding="utf-8")) if os.path.exists(args.out) else {}
    if args.zero_shot is None:
        zero_shot = old.get("serve", {}).get("zero_shot_questions", [])
    else:
        zero_shot = [q for q in args.zero_shot.split(",") if q]

    import common  # noqa: E402  (same folder)

    digest = sha256_file(args.checkpoint)
    base_weights = args.base_weights or os.path.join(common.base_dir(), "model.safetensors")
    manifest = {
        "schema": 1,
        "name": common.MODEL_NAME,
        "version": "%s+%s" % (common.MODEL_NAME, digest[:8]),
        "checkpoint": {
            "file": "%s.safetensors" % common.MODEL_NAME,
            "sha256": digest,
            "size_bytes": os.path.getsize(args.checkpoint),
            "format": "safetensors, float32 head tensors: %s" % ", ".join(common.TRAINED_PREFIXES),
        },
        "base": {
            "repo": common.BASE_REPO,
            "revision": common.BASE_REVISION,
            "weights_file": "model.safetensors",
            "weights_sha256": sha256_file(base_weights),
            "package": "laya[serve]==0.3.20",
        },
        "serve": {"zero_shot_questions": zero_shot},
        "training": {
            "method": "heads only (encoder frozen, encoder states cached once in float16), cross-entropy on noul logits divided by the noul temperature",
            "noul_temperature": report["noul_temperature"],
            "config": report["config"],
            "best_epoch": report["best_epoch"],
            "trainable_parameters": report["trainable_parameters"],
            "train_examples": report["train_examples"],
            "val_examples": report["val_examples"],
            "encoder_cache_seconds": report.get("encoder_cache_seconds"),
            "train_seconds": report["train_seconds"],
            "peak_mps_driver_gb": report["peak_mps_driver_gb"],
            "peak_mps_tensors_gb": report.get("peak_mps_tensors_gb"),
            "ac_power": bool(report["ac_power_at_start"] and report["ac_power_at_end"]),
            "device": report["device"],
            "versions": report["versions"],
            "data": {
                "seed": stats["seed"],
                "commands": stats["commands"],
                "train": stats["train"],
                "val": stats["val"],
                "sources": stats["sources"],
            },
            "val_metrics": report["history"][report["best_epoch"] - 1]["val"],
        },
    }
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")
    print("wrote %s: %s" % (args.out, manifest["version"]))


if __name__ == "__main__":
    import sys

    sys.path.insert(0, HERE)
    main()
