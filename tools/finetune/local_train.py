#!/usr/bin/env python3
"""Local fine-tune of the bouncer model heads on the owner decisions (goal B9).

The broker runs this script (`src/broker/finetune.rs`) after the training gate of
ADR 0010 passes. The broker also writes the examples: it converts the decision
log export (`apassy-decision-v1`) to `train.jsonl` and `val.jsonl` with the label
mapping of `docs/operations/fine-tune.md`. This script:

1. checks the example counts in `stats.json` against the gate again (300 owner
   decisions, 30 owner denials),
2. checks that `--init` is the shipped base checkpoint of
   `tools/basemodel/manifest.json`,
3. runs `tools/basemodel/train.py` in this process: heads only, from the base
   heads, with teacher rows that keep the other answers,
4. writes `manifest.json` next to the checkpoint, so `tools/basemodel/serve.py`
   can serve the candidate, and `result.json` for the broker.

A second guard: `--deadline` sets an alarm. The broker stops the process group
at the same time limit.

Run inside the Laya virtual environment:
  .venv/bin/python tools/finetune/local_train.py --data <dir> --out <dir> \
      [--init <apassy-base-v1.safetensors>] [--name apassy-local-v1] [--deadline 3600]
"""

import argparse
import json
import os
import signal
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
BASEMODEL = os.path.join(os.path.dirname(HERE), "basemodel")
sys.path.insert(0, BASEMODEL)

import common  # noqa: E402

MIN_OWNER_DECISIONS = 300
MIN_OWNER_DENIALS = 30
CHECKPOINT = "candidate.safetensors"


def write_json(path, value):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(value, f, indent=2)
        f.write("\n")
    os.replace(tmp, path)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True, help="folder with train.jsonl, val.jsonl, stats.json")
    ap.add_argument("--out", required=True, help="candidate folder")
    ap.add_argument("--init", default="", help="the shipped base checkpoint")
    ap.add_argument("--name", default="apassy-local-v1")
    ap.add_argument("--deadline", type=int, default=3600, help="seconds before the alarm stops this process")
    ap.add_argument("--epochs", type=int, default=4)
    ap.add_argument("--batch", type=int, default=32)
    ap.add_argument("--lr", type=float, default=1e-4)
    ap.add_argument("--warmup", type=int, default=20)
    ap.add_argument("--base-manifest", default=os.path.join(BASEMODEL, "manifest.json"))
    args = ap.parse_args()

    # The default action of SIGALRM ends the process.
    signal.alarm(max(1, args.deadline))
    t0 = time.time()

    stats = json.load(open(os.path.join(args.data, "stats.json"), encoding="utf-8"))
    if stats["owner_decisions"] < MIN_OWNER_DECISIONS or stats["owner_denials"] < MIN_OWNER_DENIALS:
        raise SystemExit("local_train: the gate needs %d owner decisions and %d denials, the data has %d and %d"
                         % (MIN_OWNER_DECISIONS, MIN_OWNER_DENIALS, stats["owner_decisions"], stats["owner_denials"]))
    base_manifest = json.load(open(args.base_manifest, encoding="utf-8"))
    init_sha = None
    if args.init:
        init_sha = common.sha256_file(args.init)
        if init_sha != base_manifest["checkpoint"]["sha256"]:
            raise SystemExit("local_train: %s is not the shipped base checkpoint %s"
                             % (args.init, base_manifest["version"]))
    print("local_train: %d owner decisions (%d denials), %d train and %d val examples, init %s"
          % (stats["owner_decisions"], stats["owner_denials"], stats["train"], stats["val"],
             base_manifest["version"] if args.init else "stock Laya heads"), flush=True)

    import train  # noqa: E402  (tools/basemodel/train.py)

    checkpoint = os.path.join(args.out, CHECKPOINT)
    argv = [
        "--data", args.data,
        "--out", checkpoint,
        "--report", os.path.join(args.out, "train.report.json"),
        "--name", args.name,
        "--epochs", str(args.epochs),
        "--batch", str(args.batch),
        "--lr", str(args.lr),
        "--warmup", str(args.warmup),
        "--cache-dir", os.path.join(args.out, "encoder-cache"),
    ]
    if args.init:
        argv += ["--init", args.init]
    report = train.main(argv)

    best = report["history"][report["best_epoch"] - 1]["val"]
    manifest = {
        "schema": 1,
        "name": args.name,
        "version": report["version"],
        "checkpoint": {
            "file": CHECKPOINT,
            "sha256": report["sha256"],
            "size_bytes": report["size_bytes"],
            "format": "safetensors, float32 head tensors: %s" % ", ".join(common.TRAINED_PREFIXES),
        },
        "base": base_manifest["base"],
        "serve": base_manifest.get("serve", {"zero_shot_questions": []}),
        "init": {"version": base_manifest["version"], "sha256": init_sha} if args.init else None,
        "training": {
            "method": "local heads-only fine-tune on owner decisions (goal B9), teacher rows keep the other answers",
            "config": report["config"],
            "best_epoch": report["best_epoch"],
            "train_examples": report["train_examples"],
            "val_examples": report["val_examples"],
            "teacher_rows": report["teacher_rows"],
            "train_seconds": report["train_seconds"],
            "encoder_cache_seconds": report["encoder_cache_seconds"],
            "peak_mps_driver_gb": report["peak_mps_driver_gb"],
            "ac_power": bool(report["ac_power_at_start"] and report["ac_power_at_end"]),
            "versions": report["versions"],
            "examples": stats,
            "val_metrics": best,
        },
    }
    write_json(os.path.join(args.out, "manifest.json"), manifest)
    result = {
        "version": report["version"],
        "checkpoint": os.path.abspath(checkpoint),
        "sha256": report["sha256"],
        "size_bytes": report["size_bytes"],
        "manifest": os.path.abspath(os.path.join(args.out, "manifest.json")),
        "init_sha256": init_sha,
        "train_seconds": report["train_seconds"],
        "encoder_cache_seconds": report["encoder_cache_seconds"],
        "total_seconds": round(time.time() - t0, 1),
        "peak_mps_driver_gb": report["peak_mps_driver_gb"],
        "peak_mps_tensors_gb": report["peak_mps_tensors_gb"],
        "train_examples": report["train_examples"],
        "val_examples": report["val_examples"],
        "teacher_rows": report["teacher_rows"],
        "best_epoch": report["best_epoch"],
        "ac_power_at_start": report["ac_power_at_start"],
        "ac_power_at_end": report["ac_power_at_end"],
        "val_before": report["zero_shot_val"],
        "val_after": best,
    }
    write_json(os.path.join(args.out, "result.json"), result)
    print("RESULT %s in %.1f s" % (report["version"], time.time() - t0), flush=True)


if __name__ == "__main__":
    main()
