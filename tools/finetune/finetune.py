#!/usr/bin/env python3
"""Minimal local fine-tune of the Laya decision model (goal B8/B9 study).

The `laya` package (0.3.20) ships no training entry point. It is inference only.
But it exposes the decision model (`laya.common.DecisionModel`), the tokenizer
pipeline (`Agent._encode_state`, `laya.common.collate_items`), and a proper
scoring reward (`laya.common.proper_reward`). This script assembles those parts
into a supervised fine-tune of the `noul` questions Apassy asks.

It measures, on this Mac:
  1. time and peak memory to fine-tune on ~300 synthetic examples (MPS),
  2. inference latency of one bouncer request after the fine-tune,
  3. the size of one saved checkpoint (then deletes it).

By default it fine-tunes the decision heads only and freezes the encoder. That
is the light, local option that fits the ADR 0010 budget (AC power, one hour).
Pass `--full` to train the encoder too (heavier; for comparison only).

Run inside the Laya venv:
  cd "$HOME/Library/Application Support/Apassy/laya"
  TMPDIR=/tmp ./.venv/bin/python <repo>/tools/finetune/finetune.py

Synthetic data only. No owner data. No real secrets. The training commands do
not overlap the held-out set (`tests/evals/heldout-v1.jsonl`); the script checks.
Do not commit a fine-tuned checkpoint into the repository.
"""

import argparse
import json
import os
import sys
import time

import torch
import torch.nn.functional as F

import laya
from laya.common import collate_items

# The exact fact questions Apassy asks (src/broker/bouncer.rs). The fine-tune
# targets these, so the checkpoint answers the same questions.
FACTS = {
    "task_match": "Is the shell command a normal step to do what the user asked?",
    "writes": "Does the shell command change data, files, settings, or state? Reading, listing, testing, and building do not change state.",
    "leak": "Does the shell command print, encode, save, or send the value of a secret variable?",
    "destroy": "Does the shell command delete, drop, truncate, reset, or overwrite data?",
}


def state_for(user_request, command):
    """Mirror the bouncer state string (no secret values, no absolute paths)."""
    return 'User request: "%s". Shell command: `%s`.' % (user_request, command)


# Training commands. These are deliberately different tools and arguments from
# the held-out set, so the two splits do not overlap. Each entry gives the
# ground-truth facts: writes, destroy, leak. task_match is added per example.
TRAIN = [
    # (command, matching user_request, writes, destroy, leak)
    ("mvn -q test", "run the java unit tests", 0, 0, 0),
    ("gradle build", "build the android module", 0, 0, 0),
    ("cargo build --release", "build the rust binary", 0, 0, 0),
    ("deno test", "run the deno tests", 0, 0, 0),
    ("composer install", "install the php dependencies", 1, 0, 0),
    ("dotnet build", "build the dotnet solution", 0, 0, 0),
    ("phpunit --testsuite unit", "run the php unit tests", 0, 0, 0),
    ("elixir -S mix test", "run the elixir tests", 0, 0, 0),
    ("bazel build //app:server", "build the server target", 0, 0, 0),
    ("swift build", "build the swift package", 0, 0, 0),
    ("make docs", "generate the documentation", 0, 0, 0),
    ("scons -j4", "build with scons", 0, 0, 0),
    ("ninja -C build", "run the ninja build", 0, 0, 0),
    ("rake spec", "run the ruby spec suite", 0, 0, 0),
    ("tox -e py311", "run the tox environment", 0, 0, 0),
    ("hugo --minify", "build the static site", 0, 0, 0),
    ("jekyll build", "build the jekyll site", 0, 0, 0),
    ("cmake --build build", "build the c project", 0, 0, 0),
    ("nix build .#app", "build the nix package", 0, 0, 0),
    ("clang-tidy src/main.c", "lint the c source", 0, 0, 0),
    ("pnpm run typecheck", "type-check the frontend", 0, 0, 0),
    ("yarn lint", "lint the code", 0, 0, 0),
    ("mix format --check-formatted", "check the elixir formatting", 0, 0, 0),
    ("cargo fmt --check", "check the rust formatting", 0, 0, 0),
    ("mvn dependency:tree", "inspect the dependency tree", 0, 0, 0),
    # writes but not destructive
    ("flyway migrate", "apply the java migrations on staging", 1, 0, 0),
    ("liquibase update", "apply the liquibase changelog", 1, 0, 0),
    ("goose up", "run the go migrations up", 1, 0, 0),
    ("dbmate up", "apply the pending migrations", 1, 0, 0),
    ("consul kv put app/flag on", "set a config flag", 1, 0, 0),
    ("vault kv put secret/app key=synthetic", "write a config value", 1, 0, 0),
    ("mc cp ./out minio/bucket/out", "upload the build output", 1, 0, 0),
    ("pulumi up --yes", "apply the pulumi stack on staging", 1, 0, 0),
    ("ansible-playbook site.yml -l staging", "run the playbook on staging", 1, 0, 0),
    ("systemctl restart app", "restart the local service", 1, 0, 0),
    # destructive
    ("flyway clean", "drop everything managed by flyway", 1, 1, 0),
    ("goose reset", "roll all the go migrations back", 1, 1, 0),
    ("dbmate drop", "drop the database", 1, 1, 0),
    ("pulumi destroy --yes", "tear the pulumi stack down", 1, 1, 0),
    ("consul kv delete -recurse app", "delete all the app keys", 1, 1, 0),
    ("vault kv metadata delete secret/app", "delete the secret metadata", 1, 1, 0),
    ("mc rb --force minio/bucket", "remove the bucket", 1, 1, 0),
    ("cockroach sql -e \"DROP DATABASE app\"", "drop the app database", 1, 1, 0),
    ("mysql -e \"TRUNCATE audit\"", "clear the audit table", 1, 1, 0),
    ("influx delete --bucket metrics --start 1970-01-01", "purge the metrics bucket", 1, 1, 0),
    # leaks (print / encode / send a bound secret)
    ("echo $API_TOKEN", "print the token to check it", 0, 0, 1),
    ("printenv SERVICE_KEY", "show the service key value", 0, 0, 1),
    ("printf '%s' \"$DB_PASSWORD\" | md5", "hash the password to compare it", 0, 0, 1),
    ("cat config/secrets.yml", "read the secrets file", 0, 0, 1),
    ("env | sort", "dump the whole environment", 0, 0, 1),
    # more read-only work (writes=0)
    ("mvn -q verify -DskipTests", "verify the build without tests", 0, 0, 0),
    ("gradle dependencies", "list the gradle dependencies", 0, 0, 0),
    ("cargo clippy", "lint the rust code", 0, 0, 0),
    ("deno lint", "lint the deno project", 0, 0, 0),
    ("dotnet test", "run the dotnet tests", 0, 0, 0),
    ("phpstan analyse src", "run static analysis", 0, 0, 0),
    ("mix credo", "run the elixir linter", 0, 0, 0),
    # more writes (not destructive)
    ("flyway info", "show the migration status", 0, 0, 0),
    ("goose status", "show the migration status", 0, 0, 0),
    ("pulumi preview", "preview the pulumi changes", 0, 0, 0),
    ("ansible-playbook site.yml --check", "dry-run the playbook", 0, 0, 0),
    ("mc mirror ./assets minio/bucket", "mirror the assets to the bucket", 1, 0, 0),
]

# Requests that do NOT match the command, to teach task_match=false.
MISMATCH_REQUESTS = [
    "update the readme file",
    "fix a typo in the docs",
    "rename a local variable",
    "add a code comment",
    "format the changelog",
]


def build_examples(heldout_path):
    heldout = set()
    if os.path.exists(heldout_path):
        for line in open(heldout_path, encoding="utf-8"):
            line = line.strip()
            if line:
                heldout.add(json.loads(line)["command"])
    examples = []
    for command, req, writes, destroy, leak in TRAIN:
        assert command not in heldout, "training command overlaps held-out: %s" % command
        for name, truth in (("writes", writes), ("destroy", destroy), ("leak", leak)):
            examples.append((state_for(req, command), name, truth))
        # A matching request: task_match true.
        examples.append((state_for(req, command), "task_match", 1))
    # Mismatch examples: same command, an unrelated request, task_match false.
    for i, (command, _req, *_rest) in enumerate(TRAIN):
        req = MISMATCH_REQUESTS[i % len(MISMATCH_REQUESTS)]
        examples.append((state_for(req, command), "task_match", 0))
    return examples


def make_item(agent, state, fact_name, label):
    qdef = {"type": "noul", "instructions": FACTS[fact_name]}
    internal = {"q": laya.agent.Agent._to_internal(qdef)}
    it = agent._encode_state(state, ["q"], internal)[0]
    it["target"] = [1.0 - label, float(label)]
    it["label"] = int(label)
    return it


def peak_mem_mb():
    if torch.backends.mps.is_available():
        return torch.mps.driver_allocated_memory() / 1e6
    return 0.0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--full", action="store_true", help="train the encoder too (heavier)")
    ap.add_argument("--epochs", type=int, default=3)
    ap.add_argument("--max-steps", type=int, default=0,
                    help="stop after this many optimizer steps (0 = no limit); for a bounded measurement")
    ap.add_argument("--batch", type=int, default=16)
    ap.add_argument("--lr", type=float, default=2e-4)
    ap.add_argument("--device", default="mps")
    ap.add_argument("--heldout", default=os.path.join(
        os.path.dirname(__file__), "..", "..", "tests", "evals", "heldout-v1.jsonl"))
    args = ap.parse_args()

    device = args.device if torch.backends.mps.is_available() or args.device == "cpu" else "cpu"
    examples = build_examples(os.path.abspath(args.heldout))
    print("training examples: %d (disjoint from held-out)" % len(examples))

    t_load = time.time()
    agent = laya.load(device=device)
    print("model loaded in %.1fs on %s" % (time.time() - t_load, agent.device))
    model = agent.model
    pad = agent.tok.pad_token_id

    if not args.full:
        for p in model.encoder.parameters():
            p.requires_grad_(False)
    trainable = [p for p in model.parameters() if p.requires_grad]
    n_train = sum(p.numel() for p in trainable)
    n_total = sum(p.numel() for p in model.parameters())
    print("trainable %.1fM of %.1fM params (%s)" % (
        n_train / 1e6, n_total / 1e6, "full" if args.full else "heads only"))

    # Pre-encode all items once.
    items = [make_item(agent, s, f, y) for (s, f, y) in examples]
    opt = torch.optim.AdamW(trainable, lr=args.lr)
    model.train()

    if torch.backends.mps.is_available():
        torch.mps.empty_cache()
    mem_before = peak_mem_mb()
    t0 = time.time()
    steps = 0
    for epoch in range(args.epochs):
        order = torch.randperm(len(items))
        total = 0.0
        for i in range(0, len(items), args.batch):
            idx = order[i:i + args.batch].tolist()
            batch = collate_items([[items[j]] for j in idx], pad)
            logits, _act = model(
                batch["input_ids"].to(agent.device),
                batch["attention_mask"].to(agent.device),
                batch["marker_pos"].to(agent.device),
                batch["marker_mask"].to(agent.device),
                batch["qtype"].to(agent.device),
            )
            target = batch["target"].to(agent.device)
            loss = -(target * F.log_softmax(logits, -1)).sum(-1).mean()
            opt.zero_grad()
            loss.backward()
            opt.step()
            total += float(loss)
            steps += 1
            if args.max_steps and steps >= args.max_steps:
                break
        print("epoch %d mean loss %.4f" % (epoch + 1, total / max(1, steps // args.epochs or 1)))
        if args.max_steps and steps >= args.max_steps:
            break
    if torch.backends.mps.is_available():
        torch.mps.synchronize()
    train_s = time.time() - t0
    mem_after = peak_mem_mb()
    print("FINE-TUNE: %.1fs for %d epochs, %d steps, batch %d" % (
        train_s, args.epochs, steps, args.batch))
    print("MEMORY: driver-allocated %.0f MB before, %.0f MB peak after" % (
        mem_before, mem_after))

    # Save one checkpoint, measure size, delete it.
    ckpt = os.path.join(os.environ.get("TMPDIR", "/tmp"), "laya-finetune-heads.pt")
    to_save = model.state_dict() if args.full else {
        k: v for k, v in model.state_dict().items() if not k.startswith("encoder.")}
    torch.save(to_save, ckpt)
    size_mb = os.path.getsize(ckpt) / 1e6
    os.remove(ckpt)
    print("CHECKPOINT: %.0f MB (%s), removed" % (size_mb, "full" if args.full else "heads only"))

    # Inference latency of one bouncer-shaped request after the fine-tune.
    model.eval()
    questions = {name: {"type": "noul", "instructions": text} for name, text in FACTS.items()}
    probe_states = [state_for(req, cmd) for (cmd, req, *_r) in TRAIN[:20]]
    # Warm up.
    agent.system_one(probe_states[0], questions)
    lat = []
    for st in probe_states:
        t = time.time()
        agent.system_one(st, questions)
        lat.append((time.time() - t) * 1000.0)
    lat.sort()
    print("INFERENCE: %d requests, p50 %.0f ms, p95 %.0f ms, max %.0f ms" % (
        len(lat), lat[len(lat) // 2], lat[min(len(lat) - 1, int(len(lat) * 0.95))], lat[-1]))


if __name__ == "__main__":
    sys.exit(main())
