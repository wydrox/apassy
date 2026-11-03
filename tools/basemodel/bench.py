#!/usr/bin/env python3
"""Measurements of the bouncer brain server for K1 (ADR 0035, implementation plan 0035).

Synthetic data only: the requests and the training set come from the labeled cases of
`tests/fixtures/bouncer/cases.tsv`; the head sets are the shipped base heads with seeded
noise. No owner data, no secret value, no vault path. The client needs only the Python
standard library; `make-heads` uses numpy when it is there (it is in the image) and
pure Python otherwise.

Subcommands (`--url` is the server; the token is `LAYA_API_KEY` or `--token-file`):

  make-heads  --base <ckpt> --out <dir> [--count 10] [--seed 1]
              synthetic head sets with the shapes of <ckpt>, each `<sha>.safetensors`
              and `<sha>.json` (its manifest, accepted by `PUT /v1/heads/<sha>`)
  make-train  --out <dir>            train.jsonl, val.jsonl, stats.json for local_train.py
  upload      --url U --heads-dir D | --candidate C  PUT every head set of D, or the
              candidate folder C of local_train.py (repeatable)
  latency     --url U [--n 50] [--heads H] [--shadow S]  one series; p50 and p95
  owners      --url U --heads-dir D [--owners 10] [--n 50]  parallel owners, one hash each
  cache       --url U --heads-dir D  memory per extra loaded head set
  suite       --url U --heads-dir D --out F  the K1 series in order (see the runbook)
  answers     --url U [--heads H] [--shadow S] --out F  answers for every case
  compare     A.json B.json [--tolerance 0.02]  equality of two `answers` files
  train       --data D --out O       one training job with wall time and peak memory
  rss                                resident memory of the serve.py process
  cgroup                             memory and CPU numbers of this container's cgroup

`--dry-run` (no subcommand) checks the generators without a server, torch or numpy.
Runbook: docs/operations/bouncer-hosting.md, section "K1 measurement procedure".
"""

import argparse
import base64
import hashlib
import json
import math
import os
import random
import resource
import shlex
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

_WRITE_BYTECODE = sys.dont_write_bytecode
sys.dont_write_bytecode = True
import common  # noqa: E402
import heads_cache  # noqa: E402

sys.dont_write_bytecode = _WRITE_BYTECODE

ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
DEFAULT_CASES = os.environ.get("APASSY_BENCH_CASES") or os.path.join(
    ROOT, "tests", "fixtures", "bouncer", "cases.tsv")
DEFAULT_MANIFEST = os.path.join(HERE, "manifest.json")

# The question texts of `bouncer::questions()` (src/broker/bouncer.rs, FACTS and
# RULE_FACT), in the order of a request. tests/basemodel/test_bench.py checks them
# against the Rust source.
FACTS = [
    ("task_match", "Is the shell command a normal step to do what the user asked?"),
    ("writes", "Does the shell command change data, files, settings, or state? Reading, "
               "listing, testing, and building do not change state."),
    ("remote", "Does the shell command act on a remote server, database, or cloud service?"),
    ("leak", "Does the shell command print, encode, save, or send the value of a secret variable?"),
    ("destroy", "Does the shell command delete, drop, truncate, reset, or overwrite data?"),
]
RULE_FACT = ("rule_break", "Does the shell command break the owner rule?")
OWNER_RULE = "Never touch production."

# The constants of `finetune::examples_from_export` (src/broker/finetune.rs).
VAL_PERCENT = 20
MAX_COPIES = 3
MIN_DENIAL_WEIGHT = 2
MAX_DENIAL_WEIGHT = 10
KEEP_QUESTIONS = ["writes", "remote", "destroy"]
DECISIONS = 300

# The model-fact part of `decide` (src/broker/bouncer.rs) for a command that the rule
# packs do not know, with a normal credential and no production declaration.
DEFAULT_TASK_MATCH = 0.75
MIN_CONFIDENCE = 0.8
DESTROY_VETO = 0.9

HEADS_NAME = "bench-synthetic"
NOISE = 0.01


# ------------------------------------------------------------------ synthetic cases
def read_cases(path=DEFAULT_CASES):
    """(ok, category, command, purpose) for each labeled case."""
    cases = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            parts = line.rstrip("\n").split("\t")
            if len(parts) != 4:
                raise SystemExit("bench: bad case line in %s" % path)
            cases.append((parts[0] == "ok", parts[1], parts[2], parts[3]))
    if not cases:
        raise SystemExit("bench: no cases in %s" % path)
    return cases


def argv_command(line):
    """The command as the broker logs it: the words of the command line, joined by spaces."""
    try:
        return " ".join(shlex.split(line))
    except ValueError:
        return line


def state_text(user_request, command, purpose, instruction=""):
    """`bouncer::state_text`."""
    state = 'User request: "%s". Shell command: `%s`.' % (user_request.strip(), command)
    if purpose.strip():
        state += " Agent's stated purpose: %s" % purpose.strip()
    if instruction.strip():
        state += " Owner rule: %s" % instruction.strip()
    return state


def questions_for(instruction):
    facts = list(FACTS)
    if instruction.strip():
        facts.append(RULE_FACT)
    return {name: {"type": "noul", "instructions": text} for name, text in facts}


def fnv1a(text):
    h = 0xCBF29CE484222325
    for byte in text.encode("utf-8"):
        h ^= byte
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


def synthetic_flags(ok, category):
    """Rule flags for a synthetic owner denial. The broker computes them with
    `shell_risk::analyze`; this script has no rule packs, so the category decides:
    `destr` is a data-loss flag, `mismatch` has no flag (the owner denies a task
    mismatch), the other risk categories have a flag without data loss."""
    if ok or category == "mismatch":
        return []
    return ["data_loss"] if category == "destr" else ["synthetic_flag"]


def make_training_set(cases, decisions=DECISIONS):
    """The mapping of `finetune::examples_from_export` on a synthetic log: `decisions`
    owner decisions, the cases in the order `(n * 7) % len` of
    tests/local_finetune.rs; `ok` is an approval, `risk` a denial."""
    questions = dict(FACTS + [RULE_FACT])
    stats = {k: 0 for k in ("lines", "owner_decisions", "owner_approvals", "owner_denials",
                            "without_user_request", "flagged_denials", "conflicts",
                            "task_match_yes", "task_match_no", "destroy_yes", "keep",
                            "denial_weight", "train", "val")}
    lines = []
    for n in range(decisions):
        ok, category, raw, purpose = cases[(n * 7) % len(cases)]
        command = argv_command(raw)
        stats["lines"] += 1
        stats["owner_decisions"] += 1
        stats["owner_approvals" if ok else "owner_denials"] += 1
        lines.append({"state": state_text(purpose, command, purpose), "command": command,
                      "allow": ok, "flags": synthetic_flags(ok, category), "has_rule": False})

    def example(line, name, answer, teacher, kind):
        return {"state": line["state"], "question": name, "instructions": questions[name],
                "answer": answer, "teacher": teacher, "kind": kind, "_command": line["command"]}

    denied = {line["state"] for line in lines if not line["allow"]}
    hard = []
    for line in lines:
        if line["allow"]:
            if line["state"] in denied:
                stats["conflicts"] += 1
            else:
                hard.append(example(line, "task_match", 1, False, "approval"))
        elif not line["flags"]:
            hard.append(example(line, "task_match", 0, False, "denial"))
        else:
            stats["flagged_denials"] += 1
            if "data_loss" in line["flags"]:
                hard.append(example(line, "destroy", 1, False, "flagged_denial"))
    copies, kept = {}, []
    for e in hard:
        key = (e["state"], e["question"], e["answer"])
        copies[key] = copies.get(key, 0) + 1
        if copies[key] <= MAX_COPIES:
            kept.append(e)
    hard = kept
    labeled = {(e["state"], e["question"]) for e in hard}
    keep, seen = [], set()
    for line in lines:
        if line["state"] in seen:
            continue
        seen.add(line["state"])
        names = ["task_match"] + KEEP_QUESTIONS + (["rule_break"] if line["has_rule"] else [])
        for name in names:
            if (line["state"], name) not in labeled:
                keep.append(example(line, name, 0, True, "keep"))
    stats["task_match_yes"] = sum(1 for e in hard if e["kind"] == "approval")
    stats["task_match_no"] = sum(1 for e in hard if e["kind"] == "denial")
    stats["destroy_yes"] = sum(1 for e in hard if e["kind"] == "flagged_denial")
    stats["keep"] = len(keep)
    if stats["task_match_no"] == 0:
        weight = MIN_DENIAL_WEIGHT
    else:
        # Rust `f64::round` rounds half away from zero.
        weight = int(math.floor(stats["task_match_yes"] / stats["task_match_no"] + 0.5))
        weight = max(MIN_DENIAL_WEIGHT, min(MAX_DENIAL_WEIGHT, weight))
    stats["denial_weight"] = weight
    everything = []
    for e in hard:
        everything.extend([e] * (1 if e["kind"] == "approval" else weight))
    everything.extend(keep)
    train = [e for e in everything if fnv1a(e["_command"]) % 100 >= VAL_PERCENT]
    val = [e for e in everything if fnv1a(e["_command"]) % 100 < VAL_PERCENT]
    if not val:
        first = min(e["_command"] for e in train)
        val = [e for e in train if e["_command"] == first]
        train = [e for e in train if e["_command"] != first]
    stats["train"], stats["val"] = len(train), len(val)
    strip = lambda rows: [{k: v for k, v in e.items() if not k.startswith("_")} for e in rows]  # noqa: E731
    return strip(train), strip(val), stats


def write_private(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def write_training_set(out, cases):
    os.makedirs(out, mode=0o700, exist_ok=True)
    train, val, stats = make_training_set(cases)
    jsonl = lambda rows: "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows).encode()  # noqa: E731
    write_private(os.path.join(out, "train.jsonl"), jsonl(train))
    write_private(os.path.join(out, "val.jsonl"), jsonl(val))
    write_private(os.path.join(out, "stats.json"), json.dumps(stats).encode())
    return stats


def make_requests(cases, n, long_chars=1400, seed=7):
    """`n` request bodies of the bouncer (5 questions, or 6 with an owner rule). Every
    third state is long: its user request grows with the purposes of other cases to
    about `long_chars` characters, so the state stays under 512 tokens."""
    rng = random.Random(seed)
    purposes = [c[3] for c in cases]
    bodies = []
    for i in range(n):
        ok, _category, raw, purpose = cases[(i * 7) % len(cases)]
        user_request = purpose
        if i % 3 == 2:
            parts = [purpose]
            while sum(len(p) + 1 for p in parts) < long_chars:
                parts.append(rng.choice(purposes))
            user_request = " ".join(parts)[:long_chars]
        instruction = OWNER_RULE if i % 2 == 1 else ""
        bodies.append({"state": state_text(user_request, argv_command(raw), purpose, instruction),
                       "questions": questions_for(instruction)})
    return bodies


# ------------------------------------------------------------------ synthetic head sets
def read_safetensors(path):
    """(header dict, data offset, file size) of a safetensors file."""
    with open(path, "rb") as f:
        (length,) = struct.unpack("<Q", f.read(8))
        header = json.loads(f.read(length).decode("utf-8"))
    return header, 8 + length, os.path.getsize(path)


def perturb(raw, rng_seed):
    """`raw` float32 bytes times (1 + NOISE * N(0, 1)), seeded."""
    try:
        import numpy as np
    except ImportError:
        np = None
    if np is not None:
        values = np.frombuffer(raw, dtype="<f4")
        noise = np.random.default_rng(rng_seed).standard_normal(values.shape[0])
        return (values * (1.0 + NOISE * noise)).astype("<f4").tobytes()
    from array import array

    values = array("f")
    values.frombytes(raw)
    if sys.byteorder != "little":
        values.byteswap()
    rng = random.Random(rng_seed)
    for i in range(len(values)):
        values[i] = values[i] * (1.0 + NOISE * rng.gauss(0.0, 1.0))
    if sys.byteorder != "little":
        values.byteswap()
    return values.tobytes()


def write_head_set(base_path, base_manifest, out_dir, index, seed, name=HEADS_NAME):
    """One synthetic head set: the tensors of `base_path` with noise. Return (sha, manifest)."""
    header, data_start, _size = read_safetensors(base_path)
    tensors = sorted(((k, v) for k, v in header.items() if k != "__metadata__"),
                     key=lambda kv: kv[1]["data_offsets"][0])
    set_name = "%s-%02d" % (name, index)
    meta = {"apassy": json.dumps({"name": set_name, "synthetic": True, "seed": seed, "index": index,
                                  "base_revision": base_manifest["base"]["revision"]}, sort_keys=True)}
    new_header = dict(header)
    new_header["__metadata__"] = meta
    encoded = json.dumps(new_header, separators=(",", ":")).encode("utf-8")
    encoded += b" " * (-len(encoded) % 8)
    tmp = os.path.join(out_dir, ".bench-%d.tmp" % index)
    digest = hashlib.sha256()
    with open(base_path, "rb") as src, open(tmp, "wb") as dst:
        prefix = struct.pack("<Q", len(encoded)) + encoded
        dst.write(prefix)
        digest.update(prefix)
        for t, (key, value) in enumerate(tensors):
            if value.get("dtype") != "F32":
                raise SystemExit("bench: %s is not F32" % key)
            start, stop = value["data_offsets"]
            src.seek(data_start + start)
            chunk = perturb(src.read(stop - start), seed * 1000003 + index * 1009 + t)
            dst.write(chunk)
            digest.update(chunk)
    sha = digest.hexdigest()
    size = os.path.getsize(tmp)
    manifest = {
        "schema": 1,
        "name": set_name,
        "version": heads_cache.model_name(set_name, sha),
        "checkpoint": {"file": "candidate.safetensors", "sha256": sha, "size_bytes": size,
                       "format": "safetensors, float32 head tensors: %s" % ", ".join(common.TRAINED_PREFIXES)},
        "base": base_manifest["base"],
        "serve": base_manifest.get("serve", {"zero_shot_questions": []}),
        "training": {"method": "synthetic bench head set (tools/basemodel/bench.py): the base heads "
                               "with %.0f%% seeded noise, not trained" % (NOISE * 100), "seed": seed},
    }
    os.replace(tmp, os.path.join(out_dir, sha + ".safetensors"))
    with open(os.path.join(out_dir, sha + ".json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")
    return sha, manifest


def make_head_sets(base_path, manifest_path, out_dir, count, seed):
    base_manifest = json.load(open(manifest_path, encoding="utf-8"))
    os.makedirs(out_dir, exist_ok=True)
    made = []
    for index in range(1, count + 1):
        sha, manifest = write_head_set(base_path, base_manifest, out_dir, index, seed)
        heads_cache.check_head_file(os.path.join(out_dir, sha + ".safetensors"))
        heads_cache.check_manifest(manifest, sha, base_manifest["base"])
        made.append({"heads": sha, "model": manifest["version"], "index": index})
    with open(os.path.join(out_dir, "index.json"), "w", encoding="utf-8") as f:
        json.dump(made, f, indent=2)
        f.write("\n")
    return made


def head_sets(heads_dir):
    """The synthetic head sets of `make-heads`, in index order."""
    with open(os.path.join(heads_dir, "index.json"), encoding="utf-8") as f:
        return json.load(f)


# ------------------------------------------------------------------ HTTP client
class Client:
    def __init__(self, url, token=None, timeout=120.0):
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise SystemExit("bench: --url must be http(s)://host:port")
        self.scheme, self.host = parsed.scheme, parsed.hostname
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.token = token
        self.timeout = timeout

    def _connection(self):
        import http.client

        if self.scheme == "https":
            return http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout)
        return http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)

    def request(self, method, path, body=None, headers=None):
        """(status, parsed JSON or None, seconds). One connection per request, as Apassy."""
        headers = dict(headers or {})
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        conn = self._connection()
        started = time.perf_counter()
        try:
            conn.request(method, path, body=body, headers=headers)
            response = conn.getresponse()
            raw = response.read()
            seconds = time.perf_counter() - started
        finally:
            conn.close()
        try:
            value = json.loads(raw) if raw else None
        except ValueError:
            value = None
        return response.status, value, seconds

    def health(self):
        return self.request("GET", "/health")

    def wait(self, limit=600):
        deadline = time.time() + limit
        while time.time() < deadline:
            try:
                status, _value, _s = self.health()
                if status == 200:
                    return True
            except OSError:
                pass
            time.sleep(2)
        raise SystemExit("bench: the server did not answer /health within %d s" % limit)

    def ask(self, body, heads=None, shadow=None):
        body = dict(body)
        if heads:
            body["heads"] = heads
        if shadow:
            body["shadow_heads"] = shadow
        return self.request("POST", "/v1/systemone", body)

    def upload(self, heads_dir, sha):
        return self.upload_files(os.path.join(heads_dir, sha + ".safetensors"),
                                 os.path.join(heads_dir, sha + ".json"), sha)

    def upload_candidate(self, folder):
        """A candidate folder of local_train.py: candidate.safetensors and manifest.json."""
        manifest_path = os.path.join(folder, "manifest.json")
        manifest = json.load(open(manifest_path, encoding="utf-8"))
        sha = manifest["checkpoint"]["sha256"]
        return sha, self.upload_files(os.path.join(folder, manifest["checkpoint"]["file"]), manifest_path, sha)

    def upload_files(self, path, manifest_path, sha):
        with open(manifest_path, "rb") as f:
            manifest = f.read()
        header = base64.urlsafe_b64encode(manifest).rstrip(b"=").decode("ascii")
        with open(path, "rb") as body:
            return self.request("PUT", "/v1/heads/" + sha, body=body, headers={
                "Content-Type": "application/octet-stream",
                "Content-Length": str(os.path.getsize(path)),
                "Apassy-Manifest": header})


def token_from(args):
    if getattr(args, "token_file", None):
        with open(args.token_file, encoding="utf-8") as f:
            return f.read().strip() or None
    return os.environ.get("LAYA_API_KEY") or None


# ------------------------------------------------------------------ memory
def server_pid():
    """The pid of the serve.py process in this PID namespace (`--pid container:<brain>`)."""
    for name in os.listdir("/proc") if os.path.isdir("/proc") else []:
        if not name.isdigit() or int(name) == os.getpid():
            continue
        try:
            with open("/proc/%s/cmdline" % name, "rb") as f:
                words = f.read().split(b"\0")
        except OSError:
            continue
        if any(w.endswith(b"serve.py") for w in words):
            return int(name)
    return None


def proc_memory(pid):
    """VmRSS and VmHWM (peak) of `pid` in MiB, or None."""
    if pid is None:
        return None
    values = {}
    try:
        with open("/proc/%d/status" % pid, encoding="utf-8") as f:
            for line in f:
                key, _, rest = line.partition(":")
                if key in ("VmRSS", "VmHWM"):
                    values[key] = round(int(rest.split()[0]) / 1024.0, 1)
    except OSError:
        return None
    return {"rss_mib": values.get("VmRSS"), "peak_rss_mib": values.get("VmHWM")}


def cgroup_numbers(root="/sys/fs/cgroup"):
    """Memory and CPU numbers of this container (cgroup v2), in MiB and seconds."""
    def read(name):
        try:
            with open(os.path.join(root, name), encoding="utf-8") as f:
                return f.read().strip()
        except OSError:
            return None

    def mib(value):
        return round(int(value) / 1048576.0, 1) if value and value.isdigit() else value

    stat = {}
    for line in (read("cpu.stat") or "").splitlines():
        key, _, value = line.partition(" ")
        if key in ("usage_usec", "nr_throttled", "throttled_usec"):
            stat[key] = int(value)
    return {"memory_current_mib": mib(read("memory.current")), "memory_peak_mib": mib(read("memory.peak")),
            "memory_max": mib(read("memory.max")), "cpu_max": read("cpu.max"), "cpu_stat": stat,
            "omp_num_threads": os.environ.get("OMP_NUM_THREADS")}


# ------------------------------------------------------------------ series
def percentile(values, p):
    """Nearest rank."""
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, int(math.ceil(p / 100.0 * len(ordered))))
    return round(ordered[rank - 1], 3)


def summary(seconds):
    return {"n": len(seconds), "p50_s": percentile(seconds, 50), "p95_s": percentile(seconds, 95),
            "max_s": round(max(seconds), 3) if seconds else None,
            "mean_s": round(sum(seconds) / len(seconds), 3) if seconds else None}


def series(client, bodies, heads=None, shadow=None):
    """Send each body once, in order. Latency of the answered ones; counts of the rest."""
    seconds, statuses, tokens, shadow_errors = [], {}, [], 0
    for body in bodies:
        status, value, s = client.ask(body, heads, shadow)
        statuses[str(status)] = statuses.get(str(status), 0) + 1
        if status == 200:
            seconds.append(s)
            usage = (value or {}).get("usage") or {}
            if isinstance(usage.get("input_tokens"), int):
                tokens.append(usage["input_tokens"])
            if shadow and "error" in ((value or {}).get("shadow") or {"error": "missing"}):
                shadow_errors += 1
    out = summary(seconds)
    out.update({"statuses": statuses, "max_input_tokens": max(tokens) if tokens else None,
                "shadow_errors": shadow_errors if shadow else None, "seconds": [round(s, 3) for s in seconds]})
    return out


def parallel_owners(client, bodies, owners, n):
    """`owners` threads at once, each with its own head hash, `n` requests in total."""
    per = max(1, n // len(owners))
    results = {sha: [] for sha in owners}
    errors = []

    def run(sha, offset):
        for i in range(per):
            status, _value, s = client.ask(bodies[(offset + i) % len(bodies)], heads=sha)
            if status == 200:
                results[sha].append(s)
            else:
                errors.append(status)

    threads = [threading.Thread(target=run, args=(sha, i * per)) for i, sha in enumerate(owners)]
    started = time.perf_counter()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    wall = time.perf_counter() - started
    everything = [s for values in results.values() for s in values]
    out = summary(everything)
    out.update({"owners": len(owners), "requests_per_owner": per, "wall_s": round(wall, 1),
                "errors": len(errors), "per_owner_p95_s": [percentile(v, 95) for v in results.values()]})
    return out


def cache_growth(client, bodies, heads, pid):
    """Load each head set with one request; memory after each. Cold time of the first request."""
    before = proc_memory(pid)
    steps = []
    for i, entry in enumerate(heads):
        status, _value, s = client.ask(bodies[i % len(bodies)], heads=entry["heads"])
        steps.append({"heads": entry["heads"][:8], "status": status, "cold_s": round(s, 3),
                      "memory": proc_memory(pid)})
    deltas = []
    previous = (before or {}).get("rss_mib")
    for step in steps:
        rss = (step["memory"] or {}).get("rss_mib")
        if previous is not None and rss is not None:
            deltas.append(round(rss - previous, 1))
        previous = rss
    return {"before": before, "steps": steps, "rss_delta_mib": deltas,
            "mean_delta_mib": round(sum(deltas) / len(deltas), 1) if deltas else None}


def run_suite(args):
    client = Client(args.url, token_from(args))
    client.wait(args.wait)
    pid = server_pid()
    cases = read_cases(args.cases)
    bodies = make_requests(cases, args.n, args.long_chars)
    report = {"url_scheme": client.scheme, "n": args.n, "label": args.label,
              "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "server_pid_visible": pid is not None, "idle": proc_memory(pid)}
    _status, health, _s = client.health()
    report["health"] = health
    # Cold: the first answer after the start of the server (no request before it).
    status, _value, s = client.ask(bodies[0])
    report["cold_first_request"] = {"status": status, "seconds": round(s, 3)}
    report["warm_default"] = series(client, bodies)
    heads = head_sets(args.heads_dir)
    if not args.skip_upload:
        report["upload"] = [client.upload(args.heads_dir, h["heads"])[0] for h in heads]
    shadow = heads[0]["heads"]
    # One request first, so the load of the head set is not in the warm series.
    client.ask(bodies[0], shadow=shadow)
    report["warm_shadow_on"] = series(client, bodies, shadow=shadow)
    report["warm_active_synthetic"] = series(client, bodies, heads=shadow)
    report["cache"] = cache_growth(client, bodies, heads[:args.owners], pid)
    report["owners_single"] = series(client, bodies, heads=heads[0]["heads"])
    report["owners_parallel"] = parallel_owners(client, bodies, [h["heads"] for h in heads[:args.owners]], args.n)
    report["peak"] = proc_memory(pid)
    single = report["owners_single"]["p95_s"]
    parallel = report["owners_parallel"]["p95_s"]
    report["checks"] = {
        "p95_warm_default_s": report["warm_default"]["p95_s"],
        "p95_shadow_on_s": report["warm_shadow_on"]["p95_s"],
        "p95_at_most_20_s": all(x is not None and x <= 20.0 for x in (
            report["warm_default"]["p95_s"], report["warm_shadow_on"]["p95_s"])),
        "per_owner_mib": report["cache"]["mean_delta_mib"],
        "per_owner_at_most_150_mib": (report["cache"]["mean_delta_mib"] is not None
                                      and report["cache"]["mean_delta_mib"] <= 150),
        "parallel_p95_ratio": round(parallel / single, 2) if single and parallel else None,
    }
    write_report(args.out, report)
    print(json.dumps(report["checks"], indent=2))


# ------------------------------------------------------------------ answers and equality
def run_answers(args):
    client = Client(args.url, token_from(args))
    client.wait(args.wait)
    cases = read_cases(args.cases)
    rows = []
    for i, (ok, category, raw, purpose) in enumerate(cases):
        instruction = OWNER_RULE if i % 2 == 1 else ""
        body = {"state": state_text(purpose, argv_command(raw), purpose, instruction),
                "questions": questions_for(instruction)}
        status, value, _s = client.ask(body, args.heads, args.shadow)
        row = {"case": i, "label": "ok" if ok else "risk", "category": category, "status": status}
        if status == 200:
            row["model"] = value.get("model")
            row["answers"] = {k: v.get("noul") for k, v in (value.get("answers") or {}).items()}
            shadow = value.get("shadow")
            if shadow is not None:
                row["shadow_model"] = shadow.get("model")
                row["shadow_answers"] = ({k: v.get("noul") for k, v in shadow["answers"].items()}
                                         if "answers" in shadow else None)
                row["shadow_error"] = shadow.get("error")
        rows.append(row)
    write_report(args.out, {"url_scheme": client.scheme, "heads": args.heads, "shadow": args.shadow,
                            "rows": rows})
    print("bench: %d answers, %d not 200" % (len(rows), sum(1 for r in rows if r["status"] != 200)))


def outcome(answers):
    """"run" or "ask" from the model facts of `decide` for an unknown command."""
    task = answers.get("task_match")
    if task is None or task < DEFAULT_TASK_MATCH:
        return "ask"
    if answers.get("destroy") is not None and answers["destroy"] >= DESTROY_VETO:
        return "ask"
    if answers.get("rule_break") is not None and 1.0 - answers["rule_break"] < MIN_CONFIDENCE:
        return "ask"
    return "run"


def compare_answers(a, b, tolerance, key="answers"):
    rows_a = {r["case"]: r for r in a["rows"]}
    rows_b = {r["case"]: r for r in b["rows"]}
    worst, per_question, outcome_diff, missing = 0.0, {}, [], []
    for case in sorted(set(rows_a) | set(rows_b)):
        ra, rb = rows_a.get(case), rows_b.get(case)
        if not ra or not rb or not ra.get(key) or not rb.get(key):
            missing.append(case)
            continue
        for q in sorted(set(ra[key]) | set(rb[key])):
            pa, pb = ra[key].get(q), rb[key].get(q)
            if pa is None or pb is None:
                missing.append(case)
                continue
            d = abs(pa - pb)
            per_question[q] = max(per_question.get(q, 0.0), d)
            worst = max(worst, d)
        if outcome(ra[key]) != outcome(rb[key]):
            outcome_diff.append(case)
    return {"key": key, "cases": len(set(rows_a) | set(rows_b)), "max_abs_delta": round(worst, 4),
            "max_abs_delta_per_question": {k: round(v, 4) for k, v in per_question.items()},
            "outcome_differs": outcome_diff, "missing": sorted(set(missing)),
            "equal": worst <= tolerance and not outcome_diff and not missing, "tolerance": tolerance}


def run_compare(args):
    a = json.load(open(args.a, encoding="utf-8"))
    b = json.load(open(args.b, encoding="utf-8"))
    result = compare_answers(a, b, args.tolerance, args.key)
    print(json.dumps(result, indent=2))
    return 0 if result["equal"] else 1


# ------------------------------------------------------------------ training
def run_train(args):
    """local_train.py on a training set, at a low CPU priority; wall time and peak memory."""
    init = args.init or os.environ.get("APASSY_BASE_MODEL", "")
    script = os.path.join(os.path.dirname(HERE), "finetune", "local_train.py")
    command = ["nice", "-n", "10", sys.executable, "-B", script, "--data", args.data,
               "--out", args.out, "--deadline", str(args.deadline)]
    if init:
        command += ["--init", init]
    os.makedirs(args.out, mode=0o700, exist_ok=True)
    started = time.perf_counter()
    status = subprocess.call(command)
    wall = time.perf_counter() - started
    child = resource.getrusage(resource.RUSAGE_CHILDREN)
    report = {"status": status, "wall_s": round(wall, 1),
              # ru_maxrss is KiB on Linux.
              "child_peak_rss_mib": round(child.ru_maxrss / 1024.0, 1), "cgroup": cgroup_numbers()}
    result = os.path.join(args.out, "result.json")
    if os.path.exists(result):
        value = json.load(open(result, encoding="utf-8"))
        report["result"] = {k: value.get(k) for k in ("version", "sha256", "train_seconds",
                                                      "encoder_cache_seconds", "total_seconds",
                                                      "train_examples", "val_examples", "best_epoch")}
    write_report(args.report, report)
    print(json.dumps({k: v for k, v in report.items() if k != "cgroup"}, indent=2))
    return status


# ------------------------------------------------------------------ dry run
def dry_run():
    """The generators without a server, torch or numpy (CI)."""
    cases = read_cases()
    train, val, stats = make_training_set(cases)
    assert stats["owner_decisions"] >= 300 and stats["owner_denials"] >= 30, stats
    assert train and val and stats["train"] == len(train) and stats["val"] == len(val)
    for row in train[:50] + val[:50]:
        assert set(row) == {"state", "question", "instructions", "answer", "teacher", "kind"}
        assert "/Users/" not in row["state"] and "/home/" not in row["state"]
    bodies = make_requests(cases, 50)
    sizes = sorted({len(b["questions"]) for b in bodies})
    assert sizes == [5, 6], sizes
    assert max(len(b["state"]) for b in bodies) < 2000
    manifest = json.load(open(DEFAULT_MANIFEST, encoding="utf-8"))
    with tempfile.TemporaryDirectory() as tmp:
        base = os.path.join(tmp, "base.safetensors")
        write_tiny_checkpoint(base)
        made = make_head_sets(base, DEFAULT_MANIFEST, os.path.join(tmp, "heads"), 2, 1)
        assert len({m["heads"] for m in made}) == 2
        stats_dir = os.path.join(tmp, "train")
        write_training_set(stats_dir, cases)
        assert sorted(os.listdir(stats_dir)) == ["stats.json", "train.jsonl", "val.jsonl"]
    print(json.dumps({"dry_run": "ok", "cases": len(cases), "train": stats["train"], "val": stats["val"],
                      "owner_decisions": stats["owner_decisions"], "owner_denials": stats["owner_denials"],
                      "denial_weight": stats["denial_weight"], "request_question_counts": sizes,
                      "base": manifest["version"]}, indent=2))
    return 0


def write_tiny_checkpoint(path):
    """A small F32 safetensors file with head tensor names, for the dry run and tests."""
    tensors = [("head.layers.0.weight", [4, 4]), ("scorer.0.weight", [4]), ("type_emb.weight", [3, 4])]
    header, offset, data = {}, 0, b""
    for i, (name, shape) in enumerate(tensors):
        n = 1
        for d in shape:
            n *= d
        header[name] = {"dtype": "F32", "shape": shape, "data_offsets": [offset, offset + 4 * n]}
        data += struct.pack("<%df" % n, *[(i + 1) * 0.1 + j * 0.01 for j in range(n)])
        offset += 4 * n
    header["__metadata__"] = {"apassy": json.dumps({"name": "tiny"})}
    encoded = json.dumps(header).encode()
    encoded += b" " * (-len(encoded) % 8)
    with open(path, "wb") as f:
        f.write(struct.pack("<Q", len(encoded)) + encoded + data)


def write_report(path, value):
    if not path:
        return
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(value, f, indent=2)
        f.write("\n")


# ------------------------------------------------------------------ command line
def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--dry-run", action="store_true", help="check the generators; no server, torch or numpy")
    sub = ap.add_subparsers(dest="command")

    def server(p):
        p.add_argument("--url", required=True)
        p.add_argument("--token-file", default="")
        p.add_argument("--wait", type=int, default=600, help="seconds to wait for /health")
        p.add_argument("--cases", default=DEFAULT_CASES)

    p = sub.add_parser("make-heads")
    p.add_argument("--base", default=os.environ.get("APASSY_BASE_MODEL", ""))
    p.add_argument("--manifest", default=DEFAULT_MANIFEST)
    p.add_argument("--out", required=True)
    p.add_argument("--count", type=int, default=10)
    p.add_argument("--seed", type=int, default=1)

    p = sub.add_parser("make-train")
    p.add_argument("--cases", default=DEFAULT_CASES)
    p.add_argument("--out", required=True)

    p = sub.add_parser("upload")
    server(p)
    p.add_argument("--heads-dir", default="", help="head sets of make-heads")
    p.add_argument("--candidate", action="append", default=[],
                   help="a candidate folder of local_train.py (repeatable)")

    p = sub.add_parser("latency")
    server(p)
    p.add_argument("--n", type=int, default=50)
    p.add_argument("--long-chars", type=int, default=1400)
    p.add_argument("--heads", default=None)
    p.add_argument("--shadow", default=None)
    p.add_argument("--out", default="")

    p = sub.add_parser("owners")
    server(p)
    p.add_argument("--heads-dir", required=True)
    p.add_argument("--owners", type=int, default=10)
    p.add_argument("--n", type=int, default=50)
    p.add_argument("--long-chars", type=int, default=1400)
    p.add_argument("--out", default="")

    p = sub.add_parser("cache")
    server(p)
    p.add_argument("--heads-dir", required=True)
    p.add_argument("--count", type=int, default=10)
    p.add_argument("--out", default="")

    p = sub.add_parser("suite")
    server(p)
    p.add_argument("--heads-dir", required=True)
    p.add_argument("--n", type=int, default=50)
    p.add_argument("--owners", type=int, default=10)
    p.add_argument("--long-chars", type=int, default=1400)
    p.add_argument("--skip-upload", action="store_true")
    p.add_argument("--label", default="")
    p.add_argument("--out", required=True)

    p = sub.add_parser("answers")
    server(p)
    p.add_argument("--heads", default=None)
    p.add_argument("--shadow", default=None)
    p.add_argument("--out", required=True)

    p = sub.add_parser("compare")
    p.add_argument("a")
    p.add_argument("b")
    p.add_argument("--tolerance", type=float, default=0.02)
    p.add_argument("--key", default="answers", choices=["answers", "shadow_answers"])

    p = sub.add_parser("train")
    p.add_argument("--data", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--init", default="")
    p.add_argument("--deadline", type=int, default=3 * 3600)
    p.add_argument("--report", default="")

    sub.add_parser("rss")
    sub.add_parser("cgroup")

    args = ap.parse_args(argv)
    if args.dry_run:
        return dry_run()
    if args.command == "make-heads":
        if not args.base:
            raise SystemExit("bench: --base or APASSY_BASE_MODEL names the base checkpoint")
        made = make_head_sets(args.base, args.manifest, args.out, args.count, args.seed)
        print(json.dumps(made, indent=2))
    elif args.command == "make-train":
        print(json.dumps(write_training_set(args.out, read_cases(args.cases)), indent=2))
    elif args.command == "upload":
        client = Client(args.url, token_from(args))
        client.wait(args.wait)
        if not args.heads_dir and not args.candidate:
            raise SystemExit("bench: upload needs --heads-dir or --candidate")
        uploads = []
        if args.heads_dir:
            for entry in head_sets(args.heads_dir):
                uploads.append((entry["heads"], client.upload(args.heads_dir, entry["heads"])))
        for folder in args.candidate:
            uploads.append(client.upload_candidate(folder))
        failed = 0
        for sha, (status, value, s) in uploads:
            failed += status not in (200, 201)
            print("%s %s %d %.1fs %s" % (sha, "ok" if status in (200, 201) else "FAILED", status, s,
                                        (value or {}).get("model") or (value or {}).get("detail")))
        return 1 if failed else 0
    elif args.command == "latency":
        client = Client(args.url, token_from(args))
        client.wait(args.wait)
        result = series(client, make_requests(read_cases(args.cases), args.n, args.long_chars),
                        args.heads, args.shadow)
        write_report(args.out, result)
        print(json.dumps({k: v for k, v in result.items() if k != "seconds"}, indent=2))
    elif args.command == "owners":
        client = Client(args.url, token_from(args))
        client.wait(args.wait)
        bodies = make_requests(read_cases(args.cases), args.n, args.long_chars)
        result = parallel_owners(client, bodies, [h["heads"] for h in head_sets(args.heads_dir)[:args.owners]],
                                 args.n)
        write_report(args.out, result)
        print(json.dumps(result, indent=2))
    elif args.command == "cache":
        client = Client(args.url, token_from(args))
        client.wait(args.wait)
        bodies = make_requests(read_cases(args.cases), args.count)
        result = cache_growth(client, bodies, head_sets(args.heads_dir)[:args.count], server_pid())
        write_report(args.out, result)
        print(json.dumps(result, indent=2))
    elif args.command == "suite":
        run_suite(args)
    elif args.command == "answers":
        run_answers(args)
    elif args.command == "compare":
        return run_compare(args)
    elif args.command == "train":
        return run_train(args)
    elif args.command == "rss":
        pid = server_pid()
        print(json.dumps({"pid": pid, "memory": proc_memory(pid)}, indent=2))
    elif args.command == "cgroup":
        print(json.dumps(cgroup_numbers(), indent=2))
    else:
        ap.print_help()
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
