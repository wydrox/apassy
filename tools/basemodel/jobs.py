"""Training jobs of the bouncer brain server (ADR 0035, unit I-srv; contract bouncer-brain-v2 section 4).

A job trains the heads on this server with `tools/finetune/local_train.py`, from the
examples of one upload (`PUT /v1/train/<sha256>`, routes in `app.py`). The job id is
the SHA-256 of the upload body.

Folders (all mode 0700, files 0600), under the jobs folder:

    <owner key>/<job id>/state.json     the job state, kept 7 days after the end
    <owner key>/<job id>/examples/      train.jsonl, val.jsonl, stats.json (the trainer's --data)
    <owner key>/<job id>/out/           the trainer's --out (encoder cache, reports)
    <owner key>/<job id>/result/        candidate.safetensors and manifest.json of a done job
    <owner key>/.upload-*/              an upload in progress

The owner key is a hash of the owner id, so no account id is a folder name. An own
server has one owner (`OWN_SERVER`); a Connect server (unit D2) passes the account.

Rules (contract section 4.7):

- One job per owner at a time (`job_busy`), and one job per server runs at a time.
- A job starts only when the host has the memory cap of the trainer plus 1 GiB free
  (plan 0035 K1); else it stays `queued`.
- The examples and every trainer file except the result are deleted when the job
  ends (`done`, `failed`, `deleted`), before the state changes, and at the latest
  24 hours after the upload, whatever the state. The sweep also runs at the start,
  so the rule holds after a crash.
- The result stays until the owner deletes the job, at the latest 7 days after the
  end. The state of a `failed` or `deleted` job is kept 7 days, then the id is unknown.
- No log line has an example, a state, a question, an answer, or the owner: only the
  first 8 hex of the job id, counts, times, states and error codes. The trainer's
  output goes nowhere (it could show example text in a traceback).

This module has no torch or FastAPI import: the trainer runs in a subprocess, and the
tests give a fake trainer, a fake clock and a fake memory reading.
"""

import base64
import hashlib
import json
import logging
import math
import numbers
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

# No __pycache__ next to this script: in Apassy.app it breaks the code signature.
_WRITE_BYTECODE = sys.dont_write_bytecode
sys.dont_write_bytecode = True
import common  # noqa: E402
import heads_cache  # noqa: E402

sys.dont_write_bytecode = _WRITE_BYTECODE

LOG = logging.getLogger("apassy.brain")

KIND = "apassy-train-job-v1"
OWN_SERVER = "own-server"
MAX_UPLOAD_BYTES = 64 * 1024 * 1024
MAX_RESULT_MANIFEST_BYTES = 12 * 1024
MAX_METRICS_BYTES = 8 * 1024
EXAMPLES_TTL = 24 * 3600
RESULT_TTL = 7 * 24 * 3600
STATE_TTL = 7 * 24 * 3600
# Plan 0035 K1: the remote job deadline is 2 x the measured time, at most 3 h.
MAX_DEADLINE = 3 * 3600
# Plan 0035 decision 2: one training job gets 2 vCPU / 4 GB; it starts only with its
# limit + 1 GB free (K1).
DEFAULT_MEMORY_BYTES = 4 * 1024 ** 3
MEMORY_HEADROOM = 1024 ** 3
NICE = 10
SWEEP_EVERY = 60
# The training gate (`src/broker/finetune.rs:43-45`, `local_train.py`).
MIN_OWNER_DECISIONS = 300
MIN_OWNER_DENIALS = 30

CHECKPOINT = "candidate.safetensors"
STATE_FILE = "state.json"
UPLOAD_PREFIX = ".upload-"
OWNER_KEY_RE = re.compile(r"\A[0-9a-f]{32}\Z")

STATES = ("queued", "running", "done", "failed", "deleted")
ERRORS = ("training_failed", "deadline", "expired", "interrupted", "bad_result")


class JobError(heads_cache.HeadsError):
    """An answer of the job routes: status, code, and a message without request data."""


def bad_job(message, status=400):
    return JobError(status, "bad_job", message)


def unknown_job():
    return JobError(404, "unknown_job", "this owner has no such job")


def job_busy():
    return JobError(409, "job_busy", "another job of this owner is queued or running")


def job_not_done():
    return JobError(409, "job_not_done", "the job is not done, or its result was deleted")


def check_job_id(value):
    """`value` if it is 64 lowercase hex characters, else 422 `bad_job`."""
    if not isinstance(value, str) or not heads_cache.HASH_RE.match(value):
        raise bad_job("a job is named by 64 lowercase hex characters (SHA-256)", status=422)
    return value


def log_id(value):
    return value[:8] if isinstance(value, str) and heads_cache.HASH_RE.match(value) else "-"


def owner_key(owner):
    """The folder name of an owner: no account id on disk in clear."""
    return hashlib.sha256(b"apassy-brain owner\0" + owner.encode("utf-8")).hexdigest()[:32]


def _count(value):
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


# ------------------------------------------------------------------ the upload checks
def decode_manifest_header(value):
    """`Apassy-Manifest` of a job: (raw, dict). 413 `too_large` over 16 KiB, else 400 `bad_job`."""
    try:
        return heads_cache.decode_manifest_header(value)
    except heads_cache.HeadsError as error:
        if error.status == 413:
            raise
        raise bad_job(error.message) from None


def check_job_manifest(manifest, base):
    """The checks of contract section 4.1 that need no body (3, 4, 5 and the form of 4.2)."""
    if manifest.get("schema") != 1 or isinstance(manifest.get("schema"), bool):
        raise bad_job("the job manifest has no schema 1")
    if manifest.get("kind") != KIND:
        raise bad_job("the manifest is not a job manifest (kind %s)" % KIND)
    name = manifest.get("name")
    if not isinstance(name, str) or not heads_cache.NAME_RE.match(name):
        raise bad_job("manifest name must be 1-55 characters of A-Z, a-z, 0-9, '.', '_', '-'")
    base_manifest = manifest.get("base")
    if not isinstance(base_manifest, dict):
        raise bad_job("the job manifest has no base block")
    if base_manifest.get("revision") != base["revision"]:
        raise bad_job("the job manifest names another base revision")
    if base_manifest.get("weights_sha256") != base["weights_sha256"]:
        raise bad_job("the job manifest names other base weights")
    files = manifest.get("files")
    if not isinstance(files, dict):
        raise bad_job("the job manifest has no files block")
    for part in ("train", "val"):
        entry = files.get(part)
        if (not isinstance(entry, dict) or not _count(entry.get("size_bytes"))
                or not isinstance(entry.get("sha256"), str) or not heads_cache.HASH_RE.match(entry["sha256"])):
            raise bad_job("manifest files.%s needs size_bytes and a sha256 of 64 lowercase hex" % part)
    stats = manifest.get("stats")
    if not isinstance(stats, dict) or not all(isinstance(k, str) and _count(v) for k, v in stats.items()):
        raise bad_job("manifest stats must be an object of non-negative integers")
    for key in ("owner_decisions", "owner_denials", "train", "val"):
        if key not in stats:
            raise bad_job("manifest stats has no %s" % key)
    if stats["owner_decisions"] < MIN_OWNER_DECISIONS or stats["owner_denials"] < MIN_OWNER_DENIALS:
        raise bad_job("the training gate needs %d owner decisions and %d owner denials"
                      % (MIN_OWNER_DECISIONS, MIN_OWNER_DENIALS))
    if stats["train"] == 0 or stats["val"] == 0:
        raise bad_job("the job has no training or no validation examples")
    if not isinstance(manifest.get("keep_heads"), bool):
        raise bad_job("manifest keep_heads must be true or false")


def body_size(manifest):
    return manifest["files"]["train"]["size_bytes"] + manifest["files"]["val"]["size_bytes"]


# ------------------------------------------------------------------ files
def _private_dir(path):
    os.makedirs(path, mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def _write_private(path, data):
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def _remove_tree(path):
    shutil.rmtree(path, ignore_errors=True)


class Upload:
    """One upload in progress: the body goes to `train.jsonl` then `val.jsonl` of a staging
    folder, hashed on the way. Never held in memory."""

    def __init__(self, manager, owner, job_id, manifest):
        self.manager = manager
        self.owner = owner
        self.job_id = job_id
        self.manifest = manifest
        self.train_size = manifest["files"]["train"]["size_bytes"]
        self.expected = body_size(manifest)
        owner_dir = _private_dir(os.path.join(manager.jobs_dir, owner_key(owner)))
        self.staging = tempfile.mkdtemp(prefix=UPLOAD_PREFIX, dir=owner_dir)
        os.chmod(self.staging, 0o700)
        examples = _private_dir(os.path.join(self.staging, "examples"))
        self._files = [self._open(os.path.join(examples, "train.jsonl")),
                       self._open(os.path.join(examples, "val.jsonl"))]
        self._digests = [hashlib.sha256(), hashlib.sha256()]
        self._whole = hashlib.sha256()
        self.size = 0

    @staticmethod
    def _open(path):
        return os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb")

    def write(self, chunk):
        if self.size + len(chunk) > min(self.expected, self.manager.max_upload):
            if self.size + len(chunk) > self.manager.max_upload:
                raise JobError(413, "too_large", "the job body is larger than %d bytes" % self.manager.max_upload)
            raise bad_job("the body is longer than the files of the manifest")
        self._whole.update(chunk)
        view = memoryview(chunk)
        if self.size < self.train_size:
            head = view[:self.train_size - self.size]
            self._files[0].write(head)
            self._digests[0].update(head)
            view = view[len(head):]
        if len(view):
            self._files[1].write(view)
            self._digests[1].update(view)
        self.size += len(chunk)

    def _close_files(self):
        for f in self._files:
            if not f.closed:
                f.flush()
                os.fsync(f.fileno())
                f.close()

    def check(self):
        """Checks 1 and 2 of contract section 4.1, after the body."""
        self._close_files()
        if self._whole.hexdigest() != self.job_id:
            raise bad_job("the SHA-256 of the body is not the SHA-256 in the path")
        if self.size != self.expected:
            raise bad_job("the body size is not the sum of the file sizes of the manifest")
        files = self.manifest["files"]
        if self._digests[0].hexdigest() != files["train"]["sha256"]:
            raise bad_job("the SHA-256 of train.jsonl does not match the manifest")
        if self._digests[1].hexdigest() != files["val"]["sha256"]:
            raise bad_job("the SHA-256 of val.jsonl does not match the manifest")

    def discard(self):
        for f in self._files:
            try:
                f.close()
            except OSError:
                pass
        _remove_tree(self.staging)


# ------------------------------------------------------------------ the trainer
# Runs as `python -I -B -c LAUNCHER <nice> <memory bytes> <python> <script> <args...>`: it
# lowers the CPU priority, caps the data segment, then becomes the trainer. No
# `preexec_fn`: the server has threads, and `preexec_fn` is not safe with threads.
LAUNCHER = """
import os, resource, sys
nice, memory = int(sys.argv[1]), int(sys.argv[2])
os.nice(nice)
if memory > 0:
    resource.setrlimit(resource.RLIMIT_DATA, (memory, memory))
os.execv(sys.argv[3], sys.argv[3:])
"""


class TrainerProcess:
    """A running trainer: its own process group, so a stop ends every child."""

    def __init__(self, popen):
        self.popen = popen

    def poll(self):
        return self.popen.poll()

    def wait(self, timeout):
        try:
            return self.popen.wait(timeout)
        except subprocess.TimeoutExpired:
            return None

    def stop(self):
        if self.popen.poll() is not None:
            return
        for sig, grace in ((signal.SIGTERM, 5), (signal.SIGKILL, 5)):
            try:
                os.killpg(self.popen.pid, sig)
            except (ProcessLookupError, PermissionError):
                pass
            try:
                self.popen.wait(grace)
                return
            except subprocess.TimeoutExpired:
                continue


class LocalTrainer:
    """`tools/finetune/local_train.py` in a subprocess at a low CPU priority with a memory cap."""

    def __init__(self, script, init="", python=None, deadline=MAX_DEADLINE,
                 memory_bytes=DEFAULT_MEMORY_BYTES, nice=NICE):
        self.script = os.path.abspath(script)
        self.init = init or ""
        self.python = python or sys.executable
        self.deadline = max(1, min(int(deadline), MAX_DEADLINE))
        self.memory_bytes = max(0, int(memory_bytes))
        self.nice = int(nice)

    @property
    def available(self):
        return os.path.isfile(self.script)

    def command(self, data_dir, out_dir, name):
        command = [self.python, "-I", "-B", "-c", LAUNCHER, str(self.nice), str(self.memory_bytes),
                   self.python, "-B", self.script, "--data", data_dir, "--out", out_dir,
                   "--name", name, "--deadline", str(self.deadline)]
        if self.init:
            command += ["--init", self.init]
        return command

    @staticmethod
    def environment():
        # The trainer needs no token or service secret of this server.
        return {k: v for k, v in os.environ.items()
                if k not in ("LAYA_API_KEY", "LAYA_API_KEY_FILE") and not k.startswith("APASSY_BRAIN_")}

    def start(self, job_dir, data_dir, out_dir, name):
        popen = subprocess.Popen(
            self.command(data_dir, out_dir, name), cwd=job_dir, env=self.environment(),
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True, close_fds=True)
        return TrainerProcess(popen)


def memory_free_bytes(cgroup="/sys/fs/cgroup", meminfo="/proc/meminfo"):
    """Free memory for a new job: the lower of the cgroup room and MemAvailable; None when unknown."""
    values = []
    try:
        with open(os.path.join(cgroup, "memory.max"), encoding="ascii") as f:
            limit = f.read().strip()
        with open(os.path.join(cgroup, "memory.current"), encoding="ascii") as f:
            current = int(f.read().strip())
        if limit != "max":
            values.append(max(0, int(limit) - current))
    except (OSError, ValueError):
        pass
    try:
        with open(meminfo, encoding="ascii") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    values.append(int(line.split()[1]) * 1024)
                    break
    except (OSError, ValueError, IndexError):
        pass
    return min(values) if values else None


# ------------------------------------------------------------------ the result
def finite_metrics(value, depth=0):
    """The numbers of the trainer's result.json: finite numbers, or objects of them. No string."""
    if not isinstance(value, dict):
        return {}
    out = {}
    for key, item in value.items():
        if not isinstance(key, str):
            continue
        if isinstance(item, bool):
            continue
        if isinstance(item, numbers.Real) and math.isfinite(item):
            out[key] = item
        elif isinstance(item, dict) and depth < 2:
            nested = finite_metrics(item, depth + 1)
            if nested:
                out[key] = nested
    return out


def compact(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


# ------------------------------------------------------------------ the jobs
class JobManager:
    """Every job of the server. Thread-safe: the routes, the runner and the sweeper share one lock.

    `trainer.start(job_dir, data_dir, out_dir, name)` gives a process with `poll()`,
    `wait(timeout)` and `stop()`. `store_heads(key, path, raw, manifest)` stores a
    result as a head set of the owner (`keep_heads`) and returns whether it did; `key`
    is (owner key, job id), so a Connect server (unit D2) can find the namespace.
    `memory_free()` gives free bytes or None (unknown: the job may start).
    """

    def __init__(self, jobs_dir, base, trainer, expected_shapes=None, store_heads=None,
                 clock=time.time, memory_free=memory_free_bytes, memory_needed=None,
                 max_upload=MAX_UPLOAD_BYTES, log=LOG):
        self.jobs_dir = os.path.abspath(jobs_dir)
        self.base = {"revision": base["revision"], "weights_sha256": base["weights_sha256"]}
        self.trainer = trainer
        self.expected_shapes = expected_shapes
        self.store_heads = store_heads
        self.clock = clock
        self.memory_free = memory_free
        if memory_needed is None:
            cap = getattr(trainer, "memory_bytes", DEFAULT_MEMORY_BYTES)
            memory_needed = cap + MEMORY_HEADROOM if cap else 0
        self.memory_needed = memory_needed
        self.max_upload = max_upload
        self.log = log
        self._lock = threading.RLock()
        self._wake = threading.Condition(self._lock)
        self._jobs = {}            # (owner key, job id) -> state dict
        self._running = None       # (key, process, wall deadline)
        self._stopping = {}        # key -> reason of a stop that the server asked for
        self._closed = False
        self._thread = None
        _private_dir(self.jobs_dir)
        self.recover()

    @property
    def available(self):
        return bool(getattr(self.trainer, "available", True))

    def now(self):
        return int(self.clock())

    # ---------------------------------------------------------------- paths and states
    def _dir(self, key):
        return os.path.join(self.jobs_dir, key[0], key[1])

    def _persist(self, key):
        job = self._jobs[key]
        _write_private(os.path.join(self._dir(key), STATE_FILE), compact(job))

    def _note(self, key, what):
        job = self._jobs.get(key)
        self.log.info("job %s %s state=%s error=%s", log_id(key[1]), what,
                      job["state"] if job else "-", (job or {}).get("error") or "-")

    @staticmethod
    def view(job):
        """The answer of `GET /v1/train/<sha256>` (contract section 4.3)."""
        done = job["state"] == "done"
        return {
            "job": job["job"],
            "state": job["state"],
            "created_at": job["created_at"],
            "started_at": job["started_at"],
            "ended_at": job["ended_at"],
            "examples_held": job["examples_deleted_at"] is None,
            "examples_deleted_at": job["examples_deleted_at"],
            "examples_deadline": job["created_at"] + EXAMPLES_TTL,
            "result_deadline": job["ended_at"] + RESULT_TTL if done else None,
            "error": job["error"] if job["state"] == "failed" else None,
            "result": job["result"] if done else None,
        }

    def recover(self):
        """At the start: load the states, end the jobs that ran when the server stopped, and sweep."""
        with self._lock:
            self._jobs.clear()
            for owner_dir in sorted(os.listdir(self.jobs_dir)):
                path = os.path.join(self.jobs_dir, owner_dir)
                if not OWNER_KEY_RE.match(owner_dir) or not os.path.isdir(path):
                    continue
                for name in sorted(os.listdir(path)):
                    job_dir = os.path.join(path, name)
                    if name.startswith(UPLOAD_PREFIX):
                        _remove_tree(job_dir)
                        continue
                    if not heads_cache.HASH_RE.match(name):
                        continue
                    try:
                        with open(os.path.join(job_dir, STATE_FILE), encoding="utf-8") as f:
                            job = json.load(f)
                        if job.get("job") != name or job.get("state") not in STATES:
                            raise ValueError("not a job state")
                    except (OSError, ValueError, RecursionError):
                        # A folder without a readable state is not a job: nothing of it stays.
                        _remove_tree(job_dir)
                        continue
                    key = (owner_dir, name)
                    self._jobs[key] = job
                    if job["state"] == "running":
                        self._fail(key, "interrupted")
            self.sweep()

    # ---------------------------------------------------------------- the routes
    def get(self, owner, job_id):
        with self._lock:
            job = self._jobs.get((owner_key(owner), job_id))
            if job is None:
                raise unknown_job()
            return self.view(job)

    def begin(self, owner, job_id, manifest):
        """Before the body: (existing job view, None) for an idempotent PUT, else (None, Upload).
        Raises 409 `job_busy`."""
        with self._lock:
            key = (owner_key(owner), job_id)
            existing = self._jobs.get(key)
            if existing is not None and existing["state"] != "deleted":
                return self.view(existing), None
            self._check_busy(key)
            # Under the lock: the sweeper removes an owner folder without jobs or uploads.
            return None, Upload(self, owner, job_id, manifest)

    def _check_busy(self, key):
        for other, job in self._jobs.items():
            if other[0] == key[0] and other[1] != key[1] and job["state"] in ("queued", "running"):
                raise job_busy()

    def commit(self, upload):
        """After the body: check it and queue the job. Returns (created, view). Takes over `upload`."""
        try:
            upload.check()
            stats = dict(upload.manifest["stats"])
            _write_private(os.path.join(upload.staging, "examples", "stats.json"),
                           json.dumps(stats, indent=2).encode("utf-8") + b"\n")
            with self._lock:
                key = (owner_key(upload.owner), upload.job_id)
                existing = self._jobs.get(key)
                if existing is not None and existing["state"] != "deleted":
                    upload.discard()
                    return False, self.view(existing)
                self._check_busy(key)
                now = self.now()
                job = {
                    "job": upload.job_id, "state": "queued", "created_at": now,
                    "started_at": None, "ended_at": None, "examples_deleted_at": None,
                    "closed_at": None, "error": None, "result": None,
                    "name": upload.manifest["name"], "keep_heads": upload.manifest["keep_heads"],
                }
                _write_private(os.path.join(upload.staging, STATE_FILE), compact(job))
                target = self._dir(key)
                _remove_tree(target)
                os.replace(upload.staging, target)
                self._jobs[key] = job
                self._note(key, "queued")
                self._wake.notify_all()
                return True, self.view(job)
        except BaseException:
            upload.discard()
            raise

    def delete(self, owner, job_id):
        """`DELETE /v1/train/<sha256>`: stop, delete the examples and the result; `deleted`."""
        with self._lock:
            key = (owner_key(owner), job_id)
            job = self._jobs.get(key)
            if job is None:
                raise unknown_job()
            if job["state"] == "deleted":
                return
            self._stop_if_running(key, "deleted")
            self._end(key, "deleted")
            self._note(key, "deleted")

    def delete_owner(self, owner):
        """`DELETE /v1/owner`: every job of the owner goes, with its folder. Counts of section 6.3."""
        jobs = examples = 0
        with self._lock:
            okey = owner_key(owner)
            for key in [k for k in self._jobs if k[0] == okey]:
                job = self._jobs[key]
                if job["state"] != "deleted":
                    jobs += 1
                if job["examples_deleted_at"] is None:
                    examples += 1
                self._stop_if_running(key, "deleted")
                del self._jobs[key]
            _remove_tree(os.path.join(self.jobs_dir, okey))
        return {"jobs": jobs, "examples": examples}

    def open_result(self, owner, job_id):
        """The open head file of a done job and its size (`GET /v1/train/<sha256>/result`)."""
        with self._lock:
            key = (owner_key(owner), job_id)
            job = self._jobs.get(key)
            if job is None:
                raise unknown_job()
            if job["state"] != "done":
                raise job_not_done()
            try:
                f = open(os.path.join(self._dir(key), "result", CHECKPOINT), "rb")
            except OSError:
                raise job_not_done() from None
            return f, os.fstat(f.fileno()).st_size

    # ---------------------------------------------------------------- endings
    def _delete_examples(self, key):
        job_dir = self._dir(key)
        _remove_tree(os.path.join(job_dir, "examples"))
        _remove_tree(os.path.join(job_dir, "out"))
        job = self._jobs[key]
        if job["examples_deleted_at"] is None:
            job["examples_deleted_at"] = self.now()

    def _end(self, key, state, error=None, result=None):
        """The job ends in `state`. The examples go first, then the state changes."""
        self._delete_examples(key)
        job = self._jobs[key]
        if state != "done":
            _remove_tree(os.path.join(self._dir(key), "result"))
        now = self.now()
        if job["ended_at"] is None:
            job["ended_at"] = now
        job["state"] = state
        job["error"] = error
        job["result"] = result
        job["closed_at"] = None if state == "done" else now
        self._persist(key)

    def _fail(self, key, error):
        self._end(key, "failed", error=error)
        self._note(key, "ended")

    def _stop_if_running(self, key, reason):
        running = self._running
        if running is not None and running[0] == key:
            self._stopping[key] = reason
            running[1].stop()

    # ---------------------------------------------------------------- the sweeper
    def sweep(self):
        """The 24-hour, 7-day and state rules. Runs at the start and every minute."""
        with self._lock:
            now = self.now()
            for key in list(self._jobs):
                job = self._jobs[key]
                if job["examples_deleted_at"] is None and now >= job["created_at"] + EXAMPLES_TTL:
                    if job["state"] == "queued":
                        self._fail(key, "expired")
                    elif job["state"] == "running":
                        self._stop_if_running(key, "deadline")
                        self._fail(key, "deadline")
                    else:
                        self._delete_examples(key)
                        self._persist(key)
                if job["state"] == "done" and now >= job["ended_at"] + RESULT_TTL:
                    self._end(key, "deleted")
                    self._note(key, "result expired")
                if job["state"] in ("failed", "deleted") and now >= (job["closed_at"] or now) + STATE_TTL:
                    _remove_tree(self._dir(key))
                    del self._jobs[key]
            # Uploads that a crash left behind, and owner folders without jobs.
            owners = {k[0] for k in self._jobs}
            for owner_dir in os.listdir(self.jobs_dir):
                path = os.path.join(self.jobs_dir, owner_dir)
                if not OWNER_KEY_RE.match(owner_dir) or not os.path.isdir(path):
                    continue
                if owner_dir not in owners and not any(n.startswith(UPLOAD_PREFIX) for n in os.listdir(path)):
                    _remove_tree(path)

    # ---------------------------------------------------------------- the runner
    def start_next(self):
        """Start the oldest queued job if no job runs and the memory is free. The started key or None."""
        with self._lock:
            if self._running is not None or self._closed:
                return None
            # Oldest first; `sorted` is stable, so equal times keep the upload order.
            queued = sorted(((job["created_at"], key) for key, job in self._jobs.items()
                             if job["state"] == "queued"), key=lambda item: item[0])
            if not queued:
                return None
            if self.memory_needed:
                free = self.memory_free()
                if free is not None and free < self.memory_needed:
                    return None
            key = queued[0][1]
            job_dir = self._dir(key)
            out_dir = _private_dir(os.path.join(job_dir, "out"))
            try:
                process = self.trainer.start(job_dir, os.path.join(job_dir, "examples"), out_dir,
                                             self._jobs[key]["name"])
            except OSError:
                self._fail(key, "training_failed")
                return None
            job = self._jobs[key]
            job["state"] = "running"
            job["started_at"] = self.now()
            deadline = job["started_at"] + getattr(self.trainer, "deadline", MAX_DEADLINE) + 30
            self._running = (key, process, deadline)
            self._persist(key)
            self._note(key, "started")
            return key

    def finish(self, poll=1.0):
        """Wait for the running job and end it. Returns the key that ended, or None."""
        running = self._running
        if running is None:
            return None
        key, process, deadline = running
        last_sweep = self.clock()
        while True:
            code = process.poll()
            if code is not None:
                break
            if self.clock() >= deadline:
                with self._lock:
                    self._stopping.setdefault(key, "deadline")
                process.stop()
                continue
            if self.clock() - last_sweep >= SWEEP_EVERY:
                self.sweep()
                last_sweep = self.clock()
            process.wait(poll)
        with self._lock:
            self._running = None
            reason = self._stopping.pop(key, None)
            job = self._jobs.get(key)
            if job is None or job["state"] != "running":
                # Deleted, swept or closed while it ran: that path ended it.
                return key
            if reason is not None:
                self._fail(key, "interrupted" if reason == "interrupted" else "deadline")
            elif code == -signal.SIGALRM:
                self._fail(key, "deadline")
            elif code != 0:
                self._fail(key, "training_failed")
            else:
                self._complete(key)
            self._wake.notify_all()
        return key

    def run_once(self):
        """Start the next job and wait for its end (the tests call this; the thread loops it)."""
        key = self.start_next()
        if key is not None:
            self.finish()
        return key

    def _complete(self, key):
        job = self._jobs[key]
        job_dir = self._dir(key)
        out_dir = os.path.join(job_dir, "out")
        try:
            result, raw = self._check_result(job, out_dir)
        except (OSError, ValueError, KeyError, TypeError, RecursionError, heads_cache.HeadsError):
            self._fail(key, "bad_result")
            return
        result_dir = _private_dir(os.path.join(job_dir, "result"))
        os.replace(os.path.join(out_dir, CHECKPOINT), os.path.join(result_dir, CHECKPOINT))
        _write_private(os.path.join(result_dir, "manifest.json"), raw)
        stored = False
        if job["keep_heads"] and self.store_heads is not None:
            try:
                stored = bool(self.store_heads(key, os.path.join(result_dir, CHECKPOINT), raw, result["manifest"]))
            except (OSError, ValueError, heads_cache.HeadsError):
                stored = False
        result["stored"] = stored
        self._end(key, "done", result=result)
        self._note(key, "ended")

    def _check_result(self, job, out_dir):
        """The output checks of contract section 4.4, as `read_result` on the Mac."""
        checkpoint = os.path.join(out_dir, CHECKPOINT)
        with open(os.path.join(out_dir, "manifest.json"), encoding="utf-8") as f:
            manifest = json.load(f)
        try:
            with open(os.path.join(out_dir, "result.json"), encoding="utf-8") as f:
                trainer_result = json.load(f)
        except (OSError, ValueError):
            trainer_result = {}
        size = os.path.getsize(checkpoint)
        digest = common.sha256_file(checkpoint)
        model = heads_cache.model_name(job["name"], digest)
        if not isinstance(manifest, dict) or manifest.get("name") != job["name"]:
            raise ValueError("another name")
        if manifest.get("version") != model:
            raise ValueError("another version")
        heads_cache.check_manifest(manifest, digest, self.base)
        if manifest["checkpoint"]["size_bytes"] != size:
            raise ValueError("another size")
        heads_cache.check_head_file(checkpoint, self.expected_shapes)
        raw = compact(manifest)
        if len(raw) > MAX_RESULT_MANIFEST_BYTES:
            raise ValueError("manifest too large")
        # Never a path of this server in an answer.
        if self.jobs_dir.encode("utf-8") in raw or b'"/' in raw:
            raise ValueError("a path in the manifest")
        metrics = finite_metrics(trainer_result)
        if len(compact(metrics)) > MAX_METRICS_BYTES:
            metrics = {k: v for k, v in metrics.items() if not isinstance(v, dict)}
        return {"heads": digest, "model": model, "size_bytes": size, "stored": False,
                "manifest": manifest, "metrics": metrics}, raw

    # ---------------------------------------------------------------- the thread
    def start(self):
        """The runner thread: one job at a time, a sweep every minute."""
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._loop, name="apassy-jobs", daemon=True)
        self._thread.start()

    def _loop(self):
        while True:
            with self._lock:
                if self._closed:
                    return
            try:
                self.sweep()
                if self.run_once() is None:
                    with self._lock:
                        if not self._closed:
                            self._wake.wait(SWEEP_EVERY if self.memory_needed == 0 else 10)
            except Exception as error:  # noqa: BLE001 -- the runner never dies; no request data
                self.log.warning("jobs runner: %s", type(error).__name__)
                time.sleep(1)

    def close(self):
        """At the server stop: a running job ends as `interrupted` and its examples go."""
        with self._lock:
            self._closed = True
            running = self._running
            if running is not None:
                self._stop_if_running(running[0], "interrupted")
                if self._jobs.get(running[0], {}).get("state") == "running":
                    self._fail(running[0], "interrupted")
            self._wake.notify_all()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=15)


# ------------------------------------------------------------------ serve.py
def own_server_store(cache):
    """`store_heads` for an own server: the result becomes an uploaded head set of the cache."""

    def store(_key, path, raw, manifest):
        sha = manifest["checkpoint"]["sha256"]
        heads_cache.check_manifest(manifest, sha, cache.base, cache.stock_available)
        cache.check_room(sha)
        out, upload = cache.new_upload()
        try:
            with out, open(path, "rb") as src:
                shutil.copyfileobj(src, out, 1 << 20)
                out.flush()
                os.fsync(out.fileno())
            cache.store(sha, upload, raw, manifest)
            upload = None
        except heads_cache.HeadsError:
            return False
        finally:
            if upload is not None:
                try:
                    os.unlink(upload)
                except FileNotFoundError:
                    pass
        return True

    return store


def env_int(name, default, environ=None):
    environ = os.environ if environ is None else environ
    raw = (environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        value = -1
    if value < 0:
        raise SystemExit("serve: invalid %s %r: must be an integer >= 0" % (name, raw))
    return value


def from_env(cache, checkpoint, heads_dir, environ=None, log=LOG):
    """The job manager of `serve.py`, or None when the server does not train.

    `APASSY_JOBS=0` turns jobs off. `APASSY_JOBS_DIR` (default: `jobs` next to the heads
    folder), `APASSY_JOB_DEADLINE` (seconds, at most 3 h), `APASSY_JOB_MEMORY_MB`
    (the memory cap of the trainer, default 4096; 0: no cap and no start rule).
    """
    environ = os.environ if environ is None else environ
    if (environ.get("APASSY_JOBS") or "").strip() == "0":
        return None
    script = os.path.join(os.path.dirname(HERE), "finetune", "local_train.py")
    if not os.path.isfile(script):
        return None
    shipped = os.path.join(HERE, "manifest.json")
    init = ""
    try:
        with open(shipped, encoding="utf-8") as f:
            if json.load(f)["checkpoint"]["sha256"] == cache.default_sha:
                init = os.path.abspath(checkpoint)
    except (OSError, ValueError, KeyError, TypeError):
        pass
    jobs_dir = environ.get("APASSY_JOBS_DIR") or os.path.join(os.path.dirname(os.path.abspath(heads_dir)), "jobs")
    trainer = LocalTrainer(
        script, init=init,
        deadline=env_int("APASSY_JOB_DEADLINE", MAX_DEADLINE, environ),
        memory_bytes=env_int("APASSY_JOB_MEMORY_MB", DEFAULT_MEMORY_BYTES // (1024 * 1024), environ) * 1024 * 1024)
    return JobManager(jobs_dir, cache.base, trainer, expected_shapes=cache.expected_shapes,
                      store_heads=own_server_store(cache), log=log)


def encode_manifest(manifest):
    """The `Apassy-Manifest` header value (tests and tools)."""
    return base64.urlsafe_b64encode(json.dumps(manifest).encode("utf-8")).rstrip(b"=").decode("ascii")
