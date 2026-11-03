"""Training jobs of the bouncer brain server (contract bouncer-brain-v2 section 4, unit I-srv).

A fake trainer, a fake clock and a fake memory reading: no torch, weights or network.
The route tests need fastapi and httpx (the CI Python job and the Laya venv have both)
and skip without them; the job manager tests need neither.
"""
import base64
import copy
import hashlib
import json
import logging
import os
import pathlib
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/basemodel"))
_WRITE_BYTECODE = sys.dont_write_bytecode
sys.dont_write_bytecode = True
import app as brain_app  # noqa: E402
import heads_cache  # noqa: E402
import jobs  # noqa: E402

sys.dont_write_bytecode = _WRITE_BYTECODE

try:
    from fastapi.testclient import TestClient
except ImportError:  # also when httpx is missing
    TestClient = None

FIXTURES = ROOT / "tests/fixtures/bouncer-brain-v2"


def fixture(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


JOB_MANIFEST = fixture("job-manifest.json")
BASE = dict(JOB_MANIFEST["base"])
SHAPES = {"head.w": [2, 2], "type_emb.weight": [3, 2], "scorer.b": [1]}
DEFAULT_SHA = "d" * 64
TOKEN = "s3cret-token"
NOW = 1790000000
SECRET = "SYNTHETIC-EXAMPLE-c4d1"
GiB = 1024 ** 3


def sha(data):
    return hashlib.sha256(data).hexdigest()


def head_file(seed, shapes=SHAPES):
    header, offset = {"__metadata__": {"seed": str(seed)}}, 0
    for name, shape in shapes.items():
        n = 4
        for dim in shape:
            n *= dim
        header[name] = {"dtype": "F32", "shape": shape, "data_offsets": [offset, offset + n]}
        offset += n
    raw = json.dumps(header).encode()
    raw += b" " * (-len(raw) % 8)
    return struct.pack("<Q", len(raw)) + raw + bytes(offset)


def examples(seed, count):
    rows = [json.dumps({"state": "User request: %s-%d-%d" % (SECRET, seed, i),
                        "question": "SYNTHETIC-QUESTION-%d" % i, "answer": "no"}) for i in range(count)]
    return ("\n".join(rows) + "\n").encode()


def make_job(seed=1, keep_heads=False, edit=None):
    """(body, manifest) of one upload: train.jsonl then val.jsonl, and the job manifest."""
    train, val = examples(seed, 5), examples(seed + 1000, 2)
    manifest = copy.deepcopy(JOB_MANIFEST)
    manifest["files"] = {"train": {"size_bytes": len(train), "sha256": sha(train)},
                         "val": {"size_bytes": len(val), "sha256": sha(val)}}
    manifest["keep_heads"] = keep_heads
    if edit is not None:
        edit(manifest)
    return train + val, manifest


def encode(manifest):
    return base64.urlsafe_b64encode(json.dumps(manifest).encode()).rstrip(b"=").decode()


class Clock:
    def __init__(self, now=NOW):
        self.now = float(now)

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class FakeProcess:
    def __init__(self, code=None):
        self.code = code
        self.stopped = False

    def poll(self):
        return self.code

    def wait(self, timeout):
        return self.code

    def stop(self):
        self.stopped = True
        if self.code is None:
            self.code = -signal.SIGTERM


class FakeTrainer:
    """Writes what `local_train.py` writes. `mode` picks the outcome of the next job."""

    available = True
    deadline = 600
    memory_bytes = 0

    def __init__(self):
        self.mode = "ok"
        self.starts = []
        self.processes = []

    def start(self, job_dir, data_dir, out_dir, name):
        seen = {n: (pathlib.Path(data_dir) / n).read_bytes() for n in sorted(os.listdir(data_dir))}
        root = os.path.dirname(os.path.dirname(job_dir))
        held = sorted(dirpath for dirpath, _dirs, _files in os.walk(root) if os.path.basename(dirpath) == "examples")
        self.starts.append({"job_dir": job_dir, "data_dir": data_dir, "out_dir": out_dir, "name": name,
                            "seen": seen, "examples_on_server": held})
        mode = self.mode
        if mode == "hold":
            process = FakeProcess()
        elif mode == "fail":
            process = FakeProcess(1)
        elif mode == "alarm":
            process = FakeProcess(-signal.SIGALRM)
        else:
            self.write_output(out_dir, name, mode)
            process = FakeProcess(0)
        self.processes.append(process)
        return process

    @staticmethod
    def write_output(out_dir, name, mode):
        body = b"not a safetensors file" if mode == "not_safetensors" else head_file(7)
        digest = sha(body)
        (pathlib.Path(out_dir) / jobs.CHECKPOINT).write_bytes(body)
        manifest = {
            "schema": 1,
            "name": name,
            "version": "%s+%s" % (name, digest[:8]),
            "checkpoint": {"file": jobs.CHECKPOINT, "sha256": digest, "size_bytes": len(body),
                           "format": "safetensors, float32 head tensors: head., type_emb., scorer."},
            "base": {"repo": "convaiinnovations/laya", "revision": BASE["revision"],
                     "weights_file": "model.safetensors", "weights_sha256": BASE["weights_sha256"],
                     "package": "laya[serve]==0.3.20"},
            "serve": {"zero_shot_questions": ["leak"]},
            "init": None,
            "training": {"method": "fake", "best_epoch": 2, "train_examples": 5, "val_examples": 2},
        }
        if mode == "bad_version":
            manifest["version"] = name + "+00000000"
        elif mode == "bad_base":
            manifest["base"]["weights_sha256"] = "e" * 64
        elif mode == "path":
            manifest["training"]["data"] = os.path.abspath(out_dir)
        elif mode == "bad_size":
            manifest["checkpoint"]["size_bytes"] = len(body) + 1
        (pathlib.Path(out_dir) / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        result = {"version": manifest["version"], "checkpoint": os.path.abspath(out_dir) + "/x",
                  "sha256": digest, "size_bytes": len(body), "train_seconds": 12.5, "total_seconds": 14.0,
                  "train_examples": 5, "val_examples": 2, "best_epoch": 2, "ac_power_at_start": True,
                  "init_sha256": None, "peak": float("nan"), "val_after": {"all_nll": 0.3, "note": "text"}}
        (pathlib.Path(out_dir) / "result.json").write_text(json.dumps(result), encoding="utf-8")


class Keep(logging.Handler):
    def __init__(self):
        super().__init__(logging.DEBUG)
        self.lines = []

    def emit(self, record):
        self.lines.append(record.getMessage())


def new_cache(heads_dir, max_stored=heads_cache.DEFAULT_STORED_LIMIT):
    default = heads_cache.HeadSet(DEFAULT_SHA, "apassy-base-v1+dddddddd", "tuned", {"leak"}, 1000, default=True)
    return heads_cache.HeadSetCache(default, heads_dir, BASE, lambda path: object(), limit=2,
                                    expected_shapes=SHAPES, max_stored=max_stored)


class Manager(unittest.TestCase):
    """The job manager without HTTP."""

    max_stored = heads_cache.DEFAULT_STORED_LIMIT

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.jobs_dir = os.path.join(self.tmp.name, "jobs")
        self.cache = new_cache(os.path.join(self.tmp.name, "heads"), self.max_stored)
        self.clock = Clock()
        self.memory = [None]
        self.trainer = FakeTrainer()
        self.manager = self.new_manager()

    def tearDown(self):
        self.tmp.cleanup()

    def new_manager(self, **options):
        options.setdefault("memory_needed", 0)
        return jobs.JobManager(self.jobs_dir, BASE, self.trainer, expected_shapes=SHAPES,
                               store_heads=jobs.own_server_store(self.cache), clock=self.clock,
                               memory_free=lambda: self.memory[0], **options)

    def submit(self, owner=jobs.OWN_SERVER, seed=1, keep_heads=False):
        body, manifest = make_job(seed, keep_heads)
        jobs.check_job_manifest(manifest, BASE)
        existing, upload = self.manager.begin(owner, sha(body), manifest)
        self.assertIsNone(existing)
        upload.write(body)
        created, view = self.manager.commit(upload)
        self.assertTrue(created)
        return sha(body), view

    def job_dir(self, job_id, owner=jobs.OWN_SERVER):
        return os.path.join(self.jobs_dir, jobs.owner_key(owner), job_id)

    def state(self, job_id, owner=jobs.OWN_SERVER):
        return self.manager.get(owner, job_id)

    def assert_no_examples(self, job_id, owner=jobs.OWN_SERVER):
        folder = self.job_dir(job_id, owner)
        self.assertFalse(os.path.exists(os.path.join(folder, "examples")))
        self.assertFalse(os.path.exists(os.path.join(folder, "out")))
        for dirpath, _dirs, files in os.walk(self.jobs_dir):
            for name in files:
                data = pathlib.Path(dirpath, name).read_bytes()
                self.assertNotIn(SECRET.encode(), data, os.path.join(dirpath, name))


class Lifecycle(Manager):
    def test_a_queued_job_holds_its_examples_in_a_private_folder(self):
        job_id, view = self.submit()
        self.assertEqual(view["state"], "queued")
        self.assertEqual(set(view), set(fixture("job-queued.json")))
        self.assertTrue(view["examples_held"])
        self.assertEqual(view["examples_deadline"], NOW + 86400)
        folder = self.job_dir(job_id)
        examples_dir = os.path.join(folder, "examples")
        self.assertEqual(sorted(os.listdir(examples_dir)), ["stats.json", "train.jsonl", "val.jsonl"])
        for path in (self.jobs_dir, os.path.dirname(folder), folder, examples_dir):
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o700, path)
        for name in os.listdir(examples_dir):
            self.assertEqual(stat.S_IMODE(os.stat(os.path.join(examples_dir, name)).st_mode), 0o600, name)
        self.assertEqual(json.load(open(os.path.join(examples_dir, "stats.json"))), JOB_MANIFEST["stats"])
        body, _manifest = make_job(1)
        self.assertEqual(pathlib.Path(examples_dir, "train.jsonl").read_bytes() +
                         pathlib.Path(examples_dir, "val.jsonl").read_bytes(), body)
        # No account id in a folder name.
        self.assertNotIn(jobs.OWN_SERVER, os.listdir(self.jobs_dir))

    def test_examples_are_absent_after_success(self):
        job_id, _ = self.submit()
        self.assertEqual(self.manager.run_once(), (jobs.owner_key(jobs.OWN_SERVER), job_id))
        view = self.state(job_id)
        self.assertEqual(view["state"], "done")
        self.assertEqual(set(view), set(fixture("job-done.json")))
        self.assertEqual(set(view["result"]), set(fixture("job-done.json")["result"]))
        self.assertFalse(view["examples_held"])
        self.assertEqual(view["examples_deleted_at"], NOW)
        self.assertEqual(view["result_deadline"], view["ended_at"] + 604800)
        self.assertIsNone(view["error"])
        self.assert_no_examples(job_id)
        self.assertEqual(sorted(os.listdir(self.job_dir(job_id))), ["result", "state.json"])
        self.assertEqual(sorted(os.listdir(os.path.join(self.job_dir(job_id), "result"))),
                         [jobs.CHECKPOINT, "manifest.json"])

    def test_the_result_passes_the_checks_and_carries_no_path_and_no_string_metric(self):
        job_id, _ = self.submit()
        self.manager.run_once()
        result = self.state(job_id)["result"]
        body = head_file(7)
        self.assertEqual(result["heads"], sha(body))
        self.assertEqual(result["model"], "apassy-remote-v1+" + sha(body)[:8])
        self.assertEqual(result["size_bytes"], len(body))
        self.assertIs(result["stored"], False)
        self.assertEqual(result["manifest"]["checkpoint"]["sha256"], result["heads"])
        self.assertEqual(result["manifest"]["version"], result["model"])
        self.assertEqual(result["manifest"]["base"]["revision"], BASE["revision"])
        self.assertEqual(result["metrics"], {"train_seconds": 12.5, "total_seconds": 14.0, "size_bytes": len(body),
                                             "train_examples": 5, "val_examples": 2, "best_epoch": 2,
                                             "val_after": {"all_nll": 0.3}})
        text = json.dumps(self.state(job_id))
        self.assertNotIn(self.tmp.name, text)
        self.assertNotIn(SECRET, text)
        self.assertLessEqual(len(jobs.compact(result["manifest"])), jobs.MAX_RESULT_MANIFEST_BYTES)

    def test_examples_are_absent_after_failure(self):
        for mode, error in [("fail", "training_failed"), ("alarm", "deadline"), ("bad_version", "bad_result"),
                            ("bad_base", "bad_result"), ("path", "bad_result"), ("bad_size", "bad_result"),
                            ("not_safetensors", "bad_result")]:
            with self.subTest(mode):
                self.trainer.mode = mode
                job_id, _ = self.submit(seed=len(self.trainer.starts) + 10)
                self.manager.run_once()
                view = self.state(job_id)
                self.assertEqual((view["state"], view["error"]), ("failed", error))
                self.assertEqual(set(view), set(fixture("job-failed.json")))
                self.assertIsNone(view["result"])
                self.assertIsNone(view["result_deadline"])
                self.assertEqual(view["examples_deleted_at"], view["ended_at"])
                self.assert_no_examples(job_id)
                self.assertEqual(os.listdir(self.job_dir(job_id)), ["state.json"])

    def test_examples_are_absent_after_a_stop(self):
        self.trainer.mode = "hold"
        job_id, _ = self.submit()
        self.manager.start_next()
        self.assertEqual(self.state(job_id)["state"], "running")
        self.manager.delete(jobs.OWN_SERVER, job_id)
        self.assertTrue(self.trainer.processes[0].stopped)
        self.manager.finish()
        view = self.state(job_id)
        self.assertEqual(view["state"], "deleted")
        self.assertEqual(set(view), set(fixture("job-deleted.json")))
        self.assertIsNone(view["result"])
        self.assert_no_examples(job_id)
        # Idempotent.
        self.manager.delete(jobs.OWN_SERVER, job_id)
        self.assertEqual(self.state(job_id)["state"], "deleted")

    def test_examples_are_absent_at_24_h_for_a_queued_job(self):
        self.memory[0] = 0
        self.manager.memory_needed = 5 * GiB
        job_id, _ = self.submit()
        self.clock.advance(86400 - 1)
        self.manager.sweep()
        self.assertTrue(self.state(job_id)["examples_held"])
        self.clock.advance(1)
        self.manager.sweep()
        view = self.state(job_id)
        self.assertEqual((view["state"], view["error"]), ("failed", "expired"))
        self.assertEqual(view["examples_deleted_at"], NOW + 86400)
        self.assert_no_examples(job_id)

    def test_examples_are_absent_at_24_h_for_a_running_job(self):
        self.trainer.mode = "hold"
        job_id, _ = self.submit()
        self.manager.start_next()
        self.clock.advance(86400)
        self.manager.sweep()
        self.assertTrue(self.trainer.processes[0].stopped)
        view = self.state(job_id)
        self.assertEqual((view["state"], view["error"]), ("failed", "deadline"))
        self.assert_no_examples(job_id)
        self.manager.finish()
        self.assertEqual(self.state(job_id)["error"], "deadline")

    def test_a_trainer_past_its_deadline_is_stopped(self):
        self.trainer.mode = "hold"
        job_id, _ = self.submit()
        self.manager.start_next()
        self.clock.advance(self.trainer.deadline + 31)
        self.manager.finish()
        self.assertTrue(self.trainer.processes[0].stopped)
        self.assertEqual((self.state(job_id)["state"], self.state(job_id)["error"]), ("failed", "deadline"))
        self.assert_no_examples(job_id)

    def test_a_restart_ends_a_running_job_as_interrupted_and_deletes_its_examples(self):
        self.trainer.mode = "hold"
        job_id, _ = self.submit()
        self.manager.start_next()
        queued_id, _ = self.submit(owner="another-owner", seed=2)
        # A leftover upload of a crash.
        leftover = os.path.join(self.jobs_dir, jobs.owner_key(jobs.OWN_SERVER), jobs.UPLOAD_PREFIX + "x")
        os.makedirs(os.path.join(leftover, "examples"))
        pathlib.Path(leftover, "examples", "train.jsonl").write_text(SECRET)
        self.clock.advance(5)
        restarted = self.new_manager()
        view = restarted.get(jobs.OWN_SERVER, job_id)
        self.assertEqual((view["state"], view["error"]), ("failed", "interrupted"))
        self.assertFalse(os.path.exists(leftover))
        self.assertFalse(os.path.exists(os.path.join(self.job_dir(job_id), "examples")))
        # A queued job of the other owner waits on, with its examples.
        self.assertEqual(restarted.get("another-owner", queued_id)["state"], "queued")
        self.assertTrue(os.path.isdir(os.path.join(self.job_dir(queued_id, "another-owner"), "examples")))

    def test_a_restart_after_24_h_deletes_every_example(self):
        job_id, _ = self.submit()
        self.clock.advance(86400 + 60)
        restarted = self.new_manager()
        self.assertEqual(restarted.get(jobs.OWN_SERVER, job_id)["error"], "expired")
        self.assert_no_examples(job_id)

    def test_the_close_at_a_server_stop_interrupts_the_running_job(self):
        self.trainer.mode = "hold"
        job_id, _ = self.submit()
        self.manager.start_next()
        self.manager.close()
        self.assertTrue(self.trainer.processes[0].stopped)
        self.assertEqual(self.state(job_id)["error"], "interrupted")
        self.assert_no_examples(job_id)
        self.manager.finish()
        self.assertIsNone(self.manager.start_next())

    def test_the_result_goes_at_7_days_and_the_state_7_days_later(self):
        job_id, _ = self.submit()
        self.manager.run_once()
        ended = self.state(job_id)["ended_at"]
        self.clock.advance(604800 - 1)
        self.manager.sweep()
        self.assertEqual(self.state(job_id)["state"], "done")
        self.clock.advance(1)
        self.manager.sweep()
        view = self.state(job_id)
        self.assertEqual(view["state"], "deleted")
        self.assertEqual(view["ended_at"], ended)
        self.assertFalse(os.path.exists(os.path.join(self.job_dir(job_id), "result")))
        self.clock.advance(604800)
        self.manager.sweep()
        with self.assertRaises(jobs.JobError) as caught:
            self.state(job_id)
        self.assertEqual((caught.exception.status, caught.exception.code), (404, "unknown_job"))
        self.assertEqual(os.listdir(self.jobs_dir), [])

    def test_a_failed_state_is_kept_7_days(self):
        self.trainer.mode = "fail"
        job_id, _ = self.submit()
        self.manager.run_once()
        self.clock.advance(604800 - 1)
        self.manager.sweep()
        self.assertEqual(self.state(job_id)["state"], "failed")
        self.clock.advance(1)
        self.manager.sweep()
        with self.assertRaises(jobs.JobError):
            self.state(job_id)

    def test_one_job_per_owner_and_one_per_server(self):
        self.trainer.mode = "hold"
        first, _ = self.submit(owner="owner-a", seed=1)
        body, manifest = make_job(2)
        with self.assertRaises(jobs.JobError) as caught:
            self.manager.begin("owner-a", sha(body), manifest)
        self.assertEqual((caught.exception.status, caught.exception.code), (409, "job_busy"))
        second, _ = self.submit(owner="owner-b", seed=3)
        self.assertEqual(self.manager.start_next()[1], first)
        self.assertIsNone(self.manager.start_next(), "one job per server at a time")
        self.assertEqual(self.manager.get("owner-b", second)["state"], "queued")
        self.manager.delete("owner-a", first)
        self.manager.finish()
        self.trainer.mode = "ok"
        self.assertEqual(self.manager.start_next()[1], second)

    def test_at_most_two_uploads_stage_at_a_time(self):
        uploads = []
        for seed in (1, 2):
            body, manifest = make_job(seed)
            _existing, upload = self.manager.begin("owner-%d" % seed, sha(body), manifest)
            uploads.append((upload, body))
        body, manifest = make_job(3)
        with self.assertRaises(jobs.JobError) as caught:
            self.manager.begin("owner-3", sha(body), manifest)
        self.assertEqual((caught.exception.status, caught.exception.code), (503, "busy"))
        # A discarded and a committed upload free their places.
        uploads[0][0].discard()
        _existing, third = self.manager.begin("owner-3", sha(body), manifest)
        upload, first_body = uploads[1]
        upload.write(first_body)
        self.assertTrue(self.manager.commit(upload)[0])
        fourth_body, fourth_manifest = make_job(4)
        _existing, fourth = self.manager.begin("owner-4", sha(fourth_body), fourth_manifest)
        for open_upload in (third, fourth):
            open_upload.discard()
        self.assertEqual(self.manager._staging, {})

    def test_an_upload_needs_disk_for_itself_and_the_uploads_that_stage(self):
        disk = [None]
        self.manager = self.new_manager(disk_free=lambda: disk[0], disk_headroom=100)
        body, manifest = make_job(1)
        size = len(body)
        disk[0] = size + 99
        with self.assertRaises(jobs.JobError) as caught:
            self.manager.begin("owner-a", sha(body), manifest)
        self.assertEqual((caught.exception.status, caught.exception.code), (503, "busy"))
        self.assertNotIn("owner", caught.exception.message)
        disk[0] = size + 100
        _existing, first = self.manager.begin("owner-a", sha(body), manifest)
        # The bytes of the upload that stages count: the same free disk is not enough twice.
        other_body, other_manifest = make_job(2)
        with self.assertRaises(jobs.JobError):
            self.manager.begin("owner-b", sha(other_body), other_manifest)
        disk[0] = size + len(other_body) + 99
        with self.assertRaises(jobs.JobError):
            self.manager.begin("owner-b", sha(other_body), other_manifest)
        disk[0] = size + len(other_body) + 100
        _existing, second = self.manager.begin("owner-b", sha(other_body), other_manifest)
        for upload in (first, second):
            upload.discard()
        # Unknown free disk does not block an upload.
        disk[0] = None
        _existing, upload = self.manager.begin("owner-a", sha(body), manifest)
        upload.discard()

    def test_a_job_cannot_read_another_jobs_folder(self):
        first, _ = self.submit(owner="owner-a", seed=1)
        second, _ = self.submit(owner="owner-b", seed=2)
        self.manager.run_once()
        self.manager.run_once()
        a, b = self.trainer.starts
        for start, job_id, owner, seed in ((a, first, "owner-a", 1), (b, second, "owner-b", 2)):
            folder = self.job_dir(job_id, owner)
            self.assertEqual(start["job_dir"], folder)
            self.assertEqual(start["data_dir"], os.path.join(folder, "examples"))
            self.assertEqual(start["out_dir"], os.path.join(folder, "out"))
            body, _ = make_job(seed)
            self.assertEqual(start["seen"]["train.jsonl"] + start["seen"]["val.jsonl"], body)
        paths = lambda start: json.dumps({k: start[k] for k in ("job_dir", "data_dir", "out_dir")})  # noqa: E731
        self.assertNotIn(self.job_dir(first, "owner-a"), paths(b))
        self.assertNotIn(self.job_dir(second, "owner-b"), paths(a))
        # When the second job starts, the examples of the first are already gone.
        self.assertEqual(b["examples_on_server"], [os.path.join(self.job_dir(second, "owner-b"), "examples")])
        trainer = jobs.LocalTrainer("/opt/apassy/tools/finetune/local_train.py")
        command = trainer.command("/jobs/k/b/examples", "/jobs/k/b/out", "apassy-remote-v1")
        self.assertEqual([part for part in command if part.startswith("/jobs/")],
                         ["/jobs/k/b/examples", "/jobs/k/b/out"])

    def test_a_job_starts_only_with_its_memory_limit_and_1_gib_free(self):
        self.manager.memory_needed = 4 * GiB + GiB
        job_id, _ = self.submit()
        self.memory[0] = 5 * GiB - 1
        self.assertIsNone(self.manager.start_next())
        self.assertEqual(self.state(job_id)["state"], "queued")
        self.memory[0] = 5 * GiB
        self.assertIsNotNone(self.manager.start_next())
        self.manager.finish()
        self.assertEqual(self.state(job_id)["state"], "done")

    def test_the_memory_rule_follows_the_trainer_cap(self):
        trainer = jobs.LocalTrainer("/x/local_train.py")
        self.assertEqual(trainer.memory_bytes, 4 * GiB)
        manager = jobs.JobManager(os.path.join(self.tmp.name, "other"), BASE, trainer, memory_free=lambda: None)
        self.assertEqual(manager.memory_needed, 5 * GiB)
        off = jobs.JobManager(os.path.join(self.tmp.name, "off"), BASE, jobs.LocalTrainer("/x", memory_bytes=0))
        self.assertEqual(off.memory_needed, 0)

    def test_the_memory_reading_takes_the_lower_of_cgroup_and_meminfo(self):
        cgroup = pathlib.Path(self.tmp.name, "cgroup")
        cgroup.mkdir()
        (cgroup / "memory.max").write_text("%d\n" % (4 * GiB))
        (cgroup / "memory.current").write_text("%d\n" % GiB)
        meminfo = pathlib.Path(self.tmp.name, "meminfo")
        meminfo.write_text("MemTotal: 16000000 kB\nMemAvailable: 8000000 kB\n")
        self.assertEqual(jobs.memory_free_bytes(str(cgroup), str(meminfo)), 3 * GiB)
        (cgroup / "memory.max").write_text("max\n")
        self.assertEqual(jobs.memory_free_bytes(str(cgroup), str(meminfo)), 8000000 * 1024)
        self.assertIsNone(jobs.memory_free_bytes(os.path.join(self.tmp.name, "none"),
                                                 os.path.join(self.tmp.name, "none")))

    def test_keep_heads_stores_the_result_as_a_head_set_of_the_owner(self):
        job_id, _ = self.submit(keep_heads=True)
        self.manager.run_once()
        result = self.state(job_id)["result"]
        self.assertIs(result["stored"], True)
        self.assertEqual(self.cache.info(result["heads"])["model"], result["model"])
        self.manager.delete(jobs.OWN_SERVER, job_id)
        # The stored head set is not the job result: it stays.
        self.assertEqual(self.cache.info(result["heads"])["heads"], result["heads"])
        self.assertFalse(os.path.exists(os.path.join(self.job_dir(job_id), "result")))

    def test_the_job_log_has_no_example_and_no_owner(self):
        keep = Keep()
        jobs.LOG.addHandler(keep)
        level = jobs.LOG.level
        jobs.LOG.setLevel(logging.DEBUG)
        try:
            job_id, _ = self.submit(owner="acc_7k2m5q4x3c")
            self.manager.run_once()
            self.trainer.mode = "fail"
            failed, _ = self.submit(owner="acc_7k2m5q4x3c", seed=5)
            self.manager.run_once()
            self.manager.delete("acc_7k2m5q4x3c", job_id)
            self.manager.delete_owner("acc_7k2m5q4x3c")
        finally:
            jobs.LOG.removeHandler(keep)
            jobs.LOG.setLevel(level)
        text = "\n".join(keep.lines)
        self.assertTrue(keep.lines)
        for needle in (SECRET, "SYNTHETIC-QUESTION", "acc_7k2m5q4x3c", jobs.owner_key("acc_7k2m5q4x3c"),
                       job_id, failed, self.tmp.name):
            self.assertNotIn(needle, text)
        self.assertIn(job_id[:8], text)


class FullHeads(Manager):
    max_stored = 1

    def test_keep_heads_with_a_full_heads_folder_is_not_stored(self):
        other = head_file(99)
        manifest = {"schema": 1, "name": "apassy-local-v1",
                    "checkpoint": {"file": "c", "sha256": sha(other), "size_bytes": len(other)},
                    "base": dict(BASE), "serve": {"zero_shot_questions": []}}
        out, path = self.cache.new_upload()
        with out:
            out.write(other)
        self.cache.store(sha(other), path, json.dumps(manifest).encode(), manifest)
        job_id, _ = self.submit(keep_heads=True)
        self.manager.run_once()
        view = self.state(job_id)
        self.assertEqual(view["state"], "done")
        self.assertIs(view["result"]["stored"], False)
        self.assertEqual(self.cache.stored_count(), 1)


class Trainer(unittest.TestCase):
    """The subprocess of `local_train.py`."""

    def test_the_command_runs_local_train_at_low_priority_with_a_memory_cap(self):
        trainer = jobs.LocalTrainer("/opt/t/local_train.py", init="/opt/m/base.safetensors", python="/py",
                                    deadline=99999)
        self.assertEqual(trainer.deadline, 10800, "at most 3 h (plan 0035 K1)")
        command = trainer.command("/j/examples", "/j/out", "apassy-remote-v1")
        self.assertEqual(command[:5], ["/py", "-I", "-B", "-c", jobs.LAUNCHER])
        self.assertEqual(command[5:7], ["10", str(4 * GiB)])
        self.assertEqual(command[7:], ["/py", "-B", "/opt/t/local_train.py", "--data", "/j/examples",
                                       "--out", "/j/out", "--name", "apassy-remote-v1", "--deadline", "10800",
                                       "--init", "/opt/m/base.safetensors"])
        self.assertNotIn("--init", jobs.LocalTrainer("/t.py").command("/d", "/o", "n"))

    def test_the_trainer_gets_no_token_and_no_output_channel(self):
        trainer = jobs.LocalTrainer("/opt/t/local_train.py", python="/py")
        environ = {"LAYA_API_KEY": TOKEN, "LAYA_API_KEY_FILE": "/run/secrets/key",
                   "APASSY_BRAIN_SERVICE_TOKEN": "x", "HF_HOME": "/opt/hf"}
        with mock.patch.dict(os.environ, environ), mock.patch.object(jobs.subprocess, "Popen") as popen:
            trainer.start("/j", "/j/examples", "/j/out", "apassy-remote-v1")
        kwargs = popen.call_args.kwargs
        self.assertEqual(kwargs["cwd"], "/j")
        for channel in ("stdin", "stdout", "stderr"):
            self.assertEqual(kwargs[channel], subprocess.DEVNULL, channel)
        self.assertTrue(kwargs["start_new_session"])
        self.assertNotIn("preexec_fn", kwargs)
        for name in ("LAYA_API_KEY", "LAYA_API_KEY_FILE", "APASSY_BRAIN_SERVICE_TOKEN"):
            self.assertNotIn(name, kwargs["env"])
        self.assertEqual(kwargs["env"]["HF_HOME"], "/opt/hf")

    @unittest.skipUnless(sys.platform.startswith("linux"), "RLIMIT_DATA is enforced on Linux")
    def test_the_launcher_lowers_the_priority_and_sets_the_cap(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = os.path.join(tmp, "probe.py")
            pathlib.Path(script).write_text(textwrap.dedent("""
                import json, os, resource, sys
                out = sys.argv[sys.argv.index("--out") + 1]
                json.dump({"nice": os.getpriority(os.PRIO_PROCESS, 0),
                           "data": resource.getrlimit(resource.RLIMIT_DATA)[0]},
                          open(os.path.join(out, "probe.json"), "w"))
            """))
            out = os.path.join(tmp, "out")
            os.makedirs(out)
            trainer = jobs.LocalTrainer(script, memory_bytes=3 * GiB)
            process = trainer.start(tmp, tmp, out, "probe")
            self.assertEqual(process.wait(60), 0)
            probe = json.load(open(os.path.join(out, "probe.json")))
        self.assertGreaterEqual(probe["nice"], 10)
        self.assertEqual(probe["data"], 3 * GiB)

    def test_from_env_turns_jobs_off_or_on(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = new_cache(os.path.join(tmp, "heads"))
            self.assertIsNone(jobs.from_env(cache, "/m.safetensors", cache.heads_dir, environ={"APASSY_JOBS": "0"}))
            manager = jobs.from_env(cache, "/m.safetensors", cache.heads_dir,
                                    environ={"APASSY_JOB_DEADLINE": "7200", "APASSY_JOB_MEMORY_MB": "3072"})
            self.assertIsNotNone(manager, "tools/finetune/local_train.py is in the repository")
            self.assertEqual(manager.jobs_dir, os.path.join(tmp, "jobs"))
            self.assertEqual(manager.trainer.deadline, 7200)
            self.assertEqual(manager.trainer.memory_bytes, 3072 * 1024 * 1024)
            self.assertEqual(manager.memory_needed, 4 * GiB)
            # Not the shipped base checkpoint: the trainer starts from the stock heads.
            self.assertEqual(manager.trainer.init, "")
            with self.assertRaises(SystemExit):
                jobs.from_env(cache, "/m", cache.heads_dir, environ={"APASSY_JOB_MEMORY_MB": "-1"})


class ImportsWithoutTorch(unittest.TestCase):
    def test_jobs_and_app_import_without_torch_or_fastapi(self):
        code = ("import sys; sys.path.insert(0, %r); import jobs, app, heads_cache; "
                "bad = [m for m in ('torch', 'fastapi', 'numpy', 'safetensors') if m in sys.modules]; "
                "sys.exit('imported: %%s' %% bad if bad else 0)" % str(ROOT / "tools/basemodel"))
        done = subprocess.run([sys.executable, "-I", "-B", "-c", code], capture_output=True, text=True, timeout=60)
        self.assertEqual(done.returncode, 0, done.stderr + done.stdout)


class FakeRouter:
    loaded = ["english"]

    def predict(self, state, questions, heads=None, shadow_heads=None):
        raise AssertionError("no inference in the job tests")


@unittest.skipIf(TestClient is None, "requires fastapi and httpx")
class Routes(Manager):
    api_key = TOKEN
    max_upload = 64 * 1024

    def setUp(self):
        super().setUp()
        self.manager.max_upload = self.max_upload
        app = brain_app.create_app(FakeRouter(), self.cache, api_key=self.api_key, jobs=self.manager)
        self.client = TestClient(app)
        self.client.__enter__()

    def tearDown(self):
        self.client.__exit__(None, None, None)
        super().tearDown()

    def auth(self, extra=None):
        headers = {"Authorization": "Bearer " + TOKEN} if self.api_key else {}
        headers.update(extra or {})
        return headers

    def put(self, body, manifest, path=None, headers=None):
        extra = {"Apassy-Manifest": encode(manifest)}
        extra.update(headers or {})
        return self.client.put("/v1/train/" + (path or sha(body)), content=body, headers=self.auth(extra))

    def assert_code(self, response, status, code):
        self.assertEqual(response.status_code, status, response.text)
        self.assertEqual(response.json()["detail"]["code"], code)

    def assert_nothing_stored(self):
        for dirpath, _dirs, files in os.walk(self.jobs_dir):
            self.assertEqual(files, [], dirpath)


class Upload(Routes):
    def test_a_new_job_is_201_queued_and_again_200(self):
        body, manifest = make_job()
        first = self.put(body, manifest)
        self.assertEqual(first.status_code, 201, first.text)
        self.assertEqual(first.json()["job"], sha(body))
        self.assertEqual(first.json()["state"], "queued")
        expected = fixture("job-queued.json")
        expected.update({"job": sha(body), "created_at": NOW, "examples_deadline": NOW + 86400})
        self.assertEqual(first.json(), expected)
        again = self.put(body, manifest)
        self.assertEqual(again.status_code, 200)
        self.assertEqual(again.json(), first.json())
        self.assertEqual(self.client.get("/v1/train/" + sha(body), headers=self.auth()).json(), first.json())

    def test_a_failed_job_is_200_unchanged_and_a_deleted_job_is_replaced(self):
        self.trainer.mode = "fail"
        body, manifest = make_job()
        self.put(body, manifest)
        self.manager.run_once()
        again = self.put(body, manifest)
        self.assertEqual(again.status_code, 200)
        self.assertEqual((again.json()["state"], again.json()["error"]), ("failed", "training_failed"))
        self.assertEqual(self.client.delete("/v1/train/" + sha(body), headers=self.auth()).status_code, 204)
        self.clock.advance(10)
        replaced = self.put(body, manifest)
        self.assertEqual(replaced.status_code, 201)
        self.assertEqual(replaced.json()["state"], "queued")
        self.assertEqual(replaced.json()["created_at"], NOW + 10)

    def test_each_failed_check_is_400_bad_job_and_stores_nothing(self):
        body, manifest = make_job()

        def edited(change):
            m = copy.deepcopy(manifest)
            change(m)
            return m

        cases = {
            "body hash is not the path": (body, manifest, "e" * 64),
            "train hash": (body, edited(lambda m: m["files"]["train"].update(sha256="f" * 64)), None),
            "val hash": (body, edited(lambda m: m["files"]["val"].update(sha256="f" * 64)), None),
            "split moved": (body, edited(lambda m: (m["files"]["train"].update(size_bytes=m["files"]["train"]["size_bytes"] + 1),
                                                    m["files"]["val"].update(size_bytes=m["files"]["val"]["size_bytes"] - 1))), None),
            "sizes do not sum": (body, edited(lambda m: m["files"]["val"].update(size_bytes=1)), None),
            "base revision": (body, edited(lambda m: m["base"].update(revision="0" * 40)), None),
            "base weights": (body, edited(lambda m: m["base"].update(weights_sha256="0" * 64)), None),
            "name": (body, edited(lambda m: m.update(name="bad name!")), None),
            "decisions under the gate": (body, edited(lambda m: m["stats"].update(owner_decisions=299)), None),
            "denials under the gate": (body, edited(lambda m: m["stats"].update(owner_denials=29)), None),
            "no train examples": (body, edited(lambda m: m["stats"].update(train=0)), None),
            "no val examples": (body, edited(lambda m: m["stats"].update(val=0)), None),
            "stats without val": (body, edited(lambda m: m["stats"].pop("val")), None),
            "a negative count": (body, edited(lambda m: m["stats"].update(conflicts=-1)), None),
            "a text in stats": (body, edited(lambda m: m["stats"].update(note="SYNTHETIC")), None),
            "a head set manifest": (body, edited(lambda m: m.update(kind="apassy-heads-v1")), None),
            "schema 2": (body, edited(lambda m: m.update(schema=2)), None),
            "no keep_heads": (body, edited(lambda m: m.pop("keep_heads")), None),
            "keep_heads text": (body, edited(lambda m: m.update(keep_heads="yes")), None),
            "no files": (body, edited(lambda m: m.pop("files")), None),
        }
        for label, (content, m, path) in cases.items():
            with self.subTest(label):
                self.assert_code(self.put(content, m, path=path), 400, "bad_job")
        headers = [{"Apassy-Manifest": "not base64!"},
                   {"Apassy-Manifest": base64.urlsafe_b64encode(b"[1, 2]").rstrip(b"=").decode()},
                   {"Apassy-Manifest": base64.urlsafe_b64encode(b"{not json").rstrip(b"=").decode()}]
        for extra in headers:
            with self.subTest(extra["Apassy-Manifest"]):
                response = self.client.put("/v1/train/" + sha(body), content=body, headers=self.auth(extra))
                self.assert_code(response, 400, "bad_job")
        self.assert_code(self.client.put("/v1/train/" + sha(body), content=body, headers=self.auth()), 400, "bad_job")
        self.assert_nothing_stored()
        self.assert_code(self.client.get("/v1/train/" + sha(body), headers=self.auth()), 404, "unknown_job")

    def test_a_message_has_no_request_data(self):
        body, manifest = make_job()
        bad = copy.deepcopy(manifest)
        bad["base"]["revision"] = "0" * 40
        for response in (self.put(body, bad), self.put(body, manifest, path="e" * 64)):
            text = response.text
            for needle in (sha(body), "e" * 64, "0" * 40, SECRET):
                self.assertNotIn(needle, text)

    def test_too_large_is_413_and_stores_nothing(self):
        body, manifest = make_job()
        big = copy.deepcopy(manifest)
        big["pad"] = "x" * (17 * 1024)
        self.assert_code(self.put(body, big), 413, "too_large")
        large = b"x" * (self.max_upload + 1)
        large_manifest = copy.deepcopy(manifest)
        large_manifest["files"] = {"train": {"size_bytes": len(large) - 10, "sha256": sha(large[:-10])},
                                   "val": {"size_bytes": 10, "sha256": sha(large[-10:])}}
        self.assert_code(self.put(large, large_manifest), 413, "too_large")
        self.assert_nothing_stored()

    def test_a_malformed_path_is_422_bad_job(self):
        body, manifest = make_job()
        for path in ("ABC", "A" * 64, "a" * 63, "g" * 64):
            with self.subTest(path):
                self.assert_code(self.put(body, manifest, path=path), 422, "bad_job")
                self.assert_code(self.client.get("/v1/train/" + path, headers=self.auth()), 422, "bad_job")
                self.assert_code(self.client.get("/v1/train/%s/result" % path, headers=self.auth()), 422, "bad_job")
                self.assert_code(self.client.delete("/v1/train/" + path, headers=self.auth()), 422, "bad_job")
        self.assert_nothing_stored()

    def test_a_second_job_of_the_owner_is_409_job_busy(self):
        first, first_manifest = make_job(1)
        second, second_manifest = make_job(2)
        self.assertEqual(self.put(first, first_manifest).status_code, 201)
        busy = self.put(second, second_manifest)
        self.assertEqual(busy.status_code, 409)
        self.assertEqual(busy.json(), fixture("error-job-busy.json"))
        self.assertEqual(os.listdir(os.path.join(self.jobs_dir, jobs.owner_key(jobs.OWN_SERVER))), [sha(first)])
        self.manager.run_once()
        self.assertEqual(self.put(second, second_manifest).status_code, 201, "a done job does not block")


class States(Routes):
    def test_the_states_follow_the_fixtures(self):
        self.trainer.mode = "hold"
        body, manifest = make_job()
        job_id = sha(body)
        self.put(body, manifest)
        self.clock.advance(4)
        self.manager.start_next()
        running = self.client.get("/v1/train/" + job_id, headers=self.auth()).json()
        expected = fixture("job-running.json")
        expected.update({"job": job_id, "created_at": NOW, "started_at": NOW + 4, "examples_deadline": NOW + 86400})
        self.assertEqual(running, expected)
        self.assert_code(self.client.get("/v1/train/%s/result" % job_id, headers=self.auth()), 409, "job_not_done")
        self.clock.advance(408)
        self.trainer.processes[0].code = 0
        FakeTrainer.write_output(self.trainer.starts[0]["out_dir"], "apassy-remote-v1", "ok")
        self.manager.finish()
        done = self.client.get("/v1/train/" + job_id, headers=self.auth()).json()
        template = fixture("job-done.json")
        self.assertEqual({k: v for k, v in done.items() if k != "result"},
                         {**{k: v for k, v in template.items() if k != "result"},
                          "job": job_id, "created_at": NOW, "started_at": NOW + 4, "ended_at": NOW + 412,
                          "examples_deleted_at": NOW + 412, "examples_deadline": NOW + 86400,
                          "result_deadline": NOW + 412 + 604800})
        self.assertEqual(set(done["result"]), set(template["result"]))

    def test_the_result_download_is_the_head_file_and_a_delete_removes_it(self):
        body, manifest = make_job()
        job_id = sha(body)
        self.put(body, manifest)
        self.manager.run_once()
        result = self.client.get("/v1/train/" + job_id, headers=self.auth()).json()["result"]
        download = self.client.get("/v1/train/%s/result" % job_id, headers=self.auth())
        self.assertEqual(download.status_code, 200)
        self.assertEqual(download.headers["content-type"], "application/octet-stream")
        self.assertEqual(int(download.headers["content-length"]), result["size_bytes"])
        self.assertEqual(sha(download.content), result["heads"])
        self.assertEqual(download.content, head_file(7))
        self.assertEqual(self.client.delete("/v1/train/" + job_id, headers=self.auth()).status_code, 204)
        deleted = self.client.get("/v1/train/" + job_id, headers=self.auth()).json()
        self.assertEqual(deleted["state"], "deleted")
        self.assertEqual(set(deleted), set(fixture("job-deleted.json")))
        self.assertIsNone(deleted["result"])
        self.assertIsNone(deleted["result_deadline"])
        self.assertEqual(os.listdir(os.path.join(self.jobs_dir, jobs.owner_key(jobs.OWN_SERVER), job_id)),
                         ["state.json"])
        self.assert_code(self.client.get("/v1/train/%s/result" % job_id, headers=self.auth()), 409, "job_not_done")
        self.assertEqual(self.client.delete("/v1/train/" + job_id, headers=self.auth()).status_code, 204)

    def test_an_unknown_job_is_404_unknown_job(self):
        for method, path in [("GET", "/v1/train/" + "e" * 64), ("GET", "/v1/train/%s/result" % ("e" * 64)),
                             ("DELETE", "/v1/train/" + "e" * 64)]:
            with self.subTest(method + " " + path):
                response = self.client.request(method, path, headers=self.auth())
                self.assertEqual(response.status_code, 404)
                self.assertEqual(response.json(), fixture("error-unknown-job.json"))

    def test_health_says_v2_with_jobs(self):
        health = self.client.get("/health").json()
        self.assertEqual(set(health), set(fixture("health.json")))
        self.assertEqual((health["contract"], health["jobs"], health["sign_in"]), ("bouncer-brain-v2", True, False))

    def test_delete_owner_removes_jobs_examples_and_head_sets_with_counts(self):
        stored = head_file(99)
        manifest = {"schema": 1, "name": "apassy-local-v1",
                    "checkpoint": {"file": "c", "sha256": sha(stored), "size_bytes": len(stored)},
                    "base": dict(BASE), "serve": {"zero_shot_questions": []}}
        out, path = self.cache.new_upload()
        with out:
            out.write(stored)
        self.cache.store(sha(stored), path, json.dumps(manifest).encode(), manifest)
        done, done_manifest = make_job(1)
        self.put(done, done_manifest)
        self.manager.run_once()
        queued, queued_manifest = make_job(2)
        self.put(queued, queued_manifest)
        response = self.client.delete("/v1/owner", headers=self.auth())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"deleted": {"heads": 1, "jobs": 2, "examples": 1}})
        self.assertEqual(set(response.json()["deleted"]), set(fixture("owner-deleted.json")["deleted"]))
        self.assertEqual(os.listdir(self.jobs_dir), [])
        for job_id in (sha(done), sha(queued)):
            self.assert_code(self.client.get("/v1/train/" + job_id, headers=self.auth()), 404, "unknown_job")
        again = self.client.delete("/v1/owner", headers=self.auth())
        self.assertEqual(again.json(), {"deleted": {"heads": 0, "jobs": 0, "examples": 0}})

    def test_delete_owner_stops_a_running_job(self):
        self.trainer.mode = "hold"
        body, manifest = make_job()
        self.put(body, manifest)
        self.manager.start_next()
        response = self.client.delete("/v1/owner", headers=self.auth())
        self.assertEqual(response.json()["deleted"], {"heads": 0, "jobs": 1, "examples": 1})
        self.assertTrue(self.trainer.processes[0].stopped)
        self.manager.finish()
        self.assertEqual(os.listdir(self.jobs_dir), [])

    def test_no_log_line_has_example_text(self):
        keep = Keep()
        brain_app.LOG.addHandler(keep)
        level = brain_app.LOG.level
        brain_app.LOG.setLevel(logging.DEBUG)
        try:
            body, manifest = make_job()
            job_id = sha(body)
            self.put(body, manifest)
            self.put(body, manifest)
            bad = copy.deepcopy(manifest)
            bad["stats"]["owner_denials"] = 1
            self.put(make_job(3)[0], bad)
            self.manager.run_once()
            self.client.get("/v1/train/" + job_id, headers=self.auth())
            self.client.get("/v1/train/%s/result" % job_id, headers=self.auth())
            self.client.delete("/v1/train/" + job_id, headers=self.auth())
            self.client.delete("/v1/owner", headers=self.auth())
        finally:
            brain_app.LOG.removeHandler(keep)
            brain_app.LOG.setLevel(level)
        text = "\n".join(keep.lines)
        self.assertIn("train put status=201", text)
        for needle in (SECRET, "SYNTHETIC-QUESTION", job_id, TOKEN, self.tmp.name):
            self.assertNotIn(needle, text)


class Auth(Routes):
    def test_every_job_route_needs_the_token(self):
        body, manifest = make_job()
        calls = [("PUT", "/v1/train/" + sha(body), {"content": body, "headers": {"Apassy-Manifest": encode(manifest)}}),
                 ("GET", "/v1/train/" + sha(body), {}),
                 ("GET", "/v1/train/%s/result" % sha(body), {}),
                 ("DELETE", "/v1/train/" + sha(body), {})]
        for wrong in [None, "Bearer wrong", TOKEN, "Bearer " + TOKEN + "x"]:
            for method, path, kwargs in calls:
                with self.subTest(method=method, path=path, auth=wrong):
                    kwargs = dict(kwargs)
                    headers = dict(kwargs.pop("headers", {}))
                    if wrong is not None:
                        headers["Authorization"] = wrong
                    response = self.client.request(method, path, headers=headers, **kwargs)
                    self.assertEqual(response.status_code, 401, response.text)
        self.assert_nothing_stored()


class NoToken(Routes):
    """An own server without `LAYA_API_KEY`: every job route is 403 `no_token`."""

    api_key = None

    def test_every_job_route_is_403_no_token_and_stores_nothing(self):
        body, manifest = make_job()
        for response in [self.put(body, manifest),
                         self.client.get("/v1/train/" + sha(body)),
                         self.client.get("/v1/train/%s/result" % sha(body)),
                         self.client.delete("/v1/train/" + sha(body)),
                         self.client.delete("/v1/train/" + "A" * 64),
                         self.client.delete("/v1/owner")]:
            with self.subTest(response.request.method + " " + response.request.url.path):
                self.assert_code(response, 403, "no_token")
        self.assert_nothing_stored()
        self.assertIs(self.client.get("/health").json()["jobs"], True)


@unittest.skipIf(TestClient is None, "requires fastapi and httpx")
class NoTrainer(unittest.TestCase):
    def test_a_server_that_cannot_train_says_so_and_has_no_job_routes(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = new_cache(os.path.join(tmp, "heads"))
            manager = jobs.JobManager(os.path.join(tmp, "jobs"), BASE,
                                      jobs.LocalTrainer(os.path.join(tmp, "missing.py")), memory_free=lambda: None)
            with TestClient(brain_app.create_app(FakeRouter(), cache, api_key=TOKEN, jobs=manager)) as client:
                self.assertIs(client.get("/health").json()["jobs"], False)
                body, manifest = make_job()
                response = client.put("/v1/train/" + sha(body), content=body,
                                      headers={"Authorization": "Bearer " + TOKEN, "Apassy-Manifest": encode(manifest)})
                self.assertEqual(response.status_code, 404)
                self.assertEqual(client.get("/v1/train/" + sha(body),
                                            headers={"Authorization": "Bearer " + TOKEN}).status_code, 404)


if __name__ == "__main__":
    unittest.main()
