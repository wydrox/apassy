"""No torch, model weights or network: the head-set cache with fake head modules."""
import base64
import hashlib
import json
import math
import os
import pathlib
import stat
import struct
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/basemodel"))
_WRITE_BYTECODE = sys.dont_write_bytecode
sys.dont_write_bytecode = True
import heads_cache  # noqa: E402

sys.dont_write_bytecode = _WRITE_BYTECODE

BASE = {"revision": "55cf4c4ebb4ebe31b2550e8bdf3bd21b99753851", "weights_sha256": "b" * 64}
SHAPES = {"head.w": [2, 2], "type_emb.weight": [3, 2], "scorer.b": [1]}
DEFAULT_SHA = "d" * 64


def head_file(seed, shapes=SHAPES, tweak=None, extra=b""):
    """A small safetensors file with the given tensors; `seed` makes the hash differ.

    `tweak(header)` changes the header before it is written; `extra` follows the data.
    """
    header, offset = {"__metadata__": {"seed": str(seed)}}, 0
    for name, shape in shapes.items():
        n = 4
        for dim in shape:
            n *= dim
        header[name] = {"dtype": "F32", "shape": shape, "data_offsets": [offset, offset + n]}
        offset += n
    if tweak is not None:
        tweak(header)
    raw = json.dumps(header).encode()
    raw += b" " * (-len(raw) % 8)
    return struct.pack("<Q", len(raw)) + raw + bytes(offset) + extra


HEX_RUN = "[0-9a-f]{8,}"


def manifest_for(body, name="apassy-local-v1", zero_shot=("leak",)):
    return {
        "schema": 1,
        "name": name,
        "checkpoint": {"file": "candidate.safetensors", "sha256": hashlib.sha256(body).hexdigest(),
                       "size_bytes": len(body)},
        "base": {"repo": "convaiinnovations/laya", **BASE},
        "serve": {"zero_shot_questions": list(zero_shot)},
    }


class FakeLoader:
    def __init__(self):
        self.calls = []
        self.fail = {}

    def __call__(self, path):
        name = os.path.basename(path)
        self.calls.append(name)
        if name in self.fail:
            raise self.fail[name]
        return {"module": name}


def default_set():
    return heads_cache.HeadSet(DEFAULT_SHA, "apassy-base-v1+dddddddd", "tuned", {"leak"}, 1000, default=True)


class CacheCase(unittest.TestCase):
    max_stored = heads_cache.DEFAULT_STORED_LIMIT

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = os.path.join(self.tmp.name, "heads")
        self.loader = FakeLoader()
        self.cache = heads_cache.HeadSetCache(default_set(), self.dir, BASE, self.loader, limit=2,
                                              expected_shapes=SHAPES, max_stored=self.max_stored)

    def tearDown(self):
        self.tmp.cleanup()

    def put(self, seed, name="apassy-local-v1"):
        body = head_file(seed)
        manifest = manifest_for(body, name)
        out, path = self.cache.new_upload()
        with out:
            out.write(body)
        created, model = self.cache.store(manifest["checkpoint"]["sha256"], path,
                                          json.dumps(manifest).encode(), manifest)
        self.assertTrue(created)
        return manifest["checkpoint"]["sha256"]


class HashValidation(unittest.TestCase):
    def test_messages_have_no_request_data(self):
        for status in (404, 409):
            error = heads_cache.UnknownHeads("e" * 64, status=status)
            self.assertEqual(error.detail(), {"code": "unknown_heads",
                                              "message": "the head set is not on this server"})
        with self.assertRaises(heads_cache.HeadsError) as caught:
            heads_cache.check_hash("f" * 63)
        self.assertNotRegex(caught.exception.message, HEX_RUN)

    def test_a_deep_manifest_header_is_bad_heads(self):
        value = base64.urlsafe_b64encode(b"[" * 10000).rstrip(b"=").decode()
        self.assertLessEqual(len(value), heads_cache.MAX_MANIFEST_HEADER_BYTES)
        with self.assertRaises(heads_cache.HeadsError) as caught:
            heads_cache.decode_manifest_header(value)
        self.assertEqual((caught.exception.status, caught.exception.code), (400, "bad_heads"))

    def test_a_valid_hash_passes(self):
        self.assertEqual(heads_cache.check_hash("0123456789abcdef" * 4), "0123456789abcdef" * 4)

    def test_malformed_hashes_are_bad_heads(self):
        for value in ["A" * 64, "a" * 63, "a" * 65, "g" * 64, " " + "a" * 63, 7, None, ["a" * 64],
                      "a" * 64 + "\n"]:
            with self.assertRaises(heads_cache.HeadsError) as caught:
                heads_cache.check_hash(value)
            self.assertEqual((caught.exception.status, caught.exception.code), (422, "bad_heads"))

    def test_the_version_name_fits_64_bytes(self):
        body = head_file(1)
        sha = hashlib.sha256(body).hexdigest()
        heads_cache.check_manifest(manifest_for(body, "a" * 55), sha, BASE)
        self.assertEqual(len(heads_cache.model_name("a" * 55, sha)), 64)
        for name in ["a" * 56, "", "-x", "a b", "a/b", 5]:
            with self.assertRaises(heads_cache.HeadsError):
                heads_cache.check_manifest(manifest_for(body, name), sha, BASE)


class Answer(CacheCase):
    def infer(self, calls, shadow_answers=None):
        def run(active, shadow):
            calls.append((active.sha, None if shadow is None else shadow.sha))
            result = {"model": "laya-rl-agent", "answers": {"leak": {"type": "noul", "noul": 0.25}},
                      "usage": {"input_tokens": 3, "output_tokens": 0}, "routing": {"model": "english"}}
            if shadow is None:
                return result, None
            return result, shadow_answers if shadow_answers is not None else {"leak": {"noul": 0.75}}
        return run

    def test_without_heads_the_default_answers(self):
        calls = []
        result = heads_cache.answer(self.cache, self.infer(calls))
        self.assertEqual(calls, [(DEFAULT_SHA, None)])
        self.assertEqual(result["heads"], DEFAULT_SHA)
        self.assertEqual(result["model"], "apassy-base-v1+dddddddd")
        self.assertNotIn("shadow", result)
        self.assertEqual(self.loader.calls, [])

    def test_an_unknown_active_hash_is_409_and_runs_nothing(self):
        calls = []
        with self.assertRaises(heads_cache.HeadsError) as caught:
            heads_cache.answer(self.cache, self.infer(calls), heads="e" * 64)
        self.assertEqual((caught.exception.status, caught.exception.code), (409, "unknown_heads"))
        self.assertEqual(calls, [])

    def test_a_malformed_hash_is_422(self):
        for fields in [{"heads": "E" * 64}, {"shadow_heads": "xyz"}]:
            with self.assertRaises(heads_cache.HeadsError) as caught:
                heads_cache.answer(self.cache, self.infer([]), **fields)
            self.assertEqual((caught.exception.status, caught.exception.code), (422, "bad_heads"))

    def test_an_unknown_shadow_hash_is_a_shadow_error_and_the_active_answer_stays(self):
        calls = []
        result = heads_cache.answer(self.cache, self.infer(calls), shadow_heads="e" * 64)
        self.assertEqual(calls, [(DEFAULT_SHA, None)])
        self.assertEqual(result["shadow"], {"heads": "e" * 64, "error": "unknown_heads"})
        self.assertEqual(result["answers"], {"leak": {"type": "noul", "noul": 0.25}})
        self.assertEqual(result["heads"], DEFAULT_SHA)

    def test_a_failed_shadow_pass_never_fails_the_request(self):
        sha = self.put(1)
        result = heads_cache.answer(self.cache, self.infer([], RuntimeError("MPS out of memory")),
                                    shadow_heads=sha)
        self.assertEqual(result["shadow"], {"heads": sha, "error": "shadow_failed"})
        self.assertEqual(result["answers"]["leak"]["noul"], 0.25)

    def test_active_and_shadow_head_sets_answer_one_request(self):
        active, shadow = self.put(1), self.put(2, name="apassy-local-v2")
        calls = []
        result = heads_cache.answer(self.cache, self.infer(calls), heads=active, shadow_heads=shadow)
        self.assertEqual(calls, [(active, shadow)])
        self.assertEqual(result["heads"], active)
        self.assertEqual(result["model"], "apassy-local-v1+" + active[:8])
        self.assertEqual(result["shadow"], {"heads": shadow, "model": "apassy-local-v2+" + shadow[:8],
                                            "answers": {"leak": {"noul": 0.75}}})

    def test_a_non_finite_shadow_is_shadow_failed_and_the_active_answer_stays(self):
        sha = self.put(1)
        for bad in [{"leak": {"noul": math.nan}}, {"leak": {"noul": 0.5, "p": [0.1, math.inf]}},
                    {"leak": {"action": {"act_probability": -math.inf}}}]:
            with self.subTest(bad):
                result = heads_cache.answer(self.cache, self.infer([], bad), shadow_heads=sha)
                self.assertEqual(result["shadow"], {"heads": sha, "error": "shadow_failed"})
                self.assertEqual(result["answers"], {"leak": {"type": "noul", "noul": 0.25}})
                self.assertEqual(result["heads"], DEFAULT_SHA)

    def test_a_non_finite_active_answer_raises_without_request_data(self):
        def run(active, shadow):
            return {"answers": {"leak": {"type": "noul", "noul": math.nan}}}, None
        with self.assertRaises(heads_cache.NonFiniteAnswer) as caught:
            heads_cache.answer(self.cache, run)
        self.assertNotIsInstance(caught.exception, ValueError, "a ValueError would be a 422 with its text")
        self.assertNotIn("leak", str(caught.exception))

    def test_an_answer_over_the_size_cap_drops_the_shadow(self):
        sha = self.put(1)
        big = {"q%d" % i: {"type": "noul", "noul": 0.5, "pad": "x" * 1000} for i in range(64)}
        result = heads_cache.answer(self.cache, self.infer([], big), shadow_heads=sha)
        self.assertEqual(result["shadow"], {"heads": sha, "error": "shadow_failed"})
        self.assertEqual(result["answers"], {"leak": {"type": "noul", "noul": 0.25}})
        self.assertLessEqual(heads_cache.encoded_size(result), heads_cache.MAX_ANSWER_BYTES)
        small = {"q%d" % i: {"type": "noul", "noul": 0.5} for i in range(64)}
        result = heads_cache.answer(self.cache, self.infer([], small), shadow_heads=sha)
        self.assertEqual(result["shadow"]["answers"], small)

    def test_finite_check_walks_nested_values(self):
        self.assertTrue(heads_cache.all_finite({"a": [1, 2.5, {"b": (3, True, None, "nan")}], "c": 10 ** 400}))
        self.assertFalse(heads_cache.all_finite({"a": [1, {"b": (3, float("nan"))}]}))
        self.assertFalse(heads_cache.all_finite([[[[float("-inf")]]]]))

    def test_the_default_can_be_the_shadow(self):
        active = self.put(1)
        result = heads_cache.answer(self.cache, self.infer([]), heads=active, shadow_heads=DEFAULT_SHA)
        self.assertEqual(result["shadow"]["heads"], DEFAULT_SHA)
        self.assertEqual(result["shadow"]["model"], "apassy-base-v1+dddddddd")


class Eviction(CacheCase):
    def test_the_least_recently_used_set_goes_and_loads_again_from_disk(self):
        a, b, c = self.put(1), self.put(2), self.put(3)
        self.assertEqual(self.loader.calls, [])
        first = self.cache.get(a)
        self.assertIs(self.cache.get(a), first, "the same hash gives the same head set")
        self.cache.get(b)
        self.cache.get(a)
        self.cache.get(c)
        self.assertEqual(self.cache.loaded(), [a, c], "b was the least recently used")
        self.cache.get(b)
        self.assertEqual(self.cache.loaded(), [c, b])
        self.assertEqual(self.loader.calls, [s + ".safetensors" for s in (a, b, c, b)])
        self.assertEqual(self.cache.get(b).zero_shot, {"leak"})

    def test_the_default_is_never_loaded_evicted_or_deleted(self):
        a, b, c = self.put(1), self.put(2), self.put(3)
        for sha in (a, b, c, a, b, c):
            self.cache.get(sha)
            self.assertIs(self.cache.get(DEFAULT_SHA).module, "tuned")
        self.assertNotIn(DEFAULT_SHA, self.cache.loaded())
        with self.assertRaises(heads_cache.HeadsError) as caught:
            self.cache.delete(DEFAULT_SHA)
        self.assertEqual((caught.exception.status, caught.exception.code), (409, "default_heads"))
        self.cache.delete_all()
        self.assertEqual(self.cache.get(DEFAULT_SHA).sha, DEFAULT_SHA)
        self.assertTrue(self.cache.info(DEFAULT_SHA)["default"])

    def test_a_load_that_fails_evicts_nothing(self):
        a, b, c, d = self.put(1), self.put(2), self.put(3), self.put(4)
        self.cache.get(a)
        self.cache.get(b)
        self.loader.fail[c + ".safetensors"] = RuntimeError("MPS out of memory")
        with self.assertRaises(RuntimeError):
            self.cache.get(c)
        self.assertEqual(self.cache.loaded(), [a, b], "a failed load keeps the loaded sets")
        self.assertTrue(os.path.exists(os.path.join(self.dir, c + ".json")), "a transient failure keeps the files")
        self.loader.fail[d + ".safetensors"] = ValueError("does not open")
        with self.assertRaises(heads_cache.UnknownHeads):
            self.cache.get(d)
        self.assertEqual(self.cache.loaded(), [a, b])

    def test_a_stored_file_that_does_not_open_is_removed_and_unknown(self):
        sha = self.put(1)
        self.loader.fail[sha + ".safetensors"] = ValueError("the stored head file does not open")
        for _ in range(2):
            with self.assertRaises(heads_cache.UnknownHeads):
                self.cache.get(sha)
        self.assertEqual(os.listdir(self.dir), [])
        self.assertEqual(self.loader.calls, [sha + ".safetensors"])

    def test_a_limit_below_one_is_refused(self):
        with self.assertRaises(ValueError):
            heads_cache.HeadSetCache(default_set(), self.dir, BASE, self.loader, limit=0)
        with self.assertRaises(ValueError):
            heads_cache.HeadSetCache(default_set(), self.dir, BASE, self.loader, max_stored=0)


class Storage(CacheCase):
    def test_files_are_private(self):
        sha = self.put(1)
        self.assertEqual(stat.S_IMODE(os.stat(self.dir).st_mode), 0o700)
        for suffix in (".safetensors", ".json"):
            self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.dir, sha + suffix)).st_mode), 0o600)
        self.assertEqual(sorted(os.listdir(self.dir)), sorted([sha + ".json", sha + ".safetensors"]))

    def test_a_second_store_changes_nothing(self):
        sha = self.put(1)
        body = head_file(1)
        manifest = manifest_for(body, name="other-name")
        out, path = self.cache.new_upload()
        with out:
            out.write(body)
        self.assertEqual(self.cache.store(sha, path, json.dumps(manifest).encode(), manifest),
                         (False, "apassy-local-v1+" + sha[:8]))
        self.assertFalse(os.path.exists(path))

    def test_a_damaged_file_is_removed_and_unknown(self):
        sha = self.put(1)
        with open(os.path.join(self.dir, sha + ".safetensors"), "r+b") as f:
            f.seek(20)
            f.write(b"X")
        with self.assertRaises(heads_cache.UnknownHeads):
            self.cache.get(sha)
        self.assertEqual(self.loader.calls, [])
        self.assertEqual(os.listdir(self.dir), [])

    def test_delete_and_delete_all(self):
        a, b = self.put(1), self.put(2)
        self.cache.get(a)
        self.cache.delete(a)
        self.assertEqual(self.cache.loaded(), [])
        with self.assertRaises(heads_cache.UnknownHeads):
            self.cache.info(a)
        with self.assertRaises(heads_cache.UnknownHeads) as caught:
            self.cache.delete(a)
        self.assertEqual(caught.exception.status, 404)
        self.cache.get(b)
        self.assertEqual(self.cache.delete_all(), 2)
        self.assertEqual(self.cache.loaded(), [])
        self.assertEqual(os.listdir(self.dir), [])

    def upload(self, seed):
        body = head_file(seed)
        manifest = manifest_for(body)
        out, path = self.cache.new_upload()
        with out:
            out.write(body)
        return manifest["checkpoint"]["sha256"], path, manifest

    def test_no_head_file_without_its_manifest_when_the_manifest_cannot_be_written(self):
        sha, path, manifest = self.upload(1)
        with mock.patch.object(heads_cache.tempfile, "mkstemp", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.cache.store(sha, path, json.dumps(manifest).encode(), manifest)
        self.assertEqual(os.listdir(self.dir), [])

    def test_no_head_file_without_its_manifest_when_the_last_rename_fails(self):
        sha, path, manifest = self.upload(1)
        real = os.replace
        calls = []

        def replace(src, dst):
            calls.append(dst)
            if dst.endswith(".json"):
                raise OSError("disk full")
            return real(src, dst)

        with mock.patch.object(heads_cache.os, "replace", side_effect=replace):
            with self.assertRaises(OSError):
                self.cache.store(sha, path, json.dumps(manifest).encode(), manifest)
        self.assertEqual([os.path.basename(c) for c in calls], [sha + ".safetensors", sha + ".json"])
        self.assertEqual(os.listdir(self.dir), [])
        with self.assertRaises(heads_cache.UnknownHeads):
            self.cache.info(sha)

    def test_stale_uploads_are_removed_at_start(self):
        out, path = self.cache.new_upload()
        out.close()
        heads_cache.HeadSetCache(default_set(), self.dir, BASE, self.loader)
        self.assertFalse(os.path.exists(path))


class StoredLimit(CacheCase):
    max_stored = 2

    def test_a_full_folder_refuses_a_new_set_and_adds_nothing(self):
        a, b = self.put(1), self.put(2)
        sha, path, manifest = Storage.upload(self, 3)
        with self.assertRaises(heads_cache.HeadsError) as caught:
            self.cache.check_room(sha)
        self.assertEqual((caught.exception.status, caught.exception.code), (409, "heads_full"))
        self.assertNotRegex(caught.exception.message, HEX_RUN)
        with self.assertRaises(heads_cache.HeadsError) as caught:
            self.cache.store(sha, path, json.dumps(manifest).encode(), manifest)
        self.assertEqual(caught.exception.code, "heads_full")
        stored = sorted(n for n in os.listdir(self.dir) if not n.startswith(heads_cache.UPLOAD_PREFIX))
        self.assertEqual(stored, sorted([a + ".json", a + ".safetensors", b + ".json", b + ".safetensors"]))
        # A stored set and the default still answer 200, and a deletion makes room.
        self.cache.check_room(a)
        self.cache.check_room(DEFAULT_SHA)
        self.cache.delete(a)
        self.cache.check_room(sha)
        self.assertEqual(self.cache.store(sha, path, json.dumps(manifest).encode(), manifest)[0], True)


class HeadFileCheck(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def check(self, data, shapes=SHAPES):
        path = os.path.join(self.tmp.name, "f")
        with open(path, "wb") as f:
            f.write(data)
        heads_cache.check_head_file(path, shapes)

    def test_a_head_file_of_the_model_passes(self):
        self.check(head_file(1))

    def test_other_files_are_bad_heads(self):
        def set_field(name, field, value):
            return lambda header: header[name].__setitem__(field, value)

        n = head_file(1)
        deep = b"[" * 200000
        cases = {
            "empty": b"",
            "text": b"not safetensors at all",
            "encoder tensor": head_file(1, {"encoder.w": [2]}),
            "missing tensor": head_file(1, {"head.w": [2, 2]}),
            "other shape": head_file(1, {**SHAPES, "head.w": [2, 3]}),
            "F16": head_file(1, tweak=set_field("head.w", "dtype", "F16")),
            "no dtype": head_file(1, tweak=lambda h: h["head.w"].pop("dtype")),
            "negative dim": head_file(1, {"head.w": [-2, -2], "type_emb.weight": [3, 2], "scorer.b": [1]}),
            "float dim": head_file(1, tweak=set_field("head.w", "shape", [2.0, 2])),
            "bool dim": head_file(1, tweak=set_field("scorer.b", "shape", [True])),
            "offsets not a pair": head_file(1, tweak=set_field("head.w", "data_offsets", [0])),
            "offsets size": head_file(1, tweak=set_field("head.w", "data_offsets", [0, 12])),
            "overlap": head_file(1, tweak=set_field("type_emb.weight", "data_offsets", [8, 32])),
            "gap at the start": head_file(1, tweak=lambda h: [h[k].__setitem__(
                "data_offsets", [h[k]["data_offsets"][0] + 4, h[k]["data_offsets"][1] + 4]) for k in SHAPES]),
            "trailing bytes": head_file(1, extra=b"\0" * 4),
            "short data": n[:-4],
            "header over the file": struct.pack("<Q", 1 << 20) + b"{}",
            "deep header": struct.pack("<Q", len(deep)) + deep,
        }
        for label, data in cases.items():
            with self.subTest(label):
                with self.assertRaises(heads_cache.HeadsError) as caught:
                    self.check(data)
                self.assertEqual((caught.exception.status, caught.exception.code), (400, "bad_heads"))


def load_serve():
    """serve.py without torch: its module level imports only common, heads_cache and app."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("apassy_serve", ROOT / "tools/basemodel/serve.py")
    serve = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(serve)
    return serve


class ServeSelection(unittest.TestCase):
    """The torch-free part of serve.py that picks the rows of the stock heads."""

    @classmethod
    def setUpClass(cls):
        cls.serve = load_serve()

    def test_rows_follow_the_question_order(self):
        questions = {"task_match": {}, "leak": {}, "writes": {}}
        self.assertEqual(self.serve.zero_shot_rows({"leak"}, questions), [False, True, False])
        self.assertIsNone(self.serve.zero_shot_rows(set(), questions))

    def test_the_default_set_keeps_the_old_path(self):
        active = default_set()
        shadow = heads_cache.HeadSet("e" * 64, "x+eeeeeeee", "shadow-module", set(), 1)
        selection = self.serve.HeadSelection(active, shadow, {"leak": {}, "writes": {}})
        self.assertIsNone(selection.active)
        self.assertEqual(selection.stock_rows, [True, False])
        self.assertEqual(selection.shadow, "shadow-module")
        self.assertIsNone(selection.shadow_rows)


class ServeStartChecks(unittest.TestCase):
    """The start-up refusals of serve.py; no server starts."""

    @classmethod
    def setUpClass(cls):
        cls.serve = load_serve()

    def test_loopback_without_a_token_starts(self):
        for host in ["127.0.0.1", "127.8.9.10", "::1", "[::1]", "localhost", "LOCALHOST"]:
            with self.subTest(host):
                self.assertIsNone(self.serve.bind_problem(host, None))

    def test_another_address_needs_a_token(self):
        for host in ["0.0.0.0", "::", "100.64.1.2", "192.168.1.5", "example.com", "", "localhost.evil", "128.0.0.1"]:
            with self.subTest(host):
                problem = self.serve.bind_problem(host, None)
                self.assertIsNotNone(problem)
                self.assertIn("LAYA_API_KEY", problem)
                self.assertIsNone(self.serve.bind_problem(host, "token"))

    def test_the_heads_folder(self):
        home = os.path.join(self.tmpdir(), "home")
        resolve = self.serve.resolve_heads_dir
        self.assertEqual(resolve(environ={}, home=home),
                         os.path.join(home, "Library", "Application Support", "Apassy", "laya", "heads"))
        self.assertEqual(resolve(environ={"APASSY_LAYA_DIR": "/data/laya"}, home=home), "/data/laya/heads")
        self.assertEqual(resolve(environ={"APASSY_LAYA_DIR": "/data/laya", "APASSY_HEADS_DIR": "/x/h"}, home=home),
                         "/x/h")
        self.assertEqual(resolve(environ={"APASSY_HEADS_DIR": ""}, home=home),
                         os.path.join(home, "Library", "Application Support", "Apassy", "laya", "heads"))
        self.assertEqual(resolve("/explicit", environ={"APASSY_HEADS_DIR": "/x/h"}), "/explicit")

    def test_the_heads_folder_is_never_in_an_app_bundle(self):
        resolve = self.serve.resolve_heads_dir
        for env in [{"APASSY_HEADS_DIR": "/Applications/Apassy.app/Contents/Resources/models/heads"},
                    {"APASSY_LAYA_DIR": "/Applications/Apassy.app/Contents/Resources"},
                    {"APASSY_HEADS_DIR": "/Applications/Other.APP/heads"}]:
            with self.subTest(env):
                with self.assertRaises(SystemExit):
                    resolve(environ=env)
        with self.assertRaises(SystemExit):
            resolve("/Applications/Apassy.app/heads", environ={})
        # A folder that only has ".app" inside a name is fine.
        self.assertEqual(resolve(environ={"APASSY_HEADS_DIR": "/data/my.apps/heads"}), "/data/my.apps/heads")

    def test_a_symlink_into_an_app_bundle_is_refused(self):
        root = self.tmpdir()
        bundle = os.path.join(root, "Apassy.app", "Contents")
        os.makedirs(bundle)
        link = os.path.join(root, "heads")
        os.symlink(bundle, link)
        with self.assertRaises(SystemExit):
            self.serve.resolve_heads_dir(environ={"APASSY_HEADS_DIR": link})

    def test_limits_from_the_environment(self):
        with mock.patch.dict(os.environ, {"APASSY_HEADS_MAX": ""}):
            self.assertEqual(self.serve.limit_from_env("APASSY_HEADS_MAX", 16), 16)
        with mock.patch.dict(os.environ, {"APASSY_HEADS_MAX": "3"}):
            self.assertEqual(self.serve.limit_from_env("APASSY_HEADS_MAX", 16), 3)
        for raw in ["0", "-1", "x"]:
            with mock.patch.dict(os.environ, {"APASSY_HEADS_MAX": raw}):
                with self.assertRaises(SystemExit):
                    self.serve.limit_from_env("APASSY_HEADS_MAX", 16)

    def tmpdir(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        return os.path.realpath(tmp.name)


if __name__ == "__main__":
    unittest.main()
