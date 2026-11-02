"""No torch, model weights or network: the head-set cache with fake head modules."""
import hashlib
import json
import os
import pathlib
import stat
import struct
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/basemodel"))
_WRITE_BYTECODE = sys.dont_write_bytecode
sys.dont_write_bytecode = True
import heads_cache  # noqa: E402

sys.dont_write_bytecode = _WRITE_BYTECODE

BASE = {"revision": "55cf4c4ebb4ebe31b2550e8bdf3bd21b99753851", "weights_sha256": "b" * 64}
SHAPES = {"head.w": [2, 2], "type_emb.weight": [3, 2], "scorer.b": [1]}
DEFAULT_SHA = "d" * 64


def head_file(seed, shapes=SHAPES):
    """A small safetensors file with the given tensors; `seed` makes the hash differ."""
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

    def __call__(self, path):
        self.calls.append(os.path.basename(path))
        return {"module": os.path.basename(path)}


def default_set():
    return heads_cache.HeadSet(DEFAULT_SHA, "apassy-base-v1+dddddddd", "tuned", {"leak"}, 1000, default=True)


class CacheCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = os.path.join(self.tmp.name, "heads")
        self.loader = FakeLoader()
        self.cache = heads_cache.HeadSetCache(default_set(), self.dir, BASE, self.loader, limit=2,
                                              expected_shapes=SHAPES)

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

    def test_a_limit_below_one_is_refused(self):
        with self.assertRaises(ValueError):
            heads_cache.HeadSetCache(default_set(), self.dir, BASE, self.loader, limit=0)


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

    def test_stale_uploads_are_removed_at_start(self):
        out, path = self.cache.new_upload()
        out.close()
        heads_cache.HeadSetCache(default_set(), self.dir, BASE, self.loader)
        self.assertFalse(os.path.exists(path))


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
        for data in [b"", b"not safetensors at all",
                     head_file(1, {"encoder.w": [2]}),
                     head_file(1, {"head.w": [2, 2]}),
                     head_file(1, {**SHAPES, "head.w": [2, 3]})]:
            with self.assertRaises(heads_cache.HeadsError) as caught:
                self.check(data)
            self.assertEqual((caught.exception.status, caught.exception.code), (400, "bad_heads"))


class ServeSelection(unittest.TestCase):
    """The torch-free part of serve.py that picks the rows of the stock heads."""

    @classmethod
    def setUpClass(cls):
        import importlib.util

        spec = importlib.util.spec_from_file_location("apassy_serve", ROOT / "tools/basemodel/serve.py")
        cls.serve = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.serve)

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


if __name__ == "__main__":
    unittest.main()
