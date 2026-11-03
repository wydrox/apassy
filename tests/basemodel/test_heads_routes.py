"""The routes of the bouncer brain server with a fake router; no torch, weights or network.

Needs fastapi and httpx (the Laya venv has both); skips without them.
"""
import base64
import hashlib
import json
import logging
import math
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
import app as brain_app  # noqa: E402
import heads_cache  # noqa: E402

sys.dont_write_bytecode = _WRITE_BYTECODE

try:
    from fastapi.testclient import TestClient
except ImportError:  # also when httpx is missing
    TestClient = None

BASE = {"revision": "55cf4c4ebb4ebe31b2550e8bdf3bd21b99753851", "weights_sha256": "b" * 64}
SHAPES = {"head.w": [2, 2], "type_emb.weight": [3, 2], "scorer.b": [1]}
DEFAULT_SHA = "d" * 64
TOKEN = "s3cret-token"
STATE = "User request: \"SYNTHETIC-STATE-7f3a\". Shell command: `cat SYNTHETIC-FILE-91c2`."
QUESTION = "SYNTHETIC-QUESTION-5d0e: does the command leak?"


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


def sha(data):
    return hashlib.sha256(data).hexdigest()


def manifest_for(body, **changes):
    manifest = {
        "schema": 1,
        "name": "apassy-local-v1",
        "checkpoint": {"file": "candidate.safetensors", "sha256": sha(body), "size_bytes": len(body)},
        "base": {"repo": "convaiinnovations/laya", **BASE},
        "serve": {"zero_shot_questions": ["leak"]},
    }
    for key, value in changes.items():
        section, _, field = key.partition("__")
        if field:
            manifest[section][field] = value
        else:
            manifest[section] = value
    return manifest


def header(manifest):
    return base64.urlsafe_b64encode(json.dumps(manifest).encode()).rstrip(b"=").decode()


class FakeRouter:
    """`BaseRouter.predict` without the model: the same `heads_cache.answer` call.

    `active_noul` and `shadow_answers(questions)` change what the fake model answers.
    """

    loaded = ["english"]

    def __init__(self, cache):
        self.cache = cache
        self.calls = []
        self.active_noul = 0.25
        self.shadow_answers = lambda questions: {qid: {"type": "noul", "noul": 0.75} for qid in questions}

    def predict(self, state, questions, heads=None, shadow_heads=None):
        def infer(active, shadow):
            self.calls.append((active.sha, None if shadow is None else shadow.sha))
            answers = {qid: {"type": "noul", "noul": self.active_noul} for qid in questions}
            result = {"model": "laya-rl-agent", "answers": answers,
                      "usage": {"input_tokens": 7, "output_tokens": 0}, "routing": {"model": "english"}}
            return result, (None if shadow is None else self.shadow_answers(questions))
        return heads_cache.answer(self.cache, infer, heads, shadow_heads)


class Loader:
    """A fake head-set loader; a name in `fail` raises its exception."""

    def __init__(self):
        self.fail = {}

    def __call__(self, path):
        name = os.path.basename(path)
        if name in self.fail:
            raise self.fail[name]
        return object()


@unittest.skipIf(TestClient is None, "requires fastapi and httpx")
class Routes(unittest.TestCase):
    # The routes that write need a token on the server (NoToken checks the 403).
    api_key = TOKEN
    max_stored = heads_cache.DEFAULT_STORED_LIMIT

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = os.path.join(self.tmp.name, "heads")
        default = heads_cache.HeadSet(DEFAULT_SHA, "apassy-base-v1+dddddddd", "tuned", {"leak"}, 1000,
                                      default=True)
        self.loader = Loader()
        self.cache = heads_cache.HeadSetCache(default, self.dir, BASE, self.loader, limit=2,
                                              expected_shapes=SHAPES, max_stored=self.max_stored)
        self.router = FakeRouter(self.cache)
        app = brain_app.create_app(self.router, self.cache, api_key=self.api_key, max_upload=4096)
        self.client = TestClient(app)
        self.client.__enter__()

    def tearDown(self):
        self.client.__exit__(None, None, None)
        self.tmp.cleanup()

    def auth(self, extra=None):
        headers = {"Authorization": "Bearer " + TOKEN} if self.api_key else {}
        headers.update(extra or {})
        return headers

    def put(self, body, manifest=None, path_sha=None, headers=None):
        manifest = manifest_for(body) if manifest is None else manifest
        extra = {"Apassy-Manifest": header(manifest), "Content-Type": "application/octet-stream"}
        extra.update(headers or {})
        return self.client.put("/v1/heads/%s" % (path_sha or sha(body)), content=body, headers=self.auth(extra))

    def ask(self, **fields):
        body = {"state": STATE, "questions": {"leak": {"type": "noul", "instructions": QUESTION}}, **fields}
        return self.client.post("/v1/systemone", json=body, headers=self.auth())

    def assert_code(self, response, status, code):
        self.assertEqual(response.status_code, status, response.text)
        self.assertEqual(response.json()["detail"]["code"], code)
        # A message never has request data, also not the requested hash.
        self.assertNotRegex(response.json()["detail"]["message"], "[0-9a-fA-F]{8,}")

    def assert_nothing_stored(self):
        self.assertEqual(os.listdir(self.dir) if os.path.isdir(self.dir) else [], [])


class Upload(Routes):
    def test_a_new_head_set_is_201_and_again_200(self):
        body = head_file(1)
        first = self.put(body)
        self.assertEqual(first.status_code, 201, first.text)
        self.assertEqual(first.json(), {"heads": sha(body), "model": "apassy-local-v1+" + sha(body)[:8]})
        again = self.put(body)
        self.assertEqual(again.status_code, 200, again.text)
        self.assertEqual(again.json(), first.json())
        self.assertEqual(stat.S_IMODE(os.stat(self.dir).st_mode), 0o700)
        self.assertEqual(sorted(os.listdir(self.dir)), sorted([sha(body) + ".json", sha(body) + ".safetensors"]))
        for name in os.listdir(self.dir):
            self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.dir, name)).st_mode), 0o600)
        with open(os.path.join(self.dir, sha(body) + ".safetensors"), "rb") as f:
            self.assertEqual(f.read(), body)

    def test_mismatches_are_400_bad_heads_and_store_nothing(self):
        body = head_file(1)
        other = head_file(2)
        cases = {
            "body hash": dict(manifest=manifest_for(other), path_sha=sha(other)),
            "manifest hash": dict(manifest=manifest_for(body, checkpoint__sha256=sha(other))),
            "size": dict(manifest=manifest_for(body, checkpoint__size_bytes=len(body) + 1)),
            "base revision": dict(manifest=manifest_for(body, base__revision="0" * 40)),
            "base weights": dict(manifest=manifest_for(body, base__weights_sha256="0" * 64)),
            "name": dict(manifest=manifest_for(body, name="no spaces")),
            "zero-shot list": dict(manifest=manifest_for(body, serve={"zero_shot_questions": "leak"})),
        }
        for label, case in cases.items():
            with self.subTest(label):
                self.assert_code(self.put(body, **case), 400, "bad_heads")
        self.assert_nothing_stored()

    def test_the_manifest_header_must_be_base64url_json(self):
        body = head_file(1)
        for value in [None, "", "not base64!", "e30=", base64.urlsafe_b64encode(b"[1]").decode().rstrip("="),
                      base64.urlsafe_b64encode(b"\xff\xfe").decode().rstrip("=")]:
            with self.subTest(value):
                headers = self.auth({"Content-Type": "application/octet-stream"})
                if value is not None:
                    headers["Apassy-Manifest"] = value
                response = self.client.put("/v1/heads/" + sha(body), content=body, headers=headers)
                self.assert_code(response, 400, "bad_heads")

    def test_a_file_that_is_not_a_head_file_of_this_model_is_400(self):
        for body in [b"x" * 64, head_file(1, {"encoder.layer.w": [2]}), head_file(1, {"head.w": [2, 2]})]:
            with self.subTest(len(body)):
                self.assert_code(self.put(body), 400, "bad_heads")
        self.assert_nothing_stored()

    def test_too_large_is_413_and_leaves_no_file(self):
        body = head_file(1, {"head.w": [1100]})
        self.assertGreater(len(body), 4096)
        self.assertEqual(self.put(body).status_code, 413)
        self.assert_nothing_stored()
        big = manifest_for(head_file(1))
        big["training"] = {"notes": "x" * (16 * 1024)}
        self.assertEqual(self.put(head_file(1), manifest=big).status_code, 413)

    def test_a_chunked_upload_without_content_length_is_capped_and_leaves_no_file(self):
        import httpx

        def chunks(data, size=512):
            for i in range(0, len(data), size):
                yield data[i:i + size]

        probe = httpx.Request("PUT", "http://x/", content=chunks(b"abc"))
        self.assertNotIn("content-length", probe.headers, "the premise: no Content-Length")
        self.assertEqual(probe.headers.get("transfer-encoding"), "chunked")
        big = head_file(1, {"head.w": [1100]})
        self.assertGreater(len(big), 4096)
        response = self.client.put(
            "/v1/heads/" + sha(big), content=chunks(big),
            headers=self.auth({"Apassy-Manifest": header(manifest_for(big)),
                               "Content-Type": "application/octet-stream"}))
        self.assert_code(response, 413, "too_large")
        self.assert_nothing_stored()
        body = head_file(2)
        response = self.client.put(
            "/v1/heads/" + sha(body), content=chunks(body, 16),
            headers=self.auth({"Apassy-Manifest": header(manifest_for(body)),
                               "Content-Type": "application/octet-stream"}))
        self.assertEqual(response.status_code, 201, response.text)
        self.assertEqual(sorted(os.listdir(self.dir)), sorted([sha(body) + ".json", sha(body) + ".safetensors"]))

    def test_a_deep_manifest_or_a_bad_dtype_is_400(self):
        body = head_file(1)
        deep = base64.urlsafe_b64encode(b"[" * 10000).rstrip(b"=").decode()
        response = self.client.put("/v1/heads/" + sha(body), content=body,
                                   headers=self.auth({"Apassy-Manifest": deep}))
        self.assert_code(response, 400, "bad_heads")
        raw = head_file(1).replace(b'"F32"', b'"F16"')
        self.assert_code(self.put(raw), 400, "bad_heads")
        self.assert_nothing_stored()

    def test_a_malformed_path_is_bad_heads(self):
        body = head_file(1)
        self.assert_code(self.put(body, path_sha="ABC"), 400, "bad_heads")
        self.assert_code(self.client.get("/v1/heads/ABC", headers=self.auth()), 422, "bad_heads")
        self.assert_code(self.client.delete("/v1/heads/" + "A" * 64, headers=self.auth()), 422, "bad_heads")


class Lookup(Routes):
    def test_get_answers_the_info_or_404(self):
        body = head_file(1)
        self.put(body)
        self.assertEqual(self.client.get("/v1/heads/" + sha(body), headers=self.auth()).json(),
                         {"heads": sha(body), "model": "apassy-local-v1+" + sha(body)[:8],
                          "size_bytes": len(body), "default": False})
        self.assertEqual(self.client.get("/v1/heads/" + DEFAULT_SHA, headers=self.auth()).json(),
                         {"heads": DEFAULT_SHA, "model": "apassy-base-v1+dddddddd", "size_bytes": 1000,
                          "default": True})
        self.assert_code(self.client.get("/v1/heads/" + "e" * 64, headers=self.auth()), 404, "unknown_heads")

    def test_delete_one_then_it_is_gone_everywhere(self):
        body = head_file(1)
        self.put(body)
        self.assertEqual(self.ask(heads=sha(body)).status_code, 200)
        response = self.client.delete("/v1/heads/" + sha(body), headers=self.auth())
        self.assertEqual((response.status_code, response.content), (204, b""))
        self.assert_code(self.client.get("/v1/heads/" + sha(body), headers=self.auth()), 404, "unknown_heads")
        self.assert_code(self.ask(heads=sha(body)), 409, "unknown_heads")
        self.assert_code(self.client.delete("/v1/heads/" + sha(body), headers=self.auth()), 404, "unknown_heads")
        self.assert_nothing_stored()

    def test_the_default_cannot_be_deleted(self):
        self.assert_code(self.client.delete("/v1/heads/" + DEFAULT_SHA, headers=self.auth()), 409, "default_heads")
        self.assertEqual(self.ask(heads=DEFAULT_SHA).status_code, 200)

    def test_delete_owner_removes_every_uploaded_set(self):
        first, second = head_file(1), head_file(2)
        self.put(first)
        self.put(second)
        response = self.client.delete("/v1/owner", headers=self.auth())
        # v2 section 6.3: 200 with the counts (a v1 client takes 200 and 204 as success).
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"deleted": {"heads": 2, "jobs": 0, "examples": 0}})
        self.assert_nothing_stored()
        again = self.client.delete("/v1/owner", headers=self.auth())
        self.assertEqual(again.json(), {"deleted": {"heads": 0, "jobs": 0, "examples": 0}})
        for body in (first, second):
            self.assert_code(self.ask(heads=sha(body)), 409, "unknown_heads")
        self.assertEqual(self.client.get("/v1/heads/" + DEFAULT_SHA, headers=self.auth()).status_code, 200)

    def test_without_a_job_manager_training_and_docs_routes_are_not_served(self):
        for method, path in [("POST", "/v1/train"), ("GET", "/v1/train/1"), ("GET", "/v1/train/1/result"),
                             ("GET", "/docs"), ("GET", "/openapi.json")]:
            with self.subTest(path):
                self.assertEqual(self.client.request(method, path, headers=self.auth()).status_code, 404)


class Systemone(Routes):
    def test_without_heads_the_default_answers(self):
        response = self.ask()
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["heads"], DEFAULT_SHA)
        self.assertEqual(body["model"], "apassy-base-v1+dddddddd")
        self.assertNotIn("shadow", body)
        self.assertEqual(self.router.calls, [(DEFAULT_SHA, None)])

    def test_null_heads_mean_the_default(self):
        body = self.ask(heads=None, shadow_heads=None).json()
        self.assertEqual(body["heads"], DEFAULT_SHA)
        self.assertNotIn("shadow", body)

    def test_active_and_shadow(self):
        active, shadow = head_file(1), head_file(2)
        self.put(active)
        self.put(shadow)
        body = self.ask(heads=sha(active), shadow_heads=sha(shadow)).json()
        self.assertEqual(body["heads"], sha(active))
        self.assertEqual(body["answers"]["leak"]["noul"], 0.25)
        self.assertEqual(body["shadow"], {"heads": sha(shadow), "model": "apassy-local-v1+" + sha(shadow)[:8],
                                          "answers": {"leak": {"type": "noul", "noul": 0.75}}})

    def test_unknown_and_malformed_heads(self):
        self.assert_code(self.ask(heads="e" * 64), 409, "unknown_heads")
        self.assert_code(self.ask(heads="E" * 64), 422, "bad_heads")
        self.assert_code(self.ask(shadow_heads=12), 422, "bad_heads")
        response = self.ask(shadow_heads="e" * 64)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["shadow"], {"heads": "e" * 64, "error": "unknown_heads"})
        self.assertEqual(response.json()["answers"]["leak"]["noul"], 0.25)

    def test_a_non_finite_shadow_is_shadow_failed(self):
        body = head_file(1)
        self.put(body)
        self.router.shadow_answers = lambda questions: {qid: {"type": "noul", "noul": math.nan}
                                                        for qid in questions}
        response = self.ask(shadow_heads=sha(body))
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["shadow"], {"heads": sha(body), "error": "shadow_failed"})
        self.assertEqual(response.json()["answers"], {"leak": {"type": "noul", "noul": 0.25}})
        self.assertEqual(response.json()["heads"], DEFAULT_SHA)

    def test_a_non_finite_active_answer_is_500_without_request_data(self):
        records = []

        class Keep(logging.Handler):
            def emit(self, record):
                records.append(self.format(record))

        keep = Keep(level=logging.DEBUG)
        brain_level = brain_app.LOG.level
        brain_app.LOG.addHandler(keep)
        brain_app.LOG.setLevel(logging.DEBUG)
        try:
            for value in (math.nan, math.inf):
                self.router.active_noul = value
                response = self.ask()
                self.assertEqual(response.status_code, 500, response.text)
                self.assertEqual(response.json(), {"detail": "inference failed"})
        finally:
            brain_app.LOG.removeHandler(keep)
            brain_app.LOG.setLevel(brain_level)
        text = "\n".join(records)
        self.assertIn("systemone inference failed: NonFiniteAnswer", text)
        self.assertIn("systemone status=500 questions=1", text)
        for secret in ("SYNTHETIC-STATE-7f3a", "SYNTHETIC-FILE-91c2", "SYNTHETIC-QUESTION-5d0e", "nan", TOKEN):
            self.assertNotIn(secret, text)

    def test_a_large_shadow_answer_is_shadow_failed_and_the_response_fits(self):
        body = head_file(1)
        self.put(body)
        self.router.shadow_answers = lambda questions: {qid: {"type": "noul", "noul": 0.5, "pad": "x" * 70000}
                                                        for qid in questions}
        response = self.ask(shadow_heads=sha(body))
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["shadow"], {"heads": sha(body), "error": "shadow_failed"})
        self.assertEqual(response.json()["answers"]["leak"]["noul"], 0.25)
        head = sum(len(k) + len(v) + 4 for k, v in response.headers.items()) + 32
        self.assertLess(len(response.content) + head, 64 * 1024)

    def test_a_stored_file_that_does_not_open_is_unknown_not_500(self):
        body = head_file(1)
        self.put(body)
        self.loader.fail[sha(body) + ".safetensors"] = ValueError("the stored head file does not open")
        for _ in range(2):
            self.assert_code(self.ask(heads=sha(body)), 409, "unknown_heads")
        self.assert_nothing_stored()

    def test_laya_guardrails_stay(self):
        post = lambda content: self.client.post("/v1/systemone", content=content, headers=self.auth())  # noqa: E731
        self.assertEqual(post(b"{not json").status_code, 400)
        self.assertEqual(post(b'{"state": "x"}').status_code, 400)
        self.assertEqual(post(json.dumps({"state": "x", "questions": []}).encode()).status_code, 400)
        many = {"q%d" % i: {"type": "noul", "instructions": "?"} for i in range(65)}
        self.assertEqual(post(json.dumps({"state": "x", "questions": many}).encode()).status_code, 413)
        self.assertEqual(post(json.dumps({"state": "x" * 50001, "questions": {}}).encode()).status_code, 413)
        self.assertEqual(post(b" " * (2 * 1024 * 1024 + 1)).status_code, 413)

    def test_no_log_line_has_the_state_the_question_or_the_answer(self):
        records = []

        class Keep(logging.Handler):
            def emit(self, record):
                records.append(self.format(record))

        keep = Keep(level=logging.DEBUG)
        root = logging.getLogger()
        old_level, brain_level = root.level, brain_app.LOG.level
        root.addHandler(keep)
        root.setLevel(logging.DEBUG)
        brain_app.LOG.setLevel(logging.DEBUG)
        try:
            body = head_file(1)
            self.put(body)
            self.assertEqual(self.ask(heads=sha(body), shadow_heads="e" * 64).status_code, 200)
            self.assertEqual(self.ask(heads="e" * 64).status_code, 409)
        finally:
            root.removeHandler(keep)
            root.setLevel(old_level)
            brain_app.LOG.setLevel(brain_level)
        text = "\n".join(records)
        self.assertIn("systemone status=200 questions=1", text, "the capture sees the server log")
        self.assertIn("systemone status=409", text)
        for secret in ("SYNTHETIC-STATE-7f3a", "SYNTHETIC-FILE-91c2", "SYNTHETIC-QUESTION-5d0e", "0.25",
                       TOKEN):
            self.assertNotIn(secret, text)


class Auth(Routes):
    api_key = TOKEN

    def test_every_route_but_health_needs_the_token(self):
        body = head_file(1)
        calls = [
            ("POST", "/v1/systemone", {"json": {"state": "x", "questions": {}}}),
            ("GET", "/v1/heads/" + DEFAULT_SHA, {}),
            ("PUT", "/v1/heads/" + sha(body), {"content": body, "headers": {"Apassy-Manifest": header(manifest_for(body))}}),
            ("DELETE", "/v1/heads/" + DEFAULT_SHA, {}),
            ("DELETE", "/v1/owner", {}),
        ]
        # The last one is legal on the wire (latin-1): it must answer 401, not 500 (as in laya).
        for wrong in [None, "Bearer wrong", "Bearer " + TOKEN + "x", TOKEN, "Bearer s\xe9cret".encode("latin-1")]:
            for method, path, kwargs in calls:
                with self.subTest(method=method, path=path, auth=wrong):
                    kwargs = dict(kwargs)
                    headers = dict(kwargs.pop("headers", {}))
                    if wrong is not None:
                        headers["Authorization"] = wrong
                    response = self.client.request(method, path, headers=headers, **kwargs)
                    self.assertEqual(response.status_code, 401, response.text)
        self.assert_nothing_stored()
        health = self.client.get("/health")
        self.assertEqual(health.status_code, 200)
        self.assertEqual(health.json()["status"], "ok")
        self.assertEqual(health.json()["loaded"], ["english"])
        self.assertIsInstance(health.json()["device"], str)
        self.assertEqual(health.json()["contract"], "bouncer-brain-v2")
        self.assertIs(health.json()["jobs"], False)
        self.assertIs(health.json()["sign_in"], False)

    def test_the_token_opens_every_route(self):
        body = head_file(1)
        self.assertEqual(self.put(body).status_code, 201)
        self.assertEqual(self.ask(heads=sha(body)).status_code, 200)
        self.assertEqual(self.client.get("/v1/heads/" + sha(body), headers=self.auth()).status_code, 200)
        self.assertEqual(self.client.delete("/v1/owner", headers=self.auth()).status_code, 200)


class NoToken(Routes):
    """Without a token the server answers the routes that write with 403 `no_token`."""

    api_key = None

    def test_the_routes_that_write_are_403_and_change_nothing(self):
        stored = head_file(1)
        manifest = manifest_for(stored)
        out, path = self.cache.new_upload()
        with out:
            out.write(stored)
        self.cache.store(sha(stored), path, json.dumps(manifest).encode(), manifest)
        before = sorted(os.listdir(self.dir))
        body = head_file(2)
        for response in [self.put(body),
                         self.client.delete("/v1/heads/" + sha(stored)),
                         self.client.delete("/v1/heads/" + "A" * 64),
                         self.client.delete("/v1/owner")]:
            with self.subTest(response.request.method + " " + response.request.url.path):
                self.assert_code(response, 403, "no_token")
        self.assertEqual(sorted(os.listdir(self.dir)), before)

    def test_the_read_routes_and_systemone_stay_open(self):
        self.assertEqual(self.client.get("/v1/heads/" + DEFAULT_SHA).status_code, 200)
        self.assert_code(self.client.get("/v1/heads/" + "e" * 64), 404, "unknown_heads")
        self.assertEqual(self.ask().status_code, 200)
        self.assertEqual(self.client.get("/health").status_code, 200)


class Full(Routes):
    max_stored = 1

    def test_a_full_server_is_409_heads_full_and_adds_nothing(self):
        first, second = head_file(1), head_file(2)
        self.assertEqual(self.put(first).status_code, 201)
        self.assert_code(self.put(second), 409, "heads_full")
        self.assertEqual(sorted(os.listdir(self.dir)), sorted([sha(first) + ".json", sha(first) + ".safetensors"]))
        self.assertEqual(self.put(first).status_code, 200, "a stored set is still idempotent")
        self.assertEqual(self.client.delete("/v1/heads/" + sha(first), headers=self.auth()).status_code, 204)
        self.assertEqual(self.put(second).status_code, 201)


class LayaParity(unittest.TestCase):
    """The guardrails copied from laya-serve 0.3.20 keep laya's values."""

    def test_the_limits_are_laya_limits(self):
        try:
            from laya import serve as laya_serve
        except ImportError:
            raise unittest.SkipTest("requires the Laya venv")
        self.assertEqual((brain_app.MAX_QUESTIONS, brain_app.MAX_STATE_CHARS, brain_app.MAX_BODY_BYTES),
                         (laya_serve.MAX_QUESTIONS, laya_serve.MAX_STATE_CHARS, laya_serve.MAX_BODY_BYTES))


if __name__ == "__main__":
    unittest.main()
