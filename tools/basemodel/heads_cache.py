"""Head sets of the bouncer brain server (ADR 0035, unit D1; contract bouncer-brain-v1).

One server holds one encoder and several head sets. A head set is the trained part
of the model (`head.`, `type_emb.`, `scorer.`) of one safetensors file, and its name
is the SHA-256 of that file.

- The default head set is the checkpoint that `serve.py` started with. It is always
  loaded and never evicted or deleted.
- Uploaded head sets are files in the heads folder (`<sha>.safetensors` and
  `<sha>.json`, mode 0600, folder mode 0700). They load on first use. At most
  `limit` uploaded sets stay loaded (least recently used first out); an evicted set
  loads again from its file. At most `max_stored` uploaded sets are stored; a new
  upload past that answers 409 `heads_full`.
- An answer never has a number that is not finite, and with its shadow it stays
  under `MAX_ANSWER_BYTES` (`answer`).

This module has no torch or FastAPI import: the loader that builds a head module is
given by `serve.py`, so the tests run with fake head objects.
"""

import base64
import binascii
import json
import math
import numbers
import os
import re
import struct
import sys
import tempfile
import threading
from collections import OrderedDict

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

# No __pycache__ next to this script: in Apassy.app it breaks the code signature.
_WRITE_BYTECODE = sys.dont_write_bytecode
sys.dont_write_bytecode = True
import common  # noqa: E402

sys.dont_write_bytecode = _WRITE_BYTECODE

DEFAULT_CACHE_LIMIT = 4
DEFAULT_STORED_LIMIT = 16
MAX_UPLOAD_BYTES = 160 * 1024 * 1024
MAX_MANIFEST_HEADER_BYTES = 16 * 1024
# A safetensors header of the head file is a few KiB; refuse anything absurd.
MAX_SAFETENSORS_HEADER_BYTES = 1024 * 1024
# The client reads at most 64 KiB of a response, headers included; keep room for them.
MAX_ANSWER_BYTES = 60 * 1024

HASH_RE = re.compile(r"\A[0-9a-f]{64}\Z")
STORED_RE = re.compile(r"\A[0-9a-f]{64}\.(?:safetensors|json)\Z")
# `<name>+<8 hex>` stays within 64 bytes (`vault::MAX_MODEL_VERSION`).
NAME_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,54}\Z")
BASE64URL_RE = re.compile(r"\A[A-Za-z0-9_-]+\Z")
UPLOAD_PREFIX = ".upload-"


class HeadsError(Exception):
    """An answer of the head routes: HTTP status, error code, and a message without request data."""

    def __init__(self, status, code, message):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message

    def detail(self):
        return {"code": self.code, "message": self.message}


class UnknownHeads(HeadsError):
    # The hash stays out of the message: a message never has request data.
    def __init__(self, sha, status=404):
        super().__init__(status, "unknown_heads", "the head set is not on this server")
        self.sha = sha


class NonFiniteAnswer(RuntimeError):
    """The active head set gave NaN or infinity. Not a ValueError: the app answers its 500."""


def bad_heads(message):
    return HeadsError(400, "bad_heads", message)


def check_hash(value, status=422):
    """Return `value` if it is 64 lowercase hex characters, else raise `bad_heads`."""
    if not isinstance(value, str) or not HASH_RE.match(value):
        raise HeadsError(status, "bad_heads", "a head set is named by 64 lowercase hex characters (SHA-256)")
    return value


def model_name(name, sha):
    """`<manifest.name>+<first 8 hex>`, as `apassy-base-v1+83224960`."""
    return "%s+%s" % (name, sha[:8])


def zero_shot_of(manifest):
    return set(manifest.get("serve", {}).get("zero_shot_questions", []))


class HeadSet:
    """One head set. `module` is what the loader built (a DecisionModel in `serve.py`)."""

    __slots__ = ("sha", "model", "module", "zero_shot", "size_bytes", "default")

    def __init__(self, sha, model, module, zero_shot, size_bytes, default=False):
        self.sha = sha
        self.model = model
        self.module = module
        self.zero_shot = set(zero_shot)
        self.size_bytes = size_bytes
        self.default = default

    def info(self):
        return {"heads": self.sha, "model": self.model, "size_bytes": self.size_bytes,
                "default": self.default}


# ------------------------------------------------------------------ upload checks
def decode_manifest_header(value):
    """`Apassy-Manifest`: base64url without padding of manifest.json. Return (raw, dict)."""
    if not value:
        raise bad_heads("the Apassy-Manifest header is missing")
    if len(value) > MAX_MANIFEST_HEADER_BYTES:
        raise HeadsError(413, "too_large", "the Apassy-Manifest header is larger than %d bytes"
                         % MAX_MANIFEST_HEADER_BYTES)
    if not BASE64URL_RE.match(value) or len(value) % 4 == 1:
        raise bad_heads("the Apassy-Manifest header is not base64url without padding")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
        manifest = json.loads(raw.decode("utf-8"))
    except (binascii.Error, ValueError, TypeError, RecursionError):
        raise bad_heads("the Apassy-Manifest header is not a JSON manifest") from None
    if not isinstance(manifest, dict):
        raise bad_heads("the manifest is not a JSON object")
    return raw, manifest


def check_manifest(manifest, sha, base, stock_available=True):
    """The checks that need no body: the same checks as `serve.verify` for the checkpoint."""
    checkpoint = manifest.get("checkpoint")
    if not isinstance(checkpoint, dict):
        raise bad_heads("the manifest has no checkpoint block")
    if checkpoint.get("sha256") != sha:
        raise bad_heads("manifest checkpoint.sha256 is not the SHA-256 in the path")
    size = checkpoint.get("size_bytes")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        raise bad_heads("manifest checkpoint.size_bytes is not a byte count")
    base_manifest = manifest.get("base")
    if not isinstance(base_manifest, dict):
        raise bad_heads("the manifest has no base block")
    if base_manifest.get("revision") != base["revision"]:
        raise bad_heads("the manifest names another base revision")
    if base_manifest.get("weights_sha256") != base["weights_sha256"]:
        raise bad_heads("the manifest names other base weights")
    name = manifest.get("name")
    if not isinstance(name, str) or not NAME_RE.match(name):
        raise bad_heads("manifest name must be 1-55 characters of A-Z, a-z, 0-9, '.', '_', '-'")
    serve = manifest.get("serve", {})
    questions = serve.get("zero_shot_questions", []) if isinstance(serve, dict) else None
    if not isinstance(questions, list) or not all(isinstance(q, str) for q in questions):
        raise bad_heads("manifest serve.zero_shot_questions must be a list of question ids")
    if questions and not stock_available:
        raise bad_heads("this server has no stock heads for serve.zero_shot_questions")


def check_body(sha, body_sha, body_size, manifest):
    if body_sha != sha:
        raise bad_heads("the SHA-256 of the body is not the SHA-256 in the path")
    if body_size != manifest["checkpoint"]["size_bytes"]:
        raise bad_heads("the body size does not match manifest checkpoint.size_bytes")


def _byte_count(value):
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def check_head_file(path, expected_shapes=None):
    """Read the safetensors header (no torch): only F32 head tensors, the model's shapes,
    and data offsets that cover the data section exactly, without gaps or overlaps."""
    not_safetensors = "the body is not a safetensors file"
    try:
        with open(path, "rb") as f:
            file_size = os.fstat(f.fileno()).st_size
            prefix = f.read(8)
            if len(prefix) < 8:
                raise bad_heads(not_safetensors)
            (length,) = struct.unpack("<Q", prefix)
            if not 0 < length <= min(MAX_SAFETENSORS_HEADER_BYTES, file_size - 8):
                raise bad_heads(not_safetensors)
            header = json.loads(f.read(length).decode("utf-8"))
    except (OSError, ValueError, TypeError, RecursionError, struct.error):
        raise bad_heads(not_safetensors) from None
    if not isinstance(header, dict):
        raise bad_heads(not_safetensors)
    tensors = {k: v for k, v in header.items() if k != "__metadata__"}
    spans = []
    for key, value in tensors.items():
        if not key.startswith(common.TRAINED_PREFIXES):
            raise bad_heads("the head file has a tensor that is not a head tensor")
        if not isinstance(value, dict):
            raise bad_heads(not_safetensors)
        if value.get("dtype") != "F32":
            raise bad_heads("the head file has a tensor that is not F32")
        shape, offsets = value.get("shape"), value.get("data_offsets")
        if not isinstance(shape, list) or not all(_byte_count(d) for d in shape):
            raise bad_heads(not_safetensors)
        if (not isinstance(offsets, list) or len(offsets) != 2
                or not all(_byte_count(o) for o in offsets)):
            raise bad_heads(not_safetensors)
        n = 4
        for dim in shape:
            n *= dim
        if offsets[1] - offsets[0] != n:
            raise bad_heads(not_safetensors)
        spans.append((offsets[0], offsets[1]))
    # The tensors fill the data section in order: each starts where the last one ended,
    # and the last one ends at the end of the file.
    end = 0
    for start, stop in sorted(spans):
        if start != end:
            raise bad_heads(not_safetensors)
        end = stop
    if 8 + length + end != file_size:
        raise bad_heads(not_safetensors)
    if expected_shapes is not None:
        if set(tensors) != set(expected_shapes):
            raise bad_heads("the head file does not fit the model of this server")
        for key, shape in expected_shapes.items():
            if list(tensors[key]["shape"]) != list(shape):
                raise bad_heads("the head file does not fit the model of this server")


def fsync_dir(path):
    """Make the renames in a folder durable."""
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


# ------------------------------------------------------------------ the cache
class HeadSetCache:
    """Head sets by SHA-256. Thread-safe: the inference thread loads, the routes store and delete."""

    def __init__(self, default, heads_dir, base, loader, limit=DEFAULT_CACHE_LIMIT,
                 expected_shapes=None, stock_available=True, log=None, max_stored=DEFAULT_STORED_LIMIT):
        if int(limit) < 1:
            raise ValueError("the head-set cache needs a limit of at least 1")
        if int(max_stored) < 1:
            raise ValueError("the heads folder needs a limit of at least 1 head set")
        self.default = default
        self.heads_dir = os.path.abspath(heads_dir)
        self.base = {"revision": base["revision"], "weights_sha256": base["weights_sha256"]}
        self.loader = loader
        self.limit = int(limit)
        self.max_stored = int(max_stored)
        self.expected_shapes = expected_shapes
        self.stock_available = stock_available
        self.log = log
        self._loaded = OrderedDict()
        self._lock = threading.Lock()
        self._remove_stale_uploads()

    @property
    def default_sha(self):
        return self.default.sha

    def loaded(self):
        """SHA-256 of the loaded uploaded head sets, least recently used first."""
        with self._lock:
            return list(self._loaded)

    def _paths(self, sha):
        return (os.path.join(self.heads_dir, sha + ".safetensors"),
                os.path.join(self.heads_dir, sha + ".json"))

    def _stored_manifest(self, sha):
        """The manifest of a stored head set, or None. The `.json` file is written last."""
        weights, meta = self._paths(sha)
        try:
            with open(meta, encoding="utf-8") as f:
                manifest = json.load(f)
        except (OSError, ValueError, RecursionError):
            return None
        if not os.path.isfile(weights) or not isinstance(manifest, dict):
            return None
        return manifest

    def _remove_files(self, sha):
        for path in reversed(self._paths(sha)):
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass

    def _stored_count(self):
        try:
            names = os.listdir(self.heads_dir)
        except OSError:
            return 0
        return sum(1 for name in names if name.endswith(".json") and STORED_RE.match(name))

    def _check_room(self, sha):
        if sha == self.default.sha or self._stored_manifest(sha) is not None:
            return
        if self._stored_count() >= self.max_stored:
            raise HeadsError(409, "heads_full", "this server stores no more head sets; delete one first")

    def check_room(self, sha):
        """Raise 409 `heads_full` when `sha` is new and the heads folder is full."""
        with self._lock:
            self._check_room(sha)

    def _remove_stale_uploads(self):
        try:
            names = os.listdir(self.heads_dir)
        except OSError:
            return
        for name in names:
            if name.startswith(UPLOAD_PREFIX):
                try:
                    os.unlink(os.path.join(self.heads_dir, name))
                except OSError:
                    pass

    def _note(self, message, *args):
        if self.log is not None:
            self.log.warning(message, *args)

    def info(self, sha):
        if sha == self.default.sha:
            return self.default.info()
        manifest = self._stored_manifest(sha)
        if manifest is None:
            raise UnknownHeads(sha)
        try:
            size = os.path.getsize(self._paths(sha)[0])
        except OSError:
            raise UnknownHeads(sha) from None
        return {"heads": sha, "model": model_name(manifest.get("name", ""), sha),
                "size_bytes": size, "default": False}

    def get(self, sha):
        """The head set for `sha`, loaded from the heads folder on first use; UnknownHeads if absent."""
        if sha == self.default.sha:
            return self.default
        with self._lock:
            found = self._loaded.get(sha)
            if found is not None:
                self._loaded.move_to_end(sha)
                return found
        manifest = self._stored_manifest(sha)
        if manifest is None:
            raise UnknownHeads(sha)
        weights, meta = self._paths(sha)
        try:
            intact = (os.path.getsize(weights) == manifest["checkpoint"]["size_bytes"]
                      and common.sha256_file(weights) == sha)
        except OSError:
            raise UnknownHeads(sha) from None
        except (KeyError, TypeError):
            intact = False
        if not intact:
            # A stored file that no longer has its name is damaged. Remove it, so that the
            # client can upload it again (PUT would otherwise answer "already present").
            self._note("heads %s: stored file does not match its hash; removed", sha[:8])
            with self._lock:
                self._remove_files(sha)
            raise UnknownHeads(sha)
        # Load first, evict after: a load that fails keeps the loaded sets as they are.
        try:
            module = self.loader(weights)
        except FileNotFoundError:
            raise UnknownHeads(sha) from None
        except ValueError:
            # The loader raises ValueError for a file that does not open or does not fit
            # (serve.py maps SafetensorError to it). Remove it: else every request fails.
            self._note("heads %s: stored file does not open or fit the model; removed", sha[:8])
            with self._lock:
                self._remove_files(sha)
            raise UnknownHeads(sha) from None
        found = HeadSet(sha, model_name(manifest.get("name", ""), sha), module,
                        zero_shot_of(manifest), manifest["checkpoint"]["size_bytes"])
        with self._lock:
            if not os.path.exists(meta):
                # Deleted while it loaded.
                raise UnknownHeads(sha)
            self._loaded[sha] = found
            while len(self._loaded) > self.limit:
                self._loaded.popitem(last=False)
        return found

    def new_upload(self):
        """An open temporary file (mode 0600) in the heads folder (mode 0700), and its path."""
        os.makedirs(self.heads_dir, mode=0o700, exist_ok=True)
        os.chmod(self.heads_dir, 0o700)
        fd, path = tempfile.mkstemp(prefix=UPLOAD_PREFIX, suffix=".tmp", dir=self.heads_dir)
        return os.fdopen(fd, "wb"), path

    def store(self, sha, upload, manifest_raw, manifest):
        """Move a checked upload into place. Return (created, model). Takes over `upload`
        unless it raises `heads_full` (then the caller removes it)."""
        weights, meta = self._paths(sha)
        with self._lock:
            existing = self.default.model if sha == self.default.sha else None
            if existing is None:
                stored = self._stored_manifest(sha)
                if stored is not None:
                    existing = model_name(stored.get("name", ""), sha)
            if existing is not None:
                os.unlink(upload)
                return False, existing
            self._check_room(sha)
            tmp, placed = None, False
            try:
                # The manifest is ready before the head file moves: no head file without it.
                fd, tmp = tempfile.mkstemp(prefix=UPLOAD_PREFIX, suffix=".json.tmp", dir=self.heads_dir)
                with os.fdopen(fd, "wb") as f:
                    f.write(manifest_raw)
                    f.flush()
                    os.fsync(f.fileno())
                os.chmod(upload, 0o600)
                os.replace(upload, weights)
                placed = True
                os.replace(tmp, meta)
                tmp = None
                fsync_dir(self.heads_dir)
            except BaseException:
                for path in (tmp, weights if placed else upload):
                    if path is None:
                        continue
                    try:
                        os.unlink(path)
                    except FileNotFoundError:
                        pass
                raise
        return True, model_name(manifest["name"], sha)

    def delete(self, sha):
        if sha == self.default.sha:
            raise HeadsError(409, "default_heads", "the default head set of this server cannot be deleted")
        with self._lock:
            if self._stored_manifest(sha) is None:
                raise UnknownHeads(sha)
            self._remove_files(sha)
            self._loaded.pop(sha, None)

    def delete_all(self):
        """Delete every uploaded head set (one owner in v1). Return how many files went."""
        removed = 0
        with self._lock:
            self._loaded.clear()
            try:
                names = os.listdir(self.heads_dir)
            except OSError:
                return 0
            # `.json` first: a head set without its manifest is no longer served.
            for name in sorted(names, key=lambda n: not n.endswith(".json")):
                if STORED_RE.match(name):
                    try:
                        os.unlink(os.path.join(self.heads_dir, name))
                        removed += 1
                    except FileNotFoundError:
                        pass
        return removed


# ------------------------------------------------------------------ one request
def all_finite(value):
    """True if no number in `value` (nested dicts, lists and tuples) is NaN or infinite."""
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, (list, tuple)):
            stack.extend(item)
        elif (isinstance(item, numbers.Real) and not isinstance(item, numbers.Integral)
              and not math.isfinite(item)):
            return False
    return True


def encoded_size(result):
    """The size of `result` as FastAPI's JSONResponse writes it."""
    return len(json.dumps(result, ensure_ascii=False, allow_nan=False, indent=None,
                          separators=(",", ":")).encode("utf-8"))


def answer(cache, infer, heads=None, shadow_heads=None):
    """Answer one `/v1/systemone` request with the active and the optional shadow head set.

    `infer(active, shadow)` runs the model and returns `(result, shadow_answers)`, where
    `shadow_answers` is a dict, or an exception when the shadow failed. The shadow never
    makes the request fail and never changes the active answer. A shadow with a number
    that is not finite, or that makes the answer larger than `MAX_ANSWER_BYTES`, becomes
    `shadow_failed`; an active answer with a number that is not finite raises
    `NonFiniteAnswer` (a 500 without request data).
    """
    active_sha = cache.default_sha if heads is None else check_hash(heads)
    shadow_sha = None if shadow_heads is None else check_hash(shadow_heads)
    try:
        active = cache.get(active_sha)
    except UnknownHeads:
        raise UnknownHeads(active_sha, status=409) from None
    shadow, shadow_error = None, None
    if shadow_sha is not None:
        try:
            shadow = cache.get(shadow_sha)
        except UnknownHeads:
            shadow_error = "unknown_heads"
        except Exception:  # noqa: BLE001 -- a shadow failure only marks the shadow
            shadow_error = "shadow_failed"
    result, shadow_answers = infer(active, shadow)
    if not all_finite(result):
        raise NonFiniteAnswer("the active head set gave a number that is not finite")
    result["model"] = active.model
    result["heads"] = active.sha
    if shadow_sha is not None:
        failed = {"heads": shadow_sha, "error": shadow_error or "shadow_failed"}
        if shadow is not None and isinstance(shadow_answers, dict) and all_finite(shadow_answers):
            result["shadow"] = {"heads": shadow.sha, "model": shadow.model, "answers": shadow_answers}
            try:
                fits = encoded_size(result) <= MAX_ANSWER_BYTES
            except (TypeError, ValueError, RecursionError):
                fits = False
            if not fits:
                result["shadow"] = failed
        else:
            result["shadow"] = failed
    return result
