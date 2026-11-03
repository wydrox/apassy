"""HTTP surface of the bouncer brain server (ADR 0035, units D1 and I-srv; contract bouncer-brain-v2).

Routes (HTTP/1.1, JSON; every route except `GET /health` needs
`Authorization: Bearer <LAYA_API_KEY>` when `LAYA_API_KEY` is set):

- `GET /health`: laya-serve's answer, unchanged.
- `POST /v1/systemone`: laya-serve's request, with optional `heads` and
  `shadow_heads` (SHA-256 of a head file). The answer names the head set that
  answered (`heads`) and, with `shadow_heads`, carries `shadow`.
- `GET`, `PUT`, `DELETE /v1/heads/<sha256>` and `DELETE /v1/owner`: head sets.
  The routes that write (`PUT`, both `DELETE`) are served only when the server has
  a token: without `LAYA_API_KEY` they answer 403 `no_token` and change nothing.
  `DELETE /v1/owner` also deletes the jobs and answers 200 with the counts (v2 6.3).
- `PUT`, `GET`, `DELETE /v1/train/<sha256>` and `GET /v1/train/<sha256>/result`:
  training jobs (v2 section 4, `jobs.py`), only when `create_app` gets a job manager.
  Every job route needs the token; without `LAYA_API_KEY` they answer 403 `no_token`.

Owners: an own server has one owner, the holder of `LAYA_API_KEY` (`own_server_owner`).
The Connect sign-in of v2 section 5 (unit D2) passes its own `owner_of(authorization,
entitlement)`: it returns the account of a live sign-in token, or raises 401
`unauthenticated` / 403 `not_entitled`; `entitlement` is "training", "hosting" or None.

The app replaces laya-serve's `create_app` (laya 0.3.20): laya's `/v1/systemone`
cannot pass `heads` to the router, so the route, its guardrails, the single
inference worker and the bearer check are the same code here, with the head fields
added.

The server never logs the state, the questions or the answers: only counts,
latency, status codes and head-set hashes.

No torch or FastAPI import at module level: FastAPI is imported in `create_app`.
"""

import hashlib
import hmac
import json
import logging
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

# No __pycache__ next to this script: in Apassy.app it breaks the code signature.
_WRITE_BYTECODE = sys.dont_write_bytecode
sys.dont_write_bytecode = True
import heads_cache  # noqa: E402
import jobs as jobs_module  # noqa: E402

sys.dont_write_bytecode = _WRITE_BYTECODE

LOG = logging.getLogger("apassy.brain")

# The guardrails of laya-serve 0.3.20 (`laya/serve.py`), the same values.
MAX_QUESTIONS = 64
MAX_STATE_CHARS = 50000
MAX_BODY_BYTES = 2 * 1024 * 1024

_FROM_ENV = object()


def log_hash(value):
    """The first 8 hex of a well-formed hash for a log line; never other request data."""
    return value[:8] if isinstance(value, str) and heads_cache.HASH_RE.match(value) else "-"


def auth_ok(api_key, authorization):
    """laya-serve's bearer check: constant time, on bytes, total for every header value."""
    if api_key is None:
        return True
    expected = ("Bearer " + api_key).encode("utf-8", "surrogateescape")
    supplied = (authorization or "").encode("utf-8", "surrogateescape")
    return hmac.compare_digest(supplied, expected)


def request_limits_problem(state, questions):
    """laya-serve's `_check_request_limits`: (status, message) or None."""
    if not isinstance(questions, dict):
        return 400, "'questions' must be an object"
    if len(questions) > MAX_QUESTIONS:
        return 413, "too many questions (%d > %d)" % (len(questions), MAX_QUESTIONS)
    try:
        state_len = len(state) if isinstance(state, str) else len(str(state))
    except Exception:  # noqa: BLE001 -- as laya: an unprintable state is too large
        state_len = MAX_STATE_CHARS + 1
    if state_len > MAX_STATE_CHARS:
        return 413, "state too large (%d > %d chars)" % (state_len, MAX_STATE_CHARS)
    return None


def declared_length_over(request, limit):
    value = request.headers.get("content-length")
    if not value:
        return False
    try:
        return int(value) > limit
    except ValueError:
        return False


def create_app(router, cache, api_key=_FROM_ENV, max_upload=heads_cache.MAX_UPLOAD_BYTES,
               jobs=None, owner_of=None):
    """The FastAPI app. `router.predict(state, questions, heads=, shadow_heads=)` answers.

    `jobs`: a `jobs.JobManager`, or None (no job routes, `jobs: false` in `/health`).
    `owner_of(authorization, entitlement)`: the owner of a request (the seam of unit D2);
    default: the one owner of an own server.
    """
    import asyncio
    from concurrent.futures import ThreadPoolExecutor
    from contextlib import asynccontextmanager
    from typing import Optional

    from fastapi import FastAPI, Header, HTTPException, Request, Response
    from fastapi.responses import JSONResponse, StreamingResponse
    from starlette.concurrency import run_in_threadpool

    if api_key is _FROM_ENV:
        api_key = os.environ.get("LAYA_API_KEY") or None

    # As laya-serve: one inference worker, one forward pass at a time, and a gate so
    # waiting requests queue on the event loop. All per-request model state (the
    # selected head sets, the stock rows) is set and cleared inside this worker.
    pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="laya-infer")
    gate = None

    @asynccontextmanager
    async def lifespan(_app):
        try:
            yield
        finally:
            if jobs is not None:
                # A running job ends as `interrupted`, and its examples go.
                jobs.close()
            pool.shutdown(wait=True, cancel_futures=True)

    app = FastAPI(title="apassy-bouncer-brain", summary="bouncer-brain-v2", lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)

    def require_auth(authorization):
        if not auth_ok(api_key, authorization):
            raise HTTPException(status_code=401, detail="invalid or missing bearer token")

    def refused(error):
        return HTTPException(status_code=error.status, detail=error.detail())

    def require_write_token(authorization):
        # Without a token anyone on the address could store or delete head sets.
        require_auth(authorization)
        if api_key is None:
            raise refused(heads_cache.HeadsError(
                403, "no_token", "this server has no token, so it does not serve the routes that write"))

    def own_server_owner(authorization, entitlement=None):
        # One owner: the holder of the token. An own server has no entitlements.
        require_write_token(authorization)
        return jobs_module.OWN_SERVER

    if owner_of is None:
        owner_of = own_server_owner
    serve_jobs = jobs is not None and jobs.available

    @app.get("/health")
    def health():
        return {
            "status": "ok",
            "loaded": router.loaded,
            "device": os.environ.get("LAYA_DEVICE") or "auto",
            "contract": "bouncer-brain-v2",
            "jobs": serve_jobs,
            "sign_in": False,
        }

    @app.post("/v1/systemone")
    async def systemone(request: Request, authorization: Optional[str] = Header(default=None)):
        nonlocal gate
        require_auth(authorization)
        started = time.perf_counter()
        status, count = 500, 0
        result = None
        try:
            if declared_length_over(request, MAX_BODY_BYTES):
                raise HTTPException(status_code=413, detail="request body too large")
            total, chunks = 0, []
            async for chunk in request.stream():
                if not chunk:
                    continue
                total += len(chunk)
                if total > MAX_BODY_BYTES:
                    raise HTTPException(status_code=413, detail="request body too large")
                chunks.append(chunk)
            try:
                body = json.loads(b"".join(chunks))
            except ValueError:
                raise HTTPException(status_code=400, detail="request body must be valid JSON") from None
            if not isinstance(body, dict) or "questions" not in body:
                raise HTTPException(status_code=400,
                                    detail="request body must be an object with a 'questions' field")
            state = body.get("state")
            questions = body["questions"]
            problem = request_limits_problem(state, questions)
            if problem is not None:
                raise HTTPException(status_code=problem[0], detail=problem[1])
            count = len(questions)
            options = {}
            if body.get("heads") is not None:
                options["heads"] = body["heads"]
            if body.get("shadow_heads") is not None:
                options["shadow_heads"] = body["shadow_heads"]
            if gate is None:
                gate = asyncio.Lock()
            try:
                async with gate:
                    loop = asyncio.get_running_loop()
                    result = await loop.run_in_executor(
                        pool, lambda: router.predict(state, questions, **options))
            except HTTPException:
                raise
            except heads_cache.HeadsError as error:
                raise refused(error) from None
            except ValueError as error:
                # Question validation errors name the question and what to fix: safe for clients.
                raise HTTPException(status_code=422, detail=str(error)) from None
            except Exception as error:  # noqa: BLE001 -- never leak paths/weights/OOM text
                LOG.warning("systemone inference failed: %s", type(error).__name__)
                raise HTTPException(status_code=500, detail="inference failed") from None
            status = 200
            return result
        except HTTPException as error:
            status = error.status_code
            raise
        finally:
            shadow = (result or {}).get("shadow")
            LOG.info("systemone status=%d questions=%d latency_ms=%.0f heads=%s shadow=%s",
                     status, count, (time.perf_counter() - started) * 1000.0,
                     str((result or {}).get("heads", "-"))[:8],
                     "-" if shadow is None else ("%s:%s" % (str(shadow.get("heads"))[:8],
                                                            shadow.get("error", "ok"))))

    @app.get("/v1/heads/{sha}")
    def get_heads(sha: str, authorization: Optional[str] = Header(default=None)):
        require_auth(authorization)
        try:
            return cache.info(heads_cache.check_hash(sha))
        except heads_cache.HeadsError as error:
            raise refused(error) from None

    @app.put("/v1/heads/{sha}")
    async def put_heads(sha: str, request: Request,
                        authorization: Optional[str] = Header(default=None),
                        manifest_header: Optional[str] = Header(default=None, alias="Apassy-Manifest")):
        require_write_token(authorization)
        started = time.perf_counter()
        status, size, upload = 500, 0, None
        try:
            heads_cache.check_hash(sha, status=400)
            raw, manifest = heads_cache.decode_manifest_header(manifest_header)
            heads_cache.check_manifest(manifest, sha, cache.base, cache.stock_available)
            if declared_length_over(request, max_upload):
                raise heads_cache.HeadsError(413, "too_large", "the head file is larger than %d bytes"
                                             % max_upload)
            # Refuse a new head set before its body when the heads folder is full.
            cache.check_room(sha)
            # Stream to a temporary file in the heads folder and hash on the way: the
            # body is never held in memory, and the rename into place is atomic.
            out, upload = cache.new_upload()
            digest = hashlib.sha256()
            with out:
                async for chunk in request.stream():
                    if not chunk:
                        continue
                    size += len(chunk)
                    if size > max_upload:
                        raise heads_cache.HeadsError(413, "too_large", "the head file is larger than %d bytes"
                                                     % max_upload)
                    digest.update(chunk)
                    out.write(chunk)
                out.flush()
                os.fsync(out.fileno())
            heads_cache.check_body(sha, digest.hexdigest(), size, manifest)
            heads_cache.check_head_file(upload, cache.expected_shapes)
            created, model = cache.store(sha, upload, raw, manifest)
            upload = None
            status = 201 if created else 200
            return JSONResponse(status_code=status, content={"heads": sha, "model": model})
        except heads_cache.HeadsError as error:
            status = error.status
            raise refused(error) from None
        finally:
            if upload is not None:
                try:
                    os.unlink(upload)
                except FileNotFoundError:
                    pass
            LOG.info("heads put status=%d heads=%s bytes=%d latency_ms=%.0f",
                     status, log_hash(sha), size, (time.perf_counter() - started) * 1000.0)

    @app.delete("/v1/heads/{sha}")
    def delete_heads(sha: str, authorization: Optional[str] = Header(default=None)):
        require_write_token(authorization)
        try:
            cache.delete(heads_cache.check_hash(sha))
        except heads_cache.HeadsError as error:
            LOG.info("heads delete status=%d heads=%s", error.status, log_hash(sha))
            raise refused(error) from None
        LOG.info("heads delete status=204 heads=%s", log_hash(sha))
        return Response(status_code=204)

    @app.delete("/v1/owner")
    def delete_owner(authorization: Optional[str] = Header(default=None)):
        owner = owner_of(authorization, None)
        # Jobs first: a running job stops before its folder goes.
        counts = jobs.delete_owner(owner) if jobs is not None else {"jobs": 0, "examples": 0}
        heads = cache.stored_count()
        removed = cache.delete_all()
        deleted = {"heads": heads, "jobs": counts["jobs"], "examples": counts["examples"]}
        LOG.info("owner delete status=200 heads=%d jobs=%d examples=%d files=%d",
                 heads, counts["jobs"], counts["examples"], removed)
        return {"deleted": deleted}

    if not serve_jobs:
        return app

    # ------------------------------------------------------------- jobs (v2 section 4)
    @app.put("/v1/train/{sha}")
    async def put_train(sha: str, request: Request,
                        authorization: Optional[str] = Header(default=None),
                        manifest_header: Optional[str] = Header(default=None, alias="Apassy-Manifest")):
        started = time.perf_counter()
        status, size, upload = 500, 0, None
        try:
            # Everything before the body: the client sends no byte before 100 Continue,
            # and uvicorn sends that only when this route reads the body.
            owner = owner_of(authorization, "training")
            jobs_module.check_job_id(sha)
            _raw, manifest = jobs_module.decode_manifest_header(manifest_header)
            jobs_module.check_job_manifest(manifest, jobs.base)
            expected = jobs_module.body_size(manifest)
            declared = request.headers.get("content-length")
            if declared is None or not declared.isdigit():
                raise jobs_module.bad_job("a job upload needs a Content-Length")
            if int(declared) > jobs.max_upload or expected > jobs.max_upload:
                raise heads_cache.HeadsError(413, "too_large", "the job body is larger than %d bytes"
                                             % jobs.max_upload)
            if int(declared) != expected:
                raise jobs_module.bad_job("the body size is not the sum of the file sizes of the manifest")
            existing, upload = jobs.begin(owner, sha, manifest)
            if existing is not None:
                status = 200
                return JSONResponse(status_code=200, content=existing)
            async for chunk in request.stream():
                if chunk:
                    size += len(chunk)
                    upload.write(chunk)
            pending, upload = upload, None
            created, view = await run_in_threadpool(jobs.commit, pending)
            status = 201 if created else 200
            return JSONResponse(status_code=status, content=view)
        except heads_cache.HeadsError as error:
            status = error.status
            raise refused(error) from None
        except HTTPException as error:
            status = error.status_code
            raise
        finally:
            if upload is not None:
                upload.discard()
            LOG.info("train put status=%d job=%s bytes=%d latency_ms=%.0f",
                     status, jobs_module.log_id(sha), size, (time.perf_counter() - started) * 1000.0)

    @app.get("/v1/train/{sha}")
    def get_train(sha: str, authorization: Optional[str] = Header(default=None)):
        owner = owner_of(authorization, None)
        try:
            return jobs.get(owner, jobs_module.check_job_id(sha))
        except heads_cache.HeadsError as error:
            raise refused(error) from None

    @app.get("/v1/train/{sha}/result")
    def get_train_result(sha: str, authorization: Optional[str] = Header(default=None)):
        owner = owner_of(authorization, "training")
        try:
            f, size = jobs.open_result(owner, jobs_module.check_job_id(sha))
        except heads_cache.HeadsError as error:
            LOG.info("train result status=%d job=%s", error.status, jobs_module.log_id(sha))
            raise refused(error) from None

        def chunks():
            with f:
                while True:
                    block = f.read(1 << 20)
                    if not block:
                        return
                    yield block

        LOG.info("train result status=200 job=%s bytes=%d", jobs_module.log_id(sha), size)
        return StreamingResponse(chunks(), media_type="application/octet-stream",
                                 headers={"Content-Length": str(size)})

    @app.delete("/v1/train/{sha}")
    def delete_train(sha: str, authorization: Optional[str] = Header(default=None)):
        owner = owner_of(authorization, None)
        try:
            jobs.delete(owner, jobs_module.check_job_id(sha))
        except heads_cache.HeadsError as error:
            raise refused(error) from None
        return Response(status_code=204)

    return app
