# Bouncer brain wire contract v2

Date: 2026-11-03.
Status: proposed for wave 3 of [implementation plan 0035](../design/implementation-plan-0035.md) (unit A2). Unit I-srv implements the training jobs in `tools/basemodel/jobs.py`, unit D2 the sign-in and the owner namespaces in `tools/basemodel/auth.py` and `owners.py`; units I-cli and C3 implement the client side in Apassy. Not implemented yet. Fixtures: `tests/fixtures/bouncer-brain-v2/`, checked by `tests/bouncer_brain_contract.rs`.
Decision: [ADR 0035](../adr/0035-bouncer-hosting-and-training-choice.md). Base: [bouncer-brain-v1](bouncer-brain-v1.md). Connect interface: items I-1 to I-5 of the plan, section "Interface with Apassy Connect", and [implementation-plan-s7-connect.md](../design/implementation-plan-s7-connect.md) section 7.

Words ([bouncer.md](../operations/bouncer.md), Words): the **bouncer brain** is the model server; the **bouncer gate** is the decision in Apassy on the Mac. An **owner** is the one holder of the bearer token on an own server, and one Connect account on a Connect server. A **job** is one training of the heads on the server from the examples of one upload. MUST/MUST NOT below are implementation requirements.

## 1. What v2 adds, and what stays

Version 2 is version 1 plus three parts that version 1 reserved: training jobs (section 4), the Connect sign-in (section 5), and owner namespaces (section 6). Sections 1 to 9 of v1 stay in force unless a section below changes them.

**For existing clients, v1 is unchanged.** Every v1 route, field, status and error code keeps its meaning on a v2 server: `GET /health`, `POST /v1/systemone`, `GET`, `PUT`, `DELETE /v1/heads/<sha256>`, and `DELETE /v1/owner`. A v1 client works against a v2 own server without a change. The one difference is the success answer of `DELETE /v1/owner`: a v2 server answers 200 with the counts of section 6.3 instead of 204 with no body. No released client sends `DELETE /v1/owner` (the Apassy client of unit C1, `src/broker/bouncer.rs` on `r17/0035-c1`, has no call to it), and a client MUST treat both 200 and 204 as success.

A v2 client against a v1 server: the routes of sections 4 and 5 answer 404 there. The client shows "this server does not run training jobs" for a 404 on `PUT /v1/train/<sha256>`, and treats a 404 on a sign-in route as unavailable. `GET /health` of section 2 tells the client before it tries.

Rules that v2 does not change and that every part below follows:

- The bouncer gate makes every decision on the Mac. Any status other than 200 of `POST /v1/systemone`, also the new 401 and 403 of a Connect server, is unavailable, and the gate asks the owner (v1 section 3.4). Unavailable is never an allowance.
- A head set from a job starts in shadow mode on the Mac, as every new head set. Only the owner promotes it (`OwnerAction::PromoteModel`). The server has no promotion.
- No request, upload, answer or log line contains a secret value, the vault path, the full path of the project or the home folder of the Mac (v1 section 8: `bouncer::shorten_paths`), or an absolute path of the server.
- The client deadlines of v1 section 8 stay: 20 s for each attempt to a remote bouncer brain, one retry after a transport timeout. The sign-in of section 5 happens inside that deadline. File transfers use the limits of `put_file` and `get_to_file` (`src/broker/http.rs`, unit C1): 30 s without a byte fails, 15 min in total.

### 1.1 Transport

As v1 section 1. In addition:

- The jobs upload and the result download use the same mechanics as the head set routes, so that the client needs no new transport: one `application/octet-stream` body with `Content-Length`, a manifest in the `Apassy-Manifest` header (base64url without padding, at most 16 KiB encoded), and `Expect: 100-continue` (v1 section 5); a download is one octet-stream body whose SHA-256 the client checks while it reads. No route of v2 uses `multipart/form-data`.
- A JSON request body of v2 (sections 5 and 7) is at most 8 KiB. A JSON answer of v2 is at most 64 KiB with its headers (the client cap of `request_json`).
- Bearer tokens are as in v1: `Authorization: Bearer <token>`, compared in constant time.

### 1.2 Two server modes

| Mode | When | Owner | Credential |
| --- | --- | --- | --- |
| Own server | `APASSY_BRAIN_CONNECT_DIRECTORY` is not set (default) | One owner: the holder of `LAYA_API_KEY` | The static bearer of v1 section 1 |
| Connect server | `APASSY_BRAIN_CONNECT_DIRECTORY` is set | One owner for each Connect account | The token of the sign-in of section 5 |

- An own server works as v1: the routes that write, also the job routes, are served only when the server has a token, else 403 `no_token`. It has no sign-in routes (404).
- A Connect server refuses to start without `APASSY_BRAIN_ORIGIN` (its public origin, I-5) and without the service token of section 7. `LAYA_API_KEY` is not an owner credential on a Connect server: a bearer that is not a live sign-in token gives 401 `unauthenticated`, also when it equals `LAYA_API_KEY`. On a Connect server the routes that write are served for every signed-in owner, so `no_token` never occurs there.
- The account token of Connect (the token of `POST /v1/account/token`) is never sent to the bouncer brain (I-2). The client MUST NOT put it in any request of this contract. The brain issues its own token after the device-key sign-in.

### 1.3 Errors

The error body of v1 section 1: `{"detail": {"code": "...", "message": "..."}}`. The client acts on the status code. A `message` never contains request data: no hash, no account id, no key id, no example text. The codes of v1 keep their meaning. New codes:

| Code | Status | Meaning |
| --- | --- | --- |
| `unauthenticated` | 401 on a Connect server, every route except `GET /health` and section 5 | A missing, unknown, expired or revoked token |
| `sign_in_failed` | 401 on `POST /v1/sign-in` | The sign-in failed: one code and one message for every cause (section 5.3) |
| `not_entitled` | 403 on a Connect server | The plan of the owner does not include hosting (sections 3 and `heads` routes) or training (section 4) |
| `bad_request` | 400 on sections 5 and 7 | A body that is not JSON, has an unknown field, or breaks an encoding of section 5 |
| `rate_limited` | 429 on `POST /v1/sign-in/challenge` | More than 4 open nonces for the key; `Retry-After: 60` |
| `busy` | 503 on section 5, and on `PUT /v1/train/<sha256>` | The nonce table is full, or the directory of section 7.1 did not answer; `Retry-After: 2`. On a job upload, before the body: 2 uploads stage already, or the disk lacks room for this body, the bodies that stage, and 512 MiB more. Nothing is added |
| `bad_job` | 400 on `PUT /v1/train/<sha256>`; 422 on a malformed `<sha256>` in a path of section 4 | An upload that does not match its path or its manifest, a manifest that breaks section 4.2, or counts under the training gate |
| `unknown_job` | 404 on `GET` and `DELETE /v1/train/<sha256>` and `GET /v1/train/<sha256>/result` | The owner has no job with this id |
| `job_busy` | 409 on `PUT /v1/train/<sha256>` | The owner already has a `queued` or `running` job with another id. Nothing is added |
| `job_not_done` | 409 on `GET /v1/train/<sha256>/result` | The job is not `done`, or its result was deleted |

`too_large` (413), `heads_full` (409), `no_token` (403) and `bad_heads` keep the v1 meaning and also apply to the job routes as section 4 says.

## 2. `GET /health`

No token, as v1. Two new fields; a v1 client ignores them:

```json
{"status": "ok", "loaded": ["english"], "device": "cpu", "contract": "bouncer-brain-v2", "jobs": true, "sign_in": false}
```

- `contract`: `"bouncer-brain-v2"`. A server without the field speaks v1.
- `jobs`: the server serves the routes of section 4. A server that cannot train (no trainer, `tools/finetune/local_train.py` missing) answers `false` and 404 on those routes.
- `sign_in`: the server is a Connect server (section 1.2) and serves section 5.

The health answer is still never a model answer (v1 section 2).

## 3. `POST /v1/systemone` and the head set routes

Unchanged from v1 sections 3 to 6, with the owner namespace of section 6:

- On a Connect server, `heads` and `shadow_heads` name head sets of the signed-in owner or the server's default head set. A head set of another owner is unknown: 409 `unknown_heads`, and `shadow.error: "unknown_heads"` for a shadow.
- On a Connect server these routes need the hosting entitlement of the token (section 5.4); without it they answer 403 `not_entitled`. `DELETE /v1/heads/<sha256>` and `DELETE /v1/owner` need no entitlement: an owner can always delete.
- `PUT /v1/heads/<sha256>` on a Connect server answers 409 `heads_full` when the owner already stores 4 head sets (section 6.2).

## 4. Training jobs

A job trains the heads on the server with `tools/finetune/local_train.py`, from the examples of one upload. The job id is the SHA-256 of the upload body: 64 lowercase hex characters. Token required (section 1.2); on an own server without a token every route of this section answers 403 `no_token`; on a Connect server they need the training entitlement (403 `not_entitled`), except `GET` and `DELETE /v1/train/<sha256>`, which an owner can always use.

### 4.1 `PUT /v1/train/<sha256>`: start a job

The upload of one job: `put_file` of C1 with the job body and the job manifest.

- Body: `train.jsonl` then `val.jsonl`, the two example files of [fine-tune.md](../operations/fine-tune.md) section 6.1 step 4, unchanged and in this order, without a separator: the bytes of `train.jsonl` are the first `files.train.size_bytes` bytes of the body, the bytes of `val.jsonl` the rest. `Content-Type: application/octet-stream`, `Content-Length` always. At most 64 MiB.
- Header `Apassy-Manifest`: the job manifest of section 4.2, base64url without padding, at most 16 KiB encoded. It carries the counts of `stats.json`, so `stats.json` is not in the body; the server writes it for the trainer.
- `Expect: 100-continue`, and no body byte before `100 Continue`, as v1 section 5. The server answers 400, 401, 403, 409 and 413 before it reads the body when the path, the manifest, the declared length, the token, the entitlement or `job_busy` is wrong.
- If the connection closes during the upload, the result is unknown: the client checks with `GET /v1/train/<sha256>`. PUT is idempotent: the same body gives the same job.

The server MUST check, before it starts anything:

1. the SHA-256 of the body equals the path;
2. `files.train.size_bytes + files.val.size_bytes` equals the body size, and the SHA-256 of each part equals its `sha256`;
3. `base.revision` and `base.weights_sha256` equal the base of the server (the job trains from that base, so the result runs wherever that base runs);
4. `name` follows the name rule of v1 section 3.2;
5. `stats.owner_decisions` is at least 300 and `stats.owner_denials` at least 30 (the training gate, `src/broker/finetune.rs:43-45`); `stats.train` and `stats.val` are not 0. The trainer checks the counts again (`local_train.py`).

Then it writes `train.jsonl`, `val.jsonl` and `stats.json` to a new folder with mode `0700` (files `0600`) that only this job reads, and the job is `queued`.

| Status | Body | When |
| --- | --- | --- |
| 201 | the job (section 4.3) | The job is new |
| 200 | the job | The owner already has a job with this id that is not `deleted` (idempotent; nothing changes, also when it `failed`: the client deletes a failed job before it uploads the same body again) |
| 400 | `bad_job` | A check above fails, or the manifest header is not base64url of a JSON object of section 4.2 |
| 401 | v1's body, or `unauthenticated` | The token is missing or wrong |
| 403 | `no_token` or `not_entitled` | Section 1.2 |
| 409 | `job_busy` | The owner has a `queued` or `running` job with another id |
| 413 | `too_large` | The declared body length is over 64 MiB, or the encoded manifest header is over 16 KiB |
| 422 | `bad_job` | The path is not 64 lowercase hex characters |

A `deleted` job with the same id is replaced by the new upload (201).

### 4.2 The job manifest

```json
{
  "schema": 1,
  "kind": "apassy-train-job-v1",
  "name": "apassy-remote-v1",
  "base": {"revision": "<40 hex>", "weights_sha256": "<64 hex>"},
  "files": {
    "train": {"size_bytes": 41213, "sha256": "<64 hex>"},
    "val": {"size_bytes": 9204, "sha256": "<64 hex>"}
  },
  "stats": {"owner_decisions": 340, "owner_denials": 40, "train": 540, "val": 60},
  "keep_heads": false
}
```

- `kind` is always `"apassy-train-job-v1"`: a head set manifest is never a job manifest, and the reverse.
- `name` is the name of the result (`<name>+<first 8 hex>`, v1 section 3.2).
- `stats` is the object of `finetune::ExampleStats` (`src/broker/finetune.rs:187`): every value is a non-negative integer, and it MUST have `owner_decisions`, `owner_denials`, `train` and `val`. It has counts only, never request data.
- `keep_heads`: `true` when the owner hosts the bouncer brain at the same server. Then the server also stores the result as a head set of the owner at the job end, with the checks and the limit of `PUT /v1/heads` (section 6.2), and `result.stored` says whether it did. The job result itself is still deleted after the download (section 4.5).
- The client sends no other field (v1 section 9). The server refuses a manifest without one of these fields, or with a field of the wrong type (400 `bad_job`); it ignores fields that it does not know.

### 4.3 `GET /v1/train/<sha256>`: the state of a job

Status 200; 404 `unknown_job`; 422 `bad_job` for a malformed path. The same object is the body of the 201 and 200 of section 4.1:

```json
{
  "job": "<64 hex>",
  "state": "done",
  "created_at": 1790000000,
  "started_at": 1790000004,
  "ended_at": 1790000412,
  "examples_held": false,
  "examples_deleted_at": 1790000412,
  "examples_deadline": 1790086400,
  "result_deadline": 1790605212,
  "error": null,
  "result": {"heads": "<64 hex>", "model": "apassy-remote-v1+<8 hex>", "size_bytes": 104996060, "stored": false, "manifest": {}, "metrics": {}}
}
```

| State | Meaning | `examples_held` | `result` | `error` |
| --- | --- | --- | --- | --- |
| `queued` | Waits for the trainer: one job per server runs at a time, and a job starts only when the server has its memory limit free (plan 0035 K1) | `true` | `null` | `null` |
| `running` | The trainer runs | `true` | `null` | `null` |
| `done` | The trainer finished and the result passed the checks of section 4.4 | `false` | the result | `null` |
| `failed` | The job ended without a result | `false` | `null` | a code below |
| `deleted` | The owner deleted the job (section 4.6), or its result deadline passed | `false` | `null` | `null` |

- Times are Unix seconds. `started_at`, `ended_at` and `examples_deleted_at` are `null` until they happen. `examples_deadline` is always `created_at + 86400`. `result_deadline` is `ended_at + 604800` for a `done` job, else `null`.
- The answer has no example data: no state text, no command, no answer of the trainer except the numbers of `result.metrics`.
- `error` of a `failed` job: `training_failed` (the trainer exited with an error), `deadline` (the trainer passed its deadline: 2 × the measured job time, at most 3 h, plan 0035 K1), `expired` (the job was still `queued` at `examples_deadline`), `interrupted` (the server stopped during the job), `bad_result` (the output failed section 4.4). The client treats any other value as `training_failed`.
- A server keeps the state of a `failed` or `deleted` job for 7 days, then the id is unknown (404).

### 4.4 The result

`result` of a `done` job:

- `heads`: the SHA-256 of the head file of the job (`candidate.safetensors`).
- `model`: `<name>+<first 8 hex of heads>`, the name of the job manifest.
- `size_bytes`: the size of the head file.
- `manifest`: the `manifest.json` that `local_train.py` wrote (the layout of v1's fixture `manifest.json`), with `checkpoint.sha256 = heads`, `checkpoint.size_bytes = size_bytes`, `version = model`, and the base of the server. Its compact JSON is at most 12 KiB, so that the client can send it as an `Apassy-Manifest` header of `PUT /v1/heads` (16 KiB encoded) to any host.
- `stored`: with `keep_heads`, whether the head set was stored for the owner (false when the limit of section 6.2 was full); `false` without `keep_heads`.
- `metrics`: an object of finite numbers, or objects of finite numbers, from the trainer's `result.json` (for example `train_seconds`, `train_examples`, `val_examples`, `best_epoch`). The client ignores keys that it does not know. Never a string.

The server checks the output before `done`, as `read_result` (`src/broker/finetune.rs:836`) does on the Mac: the version is `<name>+<first 8 hex>`, the head file has that SHA-256, and the manifest has the server's base. It never sends the trainer's own `result.json`: that file has absolute paths of the server. The client writes its own `result.json` from `result` for the unchanged `read_result` check.

### 4.5 `GET /v1/train/<sha256>/result`: the head file

Status 200 with the head file as `application/octet-stream` and its `Content-Length` (C1 `get_to_file`, which checks the SHA-256 against `result.heads` while it reads, and refuses a body over 256 MiB). 404 `unknown_job`; 409 `job_not_done` for a job that is not `done`; 422 `bad_job` for a malformed path. The route never answers with another file.

**The result is deleted after the download.** The client downloads the head file, checks its SHA-256 and the manifest, registers the candidate in shadow mode, and then sends `DELETE /v1/train/<sha256>`; the server deletes the head file and the manifest of the job at once. If the client never deletes the job, the server deletes the result at `result_deadline` (7 days after the end: chosen by this contract; the owner can change it), and the job becomes `deleted`. A head set that `keep_heads` stored is a head set of the owner (section 6), not a job result: it stays until the owner deletes it or `DELETE /v1/owner`.

### 4.6 `DELETE /v1/train/<sha256>`

204. It stops a `queued` or `running` job (its process ends), and deletes its examples and its result. The job becomes `deleted`. A `deleted` job gives 204 again (idempotent). 404 `unknown_job`; 422 `bad_job` for a malformed path.

### 4.7 The rules of a job

- **One job per owner at a time.** A second upload with another id while a job of the owner is `queued` or `running` gives 409 `job_busy`. One job per server runs at a time; others stay `queued`.
- **The examples are deleted when the job ends**: at `done`, `failed` and `deleted`, before the state changes, and at the latest at `examples_deadline` (24 hours after the upload), whatever the state. The deletion removes the job folder with `train.jsonl`, `val.jsonl`, `stats.json` and every file of the trainer except the result.
- A job reads only its own folder. The server MUST NOT log an example, a state, a question or an answer of a job; it may log the job id (first 8 hex), counts, times, states and error codes.
- The result of a job starts in shadow mode on the Mac (section 1). The server never makes it the head set of a request.

## 5. Connect sign-in

Only on a Connect server (`sign_in: true` in section 2); an own server answers 404. The device key is the account device key of the Connect plan (I-1): one P-256 key for each device, enrolled in the Connect account. The sign-in follows the device sign-in of [relay-sync-v1](relay-sync-v1.md) section 5 with its own domain tag, and the encodings of relay-sync-v1 section 2: b64u, an X9.63 public key of 65 bytes, an ECDSA P-256 SHA-256 signature in DER of at most 72 bytes. Both calls take no `Authorization` header; a server ignores one.

### 5.1 `POST /v1/sign-in/challenge`

Request:

```json
{"account": "acc_7k2m5q4x3c", "key_id": "key_4n6p2r7s5t", "public_key": "<b64u of 65 bytes>"}
```

Answer 200:

```json
{"nonce": "<b64u of 32 bytes>", "expires_at": 1790000060, "origin": "https://brain.connect.example.test"}
```

- The nonce is 32 random bytes, bound to the account, the key id and the public key of the request. It works once and lives 60 seconds. At most 4 nonces are open for one public key: a fifth gives 429 `rate_limited`. A full nonce table gives 503 `busy`.
- `origin` is the server's `APASSY_BRAIN_ORIGIN`. **The client MUST compare it with its own brain origin, the build constant of I-5, byte for byte (both without a trailing slash), and MUST stop when they differ**, without a signature and without a second call. It never takes the origin from a server answer.
- The challenge does not ask the directory. It answers the same for every well-formed request, so it does not show whether a key is enrolled. A malformed body gives 400 `bad_request`.

### 5.2 `POST /v1/sign-in`

Request:

```json
{"account": "acc_7k2m5q4x3c", "key_id": "key_4n6p2r7s5t", "public_key": "<b64u>", "nonce": "<b64u>", "signature": "<b64u DER>"}
```

The signature is over these bytes, joined with `\0` (one zero byte), with no newline and no trailing `\0` (the form of `sign_in_message`, `src/sync/relay_crypto.rs:380`, with the account id in the place of the team id):

```
"apassy-bouncer sign-in v1" 0x00 <origin> 0x00 <account> 0x00 <public key b64u> 0x00 <nonce b64u>
```

- `origin` is the client's own brain origin (I-5). The server verifies the signature with its own `APASSY_BRAIN_ORIGIN`, never with a value of the request: a signature for one origin fails at every other origin.
- The tag `apassy-bouncer sign-in v1` is used for this message only. `connect::sign` (I-1) signs it only from its allow-list. A signature with the relay tag (`apassy-relay sign-in v1`) or the Connect account tag (`apassy-connect sign-in v1`) never verifies here, and a signature of this tag never verifies there.
- The server checks, in this order: the nonce is open, unexpired and bound to the same account, key id and public key; the nonce is then used, whatever the result; the signature verifies with `public_key`; the directory (section 7.1) knows `key_id` with the SHA-256 of `public_key`, names the same `account`, and `revoked` is false.

Answer 200:

```json
{"token": "apassy_brn_<64 hex>", "expires_at": 1790000960, "account": "acc_7k2m5q4x3c", "hosting": true, "training": false}
```

- `token`: `apassy_brn_` and 64 lowercase hex characters, 32 random bytes. It lasts 15 minutes (`expires_at`).
- `hosting` and `training`: the entitlements of the directory at the sign-in (`entitled_hosting`, `entitled_training`).

### 5.3 Errors of the sign-in

- `POST /v1/sign-in` answers 401 `sign_in_failed` for every failed check of section 5.2: an unknown, used or expired nonce, a nonce of another key, a wrong signature, a key that the directory does not know, a revoked key, another account. One message for every cause: `"the sign-in failed"`.
- A directory that does not answer within 5 s, or answers with a status other than 200 or 404, gives 503 `busy`, and the nonce is used.
- A malformed body (not JSON, an unknown field, a wrong encoding, a key that is not 65 bytes from `0x04`, a signature over 72 bytes) gives 400 `bad_request`.
- The client treats every status other than 200 as unavailable for the request in progress (v1 section 3.4).

### 5.4 The token

- The server keeps tokens in memory only: never on disk, never in a log. A restart of the server ends every token. The client keeps its token in memory only (a `Zeroizing` buffer), never on disk or in the vault.
- A token belongs to one account, one key id and its entitlements of the sign-in. Every route except `GET /health` and section 5 needs it on a Connect server; a missing, unknown, expired or revoked token gives 401 `unauthenticated`. A route that needs an entitlement that the token does not have gives 403 `not_entitled`.
- The client signs in when it has no token or less than 60 s of it are left, inside the 20 s deadline of the request (C3). A 401 drops the token (`BrainCredential::invalidate` of C1): the request that got it is unavailable and is never sent again with a new token; the next request signs in again.
- A revoke event (section 7.2) ends the tokens of the key at once. A forget event ends the tokens of the account at once. A changed plan reaches the brain at the next sign-in, at the latest after 15 minutes, or at once through a forget event.

## 6. Owner namespaces

### 6.1 Who owns what

- Own server: one owner. Every uploaded head set and every job belong to it. The limit of v1 (`APASSY_HEADS_MAX`, default 16 head sets) stays.
- Connect server: every head set, job and limit belongs to the signed-in account of the token. A route never reads, uses, lists, changes or deletes a head set or a job of another account. For another account's id or hash the answer is the same as for an id or hash that does not exist (404 `unknown_heads`, 409 `unknown_heads`, 404 `unknown_job`), so a route does not show whether another owner has it. Two owners can upload the same head file; each has its own entry, and a deletion by one does not touch the other. A server may store identical files once on its disk when the deletion rules of every owner still hold.
- The server's default head set belongs to no owner: every owner can use and `GET` it (`default: true`), nobody can delete it (409 `default_heads`), and it counts for no limit.

### 6.2 Limits on a Connect server

- At most 4 stored head sets for each owner: the active one, a shadow, the previous one, and one spare (chosen by plan 0035; the owner can change it). A fifth `PUT /v1/heads/<sha256>` gives 409 `heads_full` and adds nothing; the client deletes the oldest replaced head set first (unit G).
- One job for each owner at a time (section 4.7).
- The memory limits of the inference and the job containers come from plan 0035 K1, not from this contract.

### 6.3 `DELETE /v1/owner`

Token required; on an own server without a token, 403 `no_token` (as v1). It deletes, for the owner of the token: every uploaded head set, every job (a `queued` or `running` job stops), every example, and every job result. The server's default head set stays. Answer 200:

```json
{"deleted": {"heads": 2, "jobs": 1, "examples": 1}}
```

- `heads`: the head sets deleted; `jobs`: the jobs deleted, in any state but `deleted`; `examples`: the jobs whose examples were still held and are now deleted. All are non-negative integers. The app shows them ("Delete my data at Apassy", unit C3).
- After the answer, nothing of the owner stays: no head file, no manifest, no cache entry, no job folder, no example, no result. A `GET` of a deleted head set gives 404, a request with its hash 409, a `GET` of a deleted job 404.
- A Connect token stays valid: the owner is still a customer. The forget event (section 7.2) also ends the tokens.
- A repeated call answers 200 with zeros.

## 7. Connect internal interface

Only on a Connect server. The internal routes listen on a separate address (`APASSY_BRAIN_INTERNAL_ADDR`) on the internal network of the Connect host, never on the public origin: the public listener answers 404 for every path under `/internal/`. Every internal call needs `Authorization: Bearer <service token>`; the service token is in the compose secrets (I-3), not in this contract, and a wrong one gives 401. The bodies are JSON, at most 8 KiB.

### 7.1 Directory: the brain calls Connect (I-3)

`POST /internal/v1/brain/device` at Connect, at each sign-in of section 5.2, with a deadline of 5 s:

```json
{"key_id": "key_4n6p2r7s5t", "public_key_sha256": "<64 hex>"}
```

Answer 200:

```json
{"account": "acc_7k2m5q4x3c", "entitled_hosting": true, "entitled_training": false, "revoked": false}
```

`account` is an opaque id. 404 when Connect knows no such key with this public key. The brain sends nothing else to Connect: no head hash, no job, no request data.

### 7.2 Events: Connect calls the brain (I-4)

- `POST /internal/v1/revoke` with `{"key_id": "key_4n6p2r7s5t"}`: a device key was revoked. Every token of the key ends at once. Answer 200 `{"tokens": 1}` (the number of tokens that ended).
- `POST /internal/v1/forget` with `{"account": "acc_7k2m5q4x3c"}`: the plan ended or the account was deleted. The effect of `DELETE /v1/owner` for the account, and every token of the account ends. Answer 200 `{"deleted": {"heads": 2, "jobs": 1, "examples": 1}, "tokens": 1}`.

Both are idempotent: a repeated event answers 200 with zeros. Connect retries until it gets a 2xx.

## 8. Rules

v1 section 8 applies, and:

- The server MUST NOT log the token, the service token, a nonce, a signature, a public key, an account id or a key id in clear. It may log the first 8 hex of a job id or head hash, counts, latency, status codes and error codes.
- The client MUST NOT send the Connect account token (I-2), a vault credential, the vault path, or the full path of the project or the home folder in any request of this contract. The examples of a job are the state of v1 section 8 only, as in `finetune::examples_from_export`, which shortens those paths as the broker does.
- A failed or stopped job leaves no example on the server. The 24-hour rule of section 4.7 holds also when the trainer, the sweeper or the server crashed: the server runs the sweep at its start.

## 9. Versioning

v1 section 9 applies. A v2 client sends only the fields of this contract; a v2 server ignores the request fields that it does not know, also in a job manifest; every client ignores answer fields that it does not know. A change of a route, a status code, an error code, a hash rule, the sign-in message, or the meaning of a field needs a new version (`bouncer-brain-v3`) and a change on each side.

## 10. Fixtures

`tests/fixtures/bouncer-brain-v2/` holds synthetic examples. Every hash, key, nonce, token and id in them is synthetic; the public key and the nonce are the test vectors of relay-sync-v1 section 15. No fixture holds a secret value, an example text or an absolute path.

| File | What |
| --- | --- |
| `health.json` | 200 body of `GET /health` on an own server with jobs |
| `job-manifest.json` | The `Apassy-Manifest` of `PUT /v1/train/<sha256>` |
| `job-queued.json` | 201 body of `PUT /v1/train/<sha256>` |
| `job-running.json` | 200 body of `GET /v1/train/<sha256>`, running |
| `job-done.json` | 200 body of `GET /v1/train/<sha256>`, done, with the result |
| `job-failed.json` | 200 body of `GET /v1/train/<sha256>`, failed |
| `job-deleted.json` | 200 body of `GET /v1/train/<sha256>` after `DELETE` |
| `owner-deleted.json` | 200 body of `DELETE /v1/owner` |
| `sign-in-challenge-request.json` | Request of `POST /v1/sign-in/challenge` |
| `sign-in-challenge.json` | 200 body of `POST /v1/sign-in/challenge` |
| `sign-in-request.json` | Request of `POST /v1/sign-in`. Its signature is the relay-sync-v1 vector of the relay sign-in message: it must verify as a relay sign-in and never as a brain sign-in. The test signs a brain message with the vector key |
| `sign-in.json` | 200 body of `POST /v1/sign-in` |
| `directory-request.json`, `directory-answer.json` | Section 7.1 |
| `revoke-request.json`, `revoke.json`, `forget-request.json`, `forget.json` | Section 7.2 |
| `error-job-busy.json`, `error-unknown-job.json`, `error-not-entitled.json`, `error-sign-in-failed.json`, `error-unauthenticated.json` | Error bodies |

`tests/bouncer_brain_contract.rs` (module `v2`) parses each fixture with the strict rules of the client (unknown fields refused in what the client sends), and checks the hash, version, name, state, time, 24-hour and 7-day rules, the job manifest checks of section 4.1, the code table, the messages without request data, and the sign-in message bytes and their domain separation (with the `vault` feature, a signature with the test key of relay-sync-v1 section 15).
