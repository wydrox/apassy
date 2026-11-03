# Bouncer brain wire contract v1

Date: 2026-11-02.
Status: frozen for wave 1 of [implementation plan 0035](../design/implementation-plan-0035.md) (unit A). Unit D1 implements the server side in `tools/basemodel/`; units C, F and G implement the client side in Apassy. Not implemented yet. Fixtures: `tests/fixtures/bouncer-brain-v1/`, checked by `tests/bouncer_brain_contract.rs`.
Decision: [ADR 0035](../adr/0035-bouncer-hosting-and-training-choice.md).
Version 2 ([bouncer-brain-v2](bouncer-brain-v2.md), 2026-11-03) adds the training jobs, the Connect sign-in and owner namespaces that section 1 and 7 reserve. It does not change this version for existing clients: every route, field, status and code below keeps its meaning on a v2 server (v2 section 1).

Words ([bouncer.md](../operations/bouncer.md), Words): the **bouncer brain** is the model server. It gives a probability for each question. The **bouncer gate** is the decision in Apassy on the Mac. It turns those answers into "run" or "ask the owner". This contract is the protocol between the two. The owner's server and the Apassy Connect service use the same protocol; only the address and the credential are different. MUST/MUST NOT below are implementation requirements.

## 1. Transport and authorization

- HTTP/1.1 with JSON bodies (`Content-Type: application/json`), except the head upload of section 5.
- The client MUST use `http://` only for a loopback address (`127.0.0.0/8`, `::1`, `localhost`). Every other address MUST use `https://`. The client MUST refuse an `http://` address that is not loopback before it sends a byte.
- A server that listens on an address other than loopback MUST have a token; it refuses to start without one. The client MUST NOT send a request to a non-loopback address without a credential. Tailscale gives reachability only.
- When the server has a token (`LAYA_API_KEY`), every route that it serves, except `GET /health`, requires `Authorization: Bearer <token>`. A missing or wrong token gives 401. The server compares the token in constant time.
- The routes that write (`PUT /v1/heads/<sha256>`, `DELETE /v1/heads/<sha256>`, `DELETE /v1/owner`) are served only when the server has a token. Without a token they answer 403 `no_token`.
- A route that the server does not serve answers 404 whatever the token.
- The token of an owner's server is in the vault on this Mac only. It does not sync.
- Reserved for a later version: the Apassy Connect sign-in. It is a challenge/token flow with a device key ([ADR 0019](../adr/0019-relay-teams-and-accounts.md) section 5) and its own domain tag `apassy-bouncer sign-in v1`. Version 1 defines only the name. A version 1 server and client MUST NOT use this tag for anything else.

Error bodies. The codes of this contract use one shape, the same as today's 422 `input_too_long` of `tools/basemodel/serve.py`:

```json
{"detail": {"code": "unknown_heads", "message": "the head set is not on this server"}}
```

The existing laya errors (400 bad JSON, 401, 413 body too large, 422 question validation, 500) can have a string `detail`. The client MUST NOT need the `detail` to act on an error: the status code is enough. A `message` never contains request data, also not the requested hash.

| Code | Status | Meaning |
| --- | --- | --- |
| `unknown_heads` | 409 on `POST /v1/systemone`; 404 on `GET` and `DELETE /v1/heads/<sha256>` | The server has no head set with this hash |
| `bad_heads` | 422 on `POST /v1/systemone` and on a path of `GET` or `DELETE`; 400 on `PUT /v1/heads/<sha256>` | A malformed hash, or an upload that does not match its path, manifest or the server's base |
| `default_heads` | 409 on `DELETE /v1/heads/<sha256>` | The server's default head set cannot be deleted |
| `input_too_long` | 422 on `POST /v1/systemone` | Today's rule of `serve.py`: the state does not fit the encoder |
| `too_large` | 413 on `PUT /v1/heads/<sha256>` | The declared body length is over 160 MiB or the encoded manifest header is over 16 KiB |
| `no_token` | 403 on `PUT /v1/heads/<sha256>`, `DELETE /v1/heads/<sha256>` and `DELETE /v1/owner` | The server has no token, so it does not serve the routes that write |
| `heads_full` | 409 on `PUT /v1/heads/<sha256>` | The server stores no more head sets (`APASSY_HEADS_MAX`, default 16); the owner deletes one first. Nothing is added |
| `shadow_failed` | in `shadow.error` only | A known shadow head set failed during the computation, for example for lack of memory, a non-finite value, or an answer over the size cap (section 8). The active answers stay |

## 2. `GET /health`

No token. The answer is laya's existing shape:

```json
{"status": "ok", "loaded": ["english"], "device": "mps"}
```

`loaded` is a list of strings. `device` is a string. The client uses this route only to see that the server is up. It MUST NOT treat a health answer as a model answer.

## 3. `POST /v1/systemone`

### 3.1 Request

Today's laya body, plus two optional fields:

| Field | Form | Meaning |
| --- | --- | --- |
| `state` | string or object | The state of ADR 0007 (section 8). The Apassy client sends the string of `bouncer::state_text` |
| `questions` | object: `<id>: {"type": "noul", "instructions": "..."}` | The questions of `bouncer::questions()` that this request needs |
| `heads` | optional; 64 lowercase hex characters | The SHA-256 of the active head file (today's `checkpoint.sha256` of its manifest) |
| `shadow_heads` | optional; 64 lowercase hex characters | The SHA-256 of a shadow head file |

`"heads": null` and `"shadow_heads": null` count as absent. Without `heads`, the server uses its default head set. Old clients keep working.

### 3.2 Answer

Status 200. Today's laya answer, plus `heads` and, when the request had `shadow_heads`, `shadow`:

```json
{
  "model": "apassy-local-v1+a1b2c3d4",
  "heads": "a1b2c3d4e5f60718...",
  "answers": {"task_match": {"type": "noul", "noul": 0.91}},
  "usage": {"input_tokens": 412, "output_tokens": 0},
  "routing": {"model": "english"},
  "shadow": {"heads": "0badc0de13572468...", "model": "apassy-local-v1+0badc0de", "answers": {"task_match": {"type": "noul", "noul": 0.88}}}
}
```

- `model` is the version of the head set that answered: `<manifest.name>+<first 8 hex of its SHA-256>` (section 5). The name starts with a letter or digit, has only letters, digits, `.`, `_` and `-`, and has at most 55 characters, so `<name>+<8 hex>` has at most 64 bytes (`vault::MAX_MODEL_VERSION`).
- `heads` is the SHA-256 of the head set that answered. When the request had `heads`, the server MUST answer with exactly that head set or not at all.
- `answers.<id>.noul` is a number in `0..=1` for each question of the request. Non-finite numbers (NaN, infinity) never appear in an answer: a shadow with a non-finite value becomes `shadow.error: "shadow_failed"`, and an active answer with a non-finite value is a 500 (section 3.3). The other fields of an answer (`confidence`, `answer_confidence`, `action`) and `usage` and `routing` are laya's; the client ignores them.
- When the request had `shadow_heads`, `shadow` is one of:
  - `{"heads": "<hex>", "model": "<version>", "answers": {...}}`: the answers of the shadow head set, for the same questions;
  - `{"heads": "<hex>", "error": "unknown_heads"}`: the server has no such head set;
  - `{"heads": "<hex>", "error": "shadow_failed"}`: the shadow head set is known, but its answers failed or do not fit (section 8).
- The shadow answer MUST come from the same request (one encoder pass, as the stock `leak` heads of `serve.py` today). A shadow head set MUST NOT make the request fail: an unknown shadow head set gives `shadow.error`, and the active `answers` stay. Version 1 defines the errors `unknown_heads` and `shadow_failed`; the client treats any `shadow.error` as "no answer" for the shadow head set.

### 3.3 Errors

- An unknown active `heads` gives 409 `unknown_heads`. The server MUST NOT answer with another head set instead.
- A malformed `heads` or `shadow_heads` (not 64 lowercase hex characters) gives 422 `bad_heads`. This is a client defect, not a shadow failure: the client MUST check both hashes before it sends them.
- A state that does not fit gives 422 `input_too_long`, as today.
- An active answer with a non-finite value (NaN, infinity) gives 500.

### 3.4 What the bouncer gate does with the answer

The bouncer gate treats each of these as "unavailable", and asks the owner:

- a transport error, a timeout, or any status other than 200 (also 401, 409, 422);
- a body that is not JSON, or a response larger than 64 KiB with its headers (section 8);
- a missing or invalid `answers.<id>.noul` for a question of the request;
- a `model` that is not the pinned version of the active head set;
- a `heads` that differs from the `heads` that the client sent.

A client that has a heads pin sends it as `heads` and treats an answer whose `heads` differs as unavailable. A client without a heads pin sends no `heads` and checks `model` only.

Unavailable is never an allowance. For the shadow head set the same checks apply to `shadow`. A failed shadow check records "no answer" for the shadow head set. It never changes the active decision.

## 4. `GET /v1/heads/<sha256>`

Token required when the server has one (section 1). Status 200:

```json
{"heads": "<hex>", "model": "<version>", "size_bytes": 104996060, "default": false}
```

`default` is true for the server's default head set (section 3.1). 404 `unknown_heads` when the server has no such head set. 422 `bad_heads` when the path is not 64 lowercase hex characters.

## 5. `PUT /v1/heads/<sha256>`

Token required. Served only when the server has a token; without one, 403 `no_token` (section 1). The upload of one head set.

- Body: the head file (`candidate.safetensors`), `Content-Type: application/octet-stream`, with its length in `Content-Length`. At most 160 MiB. A server may also accept a body without `Content-Length` (chunked); the same limit applies while it reads.
- Header `Apassy-Manifest`: the bytes of its `manifest.json`, base64url without padding. The encoded `Apassy-Manifest` header is at most 16 KiB.
- The client MUST send `Expect: 100-continue` and MUST NOT send the body before `100 Continue`. A final response that arrives instead is the answer, and the client stops sending. The server answers 400, 401, 403 and 413 before it reads the body when the path, the header, the manifest or the declared length is wrong.
- If the connection closes during the upload, the result is unknown: the client checks with `GET /v1/heads/<sha256>`; PUT is idempotent, so the client may send it again.
- The server MUST check, before it stores anything:
  1. the SHA-256 of the body equals the path;
  2. `manifest.checkpoint.sha256` equals the path;
  3. `manifest.checkpoint.size_bytes` equals the body size;
  4. `manifest.base.revision` and `manifest.base.weights_sha256` equal the base of the server;
  5. `manifest.name` follows the name rule of section 3.2.
- Then it stores the head file and the manifest atomically (a temporary file and a rename), files with mode `0600` in a directory with mode `0700`.
- The `model` version of the stored head set is `<manifest.name>+<first 8 hex of the sha256>`.

| Status | Body | When |
| --- | --- | --- |
| 201 | `{"heads": "<hex>", "model": "<version>"}` | The head set is new |
| 200 | the same | The head set is already there (idempotent; nothing changes) |
| 400 | `bad_heads` | Any check above fails, or the manifest header is not base64url of a JSON object |
| 401 | laya's existing body | The token is missing or wrong |
| 403 | `no_token` | The server has no token |
| 409 | `heads_full` | The server already stores its maximum number of head sets |
| 413 | `too_large` | The declared body length is over 160 MiB or the encoded manifest header is over 16 KiB |

The server checks the files as `verify` in `serve.py` does today. The server has no promotion: an upload does not make a head set active. The client chooses the head set of each request with `heads`.

## 6. Deletion

- `DELETE /v1/heads/<sha256>`: token required; without a token on the server, 403 `no_token` (section 1). 204 when deleted. 404 `unknown_heads` when the server has no such head set. 409 `default_heads` for the server's default head set. 422 `bad_heads` for a malformed path.
- `DELETE /v1/owner`: token required; without a token on the server, 403 `no_token`. 204. It deletes every head set that the owner uploaded. The default head set of the server stays. In version 1 a server has one owner, and there are no jobs; per-owner namespaces come with Apassy Connect.

After a 204, a `GET` of a deleted head set gives 404, and a request with its hash gives 409.

## 7. Training jobs

**Planned (stage 4), not served in version 1. Version 1 servers answer 404 on these routes.** This section gives only the intent; [bouncer-brain-v2](bouncer-brain-v2.md) section 4 defines the routes.

- `POST /v1/train` starts a job. The three files of [fine-tune.md](../operations/fine-tune.md) section 6.1 step 4 go up: `train.jsonl`, `val.jsonl` and `stats.json`.
- `GET /v1/train/<id>` gives the state of the job.
- `GET /v1/train/<id>/result` gives the result: `result.json`, the head file (`candidate.safetensors`) and its `manifest.json`.
- The server deletes the examples when the job ends, and at the latest 24 hours after the upload.
- The head set of a job starts in shadow mode on the Mac, as every other new head set (section 8).

A later version defines the bodies, the limits and the states.

## 8. Rules

- The client MUST NOT send a secret value, the vault path or an absolute project path. The `state` is the state of ADR 0007 only: the user request, the command, the directory relative to the project, the purpose, the environment variable names and the owner rule.
- The server MUST NOT log the `state`, the questions, the answers or the token. It may log counts, latency, status codes and hashes.
- The whole response of `POST /v1/systemone`, headers included, is at most 64 KiB (the client's cap). With a shadow, the server replaces the shadow with `shadow.error: "shadow_failed"` when the answer would be larger.
- The deadlines belong to the client: 10 s for each attempt to the bouncer brain on this Mac, 20 s for each attempt to a remote bouncer brain, and one retry after a transport timeout. The server has no deadline field. After the deadline, the bouncer gate asks the owner. On macOS the platform certificate check may take longer than the deadline in rare cases; the result is then a failure, never an allowance.
- The bouncer gate makes every decision on the Mac. The server gives only probabilities. The credential never goes to the server.
- A new head set always starts in shadow mode on the Mac. Only the owner promotes it (`OwnerAction::PromoteModel`). The server has no promotion concept.

## 9. Versioning

- The server ignores request fields that it does not know.
- The client MUST NOT send fields that this contract does not define.
- The client ignores response fields that it does not know. It still checks `model` and `heads` against its pins (section 3.4).
- A change of a route, a status code, an error code, a hash rule or the meaning of a field needs a new version of this contract (`bouncer-brain-v2`), and a change on each side.

## 10. Fixtures

`tests/fixtures/bouncer-brain-v1/` holds synthetic examples. Every hash in them is synthetic. No fixture holds a secret value or an absolute path.

| File | What |
| --- | --- |
| `request.json` | Request with `heads` |
| `request-with-shadow.json` | Request with `heads`, `shadow_heads` and the owner-rule question |
| `answer.json` | 200 answer to `request.json` |
| `answer-with-shadow.json` | 200 answer to `request-with-shadow.json`, with shadow answers |
| `answer-shadow-unknown.json` | 200 answer to `request-with-shadow.json` when the shadow head set is unknown |
| `error-unknown-heads.json` | 409 body |
| `error-bad-heads.json` | 422 body |
| `error-no-token.json` | 403 body of a route that writes, on a server without a token |
| `heads-info.json` | 200 body of `GET /v1/heads/<sha256>` |
| `manifest.json` | A candidate manifest, the layout of `tools/finetune/local_train.py` |

`tests/bouncer_brain_contract.rs` parses each fixture and checks the hash, version, name, error-code, message and shadow rules above.
