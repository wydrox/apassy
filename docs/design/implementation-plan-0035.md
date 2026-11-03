# Implementation plan — who hosts and trains the bouncer brain (ADR 0035)

Date: 2026-11-02. Status: accepted with ADR 0035 on 2026-11-02. Wave 1 (A, B, D1) merged in #67 and shipped in 0.5.14; the later waves are not merged (2026-11-03). No hosting or training code, schema change, release version, server, or payment change belongs to this PR. The PR changes only names in the docs and in app texts.
Decision: [ADR 0035](../adr/0035-bouncer-hosting-and-training-choice.md). Words: [bouncer.md](../operations/bouncer.md), Words. Related: [ADR 0018](../adr/0018-local-bouncer-shared-vault-relay.md), [ADR 0019](../adr/0019-relay-teams-and-accounts.md) section 5, [fine-tune.md](../operations/fine-tune.md) sections 6–13, [plan 0033](implementation-plan-0033.md) (format).
Base inspected: branch `docs/adr-0035-bouncer-operators` at `80826eb8`, vault schema 23 (`src/vault/mod.rs:1277`), release 0.5.12.

## Outcome and constraints

The owner makes two independent choices: who hosts the bouncer brain (this Mac, the owner's server, Apassy) and who trains it (this Mac, the owner's server, an Apassy job). One protocol serves the owner's server and the Apassy service. The owner can always download the active head file and self-host it. Apassy sells availability, not access to the owner's model.

What never changes, in every combination:

- The bouncer gate runs on the Mac and makes every decision (`decide` in `src/broker/bouncer.rs`, order of bouncer.md 3.0). The credential never leaves the vault; the server never receives it.
- Unavailable, slow, wrong version, wrong head hash (HTTP 409) = "unavailable" = ask the owner. Never an allowance.
- Shadow first: every new head set, also from an Apassy job, starts in shadow mode. Only the owner promotes it (`OwnerAction::PromoteModel`).
- No payload contains a secret value, the vault path, or an absolute project path (ADR 0007 state only).
- The local path (this Mac hosts and trains) works with no account and no network, as today.
- The training gate stays: 300 owner decisions, 30 denials (`src/broker/finetune.rs:43-45`).
- A change of either choice needs a fresh owner check (ADR 0030).

## Dependency gates

The owner answered the six open decisions of ADR 0035 on 2026-11-02 (ADR 0035, "Owner decisions"). What each answer means for the plan:

| Decision | Answer | Effect on the plan |
| --- | --- | --- |
| 1. Plans | Apassy hosting and training are part of the paid Apassy Connect, for Personal and Team; self-hosting is free and open source | H and I sit behind the Connect entitlement; J copy follows [ADR 0037](../adr/0037-own-relay-open-source.md) D3 |
| 2. Location | Contabo VPS `ottervibe`, own compose project, hard limits (first: 2 vCPU / 3 GB inference, 2 vCPU / 4 GB one training job at low CPU priority) | H deploys there after K1 passes with the same limits on `devbox-x86`; no test on the VPS. VPS region must be confirmed as EU |
| 3. Deadline | 20 s per attempt to a remote bouncer brain, one retry on transport timeout (at most 40 s); 10 s on this Mac | C adds a per-host deadline; K1 threshold p95 ≤ 20 s, target 10 s |
| 4. License | Laya and ModernBERT-large weights are Apache-2.0 (model card at `55cf4c4`, tag `commercial-use`) | E2 may bake the weights into the image, with their license and notice files |
| 5. Shared base model | Only with a separate opt-in and anonymization | Out of this plan; a separate ADR comes first |
| 6. Account | The Apassy Connect account of ADR 0037 D3 | H sign-in waits for the Connect accounts of ADR 0037 stage 7; A defines the bouncer side with its own domain tag |
| Connect content | The bouncer brain service is the one Connect service that reads content; opt-in with a consent screen | C/J1 consent screen; ADR 0037 "Who sees what" must list it |

Steps that cost money or touch production need explicit owner confirmation at the time they run, also after the decisions above: `devbox up arm` / `devbox up x86` for K (shared 12.50 EUR/month budget; `devbox down` after each session), any new server, any Stripe price or product, each deployment to the Contabo VPS `ottervibe`, any image publication outside GitHub artifacts.

## Work units and ownership

One editor owns each shared file at a time. Paths are current unless labelled "proposed". Every unit adds tests to the single integration target (`tests/it.rs` module list) or to the unit's own file.

### A — Protocol freeze: contract `bouncer-brain-v1`

- Purpose: one wire contract for both operators before any client or server code.
- Files: proposed `docs/contracts/bouncer-brain-v1.md` (format of `relay-access-request-v1.md`: Date/Status/Decision lines, numbered sections, MUST/MUST NOT); `tests/contracts.rs` gets a fixture check for the examples; proposed `tests/fixtures/bouncer-brain-v1/` (request, answer, 409, manifest, job state JSON).
- Content: `POST /v1/systemone` with `heads` (64 lowercase hex; the SHA-256 of the head file, which is today's `checkpoint_sha256`) and optional `shadow_heads`; answer keeps `model` and adds `heads`, plus `shadow` with its own answers or `{"error":"unknown_heads"}`. 409 only when the active `heads` is unknown; an unknown shadow hash never fails the request. `GET /health` without a token. `PUT /v1/heads/<sha256>` (multipart: `candidate.safetensors`, `manifest.json`; the server runs today's `verify` of `serve.py:53-65`), `DELETE /v1/heads/<sha256>`, `DELETE /v1/owner`. `POST /v1/train` (the three files of fine-tune.md 6.1 step 4), `GET /v1/train/<id>`, `GET /v1/train/<id>/result`. Auth: bearer for an own server; for Apassy a challenge/token flow with the message of ADR 0019 section 5 but a distinct domain tag (`apassy-bouncer sign-in v1`), token in memory only. Limits: 64 KiB answers, 256 MiB result download, 24 h example retention.
- Owner: implementer (opus, high). Depends on nothing. Judge panel: 2× opus + 1× fable.
- Acceptance: every example in the fixtures parses with the strict rules (unknown field rejected); `contracts::bouncer_brain_v1_fixtures_match_the_contract` (new) passes; the contract names the 409 rule, the "shadow never fails the request" rule, and the no-secret rule.

### B — TLS POST with a whole-exchange deadline

- Purpose: the client can talk to `https://` with one deadline for DNS, connect, handshake, request and answer.
- Files: `src/broker/http.rs` only. Today `post_json_loopback` (`:259-303`) refuses `Https`; `get` (`:196-243`) resolves with `to_socket_addrs` without a deadline (`:225`) and `connect` (`:340-353`) sets per-operation timeouts, not an exchange deadline; `DeadlineStream` (`:307-338`) wraps `TcpStream` only.
- Change: `post_json(destination, path, body, bearer, timeout, tls: Option<&TlsClient>)`; `DeadlineStream` under `StreamOwned`; DNS on a helper thread bounded by the remaining deadline; `get_health` without a bearer; proposed `put_file` (streamed upload) and `get_to_file` (download with a 256 MiB cap and SHA-256). `post_json_loopback` stays as a thin wrapper so `src/bin/apassy-eval.rs:101` compiles unchanged.
- Owner: implementer (opus, high). Depends on A for paths only. Judge panel: 2× opus + 1× fable (security-sensitive).
- Acceptance (unit tests in `http.rs`, using the existing local TLS test at `:559` and `:609`): `a_stalled_tls_server_fails_at_the_exchange_deadline` (total < deadline + 1 s), `a_slow_dns_name_fails_at_the_deadline`, `a_wrong_server_name_sends_no_byte_of_the_body`, `a_response_over_the_cap_is_too_large`, `an_https_plain_http_mix_is_protocol`. No `unsafe`, no new crate.

### C — Remote host in the client, credential storage, consent, owner-checked choice

- Purpose: the bouncer gate can use a remote bouncer brain, with the owner's consent and a stored credential.
- Files: `src/broker/bouncer.rs` (`new` `:182-194` loopback rule; `at_url` `:198-203`; `from_env_or` `:224-231`; `probe_health` `:252-285`; `evaluate` `:318-367`; new `expect_heads`), `src/broker/model_server.rs` (`StartMode` `:101-111`, `BouncerSettings` `:141-148`, `validate_url` `:162-164`, `load` `:170-193`, `ensure_running` `:988`), `src/broker/approvals/owner_auth.rs` (`OwnerAction` `:91`, near `:333-346`, descriptions `:535-539`), `src/desktop/owner_check.rs` (`:409-421`, `:819-827`, `:1151-1154`, `:1995-1998`), `src/vault/mod.rs` (schema 24, shared with F: C owns it first), proposed `src/vault/bouncer_host.rs`.
- Design: `BouncerSettings.hosting: Hosting { ThisMac, OwnServer { url }, Apassy }` in `bouncer.json` (per Mac, no secret); `StartMode` keeps its meaning for `ThisMac`; `ensure_running` returns after a health probe for the other two and never spawns. Credential in a new local-only vault table `bouncer_host` (bearer for an own server; device key PKCS#8 for Apassy, the form of `src/vault/relay_device.rs:57-61` without `team_id`). Rejected: `Vault::read_vault_secret` (`src/vault/vault_secret.rs:16`) because it syncs last-writer-wins across devices and a device key is per device. `APASSY_BOUNCER_URL` stays loopback-only; a remote address comes only from the owner-checked setting. New `OwnerAction::ChangeBouncerHosting { hosting, host }` and `ChangeBouncerTraining { training, host }`. The gate pins both the model version and the head hash; 409 and a wrong `heads` in the answer are "unavailable".
- Owner: implementer (opus, high). Depends on A, B. Judge panel: 2× opus + 1× fable.
- Acceptance: `bouncer.rs::only_loopback_and_unreachable_is_unavailable` (`:1389`) updated to "loopback over http, non-loopback only over https"; new `a_409_or_a_wrong_head_hash_is_unavailable`, `a_remote_host_never_spawns_a_server` (`model_server.rs`, next to `:2184`), `a_remote_url_from_the_environment_is_refused`, `changing_the_hosting_choice_needs_the_owner_check` (`tests/owner_auth.rs`), `the_bouncer_host_table_is_not_synced` (`tests/relay_sync.rs` with `tests/common/fake_relay.rs`), migration cases in `tests/vault_migration.rs` for 23→24. Synthetic-secret scan: every request body of a fake TLS server (pattern of `tests/shadow_mode.rs:52` `fake_model`) is searched for the synthetic credential value and the vault path.

### D — `serve.py` head-set cache, `heads`/`shadow_heads`, routes, auth

- Purpose: the server holds one encoder and a cache of head sets, and answers active and shadow heads from one encoder pass.
- Files: `tools/basemodel/serve.py` (`build_router` `:107`, `DualHeads` `:136-173` holds exactly two head sets; `BaseRouter.predict` `:191-206` sets one `model`; `main` `:211-229` calls `uvicorn.run(create_app(router))`), proposed `tools/basemodel/heads_cache.py`, `tools/basemodel/auth.py`, `tools/basemodel/app.py` (a FastAPI wrapper that mounts laya's app and adds the routes of A), tests in `tests/basemodel/`.
- Design: `HeadSetCache` keyed by SHA-256 with an LRU limit and a per-owner namespace; `DualHeads` becomes `MultiHeads` (active, shadow, stock `leak`) in one pass; D1 (loopback, bearer or no auth) first; D2 adds the owner namespace and the challenge/token flow (needs decision 6 for the Apassy form). Rebase on PR #60 (fp16 encoder on MPS) before editing `serve.py`. Module-level imports stay torch-free so `tests/basemodel` import `serve.py` without the Laya venv.
- Owner: implementer (opus, high). Depends on A. Judge: 1× opus for D1; panel 2× opus + 1× fable for D2 (auth).
- Acceptance: `tests/basemodel/test_heads_cache.py` (fake tensors: unknown active hash → 409, unknown shadow hash → `shadow.error`, eviction, same answer for the same hash), `test_routes.py` (PUT verifies the manifest and refuses a wrong base revision; DELETE removes the file; no request body appears in any log line), `test_auth.py` (D2: nonce once, 60 s, wrong origin refused, token 15 min). Existing `test_input_boundary.py` still skips cleanly without torch.

### E — Container image and CI

- Purpose: the image of ADR 0035 section 2 and a CI job that runs the Python tests.
- Files: `.github/workflows/ci.yml` (E1: a new `basemodel-python` job on `ubuntu-24.04` with Python 3.12, `python3 -I -m unittest discover -s tests/basemodel -p 'test_*.py'`; the macOS job at `:98` already sets up Python at `:160-163`); proposed `tools/basemodel/Dockerfile` (python 3.12, `tools/basemodel/requirements.txt` pinned, `serve.py`, `local_train.py`, `common.py`, `manifest.json`; the Apache-2.0 weights may be baked in, with their license and notice files (decision 4); a variant fetches them with `fetch_weights.py` into a volume at first start; proposed `.github/workflows/bouncer-image.yml` modelled on the relay's `image.yml` (tag `bouncer-image-*`, `docker build`, `docker save | gzip`, SHA-256, artifact), with a matrix for arm64 and x86_64 (QEMU or an arm64 GitHub runner; verify availability first); CUDA variant later.
- Owner: E1 worker (sonnet, high) with the exact steps above; E2 ops (opus, high). Depends on D1 for a meaningful job. Images are built on GitHub only; local image tests run on `devbox-arm` / `devbox-x86` with `docker --context`, never on the Mac, never on `ottervibe`.
- Acceptance: E1 job green on a push; E2 workflow produces two artifacts with checksums and `docker image inspect` reports the expected architecture; a container on a devbox answers `GET /health` and one request with the shipped `apassy-base-v1` heads (K1 measures it).

### F — Shadow in one request, candidate representation

- Purpose: the shadow candidate rides in the same request as `shadow_heads`; no second server process.
- Files: `src/broker/shadow.rs` (`DEFAULT_CANDIDATE_URL` `:36-38`, `client_for` `:66-71`, `models` `:77-94`, `begin` `:155-196`), `src/broker/run.rs:864,906`, `src/broker/decide.rs:759`, `src/vault/candidate.rs` (`NewCandidate` `:140-150`, `register_candidate` `:308-358`: drop the `http://` rule at `:319`; keep a non-empty local checkpoint at `:321`, because the app always downloads the head file first), `src/vault/mod.rs` schema 24 (after C hands it over): `model_candidate.origin` (`local` | `remote_job`), `job_id`, `uploaded_to` (host or NULL); `model_activation.heads_sha256`.
- Design: `begin` takes the shadow answers from the active response instead of a second `evaluate`; a missing `shadow` or `shadow.error` records `NoAnswer`. The local path (this Mac) uses the same mechanism once the local `serve.py` of D1 is installed; the 8775 candidate server is retired from the docs.
- Owner: implementer (opus, high). Depends on A, C, D1. Judge panel: 2× opus + 1× fable (schema migration).
- Acceptance: `tests/shadow_mode.rs::a_candidate_that_is_down_slow_or_another_version_changes_nothing` (which now also holds the former `shadow_answers_never_change_a_decision`) passes with the merged request; new `a_shadow_error_records_no_answer_and_the_active_decision_stands`; `tests/vault_migration.rs` covers 23→24 and a failed migration keeps 23. Stage 2 measurement: shadow answers on a server equal the local shadow answers for the same head set (`apassy-eval` run, K1).

### G — Own training with a remote host: head upload

- Purpose: a head set trained on this Mac runs on the owner's server or on Apassy hosting.
- Files: `src/broker/finetune.rs` (after `read_result` `:836` and registration), proposed `src/broker/heads_upload.rs`, `src/desktop/learning_ui.rs` (`start_training` `:592`, after `:650`).
- Design: after a successful training, upload `candidate.safetensors` + `manifest.json` with `put_file` (B); mark `uploaded_to`; until the upload succeeds the gate gets 409 for the candidate and records `NoAnswer`, never an unavailable active model. A promotion of a candidate that is not uploaded is refused with a named reason (pattern of `shadow::promotion_refusal`).
- Owner: implementer (opus, high). Depends on B, C, D1, F. Judge: 1× opus.
- Acceptance: `tests/local_finetune.rs`: `a_trained_head_set_is_uploaded_and_shadow_starts_after_the_upload`, `promotion_is_refused_until_the_head_set_is_on_the_host`; the upload body is scanned for the synthetic secret.

### H — Apassy hosting service

- Purpose: many owners on one encoder, device-key sign-in, deletion, no request logging, EU.
- Files: D2 code in `tools/basemodel/`; proposed `docs/operations/bouncer-service.md` (runbook: compose file, limits, deletion, metrics without request data); proposed `tools/basemodel/entitlements.py` (interface; first version a file allow-list until decision 1).
- Location: a separate compose project on `ottervibe` with hard limits (decision 2): first 2 vCPU / 3 GB for inference and 2 vCPU / 4 GB for one training job at low CPU priority. The limits protect mail, relay, pretix and MDmesh.
- Owner: ops (opus, high) for deployment plan and compose; implementer (opus, high) for D2 code. Depends on D2, E2, K1, and the Connect accounts of ADR 0037 stage 7 (decision 6). Ops returns a plan; each deployment to `ottervibe` runs only after the owner confirms it. Judge panel: 2× opus + 1× fable (device-key auth, deletion).
- Acceptance: `test_multi_owner.py` (owner A cannot read or delete owner B's head set; `DELETE /v1/owner` leaves no file, cache entry or job for the owner; a revoked key loses its token at once); a log capture of 100 requests contains no state text; K2/K3 thresholds met.

### I — Apassy training jobs

- Purpose: a job trains the heads from the owner's examples, deletes them, and the app downloads the result into shadow mode.
- Files: `tools/basemodel/jobs.py` (proposed; runs `tools/finetune/local_train.py` `:53-63` in a subprocess per job in a 0700 temp dir; `alarm` at `:67` stays), `src/broker/finetune.rs` (`Trainer` `:444`, `train` `:668`: an `Apassy` trainer variant uploads the export of 6.1 step 4 instead of starting a process; power gate does not apply to a remote job), `src/desktop/learning_ui.rs`.
- Design: result download with `get_to_file`; `read_result` validation unchanged (version = name + sha8); registration as `origin = remote_job` in shadow mode. A sweeper deletes examples at job end and at the latest 24 h after upload. The "temporary worker" of the ADR is the same container in the first version; a separate worker waits for decision 2.
- Owner: implementer (opus, high); ops for the sweeper schedule. Depends on D2, G, H. Judge panel: 2× opus + 1× fable (deletion, shadow-first).
- Acceptance: `test_jobs.py` (examples absent after success, failure and at 24 h with a fake clock; a job cannot read another owner's files); `tests/local_finetune.rs::a_remote_job_result_starts_in_shadow_mode_and_needs_promotion`; stage 4 check: the head set equals one trained locally from the same examples within the tolerance of `train.py`.

### J — UI and docs

- Purpose: the two choices, the consent screen with the trust warning (ADR section 5), and the documentation.
- Files: `src/desktop/ui/settings.rs` (`broker_section` `:860`, group "Bouncer brain" `:864`, `model_server_rows` `:1139`, pickers `:1217`, `:1242`): J1 "Hosting" picker; `src/desktop/learning_ui.rs` (`:534` training card): J2 "Training" picker; docs: `docs/operations/bouncer.md` section 1 (remote host, remove "Apassy accepts only a loopback bouncer"), `docs/operations/fine-tune.md` sections 6 and 8 (merged shadow, remote training), proposed `docs/operations/bouncer-hosting.md` (self-host runbook with the image), `docs/adr/0007-rules-and-local-bouncer.md:62` ("3 seconds" is stale; the deadline is 10 s), `CHANGELOG.md` Unreleased, website copy for the plans (after decision 1).
- Owner: implementer (opus, high) for the views; worker (sonnet, high) for the docs with a checklist. Depends on C (J1), I (J2). Judge: 1× opus; screenshots of every changed view next to the mockup before any release claim.
- Acceptance: `settings.rs` test `the_hosting_picker_needs_the_owner_check_and_shows_the_trust_warning`; `learning_ui.rs` test `the_training_picker_needs_the_owner_check`; docs links resolve (`tests/contracts.rs` link check or `scripts/`).

### K — Measurements

- Purpose: the numbers of ADR 0035 Stages 1, 3 and 4.
- K1 (stage 1): CPU latency of one request (5 or 6 questions, 512 tokens) on `devbox-arm` (CAX31) and `devbox-x86` (CX43) with the E2 image, p50/p95 over 50 requests, cold and warm; shadow on/off. Run it also with the `ottervibe` limits of H (`docker run --cpus=2 --memory=3g`). Threshold: p95 ≤ 20 s (the remote deadline, decision 3), target 10 s. Above it, the service moves to a separate server or a GPU.
- K2 (stage 3): memory per active owner ≤ 150 MB (RSS delta per cached head set) and 10 parallel owners with p95 ≤ 2× single-owner p95. K3: deletion test of H.
- Owner: ops (opus, high). Each session needs the owner's go (cost); `devbox up arm|x86` through `apassy_run_with_secrets` with "devbox tailscale auth key", results in `docs/operations/bouncer-hosting.md`, `devbox down` at the end.

### L — Integration and release

- Purpose: one combined review and one release. Files: `release-versions.json`, Cargo manifests, iOS `MARKETING_VERSION`, extension manifest, relay package version, changelog (see AGENTS.md). Owner: top-level agent with a judge panel 2× opus + 1× fable over the combined diff (remote allowance paths, secret scan, migration, deletion). Acceptance: the "Required checks" list of ADR 0035, each with a named test above.

## Execution with subagents

Roles, models and efforts (owner convention; always set both explicitly):

| role | agentType | model | effort |
| --- | --- | --- | --- |
| discovery / mass read-only fan-out | scanner | sonnet | low |
| design, plan, final synthesis (read-only) | architect | fable | xhigh |
| implementation / code edits | implementer | opus | high |
| debugging, root cause | debugger | opus | xhigh |
| devops, infrastructure, incidents | ops | opus | high |
| verification / judge panels (read-only) | judge | opus | xhigh |
| precisely specified task | worker | sonnet | high |

Rules: at most three implementation or validation workers at once across the whole Mac (16 GB); a judge panel of three counts as three. Only the top-level agent runs lint, typechecks, builds, `cargo test` and full suites, one at a time through `~/.local/bin/heavy-check`, or preferably CI after an authorized push. Subagents never run them and return the exact validation commands. One validation pass per intended revision; a failed check goes back to a worker, the rerun stays with the top-level agent. Judge panels mix models (2× opus + 1× fable) for the security-sensitive units B, C, D2, F, H, I and L. Ops never makes hard-to-reverse or outward-facing changes without the owner's confirmation (servers, Stripe, DNS, VPS deployment, image publication). Implementer, debugger and ops delegate to a worker only tasks with goal, scope, steps, checkable criteria, prohibitions and answer format. Fable never in mass fan-out. Docker only on `devbox-arm` / `devbox-x86` with an explicit architecture, never on the Mac (no Colima), never on `ottervibe`; images are built on GitHub.

Waves (implementers run first; the panel runs after they return, so the count never exceeds three):

| Wave | Units in parallel | Verified by | Needs |
| --- | --- | --- | --- |
| 1 | A, B, D1 | panel 2× opus + 1× fable on A+B; 1× opus on D1 | nothing (approve now) |
| 1b | E1 (worker), K0 = scanner map of PR #60 conflicts in `serve.py` | top-level agent reads CI | nothing |
| 2 | C, F, E2 (ops) | panel 2× opus + 1× fable on C+F; 1× opus on E2 | A, B, D1 merged |
| 3 | G, J1, K1 (ops, owner go) | 1× opus on G+J1; architect (fable) reads K1 numbers for decision 3 | wave 2 merged |
| 4 | D2, H (ops plan + implementer), I | panel 2× opus + 1× fable on D2+H+I | K1 passed; Connect accounts (ADR 0037 stage 7) |
| 5 | J2, K2/K3 (ops, owner go), L | panel 2× opus + 1× fable on the combined diff | wave 4 merged |

Handoff format (every agent returns exactly this): `Unit`, `Base revision`, `Files changed` (absolute paths), `Interface` (types, functions, routes, schema), `Tests added` (names; "not run" or "cheap check run: <command>"), `Validation commands for the top-level agent` (exact), `Deviations from the plan`, `Open questions`, `Risks seen`. A judge returns, per acceptance criterion: PASS / FAIL / UNVERIFIED with `file:line` evidence, the counter-example it tried, and a severity.

## Release note

Per AGENTS.md, shipping any unit bumps all six components together (iOS app, macOS app, Linux CLI, browser extension, relay, website) to one version, also the components without a change. Releasable increments: (1) after waves 1–2: own hosting on the owner's server with the image (Stage 1); (2) after wave 3: own training with a remote host (Stage 2); (3) after waves 4–5: Apassy hosting and Apassy training (Stages 3–4). The docs-only parts (A, J docs) are not a release. Run `scripts/check-release-versions.py --relay-checkout PATH --require-relay` before each.

## Risks and unknowns (verified in the code)

- TLS trust for an own server: `TlsClient::platform` uses platform roots; a home server with a private CA cannot be used. On a tailnet, a Tailscale Serve certificate (`*.ts.net`) is a public certificate and works; Tailscale is reachability only, so the bearer token stays required. Pinning a private CA stays undecided (C/J1 copy must say "a public certificate, for example Tailscale Serve").
- `get` resolves DNS without a deadline (`http.rs:225`); B must bound it, or the 10 s attempt is not absolute.
- `APASSY_BOUNCER_URL` wins over `bouncer.json` (`bouncer.rs:224-231`); a remote URL there would bypass consent. C refuses it.
- `probe_health` returns `NoServer` for non-loopback (`bouncer.rs:255`) and `get` needs a bearer (`http.rs:205`); health over TLS needs B's `get_health`.
- Merged shadow adds a head pass to the active request; if the server is slow, the active decision pays. K1 measures shadow on/off; F keeps `NoAnswer` semantics.
- `register_candidate` requires `http://` and a local checkpoint (`candidate.rs:319-321`); `MAX_RESPONSE_BYTES` 64 KiB (`http.rs:19`) blocks a 100 MB result download without `get_to_file`.
- `RelayDevice` requires `team_id` (`relay_device.rs:57-61`); Free/Personal owners have no team (decision 6). The relay sign-in checks the challenge origin against the relay URL (`src/sync/relay.rs` `sign_in`), so reuse needs a separate origin and domain tag.
- `serve.py` conflicts with open PR #60; D rebases first. `uvicorn.run(create_app(router))` (`serve.py:228`) needs a wrapper app for new routes.
- No Dockerfile exists; the relay workflow is x86_64 only; arm64 and CUDA runners are unverified.
- Memory: 1.8 GB idle on MPS after #60; CPU servers differ. Unknown until K1/K2.
- Stale docs: ADR 0007 says 3 seconds (`0007:62`); bouncer.md says "Apassy accepts only a loopback bouncer".
- `tests/basemodel` never ran in CI; E1 may expose import breakage.

## First wave the owner can approve now

No open decision is needed for: A (contract doc), B (TLS POST with the deadline), D1 (`serve.py` heads cache and routes behind loopback), E1 (Python CI job), and the K0 scanner map of PR #60 conflicts. Cost: none (no devbox, no server). Validation: CI after an authorized push; locally at most `~/.local/bin/heavy-check cargo test --locked --all-features --test it contracts::` and the unit tests of `http.rs`, run by the top-level agent only.
