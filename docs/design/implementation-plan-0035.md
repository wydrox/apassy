# Implementation plan — who hosts and trains the bouncer brain (ADR 0035)

Date: 2026-11-02, refreshed 2026-11-03. Status: accepted with ADR 0035 on 2026-11-02.
Decision: [ADR 0035](../adr/0035-bouncer-hosting-and-training-choice.md). Contract: [bouncer-brain-v1](../contracts/bouncer-brain-v1.md). Words: [bouncer.md](../operations/bouncer.md), Words. Related: [ADR 0037](../adr/0037-own-relay-open-source.md) D2/D3 and stage 7, [plans](../product/plans.md), [fine-tune.md](../operations/fine-tune.md) sections 6–13.
Connect: units C3, D2 (sign-in), H and K3 depend on the Apassy Connect plan [implementation-plan-s7-connect.md](implementation-plan-s7-connect.md) (ADR 0037 stage 7) through the interface in section "Interface with Apassy Connect".
Base inspected: `origin/release/0.5.16` at `dd71868c`; vault schema 26 (`src/vault/types.rs:22`), 27 (stats) in progress.

History (short):
- 2026-11-02: plan accepted; the owner answered the seven decisions of ADR 0035.
- 2026-11-03: wave 1 (A, B, D1, PR #67) shipped in 0.5.14. E1 (Python tests in CI, `.github/workflows/ci.yml:185-188`) and PR #60 (fp16 on MPS, `tools/basemodel/serve.py:125`) are on the release branch, so K0 is void.
- 2026-11-03, this refresh. Owner decision: build everything of the ADRs except the TEE track, as fast as possible, with parallel agents, and no owner approval of intermediate steps. The owner gates are removed. Where the plan left a choice open, it takes the recommended option, marked "chosen by this plan; the owner can change it". The `bouncer_host` table moves from schema 24 to schema 29.

## Outcome and constraints

The owner makes two independent choices: who hosts the bouncer brain (this Mac, the owner's server, Apassy Connect) and who trains it (this Mac, the owner's server, an Apassy Connect job). One protocol serves the owner's server and the Connect service. The owner always has the head file of every head set on the Mac and can self-host it. Apassy sells availability, not access to the owner's model.

What never changes, in every combination:

- The bouncer gate runs on the Mac and makes every decision (`decide`, `src/broker/bouncer.rs:551`, order of bouncer.md 3.0). The credential never leaves the vault; the server never receives it.
- Unavailable, slow, wrong version, wrong head hash (HTTP 409), 401 = "unavailable" = ask the owner. Never an allowance.
- Shadow first: every new head set, also from a job, starts in shadow mode. Only the owner promotes it (`OwnerAction::PromoteModel`, `src/broker/approvals/owner_auth.rs:351`).
- No payload contains a secret value, the vault path, or an absolute project path (ADR 0007 state only).
- This Mac, with no account and no network, works as today.
- The training gate stays: 300 owner decisions, 30 denials (`src/broker/finetune.rs:43-45`).
- A change of either choice needs a fresh owner check (ADR 0030) that the global Touch ID window never covers (see C2).

Out of this plan: the TEE variant (ADR 0035 section 4, ADR 0037 enterprise track) and the shared base model (decision 5: a separate ADR comes first, and nothing is collected before it).

## Owner decisions and their effect

| Decision (ADR 0035) | Answer | Effect |
| --- | --- | --- |
| 1. Plans | Connect hosting and training are paid; self-hosting is free | Self-hosting (own server) ships in the next coordinated release with no account. Connect parts wait for the Connect plan. Entitlement: all three Connect plans (Personal, Family, Team), because [plans](../product/plans.md) section 3 lists the hosted brain as a Connect function and Family came after the decision: chosen by this plan; the owner can change it. |
| 2. Location | `ottervibe`, own compose project, first limits 2 vCPU / 3 GB inference, 2 vCPU / 4 GB one training job | H deploys there. K1 measures the limits on `devbox-x86` first. The EU region is a read-only check in H. |
| 3. Deadline | 20 s per remote attempt, one retry on transport timeout; 10 s on this Mac | C1 adds `REMOTE_TIMEOUT`; K1 threshold p95 ≤ 20 s, target 10 s |
| 4. License | Apache-2.0 weights | E2 bakes the weights into the image with the license and notice files |
| 5. Base model | Separate opt-in, separate ADR | Out of this plan |
| 6. Account | The Connect account (ADR 0037 D3) | C3, D2 and H use the Connect device key and directory (interface below) |
| 7. Content at Connect | The brain is the one Connect service that reads content; opt-in with a consent screen | J1 consent screen; J3 adds the row to ADR 0037 "Who sees what" |

## What still needs the owner or money (not plan gates)

- **K1, one paid devbox run.** One bounded session on `devbox-x86` (CX43) and `devbox-arm` (CAX31): at most 2 hours per server, `devbox status` before the start (shared 12.50 EUR/month budget), `devbox down --all` at the end. The standing Hetzner rule (CLAUDE.md) applies: the top-level agent gets one "yes" from the owner for this run. That is a cost confirmation, not an approval of the plan. No second devbox run is planned: K1 also measures the stage 3 and stage 4 numbers.
- **A failed K1 threshold that needs a new server.** If p95 with the largest limits that `ottervibe` can give stays above 20 s, a separate server is a new cost: the owner chooses it. Everything else in the plan continues; only H waits.
- **The DNS record of the hosted endpoint**, if the Connect plan does not create it (account/DNS changes stay with the owner).
- **A GPU test of the CUDA image** is not planned (paid GPU). The owner can order one; until then the CUDA image is "built, not tested on a GPU".
- Store submission and TestFlight of each release follow the release rules (AGENTS.md), not this plan.

Not owner steps any more: the start of each wave, K1 interpretation (the architect decides from the numbers by the rules in K1), the image publication with the release (E2), and the deployment of the brain service to `ottervibe` (approved by decision 2; H deploys after the green ready-PR run, with a backup and a resource check first).

## Interface with Apassy Connect

The Connect plan (`implementation-plan-s7-connect.md`) owns accounts, Stripe, device enrollment and the Connect domain. This plan consumes five things. If the Connect plan changes one of them, C3, D2 and H follow it; the brain domain tag and the rule "the account token never goes to the brain" do not change.

| # | Connect gives | Form | Used by |
| --- | --- | --- | --- |
| I-1 | **Device key.** One P-256 key per device, enrolled in the Connect account, private key in a local-only vault table of the Connect plan (the form of `RelayDevice`, `src/vault/relay_device.rs:57-70`, without `team_id`). Rust API: `connect::device_identity(&Vault) -> Option<ConnectDevice { account_id, key_id, public_key }>` and `connect::sign(&Vault, tag, parts) -> Signature`, which signs only for an allow-list of tags that contains `apassy-bouncer sign-in v1`. | Rust, in the app | C3 |
| I-2 | **Account token.** The Connect session token stays in the Connect client code. It is never sent to the brain service. The brain issues its own token after the device-key sign-in. | rule | C3, D2 |
| I-3 | **Directory.** Service to service on the internal network of the Connect host: `POST /internal/v1/brain/device {key_id, public_key_sha256}` → `{account, entitled_hosting, entitled_training, revoked}`; `account` is an opaque id. Service token in the compose secrets. | HTTP, internal | D2, H |
| I-4 | **Events.** Connect calls the brain: `POST /internal/v1/revoke {key_id}` when a device key is revoked (its tokens end at once) and `POST /internal/v1/forget {account}` when the plan ends or the account is deleted (the effect of `DELETE /v1/owner`). Idempotent; Connect retries until 2xx. | HTTP, internal | D2, H |
| I-5 | **Hosted endpoint.** Its own origin `https://brain.<Connect domain>` (the Connect plan names the domain), its own certificate and compose project. Not behind the byte relay; the relay does not call it (ADR 0035 section 5). The app has the origin as a build constant, like the relay origin, never from a server answer. | config | C3, H |

Until the Connect plan delivers I-1 to I-4, C3 and D2 use fakes (`tests/basemodel/fake_connect.py`, a test `connect` module in Rust) with exactly these shapes.

## Work units and ownership

One editor owns each shared file at a time. "New" marks a file that does not exist yet. Every Rust unit adds tests to the integration target (`tests/it.rs` module list) or to its own file. A test that uses a fixed port, path or the Keychain must not run beside other tests: free port, temporary directory, or the nextest `serial` group with the reason (`.config/nextest.toml`).

### Done

- **A** — contract `bouncer-brain-v1` (`docs/contracts/bouncer-brain-v1.md`, fixtures `tests/fixtures/bouncer-brain-v1/`, `tests/bouncer_brain_contract.rs`). Shipped 0.5.14.
- **B** — `post_json` with one deadline over TLS (`src/broker/http.rs:282-299`), DNS on a helper thread (`:401`), `get_health` without a bearer (`:348`); `post_json_loopback` is a wrapper (`:261`). Shipped 0.5.14. Not done from B: streamed upload, capped download, bearer GET/DELETE with a deadline (moved to C1).
- **D1** — `tools/basemodel/app.py` (routes `:136-286`), `heads_cache.py` (`HeadSetCache` `:249`, files `<sha>.safetensors` and `<sha>.json` `:279`), `serve.py` multi heads (`:180`). Shipped 0.5.14.
- **E1** — `ci.yml:185-188` runs `tests/basemodel` without torch.

### C1 — Client transport and wire (M)

- Purpose: the bouncer gate talks to a remote brain over HTTPS, with pinned heads and the shadow in the same request.
- Files: `src/broker/http.rs`, `src/broker/bouncer.rs`, `tests/bouncer_rules.rs` (hostile-server case).
- Today: `BouncerClient::new` refuses non-loopback (`bouncer.rs:185-197`); `probe_health` gives `NoServer` for HTTPS (`:258-260`); `warm_up` and `evaluate` use `post_json_loopback` (`:299`, `:329`); one 10 s `TIMEOUT` (`:47`); `get` (`http.rs:197-247`) has a bearer but resolves with `to_socket_addrs` without a deadline (`:225-228`) and is used by the connector path (`src/broker/decide.rs:1333`), so it stays unchanged.
- Design: `BouncerClient::remote(url, credential: Arc<dyn BrainCredential>, tls: Arc<TlsClient>)` (HTTPS only, `REMOTE_TIMEOUT` 20 s, the existing single retry on transport timeout); `BrainCredential::bearer(deadline) -> Option<Zeroizing<String>>` and `invalidate()`, with `StaticBearer` for an own server (C3 adds the Connect one); a 401 invalidates the credential and the request is unavailable. `expect_heads(sha)` pins the active head hash; `evaluate_with_shadow(&request, Option<&ShadowPin>) -> (BouncerVerdict, Option<BouncerVerdict>)` sends `heads` and `shadow_heads` and checks `heads`/`model` of both parts (contract 3.4). `probe_health` and `warm_up` work over TLS. `new` and `from_env_or` (`:227-234`) stay loopback-only: `APASSY_BOUNCER_URL` can never name a remote host. In `http.rs`: `request_json(method, destination, path, bearer, body, deadline, tls)` for bearer GET and DELETE; `put_file` (`Expect: 100-continue`, no body byte before `100 Continue`, 160 MiB cap, `Apassy-Manifest` header); `get_to_file` (256 MiB cap, SHA-256 while it reads). Transfers have a progress deadline (30 s without bytes fails) and a total cap of 15 min: chosen by this plan; the owner can change it.
- Owner: implementer (opus, high). Depends on nothing. Judge panel 2× opus + 1× fable.
- Acceptance: `bouncer.rs::only_loopback_and_unreachable_is_unavailable` (`:1459`) becomes "loopback over http, non-loopback only over https with a credential"; new `a_409_a_401_or_a_wrong_head_hash_is_unavailable`, `a_shadow_error_never_changes_the_active_verdict`, `a_remote_url_from_the_environment_is_refused`, `the_remote_deadline_is_20_s_per_attempt_and_40_s_at_most`; in `http.rs`: `an_upload_sends_no_body_before_100_continue`, `an_early_final_response_stops_the_upload`, `a_download_over_the_cap_is_too_large`, `a_download_with_a_wrong_hash_is_refused`, `a_stalled_transfer_fails_at_the_progress_deadline`; `bouncer_rules.rs::a_hostile_brain_cannot_allow_production_a_flag_or_a_foreign_host` (all-low-risk answers). Every request body of the fake TLS servers is scanned for the synthetic credential value and the vault path. No `unsafe`, no new crate.

### C2 — Hosting choice, credential, owner check, schema 29 (L)

- Purpose: the owner chooses the host and the trainer with a fresh owner check; the credential is in the vault on this Mac only.
- Files: `src/vault/types.rs` (`SCHEMA_VERSION` `:22`), `src/vault/mod.rs` (`verify_user_version` `:1110-1139`, migration chain), new `src/vault/schema29.rs`, new `src/vault/bouncer_host.rs`, `src/vault/merge.rs` (`LOCAL_TABLES` `:82`), `src/broker/model_server.rs`, `src/broker/approvals/owner_auth.rs`, `src/desktop/owner_check.rs`, `tests/vault_migration.rs`, `tests/sync_schema_upgrade.rs`, `tests/owner_auth.rs`.
- Schema 29 (all of it; F uses its candidate columns, nobody else edits the file). Numbers: 27 is stats, 28 another unit; C2 merges only on top of both and takes the number that the release coordinator assigns if 28 moves; the DDL stays.

  ```sql
  CREATE TABLE bouncer_host (
      role TEXT PRIMARY KEY CHECK (role IN ('hosting', 'training')),
      kind TEXT NOT NULL CHECK (kind IN ('own_server', 'connect')),
      url TEXT NOT NULL,
      bearer BLOB,                -- own_server only; NULL for connect (the key is I-1)
      consent_version INTEGER NOT NULL,
      consented_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
  );
  ALTER TABLE model_candidate ADD COLUMN origin TEXT NOT NULL DEFAULT 'local'
      CHECK (origin IN ('local', 'remote_job'));
  ALTER TABLE model_candidate ADD COLUMN job_host TEXT;
  ALTER TABLE model_candidate ADD COLUMN job_id TEXT;
  ALTER TABLE model_candidate ADD COLUMN uploaded_to TEXT;
  ALTER TABLE model_activation ADD COLUMN heads_sha256 TEXT;
  ```

  No row for a role means "this Mac". `bouncer_host` is local (`LOCAL_TABLES` 37 → 38): a pushed copy carries none of its rows. Rejected: `Vault::read_vault_secret` (`src/vault/vault_secret.rs`), because it syncs last-writer-wins across devices.
- Where the choice lives: in the vault row, not in `bouncer.json`. Any process of the user can write `bouncer.json`; a remote address there would bypass the owner check. `bouncer.json` keeps `start`, `idle_minutes` and a loopback `url` (`model_server.rs:141-148`, `validate_url` `:162`): chosen by this plan; the owner can change it.
- `ModelServer`: `set_remote(bool)` after unlock from the hosting row. In remote mode `ensure_running` (`:995`) never spawns; the monitor (`next_job` `:1125`) probes only `GET /health` every 60 s and runs `warm_up` at the selection, after a failure, and once an hour, never every 10 s as `External` does (`PROBE_EVERY` `:77`, `probe` `:1180`). A running local server stops at the idle time. For the managed local server, the launch passes a random per-launch `LAYA_API_KEY` (next to `:2001-2003`) that the client keeps in memory, so the routes that write work on this Mac (G): chosen by this plan; the owner can change it.
- Owner actions: `OwnerAction::ChangeBouncerHosting { kind, url, consent_version }` and `ChangeBouncerTraining { kind, url, consent_version }` after `RollbackModel` (`owner_auth.rs:357`), with descriptions next to `:675-679`; matching `OwnerRequest` variants, texts and dispatch in `owner_check.rs` (patterns at `:463`, `:884-894`, `:1220-1225`, `:2105-2113`). They are not in `LocalWindowSource::permits` (`owner_auth.rs:2096`), so the global window never covers them. A return to "this Mac" also needs the check (ADR text). The bearer of an own server: pasted, or generated by the app (32 random bytes) and shown once with the `docker run -e LAYA_API_KEY=…` line.
- Owner: implementer (opus, high). Depends on the C1 names above (parallel). Judge panel 2× opus + 1× fable.
- Acceptance: `tests/vault_migration.rs` covers 28→29 in `unlock_migrates_each_earlier_schema_version_to_the_current_one` (`:843`) and a failed 29 migration keeps 28 (pattern `:1251`); `sync_schema_upgrade.rs`: a device of schema 28 refuses a copy of 29, a pushed copy has no `bouncer_host` row; `owner_auth.rs`: `changing_the_hosting_or_training_needs_a_fresh_check`, `the_owner_window_never_covers_a_hosting_change`; `model_server.rs`: `a_remote_host_never_spawns_a_server`, `a_remote_host_is_not_warmed_up_every_probe`, `a_remote_url_in_bouncer_json_is_ignored` (next to `the_address_must_be_a_loopback_http_url` `:2191`).

### E2 — Container images, workflow, bench script (M)

- Purpose: the self-host image of ADR 0035 section 2 and the tools for K1.
- Files: new `tools/basemodel/Dockerfile`, new `.dockerignore` entries for it, new `.github/workflows/bouncer-image.yml` (modelled on `relay-image.yml`; tag `bouncer-image-*`), new `tools/basemodel/bench.py` (latency, memory, parallel owners, synthetic head sets with the right shapes, a synthetic training set from `tests/fixtures/bouncer/cases.tsv`; no owner data), new `docs/operations/bouncer-hosting.md` (self-host runbook: run, token, Tailscale Serve certificate, deletion).
- Design: Python 3.12, pinned `tools/basemodel/requirements.txt`, `serve.py`, `app.py`, `heads_cache.py`, `common.py`, `manifest.json`, `tools/finetune/local_train.py`; Apache-2.0 weights baked in with license and notice files. The server refuses to bind a non-loopback address without `LAYA_API_KEY` (`serve.py` `bind_problem` `:437`). Matrix: CPU arm64, CPU x86_64, CUDA x86_64; arm64 on a GitHub arm64 runner, else QEMU (check availability first). Artifacts: `docker save | gzip` and SHA-256. Publication with each release: release assets for the CPU images and GHCR `ghcr.io/wydrox/apassy-brain:<version>` for all three (the CUDA image is over the 2 GB asset limit): chosen by this plan; the owner can change it. Images are built on GitHub only, never on the Mac or `ottervibe`.
- Owner: ops (opus, high); the bench script by a worker (sonnet, high) with exact steps. Depends on D1 (done). Judge: 1× opus.
- Acceptance: the workflow gives three artifacts with checksums; `docker image inspect` gives the expected architecture; `bench.py --dry-run` works without torch in the CI Python job.

### F — Shadow in one request (M)

- Purpose: the shadow candidate rides in the active request as `shadow_heads`; the 8775 candidate server goes away.
- Files: `src/broker/shadow.rs`, `src/broker/run.rs`, `src/broker/decide.rs`, `src/vault/candidate.rs`, `tests/shadow_mode.rs`.
- Today: a second client per candidate (`shadow.rs` `CANDIDATE_URL_ENV`/`DEFAULT_CANDIDATE_URL` `:36-47`, `client_for` `:66-71`, `models` `:77-94`) and a second `evaluate` on a thread (`begin` `:155-196`); call sites `run.rs:1212`, `:1257`, `:1278`, `decide.rs:778`; `register_candidate` needs `http://` and a local checkpoint (`candidate.rs:319-321`); `ModelActivation::is_default` means an empty `url` (`:291`).
- Design: `models` gives one client with the active pin (version and `heads_sha256`) and an optional `ShadowPin`; `begin` takes the shadow verdict from `evaluate_with_shadow` (C1) and only stores the row; a missing `shadow` or any `shadow.error` records `NoAnswer`. `register_candidate` drops the `http://` rule and keeps the local checkpoint rule (every head set is on the Mac first); `url` stays for old rows and is no longer read. `is_default` becomes "no `url` and no `heads_sha256`". A promotion writes `heads_sha256`. A candidate whose file is not on the active host (`uploaded_to` differs from the host) gives `NoAnswer` and a named promotion refusal (pattern `promotion_refusal` `shadow.rs:199`).
- Owner: implementer (opus, high). Depends on C1, C2. Judge panel 2× opus + 1× fable.
- Acceptance: `a_candidate_that_is_down_slow_or_another_version_changes_nothing` (`shadow_mode.rs:340`) passes with the merged request; new `a_shadow_error_records_no_answer_and_the_active_decision_stands`, `a_promoted_head_set_is_pinned_by_hash`, `an_old_candidate_row_with_an_8775_url_still_works_after_29`; `a_promoted_model_is_pinned_to_its_version` (`:563`) unchanged.

### A2 — Contract `bouncer-brain-v2` (S)

- Purpose: the bodies that v1 reserved: training jobs, owner namespaces, Connect sign-in.
- Files: new `docs/contracts/bouncer-brain-v2.md`, new `tests/fixtures/bouncer-brain-v2/`, `tests/bouncer_brain_contract.rs`.
- Content: every v1 route unchanged (a v1 client works against a v2 server). Jobs (as built in `docs/contracts/bouncer-brain-v2.md`): `PUT /v1/train/<sha256>` (body `train.jsonl` then `val.jsonl`, at most 64 MiB; the job manifest with the counts of `stats` in the `Apassy-Manifest` header, as C1's `put_file` sends it), `GET /v1/train/<id>` (`queued`, `running`, `done`, `failed`, `deleted`, with times, no example data, and the result data when done), `GET /v1/train/<id>/result` (the head file only, for `get_to_file`), `DELETE /v1/train/<id>`; one job per owner at a time; examples deleted at job end and at 24 h at the latest; the result is deleted after the download when the owner does not host at that server. Sign-in: `POST /v1/sign-in/challenge` → nonce (single use, 60 s); `POST /v1/sign-in` with the signature over `apassy-bouncer sign-in v1 \0 origin \0 account \0 public_key_b64u \0 nonce_b64u` (the form of `sign_in_message`, `src/sync/relay_crypto.rs:380`, with `account` for `team_id`) → token, 15 min, memory only. Owner namespace: on a Connect server every head set, job and limit belongs to the signed-in account; at most 4 stored head sets per owner (active, shadow, previous, one spare): chosen by this plan; the owner can change it. `DELETE /v1/owner` also removes jobs and examples and answers with the counts.
- Owner: implementer (opus, high). Depends on nothing. Judge panel 2× opus + 1× fable (auth design).
- Acceptance: the fixtures parse with the strict rules; the contract states the sign-in origin rule, the 24 h rule and the "result deleted after download" rule.

### K1 — Measurements, one bounded paid run (S)

- Purpose: the numbers of stages 1 to 4 that decide the limits of H. One session; see "What still needs the owner or money".
- Who: ops (opus, high), started by the top-level agent after the E2 artifacts exist; then the architect (fable, xhigh, read-only) applies the rules below. Results go to `docs/operations/bouncer-hosting.md`, section "Measurements".
- Steps: `devbox up x86` and `devbox up arm` through `apassy_run_with_secrets` with "devbox tailscale auth key"; download the artifacts on the Mac, rsync them to `dev@devbox-x86:` / `dev@devbox-arm:`, `docker --context devbox-… load`; run `bench.py`:
  1. Latency: 50 requests (5 or 6 questions, up to 512 tokens), p50/p95, cold and warm, shadow off and on; without limits and with `--cpus=2 --memory=3g`.
  2. Memory: idle and peak RSS; RSS delta per extra cached head set over 10 synthetic head sets; 10 parallel owners (different head hashes), p95.
  3. Training: one job of `local_train.py` on the synthetic set with `--cpus=2 --memory=4g` and low CPU priority: wall time and peak RSS.
  4. Equality (stages 2 and 4): the answers of the container and of `serve.py` on this Mac (the top-level agent starts one local process) for the base heads and one synthetic candidate; and the head set of step 3 against one that `local_train.py` trains on this Mac from the same synthetic set, within the tolerance of `train.py`.
  5. CUDA image: `GET /health` and one answer on CPU only.
  `devbox down --all` at the end, also after a failure.
- Rules (no owner unless a new server is needed): x86 with limits p95 ≤ 20 s → `ottervibe` with these limits; p95 > 20 s → the largest limits that `ottervibe` can give (ops reads its free CPU and memory, read-only), then measured again inside the same session; still above → the owner chooses a separate server. Memory limit = measured peak + 20 %. Inference + training limits ≤ 6 GB together (the VPS had 6.9 GB available on 2026-11-02, so 3 + 4 GB does not fit beside the production services); a job starts only when the host has its limit + 1 GB available, else it stays `queued`: chosen by this plan; the owner can change it. Remote job deadline = 2 × the measured time, at most 3 h. Per owner ≤ 150 MB and 10-owner p95 ≤ 2 × single p95, else the per-owner cache limit goes down. Equality: |Δp| ≤ 0.02 per question and the same run/ask outcome on the eval set: chosen by this plan; the owner can change it.

### G — Head set placement after training (M)

- Purpose: a head set trained on this Mac (or downloaded from a job) runs where the brain runs.
- Files: `src/broker/finetune.rs` (after `read_result` `:836` and the registration in `train` `:668`), new `src/broker/heads_place.rs`, `src/desktop/learning_ui.rs` (`start_training` `:598`, `shadow::candidate_url` at `:612`, `poll_training` after it), `tests/local_finetune.rs`.
- Design: `place(candidate, host)` with `put_file` (C1) to the hosting server, also on this Mac (per-launch key of C2); a `409 heads_full` deletes the oldest replaced candidate of this owner and tries once more; marks `uploaded_to`. Until the upload succeeds, the candidate gives `NoAnswer`, never an unavailable active model. A hosting change re-places the active and shadow head sets before the switch completes; a failed upload keeps the old host. External loopback mode without `APASSY_BOUNCER_KEY` cannot upload: the Learning view says so.
- Owner: implementer (opus, high). Depends on C1, C2, F. Judge panel 2× opus + 1× fable (with I-srv).
- Acceptance: `a_trained_head_set_is_uploaded_and_shadow_starts_after_the_upload`, `promotion_is_refused_until_the_head_set_is_on_the_host`, `a_hosting_change_moves_the_active_and_shadow_head_sets_first`; the upload body is scanned for the synthetic secret.

### J1 — Hosting picker and consent screen (M)

- Purpose: the choice of host, the trust warning (ADR section 5), and the consent screen that lists what leaves the Mac (ADR sections 1 and 4).
- Files: `src/desktop/ui/settings.rs` (`broker_section` `:865`, group "Bouncer brain" `:869`, `model_server_rows` `:1148`, pickers `:1222`, `:1246`), new `src/desktop/brain_hosting_ui.rs` (consent sheet), `design/walkthrough/` (the mockup of the new rows and the sheet).
- Design: a "Hosting" row in "Bouncer brain": This Mac, My server, Apassy Connect. "Apassy Connect" is hidden until C3 merges. The sheet shows the address, the public-certificate rule ("a public certificate, for example Tailscale Serve"), what leaves the Mac, the trust warning, then the owner check of C2. The mockup is written first; a judge compares the screenshots with it (no owner approval, owner decision 2026-11-03).
- Owner: implementer (opus, high). Depends on C2. Judge: 1× opus; the top-level agent takes the screenshots of every changed view.
- Acceptance: `the_hosting_picker_needs_the_owner_check_and_shows_the_trust_warning`, `the_consent_sheet_lists_what_leaves_the_mac`; the walkthrough model tests pass in CI.

### I-srv — Training jobs on a server (M)

- Purpose: `PUT /v1/train/<sha256>` of A2 on any server: the owner's own server (free) and later Connect.
- Files: new `tools/basemodel/jobs.py`, `tools/basemodel/app.py` (train routes), new `tests/basemodel/test_jobs.py`.
- Design: one subprocess of `tools/finetune/local_train.py` per job (its `--deadline` alarm, `:58`, `:67`) in a 0700 temporary folder; one job per owner at a time and one per server (`queued` beyond that); the memory rule of K1 before a start; a sweeper deletes examples at the job end and at 24 h at the latest (fake clock in tests); no example, state or answer in any log line. The result stays until its download.
- Owner: implementer (opus, high). Depends on A2. Judge panel 2× opus + 1× fable (with G).
- Acceptance: `test_jobs.py`: examples absent after success, failure, stop and at 24 h; a job cannot read another job's folder; the log capture of a job has no example text; torch-free import still works.

### I-cli + J2 — Remote trainer in the app, training picker (M)

- Purpose: "Training: My server / Apassy Connect" runs a job instead of a local process, and the result enters shadow mode.
- Files: `src/broker/finetune.rs` (`Trainer` `:444`, `from_env` `:481`, `train` `:668`), `src/desktop/learning_ui.rs` (training card, `training_lines` `:117`), `tests/local_finetune.rs`.
- Design: a `RemoteTrainer` uploads the export of fine-tune.md 6.1 step 4 (the gate of `gate` `:152` still applies; the AC power rule does not apply to a remote job), polls the state, downloads the result with `get_to_file`, runs the unchanged `read_result` check (version = name + sha8), registers `origin = remote_job` in shadow mode, and calls `DELETE /v1/train/<id>`. Then G places the head set. J2: the "Training" row with the owner check of C2.
- Owner: implementer (opus, high). Depends on G, I-srv. Judge panel 2× opus + 1× fable (with D2).
- Acceptance: `a_remote_job_result_starts_in_shadow_mode_and_needs_promotion`, `a_remote_job_upload_holds_no_secret_and_no_absolute_path`, `the_training_picker_needs_the_owner_check`. The stage 4 equality is K1 step 4.

### J3 — Docs (S)

- Files: `docs/operations/bouncer.md` (`:31` "Apassy accepts only a loopback bouncer", `:84` "A change in Settings needs no owner check"), `docs/operations/fine-tune.md` sections 6 and 8 (merged shadow, remote training, no 8775 server), `docs/operations/bouncer-hosting.md` (after E2 and K1), `docs/adr/0007-rules-and-local-bouncer.md:62` ("3 seconds" → 10 s local, 20 s remote), ADR 0037 "Who sees what" (the brain row), the progress line of ADR 0035, `CHANGELOG.md` Unreleased.
- Owner: worker (sonnet, high) with a checklist. Depends on F, G, J1. Judge: 1× opus (with J2).
- Acceptance: every link resolves; no text says that the brain must be on loopback.

### D2 — Connect-facing server: sign-in, owners, directory (M)

- Purpose: many owners on one encoder, Connect sign-in, deletion through I-4.
- Files: new `tools/basemodel/auth.py`, new `tools/basemodel/owners.py`, `tools/basemodel/app.py`, `tools/basemodel/heads_cache.py` (namespace), new `tests/basemodel/test_auth.py`, `test_multi_owner.py`, `fake_connect.py`.
- Design: on only when `APASSY_BRAIN_CONNECT_DIRECTORY` is set; an own server keeps the one-owner bearer of v1. The sign-in of A2 checks the device in the directory (I-3) at each sign-in; tokens in memory; `revoke` and `forget` of I-4; per-owner cache namespace, limits of A2; metrics are counts, latency and status codes only.
- Owner: implementer (opus, high). Depends on A2, I-srv (`app.py` order). Judge panel 2× opus + 1× fable.
- Acceptance: `test_auth.py`: a nonce works once and for 60 s, a wrong origin is refused, a token ends at 15 min, a revoked key loses its token at once; `test_multi_owner.py`: owner A cannot read, use or delete a head set or job of owner B; `forget` leaves no file, cache entry, job or example; a log capture of 100 requests has no state text.

### C3 — Client Connect sign-in (S–M)

- Files: new `src/broker/brain_connect.rs` (a `BrainCredential` from I-1), `src/desktop/ui/settings.rs` and `src/desktop/learning_ui.rs` (show the Connect options), `src/desktop/brain_hosting_ui.rs` ("Delete my data at Apassy" with the deletion counts).
- Design: sign-in inside the 20 s deadline of the request; the token only in memory; a 401 signs in again at the next request, never inside the same one. The origin is the I-5 constant.
- Owner: implementer (opus, high). Depends on C1, J1, I-cli, and I-1 merged from the Connect plan. Judge panel 2× opus + 1× fable.
- Acceptance: `the_connect_sign_in_uses_its_own_tag_and_origin`, `the_account_token_is_never_sent_to_the_brain`, `a_deletion_shows_the_counts`.

### H — Connect brain service on `ottervibe` (M)

- Files: new `deploy/brain/compose.yml`, new `docs/operations/bouncer-service.md` (runbook: limits, deletion, metrics without request data, backup of nothing but the head sets).
- Design: own compose project with the limits of K1; inference and the job container on an internal network with Connect; the reverse proxy routes only the I-5 origin. Ops first checks, read-only, the EU region and the free CPU and memory; then deploys the GitHub image with the release version.
- Owner: ops (opus, high). Depends on D2, E2, K1, C3 and the Connect plan live (I-1 to I-5). Judge panel 2× opus + 1× fable (deletion, isolation, no logging).

### K3 — Deletion test on the live service (S)

- Who: ops after H: two synthetic test accounts of the Connect plan; upload, job, `DELETE /v1/owner` and `forget`; then a file listing of the volume shows nothing of the owner. No devbox.

### L1, L2 — Integration and release

- L1: the next coordinated release (below). L2: the Connect release, together with the Connect plan. Files: `release-versions.json`, Cargo manifests and lock file, iOS `MARKETING_VERSION`, extension manifest, relay package version, dated changelog (AGENTS.md); the image tag is the shared version. Owner: the top-level agent with a panel 2× opus + 1× fable over the combined diff (remote allowance paths, secret scan, migration, deletion). Acceptance: the "Required checks" below, each with its test.

## Waves

Every brief carries the Mac limits: at most three implementation or validation agents at once across this Mac, also counting the agents of other plans (for example the Connect plan); a judge panel of three counts as three. Subagents never run lint, typechecks, builds, `cargo test`/`nextest` or full suites, also not through `heavy-check`; they return the exact commands. The top-level agent runs one validation pass per intended revision through `~/.local/bin/heavy-check`, or reads CI after the push. Each unit is a draft PR to `main` (`gh pr create --draft`), marked ready when complete, merged only after the ready-PR run is green. Docker only on `devbox-arm` / `devbox-x86` with an explicit architecture, never on the Mac, never on `ottervibe` for tests.

| Wave | Units (parallel) | Verified by (after the implementers return) | Starts when |
| --- | --- | --- | --- |
| 2 | C1, C2, E2 | panel 2× opus + 1× fable on C1+C2, then 1× opus on E2 | now |
| 3 | F, A2, K1 | panel on F+A2; architect (fable) applies the K1 rules | C1, C2 merged; E2 artifacts |
| 4 | G, J1, I-srv | panel on G+I-srv; 1× opus on J1 and the screenshots | F, A2 merged |
| 5 | I-cli + J2, J3, D2 | panel on I-cli+D2; 1× opus on J2+J3 | G, I-srv, J1 merged |
| L1 | next coordinated release | panel on the combined diff | wave 5 merged (D2 may be in, off by default) |
| 6 | C3, H (compose, runbook, deploy plan) | panel on C3+H | I-1 to I-5 merged in the Connect plan |
| L2 | Connect release, H deploy, K3 | panel on the combined diff | the Connect plan is live |

Judge panels (2× opus + 1× fable): C1, C2, F, A2, G, I-srv, I-cli, D2, C3, H, L1, L2. One opus judge: E2, J1, J2, J3. Fable is never in a fan-out; it is the third judge of each panel and the K1 reader.

Handoff format (every agent returns exactly this): `Unit`, `Base revision`, `Files changed` (absolute paths), `Interface` (types, functions, routes, schema), `Tests added` (names; "not run" or "cheap check run: <command>"), `Validation commands for the top-level agent` (exact), `Deviations from the plan`, `Open questions`, `Risks seen`. A judge returns, for each acceptance criterion: PASS / FAIL / UNVERIFIED with `file:line` evidence, the counter-example it tried, and a severity.

## Release grouping

Per AGENTS.md, each release bumps all six components to one version, also the components without a change. Run `python3 scripts/check-release-versions.py` with Python 3.12 before each.

| Release | Units | What the owner gets |
| --- | --- | --- |
| Next coordinated release after 0.5.16 (L1) | C1, C2, E2, F, G, J1, I-srv, I-cli + J2, J3; A2 (docs); D2 if merged, off by default | Stages 1 and 2 and own-server training: the bouncer brain and its training on the owner's server, the self-host image, merged shadow. Vault schema 29 (after 27 and 28). No account. |
| Connect release (L2, with the Connect plan) | C3, H, K3, and the Connect options in J1/J2 | Stages 3 and 4: Apassy Connect hosting and training |

## Required checks (ADR 0035) and their tests

| Check | Test |
| --- | --- |
| Unavailable server or wrong head hash asks the owner | C1 `a_409_a_401_or_a_wrong_head_hash_is_unavailable`; F `a_shadow_error_records_no_answer_and_the_active_decision_stands` |
| A server answer cannot cause a production run, a flag, secret output or a foreign host | C1 `a_hostile_brain_cannot_allow_production_a_flag_or_a_foreign_host` |
| No secret value in requests and examples | the synthetic-secret scans of C1, G and I-cli |
| A job head set starts in shadow mode | I-cli `a_remote_job_result_starts_in_shadow_mode_and_needs_promotion` |
| A change of a choice needs a fresh owner check | C2 `changing_the_hosting_or_training_needs_a_fresh_check`, `the_owner_window_never_covers_a_hosting_change` |
| After `DELETE /v1/owner`, nothing of the owner stays | D2 `test_multi_owner.py`; K3 on the live service |
| This Mac works with no account and no network | the existing local tests stay green; C2 `a_remote_url_in_bouncer_json_is_ignored` |

## Risks and unknowns (verified in the code)

- Memory on `ottervibe`: the first limits (3 + 4 GB) exceed the 6.9 GB available of 2026-11-02, and local training peaked at 2.92 GB RSS / 3.86 GB footprint on MPS (fine-tune.md 11.1). K1 measures the CPU numbers; the job start rule protects the production services.
- CPU training time at 2 vCPU is unknown (MPS: 75.6 s with the encoder cache). K1 measures it.
- The `External` monitor runs a warm-up inference every 10 s (`model_server.rs:77`, `:1160-1175`, `:1189`). Reused for a remote host, it would load the hosted service; C2 must change the cadence.
- The managed local server has no token today, so `PUT /v1/heads` answers 403 `no_token` on this Mac. C2's per-launch key fixes it; a server managed outside Apassy needs `APASSY_BOUNCER_KEY`.
- TLS trust: platform roots only (`TlsClient::platform`, `http.rs:146`). A private CA does not work; a Tailscale Serve certificate does. Pinning a self-signed certificate (as ADR 0037 D4 does on the tailnet) is not in this plan.
- `http::get` has no exchange deadline (`http.rs:225-228`) and the connector path uses it (`decide.rs:1333`); C1 adds new functions and does not change it.
- Schema numbers: 29 needs 27 and 28 first on the same branch. A schema-29 vault does not open in an older app, so the next release must update every Mac of a vault together.
- Merged shadow adds a head pass to the active request; K1 measures shadow on/off.
- MPS fp16 and CPU answers differ slightly; the equality rule of K1 sets the tolerance.
- CUDA image: over the 2 GB release-asset limit (GHCR only) and not tested on a GPU.
- arm64 image build: the GitHub arm64 runner is unverified; QEMU is slow.
- The Connect plan may change I-1 to I-5. C3, D2 and H follow it; until then they use the fakes.
- The VPS region is not yet confirmed as EU (H checks it, read-only).
