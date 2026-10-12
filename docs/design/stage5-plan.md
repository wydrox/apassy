# Plan: stage 5 (questions through the relay) and V3 (shared vaults)

Date: 2026-10-12. Branch: `feat/low-friction-access` (draft PR #15). App 0.4.1 is released; schema 18 is not. ADR 0025 §3d–§3e and ADR 0026 §6 are the decisions this plan implements.

## 0. Verified state

- App: `PendingRun.question: QuestionInfo` with `valid_answers` (`src/broker/approvals.rs`); the queue settles once; stricter answers go through `deny_stricter` (no check); `QUESTION_WAIT = 300 s` (`src/broker/server.rs`). `OwnerGate::authorize` is the only proof maker; `OwnerCheck::Companion` verifies `approve_string` only for `ApproveRun`/`ApproveAndRemember` (`owner_auth.rs`). The companion digest excludes `question` (`src/companion/digest.rs`).
- Relay membership in the app: one `relay_device` row per vault; `Session` (`src/sync/relay.rs`) signs in; the waiter thread in `sync_worker.rs` is sync-only. `vault_secret`, `shared_vault`, `item_share` exist in schema 18 with no API. `SharedVault` holds one open vault.
- Relay (`~/Dev/apassy-relay`, main 84a57fa; worktree `~/Dev/apassy-relay-sync` on `feat/vault-sync`): team schema 4, `tiny_http`, no HTTP/2 client, per-team notifier and 25 s long polls, `Need::{Member,Approver,Owner}`, 64 KiB JSON limit, audit masks tokens. The Worker forwards to the relay through Workers VPC. OPERATIONS.md has no rollback section.
- iOS: no `aps-environment`, no push code. The Secure Enclave approval key (`.biometryCurrentSet`) exists in `ApassyCompanionKit/SecureEnclaveKeys.signApproval`. Core FFI is one JSON call.

## A. Stage 5: questions through the relay

The relay routes opaque envelopes by role. The vault, not the relay, is the trust root for keys. The Worker sends push notifications without content.

### A1. Trust root and keys (schema 19, stream F19)

```sql
-- SYNCED, merged last-writer-wins like folder/shared_vault
CREATE TABLE trusted_device (uuid TEXT PRIMARY KEY, name TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('mac','iphone')), relay_device_id INTEGER,
  sign_key BLOB NOT NULL,            -- X9.63 65 B, the relay device key
  answer_key BLOB,                   -- iPhone: Secure Enclave key, biometryCurrentSet
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, updated_by TEXT NOT NULL, deleted_at INTEGER);
-- CHILD (V3): the mirror of a shared item
CREATE TABLE item_home (item_id INTEGER PRIMARY KEY, shared_vault_uuid TEXT NOT NULL, home_uuid TEXT NOT NULL);
-- LOCAL: one key pair per team (ADR 0019 §4), replaces the one-row relay_device
CREATE TABLE relay_membership (team_id TEXT PRIMARY KEY, relay_url TEXT NOT NULL, device_id INTEGER NOT NULL,
  public_key BLOB NOT NULL, key_pkcs8 BLOB NOT NULL, purposes TEXT NOT NULL /* JSON: sync|questions|share */, created_at INTEGER NOT NULL);
```

- Question key: `vault_secret 'question-key-v1'`, 32 random bytes, made by the first Mac that turns the feature on (`Vault::ensure_question_key`, new `src/vault/questions.rs`); every device that holds the vault gets it through its sync. Rotated when a device is removed (the keys of a removed device never register again); envelopes carry `key_id = hex(sha256(key)[..8])`.
- A Mac writes its own `trusted_device` row after its owner check; the row of an iPhone is written by the Mac that confirms its link, from the keys of the link (Gate 3; relay-questions-v1 section 5.2). The relay's device list is never the source of answer keys.
- Keep a compatibility accessor `Vault::relay_device()` over the membership with purpose `sync`; `tests/relay_sync.rs` must pass unchanged.

### A2. Envelope (contract `docs/contracts/relay-questions-v1.md`)

ChaCha20-Poly1305 (`ring::aead`, same code in `apassy-core`), AAD = `"apassy-question-v1\0" || team_id || "\0" || qid`.

```
POST /v1/questions            {v:1, qid:<b64u 16 B random>, to:"member"|"approvers", expires_at, key_id, nonce, ciphertext}
  plaintext QuestionCard: { qid, asker, run: {agent, command, cwd, env_names, purpose, risk, user_request,
    request_source, agent_request, remember}, question: {item_ids, items[], project{key,label}, action,
    production, why, valid_answers[]}, digest: <question digest v2>, created_at }
POST /v1/questions/{qid}/answers   {v:1, key_id, nonce, ciphertext}   -- relay stamps device_id, member_id, role, at
  plaintext Answer: { qid, by, kind, action?, project_key?, environment?, digest, time, signature }
  answer_string = "apassy-question-answer-v1\n<device uuid>\n<team id>\n<qid>\n<kind[:action[:project_key]] | correct_environment:<env>>\n<digest>\n<time>"
POST /v1/questions/{qid}/settle    {ciphertext}  -- {outcome, answered_by, device_kind}; asker only
GET  /v1/questions?since=N&wait=25
GET  /v1/questions/{qid}/answers?wait=25         -- asker only
PUT/DELETE /v1/push/token          {token, environment, bundle_id}
```

Question digest v2 (`src/companion/digest.rs`, tag `apassy-question-v2`) = the v1 input plus every `QuestionInfo` field. The v1 companion digest stays for the local-network path.

### A3. Relay: team schema 5

```sql
CREATE TABLE question (qid TEXT PRIMARY KEY, device_id INTEGER NOT NULL REFERENCES device(id), member_id INTEGER NOT NULL,
  to_approvers INTEGER NOT NULL CHECK (to_approvers IN (0,1)), key_id TEXT NOT NULL, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL,
  seq INTEGER NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('open','settled','expired')), settled_at INTEGER, settle_ciphertext BLOB);
CREATE TABLE question_answer (id INTEGER PRIMARY KEY, qid TEXT NOT NULL REFERENCES question(qid), device_id INTEGER NOT NULL,
  member_id INTEGER NOT NULL, role TEXT NOT NULL, key_id TEXT NOT NULL, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL, at INTEGER NOT NULL);
CREATE TABLE push_token (device_id INTEGER PRIMARY KEY REFERENCES device(id), token BLOB NOT NULL,
  environment TEXT NOT NULL CHECK (environment IN ('development','production')), bundle_id TEXT NOT NULL, updated_at INTEGER NOT NULL, failed_at INTEGER);
CREATE TABLE device_wrapped_key (device_id INTEGER NOT NULL REFERENCES device(id), name TEXT NOT NULL, wrapped BLOB NOT NULL,
  by_device INTEGER NOT NULL, at INTEGER NOT NULL, PRIMARY KEY (device_id, name));
```

- `migrate_v5` keeps `.pre-v5`, like `migrate_v4`. Routing set = live devices of the asking member, plus owners' and managers' devices when `to_approvers`. An answer from outside the set → 403 `not_routed`; after settle or expiry → 409; at most 3 answers per device per question.
- Limits: 300 questions per hour, 20 open. Expire at `expires_at`; delete rows after 24 h. Audit has device ids only.
- Accepted leak: `to_approvers` is one bit in the clear.

### A4. Push without content

The Worker sends APNs; the relay triggers it (`POST /internal/push` with an edge secret; `{tokens[], environment, collapse_id, expires_at}`). The Worker signs an ES256 JWT and posts `apns-push-type: alert`, priority 10, collapse id, expiration, payload `{"aps":{"alert":{"title":"Apassy","body":"A question is waiting"},"sound":"default","interruption-level":"time-sensitive"}}`. 410/`BadDeviceToken` marks the token failed.

- Secret: the `.p8` key is a Worker secret (`wrangler secret put APNS_KEY`, piped through Apassy); `APNS_KEY_ID`, `APNS_TEAM_ID=7S3F9767BM`, `APNS_TOPIC` are vars. Never in git, on the VPS, or in Docker.
- **Spike first:** from a preview Worker, a POST to `https://api.sandbox.push.apple.com/3/device/00` must return 403 `MissingProviderToken` (HTTP/2 works). Fallback: `h2`+`tokio` in the relay with the key file on the VPS.

### A5. Answers, signatures, replay

- `OwnerCheck::Remote { device_uuid, time, signature }` and `CheckMethod::Remote`. `OwnerGate::check_remote` loads the live `trusted_device`, rebuilds `answer_string` from the action and the digest v2, checks the proof lifetime (60 s slack), and verifies: iPhone → `answer_key` (Face ID) for ApproveRun, ApproveInProject, AllowProduction, correction to Development; Mac → `sign_key` after a local Touch ID for `OwnerAction::AnswerRemoteQuestion`. Stricter answers are signed with `sign_key` and need no check.
- Replay: random 128-bit qid; team, qid, kind, digest and time are signed; the queue settles once; the relay refuses answers after settle; 60 s window.
- First valid answer wins: the asker reads answers in order, skips invalid ones (bad signature, kind not in `valid_answers`, role below manager for production in a team) with an Activity line, applies the first valid one, and settles.

### A6–A9

- Teams: `to: "approvers"` when the question is production; otherwise the member's devices only.
- A personal vault without a relay account: a notifications-only team is an ordinary ADR 0019 team that never pushes a snapshot. Settings > Devices > "Notifications through the relay". iCloud stays the sync. The iPhone joins with a new core op `join_attach`. `RelaySync::disable` must not drop a membership that questions use; questions get their own waiter thread.
- Offline: the local card and the local-network companion are unchanged; relay posts retry within the 5 minutes; expired pushes are not delivered; late answers get "Already answered".
- iPhone: `ios-core-v1` gains `questions_list`, `questions_wait`, `question_open`, `question_answer`, `answer_key_register`, `push_token_set`. `QuestionsView` with the ADR 0026 bar. Entitlements: `aps-environment`, `remote-notification` background mode.

## B. V3 shared vaults (spike)

- A shared vault's relay team carries a **projection vault**: a SQLCipher file with only the shared items, written by the item owner's Mac from `item_share` rows (`src/vault/share.rs`), pushed with the existing transport. Members pull it and merge the items into their personal vault as read-only mirror rows (`item_home`). The broker, catalog, bouncer and iPhone still see one vault.
- No key holder: the projection key is a `vault_secret` in the owner's vault, wrapped per joining device (ECDH P-256 + HKDF + ChaCha20-Poly1305) into `device_wrapped_key`.
- One value: owner edits re-push the projection; mirrors are overwritten; local edits of mirrors are refused; removing a share deletes the mirror.
- Roles: members cannot reveal or copy mirrored values in the UI; managers and owners can. This is UI-enforced: a member's Mac holds the bytes (document in ADR 0026).
- Revocation: revoke the device, new projection key, re-wrap, re-push. Values already seen are not clawed back.

## C. Streams

| Stream | Files | Depends on | Needs the owner |
| --- | --- | --- | --- |
| F19 schema 19 | `src/vault/{types,mod,merge,relay_device}.rs`, `schema19.rs`, migration/sync tests, `ios/ApassyCore` mechanical | — | no |
| C0 contract | `docs/contracts/relay-questions-v1.md`, relay `docs/SPEC.md` §25 | — | no |
| N3 app questions | `src/questions/*`, `src/vault/questions.rs`, `src/relay/membership.rs`, `owner_auth.rs` (Remote), digest v2, Settings Devices, Decisions "answered on", `tests/relay_questions.rs` with a fake relay | F19, C0 | no |
| R4 relay | relay `store.rs` v5, `server/questions.rs`, `server/push.rs`, routes, limits, audit, Worker `apns.ts`, docs + rollback section | C0, A4 spike | spike, deploy |
| M3 iPhone | `ios/ApassyCore/src/core/questions.rs`, Swift `QuestionsView`, push registration, entitlements, contract | F19, C0 | APNs capability, profiles, TestFlight |
| V3 shared vaults | `src/vault/share.rs`, `src/sync/projection.rs`, sidebar, Share sheet, relay key-wrap routes | F19, R4 | relay deploy |

Order: F19 + C0 (+ A4 spike) → N3 ‖ R4 ‖ M3 → Gate 3 (2× opus + 1× fable: envelope, `check_remote`, replay, first valid answer, routing, push without content, membership migration) → owner steps → V3.

Owner steps: Apple Push capability, APNs `.p8`, new App Store profiles; Cloudflare for the spike and `wrangler secret put`/deploy; relay deploy with backup and rollback; operator team code; TestFlight upload; Gate 3 sign-off.
