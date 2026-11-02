# Apassy relay audit — 2026-10-31

## Scope and evidence boundary

Read-only senior review of `/Users/rafalw/Dev/apassy-relay-release-056`, commit **b8dc65e16664a7599c3f3c4b47b530c94b78ad1d**, package/Worker version **0.5.7**. Relay paths and line numbers below refer to that commit. App references marked **app** refer to `git show origin/main:<path>` at **af738b3c398782402db48fca47ed73b3580417b1**; the main checkout HEAD was **e13c1206654a435d9c53235a4979a38ff179488e**. The untracked app ADR `docs/adr/0028-retire-wifi-companion.md` was also read: it says **PROPOSED**, not accepted or retired. No claim here relies on the older memory's production state.

Reviewed README, SPEC, ONBOARDING, OPERATIONS, all HTTP route groups and their trust boundaries, device/team onboarding, sync storage/migrations/backups, questions/push/feed, proxy filtering, CLI auth/onboarding/services/install, deployment configuration, workflows, and relevant regression-test source. This is static review, not a whole-program proof. No relay files were changed; the owner's other relay checkout was not used. No cargo, Docker, installation, builds, SSH, authenticated production requests, or production mutations were performed. Test sources were inspected; suites and exploit reproductions were **not run**.

Public read-only checks at **2026-10-31 16:39 UTC**: `GET https://apassy-relay.wyderka.cc/healthz` returned **200**, body `ok`, version **0.5.7**, commit **b8dc65e16664a7599c3f3c4b47b530c94b78ad1d**; unauthenticated `GET /v1/me` returned **401**. These establish the public release identity and basic refusal only. Team health, actual compose/env/timers, backup recoverability, Worker bindings, APNs acceptance and physical-iPhone receipt remain **UNKNOWN**.

## Ranking

| Priority | Count | Meaning |
| --- | ---: | --- |
| P0 | 0 | No demonstrated immediate total compromise/data-loss emergency |
| P1 | 4 | Security, recovery, availability or promised core-path defect to address promptly |
| P2 | 10 | Material reliability, operations or product gap |
| P3 | 2 | Bounded usability/update improvements |

The app's 0.5.8 release has no new relay API prerequisite established by this review. The fixes below are candidates for a coordinated relay 0.5.8, not a statement that the current relay lacks questions or feed support. F04 and F11 need app work; a relay-only release cannot finish those journeys.

## P1 findings

### F01 — A demoted owner can finish a privileged mutation with cached authority

**Files:** `src/server/admin.rs:457`, `src/server/admin.rs:462`, `src/server/admin.rs:494`; `src/server/http.rs:995`; related pattern `src/server/devices.rs:294` and `src/server/sync.rs:884`.

**Impact:** Revocation/demotion is not authoritative at the mutation boundary. A concurrent request can restore an owner's role or change another member after its caller lost permission.

**Evidence:** HTTP authentication, including the post-body recheck, releases the store lock before dispatch. `role_change` trusts `by.role == Owner` outside its transaction. Inside it queries the **target**, not the current caller. Static interleaving: owner A's self-promotion request authenticates; owner B demotes A and commits; A's queued transaction observes A as a member and writes A back to owner using its cached principal. A can be a second owner without the key-holder flag, so the key-holder safeguard does not prevent this. Device revoke likewise checks cached `by.role`. In contrast, `devices::key_holder` re-reads the caller under the transaction (`devices.rs:335`). This is a code-supported race, not an executed exploit.

**Fix sketch:** Resolve the caller's live device/member and current required role on the same transaction that performs each security-sensitive write; apply consistently to role/revoke/grant/policy/invite, sync deletion and question/feed mutations. Keep the early HTTP check for resource protection. Add a deterministic barrier test: demote/revoke after initial auth but before mutation; the stale request must fail and cannot self-promote. **Size:** 1–2 implementer days for helper, callers and focused tests.

### F02 — A successful backup can contain heads without their snapshot files

**Files:** `src/server/hub.rs:1177`, `src/server/hub.rs:1188`, `src/server/hub.rs:1196`, `src/server/hub.rs:1255`; `src/server/sync.rs:871`; `deploy/vps/backup/apassy-relay-restore-test.sh:193`.

**Impact:** A manifest and matching checksums can certify an unusable sync backup. Recovery can lose the relay copy despite the backup and restore drill appearing successful.

**Evidence:** `backup` copies the team DB under its connection lock, releases it, and only then calls `copy_snapshots`, which acquires `sync_commit`. A concurrent `DELETE /v1/sync` between those steps removes all snapshot files after the backup captured their heads. Two pushes/pruning in that gap can also invalidate the captured retained versions. Directory copying and `directory.teams()` are separate operations, allowing a new team to appear in the manifest without its key in the copied directory. The restore script validates manifest hashes/counts and `active => open`; it never checks that each retained head has a matching file, size and digest. Normal backup tests (`tests/server_sync.rs:1277`) cover the sequential path.

**Fix sketch:** Freeze directory membership while taking the directory snapshot/team list; for each active team acquire `sync_commit` **before** copying its DB and retained snapshots, using the existing commit-before-store lock order. Publish the completed backup atomically. Extend the offline restore check to verify head/file/hash consistency, including suspended teams. Add forced concurrent delete/push/create backup tests. **Size:** 1–2 days.

### F03 — Byte caps do not bound slow requests; busy responses can block the accept loop

**Files:** `src/server/http.rs:579`, `src/server/http.rs:731`, `src/server/http.rs:840`, `src/server/http.rs:1291`; `src/server/sync.rs:590`; `deploy/worker/src/index.ts:90`, `deploy/worker/src/index.ts:324`.

**Impact:** Stalled uploads can occupy the shared member lane, delaying approvals, sign-in and health. Once full, an early 503 can itself hold the sole accept loop while its unread body is drained. The thread/process memory limits bound damage by outage/restart, not by timely refusal.

**Evidence:** JSON reads and snapshot reads have size checks but no application deadline/minimum-progress bound. Public edge-only POSTs read their body before device/code verification. `serve` calls `respond_busy(request)` synchronously when slots are full. The pinned tiny_http uses a length-delimited reader whose destructor reads the rest of an unread declared body; this can also occur after an early refusal. A legal-size body can therefore remain slow without violating the Worker's declared-length guard. Limiter exceptions/missing bindings fail open; the Worker has no explicit forwarding deadline. Actual Cloudflare/tunnel idle limits may reduce exposure, but their production settings were not inspected. The dependency's drain behavior is confirmed in [tiny_http 0.12.0 EqualReader](https://raw.githubusercontent.com/tiny-http/tiny-http/0.12.0/src/util/equal_reader.rs).

**Fix sketch:** Add origin read/write and header/body deadlines with cancellation, and bounded edge-route concurrency. Ensure rejection closes/cancels the underlying input without blocking the accept loop; adding a response `Connection: close` header alone does not establish that property. Consider a maintained HTTP server as part of F05. Preserve long-poll/large-upload allowances. Test legal-size stalled bodies, a full member lane plus a slow refused request, and that a separate health/approval request still answers. **Size:** 2–3 days; scope a focused mitigation before a larger server migration.

### F04 — Account-free approvals have a relay backend but no codeless app onboarding at the read app commit

**Files:** relay `src/server/hub.rs:659`, `src/server/http.rs:183`; **app** `src/relay/membership.rs:110`, `src/relay/membership.rs:217`, `src/relay/membership.rs:243`, `src/questions/worker.rs:842`.

**Impact:** A fresh Free/Personal vault without a relay membership cannot complete the promised no-account approval/push setup through this app path; the owner needs an operator team code or an existing sync team.

**Evidence:** Relay `POST /v1/connect` already creates a signed-key, one-owner questions team without a code; `sync_bytes=0` separates it from paid sync. At app `origin/main`, `NeedsTeam` and `new_questions_team` still require and validate an operator code, then call `/v1/teams`. A repository search of app `origin/main` found no `/v1/connect` implementation in `src`. The questions worker requires a `Questions` membership and a trusted local device before posting. This is an integration gap, not evidence that all existing Personal users lack push. A Personal vault with a notifications-only team can use the existing device/questions/push routes.

**Fix sketch:** Wire the app's no-account device-add flow to signed Connect creation, persist its key before the network write, adopt a questions-only membership, confirm the iPhone with safety words, transfer the question/answer keys, register APNs, and verify a cellular approval. Pair with recoverable Connect creation (F06). Do not require paid sync or a Stripe account for this path. **Size:** separate app task, roughly 2–4 days; relay needs no new basic routing primitive.

## P2 findings

### F05 — The pinned HTTP parser has published security reports and CI has no advisory gate

**Files:** `Cargo.lock:979`, `Cargo.toml:37`, `.github/workflows/ci.yml:28`; proxy header boundary `src/proxy/mod.rs:263`.

**Impact:** Parser/framing risk can survive green formatting, clippy and regression tests. Exploitability through Cloudflare must be established rather than assumed away.

**Evidence:** Lockfile pins `tiny_http 0.12.0`. Upstream tracks [CVE-2026-66752, Transfer-Encoding/request smuggling](https://github.com/tiny-http/tiny-http/issues/287) and [CVE-2026-66753, header injection](https://github.com/tiny-http/tiny-http/issues/288). These are reported dependency issues; this audit did **not** demonstrate a reachable exploit through the deployed Worker. The proxy explicitly rejects NUL header bytes, but that alone is not CR/LF validation. CI has no `cargo audit` job or saved audit output; npm CI explicitly skips audit. No tools were installed or audit command run. Rustls is already 0.23.46 (`Cargo.lock:673`), outside the affected ranges of the upstream [September handshake advisory](https://github.com/rustls/rustls/security/advisories/GHSA-2mjx-qc3c-rqvc) and [October session-debug advisory](https://github.com/rustls/rustls/security/advisories/GHSA-c8m5-c952-6cm4). This is not a complete dependency-clear result.

**Fix sketch:** Add a pinned RustSec CI scan and separately track CVEs missing from its database. Triage the two parser reports against the actual edge/VPC framing on a devbox; use a reviewed patched dependency/fork or maintained replacement, without guessing that an unreleased commit is a fix. Add malformed framing and CR/LF regression cases. **Size:** 0.5 day for the gate/triage; parser mitigation 1–3 days, potentially shared with F03.

### F06 — Lost Connect creation responses strand a team and consume scarce capacity

**Files:** `src/server/directory.rs:747`, `src/server/directory.rs:765`; `src/server/hub.rs:712`, `src/server/hub.rs:750`; related CLI `src/cli/onboarding.rs:102`.

**Impact:** A transient response loss turns first-run setup into operator recovery or key rotation; repeated attempts can leave unused teams inside the 100-team cap.

**Evidence:** The directory commits the team and one-use key before returning its id. Replaying the same valid signed Connect request returns `409 connect_key_used` and tells the client to make a new key; it does not return the existing team. Sign-in needs that now-lost team id. A cap-registration failure after commit similarly leaves the team out of service. Operator-code CLI creation preserves a staging key but explicitly requires the operator to find a possibly-created team after an ambiguous failure.

**Fix sketch:** Introduce proof-of-possession recovery/idempotency for an existing active Connect key, with a fresh challenge or bounded request id; never disclose/revive a deleted or suspended team from a replay. Return the original device/team identifiers only to the key holder. Preserve pending state in clients; test commit-then-response-loss and a retry after restart. This changes the documented one-use error behavior and needs a contract decision. **Size:** 1–2 days plus client integration.

### F07 — Push is a one-shot, memory-only, shared FIFO

**Files:** `src/server/push.rs:128`, `src/server/push.rs:251`, `src/server/push.rs:340`, `src/server/push.rs:355`; `src/server/questions.rs:564`; `deploy/worker/src/apns.ts:210`.

**Impact:** A brief Worker/APNs failure or relay restart can lose the only notification for an otherwise-valid question. Slow jobs ahead of another team delay it; queue reservations do not guarantee delivery latency.

**Evidence:** A single thread dequeues each job, makes a call bounded to 10 seconds, records failure and proceeds without retry. Jobs are not persisted or reconstructed at start. Thus two stalled jobs can delay a later question by about 20 seconds. Connect gets half the queue and two jobs per team, but shares the same sender. APNs fetches have no explicit timeout, and a job holds copied token targets without rechecking current revocation/expiry before dispatch. No APNs success code establishes physical receipt.

**Fix sketch:** Add a small bounded sender pool with per-team fairness, expiry-aware coalescing, current-token/live-device checks and jittered retries for transient errors; never retry final invalid-token errors indefinitely. Recover pending notification intent from a durable outbox or carefully bounded open-question replay. Audit drops/retry age as counts, never tokens. **Size:** 2–3 days; durable restart recovery can be a second patch if it requires a schema change.

### F08 — Green health and 401 can hide a failed team database

**Files:** `src/server/hub.rs:413`, `src/server/http.rs:762`, `src/server/http.rs:918`; `.github/workflows/health.yml:5`, `.github/workflows/health.yml:38`; `tests/server_teams.rs:628`.

**Impact:** Migration/disk/corruption failure for the owner's team looks like device removal to clients and remains invisible to the hourly public probe. Re-pairing can be the wrong recovery action.

**Evidence:** A team-open failure is logged and omitted from the hub; the process keeps serving `healthz => ok`. Valid tokens for the missing team get the same 401 as unknown teams. The checked-in regression test explicitly expects this degraded behavior. App `src/questions/client.rs:78` maps a post-sign-in 401 to `Removed`. The public workflow only checks liveness and unauthenticated refusal, at hourly cadence; compose health status alone does not restart an unhealthy-but-running container. No production incident is established.

**Fix sketch:** Keep team enumeration private and unknown-token responses uniform. Add an operator readiness/status check for expected active/open teams, DB writability/caps, last backup/restore success and push queue health, with safe alerts. Distinguish an authenticated known-team service failure where it can be proven without leaking team existence. Keep public liveness separate. **Size:** 1–2 days plus owner deployment/alert setup.

### F09 — Free onboarding has a hard capacity cliff and no packaged reclamation schedule

**Files:** `deploy/vps/compose.yaml:49`, `src/server/directory.rs:792`, `src/server/http.rs:868`, `docs/OPERATIONS.md:1184`; `src/server/hub.rs:1019`.

**Impact:** 100 active **or suspended** Connect teams stop new Free users until an operator deletes teams or raises capacity. Retrying in an hour cannot resolve a full count by itself.

**Evidence:** Compose sets 50 creations/day and 100 held teams; distinct keys from multiple networks can consume the room over days. The stored key lifetime rule is not Sybil resistance. The provided sweep is manual; OPERATIONS explicitly says its cron is not set up, and no sweep timer is provided. Idle suspension alone frees no seat; deletion is later. Full-count errors share `busy`/`Retry-After:3600`. Separately, append-only audit plus each Connect file's byte cap eventually requires operator action; this is an explicit existing owner policy, not permission to trim history.

**Fix sketch:** Add high-water/capacity alerts and a reviewed sweep timer with dry-run, retention and failure reporting; distinguish capacity exhaustion from short-lived busy in client guidance. Retain network/global creation caps. Measure on an explicitly selected devbox before increasing room. Preserve audit history unless the owner changes the policy. **Size:** 0.5–1 day plus retention/capacity decision and production installation.

### F10 — Pending CLI runs survive restart although their required one-time keys do not

**Files:** `src/server/hub.rs:1323`, `src/server/host.rs:70`, `src/server/approvals.rs:263`; default `src/config.rs:40`.

**Impact:** An agent can wait the remainder of a 10-minute approval timeout after a VPS restart for a run the host can no longer release.

**Evidence:** Run keys and proxy sessions live only in memory. Startup ends `ready` runs, but leaves `pending` rows. The host skips pending rows without a run key; lazy settlement times them out only at their old expiry. The lost keys must not be reconstructed from server data.

**Fix sketch:** At startup atomically finish orphaned pending runs with an explicit restart/interrupted reason and audit row; make CLI/MCP show a safe retry instruction. Do not automatically rerun the user's command. Test a pending run across restart and normal persisted question/feed behavior separately. **Size:** 0.5–1 day.

### F11 — Access requests still cannot reach the iPhone through the relay product contract

**Files:** **app** `docs/adr/0028-retire-wifi-companion.md:18`, `docs/adr/0028-retire-wifi-companion.md:40`; **app** `docs/contracts/relay-feed-v1.md:23`; relay `src/server/questions.rs:329`.

**Impact:** An agent requesting access to a credential can still require the owner to return to the Mac. Removing Wi-Fi UI does not supply this missing remote action.

**Evidence:** ADR 0028 explicitly marks access-request relay transport missing and retirement proposed. The feed reserves `grant_request` for a future contract. Relay questions transport opaque ciphertext, so the basic envelope carrier exists; the missing card/answer semantics, signing/owner checks and clients are principally app/iOS work. Do not equate a waiting run approval with an access-grant request.

**Fix sketch:** Decide deny-only versus Face-ID-authorized allow-once, define signed card/answer/settle semantics and then implement Mac+iPhone support before completing Wi-Fi retirement. Keep local approval available. Relay changes only if new outer metadata/limits are actually needed. **Size:** separate cross-app task; not a small relay release item.

### F12 — A feed deletion between polls can wait the next full long-poll interval

**Files:** `src/server/feed.rs:783`, `src/server/feed.rs:807`, `src/server/feed.rs:885`, `src/server/feed.rs:886`.

**Impact:** The iPhone can keep showing a removed publisher for up to an additional 25 seconds even though the relay already knows the feed is gone.

**Evidence:** Deleting the last feed advances `feed_change`. A subsequent `GET /v1/feed?since=<old>&wait=25` sees no newer feed rows. `list` initializes `first` from the **already-empty** `present`, so its completion checks see neither returned feeds, counter rollback nor a change from that first list. It does not finish on a forward counter change alone. Deletion during an existing poll wakes correctly; deletion just before it begins is the missing case. This is a static interleaving, not a measured live latency.

**Fix sketch:** Return an already-known deletion/cursor advance immediately, using a tombstone/member revision or a carefully specified forward-counter check. Avoid repeatedly waking a member for unrelated team changes. Add a regression test where deletion completes before the request starts. Normal publishing also intentionally waits up to 10 seconds (relay `feed.rs:49`, app `src/questions/worker.rs:145`); do not confuse that deliberate cadence with this defect. **Size:** 0.5–1 day.

### F13 — Installing a host for a second team replaces the first team's host service

**Files:** `src/cli/service.rs:14`, `src/cli/service.rs:46`, `src/cli/service.rs:354`, `src/cli/service.rs:387`.

**Impact:** The CLI supports several saved teams, but the owner's first team can stop processing new runs when they install a host for another team.

**Evidence:** Both launchd label and systemd unit are global constants. Generated arguments pin one `--team`. `host install` writes that same service path and restarts it, with no second-team conflict guard. App ADR 0019 section 9's single host for all teams remains unimplemented here.

**Fix sketch:** Small patch: detect an existing different-team service and explain its impact before replacement. Full fix: per-team services/logs or one supervised multi-team host with independent clients/keys. Test installing A, then B, and that A remains served under the chosen design. **Size:** 0.5 day guard; 1–2 days for per-team services.

### F14 — The operations guide mixes current release instructions with unsafe/stale commands

**Files:** `docs/OPERATIONS.md:3`, `docs/OPERATIONS.md:680`, `docs/OPERATIONS.md:929`, `docs/OPERATIONS.md:1198`, `docs/OPERATIONS.md:1256`, `docs/OPERATIONS.md:1286`; `.github/workflows/image.yml:24`.

**Impact:** Copying a later section can build on production or select an image tag that CI never produced, increasing deployment/rollback mistakes.

**Evidence:** The superseding header still demands 0.5.5 readbacks, while this checkout/public service are 0.5.7. Older sections retain `ssh ottervibe ... docker build`. Section 21 says the current workflow yields `feed-<sha>` with 3-day retention, while it now yields `release-<version>` and `sha-<full SHA>`, retained 7 days. The devbox measurement example uses bare `devbox up` and an ambiguous remote mount despite the current explicit arm/x86 policy. The warning that a fresh Worker deployment without staged ignored downloads removes CLI assets is accurate, but only a manual instruction.

**Fix sketch:** Publish one version-parameterized release/rollback runbook using CI image metadata and exact SHA, archive historical commands so they cannot be mistaken for active steps, correct devbox architecture/context/copy instructions, and add a deploy preflight requiring both CLI assets, checksums and release metadata. Preserve schema-6 rollback-check and journal precautions. **Size:** 0.5–1 day; docs/preflight only.

## P3 findings

### F15 — Script/agent output is inconsistent and help leads with expired legacy setup

**Files:** `src/cli/mod.rs:73`, `src/cli/args.rs:380`, `src/cli/args.rs:406`, `src/cli/args.rs:439`; `src/cli/client.rs:108`.

**Impact:** Agents must parse prose or use special cases for failures/mutations; new owners encounter member-token init and an `approve` command that always refuses.

**Evidence:** Most list commands have JSON success output, while `CliError` always becomes stderr prose and mutating commands lack a shared JSON result mode. `init` relies on legacy member tokens; live device enrollment disables those tokens and the migration deadline is enforced. `approve` is deliberately refused in favor of the key-holder host, but remains in the main command list.

**Fix sketch:** Add a consistent opt-in JSON envelope for success/errors with stable code, retry metadata and documented exit status; preserve child-command exit codes and one-time secret output. Lead help with create/join/device recovery and move legacy init into a compatibility section. Give subcommand help/examples. **Size:** 0.5–1 day.

### F16 — Installer/update feedback is weak for unsupported platforms and running hosts

**Files:** `deploy/worker/public/install.sh:19`, `deploy/worker/public/install.sh:25`, `deploy/worker/public/install.sh:61`, `deploy/worker/public/install.sh:101`; `.github/workflows/image.yml:66`, `.github/workflows/image.yml:118`.

**Impact:** Linux arm64 and Intel macOS users get a checksum-entry/download error instead of a platform explanation. Replacing the CLI can leave an already-running host on its old executable until restart.

**Evidence:** OS and architecture are accepted independently, but CI publishes only Linux x86_64 and Darwin arm64. Downloads have no explicit timeout. Installation verifies a same-origin SHA-256, then atomically replaces the binary and prints its version; there is no integrated update/status or running-host restart guidance. Same-origin hashes detect corruption, not compromise of that distribution origin.

**Fix sketch:** Validate the two supported OS/architecture pairs before fetching, bound download time, verify the staged executable before replacement, and print a precise service restart/version check when a host may be running. An update command or signed release manifest can follow separately. **Size:** 0.5 day for the bounded usability patch.

## Endpoint and security coverage

All non-health origin HTTP routes require the edge secret first (`src/server/http.rs:777`). Edge-only means that the public Worker adds the secret; it is **not** end-user authentication. The route table (`http.rs:140–312`) supplies these additional requirements:

| Surface | End-user authorization / reviewed boundary |
| --- | --- |
| `GET /healthz`; static `/install.sh`, `/guide`, `/dl/*` | Public by design; static files handled by Worker, read methods only |
| `POST /v1/teams`, `/v1/connect` | Operator one-use team code + device key, or signed Connect possession + prefix/daily/total limits |
| `POST /v1/join`, `/v1/devices/link`, `/cancel` | Team-bound invite/link code; pending join/device requires existing member confirmation and safety words before access |
| `/v1/auth/challenge`, `/token` | Live team/device key; 60-second nonce, consumed before validation, signed origin/team/key/nonce; access token 15 minutes, memory only |
| `/v1/me` | Member/device or agent token; team derived from token, no arbitrary team selector |
| Device enroll/list/link management/revoke, leave | Member; device-only restrictions in handlers; revoke restricted to own devices or owner; last sign-in-capable owner guarded |
| Device key-holder; member role/revoke | Owner; key-holder movement additionally resolves caller/target device under transaction; F01 identifies inconsistent transactional checks elsewhere |
| Invites/members/joins, policy/item/grant mutations, approvals/deny/audit | Owner or manager; joins recheck current approver role; manager cannot invite/promote owner; approve is refused server-side because keys stay on host |
| Collection/item listing, agent create/list/revoke | Member scope/grants/ownership enforced in handlers; agents bound to making device; device/member revocation terminates agents/sessions |
| `/v1/access`, `/v1/runs`, `/mcp` | Agent token, collection grants/rules and run ownership; real values released through key-holder host |
| `/v1/host/*` | Owner **and** current key-holder device (limited legacy bootstrap documented); role alone insufficient |
| `/v1/sync/*` | Live member device; snapshot signature/team/device/hash/CAS and transfer/byte limits; deletion owner device + If-Match; commit rechecks revoked uploader |
| `/v1/questions/*`, `/v1/push/token` | Live member device; per-member/approver routing, asker-only answers list/settle, byte/count/TTL caps; push topic/environment validated |
| `/v1/feed*` | Live device, same-member feed/action routing, counters/pace/byte/share caps; action cryptographic authority is checked by the app, not opaque relay ciphertext |
| Worker `/internal/push` | Separate push secret, fixed Apple destination/topic, bounded authenticated body/token list, no forwarding to origin |
| Operator admin | Filesystem-private Unix socket, no public HTTP endpoint; backup, limits, suspend/resume/delete privileged by local access |

No static cross-team data-access bypass was found in the inspected route/handler paths. This is not a security-clear verdict: F01, F03 and F05 remain material.

Additional observations:

- **Edge secret:** Worker replaces incoming edge/prefix/proof headers, constructs a fixed-origin target, uses manual redirects and VPC when bound (`index.ts:292–324`); origin comparison is constant-time. Prefix proof is domain-separated HMAC. No hardcoded secret value was found in inspected production source. Worker rate bindings are optional/fail-open and [Cloudflare documents them as approximate and local to each location](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/); retain origin guards. Validate HTTPS if the fallback origin is ever used.
- **Limits/replay:** JSON 64 KiB, feed JSON 352 KiB, ciphertext feed 256 KiB, snapshot 64 MiB and proxy request 8 MiB. These are size bounds, not deadlines (F03). Sign-in nonces, one-use codes, snapshot CAS/hash chain, question/action ids, expiry and app-signed answers provide replay boundaries. The codeless create signature is intentionally reusable but the key tombstone currently makes retries fail (F06).
- **Logs/privacy:** Worker source avoids URL/token/body logs and observability is disabled (`wrangler.jsonc:34`); enabling automatic request logs without filtering can expose proxy session keys in paths. Relay audit masks token forms, placeholders and **only currently-held session values** (`audit.rs:3–6`, `audit.rs:76`). Run command/purpose/request/cwd and names are durable team metadata (`decide.rs:344–372`), readable to approvers/operator via encrypted DB access. Arbitrary inline secrets unknown to the relay, or known values after their session ended, are not guaranteed redacted. Prefer client-side masking/minimal metadata; disclose this boundary. No secret-bearing log sample was collected.
- **Schema/recovery:** Team schema 6 and directory 1003 are distinct versions. Additive migrations make private `.pre-v3` through `.pre-v6` copies before transaction commit (`store.rs:381–497`, `store.rs:609`); failed teams stay out of service (F08). Schema numbers must not be bumped just to match 0.5.8. The checked-in rollback checker and hot-journal precautions are useful. A rollback can resurrect removed devices/teams from a backup; owner recovery must reconcile changes since that backup.
- **Container:** Non-root relay UID 10001, read-only rootfs, dropped capabilities, no-new-privileges, private secret mounts, constrained tmpfs, CPU/memory/PID limits, loopback-only published port and pinned tunnel image are good baseline controls. Writable data/backups remain in the relay's trust boundary. Relay base images and image-workflow actions are not all digest/SHA pinned; use recorded image ID/OCI SHA and an archived rollback artifact. The stock healthcheck is liveness, not restore/team/APNs readiness.
- **Paid plans:** This repository has no end-to-end Stripe/account entitlement provisioning workflow in the inspected server paths; operator-managed `TeamLimits`, including `sync_bytes`, enforce relay capacity. Decide integration separately; do not infer billing activation from a manual limit increase or create a new account requirement for Free approvals.
- **App errors:** At the read app commit, `src/questions/client.rs:38` retains the relay status/code but discards its detailed message; `src/questions/worker.rs:1218` maps quota refusal to an open-question explanation even when the relay refused an hourly/byte quota, and other refusals become generic local-only guidance. Coordinate stable reason/limit/retry fields with human-readable app copy; use an actionable capacity/service message for F08/F09 rather than telling a healthy device it was removed. Worker-origin failures currently return plain text 502/503 (`deploy/worker/src/index.ts:282`, `index.ts:326`), which clients deliberately collapse to unreachable; a JSON transport error can improve diagnosis without exposing the origin or secret.

## Ship in relay 0.5.8 — one-implementer shortlist

Sequential packages, no production access needed to prepare/review them. Estimates include focused regression tests in CI/devbox, not local builds on this nearly-full Mac.

| Order | Package | Finding | Size | Acceptance evidence |
| --- | --- | --- | --- | --- |
| 1 | Transactional caller authorization | F01 | 1–2 d | Barrier tests prove demotion/revocation wins over queued privileged mutations |
| 2 | Consistent backup + snapshot-aware restore validation | F02 | 1–2 d | Forced delete/push/create during backup yields a complete recoverable set or explicit failure |
| 3 | Request-deadline/parser mitigation + advisory gate | F03/F05 | 2–3 d initially | Slow/refused upload cannot block health/approval; framing reports triaged with source/patch and CI evidence |
| 4 | Connect creation recovery contract | F06 | 1–2 d | Lost acknowledgement recovers same active team with proof; deleted/suspended keys cannot revive it |
| 5 | Bounded fair push retries and expiry/live-token checks | F07 | 2–3 d | Simulated Worker timeout/429/5xx retries within question TTL; final bad token does not loop |
| 6 | Finish orphaned runs on restart + deletion-before-poll fix | F10/F12 | 1 d | Pending CLI run ends explicitly on restart; known deleted feed returns without a 25-second hold |
| 7 | One current CI-only release runbook and Worker asset preflight | F14 | 0.5–1 d | Exact image metadata selected; fresh checkout cannot deploy Worker without both verified downloads |

This is roughly **9–14 implementer days**, not a claim that every item fits a one-day release. For an immediate small relay 0.5.8, prioritize packages 1, 2, 6 and 7, then select a bounded F03/F05 mitigation before accepting internet-facing parser risk. Keep Free onboarding as a coordinated app task, not a hidden relay release prerequisite. If a package changes an API/schema, review its rollout/rollback explicitly; version-only publication must preserve production semantics.

## Production changes or owner decisions

| Item | Required owner/production action |
| --- | --- |
| Free/Personal onboarding | Decide the supported fresh-vault journey and merge the app's codeless Connect integration; test a real iPhone on cellular, with iCloud sync and no paid account. Existing Personal users need a checked membership/device/APNs path before declaring push fixed. |
| Wi-Fi retirement/access grants | Accept/revise ADR 0028 and choose deny-only versus Face-ID allow-once for access requests (F11). The file currently records a proposal, not completed retirement. |
| Connect recovery | Approve the change from permanent `connect_key_used` on any retry to possession-proven recovery (F06), preserving deletion/suspension semantics. |
| Capacity/retention | Inspect live active/suspended counts, file caps and free disk; approve/install a sweep schedule and alert thresholds. Do not silently prune append-only audit or increase room without devbox measurement. |
| Backups | After F02, perform an authorized isolated restore with head/file digest validation, including suspended teams; verify master-key backup separately, timer success/failure reporting and off-host freshness. A mirror with `--delete-after` is not an independent historical retention policy (`deploy/vps/backup/pull-backups.sh:46`). |
| Monitoring | Choose an alert destination and cadence; deploy operator readiness/capacity/backup/push checks. Keep raw URLs, request bodies, APNs tokens and auth headers out of telemetry. |
| Shipping | Build image and both CLIs only from the reviewed exact commit via GitHub `image-*`; archive verified artifacts/rollback image; stage both Worker downloads; deploy/restart only with release authorization. Read back health SHA/version and download hashes. No rollout occurred in this audit. |
| Paid sync/teams | Decide billing-to-limit provisioning and downgrade policy separately. Current manual operator limits are not evidence that Stripe/account activation is complete. |

## Verification record

- Git identity/status, source reads and targeted `rg`/`git show` searches: completed. Relay checkout started clean at the pinned SHA. App concurrent/untracked work was preserved; this report is the only intended write.
- Final relay `git status --short`, unstaged diff and staged diff: clean at the same pinned SHA. Report validation: 16 unique finding headings, priority counts 4/10/2, and cited local paths/line bounds checked successfully.
- Public GET liveness/unauthenticated refusal: completed with the limited results above.
- Primary external references: Cloudflare Worker [best practices](https://developers.cloudflare.com/workers/best-practices/workers-best-practices/), [Request framing documentation](https://developers.cloudflare.com/workers/runtime-apis/request/), current workerd types, tiny_http upstream source/issues, rustls upstream advisories. Dependency report scope is explicitly partial, not a `cargo audit` result.
- Not run: Rust/Worker suites, cargo audit, typecheck/build, shell operational scripts, container/server commands, production readiness probe, APNs send or physical-device test. Reproduction/check sketches above are requirements for subsequent implementation, not passed checks.

