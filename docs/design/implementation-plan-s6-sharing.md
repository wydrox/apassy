# Implementation plan — private sharing: way C, remote SigV4 signing, keys per member (ADR 0037 stage 6)

Date: 2026-11-03. Status: PLAN, written for the owner's decision of 2026-11-03 ("build everything in
the ADRs except the TEE track, as fast as possible, with many parallel agents"). Decision:
[ADR 0037](../adr/0037-own-relay-open-source.md) stage 6, section 10 (steps 1 to 3), D10, D11,
D13 (follows D12: nothing from the TEE track is here). Map row: `plan:s6-sharing` in
[adr-coverage.md](adr-coverage.md) (points 0037-23 to 0037-26). Format: [plan 0035](implementation-plan-0035.md),
[plan 0037](implementation-plan-0037.md).
Base inspected: `origin/release/0.5.16` at `4034c957`, vault schema 26 (`src/vault/types.rs:22`),
relay team schema 7 (`crates/apassy-relay/src/server/store.rs:31`), relay directory 1003.
Parallel plans: `implementation-plan-s4-teams.md` (stage 4: teams on nodes, members, the way A
switch) and `implementation-plan-s5-env-0011.md` (stage 5) are written at the same time as this one.
This plan names what it needs from stage 4 and what it builds before it (section "What waits for
stage 4").

## Outcome and constraints

A member's agent, a cloud agent, or the owner's own agent uses a provider with a credential that the
key holder made for that run: valid for minutes, narrowed to the run, and useless after it. The
long-lived secret never leaves the key holder (the owner's app, the node, or the team host). Where a
provider signs each request (AWS SigV4) and no short-lived credential is possible, the key holder
signs the request and the agent's machine holds only a placeholder. Where a provider has a
key-management API, each member gets a key of their own, and removing the member deletes that key.

- **Acceptance of the ADR:** a member's agent uses AWS with STS credentials that expire within 15
  minutes. The parts of this plan that need no member (the owner's own agents, cloud agents through
  the node) are the same code path and are accepted first with the owner's own agent.
- **Way C applies automatically (D11)** to every item whose provider and fields support it, in way A
  and in way B. Ways A and B then apply only to static keys. The owner can turn way C off for one
  item (an owner check); there is never a silent fall back to the long-lived value: a lease that
  fails fails the run (`lease_failed`).
- **Lifetimes.** AWS: `DurationSeconds=900`, the AWS minimum, so the ADR's 15 minutes is exact.
  Google: `generateAccessToken` with `lifetime: "900s"`. GitHub fixes installation tokens at one hour,
  so the node revokes the token when the run ends (`DELETE /installation/token`). OAuth: the
  provider's `expires_in`, and RFC 7009 revocation when the item has a revoke URL. A cloud session
  ends 30 seconds before its lease does.
- **No new crate.** HMAC-SHA256 and SHA-256 from `ring` (`ring::hmac`, `ring::digest`), RS256 from
  `ring::signature::RsaKeyPair` as `src/vault/passkey.rs:88` already uses it, Base64 from
  `crate::native::base64` as `src/broker/proxy/swap.rs:17` does, PEM armor stripped by ten lines of
  code, and the four elements of an STS answer read by a strict scanner instead of an XML crate.
- **Tests use local fakes.** Every provider call goes to a `ProviderEndpoints` value. Production has
  the real hosts over platform TLS. Tests have loopback `http://127.0.0.1:<port>` fakes written in
  the test files with `std::net` (the pattern of `tests/run_proxy.rs:53` and the TLS tests in
  `src/broker/http.rs:928`); the HTTP client already allows plain `http://` to the loopback only
  (`src/broker/http.rs:56-93`). No test needs a provider account.
- **Nothing is sealed to a device key on a node.** ADR 0037 section 10 step 1 says the host seals
  the credential to the member's device key. That mattered when the relay was a third party. On a
  node the host and the relay are one process, and the member's node reaches it over TLS pinned end
  to end (D4) or through Connect with TLS end to end. This plan delivers the lease in the session
  view over that channel and adds no second envelope. Chosen by this plan; the owner can change it
  (one more unit, after stage 4, with the question-envelope code of `src/questions/envelope.rs:135`).
- **Mac resources:** at most three implementation or validation workers on this Mac across all
  sessions. Workers never run lint, typechecks, builds, `cargo test`, or `cargo nextest`, also not
  through `heavy-check`; they return the exact commands. The top-level agent runs one validation pass
  per revision, preferably CI after an authorized push.
- **Releases:** each releasable group below bumps all six components to one version (AGENTS.md).

## Facts from the code (2026-11-03)

| Area | Fact | Where |
| --- | --- | --- |
| Run secrets | `read_secrets` reveals each item's process field; a `Placeholder` binding mints a placeholder and adds a `ProxySecret`; a `Value` binding puts the real value in `env`. `masks` is what the output masking hides. | `src/broker/run.rs:2724-2795` |
| Run proxy start | `RunProxy::start_with_access` starts the ADR 0011 proxy; the child gets `secrets.env`, `secrets.masks`, and the proxy variables. | `src/broker/run.rs:2019-2056` |
| Proxy auth positions | `swap_request` swaps a placeholder only in `Authorization`, the key headers, and the key query parameters; the body is streamed after the head went upstream, with a scanner that stops a placeholder in it. | `src/broker/proxy/swap.rs:225-297`, `mod.rs:890-1150` |
| Proxy headers | The proxy drops `accept-encoding`, `expect`, `te`, `proxy-*` before the upstream. | `src/broker/proxy/swap.rs:216` |
| Placeholders | `mint_placeholder` keeps the length and a known prefix and needs 64 random bits; `KNOWN_PREFIXES` has 40 entries. | `src/broker/proxy/swap.rs:21,68,163` |
| Binding | One `env_binding` row per item: `EnvBinding {item_id, env_name, field, delivery}`, `EnvDelivery::{Value, Placeholder(hosts)}`. One variable per item. | `src/vault/agents.rs:300-316`, `src/vault/add.rs:338` |
| Provider packs | `aws.json`: variable `AWS_ACCESS_KEY_ID`, host `amazonaws.com`, prefixes `AKIA`/`ASIA`, `real_value: true`. `gcp.json`: `GOOGLE_API_KEY`, `googleapis.com`, `real_value`, signal `service-account-key` by `json_fields.type = service_account`. `github.json`: `GITHUB_TOKEN`, prefixes include `ghs_` (installation) and `ghr_` (refresh). `cloudflare.json`: `api.cloudflare.com`, placeholder mode. | `packs/providers/*.json`; `src/vault/providers.rs:176,308` |
| Real value today | AWS and GCP credentials are delivered as the real value because the secret signs each request; the docs say a placeholder cannot sign. | `docs/operations/declarations.md:66-74`, `docs/operations/agent-path.md:190`, `tests/add_detected.rs:488-513` |
| AWS pair | A pasted `AWS_SECRET_ACCESS_KEY=…` and an `AKIA…` key are detected as two separate items. | `tests/add_detected.rs:488-497` |
| Items | `CredentialKind::{ApiKey, Login, SshKey, Database, Custom}`; fields are `Field {name, value, secret}`; `Vault::details(id)` gives field names, `reveal(id, field)` one value, `Vault::update` edits an item. | `src/contracts.rs:38`, `src/vault/types.rs:63,119`, `src/vault/mod.rs:443,523,559` |
| Vault schema | 26. The pattern of a schema module: `CLOUD_SCHEMA_VERSION`, `SCHEMA_V26_SQL`, `COLUMNS`, a `DOWNGRADE_TO_25_SQL` for tests, the chain in `migrate`. Local tables are listed in `merge::LOCAL_TABLES`. | `src/vault/schema26.rs:1-80`, `src/vault/mod.rs:1442-1452` |
| Node release | `outcome` maps the run to vault items, asks the broker, then requires `EnvDelivery::Placeholder` for every item and returns `Outcome::Release { values }`; `RunningNode::release(team, run, values, reason)`. | `src/node/host.rs:508-620` (the placeholder rule at `:552`), `src/node/backend.rs:317` |
| Node catalog | `eligible` refuses an item that is "not in placeholder mode", so AWS, GCP, and GitHub items (real value) cannot be offered to a cloud agent today. `CatalogItem` mirrors the relay item columns. | `src/node/catalog.rs:90-160` (`:107`), `src/node/backend.rs:117-146` |
| Embedded release | `release_values` requires `VALUE_ON_HOST` and `check_value` (printable ASCII without `"` and `\`, at most 4096 bytes, mintable), then `start_session` → `decide::env_items` → `sessions.create`, which mints a placeholder per item. | `crates/apassy-relay/src/server/host.rs:265-462`, `hostkeys.rs:240-253`, SPEC §11 |
| Session env | `env::build` sets `<ENV>` = placeholder, `APASSY_BASE_<ENV>`, provider base variables, `APASSY_RELAY_SESSION_EXPIRES`; `SessionView {env, placeholders, base_urls}`. `AWS_ENDPOINT_URL` is not set; "SigV4 is cut". | `crates/apassy-relay/src/server/env.rs:59-107`, `api.rs:808-817`, `docs/contracts/cloud-agents-v1.md` §8 |
| Relay items | `item` table: name, env_name, uid, sealed, provider, hosts, environment, risk, scope, reversibility; `ItemRow` the same. Team schema 7 with the `.pre-v7` copy rule. | `crates/apassy-relay/src/server/store.rs:31,61-67,907-926`, SPEC §30.4 |
| Relay routes | `route(method, path)` matches path segments to `Endpoint` with a `Need` (`Any`, `Edge`, `Member`, `Approver`, `Owner`, `Agent`). `Scope::Public` serves only `POST /mcp` and `/p/`. | `crates/apassy-relay/src/server/http.rs:272-330`, SPEC §30.5 |
| Relay proxy | `Proxy::serve` reads the whole request body (at most 8 MiB) before anything goes upstream, so a payload hash is available before the head is sent. | `crates/apassy-relay/src/proxy/mod.rs:34,196,467` |
| Member client | `apassy-team run` posts the run, polls, and spawns the child with `session.env`, after removing `CREDENTIAL_VARS`. It has no proxy of its own. | `crates/apassy-relay/src/cli/exec.rs:28-205` |
| HTTP client | `post_json` sends JSON with an optional bearer, 64 KiB answers, platform roots or extra roots, `http://` to the loopback only; no form body, no custom headers, no `PUT`/`DELETE`. | `src/broker/http.rs:20,56-93,134-160,282-346` |
| Crypto in the tree | `RsaKeyPair` and `RSA_PKCS1_SHA256` (passkeys), `EcdsaKeyPair::from_pkcs8` (device keys), `ring` 0.17.14 with `alloc`. No `rsa`, `hmac`, `sha2`, or `pem` as a direct dependency of the core. | `src/vault/passkey.rs:88`, `src/sync/relay_crypto.rs:154`, `Cargo.toml:53` |
| Owner checks | `OwnerAction::BindVariable` and `BindVariables` guard a change of the variable or its hosts; `ChangeItemRules` guards rules. | `src/broker/approvals/owner_auth.rs:329,365,372` |
| Items UI | The credential page shows ` · placeholder` after the variable; the variable sheet starts in placeholder mode when the provider hosts are known. | `src/desktop/ui/items.rs:3085-3100,3160-3178` |
| Broker context | `BrokerContext {vault, tls, approvals, approval_timeout, run_timeout, bouncer, model_gate, prompts}`; `BrokerOptions` is the place where tests inject values. | `src/broker/decide.rs:59-74`, `src/broker/server.rs:36-66` |
| Tests | One integration program `tests/it.rs` (`autotests = false`); `tests/run_proxy.rs:53` starts a fake TLS service with an rcgen certificate; relay tests have `MockUpstream::start(hosts)` with `extra_roots_der` and `resolve`, and `TestRelay` with `join_device`, `sign_in`, `add_item`, `release_body`, and the `CANARY` values. The node has its own fake backend tests. | `tests/it.rs:1-20`, `crates/apassy-relay/tests/common/{upstream,relay}.rs`, `src/node/tests.rs` |
| Command analysis | `aws sts get-session-token --duration-seconds 900` and `gcloud auth print-access-token` are already known secret-printing commands; `--aws-sigv4` is a known curl flag. | `src/broker/agent_items.rs:2325-2360`, `src/broker/shell_risk.rs:5163` |
| Trust model | `docs/security/trust-model.md` has "The rule", "Parties", "Not covered", "Cloud agents through Tailscale Funnel". | `docs/security/trust-model.md:7-59` |

## Decisions

Each one is chosen by this plan where the ADR leaves it open; the owner can change it.

| # | Decision | Choice |
| --- | --- | --- |
| S6-1 | Where way C runs | The key holder calls the provider with the long-lived secret and releases only the lease: the owner's app for local runs and for its node (cloud agents), the team host for members (stage 4). The agent's traffic goes direct to the provider. |
| S6-2 | What a lease is | `Lease { secrets: Vec<(name, value)>, plain: Vec<(name, text)>, expires_at, revoke: Option<Revoke> }`. The item's bound variable is the first secret. AWS adds the fixed names `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN` and the plain `AWS_CREDENTIAL_EXPIRATION` (RFC 3339; SDKs that ignore it lose nothing). The other kinds deliver one variable. |
| S6-3 | Vault model | A new synced table `short_lived` (item, kind, settings, enabled) decides delivery; `EnvDelivery` and `env_binding` stay as they are, so the many `match` sites on `EnvDelivery` do not change. A run with a `short_lived` item ignores the binding's delivery and uses the lease. |
| S6-4 | AWS call | `AssumeRole` when the item has `role_arn` (recommended: the role narrows the permissions), else `GetFederationToken` with the item's session policy or, when there is none, an allow-all policy (the result is still the intersection with the IAM user's own permissions; without a policy, `GetFederationToken` gives no permissions at all). `DurationSeconds=900`, `Name`/`RoleSessionName` = `apassy-<run id>`. `GetSessionToken` is not used: it cannot be narrowed. |
| S6-5 | Google call | Two steps on the host: a self-signed RS256 JWT of the service-account key → `oauth2.googleapis.com/token` gives a bootstrap token that never leaves the host; then `iamcredentials.googleapis.com` `generateAccessToken` with `lifetime: "900s"`, the item's scopes (default `cloud-platform`), for the item's `impersonate` account or the key's own `client_email`. Self-impersonation needs `roles/iam.serviceAccountTokenCreator` on the account itself (an owner step; the error text names it). |
| S6-6 | GitHub call | RS256 JWT (`iat` 60 s back, `exp` 9 min ahead; GitHub allows 10) → `POST /app/installations/{id}/access_tokens` with the item's `repositories` and `permissions`. Revoked at run end with `DELETE /installation/token`, best effort, audited. |
| S6-7 | OAuth refresh | `POST token_url` form `grant_type=refresh_token`, client auth as Basic or in the body (item setting). A rotated `refresh_token` in the answer is written to the item before the lease is delivered; a failed write delivers the lease anyway and writes an error activity row, because the old token is already dead. |
| S6-8 | Remote signing | The agent's SDK signs with the placeholder secret. The signing proxy verifies that signature against the placeholder (it proves the canonical request as the SDK built it), then re-signs with the real secret (local run proxy, relay proxy) or asks the host for the signature (`POST /v1/sign`, member's node). Only the `Authorization` header form; a presigned URL (`X-Amz-Signature` in the query) is refused, because it is a credential that others can use. `STREAMING-*` payload signing is refused with a reason. |
| S6-9 | What the sign endpoint sees | The canonical request text (method, URI, query, signed headers, payload hash) and the scope (date, region, service). It never sees the body. The audit row keeps method, path without the query, service, region, and the item; never a header value or a hash. |
| S6-10 | Keys per member | A `KeyManager` trait with two first providers: Cloudflare API tokens (`POST /client/v4/user/tokens`, with `expires_on` and `DELETE`) and AWS IAM access keys (`CreateUser` if missing, `CreateAccessKey`, `DeleteAccessKey`, `DeleteUser`). A member key is a new vault item of the team host, linked by the synced table `member_key`; the member's catalog shows that item instead of the team item. |
| S6-11 | More way C kinds | Cloudflare per-run tokens (the same API as S6-10 with `expires_on` = now + 15 min), PlanetScale passwords with `ttl`, and Neon roles (create, deliver, delete at run end) cover the "Cloudflare tokens with an expiry" and "temporary database roles" of ADR 0037 section 10. They are a separate unit (K) after the first two kinds exist. A Postgres wire client is not added. |
| S6-12 | Numbers | Vault schema 32 (31 is reserved by another plan; `schema32.rs` follows whatever is current at merge, and the top-level agent renumbers only if a lower number stays unused). Relay team schema: the next free version at merge time (8 if stage 4 has not taken it; the text below says 8). Contract `private-sharing-v1`. New codes `lease_failed`, `lease_revoke_failed`, `sign_refused`. |
| S6-13 | No iOS change | A way C run is a run: the question card lists its variables (`env_names`), the digests do not change. The iPhone shows the lease variables as it shows any variable. |
| S6-14 | Detection | A pasted `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` pair, or a service-account JSON, makes one item with the fields of its kind and `short_lived` on. An existing single-field AWS item gets "Add the secret key to make temporary credentials" in its sheet. |

## What waits for stage 4

Stage 4 (`implementation-plan-s4-teams.md`) brings members on a team host node, the member's node as
the client of the team host, and the way A switch. This plan builds first what needs no member:

| Built before stage 4 (single owner) | Needs stage 4 |
| --- | --- |
| The lease providers (C1, C2, K) and the SigV4 module, with fakes | — |
| Leases in the owner's own runs (F): the owner's agent gets STS credentials that expire in 15 minutes | — |
| Leases for cloud agents through the node (G): the session view carries the lease | — |
| SigV4 placeholders in the local run proxy (E1) and the relay proxy (E2) | — |
| The sign endpoint on the relay side (H), tested with a member device of the relay test harness | The member's node calling it from its own run proxy (L) |
| The key-management providers (J1), with fakes | Making a key when a member gets a grant, deleting it on removal (J2) |
| The item sheet, badges, and docs (I) | The collection setting texts of the way A switch for way C items (L) |

The ADR acceptance (a member's agent) is unit L. Its code path is the one that F and G accept with
the owner's own agent first.

## Work units and ownership

One editor owns each shared file at a time. Paths are current unless labelled "proposed". Every unit
adds its tests to `tests/it.rs` (a `mod` line per new file) or to the relay crate's `tests/`, and
names them below. Every test that holds a long-lived synthetic secret scans what the agent could see
(the child's environment, the run output, the session view, the audit rows, the activity log) for
that secret and fails if it is there.

### A — Contract `private-sharing-v1`

- Purpose: one wire and storage contract before any code: the way C kinds, their fields and settings,
  the lease, the session view additions, the sign endpoint, the audit rows, the codes.
- Files: proposed `docs/contracts/private-sharing-v1.md` (format of `relay-access-request-v1.md`:
  Date/Status/Decision lines, numbered sections, MUST/MUST NOT); proposed
  `tests/fixtures/private-sharing-v1/` (a `short_lived` settings object per kind, a lease, a
  `SessionView` with `short_lived` and `signers`, a sign request and answer, each error); a fixture
  check in `tests/contracts.rs`; one paragraph in `docs/contracts/cloud-agents-v1.md` §8 that points
  to it (the table there stays; G edits the table).
- Content:
  - Kinds and fields: `aws_sts` (`access_key_id` plain, `secret_access_key` secret; settings
    `role_arn?`, `policy?` (JSON text), `region?`, `services?`), `github_app` (`app_id`,
    `installation_id` plain, `private_key` secret PEM; settings `repositories?`, `permissions?`,
    `api_url?`), `google_service_account` (`key_json` secret; settings `scopes`, `impersonate?`),
    `oauth_refresh` (`client_id` plain, `client_secret?` and `refresh_token` secret; settings
    `token_url`, `revoke_url?`, `scope?`, `client_auth: basic | body`). Unit K adds
    `cloudflare_token`, `planetscale_password`, `neon_role`.
  - The lease: `secrets`, `plain`, `expires_at`, `revoke`. Fixed variable names per kind.
  - `SessionView.short_lived: [{item_id, kind, env_names, expires_at}]`; such variables are not in
    `placeholders` and have no base URL. `SessionView.signers: [{item_id, env_name, access_key_id}]`
    (the secret variable holds a placeholder as today). `AccessItem.delivery`:
    `placeholder | temporary_credentials | signed_requests`.
  - `POST /v1/sign` (Need::Member): `{session_id, item_id, scope: {date, region, service},
    canonical_request}` → `{signature}` (64 lowercase hex). 403 `sign_refused` for a session that is
    not live or not the member's, an item not in the session, a host that the item does not cover,
    a `STREAMING-*` or `UNSIGNED-PAYLOAD` hash with a body, or more than 120 requests a minute for
    one session. Body at most 64 KiB.
  - Codes: `lease_failed` (the run does not start; the message names the provider's status, never
    its body), `lease_revoke_failed` (an activity row only), `sign_refused`.
  - Audit and activity: `lease_made` (item, kind, expires_at, run), `lease_revoked`,
    `sign_request` (method, path without query, service, region, item). Never a value, a placeholder,
    a token, a hash, or a header.
  - The no-secret rule: no answer, row, log line, or error text holds a long-lived value, a lease
    value, or a signature.
- Owner: implementer (opus, high). Depends on nothing. Judge panel: 2× opus + 1× fable.
- Acceptance: every fixture parses with the strict rules (unknown field refused);
  `contracts::private_sharing_v1_fixtures_match_the_contract` (new) passes; the contract states the
  no-fallback rule (S6-1), the presign refusal (S6-8), and the no-secret rule.

### B — HTTP client: form bodies, custom headers, `PUT` and `DELETE`

- Purpose: the providers need `application/x-www-form-urlencoded` bodies (OAuth, STS), their own
  headers (`X-Amz-Date`, `Authorization: AWS4-HMAC-SHA256 …`, `Accept: application/vnd.github+json`),
  and `DELETE` (GitHub revoke, Cloudflare, IAM through form `Action=`).
- Files: `src/broker/http.rs` only.
- Change: `pub struct HttpRequest<'a> { method, path, headers: &[(&str, &str)], body: &[u8],
  content_type }` and `pub fn send(destination, request, timeout, tls) -> Result<HttpResponse,
  HttpFailure>`; `post_json`, `post_json_loopback`, `get`, and `get_health` become wrappers with their
  bytes unchanged (`requests_are_built_in_exact_buffers_with_unchanged_bytes` at `:780` keeps
  passing). A header name or value with a control character is `Protocol`. The 64 KiB cap stays.
  `pub type Resolve` and a `send_with(resolve)` stay private; tests use loopback `http://`.
- Owner: implementer (opus, high). Depends on nothing. Judge: 1× opus.
- Acceptance (unit tests in `http.rs`): `a_form_post_sends_the_exact_bytes`,
  `a_delete_with_a_bearer_sends_no_body`, `a_header_with_a_control_character_is_protocol`, and the
  existing deadline tests unchanged.

### C1 — Lease core, SigV4, and AWS STS

- Purpose: the pure provider code for AWS, and the SigV4 module that E and H reuse.
- Files: proposed `src/lease/mod.rs` (`LeaseKind`, `LeaseSource { kind, fields: Vec<Field>,
  settings: serde_json::Value }`, `Lease`, `Revoke`, `LeaseError { code, status, message }`,
  `ProviderEndpoints { sts, github, google_token, google_iam, cloudflare, aws_iam, planetscale, neon:
  DestinationUrl }` with `::production()` and the `mod` lines for C2 and K), proposed
  `src/lease/sigv4.rs` (`parse_authorization`, `canonical_request(method, uri, query, headers,
  signed_headers, payload_hash)`, `string_to_sign`, `signing_key(secret, date, region, service)`,
  `signature`, `sign_request` for the client side), proposed `src/lease/aws.rs` (`AssumeRole`,
  `GetFederationToken`, the strict scanner for `AccessKeyId`, `SecretAccessKey`, `SessionToken`,
  `Expiration`), proposed `src/lease/scan.rs` (the no-secret scan used by every test of this plan:
  `assert_no_secret(haystack, secret)`), `src/lib.rs` (the `pub mod lease;` line behind `vault`).
- Design: `pub fn acquire(source, scope: RunScope { run_label, ttl_wanted }, endpoints, tls) ->
  Result<Lease, LeaseError>` and `pub fn revoke(lease, endpoints, tls) -> Result<(), LeaseError>`.
  Deadline 20 s for the whole exchange. Every secret in `Zeroizing`. The STS request is SigV4-signed
  with the long-lived key (service `sts`, region from the settings or `us-east-1`, endpoint
  `sts.<region>.amazonaws.com`). The answer's `Expiration` must be at most 900 s after the request,
  else `LeaseError` (a provider that ignores the duration never gives a longer lease). The session
  policy, when given, must parse as JSON and be at most 2048 bytes (the STS limit).
- Owner: implementer (opus, high). Depends on B. Judge panel: 2× opus + 1× fable.
- Acceptance (unit tests in the files, with a fake STS on the loopback that verifies the incoming
  SigV4 with the test's secret): `sigv4_matches_the_aws_test_vectors` (the `get-vanilla`,
  `post-vanilla-query`, `get-header-value-trim`, and `post-x-www-form-urlencoded` vectors of the AWS
  SigV4 test suite, embedded as constants), `assume_role_gives_asia_credentials_that_expire_in_900s`,
  `get_federation_token_sends_an_allow_all_policy_when_the_item_has_none`,
  `a_longer_expiration_than_asked_is_refused`, `a_4xx_from_sts_is_lease_failed_without_the_body`,
  `the_long_lived_secret_is_not_in_the_lease_or_the_error` (scan). No `unsafe`, no new crate.

### C2 — GitHub App, Google service account, OAuth refresh

- Purpose: the other three kinds of ADR 0037 section 10 step 1.
- Files: proposed `src/lease/jwt.rs` (RS256 compact JWT with `RsaKeyPair::from_pkcs8` and
  `from_der` for PKCS#1, PEM armor stripped), `src/lease/github.rs`, `src/lease/google.rs`,
  `src/lease/oauth.rs`.
- Design: as S6-5, S6-6, S6-7. GitHub: `api_url` default `https://api.github.com`; the answer's
  `token` (`ghs_…`) and `expires_at`; `Revoke::Github { token }`. Google: the bootstrap token is
  dropped after the second call; `expireTime` of the answer must be at most 900 s ahead. OAuth:
  `expires_in` is the real expiry; without a revoke URL, a missing `expires_in` or one over 3600 s
  is `lease_failed`, and with one a missing `expires_in` shows one hour and the activity row says the
  expiry is unknown (C1/C2 security review, 2026-11-03); `Revoke::Oauth { revoke_url,
  token }` when the item has a revoke URL. A rotated refresh token is returned in
  `Lease.update_field: Option<(field, value)>` for the caller to store (F and G store it before
  delivery).
- Owner: implementer (opus, high). Depends on B, C1 (for `mod.rs` and the scan). Judge panel:
  2× opus + 1× fable.
- Acceptance (unit tests with loopback fakes): `a_github_app_jwt_is_rs256_with_a_short_expiry`
  (the fake checks the JWT signature with the test key and the `exp` ≤ 600 s),
  `an_installation_token_is_delivered_and_revoked`, `a_google_lease_asks_for_900s_and_drops_the_bootstrap_token`
  (the fake IAM endpoint sees the bootstrap bearer; the lease holds only the short token),
  `an_oauth_refresh_returns_the_rotated_token_for_storage`, `a_provider_error_body_never_reaches_the_message`,
  `no_long_lived_secret_in_any_lease_or_error` (scan over all three).

### D — Vault schema 32: `short_lived`, `member_key`, detection, and the owner check

- Purpose: the vault knows which items are way C sources, keeps their settings, and makes such items
  from a paste.
- Files: proposed `src/vault/schema32.rs`, proposed `src/vault/short_lived.rs` (`ShortLived {kind,
  settings, enabled}`, `Vault::short_lived(item)`, `set_short_lived`, `short_lived_source(item) ->
  LeaseSource` that reads the fields of the kind, `member_key` rows), `src/vault/mod.rs` (the
  migration chain and `verify_expected_columns`), `src/vault/merge.rs` (both tables sync: they hold
  no secret), `src/vault/sync.rs` as the schema 25 pattern needs, `src/vault/detect.rs` and
  `src/vault/add.rs` (S6-14), `src/broker/approvals/owner_auth.rs` (`OwnerAction::ChangeDelivery
  { item, kind, on }` with its description), `src/desktop/owner_check.rs` (its text),
  `tests/vault_migration.rs`, `tests/sync_schema_upgrade.rs`, `tests/add_detected.rs`.
- Schema (synced tables):

  ```sql
  CREATE TABLE short_lived (
      item_id INTEGER PRIMARY KEY REFERENCES item(id),
      kind TEXT NOT NULL CHECK (kind IN ('aws_sts','github_app','google_service_account',
          'oauth_refresh','cloudflare_token','planetscale_password','neon_role')),
      settings TEXT NOT NULL DEFAULT '{}',
      enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
      created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
  CREATE TABLE member_key (
      item_id INTEGER PRIMARY KEY REFERENCES item(id),
      source_item_id INTEGER NOT NULL REFERENCES item(id),
      team_id TEXT NOT NULL, member_id INTEGER NOT NULL,
      manager TEXT NOT NULL CHECK (manager IN ('cloudflare_token','aws_iam')),
      remote_id TEXT NOT NULL, created_at INTEGER NOT NULL);
  ```

  `settings` never holds a secret (role ARN, policy, scopes, URLs, repository names). A device on
  schema 31 or earlier refuses a copy of schema 32 (`UnsupportedSchema`), as 26 does for 25.
- Detection: a paste with both AWS variables, or an `AKIA…` key next to a 40-character secret, makes
  one `Custom` item with `access_key_id` and `secret_access_key`, the variable `AWS_ACCESS_KEY_ID`,
  and `short_lived` `aws_sts` on. A service-account JSON makes one `Custom` item with `key_json`, the
  variable `CLOUDSDK_AUTH_ACCESS_TOKEN`, and `google_service_account` on. The kind is `Custom`, not
  `ApiKey`: an `ApiKey` item needs a secret `token` field, so the vault refused these items and the
  whole paste with them (C1/C2 security review, 2026-11-03). The main secret of a `Custom` item is its
  first secret field (`secret_access_key`, `key_json`), the field of the variable. A `ghr_` token or an
  `app_id`/`installation_id`/PEM paste is not detected (the owner fills the sheet, unit I).
- Owner: implementer (opus, high). Depends on A. Judge panel: 2× opus + 1× fable (migration, sync).
- Acceptance: `vault_migration::schema_32_adds_short_lived_and_member_key` (31→32, and a failed
  migration keeps 31), `sync_schema_upgrade::a_schema_31_device_refuses_a_schema_32_copy`,
  `relay_sync::short_lived_settings_sync_and_hold_no_secret` (the pushed copy is scanned for the
  synthetic secret), `add_detected::an_aws_pair_becomes_one_short_lived_item`,
  `add_detected::a_service_account_json_becomes_a_short_lived_item`,
  `owner_auth::changing_delivery_needs_the_owner_check`.

### E1 — SigV4 placeholders in the local run proxy

- Purpose: an AWS item can be in placeholder mode on the owner's Mac: the SDK signs with the
  placeholder, the proxy verifies and re-signs. ADR 0011 "What this mode does not protect" loses its
  SigV4 line.
- Files: proposed `src/broker/proxy/sigv4.rs` (`SigV4Signer::{Local(secret), Remote(Box<dyn
  RemoteSigner>)}`, `pub trait RemoteSigner { fn sign(&self, scope, canonical_request) ->
  Result<[u8; 32], SignError> }`, `verify_and_resign(head, body_hash, placeholder, signer)`),
  `src/broker/proxy/mod.rs` (`ProxySecret.signer: Option<SigV4Signer>`; in `serve_requests`, when
  `Authorization` starts with `AWS4-HMAC-SHA256` and the `Credential` names a host of a signing
  secret: buffer the body up to 8 MiB (413 above), compute the payload hash or take
  `x-amz-content-sha256`, verify, re-sign, send the head with the new `Signature=` (same length),
  then the buffered body; keep every header that `SignedHeaders` lists, `accept-encoding` included,
  and mark the answer "not checked" when it is compressed, as today), `src/broker/proxy/swap.rs`
  (`Refusal::Signature { index, reason }`), `src/broker/run.rs` (`read_secrets`: an item with
  provider `aws` and `EnvDelivery::Placeholder` gets a `Local` signer; the access key id field of the
  same item, when the item has one, is delivered as a plain variable `AWS_ACCESS_KEY_ID`),
  `packs/providers/aws.json` (`real_value` stays `true` for the detection default; the owner can
  choose "Placeholder" in the sheet), `docs/adr/0011-run-proxy-placeholders.md` (a dated note),
  `docs/operations/agent-path.md` §8b and `declarations.md` (the AWS row).
- Design: the verification uses the request as received (host and path as the SDK built them); for
  the local proxy that is also the upstream form. A request whose signature does not verify against
  the placeholder is 403 with "The program signed the request with something other than the
  placeholder." A presigned URL or `STREAMING-*` is 403 `not_supported` with the reason. The event
  outcome is `swapped` with the variable name; `reason` says "re-signed".
- Owner: implementer (opus, high). Depends on C1 (the `sigv4` functions move to or are reused from
  `src/lease/sigv4.rs`: C1 owns that file; E1 only calls it). Judge panel: 2× opus + 1× fable.
- Acceptance (`tests/run_proxy.rs`, with the fake service of `:53` extended to verify SigV4 with the
  real test secret): `an_aws_request_signed_with_the_placeholder_is_re_signed`,
  `a_presigned_url_is_refused`, `a_streaming_payload_is_refused`,
  `a_wrong_signature_sends_nothing_upstream`, `the_real_secret_is_not_in_the_child_environment`
  (scan), and, when the `aws` CLI is on the machine, `the_aws_cli_lists_with_a_placeholder_secret`
  (skips without the CLI; the fake answers an S3 `ListBuckets` XML).

### E2 — SigV4 in the relay proxy and `AWS_ENDPOINT_URL_*` for cloud agents

- Purpose: a cloud agent whose AWS item is not a way C source (no STS possible) uses way B: the node
  re-signs. Lower priority than way C; last in release 2.
- Files: `crates/apassy-relay/src/proxy/mod.rs` and `swap.rs` (the same branch as E1, using
  `apassy::lease::sigv4`; the body is already buffered), `crates/apassy-relay/src/session.rs`
  (`SessionSecret.signer`), `crates/apassy-relay/src/server/env.rs` (`AWS_ENDPOINT_URL_<SERVICE>` =
  `base(<service>.<region>.amazonaws.com)` for the item's `services` and `region`;
  `AWS_ENDPOINT_URL` is not set because each service has its own host), `docs/contracts/cloud-agents-v1.md`
  §8 (the SigV4 line), SPEC §11 and §12.
- Design: the verification uses the request as the SDK built it (host `<Mac>.<tailnet>.ts.net:8443`,
  path with the `/p/<key>/<host>` prefix); the re-sign uses the upstream form (host = the upstream
  host, path without the prefix). Both are deterministic from the one request. A signed header that
  the proxy would drop (`accept-encoding`) is kept for such a request.
- Owner: implementer (opus, high). Depends on E1, G. Judge panel: 2× opus + 1× fable.
- Acceptance (`crates/apassy-relay/tests/proxy_flow.rs` with `MockUpstream` verifying SigV4):
  `a_cloud_agent_request_signed_with_the_placeholder_reaches_aws_re_signed`,
  `the_endpoint_variables_name_the_services_of_the_item`, `a_presigned_url_is_refused`, and the audit
  row has no signature.

### F — Leases in the owner's own runs

- Purpose: the owner's agent gets temporary credentials. This is the first acceptance of the ADR's
  code path, with a single owner.
- Files: `src/broker/run.rs` (`read_secrets`: for each item with `short_lived.enabled`, build the
  `LeaseSource`, `acquire`, push each lease secret into `env` and `masks` and each plain variable into
  `env`; collisions of lease names with other bindings or `RESERVED_VARIABLES` are `invalid_request`
  before the owner is asked; a rotated refresh token is stored with `Vault::update` before the
  process starts; after `exec` returns, `revoke` each lease, best effort; the activity reason gets
  "temporary credentials for N minutes"; the wire answer gets `leases: [{item_id, kind, env_names,
  expires_at}]`), `src/broker/decide.rs` (`BrokerContext.providers: Arc<ProviderEndpoints>`),
  `src/broker/server.rs` (`BrokerOptions.providers`, production by default),
  `src/broker/agent_items.rs` (`list_access` catalog: `env_holds: "temporary credentials"`,
  `extra_env_names`, `lease_secs`), `src/broker/approvals.rs` (the question's `env_names` include the
  lease names), `docs/contracts/broker-v0.md` (the new fields), `src/bin/apassy-eval.rs` if
  `BrokerOptions` construction changes there.
- Design: the lease is made after the owner's decision and the second check, inside the vault
  session, right before `read_secrets` returns, so a denied run makes no provider call. One deadline
  of 20 s per lease. `lease_failed` records an activity row with the provider's status and the
  item; the command does not run. The long-lived value is read into a `Zeroizing` buffer for the
  call and dropped before the process spawns. The evaluation entry point `evaluate_run` makes no
  provider call.
- Owner: implementer (opus, high). Depends on C1, C2, D. Judge panel: 2× opus + 1× fable.
- Acceptance (proposed `tests/short_lived_runs.rs`, a module of `tests/it.rs`, with the loopback
  fakes of a proposed `tests/support/fake_providers.rs`: `FakeSts` verifies SigV4 with the test
  secret, `FakeGithub` records the `DELETE`, `FakeGoogle`, `FakeOauth` rotates the refresh token):
  `an_aws_source_run_gets_asia_credentials_that_expire_within_900s` (the child prints its
  environment; `AWS_ACCESS_KEY_ID` starts with `ASIA`, the three secrets are masked in the output, the
  long-lived secret is in neither the environment nor the output nor the activity log),
  `a_lease_failure_runs_nothing_and_delivers_nothing`, `a_github_lease_is_revoked_after_the_run`,
  `a_rotated_refresh_token_is_stored_before_the_process_starts`,
  `lease_variable_names_cannot_collide_with_another_binding`,
  `a_denied_run_makes_no_provider_call`, `list_access_says_temporary_credentials`.

### G — Leases for cloud agents through the node

- Purpose: a cloud agent's session carries the lease; the long-lived value stays in the vault.
- Files: `src/node/backend.rs` (`CatalogItem.delivery: Delivery::{Placeholder, ShortLived(kind),
  Signed}`; `RunningNode::release(team, run, values: Vec<Released>, reason)` with
  `Released::{Value(NodeSecret), Direct { secrets: Vec<(String, NodeSecret)>, plain:
  Vec<(String, String)>, expires_at }, Signer { access_key_id, secret }}`), `src/node/catalog.rs`
  (a `short_lived` item is eligible without placeholder mode; its hosts are the provider's known
  hosts), `src/node/host.rs` (`outcome`: a `short_lived` item gets a lease instead of its value;
  `Outcome::Release` carries `Released`; a session that ends triggers `revoke`; a rotated refresh
  token is stored as in F), `src/node/tests.rs`, `crates/apassy-relay/src/embedded.rs` (the
  `Released` mapping), `crates/apassy-relay/src/server/host.rs` (`release_values` takes
  `Vec<ReleasedValue>`; `check_value` applies to each secret of a lease, not to plain variables),
  `crates/apassy-relay/src/server/decide.rs` (`env_items` carries the delivery),
  `crates/apassy-relay/src/server/env.rs` (lease variables plain in `env`, not in `placeholders`,
  no base URL; `short_lived` list; a name collision between items is `release_invalid`),
  `crates/apassy-relay/src/server/sessions.rs` and `session.rs` (lease secrets in the masks and in
  `secrets` for the answer replacement; `expires_at = min(now + ttl, lease − 30 s)`),
  `crates/apassy-relay/src/api.rs` (`SessionView.short_lived`, `AccessItem.delivery`),
  `crates/apassy-relay/src/server/admin.rs` (`checked_item`, `insert_item`, `item_update`,
  `access` carry `delivery`), `crates/apassy-relay/src/server/store.rs` (team schema 8:
  `ALTER TABLE item ADD COLUMN delivery TEXT NOT NULL DEFAULT 'placeholder'`, the `.pre-v8` copy,
  `downgrade-schema-7` as 30.4), `crates/apassy-relay/src/cli/exec.rs` (print the lease expiry on
  stderr and refuse to start a child whose lease has expired), `docs/contracts/cloud-agents-v1.md`
  §6.1 and §8 tables, `crates/apassy-relay/docs/SPEC.md` §11, §30.3, §30.4, §30.6, the relay
  changelog.
- Owner: implementer (opus, high). Depends on A, C1, C2, D, F (for `read_secrets` shape; F owns
  `src/broker/run.rs`, G does not edit it). Judge panel: 2× opus + 1× fable.
- Acceptance: core `node::tests::a_short_lived_item_is_released_as_a_lease` (the fake backend
  records a `Direct` release with an expiry ≤ 900 s and never the long-lived value),
  `node::tests::a_lease_failure_denies_the_run_with_lease_failed`,
  `node::tests::an_ended_session_revokes_its_lease`; relay `tests/embedded.rs::a_direct_release_makes_a_session_without_placeholders`,
  `tests/server_sessions.rs::a_session_ends_before_its_lease`,
  `tests/server_items.rs::delivery_is_stored_and_listed`, `tests/server_vault.rs::schema_8_adds_delivery_with_a_copy_and_a_downgrade`,
  `tests/cli_run.rs::an_expired_lease_starts_no_child`; the session view and every audit row are
  scanned for the synthetic long-lived secret.

### H — The sign endpoint on the team host

- Purpose: a member's node can have AWS requests signed by the host without holding the secret.
- Files: `crates/apassy-relay/src/server/http.rs` (`["v1", "sign"]` → `Need::Member`, `Sign`),
  proposed `crates/apassy-relay/src/server/sign.rs` (checks of S6-9, the per-session counter, the
  signature with `apassy::lease::sigv4`), `crates/apassy-relay/src/api.rs` (`SignRequest`,
  `SignAnswer`, `SessionView.signers`), `crates/apassy-relay/src/session.rs` (`SessionSecret.signer`
  shared with E2: H owns `session.rs` first; E2 after H merges), `crates/apassy-relay/src/server/env.rs`
  (a `Signer` item: the access key id as a plain variable, the placeholder in the secret variable),
  `crates/apassy-relay/src/server/audit.rs` (`sign_request`), SPEC (a new section "Remote signing"),
  the relay changelog.
- Design: the member is the member of the session (`LiveSession.member_id`); the device access
  token of ADR 0019 §5 authenticates it. `Scope::Public` does not serve `/v1/sign` (a cloud agent
  cannot use it; it has no proxy). The host checks that the canonical request's `host` header is
  covered by the item's hosts and that the `x-amz-date` in the canonical headers equals the scope
  date's day. 120 requests a minute per session, then 429 with `Retry-After: 1`.
- Owner: implementer (opus, high). Depends on A, C1, G (the `Released::Signer` and the session
  shape). Judge panel: 2× opus + 1× fable.
- Acceptance (`crates/apassy-relay/tests/server_sign.rs`, new): `a_member_gets_a_signature_for_its_own_session`
  (equal to the locally computed one), `another_member_or_an_ended_session_is_refused`,
  `a_host_outside_the_item_is_refused`, `a_streaming_hash_is_refused`,
  `the_public_listener_does_not_serve_sign`, `the_limit_holds_per_session`, and the audit row has no
  hash, header, or signature.

### I — Mac UI and docs

- Purpose: the owner sees and controls way C items.
- Files: `src/desktop/ui/items.rs` (the credential page shows ` · temporary credentials` or
  ` · signed requests` after the variable; a sheet "Temporary credentials" with the fields of the
  kind, the settings, and the switch, behind `OwnerAction::ChangeDelivery`; "Add the secret key to
  make temporary credentials" on a single-field AWS item), `src/desktop/ui/new_credential.rs`
  (the kinds in the new-credential flow), `src/desktop/ui/decisions.rs` (the card lists the lease
  variables and "expires in 15 minutes"), `src/desktop/ui/*_tests.rs` of those files,
  `docs/operations/agent-path.md` §8b (the AWS, Google, and GitHub rows), `docs/operations/declarations.md`
  (the `real_value` table gets a column "way C"), `docs/security/trust-model.md` (a section "What a
  member or a cloud agent gets": the lease, its lifetime, and what the host sees for a signed
  request), `CHANGELOG.md` lines returned to the top-level agent.
- Owner: implementer (opus, high) for the views; worker (sonnet, high) for the docs with a checklist.
  Depends on D, F. Judge: 1× opus. Mockup first; before any release claim the top-level agent puts a
  screenshot of each changed view next to the mockup.
- Acceptance: `items.rs` tests `the_delivery_sheet_needs_the_owner_check` and
  `a_short_lived_item_shows_its_badge`; `decisions.rs` test `a_card_lists_the_lease_variables`; the
  docs links resolve.

### J1 — Key-management providers

- Purpose: the API clients for a key per member, with fakes, before stage 4 gives them a member.
- Files: proposed `src/lease/keys/mod.rs` (`pub trait KeyManager { fn create(&self, label,
  policy) -> Result<MemberKey, LeaseError>; fn delete(&self, remote_id) -> …; }`, `MemberKey {
  remote_id, fields: Vec<Field>, env_name }`), `src/lease/keys/cloudflare.rs` (`POST
  /client/v4/user/tokens` with `name`, `policies` from the settings, `expires_on` optional;
  `DELETE /client/v4/user/tokens/{id}`), `src/lease/keys/aws_iam.rs` (`CreateUser`,
  `CreateAccessKey`, `DeleteAccessKey`, `DeleteUser`, SigV4 service `iam`, global endpoint; the
  user name `apassy-<team>-<member>` from a pattern in the settings).
- Owner: implementer (opus, high). Depends on B, C1. Judge: 1× opus.
- Acceptance (unit tests with loopback fakes): `a_cloudflare_token_is_made_with_the_policies_and_deleted`,
  `an_iam_user_and_key_are_made_and_removed`, `a_provider_error_never_leaks_its_body`,
  `the_team_secret_is_not_in_the_member_key_or_the_error` (scan).

### J2 — A key per member on the team host (after stage 4)

- Purpose: ADR 0037 section 10 step 3.
- Files: the stage 4 member and grant code of the node (file names from
  `implementation-plan-s4-teams.md`; J2 edits them after stage 4 merges), `src/vault/short_lived.rs`
  (`member_key` rows), `src/node/catalog.rs` (a member's catalog shows the member key item instead of
  the team item), the collection "Where members use these credentials" texts (L owns them; J2 adds
  "Each member gets a key of their own").
- Design: when a member gets a grant on a collection with a key-managed item, the host makes the
  key, stores it as a new `ApiKey` item with `short_lived` on when the provider supports it (an AWS
  member key is itself an `aws_sts` source), writes `member_key`, and audits `member_key_made`.
  Removing the member, revoking the grant, or archiving the source deletes the remote key and
  archives the item (`member_key_deleted`). A failed delete stays listed with "Replace now".
- Owner: implementer (opus, high). Depends on J1, L. Judge panel: 2× opus + 1× fable.
- Acceptance: `node::tests::a_member_grant_makes_a_member_key_and_removal_deletes_it` (fake
  managers), `a_failed_delete_keeps_the_item_listed_for_replacement`, the member's catalog test.

### K — Cloudflare per-run tokens, PlanetScale passwords, Neon roles

- Purpose: the rest of the ADR's way C list (S6-11).
- Files: proposed `src/lease/cloudflare.rs` (a per-run token with `expires_on` = now + 15 min from
  the item's policies, deleted at run end), `src/lease/planetscale.rs` (`POST
  /v1/organizations/{org}/databases/{db}/branches/{branch}/passwords` with `ttl: 900`, deleted at run
  end), `src/lease/neon.rs` (create a role with a password on the branch, deliver the connection
  string, delete at run end), their settings in A's contract (A owns the contract; K adds a dated
  section), `packs/providers/{cloudflare,planetscale,neon}.json` no change.
- Owner: implementer (opus, high). Depends on C1, C2. Judge: 1× opus.
- Acceptance: one fake per provider; `a_cloudflare_run_token_expires_in_15_minutes_and_is_deleted`,
  `a_planetscale_password_has_a_ttl_and_is_deleted`, `a_neon_role_is_deleted_after_the_run`, and the
  scan.

### L — Members (after stage 4): the member's node consumes leases and signers

- Purpose: the ADR acceptance. The member's agent runs with the lease; the member's run proxy signs
  through the host.
- Files: the stage 4 client of the team host in the member's node (file names from
  `implementation-plan-s4-teams.md`), `src/broker/proxy/sigv4.rs` (`RemoteSigner` implementation
  that calls `POST /v1/sign` with the member's device token; the type lives next to the trait, the
  HTTP call in the stage 4 client), `src/broker/run.rs` (the member path reuses the lease delivery of
  F; L edits after F merged), the collection setting texts of the way A switch (D10): "Items with
  short-lived credentials show 'Short-lived credentials' in both answers", the "Values go to members'
  devices" badge leaves way C items out, "Remove member" lists no way C item for replacement.
- Owner: implementer (opus, high). Depends on F, G, H, and stage 4. Judge panel: 2× opus + 1× fable.
- Acceptance: a synthetic two-node test (the stage 4 harness: a team host node and a member node in
  one process): `a_member_run_gets_sts_credentials_that_expire_within_15_minutes` (the member's
  child environment has `ASIA…`, the host's audit has `lease_made`, the member's vault and node
  directory never hold the long-lived key), `a_member_request_is_signed_by_the_host` (the member's
  proxy re-signs through `/v1/sign`; the fake AWS verifies with the real secret that only the host
  has), `the_way_a_switch_leaves_short_lived_items_short_lived`.

### M — Integration, security review, release

- Purpose: one combined review and one release per group below. Files: `release-versions.json`,
  the app and core Cargo manifests and `Cargo.lock`, `crates/apassy-relay` and the edge Worker
  package, iOS `MARKETING_VERSION`, the extension manifest, the dated changelog (AGENTS.md).
- Owner: the top-level agent with a judge panel 2× opus + 1× fable over the combined diff: the
  no-secret scans, the no-fallback rule, the SigV4 refusals, the migrations, the audit rows.
- Acceptance: each named test above, green in the ready run of the PR (macOS groups included);
  `python3.12 scripts/check-release-versions.py` passes; the physical check of the release.

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

Rules: at most three implementation or validation workers at once across the whole Mac (a judge
panel of three counts as three). Only the top-level agent runs lint, typechecks, builds, `cargo
test`, `cargo nextest`, and full suites, one at a time through `~/.local/bin/heavy-check`, or
preferably CI after an authorized push. Subagents never run them and return the exact validation
commands. One validation pass per intended revision. Judge panels mix models (2× opus + 1× fable)
for A, C1, C2, D, E1, E2, F, G, H, J2, L, and M. Each unit works in its own worktree off
`release/0.5.16` (or `main` once the release merged) in a draft PR; `gh pr ready` only when the unit
is complete. No owner approval is needed between waves (owner decision of 2026-11-03); the owner
steps of the next section are the only stops.

| Wave | Units in parallel | Verified by | Needs |
| --- | --- | --- | --- |
| 1 | A, B, C1 | panel on A + C1; 1× opus on B | nothing |
| 2 | C2, D, E1 | panel on C2 + D; panel on E1 | wave 1 merged |
| 3 | F, G, J1 | panel on F + G; 1× opus on J1 | wave 2 merged |
| 4 | H, I, K | panel on H; 1× opus on I + K; screenshots of I | wave 3 merged |
| 5 | E2 | panel | G, H merged |
| 6 (after stage 4) | L, J2 | panel on L + J2 | stage 4 merged |
| 7 | M | panel on the combined diff | each release group |

Handoff format (every agent returns exactly this): `Unit`, `Base revision`, `Files changed`
(absolute paths), `Interface` (types, functions, routes, schema), `Tests added` (names; "not run"
or "cheap check run: <command>"), `Validation commands for the top-level agent` (exact),
`Deviations from the plan`, `Open questions`, `Risks seen`. A judge returns, per acceptance
criterion, PASS, FAIL, or UNVERIFIED with `file:line` evidence, the counter-example it tried, and a
severity.

## Release grouping

Each group is one release of all six components at one version (AGENTS.md), after the release
that stage 4 or stage 5 ships if they land first; the version numbers are taken at release time.

| Group | Units | What ships | Acceptance of the group |
| --- | --- | --- | --- |
| R1 "temporary credentials" | A, B, C1, C2, D, F, G, I, (K) | Way C for the owner's own agents and for cloud agents: AWS STS, GitHub Apps, Google, OAuth refresh (and K's three when ready) | The owner's agent runs `aws sts get-caller-identity` and one real AWS command with `ASIA…` credentials that expire within 15 minutes; a cloud agent does the same through the node; the long-lived key is in no environment, output, or session view (the scans, plus one manual `env` print). |
| R2 "signed requests" | E1, H, J1, E2 | AWS placeholders on the Mac and for cloud agents; the sign endpoint; the key-management providers | The `aws` CLI on the owner's Mac lists S3 buckets with a placeholder secret; a cloud agent does it through the node; `POST /v1/sign` answers a member device in the relay tests. |
| R3 "members" (after stage 4) | L, J2 | The ADR acceptance; keys per member | A member's agent in another tailnet uses AWS with STS credentials that expire within 15 minutes; a Cloudflare member key is made on a grant and deleted on removal. |

R1 does not wait for R2; R2 does not wait for stage 4. If stage 4 lands before R2, R2 and R3 can be
one release.

## Owner-needed steps

The tests need no account. These steps are for the physical acceptance of each group, and for
production use.

| # | Step | When |
| --- | --- | --- |
| O1 | An AWS IAM user or key for Apassy with `sts:GetFederationToken`, or a role that trusts it with `sts:AssumeRole` (recommended), and the key pasted into Apassy as one AWS item | R1 acceptance |
| O2 | A GitHub App installed on one test repository: the app id, the installation id, and the downloaded private key | R1 acceptance (GitHub part) |
| O3 | A Google Cloud service-account key with `roles/iam.serviceAccountTokenCreator` on itself, and the IAM Credentials API enabled in its project | R1 acceptance (Google part) |
| O4 | One OAuth refresh token with its client id and secret (any provider with a token endpoint) | R1 acceptance (OAuth part); optional |
| O5 | A Cloudflare API token with "API Tokens: Edit" | R2 acceptance of J1 and K; optional |
| O6 | The physical check of R1 and R2 on the owner's Mac and a cloud agent (the commands above, and one `env` print to see no `AKIA` secret) | Before each release claim |
| O7 | The ADR acceptance with a member (Konrad's Mac in another tailnet, stage 4): `aws sts get-caller-identity` with `ASIA…` credentials, then the same command after 16 minutes fails | R3 |
| O8 | A decision only if wanted: keep AWS items in "real value" by default when they have no secret key field (this plan's choice), or ask the owner for the second field on first use | Any time |

## Risks

| Risk | Where | Mitigation |
| --- | --- | --- |
| A SigV4 edge case the proxy does not reproduce (S3 virtual-host style, double-encoded paths, `x-amz-content-sha256` forms, repeated query keys) sends a request that AWS rejects | E1, E2, H | The AWS test vectors in C1; refuse what is not understood (presign, streaming) with a reason; the `aws` CLI test when the CLI is present; a judge panel on E1, E2, and H |
| A signed header that the proxy drops (`accept-encoding`) breaks the upstream signature | E1, E2 | Keep every header in `SignedHeaders`; a compressed answer is "not checked", as today |
| `GetFederationToken` credentials cannot call IAM or STS; a run that needs them fails | C1, F | The error text names `role_arn`; `AssumeRole` is the recommended setup (O1) |
| Google self-impersonation needs a role on the account itself; `generateAccessToken` needs the IAM Credentials API | C2 | The error text names the role and the API (O3) |
| A GitHub token lives one hour; revocation at run end is best effort | C2, F, G | `lease_revoke_failed` activity row; the remaining lifetime is shown on the card |
| A rotated OAuth refresh token and a failed vault write lose the authorization | C2, F, G | Write before delivery; a loud activity row; the sheet says "authorize again" |
| The lease call adds latency before each run; a slow provider delays the run | F, G | 20 s deadline, then `lease_failed`; the decision is made before the call, so no owner wait is spent on it |
| The session view carries real short-lived values; a cloud agent that logs its environment leaks a 15-minute credential | G | Already the rule for placeholders in cloud-agents-v1 §8; the lifetime bounds the loss; the audit shows `lease_made` |
| Stage 4 edits the same relay files (`api.rs`, `env.rs`, `store.rs`, `session.rs`) | G, H, E2 | A freezes the `SessionView` additions in wave 1; G takes the next free team schema number at merge; the top-level agent orders the merges of the two plans per file |
| Schema 32 lands before 27 to 31 of the other plans | D | `schema32.rs` follows whatever is current; the top-level agent renumbers only if a lower number stays unused |
| A unit holds a long-lived secret longer than needed (the lease call) | C1, C2, F, G | `Zeroizing` buffers, dropped before the process spawns; the scans in every test |
| The `aws`, `gh`, and `gcloud` CLIs read credential files, not only variables; a tool may ignore the lease | F | The R1 physical check names each CLI; `AWS_SESSION_TOKEN` is read by every AWS SDK |

Units that need a security judge panel (2× opus + 1× fable): A, C1, C2, D, E1, E2, F, G, H, J2, L, M.

## Not verified in the code

- Whether STS answers JSON with `Accept: application/json`. The plan parses the XML elements and the
  fakes answer the XML form of the AWS documentation.
- Which AWS SDKs read `AWS_CREDENTIAL_EXPIRATION`; the variable is harmless when ignored.
- Whether the AWS CLI v2 and every SDK read `AWS_ENDPOINT_URL_<SERVICE>` for each service that E2
  sets (documented since 2023 for the SDKs and the CLI; not tried here).
- `RsaKeyPair::from_der` accepting GitHub's PKCS#1 private key form (ring documents it; C2 tests it
  with a generated key).
- The exact body shape of the Cloudflare token-create API (`policies`, `expires_on`), of PlanetScale
  passwords (`ttl`), and of Neon roles; J1 and K read the current docs before they write the fakes,
  and the fakes answer the documented shape.
- Whether `iamcredentials` `generateAccessToken` accepts `lifetime: "900s"` for the key's own
  account without a separate target (self-impersonation is documented as needing the role on the
  account).
- The AWS `GetFederationToken` 2048-byte limit on the packed policy; C1 refuses a longer one.
- How stage 4 names the member's node client and the collection setting file; L and J2 take the
  names from `implementation-plan-s4-teams.md` when it exists.
