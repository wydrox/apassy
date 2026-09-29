# apassy-relay alpha: specification

Date: 2026-09-30. Status: the plan for one day of work by three developers.
Design source: ADR 0013 of the core (way B only). Core crate: `wydrox/apassy` at rev `77f6628`.

## 1. What the alpha does

- A team keeps shared credentials in one encrypted vault on the relay.
- The owner creates the team. Members join with one-time invite codes.
- Items live in collections. A collection has a policy. A grant gives one member the use of one collection.
- A member creates agent tokens. An agent asks for a run: items, command, purpose, and the user's request.
- The relay decides with the core command analysis and the core hard rules. A known-safe command runs. Every other command waits for an approver. A production item always waits. A hard-rule failure is denied.
- An allowed or approved run gets a session: placeholders, and base URLs that point at the relay.
- The relay reverse-proxies `/p/<session key>/<host>/<path>` to `https://<host>/<path>`. It puts the real value only in an auth position, only for a host of that item. It puts the placeholder back in the response.
- The owner or a manager approves or denies with the CLI.
- The audit records every step. It never holds a value, a placeholder, a token, or a session key.
- Agents talk to the relay through a remote MCP endpoint (`/mcp`), a stdio MCP adapter (`apassy-team mcp`), or the CLI (`apassy-team run -- <cmd>`).

## 2. Cuts (not in this alpha)

- Way A (the member's Mac app gets a value for one run). The member app "Team" source.
- The model sidecar and learning. With no model: known safe runs, everything else asks.
- `CONNECT` and the run certificate. Workers cannot do `CONNECT`, so way B is base-URL rewrite only.
- The mediated `Call` for connector operations, and the MCP tool `apassy_use_credential`.
- The core wire endpoint (`WireRequest` over HTTPS). The relay has its own JSON API.
- Team rule packs and local packs per collection. Only the built-in packs of the core run.
- Grants to one agent, and grant places (project folders). A grant is member plus collection. `cwd` is for the audit only.
- Access requests from agents. Item edit and rotation (archive, then add a new item).
- Approvals in an app, on the web, or in Slack. Approvals are CLI only.
- Keep-alive to upstream hosts, HTTP/2, WebSocket and `Upgrade` (501), SSE through the quick tunnel.
- Rewriting of redirects. A `Location` header passes through, so a client that follows it goes to the real host with a placeholder and fails closed.
- Compressed upstream responses. The relay asks for identity. A compressed answer is a 502.
- Request bodies over 8 MiB (413). AWS SigV4 and other signed requests.
- Items that are not HTTP API keys (for example a Postgres URL). An item whose value cannot get a placeholder is refused.
- The `gh` CLI. `GH_HOST` cannot carry a path, so only `GITHUB_API_URL` is set.
- Sessions that survive a relay restart. A restart ends every session.
- TLS in the relay (Cloudflare ends TLS), Let's Encrypt, Docker Compose, a multi-tenant relay, several teams per relay.
- A key typed at start (D7 of the ADR). The key comes from a variable or a file.
- Self-approval checks. An owner may approve a run of their own agent.

## 3. Deployment today

```
agent (cloud session, CI, laptop)
   │ HTTPS
   ▼
Cloudflare Worker  apassy-relay.wyderka.cc   adds X-Apassy-Edge: <edge secret>
   │ HTTPS, fetch()
   ▼
cloudflared quick tunnel  https://<random>.trycloudflare.com   (URL in the Worker var RELAY_ORIGIN)
   │ HTTP
   ▼
container apassy-relay  0.0.0.0:8080 plain HTTP, /data volume   (Docker in colima on the owner's Mac, aarch64)
   │ HTTPS (rustls, ring, system roots)
   ▼
upstream API hosts (api.stripe.com, api.openai.com, ...)
```

- The relay refuses every request without the right `X-Apassy-Edge`, except `GET /healthz`. The tunnel URL alone gives no access.
- The Worker checks nothing else. It forwards everything and streams bodies.
- The image stays portable: one binary, one port, one volume, config from variables. It can move to Cloudflare Containers later (amd64 image, persistent storage needed).

## 4. Crate layout and ownership

One crate, `apassy-relay`, license `FSL-1.1-ALv2` (FSL-1.1 with the Apache-2.0 future license). Rust 1.97.0, edition 2024, `#![forbid(unsafe_code)]`, clippy `all = "warn"`.

| Path | What | Owner |
| --- | --- | --- |
| `Cargo.toml`, `Cargo.lock`, `.cargo/config.toml`, `rust-toolchain.toml`, `LICENSE` | Build and license | skeleton (frozen) |
| `src/lib.rs`, `src/api.rs`, `src/config.rs`, `src/error.rs`, `src/ids.rs`, `src/secret.rs`, `src/session.rs` | Shared types | skeleton (frozen) |
| `tests/build_options.rs` | SQLCipher build flags | skeleton (frozen) |
| `docs/SPEC.md` | This file | skeleton (frozen) |
| `src/server/**`, `src/bin/apassy-relay.rs`, `tests/server_*.rs`, `tests/common/relay.rs` | Track server | server |
| `src/proxy/**`, `tests/proxy_*.rs`, `tests/common/upstream.rs` | Track proxy | proxy |
| `src/cli/**`, `src/bin/apassy-team.rs`, `tests/cli_*.rs`, `Dockerfile`, `.dockerignore`, `deploy/**`, `docs/OPERATIONS.md`, `README.md` | Track client | client |
| `tests/e2e.rs` | End-to-end test | merger |

Rules for tracks:

- A track edits only its own paths. A track does not edit a frozen file. If a shared type is missing, the track adds its own type in its own module and says so in its report.
- No new dependencies. Every dependency is already pinned with `=` in `Cargo.toml`.
- Tests show behavior. No stubs, no skipped or ignored tests. Synthetic values only, for example `sk_test_51SyntheticCanary...`.
- Secrets: `SecretString` (zeroized, redacted `Debug`, not `Serialize`). A secret never goes into a log line, an error message, or the audit.

Binaries:

- `apassy-relay`: the server. `apassy-relay serve` (the default) and `apassy-relay init --team <name> --owner <name>`.
- `apassy-team`: the CLI for people and agents, with `apassy-team mcp`, the stdio MCP adapter.

## 5. Dependencies (pinned)

| Crate | Version | Use |
| --- | --- | --- |
| `apassy` | git rev `77f6628`, features `vault` | analysis, packs, bouncer glue, `mint_placeholder`, `HostRule`, declarations, `ExecRule`, wire envelope |
| `serde`, `serde_json`, `zeroize` | `=1.0.229`, `=1.0.151`, `=1.9.0` | same as core |
| `rusqlite` | `=0.40.2`, `bundled-sqlcipher-vendored-openssl` | team vault. Must match the core (a `links` crate) |
| `getrandom` | `=0.4.3` | tokens |
| `rustls` | `=0.23.45`, `ring`, `std`, `tls12` | upstream TLS |
| `rustls-platform-verifier` | `=0.7.0` | upstream roots (system store, plus extra roots in tests) |
| `sha2` | `=0.11.0` | token hashes |
| `base64` | `=0.23.1` | Basic auth in the swap |
| `httparse` | `=1.10.1` | upstream response heads |
| `psl` | `=2.1.238` | the public suffix list, compiled in: broad item hosts |
| `tiny_http` | `=0.12.0`, no features | inbound HTTP/1.1 server (plain HTTP) |
| `ureq` | `=3.4.2`, feature `rustls` (ring, webpki roots) | HTTPS client of the CLI, and HTTP calls in tests |
| dev: `rcgen`, `tempfile` | `=0.14.10`, `=3.27.0` | test CA for the mock upstream, temp dirs |

`tiny_http` 0.12 is old (2022). Its dependencies are `ascii`, `chunked_transfer`, `httpdate`, `log`. It is acceptable for the alpha because it serves plain HTTP behind Cloudflare. Replacing it is a later task.

## 6. Configuration of the server

From `src/config.rs` (`RelayConfig::from_env`):

| Variable | Meaning | Default |
| --- | --- | --- |
| `APASSY_RELAY_DATA` | data dir; the vault is `<dir>/team.db` | `/data` |
| `APASSY_RELAY_LISTEN` | listener address | `0.0.0.0:8080` |
| `APASSY_RELAY_PUBLIC_URL` | public origin, for base URLs and the MCP `Origin` check | required |
| `APASSY_RELAY_EDGE_SECRET` / `_FILE` | edge secret, at least 32 bytes | required |
| `APASSY_RELAY_KEY` / `_FILE` | vault passphrase, at least 16 bytes | required |
| `APASSY_RELAY_SESSION_TTL` | session lifetime, 60 to 3600 s | 900 |
| `APASSY_RELAY_APPROVAL_TIMEOUT` | wait for an approver, 30 to 86400 s | 600 |

`UpstreamOptions` (extra roots, fixed addresses) is not read from the environment. Tests set it in code.

## 7. Auth model

- **Edge.** Every request except `GET /healthz` must carry `X-Apassy-Edge: <edge secret>`. The relay compares it with `secret::same_bytes`. A missing or wrong header gets 403 `edge_refused`, and an audit row with actor `edge` (at most one row per 10 seconds, so a scan cannot fill the audit).
- **Tokens.** Every token is 32 random bytes (`getrandom`) as 64 lowercase hex characters after a prefix (`secret::new_token`). The vault stores only `sha256(token)` (`secret::token_hash`). A lookup is by hash. A token is shown once, when it is made.

| Kind | Prefix | Made by | Sent as | Lifetime |
| --- | --- | --- | --- | --- |
| Member token (owner, manager, member) | `apassy_mbr_` | `apassy-relay init` (owner), `POST /v1/join` | `Authorization: Bearer <token>` | until the member is revoked |
| Agent token | `apassy_agt_` | `POST /v1/agents` by a member | `Authorization: Bearer <token>` | 1 to 365 days, default 30 |
| Invite code | `apassy_inv_` | `POST /v1/invites` | in the body of `POST /v1/join` | one use, 1 to 168 hours, default 72 |
| Session key | `apassy_ses_` | the relay, when a run is allowed or approved | in the path `/p/<key>/...` | the session TTL |

- A bearer with the wrong kind for an endpoint gets 401 `unauthenticated`. An expired agent token gets 401 `token_expired`.
- Revocation works at the next request: the token hash is looked up each time, and revocation ends live sessions at once.
- Roles: `owner` (one, made at init), `manager`, `member`. Only the owner invites a manager and revokes a member. Owner and manager add collections, items, grants, and approve runs. Every member makes and revokes their own agents. An agent acts for its member and can use only that member's grants.

## 8. Team vault

One SQLCipher file, `<data dir>/team.db`, owned by the server track (`src/server/store.rs`).

- Open with `rusqlite`. Before any other statement: `PRAGMA key` with the passphrase, then the core parameters: `cipher_page_size = 4096`, `kdf_iter = 256000`, `cipher_hmac_algorithm = HMAC_SHA512`, `cipher_kdf_algorithm = PBKDF2_HMAC_SHA512`, `cipher_memory_security = ON`. Then `SELECT count(*) FROM sqlite_master` to check the key.
- At open, check `PRAGMA compile_options`: it must have `OMIT_LOAD_EXTENSION` and `DEFAULT_LOOKASIDE=0,0`, and must not have `ENABLE_LOAD_EXTENSION` or `USE_URI`. Refuse to start otherwise.
- The file and its directory get mode 0600 and 0700. `journal_mode = WAL` is not used (one file only): `journal_mode = DELETE`, `foreign_keys = ON`, `secure_delete = ON`.
- One connection behind a `Mutex`. The team is small.
- The schema has a version in `PRAGMA user_version` (1).

```sql
CREATE TABLE team (id INTEGER PRIMARY KEY CHECK (id = 1), name TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE member (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE,
  role TEXT NOT NULL CHECK (role IN ('owner','manager','member')),
  token_hash BLOB NOT NULL UNIQUE, created_at INTEGER NOT NULL, revoked_at INTEGER);
CREATE TABLE invite (
  id INTEGER PRIMARY KEY, code_hash BLOB NOT NULL UNIQUE,
  role TEXT NOT NULL CHECK (role IN ('manager','member')),
  created_by INTEGER NOT NULL REFERENCES member(id), created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL, used_by INTEGER REFERENCES member(id), used_at INTEGER);
CREATE TABLE collection (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, policy TEXT NOT NULL, -- api::Policy as JSON
  created_at INTEGER NOT NULL);
CREATE TABLE item (
  id INTEGER PRIMARY KEY, collection_id INTEGER NOT NULL REFERENCES collection(id),
  name TEXT NOT NULL, env_name TEXT NOT NULL, value TEXT NOT NULL,
  provider TEXT, hosts TEXT NOT NULL,          -- JSON array of host rules as text
  environment TEXT NOT NULL, risk TEXT NOT NULL, scope TEXT NOT NULL, reversibility TEXT NOT NULL,
  created_by INTEGER NOT NULL REFERENCES member(id), created_at INTEGER NOT NULL, archived_at INTEGER);
CREATE UNIQUE INDEX item_env ON item(collection_id, env_name) WHERE archived_at IS NULL;
CREATE TABLE access_grant (
  id INTEGER PRIMARY KEY, collection_id INTEGER NOT NULL REFERENCES collection(id),
  member_id INTEGER NOT NULL REFERENCES member(id), created_by INTEGER NOT NULL REFERENCES member(id),
  created_at INTEGER NOT NULL, revoked_at INTEGER);
CREATE UNIQUE INDEX grant_live ON access_grant(collection_id, member_id) WHERE revoked_at IS NULL;
CREATE TABLE agent (
  id INTEGER PRIMARY KEY, member_id INTEGER NOT NULL REFERENCES member(id), name TEXT NOT NULL,
  token_hash BLOB NOT NULL UNIQUE, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, revoked_at INTEGER);
CREATE TABLE run (
  id INTEGER PRIMARY KEY, agent_id INTEGER NOT NULL REFERENCES agent(id), member_id INTEGER NOT NULL REFERENCES member(id),
  items TEXT NOT NULL, command TEXT NOT NULL, purpose TEXT NOT NULL, user_request TEXT, cwd TEXT,  -- masked, JSON for lists
  ttl_secs INTEGER NOT NULL, flags TEXT NOT NULL, note TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending','ready','denied','timed_out','ended')),
  decided_by TEXT, approver_id INTEGER REFERENCES member(id), code TEXT,
  created_at INTEGER NOT NULL, expires_at INTEGER, decided_at INTEGER, session_expires_at INTEGER);
CREATE TABLE audit (
  id INTEGER PRIMARY KEY, at INTEGER NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
  run_id INTEGER, detail TEXT NOT NULL);   -- masked JSON
```

Item rules at `POST /v1/items`:

- `name`: 1 to 64 bytes, no control characters. `env_name`: `apassy::vault::checked_env_name`. It must not be `PATH`, `HOME`, or one of the base URL names in section 11, and must not start with `APASSY_`.
- `provider`: if set, `apassy::vault::providers::find` must know it. Hosts default to `providers::known_hosts(id)`.
- `hosts`: 1 to 16 after defaults; each `HostRule::parse` (lowercase name, optional port). No host: 400 `invalid_request` ("A relay item needs at least one host.").
- A host covers itself and every subdomain. A broad host is refused with 400 `broad_host`, unless `allow_broad_host` is true. A broad host is a public suffix (`com`, `herokuapp.com`, `github.io`, `supabase.co`), or a whole domain under a public (ICANN) suffix (`example.com`, `example.co.uk`). A known host of the item's provider is not broad as a whole domain (`amazonaws.com` for `aws`). A domain under a private suffix (`myapp.herokuapp.com`) belongs to one customer, so it is not broad. The public suffix list is compiled in with the `psl` crate. The audit row `item_added` names the allowed broad hosts in `broad_hosts`.
- `environment`, `risk`, `scope`, `reversibility`: `Environment::parse` and the others of the core. Defaults: risk `high`, scope `admin`, reversibility `irreversible` (the core defaults).
- `value`: 1 to 4096 bytes of printable ASCII (space to `~`), with no quote (`"`) and no backslash. JSON writes such a value as it is, so a JSON echo of it in a response is found. `proxy::mint(value)` must return a placeholder, else 400 `placeholder_impossible`.
- The value is never returned by any endpoint.

## 9. HTTP API

- Plain HTTP/1.1 on one port. JSON bodies at most 64 KiB (`api::MAX_JSON_BODY`), else 413 `payload_too_large`. Unknown fields are refused where the type says `deny_unknown_fields`.
- Every JSON response is the core envelope (`api::Envelope`): `{"ok":true,"result":...}` or `{"ok":false,"error":{"code":"...","message":"..."}}`. The HTTP status comes from `error::status_of(code)`.
- `Content-Type: application/json` on every JSON response. `Cache-Control: no-store` on every `/v1` and `/mcp` response.
- Load (`config::Limits`, not read from the environment). At most 256 requests run at once. Agent paths (`/p/`, `/mcp`, `/v1/runs`, `/v1/access`) can be slow, so they take at most 256 - 32 of them. The other 32 are kept for members, approvers, and `/healthz`. A request over a limit gets 503 `busy` as an envelope, with `Retry-After: 2`. `apassy-team run` asks again after a `busy` answer while it waits.
- Auth column: `edge` = edge header only; `member` = edge + member bearer; `approver` = member bearer with role owner or manager; `owner` = owner bearer; `agent` = edge + agent bearer; `any` = member or agent bearer.

| Method and path | Auth | Body | Result |
| --- | --- | --- | --- |
| `GET /healthz` | none | | `200 ok` (text), no envelope |
| `GET /v1/me` | any | | `MeView` |
| `POST /v1/join` | edge | `JoinRequest {code, name}` | `Issued {id: member id, secret: member token}` |
| `POST /v1/invites` | approver | `InviteRequest {role, expires_hours?}` | `Issued {id: invite id, secret: code, expires_at}` |
| `GET /v1/invites` | approver | | `[InviteView]` |
| `GET /v1/members` | approver | | `[MemberView]` |
| `DELETE /v1/members/{id}` | owner | | `Created {id}`; revokes the member, their agents, grants, sessions, pending runs. The owner cannot revoke themselves. |
| `POST /v1/collections` | approver | `CollectionCreate {name, policy?}` | `Created {id}` |
| `GET /v1/collections` | member | | `[CollectionView]`: all for approvers, granted ones for members |
| `PUT /v1/collections/{id}/policy` | approver | `Policy` | `CollectionView` |
| `POST /v1/items` | approver | `NewItem` | `ItemCreated {id, hosts}` |
| `GET /v1/items?collection={id}` | member | | `[ItemView]`: live items; members see granted collections only |
| `DELETE /v1/items/{id}` | approver | | `Created {id}`; archives the item and ends sessions that hold it |
| `POST /v1/grants` | approver | `GrantCreate` | `Created {id}` (409 `conflict` if a live grant exists) |
| `GET /v1/grants` | approver | | `[GrantView]` live grants |
| `DELETE /v1/grants/{id}` | approver | | `Created {id}`; ends the member's sessions with items of that collection |
| `POST /v1/agents` | member | `AgentCreate {name, days?}` | `Issued {id: agent id, secret: agent token, expires_at}` |
| `GET /v1/agents` | member | | `[AgentView]`: own agents; approvers see all |
| `DELETE /v1/agents/{id}` | member | | `Created {id}`; own agent, or any agent for an approver; ends its sessions |
| `GET /v1/approvals` | approver | | `[ApprovalView]` pending runs, oldest first |
| `POST /v1/approvals/{run_id}/approve` | approver | `DecisionRequest {reason?}` | `RunView` without `session` |
| `POST /v1/approvals/{run_id}/deny` | approver | `DecisionRequest {reason?}` | `RunView` |
| `GET /v1/audit?after={id}&limit={n}` | approver | | `[AuditEntry]`, id ascending, limit 1 to 500, default 100 |
| `GET /v1/access` | agent | | `AccessView` |
| `POST /v1/runs` | agent | `RunRequest` | `RunView` (`pending` or `ready`) |
| `GET /v1/runs/{id}?wait={s}` | agent | | `RunView`. Only the agent that made the run; else 404. `wait` 0 to 25: while `pending`, hold the response up to that many seconds. An agent has at most 4 long polls open (`Limits::long_polls_per_agent`); a poll over that is answered at once, as with `wait=0`. |
| `POST /mcp` | agent | JSON-RPC | section 14 |
| `GET /mcp`, `DELETE /mcp` | agent | | 405 |
| `ANY /p/{session key}/{host}/{path}` | edge | any | the upstream response, section 12 |

Other paths: 404 `not_found`. A known path with another method: 405 `method_not_allowed`.

Error codes are in `src/error.rs` (`codes`). The main ones: `invalid_request` 400, `placeholder_impossible` 400, `broad_host` 400, `unauthenticated` 401, `token_expired` 401, `edge_refused` 403, `forbidden` 403, `invite_invalid` 403, `not_granted` 403, `item_archived` 403, `rule_expired` / `rule_command_not_permitted` / `rule_forbidden_word` / `rule_rate_limit` 403, `not_found` 404, `method_not_allowed` 405, `conflict` 409, `run_not_pending` 409, `payload_too_large` 413, `relay_error` 500, `busy` 503. Proxy codes are in section 12. `approval_denied`, `approval_timeout`, `approval_invalidated` appear in `RunView.code`, not as HTTP errors.

`POST /v1/join`: the code must be a live invite (not used, not expired), else 403 `invite_invalid` (one message for every case). The name: 1 to 64 bytes of `[A-Za-z0-9._-]`, unique, else 409 `conflict`. The invite is marked used in the same transaction.

## 10. Decision per run

`POST /v1/runs` (and the MCP tool `apassy_request_run`). Order, in `src/server/decide.rs`:

1. **Auth.** Agent token live, agent not revoked or expired, member not revoked.
2. **Validation** (as core `RunRequest::validate`): items 1 to 16 and distinct; command 1 to 64 args, each at most 4096 bytes, no NUL, the first arg non-empty and not starting with `-`; purpose trimmed 1 to 500 bytes; `user_request` at most 32 KiB, no NUL; `cwd` absolute and no NUL if present; `ttl_secs` 60 to the relay TTL if present. Else 400 `invalid_request`.
3. **Access.** Each item exists, is live, and is in a collection with a live grant for the agent's member. Unknown, or not granted: 403 `not_granted` (the same answer, so ids do not leak). Archived: 403 `item_archived`. Two items with the same `env_name`: 400 `invalid_request`.
4. **Hard rules**, per distinct collection of the items, with `policy.rule` (`ExecRule`). A copy of core `run.rs::check`:
   - `command_text = command.join(" ")`, `lower = command_text.to_lowercase()`.
   - `expires_at` set and `now >= expires_at`: `rule_expired`.
   - `allowed_prefixes` not empty and no prefix `p` with `command_text == p` or `command_text.starts_with(p + " ")`: `rule_command_not_permitted`.
   - any `w` in `forbidden_words` with `lower.contains(&w.to_lowercase())`: `rule_forbidden_word`.
   - `max_runs_per_hour = n` and the agent has `n` or more runs (any status) with an item of this collection in the last 3600 s: `rule_rate_limit`.
   - A failure: the run row is stored with status `denied` and the code, an audit row `run_denied` is written, and the response is HTTP 403 with that code. The message names the rule, not the value.
5. **Analysis.** `RuleSet::builtin()` is built once at start (startup fails on error). Then
   `apassy::broker::shell_risk::analyze_with_providers(&rules, &command, &purpose, &env_names, &providers)`.
   `env_names` are the items' env names. `providers` has one `ProviderHosts {env_name, hosts}` per item. `hosts` are the item's host names plus the host of `public_url`, so a command that names the relay URL does not get `foreign_host`.
6. **User request.** If `apassy::broker::shell_risk::injection_flag(user_request)` is `Some(flag)`: push the flag, sort and dedup the flags, set `known_safe = false` and `known_command = false`.
7. **Context.** `declarations[i] = Some(Declaration {project: collection name, environment, risk, scope, reversibility})`. `has_user_request = user_request is Some and not blank`.
   `ctx = DecisionContext {analysis: &analysis, declarations: &declarations, has_user_request}`.
8. **Decision** (no model):
   - `apassy::broker::bouncer::before_model(&ctx)` is `Some(d)`: **ask**, note `d.note`. This covers, in order: a production item ("Production credential: the owner approves every run with it (ADR 0010)."), any flag ("Rule flags: a, b"), no user request, no declaration.
   - else a collection of the run has `policy.mode = ask`: **ask**, note "The policy of collection <name> asks for every run."
   - else `analysis.known_safe`: **allow**, `decided_by = known_safe`, note "Known safe command. No rule asked."
   - else: **ask**, note "Not a known safe command. The relay has no model, so an approver decides."
9. **Allow**: create the session now (section 11), status `ready`. **Ask**: status `pending`, `expires_at = now + approval_timeout`.
10. Write the run row and the audit rows `run_requested` (items, masked command, purpose, user request, cwd, flags, note) and `run_allowed` or `run_pending`.

Flags that ask include every flag the core emits: `secret_output`, `data_loss`, `irreversible`, `production`, `real_recipient`, `remote_code`, `remote_access`, `system_change`, `new_dependency`, `privilege`, `hook_channel`, `ask_owner`, `foreign_host`, `injection_phrase`, and `rule_pack_error`. Measured at rev 77f6628: `git status`, `ls -la`, `cargo test`, `gh repo list`, `stripe balance retrieve` are known safe; `stripe refunds create` gets `ask_owner`; `rm -rf /` gets `data_loss`; `sh -c 'echo $STRIPE_API_KEY'` gets `secret_output`; `python3 script.py` is clean but not known safe (asks).

Unavailable is never an allowance: any error in the analysis, the store, or the session creation denies or asks. It never allows.

## 11. Session lifecycle and environment

States of a run: `pending` → `ready` → `ended`, or `pending` → `denied` / `timed_out`. Or `ready` at once for an allowed run.

- **Approve** (`POST /v1/approvals/{id}/approve`): the run must be `pending` and not past `expires_at`, else 409 `run_not_pending` (a past run becomes `timed_out` first). Re-check step 1 and step 3 for the agent and items. A failure: status `denied`, `code = approval_invalidated`, `decided_by = revocation`. Success: create the session, status `ready`, `decided_by = approver`, `approver` = name, note = reason or "Approved by <name>.".
- **Deny**: the run must be `pending`: status `denied`, `code = approval_denied`, note = reason or "Denied by <name>.".
- **Timeout**: checked lazily at each read of the run and each list of approvals: a `pending` run past `expires_at` becomes `timed_out`, `code = approval_timeout`, `decided_by = timeout`, with an audit row.
- **Revocation** of an agent, a member, a grant, or an item: pending runs that depend on it are left to fail the re-check at approval; live sessions that depend on it end at once (removed from the session table), with an audit row `session_ended`.
- **Expiry**: `SessionSource::find` returns `None` after `expires_at`. `GET /v1/runs/{id}` then shows `ended`.

**Session creation** (`src/server/sessions.rs` and `src/server/env.rs`):

- `session key = secret::new_token(TokenKind::Session)`. The table is keyed by `token_hash(key)`. `session_expires_at = now + (request.ttl_secs or config.session_ttl_secs)`.
- For each item, `placeholder = proxy::mint(&value)`. `None` is `relay_error` (the item check makes it rare).
- `LiveSession {id, run_id, agent_id, member_id, expires_at, secrets: [SessionSecret {item_id, env_name, placeholder, value, hosts}]}` goes into the table. The `SessionView` for the agent is kept next to it, in memory only.
- Nothing of a session is written to disk except its id, run id, and expiry.

**Environment** in `SessionView.env`, built in `src/server/env.rs`. `base(host) = proxy::base_url(public_url, key, host rule)`:

| Variable | When | Value |
| --- | --- | --- |
| `<ENV_NAME>` | every item | the placeholder |
| `APASSY_BASE_<ENV_NAME>` | every item | `base(first host of the item)` |
| `STRIPE_API_BASE` | an item with a host covering `api.stripe.com` | `base(api.stripe.com)` |
| `OPENAI_BASE_URL` | a host covering `api.openai.com` | `base(api.openai.com) + "/v1"` |
| `ANTHROPIC_BASE_URL` | a host covering `api.anthropic.com` | `base(api.anthropic.com)` |
| `GITHUB_API_URL` | a host covering `api.github.com` | `base(api.github.com)` |
| `APASSY_RELAY_SESSION_EXPIRES` | always | the expiry, Unix seconds |

- `base_urls` maps each host of each item (as `HostRule` shows it) to `base(host)`.
- `placeholders` lists the `<ENV_NAME>` variables.
- If two items give the same provider variable, the item with the lower id wins.
- `gh` is not supported: `GH_HOST` cannot hold a path. `AWS_ENDPOINT_URL` is not set (SigV4 is cut).
- Only the agent that made the run gets the `session` part. It is never in the audit.

## 12. Reverse proxy

`src/proxy/` (track proxy). The server checks the edge secret, then calls `Proxy::handle(request, now)` for every path that starts with `/p/`.

**Route.** `/p/<key>/<host>[/<rest>][?<query>]`.
- `<key>` must be a well-formed session key (`TokenKind::of`), else 403 `session_invalid`.
- `<host>` is `name` or `name:port`, parsed with `HostRule::parse` (lowercase). A bad host: 403 `host_not_in_session`.
- `sessions.find(key, now)` is `None`: 403 `session_invalid`.
- `session.covers_host(host, port)` is false: 403 `host_not_in_session`. The relay is not an open proxy.
- Upstream URL: `https://<host>[:port]/<rest>[?<query>]`. `<rest>` empty means `/`.

**Methods.** Any method except `CONNECT`. `CONNECT`, an `Upgrade` header, or `Connection: upgrade`: 501 `not_supported`.

**Request headers.** Forwarded as received, except these, which are dropped: `host` (set to the upstream host), `connection`, `keep-alive`, `proxy-authorization`, `proxy-connection`, `te`, `trailer`, `transfer-encoding`, `upgrade`, `expect`, `accept-encoding`, `content-length` (set again), `x-apassy-edge`, `cdn-loop`, `x-forwarded-for`, `x-forwarded-proto`, `x-forwarded-host`, `x-real-ip`, and every `cf-*` header. `Connection: close` is added.

**Swap (auth positions).** A copy of core `proxy/swap.rs`, with attribution:
- `Authorization`: the value is exactly a placeholder; or `<scheme> <placeholder>` (Bearer, token, any scheme); or `Basic <base64(user:password)>` where the user and/or the password is exactly a placeholder, re-encoded after the swap. A placeholder inside a larger Basic part is refused.
- Key headers, case-insensitive: `x-api-key`, `api-key`, `apikey`, `x-auth-token`, `x-api-token`, `x-access-token`, `private-token`, `x-goog-api-key`, `x-figma-token`. Value exactly a placeholder, or `Bearer <placeholder>`.
- Key query parameters, name compared lowercase after percent-decoding: `key`, `api_key`, `apikey`, `api-key`, `access_token`, `token`, `auth`. The decoded value must equal a placeholder. The real value is percent-encoded when it is put in.
- A placeholder whose secret's hosts do not cover `(host, port)`: 403 `wrong_host`.
- A placeholder anywhere else (the path, raw or percent-decoded; another query parameter; another header; a Basic part with more text): 403 `misplaced_placeholder`.
- **Body.** Read the whole body, at most `MAX_REQUEST_BODY` (8 MiB), else 413 `payload_too_large`. Any placeholder of the session in the body: 403 `placeholder_in_body`. The body goes upstream with `Content-Length`.
- A request with no placeholder at all is forwarded as is (public endpoints of the host).
- Nothing is sent upstream before every check passes.

**Upstream.** HTTPS only, HTTP/1.1, one connection per request.
- rustls with ring, `with_safe_default_protocol_versions`, `rustls_platform_verifier::Verifier::new` (system roots; the image has `ca-certificates`), or `Verifier::new_with_extra_roots(options.extra_roots_der)` when extra roots are set (tests).
- The address comes from `options.resolve` for `(host, port)` if present, else DNS. Connect timeout `options.connect_timeout`, I/O timeout `options.io_timeout`.
- Finish the TLS handshake before the first byte (core `open_service` pattern). SNI is the host.
- A connect, TLS, or parse failure: 502 `upstream_failed` with `X-Apassy-Relay: upstream-error`.

**Response.**
- Parse the head with `httparse` (at most 64 KiB, 100 headers). Skip `100 Continue`. A `101`: 501 `not_supported`.
- `Content-Encoding` other than `identity`: 502 `encoded_response` (the body cannot be searched).
- Drop hop-by-hop headers (`connection`, `keep-alive`, `transfer-encoding`, `trailer`, `upgrade`, `content-length`); tiny_http sets the framing again.
- Replace every value of the session with its placeholder in every header value and in the body. Values and placeholders have the same length, so `Content-Length` does not change.
- The encoded forms that this request sent are replaced first, so a host that echoes the request gives back no value: for Basic, `base64(user:value)` becomes the Base64 text that the agent sent; for a key query parameter, `percent_encode(value)` (upper-case and lower-case hex) becomes the placeholder, percent-encoded at the same places, so it has the same length. If no such form of the same length exists: 501 `not_supported`, and nothing goes upstream (a placeholder from `mint` always has one).
- The body is streamed through a `Replacer` (a copy of the core one) that keeps a carry of `max value length - 1` bytes across reads, so a value split across two reads is still replaced. There is no size limit on responses. Framing: `Content-Length` (pass the length to tiny_http), `chunked` (decode, and give tiny_http a reader with no length), or read to close. `HEAD`, 204, and 304 have no body.
- The response the client gets is the upstream status and headers. The relay adds nothing to a forwarded response.

**Refusals.** Every response the relay makes itself on this path has `X-Apassy-Relay: refused` (403, 404, 413, 501) or `X-Apassy-Relay: upstream-error` (502), and an envelope body with the code.

**Audit.** Exactly one `SessionSource::record(ProxyEvent)` per request: method, host, path without query (only when forwarded), status, outcome, code, and the names of the swapped variables. Never a header, query, body, placeholder, value, or key.

## 13. Audit

`src/server/audit.rs`. Append only. No endpoint changes or deletes rows.

- Actions: `team_created`, `invite_created`, `member_joined`, `member_revoked`, `collection_created`, `policy_changed`, `item_added`, `item_archived`, `grant_created`, `grant_revoked`, `agent_created`, `agent_revoked`, `run_requested`, `run_allowed`, `run_pending`, `run_denied`, `run_approved`, `run_timed_out`, `run_invalidated`, `session_started`, `session_ended`, `proxy_request`, `auth_failed`.
- Actor: `member:<id>`, `agent:<id>`, `relay`, or `edge`.
- **Masking.** Before a row is written, its detail JSON text (and the run's command, purpose, user request, cwd) is masked:
  - every item value (all items, live or archived, loaded at start and on add) becomes `[apassy:<ENV_NAME>]`;
  - every live placeholder becomes `[apassy:<ENV_NAME>]`;
  - every text that matches a token form (`apassy_(mbr|agt|inv|ses)_` plus 64 hex) becomes `[apassy:token]`.
- A test puts canary values, placeholders, and tokens into every free-text field (purpose, user request, command, reasons) and checks that no audit row and no API response except the one that issues the secret holds them.

## 14. MCP

**Remote endpoint `POST /mcp`** (`src/server/mcp.rs`). Streamable HTTP, JSON responses only (no SSE; the quick tunnel does not support it). Stateless: no `Mcp-Session-Id`.

- Auth: edge + agent bearer. No or bad token: HTTP 401 with an envelope body.
- If an `Origin` header is present and is not the `public_url` origin: 403 `forbidden`.
- `MCP-Protocol-Version` and other unknown headers are ignored. `tools/list` and `tools/call` work without a prior `initialize` (tolerant of the 2026-07-28 revision, which has no initialize).
- Body: one JSON-RPC message. A JSON array: error -32600. Not JSON: -32700.
- A notification (no `id`) or a response: HTTP 202, empty body.
- `initialize`: `protocolVersion` = the client's if it is one of `2025-11-25`, `2025-06-18`, `2025-03-26`, `2024-11-05`, else `2025-06-18`. `capabilities: {"tools": {"listChanged": false}}`, `serverInfo: {"name": "apassy-relay", "version": <crate version>}`, and `instructions` (below).
- `ping`: `{}`. `tools/list`: the three tools. `tools/call`: below. Other methods: -32601.
- Tool results: success `{"content":[{"type":"text","text":<pretty JSON>}],"structuredContent":<result>,"isError":false}`; failure `{"content":[{"type":"text","text":"<code>: <message>"}],"isError":true}`. A tool failure is not a JSON-RPC error. Unknown tool or bad arguments: `isError` with `invalid_request`.

Tools (all `inputSchema` are `type: object`, `additionalProperties: false`):

| Tool | Arguments | Result |
| --- | --- | --- |
| `apassy_list_access` | none | `AccessView` |
| `apassy_request_run` | `items` (array of integer ≥ 1, minItems 1, required), `command` (array of string, minItems 1, required), `purpose` (string, required), `user_request` (string, required), `cwd` (string), `ttl_secs` (integer) | `RunView` |
| `apassy_run_status` | `run_id` (integer, required), `wait_secs` (integer 0 to 25, default 20) | `RunView` |

`instructions` text: "Apassy relay. Call apassy_list_access to see the credentials you can use. Call apassy_request_run with the exact command, the purpose, and the user's request. If the status is pending, an approver decides: call apassy_run_status until it is ready, denied, or timed_out. When it is ready, run the command yourself with every variable of session.env set. The variables hold placeholders and base URLs, not real values; the relay swaps them. Do not print or store the variables. If apassy-team is installed, prefer `apassy-team run`, which does all of this and keeps the variables out of the transcript."

**Stdio adapter `apassy-team mcp`** (`src/cli/mcp_stdio.rs`): reads newline-delimited JSON-RPC on stdin, posts each message as is to `<relay>/mcp` with the agent token, and writes the response body as one line on stdout. 202: writes nothing. An HTTP failure or no connection: writes a JSON-RPC error (`code: -32000`, message `relay: <code>: <message>`) with the request id, for requests only. Logs go to stderr. A line over 1 MiB: error -32600.

Claude Code config (`.mcp.json` in a repo):

```json
{"mcpServers": {"apassy": {"type": "http", "url": "https://apassy-relay.wyderka.cc/mcp",
  "headers": {"Authorization": "Bearer ${APASSY_TOKEN}"}}}}
```

or `{"command": "apassy-team", "args": ["mcp"]}` with `APASSY_RELAY_URL` and `APASSY_TOKEN` in the environment.

## 15. CLI `apassy-team`

`src/cli/` (track client). Hand-written argument parser, no new crates. HTTPS with `ureq` (`http_status_as_error(false)`, no redirects, timeout 60 s, 30 s more than `wait` for long polls).

Settings and variables:
- `APASSY_RELAY_URL`: the relay origin. Else the settings file.
- `APASSY_TEAM_TOKEN`: a member token. Else the settings file.
- `APASSY_TOKEN`: an agent token (for `access`, `run`, `mcp`).
- `APASSY_EDGE_SECRET`: optional. If set, the CLI sends `X-Apassy-Edge` (to talk to the container directly, for example on `http://127.0.0.1:8080`, and in tests).
- Settings file: `$XDG_CONFIG_HOME/apassy-team/settings.json` or `~/.config/apassy-team/settings.json`, directory 0700, file 0600, `{"relay_url": "...", "member_token": "..."}`. The token is plain text in this file in the alpha.

Commands. A secret (member token, invite code, item value) is read from stdin, never from an argument. If stdin is a terminal, the command refuses and tells the user to pipe the value.

| Command | Does |
| --- | --- |
| `init --relay URL` | reads a member token (the owner token from `apassy-relay init`) from stdin, checks `GET /v1/me`, writes the settings file |
| `join --relay URL --name NAME` | reads the invite code from stdin, `POST /v1/join`, writes the settings file with the new token |
| `me` | `GET /v1/me` |
| `invite [--role member\|manager] [--hours N]` | prints the code once on stdout |
| `members`, `member revoke ID` | list, revoke |
| `collection create NAME [policy flags]`, `collection list`, `collection policy ID [policy flags]` | policy flags: `--mode ask\|bouncer`, `--allow-prefix P` (repeat), `--forbid WORD` (repeat), `--max-runs-per-hour N`, `--instruction TEXT`, `--rule-expires-at UNIX` |
| `item add --collection ID --name NAME --env ENV_NAME --environment ENV [--provider P] [--host H]... [--risk R] [--scope S] [--reversibility R] [--allow-broad-host]` | the value from stdin, one trailing newline removed; prints the id on stdout, and on stderr what each host covers ("api.example.com and every subdomain of it") |
| `item list [--collection ID]`, `item archive ID` | |
| `grant --collection ID --member ID`, `grants`, `revoke --grant ID` | |
| `agent create NAME [--days N]`, `agent list`, `agent revoke ID` | `create` prints the token once |
| `pending` | pending runs with command, purpose, user request, flags, note |
| `approve RUN_ID [--reason TEXT]`, `deny RUN_ID [--reason TEXT]` | |
| `audit [--after ID] [--limit N] [--json]` | |
| `access` | agent token: `GET /v1/access` |
| `run --items 1,2 --purpose TEXT [--request TEXT] [--ttl SECS] [--wait SECS] [--cwd DIR] -- CMD ARGS...` | agent token: `POST /v1/runs` with the exact argv; while `pending`, polls `GET /v1/runs/{id}?wait=25` and prints "Waiting for an approver (run N)." once on stderr; on `ready`, runs the command with `session.env` added to the inherited environment, inherited stdio, and exits with its code (128 + signal on a signal); `cwd` defaults to the current directory |
| `mcp` | the stdio adapter (section 14) |

Human output is short text; `--json` prints the result JSON where it makes sense. The CLI never prints a session environment. Exit codes: 0 success (or the child's code for `run`), 2 usage error, 3 run denied or timed out, 4 relay or network error.

## 16. Docker image

`Dockerfile` (track client):

```dockerfile
# syntax=docker/dockerfile:1
FROM rust:1.97.0-trixie AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY .cargo .cargo
COPY src src
RUN cargo build --release --locked --bin apassy-relay --bin apassy-team

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin relay \
 && mkdir -p /data && chown 10001:10001 /data && chmod 0700 /data
COPY --from=build /src/target/release/apassy-relay /src/target/release/apassy-team /usr/local/bin/
USER 10001:10001
ENV APASSY_RELAY_DATA=/data APASSY_RELAY_LISTEN=0.0.0.0:8080
VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/apassy-relay"]
CMD ["serve"]
```

- `rust-toolchain.toml` is not copied: the builder image is 1.97.0 already.
- The builder image has `perl`, `make`, and a C compiler for the vendored OpenSSL and SQLCipher. `.cargo/config.toml` must be copied for the SQLCipher flags.
- `.dockerignore`: `target`, `.git`, `deploy`, `docs`, `tests`, `.wrangler`, `node_modules`.
- The local build is native (arm64 on colima). For Cloudflare Containers later: `docker buildx build --platform linux/amd64`.

## 17. Cloudflare Worker

`deploy/worker/` (track client): `src/index.ts`, `wrangler.jsonc`, `package.json` (pinned devDependencies, not installed), `test/index.test.ts`.

The Worker, about 40 lines:
- `env.RELAY_ORIGIN` (a var, the quick tunnel URL) and `env.EDGE_SECRET` (a secret). If either is missing: 503 text "relay not configured".
- The target URL is built by string: `origin + url.pathname + url.search`, where `origin = new URL(env.RELAY_ORIGIN).origin`. Never `new URL(path, origin)`: a path such as `//evil.example/x` would change the host and leak the edge secret.
- Headers: a copy of the incoming headers; delete `x-apassy-edge` (any case), then set it to `env.EDGE_SECRET`.
- `fetch(target, {method, headers, body: request.body for methods other than GET and HEAD, redirect: "manual"})`. The body streams; nothing is buffered. Return the response as is.
- No logging of URLs (the path holds session keys). `observability.enabled: false`.

`wrangler.jsonc`:

```jsonc
{
  "name": "apassy-relay-edge",
  "main": "src/index.ts",
  "compatibility_date": "2026-09-01",
  "workers_dev": false,
  "routes": [{ "pattern": "apassy-relay.wyderka.cc", "custom_domain": true }],
  "vars": { "RELAY_ORIGIN": "https://replace-me.trycloudflare.com" },
  "observability": { "enabled": false }
}
```

The secret: `wrangler secret put EDGE_SECRET` (the orchestrator does it, with the deploy). The test runs with Node's built-in runner and type stripping (`node --test deploy/worker/test/`, Node 22.18 or later), with no npm install: the source uses only erasable TypeScript (no enums, no namespaces, no parameter properties).

## 18. docs/OPERATIONS.md (track client)

Plain short sentences. Sections:
1. What runs where (the diagram of section 3).
2. Secrets: make the vault key and the edge secret with `openssl rand -hex 32` into files in `~/.apassy-relay/` (mode 0600). Never in a shell history or a repo.
3. Build the image: `docker build -t apassy-relay:alpha .`.
4. Create the team: `docker run --rm -v apassy-relay-data:/data -v ~/.apassy-relay:/run/secrets:ro -e APASSY_RELAY_KEY_FILE=/run/secrets/vault_key -e APASSY_RELAY_EDGE_SECRET_FILE=/run/secrets/edge_secret -e APASSY_RELAY_PUBLIC_URL=https://apassy-relay.wyderka.cc apassy-relay:alpha init --team <name> --owner <name>`. It prints the owner token once.
5. Start: the same with `-d --name apassy-relay --restart unless-stopped -p 127.0.0.1:8080:8080` and `serve`.
6. Tunnel: `cloudflared tunnel --url http://127.0.0.1:8080`. Copy the `trycloudflare.com` URL into the Worker var `RELAY_ORIGIN`. The URL changes at each cloudflared restart; then the Worker needs the new URL and a deploy. Errors 1016 and 530 mean the tunnel is down or the URL is old.
7. Worker: the var, the secret `EDGE_SECRET` (the same text as the edge secret file), the custom domain. Who deploys.
8. Check: `curl https://apassy-relay.wyderka.cc/healthz`, then `apassy-team init --relay https://apassy-relay.wyderka.cc < owner-token-file`, `apassy-team me`.
9. Team setup walkthrough: collection, item from stdin, invite, join, grant, agent.
10. Agents: `.mcp.json` for Claude Code (HTTP with `Authorization: Bearer ${APASSY_TOKEN}`), the stdio form, `apassy-team run`. A cloud session needs `apassy-relay.wyderka.cc` in the environment's network allowlist (Custom access) and `APASSY_TOKEN` in its environment. Use the name `APASSY_TOKEN`: Claude Code reads some credential names as empty in MCP headers.
11. Approvals: `apassy-team pending`, `approve`, `deny`. Timeouts.
12. Audit: `apassy-team audit`.
13. Backup: stop the container, copy `team.db` out of the volume. It is encrypted with the vault key; keep the key apart from the backup.
14. Revocation: agent, grant, member. Effect at the next request.
15. Limits and what this does not protect (section 20), and the cuts (section 2).

## 19. Tests

Every test starts what it needs in process. No network except 127.0.0.1. No real secrets: canaries such as `sk_test_51SyntheticCanaryValue0123456789abcdefABCDEF`.

**Shared test helpers** (each track owns one file; a test file includes it with `#[path = "common/<file>.rs"] mod <name>;`):

- `tests/common/relay.rs` (server track):
  `pub struct TestRelay { pub url: String, pub edge_secret: String, pub owner_token: String, pub dir: tempfile::TempDir, running: RunningRelay }`,
  `pub fn start(upstream: UpstreamOptions) -> TestRelay` (picks a free port by binding `127.0.0.1:0` and dropping it, sets `public_url = url`, a synthetic key and edge secret, `approval_timeout_secs = 5`, `session_ttl_secs = 60`, runs `Relay::init` then `Relay::start`),
  `pub fn start_with(config: impl FnOnce(&mut RelayConfig), upstream: UpstreamOptions) -> TestRelay`,
  `impl TestRelay { pub fn call(&self, method: &str, path: &str, token: Option<&str>, body: Option<&serde_json::Value>) -> (u16, serde_json::Value); pub fn stop(self) }` (`call` sends the edge header).
- `tests/common/upstream.rs` (proxy track):
  `pub struct MockUpstream { pub addr: SocketAddr, pub ca_der: Vec<u8>, .. }`,
  `pub fn start(hosts: &[&str]) -> MockUpstream` (an HTTPS server on `127.0.0.1:0` with an rcgen CA and one leaf for all `hosts`, a thread per connection),
  `impl MockUpstream { pub fn options(&self) -> UpstreamOptions; pub fn requests(&self) -> Vec<Recorded> }` (`options` sets `extra_roots_der = [ca_der]` and `resolve = [(host, 443, addr)]` for each host),
  `pub struct Recorded { pub method: String, pub target: String, pub headers: Vec<(String, String)>, pub body: Vec<u8> }`.
  Default answer: 200, `Content-Type: application/json`, header `X-Echo-Authorization: <the Authorization header>`, body `{"method","target","authorization","headers":{..},"body":"<utf-8 lossy>"}`. Special targets: `/chunked` (the same JSON, chunked, in pieces of 7 bytes), `/big?n=N` (N copies of the Authorization header value separated by one byte, chunked), `/gzip` (`Content-Encoding: gzip`), `/redirect` (302 with `Location: https://<host>/echo`).

**Server track** (`tests/server_*.rs` and unit tests):
- Vault: wrong key refused; the file bytes do not contain a canary value; `init` twice refused; compile options checked.
- Edge: no header and a wrong header give 403 `edge_refused`; `/healthz` works without it.
- Tokens and roles: every endpoint with no token, a wrong-kind token, a revoked token; a member cannot add items, read approvals, or read the audit; a manager cannot invite a manager; the owner cannot revoke themselves.
- Invites: one use; expired; wrong code; name conflict.
- Items: env name rules; no host refused; short value gives `placeholder_impossible`; no endpoint response ever holds the value (scan every GET response for the canary).
- Grants and access: an agent of an ungranted member gets `not_granted` for a real and an unknown id alike; `GET /v1/access` lists only granted items.
- Decision matrix, each a test: `git status` with a staging item and a user request → `ready`; the same without a user request → `pending`; with a production item → `pending` with the ADR 0010 note; `stripe refunds create` → `pending` with `ask_owner`; `rm -rf /` → `pending` with `data_loss`; `python3 script.py` → `pending`; a user request with an injection phrase → `pending` with `injection_phrase`; policy mode `ask` → `pending`; each hard rule → 403 with its code and a `run_denied` audit row.
- Approvals: approve → `ready` with a session; placeholders have the value's length and differ from it; `APASSY_BASE_*` and `STRIPE_API_BASE` start with `<public_url>/p/apassy_ses_`; deny → `approval_denied`; timeout → `timed_out`; a grant revoked while pending → `approval_invalidated`; approve twice → `run_not_pending`; `GET /v1/runs/{id}` by another agent → 404; `wait` holds and returns on approval.
- Sessions: `SessionSource::find` by key; `None` after expiry and after revoking the agent, the grant, the member, or the item.
- Audit: canaries, placeholders, and tokens in purpose, user request, command, and reasons never appear in `GET /v1/audit`.
- MCP: `initialize` version negotiation; a notification → 202; `tools/list` has the three tools with their schemas; `tools/call` for each tool; unknown method → -32601; bad JSON → -32700; array → -32600; no token → 401; wrong `Origin` → 403; `GET /mcp` → 405; `tools/call` without `initialize` works.

**Proxy track** (`tests/proxy_*.rs` and unit tests). The test hosts `Proxy` in a tiny_http server on `127.0.0.1:0` and gives it a test `SessionSource` (a map, and a list of recorded events), with `MockUpstream::options()`:
- Bearer: the upstream sees the value; the echoed value comes back as the placeholder in the body and in `X-Echo-Authorization`; the client never sees the value.
- Basic user and password; a key header (`x-api-key`); a key query parameter (`api_key`, with a value that needs percent-encoding).
- Refusals with 403 and `X-Apassy-Relay: refused`, and the upstream got nothing: a placeholder in the path, in the percent-decoded path, in another header, in another query parameter, in the body, inside a Basic part with more text; a placeholder of item A sent to a host of item B (`wrong_host`); a host not in the session; an unknown key; an expired session; a malformed key.
- `Accept-Encoding` is not forwarded; `/gzip` → 502 `encoded_response`; `/chunked` and `/big?n=5000` come back whole with every value replaced; a 9 MiB body → 413; an upstream certificate from an unknown CA → 502 `upstream_failed`; `Upgrade: websocket` → 501; `/redirect` passes the 302 through.
- Events: one per request; the serialized events never hold a value, a placeholder, or the key.
- Unit tests of the swap, the scanner, and the replacer (port the core tests with attribution).

**Client track** (`tests/cli_*.rs` and unit tests), with the binary `env!("CARGO_BIN_EXE_apassy-team")` and a recording HTTP server in the test (tiny_http) that answers with envelopes:
- The parser for every command, and usage errors exit 2.
- Settings file mode 0600 and directory 0700; variables win over the file.
- Each command sends the right method, path, bearer, edge header (when set), and body; `item add` sends the value from stdin and never prints it.
- `run`: pending then ready; the child sees the placeholder and the base URL (the test runs `sh -c 'printf "%s|%s" "$FOO_KEY" "$APASSY_BASE_FOO_KEY" > out'`); the exit code passes through; denied → 3.
- `mcp`: a request line is forwarded and answered on one line; a notification gives no output; relay down → a JSON-RPC error with the request id.
- Worker: `node --test deploy/worker/test/`: the edge header is replaced, a `//evil.example/x` path stays on the relay origin, method, query, and body pass through.
- If Docker works on the machine: `docker build -t apassy-relay:alpha .` succeeds and `docker run --rm apassy-relay:alpha init` without variables exits with a clear error. Not part of `cargo test`.

**End to end** (`tests/e2e.rs`, the merger, after the three merges). One relay with `MockUpstream::start(&["api.stripe.com", "api.github.com"])`:
1. The owner makes a collection "payments", a staging Stripe item with a canary value (provider `stripe`), and a production GitHub item (hosts `api.github.com`).
2. The owner invites; a member joins; the owner grants the collection; the member makes an agent.
3. The agent asks for `stripe balance retrieve` with the Stripe item and a user request: `ready` at once. It calls `STRIPE_API_BASE + "/v1/balance"` with `Authorization: Bearer <placeholder>` and the edge header. The mock saw the canary; the agent got the placeholder back in the body and in `X-Echo-Authorization`.
4. The agent asks for `git status` with the GitHub item: `pending` (production). The owner denies: `approval_denied`. It asks again; the owner approves; the run is `ready`.
5. A placeholder in the path → 403 refused; the Stripe placeholder sent to `api.github.com` → 403 `wrong_host`.
6. The owner revokes the grant. The next proxy request → 403 `session_invalid`. A new run → 403 `not_granted`.
7. The same flow through MCP (`/mcp` `tools/call apassy_request_run`) and through the CLI (`apassy-team run` with `APASSY_EDGE_SECRET`, writing its environment to a file that the test then uses).
8. The whole audit, as JSON text, holds no canary, no placeholder, no token, no session key.

## 20. What this does not protect

- The relay holds the vault key and every value in memory while it runs. Root on the Mac or the VM can read them.
- A session key and a placeholder together are a credential for the hosts of that item, in auth positions only, until the session ends. They can end up in an agent transcript if the agent runs the command itself. `apassy-team run` avoids that.
- The relay approves a stated command. In way B it cannot check what the agent really runs with the session. It controls which hosts get the value, where the value goes in a request, and for how long.
- Cloudflare sees all traffic in clear, including session keys in paths and placeholders in headers. It never sees a value on the agent side. It sees values on the relay-to-upstream side only if Cloudflare is that upstream.
- The quick tunnel has no SLA and a changing URL.
- An owner can approve their own agent's runs.
