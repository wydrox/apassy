# apassy-relay alpha: specification

Date: 2026-09-30. Status: the plan for one day of work by three developers, changed the same day for host-held item keys (section 21).
Design source: ADR 0013 of the core (way B only). Core crate: `wydrox/apassy` at rev `77f6628`.

## 1. What the alpha does

- A team keeps shared credentials on the relay as sealed values, in one encrypted vault. The relay never stores a readable value: the key of each item stays on the owner's host (`apassy-team host`, section 21).
- One relay holds several teams, each in its own encrypted file with its own state (section 22). The operator gives a one-time team code; its holder creates a team and is its owner. Members join with one-time invite codes.
- Items live in collections. A collection has a policy. A grant gives one member the use of one collection.
- A member creates agent tokens. An agent asks for a run: items, command, purpose, and the user's request.
- The relay checks the core hard rules and runs the core command analysis. A hard-rule failure is denied at once. Every other run waits for the owner's host, with the relay's verdict (allow or ask) as a suggestion.
- The owner's host runs its own check with its own data. It releases the keys of that run's items to the relay, sealed to a one-time key of the run, or it asks the owner on the terminal, or it denies. A known-safe command with a non-production item is released without a question.
- A released run gets a session: placeholders, and base URLs that point at the relay. The relay opens the values in memory for that session only.
- The relay reverse-proxies `/p/<session key>/<host>/<path>` to `https://<host>/<path>`. It puts the real value only in an auth position, only for a host of that item. It puts the placeholder back in the response.
- The owner or a manager can deny a waiting run with the CLI. Nobody approves on the relay.
- The audit records every step. It never holds a value, a placeholder, a token, a session key, or key material.
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
- Approvals in an app, on the web, or in Slack. The owner decides at the terminal of the host (`apassy-team host`) only.
- Item keys on another machine than the owner's (no sharing of keys to the machines of managers or members), and a key file that is not plain text (a Keychain or another store). The key file is plain on the owner's disk in this alpha.
- A migration of a vault from the first alpha (it held plaintext values). Such a vault is refused at start.
- Keep-alive to upstream hosts, HTTP/2, WebSocket and `Upgrade` (501), SSE through the quick tunnel.
- Rewriting of redirects. A `Location` header passes through, so a client that follows it goes to the real host with a placeholder and fails closed.
- Compressed upstream responses. The relay asks for identity. A compressed answer is a 502.
- Request bodies over 8 MiB (413). AWS SigV4 and other signed requests.
- Items that are not HTTP API keys (for example a Postgres URL). An item whose value cannot get a placeholder is refused.
- The `gh` CLI. `GH_HOST` cannot carry a path, so only `GITHUB_API_URL` is set.
- Sessions that survive a relay restart. A restart ends every session.
- TLS in the relay (Cloudflare ends TLS), Let's Encrypt.
- Device keys, invite links with grants, confirmed joins, limits per team, and the owner's delete of a team (ADR 0019, stages 2 to 4). In this stage a member still signs in with a member token.
- A key typed at start (D7 of the ADR). The key comes from a variable or a file.
- Self-approval checks. The owner's host may release a run of the owner's own agent.

## 3. Deployment today

Since 2026-10-01 the relay runs on a Linux VPS behind a named tunnel and a Workers VPC binding (OPERATIONS.md, section 16). The quick tunnel below is the first setup.

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
- The owner's Mac also runs `apassy-team host`. It calls the relay through the same path (Worker, tunnel) with the owner token, and holds `keys.json` (section 21). The host endpoints `/v1/host/...` are ordinary member-lane requests: the Worker forwards them like any other.

## 4. Crate layout and ownership

One crate, `apassy-relay`, license `FSL-1.1-ALv2` (FSL-1.1 with the Apache-2.0 future license). Rust 1.97.0, edition 2024, `#![forbid(unsafe_code)]`, clippy `all = "warn"`.

| Path | What | Owner |
| --- | --- | --- |
| `Cargo.toml`, `Cargo.lock`, `.cargo/config.toml`, `rust-toolchain.toml`, `LICENSE` | Build and license | skeleton (frozen) |
| `src/lib.rs`, `src/api.rs`, `src/config.rs`, `src/error.rs`, `src/ids.rs`, `src/secret.rs`, `src/session.rs` | Shared types | skeleton (frozen) |
| `tests/build_options.rs` | SQLCipher build flags | skeleton (frozen) |
| `docs/SPEC.md` | This file | skeleton (frozen) |
| `src/hostkeys.rs`, `src/decision.rs` | Host-held item keys: the crypto and formats, and the pure part of the decision (used by the relay and by the host) | server |
| `src/server/**`, `src/bin/apassy-relay.rs`, `tests/server_*.rs`, `tests/common/relay.rs` | Track server (`server/host.rs` and `server/runkeys.rs`: the host endpoints and the run keys) | server |
| `src/proxy/**`, `tests/proxy_*.rs`, `tests/common/upstream.rs` | Track proxy | proxy |
| `src/cli/**`, `src/bin/apassy-team.rs`, `tests/cli_*.rs`, `tests/host_cli.rs`, `Dockerfile`, `.dockerignore`, `deploy/**`, `docs/OPERATIONS.md`, `README.md` | Track client (`cli/host.rs` and `cli/keystore.rs`: the owner's host and the key store) | client |
| `tests/e2e.rs` | End-to-end test | merger |

Rules for tracks:

- A track edits only its own paths. A track does not edit a frozen file. If a shared type is missing, the track adds its own type in its own module and says so in its report.
- No new dependencies. Every dependency is already pinned with `=` in `Cargo.toml`. The one addition of the host-keys change is `ring` (`=0.17.14`), which is already in the lock through rustls.
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
| `base64` | `=0.23.1` | Basic auth in the swap, and binary fields on the wire (URL-safe, no padding) |
| `ring` | `=0.17.14` | host-held item keys: X25519 (`agreement`), HKDF-SHA256 (`hkdf`), AES-256-GCM (`aead`), `rand::SystemRandom` |
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
| `APASSY_RELAY_DATA` | data dir: `relay.db`, `teams/<team id>.db`, `admin.sock` (section 22) | `/data` |
| `APASSY_RELAY_LISTEN` | listener address | `0.0.0.0:8080` |
| `APASSY_RELAY_PUBLIC_URL` | public origin, for base URLs and the MCP `Origin` check | required |
| `APASSY_RELAY_EDGE_SECRET` / `_FILE` | edge secret, at least 32 bytes | required |
| `APASSY_RELAY_KEY` / `_FILE` | the master key: it opens `relay.db`, which holds the random key of each team file; at least 16 bytes | required |
| `APASSY_RELAY_SESSION_TTL` | session lifetime, 60 to 3600 s | 900 |
| `APASSY_RELAY_APPROVAL_TIMEOUT` | wait for the owner's host to decide a run, 30 to 86400 s | 600 |

`UpstreamOptions` (extra roots, fixed addresses) is not read from the environment. Tests set it in code.

`apassy-relay migrate` also reads `APASSY_RELAY_OLD_KEY` / `_FILE`: the passphrase of a `team.db` from before teams. `apassy-relay admin` reads only `APASSY_RELAY_DATA`.

## 7. Auth model

- **Edge.** Every request except `GET /healthz` must carry `X-Apassy-Edge: <edge secret>`. The relay compares it with `secret::same_bytes`. A missing or wrong header gets 403 `edge_refused`, and an audit row with actor `edge` (at most one row per 10 seconds, so a scan cannot fill the audit).
- **Tokens.** Every token is 32 random bytes (`getrandom`) as 64 lowercase hex characters after a prefix (`secret::new_token`). The vault stores only `sha256(token)` (`secret::token_hash`). A lookup is by hash. A token is shown once, when it is made.

| Kind | Prefix | Made by | Sent as | Lifetime |
| --- | --- | --- | --- | --- |
| Member token (owner, manager, member) | `apassy_mbr_` | `apassy-relay init` or `POST /v1/teams` (owner), `POST /v1/join` | `Authorization: Bearer <token>` | until the member is revoked |
| Agent token | `apassy_tagt_` | `POST /v1/agents` by a member | `Authorization: Bearer <token>` | 1 to 365 days, default 30 |
| Invite code | `apassy_inv_` | `POST /v1/invites` | in the body of `POST /v1/join` | one use, 1 to 168 hours, default 72 |
| Session key | `apassy_ses_` | the relay, when the host releases a run | in the path `/p/<key>/...` | the session TTL |
| Team code | `apassy_tcd_` | the operator, `apassy-relay admin team-code` | in the body of `POST /v1/teams` | one use, 1 to 720 hours, default 72 |

- Every token of a team names its team: `<prefix><team id>_<64 hex>`, for example `apassy_mbr_t_7k2m9q4x8c_<64 hex>`. A team code names no team: `apassy_tcd_<64 hex>`. The relay reads the team id first and looks the hash up in that team's file only (section 22).
- A member token `apassy_mbr_<64 hex>` or an agent token `apassy_agt_<64 hex>` of a relay from before teams has no team id. Only the migrated team accepts them.

- A bearer with the wrong kind for an endpoint gets 401 `unauthenticated`. An expired agent token gets 401 `token_expired`.
- Revocation works at the next request: the token hash is looked up each time, and revocation ends live sessions at once.
- Roles: `owner` (one, made at init), `manager`, `member`. Only the owner invites a manager and revokes a member. Owner and manager add collections, items, grants, and deny waiting runs. Only the owner's member token reaches the host endpoints (section 9), because only the owner's host holds item keys: a manager can deny a run but cannot release one. Every member makes and revokes their own agents. An agent acts for its member and can use only that member's grants.

## 8. Team vault

One SQLCipher file, `<data dir>/team.db`, owned by the server track (`src/server/store.rs`).

- Open with `rusqlite`. Before any other statement: `PRAGMA key` with the passphrase, then the core parameters: `cipher_page_size = 4096`, `kdf_iter = 256000`, `cipher_hmac_algorithm = HMAC_SHA512`, `cipher_kdf_algorithm = PBKDF2_HMAC_SHA512`, `cipher_memory_security = ON`. Then `SELECT count(*) FROM sqlite_master` to check the key.
- At open, check `PRAGMA compile_options`: it must have `OMIT_LOAD_EXTENSION` and `DEFAULT_LOOKASIDE=0,0`, and must not have `ENABLE_LOAD_EXTENSION` or `USE_URI`. Refuse to start otherwise.
- The file and its directory get mode 0600 and 0700. `journal_mode = WAL` is not used (one file only): `journal_mode = DELETE`, `foreign_keys = ON`, `secure_delete = ON`.
- One connection behind a `Mutex`. The team is small.
- The schema has a version in `PRAGMA user_version` (2). Version 1 was the first alpha: it kept the item values in the vault. A vault with version 1 is refused at start with a clear message (it holds plaintext values; start with a new data volume). There is no migration. Any other version is refused as unknown.

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
  name TEXT NOT NULL, env_name TEXT NOT NULL,
  uid TEXT NOT NULL UNIQUE,                    -- 32 lowercase hex: the name of the item on the host
  sealed BLOB NOT NULL,                        -- nonce || AES-256-GCM ciphertext || tag: no readable value
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
  decided_by TEXT, approver_id INTEGER REFERENCES member(id), code TEXT,  -- decided_by: approver (a deny), revocation, timeout, host
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
- `uid` and `sealed` replace the value. The relay cannot read the value, so it checks only the shape: `uid` is 32 lowercase hex characters and unused (else 400 `invalid_request`, or 409 `conflict` for a used uid), and `sealed` is base64url without padding that decodes to 12 + 16 + 1 to 4096 bytes (else 400 `invalid_request`). A body with a `value` field is refused (`deny_unknown_fields`): an old client cannot send a value by mistake.
- The value rules are the CLI's, before it seals the value: 1 to 4096 bytes of printable ASCII (space to `~`), with no quote (`"`) and no backslash (JSON writes such a value as it is, so a JSON echo of it in a response is found), and `proxy::mint(value)` must return a placeholder. The relay checks the same rules again when it opens a release, and refuses the release if a value fails them.
- The relay keeps no readable value, and no endpoint returns the sealed text. The `uid` goes only to the host, in a host request.

## 9. HTTP API

- Plain HTTP/1.1 on one port. JSON bodies at most 64 KiB (`api::MAX_JSON_BODY`), else 413 `payload_too_large`. Unknown fields are refused where the type says `deny_unknown_fields`.
- Every JSON response is the core envelope (`api::Envelope`): `{"ok":true,"result":...}` or `{"ok":false,"error":{"code":"...","message":"..."}}`. The HTTP status comes from `error::status_of(code)`.
- `Content-Type: application/json` on every JSON response. `Cache-Control: no-store` on every `/v1` and `/mcp` response.
- Load (`config::Limits`, not read from the environment). At most 256 requests run at once. Agent paths (`/p/`, `/mcp`, `/v1/runs`, `/v1/access`) can be slow, so they take at most 256 - 32 of them. The other 32 are kept for members, approvers, the owner's host (`/v1/host/...` is in the member lane, not the agent lane), and `/healthz`. A request over a limit gets 503 `busy` as an envelope, with `Retry-After: 2`. `apassy-team run` asks again after a `busy` answer while it waits.
- Auth column: `edge` = edge header only; `member` = edge + member bearer; `approver` = member bearer with role owner or manager; `owner` = owner bearer; `agent` = edge + agent bearer; `any` = member or agent bearer.

| Method and path | Auth | Body | Result |
| --- | --- | --- | --- |
| `GET /healthz` | none | | `200 ok` (text), no envelope |
| `GET /v1/me` | any | | `MeView`, with `team_id` |
| `POST /v1/teams` | edge | `TeamCreate {code, team, owner}` | `TeamCreated {team_id, member_id, secret: owner token}`; a wrong, used, or expired code is 403 `invite_invalid`; the names are checked before the code, so a bad name does not use it |
| `POST /v1/join` | edge | `JoinRequest {code, name}` | `Issued {id: member id, secret: member token}`; the team comes from the code |
| `POST /v1/invites` | approver | `InviteRequest {role, expires_hours?}` | `Issued {id: invite id, secret: code, expires_at}` |
| `GET /v1/invites` | approver | | `[InviteView]` |
| `GET /v1/members` | approver | | `[MemberView]` |
| `DELETE /v1/members/{id}` | owner | | `Created {id}`; revokes the member, their agents, grants, sessions, pending runs. The owner cannot revoke themselves. |
| `POST /v1/collections` | approver | `CollectionCreate {name, policy?}` | `Created {id}` |
| `GET /v1/collections` | member | | `[CollectionView]`: all for approvers, granted ones for members |
| `PUT /v1/collections/{id}/policy` | approver | `Policy` | `CollectionView` |
| `POST /v1/items` | approver | `NewItem {collection_id, name, env_name, uid, sealed, provider?, hosts?, environment, risk?, scope?, reversibility?, allow_broad_host?}` | `ItemCreated {id, hosts}` |
| `GET /v1/items?collection={id}` | member | | `[ItemView]`: live items; members see granted collections only |
| `DELETE /v1/items/{id}` | approver | | `Created {id}`; archives the item and ends sessions that hold it |
| `POST /v1/grants` | approver | `GrantCreate` | `Created {id}` (409 `conflict` if a live grant exists) |
| `GET /v1/grants` | approver | | `[GrantView]` live grants |
| `DELETE /v1/grants/{id}` | approver | | `Created {id}`; ends the member's sessions with items of that collection |
| `POST /v1/agents` | member | `AgentCreate {name, days?}` | `Issued {id: agent id, secret: agent token, expires_at}` |
| `GET /v1/agents` | member | | `[AgentView]`: own agents; approvers see all |
| `DELETE /v1/agents/{id}` | member | | `Created {id}`; own agent, or any agent for an approver; ends its sessions |
| `GET /v1/approvals` | approver | | `[ApprovalView]` pending runs, oldest first |
| `POST /v1/approvals/{run_id}/approve` | approver | any | always 403 `approve_on_host`: "The keys are on the owner's host. Approve there with apassy-team host." |
| `POST /v1/approvals/{run_id}/deny` | approver | `DecisionRequest {reason?}` | `RunView`; also drops the run key |
| `GET /v1/host/requests?wait={s}` | owner | | `[HostRequestView]`: pending runs that have a key in memory and are not past `expires_at`, oldest first. `wait` 0 to 25: while the list is empty, hold the response up to that many seconds. At most 2 host long polls at once (`Limits::host_long_polls`); a poll over that is answered at once, as with `wait=0`. |
| `POST /v1/host/requests/{run_id}/release` | owner | `ReleaseRequest {host_key, nonce, sealed_keys, reason?}` | `RunView` without `session` (section 11) |
| `POST /v1/host/requests/{run_id}/deny` | owner | `DecisionRequest {reason?}` | `RunView`; also drops the run key |
| `GET /v1/audit?after={id}&limit={n}` | approver | | `[AuditEntry]`, id ascending, limit 1 to 500, default 100 |
| `GET /v1/access` | agent | | `AccessView` |
| `POST /v1/runs` | agent | `RunRequest` | `RunView` (`pending`; a hard-rule denial is 403) |
| `GET /v1/runs/{id}?wait={s}` | agent | | `RunView`. Only the agent that made the run; else 404. `wait` 0 to 25: while `pending`, hold the response up to that many seconds. An agent has at most 4 long polls open (`Limits::long_polls_per_agent`); a poll over that is answered at once, as with `wait=0`. |
| `POST /mcp` | agent | JSON-RPC | section 14 |
| `GET /mcp`, `DELETE /mcp` | agent | | 405 |
| `ANY /p/{session key}/{host}/{path}` | edge | any | the upstream response, section 12 |

Other paths: 404 `not_found`. A known path with another method: 405 `method_not_allowed`.

Error codes are in `src/error.rs` (`codes`). The main ones: `invalid_request` 400, `placeholder_impossible` 400, `broad_host` 400, `unauthenticated` 401, `token_expired` 401, `edge_refused` 403, `forbidden` 403, `invite_invalid` 403, `not_granted` 403, `item_archived` 403, `rule_expired` / `rule_command_not_permitted` / `rule_forbidden_word` / `rule_rate_limit` 403, `not_found` 404, `method_not_allowed` 405, `conflict` 409, `run_not_pending` 409, `payload_too_large` 413, `relay_error` 500, `busy` 503. The host-keys change adds `approve_on_host` 403 (the approve endpoint) and `release_invalid` 403 (a release that did not check). Proxy codes are in section 12. `approval_denied`, `approval_timeout`, `approval_invalidated`, and `release_invalid` appear in `RunView.code` too. A hard-rule denial and `release_invalid` are HTTP errors as well; the other three are not.

`POST /v1/join`: the code must be a live invite (not used, not expired), else 403 `invite_invalid` (one message for every case). The name: 1 to 64 bytes of `[A-Za-z0-9._-]`, unique, else 409 `conflict`. The invite is marked used in the same transaction.

## 10. Decision per run

`POST /v1/runs` (and the MCP tool `apassy_request_run`). Order, in `src/server/decide.rs`. Steps 5 to 8 (analysis, user request, declarations, the core rules) are one pure function, `decision::assess` in `src/decision.rs`, that the owner's host calls too, with its own data (section 21).

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
8. **Verdict** (no model). It is a suggestion to the host, not a decision:
   - `apassy::broker::bouncer::before_model(&ctx)` is `Some(d)`: **ask**, note `d.note`. This covers, in order: a production item ("Production credential: the owner approves every run with it (ADR 0010)."), any flag ("Rule flags: a, b"), no user request, no declaration.
   - else a collection of the run has `policy.mode = ask`: **ask**, note "The policy of collection <name> asks for every run."
   - else `analysis.known_safe`: **allow**, note "Known safe command. No rule asked."
   - else: **ask**, note "Not a known safe command. The relay has no model, so a person decides."
9. **Pending.** Every run that passed the hard rules is stored as `pending`, whatever the verdict. `expires_at = now + approval_timeout`. The verdict is kept as the `suggestion` (`allow` or `ask`) with its note and flags. The relay makes one X25519 `EphemeralPrivateKey` for the run and keeps it in memory only (section 21). No session exists yet: the session comes with the release of the host (section 11). A hard-rule denial stays immediate (403, no host).
10. Write the run row and the audit rows `run_requested` (items, masked command, purpose, user request, cwd, flags, note) and `run_pending` (note, suggestion, `expires_at`).

Flags that ask include every flag the core emits: `secret_output`, `data_loss`, `irreversible`, `production`, `real_recipient`, `remote_code`, `remote_access`, `system_change`, `new_dependency`, `privilege`, `hook_channel`, `ask_owner`, `foreign_host`, `injection_phrase`, and `rule_pack_error`. Measured at rev 77f6628: `git status`, `ls -la`, `cargo test`, `gh repo list`, `stripe balance retrieve` are known safe; `stripe refunds create` gets `ask_owner`; `rm -rf /` gets `data_loss`; `sh -c 'echo $STRIPE_API_KEY'` gets `secret_output`; `python3 script.py` is clean but not known safe (asks).

Unavailable is never an allowance: any error in the analysis, the store, the key of the run, or the session creation denies or asks. It never allows. There is no flag, variable, or hook that lets the relay or the host release a run that the policy would ask about.

## 11. Session lifecycle and environment

States of a run: `pending` → `ready` → `ended`, or `pending` → `denied` / `timed_out`. A run becomes `ready` only by a release of the owner's host.

- **Release** (`POST /v1/host/requests/{id}/release`, owner token): the run must be `pending`, not past `expires_at`, and must have its run key in memory, else 409 `run_not_pending` (a past run becomes `timed_out` first). The relay takes the run key out of its table first: the key is used up whatever happens next. Then it checks step 1 and step 3 again for the agent and the items. A failure: status `denied`, `code = approval_invalidated`, `decided_by = revocation`, audit row `run_invalidated` (HTTP 200 with that `RunView`). Then it opens the release and decrypts the values (section 21). Success: create the session, status `ready`, `decided_by = host`, note = the reason (trimmed, at most 500 bytes, masked like every note; a longer reason is 400 before the key is used) or "Released by the owner's host.", audit rows `run_released` (run id, item ids, suggestion, note; no key material) and `session_started`. The session lifetime starts at the release: `session_expires_at = release time + (ttl_secs or config.session_ttl_secs)`. Any crypto or format failure: status `denied`, `code = release_invalid`, `decided_by = host`, audit row `run_denied`, no session, and HTTP 403 `release_invalid`. A body that is not a `ReleaseRequest` (not JSON, an unknown field, a wrong type) is 400 `invalid_request` and does not use the key.
- **Deny** (`POST /v1/host/requests/{id}/deny`, owner token, or `POST /v1/approvals/{id}/deny`, owner or manager): the run must be `pending`: status `denied`, `code = approval_denied`, `decided_by = host` or `approver`, note = reason or "Denied by the owner's host." or "Denied by <name>.". The run key is dropped.
- **Approve** (`POST /v1/approvals/{id}/approve`): always 403 `approve_on_host`.
- **Timeout**: checked lazily at each read of the run, each list of approvals, each host poll, and by the sweep every 5 seconds: a `pending` run past `expires_at` becomes `timed_out`, `code = approval_timeout`, `decided_by = timeout`, with an audit row, and its key is dropped. A run with no host, or with a host that does not answer, ends here. So does a pending run after a relay restart: it has no key in memory, is never shown to the host, and times out as any run does.
- **Revocation** of an agent, a member, a grant, or an item: the pending runs that depend on it are denied at once (`approval_invalidated`, `decided_by = revocation`, audit row `run_invalidated`) and their run keys are dropped; live sessions that depend on it end at once (removed from the session table, their values erased), with an audit row `session_ended`.
- **Expiry**: `SessionSource::find` returns `None` after `expires_at`. `GET /v1/runs/{id}` then shows `ended`, and the sweep removes the session and erases its values.
- The run keys never go to disk. They are dropped at release, deny, timeout, revocation, and at stop or restart. The sweep also drops the key of any run that is not pending.

**Session creation** (`src/server/sessions.rs` and `src/server/env.rs`):

- `session key = secret::new_token(TokenKind::Session)`. The table is keyed by `token_hash(key)`. `session_expires_at = now + (request.ttl_secs or config.session_ttl_secs)`.
- For each item, `placeholder = proxy::mint(&value)`, where `value` is the value decrypted from the release. `None` is `relay_error` (the CLI and the release check make it rare).
- `LiveSession {id, run_id, agent_id, member_id, expires_at, secrets: [SessionSecret {item_id, env_name, placeholder, value, hosts}]}` goes into the table. The `SessionView` for the agent is kept next to it, in memory only.
- Nothing of a session is written to disk except its id, run id, and expiry. The values of a session are the only readable item values that the relay ever holds, in memory, in `Zeroizing` strings. Each removal of a session (expiry, revocation, stop) erases them and drops them from the audit masks.

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

- Actions: `team_created`, `invite_created`, `member_joined`, `member_revoked`, `collection_created`, `policy_changed`, `item_added`, `item_archived`, `grant_created`, `grant_revoked`, `agent_created`, `agent_revoked`, `run_requested`, `run_pending`, `run_released`, `run_denied`, `run_timed_out`, `run_invalidated`, `session_started`, `session_ended`, `proxy_request`, `auth_failed`. (`run_allowed` and `run_approved` of the first alpha are not written any more: no run starts without a release.)
- Actor: `member:<id>`, `agent:<id>`, `relay`, `edge`, or `operator` (section 22).
- Each team has its own audit in its own file. A request that names no known team (no edge header, a token or session key of no live team) is written to the audit of the relay in `relay.db`, at most one row per 10 seconds for each kind, and never to a team. Operator actions are written there too, and also to the audit of the team they touch.
- **Masking.** Before a row is written, its detail JSON text (and the run's command, purpose, user request, cwd) is masked:
  - every item value that a live session holds becomes `[apassy:<ENV_NAME>]`. The relay holds a value only while a session lives (it never stores one), so it can mask a value only for that time. The value is added to the masks when the session is made and dropped when the session ends. The CLI refuses an item whose name, provider, or host contains its value;
  - every live placeholder becomes `[apassy:<ENV_NAME>]`;
  - every text that has the shape of a token (`apassy_(mbr|tagt|agt|inv|ses|tcd)_`, then a team id and `_` or nothing, then 64 hex) becomes `[apassy:token]`.
- A row never holds key material: no item key, no sealed text, no `run_key`, `host_key`, `nonce`, or `sealed_keys`. `run_released` names the run and the item ids.
- A test puts canary values, placeholders, and tokens into every free-text field (purpose, user request, command, reasons) while a session holds the values, and checks that no audit row and no API response except the one that issues the secret holds them, and that no row holds key material.

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

`instructions` text: "Apassy relay. Call apassy_list_access to see the credentials you can use. Call apassy_request_run with the exact command, the purpose, and the user's request. The status is pending until the owner's host releases the keys of the items: it does so by itself for a known safe command, and it asks the owner for any other. Call apassy_run_status until it is ready, denied, or timed_out. When it is ready, run the command yourself with every variable of session.env set. The variables hold placeholders and base URLs, not real values; the relay swaps them. Do not print or store the variables. If apassy-team is installed, prefer `apassy-team run`, which does all of this and keeps the variables out of the transcript."

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
- Key store: `keys.json` in the same directory, and `host.log` next to it (section 21). Mode 0600; the directory stays 0700. `keys.json` is written atomically (a temp file with mode 0600, then a rename), under a lock file, so two commands do not lose each other's entry.

Commands. A secret (member token, invite code, item value) is read from stdin, never from an argument. If stdin is a terminal, the command refuses and tells the user to pipe the value.

| Command | Does |
| --- | --- |
| `init --relay URL` | reads a member token (the owner token from `apassy-relay init`) from stdin, checks `GET /v1/me`, writes the settings file |
| `create --relay URL --team NAME --name NAME` | reads a team code of the operator from stdin, `POST /v1/teams`, writes the settings file with the owner token of the new team |
| `join --relay URL --name NAME` | reads the invite code from stdin, `POST /v1/join`, writes the settings file with the new token |
| `me` | `GET /v1/me`; prints the team id after the team name |
| `invite [--role member\|manager] [--hours N]` | prints the code once on stdout |
| `members`, `member revoke ID` | list, revoke |
| `collection create NAME [policy flags]`, `collection list`, `collection policy ID [policy flags]` | policy flags: `--mode ask\|bouncer`, `--allow-prefix P` (repeat), `--forbid WORD` (repeat), `--max-runs-per-hour N`, `--instruction TEXT`, `--rule-expires-at UNIX` |
| `item add --collection ID --name NAME --env ENV_NAME --environment ENV [--provider P] [--host H]... [--risk R] [--scope S] [--reversibility R] [--allow-broad-host]` | the value from stdin, one trailing newline removed. Checks the value locally (section 8; the relay cannot). Makes a uid and an item key, seals the value, writes the entry to `keys.json` (before the upload), and sends only `uid` and `sealed`. After the relay took the item it sets `item_id` (and the hosts the relay stored) in the entry. If the relay refuses the item, or the request certainly did not reach it, the entry is removed. If the outcome is unknown (a timeout or a dropped connection), the entry stays, so an item that exists on the relay never loses its key. Prints the id on stdout, and on stderr what each host covers ("api.example.com and every subdomain of it") and where the key is |
| `item list [--collection ID]`, `item archive ID` | |
| `grant --collection ID --member ID`, `grants`, `revoke --grant ID` | |
| `agent create NAME [--days N]`, `agent list`, `agent revoke ID` | `create` prints the token once |
| `pending` | pending runs with command, purpose, user request, flags, note |
| `deny RUN_ID [--reason TEXT]` | `POST /v1/approvals/{id}/deny` |
| `approve RUN_ID [--reason TEXT]` | `POST /v1/approvals/{id}/approve`. The relay refuses (`approve_on_host`); the CLI prints "The keys are on the owner's host. Approve there with apassy-team host." and exits 2 |
| `host [--ask-all] [--auto-limit N]` | owner token. The owner's host (section 21). Long-polls `GET /v1/host/requests?wait=25` in a loop, handles the runs one at a time, oldest first, and releases or denies each. `--ask-all`: ask for every run. `--auto-limit N`: the most automatic releases per item in the last hour (default 30). Runs until it is stopped. Exits with an error if the token is not the owner's |
| `audit [--after ID] [--limit N] [--json]` | |
| `access` | agent token: `GET /v1/access` |
| `run --items 1,2 --purpose TEXT [--request TEXT] [--ttl SECS] [--wait SECS] [--cwd DIR] -- CMD ARGS...` | agent token: `POST /v1/runs` with the exact argv; while `pending`, polls `GET /v1/runs/{id}?wait=25` and prints "Waiting for an approver (run N)." once on stderr (every run waits for the owner's host first); on `ready`, runs the command with `session.env` added to the inherited environment, inherited stdio, and exits with its code (128 + signal on a signal); `cwd` defaults to the current directory |
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
4. Create the relay and its first team: `docker run --rm -v apassy-relay-data:/data -v ~/.apassy-relay:/run/secrets:ro -e APASSY_RELAY_KEY_FILE=/run/secrets/master_key -e APASSY_RELAY_EDGE_SECRET_FILE=/run/secrets/edge_secret -e APASSY_RELAY_PUBLIC_URL=https://apassy-relay.wyderka.cc apassy-relay:alpha init --team <name> --owner <name>`. It prints the owner token once.
5. Start: the same with `-d --name apassy-relay --restart unless-stopped -p 127.0.0.1:8080:8080` and `serve`.
6. Tunnel: `cloudflared tunnel --url http://127.0.0.1:8080`. Copy the `trycloudflare.com` URL into the Worker var `RELAY_ORIGIN`. The URL changes at each cloudflared restart; then the Worker needs the new URL and a deploy. Errors 1016 and 530 mean the tunnel is down or the URL is old.
7. Worker: the var, the secret `EDGE_SECRET` (the same text as the edge secret file), the custom domain. Who deploys.
8. Check: `curl https://apassy-relay.wyderka.cc/healthz`, then `apassy-team init --relay https://apassy-relay.wyderka.cc < owner-token-file`, `apassy-team me`.
9. Team setup walkthrough: collection, item from stdin (on the owner's Mac, so the key lands in `keys.json` there), invite, join, grant, agent. Then `apassy-team host` on the owner's Mac, and what it does.
10. Agents: `.mcp.json` for Claude Code (HTTP with `Authorization: Bearer ${APASSY_TOKEN}`), the stdio form, `apassy-team run`. A cloud session needs `apassy-relay.wyderka.cc` in the environment's network allowlist (Custom access) and `APASSY_TOKEN` in its environment. Use the name `APASSY_TOKEN`: Claude Code reads some credential names as empty in MCP headers.
11. Runs and the host: `apassy-team host` (release, ask, deny, `--ask-all`, `--auto-limit`), `apassy-team pending`, `deny`. `approve` points to the host. Timeouts. `host.log`.
12. Audit: `apassy-team audit`.
13. Backup: stop the container, copy `team.db` out of the volume. It is encrypted with the vault key; keep the key apart from the backup. Also back up `keys.json` on the owner's Mac (plain text; losing it means adding the items again). The vault alone has no readable value, and `keys.json` alone opens nothing.
14. Revocation: agent, grant, member. Effect at the next request.
15. Limits and what this does not protect (section 20), and the cuts (section 2).

## 19. Tests

Every test starts what it needs in process. No network except 127.0.0.1. No real secrets: canaries such as `sk_test_51SyntheticCanaryValue0123456789abcdefABCDEF`.

**Shared test helpers** (each track owns one file; a test file includes it with `#[path = "common/<file>.rs"] mod <name>;`):

- `tests/common/relay.rs` (server track):
  `pub struct TestRelay { pub url: String, pub edge_secret: String, pub owner_token: String, pub dir: tempfile::TempDir, running: RunningRelay, .. }`,
  `pub fn start(upstream: UpstreamOptions) -> TestRelay` (picks a free port by binding `127.0.0.1:0` and dropping it, sets `public_url = url`, a synthetic key and edge secret, `approval_timeout_secs = 5`, `session_ttl_secs = 60`, runs `Relay::init` then `Relay::start`),
  `pub fn start_with(config: impl FnOnce(&mut RelayConfig), upstream: UpstreamOptions) -> TestRelay`,
  `impl TestRelay { pub fn call(&self, method: &str, path: &str, token: Option<&str>, body: Option<&serde_json::Value>) -> (u16, serde_json::Value); pub fn stop(self) }` (`call` sends the edge header). The handle also plays the owner's host: `add_item` seals the value and keeps the item key in the handle, `host_request(run)` reads the host list, and `release(run)` answers a pending run with the keys of its items, sealed to its run key (`release_for` builds the body, `run_released` asks and releases). `vault_cells()` dumps every cell of the vault, to look for a value.
- `tests/common/upstream.rs` (proxy track):
  `pub struct MockUpstream { pub addr: SocketAddr, pub ca_der: Vec<u8>, .. }`,
  `pub fn start(hosts: &[&str]) -> MockUpstream` (an HTTPS server on `127.0.0.1:0` with an rcgen CA and one leaf for all `hosts`, a thread per connection),
  `impl MockUpstream { pub fn options(&self) -> UpstreamOptions; pub fn requests(&self) -> Vec<Recorded> }` (`options` sets `extra_roots_der = [ca_der]` and `resolve = [(host, 443, addr)]` for each host),
  `pub struct Recorded { pub method: String, pub target: String, pub headers: Vec<(String, String)>, pub body: Vec<u8> }`.
  Default answer: 200, `Content-Type: application/json`, header `X-Echo-Authorization: <the Authorization header>`, body `{"method","target","authorization","headers":{..},"body":"<utf-8 lossy>"}`. Special targets: `/chunked` (the same JSON, chunked, in pieces of 7 bytes), `/big?n=N` (N copies of the Authorization header value separated by one byte, chunked), `/gzip` (`Content-Encoding: gzip`), `/redirect` (302 with `Location: https://<host>/echo`).

**Server track** (`tests/server_*.rs` and unit tests):
- Vault: wrong key refused; the file bytes do not contain a canary value; `init` twice refused; compile options checked; a vault with `user_version` 1 is refused with the message about plaintext values; a new vault is version 2 and has no `value` column; no cell of any table holds the canary bytes, after items are added and runs are released; a pending run after a restart is never shown to the host and times out.
- Edge: no header and a wrong header give 403 `edge_refused`; `/healthz` works without it.
- Tokens and roles: every endpoint with no token, a wrong-kind token, a revoked token; a member cannot add items, read approvals, or read the audit; a manager cannot invite a manager; the owner cannot revoke themselves.
- Invites: one use; expired; wrong code; name conflict.
- Items: env name rules; no host refused; a `NewItem` with a `value` is refused (400, and the answer does not repeat it); the uid (32 lowercase hex, unused) and the sealed length (12 + 16 + 1 to 4096 bytes, base64url, no padding) are checked; no endpoint response ever holds the value (scan every GET response for the canary).
- Grants and access: an agent of an ungranted member gets `not_granted` for a real and an unknown id alike; `GET /v1/access` lists only granted items.
- Decision matrix, each a test. Every passing run is `pending`, and the host sees the verdict as `suggestion`: `git status` with a staging item and a user request → `allow`; the same without a user request → `ask`; with a production item → `ask` with the ADR 0010 note; `stripe refunds create` → `ask` with `ask_owner`; `rm -rf /` → `ask` with `data_loss`; `python3 script.py` → `ask`; a user request with an injection phrase → `ask` with `injection_phrase`; policy mode `ask` → `ask`; each hard rule → 403 with its code and a `run_denied` audit row.
- Releases (`tests/server_host.rs`, `tests/server_approvals.rs`): a release → `ready` with a session; placeholders have the value's length and differ from it; `APASSY_BASE_*` and `STRIPE_API_BASE` start with `<public_url>/p/apassy_ses_`; the session works against the mock upstream (the proxy swaps the decrypted value); a release sealed for run A posted to run B → `release_invalid`, no session; a second release of one run → 409 `run_not_pending`; a changed `sealed_keys`, nonce, or host key, wrong lengths, padding, an oversize text, a wrong run id (in the plaintext or in the sealing), a missing, extra, or repeated uid, swapped or wrong item keys, a plaintext that is not JSON → `release_invalid`, the run denied, the key used up, no session; a host deny → `approval_denied`; no host → `timed_out`; a grant, item, agent, or member revoked while pending → `approval_invalidated` at once and the key dropped; an agent token that expired while pending → `approval_invalidated` at the release; `approve` → 403 `approve_on_host`; the host endpoints are 403 for a manager or a member and 401 for an agent token; `GET /v1/runs/{id}` by another agent → 404; `wait` holds and returns on the release; the host long poll holds, is limited to 2 at once, and works while the agent slots are full.
- Sessions: `SessionSource::find` by key; `None` after expiry and after revoking the agent, the grant, the member, or the item.
- Audit: canaries, placeholders, and tokens in purpose, user request, command, and reasons never appear in `GET /v1/audit` while a session holds the values; no row, response, or vault cell holds an item key, a run key, a host key, a nonce, or a sealed text of a release.
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
- Each command sends the right method, path, bearer, edge header (when set), and body; `item add` reads the value from stdin, checks it, seals it, sends only `uid` and `sealed` and never prints the value or the key, writes the entry to `keys.json` (mode 0600, directory 0700, atomic) before the upload, sets `item_id` after it, removes the entry when the relay refuses the item, and keeps it when the outcome is unknown; `approve` prints the `approve_on_host` message and exits 2.
- The host (`tests/host_cli.rs`, unit tests of `cli::host`): the policy function for every case (known safe staging → auto; production in the local store → ask; relay suggestion `ask` → ask; flags → ask; `--ask-all` → ask; limit exceeded → ask; unknown uid → deny); the loop against a real relay with a scripted person (auto release, no question; yes and no; no terminal → "No one at the host."; unknown item; the local environment wins over the relay's; oldest first; the key store is read again for each run; `host.log` has one line per run and no key); `keys.json` and `host.log` modes.
- `run`: pending then ready; the child sees the placeholder and the base URL (the test runs `sh -c 'printf "%s|%s" "$FOO_KEY" "$APASSY_BASE_FOO_KEY" > out'`); the exit code passes through; denied → 3.
- `mcp`: a request line is forwarded and answered on one line; a notification gives no output; relay down → a JSON-RPC error with the request id.
- Worker: `node --test deploy/worker/test/`: the edge header is replaced, a `//evil.example/x` path stays on the relay origin, method, query, and body pass through.
- If Docker works on the machine: `docker build -t apassy-relay:alpha .` succeeds and `docker run --rm apassy-relay:alpha init` without variables exits with a clear error. Not part of `cargo test`.

**End to end** (`tests/e2e.rs`, the merger, after the three merges). One relay with `MockUpstream::start(&["api.stripe.com", "api.github.com"])`, and the real host loop on a thread with a scripted person (no bypass: the person says no when the script is empty):
1. The owner makes a collection "payments", and adds with `apassy-team item add` (XDG dir in a temp dir) a staging Stripe item with a canary value (provider `stripe`) and a production GitHub item (hosts `api.github.com`). The vault has no readable value; `keys.json` has both keys.
2. The owner invites; a member joins; the owner grants the collection; the member makes an agent.
3. The agent asks for `stripe balance retrieve` with the Stripe item and a user request: `pending`, then released by the host without a question. It calls `STRIPE_API_BASE + "/v1/balance"` with `Authorization: Bearer <placeholder>` and the edge header. The mock saw the canary; the agent got the placeholder back in the body and in `X-Echo-Authorization`.
4. The agent asks for `git status` with the GitHub item: `pending`, and the host asks the person (production in the local store). The person says no: `approval_denied`. It asks again; the person says yes; the run is `ready`. `approve` on the relay is 403 `approve_on_host`.
5. A placeholder in the path → 403 refused; the Stripe placeholder sent to `api.github.com` → 403 `wrong_host`.
6. The owner revokes the grant. The next proxy request → 403 `session_invalid`. A new run → 403 `not_granted`.
7. The same flow through MCP (`/mcp` `tools/call apassy_request_run`, then `apassy_run_status` with a wait) and through the CLI (`apassy-team run` with `APASSY_EDGE_SECRET`, writing its environment to a file that the test then uses).
8. The whole audit, as JSON text, holds no canary, no placeholder, no token, no session key, no item key; `host.log` holds no key; no vault cell holds a value or a key.

`scripts/e2e.sh` runs the real binaries: the same flow with the auto path, the session against the mock upstream, a production run that the host denies because no terminal is there ("No one at the host."), an item with no key on the host ("Unknown item on this host."), the revoked grant, and the audit. The host runs cut off from any terminal (`setsid`). The yes path is in `tests/e2e.rs` only.

## 20. What this does not protect

What host-held item keys protect, and what they do not, is in section 21. In short:

- The relay sees a value in memory while its session lives. Root on the Mac or the VM, or a taken-over relay while it runs, can read the values of the sessions of that time, and the keys of a release while it is opened. It cannot read a value of any other run.
- The key file of the owner's host is plain text on the owner's disk in this alpha. Anyone who reads it can unseal every item of that relay that they can also fetch. Back it up: losing it means adding the items again.
- A session key and a placeholder together are a credential for the hosts of that item, in auth positions only, until the session ends. They can end up in an agent transcript if the agent runs the command itself. `apassy-team run` avoids that.
- The relay and the host check a stated command. In way B they cannot check what the agent really runs with the session. The relay controls which hosts get the value, where the value goes in a request, and for how long.
- Cloudflare sees all traffic in clear, including session keys in paths and placeholders in headers. It no longer sees a value when an item is added (the CLI seals it first). It never sees a value on the agent side. It sees values on the relay-to-upstream side only if Cloudflare is that upstream.
- The quick tunnel has no SLA and a changing URL.
- The host must be online for every run. Only the owner's host holds keys: a manager cannot release a run, and there is no sharing of keys to another machine yet.
- The owner's host may release a run of the owner's own agent.

## 21. Host-held item keys

Before this change the relay kept every item value in its vault and held the vault key, so a taken-over relay leaked every secret. Now the relay never stores a readable value. The owner's machine, the **host**, keeps a key for each item. For each run, the host decides, and if it agrees, it sends the relay the keys of that run's items, sealed to a one-time key of that run. The relay decrypts the values in memory for the session only, and forgets them when the session ends.

**Formats.** All binary fields are base64url without padding. Random bytes come from `ring::rand::SystemRandom` (and `getrandom` for tokens). Key material is in `Zeroizing` buffers (the ring X25519 private key cannot be wrapped, so ring owns its memory). The code is in `src/hostkeys.rs`, and both the relay and the CLI use it.

- **Item** (made by `apassy-team item add`). `uid` = 16 random bytes as 32 lowercase hex. `item_key` = 32 random bytes. `sealed = nonce || AES-256-GCM(item_key, nonce, value, aad)`, with `nonce` = 12 random bytes and `aad = "apassy-relay item v1\0" || uid`. The relay stores `uid` and `sealed` and never sees `item_key`.
- **Run key.** When a run becomes `pending`, the relay makes one ring X25519 `EphemeralPrivateKey` for it and keeps it in memory only, in a table keyed by run id. Its 32-byte public key is `run_key`, which the host reads in `GET /v1/host/requests`. The private key goes to no disk. It is removed at release, deny, timeout, revocation, stop, and restart. A pending run with no key in memory (for example after a restart) is never shown to the host and times out.
- **Release** (`POST /v1/host/requests/{run_id}/release`). The host makes its own X25519 `EphemeralPrivateKey`; `host_key` is its public key. Both sides compute `shared = X25519(own private, other public)` (`agree_ephemeral`; ring refuses an all-zero result). `wrap_key = HKDF-SHA256(salt = run_key || host_key, ikm = shared, info = "apassy-relay release v1")`, 32 bytes. The host seals the plaintext with AES-256-GCM(`wrap_key`, a random 12-byte `nonce`, `aad = "apassy-relay release v1\0" || run_id as decimal || "\0" || run_key`). The body is `{"host_key","nonce","sealed_keys","reason"?}`. The plaintext is JSON `{"run_id":N,"keys":[{"uid":"...","key":"<b64 32 bytes>"}]}`.
- **What the relay checks.** The run is `pending`, not past `expires_at`, and has a key in memory, else 409 `run_not_pending`. It takes the key out of the table first. It checks steps 1 and 3 again (agent, member, items, grants). It opens `sealed_keys`. `run_id` in the plaintext must be the run, and the set of uids must be exactly the set of the uids of the run's items (no more, no fewer, none twice). Each item's `sealed` is opened with its key and its uid as aad. Each value must pass the value rules of section 8. Then the session is made as always. Any crypto or format failure denies the run with `release_invalid` (HTTP 403), writes an audit row, makes no session, and erases what it opened.

**The host's decision** (`apassy-team host`, `src/cli/host.rs`). For each request, oldest first, one at a time:
1. Every item uid must be in the key store for this relay URL, else deny with "Unknown item on this host.".
2. A local check that does not depend on the relay: automatic release only if ALL are true: `--ask-all` is not set; the relay's `suggestion` is `allow` and it flags nothing; no item has environment `production` in the LOCAL key store; the host's own run of `decision::assess` (the same function as the relay's steps 5 to 8, fed with the LOCAL metadata of the items, the relay host, collection mode `bouncer`) says known safe with no flag and no rule that asks; and no item was released automatically `--auto-limit` times (default 30) in the last hour (kept in memory). Any error in this check asks, never releases.
3. Otherwise it prints the run (agent, member, command, purpose, user request, cwd, items with their LOCAL environment, flags, the relay's note, and why it asks) and asks "Release the keys for run N? [y/N] " on `/dev/tty`. Only `y` or `yes` releases. No terminal: deny with "No one at the host.". If the run expires while the host waits, it moves on. Text that an agent wrote is printed with control characters escaped, and what was typed before the question is thrown away.
4. Release: a host key, `wrap_key`, and the release as above, with the reason "Released automatically: known safe command." or "Approved on the host.". Deny: `POST .../deny` with the reason ("Denied on the host.", "Unknown item on this host.", "No one at the host.").

Every request is one JSON line in `host.log` next to `keys.json` (mode 0600): time, run id, agent, member, item uids and names, and the decision (`auto`, `approved`, `denied`, `unknown_item`, `expired`, `error`). No key material. No flag, variable, or hook makes the host release a run that it would ask about. The prompt is behind the `Asker` trait, so tests give the answers; the binary uses only the terminal.

**The key store** (`keys.json`, section 15): `{"version":1,"entries":[{"relay_url","team","uid","item_id","name","env_name","environment","hosts":[...],"risk","scope","reversibility","key","created_at"}]}`. `risk`, `scope`, and `reversibility` are added to the entries of the first design, because a core declaration needs them. The host trusts this metadata, not what the relay says about an item: the environment, the hosts, and the variable name come from the machine that made the item.

**What this protects.**
- A stolen vault, a stolen backup, or a copy of the volume gives only ciphertext: no value and no item key.
- A relay that is taken over while it runs gets only the values of the runs that the host released during that time, and only until those sessions end. It cannot ask for a value that the host did not release.
- A captured release cannot be replayed: the run key is one-time and is used up by the first try, and the release is bound to the run id and the run key by its aad.
- A relay cannot talk the host into trusting an item that it made up: an unknown uid is denied, and the environment and hosts come from the local store.
- Cloudflare no longer sees a value when an item is added: the body holds only a sealed text.

**What it does not protect.**
- The relay still sees a value while its session lives, and a taken-over relay can read the values of the sessions of that time.
- The key file is plain text on the owner's disk in this alpha. Back it up; losing it means adding the items again.
- The host must be online for every run. A run with no host times out.
- Only the owner's host holds keys. There is no sharing of keys to the machines of managers or members yet. Managers can deny a run, but cannot release one.
- The relay masks a value in the audit only while a session holds it. A value that an agent writes in a purpose before any session holds it is not masked (the relay does not know it). The CLI refuses a name, a provider, or a host that contains the value.
- A relay that is taken over can make up a run (it needs no agent). The host cannot tell a made-up run from a real one. It asks the owner for everything except a known-safe command with a non-production item, which it releases by itself. One release is enough to learn a value, so a taken-over relay can get the value of any non-production item on the host; `--auto-limit` only caps how often it happens without a person, and the owner sees every release in `host.log`. Production items always ask. `--ask-all`, or `--auto-limit 0`, makes the host ask every time.
- The host cannot check the hosts that the relay stores for an item: a relay that holds the keys of a run can send the values where it likes.
- A manager can add an item on the relay. It has no key on the owner's host, so every run with it is denied there ("Unknown item on this host.").

## 22. Teams

ADR 0019 of the core, stage 1. One relay holds several teams. Separation is by file and by state, not by a column.

**Files.** The data directory has:

| File | What | Key |
| --- | --- | --- |
| `relay.db` | the directory: each team's id, name, state (`active` or `suspended`), the random key of its file, and a `legacy` flag; the team codes (hash, expiry, use); the audit of the relay. No people, no items, no runs. `user_version` 1001 | the master key (`APASSY_RELAY_KEY`) |
| `teams/<team id>.db` | one team: the schema of section 8, unchanged (`user_version` 2) | its own random 256-bit key, kept in `relay.db` |
| `admin.sock` | the operator socket, mode 0600 | none; file mode only |
| `relay.lock` | an exclusive lock: `serve`, `init`, and `migrate` hold it, so one relay process at a time uses the data directory. `admin` does not take it | none |

- A team id is `t_` and 10 characters of lowercase base32 (`a-z`, `2-7`), random, and public. Ids inside a team file (member 1, item 1, run 1) are local to that team and repeat between teams.
- `apassy-relay init --team T --owner O` makes `relay.db` and one team. `apassy-relay init` alone makes `relay.db` with no team. Both refuse when the data directory has a relay or a `team.db`.

**Start.** A team file that cannot be opened (missing, damaged, wrong mode) does not stop the relay: the relay logs it, serves the other teams, and lists that team with `open: false`. The operator suspends and deletes it, or fixes the file, suspends, and resumes it.

**State.** Each active team has its own `Core` in memory: its file, its audit writer and masks, its session table, its run keys, its notifier, its long polls, and its limiter of refused requests. No map spans teams. The hub (`src/server/hub.rs`) keeps the active teams by id.

**Routing.** For each request, after the edge check:

1. `/p/<session key>/...`: the team id in the session key picks the team; that team's session table looks the key up. A key with another team's id finds nothing (`session_invalid`).
2. `POST /v1/teams`: no team yet (below).
3. `POST /v1/join`: the team id in the invite code picks the team.
4. Every other endpoint: the team id in the bearer token picks the team, then the token hash is looked up in that team's file only. A token of an unknown or suspended team, and a token moved to another team, get the same 401 `unauthenticated` as an unknown token.

No endpoint takes a team id in the path.

**New team.** `POST /v1/teams {code, team, owner}`. The names are checked first. In one transaction of `relay.db`: the code is checked (live, not used); the team file is made with its team row, its owner, and a `team_created` row; the code is marked used; the team row is added. A failure removes the file and keeps the code. Then the team is opened.

**Operator.** `apassy-relay admin` sends one JSON line to `admin.sock` of the running relay and prints the answer. There is no operator endpoint on HTTP.

| Command | Does |
| --- | --- |
| `team-code [--hours N]` | a one-time team code, printed once on stdout (1 to 720 hours, default 72) |
| `teams` | id, name, state, legacy, created, suspended, and for an active team the counts of live members, items, and agents and the time of its last audit row. No names of members or items, no runs, no audit |
| `suspend ID` | the team's state becomes `suspended`; a row `team_suspended` (actor `operator`) in its audit; its sessions end, its run keys go, its long polls wake, and it leaves the hub: its tokens fail at the next request |
| `resume ID` | opens the team again (a restart for that team: `ready` runs become `ended`); a row `team_resumed` |
| `delete ID` | only a suspended team, and only once the requests that started before the suspension have ended (it waits up to 10 seconds, then refuses): removes its row and file key from `relay.db`, then its file. A file that cannot be deleted is an error. No undo |

**Proxy addresses.** The proxy connects only to public addresses: after DNS it drops loopback, private, link-local, CGNAT, unique-local, site-local, multicast, documentation, benchmark, reserved, and unspecified addresses, 6to4 (`2002::/16`), local-use NAT64 (`64:ff9b:1::/48`), and IPv6 forms that carry such an IPv4 address. `APASSY_RELAY_BLOCKED_ADDRESSES` adds public addresses or networks, for the relay's own machine. It connects to the addresses it checked and does not resolve again. A name that does not resolve, an address that is not allowed, and a port that does not answer get the same 502 `upstream_failed` message.

**Migration.** `apassy-relay migrate` moves a relay from before teams (one `team.db`, keyed with `APASSY_RELAY_OLD_KEY`):

1. Refuses if `relay.db` exists, if there is no `team.db`, if `team.db.pre-teams` exists, or if the master key is the old key. Removes `relay.db.migrating` and `teams/*.migrating` of an earlier try that stopped before its commit point (their key was never saved). Opens `team.db` with the old key and checks its version (version 1 is refused as in section 8).
2. Copies it to `teams/<new id>.db.migrating`, gives the copy a new random key (`PRAGMA rekey`), and checks that the copy opens with the new key and not with the old one.
3. Writes the directory, with the team marked `legacy`, as `relay.db.migrating`, and renames it to `relay.db`. This rename is the commit point.
4. Renames the copy to `teams/<id>.db`, and `team.db` to `team.db.pre-teams` (it opens with the old key only). If the process stops here, the next `serve` does these renames.

A failure before the commit point removes what it made and leaves `team.db` as it was. Member and agent tokens without a team id keep working for the legacy team; new tokens of that team name it. An invite code made before the migration has no team id and stops working: make a new one.

**What this does not protect.** The master key and every team file are on the same machine: the operator, root, or a disk snapshot can open every team's metadata. Item values stay sealed (section 21). All teams share one process. There are no limits per team yet.
