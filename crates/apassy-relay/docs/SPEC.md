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

One crate, `apassy-relay`, license `Apache-2.0`, a member of the `wydrox/apassy` workspace (ADR 0037). Rust 1.97.0, edition 2024, `#![forbid(unsafe_code)]`, clippy `all = "warn"`.

| Path | What | Owner |
| --- | --- | --- |
| `Cargo.toml`, `Cargo.lock`, `.cargo/config.toml`, `rust-toolchain.toml`, `LICENSE` | Build and license | skeleton (frozen) |
| `src/lib.rs`, `src/api.rs`, `src/config.rs`, `src/error.rs`, `src/ids.rs`, `src/secret.rs`, `src/session.rs` | Shared types | skeleton (frozen) |
| `tests/build_options.rs` | SQLCipher build flags | skeleton (frozen) |
| `docs/SPEC.md` | This file | skeleton (frozen) |
| `src/hostkeys.rs`, `src/decision.rs` | Host-held item keys: the crypto and formats, and the pure part of the decision (used by the relay and by the host) | server |
| `src/sync_head.rs`, `src/server/sync.rs`, `tests/server_sync.rs` | Vault sync: the signed head, and the endpoints, storage, and limits (section 24) | server |
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
| `APASSY_RELAY_TEAM_VAULTS` | `1`: shared team vaults, runs, MCP, and the proxy (way B). `0`: refuse `/p/…`, MCP, `/v1/access`, `/v1/runs`, the host lane, and new collections, policies, items, grants, and team agents with 410 `team_vaults_retired` before any token check; devices, joins, links, relay sync, questions, feed, push, Connect, lists, archives, and revocations go on (ADR 0037, D8). The hosted image sets `0`; any other value stops the start | `1` |
| `APASSY_RELAY_CONNECT_TEAMS_PER_DAY` | Connect teams of the whole relay in 24 hours (section 26), 0 to 100000; `0` turns `POST /v1/connect` off | 50 |
| `APASSY_RELAY_CONNECT_TEAMS_MAX` | Connect teams the relay holds at once, active or suspended (section 26), 0 to 1000000; `0` turns `POST /v1/connect` off | 100 |
| `APASSY_RELAY_CONNECT_LONG_POLLS` | long polls of all Connect teams together (`Limits::connect_long_polls`, section 26.4), 0 to 1024; `0`: every Connect poll answers at once | 96 |

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

- Every token of a team names its team: `<prefix><team id>_<64 hex>`, for example `apassy_mbr_t_7k2m5q4x3c_<64 hex>`. A team code names no team: `apassy_tcd_<64 hex>`. The relay reads the team id first and looks the hash up in that team's file only (section 22).
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
- Load (`config::Limits`, not read from the environment). At most 256 requests run at once. Agent paths (`/p/`, `/mcp`, `/v1/runs`, `/v1/access`) can be slow, so they take at most 256 - 32 of them. The other 32 are kept for members, approvers, the owner's host (`/v1/host/...` is in the member lane, not the agent lane), and `/healthz`. A request over a limit gets 503 `busy` as an envelope, with `Retry-After: 2`. `apassy-team run` asks again after a `busy` answer while it waits. Question long polls have a lane of their own, apart from the 256 (section 25.5).
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

Human output is short text; `--json` opts finite commands into the consistent success/error envelope in section 29. The CLI never prints a session environment. Exit codes: 0 success (or the child's code for `run`), 2 usage error, 3 run denied or timed out, 4 relay or network error.

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

`deploy/worker/` (track client): `src/index.ts`, `src/limits.ts`, `src/apns.ts` (the APNs sender of `/internal/push`, section 25.6), `wrangler.jsonc`, `package.json` (pinned devDependencies, not installed), `test/index.test.ts`, `test/apns.test.ts`, and `spike/` (the A4 spike, section 25.7).

`src/index.ts` is the Worker's main module. It exports only the `default` handler (and types): workerd refuses to start a Worker whose main module exports any other value. Shared values, such as the body length limits, live in `src/limits.ts`. A test checks this.

The Worker, about 40 lines:
- `env.RELAY_ORIGIN` (a var, the quick tunnel URL) and `env.EDGE_SECRET` (a secret). If either is missing: 503 text "relay not configured".
- The target URL is built by string: `origin + url.pathname + url.search`, where `origin = new URL(env.RELAY_ORIGIN).origin`. Never `new URL(path, origin)`: a path such as `//evil.example/x` would change the host and leak the edge secret.
- Headers: a copy of the incoming headers; delete `x-apassy-edge` (any case), then set it to `env.EDGE_SECRET`.
- `fetch(target, {method, headers, body: request.body for methods other than GET and HEAD, redirect: "manual"})`. The body streams; nothing is buffered. Return the response as is. For GET and HEAD, no body is forwarded, so `Content-Length` and `Transfer-Encoding` are removed from the forwarded headers.
- No logging of URLs (the path holds session keys). `observability.enabled: false`.
- `/internal` and every path under `/internal/` are handled by the Worker itself (`apns.ts`, section 25.6) and never forwarded.
- Per-IP limits (Workers Rate Limiting, keyed by `cf-connecting-ip`, fail open when the binding is missing or fails; over the limit: 429 `rate_limited` with `Retry-After: 60`, and the relay never sees the request): `CREATE_LIMITER` (10 a minute) for `POST /v1/join`, `/v1/teams`, `/v1/devices/link`, and `/v1/devices/link/cancel`; `AUTH_LIMITER` (60 a minute) for `POST /v1/auth/challenge` and `/v1/auth/token`; `SYNC_LIMITER` (60 a minute) for `PUT /v1/sync/snapshot`; `CONNECT_LIMITER` (1 a minute, keyed by the IPv4 address or the IPv6 /64) for `POST /v1/connect` (section 26.4).
- Body length (24.5, 24.10): tiny_http reads the rest of a declared body after any early answer, on any path. So before the limiter and the relay, the Worker checks the `Content-Length` of every request other than GET and HEAD, by its exact method and path: `PUT /v1/sync/snapshot` up to 64 MiB plus 64 KiB (`MAX_SNAPSHOT_LENGTH`); `PUT /v1/feed` up to 352 KiB (`MAX_FEED_LENGTH`, the relay's own limit, section 27.11), with a `Content-Length` and no `Transfer-Encoding` as a push; a path under `/p/` up to 8 MiB plus 64 KiB (`MAX_PROXY_LENGTH`, the proxy's `MAX_REQUEST_BODY` plus the margin); every other path, including `PUT /v1/sync/snapshot/`, `POST /v1/sync/snapshot`, and paths the relay does not route, up to 64 KiB plus 64 KiB (`MAX_JSON_LENGTH`). Above it: 413 `payload_too_large`. A `Content-Length` that is not 1 to 20 digits: 400 `invalid_request`. The push must also have a `Content-Length` and no `Transfer-Encoding` (else 400). Another request without `Content-Length` passes: it has no body or a chunked one, and tiny_http does not read the rest of a chunked body after an early answer, so the relay reads at most its own cap. The relay keeps its own checks (24.3, 12).

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
- Vault: wrong key refused; the file bytes do not contain a canary value; `init` twice refused; compile options checked; a vault with `user_version` 1 is refused with the message about plaintext values; a new vault is version 2 and has no `value` column; no cell of any table holds the canary bytes, after items are added and runs are released; a pending run after a restart ends explicitly with `run_interrupted`, an audit row and a safe retry instruction.
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
- **Run key.** When a run becomes `pending`, the relay makes one ring X25519 `EphemeralPrivateKey` for it and keeps it in memory only, in a table keyed by run id. Its 32-byte public key is `run_key`, which the host reads in `GET /v1/host/requests`. The private key goes to no disk. It is removed at release, deny, timeout, revocation, stop, and restart. Startup atomically ends orphaned pending runs with existing status `ended`, code `run_interrupted`, a restart audit row and a safe retry instruction. No one-time key is reconstructed and no command is rerun.
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

ADR 0019 of the core, stages 1 and 4. One relay holds several teams. Separation is by file and by state, not by a column.

**Files.** The data directory has:

| File | What | Key |
| --- | --- | --- |
| `relay.db` | the directory: each team's id, name, kind (`operator` or `connect`, section 26), state (`active` or `suspended`) and suspension reason, file key, `legacy` flag, and limits; team codes; the key hashes of Connect teams; relay audit. No people, items, or runs. `user_version` 1003 (section 26.2) | the master key (`APASSY_RELAY_KEY`) |
| `teams/<team id>.db` | one team: the schema of section 8, unchanged (`user_version` 2) | its own random 256-bit key, kept in `relay.db` |
| `admin.sock` | the operator socket, mode 0600 | none; file mode only |
| `relay.lock` | an exclusive lock: `serve`, `init`, and `migrate` hold it, so one relay process at a time uses the data directory. `admin` does not take it | none |

- A team id is `t_` and 10 characters of lowercase base32 (`a-z`, `2-7`), random, and public. Ids inside a team file (member 1, item 1, run 1) are local to that team and repeat between teams.
- `apassy-relay init --team T --owner O` makes `relay.db` and one team. `apassy-relay init` alone makes `relay.db` with no team. Both refuse when the data directory has a relay or a `team.db`.

**Start.** A team file that cannot be opened (missing, damaged, wrong mode) does not stop the relay: the relay logs it, serves the other teams, and lists that team with `open: false`. The operator suspends and deletes it, or fixes the file, suspends, and resumes it.

**State.** Each active team has its own `Core` in memory: its file, its audit writer and masks, its session table, its run keys, its notifier, its long polls, and its limiter of refused requests. No map spans teams. The hub (`src/server/hub.rs`) keeps the active teams by id.

**Limits.** Each team has six limits. The nullable `limits TEXT` column in `relay.db` holds a JSON object. A null column uses all defaults. A missing JSON field uses its default.

| Field | Default | Count |
| --- | --- | --- |
| `members` | 50 | members without revocation, including the owner |
| `items` | 500 | items without archive status |
| `agents` | 100 | agents without revocation or expiry, whose members have no revocation |
| `runs_per_hour` | 1000 | all run rows made in the last 3600 seconds, including denials |
| `pending_runs` | 50 | run rows with status `pending` |
| `agent_requests` | 56 | simultaneous requests in the agent lane for this team |

All values are integers from 1 to 1000000, except `agent_requests`, which permits 1 to 224. The global request limits of section 9 also apply. Team agent requests cannot use the member reserve.

The relay checks counts and inserts rows in the same team transaction. A full member limit does not use the invite code. An expired agent does not use a slot. A refused run does not add a run row or a run key.

Count limits return HTTP 403 `team_limit`. The agent request limit returns HTTP 503 `busy`, with `Retry-After: 2`. A team audit row has action `limit_reached`, actor `relay`, and detail `{"limit":"<field>"}`. The relay writes at most one such row per field per ten seconds. No limit check changes the policy or the decision for an allowed run.

The relay uses new limits immediately. A lower limit does not revoke members or agents, archive items, or stop runs. New operations can start only if the applicable limit permits them.

**Routing.** For each request, after the edge check:

1. `/p/<session key>/...`: the team id in the session key picks the team; that team's session table looks the key up. A key with another team's id finds nothing (`session_invalid`).
2. `POST /v1/teams` and `POST /v1/connect` (section 26): no team yet (below).
3. `POST /v1/join`: the team id in the invite code picks the team.
4. Every other endpoint: the team id in the bearer token picks the team, then the token hash is looked up in that team's file only. A token of an unknown or suspended team, and a token moved to another team, get the same 401 `unauthenticated` as an unknown token.

No endpoint takes a team id in the path.

**New team.** `POST /v1/teams {code, team, owner}`. The names are checked first. In one transaction of `relay.db`: the code is checked (live, not used); the team file is made with its team row, its owner, and a `team_created` row; the code is marked used; the team row is added. A failure removes the file and keeps the code. Then the team is opened.

**Operator.** `apassy-relay admin` sends one JSON line to `admin.sock` of the running relay and prints the answer. There is no operator endpoint on HTTP.

| Command | Does |
| --- | --- |
| `team-code [--hours N]` | a one-time team code, printed once on stdout (1 to 720 hours, default 72) |
| `teams` | id, name, state, effective limits, legacy flag, and creation and suspension times. Active teams also show live counts and last activity. No member or item names, runs, or audit. |
| `limits ID [--members N] [--items N] [--agents N] [--runs-per-hour N] [--pending-runs N] [--agent-requests N]` | without flags, reads effective limits. Flags change only the supplied fields. Prints all six effective values. Works for active and suspended teams. |
| `suspend ID` | the team's state becomes `suspended`; a row `team_suspended` (actor `operator`) in its audit; its sessions end, its run keys go, its long polls wake, and it leaves the hub: its tokens fail at the next request |
| `resume ID` | opens the team again (a restart for that team: `ready` runs become `ended`); a row `team_resumed` |
| `delete ID` | only a suspended team, and only once the requests that started before the suspension have ended (it waits up to 10 seconds, then refuses): removes its row and file key from `relay.db`, then its file. A file that cannot be deleted is an error. No undo |

The socket command is `{"command":"limits","team":"t_7k2m5q4x3c","set":{"members":25}}`. An absent or null `set` reads the limits. The result contains the six effective fields. Each change writes `limits_changed` with actor `operator` in the team audit and relay audit.

At start, directory version 1001 becomes 1002. The relay adds `limits TEXT` and changes `PRAGMA user_version` in one transaction. Existing teams use the defaults. Since section 26 the relay goes on to 1003 in the same transaction (26.2); new directories use version 1003. The relay refuses unknown versions.

**Proxy addresses.** The proxy connects only to public addresses: after DNS it drops loopback, private, link-local, CGNAT, unique-local, site-local, multicast, documentation, benchmark, reserved, and unspecified addresses, 6to4 (`2002::/16`), local-use NAT64 (`64:ff9b:1::/48`), and IPv6 forms that carry such an IPv4 address. `APASSY_RELAY_BLOCKED_ADDRESSES` adds public addresses or networks, for the relay's own machine. It connects to the addresses it checked and does not resolve again. A name that does not resolve, an address that is not allowed, and a port that does not answer get the same 502 `upstream_failed` message.

**Migration.** `apassy-relay migrate` moves a relay from before teams (one `team.db`, keyed with `APASSY_RELAY_OLD_KEY`):

1. Refuses if `relay.db` exists, if there is no `team.db`, if `team.db.pre-teams` exists, or if the master key is the old key. Removes `relay.db.migrating` and `teams/*.migrating` of an earlier try that stopped before its commit point (their key was never saved). Opens `team.db` with the old key and checks its version (version 1 is refused as in section 8).
2. Copies it to `teams/<new id>.db.migrating`, gives the copy a new random key (`PRAGMA rekey`), and checks that the copy opens with the new key and not with the old one.
3. Writes the directory, with the team marked `legacy`, as `relay.db.migrating`, and renames it to `relay.db`. This rename is the commit point.
4. Renames the copy to `teams/<id>.db`, and `team.db` to `team.db.pre-teams` (it opens with the old key only). If the process stops here, the next `serve` does these renames.

A failure before the commit point removes what it made and leaves `team.db` as it was. Member and agent tokens without a team id keep working for the legacy team; new tokens of that team name it. An invite code made before the migration has no team id and stops working: make a new one.

**What this does not protect.** The master key and every team file are on the same machine. The operator, root, or a disk snapshot can open the metadata of every team. Item values stay sealed (section 21). All teams share one process. Team limits restrict resource use in that process.

## 23. Devices, sign-in, joins, and links

ADR 0019 of the core, stages 2 and 3. This section takes precedence over the earlier auth, schema, join, host, and team-creation rules in sections 7, 8, 9, 21, and 22. A person (or a shared device) is a member of one team. Each member has devices; each device has a P-256 key pair. A device signs in and gets an access token for 15 minutes. A join or a new device waits for a confirmation, and the confirmer must type the two safety words that the joiner sees. The shared code is `src/device.rs` (keys, the sign-in message, the safety words) and the types in `src/api.rs` ("Devices, sign-in, joins, and links"). This section was reviewed before it was built; the rules marked **(review)** close holes that the review found.

### 23.1 Words and limits

| Thing | Rule |
| --- | --- |
| Device name | 1 to 64 bytes, no control character (`checked_label` rules) |
| Public key | base64url of 65 bytes, first byte 0x04 (`device::decode_public_key`); unique among the live devices of a team |
| Devices | at most 10 live devices per member **(review)** |
| Sign-in nonce | 32 random bytes, base64url; 60 seconds; one use; at most 4 open per public key (the oldest of that key goes); at most 1000 open per team — when full, a new challenge is 503 `busy`, never an eviction of another key's nonce **(review)** |
| Access token | `apassy_acc_<team id>_<64 hex>`; 900 seconds; in memory only (a restart ends them; clients sign in again); at most 8 per device (the oldest goes) **(review)** |
| Access-token table | maps the token hash to `(device id, expires_at)` only. Every request reads the device and its member from the team file, as member tokens do, so a revocation, a role change, or a key-holder move counts at the next request **(review)** |
| Invite code | as today, `apassy_inv_<team id>_<64 hex>`, one use; the link form is `<relay URL>/join#<code>` (the CLI makes and reads it; the relay never sees the fragment) |
| Join | waits up to 72 hours for a confirmation, then `expired` |
| Link code | `apassy_lnk_<team id>_<64 hex>`; 600 seconds; one use |
| Link | waits up to 600 seconds from the link request, then `expired` |
| Safety words | `device::safety_words(team, code, public_key)`; the relay computes them when the join or link arrives and keeps them; the CLI computes them too and stops if the relay's words differ **(review)** |
| Member tokens | end at the team's `member_tokens_until` (a unix time in the team row): 14 days after the migration to version 3 for an existing team, 14 days after creation for a team made by `apassy-relay init`. After it, member tokens and agent tokens of the old form (`apassy_agt_`) are 401 with the message "Member tokens ended on <date>. Ask an owner for a new invite." **(review)** |

### 23.2 Schema version 3 (team file)

`Store::open_team` migrates a version 2 file to version 3 **(review: exact order)**:

1. Copy the file to `<file>.pre-v3` (mode 0600; refuse to migrate if that copy cannot be made; keep it — the version 2 image refuses version 3, so it is the way back). The copy is written as `<file>.pre-v3.tmp`, synced, and renamed over `.pre-v3`. A `.pre-v3` that exists while the file is still version 2 comes from a migration that did not commit; the file is the truth, so the copy is made again and the migration goes on. A failure says that the file is still version 2 and unchanged.
2. `PRAGMA foreign_keys = OFF` — outside any transaction (it is ignored inside one).
3. `BEGIN IMMEDIATE`.
4. Create the new tables under temporary names (`member_v3`, `invite_v3`), `INSERT INTO … SELECT …` with every id kept.
5. `DROP TABLE` the old `member` and `invite`, then `ALTER TABLE member_v3 RENAME TO member` (and the same for invite). Do NOT rename the old tables first: SQLite 3.26 and later would rewrite the foreign keys of the child tables to the old name.
6. Create the new tables (`device`, `join_request`, `device_link`), the new columns, and every index.
7. `PRAGMA foreign_key_check`; any row: `ROLLBACK` and refuse to open.
8. `PRAGMA user_version = 3`, `COMMIT`, `PRAGMA foreign_keys = ON`.

A new team file is made at version 3. Version 1 and unknown versions are refused as today.

```sql
-- team: the end of member tokens.
ALTER TABLE team ADD COLUMN member_tokens_until INTEGER;
-- The migration sets this to migration time + 1209600. A new file uses
-- DEFAULT (unixepoch() + 1209600); creation also sets it from the creation time.
-- member: token_hash becomes NULL-able (a member with a device has no member token; many
-- NULLs are allowed under UNIQUE); the name is unique among live members only; kind.
CREATE TABLE member (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('owner','manager','member')),
  kind TEXT NOT NULL DEFAULT 'person' CHECK (kind IN ('person','shared')),
  token_hash BLOB UNIQUE, created_at INTEGER NOT NULL, revoked_at INTEGER);
CREATE UNIQUE INDEX member_name_live ON member(name) WHERE revoked_at IS NULL;
-- invite: the role may be owner; an optional name; grants; shared. An invite is live while
-- used_at IS NULL and revoked_at IS NULL and expires_at > now; used_at is set when a join
-- arrives, used_by when that join is confirmed (review).
CREATE TABLE invite (
  id INTEGER PRIMARY KEY, code_hash BLOB NOT NULL UNIQUE,
  role TEXT NOT NULL CHECK (role IN ('owner','manager','member')),
  name TEXT, grants TEXT NOT NULL DEFAULT '[]', shared INTEGER NOT NULL DEFAULT 0,
  created_by INTEGER NOT NULL REFERENCES member(id), created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL, used_by INTEGER REFERENCES member(id), used_at INTEGER,
  revoked_at INTEGER);
CREATE TABLE device (
  id INTEGER PRIMARY KEY, member_id INTEGER NOT NULL REFERENCES member(id),
  name TEXT NOT NULL, public_key BLOB NOT NULL,
  key_holder INTEGER NOT NULL DEFAULT 0 CHECK (key_holder IN (0,1)),
  created_at INTEGER NOT NULL, last_seen_at INTEGER, revoked_at INTEGER);
CREATE UNIQUE INDEX device_key_live ON device(public_key) WHERE revoked_at IS NULL;
CREATE UNIQUE INDEX device_key_holder ON device(key_holder) WHERE key_holder = 1 AND revoked_at IS NULL;
CREATE INDEX device_member ON device(member_id);
CREATE TABLE join_request (
  id INTEGER PRIMARY KEY, invite_id INTEGER NOT NULL REFERENCES invite(id),
  name TEXT NOT NULL, device_name TEXT NOT NULL, public_key BLOB NOT NULL, safety TEXT NOT NULL,
  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
  state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','confirmed','refused','expired')),
  decided_by INTEGER REFERENCES member(id), decided_at INTEGER,
  member_id INTEGER REFERENCES member(id), device_id INTEGER REFERENCES device(id));
CREATE INDEX join_request_key ON join_request(public_key);
CREATE TABLE device_link (
  id INTEGER PRIMARY KEY, member_id INTEGER NOT NULL REFERENCES member(id),
  code_hash BLOB NOT NULL UNIQUE, made_by_device INTEGER NOT NULL REFERENCES device(id),
  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
  device_name TEXT, public_key BLOB, safety TEXT, requested_at INTEGER,
  state TEXT NOT NULL DEFAULT 'open' CHECK (state IN ('open','pending','confirmed','refused','expired')),
  decided_at INTEGER, device_id INTEGER REFERENCES device(id));
CREATE INDEX device_link_key ON device_link(public_key);
ALTER TABLE agent ADD COLUMN device_id INTEGER REFERENCES device(id);  -- NULL: made with a member token
```

Existing members keep their ids and token hashes (kind `person`). Existing invites keep their ids; an existing invite with `used_by` set gets `used_at` as it had.

### 23.3 Sign-in

`POST /v1/auth/challenge` (edge; body `ChallengeRequest`). The team comes from `team_id`: an unknown or closed team is 401 `unauthenticated`.

1. A live device (not revoked; its member not revoked) with this public key: a new nonce in the team's in-memory challenge table, keyed by the nonce, with the device id and the expiry. Answer `Challenge` with `origin` = the relay's `public_url`.
2. Otherwise, a `pending` join or a `pending` link with this key: 403 `join_pending`.
3. Otherwise, a `refused` or `expired` join or link with this key, and no live device: 403 `join_refused`.
4. Otherwise: 401 `unauthenticated`.

These answers tell a caller who knows a public key whether it waits; a public key is not a secret, and a join or link key is made fresh by the CLI.

`POST /v1/auth/token` (edge; body `TokenRequest`). The relay takes the nonce out of the table (one use) and checks: it is not expired; it was made for this public key; the device is still live (read from the file now); the signature verifies over `device::sign_in_message(public_url, team_id, public_key, nonce)` with the relay's own `public_url`. Any failure: 401 `unauthenticated`, one message, and a refusal row (rate-limited). Success: an access token, `last_seen_at` of the device set, a row `device_signed_in` (at most one per device per hour), answer `AccessGrantedRef`.

An access token works on member endpoints except `/v1/devices/enroll`. `authenticate` reads the device and the member from the file for each request and returns `MemberAuth` with `device: Option<DeviceAuth { id, key_holder }>`. A token of a revoked device or member fails at the next request (and revocation also drops the device's entries from the table).

Member tokens still work, until the team's `member_tokens_until`, for a member that has no device. The deadline applies to member tokens of both forms and agent tokens of the old form `apassy_agt_`; agent tokens with a team id keep their own expiry. The first device of a member (`POST /v1/devices/enroll`, member token only) sets that member's `token_hash` to NULL in the same transaction, binds the member's agents that have no device to the new device **(review)**, and writes `member_enrolled`.

### 23.4 The key holder **(review)**

- The host endpoints (`/v1/host/...`) need an access token of a live device with the key-holder flag whose member is a live owner — both read from the file on each request. Another device: 403 `not_key_holder`; not an owner: 403 `forbidden`.
- Until the team has a live device of any owner, the host endpoints also accept a member token of a live owner (the path of the migrated team and of a team made by `apassy-relay init`). Once any owner has a live device, member tokens never reach the host endpoints again. A permanent, secret-free audit row `host_bootstrap_ended` records this transition. Device creation for an owner, owner enrollment, and promotion of a member with a live device write this row in the same transaction. Revocation or later role changes do not reopen the bootstrap path.
- `enroll` sets the key-holder flag only when the member is an owner, the team has no live key holder, and the member is the only live owner.
- `POST /v1/devices/{id}/key-holder` (owner): if the team has a live key holder, only that device may call it (an access token of the current key holder), and the target must be a live device of a live owner; if the team has none, an owner's device may claim the flag for itself. Row `key_holder_moved` or `key_holder_claimed`. The CLI reminds the person to copy `keys.json` first.
- `PUT /v1/members/{id}/role` refuses (409) to change the role of the member whose device holds the keys. Move the flag first.
- Revoking the key-holder device leaves the team without one; the answer says so.

### 23.5 Endpoints

The seven edge endpoints (`/v1/auth/challenge`, `/v1/auth/token`, `/v1/join`, `/v1/devices/link`, `/v1/devices/link/cancel`, `/v1/teams`, and `/v1/connect` of section 26) reject a nonempty bearer token with 401 `unauthenticated`. These endpoints use only the body or code for team selection. Every authenticated endpoint selects its team from the bearer token, never from a body field.

| Method and path | Auth | Body | Result |
| --- | --- | --- | --- |
| `POST /v1/auth/challenge` | edge | `ChallengeRequest` | `Challenge`; 403 `join_pending` / `join_refused`; 401; 503 `busy` when the team's nonce table is full |
| `POST /v1/auth/token` | edge | `TokenRequest` | `AccessGranted` |
| `POST /v1/devices/enroll` | member token (not an access token) | `DeviceEnroll` | `DeviceView`. 409 `conflict` if an authenticated member has a live device already, or the key is taken. An access token is 401; after successful enrollment the old member token is also 401 |
| `GET /v1/devices` | member | | `[DeviceView]`: the caller's devices; the owner sees all live devices. `current` marks the caller's device. `last_seen_at` is set at each sign-in, and by the sync calls of a device (24.4) at most once a minute (`devices::mark_seen`), so a Mac that syncs shows a current time without a write on every long poll |
| `DELETE /v1/devices/{id}` | member: own device; owner: any | | `Created`. Revokes the device, its access tokens, its agents (as `DELETE /v1/agents`: their sessions end and their pending runs are invalidated), and the links it made **(review)**. 409 for the last live device of the last live owner **(review)** |
| `POST /v1/devices/{id}/key-holder` | section 23.4 | | `DeviceView` |
| `POST /v1/devices/links` | member with an access token, kind person | | `LinkCreatedRef`. 409 at 10 live devices |
| `POST /v1/devices/link` | edge | `LinkRequest` | `Pending` (`by` = the member name). The code must be an open, unexpired link code of this team whose device and member are still live; the link becomes `pending` (one use). The key must not be live in the team. The same code with the same key again (a retry) returns the same `Pending` while the link is pending, unexpired, and its maker device and member are live. Terminal links cannot be retried. Invalid or used link codes are 403 `forbidden`; a code with no active team is 401 **(review)** |
| `POST /v1/devices/link/cancel` | edge | `LinkCancel` (`code`, `public_key`) | `Created` (the link id). The new device takes back its pending link before a confirmation (section 24): the link with this code and this key becomes `refused` (its key then gets `join_refused` at sign-in, and `GET /v1/devices/links` no longer lists it); row `device_link_cancelled` (actor `edge`). A retry after a cancel, or a cancel of an expired link, answers the same. A confirmed link is 409 `conflict`: the device signs in and removes itself (`DELETE /v1/devices/{id}`). Another key or an unknown code is 403 `forbidden`. The Worker limits it per IP address as `POST /v1/devices/link` |
| `GET /v1/devices/links` | member with an access token | | `[LinkView]`: pending links of the caller's member |
| `POST /v1/devices/links/{id}/confirm` | member with an access token of the same member | `ConfirmRequest` | `DeviceView` of the new device (never the key holder). `safety` must equal the link's words (else 409 `conflict`, the link stays pending). Only a `pending` link with `expires_at > now` **(review)**. A link of another member returns 404 `not_found`, including for an owner. Row `device_added`; when the member is an owner, also `owner_device_added` |
| `POST /v1/devices/links/{id}/refuse` | same | | `Created` |
| `POST /v1/invites` | approver | `InviteRequest` (with `name`, `grants`, `shared`) | `Issued` as today. Role `manager` or `owner`: owner only. `shared`: role member only. `grants`: existing collections only. `name`: `checked_member_name` |
| `GET /v1/invites` | approver | | `[InviteView]` with `used_at` |
| `POST /v1/join` | edge | `JoinRequest` | `Pending` (`by` = the inviter's name). Without `device_name` and `public_key`: 400 `invalid_request` "This apassy-team is too old: update it (curl -fsSL <relay URL>/install.sh ...)". The invite must be live, and its maker a live member who may still invite that role **(review)**. The invite is used at once (`used_at`). The name is the invite's name if it has one, else the request's (required then); it must not be the name of a live member or of another pending join, else 409. The same code with the same key again returns the same `Pending` (a retry) while the join is pending and unexpired and the invite maker still has permission. Terminal joins cannot be retried **(review)**. A code of a used invite with another key writes a row `invite_reused` (rate-limited) and answers 403 `invite_invalid` with the message "The invite code is not valid, was used, or expired. If you did not use it, tell the person who invited you." |
| `GET /v1/joins` | approver | | `[JoinView]` pending, oldest first |
| `POST /v1/joins/{id}/confirm` | approver; a join for the role manager or owner: owner only | `ConfirmRequest` | `JoinConfirmed`. `safety` must equal the join's words (else 409, the join stays pending). Only a `pending` join with `expires_at > now`, whose invite's maker is still a live member allowed to invite that role **(review)**. One transaction: the member (role and kind from the invite, no token), its device (not the key holder), a grant for each collection of the invite that still exists, `invite.used_by`, rows `member_joined` and `device_added`. A live member with that name now: 409 |
| `POST /v1/joins/{id}/refuse` | approver | | `Created`. Row `join_refused` |
| `POST /v1/leave` | member | | `Created`: revokes the caller (as `DELETE /v1/members`). The last live owner cannot leave (409) |
| `PUT /v1/members/{id}/role` | owner | `RoleChange` | `MemberView`. A shared member stays `member`. The last live owner cannot lose the role (409). The key holder's member: 409 (section 23.4) |
| `DELETE /v1/members/{id}` | owner | | as today, and also: the member's devices and their access tokens, the member's live invites (`revoked_at`), the pending joins of those invites (`refused`), and the member's open and pending links (`expired`) **(review)**. The last live owner: 409 |
| `POST /v1/teams` | edge | `TeamCreate` | **(review)** `device_name` and `public_key` are required: the owner has no token and its device is the key holder; the answer has `device_id` and no `secret`. Without them: 400 with the update message. (`apassy-relay init --team` still makes an owner token: the operator's bootstrap; its team has `member_tokens_until`.) |

`GET /v1/members` fills `shared` and `devices`. `GET /v1/me` with an access token fills `device_id` and `key_holder`.

Maintenance (every 5 seconds, per team): pending joins and links past `expires_at` become `expired`; open link codes past `expires_at` become `expired`; expired nonces and access tokens leave the tables.

**(implementation review)** No change may leave the team without an owner who can sign in: revoking a device, revoking a member, `leave`, and taking the owner role away are refused (409) when afterwards no live owner has a live device or a member token that still works. Revoking the member whose device holds the keys says, like revoking that device, that the team has no key holder.

**(implementation review)** A POST or PUT checks its token when the headers arrive (before it takes a slot of the team) and again after the body has arrived. A device or member revoked, or a role changed, while a slow body was on its way, counts for that request.

Every new audit row holds no key, nonce, signature, code, or token. Public keys are not written to the audit; device ids and names are.

### 23.6 The CLI

Settings version 2, `settings.json` (directory 0700, file 0600):

```json
{"version": 2, "current": "t_7k2m5q4x3c",
 "teams": {"t_7k2m5q4x3c": {"relay_url": "https://...", "team": "Family", "member": "rafal",
                            "device_id": 3, "member_token": null}}}
```

- A version 1 file (`relay_url`, `member_token`) is read as one team whose id comes from `GET /v1/me`, and written back as version 2 on the next save.
- The device private key (PKCS#8) of a team: on macOS in the login Keychain (generic password, service `apassy-team`, account `<relay host> <team id> <settings dir>` with an absolute settings directory); on Linux and elsewhere in `device-<team id>.key` next to `settings.json` (base64url, mode 0600). Never in `settings.json`, never printed.
- **(review)** `create`, `join`, `device link`, and `device enroll` refuse when this machine already has a key or a settings entry for that team (a second key would overwrite the first). To be a second member of the same team on one machine (for example a shared device on the owner's Mac), use another `XDG_CONFIG_HOME`.
- **(review)** The CLI makes and stores the device key BEFORE it sends a join or a link request. After an error it asks `/v1/auth/challenge` to learn whether the request arrived, and retries with the same key.
- **(review)** The CLI computes the safety words itself and stops (exit 2) if `Pending.safety` differs.
- **(review)** If `Challenge.origin` is not the relay URL of the settings, the CLI says so clearly ("The relay calls itself <origin>; your settings say <url>.") and stops.
- `APASSY_TEAM` (a team id) or `--team ID` on any member command picks the team; else `current`.
- Each member command signs in when the team has a device (challenge, sign, token) and keeps the access token in memory for that process only. A 401 with an access token signs in once more and repeats the call once; a second 401 fails.
- `APASSY_TEAM_TOKEN` still works as a member token until the team's member tokens end.

Commands (secrets only on stdin, as today):

| Command | Does |
| --- | --- |
| `create --relay URL --team NAME --name NAME [--device NAME]` | makes a device key (device name default: the host name), sends it with the team code; saves the team as current |
| `join --relay URL [--name NAME] [--device NAME] [--no-wait]` | stdin: an invite code or a link `.../join#code`. Makes and stores a device key, `POST /v1/join`, prints the team, the inviter, the team id, and the safety words, and says "Tell <inviter> these words". Then signs in every 5 seconds until the join is confirmed (prints "Joined") or refused/expired (exit 3), at most 10 minutes; `--no-wait` returns at once (exit 0) and `apassy-team join --resume` waits again |
| `device enroll [--name NAME]` | with the team's member token: makes a key, `POST /v1/devices/enroll`, removes the member token from the settings |
| `device list`, `device revoke ID`, `device key-holder ID` | |
| `device add` | on an existing device: `POST /v1/devices/links`; prints the link code once on stdout and the next steps on stderr |
| `device link --relay URL [--device NAME] [--no-wait]` | on the new device, stdin: the link code; like `join` |
| `device pending`, `device confirm ID --words "W1 W2"`, `device refuse ID` | on an existing device: links that wait; confirm sends the words that the new device shows |
| `invite [--role member\|manager\|owner] [--hours N] [--name NAME] [--grant ID]... [--shared]` | prints the link `<relay URL>/join#<code>` once on stdout |
| `joins`, `confirm ID --words "W1 W2"`, `refuse ID` | approver: joins that wait, confirm with the words the joiner tells you, refuse. `joins` does NOT print the words: the confirmer must get them from the joiner **(review)** |
| `leave`, `member role ID ROLE` | |
| `team list`, `team use ID` | the teams of this machine |
| `host` | as today, for the current team; it signs in with the key-holder device; 403 `not_key_holder` ends it with a clear message. One host serves one team in this stage (ADR 0019 section 9 wants one host for all teams: later) |

### 23.7 What this does not protect

- On Linux the device key is a file: whoever reads it is that device until it is revoked.
- The safety words protect against someone who has only a leaked code: that person cannot know the real joiner's words. They do NOT protect against the path (the Worker, Cloudflare, the relay operator): the relay computes the words, and a party in the path can make a key whose words match in about 2^16 tries. An owner or manager who confirms without getting the words from the person lets the wrong person in.
- Lost devices: if the last owner loses every device, nobody can sign in as an owner. Keep two owners. The operator cannot add an owner device through the relay in this stage.
- An owner device added through a link and a reused invite are shown only in the audit; owners are not notified elsewhere yet.
- The relay operator can still change a team's file by hand (section 22).

## 24. Vault sync

ADR 0022 of the core, stage 1. A team holds one opaque snapshot of one vault, with a head signed by the device that pushed it and a version that grows by one for each push. The relay checks the head, the chain, and the hash; it never opens a snapshot (SQLCipher ciphertext with the passphrase of the vault as its only key). The app side is `docs/contracts/relay-sync-v1.md` of the core; both documents describe one wire, and this section takes precedence for the relay. Shared code: `src/sync_head.rs` (the head grammar, its hash, and the checks), used by the server; the CLI does not use sync in this stage.

### 24.1 Words and limits

| Thing | Rule |
| --- | --- |
| Snapshot | the bytes of one push, opaque; file `teams/<team id>.sync/<version>.bin`, mode 0600, in a directory of mode 0700. The current and the previous version are kept; older files are removed at the push that makes them older |
| Version | an integer from 1; `0` is "no snapshot"; each push is the current version plus one. After `DELETE /v1/sync` it starts at 1 again |
| Head | the text of 24.3, signed by the pushing device, stored with its signature in `sync_head`. The newest 10000 rows are kept (maintenance) |
| Head hash | SHA-256 of the head text; the `previous` of the next head |
| Chain | the heads after a version, oldest first, at most 1000 in one answer: a device that is further behind asks again from the last one |
| Signer | a device that signed a head of an answer, with its public key. A removed device stays a signer of the heads it pushed while it was a member, with the newest version it pushed (`last_version`); a client accepts its signature only on a head up to that version |
| Receipt | the newest version a device reported as merged, one row per device |
| Sync headers | `X-Apassy-Sync-Head` (base64url of the head text, at most 512 characters), `X-Apassy-Sync-Signature` (base64url of the DER signature, at most 96 characters) |
| `If-Match` | `"<decimal version>"`, required on a push and on a delete; `"0"` means "no snapshot" |
| `sync_bytes` | per team, default 67108864 (64 MiB), 1048576 to 67108864: the largest snapshot (`Content-Length` and the head's `size`). 64 MiB is the most that the head grammar and the app allow |
| `sync_pushes_per_hour` | per team, default 600, 1 to 1000000: `sync_head` rows with `pushed_at` in the last 3600 seconds (the kept rows are always enough) |
| `sync_transfers` | per team, default 2, 1 to 8: pushes and snapshot downloads in flight at once. Over: 503 `busy`, `Retry-After: 2` |
| `Limits::sync_transfers_total` | per relay, 16, not read from the environment: the same for the whole process |
| Sync long polls | at most 1 per device (`LongPolls::new(1)`); a second is answered at once, as with `wait=0`; `wait` is 0 to 25 |
| Auth | an access token of a live device of the team. A member token is 401 `unauthenticated` (device-only, as the link endpoints). `DELETE /v1/sync` needs the device of a live owner (else 403 `forbidden`). No role limits a push in this stage |
| Last seen | a head request (also a long poll, at its start), a push, a snapshot download, and a receipt set the device's `last_seen_at` when it is empty or at least 60 seconds old (`SEEN_EVERY_SECS`); a failure to write it does not fail the call |

### 24.2 Schema version 4 (team file)

`Store::open_team` migrates a version 3 file to version 4 with the copy rule of 23.2: copy to `<file>.pre-v4` (mode 0600, written as `.pre-v4.tmp`, synced, renamed; refuse to migrate when the copy cannot be made; keep it, the version 3 image refuses version 4), then in one `BEGIN IMMEDIATE` transaction create the tables and set `PRAGMA user_version = 4`. The migration is additive; no table is rebuilt. A new team file is made at version 4. Version 1 and unknown versions are refused as today. `remove_team_file` also removes `.pre-v4`, `.pre-v4.tmp`, and the `.sync` directory.

```sql
CREATE TABLE sync_head (
  version INTEGER PRIMARY KEY CHECK (version >= 1),
  vault_id TEXT NOT NULL, snapshot_sha256 BLOB NOT NULL, size INTEGER NOT NULL,
  previous_sha256 BLOB NOT NULL, head_sha256 BLOB NOT NULL,
  device_id INTEGER NOT NULL REFERENCES device(id), head_time INTEGER NOT NULL,
  head TEXT NOT NULL, signature BLOB NOT NULL, pushed_at INTEGER NOT NULL);
CREATE TABLE sync_receipt (
  device_id INTEGER PRIMARY KEY REFERENCES device(id),
  version INTEGER NOT NULL, at INTEGER NOT NULL);
```

The current version is `max(version)` of `sync_head`, or 0. The head rows are the chain; the snapshot files exist only for the current and the previous version.

### 24.3 The signed head

```
apassy-relay-sync-head-v1
<vault_id> <version> <snapshot_sha256> <size>
<previous> <device> <time>
```

Exactly three lines joined with `\n`, no trailing newline, no `\r`, one space between fields, ASCII only. `vault_id`: 36 characters, lowercase UUID form. `version`: decimal, 1 or more, no leading zero. `snapshot_sha256`: 64 lowercase hex. `size`: decimal, 1 to 67108864 (64 MiB), no leading zero; a push also needs it at most `sync_bytes` (check 3) and equal to `Content-Length` (check 7). `previous`: 64 lowercase hex, the head hash of the current head, or 64 `0` when the team has no head. `device`: `<team id>/<device id>` with the device id decimal and no leading zero. `time`: decimal, at most 12 digits; the pushing device's clock, stored as `head_time`, not checked against the relay's clock. Any other text is 400 `invalid_request` before any signature work.

The signature is ECDSA P-256 with SHA-256 over the bytes of the head text, ASN.1 DER (`device::verify`), by the public key of the device named in `device`.

Checks of a push, in this order; the first failure answers and nothing is stored:

1. The headers (400): `If-Match`, `Content-Length`, both sync headers present and decodable, the head parses. `Transfer-Encoding` is refused. Then a `Content-Length` above 64 MiB is 413 `payload_too_large`, also before the token: no push can have it. The Worker refuses a missing or malformed `Content-Length`, `Transfer-Encoding`, and a `Content-Length` above 64 MiB plus 64 KiB before the relay (section 17); the relay checks again.
2. The token (401), read again after the body as 23.5 requires. An access token that expires during the upload fails this second read (401 `token_expired`) after the whole body; so a client signs in again before an upload when its token has less left than the longest upload it allows (the app: 10 minutes).
3. `Content-Length` at most `sync_bytes` (413 `payload_too_large`). The relay asks to close the connection, but tiny_http drops that header and reads the rest of the body first (24.5).
4. `sync_pushes_per_hour` (403 `team_limit`, a `limit_reached` row as in section 22).
5. A transfer slot of the team and of the relay (503 `busy`).
6. `If-Match` equals the current version (412 `precondition_failed`; the answer carries `ETag: "<current>"`).
7. 403 `sync_head_invalid` with the message naming the check: `device` names this team and the device of the token; the signature verifies with that device's stored public key; `version` is the current version plus one; `previous` is the current head's `head_sha256`, or 64 zeros when there is none; `vault_id` equals the current head's when there is one; `size` equals `Content-Length`.
8. The body streams to `teams/<team id>.sync/<version>.<random>.tmp` while it is hashed; fewer or more bytes than `Content-Length` is 400; a hash other than `snapshot_sha256` is 403 `sync_head_invalid` ("hash"). The temporary file is removed on every failure.
9. Under the team's sync mutex (one commit at a time): the current version is read again (412 when another push committed first); the file is renamed to `<version>.bin`; in the transaction that inserts the row, the device and its member must still be live (401 otherwise, and the file goes): a removal takes the same store, so a device removed after step 2 still gets no head; the row is inserted; the file of version minus two is removed; `sync_pushed` is written; the notifier wakes the long polls.

A refused push writes a refusal row (kind `sync`, action `sync_refused`, detail `{"reason": "<check>"}`), rate-limited as other refusals. The reasons are the checks of 7 and 8 (`device`, `signature`, `version`, `previous`, `vault id`, `size`, `hash`), `if_match` (412), `too_large` (413), and `length` (400 for the body).

### 24.4 Endpoints

| Method and path | Auth | Body | Result |
| --- | --- | --- | --- |
| `GET /v1/sync/head?since=N&wait=S` | device | | `SyncHeadView`: `version` (0 when empty), and when not empty `head` (base64url text), `signature`, `device_id`, `device_name`, `pushed_at` (relay time); `chain`: the rows of versions `since + 1` to `version`, oldest first, at most 1000 (with more, the oldest 1000: the device asks again with `since` = the last entry's version), each `{version, head, signature, device_id, pushed_at}`; `chain_from`: the version of the first chain entry, absent when the chain is empty; `signers`: `[{device_id, public_key, removed, last_version}]` for the device of the current head and of each chain entry (`public_key` base64url; `removed` and `last_version` only for a device that was removed or whose member was removed: `last_version` is the newest version of its kept heads); `receipts`: `[{device_id, device_name, version, at}]` for the live devices. `ETag: "<version>"`. `wait` 0 to 25: while `version == since`, hold the answer up to `wait` seconds on the team notifier (a push or a delete wakes it), then answer the current state. A `since` above the current version (after a delete or a restore) answers at once with an empty chain |
| `GET /v1/sync/snapshot?version=N` | device | | the bytes: `200`, `Content-Type: application/octet-stream`, `Content-Length`, `ETag: "N"`, `X-Apassy-Sync-Head`, `X-Apassy-Sync-Signature`, `Cache-Control: no-store`, streamed from the file (`Response::from_file`). `version` is required; a version that is not the current or the previous one, or an empty team, is 404. Takes a transfer slot. Writes `sync_fetched` after the answer, at most once per device and version |
| `PUT /v1/sync/snapshot` | device | the snapshot bytes, with `If-Match`, `Content-Type: application/octet-stream`, `Content-Length`, the two sync headers | 24.3. On success `SyncHeadView` of the new version with an empty chain and the receipts |
| `POST /v1/sync/receipt` | device | `{"version": N}` | `{"version": N, "at": now}`; upsert of `sync_receipt` for the caller's device; `N` above the current version is 409 `conflict`; row `sync_received` |
| `DELETE /v1/sync` | owner's device, `If-Match` | | `{"last_version": N}`. Removes every `sync_head` and `sync_receipt` row and the `.sync` directory's files; `If-Match: "0"` on an empty team is a no-op. Row `sync_deleted` with `last_version`; wakes the long polls |

Changes to existing results: `DeviceView` gains `public_key` (base64url of the stored 65 bytes); `LinkView` gains `public_key` (the key of the pending request), so the confirming device computes the safety words itself. `TeamCreated` is unchanged. The chain entries carry `device_id` only; the keys are in `signers`. A client checks every head with them, not with `GET /v1/devices`, which lists live devices only: a head pushed by a device that was removed later (a Mac that turned relay sync off, or one removed in "Devices…") stays verifiable for the versions it pushed, and the other devices push on top of it. The relay never accepts a push of a removed device (its tokens end at the removal; a push is read again after its body, and its commit checks the device again in the transaction that stores the head), so its newest kept head is the last one it could sign.

### 24.5 HTTP layer

- Routes: `["v1","sync","head"]` GET, `["v1","sync","snapshot"]` GET and PUT, `["v1","sync","receipt"]` POST, `["v1","sync"]` DELETE. `Need::Member` for all but the delete (`Need::Owner`); the handlers then require `MemberAuth.device` (401 otherwise), as `own_device` does for links.
- `PUT /v1/sync/snapshot` is the one route that bypasses `read_body` and `MAX_JSON_BODY`: `handle` dispatches it with the `Request` so the handler streams `as_reader()` to the temporary file. It re-authenticates after the body as every POST and PUT does. The 64 KiB cap stays for every JSON body, including `POST /v1/sync/receipt`.
- Sync paths are in the member lane (not `is_agent_path`). The transfer slots (24.1) bound the threads a team can hold with slow transfers of a signed-in device; `Limits::sync_transfers_total` bounds the relay. A stalled client holds its thread until the TCP connection ends; this is accepted in this stage and listed in 24.10. A push that is answered before its transfer slot (a 400, 401, or 413 before the token, a 403 or 413 after it) takes no slot, so the slots do not bound those.
- `Core` gets `sync_transfers: AtomicUsize`, `sync_polls: LongPolls`, and `sync_commit: Mutex<()>`, and `relay_sync_transfers: Arc<AtomicUsize>`: one counter of the hub, shared by every team, for `Limits::sync_transfers_total`. `sync_commit` also covers the lookup and open of a snapshot for a download, the delete, and the copy of a backup, so a file is never removed or replaced between its row and its open.
- Every JSON answer has `Content-Length` (never chunked), and so has a snapshot download. A 503 answer has `Retry-After: 2`. tiny_http drops a `Connection: close` header: after an early answer to a push (400, 401, 412, 413, 403), it reads and drops the rest of the declared body, holding the request thread, before the connection serves another request or closes. So the app always sends the whole body (contract relay-sync-v1 section 9). Closing the socket on an early answer needs a server that exposes it (tiny_http 0.12 does not); see 24.10. The same holds for any early answer with a declared body (404, 405, 401, 413), on any path. The edge bounds what such a request can make the relay read: the Worker refuses a push without a usable `Content-Length` or with one above 64 MiB plus 64 KiB, a proxy body above 8 MiB plus 64 KiB, and any other body above 128 KiB, before forwarding it, and limits pushes (exact `PUT /v1/sync/snapshot`) per IP address with `SYNC_LIMITER` (section 17). It bounds bytes, not time.
- Maintenance (every 5 seconds, per team): `DELETE FROM sync_head WHERE version <= current - 10000`; a `.tmp` file in the `.sync` directory older than one hour is removed.

### 24.6 Audit

New actions, all without the head text, the signature, or any snapshot byte: `sync_pushed {version, device_id, size}`, `sync_fetched {version, device_id}`, `sync_received {version, device_id}`, `sync_deleted {last_version}`, and the refusal `sync_refused {reason}` (actor `edge` as other refusals, rate-limited). `limit_reached` names `sync_pushes_per_hour` as other limits. The masks need no change: a head holds no token form.

### 24.7 Operator

`limits ID` reads and sets three more fields: `--sync-bytes N`, `--sync-pushes-per-hour N`, `--sync-transfers N`, with the ranges of 24.1; the result prints nine effective values. `TeamLimits` gets the three fields with `serde(default)`, so an existing `limits` column reads unchanged. `teams` shows, for an open team, the current sync version and the size of the current snapshot (`sync_version`, `sync_size`). `delete ID` removes the `.sync` directory with the file. The backup of each team (`deploy/vps/backup`) copies `teams/<id>.sync/` next to `teams/<id>.db`: up to about 128 MiB more per team.

### 24.8 Files

| File | What | Mode |
| --- | --- | --- |
| `teams/<team id>.sync/` | the snapshots of the team | directory 0700 |
| `teams/<team id>.sync/<version>.bin` | the current and the previous snapshot | 0600 |
| `teams/<team id>.sync/<version>.<random>.tmp` | a push in flight; removed on failure or by maintenance after one hour | 0600 |
| `teams/<team id>.db.pre-v4` | the file before the migration to version 4 | 0600 |

### 24.9 Tests

- The head: the test vectors of the contract (both heads hash and verify; one changed character fails; another key fails); every malformed text of 24.3 is 400 before a signature is checked.
- The sign-in and safety vectors of the contract (`src/device.rs`): the sign-in message hashes to the contract's SHA-256 and its signature verifies; the link code and the vector key give the safety hash and `tulip arrow`.
- The contract's vectors use the team id `t_7k2m5q4x3c` (`a-z`, `2-7`): the relay parses, stores, and chains both vector heads with the contract's hashes and signatures. Head 2 on an empty team fails the `version` check (it comes before `previous`).
- A push on an empty team with `If-Match: "0"` and head 1, then head 2 with `If-Match: "1"`: 200, the files, the rows, the audit rows, `GET /v1/sync/head?since=0` returns both chain entries and `since=1` returns one. Refused and nothing stored: head 2 on an empty team (`version`: the version check comes before the previous check); head 1 after head 1 (`version`); a stale `If-Match` (412 with `ETag`); a changed `size`, a body shorter or longer than `Content-Length`, a body with another hash; a head naming another device signed by that device's key (`device`); a head signed by a revoked device (401); a device removed after the last check of the caller and before the commit (401, no file stays); a member token (401); a snapshot of 64 MiB plus one byte (413, and the temporary file is gone; 413 also without a valid token); a vault id that differs from the current head's.
- Signers: a device pushes, is removed, and the head answer still lists its key with `removed` and `last_version`; its push is 401; another device pushes on top of its head; a page after its heads does not name it. A unit test checks the signers of a removed member.
- Paging: with 2500 heads, `since = 0`, `1000`, and `2000` give the versions 1 to 1000, 1001 to 2000, and 2001 to 2500, each with `chain_from = since + 1`.
- Link cancel: a cancel with another key is 403; with a bearer, 401; with the code and the key, the link is refused (the key gets `join_refused`, the links list is empty, row `device_link_cancelled`), and a retry answers the same; a confirmed link is 409.
- Two pushes at one version from two threads: one 200, one 412, one file, the chain has one new entry.
- `GET /v1/sync/snapshot`: the current and the previous version stream with the headers; the version before them is 404; after a third push the first file is gone; a transfer over `sync_transfers` is 503.
- The long poll: `wait=25` with `since` equal to the current version holds and returns on a push and on a delete; a second poll of the same device returns at once.
- `DELETE /v1/sync`: owner's device only; `If-Match` checked; files and rows gone; the next push is version 1 with zeros.
- Separation: the access token of team A gets 401 on every sync endpoint with the snapshot of team B; the files of team B are untouched.
- Receipts: `POST /v1/sync/receipt` shows in `GET /v1/sync/head`; a version above the current one is 409.
- Last seen (unit test in `src/server/devices.rs`): a head request, a receipt, a push, and a download set `last_seen_at`; a second call within 60 seconds does not change it; `GET /v1/devices` shows it.
- The Worker (`deploy/worker/test/`): a push with no, an empty, a non-numeric, or a chunked `Content-Length` is 400 and one above 64 MiB plus 64 KiB is 413, before the limiter and the relay; one at that size passes; `SYNC_LIMITER` keys pushes by address, its refusal is 429, and a missing or failing limiter lets them pass; downloads and other sync routes are not limited; `PUT /v1/sync/snapshot/`, `POST` and `PATCH /v1/sync/snapshot`, `PUT /v1/sync/head`, `POST /v1/sync/receipt`, `DELETE /v1/sync`, an unknown path, and other JSON routes get 413 above 128 KiB and 400 for a malformed length, before the limiter and the relay, and pass at 128 KiB; a `/p/` body gets 413 above 8 MiB plus 64 KiB; GET and HEAD are forwarded without `Content-Length` or `Transfer-Encoding`; `POST /v1/devices/link/cancel` uses `CREATE_LIMITER`.
- Limits: `sync_pushes_per_hour` gives 403 `team_limit` and one `limit_reached` row per ten seconds; the operator sets and reads the three fields; a `limits` column without them reads the defaults.
- Migration: a version 3 file opens as version 4 with `.pre-v4` next to it; a failed copy leaves version 3.
- No audit row, response, or vault cell holds a snapshot byte, the head signature, or a token.

### 24.10 What this does not protect

- A removed device's key stays in the team file and in `signers` for the heads it pushed while it was a member. Its key cannot push again; a client refuses it on a head above its `last_version`.
- The relay checks that a head is signed by a device the team file lists. The operator, or root, can add a device row by hand and sign heads with it; a client in this stage verifies against the relay's `signers`, so it accepts them. ADR 0022 stage 2 moves the device keys into the vault.
- The relay can withhold a push or serve an older version; a client sees it through the version and the chain and stops, it cannot be fooled into merging a fork. It can delete the snapshots; the clients keep their vaults.
- Snapshot bytes are the vault's SQLCipher ciphertext: the operator, root, a disk snapshot, and a backup hold them, with the salt; the passphrase is not on the relay.
- A stalled push of a signed-in device holds a request thread until the connection ends; the transfer limits bound how many.
- An early answer does not end a request with a declared body, on any path: the relay reads the rest of it before the connection closes. The Worker bounds the bytes at the edge (section 17): a push with a missing, malformed, or chunked length, or one above 64 MiB plus 64 KiB, never reaches the relay; a body under `/p/` is bounded at 8 MiB plus 64 KiB, and every other body (a trailing slash, another method, an unknown path) at 128 KiB. Only the exact push is rate-limited: `SYNC_LIMITER` allows about 60 a minute per IP address. What stays open: a caller without a token can still trickle a body within those bounds, and each such request holds a request thread until the edge or the client ends the connection; no transfer slot bounds them. That works on any route, within about 60 pushes a minute per address for a push of up to 64 MiB and with no rate limit for the smaller bodies elsewhere; many addresses get more. A caller that reaches the relay's origin without the Worker has no such bound, but it needs the edge secret. Ending it needs a server with read timeouts that can close the socket on an early answer.
- Sizes, times, device ids and names, and the push rate are visible to the operator and in the audit.

## 25. Questions and push

**Status: built (stream R4, branch `feat/questions`), not deployed; the A4 spike (25.7) has not run yet.** ADR 0025 of the core, §3d and §3e (stage 5), and section A of its `docs/design/stage5-plan.md`. A device of a vault posts a question of its agent broker; the relay stores it sealed, routes it to the other devices of the same member (and, for `to: "approvers"`, to the owners' and managers' devices), takes their sealed answers, and triggers an Apple push without content through the Worker. The relay never reads a question or an answer: they are ChaCha20-Poly1305 envelopes under a key that only the devices of the vault hold. The app side is `docs/contracts/relay-questions-v1.md` of the core, with its integrator decisions; both documents describe one wire, and this section takes precedence for the relay. The envelopes' plaintext, the answer signatures, and the trust rules are in the contract only: the relay needs none of them. Code: `src/server/questions.rs` (routes, routing, limits, maintenance), `src/server/push.rs` (the push trigger), `deploy/worker/src/apns.ts` (the APNs sender).

### 25.1 Words and limits

| Thing | Rule |
| --- | --- |
| Question | one sealed card of one asking device: `qid`, `to`, `key_id`, `nonce`, `ciphertext`, `expires_at`; a state `open`, `settled`, or `expired` |
| `qid` | base64url of 16 bytes: exactly 22 characters of `A-Za-z0-9-_` that decode to 16 bytes (non-canonical text refused); made by the asker; unique in the team (409 `conflict` otherwise). In a path, a `qid` out of its form is 400 |
| `to` | `member` or `approvers` (the routing bit, 25.3); stored as `to_approvers` 0 or 1. `approvers` is refused with 403 `not_routed` unless `APASSY_RELAY_QUESTIONS_TO_APPROVERS=1` (25.3) |
| `key_id` | 16 lowercase hex characters; an answer and a settle must carry the question's `key_id` (400 otherwise) |
| `nonce` | base64url of exactly 12 bytes |
| Ciphertext | base64url, not empty (400); a card at most 32784 bytes, an answer at most 8208, a settle at most 1040 (decoded); over: 413 `payload_too_large` |
| `v` | `1` in every body; another value is 400 |
| `expires_at` | unix seconds, `now + 10 < expires_at <= now + 600` on the relay clock (400 otherwise). The app uses 300 s. The relay never changes it: the card's AAD binds it |
| State at a time | `settled` stays settled; an `open` question with `expires_at <= now` is `expired` at once, in every answer and check, before maintenance marks it |
| Asker | the device of the access token that posted the question (`question.device_id`) |
| Routing set | 25.3 |
| Answer | one sealed answer of one device in the routing set, stamped by the relay with its device id, member id, role, and time |
| Settle | one sealed envelope of the asker that ends the question |
| Question sequence | `team.question_seq`, a counter of the team that only grows; a question takes the next value when it is posted, settled, and expired (`question.seq`) |
| `open_questions` | per team, default 20, 1 to 1000: questions with state `open` and `expires_at > now`. Over: 403 `too_many_questions` |
| `questions_per_hour` | per team, default 300, 1 to 1000000: questions with `created_at` in the last 3600 seconds (a purged question still counts until it is deleted). Over: 403 `too_many_questions` |
| `member_open_questions`, `member_questions_per_hour` | the same counts for the questions of one member (all its devices), default 15 and 225, ranges as the team's. Over: 403 `too_many_questions` |
| `device_open_questions`, `device_questions_per_hour` | the same counts for the questions of one asking device, default 10 and 150, ranges as the team's. One device cannot use the whole quota of its member or its team. Over: 403 `too_many_questions` |
| `question_bytes` | per team, default 8388608 (8 MiB), 1048576 to 268435456: the bytes of ciphertext that the team file holds at once, cards, settles, and answers together (purged questions hold none). A post whose card would pass it: 403 `too_many_questions`; an answer: 403 `too_many_answers`. A settle is never refused for it |
| Answers per device per question | 3, fixed. Over: 403 `too_many_answers` |
| Answers per question | 20, fixed, of all devices. Over: 403 `too_many_answers` |
| Question long polls | 1 per device for the list (`question_polls`) and 1 per device for answers (`answer_polls`), both `LongPolls::new(1)`; a second is answered at once, as with `wait=0`; `wait` 0 to 25. They run in the question lane (25.5), at most `Limits::question_long_polls_per_team` (32) of one team |
| List page | at most 100 questions per answer |
| Push token | at most 1 per device; lowercase hex of the APNs device token, 32 to 200 characters, stored as its text; `environment` `development` or `production`; `bundle_id` equal to `APASSY_RELAY_PUSH_TOPIC` |
| Purge | 10 minutes after a question was settled (`settled_at`) or expired (`expires_at`), maintenance deletes its answers and empties its card and settle; the row keeps its metadata (25.8) |
| Retention | maintenance deletes a question and its answers 24 hours after `created_at` |
| Auth | an access token of a live device (`Need::Member`, then `MemberAuth.device` required, as 24.5). A member token is 401 `unauthenticated`, before its body is parsed |

### 25.2 Schema version 5 (team file)

`Store::open_team` migrates a version 4 file to version 5 with the copy rule of 23.2 and 24.2: copy to `<file>.pre-v5` (mode 0600, written as `.pre-v5.tmp`, synced, renamed; refuse to migrate when the copy cannot be made; keep it, the version 4 image refuses version 5), then in one `BEGIN IMMEDIATE` transaction add the column, create the tables, and set `PRAGMA user_version = 5`. The migration is additive: no table is rebuilt, and the sync tables and rows are untouched. A version 3 file goes through 4 to 5 in one start, with both copies. A new team file was made at version 5 until section 27 (now version 6, 27.2). Version 1 and versions above the current one are refused. `remove_team_file` also removes `.pre-v5` and `.pre-v5.tmp`.

```sql
ALTER TABLE team ADD COLUMN question_seq INTEGER NOT NULL DEFAULT 0;
CREATE TABLE question (
  qid TEXT PRIMARY KEY,
  device_id INTEGER NOT NULL REFERENCES device(id), member_id INTEGER NOT NULL REFERENCES member(id),
  to_approvers INTEGER NOT NULL CHECK (to_approvers IN (0,1)),
  key_id TEXT NOT NULL, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL,
  seq INTEGER NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('open','settled','expired')),
  settled_at INTEGER, settle_nonce BLOB, settle_ciphertext BLOB);
CREATE INDEX question_seq ON question(seq);
CREATE INDEX question_open ON question(state, expires_at);
CREATE TABLE question_answer (
  id INTEGER PRIMARY KEY, qid TEXT NOT NULL REFERENCES question(qid) ON DELETE CASCADE,
  device_id INTEGER NOT NULL REFERENCES device(id), member_id INTEGER NOT NULL REFERENCES member(id),
  role TEXT NOT NULL CHECK (role IN ('owner','manager','member')),
  key_id TEXT NOT NULL, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL, at INTEGER NOT NULL);
CREATE INDEX question_answer_qid ON question_answer(qid, id);
CREATE TABLE push_token (
  device_id INTEGER PRIMARY KEY REFERENCES device(id), token BLOB NOT NULL,
  environment TEXT NOT NULL CHECK (environment IN ('development','production')),
  bundle_id TEXT NOT NULL, updated_at INTEGER NOT NULL, failed_at INTEGER);
CREATE TABLE device_wrapped_key (
  device_id INTEGER NOT NULL REFERENCES device(id), name TEXT NOT NULL, wrapped BLOB NOT NULL,
  by_device INTEGER NOT NULL REFERENCES device(id), at INTEGER NOT NULL,
  PRIMARY KEY (device_id, name));
```

- The plan's `question` table has one `settle_ciphertext`; a settle also needs its nonce (`settle_nonce`). `team.question_seq` is not in the plan: `max(seq)` of the kept rows can go down when maintenance deletes them, and a device that polls with `since` above it would miss new questions.
- `device_wrapped_key` is for shared vaults (plan section B, stream V3) and for the question key of approvers' devices (contract section 5.4). This stage creates the table and no route uses it.
- Revoking a device (`DELETE /v1/devices/{id}`) or a member (`DELETE /v1/members/{id}`, `POST /v1/leave`) deletes the `push_token` rows of the removed devices in the same transaction. Their questions and answers stay until maintenance deletes them.

### 25.3 Routing

The routing set of a question, read from the file at each use (a list, an answer, a push), so a revocation or a role change counts at once:

```sql
SELECT d.id FROM device d JOIN member m ON m.id = d.member_id
WHERE d.revoked_at IS NULL AND m.revoked_at IS NULL AND d.id <> :asker_device
  AND (m.id = :asker_member OR (:to_approvers = 1 AND m.role IN ('owner','manager')))
```

- The asking device is never in its own set: it cannot list or answer its own question.
- A device outside the set gets 403 `not_routed` when it answers, and never sees the question in its list. It can learn that a `qid` exists only if it knows the `qid` (128 random bits).
- The relay does not check what the asker put in `to`. `to_approvers` is the one bit of a question that the relay reads; the card's AAD binds it, so a relay that flips it makes the card fail to open.
- Until shared vaults (integrator decision 1 of the contract), the app sends every question with `to: "member"`, and the relay refuses `to: "approvers"` with 403 `not_routed` (after the forms and sizes, before the transaction, with a `question_refused` row): an approver's device has no question key until V3, so such a question could only wait. `APASSY_RELAY_QUESTIONS_TO_APPROVERS=1` (default `0`; any other value stops the start) turns the routing above on; with V3 it is set and needs no other relay change.

### 25.4 Endpoints

Routes: `["v1","questions"]` POST and GET, `["v1","questions",qid,"answers"]` POST and GET, `["v1","questions",qid,"settle"]` POST, `["v1","push","token"]` PUT and DELETE; `Need::Member` for all, then the handler requires `MemberAuth.device` (401 otherwise). The device and its member are read again at each request, and a POST or PUT reads the token again after its body (23.5), so the role and the liveness used for routing are current. A long poll reads them again at each turn (25.5). A request without a valid token is 401 before its body is read, as on every endpoint. The request time (`now`) of `POST /v1/questions`, `…/answers`, `…/settle`, and `PUT /v1/push/token` is taken after the body has arrived, so a slow body cannot answer a question that expired meanwhile, or post with an old clock.

| Method and path | Auth | Body | Result |
| --- | --- | --- | --- |
| `POST /v1/questions` | device | `QuestionPost {v, qid, to, expires_at, key_id, nonce, ciphertext}` | `{qid, seq, created_at, expires_at}`. Forms (400), then the size (413), then `to: "approvers"` without the flag (403 `not_routed`, 25.3). Then in one transaction: the `qid` is new (409 `conflict`: a retry of a post that landed), in this order `open_questions`, `questions_per_hour`, `member_open_questions`, `member_questions_per_hour`, `device_open_questions`, `device_questions_per_hour`, `question_bytes` (403 `too_many_questions` with a message that names the limit, a `limit_reached` row as in section 22, committed), the row with the caller's device and member, `seq = ++team.question_seq`, `question_posted`. Then the notifier wakes the long polls, and the push trigger runs (25.6). |
| `GET /v1/questions?since=N&wait=S` | device | | `{seq, questions: [QuestionView]}`: the questions whose routing set holds the caller, with `seq > since`, oldest `seq` first, at most 100; a purged question (25.8) is not listed again. `QuestionView` = `{qid, seq, to, from_device_id, from_device_name, key_id, nonce, ciphertext, created_at, expires_at, state}`, plus `settled_at` and `settle {key_id, nonce, ciphertext}` when settled. The top-level `seq` is `team.question_seq`. `wait`: while the list is empty, hold up to `wait` seconds on the team notifier (a post, a settle, an expiry, or a deletion wakes it). A top-level `seq` below `since` (a restored relay) answers at once. |
| `POST /v1/questions/{qid}/answers` | device | `EnvelopePost {v, key_id, nonce, ciphertext}` | `{id, at}`. Checks in this order: 400 (shape) → 413 → 404 `not_found` (no such `qid` in the team) → 403 `not_routed` (25.3) → 409 `question_settled` / `question_expired` (state at now) → 400 (`key_id` differs) → 403 `too_many_answers` (3 of this device, then 20 of all devices, then `question_bytes` with a `limit_reached` row). The row stamps the caller's device id, member id, role, and the relay time. Row `question_answered`; the notifier wakes the asker's answer long poll. The relay does not settle the question. |
| `GET /v1/questions/{qid}/answers?after=N&wait=S` | the asker's device | | `{state, expires_at, answers: [{id, device_id, member_id, role, key_id, nonce, ciphertext, at}]}` with `id > after`, `id` order (none after the purge). Another device: 404 `not_found` (as a link of another member, 23.5). `wait`: while there is no such answer and the state is `open`, hold up to `wait` seconds. |
| `POST /v1/questions/{qid}/settle` | the asker's device | `EnvelopePost {v, key_id, nonce, ciphertext}` | `{qid, state: "settled", settled_at}`. 400 (shape) → 413 → 404 for another device or an unknown `qid`. A settled question: the same `key_id`, `nonce`, and `ciphertext` again answer the same (a retry, no new `seq`); another envelope is 409 `question_settled`, and so is any settle after the purge. An expired question (state at now): 409 `question_expired`. Then 400 when the `key_id` differs. `seq = ++team.question_seq`, row `question_settled`, the notifier wakes. |
| `PUT /v1/push/token` | device | `PushTokenPut {token, environment, bundle_id}` | `{device_id, updated_at}`; upsert for the caller's device, `failed_at` cleared. A relay without push (25.6): 409 `push_unavailable`. A token, environment, or `bundle_id` (other than the topic) out of its form: 400. Row `push_token_set {device_id, environment}` |
| `DELETE /v1/push/token` | device | | `{device_id}`; removes the caller's row (no row: the same answer). Row `push_token_removed {device_id}` when a row was removed |

New error codes in `src/error.rs`: `not_routed` 403, `too_many_questions` 403, `too_many_answers` 403, `question_settled` 409, `question_expired` 409, `push_unavailable` 409. `too_many_questions` is 403, not 429: the app holds every call to the relay after a 429 (contract relay-sync-v1 section 3), and a full question limit must not stop its sync.

### 25.5 Long polls, the notifier, and the question lane

- The team notifier of section 22 wakes on a post, an answer, a settle, an expiry, and a deletion by maintenance. A woken poll reads the file again and answers only when its condition holds; else it waits for the rest of its `wait` (it also reads again every 500 ms, so an expiry by the clock is seen without maintenance).
- `Core` gets `question_polls` and `answer_polls` (`LongPolls::new(1)` each, keyed by device id), apart from `sync_polls`. The three kinds of poll of one device do not take each other's place.
- The question lane (integrator decision 4 of the contract): the accept loop sends a `GET /v1/questions` or `GET /v1/questions/{qid}/answers` with a `wait` above 0 to its own lane of `Limits::question_long_polls` threads (128, not read from the environment). These threads are not counted in `max_active`, so question polls never take the member reserve of section 9 or the threads of sync and every member request. When the question lane is full, such a request runs in the member lane like any other and is answered at once, as with `wait=0`. The lane bounds the relay: about 64 active devices with both polls fill it, and then their polls return at once and the app asks again.
- A team's share of the lane: at most `Limits::question_long_polls_per_team` (32, not read from the environment) question polls of one team wait at once (`Core::question_lane`, taken after the token and the per-device poll). A poll over it is answered at once, as with `wait=0`, so one team cannot fill the lane for the others.
- Each turn of a long poll (at least every 500 ms) reads the device and its member again (`device_member`). A device or member revoked, or a role changed, since the request began: the poll ends with 401 `unauthenticated`, not with a list made for the old role.

### 25.6 Push

**Relay side** (`src/server/push.rs`). After the commit of `POST /v1/questions`, the handler reads the push tokens of the routing set (`failed_at IS NULL`) in the same transaction, and hands one job `{team, tokens with their device and environment, expires_at}` to the push thread through a bounded queue of 256 jobs. A full queue drops the job (row `push_dropped {}`, at most one per ten seconds per team). The request never waits for the push. The push thread, for each environment (`development` first), posts batches of at most 50 tokens (each token is one subrequest of the Worker):

```
POST <APASSY_RELAY_PUSH_URL>          (for example https://apassy-relay.wyderka.cc/internal/push)
X-Apassy-Push: <push secret>
Content-Type: application/json

{"tokens":["<hex>",...],"environment":"production","collapse_id":"apassy-question","expires_at":1790000300}
```

- The client is `ureq` (already a dependency, with rustls and the webpki roots), timeout 10 s for the whole call, no redirects, no retry: a push that fails is lost, and the question still waits on the asking Mac and in the list.
- The answer is `{"results":[{"token":"<hex>","status":200},{"token":"<hex>","status":410,"reason":"Unregistered"}]}`. A token with status 410, or 400 with reason `BadDeviceToken` or `DeviceTokenNotForTopic`, gets `failed_at = now` (only while the device still has that token) and is not used again until its device sends `PUT /v1/push/token`. Rows: `push_sent {count, environment}` per job and environment when at least one was sent; `push_failed {device_id, status, reason}` per token that APNs did not take, at most one per device and ten seconds; `push_failed {count, status, reason: "worker"}` when the Worker did not answer 200 with results (`status` 0: no answer), at most one per team and ten seconds.
- Config (`src/config.rs`): `APASSY_RELAY_PUSH_URL` (`https://`, or `http://` to a loopback address for tests), `APASSY_RELAY_PUSH_TOPIC` (the bundle id, `com.wydrox.apassy.companion`), and `APASSY_RELAY_PUSH_SECRET` or `APASSY_RELAY_PUSH_SECRET_FILE` (at least 32 bytes; the Worker's `PUSH_SECRET`). All three: push is on. None: push is off, the relay logs one line at start, no job is made, and `PUT /v1/push/token` is 409. Some but not all, or a value out of its form: the relay refuses to start (a configuration error), so a typo does not turn push off without a word.
- The push secret is its own secret (integrator decision 5), not the edge secret: the edge secret goes from the Worker to the relay only, and the push secret from the relay to the Worker only.

**Worker side** (`deploy/worker/src/apns.ts`, called from `src/index.ts`):

- Every path that is `/internal` or starts with `/internal/` (checked on the raw path and on the parsed one) goes to `handleInternal` and is never forwarded to the relay, rate-limited, or length-checked as a relay route.
- `POST /internal/push`, exact path and method. Any other method or path, a missing `PUSH_SECRET`, or an `X-Apassy-Push` header that is missing or not equal to `PUSH_SECRET`: 404 with the same plain-text body (`not found`), so a scan learns nothing. The secret is compared through the SHA-256 digests of both values, with a constant-time loop.
- The body is at most 64 KiB (a declared `Content-Length` above it, or more bytes read: 413), JSON, an object with exactly the four fields; `tokens` 1 to 50 entries of 32 to 200 lowercase hex characters; `environment` `development` or `production`; `collapse_id` 1 to 64 characters of `A-Za-z0-9._-`; `expires_at` a non-negative integer. Else 400 `invalid_request`. Then a Worker without `APNS_KEY`, `APNS_KEY_ID`, `APNS_TEAM_ID`, or `APNS_TOPIC`, or with a key that does not import: 503 `push_unavailable`.
- The APNs provider token: a JWT `{"alg":"ES256","kid":APNS_KEY_ID}.{"iss":APNS_TEAM_ID,"iat":<now>}` signed with the `.p8` key (`crypto.subtle.importKey("pkcs8", …, {name:"ECDSA", namedCurve:"P-256"})`, `sign({name:"ECDSA", hash:"SHA-256"})`, which gives the raw `r||s` form JWS needs). The Worker keeps it in a module variable with its inputs and makes a new one after 50 minutes or when the key, key id, or team id changes (Apple accepts a token for 60 minutes and refuses one renewed more often than every 20).
- For each token, in parallel: `POST https://api.push.apple.com/3/device/<token>` (`production`) or `https://api.sandbox.push.apple.com/3/device/<token>` (`development`) with `authorization: bearer <jwt>`, `apns-topic: APNS_TOPIC`, `apns-push-type: alert`, `apns-priority: 10`, `apns-expiration: <expires_at>`, `apns-collapse-id: <collapse_id>`, `content-type: application/json`, and the fixed payload:

```json
{"aps":{"alert":{"title":"Apassy","body":"A question is waiting"},"sound":"default","interruption-level":"time-sensitive"}}
```

- The answer is 200 `{"results":[...]}` in the order of `tokens`: each token with the APNs status and, for a status other than 200, the APNs `reason` when it is a word of 1 to 64 letters, else `Unknown`. A fetch that throws gives status 0, reason `Unreachable`. The Worker logs nothing (`observability.enabled: false` stays).
- Secrets and vars: `PUSH_SECRET` and `APNS_KEY` are Worker secrets (`wrangler secret put`, the values piped through Apassy, never typed or echoed); `APNS_KEY_ID` (set by the owner before the deploy), `APNS_TEAM_ID` (`7S3F9767BM`), and `APNS_TOPIC` (`com.wydrox.apassy.companion`) are vars in `wrangler.jsonc`. The key is never in git, on the VPS, or in a Docker image.
- The payload, the headers, and the collapse id are the same for every question: Apple learns that a device of this bundle gets a question at a time, nothing else.

### 25.7 The A4 spike and the fallback

APNs speaks HTTP/2 only. Before push goes live, a spike must show that a Worker's `fetch` reaches APNs: `deploy/worker/spike/` is a separate throwaway Worker (`apassy-apns-spike`, no route, no binding) that posts to `https://api.sandbox.push.apple.com/3/device/00` with an empty JSON body and no `authorization`. The owner runs it on Cloudflare's network with `npx wrangler dev --remote -c spike/wrangler.jsonc` and `curl -s http://127.0.0.1:8787/` (`deploy/worker/spike/README.md`); nothing is deployed. The expected answer is **403 with `{"reason":"MissingProviderToken"}`** (`"ok":true`). Any other result (a connection error, a protocol error, a 4xx without that reason) means the Worker cannot send, and push takes the fallback instead of `apns.ts`:

- The relay sends APNs itself from its push thread: `h2` with `tokio` (a current-thread runtime on the push thread only) and `tokio-rustls`, the same headers, payload, JWT rules (`ring` `ECDSA_P256_SHA256_FIXED_SIGNING`), and failure handling as 25.6. Not built.
- The `.p8` key is then a file on the VPS: `/opt/apassy/secrets/relay/apns_key.p8`, mode 0400, owned by the relay user, mounted read-only like the master key, named by `APASSY_RELAY_APNS_KEY_FILE`, with `APASSY_RELAY_APNS_KEY_ID`, `APASSY_RELAY_APNS_TEAM_ID`, and `APASSY_RELAY_PUSH_TOPIC`. This puts an Apple key on the VPS, which the plan avoids: it needs the owner's decision.
- The spike's result and the choice go in `docs/OPERATIONS.md` (section 19) with the deploy. Without push, questions still work: the devices find them by their long polls.

### 25.8 Maintenance and expiry

Every 5 seconds, per team (with the maintenance of 23.5 and 24.5), in two transactions: first the purge and the deletions, which write no row (so a Connect team at its file cap still frees their pages, section 26.4), then the expiries:

- open questions with `expires_at <= now` become `expired`, oldest `seq` first, each with `seq = ++team.question_seq` and a row `question_expired`;
- the purge: for each question settled with `settled_at <= now - 600`, or not settled with `expires_at <= now - 600`, its answers are deleted and its `ciphertext` becomes empty, `settle_nonce` and `settle_ciphertext` NULL (an empty card marks a purged question; a posted card is never empty). The row keeps `qid`, devices, `seq`, times, and state, so a repost of its `qid` is still 409 and the hourly limits still count it. No list shows it again: it is past its `expires_at`, and the app treats a question it does not see again as expired. No `seq` and no wake;
- questions with `created_at <= now - 86400` are deleted with their answers;
- one wake of the notifier when a question expired or was deleted;
- nothing else: push tokens stay until replaced, removed, or their device is revoked.

### 25.9 Audit

New actions, with device ids and counts only: no `qid`, no `key_id`, no nonce, no ciphertext, no push token, no bundle id, no secret.

| Action | Detail |
| --- | --- |
| `question_posted` | `{device_id, to_approvers, routed}` (`routed` = the size of the routing set) |
| `question_answered` | `{device_id, asker_device_id}` |
| `question_settled` | `{device_id}` |
| `question_expired` | `{device_id}` (the asker; actor `relay`) |
| `question_refused` | `{reason, device_id}`: `not_routed`, `too_many_questions`, `too_many_answers`, `settled`, `expired`, with the refused device; actor `edge` as other refusals, at most one row per reason and ten seconds (the first device of the ten seconds) |
| `push_token_set`, `push_token_removed` | `{device_id, environment}` / `{device_id}` |
| `push_sent` | `{count, environment}` |
| `push_failed` | `{device_id, status, reason}` with the APNs reason word, or `{count, status, reason: "worker"}` |
| `push_dropped` | `{}` |

`limit_reached` names `open_questions`, `questions_per_hour`, `member_open_questions`, `member_questions_per_hour`, `device_open_questions`, `device_questions_per_hour`, and `question_bytes`. The masks need no change: no new row holds a token form. The relay logs nothing of a question or a push; the one push line in the log is "push is off" at start.

### 25.10 Operator

`limits ID` reads and sets `--open-questions N`, `--member-open-questions N`, `--device-open-questions N` (1 to 1000), `--questions-per-hour N`, `--member-questions-per-hour N`, `--device-questions-per-hour N` (1 to 1000000), and `--question-bytes N` (1048576 to 268435456); the result prints sixteen effective values. `TeamLimits` gets the seven with `serde(default)`, so an existing `limits` column reads unchanged. The image before questions (`sync-*`) reads the column with `deny_unknown_fields`, so `TeamLimits::stored_json` writes these seven fields only when they differ from their default: with default question limits a rollback reads `relay.db` as it is, after any other change it needs the backup (docs/OPERATIONS.md 19.3). `teams` shows, for an open team, `open_questions` and `push_tokens` (counts). No command shows a question, an answer, or a token.

### 25.11 Tests

`tests/server_questions.rs`, unit tests in `src/server/questions.rs`, `src/server/push.rs`, `src/server/store.rs`, `src/server/http.rs`, `src/config.rs`, and `deploy/worker/test/apns.test.ts`:

- The contract's vectors: the relay accepts the vector `qid`, `key_id`, the three nonces, and the card, answer, and settle ciphertexts (1154, 386, 221 bytes) and returns them byte for byte; the card AAD built from the clear fields equals the contract's hex.
- Post, list, answer, read, settle: one asker and two devices of its member; both list the question, answer, and the asker reads both answers in order with the stamp; after the settle both see `settled` with the settle envelope and the next `seq`; a third answer is 409 `question_settled`; the same settle again answers the same, another is 409; a repost is 409 `conflict`.
- Routing: devices of other members get nothing in their list and 403 `not_routed` on an answer for `to: "member"`; with `to: "approvers"`, a manager's and an owner's devices list and answer (stamped `owner` and `manager`), a member's do not. The asking device does not see its own question and gets 403 on an answer. A device revoked after the post gets 401; a member whose role drops from manager stops seeing approvers' questions at once.
- Asker only: `GET …/answers` and `POST …/settle` from another device of the same member are 404; a member token is 401 on all seven routes.
- Limits and forms: the 11th open question of one device, the 16th of one member (from its second device), and the 21st of the team (from another member) are 403 `too_many_questions` naming `device_open_questions`, `member_open_questions`, and `open_questions`, with one `limit_reached` row each per ten seconds; the 26th in an hour (operator limit 25), then the hourly shares of a device and of a member are refused the same way; the 4th answer of one device and the 21st answer of a question are 403 `too_many_answers`; `to: "approvers"` without the flag is 403 `not_routed` (after a 400 for its forms) and stores nothing; a card of 32785, an answer of 8209 (also on an unknown `qid`: 413 before 404), and a settle of 1041 bytes are 413, and 32784, 8208, 1040 pass; `expires_at` of `now + 10` and `now + 650` are 400 (the exact bounds in a unit test); `v`, `qid`, `to`, `key_id`, `nonce`, an empty ciphertext, and an unknown field are 400; an answer or settle with another `key_id` is 400; the operator sets both limits and `teams` shows the counts.
- Expiry: a question past `expires_at` refuses answers and settles (409 `question_expired`) before maintenance; maintenance marks it `expired` with a new `seq`; after 24 hours every question and answer is gone (404), and a new question still gets a `seq` above every earlier one.
- Storage: with `question_bytes` 1 MiB, 31 full cards pass and the 32nd is 403 `too_many_questions` naming `question_bytes`; three full answers pass and a fourth is 403 `too_many_answers`; a settle still passes. Five minutes after the expiry the ciphertexts are still there; ten minutes after the end the file holds no ciphertext and no answer, no list shows the questions, the asker reads `settled` with no answers, a repost of a purged `qid` is 409, and a new card fits again.
- The request time: a post whose headers come 3 s before its body with `expires_at` 602 s after the headers passes, with `created_at` at least 3 s after them; an answer and a settle with a slow body are stamped with the time after the body.
- Default `TeamLimits` written by `stored_json` deserialize into the field list of the image before questions (embedded in a unit test, `deny_unknown_fields`); each question limit set away from its default is written and refused by it.
- Long polls: `wait=25` on the list returns on a post; on answers it returns on an answer and on an expiry; a second poll of the same device returns at once; a sync poll and a list poll of one device do not stop its answer poll from waiting. A list poll of a device revoked while it waits, a list poll of a manager made a member, and an answer poll of an asking device revoked while it waits all end with 401, not with the question or answer that comes next.
- The team's share: with `question_long_polls_per_team` 2, two polls of a team wait, a third poll of that team returns at once, a poll of another team still waits, and after the two end the team's polls wait again.
- The question lane: with `max_active` 2 and two question polls held, `GET /v1/me` still answers 200 and a third poll is answered at once; a version that counts question polls in `max_active` fails this test.
- Push: with a mock Worker, a post sends one call per environment with the tokens of the routing set only (not the asker's, not another member's, not failed ones), the push secret, the constant collapse id, and `expires_at`; a 410 result marks the token failed and the next post skips it; `PUT` clears it; revoking a device or a member removes its token; a Worker that does not answer delays no post. Without push config, `PUT /v1/push/token` is 409 and nothing is sent. Config: all three values or none.
- The Worker: `/internal/push` without the secret, with a wrong one, with another method, `/internal/x`, and `/internal/push/` are 404 with the same body and never reach the relay; a valid call with a mock `fetch` sends one APNs request per token with the headers and the payload above, to the sandbox host for `development`; the JWT has `kid`, `iss`, `iat`, verifies with the public key of a test key, is reused within 50 minutes and renewed after; 410 and `BadDeviceToken` come back in the results; malformed bodies are 400, large ones 413, a missing APNs config 503.
- Migration: a version 4 file opens as version 5 with `.pre-v5` next to it; a failed copy leaves version 4 without the new tables; the sync tables and rows are untouched; a version above the current one (now 7, 27.2) is refused.
- Separation: the access token of team A gets nothing of team B's questions and 404 for its `qid` on every question route; the same `qid` is free in another team.
- No audit row holds a `qid`, a `key_id`, a nonce, a ciphertext, a push token, the bundle id, or the push secret.

### 25.12 What this does not protect

- The relay sees the metadata: which device of which member posts and answers, when, how large each envelope is, the routing bit, and which devices have push tokens. The operator, root, a disk snapshot, and a backup hold the sealed envelopes until 10 minutes after the question ended (at most about 20 minutes after the post), and the metadata for 24 hours. `secure_delete` overwrites a dropped ciphertext in the file; a backup or a disk snapshot made before keeps it. Cloudflare sees the same.
- The relay can drop, delay, or reorder questions, answers, and pushes, and can lie about roles in its stamp (the contract's section 18 says what the app trusts it for). It cannot read an envelope or make an answer that counts.
- The push secret lets its holder ask the Worker to send the fixed notification to any token it knows. It gives no content and no access to a team. It is on the VPS (a file like the edge secret) and in the Worker.
- Apple sees each push: the device token, the bundle id, and the time.
- With the fallback of 25.7, the APNs key is on the VPS, and root on the VPS can send notifications as Apassy.
- A full question lane makes question polls return at once (the app asks again); it does not stop other requests.

## 26. Connect teams

**Status: built (stream S4, branch `feat/connect`), not deployed.** Contract (a) "Codeless Connect team" of the core's plan (`docs/product/sync-plans/build-plan.md`, ADR 0027, `docs/contracts/relay-connect-v1.md`). On the Free plan there is no account and no team code: the Mac app makes its own team on the first "Add a device…", so every device of the vault gets the questions of section 25 through the relay. A Connect team is an ordinary team of sections 22 and 23 (one file, the member `owner`, device keys, confirmed links with safety words) made without the operator's code of section 22. Only the Mac calls the endpoint; the iPhone never makes a team. Code: `Hub::create_connect_team` and `Hub::connect_sweep` (`src/server/hub.rs`), the in-memory guards in `src/server/connect.rs`, the directory functions in `src/server/directory.rs`, `ConnectCreate` and `TeamKind` in `src/api.rs`, `device::connect_message`, and `CONNECT_LIMITER` and `CONNECT_PREFIX_LIMITER` in `deploy/worker/src/index.ts`.

Anyone can call `POST /v1/connect`, and a Connect team then holds a token for the authenticated routes and the long polls. So every resource that a team can use has a bound of its own here: a count, a rate, or a cap of bytes. Nothing of the client's address is written to disk.

### 26.1 Words and limits

| Thing | Rule |
| --- | --- |
| Kind | `team.kind` in `relay.db`: `operator` (made with a team code, `apassy-relay init`, or `migrate`) or `connect` (made by `POST /v1/connect`). Fixed for the life of the team. The sign-in answer and `GET /v1/me` carry it as `team_kind` (26.6) |
| Owner | the member `owner` (role `owner`, kind `person`), with no member token; its device is the key holder, as in `POST /v1/teams` with a device key |
| Connect key | `sha256` of the 65 bytes of the device public key, in `connect_key`. One key makes at most one Connect team, ever: the row stays when its team is suspended or deleted. When the team is deleted, `connect_key.team_id` becomes NULL: the key stays used and names no team. A key of an operator team is not a Connect key |
| Proof of key | the body carries a signature of `device::connect_message` by the device key (26.3) |
| Daily cap | `APASSY_RELAY_CONNECT_TEAMS_PER_DAY` (section 6), default 50, 0 to 100000: the `connect_key` rows with `created_at` in the last 86400 seconds, for the whole relay. At the cap: 503 `busy` with `Retry-After: 3600`. `0` turns `POST /v1/connect` off (every call is 503) |
| Room | `APASSY_RELAY_CONNECT_TEAMS_MAX` (section 6), default 100, 0 to 1000000: the Connect teams in `relay.db`, active or suspended. At it: 503 `busy` ("no room") with `Retry-After: 3600`. A deleted team frees its place |
| Client prefix | at most 5 Connect teams per client prefix (IPv6 /48, IPv4 /24, from the Worker with its HMAC under the edge secret) in one UTC day, and never more than a tenth of the daily cap (at least 1). Counted in memory only (26.4). Over it: 429 `rate_limited` with `Retry-After` the seconds to the next UTC day |
| Limits | the preset `connect` of `TeamLimits` (26.4), written into the `limits` column when the team is made |
| File cap | the team file is capped at `question_bytes` + 8 MiB (26.4). Nothing is deleted to stay under it: at the cap, writes are 403 `team_limit` |
| Request rate | 300 authenticated requests a minute for each member the limits allow (26.4) |
| Devices | 10 live devices per member, as in every team (section 23.1) |
| Edge limits | `CONNECT_LIMITER` and `CONNECT_PREFIX_LIMITER` of the Worker (26.4) |

### 26.2 Directory version 1003

`Directory::open` moves a version 1002 file to 1003, and a 1001 file through 1002 to 1003, in one transaction; a failure leaves the file at its version and stops the start. The change is additive: no table is rebuilt, and every existing team becomes `operator`. New directories are made at 1003. Versions above 1003 are refused.

```sql
ALTER TABLE team ADD COLUMN kind TEXT NOT NULL DEFAULT 'operator' CHECK (kind IN ('operator','connect'));
ALTER TABLE team ADD COLUMN suspend_reason TEXT;   -- 'idle' when the sweep of 26.5 suspended the team
CREATE TABLE connect_key (
  key_hash BLOB PRIMARY KEY, team_id TEXT, created_at INTEGER NOT NULL);
CREATE INDEX connect_key_created ON connect_key(created_at);
PRAGMA user_version = 1003;
```

- `suspend_reason` is set by the sweep only. `admin suspend` sets it to NULL; `admin resume` clears it.
- `connect_key.team_id` names the live team the key made, for the operator; `admin delete` sets it to NULL in the transaction that removes the team row. No route reads it.
- The image before this section (directory 1002) refuses a 1003 file, and a Connect team's `limits` (`sync_bytes` 0, `items` 0, `agents` 0) are out of its ranges. A rollback to it restores `relay.db` from the backup made before the deploy (docs/OPERATIONS.md section 20.3). Team files do not change (schema 5).

### 26.3 `POST /v1/connect`

Edge only, like `POST /v1/teams`: a nonempty bearer token is 401 `unauthenticated` (section 23.5). The body is `ConnectCreate`:

```json
{"v": 1, "team": "Rafal", "device_name": "Rafal's MacBook Pro",
 "public_key": "<base64url of 65 bytes>", "signature": "<base64url of a DER signature>"}
```

`signature` is an ECDSA P-256 SHA-256 signature (ASN.1 DER, base64url without padding, at most 72 bytes) by the device key of these bytes (`device::connect_message`):

```text
"apassy-relay connect v1" 0x00 origin 0x00 public_key
```

`origin` is the relay URL the app is configured with, without a trailing slash (the relay uses its `APASSY_RELAY_PUBLIC_URL`), and `public_key` is the base64url text of the body's `public_key`, as sent. It is the form of the sign-in message (section 23.3) with its own domain, so neither signature can stand for the other, and a signature for one relay is worthless at another.

Checks, in this order; the first failure answers and nothing is stored:

1. The body: at most 64 KiB (413), JSON with exactly these five fields (400 `invalid_request`; an unknown field, such as a `code`, is 400 too).
2. `v` is 1; `team` is a team name (`checked_team_name`: 1 to 64 bytes after trimming, no control character); `device_name` is a device name (`checked_label`); `public_key` decodes to 65 bytes with the first byte 0x04 that are a point on P-256 (`device::decode_public_key`); `signature` decodes and verifies. Each: 400 `invalid_request`.
3. The client prefix (26.4), in memory: a prefix that made its teams of the UTC day is 429 `rate_limited` with `Retry-After` the seconds to the next UTC day, and a relay audit row `connect_refused {reason: "rate_limited"}`. The call reserves one team for its prefix; a failure in any later step gives it back.
4. A read of `relay.db`: the key hash is not in `connect_key` (409 `connect_key_used`, "This device key made a team before. Make a new device key."); fewer than `connect_teams_per_day` rows of `connect_key` are younger than 86400 seconds (503 `busy`, `Retry-After: 3600`, relay audit `connect_refused {reason: "busy"}`); fewer than `connect_teams_max` Connect teams exist (503 `busy` "no room", `Retry-After: 3600`, `connect_refused {reason: "full"}`).
5. The team file is made (section 22) with its team row, the member `owner`, its device (the key holder), and the team audit rows `host_bootstrap_ended`, `device_added`, and `team_created`. This is outside the lock of `relay.db`: its key derivation (PBKDF2) takes about 0.1 s, and other calls to the directory do not wait for it.
6. In one transaction of `relay.db`: the checks of step 4 again (another call may have used the key or the room meanwhile; the same answers and rows); the team row with `kind = 'connect'` and the `connect` limits; the `connect_key` row; the relay audit row `team_created {team_id, kind: "connect"}`. A failure removes the file of step 5, so a refused or failed call uses no key and counts for no cap.
7. The team is opened and served, with its file cap.

Each `connect_refused` row has actor `edge` and is written at most once per ten seconds for each reason; it holds the reason only.

The answer is `TeamCreated` with `kind`:

```json
{"ok": true, "result": {"team_id": "t_7k2m5q4x3c", "member_id": 1, "device_id": 1, "kind": "connect"}}
```

There is no secret in it: the device signs in (section 23.3) with its key and the `team_id`. `POST /v1/teams` is unchanged: its answer has no `kind`.

**A lost answer.** Save the original private key before sending. The old creation
proof still gets 409; recover with a fresh `POST /v1/connect/challenge` nonce and
`connect_recovery_message` signature as specified in section 28 and OPERATIONS 22.
Recovery returns only the original active identifiers; it never creates/resumes a
team, changes names, clears the key tombstone or issues an access token. Then use
the existing device sign-in challenge/token flow. A 404 challenge route means an
older server: keep the pending key for operator recovery, do not rotate it blindly.

**Enumeration.** No route lists, reads, or names Connect teams (`GET /v1/connect` and `GET /v1/teams` are 405). The only answer that depends on stored state before the team exists is the 409 for a key that made a team, which is the same for every such key and names no team; with the proof of key, only the holder of the private key can get it. A team id of a Connect team behaves as any team id (section 22: public, 401 for an unknown or suspended team).

### 26.4 Limits

**The Worker.** `POST /v1/connect` (exact method and path) passes two Workers Rate Limiting bindings, each with a key of its own, before it reaches the relay:

- `CONNECT_LIMITER` (namespace 1004), 1 request a minute, keyed by the `cf-connecting-ip` address for IPv4 and by the /64 of an IPv6 address (`2001:db8:1:2::/64`), because one client usually holds a whole /64;
- `CONNECT_PREFIX_LIMITER` (namespace 1005), 3 requests a minute, keyed by the coarse prefix: the /24 of an IPv4 address (`198.51.100.0/24`) and the /48 of an IPv6 address (`2001:db8:1::/48`). It is asked only when the first one lets the call pass.

The bindings count only per 10 or 60 seconds, so a daily limit cannot be set at the edge. Over either: 429 `rate_limited`, `Retry-After: 60`, and the relay never sees the call. Each fails open on its own when it is missing or fails. The Worker then sets `X-Apassy-Client-Prefix` to the coarse prefix on `POST /v1/connect` only (`unknown` when there is no `cf-connecting-ip`; text that is not an address stays as it is), and beside it `X-Apassy-Client-Prefix-Mac`: the lowercase hex of HMAC-SHA256 under the edge secret of `"apassy-relay client prefix v1" 0x00 prefix`. It removes any copy of either header that a client sent, on every route and on static files, as it does for the edge header. The body is bounded at 128 KiB before the limiters, as every JSON route (section 17). The Worker stores no address.

**The relay.** The Worker's limiters fail open and count per Cloudflare location, so the relay has bounds of its own:

- one team per key (26.3), the daily cap, and the room (26.1), in `relay.db`;
- the client prefix (`src/server/connect.rs`), in memory only. The relay reads `X-Apassy-Client-Prefix` on `POST /v1/connect` only, behind the edge secret, and takes it only when `X-Apassy-Client-Prefix-Mac` is its HMAC under the edge secret (`connect::verified_prefix`, compared in constant time with `ring::hmac::verify`). The edge secret alone does not prove the prefix: a Worker from before the HMAC forwarded a client's own `X-Apassy-Client-Prefix`. A request without the prefix, without a valid HMAC, or with more than 64 bytes counts as the one prefix `unknown`: without the new Worker every call shares one count. So **the daily cap stays 0 while any Worker older than the one with the HMAC is live, and the Worker is always deployed before the relay** (docs/OPERATIONS.md sections 20.2 and 20.3). The relay keeps no prefix: it keeps the HMAC-SHA256 of the prefix under a 32-byte salt from the system's random source, made at the first call of each UTC day and kept in memory only, and a count beside each hash. At the next UTC day the salt and every count go. A prefix makes at most `min(5, max(1, connect_teams_per_day / 10))` teams a day; a call is counted when it passes step 2 of 26.3, and its count is given back when it fails later. At most 65536 prefixes are counted in a day; a new one beyond that is 503 `busy` (`connect_refused {reason: "prefixes_full"}`). A restart forgets every count. No audit row, log line, or file holds a prefix or an address.

**The team.** `TeamLimits::connect()`:

| Field | Connect | Default |
| --- | --- | --- |
| `members` | 1 | 50 |
| `items` | 0 | 500 |
| `agents` | 0 | 100 |
| `sync_bytes` | 0 | 67108864 |
| `question_bytes` | 2097152 (2 MiB) | 8388608 |
| `feed_bytes` | 1048576 (1 MiB, section 27; not stored, 27.8) | 4194304 |
| every other field | the default | |

- `members` 1: `POST /v1/invites` is 403 `team_limit` (no join could use the invite), and so is a join of an invite made before. Devices of the owner come by device links with safety words (section 23.5), up to 10.
- `items` 0: `POST /v1/collections`, `PUT /v1/collections/{id}/policy`, and `POST /v1/grants` are 403 `team_limit`, before any row is written. A grant is refused only for `items` 0, in every team: a team of one member with items (a solo operator team) needs a grant for its owner to run anything (`decide`, `access`). Each refusal writes one `limit_reached` row at most every ten seconds for each limit, as every limit of section 22 does.
- `items` 0 and `agents` 0: no item, no agent, so no run, no session, and no use of the proxy of section 12 (403 `team_limit`). Without them a free team would be an open HTTP proxy with the relay's address. `GET /v1/host/requests?wait=S` of a team whose `agents` is 0 answers at once: no run can come.
- `sync_bytes` 0: no vault sync on the relay. `PUT /v1/sync/snapshot` answers 403 `plan_required` ("Vault sync through the relay is not in this team's plan.") after the headers (400) and the token (401), before the size checks of 24.3, with a refusal row `sync_refused {reason: "plan_required"}`. `POST /v1/sync/receipt` answers the same, even for version 0. `GET /v1/sync/head` answers at once, also with a `wait`: no new version can come. Snapshots that the team pushed while a plan allowed it can still be downloaded.
- `question_bytes` 2 MiB: about 60 full cards at once; the other question limits are the defaults of section 25.1.
- The ranges of section 22 change for three fields: `items` and `agents` are 0 to 1000000 (0: none), and `sync_bytes` is 0 or 1048576 to 67108864. Every other range is unchanged. The operator can set the limits of any team, Connect or operator, with `admin limits` (for example `--sync-bytes 67108864` lifts the sync limit of one team). A later entitlement (contract (c)) changes the same fields.

**Rows written only on a change.** `POST /v1/sync/receipt` writes `sync_received` only when the device's version changes, and `PUT /v1/push/token` writes `push_token_set` only when the token, the environment, or the bundle id changes; the same call again moves only the row's time. An expired or refused device link stays 7 days (a sign-in of its key reads `join_refused`), and at most 100 of them stay in a team; then the maintenance pass deletes the row. These hold for every team.

**The file cap.** A Connect team's file has `PRAGMA max_page_count` set from its limits (`TeamLimits::file_bytes`): `question_bytes` + `feed_bytes` (section 27) + 8 MiB, plus 16 KiB for each item and 1 MiB for each member beyond the first that a plan gives it (11 MiB, 2816 pages, for the preset; 10 MiB before section 27). It is set at each open and at each `admin limits`. A write past it is refused by SQLite and answered 403 `team_limit` ("The team's storage limit is reached."); the transaction rolls back. An operator team has no cap: the operator made it with a code and watches it.

No audit row is ever deleted to stay under the cap (owner decision, 2026-10-13): a Connect team at its cap gets 403 `team_limit` for every write that needs a new page, including the hourly `device_signed_in` row of a sign-in, until the operator raises its limits (`admin limits --question-bytes`, which raises the cap byte for byte) or deletes the team. The maintenance pass deletes old answers, cards, and questions (section 25.8) in a transaction of its own that writes no row, before the transaction that writes the `question_expired` rows, so a full team still frees those pages. The operator sees it:

- the maintenance pass (`audit::watch_cap`) logs `warning: the file of Connect team <id> is near its cap` at 90 % of the cap in use, and `... is full: its writes are refused with 403 team_limit` at 98 %, with the bytes, the cap, and the command that raises it; at most one line an hour for each team, unless the level rises. A sweep of a full team that fails with `team_limit` is not logged again;
- `admin teams` shows for each open team `file_bytes` (pages in use × 4096), `file_cap` (bytes, `null` without a cap), and `file_level`: `ok`, `near` (90 %), or `full` (98 %), `null` without a cap.

**Rows that outsiders cause.** A team id is public (it is in every device link code), so anyone can make a Connect team's relay write a refusal: a forged, expired, or revoked token with its id (`auth_failed`, section 23.5), `POST /v1/auth/token` with its id (`device_sign_in_refused`), a used invite (`invite_reused`), a join over its `members` limit, and a proxy request over its `agent_requests` before the session is checked (`limit_reached`). At one row per kind and ten seconds that is about 17 000 rows a day per kind, which without trimming would fill the file and block the team. So for a Connect team these rows never go into its file (`Core::outside_refusal`, `Core::outside_limit`): they go to the relay audit, actor `edge`, with the same action and detail plus `team_id`, at most one row per kind and ten seconds for all Connect teams together (kinds `connect_token`, `connect_device_sign_in`, `connect_invite_reused`, `connect_members`, `connect_agent_requests`), so the relay audit grows by at most 30 rows a minute (five kinds), however many teams are attacked. They are written with no lock of the team file held (`relay.db` is always locked first). Every other row of a Connect team comes from a request with a valid token of one of its devices (or from the operator, or from the relay's own sweeps of rows those requests made), and the team's 300 requests a minute bound them. An operator team keeps all of these rows in its own audit, as before.

**Opening a Connect team.** At each open, the cap is set (tried twice); a Connect team whose cap cannot be set is not served (logged; out of service like a team that fails to open), never served without a cap. Its connection also gets `PRAGMA cache_size = -64` (a page cache of 64 KiB, `connect::CACHE_KIB`) instead of SQLite's 2 MiB, so a room of 100 teams fits the production container (2 cores, 512 MiB); operator teams keep the default.

**Orphan files.** A Connect team's file is made before the `relay.db` transaction that adds its row (26.3 steps 5 and 6). A crash between them leaves a file whose key is nowhere. At start, before the teams open, the relay removes every `teams/<id>.db` of a well-formed id that no row of `relay.db` names, with its journal, `.pre-v*` copies, and snapshots (`remove_team_file`), and logs each one. Other names in `teams/` stay.

**The request rate.** A Connect team makes at most 300 authenticated requests a minute (fixed windows of the UTC minute) for each member its limits allow; over it 429 `rate_limited` with `Retry-After` the seconds to the next minute, and one `limit_reached {limit: "requests_per_minute"}` row at most every ten seconds. The count is in memory. Operator teams have no such rate. The sign-in routes (section 23) are not counted: they name a team in their body and have no token.

**Long polls.** All Connect teams together hold at most `Limits::connect_long_polls` long polls at once, in any lane: `GET /v1/questions`, `GET /v1/questions/{qid}/answers`, `GET /v1/sync/head`, `GET /v1/host/requests`, and `GET /v1/runs/{id}`. It is `APASSY_RELAY_CONNECT_LONG_POLLS` (section 6), default 96: the 128 threads of the question lane less one team's share of 32, so an operator team always finds its share of the lane, and well under the 224 threads of the member lane that are not the reserve. A Connect team's question polls also take at most 2 of the question lane (`connect::TEAM_QUESTION_POLLS`: its Mac and one other device; section 25.5), not 32. Its feed polls (`GET /v1/feed`, `GET /v1/feed/actions`, `GET /v1/feed/actions/{id}`) do not count in `connect_long_polls` or in the question lane: they run in the feed lane, at most 3 of one Connect team (`connect::TEAM_FEED_POLLS`) and at most `Limits::connect_feed_long_polls` (48) of all Connect teams together (section 27.7), so feed polls leave the question and answer polls of every team the capacity they had before section 27. A poll over a bound is answered at once, as with `wait=0`. So Connect teams can fill neither the member lane (256 threads) nor the question lane (128).

**A Connect team's question poll can return early.** `GET /v1/questions?wait=S` and `GET /v1/questions/{qid}/answers?wait=S` of a Connect team may answer at once with what there is (often nothing) although `S` is above 0: when the team holds its 2 seats, when all Connect teams hold their seats, or when the question lane is full. The answer looks like a poll that timed out. A client must not poll again at once: after an answer that came back sooner than it asked and brought nothing new, it waits before the next poll (for example 5 s, doubling to 60 s while that goes on, with some random jitter), and goes back to its normal long poll after an answer that waited or brought something. It also keeps one question poll per device: a second poll of the same device answers at once too (section 25.5).

**Push.** All Connect teams together have at most 128 jobs (half the queue) in the push queue of section 25.6, and one Connect team at most 2; more are dropped with a `push_dropped` row, as a full queue drops them. Operator teams always find room.

**Maintenance.** The five-second maintenance pass of every team runs on a thread of its own, not on the accept loop. A Connect team with no request since its last pass is passed over until 60 seconds went by; its expiries are read at request time too, so the pass only writes them down.

New error codes in `src/error.rs`: `plan_required` 403, `connect_key_used` 409, `rate_limited` 429.

### 26.5 Idle Connect teams

`apassy-relay admin connect-sweep [--idle-days N] [--delete-days N] [--dry-run]` (socket command `{"command":"connect_sweep","idle_days":30,"delete_days":30,"dry_run":false}`; both 1 to 3650, default 30). The relay does not run it by itself; the operator runs it, or schedules it (docs/OPERATIONS.md section 20.4).

1. Each active, open Connect team whose limits are exactly `TeamLimits::connect()`, that has no row in `sync_head`, and whose newest `last_seen_at` of its live devices (a device that never signed in counts with its `created_at`) is at least `idle_days` old is suspended as `admin suspend` does, with `suspend_reason = 'idle'` and the audit rows `team_suspended {reason: "idle"}` in the team and the relay audit (actor `operator`). The number of devices does not matter: a second device does not keep an idle team.
2. Each suspended Connect team with `suspend_reason = 'idle'`, limits exactly `TeamLimits::connect()`, and `suspended_at` at least `delete_days` old is deleted as `admin delete` does (file, snapshots, key in `relay.db`). Its `connect_key` row stays, with `team_id` NULL.
3. A team whose limits differ from the preset (a plan or the operator lifted them), a team with a sync head, an operator team, a team the operator suspended, and a team that did not open are never touched. A team suspended by this run is deleted by a later run. `--dry-run` changes nothing and names the same teams.

The answer is `{"dry_run": false, "suspended": [ids], "deleted": [ids], "failed": [{"team": id, "error": "..."}]}`. A suspended team's device gets 401 at sign-in (section 22); the app treats that as a team that is gone and connects again with a new key. The operator can `admin resume` an idle team during its suspension; that clears the reason.

### 26.6 The kind in answers

`AccessGranted` (`POST /v1/auth/token`) gains `team_kind` (`"operator"` or `"connect"`), and `GET /v1/me` gains `team_kind` for every token. The app uses it to tell a grandfathered operator vault from a Connect team (plan risk 8). Clients that do not know the field ignore it; the CLI reads it as optional.

### 26.7 Audit

Relay audit: `team_created {team_id, kind: "connect"}` (no key, no key hash, no device name, no address), `connect_refused {reason}` with the reason `busy` (daily cap), `full` (room), `rate_limited` (client prefix), or `prefixes_full` (actor `edge`, at most one per reason and ten seconds), and `team_suspended {team_id, reason: "idle"}` from the sweep. Relay audit, for Connect teams only: the rows that outsiders cause (26.4), actor `edge`, with `team_id`: `auth_failed {code, path_kind, team_id}`, `device_sign_in_refused {team_id}`, `invite_reused {invite_id, team_id}`, and `limit_reached {limit, team_id}` for `members` and `agent_requests`, at most one per kind and ten seconds for all Connect teams together. Team audit: the rows of a new team (section 23), `team_suspended {reason: "idle"}`, `sync_refused {reason: "plan_required"}`, and `limit_reached` for the refusals of 26.4 that its own devices cause (`members`, `items`, `requests_per_minute`). No audit row of any team is ever deleted. No row holds a public key, a prefix, or an address.

### 26.8 Tests

`tests/server_connect.rs`, unit tests in `src/server/connect.rs`, `src/server/directory.rs`, `src/server/push.rs`, `src/device.rs`, `src/config.rs`, `src/error.rs`, `src/server/http.rs`, `src/server/operator.rs`, `src/bin/apassy-relay.rs`, and `deploy/worker/test/index.test.ts`:

- Creation: the answer has `team_id`, `member_id`, `device_id`, `kind: "connect"`, and nothing else; the device signs in as `owner`, key holder, `team_kind: "connect"`; `admin teams` shows `kind` and the `connect` limits; the relay audit names the team and kind, never the key. Bad bodies (each field, a key off the curve, a bad or missing signature, an unknown field, a missing `v`) are 400 and make nothing; a bearer is 401; `GET /v1/connect`, `GET /v1/teams`, and `DELETE /v1/connect` are 405.
- Proof of key: a signature by another key, for another origin, of another key's message, or of a sign-in message is 400 and uses nothing; a trailing slash on the signed origin passes. A key off the curve is 400 on `/v1/connect`, `/v1/teams` (without using the code), and `/v1/devices/link`, and 401 at sign-in. Unit tests: the message has one form; a flipped bit of Y and 0x04 with 64 equal bytes are refused.
- One team per key: the same key, also with other names, and also after its team is deleted, is 409 `connect_key_used` with one body for every used key that names no team; the deleted team's `connect_key.team_id` is NULL. Eight concurrent calls with one key make one team and one file.
- The daily cap: with a cap of 2, the third call is 503 `busy` with one `Retry-After: 3600`, no file is made, one `connect_refused` row; a used key still gets 409; operator teams are not capped; a row older than 24 hours no longer counts; a cap of 0 refuses every call.
- The room: with a maximum of 2, the third call is 503 "no room" with `Retry-After: 3600` and one `connect_refused {reason: "full"}` row; operator teams do not count; a suspended team still counts; a deleted one frees its place; no file is left.
- The client prefix: five teams from one prefix, the sixth 429 with a `Retry-After` within a day; the refused key works from another prefix; calls without the header share one count; a bad body costs the prefix nothing; with a daily cap of 20 a prefix makes 2; the relay audit has `connect_refused {reason: "rate_limited"}` and no prefix. Unit tests: the share of the cap, a ticket not kept gives its count back (also across a day), a new salt and no counts at the next UTC day with only salted hashes kept, missing and long prefixes share one count, the table is bounded.
- `plan_required`: a valid first push of a Connect team's device is 403 `plan_required`, nothing is stored, the refusal row names it; without a token it is 401; after `admin limits --sync-bytes 67108864` the same push passes; `--sync-bytes 0` is accepted. A receipt with `sync_bytes` 0 is `plan_required`.
- The preset: an invite, a collection, a policy, a grant, and an agent are 403 `team_limit` naming the limit, with no row written but one `limit_reached` row per limit; after `admin limits --items 10 --members 3` a collection and an invite pass.
- Rows on a change: three equal receipts write one `sync_received` row; three equal push tokens write one `push_token_set` row, and a new environment or token one more each.
- Device links: 105 expired links leave the newest 100; a week after they ended, none.
- The file cap: a Connect team's file is capped at 2560 pages with a page cache of 64 KiB, an operator team's has neither; `admin teams` shows `file_bytes`, `file_cap`, and `file_level` (`null` for an operator team); `admin limits --items 10` adds 40 pages; at 92 % `watch_cap` answers `near` and `admin teams` says so; a full file answers a question post 403 `team_limit` and stores nothing; the maintenance pass then warns once (`full`), not again within the hour, deletes no audit row (the count and the last id stay), and still deletes a question of two days ago; after `admin limits --question-bytes 4194304` the same post passes and the level is `ok`. Unit tests: the levels at 90 % and 98 %, and when a warning is due (a rise at once, the same level once an hour, a fall never sooner).
- Outsiders: four kinds of forged tokens with a Connect team's id, sign-ins without a challenge and with a wrong signature, and proxy requests with a forged session key of the team add no row and no page to its file; the relay audit has `auth_failed` and `device_sign_in_refused` with the `team_id`, at most one per kind; the team's device still works; a forged token of an operator team still writes `auth_failed` into that team's audit.
- Orphans: at start a `teams/<id>.db` and its journal with no row in `relay.db` are removed; `notes.db`, `<id>.db.migrating`, and the files of known teams stay, and the known team still signs in.
- The prefix proof: a prefix without the HMAC, with the HMAC of another secret or another prefix, or with text that is not one counts as `unknown`; five such calls use up the count of `unknown`, and the same network with a valid HMAC has its own count. Unit tests: the vectors shared with the Worker's tests, upper-case hex, a flipped bit, a cut or non-hex value.
- Grants: an operator team with `members` 1 and `items` 5 grants its owner, makes an agent, and gets a run released to `ready`; with `items` 0 the grant is 403 `team_limit` (`tests/server_limits.rs`).
- The request rate: a Connect team gets 429 `rate_limited` with `Retry-After` 1 to 60 and one `limit_reached {limit: "requests_per_minute"}` row; an operator team is not limited. Unit test of the minute window.
- Long polls: a Connect team's `GET /v1/host/requests?wait=3` and `GET /v1/sync/head?wait=3` answer at once, an operator team's sync poll waits; with `connect_long_polls` 1, a second Connect team's question poll answers at once while the first holds the seat, an operator team's still waits, and the seat comes back; two devices of a Connect team hold their polls while a third device's answers at once. Unit test: `APASSY_RELAY_CONNECT_LONG_POLLS` is 0 to 1024, default 96, and the only limit read from the environment; the defaults of the caps are 50 and 100.
- Measurement (ignored, run by hand on the devbox, docs/OPERATIONS.md section 20.5): `measure_connect_teams` prints the memory and open files per Connect team and the start time.
- Push: unit test of the budget (2 jobs per Connect team, half the queue for all).
- Devices: a link with wrong words is 409 and the key gets `join_pending`; the right words add a device that signs in as `owner`, not the key holder; the 11th device's link is 409.
- Questions: the Mac posts, the linked iPhone lists, answers, and the Mac reads the answer stamped `owner` and settles; the 2 MiB budget refuses a card with `too_many_questions` naming `question_bytes` after about 60 full cards.
- Operator teams: `POST /v1/teams` answers without `kind`, default limits, `team_kind: "operator"`, a snapshot push passes, a used team code is still refused; the same key can still make a Connect team.
- Migration: a 1002 directory with an active team, a team with changed limits, and a suspended team opens as 1003 with every team `operator`, the same states and limits, working tokens and sign-ins; Connect works after it. Unit tests: 1001 and 1002 to 1003; a failed migration keeps the version; 1004 is refused.
- The sweep: idle Connect teams with one or two devices are suspended (and `--dry-run` only names them); a fresh one, an operator team, and one the operator suspended are untouched; 30 days after the suspension the idle teams are deleted and their keys stay used; a resumed idle team loses its reason; a team with lifted limits and a team with a sync head (back at the preset) are not swept.
- The Worker: `POST /v1/connect` uses `CONNECT_LIMITER` then `CONNECT_PREFIX_LIMITER` and no other limiter, keyed by the IPv4 address or the IPv6 /64, then by the /24 or /48 (several forms of one network give one key; malformed text and IPv4-mapped forms stay as they are); 429 with `Retry-After: 60` before the relay; each missing or failing binding passes; the relay gets exactly one `x-apassy-client-prefix` and one `x-apassy-client-prefix-mac`, the Worker's (fixed vectors), even when the client sent its own; other routes reach the relay without the client's copy of either; other methods and paths use neither binding; `/v1/teams` keeps the full address with `CREATE_LIMITER`; a body above 128 KiB is 413 before the limiters.

### 26.9 What this does not protect

- Anyone can make a Connect team. The bounds are one team per key and proof of that key, the relay-wide cap of a day and the room, the per-prefix count of the relay, and the Worker's limiters, which fail open and count per location. A caller with many keys and many /48 or /24 networks can still use the whole cap of a day, and then no one else can connect until the window moves (503 for everyone); filling the room takes `connect_teams_max / connect_teams_per_day` days (2 by default) and the operator sees it coming as `team_created` rows. The operator lowers or raises the caps, sets either to 0, and runs the sweep.
- The disk that Connect teams can take is bounded by `connect_teams_max` × the file cap (about 1 GiB at the defaults), plus the journal of one transaction per team and the relay audit's rate-limited refusals. An operator team's file has no cap.
- A Connect team that uses its file fully (many questions a day for months) reaches its cap and is refused until the operator raises it: no audit is trimmed. The operator sees it in the log and in `admin teams` (26.4).
- The rows that outsiders cause for Connect teams share one rate limit per kind in the relay audit: a flood against one team can hide a refusal of another team in the same ten seconds. They are refusals only; nothing is lost from any team.
- The per-prefix count is in memory: a restart starts it again, and with several relay processes each would count alone (there is one).
- Each Connect team costs a file, its open connection (with 64 KiB of page cache), and its key derivation at every start of the relay (about 0.1 s of one core each; see docs/OPERATIONS.md section 20.5, which also says how to measure it before raising the room).
- A Connect team is as separate from other teams as any team (section 22). The relay sees the same metadata as for any team; the questions stay sealed (section 25.12).
- The 409 tells the holder of a device key that it made a Connect team. A public key is not a secret, but the proof of key means only its holder gets this answer, and it names no team.
- An account or an entitlement never adds a device: a device of a Connect team is the one that made it or one confirmed with safety words by a device of the owner (section 23).

## 27. The feed of a Mac

**Status: built (branch `feat/feed`), not deployed.** Contract `docs/contracts/relay-feed-v1.md` of the core (section D of the stage 5 plan, "The Mac feed"). Each Mac of a vault keeps one sealed **feed** of its agents on the relay; the other live devices of the same member (the iPhones) read it and send one kind of sealed **action** back to that Mac, which settles it once. The relay never opens a feed, an action, or a settle: they are ChaCha20-Poly1305 envelopes under the question key of the vault (contract sections 5 and 6), which never reaches the relay. It checks forms, sizes, routing, and limits, stamps the sender, and stores every envelope byte for byte. Both documents describe one wire; this section takes precedence for the relay, and the plaintexts, the action string, the signatures, and the target's checks are in the contract only. Code: `src/server/feed.rs` (routes, routing, limits, the feed read budget, the held-back audit rows, maintenance), `src/server/store.rs` (schema 6), `src/server/directory.rs` (`feed_bytes`, `feed_actions_per_hour`), `src/server/http.rs` (routes, the body cap, the feed lane), `src/server/rollback.rs` (`apassy-relay rollback-check`), `deploy/worker/src/index.ts` (the edge body cap).

### 27.1 Words and limits

| Thing | Rule |
| --- | --- |
| Feed | one sealed envelope of one device: `seq`, `key_id`, `nonce`, `ciphertext`, at most one per device (`feed.device_id` is the key), replaced whole by each `PUT` |
| `seq` | a JSON number from 1 to 2^53 − 1, chosen by the publisher, above the stored `seq` of the device (409 `seq_not_newer` otherwise). The relay stores and returns it as given: the feed's AAD binds it |
| Feed counter | `team.feed_change`, a counter of the team that only grows: each accepted feed takes the next value (`feed.change_seq`, `change` on the wire), and so does each deletion of one or more feeds. Readers poll with it. It is not `seq` |
| Action | one sealed envelope of one sending device to one target device: `action_id`, `to_device`, `key_id`, `nonce`, `ciphertext`; a state `open`, `settled`, or `expired`; stamped with the sender's device and member |
| `action_id` | the form of a `qid` (25.1): 22 base64url characters of 16 bytes, made by the sender, unique in the team (409 `conflict`). In a path, out of its form: 400 |
| Action sequence | `team.feed_action_seq`: an action takes the next value when it is posted (`feed_action.seq`). Targets poll with it |
| Settle | the clear `outcome` (`applied`, `refused`, or `stale`) and one sealed envelope of the target. Its `key_id` is any 16-hex form: a target that cannot open an action settles it under its current key (contract 9.5) |
| `key_id`, `nonce`, `v` | as 25.1: 16 lowercase hex characters, base64url of 12 bytes, `v` 1 in every body |
| Ciphertext | base64url, not empty (400); a feed at most 262144 bytes, an action at most 4112, a settle at most 1040 (decoded); over: 413 `payload_too_large` |
| Body of `PUT /v1/feed` | at most 360448 bytes (352 KiB: the base64url of a 256 KiB feed is 349526 characters), with `Content-Length` and without `Transfer-Encoding` (400 otherwise), checked from the headers before the token; over: 413. Every other body keeps 64 KiB (section 9) |
| Pace | one accepted feed per device per 10 s on the relay clock (`feed.updated_at`, and in memory `Core::feed_times`, so a `DELETE` does not lift it); sooner: 403 `feed_limit` |
| `feed_bytes` | per team, default 4194304 (4 MiB), 1048576 to 67108864; 1048576 (1 MiB) in the `connect` preset: the bytes of feed ciphertext that the team file holds at once. A feed whose ciphertext, with every other device's feed (not the caller's own old one), would pass it: 403 `feed_limit`. Its own budget: it never counts in `question_bytes`, and questions never count in it |
| Member share | one member's feeds and actions stay within `feed::member_share` of each team limit: three quarters of it (`limit − ⌊limit/4⌋`, as the question limits of a member are 15 of 20 and 225 of 300), so one member at its share leaves the rest to the others: `member_feed_bytes` (3 MiB of 4 MiB; 768 KiB of 1 MiB), `member_feed_actions_per_hour` (45 of 60), `member_open_feed_actions` (15 of 20). A team whose `members` limit is 1 (the `connect` preset) gives its member the whole limit. Derived, not stored: no new field in `relay.db`. At the defaults a member's 10 devices (10 × 256 KiB) fit in its share of `feed_bytes`. Over: 403 `feed_limit` or `too_many_actions` naming the share |
| `feed_actions_per_hour` | per team, default 60, 1 to 1000000: actions with `created_at` in the last 3600 seconds (purged ones count until they are deleted). Over: 403 `too_many_actions` |
| Open actions | 20 of the team, 15 of one member (the member share), and 10 of one sending device, fixed (state `open`, `expires_at > now`). Over: 403 `too_many_actions` |
| Action lifetime | `expires_at = created_at + 300`. An `open` action with `expires_at <= now` is `expired` at once in every answer and check. The target's 60 s window of the action's `time` is the app's (contract 9.4) |
| Answers | a feed list stops adding feeds once the base64url ciphertexts of its answer reach 1 MiB (it always adds one) and sets `more: true`; an action list holds at most 20 |
| Feed reads | the base64url ciphertext text that `GET /v1/feed` gives one device: at most `feed::FEED_READ_TEXT_PER_MINUTE` (16 MiB) in one minute of the relay clock, with at most `feed::FEED_READS_IN_FLIGHT` (2: its long poll and one more) reads of the device at once (`Core::feed_reads`, in memory). Each read reserves `feed::FEED_READ_RESERVE` (1 MiB plus one whole feed: the most one page gives) before it reads, and gives back what it did not use when it ends, so reads in parallel cannot pass the budget. A read whose reserve does not fit, or a third read in flight, is 403 `feed_rate` (no audit row), before any read of the file. An empty answer costs nothing once it ends. A correct reader gets each feed once per change, so 16 MiB is about eleven reads of a whole member at the largest feeds, and a Mac publishes at most every 10 s. The count is of what the relay sent, not of what reached the device: a poll that the app cancelled counts too |
| Feed long polls | 1 per device for the feed list (`feed_polls`), 1 for the action list (`feed_action_polls`), 1 for an action status (`feed_status_polls`), each `LongPolls::new(1)`, apart from the question and sync polls; `wait` 0 to 25; in the feed lane, apart from the question lane (27.7) |
| Purge | 10 minutes after an action was settled or expired, maintenance empties its `nonce` and `ciphertext` and drops its settle envelope; it is then unknown (404) on every route, and its `action_id` stays taken |
| Retention | an action is deleted 24 hours after `created_at`; a feed 30 days after `updated_at`, by `DELETE /v1/feed`, and at the revocation of its device or member |
| Start and delete rows | at most one `feed_started` or `feed_deleted` (of a device's own `DELETE`) per device and hour (`feed::FEED_AUDIT_SECS`, in memory: `Core::feed_audit`), so a loop of `PUT` and `DELETE` cannot grow a Connect team's audit, which is never trimmed. A change within the hour of the device's last row is held back; once the hour has passed, maintenance writes a row of the state the feed is in then, when it is not what the last row says (27.9). So the last row of a device says where its feed is, at most an hour late |
| Auth | an access token of a live device (`Need::Member`, then `MemberAuth.device`, as 25.1). A member token is 401 `unauthenticated` on every feed route |

### 27.2 Schema version 6 (team file)

`Store::open_team` migrates a version 5 file to version 6 with the copy rule of 23.2: copy to `<file>.pre-v6` (mode 0600, written as `.pre-v6.tmp`, synced, renamed; refuse to migrate when the copy cannot be made: the team stays at version 5 and does not open), then in one `BEGIN IMMEDIATE` transaction run the statements below and set `PRAGMA user_version = 6` (`migrate_v6`). The change is additive: no table is rebuilt, and the question, sync, push, and device rows are untouched. A version 2 to 4 file goes on to 6 in one start, with each copy. A new team file is made at version 6. Version 1 and versions above 6 are refused, and the version 5 image refuses a version 6 file (its `open_team` accepts 3 to 5 only). `relay.db` does not change version (1003). `remove_team_file` also removes `.pre-v6` and `.pre-v6.tmp`.

```sql
ALTER TABLE team ADD COLUMN feed_change INTEGER NOT NULL DEFAULT 0;
ALTER TABLE team ADD COLUMN feed_action_seq INTEGER NOT NULL DEFAULT 0;
CREATE TABLE feed (
  device_id INTEGER PRIMARY KEY REFERENCES device(id),
  member_id INTEGER NOT NULL REFERENCES member(id),
  seq INTEGER NOT NULL CHECK (seq >= 1),
  key_id TEXT NOT NULL, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL,
  change_seq INTEGER NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
CREATE INDEX feed_change ON feed(change_seq);
CREATE TABLE feed_action (
  action_id TEXT PRIMARY KEY,
  seq INTEGER NOT NULL,
  from_device INTEGER NOT NULL REFERENCES device(id),
  to_device INTEGER NOT NULL REFERENCES device(id),
  member_id INTEGER NOT NULL REFERENCES member(id),
  key_id TEXT NOT NULL, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL,
  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('open','settled','expired')),
  outcome TEXT CHECK (outcome IN ('applied','refused','stale')),
  settled_at INTEGER, settle_key_id TEXT, settle_nonce BLOB, settle_ciphertext BLOB);
CREATE INDEX feed_action_to ON feed_action(to_device, seq);
CREATE INDEX feed_action_created ON feed_action(created_at);
```

`feed.change_seq` is the `change` of the wire (the column avoids the word). `feed.created_at` is the time of the device's first feed since its last deletion; a replacement keeps it.

### 27.3 Routing

Same-member routing, read from the file at each request and at each turn of a long poll: the live devices (not revoked, member not revoked) of the caller's member.

- A device lists the feeds of the live devices of its own member, its own included, and `present` names every one of them that has a feed now. Other members' devices never see a feed, its `change`, or that it exists; the top-level `change` is the team's counter, as the question sequence is (25.12).
- An action goes to a live device of the caller's member that is not the caller (403 `not_routed` otherwise, also for an unknown id). The target must have a feed (404 `not_found`).
- Only the target lists and settles an action; only the sender reads its status. Any other device gets nothing in its list and 404 on the action's routes, as an unknown `action_id`.
- There is no `approvers` routing: a feed holds one member's agents.

### 27.4 Endpoints

Routes: `["v1","feed"]` PUT, GET, DELETE; `["v1","feed","actions"]` POST, GET; `["v1","feed","actions",id]` GET; `["v1","feed","actions",id,"settle"]` POST. `Need::Member` for all, then the handler requires `MemberAuth.device`. A POST or PUT reads the token again after its body (23.5), and its request time is taken after the body (25.4). A request without a valid token is 401 before its body is read, as everywhere; `PUT /v1/feed` checks its `Content-Length` and `Transfer-Encoding` before that (400, then 413), as a snapshot push does.

| Method and path | Auth | Body | Result |
| --- | --- | --- | --- |
| `PUT /v1/feed` | device | `FeedPut {v, seq, key_id, nonce, ciphertext}` | `{device_id, seq, change, updated_at}`. 400 (headers, then shape and forms) → 413 → 401 → in one transaction: 409 `seq_not_newer` (a `seq` at or below the stored one; before the pace, so a retry of a feed that landed gets 409) → 403 `feed_limit` (the pace, then `feed_bytes`, then `member_feed_bytes`, each limit with a `limit_reached` row) → the caller's row replaced, `change = ++team.feed_change`, `feed_started` only when the device had no feed (held back within the hour of its last row, 27.1). The notifier wakes the polls. |
| `GET /v1/feed?since=N&wait=S` | device | | `FeedList {change, more, present, feeds: [FeedView]}`: the member's feeds with `change > since`, oldest `change` first, paged at 1 MiB of ciphertext text (27.1). `FeedView` = `{device_id, device_name, seq, change, key_id, nonce, ciphertext, updated_at}` (`device_name` for a log only). `wait`: while there is no such feed, hold; a feed of the member that leaves (`present` changes) or a top-level `change` below `since` (a restored relay) answers at once. A read whose reserve does not fit in the device's 16 MiB of this minute, or a third read of the device in flight (27.1): 403 `feed_rate`, after the 400 of the query and the 401 of the token; the message names the time of the next minute. |
| `DELETE /v1/feed` | device | | `{device_id, change}`; removes the caller's feed with `change = ++team.feed_change` and a `feed_deleted {device_id, reason: "deleted"}` row (held back within the hour of its last row, 27.1); the open actions to the device expire. No feed: the same answer with the counter as it is, and no row. No pace of its own: a delete with a feed follows a paced `PUT`, and one without writes nothing. |
| `POST /v1/feed/actions` | device | `ActionPost {v, action_id, to_device, key_id, nonce, ciphertext}` | `{action_id, seq, created_at, expires_at}`. 400 → 413 → 401 → in one transaction: 403 `not_routed` → 404 (the target has no feed) → 409 `conflict` (the `action_id` exists in the team, also purged) → 403 `too_many_actions` (`feed_actions_per_hour`, then 20 open of the team, then the member's shares `member_feed_actions_per_hour` and `member_open_feed_actions`, then 10 open of the sender, each with a `limit_reached` row) → the row with the caller's device and member, `seq = ++team.feed_action_seq`, `expires_at = now + 300`, `feed_action_posted`. The notifier wakes the target's poll. |
| `GET /v1/feed/actions?after=N&wait=S` | the target | | `ActionList {seq, actions: [ActionView]}`: the open actions to the caller with `seq > after`, oldest first, at most 20. `ActionView` = `{action_id, seq, from_device_id, key_id, nonce, ciphertext, created_at, expires_at}`. `wait`: while there is none, hold; a top-level `seq` below `after` answers at once. |
| `POST /v1/feed/actions/{id}/settle` | the target | `ActionSettle {v, outcome, key_id, nonce, ciphertext}` | `{action_id, state: "settled", outcome, settled_at}`. 400 → 413 → 404 (another device, an unknown or purged `id`). A settled action: the same outcome and envelope again answer the same (a retry, also after `expires_at`); another body is 409 `action_settled`. An expired one (state at now): 409 `action_expired`. Row `feed_action_settled`; the notifier wakes the sender's poll. |
| `GET /v1/feed/actions/{id}?wait=S` | the sender | | `ActionStatus {action_id, to_device, state, created_at, expires_at}`, plus `outcome`, `settled_at`, and `settle {key_id, nonce, ciphertext}` when settled. 404 for another device or a purged action. `wait`: while it is `open`, hold. |

New error codes in `src/error.rs`: `feed_limit` 403, `feed_rate` 403, `too_many_actions` 403, `seq_not_newer` 409, `action_settled` 409, `action_expired` 409 (`not_routed` 403 is 25.4's). `feed_limit`, `feed_rate`, and `too_many_actions` are 403, not 429: the app holds every call to a relay after a 429 (relay-sync-v1 section 3), and these concern one device's feed only, so its question answers and syncs go on.

### 27.5 Revocation

Revoking a device (`DELETE /v1/devices/{id}`) or a member (`DELETE /v1/members/{id}`, `POST /v1/leave`) deletes the feeds of the removed devices in the same transaction, with one new feed counter value and a `feed_deleted {device_id, reason: "device_revoked" | "member_revoked"}` row each, and expires the open actions to them and from them (`expires_at` set to now). So a reader sees the device leave `present` at its next answer, and a revoked device's poll ends with 401 at its next turn.

### 27.6 Maintenance

Every 5 seconds, per team, after the sweeps of 25.8, in one transaction that writes no audit row (so a Connect team at its file cap still frees the pages; it also runs when an earlier sweep of the pass failed):

- open actions with `expires_at <= now` become `expired` (no row, no sequence value);
- the purge: an action settled with `settled_at <= now - 600`, or not settled with `expires_at <= now - 600`, gets an empty `nonce` and `ciphertext` and a NULL settle envelope; the row keeps its ids, times, state, and outcome until it is deleted, so its `action_id` stays taken and `feed_actions_per_hour` still counts it;
- actions with `created_at <= now - 86400` are deleted;
- feeds with `updated_at <= now - 30 days` are deleted with one new feed counter value, and the open actions to their devices expire;
- one wake of the notifier when an action expired or a feed went.

### 27.7 Long polls and the lane

- `GET /v1/feed`, `GET /v1/feed/actions`, and `GET /v1/feed/actions/{id}` with a `wait` above 0 are feed-lane polls (`http::poll_kind` = `PollKind::Feed`): they run on threads of their own, at most `Limits::feed_long_polls` (64) for the relay, apart from `max_active` and from the 128 threads of the question lane (25.5), and in the member lane, answered at once, when it is full. So feed polls never take a thread, a team seat, or a Connect seat of a question or answer poll: those keep the capacity they had before this section (128 threads, 32 of one team, 2 of a Connect team, `connect_long_polls` of all Connect teams).
- Each team has a share of the feed lane (`Core::feed_lane`): an operator team `Limits::feed_long_polls_per_team` (16), a Connect team `connect::TEAM_FEED_POLLS` (3). Within it: list polls hold at most half of the share and status polls at most a quarter, each at least one seat (`feed::kind_seats`, `Core::feed_lists`, `Core::feed_statuses`: 8 and 4 of 16, 1 and 1 of a Connect team's 3), so they leave seats to the Macs' action polls (`GET /v1/feed/actions`, any free seat) and a status poll never waits behind a list poll; and the polls of one member hold at most the share less one seat for each other member that has a feed (`feed::member_seats`, `Core::feed_members`, at least one), so one member's devices leave a seat to each other member's Mac. A Connect team has one member: its 3 seats are one list poll, one status poll, and the Mac's action poll.
- All Connect teams together hold at most `Limits::connect_feed_long_polls` (48) feed polls (`Core::feed_poll_seat`): the feed lane less one operator team's share, as `connect_long_polls` is for the question lane (26.4). They do not count in `connect_long_polls`.
- A Connect team's feed poll can return early with nothing new, and the app backs off as for questions (contract 10.10).
- A poll over a bound, or a second poll of one kind of one device, is answered at once, as with `wait=0`. Each turn (at least every 500 ms) reads the caller again: a device or member revoked since the request began ends the poll with 401. A role change does not: feeds route by member only.
- Threads: the relay may run 256 request threads, 128 question polls, and 64 feed polls at once. tiny_http 0.12 also keeps one pool thread per open connection, for the whole request and while a keep-alive connection is idle, so each request in flight costs two tasks: about 2 × 448 + 8 ≈ 904 at the limits, plus idle connections (`pids_limit` 2048 in `deploy/vps/compose.yaml`; memory is the real bound, docs/OPERATIONS.md 20.5). When tiny_http cannot start a thread its accept thread ends and the listener closes; `http::serve` probes the listener every 10 s (`listener_alive`) and returns an error after three failed probes or an accept error, and `apassy-relay serve` then exits 1, so the container restarts.

### 27.8 Limits in `relay.db`

`TeamLimits` gets `feed_bytes` and `feed_actions_per_hour` (18 fields). The version 5 image reads the `limits` column with `deny_unknown_fields`, so `TeamLimits::stored_json(kind)` leaves each of the two out while it equals the preset of the team's kind (`TeamLimits::for_kind`: 4 MiB and 60 for an operator team, 1 MiB and 60 for a Connect team), and `TeamLimits::from_stored(text, kind)` fills a missing one from that preset. So the `connect` preset's 1 MiB is never stored, every column written by the version 5 image reads as before, and with the two limits at their preset a rollback reads `relay.db` as it is. A value set away from the preset is stored, and then the version 5 image refuses the column (docs/OPERATIONS.md 21.3).

A Connect team's file cap (26.4) grows by its `feed_bytes`: `question_bytes` + `feed_bytes` + 8 MiB, plus the room for items and members (11 MiB, 2816 pages, at the preset).

### 27.9 Audit

No row per feed update (a Mac publishes up to every 10 s, and a Connect team never deletes audit rows), and no row for an expiry or a purge. Rows have device ids and the clear outcome only: no `seq`, `key_id`, nonce, ciphertext, or `action_id`.

| Action | Detail |
| --- | --- |
| `feed_started` | `{device_id}`: the first feed of a device (again after a deletion); held back within the hour of the device's last row (27.1) |
| `feed_deleted` | `{device_id, reason}`: `deleted` (held back within the hour of the device's last row), `device_revoked`, or `member_revoked` (always); not written for the 30-day retention, whose transaction writes no row |
| `feed_action_posted` | `{device_id, to_device_id}` |
| `feed_action_settled` | `{device_id, from_device_id, outcome}` |

`limit_reached` (section 22) names `feed_bytes`, `member_feed_bytes`, `feed_actions_per_hour`, `open_feed_actions`, `member_feed_actions_per_hour`, `member_open_feed_actions`, and `device_open_feed_actions`, at most one row per kind and hour for the team (`feed::FEED_LIMIT_ROW_SECS`, `Core::limit_error_every`), not per ten seconds as other kinds: a device that keeps posting at a limit would write 360 rows an hour, and a Connect team never trims its audit. The 10 s pace and the feed read budget write no row: they are paces of one device, which a correct device never meets. For the same reason a loop of `PUT` and `DELETE /v1/feed` writes at most one `feed_started` or `feed_deleted` per device and hour (`feed::FEED_AUDIT_SECS`); a change within the hour is held back, and the feed maintenance writes, once the hour has passed, a row of the state the feed is in then when the last row says the other one (`audit_catch_up`, actor the device's member, in its own transaction after the one of 27.6, so a Connect team at its file cap tries again at the next pass; a revoked device has its revocation row and gets none). The hold is in memory: a restart forgets it, and the next change writes its row at once.

### 27.10 Operator

`admin limits ID` reads and sets `--feed-bytes N` (1048576 to 67108864) and `--feed-actions-per-hour N` (1 to 1000000); the result prints eighteen effective values. The member shares (27.1) follow from them and are not set apart. No command shows a feed or an action.

- `apassy-relay rollback-check` (`src/server/rollback.rs`): not an `admin` command, so it needs no running relay. It reads `relay.db` with the master key (`APASSY_RELAY_KEY_FILE`, as `serve`) and each team file and its `.pre-v6` copy with the file's key, all with `Store::open_read_only`: it writes nothing and takes no lock of the relay (`relay.lock`), but its reads take SQLite's shared locks for a moment, and a write of the relay waits for them (up to 5 s, rusqlite's busy timeout). It runs in the container of the new image with the relay up (`docker compose exec`, where it shares the CPU quota: about two key derivations per team) or stopped (`docker compose run`). It derives the file keys on up to 8 threads, no more than the cores; a thread that panics leaves an `error` for each of its teams, and the answer has one entry per team of the directory or the command fails. For every team it prints `{team, kind, state, schema, pre_v6, revocations, changes, audit_rows_lost, audit_lost, access_rows_lost, feed_limits_stored, clean}`. With a `.pre-v6` copy it compares the file with the copy: `revocations` names each device, member, agent token, access grant, and invite that is revoked in the file and live in the copy `{kind, id, revoked_at}` (oldest first); `changes` names, `{kind, id}`, each member whose role changed (`member_role`), each member token that ended since (`member_token`, a device enrollment ends it), each collection whose policy changed (`collection_policy`), each device whose key-holder flag changed (`key_holder`), each item archived since (`item_archived`: live again for its grants after a rollback), each invite used since (`invite_used`: usable again), and each agent bound to a device since (`agent_device`: unbound again, so a later revocation of the device does not revoke it); `audit_lost` counts the audit rows that the copy lacks, by action, and `access_rows_lost` names those of them that record a change of access (`device_revoked`, `member_revoked`, `agent_revoked`, `grant_revoked`, `member_role_changed`, `policy_changed`, `item_archived`, `key_holder_moved`, `key_holder_claimed`, `member_enrolled`), as a net for what the comparison does not see. Rows that only the file has are left out of `revocations` and `changes`: they go with the rollback. `feed_limits_stored` is true when the team's limits column in `relay.db` holds a feed limit (`TeamLimits::stored_json`), which the schema 5 image refuses for the whole directory. `pre_v6: false` with `schema: 6` is a team made after the migration; with a schema below 6, a team suspended through the migration and left as it is (the relay does not open suspended teams at start). A team is `clean` when it has nothing in `revocations`, `changes`, or `access_rows_lost`, no stored feed limit, no `error`, and a copy or a schema below 6; the command exits 1 when any team is not clean, 0 otherwise, and 1 also when `relay.db` cannot be read. It names kinds, ids, times, and audit action names only: no name, token, policy, or audit detail.
- `admin delete ID --free-connect-key` (a suspended Connect team only; 400 for an operator team): deletes the team as `admin delete` does, and in the same transaction of `relay.db` replaces the hash of its `connect_key` row with random bytes, so the device key that made the team can make a new one (`POST /v1/connect` no longer answers 409 `connect_key_used`); the row stays for the daily cap. The answer has `"connect_key": "freed"`, or `"none"` when the team had no `connect_key` row; the `team_deleted` row of the relay audit has `connect_key_freed` with the same truth. Without the flag the key stays used, as 26.2 says.

### 27.11 The Worker

`PUT /v1/feed` (exact method and path) may declare up to 360448 bytes (`MAX_FEED_LENGTH`, the relay's own limit, no margin), and must declare its length without `Transfer-Encoding` (400 `invalid_request` otherwise); above it 413 `payload_too_large`. Every other route keeps its cap of section 17 (`PUT /v1/feed/`, `POST /v1/feed`, and the action routes included: 128 KiB). The Worker has no limiter for the feed routes and forwards them as any route. An older Worker answers a feed body over 128 KiB with 413, and the app then fits its feed to 96 KiB of plaintext (contract 14.2).

### 27.12 Tests

`tests/server_feed.rs`, unit tests in `src/server/feed.rs`, `src/server/store.rs`, `src/server/directory.rs`, `src/server/http.rs`, `src/error.rs`, `src/bin/apassy-relay.rs`, and `deploy/worker/test/index.test.ts`:

- The contract's vectors: the relay accepts the vector `action_id`, `key_id`, the three nonces, and the feed, action, and settle ciphertexts (943, 435, 130 bytes), with the Mac as device 2 and the iPhone as device 3; it returns them byte for byte and stores them as given; the feed, action, and settle AADs built from the clear values that the relay returns (`device_id`, `seq`, `key_id`, the stamped `from_device_id`, the target's id, `action_id`, `outcome`) with the vector team id equal the contract's hex (62, 78, 82 bytes); the sizes of contract 6.3.
- Publish and read: every device of the member reads the feed, the publisher too; `present`, `change`, and `more`; a second device's feed takes the next counter value; a new feed replaces the old one (one row).
- Routing: another member's devices see only their own member's feeds, get 403 `not_routed` for an action to the first member's devices, and 404 for its actions; an action to oneself or to an unknown device is 403; to a device without a feed 404; a member token is 401 on all seven routes; another team sees nothing.
- `seq`: the same or a lower `seq` is 409 `seq_not_newer` (also within the pace); 0 and 2^53 are 400, 2^53 − 1 passes.
- Sizes, pace, and budget: a feed of 262145 bytes is 413 and 262144 passes; a body over 360448 is 413 from `Content-Length` before the token; no `Content-Length` and `Transfer-Encoding` are 400; a 352 KiB body is read whole; other bodies over 64 KiB, an action of 4113 and a settle of 1041 bytes are 413; forms are 400; a second feed within 10 s is 403 `feed_limit`, also after a delete; with `feed_bytes` 1 MiB one member's three full feeds pass and its fourth is 403 naming `member_feed_bytes`, another member's full feed still passes (1 MiB in all), and then a third member's feed is 403 naming `feed_bytes`, with one `limit_reached` row each; the caller's own old feed does not count, and questions still fit.
- Actions: only the target lists and settles, only the sender reads the status; the settle retry, `action_settled`, a settle under another `key_id`; 10 open of a sender, 15 of a member (`member_open_feed_actions`) while another member still posts up to the team's 20, then `open_feed_actions`; with `feed_actions_per_hour` 24 a member stops at 18 (`member_feed_actions_per_hour`) while the other member posts up to the team's limit; each with its `limit_reached` row; an action past `expires_at` is `expired` and refuses a settle with `action_expired`; maintenance marks expiries, purges 10 minutes after the end (404, `action_id` still taken), and deletes after 24 hours. Unit tests: `member_share` of each limit, and the whole limit for a team of one member.
- Feed reads: one device reads three full feeds (1048578 characters) fifteen times in a minute (each read reserves a whole page first), and its sixteenth feed read is 403 `feed_rate`, also one that would give nothing; its `/v1/me` and question reads go on, another device reads as before, fifty empty reads of a device cost nothing; no `limit_reached` row. Forty reads of everything at once from one device: each is 200 or 403 `feed_rate`, at most fifteen pass, and the text given stays within 16 MiB. Unit test: two reads in flight and a third refused, the reserve and its refund, the budget, and a read that ends in the next minute.
- Feeds go: `DELETE /v1/feed`, the revocation of a device (its actions to and from it expire) and of a member, and 30 days without an update; each moves the counter.
- Long polls: the feed list wakes on a feed and when a feed leaves, the action list on a post, the status on a settle and on an expiry; a second poll of one kind answers at once; the three kinds of one device do not take each other's place; a counter below `since` answers at once; a revoked device's poll ends with 401. With the question share and the feed share of a team at 2, two question polls and two feed polls hold at once, each in its own lane, and a third of either kind answers at once (`/v1/me` still answers with `max_active` 2). The unfriendly order: two readers ask first, one holds and one answers at once, and the Mac's action poll then holds. With a share of 4, one member's three polls hold, its fourth answers at once, and the other member's Mac still holds its action poll. Unit tests: `kind_seats` and `member_seats`.
- Connect: the preset's 1 MiB of feeds is not stored, the file cap is 11 MiB, four full feeds fit and a fifth does not; two readers' list polls ask first and one answers at once, then the Mac's action poll, the reader's status poll (a seat of its own), and two question polls hold with the first list poll; with `connect_long_polls` and `connect_feed_long_polls` each 1, one Connect team holds a feed poll and a question poll at once and another team's poll of either kind answers at once.
- Rollback: `rollback::check` with the relay up names nothing but lost audit rows right after the migration; after a device, a member (with its device), and a demotion it names the three revocations by kind and id, oldest first, the `member_role` change, and `device_revoked`, `member_revoked`, and `member_role_changed` in `audit_lost`, leaves the `.pre-v6` copy byte for byte as it was, and says the same with the relay stopped; a team made after the migration has `pre_v6: false`; copying the copy back makes the device and the member live again. A stored feed limit makes the team not clean until it is set back; the team is clean right after the migration and not after the revocations, with each of their actions in `access_rows_lost`. Unit tests: the comparison for each kind of revocation and change (also an archived item, a used invite, and an agent bound to a device), rows revoked before the copy, rows made after it, and the audit by action; `is_clean` (schema 4 and 5 without a copy are clean, schema 6 without one is not), and the entry of a team whose thread stopped. The listener probe sees a listener go, also on an unspecified address. `admin delete --free-connect-key` lets the same device key make a new Connect team (the row stays, with a random hash), without the flag the key stays used, and an operator team refuses the flag. The parsers of `admin delete [--free-connect-key]` and `rollback-check`.
- Schema 6: a version 5 file opens as version 6 with `.pre-v6` (mode 0600, encrypted, version 5) and keeps its rows; a failed copy leaves version 5 without the new tables; version 7 is refused; through the relay, a version 5 team keeps its question, then publishes, and copying `.pre-v6` back gives version 5 again.
- Limits: the feed limits at the preset of each kind read in a copy of the version 5 image's `TeamLimits` (`deny_unknown_fields`), and each set away from its preset is written and refused by it; the CLI flags and their ranges.
- The Worker: `PUT /v1/feed` of exactly 360448 bytes passes and of one more is 413 before the relay; a missing, non-numeric, or chunked length is 400; the raised cap holds for `PUT /v1/feed` only; the feed reads pass with path and query.
- No audit row holds an `action_id`, a nonce, or a ciphertext; a second feed adds no row; a delete within the hour of the device's first row writes none, a loop of six `DELETE` and `PUT` adds no row, and maintenance an hour later adds none either (the feed is on, as the last row says); an hour later a delete writes its row at once, the start right after it is written by maintenance an hour later with the member as actor, a revocation within the hour still writes its `feed_deleted`, and a revoked device gets no late row.

### 27.13 Differences from the contract

- **The order of 401.** The contract orders `PUT /v1/feed` as 400 → 413 → 401 and `POST /v1/feed/actions` the same. The relay checks the token before it reads any body, on every route (section 9: a caller without a valid token cannot hold a team's slots), so a body with a bad shape and a bad token gets 401. The header checks of `PUT /v1/feed` (`Content-Length`, `Transfer-Encoding`, the 352 KiB cap) come before the token, as the contract says.
- **The feed lane.** The contract (10.10) says the feed polls run in the question lane, count in a team's share of it, and in a Connect team in the Connect bound. The relay gives them a lane of their own instead (27.7): 64 threads, 16 seats of an operator team, 2 of a Connect team, 48 of all Connect teams, apart from the question lane, its team shares, and `connect_long_polls`. Feed polls in the question lane let one member's devices (three feed polls each, ten devices) fill a team's share of 32 and Connect teams' feed polls halve the room of their question polls. The client sees no difference: a poll over a bound is answered at once, as the contract says.
- **The feed seats.** Of a team's feed share, list polls hold at most half and status polls at most a quarter, and one member's polls leave a seat to each other member with a feed (27.7). The contract does not name them; a poll over a seat is answered at once, as it says.
- **Member shares.** The contract (12) gives the feed and action limits per team and per sending device. The relay also bounds each member at three quarters of each team limit (27.1), as questions are, so one member cannot block another. Over a share the answer is the contract's 403 `feed_limit` or `too_many_actions`; the message names `member_feed_bytes`, `member_feed_actions_per_hour`, or `member_open_feed_actions`.
- **Feed reads.** The contract has no limit on `GET /v1/feed`. The relay gives one device at most 16 MiB of feed text a minute and then answers 403 `feed_rate` until the next minute (27.1); a 403, not a 429, so the app's other calls go on.
- **Start and delete rows.** The contract writes no audit detail for feeds; the relay holds back a `feed_started` or `feed_deleted` within the hour of the device's last row and writes the state of the feed later (27.9).
- **No row for the pace.** The contract writes `limit_reached` "as in section 22"; the relay writes it for `feed_bytes` and the action limits, not for the 10 s pace (27.9).
- **Purge.** The contract's "purged" action is unknown (404) at once; the relay keeps its metadata without envelopes until 24 hours after the post, as questions do (25.8), so its `action_id` stays taken (409 on a repost) and the hourly limit counts it.
- **Revocation.** Besides the deletion of the feed, the open actions to and from a revoked device expire at once.

### 27.14 What this does not protect

- The relay sees what contract section 15 lists: the devices of the publisher, sender, and target and that they share a member; the size and time of each feed and action; each `seq` (which follows the Mac's clock), `key_id`, and the clear outcome. The operator, root, a disk snapshot, and a backup hold the last feed of each device until it is replaced or deleted (up to 30 days after its last update), and the action envelopes until 10 minutes after they ended. `secure_delete` overwrites a replaced or dropped ciphertext in the file; a backup made before keeps it. Cloudflare sees the same.
- The relay can withhold, delay, or keep serving an old feed, refuse to route, or drop actions and settles. It cannot read, forge, roll back, or move a feed, an action, or a settle, or flip an outcome: the AADs and the action's signature bind them (contract 6.1, 9.3).
- The team-wide `change` and action `seq` move for every member's feeds and actions: a member can see that another member's devices are active, not what they do (as the question sequence, 25.12).
- A full feed budget refuses the next feed of a team; the Macs keep their last feed on the relay and their own Agents page. One member can still fill its share, three quarters of the budget and of the action limits, and two members can fill all of it: the shares keep one member from blocking every other, not from blocking a third (as for questions, 25.12).
- One member's polls leave one seat for each other member with a feed, not more: that member's Mac finds a seat for its action poll, but its iPhones' list and status polls can still be answered at once while the busy member holds the rest, and back off. Question polls are not touched. A Connect team has one member.
- The feed read budget and the held-back start and delete rows are kept in memory: a restart forgets them, so a device that loops on feed reads across restarts gets its 16 MiB again each time, and a change held back before a restart gets no late row (the next change writes its row at once).
- A rollback to the schema 5 image undoes every revocation and change of access made since the migration, in every team (27.15).

### 27.15 Rollback to schema 5

The way back to the schema 5 image (docs/OPERATIONS.md 21.3) copies each `teams/<id>.db.pre-v6` over its team file. The copy is the team as it was at the migration, so the rollback undoes everything the team file got since then, not only the feeds:

- **Changes of access come back undone.** A device revoked since then signs in again with its key; a member's or an agent's revoked token works again, and so does a member token that a device enrollment ended; a revoked access grant gives access again; a revoked invite can be used again; a demoted member has its old role, a collection its old policy, and the key holder is the old device again. Nothing tells the team: the old image has no record of the change.
- **The audit loses its rows since then,** also the `device_revoked`, `member_revoked`, `agent_revoked`, `grant_revoked`, `member_role_changed`, and `policy_changed` rows that recorded those changes, and the questions, devices, push tokens, and sync heads made since then (19.3).
- **A team made after the migration** has no copy and is version 6: the old image cannot open it. A Connect team's `connect_key` stays in `relay.db` (26.2), so its device would get 409 `connect_key_used` at its next `POST /v1/connect`. `admin delete ID --free-connect-key` with the new image still up deletes such a team and frees its key (27.10).

So the operator turns new Connect teams off and runs `apassy-relay rollback-check` before anything is stopped, and again as the gate with the relay stopped, right before the copy, which copies only the teams with a copy that the gate listed. A feed limit stored in `relay.db` (`feed_limits_stored`) is set back to the preset with the new image, never by restoring `relay.db` from a backup (that drops the teams made since, and the old image's start removes their files as orphans). When it names any revocation or change, the operator fixes forward (a new image from the schema 6 branch with the fix) rather than rolling back. When a rollback is the only way, the operator suspends each named Connect team with the new image still up (the suspension is in `relay.db`, which the rollback keeps), and the owner of each named operator team re-applies each named change right after the old image starts, before the team's devices are told the relay is back. The command reads the files without the relay, so it also runs when the new image cannot serve, as long as its binary starts.


## 28. Audit reliability addendum (F06–F09)

This supersedes the permanent-retry-refusal, shared FIFO/one-shot push and manual
sweep behavior in sections 25–26. See OPERATIONS section 22 for exact wire messages,
queue/TTL limits, private readiness, archive retention and rollout/rollback.

- Connect creation stays compatible. A fresh, one-use 60-second challenge at
  `POST /v1/connect/challenge` enables recovery of the same active team at
  `POST /v1/connect` with optional `recovery_nonce` and a domain-separated signature.
  Old creation proof replays remain 409; suspended/deleted/revoked identities cannot
  recover or revive. No schema change (6/1003).
- Push is bounded per question/team with round-robin fairness, four senders,
  transient retries/backoff inside TTL, live identity/token checks and bounded
  open-question replay after restart. Final bad tokens stop; overflow/restart
  replay remains best effort, with possible collapse-id-coalesced duplicates.
- Public health is liveness only. Private `admin readiness` checks active team
  readability and caps, returns only to the filesystem-authorized operator and
  exits nonzero on an unavailable active team.
- `admin connect-sweep` defaults to dry-run; `--apply` enables the existing 30-day
  idle suspension plus 30-day deletion policy. Packaged systemd units default to
  dry-run and are not installed automatically. Automatic deletion first preserves
  an immutable master-key-encrypted DB snapshot including all append-only audit.


## 29. CLI audit reliability addendum (F13/F15/F16)

- Service identity is per saved team: launchd
  `com.wydrox.apassy.team-host.<team>.plist`, systemd
  `apassy-team-host-<team>.service`. Service logs carry the team id. Install migrates
  the old pinned single service to its original team's name before installing
  another team, preserving options and retaining/attempting restoration of the old
  service on start failure. Ambiguous or conflicting files require manual review.
  Status/uninstall select the requested team and never remove another team's service.
- Per-team process locks allow several teams in one config directory. New hosts
  share a compatibility fence against old single-host binaries and retain exclusive
  locks for their own team. An old running host must stop before new hosts start.
  Keys also carry an optional stable `team_id` in keys.json version 1; hosts release
  only entries explicitly bound to their authenticated team. Names and UIDs never
  determine ownership. Old unbound entries are retained and fail closed until the
  owner verifies and binds them (ONBOARDING, legacy key ownership).
- Every finite CLI command accepts global `--json` before the child's delimiter.
  One stdout document contains `ok`, `exit_code`, and `result` or `error` with stable
  `code`, `message`, optional `status`/`retry_after` and `retryable`. Lists now share
  the envelope with mutations/errors; progress is stderr. Commands issuing one-time
  secrets (invite, agent create, device add) reject JSON mode before any request;
  use plain output saved privately. Recognized credentials reflected in metadata
  or errors are redacted. No session environment is emitted. Child exit codes are
  preserved; JSON mode suppresses child stdout/stderr because either can contain
  the credential environment. Streaming host/MCP
  reject wrapping. Help leads with device create/join/recovery; expired legacy
  token setup and refused approve are in Compatibility.
- Installer platform pairs match published artifacts exactly (Darwin arm64/Linux
  x86_64), downloads have total deadlines, and staged execution/version validation
  precedes replacement. Update feedback names per-team restart/status commands.
  Status reports `cli_version`; startup logs identify the actual running host.

No relay API, schema, package version or release configuration changes in this CLI
patch. Deployment and service installation/restart remain explicit owner actions.
Before rolling back the CLI, uninstall/stop per-team services using the new CLI;
older binaries use one global lock and cannot run concurrently per team. Reinstall
one selected legacy host if needed. Saved settings/device keys and keys.json retain
their existing format versions; the key ownership field is additive. Old CLIs
ignore it and can drop it when rewriting keys.json, so stop old writers before
restarting a new host. Installer hashes continue to detect corruption, not an
independent compromise of the download origin.
