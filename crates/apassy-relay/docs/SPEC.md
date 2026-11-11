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
| `APASSY_RELAY_CONNECT_SYNC_BYTES` | `sync_bytes` of a new Connect team (`RelayConfig::connect_sync_bytes`, section 26.4): 0 (no relay sync, 403 `plan_required`) or 1048576 to 67108864; the hosted relay sets 67108864 until Apassy Connect starts | 0 |
| `APASSY_RELAY_CONNECT_LONG_POLLS` | long polls of all Connect teams together (`Limits::connect_long_polls`, section 26.4), 0 to 1024; `0`: every Connect poll answers at once | 96 |
| `APASSY_CONNECT_INGRESS_LISTEN` | with the account routes: the SNI ingress of the tunnel (section 35.7, 35.11; hosted `0.0.0.0:443`) | none: off |
| `APASSY_CONNECT_ACME_LISTEN` | with the account routes: the ACME HTTP-01 listener of the tunnel (hosted `0.0.0.0:80`) | none: off |
| `APASSY_CONNECT_NODE_ZONE` | the DNS zone of the nodes' public names | `node.apassy.wyderka.cc` |
| `APASSY_CONNECT_TUNNEL_STREAMS` | open tunnel streams of one account, 1 to 4096 | 64 |
| `APASSY_CONNECT_TUNNEL_NODES` | nodes of one account, 1 to 64 | 8 |
| `APASSY_CONNECT_TUNNEL_DIALS_PER_MINUTE` | dials of one account in one minute, 1 to 6000 | 60 |
| `APASSY_CONNECT_TUNNEL_GIB_PER_MONTH` | tunnel GiB of one account in one UTC month for each person or member, 1 to 10240 | 20 |
| `APASSY_CONNECT_TUNNEL_PING_SECS` | ping interval of a tunnel WebSocket, 5 to 300 s | 30 |
| `APASSY_CONNECT_TUNNEL_IDLE_SECS` | a tunnel WebSocket without a message closes, 10 to 3600 s, above the ping | 90 |
| `APASSY_CONNECT_TUNNEL_STREAM_IDLE_SECS` | a stream without a byte is reset, 60 to 86400 s | 900 |
| `APASSY_CONNECT_TUNNEL_STREAM_BUFFER_KIB` | KiB buffered toward one client of a stream, 64 to 16384 | 256 |

`UpstreamOptions` (extra roots, fixed addresses) is not read from the environment. Tests set it in code.

The environment always makes the edge required (`EdgeMode::Required`) and no public listener, so the hosted relay is as before. Three settings are set only in code: `RelayConfig.edge` (`EdgeMode::Required(secret)` or `EdgeMode::Off`), `RelayConfig.public_listen` (a second listener of `Scope::Public`), and `RelayConfig.auth_limiter` (the failed-auth limiter of each listener). `RelayConfig::embedded` sets them for a Mac's own node (section 30.1). `Relay::start` refuses `EdgeMode::Off` unless every listener address is a loopback address (`RelayConfig::check_listeners`, 400 `invalid_request`), before it opens or makes anything. A node on the tailnet (section 32) has four more settings, also in code only: `tailnet_listen` (a third listener of `Scope::Tailnet`, always on the loopback), `tailnet_agents`, `sign_in_origins` (empty on the hosted relay: `public_url` alone), and `push` in the gateway form (`PushConfig::Gateway`). `from_env` makes none of them: the hosted relay keeps one listener, one sign-in origin, and the Worker push (`PushConfig::Worker`).

`apassy-relay migrate` also reads `APASSY_RELAY_OLD_KEY` / `_FILE`: the passphrase of a `team.db` from before teams. `apassy-relay admin` reads only `APASSY_RELAY_DATA`.

## 7. Auth model

- **Edge.** Every request except `GET /healthz` must carry `X-Apassy-Edge: <edge secret>`. The relay compares it with `secret::same_bytes`. A missing or wrong header gets 403 `edge_refused`, and an audit row with actor `edge` (at most one row per 10 seconds, so a scan cannot fill the audit). An embedded node has no edge (`EdgeMode::Off`, section 30.1): no header is checked, and every listener is on the loopback.
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

The table is the scope `Scope::Node`: the hosted relay's one listener and an embedded node's loopback listener. The public listener of an embedded node (`Scope::Public`, section 30.5) serves `POST /mcp` and `ANY /p/...` only; every other request there, `GET /healthz`, `GET /`, `GET /mcp`, and every `/v1` path included, is 404 `not_found` before any other check.

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

**Request headers.** Forwarded as received, except these, which are dropped: `host` (set to the upstream host), `connection`, `keep-alive`, `proxy-authorization`, `proxy-connection`, `te`, `trailer`, `transfer-encoding`, `upgrade`, `expect`, `accept-encoding`, `content-length` (set again), `x-apassy-edge`, `cdn-loop`, `x-forwarded-for`, `x-forwarded-proto`, `x-forwarded-host`, `x-real-ip`, every `cf-*` header, and every `tailscale-*` header (the identity headers of Tailscale Serve, such as `Tailscale-User-Login`, `Tailscale-User-Name`, `Tailscale-User-Profile-Pic`, and `Tailscale-App-Capabilities`; the name compared without case). `Connection: close` is added.

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
- The JSON, HTML, and percent escapes of each value are replaced too, in any mix, so a host that echoes the value escaped gives back no value: JSON `\/`, `\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t`, and `\u00xx` (either case); for a non-ASCII character `\uXXXX` of its code point (either case), built from UTF-8, with a surrogate pair above U+FFFF; HTML `&amp;`, `&lt;`, `&gt;`, `&apos;`, `&quot;`, and the decimal and hexadecimal entities of each character (`&#NN;`, `&#xHH;`, `&#XHH;`, hex digits in either case, up to four leading zeros); and the percent-encoding `%HH` (either case) of each byte, for a value that went raw in a header and comes back in a URL. This covers each character of the value that is not a letter, a digit, or `-_.`. A whole form of the value becomes the placeholder, followed by the last byte of the placeholder for each byte that the form has more than the value, so the length stays the same and only the total length shows (not where the value has an escaped character). The longest form wins (`…&amp;` and not `…&` followed by `amp;`), and while more data can still make a longer form, the replacer waits for it; at the end of the body the form is replaced as it is. These patterns replace the raw pair of their value; the encoded forms that the request sent go first.
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
- Per-IP limits (Workers Rate Limiting, keyed by `cf-connecting-ip`, fail open when the binding is missing or fails; over the limit: 429 `rate_limited` with `Retry-After: 60`, and the relay never sees the request): `CREATE_LIMITER` (10 a minute) for `POST /v1/join`, `/v1/teams`, `/v1/devices/link`, and `/v1/devices/link/cancel`; `AUTH_LIMITER` (60 a minute) for `POST /v1/auth/challenge`, `/v1/auth/token`, and, with Connect, `/v1/account/challenge`, `/v1/account/token`, `/v1/account/devices/join`, and `/v1/account/devices/join/cancel`, and, in a budget of its own (the key `peers:` and the IPv4 address or the IPv6 /64), `POST /v1/account/list` and every method of `/v1/account/peers/…` (section 33.13; the relay also counts each device, 33.12); `ACCOUNT_LIMITER` (5 a minute, keyed by the IPv4 address or the IPv6 /64) for `POST /v1/account` and `/v1/account/recover` (section 34.8); `TUNNEL_LIMITER` (60 a minute, the same key) for `GET /v1/tunnel/dial/*` and `TUNNEL_NODE_LIMITER` (60 a minute, the same key, a budget of its own) for `GET /v1/tunnel/node` (section 35.13); `SYNC_LIMITER` (60 a minute) for `PUT /v1/sync/snapshot`; `CONNECT_LIMITER` (1 a minute, keyed by the IPv4 address or the IPv6 /64) for `POST /v1/connect` (section 26.4).
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
| `relay.db` | the directory: each team's id, name, kind (`operator` or `connect`, section 26), state (`active` or `suspended`) and suspension reason, file key, `legacy` flag, and limits; team codes; the key hashes of Connect teams; the OAuth clients, connect requests, and refresh-token hashes of an embedded node (section 31.8); relay audit. No people, items, or runs. `user_version` 1004 (section 31.8; 1003 in section 26.2) | the master key (`APASSY_RELAY_KEY`) |
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
4. `sync_pushes_per_hour` (403 `team_limit`, a `limit_reached` row as in section 22). Then, for a Connect team only (section 26), the snapshot bytes of the hour: the `size` of the `sync_head` rows with `pushed_at` in the last 3600 seconds plus this `Content-Length` at most `CONNECT_SYNC_BYTES_PER_HOUR` (536870912, 512 MiB). Over it: 429 `rate_limited` with `Retry-After` the seconds until enough of those bytes leave the window (at least 1), and a `limit_reached {limit: "sync_bytes_per_hour"}` row at most every ten seconds. An operator team has no byte rate.
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
- This is `PushConfig::Worker`, the only form `from_env` makes. A node pushes through a push gateway instead (`PushConfig::Gateway`, section 32.5); the queue, its budget, and its throttles are the same.

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

**The team.** `TeamLimits::connect()` (`sync_bytes` from the setting below, `TeamLimits::connect_with`):

| Field | Connect | Default |
| --- | --- | --- |
| `members` | 1 | 50 |
| `items` | 0 | 500 |
| `agents` | 0 | 100 |
| `sync_bytes` | `APASSY_RELAY_CONNECT_SYNC_BYTES`, default 0 | 67108864 |
| `sync_pushes_per_hour` | 30 (`CONNECT_SYNC_PUSHES_PER_HOUR`) | 600 |
| `question_bytes` | 2097152 (2 MiB) | 8388608 |
| `feed_bytes` | 1048576 (1 MiB, section 27; not stored, 27.8) | 4194304 |
| every other field | the default | |

- `members` 1: `POST /v1/invites` is 403 `team_limit` (no join could use the invite), and so is a join of an invite made before. Devices of the owner come by device links with safety words (section 23.5), up to 10.
- `items` 0: `POST /v1/collections`, `PUT /v1/collections/{id}/policy`, and `POST /v1/grants` are 403 `team_limit`, before any row is written. A grant is refused only for `items` 0, in every team: a team of one member with items (a solo operator team) needs a grant for its owner to run anything (`decide`, `access`). Each refusal writes one `limit_reached` row at most every ten seconds for each limit, as every limit of section 22 does.
- `items` 0 and `agents` 0: no item, no agent, so no run, no session, and no use of the proxy of section 12 (403 `team_limit`). Without them a free team would be an open HTTP proxy with the relay's address. `GET /v1/host/requests?wait=S` of a team whose `agents` is 0 answers at once: no run can come.
- `sync_bytes` 0: no vault sync on the relay. `PUT /v1/sync/snapshot` answers 403 `plan_required` ("Vault sync through the relay is not in this team's plan.") after the headers (400) and the token (401), before the size checks of 24.3, with a refusal row `sync_refused {reason: "plan_required"}`. `POST /v1/sync/receipt` answers the same, even for version 0. `GET /v1/sync/head` answers at once, also with a `wait`: no new version can come. Snapshots that the team pushed while a plan allowed it can still be downloaded.
- `question_bytes` 2 MiB: about 60 full cards at once; the other question limits are the defaults of section 25.1.
- `sync_pushes_per_hour` 30, and at most 512 MiB of snapshots an hour (`CONNECT_SYNC_BYTES_PER_HOUR`, not stored, check 4 of 24.3): anyone can make a Connect team, so its pushes are bounded in count and in bytes. A vault that one person changes pushes far less. The idle sweep (26.5) also counts a team made with the earlier preset (600 pushes an hour) as a Connect preset; `admin limits <id> --sync-pushes-per-hour 30` gives such a team the new count.
- **The sync size of a new Connect team** (plans section 4.1, ADR 0037 stage 7 plan unit S0). `sync_bytes` of a new Connect team is the relay setting `APASSY_RELAY_CONNECT_SYNC_BYTES` (`RelayConfig::connect_sync_bytes`, `TeamLimits::connect_with`): 0 by default, so a relay that its owner runs keeps `plan_required` unless its operator turns it on; 0 or 1048576 to 67108864, any other value stops the start. The hosted relay sets 67108864 until Apassy Connect starts, so the Mac makes a relay sync team without a code (`POST /v1/connect`, then the first push of 24.3). The value is stored in the team's `limits` column when the team is made (`sync_bytes` is a field that every image reads, so the rollback rule of `FEED_LIMIT_FIELDS` holds unchanged and the directory stays at its version); a later change of the setting changes only teams made after it. A team made before keeps its value: `admin limits <id> --sync-bytes 67108864` gives it the same size. With `sync_bytes` above 0 the file cap of the team grows by `CONNECT_SYNC_FILE_BYTES` (16 MiB) for its sync heads (below), and the idle sweep counts the setting's limits as a Connect preset (26.5). The snapshots are files of their own (section 24): with the setting, the room of 26.1 holds up to `APASSY_RELAY_CONNECT_TEAMS_MAX` × 2 × `sync_bytes` of snapshots (12.5 GiB at 100 teams), plus one temporary file per transfer while a push runs (docs/OPERATIONS.md section 20.6).
- The ranges of section 22 change for three fields: `items` and `agents` are 0 to 1000000 (0: none), and `sync_bytes` is 0 or 1048576 to 67108864. Every other range is unchanged. The operator can set the limits of any team, Connect or operator, with `admin limits` (for example `--sync-bytes 67108864` lifts the sync limit of one team). A later entitlement (contract (c)) changes the same fields.

**Rows written only on a change.** `POST /v1/sync/receipt` writes `sync_received` only when the device's version changes, and `PUT /v1/push/token` writes `push_token_set` only when the token, the environment, or the bundle id changes; the same call again moves only the row's time. An expired or refused device link stays 7 days (a sign-in of its key reads `join_refused`), and at most 100 of them stay in a team; then the maintenance pass deletes the row. These hold for every team.

**The file cap.** A Connect team's file has `PRAGMA max_page_count` set from its limits (`TeamLimits::file_bytes`): `question_bytes` + `feed_bytes` (section 27) + 8 MiB, plus 16 KiB for each item and 1 MiB for each member beyond the first that a plan gives it, plus 16 MiB when `sync_bytes` is above 0 (the signed heads that maintenance keeps, `sync::KEPT_HEADS`, and the push audit; 11 MiB, 2816 pages, for the preset without sync, 27 MiB with it; 10 MiB before section 27). It is set at each open and at each `admin limits`. A write past it is refused by SQLite and answered 403 `team_limit` ("The team's storage limit is reached."); the transaction rolls back. An operator team has no cap: the operator made it with a code and watches it.

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

1. Each active, open Connect team whose limits are exactly a Connect preset (`TeamLimits::is_connect_preset`: `TeamLimits::connect()`, or `TeamLimits::connect_with` of `APASSY_RELAY_CONNECT_SYNC_BYTES`), that has no row in `sync_head`, and whose newest `last_seen_at` of its live devices (a device that never signed in counts with its `created_at`) is at least `idle_days` old is suspended as `admin suspend` does, with `suspend_reason = 'idle'` and the audit rows `team_suspended {reason: "idle"}` in the team and the relay audit (actor `operator`). The number of devices does not matter: a second device does not keep an idle team.
2. Each suspended Connect team with `suspend_reason = 'idle'`, limits exactly a Connect preset, and `suspended_at` at least `delete_days` old is deleted as `admin delete` does (file, snapshots, key in `relay.db`). Its `connect_key` row stays, with `team_id` NULL.
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
- Long polls: a Connect team's `GET /v1/host/requests?wait=3` and `GET /v1/sync/head?wait=3` answer at once, an operator team's sync poll waits; with `connect_long_polls` 1, a second Connect team's question poll answers at once while the first holds the seat, an operator team's still waits, and the seat comes back; two devices of a Connect team hold their polls while a third device's answers at once. Unit test: `APASSY_RELAY_CONNECT_LONG_POLLS` is 0 to 1024, default 96, and the only limit read from the environment; the defaults of the caps are 50 and 100. Sync size (26.4): `server_connect::a_connect_team_gets_the_configured_sync_bytes` (a relay with `APASSY_RELAY_CONNECT_SYNC_BYTES` 67108864 makes Connect teams that take a first push, with a 27 MiB file cap; a team keeps its value after the setting goes back to 0, and a team made then is `plan_required`), `server_connect::connect_sync_bytes_zero_keeps_plan_required`, `server_connect::the_idle_sweep_takes_a_codeless_sync_team_only_without_a_head`; unit tests `config::tests::connect_sync_bytes_is_0_or_1_mib_to_64_mib` and `directory::tests::connect_with_sync_bytes_stores_them_and_keeps_the_rollback_rule`.
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

`Store::open_team` migrates a version 5 file to version 6 with the copy rule of 23.2: copy to `<file>.pre-v6` (mode 0600, written as `.pre-v6.tmp`, synced, renamed; refuse to migrate when the copy cannot be made: the team stays at version 5 and does not open), then in one `BEGIN IMMEDIATE` transaction run the statements below and set `PRAGMA user_version = 6` (`migrate_v6`). The change is additive: no table is rebuilt, and the question, sync, push, and device rows are untouched. A version 2 to 4 file goes on to 6 in one start, with each copy. A new team file was made at version 6 until section 30 (now version 7, 30.4). Version 1 and versions above the current one are refused, and the version 5 image refuses a version 6 file (its `open_team` accepts 3 to 5 only). `relay.db` does not change version (1003). `remove_team_file` also removes `.pre-v6` and `.pre-v6.tmp`.

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
- Schema 6: a version 5 file opens as version 6 with `.pre-v6` (mode 0600, encrypted, version 5) and keeps its rows; a failed copy leaves version 5 without the new tables; a version above the current one (now 8) is refused; through the relay, a version 5 team keeps its question, then publishes, and copying `.pre-v6` back gives version 5 again.
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


## 30. Embedded node

A Mac's own node (ADR 0037, cloud slice; docs/design/implementation-plan-0037-cloud-agents.md of the core): the relay runs as threads of the Mac app, and hosted cloud agents reach it through Tailscale Funnel. The app talks to it through the object-safe traits `NodeBackend` and `RunningNode` of the core (`src/node/backend.rs`), which use plain types only: the core cannot depend on the relay. The relay implements them in `src/embedded.rs` (`EmbeddedRelay`, `EmbeddedNode`). The hosted relay's behaviour and wire contracts do not change: everything below is reachable only through `RelayConfig::embedded` or in process, except schema 7 (30.4), the marker check of 30.6, and the dropped `tailscale-*` headers (section 12).

### 30.1 Edge mode and configuration

`RelayConfig.edge` is `EdgeMode::Required(secret)` (the hosted relay: `from_env` always reads the secret, as before) or `EdgeMode::Off`. `Off` is refused unless every listener (`listen`, `public_listen`, and `tailnet_listen`, section 32.1) is a loopback address: `Relay::start` and `EmbeddedNode::start` check it before anything is opened or made. Funnel ends TLS in `tailscaled` on the same Mac and connects from the loopback, so the loopback bind keeps other computers away; it does not keep the programs of the Mac away. Any local program (a coding agent too) can connect to the public listener and run the whole MCP authorization flow (section 31) as any client name, so its connect request looks like a real one (review 0.5.16). The owner's prompts therefore name the host of the request's redirect URI (`PendingConnect.redirect_host`, 31.7): "Returns to <host>", or "Returns to a program on a computer (localhost)" for a loopback host, and the Mac adds "A program on this Mac can start this request." Accepting only connections of the Tailscale process (a peer-process check) is planned for 0.5.17. With `Off`, `POST /v1/connect` verifies no client prefix (there is no Worker), and Connect is off anyway.

`RelayConfig::embedded(EmbeddedOptions {data_dir, master_key, public_url, public_listen})`:

| Field | Value |
| --- | --- |
| `listen` | `127.0.0.1:0` (the node listener, `Scope::Node`; the app's own diagnostics) |
| `public_listen` | from the options: `127.0.0.1:<port>`, the Funnel target, or `None` |
| `public_url` | from the options: the Funnel origin `https://<DNSName>:8443`, checked as an origin |
| `public_origins` | empty: `public_url` alone. `RelayConfig::with_public_origins` adds further origins after it (`NodeConfig.public_origins` of the core: the public name at Connect while Funnel is up too), each checked as an origin, a repeat left out; they need `public_listen` (section 31.1) |
| `edge` | `EdgeMode::Off` |
| `master_key` | from the options, at least 16 bytes (the Keychain key of the app) |
| `session_ttl_secs` | 600 |
| `approval_timeout_secs` | 300 (the broker's question wait) |
| `push` | none; with a node origin and `push_gateway`, `PushConfig::Gateway` (section 32.5) |
| `tailnet_listen`, `tailnet_agents`, `sign_in_origins` | none, off, empty; with `node_origin`, section 32.2 |
| `team_vaults` | on |
| `connect_teams_per_day`, `connect_teams_max` | 0: Connect is off |
| `auth_limiter` | on (30.5) |
| `operator_socket` | off: no `admin.sock` (below) |
| `oauth` | `Some(OAuthConfig::new(..))`: the MCP authorization flow (section 31); the connect page names the computer `EMBEDDED_MAC_NAME`: "your Mac" on macOS, "your computer" on Linux (`HOST_WORD`, the platform word of the machine the relay runs on), also when `EmbeddedRelay::start` starts it for the app: the page is public, so it never shows the computer name. The hosted relay (`from_env`) has `None`. |
| `backup_dir` | `<data_dir>/backups` |
| `limits`, upstream, timeouts | the defaults of `from_env` |

An embedded node serves no operator socket (`RelayConfig.operator_socket` is false; review 0.5.16). Its `<data_dir>` belongs to the Mac user, and the coding agents of that Mac run as the same user, so a socket of mode 0600 there would let any of them run `suspend`, `delete`, or `team-code` on the personal team. `Relay::start` removes an `admin.sock` that an older version left. The hosted relay (`from_env`) keeps the socket on. The Linux node (`apassy serve`, section 32) turns it on in `node::config::relay_config`, because `apassy pair` and `apassy status` use it (`docs/operations/linux-node.md`). `EmbeddedNode::start` makes an empty directory (`Relay::init_empty`) at the first start. One process at a time holds `relay.lock`: a second node on the same directory is 409 `conflict`.

### 30.2 The personal team

`Hub::create_personal_team(name, now) -> TeamId` makes a team without a team code: a team file with its owner member (`owner`) and the directory row, in the order of `Relay::init`, and an audit row `team_created` with `{"kind": "personal"}` in `relay.db`. The owner token is made, hashed into the member row, and dropped: nobody holds it. The node acts for the owner in process (`MemberAuth` of the owner, no device). `team.member_tokens_until` is `NULL`, so the in-process owner never meets the member-token deadline. The team is an operator team with `TeamLimits::personal()`: the defaults with `agents` 20, `runs_per_hour` 120, `pending_runs` 10, and `agent_requests` 16. On a node with the MCP authorization flow (`RelayConfig.oauth`), `agents` counts every agent that is not revoked, also an agent whose token expired and an agent of the flow without a live token (`TokenIssue::Later`); elsewhere an expired agent frees its place. A restart opens it again from `relay.db` like any team. `RunningNode::create_team` then makes the collection `cloud` (policy `ask`: every run asks) and the owner's grant on it. One team for each vault; the vault keeps the team id.

### 30.3 The catalog mirror

`RunningNode::sync_items(team, items)` makes the live items of `cloud` exactly `items` (`CatalogItem`: uid, name, variable, hosts, provider, declarations). Every item is checked first with the checks of `POST /v1/items` (`admin::checked_item`), so a bad item changes nothing. Then: a live item whose uid is not in the list is archived (`item_archive`: its pending runs are denied and its sessions end); a new uid is added (`admin::insert_item`, the `items` limit holds); an item whose fields differ is changed in place (`admin::item_update`: an `item_changed` row, its pending runs denied with `approval_invalidated`, its sessions ended); an archived item is made live again the same way (the `items` limit holds). A second call with the same list changes nothing. Its `sealed` is `hostkeys::VALUE_ON_HOST` (30.6): the node stores metadata only.

### 30.4 Schema version 7 (team file): the item list of an agent

```sql
ALTER TABLE agent ADD COLUMN items TEXT;
```

`agent.items` is a JSON array of item ids, or `NULL`: every item of the member's grants (every agent before this version, and every agent of `POST /v1/agents`, whose wire does not change). A list narrows the grants and never widens them: `decide::check_access` (the run request, and the recheck of every release) refuses an item outside the list with the answer of an unknown item (403 `not_granted`), and `admin::access` (`GET /v1/access`, `apassy_list_access`) leaves it out. An unknown agent or a list that does not parse gives no item. Only the in-process host sets a list: `admin::insert_agent` with a list of live items (at most 500, distinct), and `admin::agent_set_items`, which in the same transaction denies the pending runs of the agent with an item that the new list leaves out (`approval_invalidated`) and ends its sessions with one (`agent_items_changed` rows).

`Store::open_team` migrates a version 6 file with the copy rule of 23.2: `<file>.pre-v7` (mode 0600), then in one transaction the column (only when it is not there) and `PRAGMA user_version = 7` (`migrate_v7`). The change is additive. A version 2 to 5 file goes on to 7 in one start, with each copy. A new team file was made at version 7 until section 32 (now version 8, 32.5). Versions above the current one are refused, and the schema 6 image refuses a version 7 file. `remove_team_file` also removes `.pre-v7` and `.pre-v7.tmp`. `relay.db` stays at 1003 (until section 31, which makes it 1004).

The way back in place: `apassy-relay downgrade-schema-6`, with the relay stopped (it takes `relay.lock`), runs `Store::downgrade_to_v6` on every team file of version 7 (or 8, section 32.5). The schema 6 image does not know the column and would give a listed agent every item of its member's grants, so each live agent with a list is revoked (an `agent_revoked` row of the operator with `{"reason": "schema_rollback"}`) and its pending runs are denied (`approval_invalidated`); then every list is cleared and the version is set to 6. The empty column stays: the schema 6 image never reads it, and a later `migrate_v7` keeps it. The other way back is the `.pre-v7` copy (docs/OPERATIONS.md 23.3).

### 30.5 The public listener, its scope, and the failed-auth limiter

`RelayConfig.public_listen` binds a second `tiny_http` server, served by the thread `relay-public-accept` with `Scope::Public`. It has its own lanes: `Limits {max_active: 32, member_reserve: 0, ..}` (`config::PUBLIC_MAX_ACTIVE`), so it never takes the threads of the node listener. Only the node listener runs the maintenance sweep. `Scope::Public` serves `POST /mcp` and `ANY /p/...`, and with `RelayConfig.oauth` the endpoints of section 31.1; any other request is 404 `not_found` before the health answer, the edge check, the token, or the body (section 9). The public listener trusts no header: the identity headers of Tailscale Serve are not read, and the proxy drops every `tailscale-*` header (section 12). `RunningRelay::public_addr` is its bound address. `stop` joins both accept threads.

With `RelayConfig.auth_limiter` (an embedded node; the hosted relay has it off), each listener counts its failed authentications: a bearer that names no team or that `authenticate` refuses (401 `unauthenticated` or `token_expired`), and a proxy path whose session key names no live session. Since 0.5.16 (review 0.5.16) the count depends on the path:

| Requests | Count (`http::Counted`) | Limit in a window of `AUTH_FAILURE_WINDOW_SECS` (60) s |
| --- | --- | --- |
| The MCP authorization flow (31.1: `/.well-known/…`, `/oauth/…`) | none of the listener: a bad code or refresh token counts for its client only (31.5), and through a `public` stream of the Connect tunnel for no client | — |
| `/mcp` and `/p/…` with a source address | one window for each source (`http::AgentAuthFailures`) | `AUTH_FAILURES_MAX` (20) |
| `/mcp` and `/p/…` without a source address, or a source that the full table cannot take | one shared window of the listener | `AGENT_SHARED_FAILURES_MAX` (600) |
| Every other path (the node listener only: the public listener has no other path) | one window of the listener (`http::AuthFailures`) | `AUTH_FAILURES_MAX` (20) |
| Every path of the tailnet listener (section 32.1) | one window for each tailnet peer (`http::AuthFailures`, `FailureKeys::PerPeer`); `X-Forwarded-For` is not read there | `AUTH_FAILURES_MAX` (20) |
| Every request through a `public` stream of the Connect tunnel (the public listener, `http::Counted::Tunnel`) | none of the listener; no header of the request is read for it | — (Connect bounds the streams, below) |
| Every request through a `device` stream of the Connect tunnel (the tailnet listener, `http::Counted::TunnelDevice`) | one window for each stream, by the serial that the front gives it in process (`front_peers::TunnelStream::serial`), and one window of every `device` stream of the listener together (`http::TunnelDeviceFailures`); never a tailnet peer's count, and no header is read | `TUNNEL_STREAM_FAILURES_MAX` (10) for a stream; `TUNNEL_DEVICE_FAILURES_MAX` (1200) for all of them |

The source address is the last address of `X-Forwarded-For`, which Tailscale Funnel (Serve) sets, and overwrites, to the address that connected to it; an IPv6 address counts by its /64. It is read for this count only: it gives no identity and no authority, so a local program that forges it only moves its own failures to another count. A listener keeps at most `AUTH_SOURCES_MAX` (4096) source windows; when the table is full, the windows that ended are dropped first, and a further source counts, and is checked, in the shared window. A window starts at its first failure. With the limit reached, every further request of that count in the window, with a good token too, gets 429 `rate_limited` with `Retry-After: 60`, after the edge check and before any token, body, or proxy work; the OAuth routes are answered before this check. The window then ends and its count starts again. The other listener keeps its own counts. Each listener at a limit writes at most one row in ten seconds to the relay audit: action `rate_limited`, kind `auth_limit_public`, `auth_limit_node`, `auth_limit_tailnet`, or `auth_limit_tailnet_local`, detail `{"code": "rate_limited", "scope": "public" | "node" | "tailnet", "bucket": "source" | "shared" | "listener" | "peer"}`, with `"peer": "<address>"` for the bucket `peer` and `"listener": "local_route"` on the Mac's local route (32.1). The counts are in memory only.

A stream of the Connect tunnel (section 35) reaches the public listener (a `public` stream) or the tailnet listener (a `device` stream) through the node's TLS front, which writes the connection down in process (`apassy::net::front_peers::register_tunnel`, with a serial for each stream that stays unique when a later connection reuses the loopback port); the listener knows it from the connection's addresses (`Listener::listen` and the request's remote address), never from a header.

The failures of a `public` stream are in no count of the listener: there the client sets `X-Forwarded-For` itself (Connect adds nothing), so a count by it would let a stranger with changing values try without end, and a count without it would let a stranger's bad tokens put every cloud agent at 429. A cloud agent with a good token through the tunnel is therefore never held by anyone's failures. What bounds the tries instead: each `public` stream carries one request (the deadline transport), Connect bounds the streams of a node (35.4: 60 new `public` streams for each node a minute), and the tokens are long random values.

The failures of a `device` stream have counts of their own (since unit RM). Only devices of the node's account, devices of an account with a grant, and Connect itself open them, and a `device` stream can carry several requests one after another (35.6), so guessing through a dial is bounded on the node, not only by Connect's dial rate. The node cannot tell which account dialed: Connect names none in the stream's `open` (connect-tunnel-v1 section 5), and a bad token names no one. So the counts are by stream and by node:

- each stream has its own window: at `TUNNEL_STREAM_FAILURES_MAX` (10) bad tokens or session keys in 60 s, every further request on that stream gets 429 `rate_limited` (`Retry-After: 60`); a new dial is a new stream with a new count, and Connect bounds the dials (60 a minute for the account's own devices, and 60 for each other account, 35.4);
- all `device` streams of the listener share one window: at `TUNNEL_DEVICE_FAILURES_MAX` (1200) in 60 s, every request on every `device` stream gets 429 until the window ends, a good token too. 1200 is above what one account brings in a window at Connect's dial rate (60 × 10 = 600), so one account alone, a grantee too, never holds the owner's or another account's dials at 429; two or more accounts at their full dial rate together, or Connect itself, can. A table of at most `AUTH_SOURCES_MAX` (4096) stream windows; a stream that a full table cannot take counts in the node's window only.

These counts are apart from the tailnet peers' (a tunnel stream has no peer) and from the Mac's local route: the owner's devices on the tailnet and the Mac's own clients are never held by a tunnel's failures. The audit row of a 429 names the bucket `tunnel_stream` or `tunnel_node`, without an address.

Why: the earlier single count of 20 for the whole listener was checked before the flow, so a stranger with 20 bad tokens a minute held every agent of the owner, and their OAuth refresh, at 429. Funnel gives each request the address of its caller, so a per-source count keeps the owner's agents working; the shared count of 600 bounds requests that come without an address (a program on the Mac, or a Funnel that sends none) while it stays far above what the owner's agents fail.

### 30.6 The in-process host and its release

The app is the owner's host in the same process: it reads pending runs with `host::embedded_requests` (the list of `GET /v1/host/requests` without `authorize_host` and without the run key), and answers with:

- `host::release_values(core, run_id, values, reason, now)`: as `host::release`, the run must be pending with its key in memory (else 409 `run_not_pending`), and the key is taken out first (one use). Steps 1 and 3 are checked again (`approval_invalidated`). Then each item of the run must hold `hostkeys::VALUE_ON_HOST`, there must be exactly one value for each item, in the order of the run, and each value must pass `hostkeys::check_value`; else the run is denied with `release_invalid` (`decided_by = host`). The session is made from the values (`decide::env_items`, `sessions.create`), the run becomes `ready`, and `run_released` is written with the actor `host:embedded`, then `session_started`. There is no `authorize_host`: the caller owns the store, and no HTTP route leads here.
- `approvals::deny` with `Denier::Embedded`: as the host's deny, with the actor `host:embedded`.

`hostkeys::VALUE_ON_HOST` is the one byte `0x00`, the `sealed` of every item of an embedded node: the value stays in the owner's vault. It is shorter than `MIN_SEALED_BYTES`, so `POST /v1/items` never stores it (400), and `host::release` over HTTP fails closed for a run with such an item: the run is denied with `release_invalid`, whatever keys the release carries.

At rest the node's directory holds the team metadata, item metadata, agent token hashes, run rows (masked command, purpose, user request), and the audit; never a value or an item key.

### 30.7 Tests

`tests/embedded.rs`, on free loopback ports and temporary directories: `EdgeMode::Off` with a listener off the loopback is refused, before any file is made; on the public listener `/v1/me`, `/healthz`, `GET /`, `GET /mcp`, `/v1/runs`, the host lane, and `/v1/teams` are 404 while `POST /mcp` and `/p/` work, and the node listener serves every route without an edge; `tailscale-*` headers do not reach the upstream; the limiter answers 401 twenty times to one source address and 429 with `Retry-After: 60` at its 21st request (on `/mcp` and `/p/`), with one audit row naming the bucket, while an agent from another address, a request without an address, and the OAuth metadata still answer; 600 bad tokens without an address put the shared count at 429 while a sourced agent still answers; the node listener has its own counts (bad session keys on `/p/` do not limit `/v1/me`; 20 bad tokens on `/v1/me` do); the `device` streams of the tunnel share the count of the node (1200 bad tokens on streams of their own: the next request of any stream, with a good token too, is 429, with an audit row of the bucket `tunnel_node`) while a tailnet peer and the local route keep theirs, and one kept `device` stream reaches its own count at its 11th bad token (429 for every further request on it, a good token too) while a new stream answers (`tests/tailnet_scope.rs`); an agent list narrows `apassy_list_access` and refuses a run outside it with `not_granted`, a narrowed list denies a waiting run, and the sync is idempotent and archives; `release_values` is single use, fails closed on a missing or bad value with `release_invalid`, writes `run_released` by `host:embedded` and `session_started`, and a denial and a revocation work; an item with the marker fails the HTTP release with `release_invalid`; a personal team is made without a code and a restart opens it again with its agent; an embedded node serves no operator socket (`team_code`, `suspend`, `delete` and `teams` fail to connect) and removes a stale `admin.sock` at the start; `downgrade-schema-6` revokes a listed agent and the next start moves the file to 7 again. Unit tests: the scope (`http::tests`), the limiter window, the count of one tunnel stream and of every stream of the node, a full stream table, the source address (last `X-Forwarded-For`, IPv6 /64), the per-source and shared counts, a full source table, the embedded configuration (`config::tests`), and the schema 7 migration, its copy, a failed copy, and the downgrade (`store::tests`).

### 30.8 What this does not protect

- The public listener is on the internet through Funnel: anyone can reach `POST /mcp` and `/p/`. A bearer token, a session key, the team limits, the public lanes, and the failed-auth limiter bound what a stranger can do. The limiter counts `/mcp` and `/p/` by the source address that Funnel forwards (30.5): a stranger with bad tokens holds only their own address at 429. A stranger with many addresses (for example 4096 IPv6 /64s) can fill the source table and then hold the shared count at 429, and with it every agent whose address has no window yet; that needs thousands of addresses and more than 600 bad tokens a minute. A program on the Mac reaches the listener without Funnel (section 30.1) and can forge `X-Forwarded-For`, so it can hold the shared count or a guessed source address at 429. The node listener keeps working.
- The `device` streams of the Connect tunnel share one failed-auth count of the node (30.5), because the node cannot tell which account dialed. Two accounts that may dial the node, at their full dial rate with bad tokens, or Connect itself, can hold every `device` stream at 429 for a window; the owner's devices on the tailnet and the Mac's own clients keep working.
- A cloud agent holds placeholders, base URLs, and a session key, and can use the proxy until the session ends (600 s, way B). A revocation ends it at once.
- The node trusts the app process: whoever runs code in it can release any run. The values are in the vault of the same process anyway.

## 31. The MCP authorization flow of an embedded node

A remote agent (first: Grok Bot) gets only the MCP address of the node. It connects with the authorization flow of the MCP specification (OAuth 2.1 with PKCE, RFC 9728 resource metadata, RFC 8414 server metadata, RFC 7591 registration), the owner allows it on the Mac (or the iPhone), and its access token is the relay agent token of an agent of the personal team, so `POST /mcp` authenticates as in section 14. Code: `src/server/oauth.rs`; HTTP: `src/server/http.rs`; node side: `src/embedded.rs` and the traits of `src/node/backend.rs` of the core. Everything here is served only when `RelayConfig.oauth` is set (`RelayConfig::embedded`). The hosted relay has `None`: every path of 31.1 is 404 `not_found` there, and its 401 of `/mcp` has no `WWW-Authenticate`. The bearer token of section 30 (`TokenIssue::Now`, the CLI `apassy agents add-remote`) stays as the fallback.

### 31.1 Endpoints

Served on both listeners of a node (the public one through Funnel and the Connect tunnel). `<origin>` is the public origin that the request arrived on (`http::arrival_origin`), one of `RelayConfig::public_origins()`: `public_url` (the Funnel origin) first, and on a Mac with Funnel and the Connect route both on, the public name at Connect `https://<label>.node.<zone>` after it. It is decided by the listener and the connection, never by a header (`Host`, `X-Forwarded-*`, and `Forwarded` are not read for it):

- On the public listener, a `public` stream of the Connect tunnel (section 35.3) has the origin whose host is the TLS server name of the stream, compared without case and without a final dot (`RelayConfig::public_origin_named`). The node's TLS front ends that TLS with the public certificate, which it serves only for the public name, and writes the connection to the listener down in process with that name (`apassy::net::front_peers::register_tunnel_named`, keyed by the loopback addresses of the connection).
- A tunnel stream whose server name is no origin of the node, or that has none, is refused: every request on it is 404 `not_found` before anything else (no metadata, no challenge, no flow, no `/mcp`, no `/p/`). A guessed origin would hand out metadata and tokens of an address that the client did not connect to.
- Every other connection (Funnel's from `tailscaled`, a program of the Mac) and every other listener (the node listener) has the first origin, `public_url`.

A node with one origin answers exactly as before this rule. A request at the failed-auth limit (30.5) is 429 first, here too; the flow itself never adds to that limit (31.5). JSON answers are plain objects (not the envelope of section 9) with `Cache-Control: no-store` and `Pragma: no-cache`; errors are `{"error": <code>, "error_description": <text>}` (RFC 6749 section 5.2).

| Endpoint | Answer |
| --- | --- |
| `GET /.well-known/oauth-protected-resource`, `GET /.well-known/oauth-protected-resource/mcp` (RFC 9728) | `{"resource": "<origin>/mcp", "authorization_servers": ["<origin>"], "bearer_methods_supported": ["header"], "scopes_supported": ["apassy"], "resource_name": "Apassy"}` |
| `GET /.well-known/oauth-authorization-server`, `GET /.well-known/openid-configuration` (RFC 8414) | `issuer` `<origin>`; `authorization_endpoint`, `token_endpoint`, `registration_endpoint`, `revocation_endpoint` under `<origin>/oauth/`; `response_types_supported ["code"]`, `response_modes_supported ["query"]`, `grant_types_supported ["authorization_code", "refresh_token"]`, `code_challenge_methods_supported ["S256"]`, `token_endpoint_auth_methods_supported ["none"]`, `revocation_endpoint_auth_methods_supported ["none"]`, `scopes_supported ["apassy"]`, `authorization_response_iss_parameter_supported true` |
| `POST /oauth/register` (RFC 7591), JSON, at most 16 KiB | 201 `{"client_id": "c_<32 hex>", "client_id_issued_at", "client_name"?, "redirect_uris", "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"], "token_endpoint_auth_method": "none", "scope": "apassy"}`. No secret: every client is public, whatever method it asks for. 400 `invalid_redirect_uri` or `invalid_client_metadata`; 429 `rate_limited` with `Retry-After: 600` (31.5). |
| `GET /oauth/authorize` | A connect request (31.3), then 303 to `/oauth/wait/<id>`. Unknown client or a redirect URI that is not registered: 400 page "This connection link is not valid.", never a redirect. Any other error of a client that the owner never allowed (31.5): the same 400 page, never a redirect, since anyone can register a client with any https redirect URI and a redirect would make a link of the node an open redirect. Any other error of a client that the owner allowed at least once: 303 to the redirect URI with `error` (`unsupported_response_type`, `invalid_request` for a missing or non-S256 PKCE challenge or a `state` over 512 bytes, `invalid_target` for a `resource` that is not `<origin>/mcp`), `error_description`, `state`, and `iss`. |
| `GET /oauth/wait/<id>` | The page of 31.4. |
| `POST /oauth/token`, a form (or a JSON object of strings), at most 16 KiB | `authorization_code` (`code`, `code_verifier`, `client_id`, `redirect_uri` optional and then equal, `resource` optional) or `refresh_token` (`refresh_token`, `client_id`). 200 `{"access_token", "token_type": "Bearer", "expires_in", "refresh_token", "scope": "apassy"}`. Errors: 400 `invalid_request` (a missing value, a repeated parameter), `invalid_client` (a client of another origin of the node, 31.2), `invalid_grant`, `unsupported_grant_type`, `invalid_target`. |
| `POST /oauth/revoke` (RFC 7009) | 200 `{}` always (31.6). |
| `POST /mcp` 401 | adds `WWW-Authenticate: Bearer resource_metadata="<origin>/.well-known/oauth-protected-resource/mcp", scope="apassy"`, and `, error="invalid_token"` when the request had a bearer token. Other 401s and other paths do not. |

The form decoder is the relay's own (`oauth::decode_form`): `+` is a space, `%XX` a byte, the result must be UTF-8, and a parameter that is there twice refuses the request (RFC 6749 section 3.1). No new crate.

### 31.2 Rules

- Every client is public (`token_endpoint_auth_method = "none"`). PKCE S256 is required: the challenge is 43 base64url characters, the verifier 43 to 128 unreserved characters.
- Redirect URIs: 1 to 8 for each client; ASCII, at most 512 bytes, no fragment, no space, no user part; `https://<host>…`, or `http://localhost`, `http://127.0.0.1`, or `http://[::1]` with any port. At authorization the URI is the registered one exactly, except that a loopback URI may have another port (RFC 8252 section 7.3). Without `redirect_uri`, a client with one registered URI uses it.
- `resource` (RFC 8707), when sent to `authorize` or `token`, is `<origin>/mcp`.
- A client belongs to the origin that it registered at, and so do its connect requests, codes, refresh tokens, and the access token of its agent. The client id keeps its form `c_<32 hex>`: 10 random bytes, then a tag of 6 bytes, the first bytes of SHA-256 over `apassy-oauth-client-origin-v1`, a zero byte, the origin, a zero byte, and the random bytes (`oauth::new_client_id`; no tag of another origin of the node matches it). Its origin (`oauth::client_origin`) is the origin of the set whose tag it carries; a client id with the tag of no origin of the set (a client of an earlier version, which had one origin, or of an origin that the node no longer has) belongs to the first origin, so a node with one origin treats every client as before. On another origin of the node: `authorize` answers the page of an unknown client; the page of its request is 404 "The request ended." (no code is sent); `token` is 400 `invalid_client` ("The client is not registered at this address.") before the code or the refresh token is looked at, so neither is used up nor its family revoked, and the client can register there; `revoke` changes nothing. The access token of an agent of the flow works on `POST /mcp` only on the origin of the client of its latest refresh token (`oauth::agent_origin`): elsewhere it is 401 with this origin's `WWW-Authenticate` and `error="invalid_token"`, not counted in any limiter. The bearer token of `TokenIssue::Now` has no client and works on every origin. A browser's `Origin` on `/mcp` must be the arrival origin (403 otherwise).
- A session is made for the origin of its agent (`host::release_values_at`, from `EmbeddedNode::release`): an agent of the flow gets base URLs `<its origin>/p/<key>/<host>`, any other agent `<public_url>/p/…`. The proxy serves the key only on that origin; on another one the request is answered as a key that names no session (403 `session_invalid`, the proxy's refusal row), and nothing goes upstream.
- A code is made when the page of an allowed request is first loaded (31.4), lives `CODE_SECS` (300 s), and is bound to its client, its redirect URI, its PKCE challenge, and its request. Its first redemption uses it up, also when the redemption fails (a wrong verifier, client, or redirect URI, or an expired code): then the family of the request is revoked. A second redemption of a redeemed code is `invalid_grant` and revokes the family: its refresh tokens are revoked and the agent's access token is dropped.
- The access token is the relay agent token of the agent of the request (`apassy_tagt_<team>_<hex>`): `issue_access` writes a fresh one into the agent row (its hash and `expires_at` = now + `ACCESS_TOKEN_SECS`, 24 h) with an `agent_token_issued` row (actor `oauth`). One live access token for each agent: a new one replaces the old one.
- The refresh token lives `REFRESH_TOKEN_SECS` (90 days) and is rotated at each use: the old one is marked used and a new one of the same family gets a new 90 days. A used, revoked, or expired refresh token is `invalid_grant`; a used one, or one sent with another `client_id`, also revokes its family and drops the access token. One live family for each agent: redeeming a new code for an agent revokes its older families.
- A team or agent that is gone, or a revoked agent, makes the grant `invalid_grant` and revokes the new refresh token.
- Codes and refresh tokens are 256 random bits (base64url). Only their SHA-256 is stored. The audit rows of the flow name client ids, teams, agents, and reasons, never a code or a token.

### 31.3 Connect requests

`GET /oauth/authorize` with a good client, redirect URI, PKCE, and resource makes a `connect_request`: an id (32 hex characters, in the page address), the client, the redirect URI, `state`, the challenge, a match code (`XXX-XXX` of 24 letters and digits without look-alikes, such as `K7Q-4MD`), status `pending`, and `expires_at` = now + `CONNECT_SECS` (300 s). It writes `connect_requested`, wakes every team's `wait_pending` (31.7), and answers 303 to the page. The same request again (the same client, redirect URI, challenge, and state while it waits) answers 303 to the same page. A request of the same client with another redirect URI, challenge, or state ends the waiting one (`expired`, a `connect_replaced` row; its page says "The request ended.") and makes a new one with its own id, page, and match code: never a 429 page without a code. A client id is public, so a request that someone else keeps open must never stand in for the browser of the client; the owner allows only the request whose code the browser shows.

The node makes a new agent for each allowed request (`Node::allow_connect` of the core): a client that already has an agent gets a second one with no item ("Grok Bot 2"). A request is never connected to an agent that exists, and the old agent stays until the owner disconnects it.

The owner answers in the app with `RunningNode::decide_connect(id, Allow{team, agent} | Deny)` (31.7). Statuses: `pending` → `allowed` (with the team and agent) or `denied` (also when the agent is revoked, 31.7) or `expired` (unanswered at `expires_at`, or allowed and its page not loaded within `CODE_SECS` of the answer) ; `allowed` → `redeemed` at the first redemption of its code.

### 31.4 The page

`GET /oauth/wait/<id>` answers HTML with `Content-Type: text/html; charset=utf-8` and, on every page and every 303 of the flow, `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`. It has no script, form, button, link, image, or cookie: nothing on it can authorize, and loading it changes nothing but the delivery of an allowed code.

| State | Answer |
| --- | --- |
| `pending` | 200 with `Refresh: 3`: "<client> wants to connect to <Mac>", the match code, "Approve on your Mac or iPhone.", that the request ends in N minutes, and "Deny requests on your Mac that you did not start, then connect again." |
| `allowed`, no code sent yet | 303 to `<redirect_uri>?code=…&state=…&iss=<origin>`, once. |
| `allowed` with the code sent, or `redeemed` | 200 "Connected / You can close this page." |
| `denied` | 200 "You denied the connection." |
| `expired`, or an unknown id | 200 (404 for an unknown id) "The request ended." |

`<client>` is the registered name, cleaned (no control character, no format character of category Cf, and no code point of the tag block U+E0000–E007F: `apassy::text::is_hidden_char` of the core, the rule of the node and of the connect card too; runs of spaces as one; trimmed; at most 64 bytes) and HTML-escaped, or "An MCP client". The page cleans a stored name again, so a client stored by an older version shows no such character either. `<Mac>` is `OAuthConfig.mac_name`: "your Mac" (`EMBEDDED_MAC_NAME`) on every node of the Mac app and "your computer" on a Linux node, never the computer name. The other lines of the page and the OAuth errors that name the machine use the same word (`HOST_WORD`): "Approve on your Mac or iPhone." or "Approve on your computer or iPhone.". The page never shows an item, an agent list, the owner's name, or the name of the Mac; only the owner's own prompts (the Touch ID dialog, the iPhone card) name the Mac.

### 31.5 Limits

Funnel forwards no client identity, so every limit is per node.

| Limit | Value | Answer |
| --- | --- | --- |
| Registrations | 10 in 10 minutes of clients that the owner then allowed (`created_at` of the stored clients). A client that was never allowed does not count | 429 `rate_limited`, `Retry-After: 600` |
| Stored clients | 100 clients that the owner allowed at least once. A client that was never allowed does not count: when 100 are stored, a registration first deletes the oldest client that was never allowed (one with no waiting request first, then one with its requests; an `oauth_client_evicted` row) | 429 `rate_limited`, `Retry-After: 600`, only when 100 allowed clients are stored |
| Open connect requests | 3 on the node | 429 page "Too many connection requests wait." with "Deny requests on your Mac that you did not start, then connect again." |
| Open connect requests of one client | 1 | A new request of the client ends the waiting one (31.3); no 429 |
| Bodies of `register`, `token`, `revoke` | 16 KiB | 413 `invalid_request` |
| Bad codes and refresh tokens | 20 `invalid_grant` answers of `POST /oauth/token` for one registered client in a window of 60 s that starts at the first (`oauth::ClientFailures`, in memory). Codes and refresh tokens are 256 bits: the limit only slows a client that sends bad ones in a loop. They never count in the failed-auth limiter of the listener (30.5), and a client id that nobody registered is not counted. A request through a `public` stream of the Connect tunnel is neither counted nor refused: every caller there arrives from the loopback with the node's public name, and Connect bounds the new streams of a node (60 a minute, section 35.4), each with one request, as for the listener (30.5) | 429 `rate_limited`, `Retry-After: 60`, for the token requests of that client only |

"Allowed at least once": a request of the client was allowed (only an allow sets its `team_id`), or the client has a refresh token. Pruning (at each registration and authorization) deletes connect requests older than 7 days, refresh tokens past their end, a client that was never allowed 1 hour after its registration (`NEVER_ALLOWED_CLIENT_SECS`) with its requests, and a client with no live refresh token, no open request, and no use in 7 days. An authorize does not renew a client: only a redeemed code and a refresh set `used_at`.

### 31.6 Revocation

`POST /oauth/revoke` with a refresh token revokes its family and drops the agent's access token; with an access token of an agent that has a live family, the same. Any other token (unknown, or the CLI bearer token of `TokenIssue::Now`) changes nothing. The answer is 200 `{}` in every case, and it does not count in the limiter.

### 31.7 The node traits

`src/node/backend.rs` of the core, implemented by `EmbeddedNode`:

- `NewCloudAgent.token: TokenIssue::{Now{lifetime_days}, Later}`; `CreatedAgent.token: Option<NodeSecret>`. `Later` makes the agent (with its item list, normally empty) and drops its token at once (`oauth::drop_access`, an `agent_token_dropped` row with `token_later`): it has no live token until a code of an allowed request is redeemed. Such agents do not count in the `agents` team limit while they have no live token (the count reads `expires_at`).
- `pending_connects() -> Vec<PendingConnect {id, client_id, client_name, code, created_at, expires_at, redirect_host}>`: the requests that wait, on the whole node, oldest first; due ones become `expired` first. `redirect_host` (since 0.5.16) is the host of the request's redirect URI (`oauth::redirect_host`): lowercase, without the port, an IPv6 address in brackets; the owner's prompts and the connect card show it.
- `decide_connect(id, ConnectDecision::Allow{team, agent} | Deny)`: `Allow` needs an open team and a live (not revoked) agent of it (`not_found` otherwise). A request that does not wait any more is `connect_not_pending`. A `connect_allowed` or `connect_denied` row.
- `agent_access(team, agent) -> AgentAccess {revoked, token_expires_at, client_id, connected_at, refresh_expires_at}`: the live token and the live refresh family of the agent; `not_found` for an unknown agent.
- `revoke_agent` revokes the agent (section 30) and then its refresh families, denies the waiting requests of its clients and its allowed, unredeemed requests (`oauth::forget_agent`).
- `wait_pending` also returns, maybe with an empty list, when the set of waiting connect requests changes; the host loop calls `pending_connects` after each return. Every trait method has the default of a node without the flow (none, `not_supported`), so the fakes of the core compile unchanged.

### 31.8 Directory version 1004

`Directory::open` moves a 1003 file to 1004 in one transaction (and 1001 and 1002 through 1003 to 1004 in the same one); a failure leaves the file at its version and stops the start. The change is additive. New directories are made at 1004; versions above it are refused. The hosted relay migrates too and keeps the tables empty.

```sql
CREATE TABLE oauth_client (
  client_id TEXT PRIMARY KEY, client_name TEXT, redirect_uris TEXT NOT NULL,
  created_at INTEGER NOT NULL, used_at INTEGER);
CREATE INDEX oauth_client_created ON oauth_client(created_at);
CREATE TABLE connect_request (
  id TEXT PRIMARY KEY, client_id TEXT NOT NULL, redirect_uri TEXT NOT NULL, state TEXT,
  code_challenge TEXT NOT NULL, match_code TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending','allowed','denied','expired','redeemed')),
  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, decided_at INTEGER,
  team_id TEXT, agent_id INTEGER, code_hash BLOB UNIQUE, code_expires_at INTEGER);
CREATE INDEX connect_request_client ON connect_request(client_id);
CREATE TABLE oauth_refresh (
  token_hash BLOB PRIMARY KEY, family TEXT NOT NULL, client_id TEXT NOT NULL,
  team_id TEXT NOT NULL, agent_id INTEGER NOT NULL, created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL, used_at INTEGER, revoked_at INTEGER);
CREATE INDEX oauth_refresh_family ON oauth_refresh(family);
CREATE INDEX oauth_refresh_agent ON oauth_refresh(team_id, agent_id);
PRAGMA user_version = 1004;
```

`code_hash` and `token_hash` are SHA-256. The family of a refresh token is the id of its connect request. The image before this section (directory 1003) refuses a 1004 file. The way back in place is `apassy-relay downgrade-directory-1003` (`Directory::downgrade_to_1003`), with the relay stopped (it takes `relay.lock`): the three tables go and the version is 1003 again, in one transaction; a 1003 file is left as it is. Access tokens already issued stay in their team files until they end (at most 24 h); no client can refresh them. The next start of a 1004 image makes the tables again, empty (docs/OPERATIONS.md section 24).

### 31.9 Tests

`tests/oauth.rs`, on free loopback ports and temporary directories: both metadata paths of each document on both listeners; the challenge of a 401 of `/mcp`, with and without a token; register → authorize → the waiting page (headers, `Refresh`, no active part, the code of `pending_connects`) → allow → 303 with `code`, `state`, `iss` → "Connected" → token → `/mcp` 200 with no item, and `agent_access`; codes and refresh tokens stored as hashes only; a wrong verifier uses the code up; a reused code revokes the family and its access token; refresh rotates, one live access token, another client's refresh and a reused refresh revoke the family; an access token ends and the refresh gives a new one; the denied, ended, and unknown pages and `connect_not_pending`; the checks of `authorize` (bad client, redirect, response type, PKCE, resource, state; loopback ports), whose errors are a page for a client that was never allowed, also one registered with a hostile redirect URI, and a 303 back for an allowed client; registration checks, the cleaned name, and the window of 10 that counts only allowed clients; a full table of 100 drops the oldest client that was never allowed (an idle one first, then one with its request) and refuses only at 100 allowed clients; a client that was never allowed is pruned an hour after its registration with its request, and an authorize does not renew it; the node limit of open requests; a new request of a client ends its waiting one, whose page ends and which cannot be allowed, and opens one with its own code; 20 bad codes and refresh tokens put only their client at 429, while another client refreshes and the listener answers, and an unregistered client id is never counted; a hostile client name is cleaned and escaped; revoking an agent ends its connection and denies its client's request; the client's revocation; a connect request wakes `wait_pending`; a `TokenIssue::Now` agent has no OAuth connection and keeps its token; the hosted relay and an embedded node without `oauth` answer 404 on every path; directory 1004 → 1003 → 1004 with a live node. `tests/public_origins.rs`, a node with the Funnel origin and a public name at Connect, each connection written down as the front would: each origin names itself in both metadata documents and in the challenge of `/mcp`, also with a forged `Host`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Forwarded-Port`, and `Forwarded` of the other, and a server name in another case with a final dot; a tunnel stream with no server name, an empty one, or one of no origin of the node is 404 on the metadata, `register`, `/mcp`, and `/p/`, while Funnel's connections answer; bad codes and refresh tokens through the tunnel put no client at 429, while a client of the Funnel origin is at 429 after 20; a node with one origin answers as before (whatever the headers), refuses a tunnel stream with another name, and a repeat of `public_url` is no second origin; for a client of each origin, on the other: `authorize` is the invalid page and opens no request, the page sends no code, the code and the refresh token are `invalid_client` and stay good, `invalid_target` for the other resource, the access token is 401 with that origin's challenge (also with a forged `Host`), a revocation changes nothing, a browser `Origin` of the other origin is 403; a session of an agent of the Connect origin has its base URLs there, is `session_invalid` at Funnel (also with Connect's `Host`) with nothing upstream, and swaps the value at Connect; a `TokenIssue::Now` agent works on both and its session is on the Funnel origin only. Unit tests: the form decoder, redirect URIs, names and escaping, PKCE (RFC 7636 appendix B) and match codes, routes, the page, and the origin tag of a client id (the form `c_<32 hex>`, the origin it registered at, a client of before the tag and of a gone origin on the first, one origin for all) (`oauth::tests`); the public origins of the configuration (Funnel first, repeats left out, the server name lookup, a further origin without the public listener refused) (`config::tests`); 1003 ↔ 1004, the same schema after the way back and up, and a failed migration keeps its version (`directory::tests`); the embedded configuration, whose page says "your Mac" (`config::tests`); a node started as the app starts it says "your Mac" on its page, never the computer name (`tests/embedded.rs`).

### 31.10 What this does not protect

- A program on the Mac reaches the public listener without Funnel (30.1) and can run the whole flow with any client name and a redirect URI of its own. Its request differs from a real one only in where the code goes back: the owner's prompts show the redirect host, and a loopback host says "a program on a computer (localhost)" and, on the Mac, "A program on this Mac can start this request." A local program that registers an `https://` redirect URI of a site it controls is not told apart by this line.
- The page is public: anyone with the address of a waiting request sees its client name and the match code (the page says "your Mac", never the computer name). The code only helps the owner see that the request in the app is the one in the browser. A stranger who starts a request, also with the public client id of the owner's client, can make the owner see "<name> wants to connect": the owner must allow only a request that they started, with the same code. A new request of the client ends the stranger's, so the owner's browser always shows the code of its own request; and an allowed request makes a new agent with no item, so even a mistaken Allow gives no credential.
- A stranger can hold the three open seats, and so delay a real connection: the busy page tells the owner to deny the requests that they did not start, and each request ends after 300 s. A stranger's registrations fill no limit (31.5), but a flood of them can drop a client that registered and was not allowed yet; such a client registers again. A stranger who sends 20 bad codes or refresh tokens through Funnel with the public id of a client holds that client's token requests at 429 for the rest of each 60 s window; its access token keeps working until it ends. Through the Connect tunnel these count for no client (31.5).
- Whoever holds a code and its verifier, or a refresh token, is the client. The flow binds them to the client id, which is public; it is not a client secret.
- An allowed request's code reaches whichever browser loads the page first. PKCE keeps it useless to anyone but the client that made the challenge. So a leaked authorize URL, or the address of its page, can burn the code: its holder loads the page first, or redeems the code with a wrong verifier, which uses it up and revokes the family; the same URL with other parameters ends the waiting request (31.3). This is a known limit, a denial of service only: the client connects again (docs/security/trust-model.md).
- Revoking a family or the agent ends the access token at the next request; a session that was released before it lives until it ends (at most 600 s, section 30).
- The origin binding (31.1, 31.2) keeps the connections of the two origins of one node apart; it is not an access control: anyone can register at either origin, and a client id names the origin it registered at to whoever knows the node's origins. A program on the Mac reaches the public listener without the front and so always has the first origin. A client of an origin that the node no longer has falls back to the first origin.


## 32. A node on the tailnet: the tailnet listener, sign-in origins, teams of devices, push handles, and node pairing codes

ADR 0037 stage 2 and 3 (docs/design/implementation-plan-s2-s3.md of the core, unit N1; contracts `node-pairing-v1` and `push-gateway-v1` of the core). A node (the relay inside the Mac app, or later `apassy serve` on Linux) serves the devices of its teams on its own tailnet address, behind a TLS front with a pinned, self-signed certificate (unit N2 of the core). The front does not parse HTTP: it forwards bytes to a third loopback listener of the relay. Everything here is reachable only through `RelayConfig::embedded` with a node origin, or in process. The hosted relay keeps one listener, one sign-in origin, and the Worker push; the only change it sees is team schema 8 (32.5) and directory 1005 (32.6), both additive, and 409 `push_unavailable` at `PUT`/`DELETE /v1/push/handle`.

### 32.1 The tailnet listener and its scope

`RelayConfig.tailnet_listen` binds a third `tiny_http` server, served by the thread `relay-tailnet-accept` with `Scope::Tailnet { agents: RelayConfig.tailnet_agents }`. It is always on the loopback (`check_listeners` refuses any other address in every edge mode, 400 `invalid_request`): only the TLS front reaches it. It has the lanes and limits of the node listener (`RelayConfig.limits`) but threads and a failed-auth count of its own (30.5; its audit kind is `auth_limit_tailnet`, scope `tailnet`). The count has one window for each tailnet peer on every path (N8-1): the TLS front names the peer of each connection that it pumps in process memory (`apassy::net::front_peers`), keyed by the loopback address pair of its connection to the relay; a connection that the front did not make counts as its own address, the loopback. No header is read for it. A fourth loopback listener, `RunningRelay::tailnet_local_addr` (thread `relay-local-accept`), serves the same routes for the Mac's own clients (the local route of the node origin); the front never forwards to it, and it counts as one window of its own (audit kind `auth_limit_tailnet_local`). It runs no maintenance. `RunningRelay::tailnet_addr` is its bound address, `tailnet_listener_url()` its `http://` origin; `stop` joins its accept thread with the others.

`Scope::Tailnet` serves, as an exact path or a path below it:

| Kind | Paths |
| --- | --- |
| Always | `/healthz`, `/v1/join`, `/v1/teams`, `/v1/me`, `/v1/leave`, `/v1/invites`; `/v1/auth/…`, `/v1/devices…`, `/v1/joins…`, `/v1/members…`, `/v1/sync/…`, `/v1/questions…`, `/v1/push/…`, `/v1/feed…` |
| With `agents` (the Linux node) | `/v1/access`, `/v1/audit`, `/mcp`; `/v1/collections…`, `/v1/items…`, `/v1/grants…`, `/v1/agents…`, `/v1/approvals…`, `/v1/runs…`, `/v1/host/…`, `/p/…` |

"Below" means the prefix followed by `/` or nothing: `/v1/mex` and `/v1/devicesx` are not served. Every other request is 404 `not_found` before the health answer, the token, or the body, as on the public listener: `/v1/connect…`, the operator routes, and the MCP authorization flow (section 31) are never served there, also with `RelayConfig.oauth` set (`Scope::serves_oauth` is false), and a 401 of `POST /mcp` on this listener carries no `WWW-Authenticate`. The listener trusts no header of the front: no peer address, no Tailscale identity. A Tailscale identity is never authorization (ADR 0037 §3); the token is.

The Mac node uses `agents: false`: an agent token is 404 on its tailnet listener, and cloud agents keep the public listener (section 30). The app's own clients reach the node through the loopback node listener (`Scope::Node`, every route) and sign the node origin there too.

### 32.2 Configuration

`EmbeddedOptions` gains `node_origin: Option<String>`, `tailnet_listen: Option<SocketAddr>`, `tailnet_agents: bool`, and `push_gateway: Option<String>`. `RelayConfig::embedded` checks:

- `node_origin` with `config::checked_node_origin` (node-pairing-v1 section 3): `https://<host>:<port>`, a lowercase host of letters, digits, `.`, and `-` (the Tailscale IPv4 in practice), an explicit port 1 to 65535 without a leading zero that is not 443, and nothing else (no path, user, query, or trailing slash). The text is kept as it is: devices sign it.
- `node_origin` and `tailnet_listen` go together; `tailnet_agents` and `push_gateway` need them. Else 400 `invalid_request`.
- `push_gateway` with `config::checked_gateway`: an origin `https://<host>[:<port>]` in lowercase with no path (or `http://127.0.0.1` / `http://localhost` with a port, for tests). It becomes `PushConfig::Gateway { gateways: [push_gateway], timeout: 10 s }` (32.5). `config::DEFAULT_PUSH_GATEWAY` is `https://push.apassy.wyderka.cc`, the default that the app passes; `config::DEFAULT_NODE_PORT` is 8444.

| Field of `RelayConfig` | Without `node_origin` | With it |
| --- | --- | --- |
| `tailnet_listen`, `tailnet_agents` | `None`, off | from the options |
| `sign_in_origins` | empty: `public_url` alone (30.1) | the node origin, then `public_url` when `public_listen` is set and differs (32.3) |
| `push` | `None` | `PushConfig::Gateway` with `push_gateway`, or `None` without it |

`RelayConfig::is_node()` is true when `tailnet_listen` is set; only a node takes a node pairing code (32.6). `from_env` sets none of these: `tailnet_listen` `None`, `sign_in_origins` empty, and `push` only in the Worker form.

The core starts a node on the tailnet with `NodeBackend::start_on_tailnet(NodeConfig, Some(NodeTailnet {node_origin, tailnet_listen, tailnet_agents, push_gateway}))`; `start(config)` is `start_on_tailnet(config, None)`. The default of the trait method answers `not_supported` for `Some`, so the fakes of the core compile unchanged.

### 32.3 Sign-in origins

`RelayConfig::sign_in_origins()` is `sign_in_origins`, or `[public_url]` when it is empty (the hosted relay, and a node without the tailnet route). `POST /v1/auth/token` verifies the signature of section 23.2 (`apassy-relay sign-in v1\0<origin>\0<team>\0<key>\0<nonce>`, unchanged) against each origin of the set and accepts the first that matches; one signed with any other origin is 401 `unauthenticated`, as a bad signature. The hosted relay therefore accepts exactly `public_url`, as before.

`POST /v1/auth/challenge` names one origin in its answer: the one whose authority (`<host>:<port>` after the scheme) equals the request's `Host`, compared without case after trimming, else the first of the set (`devices::challenge_origin`). Only the name in the answer depends on `Host`; the token step accepts any origin of the set, so a client that knows its origin (it stored it from the link) signs it whatever the challenge said. `devices::challenge(core, request, now)` keeps its form: it is `challenge_for(core, request, None, now)`.

### 32.4 Teams of devices on a node

A node hosts several teams side by side (ADR 0037 §2): the personal team of section 30.2 and teams of devices, such as the questions team of a vault (plan decision D6 of the core).

`Hub::create_device_team(name, device_name, public_key, now) -> (TeamId, DeviceId)` is the bootstrap of `POST /v1/teams` (section 23) in process, without a team code: a team file with its owner member (`owner`) and the first device `device_name` with the P-256 public key `public_key` (b64u of 65 bytes), which holds the team's keys; no member token. The names and the key are checked as at `POST /v1/teams` (400 `invalid_request`), before any file is made. The team is an operator team with `TeamLimits::default()`. The relay audit row is `team_created {team_id, kind: "device"}`. A failure after the file was made removes it again. A restart opens the team from `relay.db` like any team. The device signs in through the tailnet listener (or the node listener) with the node origin like any device, and then makes device links (`POST /v1/devices/links`, section 23) for the other devices of the owner.

`RunningNode` (core `src/node/backend.rs`, implemented by `EmbeddedNode`) gains, each with a default of a node without the route (`None` or `not_supported`):

| Method | Does |
| --- | --- |
| `tailnet_addr() -> Option<SocketAddr>` | The bound tailnet listener: the target of the front. |
| `create_device_team(name, device_name, public_key_b64u) -> (NodeTeamId, u64)` | `Hub::create_device_team`; returns the team and the device id. |
| `devices(team) -> Vec<NodeDevice>` | The live devices of the team, oldest first: `id`, `name`, `member_id`, `member_name`, `role`, `key_holder`, `created_at`, `last_seen_at`, `push` (a push handle that has not failed). The relay keeps no device kind. |
| `revoke_device(team, id)` | `devices::revoke` as the team's owner device (the key holder first): its tokens stop, its push token and handle go, its feed goes (27.5). The last device of the last owner is 409 `conflict`. |
| `make_node_code(minutes) -> NodeCode {code, expires_at}` | A node pairing code of 32.6; `not_supported` on a node without the tailnet route. |

### 32.5 Push through the gateway: team schema 8

A node never holds an APNs token. A device exchanges its token for a **handle** and a **secret** at the push gateway (`push-gateway-v1` sections 5 and 6) and gives the node those (`PUT /v1/push/handle`); for each question the node asks the gateway to push to the handle, with a proof made from the secret. `PushConfig` is an enum: `Worker { url, topic, secret, timeout, backoff_unit }` (section 25.6, the hosted relay, the only form of `from_env`) or `Gateway { gateways, timeout, backoff_unit }` (`PushConfig::gateway(list)`, each checked with `checked_gateway`, at least one). `Push::status()` names the mode: `off`, `worker`, or `gateway`.

**Schema version 8 (team file).**

```sql
CREATE TABLE push_handle (
  device_id INTEGER PRIMARY KEY REFERENCES device(id), gateway TEXT NOT NULL,
  handle BLOB NOT NULL, secret BLOB NOT NULL, updated_at INTEGER NOT NULL, failed_at INTEGER);
```

`Store::open_team` migrates a version 7 file with the copy rule of 23.2: `<file>.pre-v8` (mode 0600), then in one transaction the table and `PRAGMA user_version = 8` (`migrate_v8`). The change is additive: `push_token` and every other table are untouched. A version 2 to 6 file goes on to 8 in one start, with each copy. A new team file is made at version 8; versions above 8 are refused, and the schema 7 image refuses a version 8 file. `remove_team_file` also removes `.pre-v8` and `.pre-v8.tmp`. A file that came back from 8 (below) has the table already: `migrate_v8` keeps it and deletes the handles of the devices and members revoked meanwhile (the image of schema 7 does not delete them at a revocation). The team file is SQLCipher; the handle and the secret never go to a log or an audit row.

The way back in place: `apassy-relay downgrade-schema-7` (`rollback::downgrade_to_7`, `Store::downgrade_to_v7`), with the relay stopped (it takes `relay.lock`): every team file of version 8 is set to version 7 and nothing else changes; the schema 7 image never reads `push_handle`. The devices of a node get no push until the next start of schema 8. `downgrade-schema-6` takes a file of version 7 or 8 to 6 (30.4). The other way back is the `.pre-v8` copy (docs/OPERATIONS.md 25.2).

**Endpoints** (`Need::Member`, then the handler requires `MemberAuth.device`, as `PUT /v1/push/token`; served on the node, tailnet, and hosted listeners):

| Endpoint | Body | Answer |
| --- | --- | --- |
| `PUT /v1/push/handle` | `PushHandlePut {v: 1, gateway, handle, secret}`, exactly these fields | `{device_id, updated_at}`; one handle per device, replaced on each call, which also clears `failed_at`. Row `push_handle_set {device_id}` only when the gateway, handle, or secret changes (as `push_token_set`, section 26.4). |
| `DELETE /v1/push/handle` | none | `{device_id}`; removes the caller's handle. Row `push_handle_removed {device_id}` when there was one. |

In order: a relay that does not push through a gateway (the hosted relay, a node without `push_gateway`) is 409 `push_unavailable`; `v` other than 1, an unknown or missing field, a `gateway` that is not an origin of `checked_gateway` form (also with spaces around it), a `handle` that is not canonical b64u of 16 to 1024 bytes, or a `secret` that is not 43 characters of canonical b64u of 32 bytes is 400 `invalid_request`; a `gateway` that is not exactly one of the node's gateways is 409 `push_gateway_refused` (new in `src/error.rs`), so a device cannot make the node call an arbitrary address. The node never opens a handle. A device of a node uses these routes; `PUT /v1/push/token` there is 409 `push_unavailable` (a gateway node has no topic). Revoking a device (`devices::revoke`) or a member (`admin::revoke_member`) deletes its handles in the same transaction.

**The sealed summary.** In the gateway mode, `POST /v1/questions` reads the optional header `X-Apassy-Push-Summary` (`push::SUMMARY_HEADER`; push-gateway-v1 section 12): exactly 720 characters of canonical b64u that decode to 540 bytes, else 400 `invalid_request` before the token is checked. The node keeps it in memory with the push job only, never stores or logs it, and does not open it. Other relays ignore the header. A job made at a restart (`questions::recover_push`) has no summary.

**The push thread in the gateway mode.** After the commit of `POST /v1/questions`, the handles of the routing set (25.6) with `failed_at IS NULL` go to the same bounded fair queue, budget, and throttles as the Worker mode. Before the push each handle is read again: the question is open, unanswered, and not expired, the device is in its routing set, and its stored handle and gateway are still those of the job. A handle whose gateway is not one of the node's is skipped. For each handle, one `POST <gateway>/v1/push` (`ureq`, no redirects, timeout 10 s or the time to the question's end if less) with the body, fields in this order:

```json
{"v":1,"handle":"<b64u>","at":<now>,"expires_at":<the question's>,"collapse_id":"apassy-question","proof":"<b64u 43>"}
```

and `,"summary":"<720>"` after `proof` when the job has one. `proof = b64u(HMAC-SHA256(secret, "apassy-push-v1" 0 handle 0 at 0 expires_at 0 collapse_id [0 summary]))` (`push::proof`; the numbers decimal, the handle and summary as sent). The body never holds a token or the secret. A gateway push is sent once: no retry.

| Answer of the gateway | The node |
| --- | --- |
| 200 `{"v":1,"status":200}` | counts it; one `push_sent {count, via: "gateway"}` per job |
| 200 with status 410, or 400 with reason `BadDeviceToken` or `DeviceTokenNotForTopic` | `failed_at = now` (only while the device still has that handle) |
| 403 `handle_invalid`, `handle_expired`, or `proof_invalid` | `failed_at = now`, the same way |
| 403 `stale_request` | the handle stays; `push_failed {reason: "clock"}`, at most one per team and ten seconds |
| Anything else (another 200 status, a 400 of another version, 409, 429, a 5xx, no answer) | the push is dropped, the handle stays |

Except the clock row, each push that did not go writes `push_failed {device_id, status, reason}` (`reason` the APNs word, the gateway's code, or `gateway`), at most one per device and ten seconds. A failed handle is not used again until its device sends `PUT /v1/push/handle`.

### 32.6 Directory version 1005: node pairing codes

```sql
ALTER TABLE team_code ADD COLUMN kind TEXT NOT NULL DEFAULT 'operator' CHECK (kind IN ('operator','node'));
```

`Directory::open` moves a 1004 file to 1005 in one transaction (and 1001 to 1003 through 1004 to 1005 in the same one); a failure leaves the file at its version and stops the start. The change is additive: every existing code is `operator`. New directories are made at 1005; versions above it are refused, and the 1004 image refuses a 1005 file.

A **node pairing code** (node-pairing-v1 section 6) is a team code of kind `node`: `apassy_tcd_<64 hex>`, one use, 1 to 10 minutes (`directory::MAX_NODE_CODE_MINUTES`), made by `Directory::new_node_code(minutes, now)` with the relay audit row `node_code_created {code_id, expires_at}`. Callers: `RunningNode::make_node_code` (in process) and the operator command `node_code {minutes}` (`apassy-relay admin node-code [--minutes <n>]`, default 10; `apassy pair` on the Linux node, later). `POST /v1/teams` (section 23) takes it like an operator code only on a node (`RelayConfig::is_node`); elsewhere it is 403 `invite_invalid`, as an unknown code, and stays unused. The `team_created` row names `code_kind`. A used or expired code is 403 `invite_invalid`.

The way back in place: `apassy-relay downgrade-directory-1004` (`Directory::downgrade_to_1004`), with the relay stopped: the unused node codes are deleted (the 1004 image would take one for an operator code) and the version is 1004 again, in one transaction; used codes stay as history, and the column stays (the 1004 image never reads it, and the next open of 1005 keeps it). A 1004 file is left as it is; another version exits 1. `downgrade-directory-1003` takes a 1004 or 1005 file to 1003, with the same step first (docs/OPERATIONS.md 25.3).

### 32.7 Tests

`tests/tailnet_scope.rs`, `tests/node_teams.rs`, and `tests/push_handles.rs`, on free loopback ports and temporary directories (`tests/common/node.rs` starts a node with a tailnet listener, the node origin `https://100.64.0.7:8444`, and optionally the team routes and a push gateway; the tests call the tailnet listener as the front would): the tailnet listener serves `/healthz` and the device routes and is 404 for the team routes, the proxy, Connect, the OAuth paths, and any other path, while the node and public listeners serve the OAuth metadata; with `agents` it serves `/mcp`, `/v1/runs`, `/v1/access`, and the host lane, and a 401 of `/mcp` there has no `WWW-Authenticate`; it stops with the node. A device team is made in process, its device signs in with the node origin, gets `owner`, makes links, survives a restart, and is listed and revoked (the last owner device is `conflict`); a sign-in signed with the Funnel origin passes, one with an unknown origin is 401, a node without the public route takes only its node origin, and the hosted relay accepts exactly `public_url`; a node code makes a team once, is refused after its minutes, and makes no team on a relay that is not a node. `PUT /v1/push/handle` stores the decoded handle and secret, writes one row per change and no handle or secret in the audit, refuses a gateway off the list (409) and every bad form (400); the hosted relay and a node without a gateway answer 409; a post makes one call per handle of the routing set (not the asker's) with six fields, the proof of `push::proof`, and no token; a 410 marks the handle, the next post skips it, a new `PUT` clears it, `handle_expired` marks it, `stale_request` writes the clock row and keeps it, a 503 drops the push; a summary goes into the body and the proof, and a bad one is 400; a revoked device loses its handle. Unit tests: the proofs of the contract's vectors and the body form, the actions of each gateway answer, the summary form, and the modes (`push::tests`); the scope (`http::tests`); the challenge origin (`devices::tests`); the configuration and the origin and gateway forms (`config::tests`); schema 7 ↔ 8 with the copy and a revoked device in between (`store::tests`); directory 1004 ↔ 1005 with the codes (`directory::tests`); the new commands (`bin` tests).

### 32.8 What this does not protect

- Whoever reaches the tailnet listener can call every device route, as on the hosted relay; a device token, the team limits, and the failed-auth limiter bound what they can do. The listener is on the loopback, so the TLS front (unit N2 of the core) is what decides who reaches it.
- A device of a team can make the node call its gateway (one of the node's), once per question, with a handle of its choosing. The gateway allow-list keeps it from making the node call anything else.
- A node that held a handle can push the fixed notification to that device until the handle expires at the gateway (180 days), also after the device left the team (push-gateway-v1 section 17).
- The sign-in origin set widens what a signature is good for to the origins of one node; a signature for another node's origin, or the hosted relay's, is refused.

## 33. Connect accounts

Apassy Connect accounts (ADR 0037 stage 7, plan s7 unit C1). The wire is the contract [connect-account-v1](../../../docs/contracts/connect-account-v1.md); this section names how the relay serves it. The code is `server/account.rs` (routes, sign-in, devices, vault stores, recovery), `server/entitlement.rs` (the token), and the directory step of 33.10.

### 33.1 Settings and modes

| Variable | Effect |
| --- | --- |
| `APASSY_RELAY_CONNECT_ACCOUNTS` | `1`: the account routes beside every other route (the transition). `0` or unset: every route of the contract is 404 `not_found` (they fall through to the route table). |
| `APASSY_RELAY_MODE` | `relay` (default) or `connect`. In `connect` mode the master key is refused at start (`APASSY_RELAY_KEY` and `APASSY_RELAY_KEY_FILE` must be unset), `relay.db` and the vault stores are plain SQLite files (33.8), shared team vaults are off, and the account routes are on (`APASSY_RELAY_CONNECT_ACCOUNTS=0` is refused there). The retired routes of contract section 14, the start checks, and the cutover are section 37. |
| `APASSY_CONNECT_SIGNING_KEY_FILE` | The Ed25519 key of the entitlement token, PKCS#8 (DER or PEM). Without it the well-known document lists no key and `GET /v1/account/entitlement` is 503 `busy` for an entitled account. A key that this relay did not publish before signs only `entitlement::PUBLISH_LEAD_SECS` (3600 s) after its first start with it (33.9). |
| `APASSY_CONNECT_PUBLISHED_KEYS_FILE` | More published keys: JSON `{"keys":[{"kid","public_key"}]}`, at most 8 Ed25519 public keys (b64u, 32 bytes), each `kid` the `entitlement::key_id` of its key, read at start (`config::published_keys_from`). The next signing key before a rotation, the previous one for a day after it. |
| `APASSY_RELAY_CONNECT_ACCOUNTS_PER_DAY` | New accounts of the whole relay in any 24 hours, 0 to 100000 (default 1000; `0`: none). Over it `POST /v1/account` is 503 `busy` with `Retry-After: 3600`. |
| `APASSY_RELAY_CONNECT_ACCOUNTS_MAX` | Accounts the relay holds, 0 to 10000000 (default 100000). At it, the same 503. |
| `APASSY_CONNECT_SITE_URL` | The `https://` site origin for billing and groups (default `https://apassy.wyderka.cc`). |

`RelayConfig.connect` (`ConnectConfig`) holds them; `ConnectConfig::default()` has no accounts. The account routes are served only on the node listener (`Scope::Node`); the public and tailnet listeners answer 404 for them.

### 33.2 Order of a request

After `/healthz` and the edge secret, before the proxy and the route table: an account path (`/v1/account`, below it, and `/.well-known/apassy-connect.json`) goes to `http::respond_account`. The route (404, 405); an **edge route** (`POST /v1/account`, `…/challenge`, `…/token`, `…/devices/join`, `…/devices/join/cancel`, `…/recover`, the well-known document) refuses any `Authorization` header with 400 `invalid_request` and reads its body; **every other route** (`Need::Account`) checks the account token before the body (401, or 403 `account_required` for a team token), reads the body (64 KiB, 413 above), and checks the token again after it. A 401 counts in the listener's failed-auth limiter and writes an `auth_failed` refusal row (`account_token`) to the relay audit, at most one per ten seconds. Request bodies are strict (`deny_unknown_fields`, no missing or duplicate field): 400 `invalid_request`. `DELETE` routes take no body or `{}`.

### 33.3 Accounts, devices, and sign-in

- `POST /v1/account` takes `account_id`, the id of the new account that the device made (`acc_` and 10 characters of `a-z2-7`, else 400; an id that exists is 409 `conflict` and the device makes another and signs again), `recovery_key` (b64u of a 32-byte Ed25519 public key, 43 characters; `device::RecoveryKey` derives it from the 16 bytes of the recovery code, which never leave the device), and `statement`, and verifies the ECDSA signature over `account_message(public_url, key, recovery_key)` (`apassy-connect account v1`) and the statement, the key's signature over the root entry of the device list (`account_list_message(public_url, account_id, 1, "-", "root", key, "-", device_name, key)`, the device name as Connect keeps it, trimmed); another origin, key, recovery key, id, name, or domain is 400 and makes nothing. The first device is the account's **root**: version 1 of its signed device list (33.4), with that statement as its signature. Device ids are `dev_` with 10 random characters of `a-z2-7`. The SHA-256 of the parsed body is kept (`account.create_hash`): the same body again within 600 s answers the same result and counts for no cap; the same key otherwise is 409 `conflict`. New accounts have the relay's caps (`APASSY_RELAY_CONNECT_ACCOUNTS_PER_DAY`, `_MAX`: 503 `busy`, `Retry-After: 3600`) and the cap of the client prefix that the Worker proved (`X-Apassy-Client-Prefix` with `-Mac`, the scheme of section 26; the Worker proves every call it forwards, so only a call without the Worker, such as a node's own, has none and counts for the relay's caps only): `connect::per_prefix` of the daily cap, 5 at the default, a UTC day, in its own `PrefixLimiter` (429 `rate_limited`).
- **One key, one account, ever**: `account_key` keeps the SHA-256 of every key that became a device (creation, confirmation, recovery) and its account, also after a revoke or a deletion. Such a key cannot make an account, join, or recover (409).
- `POST /v1/account/challenge`: a key that **is or was** a device of the account (live, revoked, or of the deleted account, from `account_key`) gets a 32-byte nonce for 60 s. Connect keeps nothing for it: the nonce is 12 random bytes, the expiry as a big-endian u32, and the first 16 bytes of HMAC-SHA256 under a 32-byte key of this process over `"apassy-connect nonce v1" 0x00 account 0x00 SHA-256(key) 0x00 random ‖ expiry`. So a challenge never ends another one, and a restart ends every open nonce. A key with a pending join of the account is 403 `join_pending`; with a refused, cancelled, or expired one 403 `join_refused`; any other 401. The answer names `public_url` as `origin`.
- `POST /v1/account/token` checks, in this order: (1) the nonce (its MAC for this account and key, not expired), the key (on the curve), and the signature over `account_sign_in_message(public_url, account, key, nonce)` (`apassy-connect sign-in v1`): any failure is one 401, and nothing is used; (2) the device: a live device of the account goes on; a key that is or was a device of the account and is not live (revoked, or the account was deleted) is 403 `device_removed`, an answer that only the device's own signature gets; else 401; (3) under the lock of the sign-in state: a nonce that granted a sign-in before is 401; a key that holds `USED_NONCES_PER_KEY` (30) used nonces that have not expired is 429 `rate_limited` for that key only (another key of the account signs in) and its nonce stays unused; a full token table (100000) or used-nonce table (`MAX_USED_NONCES`, 100000) is 503 `busy` and the nonce stays unused; else the nonce is kept as used until its expiry and the token is kept. The token is `apassy_act_<account id>_<64 hex>` (`secret::new_account_token`), 900 s, kept in memory as its SHA-256 (at most 8 for each device: a ninth drops the oldest). It is never a team token: `parse_token` refuses it, and `parse_account_token` refuses team tokens.
- **Domain separation**: the relay verifies an account sign-in only over `apassy-connect sign-in v1`, a team sign-in only over `apassy-relay sign-in v1` (section 23), a Connect team only over `apassy-relay connect v1` (section 26); it never accepts `apassy-bouncer sign-in v1`. Each message binds the origin.
- `account::authenticate` (used by every `Need::Account` route, also those of billing, groups, and the tunnel) reads the token in memory and then the device in `relay.db` (live, account not deleted), so a revoked device fails at once. It writes `last_seen_at` rounded to the hour, at most once an hour.
- `GET /v1/account` is the `AccountView`: `plan` from `Plans` (33.6), `group` from `Groups`, the live devices, and `device_list`, the account's **signed device list** from version 1 (`account_list`). Entry *v* is `{version, op, key, link_hash, name, by, signature}`: version 1 is `root` (the root key as `key` and `by`, no link, the device name, signed by the root key itself); each later entry is an `add` (with the link hash and the device name of the join) or a `remove` (`name` null), signed by `by` over `account_list_message(public_url, account, v, previous, op, key, link_hash or "-", name or "-", by)` (`apassy-connect device-list v1`), where `previous` is `account_list_hash` (b64u of the SHA-256) of the message of entry *v−1* (`-` for version 1). The join answer carries the same list. The devices verify the list from the root that they pinned and need not trust Connect for it; a device answer has no chain.

### 33.4 Adding and removing devices

- `POST /v1/account/devices/link` stores only the link hash (43 b64u characters), one use, 600 s, at most 3 open for each device. Connect never sees the code, so it cannot compute the six safety words (`device::account_safety_words`, the vectors of the contract): the devices compare them.
- `POST /v1/account/devices/join` (edge) verifies the signature over `account_join_message` (`apassy-connect join v1`), finds an unused, unexpired link of a live device of the account (else 403 `forbidden`), marks it used, and stores a pending join with the SHA-256 of its body (the same body again answers the same result). Nothing is added until the confirmation.
- `…/pending` lists the pending joins of links that the calling device made. `…/pending/{join_id}/confirm` and `…/refuse` are for that device only (403 `forbidden` for another device of the account, 404 for another account, 409 when the join is not pending or expired). The confirm takes `{"public_key","version","statement"}` and adds exactly the key in its body: another key is 409 and adds nothing. `statement` is the `add` entry of the device list for that key, the join's link hash, and the join's device name as Connect keeps it, signed by the caller (`append_signed`): `version` must be the head's version and 1 (else 409 `conflict`: the device reads the list and signs again), the list must have room (an entry that adds something, an `add`, a `peer`, a `share`, or a `join`, at most at `LAST_ADD_VERSION`, 822, and any entry at most at `MAX_LIST_ENTRIES`, 1024: else 403 `account_limit`, whose message says that the list is nearly full, that a removal still works, and that a recovery starts a new list; the last `LIST_REMOVAL_RESERVE` versions, the live-device limit (at least 10), `MAX_PEERS` (64), and `MAX_SHARED` (128), are kept for the entries that end something, so every live device can be removed, the last one by itself, every peer and share ended, and the account recovered; `account::next_entry` makes these checks for every entry), the signer must be a device of the list, the key must never have been in it (409), and the signature must verify over the entry with the head's hash (else 400); a refusal adds nothing. The device row (with `added_by`, the caller) and the entry are written in one transaction; the answer is its device view. At most 10 live devices (403 `account_limit`). `…/join/cancel` (edge) ends a pending join; it takes the joining key's signature over `account_join_cancel_message` (`apassy-connect join-cancel v1`), else 400.
- `DELETE /v1/account/devices/{device_id}` (any live device of the account, also itself) takes `{"version","statement"}`, the `remove` entry of the device list for the device's key, signed by the caller with the checks of the confirm (409 for an old version, 404 for a key that the list does not hold, 400 for a bad signature; nothing changes). In one transaction of `relay.db`: the entry, the revoke of the device (its row stays; its key stays in `account_key`), its pending joins expire, its open links end, its tunnel node and grants go, an I-4 `revoke` event is recorded (`brain_event`), and its rows of `account_store_device` go with a waiting `account_store_removal` for each store (33.5). Then its tokens leave memory, its tunnel closes, and each removal is applied to its store file when that file is open. The last live device can go, also at version 1024 of the list; the account then needs recovery.

### 33.5 Vault stores

- A vault store is a team of kind `account` (`TeamKind::Account`) with `team.account_id` and `team.vault_id` (unique together), `TeamLimits::account(members)`: 64 MiB snapshots, 120 pushes an hour, no items, no agents, the smallest question and feed budgets, a file cap of 24 MiB plus 1 MiB for each further member. `Hub::create_vault_store` makes its file with the owner member named by the account id and device 1 named by the account device id, with the account device's public key; `account_store_device` maps each account device to its store device. A race for the same vault answers the store that won.
- `POST /v1/account/vaults` needs `Plans::plan(...).entitled` (403 `plan_required`) and at most `10 × Plans::people` stores (403 `account_limit`); the same vault id answers the existing store. `GET /v1/account/vaults` lists the stores the account made or holds a device in.
- `POST /v1/account/vaults/{team_id}/devices` takes `{"device_id","public_key"}`, the key that the caller verified: the caller's device must be in the store (403 `forbidden`); the team must be a vault store (404 `not_found` for no team and for a team of another kind: `account_required` is only a team token on an account route); the target is a live device of the account that made the store, or of an account that the owner's list shares the store with (`account::share_active`, 33.13) and for which `Groups::share_group` with the owner is true: an unknown or revoked device and a device of any other account are the same 403 `not_in_group`; its key must be `public_key` (else 409 `conflict`, nothing added); at most 10 devices of one account in a store. `Hub::add_store_device` adds a member for the account (when there is none) and the device without the item keys; a key that is in the store keeps its id. It writes the map row in a directory transaction that checks again that the device is live and may be in the store (`account::may_join_store`: of the store's account, or of an account that the owner's list shares the store with and that is in one group with it as active members); when it may not any more (a revoke or a group removal since the checks of the route), that transaction queues the removal of the row that the store file just took, the removal is applied, and the answer is 403 `not_in_group`. A store device id that is used again ends the removal that waited for it. The add and the apply of each removal to a store file hold one lock of the hub (`store_changes`), and an apply goes on only while its waiting row is there, so a removal that an add ended never revokes the device later.
- `DELETE /v1/account/vaults/{team_id}` by a device **in the store** of the account that made it (else 403 `forbidden`): `Hub::delete_vault_store` takes the store out of service, waits for its requests (at most 10 s, else 409), deletes its row, its device map, its waiting removals, and its file with the snapshots.
- A device leaves a store in two halves. First, in the directory transaction of the change that causes it (a revoke, a group removal, the deletion of its account, whose transaction also deletes the account), its map row goes, so the relay-sync sign-in of the store refuses it from the commit on (below), and an `account_store_removal` row waits (`hub::queue_store_removal`). Then, after the commit (`Hub::apply_removals`), when the store is open its relay-sync tokens of the store are dropped and its long polls woken, also when the file write fails, and its device row there is revoked (with its audit row, or without it when the file cannot take both); the waiting row goes when the write worked. When the store is not open (suspended) or the write fails (a file at its cap), the row waits: the open of the store (`register` of a store, at a resume or a start) applies it before the store serves, and the maintenance pass retries it (`Hub::retry_store_removals`: due rows, at most 100 a pass, a wait that doubles from 60 s to an hour; a row of a store that is gone ends). The heads it signed stay verifiable (relay-sync-v1: a removed device keeps its key).
- **The nonces of a vault store keep no state until they are used** (`devices::StoreNonces`): the nonce of `POST /v1/auth/challenge` is still b64u of 32 bytes (relay-sync-v1 does not change): 12 random bytes, the expiry as a big-endian u32, and the first 16 bytes of HMAC-SHA256 under a 32-byte key of the open store (made at its first challenge, gone at its suspension or a stop) over `"apassy-relay store nonce v1" 0x00 team 0x00 SHA-256(key) 0x00 random ‖ expiry`, on a clock that never goes back. So a challenge never ends another one of the same key, also when another device of the store asks for them. `POST /v1/auth/token` takes such a nonce only for its store and its key, not expired; it is used only by the sign-in that it grants, under the lock of the access tokens, and kept until its expiry: a used nonce is 401, a key with `STORE_USED_NONCES_PER_KEY` (30) used nonces is 429 `rate_limited`, a full table (`STORE_USED_NONCES`, 1000 a store) is 503 `busy`, each with the nonce unused. Teams of other kinds keep their nonces as section 23 says (4 open for each device, 1000 a team, a nonce used up by any call that names it).
- The relay-sync sign-in of a vault store (`devices::challenge_for`, `devices::token`) also needs, in `relay.db`, a map row of the store device whose account device is live (`account::store_device_live`), and for a device of another account than the one that made the store, the share condition of 33.13 with the member's `join` (the owner's active `share`, the member's `join` made while it was active, the pinned root, no later group removal) and that both accounts are active members of one group: else 401. The token step checks it again after it keeps the token and drops the token when the check fails, so a removal that commits during a sign-in leaves no token.
- **What a store serves** (`http::vault_store_allows`, after the token check): `GET /v1/me`, `GET /v1/devices`, `DELETE /v1/sync` always; a push and a receipt with an entitled plan of the store's account (403 `plan_required`, the place of the `sync_bytes` check of section 24), and a push by a device of another account (`account_store_device.account_id` of the signed-in store device) also with an entitled plan of that account (403 `plan_required`: a member beyond the paid seats or with a read-only plan pulls and does not push); `GET /v1/sync/head` and `…/snapshot` with `PlanView::can_pull` (entitled or `read_only`); every other team route is 403 `forbidden` (invites, joins, device links, members, items, agents, questions, feed, push). The relay-sync sign-in (`/v1/auth/challenge`, `/v1/auth/token`) and the sync routes are those of section 24, unchanged. A store's outside refusals go to the relay audit and its polls and requests have the Connect bounds (`Core::hosted`).

### 33.6 Seams for billing and groups

`account::Plans` (`plan`, `people`, `cancel_for_deletion`) and `account::Groups` (`group_of`, `share_group`, `blocks_deletion`) are installed with `Hub::set_plans` and `Hub::set_groups`. With the account routes on, `Hub::open` installs the groups of section 36 (`group::DirectoryGroups`) and, when Stripe is set up, billing (section 34, `billing_store::BillingPlans`). Without Stripe, `NoPlans` answers `PlanView::none()` for every account (no new store, no push, no pull, no entitlement token: 403 `plan_required`); a test may install its own plans with `Hub::set_plans`. Each call gets the directory store and takes its own lock. The tables of both are in directory 1006 already (33.10). `tunnel_node`, `tunnel_grant`, and `tunnel_usage` are unused by C1, except that a revoke and a deletion delete the rows of their device or account.

### 33.7 Recovery and deletion

- `POST /v1/account/recover` (edge) takes `{"account_id","device_name","platform","public_key","recovery_key","signature","recovery_signature","statement"}`; the recovery code never travels. The message is `account_recover_message(public_url, account, key, next recovery key)` (`apassy-connect recover v1`). The new device key's ECDSA signature over it and `statement`, its signature over the root entry of the new device list (as at creation, with `device_name`), are checked first (else 400, not counted); the same body again within 600 s while the device it made is live answers the same result (`account.recover_hash`, `recovered_at`, `recover_device`, `recover_deleted`); then `recovery_signature`, the 64-byte Ed25519 signature of the account's stored recovery key over the message, and no live device: a wrong signature, an unknown account, and a live device are the same 403 `forbidden`. The signature is checked before any limit, and a valid one is never limited. Only failures count and are limited: a wrong recovery signature of an existing account counts for the account and the client prefix (proven, or `unknown` without the proof); a recovery of an account id that names no account counts for that id, in a table of unknown ids of its own (never in the table of accounts), and for the prefix, with the same rule, the same checks, and the same answers, and its recovery signature is verified with a stand-in key of this process, so it costs the same work. After 5 failures an hour for the id, or 20 an hour for the prefix, a further failure is 429 `rate_limited` (`Retry-After: 3600`); the counts are in memory, under their own lock, in tables of at most 10000 accounts, 10000 unknown ids, and 10000 prefixes (a new one in a full table is 503 `busy`). A used key is 409. Every vault store of the account is deleted, the new device is the account's new root and starts a new device list (version 1; the entries before are dropped), the recovery key becomes `recovery_key`, the subscription stays.
- `DELETE /v1/account`: `Groups::blocks_deletion` (409), `Plans::cancel_for_deletion`, every store of the account deleted, and then in one transaction its devices out of other accounts' stores (the first half of 33.5; the files take the removals after the commit), its tunnel rows and the email copy of `stripe_customer` gone, the account with its devices, links, and joins deleted (`ON DELETE CASCADE`), the keys kept in `account_key` with the account id (a sign-in of such a key is 403 `device_removed`), an I-4 `forget` event queued, and its tokens dropped.
- **Maintenance** (`account::maintain`, from the relay's maintenance pass): the waiting store removals at every pass; at most once an hour, the links (with their joins) more than a day past their end, and, older than 90 days, the relay audit rows of accounts (actor `account:…`), the rows of revoked devices (their keys stay in `account_key` and their entries in the device list), and the I-4 events delivered more than 90 days ago (`done_at`; an event that was never delivered stays, `account::prune`).

### 33.8 Plain files

`Store::create_plain`, `Store::open_plain`, `Store::create_team_plain`, and `Store::open_team_plain` open SQLite without a key, with the other checks of a keyed file (build options, defensive mode, secure delete, foreign keys, journal mode DELETE). They run only when `store::plain_allowed` passes: `APASSY_RELAY_MODE=connect`, an empty master key, and neither `APASSY_RELAY_KEY` nor `APASSY_RELAY_KEY_FILE` in the environment. An encrypted file does not open plain. In `connect` mode `Directory::create` and `open`, new team files, and `Hub::open_team` use them; a plain team file must be of the current schema (no migration). The cutover of existing files is `connect-cutover` (section 37.5).

### 33.9 The entitlement token

`Entitlement::sign(signer, claims)` and `Entitlement::verify(keys, token, now)` (`server/entitlement.rs`) follow contract section 10: the compact JSON of `Claims` in the order `v, kid, acc, plan, group, feats, iat, exp`, Ed25519 over `"apassy-connect entitlement v1" 0x00 <payload b64u>`. The key id is `ek_` and 16 hex characters of the SHA-256 of the public key (`entitlement::key_id`), so a new key has a new id. `GET /v1/account/entitlement` answers a token of 24 h for an entitled plan of `personal`, `family`, or `team` (else 403 `plan_required`), with every feature (`brain`, `sync`, `tunnel`). The well-known document lists the keys of the configuration only: the signing key and the keys of `APASSY_CONNECT_PUBLISHED_KEYS_FILE` (`account::published_keys`); a key removed from the file goes at the next start. `entitlement_key` is history: the kid and public key of each of them with the time this relay first published it (`created_at`, at start, `account::record_keys`) and the time of its last token; it never decides what is published. A signing key signs only after this relay published it for `PUBLISH_LEAD_SECS` (3600 s, by its `created_at`), unless it is among the first keys this relay ever recorded; until then `GET /v1/account/entitlement` is 503 `busy`. A rotation: publish the next key in the file, restart, wait an hour, make it the signing key and the old one a published key, restart, and drop the old one from the file a day later. No route takes the token as a credential.

### 33.10 Directory version 1006

`DIRECTORY_VERSION` is 1006 (`BEFORE_ACCOUNTS_VERSION` 1005; the step is one constant, so it can be renumbered if another plan lands a step first). `MIGRATE_ACCOUNTS`, additive, in the transaction that moves 1001 to 1005 up: the table `team` is rebuilt with the kind `account` and the columns `account_id`, `vault_id` (SQLite cannot widen a CHECK; the rows are copied and `team_legacy` is made again), and the tables `account` (with `recovery_key` and the last recovery), `account_device` (with `added_by`), `account_list` (the signed device lists, one row for each entry with its device name, its signature, and its hash), `account_key` (with `account_id`), `account_link`, `account_join`, `account_store_device`, `account_store_removal`, `brain_event`, `"group"`, `group_member`, `group_invite`, `stripe_customer`, `stripe_subscription`, `stripe_event`, `tunnel_node`, `tunnel_grant`, `tunnel_usage`, and `entitlement_key` are made. `stripe_subscription` has the columns of billing (34.10), `last_invoice_created` and `stores_deleted_at` included. A new file runs the 1005 schema and then the same step, so a new and a migrated file have the same schema. Nothing in them is secret; tokens, link codes, recovery codes, client addresses, and the signing key are never stored. The images before refuse 1006. The step was not released before it took its final form: a file of 1006 (or one taken back to 1005) without `account_list.name` (no device list, or entries that sign no device name) or without `account_list.team_id` (no entries of contract section 16) holds an earlier build of it and is refused at open with a message to restore the backup taken before that build. The step also makes `account_peer_link` and `account_peer_join` (33.13).

The way back in place: `apassy-relay downgrade-directory-1005 --delete-vault-stores` (`Directory::downgrade_to_1005`), with the relay stopped: the vault store rows, their device map, and their waiting removals go and the version is 1005, in one transaction; then their files are deleted. Without `--delete-vault-stores` a directory that holds vault stores is refused (`409 conflict`, nothing changed), so no command for the old team files deletes a paid store by mistake; `downgrade-directory-1004` and `-1003` take the same flag. The downgrade commands open `relay.db` as `Directory::open` does: a plain file in `connect` mode, else keyed. Every other table and column stays (the 1005 image never reads them; the next open of 1006 keeps them). `downgrade-directory-1004` and `-1003` take a 1006 file down with the same step first. docs/OPERATIONS.md section 26.3.

### 33.11 Tests

`tests/server_account.rs`, on free loopback ports and temporary directories, with a `Plans` of the test: an account only with a valid signature over its recovery key and one key for one account; sign-in refused for another origin, another domain, and a used or made-up nonce, a refused call that uses nothing, and later challenges that never end an earlier one; a removed device (revoked, or of a deleted account) that learns it only from its own signed sign-in; a link of one use and 600 s; a join only with the confirmation and the signed `add` entry of the link's device and the same words on both sides (the vectors, this relay and the app), and a cancel only with the joining key's signature; the signed device list of root → B → C and a revoke of B, which keeps every entry before it, refuses a change over an old head (409) or without a valid statement (400), and is bounded (403 `account_limit`); the vectors of the list (names, the signed root); the root statements of creation and recovery and the device's account id; an `add` taken at 822 and refused at 823 while removes up to 1024 (the last device by itself at 1024) and the recovery after them work; a store add that races a revoke and maps nothing; a removal left by a crash after its commit that lands when the store opens; the used nonces of one key that leave another key alone; the nonces of a vault store that never end another and work once; a key off the curve refused on every route that takes one; a store add only with the checked key and a store delete only by a device in it; a revoke that ends the token at once and removes the device from every store, and one that waits for a suspended store or a file that refuses the write and lands at a resume, the maintenance pass, or a restart; a vault store as a relay-sync team with the account key (push, chain, receipt, plan gates, relay sync only); no store access for another account without a group; recovery only with no live device and the recovery key's signature, deleting the stores, a new root, the same answer for a repeat, and the counts and limits of failed signatures only, for each account and each prefix (a valid signature recovers also when the account, the prefix, or `unknown` is limited), and the same answers for an unknown and an existing account over six wrong tries and at the limit of the prefix; the caps of new accounts (relay, prefix); the pruning of links, joins, account audit rows, revoked devices, and delivered I-4 events (an undelivered one stays); published keys from the configuration only and the hour of a new signing key; the entitlement token with the published key (this relay and the app), refused after `exp`, with a changed claim, or another key; `open_plain` and `connect` mode against a master key, plain files in `connect` mode, and the downgrade commands on them; directory 1006 to 1005 and back, the refusal of an earlier build of the step, and the rollback note; 404 without the setting; and the app's `src/connect` client against the relay. `tests/server_group.rs`: a group removal that goes on past a store that refuses the write, a member added to a store again (after a newer share and its own join), which ends the removal that waited for it, and a confirmation that Stripe refuses, which removes the store rows of its window (`a_confirm_that_stripe_refuses_removes_the_store_rows_of_its_window`). Unit tests: the routes and value forms, the stateless nonce, the full sign-in tables, the used nonces of one key, the nonce clock that never goes back, and the recovery counts, an unknown id's in its own table with the rule of an existing one (`account::tests`), the nonces of a vault store (`devices::tests`), the message forms, the link fingerprint, and the recovery key (`device::tests`), the settings (`config::tests`), the token (`entitlement::tests`), the token forms (`secret::tests`), the need (`auth::tests`), and the directory steps (`directory::tests`).

### 33.12 What this does not protect

- Connect sees the public keys, names, and platforms of the devices, the vault ids, the times of sign-ins (rounded to the hour), and which devices share a store. It never sees a link code, a recovery code, a vault key, or a value.
- The per-address limits of the edge routes are the Worker's (contract section 3); the relay bounds the tokens, the used nonces (30 of one key that have not expired, a nonce living 60 s, 429 for that key; 100000 in all, 503; for a vault store 30 of one key and 1000 a store), the requests of one device to the routes of section 16 (`peers::PeerCalls`: 60 in a fixed window of 60 s from its first request, then 429 `rate_limited` with `Retry-After` until the window ends; at most 100000 devices counted at once, 503 `busy` for a new one), the new accounts of a prefix, and the failed recovery tries in memory only, so a restart resets them (and ends every account token and open nonce). A nonce carries its expiry on a clock that follows the wall clock forward and never goes back, so a wall clock that is set back never makes a used nonce valid again.
- The I-4 events (`brain_event`) are recorded, not sent: the delivery to the bouncer brain and its internal routes (contract section 11) are a later unit, which marks each event delivered (`done_at`); an event is pruned 90 days after its delivery and never before it.
- The relay cannot change the device list for an Apassy client, but it can withhold its newer entries from a client, which then keeps the last list it verified (connect-account-v1 section 7.5). For a shared vault it can withhold an `unshare` or a removal, give a new device an old prefix, or keep the devices of a share apart (section 16.8); it can never add a member or a key to a share.

### 33.13 Vaults shared between accounts

The wire is contract section 16; the code is `server/peers.rs` with three hooks in `server/account.rs` (`next_entry`, the share condition `ACTIVE_SHARE` of `share_active`, `may_join_store`, and `store_device_live`, and the early check of `store_device_add`), the mark of a group removal in `server/group.rs`, and the push rule in `http::vault_store_allows`.

- **The entries.** `account_list` holds the entries that name another account in the chain of the device entries (`op` `peer`, `unpeer`, `share`, `unshare`, `join`, `leave`; `key` is NULL; `peer_account`, `peer_root` of a `peer`, `team_id` of a store op). `GET /v1/account` and every answer that carries a list give them with `account_id`, `root`, and `team_id`; a device entry carries none of the three.
- **`POST /v1/account/list`** takes `{"version","op","account_id","root","team_id","statement"}`, strict. In this order: the shape (400); for a `peer`, `share`, or `join` both accounts active in one group (`Groups::share_group`, 403 `not_in_group`); for a `share` an entitled Family or Team plan of both (`Plans::plan`, 403 `plan_required`); then in one transaction the group and the plan again where the seam reads on the open transaction (`Groups::share_group_on`, `Plans::plan_on`; `DirectoryGroups` does, the plans of billing do not yet and keep the answer read before), so a group removal that commits between the two refuses the entry; `next_entry` (409 for another version, 403 `account_limit` for the room, 401 for a signer that is not live in the list), the signature over `device::share_list_message` with the head's hash (400), the rules of section 16.1 over the stored list (`ListState`: 409, 403 `account_limit` over 64 peers or 128 shares and joins), a `peer` root that is the key of version 1 of the other account's list (409), a `share` of a store that the caller's account made (403 `forbidden`, 404 for no store), a `join` of a store that the other account made and shares with the caller by the share condition below (409). A `join` writes the version of the owner's `share` it follows (`account_join_share`). An `unshare` queues the removal of the other account's store rows of the store, and a `leave` of the caller's own, in the same transaction (`hub::queue_store_removal`; the files take them after the commit, 33.5). A `peer` confirms the pending answers of that account to the caller's share codes. Each entry writes the relay audit row `account_list_peer_entry`.
- **Share codes.** `POST /v1/account/peers/link` keeps the link hash for one member of the group (`account_peer_link`: one use, 600 s, at most 3 of one device that have not expired, used or not, 403 `account_limit`; 403 `not_in_group` for another account, checked again in the transaction). `POST /v1/account/peers/join` takes the signed answer of a device of that member (`device::peer_join_message` with the member's root, the key of version 1 of its list; 400 otherwise), checks the group again in its transaction, uses the code (403 `forbidden` for an unknown, used, expired code, one of a revoked device, or one for another account), and keeps the answer with the SHA-256 of its body (`account_peer_join`; the same body again answers the same); a new answer ends the oldest pending answers to the codes of the same device beyond `peers::PENDING_PER_DEVICE` (8, `expired`). `GET /v1/account/peers/pending` gives the device that made a code at most 8 pending answers (the newest, in their order, SQL `LIMIT`) with the answering account's list, read after the answers, each account's once and in a lock of its own (also the inviter's list of `POST …/join` and the list of `GET /v1/account/peers/{account_id}`); `GET` and `DELETE /v1/account/peers/join/{id}` serve the two devices of an answer (404 for any other; `DELETE` by the maker refuses, by the answerer withdraws, a decided answer stays). A revoke (`DELETE /v1/account/devices/{id}`) ends, in its transaction, the share codes of the device, the pending answers to them, and the pending answers that it gave. The codes and their answers are pruned a day after they end, with the device links (`account::prune`). Every route of this section, `POST /v1/account/list` too, counts for the calling device before its body is read (33.12).
- **The other account's list.** `GET /v1/account/peers/{account_id}` answers its name, its live device rows, and its list from version 1, only within one group (403 `not_in_group`).
- **Stores: the share condition.** A device of another account than the one that made a store is added (`store_device_add`, `may_join_store`) only while `ACTIVE_SHARE` holds: the last `share` or `unshare` of the owner's list for that store and that account is a `share` (an index on `account_list(team_id)`); that share is newer than the owner's version in `account_share_void` for that account (below); the owner's last `peer` entry of that account pins the key of version 1 of that account's list now (after a recovery of the member its new devices are neither added nor signed in until the owner's `unshare`, `unpeer`, `peer` of the new root, and `share`); and both accounts are active members of one group. It signs in (`store_device_live`) only while, besides, the member's list has an active `join` of the store naming the owner (no later `leave`) whose recorded share (`account_join_share`) is that active `share`: the owner may add the member's devices first (the ceremony of section 16.2), and they sign in after the member's `join`; after a `leave`, or after a newer `share`, the member signs in again only after a new `join`.
- **A group removal is never a grant.** `DELETE /v1/account/group/members/{account}` writes, in its transaction, for every account whose list has a `share` naming the removed account, the head version of that list into `account_share_void` (`peers::void_shares_naming`, an index on `account_list(peer_account)`). After a new admission no `share` up to that version counts: only a newer `share` (the owner's `unshare` and `share` again) and the member's `join` after it give its devices the store again. A recovery of the owner drops its marks with its list. A confirmation that goes back to pending (Stripe refused the seats) removes the store rows between the member and the group's other accounts that came in its window, in the same transaction.
- **Pushes.** A push to a shared store needs an entitled plan of the store's account and of the pushing device's account (33.5); a member beyond the paid seats, or one with a read-only plan, pulls and downloads, and its push is 403 `plan_required`.
- **Directory.** The columns and the tables (`account_peer_link`, `account_peer_join`, and the marks `account_share_void`, `account_join_share` with the index `account_list_named`) are part of the accounts step of 1006 (33.10): the step was not released before it took this form, and a file of 1006 without `account_list.team_id` is refused at open as an earlier build. A file of 1006 without the marks (a build before them) gets them at open, additive (`directory::SHARE_MARKS`).
- **Tests.** `tests/server_share.rs`: each check of the list route, the plan and group conditions (a plan on one side only, `a_share_needs_the_plan_on_both_accounts`), a share code of one use for its member, the other account's list within one group, the removal of the store rows in the transaction of an `unshare` and a `leave`, a store row without the share that is no live store device, the member's sign-in only after its `join`, the bounds (`each_adding_entry_stops_at_822_and_each_end_works_up_to_1024`: `peer`, `share`, `join` taken at 822 and refused at 823, `unshare`, `unpeer`, `leave` up to 1024; `add` and `remove` in `tests/server_account.rs`; 64 peers; `a_list_holds_at_most_128_shares_and_joins`), the refusal of an earlier step, `a_member_that_recovers_gets_no_new_device_into_the_shared_store`, `a_removal_from_the_group_grants_nothing_after_a_new_admission`, `a_member_that_left_signs_in_again_only_after_its_own_join`, `an_unshare_that_races_a_store_add_maps_nothing`, `a_used_code_counts_until_it_expires_and_pending_answers_are_bounded`, `a_revoked_device_ends_its_share_codes_and_answers`, `an_answer_is_refused_by_its_maker_or_withdrawn_by_its_answerer`, `another_accounts_key_signs_no_entry`, `a_device_that_its_list_removed_signs_no_entry` (401), `a_read_only_member_pulls_a_shared_store_and_does_not_push`, and `the_routes_of_shared_vaults_count_for_each_device`; `tests/server_group.rs` (33.11); `tests/app_vault_share.rs`: two accounts of a family share a vault with the app's client through the ceremony, sync it both ways, and end the share; the Worker's `shared vault rate limit` (`deploy/worker/test/index.test.ts`).

## 34. Billing

ADR 0037 stage 7, D3 (docs/design/implementation-plan-s7-connect.md of the core, unit C2; contract `connect-billing-v1` of the core, which wins over this section where they differ). Connect sells three plans through Stripe Checkout and the Stripe Customer Portal, with no Stripe SDK: `src/server/stripe.rs` is the Stripe client and the webhook check, `src/server/billing.rs` the plans, the plan state, and the handlers. Section 33 (Connect accounts, unit C1) gives the account, the account token, and the directory tables; this section numbers its parts on the assumption that C1 takes 33.

**Wired (unit CW):** with the account routes on (`APASSY_RELAY_CONNECT_ACCOUNTS=1` or `connect` mode) and both Stripe files set, `Hub::open` makes billing on the directory tables (`server/billing_store.rs`, `DirectoryBilling`) and installs it as the `Plans` seam of the accounts (`BillingPlans`): the plan of every account, its people for the store limit, and the cancel of `DELETE /v1/account` come from it. The routes are in 34.11, the maintenance pass in 34.6, the settings in 34.7. Without the Stripe files the billing routes answer 503 `busy` and no account has a plan; without the account routes nothing of this section exists (every path is 404).

### 34.1 Rules

- **Prices are configuration.** No amount is in code. Connect resolves the prices of six lookup keys (`connect_<plan>_<month|year>`) at start with `GET /v1/prices?lookup_keys[]=…&active=true&expand[]=data.tiers` and keeps them for an hour (`PRICE_TTL`); a failed lookup keeps the last prices, and the next lookup waits a minute (`PRICE_RETRY_SECS`): until then `GET /v1/plans` answers the last prices, or `503 busy`, without a call to Stripe. A price is used only in the form of the contract: `eur`, `tax_behavior=inclusive`, recurring at the interval of its key; Personal and Team `per_unit`; Family `tiered` and `graduated`, tier 1 `up_to=4` with a flat amount, tier 2 `up_to=inf` with the unit amount of each further person. A price that fails is logged and left out, so its plan or interval is not offered.
- **State only from Stripe.** A subscription's status, plan, and quantity change only on a verified webhook (34.5) or on Stripe's answer to Connect's read of that subscription (`GET /v1/subscriptions/{id}`, the maintenance pass of 34.6), with the same rules (`billing::apply_subscription`). The webhook makes the groups, and gives a group the kind of its owner's new plan while the owner is alone in it (34.5). Connect writes its own facts only: the customer it makes before an account's first checkout (34.3), the open checkout session, a quantity Stripe accepted from Connect (34.4, and the quantity 1 of a Connect Personal plan, 34.6), the problems it records for the operator (34.5), the time of its last read of a subscription, the clock of the deletion pass, and the mark of deleted stores.
- **What Stripe gets:** the account id (`client_reference_id`, `metadata[account_id]`, `subscription_data[metadata][account_id]`, the customer's `metadata[account_id]`), price ids, quantities, customer, session, and subscription ids, and the site URLs. Never a device key, a token, a vault id, a device name, or a value.
- **Only Stripe's pages:** a Checkout Session's `url` must be a page of `https://checkout.stripe.com/` and a portal session's of `https://billing.stripe.com/` (`stripe::is_stripe_page`); another answer is `502 upstream_failed`. The Mac opens no other (`connect::account`, `stripe_page`).
- **Every Stripe call** carries `Authorization: Bearer <restricted key>`, `Stripe-Version: 2025-03-31.basil` (the version of the webhook endpoint), and form encoding; every POST an `Idempotency-Key`. A transport failure, 409, 429, or 5xx is tried once more with the same key. A Stripe refusal is `502 upstream_failed`; an outage or 429 is `503 busy`. The client accepts `https://` bases, and `http://` on a loopback address only (the fake server of the tests).
- **Logs** name event ids and types, Stripe object ids, account ids, HTTP statuses, and Stripe's error type and code. Never an email, a key, a body, or Stripe's error message.

### 34.2 Plans and totals

| Plan | Unit | Included | Max | Stripe quantity |
| --- | --- | --- | --- | --- |
| `personal` Connect Personal | account | 1 | 1 | 1 |
| `family` Connect Family | person | 4 | 10 | people |
| `team` Connect Team | member | 1 | 250 | seats |

The total for `n` units is `amount + max(0, n − included) × extra` for `1 ≤ n ≤ max` (`billing::total_cents`); a count outside is `409 seat_limit`. A Family of 2 pays the price of 4; a Family of 6 pays 700 a month or 7000 a year in the default configuration. `GET /v1/plans` (public) answers the `PlansView` of the contract from the resolved prices (`Billing::plans`); a plan without a usable price is left out.

### 34.3 Checkout

`Billing::checkout(account, body, now)` takes `{"plan","interval","people"?,"seats"?}` with unknown fields refused: `people` for Family only, `seats` for Team only. Refused: an account that is a pending or active member of a group (not its owner), or one whose plan is entitled (`409 conflict`: the portal changes a plan); an account whose Stripe customer has a subscription that is not over (`GET /v1/subscriptions?customer=…&status=all`: any status but `canceled` and `incomplete_expired`, so also `past_due` beyond the grace, `unpaid`, `paused`, and `incomplete`; Stripe's list is read page after page with `starting_after`, and a list longer than ten pages of 100 (`stripe::MAX_LIST_PAGES`) counts as such a subscription), `409 conflict`: the account pays it or ends it in the portal first, so it never pays for two plans; a count outside the plan (`409 seat_limit`); a plan without a usable price, or a Family price whose tier 2 differs from `APASSY_CONNECT_FAMILY_EXTRA_CENTS` or `_YEAR_CENTS` (`503 busy`, logged). An owner whose plan lapsed may buy again. A plan of the group's kind keeps the group, and a count below the active members, the owner included, is `409 seat_limit` ("The family has 3 people; choose at least 3."). A plan of the other kind (Family and Team) is `409 conflict` while anyone else is in the group, active or pending; with the owner alone the group takes the new kind when the subscription arrives (34.5). Connect Personal is `409 conflict` while the group has other active members.

Before an account's first session Connect makes its Stripe customer (`POST /v1/customers` with `metadata[account_id]`; the idempotency key is a hash of the account, so two first checkouts at once get one customer) and stores it in `stripe_customer`. The form is the contract's, in its order (`billing::checkout_form`), plus `tax_id_collection[enabled]=true` for Team, and always `customer` with `customer_update[address]=auto`; for Team also `customer_update[name]=auto` (Stripe saves the business name of a collected tax id on the existing customer).

Sessions (`stripe_customer.checkout_*`): a request is a hash of the plan, the interval, the count, and the price id. The list of subscriptions is read first. A repeated request gets the stored session while Stripe shows it `open` (`GET /v1/checkout/sessions/{id}`). Otherwise, in this order: every open session of the account ends (`Billing::end_sessions_locked`): the ones Stripe lists for its customer (`GET /v1/checkout/sessions?customer=…&status=open`, page after page, also sessions Connect no longer stores) and the stored one, each with `POST /v1/checkout/sessions/{id}/expire`; a session that Stripe does not expire counts as ended only when Stripe shows it is not `open`, else the request is `503 busy` and no session is made; when a session was ended, the list of subscriptions above is read again, so a session that completed just before it ended shows its subscription there; then a new session with a fresh idempotency key, which a retry of the call reuses, stored under the account's lock (the lock under which the deletion of 34.6 checks for a stored session). The checkouts of one account run one at a time (a lock of each account's checkout), so two requests at once leave one open session in every branch: the second gets the session the first stored, or ends it before it makes its own. The answer is `{url, session_id, expires_at}`. When an account joins a group (`POST /v1/account/group/join`), `Billing::end_open_checkout` ends its open sessions the same way under the same lock, so a checkout that runs at the same time stores its session first and the join ends it; a session that cannot be ended stays stored and is logged, and a subscription it makes that cannot bind is recorded (34.5).

### 34.4 The portal, seats, and cancellation

- `Billing::portal(account, body)`: `{}` only. A member that is not the owner: `403 forbidden`; no Stripe customer: `404 not_found`. `POST /v1/billing_portal/sessions` with `customer` and `return_url=<site>/connect/done`.
- `Billing::change_seats(account, body, now)`: `{"quantity"}` from the active owner of a group (another member: `403 forbidden`; an account outside, or pending: `403 not_in_group`), through `Billing::request_group_quantity(group, quantity, now)`, which takes the lock of the group (`Billing::with_group_lock`). C3's confirm holds that lock itself and calls `Billing::request_quantity_locked`. The group's plan is `Billing::group_plan`: its subscription of the group's kind with the best state (34.6). Refused: no entitled group plan (`403 plan_required`); a count outside the plan or below the active members, the owner included (`409 seat_limit`, "The family has 5 people; choose at least 5."). The quantity at Stripe (`SubscriptionRow::effective_quantity`: one Stripe accepted from Connect since the last subscription event, else the stored one) again answers `pending: false` without a call. Otherwise `POST /v1/subscription_items/{item}` with `quantity` and `proration_behavior=create_prorations`, with a fresh idempotency key for each change, and the answer `{quantity, pending: true}`. When that call ends in a timeout, a 5xx, or 429 (the change may have happened), Connect reads the item (`GET /v1/subscription_items/{item}`): Stripe's quantity equal to the one asked counts as accepted; otherwise the error stands. Stripe applies it at once: Connect records it (`requested_quantity`, `requested_at`) and counts it until a subscription event carries that quantity, or one more than 5 minutes newer carries Stripe's word; the stored quantity is always Stripe's.
- `Billing::cancel_for_account_deletion(account)` (for `DELETE /v1/account`), under the account's checkout lock, in this order: every open checkout session of the account ends first, as for a new checkout (34.3: those Stripe lists for its customer and the stored one), so none can make a subscription later; then `DELETE /v1/subscriptions/{id}` for each subscription that is not final (anything but `canceled` and `incomplete_expired`, so `unpaid` and `paused` too; a 404 counts as ended): the stored ones and those Stripe lists for the account's customer; then Stripe's list is read once more, and a subscription that appeared in between (a session that completed just before it ended) is canceled too. A Stripe error in any step, a session that stays open, or a list longer than ten pages refuses the deletion, and nothing is deleted. Then the email copy is deleted. The customer row stays for support; the state changes with the webhook.

### 34.5 The webhook

The route (34.11) refuses first, before it reads a byte of the body and with nothing to drain: a declared length above 256 KiB (`413`), and a `Stripe-Signature` header that is missing, malformed, or whose `t` is more than 300 s from the relay's clock (`Billing::webhook_precheck`, `stripe::check_signature_header`; `400`). Then `Billing::webhook(signature, body, now)` checks, in this order, and every refusal changes nothing:

1. the size: above 256 KiB (`MAX_WEBHOOK_BODY`) is `413 payload_too_large`;
2. the signature (`stripe::verify_signature`): `Stripe-Signature: t=<seconds>,v1=<hex>[,v1=…]` (at most 4 KiB, 8 `v1`; one `t`; other schemes ignored); HMAC-SHA256 with the endpoint secret over `<t>.<body>`, compared with `ring::hmac::verify`; `|now − t| ≤ 300`. A failure is `400 invalid_request` ("The Stripe signature does not verify."); the log names the reason. The `t` of a verified event is kept as the latest time seen from Stripe (34.6);
3. the event JSON (`id` of form `evt_…`, `type`, `created`, `data.object`): `400 invalid_request`;
4. the event id, stored in `stripe_event` in the same transaction as the effect: a repeat answers `{"received":true,"duplicate":true}` and changes nothing. A failed transaction keeps no id, so Stripe retries. The effect runs under the lock of the event's account (`Billing::with_account_lock`), so it never overlaps the deletion of that account's stores.

The effects (fields as the contract's table; every other field ignored):

- `checkout.session.completed`: needs `mode=subscription`, `client_reference_id` equal to `metadata.account_id`, a known account, and `cus_`/`sub_` ids. An account bound to another customer, a customer bound to another account, or a subscription bound elsewhere is not applied. Stores the customer with the email copy, clears the stored open session when it is this one, and binds the subscription (`incomplete` until its own event).
- `customer.subscription.created|updated|deleted` (`billing::apply_subscription`, also for Stripe's answer to a read): a known subscription must keep its customer and account; a new one needs a known account in `metadata.account_id` and a customer not bound elsewhere. An event older than the last applied subscription event of that subscription is ignored (a `created` with the same `created` time too); `canceled` and `incomplete_expired` are final: an event of another status after them is ignored. The plan and the interval come from the price (`billing::plan_of_price`): its lookup key, else `metadata.apassy_plan` with a monthly or yearly interval (a price that a newer one of the products script took the key from), else a stored subscription keeps its plan and interval; a price Connect cannot map gives no plan (the subscription is stored, gives no plan, and is recorded). The status always applies. Stores the item, the quantity (Stripe's, whatever the members; 34.6 decides who it pays for), the status (`deleted` is `canceled`), `cancel_at_period_end`, and the period end (of the item, else the top level). The end of an ended status is `ended_at`, else the one stored, else the event time. `active` and `trialing` clear the failure time; `past_due` without one starts the grace at the event time. A Family or Team plan makes its group with the buyer as the active `owner`, or binds to the group the buyer owns when it is of the plan's kind; a group of the other kind takes the plan's kind (`set_group_kind`; its open invites go) when the buyer is alone in it and no subscription of its kind is entitled. A buyer that is a member of another group, or owns one of the other kind with others in it, leaves the subscription without a group: while it charges it is recorded (`no_group`), and the maintenance pass tries to bind it again (34.6). A price of Connect Personal with a quantity above 1 that charges is recorded (`personal_quantity`); a price Connect cannot map on a stored Personal row is not (it keeps the plan and never leads to a quantity change). A known subscription of a deleted account whose status charges is applied and recorded (`deleted_account`), checked after the final status and the order of events, so an older event that arrives late records nothing; no group is made for an account that no longer exists. A plan that is not of its group's kind (a portal switch from Family to Personal) keeps the group and records the time (`kind_left_at`); the group's kind again clears it.
- `invoice.paid` and `invoice.payment_failed`: the subscription of `parent.subscription_details.subscription` (or `subscription`) must be known and have the invoice's customer; an invoice event older than the last applied one is ignored. `paid` clears the first failure; `payment_failed` sets it if none is set.
- Any other type: stored id, no effect.

An event that does not apply is logged and answered `200` with its id stored, so Stripe does not retry it. When its subscription charges (`StripeStatus::charges`: `active`, `trialing`, `past_due`, `incomplete`, `unpaid`; or a completed checkout) and its account or customer is known (also the customer of a deleted account), it is recorded for the operator in the same transaction: one `billing_problem` row for each subscription or session (with the account, the customer, the event, a reason: `bound_elsewhere`, `unknown_price`, `deleted_account`, `no_account`, `unknown_account`, `no_group`, `personal_quantity`, and from the pass `raise_refused`; later events count on it). A row that opens again after it was resolved, or an open row recorded with another reason, takes the new reason; the audit row `billing_problem_recorded` (actor `billing`, ids only) is written for a new row, a reopened one, and a new reason, so the audit keeps every earlier reason. Connect closes a problem that it resolved itself, with the audit row `billing_problem_resolved` (actor `billing`, the reason, and how): `no_group` when the subscription binds to a group (the pass of 34.6 or a later event) or no longer needs one; `personal_quantity` when Stripe accepted quantity 1 from the pass, or a later event or read shows one unit, another plan, or a status that does not charge. `apassy-relay admin readiness` shows the count of open problems (`billing.open_problems`); `apassy-relay admin billing` lists them, and `--resolve <id>` closes one after the operator canceled or refunded it in the Stripe dashboard. The answer is `{"received":true,"duplicate":false}`.

### 34.6 The plan state

`billing::plan_state` is a pure function of the stored subscription and the time (contract section 8; `plan-states.json`). `PlanState::allows` gives the permissions: a new store, a push, a dial, and an entitlement token need `entitled`; a pull and a download also work in `read_only`. `PlanState::require` answers `403 plan_required` ("This account is not on Apassy Connect.").

| Stripe status | Plan status | Times |
| --- | --- | --- |
| none | `none` | — |
| `incomplete`, an unknown status | `pending` | — |
| `active`, `trialing` | `active`, `trialing` (entitled) | `renews_at` = period end, or `ends_at` with `cancel_at_period_end` |
| `past_due`, `now <` first failure + grace | `past_due` (entitled) | `grace_until` |
| `past_due` beyond the grace; `canceled`, `unpaid`, `incomplete_expired`, `paused` | `read_only` while `now < end + read-only days`, then `suspended` until `end + delete days`, then `none` | `read_only_until`, `delete_at`; `grace_until` stays for a past due |

`end` is `grace_until` for a past due beyond its grace, else the stored end, else the period end; a past due without a failure time counts the grace from the period end. The account's `PlanView` (`billing::account_plan`) comes from its own subscriptions and, for an active member that is not the owner, from every subscription bound to its group; a subscription whose price Connect cannot map gives none. The best state wins (`PlanState::rank`: entitled, then `read_only`, `suspended`, `pending`), then the newest: a late event of an older subscription never hides a paid one. For a member:

- a subscription of the group's kind gives its state only to the members it pays for (`SubscriptionRow::seats_paid`: the quantity at Stripe, for Family at least the 4 included), counted by `member_rank`: the owner first, then the earliest `joined_at`. A member beyond them is `read_only` without times, and is never deleted for it;
- a subscription that left the group's kind (`kind_left_at`) gives the read-only window of a plan that ended at that time (`read_only`, then `suspended`, then `none`), without `delete_at`.

A pending member has `none`. The `group_id` of a view is set only for a plan of its group's kind.

`Billing::maintenance(now)` prunes event ids older than 30 days and lists each ended plan of a mapped price whose `delete_at ≤ now`, whose stores were not deleted, and that Stripe was not read for in the last day (`checked_at`; `DueDeletion`). `billing_store::maintain` runs at most once an hour on a thread of its own (`relay-billing`, `http::maintain_billing`), so a slow Stripe never holds the teams' pass, and then:

1. `Billing::reconcile`: each live subscription (`active`, `trialing`, `past_due`) whose period ended more than two days ago (`STALE_PERIOD_SECS`) is read from Stripe at most once a day (`RECHECK_SECS`, `checked_at`), outside the account's lock, and Stripe's state is applied under it, with the `Date` of Stripe's answer as its time (an answer without one applies at the time of the last applied event, never at the relay's clock); each live Family or Team subscription without a group is bound again (34.5), and one that still cannot bind is recorded (`no_group`) when no open problem names it; each live subscription stored as Connect Personal with a quantity above 1 (a portal switch from Family that kept the people) is read from Stripe first and the read applied, and gets quantity 1 at Stripe (`POST /v1/subscription_items/{item}`) only when Stripe shows the stored item, a price of Connect Personal, a quantity above 1, and a status that charges; the write requires the stored plan to be still Connect Personal with the same item, records the quantity as one Stripe accepted, and closes `personal_quantity` (a price Connect cannot map never changes a quantity); and, only with `BillingConfig::auto_raise_seats` (`APASSY_CONNECT_AUTO_RAISE_SEATS=1`, 34.7), each group whose entitled plan's quantity at Stripe is below its active members gets it raised to them (at most the plan's maximum), under the group's lock, with `create_prorations`; a raise Stripe refuses is recorded (`raise_refused`) and not asked again while that problem is open. Without the setting (the default) the pass raises no quantity: the members beyond the paid ones stay `read_only` until the owner raises the seats (`Billing::change_seats`), so Connect never charges an owner more without an action of the owner. A failed call is logged; the next pass tries again. The pass stops between subscriptions, groups, and due plans when the relay stops (`Billing::reconcile_until`, `billing_store::maintain_until`); the rest waits for the next pass;
2. `Billing::deletion_gate`: every pass records its time (`billing_clock.last_pass_at`); a pass more than two days (`MAX_PASS_GAP`) after the last one holds every deletion (`held_since`) until the operator runs `apassy-relay admin billing --resume-deletions` (audit row `billing_deletions_resumed`), which takes the current clock as right;
3. for each due plan, first outside every lock: `Billing::verify_ended` reads the subscription from Stripe, applies it, and stamps `checked_at`; the pass goes on only when Stripe shows an ended status (`canceled`, `unpaid`, `incomplete_expired`, `paused`) and the relay's clock is at most a day (`MAX_CLOCK_AHEAD`) ahead of the latest time it saw from Stripe (a verified webhook's `t`, an answer's `Date`). A Stripe that cannot be reached skips the plan until the next pass. The accounts are the buying account and, when `Billing::deletes_members` (the plan is of its group's kind and no subscription of the group still gives a plan), each active member. An account with a plan here keeps its data. For each other one, `Billing::deletion_blocked` asks whether anything keeps its data: an open billing problem of the account or its customer; a stored checkout session that Stripe shows `open` or `complete` (an expired one is forgotten); an open session that Stripe lists for its customer; or a subscription that Stripe lists for its customer and that is not over (anything but `canceled` and `incomplete_expired`, except an `unpaid` or `paused` one that Connect stores), or a list longer than ten pages. An account without a Stripe customer has nothing at Stripe (every session names the customer, made before the first one): its open problems and its stored session decide. A Stripe error counts as a reason to keep the data. While the buying account is kept this way, nothing of the plan is deleted, the data of its members neither. Then, under the lock of the buying account, `Billing::still_due` checks the plan again and `Billing::has_open_checkout` checks for a stored session again (a checkout stores its session under that lock, so a session stored after the questions above keeps the data), and the vault stores and the tunnel nodes of each remaining account go, each member under its own lock, only when its plan is `none` and it has no stored session. The audit row `plan_stores_deleted` (actor `billing`; the subscription, the account, the group, and the counts of accounts, stores, nodes, failures, and accounts kept waiting) and I-4 `forget` (`brain_event`) are written when something was deleted, an account failed, or the plan is done; `forget` goes to each account whose data went in this pass, and to every handled account when the plan is done. `Billing::mark_stores_deleted` marks the plan done when no account failed or waits. A failed or waiting plan is logged and read again a day later; the pass goes on.

Read-only and suspended are states that each request reads, not actions of the pass. A payment before the deletion (`unpaid` to `active`) keeps the stores; `active` again clears the mark. After an applied webhook or read that leaves an account (or a member of the group it owns) without an entitled plan, its open tunnel streams close (section 35).

### 34.7 Configuration

| Variable | Meaning | Default |
| --- | --- | --- |
| `STRIPE_SECRET_KEY_FILE` | A file with the restricted key (`rk_live_…`; `rk_test_…` or `sk_test_…` in a sandbox). A live secret key `sk_live_…` is refused. | required for billing |
| `STRIPE_WEBHOOK_SECRET_FILE` | A file with the endpoint secret (`whsec_…`) | required for billing |
| `APASSY_CONNECT_SITE_URL` | The https origin of the done, cancel, and join pages, without a path | `https://apassy.wyderka.cc` |
| `APASSY_CONNECT_FAMILY_EXTRA_CENTS`, `APASSY_CONNECT_FAMILY_EXTRA_YEAR_CENTS` | Tier 2 of the Family prices that checkouts expect | 100, 1000 |
| `APASSY_CONNECT_GRACE_DAYS` | Entitled days after the first failed payment (1 to 60) | 14 |
| `APASSY_CONNECT_READ_ONLY_DAYS` | Read-only days after the end (1 to 365) | 30 |
| `APASSY_CONNECT_DELETE_DAYS` | Days from the end to the deletion of the stores (above the read-only days, at most 730) | 90 |
| `APASSY_CONNECT_AUTO_RAISE_SEATS` | `1`: the maintenance pass raises the quantity of an entitled Family or Team plan at Stripe to its active members, with `create_prorations` (34.6). `0`: it changes no quantity, and the members beyond the paid quantity stay `read_only` until the owner raises the seats | 0 |

`config::billing_from` reads them into `ConnectConfig.billing` (`BillingSettings`): both files or neither (one alone stops the start), the six settings checked even without the files, and the site from `APASSY_CONNECT_SITE_URL` as section 33.1 checks it. The Stripe API base is `https://api.stripe.com`; no setting changes it. Only code sets another base (`BillingSettings.stripe_api_base`, the fake Stripe of the tests), and `Hub::open` refuses any base other than Stripe's own or a loopback `http://` address. The debug form of the settings never shows the key or the secret.

### 34.8 The edge Worker

`POST /v1/stripe/webhook` (exactly) has its own cap of 256 KiB (`MAX_STRIPE_WEBHOOK_LENGTH`), needs `Content-Length` (chunked is `400`), and has no per-address limiter: Stripe sends every event from a few shared addresses, and the signature is the relay's check. In its place the Worker refuses, before it forwards a byte, a `Stripe-Signature` that is missing, longer than 4 KiB, without one `t` of digits or without a `v1`, or whose `t` is more than 300 s from its clock (`400 invalid_request`). The Worker forwards the body bytes and `Stripe-Signature` unchanged. `POST /v1/account` and `POST /v1/account/recover` have `ACCOUNT_LIMITER` (namespace 1006, 5 a minute), keyed by the IPv4 address or the IPv6 /64; `POST /v1/account/challenge`, `/v1/account/token`, `/v1/account/devices/join`, and `/v1/account/devices/join/cancel` have `AUTH_LIMITER` (60 a minute, the full address), as connect-account-v1 section 3 says.

### 34.9 Tests

`tests/server_billing.rs` runs the handlers against `tests/common/fake_stripe.rs` (an in-process server on a free loopback port that records calls, replays idempotent POSTs, keeps sessions and subscriptions, and can fail, delay, or send a chosen `Date`) and `MemoryBillingStore`, with the fixtures of `tests/fixtures/connect-billing-v1/` of the core: also the paid seats, a re-buy for the members, the reconciliation, a price without its lookup key, final statuses, the group's plan over a late event, a switch to Personal, the customer before the first session, the problems for the operator, the read before a deletion, the clock gate, the price failure wait, and Stripe's page origins. `tests/server_billing_routes.rs` runs a relay with billing against the fake Stripe over HTTP: the price warm-up and the public plans (equal to `plans.json`), the checkout form, the raw webhook (exact bytes, a changed byte, another secret, 301 s late, no `v1`, 256 KiB + 1, a repeat, an unknown account, a refusal before the body), every plan state against a real vault store (push, pull, download, new store, entitlement token), the deletion day with its audit row, a deletion that Stripe shows live or cannot answer, a failed deletion that does not stop the pass, the held pass and the operator's resume, the problems in the operator's readiness, the account deletion, and the settings. The Connect tests run the billing pass themselves (`billing_store::defer_background_pass`). `tests/server_group.rs` (section 36) and `tests/server_connect_e2e.rs` (the app client end to end) use the same helpers (`tests/common/connect.rs`). `tests/connect_billing_sandbox.rs` is the test-clock flow against the Stripe sandbox, ignored unless `STRIPE_SANDBOX_KEY_FILE` is set, run only by `.github/workflows/connect-sandbox.yml` (manual).

### 34.10 Storage

`DirectoryBilling` keeps every billing transaction in one immediate transaction of `relay.db`: an event id and its effect commit together. `stripe_customer` (customer id, account id, the email copy, also copied to `account.email` for `GET /v1/account`; `checkout_session`, `checkout_request`, `checkout_expires_at` of the open session), `stripe_subscription` (the `SubscriptionRow`: ids, item, account, group, lookup key, quantity, status, period end, `cancel_at_period_end`, first failure, end, `event_created` of the last applied subscription event, `last_invoice_created` of the last applied invoice event, `stores_deleted_at`, `requested_quantity` and `requested_at`, `kind_left_at`, `checked_at`), `stripe_event` (id, type, time), `billing_problem` (object id, account, customer, event, reason, first and last time, events, `resolved_at`), `billing_clock` (one row: `last_pass_at`, `stripe_time`, `held_since`), `"group"` (with its `subscription_id`), `group_member` (the owner row of a new group). No card, address, or tax id.

### 34.11 Routes

| Route | Where | Notes |
| --- | --- | --- |
| `GET /v1/plans` | `http::respond_billing` | public: no `Authorization` (400 with one); 405 for another method; the cached prices (an hour), resolved at start on a thread of its own |
| `POST /v1/stripe/webhook` | `http::respond_billing` | the edge secret as every route; a declared length above 256 KiB (413) and the `Stripe-Signature` header with its `t` (400) before the body is read, and the refusal reads nothing (`abort_input`); then the raw body read up to 256 KiB + 1 byte (413 above, before the HMAC); then 34.5 |
| `GET /v1/account/plan` | `account::dispatch` | the `PlanView` of `Plans::plan` (also without Stripe: `none`) |
| `POST /v1/account/checkout` | `account::dispatch` | `Billing::checkout` (34.3) |
| `POST /v1/account/portal` | `account::dispatch` | `Billing::portal` (34.4) |
| `POST /v1/account/group/seats` | `group::dispatch` | `Billing::change_seats` (34.4) |
| `DELETE /v1/account` | `account::delete_account` | `Plans::cancel_for_deletion` = `Billing::cancel_for_account_deletion` before any row goes: a Stripe failure leaves the account as it was |

The account routes need the account token (section 33.2). Without the Stripe files every route of this table but `GET /v1/account/plan` and `DELETE /v1/account` answers 503 `busy`.

## 35. Tunnel and ingress

ADR 0037 stage 7, unit C4; the wire is docs/contracts/connect-tunnel-v1.md (the contract wins where this section is shorter). Code: `src/server/tunnel.rs` (the broker), `src/server/tunnel/frame.rs` (the frame and the stream rules), `src/server/tunnel/ws.rs` (WebSocket), `src/server/ingress.rs` (ports 443 and 80), and `src/server/tunnel_routes.rs` (unit CW: the broker on the account store, the routes, the start, the usage in `relay.db`, and the hooks of the other units). The tunnel exists only with the account routes (`APASSY_RELAY_CONNECT_ACCOUNTS=1` or `APASSY_RELAY_MODE=connect`, section 33): without them `Relay::start` makes no broker and no ingress, and every `/v1/tunnel/...` path is 404 `not_found` (35.10 to 35.13).

### 35.1 What the broker does

A node keeps one WebSocket (`GET /v1/tunnel/node`, subprotocol `apassy-tunnel-v1`). Each dial of a device (`GET /v1/tunnel/dial/{node_id}`) and each ingress connection is one stream of the frame mux `[stream u32 BE][kind u8][flags u8][len u16 BE][payload]` on it. The broker forwards bytes unchanged, stores none of them, and logs nothing: no content, no token, no client address. For each account and UTC month it counts dials, streams, and bytes (both directions, every stream of the account's nodes): `Broker::usage`, `usage_all`, and `restore_usage` (the store keeps them across a restart). Each stream belongs to one class of the node's account, with its own slots and counts (35.4): a dial of one of the account's own devices, a dial of a device of another account with a grant, a `public` stream of the ingress, or an `acme` stream of the ingress. The public streams have their own counters (`Broker::ingress_usage`), the ACME streams too (`Broker::acme_usage`), and so has each other account that dials the account's nodes (`Broker::grantee_usage`).

The broker asks the account store through the trait `TunnelDirectory`: the caller of a bearer token (`Refusal::Unauthenticated` is 401, `Refusal::AccountRequired` 403 `account_required`, `Refusal::Unavailable` 503 `busy`), the node of the caller's device and a node by id (each `Ok(Some(..))`, `Ok(None)`, or `Err(Unavailable)`), `has_grant(node_id, grantee_account)` and `entitled(account_id)` (each `Ok(true)`, `Ok(false)`, or `Err(Unavailable)`), and `budget_units(account_id)` (`Ok` of 1, or the people of Family, or the members of Team, or `Err(Unavailable)`). `Unavailable` means the store could not answer: it is never read as a "no". A device may dial a node of its own account, or of another account that granted its account (`tunnel::may_dial`). `MemoryDirectory` is the test implementation.

### 35.2 The checks before the `101`

`Broker::serve_node` and `Broker::serve_dial` take a `tiny_http::Request`, answer a refusal with the error envelope, or answer `101 Switching Protocols` with `Sec-WebSocket-Accept` and `Sec-WebSocket-Protocol: apassy-tunnel-v1` through `Request::upgrade_split`, and return at once; two threads carry the WebSocket after that. A dial is checked in the contract's order: 400 `invalid_request` (not an upgrade, another subprotocol, a body), 401 `unauthenticated`, 403 `account_required`, 404 `node_unknown` (also a malformed node id), 403 `not_in_group`, 403 `plan_required`, 429 `tunnel_limit`, 503 `tunnel_offline`. A node WebSocket: 400, 401, 403 `account_required`, 404 `node_unknown` (the device has no registered node), 403 `plan_required`, 403 `account_limit` (8 nodes of the account online), 429 `tunnel_limit` (all node WebSockets of the broker). A token, a node, a grant, or a plan that the directory cannot check now (`Unavailable`) is 503 `busy` in place of 401, 404 `node_unknown`, 403 `not_in_group`, or 403 `plan_required`, at every step of both routes: a client tries again with its backoff, and only a definite answer of the store is a 401, a 403, or a 404. The ingress gives such a name the alert of an unknown name.

A second WebSocket of the same node replaces the first: the old one gets close 4005, and its streams end (their dials get 4001). A node that goes away ends its streams the same way.

### 35.3 Streams

Connect opens every stream, with ids from 1 that only grow on one WebSocket. A dial opens a `device` stream with an empty `open`; each binary message of the dial (1 to 16384 bytes; more is close 1009) becomes one frame. A node's `close` ends the stream for its client, a dial and an ingress connection alike: from that frame on, Connect forwards and counts no more bytes of the client; the client gets the node's last bytes, then the dial closes with 1000 and an ingress connection is closed; and Connect closes the client's direction toward the node, so the stream ends on both sides. A node's `reset` closes a dial with 4004 and an ingress connection at once. A dial's WebSocket close and an ingress client's half-close send `close` (an ACME request carries it with its `open`). After a dial's WebSocket close the node has `Limits::close_grace` (10 s) from the close to close its side, then Connect resets the stream; a half-closed ingress client still reads, so there the 10 s are of silence: Connect resets the stream when for 10 s the node sends nothing on it and no byte of the node reaches the client (a slow reader keeps the node's stream, which waits for window, from being silent). Every half-closed stream ends at most `Limits::half_closed_life` (10 minutes) after the client's close. `frame::Sequencer` applies the rules of contract section 4 to both directions: a broken rule of a live stream resets that stream (a `reset` to the node, 4004 to the client) and leaves the WebSocket open; a frame for no live stream is dropped, and a `reset` is never answered with a `reset`. A malformed frame closes the node's WebSocket with 1002, a text message with 1003.

When Connect ends a stream whose `open` is still in the queue toward the node, the `open` and every queued frame of the stream leave the queue and nothing is sent: the node never hears of it. Otherwise its `reset` goes ahead of queued data, never ahead of its own `open`, and is never dropped (35.4).

On the node (`src/node/tunnel.rs` of the core), the TLS front ends a stream in one of two ways, and the node forgets the stream at once either way: a clean end after its last bytes (`Conn::finish`: the node's `close`, and Connect ends the stream once the bytes reached the client), or any other end (`shutdown(Both)`: a `reset`). So the node never keeps a stream whose own side is closed. The node keeps at most 64 `device`, 16 `public`, and 4 `acme` streams open, each kind in slots of its own (the classes of 35.4), so 16 open `public` streams never make the node reset an `acme` stream.

**Windows** (contract section 4). Each direction of a stream has a window: 64 KiB (`frame::INITIAL_WINDOW`) when it opens, spent by data and added to by the receiver's `window` frames (flag 0x08, a 4-byte u32 BE). The sequencer keeps both windows of each live stream (`Sequencer::credit`) and names data over a window, or a window over 16 MiB, `over_window`. Connect sends a client's bytes to the node only within the node's window: the client's reader waits for a `window` frame (backpressure to the client's TCP window), and frames of up to 16384 bytes go out as the window allows. Connect grants the node `Limits::stream_buffer` (256 KiB): the rest of it right behind the `open`, and then, each time the client has read a quarter of it, that much more (`window` frames ahead of the queued data, never ahead of the stream's `open`). The node does the same toward Connect for the front (256 KiB, a quarter at a time), and its writes wait for Connect's window up to the front's write timeout. So one stream never makes either side buffer more than it granted, a large answer to a slow client arrives whole, and a peer that ignores the window has its stream reset.

What a `device` stream reaches: the node's tailnet listener (`Scope::Tailnet`, 32.1), as on the tailnet. A `device` stream may carry sequential requests, never pipelined (35.6); a `public` stream carries one. Who can open one: every device of the node's account, every device of an account whose grant holds (36), and Connect itself, which can open any stream on a node's WebSocket. Inside, each runs TLS to the pinned node certificate (TLS has no client authentication: the device route's protection is the pin for the device and the tokens of the routes for the node). The routes that need no token there are the sign-in steps (`/v1/auth/challenge`, `/v1/auth/token`), a device link (`POST /v1/devices/link`, `/v1/devices/link/cancel`, with a one-use link code and the owner's confirmation with the safety words), and `/healthz`; every other route needs a device token of a team on the node. On a stream of the tunnel the tailnet listener answers `POST /v1/teams` (team codes), `POST /v1/join`, and `/v1/invites` with 404 `not_found`, as an unknown path (`http::TUNNEL_DEVICE_REFUSED`): no device needs a team code, an invite, or a join through Connect. Device links stay, so a device pairs through Connect. The front writes each tunnel stream down in process with the server name of its TLS handshake (`apassy::net::front_peers::register_tunnel_named`), and the listener knows it from the connection's addresses, never from a header. A `public` stream reaches the public listener (`Scope::Public`, 30.5): `/mcp`, `/p/`, and the MCP authorization flow, answered with the public origin of its server name (31.1); the public certificate is served only for the node's public name, so a `public` stream that the front pumps names it.

The frames of a stream are found by its id in the sequencer of its own WebSocket and go only to that stream's client: no buffer is shared between streams (the property tests interleave streams at random).

### 35.4 Limits and queues

`tunnel::Limits` (defaults; configuration, not wire constants). Each stream of an account's nodes is in one of four classes, each with its own slots and counts, so that no class can make another fail:

| Class | Slots (open at once) | Rate | Bytes a UTC month | Over it |
| --- | --- | --- | --- | --- |
| Dials of the account's own devices | `streams_per_account` (64), shared with the next row | `dials_per_minute` (60) a clock minute | the dial budget: `bytes_per_month` (20 GiB) for each budget unit, shared with the next row | 429 `tunnel_limit`; over the budget the dials close with 4002 |
| Dials of another account with a grant | at most `streams_per_grantee` (16) for each such account and `grantee_streams` (32) for all of them together, of the `streams_per_account`: the account's own devices keep the other `streams_per_account − grantee_streams` (32 with the defaults; the settings require `grantee_streams` at most `streams_per_account`, 35.11) | `dials_per_minute` (60) for each pair of (node account, dialing account), apart from the account's own | together at most `grantee_bytes_percent` (50 %) of the dial budget, the own devices keep the rest; one other account at most its part of that share, `streams_per_grantee / grantee_streams` of it (`Limits::grantee_each_budget`: 25 % of the budget with the defaults), so one never spends the others' part | 429 `tunnel_limit`; over its part that account's dials close with 4002, over the share all those dials; the own dials go on |
| `public` streams of the ingress | `ingress_streams` (16), slots of their own | `ingress_per_minute` (60) new streams for each node a clock minute, refused ones included | `ingress_bytes_per_month` (5 GiB) for each budget unit, a budget of its own | the connection is closed; over the budget the `public` streams end |
| `acme` streams of the ingress (the node's certificate renewal) | `acme_streams` (4), slots of their own | `acme_per_minute` (30) new streams for each account a clock minute, refused ones included, outside the `public` rate (the ingress's per-address limit, 35.7, holds too) | counted (`Broker::acme_usage`), in no budget: each carries at most 8 KiB in and 64 KiB out | port 80: 404 |

The node must send a first frame on a `public` or `acme` stream within `ingress_first_byte` (10 s), else the stream is reset. A dial is never refused because of the ingress or of another account's dials beyond their share, and the `public` streams never keep an `acme` stream out (only the broker's ingress share below holds both). Every `recheck` (60 s) the broker asks the directory again about the open streams: the streams of an account whose plan ended (also at the end of a period, without billing's hook) end with 4003, and so do the dials of another account whose grant no longer holds (the grant went, or the two accounts no longer share a group: a removed member, a group that ended). Only a definite answer ends a stream with 4003: a plan or a grant that the directory cannot check (`Unavailable`) skips the round for its streams, and a stream that skipped `recheck_skips` (3) rounds in a row ends at the next with 1013 (try again; the iPhone dials again with its backoff, not the 15 minutes of 4003). A round that answers starts its count again.

Also: 8 nodes online, pings every 30 s, a WebSocket closed after 90 s without a message (read and write timeouts), a stream reset after 15 minutes without a byte, at most `stream_buffer` (256 KiB, the window granted to the node) buffered toward one client, 1 MiB queued toward one node, 4096 node WebSockets and `max_streams` (4096) streams for the whole broker.

The broker's streams are split too, so that the ingress of many nodes together cannot fill them: the `public` and `acme` streams of all accounts together hold at most `Limits::ingress_cap()`, `ingress_share_percent` (50 %) of `max_streams` (at least 1 and fewer than all: 2048 of 4096 by default), and a dial is refused only when all `max_streams` are open. The dials (of an account's own devices and of other accounts alike) therefore always keep at least `max_streams − ingress_cap` (2048) streams of the broker, whatever the ingress holds; the ingress keeps its share against the dials only up to the free streams (a broker full of dials refuses the ingress too). Within the dials, the per-account slots above keep each account's own devices apart from other accounts. The month and the minute come from an injectable `Clock`. Each new stream asks `budget_units` again: a lookup that fails keeps the budget known before (with none known yet the stream is not refused or ended for a budget, and the next stream asks again), and a budget that changed is checked again, so a larger budget (more people) counts from the next new stream, also in a month that tripped; otherwise a month that tripped stays tripped until the first day of the next UTC month.

Every queue has a cap. Toward a node: data waits for the node's window and for room (backpressure to the client's TCP window), `open` frames and the first `window` behind each are bounded by the stream count, and resets, later windows, and pongs go ahead of the data in a queue that drops nothing: at most one queued pong (a new one replaces it), one reset for each stream that Connect ends, and one `window` frame (12 bytes) for each quarter window of node data that a client read. For a node that reads its WebSocket that is a few frames for each stream. A node that stops reading still has its frames counted within the windows Connect granted, so the queue grows by at most one window frame for each 64 KiB that its clients read, until the writer's write timeout (`Limits::idle_timeout`, 90 s) ends the WebSocket. Neither a reset nor a window goes ahead of its own stream's `open` (35.3). Toward a client: at most the window that Connect granted the node (256 KiB) waits, so a client that does not read never makes Connect buffer more: the node waits for window instead, and a node that sends over it has its stream reset; a node's writes for other streams never wait for one client. A client writer that is still inside a data write one maintenance tick after its stream was reset has its socket shut down; the close code itself is never cut off, so a dial that Connect ends always gets its code unless its client does not read.

### 35.5 WebSocket

`tunnel::ws` is this crate's own RFC 6455 code: `Cargo.lock` had no synchronous WebSocket crate, and the tunnel needs only binary messages, ping, pong, and close, without extensions; SHA-1 for the handshake comes from `ring`, already in the lock. It refuses RSV bits, unknown opcodes, unmasked client frames, masked server frames, non-minimal lengths, a 64-bit length with the top bit set, control frames over 125 bytes or fragmented, a continuation without a message, a new message inside a fragmented one, a message over its cap (checked before any allocation), a one-byte close payload, an invalid close code, and a close reason that is not UTF-8.

### 35.6 The vendored HTTP server

The relay's deadline transport refused every upgrade (`vendor/tiny_http/APASSY-PATCH.md`). It now passes a `GET` upgrade without `Content-Length` or `Transfer-Encoding` to the handler (anything else is still refused, and an upgrade ends the connection's requests). `Request::upgrade_split` ends the request's header, body, and handle deadlines, sets read and write timeouts of `Limits::idle_timeout`, makes the reaper forget the transport, and returns the read half, the write half, and a shutdown function. The read half is the buffered reader that read the head, so a first WebSocket frame in the same TCP segment as the handshake is kept (`tests/server_tunnel.rs`, `upgrade_keeps_bytes_sent_with_the_head`). A request asks for an upgrade by one rule, `tiny_http::asks_upgrade`: an `Upgrade` header, or the token `upgrade` (any case, comma-separated) in any `Connection` header; a value that only contains the letters, such as `x-upgraded`, is not one. The same rule decides in the three places: the guarded transport (refuses an upgrade with a body or of another method), the choice of the raw reader (only for a request that asks for an upgrade and has no `Content-Length` or `Transfer-Encoding`, so a body keeps its framing), and the relay's guard. Only the two tunnel routes take an upgrade: `http::handle` answers a request that asks for one on any other method and path with 400 `invalid_request` and `Connection: close`, before any other check (also before `/healthz`, the OAuth flow, the edge secret, and the proxy), before a handler sees it, and without reading a body. This holds on every listener (`Scope::Node`, `Scope::Public` with `/mcp` and `/p/`, `Scope::Tailnet` and the local route) and for the tunnel routes too on a relay without the account routes or on a listener other than the node listener. The transport itself still answers an upgrade with a body or of another method than `GET` with the same 400.

**Sequential requests on a device stream** (2026-11-11). A connection of the deadline transport serves one request and its answer says `Connection: close`, with one exception: a device stream of the tunnel on the tailnet listener (35.3) carries sequential requests, so that the iPhone reaches its Mac with one dial for the requests that follow each other (`apassy::sync::KeptDials`, ios-core-v1 section 5.15). The relay gives that listener `tiny_http::KeepAlive` with `allow` = `apassy::net::front_peers::is_tunnel` (asked when an answer is written; the TLS front of the process writes the stream down before its first byte, never a header) and `idle` = `server::TUNNEL_KEEP_IDLE` (45 s). Every other connection (the node and public listeners, the local route, a tailnet peer, a local process, a `public` stream of the ingress, the hosted relay) keeps one request per connection. On a kept stream:

- An answer keeps the connection only for an HTTP/1.1 request that asks neither to close nor to upgrade, whose body was read to its end, with an answer that does not close (a `413`, the upgrade guard's `400`), and when no byte of a next request waits on the socket; such an answer has no `Connection` header. Otherwise it says `Connection: close` and the connection ends, as everywhere else. An answer that cancels the request's input closes too: `/healthz`, 503 `busy`, and a route that is answered before its body is read (an unknown path, `http::TUNNEL_DEVICE_REFUSED`).
- Requests are never pipelined: the next head is read only after the answer before it was written whole; bytes of a next request that came before that close the connection, and that request is never served.
- Between two requests the first byte of the next head must come within 45 s; an idle connection closes without a byte (no `408`). From that byte on the request has the header (10 s), body, and handle (90 s, the reaper) deadlines of a new connection.
- The 45 s are above the iPhone's 30 s for a kept dial (the client closes first, so it never sends into a connection that the relay closes) and below the front's idle limit (120 s) and Connect's 15 minutes for a stream without a byte. A kept stream holds its slots meanwhile: a front connection, a `device` stream of the node (35.3: at most 64), one of the 1024 live transports, and a pool thread.

Tests: `vendor/tiny_http/src/keep_alive_tests.rs` (the transport) and `tests/tunnel_keep_alive.rs` (the relay: a stream through the front's own `serve_connection` carries sequential requests and the failed token among them is answered; a pipelined request closes; every other listener and connection serves one request with `Connection: close`; the order of the idle times).

### 35.7 The ingress

`ingress::serve_sni` (port 443): reads exactly the first TLS record, at most 16 KiB, within 5 seconds; parses only the ClientHello's `server_name` (one `host_name` entry; every length must add up, no duplicate extension, no bytes after the record, a ClientHello that spans records is refused); and opens a `public` stream with the exact record as the payload of `open`. Bytes the agent sent after the record are forwarded as data. A name of no registered node, an offline node, a node of an account without a plan, a name outside the zone, or a hello without a name gets the alert `15 03 03 00 02 02 70` and a close. A truncated, malformed, or slow hello is closed without an answer. Over the account's stream limit or budget the connection is closed.

`ingress::serve_acme` (port 80): reads a request head of at most 8 KiB within 5 seconds; forwards only `GET /.well-known/acme-challenge/<token>` (`[A-Za-z0-9_-]`, 1 to 128) over HTTP/1.1 with one `Host` (an optional `:80`) that is the public name of an online node, and no body and no bytes after the head, as an `acme` stream whose `open` carries the head and `close`; the node's answer (at most 64 KiB) goes back. Anything else gets `HTTP/1.1 404 Not Found`, `Connection: close`, an empty body.

Both keep each client address only in memory, for 30 new connections a minute per address (IPv6 per /64; a table of at most 65,536 addresses, and when it is full of addresses of this minute, new ones are refused), and at most 256 connections in their first record or head. A forwarded connection is a stream of the ingress class of 35.4 (its own slots, open rate, first-byte deadline, and budget). An accept that fails (a full descriptor table) waits 10 ms, doubling, at most 1 s, before the next (`ingress::accept_backoff`), so the loop never spins. `IngressHandle::stats` counts accepted, rate-limited, busy, malformed, timed-out, unrecognized, limited, forwarded connections, and failed accepts, with no address and no name.

### 35.8 Tests

`tests/server_tunnel.rs`, on free loopback ports through the relay's own deadline transport: the contract vectors (frames, invalid frames, sequences); the sequencer under random interleaving; 404 for an unknown node, 503 for an offline one, the order of 401, 403 `account_required`, 400, and 403 `plan_required`; another account without a grant (403), with one, and after `revoke_grant` (4003); the eighth-node limit; the first frame in the handshake's segment; a tunnel that outlives the request deadlines; streams of eight concurrent devices with random sizes and a node that echoes in random pieces; slot release on close; the 65th stream (429, and the ingress refused); the dial rate; the byte budget trip and its reset on the first of the month with a fake clock; node replacement (4005 and 4001); node close and reset; a broken stream rule, a malformed frame, text, and an oversized dial message; a client that does not read; a rustls ClientHello forwarded unchanged both ways; unknown, offline, foreign, and not-entitled names; truncated, malformed, slow, and silent hellos; the per-address limit; the ACME path filter; node removal and a plan's end; usage and its restore. Unit tests: `tunnel::frame`, `tunnel::ws`, `tunnel` (months, names), `ingress` (every truncation of a hello, malformed hellos, ACME heads, the address table).

`tests/server_tunnel_routes.rs` runs the wired tunnel on a relay with the account routes, with real account devices on free loopback ports: a node registered and dialed through the routes with an echoing fake node; strict bodies and 401, 403 `account_required`, 404, 405 on the JSON routes; the dial checks in the contract's order (400, 401, 403 `account_required`, 404 `node_unknown`, 403 `not_in_group`, 403 `plan_required`, 429 `tunnel_limit`, 503 `tunnel_offline`); a grant through the routes, its deletion (4003), a grant that holds only while the accounts share a group, `grants_end_between` and `plan_ended` (4003); a revoked node device (node closed 4003, dials 4001, row deleted), a revoked dialer (4003), `DELETE /v1/tunnel/nodes/{id}`, and an account deletion; the ninth node (403 `account_limit`); a byte budget that still holds after a restart on the same data directory; the ingress and the ACME listener started from the configuration; nothing of the tunnel without the account routes; the walk of every route of the relay with an `Upgrade` on every listener (35.6) and the two tunnel routes answering `101`; a bad token on the two upgrade routes reaching the failed-auth limit (429 at the 21st with `auth_limiter`); and every example of `examples.json` with the relay's strict types.

The review of the tunnel added, in `tests/server_tunnel.rs`: an ingress stream that ends when the node closes it while the client keeps its side open (Connect closes the client's direction, frees the slot, and counts no later client byte); the ingress's own slots (open with all 64 dial slots taken), its per-node open rate (the refused ones counted), its first-byte deadline, and its own budget (which never trips the dials); another account's dials with their own rate and slots and the owner's share of the slots and of the budget; a plan and a grant that end without a hook (4003 at the next recheck); the stored keys of `usage_all` restored after a restart; a `Connection` value that only contains `upgrade` (not an upgrade: the body keeps its `Content-Length`). The settings: the ingress share of the broker's streams, filled by the ingress of two nodes of two accounts, refuses a further ingress stream while the dials still take the rest of the broker, and an ended ingress stream gives its place back (`the_ingress_of_many_nodes_never_takes_the_streams_kept_for_dials`); every setting of 35.11 with its default, its bounds, and the relations of the grantee limits (`config::tests`). Unit tests: a reset that never overtakes its own `open` and is never dropped (`tunnel::tests`), the kept months of `tunnel_usage` (`tunnel_routes::tests`), the accept backoff (`ingress::tests`), and the one upgrade rule (`tiny_http` `common::test`). In `tests/tailnet_scope.rs`: requests through a tunnel stream in no failed-auth count, whatever their `X-Forwarded-For`, while Funnel's connections keep their per-source count; and a `device` stream that gets 404 for `POST /v1/teams`, `POST /v1/join`, and `/v1/invites`, and still reaches the sign-in and the device link.

The second review of the tunnel added, in `tests/server_tunnel.rs`: a 5 MiB answer of a node that sends only within its window, to a client that reads 64 KiB at a time with pauses (twenty times slower than the node), arrives whole and in order while at most the window waits toward the client (`Broker::peak_stream_buffer`); a client's bytes that reach a node only within the windows it grants late (a sequencer on the node side checks every frame); a node that sends over its window has only that stream reset; the ACME challenge that gets through while the `public` slot is taken, the minute's `public` rate is spent, and then the `public` budget is spent, and the ACME class's own slot count; a directory that cannot answer: a few skipped rounds keep the streams, a new dial is 503 `busy`, a longer failure ends the dial of the account and of a grantee with 1013, never 4003; one other account that spends its part of the share while another other account still dials; an agent that half-closes, still gets the node's answer, and is reset after the node's silence. The contract vectors have the `window` frames, `bad_window`, and the sequences of `over_window`. On the node: a write that waits for Connect's window and times out, a read that grants more, and a reset that ends a waiting write (`node::tunnel::tests`); the registration answer that must name the node kept for this device (`check_registration`). On the iPhone: a dial that Connect closes with 1013 waits only for the backoff (`core::transport::tests`).

### 35.9 What this does not protect

- Connect sees the sizes and times of the TLS records of every stream, the server names of the ingress, and the client addresses of the ingress (in memory).
- Whoever operates Connect, or controls the DNS of the node zone or the port 80 that its names point to, can get a publicly trusted certificate for a node's public name and end the TLS of the cloud agents that use that name: the same trust as a Tailscale Funnel name. A `device` stream is different: the device checks the pin of the node's own certificate, which no CA issues.
- Connect itself can open any stream on a node's WebSocket and reach the routes of 35.3 that need no token; a device link still needs a one-use code and the owner's confirmation.
- A node can hold the slots of its own account's streams until the idle reset; it cannot reach another account's streams.
- Strangers at the ingress can hold the account's 16 `public` slots and spend its `public` budget (bounded by the per-node open rate, the first-byte deadline, and the node's own handshake deadline); they never take a dial slot or dial bytes, and the `acme` streams keep slots of their own outside that rate and budget. Strangers on port 80 can hold the 4 `acme` slots for a moment (each request is answered at once by the node, and the per-address limit of 35.7 holds), so a validation of the CA that arrives then is refused and is tried again by the node's renewal; and the ingress of all nodes together can still fill the broker's ingress share.
- The ingress is a raw TCP port on the Connect host: the per-address limit and the pending cap bound the work of one address, not of many.

### 35.10 The routes on the account store

`tunnel_routes::AccountDirectory` is the `TunnelDirectory` of the broker on `relay.db`. It holds the hub weakly (the hub holds the broker) and caches nothing beyond one call:

- `caller`: `account::authenticate`, so each request reads the device in `relay.db` again: a revoked device's token is 401 `unauthenticated` at once, a relay-sync team token is 403 `account_required`.
- `device_node` and `node`: the rows of `tunnel_node` (`id`, `account_id`, `device_id`, `name`, `pin`, `created_at`).
- `has_grant`: a row of `tunnel_grant` for the node and the grantee account, and the node's account and the grantee share a group now (`Groups::share_group`). A row of accounts that no longer share a group grants nothing.
- `entitled`: `Plans::plan(...).entitled` of the account now. `budget_units`: `Plans::people` (at least 1).
- A store error in any of them is `Unavailable` (`Refusal::Unavailable` for the caller): 503 `busy` on the routes, never a 401 or a 404.

The routes (connect-tunnel-v1 sections 3 and 6; the contract wins), each with an account token, strict bodies (`deny_unknown_fields`, 400), and the errors of connect-account-v1 section 4 (`node_unknown` 404, `tunnel_limit` 429, and `tunnel_offline` 503 are codes of `error::codes`):

| Route | Answer |
| --- | --- |
| `POST /v1/tunnel/nodes` `{"name","pin"}` | The `NodeView` of the calling device's node: new, or the same node with the new name and pin. The id of a new node is `node_` and 10 of `a-z2-7` from the first 50 bits of SHA-256 over a label, the account id, and the device id (`tunnel_routes::node_id_of`), so the device's node gets the same id and public name again after its row was deleted (a `DELETE`, the data deletion of an ended plan); an id that another device's row holds (a collision) is a 500 and never shared. The name is 1 to 64 bytes without a control character, trimmed; the pin is 43 characters of base64url of 32 bytes. A new node over `nodes_per_account` (8) of the account: 403 `account_limit`. |
| `GET /v1/tunnel/nodes` | The nodes of the account, and those of accounts whose grant to it holds, as `NodeView`s (`online`: the broker has its WebSocket; `public_name`: the label, `.`, and `APASSY_CONNECT_NODE_ZONE`). |
| `DELETE /v1/tunnel/nodes/{node_id}` | From a device of the node's account (else 404 `node_unknown`): the node and its grants go, its WebSocket closes (4003), its streams end (4001). `{"node_id"}`. |
| `GET /v1/tunnel/node` | `Broker::serve_node` (35.2). |
| `GET /v1/tunnel/dial/{node_id}` | `Broker::serve_dial` (35.2), the checks of contract 3.3 in order. |
| `POST /v1/tunnel/grants` `{"node_id","account_id"}` | From a device of the node's account (another account: 403 `forbidden`; no such node: 404 `node_unknown`; the own account: 400): the grantee must share a group with the account (403 `not_in_group`). The `GrantView` (id `tgr_` and 10 of `a-z2-7`); the same grant again answers the existing one. |
| `GET /v1/tunnel/grants` | The grants that the account made and those made to it. |
| `DELETE /v1/tunnel/grants/{grant_id}` | From either account (else 404 `not_found`): the grant goes and the grantee's open streams to the node reset at once (4003). `{"grant_id","closed_streams"}`. |

The JSON routes read the caller, the body, and the caller again (as the account routes); a bad token counts against the listener's failed-auth limit, on the JSON routes and on the two upgrade routes alike (`Broker::serve_node` and `Broker::serve_dial` return the refusal they answered, and `http::respond_tunnel` counts a 401 and writes an `auth_failed` row of the relay audit). The hosted relay runs without `auth_limiter`, so there the count has no effect; the Worker's limiters bound the routes at the edge. The audit of the relay gets `tunnel_node_registered`, `tunnel_node_updated`, `tunnel_node_removed`, `tunnel_grant_created`, `tunnel_grant_removed`, and `tunnel_grants_ended`, with ids only.

A plan that ends at the end of a period, and a grant that stops holding without a hook, end their open streams within `Limits::recheck` (35.4).

Hooks: `account::revoke` deletes the device's node row and the node's grants, then `tunnel_routes::device_revoked` (`Broker::revoke_device`: the node closes with 4003, the device's dials end with 4003). `account::delete_account` deletes the account's nodes and the grants both ways, then `tunnel_routes::account_deleted` (`Broker::end_account`, `Broker::forget_account`, and the account's rows of `tunnel_usage`, 35.12). For billing, `tunnel_routes::plan_ended(hub, account)` ends the open streams of the account's nodes with 4003 (`Broker::end_plan`; the node WebSockets stay, new dials and ingress streams are refused by `entitled`). For groups, `tunnel_routes::grants_end_between(hub, account, others, now)` deletes the grants between `account` and each of `others`, both ways, resets the streams they carried at once (4003), and returns how many grants it deleted.

### 35.11 Configuration and start

`ConnectConfig::tunnel` (`config::TunnelSettings`, from `tunnel_from` in `connect_from`; section 6): `APASSY_CONNECT_INGRESS_LISTEN` and `APASSY_CONNECT_ACME_LISTEN` (socket addresses; unset: that listener is off), `APASSY_CONNECT_NODE_ZONE` (a DNS name, default `node.apassy.wyderka.cc`), and the limits of contract section 8: `APASSY_CONNECT_TUNNEL_STREAMS` (64, 1 to 4096), `APASSY_CONNECT_TUNNEL_NODES` (8, 1 to 64), `APASSY_CONNECT_TUNNEL_DIALS_PER_MINUTE` (60, 1 to 6000), `APASSY_CONNECT_TUNNEL_GIB_PER_MONTH` (20 for each person or member, 1 to 10240), `APASSY_CONNECT_TUNNEL_PING_SECS` (30, 5 to 300), `APASSY_CONNECT_TUNNEL_IDLE_SECS` (90, 10 to 3600, above the ping), `APASSY_CONNECT_TUNNEL_STREAM_IDLE_SECS` (900, 60 to 86400), `APASSY_CONNECT_TUNNEL_STREAM_BUFFER_KIB` (256, 64 to 16384). The other classes of 35.4: `APASSY_CONNECT_TUNNEL_GRANTEE_STREAMS` (`streams_per_grantee`, 16, 1 to the total below), `APASSY_CONNECT_TUNNEL_GRANTEE_STREAMS_TOTAL` (`grantee_streams`, 32, 1 to `APASSY_CONNECT_TUNNEL_STREAMS`; unset, at most half of the account's streams and at least 1, so that a smaller account limit keeps the contract's split; the per-grantee default is then at most this total), `APASSY_CONNECT_TUNNEL_GRANTEE_BYTES_PERCENT` (`grantee_bytes_percent`, 50, 1 to 90), `APASSY_CONNECT_TUNNEL_INGRESS_STREAMS` (`ingress_streams`, 16, 1 to 4096), `APASSY_CONNECT_TUNNEL_INGRESS_PER_MINUTE` (`ingress_per_minute`, 60, 1 to 6000), `APASSY_CONNECT_TUNNEL_INGRESS_FIRST_BYTE_SECS` (`ingress_first_byte`, 10, 1 to 120), `APASSY_CONNECT_TUNNEL_INGRESS_GIB_PER_MONTH` (`ingress_bytes_per_month`, 5 for each person or member, 1 to 10240); and the whole broker: `APASSY_CONNECT_TUNNEL_MAX_STREAMS` (`max_streams`, 4096, 64 to 65536) and `APASSY_CONNECT_TUNNEL_INGRESS_SHARE_PERCENT` (`ingress_share_percent`, 50, 1 to 90). None of them set is the contract's default; they change nothing without the account routes. `tunnel_routes::limits_of` copies them into `tunnel::Limits`; the recheck (60 s) and its 3 skipped rounds, the 4 `acme` slots and their rate (30 a minute for each account), the node queue, the close grace, the life of a half-closed stream (10 minutes), and `max_nodes` keep the defaults of `tunnel::Limits`. `APASSY_CONNECT_TUNNEL_STREAM_BUFFER_KIB` is the window that Connect grants a node for each stream (at least the 64 KiB of the initial window).

`Relay::start` calls `tunnel_routes::start` after the hub opens: with the account routes it makes the broker (`Hub::tunnel`), restores this month's usage, binds each ingress listener whose address is set (a bind failure stops the start), and starts the usage writer. `RunningRelay::stop` stops the ingress, closes every tunnel WebSocket (1000; streams 4001), and writes the usage once more before the data directory unlocks. `RunningRelay::tunnel_ingress_addr` and `tunnel_acme_addr` give the bound addresses.

### 35.12 Usage in `relay.db`

`tunnel_usage` (`account_id`, `month` as `yyyymm` UTC text, `dials`, `streams`, `bytes`) keeps the counters of section 35.1. The `account_id` column holds the key of `Broker::usage_all`: the account id for the whole account (every dial, stream, and byte of its nodes), `<account>/ingress` for its `public` streams, `<account>/acme` for its `acme` streams, and `<account>/dial/<other account>` for the dials of another account to its nodes. The parts are in the whole: the dial bytes of an account are its bytes without its `public` and `acme` bytes, and the dials of other accounts are part of them (their share of the dial budget, 35.4). When an account is deleted (`tunnel_routes::account_deleted`), its counters leave the broker (`Broker::forget_account`) and its rows leave `tunnel_usage` (`tunnel_routes::forget_usage`): its own rows and their parts, and its rows as a dialing account in other accounts (`<other>/dial/<account>`). The deletion wins over a snapshot that the writer took before it: the account stays in `Broker::forgotten` until the writer's next snapshot, and the writer asks it inside its write transaction and writes none of its rows (a deletion after that waits for the write and deletes them). The writer thread writes the counters that changed every `USAGE_FLUSH_SECS` (60 seconds) and once at stop; a write keeps the larger of the stored and the counted value, so it never lowers a count. At start the rows of the current month go back into the broker (`Broker::restore_usage`), so a restart does not reset a budget: an account over its bytes stays at 429 `tunnel_limit` until the first day of the next month. A crash loses at most the last minute of counts. Rows of earlier months stay as the audit's counts for each account and month (contract section 9) for 13 months with the current one (`tunnel_routes::USAGE_MONTHS_KEPT`): older rows are deleted at the start and with each write.

### 35.13 The edge Worker

The Worker forwards a WebSocket upgrade only on `GET /v1/tunnel/*` (raw and parsed path equal), with its headers unchanged and the edge secret set, and returns the relay's `101` response as it is. An upgrade on any other path or method gets 400 `invalid_request` at the edge, and the relay refuses it again (35.6). `GET /v1/tunnel/dial/*` has `TUNNEL_LIMITER` (namespace 1007, 60 a minute for each IPv4 address or IPv6 /64, the key of `ACCOUNT_LIMITER`), and `GET /v1/tunnel/node` has `TUNNEL_NODE_LIMITER` (namespace 1008, 60 a minute, the same key): two budgets, so the dials of the phones behind a node's address never use up the node's. Over either: 429 `rate_limited` with `Retry-After: 60`; the node and the iPhone answer it with their short backoff, not the 15 minutes of 429 `tunnel_limit`. Whether the Workers VPC binding carries a WebSocket upgrade is not verified (docs/OPERATIONS.md section 28.1).

## 36. Groups: Family and Team

ADR 0037 stage 7, plan s7 unit C3; the wire is [connect-billing-v1](../../../docs/contracts/connect-billing-v1.md) section 6 (the contract wins where this section is shorter). Code: `src/server/group.rs`, on the directory tables `"group"`, `group_member`, and `group_invite` of directory 1006 (section 33.10). The routes exist only with the account routes on; each needs the account token (section 33.2) and a strict body.

### 36.1 What a group is

The Stripe webhook makes a group when a Family or Team subscription is bound (34.5), with the buying account as its active `owner`. A Family has one organizer (`owner`) and `member`s: no admins, 4 people included, at most 10. A Team has `owner`, `admin`s, and `member`s, one seat each, at most 250. A member keeps its own account, devices, and stores. Only an **active** member gets the group's plan (34.6), and only one that the plan pays for (the owner first, then the earliest confirmed; a member beyond them is read-only until the quantity is raised); a pending member has none. The group's plan is its subscription of the group's kind (`Billing::group_plan`), not the owner's own plan: after a switch to Personal the group has none.

### 36.2 Routes

| Route | Who | Answer, refusals |
| --- | --- | --- |
| `GET /v1/account/group` | any member | the `GroupView` (`group_id`, `kind`, `role`, `owner_account`, `included`, `quantity` at Stripe of the group's plan, else of its newest subscription, `members`); a pending member sees the owner and itself only; no group: 404 `not_found` |
| `POST /v1/account/group/invites` `{"role"}` | the owner or an active admin | `{invite_id, url, expires_at}`; `url` is `<APASSY_CONNECT_SITE_URL>/connect/join#apassy_gin_<group id>_<64 hex>`. `admin` only in a Team and only by the owner (403 `forbidden`); a role other than `member` or `admin`: 400; the group's plan not entitled: 403 `plan_required`; 20 open invites: 403 `account_limit` |
| `POST /v1/account/group/join` `{"code"}` | the invited account | `{group_id, kind, state: "pending", owner_name}`; a malformed code: 400; an unknown, used, or expired code: 403 `forbidden` (one answer); an account in a group, or with an entitled plan of its own: 409 `conflict`; the same code again by the account that used it answers the same |
| `POST /v1/account/group/members/{account}/confirm` `{}` | the owner or an active admin | the member view, `active`. Under the lock of the group (`Billing::with_group_lock`, also taken by a seats change and the pass's quantity check): the group's plan entitled (else 403 `plan_required`); the active members counted with this one (409 `seat_limit` above the plan's maximum); the member made active (audit `group_member_confirmed`); when the count exceeds the quantity at Stripe, `Billing::request_quantity_locked` asks Stripe for it (`create_prorations`); when Stripe refuses, the member is pending again (audit `group_member_confirm_undone`) and the answer is Stripe's error; an account not in this group: 404 |
| `DELETE /v1/account/group/members/{account}` | the owner or an active admin; a member itself | `{account_id, removed_from_stores}`. The owner cannot be removed (403); only the owner removes an admin (403); a member may remove itself (a pending one cancels its join) |
| `POST /v1/account/group/seats` `{"quantity"}` | the owner | 34.4 |

A caller in no group: 403 `not_in_group` (404 for the view); a role that may not: 403 `forbidden`. The owner's device runs the owner check (`OwnerAction::ChangeConnectGroup`) before a confirm or a removal; Connect does not see it.

### 36.3 Invites

The code is 32 random bytes in hex after the group id. Connect stores only its SHA-256 (`group_invite.code_hash`), the role, the inviting account, the times, and, once used, the account that used it. A code works once, for 7 days (`INVITE_SECS`). The join marks the invite used and adds the member as `pending` in one transaction, so two accounts never use one code.

### 36.4 Removal

A removal, in this order: the devices of the removed account leave the vault stores of the group's other accounts, and their devices leave the removed account's stores (`Hub::remove_store_device`; `removed_from_stores` counts the first kind); the tunnel grants between it and the group end, both ways, and their streams close (section 35); its `group_member` row goes and `account.group_id` is cleared; an audit row `group_member_removed`. The removed account keeps a free account; its next request has no plan (34.6). The quantity at Stripe does not change: the owner lowers it with the seats route.

### 36.5 The seam of the accounts

`group::DirectoryGroups` is the `Groups` seam (33.6): `group_of` (the `group` of `GET /v1/account`: id, kind, role, state), `share_group` (both accounts are **active** members of one group: a device of the other account may join a vault store, and the store becomes `shared`), and `blocks_deletion` (an owner with another active member: `DELETE /v1/account` is 409 `conflict`). An account that is deleted leaves its group in the same transaction (`group::forget_account`): a member's row goes; an owner's group, its pending members, and its invites go.

### 36.6 Tests

`tests/server_group.rs`, one test for each bullet of the plan's C3 acceptance, with subscriptions from signed synthetic webhooks against the fake Stripe, and confirms sent at once on threads (the maximum holds; each confirm raises the seats it needs; a confirm waits for a seats change; a refused raise leaves the member pending), a switch to Personal, and a late event of an old plan at its deletion day: the group made by the webhook; an invite is one use and 7 days, stored as a hash; a pending member has no entitlement until confirmed, and a member does not buy; the Family quantity follows the people (4 included, the fifth raises it with prorations, the change applied only on the webhook, `seat_limit` below the members and above 10) and the Team quantity its members; a removed member keeps a free account, loses the plan within one request, and leaves the shared store; a member's device joins a shared store and a stranger's or a pending member's does not; roles (a Family has no admins, only the owner invites or removes an admin, the owner cannot be removed, a member may leave); an owner with members cannot delete the account, a member can, and then the owner can (the subscription canceled at once).

## 37. The end of the free paths, the Connect-only mode, and the cutover

ADR 0037 stage 7, D8, D14; plan s7 unit C5, decision 1 and section 5 (releases R3); contract [connect-account-v1](../../../docs/contracts/connect-account-v1.md) section 14 (the contract wins where this section is shorter). Code: `src/config.rs` (`free_connect`, `free_sync_ended`, `check_mode`, `refuse_connect_mode`), `src/server/http.rs` (`retired_in_connect_mode`, `Endpoint::serves_in_connect_mode`, `Endpoint::is_free_connect_use`), `src/server/mod.rs` (`Core::sync_bytes`, no proxy in `connect` mode), `src/server/cutover.rs` (the backup of a stopped relay and the cutover), `src/bin/apassy-relay.rs` (`backup`, `connect-cutover`). The owner's runbook is [docs/operations/connect.md](../../../docs/operations/connect.md); the operator's section is docs/OPERATIONS.md section 29.

### 37.1 The transition switches (before the cutover)

Both are off by default: a relay that someone runs for themselves, and the hosted relay until the owner sets them, behave as before.

| Setting | Effect |
| --- | --- |
| `APASSY_RELAY_FREE_CONNECT=0` | `POST /v1/connect` and `POST /v1/connect/challenge` answer 410 `free_connect_ended` before their body is read. A free Connect team (`TeamKind::Connect`) gets 410 `free_connect_ended` on its question, answer, settle, feed, feed action, push token, and push handle routes (`Endpoint::is_free_connect_use`), after its token is checked and before its body is read. Its sign-in, `GET /v1/me`, the device routes, `POST /v1/leave`, and relay sync stay, so the app can move its approvals and its vault and then delete the membership |
| `APASSY_RELAY_FREE_CONNECT=0` with `APASSY_RELAY_CONNECT_SYNC_BYTES` 0 (or unset) | `RelayConfig::free_sync_ended`: `Core::sync_bytes` of every free Connect team is 0, whatever its stored `sync_bytes` (an operator's `admin limits --sync-bytes` included). A push and a receipt are 403 `plan_required` with the `sync_refused` audit row of section 24; a head long poll answers at once; a pull and a download still work |

`APASSY_RELAY_CONNECT_SYNC_BYTES=0` alone keeps its meaning of section 26.4 (new teams only): the gap for existing teams closes only together with the end of the free path, so a self-run relay that raised one team's `sync_bytes` keeps it. Operator teams and vault stores never see either switch. In `connect` mode `free_connect` is always off.

### 37.2 `APASSY_RELAY_MODE=connect`: what is served

The relay serves Apassy Connect only. After `/healthz` and the edge secret, every request whose path the relay would serve otherwise is answered 410 `hosted_retired` **before its token is checked and before its body is read** (`retired_in_connect_mode`):

| Served | Retired (410 `hosted_retired`) |
| --- | --- |
| `GET /healthz` (with `x-apassy-relay-mode: connect`) | `/mcp` (every method) and `/p/` and below: no proxy exists |
| the account, device, vault store, entitlement, and group routes (`/v1/account` and below), `/.well-known/apassy-connect.json` | `POST /v1/connect`, `/v1/connect/challenge`, `POST /v1/teams`, `POST /v1/join` |
| billing: `GET /v1/plans`, `POST /v1/stripe/webhook` | `/v1/questions` and below, `/v1/feed` and below, `/v1/push/token`, `/v1/push/handle` |
| the tunnel: `/v1/tunnel/` and below (section 35), and the ingress listeners | invites, joins, device links, members, collections, items, grants, agents, approvals, audit, access, runs, the host routes, `POST /v1/leave`, `DELETE /v1/devices/{id}`, `POST /v1/devices/enroll`, key holders |
| relay-sync-v1 of a vault store: `POST /v1/auth/challenge`, `POST /v1/auth/token`, `GET /v1/me`, `GET /v1/devices`, `GET /v1/sync/head`, `GET`/`PUT /v1/sync/snapshot`, `POST /v1/sync/receipt`, `DELETE /v1/sync` (`Endpoint::serves_in_connect_mode`; section 33.5 still applies) | |

A path of the route table is retired whatever its method (a method that none of its routes has is 410 too, unless one of them is served, then 405). A path that the relay never had stays 404. A request with an `Upgrade` on a retired route is 400 `invalid_request` ("This route does not upgrade the connection.") before the 410: only the two tunnel routes upgrade (section 35.6), and that check comes first on every route and listener, in both modes. The static downloads (`/dl/`, `/guide`, `/install.sh`) are the Worker's (37.6).

### 37.3 `connect` mode: the start

- From the environment (`RelayConfig::from_lookup`): the master key is refused (`APASSY_RELAY_KEY` and `APASSY_RELAY_KEY_FILE`, section 33.1), and so is any push value (`APASSY_RELAY_PUSH_URL`, `_TOPIC`, `_SECRET`, `_SECRET_FILE`): Connect sends no push; the nodes push through the push gateway (ADR 0037 D7). Shared team vaults and the free Connect paths are forced off; the account routes are on (`APASSY_RELAY_CONNECT_ACCOUNTS=0` is refused).
- `Relay::start` checks a configuration made in code with `RelayConfig::check_mode`: in `connect` mode it refuses a master key, push, shared team vaults, the public or tailnet listener of a node, the MCP authorization flow, and the account routes off.
- No `Proxy` is built (`RunningRelay::proxy_built` is false; `/p/` cannot reach one), and with no push configuration `push::Push::start` starts no sender thread (`RunningRelay::push_on` is false).
- `Hub::open` first refuses a cutover that is not finished (`cutover::check_start`), before it opens, migrates, or sweeps any file: in either mode a plain `relay.db` beside `relay.db.keyed` (committed, not finished); in `connect` mode also an encrypted `relay.db` (not cut over, or a run stopped before its commit point). The message says to run `apassy-relay connect-cutover` again with the configuration before the cutover. A `cutover.json` that cannot be read, or whose state is not `done`, is refused only when the files are not those of a finished cutover (`cutover::unfinished`, read-only: `relay.db` plain; no `relay.db.keyed`, `relay.db.work`, `relay.db.plain`, or `.plain` name in `teams/`; no old file and no audit archive; every entry of `teams/` with a team id plain; and, when `relay.db` has no write journal, only teams of kind `account` with each team id of `teams/` one of them); that message says to restore the stopped backup, because the cutover cannot finish it either. On the files of a finished cutover the relay starts, logs one line that the record is not readable or not `done`, and never rewrites the record. A write journal of a plain file is no reason: SQLite rolls it back at the open. A `relay.db.keyed` beside a keyed `relay.db` (a run stopped before its commit point) does not stop `relay` mode: `relay.db` is whole, and the next cutover removes the copy.
- `relay.db` and the vault stores open plain (section 33.8). `Hub::open` serves only teams of kind `account`. After a finished cutover, and on a relay made in `connect` mode, there is no other kind; one in a `relay.db` changed by hand is logged and not served. A vault store that does not open is logged as out of service with the advice to keep its file and restore it from a backup (for an encrypted file: the cutover did not convert it), never to delete it.
- `apassy-relay init` makes an empty plain relay (`init --team` is refused: Connect has no operator team), `admin team-code` and `admin node-code` are refused, and `migrate`, `rollback-check`, `downgrade-schema-6`, `downgrade-schema-7`, and `downgrade-directory-1003` to `-1005` refuse with a message that names the way back (37.7).
- `/healthz` answers `ok` with `x-apassy-relay-version`, `x-apassy-relay-commit`, and `x-apassy-relay-mode` (`relay` or `connect`, in both modes).

### 37.4 Backups

- `admin backup` (a running relay) copies plain files to plain files in `connect` mode (`Store::snapshot_plain_on`, the SQLite backup API), reads a closed store read-only plain, checks the snapshots as before, and adds `"mode": "connect"` to `MANIFEST.json`. `snapshot-check` reads plain files in `connect` mode.
- `apassy-relay backup` (the relay stopped; it takes `relay.lock`) copies every file of the relay in the data directory byte for byte: `relay.db`, every file under `teams/` (team files, `.pre-v*` copies, snapshot folders, files of team ids that `relay.db` does not name, files of no team, and `.plain` names that are not side files of the cutover), `team.db`, its journal, and `team.db.pre-teams`, `relay.db.migrating` and its journal (a migration that stopped), and `audit-archive/`, so every file that the cutover changes or deletes and every file under `teams/`, into a new folder of `APASSY_RELAY_BACKUP_DIR` (mode 0700, files 0600). Each copy is hashed against its source, the data directory is listed again after the copies (it must not have changed), and `MANIFEST.json` names every file with its size and SHA-256, `"stopped": true`, the mode, the directory version, and the number of teams. It refuses while the relay runs, while a write journal remains (`-journal`: start and stop the relay once, it rolls the write back), and on a committed cutover (`relay.db` plain beside `relay.db.keyed`: run the cutover again to finish it). A `relay.db.keyed` beside a keyed `relay.db` is a side file of a run that stopped before its commit point: the backup leaves it out, like the other side files (`relay.db.work`, `relay.db.plain`, `cutover.json`, their journals and temporary files, and `<file>.plain` or `<file>.plain-journal` beside a file `<file>` of a vault store of an account, `cutover::is_side_file`). Entries at the top of the data directory that the relay does not know are not in it; the cutover neither changes nor deletes them. It works in both modes and holds no key.

### 37.5 `apassy-relay connect-cutover`

`connect-cutover [--dry-run | --confirm-delete-teams <plan_sha256>] [--backup <folder>]` runs once, with the relay stopped and the configuration before the cutover (the master key). `--dry-run` is the default. The steps (`cutover::run`):

1. Take `relay.lock` (a running relay: 409 `conflict`, "stop it first"). Refuse a write journal. Read `relay.db` read-only with the master key: it must be directory `DIRECTORY_VERSION`; every vault store (kind `account`) must open with its key at team schema `SCHEMA_VERSION`. Each other file of a vault store in `teams/` (a `.pre-v*` copy, of any team schema) that opens with the store's key and passes `integrity_check` is listed in `converted` beside the store's database; a plain one is listed in `left` and stays as it is; any other one (it would open with no key after the cutover) refuses the cutover, dry run included, before any change, with the file's name: restore it, or move it out of the data directory, then a new stopped backup. A vault store whose database does not open with its key refuses it too; no message advises deleting a store.
2. **The backup check** (`backup_check`): the stopped backup named by `--backup`, or else the newest folder of `APASSY_RELAY_BACKUP_DIR` whose `MANIFEST.json` says `"stopped": true`, lists exactly the files of the data directory now (37.4, the cutover's side files left out) with the same sizes and SHA-256, and each of its files still matches its manifest. A backup of a running relay (`admin backup`) never passes: the relay writes `relay.db` after it. The dry run ends here and answers the plan (`state: dry_run`): the stores that stay, the files made plain, the teams that go, the team ids that have files but no row (`orphans`; their files go too), the counts and hashes before, the entries left, the backup checked, side files of an earlier run (`side_files`), and `plan_sha256`, the SHA-256 of the JSON of the plan (`kept`, `deleted`, `orphans`, `converted`, `files_before`, `left`, the backup's folder and manifest hash, and the relay's version and commit, `relay_version` and `relay_commit`; no time). So a new image needs a new dry run. It opens every file read-only and writes nothing. `--confirm-delete-teams` takes that `plan_sha256`: a run whose plan differs (a newer backup, a changed file, another value) is refused (409 `conflict`) and changes nothing. A committed cutover is confirmed with the `plan_sha256` of its `cutover.json`.
3. The side files of an earlier run before its commit point go (`relay.db.work`, `relay.db.plain`, `relay.db.keyed`, `cutover.json`, the `.plain` copies beside the files of the vault stores, and their journals and temporary files), and the record keeps their names (`side_files`). A `.plain` name that is not such a copy is data: it is in the inventory and the backup, and goes or stays with its team like any other file. For each file of `converted`, a plain copy `<file>.plain`. SQLCipher refuses the SQLite backup API between a keyed and a plain file ("backup is not supported with encrypted databases"), so the copies are made with `sqlcipher_export` and the source's `user_version` (`Store::export_plain`). Each copy is checked against its source (`check_copy`): the version, the schema objects (`sqlite_master`: type, name, table, SQL), a SHA-256 of the rows of every table (`ORDER BY` every column, each value with its type), and `PRAGMA integrity_check`. For `relay.db`: a byte copy `relay.db.work` (its hash must be the inventory's), opened with the master key; there, in one transaction, the teams of other kinds go, the team codes, free Connect keys, and OAuth state go (`team_code`, `connect_key`, `oauth_refresh`, `connect_request`, `oauth_client`), store device maps of no remaining store go, every `team.file_key` becomes empty, and one audit row `connect_cutover` (`{"kept", "deleted"}`) is written; then `VACUUM`, still keyed (`temp_store` is memory). Only then is it exported to `relay.db.plain`, which is checked against the working copy (`check_copy`) and against the keyed `relay.db` (`check_plain_directory`: the same version and schema objects; exactly the kept stores, every column as before but an empty key; the cleared tables empty; the device maps of the kept stores as before; the audit as before with exactly one `connect_cutover` row more; every other table the same rows by hash; `integrity_check`). `relay.db.work` is deleted. No team key and no deleted row is ever written to the disk in plain. An error in this step or the next before the commit point removes every side file it wrote (`remove_side_files`), so the data directory is the bytes it was.
4. `cutover.json` (`state: committing`, the plan, the hashes before), a copy of the keyed `relay.db` as `relay.db.keyed` (its hash must be the inventory's), and then the rename of `relay.db.plain` over `relay.db`: **the commit point**.
5. Before any deletion (`check_committed`, read-only): `cutover.json` gives its own `plan_sha256` again (a record changed by hand is refused), the plain `relay.db` names exactly its stores, the backup is checked again against `cutover.json` (`MANIFEST.json` the same SHA-256, the same file list, every file matching: `recheck_backup`), `relay.db.keyed` is checked against the inventory's `relay.db` and gives each store's key, every file about to go must be in the inventory with the same size and hash, and each converted file is plain and whole, or keyed, opens with its key, and has no write journal. Then each file that is still keyed is exported again (a plain copy of a run that stopped, whole or partial, and its journal are removed first) and its new copy replaces it (checked against its keyed source, one rename each). Every other entry of `teams/` whose name starts with a team id that is not a kept store goes, `orphans` included: `<id>.db`, `-journal`, `.pre-v*`, `.pre-v*.tmp`, `.plain` names, and the snapshot folder `<id>.sync`. An entry without a team id is left and named. Also `team.db`, its journal, `team.db.pre-teams`, `relay.db.migrating` and its journal, the audit archives (they open only with the master key), and a socket that a stopped relay left. Then the result is checked: only `relay.db` and the kept stores' files, `relay.db` and each converted file plain (a store's database at the current schema) with `integrity_check`, and every other file of a kept store the bytes it was before.
6. `cutover.json` again (`state: done`, the counts and the list of files with their hashes after, `files_deleted` as the files of `files_before` that are gone, also those of an earlier run, the entries left), `relay.db.keyed` checked again against the inventory, and last its deletion.

**What is never deleted:** an entry of `teams/` whose team id is a kept store, other than the cutover's own side files. The cutover only replaces a store's database and its keyed copies by their checked plain copies; its snapshots and its plain files stay byte for byte. No file is left that opens only with a key that the cutover removes: such a file refuses the cutover at step 1. Every file that the cutover deletes is a file of the inventory, so of the backup, and is named in `files_deleted`.

**Interrupted runs** (`cutover::Interrupt` stops like a kill, `Options::fail` fails like an error; the tests): before the commit point `relay.db` is keyed and whole: an error removes the side files at once, and after a kill a second run removes them and starts again. After it, the plain `relay.db` names the stores, `cutover.json` holds the plan and the hashes before, and `relay.db.keyed` holds the keys: a second run with `--confirm-delete-teams <plan_sha256>` finishes steps 5 and 6; each file that is still keyed is exported again with its key from `relay.db.keyed`. A dry run of a committed cutover makes every check of step 5 (`check_committed`), changes nothing, and answers `state: committing` with what the confirmed run does: `to_convert` (the files made plain), `to_delete` (the files deleted), `side_files`, and `files_deleted` so far; a check that fails fails both alike. The plan hash of a committed cutover is computed from `cutover.json`, with the relay version and commit that it records. After step 6 a run answers the record of `cutover.json` and changes nothing, also in `connect` mode. At any point the stopped backup of step 2 restores the relay as it was.

`cutover.json` holds ids, kinds, states, counts, sizes, file names, and SHA-256 values only: no name, key, token, or email. The line on stderr after the JSON says what the run did (`cutover::summary`): a dry run with the command to confirm it, a committed cutover that is not finished, a cutover done now, or one done before ("nothing changed").

### 37.6 The edge Worker

One build serves both phases (`deploy/worker/src/index.ts`): the var `RELAY_MODE` is `relay` (or unset) before the cutover and `connect` after it. In `connect` mode `/internal/push` answers 404 without reading the request (the APNs sender is off), `/v1/connect` and `/v1/connect/challenge` answer 410 `hosted_retired` at the edge, with the relay's message, before a guard, the body, or the relay (so `CONNECT_LIMITER` and `CONNECT_PREFIX_LIMITER` are never asked, and no client prefix is sent), and `/p/` has the 64 KiB JSON cap instead of the proxy's 8 MiB. A deploy cannot set a mode that is not the relay's: the Wrangler build hook and `npm run preflight` run `scripts/check-relay-mode.mjs`, which reads `RELAY_MODE` from `wrangler.jsonc`, asks `GET https://<route>/healthz` (or `APASSY_EDGE_HEALTH_URL`) for `x-apassy-relay-mode`, and refuses a difference or a relay that does not answer 200. A 200 without the header is a relay before it, in `relay` mode: a `relay` deploy passes, a `connect` one is refused. `APASSY_EDGE_MODE_CHECK=skip` passes it only when the relay cannot be reached (the request fails or times out, or a gateway error 502, 504, 520 to 527, or 530 without the mode header: the Worker's "relay unreachable" or Cloudflare's), and says so; when the relay answers, the skip is ignored and the check runs. The check runs only in a build: a change of `RELAY_MODE` in the Cloudflare dashboard or a rollback to an older Worker version is not seen; then the relay's own 410 `hosted_retired` on the retired routes (37.2) still holds in `connect` mode. `/dl/`, `/guide`, `/install.sh`, the account, billing, and tunnel guards, and everything else are the same in both. Another value of `RELAY_MODE` answers 503 "relay not configured" on every relay route and 404 on `/internal/`, and still serves the static files.

### 37.7 The way back

There is no in-place way back from `connect` mode: the plain files have no key, and no image before Connect opens them. The way back is the stopped backup of the cutover (step 2) restored into an empty data volume, the previous image and its compose settings, and the master key of that backup (docs/operations/connect.md, "Rollback").

### 37.8 Tests

`tests/server_connect_cutover.rs`, on free loopback ports and temporary directories with the fake Stripe: the switch's default and parsing; `POST /v1/connect` and its challenge 410 before the body; a free Connect team's questions, feed, and push 410 and its devices kept, while an operator team on the same relay keeps them; free sync ended for an existing free team (push and receipt `plan_required`, pulls and downloads work, the long poll answers at once) only with both switches, never for an operator team; a vault store unaffected; in `connect` mode every retired route 410 with a body that is not JSON and a bearer that is not a token, the served routes not 410, the mode on `/healthz`; no proxy and no push thread (checked against `/proc/self/task` under nextest, with a relay with push as the control); the push values, the master key, and the node settings refused at start; plain online and stopped backups, the restore check of a restored plain backup, and the keyed rollbacks refused without a change; the cutover's dry run changing no file (hash and time); its refusal while the relay runs, without a stopped backup, with only an online backup, with a stale or damaged one; the real run leaving exactly `relay.db`, `cutover.json`, and the stores, plain, without a key, with the snapshots unchanged, opened by `connect` mode (sign-in, pull, download, a new push) while the deleted teams are gone; each interruption point finished by a second run to the same result; the stopped backup restoring a run stopped halfway (every team signs in and pulls with the master key); no file of a store deleted; the binary end to end (`init`, `backup`, `connect-cutover`, `connect-cutover --confirm-delete-teams` without a plan (exit 2) and with another one (exit 1, nothing changed), then with the plan of the dry run, `serve` in `connect` mode, a second run in `connect` mode). The review fixes of C5: at every interruption point no team key is on the disk in plain, neither mode starts (and the refused start changes no byte), a committed cutover refuses `backup` and answers `committing` with the line "committed and not finished", and the record lists every file that went, also those of an earlier run; an error before the commit point leaves no side file; a stale `relay.db.keyed` beside a keyed `relay.db` blocks neither the relay nor `backup` nor the cutover; a resumed run checks the backup again (gone, or one file changed: nothing deleted); a keyed copy that is not the inventory's `relay.db` is kept; the confirmation is bound to the plan (another value, a newer backup); the backup and the record cover the files of a stopped migration, and a keyed `.pre-v*` copy of a kept store becomes plain; a relay without `teams/` cuts over; an `Upgrade` on a retired route is 400; `check_copy` finds another value, another type, and another schema object at the same row counts (unit tests). The second review: on a finished cutover a record that cannot be read, is empty, or says `committing` lets `connect` mode start without a change to the record, also with a hot journal of `relay.db` (rolled back at the start), and the same records refuse a cutover that is not finished (a keyed team file left); the dry run of a committed cutover answers `to_convert` and `to_delete` and refuses as the confirmed run does (a file of a team that goes, new since the backup; a record whose `converted` or `left` was edited); a partial or missing plain copy after the commit point is written again; a `.plain` name of a team that goes, the files of a team id without a row (`orphans`), and a file of no team are in the backup and counted, a side file of an earlier run is not in the backup and is listed; a `.pre-v6` copy with another version and table becomes plain with them; a file of a store that does not open with its key refuses the cutover before any change; `admin delete` refuses a vault store in both modes; the plan hash covers the relay version and commit (unit test). The Worker: `test/index.test.ts`, "relay mode", for both settings (the edge 410 of `/v1/connect` in `connect` mode), and `test/relay-mode-check.test.ts` for the deploy check.

### 37.9 What this does not protect

- The plain files hold no secret but are not encrypted: public keys, device names, account and Stripe ids, vault ids, signed heads, hashes, and the email copied from Stripe (section 33.12). The snapshots stay ciphertext under each vault's passphrase. Disk encryption of the host is the owner's choice.
- The stopped backup of the cutover and its master key open every deleted team's metadata (never an item value). Their retention is the owner's choice (docs/operations/connect.md); until both are destroyed, the deleted teams can come back.
- Deleting a file frees its blocks; the filesystem does not overwrite them. The deleted files were SQLCipher ciphertext (team files, copies, archives, `relay.db.keyed`) or snapshot ciphertext, and the cutover writes no team key or deleted row to the disk in plain (37.5, step 3), so the freed blocks open only with the master key. An owner who wants no such ciphertext left moves the plain files to a new volume and destroys the old one (docs/operations/connect.md, section 9.6).
- The switches are read at start: a relay holds no long poll of a free team across a restart, but a request that started before the restart ends as it began.
