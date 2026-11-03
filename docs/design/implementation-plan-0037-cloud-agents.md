# Implementation plan — cloud agents (ADR 0037, cloud slice)

Date: 2026-11-03. Status: PLAN, accepted by the owner's decisions of 2026-11-03 (below).
Decision: [ADR 0037](../adr/0037-own-relay-open-source.md) §3 "Public", §6; [ADR 0011](../adr/0011-run-proxy-placeholders.md) stage 7.
Parent plan: [implementation-plan-0037.md](implementation-plan-0037.md) (2A, 2D).

## Owner decisions (2026-11-03)

1. **Order.** This cloud slice comes before the rest of stage 2 (iPhone over the tailnet, push gateway,
   Devices UI). The iPhone keeps today's hosted questions lane for approvals.
2. **Public route.** Tailscale Funnel on port 8443, off by default, `/mcp` and `/p/` only. Never port
   443: on the owner's Mac, 443 serves T3 Code through Tailscale Serve. The agent changes the tailnet
   policy through the Tailscale API, after it shows the owner the diff.
3. **Store.** List Apassy in the owner's private team plugins now. Prepare the public plugin repository
   and the submission text. Submit publicly only after the release and the owner's OK.

Defaults for the questions that the plan raised (the owner can change them): run questions reach the
Mac and the iPhone, not the Watch (ADR 0039 §3); every cloud run asks the owner and nothing is
remembered; if window reopen is not reliable, this release says "keep the window open or minimized";
token lifetime 90 days, session TTL 600 s, limits as in decision 3.

## Owner feedback on the first mockup (2026-11-03) — replaces decision 6 and the token part of decision 3

The owner refused "Settings → Cloud agents → Add a cloud agent". The owner never adds an agent by
hand, local or remote. The model is T3 Code's environments:

- **Sidebar.** The section "Agents" is renamed **Bouncer**. It holds **Overview** (stats: runs,
  automatic allows, questions to the owner, denials, answer times, per agent and per environment),
  **Decisions** (open and history), **Agents** (local and remote agents of every environment), and
  **Logs** (the activity log).
- **Environments.** Each Mac is an environment. The scope bar of PR #88 selects **All environments** or
  one Mac (and a project), on every Bouncer page. Data of other Macs comes from relay-feed-v1, read-only.
- **Remote agents connect by themselves.** The owner gives the agent only the MCP address. The MCP
  endpoint speaks the MCP authorization flow (OAuth 2.1 with PKCE, dynamic client registration,
  protected-resource and authorization-server metadata). Grok Bot shows "Authorize"; the browser page on
  the Mac's public route says "Approve on your Mac"; the Mac shows a connect decision in Decisions
  ("Grok Bot wants to connect", Allow with Touch ID / Deny), also on the iPhone. After Allow, the agent
  is a remote agent of that environment and appears in Agents like a local agent. Visibility follows the
  same rules as a local agent (ADR 0012); every run still asks the owner. A bearer token made with the
  CLI stays as a fallback for clients without OAuth.
- **Remote access switch.** The public route (Tailscale Funnel) is switched on the Agents page of this
  Mac's environment, next to the MCP address; it is not a Settings page.

Effect on the units: U1 gets the OAuth endpoints on the public scope and pending connect requests; U2
replaces "add agent" with connect requests decided like runs; U3 draws the Bouncer section.

## Outcome

A hosted cloud agent (first: xAI Grok Bot) adds one MCP server by HTTPS URL and a bearer header. It
lists the credentials that the owner chose for it, asks for a run, the owner approves on the Mac or the
iPhone, and the agent calls the API through the Mac's way B proxy. The agent holds placeholders, base
URLs, and a session key, never a value. No Apassy-run server is on the path.

## Prototype (2026-11-03, `~/.apassy-grokbot-proto`, synthetic item only)

- The relay from this workspace (`target/debug`, `APASSY_RELAY_TEAM_VAULTS=1`) on 127.0.0.1, a small
  front that adds `X-Apassy-Edge`, `apassy-team host --dialog`, a synthetic item for `httpbingo.org`, and
  an agent token. `apassy_list_access` and `apassy_request_run` work over the tailnet URL. The host asks
  the owner with a dialog, because `curl` is not a known safe command.
- Device sign-in in `apassy-team` is origin-bound (`src/cli/signin.rs`), so the host lane and the owner
  API share the origin with `/mcp`. The prototype front lets `/v1/` through only when Tailscale Serve's
  `Tailscale-User-Login` header is the owner's (Serve strips a client copy; Funnel requests have no
  identity headers). The product does not trust a header: the host is in-process, so the public route
  has no `/v1/`.
- Funnel was not yet allowed by the tailnet policy.

## Facts from the code (2026-11-03)

| Area | Fact | Where |
| --- | --- | --- |
| Crate cycle | The relay depends on the root crate by path. The desktop code is inside the root crate (`desktop` feature, bin `apassy` at `src/main.rs`). The root crate cannot depend on the relay. | `crates/apassy-relay/Cargo.toml:14`, `Cargo.toml:76` |
| Relay start | `Relay::start(config) -> RunningRelay { addr, hub() }`; one `tiny_http` accept thread; `stop()` ends sessions and drops run keys. | `crates/apassy-relay/src/server/mod.rs:590`, `:379` |
| Edge | `X-Apassy-Edge` is checked on every request except `/healthz`. There is no off switch. | `server/http.rs:853` |
| Routes | `/mcp` (POST, agent), `/p/` (edge only, proxy), the rest `/v1/...`. `is_agent_path` sets the lane. | `server/http.rs:173`, `:361` |
| Run flow | `decide::request_run` stores a pending run, a one-time X25519 key, and a suggestion. `host::release` takes the key, rechecks agent and grants, opens the sealed keys, then `sessions.create` with `EnvItem {item_id, env_name, value, hosts}`. | `server/decide.rs:298`, `server/host.rs:163`, `server/sessions.rs:56` |
| Host auth | `authorize_host` needs the owner and a key-holder device, or the bootstrap path. | `server/devices.rs:377-412` |
| Catalog | `admin::access` lists live items in collections granted to the agent's member; no filter for each agent. Items need `sealed BLOB NOT NULL`. | `server/admin.rs:1269`, `docs/SPEC.md` §8 |
| Agent tokens | `apassy_tagt_<team>_<64 hex>`, SHA-256 stored, 1 to 365 days (default 30), revocation at the next request. | `src/secret.rs:108`, `server/admin.rs:1108` |
| Public URL | `checked_public_url` accepts `https://host:port`, no path. Base URLs are `<public_url>/p/<key>/<host>`. | `src/config.rs:494`, `src/proxy/mod.rs:40` |
| Limits | Global `Limits` (256 active, 32 member reserve); team limits (`runs_per_hour`, `pending_runs`, `agent_requests`). Refused requests write at most one audit row per 10 s. | `src/config.rs:157`, `server/hub.rs:1550` |
| Broker run | `run_inner`: auth, hard rules, analysis, `prompts.resolve` (hook), `injection_flag`, bouncer route, owner question, then `read_secrets` and the local proxy. `evaluation_only` stops before `read_secrets`. | `src/broker/run.rs:728`, `:794`, `:1212`, `:1588`, `src/broker/approvals.rs:1279` |
| Vault agents | `agent(id, name, token, created_at, revoked_at, token_issued_at, see_all)`; no kind column. Visibility: `see_all` and `agent_exception`; `catalog_for_agent`. | `src/vault/agents.rs:29`, `:163`, `src/vault/access.rs:273` |
| Items for a proxy | `env_binding(item_id, env_name, field, placeholder_hosts)`; the value comes from `Vault::reveal(id, field)`. | `src/vault/agent_items.rs:1338`, `src/vault/mod.rs:548` |
| Questions | The Mac shows the card and posts it to the relay for the iPhone; the first answer wins. The Watch answers access requests only. | `src/questions/worker.rs:30`, `:1649` |
| Lifecycle | `sync_companion` reconciles each frame; `end_waiting_runs` and `on_exit` stop it. No close handling found: closing the window most likely quits. | `src/desktop/companion.rs:191`, `src/desktop/mod.rs:322`, `:478` |
| Tailscale | `hosts.rs` runs `tailscale status --json` from four fixed paths (2 s timeout). No serve or funnel code. | `src/companion/hosts.rs:19` |
| Keychain | Through the Swift helper: `NativeHelper::keychain_store/read/delete`; `keychain_unavailable` without a provisioning profile. | `src/native/mod.rs:921-998` |
| Settings | `SettingsSection` enum + `settings::draw` and `status_line`. Copy: `Clipboard::copy_secret`. Revoke: `Sheet::RevokeAgent`. | `src/desktop/ui/settings_view.rs:19`, `ui/settings.rs:49`, `ui/agents.rs:492` |

## Decisions

### 1. Crate layout and the embedded relay

- **Layout.** The core gets `src/node/backend.rs` with object-safe traits `NodeBackend`
  (`start(NodeConfig) -> Box<dyn RunningNode>`) and `RunningNode` (bootstrap, catalog sync, agents,
  pending runs, release, deny, session state, audit rows, stop), with plain types only. The relay
  implements them in `crates/apassy-relay/src/embedded.rs`. A new crate `crates/apassy-app` (bin
  `apassy`, the current `src/main.rs` plus one line of wiring) depends on `apassy` (`desktop`, `vault`)
  and `apassy-relay`, and calls `desktop::run(RunOptions { node: Some(...) })`. The other bins stay.
  Rejected: a sidecar relay process (values would cross a process boundary; ADR 0037 §2 says a thread)
  and a split of the core (weeks, no gain here).
- **`EdgeMode::{Required(secret), Off}`** replaces `edge_secret`. `Off` is refused unless every
  listener is loopback. `from_lookup` keeps the secret required, so the hosted relay does not change.
- **Embedded config** (`RelayConfig::embedded(EmbeddedOptions)`): data directory
  `paths::data_dir()/node`, node listener `127.0.0.1:0`, public listener `127.0.0.1:<port>`
  (decision 4), `public_url` = the Funnel origin, no push, `team_vaults` on, Connect off,
  `session_ttl_secs` 600, `approval_timeout_secs` 300 (= the broker's question wait), operator socket in
  the data directory (0600, for diagnostics).
- **Master key** (`src/node/master_key.rs`): one 32-byte key for each Mac user in a Keychain generic
  password, account `node-master-key`, through `NativeHelper` (this device only, not synchronizable).
  When the helper says `keychain_unavailable` (development builds): a 0600 file `node/master.key` and a
  visible note. A lost key means a new empty node: nothing secret is lost (decision 2); the owner adds
  the cloud agents again.
- **Personal team bootstrap:** `Hub::create_personal_team(name) -> TeamId` makes the team row and the
  team file with the owner member; the owner token is generated, hashed, and discarded. One team for each
  vault; the vault stores `node_team_id`. A restart reopens teams from `relay.db`. No team code.
- **Lifecycle** (`src/desktop/node.rs`, as `sync_companion`): start when a vault with cloud agents is
  unlocked and the route is on; stop (Funnel off, then `RunningRelay::stop`, then join the host thread)
  from `end_waiting_runs` and `on_exit`. **Window close:** a half-day spike on `close_requested`; if
  reopen is not reliable, the documented limit of the defaults above.

### 2. The Mac as host, in-process; how values reach the proxy

**Chosen: a value-provider seam.** The relay store holds only metadata for shared items: `uid`, name,
`env_name`, hosts, provider, environment, risk, scope, reversibility, in collection "cloud". `sealed`
holds a one-byte marker, so the HTTP release path fails closed (`release_invalid`). At release, the
in-process host reads each value from the vault (`Vault::reveal`) and calls the new
`host::release_values(core, run_id, values, reason)`: it takes the run key (one use), rechecks steps 1
and 3, runs `check_value`, `env_items`, `sessions.create`, and writes `run_released` with actor
`host:embedded`. No `authorize_host`: the caller owns the store.

**At rest the node directory holds:** team metadata, item metadata, agent token hashes, run rows (masked
command, purpose, user request), and the audit; never a value or an item key. All in SQLCipher files
under the Keychain master key.

Why: the vault stays the only copy; a rotated value applies at the next run without a new seal; a lost
node directory loses nothing secret. Rejected: (a) items sealed into the relay store with item keys in
the vault: a second ciphertext copy and a new seal on every edit; (b) `apassy-team host` with
`keys.json`: a plain-text key file and a second policy next to the bouncer (the prototype).

**Catalog mirror** (`src/node/catalog.rs`): on node start and on each change of visibility, env
binding, or archival: one relay item for each vault item that a cloud agent sees and that is eligible
(an env binding with placeholder hosts; the value passes the relay's `check_value`); archive the others;
set the item list of each relay agent (decision 3).

**Host loop** (`src/node/host.rs`, one thread for each node): waits on the relay notifier through
`RunningNode::wait_pending`; for each pending run maps relay ids to vault ids, calls the new
`broker::run::evaluate_cloud(ctx, agent_id, &RunRequest, CloudContext)` (= `run_inner` with
`evaluation_only`, without `authenticate` and `prompts.resolve`), and on `Approved` releases, else denies
with the reason. Activity: one row at the decision ("cloud run", agent, items, decision, reason) and one
at session end with the counts of the relay's `proxy_request` rows (host, status, outcome), as ADR 0011
§5 does locally. The host checks released runs every 5 s for session end.

### 3. Visibility, identity, token, limits

- **Vault** (next schema version; check the number): `agent.kind TEXT NOT NULL DEFAULT 'local'`
  (`local` | `cloud`); table `cloud_agent(agent_id PK, relay_agent_id, token_expires_at, last_used_at)`;
  table `cloud_item(item_id PK, uid)`; setting `node_team_id`. A cloud agent is a normal vault agent, so
  ADR 0012 visibility, "never for this agent", and the activity log work unchanged. A new cloud agent
  starts with `see_all = 0` and an explicit pick of items.
- **Relay** (team schema 7): `agent.items TEXT NULL` (JSON item ids; NULL = all granted). `check_access`
  and `admin::access` filter by it. Down-migration documented as for schemas 5 and 6.
- **Token:** the relay agent token, made in-process by `admin::create_agent` with the lifetime from the
  UI (30, 90 default, 365 days), shown once, copied with `copy_secret`, stored as a hash. Revoke =
  `admin::revoke_agent` (ends sessions, invalidates pending runs) + vault `revoke_agent`. Renew = revoke
  and a new token.
- **Limits for a public endpoint:** personal team limits `agents 20, runs_per_hour 120, pending_runs 10,
  agent_requests 16`; the public listener has its own `Limits { max_active: 32, member_reserve: 0 }`;
  body caps as today. New: a failed-auth limiter for each listener: 20 bad bearers or session keys in
  60 s → 429 `rate_limited` with `Retry-After: 60` for that listener, one audit row per 10 s.

### 4. The public route

- **Relay:** `RelayConfig.public_listen: Option<SocketAddr>`; `Relay::start` binds a second
  `tiny_http` server (thread `relay-public-accept`); `http::handle` takes `Scope::{Node, Public}`.
  `Public` routes only `POST /mcp` and `/p/*`; everything else, `/healthz` included, is 404. No header is
  trusted; `tailscale-*` joins the request headers that the upstream proxy drops. Funnel ends TLS in
  `tailscaled` on the Mac and connects from loopback, so `EdgeMode::Off` holds.
- **App** (`src/node/funnel.rs`, the CLI paths from `hosts.rs`): `status --json` → `BackendState ==
  Running`, `Self.DNSName`; `serve status --json` → refuse if 443 has or would get Funnel (the app never
  passes 443); refuse if 8443 is held by a handler whose target is not the app's port, and say so (offer
  10000, the only other Funnel port); enable with `tailscale funnel --bg --https=8443
  http://127.0.0.1:<port>`; disable with `tailscale funnel --https=8443 off`. Never `funnel reset` or
  `serve reset`: they would drop the other handlers. Apply again on each start, turn off on lock and
  quit, clean stale entries at start.
- **Loopback port:** chosen once (a free port in 49152–65535) and stored in the preferences, so the
  Funnel target stays the same.
- **States:** no CLI → "Install Tailscale and sign in"; not running → "Tailscale is not connected";
  the policy refuses Funnel → the CLI's message with its admin-console link; the tailnet name changed →
  restart the node with the new `public_url` (sessions end).
- **URL:** `https://<DNSName>:8443` is `public_url`; the UI shows `<public_url>/mcp`.

### 5. Trust in `user_request`

A cloud agent has no hook. The agent text goes into `PendingRun.user_request` with the source "from the
cloud agent, not verified"; `injection_flag` still applies. In this release every cloud run asks the
owner: `Route::Ask` with a new `ReasonKind::CloudAgent`, no project, nothing remembered, no automatic
allow. The card names the agent and shows the request as not verified. Later, with usage data: an
"allow known safe, non-production commands" switch for each agent, as `apassy-team host` has.

### 6. UI: Settings → Cloud agents

Mockup first (`docs/design/cloud-agents-mockup.html`), approved by the owner before the UI unit writes
code; a screenshot of each view next to the mockup before any release claim. Content: a status block
(Tailscale name, route off or on, URL, port, warnings); the switch "Public route (Tailscale Funnel)"
behind an owner check; "Add a cloud agent…" (name, kind Grok Bot or other MCP client, item picker, token
lifetime) → a one-time sheet with the token and "Copy setup" (MCP URL, `Authorization: Bearer …`, the
Grok Bot steps); the list (name, items, expiry, last use, live session, Revoke… with an owner check);
"Recent cloud activity" (last 20 masked relay audit rows).

### 7. Grok Bot artifacts

`deploy/plugins/apassy-cloud/` in this repository, mirrored to the marketplace repository:
`.cursor-plugin/plugin.json`, `mcp.json` (URL and `Authorization: Bearer` header from the user's own
values; verify the interpolation syntax), `README.md` (Apassy → Settings → Cloud agents → Add → Copy
setup; Grok Bot → add the MCP server by URL and header), `skills/apassy/SKILL.md` (list access, request
a run, poll the status, run with `session.env`, never print it). `.grok-plugin/` only if xAI publishes a
format. `docs/store/grok-bot-submission.md`: listing text and testing instructions.

### 8. Docs, contracts, security review

- New `docs/contracts/cloud-agents-v1.md`: the public surface (tools, `/p/` rules, auth, limits, codes,
  what the agent never gets). Relay `docs/SPEC.md`: config (edge mode, public listener), scope, embedded
  release, a new section "Embedded node"; `docs/OPERATIONS.md`: schema 7 rollback.
  `docs/security/trust-model.md`: Funnel and `tailscaled` rows. ADR 0037: one status line "cloud slice
  first (2026-11-03)". CHANGELOG, README "Cloud agents".
- **Security review scope:** the public listener (scope filter, parser limits, failed-auth limiter, 404
  for everything else); the Funnel route (never 443, never a reset, off on lock and quit, stale config);
  token auth and revocation at the next request; proxy refusals on the public scope (misplaced
  placeholder, wrong host, body, private upstream addresses); `release_values` (one-time key, rechecks,
  `check_value`); lock behaviour (sessions and keys gone, Funnel off); what the audit stores. Panel:
  2× opus + 1× fable judges, read-only.

## Work units

| Unit | Files | Acceptance tests (written by the worker, run by CI) |
| --- | --- | --- |
| U1 Relay seams | `crates/apassy-relay/src/{config.rs, embedded.rs (new), api.rs, server/{mod,http,host,admin,decide,store,mcp}.rs, proxy/mod.rs}`, `tests/embedded.rs` (new), `src/node/backend.rs` (new, the traits), relay `docs/SPEC.md`, `docs/OPERATIONS.md` | `Off` with a non-loopback bind is refused; the existing suite passes in `Required`; public scope: `/v1/me`, `/healthz`, `GET /` → 404, `/mcp` and `/p/` work; schema 6 → 7 and back; `agent.items` filters `access` and `check_access`; `release_values` is one-use, fails closed on a bad value, writes the audit rows; bootstrap; a restart reopens; the limiter trips and resets; `tailscale-*` is dropped upstream |
| U2 Node, host, catalog, funnel, vault | `src/node/{mod,catalog,host,funnel,master_key}.rs` (new), `src/desktop/{node.rs (new), mod.rs}`, the next vault schema, `src/vault/agents.rs`, `src/broker/{run,decide,route_diagnostics}.rs`, `src/companion/hosts.rs`, `crates/apassy-app/**` (new), `scripts/build-app.sh`, `.github/workflows/ci.yml` | With a fake backend: the catalog mirror is idempotent and archives; a cloud run always asks, nothing is remembered, the injection flag asks; approval releases the vault values in item order; denial denies with the reason; activity rows at decision and session end; lock stops the node and turns Funnel off (fake CLI); `funnel.rs` parses `serve status --json` fixtures (443 in use, 8443 foreign, policy refusal); vault migration up and down; the window-close spike result in the PR |
| U3 UI, docs, plugin | `docs/design/cloud-agents-mockup.html`, `src/desktop/ui/{settings_view.rs, settings.rs, cloud_agents.rs (new)}`, `docs/contracts/cloud-agents-v1.md`, `docs/security/trust-model.md`, `deploy/plugins/apassy-cloud/**`, `docs/store/grok-bot-submission.md`, `CHANGELOG.md`, `README.md` | Mockup approved by the owner before UI code; each view next to the mockup; the token appears once and is copied with `copy_secret`; Revoke and the route switch need an owner check |
| U4 Integration, review, E2E | `crates/apassy-app/tests/cloud_e2e.rs` (new): embedded relay + public listener on loopback + a test asker + a local TLS upstream | The loopback E2E passes in CI; the review finds no open high finding; the owner's physical E2E below |
| U5 Release | `release-versions.json`, manifests, `MARKETING_VERSION`, extension manifest, CHANGELOG date | `scripts/check-release-versions.py`; all six components live at one version (AGENTS.md) |

## Order, parallelism, checks

1. U1 starts first and lands the traits in `src/node/backend.rs` early. U2 starts on the vault schema,
   `funnel.rs`, `master_key.rs`, and the `apassy-app` crate against those traits. U3 starts with the
   mockup. Never more than three workers on this Mac.
2. U2's wiring and U4 wait for U1. One editor for each shared file: `src/broker/run.rs` belongs to U2;
   `settings.rs` to U3.
3. Each unit is a draft PR; it is marked ready when complete and merged after the ready run is green
   (macOS groups included).
4. Workers never run lint, typechecks, builds, or full suites; they return the commands. The top-level
   agent runs one pass for each revision through CI, or locally only through `~/.local/bin/heavy-check`.
5. Sizes: U1 M, U2 L, U3 M, U4 S–M, U5 S.

## End-to-end acceptance (owner, physical)

1. Funnel is allowed for this Mac in the tailnet policy, and the prototype handler on 8443 is removed.
2. Settings → Cloud agents: route on, URL shown; a synthetic item for `httpbingo.org` (`HTTPBIN_TOKEN`);
   agent "Grok Bot" with that one item; Copy setup.
3. In Grok Bot (model gpt-6.1-sol fast): add the MCP server by URL and header. `apassy_list_access`
   shows one item. `apassy_request_run` for `curl -H "Authorization: Bearer $HTTPBIN_TOKEN"
   $APASSY_BASE_HTTPBIN_TOKEN/bearer`.
4. The question appears on the Mac and the iPhone with "from the cloud agent, not verified"; the owner
   approves on the Mac.
5. The Bot runs the command; the answer shows the placeholder, not the value; the Mac's activity log has
   the decision row and the session summary; the relay audit has one `proxy_request` row.
6. Lock the vault: `apassy_run_status` and `/p/` fail; `tailscale serve status` shows no Funnel on 8443.
   Unlock: the route returns. Revoke the agent: the next call is 401.
7. A packet log of the Bot's traffic shows only the Funnel URL; no request to `apassy-relay.wyderka.cc`.

## Release

One release of all six components at one version (AGENTS.md): Mac app (this feature), relay (schema 7,
embedded mode; hosted behaviour unchanged, `team_vaults` stays off), Linux CLI, extension, and iOS
(version only), website (changelog). `scripts/check-release-versions.py` before publication; verify
each live artifact. The plugin directory ships in the repository and the marketplace mirror, not as a
seventh component.

## Risks

| Risk | Mitigation |
| --- | --- |
| A public listener on a personal Mac | Loopback bind, scope filter, bearer tokens, team and lane limits, failed-auth limiter, off on lock and quit, security review before release |
| The Bot holds a session key and placeholders and can use the proxy until the session ends (way B) | TTL 600 s; revoke ends sessions at once; every request is in the audit |
| Machine name in Certificate Transparency logs (Funnel certificate) | Stated once when the route is enabled (ADR 0037 risk) |
| Window close may quit; the Mac must be unlocked and awake for every run | Spike in U2; else the documented limit; a power assertion while a session lives is a later unit |
| Two schema bumps (vault, relay 7) | Down-migrations with tests; rollback notes in OPERATIONS |
| Moving the `apassy` bin to `crates/apassy-app` changes build commands | Scripts and CI updated in U2 |
| Grok Bot's MCP client behaviour (Origin header, 202, `isError`) is not known | Loopback E2E with a generic client in CI; the physical E2E decides |
| Keychain item lost on reinstall or a new signature | Node data is metadata only; the UI says "add your cloud agents again" |

## Not verified in the code

- Whether `NativeHelper::keychain_store` sets this-device-only, non-synchronizable attributes (Swift
  helper; `src/native/mod.rs:921`).
- Cursor plugin manifest fields and the `mcp.json` interpolation syntax; whether Grok Bot reads a
  plugin's `mcp.json` or only its own URL and header setting.
- `tailscale funnel --https=8443 off` on 1.104.4 and the exact `serve status --json` shape.
- Whether the relay sweep signals session expiry; the plan polls every 5 s instead.
- The next vault schema number (`src/vault/schema25.rs` is the newest file).
- `evaluate_run` (`src/broker/decide.rs:78`) authenticates by token first (`run.rs:745`); the new
  `evaluate_cloud` must bypass that.
