# Implementation plan — the Bouncer section and self-connecting remote agents

Date: 2026-11-03. Status: PLAN.
Decision: [ADR 0037](../adr/0037-own-relay-open-source.md) cloud slice; the owner's feedback of 2026-11-03;
the mockup `docs/design/cloud-agents-mockup.html` (PR #92: 14 frames, notes F1–F6).
Parent: [implementation-plan-0037-cloud-agents.md](implementation-plan-0037-cloud-agents.md). Its decisions 1, 2, 4,
5, 7, 8 stand. Decision 6 and the token part of decision 3 are replaced here.

## Outcome

The sidebar gets a section **Bouncer**: Overview, Decisions, Agents, Logs. Every page shows all Macs of the vault
("environments") through one scope bar; other Macs are read-only from relay-feed v2. A remote agent (first: Grok Bot)
gets only the MCP address; it connects with the MCP authorization flow (OAuth 2.1), the owner allows it in Decisions
with Touch ID (also on the iPhone), and it appears in Agents with no credentials until the owner chooses some. Every
remote run still asks the owner.

## Facts from the code (2026-11-03)

| Area | Fact | Where |
| --- | --- | --- |
| Branch base | `feat/cloud-agents-u1` and `-u2` do not contain PR #88 (scope bar, Mac feed reader) or #91 (decision log). The UI base is `main` b571d25b. | `git merge-base` |
| Layout | Every `Place` draws a list column and a detail column; no wide pane exists. ⌘1 credentials, ⌘2 Decisions, ⌘3 Agents. | `src/desktop/mod.rs:81`, `src/desktop/ui/shell.rs:98-140, 206-210` |
| Sidebar | `agents_section()` builds the "Agents" group: Decisions (red badge), Agents (count = local + other Macs' connected). | `src/desktop/ui/sidebar.rs:469-538` |
| Scope bar | `scope_bar(ui, &mut ActivityScope, devices, projects)`; state `app.ui.activity_scope`; `DeviceScope::{All, ThisMac, Other(id)}`. Lists only Macs with a feed; hidden with one Mac. | `src/desktop/ui/scope_bar.rs:28`, `src/desktop/remote_feeds.rs:49-61` |
| Feeds | `app.remote_macs` (Ready / NeedsSync / NeedsUpdate), in memory; no 24 h dim in the UI. `Feed::parse` needs `v == 1`, `deny_unknown_fields`; `place == "mac"` enforced. The iPhone core has its own strict parser (`v == 1`). | `remote_feeds.rs:25-135`, `src/questions/feed.rs:215-345`, `ios/ApassyCore/src/core/feed.rs:271-452` |
| Contract | "A new field in a feed … is a new `v`"; an old reader shows "Update Apassy to see the agents of <Mac>". | `docs/contracts/relay-feed-v1.md` §7.1, §14.1 |
| Run data | `decision_log(at, agent_id, agent_name, asked, decision allow/deny, decided_by rule/model/pattern/owner/no_answer, …)`, index on `at`; `item_use(at, item_id, agent_id, project_label, outcome, decided_by, answered_on, decision_log_id)`. No answer-time column. | `src/vault/learning.rs:62`, `src/vault/schema18.rs:123`, `src/decision_log.rs` |
| answered_on | Only `CheckMethod::Companion` yields "iPhone"; a relay answer is logged as the Mac. | `src/broker/run.rs:1387-1392` |
| Agents list | `list_column` calls `local_facts()` → `agent_uses(id, 500)` for each agent, each frame. | `src/desktop/ui/agents.rs:357, 391-412` |
| Questions | One card kind (run), `deny_unknown_fields`, `QUESTION_CARD_VERSION = 1`; a card's `v` is per card; an unreadable `v` shows "Update Apassy to read this question". The Watch never answers run questions. | `src/questions/envelope.rs:31, 231`, `relay-questions-v1.md` §7.1, §17 |
| Cloud run | `evaluate_cloud` → `run_inner(evaluation_only)`; `ReasonKind::CloudAgent`; `request_source = "from the cloud agent, not verified"`; `valid_answers = [Once]`; the card reaches the iPhone as a normal run card. | U2 `src/broker/run.rs`, `src/node/host.rs` |
| Relay public scope | `Scope::Public` serves `POST /mcp` and `/p/*`; everything else 404. JSON only; no `WWW-Authenticate`. Failed-auth limiter 20 / 60 s per listener. `/mcp` refuses a foreign `Origin`. | U1 `crates/apassy-relay/src/server/http.rs` |
| Relay store | Team schema 7 (`agent.items`); directory `relay.db` version 1003. Audit `proxy_request` rows hold `ProxyEvent {at, method, host, path, status, outcome, code}`; `EmbeddedNode::audit` filters by run id. | `store.rs`, `directory.rs`, `sessions.rs`, `embedded.rs` |
| Node API | `RunningNode` has no connect or OAuth method. `Node::add_agent(name, items, days) → token`; `cloud_node(team_id, port, route_on)` in the vault; `keep_open_for_node` cancels close and minimizes. | `src/node/backend.rs`, `src/node/mod.rs`, `src/desktop/node.rs` |

## Decisions

### 1. Navigation and layout

- **Places.** `Place` gains `Overview` and `Logs`; `Agents` and `Decisions` stay. `Place::is_wide()` is true for
  Overview, Agents, Logs: `shell.rs` skips the list panel and calls `wide_pane(app, ui)`. Decisions keeps list and
  detail. The agent page is `Place::Agents` with `app.ui.agents.open: Option<AgentRef>`
  (`AgentRef::{Local(u64), Other{device, id}}`); "‹ Agents" and ⌘[ clear it.
- **Shortcuts.** ⌘1 credentials, ⌘2 Overview, ⌘3 Decisions, ⌘4 Agents, ⌘5 Logs.
- **Sidebar.** `agents_section()` becomes `bouncer_section()`: title "Bouncer"; rows Overview, Decisions (badge =
  waiting runs + pending connects), Agents, Logs. The Decisions "Activity" button and its timeline go: that view is
  the Logs page. A notification deep link (`activity_id`) opens Logs with the row selected. Settings → Bouncer
  (brain) stays.
- **Scope bar** on all four pages, one shared `app.ui.activity_scope`. Words: "All Environments", "All Projects". The
  environment list: this Mac first, then every live `trusted_device` of kind `mac`, with the feed's age or "Never
  reported"; never-reported last and dimmed. The menu always shows (one Mac: "Other Macs appear when they use this
  vault."). A Mac whose feed is older than 24 h is dimmed everywhere (contract §8).
- **Kit additions** (`kit.rs`): stat tile, 7-bar chart, environment header ("This Mac" / "Read-only"), cloud badge on
  the avatar, "Remote" cap, ⓘ help popover, empty-state block (title ≤ 5 words, line ≤ 12 words, one button, one link).

### 2. Data per page

| Data | This Mac | Other Macs |
| --- | --- | --- |
| Agents, status, projects | vault `agent`, `item_use`, node (remote agents) | feed `agents[]` (v1 fields) |
| Runs, asked, denied, per day, per agent (F3, F5) | `decision_log` 7-day pass (decision 3) | feed v2 `week.days`, `agents[].days` |
| Median answer (F4) | `decision_log.wait_ms` (schema 27) | feed v2 `week.answer_p50_secs`; across Macs, each Mac's p50 weighted by `week.by_you` (approximate, said in the ⓘ) |
| Remote agents (F1, F2) | `agent.kind = cloud`, `cloud_agent` | feed v2 `agents[].where = remote`, `connected_at` |
| Remote access (F6) | `Node::status` | feed v2 `remote_access` (never the address) |
| Open questions, connects | approval queue, `Node::pending_connects` | none (questions lane) |
| Proxied requests | relay audit by run id | none (§7.2) |

**Feed v2, not additive v1.** The contract (§14.1) makes any new field a new `v`; both readers are strict. The
publisher writes `v: 2` with `remote_access: off|on|problem`, `week.days` (7 × `{runs, asked}`, today first, local
days), `week.answer_p50_secs` (number or `null`), `agents[].where: mac|remote`, `agents[].connected_at`, `agents[].days`
(7 × `{runs, asked, not_allowed}`). Under 20 KiB; `fit` (§7.3) never cuts `days`. Readers (Mac `feed_reader.rs`, iPhone
`ios/ApassyCore/src/core/feed.rs`) accept `v` 1 or 2; a v1 feed fills the new tiles with "—". Old readers show "Update
Apassy to see the agents of <Mac>" until updated; all six components ship together.

**Vault schema 27** (U3a, after U2's 26): `decision_log.request TEXT NOT NULL DEFAULT 'run'`
(`run | browser_fill | connector`), `decision_log.wait_ms INTEGER NULL`, `cloud_agent.client_id TEXT NULL`,
`cloud_agent.connected_with TEXT NOT NULL DEFAULT 'token'` (`oauth | token`), table
`cloud_run(relay_run_id PK, decision_log_id, agent_id, at, ended_at, forwarded, refused, failed)`. Down-migration as for 26.

### 3. Overview stats

Window: the last 7 × 24 h; per-day bars by local calendar day, today first. One `decision_log` row with
`request = 'run'` is one run.

| Figure | Definition |
| --- | --- |
| Runs | rows in the window |
| Allowed by bouncer | `asked = 0 AND decision = 'allow'`; % of runs |
| Asked you | `asked = 1`; % of runs |
| Denied | `decision = 'deny'` (by you, by a rule, or no answer) |
| Median answer | median of `wait_ms` over `asked = 1 AND decided_by = 'owner'`; "—" when none |
| Ask rate (agent) | asked / runs; orange and an attention item at ≥ 25 % with ≥ 10 runs |
| Last active | newest `item_use.at`; "Active now" within 10 min; "Waits for you" with an open question |
| Attention, in order | a Mac silent 24 h after reporting before; a production credential used; an agent that asks often; a remote agent with a denial |

Computation: `Vault::bouncer_stats(since, until, project) -> LocalStats` (new `src/vault/stats.rs`), one SQL pass over
`decision_log` joined to `item_use`, grouped in Rust. The app keeps `BouncerCache`, recomputed when an activity change
counter moves (at most once per 2 s) and when the feed poll sees changed rows. No vault query runs per frame; the
Agents list drops `local_facts()` for the cache. The publisher computes the feed's `days` and `answer_p50_secs` from
the same function.

### 4. Remote agents connect by themselves

**Endpoints** on the relay, served only when `RelayConfig.oauth` is set (embedded config; the hosted relay keeps 404):

| Endpoint | Answer |
| --- | --- |
| `GET /.well-known/oauth-protected-resource` and `…/mcp` (RFC 9728) | `resource = <origin>/mcp`, `authorization_servers = [<origin>]`, `bearer_methods_supported = ["header"]`, `scopes_supported = ["apassy"]` |
| `GET /.well-known/oauth-authorization-server`, also `/.well-known/openid-configuration` (RFC 8414) | `issuer`, the endpoints below, `response_types_supported = ["code"]`, `grant_types_supported = ["authorization_code","refresh_token"]`, `code_challenge_methods_supported = ["S256"]`, `token_endpoint_auth_methods_supported = ["none"]` |
| `POST /oauth/register` (RFC 7591) | 201 with a random `client_id`, the echoed fields, `token_endpoint_auth_method = "none"`, no secret |
| `GET /oauth/authorize` | makes a connect request (id, match code, 300 s), 303 to `/oauth/wait/<id>` |
| `GET /oauth/wait/<id>` | the page of frame 7 with `Refresh: 3`; allowed → 303 to `redirect_uri?code=…&state=…` once; denied → "You denied the connection."; expired → "The request ended." |
| `POST /oauth/token` | `authorization_code` with PKCE, or `refresh_token`; `access_token` = the relay agent token (so `/mcp` auth is unchanged), `token_type = "Bearer"`, `expires_in`, `refresh_token`; errors as RFC 6749 §5.2 |
| `POST /oauth/revoke` (RFC 7009) | 200 always |
| `POST /mcp` 401 | adds `WWW-Authenticate: Bearer resource_metadata="<origin>/.well-known/oauth-protected-resource/mcp"` |

The relay gets a small form decoder in `server/oauth.rs`, no new crate.

**Rules.** PKCE S256 required; code 300 s, single use, bound to client, redirect URI, challenge, and request; a second
use revokes the token family. Access token 24 h (`ACCESS_TOKEN_SECS`); refresh token 90 days, rotated at each use,
reuse revokes the family. Redirect URIs: `https://…`, or `http://localhost|127.0.0.1|[::1]` with any port (RFC 8252);
exact match otherwise; ≤ 512 bytes. `resource`, when sent, must equal `<origin>/mcp`. One live access token per agent.

**Limits on the public listener.** Registrations 10 per 10 min and 100 stored clients (unused clients pruned after
7 days). Open connect requests ≤ 3 per node and 1 per client. Bad codes and refresh tokens count in the failed-auth
limiter. Funnel forwards no client identity, so every limit is per node.

**The page.** No script, form, cookie, or button: nothing on it can authorize. Headers: `Content-Security-Policy:
default-src 'none'; style-src 'unsafe-inline'`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`,
`Cache-Control: no-store`, `X-Content-Type-Options: nosniff`. It shows the client name (cleaned, ≤ 64 bytes, escaped),
the Mac's name, the match code, and the state text; never an item, an agent list, or the owner's name.

**Storage** in the directory `relay.db` (1003 → 1004): `oauth_client`, `connect_request`, `oauth_refresh`. Codes and
refresh tokens are stored hashed. Rollback note in `OPERATIONS.md`.

**Trait additions** (`src/node/backend.rs`, implemented in `embedded.rs`): `pending_connects()`,
`decide_connect(id, ConnectDecision::{Allow{team, agent}, Deny})`, `NewCloudAgent.token: TokenIssue::{Now{lifetime_days},
Later}`, `agent_access(team, agent)`; `revoke_agent` also drops the refresh family and denies the client's open requests.
The authorize handler wakes `wait_pending`; the host loop polls `pending_connects()` after each wake and every 5 s.

**The Mac side** (`src/node/mod.rs`, `host.rs`): `Node::pending_connects()`, `Node::allow_connect(vault, id)` (behind
`OwnerRequest::AllowConnect`, "Connect <name> to this Mac"), `Node::deny_connect(id)`. Allow: relay agent with no items
→ vault `add_cloud_agent` (kind `cloud`, `see_all = 0`, `client_id`, `connected_with = oauth`) → `decide_connect(Allow)`;
if the vault save fails, the relay agent is revoked and the request denied. Name = `client_name`, or "MCP client"; a
taken name becomes "Grok Bot 2". The same `client_id` with a live agent reconnects to that agent. Activity rows:
`remote agent connected`, `agent disconnected`, `remote access on`, `remote access off`. The host writes `cloud_run` rows.

**CLI fallback.** `apassy agents add-remote <name> [--days 90]` (owner check): creates the agent
(`connected_with = token`, no items) and prints the token once with the MCP address.

**Removed from U2:** the UI-facing `Node::add_agent(name, items, days)`, the item picker at creation, and the one-time
token sheet. `Shared::add_agent` stays as the internal primitive of the CLI fallback.

### 5. Agents page and agent page

- **Page** (wide): for each environment in scope, a header (This Mac / Read-only, report age, "Remote access off" for
  other Macs from F6), a table (Agent, Project, Status, Runs Today, Asks You), a "Disconnected (n)" disclosure. Rows
  of other Macs open the compact read-only agent page ("Change on <Mac>."). "Connect an Agent…" keeps today's sheet
  for local hosts; remote agents never need a button.
- **Remote access block** of this Mac: switch (`Node::set_route`, owner check), MCP address, Copy, ⓘ. Problem states
  from `Node::status`: not installed → Get Tailscale…; not connected → Check Again; policy → Open Admin Console…; port
  taken → Use Port 10000. With the route on and no remote agent: "No remote agents yet. Give one this address."
- **Agent page**: header (avatar, name, Remote cap, ⓘ), four tiles, five recent runs, "Can see" (Only and Never rows,
  "Choose Credentials…"), "Disconnect…" last. "Choose Credentials…" opens today's ADR 0012 picker; the catalog mirror
  pushes the change to the relay agent's items. Disconnect: local = today's sheet; remote = the same sheet, then
  `Node::revoke_agent`.

### 6. Decisions

- **Open.** Connect requests join the waiting list (`Key::Connect(id)`). Card: "<name> wants to connect", the Mac, the
  timer, the Code row, one warning line, Deny / Allow (Touch ID).
- **Cloud run card**: "<Agent> wants to use <credential>", rows Credential, Agent (Remote cap), Sends To, Request
  ("Not verified" cap), Command; Deny / Allow Once.
- **History** below Waiting: All / Asked You / Automatic / Denied, an agent menu, day groups; this Mac from
  `Vault::bouncer_log`, other Macs from feed `recent` (read-only).
- **iPhone.** Run cards stay card v1. A connect request is card v2 `kind = connect` (`client_name`, `mac_name`, `code`),
  answered with Face ID or denied, settled like a run. An old iPhone shows "Update Apassy to read this question" for
  connect cards only. The Watch gets nothing new.
- **Empty states**: frames 9c and 10a.

### 7. Logs

`src/desktop/ui/logs.rs` (wide). `LogEvent {at, env, agent, kind: Run|Connect|Disconnect|RemoteAccessOn|RemoteAccessOff,
credential, outcome, relay_run}`. This Mac: `decision_log` ⨝ `item_use` (200 newest, "Load More"), the activity
operations, open runs and connects; other Macs: feed `recent` (runs only). Filters: All / Runs / Connections / Denied,
agent, text. Expanding a cloud run of this Mac shows time, method, host, status or "Refused: <code>" from the relay
audit; never a path, header, body, or value. Empty states: frames 9d and 14.

### 8. Docs and contracts

`cloud-agents-v1.md` §4 and §15 become the OAuth flow (the bearer token is the CLI fallback); `relay-feed-v1.md` gets a
v2 section and "accept 1 or 2"; `relay-questions-v1.md` gets card v2 `kind = connect`; `owner-cli-v1.md` gets
`agent_add_remote`; relay `SPEC.md` gets the OAuth endpoints, directory 1004, and limits; `OPERATIONS.md` the
rollbacks; `trust-model.md` the public page; the plugin README says "add the MCP server by URL, press Authorize, allow
on your Mac". CHANGELOG upgrade notes: vault 26 and 27, relay 7 and directory 1004, feed v2, connect cards.

## Work units

| Unit | Base → PR | Owns | Acceptance tests (the worker writes, CI runs) |
| --- | --- | --- | --- |
| L0 Land the stack | top-level agent | merge `main` into #86 and #89; merge #92 into #85; mark #85, #86, #89 ready; merge in that order | ready runs green (macOS groups) |
| U1b Relay OAuth and connects | #86 head → `feat/cloud-agents-oauth` | `crates/apassy-relay/src/server/{oauth.rs, connect.rs, http.rs, auth.rs, directory.rs, mcp.rs}`, `src/embedded.rs`, `src/config.rs`, `src/node/backend.rs`, `tests/oauth.rs`, relay `SPEC.md`, `OPERATIONS.md`, `cloud-agents-v1.md` | metadata; register → authorize → wait → allow → 303 → token → `/mcp` 200; wrong verifier and reused code → `invalid_grant` and family revoked; refresh rotates, reuse revokes; deny and expiry pages; limits; headers; `WWW-Authenticate`; hosted config → 404; directory 1003 ↔ 1004 |
| U3a Stats, schema 27, feed v2 | `main` after #89 → `feat/bouncer-stats` | `src/vault/{schema27.rs, stats.rs}`, `learning.rs`, `cloud.rs`, `src/broker/run.rs` (`wait_ms`, request kind, `answered_on` for relay answers), `src/questions/{feed,feed_reader}.rs`, `ios/ApassyCore/src/core/feed.rs`, `relay-feed-v1.md`, `tests/relay_feed.rs` | 26 ↔ 27; stats of a fixture vault equal hand-computed numbers; v2 within limits, `fit` keeps `days`; both readers accept 1 and 2, refuse 3; a relay answer gives `answered_on` = the iPhone |
| U2b Node connect | `main` after U1b, U3a → `feat/cloud-agents-connect` | `src/node/{mod,host}.rs`, `src/vault/cloud.rs`, `src/desktop/{node,owner_check,owner_socket}.rs`, `src/cli/**`, `owner-cli-v1.md`, `deploy/plugins/apassy-cloud/**`, store draft, trust model | allow makes a cloud agent with no items and decides on the relay; reconnect; "Grok Bot 2"; deny; expiry; disconnect revokes relay, family, vault; activity and `cloud_run` rows; CLI token once with the owner check |
| U3b-1 Navigation, Overview, Logs | `main` after U3a → `feat/bouncer-section` | `src/desktop/mod.rs`, `ui/{shell,sidebar,columns,scope_bar,kit,demo}.rs`, `ui/{overview,logs}.rs`, `remote_feeds.rs`, `keyboard_tests.rs`, `README.md` | ⌘2–⌘5; wide pane; never-reported Mac and one-Mac menu; Overview equals the stats fixture; Logs filters and expansion; empty states 9a, 9d, 10b, 11b, 14; no vault query per frame |
| U3b-2 Agents, agent page, Decisions | `main` after U2b, U3b-1 → `feat/bouncer-agents` | `ui/agents.rs`, `ui/agents/remote.rs`, `ui/{decisions,decisions_activity}.rs`, `ui/agent_onboarding.rs`, `owner_store/**` | tables per environment; states 8a–8d; agent pages; Choose Credentials… changes relay items; Disconnect… both kinds; connect card through the owner check; cloud run card; history filters; empty states 9b, 9c, 10a, 11a, 12, 13 |
| U2c Connect on the iPhone | `main` after U2b → `feat/connect-on-iphone` | `relay-questions-v1.md`, `src/questions/{envelope,worker}.rs`, `ios/ApassyCore/src/core/questions*.rs`, the Swift questions view | run cards stay v1; a connect card is posted, answered, settled once; an old reader shows the update text for it only |
| U4 E2E and review | `main` | `crates/apassy-app/tests/cloud_e2e.rs` (test OAuth client, loopback public listener, local TLS upstream); judge panel 2× opus + 1× fable on U1b, U2b | loopback E2E green in CI; no open high finding |
| U5 Release | `main` | `release-versions.json`, manifests, `MARKETING_VERSION`, extension manifest, CHANGELOG | `scripts/check-release-versions.py`; six components live at one version |

## Order, parallelism, checks

1. Phase 1: U1b, U3a, and the top-level agent on L0. Phase 2: U2b, U3b-1, and the iPhone half of U2c. Phase 3:
   U3b-2, the Mac half of U2c, U4. Never more than three implementation workers on this Mac.
2. One editor per shared file: `backend.rs` and `embedded.rs` belong to U1b; `run.rs` and `feed.rs` to U3a; `shell.rs`,
   `sidebar.rs`, `kit.rs` to U3b-1; `agents.rs`, `decisions.rs` to U3b-2; `worker.rs` to U2c.
3. Each unit is a draft PR, marked ready when complete, merged after the ready run is green. Workers never run lint,
   typechecks, builds, or test suites. The top-level agent validates one revision at a time through CI, or locally
   only through `~/.local/bin/heavy-check`.
4. Workers code against the types in this plan (`BouncerStats`, `LogEvent`, `PendingConnect`, `AgentRef`); a change
   to them goes through this file first.
5. Sizes: L0 S, U1b L, U3a M, U2b M, U3b-1 L, U3b-2 L, U2c M, U4 S–M, U5 S.

## End-to-end acceptance with Grok Bot (owner, physical)

1. Funnel is allowed for this Mac in the tailnet policy; the prototype handler on 8443 is removed.
2. Agents → Remote Access on (Touch ID); the address appears; Copy. Add a synthetic item for `httpbingo.org`
   (`HTTPBIN_TOKEN`, a broad host: `httpbin.org` is on the Public Suffix List and is refused).
3. Grok Bot (model gpt-6.1-sol fast): add the MCP server by URL; press Authorize. The browser shows frame 7 with a
   code; Decisions shows "Grok Bot wants to connect" with the same code on the Mac and the iPhone; Allow with Touch ID;
   the browser shows "Connected"; the Bot lists the three tools.
4. Agents: "Grok Bot · Remote"; Choose Credentials… → the item. `apassy_list_access` shows one item;
   `apassy_request_run` for `curl -H "Authorization: Bearer $HTTPBIN_TOKEN" $APASSY_BASE_HTTPBIN_TOKEN/bearer`.
5. The run card shows "Not verified" on the Mac and the iPhone; Allow Once on the Mac. The answer shows the
   placeholder, never the value. Logs: the run row with one proxied request; the agent page counts it.
6. Deny a second run on the iPhone: Logs shows "Denied on iPhone".
7. A second Authorize (new client) → Deny → "You denied the connection." A third one left alone ends after 5 minutes.
8. Refresh: with `ACCESS_TOKEN_SECS` = 120 in a development build, the Bot keeps working after 2 minutes without a new
   Authorize. If not, note it and raise the constant.
9. Lock the vault: `apassy_run_status` and `/p/` fail, no Funnel on 8443; unlock restores it. Disconnect…: the next
   call is 401 with `WWW-Authenticate`.
10. A packet log of the Bot's traffic shows only the Funnel URL; no request to `apassy-relay.wyderka.cc`.

## Screenshots and release

- Before any release claim: a screenshot of each of the 14 frames next to the mockup (demo data through `demo.rs`;
  real for frames 7 and 8), and the mockup's text rules checked.
- One release of all six components at one version (AGENTS.md). Upgrade notes: vault schema 26 and 27, relay team
  schema 7 and directory 1004, feed v2, connect cards v2. `scripts/check-release-versions.py` before publication;
  verify each live artifact.

## Risks

| Risk | Mitigation |
| --- | --- |
| Grok Bot's OAuth client is unknown (registration, metadata path, redirect scheme, `resource`, refresh) | both metadata paths, loopback and https redirects, `resource` optional, one-constant access lifetime; the CLI token as fallback; a generic-client E2E in CI; the physical E2E decides |
| New public GET endpoints on a personal Mac | no script, form, cookie, or button; strict CSP and frame denial; node-wide limits; codes and tokens hashed; security panel before release |
| Feed v2 and connect cards break old readers until updated | the designed update texts; all components ship together; run cards stay v1 |
| U1 and U2 branches lack #88 and #91 | L0 merges `main` first |
| Two vault schema bumps in one release | down-migrations with tests; the installed app is swapped only from the release build |
| A new wide-pane layout | keyboard and layout tests in U3b-1; Decisions keeps its columns |
| The median across Macs is approximate | said in the Overview ⓘ |
| Connect requests expire in 5 minutes; the Mac must be unlocked and awake | the page says so; `keep_open_for_node` keeps the window alive |
| A relay answer is logged as the Mac | fixed and tested in U3a |

## Not verified in the code

- `ios/ApassyCore/src/core/feed.rs`: the strict parser was seen by grep, not read; its limits may differ from the Mac's.
- Whether Tailscale Funnel adds `X-Forwarded-For` to the loopback target; the plan uses node-wide limits only.
- `decision_log` rows for browser fills and connector uses; the `request` column makes "Runs" exact either way.
- The vendored `tiny_http` with a 303 and custom headers.
- The cost of `decisions_activity::load` per frame; replaced by `BouncerCache`.
- The day boundary of `ask_rate_by_day` (`src/vault/learning.rs:600`).
- Grok Bot's OAuth behaviour: steps 3, 7, and 8 of the end-to-end test check it.
