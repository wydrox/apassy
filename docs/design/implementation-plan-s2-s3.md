# Implementation plan — ADR 0037 stages 2 and 3: the node over the tailnet, the Linux node, and the end of the Wi-Fi companion

Date: 2026-11-03. Status: PLAN, written on the owner's decision of 2026-11-03 ("build everything in the ADRs except the TEE track, as fast as possible, with many parallel agents; no approval of intermediate steps").
Decision: [ADR 0037](../adr/0037-own-relay-open-source.md) stage 2 (the rest), stage 3, D4, D6, D7; [ADR 0028](../adr/0028-retire-wifi-companion.md) stage 3; [ADR 0020](../adr/0020-iphone-companion.md) (the code that moves); [ADR 0032](../adr/0032-connect-onboarding.md) (the handoff that stays); [ADR 0033](../adr/0033-iphone-access-requests.md) (unchanged inner protocol).
Parent: [implementation-plan-0037.md](implementation-plan-0037.md), stages 2 and 3, refreshed against `release/0.5.16` at `dd71868c`. Sibling plans that run now: [cloud agents](implementation-plan-0037-cloud-agents.md) (shipped on this branch: U1, U2, U3, docs) and [the Bouncer section](implementation-plan-bouncer-section.md) (U1b, U2b, U2c, U3a, U3b-1, U3b-2 in progress). Format: [plan 0035](implementation-plan-0035.md).

Where an ADR leaves a choice open, this plan takes the recommended option and marks it **chosen by this plan; the owner can change it**.

## Outcome and constraints

After this plan, an iPhone on cellular with Tailscale approves a run on the Mac with no request to `apassy-relay.wyderka.cc`: the questions, the feed, and the access requests go to the relay inside the Mac app, over the tailnet, behind a pinned certificate. A Linux machine runs the same node without a window (`apassy serve`), as a systemd user service, from a `.tar.gz` or a `.deb` with checksums, and the Mac and the iPhone pair with it. Push notifications still arrive, through a small gateway that holds the APNs key and nothing else. The Wi-Fi companion shows its end-of-life notice in this release and goes two releases later.

- **No TEE, no Connect.** Stage 7 (Apassy Connect) and the enterprise track stay out. The hosted relay keeps relay sync, questions, feed, and push until stage 7 (ADR 0037, Migration).
- **The wire contracts do not change shape.** relay-questions-v1, relay-feed-v1, relay-access-request-v1, relay-sync-v1, and the ADR 0019 device identity move to a new origin. The only additions are a fragment grammar for pairing links (`node-pairing-v1`), a push-handle contract (`push-gateway-v1`), and two relay endpoints for push handles.
- **One release of all six components at one version** (AGENTS.md). Section "Release grouping" says what ships together.
- **Nothing listens on `0.0.0.0`.** The relay stays on the loopback; a TLS front on the tailnet addresses makes it reachable (ADR 0037 §2, §3).
- **Numbers reserved for this plan** (to avoid collisions with the parallel plans): vault schema 28, relay team schema 8, relay directory 1005. New contracts: `node-pairing-v1`, `push-gateway-v1`.
- **Mac resources:** at most three implementation or validation workers on this Mac across all sessions. Workers never run lint, typechecks, builds, or full suites; they return the commands. The top-level agent validates one revision at a time through CI, or locally only through `~/.local/bin/heavy-check`.

## Facts from the code (2026-11-03, `release/0.5.16` at `dd71868c`)

| Area | Fact | Where |
| --- | --- | --- |
| Embedded relay | `RelayConfig::embedded(EmbeddedOptions { data_dir, master_key, public_url, public_listen })` sets `listen = 127.0.0.1:0` (`Scope::Node`, every route), `edge = EdgeMode::Off`, `push: None`, `team_vaults: true`, `connect_teams_per_day: 0`. `Relay::start` refuses `EdgeMode::Off` unless every listener is loopback. | `crates/apassy-relay/src/config.rs:252-263`, `:389-414`; relay `docs/SPEC.md` §6, §30.1 |
| Node seam | `NodeBackend::start(NodeConfig) -> Box<dyn RunningNode>`; `RunningNode` has `node_addr()`, `public_addr()`, `create_team`, `has_team`, `sync_items`, `create_agent`, `release`, `deny`, `recent_audit`, `stop`. No device, link, or questions method: the Mac is the owner member in-process without a token. | `src/node/backend.rs` (whole file), `crates/apassy-relay/src/embedded.rs:1-60` |
| Node service | `Node::start` makes the master key (Keychain through `NativeHelper`, else a 0600 file), chooses a stable public port in 49152–65535, makes the personal team, mirrors the catalog, turns Funnel on 8443 on, and runs the host thread. The desktop starts it from `sync_node` and stops it from `end_waiting_runs` and `on_exit`. | `src/node/mod.rs:1-140`, `src/node/master_key.rs:1-40`, `src/desktop/node.rs:72-260`, `src/desktop/mod.rs:357, :513` |
| Tailscale | `funnel.rs` parses `tailscale status --json` (`BackendState`, `Self.DNSName`) and `serve status --json`; `SystemTailscale` runs the CLI from four fixed paths. The companion finds the Tailscale IPv4 the same way and orders link hosts: Tailscale IPv4, `<name>.local`, primary IPv4. | `src/node/funnel.rs:43-240`, `src/companion/hosts.rs:35-115` |
| Sign-in origin | The relay verifies a device sign-in with exactly `core.config.public_url` in the signed message `apassy-relay sign-in v1\0<origin>\0<team>\0<key>\0<nonce>`. One origin per relay. | `crates/apassy-relay/src/server/devices.rs:210`, `src/device.rs:137-155` |
| Public URL | `checked_public_url` takes `https://` (or `http://`) plus a host, an optional port, and nothing else; no path, query, or fragment. | `crates/apassy-relay/src/config.rs:607-621` |
| Client URL | `RelayUrl { origin, destination }`: the origin string is what the app stores and signs; the destination is where it connects. `parse_destination` allows `https://` to any host and `http://` to loopback only. | `src/sync/relay_http.rs:70-120`, `src/broker/http.rs` (`parse_destination`) |
| Client trust | `TlsClient::platform()` builds rustls with `rustls_platform_verifier` and the ring provider; `with_extra_roots` for tests. No pin. The relay client makes one connection per request, HTTP/1.1, with `Cancel` and a deadline. An external transport can replace TCP once per process (`set_http_transport`, the watch). | `src/broker/http.rs:150-175`, `src/sync/relay_http.rs:1-60` |
| Link format | A device link is `<relay URL>/link#<code>`; `PendingJoin::parse_link` splits on `/link#` after `PairingChannel::parse` strips `&handoff=…`. `LinkCode { code, link, expires_at }` is made with `POST /v1/devices/links`; the link text is built from the client's own origin. | `src/sync/relay.rs:2392-2460`, `src/sync/relay/devices.rs:85-99`, `src/relay/pairing.rs:14-100` |
| Memberships | `RelayMembership { relay_url, team_id, device_id, key_pkcs8, purposes, public_key }` is a local vault table; `questions_membership(vault)` picks the one with purpose `questions`. `RelayLink { url, team_id, device_id, extra }` in `vaults.json` is the sync link. Both keep unknown fields. | `src/vault/trusted_device.rs:1-40`, `src/relay/membership.rs:1-40`, `src/vaults.rs:141-170` |
| Questions worker | The poster, reader, and lister use `QuestionsClient` over `RelayMember` over `relay_http`; they never name an origin themselves. The local-network companion runs beside them. | `src/questions/worker.rs:1-60`, `src/questions/client.rs:1-30`, `src/sync/relay/member.rs:1-60` |
| Connect today | "Get approvals on your iPhone" → `questions_add_iphone` → `team_sheet` → `prepare_connect` / `create_connect` (`POST /v1/connect` on the hosted relay), then `SyncSheet::AddIphone` with the QR of `LinkCode.link` plus the ADR 0032 handoff. | `src/desktop/ui/sync/questions.rs:1039-1080, :702-719`, `src/desktop/ui/sync/relay.rs:900-925, :3292`, `src/relay/connect.rs:53-85` |
| Settings → Devices | `devices_section` = This Mac (notifications), the companion group (`companion::draw`), Other Macs, and the relay group with "Get approvals on your iPhone" / "Add an iPhone or a Mac…" and the relay devices with "Remove…". | `src/desktop/ui/settings.rs:272-285, :480-540`, `src/desktop/ui/companion.rs:29-35` |
| Companion listener | rustls `ServerConfig`, TLS 1.3 only, `http/1.1` ALPN, no tickets, an rcgen certificate in the vault (schema 15); pin = `b64u(SHA-256(DER))`; binds `0.0.0.0` on IPv4; closes connections from the Mac's own addresses; `Connections` and `RateLimiter` limits; a strict HTTP/1.1 reader (8 KiB head, 16 KiB body). Starts on unlock, stops on lock and quit. | `src/companion/server.rs:1-60, :221-243`, `crypto.rs:211`, `limits.rs:39-230`, `http.rs:1-30`, `src/vault/companion.rs:40-60`, `src/desktop/companion.rs:1-30` |
| Companion size | Rust: `src/companion/` 6,900 lines, `src/desktop/companion.rs` 494, `src/desktop/ui/companion.rs` 385, `src/vault/companion.rs` 438. Swift: `ApassyCompanionKit` about 2,400 lines (18 files), `SessionModel` 353, `PairingModel` 302, `MacConnection`, the pairing and Main views, `RootModel` holds `companion`, `VaultTabView` polls it, `JoinModel` falls back to a companion code. `ApassyVaultKit` depends on the Kit (`PinnedTLS`, `Encoding`, `FaceIDWindow`). The iOS Info.plist has `NSLocalNetworkUsageDescription`. | `wc -l`; `ios/ApassyCompanion/Sources/Models/RootModel.swift:6-143`, `ios/ApassyVaultKit/Package.swift:23-25`, `ios/ApassyCompanion/project.yml:116` |
| iPhone pinning | `PinnedTLS.pinText` = `b64u(SHA-256(DER))`, the Mac's format; `PinnedTLSDelegate` refuses everything but the pinned leaf. The watch's `URLSessionCoreTransport` uses system trust, TLS 1.2 minimum. | `ios/ApassyCompanionKit/Sources/ApassyCompanionKit/PinnedTLS.swift:1-80`, `ios/ApassyVaultKit/Sources/ApassyVaultCore/URLSessionCoreTransport.swift:1-60` |
| iPhone core | `VaultEntry { id, name, sync_source, relay_url, team_id, device_id, added_at }` in `phone.json` (version 1); a join builds `RelaySync::new(RelayConfig::in_data_dir(…, relay_url, …))`; the questions context builds `RelayMember::new(relay_url, team_id, device_id, key)`. Push: `push_token_set` / `push_token_clear`, `PUT /v1/push/token`, 409 `push_unavailable` is a known error. | `ios/ApassyCore/src/core/config.rs:14-30`, `join.rs:271-313`, `questions.rs:1003-1022, :758, :1268-1287` |
| iPhone app | `DevicesSettingsView` shows `QuestionsStateRow` ("Questions through the relay"), `MacPairingRow` ("Mac on Wi-Fi"), Add Apple Watch. `JoinModel.handleCode` takes a scanned or pasted link. `PushRegistrar` gives the APNs token to `QuestionsModel.receivePushToken`. | `ios/ApassyCompanion/Sources/Views/Settings/DevicesSettingsView.swift:1-75`, `Vault/JoinModel.swift:87-130`, `PushRegistrar.swift:1-30` |
| Push today | The relay's push thread posts batches of tokens to the Worker's `/internal/push` with `X-Apassy-Push`; `PushConfig { url, topic, secret }`; the Worker (`apns.ts`) holds the APNs key and sends the fixed notification with collapse id `apassy-question`. Team table `push_token(device_id PK, token, environment, bundle_id, updated_at, failed_at)`. | `crates/apassy-relay/src/server/push.rs:1-60`, `src/config.rs:313-335`, `docs/SPEC.md` §25.6, §25.2; `crates/apassy-relay/deploy/worker/src/{index.ts,apns.ts,limits.ts}` |
| Relay directory | `relay.db` version 1003: `team`, `team_code(code_hash, created_at, expires_at, used_at, team_id)`, `audit`, `connect_key`. The Bouncer plan takes 1004 (OAuth tables). Team schema 7; the migration pattern writes `<team>.db.pre-v<N>`. | `crates/apassy-relay/src/server/directory.rs:24-60`, `store.rs:31, :518-520` |
| Team CLI | `apassy-team` is `apassy_relay::cli::main(args)`: `init`, `create`, `join`, `me`, `invite(s)`, `member(s)`, `device`, `team`, `collection`, `item`, `grant`, `agent`, `run`, `mcp`, `host` (with `host install|uninstall|status` through `cli/service.rs`: a launchd plist or a systemd user unit, `WantedBy=default.target`). Settings in `~/.config/apassy-team/settings.json`, keys in `keys.json`. The client is `ureq` with webpki roots: no pin. | `crates/apassy-relay/src/cli/args.rs:455-670`, `service.rs:111-136`, `settings.rs:1-40`, `keystore.rs:1-30`, `client.rs:200` |
| Binaries | The root `apassy` bin needs `desktop`; `crates/apassy-app` builds `apassy-app` (desktop + vault + the relay) and ships as `Contents/MacOS/apassy`. `pub mod cli` (the owner command line) is behind `desktop`; `node`, `sync`, `questions`, `relay`, `companion` are behind `vault`. `apassy status` and `apassy doctor` exist as owner commands. | `Cargo.toml:79-82`, `crates/apassy-app/Cargo.toml`, `src/lib.rs:9-58`, `src/cli/mod.rs:183, :201`, `src/cli/doctor.rs:1-20` |
| Paths | Linux data directory is `$XDG_DATA_HOME/apassy` or `~/.local/share/apassy`. | `src/paths.rs:1-36` |
| Linux CI | `relay-image.yml` builds the image and `apassy-team` for linux-x86_64 (rust 1.97 bullseye, glibc ≤ 2.31 checked) and darwin-arm64 on the `image-*` tag, with `SHA256SUMS-*` and `release-*.json`. No aarch64 Linux, no `.deb`, no attestation. `check-release-versions.py` requires the relay crate to build `apassy-relay` and `apassy-team`. The Worker serves `/dl/`, `/install.sh`, `/guide`. | `.github/workflows/relay-image.yml`, `scripts/check-release-versions.py:62-82`, `crates/apassy-relay/deploy/worker/src/index.ts:230-241`, `public/install.sh` |
| Tests | `tests/common/fake_relay.rs` is an in-process fake relay (sync, questions, feed) for the app's tests; `crates/apassy-app/tests/` exists for cross-crate E2E; the relay has `tests/embedded.rs`. | `tests/common/fake_relay.rs:1-30`, `crates/apassy-app/`, `crates/apassy-relay/tests/` |

## Decisions

### D1. One node origin per Mac, and a set of accepted sign-in origins (chosen by this plan; the owner can change it)

- The **node origin** is `https://<Tailscale IPv4>:8444` (for example `https://100.64.0.7:8444`). It is the string that every device stores as `relay_url`, signs at sign-in, and shows. The Tailscale IPv4 of a node is stable for the life of the node in the tailnet; MagicDNS may be off, so the name is not the origin. The MagicDNS name and the Tailscale IPv6 are **alternative destinations** (`alt`), tried in order after the origin's host, with the same origin string.
- Port 8444: a fixed port next to Funnel's 8443 (ADR 0037 cloud slice, decision 2: never 443, which serves T3 Code through Tailscale Serve on the owner's Mac). It is a node setting that the owner can change before the first pairing; after that a change needs new pairings, and Settings says so.
- The relay accepts a **set** of sign-in origins (`RelayConfig.sign_in_origins`, embedded and Linux only): the node origin and, on a Mac with the public route on, the Funnel `public_url`. The hosted relay keeps exactly one. The message form of ADR 0019 §5 does not change.
- The Mac's own clients (the questions worker, the feed publisher, the access worker, the Mac feed reader) reach the node over the loopback without TLS: `relay_http` gets a process-wide **local route table** (`set_local_route(origin, SocketAddr)`, cleared at `clear_local_route`), set by the node on start. A request to an origin with a local route connects plain to that loopback address and still signs the node origin. So `src/questions/worker.rs` (owned by U2c) does not change, and the loopback port can stay `127.0.0.1:0`.

### D2. The TLS front (ADR 0037 D4, 2B)

- A new module `src/net/` in the core: `tls_front.rs` (accept loop, rustls server, byte pump to the loopback target, limits), `tailnet.rs` (addresses and ranges), `pin.rs` (the pin helpers that the companion has today). The companion's `tls_config`, `Connections`, `RateLimiter`, and `certificate_pin` move there and the companion uses the moved code: the companion keeps working until its removal.
- Binds only the tailnet addresses of this machine: IPv4 in `100.64.0.0/10` and IPv6 in `fd7a:115c:a1e0::/48`, found from the interfaces and checked against `tailscale status --json`. Never `0.0.0.0` or `::`. Rebinds within 10 s when Tailscale goes up or down or the address changes.
- Refuses a peer outside those ranges before the TLS handshake. Limits: 64 connections in total, 8 per peer address, 60 new connections per peer per minute, a 15 s handshake deadline, a 120 s idle deadline on the pump (long polls of 25 s pass through), at most 4 MiB per direction per connection (a snapshot upload uses the relay sync route and is larger: the pump has no body cap, only the idle deadline; the relay has the size limits).
- The front does **not** parse HTTP. It forwards bytes to the relay's **tailnet-scope listener** (D3). So the HTTP parser that is exposed is the relay's vendored `tiny_http`, as on the hosted relay behind Cloudflare, with the relay's own request limits.
- The node certificate: rcgen, P-256, self-signed, 10 years, subject `Apassy node <machine name>`, made at the first start. The DER is in `node/front/cert.der`; the PKCS#8 key is sealed with AES-256-GCM under a key derived from the node master key (HKDF-SHA256, info `apassy-node-front-v1`) in `node/front/key.sealed` (0600). The pin is `b64u(SHA-256(DER))`, the companion's format, so `PinnedTLS.swift` and the Rust check agree. TLS 1.3 only, no tickets, no early data, ALPN `http/1.1`. The verifier on the client ignores names and dates.
- Tailscale identity is never authorization (ADR 0037 §3). A WhoIs check through the Tailscale LocalAPI is a later addition, not in this plan.

### D3. Relay listener scopes (chosen by this plan; the owner can change it)

`Scope` gains `Tailnet { agents: bool }`: a third loopback listener that the front forwards to. It serves the device routes (`/v1/auth/*`, `/v1/devices*`, `/v1/join`, `/v1/joins*`, `/v1/invites`, `/v1/teams`, `/v1/me`, `/v1/leave`, `/v1/members*`, `/v1/sync/*`, `/v1/questions*`, `/v1/push/*`, `/v1/feed*`, `/healthz`). With `agents: true` (the Linux node) it also serves the team routes (`/v1/collections*`, `/v1/items*`, `/v1/grants*`, `/v1/agents*`, `/v1/policies*`, `/v1/runs*`, `/v1/access`, the host lane, `/mcp`, `/p/`). Never the operator routes, `/v1/connect`, or the OAuth endpoints. Everything else is 404. The Mac node uses `agents: false`; `/mcp` for other-machine agents is stage 5.

### D4. Pairing links (`node-pairing-v1`, chosen by this plan; the owner can change it)

- A device link keeps the form `<origin>/link#<fragment>`. The fragment is `<code>(&<key>=<value>)*` with the keys `pin` (the node pin, b64u, 43 characters), `alt` (comma-separated alternative hosts, each `host[:port]`, at most 4), `name` (the node's display name, percent-encoded, at most 40 characters), and `handoff` (ADR 0032, unchanged bytes). Unknown keys refuse the link. The fragment never reaches a server. A link without `pin` is a hosted-relay link and keeps today's system trust.
- A **node pairing code** for a new team on a node (the Linux node, D8) is `<origin>/pair#<team code>&pin=…&alt=…&name=…`: the team code is a one-use `team_code` of kind `node`, valid 10 minutes, made by `apassy pair` in the node's directory. The Mac uses it with the existing `POST /v1/teams` flow (relay-sync-v1 §6), so the relay gets no new creation endpoint. A personal Mac node needs no code: the Mac creates its teams in-process.
- The Mac's own device link text uses the **node origin** (not the loopback destination): `LinkCode::link` gains an "advertised origin" parameter.

### D5. Pinned trust in the clients (2C)

- `TlsClient::pinned(pin)`: a custom `ServerCertVerifier` that compares SHA-256 of the leaf DER with the pin in constant time and accepts nothing else; TLS 1.3 only. `TlsTrust::{System, Pinned(Pin)}` on `RelayUrl` and `RelayConfig`. A pinned origin refuses a certificate that does not match, a chain, and any downgrade to system trust; system mode is unchanged. The same Rust code runs on the Mac and on the iPhone (`ios/ApassyCore` uses `apassy::sync`).
- Where the pin and the alternatives live: `RelayLink { pin, alt }` in `vaults.json` (serde defaults; the `extra` map already tolerates them); `relay_membership.pin TEXT NULL`, `relay_membership.alt TEXT NULL` (JSON list) in the vault, **schema 28**, local table, no sync change; `VaultEntry { pin, alt }` in the iPhone's `phone.json` (list version stays 1, defaults). `RelayMember::new` and `RelayConfig::in_data_dir` take a `TlsTrust`.
- The watch (ADR 0039 §5) reaches the relay through `URLSessionCoreTransport`; a request to a pinned origin carries the pin, and the transport uses `PinnedTLSDelegate` for it. Without this the watch cannot read access requests of a node team; the plan includes it in N6 and marks the physical check as pending.

### D6. The questions team of a vault on the Mac's node (2E)

- A vault's questions team moves to the Mac's node when Tailscale is on this Mac; otherwise "Get approvals on your iPhone" keeps the hosted Connect path (D14 of ADR 0037, until stage 7).
- `RunningNode::create_device_team(name, device_name, public_key) -> (NodeTeamId, device_id)`: the ADR 0019 bootstrap of `POST /v1/teams` in-process, no code, the Mac's key as the first device and key holder. The vault then gets a `RelayMembership { relay_url: <node origin>, purposes: [questions] }` through the existing `adopt_questions_team` path, and the questions worker runs unchanged (D1).
- The personal cloud-agent team of U2 stays a separate team; the questions team is a second team in the same node (one node hosts several teams; ADR 0037 §2).
- **Move approvals to this Mac** (ADR 0037, Migration): a sheet that (1) creates the node questions team, (2) shows the node pairing QR for the iPhone (a new device key and a new confirmation are unavoidable: identity is per team, ADR 0019 §4), (3) after the iPhone's confirmed join deletes the hosted membership (`disable_questions` and `DELETE /v1/devices/{id}` on the hosted relay, best effort). The feed and the access requests follow the questions team, as today.
- The node runs while a vault is unlocked and the tailnet route is on; it stops on lock and on quit (U2's `sync_node`, `end_waiting_runs`, `on_exit`). A locked vault means no questions, so no listener (ADR 0037 stage 2 acceptance: "a vault lock stops the listener").

### D7. Push gateway with per-device handles (ADR 0037 §7, D7; `push-gateway-v1`)

- `apassy-push` is a Cloudflare Worker in `crates/apassy-relay/deploy/push-gateway/` that imports `../worker/src/apns.ts`. The Apassy project runs one at `https://push.apassy.wyderka.cc` (owner-needed: the route and the secrets). Self-hosters deploy the same source with their own bundle id and APNs key. The Worker stores nothing and logs nothing.
- The iPhone: `POST /v1/handles {v:1, token, environment, bundle_id}` → `{handle, secret, expires_at}`. `handle` = b64u of a 12-byte nonce and `AES-256-GCM(gateway key, {token, environment, bundle_id, secret, issued_at, expires_at})`; `secret` is 32 random bytes, returned once, also inside the sealed handle. Handles last 180 days; the iPhone renews at launch as it renews tokens today.
- The iPhone gives the node the handle, never the token: `PUT /v1/push/handle {v:1, gateway, handle, secret}` and `DELETE /v1/push/handle` (relay team schema 8: table `push_handle(device_id PK, gateway, handle, secret, updated_at, failed_at)`; `push_token` and `PUT /v1/push/token` stay for the hosted relay). The node's push thread, in `PushMode::Gateway`, sends one `POST <gateway>/v1/push {v:1, handle, at, expires_at, collapse_id, proof}` per handle, where `proof = b64u(HMAC-SHA256(secret, "apassy-push-v1\0" || handle || "\0" || at || "\0" || expires_at || "\0" || collapse_id))` and `at` is within 5 minutes of the gateway's clock. The gateway opens the handle, checks the proof, and sends today's fixed notification. A forged, altered, or expired handle is 403; a wrong proof is 403; APNs 410 → `{status: 410, reason: "Unregistered"}` and the node sets `failed_at`.
- Limits at the gateway: 60 pushes per handle per hour, 600 per node address per hour, 30 handle creations per address per hour, through the Worker's rate-limiting bindings keyed by SHA-256 of the handle or the address. What the gateway sees: push handles (so tokens, inside its own key), node addresses, times (ADR 0037, "Who sees what").
- The gateway URL is a node setting with the default above; `status` and `doctor` show it.

### D8. The Linux node (stage 3)

- **Binary.** `crates/apassy-app` gets the features `window` (default; `apassy/desktop`, eframe) and `node` (always on). The Linux package builds `apassy-app` with `--no-default-features --features node` and installs it as `apassy`. The macOS bundle is unchanged. The node commands live in the relay crate (`crates/apassy-relay/src/node/`), because the server, the admin functions, the team CLI, and the service writer are there; the app binary dispatches `serve`, `up`, `pair`, `team`, and on Linux also `status` and `doctor`, to `apassy_relay::node::main`. On macOS, `apassy status` and `apassy doctor` stay the owner commands and get a "Node" section through the owner socket (U2b owns `src/cli/**`; the section lands after U2b).
- **`apassy serve`**: the node without a window: the relay with a headless embedded config (data `<data_dir>/node`, master key from `$CREDENTIALS_DIRECTORY/apassy-node-key` when systemd gives one, else `node/master.key` 0600; `team_vaults` on; `Scope::Tailnet { agents: true }`), the TLS front on the tailnet addresses (port 8444), `sign_in_origins = [node origin]`, no Funnel, no public listener, push in gateway mode. It is a sync home, a questions relay, and a team host for `apassy team …` (today's `apassy-team` hosts). It needs no vault and no unlock (the old plan's 3C): item keys of a team stay in `keys.json` of `apassy team host` as today; a team host with vault item keys is stage 4.
- **`apassy up`**: checks Tailscale (not installed → the install line; `NeedsLogin` → `sudo tailscale up`), makes the data directory 0700 and the master key (`systemd-creds encrypt` when available, TPM2-backed when the machine has one, else the file), writes and starts the systemd user unit (`ExecStart=<exe> serve`, `Restart=on-failure`, `WantedBy=default.target`), waits for `/healthz` on the loopback, prints `status`, then `pair`. It prints the `loginctl enable-linger $USER` hint when linger is off.
- **`apassy pair [--minutes 10] [--json]`**: makes a node pairing code (D4) and prints the link as text and as a QR code in the terminal (`qrcode` 0.14.1 without features, the core's pin, added to the relay crate).
- **`apassy status [--json]`**: the service state, the routes (tailnet address and port, Funnel n/a, LAN off), the pin, teams and devices with their last contact (through the in-process admin functions, read-only), the push gateway, the key source.
- **`apassy doctor [--json]`**: Tailscale installed, running, and with an address; 8444 free or ours; the data directory 0700; the key source; the unit installed, enabled, active; linger; clock skew against the gateway's `Date` header; a leftover `apassy-team` host service (offers `apassy team host install`).
- **`apassy team …`** = `apassy-team` with the first word removed; the settings directory stays `~/.config/apassy-team` for one release, then `apassy`. The `apassy-team` binary stays one release as an alias that prints one deprecation line (3F).
- **Packages**: `apassy-<version>-linux-x86_64.tar.gz` and `-aarch64.tar.gz` (the binary, a `apassy-team` shim script, `LICENSE`, `NOTICE`, `README.md`, the unit template), `apassy_<version>_amd64.deb` and `_arm64.deb` built with `dpkg-deb` (no new tool), `SHA256SUMS`, GitHub build attestations (`actions/attest-build-provenance`), built on `ubuntu-24.04` (x86_64, in the bullseye container for glibc 2.31) and `ubuntu-24.04-arm` (aarch64). The Worker's `install.sh` installs `apassy` and keeps the `apassy-team` shim. The `linux-cli` component of `release-versions.json` is this package from now on.

### D9. Settings → Devices (2H) and the Wi-Fi companion (D6, ADR 0028 stage 3)

- Mockup first (`docs/design/devices-settings-mockup.html`), approved by the owner before UI code; every view next to the mockup before a release claim (owner rule). Content: a **Node** group (Tailscale state and address, the route switch "Reachable on your tailnet" behind an owner check, the port, the pin as six safety-style words for a visual check, warnings), the device list (each device: name, kind, role, route "via your Mac" / "via Apassy relay" / "Wi-Fi", last contact, **Revoke…** behind an owner check), **Add an iPhone or a Mac…** (through the node when Tailscale is on, else hosted Connect), **Move approvals to this Mac** when a hosted questions membership exists, and the Wi-Fi companion group in its notice state.
- **Release R1 (this plan)**: no "Pair an iPhone" on Wi-Fi; a Mac with paired companion devices shows once: "The iPhone app now reaches this Mac through your tailnet. Wi-Fi pairing ends in two versions." The listener still runs for these Macs. **R2**: the notice says "in the next version". **R3**: removal (unit W2). ADR 0028 D3 chose N and N+1; ADR 0037 D6 asks for two releases of notice; this plan follows D6 (chosen by this plan; the owner can change it).

### D10. Security review (2J)

A judge panel (2× opus + 1× fable, read-only) on N1, N2, N3, N4, N5 before the release: the front (bind set, peer refusal, limits, the pump's deadlines, the sealed key), the tailnet scope (route allow-list, 404 for the rest, no trusted header), the sign-in origin set, the pin verifier (no fallback, constant time, TLS 1.3 only), the pairing fragment parser (strictness, the handoff stays), the gateway (handle sealing, proof, limits, no storage), what the node directory and the logs hold, and lock behaviour (listener down, tokens gone). Findings go back to the unit's implementer; the trust model gets the result.

## Work units

Sizes: S is days, M is one to two weeks, L is three weeks or more. "Core units" are U1b, U2b, U2c, U3a of the Bouncer plan. Every unit is a draft PR, marked ready when complete, merged after the ready run is green (macOS groups included). Every acceptance test is written by the unit's worker and runs in CI.

### N0 — Contracts and numbers (S)

- **Owns:** `docs/contracts/node-pairing-v1.md` (new), `docs/contracts/push-gateway-v1.md` (new), one "Origins" note in `relay-questions-v1.md` §10.1, `relay-feed-v1.md`, `relay-access-request-v1.md` §1, `relay-sync-v1.md` §3 (one paragraph each: the origin is a value; a node origin is pinned), `tests/contracts.rs` fixtures for both contracts, `docs/security/trust-model.md` rows for the node origin, the front, and the gateway.
- **Interface:** the fragment grammar of D4, the handle and proof forms of D7, the port and the origin form of D1, test vectors (a link with every key, a handoff after a pin, a sealed handle with a known key, a proof).
- **Acceptance tests:** `contracts::node_pairing_v1_fixtures_match_the_contract`, `contracts::push_gateway_v1_fixtures_match_the_contract` (strict parsing, unknown field refused, the vectors reproduce).
- **Depends on:** nothing. Starts first; N3, N5, N6 code against it.

### N1 — Relay: tailnet scope, sign-in origins, device-team bootstrap, push handles, team schema 8, directory 1005 (L)

- **Owns:** `crates/apassy-relay/src/{config.rs, embedded.rs}`, `src/server/{mod.rs, http.rs, devices.rs, push.rs, store.rs, directory.rs, admin.rs}`, `src/node/backend.rs` (the trait additions only), `crates/apassy-relay/tests/{tailnet_scope.rs, push_handles.rs, node_teams.rs}` (new), relay `docs/SPEC.md` (§6, §25, §30, a new §31 "Tailnet scope and node pairing codes"), `docs/OPERATIONS.md` (schema 8 and 1005 rollbacks). Bases on U1b's head: U1b owns `config.rs`, `http.rs`, `directory.rs`, `embedded.rs`, `backend.rs` until it merges.
- **Interface:**
  - `RelayConfig { tailnet_listen: Option<SocketAddr>, tailnet_agents: bool, sign_in_origins: Vec<String>, push: Option<PushConfig> }` with `PushConfig::Gateway { url, timeout, backoff_unit }` beside today's `PushConfig::Worker {…}` (an enum; `from_env` keeps the Worker form only). `EmbeddedOptions` gains `node_origin: String`, `tailnet_listen`, `tailnet_agents`, `push_gateway: Option<String>`. `check_listeners` covers the third listener.
  - `Scope::Tailnet { agents: bool }` routing per D3.
  - `devices::token` verifies against each origin of `sign_in_origins` (the hosted relay: `[public_url]`).
  - `RunningNode::create_device_team(name, device_name, public_key_b64u) -> Result<(NodeTeamId, u64), NodeError>`, `RunningNode::tailnet_addr() -> Option<SocketAddr>`, `RunningNode::devices(team) -> Vec<NodeDevice { id, name, kind, last_seen_at, key_holder }>`, `RunningNode::revoke_device(team, id)`, `RunningNode::make_node_code(minutes) -> NodeSecret` (a `team_code` of kind `node`), `NodeConfig { node_origin, tailnet_listen, tailnet_agents, push_gateway }`.
  - Team schema 8: `push_handle(device_id INTEGER PRIMARY KEY REFERENCES device(id), gateway TEXT NOT NULL, handle BLOB NOT NULL, secret BLOB NOT NULL, updated_at INTEGER NOT NULL, failed_at INTEGER)`; `PUT /v1/push/handle`, `DELETE /v1/push/handle` (device auth, 409 `push_unavailable` on a relay without a gateway); revoking a device deletes its row. Rows `push_handle_set {device_id}`, `push_handle_removed {device_id}`. Down-migration `apassy-relay downgrade-schema-7` as for 7.
  - Directory 1005: `team_code.kind TEXT NOT NULL DEFAULT 'operator' CHECK (kind IN ('operator','node'))`; `POST /v1/teams` with a `node` code works only on a node (`tailnet_listen` set) and marks it used; rollback note.
  - `push.rs`: `Gateway` mode posts one request per handle with the proof of D7; `failed_at` on 410 or `Unregistered`; the same queue, budget, and throttles.
- **Acceptance tests:** the existing suite passes in `Required` mode; a `Tailnet` listener serves `/v1/me` and `/v1/questions` and answers 404 to `/mcp`, `/p/`, `/v1/connect`, the OAuth paths, and the operator routes, and with `agents: true` serves `/mcp`, `/v1/runs`, the host lane; a sign-in signed with the second origin passes and one signed with an unknown origin fails; the hosted config accepts exactly `public_url`; `create_device_team` makes an owner device that signs in and makes links; a `node` code creates a team once and is refused the second time and after 10 minutes; schema 7 → 8 and back; `PUT /v1/push/handle` upserts and a revoked device loses it; the push thread in gateway mode posts the proof of the contract's vector to a fake gateway, marks 410, and never posts a token; directory 1004 → 1005 and back.
- **Size:** L. **Depends on:** U1b (file ownership), N0 (vectors).

### N2 — TLS front and tailnet addresses (M)

- **Owns:** `src/net/{mod.rs, tls_front.rs, tailnet.rs, pin.rs, sealed_key.rs}` (new), `src/companion/{server.rs, crypto.rs, limits.rs, hosts.rs}` for the extraction only (the companion calls the moved code; its behaviour does not change), `fuzz/` target `tls_front_pump` (cargo-fuzz; the top-level agent runs it), `tests/tls_front.rs` (new).
- **Interface:** `tailnet::addresses(status: &Tailscale, interfaces) -> Vec<IpAddr>` (only the two ranges); `tailnet::is_tailnet_peer(IpAddr) -> bool`; `pin::certificate_pin(der) -> String`, `pin::parse(text) -> Option<Pin>`; `sealed_key::{seal, open}` (AES-256-GCM with ring under HKDF of the master key); `tls_front::Front::start(FrontOptions { addresses, port, certificate, target: SocketAddr, limits: FrontLimits }) -> FrontHandle { bound: Vec<SocketAddr>, pin, stop(), rebind(addresses), open_connections() }`; `FrontLimits` defaults of D2; `NodeCertificate::load_or_make(dir, master_key) -> (der, pin, key)`.
- **Acceptance tests:** a bind to `0.0.0.0`, `::`, or a non-tailnet address is refused; a peer from `192.168.1.5` is closed before the handshake and `100.64.0.9` is accepted (with the `allow_test_peers` hook that the companion has for tests, loopback stands in for a tailnet peer); the pump passes a 25 s long poll through and ends an idle connection at 120 s; the per-peer and total limits hold; `rebind` moves the listener; the sealed key opens only with the right master key; the pin equals `PinnedTLS.pinText` for the fixture DER (`ios/ApassyCompanionKit` test); the companion's existing tests pass after the extraction; the fuzz target runs 5 minutes with no finding (the top-level agent, through `heavy-check`).
- **Size:** M. **Depends on:** nothing. Starts with N0 and N1.

### N3 — Pinned trust and node links in the clients (M)

- **Owns:** `src/broker/http.rs` (`TlsClient::pinned`, the verifier), `src/sync/relay_http.rs` (`TlsTrust`, `RelayUrl::with_trust`, alternative destinations, the local route table of D1), `src/sync/relay.rs` and `src/sync/relay/{devices.rs, member.rs}` (the advertised origin in `LinkCode::link`, `PendingJoin::parse_link` with the fragment grammar, `RelayMember::new` with trust), `src/relay/pairing.rs` (the handoff after a pinned fragment: the AAD keeps "the original full link without handoff"), `src/vaults.rs` (`RelayLink { pin, alt }`), `src/vault/{schema28.rs (new), trusted_device.rs, mod.rs}` (schema 28: `relay_membership.pin`, `relay_membership.alt`; `SCHEMA_VERSION = 28` after U3a's 27), `ios/ApassyCore/src/core/{config.rs, join.rs, mod.rs, sync.rs}` (`VaultEntry { pin, alt }`, the join with a pinned link, `RelayMember` with trust; `questions.rs` only in the `member_of` function, agreed with U2c), `tests/vault_migration.rs`, `tests/relay_sync.rs`, `ios/ApassyCore` tests.
- **Interface:** `TlsTrust::{System, Pinned(Pin)}`; `TlsClient::pinned(&Pin)`; `RelayUrl::parse_with_trust(text, trust)`, `RelayUrl::alternatives(&[String])`; `relay_http::{set_local_route, clear_local_route}`; `LinkCode::for_origin(advertised: &str)`; `PairedLink { origin, code, pin: Option<Pin>, alt, name, handoff }` from `parse_link`; `RelayMembership { pin: Option<String>, alt: Vec<String> }`; `Vault::set_membership_trust(team, pin, alt)`; iPhone core `join_start` accepts a pinned link and stores the pin in the entry and the membership.
- **Acceptance tests (unit and integration, with `tests/common/fake_relay.rs` behind a local TLS listener):** a pinned client refuses a certificate with another pin, a chain that ends in the pinned leaf but presents another leaf, and a system-trusted certificate; a system client is unchanged; the second destination is tried when the first refuses the connection and the signed origin stays the first one; a local route connects plain to the loopback and signs the node origin; `parse_link` accepts the contract's vectors and refuses an unknown key, a second `pin`, and `pin` after `handoff`; the handoff AAD equals the pre-pin AAD for a link without a pin (ADR 0032 vectors unchanged); schema 27 ↔ 28; `vaults.json` with `pin` and `alt` round-trips and an old list without them loads; the iPhone core joins a fake pinned node and its entry has the pin.
- **Size:** M. **Depends on:** N0; U3a for the schema number order (28 after 27).

### N4 — The node over the tailnet on the Mac: questions team, pairing, lifecycle, move (L)

- **Owns:** `src/node/{mod.rs, tailnet.rs (new), questions_team.rs (new)}`, `src/desktop/node.rs`, `src/relay/membership.rs` (`adopt_node_team`), `src/desktop/ui/sync/{questions.rs, relay.rs}` (the sheets: the node path of "Get approvals on your iPhone", the pinned QR, "Move approvals to this Mac"), `src/vault/cloud.rs` (the node settings: `tailnet_on`, `tailnet_port`, `node_origin`, `push_gateway`; the `cloud_node` row grows in schema 28, coordinated with N3 which owns `schema28.rs`), `crates/apassy-app/tests/node_tailnet_e2e.rs` (new). Bases on U2b (owner of `src/node/{mod,host}.rs`, `src/desktop/node.rs`, `src/vault/cloud.rs`).
- **Interface:** `Node::start` also starts the front (N2) against `RunningNode::tailnet_addr()` when `tailnet_on`, sets the local route (D1), and passes `sign_in_origins`; `Node::status` adds `tailnet: TailnetStatus { on, origin, bound, pin, pin_words, devices: Vec<NodeDeviceView> }`; `Node::set_tailnet(on)` (owner check); `Node::ensure_questions_team(vault) -> RelayMembership` (D6); `Node::pairing_link(vault, handoff) -> LinkCode` with the node origin, `pin`, `alt`, `name`; `Node::revoke_device(team, id)`; `Node::move_approvals(vault) -> MoveState`. Lifecycle: the route is on while the vault is unlocked; lock, quit, and `end_waiting_runs` stop the front first, then the relay (every session and run key gone), then clear the local route.
- **Acceptance tests:** with a fake backend and a fake front: the questions team is made once and reused after a restart; the pairing link has the node origin, the pin, the alternatives, and the handoff; lock stops the front before the relay and clears the local route; the E2E in `crates/apassy-app/tests`: an embedded node with the real relay, the real front on a loopback "tailnet" address (the test hook), a Mac questions worker posting through the local route, and a simulated iPhone core (`ios/ApassyCore` as a dev-dependency, or the Rust client pieces) joining through the pinned link, reading the question, answering, and the Mac settling, with the question, answer, and settle digests unchanged (relay-questions-v1 §20 vectors); "Move approvals" ends with no hosted membership in the vault and a `DELETE` sent to the fake hosted relay.
- **Size:** L. **Depends on:** N1, N2, N3, U2b.

### N5 — Push gateway (M)

- **Owns:** `crates/apassy-relay/deploy/push-gateway/{wrangler.jsonc, package.json, src/index.ts, src/handles.ts, test/*.test.ts, README.md}` (new; imports `../worker/src/apns.ts`), `.github/workflows/ci.yml` (one vitest step for the gateway, next to the Worker's), `docs/operations/push-gateway.md` (new: deploy, secrets, self-hosting), the iPhone core push registration (`ios/ApassyCore/src/core/questions.rs`, the `push_token_set` path: with a node membership, register a handle at the gateway and `PUT /v1/push/handle`; with a hosted membership, `PUT /v1/push/token` as today; `questions-push.json` keeps the handle, never the token after the exchange), `ios/ApassyCompanion/Sources/PushRegistrar.swift` only if the token flow needs a change (expected: none).
- **Interface:** per D7 and `push-gateway-v1`: `POST /v1/handles`, `POST /v1/push`, `GET /healthz`; Worker secrets `GATEWAY_KEY` (32 bytes), `APNS_KEY`; vars `APNS_KEY_ID`, `APNS_TEAM_ID`, `APNS_TOPIC`; rate-limiting bindings `handles_per_address`, `pushes_per_handle`, `pushes_per_address`.
- **Acceptance tests (vitest):** a handle round-trips; a handle sealed under another key, a cut handle, and an expired handle are 403; a wrong proof and a stale `at` are 403; the fixed payload and the collapse id are exactly today's; APNs 410 maps to `{status: 410, reason: "Unregistered"}`; the limits trip; nothing is written to KV or logs (no binding exists). iPhone core: a node membership never sends `PUT /v1/push/token`; the handle file holds no token after the exchange.
- **Size:** M. **Depends on:** N0 (vectors), N1 (the relay endpoints, for the iPhone core path), U2c for `questions.rs` ownership order (N5 edits only the push functions; agreed in the PR).

### N6 — iPhone app (M)

- **Owns:** `ios/ApassyCompanion/Sources/Vault/{JoinModel.swift, VaultSettings.swift}`, `Views/Vault/JoinFlowView.swift`, `Views/Settings/DevicesSettingsView.swift`, `Models/QuestionsModel.swift` (the "Tailscale is off on this iPhone" state), `Views/Decisions/DecisionsView.swift` (one quiet footer line, never a card), `ios/ApassyVaultKit/Sources/ApassyVaultKit/{Models.swift, Questions.swift}`, `ios/ApassyVaultKit/Sources/ApassyVaultCore/URLSessionCoreTransport.swift` (the pin for the watch, D5), `ios/ApassyCompanion/ModelTests/**` for the above, `docs/contracts/ios-core-v1.md` §5.2 and §5.10 (the pinned join, the handle).
- **Interface:** `JoinModel.handleCode` accepts a node link (the core parses it; the model shows "via your Mac" and the node name from `name`); Settings → Devices: "Questions" row shows "via your Mac (Tailscale)" or "via Apassy relay", the node name and the pin words, and the quiet line "Turn on Tailscale on this iPhone to reach <Mac>" when a node origin is unreachable; `MacPairingRow` stays until W2; the watch transport pins when the request says so.
- **Acceptance tests:** `JoinModelTests` with a node link (state and texts), `QuestionsModelTests` for the unreachable-node state (no card in Requests), `VaultSettingsTests` for the device rows, a `URLSessionCoreTransport` test that a pinned request refuses a system-trusted local server (macOS `swift test` with a local TLS listener), the Kit's `PinnedTLS` vector equals the Rust pin.
- **Size:** M. **Depends on:** N3, N5.

### N7 — Mac Settings → Devices and the Wi-Fi notice (M)

- **Owns:** `docs/design/devices-settings-mockup.html` (new, first), `src/desktop/ui/settings.rs` (the Devices section), `src/desktop/ui/devices.rs` (new: the Node group and the device list), `src/desktop/ui/companion.rs` (notice state, no "Pair an iPhone"), `src/desktop/ui/settings_tests.rs`, `src/desktop/ui/companion_tests.rs`, `src/desktop/owner_check.rs` only for the two new `OwnerRequest`s (`SetTailnetRoute`, `RevokeNodeDevice`; coordinated with U2b, which owns the file until it merges), `docs/operations/companion.md` (the notice), `docs/operations/node.md` (new: the Mac node, pairing, revoke, the port).
- **Acceptance tests:** the Devices section draws every state of the mockup with demo data (no Tailscale, Tailscale off, route off, route on with devices, a hosted membership with "Move approvals", the companion notice); the route switch and Revoke go through the owner check; "Pair an iPhone" is absent; the notice shows once and is dismissable; screenshots of each view next to the mockup before the release claim (owner rule).
- **Size:** M. **Depends on:** N4 (the `Node::status` shape); the mockup can start at once.

### N8 — Security review and trust model (S–M)

- **Owns:** `docs/security/trust-model.md`, `docs/reviews/node-tailnet-2026-11/` (new: the panel's report), fixes go back to the owning units.
- **Scope:** D10. **Acceptance:** no open high finding; each medium finding fixed or recorded with the owner's acceptance.
- **Size:** S–M. **Depends on:** N1, N2, N3, N4, N5.

### L1 — Linux node binary and commands (L)

- **Owns:** `crates/apassy-app/{Cargo.toml, src/main.rs}` (features `window` and `node`, the dispatch), `crates/apassy-relay/Cargo.toml` (`qrcode`), `crates/apassy-relay/src/node/{mod.rs, config.rs, serve.rs, up.rs, pair.rs, status.rs, doctor.rs, team.rs, qr.rs, keys.rs}` (new), `crates/apassy-relay/src/cli/{mod.rs, service.rs, settings.rs}` (the `team` prefix, the unit for `serve`, the settings directory), `crates/apassy-relay/src/bin/apassy-team.rs` (the alias with the deprecation line), `crates/apassy-relay/tests/node_cli.rs` (new), `docs/operations/linux-node.md` (new), `README.md` (Linux).
- **Interface:** D8. `apassy_relay::node::main(args) -> i32`; `NodeFiles { data_dir, key_source, front_dir }`; `HeadlessOptions { node_origin, tailnet_listen, push_gateway, port }`; `serve` runs until SIGTERM (the relay has no signal handling: `serve` installs one through `rustix`'s signal or a `ctrlc`-free approach with `signal_hook`-free code: a pipe on a thread with `rustix::io`; decide in L1, no new crate if possible) and stops the front first; `pair` output JSON `{link, expires_at, pin, origin}`; `status --json` and `doctor --json` shapes documented in `linux-node.md`.
- **Acceptance tests:** `apassy-app` builds with `--no-default-features --features node` on Linux in CI (no eframe in the lock's resolved set for that build: checked with `cargo tree -e features`); `serve` on a temporary directory with the test front hook starts, answers `/healthz` through the front with the pin, and stops on SIGTERM within 5 s; `pair` prints a link that `PendingJoin::parse_link` accepts; `status --json` and `doctor --json` match their documented shapes on a fixture; `apassy team me` equals `apassy-team me`; the alias prints the deprecation line to stderr and the same stdout.
- **Size:** L. **Depends on:** N1 (config and scope), N2 (the front is in the core; the relay crate depends on the core, so it can use `apassy::net`).

### L2 — Service and key on Linux (S)

- **Owns:** `crates/apassy-relay/src/node/{service.rs, keys.rs}`, `packaging/linux/apassy-node.service` (new template), `docs/operations/linux-node.md` (the service section).
- **Interface:** `up` writes `~/.config/systemd/user/apassy-node.service` (`ExecStart=<exe> serve`, `LoadCredentialEncrypted=apassy-node-key:%h/.local/share/apassy/node/master.key.cred` when `systemd-creds` exists, `Restart=on-failure`, `WantedBy=default.target`), `systemctl --user daemon-reload`, `enable --now`; the linger hint; `uninstall` reverses it.
- **Acceptance tests:** the generated unit parses (`systemd-analyze verify` in CI on ubuntu-24.04); with a fake `systemd-creds` the key file is encrypted and the plain file is absent; without it the plain file is 0600 and `status` says "file".
- **Size:** S. **Depends on:** L1.

### L3 — Packages and CI (M)

- **Owns:** `.github/workflows/relay-image.yml` (the `linux-cli` job becomes `linux-node` with a matrix x86_64 / aarch64, the `.tar.gz`, the `.deb`, `SHA256SUMS`, attestations; the image job stays), `packaging/linux/{deb/control.in, deb/postinst, tarball.sh, build.sh}` (new), `crates/apassy-relay/deploy/worker/public/install.sh` (installs `apassy`, keeps the `apassy-team` shim), `scripts/check-release-versions.py` (the `linux-cli` component now means the node package; it requires the `apassy-app` crate version and the relay version to match), `docs/operations/release.md` (the Linux section), `AGENTS.md` (one line: `linux-cli` is the Linux node).
- **Acceptance tests:** the workflow on a test tag produces both tarballs, both `.deb`s, `SHA256SUMS`, and `release-linux-*.json`; `dpkg-deb --info` and `--contents` match; `apassy --version` prints the shared version from the tarball and from the installed `.deb` in a Debian 12 container step; the glibc check holds for x86_64 (≤ 2.31) and is documented for aarch64 (ubuntu-24.04-arm, glibc 2.39: the plan accepts it and says so in the download note; a bullseye arm64 container is the follow-up); `check-release-versions.py` passes; `install.sh` installs from a `file://` directory in a CI step.
- **Size:** M. **Depends on:** L1.

### L4 — The Mac and the iPhone use a Linux node (S–M)

- **Owns:** `src/desktop/ui/sync/relay.rs` (the relay sheet accepts a node pairing link: origin, pin, alt, the `node` team code; "Your own node" wording), `src/relay/membership.rs` (`create_team_on_relay` with a pinned URL), `src/desktop/ui/sync_tests.rs`, `docs/operations/sync.md` (the node as the relay of a vault).
- **Acceptance tests:** pasting a node pairing link into the relay sheet creates the team on the fake pinned node and stores the pin in the sync link and the membership; an iPhone device link from that Mac carries the Linux node's origin and pin; a wrong pin refuses before any request.
- **Size:** S–M. **Depends on:** N3, L1.

### W1 — Wi-Fi companion notice (in N7, release R1) and W2 — removal (M, release R3)

- **W2 owns (later):** delete `src/companion/` (what N2 did not move), `src/desktop/companion.rs`, `src/desktop/ui/companion.rs`, `src/vault/companion.rs` and the `companion_*` tables (a vault schema migration of its release; the number is taken then), `docs/contracts/companion-v1.md` (marked removed), `docs/operations/companion.md`; iOS: `ios/ApassyCompanionKit` shrinks to the pieces `ApassyVaultKit` uses (`PinnedTLS`, `Encoding`, `FaceIDWindow*`, `Keychain`, `TextRules`; the companion client, keys, pairing store, wire models, and signing strings go), `SessionModel`, `MacConnection`, `PairingModel`, `Views/Pairing/*`, `Views/Main/{MacView, StatusCapsule, ForgetMacButton, InboxView, ApprovalsView, ActivityView, RunRow, RunDetailView}` where only the companion used them, the companion branch of `RootModel`, `VaultTabView.companionPolling`, `JoinModel.onCompanionCode`, the run and question de-duplication in `Decisions`, `NSLocalNetworkUsageDescription` and the local-network ATS entries in `project.yml` and `Info.plist`; `CHANGELOG` upgrade note.
- **Acceptance:** no `companion` symbol in the app and the Kit; the iPhone asks for no Local Network permission (a UI test checks the absence of the prompt key); the vault migration drops the tables and an older app refuses the copy as usual.
- **Depends on:** R1 and R2 shipped.

### R — Release (S)

- **Owns:** `release-versions.json`, the Cargo manifests and the lockfile, iOS `MARKETING_VERSION`, the extension manifest, the dated `CHANGELOG.md` section with the upgrade notes (vault 28, relay team 8, directory 1005, the node origin, the push gateway, the Wi-Fi notice), the relay deploy plan (the image tag, the compose diff on `ottervibe`: no change of behaviour for the hosted relay beyond schema 8 and 1005), the Worker deploy for `install.sh` and `/dl`, the gateway deploy.
- **Acceptance:** `python3.12 scripts/check-release-versions.py`; all six components live at one version; the physical acceptance below.

## One editor per shared file

| File or area | Editor | Until |
| --- | --- | --- |
| `crates/apassy-relay/src/{config.rs, embedded.rs, server/http.rs, server/directory.rs}`, `src/node/backend.rs` | U1b, then N1 | N1 merges |
| `crates/apassy-relay/src/server/{devices.rs, push.rs, store.rs, admin.rs}` | N1 | N1 merges |
| `crates/apassy-relay/src/node/**`, `src/cli/**`, `src/bin/apassy-team.rs` | L1 (L2 for `node/{service,keys}.rs`) | L3 |
| `src/net/**`, `src/companion/{server,crypto,limits,hosts}.rs` | N2 | W2 |
| `src/broker/http.rs`, `src/sync/**`, `src/relay/pairing.rs`, `src/vaults.rs`, `src/vault/schema28.rs` | N3 | N3 merges |
| `src/relay/membership.rs` | N3 (trust), then N4 (`adopt_node_team`), then L4 | serial |
| `src/node/{mod,host}.rs`, `src/desktop/node.rs`, `src/vault/cloud.rs`, `src/desktop/owner_check.rs` | U2b, then N4 (N7 adds two `OwnerRequest`s in N4's PR) | N4 merges |
| `src/questions/{envelope,worker}.rs`, `ios/ApassyCore/src/core/questions*.rs` | U2c; N3 and N5 edit only `member_of` and the push functions, in PRs that base on U2c's head | U2c merges |
| `src/questions/{feed,feed_reader}.rs`, `ios/ApassyCore/src/core/feed.rs`, `src/broker/run.rs`, `src/vault/schema27.rs` | U3a; this plan does not touch them | — |
| `src/desktop/ui/sync/{questions,relay}.rs` | N4, then L4 | serial |
| `src/desktop/ui/{settings,companion,devices}.rs` | N7 | N7 merges |
| `src/desktop/{mod,ui/shell,ui/sidebar}.rs` | U3b-1; this plan does not touch them | — |
| `ios/ApassyCompanion/Sources/**` (Swift) | N6 (the Swift questions view belongs to U2c) | N6 merges |
| `crates/apassy-relay/deploy/push-gateway/**`, `deploy/worker/public/install.sh` | N5; L3 for `install.sh` | — |
| `.github/workflows/relay-image.yml`, `packaging/linux/**`, `scripts/check-release-versions.py` | L3 | — |
| `docs/contracts/**` | N0, then the unit named in each contract | — |
| `docs/security/trust-model.md` | N0, then N8 | — |

## Order and parallelism

1. **Phase 1 (now):** N0, N2, and the N7 mockup; N1 starts on U1b's head. Three workers at most on this Mac; the relay crate's unit tests of N1 and N2 run on CI.
2. **Phase 2:** N3 (after N0), N5 (after N0; the Worker half needs no Rust), L1 (after N1 and N2).
3. **Phase 3:** N4 (after N1, N2, N3, U2b), N6 (after N3, N5), L2 and L3 (after L1).
4. **Phase 4:** N7 (after N4), L4 (after N3, L1), N8 (the panel), R.
5. Each unit codes against the types in this plan (`TlsTrust`, `PairedLink`, `FrontOptions`, `NodeDevice`, `TailnetStatus`, the contract vectors). A change to them goes through this file first.
6. Validation: CI after an authorized push; a local run only through `~/.local/bin/heavy-check`; workers return commands. The fuzz target and the screenshots are the top-level agent's.

## Release grouping

- **R1 — the next coordinated release after the Bouncer section (0.5.18 if the Bouncer section is 0.5.17; else 0.5.17):** N0, N1, N2, N3, N4, N5, N6, N7 (with W1), N8, L1, L2, L3, L4, R. The pieces interlock (a node without pinned clients is useless; a Linux node without the Mac's node link parser is unreachable), so they ship together. Hosted relay: schema 8 and directory 1005 only, no behaviour change. iPhone: node links, pinned trust, handles. Extension: version only. Website: changelog.
- **If the Bouncer release ships first and the owner wants something of this plan in it:** only W1 (the Wi-Fi notice, part of N7's companion group) and the N0 contracts are safe to include; nothing else, because N1 and N3 change the relay and the vault schema.
- **R2:** the notice changes to "in the next version". No other unit.
- **R3:** W2 (the companion removal, with its vault schema migration).

## Owner-needed steps

| Step | When | Why only the owner |
| --- | --- | --- |
| Approve the Devices mockup (`docs/design/devices-settings-mockup.html`) | Before N7 writes UI code | Owner rule: mockup first |
| Tailscale: the Mac mini, the MacBook, the iPhone, and one Linux test machine on the owner's tailnet; MagicDNS on (recommended, not required) | Before the N4 and L1 physical checks | The Tailscale account is the owner's |
| A Linux test machine on the tailnet: `devbox-arm` or `devbox-x86` joined with the "devbox tailscale auth key" (a paid Hetzner run: `devbox up arm` needs the owner's go) | L1 to L4 acceptance | Paid run; the devbox is on-demand |
| Push gateway: the Cloudflare route `push.apassy.wyderka.cc` (a DNS and account change) and the secrets `GATEWAY_KEY`, `APNS_KEY` piped through Apassy, `APNS_KEY_ID`, `APNS_TEAM_ID` as vars | Before N5's deploy | DNS and account settings; the APNs key is the owner's |
| Physical acceptance (below) | Before the release claim | Devices in the owner's hands |
| TestFlight upload and the group, the Chrome Web Store submission, the relay image on `ottervibe`, the GitHub release | R | Publication steps and the production VPS |
| `loginctl enable-linger` on the Linux node (needs sudo or a logind policy) | L2 acceptance | Root on the owner's machine |

**Physical acceptance (owner):**

1. Settings → Devices on the Mac mini: Tailscale found, route on (Touch ID), the port and the pin words shown. "Add an iPhone or a Mac…" shows the QR.
2. iPhone (Tailscale on, Wi-Fi off, cellular): scan; the safety words match on both; Touch ID confirms. Settings → Devices on the iPhone says "via your Mac (Tailscale)".
3. A run on the Mac that asks: the question appears on the iPhone within 5 s; Face ID; the Mac settles. A packet log of the iPhone's traffic (the Tailscale app's log or `tcpdump` on the Mac's utun) shows no request to `apassy-relay.wyderka.cc`.
4. A push arrives with the iPhone app closed (the gateway), with the fixed text.
5. Revoke the iPhone on the Mac: the next request from the iPhone is refused; pair again.
6. Lock the vault: `tailscale status` shows the front gone (`lsof -i :8444` empty); unlock: it returns. Quit: nothing listens.
7. Turn Tailscale off on the iPhone: Settings → Devices shows the quiet line; Requests shows no card.
8. The Wi-Fi companion group shows the notice; no "Pair an iPhone".
9. Linux: `curl -fsSL <relay>/install.sh | sh`, `apassy up`, `apassy pair`; the Mac's relay sheet takes the link ("Your own node"); the iPhone joins through the Mac's link; reboot the Linux machine; `apassy status` is green after the boot without a login (linger).
10. An access request (ADR 0033) through the node reaches the iPhone and, if the watch is paired, the watch (the pinned transport); record the result.

## Risks

| Risk | Mitigation |
| --- | --- |
| iOS asks for Local Network permission for `100.x` addresses from Rust sockets, or ATS blocks a raw socket | Check on the owner's iPhone in step 2; the addresses are on a `/32` of the Tailscale utun, which iOS does not treat as a local subnet; raw sockets are outside ATS. If the prompt appears, the plan keeps the existing usage description until W2 |
| The Mac App Store Tailscale variant and a socket bound to the Tailscale IPv4 | The companion already uses that address as a link host; N2's first task is a 30-minute check on the owner's Mac mini: bind `100.x:8444`, connect from the MacBook. If it fails, bind `::` with a peer filter is **not** the fallback (ADR 0037 §2); the fallback is `tailscale serve --bg --tcp 8444 tcp://127.0.0.1:<port>` with the pin kept end-to-end (Serve in TCP mode does not end TLS), recorded in the plan |
| A changed Tailscale IPv4 (the node is removed and re-added to the tailnet) changes the origin | `doctor` says so and offers "pair again"; the alternatives do not help because the origin is the signed value |
| Port 8444 is taken | `status` and `doctor` name the process; the port is a setting before the first pairing |
| Two new listeners on user machines (the front, the tailnet scope) | Loopback relay, tailnet-only bind and peers, limits, no HTTP parsing in the front, the relay's limits, fuzzing, the N8 panel |
| The push gateway is an Apassy-run service without accounts | Handles are sealed under the gateway key, proofs bind a secret the gateway never stores, per-handle and per-address limits; a self-hoster can run their own |
| Vault schema 28 right after 27 in one release, relay team 8 and directory 1005 right after 7 and 1004 | Down-migrations with tests; the installed app is swapped only from the release build; upgrade notes name every number |
| The questions worker is owned by U2c and the node work must not edit it | D1's local route table keeps `worker.rs` untouched; a conflict is a plan change here first |
| The `apassy` binary name on Linux is the node, on macOS the owner command line: `status` and `doctor` mean different things | `linux-node.md` says so; the Mac's `apassy doctor` gets a "Node" section so that the words match where they can |
| aarch64 Linux builds on `ubuntu-24.04-arm` need glibc 2.39 | Said in the download note; a bullseye arm64 container build is the follow-up |
| GitHub attestations and `.deb` building are new to this repository | L3 tests the workflow on a test tag before the release tag |
| The Wi-Fi companion stays two more releases with its listener | The listener runs only for Macs with paired devices and no new pairing; its code now shares the front's TLS and limits (N2) |

## Not verified in the code

- Whether binding a socket to the Tailscale IPv4 on macOS receives tailnet connections with the App Store Tailscale variant (N2's first check; the risk row above).
- Whether iOS shows a Local Network prompt for a Rust socket to a `100.x` address over the Tailscale VPN (physical step 2).
- Whether `URLSessionCoreTransport` on the watch can take a per-request trust delegate without a second session (N6; else one pinned session per origin).
- The exact `tailscale status --json` fields for the IPv6 address (`Self.TailscaleIPs` holds both; `funnel.rs` reads only `DNSName` and the state today).
- `team_code` of the directory has `expires_at` and `used_at` (`directory.rs:35-37`); whether `admin` has a function to add a code with a chosen expiry, or only `apassy-relay admin team-code` (N1 adds one if needed).
- Whether the vendored `tiny_http` accepts a third bound server in one `Relay` (the public listener pattern of U1 suggests yes).
- Whether `ubuntu-24.04-arm` runners are available to this repository's workflows (public repository: expected yes; else `cross` in the x86_64 job).
- Whether a Rate Limiting binding of Cloudflare Workers is available on the owner's plan for the gateway (else the gateway uses a Durable Object counter, which stores counts only, never handles).
- `signal` handling for `apassy serve` without a new crate (`rustix` has `rustix::process` signals on Linux; L1 decides).
