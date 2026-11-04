# Changelog

## [0.5.17] - 2026-11-04

Coordinated Apassy 0.5.17 release. Most new code serves a node on a tailnet: the
relay inside the Mac app and the Linux node `apassy serve` (SPEC section 32). The
hosted relay gets two migrations, relay sync without a team code, and the Connect
team limits.

- Team schema 8: the table `push_handle`, after a copy `<team>.db.pre-v8`.
  `apassy-relay downgrade-schema-7` is the way back; `downgrade-schema-6` takes 7 or
  8. The hosted relay keeps the table empty and answers 409 `push_unavailable` on
  `PUT`/`DELETE /v1/push/handle` (OPERATIONS section 25).
- Directory 1005: `team_code.kind` (`operator` or `node`) and one-use node pairing
  codes of 1 to 10 minutes (`apassy-relay admin node-code`), which only a relay with
  a tailnet listener takes. `apassy-relay downgrade-directory-1004` is the way back.
- Node on the tailnet: a tailnet listener with the device routes (and with agents the
  team routes, never OAuth or `/v1/connect`), the node origin as a sign-in origin,
  teams of devices, and push through the push gateway with one handle per device. A
  401 of `POST /mcp` on that listener carries no `WWW-Authenticate`. Failed sign-ins
  count per tailnet peer, as the node's TLS front saw it; the Mac's local route has a
  listener and a count of its own.
- `APASSY_RELAY_CONNECT_SYNC_BYTES` (default `0`): the `sync_bytes` of each new
  Connect team, so the hosted relay can keep a relay copy made without a team code.
  A team keeps the value it was made with (OPERATIONS section 20.6).
- Connect teams: at most 30 snapshot pushes and 512 MiB of snapshots an hour (403
  `team_limit`, 429 `rate_limited` with `Retry-After`).
- Push gateway Worker (`deploy/push-gateway`, push-gateway-v1): seals APNs tokens
  into handles and sends one APNs request per proof, with hourly and per-token
  limits in a Durable Object counter. Not deployed yet.
- The proxy shares its echo scrub with the Mac's run proxy (`echo.rs`).
- Linux node packages: `apassy-<version>-linux-<arch>.tar.gz` and
  `apassy_<version>_<arch>.deb` for x86_64 and aarch64 (glibc 2.31). `apassy-team`
  stays one release as an alias of `apassy team`.

## [0.5.16] - 2026-11-03

Coordinated Apassy 0.5.16 release. The hosted relay goes from 0.5.14 to 0.5.16.
Most new code serves the embedded node that the Mac app runs for remote agents
(SPEC sections 30 and 31); the hosted relay changes only by its migrations.

- Team schema 7: `agent.items`, an item list for each agent (NULL is every
  granted item), after a copy `<team>.db.pre-v7`. `apassy-relay
  downgrade-schema-6` takes a stopped relay back and revokes each agent with a
  list (OPERATIONS section 23).
- Directory 1004: the tables of the MCP authorization flow. The hosted relay
  migrates, keeps them empty, and answers 404 on every path of the flow.
  `apassy-relay downgrade-directory-1003` is the way back (OPERATIONS section 24).
- Embedded node (`apassy_relay::embedded::EmbeddedRelay`): `EdgeMode::Off` only
  on the loopback, a public listener that serves only `POST /mcp`, `/p/` and the
  authorization flow, a personal team without a code, the in-process release,
  agent item lists, and no operator socket.
- The MCP authorization flow on a node: OAuth 2.1 with PKCE S256, dynamic client
  registration, connect requests that the owner allows, refresh rotation with
  family revocation. A new connect never takes over an agent; errors of a client
  that the owner never allowed show a page, not a redirect; only allowed clients
  fill the client limits; bad codes count per client.
- The failed-auth limiter of the public listener counts per source address
  (IPv6 by /64), and the authorization flow is answered before it.
- The proxy drops `tailscale-*` request headers, and its scrub also replaces
  JSON-escaped, HTML-escaped and percent-encoded echoes of a value.
- One rule for hidden characters in client names (`apassy::text::is_hidden_char`).

The relay edge Worker changes only its `/guide` text. The Linux CLI
(`apassy-team`) has no functional change.

## [0.5.15] - 2026-11-03

Version alignment with the coordinated Apassy 0.5.15 release. No functional,
protocol or schema change.

## [0.5.14] - 2026-11-02

The relay moves into the Apassy workspace as `crates/apassy-relay` under
Apache-2.0 (ADR 0037). The image and both team CLIs build from the Apassy
repository's `relay-image.yml` workflow (tag `image-*`).

- `APASSY_RELAY_TEAM_VAULTS=0` refuses the proxy, MCP, `/v1/access`, `/v1/runs`,
  the host lane and new team-vault content with 410 `team_vaults_retired`.
  Devices, joins, relay sync, questions, feed, push and Connect keep working.
  The hosted image sets `0`; the default is `1`.
- The vendored `tiny_http` drops its unused TLS features and dev-dependencies.

Team schema 6 and directory schema 1003 remain unchanged.

## [0.5.13] - 2026-11-02

Version alignment with Apassy 0.5.13; no protocol or schema change.

No unreleased functional changes since `image-release-0.5.9`
(`67dc722`). Team schema 6, directory schema 1003, and pinned dependencies
remain unchanged. Both binaries share the root Cargo package version.
Earlier release records are in `docs/releases/`.
