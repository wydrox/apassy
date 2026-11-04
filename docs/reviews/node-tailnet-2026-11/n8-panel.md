# N8 security panel: the node over the tailnet, the push gateway, the Linux node

Date: 2026-11-03. Plan: [implementation-plan-s2-s3.md](../../design/implementation-plan-s2-s3.md),
unit N8 (decision D10). Reviewed: `release/0.5.17` at `6bd9181f` (branch `r17/n8-panel`).
Method: adversarial source reading, read-only. No test, build, or fuzz run (see "Not verified").
No production system, paid server, vault, or Keychain was touched.

## Verdict: FAIL

No High finding. One **Medium** finding (N8-1) is open: an unauthenticated tailnet peer can
stop every device of a node, and the Mac itself, from using the node. The N8 acceptance of the
plan ("each medium finding fixed or recorded with the owner's acceptance") is not met. The
verdict becomes PASS when N8-1 is fixed or the owner accepts it in writing. The Low and Info
findings below do not block.

What held up under attack:

- **Pinning.** I found no path where a node origin connects with the system trust store or
  another pin. The Rust verifier checks the SHA-256 of the leaf only, compares it in constant
  time, takes TLS 1.3 only, and checks the CertificateVerify signature with the leaf key
  (`src/broker/http.rs:196-284`). A pin mismatch stops before any request byte and tries no
  alternative destination (`src/sync/relay_http.rs:945-993`). A stored pin that does not parse
  is an error, never system trust (`src/sync/relay_http.rs:99-108`). A pinned vault
  membership upgrades a system-trust address before any token goes out, and refuses a
  different pin (`src/sync/relay.rs:1307-1322`, `:1560-1570`). The known TODO sites are
  resolved: `ios/ApassyCore/src/core/join.rs:299-307` (`with_url_trust`),
  `ios/ApassyCore/src/core/config.rs:52-65` (`with_trust` from the entry's pin), and
  `src/desktop/sync_worker.rs:1520` (test code only). The three desktop sites are N8-6. The
  watch transport pins in a separate TLS 1.3 session and cancels every other challenge
  (`ios/ApassyVaultKit/Sources/ApassyVaultCore/URLSessionCoreTransport.swift:110-128, :224-243`).
- **Downgrade to the hosted relay.** A link without `pin` is a hosted link, and a node
  origin (`https://100.x:port`) with system trust fails closed: no public CA issues a
  certificate for that range. A pinned origin never sends a push token. The node answers
  409 to `PUT /v1/push/token` in gateway mode (`crates/apassy-relay/src/server/questions.rs:989-994`),
  and the iPhone core never sends a token to a pinned origin
  (`ios/ApassyCore/src/core/questions.rs:2770-2790`, `questions/push_gateway.rs:80-98`).
  A client signs only its own stored origin and refuses a challenge that names another
  (`src/sync/relay.rs:539`).
- **Front binding and peers.** The front binds only addresses that are both in
  `Self.TailscaleIPs` and on an interface (`src/net/tailnet.rs:116-124, :159-169`). So a
  carrier CGNAT address on Wi-Fi is never bound. Peers outside the two ranges are closed
  before TLS (`src/net/tls_front.rs:630-636`). The front parses no HTTP, issues no tickets,
  takes no early data, and connects only to a loopback target
  (`src/net/tls_front.rs:209-227, :399-401`). The test hooks of `apassy serve` exist only
  in debug builds (`crates/apassy-relay/src/node/serve.rs:683-691`).
- **Tailnet scope routing.** An allow-list runs first, then exact segment matching, so
  `..`, `//`, percent forms, and absolute-form targets cannot reach `/v1/connect`, OAuth,
  or operator paths (`crates/apassy-relay/src/server/http.rs:86-142, :342-386, :1050-1061`).
  The Mac node uses `agents: false` (`src/node/mod.rs:642`). The scope trusts no header:
  `Host` only chooses which origin a challenge names (`server/devices.rs:147-164`).
- **Node codes.** A node code is a one-use `team_code` of kind `node`, 1 to 10 minutes. It
  is checked and marked used in one transaction, and it works only on a relay with a tailnet
  listener (`server/directory.rs:837-848, :909-941`; `server/hub.rs:612-619`). The
  in-process device team stores no owner token (`server/hub.rs:104-121, :781-788`).
- **Move approvals and Devices.** The move starts only after
  `OwnerRequest::EnableRelayQuestions` for the node origin
  (`src/desktop/ui/sync/questions.rs:409-426`). It finishes only after a device confirmed in
  the node team (`:547-578`). The route switch and Revoke check the owner proof
  (`src/desktop/ui/devices.rs:1973-2069`).
- **Push gateway.** Handles are AES-256-GCM sealed, with the format and key id in the AAD.
  Proofs are HMAC checked with `crypto.subtle.verify`. The checks run in the contract's order.
  A missing rate-limit binding fails closed (503). The gateway has no storage binding and
  observability is off (`deploy/push-gateway/src/gateway.ts:175-307`, `src/handles.ts:292-383`,
  `wrangler.jsonc`). The payload is the fixed text. No client sends a sealed summary yet, so
  no item name reaches Apple or the gateway, even as ciphertext. The node calls only its own
  gateways, follows no redirect, and never logs a handle or a secret
  (`server/push.rs:493, :951-953, :1121-1196`).
- **Linux key at rest.** The order is: a systemd credential, then a `systemd-creds --user`
  file, then a 0600 file. Symlinks, non-files, and group or other readable modes are refused.
  The directory is 0700. The unit has `UMask=0077` and `NoNewPrivileges=yes`, and its paths
  pass an allow-list (`crates/apassy-relay/src/node/keys.rs:86-250`, `node/service.rs:41-63`).
- **Migrations.** Team schema 8 is additive with a `.pre-v8` copy. The way back keeps the
  table, and the next upgrade drops the handles of devices revoked in between
  (`server/store.rs:547-584`). Directory 1005 is additive, and its way back deletes unused
  node codes (`server/directory.rs:66-83, :716-733`). Vault 28 adds columns to local tables
  only. An older app refuses the file, and a lost pin fails closed (`src/vault/schema28.rs`).

## Findings

### N8-1 — Medium — One tailnet peer locks every device out of the node

- **Where.** `crates/apassy-relay/src/server/http.rs:168-196` (`AuthFailures`: one window
  per listener), `:1099-1102` (a limited listener answers 429 to everything but
  `/healthz`, sign-in included), `:1269-1272` and `:1294-1296` (a missing or bad bearer
  counts). `crates/apassy-relay/src/config.rs:686` (`auth_limiter: true` for every embedded
  and headless node). `src/net/tls_front.rs:765` (the front connects from the loopback, so
  every tailnet peer arrives as `127.0.0.1`). `src/node/tailnet.rs:382` (the Mac's own
  local route targets the same tailnet listener).
- **Scenario.** Any device that the Tailscale ACLs let reach `100.x:8444` needs no key:
  another device of the owner, a shared-in node, or a compromised box on the tailnet. It
  opens a TLS connection (it does not need to check the pin) and sends `GET /v1/me` with no
  `Authorization` 20 times in 60 s. It repeats once a minute. From then on, every request on
  the node's tailnet listener gets `429 rate_limited`: the iPhone's sign-in, answers, the
  feed, access requests, and relay sync. The Mac's own questions worker also posts through
  the local route to this listener, so its posts get 429 as well. Runs that need an approval
  wait and time out. The front's per-peer limits do not help: 20 requests fit in one
  connection, or in 20 of the 60 new connections a minute. The audit row
  `auth_limit_tailnet` names no peer, because the relay sees only the front.
- **Minimal fix.** (a) Give the Mac's local route a loopback listener that the front does not
  forward to, so tailnet peers can never limit the Mac's own clients. (b) On
  `Scope::Tailnet`, do not lock the whole listener. Either turn `auth_limiter` off for that
  scope (tokens are 256-bit random, and the front already limits connections per peer), or
  count failures per front peer: the front records `loopback source port → peer address`
  for each pumped connection in process, and the tailnet listener keys `AuthFailures` by
  that peer. Test: a peer with 25 bad tokens a minute does not stop a second peer's sign-in
  or the Mac's question post.
- **Owner.** N1 (relay) with N2 and N4 (front, local route).

### N8-2 — Low — After a certificate replacement, the Mac keeps handing out the old pin

- **Where.** `src/node/mod.rs:1298-1321` (`pairing_link` builds the link from the stored
  membership), `src/node/questions_team.rs:97-108` (`device_link` uses
  `membership_relay_url`), `src/node/mod.rs:803-807` (the note "Pair your iPhone again"),
  `src/node/mod.rs:1243-1246` (`ensure_questions_team` reuses a membership without
  comparing its pin with the route's).
- **Scenario.** `front/cert.der` or `front/key.sealed` is lost or unreadable, while
  `relay.db` and the team still open. `tailnet::certificate` makes a new certificate and the
  Mac says "Pair your iPhone again". Every new pairing QR still carries the old pin (and the
  old `alt`), so each iPhone refuses with a pin mismatch. Nothing recovers except removing
  the questions team. This fails closed: nothing leaks, but pairing is stuck.
- **Minimal fix.** In `pairing_link` and `ensure_questions_team`, compare `membership.pin`
  with the route's pin. When they differ, write the route's pin and alternatives into the
  Mac's own membership (`Vault::set_membership_trust`): the Mac is that node and reaches it
  through the local route. Or build the link from the running route. Test: replace the
  certificate, then check that the pairing link has the new pin.
- **Owner.** N4.

### N8-3 — Low — Anyone who knows a device token can make handles and push to it

- **Where.** `crates/apassy-relay/deploy/push-gateway/src/gateway.ts:189-226`
  (`POST /v1/handles` takes any well-formed token of the topic), `:262-269` (limits per node
  address and per handle only); `wrangler.jsonc:17-21`.
- **Scenario.** Some parties know an APNs token of the app: Apple, the hosted relay
  (`push_token` of hosted memberships), or anyone who copies one from a leak or a backup.
  Such a party makes handles at 10 a minute per address and pushes the fixed "A question is
  waiting" (sound, time-sensitive) at 10 a minute per handle. With more handles and more
  addresses, the rate per device has no bound. Before the gateway, only the holder of the
  relay Worker's secret could push. The same open endpoint lets junk tokens spend the
  project's APNs requests.
- **Minimal fix.** Add a `pushes_per_token` binding keyed by SHA-256 of the token, checked
  after the handle opens (step 4), for example 10 a minute. Test: 11 pushes through 11
  handles of one token in a minute give one 429.
- **Owner.** N5.

### N8-4 — Low — The gateway limits are 10× to 20× the contract's

- **Where.** `deploy/push-gateway/wrangler.jsonc:12-21`: 10/min per handle, 100/min per
  address, 10/min handle creations. That is 600/h, 6000/h, and 600/h. Contract
  `docs/contracts/push-gateway-v1.md` §13 and plan D7 say 60/h, 600/h, and 30/h. The comment
  in `wrangler.jsonc` gives the reason: a binding counts only per 10 s or 60 s.
- **Scenario.** Readers of the contract and the trust model expect a cap 10 times lower
  than the deployed one. A node, or a holder of a handle, can push 600 times an hour to one
  device.
- **Minimal fix.** Change contract §13 and plan D7 to the per-minute numbers (N0 or N5),
  with the owner's acceptance. Or keep the hourly numbers with a Durable Object counter,
  which the contract already allows.
- **Owner.** N5, with N0 for the contract.

### N8-5 — Low — The Serve fallback turns every local process into a tailnet peer

- **Where.** `src/net/tls_front.rs:402-408, :422-424`; `src/node/tailnet.rs:193-209,
  :353-363`; `crates/apassy-relay/src/node/serve.rs:553-556`.
- **Scenario.** With `FrontRoute::ServeTcp`, the front binds `127.0.0.1:<free port>` and
  admits every loopback peer. Any local process, of any local user on a Linux host, reaches
  it as a "tailnet peer". All real tailnet peers share one bucket of 64 connections, so one
  peer can hold every slot. After a crash, the `tailscale serve --tcp 8444` forward stays and
  points at a loopback port that another local process can then bind. That process gets the
  tailnet traffic. Paired devices refuse its certificate, so no data leaks, but no device
  reaches the node.
- **Minimal fix.** On start in ServeTcp mode, remove a stale forward of the port before
  enabling it. The trust model now says what this mode exposes (change T3). Use the PROXY
  protocol of Tailscale Serve when it is available, to get per-peer limits back.
- **Owner.** N2 and N4; L1 for `serve`.

### N8-6 — Info — Three desktop paths hold system trust and rely on the vault membership

- **Where.** `src/desktop/ui/sync/relay.rs:1630-1639` (`relay_staged`), `:1676-1684`
  (`relay_take_staged` copies the staged trust, which is `System`), and `:2981-2986` (join).
- **Why it is safe today.** A pinned join carries its pin in `JoinedDevice::session`. The
  next session of the vault restores the pin from `relay_membership.pin` before any token
  goes out (`src/sync/relay.rs:1560-1570`). A system-trust connection to a `100.x` origin
  fails anyway.
- **Hardening.** Carry `with_url_trust(&joined.session.url)` into the staged config, so
  that a future direct `config.relay_url()` cannot connect with system trust.

### N8-7 — Info — The node words are 48 bits, and grinding them is cheap

- **Where.** `src/net/pin.rs:38-44`; node-pairing-v1 §4a.
- **Note.** The words are the first six bytes of the pin. The pinned verifier ignores the
  certificate's own signature, so an attacker can vary any DER bytes and needs about 2^48
  SHA-256 computations to match six words: hours on a few GPUs. The trust comes from the
  whole pin and from the safety words of the pairing, which cover the pin (contract §8).
  Never present the node words as enough to trust a node, for example in a "certificate
  changed" flow.

### N8-8 — Info — Smaller notes

- `crates/apassy-relay/src/node/keys.rs:395`: `seal` deletes the plain `master.key` with
  `remove_file`, so the bytes can remain in freed blocks, snapshots, and backups.
  `systemd-creds --user decrypt` opens the credential for the same user by design
  (`keys.rs:19-21` says so). Without TPM2, the credential protects against copies of the
  home directory only.
- `crates/apassy-relay/src/server/http.rs:1062-1078`: `/healthz` on the tailnet listener
  gives any tailnet peer the relay version and the build commit, with no authentication.
- Cloudflare Rate Limiting bindings are counted per location and are eventually
  consistent. The gateway limits are therefore approximate.

## Fixes

Follow-up on `r17/fix-trust-docs`: Serve without PROXY peer addresses keeps a shared
listener-wide failed-auth limit of **200 in 60 s**, versus **20 in 60 s per peer**
when addresses are available. One peer can still exhaust the shared limit. Node status
flags `serve_without_peer_addresses`; Mac Devices and Linux `apassy doctor` show
"Tailscale Serve without peer addresses: update Tailscale". The separate local route
keeps its own 20/min limit. Tests cover 200 failures, the local route isolation, the
Serve status flag for old and current CLIs, and the doctor warning.

The trust model also records the authority of both remote bouncer hosts: they can cause
development and staging runs without asking, within the hard gate. The Linux guide and
doctor warn against running coding agents as the node's user (known config folders only).

Date: 2026-11-03. Branch `r17/fix-n8`, based on `release/0.5.17` at `32ec1d6e`. N8-6 belongs to
unit L4 and is not in this branch.

| Finding | Commit | Change | Test |
| --- | --- | --- | --- |
| N8-1 Medium | `16489934` | The front names the tailnet peer of each pumped connection in process memory (`src/net/front_peers.rs`), keyed by the loopback address pair of its connection to the relay; no header. The tailnet listener counts failed authentications per peer (`FailureKeys::PerPeer`); a connection that the front did not make counts as the loopback. The audit row names the peer. The Mac's local route goes to its own loopback listener (`RunningRelay::tailnet_local_addr`, `RunningNode::local_route_addr`), which the front never forwards to and which counts on its own (`auth_limit_tailnet_local`) | `tailnet_scope::one_tailnet_peer_with_bad_tokens_does_not_limit_another_peer_or_the_local_route` (peer A: 20 × 401 then 429; peer B, an unnamed local connection, and a signed-in device on the local route are not limited), `tailnet_scope::the_local_route_listener_counts_its_own_failures`, `tls_front::the_front_names_the_peer_of_each_pumped_connection_until_it_ends`, `net::front_peers` unit tests |
| N8-2 Low | `e09d9575` | `Node::pairing_link` and `Node::ensure_questions_team` take the pin and the alternatives of the running route and write them into the Mac's membership when they differ (`Vault::set_membership_trust`) | `node::tailnet_tests::after_a_certificate_replacement_the_team_and_its_links_take_the_new_pin` |
| N8-3 Low | `89ef55ab` | The gateway limits each APNs token: 10 handle creations a day, and 30 pushes an hour over all its handles (checked after the handle opens). Contract section 13 has the two rows | `gateway.test.ts`: "give one token 10 handles a day, over every address", "give one token 30 pushes an hour through all its handles" |
| N8-4 Low | `89ef55ab` | The contract's numbers (60/600/30 an hour) are in code. A Rate Limiting binding counts per 60 s at most, so the gateway uses the Durable Object counter that section 13 allows (`src/limits.ts`): one window of counts per limit and key (SHA-256), deleted by an alarm when it ends; `Retry-After` is the rest of the window; no counter or a failed one is 503. The contract's numbers are unchanged | `gateway.test.ts`: "are the contract's hourly numbers…", "count a fixed window…", "give one handle 60 pushes an hour, then 429 with the rest of the hour, then again", "is unavailable when a counter fails", and the deployment checks |
| N8-5 Low | `16489934` | Serve is asked for a PROXY protocol v1 line (`--proxy-protocol=1`, with a fallback for a command line without it); the front reads the peer from it and gives each peer at most 16 of the 64 connections and 60 new ones a minute. At start the front first turns off a forward to its earlier local port left by a crash (`ServeTcp::clear_stale`; the Mac keeps the port in `serve-tcp-port`, `apassy serve` uses its fixed port). `apassy serve` takes the fallback limits of the Mac. The trust model says that the fallback cannot tell local processes from peers, and that a local process can write a PROXY line too | `tls_front::the_serve_fallback_reads_the_peer_of_a_proxy_line_and_caps_each_peer`, `net::tls_front::tests::a_proxy_v1_line_names_its_source`, `net::tailnet::tests::a_stale_forward_of_a_crash_goes_before_the_front_takes_a_port`, `…::an_old_command_line_gets_the_forward_without_the_proxy_protocol` |
| N8-6 Info | — | Unit L4 | — |
| N8-7 Info | `4da1010f` | The Mac's help of Node Words and the iPhone's line ("Node words to compare: …") call them safety words to compare and say that the same words are not proof of the node; node-pairing-v1 section 4a says why. The term "node words" stays (the contract's name), so the words are not mixed up with the safety words of a pairing | Swift model tests updated (`DeviceRouteTests`, `JoinModelTests`); not run (no Xcode run in this unit) |

The trust-model rows of N8-1, N8-3 (the per-token bound), and N8-5 are in `16489934`; the
gateway's storage row is in `89ef55ab`.

With N8-1 fixed, the verdict is **PASS** under the plan's rule; the Low and Info findings are
fixed except N8-6 (L4).

Checks on `r17/fix-n8` (all through `heavy-check`): `cargo test -p apassy-relay --test
tailnet_scope` 5/5; `cargo test -p apassy-relay --lib -- server::http node::` 45/45; `cargo test
--features vault,insecure-test-kdf --lib -- node:: net::` 61 of 62 (one failure that the base has
too, below); `cargo test --features vault,insecure-test-kdf --test it -- tls_front:: relay_pinned::`
19/19; the gateway's `npm test` 42/42 and `tsc` clean; `cargo clippy --offline --locked
--all-features --all-targets -- -D warnings` and `-p apassy-relay -p apassy-core` clean; `cargo fmt
--all --check` clean. The relay suites `embedded`, `node_cli`, `cli_json`, `server_audit`, and
`server_connect` pass.

Failures that the base `32ec1d6e` has too (checked by running them on the base), not caused by
these fixes: `node::tailnet_tests::the_tailnet_route_starts_without_funnel_and_a_lock_stops_the_front_before_the_relay`
(`Node::status` gives the Funnel URL whenever Tailscale names the Mac), and 7 of 19 tests of
`crates/apassy-relay/tests/oauth.rs` ("The code is not valid" at the token step).

Not verified: the PROXY line of a real `tailscale serve --proxy-protocol=1` (1.98 and 1.104
list the flag); the Durable Object counter on the deployed Worker (the deploy is the owner's
step: the class `LimitCounter`, migration `v1-limits`); the Swift tests.

## Changes to `docs/security/trust-model.md` (only where the code proves the doc wrong)

| Mark | Change | Code that proves it |
| --- | --- | --- |
| T1 | The node over the tailnet and the gateway are built on `release/0.5.17` and unreleased. They are no longer "planned" | N1 to N7 merged at `6bd9181f` |
| T2 | New row "Your Linux node": it holds no vault and needs no unlock. It holds the relay directory and team files under the node master key (a systemd credential, `master.key.cred`, or a 0600 `master.key`), and the item keys of `apassy team host`. The old row claimed the Linux node holds "your vaults, the broker, the bouncer" | `crates/apassy-relay/src/node/serve.rs`, `node/keys.rs:1-21`; plan D8 |
| T3 | TLS front: in the Serve fallback it binds `127.0.0.1`. Then every peer is `127.0.0.1` (`tailscaled` or any local process), and the per-peer limits are one pool. The old row said it binds only the tailnet ranges and refuses other peers | `src/net/tls_front.rs:402-408, :422-424` |
| T4 | Tailnet listener: it also sees requests without a key from any tailnet peer (sign-in challenges, link, join, and team codes), the Mac's own clients in plain text over the local route, and on the Linux node the member and agent requests of the team routes. It cannot tell peers apart, and its failed-auth limit covers the whole listener (N8-1). The old row said "device-signed requests" | `server/http.rs:86-142, :168-196, :1099`; `src/node/tailnet.rs:382` |
| T5 | Push gateway: it has no storage binding, but Cloudflare's rate-limit counters (60 s) are keyed by SHA-256 of the handle or of the client address. Any holder of a device token can make a handle and push the fixed alert within the limits (N8-3). The old rows said "stores … nothing" and implied that only a node with a handle can push | `deploy/push-gateway/wrangler.jsonc:17-21`, `src/gateway.ts:189-226` |

## Not verified

- **No test, build, or fuzz run.** The Mac had 14 GiB of free disk, under the 15 GiB floor
  of the owner's resource rules, so I queued no `heavy-check cargo test`. Every statement
  above comes from reading the source at `6bd9181f`. The `tls_front_pump` fuzz target did not
  run. N8-1 is shown from the code path; no test reproduces it yet.
- **Reachability of the Tailscale address from the LAN.** macOS and Linux use the weak host
  model, so a LAN host can open TCP to the Tailscale IPv4 of the node; the peer check then
  closes it before TLS. A spoofed `100.64/10` source gets no SYN-ACK back: its route is the
  Tailscale interface, and on Linux the `ts-input` netfilter rule also drops such packets.
  This is reasoning only, not tested on the owner's machines or with the App Store Tailscale.
- Whether a lock of the vault stops the front on every lock path (screen lock, the
  auto-lock timer). I read `src/desktop/node.rs` and the doc of `stop_node`, not each caller.
- The Swift pinned transport on a real watch, ATS with an IP origin, and URLSession
  connection reuse across pins (one pin per origin makes reuse harmless).
- `systemd-creds --user` on a real systemd 256 or later, and the TPM2 binding.
- L4 (the Mac's relay sheet takes a Linux node's pairing link). Today
  `relay_enable_new` parses a typed address with system trust, so a pasted node link fails
  closed.
- The gateway against the deployed Worker, the Cloudflare binding semantics, and APNs
  behaviour with many bad tokens.
- The watch core (`ios/ApassyCore/src/core/watch.rs`) beyond its membership trust.
