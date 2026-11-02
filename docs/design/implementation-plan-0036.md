# Implementation plan — your own relay, build path (ADR 0036)

Date: 2026-11-02. Status: PLAN, accepted with ADR 0036. Stages 0 and 1 started 2026-11-02. Decision: [ADR 0036](../adr/0036-own-relay-open-source.md).

## Outcome and constraints

Apassy works with no Apassy-run server holding a key that opens a value. Every Mac and Linux machine
is a node with its own relay server. The iPhone, other devices, and team members reach a node over
Tailscale with a pinned certificate. The relay is Apache-2.0 in this repository.

- **No TEE on the build path.** TEE features are the enterprise track (ADR 0036, E1 to E4). Until
  then no Apassy-run server does the way B swap.
- **The wire contracts stay.** relay-questions-v1, relay-feed-v1, relay-access-request-v1,
  relay-sync-v1, and the ADR 0019 device identity move to a new origin. They do not change shape.
- **The hosted relay keeps running** until stage 7, so users without Tailscale lose nothing.
- **Releases:** each stage is a release of all six components at one version (AGENTS.md).
- **Mac resources:** at most three implementation or validation workers on this Mac. Workers do not
  run lint, typechecks, builds, or full test suites. The top-level agent runs one validation pass per
  revision through `~/.local/bin/heavy-check`, and prefers CI.

## Facts from the code (2026-11-02)

Read-only inventory of `apassy-relay` (`main`), this repository (`feat/touch-id-panel`), and `ios/`.

| Area | Fact | Where |
| --- | --- | --- |
| Relay start | `Relay::start(config) -> RunningRelay`, with `stop()` and `wait()`. One accept thread and one thread per request. No signal handling and no global state. The tests already start it in-process on 127.0.0.1. | relay `src/server/mod.rs:525`, `:281`, `:314`; `tests/common/relay.rs` |
| Relay config | `RelayConfig::from_lookup(closure)` builds the config without environment variables. The default listen address is `0.0.0.0:8080`. Plain HTTP (`tiny_http`, no TLS). | relay `src/config.rs:265`, `:269` |
| Edge secret | `X-Apassy-Edge` is always required. There is no switch to turn it off. | relay `src/server/http.rs:626` |
| Operator | Only through the `admin.sock` Unix socket (team codes, limits, suspend, backup). There is no operator HTTP endpoint. | relay `src/server/operator.rs` |
| Push | One push thread posts tokens to the Worker's push route with a shared secret. The Worker holds the APNs key. | relay `src/server/push.rs`; `deploy/worker/src/apns.ts` |
| Core use | Git dependency on `apassy` at rev `77f6628` with `vault`. One pin differs: rustls `=0.23.45` (relay) and `=0.23.46` (core). The other shared pins match. | relay `Cargo.toml:14` |
| Relay size | About 31,000 lines: server 14.5k, CLI 7.7k, proxy 1.6k. 616 tests, none need Docker. Worker: about 600 lines of TypeScript with vitest. | relay `src/`, `tests/`, `deploy/worker/test/` |
| Service install | `apassy-team host-install` writes a launchd LaunchAgent or a systemd user unit, without root. | relay `src/cli/service.rs` |
| App relay origin | `RelayLink { url, team_id, device_id }` per vault. The default origin is a constant. | `src/vaults.rs:144`; `src/sync/relay_http.rs:39` |
| App TLS trust | System roots through `rustls_platform_verifier`. No pin. `https://` to any host, `http://` to loopback only. | `src/broker/http.rs:21-29`, `:162-164` |
| Companion listener | `std::net` and threads, rustls `ServerConfig`, an rcgen certificate stored with the vault, pin = base64url SHA-256 of the certificate DER. Binds `0.0.0.0` (IPv4). Has connection limits. Starts on unlock, stops on lock and quit. | `src/companion/server.rs:104`, `crypto.rs:211`, `limits.rs`; `src/desktop/companion.rs:187-251` |
| Tailscale | The companion already finds the local Tailscale IPv4 address. | `src/companion/hosts.rs:19` |
| iPhone client | The relay client is the Rust core (the shared `relay_http.rs`), not URLSession. `relay_url` comes from the join link. Push token: `PUT /v1/push/token`. No Notification Service Extension. Foreground long polls of 25 s. | `ios/ApassyCore/src/core/join.rs:168`, `questions.rs:2350` |
| iPhone pinning | `ApassyCompanionKit` pins the SHA-256 of the leaf certificate DER, the same format as the Mac. | `ios/ApassyCompanionKit/Sources/ApassyCompanionKit/PinnedTLS.swift:15` |
| Linux | CI runs clippy with all features and the test shards on ubuntu-24.04. The `apassy` binary needs the `desktop` feature. There is no Linux packaging. Linux has no agent isolation. | `.github/workflows/ci.yml`; `Cargo.toml` `[[bin]]`; README |
| Release check | `--relay-checkout` reads the relay repository's version and its two binaries. | `scripts/check-release-versions.py:67-79` |

## Stage 0 — Prepare (S)

**0A Trust model.** Write `docs/security/trust-model.md` from ADR 0036, "Who sees what after this".

**0B History scan.** Run gitleaks on every ref of `apassy-relay`, and `/usr/bin/grep -E` (not ugrep) for
the token prefixes (`apassy_acc_`, `apassy_tagt_`, `apassy_ses_`, `apassy_lnk_`), private-key blocks,
and `.p8` names. Write the report without values. If it is clean, keep the history (D1). If not,
import one squashed commit.

**0C Scrub list.** Move these out of the published tree, into private operations notes:

- Server addresses in `deploy/vps/compose.yaml:43`.
- VPS alias, backup paths, and the `cc.wyderka…` launchd label (`deploy/vps/backup/*`, `docs/OPERATIONS.md`).
- `APNS_KEY_ID` and `APNS_TEAM_ID` in `deploy/worker/wrangler.jsonc:30-31`. Set them as Worker
  variables at deploy time.
- `health.yml`: it monitors production, so it stays private.

The public host name, the bundle id, and the GitHub org are already public and can stay.

**0D Decisions.** All accepted on 2026-11-02 (ADR 0036, the table at the end).

**0E Turn off shared team vaults and way B on the hosted relay (D8, now).**

1. **Inventory, read-only.** Use the operator socket (`admin teams`) to list the operator teams that
   have collections, items, agents, or way B sessions. Connect teams and personal relay-sync teams
   are out of scope.
2. **Notice.** Tell the owners of the affected teams. A message on the owner's behalf needs the
   owner's confirmation first.
3. **Bridge.** Until the new image ships, suspend the affected teams with `admin suspend`. This is
   reversible with `admin resume`.
4. **Code.** Add the setting `APASSY_RELAY_TEAM_VAULTS` (`1` by default for a user's own node; the hosted image sets `0`). With `0`, it
   refuses `/p/…`, run sessions, the host release endpoints, team MCP, and creating items,
   collections, grants, and team agents, with `410 team_vaults_retired`. It keeps devices, joins,
   links, relay sync, questions, feed, access requests, push, and Connect. Tests cover each refused
   route and each kept route. It lands in the moved crate (1A), so it ships in the first release
   from this repository. Done in PR #66 (`tests/server_team_vaults.rs`).
5. **CLI.** `apassy-team` prints the relay's message for `team_vaults_retired`: what is off, and that a team runs on its own node.
6. **Data.** Team files stay encrypted on the relay for the stage 4 export. Deleting them is a
   separate step that needs the owner's confirmation.

**Acceptance:**

- A clean scan report and an empty scrub list.
- The hosted relay refuses team-vault and proxy requests.
- A synthetic relay-sync push and pull and a question round trip still work against it.

## Stage 1 — Open the relay (S–M)

**1A Move the crate.** Own: `crates/apassy-relay/**`, root `Cargo.toml`, `Cargo.lock`, `.cargo/config.toml`.

- Import with history (`git filter-repo --to-subdirectory-filter`) or one commit (0B).
- `apassy = { path = "../..", default-features = false, features = ["vault"] }`.
- rustls `=0.23.46`. Merge the SQLCipher build flags into the one `.cargo/config.toml`.
- Workspace member. `license = "Apache-2.0"`. Replace LICENSE. Add a notice that versions before
  the move were FSL-1.1-ALv2.

**1B CI.** Own: `.github/workflows/ci.yml`, a new `relay-image.yml`.

- Relay clippy and tests on macos-15 and ubuntu-24.04, in the existing shard scheme.
- Worker vitest.
- The image build on the `image-*` tag, moved from the relay repository. Images still build on
  GitHub, never on the VPS.

**1C Worker.** Move `deploy/worker` to `deploy/relay-edge` (the edge and the push route). Values only
from Worker variables and secrets.

**1D Release tooling.** `scripts/check-release-versions.py` reads `crates/apassy-relay/Cargo.toml`.
`--relay-checkout` becomes an error with a message. Update AGENTS.md: the six components stay, one
repository.

**1E Archive.** Archive `wydrox/apassy-relay` after the first release from this repository.

**Acceptance:** a clean clone builds `apassy-relay`, `apassy-team`, and the image. The relay tests are
green in CI. The deployed image from this repository behaves like the last one (health, a synthetic
question round trip). The release check passes.

## Stage 2 — Node on the Mac (L)

Order: 2A first. Then 2B, 2C, and 2F in parallel. Then 2D and 2E. Then 2G, 2H, and 2I. Last 2J.

**2A Embedded relay mode.** Own: `crates/apassy-relay/src/{config.rs,server/mod.rs,server/http.rs,server/directory.rs}`.

- `EdgeMode::{Required(secret), Off}`. `Off` is refused unless the listen address is loopback.
- An embedded config builder: data directory in Application Support (or `$XDG_DATA_HOME` on
  Linux), no backup directory, no Connect limits, operator socket in the data directory.
- A personal bootstrap: the node owner creates the personal team and its first device through the
  directory API, with no team code.
- A `MasterKeySource` trait. On macOS, a data-protection Keychain item (this device only), so the
  node does not depend on which vault is unlocked. On Linux, systemd credentials or a 0600 file.
  Decide in 2A.

Acceptance: the existing relay suite passes in `Required` mode. New tests: an `Off` with a
non-loopback bind is refused; the bootstrap works; a restart reopens the teams.

**2B TLS front.** Own: proposed `src/net/tls_front.rs`, `src/net/tailnet.rs`; `src/companion/{server,crypto,limits,hosts}.rs` for the extraction only.

- Extract `tls_config`, the accept loop, the connection limiter, and the pin helper from the
  companion. The companion uses the extracted code too.
- Bind only the tailnet addresses: IPv4 in 100.64.0.0/10 from `hosts.rs`, and IPv6 in
  fd7a:115c:a1e0::/48. Never `0.0.0.0`.
- Refuse peers outside those ranges. Rebind when Tailscale goes up or down.
- Forward the plain stream to the relay's loopback port. Long polls stream through.
- A new node certificate (rcgen). The pin format is the companion's, so the Swift and Rust checks
  match. The verifier ignores dates.

Acceptance: unit tests for bind refusal, peer refusal, the limits, long-poll passthrough, and rebind.
Add a fuzz target for the front; the top-level agent runs it.

**2C Pinned trust in the client.** Own: `src/broker/http.rs`, `src/sync/relay_http.rs`, `src/vaults.rs`, `ios/ApassyCore/src/core/{config,join}.rs`; contracts.

- `TlsTrust::{System, Pinned(pin)}`. A pinned connection ignores the host name and the system store.
- `RelayUrl` accepts `https://` to tailnet literal addresses and `*.ts.net` names.
- `RelayLink` and the iPhone membership store the pin and an alternative address.
- The link fragment adds `pin=` and `alt=`. A fragment never reaches a server.
- New contract `docs/contracts/node-pairing-v1.md`. A note on the origin in the four relay contracts.

Acceptance: a pinned client refuses any other certificate and any downgrade to system trust. System
mode is unchanged. ApassyCore tests run against a fake node behind the TLS front.

**2D Node lifecycle.** Own: proposed `src/desktop/node.rs`, `src/desktop/mod.rs`.

- Start the embedded relay and the TLS front with the broker. Stop both on vault lock and on quit,
  with the companion's hooks.
- **Check first:** `src/desktop` has no close handling, so closing the window may quit the app. If
  so, add "Keep running in the menu bar", because the iPhone must reach the Mac while its window is
  closed.

Acceptance: lock stops the listener at once. Quit leaves no listener. Closing the window keeps the
node running.

**2E Connect to your own node.** Own: `src/relay/{connect,pairing}.rs`, `src/vault/connect.rs`, `src/questions/*` as needed.

- "Get approvals on your iPhone" creates the personal team on the local node when Tailscale is
  present. Otherwise it uses hosted questions-only Connect as today (D14).
- The pairing QR carries the node URL, the alternative address, the pin, the link code, and the
  ADR 0032 handoff.
- "Move approvals to this Mac" for existing Connect memberships, then delete the hosted membership.

Acceptance: a synthetic Mac and a simulated iPhone core pair over the front. The question, answer,
and settle digests are unchanged. The migration leaves no hosted membership.

**2F Push gateway.** Own: `deploy/relay-edge` (push route), `crates/apassy-relay/src/server/push.rs`, iPhone push registration in ApassyCore; new `docs/contracts/push-gateway-v1.md`.

- The iPhone sends its APNs token to the gateway. It gets back a handle, sealed under a gateway key
  (token, environment, time), and a handle secret.
- The iPhone gives the node the handle, not the token. The node asks for a push with the handle,
  authenticated with the handle secret.
- The gateway stores nothing and rate-limits per handle. It sends today's fixed notification.
- The hosted relay keeps its old route until stage 7.
- The gateway is free for everyone, self-hosters included (D7).

Acceptance: the node never holds an APNs token. A forged or altered handle is refused. The rate
limit holds. Worker tests.

**2G iPhone app.** Own: `ios/ApassyCompanion/**`, `ios/ApassyVaultKit/**`.

- Scan and accept node links. Show "via Tailscale" in Settings.
- One quiet state for "Tailscale is off on this iPhone". No unavailability card in Requests
  (ADR 0028 lesson).
- **Check:** does iOS ask for Local Network permission for 100.x addresses from Rust sockets? ATS
  does not apply to raw sockets; confirm this too.

**2H Mac UI.** Own: `src/desktop/ui/*` for Settings → Devices.

- Tailscale status (found, name, address), "Add an iPhone", and the device list with route, last
  contact, and Revoke.
- Make a mockup first. Before any release claim, compare a screenshot of each view with the
  approved mockup.

**2I Wi-Fi companion (D6).** The release that ships 2B offers no new Wi-Fi pairing and shows the
ADR 0028 notice. The release after it removes `src/companion/` (except the parts that 2B extracted),
companion-v1, `ApassyCompanionKit`'s companion client, and the device rows (a schema migration).

**2J Security review.** The front, `EdgeMode::Off`, pairing, and the push handles. Update the trust
model with the results.

**Stage acceptance (owner, physical):** an iPhone on cellular with Tailscale approves a run on the
Mac. A packet log shows no request to `apassy-relay.wyderka.cc`. Revoke works at the next request.
A vault lock stops the listener.

## Stage 3 — Linux node (M–L)

**3A Headless binary.** The `apassy` binary needs `desktop` today. Add a `node` feature, so that
`apassy` builds on Linux with `--no-default-features --features vault,node` and runs only
subcommands. The macOS binary keeps the window. Decide in 3A whether `src/main.rs` splits or a
second entry point is added.

**3B Commands.** `serve`, `up` (checks Tailscale, chooses routes, installs the service, prints the
pairing QR in the terminal), `pair`, `status [--json]`, `doctor`, `team …` (the `apassy-team`
commands).

**3C Unlock.** In stage 3 the Linux node is a sync home and a pairing peer. These roles need no vault
unlock, because a sync home stores ciphertext. A team host (stage 4) needs its item keys:
`apassy unlock` on a terminal at first, and TPM2 sealing through systemd credentials later.

**3D Service.** Reuse `cli/service.rs` (systemd user unit). `up` gives the `loginctl enable-linger`
hint, so the node starts at boot without a login.

**3E Packages.** `.tar.gz` for x86_64 and aarch64, and `.deb`. SHA-256 checksums, GitHub build
attestations, and an install script. Build on GitHub runners.

**3F Compatibility.** `apassy-team` stays as a thin alias with a deprecation notice for one release.

**Acceptance:** a fresh Debian or Ubuntu machine on the tailnet installs the package, pairs with the
Mac and the iPhone, and survives a reboot with linger.

## Stages 4 to 7 (outline; one plan each before they start)

- **4 Sync and teams on nodes.**
  - A sync-home role that serves relay-sync-v1 from a node, with the anchors and chain unchanged.
  - A team host on a node, and the Tailscale share flow (manual at first).
  - A **spike for the embedded tailnet (D9):** libtailscale through its C API from Rust. Check the
    binary size, the Go runtime in a notarized app, the per-tailnet auth key, and the state
    directory. The spike ends with go or no-go.
  - The way A switch and its information (D10).
  - The team export endpoint on the hosted relay, and import on a node.
- **5 Linked environments.** `apassy environment link` (`ssh -R` or the tailnet), the thin executor,
  the remote MCP endpoint on the node, and Funnel (off by default).
- **6 Private sharing.** Way C for AWS STS, GitHub Apps, Google Cloud, and OAuth refresh tokens.
  Remote SigV4 signing. Keys per member where a provider has a key-management API.
- **7 Apassy Connect.**
  - A byte relay: the node keeps an outbound tunnel, and Connect forwards TLS streams by id without
    opening them.
  - The blind sync store, the production push gateway, and accounts with Stripe (live account
    exists; Stripe Tax is pending).
  - The free questions-only path of ADR 0032 ends (D14: all of Connect is paid). Show a notice two
    releases before.
  - Remove the master key, team files, and way B from the hosted service.

## Merge order and checks

1. Stage 1 merges before any stage 2 unit, so that one repository and one lock file exist.
2. In stage 2, one editor owns each shared file at a time. `src/companion/*` belongs to 2B until the
   extraction merges. `src/sync/relay_http.rs` belongs to 2C.
3. Validation is one top-level pass per revision: CI after an authorized push. A local run goes only
   through `~/.local/bin/heavy-check`. A worker reports the exact commands and does not run them.
4. Physical checks on the iPhone (cellular, Tailscale, Face ID, push) are separate acceptance steps
   for the owner. A synthetic pass is not a device pass.

## Open checks found while mapping

1. Does closing the Mac window quit the app? No close handling was found in `src/desktop` (2D).
2. Does iOS ask for Local Network permission for tailnet addresses from Rust sockets (2G)?
3. Where does the node master key live when there are several vaults (2A)?
4. Headless unlock on Linux for a team host (3C, stage 4).
5. Can a Go runtime (libtailscale) ship inside the notarized Rust app (stage 4 spike)?
6. Abuse limits of the push gateway without accounts (2F).
