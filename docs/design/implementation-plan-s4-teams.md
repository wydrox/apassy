# Implementation plan — stage 4: sync and teams on nodes (ADR 0037)

Date: 2026-11-03. Status: PLAN, written on the owner's decision of 2026-11-03 (build everything in the ADRs except the TEE track, as fast as possible, with parallel agents, no intermediate approvals). Where an ADR leaves a choice open, this plan takes the recommended option and marks it "chosen by this plan; the owner can change it".
Decision: [ADR 0037](../adr/0037-own-relay-open-source.md) stage 4 (sections 2, 4, 5, 9, 10, "Migration", D5, D8, D9, D10), [ADR 0018](../adr/0018-local-bouncer-shared-vault-relay.md), [ADR 0019](../adr/0019-relay-teams-and-accounts.md) (section 9 "one host for all teams", stage 5, notifications), [ADR 0022](../adr/0022-relay-sync.md) stage 2 and later, [ADR 0026](../adr/0026-simple-app.md) §6, [sync.md](../operations/sync.md) section 11.
Parent plan: [implementation-plan-0037.md](implementation-plan-0037.md) ("Stages 4 to 7"). Parallel plan: `implementation-plan-s2-s3.md` (the rest of stage 2 and stage 3); this plan depends on it by the unit names of the parent plan (2B TLS front, 2C pinned trust, 2D node lifecycle, 2E pairing, 2G iPhone, 3A headless binary, 3B commands, 3C unlock, 3D service, 3E packages). If that plan renames them, the names here follow.
Base inspected: `origin/release/0.5.16` at `0edf1f90` (vault schema 26, relay team schema 7, directory 1003, release 0.5.15 shipped, 0.5.16 in preparation).
Format: [implementation-plan-0035.md](implementation-plan-0035.md).

## Outcome and constraints

After this stage, no Apassy-run server holds a team file or a vault copy of a user who runs a node:

- **Sync home.** A node (a Mac, or a Linux `apassy serve`) is the sync home of a vault: it serves relay-sync-v1 on its own origin, and the owner's other Macs (and later the iPhone) sync through it. Moving the home is one action on one Mac; the other devices follow by themselves. The hosted relay keeps relay sync until stage 7.
- **Team host.** A node hosts shared vaults (teams) for members in the owner's tailnet and, through Tailscale node sharing, in other tailnets. The host holds the item keys and does the way B swap. Approvals stay on the owner's devices. One host process serves every team of the machine (ADR 0019 §9 closed).
- **Shared vaults in the app** (ADR 0026 §6, ADR 0018): the Shared section of the sidebar works. A credential has one home and can be in many shared vaults; members use it through their agents; the owner edits it.
- **Way A switch** (D10): a collection can deliver values to members' devices, with the facts shown, the badge, the audit, and the removal list.
- **Embedded tailnet node** (D9): a spike with go or no-go, then the team host as its own tailnet machine `apassy-team-<slug>` that listens only on the Apassy port.
- **Migration** (D8): hosted teams export from the hosted relay and import into a node; relay-sync vaults move to a sync home and delete their relay copy.
- **ADR 0022 stage 2:** the vault is the trust root for signed heads (the relay cannot add a device); receipts are shown (already shipped, see Facts); the 64 MiB push gets a check.
- **ADR 0019 open items:** one host process for all teams (by the node), the Secure Enclave device key on the Mac (vault schema 33), owner notifications beyond the audit.

What does not change: the wire contracts relay-sync-v1, relay-questions-v1, relay-feed-v1, relay-access-request-v1, and the ADR 0019 device identity keep their shape; additions are additive and named below. No TEE work (D12). The hosted relay runs until stage 7. Every release ships all six components at one version (AGENTS.md).

Process constraints (house rules): at most three implementation or validation workers across this Mac; workers do not run lint, typechecks, builds, or full suites and return the exact commands; the top-level agent runs one validation pass per revision through `~/.local/bin/heavy-check`, and prefers CI after an authorized push; Docker only on `devbox-arm` or `devbox-x86` with the architecture named; never `ottervibe` for development; browser work only in Helium on port 9223.

## Facts from the code (2026-11-03, `0edf1f90`)

| Area | Fact | Where |
| --- | --- | --- |
| Vault schema | `SCHEMA_VERSION` is 26 (cloud agents, local tables). The bouncer-section plan claims 27; this plan has 30 and 33. | `src/vault/types.rs:22`, `src/vault/schema26.rs:1-20`, `docs/design/implementation-plan-bouncer-section.md:75` |
| Relay schemas | Team file `SCHEMA_VERSION` 7 (`agent.items`); directory `DIRECTORY_VERSION` 1003. The bouncer-section plan claims directory 1004; this plan has team 9 and directory 1006. | `crates/apassy-relay/src/server/store.rs:31`, `crates/apassy-relay/src/server/directory.rs:24`, `implementation-plan-bouncer-section.md:193` |
| Embedded relay | `RelayConfig::embedded(EmbeddedOptions {data_dir, master_key, public_url, public_listen})`, `EdgeMode::Off` on loopback only, `Hub::create_personal_team(name, now)` without a team code, `EmbeddedRelay`/`EmbeddedNode` behind the core's traits. SPEC section 30. | `crates/apassy-relay/src/config.rs:252,389`, `crates/apassy-relay/src/server/hub.rs:680`, `crates/apassy-relay/src/embedded.rs:50,82`, `crates/apassy-relay/docs/SPEC.md` §30 |
| Node seam | `NodeBackend::start` and `RunningNode` (`create_team`, `has_team`, `sync_items`, `create_agent`, `set_agent_items`, `revoke_agent`, `wait_pending`, `release`, `deny`, `run_state`, `recent_audit`, `stop`) with plain types; one personal team named `Personal` for each vault; the node starts only for an unlocked vault whose public route is on. | `src/node/backend.rs:109,260-345`, `src/node/mod.rs:54,197-202`, `Node::may_run` in `src/node/mod.rs` |
| In-process host | One host thread per node waits for pending runs, asks the broker (`evaluate_cloud`), reads values from the vault, and calls `host::release_values` (one use, fails closed). Items of the personal team carry `hostkeys::VALUE_ON_HOST`. | `src/node/host.rs:1-19`, `src/broker/run.rs:933`, `crates/apassy-relay/src/server/host.rs:415`, `crates/apassy-relay/src/hostkeys.rs:44` |
| Hosted-team key holder | `apassy-team host` keeps item keys in `keys.json`, serves one team per process (one launchd label or systemd unit per team), and releases keys sealed to the run key (`host::release`). `authorize_host` needs the key-holder device of a live owner. | `crates/apassy-relay/src/cli/host.rs:1-9`, `crates/apassy-relay/src/cli/keystore.rs:24`, `crates/apassy-relay/src/cli/service.rs:14-20`, `crates/apassy-relay/src/server/host.rs:362`, `crates/apassy-relay/src/server/devices.rs:377`, SPEC §23.6 (`host`) |
| Relay sync server | `server/sync.rs`: push with every check of SPEC §24.3, `view` with chain, signers, receipts, `KEPT_HEADS` 10000, `MAX_CHAIN` 1000; routes under `/v1/sync/*`. The embedded node serves them unchanged on its node listener. | `crates/apassy-relay/src/server/sync.rs:36-38,323,557`, `crates/apassy-relay/src/server/http.rs:280-373` |
| Relay routes | `/v1/teams` (edge), `/v1/items`, `/v1/grants`, `/v1/agents`, `/v1/audit` (approver, `after` and `limit`), `/v1/runs` (`Need::Agent`), `/v1/host/requests` (owner). | `crates/apassy-relay/src/server/http.rs:314,336,344,352,365,367,369`, `crates/apassy-relay/src/server/audit.rs:328` |
| App sync engine | `SyncTransport` trait; `RelaySync` holds the vault only for local steps; the head check 3 (`check_identity`, `signed_by_member`) trusts the relay's `signers`; the contract says stage 2 reads keys from a synced table. The iPhone core uses the same engine. | `src/sync/transport.rs:63`, `src/sync/relay.rs:21,723,880`, `docs/contracts/relay-sync-v1.md` §13 check 3, `ios/ApassyCore/src/core/sync.rs:1-3` |
| Fake relay | The engine tests run against an in-process fake relay of 2537 lines; the app crate's tests can use the real relay crate (the app crate depends on both). | `tests/common/fake_relay.rs`, `tests/relay_sync.rs`, `crates/apassy-app/Cargo.toml`, `.github/workflows/ci.yml:304` |
| Trust root pieces | `trusted_device` (uuid, kind `mac|iphone|watch`, `relay_devices` map team id → device number, `sign_key`, `answer_key`; synced LWW, a removal wins) and `relay_membership` (local; purposes `sync`, `questions`, `share`) exist since schema 19; `item_home` marks a mirror of a shared-vault credential. A Mac registers its own `trusted_device` row only when questions are on, not for relay sync alone. | `src/vault/schema19.rs:28-52`, `src/vault/trusted_device.rs:91-118,142,185`, `src/relay/membership.rs:202,214,328` |
| Shared vault tables | `shared_vault (uuid, name, color, relay_url, team_id, …)` and `item_share (item_id, shared_vault_uuid)` exist since schema 18, synced; the sidebar reads `app.ui.shared_vaults`, which nothing fills. No "way A" code exists. | `src/vault/schema18.rs:79-94`, `src/desktop/ui/sidebar.rs:21-37` |
| Merge rules | `LWW_TABLES` (4 tables, with their column lists), `LOCAL_TABLES` (37), `SYNCED_TABLES` (22); a coverage test fails for an unlisted table; `UPGRADABLE_SCHEMA` 25. | `src/vault/merge.rs:82,124,173,207` |
| Questions to approvers | `questions_to_approvers` is off ("Off until shared vaults"); the relay refuses `to: approvers` with 403 `not_routed`. | `crates/apassy-relay/src/config.rs:296-297`, `crates/apassy-relay/src/server/questions.rs:472`, `src/questions/envelope.rs:48` |
| Hosted relay | `team_vaults` off on the hosted image (410 `team_vaults_retired`); devices, sync, questions, feed, push stay. No export endpoint exists. | `crates/apassy-relay/src/config.rs:291-294`, `crates/apassy-relay/tests/server_team_vaults.rs` |
| Client TLS | Platform verifier, no pin; `RelayLink {url, team_id, device_id}` in the vault list. Pinned trust is 2C of the parallel plan. | `src/broker/http.rs:163-165`, `src/vaults.rs:144-150` |
| Tailscale | Only the system CLI at four fixed paths; Funnel on 8443; no tsnet or libtailscale anywhere in the tree. | `src/companion/hosts.rs:21-26`, `src/node/funnel.rs:30` |
| Lints and build | `unsafe_code = "forbid"` in the root crate, the relay, and the app crate; no crate has a `build.rs`; `cc` is in the lock file. | `Cargo.toml:147`, `crates/apassy-relay/Cargo.toml:54`, `crates/apassy-app/Cargo.toml`, `Cargo.lock:668` |
| CI | Relay and iPhone core tests with cargo-nextest in two slices on ubuntu-24.04, app crate tests in slice 1; `relay-image.yml` builds the Linux x86_64 CLI on ubuntu-24.04 and the Darwin arm64 CLI on macos-15. No Go step. | `.github/workflows/ci.yml:263-306`, `.github/workflows/relay-image.yml:68,122` |
| Receipts | "Received by <Mac>" is shown already (ADR 0022 moved receipts to stage 1). | `docs/operations/sync.md` §17.3 and the test `received_by_shows_the_receipt_of_the_other_mac` |
| Member run today | `apassy-team run -- <cmd>` requests a run, waits, and runs the child with the session environment (placeholders and base URLs). | `crates/apassy-relay/src/cli/exec.rs:1-5` |
| Node pairing | `docs/contracts/node-pairing-v1.md` does not exist yet (2C of the parallel plan). | `ls docs/contracts/` |

## Decisions

Sources: an ADR, or "chosen by this plan; the owner can change it".

### 1. The sync home (ADR 0037 D5, ADR 0022 stage 2)

- **A sync home is a team of purpose `sync` on a node.** The node's embedded relay serves relay-sync-v1 unchanged on its node listener; the tailnet reaches it through the TLS front (2B) with the pinned node certificate (2C). The directory of the node records the purpose and the vault id of the team (directory 1006). A node refuses a second sync team for one vault id. *ADR 0037 §5, D5.*
- **Devices are pre-enrolled from the vault.** The Mac that creates the sync team sends the public key of every live `trusted_device` of kind `mac`, `iphone`, or `linux` with the creation, and later with `POST /v1/devices` (owner device). A pre-enrolled device signs in with its existing key and gets its device number; no link, no safety words, no confirmation, because the vault's table already is the owner-confirmed list (each row was confirmed with the safety words and the owner check when the device joined, ADR 0019 §6). *Chosen by this plan; the owner can change it.*
- **The vault is the trust root for heads** (ADR 0022 stage 2, relay-sync-v1 §13 check 3): a head is accepted only when the signer's public key is the `sign_key` of a `trusted_device` row of the vault with `relay_devices[team id] == device number`. For a removed device (`deleted_at`), the relay's `signers[].last_version` stays as the upper bound of the versions it may have signed. The first merge of a Mac with no anchor (trust on first use, behind the owner's action) uses the relay's `signers` once and then checks that the signer is in the merged table; a mismatch shows "The relay served a copy signed by a device this vault does not know" and no further merge. Consequence: every device that relay-syncs registers its own row (today only questions do). *ADR 0022 §4 and stage 2.*
- **Moving the home is one action on one Mac.** "Sync home" in Settings › Vault › Sync lists: this Mac, each paired Linux node and Mac node, and "Apassy relay (hosted)". A move: pair with the node as a sync peer (2E), create the sync team there with the pre-enrolled devices, push version 1 (a fresh chain), write the synced one-row table `sync_home (origin, pin, team_id, moved_at, moved_by)` (vault schema 30), and update this Mac's membership and `sync.relay`. Each other device sees the new row at its next merge from the old home, signs in at the new origin with its existing key, adopts the new anchor by one fetch (its own changes are pushed again), and leaves the old team. The last device to leave gets "Delete the copy on the relay" (exists). *ADR 0037 "Migration", relay sync users; the mechanism is chosen by this plan.*
- **Default home:** the first always-on Linux node, else the first Mac. The app proposes the Linux node when it pairs. *ADR 0037 D5.*
- **A Mac that is the home of its own vault syncs in process:** its `RelayTransport` talks plain `http://127.0.0.1:<node port>`, which the existing loopback rule allows. *Chosen by this plan.*
- **The iPhone** keeps today's relay sync through the hosted relay until 2C lands on iOS; then it follows the `sync_home` row like a Mac (pre-enrolled by its `trusted_device` row). *ADR 0037 §5 "later, the iPhone can sync from a node too".*

### 2. The team host (ADR 0037 §5, §9; ADR 0019 §9; ADR 0018)

- **A team host is a node; the node is the key holder of every team it hosts.** Values of a hosted team are sealed in the team file with host-held item keys (SPEC §21, `hostkeys.rs` unchanged), and the item keys are in the **node key store**: a SQLCipher file `node/keys.db` under the node master key (Keychain on macOS; a systemd credential or a 0600 file on Linux). This replaces `keys.json` for node-hosted teams and gives "one host process for all teams of a machine" (ADR 0019 §9): the node's host loop serves every hosted team. A Linux team host needs no vault passphrase (3C becomes "not needed for hosting"; a sync home needs none either). *ADR 0037 §5 "the team host node, which is also the key holder"; the key store is chosen by this plan.*
- **Approvals stay on the owner's devices, through the host lane.** The node does not decide a team run. An **approver device** (a Mac of an owner or a manager of the team, running Apassy) long-polls `GET /v1/host/requests` of each team it approves for, runs its bouncer and, when the bouncer asks, the owner's question on the Mac and the iPhone (the owner's own questions lane, which works today), and answers with the new `POST /v1/host/requests/{id}/approve {reason}` or the existing `deny`. The node then opens the item keys from its key store and makes the session. On the owner's own Mac that hosts the team, this is the in-process host loop of today. `questions_to_approvers` stays off. *ADR 0037 §9 step 4; ADR 0026 §6 "a production use needs an owner or a manager"; the lane is chosen by this plan (the sealed questions lane would need a team question key that no device holds today).*
- **One home, a sealed copy on the host.** A credential keeps its home in the owner's vault. Sharing it into a shared vault sends its value sealed to the host's X25519 delivery key (`PUT /v1/items/{id}/value`), and every edit at the home sends it again; the host seals it under a fresh item key into the team file. Members and managers get mirrors (`item_home` rows) with the metadata (name, variable, hosts, environment), never a value. "Only the item's owner edits it." *ADR 0026 §6; the transport is chosen by this plan.*
- **Member runs go through the member's node.** The member's Mac registers one relay agent per local agent lazily (`team_agent`, vault schema 30, local) and requests runs for it; the member's own bouncer decides first (ADR 0018: stricter local rules), then the command runs once with the merged environment: personal items through the local proxy (ADR 0011), team items through the team host's `/p/` (way B). A Linux member uses `apassy team run` (3B keeps the `apassy-team` commands). *ADR 0018, ADR 0037 §9; chosen by this plan.*
- **The team host of a personal Mac listens only on its tailnet address** through the TLS front; sharing a personal Mac's node is refused in the UI with the ADR's warning until the embedded tailnet node exists (section 4). *ADR 0037 §9 "Never share a personal Mac".*
- **Roles, invites, joins, safety words, revocation:** unchanged from ADR 0019; the invite link carries the host origin and the pin (`https://<host>:8443/join#<team>.<code>&pin=<pin>`; the fragment never reaches a server). *ADR 0019 §6, ADR 0037 §4.*

### 3. The way A switch (ADR 0037 D10, section 10)

- Collection setting `delivery = host | member` ("Where members use these credentials": "On the team host (recommended)" or "On each member's device"), default `host`. Team schema 9. *ADR 0037 D10.*
- A member device registers an X25519 **delivery key** at join or link (new field, team schema 9); a way A release seals each value to it with the primitives of `hostkeys::seal_release` (X25519 ephemeral, HKDF-SHA256, AES-256-GCM, AAD = team id, run id, item uid). The sealed values ride in the run answer; the member's node opens them in memory for one run and uses its local proxy. *Chosen by this plan.*
- The confirmation text, the production warning, the badge "Values go to members' devices", the audit row `value_delivered {member, device, item, run}` (never the value), and the removal list with "Replace now" where a connector can rotate, else "Replace at the provider": as in the ADR. Changing the setting needs a fresh owner check (`OwnerAction::ChangeDelivery`). *ADR 0037 section 10.*
- Way C items (stage 6) show "Short-lived credentials" in both answers; this plan only reserves the label. *ADR 0037 D11.*

### 4. The embedded tailnet node (ADR 0037 D9)

- **How a Rust app embeds tsnet:** through `libtailscale` (github.com/tailscale/libtailscale), a Go package that builds `tailscale.com/tsnet` as a C archive (`go build -buildmode=c-archive` → `libtailscale.a` and `libtailscale.h`). Its C API is small: `tailscale_new`, `tailscale_set_dir`, `tailscale_set_hostname`, `tailscale_set_authkey`, `tailscale_set_control_url`, `tailscale_set_ephemeral`, `tailscale_set_logfd`, `tailscale_up`, `tailscale_listen(sd, "tcp", ":8443", &listener)`, `tailscale_accept(listener, &conn)`, `tailscale_dial`, `tailscale_loopback` (the LocalAPI address and credentials for WhoIs and status), `tailscale_close`, `tailscale_errmsg`. A connection is a file descriptor (one end of a socket pair that Go pumps to the tailnet TCP connection), so the Rust side wraps it as a `UnixStream` and hands it to the TLS front like any accepted socket. Userspace networking (gVisor netstack): no TUN device, no root, no NetworkExtension, outbound UDP for WireGuard and HTTPS to the control server and DERP only. *Chosen by this plan on the ADR's D9 (libtailscale through its C API).*
- **A new crate `crates/apassy-tailnet`** owns the FFI: `ffi.rs` is the one module in the workspace with `unsafe` (the crate sets `unsafe_code = "deny"` with `#[allow(unsafe_code)]` on that module only, reviewed by a judge panel); `lib.rs` is a safe API: `TailnetNode::up(TailnetOptions {dir, hostname, auth_key, control_url})`, `listen(port) -> Listener`, `Listener::accept() -> UnixStream`, `whois(addr) -> Peer`, `status() -> Status`, `Drop` closes. Feature `tailnet` of the app crate and the Linux node, off by default so that `cargo t` needs no Go. The root crate and the relay keep `forbid`.
- **Build in CI:** `build.rs` of the crate links a prebuilt archive from `APASSY_LIBTAILSCALE_DIR`, else builds it when `go` is on `PATH` (`CGO_ENABLED=1 go build -trimpath -buildmode=c-archive`), else fails with the message "the embedded tailnet needs Go or a prebuilt archive". A new job `tailnet-archive` in `ci.yml` (and the same steps in `release.yml` and `relay-image.yml`) runs `actions/setup-go` with Go pinned by exact version and checksum, builds the archive on `macos-15` (arm64, `CGO_CFLAGS=-mmacosx-version-min=<the app's target>`) and on `ubuntu-24.04` (x86_64, glibc 2.31 compatibility checked with `readelf` as the Linux CLI is), uploads it as an artifact with its SHA-256, and the build jobs download it. Reproducibility: `-trimpath`, a pinned `go.sum`, `GOFLAGS=-mod=readonly`; the SBOM lists the Go modules.
- **License:** Tailscale and libtailscale are BSD-3-Clause; the archive also contains wireguard-go (MIT), gVisor (Apache-2.0), and golang.org/x modules (BSD-3-Clause). Linking them into an Apache-2.0 app is allowed; the app bundle and the Linux tarball ship `THIRD-PARTY-LICENSES` with each notice (`go-licenses report` in CI), and the website's open-source page names them.
- **Use:** a team host runs one embedded node per machine, `apassy-team-<slug>`, that listens only on 8443 and is shared to members' Tailscale users; the Mac stays on its own tailnet with the system client. The auth key is an Apassy credential (a tagged, pre-authorized key from the owner's admin console), read once at `up`; the node state (`tailscaled.state`, with the node private key) lives in `node/tailnet/<slug>/`, mode 0600, named in the trust model. The share itself is made in the Tailscale admin console in this stage; the API call comes later (ADR §9 step 1).
- **Spike first (go or no-go), with the fallback named:** if the archive cannot be notarized, is unstable in process (signals, threads), or costs more than 40 MB in the app, the fallback is a Go helper binary `apassy-tailnet-helper` in `Contents/Helpers/` (signed with the app) that speaks to the node over a Unix socket and passes connections as file descriptors. Same safe API, no FFI. *The fallback is chosen by this plan.*

### 5. Migration (ADR 0037 D8 and "Migration")

- **Hosted teams:** the hosted relay gets `POST /v1/team/export {wrap_key}` for the key-holder device of a live owner: the relay copies the team file, rekeys the copy to a fresh random key, seals that key to the request's X25519 `wrap_key` (the primitives of `seal_release`), and answers with the sealed key and the file (streamed, as a snapshot download). On the node, `apassy team import <file>` (3B) and "Import a hosted team…" on the Mac open the file, import `keys.json` of the old key holder into the node key store, keep members, roles, collections, items, grants, and the audit, revoke every device (the old origin is gone), and print one device link per member for the new origin. Members join again with a link, which keeps their member row and grants. Deleting the hosted team files stays a separate step with the owner's confirmation. *ADR 0037 "Migration"; the export shape is chosen by this plan.*
- **Relay-sync vaults:** section 1 (one action; "Delete the copy on the relay" exists).
- **Shared folder vaults** (sync.md §11): they stay as the free way without a host. A note and the path "Move to a team host" (the owner creates the team on their host and shares the items; the others join) go into §11 and the Shared section's empty state.

### 6. ADR 0019 stage 5 and notifications

- **Secure Enclave device key (vault schema 33, separate):** `relay_membership.key_backing` (`vault` today, `secure_enclave` new), `key_pkcs8` nullable, `se_key_ref`. The native helper gets `se_key_create`, `se_key_sign`, `se_key_delete` (`SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave`, behind the data-protection Keychain that the signed app has). `DeviceKey` becomes a `Signer` trait with the two backings. New memberships on a signed app use the Secure Enclave; "Move this Mac's keys to the Secure Enclave" re-enrolls the Mac through the trust root (a new `trusted_device` row and pre-enrollment at each team, then the old device is removed). Development builds without the helper keep the vault key. *ADR 0019 stage 5; ADR 0022 open question 2.*
- **Notifications beyond the audit:** the Mac of an owner reads `GET /v1/audit?after=<seq>` of each team it owns once a minute while unlocked (the member long poll comes later) and posts a macOS notification with fixed text for `owner_device_added`, `member_joined`, `invite_reused`, `key_holder_moved`, `value_delivered`, `delivery_changed`, and `team_imported` (docs/operations/notifications.md gets the reasons). *ADR 0019 "notifications beyond the audit"; the mechanism is chosen by this plan.*

### 7. Numbers and contracts

| Thing | Value |
| --- | --- |
| Vault schema | 30: `sync_home` (synced, one row), `relay_membership.delivery_key_pkcs8` and `delivery_public` (local), `team_agent` (local), `delivered_value` (local, the member's own log), `shared_vault.pin`, `shared_vault.delivery`, `shared_vault.hosted_here` (synced LWW columns), `trusted_device.kind` gains `linux`. 33: the Secure Enclave backing. Merge order of vault migrations is number order (27 bouncer section, 28–29 the parallel plan, 30 this plan, 31–32 reserved, 33 this plan); a plan whose lower number is not ready either waits or asks the owner to reassign. |
| Relay team schema | 9: `device.delivery_key BLOB`, `device.added_by TEXT` (`join`, `link`, `pre_enrolled`, `node`), `collection.delivery TEXT NOT NULL DEFAULT 'host'`, `run.delivery TEXT`, `run.delivered BLOB` (purged with the session), `item.home_uuid TEXT`, `item.value_updated_at INTEGER`. Copy rule of SPEC §23.2 (`.pre-v9`), additive, with a documented way back. |
| Relay directory | 1006: `team.purpose TEXT NOT NULL DEFAULT 'team'` (`team`, `personal`, `sync`, `questions`), `team.hosted INTEGER NOT NULL DEFAULT 0` (this node holds the keys), `team.vault_id TEXT` (sync teams), unique index on `(purpose, vault_id)` for `sync`. |
| Contracts | New `docs/contracts/node-teams-v1.md` (the team host wire: creation on a node, invites with origin and pin, pre-enrolled devices, delivery keys, the host lane `approve`, way A delivery, export and import). `relay-sync-v1.md` gets a dated revision (additive: pre-enrolled devices, the `sync_home` row, the trust-root check 3). `node-pairing-v1.md` (owned by 2C) gets the roles `sync-peer` and `team-member` after 2C merges, by this plan's unit SH-C as the sole editor at that time. Relay `SPEC.md` sections: 31 team hosting on a node, 32 sync home and pre-enrolled devices, 33 way A delivery, 34 team export. |
| Audit actions (relay) | `device_pre_enrolled`, `item_value_updated`, `value_delivered`, `delivery_changed`, `team_exported`, `team_imported`, `run_approved` (host lane). None holds a value, a key, a nonce, or a token. |

## Work units

One editor per shared file (see the table after the units). Every unit adds tests that CI runs; the implementer writes them and does not run the heavy suites (house rules). Sizes: S days, M one to two weeks, L three weeks or more. Each unit returns the handoff of plan 0035 (`Unit`, `Base revision`, `Files changed`, `Interface`, `Tests added`, `Validation commands for the top-level agent`, `Deviations`, `Open questions`, `Risks seen`).

### T0 — Spike: the embedded tailnet node

- Purpose: go or no-go for libtailscale in the app (decision 4), with numbers.
- Owned files: proposed `crates/apassy-tailnet/**` (Cargo.toml, `build.rs`, `src/ffi.rs`, `src/lib.rs`, `go/` with `go.mod`, `go.sum`, a pinned libtailscale commit), proposed `.github/workflows/tailnet-spike.yml` (manual), proposed `docs/design/spike-tsnet.md`, root `Cargo.toml` (workspace member only).
- Interface: the safe API of decision 4; a bin `apassy-tailnet-spike` that joins a tailnet with an auth key from stdin, listens on 8443, and echoes.
- Checks and numbers in `spike-tsnet.md`: archive and binary sizes on both platforms; link flags on macOS (frameworks, `-lresolv`) and Linux (`-lpthread`, glibc 2.31); Go version pinned; the Go runtime's signal handlers next to Rust's (a SIGSEGV in Rust code still gives Rust's abort; a Go panic is contained); threads at idle; memory at idle; a notarized test build of the app with the archive through `release.yml` `provider-check` (a signed test build; needs no owner's hands); the `tailscale_loopback` LocalAPI answers `status` and `whois`; whether the login URL for a node without an auth key is readable from `status` (`AuthURL`); the state file's mode and content; the time to `up`; a second tailnet reaches the listener through a share (needs the owner step O1).
- Acceptance tests (`crates/apassy-tailnet/tests/`, feature `tailnet`, skipped without Go): `the_archive_links_and_a_node_object_is_made_and_dropped`, `up_without_a_network_fails_with_a_readable_error`, `a_listener_on_the_apassy_port_refuses_a_second_bind`; a Linux CI run of `tailnet-spike.yml` with two ephemeral auth keys (secrets) shows one TCP round trip across tailnets.
- Size: M. Depends on: nothing. Judge panel: 2× opus + 1× fable (FFI, signals, licensing).

### SH-R — Relay: sync teams, pre-enrolled devices, purposes

- Purpose: a node can be a sync home for a vault, with devices from the vault's trust root.
- Owned files: `crates/apassy-relay/src/server/directory.rs` (1006), `crates/apassy-relay/src/server/hub.rs` (`create_sync_team(vault_id, owner_device, pre_enrolled)`), `crates/apassy-relay/src/server/devices.rs` (`pre_enroll`, `added_by`), `crates/apassy-relay/src/server/store.rs` (team schema 9, shared with TH-R: SH-R owns it first and lands the whole migration; TH-R adds no DDL), `crates/apassy-relay/src/api.rs` (new types), `crates/apassy-relay/src/server/http.rs` (routes `POST /v1/devices` owner, `POST /v1/sync/home` edge with a pairing code), `crates/apassy-relay/src/embedded.rs` and `src/node/backend.rs` (`RunningNode::create_sync_home`, `pre_enroll_devices`, `sync_teams`), `crates/apassy-relay/docs/SPEC.md` §32, `crates/apassy-relay/tests/server_sync.rs`, new `crates/apassy-relay/tests/server_sync_home.rs`.
- Interface: `POST /v1/sync/home {code, vault_id, device_name, public_key, pre_enrolled: [{uuid, name, kind, public_key}]}` (edge; the pairing code of 2E, one use) → `{team_id, device_id, devices: [{uuid, device_id}]}`; `POST /v1/devices {uuid, name, kind, public_key}` (owner device) → `DeviceView` with `added_by: pre_enrolled`; a pre-enrolled device's first sign-in works with its key; `GET /v1/me` carries `team_purpose`. Directory 1006 and team schema 9 migrations with `.pre-v9` and the way back (`downgrade-schema-8`? no: the way back is the copy; document it).
- Acceptance tests: `a_sync_team_is_made_from_a_pairing_code_with_pre_enrolled_devices_and_no_links`, `a_pre_enrolled_device_signs_in_and_pushes_and_its_head_names_its_number`, `a_second_sync_team_for_one_vault_id_is_refused`, `pre_enrolling_a_key_that_is_live_is_a_conflict_and_a_removed_key_is_refused`, `the_directory_moves_1003_to_1006_and_a_team_file_7_to_9_with_copies`, `a_version_9_file_is_refused_by_the_schema_8_code_path` (unit), separation tests as in SPEC §24.9 for the new routes.
- Size: M. Depends on: nothing (the embedded mode exists). Judge: 1× opus.

### SH-V — Vault: schema 30, the trust root for heads, self-registration

- Purpose: the vault holds what the sync home and the teams need, and every relay-sync Mac is a trusted device of its vault.
- Owned files: proposed `src/vault/schema30.rs`, `src/vault/mod.rs` (schema bump, `LOCAL_TABLES`, `SYNCED_TABLES`), `src/vault/merge.rs` (`LWW_TABLES` columns of `shared_vault`, `sync_home`), `src/vault/trusted_device.rs` (`kind linux`, `signer_key(team_id, device_number) -> Option<(Vec<u8>, removed: bool)>`, delivery key on `RelayMembership`), proposed `src/vault/sync_home.rs`, proposed `src/vault/team_agent.rs`, `src/relay/membership.rs` (`register_this_device` for every membership purpose, at sync enable and at join), `tests/vault_migration.rs`, `tests/trusted_devices.rs`, `tests/folder_sync.rs` (the table coverage test).
- Interface: `Vault::sync_home() -> Option<SyncHome>`, `set_sync_home(SyncHome)`; `Vault::team_agents(team)`, `add_team_agent`, `remove_team_agent`; `Vault::delivered_values(team)`; `RelayMembership { delivery_key_pkcs8: Option<Zeroizing<Vec<u8>>>, delivery_public: Option<Vec<u8>>, … }`; `Vault::signer_key`.
- Acceptance tests: `version_30_migration_adds_the_tables_and_is_atomic`, `a_failed_migration_from_26_keeps_26_and_the_data` (pattern of `a_failed_migration_from_version_13_keeps_the_old_version_and_data`), `sync_home_syncs_last_writer_wins_and_team_agents_and_delivered_values_stay_local`, `a_linux_device_row_is_valid_and_a_watch_row_still_is`, `turning_relay_sync_on_registers_this_mac_as_a_trusted_device` (in `tests/relay_sync.rs`, written here, run with SH-C), `signer_key_names_a_removed_device_as_removed`.
- Size: M. Depends on: vault migrations 27 to 29 merged first (number order). Judge panel: 2× opus + 1× fable (migration, merge rules).

### SH-C — Sync client: the trust root, the move of the home, Settings

- Purpose: the Mac checks heads against its vault, moves its sync home in one action, and follows a move made elsewhere.
- Owned files: `src/sync/relay.rs` (check 3 against `Vault::signer_key`; `RelaySync::move_home(target)`, `follow_home()`; the in-process loopback origin), `src/sync/relay/devices.rs`, `src/sync/relay/member.rs`, `src/sync/state.rs` (format 4: `origin`, `pin`), `src/sync/relay_http.rs` (pinned trust from 2C, used not changed), `src/sync/mod.rs`, `src/desktop/sync_worker.rs` (a `follow_home` step after a merge that brought a new `sync_home` row), `src/desktop/ui/sync/relay.rs` (the "Sync home" picker and its sheet), `src/desktop/ui/sync_tests.rs`, `src/vaults.rs` (`RelayLink.pin` if 2C did not add it; else untouched), `tests/relay_sync.rs`, `tests/common/fake_relay.rs` (pre-enrolled devices, `sync_home`), `docs/contracts/relay-sync-v1.md` (dated revision), `docs/contracts/node-pairing-v1.md` (the two roles, after 2C), proposed `crates/apassy-app/tests/sync_home.rs` (the real relay in process).
- Interface: `RelaySync::move_home(SyncHomeTarget {origin, pin, pairing_code}) -> MoveReport`; `RelaySync::follow_home(&SyncHome) -> FollowReport`; `UiStatus::HomeMoved`; texts: "Sync home: Mac mini (this Mac)", "Moving the sync home to <node>…", "<vault> now syncs through <node>. Your other Macs follow at their next sync."
- Acceptance tests: `a_head_signed_by_a_key_outside_the_vaults_trusted_devices_is_refused_even_when_the_relay_lists_it` (the ADR 0022 stage 2 property), `a_removed_devices_old_heads_still_verify_up_to_its_last_version`, `the_first_use_without_an_anchor_checks_the_signer_after_the_merge`, `moving_the_home_writes_the_synced_row_pushes_version_one_and_leaves_the_old_team`, `the_second_mac_follows_the_home_at_its_next_sync_without_a_link`, `a_mac_that_syncs_in_process_uses_the_loopback_origin`, `two_macs_and_a_linux_home_converge_after_one_mac_misses_1500_versions` (the stage acceptance, synthetic: the real relay in `crates/apassy-app/tests/sync_home.rs`, chain paging exercised), `the_last_mac_to_leave_can_delete_the_relay_copy`, `the_sync_home_picker_lists_this_mac_paired_nodes_and_the_hosted_relay` (UI). Also one push of 64 MiB against the in-process relay in the Linux CI slice (`a_64_mib_push_passes_the_front_and_a_byte_more_is_refused`, the front from 2B when merged; without it, the loopback listener).
- Size: L. Depends on: SH-R, SH-V; 2C for the tailnet path (the in-process and loopback tests do not need it); 2E for the pairing code.
- Judge panel: 2× opus + 1× fable (the trust root and the move).

### SH-N — The node as a sync home (Mac and Linux)

- Purpose: the node serves sync teams whenever it runs, shows them, and the Linux node is the default home.
- Owned files: proposed `src/node/sync_home.rs`, `src/node/mod.rs` (start conditions: the node also runs when the vault has sync teams or hosted teams; shared with 2D of the parallel plan: SH-N lands after 2D), `src/node/tests.rs`, the `apassy status` and `apassy doctor` output of 3B (a section "Sync homes: <vault name> v<version>, received by …"), `docs/operations/sync.md` §17 (a new §18 "Your own node as the sync home").
- Interface: `Node::sync_homes() -> Vec<SyncHomeView {team_id, vault_name, version, receipts}>`; `apassy status` prints them; `apassy pair --role sync-peer` (3B) prints the pairing QR for a Mac.
- Acceptance tests: `the_node_runs_for_a_vault_with_a_sync_team_and_no_cloud_agent`, `a_restart_of_the_node_opens_its_sync_teams_again` (relay test exists for personal teams; extend), `status_lists_each_sync_home_with_its_version_and_receipts`.
- Size: M. Depends on: SH-R, 2D, 3B (for the Linux commands; the Mac part lands first).
- Judge: 1× opus.

### SH-I — The iPhone follows the sync home

- Purpose: the iPhone syncs from the node once it can pin.
- Owned files: `ios/ApassyCore/src/core/sync.rs`, `ios/ApassyCore/src/core/config.rs`, `ios/ApassyCore/src/core/join.rs` (the pre-enrolled sign-in), `docs/contracts/ios-core-v1.md` (one section), the iOS Settings row "Sync: via <node>".
- Acceptance tests (`ios/ApassyCore` tests, fake relay of the core): `the_iphone_signs_in_at_the_new_home_with_its_existing_key_after_the_row_arrives`, `without_a_pin_the_iphone_keeps_the_old_home_and_says_so`.
- Size: S–M. Depends on: SH-V, SH-C, 2C on iOS (2G). Judge: 1× opus.

### TH-R — Relay: teams hosted on a node (keys in the node, the host lane `approve`)

- Purpose: a node hosts teams whose keys it holds; approvers decide over the host lane; values arrive sealed to the host.
- Owned files: proposed `crates/apassy-relay/src/server/nodekeys.rs` (the key store `node/keys.db`: `item_key(team_id, uid, key, name, env_name, environment, hosts, risk, scope, reversibility, created_at)`, the entries of SPEC §15 `keys.json`), `crates/apassy-relay/src/server/host.rs` (`approve_from_store`, `embedded_requests` for hosted teams, `deliver_values` for way A), `crates/apassy-relay/src/server/admin.rs` (`item_value_put`: open the envelope sealed to the host delivery key, make the item key, seal the value, store the key; `collection_delivery_put`), `crates/apassy-relay/src/server/decide.rs` (`run.delivery` copied from the collection), `crates/apassy-relay/src/server/sessions.rs` (purge `run.delivered` with the session), `crates/apassy-relay/src/hostkeys.rs` (`seal_to_key`, `open_with_key` for X25519 static keys; `delivery_aad`), `crates/apassy-relay/src/server/http.rs` (routes: `PUT /v1/items/{id}/value`, `PUT /v1/collections/{id}/delivery`, `POST /v1/host/requests/{id}/approve`, `GET /v1/host/delivery-key`), `crates/apassy-relay/src/embedded.rs` and `src/node/backend.rs` (`create_hosted_team`, `host_delivery_key`, `approve`, `hosted_pending`), `crates/apassy-relay/docs/SPEC.md` §31 and §33, new `crates/apassy-relay/tests/server_hosted_teams.rs`, `crates/apassy-relay/tests/server_host.rs`.
- Interface: the host lane for a hosted team accepts the devices of live owners and managers ("approver devices"); `POST /v1/host/requests/{id}/approve {reason}` → the run becomes `ready` with the session (way B) or `ready` with `delivered` (way A); `GET /v1/host/delivery-key` → the node's X25519 public key (signed by the node device key); `PUT /v1/items/{id}/value {sealed, host_key, nonce}`; `PUT /v1/collections/{id}/delivery {delivery}` (owner, writes `delivery_changed`); `GET /v1/runs/{id}` gains `delivered: [{uid, sealed, host_key, nonce}]` for way A; `authorize_host` for a hosted team: approver devices, else 403 `forbidden`; the HTTP `release` with `sealed_keys` on a hosted team is 409 `keys_on_node`.
- Acceptance tests: `an_approver_device_approves_a_hosted_run_and_the_node_opens_the_keys_from_its_store`, `a_member_device_cannot_approve_and_gets_forbidden`, `a_value_put_sealed_to_the_host_is_stored_sealed_under_a_fresh_item_key_and_the_store_has_the_key`, `a_value_put_sealed_to_another_key_is_refused_and_nothing_is_stored`, `a_way_a_approval_delivers_sealed_values_to_the_members_delivery_key_and_no_session_is_made`, `delivered_values_are_purged_with_the_run`, `the_release_with_sealed_keys_on_a_hosted_team_is_keys_on_node`, `a_hosted_team_file_on_disk_holds_no_value_and_the_key_store_holds_no_value`, separation: a token of team A reaches nothing of team B's key store.
- Size: L. Depends on: SH-R (schema 9 DDL lands there). Judge panel: 2× opus + 1× fable (keys, sealing, authorization).

### TH-N — Node: the team host service (all teams of the machine)

- Purpose: the node hosts teams, approves in process when the owner's Mac is the host, and serves as the approver device for teams hosted elsewhere.
- Owned files: proposed `src/node/teams.rs` (hosted teams: create, open, invite, joins and confirms in process for the owner on the host Mac; the host loop over every hosted team), `src/node/host.rs` (generalize: a pending run of a hosted team goes through the broker's evaluation with the team's items as context, then `approve`; a run of the personal team stays as today), proposed `src/node/approver.rs` (the approver loop for teams this Mac approves for but does not host: `GET /v1/host/requests` long polls over `RelayMember`, the bouncer, the owner's question, `approve` or `deny`), `src/node/mod.rs` (start conditions, after SH-N), `src/node/tests.rs`, `src/broker/run.rs` (one hook: `evaluate_team(ctx, TeamContext)` next to `evaluate_cloud`; TH-N is the sole editor of `run.rs` in its wave), `docs/operations/` new `team-host.md`.
- Interface: `Node::hosted_teams()`, `Node::create_hosted_team(name) -> TeamId`, `Node::invite(team, role, collections, name) -> InviteLink`, `Node::pending_joins(team)`, `Node::confirm_join(team, id, words)` (behind `OwnerAction::ConfirmTeamJoin`), `Node::approver_teams()`; `apassy team create|invite|joins|confirm|members|collections` (3B) call the same code on Linux.
- Acceptance tests: `a_hosted_run_on_the_owners_mac_is_decided_in_process_and_the_value_never_leaves_the_node_store_except_into_the_session`, `the_approver_loop_asks_the_owner_and_answers_the_remote_host` (two nodes in process: a host and an approver, the real relay), `a_run_without_an_approver_online_times_out_and_is_denied_with_no_one_at_the_host`, `one_host_loop_serves_three_hosted_teams_and_the_personal_team`, `a_confirm_needs_the_owner_check_and_the_same_safety_words`.
- Size: L. Depends on: TH-R, SH-N, 2D. Judge panel: 2× opus + 1× fable.

### TH-M — The Mac app: shared vaults (owner and member sides)

- Purpose: the Shared section works end to end for the owner (share, invite, members, collections) and for a member (join, see mirrors, run).
- Owned files: proposed `src/vault/shared_vault.rs` (the API over `shared_vault`, `item_share`, `item_home`, `team_agent`), proposed `src/desktop/ui/shared.rs` (the Shared rows, "New shared vault…", "Invite…", "Members…", "Collections…", the credential "Share in…" picker, "From you" and "From others", the badge of a way A collection, the removal sheet with the delivered list), `src/desktop/ui/sidebar.rs` (fill `shared_vaults`), `src/desktop/ui/items.rs` (share rows and the badge; one editor at a time with the bouncer-section plan: TH-M lands after it), proposed `src/relay/team_client.rs` (the member API over `RelayMember`: items, collections, runs, agents, invites, joins, the value put sealed to the host), proposed `src/broker/team_run.rs` (a run with team items: request on each host, wait, merge the environment, way B base URLs or way A opened values through the local proxy), `src/broker/run.rs` (the call into `team_run`; after TH-N's hook merges), `docs/design/shared-vaults-mockup.html` (first; the owner's rule: screenshots next to the mockup before any release claim), `docs/contracts/node-teams-v1.md` (the app side), `tests/` new `shared_vaults.rs`.
- Interface: `Vault::share_item(item, shared_vault)`, `unshare_item`, `shared_vault_items(uuid) -> {from_you, from_others}`; `TeamClient::put_value(item, value)` after each edit of a shared credential (the sync worker's local-change step calls it); `broker::team_run::run(ctx, request) -> Outcome`.
- Acceptance tests: `sharing_a_credential_sends_its_value_sealed_to_the_host_and_an_edit_sends_it_again`, `a_member_sees_a_mirror_with_metadata_and_no_value_and_cannot_edit_it`, `a_members_agent_runs_a_command_whose_team_item_goes_through_the_hosts_proxy_and_whose_personal_item_goes_through_the_local_proxy` (the real relay in `crates/apassy-app/tests/`), `a_way_a_run_opens_the_delivered_value_in_memory_and_logs_it_locally`, `a_removed_member_gets_forbidden_at_the_next_request_and_keeps_only_what_was_delivered`, `the_shared_section_matches_the_mockup` (the UI tests of `src/desktop/ui/*_tests.rs`), `the_invite_link_carries_the_origin_and_the_pin_in_the_fragment`.
- Size: L. Depends on: TH-R, TH-N, SH-V, 2C, 2E. Judge panel: 2× opus + 1× fable.

### TH-A — The way A switch

- Purpose: the collection setting, its facts, the audit, and the removal list (decision 3).
- Owned files: `src/desktop/ui/shared.rs` (the setting sheet; TH-A edits it after TH-M merges), `src/broker/approvals/owner_auth.rs` (`OwnerAction::ChangeDelivery {team, collection, delivery, count, production}`), `src/desktop/owner_check.rs` (the prompt text), `src/vault/shared_vault.rs` (`delivered_values_of_member`), `docs/operations/team-host.md` (the section "Where members use these credentials"), `tests/owner_auth.rs`.
- Acceptance tests: `turning_on_member_delivery_shows_the_count_the_production_warning_and_needs_the_owner_check`, `the_badge_shows_on_the_collection_and_on_each_item`, `removing_a_member_lists_every_credential_delivered_to_them_with_replace_now_where_a_connector_rotates`, `the_audit_row_names_member_device_item_and_run_and_never_the_value` (relay side, in TH-R's test file, written here).
- Size: M. Depends on: TH-R, TH-M. Judge: 1× opus.

### TH-T — The embedded tailnet node for team hosts

- Purpose: a team host is its own tailnet machine that exposes only the Apassy port (decision 4), after T0 says go.
- Owned files: `crates/apassy-tailnet/**` (productize the spike), the TLS front's listener source (`src/net/tls_front.rs` of 2B: one trait `AcceptSource` added by TH-T after 2B merges), proposed `src/node/tailnet.rs` (up, down, status, whois refusal of peers outside the share), `src/desktop/ui/shared.rs` ("Team host network" picker: "This Mac's Tailscale (tailnet members only)" or "Its own tailnet machine apassy-team-<slug>", the auth key field as an Apassy credential), `.github/workflows/ci.yml` (job `tailnet-archive`), `.github/workflows/release.yml` and `relay-image.yml` (download the archive), `scripts/build-app.sh` (bundle `THIRD-PARTY-LICENSES`), `docs/security/trust-model.md` (the tailnet state file, the control server), `docs/operations/team-host.md` (the share flow in the admin console, the grant for port 8443, Headscale).
- Interface: `TailnetNode` of decision 4; `Node::tailnet_status()`; the invite link of a team on an embedded node names `https://apassy-team-<slug>.<tailnet>.ts.net:8443`.
- Acceptance tests: the T0 tests, plus `a_peer_outside_the_share_is_refused_by_whois_before_tls` (unit with a fake LocalAPI), `the_team_host_listens_on_the_apassy_port_only` (a scan of the embedded node's ports in the Linux job), and the two-tailnet script `scripts/tests/two-tailnets.sh` (nightly or manual, two auth keys and two API keys as secrets): node A in tailnet A hosts a team, the script shares it to tailnet B's user through the API (`device-invites` and `accept`), node B joins the team, B's agent runs way B on A, B holds placeholders only, revoking the share cuts the next request.
- Size: L. Depends on: T0 (go), 2B, TH-N. Judge panel: 2× opus + 1× fable.

### TH-X — Migration of hosted teams

- Purpose: a hosted team moves to a node (decision 5).
- Owned files: `crates/apassy-relay/src/server/admin.rs` (`team_export`), `crates/apassy-relay/src/server/http.rs` (route `POST /v1/team/export`, streamed like a snapshot download, hosted relay only when `team_vaults` is off is still allowed: the export reads, it does not serve team content), `crates/apassy-relay/src/server/rollback.rs` or a new `crates/apassy-relay/src/server/import.rs` (`import_team_file`), `crates/apassy-relay/src/cli/commands.rs` (`apassy team export` on the key holder's machine: makes the X25519 wrap key, downloads, opens, writes `<team>.export` with the file and `keys.json`), the node command `apassy team import <path>` (3B's command set; TH-X owns the subcommand), the Mac sheet "Import a hosted team…" (`src/desktop/ui/shared.rs`, after TH-M), `crates/apassy-relay/docs/SPEC.md` §34, `crates/apassy-relay/deploy/worker/src/index.ts` (the edge Worker: the body and download limits for the export route), new `crates/apassy-relay/tests/server_export.rs`.
- Interface: `POST /v1/team/export {wrap_key}` (key-holder device of a live owner) → `200`, `application/octet-stream`, headers `X-Apassy-Export-Key` (sealed file key, b64u), `X-Apassy-Export-Host-Key`, `X-Apassy-Export-Nonce`; audit `team_exported`. Import: members, roles, collections, items (sealed), grants, audit kept; devices revoked; `team_imported` written; one link per member printed; `keys.json` entries moved into the node key store.
- Acceptance tests: `the_key_holder_exports_a_team_and_another_owner_device_gets_forbidden`, `the_export_opens_only_with_the_wrap_key_and_holds_no_item_key`, `an_import_keeps_members_and_grants_revokes_devices_and_opens_every_item_with_the_imported_keys`, `a_member_joins_the_imported_team_with_a_link_and_keeps_their_grants`, `the_hosted_image_serves_the_export_with_team_vaults_off`.
- Size: M. Depends on: TH-R, TH-N, 3B. A deploy of the hosted relay (the house rule: confirm the image digest and the backup before the compose change, as the 0.5.16 plan's G4). Judge panel: 2× opus + 1× fable.

### TH-E — Owner notifications beyond the audit

- Owned files: proposed `src/relay/team_events.rs` (the audit reader, once a minute, per owned team), `src/desktop/notifications.rs` or the notifier glue used by sync health (`src/desktop/sync_health.rs` pattern), `docs/operations/notifications.md` (the reasons), `tests/notifications.rs`.
- Acceptance tests: `a_member_join_on_the_host_notifies_the_owner_once_with_fixed_text`, `a_value_delivery_notifies_and_names_no_value`, `the_notifier_takes_only_the_listed_reasons`.
- Size: S. Depends on: TH-M. Judge: 1× opus.

### SE — The Secure Enclave device key (vault schema 33)

- Owned files: proposed `src/vault/schema33.rs`, `src/vault/mod.rs` (bump, after 30 to 32 merged), `src/vault/trusted_device.rs` (`key_backing`), `src/sync/relay_crypto.rs` (`Signer` trait; `DeviceKey::Vault`, `DeviceKey::SecureEnclave`), `src/native/mod.rs` (`se_key_create`, `se_key_sign`, `se_key_delete`) and the Swift helper (`native/` sources of the signed helper), `src/relay/membership.rs` (new memberships prefer the Secure Enclave; "Move this Mac's keys to the Secure Enclave" re-enrolls through the trust root), `src/desktop/ui/settings.rs` (Security: one row with the state and the button), `tests/vault_migration.rs`, `tests/native_helper.rs`.
- Acceptance tests: `version_33_migration_keeps_vault_keys_and_marks_them_vault`, `a_membership_with_a_secure_enclave_key_signs_a_head_and_a_sign_in_through_the_helper` (the helper in tests signs with a software key behind the same IPC), `moving_the_keys_adds_a_new_trusted_device_pre_enrolls_it_and_removes_the_old_one`, `without_the_helper_new_memberships_keep_the_vault_key_and_the_row_says_so`.
- Size: M. Depends on: SH-V, SH-C, SH-R (pre-enrollment). The real Secure Enclave needs the signed app on the owner's Mac (owner step O4). Judge panel: 2× opus + 1× fable.

### DOC — Documents

- Owned files: `docs/operations/sync.md` (§11 the team host path; §18 sync home), `docs/operations/team-host.md` (new; shared with TH-N, TH-T, TH-A: DOC is the final editor), `docs/security/trust-model.md` (team host, node key store, tailnet state, the export), `docs/adr/0018…`, `0019…`, `0022…`, `0026…`, `0037…` status lines, `CHANGELOG.md` Unreleased (the top-level agent owns it; DOC returns lines), the website changelog (derived).
- Size: S. Depends on: the units of each release. Worker (sonnet, high) with a checklist; the top-level agent reviews.

### REL — Integration and release

- The top-level agent: one combined judge panel (2× opus + 1× fable) over each release's diff (keys, sealing, authorization, migrations, the trust root, FFI), `python3 scripts/check-release-versions.py` with Python 3.12, the six-component bump, and the live checks of AGENTS.md.

## One editor per shared file

| File | Order of editors |
| --- | --- |
| `src/vault/mod.rs`, `src/vault/merge.rs` | 27 (bouncer section) → 28–29 (parallel plan) → SH-V (30) → SE (33) |
| `crates/apassy-relay/src/server/store.rs`, `directory.rs` | 1004 (bouncer section) → 8, 1005 (parallel plan) → SH-R (9, 1006); TH-R adds no DDL |
| `crates/apassy-relay/src/server/http.rs` | SH-R → TH-R → TH-X (each appends routes; rebase in that order) |
| `crates/apassy-relay/src/embedded.rs`, `src/node/backend.rs` | SH-R → TH-R |
| `crates/apassy-relay/docs/SPEC.md` | each unit appends its own section (31 TH-R, 32 SH-R, 33 TH-R, 34 TH-X) in merge order |
| `src/node/mod.rs`, `src/node/host.rs` | 2D (parallel plan) → SH-N → TH-N |
| `src/sync/**`, `tests/relay_sync.rs`, `tests/common/fake_relay.rs` | 2C (parallel plan) → SH-C |
| `src/relay/membership.rs` | SH-V → SE |
| `src/broker/run.rs` | the 0.5.16 fixes and the bouncer-section plan → TH-N (one hook) → TH-M (one call) |
| `src/desktop/ui/shared.rs` (new) | TH-M → TH-A → TH-T → TH-X |
| `src/desktop/ui/sidebar.rs`, `src/desktop/ui/items.rs` | the bouncer-section plan → TH-M |
| `docs/contracts/node-pairing-v1.md` | 2C → SH-C |
| `docs/contracts/relay-sync-v1.md` | SH-C only |
| `docs/contracts/node-teams-v1.md` (new) | TH-R writes the relay side first → TH-M adds the app side |
| `.github/workflows/ci.yml` | T0 (a manual spike workflow only) → TH-T (the archive job) |
| `CHANGELOG.md` | the top-level agent |

## Execution with subagents

Roles, models, and efforts (house convention; set both explicitly):

| Unit | agentType | model | effort | Judge |
| --- | --- | --- | --- | --- |
| T0 | implementer (spike) + ops (CI job) | opus | high | 2× opus + 1× fable |
| SH-R, SH-V, SH-N, SH-I, TH-A, TH-E | implementer | opus | high | 1× opus (SH-V: panel) |
| SH-C, TH-R, TH-N, TH-M, TH-T, TH-X, SE | implementer | opus | high | 2× opus + 1× fable |
| DOC | worker | sonnet | high | top-level agent |
| Two-tailnet script, devbox runs | ops | opus | high | returns a plan; paid runs need the owner's go |

Waves (at most three implementers on this Mac at once; judges run after they return; more parallelism only in remote sessions):

| Wave | Units in parallel | Needs |
| --- | --- | --- |
| 1 | T0, SH-R, SH-V | vault migrations 27–29 merged (else SH-V waits and the wave takes TH-R's relay-only part) |
| 2 | SH-C, TH-R, SH-N | wave 1; 2C and 2D of the parallel plan for the tailnet path and the lifecycle |
| 3 | TH-N, TH-X (relay side), SH-I | wave 2; 2G and 3B |
| 4 | TH-M (mockup first), TH-A, TH-T | wave 3; T0 said go; 2B, 2E |
| 5 | TH-X (node and Mac side), TH-E, SE | wave 4 |
| 6 | DOC, REL | all |

## Release grouping

Each release bumps all six components (AGENTS.md). The relay goes first when a release changes it.

| Release | Units | What the owner gets | Stage acceptance covered |
| --- | --- | --- | --- |
| R1 (the first after 0.5.16 and the parallel plan's 2C/2D) | SH-R, SH-V, SH-C, SH-N, T0 (report only), the export endpoint of TH-X (relay side, deployed) | A Mac or a Linux node as the sync home; the move in one action; the vault as the trust root; the 64 MiB check | "Two Macs and a Linux sync home converge after one Mac is offline for a day" (synthetic in CI; the physical run is O3) |
| R2 | TH-R, TH-N, TH-M, TH-A, TH-E, SH-I | Shared vaults with a team host on the owner's Mac or on a Linux node over the system Tailscale (members in the owner's tailnet, or a shared dedicated Linux host as D9 allows until then); way A switch; notifications; the iPhone follows the home | Members in one tailnet; the way A facts |
| R3 | TH-T, TH-X (node and Mac side), SE, DOC | The embedded tailnet node and cross-tailnet sharing; import of hosted teams; Secure Enclave keys | "Konrad's agent, in another tailnet, runs way B on Rafal's team host" (synthetic: the two-tailnet script; physical: O3) |

## Owner-needed steps

The plan keeps the owner's hands out of the build. These remain:

| Id | Step | Why it needs the owner | Synthetic alternative |
| --- | --- | --- | --- |
| O1 | A second Tailscale tailnet (a second account) for the two-tailnet test, two API keys (one per tailnet, with device and invite scopes) and two ephemeral, tagged auth keys, stored as GitHub secrets (`TS_A_API`, `TS_A_AUTH`, `TS_B_API`, `TS_B_AUTH`) or in Apassy for devbox runs; and the ACL change in the owner's tailnet (`tag:apassy-team`, port 8443 to `autogroup:shared`), shown as a diff before it is applied | Account creation, MFA, and a tailnet policy change are the owner's | With the secrets in place, `scripts/tests/two-tailnets.sh` runs nightly on ubuntu-24.04 (two embedded nodes, one share through the API) and stands in for "Konrad's agent in another tailnet"; CI needs no second person |
| O2 | Deploy of the hosted relay with the export endpoint (R1) and of each later relay version | The house rule: the image digest and the backup are confirmed before the compose change on `ottervibe` | None; the relay tests cover the endpoint |
| O3 | The physical acceptance of each release on the owner's devices: Mac mini and MacBook Pro as sync peers with `devbox-x86` as the home (a paid devbox hour, the owner's go), an iPhone over the tailnet, a member Mac in the second tailnet | Real hardware and the owner's accounts | The synthetic tests of SH-C, TH-N, TH-T |
| O4 | One Touch ID on each Mac when "Move this Mac's keys to the Secure Enclave" runs (SE) | The Secure Enclave is per device | Development builds keep the vault key; the test helper signs with a software key |
| O5 | Deleting the hosted team files after an export (D8) | The ADR makes it a separate confirmed step | — |
| O6 | Store and TestFlight publication at each release, and the Chrome Web Store submission | The house rule for publication | — |
| O7 | The Tailscale device share for a real team host (admin console) until the API call lands | The console is the owner's | The two-tailnet script uses the API with O1's keys |

Not needed from the owner: approving intermediate steps, the notarized test build of T0 (`release.yml` `provider-check`, triggered by the top-level agent), the relay image builds, the CI secrets other than O1.

## Risks

| Risk | Mitigation |
| --- | --- |
| The Go runtime in the app process: signal handlers, threads at idle, crash reports, a 30 MB larger binary | T0 measures; the helper-binary fallback of decision 4; feature `tailnet` off by default; one crate holds the FFI |
| `unsafe` enters the workspace | Only `crates/apassy-tailnet/src/ffi.rs`; the root, the relay, and the app crate keep `forbid`; a judge panel reads every unsafe block |
| Schema numbers across three plans (vault 27–33, team 8–9, directory 1004–1006) | Merge in number order; a unit whose lower number is late waits or asks the owner to reassign; `unlock_migrates_each_earlier_schema_version_to_the_current_one` guards the chain |
| The parallel plan's 2B, 2C, 2D, 2E, 3B land late | SH-R, SH-V, TH-R, and the in-process tests need none of them; the tailnet path and the Linux commands wait |
| Host availability: every run of every member needs the host and an approver online | Recommend a Linux host; the approver loop runs on every owner's and manager's Mac; a run without an approver times out with a clear reason |
| A shared personal Mac exposes every port | The UI refuses to share a personal node; the embedded node of TH-T listens on 8443 only; the docs name the grant |
| The node key store holds item keys under a key on the same machine | The trust model says so (the host is the key holder, ADR 0037 §9); root on the host reads them as it does today on the hosted relay; TPM2 sealing on Linux is a later step |
| Pre-enrollment trusts the vault's device table | Each row was confirmed with the safety words and the owner check when it joined; a removed row never comes back (tombstone wins); the trust-root check refuses any signer outside the table |
| `run.rs` is shared with the 0.5.16 fixes and the bouncer-section plan | One editor per wave; TH-N adds one hook, TH-M one call |
| The 64 MiB push through Cloudflare is still unverified on the live relay | SH-C's in-process check covers the node path; the hosted path is one synthetic push by ops with the owner's team code (plans.md §4.1 removes the code later) |
| The way A value on a member's device is a copy the member can keep | D10 accepts it; the facts, the badge, the audit, and the removal list are the mitigation |
| The export endpoint on the hosted relay is a new route on production | Key-holder owner device only; the file is useless without the wrap key; audit `team_exported`; O2 |

## Not verified in the code

- libtailscale: the exact C function list, the link flags on macOS (frameworks, `-lresolv`) and Linux, the archive size, whether `tailscale_loopback` and the LocalAPI expose `AuthURL` for a login without an auth key, and the Go version that the pinned libtailscale commit needs. T0 verifies all of it.
- The Tailscale API for device invites (`POST /api/v2/device/{deviceID}/device-invites`) and their acceptance (`POST /api/v2/device-invites/{inviteCode}/accept`), their scopes, and that a shared node answers on a port that the sharing tailnet's grant allows. O1 and the two-tailnet script verify it.
- Whether `Hub::create_team` and `make_team_file_with_device` can take pre-enrolled devices in one transaction without a rebuild of `joins.rs` (SH-R reads `hub.rs:74-160` first).
- Whether the session environment that `apassy-team run` builds (SPEC §11) can be merged with the local proxy's environment of ADR 0011 in one child without a variable collision (TH-M reads `src/broker/run.rs` `read_secrets` and `crates/apassy-relay/src/cli/exec.rs` first).
- The `trusted_device.kind` CHECK constraint: schema 24 added `watch`; schema 30 must use the same rebuild or `CHECK` pattern (SH-V reads `src/vault/schema24.rs`).
- The iPhone's relay key: whether `ios/ApassyCore/src/core/join.rs` keeps it in the vault like the Mac (SH-I reads it first; SE leaves the iPhone unchanged).
- The Swift helper's Secure Enclave API through the existing IPC of `src/native/mod.rs` (SE reads `keychain_store` first).
- Whether `GET /v1/audit` on the hosted relay is reachable for Connect teams with the current limits (TH-E needs it only on nodes).
- The window-close behavior of the Mac app (open check 1 of the parent plan; the parallel plan's 2D owns it; a team host on a Mac needs "keep running").
