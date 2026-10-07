# ADR 0022: Vault sync through the Apassy relay

Date: 2026-10-06. Status: accepted for stage 1 on 2026-10-06.

## Context

- A vault syncs only through a folder that a sync service keeps in step ([ADR 0014](0014-icloud-sync.md); engine in `src/sync/mod.rs`; merge by credential with version vectors in `src/vault/merge.rs`). On 2026-10-06 iCloud Drive stalled on both of the owner's Macs for a day. The folder path depends on a service that Apassy does not control.
- The relay ([ADR 0019](0019-relay-teams-and-accounts.md), `apassy-relay` branch `main`, commit `a0c4a71`, live image `teams-748f72e`) already has teams with separate SQLCipher files, P-256 device keys, challenge sign-in with 15-minute tokens (`src/server/devices.rs`), device link codes confirmed with safety words, per-team limits (`src/server/directory.rs`), an audit, and long polls on a per-team notifier (`src/server/approvals.rs`). It has no blob storage, no versions, and no ETag pattern. JSON bodies are capped at 64 KiB (`src/api.rs`, `MAX_JSON_BODY`).
- Sync scheduling moves from the window to a backend worker (`src/desktop/sync_worker.rs`, 2026-10-06). The relay transport plugs into that worker.
- The app has no relay client yet. It has what one needs: a rustls HTTPS client (`src/broker/http.rs`), `ring` with P-256 ([ADR 0020](0020-iphone-companion.md)), and the data-protection Keychain helper that the agent sandbox cannot reach (`docs/operations/isolation.md`).

## Decision

Add a second transport for the existing sync engine, not a second engine. The relay stores one opaque, device-signed, versioned snapshot per vault and does a compare-and-swap on its version. The identity is an ADR 0019 team with one member and several devices (a "personal team"). A second Mac joins through the existing device link flow. The passphrase stays the only key ([ADR 0003](0003-passphrase-vault.md)): the relay never holds anything that opens a vault.

Decided by the owner on 2026-10-06, for stage 1 (the open questions of the first draft, in order):

1. **Team creation.** An operator team code creates the personal team (`POST /v1/teams` with the vault name as the team name, the fixed member name `owner`, and this Mac as the first device). Open sign-up waits for ADR 0019's abuse limits and billing.
2. **Device key.** A P-256 key made in the app with `ring`, stored in a new local-only table of the vault, `relay_device` (schema version 16, one row, part of `vault::LOCAL_TABLES`): a sync copy never carries it, the agent sandbox cannot read it (the profile denies every vault file), and it is encrypted at rest with the vault. The first draft put it in the data-protection Keychain; that Keychain needs a provisioning profile that this Mac does not have. The Keychain or the Secure Enclave comes later (ADR 0019 stage 5). Consequence: the app signs in and syncs only while the vault is unlocked; a locked vault shows its last known state.
3. **Adding a Mac.** The new Mac pastes the device link (`<relay URL>/link#apassy_lnk_…`, or the bare code with the relay address), and both Macs show the same two safety words: the new Mac from its own key, the first Mac from the public key the relay reports for the pending link (`LinkView.public_key`, new). The pasteboard exposure of the code is bounded by the one-use, 10-minute code and by the confirmation on the first Mac.
4. **Sizes.** 64 MiB per snapshot; the relay keeps the current and the previous version, and the newest 10000 signed heads as the chain.
5. **One transport per vault.** A vault syncs through a folder or through the relay, never both. Turning relay sync off keeps the relay copy; the last device also gets "Delete the copy on the relay".
6. **Confirmation.** Confirming a new Mac needs a fresh owner check (Touch ID or the passphrase) for the new `OwnerAction::ConfirmSyncDevice { link_id, device_name, public_key }`, as pairing an iPhone does.

Also decided:

- **Transport.** The app talks to the relay over `https://`. Plain `http://` is allowed only for a loopback address (`127.0.0.1`, `localhost`, `[::1]`) with an explicit port, for tests and local runs, with the rule of `broker::http::parse_destination` (the bouncer rule). The default relay address is `https://apassy-relay.wyderka.cc`.
- **The contract** is `docs/contracts/relay-sync-v1.md` (the app side) and relay SPEC section 24 (the relay side). Refinements made while writing them, which replace the sketches in Design sections 2, 4, and 6 where they differ: the head is three ASCII lines with an exact grammar, its hash is the chain link, and it travels in two headers (`X-Apassy-Sync-Head`, `X-Apassy-Sync-Signature`); the device in the head is `<team id>/<device id>`; `If-Match` is required on every push and on the delete, and `412 precondition_failed` carries the current version as `ETag`; an empty relay answers `200` with `version: 0` (every answer stays an envelope), not `204`; `GET /v1/sync/head?since=N` returns the full signed chain since N (at most 1000 entries) so a Mac verifies every link back to its anchor, the head hash of the version it saw last; `POST /v1/sync/receipt` records "merged version N" per device (the relay has it in stage 1, the app shows it in stage 2); `DeviceView` gains `public_key`; the team file goes to schema version 4 (`sync_head`, `sync_receipt`); the per-team limits are `sync_bytes`, `sync_pushes_per_hour`, and `sync_transfers` (2), with a relay-wide cap of 16 transfers; a time in the head is informational, the relay does not check clock skew.
- **Trust anchor.** A Mac that has no anchor (the first enable on a vault that is already on the relay, "Use a vault from another Mac") accepts the current chain behind the owner's explicit action and stores it as its anchor. "Use the relay copy" is the documented way out of a refused version or chain: the owner decides that the relay copy is the one to keep, and the Mac drops its anchor, keeps its device, and merges the current head as at a first sync. (Turning relay sync off and on again was the first way out; it fails for the last Mac of a team, whose device the relay keeps.)
- **Restore from a backup keeps the device key.** A backup is the owner's own encrypted file, and dropping the key would lock the only Mac out of its team. A vault cloned through a backup acts as one device on two Macs; the chain stays valid.

Rejected:

- An op-log. It needs a new encoding and a second merge engine, it shows the change frequency to the relay, and folder and relay sync would diverge. Revisit if snapshots grow past about 50 MiB.
- A new account system. ADR 0019 already has device keys, revocation, limits, and an audit.
- A second encryption layer over SQLCipher. It adds a key to manage and solves nothing that a signed head does not (section 4).
- The device key in the data-protection Keychain for stage 1. It needs a provisioning profile; the local vault table gives the same two properties that matter now (never in a sync copy, unreachable to the sandbox) and is encrypted at rest.
- The relay's words shown to the confirmer, or the chain carrying public keys. Both would let the relay substitute a key and the words together; the first Mac computes the words from the key and takes keys from the device list, so a substituted key shows different words on the two Macs.
- A `/link` web page on the relay. The app parses the pasted text itself; nothing opens in a browser, and the fragment never reaches the relay.
- Versions that continue after `DELETE /v1/sync`. Restarting at 1 needs no extra state; a Mac with an older anchor sees it and asks the owner.

## Design

### 1. What goes over the relay

The same bytes as today: the stripped, vacuumed SQLCipher copy from `Vault::write_sync_copy` (`src/vault/sync.rs`), merged on the other Mac with `Vault::merge_from` (`src/vault/merge.rs`) after `check_attached`. The relay sees ciphertext and the SQLCipher salt. Ciphertext does not compress, so there is no compression.

- Limit: 64 MiB per snapshot. A vault of 500 items is a few MB (estimate).
- The Worker streams bodies without buffering. The Cloudflare upload limit must be checked before stage 1 (public docs say 100 MB on Free and Pro).
- Rate: a push after the 5-second settle and a pull on notify make a few requests per minute. Add `sync_pushes_per_hour` (default 600) to the per-team limits.

### 2. The transport

A new `src/sync/transport.rs`. `FolderSync::sync_with` becomes a `SyncEngine<T: SyncTransport>`.

```rust
pub struct RemoteHead { pub version: u64, pub sha256: [u8; 32], pub size: u64, pub signed: Option<SignedHead> }
pub enum Remote { Empty, Head(RemoteHead), Unavailable, NotReady }
pub enum Precondition { Absent, Version(u64), Any }

pub trait SyncTransport {
    fn head(&self) -> Result<Remote, SyncError>;
    fn fetch(&self, head: &RemoteHead, dest: &Path) -> Result<(), SyncError>; // checks sha256
    fn put(&self, file: &Path, sha256: &[u8; 32], expect: Precondition) -> Result<RemoteHead, SyncError>;
    fn wait_for_change(&self, since: u64, timeout: Duration) -> Result<bool, SyncError>;
}
```

| Operation | Folder (today) | Relay |
| --- | --- | --- |
| `head` | probe and file SHA-256; version 0, the hash is the identity | `GET /v1/sync/head` gives the version, the hash, and the signed head |
| `fetch` | copy the cloud file to a new file | `GET /v1/sync/snapshot?version=N`, streamed to the work file, hash checked |
| `put` | temp file and rename; the precondition is ignored, version vectors keep it safe (ADR 0014) | `PUT /v1/sync/snapshot` with `If-Match: "N"`; a 412 makes the engine fetch, merge, and push again (at most 3 rounds) |
| `wait_for_change` | sleep (30-second poll) | long poll `?wait=25`, as `/v1/host/requests` does |

`SyncState` (`src/sync/state.rs`) gets `transport` and `last_remote_version`. An `enum Transport { Folder, Relay }` implements the trait, so the worker and the before-lock hook hold a plain value.

The worker keeps its tick: the local change check, the settle, the push, and a periodic pull every 5 minutes as a fallback. The relay transport adds one waiter thread that calls `wait_for_change` and tells the worker to pull at once.

What the relay does better than a folder:

- The compare-and-swap removes the case "two Macs push, the service keeps one" (`docs/operations/sync.md`).
- Other Macs merge within a second.
- The relay records which device fetched which version, so "Receipt on another Mac is not confirmed" becomes "Received by Mac mini".

### 3. Identity and access

- **Owner of a synced vault.** In stage 1, one ADR 0019 team per vault; the team ID maps to `sync_meta.vault_id`. Creating it needs an operator team code (`POST /v1/teams`). Open sign-up is an open question.
- **Device key.** P-256 as in ADR 0019, made in the app with `ring`, kept by the Keychain helper in the data-protection keychain, so a sandboxed agent cannot read it. The Secure Enclave comes with ADR 0019 stage 5. Sign-in uses `POST /v1/auth/challenge` and `/token`, as the relay CLI does. The app implements the client side itself: it cannot depend on the relay crate (FSL license).
- **A second Mac joins.** The "Add a device" flow of ADR 0019:
  1. The first Mac shows an `apassy_lnk_` link.
  2. The owner pastes it on the second Mac (`POST /v1/devices/link`).
  3. The first Mac shows the second Mac's name and two safety words. Confirm needs a fresh owner check (`OwnerAction::ConfirmSyncDevice`, as pairing does in ADR 0020).
  4. The second Mac fetches the snapshot, and the owner types the passphrase, as `FolderSync::adopt` does today.

  A Mac that already has the vault (same vault ID) links and merges, as `enable` does.
- **Removal.** `DELETE /v1/devices/{id}` ends the tokens of that device at once. The removed Mac keeps its local vault and the passphrase. Removing a person still means a passphrase change and a rotation of each credential, as with a folder.
- **Launcher.** `SyncLink` (`src/vaults.rs`) gets `relay: Option<RelayLink { url, team_id, device_id }>`. `apassy-sandbox` skips relay links: there is no synced file to deny. An older launcher that reads a new list stops, so both ship together.

### 4. Integrity against the relay: signed heads

SQLCipher gives confidentiality and a per-page HMAC with a key that only the passphrase yields. The content digest catches mixed pages. A malicious relay can still replay an old snapshot (harmless to data by ADR 0014, but it freezes sync) or fork the devices. So each push carries a head signed by the device key:

```
apassy-relay-sync-head-v1
<vault_id> <version> <sha256 of snapshot> <size>
<sha256 of previous head, or 64 zeros> <device id> <unix time>
```

- **The relay checks:** the signature against the device of the token, `version == current + 1`, `previous == current head hash`, and the body hash.
- **A Mac accepts a head only if:**
  - a device of the team signed it;
  - its version is above `last_remote_version`;
  - the chain since its last seen version has its own last pushed head. `GET /v1/sync/head?since=N` gives the head hashes since N.
- A failure shows "The relay served a copy that does not include this Mac's last change", and there is no merge.
- Stage 2 puts the device public keys in a synced table inside the vault, so the relay cannot add a device.

### 5. What the owner sees

- **Settings > General > Sync.** The picker gets "Apassy relay" after the detected folders. The first use opens a sheet with the relay address (default `https://apassy-relay.wyderka.cc`), the team code, and the name of this Mac. The row has "Add a Mac…" (link, safety words, Confirm), "Devices…", and "Sync now".
- **"Use a vault from another Mac"** gets a second source, "Apassy relay": paste the link, see "Waiting for <Mac>…" with the safety words, then type the passphrase.
- **Statuses.**
  - Up to date: "Saved to the relay. Received by Mac mini 1 minute ago."
  - Not reachable: "Relay not reachable. Apassy syncs when it is back."
  - Damaged: "The copy on the relay fails a check."
  - New problem texts for "removed from the relay" and the fork warning.
- **Offline.** Changes stay on the Mac and go at the next tick. A failure never stops a lock (ADR 0014). Conflicts work as today.
- **One transport per vault in stage 1.** Turning relay sync off keeps the relay copy, as a folder file stays. The last device also gets "Delete the copy on the relay".

### 6. Relay changes (`apassy-relay`, `main`)

| Change | Where |
| --- | --- |
| `GET /v1/sync/head[?since=N][&wait=0..25]`: the head, the fetch receipts, and the chain hashes; 204 when empty | new `src/server/sync.rs`, with the notifier of `approvals.rs` |
| `GET /v1/sync/snapshot?version=N`: `application/octet-stream`, `ETag "N"` | same |
| `PUT /v1/sync/snapshot` with `If-Match` and `X-Apassy-Sync-Head`; the raw body streams to a temp file while it is hashed (the container has 512 MB); 412 with the current head; 413 over `sync_bytes` | `src/server/http.rs`: this route only bypasses the 64 KiB JSON cap |
| `DELETE /v1/sync` (owner) | same |
| Storage: a `sync_head` table in `teams/<id>.db`, snapshots as files `teams/<id>.sync/<version>.bin`; keep the current and the previous; team deletion removes the folder | `src/server/vault.rs`, admin delete |
| Limits: `sync_bytes` (64 MiB), `sync_pushes_per_hour`, at most 2 transfers at once per team | `src/config.rs`, `directory.rs` |
| Audit: `sync_pushed`, `sync_fetched`, `sync_deleted` (version, device, size; never content) | `src/server/audit.rs` |
| Backups include the snapshot files (ciphertext) | `deploy/vps/backup/*` |
| Contract: relay SPEC section 24 "Vault sync"; app side in `docs/contracts/relay-sync-v1.md` | docs |

## Threats

| Actor | Can | Cannot |
| --- | --- | --- |
| Relay operator, root, a VPS snapshot | see ciphertext, sizes, times, device IDs, the team name; withhold updates; replay (found by the version) or fork (found by the chain) | read a value; forge a snapshot or a head |
| Cloudflare (TLS ends there, ADR 0019) | the above, and 15-minute access tokens | the same |
| A stolen access token | fetch ciphertext | push (no device-signed head) |
| A stolen device private key | fetch; push garbage with a valid head, so other Macs show "Damaged" until the device is revoked | read a value; make a valid snapshot |
| A leaked device link | nothing without the confirmation on the first Mac | |
| A Mac with the passphrase | everything, as today (ADR 0014) | |
| The relay as a recovery path | none: it has no passphrase and no key | |

## Stages

1. **Personal vault, two Macs, pull and push with compare-and-swap.**
   - App: `SyncTransport`; `FolderSync` refactored with no change in behavior (`tests/folder_sync.rs` and `src/desktop/ui/sync_tests.rs` pass unchanged); `RelayTransport`; the device key in the Keychain; team creation; "Add a Mac" with the owner check; the relay path of "Use a vault from another Mac"; the launcher skip.
   - Relay: the endpoints, storage, limits, audit, and SPEC section 24.
   - Tests, against an in-process fake relay:
     - the scenarios of `sync.md` section 15;
     - two pushes at one version give one 412, then a merge and a retry, and nothing is lost;
     - a stale head and a forked head are refused;
     - 64 MiB + 1 byte is refused;
     - a wrong passphrase at adoption makes no file;
     - a relay-synced vault starts the sandbox;
     - the token of team A gets nothing of the snapshot of team B.
2. **Live notify and receipts.** `wait_for_change` wired to the worker, the "Received by …" status, and the device list inside the vault. Tests: a change on Mac A is merged on Mac B within 2 seconds with a fake relay; a head signed by an unlisted key is refused.
3. **Teams.** Teams with several members as shared vaults (ADR 0018, ADR 0019 stage 5), several vaults per team, and who may push by role. The companion through the relay (ADR 0020) stays separate.

Risks:

- The trait must fit the worker of 2026-10-06, or the worker is refactored twice.
- The relay uses one thread per request, so a slow 64 MiB upload holds a thread: cap the transfers.
- The operator code at onboarding.
- The Cloudflare body limit is not checked yet.
- A device key in the Keychain is weaker than the Secure Enclave until ADR 0019 stage 5.
- Backups grow by up to about 128 MiB per team.

## Open questions

1. Open sign-up and billing instead of operator team codes (ADR 0019 open decision 1). Until then, the operator makes a code per personal team.
2. When the key moves to the Keychain or the Secure Enclave (a provisioning profile, ADR 0019 stage 5), and how a vault with a `relay_device` row migrates: the row keeps the key until a migration moves it and the relay gets a new device.
3. The Cloudflare body limit for a 64 MiB push through the Worker (public docs say 100 MB on the current plan) is still unverified on the live relay: one 64 MiB test push before stage 1 ships.
4. Whether `GET /v1/devices` stays the source of signing keys for the chain check until stage 2, or stage 2 (keys in a synced vault table) ships together with stage 1 for a second Mac. Decided for stage 1 (see "Changes after the review of stage 1"): the keys come with the head answer (`signers`), including removed devices for the versions they pushed.
5. Whether a Mac that was away for more than 10000 pushes (the chain is truncated) should get a softer path than "turn sync off and on again".

## Changes after the review of stage 1

Recorded on 2026-10-06, after an adversarial review of the engine and the relay (contract relay-sync-v1, revised the same day; relay SPEC section 24):

1. **Removed devices keep their heads.** A Mac that is removed ("Devices…" > Remove, or "Turn off" while another Mac stays) made every head it had signed unverifiable, because the app checked heads with `GET /v1/devices`, which lists live devices only. The current head then failed with "Damaged" on every other Mac, forever. Now the head answer carries `signers`: the key of each device that signed the current head or a chain entry, and for a removed device the newest version it pushed. A Mac accepts a removed device's signature only up to that version. The relay never takes a push of a removed device, so that version is the last one it could sign.
2. **Chain pages.** The relay answered the newest 1000 heads after `since`, the app expected the oldest; a Mac more than 1000 versions behind saw a false fork. The relay now answers the oldest 1000, and the app asks again from the last one (at most 20 answers; the relay keeps 10000 heads).
3. **No spin.** The waiter signals each pair (`since`, version) once and waits 5 s, doubling to 60 s, on an error, on the same pair again, and on an early answer with the same version. A failed relay sync of the worker waits 5 s, doubling to 60 s (at least 60 s after a `429`), whatever asks for it; the pull flag is not used up while a run waits for the owner. A copy that needs the new passphrase, whose bytes are damaged, that is too large, that holds another vault, or that has a newer schema is not downloaded again until the head changes, the owner acts, or the vault locks. A `429` makes every call to that relay fail at once until its `Retry-After` passed.
4. **No network under the vault mutex.** The worker's relay sync holds the vault mutex only to read the vault, to merge, and to write the sync copy (`RelaySync::sync_shared`); the window and the agent broker keep the vault during a transfer.
5. **Receipts.** The app sends `POST /v1/sync/receipt` after each merge of a pulled version and after an adoption, so "Received by <Mac>" is true (moved from stage 2).
6. **A lock ends the long poll.** A lock closes the socket of the long poll in flight, and the dropped session signs in no more; while the key is in memory, the worker looks at the lock every second. Tokens, link codes, and team codes stay in buffers that are erased on drop.
7. **A pending join waits through a failure that passes by itself** (no network, a busy or limiting relay) with a growing wait, and the new Mac can cancel before the confirmation (`POST /v1/devices/link/cancel` with the code and its key; a confirmed link makes it remove its device instead).
8. **"Replace with this Mac's vault".** A damaged relay copy is replaced by a new version over the current head, signed as usual, without a merge (`RelaySync::replace_relay_copy`).
9. **Errata.** A team id is `t_` and 10 characters of `a-z2-7` on both sides (the app had accepted any digit). The test vectors use the valid team id `t_7k2m5q4x3c`, checked with `openssl`. `WORDS[174]` is `marble` (not 169). A head on an empty team that fails both checks names `version`, the first check in the relay's order. The head grammar allows `size` up to 67108864 on both sides, and `sync_bytes` is at most that.

## Changes after rounds 2 and 3

Recorded on 2026-10-07. Round 2 closed the gaps that a live test with two Macs and the review of round 1 left open. Round 3 is the review of round 2. The contract (`docs/contracts/relay-sync-v1.md`) and relay SPEC section 24 carry the details.

Round 2:

1. **A removed Mac stops.** A Mac that another Mac removed asked the relay again at the normal retry wait (43 sign-in challenges in the live test). A `401` to the challenge, or a second `401` after a new sign-in, now marks the vault as removed: no call goes to the network, the status says "Removed from the relay", and the worker and the waiter stop for that vault. Folder sync and other vaults go on.
2. **Remove asks first.** "Remove" in "Devices…" opens a confirmation with Cancel as the default. No owner check, as the contract allows.
3. **Add a Mac shows only the result** after Confirm (no used link). The team code field is masked and erased after each try.
4. **Join under another passphrase** asks for "Passphrase of the copy" instead of failing and removing the new device.
5. **Last seen.** The relay writes `last_seen_at` on head, push, download, and receipt calls, at most once a minute per device (`devices::mark_seen`).
6. **Edge size check.** The Worker refuses a snapshot push with `Transfer-Encoding`, a missing or malformed `Content-Length` (400), or more than 64 MiB plus 64 KiB (413), and rate limits pushes (`SYNC_LIMITER`, 60 a minute per IP). `POST /v1/devices/link/cancel` uses `CREATE_LIMITER`.

Round 3:

1. **A removal is not final.** The relay answers a removed device and a suspended or stopped team with the same `401`, so round 2 could cut a healthy Mac off for good. The mark now holds the time of the next try: the Mac asks once every 15 minutes and syncs again by itself when the relay lets it in. "Turn off" always asks the relay, so a device that the relay still knows leaves the team. A `401` to `POST /v1/auth/token` is a failed sign-in, not a removal.
2. **The join takes the passphrase of the copy.** Round 2 kept the joining Mac's own passphrase, which may be an old one that leaked. The joining vault now takes the passphrase of the relay copy, as on a folder and as on a Mac with an anchor (`Vault::take_passphrase_of_copy`), and the other Macs go on with no passphrase step. "Use the relay copy" keeps the rule of the no-anchor case: the passphrase only opens the copy. The sheet stays on the screen while the merge runs.
3. **Every body is bounded at the edge, not only the push.** The relay's HTTP server reads the rest of a declared body even after an early answer, on any path. The Worker now checks the declared length of every request that has a body: 64 MiB plus 64 KiB for the exact push, 8 MiB plus 64 KiB under `/p/`, 128 KiB elsewhere; a malformed length gets 400. GET and HEAD are forwarded without body headers. This bounds bytes, not time.
4. **Bouncer and build.** Not relay sync, but in the same release: the model weights download as an install step, and the demo build without the vault compiles again with a CI step. See the changelog.

Still open after round 3:

- The removal mark is in memory only, so each app start sends one challenge. Saving it needs a field in `src/sync/state.rs`.
- The relay has no separate code for a removed device. A code such as `401 device_removed` would end the guessing; it needs a relay change, a deploy, and a contract change.
- A long poll that was running when the device was removed ends at its wait time (up to 25 s) before the Mac sees the `401`.
- A body sent slowly, within the size limits, still holds a relay thread (SPEC 24.10). A real fix needs a server with read timeouts.
- Open question 3 (the Cloudflare body limit for 64 MiB) is checked in the release order (`docs/operations/release.md`, "Relay first"): a push of a few MiB through the real edge and tunnel must keep `Content-Length`.

Release rule (this phase): vault schema 16 means a vault that 0.3.3 opened no longer opens in 0.3.2, and Macs that sync one vault must all update (`src/vault/merge.rs` refuses a copy of another schema). The relay is deployed before the app is published.
