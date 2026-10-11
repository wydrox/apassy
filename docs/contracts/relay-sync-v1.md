# Relay sync wire contract v1

Date: 2026-10-06 (revised the same day after the review of stage 1: removed signers, chain pages, the receipt, the cancel of a pending link, the long-poll and retry rules, valid test vectors).
Status: proposed, for stage 1 of [ADR 0022](../adr/0022-relay-sync.md). The app side (`src/sync/`, `src/vault/relay_device.rs`) and the relay side (`apassy-relay`, `src/server/sync.rs`, `docs/SPEC.md` section 24) implement it. A change to this document changes both sides, one pull request on each side; a change to the head text or to a check bumps `v1`. The app implements the client itself and does not depend on the relay crate (FSL license): everything the app needs, including the word list of the safety words, is in this document.

## 1. Parts

| Part | Location | Feature or target |
| --- | --- | --- |
| Transport trait, the folder transport, the relay transport, the sync state | `src/sync/transport.rs`, `src/sync/relay.rs`, `src/sync/state.rs` | `vault` |
| HTTPS client of the relay: JSON calls, a streamed download, a streamed upload | `src/sync/relay_http.rs` (rustls, as `src/broker/http.rs`) | `vault` |
| Device key, the head, the sign-in message, the safety words | `src/sync/relay_crypto.rs` (`ring`) | `vault` |
| The device key in the vault, schema version 16 | `src/vault/relay_device.rs` | `vault` |
| The owner check for a new Mac | `src/broker/approvals/owner_auth.rs` (`OwnerAction::ConfirmSyncDevice`) | `vault` |
| Settings > General > Sync, "Add a device…", "Devices…", "Use a vault from another Mac" | `src/desktop/ui/sync.rs`, `src/desktop/sync_worker.rs` | `desktop` |
| The relay link in the vault list; the launcher skip | `src/vaults.rs` (`SyncLink::relay`), `src/bin/apassy-sandbox.rs` | `vault`, launcher |
| The relay: endpoints, storage, limits, audit | `apassy-relay`: `src/server/sync.rs`, `http.rs`, `store.rs`, `directory.rs` | SPEC section 24 |
| Tests against an in-process fake relay | `tests/relay_sync.rs`, `tests/common/fake_relay.rs` | `vault` |

## 2. Encodings

- **b64u**: base64url without padding (RFC 4648 section 5), as in [companion-v1](companion-v1.md). The relay refuses padding and non-canonical text. Every binary value on this wire uses it: public keys, signatures, nonces, the head text in a header.
- **hex**: lowercase hexadecimal.
- **Public key**: a P-256 point in X9.63 uncompressed form, 65 bytes, first byte `0x04`. Rust: `ring::signature::UnparsedPublicKey` with `ECDSA_P256_SHA256_ASN1`; the key pair is `EcdsaKeyPair` with `ECDSA_P256_SHA256_ASN1_SIGNING`.
- **Signature**: ECDSA P-256 with SHA-256 over the exact bytes of a message, ASN.1 DER, at most 72 bytes, sent as b64u.
- **Head text**: ASCII lines joined with `\n` (0x0A), no trailing newline, no `\r`, one space (0x20) between fields (section 8). **Head hash**: hex SHA-256 of the head text bytes.
- **Sign-in message**: bytes joined with `\0` (0x00), not newlines (section 5). The two formats differ on purpose: the head is a text document that people can read in a test, the sign-in message is the relay's existing form.
- **Time**: Unix seconds, a decimal integer.
- **IDs**: a team id is `t_` and 10 characters of `a-z2-7` (12 characters). A device id is a decimal number in JSON (the relay's row id, `"device_id": 2`) and `<team id>/<number>` in the head text (`t_7k2m5q4x3c/2`). A vault id is the UUID of `sync_meta.vault_id` (36 lowercase characters). A version is a decimal `u64`; `0` means "no snapshot". A link code is `apassy_lnk_<team id>_<64 hex>`; a team code `apassy_tcd_<64 hex>`; an access token `apassy_acc_<team id>_<64 hex>`.
- **JSON**: every relay answer is the envelope `{"ok":true,"result":...}` or `{"ok":false,"error":{"code":"...","message":"..."}}`. The app reads `ok` first and then `result` or `error`. The relay refuses unknown fields in a request body (`deny_unknown_fields`): the app sends only the fields below. The app ignores unknown fields in a result.
- **Names**: a team name and a device name are 1 to 64 bytes without a control character, trimmed. A member name is 1 to 64 bytes of `[A-Za-z0-9._-]`. A vault name of 40 characters can exceed 64 bytes: the app cuts at a character boundary.

## 3. Transport

- The relay address is an origin: `https://<host>[:port]` for any host. `http://` is allowed only for a loopback address with an explicit port: `127.0.0.1`, `localhost`, or `[::1]`, with the rules of `broker::http::parse_destination` (tests and local runs, like the bouncer rule). No path, query, user, or trailing slash is stored. The default is `https://apassy-relay.wyderka.cc`.
- HTTPS: rustls with the platform verifier (the macOS trust store), HTTP/1.1, no redirects (a 3xx is a failure). One connection per request, `Connection: close`.
- The public address is the Cloudflare Worker of the relay. The Worker adds `X-Apassy-Edge`; the app never sends that header. The Worker limits `POST /v1/teams`, `POST /v1/join`, `POST /v1/devices/link`, `POST /v1/devices/link/cancel`, `POST /v1/auth/challenge`, `POST /v1/auth/token`, and `PUT /v1/sync/snapshot` per IP address and answers `429` with `Retry-After: 60` and a JSON error (`rate_limited`); the app waits that long before the next attempt, so a refused push also holds back long polls and downloads to that relay for 60 s. The Worker also checks a declared body length before the relay: a push without `Content-Length`, with `Transfer-Encoding`, or with a malformed `Content-Length` gets `400 invalid_request`, and one over 64 MiB plus 64 KiB gets `413 payload_too_large`; any other body over 128 KiB gets `413`, and a malformed length `400`. These answers carry the same JSON error. A Worker without a relay answers `502` or `503` with a text body (`relay unreachable`, `relay not configured`); any non-JSON body means "Relay not reachable".
- Headers the app sends: `Host`, `Authorization: Bearer <access token>` on every endpoint except the four edge endpoints of section 5 and 6 (those get no `Authorization` header: the relay refuses a bearer there), `Content-Type: application/json` or `application/octet-stream`, `Content-Length` always (never `Transfer-Encoding: chunked`), and the two sync headers of section 8 on a push. `Cache-Control: no-store` comes back on every answer.
- Sizes: a JSON request body is at most 64 KiB; the app reads a JSON answer up to 2 MiB (the chain of section 9 can reach 400 KiB); a snapshot is at most 64 MiB (67108864 bytes) and streams to or from a file, never into memory.
- Deadlines: connect 10 s per address, and the name lookup and the connect together at most 30 s; the response headers within 30 s (a long poll: `wait` + 15 s); a body read or write that makes no progress for 60 s fails.
- Retries: `503 busy` waits `Retry-After` (2 s) and tries again, at most 3 times. `429` waits `Retry-After` (60 s without one, at most 300 s): until then every call to that relay fails at once without the network, and the background worker waits at least 60 s. A connection error, and any other failed sync of the worker, waits 5 s, then 10, 20, 40, and 60 (section 11). A failed upload follows the unknown-outcome rule of section 10. A download or an upload of a snapshot ends after 10 minutes, and a lock ends it at once (section 5).

## 4. Errors

Each error has an HTTP status and the envelope body `{"ok":false,"error":{"code":"precondition_failed","message":"Another Mac pushed version 7."}}`. The message is text for the owner; the app may show it. It never holds a key, a token, or vault content.

| Status | Code | When |
| --- | --- | --- |
| 400 | `invalid_request` | Malformed JSON, an unknown field, a bad name or key encoding, a missing or malformed sync header, a head text that does not parse (section 8), `If-Match` not `"<decimal>"`, a missing `Content-Length`, `Transfer-Encoding`, `since`, `wait`, or `version` not a number, `wait` over 25. |
| 401 | `unauthenticated` | A missing, unknown, or revoked token; a token of another team; a member token on a sync or link endpoint (devices only); a sign-in that failed (one message for every cause); a challenge for a key that is not a live device and not waiting. The app signs in again once and repeats the call once; a second 401, or a 401 to the challenge, is "Removed from the relay" and holds the sign-ins of that device for 15 minutes (section 13). A 401 to `POST /v1/auth/token` is a sign-in that failed, not a removal: it passes by itself. |
| 401 | `token_expired` | The access token is older than 15 minutes. The app signs in again. |
| 403 | `forbidden` | A link code that is not valid, was used, or expired; a link cancel with another key; `DELETE /v1/sync` by a device that is not an owner's. |
| 403 | `invite_invalid` | A team code that is wrong, used, or expired. |
| 403 | `join_pending` | A challenge for a key whose link waits for a confirmation. The new Mac keeps waiting. |
| 403 | `join_refused` | A challenge for a key whose link was refused or expired. |
| 403 | `sync_head_invalid` | A push whose head fails a check: the device, the signature, the version, the previous hash, the vault id, the size, or the body hash. The message names the check. Nothing is stored. |
| 403 | `team_limit` | `sync_pushes_per_hour` is reached. |
| 404 | `not_found` | An unknown path; a snapshot version that the relay does not keep (only the current and the previous version are kept); `GET /v1/sync/snapshot` when the relay has no snapshot; a link id that is not the caller's. |
| 405 | `method_not_allowed` | A known path with another method. |
| 409 | `conflict` | The safety words of a confirmation do not match; a link that does not wait any more; a cancel of a link that was confirmed; a receipt for a version above the current one; a public key that belongs to a live device. |
| 412 | `precondition_failed` | `If-Match` does not name the current version. The answer carries `ETag: "<current version>"`. |
| 413 | `payload_too_large` | `Content-Length` over `sync_bytes` (64 MiB), or a JSON body over 64 KiB. The relay still reads the rest of the declared body before the connection can go on or close (section 9), so the app sends the whole body. |
| 429 | `rate_limited` | The Worker's per-IP limit on an edge endpoint or on `PUT /v1/sync/snapshot` (section 3). `Retry-After: 60`. |
| 500 | `relay_error` | Anything else on the relay. |
| 503 | `busy` | The relay is full, the team's `sync_transfers` (2) are in use, or the sign-in challenge table is full. `Retry-After: 2`. |

Which code wins on a push, in order: at the Worker, 400 (`Content-Length` missing or malformed, `Transfer-Encoding`) → 413 (`Content-Length` over 64 MiB plus 64 KiB) → 429 (the per-IP push limit); then at the relay, 400 (shape, including a head outside the grammar of section 8.1) → 413 (`Content-Length` over 64 MiB, before the token) → 401 (token) → 413 (`Content-Length` over the team's `sync_bytes`) → 403 `team_limit` → 503 (transfers) → 412 (`If-Match`) → 403 `sync_head_invalid` (device, signature, version, previous, vault id, size, in this order: the first failed check is the one the message names) → the body streams → 400 (bytes differ from `Content-Length`) → 403 `sync_head_invalid` (hash) → 412 again if another push committed first.

## 5. Sign-in

The app reuses the device sign-in of ADR 0019 (relay SPEC section 23.3). Both calls are edge endpoints: no `Authorization` header.

`POST /v1/auth/challenge` with `{"team_id":"t_7k2m5q4x3c","public_key":"<b64u>"}` answers `{"nonce":"<b64u of 32 bytes>","expires_at":1790000060,"origin":"https://apassy-relay.wyderka.cc"}`. The nonce lives 60 seconds and works once; at most 4 are open per key. The app refuses to continue when `origin` differs from its configured relay address (both without a trailing slash) and says: "The relay calls itself <origin>; your settings say <url>."

`POST /v1/auth/token` with `{"team_id":"…","public_key":"<b64u>","nonce":"<b64u>","signature":"<b64u>"}`. The signature is over these bytes, joined with `\0`, with no newline and no trailing `\0`:

```
"apassy-relay sign-in v1" 0x00 <origin> 0x00 <team id> 0x00 <public key b64u> 0x00 <nonce b64u>
```

`origin` is the configured relay address without a trailing slash. The answer is `{"token":"apassy_acc_<team id>_<64 hex>","expires_at":1790000900,"team_id":"…","team":"Personal","member_id":1,"member_name":"owner","role":"owner","device_id":2,"key_holder":true}`. The token lasts 15 minutes and lives in a `Zeroizing` buffer in memory: never on disk, never in the vault. The app signs in when it has no token or less than 60 s of it are left, and once more after a `401`; a second `401` fails the operation. A `401` to the challenge, or a second `401`, means that the device was removed: the app signs in no more for that vault until its next try 15 minutes later (section 13). A `401` to the token call is a sign-in that failed (the nonce ended, the relay started again): the app shows "the relay had an error" and tries again as after any error that passes by itself. The relay reads the token of a push again after the body, so before an upload the app signs in also when the token ends before the upload could (10 minutes, section 3): an upload never fails at its end with `token_expired`. A restart of the relay ends every token; the next call gets `401` and the app signs in again.

Everything on the relay needs the device key, and the key is in the vault (section 14): the app signs in and syncs only while the vault is unlocked. A lock ends the waiter of section 11 and drops the token: the app closes the sockets of the long poll, of a download or an upload, and of a device call (section 9) in flight at once, also during the TLS handshake, and the dropped session signs in no more. The name lookup and the TCP connect run on a helper thread that holds no token: a request stops waiting for them at a lock. While the key is in memory, the worker also looks at the lock every second.

The token, a link code, and a team code stay in buffers that are erased on drop: the request head, a JSON request body (written from borrowed values, not from an intermediate JSON value), and every answer buffer (the answer is read straight into its typed result).

## 6. The personal team

The first Mac that turns relay sync on for a vault creates one ADR 0019 team for that vault, with an operator team code. Edge endpoint, no `Authorization`.

`POST /v1/teams` with:

```json
{"code":"apassy_tcd_<64 hex>","team":"Personal","owner":"owner","device_name":"MacBook Pro","public_key":"<b64u>"}
```

- `code`: the team code the owner typed. The app checks its shape before it sends. The field is masked, as a passphrase, and its text is erased after each try.
- `team`: the vault name, trimmed and cut to 64 bytes at a character boundary.
- `owner`: the fixed member name `owner`. A personal team has one member.
- `device_name`: this Mac's name (`sync::device_name()`, control characters removed, cut to 64 bytes); `public_key`: the new device key.

Answer: `{"team_id":"t_7k2m5q4x3c","member_id":1,"device_id":1}`. The device is the owner's and holds the key-holder flag (unused by sync). The app then signs in (section 5), reads `GET /v1/sync/head` (version 0) and pushes version 1 (section 10). The app stores the link only after the first push succeeded; when the push fails, the team stays on the relay with no snapshot, and the next "turn on" with the same team needs a link code from another Mac or a new team code (stage 1 does not reuse a failed team: the owner asks the operator for another code).

Turning relay sync on for a vault that is already on the relay (the same vault id; for example a Mac that synced through iCloud Drive before) goes through the link flow of section 7 and merges instead of adopting: after sign-in, the head's vault id must equal the local one (else "The relay copy holds another vault."), the Mac merges the snapshot (`merge_from`) and pushes. The picker offers both: "New relay copy (team code)" and "Join this vault's relay copy (link from another Mac)". The merge opens the relay copy with the key of this vault. A relay copy under another passphrase fails with `NeedsPassphrase`: nothing turns on yet, the new device stays, and the sheet asks for the passphrase of the copy ("The relay copy of <vault> uses another passphrase than this vault", field "Passphrase of the copy", "Merge"). The relay copy is the live copy of the team, and the Mac that joins is the one that was away (it had relay sync off), so the rules are those of a passphrase changed on another Mac (section 13, with an anchor; the folder rule of `FolderSync::take_new_passphrase`): the passphrase must open the copy, the vault is rekeyed to it (`RelaySync::enable_joined_with_passphrase`, `Vault::take_passphrase_of_copy`), then it merges the copy and pushes. An old passphrase of the joining Mac, maybe one that leaked, does not come back, and the other Macs go on with no passphrase step. The sheet says so before "Merge": "<vault> takes it, as on your other Macs". The message says "<vault> uses the passphrase of the relay copy now, as your other Macs, and merged with the copy." A wrong passphrase changes nothing and asks again. A failure after the passphrase opened the copy (the network, a lock) ends the join and removes the new device, and the vault keeps the passphrase of the copy; the message says so, and a new join needs no passphrase step. "Cancel", Escape, or a lock while the sheet asks removes the new device from the relay (section 7.2 step 7); while the merge runs the step stays on the screen with "Merge" disabled, and its answer ends it.

## 7. Adding a Mac

The ADR 0019 device link, with both Macs computing the safety words. A link code works once, for 10 minutes, and adds a device only after a confirmation on the first Mac behind a fresh owner check.

### 7.1 The first Mac: "Add a device…"

1. Signed in. `POST /v1/devices/links` with an empty body answers `{"secret":"apassy_lnk_<team id>_<64 hex>","expires_at":1790000600}`. The sheet shows the link as `<relay URL>/link#<code>` with a Copy button (the pasteboard; an agent can read it, and a stolen code gives nothing without the confirmation below), the same text as a QR code (error correction M) for the iPhone app, and "Waiting for the other device…". The QR code goes when the link expires. The code stays in memory while the sheet is open.
2. While the sheet is open, the app asks `GET /v1/devices/links` every 5 s: `[{"id":4,"device_name":"Mac mini","public_key":"<b64u>","created_at":1790000100,"expires_at":1790000700}]`, the pending links of this member. For each one the app computes `safety_words(team id, code, public key)` (section 7.3) with the code it holds and shows: `"Mac mini" asks to sync "Personal". Both devices show: marble kayak. Confirm only if the other device shows the same words.` with Confirm and Refuse. A pending link for which the sheet holds no code (an older link) shows Refuse only.
3. Confirm starts the owner check for `OwnerAction::ConfirmSyncDevice { link_id, device_name, public_key }` (Touch ID or the passphrase; the prompt reason is `add the device "Mac mini" to the sync of this vault`). After the check: `POST /v1/devices/links/4/confirm` with `{"safety":"marble kayak"}`, the words the first Mac computed. Answer: the `DeviceView` of the new device. The sheet says "Added. Mac mini receives the vault now." and shows only that and "Done": the used link, its QR code, and "Waiting for the other device…" go, and the sheet asks the relay no more. A `409 conflict` means the relay's record of the key differs from what it showed: the sheet says "The relay's record of this Mac does not match. Nothing was added." and refuses the link.
4. Refuse: `POST /v1/devices/links/4/refuse` with `{}`. Cancel refuses a pending link; an open, unused code just expires.

### 7.2 The new Mac: "Use a vault from another Mac" > "Apassy relay"

1. The owner pastes the text: `<relay URL>/link#<code>`, or a bare code with the relay address in the field above (default prefilled). The app parses the code (shape `apassy_lnk_<team id>_<64 hex>`) and takes the team id from it. The relay address follows section 3.
2. The app makes a P-256 device key with `ring` and keeps it in memory (`Zeroizing`) until a vault exists to hold it. The device name is this Mac's name.
3. `POST /v1/devices/link` (edge, no `Authorization`) with `{"code":"<code>","device_name":"Mac mini","public_key":"<b64u>"}` answers `{"id":4,"team_id":"t_7k2m5q4x3c","team":"Personal","safety":"marble kayak","expires_at":1790000700,"by":"owner"}`. The app computes the words itself and stops when they differ from `safety`: "The relay's words differ from this Mac's. Cancel and make a new link." It shows: `Waiting for the other Mac… Both Macs show: marble kayak. Confirm on the other Mac if it shows the same words.` A `403 forbidden` means the code is used or expired: "This link does not work. Another device may have used it. Make a new link on the other Mac." The same code with the same key again (a retry after a network error) returns the same answer.
4. Every 5 s the app sends `POST /v1/auth/challenge` for its key: `403 join_pending` keeps waiting; `403 join_refused` ends with "The other Mac refused, or the link expired."; `200` means confirmed: the app finishes the sign-in and continues. A failure that can pass by itself (no network, a non-JSON answer, `429`, `503`, `500`) keeps waiting too: the next asks skip the relay for 2 s, then 4, up to 60 (at least the `Retry-After` of a `429`). Any other answer ends the join. It gives up at `expires_at`.
5. The app reads `GET /v1/sync/head` and `GET /v1/devices`, checks the head with no anchor (section 13, first use), fetches `GET /v1/sync/snapshot?version=N`, checks the hash and the size, and asks for the passphrase. `Vault::adopt_sync_copy` makes the local vault. A wrong passphrase makes no file; the owner can type it again against the same download. A relay with version 0 ends with "The relay has no copy of this vault yet. Turn on relay sync on the other Mac first."
6. After adoption, in this order: the `relay_device` row (section 14) with the key, the relay address, the team id, and `device_id` from the sign-in answer; the vault list entry with `sync.relay`; the sync state with the anchor `(N, head hash)`.
7. Cancel before the confirmation: `POST /v1/devices/link/cancel` (edge, no `Authorization`) with `{"code":"<code>","public_key":"<b64u>"}`, the code and the key of step 3. The relay refuses the pending link (the first Mac no longer lists it; the key gets `join_refused`) and answers `{"id":4}`; a retry answers the same. When the first Mac confirmed in the meantime the relay answers `409 conflict`, and the app signs in and removes its new device as below. Cancel after the confirmation, and a quit before step 6, leave a confirmed device with no vault: the app sends `DELETE /v1/devices/<own id>` (best effort, while it still holds the key and a token) and forgets the key. An orphan that this misses shows in "Devices…" on the first Mac, where the owner removes it.

### 7.3 Safety words

Both Macs compute `SHA-256("apassy-relay safety v1" 0x00 <team id> 0x00 <link code> 0x00 <public key, 65 raw bytes>)` and take `WORDS[digest[0]]` and `WORDS[digest[1]]` from the list of section 16, shown as two words with one space. A typed comparison ignores case and surrounding spaces. The relay computes the same words when the link arrives and checks the confirmer's words against them. A party in the path (the Worker, Cloudflare, the relay) can make a key whose words match in about 2^16 tries; the words protect against a leaked code, not against the path. Stage 2 (device keys inside the vault) closes that.

## 8. The signed head

Every snapshot on the relay has a head: a short text signed by the device that pushed it. The head binds the bytes (hash and size), the vault, the version, the previous head (a chain), the device, and a time. The relay checks it on a push; every Mac checks it before a merge.

### 8.1 Grammar

```
apassy-relay-sync-head-v1
<vault_id> <version> <snapshot_sha256> <size>
<previous> <device> <time>
```

| Field | Form |
| --- | --- |
| line 1 | the fixed text `apassy-relay-sync-head-v1` |
| `vault_id` | 36 characters, `8-4-4-4-12` lowercase hex, the UUID of `sync_meta.vault_id` of the vault |
| `version` | decimal, 1 or more, no leading zero; the relay's current version plus one |
| `snapshot_sha256` | 64 lowercase hex: SHA-256 of the snapshot bytes |
| `size` | decimal, the number of snapshot bytes, 1 to 67108864, no leading zero |
| `previous` | 64 lowercase hex: the head hash (SHA-256 of the head text) of the current head on the relay, or 64 `0` when the relay has no head (version 1, or the first push after `DELETE /v1/sync`) |
| `device` | `<team id>/<device number>`: the team and the device of the access token, for example `t_7k2m5q4x3c/2` |
| `time` | decimal Unix seconds of the pushing Mac, at most 12 digits; informational, the relay does not check it against its clock |

Exactly three lines joined with `\n`, no trailing newline, no `\r`, one space between fields, nothing else. Every byte is ASCII. The relay refuses any other text with `400 invalid_request` before it checks the signature. The app and the relay parse the same grammar: a `size` above 67108864 is outside it on both sides, and the relay's `sync_bytes` is at most 67108864. The snapshot is the file that `Vault::write_sync_copy` writes (the stripped, vacuumed SQLCipher copy); its bytes are opaque to the relay.

### 8.2 Hash and signature

- **Head hash** = hex SHA-256 of the UTF-8 bytes of the head text. It is the `previous` of the next head and the anchor that a Mac stores (section 13).
- **Signature** = ECDSA P-256 SHA-256 over the same bytes, DER, by the device key named in `device`. Sent as b64u.

### 8.3 On the wire

Two headers carry a head; the text has newlines, so it is b64u in a header:

| Header | Value |
| --- | --- |
| `X-Apassy-Sync-Head` | b64u of the head text (at most 512 characters) |
| `X-Apassy-Sync-Signature` | b64u of the DER signature (at most 96 characters) |

A push sends both. The answers of `GET /v1/sync/head` and `GET /v1/sync/snapshot` carry the head of the version they describe: in the JSON fields `head` and `signature` (b64u), and as the same two headers on the snapshot download. A Mac takes every value (vault id, version, hash, size, device) from the head text it verified, never from the unsigned JSON fields next to it.

## 9. Endpoints

All sync endpoints need the access token of a live device of the team (`Authorization: Bearer apassy_acc_…`); a member token gets `401`. The relay finds the team from the token: no endpoint takes a team id in the path.

### `GET /v1/sync/head?since=N&wait=S`

- `since` (default 0): the version this Mac has. `wait` (default 0, at most 25): while the current version equals `since`, hold the answer up to `wait` seconds (section 11). A version below `since` (a relay restored from a backup) answers at once.
- Answer with a snapshot:

```json
{
  "version": 2,
  "head": "<b64u head text of version 2>", "signature": "<b64u>",
  "device_id": 2, "device_name": "MacBook Pro", "pushed_at": 1790000061,
  "chain": [
    {"version": 1, "head": "<b64u>", "signature": "<b64u>", "device_id": 2, "pushed_at": 1790000001},
    {"version": 2, "head": "<b64u>", "signature": "<b64u>", "device_id": 2, "pushed_at": 1790000061}
  ],
  "chain_from": 1,
  "signers": [{"device_id": 2, "public_key": "<b64u>"}],
  "receipts": [{"device_id": 3, "device_name": "Mac mini", "version": 2, "at": 1790000100}]
}
```

- `chain` holds the heads of the versions `since + 1` to `version`, oldest first, at most 1000: with more, the oldest 1000, and the Mac asks again with `since` set to the version of the last entry, until the chain reaches `version` (at most 20 answers). `chain_from` is the version of the first entry and is absent when the chain is empty. When the relay has dropped older heads (it keeps the newest 10000), the chain starts later than `since + 1`; the Mac then cannot verify the chain (section 13).
- `signers`: `[{"device_id": 2, "public_key": "<b64u>"}, {"device_id": 3, "public_key": "<b64u>", "removed": true, "last_version": 1}]`, one entry for the device of the current head and of each chain entry of this answer. A device that was removed, or whose member was removed, has `removed: true` and `last_version`, the newest version it pushed (the relay never takes a push of a removed device: the commit of a push checks the device and its member again in the transaction that stores the head, so this is the last version it could sign). The Mac checks every head with these keys (section 13, check 3). Absent when empty.
- `receipts`: for each live device, the newest version it reported as merged (`POST /v1/sync/receipt`). The app shows "Received by Mac mini". It reads them with `since` = the version it saw last, so the answer has no chain of older heads.
- `pushed_at` is the relay's clock, not the head's `time`.
- Answer without a snapshot: `{"version": 0, "chain": [], "receipts": []}` (200, not 204: every answer is an envelope). `ETag: "<version>"` is on every answer.

### `GET /v1/sync/snapshot?version=N`

- `version` is required and must be the current or the previous version; others get `404`.
- Answer: `200`, `Content-Type: application/octet-stream`, `Content-Length`, `ETag: "N"`, `X-Apassy-Sync-Head`, `X-Apassy-Sync-Signature`, the snapshot bytes. The app streams them to a private file in the work folder (mode 0600) while it hashes them, as the folder transport does, and checks the hash and the size against the head.
- The relay writes an audit row `sync_fetched` (at most one per device and version) after the answer.

### `PUT /v1/sync/snapshot`

- Headers: `If-Match: "N"` with N the version the Mac saw last (`"0"` for the first push), `Content-Type: application/octet-stream`, `Content-Length` equal to the head's `size`, `X-Apassy-Sync-Head`, `X-Apassy-Sync-Signature`. No `Expect: 100-continue` is needed. The relay may answer before the body ends (a 412 or 413); it still reads the rest of the body, so the app sends the whole body and then reads the answer.
- Body: the snapshot bytes.
- The relay checks, in the order of section 4, before it reads the body: the headers; the device of the head is the device of the token and the team is this team; the signature verifies with that device's public key; `If-Match` equals the current version; `version` is the current version plus one; `previous` is the head hash of the current head, or 64 zeros when there is none; `vault_id` equals the current head's vault id when there is one; `size` equals `Content-Length` and is at most `sync_bytes`. Then it streams the body to a temporary file while hashing; the bytes must equal `Content-Length` and hash to `snapshot_sha256`. Then, under the team's sync lock, it checks the version once more (another push may have committed: `412`), renames the file, stores the head, drops the snapshot before the previous one, writes `sync_pushed`, and wakes the long polls.
- Answer: the same shape as `GET /v1/sync/head` for the new version, with an empty chain and the receipts.

### `POST /v1/sync/receipt`

- Body `{"version": N}`: this device merged version N. `409` when N is above the current version. Answer `{"version": N, "at": 1790000100}`. Audit `sync_received`. The app sends it after each merge of a pulled version and after an adoption (section 7.2), best effort: a failure changes nothing.

### `DELETE /v1/sync`

- The owner's device only (`403 forbidden` for another device). `If-Match: "N"` is required and must be the current version (`412` otherwise; `"0"` on an empty relay is a no-op). Removes every head, every receipt, and every snapshot file. The next push is version 1 with 64 zeros as `previous`. Answer `{"last_version": N}`. Audit `sync_deleted`. Other Macs then see a version below their anchor and show the notice of section 13.

### `GET /v1/devices`

- As in SPEC section 23.5, with `public_key` (b64u) added to each `DeviceView`: `[{"id":2,"member_id":1,"member_name":"owner","name":"MacBook Pro","public_key":"<b64u>","key_holder":true,"created_at":…,"last_seen_at":…,"current":true}]`. The owner sees every live device of the team. "Devices…" shows this list with Remove (`DELETE /v1/devices/{id}`); the last device of the owner cannot be removed (`409`). Remove asks first: "Remove <Mac> from the relay? It keeps its vault but stops syncing. To add it again you need a new link and the owner check." with "Remove" and "Cancel", and Cancel has the focus for the keyboard. It needs no owner check: it only takes access away, and adding the Mac again needs the owner check of section 7.1. The app does not check heads with this list (it has live devices only): it uses `signers` of the head answer, so removing a Mac, or a Mac that turns relay sync off, does not stop the others.

### `GET /v1/devices/links`, `POST /v1/devices/links`, `POST /v1/devices/link`, `POST /v1/devices/links/{id}/confirm`, `POST /v1/devices/links/{id}/refuse`

- As in SPEC section 23.5, with `public_key` (b64u) added to each `LinkView`, so the first Mac computes the safety words itself (section 7).

### `POST /v1/devices/link/cancel`

- Edge endpoint, no `Authorization`, limited per IP address by the Worker as `POST /v1/devices/link`. Body `{"code":"apassy_lnk_…","public_key":"<b64u>"}`: the new Mac takes back its pending link before the confirmation (section 7.2 step 7). Answer `{"id": <link id>}`; the link becomes refused. A retry, or a cancel of an expired link, answers the same. `409 conflict`: the link was confirmed. `403 forbidden`: another key, or an unknown code. Audit `device_link_cancelled`.

## 10. The push: compare-and-swap

A sync of the relay transport, inside the engine of ADR 0014 (merge first, then push when the vault has content that the relay lacks), at most 3 rounds:

1. `GET /v1/sync/head?since=<last_remote_version>` (more answers for a chain over 1000 heads); verify (section 13). When the version is above the last seen one, fetch and merge, store the anchor, and send `POST /v1/sync/receipt` for that version.
2. When the synced content of the vault differs from the content of the snapshot it saw last (`last_content`, as with a folder): write the sync copy, hash it, build the head with `version = remote version + 1`, `previous = remote head hash` (or 64 zeros when the remote version is 0), `device = own`, `time = now`; sign; `PUT /v1/sync/snapshot` with `If-Match: "<remote version>"`.
3. `200`: store the anchor `(new version, head hash)`, `last_content`, and the time. Done.
4. `412`: another Mac pushed first. Go to step 1 (the merge takes its change). After 3 rounds the sync ends with "The relay is busy with another Mac. Apassy tries again." and the next tick starts again; nothing is lost, the change stays on this Mac.
5. Any other error ends the sync; the change stays and goes at the next tick.

Unknown outcome: when the connection fails during or after the upload, the app asks `GET /v1/sync/head`. If the version is the expected one and the head is this device's with this snapshot hash, the push landed (step 3); otherwise step 5. The relay never has a partial snapshot: the file is renamed only after the hash matched.

The folder transport ignores the precondition (version vectors keep it safe, ADR 0014). The relay transport never pushes without `If-Match`.

The vault mutex of the app is held only for the local steps: reading the vault, the merge, and writing the sync copy. The sign-in, the head, the download, and the upload run without it (`RelaySync::sync_shared`), so the window and the agent broker keep the vault during a transfer.

A copy that fails for a reason that does not pass by itself (it needs the new passphrase, its bytes are not its head's, it is too large, it holds another vault, or its schema is newer than this app) is not downloaded again: the next syncs answer the same failure from the head alone, until the head changes, the owner acts (the new passphrase, "Replace with this Mac's vault", "Use the relay copy"), or the vault locks. A network failure, a lock, or a file error on this Mac can pass, and the next sync downloads again. The new passphrase checks the copy and merges it with one download; when the sync after the rekey fails, the vault keeps the new passphrase and the sync tries again later.

"Replace with this Mac's vault" (`RelaySync::replace_relay_copy`, for a damaged relay copy): read the head without checks, write the sync copy, and push it as the next version over the current head (`previous` = the hash of the current head text, `If-Match` = its version), signed as usual; a `412` reads the head again, at most 3 rounds. The relay still checks the push (a copy of another vault there is `OtherVault`). The anchor becomes the new head. Another Mac whose anchor is the version below links to it; a Mac that cannot link (it never saw a head that verifies) uses the relay copy (section 13).

## 11. Long poll

While the vault is unlocked and relay sync is on, one waiter thread asks `GET /v1/sync/head?since=<last_remote_version>&wait=25`. The relay answers at once when its version differs from `since`, or when a push or a delete happens, or after `wait` seconds. A version that differs from `since` makes the worker pull now, once for each pair (`since`, version). The waiter then waits 5 s, doubling up to 60 s, before it asks again in each of these cases: an error; the same pair again (the pull failed, a run waits for the owner, or the pull is still on its way); the same version answered well before `wait` ran out (the relay keeps at most one sync long poll per device and answers a second one at once, as with `wait=0`, and answers at once while it stops). Every other wait is at least 200 ms. The worker does not take the pull while a run waits for the owner or while a failed relay sync waits for its retry: the flag stays for later. A failed relay sync of the worker waits 5 s, then 10, 20, 40, and 60 (at least 60 after a `429`) before the next one, whatever asks for it; it retries on its own at that time. A command of the window starts again at once. A lock ends the long poll and a download or an upload in flight at once (section 5) and stops the waiter. The worker's 5-minute pull stays as the fallback. A removed device (section 13) stops both: the first refusal, of the waiter or of a sync, shows "Removed from the relay" at once, and neither asks the relay about that vault again until the next try of the worker, 15 minutes later (a sync that works then clears the status, and the waiter goes on). The relay does not end a long poll that was in flight when another Mac removed this one: it answers at its `wait`, and the next poll gets the `401`.

## 12. Limits

| Limit | Value | Where |
| --- | --- | --- |
| Snapshot size (`sync_bytes`) | 64 MiB (67108864 bytes) | relay, per team; the app refuses to push a larger copy and shows "The vault is too large for the relay (64 MiB)." |
| Snapshots kept | the current and the previous version | relay |
| Heads kept (the chain) | the newest 10000 | relay |
| Chain entries in one answer | 1000, the oldest after `since`; the Mac asks again from the last one | relay |
| Pushes per hour (`sync_pushes_per_hour`) | 600 | relay, per team: `403 team_limit` |
| Transfers at once (`sync_transfers`) | 2 per team (a push or a download), 16 per relay | relay: `503 busy` |
| Sync long polls | 1 per device; `wait` 0 to 25 s | relay |
| Access token | 15 minutes, in memory | both |
| Link code | 10 minutes, one use; a pending link waits 10 minutes from the request | relay |
| Devices | at most 10 live devices per member | relay |
| JSON request body | 64 KiB | relay |
| JSON answer | the app reads at most 2 MiB | app |

## 13. What the Mac checks before it merges

The Mac keeps an anchor: `last_remote_version` and `last_head_sha256`, the head hash of the version it saw last (the head it pushed, or the head it fetched and merged). It accepts a head and merges the snapshot only when every check passes, in this order:

1. The head text parses (section 8.1), and its `device` names this link's team id.
2. Its `vault_id` is this vault's `sync_meta.vault_id`. Else `OtherVault`: "The relay copy holds another vault."
3. The signature verifies with the public key that `signers` of the same answer lists for the head's device: a live device of the team for any version; a removed device only when the head's version is at most its `last_version` (the heads it pushed while it was a member). Stage 2 reads the keys from a synced table in the vault. Else `Damaged`: "The copy on the relay fails a check." The way out of `Damaged` is "Replace with this Mac's vault" (section 10).
4. `version` is above `last_remote_version`. A version equal to it with another head hash, or a lower version, is refused: "The relay has an older copy than this Mac saw. To go on, select “Use the relay copy…” in Settings > General > Sync." (A relay restored from a backup, or `DELETE /v1/sync` on another Mac, lands here.)
5. The chain from `last_remote_version` to `version` is continuous, over as many answers as it takes (section 9): the first entry's `previous` equals `last_head_sha256`; each later entry's `previous` equals the head hash of the entry before; every entry's signature verifies by the rule of check 3; the last entry is the current head. A chain that starts later than `last_remote_version + 1` (the relay dropped old heads) or that does not link to the anchor is refused: "The relay served a copy that does not include this Mac's last change. To go on, select “Use the relay copy…” in Settings > General > Sync." No merge.
6. The downloaded bytes hash to `snapshot_sha256` and have `size` bytes. Else `Damaged`.
7. The copy passes the checks of ADR 0014: it opens with the key of the vault (else `NeedsPassphrase`: with an anchor, the passphrase changed on another Mac, and the prompt and the rekey work as with a folder; without one, see below), the integrity check, the schema version (both Macs ship the same version), the content digest, the vault id.

With no anchor (`last_remote_version` is 0: the first enable on a vault that is already on the relay, and "Use a vault from another Mac") the Mac accepts the chain it is given after checks 1, 2, 3, 6, and 7, and stores the current head as its anchor: trust on first use, behind the owner's explicit action. "Use the relay copy" (`RelaySync::use_relay_copy`) is the way out of checks 4 and 5: the owner decides that the relay copy is the one to keep. The Mac forgets its anchor, keeps its device and key, accepts the current head after checks 1, 2, 3, 6, and 7 as above, merges it (its own changes stay and are pushed again), and stores the new head as its anchor. It works for the last device of a team too, which could not join again after a turn-off. When that copy then fails in a way that stays (it needs another passphrase, or its bytes are damaged), the forgotten anchor is saved: the prompt for the passphrase of the copy, or "Replace with this Mac's vault", then starts from the copy as it is now. A relay restored from a backup that predates a passphrase change lands here.

Without an anchor (`RelaySync::keeps_passphrase`), the passphrase prompt does not rekey the vault: the copy can be older than this vault, from before a passphrase change, maybe one made because the old passphrase leaked. The prompt says "The relay copy of <vault> uses another passphrase" and asks for "Passphrase of the copy". That passphrase only opens the copy for the merge (`Vault::merge_from_with_passphrase`, an `ATTACH … KEY`); the vault keeps the passphrase of this Mac, stores the head as its anchor, and pushes the merged vault under its own passphrase, also when its content equals the copy's. The result says "Apassy merged the relay copy into <vault>, which keeps the passphrase of this Mac." Other Macs that still use the copy's passphrase then see `NeedsPassphrase` with an anchor and take the passphrase of this Mac. With an anchor the prompt stays "The passphrase of <vault> changed on another Mac", and the vault takes the new passphrase.

Other texts: a `401` after a second sign-in attempt, or a `401` to the challenge, is "Removed from the relay. This Mac keeps its vault. Turn relay sync off, then join again with a link from another Mac." The Mac shows it at once and holds the vault (`RelaySync::is_removed`): no challenge, no long poll, no sync, no device call, also after a lock and an unlock. The relay answers a suspended team, a team that is out of service, and a relay that stops with the same `401` (relay SPEC section 23), so the hold is not final: 15 minutes after the last refusal (`RelaySync::removed_until`) the worker signs in once more, and a sign-in that works clears it. A removed Mac thus sends one challenge every 15 minutes, and one more at each start of the app (the mark lives in memory). "Turn off" and "Delete the copy on the relay" ask the relay at once also while it holds, so a device that the relay still knows leaves the team; a `401` there means that the relay did not know the device, and the message says to remove it in "Devices…" on another Mac when it still shows there. Turning relay sync off (`RelaySync::disable`) or a join with a new link clears the hold. A join needs relay sync off first, so the way back is "Turn off", then "Join from another Mac". Folder sync and the other vaults go on. A connection failure is "Relay not reachable. Apassy syncs when it is back." A failure never stops a lock or a quit.

## 14. What the Mac stores

### 14.1 The vault list (`vaults.json`, no secret)

`SyncLink` gets `relay: Option<RelayLink>`:

```json
{"id":"…","name":"Personal","path":"/…/vault.db","added_at":1790000000,
 "sync":{"state":"<list id>","folder":"","file":"","relay":{"url":"https://apassy-relay.wyderka.cc","team_id":"t_7k2m5q4x3c","device_id":2}}}
```

- One transport per vault: a link has a folder and a file, or a relay, never both. `folder` and `file` are empty for a relay link.
- `apassy-sandbox` skips a link with `relay`: there is no synced file to deny. An older launcher stops on such a list (it sees a synced vault without a valid file), so the app and the launcher ship together.

### 14.2 The sync state (`<data folder>/sync/<list id>.json`, mode 0600, no secret)

Format 3. New fields: `transport` (`"folder"` or `"relay"`), `relay_url`, `team_id`, `device_id`, `last_remote_version`, `last_head_sha256` (hex). `file_name`, `last_file_sha256`, and `folder` are required only for `transport: "folder"`. `vault_id`, `last_content`, `last_sync_at`, and `vault_path` stay as they are. A format 2 file reads as `transport: "folder"`.

### 14.3 The device key in the vault (schema version 16)

The private key is in a local-only table of the vault, so a sync copy never carries it (`strip_attached` deletes the rows of every table in `vault::LOCAL_TABLES` from the pushed copy, and the table coverage test in `tests/folder_sync.rs` fails unless the table is listed), the agent sandbox cannot read it (the profile denies every vault file), and it is encrypted at rest with the rest of the vault. Module `src/vault/relay_device.rs`:

```sql
CREATE TABLE relay_device (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    relay_url TEXT NOT NULL,
    team_id TEXT NOT NULL,
    device_id INTEGER NOT NULL,
    public_key BLOB NOT NULL,
    key_pkcs8 BLOB NOT NULL,
    created_at INTEGER NOT NULL
);
UPDATE vault_meta SET schema_version = 16 WHERE id = 1;
PRAGMA user_version = 16;
```

- `SCHEMA_V16_SQL`, `SCHEMA_V16_COLUMNS` (`SELECT id, relay_url, team_id, device_id, public_key, key_pkcs8, created_at FROM relay_device LIMIT 0`), `RELAY_DEVICE_SCHEMA_VERSION = 16`, `SCHEMA_VERSION` becomes 16, `LOCAL_TABLES` becomes 22 entries. One row (`id = 1`): one transport per vault, one team per vault. Stage 3 drops the `CHECK`.
- `key_pkcs8` is the document that `ring::signature::EcdsaKeyPair::generate_pkcs8` makes; it is read into a `Zeroizing` buffer and loaded with `from_pkcs8`. `public_key` is the 65-byte point. The key is made before the device exists on the relay and written after the vault exists (section 7.2 step 6, section 6).
- A migration from 15 adds the table; a copy from another schema version is `UnsupportedSchema`, as today, so both Macs run the same app version.
- A restore from a backup keeps the row: a backup is the owner's own encrypted file, and dropping the key would lock the only Mac out of its team (ADR 0019: a team whose owner has no device cannot be entered again). A vault cloned through a backup instead of the relay acts as the same device on both Macs; the chain stays valid, only the device list and "Received by" cannot tell them apart. A copy made by `adopt_sync_copy` has no row (stripped).
- Turning relay sync off deletes the row, the state file, and `sync.relay`; the relay keeps the copy. On a Mac that is not the last of the team, "Turn off" first removes its own device (`DELETE /v1/devices/<id>`); a Mac that the relay does not know (`401` to its challenge, asked also while the removal of section 13 holds) says that it was no longer in the team and to remove it in "Devices…" on another Mac if it still shows there, and the relay keeps the last device of the team (`409`, the message says that it was the last Mac). "Turn off" needs the vault open and unlocked, since the row is in the vault. "Remove from list" of a locked vault keeps the row in the vault file, and this Mac stays in the team (the message says so). The last device also gets "Delete the copy on the relay" (`DELETE /v1/sync`). Its device stays on the relay (the last device of the owner cannot be removed, section 9) while its key leaves the vault, so only the operator can reuse or delete the team.

## 15. Test vectors

These values are synthetic. Both test suites use them. The private key is the raw 32-byte scalar; `ring` builds the pair with `EcdsaKeyPair::from_private_key_and_public_key(&ECDSA_P256_SHA256_ASN1_SIGNING, &private, &public, &rng)`, as the companion tests do. The public key is the X9.63 point.

| Name | Value |
| --- | --- |
| Device key, private (hex) | `4f2d9c6e1b3a7d8f0c5e2a9b7f4d1c3e6a8b0d2f4c6e8a1b3d5f7a9c0e2b4d6f` |
| Device key, public (hex, 65 bytes) | `04ea47901e55bd31d76b0a545d9c60bb8e10f7b2366f3abd1bfb88ead14cf668fc0ded38eded5f35623c3081110ec6b18410b48a1d433df5da33899d05b1318eb0` |
| Device key, public (b64u) | `BOpHkB5VvTHXawpUXZxgu44Q97I2bzq9G_uI6tFM9mj8De047e1fNWI8MIERDsaxhBC0ih1DPfXaM4mdBbExjrA` |
| Team id | `t_7k2m5q4x3c` |
| Device | `t_7k2m5q4x3c/2` (JSON `"device_id": 2`) |
| Vault id | `0f3c2a10-5b7e-4d9a-8c21-6f0e4b1d9a77` |
| Snapshot 1 | the UTF-8 bytes of `synthetic snapshot` (18 bytes) |
| SHA-256 of snapshot 1 | `5b77343bd881a4f425bde1ec9979946ec1add11de02010d4c63159977bac4de8` |
| Snapshot 2 | the UTF-8 bytes of `synthetic snapshot 2` (20 bytes) |
| SHA-256 of snapshot 2 | `7dd91ab21b30df12a943c507d6e7d808f6ea2608faa3239aa7fed621ecae241a` |
| Head 1 hash (hex SHA-256 of the head 1 text, 223 bytes) | `d562a4c9951ac36b211ed9786a6897f16870639c54df9d168c56c39d4ce387d9` |
| Head 2 hash | `2a3d34a3454acf98a897115ed30e8ea195852d7e943c780974c1f2489810cc3c` |
| Head 1 (b64u, the `X-Apassy-Sync-Head` value) | `YXBhc3N5LXJlbGF5LXN5bmMtaGVhZC12MQowZjNjMmExMC01YjdlLTRkOWEtOGMyMS02ZjBlNGIxZDlhNzcgMSA1Yjc3MzQzYmQ4ODFhNGY0MjViZGUxZWM5OTc5OTQ2ZWMxYWRkMTFkZTAyMDEwZDRjNjMxNTk5NzdiYWM0ZGU4IDE4CjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAgdF83azJtNXE0eDNjLzIgMTc5MDAwMDAwMA` |
| Head 2 (b64u) | `YXBhc3N5LXJlbGF5LXN5bmMtaGVhZC12MQowZjNjMmExMC01YjdlLTRkOWEtOGMyMS02ZjBlNGIxZDlhNzcgMiA3ZGQ5MWFiMjFiMzBkZjEyYTk0M2M1MDdkNmU3ZDgwOGY2ZWEyNjA4ZmFhMzIzOWFhN2ZlZDYyMWVjYWUyNDFhIDIwCmQ1NjJhNGM5OTUxYWMzNmIyMTFlZDk3ODZhNjg5N2YxNjg3MDYzOWM1NGRmOWQxNjhjNTZjMzlkNGNlMzg3ZDkgdF83azJtNXE0eDNjLzIgMTc5MDAwMDA2MA` |
| Signature of head 1 (b64u DER) | `MEUCIHD6Ih2lhM6u-hBJFTF2urGCw1UeM8vL3oM2mIDm0MvgAiEAxXcwrQRcPb0WAAgj4tylCij4Qxlbu7jISfCuxGIJDHA` |
| Signature of head 2 (b64u DER) | `MEUCIQDpxvOaoLg8rz7vXW0U0xd6lGyttG8CeaRV76DrHTChYgIgIpwTtg1Z-BqkmTw1uDnO8FHS_YddNgbMPCWJP8KKa-g` |
| Sign-in origin | `https://relay.example.test` |
| Sign-in nonce (b64u of bytes 0 to 31) | `AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8` |
| SHA-256 of the sign-in message | `43722057f746ba2b1759952943e9532ad49c68496c11a6f1bef65709c20e7aaa` |
| Signature of the sign-in message (b64u DER) | `MEUCIAyr22ugUYumzN6x8ktWI1ruvFmEVjktZGhAfa7dRmeXAiEAiHEWtFJmR5giJlad5O0jy9dVkHD3IAKRM3TZRXzwJEY` |
| Link code | `apassy_lnk_t_7k2m5q4x3c_abababababababababababababababababababababababababababababababab` |
| Safety hash (SHA-256 of the safety message) | `fc0f67b7df128c3d82fae26d0b646d9bcd3623adcb562f7d85d313f7456a3b7c` |
| Safety words | `tulip arrow` (`WORDS[0xfc]`, `WORDS[0x0f]`) |

Head 1 text (version 1, no previous head; the bytes between the fences, with `\n` between the lines and none at the end):

```
apassy-relay-sync-head-v1
0f3c2a10-5b7e-4d9a-8c21-6f0e4b1d9a77 1 5b77343bd881a4f425bde1ec9979946ec1add11de02010d4c63159977bac4de8 18
0000000000000000000000000000000000000000000000000000000000000000 t_7k2m5q4x3c/2 1790000000
```

Head 2 text (its `previous` is the head 1 hash):

```
apassy-relay-sync-head-v1
0f3c2a10-5b7e-4d9a-8c21-6f0e4b1d9a77 2 7dd91ab21b30df12a943c507d6e7d808f6ea2608faa3239aa7fed621ecae241a 20
d562a4c9951ac36b211ed9786a6897f16870639c54df9d168c56c39d4ce387d9 t_7k2m5q4x3c/2 1790000060
```

The sign-in message of these vectors, as bytes (`\0` is one zero byte):

```
apassy-relay sign-in v1\0https://relay.example.test\0t_7k2m5q4x3c\0BOpHkB5VvTHXawpUXZxgu44Q97I2bzq9G_uI6tFM9mj8De047e1fNWI8MIERDsaxhBC0ih1DPfXaM4mdBbExjrA\0AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8
```

Both suites must show: the head texts hash to the head hashes; each signature verifies with the public key over its text; a signature fails after one changed character of its text, and fails with another key; the relay accepts head 1 on an empty team with `If-Match: "0"` and head 2 after it with `If-Match: "1"`, and refuses head 2 on an empty team (`version`: the version check comes before the previous check, section 4), head 1 after head 1 (`version`), head 2 with a changed `size` or a body whose hash differs (`sync_head_invalid`), and head 2 signed by another live device but naming `t_7k2m5q4x3c/2` (`device`); the app accepts the chain [head 1, head 2] from the anchor (1, head 1 hash) and refuses it from an anchor whose hash differs; the safety message gives `tulip arrow`. ECDSA signatures are randomized: a new signature of the same text differs and still verifies. Every value was checked with `openssl dgst -sha256 -verify` against the public key, and both suites check them (the relay's `src/sync_head.rs`, `src/device.rs` (the sign-in message and the safety words), and `tests/server_sync.rs`; the app's `src/sync/relay_crypto.rs`, `src/sync/relay.rs`, and `tests/relay_sync.rs`).

## 16. The word list

The 256 words of the safety words, in index order (the same list as the relay's `src/device.rs`; the app copies it from here):

```
acid acorn actor adult agent alarm album alert alpha amber
angle apple april arena armor arrow atlas attic audio aunt
autumn award bacon badge bagel baker bamboo banana band barn
basil basket beach beard beaver bell berry bike bird blade
blaze bloom board boat bonus book boot bottle brain branch
bread brick bridge broom brush bubble bucket cabin cable cactus
camel camera candle canoe canyon carbon carpet carrot castle cave
cedar cello chalk cherry chess chief cider circle cliff cloud
clover coast cobra cocoa comet coral cotton cousin coyote crane
crayon cream cube cup daisy dancer delta desert dinner disk
doctor domino donkey door dragon dream drum eagle earth echo
elbow ember engine falcon fence ferry fiber field finch flag
flame flute forest fossil fox frost galaxy garden garlic gecko
giant ginger globe goat gold grape gravel guitar hammer harbor
harp hazel helmet heron hippo honey hornet hotel husky igloo
island ivory jacket jaguar jelly jungle kayak kettle kiwi koala
ladder lagoon laser lemon lilac lime lion lizard locket lotus
lunar magnet mango maple marble meadow melon meteor mint mirror
monkey moose mosaic muffin nectar needle nest noodle oasis ocean
olive onion orange orbit orchid otter owl oyster paddle panda
paper parrot peach peanut pearl pebble pencil pepper piano pilot
pine planet plum pocket pony poppy potato prism puzzle quartz
quill rabbit radar radio raven ribbon river robin rocket rose
ruby saddle salmon sandal satin scarf seal shark shell sled
snail solar spoon squid stamp star stone sugar swan tango
tiger topaz tulip whale wolf zebra
```

A test checks that the list has 256 different words, that index 174 is `marble` and index 156 is `kayak` (the words of the examples in section 7), and that index 252 is `tulip` and index 15 is `arrow` (the words of the vector).
