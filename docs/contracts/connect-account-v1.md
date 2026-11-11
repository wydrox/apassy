# Connect account contract v1

Date: 2026-11-03. Status: proposed, for ADR 0037 stage 7 (unit D1 of [the stage 7 plan](../design/implementation-plan-s7-connect.md)). Not implemented. The relay side is C1 (`crates/apassy-relay/src/server/account.rs`), the Mac side M1 (`src/connect/`), the iPhone side I1 (`ios/ApassyCore/src/core/connect.rs`), the bouncer brain side H of [plan 0035](../design/implementation-plan-0035.md) (`entitlements.py`). Synthetic vectors in section 15 include exact message bytes, ECDSA and Ed25519 signatures, the signed device list, the link fingerprint, the safety words, and the recovery key.
Revised on 2026-11-10, before any release (unit FA): the device statements and the verified device list (section 7.5), challenges that keep no state, the signed-in removal answer, the link fingerprint, the recovery key, and the limits of section 13.
Revised on 2026-11-11, before any release (unit FA2): the signed, versioned device list replaces the chains of statements (sections 5 to 7.5); a confirmation and a revoke are entries of it; the signers of a vault store come from each device's own trust store (section 7.5); a removal leaves the stores in the transaction of the change (7.4); the limits of section 13.
Revised on 2026-11-11, before any release (unit FA3): each entry of the device list signs the device name, and the root entry is signed by its own key, so the device makes the account id (sections 2, 5, 6, 9); a list counts on a device only while it holds the device's own key, and a new device pins only a list with its own `add` (7.2, 7.5); a revoke names the key of the verified list (7.4); an `add` leaves room to remove every device (7.5, 13); a head below a head of a live device may be signed by a device that left, and a live device signs over a head of a device that left (7.5); a vault store has no device link, and a store of another account is refused by the client (8).
Decision: [ADR 0037](../adr/0037-own-relay-open-source.md) sections 1 and 7, stage 7, D2, D3; [ADR 0035](../adr/0035-bouncer-hosting-and-training-choice.md) decision 6 and section 2; [ADR 0019](../adr/0019-relay-teams-and-accounts.md) (device identity); [plans](../product/plans.md) section 3.

This contract defines Connect accounts: account creation, account devices and their sign-in, the device link with safety words, vault stores (one [relay-sync-v1](relay-sync-v1.md) team for each vault), recovery, the entitlement token for other Connect services, and the internal routes of the hosted bouncer brain. Billing and groups are [connect-billing-v1](connect-billing-v1.md); the byte relay is [connect-tunnel-v1](connect-tunnel-v1.md). MUST and MUST NOT below are requirements on both sides. A change to a message, a field, or a check needs a new version of this contract.

## 1. Rules

- **No account sign-in adds a device.** A new device joins an account only by a confirmation on a verified device of the account, with the safety words of section 7 and a fresh owner check (`OwnerAction::ConfirmConnectDevice`, Touch ID or the passphrase). The confirming device signs the `add` entry of the account's signed device list for the new key (section 7.5); a client accepts a device only when the list holds it, and only a list that it verified from the account's first key, which the client pinned. There is no password, no email sign-in, and no web sign-in.
- **No answer of Connect removes a device from itself.** A refused sign-in is never a removal. Only the signed-in answer `403 device_removed` (section 6) says that a device was removed, and even then the device keeps its key and its vault rows until its owner confirms "Forget This Mac" (or iPhone) on it.
- The account has no secret on Connect. Connect holds public keys (also the account's public recovery key), the signed device lists, names, ids, hashes, and the Stripe ids of [connect-billing-v1](connect-billing-v1.md). It never holds a private key, a link code, a recovery code, a passphrase, a vault key, an item key, or a value.
- The relay-sync-v1 wire does not change. A vault store is a relay-sync-v1 team; its endpoints, heads, chain, receipts, and errors are those of relay-sync-v1.
- Requests are strict: every request body rejects unknown, duplicate, and missing fields (`deny_unknown_fields`) with `400 invalid_request`. A client ignores unknown fields in a result. Enumerations reject unknown values.
- The account routes exist only when the relay runs with `APASSY_RELAY_CONNECT_ACCOUNTS=1` or `APASSY_RELAY_MODE=connect`. Without them every route of this contract answers `404 not_found`.

## 2. Encodings

The encodings of relay-sync-v1 section 2 apply: b64u without padding, lowercase hex, the P-256 public key in X9.63 uncompressed form (65 bytes, first byte `0x04`), ECDSA P-256 SHA-256 signatures in ASN.1 DER (at most 72 bytes) as b64u, times as Unix seconds, the JSON envelope `{"ok":true,"result":…}` or `{"ok":false,"error":{"code":…,"message":…}}`.

| Value | Form |
| --- | --- |
| Account id | `acc_` and 10 characters of `a-z2-7` (14 characters), made by the first device (section 6) |
| Account device id | `dev_` and 10 characters of `a-z2-7`. It is the `key_id` of plan 0035 I-1, I-3, and I-4 |
| Group id | `grp_` and 10 characters of `a-z2-7` ([connect-billing-v1](connect-billing-v1.md)) |
| Vault store id | a relay-sync-v1 team id, `t_` and 10 characters of `a-z2-7`, of the team kind `account` |
| Store device id | the relay-sync-v1 device number of an account device inside one vault store (JSON number) |
| Account token | `apassy_act_<account id>_<64 hex>` |
| Link code | `apassy_alk_<account id>_<64 hex>_<link fingerprint>` (123 characters), made by the device that adds a device; it never reaches Connect |
| Link fingerprint | 32 lowercase hex: the first 16 bytes of `SHA-256("apassy-connect link-keys v1" 0x00 <root key, 65 raw bytes> 0x00 <confirming device's key, 65 raw bytes>)`. The root key is the account's first key as the making device pinned it (section 7.5) |
| Link hash | b64u of `SHA-256("apassy-connect link v1" 0x00 <link code>)`, 43 characters |
| Recovery code | 16 random bytes. Shown as 16 words (`WORDS[byte]`, relay-sync-v1 section 16); a device may also accept the text `apassy_rec_<32 hex>`. It never leaves the device where it is made or typed |
| Recovery key | The Ed25519 key pair of the seed `SHA-256("apassy-connect recovery key v1" 0x00 <16 bytes>)`. On the wire: b64u of the 32-byte public key (43 characters). Signatures: b64u of 64 bytes |
| Device-list entry | One version of the signed device list (section 7.5): `{"version","op","key","link_hash","name","by","signature"}`; `name` is the device name of a `root` or an `add` (else `null`); `signature` is b64u of a DER ECDSA signature by `by` over the `apassy-connect device-list v1` message (section 5) |
| Key fingerprint | What an owner check and Settings show of a device key: the first 6 bytes of the SHA-256 of its 65 raw bytes, as three groups of four lowercase hex characters (`1a2b 3c4d 5e6f`) |
| List hash | b64u of the SHA-256 of the message of a device-list entry, 43 characters. The next entry names it |
| Vault id | the UUID of `sync_meta.vault_id`, 36 lowercase characters |
| Platform | `mac`, `iphone`, or `linux` |
| Names | a person's name and a device name: 1 to 64 bytes of UTF-8 without a control character, trimmed |

## 3. Transport

- The Connect origin follows relay-sync-v1 section 3 (`https://` anywhere, `http://` on loopback only, no path). The hosted origin is `https://apassy-relay.wyderka.cc`.
- The **edge endpoints** carry no `Authorization` header (Connect refuses a bearer there with `400 invalid_request`): `POST /v1/account`, `POST /v1/account/challenge`, `POST /v1/account/token`, `POST /v1/account/devices/join`, `POST /v1/account/devices/join/cancel`, `POST /v1/account/recover`, and `GET /.well-known/apassy-connect.json`.
- Every other route of this contract needs `Authorization: Bearer <account token>` and answers `401 unauthenticated` without a valid one. A token of a revoked device is not valid: `401 unauthenticated`, from the moment of the revoke (section 7.4). A relay-sync team token on one of these routes is `403 account_required`.
- **The account token goes only to the Connect origin** (plan 0035 I-2). A client MUST NOT send it to the bouncer brain, a node, the push gateway, the site, or Stripe, and MUST NOT write it to disk or into a vault. It lives 15 minutes in memory (`Zeroizing`).
- The Worker limits by client address: `POST /v1/account` and `POST /v1/account/recover` with `ACCOUNT_LIMITER` (namespace 1006, 5 a minute); `POST /v1/account/challenge`, `POST /v1/account/token`, `POST /v1/account/devices/join`, and `POST /v1/account/devices/join/cancel` with the existing `AUTH` limiter. A refusal is `429 rate_limited` with `Retry-After: 60`. On `POST /v1/account` and `POST /v1/account/recover` the Worker also sends the coarse client prefix with its HMAC (`X-Apassy-Client-Prefix`, `X-Apassy-Client-Prefix-Mac`, the scheme of `POST /v1/connect`). Connect takes a prefix only with a valid HMAC. A new account without one counts for the caps of the relay only: behind the Worker every call carries the edge secret, and the Worker proves each call it forwards. A failed recovery without one counts for the prefix `unknown` (section 13).
- A JSON request body is at most 64 KiB.

| Route | Auth | Section |
| --- | --- | --- |
| `POST /v1/account` | edge | 6 |
| `POST /v1/account/challenge`, `POST /v1/account/token` | edge | 6 |
| `GET /v1/account`, `DELETE /v1/account` | account token | 6 |
| `POST /v1/account/devices/link`, `GET /v1/account/devices/pending` | account token | 7.1 |
| `POST /v1/account/devices/pending/{join_id}/confirm`, `…/refuse` | account token, the device that made the link | 7.1 |
| `POST /v1/account/devices/join`, `POST /v1/account/devices/join/cancel` | edge | 7.2 |
| `DELETE /v1/account/devices/{device_id}` | account token | 7.4 |
| `POST /v1/account/vaults`, `GET /v1/account/vaults` | account token | 8 |
| `POST /v1/account/vaults/{team_id}/devices`, `DELETE /v1/account/vaults/{team_id}` | account token, a device in the store (for the deletion: of the account that made it) | 8 |
| `POST /v1/account/recover` | edge | 9 |
| `GET /v1/account/entitlement`, `GET /.well-known/apassy-connect.json` | account token; edge | 10 |
| `POST /internal/v1/brain/device` | service token, internal listener | 11 |

## 4. Errors

The relay-sync-v1 codes keep their meaning: `invalid_request` 400, `unauthenticated` 401, `token_expired` 401, `forbidden` 403, `join_pending` 403, `join_refused` 403, `not_found` 404, `method_not_allowed` 405, `conflict` 409, `payload_too_large` 413, `rate_limited` 429, `relay_error` 500, `busy` 503. A client never takes `401` for a removal (section 6). Connect adds:

| Status | Code | When | Contract |
| --- | --- | --- | --- |
| 403 | `device_removed` | `POST /v1/account/token` with a valid nonce and a valid signature, for a key that was a device of the account and is not live any more (revoked, or the account was deleted). Only the device itself can cause this answer | this |
| 403 | `account_required` | A route of Connect that needs an account token, called with a relay-sync team token. A token of a revoked device is `401 unauthenticated` (section 3), and a team id that is not a vault store is `404 not_found` (section 8) | this |
| 403 | `not_in_group` | A device of another account is named for a vault store, a group route, or a dial, and the two accounts share no group (or no tunnel grant) | this, billing, tunnel |
| 403 | `plan_required` | The account is not entitled for the action: a new vault store, a push to a store, the entitlement token, a dial. A checkout by a member of a group is `409 conflict` ([connect-billing-v1](connect-billing-v1.md) section 4) | this, billing, tunnel |
| 403 | `account_limit` | A count limit of section 13: devices, vault stores, nodes | this, tunnel |
| 409 | `seat_limit` | Seats or people below the confirmed members, or above the maximum of the plan | billing |
| 429 | `tunnel_limit` | Open streams, dials a minute, or the monthly byte budget of the account | tunnel |
| 404 | `node_unknown` | A dial or a grant names a node that does not exist | tunnel |
| 503 | `tunnel_offline` | The node exists and has no open tunnel | tunnel |
| 410 | `free_connect_ended` | `POST /v1/connect` (the free questions-only Connect of ADR 0032), its challenge, and the questions, feed, and push routes of a free Connect team, while `APASSY_RELAY_FREE_CONNECT=0` | this |
| 410 | `hosted_retired` | In `APASSY_RELAY_MODE=connect`: a retired route of section 14 | this |

A `403 plan_required` and a `403 account_required` never carry a price, a link, or a purchase hint: the iPhone shows them as "Not on Connect" ([connect-billing-v1](connect-billing-v1.md) section 10).

## 5. Messages and domain tags

Every signed message is its parts joined with one `0x00` byte, no trailing `0x00`, no newline (the form of relay-sync-v1 section 5). `origin` is the Connect origin without a trailing slash; Connect compares it with its own public URL, so a signature for one Connect is worthless at another.

| Tag | Message | Signed by | Used by |
| --- | --- | --- | --- |
| `apassy-connect account v1` | tag, origin, public key b64u, recovery key b64u | the new account device | `POST /v1/account` |
| `apassy-connect sign-in v1` | tag, origin, account id, public key b64u, nonce b64u | an account device | `POST /v1/account/token` |
| `apassy-connect join v1` | tag, origin, account id, link hash, public key b64u | the joining device | `POST /v1/account/devices/join` |
| `apassy-connect join-cancel v1` | tag, origin, account id, link hash, public key b64u | the joining device | `POST /v1/account/devices/join/cancel` |
| `apassy-connect device-list v1` | tag, origin, account id, version (decimal), previous (the list hash of the entry before, or `-` for version 1), op (`root`, `add`, or `remove`), key b64u, link hash (of an `add`, else `-`), name (the device name of a `root` or an `add`, else `-`), by (the signing key b64u) | the root key itself for the `root` entry; a device of the list: the confirming device for an `add`, the revoking device for a `remove` | `POST /v1/account` and `POST /v1/account/recover` (the `root`), `POST /v1/account/devices/pending/{join_id}/confirm` and `DELETE /v1/account/devices/{device_id}`: the entries of the device list (section 7.5) |
| `apassy-connect recover v1` | tag, origin, account id, the new device's public key b64u, the new recovery key b64u | the recovering device, and the old recovery key (Ed25519) | `POST /v1/account/recover` |
| `apassy-bouncer sign-in v1` | tag, brain origin, account id, public key b64u, nonce b64u | an account device | the brain's sign-in (plan 0035 A; bouncer-brain-v1 section 1) |
| `apassy-relay sign-in v1` | relay-sync-v1 section 5, with the vault store id as the team id | an account device in the store | relay-sync-v1 team sign-in |
| `apassy-relay-sync-head-v1` | the first line of a relay-sync-v1 head (section 8) | an account device in the store | relay-sync-v1 pushes |
| `apassy-connect entitlement v1` | tag, payload b64u (section 10) | Connect's signing key (Ed25519) | the entitlement token |

Hashes that are not signatures: `apassy-connect link v1` (the link hash), `apassy-connect link-keys v1` (the link fingerprint), `apassy-connect safety v1` (section 7.3), `apassy-connect recovery key v1` (the seed of the recovery key), and the list hash (the SHA-256 of an `apassy-connect device-list v1` message, section 2).

**The account device key** is one P-256 key for each physical device, made on the device and kept outside every vault: on the Mac a Keychain item through `NativeHelper` (this device only, not synchronizable, the pattern of `src/node/master_key.rs`), on the iPhone the Keychain of `ApassyCompanionKit`, on Linux a file with mode 0600. The client signs with it **only** messages that begin with one of the nine ECDSA tags of the table (plan 0035 I-1: `connect::sign` has an allow-list that contains `apassy-bouncer sign-in v1`); it refuses any other message. The recovery key is not the device key: it exists only while a recovery code is shown or typed. A vault store's relay-sync rows on the Mac point at this key (`relay_device.key_source = 'account'`, M1) and hold no private key.

## 6. Account and sign-in

### `POST /v1/account` (edge)

```json
{"account_id":"acc_k7m2q4x3ca","name":"Rafal","device_name":"MacBook Pro","platform":"mac","public_key":"<b64u>","recovery_key":"<b64u>","signature":"<b64u>","statement":"<b64u>"}
```

- `signature` is over the `apassy-connect account v1` message, which covers the recovery key. `recovery_key` is the public recovery key of a recovery code that the device made (section 9).
- `account_id` is the id of the new account, made by the device (section 2): the root entry names it. `statement` is the root entry of the device list (section 7.5): the new device key's signature over the `apassy-connect device-list v1` message of version 1 with previous `-`, op `root`, its key, link `-`, `device_name` as Connect keeps it (trimmed), and its key as `by`. A statement that does not verify, or an id of another form, is `400 invalid_request`, and nothing is made. An id that exists is `409 conflict`: the device makes another id and signs again.
- The first device is the one that creates the account: the **root** of its device list (section 7.5). Creation is free and needs no plan. Over the account caps of section 13 the answer is `503 busy` with `Retry-After: 3600`, or `429 rate_limited` for a client prefix.
- A key is a device of at most one account. The same body again within 10 minutes (a retry after a lost answer) answers the same result; the same key with another body, or later, is `409 conflict`.
- Answer: `{"account_id":"acc_k7m2q4x3ca","device_id":"dev_m2k7q3x4ab","created_at":1790000000}`, the account id of the body. The Mac then shows the recovery code once (section 9) and signs in.

### `POST /v1/account/challenge` and `POST /v1/account/token` (edge)

`POST /v1/account/challenge` with `{"account_id":"…","public_key":"<b64u>"}` answers `{"nonce":"<b64u of 32 bytes>","expires_at":1790000060,"origin":"https://apassy-relay.wyderka.cc"}`. The nonce lives 60 s and works once. Connect keeps no state for a nonce until it is used: the nonce carries its expiry and a MAC of Connect over the account and the key (12 random bytes, the expiry as 4 bytes big-endian, 16 bytes of HMAC-SHA256 under a key of the running relay), so a challenge never ends another challenge of the same key, and any number of challenges costs Connect no memory. A restart of Connect ends every open nonce. The client stops when `origin` differs from its configured origin. For a key whose join waits, the answer is `403 join_pending`; for a key whose join was refused or expired, `403 join_refused`; a key that is or was a device of that account (live, revoked, or of a deleted account) gets a nonce; for any other key, `401 unauthenticated`.

`POST /v1/account/token` with `{"account_id":"…","public_key":"<b64u>","nonce":"<b64u>","signature":"<b64u>"}`, the signature over the `apassy-connect sign-in v1` message, answers `{"token":"apassy_act_<account id>_<64 hex>","expires_at":1790000900,"account_id":"…","device_id":"dev_…"}`. In this order:

1. A nonce that is not one of this Connect for this account and key, an expired nonce, a wrong origin, or a wrong signature: `401 unauthenticated`, one message for every cause. The nonce is not used up.
2. A key that was a device of the account and is not live any more (revoked, or the account was deleted): `403 device_removed`. Connect gives this answer only to a request that the device itself signed.
3. A nonce that was used: `401 unauthenticated`. A full table of tokens: `503 busy`, and the nonce stays unused. Else the nonce is used up with the token.

**The client never takes a refusal for a removal.** After a `401` or a `503` of `POST /v1/account/token` it takes a fresh challenge and tries again, at most three times, 1 s and then 3 s apart; it never repeats a token request with the same nonce. Only `403 device_removed` shows "Connect says this device was removed from the account", and the device then keeps its key, its account file, and its vault rows until the owner confirms "Forget This Mac" (or iPhone) on it.

### `GET /v1/account`

Answers the `AccountView`:

```json
{"account_id":"acc_…","name":"Rafal","email":null,"created_at":1790000000,"plan":{…},"devices":[{…}],"group":null,"device_list":[{…}]}
```

- `email` is the email of the Stripe customer, copied by Connect after `checkout.session.completed` ([connect-billing-v1](connect-billing-v1.md) section 7), else `null`. Connect sends no mail in stage 7.
- `plan` is the `PlanView` of [connect-billing-v1](connect-billing-v1.md) section 8. `group` is `null` or `{"group_id":"grp_…","kind":"family|team","role":"owner|admin|member","state":"pending|active"}`.
- `devices` lists the live devices as `DeviceView`s: `{"device_id":"dev_…","name":"MacBook Pro","platform":"mac","public_key":"<b64u>","created_at":1790000000,"last_seen_at":1790002800}`. `last_seen_at` is rounded down to the hour, or `null`. Whether a listed device is a device of the account is the device list's to say, not this list's.
- `device_list` is the signed device list of the account from version 1 (section 7.5).

The Mac polls this route every 3 s while the checkout sheet is open ([connect-billing-v1](connect-billing-v1.md) section 4).

### `DELETE /v1/account`

From a live device after an owner check on it (`OwnerAction::DeleteConnectAccount`), with an empty JSON body `{}`. Connect cancels the subscription at once ([connect-billing-v1](connect-billing-v1.md) section 9), deletes every vault store, device, link, grant, and node of the account, records I-4 `forget` (section 11), and keeps the Stripe customer for the invoices. Answer: `{"account_id":"acc_…","deleted_stores":2,"subscription_canceled":true}`. An organizer or a Team owner with confirmed members is refused with `409 conflict` until the members are removed.

## 7. Account devices

### 7.1 The existing device: "Add a device…"

1. The device makes a link code (32 random bytes and the link fingerprint of its pinned root key and its own key, section 2) and keeps it in memory. `POST /v1/account/devices/link` with `{"link_hash":"<b64u>"}` answers `{"link_id":7,"expires_at":1790000600}`. The link works once and for 10 minutes. The device shows the code as text with a Copy button and as a QR code of the same text (error correction M). Connect never sees the code.
2. While the sheet is open the device asks `GET /v1/account/devices/pending` every 5 s: `[{"join_id":4,"link_id":7,"device_name":"iPhone","platform":"iphone","public_key":"<b64u>","created_at":1790000100,"expires_at":1790000600}]`, the joins of links that this device made. For each it computes the safety words (7.3) with the code it holds and shows: `"iPhone" asks to join your Apassy Connect account. Both devices show: audio coyote forest mint magnet apple. Confirm only if the other device shows the same words.`
3. Confirm runs the owner check for `OwnerAction::ConfirmConnectDevice`, reads the account and verifies its device list (section 7.5), and then `POST /v1/account/devices/pending/{join_id}/confirm` with `{"public_key":"<b64u>","version":3,"statement":"<b64u>"}`: the key for which it computed the words, and the `add` entry of the device list that it signs for that key, the link hash of its link, and the device name of the pending join as the sheet showed it, at the version after the head that it verified, over that head's list hash. Connect verifies the entry with the `device_name` of the pending join as it answers it. A list that is nearly full answers `403 account_limit` (7.5). Connect checks the entry with the confirming device's key and its own head (`400 invalid_request` when it does not verify; `409 conflict` when `version` is not the head's version and 1: the device reads the list again and signs once more), adds exactly that key with the entry, both in one transaction; a pending join whose key differs is `409 conflict`; each refusal adds nothing. Only the device that made the link may confirm or refuse (else `403 forbidden`). Answer: the new device's `DeviceView`. The confirming device pins the entry it signed as its new head.
4. Refuse: `POST /v1/account/devices/pending/{join_id}/refuse` with `{}` answers `{"join_id":4}`.

### 7.2 The new device

1. It reads the code (paste or QR), takes the account id from it, makes its account device key, and computes the link hash.
2. `POST /v1/account/devices/join` (edge) with `{"account_id":"…","link_hash":"<b64u>","device_name":"iPhone","platform":"iphone","public_key":"<b64u>","signature":"<b64u>"}`, the signature over the `apassy-connect join v1` message. Answer: `{"join_id":4,"account_id":"…","confirmer":{"device_id":"dev_…","name":"MacBook Pro","public_key":"<b64u>"},"expires_at":1790000600,"device_list":[…]}`. An unknown, used, or expired link: `403 forbidden`. The same body again answers the same confirmer and the list as it is then.
3. It checks the confirmer: the link fingerprint of the root of `device_list` (the key of its version 1) and of `confirmer.public_key` must be the fingerprint in the code, the list must verify from that root (section 7.5), and the confirmer must be a device of it. Any other key, root, or list ends the join: the device cancels it and says that the code does not match the device that answered. It pins that root and that list, computes the words with the confirmer's key, and shows: `Waiting for MacBook Pro… Both devices show: audio coyote forest mint magnet apple.`
4. Every 5 s it asks `POST /v1/account/challenge` for its key: `403 join_pending` waits, `403 join_refused` ends, a nonce means confirmed: it signs in and reads `GET /v1/account`. It pins only a list that verifies from the root of step 3, goes on from the list of step 3, and holds its own `add`, signed by the confirmer of step 3 with the link hash of its code; any other list ends the join here, and no account file is written. A read that fails on the way waits for the next poll.
5. Cancel before the confirmation: `POST /v1/account/devices/join/cancel` (edge) with `{"account_id":"…","link_hash":"<b64u>","public_key":"<b64u>","signature":"<b64u>"}`, the signature of the joining key over the `apassy-connect join-cancel v1` message (`400 invalid_request` without a valid one), answers `{"join_id":4}`.

### 7.3 Safety words

Both devices compute

```
SHA-256("apassy-connect safety v1" 0x00 <account id> 0x00 <link code> 0x00 <confirmer public key, 65 raw bytes> 0x00 <joiner public key, 65 raw bytes>)
```

and show `WORDS[digest[0]]` to `WORDS[digest[5]]`, six words of the relay-sync-v1 list (section 16) with one space between them, the six-word form of the ADR 0032 handoff (relay-questions-v1). A typed comparison ignores case and surrounding spaces. The words cover both keys and the code. Connect never knows the code, so it cannot compute the words or make a key whose words match. The code names the confirming device's key (the link fingerprint), so the new device accepts no other confirmer key; a party that has the code (a leaked QR) can change only the joining key, and needs words that equal the words of the person's own new device: one in 2^48 for each key it tries, within the 10 minutes of the link.

### 7.4 Revoke

`DELETE /v1/account/devices/{device_id}` from any live device of the account, after an owner check on that device (`OwnerAction::RevokeConnectDevice`; a device may revoke itself, which is "Forget this device"), with `{"version":4,"statement":"<b64u>"}`: the `remove` entry of the device list for the device's key, signed by the calling device at the version after the head that it verified, over that head's list hash (section 7.5). A client signs it only for a key that the list that it verified holds as a device: it takes the key of the row, shows in the owner check the name that the list signed for that key and its key fingerprint (section 2), and refuses (nothing is sent) a row that its list does not hold, a row whose key is the client's own while its id is not, and the reverse. Connect checks it as the `add` of 7.1 (`409 conflict` for another version, `404 not_found` for a key that the list does not hold, `400 invalid_request` for an entry that does not verify; nothing changes). Answer: `{"device_id":"dev_…","removed_from_stores":2}`. At once, in one transaction with the entry: the device is revoked, its open links end, its node goes, Connect records I-4 `revoke` (section 11), and it leaves every vault store: its store rows go, so its store sign-in is refused from this moment, with a waiting removal for each store file. Then its account token and its relay-sync team tokens end, its node's tunnel closes, and each store file that is open revokes its row; a store whose file is not open (suspended, or a failed open) revokes it when it opens next, and the maintenance pass retries a removal until it is done. The last live device can be revoked, also by itself and at the last version of the list (7.5); the account then needs recovery (section 9). Its entries stay in the device list, so the devices it confirmed stay devices (section 7.5).

### 7.5 The signed device list

The device list of an account is a signed list with a cryptographic root. Connect keeps it and answers it from version 1 in `GET /v1/account` and in the join answer:

```json
"device_list":[
  {"version":1,"op":"root","key":"<b64u>","link_hash":null,"name":"MacBook Pro","by":"<b64u>","signature":"<b64u>"},
  {"version":2,"op":"add","key":"<b64u>","link_hash":"<b64u>","name":"iPhone","by":"<b64u>","signature":"<b64u>"},
  {"version":3,"op":"remove","key":"<b64u>","link_hash":null,"name":null,"by":"<b64u>","signature":"<b64u>"}
]
```

- Version 1 is the root: the first device of the account (after a recovery, the recovering device), with `key` and `by` its key, no link, its device name, and its own signature (the `statement` of section 6 or 9). Its authority is the pin of each device; its signature binds its name.
- Each later version is one change: an `add` (the confirmation of 7.1, with the link hash and the device name of the join) or a `remove` (the revoke of 7.4, also of the signing device itself). `by` signed the `apassy-connect device-list v1` message of the entry (section 5), whose `previous` is the list hash of the entry before. So each entry names the whole history before it, and Connect cannot reorder, drop, or insert an entry without breaking the signatures after it.
- A list verifies from a root when: version 1 is that root, signed by itself over its name; the versions follow each other from 1; each later entry is signed by a device of the list at the version before; an `add` names a link hash, a name (section 2), and a key that the list never held (a key that left is never added again: Connect answers `409 conflict`), at version 246 or lower; a `remove` names a key that is a device of the list and no name. The devices of the list at a version are the keys added and not removed up to it; the name of a device is the name of its `root` or `add`. At most 256 entries. An `add` above version 246 (256 entries less the 10 live devices of section 13) is `403 account_limit`, so every live device can still be removed, the last one by itself, up to version 256; then a recovery starts a new list (section 9). Connect refuses an entry that would break these rules.

Each client keeps in its account file the root key that it pinned when it made the account (its own key), recovered it (its own key), or joined it (the root that the link fingerprint named); the version and the list hash of the newest list that it verified (its **pin**); the devices of that list; and the keys that were devices of it and left (also those that left before this client joined). It never takes another root from Connect. A list counts on a client only when it verifies from the pinned root, is not older than the pin, holds the pinned entry at the pinned version, and holds the client's own key as a device: an older list (a rollback), another history (a fork), or a list without the client's own key counts for nothing, and the client keeps what it had. A new device pins only a list that holds its own `add` by the confirming device that its code named (7.2 step 4). The client then moves its pin to the head of the list, and a device that left the list moves to the keys that left. A device is **verified** when the list that counted holds its key. An unverified device is no device of the account for any decision of the client: it is shown as "Not verified" in Settings › Connect and on the iPhone, it is never added to a vault store, its heads are not accepted in a vault store, and it is never taken as the confirming device of a join. A device that a device of the list confirmed stays a device when its confirmer leaves later: its `add` precedes the `remove`, also on a client that joins after the removal. A client signs an entry only after the head that it verified, and pins the entry that it signed.

**The signers of a vault store** come from the trust store of the client alone, never from an answer of Connect (a group, a store marked `shared`, a device that Connect lists in the store). The current head of a vault store is accepted only when its signer's key is a device of the list that counted, or is a key that left that list (a key that it removed: it was a device of the account), and the head's version is not after the store's anchor: the version that the client had merged of that store when it learned of the removal. Each head of the chain below a head that a device of the list signed is accepted when its signer's key is a device of the list or a key that left it: the device that signed the head above it had taken it. A head of a key that was never a device of the list is refused everywhere. A live device whose own anchor head is signed by a key that left pushes a head of its own over it at its next sync, with the same content; a client whose current head is signed by a key that left, after its anchor (a device that was behind, or a new device without an anchor), waits for it and says "Waiting for another device of this account to sync", and changes nothing. So a store is not stuck on a head that such a device pushed before it left. Connect refuses the store sign-in of a removed device from the commit of the removal (7.4); a running sync on another device takes the removal into its signers with the next list that it verifies: the Mac reads the account at the unlock, every 30 minutes, and within a minute after a sync of a vault store was refused or waits for a device, and its sync of a store does not wait for Connect when the account file is enough (its trust store). The cost: a device from which Connect withheld a removal still takes a later push of the device that left, and its own next head carries that push into a head that the other devices take; the removal reaches it with the next list that it verifies. A device of another account (a member of the same family or team) signs nothing on a client: no step of this version pins the root of another account, so its heads are refused in every store, also in a store that Connect marks `shared`.

A recovery starts a new root and a new list. The devices of the old root were revoked before it (section 9); one of them comes back only by joining again with a link of the recovered device, whose fingerprint names the new root. Connect never moves a client to another root.

## 8. Vault stores

A vault store is a relay-sync-v1 team of kind `account` with `TeamLimits::account(plan)`: `sync_bytes` 64 MiB, 10 devices for each member, no items, no agents, no questions. Its relay-sync endpoints work unchanged with team sign-in `apassy-relay sign-in v1` and the store's team id; the device key is the account device key.

- `POST /v1/account/vaults` with `{"vault_id":"<uuid>","name":"Personal"}` makes the store with the calling device as store device 1 and answers the `VaultStoreView`: `{"team_id":"t_…","vault_id":"…","name":"Personal","created_at":1790000000,"shared":false,"devices":[{"store_device_id":1,"device_id":"dev_…","account_id":"acc_…"}]}`. It needs an entitled plan (`403 plan_required`). The same vault id of the same account again answers the existing store.
- `GET /v1/account/vaults` lists the stores that hold a device of this account, as `VaultStoreView`s.
- A vault store has no device link of relay-sync-v1 section 7: its relay routes other than its sign-in, `GET /v1/me`, `GET /v1/devices`, and the sync routes answer `403 forbidden`. A device of the account gets the copy of a store that lists it: it signs in to the store with the account key, downloads the head, and makes the vault with the passphrase of the copy; a device in the store adds it first (below).
- `POST /v1/account/vaults/{team_id}/devices` with `{"device_id":"dev_…","public_key":"<b64u>"}`, from a device that is already in the store, adds a live device of the same account, or of an active member account of the same group (the store becomes `shared`), and answers `{"store_device_id":2,"device_id":"dev_…","account_id":"acc_…"}`. `public_key` is the key that the calling client verified (section 7.5); a device with another key is `409 conflict` and nothing is added. Any other device (unknown, revoked, or of an account outside the group): `403 not_in_group`. The added device still needs the vault passphrase and merges by relay-sync-v1 sections 6 and 7. A device of another account signs in to the store only while both accounts are active members of one group. Connect checks the device and the group again in the transaction that adds it: a device that was revoked or left the group in the meantime is `403 not_in_group`, and nothing stays. An Apassy client adds only verified devices of its own account, takes no head of another account's device (section 7.5), and refuses a store that Connect marks `shared` before any request ("Sharing a vault between accounts is not available yet"), so in this version a store syncs between the devices of the account that made it.
- `DELETE /v1/account/vaults/{team_id}`, from a device in the store of the account that made it, deletes the store with its snapshots (an owner check on the Mac) and answers `{"team_id":"t_…"}`. Another caller: `403 forbidden`.
- The relay-sync challenge of a vault store keeps no state until its nonce is used: the form of section 6 with the store id in the place of the account id, still b64u of 32 bytes (relay-sync-v1 does not change). A challenge never ends another one of the same key, a used nonce is refused, and at most 30 used nonces of one key (`429 rate_limited`) and 1000 of one store (`503 busy`) are kept, each with the nonce unused.
- On both `{team_id}` routes a team id that names no vault store (no team, or a relay-sync team of another kind) is `404 not_found`.
- A push to a store of an account that is not entitled answers `403 plan_required` at the place of today's `sync_bytes` check (relay-sync-v1 section 4 order); pulls and downloads follow the plan state of [connect-billing-v1](connect-billing-v1.md) section 8.

## 9. Recovery

The account creation makes a recovery code on the device (16 random bytes) and sends only its public recovery key (section 2). The Mac shows the code once as 16 words with "Save it in another password manager"; it is never stored by Apassy and never sent anywhere.

`POST /v1/account/recover` (edge) with

```json
{"account_id":"acc_…","device_name":"MacBook Air","platform":"mac","public_key":"<b64u>","recovery_key":"<b64u>","signature":"<b64u>","recovery_signature":"<b64u>","statement":"<b64u>"}
```

works only when the account has no live device. The message is `apassy-connect recover v1` (origin, account id, the new device's public key, the new recovery key `recovery_key` of a new code). `signature` is the new device key's signature over it (`400 invalid_request` without a valid one), `recovery_signature` the signature of the account's stored recovery key (Ed25519, 64 bytes), `statement` the root entry of the new device list (section 7.5), signed by the new device key over `device_name` (`400 invalid_request` without a valid one, checked with `signature`). Connect verifies it with the stored public key before any limit (a valid one is never limited), makes the new device the first device and the root of a new device list (section 7.5), deletes every vault store of the account (a new device list cannot verify the old heads), replaces the recovery key, keeps the subscription, and answers `{"account_id":"acc_…","device_id":"dev_…","deleted_stores":2}`. A wrong signature, an unknown account, or an account with a live device: `403 forbidden`, one message for all; a wrong recovery signature and an unknown account have the same limits (section 13) and get the same answers. The same body again within 10 minutes, while the device it made is live, answers the same result (a retry after a lost answer). Limits: section 13.

## 10. The entitlement token

`GET /v1/account/entitlement` answers `{"token":"<payload b64u>.<signature b64u>","expires_at":1790086400}` for an entitled account, else `403 plan_required`.

- The payload is the UTF-8 JSON of the claims, compact: `{"v":1,"kid":"ek_…","acc":"acc_…","plan":"personal|family|team","group":null|"grp_…","feats":["brain","sync","tunnel"],"iat":…,"exp":…}`. `feats` is sorted, without repeats, from `brain`, `sync`, `tunnel`; v1 gives every entitled account all three. `exp` is `iat` + 86400.
- The signature is Ed25519 over `"apassy-connect entitlement v1" 0x00 <payload b64u>` with the Connect signing key (`APASSY_CONNECT_SIGNING_KEY_FILE`, a PKCS#8 file, `ring`).
- `GET /.well-known/apassy-connect.json` (edge) publishes the keys: `{"v":1,"origin":"https://apassy-relay.wyderka.cc","keys":[{"kid":"ek_…","alg":"Ed25519","public_key":"<b64u of 32 bytes>"}]}`. It lists only keys of the configuration: the signing key and the public keys of `APASSY_CONNECT_PUBLISHED_KEYS_FILE` (the next key before a rotation, the previous key for 24 hours after it). A key that leaves that file is dropped at the next start. A signing key signs tokens only after this Connect has published it for one hour, unless it is the first key this Connect ever had; before that `GET /v1/account/entitlement` is `503 busy`. So a rotation adds the new key before tokens use it, and the operator removes the old key 24 hours after the last token signed with it.
- A service checks: two parts, canonical b64u; a known `kid`; the signature; strict claims (unknown fields refused); `v` is 1; `now < exp`; `iat <= now + 300`; `exp - iat <= 86400`; its feature in `feats`; and `acc` equals the account that the service authenticated by other means (the brain: the I-3 answer for the signed-in device). It never calls Connect for a request (ADR 0035 section 5). A plan that ends is refused within 24 hours; I-4 `forget` is the hard removal.
- The token is not a credential for Connect: Connect never accepts it in `Authorization`.
- The Mac sends to the brain only `Authorization: Bearer <the brain's own token>` (from the `apassy-bouncer sign-in v1` sign-in), never the account token (I-2) and no entitlement header. The brain learns the account and its entitlement from the I-3 directory answer at that sign-in ([bouncer-brain-v2](bouncer-brain-v2.md)), and its token lives 15 minutes, so an ended plan is refused at the next sign-in. Other services check the entitlement token as above.

## 11. The bouncer brain (plan 0035 I-1 to I-5)

Status: this version of Connect records the I-4 events (`brain_event`) and serves none of the internal routes. The internal listener, the I-3 route, and the delivery of the I-4 events are a later unit; until it ships, Connect sends nothing to the brain and answers no request of it. The table is the contract of that unit.

| Item | Here |
| --- | --- |
| I-1 device key | The account device key of section 5; `key_id` is the account device id. The brain signs in with `apassy-bouncer sign-in v1`, account id in the place of the team id (vector `brain_sign_in`, section 15). |
| I-2 token | Section 3: the account token stays with the Connect client; the brain issues its own token. |
| I-3 directory | `POST /internal/v1/brain/device` with `{"key_id":"dev_…","public_key_sha256":"<64 hex>"}` answers `{"account":"acc_…","entitled_hosting":true,"entitled_training":true,"revoked":false}`. `public_key_sha256` is the hex SHA-256 of the 65 raw key bytes. `account` is the account id, opaque to the brain. Both entitlements are `"brain" in feats` of the account now (the training consent stays with the brain, J1). A revoked device answers `revoked: true` with both entitlements `false`; an unknown key id, or a hash that differs from the device's key, is `404 not_found`. |
| I-4 events | The routes of the brain: `POST /internal/v1/revoke` with `{"key_id":"dev_…"}` when a device is revoked, and `POST /internal/v1/forget` with `{"account":"acc_…"}` when the plan is deleted (90 days, [connect-billing-v1](connect-billing-v1.md) section 8) or the account is deleted. Both are idempotent. Connect records each event in the directory (`brain_event`) in the transaction of the revoke or the deletion, and prunes it 90 days after its delivery (`done_at`, set at the 2xx); an event that was never delivered stays. The later unit delivers each recorded event until a 2xx; with I-3 the brain also learns a revoke at the next sign-in of the device (`revoked: true`). |
| I-5 origin | The brain is `https://brain.apassy.wyderka.cc` (its own certificate and compose project), not behind the byte relay. The app has the origin as a build constant. |

The internal routes are served only on the internal listener of the Connect host (`APASSY_CONNECT_INTERNAL_LISTEN`, the compose network), never through the Worker, with `Authorization: Bearer <service token>` from the compose secret file `APASSY_CONNECT_BRAIN_TOKEN_FILE`; another caller gets `401 unauthenticated`.

## 12. What Connect stores

In directory 1006 (C1): `account` (id, name, created_at, public recovery key, the last recovery's body hash and answer, email copy, group), `account_device` (id, account, name, platform, public key, the confirming device, created_at, last_seen hour, revoked_at; a revoked row is pruned after 90 days), `account_list` (the signed device list: each entry with its device name, its signature, and its list hash), `account_key` (the hash of every key that was a device, with its account), `account_link` (link hash, creating device, expiry, use; pruned a day after it ends, with its joins), pending joins (key, name, platform, link), pending removals of a device from a vault store file that was not open, `vault_store` (a `team` row of kind `account` with `team.account_id`, vault id, name), the billing rows of [connect-billing-v1](connect-billing-v1.md), `tunnel_grant` and nodes of [connect-tunnel-v1](connect-tunnel-v1.md), `entitlement_key` (kids and public keys, when each was first published and last used; a record, never the source of the published keys), and the I-4 outbox (pruned 90 days after delivery). In `APASSY_RELAY_MODE=connect` these files are plain SQLite: nothing in them is secret. The snapshots in the stores are SQLCipher ciphertext under the user's passphrase.

Never stored: tokens (memory only), nonces (a used nonce is kept in memory until it expires), link codes, recovery codes, the signing key (a file), client addresses and prefixes (memory only, for rate limits), vault content.

## 13. Limits

Chosen defaults; the owner can change each without code.

| Limit | Value |
| --- | --- |
| Live devices of one account | 10 (`account_limit`) |
| Vault stores | 10 for each person (Personal 10; Family 10 for each person; Team 10 for each member) (`account_limit`) |
| Store size | 64 MiB (`sync_bytes`) |
| Open links of one device | 3; a link lives 600 s |
| Pending joins of one link | 1 |
| Account token | 15 minutes; challenges 60 s, no limit on open challenges (they keep no state) |
| Used sign-in nonces | 30 of one key that have not expired, a nonce living 60 s (`429 rate_limited` for that key, its nonce unused; the other keys of the account go on), 100 000 in all (`503 busy`) |
| Device list | 256 entries; an `add` at version 246 at most, so every live device can be removed up to 256 (`account_limit`; a recovery starts a new list). The app says when 20 or fewer versions are left for an `add` |
| New accounts | 1000 a day for the relay (`APASSY_RELAY_CONNECT_ACCOUNTS_PER_DAY`, 0 turns creation off) and 100 000 in all (`APASSY_RELAY_CONNECT_ACCOUNTS_MAX`): `503 busy`; 5 a day for each client prefix: `429 rate_limited` |
| Entitlement token | 24 hours |
| Recovery tries | A valid recovery signature is never limited. Only failures count and are limited: a wrong recovery signature for an existing account counts for the account and for the client prefix: after 5 for the account in an hour, or 20 for the client prefix in an hour (a call without the Worker's proof counts for the prefix `unknown`), a further wrong one is `429 rate_limited`; at most 10 000 accounts and 10 000 prefixes are counted at once (`503 busy` for a new one). A recovery of an account id that names no account counts for that id in a table of its own, with the rule of an existing account (after 5 in an hour a further one is `429 rate_limited`; at most 10 000 ids, `503 busy` for a new one), and for the client prefix, so an unknown and an existing id get the same answers |

## 14. Modes and retired routes

- **Transition** (`APASSY_RELAY_CONNECT_ACCOUNTS=1`): the routes of the three Connect contracts are added to a running relay. With `APASSY_RELAY_FREE_CONNECT=0`, `POST /v1/connect` and `POST /v1/connect/challenge` answer `410 free_connect_ended` before their body is read, and so do the questions, feed, and push routes of a free Connect team (after its token, before its body); its sign-in, devices, leaving, and relay sync stay. With `APASSY_RELAY_CONNECT_SYNC_BYTES=0` as well, a push or a receipt of a free Connect team is `403 plan_required` whatever its own `sync_bytes`, and its pulls work. Teams made with a team code and vault stores are not affected.
- **Connect only** (`APASSY_RELAY_MODE=connect`): no master key (`APASSY_RELAY_KEY` and its file form are refused at start), no push settings, no proxy. These routes answer `410 hosted_retired` before any token or body is read: `POST /v1/connect` and its challenge, `POST /v1/teams`, `POST /v1/join`, `/v1/questions` and below, `/v1/feed` and below, `/v1/push/token`, `/v1/push/handle`, `/mcp`, `/p/` and below, and every other relay route that is not relay-sync-v1 of a vault store (its sign-in, `GET /v1/me`, `GET /v1/devices`, and the sync routes). Relay-sync-v1 works only for vault stores. `/healthz` names the mode (`x-apassy-relay-mode`). The relay's SPEC section 37 lists every route.

## 15. Test vectors

`tests/fixtures/connect-account-v1/vectors.json` (made by `generate_vectors.py` in the same directory, with OpenSSL 3). The values are synthetic.

| Name | Value |
| --- | --- |
| Origin | `https://connect.example.test` |
| Account id | `acc_k7m2q4x3ca` |
| Device A | the relay-sync-v1 section 15 key, `dev_m2k7q3x4ab` |
| Device B | private `1c9a5e3f7b2d4a6c8e0f1a3b5c7d9e2f4a6b8c0d1e3f5a7b9c2d4e6f8a1b3c5d`, `dev_p4n6r2t7bc` |
| Nonce | bytes 0 to 31 |
| Link code | `apassy_alk_acc_k7m2q4x3ca_`, 32 bytes `0xcd` in hex, `_`, and the link fingerprint of device A as root and as confirming device |
| Safety words (A confirms, B joins) | `audio coyote forest mint magnet apple` |
| Recovery code | bytes 16 to 31, `apassy_rec_101112131415161718191a1b1c1d1e1f`; its recovery key; the new recovery code of the recovery vector is bytes 64 to 79 |
| Entitlement key | Ed25519 seed bytes 32 to 63, kid `ek_test_1` |

`vectors.json` holds for each message its exact bytes (b64u), its SHA-256, and an ECDSA signature that verifies with the signer's public key (the recovery message also its Ed25519 signature by the recovery key); the device list of A as the root, A's `add` of B (version 2), and A's `remove` of B (version 3), with the list hash of each version and the devices at each; the link fingerprint, the link code, and its hash; the safety hash and words; the recovery words, seed, and public key; and two entitlement tokens (Personal; a Family member) with their payloads and Ed25519 signatures. `examples.json` holds one example of every request and result body of this contract, and the error bodies.

Both suites must show: each message is the join of its parts and starts with its tag; each signature verifies over its message with its signer's key and fails over a message with one changed byte; the link fingerprint, the link hash, the safety words, and the recovery key are reproduced from their inputs; the device list verifies from A as the root, holds B at version 2 and not at version 3, and a device that pinned version 3 refuses the list of version 2; each entitlement token verifies with the published key and fails with a changed claim, after `exp`, or with another key; every example parses with strict types. The app's tests: M1 (`tests/connect_account.rs`); the relay's: C1 (`tests/server_account.rs`); the fixture check: `contracts::connect_account_v1_fixtures_match_the_contract`.
