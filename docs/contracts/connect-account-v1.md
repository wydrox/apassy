# Connect account contract v1

Date: 2026-11-03. Status: proposed, for ADR 0037 stage 7 (unit D1 of [the stage 7 plan](../design/implementation-plan-s7-connect.md)). Not implemented. The relay side is C1 (`crates/apassy-relay/src/server/account.rs`), the Mac side M1 (`src/connect/`), the iPhone side I1 (`ios/ApassyCore/src/core/connect.rs`), the bouncer brain side H of [plan 0035](../design/implementation-plan-0035.md) (`entitlements.py`). Synthetic vectors in section 15 include exact message bytes, ECDSA and Ed25519 signatures, the safety words, and the recovery hash.
Decision: [ADR 0037](../adr/0037-own-relay-open-source.md) sections 1 and 7, stage 7, D2, D3; [ADR 0035](../adr/0035-bouncer-hosting-and-training-choice.md) decision 6 and section 2; [ADR 0019](../adr/0019-relay-teams-and-accounts.md) (device identity); [plans](../product/plans.md) section 3.

This contract defines Connect accounts: account creation, account devices and their sign-in, the device link with safety words, vault stores (one [relay-sync-v1](relay-sync-v1.md) team for each vault), recovery, the entitlement token for other Connect services, and the internal routes of the hosted bouncer brain. Billing and groups are [connect-billing-v1](connect-billing-v1.md); the byte relay is [connect-tunnel-v1](connect-tunnel-v1.md). MUST and MUST NOT below are requirements on both sides. A change to a message, a field, or a check needs a new version of this contract.

## 1. Rules

- **No account sign-in adds a device.** A new device joins an account only by a confirmation on a live device of the account, with the safety words of section 7 and a fresh owner check (`OwnerAction::ConfirmConnectDevice`, Touch ID or the passphrase). There is no password, no email sign-in, and no web sign-in.
- The account has no secret on Connect. Connect holds public keys, names, ids, hashes, and the Stripe ids of [connect-billing-v1](connect-billing-v1.md). It never holds a private key, a link code, a recovery code, a passphrase, a vault key, an item key, or a value.
- The relay-sync-v1 wire does not change. A vault store is a relay-sync-v1 team; its endpoints, heads, chain, receipts, and errors are those of relay-sync-v1.
- Requests are strict: every request body rejects unknown, duplicate, and missing fields (`deny_unknown_fields`) with `400 invalid_request`. A client ignores unknown fields in a result. Enumerations reject unknown values.
- The account routes exist only when the relay runs with `APASSY_RELAY_CONNECT_ACCOUNTS=1` or `APASSY_RELAY_MODE=connect`. Without them every route of this contract answers `404 not_found`.

## 2. Encodings

The encodings of relay-sync-v1 section 2 apply: b64u without padding, lowercase hex, the P-256 public key in X9.63 uncompressed form (65 bytes, first byte `0x04`), ECDSA P-256 SHA-256 signatures in ASN.1 DER (at most 72 bytes) as b64u, times as Unix seconds, the JSON envelope `{"ok":true,"result":…}` or `{"ok":false,"error":{"code":…,"message":…}}`.

| Value | Form |
| --- | --- |
| Account id | `acc_` and 10 characters of `a-z2-7` (14 characters) |
| Account device id | `dev_` and 10 characters of `a-z2-7`. It is the `key_id` of plan 0035 I-1, I-3, and I-4 |
| Group id | `grp_` and 10 characters of `a-z2-7` ([connect-billing-v1](connect-billing-v1.md)) |
| Vault store id | a relay-sync-v1 team id, `t_` and 10 characters of `a-z2-7`, of the team kind `account` |
| Store device id | the relay-sync-v1 device number of an account device inside one vault store (JSON number) |
| Account token | `apassy_act_<account id>_<64 hex>` |
| Link code | `apassy_alk_<account id>_<64 hex>`, made by the device that adds a device; it never reaches Connect |
| Link hash | b64u of `SHA-256("apassy-connect link v1" 0x00 <link code>)`, 43 characters |
| Recovery code | 16 random bytes. Shown as 16 words (`WORDS[byte]`, relay-sync-v1 section 16), on the wire `apassy_rec_<32 hex>` |
| Recovery hash | hex of `SHA-256("apassy-connect recovery v1" 0x00 <16 bytes>)` |
| Vault id | the UUID of `sync_meta.vault_id`, 36 lowercase characters |
| Platform | `mac`, `iphone`, or `linux` |
| Names | a person's name and a device name: 1 to 64 bytes of UTF-8 without a control character, trimmed |

## 3. Transport

- The Connect origin follows relay-sync-v1 section 3 (`https://` anywhere, `http://` on loopback only, no path). The hosted origin is `https://apassy-relay.wyderka.cc`.
- The **edge endpoints** carry no `Authorization` header (Connect refuses a bearer there with `400 invalid_request`): `POST /v1/account`, `POST /v1/account/challenge`, `POST /v1/account/token`, `POST /v1/account/devices/join`, `POST /v1/account/devices/join/cancel`, `POST /v1/account/recover`, and `GET /.well-known/apassy-connect.json`.
- Every other route of this contract needs `Authorization: Bearer <account token>` and answers `401 unauthenticated` without a valid one.
- **The account token goes only to the Connect origin** (plan 0035 I-2). A client MUST NOT send it to the bouncer brain, a node, the push gateway, the site, or Stripe, and MUST NOT write it to disk or into a vault. It lives 15 minutes in memory (`Zeroizing`).
- The Worker limits by client address: `POST /v1/account` and `POST /v1/account/recover` with `ACCOUNT_LIMITER` (namespace 1006, 5 a minute); `POST /v1/account/challenge`, `POST /v1/account/token`, `POST /v1/account/devices/join`, and `POST /v1/account/devices/join/cancel` with the existing `AUTH` limiter. A refusal is `429 rate_limited` with `Retry-After: 60`.
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
| `POST /v1/account/vaults/{team_id}/devices`, `DELETE /v1/account/vaults/{team_id}` | account token, a device in the store | 8 |
| `POST /v1/account/recover` | edge | 9 |
| `GET /v1/account/entitlement`, `GET /.well-known/apassy-connect.json` | account token; edge | 10 |
| `POST /internal/v1/brain/device` | service token, internal listener | 11 |

## 4. Errors

The relay-sync-v1 codes keep their meaning: `invalid_request` 400, `unauthenticated` 401, `token_expired` 401, `forbidden` 403, `join_pending` 403, `join_refused` 403, `not_found` 404, `method_not_allowed` 405, `conflict` 409, `payload_too_large` 413, `rate_limited` 429, `relay_error` 500, `busy` 503. Connect adds:

| Status | Code | When | Contract |
| --- | --- | --- | --- |
| 403 | `account_required` | A route of Connect that needs a live account device, called with a relay-sync team token, a token of a revoked device, or for a vault store that is not of kind `account` | this |
| 403 | `not_in_group` | A device of another account is named for a vault store, a group route, or a dial, and the two accounts share no group (or no tunnel grant) | this, billing, tunnel |
| 403 | `plan_required` | The account is not entitled for the action: a new vault store, a push to a store, the entitlement token, a dial, a checkout of a group member | this, billing, tunnel |
| 403 | `account_limit` | A count limit of section 13: devices, vault stores, nodes | this, tunnel |
| 409 | `seat_limit` | Seats or people below the confirmed members, or above the maximum of the plan | billing |
| 429 | `tunnel_limit` | Open streams, dials a minute, or the monthly byte budget of the account | tunnel |
| 404 | `node_unknown` | A dial or a grant names a node that does not exist | tunnel |
| 503 | `tunnel_offline` | The node exists and has no open tunnel | tunnel |
| 410 | `free_connect_ended` | `POST /v1/connect` (the free questions-only Connect of ADR 0032) while `APASSY_RELAY_FREE_CONNECT=0` | this |
| 410 | `hosted_retired` | In `APASSY_RELAY_MODE=connect`: a retired route of section 14 | this |

A `403 plan_required` and a `403 account_required` never carry a price, a link, or a purchase hint: the iPhone shows them as "Not on Connect" ([connect-billing-v1](connect-billing-v1.md) section 10).

## 5. Messages and domain tags

Every signed message is its parts joined with one `0x00` byte, no trailing `0x00`, no newline (the form of relay-sync-v1 section 5). `origin` is the Connect origin without a trailing slash; Connect compares it with its own public URL, so a signature for one Connect is worthless at another.

| Tag | Message | Signed by | Used by |
| --- | --- | --- | --- |
| `apassy-connect account v1` | tag, origin, public key b64u | the new account device | `POST /v1/account` |
| `apassy-connect sign-in v1` | tag, origin, account id, public key b64u, nonce b64u | an account device | `POST /v1/account/token` |
| `apassy-connect join v1` | tag, origin, account id, link hash, public key b64u | the joining device | `POST /v1/account/devices/join` |
| `apassy-connect recover v1` | tag, origin, account id, public key b64u | the recovering device | `POST /v1/account/recover` |
| `apassy-bouncer sign-in v1` | tag, brain origin, account id, public key b64u, nonce b64u | an account device | the brain's sign-in (plan 0035 A; bouncer-brain-v1 section 1) |
| `apassy-relay sign-in v1` | relay-sync-v1 section 5, with the vault store id as the team id | an account device in the store | relay-sync-v1 team sign-in |
| `apassy-relay-sync-head-v1` | the first line of a relay-sync-v1 head (section 8) | an account device in the store | relay-sync-v1 pushes |
| `apassy-connect entitlement v1` | tag, payload b64u (section 10) | Connect's signing key (Ed25519) | the entitlement token |

Hashes that are not signatures: `apassy-connect link v1` (the link hash), `apassy-connect safety v1` (section 7.3), `apassy-connect recovery v1` (the recovery hash).

**The account device key** is one P-256 key for each physical device, made on the device and kept outside every vault: on the Mac a Keychain item through `NativeHelper` (this device only, not synchronizable, the pattern of `src/node/master_key.rs`), on the iPhone the Keychain of `ApassyCompanionKit`, on Linux a file with mode 0600. The client signs with it **only** messages that begin with one of the seven ECDSA tags of the table (plan 0035 I-1: `connect::sign` has an allow-list that contains `apassy-bouncer sign-in v1`); it refuses any other message. A vault store's relay-sync rows on the Mac point at this key (`relay_device.key_source = 'account'`, M1) and hold no private key.

## 6. Account and sign-in

### `POST /v1/account` (edge)

```json
{"name":"Rafal","device_name":"MacBook Pro","platform":"mac","public_key":"<b64u>","recovery_hash":"<64 hex>","signature":"<b64u>"}
```

- `signature` is over the `apassy-connect account v1` message. `recovery_hash` is the hash of a recovery code that the device made (section 9).
- The first device is the one that creates the account. Creation is free and needs no plan.
- A key is a device of at most one account. The same body again within 10 minutes (a retry after a lost answer) answers the same result; the same key with another body, or later, is `409 conflict`.
- Answer: `{"account_id":"acc_k7m2q4x3ca","device_id":"dev_m2k7q3x4ab","created_at":1790000000}`. The Mac then shows the recovery code once (section 9) and signs in.

### `POST /v1/account/challenge` and `POST /v1/account/token` (edge)

`POST /v1/account/challenge` with `{"account_id":"…","public_key":"<b64u>"}` answers `{"nonce":"<b64u of 32 bytes>","expires_at":1790000060,"origin":"https://apassy-relay.wyderka.cc"}`. The nonce lives 60 s, works once, and at most 4 are open for each key. The client stops when `origin` differs from its configured origin. For a key whose join waits, the answer is `403 join_pending`; for a key whose join was refused or expired, `403 join_refused`; for any other key that is not a live device of that account, `401 unauthenticated`.

`POST /v1/account/token` with `{"account_id":"…","public_key":"<b64u>","nonce":"<b64u>","signature":"<b64u>"}`, the signature over the `apassy-connect sign-in v1` message, answers `{"token":"apassy_act_<account id>_<64 hex>","expires_at":1790000900,"account_id":"…","device_id":"dev_…"}`. A used or expired nonce, a wrong origin, a wrong signature, or a revoked key: `401 unauthenticated`, one message for every cause.

### `GET /v1/account`

Answers the `AccountView`:

```json
{"account_id":"acc_…","name":"Rafal","email":null,"created_at":1790000000,"plan":{…},"devices":[{…}],"group":null}
```

- `email` is the email of the Stripe customer, copied by Connect after `checkout.session.completed` ([connect-billing-v1](connect-billing-v1.md) section 7), else `null`. Connect sends no mail in stage 7.
- `plan` is the `PlanView` of [connect-billing-v1](connect-billing-v1.md) section 8. `group` is `null` or `{"group_id":"grp_…","kind":"family|team","role":"owner|admin|member","state":"pending|active"}`.
- `devices` lists the live devices: `{"device_id":"dev_…","name":"MacBook Pro","platform":"mac","public_key":"<b64u>","created_at":1790000000,"last_seen_at":1790002800}`. `last_seen_at` is rounded down to the hour, or `null`.

The Mac polls this route every 3 s while the checkout sheet is open ([connect-billing-v1](connect-billing-v1.md) section 4).

### `DELETE /v1/account`

From a live device after an owner check on it (`OwnerAction::DeleteConnectAccount`), with an empty JSON body `{}`. Connect cancels the subscription at once ([connect-billing-v1](connect-billing-v1.md) section 9), deletes every vault store, device, link, grant, and node of the account, sends I-4 `forget` (section 11), and keeps the Stripe customer for the invoices. Answer: `{"account_id":"acc_…","deleted_stores":2,"subscription_canceled":true}`. An organizer or a Team owner with confirmed members is refused with `409 conflict` until the members are removed.

## 7. Account devices

### 7.1 The existing device: "Add a device…"

1. The device makes a link code (32 random bytes, section 2) and keeps it in memory. `POST /v1/account/devices/link` with `{"link_hash":"<b64u>"}` answers `{"link_id":7,"expires_at":1790000600}`. The link works once and for 10 minutes. The device shows the code as text with a Copy button and as a QR code of the same text (error correction M). Connect never sees the code.
2. While the sheet is open the device asks `GET /v1/account/devices/pending` every 5 s: `[{"join_id":4,"link_id":7,"device_name":"iPhone","platform":"iphone","public_key":"<b64u>","created_at":1790000100,"expires_at":1790000600}]`, the joins of links that this device made. For each it computes the safety words (7.3) with the code it holds and shows: `"iPhone" asks to join your Apassy Connect account. Both devices show: blaze cable flute board seal tiger. Confirm only if the other device shows the same words.`
3. Confirm runs the owner check for `OwnerAction::ConfirmConnectDevice` and then `POST /v1/account/devices/pending/{join_id}/confirm` with `{"public_key":"<b64u>"}`, the key for which it computed the words. Connect adds exactly that key; a pending join whose key differs is `409 conflict` and nothing is added. Only the device that made the link may confirm or refuse (else `403 forbidden`). Answer: the new device's `DeviceView`.
4. Refuse: `POST /v1/account/devices/pending/{join_id}/refuse` with `{}` answers `{"join_id":4}`.

### 7.2 The new device

1. It reads the code (paste or QR), takes the account id from it, makes its account device key, and computes the link hash.
2. `POST /v1/account/devices/join` (edge) with `{"account_id":"…","link_hash":"<b64u>","device_name":"iPhone","platform":"iphone","public_key":"<b64u>","signature":"<b64u>"}`, the signature over the `apassy-connect join v1` message. Answer: `{"join_id":4,"account_id":"…","confirmer":{"device_id":"dev_…","name":"MacBook Pro","public_key":"<b64u>"},"expires_at":1790000600}`. An unknown, used, or expired link: `403 forbidden`. The same body again answers the same result.
3. It computes the words with the confirmer's key and shows: `Waiting for MacBook Pro… Both devices show: blaze cable flute board seal tiger.`
4. Every 5 s it asks `POST /v1/account/challenge` for its key: `403 join_pending` waits, `403 join_refused` ends, a nonce means confirmed: it signs in.
5. Cancel before the confirmation: `POST /v1/account/devices/join/cancel` (edge) with `{"account_id":"…","link_hash":"<b64u>","public_key":"<b64u>"}` answers `{"join_id":4}`.

### 7.3 Safety words

Both devices compute

```
SHA-256("apassy-connect safety v1" 0x00 <account id> 0x00 <link code> 0x00 <confirmer public key, 65 raw bytes> 0x00 <joiner public key, 65 raw bytes>)
```

and show `WORDS[digest[0]]` to `WORDS[digest[5]]`, six words of the relay-sync-v1 list (section 16) with one space between them, the six-word form of the ADR 0032 handoff (relay-questions-v1). A typed comparison ignores case and surrounding spaces. The words cover both keys and the code. Connect never knows the code, so it cannot compute the words or make a key whose words match; a party that has the code (a leaked QR) still needs the confirmer to accept words that differ from the words on the person's own new device.

### 7.4 Revoke

`DELETE /v1/account/devices/{device_id}` from any live device of the account, after an owner check on that device (`OwnerAction::RevokeConnectDevice`; a device may revoke itself, which is "Forget this device"). Answer: `{"device_id":"dev_…","removed_from_stores":2}`. At once: its account token and its relay-sync team tokens end, it is removed from every vault store, its node's tunnel closes, and Connect sends I-4 `revoke` (section 11). The last live device can be revoked; the account then needs recovery (section 9).

## 8. Vault stores

A vault store is a relay-sync-v1 team of kind `account` with `TeamLimits::account(plan)`: `sync_bytes` 64 MiB, 10 devices for each member, no items, no agents, no questions. Its relay-sync endpoints work unchanged with team sign-in `apassy-relay sign-in v1` and the store's team id; the device key is the account device key.

- `POST /v1/account/vaults` with `{"vault_id":"<uuid>","name":"Personal"}` makes the store with the calling device as store device 1 and answers the `VaultStoreView`: `{"team_id":"t_…","vault_id":"…","name":"Personal","created_at":1790000000,"shared":false,"devices":[{"store_device_id":1,"device_id":"dev_…","account_id":"acc_…"}]}`. It needs an entitled plan (`403 plan_required`). The same vault id of the same account again answers the existing store.
- `GET /v1/account/vaults` lists the stores that hold a device of this account, as `VaultStoreView`s.
- `POST /v1/account/vaults/{team_id}/devices` with `{"device_id":"dev_…"}`, from a device that is already in the store, adds a live device of the same account, or of an active member account of the same group (the store becomes `shared`), and answers `{"store_device_id":2,"device_id":"dev_…","account_id":"acc_…"}`. Any other device: `403 not_in_group`. The added device still needs the vault passphrase and merges by relay-sync-v1 sections 6 and 7; a member's device of a shared Family or Team vault joins through the link, the words, and the passphrase (M3).
- `DELETE /v1/account/vaults/{team_id}` deletes the store with its snapshots (an owner check on the Mac) and answers `{"team_id":"t_…"}`.
- A push to a store of an account that is not entitled answers `403 plan_required` at the place of today's `sync_bytes` check (relay-sync-v1 section 4 order); pulls and downloads follow the plan state of [connect-billing-v1](connect-billing-v1.md) section 8.

## 9. Recovery

The account creation makes a recovery code on the device (16 random bytes) and sends only its hash. The Mac shows it once as 16 words with "Save it in another password manager"; it is never stored by Apassy.

`POST /v1/account/recover` (edge) with

```json
{"account_id":"acc_…","recovery":"apassy_rec_<32 hex>","device_name":"MacBook Air","platform":"mac","public_key":"<b64u>","recovery_hash":"<64 hex>","signature":"<b64u>"}
```

works only when the account has no live device. The signature is over `apassy-connect recover v1`; `recovery_hash` is the hash of a new code that replaces the old one. Connect compares the hash of `recovery` in constant time, makes the new device the first device, deletes every vault store of the account (a new device set cannot verify the old chains), keeps the subscription, and answers `{"account_id":"acc_…","device_id":"dev_…","deleted_stores":2}`. A wrong code, or an account with a live device: `403 forbidden`, one message for both. At most 5 tries for each account an hour.

## 10. The entitlement token

`GET /v1/account/entitlement` answers `{"token":"<payload b64u>.<signature b64u>","expires_at":1790086400}` for an entitled account, else `403 plan_required`.

- The payload is the UTF-8 JSON of the claims, compact: `{"v":1,"kid":"ek_…","acc":"acc_…","plan":"personal|family|team","group":null|"grp_…","feats":["brain","sync","tunnel"],"iat":…,"exp":…}`. `feats` is sorted, without repeats, from `brain`, `sync`, `tunnel`; v1 gives every entitled account all three. `exp` is `iat` + 86400.
- The signature is Ed25519 over `"apassy-connect entitlement v1" 0x00 <payload b64u>` with the Connect signing key (`APASSY_CONNECT_SIGNING_KEY_FILE`, a PKCS#8 file, `ring`).
- `GET /.well-known/apassy-connect.json` (edge) publishes the keys: `{"v":1,"origin":"https://apassy-relay.wyderka.cc","keys":[{"kid":"ek_…","alg":"Ed25519","public_key":"<b64u of 32 bytes>"}]}`. A rotation adds the new key before tokens use it and removes the old key 24 hours after the last token signed with it.
- A service checks: two parts, canonical b64u; a known `kid`; the signature; strict claims (unknown fields refused); `v` is 1; `now < exp`; `iat <= now + 300`; `exp - iat <= 86400`; its feature in `feats`; and `acc` equals the account that the service authenticated by other means (the brain: the I-3 answer for the signed-in device). It never calls Connect for a request (ADR 0035 section 5). A plan that ends is refused within 24 hours; I-4 `forget` is the hard removal.
- The token is not a credential for Connect: Connect never accepts it in `Authorization`.
- The Mac sends to the brain `Authorization: Bearer <the brain's own token>` (from the `apassy-bouncer sign-in v1` sign-in) and `X-Apassy-Entitlement: <entitlement token>`, and never the account token (I-2).

## 11. The bouncer brain (plan 0035 I-1 to I-5)

| Item | Here |
| --- | --- |
| I-1 device key | The account device key of section 5; `key_id` is the account device id. The brain signs in with `apassy-bouncer sign-in v1`, account id in the place of the team id (vector `brain_sign_in`, section 15). |
| I-2 token | Section 3: the account token stays with the Connect client; the brain issues its own token. |
| I-3 directory | `POST /internal/v1/brain/device` with `{"key_id":"dev_…","public_key_sha256":"<64 hex>"}` answers `{"account":"acc_…","entitled_hosting":true,"entitled_training":true,"revoked":false}`. `public_key_sha256` is the hex SHA-256 of the 65 raw key bytes. `account` is the account id, opaque to the brain. Both entitlements are `"brain" in feats` of the account now (the training consent stays with the brain, J1). A revoked device answers `revoked: true` with both entitlements `false`; an unknown key id, or a hash that differs from the device's key, is `404 not_found`. |
| I-4 events | Connect calls the brain: `POST /internal/v1/revoke` with `{"key_id":"dev_…"}` when a device is revoked, and `POST /internal/v1/forget` with `{"account":"acc_…"}` when the plan is deleted (90 days, [connect-billing-v1](connect-billing-v1.md) section 8) or the account is deleted. Both are idempotent; Connect keeps each event in the directory and retries until a 2xx (1 minute, doubling, at most 1 hour). |
| I-5 origin | The brain is `https://brain.apassy.wyderka.cc` (its own certificate and compose project), not behind the byte relay. The app has the origin as a build constant. |

The internal routes are served only on the internal listener of the Connect host (`APASSY_CONNECT_INTERNAL_LISTEN`, the compose network), never through the Worker, with `Authorization: Bearer <service token>` from the compose secret file `APASSY_CONNECT_BRAIN_TOKEN_FILE`; another caller gets `401 unauthenticated`.

## 12. What Connect stores

In directory 1007 (C1): `account` (id, name, created_at, recovery hash, email copy, group), `account_device` (id, account, name, platform, public key, created_at, last_seen hour, revoked_at), `account_link` (link hash, creating device, expiry, use), pending joins (key, name, platform, link), `vault_store` (a `team` row of kind `account` with `team.account_id`, vault id, name), the billing rows of [connect-billing-v1](connect-billing-v1.md), `tunnel_grant` and nodes of [connect-tunnel-v1](connect-tunnel-v1.md), `entitlement_key` (kids and public keys only), and the I-4 outbox. In `APASSY_RELAY_MODE=connect` these files are plain SQLite: nothing in them is secret. The snapshots in the stores are SQLCipher ciphertext under the user's passphrase.

Never stored: tokens (memory only), link codes, recovery codes, the signing key (a file), client addresses (memory only, for rate limits), vault content.

## 13. Limits

Chosen defaults; the owner can change each without code.

| Limit | Value |
| --- | --- |
| Live devices of one account | 10 (`account_limit`) |
| Vault stores | 10 for each person (Personal 10; Family 10 for each person; Team 10 for each member) (`account_limit`) |
| Store size | 64 MiB (`sync_bytes`) |
| Open links of one device | 3; a link lives 600 s |
| Pending joins of one link | 1 |
| Account token | 15 minutes; challenges 60 s, at most 4 open for each key |
| Entitlement token | 24 hours |
| Recovery tries | 5 for each account an hour |

## 14. Modes and retired routes

- **Transition** (`APASSY_RELAY_CONNECT_ACCOUNTS=1`): the routes of the three Connect contracts are added to a running relay. With `APASSY_RELAY_FREE_CONNECT=0`, `POST /v1/connect` answers `410 free_connect_ended`.
- **Connect only** (`APASSY_RELAY_MODE=connect`): no master key (`APASSY_RELAY_KEY` is refused at start), no proxy. These routes answer `410 hosted_retired` before any body is read: `POST /v1/connect`, `POST /v1/teams`, `POST /v1/join`, `/v1/questions` and below, `/v1/feed` and below, `/v1/push/token`, `/mcp`, `/p/` and below. Relay-sync-v1 works only for vault stores.

## 15. Test vectors

`tests/fixtures/connect-account-v1/vectors.json` (made by `generate_vectors.py` in the same directory, with OpenSSL 3). The values are synthetic.

| Name | Value |
| --- | --- |
| Origin | `https://connect.example.test` |
| Account id | `acc_k7m2q4x3ca` |
| Device A | the relay-sync-v1 section 15 key, `dev_m2k7q3x4ab` |
| Device B | private `1c9a5e3f7b2d4a6c8e0f1a3b5c7d9e2f4a6b8c0d1e3f5a7b9c2d4e6f8a1b3c5d`, `dev_p4n6r2t7bc` |
| Nonce | bytes 0 to 31 |
| Link code | `apassy_alk_acc_k7m2q4x3ca_` and 32 bytes `0xcd` in hex |
| Safety words (A confirms, B joins) | `blaze cable flute board seal tiger` |
| Recovery code | bytes 16 to 31, `apassy_rec_101112131415161718191a1b1c1d1e1f` |
| Entitlement key | Ed25519 seed bytes 32 to 63, kid `ek_test_1` |

`vectors.json` holds for each message its exact bytes (b64u), its SHA-256, and an ECDSA signature that verifies with the signer's public key; the link hash; the safety hash and words; the recovery words and hash; and two entitlement tokens (Personal; a Family member) with their payloads and Ed25519 signatures. `examples.json` holds one example of every request and result body of this contract, and the error bodies.

Both suites must show: each message is the join of its parts and starts with its tag; each signature verifies over its message with its signer's key and fails over a message with one changed byte; the link hash, the safety words, and the recovery hash are reproduced from their inputs; each entitlement token verifies with the published key and fails with a changed claim, after `exp`, or with another key; every example parses with strict types. The app's tests: M1 (`tests/connect_account.rs`); the relay's: C1 (`tests/server_account.rs`); the fixture check: `contracts::connect_account_v1_fixtures_match_the_contract`.
