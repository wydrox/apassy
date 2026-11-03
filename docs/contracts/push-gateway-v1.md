# Push gateway contract v1

Date: 2026-11-03.
Status: frozen for [implementation plan S2–S3](../design/implementation-plan-s2-s3.md) (unit N0). Not implemented yet. Unit N5 builds the gateway (`crates/apassy-relay/deploy/push-gateway/`) and the iPhone core registration; unit N1 builds the node side (relay team schema 8, `PUT`/`DELETE /v1/push/handle`, the push thread in gateway mode). Sections 11 (the Apple Watch) and 12 (the sealed summary for a Notification Service Extension) are defined here and built by later units (section 16). Fixtures: `contracts::push_gateway_v1_fixtures_match_the_contract` in `tests/contracts.rs`.
Decision: [ADR 0037](../adr/0037-own-relay-open-source.md) §7 and D7; [ADR 0039](../adr/0039-apple-watch-access-requests.md) §7 (the watch); plan decision D7.

MUST and MUST NOT are implementation requirements.

## 1. Purpose and scope

Only the holder of the APNs key of the app's bundle id can push to the App Store and TestFlight apps. A node (the Mac's, or a Linux node) must not hold that key, and the Apassy project must not learn which node serves which device. The **push gateway** (`apassy-push`) is a stateless Cloudflare Worker that holds the APNs key and nothing else:

- A device gives its APNs token to the gateway once and gets a **handle**: the token sealed under the gateway's own key, with a per-handle **secret**.
- The device gives the node the handle and the secret, never the token.
- For each new question the node asks the gateway to push to a handle, with a **proof** made from the secret. The gateway opens the handle, checks the proof, and sends the fixed notification.

The gateway stores nothing, logs nothing, and sees no question data. The hosted relay (`apassy-relay.wyderka.cc`) keeps its Worker push (relay SPEC §25.6, relay-questions-v1 §10.8 and §14) until ADR 0037 stage 7; this contract does not change it.

## 2. Parts

| Part | Role | Unit |
| --- | --- | --- |
| Push gateway | `POST /v1/handles`, `POST /v1/push`, `GET /healthz`. Run by the Apassy project at `https://push.apassy.wyderka.cc`; self-hosters deploy the same source with their own bundle ids and APNs key | N5 |
| Node relay | Stores handles per device (team schema 8); its push thread calls `POST /v1/push` | N1 |
| iPhone core | Exchanges the token for a handle per questions team on a node, and sends it to the node | N5 |
| Watch core | The same, with the device kind `watch` (section 11) | later |
| Notification Service Extensions | Open a sealed summary on the iPhone and on the watch (section 12) | later |

## 3. Encodings

- JSON bodies, UTF-8, `Content-Type: application/json`. Every object has exactly its fields: an unknown, missing, or repeated field refuses the request (400 `invalid_request`). `v` is `1`.
- b64u: base64url without padding, canonical (the last character has no padding bits set), as relay-sync-v1 §2.
- Times are Unix seconds, non-negative safe integers.
- `token`: the APNs device token as lowercase hex, 32 to 200 characters (as relay-questions-v1 §10.8).
- `environment`: `development` or `production` (the `aps-environment` of the build).
- `collapse_id`: 1 to 64 characters of `A-Za-z0-9._-`. In v1 the node always sends `apassy-question`.
- Request bodies are at most 4096 bytes (a declared `Content-Length` above it, or more bytes read: 413).

## 4. Gateway configuration

| Name | Kind | Value |
| --- | --- | --- |
| `GATEWAY_KEY` | Worker secret | 32 random bytes, b64u (43 characters). The AES-256-GCM key of the handles |
| `GATEWAY_KEY_ID` | var | 1 to 255. The key id written in each new handle |
| `GATEWAY_KEY_PREVIOUS`, `GATEWAY_KEY_PREVIOUS_ID` | Worker secret, var | Optional: the key before a rotation, so handles made under it open until they expire |
| `APNS_KEY` | Worker secret | The `.p8` text (PKCS#8 EC P-256 PEM), as the relay Worker |
| `APNS_KEY_ID`, `APNS_TEAM_ID` | vars | The APNs key id; the Apple team id (`7S3F9767BM`) |
| `APNS_TOPIC` | var | The bundle id of the iPhone app (`com.wydrox.apassy.companion`): device kind `iphone` |
| `APNS_WATCH_TOPIC` | var, optional | The bundle id of the watch app (`com.wydrox.apassy.companion.watchkitapp`): device kind `watch`. Without it, `kind: "watch"` is 409 `kind_unavailable` |
| `handles_per_address`, `pushes_per_handle`, `pushes_per_address` | rate-limiting bindings | Section 13 |

The key values are piped through Apassy into `wrangler secret put`, never typed, echoed, or committed. `observability.enabled` is `false`. The Worker has no KV, D1, R2, Durable Object, Queue, or log binding.

## 5. The handle

```
handle      = b64u( header || nonce || ciphertext || tag )
header      = 0x01 || key_id                      ; 2 bytes: format 1, the gateway key id
nonce       = 12 random bytes
ciphertext  = AES-256-GCM( GATEWAY_KEY, nonce, plaintext, aad )
aad         = "apassy-push-handle-v1" || 0x00 || header
plaintext   = the UTF-8 JSON below, with no white space, fields in this order
```

```json
{"v":1,"kind":"iphone","token":"<hex>","environment":"production","bundle_id":"com.wydrox.apassy.companion","secret":"<b64u 43>","issued_at":1790000000,"expires_at":1805552000}
```

- `kind` is `iphone` or `watch` (section 11); `bundle_id` is the topic of that kind on this gateway.
- `secret` is 32 random bytes made by the gateway for this handle. It is returned to the device once and lives only inside the handle and with the device and the node.
- `expires_at` is `issued_at + 15552000` (180 days).
- The gateway opens a handle with the key of the header's key id (`GATEWAY_KEY_ID` or `GATEWAY_KEY_PREVIOUS_ID`). An unknown key id, a header other than format 1, a handle shorter than 2 + 12 + 16 bytes or longer than 1024 bytes, a failed open, or a plaintext out of its form: 403 `handle_invalid`. `expires_at` in the past on the gateway's clock: 403 `handle_expired`.
- The gateway cannot revoke a handle (it keeps no state). A handle stops at `expires_at`, when APNs refuses its token, or when the gateway retires its key.

## 6. `POST /v1/handles`

Called by the device (the iPhone core, later the watch core), with system trust, over the public internet.

```json
{"v":1,"kind":"iphone","token":"<hex>","environment":"production","bundle_id":"com.wydrox.apassy.companion"}
```

- `bundle_id` must equal the gateway's topic of `kind`: else 409 `wrong_bundle` (a build with another bundle id needs its own gateway).
- Answer 200:

```json
{"v":1,"handle":"<b64u>","secret":"<b64u 43>","expires_at":1805552000}
```

- The gateway makes a new nonce and a new secret on every call: two calls give two independent handles.
- The device makes **one handle per questions team** on a node (not one shared by teams), so a node that loses the device keeps only its own handle, and the limits of one team do not count against another.
- Renewal: at each launch with notifications on, the device makes a new handle for a team when the APNs token changed or when its handle expires within 30 days, and sends it with `PUT /v1/push/handle`. The old handle is forgotten.
- The device keeps the handle, the secret, and `expires_at` per team in `questions-push.json`; it never writes the token there after the exchange (the token comes from APNs at each launch).

## 7. `POST /v1/push`

Called by the node's push thread, one request per handle.

```json
{"v":1,"handle":"<b64u>","at":1790000100,"expires_at":1790000400,"collapse_id":"apassy-question","proof":"<b64u 43>"}
```

With a sealed summary (section 12), one more field `"summary":"<b64u 720>"` after `proof`.

```
proof   = b64u( HMAC-SHA256( secret, message ) )
message = "apassy-push-v1" 0x00 handle 0x00 at 0x00 expires_at 0x00 collapse_id [ 0x00 summary ]
```

`handle` and `summary` are their b64u texts as sent, `at` and `expires_at` decimal without leading zeros, `secret` the 32 decoded bytes. No field can hold a zero byte.

The gateway checks, in this order:

1. The shape (section 3), `at < expires_at ≤ at + 600` (the question bound of relay-questions-v1 §10.2): else 400 `invalid_request`.
2. `|at − now| ≤ 300` on the gateway's clock: else 403 `stale_request`.
3. The rate limits of section 13: else 429 `rate_limited` with `Retry-After`.
4. The handle (section 5): 403 `handle_invalid` or `handle_expired`.
5. The proof, in constant time, with the handle's secret: else 403 `proof_invalid`.
6. The topic of the handle's kind exists (`APNS_WATCH_TOPIC` for `watch`): else 409 `kind_unavailable`. The APNs configuration is complete and the key imports: else 503 `push_unavailable`.
7. One APNs request (section 11). `apns-expiration` is `expires_at`.

Answer 200 with the APNs result, also when APNs refused:

```json
{"v":1,"status":200}
{"v":1,"status":410,"reason":"Unregistered"}
{"v":1,"status":0,"reason":"Unreachable"}
```

`reason` is the APNs reason when it is a word of 1 to 64 letters, else `Unknown`; status 0 means the APNs request threw or timed out (8 s), as the relay Worker (`apns.ts`).

A replay of the same request within the 300 s window sends the same notification again; the per-handle limit bounds it, and the collapse id makes it replace the visible one.

## 8. `GET /healthz`

Answer 200 `{"v":1,"ok":true}` with a `Date` header. `apassy doctor` on a node uses the `Date` for the clock check (a skew over 60 s is a warning, over 300 s an error: pushes would be `stale_request`).

## 9. Errors

The body of every error is the relay's envelope, `{"ok":false,"error":{"code":"…","message":"…"}}`, with `Cache-Control: no-store`. A message never contains a token, handle, secret, proof, or summary.

| Status | Code | When |
| --- | --- | --- |
| 400 | `invalid_request` | Malformed JSON, an unknown, missing, or repeated field, `v` not 1, a value out of its form, the times of section 7 step 1 |
| 403 | `stale_request` | `at` more than 300 s from the gateway's clock |
| 403 | `handle_invalid` | The handle does not open, or its plaintext is out of form |
| 403 | `handle_expired` | The handle's `expires_at` is past |
| 403 | `proof_invalid` | The proof does not match |
| 404 | `not_found` | Any other path or method |
| 409 | `wrong_bundle` | `POST /v1/handles` with a `bundle_id` that is not the topic of `kind` |
| 409 | `kind_unavailable` | `kind: "watch"` on a gateway without `APNS_WATCH_TOPIC` |
| 413 | `payload_too_large` | A body over 4096 bytes |
| 429 | `rate_limited` | Section 13; `Retry-After` in seconds |
| 503 | `push_unavailable` | The APNs configuration is missing or does not import |

## 10. The node side

**Endpoints** (relay team schema 8; device auth as relay-questions-v1 §10.1; on the tailnet scope of a node and on the hosted relay, which answers 409 `push_unavailable` because it has no gateway):

- `PUT /v1/push/handle` with `{"v":1,"gateway":"https://push.apassy.wyderka.cc","handle":"<b64u>","secret":"<b64u 43>"}`: one handle per device, replaced on each call, which also clears a failed mark. Answer `{"device_id":3,"updated_at":1790000000}`. `gateway` is an origin (`https://` with a host and an optional port, no path); it must be one of the node's gateways (a node setting, default `["https://push.apassy.wyderka.cc"]`): else 409 `push_gateway_refused`, so a team device cannot make the node call an arbitrary address. A relay without a gateway: 409 `push_unavailable`. The handle is 16 to 1024 bytes after b64u decoding and is not opened by the node. The audit row is `push_handle_set {device_id}`.
- `DELETE /v1/push/handle` with no body: removes the caller's handle; answer `{"device_id":3}`; row `push_handle_removed {device_id}`. Revoking a device deletes its row too.
- A device on a node uses these, never `PUT /v1/push/token`.

**Table** (team schema 8): `push_handle(device_id INTEGER PRIMARY KEY REFERENCES device(id), gateway TEXT NOT NULL, handle BLOB NOT NULL, secret BLOB NOT NULL, updated_at INTEGER NOT NULL, failed_at INTEGER)`. The node's team file is SQLCipher; the handle and the secret never go to a log or an audit row.

**Push thread** (`PushMode::Gateway`): after the commit of `POST /v1/questions`, the handles of the routing set (`failed_at IS NULL`) go to the existing bounded queue; for each, one `POST <gateway>/v1/push` with `at` = now, `expires_at` = the question's, `collapse_id` = `apassy-question`, and the proof. Timeout 10 s, no redirects, no retry; the same queue, budget, and throttles as the Worker mode (relay SPEC §25.6). `failed_at = now` on: an answer with status 410; status 400 with reason `BadDeviceToken` or `DeviceTokenNotForTopic`; gateway 403 `handle_invalid`, `handle_expired`, or `proof_invalid`. A 403 `stale_request` writes `push_failed {reason:"clock"}` (at most one per team and ten seconds) and keeps the handle. A 429, a 5xx, status 0, or no answer drops that push. The node never sends a token.

## 11. Device kinds and payloads

| Kind | Device | APNs topic | Registers | Built |
| --- | --- | --- | --- | --- |
| `iphone` | The iPhone app | `APNS_TOPIC` (`com.wydrox.apassy.companion`) | The iPhone core, for each questions team on a node | R1 (N5) |
| `watch` | The independent watch app (ADR 0039: its own relay device and membership) | `APNS_WATCH_TOPIC` (`com.wydrox.apassy.companion.watchkitapp`) | The watch core, for its one questions team, when the owner turns on "Notifications on this watch" | Later (section 16) |

Every push is one HTTP/2 request to `https://api.push.apple.com/3/device/<token>` (`production`) or `https://api.sandbox.push.apple.com/3/device/<token>` (`development`) with `authorization: bearer <provider JWT>`, `apns-topic: <topic of kind>`, `apns-push-type: alert`, `apns-priority: 10`, `apns-expiration: <expires_at>`, `apns-collapse-id: <collapse_id>`, `content-type: application/json`, and one of two payloads, the same for both kinds:

- **Without a summary** — exactly today's payload (relay-questions-v1 §14.1), byte for byte:

```json
{"aps":{"alert":{"title":"Apassy","body":"A question is waiting"},"sound":"default","interruption-level":"time-sensitive"}}
```

- **With a summary** (section 12) — the same alert, `mutable-content` on, and the sealed summary as `s`:

```json
{"aps":{"alert":{"title":"Apassy","body":"A question is waiting"},"sound":"default","interruption-level":"time-sensitive","mutable-content":1},"s":"<summary>"}
```

Rules for both kinds:

- The visible text without an extension, or when the extension fails, is the fixed text. Apple and the gateway see the token, the topic (so the kind), the time, and, with a summary, 720 characters of ciphertext of constant length.
- The collapse id is the constant `apassy-question` for both kinds.
- The watch is a device of the member, so it is in the routing set of every question of its team, also of run questions it cannot answer (ADR 0039 §2: access requests only). The relay cannot tell them apart (the outer post shows no kind, relay-access-request-v1 §1). So a watch push says only "A question is waiting"; a tap opens the watch app on Requests, which lists only access requests. With a summary, the watch extension shows details only for `kind: "access"` and the body "Answer on your iPhone or Mac" for `kind: "run"`.
- ADR 0039 §7 stays true for a watch without a handle: the iPhone's alert is mirrored to the watch when the iPhone is locked. Whether watchOS shows both the mirrored alert and the watch's own push is open (section 17); the watch registers a handle only when the owner turns its notifications on.
- No notification actions (ADR 0033 §7) and no `content-available` push.

## 12. The sealed summary (Notification Service Extension)

ADR 0037 §7: a Notification Service Extension opens a sealed summary on the device, so the notification can say more while the gateway, the node, and Apple still see nothing.

**Key.** Every device of the vault holds the vault's question key (relay-questions-v1 §5.1). The summary key is derived from it, so no new key exchange is needed and it opens summaries only (not cards):

```
summary_key = HKDF-SHA256( salt = empty, ikm = question key (32 bytes), info = "apassy-push-summary-v1", length 32 )
```

**Format.**

```
summary    = b64u( nonce || ChaCha20-Poly1305( summary_key, nonce, padded, aad ) )   ; 720 characters
nonce      = 12 random bytes
aad        = "apassy-push-summary-v1"
padded     = uint16-be( len(json) ) || json || zero bytes, 512 bytes in total
json       = the UTF-8 JSON below, no white space, fields in this order, at most 510 bytes
```

```json
{"v":1,"team":"t_7k2m5q4x3c","qid":"oKGio6SlpqeoqaqrrK2urw","expires_at":1790000400,"kind":"access","title":"Access request","body":"…"}
```

- `team` and `qid` are those of the question (relay-questions-v1 §4); `expires_at` equals the question's. `kind` is `run` or `access`. `title` is 1 to 64 bytes and `body` 1 to 160 bytes of UTF-8 with no control character; they never carry a value (a card never carries one).
- The asking Mac seals a summary only when the vault setting "Show details in notifications" is on (default off). The text follows the card: for an access request `Access request` and `<agent> wants <item name>`; for a run question `Run waiting` and `<agent> asks to run a command`. Never the command, a host, or a variable.

**Carrier.** The asker sends the summary with the question as the header `X-Apassy-Push-Summary: <summary>` on `POST /v1/questions`. The body and its fields do not change. The node checks only the form (720 b64u characters, 540 bytes), keeps it in memory with the push job, never stores or logs it, and sends it in `POST /v1/push`. The hosted relay ignores the header (its Worker payload stays fixed). The unit that builds this section adds one line to relay-questions-v1 §10.3 when it lands; until then no client sends the header.

**Gateway.** `summary` is opaque: the gateway checks its form, includes it in the proof, and copies it to `s`.

**Extensions.**

- The iPhone app writes the summary key of each questions team into a Keychain item of an access group shared with its extension (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`), when the vault unlocks, and deletes it when the team is left or notifications are turned off. The watch app does the same for its one team.
- The extension decodes `s`, tries each summary key it has (at most 16), and on success checks `v`, that `team` is the team of the key that opened it, `expires_at` in the future, and the text rules. Then it sets the notification's title and body from the summary (the watch: section 11). On any failure, or after 5 s, it delivers the notification unchanged.
- The extension makes no network request, opens no vault, and logs nothing.

## 13. Limits

| Limit | Value | Key of the binding |
| --- | --- | --- |
| Pushes per handle | 60 per hour | SHA-256 of the handle text |
| Pushes per node address | 600 per hour | SHA-256 of the client address |
| Handle creations per address | 30 per hour | SHA-256 of the client address |
| Request body | 4096 bytes | — |
| Handle | at most 1024 bytes decoded | — |
| Handle lifetime | 180 days | — |
| Clock window of `at` | ±300 s | — |
| `expires_at − at` | 1 to 600 s | — |
| Handles per device and team on a node | 1 | — |

If the Cloudflare plan has no Rate Limiting binding, a Durable Object counter keyed the same way replaces it; it stores counts only, never a handle, token, or address.

## 14. Who sees what

| Party | Sees | Does not see |
| --- | --- | --- |
| Push gateway | Handles (and so, inside its own key, tokens, kinds, and environments), node IP addresses, device IP addresses at handle creation, times, the summary's ciphertext | Which team or vault, any question data, the summary's text |
| Node | Handles and secrets of its devices | Tokens |
| Apple (APNs) | Token, topic, time, payload (fixed text; summary ciphertext) | Question data |

## 15. Versioning

- `v: 1` in every body; format byte `0x01` in the handle; domain tags `apassy-push-handle-v1`, `apassy-push-v1`, `apassy-push-summary-v1`. A change of any of them is `push-gateway-v2`.
- A gateway of v1 refuses a v2 body (400). A node keeps the device's handle and sets no failed mark on a 400.

## 16. Build status

| Section | Built by | Release |
| --- | --- | --- |
| 3 to 10, 13, kind `iphone` | N1 (node), N5 (gateway, iPhone core) | R1 of plan S2–S3 |
| Kind `watch` at the gateway (topic mapping) | N5 | R1 (accepted, not yet used) |
| Watch registration (section 11) | A later watch unit (`ios/ApassyVaultKit`, the watch core) | After R1 |
| Sealed summary and both extensions (section 12) | A later unit | After R1 |

## 17. What this does not protect, and open questions

- A node that held a handle can push the fixed notification to that device until the handle expires (180 days), within the limits, also after the device left its team. The device cannot revoke a handle at a stateless gateway. A new APNs token (reinstall) ends it.
- The gateway learns which node addresses push to how many handles, and when.
- A party that reads a push request in transit (only the gateway, behind TLS) can replay it for 300 s.
- Open: whether watchOS shows both the mirrored iPhone alert and the watch's own push for the same question (a physical check before the watch unit; if it does, the watch unit decides which one to keep).
- Open: whether the Cloudflare plan of the owner has Rate Limiting bindings (section 13).

## 18. Test vectors

These values are synthetic. `contracts::push_gateway_v1_fixtures_match_the_contract` seals the handles with the given nonces, recomputes the proofs, derives the summary key, seals the summary, and checks that each body parses strictly and that an unknown field is refused. Unit N5 checks the gateway (TypeScript) against the same values; unit N1 checks the node's proof.

| Name | Value |
| --- | --- |
| `GATEWAY_KEY` (bytes `40` to `5f`) | `QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8` |
| `GATEWAY_KEY_ID` | `1` |
| iPhone token | `a1` repeated 32 times |
| iPhone secret (bytes `60` to `7f`) | `YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn8` |
| iPhone handle nonce | bytes `00` to `0b` |
| Watch token | `b2` repeated 32 times |
| Watch secret (bytes `80` to `9f`) | `gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp8` |
| Watch handle nonce | bytes `10` to `1b` |
| `issued_at`, handle `expires_at` | `1790000000`, `1805552000` |
| Push `at`, `expires_at`, `collapse_id` | `1790000100`, `1790000400`, `apassy-question` |
| Question key (bytes `c0` to `df`) | `wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t8` |
| Summary key | `K-iD_0Xo0XYWPOS-Iz7HiP6Cs2rdeAtf21jMtRLg-Zc` |
| Summary nonce | bytes `20` to `2b` |

iPhone handle plaintext:

```
{"v":1,"kind":"iphone","token":"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1","environment":"production","bundle_id":"com.wydrox.apassy.companion","secret":"YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn8","issued_at":1790000000,"expires_at":1805552000}
```

iPhone handle:

```
AQEAAQIDBAUGBwgJCgtBJxpaTb1ogql77qaa1-7S86xCZwlugXGaT4PzL5NTfCFBpTDac2pO0SkZriCatsFILmsMt3V6FVKy5oQwVC_Xp0KbnZecVv6zArmDfifrV5jgi8MknGQGiRecJm9NW2etrseKbY4QHHDC16hpS29-n_ooa8Wf7_gDcl-gXUOCOht6OHZn7JjU2hewAbctZWpd_qZzpQMPBS4GKjewB9GMj8v0if9Q6ZZSlj1UQzXfSRw3Lme5AOFU5ggjW-mmefcljd5raXzDrJ-r7U7GcjJI-XAMcaScWgVAShGeklTDrvW8Qpt8C40X2UhL_GmK8G3vg9q7_5xrlTqrBrHrZRBMHwSQ3dMPyRp5zrrzBIgGn6IlRz7SLrGYTy4uHS4
```

iPhone proof (no summary): `-MmhDTmjMiBV6cNqCsq29jnlp9anOujN_dXLn6hbbnY`

Watch handle plaintext:

```
{"v":1,"kind":"watch","token":"b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2","environment":"production","bundle_id":"com.wydrox.apassy.companion.watchkitapp","secret":"gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp8","issued_at":1790000000,"expires_at":1805552000}
```

Watch handle:

```
AQEQERITFBUWFxgZGhsCGEvzbKA4AcXPuDTJwi3BZGPnoSQ9aH8XBay_-VOQstGWIJlekXGdAALT_B73l_ZgGeZMEDAmyTp2zqYF69tWqZ_1R6DSxX2gstrWUC6hi0uL_AXLKTvezTUSly0XROF6ardVkVxMFK69c8oKF652vi9NMQVtpThfgcSo1b4B8urodIEdJzfJsnhSiQ2d5NFf0hi-5MRKb1hhk1whHjAU3e-pWX7QCq_bvnIu4-iml6auHpWStEPb5l8i9oVTE7ZxeOKQupMT1YV2MB-wVcUDzDx1kjox7A8NLoDDI84B00IU9fWhfFl2srTzPyfOPP8eKqBUfazI2uE1AUYBE8c3XkCdmXoCQiRLuWBv8G00W7pcFusI2_UX-MOYh1D253_JLDrQmxzREA
```

Watch proof: `KxRYEBo7r3KCRqcOBVc8OpRsPuz2rRb4LxFQtvzzaBI`

Summary JSON (174 bytes):

```
{"v":1,"team":"t_7k2m5q4x3c","qid":"oKGio6SlpqeoqaqrrK2urw","expires_at":1790000400,"kind":"access","title":"Access request","body":"Claude Code wants “Stripe test key”"}
```

Summary:

```
ICEiIyQlJicoKSorLZYy_9V2mK8YOxL9BrISycdM3QC8LastsrSZ2rydHt5kH7FQOVw3Z9Fcdh4X0rBDP0peQmDtu1ueo2qMc8jG-HaJeH5MYA7UnBcbZRxtOLpdrfxf1XCmrKUi-gmLBZxFvggJiX35uKUAdZwfhwUqeu6y8tnLbItuN-Yk4e_Jkqawp39RHi3ux-0DNm4DCs1Nlnki8MWzWpS7q_Yf1-3uwYdSdBlr-qq7uI6GCJiJ-79H4cte4JJnY8GQ0RvTh9ZbxyqpdIhFpoe0V1w2ZgierYd-NuopbMxBWD0nepd9qDJGCGmbMZG1CwxXrjC_l2986y7k_EjhkwIbDdeBxTVnZ67guVWth1D8h-UMVEvCKR3zc2ANEQ1Qrr-skb_eNEo0hnj6Bvx6MiFWKwMUV_PcRAFVpb7so6XLs1i2bkYSzEv-w_buoaz-EnNnMD70ddE-FuZDqHiWaar_Wo0dSHz5qf5hcXNT6x185swuTpTL8sKUr32di0Qa0ObJE6BCpMOdFlxGtaKrb7bu1svCr0nLWDhMhi2Tp8ibOnvYKei4HFG251WGQ8AxcJl_7m_NTDOq4bDlEOOaOgSF7KiofJolVL4sBk8oFlaTgp2-Jvn4rFU1c04OaWJGQfOaJIvpnRXa883CBzSKZ2sNaovOg00TUiQ8Dc31pqs-ZzE8xHmg7E7YbmDyG3-UPiey7OE407l9
```

iPhone proof with this summary: `gyriDrKhiUeSYbgOm5weYj7NG6isjzaE3IEJp9qDV3g`

Checks that must fail: the iPhone handle under the key with its first byte changed (`handle_invalid`); the handle with its 20th decoded byte (in the ciphertext) flipped (`handle_invalid`); the iPhone handle at a gateway time after `1805552000` (`handle_expired`); the iPhone proof with `at` `1790000101` (`proof_invalid`); the iPhone proof checked with the watch secret (`proof_invalid`); a push body with a field `"token"` (`invalid_request`); a summary of 719 characters (`invalid_request`).
