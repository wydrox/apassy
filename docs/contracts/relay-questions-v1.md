# Relay questions wire contract v1

Date: 2026-10-12.
Status: DRAFT, for stage 5 of [ADR 0025](../adr/0025-low-friction-access.md) (§3d, §3e) and section A of the [stage 5 plan](../design/stage5-plan.md). Not in the code. The app side (stream N3: `src/questions/`, `src/vault/questions.rs`, `src/relay/membership.rs`, `src/companion/digest.rs`, `src/broker/approvals/owner_auth.rs`), the iPhone side (stream M3: `ios/ApassyCore`, contract [ios-core-v1](ios-core-v1.md)), and the relay side (stream R4: `apassy-relay`, `docs/SPEC.md` section 25) implement it. A change to this document changes every side, one pull request on each; a change to a tag, to the AAD, to the answer string, to the digest, or to a check bumps its version. The app implements the client itself and does not depend on the relay crate (FSL license): everything the app needs is in this document.

## 1. Purpose

A waiting run of the broker (ADR 0024, ADR 0025 §3) is a question for the owner. Today it shows on the Mac that asks and, on the local network, on a paired iPhone ([companion-v1](companion-v1.md)). This contract carries the question to **every device of the vault** through the relay, wakes the iPhones with a push notification without content, and brings the answers back:

- The relay routes opaque envelopes by role. It never reads a question or an answer: both are sealed with a key that only devices holding the vault have.
- The vault, not the relay, is the trust root for keys: an answer counts only when its signature verifies with a key from the `trusted_device` table of the vault.
- The asking Mac stays the only place where a decision takes effect. It reads the answers in order and applies the first valid one (section 12.3). The queue settles once.
- The Worker sends Apple push notifications with fixed text. Apple sees no question.

The local paths stay as they are: the card on the asking Mac and the local-network companion (contract companion-v1 with digest v1). Without the relay, notifications work on the Mac and on the local network only (ADR 0025 §3e).

## 2. Parts

| Part | Location | Stream |
| --- | --- | --- |
| The question key, `Vault::ensure_question_key` | `src/vault/questions.rs` | N3 |
| `trusted_device`, `relay_membership` (schema 19) | `src/vault/relay_device.rs`, `schema19.rs` | F19 |
| Envelope, card, answer, settle, the asker and answerer procedures, the waiter thread | `src/questions/` | N3 |
| Relay client for questions, membership per team with purposes | `src/relay/membership.rs`, `src/sync/relay_http.rs` (reused) | N3 |
| Question digest v2 | `src/companion/digest.rs` | N3 |
| `OwnerCheck::Remote`, `CheckMethod::Remote`, `OwnerAction::AnswerRemoteQuestion` | `src/broker/approvals/owner_auth.rs` | N3 |
| Tests against a fake relay | `tests/relay_questions.rs`, `tests/common/fake_relay.rs` | N3 |
| iPhone core calls `questions_list`, `questions_wait`, `question_open`, `question_answer`, `answer_key_register`, `push_token_set` | `ios/ApassyCore/src/core/questions.rs` | M3 |
| Swift `QuestionsView`, push registration, the Secure Enclave answer key | `ios/` | M3 |
| Relay endpoints, team schema 5, routing, limits, audit, the push trigger | `apassy-relay`: `src/server/questions.rs`, `src/server/push.rs`, `store.rs` | R4, SPEC section 25 |
| APNs sender | `apassy-relay`: `deploy/worker/src/apns.ts` | R4 |

## 3. Actors and words

| Word | Meaning |
| --- | --- |
| Asker | The Mac whose broker has the waiting run. It posts the question, reads the answers, applies one, and settles. |
| Answering device | Any other device in the routing set: another Mac with the vault, or an iPhone with the vault (ADR 0023). |
| Questions team | The ADR 0019 team that carries the questions of a vault: the relay sync team when the vault syncs through the relay, or a notifications-only team that never pushes a snapshot (plan A6). Its id is `team_id` below. |
| Routing set | The live devices that may read and answer a question (section 11). The relay computes it; the asker trusts it for nothing. |
| Question key | 32 random bytes in the vault, shared by every device that holds the vault (section 5.1). |
| `trusted_device` | A synced row of the vault per device: its uuid, kind, relay device id, `sign_key`, and for an iPhone `answer_key` (section 5.2). |
| Relay | `apassy-relay`. Stores sealed envelopes for at most 24 hours, routes them, counts, and triggers pushes. |
| Worker | The Cloudflare Worker in front of the relay. It sends APNs requests for the relay (section 14). |

## 4. Encodings

The encodings of [relay-sync-v1](relay-sync-v1.md) section 2 apply: b64u without padding (non-canonical text refused), lowercase hex, P-256 public keys in X9.63 form (65 bytes), ECDSA P-256 SHA-256 signatures in ASN.1 DER (at most 72 bytes, sent as b64u), Unix seconds, the relay JSON envelope `{"ok":true,"result":...}` / `{"ok":false,"error":{...}}`, `deny_unknown_fields` on every relay request body. In addition:

| Value | Form |
| --- | --- |
| `qid` | 16 random bytes from the asker's CSPRNG, b64u: exactly 22 characters of `A-Za-z0-9-_`. |
| `key_id` | `hex(SHA-256(question key)[0..8])`: exactly 16 lowercase hex characters. |
| `nonce` | 12 random bytes, b64u: exactly 16 characters. A new nonce for each envelope. |
| `ciphertext` | b64u of the ChaCha20-Poly1305 output: the sealed bytes followed by the 16-byte tag. |
| Device uuid | `trusted_device.uuid`: a random UUID, 36 lowercase characters `8-4-4-4-12`. |
| Relay device id | the relay's device number, a decimal JSON number (`"device_id": 2`), and decimal text in the AAD. |
| Run id, question id, item id | decimal strings in JSON (`"123456789012345"`), as in companion-v1. |
| Digest | 64 lowercase hex characters (section 8). |
| Text in a signed or hashed field | the exact UTF-8 bytes. No normalization. |

## 5. Keys

### 5.1 The question key

- `vault_secret` row `question-key-v1`: 32 bytes from the CSPRNG. The first Mac that turns "Notifications through the relay" on makes it (`Vault::ensure_question_key`) when the row is absent. Every device that holds the vault gets it through its sync (iCloud Drive or the relay snapshot); `vault_secret` merges last-writer-wins by `(updated_at, updated_by)`.
- `key_id` names the key on the wire. A device that has no key with the `key_id` of an envelope cannot read it: it shows "Sync this vault to read this question" and does not answer.
- **Rotation.** When the owner removes a device from the vault (Settings > Devices), the Mac that removes it writes a new key. Questions already posted keep their `key_id`: the asker keeps the key of each open question in memory (a `Zeroizing` buffer) until the question settles or expires, so answers to it still open. A new question always uses the current key.
- Two Macs that make a key at the same time: last-writer-wins keeps one. A question sealed with the other key can be read only by devices that still hold it, and expires; the next question uses the kept key. No other action.
- The key never leaves the vault in clear, never goes to the relay, the Worker, or Apple, and is never logged.

### 5.2 Device keys (`trusted_device`, schema 19)

Each device registers its own row (plan A1). The relay's device list is never the source of an answer key.

| Column | Mac | iPhone |
| --- | --- | --- |
| `uuid` | random, made once per device per vault | same |
| `kind` | `mac` | `iphone` |
| `relay_device_id` | its device id in the questions team | same |
| `sign_key` | the public key of its relay device key (`relay_membership.key_pkcs8`, local) | the public key of its relay device key (Secure Enclave, no biometry) |
| `answer_key` | NULL | the public key of a Secure Enclave key with `.privateKeyUsage` + `.biometryCurrentSet`, no passcode fallback, `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (as the companion approval key, companion-v1 section 5.2). Registered with `answer_key_register`. |

A row with `deleted_at` set is not live. A new Face ID enrollment makes the `answer_key` unusable: the iPhone makes a new one and registers it again, which needs the vault to sync once before its approvals count.

### 5.3 Which key signs which answer

| Answer kind (section 9.1) | iPhone signs with | Mac signs with | The asker's owner check |
| --- | --- | --- | --- |
| `approve_once`, `approve_in_project`, `allow_production`, `correct_environment` to `development` | `answer_key`, after Face ID for this answer | `sign_key`, after a local Touch ID for `OwnerAction::AnswerRemoteQuestion` on the answering Mac | `OwnerGate::authorize` with `OwnerCheck::Remote`: the gate verifies the signature with the key of this table (section 12.4). A signature by the other key of the device is invalid. |
| `deny`, `never_for_agent`, `always_ask_for_agent`, `disconnect`, `correct_environment` to `production` | `sign_key`, no Face ID | `sign_key`, no Touch ID | None: these answers take authority away (`ApprovalQueue::deny_stricter`, `mark_production`). The signature still must verify with `sign_key`, so the relay cannot make one. |

Each `answer_key` signature uses a new `LAContext` with `touchIDAuthenticationAllowableReuseDuration = 0`. The prompt reason is `answer a question of agent "NAME"`, where NAME is the agent name with control characters and `"` removed, at most 40 characters. The Touch ID reason on a Mac is the reason of the matching local answer with ` on <asker name>` added.

### 5.4 Teams with approvers (V3)

A question goes `to: "approvers"` only for an item of a team collection (ADR 0025 §3e, plan A6). Such items reach a member's vault only with shared vaults (plan section B, stream V3). Until V3:

- the app sends every question with `to: "member"`,
- the relay implements the `approvers` routing (section 11) so that V3 needs no relay change,
- the asker counts an answer only from a device in its own `trusted_device` table.

With V3, the devices of other members get the question key as a `device_wrapped_key` row named `question-key-v1:<key_id>` (ECDH P-256 + HKDF-SHA256 + ChaCha20-Poly1305, the wrap of plan B), and their `trusted_device` rows come from the shared vault. Both are open (section 19).

## 6. The envelope

Every card, answer, and settle on the wire is sealed with **ChaCha20-Poly1305** (RFC 8439; `ring::aead::CHACHA20_POLY1305` in the app and in `apassy-core`; CryptoKit `ChaChaPoly` is equivalent) under the question key named by `key_id`, with a fresh 12-byte random nonce. A nonce is never reused under one key: with random nonces, a key may seal at most 2^32 envelopes, far above the limits of section 15.

### 6.1 AAD

The AAD is the ASCII bytes of these fields joined with one zero byte (0x00), with no zero byte at the start or the end:

```
card:   "apassy-question-v1" 0x00 "card"   0x00 <team id> 0x00 <qid> 0x00 <key_id> 0x00 <to> 0x00 <expires_at>
answer: "apassy-question-v1" 0x00 "answer" 0x00 <team id> 0x00 <qid> 0x00 <key_id> 0x00 <relay device id of the answering device>
settle: "apassy-question-v1" 0x00 "settle" 0x00 <team id> 0x00 <qid> 0x00 <key_id>
```

- `<to>` is `member` or `approvers`; `<expires_at>` and the device id are decimal without leading zeros. No field can hold a zero byte (their grammars exclude it).
- The part name (`card`, `answer`, `settle`) separates the three kinds: an envelope of one kind never opens as another.
- The card binds the routing bit and the expiry that the relay stores and returns in clear. A relay that changes either makes the card fail to open.
- The answer binds the relay device id that the relay stamps on it. The asker opens an answer with the stamped id; a relay that moves an answer to another device makes it fail to open.
- The plan (A2) had `"apassy-question-v1\0" || team_id || "\0" || qid`. This contract adds the part name, `key_id`, and the clear metadata above. The tag stays `apassy-question-v1`.

### 6.2 Opening

A device opens an envelope only with the key whose `key_id` equals the envelope's `key_id` and with the AAD built from the values that the relay returned with it. A failure to open is one result for every cause ("This question could not be read"); the device never tells the relay why.

### 6.3 Sizes

| Envelope | Plaintext | Ciphertext (plaintext + 16) |
| --- | --- | --- |
| Card | at most 32768 bytes | at most 32784 bytes |
| Answer | at most 8192 bytes | at most 8208 bytes |
| Settle | at most 1024 bytes | at most 1040 bytes |

The relay refuses a larger ciphertext with `413 payload_too_large`. The asker never cuts a card to fit: the digest covers the exact fields. A run whose card is over the limit, or over a count limit of section 7.2, is not posted; the question stays on this Mac, and the card says "This question is too long for your other devices. Answer it on this Mac."

## 7. The question card

### 7.1 Schema

The plaintext of a card is one JSON object, UTF-8, with exactly these fields. The answering device refuses a card with an unknown or missing field ("Update Apassy to read this question"): the card shows only what the digest covers.

```json
{
  "v": 1,
  "qid": "oKGio6SlpqeoqaqrrK2urw",
  "asker": {"device": "0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d", "name": "MacBook Pro"},
  "created_at": 1790000000,
  "run": {
    "id": "123456789012345",
    "agent": "claude-code",
    "command": ["npm", "run", "migrate"],
    "cwd": "/tmp/synthetic-shop",
    "env_names": ["DATABASE_URL", "API_TOKEN"],
    "purpose": "Apply the new migration.",
    "risk": "production credential: always asks the owner",
    "user_request": "Deploy the new schema to staging.",
    "request_source": "from the host hook",
    "agent_request": "Run the migration.",
    "remember": null
  },
  "question": {
    "id": "123456789012345",
    "item_ids": ["7", "9"],
    "items": [
      {"item_id": "7", "name": "Shop database", "production": true, "unconfirmed": false, "always_ask": false},
      {"item_id": "9", "name": "API token", "production": false, "unconfirmed": true, "always_ask": false}
    ],
    "project": {"key": "/tmp/synthetic-shop/.git", "label": "synthetic-shop"},
    "action": "deploy",
    "production": true,
    "why": "A production credential goes to a deploy.",
    "valid_answers": ["once", "production:deploy", "correct_environment", "never_for_agent", "always_ask_for_agent", "disconnect"]
  },
  "digest": "f3b3231d5e65efa3edf428f34bb446d0b6d81ac964256e973c2ebf1d517f267d"
}
```

| Field | Rule |
| --- | --- |
| `v` | `1`. |
| `qid` | equal to the `qid` of the relay record. |
| `asker.device` | the asker's `trusted_device.uuid`. |
| `asker.name` | the asker's `trusted_device.name`, 1 to 64 bytes. For the card only; not in the digest. |
| `created_at` | the asker's clock when it posts. |
| `run` | every field of `PendingRun` except `question`, with the names of companion-v1 `GET /v1/inbox`. `remember` is `null` or `{"pattern": text, "approvals": u32, "needed": u32}`. |
| `question.id` | `QuestionInfo.id`, equal to `run.id`. |
| `question.item_ids` | `QuestionInfo.item_ids`, in order. |
| `question.items` | `QuestionInfo.items`, in the order of `item_ids`, with the same ids. |
| `question.project` | `null` when the folder is too wide to be a project; else `{"key": Project.key, "label": Project.label}`. `Project.root` is not on the wire: the Mac derives it from `cwd` and `key`. |
| `question.action` | `ActionKind::as_str`: `read`, `change`, `deploy`, or `delete`. |
| `question.production`, `question.why` | as in `QuestionInfo`. |
| `question.valid_answers` | each `AnswerKind` as text: `once`, `in_project:<action>`, `production:<action>`, `never_for_agent`, `always_ask_for_agent`, `disconnect`, `correct_environment`. No duplicates. |
| `digest` | the question digest v2 of the run as it waits (section 8). |

### 7.2 Limits

At most 256 entries in `command`, 64 in `env_names`, 64 in `item_ids` (and as many in `items`), 16 in `valid_answers`. Texts have no other limit than the plaintext size of section 6.3. The asker checks before it posts (section 6.3); the answering device refuses a card over a limit.

### 7.3 What the answering device checks before it shows a card

In this order; the first failure shows "This question could not be read" and offers no answer:

1. The envelope opens (section 6.2).
2. The JSON parses with exactly the fields above, within the limits.
3. `v` is 1 and `qid` equals the relay's `qid`.
4. It computes the digest v2 from the card's fields itself and gets `digest`.
5. `asker.device` is a live `trusted_device` of its vault whose `relay_device_id`, when set, equals the relay's `from_device_id`.
6. The relay's `expires_at` is in the future on its clock.

The card shows each text with control and format characters replaced by `?`, and long paths shortened, by the rules of `shown_path` (`src/broker/approvals.rs`). Only the display changes; the digest covers the exact bytes. The card offers only the answers of `valid_answers`, plus `deny` (section 9.1).

## 8. The question digest v2

`question_digest_v2(run) = SHA-256(input)`, sent as 64 lowercase hex characters. It extends the companion digest v1 (`src/companion/digest.rs`, companion-v1 section 7): the same encoding of every `PendingRun` field with a new tag, then every `QuestionInfo` field. The v1 digest stays for the local-network companion and never changes.

Encoding primitives (as in v1):

- `u64(n)`: 8 bytes, big-endian. `u32(n)`: 4 bytes, big-endian. `flag(b)`: one byte, `0x00` or `0x01`.
- `text(s)`: `u64(byte length of s)` then the UTF-8 bytes of `s`.
- `list(v)`: `u64(count)` then `text` of each entry.

Input, in this exact order:

```
text("apassy-question-v2")
u64(run.id)
text(run.agent)
list(run.command)
text(run.cwd)
list(run.env_names)
text(run.purpose)
text(run.risk)
text(run.user_request)
text(run.request_source)
text(run.agent_request)
run.remember:  None -> 0x00
               Some -> 0x01 text(pattern) u32(approvals) u32(needed)
u64(question.id)
u64(count of question.item_ids) then u64(each item id)
question.project:  None -> 0x00
                   Some -> 0x01 text(project.key) text(project.label)
text(question.action)                -- "read" | "change" | "deploy" | "delete"
flag(question.production)
text(question.why)
u64(count of question.items) then for each item:
    u64(item_id) text(name) flag(production) flag(unconfirmed) flag(always_ask)
list(question.valid_answers)         -- the texts of section 7.1
```

The part up to `run.remember` is byte for byte the v1 input with the tag `apassy-question-v2` instead of `apassy-companion-run-v1`. The digest covers the bouncer text (`risk`, `why`) on purpose: the device signs what it showed. The remote digest is not used to join two calls of an agent; that stays `template_of` in the queue.

## 9. The answer

### 9.1 Answer kinds

| `kind` | Extra fields | Needs in `valid_answers` | Effect at the asker | Settles the question |
| --- | --- | --- | --- | --- |
| `approve_once` | none | `once` | `OwnerAction::ApproveRun(run)` | yes |
| `approve_in_project` | `action`, `project_key` | `in_project:<action>` | `OwnerAction::ApproveInProject { run, project, action }` | yes |
| `allow_production` | `action`, `project_key` | `production:<action>` | `OwnerAction::AllowProduction { run, project, action }` | yes |
| `correct_environment` | `item_id`, `environment` | `correct_environment`, and the item is in `question.items` with `unconfirmed: true` | `development`: `correct_environment` with a proof for `OwnerAction::ChangeItemRules { item_id }`; `production`: `mark_production(item_id)`, no check | no: the question still waits (section 12.5) |
| `deny` | none | always valid | `ApprovalQueue::deny` | yes |
| `never_for_agent` | none | `never_for_agent` | `deny_stricter(StricterAnswer::NeverForAgent)` | yes |
| `always_ask_for_agent` | none | `always_ask_for_agent` | `deny_stricter(StricterAnswer::AlwaysAskForAgent)` | yes |
| `disconnect` | none | `disconnect` | `deny_stricter(StricterAnswer::Disconnect)` | yes |

`action` must equal `question.action`, `project_key` must equal `question.project.key` (a question without a project offers neither kind), `item_id` is a decimal string, `environment` is `development` or `production`. "Approve and remember" (a pattern, ADR 0010) is not a remote answer in v1.

### 9.2 Schema

The plaintext of an answer is one JSON object with `v`, `qid`, `by`, `kind`, the extra fields of its kind and no others, `digest`, `time`, and `signature`:

```json
{"v":1,"qid":"oKGio6SlpqeoqaqrrK2urw","by":"6f1c0e2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b","kind":"allow_production","action":"deploy","project_key":"/tmp/synthetic-shop/.git","digest":"f3b3231d5e65efa3edf428f34bb446d0b6d81ac964256e973c2ebf1d517f267d","time":1790000030,"signature":"<b64u DER>"}
```

| Field | Rule |
| --- | --- |
| `v` | `1` |
| `qid` | the question's `qid` |
| `by` | the answering device's `trusted_device.uuid` |
| `kind` | section 9.1 |
| `digest` | the card's `digest` (the device checked it, section 7.3) |
| `time` | the answering device's clock when it builds the answer, before the Face ID or Touch ID prompt |
| `signature` | section 9.3, by the key of section 5.3 |

### 9.3 The answer string

The signed text: seven lines joined with `\n` (0x0A), no trailing newline, no `\r`:

```
apassy-question-answer-v1
<by: device uuid>
<team id>
<qid>
<choice>
<digest>
<time>
```

`<choice>` is exactly one of:

```
approve_once
approve_in_project:<action>:<project_key>
allow_production:<action>:<project_key>
correct_environment:<environment>:<item_id>
deny
never_for_agent
always_ask_for_agent
disconnect
```

- `<project_key>` is the exact key and the last part of its line, so a `:` inside it is unambiguous. A key with a control character cannot be in an answer: the asker's question then offers neither `in_project` nor `production` remotely (the builder returns `None`, as `approve_string` does). No other field can hold a control character.
- The plan (A2) had `correct_environment:<env>`. A correction is for one item (`OwnerAction::ChangeItemRules { item_id }`), so the item id is signed too.
- The asker never parses this text: it rebuilds it from the action it is about to take, the team id of its membership, the `qid` it posted, the digest v2 of the run as it waits, and the answer's `by` and `time`, and verifies the signature over the rebuilt bytes (section 12.4).

### 9.4 Settle

The asker seals one settle when its question ends, whatever ended it:

```json
{"v":1,"qid":"oKGio6SlpqeoqaqrrK2urw","outcome":"approved","answered_by":"6f1c0e2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b","device_name":"Test iPhone","device_kind":"iphone","kind":"allow_production","at":1790000031}
```

| Field | Rule |
| --- | --- |
| `outcome` | `approved`, `denied`, `timed_out`, `invalidated` (the vault was locked or replaced, or the broker stopped), or `replaced` (section 12.5) |
| `answered_by`, `device_name`, `device_kind` | the device whose answer settled it (`mac` or `iphone`; the asker itself for an answer on its own card or through the local-network companion, with `device_kind` of the device that answered there), or `null` for `timed_out`, `invalidated`, `replaced` |
| `kind` | the answer kind of section 9.1, or `null` |
| `at` | the asker's clock |
| `replaced_by` | only with `outcome: "replaced"`: the `qid` of the new question |

The other devices show "Answered on Test iPhone", "Expired", or the new question. The settle is not signed: it is sealed with the question key, so only a device of the vault can make it, and it changes nothing but the display.

## 10. Relay endpoints

### 10.1 Common rules

- Transport, headers, deadlines, and retries: relay-sync-v1 section 3. A `429` from the Worker holds every call to that relay, as there.
- Auth: `Authorization: Bearer apassy_acc_…`, the access token of a **live device** of the questions team (relay-sync-v1 section 5). The relay checks `Need::Member` and then requires `MemberAuth.device`; a member token gets `401 unauthenticated`.
- The team comes from the token. No endpoint takes a team id.
- Bodies: JSON, at most 64 KiB, `deny_unknown_fields`. `v` must be `1`.

### 10.2 Errors

| Status | Code | When |
| --- | --- | --- |
| 400 | `invalid_request` | Malformed JSON, an unknown field, `v` not 1; a `qid`, `key_id`, `nonce`, or `ciphertext` out of its form; an empty ciphertext; `to` not `member` or `approvers`; `expires_at` not in `(now + 10, now + 600]` on the relay clock; an answer or settle whose `key_id` differs from the question's; `since`, `after`, or `wait` not a number, `wait` over 25; a push token, environment, or bundle id out of its form. |
| 401 | `unauthenticated` / `token_expired` | As relay-sync-v1 section 4. |
| 403 | `not_routed` | An answer from a device outside the routing set (section 11), or from the asking device itself. |
| 403 | `too_many_questions` | The team has `open_questions` (20) open questions, or posted `questions_per_hour` (300) in the last hour. The message names which. Not `429`, so the app's other calls to the relay go on. |
| 403 | `too_many_answers` | The device already posted 3 answers to this question. |
| 404 | `not_found` | An unknown `qid` in this team (also after the 24-hour deletion); `GET …/answers` or `POST …/settle` by a device that is not the asker. |
| 409 | `conflict` | `POST /v1/questions` with a `qid` that exists in the team. |
| 409 | `question_settled` | An answer to a settled question; a settle of a settled question with another envelope. |
| 409 | `question_expired` | An answer or a settle after `expires_at`. |
| 409 | `push_unavailable` | `PUT /v1/push/token` on a relay without push (section 14). |
| 413 | `payload_too_large` | A body over 64 KiB, or a ciphertext over section 6.3. |
| 503 | `busy` | As relay-sync-v1. `Retry-After: 2`. |

Which code wins on `POST /v1/questions/{qid}/answers`, in order: 400 (shape) → 413 → 401 → 404 → 403 `not_routed` → 409 `question_settled` / `question_expired` → 400 (`key_id`) → 403 `too_many_answers`.

### 10.3 `POST /v1/questions`

```json
{"v":1,"qid":"oKGio6SlpqeoqaqrrK2urw","to":"member","expires_at":1790000300,"key_id":"630dcd2966c43366","nonce":"AAECAwQFBgcICQoL","ciphertext":"<b64u>"}
```

Answer: `{"qid":"oKGio6SlpqeoqaqrrK2urw","seq":41,"created_at":1790000001,"expires_at":1790000300}`. The relay stores the question with the caller's device and member, gives it the next `seq` of the team, wakes the question long polls, and triggers a push to the routing set (section 14). A retry after a network error with the same body gets `409 conflict` when the first one landed; the asker then treats the question as posted.

### 10.4 `GET /v1/questions?since=N&wait=S`

The questions whose routing set holds the caller, except its own, with `seq > since`, oldest `seq` first, at most 100 (with more, the device asks again with `since` = the last `seq`). `wait` 0 to 25: while there is none, hold the answer up to `wait` seconds. One question long poll per device; a second is answered at once, as with `wait=0`.

```json
{
  "seq": 42,
  "questions": [
    {"qid":"oKGio6SlpqeoqaqrrK2urw","seq":42,"to":"member","from_device_id":2,"from_device_name":"MacBook Pro",
     "key_id":"630dcd2966c43366","nonce":"AAECAwQFBgcICQoL","ciphertext":"<b64u>",
     "created_at":1790000001,"expires_at":1790000300,"state":"settled","settled_at":1790000031,
     "settle":{"key_id":"630dcd2966c43366","nonce":"ICEiIyQlJicoKSor","ciphertext":"<b64u>"}}
  ]
}
```

- `seq` (top level) is the team's current question sequence. A question gets a new `seq` when it is posted, settled, and expired, so a device that polls with its last `seq` sees each change once.
- `state` is `open`, `settled`, or `expired`. `settled_at` and `settle` are present only when settled.
- A top-level `seq` below `since` (a relay restored from a backup) means: the device sets `since` to 0 and reads again.

### 10.5 `POST /v1/questions/{qid}/answers`

```json
{"v":1,"key_id":"630dcd2966c43366","nonce":"EBESExQVFhcYGRob","ciphertext":"<b64u>"}
```

Answer: `{"id":7,"at":1790000032}`. The relay stamps the caller's device id, member id, member role, and time, stores the answer, and wakes the asker's answer long poll. It does not read it, and does not settle the question.

### 10.6 `GET /v1/questions/{qid}/answers?after=N&wait=S`

The asker only. The answers with `id > after`, in `id` order (arrival order), and the state:

```json
{"state":"open","expires_at":1790000300,
 "answers":[{"id":7,"device_id":3,"member_id":1,"role":"owner","key_id":"630dcd2966c43366","nonce":"EBESExQVFhcYGRob","ciphertext":"<b64u>","at":1790000032}]}
```

`wait` 0 to 25: while there is no such answer and the question is open, hold up to `wait` seconds. One answer long poll per device.

### 10.7 `POST /v1/questions/{qid}/settle`

The asker only. Body `{"v":1,"key_id":"…","nonce":"…","ciphertext":"<b64u>"}`. Answer: `{"qid":"…","state":"settled","settled_at":1790000031}`. The same body again answers the same (a retry); another body after a settle is `409 question_settled`. After `expires_at`: `409 question_expired`; the devices show "Expired".

### 10.8 `PUT /v1/push/token`, `DELETE /v1/push/token`

`PUT` with `{"token":"<hex>","environment":"production","bundle_id":"com.wydrox.apassy.companion"}`: one token per device, replaced on each call, which also clears a failed mark. `token` is the APNs device token as lowercase hex, 32 to 200 characters; `environment` is `development` or `production` (the `aps-environment` of the build); `bundle_id` must equal the relay's push topic. Answer `{"device_id":3,"updated_at":1790000000}`. `DELETE` with no body removes the token of the caller's device; answer `{"device_id":3}`. The iPhone sends `PUT` at each launch and each new token from iOS, and `DELETE` when the owner turns notifications off or leaves the vault.

## 11. Routing

The routing set of a question is computed by the relay when it lists, accepts an answer, and pushes, from the live state at that moment:

- every live device (not revoked, member not revoked) of the **asking member**, except the asking device;
- when `to` is `approvers`, also every live device of every live member with the role `owner` or `manager`.

Other members' devices never see the question, its existence, or a push. The routing bit `to` is one bit in clear: the relay knows whether a question is about production for a team (accepted leak, plan A3). The asker chooses `to`: `approvers` when the question is about a team item with `question.production` (section 5.4), else `member`.

## 12. The asker

### 12.1 Posting

When a run starts to wait and "Notifications through the relay" is on for the vault, the waiter thread of the questions membership (not the sync waiter) posts it:

1. Build the card, check section 6.3 and 7.2, and compute the digest v2.
2. `qid` = 16 random bytes; nonce = 12 random bytes; `expires_at` = the time the local question ends (`QUESTION_WAIT`, 300 s, after it started to wait).
3. `POST /v1/questions`. A failure that can pass (no network, `500`, `503`, a non-JSON answer) retries after 2, 4, 8, 16, 30, 30… seconds while the question waits. `403 too_many_questions` and `413` do not retry: the question stays local, and Activity says why.
4. A call of the same agent that joins the waiting question (`QuestionRefusal::Superseded`) posts nothing new.

The local card shows at once; it does not wait for the relay.

### 12.2 Reading the answers

While the question waits, the asker long-polls `GET /v1/questions/{qid}/answers?after=<last id>&wait=25` and processes each answer in `id` order, once.

### 12.3 First valid answer wins

For each answer, in order, the asker checks; the first failure skips the answer with an Activity line ("An answer from <device> did not count: <reason>") and goes on to the next:

1. It opens with the question's key and the AAD with the stamped `device_id` (section 6.1).
2. The JSON has the fields of its kind, `v` is 1, `qid` is this question's.
3. `by` is a live `trusted_device`; its `relay_device_id`, when set, equals the stamped `device_id`.
4. `kind` is valid for the question (section 9.1) and its extra fields match the question.
5. `digest` equals the digest v2 of the run **as it waits now**. Else the reason is "the request changed".
6. For `to: "approvers"`: an approving kind (`approve_once`, `approve_in_project`, `allow_production`) counts only with a stamped `role` of `owner` or `manager`.
7. The owner check of section 12.4 passes, for the approving kinds and `correct_environment` to `development`; for the other kinds, the `sign_key` signature verifies over the rebuilt answer string and `time` is in the window of 12.4.
8. The queue takes it (`ApprovalQueue::approve` or `deny` / `deny_stricter`). A refusal (`NotWaiting`: an answer on this Mac or through the companion came first; `Changed`) ends the processing: the question is already settled locally.

The first answer that passes every check takes effect. Then the asker posts the settle (section 9.4) with the outcome. When the question ends any other way (a local answer, the timeout, a lock, the broker stopping), the asker posts the settle with that outcome, best effort, while it still has a token: a lock never waits for the network, and a question that gets no settle expires on the relay.

### 12.4 `OwnerCheck::Remote`

`OwnerGate::authorize(action, OwnerCheck::Remote { device_uuid, team_id, qid, time, signature })`, with `action` the `OwnerAction` of section 9.1 for the run as it waits. `CheckMethod::Remote` is recorded with the decision. The gate:

1. loads the live `trusted_device` with `device_uuid` from the vault in this session (else `RemoteRejected`);
2. checks `now - 60 <= time <= now + 60` on the Mac clock (`PROOF_LIFETIME`, and the 60 s future slack of the companion; else `RemoteStale`);
3. rebuilds the answer string from `device_uuid`, `team_id`, `qid`, the choice made from the action (its kind, action, project key; the item id and environment of a correction), the digest v2 of the run in the action (for a correction: of the run that waits for this `qid`), and `time` (a control character: `RemoteRejected`);
4. verifies the signature with `answer_key` for an `iphone` row (a NULL `answer_key` is `RemoteRejected`) or `sign_key` for a `mac` row;
5. checks the vault session before and after, as for Touch ID.

A remote check can make a proof only for `ApproveRun`, `ApproveInProject`, `AllowProduction`, and `ChangeItemRules` for a correction of an item of the waiting question. Any other action is `RemoteUnsupported`: a remote device can never reveal, grant, pair, connect an agent, or change a setting. The answer is counted as one owner interaction by the broker, as a local answer is (ADR 0025 §1).

### 12.5 A correction, and a changed question

`correct_environment` does not settle: the question still waits, and the device may answer again (at most 3 answers per device per question). When the waiting run changes after a correction or a new evaluation, so that its digest v2 differs from the posted card, the asker settles the old `qid` with `outcome: "replaced"` and `replaced_by`, and posts a new question with a new `qid` and the rest of the old expiry. The devices show the new one.

## 13. The answering device

1. **Find.** It long-polls `GET /v1/questions?since=<last seq>&wait=25` while it runs in the foreground (an iPhone), or always while the vault is unlocked (a Mac with the feature on). A push wakes the iPhone app only when the owner opens the notification; the app then reads the list.
2. **Show.** It opens and checks each open card (section 7.3), and shows it as on the asking Mac, with "Asked on <asker.name>". A Mac shows a remote question in Decisions next to its own, marked with the asking Mac. A settled or expired question leaves the list; the device shows "Answered on <device_name>" or "Expired" when it was open on the screen.
3. **Answer.** The owner selects an answer. The device sets `time`, builds the answer string, asks for Face ID (iPhone, `answer_key`) or Touch ID (Mac, `OwnerAction::AnswerRemoteQuestion`) for the approving kinds of section 5.3, signs, seals, and posts. It shows "Sent. Waiting for <asker.name>…" until the settle arrives.
4. **Retries.** After a network error or a `500`/`503`, it posts the same answer again (a new nonce and envelope, the same signature) while `time` is less than 55 s old; after that it asks again. A `409 question_settled` or `question_expired` shows "Already answered" or "Expired", with the settle text when it has it. A `403 not_routed` shows "This device cannot answer this question".
5. The relay accepting an answer does not mean that it counted: only the settle says what happened.

## 14. Push

### 14.1 What Apple sees

The relay asks the Worker to send, for each new question, one push to each live token in the routing set. The payload is fixed and the same for every question and every vault:

```json
{"aps":{"alert":{"title":"Apassy","body":"A question is waiting"},"sound":"default","interruption-level":"time-sensitive"}}
```

APNs headers: `apns-push-type: alert`, `apns-priority: 10`, `apns-topic: <bundle id>`, `apns-expiration: <expires_at>` (an expired push is not delivered), `apns-collapse-id: apassy-question` (a constant: a new question replaces the visible notification, and the id tells Apple nothing). Apple sees the device token, the time, and the bundle id: who has Apassy and when a question arrives. It sees no qid, no agent, no item, no vault.

The relay side of the push (`POST /internal/push` on the Worker with the edge secret, the APNs token key as a Worker secret, the HTTP/2 spike and its fallback) is in the relay SPEC section 25.

### 14.2 The iPhone

- Entitlements: `aps-environment` (`development` in debug builds, `production` for TestFlight and the App Store), the `remote-notification` background mode, and the time-sensitive notifications capability (`com.apple.developer.usernotifications.time-sensitive`) for `interruption-level`.
- It asks for notification permission when the owner turns on "Notifications through the relay" on the iPhone, not at launch. A refusal leaves the long poll while the app is open.
- The notification shows the fixed text. Opening it opens Questions, which reads the list.

## 15. Limits

| Limit | Value | Where |
| --- | --- | --- |
| Question lifetime | `expires_at` in `(now + 10, now + 600]`; the app uses 300 s | relay; app |
| Open questions | 20 per team (`open_questions`) | relay: `403 too_many_questions` |
| Questions per hour | 300 per team (`questions_per_hour`) | relay: `403 too_many_questions` |
| Waiting questions per agent | 1 (ADR 0024, ADR 0025 §3) | app |
| Answers per device per question | 3 | relay: `403 too_many_answers` |
| Card / answer / settle ciphertext | 32784 / 8208 / 1040 bytes | relay: `413` |
| Question long polls | 1 per device for the list, 1 per device for answers; `wait` 0 to 25 s | relay |
| Questions in one list answer | 100 | relay |
| Push tokens | 1 per device | relay |
| Retention | questions and answers are deleted 24 hours after `created_at` | relay |
| Proof window | `time` within 60 s of the asker's clock, both ways | app |

## 16. Expiry, replay, offline, and late answers

- **Expiry.** The relay marks a question `expired` at `expires_at` (its maintenance runs every 5 s) and refuses answers after it. The asker's own deadline is the same time; the queue times out the run.
- **Replay.** A `qid` is 128 random bits. Each answer signs the team, the `qid`, the choice, the digest, the device, and the time. The queue settles once; the relay refuses answers after a settle; a proof older than 60 s does not count. An answer replayed into another question, another team, or another run fails the signature; replayed into the same question it finds the queue settled.
- **The relay** can drop, delay, reorder, or duplicate envelopes, and can refuse to route. It cannot read a card or an answer, make an answer that counts, move an answer to another device, or change the routing bit or the expiry without the card failing to open. Drops and delays make questions wait on the asking Mac, where the local card always works.
- **Offline asker.** The local card and the local-network companion are unchanged. Posts retry within the 5 minutes (section 12.1). A question posted while the asker was online keeps its answers on the relay until it expires; the asker reads them when it is back, and an answer older than 60 s by then does not count.
- **Offline answering device.** It sees open questions at its next list. Pushes expire with the question.
- **Late answers.** After the settle or the expiry the relay answers `409`; the device shows "Already answered on <device>" or "Expired".
- **Lock.** A lock of the asker's vault ends the waiting runs (`invalidate_all`), drops the relay token, and stops the waiter. Its open questions expire on the relay. A lock of an answering Mac drops its questions view; an iPhone needs the vault unlocked to read the key.

## 17. Versioning

- `v` is `1` in every request body, card, answer, and settle. The relay refuses another `v` with `400`. A device that cannot read a card's `v` shows "Update Apassy to read this question".
- The tags `apassy-question-v1` (AAD), `apassy-question-answer-v1` (answer string), and `apassy-question-v2` (digest; v2 because it extends the companion digest v1) change with any change of their bytes. The vault secret name `question-key-v1` changes with the key's meaning.
- New optional fields in a relay result are ignored by the app. A new field in a card, answer, or settle is a new `v`.
- The local-network companion keeps contract companion-v1 and digest v1.

## 18. What this does not protect

- **The vault is the trust root.** Any device that holds the vault holds the question key and can write `trusted_device` rows. A device removed from the vault but still holding a copy of it (for example through iCloud Drive) gets the next key by its sync, until it no longer syncs. Removing a device for questions also needs it out of the vault's sync.
- **A Mac's `sign_key` is not biometric.** It is in the vault (local table) and usable while the vault is unlocked. The local Touch ID before a Mac signs an approving answer is enforced by the answering Mac's app, not by the key: malware on another Mac with the vault unlocked can sign an approval. An iPhone's `answer_key` needs Face ID in the Secure Enclave.
- **Metadata.** The relay and its operator see which devices of which team post and answer, when, how large the envelopes are, and the routing bit. Cloudflare sees the same. Apple sees which devices get a push and when.
- **Roles from the relay.** For `to: "approvers"`, the role that counts is the relay's stamp (section 12.3 step 6). A relay that lies can make a member's valid answer count as an approver's. With V3 the roles should come from the shared vault (section 19).
- **The relay can deny service**: drop questions, answers, or pushes. The asking Mac always keeps its local card.
- **Display text.** The card shows the agent's and the bouncer's text. A prompt injection in those fields reaches every device; it is shown as text, never as a link.

## 19. Open questions

1. **Approvers' keys and trust (V3).** Devices of other members need the question key (proposed: `device_wrapped_key`, section 5.4) and their `trusted_device` rows from the shared vault, and roles that do not come from the relay. Which P-256 key of the device takes the ECDH wrap (the relay device key is a signing key; the Secure Enclave separates signing and key agreement)?
2. **An approving answer for a production team item by the member.** This contract counts `approve_once` on a `to: "approvers"` question only from an owner or a manager (section 12.3 step 6). ADR 0025 §3e names only the production allowance.
3. **More than one questions team.** `trusted_device.relay_device_id` holds one id. A vault whose devices are in two teams (sync and notifications) needs one id per team, or the rule "the questions team is the sync team when there is one".
4. **The notification after a settle.** The pushed notification stays in Notification Center after another device answers. A background push to remove it would need `apns-push-type: background` and a second request; not in v1.
5. **Member lane capacity on the relay.** Question long polls, like sync long polls, run in the member lane of 32 requests of the whole relay (SPEC section 9). See SPEC section 25.
6. **The device uuid form.** Section 4 fixes a 36-character UUID for `trusted_device.uuid`; stream F19 must use it.

## 20. Test vectors

These values are synthetic. Every suite (the app, `apassy-core` for the iPhone, the relay for the AAD and sizes) uses them. They were computed with a throwaway Rust program on `ring` 0.17.14 (`ring::aead::CHACHA20_POLY1305`, `ring::digest`, `ring::signature`), the primitives the app uses, and checked independently with Python `cryptography` (`ChaCha20Poly1305`) and `hashlib`: both give the same digests and ciphertext.

| Name | Value |
| --- | --- |
| Question key (hex) | `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f` |
| `key_id` | `630dcd2966c43366` |
| Team id | `t_7k2m5q4x3c` |
| `qid` (bytes `a0` to `af`) | `oKGio6SlpqeoqaqrrK2urw` |
| `to`, `expires_at` | `member`, `1790000300` |
| Asker device uuid | `0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d` |
| Answering device uuid, relay device id | `6f1c0e2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b`, `3` |
| Card nonce (bytes `00` to `0b`) | `AAECAwQFBgcICQoL` |
| Answer nonce (bytes `10` to `1b`) | `EBESExQVFhcYGRob` |
| Settle nonce (bytes `20` to `2b`) | `ICEiIyQlJicoKSor` |
| Answer key, private (hex) | `bb684f0551ffd30d7040500bc8fa0d83efd5dbde18ea1e253f098b6ddfca5f1b` (the approval key of companion-v1 section 9) |
| Answer key, public (b64u) | `BAotqUNjRqTfgIY4YuJGS5yZV2N5Jat0I5dFMlv29IqSFmgkZk2dzWe-n2AcgOt933rMrBOrK054Bc7RwNTeyts` |

### 20.1 Digests

The run is the base run of the tests in `src/companion/digest.rs` (id `123456789012345`, agent `claude-code`, command `npm run migrate`, cwd `/tmp/synthetic-shop`, the same texts).

| Name | Value |
| --- | --- |
| Digest v1 of the base run, with its remember offer `npm run migrate`, 1, 3 | `f9eaafb74648d988f9d086cd06f21f1f5f9a2429fa30e23ffa3a9d167dab4245` |
| Digest v2 of the base run with `remember: None` and the question of section 7.1 (input 708 bytes) | `f3b3231d5e65efa3edf428f34bb446d0b6d81ac964256e973c2ebf1d517f267d` |
| Digest v2 of the base run, with its remember offer, and `QuestionInfo::default()` (`id` 0, no items, no project, `change`, not production, empty `why`, `["once"]`) | `0807a3e555dbde9f82b73ab8a6660911c1a28149eb1fe6382460166a798bf274` |

The question of the second row: `id` `123456789012345`; `item_ids` `[7, 9]`; `project` `/tmp/synthetic-shop/.git`, `synthetic-shop`; `action` `deploy`; `production` true; `why` `A production credential goes to a deploy.`; items `7` `Shop database` (production), `9` `API token` (unconfirmed); `valid_answers` as in section 7.1.

### 20.2 The card

The card plaintext is exactly these 1138 bytes (one line, no newline at the end; SHA-256 `6b25b67d3570fe460fd30999abdd692269f46fd092f015846baafc2ba57c03dc`):

```
{"v":1,"qid":"oKGio6SlpqeoqaqrrK2urw","asker":{"device":"0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d","name":"MacBook Pro"},"created_at":1790000000,"run":{"id":"123456789012345","agent":"claude-code","command":["npm","run","migrate"],"cwd":"/tmp/synthetic-shop","env_names":["DATABASE_URL","API_TOKEN"],"purpose":"Apply the new migration.","risk":"production credential: always asks the owner","user_request":"Deploy the new schema to staging.","request_source":"from the host hook","agent_request":"Run the migration.","remember":null},"question":{"id":"123456789012345","item_ids":["7","9"],"items":[{"item_id":"7","name":"Shop database","production":true,"unconfirmed":false,"always_ask":false},{"item_id":"9","name":"API token","production":false,"unconfirmed":true,"always_ask":false}],"project":{"key":"/tmp/synthetic-shop/.git","label":"synthetic-shop"},"action":"deploy","production":true,"why":"A production credential goes to a deploy.","valid_answers":["once","production:deploy","correct_environment","never_for_agent","always_ask_for_agent","disconnect"]},"digest":"f3b3231d5e65efa3edf428f34bb446d0b6d81ac964256e973c2ebf1d517f267d"}
```

Card AAD (text, `\0` is one zero byte): `apassy-question-v1\0card\0t_7k2m5q4x3c\0oKGio6SlpqeoqaqrrK2urw\0630dcd2966c43366\0member\01790000300`

Card AAD (hex):

```
6170617373792d7175657374696f6e2d7631006361726400745f376b326d357134783363006f4b47696f36536c7071656f71617172724b327572770036333064636432393636633433333636006d656d6265720031373930303030333030
```

Card ciphertext (hex, 1154 bytes; SHA-256 `23bff23dc75b1d95e9e20a69e3b2fd622377422a0f781c749f0abec68c843d4f`; the last 16 bytes are the tag `a64023ed808b856f3e612507ce64a66b`):

```
f2d97e2213268962c6ea5bd1a23f61288e19ddd10218ddc883f85ea404b2d477def55e84c43293f9445913aa47aef4011ae1df1d9e4d9aa13088bb30f57afde5185585a9d47201dda5242f91201fea95f7ea2202095b910c6c64933abc5f2e9d23bf0196d5e305b9d038b1d8cdfa97d09b007445a57f238a2a0c40ba1d60de32835cf28a9003ef5c79234f4a001e194fda53bd092906a87c08c39603972f950f0881b8d88c76a7d2bb5c4a3206d68a6eaa769c6874371b60bc7ac3f20852f132f5653ce00e906e71496a1f55ef281d6040f4e74e13618d7b344445c2897b08984e1e2692edc761c2e0d82732c668bbff8931df900e0fc3fd93f303b495df2d00e6ff74d60725dbf1e8f8a51c48b59fbab440e585539629fb5744514e5432f0097360125db91fad7922072ba7e46729661b4d8997ddb612f737c872a6020d0bde2233e7626b3de5f7808253ac3be6e0d31dc7aa6282180fbb043a20f46eb42b180b1a695f1c13360fb03ddfbb58c46063d173951a4982f4a0913f3339535b78f7854537a69637511d5e2c226e30d37f159a0ec897fc28d4a6ea749989f37b590cf7f6a30caf27de4e2802d14b1db0dc0de3db79e82ccd1e76f2572f82af25e365317e42bffd3e97a056e727352a699d6350e12f9ceb2b7ddb169decdad203236ff12350de3bab743232a4dd3f5685f47cc72981327ed03cc4323d575371249f8418739fe2eee8a3fc7ceda1da72d0a62d8a741b920ad04be913f15fae7d572703194d4cba17f66443a28362038e58c0dff69e4307fbb11072f42b14735d691cf1ff6c91e24f9f65d451fabe07796ea5299e93c7586b6e3280d03d436c14146585f0b9e3218f4a52c29ed0798582b55c22aa91d40bd1ec73bfc38c2bd3407fd7c8ccc8e0e4575223d1eccdb3c4f760df7b7122667449f39c38c89422c0dc468bf2a0665307af7d388d734d4656b83983446820fedce1131846d821fe09ca81baaa8a80aae9c92d925bf07de3974e62c60d4ad08adc9b7d4a1f700915d1ea0b967ea64c84bc4780add5347e5153825db90afa9c02f3cbaaa126dbc3fb97c2ba8ed92c4cc0d241e23d6fc59b78b4d59e36d0882f110acdbdb75e026c9df55fc80577c8726e7e012d391ede22c42ce32ba5878926adf56d7cab49b150a201d9fa07f545dd5152181821c7e17100ff04cb5f46b3d3e7a7b675e9c4c6d63198562b627b8392a4ec03ca59e2f19396cd8817eb18109903c1fb0afd39b6c4462405490fcf931f1053ecf73483e7b28c3ac615f63f4fab000a6259259a98d219dde6c4e8715c1e14eebd130f6e1f22ee269ef7f6c1acac47d244597baeb538b9e97c83438bb4f1eca9a36ebef614c3b6cd86f4b4868b9a6c81d78d3dce172a591b5bba86b4245b79040a3cb37079e995f5e8b83b1113c1bca6576f113d645d1136accc2bff64bada12aad3eb950834f63caa3fff01c55952edd9ac6f374f86eded6cc93825c114418705f39324695c99b3d7e9914484015fd789ccc85359d662fdddf55cc373592d345335c277af91b1f2bb758f652496ca22d87b75118bb17eafb0885e9759633a2cb69ccaa58a3890a212cabd334cb8a64023ed808b856f3e612507ce64a66b
```

### 20.3 The answer

`allow_production` for `deploy` in `/tmp/synthetic-shop/.git` by the answering device at `time` `1790000030`. The answer string (the bytes between the fences, `\n` between the lines, none at the end; SHA-256 `92988898270a1b99cbe4550c67ba69f8a5d3c872bc9f9b41341cb19d2eaab270`):

```
apassy-question-answer-v1
6f1c0e2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b
t_7k2m5q4x3c
oKGio6SlpqeoqaqrrK2urw
allow_production:deploy:/tmp/synthetic-shop/.git
f3b3231d5e65efa3edf428f34bb446d0b6d81ac964256e973c2ebf1d517f267d
1790000030
```

Signature by the answer key (b64u DER; it must verify with the public key above): `MEQCIGMC9y1cqvAp-20KSFEKld0OxGzAAChwzuk1koc-mdXRAiAU9SNPzZkCVoP16J25cR9fHwzNI7JcENt9p-SIAsvETA`

The answer plaintext (370 bytes, one line):

```
{"v":1,"qid":"oKGio6SlpqeoqaqrrK2urw","by":"6f1c0e2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b","kind":"allow_production","action":"deploy","project_key":"/tmp/synthetic-shop/.git","digest":"f3b3231d5e65efa3edf428f34bb446d0b6d81ac964256e973c2ebf1d517f267d","time":1790000030,"signature":"MEQCIGMC9y1cqvAp-20KSFEKld0OxGzAAChwzuk1koc-mdXRAiAU9SNPzZkCVoP16J25cR9fHwzNI7JcENt9p-SIAsvETA"}
```

Answer AAD (hex; text `apassy-question-v1\0answer\0t_7k2m5q4x3c\0oKGio6SlpqeoqaqrrK2urw\0630dcd2966c43366\03`):

```
6170617373792d7175657374696f6e2d763100616e7377657200745f376b326d357134783363006f4b47696f36536c7071656f71617172724b3275727700363330646364323936366334333336360033
```

Answer ciphertext (hex, 386 bytes):

```
25e833253c28ea4b6aaf5741e389da3e3d0f9a1fd7aea605e7fcc66c9dced1adcefff20efba899be0cb7c1ceb3cb32bf206d626c9953465defbab3b89e8d1ff8327cf7ec21c7ec2787484140c0b291f117db2557de3967a5f61be0d5bcf26128d2d20e2eda7de6910266abba48c80fb399588f148fb234ca61707674c2ca04549304e6b80a7a418b40b0a3e798143e954cf74dafda3441b8e0a99ded218ce4f533dcfdffac93b4114b8dd6b5a4bffeb094da742ad1e5e6a8821c796b3c594c23683028ef1c55d1b464cce313780013a5fecc377db92cc3bfcd5469686e75b04a01e226f674b06b3e519ad72f975b5aee88e3e4a8c5e8d3edca1a4b57c3d1627e17b8a7630579bf1b458e7660749530e2b713d036f4b7b363d0935a5b115481975d54a9351cda0cba86e3d202a94a984f4dd2bedf7d690c38ed4a3c058e95c8456e92c408d061d0062ede9e7299e4a0e157b9fc13d09fd25e76bfa0b456b99d17885a8f5d6583b02cbe06327ca1eb93ab08de920c3f69fd1aa8d635952bfa3b561c30
```

### 20.4 The settle

The settle plaintext (205 bytes, one line):

```
{"v":1,"qid":"oKGio6SlpqeoqaqrrK2urw","outcome":"approved","answered_by":"6f1c0e2a-3b4d-4e5f-8a9b-0c1d2e3f4a5b","device_name":"Test iPhone","device_kind":"iphone","kind":"allow_production","at":1790000031}
```

Settle AAD (hex; text `apassy-question-v1\0settle\0t_7k2m5q4x3c\0oKGio6SlpqeoqaqrrK2urw\0630dcd2966c43366`):

```
6170617373792d7175657374696f6e2d763100736574746c6500745f376b326d357134783363006f4b47696f36536c7071656f71617172724b327572770036333064636432393636633433333636
```

Settle ciphertext (hex, 221 bytes):

```
08c5fe5e2bded018eaacc9ea731de0f33c0711044305ef3ce38e4cc5cdc9a95931c2f021ee37f50891bb8e780d94417ae76d1515fc3c76f7ca24e0c3472df717faea79cbe8b60ad589fe1467835b1e42cf7dad045cca0dc97bf303a57429ee4bc00a4175fd49e86be86a99b517e0fba583d6af00b7fc7d6a983f524c793c91a2f1a27695d2a61fb5a3dfb82ba1b0cc87f5cb65f8b240c5048e9db9946699d9cf33b2e300c919917c85e02c39b7da8a4cbd1d46065030eb6a8df582bea0f277bfec618de93fe7d74fd233a2f8646fb5f066a9390178f5251b3cc003cfec
```

### 20.5 What the suites must show

- The key gives `key_id`; the base run gives the three digests; the card's `digest` equals the second.
- Each plaintext seals to its ciphertext with its key, nonce, and AAD, and each ciphertext opens to its plaintext.
- The card does not open with `approvers` instead of `member`, with another `expires_at`, `qid`, team id, or `key_id`, or with the part `answer`. The answer does not open with the device id `2`. The settle does not open as a card.
- The answer signature verifies over the answer string and fails after one changed character of it, and with the companion request key. ECDSA signatures are randomized: a new signature of the same string differs and still verifies.
- The asker accepts the answer for the question of section 7.1 with the clock at `1790000030` to `1790000090`, and refuses it at `1790000091` (stale), with another digest (`changed`), with the choice `approve_in_project:deploy:/tmp/synthetic-shop/.git` (not in `valid_answers`), and from a `trusted_device` row whose `answer_key` is another key.
- Every field of `QuestionInfo` changes the digest v2 (as `every_field_changes_the_digest` for v1), and moving text between `why` and an item name, or between two items, changes it.

## Integrator decisions on the open questions (2026-10-12)

1. **Team approvers.** Until shared vaults (V3) give approvers the question key, their device entries and roles, every question goes to the asking member's own devices only. A production question about a team item cannot be answered remotely until then; it waits on the asking Mac.
2. **"Allow once" on a production team item** needs an owner or a manager of the team (ADR 0026 §6). Kept.
3. **One relay id per device is not enough.** Schema 19 maps a trusted device to a relay device id per team (`trusted_device` → per-team mapping), so one vault can be in a notifications-only team and in shared-vault teams.
4. **Long polls.** The relay gets a separate pool of long-poll slots for questions (stream R4), so question waits do not take the shared member slots.
5. **Push secret.** The relay calls the Worker's push route with its own `PUSH_SECRET`, not the edge secret.
6. **Bundle id.** `com.wydrox.apassy.companion` (checked in `ios/ApassyCompanion/project.yml`). Device ids follow the schema 19 `trusted_device.uuid` format.
