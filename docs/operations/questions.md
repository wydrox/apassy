# Questions through the relay

## Remote owner prompt contract (2026-11-02)

Command questions publish the exact **card `v: 1`** format by default, so old
iPhones keep working and new signed answer choices are accepted. Publication is
controlled by `QUESTION_CARD_VERSION = 1` in `src/questions/envelope.rs`.
The v2 encoder is retained but OFF. Do not switch it to 2 until all recipients
support it: `post_question` sends one ciphertext to all member devices, devices
declare no capabilities, and the relay is unchanged. The iPhone decoder in
`ios/ApassyCore/src/core/questions/envelope.rs` uses `exact()` to reject extra
fields and versions other than 1; it does not ignore new fields. TestFlight
0.5.10 therefore cannot read v2. A new iPhone can use the v1 fields below without
enabling v2 publication. The Mac reads both versions and accepts every old answer
kind. Answer/settle/envelope versions, encryption AAD, routes and digest v2 remain
unchanged. This extension applies to command approvals, not access-request cards.

The disabled card v2 encoder keeps every v1 field and adds this required root object:

```json
{
  "v": 2,
  "owner_prompt": {
    "agent_stated_task": "Deploy the requested change",
    "purpose": "Run the migration",
    "task_provenance": "agent-stated",
    "reason_headline": "Why the owner is asked",
    "environment_known": false,
    "allowed_answer_kinds": ["deny", "deny_with_comment", "approve_as_development", "approve_as_production"]
  }
}
```

The example omits the unchanged root fields `qid`, `asker`, `created_at`, `run`,
`question`, `digest`. `run.user_request` is the effective task; `run.agent_request`
is the differing agent task when a verified hook replaced it. The display field
`owner_prompt.agent_stated_task` uses `run.agent_request` when nonempty, otherwise
`run.user_request`. Purpose is also retained as `run.purpose`. Provenance is
`hook` or `agent-stated` (sources beginning `from the agent`, or empty, are
agent-stated). Headline is `ReasonKind::headline()`. Environment is known exactly
when no question item is `unconfirmed`. These display fields are sealed but do
not change digest v2. Clients must continue to compute digest v2 from the original
v1 fields, including `question.valid_answers`; do not add `owner_prompt` to it.

### iPhone button derivation from v1

Inspect `question.items[*].unconfirmed`. A `true` means the environment of that
item is unknown, including an item with no environment declaration (the Mac
represents that absence as `unconfirmed: true`; there is no nullable environment
field). When exactly one item has `unconfirmed: true`, offer **Allow as dev**
(`approve_as_development`), **Allow as prod** (`approve_as_production`),
**Dismiss** (`deny`), and **Dismiss with comment** (`deny_with_comment`). Unknown
takes precedence even in a mixed question that also contains confirmed production
items. The answer names no item: the Mac labels only that one unconfirmed item.

When no item, or two or more items, have `unconfirmed: true`, offer **Allow**
(`approve`), **Dismiss** (`deny`), and **Dismiss with comment**
(`deny_with_comment`). The Mac bar has one **Dismiss** beside a comment field: it
sends `deny_with_comment` when the field holds text, else `deny`. With two or more unknown items an answer without an item
could label a production credential that the owner did not look at, so the run
asks as any other and labels nothing; the owner labels each item on the Mac. An item's `production: true` with `unconfirmed: false`
means confirmed production; both flags false mean known non-production.
`question.production` is the question-level production flag, not the unknown
environment test. Do not infer unknown status from `why`, `risk`, item names,
or `question.production`.

The Mac derives these offers from its live pending question exactly as for its
local buttons, independent of card version and the legacy offer list.
`owner_prompt.allowed_answer_kinds`, when v2 is enabled, reflects the same rule.
New unoffered kinds are refused. The original `question.valid_answers` remains
unchanged for legacy clients and digest v2; it gates only legacy answer kinds.

Answer plaintext JSON has exactly `v` (1), `qid`, `by` (trusted-device UUID),
`kind`, `digest` (unchanged lowercase digest v2), `time` (Unix seconds integer),
and `signature` (unpadded base64url DER ECDSA P-256/SHA-256). For
`deny_with_comment` only, it also requires `comment` (JSON string). No other
extra fields are allowed for the five current kinds:

| `kind` | Effect | iPhone signing key |
| --- | --- | --- |
| `approve` | Approve known-environment run once | Secure Enclave `answer_key` |
| `approve_as_development` | Classify the one unknown item development and approve once | `answer_key` |
| `approve_as_production` | Classify the one unknown item production and approve once | `answer_key` |
| `deny` | Dismiss | `sign_key` |
| `deny_with_comment` | Dismiss and return comment to agent | `sign_key` |

Both classify answers take no item/environment field: they classify every unknown
item of the exact signed pending run. They use the same queue guard as the Mac
buttons (exact pending run, unconfirmed item, proof/session, live deadline).
The broker writes classifications only after its final unchanged-authorization
check, through the same persistence path as local buttons. A comment carries no
authority and is returned only on the denial path.

Normalize comments **before signing**: remove Unicode control scalars (`Cc`),
U+2028 and U+2029; take the first 500 Unicode scalar values; then trim Unicode
whitespace at both ends. No Unicode composition normalization or markup parsing
is performed. Empty normalized strings are permitted. The Mac rejects a wire
comment that differs from this normalized result, including one over 500 scalars.
Render as plain text. The exact signed UTF-8 message is seven LF-separated lines,
with no trailing LF:

```text
apassy-question-answer-v1
<by>
<team_id>
<qid>
<choice>
<digest>
<time>
```

For `approve`, `approve_as_development`, `approve_as_production`, and `deny`,
`<choice>` is exactly the kind string. For `deny_with_comment` it is
`deny_with_comment:<unpadded-base64url-of-normalized-comment-UTF8>`.
For example, comment `No` produces `deny_with_comment:Tm8`. Changing comment
bytes invalidates the signature. A Mac uses its `sign_key` for all answers,
with an owner check for each approving answer. Device/team/qid/digest bindings,
the +/-60 second signature window, ordered replay protection, relay routing and
first-winner settlement remain in force.

Legacy mappings are intentionally compatible: `approve_once` is a one-run
approval (also accepted on an unknown environment, without classification);
`approve_in_project` and `allow_production` retain their offered project/action
remembering behavior, closest to Allow with the secondary remember option;
`correct_environment` retains the old per-item correction without settling or
approving (development requires the answer key, production the sign key).
`never_for_agent`, `always_ask_for_agent`, and `disconnect` remain stricter
denials with their existing restrictions. `deny` is unchanged. Legacy kinds
still require their original offers and extra fields. Their signed choice lines
remain `approve_once`, `approve_in_project:<action>:<project_key>`,
`allow_production:<action>:<project_key>`,
`correct_environment:<development|production>:<item_id>`, `never_for_agent`,
`always_ask_for_agent`, and `disconnect`, respectively. No legacy kind accepts a
comment, and no legacy signature is reinterpreted as a classification-and-allow.

Stage 5 of [ADR 0025](../adr/0025-low-friction-access.md) (§3d, §3e), contract [relay-questions-v1](../contracts/relay-questions-v1.md). The app side is `src/questions/`, `src/vault/questions.rs`, `src/relay/membership.rs`, the question digest v2 in `src/companion/digest.rs`, and `OwnerCheck::Remote` in `src/broker/approvals/owner_auth.rs`. The window side is Settings > Devices (`src/desktop/ui/settings.rs`, `src/desktop/ui/sync/questions.rs`, and "Add a Device…" in `src/desktop/ui/sync/relay.rs`) and Decisions (`src/desktop/ui/decisions.rs`).

## What it does

A run that waits for the owner is a question. It always shows on the asking Mac (the card) and, on the local network, on a paired iPhone (companion-v1, digest v1). With **Settings > Devices > "Send questions through the relay"** on, the asking Mac also:

1. seals the question card with the question key of the vault (ChaCha20-Poly1305, AAD of contract section 6.1) and posts it (`POST /v1/questions`, `to: "member"`, `expires_at` = the end of the 5-minute wait);
2. long-polls the answers (`GET /v1/questions/{qid}/answers?wait=25`) and checks each one in order (contract 12.3): it opens with the key of the question and the device number that the relay stamped, has the fields of its kind, comes from a live `trusted_device` of the vault, is offered by the question, has the digest v2 of the run as it waits now, and verifies: an approval or a correction to development through `OwnerGate::authorize` with `OwnerCheck::Remote` (the iPhone `answer_key`, or the Mac `sign_key`), a stricter answer with the `sign_key` and the 60-second window;
3. applies the first answer that passes through the approval queue (`approve` with a `CheckMethod::Remote` proof, `deny`, or `deny_stricter`), and settles the question on the relay (`POST …/settle`) with who answered;
4. settles a question that ended another way (an answer on this Mac or through the companion, the timeout, the broker stopping) with that outcome, best effort.

An answer that does not count gets an entry in the activity log ("An answer from DEVICE did not count: REASON."), with no command, no credential, and no value. Decisions shows "AGENT: Answered on DEVICE" for 10 minutes after an answer from another device.

The relay sees only the routing: the team, the devices, the times, the sizes, and the bit `to`. It never gets a command, a credential name, a variable, or a value: every card, answer, and settle is sealed.

## Turning it on

The switch is **off by default**. It is on exactly when the open vault has, on this Mac, a relay membership with the purpose `questions` (`relay_membership`, a local table). It is disabled only while the vault is locked.

On opens a new channel that can approve runs, so it needs the **owner check** (Touch ID or the passphrase) for `OwnerAction::EnableRelayQuestions { relay_url, team_id }` before anything changes. The proof names the relay and the team, and the app checks it in the vault session before it acts.

- A vault that syncs through the relay: the check names its sync team. Then the switch adds the purpose `questions` to the sync membership (`relay::membership::enable_questions`). No relay call. It also makes the question key (`vault_secret 'question-key-v1'`, `Vault::ensure_question_key`) when the vault has none, and registers this Mac as a `trusted_device` (kind `mac`, `sign_key` = the public key of the membership, its device number in the team). The key and the row reach the other devices through the sync.
- A vault without relay sync (iCloud Drive, a folder, or none): the switch opens the sheet "Questions of VAULT through the Apassy relay" with the relay address (the Apassy relay by default), the operator team code (masked, as in "Turn on" of relay sync), and the name of this Mac. "Turn On…" checks the fields, then the owner check names the relay and no team (`team_id: None`). After it passes, `POST /v1/teams` runs on a thread of its own with no vault (`relay::membership::new_questions_team`): a new device key and a team that never gets a snapshot. Then the vault keeps the membership with the purpose `questions` only (`adopt_questions_team`), makes the question key, and registers this Mac. The team code stays in memory only from "Turn On…" to that call; a lock, another sync sheet, a failed check, and Cancel erase it. `create_questions_team` does both steps in one call for a caller without a window.
- **A vault that has a questions team already** (a second Mac of a vault in iCloud Drive: the vault names the team in `vault_secret 'questions-team-v1'`, or live trusted devices have a device number in a team that this Mac is not in): the sheet becomes "Join the questions of VAULT", never a second team (`existing_questions_team`; `create_questions_team` and `adopt_questions_team` refuse with `AlreadyEnabled`). The owner pastes a link made on a Mac that has the questions on ("Add an iPhone or a Mac…") and the name of this Mac. "Join…" refuses a link of another team, then the owner check names the relay and the team of the link (`EnableRelayQuestions { team_id: Some(team) }`). After it passes, the link goes to the relay with a new key of this Mac (`PendingJoin`, on a thread of its own); both Macs show the safety words; the other Mac confirms with its own owner check. Then this vault keeps the new key for the questions only (`join_questions_team`) and this Mac writes its own row. Cancel, a lock, or another sync sheet gives the join up.
- **Off needs no check**: it takes authority away. It removes the purpose `questions`; relay sync never changes. A notifications-only membership goes with its key. The trusted device row stays, so an answer on its way still verifies.
- **A removed Mac** (its key is the key of a removed row): the switch says "Off. This Mac was removed from the questions of this vault…", and the waiter asks and lists nothing ("This device was removed from questions"). On drops the removed key and opens the join sheet: a new key and a new confirmation. A Mac whose key is its relay sync key cannot get a new one here: the switch is disabled and says to turn relay sync off and join the vault again.

Only these steps, after the owner check, write the row of a Mac. The questions waiter never registers or re-registers a row: a Mac with a questions membership and no live row asks nothing through the relay.

## Devices, "Add an iPhone or a Mac…", and "Remove…"

While it is on, Settings > Devices lists each live `trusted_device` of the vault: "This Mac", "Mac · answers after Touch ID", "iPhone · answers with Face ID", or "iPhone · its Face ID key has not synced yet" (no `answer_key` yet). It reads `GET /v1/devices` of the questions team every 30 seconds while the section shows and adds "Push on" or "Push off" to a device when the relay says so (an optional `push` field of the device; the relay of R4 does not send it yet, so the state shows only when it does). The relay's device list is never the source of a key.

"Add an iPhone or a Mac…" links a device to the questions team:

- A notifications-only team: the "Add a device to the questions of VAULT" sheet (the "Add a Device…" sheet in its questions mode, `SyncSheet::AddIphone`). It makes a link with the key of the membership (`QuestionsClient::create_link`, `POST /v1/devices/links`) and shows it as a QR code and as text. On the iPhone, Questions scans it and joins with `join_attach` (`PendingJoin`, nothing to download); another Mac pastes it in its join sheet. The sheet asks the relay every 5 seconds for the devices that wait, with the safety words that this Mac computes from its code; "Confirm…" needs the owner check `OwnerRequest::ConfirmQuestionsDevice`, whose proof is `OwnerAction::ConfirmSyncDevice` for exactly that link, name, and key; "Refuse" and closing the sheet refuse. A lock closes the client of the sheet at once.
- A vault that syncs through the relay: "Add a Device…" of relay sync.

**The confirming Mac writes the row of an iPhone.** The iPhone sends its answer key with its link, at the end of the device name (`<name> ~<compressed key>`, `questions::device_link`; the sheet and the prompt show the name without it), so the proof of the confirmation covers the answer key. After the relay confirms, this Mac writes the row (`register_linked_device`: a new UUID, the name, the relay key of the link as `sign_key`, the answer key, the device number); it reaches the iPhone with the sync of the vault, and the iPhone answers once it is there. The iPhone never writes its own row: `answer_key_register` only checks it. "Add a Device…" of relay sync does the same for an iPhone whose link carries an answer key. A Mac's link carries none: a Mac writes its own row after its own owner check. A holder of the vault passphrase can still write rows directly: the same class as holding the vault.

**"Remove…"** is on each device but this Mac. It asks first ("Remove “NAME” from the questions of “VAULT”?") and needs no owner check: it takes authority away. Then `Vault::remove_trusted_device_and_rotate` keeps the row with `deleted_at` (the removal syncs and wins over any edit) and writes a new question key, and, when this Mac is in the team and the row has a device number there, the relay revokes the device on a thread of its own (`QuestionsClient::remove_device`, `DELETE /v1/devices/{id}`): it gets no question and no push from then on. The relay has no call to clear the push token of another device; the token of a revoked device stays unused. The keys of a removed row never register again (`Vault::trusted_key_removed`), so a removed device comes back only with a new relay key, a new answer key, and a new confirmation. For a vault in iCloud Drive the confirmation says that the device keeps its copy of the vault until the vault is removed from it or from iCloud Drive; it can no longer answer. "Remove" in "Devices…" of relay sync also removes the trusted device with that device number in the sync team, with a new question key.

## Keys

- The question key is the vault's (`Vault::question_key`, `ensure_question_key`, `rotate_question_key`). The iPhone core reads it with `Vault::question_key` too. It never goes to the relay and is never logged.
- `Vault::remove_trusted_device_and_rotate` removes a device and writes a new key. A question already posted keeps its key in the memory of the asking Mac until it ends; the next question uses the new key, so a device that only has the old key cannot read it ("Sync this vault to read this question").
- Until shared vaults (V3), every question goes `to: "member"` (the relay refuses `to: "approvers"` with `403 not_routed` by default). A production question about a mirrored team credential (`item_home`) stays on the asking Mac; its card says "Remote answers for team production come with shared vaults; answer on this Mac."

## Order of the answers

The relay can deliver an answer again or out of order. The asking Mac keeps, per question, the answers that took effect (by device, `time`, and kind) and applies an answer of a device only when its signed `time` is later than that device's last answer that took effect ("it is not newer than an answer of this device that counted"). An environment correction applies only when it is newer than the last change of the environment of the credential: after a correction through the relay, newer than the answer that made it; after another change (a newer declaration event), newer than that change on this Mac's clock ("the environment of the credential changed after this answer"). Each refusal is an Activity line. "Development", "Production", then a replayed "Development" leave the credential production.

## An old relay and the relay limits

A relay that predates the questions answers `404` to `POST` or `GET /v1/questions`. The waiter then stops its loops for 5 minutes, keeps each question on this Mac, and shows "The relay does not support questions yet — update the relay." in Settings > Devices and once in Activity; it asks again after the wait. `403 too_many_questions` (20 open per team, 10 per device, 15 per member, 300 an hour) keeps the question on this Mac with a note. `403 too_many_answers` (3 per device, 20 per question, a byte budget per team) shows "The relay refused the answer: too many answers." on the answering device. A question leaves the relay's list 10 minutes after it ended; then the asker gets no answers (or `404`) and a repeated settle `409 question_settled`, both normal ends.

## Answering from another Mac

With the questions on, the questions waiter of each Mac also lists the questions of the other devices of the vault (contract section 13): a third thread, the lister, long-polls `GET /v1/questions?since=N&wait=25` with the client of the session, opens and checks each open card (`questions::open_question`, contract 7.3: the key, the fields, the digest v2, the asker as a live `trusted_device` with the relay number that the relay stamped, the expiry), and keeps the open ones in `QuestionsView::remote`. A settled or expired question, and a card that this Mac cannot read, leave the list. A lock, off, and another vault empty it.

Decisions lists them in **Waiting** after the questions of this Mac, as "AGENT · PROJECT · from MAC" with the time left until they end on the relay, and counts them in the badge. The detail and the bottom bar are those of a local question, with "Asked on MAC.". The answer goes through `QuestionsWorker::answering` and `RemoteAnswering::send` on a thread of its own, signed with the relay key of this Mac (`questions::answer_from_mac`):

- An approving answer (Allow Once, the remembered answers, Development) needs a fresh owner check on this Mac for `OwnerAction::AnswerRemoteQuestion` of exactly that question and answer (`OwnerRequest::AnswerRemoteQuestion`; Touch ID; its reason is the reason of the matching local answer with " on ASKER"). A proof for another question or answer does not count.
- A stricter answer (Deny, Production, Never, Always Ask, Disconnect after its confirmation) needs no check.

The asking Mac checks each answer and decides; the protocol has no receipts yet, so this Mac (and an iPhone) shows "Sent. The Mac checks it; if the run does not continue within a minute, the answer was refused." until the settle takes the question from the list, and the asking Mac writes an Activity line with the device and the reason for each answer that did not count. The relay answers `409 question_settled` ("Already answered"), `409 question_expired` ("Expired"), or `403 not_routed`; each takes the question from the list at once.

## Lock and stop

A lock drops the relay token and ends the long polls at once (`QuestionsWorker::forget`); the open questions expire on the relay, and the questions of the other devices leave Decisions. The worker reads the vault again after the next unlock. Quit stops the three threads.

## Tests

`tests/relay_questions.rs` runs against the in-process fake relay (`tests/common/fake_relay.rs`, contract section 10): the contract test vectors, the window of an answer, off by default, a two-Mac round trip, an iPhone answer with a P-256 answer key, refused answers (signature, kind, digest, team, age) in Activity, the first valid answer, expiry and late answers, key rotation, no plaintext in any request body, a question of Mac B on the list of Mac A with its Allow (only with the owner check of A, not with a proof for another question) and a stricter answer (no check) reaching the queue of B, a notifications-only team that goes with off, and the Gate 3 probes: a removed Mac that cannot register again (the vault refuses its key, its waiter writes nothing, Mac A keeps no live row of it), a removed device revoked on the relay, a replayed and a reordered correction that leave the credential production, an old relay that answers `404`, an iPhone whose link carries its answer key and whose row the Mac writes, and a second Mac that joins the team of the vault instead of making another. `ios/ApassyCore/tests/questions_flow.rs` covers the iPhone side: no row written by the iPhone, `answer_key_register` as a check, a removed iPhone that cannot answer, and a new attach with new keys. The headless app tests cover the window: the switch and its owner check (`src/desktop/ui/settings_tests.rs`), the team sheet, its owner check before the relay call, "Add an iPhone or a Mac…" with the QR code, the safety words, the owner check, the row of the iPhone, and "Remove…" with its revocation, the join of a second Mac, and "Remove" of relay sync that also removes the trusted device (`src/desktop/ui/sync_tests.rs`), and a question of another Mac in Decisions with its owner check and the stricter answers without one (`src/desktop/ui/decisions_tests.rs`). No test calls a real relay.

## Access requests from an agent

An access request is separate from a command approval and from a request to paste a missing credential. Mac Decisions and iPhone Requests show the authenticated agent/item/vault identities, revision, canonical folder/project, exact ASCII hosts and ports, environment and delivery. Agent reason text is labelled separately. Incomplete or old explicitly dispatched notes offer Deny only.

Deny needs no biometric check. iPhone Allow once requires a fresh Face ID signature from this team's registered Secure Enclave current-set key. Touch-ID-only devices can deny or review on the Mac. Cancelling, backgrounding or switching vaults invalidates the pending signing context. Enrollment changes require reconnect and Mac confirmation; the app never silently replaces the registered answer key.

One winning answer is committed by the asking Mac. “Answered on <device>” confirms historical consent, not remaining availability or execution. An allowance expires with the original 300-second request, is memory-only, and is burned by one explicitly referenced matching one-item run before the bouncer. Failure, cancellation, restart, lock or repeated use never refunds it. The bouncer and hard vetoes still apply; no durable grant, remembered answer, production allowance, evaluation permission or Touch ID window is created remotely.

Agents should continue normal `can_use` runs. For scoped asynchronous consent, `apassy_request_access` accepts `scope: {action, hosts}`; query `apassy_access_request_status`, attach `access_request_id` to one matching run, and cancel abandoned requests with `apassy_cancel_access_request`. Status/cancel never create requests. After a lost use response, query status; repeating the run cannot join an admitted operation. Exact destination recognition is conservative; an ambiguous command needs ordinary Mac review.

Publication uses the existing questions transport and generic time-sensitive push class. Budgets are local to each Mac/vault: one active or unconsumed scope per agent, 30-second cooldown, five new requests/hour/agent, twenty/hour/Mac and ten open. Coalescing retains the first reason and deadline. Deny/cancel/failure does not refund budgets. Export failure leaves the Mac card usable with a local-only explanation. Three durable iPhone POST reservations bound retries across refresh, history clearing and restart. Relays need no change.

After Connect pairing, the Mac offers “An older iPhone '<name>' is still paired. Remove it?” for a same-name or same-team iPhone. Keep changes nothing. Remove requires a fresh check and uses the existing trusted-device revocation/key-rotation path. The old phone is never automatically removed.

Review hardening: access publication reserves at most one unsettled relay slot per asking Mac, including uncertain POSTs, leaving nine for eight concurrent broker operations and one Connect handoff. Other access cards stay available locally with the original deadline. Expiry or confirmed settlement frees the slot. Explicit MCP operation cancellation withdraws its scoped card; disconnection or a lost response alone does not. Pending Face ID is invalidated at the signing/request deadline and on task cancellation.
