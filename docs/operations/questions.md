# Questions through the relay

Stage 5 of [ADR 0025](../adr/0025-low-friction-access.md) (§3d, §3e), contract [relay-questions-v1](../contracts/relay-questions-v1.md). The app side is `src/questions/`, `src/vault/questions.rs`, `src/relay/membership.rs`, the question digest v2 in `src/companion/digest.rs`, and `OwnerCheck::Remote` in `src/broker/approvals/owner_auth.rs`. The window side is Settings > Devices (`src/desktop/ui/settings.rs`, `src/desktop/ui/sync/questions.rs`, and "Add a device…" in `src/desktop/ui/sync/relay.rs`) and Decisions (`src/desktop/ui/decisions.rs`).

## What it does

A run that waits for the owner is a question. It always shows on the asking Mac (the card) and, on the local network, on a paired iPhone (companion-v1, digest v1). With **Settings > Devices > "Send questions through the relay"** on, the asking Mac also:

1. seals the question card with the question key of the vault (ChaCha20-Poly1305, AAD of contract section 6.1) and posts it (`POST /v1/questions`, `to: "member"`, `expires_at` = the end of the 5-minute wait);
2. long-polls the answers (`GET /v1/questions/{qid}/answers?wait=25`) and checks each one in order (contract 12.3): it opens with the key of the question and the device number that the relay stamped, has the fields of its kind, comes from a live `trusted_device` of the vault, is offered by the question, has the digest v2 of the run as it waits now, and verifies: an approval or a correction to development through `OwnerGate::authorize` with `OwnerCheck::Remote` (the iPhone `answer_key`, or the Mac `sign_key`), a stricter answer with the `sign_key` and the 60-second window;
3. applies the first answer that passes through the approval queue (`approve` with a `CheckMethod::Remote` proof, `deny`, or `deny_stricter`), and settles the question on the relay (`POST …/settle`) with who answered;
4. settles a question that ended another way (an answer on this Mac or through the companion, the timeout, the broker stopping) with that outcome, best effort.

An answer that does not count gets an Activity line ("An answer from DEVICE did not count: REASON."), with no command, no credential, and no value. Decisions shows "AGENT: Answered on DEVICE" for 10 minutes after an answer from another device.

The relay sees only the routing: the team, the devices, the times, the sizes, and the bit `to`. It never gets a command, a credential name, a variable, or a value: every card, answer, and settle is sealed.

## Turning it on

The switch is **off by default**. It is on exactly when the open vault has, on this Mac, a relay membership with the purpose `questions` (`relay_membership`, a local table). It is disabled only while the vault is locked.

On opens a new channel that can approve runs, so it needs the **owner check** (Touch ID or the passphrase) for `OwnerAction::EnableRelayQuestions { relay_url, team_id }` before anything changes. The proof names the relay and the team, and the app checks it in the vault session before it acts.

- A vault that syncs through the relay: the check names its sync team. Then the switch adds the purpose `questions` to the sync membership (`relay::membership::enable_questions`). No relay call. It also makes the question key (`vault_secret 'question-key-v1'`, `Vault::ensure_question_key`) when the vault has none, and registers this Mac as a `trusted_device` (kind `mac`, `sign_key` = the public key of the membership, its device number in the team). The key and the row reach the other devices through the sync.
- A vault without relay sync (iCloud Drive, a folder, or none): the switch opens the sheet "Questions of VAULT through the Apassy relay" with the relay address (the Apassy relay by default), the operator team code (masked, as in "Turn on" of relay sync), and the name of this Mac. "Turn On…" checks the fields, then the owner check names the relay and no team (`team_id: None`). After it passes, `POST /v1/teams` runs on a thread of its own with no vault (`relay::membership::new_questions_team`): a new device key and a team that never gets a snapshot. Then the vault keeps the membership with the purpose `questions` only (`adopt_questions_team`), makes the question key, and registers this Mac. The team code stays in memory only from "Turn On…" to that call; a lock, another sync sheet, a failed check, and Cancel erase it. `create_questions_team` does both steps in one call for a caller without a window.
- **Off needs no check**: it takes authority away. It removes the purpose `questions`; relay sync never changes. A notifications-only membership goes with its key. The trusted device row stays, so an answer on its way still verifies.

## Devices and "Add an iPhone…"

While it is on, Settings > Devices lists each live `trusted_device` of the vault: "This Mac", "Mac · answers after Touch ID", "iPhone · answers with Face ID", or "iPhone · its Face ID key has not synced yet" (no `answer_key` yet). It reads `GET /v1/devices` of the questions team every 30 seconds while the tab shows and adds "Push on" or "Push off" to a device when the relay says so (an optional `push` field of the device; the relay of R4 does not send it yet, so the state shows only when it does). The relay's device list is never the source of a key.

"Add an iPhone…" links an iPhone to the questions team:

- A notifications-only team: the "Add an iPhone to the questions of VAULT" sheet (the "Add a device…" sheet in its questions mode, `SyncSheet::AddIphone`). It makes a link with the key of the membership (`QuestionsClient::create_link`, `POST /v1/devices/links`) and shows it as a QR code and as text. On the iPhone, Questions scans it and joins with `join_attach` (`PendingJoin`, nothing to download). The sheet asks the relay every 5 seconds for the iPhones that wait, with the safety words that this Mac computes from its code; "Confirm…" needs the owner check `OwnerRequest::ConfirmQuestionsDevice`, whose proof is `OwnerAction::ConfirmSyncDevice` for exactly that link, name, and key; "Refuse" and closing the sheet refuse. A lock closes the client of the sheet at once.
- A vault that syncs through the relay: "Add a device…" of relay sync, unchanged.

The iPhone then registers its own row with its answer key (`answer_key_register`); the row reaches the Macs through the sync of the vault, and Devices lists it.

## Keys

- The question key is the vault's (`Vault::question_key`, `ensure_question_key`, `rotate_question_key`). The iPhone core reads it with `Vault::question_key` too. It never goes to the relay and is never logged.
- `Vault::remove_trusted_device_and_rotate` removes a device and writes a new key. A question already posted keeps its key in the memory of the asking Mac until it ends; the next question uses the new key, so a device that only has the old key cannot read it ("Sync this vault to read this question").
- Until shared vaults (V3), every question goes `to: "member"`. A production question about a mirrored team credential (`item_home`) stays on the asking Mac.

## Answering from another Mac

With the questions on, the questions waiter of each Mac also lists the questions of the other devices of the vault (contract section 13): a third thread, the lister, long-polls `GET /v1/questions?since=N&wait=25` with the client of the session, opens and checks each open card (`questions::open_question`, contract 7.3: the key, the fields, the digest v2, the asker as a live `trusted_device` with the relay number that the relay stamped, the expiry), and keeps the open ones in `QuestionsView::remote`. A settled or expired question, and a card that this Mac cannot read, leave the list. A lock, off, and another vault empty it.

Decisions lists them in **Waiting** after the questions of this Mac, as "AGENT · PROJECT · from MAC" with the time left until they end on the relay, and counts them in the badge. The detail and the bottom bar are those of a local question, with "Asked on MAC.". The answer goes through `QuestionsWorker::answering` and `RemoteAnswering::send` on a thread of its own, signed with the relay key of this Mac (`questions::answer_from_mac`):

- An approving answer (Allow Once, the remembered answers, Development) needs a fresh owner check on this Mac for `OwnerAction::AnswerRemoteQuestion` of exactly that question and answer (`OwnerRequest::AnswerRemoteQuestion`; Touch ID; its reason is the reason of the matching local answer with " on ASKER"). A proof for another question or answer does not count.
- A stricter answer (Deny, Production, Never, Always Ask, Disconnect after its confirmation) needs no check.

The asking Mac checks each answer and decides; this Mac shows "Sent. Waiting for MAC…" until the settle takes the question from the list. The relay answers `409 question_settled` ("Already answered"), `409 question_expired` ("Expired"), or `403 not_routed`; each takes the question from the list at once.

## Lock and stop

A lock drops the relay token and ends the long polls at once (`QuestionsWorker::forget`); the open questions expire on the relay, and the questions of the other devices leave Decisions. The worker reads the vault again after the next unlock. Quit stops the three threads.

## Tests

`tests/relay_questions.rs` runs against the in-process fake relay (`tests/common/fake_relay.rs`, contract section 10): the contract test vectors, the window of an answer, off by default, a two-Mac round trip, an iPhone answer with a P-256 answer key, refused answers (signature, kind, digest, team, age) in Activity, the first valid answer, expiry and late answers, key rotation, no plaintext in any request body, a question of Mac B on the list of Mac A with its Allow (only with the owner check of A, not with a proof for another question) and a stricter answer (no check) reaching the queue of B, and a notifications-only team that goes with off. The headless app tests cover the window: the switch and its owner check (`src/desktop/ui/settings_tests.rs`), the team sheet, its owner check before the relay call, and "Add an iPhone…" with the QR code, the safety words, and the owner check (`src/desktop/ui/sync_tests.rs`), and a question of another Mac in Decisions with its owner check and the stricter answers without one (`src/desktop/ui/decisions_tests.rs`). No test calls a real relay.
