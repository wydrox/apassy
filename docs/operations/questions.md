# Questions through the relay

Stage 5 of [ADR 0025](../adr/0025-low-friction-access.md) (§3d, §3e), contract [relay-questions-v1](../contracts/relay-questions-v1.md). The app side is `src/questions/`, `src/vault/questions.rs`, `src/relay/membership.rs`, the question digest v2 in `src/companion/digest.rs`, and `OwnerCheck::Remote` in `src/broker/approvals/owner_auth.rs`.

## What it does

A run that waits for the owner is a question. It always shows on the asking Mac (the card) and, on the local network, on a paired iPhone (companion-v1, digest v1). With **Settings > Devices > "Send questions through the relay"** on, the asking Mac also:

1. seals the question card with the question key of the vault (ChaCha20-Poly1305, AAD of contract section 6.1) and posts it (`POST /v1/questions`, `to: "member"`, `expires_at` = the end of the 5-minute wait);
2. long-polls the answers (`GET /v1/questions/{qid}/answers?wait=25`) and checks each one in order (contract 12.3): it opens with the key of the question and the device number that the relay stamped, has the fields of its kind, comes from a live `trusted_device` of the vault, is offered by the question, has the digest v2 of the run as it waits now, and verifies: an approval or a correction to development through `OwnerGate::authorize` with `OwnerCheck::Remote` (the iPhone `answer_key`, or the Mac `sign_key`), a stricter answer with the `sign_key` and the 60-second window;
3. applies the first answer that passes through the approval queue (`approve` with a `CheckMethod::Remote` proof, `deny`, or `deny_stricter`), and settles the question on the relay (`POST …/settle`) with who answered;
4. settles a question that ended another way (an answer on this Mac or through the companion, the timeout, the broker stopping) with that outcome, best effort.

An answer that does not count gets an Activity line ("An answer from DEVICE did not count: REASON."), with no command, no credential, and no value. Decisions shows "AGENT: Answered on DEVICE" for 10 minutes after an answer from another device.

The relay sees only the routing: the team, the devices, the times, the sizes, and the bit `to`. It never gets a command, a credential name, a variable, or a value: every card, answer, and settle is sealed.

## Turning it on

The switch is **off by default**. It is on exactly when the open vault has, on this Mac, a relay membership with the purpose `questions` (`relay_membership`, a local table).

- A vault that syncs through the relay: the switch adds the purpose `questions` to the sync membership (`relay::membership::enable_questions`). No relay call. It also makes the question key (`vault_secret 'question-key-v1'`, `Vault::ensure_question_key`) when the vault has none, and registers this Mac as a `trusted_device` (kind `mac`, `sign_key` = the public key of the membership, its device number in the team). The key and the row reach the other devices through the sync.
- A vault without relay sync: the switch is disabled ("First sync this vault through the Apassy relay in Sync below."). The API for a notifications-only team exists (`relay::membership::create_questions_team`, with an operator team code); the app has no sheet for it yet.
- Off removes the purpose `questions`; relay sync never changes. A notifications-only membership goes with its key.

## Keys

- The question key is the vault's (`Vault::question_key`, `ensure_question_key`, `rotate_question_key`). The iPhone core reads it with `Vault::question_key` too. It never goes to the relay and is never logged.
- `Vault::remove_trusted_device_and_rotate` removes a device and writes a new key. A question already posted keeps its key in the memory of the asking Mac until it ends; the next question uses the new key, so a device that only has the old key cannot read it ("Sync this vault to read this question").
- Until shared vaults (V3), every question goes `to: "member"`. A production question about a mirrored team credential (`item_home`) stays on the asking Mac.

## Answering from another Mac

`questions::open_question` checks a card (contract 7.3); `questions::answer_from_mac` signs with the relay key of the Mac. An approving answer needs a fresh owner check for `OwnerAction::AnswerRemoteQuestion` (Touch ID; its reason is the reason of the matching local answer with " on ASKER"). The relay answers `409 question_settled` ("Already answered") or `409 question_expired` ("Expired") after the end. The Decisions view of a Mac does not list remote questions yet.

## Lock and stop

A lock drops the relay token and ends the long poll at once (`QuestionsWorker::forget`); the open questions expire on the relay. The worker reads the vault again after the next unlock. Quit stops both threads.

## Tests

`tests/relay_questions.rs` runs against the in-process fake relay (`tests/common/fake_relay.rs`, contract section 10): the contract test vectors, the window of an answer, off by default, a two-Mac round trip, an iPhone answer with a P-256 answer key, refused answers (signature, kind, digest, team, age) in Activity, the first valid answer, expiry and late answers, key rotation, and no plaintext in any request body. No test calls a real relay.
