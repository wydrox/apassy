# ADR 0028 — Retire the Wi-Fi companion; the relay carries every request to the iPhone

Date: 2026-10-19.
Status: Connect onboarding prerequisite implemented in ADR 0032. Wi-Fi retirement remains PROPOSED and is not accepted by the owner yet. When accepted, it supersedes [ADR 0020](0020-iphone-companion.md) §1–§5 in stages (section "Decision").

Connect onboarding prerequisite implemented by [ADR 0032](0032-connect-onboarding.md) on 2026-11-01: Free and Personal vaults can create a questions-only connection without an operator code or paid account, then confirm an iPhone and register push. This does not complete access-request transport or authorize removing the Wi-Fi companion; stages 2 and 3 remain open.

## Context

- [ADR 0020](0020-iphone-companion.md) (2026-09-30) added the iPhone companion: the iPhone polls the Mac every 2 s over HTTPS on the local network (`src/companion/`, contract [companion-v1](../contracts/companion-v1.md)). At that time there was no relay.
- Since then the relay carries questions ([relay-questions-v1](../contracts/relay-questions-v1.md)) and the feed. They reach the iPhone on any network, with push notifications. The Free plan includes approvals through the relay (no account).
- The Requests tab merges both sources. `Decisions.waiting` drops a Wi-Fi run that a relay question already shows, because the question is richer. So with the relay on, the Wi-Fi path adds almost nothing to the list.
- But the UI still shows its state. On 2026-10-19 the owner, on cellular, saw "Rafal's Mac mini is unavailable · Last updated 9:08 · Retry" in Requests (`DecisionsView.swift`, branch `product/ios-requests`). The Mac was healthy and relay questions worked. The card shows for every state that is not `connected`, also `connecting`.

### What only the Wi-Fi companion does today

| Function | Wi-Fi companion | Relay |
| --- | --- | --- |
| Approve or deny a waiting run | yes, same network only | yes, any network, with push |
| Deny an access request (an agent asks for a credential) | yes | **no** — not in relay-questions-v1 |
| Newest 50 Mac activity entries | yes | partly: feed and encrypted Requests history |
| Works when "Send questions through the relay" is off for a vault, or the relay refuses a question (`403 too_many_questions`, `413`, `404`) | yes | no — the question stays local |
| Works without internet | yes | no |

### What it costs

- A network listener in the Mac app (TLS on a random port, 48620 on the owner's Mac today). It is attack surface that the rest of Apassy does not have: everything else is a Unix socket or an outbound connection.
- A second pairing flow (QR code, 6-digit code, owner check), a second device list, and the iOS Local Network permission prompt.
- A second wire protocol and its code: about 8,200 lines of Rust (`src/companion/`, `src/desktop/companion.rs`, `src/desktop/ui/companion.rs`, `src/vault/companion.rs`) and about 2,600 lines of Swift (`ios/ApassyCompanionKit`), plus `SessionModel`, `MacConnection`, pairing views, and the de-duplication in `Decisions`.
- Confusing states in the UI, as above.

## Decision (proposed)

The relay becomes the only path from the Mac to the iPhone. The Wi-Fi companion is removed in three stages.

### Stage 1 — Hide it from Requests (iOS only, no protocol change)

- Remove the "<Mac> is unavailable" card from Requests. The Wi-Fi state shows only in Settings → Devices → "<Mac> on Wi-Fi".
- When a vault does not send questions through the relay, Requests shows one quiet line for it: "Requests from <vault> reach this iPhone only on the same Wi-Fi as the Mac. Turn on relay questions on the Mac."
- Wi-Fi runs and access requests that arrive still show in the list as today.

### Stage 2 — Access requests through the relay

- Add a question kind for an access request to relay-questions-v1 (a new card type; answers `deny` and, if the owner wants it, `allow_once` with Face ID). Same envelope, same signing keys, same settle rules.
- The Mac posts an access request as a question when relay questions are on for the vault.
- After this stage the relay covers every request that the companion covers.

### Stage 3 — Remove the companion

- Release N: the Mac app no longer offers "Pair an iPhone" on Wi-Fi. A Mac with paired companion devices shows once: "The iPhone app now uses the relay. Wi-Fi pairing ends in the next version." The listener still runs for these Macs.
- Release N+1: remove the listener, `companion-v1`, the device store rows (a vault schema migration drops them), `ApassyCompanionKit`, `SessionModel`, `MacConnection`, the pairing views, and the run/question de-duplication.
- The iPhone stops asking for Local Network permission.

## Consequences

- One path, one pairing, one device list. No network listener on the Mac.
- **Lost: approvals without internet**, and approvals for a vault whose owner turned relay questions off. The owner then approves on the Mac. This matches ADR 0025: the relay is the low-friction default, and the Mac card is always the local path.
- **Lost: the "nothing leaves the LAN" property for request metadata.** The relay sees only sealed envelopes (relay-questions-v1 §6), sizes, and times. The owner already accepted this for questions.
- Until stage 2 ships, an owner who stops using Wi-Fi can deny access requests only on the Mac.

## Open decisions

- D1. Accept the retirement at all, or keep the companion as an opt-in "offline mode"? Recommendation: retire. The offline case is rare for a Mac that runs agents, and the listener is the cost.
- D2. Stage 2: may the iPhone also *allow* an access request (Face ID), or only deny it, as today over Wi-Fi?
- D3. Stage 3 timing: N = the next minor release after stage 2, N+1 = the one after.
