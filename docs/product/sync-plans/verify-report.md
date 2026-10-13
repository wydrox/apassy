# Verify report: Connect devices, sync, and plans

Date: 2026-10-13. Branch `product/sync-plans`, verified at b115c55. The relay part is on `feat/connect` in the relay repository (through 93ddc93) and is not deployed.

## How it was verified

- **Mac:** the screenshot tour on synthetic data (`scripts/screenshots.sh`, a release build from this tree, a fake relay on 127.0.0.1, and fake plans inside the example only). This run produced 43 images; the new screens are in `screenshots/`.
- **iPhone:** the iOS Simulator (iPhone 17) with the launch hooks that are compiled only for the Simulator.
- **Native UI, not a web app.** So the Playwright, axe, and viewport steps of the checklist do not apply. Accessibility was checked by reading the code and the images. VoiceOver was not run.
- **Not verified:**
  - physical devices;
  - a real iCloud account;
  - the live relay with `POST /v1/connect` (not deployed);
  - push notifications;
  - a real checkout, since there is no account service.

## Scorecard

| Lens | Before (audit) | After |
|---|---|---|
| Information | 1/3 | 3/3 |
| Meaning | 1/3 | 2/3 |
| Time | 1/3 | 3/3 |
| Memory | 1/3 | 2/3 |
| Ethics | PASS | PASS |
| Accessibility | — | PASS (by reading; VoiceOver not run) |

- **Meaning** stays at 2: "Apassy relay" still shows in one status line and in the sidebar footer (finding 1).
- **Memory** stays at 2: the planned peak, the test question (A5), is not built (finding 4).

## Emotional curve (Flow A, as built)

| Step | Score | Note |
|---|---|---|
| Settings > Devices, empty | +1 | The hero says the value: "Approve your agents from your iPhone". |
| Add a device: QR at once | +1 | No field, no code, no relay address. |
| iPhone: Connect to your Mac, scan | +1 | One door. |
| Free: open the vault from iCloud first | −1 | Needed for approvals away from Wi-Fi (owner decision 5). The screen says why. "Only on this Wi-Fi" is the honest alternative. |
| Two words | −1 → 0 | One line says why. It names no Mac, and shows "Code from “Mac mini”" in secondary text. |
| Touch ID on the Mac | 0 | Familiar. |
| Done: "iPhone 17 Pro is connected. It approves with Face ID." | +1 | Has "Add another device" and "Done". |

There is no −2 step. The ending follows the recipe: confirmation, what happens next, and how to undo. The planned +2 peak (the test question) is missing (finding 4).

## Spec conformance

| Screen | Result |
|---|---|
| M1 Devices hub | Matches: one list, what each device does, last seen, "⋯" (Remove…, Stop approvals here), "Add a device…", the trust line, the empty hero, "Pair on this network" at L3. |
| M2 Add a device | Matches: one sheet, the QR code, a link without the pairing secret, the words at 22 pt, "Confirm with Touch ID" / "Refuse", "New code", the unreachable fallback, the end with two buttons. |
| M3 Vault > Sync | Matches: iCloud Drive / Apassy / Off, "Other folder…" and "Use another relay…" in the menu, the line under the choice, and an honest iCloud-off note. |
| M4 Upgrade | Matches the copy and the order. "Not now" is the same size as "Continue to checkout". The full price is shown. |
| M5 Plan | Matches: Free, Personal, past due, offline, and ended. |
| Flow E | Matches: approvals and the vault stay. |
| I1 Welcome | Matches. |
| I2 Free | Changed from the spec: the vault opens before the words, because the core keeps the relay key in the vault. The copy follows the security fix: no Mac named by the code. |
| I3 iPhone Devices | Matches, plus "Disconnect from Apassy Connect". |
| Release default | With `NoPlanProvider`, nothing about plans shows (test `the_app_as_it_ships_shows_nothing_about_plans`). |

## Ethics gate on the built UI

All checks PASS:

- the only nudge is a small gray "Personal" tag on one choice;
- there are no banners;
- upgrade entry points exist only where a paid feature is picked, plus Settings > Plan;
- "Not now" has the same weight as the upgrade;
- the full price is shown;
- cancel is in the same place as buying;
- there is no countdown or recommendation in Compare plans;
- a downgrade keeps the vault and the approvals (fixed in a64225d: turning sync off no longer leaves the Connect team).

## Security review

Three adversarial judges ran (2 on Opus, 1 on Fable). All their P1 and P2 findings are fixed:

- the Mac add-device path;
- a link that the owner did not make, with Disconnect on the iPhone;
- the 401 "team gone" handling;
- a proof bound to its purpose;
- the relay's resource bounds, per-prefix limit, live-team cap, sweep, and proof of key.

The relay was judged UNSAFE to deploy before its fixes. It was not judged again after them: a second review is due before any deploy.

## Findings

| # | Screen / state | Issue | Principle | Severity | Owning stage | Fix | Status |
|---|---|---|---|---|---|---|---|
| 1 | Vault list line, sidebar footer | "Apassy relay" instead of "Apassy"; the footer is cut ("Synced just now · A…"). | Mental Model | P2 | 1 (copy) | Use the vocabulary of the spec in `sync.rs` status words and the footer. | open |
| 2 | Owner check of "Switch to Apassy" | The generic note under the dialog lists every kind of owner check. It is long next to the device list. | Cognitive Load | P2 | 3 | A shorter note for this request. | open |
| 3 | Plan ended, tour | Without an iCloud folder, "Move sync to iCloud Drive" is disabled. The note says why and offers "Turn sync off". | Feedback Loop | — | — | Correct as built. | ok |
| 4 | A5 test question | Not built: it needs a card flag in relay-questions-v1 on three sides. | Peak-End Rule | P2 | 4 | Contract v2 plus the Mac, the iPhone, and the relay. | deferred |
| 5 | I2 Free | The vault opens before the words, not after. | Goal Gradient | P2 | 1 | Accepted: the core needs the vault for the relay key. | accepted |
| 6 | Pairing fallback | The `p` window is 300 s; the link lives 600 s. | Feedback Loop | P2 | 4 | Align the two windows. | open |
| 7 | Old iPhone app on a new Free code | It fails ("needs a newer version"). | Expectations Bias | P2 | — | Recorded in ADR 0027 Rollout. Ship both apps together. | accepted |

## Gates (on b79d66a / b115c55)

- **Rust:**
  - `cargo fmt --check` and `cargo clippy --all-features --all-targets -D warnings`: clean.
  - `--lib`: 1053 passed.
  - `relay_sync` 44, `relay_questions` 23, `trusted_devices` 3, `contracts` 17, `folder_sync` 19, `agent_run` 23: all passed.
- **iOS** (from the fix stream):
  - `swift test`: ApassyCompanionKit 177, ApassyVaultKit 45 + 32, ModelTests 299, all passed.
  - Simulator build: succeeded.
  - ApassyCore tests: passed.
- **Relay** (`feat/connect`): 608 Rust tests and 105 Worker tests, all passed.

## Before a release of this work

1. Run a second adversarial review of the relay after its fixes.
2. Deploy relay schema 5 (questions, push) and then Connect, with the owner's go. Follow OPERATIONS §19 and §20, Worker first.
3. Decide on the policy of trimming the audit rows of Connect teams.
4. Build the account service, set prices, and set up Stripe. These block the Plan UI (it stays hidden until then).
5. Ship the Mac app and the iPhone app together.
6. Test on physical devices: iCloud, Connect off Wi-Fi, push.
