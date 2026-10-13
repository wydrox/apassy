# ADR 0027 — Plans and Apassy Connect

Date: 2026-10-13.
Status: Accepted by the owner on 2026-10-13 (Gate A of [docs/product/sync-plans](../product/sync-plans/README.md)). Not built yet: the phases are in "Rollout". The wire contract is [relay-connect-v1](../contracts/relay-connect-v1.md). The flow is in the [flow spec](../product/sync-plans/flow-spec.md); the contracts and streams are in the [build plan](../product/sync-plans/build-plan.md).

## Context

On 2026-10-13 the owner asked that the flow in the app follows the plans: Free syncs through iCloud, the paid plans sync through the Apassy relay, and every plan approves on any device. An audit of the flow found:

- Apassy has five ways to connect a device, and they share no words.
- Two of them ask for a team code (`apassy_tcd_…`) that only the operator of a relay can make. A free user cannot turn on approvals on the iPhone away from the Wi-Fi, which is the value of every plan.
- There is no plan, account, or upgrade anywhere in the app. The site says "Apassy is free" and "No account".
- A vault that syncs through iCloud and later moves to the relay would have two relay teams: one for the questions and one for the sync. The code allows that (`set_membership_purposes` forbids two sync teams, not sync plus questions).

The owner decided the following on 2026-10-13:

1. No account on Free. The first "Add a device…" makes the connection. An account is made only at purchase.
2. The owner buys on the Mac, in the browser. The iPhone shows the plan and sells nothing.
3. Both paid plans have shared vaults.
4. Other folders (Dropbox, a network share) stay free, under "Other folder…". iCloud Drive is the free option in front.
5. On Free, the iPhone approves away from the Wi-Fi only with the vault open from iCloud.

## Decision

### 1. Plans

| Plan | What it has |
| --- | --- |
| **Free** | Sync through iCloud Drive. Other folders under "Other folder…". Approvals on every device through the relay ("Apassy Connect"). No account. |
| **Personal** (paid) | Sync through the Apassy relay. Shared vaults with a few people. |
| **Team** (paid) | Shared vaults, roles, member management, and billing per seat. |

The owner set the prices on 2026-10-13: Personal €1 a month for one person, and Team €2 a month for each member. They exist as Stripe products in the "Apassy" sandbox; a live Stripe account is not activated yet, and EU VAT (Stripe Tax) is not set up.

The code also has `Plan::Operator`. It is a sync membership whose relay team has `kind` `operator`: a vault on a relay that its owner runs, or a vault made before this record. It keeps working as before.

Approvals are never a paid feature. A downgrade never removes them, and never removes the vault.

### 2. Purchase

The owner buys on the Mac. "Continue to checkout" opens a web checkout in the browser, which comes back to the app. The account is made there. The Mac is sold outside the Mac App Store (Developer ID), so this is allowed.

The iPhone shows the plan (name and renewal date) and nothing else: no price, no link to a purchase. The Mac writes the plan to the vault (`vault_secret` `plan-v1`: plan name and `renews_at`; no token, no email).

### 3. Free, away from the Wi-Fi

Questions through the relay are sealed with the question key ([relay-questions-v1](../contracts/relay-questions-v1.md) §5.1). Only devices that hold the vault have it. So on Free, connecting the iPhone includes the iCloud file and the passphrase. Without the vault, the iPhone approves only on the same Wi-Fi, through local pairing.

The relay does not wrap the question key for the iPhone. That would be a new key path for a device that holds no vault, and it is not part of this record.

### 4. The codeless Connect team (contract a)

- A new edge endpoint, `POST /v1/connect`, makes a team with no operator code. `POST /v1/teams` with `apassy_tcd_…` stays for operators.
- Only the Mac calls it. The Mac decides the plan. The iPhone never creates a team. So App Attest is not needed in v1.
- The team is an ordinary ADR 0019 team: one file, one member `owner`, device keys, confirmed joins. It only lacks the operator code of ADR 0019 section 10. The relay marks it `kind` `connect`.
- Abuse limits take the place of the code: one Connect team per public key ever, a per-IP limit at the Worker and at the relay, a relay-wide cap per day, and a small `connect` preset of limits. The preset allows 0 bytes of sync, so a Connect team cannot store a vault.
- A Connect team with one device and no use for 30 days is suspended and then deleted.

The details are in [relay-connect-v1](../contracts/relay-connect-v1.md).

### 5. One vault, one device list (contract b)

The Connect team is the only team of a vault. Upgrading to Personal adds the purpose `sync` to the existing membership. It never makes a second team. The Mac gets a new `RelaySync::enable_on_membership(team_id)` that reuses the existing key. The relay lifts the limits of the team with `POST /v1/teams/entitlement`. Other devices keep their rows and gain `sync` when they see a version above 0. The iPhone core switches to the relay on the same membership.

A downgrade drops `sync` on each device. The relay deletes the snapshot after 30 days.

Vaults made before this record keep their two teams (one for sync, one for questions). The hub lists devices by `trusted_device.uuid`, so the list is already one. An iPhone paired on the Wi-Fi (`companion_device`) is a separate identity and shows in the same list.

### 6. The entitlement seam (contract c)

- The Mac has a module `plan` with the types `Plan` (`Free`, `Personal`, `Team`, `Operator`) and `Entitlement` (`plan`, `email`, `renews_at`, `status`, `checked_at`), and a trait `PlanProvider`. A fake provider, set by `APASSY_PLAN`, serves the screenshots and the tests.
- The real provider uses a token, `apassy_ent_…`: ES256, claims `sub`, `email`, `plan`, `iat`, `exp` (30 days). An accounts service issues it after the checkout (Stripe Checkout and webhooks). The Mac caches it in the data folder, outside the vault. It stays valid 14 days past `checked_at`, then the plan shows as ended.
- The relay checks the token with the public key of the accounts service on `POST /v1/teams/entitlement`, and checks `exp` again on each push.
- **The token never adds a device, never signs in, and never opens a vault.** It holds no device claim. Sign-in stays a device-key challenge only. A stolen token yields at most a raised limit on a team that the thief cannot enter.
- The sign-in answer gets `team_kind`, so a Mac can tell `Operator` from the rest.

### 7. The link payload (contract d)

The QR code and the pasted text are the same string. The old body stays. The fragment is extended:

`https://<relay>/link#apassy_lnk_<team>_<64hex>&r=sync|connect&n=<Mac name>&e=<expires>&p=<b64u of apassy://pair…>`

A parser takes the code before the first `&`. A missing `r` means `sync`. `r=sync` runs the paid join (`join_finish`, which downloads the copy). `r=connect` runs the Free join (`join_attach`), then the iCloud card. `p` lets the same QR fall back to "Pair on this network" when the relay cannot be reached. The Mac sets `r` from the plan. A second Mac that pastes `r=connect` joins the questions team. The format, the parse rules, and the test vectors are in [relay-connect-v1](../contracts/relay-connect-v1.md).

### 8. Invariants

- A device that can approve is added only after safety words on both sides and an owner check on a device the owner already has (`OwnerAction::ConfirmSyncDevice`, ADR 0022 decision 6, ADR 0025 §3e). The answer key of the iPhone rides in the confirmed `device_name`.
- The relay sees routing only: sealed cards and answers, and ciphertext snapshots. The `to` bit and the sizes are the accepted leak ([relay-questions-v1](../contracts/relay-questions-v1.md) §18).
- An account sign-in or an entitlement token never adds a device, never signs in, and never opens a vault. Sign-in stays a device-key challenge only.
- A stolen entitlement token yields at most a raised limit on a team that the thief cannot enter.
- A downgrade never removes approvals or the vault.

### 9. Rollout

Each phase ships on its own.

| Phase | Needs | Delivers |
| --- | --- | --- |
| **P1 Unify** | nothing | One devices hub, one "Add a device…" sheet, one door on the iPhone, the hints fixed, a third first step ("Approve on your iPhone"). A Free vault with no team gets "Pair on this network" as the only path. Operator vaults work as before. |
| **P2 Connect for all** | contract (a) in the relay, with schema 5 deployed (push, APNs) | Approvals work away from the Wi-Fi on Free. A second Mac on Free joins the questions team with a link. |
| **P3 Plan and checkout** | contracts (b) and (c); accounts and Stripe | The Plan section of Settings, the upgrade sheet, the web checkout. Sync through Apassy is gated. `Plan::Operator` is grandfathered. |
| **P4 Shared vaults** | the shared vaults of ADR 0026 §6 | Shared vaults in Personal and Team. |

Without push (the APNs setup of schema 5), the iPhone sees questions only while the app is in the foreground.

An iPhone app from before P2 reads a link with `r=connect` as an old link and runs the paid join (`join_finish`). A Connect team has no copy of the vault, so that join fails ("the relay has no copy"). The owner updates the iPhone app; the Mac cannot make an old link for a Free vault. A Mac from before P2 that pastes such a link is refused the same way. A Mac of this version refuses a link with `r=connect` in "Use a vault from another Mac" and says where to paste it (Settings > Devices > Approve here…).

## What this does not protect

- A link shows the team id and a one-use code. It gives nothing without the safety words on both screens and the owner check on a device that already belongs to the vault (ADR 0022 decision 6). The strength of that check is the strength of the words and of the owner check; this record adds nothing to it.
- A relay in the middle can count the Connect teams, the devices, and the sizes and times of the questions. It cannot read a question, an answer, or a vault. It can refuse service.
- The limits are abuse limits, not a proof of who creates a team. The Worker limits fail open when their binding fails, so the relay keeps its own caps. A determined person with many keys and many IPs can still make Connect teams until the daily cap is reached.
- An account holds an email and a plan, nothing else. It is not a key to a vault. If the accounts service is lost, the paid plans cannot be bought or renewed; vaults and approvals keep working.
- A Free iPhone that did not open the vault from iCloud cannot read a question away from the Wi-Fi. This is by design (§3).
- **A link you did not make.** Anyone can make a Connect team and its link, with any Mac name in `n`. A person who gets the owner to scan such a link on an iPhone that has the vault open can join that iPhone to the person's team, and confirm it on the person's own Mac with the two words that both screens show. The iPhone then sends nothing of the vault: the questions of the owner's Macs never reach that team, and a question of the stranger's Mac cannot be read without the question key of a vault that the stranger has. What it gets is an iPhone that listens to the wrong team. Three things limit it. The iPhone refuses a link whose team is not the questions team that the vault names (`questions-team-v1`, written by the owner's Mac), before any relay call. The iPhone never says that a link comes from "your Mac": the name in a link shows only as "Code from “n”", and the words screen says "The Mac that made this code shows the same two words". And Settings > Devices > "Disconnect from Apassy Connect" on the iPhone takes it out of any team, with no Face ID; the owner then connects it again from their own Mac. A vault that names no team yet (its first Connect) takes any link, as before.

## Relation to other records

- ADR 0019: replaces open decision 1 (open sign-up instead of operator team codes, and billing). A Connect team is an ordinary ADR 0019 team without the operator code.
- ADR 0022: replaces the operator team code as the way to make a personal team (open question 1). Operators keep the code for self-hosted relays (`POST /v1/teams`, `apassy_tcd_…`).
- ADR 0023: replaces D5 (sign-up without an operator team code).
- ADR 0025 §3e: questions through the relay work in a Connect team as they do in any team.
- ADR 0026: changes §3 nothing; it adds the Plan section to Settings. Shared vaults (§6) are the P4 phase.
- [relay-sync-v1](../contracts/relay-sync-v1.md) §6: a Connect team rejects snapshots with `plan_required`.
- [relay-questions-v1](../contracts/relay-questions-v1.md) §12.6: questions work in a Connect team; the rules of the question key do not change.
