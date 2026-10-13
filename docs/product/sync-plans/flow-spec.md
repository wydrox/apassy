# Flow Spec: Connect devices, sync, and plans

Status: approved at Gate A on 2026-10-13. The owner's decisions:

1. **No account on Free.** The first "Add a device…" makes the connection. An account is made only at purchase.
2. **Buy on the Mac, in the browser.** A web checkout opens from the Mac and comes back to the app. The iPhone shows the plan, with no purchase.
3. **Shared vaults in both paid plans.** Personal can share a vault with a few people. Team adds roles, member management, and billing per seat.
4. **Other folders stay free.** Dropbox or a network share sits under "Other folder…" (L3). iCloud Drive is the free option in front.
5. **On Free, the iPhone approves away from Wi-Fi only with the vault open from iCloud** (2026-10-13). Questions through the relay are sealed with the question key, which only devices that hold the vault have. So on Free, connecting the iPhone includes the iCloud file and the passphrase. Without the vault, the iPhone approves only on the same Wi-Fi (local pairing).

 Mode: Improve (audit, then design). Sources: the inventories of the Mac and iPhone flows, the relay, and ADRs 0014, 0019, 0020, 0022, 0023, 0025 §3e, 0026 §6, and a study of T3 Connect (T3 Code).

The owner's target: Free syncs through iCloud. Paid (Personal) and Team (paid) sync through the Apassy relay. Only paid plans have shared vaults, through the relay. Every plan has approvals on any device, through the relay. The model is T3 Connect, which links your machines and your phone through one managed service.

## A. Audit of the current flow

### Verdict

Today Apassy has five ways to connect a device, and they share no words:

- iCloud file on the iPhone;
- "Join a team" through the relay;
- pairing on the local network with a 6-digit code;
- "Questions through the relay" with a link;
- "Use a vault from another Mac".

Two of them ask for a team code from the operator of the relay (`apassy_tcd_…`), which only the owner of the relay can make. So a free user cannot turn on approvals on the iPhone away from the Wi-Fi, which is the planned value of every plan.

The emotional curve has no peak. The worst moment is the team code field, a dead end for anyone but the operator. The flow ends on a list of rows, not on a device that works.

### Scorecard (current)

Information 1/3 · Meaning 1/3 · Time 1/3 · Memory 1/3 · Ethics PASS (no persuasion at all; no plans yet)

### Findings

| # | Screen / step | Issue (observed) | Principle(s) | Severity | Recommendation | Metric |
|---|---|---|---|---|---|---|
| 1 | Mac: Settings > Devices > Relay switch, "Questions of VAULT through the Apassy relay" sheet | A free user must type an operator team code to get approvals on the iPhone. Nobody but the operator has one. | **Curse of Knowledge**, **Expectations Bias** | P0 | The first "Add a device…" makes the connection on its own. No code, no relay address. | % of free vaults with a second device |
| 2 | iPhone: Welcome | Three equal doors ("iCloud · Personal · Free", "Join a team · Apassy relay", "Only approve agent runs"). The user must know the plan and the network before the first step. | **Hick's Law**, **Mental Model** | P1 | One door: "Connect to your Mac". The Mac decides what the iPhone gets from the plan. | Welcome → connected rate |
| 3 | Mac + iPhone: three device paths | Pairing (QR + 6-digit code), relay questions (QR + words), and relay sync (QR + words) are separate, with hints that name screens that do not exist ("Settings > Devices > Notifications through the relay > Add an iPhone", "Settings > iPhone companion"). | **Recognition over Recall**, **Familiarity Bias** | P1 | One "Add a device…" with one QR. The local pairing stays only as an offline fallback (L3). | Support contacts about pairing |
| 4 | Mac: three sheets | "Relay address" and "Team code" fields show in the relay sync sheet, the questions sheet, and "Use a vault from another Mac". | **Cognitive Load**, **Tesler's Law** | P1 | Hide both. They stay under "Use another relay…" (L3) for self-hosted relays. | — |
| 5 | Mac: "Add a device…", "Add a Mac…", "Add an iPhone or a Mac…" | Three buttons, three titles, one sheet. "Devices…" opens "Macs that sync". | **Similarity**, **Method of Loci** | P1 | One button, "Add a device…", in Settings > Devices, and one device list. | — |
| 6 | Approvals on other devices | Off by default, behind a switch with jargon ("Send questions through the relay"). The main promise of every plan sits at L2 and is off. | **Default Bias**, **Discoverability** | P1 | A connected device approves by default. A device row can turn it off. | % of questions answered away from the Mac |
| 7 | Plans | There is no plan, account, or upgrade anywhere. The site says "Apassy is free" and "No account". | **Expectations Bias**, **Streisand Effect** | P1 | A "Plan" section; contextual upgrade at the two places where a paid feature is picked; one honest price; a pricing page. | Contextual upgrade conversion |
| 8 | iPhone | The iPhone cannot start a relay vault and calls a personal relay vault a "team". | **Mental Model** | P1 | "Team" only for people. Your own devices are "your devices". | — |
| 9 | First steps (Mac) | Only "Paste your first credential" and "Connect an agent". Approving on the phone, the "wow" of Apassy, is never offered. | **Aha! moment**, **Zeigarnik** | P2 | An optional third step after the agent: "Approve on your iPhone". | First-week connected device rate |
| 10 | Naming | "Mac" vs "device", "relay" vs "team", "questions" vs "notifications". | **Mental Model** | P2 | Vocabulary below. | — |

## 0. Context

- **User and job-to-be-done:** a developer who runs agents. In their words: "I want my agents to work while I'm away, and approve them from my phone. I want my secrets on my Mac and my iPhone, and later share some with my team."
- **Entry points:**
  - the Mac's Settings (gear, ⌘,);
  - a question that waits while the owner is away from the Mac ("I wish I could answer this on my phone");
  - the iPhone app from the App Store ("Approve your agents from anywhere");
  - the Shared section of the sidebar ("No shared vaults").
- **Emotional state at entry:** usually calm, during setup. It is anxious when a run waits: an agent is blocked and the owner is away. Design implication: adding a device must take under a minute, with no field to type, and must work from the first try.
- **User success:** every device of mine can approve; my vault is on the devices where I want it; I know what I pay for.
- **Business success:**
  - free users connect a second device (activation);
  - paid conversion at the two contextual points (relay sync, shared vault);
  - low support load (no team codes).
- **Conflicts between the two:**
  - The business wants upgrades. The user wants no nagging. Resolution: an upgrade shows only where the owner picks a paid feature, never as a banner.
  - The business may want an account for everyone, like T3. The user of a password vault wants no account. Resolution at Gate A: no account on Free.
- **Constraints and assumptions:**
  - Adding a device that can approve must stay confirmed by a device the owner already has: safety words plus Touch ID (ADR 0022 decision 6, ADR 0025 §3e). Unlike T3 Connect, an account sign-in alone never adds a device. A stolen account must not approve production.
  - The relay sees routing only; vault copies and questions stay end-to-end encrypted.
  - The Mac app is sold outside the Mac App Store (Developer ID), so a web checkout is possible. The iPhone app is in the App Store and sells nothing (Gate A): it shows the plan only.
  - iOS asks the user to pick the iCloud file (the sandbox), so a free iPhone vault needs one file pick.
  - Backend work this flow needs is listed in section 9.
  - Prices are not decided: the spec writes `PRICE`.

## 1. Experience targets

- **Aha! moment (planned peak):** right after a device connects, the Mac sends a test question, "Try it: approve this test on your iPhone". The phone buzzes, Face ID, and the Mac says "Your iPhone answered in 3 seconds." The test has no authority.
- **End state:** the Devices list shows the new device with what it does ("Approves with Face ID · Syncs through iCloud Drive"). The owner holds a phone that answers their agents anywhere.
- **The one sentence the user says afterwards:** "I scanned one code, tapped Face ID, and now my agents ask my phone."
- **Likely negative peaks to neutralize:**
  - The safety words feel like a test. Say why, in one line.
  - The iCloud file is not downloaded on the iPhone. Show the progress, and offer to wait.
  - A paid feature appears as a wall. Use one honest sheet with "Not now".
  - The owner cancels the plan and fears losing the vault. Say "Your vault stays on your devices", and move sync to iCloud in one click.
  - The relay is not reachable. Say "Can't reach Apassy Connect", with the local-network fallback.
- **Target length:**
  - Connect a device: 4 steps, under 1 minute.
  - Upgrade: 3 steps in the app, plus the checkout.
  - Switch sync to Apassy: 1 confirmation.

## 2. Information architecture

**Top tasks, ranked:**
1. Approve on another device (all plans).
2. Have my vault on my other devices (sync).
3. See and remove my devices.
4. Know and change my plan.
5. Share a vault with people (paid).

**Structure: Settings sections on the Mac.** These are the six sections of today plus one:

| Section | Holds |
|---|---|
| Vault | the vault; **Sync** with plan-aware choices; Backup; Import |
| **Devices** | **the hub:** every device of this vault, what each does, "Add a device…" |
| Security | Touch ID, passphrase |
| Bouncer | the model, calibration |
| Tools | command line, browser extension |
| **Plan** (new) | Free / Personal / Team, what it includes, Upgrade or Manage |
| Updates | updates, version |

Plan sits near the end (**Serial Position**: the top tasks first). It is never a badge in the sidebar.

**Disclosure layers:**
- **L1 (always visible):**
  - the device list;
  - "Add a device…";
  - the sync choice of the vault ("iCloud Drive" / "Apassy" / "Off");
  - the plan name.
- **L2 (one click away):**
  - a device row: approves (on/off), "Remove…";
  - the sync status and "Sync now";
  - "Manage subscription".
- **L3 (advanced):**
  - "Other folder…" (Dropbox, a share; free, Gate A);
  - "Pair on this network" (offline fallback, the 6-digit code);
  - "Use another relay…" (relay address and team code, for self-hosted relays);
  - "Use the relay copy…" and other repair sheets.

**Vocabulary:**

| User term | Avoided internal term |
|---|---|
| Your devices / Add a device | questions team, membership, trusted device |
| Apassy Connect (links your devices; every plan) | relay, `/v1/questions`, notifications-only team |
| Sync through Apassy (Personal, Team) | relay sync, relay copy, team snapshot |
| iCloud Drive (Free) | folder sync |
| Approves with Face ID / Touch ID | answer key, Secure Enclave |
| Team (people) and shared vault | team (for your own devices) |
| Plan: Free, Personal, Team | entitlement, operator team code |

**Entry points and discoverability:**
- Settings > Devices;
- First steps (optional third step "Approve on your iPhone");
- the waiting-question banner while the Mac has no other device: a quiet "Get these on your iPhone" link;
- the Shared section of the sidebar;
- the Sync choice.

## 3. Flow map

### Flow A: Connect a device (every plan)

```
[Settings > Devices | First steps | waiting-question link]
  → [A1 Mac: "Add a device" sheet: QR + link]
  → [A2 iPhone: "Connect to your Mac" → scan] (or a Mac: "Use a vault from another Mac" → paste)
  → [A3 Both: two words · Mac: "Confirm with Touch ID"]
  → [A4 Device: what you get on your plan]
        Free:     approvals on → "Open your vault from iCloud Drive too?" → pick file → passphrase
        Personal/Team: the vault arrives through Apassy → passphrase → Face ID unlock
  → [A5 Peak: test question → Face ID → "Answered in 3 s"]
  → [Done | Add another device]
     ↘ errors: link expired → "New link"; words differ → "Refuse"; offline → "Pair on this network"
```

| # | Step | User goal | Ask from user | Value given | Principles | Exit/back/skip |
|---|---|---|---|---|---|---|
| A1 | Add a device (Mac) | "Get my phone in" | nothing; one button | a QR code at once, no fields | **Spark Effect**, **Tesler's Law** | Close |
| A2 | Scan (device) | connect | point the camera | instant link | **Fitts's Law** | "Paste the link instead" |
| A3 | Words + Touch ID | be sure it's my device | compare 2 words, Touch ID | proof that nobody else joins | **Feedforward**, **Authority Bias** (honest) | "Refuse" |
| A4 | Plan-shaped result | have what I need | Free: pick the iCloud file, passphrase; paid: passphrase | approvals on; vault on this device | **Default Bias**, **Progressive Disclosure** | "Not now" for the vault |
| A5 | Test approval | see it work | Face ID once | the peak | **Aha! moment**, **Peak-End Rule** | "Skip" |

### Flow B: Choose how a vault syncs

```
[Settings > Vault > Sync] → choice: iCloud Drive (Free) | Apassy (Personal) | Off  [L3: Other folder…]
   Free + "Apassy" → Flow C (upgrade sheet)
   Personal + "Apassy" → one confirmation "Switch “Personal” to Apassy?" → done (connected devices get the vault, no new pairing)
   Paid → "iCloud Drive" → one confirmation → done
```

### Flow C: Upgrade (only where a paid feature is picked, plus Settings > Plan)

```
[Sync: "Apassy" on Free | Shared: "Share a vault…" on Free | Settings > Plan]
  → [C1 sheet: what you get, PRICE, "Continue to checkout", "Not now"]
  → [C2 browser checkout (account made here) → back to the app (apassy:// link)]
  → [C3 "Personal is on" → "Switch “Personal” to Apassy now?" (primary) | "Later"]
  → [Done: Sync shows "Apassy · instant on all devices"; receipt email]
     ↘ payment not confirmed yet → "Waiting for the payment…" + "Check again"; checkout closed → nothing changed, no state left
```

### Flow D: Share a vault (paid)

Shared vaults are not built (ADR 0026 §6). This spec covers only the entry:

- On Free, the Shared empty state says "Share a vault with people. Part of Personal and Team." with "See plans".
- On a paid plan, it opens "New shared vault…" (future).

### Flow E: Downgrade or cancel

- **Cancel:** Settings > Plan > "Manage subscription" opens the same web portal as the checkout (**Symmetry**).
- **At the end of the period**, one sheet: "Personal ended. Your vault stays on all your devices. Sync moves to iCloud Drive." It offers "Move sync to iCloud Drive" (primary) and "Turn sync off".
- **What stays and what goes:**
  - Approvals on all devices stay (they are free).
  - The relay copy is deleted after 30 days, as stated in the sheet.

## 4. Screen specs

### Screen M1: Settings > Devices (Mac), the hub

- **Purpose:** see every device of this vault and add one.
- **Primary action:** "Add a device…", top right of the list.
- **Hierarchy:**
  1. Header: "Devices". Status line: "3 devices · approvals on all".
  2. The list. One row per device:
     - name and kind icon;
     - what it does: "Approves with Face ID · Syncs through iCloud Drive", or "This Mac";
     - last seen.
  3. Primary CTA: "Add a device…".
  4. Secondary, in the row "⋯": "Stop approvals here", "Remove…".
  5. Note: "Each question goes to every device. The first answer counts. Apassy Connect sees no command and no credential."
- **Defaults:** a new device approves.
- **Trust element at the anxiety point:** next to "Add a device…": "A new device needs your Touch ID here."
- **States:**
  - Empty (only this Mac): "Approve your agents from your iPhone. Add a device to get each question there too." with "Add a device…".
  - Loading: skeleton rows.
  - Error: "Can't reach Apassy Connect. Devices show when it is back. On this Wi-Fi? Pair on this network." (L3 link).
  - Success: a toast on add: "iPhone 17 is connected."
- **Principles applied:**
  - **Recognition over Recall**: one list instead of three sections.
  - **Default Bias**: approvals are on.
  - **Tesler's Law**: the relay is invisible.
- **Accessibility notes:** each row reads as "iPhone 17, approves with Face ID, syncs through iCloud Drive, last seen 2 minutes ago"; targets of at least 28 pt on the Mac.

### Screen M2: "Add a device" sheet (Mac)

- **Purpose:** show one code that any device can use.
- **Primary action:** none until a device asks. Then "Confirm with Touch ID".
- **Hierarchy:**
  1. Headline: "Add a device".
  2. QR code. Under it: "On your iPhone, open Apassy and select Connect to your Mac. On another Mac, paste the link." Then the link with "Copy link".
  3. Note: "Works once, for 10 minutes. Nothing is shared until you confirm here."
  4. When a device asks: "iPhone 17 wants to connect. Both show:" **word word**. "Confirm only if your device shows the same words." Then "Confirm with Touch ID" (primary) and "Refuse".
- **Defaults:** the device name comes from the device.
- **Trust element:** the words line, with its reason, at the confirm button.
- **States:**
  - Waiting: "Waiting for your device…" with a subtle pulse.
  - Expired: "This code expired." with "New code".
  - Relay unreachable: "Can't reach Apassy Connect." with "Try again" and "Pair on this network instead".
  - Success: "Connected. Sending a test question to iPhone 17…" (A5).
- **Principles applied:**
  - **Feedforward**: what happens before it happens.
  - **Von Restorff Effect**: the words stand out.
  - **Labor Illusion**: none needed, it is under 2 s.
- **Accessibility notes:** the QR code has its link as text; the words are read as words, not as an image.

### Screen M3: Vault > Sync (Mac), plan-aware

- **Purpose:** choose where this vault syncs.
- **Primary action:** the segmented choice.
- **Hierarchy:**
  1. Label "Sync".
  2. Choice: "iCloud Drive", "Apassy", "Off". "Apassy" carries a small "Personal" tag on Free. "Other folder…" is in the menu.
  3. The line under it, by choice:
     - iCloud: "Free. Your other devices get changes in about a minute while Apassy is open."
     - Apassy: "Changes reach your devices in seconds, also without iCloud. Encrypted on your Mac: Apassy can't read it."
     - Off: "This vault stays on this Mac."
  4. Status: "Synced 2 minutes ago", with "Sync now".
- **Defaults:**
  - A new vault: iCloud Drive when iCloud is on, else Off.
  - Paid: Apassy.
- **Trust element:** the encryption line, at the paid option.
- **States:**
  - iCloud off on this Mac: "iCloud Drive is off on this Mac. Turn it on in System Settings, or sync through Apassy." This is honest: the free fix comes first.
  - Error states: as today, with the new words.
- **Principles applied:**
  - **Framing**: by speed and need, not by "premium".
  - **Feedforward**.
  - **Anchoring**, honest: the free option comes first.

### Screen M4: Upgrade sheet (Mac), shown only from a paid pick

- **Purpose:** decide about Personal or Team with full facts.
- **Primary action:** "Continue to checkout".
- **Hierarchy:**
  1. Headline:
     - from Sync: "Sync through Apassy";
     - from Shared: "Share vaults with people".
  2. Three lines of what you get. For Sync:
     - "Changes on every device in seconds";
     - "Works without iCloud";
     - "End-to-end encrypted. Apassy can't read your vault."
  3. Price: "PRICE a month, or PRICE a year". The plan name: "Personal".
  4. Primary: "Continue to checkout". It opens the browser.
  5. Secondary, with the same weight as text: "Not now". A link: "Compare plans".
  6. Reassurance: "Cancel any time in Settings > Plan. Your vault stays on your devices."
- **Defaults:** monthly. No pre-selected add-ons.
- **States:**
  - Waiting after the browser: "Finish in your browser. Apassy turns Personal on when the payment is done." with "Check again" and "Cancel".
  - Not confirmed after 2 minutes: "We didn't get the payment yet. If you paid, select Check again. If not, nothing changed."
  - Success: C3.
- **Principles applied:**
  - **Feedforward**: the CTA says where it goes.
  - **Loss Aversion**, honest: "your vault stays".
  - Ethics gate below.

### Screen M5: Settings > Plan (Mac)

- **Free:**
  - "Free";
  - "iCloud Drive sync · Approvals on all your devices";
  - "Compare plans" (opens the sheet with three columns: Free, Personal, Team; Personal is highlighted only as a mark of what most single users pick, if that is true).
- **Paid:**
  - "Personal · renews DATE";
  - "Manage subscription" (web portal, same place as checkout);
  - the account email;
  - "Sign out of this Mac" (asks first; sync through Apassy stops on this Mac).
- **States:**
  - offline: "Plan checked DATE. Works offline for 14 days."
  - payment failed: one line with "Update payment".

### Screen I1: iPhone Welcome

- **Purpose:** connect the iPhone to the owner's Mac.
- **Primary action:** "Connect to your Mac".
- **Hierarchy:**
  1. Headline: "Approve your agents from anywhere".
  2. Supporting: "On your Mac, open Apassy > Settings > Devices > Add a device. Then scan the code."
  3. Primary CTA: "Connect to your Mac" (opens the camera).
  4. Secondary: "Paste a link instead".
  5. Footnote link: "No Mac yet? Learn about Apassy".
- **States:**
  - Camera denied: "Apassy needs the camera to scan the code. Or paste the link." with "Open Settings".

### Screen I2: iPhone after connecting (plan-shaped)

- **Free:**
  - "Connected to MacBook Pro. One more step: open your vault from iCloud Drive, so this iPhone can approve away from your Wi-Fi."
  - Then "Open from iCloud Drive" (primary) and "Only on this Wi-Fi" (secondary).
  - The secondary choice explains itself: "This iPhone approves while it is on the same Wi-Fi as your Mac. Open the vault later in Settings > Devices."
  - The file picker opens at iCloud Drive > Apassy, then asks for the passphrase.
- **Paid:**
  - "Connected. Your vault arrives through Apassy."
  - Then the passphrase, then Face ID unlock (as today).
- **Test question (A5):**
  - a notification "Test from MacBook Pro: tap to try approving";
  - Face ID;
  - "Done. Real questions come here when your agents ask."

### Screen I3: iPhone Settings > Devices

- "This iPhone: approves with Face ID · Connected".
- "Vault: syncs through iCloud Drive / Apassy".
- "Plan: Free · Change it on your Mac". There is no purchase on the iPhone (Gate A).

## 5. Ending design

- **Confirmation copy:** "iPhone 17 is connected. It approves with Face ID."
- **User credit and artifact shown:** the new row in Devices, and "Your iPhone answered in 3 seconds".
- **Value or labor shown:** the time of the test answer.
- **Celebration level:** subtle, a check and a light haptic on the iPhone. It is a first, but it is a setup step, not a milestone.
- **What happens next and how to undo:** "Each question now goes to both. Remove a device in Settings > Devices."
- **One optional next step:** "Add another device".
- **Exit:** "Done".
- **Off-product follow-through:** none for Free (no account). For a purchase, the receipt email repeats what the plan includes and how to cancel.
- **Feedback ask:** none in the flow. One CES question in the next release survey only.

## 6. Emotional journey (Flow A)

| Step | Emotion (−2…+2) | Driver | Fix if negative |
|---|---|---|---|
| Open Devices | 0 | neutral | — |
| Add a device: QR at once | +1 | no fields | — |
| Scan | +1 | instant | — |
| Two words | −1 | "is this a test?" | one line that says why; large words |
| Touch ID | 0 | familiar | — |
| Free: pick the iCloud file | −1 | Files, maybe not downloaded | open at the right folder; show the download; "Not now" |
| Test approval | +2 | it works on the phone (peak) | — |
| Done | +1 | the device in the list | — |

## 7. Ethics gate

| Persuasive element | Principle | Transparency | Symmetry | Reversibility | Alignment | Verdict |
|---|---|---|---|---|---|---|
| "Personal" tag on the Apassy sync option | Feedforward | yes | the free option comes first | n/a | yes | PASS |
| Upgrade sheet at a paid pick | Loss Aversion (honest) | full price shown | "Not now" is as easy | cancel in Settings > Plan | yes | PASS |
| Approvals on by default for a new device | Default Bias | the note says it | one click in the row | yes | the user added the device to approve | PASS |
| Test question at the end | Peak-End Rule | labelled "Test" | "Skip" | n/a | shows real value | PASS |
| Cancel at the end of the period moves sync to iCloud | Loss Aversion | stated in the sheet | yes | the vault stays | yes | PASS |
| Trial (if any) | Default Bias | reminder before the charge | cancel in the same place | yes | — | PASS only with a reminder; else FAIL |

Never: a banner or a badge that nags a Free user, a countdown, a pre-selected yearly plan, a vault held back on downgrade, or approvals taken away on downgrade.

## 8. Validation

- **Hypotheses (written before testing):**
  - H1: with one "Add a device…" and no team code, ≥ 60% of new Mac vaults connect a second device in week 1. Today this is about 0 outside the operator.
  - H2: median time from "Add a device…" to connected is under 45 s.
  - H3: contextual upgrade at the sync pick converts better than "Compare plans" in Settings.
- **Metrics:**
  - step completion of Flow A;
  - time to the first approval on another device;
  - % of questions answered away from the Mac;
  - upgrade conversion by entry point;
  - downgrade → iCloud success;
  - support contacts about pairing and codes.
- **Research plan:** 5 developers with no setup, a neutral script ("make your phone able to answer your agent"). Watch drop-offs at the words and at the iCloud file.
- **Rollout:**
  1. Connect for all, with free approvals. This needs the relay update (section 9).
  2. Plan and checkout.
  3. Sync through Apassy gated by plan. Existing operator-code teams stay as they are (grandfathered).
  4. Shared vaults (Team).

## 9. Dependencies outside the app (not UI, but this flow needs them)

1. **Relay: a free Connect team without an operator code.**
   - Today `POST /v1/teams` needs `apassy_tcd_…`.
   - It needs abuse limits instead: per-device keys, limits per team and per IP, and App Attest/DeviceCheck on the iPhone.
   - The questions schema (team schema 5) must be deployed first. It is not deployed today.
2. **Accounts and entitlements** (paid only; there is no account on Free):
   - an account service with checkout (for example Stripe) and webhooks;
   - a signed entitlement that the relay checks for sync pushes and for shared vaults.
3. **One vault, one Connect team.**
   - A vault that upgrades from iCloud + Connect to Apassy sync keeps its device list: the questions team becomes the sync team.
   - Today the code keeps a questions team and a sync team apart (`membership.rs`).
4. **Site:** a pricing page. "Apassy is free" and "No account" become true per plan.
5. **Decision record:** a new ADR for plans. It replaces ADR 0019 open decision 1, the operator code of ADR 0022, and ADR 0023 D5.
