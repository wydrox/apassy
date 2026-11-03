# Flow Spec: Apple Watch answers access requests

Status: **Gate A accepted by the owner on 2026-11-03** (buttons after the full facts). Mode: master-product **Build** (the flow does not exist).
Sources: [ADR 0033](../../adr/0033-iphone-access-requests.md) §7 (the iPhone screen spec this adapts),
[relay-access-request-v1](../../contracts/relay-access-request-v1.md), the iPhone
`AccessRequestDetailView.swift`, and Apple's watchOS HIG pages (quoted where used, fetched 2026-11-03).
Owner decisions (2026-11-03): an independent watch (its own relay membership), **access requests only**,
**Allow once** while the watch is unlocked on the wrist, arm64 watches only.

## 0. Context

- **User and job-to-be-done:** the vault owner, away from the Mac or with the iPhone in a pocket. An agent
  on a Mac asked for an existing credential (`apassy_request_access`). In the owner's words: *"Let the
  agent use this once, or say no, without walking to my Mac or taking out my phone."*
- **Entry points:**
  1. The iPhone's fixed notification ("A question is waiting"), mirrored to the watch while the iPhone is
     locked. A tap opens the watch app on **Requests**. The payload has no request or vault id, so the app
     never opens a request detail by itself (contract relay-questions-v1 §14.2).
  2. The app from the Home Screen or the Smart Stack.
  3. First launch: the watch is not connected yet. It shows **Connect**.
- **Emotional state at entry:** the owner was interrupted in the middle of something and may not trust the
  agent. **Design implication:** facts come before buttons, nothing creates urgency, and Deny is as easy as
  Allow once (**Empathy Gap**, **Affect Heuristic**).
- **User success:** a correct decision on the exact scope (agent, credential, Mac, action, hosts, folder),
  confirmed by the asking Mac.
- **Business success:** no wrong-scope decisions, few unconfirmed answers, short time to a decision. The
  allow rate is **not** a goal (ADR 0033 §7, ethics).
- **Conflicts between the two:** the watchOS HIG asks for "quick, glanceable, single-screen interactions",
  while ADR 0033 requires the full hosts and folder to be readable before Allow once. **Resolution, in the
  user's favor:** the detail starts with a one-glance summary. The full facts follow, and the answer
  buttons come after them, so the owner scrolls past the facts (Digital Crown) to answer. A request
  without a complete scope offers Deny only.
- **Constraints and assumptions:**
  - watchOS 26 or later, arm64 watches only. SwiftUI only. The vault core is Rust, and its HTTP goes
    through URLSession.
  - No notification actions, no answer from a notification, no preselected answer, no swipe to approve
    (ADR 0033 §7, Defaults/trust).
  - **Allow once** signs with the watch's Secure Enclave answer key, which works only while the watch is
    unlocked and on the wrist. **Deny** signs with the relay device key and needs no authentication.
  - The watch never shows run questions, vault items, or agents.
  - One connected vault per watch in v1 (default; the owner can change it).
  - The watch app has no push of its own in v1. Without the iPhone nearby, the owner opens the app by hand.

## 1. Experience targets

- **Aha! moment (planned peak):** the first answer from the wrist comes back **confirmed by the Mac**:
  "Allowed once", with a success haptic. During setup, the peak is "Connected: this watch answers access
  requests for “Personal”".
- **End state:** the outcome in the past tense, its real deadline, and what is still true ("The bouncer
  still checks the command"), followed by **Done**.
- **The one sentence the user says afterwards:** *"I read what the agent wanted on my watch, allowed it
  once, and my Mac confirmed it."*
- **Likely negative peaks to neutralize** (**Negativity Bias**):
  1. An answer that stays **unconfirmed** because the Mac or the relay is offline.
  2. The request **expires** while the owner reads it.
  3. **Allow once fails** because the watch is locked or off the wrist.
  4. The safety words do not match during setup, or setup fails.
  5. A Mac **removed this watch**, or the question key was rotated, so the watch cannot read new requests.
- **Target length:** an answer takes 3 steps (Requests, detail, answer) and 15 to 30 seconds. Setup takes
  4 steps across three devices and about 1 to 2 minutes, once.

## 2. Information architecture

- **Top tasks (ranked):**
  1. Decide a waiting request.
  2. See the result of an answer.
  3. Connect this watch (once).
  4. See what this watch is connected to, and remove it.
- **Structure:** one `NavigationStack`, no tabs, no vertical pages. The HIG asks to "minimize the depth of
  hierarchy". The stack is **Requests** (root) → **Request** → **Exact identities** (L3). A toolbar button
  opens **This watch** (settings) as a sheet. Setup replaces the root until it is connected.
- **Disclosure layers:**
  - **L1, a Requests row:** "<agent> asks for <credential>", "on <Mac>", and the expiry time.
  - **L2, the Request detail:** all scope facts, the reason, the expiry, the buttons, and the result.
  - **L3, Exact identities:** agent id, Mac id, vault id, credential id and UUID, revision, request id.
- **Vocabulary** (the same words as the iPhone app):
  - "access request" (not "question" or "card")
  - "Allow once" / "Deny"
  - "Asked on <Mac>"
  - "credential" (not "item")
  - "This watch"
  - "Connect" (not "pair" or "join")
- **Entry points and discoverability:**
  - The iPhone shows **Add Apple Watch** in Settings › Devices, next to the existing Connect items.
  - The Mac shows a connected watch in Settings › Devices as "<name> (Apple Watch)".
  - The watch's first screen tells the owner where to start.

## 3. Flow map

```text
SETUP (once)
[Watch: Connect] ─▶ [iPhone: Add Apple Watch ▸ scan the code on the Mac] ─▶ [Watch: Check the words]
                                                                                │
                              [Mac: compare the words ▸ Touch ID] ◀─────────────┘
                                                │
                                                ▼
                            [Watch: Connected] ─▶ [Requests (empty)]
     ↘ words differ / Cancel / link expired ─▶ [Watch: Connect, with the reason]

ANSWER
[Notification mirrored from the iPhone | open the app] ─▶ [Requests] ─▶ [Request]
   ─▶ Allow once (wrist check) ─┐
   ─▶ Deny ─────────────────────┼─▶ [Sending] ─▶ [Sent, waiting for <Mac>] ─▶ [Confirmed result] ─▶ Done ─▶ [Requests]
                                │                       ↘ 60 s with no settle ─▶ [Not confirmed]
   ↘ locked/off wrist ─▶ [Request, "Unlock this watch on your wrist…", Deny still available]
   ↘ expired / answered elsewhere ─▶ [Request with the final state, buttons off]
```

| # | Step | User goal at this step | Ask from user | Value given | Principles | Exit/back/skip |
| --- | --- | --- | --- | --- | --- | --- |
| S1 | Connect (watch) | "How do I set this up?" | Open the iPhone app | Exact path on the iPhone | **Recognition Over Recall**, **Feedforward** | Leave the app; nothing is started |
| S2 | Add Apple Watch (iPhone) | Start the connection | Scan the Mac's code | Link sent to the watch | **Spark Effect** | Cancel on the iPhone |
| S3 | Check the words (watch) | "Is this my Mac?" | Compare 6 words with the Mac | Proof that the link is not swapped | **Authority Bias** (proof at the anxiety point) | **Cancel** on the watch |
| S4 | Confirm (Mac) | Approve this watch | Touch ID | Watch row written by the Mac | **Commitment & Consistency** | Cancel on the Mac |
| S5 | Connected | "Did it work?" | Nothing | What the watch can and cannot do | **Peak-End Rule**, **Feedback Loop** | **Done** |
| A1 | Requests | "Is anything waiting?" | Nothing | Waiting requests, newest first | **Serial Position**, **Pareto** | Close the app |
| A2 | Request | Decide on full facts | Read, then choose | Every scope fact | **Hick's Law** (two choices), **Fitts's Law** | Back; Deny |
| A3 | Sending / Sent | "Did it go through?" | Nothing | Honest status | **Feedback Loop**, **Chronoception** | Back (the answer stays sent) |
| A4 | Confirmed | "What did I just allow?" | Nothing | Outcome, deadline, what is still checked | **Peak-End Rule**, **Cognitive Dissonance** | **Done** |

## 4. Screen specs

Wireframes are for a 45 mm screen. Text uses semantic styles and wraps; nothing important is truncated.

### Screen S1: Connect (watch, not connected)

```text
┌──────────────────────┐
│ Apassy          9:41 │
│                      │
│ Connect to your Mac  │
│                      │
│ On your iPhone, open │
│ Apassy ▸ Settings ▸  │
│ Devices ▸ Add Apple  │
│ Watch.               │
│                      │
│ 📱 Waiting for your  │
│    iPhone            │
└──────────────────────┘
```

- **Purpose:** tell the owner where setup starts. The watch has no camera, so the iPhone scans the Mac's
  code and passes it to the watch.
- **Primary action:** none on the watch. The step happens on the iPhone (**Feedforward**).
- **Hierarchy:**
  1. Headline: "Connect to your Mac".
  2. Supporting: "On your iPhone, open Apassy › Settings › Devices › Add Apple Watch."
  3. Status: "Waiting for your iPhone", with the `iphone` symbol and **no spinner**. HIG feedback.md ›
     watchOS: "Avoid displaying an indeterminate progress indicator".
  4. Reassurance: "This watch answers access requests only. Your passwords stay on your Mac and iPhone."
- **Defaults and prefills:** none.
- **Trust element at the anxiety point:** the owner worries about putting passwords on the watch. The
  reassurance line says that no credential reaches the watch.
- **States:**
  - **After a failed attempt,** an extra line above the steps gives the reason:
    - "The words didn't match, so nothing was connected. Start again on your iPhone."
    - "The code expired. Show a new code on your Mac."
    - "Couldn't reach the relay. Check that this watch is online, then start again on your iPhone."
  - **Removed:** headline "This watch was removed". Body: "A Mac removed this watch. To answer again, connect it again."
- **Principles applied:** **Recognition Over Recall** (the exact menu path); **Cognitive Load** (one task).
- **Accessibility notes:** VoiceOver reads the headline, the path, then the status. The status is a
  label, not an animation.

### Screen S2: Add Apple Watch (iPhone, Settings › Devices)

- **Purpose:** scan the Mac's Connect code for the watch and hand the link to the watch.
- **Primary action:** "Scan the Code on Your Mac" (camera, the existing scanner).
- **Hierarchy:**
  1. Headline: "Add Apple Watch".
  2. Steps:
     1. "On your Mac, open Apassy › Settings › Devices › Add an iPhone or a Mac…"
     2. "Scan the code with this iPhone."
     3. "Check the words on your watch and your Mac."
  3. Primary: "Scan the Code on Your Mac".
  4. Secondary: "Cancel".
  5. Reassurance: "This iPhone only passes the code to your watch. The watch makes its own keys."
- **States:**
  - **Watch not reachable:** "Open Apassy on your Apple Watch, then try again." The scan button is off.
  - **No paired watch:** "Pair an Apple Watch with this iPhone first." The section is hidden when
    `WCSession.isPaired` is false and `isWatchAppInstalled` is false.
  - **Sent:** "Sent to your watch. Check the words on your watch and your Mac." with **Done**.
  - **Error:** "Couldn't send the code to your watch. Keep the watch near this iPhone and try again."
- **Principles applied:** **Goal Gradient** (3 numbered steps, which really are a sequence);
  **Feedforward**.

### Screen S3: Check the words (watch)

```text
┌──────────────────────┐
│ ‹ Cancel        9:42 │
│ Check the words      │
│ 1 amber   4 lunar    │
│ 2 cobalt  5 orbit    │
│ 3 harbor  6 velvet   │
│                      │
│ Confirm them on your │
│ Mac. If they differ, │
│ cancel.              │
│ ⌚ Waiting for your  │
│    Mac               │
└──────────────────────┘
```

- **Purpose:** let the owner compare the six safety words with the Mac before the Mac writes this watch
  into the vault.
- **Primary action:** none on the watch. The owner confirms on the Mac. **Cancel** (toolbar, top
  leading) is the way out.
- **Hierarchy:**
  1. Headline: "Check the words".
  2. Six words, numbered 1 to 6 in two columns at body size. The numbers mark a real sequence.
  3. "Confirm them on your Mac. If they differ, cancel."
  4. Status: "Waiting for your Mac" (no spinner).
- **Trust element at the anxiety point:** the words are the proof. The copy says what to do when they
  differ, right next to them.
- **States:**
  - **Loading** (the link is being registered, under 2 s): "Connecting…" with a small `ProgressView`.
    HIG loading.md › watchOS: "better to display a loading indicator than a blank screen".
  - **Confirmed:** goes to S5.
  - **Cancelled:** goes back to S1, with no reason line.
  - **Expired or refused:** goes back to S1 with the matching reason line.
- **Principles applied:** **Chunking** (6 words in 2×3); **Authority Bias** (proof at the decision).
- **Accessibility notes:** VoiceOver reads "Word 1, amber" and so on. The words stay readable at the
  largest Dynamic Type sizes; at accessibility sizes they fall back to one column and the screen scrolls.

### Screen S5: Connected

- **Purpose:** confirm the setup and say what the watch can and cannot do.
- **Primary action:** "Done" (full width).
- **Hierarchy:**
  1. `checkmark.circle.fill` and the headline "Connected".
  2. "This watch answers access requests for “<vault>” on <Mac>."
  3. "Allow once works while this watch is unlocked on your wrist. Run approvals stay on your iPhone and Mac."
  4. Primary: "Done".
- **States:** none (this screen exists only after a verified handoff).
- **Principles applied:** **Peak-End Rule** (setup ends on a clear, specific success); **Cognitive
  Dissonance** (what the watch cannot do is stated up front).

### Screen A1: Requests (root)

```text
┌──────────────────────┐
│ Requests     ⚙︎  9:43 │
│ ┌──────────────────┐ │
│ │ Claude Code asks │ │
│ │ for GitHub token │ │
│ │ on Studio Mac    │ │
│ │ Until 9:48       │ │
│ └──────────────────┘ │
│ ┌──────────────────┐ │
│ │ Codex asks for   │ │
│ │ Stripe key …     │ │
└──────────────────────┘
```

- **Purpose:** show what is waiting.
- **Primary action:** tap a row to open the request.
- **Hierarchy (row):**
  1. "<agent> asks for <credential>" (headline, up to 3 lines).
  2. "on <Mac>" (secondary).
  3. "Until <time>" (secondary, static time, no countdown).
  - A Production credential adds a "Production" text label, not a color alone.
- **Toolbar:** the gear button "This watch" (top trailing) opens settings.
- **States:**
  - **Empty:** `ContentUnavailableView`, title "No access requests waiting". Description: "When an agent
    asks for a credential, the request appears here."
  - **Loading** (first fetch only): show the last known list at once; with none, show a small
    `ProgressView` "Checking…" for at most about 2 s, then the empty or error state.
  - **Offline:** keep the rows with a footer "Offline. Showing requests from <time>." Answers stay
    possible; their sending can fail.
  - **Answered or expired rows:** they leave the list 10 minutes after they end (the core's rule). Until
    then they show "Allowed once", "Denied", or "Expired" in place of "Until <time>".
  - **Unreadable row:** "Can't read this request" with "Connect this watch again to read new requests."
    (key rotation), or "Update Apassy to read this request." (a newer version).
  - **Removed:** goes to S1 in the Removed state.
- **Principles applied:** **Serial Position** (newest first); **Recognition Over Recall** (agent,
  credential, and Mac are visible in the row).
- **Accessibility notes:** each row is one VoiceOver element: "Claude Code asks for GitHub token on
  Studio Mac, until 9:48". Rows are `.privacySensitive()`, so Always On redacts them (Always On HIG:
  "Hide sensitive information").

### Screen A2: Request (detail)

```text
┌──────────────────────┐
│ ‹ Request       9:43 │
│ Claude Code asks for │
│ GitHub token         │
│ Asked on Studio Mac  │
│ · Personal           │
│──────────────────────│
│ Production           │
│ Real value reaches   │
│ the process          │
│ Action   Deploy      │
│ Hosts                │
│  api.github.com      │
│  uploads.github.com  │
│ Project  shop        │
│  /Users/r/Dev/shop   │
│ The agent says       │
│  "Need to push the   │
│   release tag."      │
│ Agent id 7           │
│ Agent-reported host  │
│ (not verified): codex│
│ Until 9:48           │
│ Requested scope;     │
│ checked against Mac  │
│ policy.              │
│ ┌──────────────────┐ │
│ │   Allow once     │ │
│ └──────────────────┘ │
│                      │
│ ┌──────────────────┐ │
│ │      Deny        │ │
│ └──────────────────┘ │
│ Allows one scoped    │
│ use attempt. The     │
│ bouncer still checks │
│ the command and may  │
│ ask you.             │
│ Exact identities  ›  │
└──────────────────────┘
```

- **Purpose:** decide one access request on full facts.
- **Primary action:** "Allow once" (`.borderedProminent`, full width), shown only when the scope is
  complete and this watch can sign. **Deny** (`role: .destructive`, `.bordered`, full width) is the same
  height, separated by spacing, and never needs authentication. HIG buttons.md › watchOS: "Prefer
  buttons that span the width of the screen for primary actions", and "Use the same height for vertical
  stacks".
- **Hierarchy:**
  1. Headline: "<agent> asks for <credential>".
  2. "Asked on <Mac> · <vault>".
  3. Environment as text ("Production" / "Development") and the delivery line: "Real value reaches the
     process" or "Placeholder for these hosts only".
  4. Action, then **every** host (monospaced, ASCII A-labels, wrapping, never truncated).
  5. Project label and the full folder (wrapping).
  6. "The agent says": the reason as plain escaped text.
  7. "Agent id <id>". Host provenance: "Agent-reported host (not verified): <host>" or "Connection label
     (not executable attestation): <host>", or "Agent host: unknown".
  8. "Until <time>" (neutral, no countdown) and "Requested scope; checked against Mac policy."
  9. Buttons: Allow once, then Deny.
  10. Footnote: "Allows one scoped use attempt. The bouncer still checks the command and may ask you."
  11. "Exact identities" link (L3).
- **Defaults and prefills:** no preselected answer. Neither button has focus when the screen opens.
- **Trust element at the anxiety point:** the owner worries what the agent will do with the credential.
  The scope facts and the "bouncer still checks" line sit right next to the buttons.
- **States:**
  - **Deny only** (the scope is incomplete, or the card offers no Allow once): "Review on <Mac>: this
    request does not specify <fields>." Only Deny is shown.
  - **Authenticating** (Allow once, usually silent with the watch on the wrist): the buttons are
    disabled and show "Checking your wrist…" for at most the system's time.
  - **Allow once refused by the system** (locked, off the wrist, or no passcode): "Allow once needs this
    watch unlocked on your wrist. Nothing was sent." Deny stays available.
  - **Sending** (under 1 s usually): the buttons become disabled. A label replaces them: "Sending…".
  - **Sent:** "Sent. Waiting for <Mac> to confirm." The buttons stay off.
  - **Not confirmed** (60 s with no settle, or past expiry): "Not confirmed. <Mac> may be offline. Check
    on <Mac>." There is no automatic retry with a new signature (contract §4: at most 3 posts).
  - **Confirmed:** goes to A4 in place.
  - **Answered elsewhere:** "Answered on <device>", then the outcome (A4 copy). The buttons are removed.
  - **Expired:** "Expired. Nothing was allowed." The buttons switch to a disabled appearance; they are
    not removed (Always On HIG: "prefer transitioning an interactive component to an unavailable
    appearance").
  - **Unavailable** (the request left the list): `ContentUnavailableView` "This access request is no
    longer available".
  - **Wrist down (Always On):** facts are `.privacySensitive()` and redacted; the buttons look unavailable.
  - **Background:** any signing in progress is cancelled and its result discarded. The sensitive model is
    cleared (ADR 0033 §7, States).
- **Principles applied:** **Hick's Law** (two answers); **Fitts's Law** (full-width buttons);
  **Feedforward** (what Allow once does is shown next to it); **Von Restorff Effect** (only Allow once is
  prominent).
- **Accessibility notes:**
  - The VoiceOver order follows the hierarchy.
  - Hosts and the folder are announced in full.
  - No countdown announcement.
  - Text with icons, never color alone.
  - Reduce Motion: no custom animation.

### Screen A3: Exact identities (L3)

- `List` of `LabeledContent` rows: Agent id, Mac id, Vault id, Credential id (local / UUID), Revision,
  Request id. Monospaced values, wrapping. Read-only.

### Screen A4: Confirmed result (in place of the buttons in A2)

- **Allowed:**
  - `checkmark.circle.fill` and the headline "Allowed once".
  - "Consent recorded for one attempt before <time>."
  - "The bouncer still checks the command and may ask you."
  - "Check on <Mac> for remaining availability."
  - "Answered on This watch" (or another device).
  - Primary: "Done" (back to Requests).
- **Denied:** `xmark.circle` and the headline "Denied". "Nothing was allowed." "Answered on <device>". Primary: "Done".
- **Granted on the Mac:** "Access granted on the Mac". **Invalidated:** "Access request invalidated. Review on the Mac."
- **Feedback:** a `.success` haptic for a confirmed answer from this watch, and none for an outcome
  first seen in the list.

### Screen W: This watch (settings sheet)

- **Purpose:** show what this watch is connected to, and let the owner disconnect it.
- **Hierarchy:**
  1. "Connected to “<vault>”".
  2. "Macs that can ask": the trusted Mac names.
  3. "Allow once needs this watch unlocked on your wrist."
  4. "Remove This Watch" (`role: .destructive`).
- **Remove:** a confirmation dialog: "Remove this watch? It stops answering access requests. Also remove
  it on your Mac in Settings › Devices." with "Remove" and "Cancel". This is the one irreversible local
  action, so it gets a warning and a Cancel. Removing deletes the watch's keys and state and goes to S1.

## 5. Ending design

- **Confirmation copy:** "Allowed once" / "Denied". Past tense, and only after the Mac's signed settle.
- **User credit and artifact shown:** "Answered on This watch", and the exact deadline.
- **Value or labor shown:** "Consent recorded for one attempt before 9:48". The Mac confirmed it.
- **Celebration level:** subtle. A routine security decision gets a haptic and a checkmark, nothing more
  (**Delighters**, used in proportion). The setup's "Connected" is a first, but it still gets no
  confetti, because this is a security product.
- **What happens next and how to undo:**
  - "The bouncer still checks the command and may ask you."
  - "Check on <Mac> for remaining availability."
  - An unused permit can be invalidated on the Mac. A consumed attempt cannot be undone, and the app does
    not suggest otherwise.
- **One optional next step:** none for an answer; the next request is the trigger. For setup, the next
  step is the empty Requests list, which explains what will appear there.
- **Exit:** "Done".
- **Off-product follow-through:** the Mac's Activity lists "Answered on <watch> (Apple Watch)".
- **Feedback ask:** none in the product. The validation plan below measures behavior instead.

## 6. Emotional journey

| Step | Emotion (−2…+2) | Driver | Fix if negative |
| --- | --- | --- | --- |
| Notification | −1 | Interruption, an unknown agent | Fixed text; the app opens on the list, not a guessed request |
| Requests | 0 | Recognizes the agent, credential, and Mac | — |
| Request | 0 | Understands the facts | Facts before buttons; no urgency |
| Allow once (wrist check) | 0 | Usually silent | A clear message if it fails, and Deny stays available |
| Sent, waiting | −1 | Uncertainty | "Sent. Waiting for <Mac> to confirm." names who confirms |
| Confirmed | +1 | Clear, specific outcome | — |
| Not confirmed (alternative) | −1 | Mac offline | Says what to do: check on the Mac; no silent retry |
| Setup: words | 0 | Careful, but guided | The copy says what to do when the words differ |
| Setup: Connected | +1 | Done, scope stated | — |

These are hypotheses, not measured results.

## 7. Ethics gate

| Persuasive element | Principle | Transparency | Symmetry | Reversibility | Alignment | Verdict |
| --- | --- | --- | --- | --- | --- | --- |
| Allow once styled prominent | **Von Restorff Effect** | The footnote and the scope sit next to it | Deny is the same size and height, separate, and needs no check | An unused permit can be invalidated on the Mac | The owner can decide on the wrist | Keep |
| Notification opens Requests | **External Trigger** | Fixed generic text | — | — | No guessed request, no action on the notification | Keep |
| Success haptic | **Delighters** | — | Deny gets the same haptic | — | Confirms the outcome, does not reward allowing | Keep (the same for both outcomes) |
| Expiry time | **Scarcity** ⚠ | The real deadline | — | — | Neutral static time, no countdown or animation | Keep (no countdown) |

There is no default answer, no confirmshaming, no hidden scope, and no "allow always".

## 8. Validation

- **Hypotheses (written before testing):**
  1. Owners find the decision on the watch as clear as on the iPhone. Wrong-scope decisions stay at 0 in
     synthetic tests where the scope differs from the stated task.
  2. The median time from opening a request to answering it is under 30 s.
  3. Unconfirmed answers come only from an offline Mac or relay.
- **Metrics** (local, redacted, aggregate only):
  - decisions per outcome;
  - Allow once failures by reason (locked, off the wrist);
  - unconfirmed receipts;
  - expired while open;
  - the setup completion rate and how often the words did not match.

  The allow rate is not a goal.
- **Research plan:** a synthetic vault and synthetic agents only.
  - Neutral scenarios, including one where denying is correct, and owners who abandon.
  - Observe the Digital Crown use on long host lists.
- **Rollout:**
  - First TestFlight with the owner only, behind the setup flow: nothing changes until a watch is connected.
  - Physical acceptance covers the Secure Enclave key ACL with the wrist check, the mirrored notification
    tap, LTE without the iPhone, and Always On redaction.
