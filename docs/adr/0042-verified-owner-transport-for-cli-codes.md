# ADR 0042 — A verified owner transport for the command line: a confirmation click in the Apassy panel

Date: 2026-11-03.
Status: PROPOSED (draft). Written on the owner's decision of 2026-11-03 ("build everything in the
ADRs except the TEE track; no approval of intermediate steps"). Where this record chooses between
options, the choice is **chosen by this ADR; the owner can change it**.
Plan: [implementation-plan-misc.md](../design/implementation-plan-misc.md), units M8 and M9.
Amends: [ADR 0030](0030-owner-check-window.md) (amendment of 2026-11-01, "CLI code") and
[ADR 0034](0034-mfa-codes-cli-and-agents.md) ("Security review correction"). Uses the panel of
[ADR 0038](0038-touch-id-panel.md).

## Context

`apassy code ITEM` prints or copies a one-time code. Since ADR 0034 it needs a fresh owner check
for each code, also inside a valid owner window, because the owner socket cannot tell the owner from
an agent:

- The owner socket has file permissions and a bearer session (`APASSY_SESSION`). A child process
  inherits the session. An unsandboxed agent of the same user can use it.
- Process ancestry, the TTY, and flags do not help. An agent runs in the same terminal session and
  the same process tree as the owner's shell. A process on a TTY can push input into it
  (`TIOCSTI`), and a pseudo-terminal has no physical keyboard.

The cost: each code is a Touch ID touch. On a Mac without a Touch ID sensor it is the passphrase,
typed each time. The owner chose a global window (ADR 0030, 2026-11-02) to stop this for every other
owner action.

## Options

| Option | Result |
| --- | --- |
| A. Peer identity on the owner socket (`LOCAL_PEERTOKEN`, code signature of the caller, process ancestry) | Rejected. The caller is the signed `apassy` binary in both cases; the agent and the owner share the ancestry. |
| B. Bind the session to a TTY or a process group | Rejected. An agent in the same session has the same TTY and can write to it. |
| C. A confirmation click in the Apassy panel, verified as hardware input, inside a valid window | **Chosen.** The owner's hand on the mouse or the keyboard of this Mac is the proof. An agent can open the panel but cannot press it. |
| D. A signed CLI with its own LocalAuthentication context and a reuse duration | Rejected. A context does not live across CLI processes; each run is a fresh Touch ID, as today. |
| E. Keep every CLI code fresh | Kept as the fallback whenever C cannot verify the press. |

## Decision

### 1. The flow

1. `apassy code ITEM [--copy]` sends `OwnerRequest::CliCode` as today.
2. The frequency is Every time, or no valid window exists: the fresh check of ADR 0034, unchanged.
3. A valid window exists: the app opens the Apassy panel of ADR 0038 in a new **confirm** mode. The
   panel has no `LAAuthenticationView` and no text field. Its title comes from a fixed Rust
   template: "Show the code of “<item title>” in the command line" or "Copy the code of “<item
   title>” for the command line". A supporting line names the caller as the socket sees it: the
   executable name and process id, and the app of its terminal when the process tree names one. The
   buttons are **Cancel** and **Show Code** (or **Copy Code**). No button is the default. Return
   does nothing. Esc cancels.
4. The press counts only when the helper verifies it as hardware input (section 2). Then the helper
   answers `confirmed` with the request nonce. Rust checks the window (ADR 0030: the same helper
   identity, the lock counter, the absolute deadline, the vault epoch) and issues a single-use proof
   that binds the item, the OTP field, show or copy, the vault epoch, and the CLI request id.
5. Any press that the helper cannot verify turns the panel into the fresh check (Touch ID or the
   passphrase). It never fails silently and never uses the window.

### 2. Hardware input

The helper is a separate signed process. It reads the `NSEvent` of the press in its own event loop and
its `CGEvent`:

- A press is hardware input only when `kCGEventSourceUnixProcessID` is 0 and
  `kCGEventSourceStateID` is `kCGEventSourceStateHIDSystemState`. Every other event, including one
  posted with `CGEventPost` by another process, AppleScript, Universal Control, and Screen Sharing,
  is unverified.
- An accessibility press (`AXPress`, VoiceOver, Voice Control, Switch Control) creates no event. It
  is unverified. Assistive technology still works: it leads to the fresh check.
- The predicate is one function in Swift (`HardwareInput.isPhysical`) and one in Rust
  (`apassy_input_guard::is_physical`, unit M8 of the plan) with the same table of cases. The
  physical session confirms the values on the owner's Mac. If the values differ from this section,
  the predicate fails closed: every press is unverified, so the owner gets Touch ID as before.

### 3. Limits

- One CLI confirmation panel at a time. A second `apassy code` while one is open gets `busy`.
- Three cancels within 5 minutes: CLI codes need the fresh check for the next 15 minutes. This stops
  an agent from opening the panel again and again until the owner clicks by habit.
- The panel closes after 60 seconds without an answer. The CLI gets `expired`.
- The window rules of ADR 0030 stay: lock, sleep, user switch, quit, helper failure, a vault change
  end it. The confirmation never extends the window and never seeds it.
- Show Code and Copy Code in the app window, and every other owner action, do not change.

### 4. What the panel proves and what it does not

- It proves that a person pressed a button of the Apassy panel with the mouse, the trackpad, or the
  keyboard of this Mac, inside a window that the owner opened with Touch ID or the passphrase.
- It does not prove which person. Anyone at the unlocked Mac inside the window can confirm. This is
  the residual risk that the owner accepted for the window (ADR 0030, 2026-11-02).
- A same-user process cannot inject into the signed, hardened helper or forge its answer: the answer
  goes over the helper's pipe, which only the app holds, and carries the request nonce.
- A remote session (Screen Sharing, a remote desktop tool) gives unverified input, so it gets the
  fresh check. This is intended.

### 5. Diagnostics

Privacy-safe counts only: confirmations, unverified presses by kind (synthetic event,
accessibility press), cancels, expiries, and the lockout of section 3. No item name, code, command,
or process name is logged.

## Consequences

- CLI codes join the global window for a person at the Mac. An agent that inherited the owner
  session can open the panel, but it can only get a code with a hardware press or a fresh Touch ID.
- The ADR 0030 limit line "CLI code" changes from "always fresh" to "fresh, or a verified
  confirmation inside the window".
- The helper gains one mode, and the app gains one window source (`LocalWindowSource::CliConfirm`).
  The window reuse is allowed for `OwnerAction::CliCode` only with this source.

## Required checks

- A synthetic `CGEventPost` click and an `AXPress` on Show Code open the fresh check; neither issues
  a proof.
- A hardware click inside a valid window issues one proof; the second use of the proof fails.
- Every time, a locked screen, a slept Mac, an ended window, a changed vault, and a helper restart
  each give the fresh check.
- A second request while the panel is open gets `busy`; three cancels give the 15-minute lockout.
- The panel title and the caller line come from templates; an item title with control characters
  is cleaned.
- Physical: the field values of a hardware press on the owner's Mac; VoiceOver leads to Touch ID;
  Universal Control leads to Touch ID.

## Relation to other records

- ADR 0030: the window and its revocation are unchanged. The synthetic-input hardening of its owner
  decision A is unit M8 of the plan, which provides the same predicate for the egui buttons.
- ADR 0034: the proof binding of each CLI code is unchanged; only the source of the check changes.
- ADR 0038: the panel gains a confirm mode. Its rule "no panel contains a text field" stays.
