# Notifications and the inbox

Date: 2026-09-26.
Scope: goal items N1, N2, N3, and N4 ([goal](../goal.md), [ADR 0010](../adr/0010-closing-open-decisions.md), Notifications).
Host: Mac16,10 (Mac mini, Apple M4), macOS 27.0 (26A428), Rust 1.97.0.
This document does not open the real-secret gate.

## What the owner sees

- A run that waits for the owner causes a macOS notification "Approval waiting".
- A request that the broker blocks causes a macOS notification "Request blocked".
- The preview has the agent name and the event type only. It never has the command, the user request, the purpose, or a value (N2).
- The owner decides in the app. A notification is not an approval. "Mark as seen" in the inbox is not an approval (N4).
- The Activity view has the Inbox card. It shows the notification channel, the delivery result of each event, and the events.

## Design

| Part | File | Work |
| --- | --- | --- |
| Watcher thread | `src/desktop/notify.rs` | Wakes when a run starts to wait, and every 1 s. Finds new waiting runs in the approval queue and new blocked requests in the activity log. |
| Sender thread | `src/desktop/notify.rs` | Calls `NativeHelper::notify` for each event. A call can block for 40 s, so the watcher does not wait for it. |
| Preview | `src/native/mod.rs` | `Notification::new(event_id, agent_name, event)` is the only constructor. It takes no free text. |
| Inbox | `src/desktop/inbox.rs` | Waiting runs from the queue, and events from the activity log in the vault. |
| Inbox card | `src/desktop/ui/inbox_view.rs` | Channel state, delivery results, events, "Mark as seen". |

The notification center starts with the window, after the broker. It replaces the notifier of the approval queue: the notifier wakes the watcher and repaints the window.
The helper calls run on worker threads only. The UI thread never calls the helper.

### Which events cause a notification

| Event | Source | Notification |
| --- | --- | --- |
| A run starts to wait for the owner | Approval queue | "Approval waiting", one for each run |
| A request is refused (rule, grant, bouncer, token, directory) | Activity entry with decision `deny` | "Request blocked" |
| The owner denied a run, the owner did not decide in time, or a lock ended the run | Activity entry with decision `deny` | None. The owner already knows. |
| A run that the bouncer allowed | Activity entry with decision `allow` | None |

The watcher reads the activity log only when the vault is unlocked. At the first read after an unlock, it takes the existing entries as history. They cause no notification.
The broker cannot write the log while the vault is locked. So a request that arrives when the vault is locked causes no notification. The agent gets `vault_locked`.

The watcher finds an owner-caused denial by the start of its reason text (`src/desktop/inbox.rs`, `ENDED_WITHOUT_APPROVAL`). If a later change of `src/broker/run.rs` changes such a text, the result is one extra "Request blocked" notification. It is never a lost notification.

### Preview text (N2)

| Event | Title | Body |
| --- | --- | --- |
| Approval waiting | Approval waiting | Agent "NAME" waits for your decision. Open Apassy to review. |
| Request blocked | Request blocked | Apassy blocked a request from agent "NAME". |

NAME is the agent name from the vault, with control characters removed, at most 40 characters.
The notification identifier is `run-<id>` or `activity-<id>`. It has no text from the request.

### Inbox storage (N3)

The inbox has no own table. It reuses the encrypted activity log of the vault (schema v2, table `activity`). There is no schema change.

- The broker stores each refusal and each result of a request in the log.
- A waiting run gets its entry when the wait ends: approved, denied, timed out, or invalidated.
- When the owner locks the vault, or quits Apassy, while runs wait, the app first stores a denial for each waiting run: "The owner locked the vault before a decision. The run did not start." or "Apassy stopped before the owner decided. The run did not start." The app holds the vault mutex from this entry to the lock. So the broker finds the vault locked and does not store a second entry.
- The inbox shows the last 100 log entries that are inbox events, and the runs that wait now.

After a restart, the vault starts locked (V3). The inbox shows the events after the owner unlocks the vault.

### Delivery failure (N3)

A delivery fails when the helper answers `notifications_denied` or `notifications_unavailable`, when `delivered` is false, when the helper is missing, or when the helper does not answer in 40 s.
Then:

- the event in the inbox shows "Notification failed: ... The event stays in this inbox.",
- the Inbox card shows the number of failed notifications and the channel state,
- nothing changes in the approval queue. The run still waits until the owner decides or the approval time ends.

The channel state comes from `notify_status` at start, from each `notify` answer, and from the "Check notification settings" button. "Allow notifications" calls `notify_authorize` when the owner has not decided yet.

### Not an approval (N4)

- `ApprovalQueue::approve` takes only an `OwnerProof` from `OwnerGate::authorize` (goal item A4). The notification code and the inbox code cannot make a proof.
- The proof names the run exactly as the owner saw it. An approval of an old run (it ended, or it is from an earlier queue or vault session) fails with `NotWaiting`. An approval of a changed request (other command, directory, variables, purpose, or user request) fails with `Changed`.
- The broker checks the vault epoch again after the decision (V3).

## Evidence

Tests, all with synthetic values:

| Test | Item | What it shows |
| --- | --- | --- |
| `tests/notifications.rs` `waiting_approval_notifies_within_five_seconds` | N1, N2, N4 | Real broker, fake helper. A run in "ask" mode waits. The `notify` request arrives in less than 5 s. Title and body are exactly the fixed text. The request log has no command, purpose, user request, or secret canary. The delivered notification does not approve: the run times out, and the command does not run. |
| `tests/notifications.rs` `blocked_request_notifies_within_five_seconds` | N1, N2 | A refused run (directory outside the grant) causes "Request blocked" in less than 5 s. An owner denial causes no "Request blocked". |
| `tests/notifications.rs` `delivery_failure_is_visible_and_the_request_stays` | N3 | The fake answers `notifications_denied`. The delivery is `Failed`, the channel cannot deliver, the run still waits, and the inbox lists it. |
| `tests/notifications.rs` `inbox_keeps_events_after_a_restart` | N3 | A blocked request and a waiting run. The app quits with `lock_ending_runs`. A new session opens the file and unlocks. The inbox has both events, one entry for the run, and no secret. |
| `tests/notifications.rs` `old_or_changed_request_cannot_be_approved` | N4 | With a passed passphrase check: a changed command or directory gives `Changed`. After a denial, the old run gives `NotWaiting`. The command does not run. |
| `src/broker/approvals.rs` `approve_refuses_without_a_matching_fresh_proof` | N4, A4 | A proof for another action, an old proof, a changed run, and another run ID are refused. "Approve and remember" uses the same path. |
| `src/desktop/ui/owner_tests.rs` `approval_needs_the_owner_check_and_seen_is_not_an_approval` | N4, A4 | In the app: "Mark as seen" and a wrong passphrase do not approve. The correct passphrase approves. |
| `src/desktop/inbox.rs` unit tests | N1, N3 | The classification of log entries, and the notification identifiers. |

Measured time from the event to the `notify` request, three runs of the two N1 tests:

| Event | Run 1 | Run 2 | Run 3 |
| --- | --- | --- | --- |
| Approval waiting | 0.14 ms | 0.12 ms | 0.09 ms |
| Request blocked | 670 ms | 679 ms | 675 ms |

The approval time starts when the test sees the waiting run. The test looks every 5 ms, so the real time can be up to 5 ms longer. The notifier wakes the watcher at once.
The blocked time starts when the agent gets the refusal. The watcher reads the log every 1 s, so the worst case is about 1 s plus the helper call.
These times are to the helper request. The time until macOS shows the banner is in the owner checklist.

## Limits

- A crash or `kill -9` while a run waits leaves no entry for that run. The run did not start, and the agent got no approval. A crash-safe "waiting" entry needs a new activity decision value, which is a schema change. The worker that owns schema v7 decides this.
- The watcher reads at most 50 new log entries per second. A burst of more refusals causes notifications for the newest 50 only. All entries stay in the log and in the inbox.
- "Mark as seen" is kept in memory only. After a restart, each event shows again as not seen.
- The delivery result of an event is kept in memory only. After a restart, the inbox shows the events without a delivery result.
- A notification tells the owner that an event exists. It cannot prove that the owner saw it.

## Owner checklist

Use a vault with synthetic values. Record the results here.

1. Build: `scripts/build-app.sh`. Start: `open target/Apassy.app`. Allow notifications: Activity > Inbox > "Allow notifications", then click "Allow" in the macOS prompt. Expect "Notifications are allowed. Banners are on."
2. N1, N2 waiting: register an agent, give it process access with "Allow, ask each time", and send a run from the agent. Expect a banner "Approval waiting" within 5 seconds, with the agent name and no command. Measure with a stopwatch from the agent request to the banner.
3. N1, N2 blocked: send a run from a directory outside the grant. Expect a banner "Request blocked" within 5 seconds.
4. N4: click the banner. Expect that Apassy opens and the run still waits. Select "Mark as seen". Expect that the run still waits. Approve it only through "Approve once" and Touch ID or the passphrase.
5. N3 failure: turn off notifications for Apassy in System Settings > Notifications. Send a run in "ask" mode. Expect "Notification failed" at the event, and the run still waits.
6. N3 restart: while a run waits, quit Apassy. Start it, open and unlock the vault. Expect the event "Approval ended without a run" with "Apassy stopped before the owner decided", and the earlier "Request blocked" event.
