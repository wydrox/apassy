//! The owner inbox (goal items N1, N3, N4).
//!
//! The inbox has no own storage. It reuses two sources:
//!
//! - The approval queue for runs that wait now.
//! - The encrypted activity log in the vault. The broker stores each refusal and each
//!   result there. A waiting run gets its entry when the wait ends: approved, denied,
//!   timed out, or invalidated. When the owner locks the vault or quits while runs
//!   wait, the app stores an entry for each run first
//!   ([`super::owner_store::OwnerSession::lock_ending_runs`]).
//!
//! So each event stays in the inbox after a restart, when the owner unlocks the vault.
//! A crash or `kill -9` while a run waits leaves the wait record of the broker in the
//! vault (schema 7). The next unlock gives the run an entry that starts with
//! [`ENDED_BY_RESTART`]. The run did not start.
//!
//! An acknowledgment only marks an event as seen. It is not an approval (N4).

use crate::broker::approvals::PendingRun;
use crate::desktop::model::ModelResult;
use crate::desktop::owner_store::{AgentActivityRow, ENDED_BY_LOCK, ENDED_BY_QUIT, OwnerSession};
use crate::vault::{ActivityDecision, ENDED_BY_RESTART};

/// How many activity entries the inbox reads.
pub const INBOX_LIMIT: usize = 100;

/// The broker texts for a run that waited and then ended without an approval
/// (`src/broker/run.rs`), and the texts of the app for a lock or a quit.
const ENDED_WITHOUT_APPROVAL: [&str; 6] = [
    "The owner denied this run.",
    "The owner did not decide in",
    "The vault was locked, or Apassy stopped, before the run started.",
    ENDED_BY_LOCK,
    ENDED_BY_QUIT,
    ENDED_BY_RESTART,
];
/// The broker text when the owner locks the vault during the checks of a run.
const RELOCKED: &str = "The vault was locked while Apassy checked this request.";
/// The start of a result entry after an owner approval.
const OWNER_APPROVED: &str = "Owner approved";

/// One event key. A notification uses it as its identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EventKey {
    /// A run that waits in the approval queue.
    Run(u64),
    /// An entry of the activity log.
    Activity(u64),
}

impl EventKey {
    /// The notification identifier: `run-<id>` or `activity-<id>`.
    pub fn notification_id(self) -> String {
        match self {
            Self::Run(id) => format!("run-{id}"),
            Self::Activity(id) => format!("activity-{id}"),
        }
    }
}

/// The type of an inbox event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboxKind {
    /// A run waits for the owner now.
    ApprovalWaiting,
    /// A run waited for the owner, and the wait ended.
    ApprovalEnded { approved: bool },
    /// The broker refused a request: a rule, a grant, the bouncer, or a token.
    RequestBlocked,
}

impl InboxKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::ApprovalWaiting => "Approval waiting",
            Self::ApprovalEnded { approved: true } => "Approved by you",
            Self::ApprovalEnded { approved: false } => "Approval ended without a run",
            Self::RequestBlocked => "Request blocked",
        }
    }
}

/// One inbox event. It has no secret value: the broker never stores one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboxEvent {
    pub key: EventKey,
    pub kind: InboxKind,
    /// UTC time, or "now" for a waiting run.
    pub when: String,
    pub agent: String,
    /// The request: `run <command>` or a connector operation.
    pub summary: String,
    /// The reason or the purpose.
    pub detail: String,
}

/// True when an activity entry ended because of an owner action or a lock. The owner
/// already knows about it, so it causes no notification.
fn owner_caused(reason: &str) -> bool {
    reason.starts_with(RELOCKED)
        || ENDED_WITHOUT_APPROVAL
            .iter()
            .any(|prefix| reason.starts_with(prefix))
}

/// The inbox type of an activity entry, or `None` for an entry that is not an inbox
/// event (for example a run that the bouncer allowed).
pub fn classify(decision: ActivityDecision, reason: &str) -> Option<InboxKind> {
    if reason.starts_with(OWNER_APPROVED) {
        return Some(InboxKind::ApprovalEnded { approved: true });
    }
    if decision != ActivityDecision::Deny {
        return None;
    }
    if ENDED_WITHOUT_APPROVAL
        .iter()
        .any(|prefix| reason.starts_with(prefix))
    {
        Some(InboxKind::ApprovalEnded { approved: false })
    } else {
        Some(InboxKind::RequestBlocked)
    }
}

/// True when an activity entry is a blocked request that needs a notification (N1).
pub fn needs_notification(decision: ActivityDecision, reason: &str) -> bool {
    decision == ActivityDecision::Deny && !owner_caused(reason)
}

fn from_row(row: AgentActivityRow) -> Option<InboxEvent> {
    let kind = classify(row.decision, &row.reason)?;
    Some(InboxEvent {
        key: EventKey::Activity(row.id),
        kind,
        when: row.when,
        agent: row.agent,
        summary: row.operation,
        detail: row.reason,
    })
}

fn from_run(run: &PendingRun) -> InboxEvent {
    InboxEvent {
        key: EventKey::Run(run.id),
        kind: InboxKind::ApprovalWaiting,
        when: "now".to_owned(),
        agent: run.agent.clone(),
        summary: format!("run {}", run.command.join(" ")),
        detail: format!("Purpose: {}", run.purpose),
    }
}

/// The inbox: waiting runs first, then events from the activity log, newest first.
/// The vault must be unlocked.
pub fn collect(session: &OwnerSession, pending: &[PendingRun]) -> ModelResult<Vec<InboxEvent>> {
    let rows = session.activity(INBOX_LIMIT)?;
    Ok(pending
        .iter()
        .map(from_run)
        .chain(rows.into_iter().filter_map(from_row))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_texts_are_approval_events_and_other_denials_are_blocks() {
        use ActivityDecision::{Allow, Deny, Error};
        assert_eq!(
            classify(Allow, "Owner approved. Exit code 0."),
            Some(InboxKind::ApprovalEnded { approved: true })
        );
        assert_eq!(
            classify(Error, "Owner approved. The run timed out and was stopped."),
            Some(InboxKind::ApprovalEnded { approved: true })
        );
        // An approval on the iPhone (ADR 0014) is an approval event too.
        assert_eq!(
            classify(Allow, "Owner approved on the iPhone. Exit code 0."),
            Some(InboxKind::ApprovalEnded { approved: true })
        );
        assert_eq!(classify(Allow, "Bouncer allowed. Exit code 0."), None);
        for reason in [
            "The owner denied this run. Risk: low.",
            "The owner did not decide in 120.0 seconds. Risk: low.",
            ENDED_BY_LOCK,
            ENDED_BY_QUIT,
            ENDED_BY_RESTART,
        ] {
            assert_eq!(
                classify(Deny, reason),
                Some(InboxKind::ApprovalEnded { approved: false }),
                "{reason}"
            );
            assert!(!needs_notification(Deny, reason), "{reason}");
        }
        let blocked = "The command is not in the permitted prefixes. Purpose: test.";
        assert_eq!(classify(Deny, blocked), Some(InboxKind::RequestBlocked));
        assert!(needs_notification(Deny, blocked));
        assert!(!needs_notification(Allow, blocked));
        assert!(!needs_notification(Deny, RELOCKED));
    }

    #[test]
    fn notification_ids_follow_the_helper_rule() {
        assert_eq!(EventKey::Run(7).notification_id(), "run-7");
        assert_eq!(EventKey::Activity(12).notification_id(), "activity-12");
    }
}
