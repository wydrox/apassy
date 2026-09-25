//! Owner approvals for process runs (ADR 0006).
//!
//! A broker thread puts a pending run in the queue and waits. The desktop app
//! shows the queue and records the owner decision. A pending run has no secret
//! value, only environment variable names.

use std::collections::BTreeMap;
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

/// A run that waits for the owner. It has no secret value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRun {
    pub id: u64,
    pub agent: String,
    pub command: Vec<String>,
    pub cwd: String,
    pub env_names: Vec<String>,
    pub purpose: String,
    /// Bouncer result and heuristic flags. It has no secret value.
    pub risk: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalOutcome {
    Approved,
    Denied,
    TimedOut,
}

#[derive(Debug, Default)]
struct QueueState {
    next_id: u64,
    pending: Vec<PendingRun>,
    decisions: BTreeMap<u64, bool>,
}

type Notifier = Box<dyn Fn() + Send + Sync>;

#[derive(Default)]
pub struct ApprovalQueue {
    state: Mutex<QueueState>,
    changed: Condvar,
    /// Called when a run starts to wait. The desktop app uses it to repaint at once.
    notifier: Mutex<Option<Notifier>>,
}

impl std::fmt::Debug for ApprovalQueue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApprovalQueue").finish_non_exhaustive()
    }
}

impl ApprovalQueue {
    pub fn new() -> Self {
        Self::default()
    }

    fn state(&self) -> MutexGuard<'_, QueueState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Set the function that runs when a new run waits.
    pub fn set_notifier(&self, notifier: impl Fn() + Send + Sync + 'static) {
        *self.notifier.lock().unwrap_or_else(PoisonError::into_inner) = Some(Box::new(notifier));
    }

    fn notify_owner(&self) {
        if let Some(notifier) = self
            .notifier
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
        {
            notifier();
        }
    }

    /// Runs that wait for a decision, oldest first.
    pub fn pending(&self) -> Vec<PendingRun> {
        self.state().pending.clone()
    }

    /// Record the owner decision. Returns false when the run no longer waits.
    pub fn decide(&self, id: u64, approve: bool) -> bool {
        let mut state = self.state();
        if !state.pending.iter().any(|run| run.id == id) {
            return false;
        }
        state.pending.retain(|run| run.id != id);
        state.decisions.insert(id, approve);
        self.changed.notify_all();
        true
    }

    /// Deny every waiting run. The desktop app calls this when the owner locks the vault.
    pub fn deny_all(&self) {
        let mut state = self.state();
        let ids: Vec<u64> = state.pending.iter().map(|run| run.id).collect();
        state.pending.clear();
        for id in ids {
            state.decisions.insert(id, false);
        }
        self.changed.notify_all();
    }

    /// Put a run in the queue and wait for the owner or the timeout.
    pub fn wait_for(&self, mut run: PendingRun, timeout: Duration) -> ApprovalOutcome {
        let deadline = Instant::now() + timeout;
        let mut state = self.state();
        state.next_id += 1;
        let id = state.next_id;
        run.id = id;
        state.pending.push(run);
        self.changed.notify_all();
        drop(state);
        self.notify_owner();
        let mut state = self.state();
        loop {
            if let Some(approved) = state.decisions.remove(&id) {
                return if approved {
                    ApprovalOutcome::Approved
                } else {
                    ApprovalOutcome::Denied
                };
            }
            let now = Instant::now();
            if now >= deadline {
                state.pending.retain(|pending| pending.id != id);
                return ApprovalOutcome::TimedOut;
            }
            state = self
                .changed
                .wait_timeout(state, deadline - now)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    fn run() -> PendingRun {
        PendingRun {
            id: 0,
            agent: "Agent".to_owned(),
            command: vec!["true".to_owned()],
            cwd: "/tmp".to_owned(),
            env_names: vec!["X".to_owned()],
            purpose: "test".to_owned(),
            risk: String::new(),
        }
    }

    #[test]
    fn approve_deny_and_timeout() {
        let queue = Arc::new(ApprovalQueue::new());
        let signals = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&signals);
        queue.set_notifier(move || {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        });
        let waiter = {
            let queue = Arc::clone(&queue);
            std::thread::spawn(move || queue.wait_for(run(), Duration::from_secs(5)))
        };
        while queue.pending().is_empty() {
            std::thread::sleep(Duration::from_millis(5));
        }
        let id = queue.pending()[0].id;
        assert!(queue.decide(id, true));
        assert_eq!(waiter.join().expect("join"), ApprovalOutcome::Approved);
        assert_eq!(signals.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(!queue.decide(id, false));

        let waiter = {
            let queue = Arc::clone(&queue);
            std::thread::spawn(move || queue.wait_for(run(), Duration::from_secs(5)))
        };
        while queue.pending().is_empty() {
            std::thread::sleep(Duration::from_millis(5));
        }
        queue.deny_all();
        assert_eq!(waiter.join().expect("join"), ApprovalOutcome::Denied);

        assert_eq!(
            queue.wait_for(run(), Duration::from_millis(20)),
            ApprovalOutcome::TimedOut
        );
        assert!(queue.pending().is_empty());
    }
}
