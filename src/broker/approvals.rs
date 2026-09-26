//! Owner approvals for process runs (ADR 0006).
//!
//! A broker thread puts a pending run in the queue and waits. The desktop app
//! shows the queue and records the owner decision. A pending run has no secret
//! value, only environment variable names.
//!
//! An approval is valid only in the queue and the vault session where the run
//! started to wait (goal item V3). [`ApprovalQueue::invalidate_all`] ends every
//! waiting run and every decision that a run did not use yet. The waiting thread
//! also checks the vault, so a lock ends the wait even when nobody calls
//! `invalidate_all`. Run IDs start at a random value, so an ID from an earlier
//! queue does not match a run in a new queue.
//!
//! An approval needs a fresh owner check (goal item A4). [`ApprovalQueue::approve`]
//! takes an [`OwnerProof`] from [`OwnerGate::authorize`] for exactly the run that
//! waits. Each approval path, also "Approve and remember", goes through it. A denial
//! needs no check, because it only takes authority away.

mod owner_auth;

use std::collections::BTreeMap;
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

pub use owner_auth::{
    CheckMethod, OwnerAction, OwnerAuthError, OwnerCheck, OwnerGate, OwnerProof, PROOF_LIFETIME,
    ProofRefusal, touch_id_detail,
};

/// How often a waiting run checks that its vault session is still valid.
const WATCH_INTERVAL: Duration = Duration::from_millis(100);

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
    /// The user request: from the host hook when there is one, else from the agent.
    /// Empty when there is none.
    pub user_request: String,
    /// Where the user request comes from, for example "from the agent" (goal item B6).
    pub request_source: String,
    /// The agent text when a hook request replaced it and the two differ. Else empty.
    pub agent_request: String,
    /// The pattern that "Approve and remember" teaches (ADR 0010). `None` when the run
    /// cannot teach a pattern, for example a production run or a run with a rule flag.
    pub remember: Option<RememberOffer>,
}

/// A pattern that the owner can teach with "Approve and remember".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RememberOffer {
    /// The generalized command, for example `git log -n <number>`.
    pub pattern: String,
    /// Approvals that the pattern has now.
    pub approvals: u32,
    /// Approvals that the pattern needs to run without a prompt.
    pub needed: u32,
}

/// The owner answer that a waiting run gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answer {
    Approve,
    /// Approve the run and add one approval to its pattern.
    ApproveAndRemember,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalOutcome {
    Approved,
    /// The owner approved with "Approve and remember".
    ApprovedAndRemembered,
    Denied,
    TimedOut,
    /// The vault was locked or replaced, or the broker stopped, before the run used a
    /// decision. An approval from before that event is not valid.
    Invalidated,
}

/// Why [`ApprovalQueue::approve`] refused an approval. The run did not get it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalRefusal {
    /// The proof is not for an approval.
    NotAnApproval,
    /// The owner check is older than [`PROOF_LIFETIME`].
    Stale,
    /// No run with this ID waits: it ended, timed out, or belongs to an older queue.
    NotWaiting,
    /// The waiting run is not the run that the owner confirmed.
    Changed,
    /// "Approve and remember" for a run that cannot teach a pattern.
    NothingToRemember,
}

impl ApprovalRefusal {
    pub fn message(self) -> &'static str {
        match self {
            Self::NotAnApproval => "The owner check was for another action. Nothing was approved.",
            Self::Stale => "The owner check is too old. Confirm again. Nothing was approved.",
            Self::NotWaiting => "The run no longer waits. Nothing was approved.",
            Self::Changed => {
                "The request changed after you saw it. Nothing was approved. Review the request again."
            }
            Self::NothingToRemember => {
                "This run cannot teach a pattern. Nothing was approved. Use \"Approve once\"."
            }
        }
    }
}

#[derive(Debug, Default)]
struct QueueState {
    next_id: u64,
    /// Changes when [`ApprovalQueue::invalidate_all`] runs. A run that started to wait
    /// in an earlier generation cannot use a decision.
    generation: u64,
    /// The broker stopped. A new run does not wait.
    closed: bool,
    pending: Vec<PendingRun>,
    decisions: BTreeMap<u64, Answer>,
}

type Notifier = Box<dyn Fn() + Send + Sync>;

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

impl Default for ApprovalQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl ApprovalQueue {
    pub fn new() -> Self {
        // A random start keeps IDs of one queue apart from the IDs of a later queue,
        // for example after a restart. 48 bits leave room to count up.
        let mut seed = [0u8; 8];
        let start = if getrandom::fill(&mut seed).is_ok() {
            u64::from_le_bytes(seed) >> 16
        } else {
            0
        };
        Self {
            state: Mutex::new(QueueState {
                next_id: start,
                ..QueueState::default()
            }),
            changed: Condvar::new(),
            notifier: Mutex::new(None),
        }
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

    /// Approve a waiting run (goal item A4). `proof` must come from
    /// [`OwnerGate::authorize`] for [`OwnerAction::ApproveRun`] or
    /// [`OwnerAction::ApproveAndRemember`], with the run exactly as it waits now. A
    /// notification or an acknowledgment cannot make a proof, so it is never an
    /// approval (goal item N4). "Approve and remember" needs a run with a pattern
    /// offer. Its run ends with [`ApprovalOutcome::ApprovedAndRemembered`], and the
    /// broker then adds one approval to the pattern (ADR 0010).
    pub fn approve(&self, proof: OwnerProof) -> Result<(), ApprovalRefusal> {
        let Some(confirmed) = proof.action().run() else {
            return Err(ApprovalRefusal::NotAnApproval);
        };
        if !proof.is_fresh() {
            return Err(ApprovalRefusal::Stale);
        }
        let answer = match proof.action() {
            OwnerAction::ApproveAndRemember(_) => Answer::ApproveAndRemember,
            _ => Answer::Approve,
        };
        let mut state = self.state();
        match state.pending.iter().find(|run| run.id == confirmed.id) {
            None => Err(ApprovalRefusal::NotWaiting),
            Some(waiting) if waiting != confirmed => Err(ApprovalRefusal::Changed),
            Some(waiting) if answer == Answer::ApproveAndRemember && waiting.remember.is_none() => {
                Err(ApprovalRefusal::NothingToRemember)
            }
            Some(_) => {
                Self::settle(&mut state, confirmed.id, answer);
                self.changed.notify_all();
                Ok(())
            }
        }
    }

    /// Deny a waiting run. A denial needs no owner check. Returns false when the run
    /// no longer waits.
    pub fn deny(&self, id: u64) -> bool {
        let mut state = self.state();
        if !state.pending.iter().any(|run| run.id == id) {
            return false;
        }
        Self::settle(&mut state, id, Answer::Deny);
        self.changed.notify_all();
        true
    }

    fn settle(state: &mut QueueState, id: u64, answer: Answer) {
        state.pending.retain(|run| run.id != id);
        state.decisions.insert(id, answer);
    }

    /// End every waiting run and every decision that a run did not use yet. The
    /// desktop app calls this when the owner locks the vault. The broker calls it
    /// when it stops.
    pub fn invalidate_all(&self) {
        let mut state = self.state();
        state.generation = state.generation.wrapping_add(1);
        state.pending.clear();
        state.decisions.clear();
        self.changed.notify_all();
    }

    /// End every waiting run and refuse new waits. The broker calls this when it stops.
    pub fn close(&self) {
        self.state().closed = true;
        self.invalidate_all();
    }

    /// Put a run in the queue and wait for the owner or the timeout.
    ///
    /// `still_valid` checks the vault session of the run. It runs without the queue
    /// lock, about every 100 ms. When it returns false, the wait ends with
    /// [`ApprovalOutcome::Invalidated`], also after an approval that the run did not use.
    pub fn wait_for(
        &self,
        mut run: PendingRun,
        timeout: Duration,
        still_valid: impl Fn() -> bool,
    ) -> ApprovalOutcome {
        let deadline = Instant::now() + timeout;
        let mut state = self.state();
        if state.closed {
            return ApprovalOutcome::Invalidated;
        }
        state.next_id = state.next_id.wrapping_add(1);
        let id = state.next_id;
        let generation = state.generation;
        run.id = id;
        state.pending.push(run);
        self.changed.notify_all();
        drop(state);
        self.notify_owner();
        loop {
            let mut state = self.state();
            if state.generation != generation {
                state.pending.retain(|pending| pending.id != id);
                state.decisions.remove(&id);
                return ApprovalOutcome::Invalidated;
            }
            if let Some(answer) = state.decisions.remove(&id) {
                return match answer {
                    Answer::Approve => ApprovalOutcome::Approved,
                    Answer::ApproveAndRemember => ApprovalOutcome::ApprovedAndRemembered,
                    Answer::Deny => ApprovalOutcome::Denied,
                };
            }
            let now = Instant::now();
            if now >= deadline {
                state.pending.retain(|pending| pending.id != id);
                return ApprovalOutcome::TimedOut;
            }
            let wait = (deadline - now).min(WATCH_INTERVAL);
            drop(
                self.changed
                    .wait_timeout(state, wait)
                    .unwrap_or_else(PoisonError::into_inner)
                    .0,
            );
            // The check can take the vault lock. The owner thread takes the vault lock
            // and then the queue lock, so do not hold the queue lock here.
            if !still_valid() {
                let mut state = self.state();
                state.pending.retain(|pending| pending.id != id);
                state.decisions.remove(&id);
                return ApprovalOutcome::Invalidated;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::mpsc;

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
            user_request: String::new(),
            request_source: String::new(),
            agent_request: String::new(),
            remember: None,
        }
    }

    fn wait_until_pending(queue: &ApprovalQueue) -> u64 {
        loop {
            if let Some(run) = queue.pending().first() {
                return run.id;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// A proof for the waiting run `id`, as the gate makes it after an owner check.
    fn proof_for(queue: &ApprovalQueue, id: u64) -> OwnerProof {
        let run = queue
            .pending()
            .into_iter()
            .find(|run| run.id == id)
            .expect("the run waits");
        OwnerProof::issue_for_test(OwnerAction::ApproveRun(run), [0; 32], Instant::now())
    }

    fn start_waiter(queue: &Arc<ApprovalQueue>) -> std::thread::JoinHandle<ApprovalOutcome> {
        let queue = Arc::clone(queue);
        std::thread::spawn(move || queue.wait_for(run(), Duration::from_secs(5), || true))
    }

    /// Goal item A4: an approval needs a fresh proof for exactly the waiting run.
    #[test]
    fn approve_refuses_without_a_matching_fresh_proof() {
        let queue = Arc::new(ApprovalQueue::new());
        let waiter = start_waiter(&queue);
        let id = wait_until_pending(&queue);
        let waiting = queue.pending()[0].clone();

        // A proof for another action is not an approval.
        let reveal =
            OwnerProof::issue_for_test(OwnerAction::Reveal { item_id: 1 }, [0; 32], Instant::now());
        assert_eq!(queue.approve(reveal), Err(ApprovalRefusal::NotAnApproval));

        // An old owner check is not an approval.
        let old = Instant::now()
            .checked_sub(PROOF_LIFETIME + Duration::from_secs(1))
            .expect("old instant");
        let stale =
            OwnerProof::issue_for_test(OwnerAction::ApproveRun(waiting.clone()), [0; 32], old);
        assert_eq!(queue.approve(stale), Err(ApprovalRefusal::Stale));

        // The owner confirmed another command than the one that waits.
        let mut changed = waiting.clone();
        changed.command = vec!["rm".to_owned(), "-rf".to_owned(), "/tmp/x".to_owned()];
        let proof =
            OwnerProof::issue_for_test(OwnerAction::ApproveRun(changed), [0; 32], Instant::now());
        assert_eq!(queue.approve(proof), Err(ApprovalRefusal::Changed));

        // Another waiting run with the same content but another ID.
        let mut other = waiting.clone();
        other.id = id.wrapping_add(1000);
        let proof =
            OwnerProof::issue_for_test(OwnerAction::ApproveRun(other), [0; 32], Instant::now());
        assert_eq!(queue.approve(proof), Err(ApprovalRefusal::NotWaiting));

        // "Approve and remember" uses the same path. This run has no pattern offer.
        let remember = OwnerProof::issue_for_test(
            OwnerAction::ApproveAndRemember(waiting.clone()),
            [0; 32],
            Instant::now(),
        );
        assert_eq!(
            queue.approve(remember),
            Err(ApprovalRefusal::NothingToRemember)
        );

        // Each refusal left the run waiting.
        assert_eq!(queue.pending(), vec![waiting.clone()]);
        let once = OwnerProof::issue_for_test(
            OwnerAction::ApproveRun(waiting.clone()),
            [0; 32],
            Instant::now(),
        );
        assert_eq!(queue.approve(once), Ok(()));
        assert_eq!(waiter.join().expect("join"), ApprovalOutcome::Approved);

        // The run ended. The same approval again finds no run.
        let again =
            OwnerProof::issue_for_test(OwnerAction::ApproveRun(waiting), [0; 32], Instant::now());
        assert_eq!(queue.approve(again), Err(ApprovalRefusal::NotWaiting));
    }

    #[test]
    fn approve_deny_and_timeout() {
        let queue = Arc::new(ApprovalQueue::new());
        let signals = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&signals);
        queue.set_notifier(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        });
        let waiter = {
            let queue = Arc::clone(&queue);
            std::thread::spawn(move || queue.wait_for(run(), Duration::from_secs(5), || true))
        };
        let id = wait_until_pending(&queue);
        assert_eq!(queue.approve(proof_for(&queue, id)), Ok(()));
        assert_eq!(waiter.join().expect("join"), ApprovalOutcome::Approved);
        assert_eq!(signals.load(Ordering::SeqCst), 1);
        assert!(!queue.deny(id));

        let waiter = start_waiter(&queue);
        let id = wait_until_pending(&queue);
        assert!(queue.deny(id));
        assert_eq!(waiter.join().expect("join"), ApprovalOutcome::Denied);

        assert_eq!(
            queue.wait_for(run(), Duration::from_millis(20), || true),
            ApprovalOutcome::TimedOut
        );
        assert!(queue.pending().is_empty());
    }

    /// "Approve and remember" with a proof for a run with a pattern offer ends the wait
    /// with its own outcome, so the broker adds one approval to the pattern.
    #[test]
    fn approve_and_remember_with_an_offer() {
        let queue = Arc::new(ApprovalQueue::new());
        let offered = PendingRun {
            remember: Some(RememberOffer {
                pattern: "git log -n <number>".to_owned(),
                approvals: 1,
                needed: 3,
            }),
            ..run()
        };
        let waiter = {
            let queue = Arc::clone(&queue);
            std::thread::spawn(move || queue.wait_for(offered, Duration::from_secs(5), || true))
        };
        let id = wait_until_pending(&queue);
        let waiting = queue.pending()[0].clone();
        let proof = OwnerProof::issue_for_test(
            OwnerAction::ApproveAndRemember(waiting),
            [0; 32],
            Instant::now(),
        );
        assert_eq!(queue.approve(proof), Ok(()));
        assert!(!queue.deny(id), "the run no longer waits");
        assert_eq!(
            waiter.join().expect("join"),
            ApprovalOutcome::ApprovedAndRemembered
        );
    }

    #[test]
    fn invalidate_all_ends_waiting_runs() {
        let queue = Arc::new(ApprovalQueue::new());
        let waiter = {
            let queue = Arc::clone(&queue);
            std::thread::spawn(move || queue.wait_for(run(), Duration::from_secs(5), || true))
        };
        let id = wait_until_pending(&queue);
        let proof = proof_for(&queue, id);
        queue.invalidate_all();
        assert_eq!(waiter.join().expect("join"), ApprovalOutcome::Invalidated);
        assert!(queue.pending().is_empty());
        assert_eq!(
            queue.approve(proof),
            Err(ApprovalRefusal::NotWaiting),
            "the run no longer waits"
        );

        // An invalidated queue still takes new runs. A closed queue does not.
        let waiter = {
            let queue = Arc::clone(&queue);
            std::thread::spawn(move || queue.wait_for(run(), Duration::from_secs(5), || true))
        };
        wait_until_pending(&queue);
        queue.close();
        assert_eq!(waiter.join().expect("join"), ApprovalOutcome::Invalidated);
        assert_eq!(
            queue.wait_for(run(), Duration::from_secs(5), || true),
            ApprovalOutcome::Invalidated
        );
        assert!(queue.pending().is_empty());
    }

    /// An approval that the run did not use yet is not valid after `invalidate_all`.
    #[test]
    fn invalidate_all_voids_an_unused_approval() {
        let queue = Arc::new(ApprovalQueue::new());
        let (entered, in_check) = mpsc::channel();
        let (release, go) = mpsc::channel::<()>();
        let waiter = {
            let queue = Arc::clone(&queue);
            std::thread::spawn(move || {
                // Hold the waiter in its first vault check. The owner approves, and then
                // the queue is invalidated, before the waiter reads the decision.
                let first = AtomicBool::new(true);
                queue.wait_for(run(), Duration::from_secs(5), || {
                    if first.swap(false, Ordering::SeqCst) {
                        entered.send(()).expect("signal");
                        go.recv().expect("release");
                    }
                    true
                })
            })
        };
        in_check.recv().expect("waiter in check");
        let id = queue.pending()[0].id;
        assert_eq!(queue.approve(proof_for(&queue, id)), Ok(()));
        queue.invalidate_all();
        release.send(()).expect("release");
        assert_eq!(waiter.join().expect("join"), ApprovalOutcome::Invalidated);
    }

    /// A lock of the vault ends the wait, also after an approval that the run did not use.
    #[test]
    fn invalid_session_ends_the_wait() {
        let queue = Arc::new(ApprovalQueue::new());
        let valid = Arc::new(AtomicBool::new(true));
        let (entered, in_check) = mpsc::channel();
        let (release, go) = mpsc::channel::<()>();
        let waiter = {
            let queue = Arc::clone(&queue);
            let valid = Arc::clone(&valid);
            std::thread::spawn(move || {
                let first = AtomicBool::new(true);
                queue.wait_for(run(), Duration::from_secs(5), || {
                    if first.swap(false, Ordering::SeqCst) {
                        entered.send(()).expect("signal");
                        go.recv().expect("release");
                    }
                    valid.load(Ordering::SeqCst)
                })
            })
        };
        in_check.recv().expect("waiter in check");
        let id = queue.pending()[0].id;
        assert_eq!(queue.approve(proof_for(&queue, id)), Ok(()));
        valid.store(false, Ordering::SeqCst);
        release.send(()).expect("release");
        assert_eq!(waiter.join().expect("join"), ApprovalOutcome::Invalidated);

        // Without a decision, the check ends the wait in about one interval.
        let started = Instant::now();
        assert_eq!(
            queue.wait_for(run(), Duration::from_secs(5), || false),
            ApprovalOutcome::Invalidated
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(queue.pending().is_empty());
    }

    #[test]
    fn a_new_queue_does_not_reuse_ids() {
        let first = ApprovalQueue::new();
        let second = ApprovalQueue::new();
        let old = {
            let _ = first.wait_for(run(), Duration::from_millis(1), || true);
            first.state().next_id
        };
        let new = {
            let _ = second.wait_for(run(), Duration::from_millis(1), || true);
            second.state().next_id
        };
        assert_ne!(old, new, "run IDs start at a random value");
    }
}
