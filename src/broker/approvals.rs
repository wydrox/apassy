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
//!
//! A run with a first use (ADR 0024) also has a [`FirstUseOffer`] in the queue. The
//! offer stays out of [`PendingRun`], so the digest that an iPhone signs does not
//! change, and a phone can approve such a run only once. "Allow in this folder"
//! ([`OwnerAction::ApproveAndGrant`]) names the run and the offer exactly as the owner
//! saw them. The broker saves the grant after its second check.

mod owner_auth;

use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use crate::vault::{Declaration, SuggestedDeclaration};

pub use owner_auth::{
    CheckMethod, OwnerAction, OwnerAuthError, OwnerCheck, OwnerGate, OwnerProof, PROOF_LIFETIME,
    ProofRefusal, grant_declarations, grant_has_production, touch_id_detail,
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

/// True when `folder` is too wide for a lasting grant (ADR 0024): the root, the home
/// folder, a parent of the home folder, or a filesystem alias of one of them. Such
/// a folder gets "Allow once" only. The
/// card, the queue, and the broker all ask this one function. Without a usable `HOME`,
/// only the root is known to be broad.
pub fn folder_is_broad(folder: &str) -> bool {
    let home = std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .and_then(|home| std::fs::canonicalize(home).ok());
    folder_is_broad_with(Path::new(folder), home.as_deref())
}

/// A path for a card or a dialog: control and direction characters become `?`, and a
/// path longer than `max` characters keeps its start and its end around `…`. Only the
/// text on screen changes. A proof always names the exact path.
pub fn shown_path(path: &str, max: usize) -> String {
    let clean: Vec<char> = path
        .chars()
        .map(|c| {
            // Foundation's controlCharacters also contains Unicode format (Cf)
            // scalars. Keep display text acceptable to the native owner prompt.
            // Unicode 17: ucd/extracted/DerivedGeneralCategory.txt, category Cf.
            let hidden = c.is_control()
                || matches!(
                    c,
                    '\u{00AD}'
                        | '\u{0600}'..='\u{0605}'
                        | '\u{061C}'
                        | '\u{06DD}'
                        | '\u{070F}'
                        | '\u{0890}'..='\u{0891}'
                        | '\u{08E2}'
                        | '\u{180E}'
                        | '\u{200B}'..='\u{200F}'
                        | '\u{202A}'..='\u{202E}'
                        | '\u{2060}'..='\u{206F}'
                        | '\u{FEFF}'
                        | '\u{FFF9}'..='\u{FFFB}'
                        | '\u{110BD}'
                        | '\u{110CD}'
                        | '\u{13430}'..='\u{1343F}'
                        | '\u{1BCA0}'..='\u{1BCA3}'
                        | '\u{1D173}'..='\u{1D17A}'
                        | '\u{E0001}'
                        | '\u{E0020}'..='\u{E007F}'
                );
            if hidden { '?' } else { c }
        })
        .collect();
    if clean.len() <= max {
        return clean.into_iter().collect();
    }
    let keep = max.saturating_sub(1);
    let (head, tail) = (keep / 2, keep - keep / 2);
    let mut out: String = clean[..head].iter().collect();
    out.push('…');
    out.extend(&clean[clean.len() - tail..]);
    out
}

fn folder_is_broad_with(folder: &Path, home: Option<&Path>) -> bool {
    let canonical = std::fs::canonicalize(folder).ok();
    if [Some(folder), canonical.as_deref()]
        .into_iter()
        .flatten()
        .any(|folder| {
            folder.parent().is_none() || home.is_some_and(|home| home.starts_with(folder))
        })
    {
        return true;
    }
    let Some((home, home_metadata)) = home.and_then(|home| {
        std::fs::metadata(home)
            .ok()
            .map(|metadata| (home, metadata))
    }) else {
        return false;
    };
    // realpath does not resolve all filesystem aliases (for example macOS firmlinks
    // and /.nofollow). A folder aliases HOME or an ancestor if appending that
    // ancestor's relative path to HOME reaches the same directory identity.
    home.ancestors().any(|ancestor| {
        let relative_home = home.strip_prefix(ancestor).expect("ancestor of home");
        std::fs::metadata(folder.join(relative_home)).is_ok_and(|metadata| {
            metadata.dev() == home_metadata.dev() && metadata.ino() == home_metadata.ino()
        })
    })
}

/// A first use (ADR 0024): the items of a waiting run that the agent has no process
/// grant for. "Allow in this folder" gives a grant for each of them in `folder`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirstUseOffer {
    pub agent_id: u64,
    /// The folder of the grant: the nearest parent of the working directory with
    /// `.git`, or the working directory.
    pub folder: String,
    pub items: Vec<FirstUseItem>,
}

/// One item of a first use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirstUseItem {
    pub item_id: u64,
    pub name: String,
    /// The declaration of the item. `None`: the grant saves the declaration that the
    /// owner accepts on the card.
    pub declaration: Option<Declaration>,
}

/// A declaration that the owner accepted on the first-use card, for an item without one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirstUseDeclaration {
    pub item_id: u64,
    pub declaration: Declaration,
    pub provider: Option<String>,
    /// The form that Apassy suggested. The vault records whether the owner changed it.
    pub suggested: Option<SuggestedDeclaration>,
}

/// What "Allow in this folder" saves after the broker checks the run again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantChoice {
    pub folder: String,
    pub declarations: Vec<FirstUseDeclaration>,
}

/// The end of a wait: the outcome, the check that the owner did for an approval, and
/// for "Allow in this folder" what the broker saves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settled {
    pub outcome: ApprovalOutcome,
    pub method: Option<CheckMethod>,
    pub grant: Option<GrantChoice>,
}

impl Settled {
    fn ended(outcome: ApprovalOutcome) -> Self {
        Self {
            outcome,
            method: None,
            grant: None,
        }
    }
}

/// [`ApprovalQueue::wait_for_first_use`] refused the wait: a first use of the same
/// agent already waits (ADR 0024).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirstUseBusy;

/// The owner answer that a waiting run gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answer {
    Approve,
    /// Approve the run and add one approval to its pattern.
    ApproveAndRemember,
    /// Approve the run and give the agent access at first use (ADR 0024).
    ApproveAndGrant,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalOutcome {
    Approved,
    /// The owner approved with "Approve and remember".
    ApprovedAndRemembered,
    /// The owner approved a first use with "Allow in this folder" (ADR 0024).
    ApprovedAndGranted,
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
    /// "Allow in this folder" for a run without a first use, or for a folder that is too
    /// wide for a lasting grant (the root, the home folder, or a parent of it).
    NothingToGrant,
    /// The declarations of "Allow in this folder" do not match the first use: each
    /// item without a declaration needs exactly one.
    DeclarationsDoNotMatch,
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
            Self::NothingToGrant => {
                "This run cannot get access in a folder. Nothing was approved. Use \"Allow once\"."
            }
            Self::DeclarationsDoNotMatch => {
                "Each new credential needs one declaration. Nothing was approved. Review the request again."
            }
        }
    }
}

/// An answer with the check that the owner did for it. A denial has no check.
#[derive(Debug, Clone)]
struct Decision {
    answer: Answer,
    method: Option<CheckMethod>,
    grant: Option<GrantChoice>,
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
    /// The first-use offer of a waiting run (ADR 0024).
    offers: BTreeMap<u64, FirstUseOffer>,
    decisions: BTreeMap<u64, Decision>,
    /// When each waiting run started to wait. It is not part of the run, so the
    /// equality of two runs (and an owner proof for one) does not depend on it.
    waiting_since: BTreeMap<u64, Instant>,
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

    /// Ask the desktop app to repaint: a run waits, or an agent asked for access.
    pub(crate) fn notify_owner(&self) {
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

    /// Runs that wait for a decision, oldest first, with the time since each one started
    /// to wait. The iPhone inbox shows it as `waiting_seconds`.
    pub fn pending_with_age(&self) -> Vec<(PendingRun, Duration)> {
        let state = self.state();
        let now = Instant::now();
        state
            .pending
            .iter()
            .map(|run| {
                let age = state
                    .waiting_since
                    .get(&run.id)
                    .map_or(Duration::ZERO, |since| {
                        now.saturating_duration_since(*since)
                    });
                (run.clone(), age)
            })
            .collect()
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
            OwnerAction::ApproveAndGrant { .. } => Answer::ApproveAndGrant,
            _ => Answer::Approve,
        };
        let method = proof.method();
        let mut state = self.state();
        match state.pending.iter().find(|run| run.id == confirmed.id) {
            None => Err(ApprovalRefusal::NotWaiting),
            Some(waiting) if waiting != confirmed => Err(ApprovalRefusal::Changed),
            Some(waiting) if answer == Answer::ApproveAndRemember && waiting.remember.is_none() => {
                Err(ApprovalRefusal::NothingToRemember)
            }
            Some(_) => {
                let grant = match proof.action() {
                    OwnerAction::ApproveAndGrant {
                        offer,
                        declarations,
                        ..
                    } => Some(Self::grant_choice(
                        state.offers.get(&confirmed.id),
                        offer,
                        declarations,
                    )?),
                    _ => None,
                };
                Self::settle(&mut state, confirmed.id, answer, Some(method), grant);
                self.changed.notify_all();
                Ok(())
            }
        }
    }

    /// The grant of "Allow in this folder": the offer must be the waiting offer, and each
    /// item without a declaration needs exactly one declaration (ADR 0024).
    fn grant_choice(
        waiting: Option<&FirstUseOffer>,
        confirmed: &FirstUseOffer,
        declarations: &[FirstUseDeclaration],
    ) -> Result<GrantChoice, ApprovalRefusal> {
        let Some(waiting) = waiting else {
            return Err(ApprovalRefusal::NothingToGrant);
        };
        if waiting != confirmed {
            return Err(ApprovalRefusal::Changed);
        }
        // A crafted request cannot save a lasting grant for the root or the home folder.
        if folder_is_broad(&waiting.folder) {
            return Err(ApprovalRefusal::NothingToGrant);
        }
        let undeclared: Vec<u64> = waiting
            .items
            .iter()
            .filter(|item| item.declaration.is_none())
            .map(|item| item.item_id)
            .collect();
        let mut named: Vec<u64> = declarations.iter().map(|d| d.item_id).collect();
        named.sort_unstable();
        let mut expected = undeclared;
        expected.sort_unstable();
        if named != expected {
            return Err(ApprovalRefusal::DeclarationsDoNotMatch);
        }
        Ok(GrantChoice {
            folder: waiting.folder.clone(),
            declarations: declarations.to_vec(),
        })
    }

    /// The first-use offer of a waiting run, or `None` (ADR 0024).
    pub fn first_use(&self, id: u64) -> Option<FirstUseOffer> {
        self.state().offers.get(&id).cloned()
    }

    /// Deny a waiting run. A denial needs no owner check. Returns false when the run
    /// no longer waits.
    pub fn deny(&self, id: u64) -> bool {
        let mut state = self.state();
        if !state.pending.iter().any(|run| run.id == id) {
            return false;
        }
        Self::settle(&mut state, id, Answer::Deny, None, None);
        self.changed.notify_all();
        true
    }

    fn settle(
        state: &mut QueueState,
        id: u64,
        answer: Answer,
        method: Option<CheckMethod>,
        grant: Option<GrantChoice>,
    ) {
        state.pending.retain(|run| run.id != id);
        state.waiting_since.remove(&id);
        state.offers.remove(&id);
        state.decisions.insert(
            id,
            Decision {
                answer,
                method,
                grant,
            },
        );
    }

    /// Remove a run that ended without a decision: a timeout, or an invalid session.
    fn forget(state: &mut QueueState, id: u64) {
        state.pending.retain(|pending| pending.id != id);
        state.waiting_since.remove(&id);
        state.offers.remove(&id);
    }

    /// End every waiting run and every decision that a run did not use yet. The
    /// desktop app calls this when the owner locks the vault. The broker calls it
    /// when it stops.
    pub fn invalidate_all(&self) {
        let mut state = self.state();
        state.generation = state.generation.wrapping_add(1);
        state.pending.clear();
        state.waiting_since.clear();
        state.offers.clear();
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
        run: PendingRun,
        timeout: Duration,
        still_valid: impl Fn() -> bool,
    ) -> ApprovalOutcome {
        self.wait_for_decision(run, timeout, still_valid).0
    }

    /// Like [`Self::wait_for`], and also the check that the owner did for an approval:
    /// Touch ID, the passphrase, or the iPhone. The check is `None` for every other
    /// outcome. The activity log names it.
    pub fn wait_for_decision(
        &self,
        run: PendingRun,
        timeout: Duration,
        still_valid: impl Fn() -> bool,
    ) -> (ApprovalOutcome, Option<CheckMethod>) {
        let settled = match self.wait(run, None, timeout, still_valid) {
            Ok(settled) => settled,
            Err(FirstUseBusy) => Settled::ended(ApprovalOutcome::Invalidated),
        };
        (settled.outcome, settled.method)
    }

    /// Like [`Self::wait_for_decision`], for a run with a first use (ADR 0024). The
    /// owner can answer with "Allow in this folder"; then [`Settled::grant`] has what
    /// the broker saves. A first use of the same agent that already waits refuses the
    /// wait, so one agent cannot fill the queue with first uses.
    pub fn wait_for_first_use(
        &self,
        run: PendingRun,
        offer: FirstUseOffer,
        timeout: Duration,
        still_valid: impl Fn() -> bool,
    ) -> Result<Settled, FirstUseBusy> {
        self.wait(run, Some(offer), timeout, still_valid)
    }

    fn wait(
        &self,
        mut run: PendingRun,
        offer: Option<FirstUseOffer>,
        timeout: Duration,
        still_valid: impl Fn() -> bool,
    ) -> Result<Settled, FirstUseBusy> {
        let deadline = Instant::now() + timeout;
        let mut state = self.state();
        if state.closed {
            return Ok(Settled::ended(ApprovalOutcome::Invalidated));
        }
        if let Some(offer) = &offer
            && state
                .offers
                .values()
                .any(|waiting| waiting.agent_id == offer.agent_id)
        {
            return Err(FirstUseBusy);
        }
        state.next_id = state.next_id.wrapping_add(1);
        let id = state.next_id;
        let generation = state.generation;
        run.id = id;
        state.pending.push(run);
        state.waiting_since.insert(id, Instant::now());
        if let Some(offer) = offer {
            state.offers.insert(id, offer);
        }
        self.changed.notify_all();
        drop(state);
        self.notify_owner();
        loop {
            let mut state = self.state();
            if state.generation != generation {
                Self::forget(&mut state, id);
                state.decisions.remove(&id);
                return Ok(Settled::ended(ApprovalOutcome::Invalidated));
            }
            if let Some(decision) = state.decisions.remove(&id) {
                let outcome = match decision.answer {
                    Answer::Approve => ApprovalOutcome::Approved,
                    Answer::ApproveAndRemember => ApprovalOutcome::ApprovedAndRemembered,
                    Answer::ApproveAndGrant => ApprovalOutcome::ApprovedAndGranted,
                    Answer::Deny => ApprovalOutcome::Denied,
                };
                return Ok(Settled {
                    outcome,
                    method: decision.method,
                    grant: decision.grant,
                });
            }
            let now = Instant::now();
            if now >= deadline {
                Self::forget(&mut state, id);
                return Ok(Settled::ended(ApprovalOutcome::TimedOut));
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
                Self::forget(&mut state, id);
                state.decisions.remove(&id);
                return Ok(Settled::ended(ApprovalOutcome::Invalidated));
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

    /// ADR 0024: the root, the home folder, and its parents are broad. A project below
    /// the home folder, a sibling, and a folder elsewhere are not.
    #[test]
    fn a_lasting_grant_is_refused_for_the_root_the_home_folder_and_its_parents() {
        let home = Path::new("/Users/synthetic");
        for broad in ["/", "/Users", "/Users/synthetic"] {
            assert!(
                folder_is_broad_with(Path::new(broad), Some(home)),
                "{broad}"
            );
        }
        for narrow in [
            "/Users/synthetic/shop",
            "/Users/synthetic/shop/api",
            "/Users/other",
            "/tmp/shop",
        ] {
            assert!(
                !folder_is_broad_with(Path::new(narrow), Some(home)),
                "{narrow}"
            );
        }
        // Without a home folder only the root is known to be broad.
        assert!(folder_is_broad_with(Path::new("/"), None));
        assert!(!folder_is_broad_with(Path::new("/Users"), None));
        assert!(!folder_is_broad("/tmp/synthetic-not-the-home-folder"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_filesystem_aliases_of_home_and_its_ancestors_are_broad() {
        let Some(home) = std::env::var_os("HOME")
            .filter(|home| !home.is_empty())
            .and_then(|home| std::fs::canonicalize(home).ok())
        else {
            return;
        };
        let home_metadata = std::fs::metadata(&home).expect("home metadata");
        let relative_home = home.strip_prefix("/").expect("absolute home");
        for prefix in [Path::new("/.nofollow"), Path::new("/System/Volumes/Data")] {
            // Only exercise aliases present on this host. Read metadata alone; never
            // read or modify the real home directory's contents.
            let aliases_home =
                std::fs::metadata(prefix.join(relative_home)).is_ok_and(|metadata| {
                    metadata.dev() == home_metadata.dev() && metadata.ino() == home_metadata.ino()
                });
            if !aliases_home {
                continue;
            }
            for ancestor in home.ancestors() {
                let alias = prefix.join(ancestor.strip_prefix("/").expect("absolute ancestor"));
                assert!(
                    folder_is_broad_with(&alias, Some(&home)),
                    "{}",
                    alias.display()
                );
            }
        }
        let dir = tempfile::tempdir().expect("temp dir");
        let project = dir.path().join("project");
        std::fs::create_dir(&project).expect("project dir");
        let linked_project = dir.path().join("linked-project");
        std::os::unix::fs::symlink(&project, &linked_project).expect("project symlink");
        assert!(!folder_is_broad_with(&project, Some(&home)));
        assert!(!folder_is_broad_with(&linked_project, Some(&home)));
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

    /// A waiting run has an age, and the age is not part of the run: two reads of the
    /// same run are equal, and a proof for the run stays valid as the age grows.
    #[test]
    fn pending_with_age_reports_how_long_a_run_waits() {
        let queue = Arc::new(ApprovalQueue::new());
        assert!(queue.pending_with_age().is_empty());
        let waiter = start_waiter(&queue);
        let id = wait_until_pending(&queue);
        let first = queue.pending_with_age();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].0.id, id);
        assert!(first[0].1 < Duration::from_secs(5));
        // A run that started to wait 90 seconds ago.
        let since = Instant::now()
            .checked_sub(Duration::from_secs(90))
            .expect("old instant");
        queue.state().waiting_since.insert(id, since);
        let aged = queue.pending_with_age();
        assert!(aged[0].1 >= Duration::from_secs(90));
        assert!(aged[0].1 < Duration::from_secs(95));
        assert_eq!(aged[0].0, first[0].0, "the age is not part of the run");
        assert_eq!(queue.pending(), vec![first[0].0.clone()]);
        // The proof for the run works after it aged.
        assert_eq!(queue.approve(proof_for(&queue, id)), Ok(()));
        assert_eq!(waiter.join().expect("join"), ApprovalOutcome::Approved);
        assert!(queue.pending_with_age().is_empty());
        assert!(
            queue.state().waiting_since.is_empty(),
            "the age is dropped when the run settles"
        );
    }

    /// Every way that a wait ends drops its start time: a denial, a timeout, an invalid
    /// session, and an invalidation of the queue.
    #[test]
    fn the_start_time_is_dropped_when_a_run_ends() {
        let queue = Arc::new(ApprovalQueue::new());
        let waiter = start_waiter(&queue);
        let id = wait_until_pending(&queue);
        assert!(queue.deny(id));
        waiter.join().expect("join");
        assert!(queue.state().waiting_since.is_empty(), "denied");

        assert_eq!(
            queue.wait_for(run(), Duration::from_millis(20), || true),
            ApprovalOutcome::TimedOut
        );
        assert!(queue.state().waiting_since.is_empty(), "timed out");

        assert_eq!(
            queue.wait_for(run(), Duration::from_secs(5), || false),
            ApprovalOutcome::Invalidated
        );
        assert!(queue.state().waiting_since.is_empty(), "invalid session");

        let waiter = start_waiter(&queue);
        wait_until_pending(&queue);
        assert_eq!(queue.pending_with_age().len(), 1);
        queue.invalidate_all();
        assert_eq!(waiter.join().expect("join"), ApprovalOutcome::Invalidated);
        assert!(queue.state().waiting_since.is_empty(), "invalidated");
        assert!(queue.pending_with_age().is_empty());
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
#[test]
fn shown_paths_hide_format_characters_and_keep_printable_unicode() {
    assert_eq!(
        shown_path("/tmp/a\u{00AD}b\u{E0041}\u{206A}/界é🦀", usize::MAX),
        "/tmp/a?b??/界é🦀"
    );
    assert_eq!(
        shown_path("\u{0600}\u{0891}\u{180E}\u{1343F}\u{FFF9}", usize::MAX),
        "?????"
    );
}
