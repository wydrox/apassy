//! The asker (contract relay-questions-v1, section 12): the questions waiter of this Mac.
//!
//! Three threads, apart from the sync waiter:
//!
//! - The poster watches the approval queue (a wake from the queue notifier, and every
//!   [`QuestionsConfig::tick`]). When the open vault is unlocked and has a membership
//!   with the purpose `questions`, it seals each new waiting question with the current
//!   question key and posts it ([`QuestionsClient::post_question`]); a failure that can
//!   pass is tried again after 2, 4, 8, 16, 30, 30… seconds while the question waits.
//!   When a question ends on this Mac (an answer on the card or through the companion,
//!   the timeout, a lock, the broker stopping), it posts the settle, best effort.
//! - The reader long-polls the answers of the open questions and takes them in `id`
//!   order. It checks each answer (section 12.3); the first one that passes takes effect
//!   through the queue with a [`CheckMethod::Remote`] proof from the owner gate, or as a
//!   stricter answer, and the question settles. An answer that does not count gets a
//!   line in Activity, with the device and the reason and no value.
//! - The lister long-polls the questions of the other devices of the vault (section 13,
//!   `GET /v1/questions`), opens and checks each card ([`open_question`]), and keeps the
//!   open ones in the view ([`QuestionsView::remote`]): Decisions lists them next to the
//!   questions of this Mac. [`QuestionsWorker::answering`] gives what it takes to answer
//!   one from this Mac ([`RemoteAnswering::send`], signed with the relay key of this Mac,
//!   an approving answer only with a fresh owner check).
//!
//! The local card and the local-network companion are unchanged: the card shows at once,
//! and whichever answer the queue takes first counts. A lock drops the relay token and
//! ends the long poll; the open questions then expire on the relay. Each question keeps
//! the key that sealed it until it ends, so a rotation does not lose its answers.
//!
//! Lock order: the vault mutex, then the queue lock (as the owner thread). The worker
//! never holds its own state lock while it takes the vault, calls the gate, or calls
//! the relay.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, Weak};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::answer::{AnswerError, OpenedQuestion, answer_from_mac, open_question};
use super::client::{AnswerReceipt, AnswerRecord, MAX_WAIT, QuestionsClient, QuestionsError};
use super::envelope::{
    AnswerBody, Card, CardError, Choice, RemoteEnvironment, Sealed, SettleBody, SettleOutcome,
    TO_APPROVERS, TO_MEMBER, VERSION, answer_aad, card_aad, new_qid, settle_aad,
};
use crate::broker::SharedVault;
use crate::broker::approvals::{
    ApprovalOutcome, ApprovalQueue, ApprovalRefusal, CheckMethod, OwnerAction, OwnerAuthError,
    OwnerCheck, OwnerGate, OwnerProof, PendingRun, RunEnd, StricterAnswer, verify_remote_answer,
};
use crate::companion::digest::question_digest_v2_hex;
use crate::relay::membership::{questions_membership, this_device, this_device_removed};
use crate::sync::decode_b64u;
use crate::sync::relay_http::Cancel;
use crate::vault::ItemEventKind;
use crate::vault::usage::InteractionKind;
use crate::vault::{
    ActivityDecision, Environment, NewActivity, QuestionKey, TrustedDevice, TrustedDeviceKind,
    Vault, VaultErrorKind,
};

/// How long a question waits for the owner (`QUESTION_WAIT` of the broker).
pub const QUESTION_WAIT: Duration = Duration::from_secs(300);
/// The waits between two posts of a question that failed for a reason that can pass.
const RETRY_WAITS: [u64; 5] = [2, 4, 8, 16, 30];
/// With more than one open question, the reader asks for the answers of each this often.
const SHORT_POLL_EVERY: Duration = Duration::from_secs(2);
/// How often the poster reads the membership of the open vault again.
const MEMBERSHIP_EVERY: Duration = Duration::from_secs(2);
/// The most answered and refused lines that the view keeps.
const MAX_VIEW_LINES: usize = 20;
/// The operation of an Activity line about an answer through the relay.
pub const ACTIVITY_OPERATION: &str = "answer through the relay";
/// The relay lists at most this many questions in one answer (section 10.4).
const LIST_PAGE: usize = 100;
/// The owner removed this Mac from the questions (its key is in a removed row).
pub const REMOVED: &str = "This device was removed from questions. To answer and ask through the relay again, turn “Send questions through the relay” on again: it needs your confirmation and a new key.";
/// The vault has a questions membership on this Mac but no row of this Mac.
pub const NOT_REGISTERED: &str = "This Mac is not a device of the questions of this vault. Turn “Send questions through the relay” off and on again.";
/// `POST /v1/questions` or `GET /v1/questions` answered `404`: the relay predates the
/// questions (contract section 10).
pub const UNSUPPORTED: &str = "The relay does not support questions yet — update the relay.";
/// After a `404` of the questions routes, the loops ask the relay again this much later.
const UNSUPPORTED_WAIT: Duration = Duration::from_secs(5 * 60);
/// What the answering device shows after the relay took its answer: the protocol has no
/// receipts yet, so a refusal shows only as a run that does not go on.
pub const SENT: &str = "Sent. The Mac checks it; if the run does not continue within a minute, the answer was refused.";
/// The local note of a production question about a team credential (integrator
/// decision 1).
pub const TEAM_PRODUCTION: &str =
    "Remote answers for team production come with shared vaults; answer on this Mac.";
/// The shortest time between two list calls that brought nothing: a relay that does not
/// hold the long poll is not asked in a loop.
const LIST_AT_LEAST: Duration = Duration::from_secs(1);

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// The settings of the questions waiter.
#[derive(Debug, Clone)]
pub struct QuestionsConfig {
    /// How long a question waits: its `expires_at` is this long after it started to wait.
    pub question_wait: Duration,
    /// How often the poster looks at the queue without a wake.
    pub tick: Duration,
    /// The name of this Mac for its trusted device row.
    pub device_name: String,
}

impl Default for QuestionsConfig {
    fn default() -> Self {
        Self {
            question_wait: QUESTION_WAIT,
            tick: Duration::from_millis(250),
            device_name: crate::sync::device_name(),
        }
    }
}

/// An answer through the relay that took effect: for "Answered on DEVICE".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteAnswered {
    pub run_id: u64,
    pub agent: String,
    pub device_name: String,
    pub device_kind: TrustedDeviceKind,
    /// The answer kind (section 9.1), for example `approve_once`.
    pub kind: String,
    pub at: u64,
}

impl RemoteAnswered {
    /// "Answered on DEVICE".
    pub fn line(&self) -> String {
        format!("Answered on {}", self.device_name)
    }
}

/// An answer through the relay that did not count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteRefused {
    pub run_id: u64,
    pub device: String,
    pub reason: String,
    pub at: u64,
}

/// What the window shows of the questions through the relay.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuestionsView {
    /// The open vault sends its questions through the relay.
    pub on: bool,
    pub team_id: Option<String>,
    /// The waiting runs that are on the relay, with their `qid`.
    pub posted: BTreeMap<u64, String>,
    /// The waiting runs that stay on this Mac, with the reason.
    pub local_only: BTreeMap<u64, String>,
    /// The latest answers through the relay that took effect, oldest first.
    pub answered: Vec<RemoteAnswered>,
    /// The latest answers that did not count, oldest first.
    pub refused: Vec<RemoteRefused>,
    /// A problem of the relay for the window, in words.
    pub problem: Option<String>,
    /// The open questions of the other devices of the vault, opened and checked, the
    /// soonest end first.
    pub remote: Vec<RemoteQuestion>,
    /// The owner removed this Mac from the questions ([`REMOVED`]).
    pub removed: bool,
    /// The relay answered `404` to the questions routes ([`UNSUPPORTED`]); the loops
    /// wait some minutes before they ask it again.
    pub unsupported: bool,
}

/// A question of another device of the vault, opened and checked (section 13): it shows
/// in Decisions next to the questions of this Mac, "from ASKER".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteQuestion {
    /// The number of the question on this Mac, for the window.
    pub id: u64,
    pub question: OpenedQuestion,
    /// After an answer of this Mac: [`SENT`].
    pub sent: Option<String>,
}

impl RemoteQuestion {
    /// The name of the asking Mac, as its card names it.
    pub fn asker(&self) -> &str {
        &self.question.card.asker.name
    }

    /// When the question ends on the relay (Unix seconds).
    pub fn expires_at(&self) -> u64 {
        self.question.record.expires_at
    }
}

/// The questions of the other devices, as the lister keeps them.
#[derive(Default)]
struct Remote {
    /// The team of the list. Another team starts the list again.
    team_id: Option<String>,
    /// The last question sequence seen (section 10.4).
    since: u64,
    /// The number of the next new question.
    next_id: u64,
    /// The open questions, by `qid`.
    open: BTreeMap<String, RemoteQuestion>,
}

/// An answer of this Mac to a question of another device, ready to send on a thread of
/// its own ([`QuestionsWorker::answering`]). It holds the relay key of this Mac in memory
/// while it lives.
pub struct RemoteAnswering {
    id: u64,
    client: QuestionsClient,
    question: OpenedQuestion,
    /// The trusted device UUID of this Mac.
    by: String,
    keys: Vec<QuestionKey>,
    epoch: [u8; 32],
    shared: Weak<Shared>,
}

impl std::fmt::Debug for RemoteAnswering {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteAnswering")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl RemoteAnswering {
    /// The question as this Mac opened and checked it.
    pub fn question(&self) -> &OpenedQuestion {
        &self.question
    }

    /// Sign, seal, and post `choice` (section 13 step 3). An approving choice needs
    /// `proof` for `remote_owner_action` of this question and choice, in the vault
    /// session of this Mac; a stricter one needs none. It calls the relay: run it on a
    /// thread of its own. Success shows [`SENT`] on the question until
    /// the settle takes it from the list; "Already answered", "Expired", and "cannot
    /// answer" take it at once.
    pub fn send(
        &self,
        choice: Choice,
        proof: Option<OwnerProof>,
    ) -> Result<AnswerReceipt, AnswerError> {
        let result = answer_from_mac(
            &self.client,
            &self.question,
            &self.by,
            choice,
            unix_now(),
            &self.keys,
            proof,
            &self.epoch,
        );
        if let Some(shared) = self.shared.upgrade() {
            match &result {
                // No receipt yet: the asking Mac checks the answer, and only the run going
                // on (the settle) says that it counted.
                Ok(_) => shared.remote_sent(&self.question.record.qid, SENT.to_owned()),
                Err(
                    AnswerError::AlreadyAnswered | AnswerError::Expired | AnswerError::NotRouted,
                ) => {
                    shared.remote_gone(&self.question.record.qid);
                }
                Err(_) => {}
            }
        }
        result
    }
}

/// The session of the open vault: its relay client, its team, and this Mac.
#[derive(Clone)]
struct Active {
    client: QuestionsClient,
    team_id: String,
    path: PathBuf,
    epoch: [u8; 32],
    /// The trusted device of this Mac.
    me: TrustedDevice,
}

/// A waiting run that this Mac asks through the relay.
struct Asked {
    run_id: u64,
    agent: String,
    qid: String,
    /// The key that sealed the card. It stays until the question ends.
    key: QuestionKey,
    digest: String,
    to: &'static str,
    expires_at: u64,
    card: Sealed,
    posted: bool,
    next_try: Instant,
    tries: usize,
    last_answer: u64,
    /// The reader applies an answer of this question now.
    applying: bool,
    /// The queue ended the run while the reader applied an answer.
    ended: Option<RunEnd>,
    /// The relay says that the question is settled or expired: nothing more to read.
    finished: bool,
    /// The answers of this question that took effect: by device UUID, the `time` of
    /// each, in order. A device's next answer must have a later `time`, so a replayed or
    /// reordered answer never applies twice.
    applied: BTreeMap<String, Vec<(u64, &'static str)>>,
}

impl Asked {
    /// The `time` of the last answer of `device` that took effect.
    fn last_time(&self, device: &str) -> Option<u64> {
        self.applied
            .get(device)
            .and_then(|times| times.last())
            .map(|(time, _)| *time)
    }
}

/// The last change of the environment of a credential through the relay: the newest
/// declaration event of the credential after it, and the answer `time` that made it.
#[derive(Debug, Clone, Copy)]
struct EnvironmentMark {
    event_id: u64,
    time: u64,
}

#[derive(Default)]
struct State {
    active: Option<Active>,
    checked_at: Option<Instant>,
    asked: BTreeMap<u64, Asked>,
    local_only: BTreeMap<u64, String>,
    /// By credential: the last environment correction through the relay.
    environment: BTreeMap<u64, EnvironmentMark>,
    /// The relay answered `404` to the questions routes: no call before this time.
    unsupported_until: Option<Instant>,
    /// The Activity line of [`UNSUPPORTED`] was written for this team.
    unsupported_logged: Option<String>,
}

struct Shared {
    queue: Arc<ApprovalQueue>,
    vault: SharedVault,
    gate: OwnerGate,
    config: QuestionsConfig,
    stop: AtomicBool,
    /// Counts the wakes of the poster and the changes of the open questions.
    wakes: Mutex<u64>,
    woken: Condvar,
    state: Mutex<State>,
    /// Ends the long poll of the reader: a new question, a question that ended, a lock.
    poll: Mutex<Option<Arc<Cancel>>>,
    view: Mutex<QuestionsView>,
    on_change: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
    /// The questions of the other devices.
    remote: Mutex<Remote>,
}

/// The questions waiter of the app. It stops when dropped.
pub struct QuestionsWorker {
    shared: Arc<Shared>,
    threads: Vec<JoinHandle<()>>,
}

impl std::fmt::Debug for QuestionsWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuestionsWorker").finish_non_exhaustive()
    }
}

impl QuestionsWorker {
    /// Start the poster and the reader for the open vault in `vault` and the questions of
    /// `queue`. `gate` makes the proofs of the answers.
    pub fn start(
        queue: Arc<ApprovalQueue>,
        vault: SharedVault,
        gate: OwnerGate,
        config: QuestionsConfig,
    ) -> Self {
        let shared = Arc::new(Shared {
            queue,
            vault,
            gate,
            config,
            stop: AtomicBool::new(false),
            wakes: Mutex::new(0),
            woken: Condvar::new(),
            state: Mutex::new(State::default()),
            poll: Mutex::new(None),
            view: Mutex::new(QuestionsView::default()),
            on_change: Mutex::new(None),
            remote: Mutex::new(Remote::default()),
        });
        let mut threads = Vec::new();
        for (name, body) in [
            ("apassy-questions-post", poster as fn(&Shared)),
            ("apassy-questions-read", reader as fn(&Shared)),
            ("apassy-questions-list", lister as fn(&Shared)),
        ] {
            let worker = Arc::clone(&shared);
            if let Ok(handle) = std::thread::Builder::new()
                .name(name.to_owned())
                .spawn(move || body(&worker))
            {
                threads.push(handle);
            }
        }
        Self { shared, threads }
    }

    /// Look at the queue now: a run started to wait. The notification center calls it.
    pub fn wake(&self) {
        self.shared.wake();
    }

    /// A function that wakes the poster, for the notifier of the queue.
    pub fn waker(&self) -> impl Fn() + Send + Sync + 'static {
        let shared = Arc::downgrade(&self.shared);
        move || {
            if let Some(shared) = shared.upgrade() {
                shared.wake();
            }
        }
    }

    /// Run `on_change` when the view changes, so the window can repaint.
    pub fn set_on_change(&self, on_change: impl Fn() + Send + Sync + 'static) {
        *lock(&self.shared.on_change) = Some(Box::new(on_change));
    }

    /// A copy of what the window shows.
    pub fn view(&self) -> QuestionsView {
        lock(&self.shared.view).clone()
    }

    /// Drop the relay token and end the long poll now: the vault locked. The worker
    /// signs in again after the next unlock.
    pub fn forget(&self) {
        self.shared.forget();
    }

    /// What it takes to answer the remote question `id` of the view from this Mac: the
    /// relay client of the session, this Mac's trusted device, the question key, and the
    /// vault session. It reads the vault for a moment, with no network; the answer goes
    /// with [`RemoteAnswering::send`] on a thread of its own.
    pub fn answering(&self, id: u64) -> Result<RemoteAnswering, AnswerError> {
        self.shared.answering(&self.shared, id)
    }

    /// Put a remote question in the view as the lister does, for a test of the window.
    #[cfg(test)]
    pub(crate) fn insert_remote_for_test(&self, question: OpenedQuestion) -> u64 {
        let id = {
            let mut remote = lock(&self.shared.remote);
            remote.next_id += 1;
            let id = remote.next_id;
            remote.open.insert(
                question.record.qid.clone(),
                RemoteQuestion {
                    id,
                    question,
                    sent: None,
                },
            );
            id
        };
        self.shared.publish_remote();
        id
    }

    /// Stop the threads and wait for them.
    pub fn stop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        self.shared.forget();
        self.shared.wake();
        for handle in self.threads.drain(..) {
            let _ = handle.join();
        }
    }
}

impl Drop for QuestionsWorker {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The parts of an open question that the reader needs, copied out of the state.
struct Reading {
    run_id: u64,
    agent: String,
    qid: String,
    key: QuestionKey,
    to: &'static str,
    expires_at: u64,
    last_answer: u64,
}

/// What became of one answer.
enum Verdict {
    /// It did not count, with the reason for Activity.
    Refused { device: String, reason: String },
    /// It took effect and ends the question.
    Settled {
        outcome: SettleOutcome,
        device: TrustedDevice,
        kind: &'static str,
    },
    /// It took effect and the question still waits (a correction).
    Corrected,
    /// The run no longer waits: an answer on this Mac or through the companion came
    /// first. The processing of the question ends.
    Ended,
}

impl Shared {
    fn wake(&self) {
        *lock(&self.wakes) += 1;
        self.woken.notify_all();
    }

    /// Sleep up to `wait` or until a wake. False when the worker stops.
    fn sleep(&self, wait: Duration) -> bool {
        let wakes = lock(&self.wakes);
        let seen = *wakes;
        let _ = self
            .woken
            .wait_timeout_while(wakes, wait, |wakes| {
                *wakes == seen && !self.stop.load(Ordering::SeqCst)
            })
            .unwrap_or_else(PoisonError::into_inner);
        !self.stop.load(Ordering::SeqCst)
    }

    fn changed(&self) {
        if let Some(on_change) = lock(&self.on_change).as_ref() {
            on_change();
        }
    }

    /// End the long poll of the reader, so it plans again.
    fn end_poll(&self) {
        if let Some(cancel) = lock(&self.poll).take() {
            cancel.close();
        }
        self.wake();
    }

    /// The vault locked or changed: drop the client, the token, and the open questions.
    fn forget(&self) {
        let active = {
            let mut state = lock(&self.state);
            state.asked.clear();
            state.local_only.clear();
            state.environment.clear();
            state.checked_at = None;
            state.active.take()
        };
        if let Some(active) = active {
            active.client.close();
        }
        self.end_poll();
        self.forget_remote();
        let mut view = lock(&self.view);
        if view.on || !view.posted.is_empty() || !view.local_only.is_empty() {
            view.on = false;
            view.team_id = None;
            view.posted.clear();
            view.local_only.clear();
            drop(view);
            self.changed();
        }
    }

    /// The unlocked open vault, when it is the vault of `active`.
    fn vault_of<'a>(
        guard: &'a mut MutexGuard<'_, Option<Vault>>,
        active: &Active,
    ) -> Option<&'a mut Vault> {
        guard.as_mut().filter(|vault| {
            !vault.is_locked() && vault.path() == active.path && vault.epoch() == active.epoch
        })
    }

    // ---- The poster. ----

    /// Find the session of the open vault: `None` when it is locked or has no membership
    /// with the purpose `questions`. Reads the vault only every [`MEMBERSHIP_EVERY`] or
    /// after a lock, an unlock, or another vault.
    fn session(&self) -> Option<Active> {
        let (path, epoch) = {
            let guard = lock(&self.vault);
            match guard.as_ref() {
                Some(vault) if !vault.is_locked() => (vault.path().to_path_buf(), vault.epoch()),
                _ => return None,
            }
        };
        {
            let state = lock(&self.state);
            if let Some(active) = &state.active
                && active.path == path
                && active.epoch == epoch
                && state
                    .checked_at
                    .is_some_and(|at| at.elapsed() < MEMBERSHIP_EVERY)
            {
                return Some(active.clone());
            }
        }
        // The row of this Mac is written only when the owner turns the questions on
        // (`EnableRelayQuestions`); the waiter never writes one. A Mac without a live row
        // asks nothing through the relay, and a Mac whose key is in a removed row says so.
        let found = {
            let mut guard = lock(&self.vault);
            let vault = guard
                .as_mut()
                .filter(|vault| !vault.is_locked() && vault.path() == path)?;
            match questions_membership(vault).ok()? {
                None => Err(None),
                Some(membership) => match this_device(vault, &membership).ok()? {
                    Some(me) => {
                        if vault.question_key().ok()?.is_none() {
                            vault.ensure_question_key().ok()?;
                        }
                        Ok((membership, me))
                    }
                    None if this_device_removed(vault, &membership).unwrap_or(false) => {
                        Err(Some(REMOVED))
                    }
                    None => Err(Some(NOT_REGISTERED)),
                },
            }
        };
        let (membership, me) = match found {
            Ok(found) => found,
            Err(problem) => {
                self.stand_down(problem);
                return None;
            }
        };
        let mut state = lock(&self.state);
        state.checked_at = Some(Instant::now());
        if let Some(active) = &mut state.active
            && active.path == path
            && active.epoch == epoch
            && active.team_id == membership.team_id
        {
            active.me = me;
            return Some(active.clone());
        }
        drop(state);
        let client = QuestionsClient::from_membership(&membership).ok()?;
        let active = Active {
            client,
            team_id: membership.team_id.clone(),
            path,
            epoch,
            me,
        };
        let old = {
            let mut state = lock(&self.state);
            state.asked.clear();
            state.local_only.clear();
            state.active.replace(active.clone())
        };
        if let Some(old) = old {
            old.client.close();
        }
        let mut view = lock(&self.view);
        view.on = true;
        view.team_id = Some(active.team_id.clone());
        view.posted.clear();
        view.local_only.clear();
        view.problem = None;
        view.removed = false;
        view.unsupported = false;
        drop(view);
        self.changed();
        Some(active)
    }

    /// The vault has a questions membership but this Mac may not ask through it: it was
    /// removed, or it has no row. The session goes, and the view says why.
    /// `None`: the questions are off for the vault.
    fn stand_down(&self, problem: Option<&str>) {
        if lock(&self.state).active.is_some() {
            self.forget();
        }
        let mut view = lock(&self.view);
        let removed = problem == Some(REMOVED);
        let known = [Some(REMOVED), Some(NOT_REGISTERED)].contains(&view.problem.as_deref());
        let problem = match problem {
            Some(problem) => Some(problem.to_owned()),
            // Off: a problem of this kind goes; another one (of the relay) stays.
            None if known => None,
            None => view.problem.clone(),
        };
        if view.problem != problem || view.removed != removed {
            view.problem = problem;
            view.removed = removed;
            drop(view);
            self.changed();
        }
    }

    /// One step of the poster.
    fn post_step(&self) {
        // The waiting runs first, then the ends: a run that ends between the two calls
        // is in both, and its end wins.
        let pending = self.queue.pending_with_age();
        let ended = self.queue.take_ended();
        let Some(active) = self.session() else {
            if lock(&self.state).active.is_some() {
                self.forget();
            }
            return;
        };
        let ended_ids: Vec<u64> = ended.iter().map(|end| end.id).collect();
        let pending: Vec<(PendingRun, Duration)> = pending
            .into_iter()
            .filter(|(run, _)| !ended_ids.contains(&run.id))
            .collect();
        // Questions that ended on this Mac: settle them on the relay.
        for end in ended {
            let asked = {
                let mut state = lock(&self.state);
                state.local_only.remove(&end.id);
                match state.asked.get_mut(&end.id) {
                    Some(asked) if asked.applying => {
                        asked.ended = Some(end);
                        None
                    }
                    Some(_) => state.asked.remove(&end.id),
                    None => None,
                }
            };
            if let Some(asked) = asked {
                self.end_poll();
                if asked.posted {
                    self.settle_local(&active, &asked, end);
                }
            }
        }
        // A question that left the queue without an end that this worker saw.
        let gone: Vec<Asked> = {
            let mut state = lock(&self.state);
            let ids: Vec<u64> = state
                .asked
                .iter()
                .filter(|(id, asked)| {
                    !asked.applying && !pending.iter().any(|(run, _)| run.id == **id)
                })
                .map(|(id, _)| *id)
                .collect();
            state
                .local_only
                .retain(|id, _| pending.iter().any(|(run, _)| run.id == *id));
            ids.iter().filter_map(|id| state.asked.remove(id)).collect()
        };
        for asked in gone {
            self.end_poll();
            if asked.posted {
                self.settle(&active, &asked, SettleOutcome::Invalidated, None, None);
            }
        }
        for (run, age) in pending {
            enum Next {
                Ask,
                Retry,
                Replace,
                Nothing,
            }
            let next = {
                let state = lock(&self.state);
                if state.local_only.contains_key(&run.id) {
                    Next::Nothing
                } else {
                    match state.asked.get(&run.id) {
                        None => Next::Ask,
                        Some(asked) if asked.applying => Next::Nothing,
                        Some(asked)
                            if asked.posted && asked.digest != question_digest_v2_hex(&run) =>
                        {
                            Next::Replace
                        }
                        Some(asked) if !asked.posted && Instant::now() >= asked.next_try => {
                            Next::Retry
                        }
                        Some(_) => Next::Nothing,
                    }
                }
            };
            match next {
                Next::Ask => self.ask(&active, &run, age, None),
                Next::Retry => self.post(&active, run.id),
                Next::Replace => {
                    let old = lock(&self.state).asked.remove(&run.id);
                    if let Some(old) = old {
                        self.ask(&active, &run, age, Some(old));
                    }
                }
                Next::Nothing => {}
            }
        }
        self.publish();
    }

    /// Copy the open questions to the view.
    fn publish(&self) {
        let (posted, local_only) = {
            let state = lock(&self.state);
            (
                state
                    .asked
                    .iter()
                    .filter(|(_, asked)| asked.posted)
                    .map(|(id, asked)| (*id, asked.qid.clone()))
                    .collect::<BTreeMap<_, _>>(),
                state.local_only.clone(),
            )
        };
        let mut view = lock(&self.view);
        if view.posted != posted || view.local_only != local_only {
            view.posted = posted;
            view.local_only = local_only;
            drop(view);
            self.changed();
        }
    }

    /// Keep `run` on this Mac only, with `why` in Activity and on the card.
    fn keep_local(&self, active: &Active, run: &PendingRun, why: &str) {
        lock(&self.state).local_only.insert(run.id, why.to_owned());
        self.activity(active, &run.agent, why);
    }

    /// Ask `run` through the relay (section 12.1): build and seal its card, then post it.
    /// `replaces` is the question of the same run with another digest: it settles as
    /// `replaced`, and the new one keeps the rest of its expiry.
    fn ask(&self, active: &Active, run: &PendingRun, age: Duration, replaces: Option<Asked>) {
        let now = unix_now();
        let expires_at = match &replaces {
            Some(old) => old.expires_at,
            None => now
                .saturating_sub(age.as_secs())
                .saturating_add(self.config.question_wait.as_secs()),
        };
        // The relay takes an expiry in (now + 10, now + 600].
        if expires_at <= now + 10 {
            lock(&self.state).local_only.insert(
                run.id,
                "The question ends too soon for your other devices.".to_owned(),
            );
            return;
        }
        let (key, team_item) = {
            let mut guard = lock(&self.vault);
            let Some(vault) = Self::vault_of(&mut guard, active) else {
                return;
            };
            let key = vault.question_key().ok().flatten();
            let team_item = run
                .question
                .item_ids
                .iter()
                .any(|item| vault.item_home(*item).is_ok_and(|home| home.is_some()));
            (key, team_item)
        };
        let Some(key) = key else {
            return;
        };
        // Until shared vaults give the approvers the key (integrator decision 1), a
        // production question about a team item stays on this Mac.
        if team_item && run.question.production {
            self.keep_local(active, run, TEAM_PRODUCTION);
            return;
        }
        // A relay without the questions routes: the question stays here until the wait
        // after the `404` ends.
        if self.unsupported_now() {
            lock(&self.state)
                .local_only
                .insert(run.id, UNSUPPORTED.to_owned());
            return;
        }
        let Some(qid) = new_qid() else {
            return;
        };
        let card = Card::from_run(&qid, &active.me.uuid, &active.me.name, now, run);
        let plaintext = match card.to_plaintext() {
            Ok(plaintext) => plaintext,
            Err(CardError::TooLong | CardError::Unreadable) => {
                self.keep_local(
                    active,
                    run,
                    "This question is too long for your other devices. Answer it on this Mac.",
                );
                return;
            }
        };
        let to = TO_MEMBER;
        let aad = card_aad(&active.team_id, &qid, &key.key_id(), to, expires_at);
        let Some(sealed) = Sealed::new(&key, &aad, &plaintext) else {
            return;
        };
        if let Some(old) = &replaces {
            self.settle(active, old, SettleOutcome::Replaced, None, Some(&qid));
        }
        lock(&self.state).asked.insert(
            run.id,
            Asked {
                run_id: run.id,
                agent: run.agent.clone(),
                qid,
                key,
                digest: card.digest,
                to,
                expires_at,
                card: sealed,
                posted: false,
                next_try: Instant::now(),
                tries: 0,
                last_answer: 0,
                applying: false,
                ended: None,
                finished: false,
                applied: BTreeMap::new(),
            },
        );
        self.post(active, run.id);
    }

    /// Post the card of the question of `run_id`, or plan the next try.
    fn post(&self, active: &Active, run_id: u64) {
        let Some((qid, expires_at, card, to, agent)) =
            lock(&self.state).asked.get(&run_id).map(|asked| {
                (
                    asked.qid.clone(),
                    asked.expires_at,
                    asked.card.clone(),
                    asked.to,
                    asked.agent.clone(),
                )
            })
        else {
            return;
        };
        let result = active.client.post_question(&qid, to, expires_at, &card);
        // A retry of a post that landed gets `409 conflict`: the question is posted.
        let posted = match &result {
            Ok(_) => true,
            Err(error) => error.code() == Some("conflict"),
        };
        let mut state = lock(&self.state);
        let Some(asked) = state.asked.get_mut(&run_id) else {
            return;
        };
        if posted {
            asked.posted = true;
            state.unsupported_until = None;
            drop(state);
            {
                let mut view = lock(&self.view);
                view.problem = None;
                view.unsupported = false;
            }
            self.end_poll();
            return;
        }
        let Err(error) = result else {
            return;
        };
        if error.status() == Some(404) {
            state.asked.remove(&run_id);
            state.local_only.insert(run_id, UNSUPPORTED.to_owned());
            drop(state);
            self.mark_unsupported(active, &agent);
            return;
        }
        if error.can_pass() {
            let wait = RETRY_WAITS[asked.tries.min(RETRY_WAITS.len() - 1)];
            asked.tries += 1;
            asked.next_try = Instant::now() + Duration::from_secs(wait);
            drop(state);
            lock(&self.view).problem =
                Some("The relay does not answer. Questions wait on this Mac.".to_owned());
            return;
        }
        state.asked.remove(&run_id);
        let why = match error.code() {
            // The relay counts the open questions of the team, of this Mac, and of the
            // member, and the questions of the last hour; its message names the limit.
            Some("too_many_questions") => {
                "The relay has too many open questions of this Mac or this vault. Answer it on this Mac."
            }
            Some("payload_too_large") => {
                "This question is too long for your other devices. Answer it on this Mac."
            }
            _ if matches!(error, QuestionsError::Removed) => {
                "The relay refused this Mac. Answer the question on this Mac."
            }
            _ => "The relay did not take this question. Answer it on this Mac.",
        };
        state.local_only.insert(run_id, why.to_owned());
        drop(state);
        self.activity(active, &agent, why);
    }

    /// Whether the loops wait after a `404` of the questions routes.
    fn unsupported_now(&self) -> bool {
        lock(&self.state)
            .unsupported_until
            .is_some_and(|until| Instant::now() < until)
    }

    /// The relay answered `404` to `POST` or `GET /v1/questions`: it predates the
    /// questions. The loops wait [`UNSUPPORTED_WAIT`], Settings says so, and Activity says
    /// it once for the team.
    fn mark_unsupported(&self, active: &Active, agent: &str) {
        let first = {
            let mut state = lock(&self.state);
            state.unsupported_until = Some(Instant::now() + UNSUPPORTED_WAIT);
            let first = state.unsupported_logged.as_deref() != Some(active.team_id.as_str());
            state.unsupported_logged = Some(active.team_id.clone());
            first
        };
        {
            let mut view = lock(&self.view);
            view.unsupported = true;
            view.problem = Some(UNSUPPORTED.to_owned());
        }
        if first {
            self.activity(active, agent, UNSUPPORTED);
        }
        self.changed();
    }

    /// Settle a question that ended on this Mac with `end`.
    fn settle_local(&self, active: &Active, asked: &Asked, end: RunEnd) {
        let outcome = match end.outcome {
            ApprovalOutcome::Approved
            | ApprovalOutcome::ApprovedAndRemembered
            | ApprovalOutcome::ApprovedAndGranted => SettleOutcome::Approved,
            ApprovalOutcome::Denied => SettleOutcome::Denied,
            ApprovalOutcome::TimedOut => SettleOutcome::TimedOut,
            ApprovalOutcome::Invalidated => SettleOutcome::Invalidated,
        };
        let by = match outcome {
            SettleOutcome::Approved | SettleOutcome::Denied => {
                let kind = if end.method == Some(CheckMethod::Companion) {
                    "iphone"
                } else {
                    "mac"
                };
                Some((&active.me, kind))
            }
            _ => None,
        };
        self.settle(active, asked, outcome, by, None);
    }

    /// Post the settle of `asked`, best effort.
    fn settle(
        &self,
        active: &Active,
        asked: &Asked,
        outcome: SettleOutcome,
        by: Option<(&TrustedDevice, &str)>,
        replaced_by: Option<&str>,
    ) {
        self.settle_with(active, asked, outcome, by, None, replaced_by);
    }

    fn settle_with(
        &self,
        active: &Active,
        asked: &Asked,
        outcome: SettleOutcome,
        by: Option<(&TrustedDevice, &str)>,
        kind: Option<&str>,
        replaced_by: Option<&str>,
    ) {
        let body = SettleBody {
            v: VERSION,
            qid: asked.qid.clone(),
            outcome: outcome.as_str().to_owned(),
            answered_by: by.map(|(device, _)| device.uuid.clone()),
            device_name: by.map(|(device, _)| device.name.clone()),
            device_kind: by.map(|(_, kind)| kind.to_owned()),
            kind: kind.map(str::to_owned),
            at: unix_now(),
            replaced_by: replaced_by.map(str::to_owned),
        };
        let Some(plaintext) = body.to_plaintext() else {
            return;
        };
        let aad = settle_aad(&active.team_id, &asked.qid, &asked.key.key_id());
        if let Some(sealed) = Sealed::new(&asked.key, &aad, &plaintext) {
            let _ = active.client.settle(&asked.qid, &sealed);
        }
    }

    /// An Activity line without values: the agent and the reason.
    fn activity(&self, active: &Active, agent: &str, reason: &str) {
        let mut guard = lock(&self.vault);
        if let Some(vault) = Self::vault_of(&mut guard, active) {
            let _ = vault.record_activity(&NewActivity {
                agent_id: None,
                agent_name: agent.to_owned(),
                item_id: None,
                operation: ACTIVITY_OPERATION.to_owned(),
                decision: ActivityDecision::Error,
                reason: reason.to_owned(),
            });
        }
    }

    // ---- The reader. ----

    /// The open questions on the relay, and the session.
    fn readings(&self) -> Option<(Active, Vec<Reading>)> {
        let state = lock(&self.state);
        let active = state.active.clone()?;
        let readings = state
            .asked
            .values()
            .filter(|asked| asked.posted && !asked.applying && !asked.finished)
            .map(|asked| Reading {
                run_id: asked.run_id,
                agent: asked.agent.clone(),
                qid: asked.qid.clone(),
                key: asked.key.clone(),
                to: asked.to,
                expires_at: asked.expires_at,
                last_answer: asked.last_answer,
            })
            .collect();
        Some((active, readings))
    }

    /// One step of the reader.
    fn read_step(&self) {
        let Some((active, readings)) = self.readings() else {
            self.sleep(Duration::from_secs(1));
            return;
        };
        match readings.as_slice() {
            [] => {
                self.sleep(Duration::from_secs(1));
            }
            [one] => {
                let cancel = Arc::new(Cancel::default());
                *lock(&self.poll) = Some(Arc::clone(&cancel));
                let left = one.expires_at.saturating_sub(unix_now()).max(1);
                let wait = Duration::from_secs(left).min(super::client::MAX_WAIT);
                let result =
                    active
                        .client
                        .answers_with(&one.qid, one.last_answer, wait, Some(&cancel));
                {
                    let mut poll = lock(&self.poll);
                    if poll.as_ref().is_some_and(|held| Arc::ptr_eq(held, &cancel)) {
                        *poll = None;
                    }
                }
                // A poll that the poster ended: plan again at once.
                if result.is_err() && cancel.is_closed() {
                    return;
                }
                self.take_answers(&active, one, result);
            }
            many => {
                for reading in many {
                    let result =
                        active
                            .client
                            .answers(&reading.qid, reading.last_answer, Duration::ZERO);
                    self.take_answers(&active, reading, result);
                }
                self.sleep(SHORT_POLL_EVERY);
            }
        }
    }

    fn take_answers(
        &self,
        active: &Active,
        reading: &Reading,
        result: Result<super::client::AnswerList, QuestionsError>,
    ) {
        let list = match result {
            Ok(list) => list,
            // The relay forgot the question (it ended long ago): an end, not a failure.
            Err(error) if error.status() == Some(404) => {
                let mut state = lock(&self.state);
                if let Some(asked) = state.asked.get_mut(&reading.run_id)
                    && asked.qid == reading.qid
                {
                    asked.finished = true;
                }
                return;
            }
            Err(error) => {
                if !matches!(error, QuestionsError::Closed) && !self.stop.load(Ordering::SeqCst) {
                    self.sleep(Duration::from_secs(2));
                }
                return;
            }
        };
        let mut answers = list.answers;
        answers.sort_by_key(|answer| answer.id);
        for answer in answers
            .iter()
            .filter(|answer| answer.id > reading.last_answer)
        {
            {
                let mut state = lock(&self.state);
                match state.asked.get_mut(&reading.run_id) {
                    Some(asked) if asked.qid == reading.qid => {
                        asked.last_answer = answer.id;
                        asked.applying = true;
                    }
                    _ => return,
                }
            }
            let verdict = self.judge(active, reading, answer);
            if self.after_verdict(active, reading, verdict) {
                return;
            }
        }
        if list.state != "open" {
            // Expired or settled on the relay: nothing more to read.
            let mut state = lock(&self.state);
            if let Some(asked) = state.asked.get_mut(&reading.run_id)
                && asked.qid == reading.qid
            {
                asked.finished = true;
            }
        }
    }

    /// Act on a verdict. True when the question ended.
    fn after_verdict(&self, active: &Active, reading: &Reading, verdict: Verdict) -> bool {
        match verdict {
            Verdict::Refused { device, reason } => {
                self.done_applying(reading);
                self.activity(
                    active,
                    &reading.agent,
                    &format!("An answer from {device} did not count: {reason}."),
                );
                let mut view = lock(&self.view);
                push_line(
                    &mut view.refused,
                    RemoteRefused {
                        run_id: reading.run_id,
                        device,
                        reason,
                        at: unix_now(),
                    },
                );
                drop(view);
                self.changed();
                false
            }
            Verdict::Corrected => {
                self.done_applying(reading);
                false
            }
            Verdict::Settled {
                outcome,
                device,
                kind,
            } => {
                let asked = lock(&self.state).asked.remove(&reading.run_id);
                if let Some(asked) = asked {
                    self.settle_with(
                        active,
                        &asked,
                        outcome,
                        Some((&device, device.kind.as_str())),
                        Some(kind),
                        None,
                    );
                }
                let mut view = lock(&self.view);
                push_line(
                    &mut view.answered,
                    RemoteAnswered {
                        run_id: reading.run_id,
                        agent: reading.agent.clone(),
                        device_name: device.name.clone(),
                        device_kind: device.kind,
                        kind: kind.to_owned(),
                        at: unix_now(),
                    },
                );
                view.posted.remove(&reading.run_id);
                drop(view);
                self.changed();
                true
            }
            Verdict::Ended => {
                // The queue ended the run another way. Settle with that end when the
                // poster gave it; else the poster settles when it sees it.
                let ended = {
                    let mut state = lock(&self.state);
                    match state.asked.get_mut(&reading.run_id) {
                        Some(asked) if asked.ended.is_some() => {
                            let end = asked.ended;
                            state.asked.remove(&reading.run_id).zip(end)
                        }
                        Some(asked) => {
                            asked.applying = false;
                            None
                        }
                        None => None,
                    }
                };
                if let Some((asked, end)) = ended {
                    self.settle_local(active, &asked, end);
                }
                true
            }
        }
    }

    /// The reader is done with an answer that did not end the question. When the queue
    /// ended the run meanwhile, settle it with that end.
    fn done_applying(&self, reading: &Reading) {
        let ended = {
            let mut state = lock(&self.state);
            match state.asked.get_mut(&reading.run_id) {
                Some(asked) => {
                    asked.applying = false;
                    if asked.ended.is_some() {
                        let end = asked.ended;
                        state.asked.remove(&reading.run_id).zip(end)
                    } else {
                        None
                    }
                }
                None => None,
            }
        };
        if let Some((asked, end)) = ended {
            let active = lock(&self.state).active.clone();
            if let Some(active) = active {
                self.settle_local(&active, &asked, end);
            }
        }
    }

    /// Check one answer (section 12.3) and apply it when it passes.
    fn judge(&self, active: &Active, reading: &Reading, record: &AnswerRecord) -> Verdict {
        let unknown = format!("device {}", record.device_id);
        let refuse = |device: &str, reason: &str| Verdict::Refused {
            device: device.to_owned(),
            reason: reason.to_owned(),
        };
        // 1. It opens with the key of the question and the stamped device number.
        let aad = answer_aad(
            &active.team_id,
            &reading.qid,
            &reading.key.key_id(),
            record.device_id,
        );
        let Some(plaintext) = record.sealed().open(&reading.key, &aad) else {
            return refuse(&unknown, "it could not be read");
        };
        // 2. The fields of its kind, `v` 1, and this `qid`.
        let parsed = AnswerBody::parse(&plaintext).and_then(|body| {
            let choice = Choice::from_body(&body)?;
            let signature = decode_b64u(&body.signature)?;
            (body.qid == reading.qid).then_some((body, choice, signature))
        });
        let Some((body, choice, signature)) = parsed else {
            return refuse(&unknown, "it has a bad form");
        };
        // 3. A live trusted device with the stamped number; the run as it waits now.
        let (device, run) = {
            let mut guard = lock(&self.vault);
            let Some(vault) = Self::vault_of(&mut guard, active) else {
                return Verdict::Ended;
            };
            let device = vault.trusted_device(&body.by).ok().flatten();
            let run = self
                .queue
                .pending()
                .into_iter()
                .find(|run| run.id == reading.run_id);
            (device, run)
        };
        let Some(run) = run else {
            return Verdict::Ended;
        };
        let Some(device) = device.filter(|device| {
            device
                .relay_devices
                .get(&active.team_id)
                .is_none_or(|id| *id == record.device_id)
        }) else {
            return refuse(&unknown, "the device is not a device of this vault");
        };
        let name = device.name.clone();
        // 4. The question offers it, with matching fields.
        if !choice.valid_for(&run.question) {
            return refuse(&name, "the question does not offer this answer");
        }
        // 5. The digest of the run as it waits now.
        if body.digest != question_digest_v2_hex(&run) {
            return refuse(&name, "the request changed");
        }
        // 6. A team production question counts an approval of an approver only.
        let approving = matches!(
            choice,
            Choice::ApproveOnce | Choice::ApproveInProject { .. } | Choice::AllowProduction { .. }
        );
        if reading.to == TO_APPROVERS
            && approving
            && !matches!(record.role.as_str(), "owner" | "manager")
        {
            return refuse(&name, "an owner or a manager of the team must answer");
        }
        // 7. The owner check, or the signature of a stricter answer.
        let proof = if choice.needs_owner_check() {
            let Some(action) = super::answer::local_action(&run, &choice) else {
                return refuse(&name, "the question does not offer this answer");
            };
            let correction_of =
                matches!(choice, Choice::CorrectEnvironment { .. }).then(|| Box::new(run.clone()));
            let check = OwnerCheck::Remote {
                device_uuid: body.by.clone(),
                team_id: active.team_id.clone(),
                qid: reading.qid.clone(),
                time: body.time,
                signature,
                correction_of,
            };
            match self.gate.authorize(action, check) {
                Ok(proof) => Some(proof),
                Err(error) => return refuse(&name, remote_reason(&error)),
            }
        } else {
            if let Err(error) = verify_remote_answer(
                &device,
                &active.team_id,
                &reading.qid,
                &choice,
                &body.digest,
                body.time,
                &signature,
                unix_now(),
            ) {
                return refuse(&name, remote_reason(&error));
            }
            None
        };
        // A replayed or reordered answer: the answers of one device to one question take
        // effect in the order of their signed `time`, each once.
        let last = lock(&self.state)
            .asked
            .get(&reading.run_id)
            .filter(|asked| asked.qid == reading.qid)
            .and_then(|asked| asked.last_time(&body.by));
        if last.is_some_and(|last| body.time <= last) {
            return refuse(
                &name,
                "it is not newer than an answer of this device that counted",
            );
        }
        // 8. The queue takes it.
        let kind = choice.kind();
        let verdict = self.apply(active, &run, choice, proof, device, body.time);
        if matches!(verdict, Verdict::Settled { .. } | Verdict::Corrected) {
            let mut state = lock(&self.state);
            if let Some(asked) = state
                .asked
                .get_mut(&reading.run_id)
                .filter(|asked| asked.qid == reading.qid)
            {
                asked
                    .applied
                    .entry(body.by.clone())
                    .or_default()
                    .push((body.time, kind));
            }
        }
        verdict
    }

    fn apply(
        &self,
        active: &Active,
        run: &PendingRun,
        choice: Choice,
        proof: Option<crate::broker::approvals::OwnerProof>,
        device: TrustedDevice,
        time: u64,
    ) -> Verdict {
        let name = device.name.clone();
        let kind = choice.kind();
        let settled = |outcome| Verdict::Settled {
            outcome,
            device: device.clone(),
            kind,
        };
        match choice {
            Choice::ApproveOnce
            | Choice::ApproveInProject { .. }
            | Choice::AllowProduction { .. } => {
                let Some(proof) = proof else {
                    return Verdict::Refused {
                        device: name,
                        reason: "the owner check did not pass".to_owned(),
                    };
                };
                match self.queue.approve(proof) {
                    Ok(()) => settled(SettleOutcome::Approved),
                    Err(ApprovalRefusal::NotWaiting | ApprovalRefusal::Changed) => Verdict::Ended,
                    Err(refusal) => Verdict::Refused {
                        device: name,
                        reason: refusal.message().trim_end_matches('.').to_owned(),
                    },
                }
            }
            Choice::Deny => {
                if self.queue.deny(run.id) {
                    settled(SettleOutcome::Denied)
                } else {
                    Verdict::Ended
                }
            }
            Choice::NeverForAgent | Choice::AlwaysAskForAgent | Choice::Disconnect => {
                let stricter = match choice {
                    Choice::NeverForAgent => StricterAnswer::NeverForAgent,
                    Choice::AlwaysAskForAgent => StricterAnswer::AlwaysAskForAgent,
                    _ => StricterAnswer::Disconnect,
                };
                let mut guard = lock(&self.vault);
                let Some(vault) = Self::vault_of(&mut guard, active) else {
                    return Verdict::Ended;
                };
                match self.queue.deny_stricter(run.id, stricter, vault) {
                    Ok(true) => settled(SettleOutcome::Denied),
                    Ok(false) => Verdict::Ended,
                    Err(error) if error.kind() == VaultErrorKind::InvalidInput => {
                        drop(guard);
                        if self.queue.deny(run.id) {
                            settled(SettleOutcome::Denied)
                        } else {
                            Verdict::Ended
                        }
                    }
                    // The run is denied; the vault change failed.
                    Err(_) => settled(SettleOutcome::Denied),
                }
            }
            Choice::CorrectEnvironment {
                item_id,
                environment,
            } => {
                // The state lock is never held while the vault is taken.
                let mark = lock(&self.state).environment.get(&item_id).copied();
                let mut guard = lock(&self.vault);
                let Some(vault) = Self::vault_of(&mut guard, active) else {
                    return Verdict::Ended;
                };
                // A correction counts only when it is newer than the last change of the
                // environment of the credential: after a correction through the relay,
                // newer than the answer that made it; after any other change, newer
                // than the change on this Mac's clock.
                let newest = newest_declaration(vault, item_id);
                let stale = match (newest, mark) {
                    (Some((id, _)), Some(mark)) if id == mark.event_id => time <= mark.time,
                    (Some((_, at)), _) => time < at,
                    (None, Some(mark)) => time <= mark.time,
                    (None, None) => false,
                };
                if stale {
                    return Verdict::Refused {
                        device: name,
                        reason: "the environment of the credential changed after this answer"
                            .to_owned(),
                    };
                }
                let done = match environment {
                    RemoteEnvironment::Production => vault
                        .set_declaration_environment(item_id, Environment::Production)
                        .map(|_| {
                            let _ = vault.record_interaction(
                                InteractionKind::Correction,
                                "production",
                                &[item_id],
                            );
                        }),
                    RemoteEnvironment::Development => {
                        let expected = OwnerAction::ChangeItemRules { item_id };
                        match proof.map(|proof| proof.check(&expected, &vault.epoch())) {
                            Some(Ok(())) => vault
                                .set_declaration_environment(item_id, Environment::Development)
                                .map(|_| ()),
                            _ => {
                                return Verdict::Refused {
                                    device: name,
                                    reason: "the owner check did not pass".to_owned(),
                                };
                            }
                        }
                    }
                };
                match done {
                    Ok(()) => {
                        if let Some((event_id, _)) = newest_declaration(vault, item_id) {
                            drop(guard);
                            lock(&self.state)
                                .environment
                                .insert(item_id, EnvironmentMark { event_id, time });
                        }
                        Verdict::Corrected
                    }
                    Err(_) => Verdict::Refused {
                        device: name,
                        reason: "the credential could not be changed".to_owned(),
                    },
                }
            }
        }
    }
}

// ---- The lister: the questions of the other devices. ----

impl Shared {
    /// The questions of the other devices go: the vault locked, changed, or the
    /// questions went off.
    fn forget_remote(&self) {
        {
            let mut remote = lock(&self.remote);
            let next_id = remote.next_id;
            *remote = Remote {
                next_id,
                ..Remote::default()
            };
        }
        self.publish_remote();
    }

    /// Copy the open questions of the other devices to the view.
    fn publish_remote(&self) {
        let mut list: Vec<RemoteQuestion> = lock(&self.remote).open.values().cloned().collect();
        list.sort_by_key(|question| (question.expires_at(), question.id));
        let mut view = lock(&self.view);
        if view.remote != list {
            view.remote = list;
            drop(view);
            self.changed();
        }
    }

    /// An answer of this Mac to `qid` went to the relay.
    fn remote_sent(&self, qid: &str, text: String) {
        if let Some(question) = lock(&self.remote).open.get_mut(qid) {
            question.sent = Some(text);
        }
        self.publish_remote();
    }

    /// The relay says that `qid` takes no more answers.
    fn remote_gone(&self, qid: &str) {
        lock(&self.remote).open.remove(qid);
        self.publish_remote();
    }

    /// See [`QuestionsWorker::answering`].
    fn answering(&self, me: &Arc<Self>, id: u64) -> Result<RemoteAnswering, AnswerError> {
        let active = lock(&self.state).active.clone().ok_or(AnswerError::Gone)?;
        let question = lock(&self.remote)
            .open
            .values()
            .find(|question| question.id == id)
            .map(|question| question.question.clone())
            .filter(|question| question.team_id == active.team_id)
            .ok_or(AnswerError::Gone)?;
        let key = {
            let mut guard = lock(&self.vault);
            let vault = Self::vault_of(&mut guard, &active).ok_or(AnswerError::Gone)?;
            vault.question_key().ok().flatten()
        };
        Ok(RemoteAnswering {
            id,
            client: active.client.clone(),
            question,
            by: active.me.uuid.clone(),
            keys: key.into_iter().collect(),
            epoch: active.epoch,
            shared: Arc::downgrade(me),
        })
    }

    /// One step of the lister: one long poll of `GET /v1/questions`, then each question
    /// that changed is opened and checked again (section 7.3), or leaves the list.
    fn list_step(&self) {
        let active = lock(&self.state).active.clone();
        let Some(active) = active else {
            if lock(&self.remote).team_id.is_some() {
                self.forget_remote();
            }
            self.sleep(Duration::from_secs(1));
            return;
        };
        let since = {
            let mut remote = lock(&self.remote);
            if remote.team_id.as_deref() != Some(active.team_id.as_str()) {
                let next_id = remote.next_id;
                *remote = Remote {
                    team_id: Some(active.team_id.clone()),
                    next_id,
                    ..Remote::default()
                };
            }
            remote.since
        };
        if self.unsupported_now() {
            // A relay without the questions routes: no list until the wait ends.
            self.sleep(Duration::from_secs(5));
            return;
        }
        let started = Instant::now();
        let list = match active.client.list(since, MAX_WAIT) {
            Ok(list) => list,
            Err(error) if error.status() == Some(404) => {
                self.mark_unsupported(&active, "Apassy");
                return;
            }
            Err(error) => {
                if !matches!(error, QuestionsError::Closed) && !self.stop.load(Ordering::SeqCst) {
                    self.sleep(Duration::from_secs(2));
                }
                return;
            }
        };
        if list.seq < since {
            // A relay restored from a backup: read again from the start.
            lock(&self.remote).since = 0;
            return;
        }
        let (keys, devices) = {
            let mut guard = lock(&self.vault);
            let Some(vault) = Self::vault_of(&mut guard, &active) else {
                return;
            };
            (
                vault
                    .question_key()
                    .ok()
                    .flatten()
                    .into_iter()
                    .collect::<Vec<_>>(),
                vault.trusted_devices().unwrap_or_default(),
            )
        };
        let now = unix_now();
        {
            let mut remote = lock(&self.remote);
            if remote.team_id.as_deref() != Some(active.team_id.as_str()) {
                return;
            }
            for record in &list.questions {
                let opened = (record.state == "open")
                    .then(|| open_question(record, &active.team_id, &keys, &devices, now).ok())
                    .flatten();
                match opened {
                    Some(question) => {
                        if let Some(known) = remote.open.get_mut(&record.qid) {
                            known.question = question;
                        } else {
                            remote.next_id += 1;
                            let id = remote.next_id;
                            remote.open.insert(
                                record.qid.clone(),
                                RemoteQuestion {
                                    id,
                                    question,
                                    sent: None,
                                },
                            );
                        }
                    }
                    // Settled, expired, or a card that this Mac cannot read: it offers
                    // no answer here.
                    None => {
                        remote.open.remove(&record.qid);
                    }
                }
            }
            remote
                .open
                .retain(|_, question| question.expires_at() > now);
            let last = list.questions.iter().map(|record| record.seq).max();
            remote.since = match last {
                Some(last) if list.questions.len() >= LIST_PAGE => last,
                Some(last) => last.max(list.seq),
                None => list.seq.max(since),
            };
        }
        self.publish_remote();
        if list.questions.is_empty() && started.elapsed() < LIST_AT_LEAST {
            self.sleep(LIST_AT_LEAST.saturating_sub(started.elapsed()));
        }
    }
}

/// The newest declaration event of the credential `item_id`: its ID and time.
fn newest_declaration(vault: &Vault, item_id: u64) -> Option<(u64, u64)> {
    vault
        .item_events(item_id, crate::vault::MAX_ITEM_EVENTS)
        .ok()?
        .into_iter()
        .find(|event| event.kind == ItemEventKind::Declaration)
        .map(|event| (event.id, event.at))
}

/// The reason of a failed check for Activity.
fn remote_reason(error: &OwnerAuthError) -> &'static str {
    match error {
        OwnerAuthError::RemoteStale => "the answer is too old",
        OwnerAuthError::RemoteRejected => "its signature does not verify",
        OwnerAuthError::RemoteUnsupported => "the question does not offer this answer",
        OwnerAuthError::SessionChanged | OwnerAuthError::VaultLocked => {
            "the vault was locked during the check"
        }
        _ => "the owner check did not pass",
    }
}

fn push_line<T>(lines: &mut Vec<T>, line: T) {
    if lines.len() >= MAX_VIEW_LINES {
        lines.remove(0);
    }
    lines.push(line);
}

fn poster(shared: &Shared) {
    while !shared.stop.load(Ordering::SeqCst) {
        shared.post_step();
        if !shared.sleep(shared.config.tick) {
            break;
        }
    }
}

fn reader(shared: &Shared) {
    while !shared.stop.load(Ordering::SeqCst) {
        shared.read_step();
    }
}

fn lister(shared: &Shared) {
    while !shared.stop.load(Ordering::SeqCst) {
        shared.list_step();
    }
}
