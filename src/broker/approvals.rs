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
//!
//! ADR 0025: each waiting run is a question with a [`QuestionInfo`] for the card ("Why you
//! are asked"). An agent has at most one waiting question
//! ([`ApprovalQueue::wait_for_question`]). The same request of the same agent again, in
//! the same vault session, joins the waiting question instead: the newest call gets the
//! answer, and an older call ends at once, so one answer starts one run. A call never
//! joins the question of another agent. "Allow ACTION in PROJECT"
//! ([`OwnerAction::ApproveInProject`]) and "Allow production for PROJECT: ACTION"
//! ([`OwnerAction::AllowProduction`]) approve the run and give the broker an
//! [`AnswerChoice`] that it remembers after its second check. The stricter answers
//! ("Not for this agent", "Always ask for this agent", "Disconnect the agent") deny the
//! run and need no owner check ([`ApprovalQueue::deny_stricter`]).
//!
//! A question names the answers that can take effect ([`QuestionInfo::valid_answers`]).
//! The queue refuses a remembered answer that the question does not offer, for example
//! "Allow ACTION in PROJECT" without a running bouncer or for a kind of action that the
//! rules are not sure of. A call joins a waiting question when its run is the same
//! except for the IDs, the bouncer text (`risk`, `question.why`), and the pattern offer,
//! and when its credentials are as they were at the first check of the call that asked
//! ([`baseline_of`]). The broker checks each credential again after the answer, against
//! the first check of the call that takes the answer. So when a credential changed (an
//! edit, or a merge of a sync) the new call does not join: the old question ends, and
//! the new call asks again. An answer never covers a version of a credential that came
//! after its question showed.

mod owner_auth;

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use super::action_kind::ActionKind;
use super::project::Project;
use crate::vault::exceptions::ExceptionKind;
use crate::vault::{
    Declaration, SuggestedDeclaration, Vault, VaultError, VaultErrorKind, VaultResult,
};

pub use owner_auth::{
    CheckMethod, OwnerAction, OwnerAuthError, OwnerCheck, OwnerGate, OwnerProof, PROOF_LIFETIME,
    ProofRefusal, action_words, grant_declarations, grant_has_production, remote_key,
    touch_id_detail, verify_remote_answer,
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
    /// What the question is about and why the owner is asked (ADR 0025). It is not in
    /// the digest that an iPhone signs, so a phone approves the run once only.
    pub question: QuestionInfo,
}

/// The question of a waiting run (ADR 0025 §3): the items, the project, the kind of
/// action, and why the owner is asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuestionInfo {
    /// The ID of the waiting run. The queue sets it.
    pub id: u64,
    pub item_ids: Vec<u64>,
    /// The project of the working directory. `None`: the folder is too wide to be a
    /// project, and no answer can be remembered.
    pub project: Option<Project>,
    pub action: ActionKind,
    /// An item of the run has a production declaration from a real signal without an
    /// allowance: only "Allow production" can be remembered.
    pub production: bool,
    /// Why the owner is asked, for the card. No secret value.
    pub why: String,
    /// Each item of the run, in the order of `item_ids`.
    pub items: Vec<QuestionItem>,
    /// The answers that can take effect now. The card offers only these, and the queue
    /// refuses a remembered answer that is not here.
    pub valid_answers: Vec<AnswerKind>,
}

impl Default for QuestionInfo {
    fn default() -> Self {
        Self {
            id: 0,
            item_ids: Vec::new(),
            project: None,
            action: ActionKind::Change,
            production: false,
            why: String::new(),
            items: Vec::new(),
            valid_answers: vec![AnswerKind::Once],
        }
    }
}

/// One item of a question (ADR 0025 §3, §5).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuestionItem {
    pub item_id: u64,
    pub name: String,
    /// Production from a real signal (the owner, a value signal, or usage): each run
    /// waits unless the owner allowed production for the project and the kind of action.
    pub production: bool,
    /// Production only by default, without a signal. The first use in a project with a
    /// kind of action asks, and the owner can correct the environment
    /// ([`AnswerKind::CorrectEnvironment`]).
    pub unconfirmed: bool,
    /// "Always ask me" of the item, or "Always ask for this agent": nothing is
    /// remembered for it.
    pub always_ask: bool,
}

/// An answer that a question can offer (ADR 0025 §3, §3b, §3f, §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnswerKind {
    /// "Allow once".
    Once,
    /// "Allow ACTION in PROJECT".
    InProject(ActionKind),
    /// "Allow production for PROJECT: ACTION".
    Production(ActionKind),
    /// "Not for this agent".
    NeverForAgent,
    /// "Always ask for this agent".
    AlwaysAskForAgent,
    /// "Disconnect the agent".
    Disconnect,
    /// "Development" or "Production": the owner corrects the environment of an item whose
    /// production value is only a default (`QuestionItem::unconfirmed`).
    CorrectEnvironment,
}

/// What "Allow ACTION in PROJECT" or "Allow production for PROJECT: ACTION" remembers
/// after the broker checks the run again (ADR 0025 §3, §3b).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnswerChoice {
    pub project: Project,
    pub action: ActionKind,
    /// "Allow production": the production items get a production allowance.
    pub production: bool,
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

pub(crate) fn folder_is_broad_with(folder: &Path, home: Option<&Path>) -> bool {
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
/// for "Allow in this folder" or a remembered answer what the broker saves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settled {
    pub outcome: ApprovalOutcome,
    pub method: Option<CheckMethod>,
    pub grant: Option<GrantChoice>,
    /// The answer to remember (ADR 0025).
    pub answer: Option<AnswerChoice>,
    /// The call joined a question that already waited.
    pub attached: bool,
}

impl Settled {
    fn ended(outcome: ApprovalOutcome) -> Self {
        Self {
            outcome,
            method: None,
            grant: None,
            answer: None,
            attached: false,
        }
    }
}

/// How a waiting run ended, for a watcher of the queue: the questions through the relay
/// settle their copy on the relay with it ([`ApprovalQueue::take_ended`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunEnd {
    pub id: u64,
    pub outcome: ApprovalOutcome,
    /// The check of an approval: Touch ID, the passphrase, the iPhone, or a device
    /// through the relay.
    pub method: Option<CheckMethod>,
}

/// The most ends that wait for [`ApprovalQueue::take_ended`]. Older ones go.
const MAX_ENDED: usize = 256;

/// [`ApprovalQueue::wait_for_first_use`] refused the wait: a question of the same
/// agent already waits (ADR 0024, ADR 0025).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirstUseBusy;

/// Why [`ApprovalQueue::wait_for_question`] gave no answer to this call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuestionRefusal {
    /// Another question of the same agent waits.
    Busy,
    /// A newer identical call of the same agent joined the question and gets the answer,
    /// or replaced it with a new question because a credential changed.
    Superseded,
}

/// A stricter answer to a question (ADR 0025 §3f). It denies the run and needs no owner
/// check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StricterAnswer {
    /// "Not for this agent": each item of the question.
    NeverForAgent,
    /// "Always ask for this agent": each item of the question.
    AlwaysAskForAgent,
    /// "Disconnect the agent".
    Disconnect,
}

/// The owner answer that a waiting run gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answer {
    Approve,
    /// Approve the run and add one approval to its pattern.
    ApproveAndRemember,
    /// Approve the run and give the agent access at first use (ADR 0024).
    ApproveAndGrant,
    /// Approve the run and remember a project answer (ADR 0025).
    ApproveInProject,
    /// Approve the run and allow production (ADR 0025 §3b).
    AllowProduction,
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
    /// A remembered answer for a run without a project, for another project or kind of
    /// action than the question names, or one that the question does not offer because
    /// it could not take effect ([`QuestionInfo::valid_answers`]: no bouncer runs, the
    /// rules are not certain of the kind of action, an item always asks, or a rule flag
    /// asks at each run).
    NoProject,
    /// "Allow production" for a question without a production item.
    NotProduction,
    /// "Allow ACTION in PROJECT" for a question with a production item: production
    /// needs its own allowance.
    ProductionNeedsAllowance,
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
            Self::NoProject => {
                "Apassy cannot remember this answer for this run. Nothing was approved. Use \"Allow once\"."
            }
            Self::NotProduction => {
                "This run uses no production credential. Nothing was approved. Review the request again."
            }
            Self::ProductionNeedsAllowance => {
                "A production credential needs \"Allow production\". Nothing was approved."
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
    remember: Option<AnswerChoice>,
}

/// The question of one waiting run (ADR 0025).
#[derive(Debug, Clone)]
struct Question {
    agent_id: u64,
    /// The vault session of the question. A call from another session never joins it.
    session: [u8; 32],
    /// The run as it waits, with its IDs set to 0. An identical call joins it.
    template: PendingRun,
    /// The credentials at the first check of the call that asked ([`baseline_of`]). A
    /// call with another baseline does not join: it replaces the question.
    baseline: Baseline,
    deadline: Instant,
    /// Grows with each call that joins. Only the newest call takes the answer.
    turn: u64,
}

/// The agent of a call that waits as a question, its vault session, and its
/// [`Baseline`].
#[derive(Debug, Clone, Copy)]
struct Asker {
    agent_id: u64,
    session: [u8; 32],
    baseline: Baseline,
}

/// The run with its IDs at 0 and without the text of the bouncer and the pattern offer,
/// to compare two calls. The same request again can get another model text or another
/// approval count; it is still the same request.
fn template_of(run: &PendingRun) -> PendingRun {
    let mut template = run.clone();
    template.id = 0;
    template.question.id = 0;
    template.risk.clear();
    template.remember = None;
    template.question.why.clear();
    template
}

/// A digest of what the broker checks again after the answer of a question: the
/// credentials of the call and their access ([`ApprovalQueue::wait_for_question`]).
pub type Baseline = [u8; 32];

/// The [`Baseline`] of `state`: SHA-256 of its debug text. `state` is plain data (no
/// hash map), so equal state gives equal text.
pub fn baseline_of(state: &impl std::fmt::Debug) -> Baseline {
    let text = format!("{state:?}");
    let digest = ring::digest::digest(&ring::digest::SHA256, text.as_bytes());
    let mut baseline = [0; 32];
    baseline.copy_from_slice(digest.as_ref());
    baseline
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
    /// The question of each waiting run of a known agent (ADR 0025).
    questions: BTreeMap<u64, Question>,
    /// Questions that a call with another baseline replaced. The call that waits on one
    /// ends with [`QuestionRefusal::Superseded`].
    replaced: BTreeSet<u64>,
    decisions: BTreeMap<u64, Decision>,
    /// When each waiting run started to wait. It is not part of the run, so the
    /// equality of two runs (and an owner proof for one) does not depend on it.
    waiting_since: BTreeMap<u64, Instant>,
    /// How the latest runs ended, oldest first ([`ApprovalQueue::take_ended`]).
    ended: std::collections::VecDeque<RunEnd>,
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
            OwnerAction::ApproveInProject { .. } => Answer::ApproveInProject,
            OwnerAction::AllowProduction { .. } => Answer::AllowProduction,
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
            Some(waiting) => {
                let remember = match proof.action() {
                    OwnerAction::ApproveInProject {
                        project, action, ..
                    } => Some(Self::answer_choice(waiting, project, *action, false)?),
                    OwnerAction::AllowProduction {
                        project, action, ..
                    } => Some(Self::answer_choice(waiting, project, *action, true)?),
                    _ => None,
                };
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
                Self::settle(
                    &mut state,
                    confirmed.id,
                    answer,
                    Some(method),
                    grant,
                    remember,
                );
                self.changed.notify_all();
                Ok(())
            }
        }
    }

    /// The answer of "Allow ACTION in PROJECT" or "Allow production": the project and
    /// the kind of action must be those of the waiting question, and production needs
    /// its own answer (ADR 0025 §3b).
    fn answer_choice(
        waiting: &PendingRun,
        project: &Project,
        action: ActionKind,
        production: bool,
    ) -> Result<AnswerChoice, ApprovalRefusal> {
        let question = &waiting.question;
        if question.item_ids.is_empty()
            || question.project.as_ref() != Some(project)
            || question.action != action
        {
            return Err(ApprovalRefusal::NoProject);
        }
        let offered = if production {
            AnswerKind::Production(action)
        } else {
            AnswerKind::InProject(action)
        };
        match (production, question.production) {
            (true, false) => Err(ApprovalRefusal::NotProduction),
            (false, true) => Err(ApprovalRefusal::ProductionNeedsAllowance),
            _ if !question.valid_answers.contains(&offered) => Err(ApprovalRefusal::NoProject),
            _ => Ok(AnswerChoice {
                project: project.clone(),
                action,
                production,
            }),
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
        Self::settle(&mut state, id, Answer::Deny, None, None, None);
        self.changed.notify_all();
        true
    }

    /// Deny a waiting question and make the agent stricter (ADR 0025 §3f): "Not for this
    /// agent" or "Always ask for this agent" for each item of the question, or
    /// "Disconnect the agent". It takes authority away and needs no owner check.
    ///
    /// The caller holds the vault (the owner thread takes the vault lock, then the queue
    /// lock). `Ok(false)`: the run no longer waits, and nothing changed. A run without a
    /// known agent is not denied (`InvalidInput`): use [`Self::deny`]. When the vault
    /// change fails, the run is still denied and the error is returned.
    pub fn deny_stricter(
        &self,
        id: u64,
        stricter: StricterAnswer,
        vault: &mut Vault,
    ) -> VaultResult<bool> {
        let mut state = self.state();
        let Some(run) = state.pending.iter().find(|run| run.id == id).cloned() else {
            return Ok(false);
        };
        let Some(agent) = state.questions.get(&id).map(|question| question.agent_id) else {
            return Err(VaultError::new(VaultErrorKind::InvalidInput));
        };
        let changed = match stricter {
            StricterAnswer::NeverForAgent | StricterAnswer::AlwaysAskForAgent => {
                let kind = if stricter == StricterAnswer::NeverForAgent {
                    ExceptionKind::Never
                } else {
                    ExceptionKind::AlwaysAsk
                };
                run.question
                    .item_ids
                    .iter()
                    .try_for_each(|item| vault.add_agent_exception(agent, *item, kind))
            }
            StricterAnswer::Disconnect => vault.revoke_agent(agent),
        };
        Self::settle(&mut state, id, Answer::Deny, None, None, None);
        self.changed.notify_all();
        changed.map(|()| true)
    }

    /// "Deny, and not for this agent".
    pub fn deny_and_never(&self, id: u64, vault: &mut Vault) -> VaultResult<bool> {
        self.deny_stricter(id, StricterAnswer::NeverForAgent, vault)
    }

    /// "Deny, and always ask for this agent".
    pub fn deny_and_always_ask(&self, id: u64, vault: &mut Vault) -> VaultResult<bool> {
        self.deny_stricter(id, StricterAnswer::AlwaysAskForAgent, vault)
    }

    /// "Deny, and disconnect the agent".
    pub fn deny_and_disconnect(&self, id: u64, vault: &mut Vault) -> VaultResult<bool> {
        self.deny_stricter(id, StricterAnswer::Disconnect, vault)
    }

    /// The ends of waiting runs since the last call, oldest first: an answer, a timeout,
    /// or an invalid session. At most the last 256 are kept.
    pub fn take_ended(&self) -> Vec<RunEnd> {
        self.state().ended.drain(..).collect()
    }

    /// Note how the waiting run `id` ends, when it waits.
    fn note_end(
        state: &mut QueueState,
        id: u64,
        outcome: ApprovalOutcome,
        method: Option<CheckMethod>,
    ) {
        if state.pending.iter().any(|run| run.id == id) {
            if state.ended.len() >= MAX_ENDED {
                state.ended.pop_front();
            }
            state.ended.push_back(RunEnd {
                id,
                outcome,
                method,
            });
        }
    }

    fn settle(
        state: &mut QueueState,
        id: u64,
        answer: Answer,
        method: Option<CheckMethod>,
        grant: Option<GrantChoice>,
        remember: Option<AnswerChoice>,
    ) {
        Self::note_end(state, id, Self::outcome_of(answer), method);
        state.pending.retain(|run| run.id != id);
        state.waiting_since.remove(&id);
        state.offers.remove(&id);
        state.questions.remove(&id);
        state.decisions.insert(
            id,
            Decision {
                answer,
                method,
                grant,
                remember,
            },
        );
    }

    fn outcome_of(answer: Answer) -> ApprovalOutcome {
        match answer {
            Answer::Approve | Answer::ApproveInProject | Answer::AllowProduction => {
                ApprovalOutcome::Approved
            }
            Answer::ApproveAndRemember => ApprovalOutcome::ApprovedAndRemembered,
            Answer::ApproveAndGrant => ApprovalOutcome::ApprovedAndGranted,
            Answer::Deny => ApprovalOutcome::Denied,
        }
    }

    /// Remove a run that ended without a decision: a timeout, or an invalid session.
    fn forget(state: &mut QueueState, id: u64, outcome: ApprovalOutcome) {
        Self::note_end(state, id, outcome, None);
        state.pending.retain(|pending| pending.id != id);
        state.waiting_since.remove(&id);
        state.offers.remove(&id);
        state.questions.remove(&id);
    }

    /// End every waiting run and every decision that a run did not use yet. The
    /// desktop app calls this when the owner locks the vault. The broker calls it
    /// when it stops.
    pub fn invalidate_all(&self) {
        let mut state = self.state();
        state.generation = state.generation.wrapping_add(1);
        let ids: Vec<u64> = state.pending.iter().map(|run| run.id).collect();
        for id in ids {
            Self::note_end(&mut state, id, ApprovalOutcome::Invalidated, None);
        }
        state.pending.clear();
        state.waiting_since.clear();
        state.offers.clear();
        state.questions.clear();
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
        let settled = match self.wait(run, None, None, timeout, still_valid) {
            Ok(settled) => settled,
            Err(_) => Settled::ended(ApprovalOutcome::Invalidated),
        };
        (settled.outcome, settled.method)
    }

    /// Put the question of `agent_id` in the queue and wait for the owner or the timeout
    /// (ADR 0025). `session` is the vault epoch of the run.
    ///
    /// An agent has at most one waiting question: another question of the agent gives
    /// [`QuestionRefusal::Busy`]. The same run again (equal except for its IDs), from the
    /// same agent in the same session, with the same `baseline`, joins the waiting
    /// question and keeps its time limit; the older call then ends with
    /// [`QuestionRefusal::Superseded`], so only the newest call gets the answer and one
    /// answer starts one run.
    ///
    /// `baseline` is the digest of what the broker checks again after the answer
    /// ([`baseline_of`]). The same run with another baseline (a credential changed after
    /// the question showed) does not join: the waiting question ends, its call ends with
    /// [`QuestionRefusal::Superseded`], and this call asks again with a new question and
    /// a new time limit. So an answer always covers the credentials as they were when its
    /// question showed.
    pub fn wait_for_question(
        &self,
        run: PendingRun,
        agent_id: u64,
        session: [u8; 32],
        baseline: Baseline,
        timeout: Duration,
        still_valid: impl Fn() -> bool,
    ) -> Result<Settled, QuestionRefusal> {
        let asker = Asker {
            agent_id,
            session,
            baseline,
        };
        self.wait(run, None, Some(asker), timeout, still_valid)
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
        let asker = Asker {
            agent_id: offer.agent_id,
            session: [0; 32],
            baseline: [0; 32],
        };
        self.wait(run, Some(offer), Some(asker), timeout, still_valid)
            .map_err(|_| FirstUseBusy)
    }

    fn wait(
        &self,
        mut run: PendingRun,
        offer: Option<FirstUseOffer>,
        agent: Option<Asker>,
        timeout: Duration,
        still_valid: impl Fn() -> bool,
    ) -> Result<Settled, QuestionRefusal> {
        let mut state = self.state();
        if state.closed {
            return Ok(Settled::ended(ApprovalOutcome::Invalidated));
        }
        let generation = state.generation;
        let template = template_of(&run);
        let mut replaced = None;
        let joined = match agent {
            Some(asker) => {
                match state
                    .questions
                    .iter_mut()
                    .find(|(_, question)| question.agent_id == asker.agent_id)
                {
                    Some((id, question))
                        if offer.is_none()
                            && question.session == asker.session
                            && question.template == template =>
                    {
                        if question.baseline == asker.baseline {
                            question.turn = question.turn.wrapping_add(1);
                            Some((*id, question.turn, question.deadline))
                        } else {
                            replaced = Some(*id);
                            None
                        }
                    }
                    Some(_) => return Err(QuestionRefusal::Busy),
                    None => None,
                }
            }
            None => None,
        };
        if let Some(old) = replaced {
            // A credential changed after the old question showed. The old question ends,
            // and this call asks again, so the owner answers for the credential as it is.
            Self::forget(&mut state, old, ApprovalOutcome::Invalidated);
            state.replaced.insert(old);
        }
        let attached = joined.is_some();
        let (id, turn, deadline) = match joined {
            Some(joined) => joined,
            None => {
                let deadline = Instant::now() + timeout;
                state.next_id = state.next_id.wrapping_add(1);
                let id = state.next_id;
                run.id = id;
                run.question.id = id;
                state.pending.push(run);
                state.waiting_since.insert(id, Instant::now());
                if let Some(offer) = offer {
                    state.offers.insert(id, offer);
                }
                if let Some(asker) = agent {
                    state.questions.insert(
                        id,
                        Question {
                            agent_id: asker.agent_id,
                            session: asker.session,
                            template,
                            baseline: asker.baseline,
                            deadline,
                            turn: 0,
                        },
                    );
                }
                (id, 0, deadline)
            }
        };
        self.changed.notify_all();
        drop(state);
        if !attached {
            self.notify_owner();
        }
        // The newest call that joined the question takes the answer.
        let superseded = |state: &QueueState| {
            agent.is_some()
                && state
                    .questions
                    .get(&id)
                    .is_some_and(|question| question.turn != turn)
        };
        loop {
            let mut state = self.state();
            if state.replaced.remove(&id) {
                return Err(QuestionRefusal::Superseded);
            }
            if state.generation != generation {
                Self::forget(&mut state, id, ApprovalOutcome::Invalidated);
                state.decisions.remove(&id);
                return Ok(Settled::ended(ApprovalOutcome::Invalidated));
            }
            if superseded(&state) {
                return Err(QuestionRefusal::Superseded);
            }
            if let Some(decision) = state.decisions.remove(&id) {
                let outcome = Self::outcome_of(decision.answer);
                return Ok(Settled {
                    outcome,
                    method: decision.method,
                    grant: decision.grant,
                    answer: decision.remember,
                    attached,
                });
            }
            if !state.pending.iter().any(|pending| pending.id == id) {
                // The question ended without an answer for this call: the call that
                // owned it saw an invalid session.
                return Ok(Settled::ended(ApprovalOutcome::Invalidated));
            }
            let now = Instant::now();
            if now >= deadline {
                Self::forget(&mut state, id, ApprovalOutcome::TimedOut);
                return Ok(Settled {
                    attached,
                    ..Settled::ended(ApprovalOutcome::TimedOut)
                });
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
                if state.replaced.remove(&id) || superseded(&state) {
                    return Err(QuestionRefusal::Superseded);
                }
                Self::forget(&mut state, id, ApprovalOutcome::Invalidated);
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
            question: QuestionInfo::default(),
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

    /// ADR 0025: one waiting question per agent. Only the same run of the same agent in
    /// the same vault session joins it, and then only the newest call gets the answer.
    #[test]
    fn a_question_is_joined_only_by_the_same_run_of_the_same_agent_and_session() {
        let queue = Arc::new(ApprovalQueue::new());
        let ask = |agent: u64, session: u8, run: PendingRun| {
            let queue = Arc::clone(&queue);
            std::thread::spawn(move || {
                queue.wait_for_question(
                    run,
                    agent,
                    [session; 32],
                    [0; 32],
                    Duration::from_secs(5),
                    || true,
                )
            })
        };
        let first = ask(7, 1, run());
        let id = wait_until_pending(&queue);
        assert_eq!(queue.pending()[0].question.id, id);
        let mut other = run();
        other.command = vec!["false".to_owned()];
        let wait = Duration::from_secs(5);
        assert_eq!(
            queue.wait_for_question(other, 7, [1; 32], [0; 32], wait, || true),
            Err(QuestionRefusal::Busy)
        );
        assert_eq!(
            queue.wait_for_question(run(), 7, [2; 32], [0; 32], wait, || true),
            Err(QuestionRefusal::Busy),
            "another vault session never joins"
        );
        let foreign = ask(8, 1, run());
        while queue.pending().len() < 2 {
            std::thread::sleep(Duration::from_millis(5));
        }
        let joined = ask(7, 1, run());
        assert_eq!(
            first.join().expect("join"),
            Err(QuestionRefusal::Superseded)
        );
        assert_eq!(queue.pending().len(), 2);
        assert!(queue.deny(id));
        let settled = joined.join().expect("join").expect("an answer");
        assert_eq!(settled.outcome, ApprovalOutcome::Denied);
        assert!(settled.attached);
        let waiting = queue.pending();
        assert_eq!(waiting.len(), 1, "the other agent still waits");
        assert!(queue.deny(waiting[0].id));
        let settled = foreign.join().expect("join").expect("an answer");
        assert!(!settled.attached);
    }

    /// Gate 1 (C-F7): the same request again joins its question also when the bouncer
    /// text or the pattern offer changed.
    #[test]
    fn a_question_is_joined_without_the_bouncer_text_and_the_pattern_offer() {
        let queue = Arc::new(ApprovalQueue::new());
        let first = {
            let queue = Arc::clone(&queue);
            std::thread::spawn(move || {
                let mut run = run();
                run.risk = "The model was not sure.".to_owned();
                run.question.why = run.risk.clone();
                queue.wait_for_question(run, 7, [1; 32], [0; 32], Duration::from_secs(5), || true)
            })
        };
        let id = wait_until_pending(&queue);
        let joined = {
            let queue = Arc::clone(&queue);
            std::thread::spawn(move || {
                let mut run = run();
                run.risk = "Another model text.".to_owned();
                run.question.why = run.risk.clone();
                run.remember = Some(RememberOffer {
                    pattern: "true".to_owned(),
                    approvals: 1,
                    needed: 3,
                });
                queue.wait_for_question(run, 7, [1; 32], [0; 32], Duration::from_secs(5), || true)
            })
        };
        assert_eq!(
            first.join().expect("join"),
            Err(QuestionRefusal::Superseded)
        );
        assert_eq!(queue.pending().len(), 1);
        assert!(queue.deny(id));
        let settled = joined.join().expect("join").expect("an answer");
        assert!(settled.attached);
        assert_eq!(settled.outcome, ApprovalOutcome::Denied);
    }

    /// The same request after a change of a credential (another baseline) does not
    /// join: the old question ends, and an approval of its card does nothing. The new
    /// call asks again, and only an answer to the new card counts.
    #[test]
    fn a_question_is_asked_again_when_the_credentials_changed() {
        let queue = Arc::new(ApprovalQueue::new());
        let ask = |baseline: u8| {
            let queue = Arc::clone(&queue);
            std::thread::spawn(move || {
                queue.wait_for_question(
                    run(),
                    7,
                    [1; 32],
                    [baseline; 32],
                    Duration::from_secs(5),
                    || true,
                )
            })
        };
        let first = ask(1);
        let old = wait_until_pending(&queue);
        let old_card = proof_for(&queue, old);
        let _ = queue.take_ended();

        let second = ask(2);
        assert_eq!(
            first.join().expect("join"),
            Err(QuestionRefusal::Superseded)
        );
        let new = loop {
            if let Some(run) = queue.pending().into_iter().find(|run| run.id != old) {
                break run.id;
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        assert_eq!(queue.pending().len(), 1, "the old question ended");
        assert_eq!(
            queue.take_ended(),
            vec![RunEnd {
                id: old,
                outcome: ApprovalOutcome::Invalidated,
                method: None,
            }]
        );
        assert!(queue.state().replaced.is_empty());
        assert_eq!(queue.approve(old_card), Err(ApprovalRefusal::NotWaiting));

        // The same request with the new baseline joins the new question.
        let third = ask(2);
        assert_eq!(
            second.join().expect("join"),
            Err(QuestionRefusal::Superseded)
        );
        assert_eq!(queue.pending().len(), 1);
        assert_eq!(queue.pending()[0].id, new);
        queue.approve(proof_for(&queue, new)).expect("approve");
        let settled = third.join().expect("join").expect("an answer");
        assert_eq!(settled.outcome, ApprovalOutcome::Approved);
        assert!(settled.attached);
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
