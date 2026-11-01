//! Decisions (ADR 0026 §2, ADR 0025 §3): what waits for the owner.
//!
//! The list has three sections, each only when it has a row:
//!
//! - **Waiting**: the questions that wait, with the agent, the credential, the project, a
//!   red dot for production, and the time left of the 5-minute wait.
//! - **Requests**: the open credential requests of agents (ADR 0025 §6).
//! - **Suggestions**: the open corrections from the use log (ADR 0025 §5).
//!
//! The line under the title counts the owner interactions and the automatic decisions of
//! the week (ADR 0025 §1). When macOS cannot show a notification, one small line at the
//! bottom of the list says so, once for the place, not in each detail.
//!
//! Each row and each header has the round avatar of the agent ([`kit::avatar`]); a
//! suggestion has the tile of its credential.
//!
//! The detail of a question has its facts, its command, why the owner is asked, and a bar
//! at the bottom: Deny, Allow Once, and the remembered answer that the question offers
//! ([`QuestionInfo::valid_answers`]). The "⋯" menu makes the agent stricter. Each answer
//! that gives authority passes the owner check; a stricter answer needs none.
//!
//! The detail of a request says what the agent asks for, why, where the owner gets it
//! (the domain as plain text: Apassy opens no link that an agent wrote), and where it is
//! saved. The owner pastes the key in a masked field and sees what Apassy found, as in
//! New Credential. Save adds the item with the origin of the request and needs no owner
//! check: a new item moves no authority. Not Now dismisses the request. The paste is
//! erased after each answer, on another selection, and on lock, and no value shows.
//!
//! The detail of a suggestion has its question, the facts of the use log, and Ignore and
//! the two choices. An answer that leaves the credential at an environment other than
//! production passes the owner check; production and a project need none.
//!
//! After each answer, the next decision is selected.
//!
//! With "Send questions through the relay" on, a question that another device answered
//! leaves the list, and the detail says "Answered on DEVICE" for a few minutes
//! ([`answered_lines`]). A question that stays on this Mac says why.
//!
//! The questions of the other Macs of the vault (relay-questions-v1 section 13) wait in
//! the same section, "from MAC", after the questions of this Mac. They have the same
//! detail and bar. An answer that gives authority passes the owner check on this Mac for
//! `OwnerAction::AnswerRemoteQuestion`; a stricter one needs none. This Mac signs the
//! answer with its relay key and sends it on a thread of its own; the asking Mac checks
//! it and decides. The question shows "Sent. The Mac checks it; …" until it settles: the
//! protocol has no receipts yet, so a refused answer shows as a run that does not go on.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use eframe::egui::{
    self, Align, Frame, Label, Layout, Margin, Pos2, Rect, RichText, Sense, TextEdit, TextStyle,
    TextWrapMode, Vec2, WidgetInfo, WidgetText, WidgetType,
};
use serde_json::Value;

use super::columns::{self, Group};
use super::folders::FolderTree;
use super::kit::{self, Font, Icon, Style, Tone};
use crate::broker::action_kind::ActionKind;
use crate::broker::approvals::{
    AnswerKind, ApprovalQueue, EvaluationOffer, PendingRun, QuestionInfo, QuestionItem,
    StricterAnswer, shown_path,
};
use crate::broker::server::QUESTION_WAIT;
use crate::contracts::CredentialKind;
use crate::desktop::owner_check::{OwnerRequest, Task, TaskPoll};
use crate::desktop::owner_store::{OwnerSession, OwnerSummary};
use crate::desktop::{BrokerState, DesktopApp};
use crate::questions::{
    AnswerError, AnswerReceipt, Choice, RemoteEnvironment, RemoteQuestion, remote_owner_action,
};
use crate::vault::agent_items::{
    Correction, CorrectionAnswer, CorrectionKind, CredentialRequest, RAISED_FROM_FACT,
};
use crate::vault::bouncer_scopes::EvaluationConfirmation;
use crate::vault::detect::{self, Detected};
use crate::vault::{Environment, RiskLevel};

/// The color of the time left, as in the mockup (#c86a00).
const TIMER: egui::Color32 = egui::Color32::from_rgb(200, 106, 0);
/// The fill of the bars at the bottom of a detail, as in the mockup.
const BAR_FILL: egui::Color32 = egui::Color32::from_rgb(246, 246, 247);
/// The longest project name in a button. A longer name ends with "…".
const SHORT_PROJECT: usize = 28;
/// The longest folder path in the facts.
const SHOWN_PATH: usize = 80;
/// The salt of the paste field of a request.
pub(super) const REQUEST_FIELD: &str = "decision-request";
/// The note when the paste of a request has no credential.
const NOTHING_FOUND: &str = "Apassy found no credential in the text. Paste the secret, a KEY=value line, or a URL with a password.";

/// One decision of the list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum Key {
    LegacyAccess(u64),
    Access(u64),
    /// A waiting question, by run ID.
    Run(u64),
    /// An open credential request, by request ID.
    Request(u64),
    /// An open correction, by correction ID.
    Suggestion(u64),
    /// A question of another Mac of the vault, by its number in the questions waiter.
    Remote(u64),
}

/// The answers of this Mac to questions of other Macs, while the relay takes them: the
/// name of the asking Mac, and the answer of the relay.
#[derive(Default)]
struct Sending {
    tasks: Vec<Task<(String, Result<AnswerReceipt, AnswerError>)>>,
    repaint: Option<egui::Context>,
}

impl std::fmt::Debug for Sending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sending")
            .field("tasks", &self.tasks.len())
            .finish_non_exhaustive()
    }
}

/// The paste of a request. It is a secret: Debug shows no value, and a drop erases it.
/// A lock resets the state of the view, so it erases the paste too.
#[derive(Default)]
struct Paste(String);

impl Paste {
    fn erase(&mut self) {
        use zeroize::Zeroize;
        self.0.zeroize();
    }
}

impl std::fmt::Debug for Paste {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Paste(..)")
    }
}

impl Drop for Paste {
    fn drop(&mut self) {
        self.erase();
    }
}

/// The state of the view.
#[derive(Debug, Default)]
pub(crate) struct State {
    /// The selected decision.
    selected: Option<Key>,
    /// Notification navigation never substitutes a newer request.
    routed: bool,
    activity_id: Option<u64>,
    show_activity: bool,
    /// Its place in the list in the last frame. When it goes (an answer, a time-out), the
    /// decision that takes its place is selected.
    index: usize,
    /// "Disconnect AGENT…" waits for its confirmation: the question and the agent name.
    disconnect: Option<(Key, String)>,
    /// The request of the paste and its folder: the request ID and the folder UUID
    /// (`None`: the top level).
    form: Option<(u64, Option<String>)>,
    /// The paste of the selected request.
    paste: Paste,
    /// The answers to questions of other Macs that go to the relay now.
    sending: Sending,
    /// An immutable offer snapshot with only the owner's classification edits.
    evaluation: Option<EvaluationDraft>,
}

impl State {
    pub(crate) fn forget_evaluation(&mut self) {
        self.evaluation = None;
    }
}

#[derive(Debug)]
struct EvaluationDraft {
    run_id: u64,
    offer: EvaluationOffer,
    confirmations: Vec<EvaluationConfirmation>,
    expanded: bool,
    stale: bool,
}

impl EvaluationDraft {
    fn new(run_id: u64, offer: EvaluationOffer) -> Self {
        Self {
            run_id,
            confirmations: offer
                .items
                .iter()
                .map(|item| item.confirmation.clone())
                .collect(),
            offer,
            expanded: false,
            stale: false,
        }
    }
}

/// What waits for the owner, in the order of the list.
pub(super) struct Open {
    legacy_access: Vec<crate::vault::AccessRequest>,
    pub(super) access: Vec<crate::vault::access_once::AccessRecord>,
    pub(super) waiting: Vec<Waiting>,
    /// The questions of other Macs, after the questions of this Mac.
    pub(super) remote: Vec<RemoteWaiting>,
    pub(super) requests: Vec<CredentialRequest>,
    pub(super) suggestions: Vec<(Correction, OwnerSummary)>,
}

impl Open {
    fn keys(&self) -> Vec<Key> {
        self.waiting
            .iter()
            .map(|waiting| Key::Run(waiting.run.id))
            .chain(
                self.remote
                    .iter()
                    .map(|remote| Key::Remote(remote.question.id)),
            )
            .chain(self.access.iter().map(|r| Key::Access(r.id)))
            .chain(self.legacy_access.iter().map(|r| Key::LegacyAccess(r.id)))
            .chain(self.requests.iter().map(|request| Key::Request(request.id)))
            .chain(
                self.suggestions
                    .iter()
                    .map(|(correction, _)| Key::Suggestion(correction.id)),
            )
            .collect()
    }
}

/// An answer to a credential request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RequestAnswer {
    /// Save the paste for the request.
    Save,
    /// Dismiss the request.
    NotNow,
}

/// An answer to a suggestion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SuggestionAnswer {
    Ignore,
    /// Accept the proposal (a project).
    Accept,
    /// The credential is in this environment: the proposal or the other choice.
    Environment(Environment),
}

/// One question that waits, with the time left of its wait.
#[derive(Debug, Clone)]
pub(super) struct Waiting {
    pub(super) run: PendingRun,
    pub(super) left: Duration,
}

/// One question of another Mac, with the time left until it ends on the relay.
#[derive(Debug, Clone)]
pub(super) struct RemoteWaiting {
    pub(super) question: RemoteQuestion,
    pub(super) left: Duration,
}

impl RemoteWaiting {
    fn run(&self) -> &PendingRun {
        &self.question.question.run
    }
}

/// The remembered answer that the bottom bar offers as its main button.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Primary {
    /// "Allow ACTION in PROJECT".
    InProject(ActionKind),
    /// "Allow production: ACTION in PROJECT".
    Production(ActionKind),
    /// "Development" (and "Production") for a credential that is production only by
    /// default.
    Correct,
}

/// An answer of the owner on the card.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Answer {
    Deny,
    Once,
    /// Allow this run once and separately authorize later model evaluation.
    Evaluate {
        offer: EvaluationOffer,
        confirmations: Vec<EvaluationConfirmation>,
    },
    InProject(ActionKind),
    Production(ActionKind),
    /// Mark the credential as development: the owner check first.
    Development {
        item_id: u64,
        name: String,
    },
    /// Mark the credential as production: stricter, no check.
    MarkProduction {
        item_id: u64,
        name: String,
    },
    Never,
    AlwaysAsk,
    Disconnect,
}

// ---- Pure parts, for the tests. ----

/// The time left of a wait of `timeout` that started `age` ago.
pub(super) fn time_left(timeout: Duration, age: Duration) -> Duration {
    timeout.saturating_sub(age)
}

/// "4:52": minutes and seconds, rounded up, so a wait shows "0:00" only at its end.
pub(super) fn clock(left: Duration) -> String {
    let seconds = left.as_millis().div_ceil(1000);
    format!("{}:{:02}", seconds / 60, seconds % 60)
}

/// The kind of action in a button: "Read", "Change", "Deploy", "Delete".
pub(super) fn action_label(action: ActionKind) -> &'static str {
    match action {
        ActionKind::Read => "Read",
        ActionKind::Change => "Change",
        ActionKind::Deploy => "Deploy",
        ActionKind::Delete => "Delete",
    }
}

/// The main answer of a question from the answers that can take effect: production
/// first, then the project answer, then the correction of a default production value.
pub(super) fn primary(question: &QuestionInfo) -> Option<Primary> {
    let offered =
        |wanted: fn(&AnswerKind) -> Option<Primary>| question.valid_answers.iter().find_map(wanted);
    let in_project = question.project.is_some();
    offered(|answer| match answer {
        AnswerKind::Production(action) => Some(Primary::Production(*action)),
        _ => None,
    })
    .filter(|_| in_project)
    .or_else(|| {
        offered(|answer| match answer {
            AnswerKind::InProject(action) => Some(Primary::InProject(*action)),
            _ => None,
        })
        .filter(|_| in_project)
    })
    .or_else(|| {
        offered(|answer| match answer {
            AnswerKind::CorrectEnvironment => Some(Primary::Correct),
            _ => None,
        })
        .filter(|_| question.items.iter().any(|item| item.unconfirmed))
    })
}

/// A project name for a button, at most [`SHORT_PROJECT`] characters.
fn short(text: &str) -> String {
    let mut cut: String = text.chars().take(SHORT_PROJECT).collect();
    if cut.len() < text.len() {
        cut.pop();
        cut.push('…');
    }
    cut
}

/// The label of the main button, or `None` when the question offers no remembered
/// answer.
pub(super) fn primary_label(question: &QuestionInfo) -> Option<String> {
    let project = question
        .project
        .as_ref()
        .map(|project| short(&project.label));
    Some(match (primary(question)?, project) {
        (Primary::InProject(action), Some(project)) => {
            format!("Allow {} in {project}", action_label(action))
        }
        (Primary::Production(action), Some(project)) => {
            format!("Allow production: {} in {project}", action_label(action))
        }
        (Primary::Correct, _) => "Development".to_owned(),
        _ => return None,
    })
}

/// The decision to select: the selected one while it waits, else the one at its place,
/// else the last one.
pub(super) fn next_selection<T: Copy + PartialEq>(
    ids: &[T],
    selected: Option<T>,
    index: usize,
) -> Option<T> {
    if selected.is_some_and(|id| ids.contains(&id)) {
        return selected;
    }
    ids.get(index.min(ids.len().saturating_sub(1))).copied()
}

/// A command as a shell would read it: an argument with a space or a quote is quoted.
pub(super) fn shell_words(command: &[String]) -> String {
    command
        .iter()
        .map(|arg| {
            let plain = !arg.is_empty()
                && arg
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-_./=:@%+,".contains(c));
            if plain {
                arg.clone()
            } else {
                format!("'{}'", arg.replace('\'', "'\\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// The hosts that the command names, as the broker compares them.
fn command_hosts(command: &[String]) -> Vec<String> {
    let mut hosts: Vec<String> = crate::broker::shell_risk::command_hosts(command)
        .iter()
        .filter_map(|host| crate::vault::answers::normal_host(host))
        .collect();
    hosts.sort();
    hosts.dedup();
    hosts
}

/// The credentials of a question: "Stripe live", "A and B", or "A and 2 more".
fn item_names(run: &PendingRun) -> String {
    let names: Vec<&str> = if run.question.items.is_empty() {
        run.env_names.iter().map(String::as_str).collect()
    } else {
        run.question
            .items
            .iter()
            .map(|item| item.name.as_str())
            .collect()
    };
    match names.as_slice() {
        [] => "a credential".to_owned(),
        [one] => (*one).to_owned(),
        [one, two] => format!("{one} and {two}"),
        [one, rest @ ..] => format!("{one} and {} more", rest.len()),
    }
}

/// The project of a question for the facts and the list.
fn project_text(run: &PendingRun) -> String {
    match (&run.question.project, run.cwd.is_empty()) {
        (Some(project), _) => project.label.clone(),
        (None, true) => "No project".to_owned(),
        (None, false) => format!("No project ({})", shown_path(&run.cwd, SHOWN_PATH)),
    }
}

fn production(run: &PendingRun) -> bool {
    run.question.production || run.question.items.iter().any(|item| item.production)
}

/// "Codex asks for a Stripe test key".
pub(super) fn request_title(request: &CredentialRequest) -> String {
    format!("{} asks for a {}", request.agent_name, request.name)
}

/// The project of a request, or "No project".
fn request_project(request: &CredentialRequest) -> String {
    if request.project_label.is_empty() {
        "No project".to_owned()
    } else {
        request.project_label.clone()
    }
}

/// The domains of "where to get it", as the owner must read them: the hosts of the URLs
/// in the text (after user info such as `stripe.com@`), else the hosts of bare words such
/// as `dashboard.stripe.com/apikeys`. A host that is not plain ASCII is left out, so a
/// look-alike name never shows as a domain. Apassy shows them as text and opens no link
/// (ADR 0025 §6: an agent wrote the text).
pub(super) fn where_domains(text: &str) -> Vec<String> {
    use crate::vault::providers::url_hosts;
    let mut hosts = url_hosts(text);
    if hosts.is_empty() {
        hosts = text
            .split_whitespace()
            .filter(|word| word.contains('.') && !word.contains("://"))
            .flat_map(|word| {
                let word = word.trim_matches(|c: char| ",;:()<>\"'`".contains(c));
                url_hosts(&format!("https://{word}"))
            })
            .filter(|host| {
                // A domain ends with a word of letters: "e.g." and "v1.2" are none.
                host.contains('.')
                    && host.rsplit('.').next().is_some_and(|tld| {
                        tld.len() >= 2 && tld.chars().all(|c| c.is_ascii_alphabetic())
                    })
            })
            .collect();
    }
    let mut unique: Vec<String> = Vec::new();
    for host in hosts {
        if !unique.contains(&host) {
            unique.push(host);
        }
    }
    unique
}

/// The name of an environment for a button: "Development".
fn environment_label(environment: Environment) -> &'static str {
    match environment {
        Environment::Production => "Production",
        Environment::Staging => "Staging",
        Environment::Development => "Development",
        Environment::Local => "Local",
    }
}

/// The environment before a raise to production, from the facts of a correction.
fn raised_from(correction: &Correction) -> Option<Environment> {
    correction
        .facts
        .get(RAISED_FROM_FACT)
        .and_then(Value::as_str)
        .and_then(|text| Environment::parse(text).ok())
}

/// The question of a suggestion: "Is OpenAI API a development key?" (a key, as in the
/// mockup; another kind is a credential) or "Limit Stripe key to acme-billing?".
pub(super) fn suggestion_question(
    correction: &Correction,
    name: &str,
    kind: CredentialKind,
) -> String {
    let noun = match kind {
        CredentialKind::ApiKey | CredentialKind::SshKey => "key",
        CredentialKind::Database => "database",
        CredentialKind::Login | CredentialKind::Custom => "credential",
    };
    match correction.kind {
        CorrectionKind::Environment => {
            format!("Is {name} a {} {noun}?", correction.proposed)
        }
        CorrectionKind::Project => format!("Limit {name} to {}?", correction.proposed),
    }
}

/// The line under a suggestion in the list.
fn suggestion_subtitle(correction: &Correction) -> String {
    match correction.kind {
        CorrectionKind::Environment => "Development or production?".to_owned(),
        CorrectionKind::Project => format!("Only in {}?", correction.proposed),
    }
}

/// The choices of a suggestion besides Ignore, the proposal first: the proposed
/// environment and the other one (production, or the environment before a raise), or
/// the project.
pub(super) fn suggestion_choices(correction: &Correction) -> Vec<(String, SuggestionAnswer)> {
    match correction.kind {
        CorrectionKind::Project => vec![(
            format!("Only in {}", short(&correction.proposed)),
            SuggestionAnswer::Accept,
        )],
        CorrectionKind::Environment => {
            let Ok(proposed) = Environment::parse(&correction.proposed) else {
                return Vec::new();
            };
            let other = if proposed == Environment::Production {
                raised_from(correction).unwrap_or(Environment::Development)
            } else {
                Environment::Production
            };
            [proposed, other]
                .into_iter()
                .map(|environment| {
                    (
                        environment_label(environment).to_owned(),
                        SuggestionAnswer::Environment(environment),
                    )
                })
                .collect()
        }
    }
}

/// What an answer to a suggestion does: the answer to the correction, the environment
/// that the owner chose instead of the proposal, and the environment that the
/// credential gets. The owner check is [`suggestion_needs_check`].
pub(super) fn suggestion_outcome(
    correction: &Correction,
    answer: SuggestionAnswer,
) -> (CorrectionAnswer, Option<Environment>, Option<Environment>) {
    let (answer, chosen) = match answer {
        SuggestionAnswer::Ignore => (CorrectionAnswer::Ignored, None),
        SuggestionAnswer::Accept => (CorrectionAnswer::Accepted, None),
        SuggestionAnswer::Environment(environment)
            if correction.kind == CorrectionKind::Environment
                && correction.proposed == environment.as_str() =>
        {
            (CorrectionAnswer::Accepted, None)
        }
        SuggestionAnswer::Environment(environment) => {
            (CorrectionAnswer::Ignored, Some(environment))
        }
    };
    let result = chosen.or_else(|| OwnerSession::suggestion_environment(correction, answer));
    (answer, chosen, result)
}

/// True when the answer passes the owner check first: the bouncer is then less careful.
/// The vault decides (`Vault::needs_owner_check_for_correction`).
pub(super) fn suggestion_needs_check(
    app: &DesktopApp,
    correction: &Correction,
    answer: SuggestionAnswer,
) -> bool {
    let (settle, chosen, _) = suggestion_outcome(correction, answer);
    app.owner_ui
        .session
        .answer_needs_check(correction.id, settle, chosen)
}

/// The facts of a correction as rows for the owner, in the order of the mockup: the
/// uses, the project, where it sends, the provider, then the signal. Lists are joined,
/// a provider shows its name, and a folder its short path. The bookkeeping of the
/// correction (whether it applied, the environment before) shows no row: "Before"
/// names the environment that Ignore gives back.
pub(super) fn fact_rows(facts: &Value) -> Vec<(String, String)> {
    use crate::broker::corrections::{APPLIED_FACT, PREVIOUS_ENVIRONMENT_FACT};
    const ORDER: [&str; 8] = [
        "uses",
        "project_label",
        "project_key",
        "hosts",
        "provider",
        "agents",
        "signal",
        RAISED_FROM_FACT,
    ];
    let Some(map) = facts.as_object() else {
        return match facts {
            Value::Null => Vec::new(),
            other => vec![("Facts".to_owned(), other.to_string())],
        };
    };
    let mut keys: Vec<&String> = map
        .keys()
        .filter(|key| *key != APPLIED_FACT && *key != PREVIOUS_ENVIRONMENT_FACT)
        .collect();
    keys.sort_by_key(|key| {
        (
            ORDER
                .iter()
                .position(|known| known == key)
                .unwrap_or(ORDER.len()),
            (*key).clone(),
        )
    });
    keys.into_iter()
        .filter(|key| !map[*key].is_null())
        .map(|key| (fact_label(key), fact_value(key, &map[key])))
        .collect()
}

fn fact_label(key: &str) -> String {
    match key {
        "signal" => "Seen".to_owned(),
        "provider" => "Provider".to_owned(),
        "hosts" => "Sends to".to_owned(),
        "uses" => "Uses".to_owned(),
        "project_label" => "Project".to_owned(),
        "project_key" => "Folder".to_owned(),
        "agents" => "Agents".to_owned(),
        RAISED_FROM_FACT => "Before".to_owned(),
        other => {
            let words = other.replace('_', " ");
            let mut chars = words.chars();
            chars.next().map_or_else(String::new, |first| {
                first.to_uppercase().chain(chars).collect()
            })
        }
    }
}

fn fact_value(key: &str, value: &Value) -> String {
    let text = |value: &Value| match value {
        Value::String(text) => text.clone(),
        Value::Bool(true) => "Yes".to_owned(),
        Value::Bool(false) => "No".to_owned(),
        other => other.to_string(),
    };
    match (key, value) {
        ("provider", Value::String(id)) => crate::vault::providers::find(id)
            .map_or_else(|| id.clone(), |provider| provider.label.clone()),
        ("project_key", Value::String(path)) => shown_path(path, SHOWN_PATH),
        // The use log has no other host for the item (`development_hosts`).
        ("hosts", Value::Array(values)) if !values.is_empty() => {
            format!(
                "only {}",
                values.iter().map(text).collect::<Vec<_>>().join(", ")
            )
        }
        (_, Value::Array(values)) => values.iter().map(text).collect::<Vec<_>>().join(", "),
        (_, value) => text(value),
    }
}

// ---- The queue. ----

fn queue(app: &DesktopApp) -> Option<(Arc<ApprovalQueue>, Duration)> {
    match &app.broker {
        BrokerState::Running(handle) => {
            Some((Arc::clone(handle.approvals()), handle.approval_timeout()))
        }
        _ => None,
    }
}

/// The questions that wait, the least time left first.
pub(super) fn waiting(app: &DesktopApp, pending: &[PendingRun]) -> Vec<Waiting> {
    let (ages, timeout) = match queue(app) {
        Some((queue, timeout)) => (
            queue
                .pending_with_age()
                .into_iter()
                .map(|(run, age)| (run.id, age))
                .collect::<BTreeMap<_, _>>(),
            timeout,
        ),
        None => (BTreeMap::new(), QUESTION_WAIT),
    };
    let mut waiting: Vec<Waiting> = pending
        .iter()
        .map(|run| Waiting {
            left: time_left(timeout, ages.get(&run.id).copied().unwrap_or_default()),
            run: run.clone(),
        })
        .collect();
    waiting.sort_by_key(|waiting| waiting.left);
    waiting
}

/// The open credential requests of agents (ADR 0025 §6).
fn open_requests(app: &DesktopApp) -> usize {
    app.owner_ui
        .session
        .open_credential_requests()
        .map_or(0, |requests| requests.len())
}

/// The questions of other Macs of the vault that still wait, the soonest end first.
pub(super) fn remote_waiting(app: &DesktopApp) -> Vec<RemoteWaiting> {
    let Some(questions) = &app.owner.questions else {
        return Vec::new();
    };
    let now = unix_now();
    questions
        .view()
        .remote
        .into_iter()
        .filter(|question| question.expires_at() > now)
        .map(|question| RemoteWaiting {
            left: Duration::from_secs(question.expires_at().saturating_sub(now)),
            question,
        })
        .collect()
}

/// The red count of Decisions in the sidebar: what blocks an agent, the waiting
/// questions (also those of other Macs) and the open credential requests. Suggestions
/// do not count.
pub(super) fn badge_count(app: &DesktopApp, pending: &[PendingRun]) -> usize {
    let access = app
        .owner_ui
        .session
        .with_vault(|v| {
            v.scoped_access_requests()
                .map(|rows| {
                    rows.iter()
                        .filter(|r| r.state == "open" && v.access_record_live(r))
                        .count()
                })
                .unwrap_or(0)
        })
        .unwrap_or(0);
    pending.len() + remote_waiting(app).len() + open_requests(app) + access
}

/// Everything that waits for the owner, in the order of the list.
pub(super) fn open(app: &DesktopApp, pending: &[PendingRun]) -> Open {
    let session = &app.owner_ui.session;
    Open {
        legacy_access: session
            .with_vault(|v| {
                v.access_requests(true, 1000)
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|r| v.scoped_access_request(r.id).is_err())
                    .collect()
            })
            .unwrap_or_default(),
        access: session
            .with_vault(|v| v.scoped_access_requests().unwrap_or_default())
            .unwrap_or_default(),
        waiting: waiting(app, pending),
        remote: remote_waiting(app),
        requests: session.open_credential_requests().unwrap_or_default(),
        suggestions: session.open_suggestions().unwrap_or_default(),
    }
}

/// The selected question, by run ID.
#[cfg(test)]
pub(super) fn selected(app: &DesktopApp) -> Option<u64> {
    match app.ui.decisions.selected {
        Some(Key::Run(run_id)) => Some(run_id),
        _ => None,
    }
}

/// The selected decision.
#[cfg(test)]
pub(super) fn selected_key(app: &DesktopApp) -> Option<Key> {
    app.ui.decisions.selected
}

/// Select a decision, as a click on its row does.
#[cfg(test)]
pub(super) fn select_key(app: &mut DesktopApp, key: Key) {
    app.ui.decisions.forget_evaluation();
    app.ui.decisions.routed = false;
    app.ui.decisions.show_activity = false;
    app.ui.decisions.activity_id = None;
    app.ui.decisions.selected = Some(key);
    app.ui.decisions.disconnect = None;
}

/// Type into the paste field of the selected request.
#[cfg(test)]
pub(super) fn set_paste(app: &mut DesktopApp, text: &str) {
    let paste = &mut app.ui.decisions.paste;
    paste.erase();
    paste.0.push_str(text);
}

/// The paste of the selected request is empty.
#[cfg(test)]
pub(super) fn paste_is_empty(app: &DesktopApp) -> bool {
    app.ui.decisions.paste.0.is_empty()
}

/// "Disconnect AGENT…" waits for its confirmation.
#[cfg(test)]
pub(super) fn disconnecting(app: &DesktopApp) -> bool {
    app.ui.decisions.disconnect.is_some()
}

#[cfg(test)]
pub(super) fn evaluation_confirmations(app: &DesktopApp) -> Option<Vec<EvaluationConfirmation>> {
    app.ui
        .decisions
        .evaluation
        .as_ref()
        .map(|draft| draft.confirmations.clone())
}

/// Select a question, for example from the banner of another view.
pub(super) fn select(app: &mut DesktopApp, run_id: u64) {
    app.ui.decisions.forget_evaluation();
    app.ui.decisions.routed = false;
    app.ui.decisions.show_activity = false;
    app.ui.decisions.activity_id = None;
    app.ui.decisions.selected = Some(Key::Run(run_id));
    app.ui.decisions.disconnect = None;
}

/// A notification is a hint to one exact request, never an approval or a next-item action.
pub(super) fn route_notification(
    app: &mut DesktopApp,
    destination: crate::desktop::notify::NotificationDestination,
) {
    use crate::desktop::inbox::EventKey;
    use crate::desktop::notify::NotificationDestination;
    app.ui.decisions.paste.erase();
    app.ui.decisions.forget_evaluation();
    app.ui.decisions.disconnect = None;
    app.ui.decisions.form = None;
    app.ui.decisions.routed = true;
    app.ui.decisions.activity_id = None;
    app.ui.decisions.show_activity = false;
    app.ui.decisions.selected = match destination {
        NotificationDestination::Event {
            key: EventKey::Run(id),
            ..
        } => Some(Key::Run(id)),
        NotificationDestination::Event {
            key: EventKey::Request(id),
            ..
        } => Some(Key::Request(id)),
        NotificationDestination::Event {
            key: EventKey::Correction(id),
            ..
        } => Some(Key::Suggestion(id)),
        NotificationDestination::Event {
            key: EventKey::Activity(id),
            ..
        } => {
            app.ui.decisions.activity_id = Some(id);
            app.ui.decisions.show_activity = true;
            None
        }
        NotificationDestination::Requests => {
            app.set_note("This request is no longer waiting. Review current requests or Activity.");
            None
        }
    };
    app.place = crate::desktop::Place::Decisions;
    app.ui.sidebar_float = false;
}

fn sync_selection(state: &mut State, open: &Open) {
    let keys = open.keys();
    state.selected = if state.routed {
        state.selected.filter(|key| keys.contains(key))
    } else {
        next_selection(&keys, state.selected, state.index)
    };
    if state
        .evaluation
        .as_ref()
        .is_some_and(|draft| state.selected != Some(Key::Run(draft.run_id)))
    {
        state.forget_evaluation();
    }
    if let Some(selected) = state.selected {
        state.index = keys.iter().position(|key| *key == selected).unwrap_or(0);
    }
    if state
        .disconnect
        .as_ref()
        .is_some_and(|(key, _)| !keys.contains(key))
    {
        state.disconnect = None;
    }
    // The paste belongs to one request: another selection erases it.
    let request = match state.selected {
        Some(Key::Request(id)) => open.requests.iter().find(|request| request.id == id),
        _ => None,
    };
    if state.form.as_ref().map(|(id, _)| *id) != request.map(|request| request.id) {
        state.paste.erase();
        state.form = request.map(|request| (request.id, request.folder.clone()));
    }
}

/// Erase the paste of a request and the undo history of its field.
fn erase_paste(app: &mut DesktopApp, ctx: &egui::Context) {
    app.ui.decisions.paste.erase();
    super::forget_secret_field(ctx, REQUEST_FIELD);
}

// ---- The list column. ----

/// The mark at the left of a row or a header: the round avatar of the agent that asks,
/// or the tile of the credential of a suggestion.
#[derive(Clone)]
enum Mark {
    Agent(String),
    Tile(kit::Tile),
}

/// One row of the list, with its key.
struct ListRow {
    key: Key,
    mark: Mark,
    title: String,
    subtitle: String,
    production: bool,
    left: Option<String>,
}

fn list_rows(open: Open) -> Vec<Group<ListRow>> {
    let mut groups = Vec::new();
    let waiting: Vec<ListRow> = open
        .waiting
        .into_iter()
        .map(|waiting| {
            let run = &waiting.run;
            ListRow {
                key: Key::Run(run.id),
                mark: Mark::Agent(run.agent.clone()),
                title: item_names(run),
                subtitle: format!("{} · {}", run.agent, project_text(run)),
                production: production(run),
                left: Some(clock(waiting.left)),
            }
        })
        .chain(open.remote.into_iter().map(|remote| {
            let run = remote.run();
            ListRow {
                key: Key::Remote(remote.question.id),
                mark: Mark::Agent(run.agent.clone()),
                title: item_names(run),
                subtitle: remote_subtitle(&remote.question),
                production: production(run),
                left: Some(clock(remote.left)),
            }
        }))
        .collect();
    let access: Vec<ListRow> = open
        .access
        .into_iter()
        .map(|r| ListRow {
            key: Key::Access(r.id),
            mark: Mark::Agent(r.card.card.agent.name.clone()),
            title: r.card.card.item.name.clone(),
            subtitle: format!(
                "{} (id {}) · {}",
                r.card.card.agent.name, r.card.card.agent.id, r.state
            ),
            production: r.card.card.item.environment
                == crate::questions::access_request::Environment::Production,
            left: (r.state == "open").then(|| {
                clock(Duration::from_secs(
                    r.card.card.expires_at.saturating_sub(unix_now()),
                ))
            }),
        })
        .collect();
    let legacy_access: Vec<ListRow> = open
        .legacy_access
        .into_iter()
        .map(|r| ListRow {
            key: Key::LegacyAccess(r.id),
            mark: Mark::Agent(r.agent_name.clone()),
            title: r.item_name,
            subtitle: format!("{} · Mac review", r.agent_name),
            production: false,
            left: None,
        })
        .collect();
    let requests: Vec<ListRow> = open
        .requests
        .into_iter()
        .map(|request| ListRow {
            key: Key::Request(request.id),
            mark: Mark::Agent(request.agent_name.clone()),
            subtitle: format!("{} · {}", request.agent_name, request_project(&request)),
            title: request.name,
            production: false,
            left: None,
        })
        .collect();
    let suggestions: Vec<ListRow> = open
        .suggestions
        .into_iter()
        .map(|(correction, item)| ListRow {
            key: Key::Suggestion(correction.id),
            mark: Mark::Tile(super::credential_tile(item.kind, &item.service, &item.name)),
            title: item.name,
            subtitle: suggestion_subtitle(&correction),
            production: false,
            left: None,
        })
        .collect();
    for (title, rows) in [
        ("Waiting", waiting),
        ("Access requests", access),
        ("Legacy access notes", legacy_access),
        ("Requests", requests),
        ("Suggestions", suggestions),
    ] {
        if !rows.is_empty() {
            groups.push(Group {
                title: title.to_owned(),
                rows,
            });
        }
    }
    groups
}

pub(super) fn list_column(app: &mut DesktopApp, ui: &mut egui::Ui, pending: &[PendingRun]) {
    let open = open(app, pending);
    let receive_problem = app
        .owner
        .questions
        .as_ref()
        .and_then(|questions| questions.view().receive_problem);
    sync_selection(&mut app.ui.decisions, &open);
    let subtitle = app
        .owner_ui
        .session
        .week_counts()
        .map(|counts| counts.line())
        .unwrap_or_default();
    let mut history = false;
    columns::list_toolbar(ui, "Decisions", &subtitle, |ui| {
        history = kit::small_button(ui, "Activity", Style::Bordered).clicked();
    });
    if history {
        app.ui.decisions.forget_evaluation();
        app.ui.decisions.selected = None;
        app.ui.decisions.routed = true;
        app.ui.decisions.activity_id = None;
        app.ui.decisions.show_activity = true;
    }
    if app.ui.decisions.routed
        && app.ui.decisions.selected.is_none()
        && !app.ui.decisions.show_activity
    {
        columns::list_note(
            ui,
            "This request is no longer waiting. Review current requests or Activity.",
        );
    }
    if let Some(problem) = receive_problem.as_deref() {
        columns::list_note(ui, problem);
    }
    // The rows come first in the layout, so ⌘2 and Tab reach them before the footer.
    let notice = notifications_off(app);
    let area = ui.available_rect_before_wrap();
    let footer_top = area.bottom() - if notice.is_some() { FOOTER } else { 0.0 };
    let rows_rect = Rect::from_min_max(area.min, Pos2::new(area.right(), footer_top));
    let groups = list_rows(open);
    let empty = groups.is_empty();
    let selected = app.ui.decisions.selected;
    let mut chosen = None;
    let mut rows_ui = ui.new_child(egui::UiBuilder::new().max_rect(rows_rect));
    columns::grouped_rows(
        &mut rows_ui,
        "decisions-list",
        &groups,
        true,
        |ui, row| {
            let response = ui
                .push_id(("decision-row", row.key), |ui| {
                    decision_row(
                        ui,
                        &DecisionRow {
                            mark: &row.mark,
                            title: &row.title,
                            subtitle: &row.subtitle,
                            production: row.production,
                            left: row.left.as_deref(),
                            selected: selected == Some(row.key),
                        },
                    )
                })
                .inner;
            if response.clicked() {
                chosen = Some(row.key);
            }
        },
        // With nothing open, the list says so, and the detail says "All clear", as in
        // the mockup.
        |ui| {
            if empty && receive_problem.is_none() {
                ui.add_space(40.0);
                columns::list_note(ui, "Nothing needs you");
            }
        },
    );
    if let Some(summary) = notice {
        let footer = Rect::from_min_max(Pos2::new(area.left(), footer_top), area.max);
        notifications_footer(app, ui, footer, &summary);
    }
    ui.allocate_rect(area, Sense::hover());
    if let Some(key) = chosen {
        app.ui.decisions.forget_evaluation();
        app.ui.decisions.routed = false;
        app.ui.decisions.show_activity = false;
        app.ui.decisions.activity_id = None;
        app.ui.decisions.selected = Some(key);
        app.ui.decisions.disconnect = None;
    }
}

/// One row of the list.
struct DecisionRow<'a> {
    mark: &'a Mark,
    title: &'a str,
    subtitle: &'a str,
    production: bool,
    /// The time left of a question, in orange.
    left: Option<&'a str>,
    selected: bool,
}

/// A row of the list as [`kit::list_row`], with the time left in orange at the right
/// and the red dot of production before it.
fn decision_row(ui: &mut egui::Ui, row: &DecisionRow<'_>) -> egui::Response {
    let width = ui.available_width();
    let (rect, response) = ui.allocate_exact_size(Vec2::new(width, 48.0), Sense::click());
    let name = format!(
        "{}, {}{}{}",
        row.title,
        row.subtitle,
        if row.production { ", production" } else { "" },
        row.left
            .map_or_else(String::new, |left| format!(", {left} left"))
    );
    response.widget_info(|| {
        WidgetInfo::selected(WidgetType::SelectableLabel, true, row.selected, &name)
    });
    if response.gained_focus() {
        response.scroll_to_me(None);
    }
    if !ui.is_rect_visible(rect) {
        return response;
    }
    let painter = ui.painter();
    if row.selected {
        painter.rect_filled(rect, 8, kit::SELECTION);
    } else if response.hovered() {
        painter.rect_filled(rect, 8, egui::Color32::from_rgb(247, 247, 248));
    }
    if response.has_focus() {
        kit::inner_focus_ring(painter, rect, 8);
    }
    // An agent has a round avatar of 28 points, a credential a tile of 32, as in the
    // mockup.
    let side = match row.mark {
        Mark::Agent(_) => 28.0,
        Mark::Tile(_) => 32.0,
    };
    let tile_rect = Rect::from_min_size(
        Pos2::new(rect.left() + 8.0, rect.center().y - side / 2.0),
        Vec2::splat(side),
    );
    match row.mark {
        Mark::Agent(name) => kit::paint_avatar(ui, tile_rect, name),
        Mark::Tile(tile) => kit::paint_tile(ui, tile_rect, tile),
    }
    let (title_color, sub_color, time_color, dot) = if row.selected {
        let white = egui::Color32::WHITE;
        (white, egui::Color32::from_white_alpha(210), white, white)
    } else {
        (kit::LABEL, kit::SECONDARY, TIMER, kit::PRODUCTION)
    };
    let galley = |value: egui::RichText, max: f32| {
        WidgetText::from(value).into_galley(ui, Some(TextWrapMode::Truncate), max, TextStyle::Body)
    };
    let mut right = rect.right() - 8.0;
    if let Some(left) = row.left {
        let time = galley(timer_text(left, Font::Callout).color(time_color), 60.0);
        right -= time.size().x;
        painter.galley(
            Pos2::new(right, rect.center().y - time.size().y / 2.0),
            time,
            time_color,
        );
        right -= 6.0;
    }
    if row.production {
        painter.circle_filled(Pos2::new(right - 3.5, rect.center().y), 3.5, dot);
        right -= 13.0;
    }
    let left = tile_rect.right() + 10.0;
    let text_width = (right - left).max(10.0);
    let title = galley(kit::row_title(row.title).color(title_color), text_width);
    let subtitle = galley(
        kit::text(row.subtitle, Font::Callout).color(sub_color),
        text_width,
    );
    let top = rect.center().y - (title.size().y + subtitle.size().y) / 2.0;
    let title_height = title.size().y;
    painter.galley(Pos2::new(left, top), title, title_color);
    painter.galley(Pos2::new(left, top + title_height), subtitle, sub_color);
    response
}

// ---- The detail column. ----

pub(super) fn detail_column(app: &mut DesktopApp, ui: &mut egui::Ui, pending: &[PendingRun]) {
    let mut open = open(app, pending);
    sync_selection(&mut app.ui.decisions, &open);
    if app.ui.decisions.show_activity {
        let activity_id = app.ui.decisions.activity_id;
        columns::detail_toolbar(ui, |_| {});
        columns::detail_body(ui, ("notification-activity", activity_id), |ui| {
            let rows = app
                .owner_ui
                .session
                .activity(crate::vault::MAX_ACTIVITY_ROWS)
                .unwrap_or_default();
            let exact: Vec<_> = rows
                .into_iter()
                .filter(|row| activity_id.is_none_or(|id| row.id == id))
                .collect();
            super::timeline::access_timeline(
                app,
                ui,
                &exact,
                "notification-activity-history",
                "Activity",
                "This activity is no longer available.",
                true,
            );
        });
        return;
    }
    match app.ui.decisions.selected {
        Some(Key::LegacyAccess(id)) => {
            if let Some(note) = open.legacy_access.into_iter().find(|r| r.id == id) {
                columns::detail_toolbar(ui, |ui| {
                    ui.heading("Legacy access note");
                });
                columns::detail_body(ui, ("legacy-access", id), |ui| {
                    ui.heading(format!("{} asks for {}", note.agent_name, note.item_name));
                    ui.label(format!(
                        "Original note: {}",
                        crate::vault::format_utc(note.created_at)
                    ));
                    ui.strong("The agent says");
                    ui.label(crate::questions::access_request::display_text(&note.reason));
                    ui.label("This old note has no complete scope. It cannot allow access from an iPhone.");
                    if ui.button("Send a new Deny-only card to iPhone").clicked() {
                        let response = app
                            .owner_ui
                            .session
                            .with_vault(|v| crate::broker::access_once::dispatch_legacy(v, id));
                        match response {
                            Some(r) if r.ok => {
                                if let Some(id) =
                                    r.result.as_ref().and_then(|r| r["request_id"].as_u64())
                                {
                                    app.ui.decisions.selected = Some(Key::Access(id));
                                }
                            }
                            _ => {
                                app.set_err("The note could not be dispatched. Review on this Mac.")
                            }
                        }
                    }
                });
                return;
            }
        }
        Some(Key::Access(id)) => {
            if let Some(r) = open.access.into_iter().find(|r| r.id == id) {
                return access_detail(app, ui, &r);
            }
        }
        Some(Key::Run(id)) => {
            if let Some(current) = open.waiting.into_iter().find(|w| w.run.id == id) {
                return question_detail(app, ui, pending, current);
            }
        }
        Some(Key::Request(id)) => {
            if let Some(request) = open.requests.into_iter().find(|r| r.id == id) {
                return request_detail(app, ui, pending, &request);
            }
        }
        Some(Key::Suggestion(id)) => {
            if let Some(index) = open.suggestions.iter().position(|(c, _)| c.id == id) {
                let (correction, item) = open.suggestions.swap_remove(index);
                return suggestion_detail(app, ui, pending, &correction, &item);
            }
        }
        Some(Key::Remote(id)) => {
            if let Some(remote) = open.remote.into_iter().find(|r| r.question.id == id) {
                return remote_detail(app, ui, pending, remote);
            }
        }
        None => {}
    }
    columns::detail_toolbar(ui, |_| {});
    columns::detail_body(ui, ("decision", None::<u64>), |ui| {
        super::shell::banners(app, ui, pending);
        let answered = app
            .owner
            .questions
            .as_ref()
            .map(|questions| answered_lines(&questions.view(), unix_now()))
            .unwrap_or_default();
        for line in &answered {
            kit::tone_note(ui, line, Tone::Accent);
        }
        // The list carries the receiving error; do not claim that all requests are clear.
        if app
            .owner
            .questions
            .as_ref()
            .is_some_and(|questions| questions.view().receive_problem.is_some())
        {
            return;
        }
        columns::nothing_selected(
            ui,
            Icon::CheckCircle,
            if app.ui.decisions.routed {
                "Select a Request"
            } else {
                "All clear"
            },
            if app.ui.decisions.routed {
                "Review a current request from the list. Activity keeps completed outcomes."
            } else {
                "Nothing waits for you. A new question also shows as a macOS notification."
            },
        );
    });
}

/// How long "Answered on DEVICE" stays in Decisions.
const ANSWERED_SHOWN_FOR: u64 = 10 * 60;

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// The questions that another device answered through the relay in the last minutes,
/// newest first: "AGENT: Answered on DEVICE".
pub(super) fn answered_lines(view: &crate::questions::QuestionsView, now: u64) -> Vec<String> {
    view.answered
        .iter()
        .rev()
        .filter(|answered| answered.at.saturating_add(ANSWERED_SHOWN_FOR) >= now)
        .map(|answered| {
            let agent = shown_path(&answered.agent, 40);
            let device = shown_path(&answered.device_name, 40);
            format!("{agent}: Answered on {device}")
        })
        .collect()
}

/// Why a waiting question stays on this Mac, when it does.
fn local_only_note(app: &DesktopApp, run_id: u64) -> Option<String> {
    app.owner
        .questions
        .as_ref()
        .and_then(|questions| questions.view().local_only.get(&run_id).cloned())
}

/// The detail of a waiting question.
fn question_detail(
    app: &mut DesktopApp,
    ui: &mut egui::Ui,
    pending: &[PendingRun],
    current: Waiting,
) {
    prepare_evaluation(app, current.run.id);
    let mut answer = None;
    columns::detail_toolbar(ui, |ui| more_menu(ui, &current.run, &mut answer));
    bottom_bar(ui, ("decision-bar", current.run.id), |ui| {
        action_bar(ui, &current.run, &mut answer);
    });
    decision_body(ui, ("decision", Some(current.run.id)), |ui| {
        super::shell::banners(app, ui, pending);
        draw_question(app, ui, &current, &mut answer, None);
    });
    if let Some(answer) = answer {
        apply(app, ui.ctx(), &current.run, answer);
    }
    disconnect_sheet(app, ui.ctx());
}

/// "AGENT · PROJECT · from MAC": the subtitle of a question of another Mac.
pub(super) fn remote_subtitle(question: &RemoteQuestion) -> String {
    let run = &question.question.run;
    format!(
        "{} · {} · from {}",
        run.agent,
        project_text(run),
        shown_path(question.asker(), 40)
    )
}

/// The detail of a question of another Mac: the same facts and bar as a question of this
/// Mac, with the asking Mac.
fn remote_detail(
    app: &mut DesktopApp,
    ui: &mut egui::Ui,
    pending: &[PendingRun],
    remote: RemoteWaiting,
) {
    app.ui.decisions.forget_evaluation();
    let run = remote.run().clone();
    let mut answer = None;
    columns::detail_toolbar(ui, |ui| more_menu(ui, &run, &mut answer));
    bottom_bar(ui, ("decision-remote-bar", remote.question.id), |ui| {
        action_bar(ui, &run, &mut answer);
    });
    let current = Waiting {
        run,
        left: remote.left,
    };
    decision_body(ui, ("decision-remote", Some(remote.question.id)), |ui| {
        super::shell::banners(app, ui, pending);
        draw_question(app, ui, &current, &mut answer, Some(&remote.question));
    });
    if let Some(answer) = answer {
        apply_remote(app, ui.ctx(), &remote.question, answer);
    }
    disconnect_sheet(app, ui.ctx());
}

/// The height of the footer of the list.
const FOOTER: f32 = 36.0;

/// Why macOS cannot show a notification, or `None` when it can (or no notifier runs).
fn notifications_off(app: &DesktopApp) -> Option<String> {
    let view = app.owner.notifications.as_ref()?.view();
    (!view.channel.can_deliver()).then(|| view.channel.summary())
}

/// One small line at the bottom of the list when macOS cannot show a notification:
/// questions still wait here, so it says so once, not on each decision. The reason is
/// its tooltip; the controls are in Settings.
fn notifications_footer(app: &mut DesktopApp, ui: &mut egui::Ui, rect: Rect, summary: &str) {
    ui.painter().hline(
        rect.x_range(),
        rect.top() + 0.5,
        egui::Stroke::new(1.0, kit::SEPARATOR),
    );
    let inner = Rect::from_min_max(
        Pos2::new(rect.left() + 16.0, rect.top() + 1.0),
        Pos2::new(rect.right() - 8.0, rect.bottom()),
    );
    let mut open = false;
    ui.scope_builder(
        egui::UiBuilder::new()
            .max_rect(inner)
            .layout(Layout::left_to_right(Align::Center)),
        |ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            kit::paint_icon_in(ui, Icon::Warning, 12.0, Tone::Warning.mark());
            ui.add(
                Label::new(
                    kit::text("macOS notifications are off", Font::Footnote).color(kit::SECONDARY),
                )
                .truncate(),
            )
            .on_hover_text(summary);
            open = kit::small_button(ui, "Open Settings", Style::Link)
                .on_hover_text(summary)
                .clicked();
        },
    );
    if open {
        super::settings_view::open(app, super::SettingsSection::Devices);
    }
}

/// The time left in the orange of the mockup, at weight 500.
fn timer_text(value: impl Into<String>, font: Font) -> RichText {
    kit::text(value, font).variation(b"wght", 500.0)
}

/// The header of a detail as in the mockup: the mark at 56 points, the title at 20
/// points bold, and the line under it.
fn detail_header(ui: &mut egui::Ui, mark: &Mark, title: &str, line: impl FnOnce(&mut egui::Ui)) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 14.0;
        match mark {
            Mark::Agent(name) => kit::avatar(ui, name, 56.0),
            Mark::Tile(tile) => kit::tile(ui, tile, 56.0),
        };
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 2.0;
            // Centered on the mark when the title has one line, as in the mockup.
            let one_line: f32 = 24.0 + 2.0 + 18.0;
            let title_rich = kit::text(title, Font::Title).size(20.0).color(kit::LABEL);
            let lines = kit::galley(ui, title_rich.clone()).size().x > ui.available_width();
            if !lines {
                ui.add_space(((56.0 - one_line) / 2.0).max(0.0));
            }
            ui.add(Label::new(title_rich).wrap());
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing.x = 0.0;
                line(ui);
            });
        });
    });
    ui.add_space(22.0);
}

/// The label of a group in a detail: 12 points, semibold, secondary, as in the mockup.
fn group_label(ui: &mut egui::Ui, label: &str) {
    // A section leaves 20 points under it; the mockup has 18 above a label and 6 under.
    ui.add_space(-8.0);
    ui.horizontal(|ui| {
        ui.add_space(2.0);
        ui.label(
            kit::text(label, Font::Callout)
                .variation(b"wght", 600.0)
                .color(kit::SECONDARY),
        );
    });
    ui.add_space(-2.0);
}

/// The body of a detail: the reading column of the mockup, 584 points wide.
fn decision_body(
    ui: &mut egui::Ui,
    salt: impl std::hash::Hash + std::fmt::Debug,
    add: impl FnOnce(&mut egui::Ui),
) {
    columns::detail_body(ui, salt, |ui| {
        Frame::NONE
            .inner_margin(Margin::symmetric(12, 0))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                add(ui);
            });
    });
}

/// The kinds of buttons in the bars at the bottom of a detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Bar {
    /// White with a hairline border.
    Plain,
    /// White with a hairline border and red text: Deny.
    Deny,
    /// The main answer, in the accent color.
    Main,
    /// The main answer that allows production: red, as on the iPhone.
    Production,
}

/// A button of a bar at the bottom of a detail, as in the mockup: 28 points high, 7
/// round, 14 at each side, the label at weight 500.
fn bar_button(ui: &mut egui::Ui, label: &str, kind: Bar) -> egui::Response {
    let galley = kit::galley(ui, kit::text(label, Font::Body).variation(b"wght", 500.0));
    let size = Vec2::new(galley.size().x + 28.0, 28.0);
    let (rect, response) = ui.allocate_exact_size(size, Sense::click());
    let enabled = ui.is_enabled();
    response.widget_info(|| WidgetInfo::labeled(WidgetType::Button, enabled, label));
    if response.gained_focus() {
        response.scroll_to_me(None);
    }
    if !ui.is_rect_visible(rect) {
        return response;
    }
    let pressed = response.is_pointer_button_down_on();
    let hovered = response.hovered();
    let (fill, text, border) = match kind {
        Bar::Plain | Bar::Deny => (
            if pressed {
                kit::FILL_PRESSED
            } else if hovered {
                egui::Color32::from_rgb(250, 250, 250)
            } else {
                egui::Color32::WHITE
            },
            if kind == Bar::Deny {
                kit::PRODUCTION
            } else {
                kit::LABEL
            },
            Some(egui::Color32::from_black_alpha(48)),
        ),
        Bar::Main => (
            if pressed || hovered {
                egui::Color32::from_rgb(0, 94, 224)
            } else {
                egui::Color32::from_rgb(10, 108, 255)
            },
            egui::Color32::WHITE,
            None,
        ),
        Bar::Production => (
            if pressed || hovered {
                egui::Color32::from_rgb(200, 40, 32)
            } else {
                kit::PRODUCTION
            },
            egui::Color32::WHITE,
            None,
        ),
    };
    let (fill, text) = if enabled {
        (fill, text)
    } else {
        (fill.gamma_multiply(0.4), text.gamma_multiply(0.6))
    };
    let painter = ui.painter();
    painter.rect_filled(rect, 7, fill);
    if let Some(border) = border {
        painter.rect_stroke(
            rect,
            7,
            egui::Stroke::new(1.0, border),
            egui::StrokeKind::Inside,
        );
    }
    if response.has_focus() {
        kit::focus_ring(painter, rect, 7);
    }
    painter.galley(rect.center() - galley.size() / 2.0, galley, text);
    response
}

/// A bar at the bottom of a detail: a hairline on top, the light fill of the mockup.
fn bottom_bar(
    ui: &mut egui::Ui,
    id: impl std::hash::Hash + std::fmt::Debug,
    add: impl FnOnce(&mut egui::Ui),
) {
    egui::Panel::bottom(egui::Id::new(id))
        .resizable(false)
        .show_separator_line(true)
        .frame(
            Frame::NONE
                .fill(BAR_FILL)
                .inner_margin(Margin::symmetric(16, 10)),
        )
        .show(ui, add);
}

/// The caption of a bar: 11.5 points, secondary, left-aligned in the space between the
/// buttons, on at most two lines.
fn bar_caption(ui: &mut egui::Ui, caption: &str) {
    if caption.is_empty() {
        return;
    }
    let width = ui.available_width();
    ui.allocate_ui_with_layout(
        Vec2::new(width, 28.0),
        Layout::left_to_right(Align::Center),
        |ui| {
            ui.set_max_width(width);
            ui.add(
                Label::new(
                    kit::text(caption, Font::Footnote)
                        .size(11.5)
                        .color(kit::SECONDARY),
                )
                .wrap(),
            );
        },
    );
}

/// "⋯": the stricter answers that the question offers (ADR 0025 §3f).
fn more_menu(ui: &mut egui::Ui, run: &PendingRun, answer: &mut Option<Answer>) {
    let valid = &run.question.valid_answers;
    let offers = |kind: AnswerKind| valid.contains(&kind);
    if !offers(AnswerKind::NeverForAgent)
        && !offers(AnswerKind::AlwaysAskForAgent)
        && !offers(AnswerKind::Disconnect)
    {
        return;
    }
    let more = kit::toolbar_button(ui, Some(Icon::More), "", "More answers for this question");
    egui::Popup::menu(&more).show(|ui| {
        ui.set_min_width(200.0);
        if offers(AnswerKind::NeverForAgent)
            && ui
                .selectable_label(false, format!("Never for {}", run.agent))
                .clicked()
        {
            *answer = Some(Answer::Never);
        }
        if offers(AnswerKind::AlwaysAskForAgent)
            && ui
                .selectable_label(false, format!("Always Ask for {}", run.agent))
                .clicked()
        {
            *answer = Some(Answer::AlwaysAsk);
        }
        if offers(AnswerKind::Disconnect) {
            ui.separator();
            if ui
                .selectable_label(false, format!("Disconnect {}…", run.agent))
                .clicked()
            {
                *answer = Some(Answer::Disconnect);
            }
        }
    });
}

/// The first credential of a question that is production only by default.
fn unconfirmed(run: &PendingRun) -> Option<&QuestionItem> {
    run.question.items.iter().find(|item| item.unconfirmed)
}

/// A queued offer is a snapshot. Changed scope details require an explicit review;
/// they never replace classification edits while the owner is reading the question.
fn prepare_evaluation(app: &mut DesktopApp, run_id: u64) {
    // ADR 0031: keep compatibility code and stored scopes, hide obsolete setup.
    const EVALUATION_SETUP_VISIBLE: bool = false;
    let offer = (EVALUATION_SETUP_VISIBLE && !app.owner_ui.session.is_locked())
        .then(|| queue(app).and_then(|(queue, _)| queue.evaluation_offer(run_id)))
        .flatten();
    let Some(offer) = offer else {
        app.ui.decisions.forget_evaluation();
        return;
    };
    match app.ui.decisions.evaluation.as_mut() {
        Some(draft) if draft.run_id == run_id => {
            if draft.offer != offer {
                draft.stale = true;
            }
        }
        _ => app.ui.decisions.evaluation = Some(EvaluationDraft::new(run_id, offer)),
    }
}

fn evaluation_panel(
    app: &mut DesktopApp,
    ui: &mut egui::Ui,
    run: &PendingRun,
    answer: &mut Option<Answer>,
) {
    let Some(draft) = app.ui.decisions.evaluation.as_mut() else {
        return;
    };
    ui.add_space(12.0);
    kit::disclosure(ui, &mut draft.expanded, "Let the bouncer decide next time");
    if !draft.expanded {
        return;
    }
    if draft.stale {
        kit::tone_note(
            ui,
            "The permission details changed. Review them again before enabling the bouncer.",
            Tone::Warning,
        );
        let run_id = draft.run_id;
        if kit::small_button(ui, "Review updated details", Style::Bordered).clicked() {
            app.ui.decisions.forget_evaluation();
            prepare_evaluation(app, run_id);
            if let Some(draft) = app.ui.decisions.evaluation.as_mut() {
                draft.expanded = true;
            }
        }
        return;
    }
    kit::section(
        ui,
        None,
        Some(
            "Confirm each credential's environment and risk. This run is allowed once; matching later requests are evaluated by the model. Production, always-ask, and hard checks still apply.",
        ),
        |s| {
            s.labeled(
                "Agent",
                kit::text(
                    format!("{} (ID {})", run.agent, draft.offer.agent_id),
                    Font::Body,
                ),
            );
            s.labeled("Project", kit::text(&draft.offer.project.label, Font::Body));
            s.labeled(
                "Project folder",
                kit::text(&draft.offer.project.key, Font::Mono),
            );
            s.labeled(
                "Action",
                kit::text(action_label(draft.offer.action), Font::Body),
            );
            for (item, confirmation) in draft.offer.items.iter().zip(&mut draft.confirmations) {
                s.row(|ui| {
                    ui.label(kit::medium(&item.name, Font::Body));
                });
                s.field("Environment", |ui| {
                    egui::ComboBox::from_id_salt((
                        "evaluation-environment",
                        draft.run_id,
                        confirmation.item_id,
                    ))
                    .selected_text(environment_label(confirmation.environment))
                    .show_ui(ui, |ui| {
                        for value in Environment::ALL {
                            ui.selectable_value(
                                &mut confirmation.environment,
                                *value,
                                environment_label(*value),
                            );
                        }
                    })
                    .response
                });
                s.field("Risk", |ui| {
                    egui::ComboBox::from_id_salt((
                        "evaluation-risk",
                        draft.run_id,
                        confirmation.item_id,
                    ))
                    .selected_text(confirmation.risk.as_str())
                    .show_ui(ui, |ui| {
                        for value in RiskLevel::ALL {
                            ui.selectable_value(&mut confirmation.risk, *value, value.as_str());
                        }
                    })
                    .response
                });
                s.labeled(
                    "Hosts",
                    kit::text(
                        if confirmation.hosts.is_empty() {
                            "No destination host".to_owned()
                        } else {
                            confirmation.hosts.join(", ")
                        },
                        Font::Mono,
                    ),
                );
            }
            if draft.offer.command_binding.is_some() {
                s.labeled("Applies to", kit::text("Only this exact command, execution context and directly selected script version.", Font::Body));
            }
            s.row(|ui| {
                if kit::small_button(ui, "Allow once and enable bouncer", Style::Prominent)
                    .clicked()
                {
                    *answer = Some(Answer::Evaluate {
                        offer: draft.offer.clone(),
                        confirmations: draft.confirmations.clone(),
                    });
                }
            });
        },
    );
}

/// The bar at the bottom: Deny on the left; a caption; Allow Once; the main answer.
fn action_bar(ui: &mut egui::Ui, run: &PendingRun, answer: &mut Option<Answer>) {
    let question = &run.question;
    let main = primary(question);
    let main_label = primary_label(question);
    let caption = match (main, &question.project) {
        (Some(Primary::InProject(_)), Some(project)) => format!(
            "All agents in {} · from the next matching use.",
            short(&project.label)
        ),
        // The button names the action; the caption stays on two lines next to it.
        (Some(Primary::Production(_)), Some(project)) => format!(
            "Production allowance in {} · all agents · next matching use.",
            short(&project.label)
        ),
        (Some(Primary::Correct), _) => unconfirmed(run).map_or_else(String::new, |item| {
            format!("Is {} a development credential?", item.name)
        }),
        _ => "Allow Once allows this run only.".to_owned(),
    };
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 8.0;
        if bar_button(ui, "Deny", Bar::Deny).clicked() {
            *answer = Some(Answer::Deny);
        }
        ui.add_space(4.0);
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            match (main, &main_label) {
                (Some(Primary::Correct), Some(label)) => {
                    let item = unconfirmed(run);
                    if bar_button(ui, label, Bar::Main).clicked()
                        && let Some(item) = item
                    {
                        *answer = Some(Answer::Development {
                            item_id: item.item_id,
                            name: item.name.clone(),
                        });
                    }
                    if bar_button(ui, "Production", Bar::Plain).clicked()
                        && let Some(item) = item
                    {
                        *answer = Some(Answer::MarkProduction {
                            item_id: item.item_id,
                            name: item.name.clone(),
                        });
                    }
                    if bar_button(ui, "Allow Once", Bar::Plain).clicked() {
                        *answer = Some(Answer::Once);
                    }
                }
                (Some(remembered), Some(label)) => {
                    // Production has its own red button, as on the iPhone (ADR 0025 §3b).
                    let kind = if matches!(remembered, Primary::Production(_)) {
                        Bar::Production
                    } else {
                        Bar::Main
                    };
                    if bar_button(ui, label, kind).clicked() {
                        *answer = Some(match remembered {
                            Primary::Production(action) => Answer::Production(action),
                            Primary::InProject(action) => Answer::InProject(action),
                            Primary::Correct => Answer::Once,
                        });
                    }
                    if bar_button(ui, "Allow Once", Bar::Plain).clicked() {
                        *answer = Some(Answer::Once);
                    }
                }
                _ => {
                    if bar_button(ui, "Allow Once", Bar::Main).clicked() {
                        *answer = Some(Answer::Once);
                    }
                }
            }
            ui.add_space(8.0);
            bar_caption(ui, &caption);
        });
    });
}

/// A credential of the question with its provider tile and its production cap.
fn credential_row(app: &DesktopApp, section: &mut kit::Section<'_>, item: &QuestionItem) {
    let tile = item_tile(app, item.item_id, &item.name);
    section.row(|ui| {
        ui.horizontal(|ui| {
            ui.label(kit::text("Credential", Font::Body).color(kit::LABEL));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.spacing_mut().item_spacing.x = 6.0;
                if item.production {
                    kit::cap(ui, "Production", true);
                } else if item.unconfirmed {
                    kit::cap(ui, "Production by default", false);
                }
                if item.always_ask {
                    kit::cap(ui, "Always ask", false);
                }
                ui.add(Label::new(kit::text(&item.name, Font::Body).color(kit::LABEL)).truncate());
                kit::tile(ui, &tile, 20.0);
            });
        });
    });
}

/// The provider tile of a credential, or the tile of its kind.
fn item_tile(app: &DesktopApp, item_id: u64, name: &str) -> kit::Tile {
    let session = &app.owner_ui.session;
    let provider = session
        .with_vault(|vault| vault.declaration_provider(item_id))
        .and_then(Result::ok)
        .flatten()
        .and_then(|id| crate::vault::providers::find(&id))
        .map(|provider| provider.label.clone());
    let (kind, service) = session
        .details(item_id)
        .map_or((CredentialKind::Custom, String::new()), |details| {
            (details.kind, details.service)
        });
    super::credential_tile(kind, provider.as_deref().unwrap_or(&service), name)
}

fn draw_question(
    app: &mut DesktopApp,
    ui: &mut egui::Ui,
    waiting: &Waiting,
    answer: &mut Option<Answer>,
    remote: Option<&RemoteQuestion>,
) {
    let run = &waiting.run;
    let question = &run.question;
    detail_header(
        ui,
        &Mark::Agent(run.agent.clone()),
        &format!("{} wants to use {}", run.agent, item_names(run)),
        |ui| {
            ui.label(
                kit::text(format!("{} · ", project_text(run)), Font::Body).color(kit::SECONDARY),
            );
            ui.label(timer_text(clock(waiting.left), Font::Body).color(TIMER));
            ui.label(kit::text(" left to answer", Font::Body).color(kit::SECONDARY));
        },
    );
    let mut notes = false;
    match remote {
        Some(remote) => {
            notes = true;
            kit::tone_note(
                ui,
                format!(
                    "Asked on {}. The answer goes there through the relay, end-to-end encrypted.",
                    shown_path(remote.asker(), 40)
                ),
                Tone::Accent,
            );
            if let Some(sent) = &remote.sent {
                kit::tone_note(ui, sent, Tone::Good);
            }
        }
        None => {
            if let Some(note) = local_only_note(app, run.id) {
                notes = true;
                kit::tone_note(ui, &note, Tone::Warning);
            }
        }
    }
    if notes {
        ui.add_space(12.0);
    }
    let hosts = command_hosts(&run.command);
    kit::section(ui, None, None, |s| {
        for item in &question.items {
            credential_row(app, s, item);
        }
        if question.items.is_empty() && !run.env_names.is_empty() {
            s.labeled(
                "Variables",
                kit::text(run.env_names.join(", "), Font::Mono).color(kit::LABEL),
            );
        }
        s.labeled(
            "Action",
            kit::text(action_label(question.action), Font::Body).color(kit::SECONDARY),
        );
        s.labeled(
            "Project",
            kit::text(project_text(run), Font::Body).color(kit::SECONDARY),
        );
        // A command without a host (a command line tool) has no row, as in the mockup.
        if !hosts.is_empty() {
            s.labeled(
                "Sends to",
                kit::text(hosts.join(", "), Font::Body).color(kit::SECONDARY),
            );
        }
    });
    // The request of the user shows only when the agent sent a different one (goal item
    // B6): the owner then compares the two. Else the mockup has no request group.
    if !run.user_request.is_empty() && !run.agent_request.is_empty() {
        let source = if run.request_source.is_empty() {
            "from the agent"
        } else {
            run.request_source.as_str()
        };
        group_label(ui, "Request");
        kit::section(ui, None, None, |s| {
            s.row(|ui| {
                kit::paragraph(
                    ui,
                    format!("\"{}\" ({source})", run.user_request),
                    Font::Body,
                    kit::LABEL,
                );
                // Goal item B6: the hook request replaced a different text of the agent.
                kit::tone_note(
                    ui,
                    format!(
                        "The agent sent a different request: \"{}\"",
                        run.agent_request
                    ),
                    Tone::Warning,
                );
            });
        });
    }
    group_label(ui, "Command");
    kit::section(ui, None, None, |s| {
        s.row(|ui| {
            Frame::NONE
                .fill(egui::Color32::from_rgb(242, 242, 244))
                .corner_radius(6)
                .inner_margin(Margin::symmetric(10, 8))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.add(
                        Label::new(
                            kit::text(shell_words(&run.command), Font::Mono).color(kit::LABEL),
                        )
                        .wrap(),
                    );
                });
        });
    });
    let why = if !question.why.is_empty() {
        question.why.clone()
    } else if !run.risk.is_empty() {
        run.risk.clone()
    } else {
        "The bouncer did not decide this run, so it asks you.".to_owned()
    };
    group_label(ui, "Why you are asked");
    kit::section(ui, None, None, |s| {
        s.row(|ui| kit::paragraph(ui, why, Font::Body, kit::LABEL));
    });
    if remote.is_none() {
        evaluation_panel(app, ui, run, answer);
    }
    // The correction stays at hand when the bar offers a remembered answer.
    if question
        .valid_answers
        .contains(&AnswerKind::CorrectEnvironment)
        && primary(question) != Some(Primary::Correct)
    {
        group_label(ui, "Environment");
        kit::section(
            ui,
            None,
            Some("Until you answer, the bouncer treats it as production and asks more often."),
            |s| {
                for item in question.items.iter().filter(|item| item.unconfirmed) {
                    s.row(|ui| {
                        egui::Sides::new().shrink_left().show(
                            ui,
                            |ui| {
                                ui.add(
                                    Label::new(
                                        kit::text(
                                            format!("{} is production only by default.", item.name),
                                            Font::Body,
                                        )
                                        .color(kit::LABEL),
                                    )
                                    .wrap(),
                                );
                            },
                            |ui| {
                                if kit::small_button(ui, "Development", Style::Bordered).clicked() {
                                    *answer = Some(Answer::Development {
                                        item_id: item.item_id,
                                        name: item.name.clone(),
                                    });
                                }
                                if kit::small_button(ui, "Production", Style::Bordered).clicked() {
                                    *answer = Some(Answer::MarkProduction {
                                        item_id: item.item_id,
                                        name: item.name.clone(),
                                    });
                                }
                            },
                        );
                    });
                }
            },
        );
    }
    // The quiet line at the foot of a detail of the mockup (`.meta-foot`).
    ui.add_space(2.0);
    ui.vertical_centered(|ui| {
        ui.add(
            Label::new(
                kit::text(
                    "The process can read these secrets. An allow needs Touch ID or the passphrase now. A notification is not an approval.",
                    Font::Footnote,
                )
                .color(kit::TERTIARY),
            )
            .wrap()
            .halign(Align::Center),
        );
    });
}

/// Do the answer of the owner. An answer that gives authority opens the owner check;
/// the run stays in the queue until it passes. A stricter answer acts at once.
pub(super) fn apply(app: &mut DesktopApp, ctx: &egui::Context, run: &PendingRun, answer: Answer) {
    let Some((queue, _)) = queue(app) else {
        app.set_err("The broker is not running. Nothing changed.");
        return;
    };
    let names = item_names(run);
    match answer {
        Answer::Deny => {
            if queue.deny(run.id) {
                app.set_ok(format!("Denied. {} gets a refusal.", run.agent));
            } else {
                app.set_err("The question no longer waits.");
            }
        }
        Answer::Once => app.allow_once_clicked(OwnerRequest::ApproveRun(run.clone()), ctx),
        Answer::Evaluate {
            offer,
            confirmations,
        } => {
            let same_offer = queue.evaluation_offer(run.id).as_ref() == Some(&offer);
            let same_bindings = offer.items.len() == confirmations.len()
                && offer
                    .items
                    .iter()
                    .zip(&confirmations)
                    .all(|(item, chosen)| {
                        item.confirmation.item_id == chosen.item_id
                            && item.confirmation.revision == chosen.revision
                            && item.confirmation.hosts == chosen.hosts
                    });
            if !same_offer || !same_bindings {
                app.set_err(
                    "The bouncer permission is no longer offered. Review the question again.",
                );
                return;
            }
            app.ask_owner(
                OwnerRequest::ApproveAndEvaluate {
                    run: run.clone(),
                    offer,
                    confirmations,
                },
                Some(ctx),
            );
        }
        Answer::InProject(action) | Answer::Production(action) => {
            let Some(project) = run.question.project.clone() else {
                app.set_err("This question has no project. Use Allow Once.");
                return;
            };
            let request = if matches!(answer, Answer::Production(_)) {
                OwnerRequest::AllowProduction {
                    run: run.clone(),
                    project,
                    action,
                }
            } else {
                OwnerRequest::ApproveInProject {
                    run: run.clone(),
                    project,
                    action,
                }
            };
            app.ask_owner(request, Some(ctx));
        }
        Answer::Development { item_id, name } => {
            if !queue.pending().iter().any(|r| r == run)
                || !(Choice::CorrectEnvironment {
                    item_id,
                    environment: RemoteEnvironment::Development,
                })
                .valid_for(&run.question)
            {
                app.set_err("The question no longer offers this correction.");
                return;
            }
            app.development_clicked(
                OwnerRequest::CorrectEnvironment {
                    run_id: run.id,
                    agent: run.agent.clone(),
                    item_id,
                    name,
                    environment: Environment::Development,
                },
                ctx,
            );
        }
        Answer::MarkProduction { item_id, name } => {
            let result = app.owner_ui.session.mark_production(item_id);
            let _ = app.apply(
                result,
                &format!(
                    "{name} is marked as production. The question of {} still waits.",
                    run.agent
                ),
            );
        }
        Answer::Never | Answer::AlwaysAsk => {
            let (stricter, message) = if answer == Answer::Never {
                (
                    StricterAnswer::NeverForAgent,
                    format!("Denied. {} never gets {names}.", run.agent),
                )
            } else {
                (
                    StricterAnswer::AlwaysAskForAgent,
                    format!("Denied. Each use of {names} by {} asks you.", run.agent),
                )
            };
            stricter_answer(app, &queue, run.id, stricter, &message);
        }
        Answer::Disconnect => {
            app.ui.decisions.disconnect = Some((Key::Run(run.id), run.agent.clone()));
        }
    }
}

/// The answer to a question of another Mac as its card names it (section 9.1). `None`
/// when the question has no project for a project answer.
pub(super) fn remote_choice(run: &PendingRun, answer: &Answer) -> Option<Choice> {
    let project_key = || {
        run.question
            .project
            .as_ref()
            .map(|project| project.key.clone())
    };
    Some(match answer {
        Answer::Deny => Choice::Deny,
        Answer::Once => Choice::ApproveOnce,
        Answer::Evaluate { .. } => return None,
        Answer::InProject(action) => Choice::ApproveInProject {
            action: *action,
            project_key: project_key()?,
        },
        Answer::Production(action) => Choice::AllowProduction {
            action: *action,
            project_key: project_key()?,
        },
        Answer::Development { item_id, .. } => Choice::CorrectEnvironment {
            item_id: *item_id,
            environment: RemoteEnvironment::Development,
        },
        Answer::MarkProduction { item_id, .. } => Choice::CorrectEnvironment {
            item_id: *item_id,
            environment: RemoteEnvironment::Production,
        },
        Answer::Never => Choice::NeverForAgent,
        Answer::AlwaysAsk => Choice::AlwaysAskForAgent,
        Answer::Disconnect => Choice::Disconnect,
    })
}

/// Do the answer of the owner to a question of another Mac. An answer that gives
/// authority opens the owner check for `OwnerAction::AnswerRemoteQuestion`; a stricter
/// one goes at once. "Disconnect" asks once, as on this Mac.
pub(super) fn apply_remote(
    app: &mut DesktopApp,
    ctx: &egui::Context,
    remote: &RemoteQuestion,
    answer: Answer,
) {
    let run = &remote.question.run;
    if answer == Answer::Disconnect {
        app.ui.decisions.disconnect = Some((Key::Remote(remote.id), run.agent.clone()));
        return;
    }
    let Some(choice) = remote_choice(run, &answer) else {
        app.set_err("This question has no project. Use Allow Once.");
        return;
    };
    if choice.needs_owner_check() {
        let Some(action) = remote_owner_action(&remote.question, &choice) else {
            app.set_err("This question does not offer this answer.");
            return;
        };
        app.ask_owner(
            OwnerRequest::AnswerRemoteQuestion {
                remote_id: remote.id,
                choice,
                action,
            },
            Some(ctx),
        );
    } else {
        app.answer_remote_question(remote.id, choice, None);
    }
}

impl DesktopApp {
    /// Send `choice` to the question `remote_id` of another Mac on a thread of its own:
    /// signed with the relay key of this Mac, with `proof` for an approving answer.
    pub(crate) fn answer_remote_question(
        &mut self,
        remote_id: u64,
        choice: Choice,
        proof: Option<crate::broker::approvals::OwnerProof>,
    ) {
        let Some(questions) = &self.owner.questions else {
            self.set_err("Questions through the relay are not running. Nothing was sent.");
            return;
        };
        let answering = match questions.answering(remote_id) {
            Ok(answering) => answering,
            Err(error) => {
                self.set_err(error.message());
                return;
            }
        };
        let asker = answering.question().card.asker.name.clone();
        let sending = &mut self.ui.decisions.sending;
        sending
            .tasks
            .push(Task::spawn(sending.repaint.clone(), move || {
                let result = answering.send(choice, proof);
                (asker, result)
            }));
    }

    /// Each frame: the answers of the relay to the answers of this Mac.
    pub(crate) fn poll_remote_answers(&mut self, ctx: &egui::Context) {
        let sending = &mut self.ui.decisions.sending;
        sending.repaint = Some(ctx.clone());
        let mut done = Vec::new();
        sending.tasks.retain(|task| match task.poll() {
            TaskPoll::Waiting => true,
            TaskPoll::Done(result) => {
                done.push(Some(result));
                false
            }
            TaskPoll::Lost => {
                done.push(None);
                false
            }
        });
        if !sending.tasks.is_empty() {
            ctx.request_repaint_after(Duration::from_millis(200));
        }
        for result in done {
            match result {
                Some((_, Ok(_))) => self.set_ok(crate::questions::worker::SENT),
                Some((_, Err(error))) => self.set_err(error.message()),
                None => self.set_err("The answer did not go to the relay. Try again."),
            }
        }
    }

    /// Wait until the answers of this Mac went to the relay, for a test.
    #[cfg(test)]
    pub(crate) fn settle_remote_answers_for_test(&mut self) {
        let ctx = egui::Context::default();
        let start = std::time::Instant::now();
        while !self.ui.decisions.sending.tasks.is_empty() {
            assert!(
                start.elapsed() < Duration::from_secs(20),
                "the answer hangs"
            );
            std::thread::sleep(Duration::from_millis(10));
            self.poll_remote_answers(&ctx);
        }
    }
}

fn stricter_answer(
    app: &mut DesktopApp,
    queue: &ApprovalQueue,
    run_id: u64,
    stricter: StricterAnswer,
    message: &str,
) {
    match app.owner_ui.session.deny_stricter(queue, run_id, stricter) {
        Ok(true) => app.set_ok(message),
        Ok(false) => app.set_err("The question no longer waits. Nothing changed."),
        Err(err) => app.set_err(err.message),
    }
}

/// "Disconnect AGENT…" asks once. It denies the question and revokes the agent: it
/// takes authority away, so it needs no owner check.
fn disconnect_sheet(app: &mut DesktopApp, ctx: &egui::Context) {
    let Some((key, agent)) = app.ui.decisions.disconnect.clone() else {
        return;
    };
    let mut confirm = false;
    let mut cancel = false;
    let response = kit::sheet(ctx, "disconnect-agent", 400.0, |ui| {
        kit::sheet_title(
            ui,
            &format!("Disconnect {agent}?"),
            Some(
                "Apassy denies this question, and the token of the agent stops working at once. You can connect it again later in Agents.",
            ),
        );
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                confirm = kit::button(ui, "Disconnect", Style::DestructiveProminent).clicked();
                cancel = kit::alert_cancel(ui).clicked();
            },
        );
    });
    if cancel || response.escape {
        app.ui.decisions.disconnect = None;
    }
    if confirm {
        app.ui.decisions.disconnect = None;
        let run_id = match key {
            Key::Run(run_id) => run_id,
            Key::Remote(remote_id) => {
                app.answer_remote_question(remote_id, Choice::Disconnect, None);
                return;
            }
            _ => return,
        };
        let Some((queue, _)) = queue(app) else {
            app.set_err("The broker is not running. Nothing changed.");
            return;
        };
        stricter_answer(
            app,
            &queue,
            run_id,
            StricterAnswer::Disconnect,
            &format!("{agent} is disconnected. Its token does not work."),
        );
    }
}

// ---- Requests (ADR 0025 §6). ----

/// The detail of a credential request.
fn request_detail(
    app: &mut DesktopApp,
    ui: &mut egui::Ui,
    pending: &[PendingRun],
    request: &CredentialRequest,
) {
    columns::detail_toolbar(ui, |_| {});
    let tree = FolderTree::load(app);
    let mut folder = app
        .ui
        .decisions
        .form
        .as_ref()
        .filter(|(id, _)| *id == request.id)
        .and_then(|(_, folder)| folder.clone());
    // A folder that is gone gives way to the top level.
    if folder
        .as_deref()
        .is_some_and(|uuid| tree.get(uuid).is_none())
    {
        folder = None;
    }
    let detected = detect::detect(&app.ui.decisions.paste.0);
    let ready = detected.len() == 1;
    let mut answer = None;
    bottom_bar(ui, ("request-bar", request.id), |ui| {
        request_bar(ui, ready, &mut answer);
    });
    decision_body(ui, ("request", request.id), |ui| {
        super::shell::banners(app, ui, pending);
        request_header(ui, request);
        kit::section(ui, None, None, |s| {
            s.labeled(
                "For",
                kit::text(&request.purpose, Font::Body).color(kit::SECONDARY),
            );
            s.row(|ui| get_it_at(ui, &request.where_to_get));
            s.row(|ui| saves_to(ui, request.id, &tree, &mut folder));
        });
        group_label(ui, "Key");
        paste_field(ui, &mut app.ui.decisions.paste.0);
        ui.add_space(-2.0);
        let typed = !app.ui.decisions.paste.0.trim().is_empty();
        match detected.as_slice() {
            [] if typed => kit::tone_note(ui, NOTHING_FOUND, Tone::Warning),
            [] => {}
            [found] => detected_row(ui, found, &request.name),
            many => kit::tone_note(
                ui,
                format!(
                    "The text has {} credentials. Paste one for this request.",
                    many.len()
                ),
                Tone::Warning,
            ),
        }
        ui.horizontal(|ui| {
            ui.add_space(6.0);
            kit::paragraph(
                ui,
                format!(
                    "{} never sees the value. The bouncer decides each use of it.",
                    request.agent_name
                ),
                Font::Callout,
                kit::SECONDARY,
            );
        });
    });
    drop(detected);
    app.ui.decisions.form = Some((request.id, folder));
    // The field keeps no undo history: Cmd+Z never brings a paste back.
    super::forget_secret_field(ui.ctx(), REQUEST_FIELD);
    if let Some(answer) = answer {
        apply_request(app, ui.ctx(), request, answer);
    }
}

fn request_header(ui: &mut egui::Ui, request: &CredentialRequest) {
    detail_header(
        ui,
        &Mark::Agent(request.agent_name.clone()),
        &request_title(request),
        |ui| {
            ui.label(kit::text(request_project(request), Font::Body).color(kit::SECONDARY));
        },
    );
}

/// "Saves to": the folder as a plain value, as in the mockup, and "Change" with a menu
/// of the folders.
fn saves_to(ui: &mut egui::Ui, id: u64, tree: &FolderTree, folder: &mut Option<String>) {
    let label = tree.path_label(folder.as_deref());
    egui::Sides::new().shrink_left().show(
        ui,
        |ui| ui.label(kit::text("Saves to", Font::Body).color(kit::LABEL)),
        |ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            let change = kit::small_button(ui, "Change", Style::Link);
            ui.ctx().accesskit_node_builder(change.id, |node| {
                node.set_label(format!("Change the folder, now {label}"));
            });
            egui::Popup::menu(&change)
                .id(egui::Id::new(("request-folder", id)))
                .show(|ui| {
                    ui.set_min_width(180.0);
                    for (choice, name) in tree.choices() {
                        if ui.selectable_label(*folder == choice, name).clicked() {
                            *folder = choice;
                            ui.close();
                        }
                    }
                });
            ui.add(Label::new(kit::text(&label, Font::Body).color(kit::SECONDARY)).truncate());
        },
    );
}

/// "Get it at" on one line, as in the mockup: the text of the agent with its domain in
/// medium weight. When the text does not start with its real domain (user info such as
/// `stripe.com@`, or no domain), the domain in bold comes first and the whole text under
/// it. Not a link: the text came from an agent, and a link can hide where it goes.
fn get_it_at(ui: &mut egui::Ui, where_to_get: &str) {
    let domains = where_domains(where_to_get);
    let plain = where_to_get
        .strip_prefix("https://")
        .or_else(|| where_to_get.strip_prefix("http://"))
        .unwrap_or(where_to_get);
    if let [domain] = domains.as_slice()
        && !plain.contains(char::is_whitespace)
        && plain.len() <= 80
        && let Some(rest) = plain.strip_prefix(domain.as_str())
        && (rest.is_empty() || rest.starts_with('/'))
    {
        egui::Sides::new().shrink_right().show(
            ui,
            |ui| ui.label(kit::text("Get it at", Font::Body).color(kit::LABEL)),
            |ui| {
                let mut job = egui::text::LayoutJob::default();
                kit::medium(domain, Font::Body).color(kit::LABEL).append_to(
                    &mut job,
                    ui.style(),
                    egui::FontSelection::Default,
                    Align::Center,
                );
                kit::text(rest, Font::Body).color(kit::SECONDARY).append_to(
                    &mut job,
                    ui.style(),
                    egui::FontSelection::Default,
                    Align::Center,
                );
                ui.add(Label::new(job).truncate())
                    .on_hover_text("Apassy opens no link. Check the domain before you sign in.")
            },
        );
        return;
    }
    egui::Sides::new().shrink_right().show(
        ui,
        |ui| ui.label(kit::text("Get it at", Font::Body).color(kit::LABEL)),
        |ui| {
            let shown = if domains.is_empty() {
                kit::text(
                    if where_to_get.is_empty() {
                        "The agent did not say"
                    } else {
                        "No domain in the text"
                    },
                    Font::Body,
                )
                .color(kit::SECONDARY)
            } else {
                kit::medium(domains.join(", "), Font::Body).color(kit::LABEL)
            };
            ui.add(Label::new(shown).truncate())
        },
    );
    if !where_to_get.is_empty() && domains.first().map(String::as_str) != Some(where_to_get) {
        ui.add(
            Label::new(kit::text(where_to_get, Font::Callout).color(kit::SECONDARY))
                .wrap()
                .selectable(false),
        );
    }
    if !domains.is_empty() {
        ui.add(
            Label::new(
                kit::text(
                    "Apassy opens no link. Check the domain before you sign in.",
                    Font::Callout,
                )
                .color(kit::TERTIARY),
            )
            .wrap(),
        );
    }
}

/// The masked paste field of a request.
fn paste_field(ui: &mut egui::Ui, value: &mut String) {
    super::presize(value, super::SECRET_VALUE_CAPACITY);
    let response = ui.add(
        TextEdit::multiline(value)
            .password(true)
            .id(super::secret_field_id(REQUEST_FIELD))
            .char_limit(super::SECRET_VALUE_CAPACITY / 4)
            .font(egui::TextStyle::Monospace)
            .hint_text(kit::text("Paste the key", Font::Mono).color(kit::TERTIARY))
            .margin(kit::FIELD_MARGIN)
            .desired_rows(3)
            .desired_width(f32::INFINITY),
    );
    ui.ctx().accesskit_node_builder(response.id, |node| {
        node.set_label("Paste the requested credential");
    });
}

/// What Apassy found in the paste, as New Credential shows it: the provider tile, the
/// name of the request, the provider, the variable, the host, and the environment.
fn detected_row(ui: &mut egui::Ui, found: &Detected, name: &str) {
    let provider = found
        .provider
        .as_deref()
        .and_then(crate::vault::providers::find)
        .map_or_else(|| found.kind.label().to_owned(), |p| p.label.clone());
    let (cap, red) =
        super::new_credential::row_cap(found).unwrap_or(("Production by default", false));
    kit::section(ui, None, None, |s| {
        s.row(|ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 10.0;
                kit::tile(
                    ui,
                    &super::credential_tile(found.kind, &provider, name),
                    32.0,
                );
                ui.vertical(|ui| {
                    ui.set_width((ui.available_width() - 150.0).max(80.0));
                    ui.spacing_mut().item_spacing.y = 2.0;
                    ui.add(Label::new(kit::medium(name, Font::Body).color(kit::LABEL)).truncate());
                    ui.add(
                        Label::new(
                            RichText::new(super::new_credential::row_line(found))
                                .font(egui::FontId::monospace(11.5))
                                .color(kit::SECONDARY),
                        )
                        .truncate(),
                    );
                });
                kit::cap(ui, cap, red);
            });
        });
    });
}

/// The bar of a request: Not Now and Save.
fn request_bar(ui: &mut egui::Ui, ready: bool, answer: &mut Option<RequestAnswer>) {
    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
        ui.spacing_mut().item_spacing.x = 8.0;
        let save = ui
            .add_enabled_ui(ready, |ui| bar_button(ui, "Save", Bar::Main))
            .inner
            .on_disabled_hover_text("Paste the key to save it.")
            .on_hover_text("Save adds a new credential. Apassy shows no value.");
        if save.clicked() {
            *answer = Some(RequestAnswer::Save);
        }
        if bar_button(ui, "Not Now", Bar::Plain).clicked() {
            *answer = Some(RequestAnswer::NotNow);
        }
    });
}

/// Answer a credential request. Save adds the pasted credential with the origin of the
/// request and settles the request with it; Not Now dismisses it. Neither needs the
/// owner check: no authority moves. The paste is erased after either.
pub(super) fn apply_request(
    app: &mut DesktopApp,
    ctx: &egui::Context,
    request: &CredentialRequest,
    answer: RequestAnswer,
) {
    match answer {
        RequestAnswer::NotNow => {
            erase_paste(app, ctx);
            let result = app.owner_ui.session.dismiss_credential_request(request.id);
            let _ = app.apply(
                result,
                &format!("Not now. {} gets no {}.", request.agent_name, request.name),
            );
        }
        RequestAnswer::Save => {
            let mut detected = detect::detect(&app.ui.decisions.paste.0);
            if detected.len() != 1 {
                drop(detected);
                app.set_err("Paste one credential for this request. Nothing was saved.");
                return;
            }
            let mut found = detected.remove(0);
            drop(detected);
            found.title.clone_from(&request.name);
            let tree = FolderTree::load(app);
            let folder = app
                .ui
                .decisions
                .form
                .as_ref()
                .filter(|(id, _)| *id == request.id)
                .and_then(|(_, folder)| folder.clone())
                .filter(|uuid| tree.get(uuid).is_some());
            let result =
                app.owner_ui
                    .session
                    .save_credential_request(request.id, &found, folder.as_deref());
            drop(found);
            match result {
                Ok(item) => {
                    erase_paste(app, ctx);
                    app.set_ok(format!(
                        "Saved {} in {} for {}. The bouncer decides each use.",
                        item.title,
                        tree.path_label(folder.as_deref()),
                        request.agent_name
                    ));
                }
                // The paste stays, so the owner can choose another folder.
                Err(err) => app.set_err(err.message),
            }
        }
    }
}

// ---- Suggestions (ADR 0025 §5). ----

/// The detail of a suggestion.
fn suggestion_detail(
    app: &mut DesktopApp,
    ui: &mut egui::Ui,
    pending: &[PendingRun],
    correction: &Correction,
    item: &OwnerSummary,
) {
    columns::detail_toolbar(ui, |_| {});
    let mut answer = None;
    bottom_bar(ui, ("suggestion-bar", correction.id), |ui| {
        suggestion_bar(ui, app, correction, &mut answer);
    });
    decision_body(ui, ("suggestion", correction.id), |ui| {
        super::shell::banners(app, ui, pending);
        let tile = item_tile(app, item.id, &item.name);
        detail_header(
            ui,
            &Mark::Tile(tile),
            &suggestion_question(correction, &item.name, item.kind),
            |ui| {
                ui.label(
                    kit::text("Apassy noticed this from how agents use it.", Font::Body)
                        .color(kit::SECONDARY),
                );
            },
        );
        let facts = fact_rows(&correction.facts);
        if !facts.is_empty() {
            kit::section(ui, None, None, |s| {
                for (label, value) in &facts {
                    s.labeled(label, kit::text(value, Font::Body).color(kit::SECONDARY));
                }
            });
            ui.add_space(-18.0);
        }
        ui.horizontal(|ui| {
            ui.add_space(6.0);
            kit::paragraph(
                ui,
                suggestion_note(correction),
                Font::Callout,
                kit::SECONDARY,
            );
        });
    });
    if let Some(answer) = answer {
        apply_suggestion(app, ui.ctx(), correction, &item.name, answer);
    }
}

/// The note under the facts: what holds until the owner answers.
fn suggestion_note(correction: &Correction) -> String {
    match (correction.kind, correction.proposed.as_str()) {
        (CorrectionKind::Project, project) => {
            format!("With the project {project}, a use in another project asks you.")
        }
        (CorrectionKind::Environment, "production") => match raised_from(correction) {
            Some(before) => format!(
                "Apassy treats it as production until you answer. Ignore makes it {} again.",
                before.as_str()
            ),
            None => "Production makes the bouncer more careful with it.".to_owned(),
        },
        (CorrectionKind::Environment, _) => {
            "Until you answer, the bouncer treats it as production and asks more often.".to_owned()
        }
    }
}

/// The bar of a suggestion: Ignore on the left; a caption; the choices, the proposal as
/// the main button.
fn suggestion_bar(
    ui: &mut egui::Ui,
    app: &DesktopApp,
    correction: &Correction,
    answer: &mut Option<SuggestionAnswer>,
) {
    let choices = suggestion_choices(correction);
    let mut checked: Vec<&str> = choices
        .iter()
        .filter(|(_, choice)| suggestion_needs_check(app, correction, *choice))
        .map(|(label, _)| label.as_str())
        .collect();
    if suggestion_needs_check(app, correction, SuggestionAnswer::Ignore) {
        checked.push("Ignore");
    }
    let caption = match checked.as_slice() {
        [] => String::new(),
        [one] => format!("{one} needs Touch ID or the passphrase."),
        [first, second, ..] => format!("{first} and {second} need Touch ID or the passphrase."),
    };
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 8.0;
        if bar_button(ui, "Ignore", Bar::Plain).clicked() {
            *answer = Some(SuggestionAnswer::Ignore);
        }
        ui.add_space(4.0);
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            for (index, (label, choice)) in choices.iter().enumerate() {
                let kind = if index == 0 { Bar::Main } else { Bar::Plain };
                if bar_button(ui, label, kind).clicked() {
                    *answer = Some(*choice);
                }
            }
            ui.add_space(8.0);
            bar_caption(ui, &caption);
        });
    });
}

/// Answer a suggestion. An answer that leaves the credential at an environment other
/// the vault finds too loose opens the owner check; the others act at once.
pub(super) fn apply_suggestion(
    app: &mut DesktopApp,
    ctx: &egui::Context,
    correction: &Correction,
    name: &str,
    answer: SuggestionAnswer,
) {
    let (settle, chosen, result) = suggestion_outcome(correction, answer);
    if suggestion_needs_check(app, correction, answer)
        && let Some(environment) = result
    {
        app.ask_owner(
            OwnerRequest::AnswerSuggestion {
                correction_id: correction.id,
                item_id: correction.item_id,
                name: name.to_owned(),
                answer: settle,
                chosen,
                environment,
            },
            Some(ctx),
        );
        return;
    }
    let outcome = app.owner_ui.session.answer_correction(
        correction.id,
        correction.item_id,
        settle,
        chosen,
        None,
    );
    match outcome {
        Ok(Some(environment)) => app.set_ok(format!("{name} is {}.", environment.as_str())),
        Ok(None) if settle == CorrectionAnswer::Accepted => app.set_ok(format!(
            "{name} is limited to {}. A use in another project asks you.",
            correction.proposed
        )),
        Ok(None) => app.set_ok("Ignored. Apassy does not suggest this again."),
        Err(err) => app.set_err(err.message),
    }
}

fn access_detail(
    app: &mut DesktopApp,
    ui: &mut egui::Ui,
    r: &crate::vault::access_once::AccessRecord,
) {
    use crate::questions::access_request::{Choice, Delivery, HostSource};
    let c = &r.card.card;
    columns::detail_toolbar(ui, |ui| {
        ui.heading("Access request");
    });
    columns::detail_body(ui, ("access-request", r.id), |ui| {
        ui.ctx().request_repaint_after(Duration::from_secs(1));
        let export_note = app.owner.questions.as_ref().and_then(|q| {
            let view = q.view();
            view.access_local_only
                .get(&r.id)
                .cloned()
                .or_else(|| {
                    view.problem.map(|p| {
                        format!("Review on this Mac. Remote publication is unavailable: {p}")
                    })
                })
                .or_else(|| {
                    (!view.on)
                        .then(|| "Review on this Mac. The relay connection is not ready.".into())
                })
        });
        if let Some(note) = export_note {
            ui.label(note);
        }
        if c.team_id == "local" {
            ui.label(
                "Review on this Mac. Connect an iPhone before creating a request to send there.",
            );
        }
        ui.heading(format!(
            "{} (id {}) asks for {}",
            c.agent.name, c.agent.id, c.item.name
        ));
        ui.label(format!("{} · Asked on {}", c.vault_name, c.asker.name));
        ui.strong("Mac-verified fields");
        ui.label(format!(
            "Agent id {} · Item {} / {} · revision {}",
            c.agent.id, c.item.local_id, c.item.uuid, c.item.revision
        ));
        ui.label(format!("Mac {} · Vault {}", c.asker.device, c.vault_id));
        if c.agent.host.is_none() {
            ui.label("Agent host: unknown");
        }
        if let Some(host) = &c.agent.host {
            ui.label(format!(
                "{}: {}",
                if c.agent.host_source == HostSource::AgentClaimed {
                    "Agent-reported host (not verified)"
                } else {
                    "Connection label (not executable attestation)"
                },
                host
            ));
        }
        ui.label(format!("Environment: {:?}", c.item.environment));
        if c.item.delivery == Delivery::RealValue {
            ui.label("Real value reaches the process. Reviewed destinations do not confine its networking.");
        } else {
            ui.label("Placeholder restricted to these exact hosts and ports before expiry.");
        }
        ui.label(format!(
            "Project: {}",
            c.project
                .as_ref()
                .map_or("Incomplete", |p| p.label.as_str())
        ));
        if let Some(project) = &c.project {
            ui.label(format!(
                "Project identity: {}",
                crate::questions::access_request::display_text(&project.key)
            ));
        }
        ui.label(format!(
            "Folder: {}",
            crate::questions::access_request::display_text(&c.cwd)
        ));
        ui.strong("Requested scope; checked against Mac policy");
        ui.label(format!(
            "Action: {}",
            c.action.map_or("Incomplete", |a| match a {
                crate::questions::access_request::Action::Read => "Read",
                crate::questions::access_request::Action::Change => "Change",
                crate::questions::access_request::Action::Deploy => "Deploy",
                crate::questions::access_request::Action::Delete => "Delete",
            })
        ));
        for host in &c.hosts {
            ui.label(host);
        }
        ui.separator();
        ui.strong("The agent says");
        ui.label(&c.reason);
        ui.separator();
        ui.label(format!(
            "Expires: {}",
            crate::vault::format_utc(c.expires_at)
        ));
        ui.label(
            "Allows one scoped use attempt. The bouncer still checks the command and may ask you.",
        );
        ui.label("One attempt can make multiple network calls. No durable grant, remembered answer, production allowance or evaluation permission is saved.");
        if let Some(reason) = &c.local_review_reason {
            ui.label(format!("Review access on {}: {}", c.asker.name, reason));
        }
        let status = app
            .owner_ui
            .session
            .with_vault(|v| v.access_status(c.agent.id.parse().unwrap_or(0), r.id).ok())
            .flatten();
        if let Some(receipt) = &r.receipt {
            if let Some(device) = &receipt.device_name {
                ui.strong(format!("Answered on {device}"));
            } else {
                ui.strong("Access request ended without an answer");
            }
            ui.label(format!(
                "{:?} · Consent history; live permit: {}",
                receipt.outcome,
                status.as_ref().map_or("unavailable", |s| s.permit.as_str())
            ));
        }
        let live = status.as_ref().is_some_and(|s| s.state == "open") && unix_now() < c.expires_at;
        if ui
            .add_enabled(
                live && c.valid_answers.contains(&Choice::AllowOnce),
                egui::Button::new("Allow once"),
            )
            .clicked()
        {
            app.ask_owner(
                OwnerRequest::AllowAccessOnce {
                    request_id: r.id,
                    digest: r.card.digest.clone(),
                },
                Some(ui.ctx()),
            );
        }
        ui.add_space(12.0);
        if ui.add_enabled(live, egui::Button::new("Deny")).clicked() {
            match app.owner_ui.session.deny_access_request(r.id) {
                Ok(()) => app.set_ok("Denied."),
                Err(e) => app.set_err(e.message),
            }
        }
        if ui
            .add_enabled(live, egui::Button::new("Grant access on this Mac…"))
            .clicked()
        {
            app.ask_owner(
                OwnerRequest::GrantRequest {
                    request_id: r.id,
                    agent_id: c.agent.id.parse().unwrap_or(0),
                    item_id: c.item.local_id.parse().unwrap_or(0),
                    agent_name: c.agent.name.clone(),
                    item_name: c.item.name.clone(),
                    place: crate::vault::GrantPlace::Folder(c.cwd.clone()),
                    mode: crate::vault::ExecMode::Bouncer,
                },
                Some(ui.ctx()),
            );
        }
    });
}

#[cfg(test)]
mod answered_tests {
    use super::*;
    use crate::questions::{QuestionsView, RemoteAnswered};
    use crate::vault::TrustedDeviceKind;

    #[test]
    fn a_remote_answer_shows_answered_on_its_device_for_ten_minutes() {
        let answered = |run_id, device: &str, at| RemoteAnswered {
            run_id,
            agent: "claude-code".to_owned(),
            device_name: device.to_owned(),
            device_kind: TrustedDeviceKind::Iphone,
            kind: "approve_once".to_owned(),
            at,
        };
        let view = QuestionsView {
            answered: vec![
                answered(1, "Old iPhone", 1_000),
                answered(2, "Test iPhone", 2_000),
                answered(3, "Mac\u{202E}mini", 2_100),
            ],
            ..QuestionsView::default()
        };
        assert_eq!(
            answered_lines(&view, 2_200),
            [
                "claude-code: Answered on Mac?mini",
                "claude-code: Answered on Test iPhone"
            ]
        );
        assert!(answered_lines(&view, 2_100 + ANSWERED_SHOWN_FOR + 1).is_empty());
        assert_eq!(
            answered(2, "Test iPhone", 0).line(),
            "Answered on Test iPhone"
        );
    }
}
