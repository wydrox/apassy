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
//! the week (ADR 0025 §1).
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
    AnswerKind, ApprovalQueue, PendingRun, QuestionInfo, QuestionItem, StricterAnswer, shown_path,
};
use crate::broker::server::QUESTION_WAIT;
use crate::contracts::CredentialKind;
use crate::desktop::owner_check::OwnerRequest;
use crate::desktop::owner_store::{OwnerSession, OwnerSummary};
use crate::desktop::{BrokerState, DesktopApp};
use crate::vault::Environment;
use crate::vault::agent_items::{
    Correction, CorrectionAnswer, CorrectionKind, CredentialRequest, RAISED_FROM_FACT,
};
use crate::vault::detect::{self, Detected};

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
    /// A waiting question, by run ID.
    Run(u64),
    /// An open credential request, by request ID.
    Request(u64),
    /// An open correction, by correction ID.
    Suggestion(u64),
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
    /// Its place in the list in the last frame. When it goes (an answer, a time-out), the
    /// decision that takes its place is selected.
    index: usize,
    /// "Disconnect AGENT…" waits for its confirmation: the run and the agent name.
    disconnect: Option<(u64, String)>,
    /// The request of the paste and its folder: the request ID and the folder UUID
    /// (`None`: the top level).
    form: Option<(u64, Option<String>)>,
    /// The paste of the selected request.
    paste: Paste,
}

/// What waits for the owner, in the order of the list.
pub(super) struct Open {
    pub(super) waiting: Vec<Waiting>,
    pub(super) requests: Vec<CredentialRequest>,
    pub(super) suggestions: Vec<(Correction, OwnerSummary)>,
}

impl Open {
    fn keys(&self) -> Vec<Key> {
        self.waiting
            .iter()
            .map(|waiting| Key::Run(waiting.run.id))
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

/// The question of a suggestion: "Is Stripe key a development credential?" or "Limit
/// Stripe key to acme-billing?".
pub(super) fn suggestion_question(correction: &Correction, name: &str) -> String {
    match correction.kind {
        CorrectionKind::Environment => {
            format!("Is {name} a {} credential?", correction.proposed)
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

/// The facts of a correction as rows for the owner, the signal first. Lists are joined,
/// a provider shows its name, and a folder its short path.
pub(super) fn fact_rows(facts: &Value) -> Vec<(String, String)> {
    const ORDER: [&str; 8] = [
        "signal",
        "provider",
        "hosts",
        "uses",
        "project_label",
        "project_key",
        "agents",
        RAISED_FROM_FACT,
    ];
    let Some(map) = facts.as_object() else {
        return match facts {
            Value::Null => Vec::new(),
            other => vec![("Facts".to_owned(), other.to_string())],
        };
    };
    let mut keys: Vec<&String> = map.keys().collect();
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
        "hosts" => "Hosts".to_owned(),
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

/// The red count of Decisions in the sidebar: what blocks an agent, the waiting
/// questions and the open credential requests. Suggestions do not count.
pub(super) fn badge_count(app: &DesktopApp, pending: &[PendingRun]) -> usize {
    pending.len() + open_requests(app)
}

/// Everything that waits for the owner, in the order of the list.
pub(super) fn open(app: &DesktopApp, pending: &[PendingRun]) -> Open {
    let session = &app.owner_ui.session;
    Open {
        waiting: waiting(app, pending),
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

/// Select a question, for example from the banner of another view.
pub(super) fn select(app: &mut DesktopApp, run_id: u64) {
    app.ui.decisions.selected = Some(Key::Run(run_id));
    app.ui.decisions.disconnect = None;
}

fn sync_selection(state: &mut State, open: &Open) {
    let keys = open.keys();
    state.selected = next_selection(&keys, state.selected, state.index);
    if let Some(selected) = state.selected {
        state.index = keys.iter().position(|key| *key == selected).unwrap_or(0);
    }
    if state
        .disconnect
        .as_ref()
        .is_some_and(|(run_id, _)| !keys.contains(&Key::Run(*run_id)))
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

/// One row of the list, with its key.
struct ListRow {
    key: Key,
    tile: kit::Tile,
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
                tile: kit::Tile::letter(super::agents::agent_color(&run.agent), &run.agent),
                title: item_names(run),
                subtitle: format!("{} · {}", run.agent, project_text(run)),
                production: production(run),
                left: Some(clock(waiting.left)),
            }
        })
        .collect();
    let requests: Vec<ListRow> = open
        .requests
        .into_iter()
        .map(|request| ListRow {
            key: Key::Request(request.id),
            tile: kit::Tile::letter(
                super::agents::agent_color(&request.agent_name),
                &request.agent_name,
            ),
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
            tile: super::credential_tile(item.kind, &item.service, &item.name),
            title: item.name,
            subtitle: suggestion_subtitle(&correction),
            production: false,
            left: None,
        })
        .collect();
    for (title, rows) in [
        ("Waiting", waiting),
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
    sync_selection(&mut app.ui.decisions, &open);
    let subtitle = app
        .owner_ui
        .session
        .week_counts()
        .map(|counts| counts.line())
        .unwrap_or_default();
    columns::list_toolbar(ui, "Decisions", &subtitle, |_| {});
    let groups = list_rows(open);
    let selected = app.ui.decisions.selected;
    let mut chosen = None;
    columns::grouped_rows(
        ui,
        "decisions-list",
        &groups,
        true,
        |ui, row| {
            let response = ui
                .push_id(("decision-row", row.key), |ui| {
                    decision_row(
                        ui,
                        &DecisionRow {
                            tile: row.tile.clone(),
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
        |ui| {
            if groups.is_empty() {
                columns::list_note(ui, "Nothing needs you");
            }
        },
    );
    if let Some(key) = chosen {
        app.ui.decisions.selected = Some(key);
        app.ui.decisions.disconnect = None;
    }
}

/// One row of the list.
struct DecisionRow<'a> {
    tile: kit::Tile,
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
    let tile_rect = Rect::from_min_size(
        Pos2::new(rect.left() + 8.0, rect.center().y - 16.0),
        Vec2::splat(32.0),
    );
    kit::paint_tile(ui, tile_rect, &row.tile);
    let (title_color, sub_color, time_color, dot) = if row.selected {
        let white = egui::Color32::WHITE;
        (white, egui::Color32::from_white_alpha(210), white, white)
    } else {
        (
            kit::LABEL,
            kit::SECONDARY,
            Tone::Warning.text(),
            kit::PRODUCTION,
        )
    };
    let galley = |value: egui::RichText, max: f32| {
        WidgetText::from(value).into_galley(ui, Some(TextWrapMode::Truncate), max, TextStyle::Body)
    };
    let mut right = rect.right() - 8.0;
    if let Some(left) = row.left {
        let time = galley(kit::text(left, Font::Callout).color(time_color), 60.0);
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
    let title = galley(
        kit::medium(row.title, Font::Body).color(title_color),
        text_width,
    );
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
    match app.ui.decisions.selected {
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
        None => {}
    }
    columns::detail_toolbar(ui, |_| {});
    columns::detail_body(ui, ("decision", None::<u64>), |ui| {
        super::shell::banners(app, ui, pending);
        notifications_notice(app, ui);
        let answered = app
            .owner
            .questions
            .as_ref()
            .map(|questions| answered_lines(&questions.view(), unix_now()))
            .unwrap_or_default();
        for line in &answered {
            kit::tone_note(ui, line, Tone::Accent);
        }
        columns::nothing_selected(
            ui,
            Icon::CheckCircle,
            "All clear",
            "Nothing waits for you. A new question also shows as a macOS notification.",
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
    let mut answer = None;
    columns::detail_toolbar(ui, |ui| more_menu(ui, &current.run, &mut answer));
    egui::Panel::bottom(egui::Id::new(("decision-bar", current.run.id)))
        .resizable(false)
        .show_separator_line(true)
        .frame(
            Frame::NONE
                .fill(kit::SURFACE)
                .inner_margin(Margin::symmetric(16, 10)),
        )
        .show(ui, |ui| action_bar(ui, &current.run, &mut answer));
    columns::detail_body(ui, ("decision", Some(current.run.id)), |ui| {
        super::shell::banners(app, ui, pending);
        notifications_notice(app, ui);
        draw_question(app, ui, &current, &mut answer);
    });
    if let Some(answer) = answer {
        apply(app, ui.ctx(), &current.run, answer);
    }
    disconnect_sheet(app, ui.ctx());
}

/// A short banner when macOS cannot show a notification. The controls are in Settings.
fn notifications_notice(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let Some(center) = &app.owner.notifications else {
        return;
    };
    let view = center.view();
    if view.channel.can_deliver() {
        return;
    }
    let summary = view.channel.summary();
    let open = kit::notice(
        ui,
        Tone::Warning,
        "macOS notifications are off",
        Some(&summary),
        |ui| kit::small_button(ui, "Open Settings", Style::Link).clicked(),
    );
    if open {
        app.open_settings_window();
        app.ui.settings_tab = super::settings::SettingsTab::Notifications;
    }
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

/// The bar at the bottom: Deny on the left; a caption; Allow Once; the main answer.
fn action_bar(ui: &mut egui::Ui, run: &PendingRun, answer: &mut Option<Answer>) {
    let question = &run.question;
    let main = primary(question);
    let main_label = primary_label(question);
    let caption = match (main, &question.project) {
        (Some(Primary::InProject(_)), Some(project)) => format!(
            "Allow is remembered for all agents in {}.",
            short(&project.label)
        ),
        (Some(Primary::Production(action)), Some(project)) => format!(
            "Production stays allowed for {} in {} for all agents.",
            crate::broker::approvals::action_words(action),
            short(&project.label)
        ),
        (Some(Primary::Correct), _) => unconfirmed(run).map_or_else(String::new, |item| {
            format!("Is {} a development credential?", item.name)
        }),
        _ => "Allow Once allows this run only.".to_owned(),
    };
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 8.0;
        if kit::button(ui, "Deny", Style::Destructive).clicked() {
            *answer = Some(Answer::Deny);
        }
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            match (main, &main_label) {
                (Some(Primary::Correct), Some(label)) => {
                    let item = unconfirmed(run);
                    if kit::button(ui, label, Style::Prominent).clicked()
                        && let Some(item) = item
                    {
                        *answer = Some(Answer::Development {
                            item_id: item.item_id,
                            name: item.name.clone(),
                        });
                    }
                    if kit::button(ui, "Production", Style::Bordered).clicked()
                        && let Some(item) = item
                    {
                        *answer = Some(Answer::MarkProduction {
                            item_id: item.item_id,
                            name: item.name.clone(),
                        });
                    }
                    if kit::button(ui, "Allow Once", Style::Bordered).clicked() {
                        *answer = Some(Answer::Once);
                    }
                }
                (Some(remembered), Some(label)) => {
                    if kit::button(ui, label, Style::Prominent).clicked() {
                        *answer = Some(match remembered {
                            Primary::Production(action) => Answer::Production(action),
                            Primary::InProject(action) => Answer::InProject(action),
                            Primary::Correct => Answer::Once,
                        });
                    }
                    if kit::button(ui, "Allow Once", Style::Bordered).clicked() {
                        *answer = Some(Answer::Once);
                    }
                }
                _ => {
                    if kit::button(ui, "Allow Once", Style::Prominent).clicked() {
                        *answer = Some(Answer::Once);
                    }
                }
            }
            ui.add(Label::new(kit::text(caption, Font::Callout).color(kit::SECONDARY)).truncate());
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
) {
    let run = &waiting.run;
    let question = &run.question;
    ui.horizontal(|ui| {
        kit::tile(
            ui,
            &kit::Tile::letter(super::agents::agent_color(&run.agent), &run.agent),
            48.0,
        );
        ui.add_space(6.0);
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 2.0;
            ui.add(
                Label::new(
                    kit::text(
                        format!("{} wants to use {}", run.agent, item_names(run)),
                        Font::Title3,
                    )
                    .color(kit::LABEL),
                )
                .wrap(),
            );
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing.x = 0.0;
                ui.label(
                    kit::text(format!("{} · ", project_text(run)), Font::Callout)
                        .color(kit::SECONDARY),
                );
                ui.label(
                    kit::text(
                        format!("{} left to answer", clock(waiting.left)),
                        Font::Callout,
                    )
                    .color(Tone::Warning.text()),
                );
            });
        });
    });
    if let Some(note) = local_only_note(app, run.id) {
        ui.add_space(8.0);
        kit::tone_note(ui, &note, Tone::Warning);
    }
    ui.add_space(16.0);
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
        s.labeled(
            "Sends to",
            kit::text(
                if hosts.is_empty() {
                    "No host in the command".to_owned()
                } else {
                    hosts.join(", ")
                },
                Font::Body,
            )
            .color(kit::SECONDARY),
        );
    });
    if !run.user_request.is_empty() {
        let source = if run.request_source.is_empty() {
            "from the agent"
        } else {
            run.request_source.as_str()
        };
        kit::section(ui, Some("Request"), None, |s| {
            s.row(|ui| {
                kit::paragraph(
                    ui,
                    format!("\"{}\" ({source})", run.user_request),
                    Font::Body,
                    kit::LABEL,
                );
                // Goal item B6: the hook request replaced a different text of the agent.
                if !run.agent_request.is_empty() {
                    kit::tone_note(
                        ui,
                        format!(
                            "The agent sent a different request: \"{}\"",
                            run.agent_request
                        ),
                        Tone::Warning,
                    );
                }
            });
        });
    }
    kit::section(ui, Some("Command"), None, |s| {
        s.row(|ui| {
            ui.add(
                Label::new(kit::text(shell_words(&run.command), Font::Mono).color(kit::LABEL))
                    .wrap(),
            );
        });
    });
    let why = if !question.why.is_empty() {
        question.why.clone()
    } else if !run.risk.is_empty() {
        run.risk.clone()
    } else {
        "The bouncer did not decide this run, so it asks you.".to_owned()
    };
    kit::section(ui, Some("Why you are asked"), None, |s| {
        s.row(|ui| kit::paragraph(ui, why, Font::Body, kit::LABEL));
    });
    // The correction stays at hand when the bar offers a remembered answer.
    if question
        .valid_answers
        .contains(&AnswerKind::CorrectEnvironment)
        && primary(question) != Some(Primary::Correct)
    {
        kit::section(
            ui,
            Some("Environment"),
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
    kit::note(
        ui,
        "The process can read these secrets. An allow needs Touch ID or the passphrase now. A notification is not an approval.",
    );
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
        Answer::Once => app.ask_owner(OwnerRequest::ApproveRun(run.clone()), Some(ctx)),
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
        Answer::Development { item_id, name } => app.ask_owner(
            OwnerRequest::CorrectEnvironment {
                run_id: run.id,
                agent: run.agent.clone(),
                item_id,
                name,
                environment: Environment::Development,
            },
            Some(ctx),
        ),
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
            app.ui.decisions.disconnect = Some((run.id, run.agent.clone()));
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
    let Some((run_id, agent)) = app.ui.decisions.disconnect.clone() else {
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
    egui::Panel::bottom(egui::Id::new(("request-bar", request.id)))
        .resizable(false)
        .show_separator_line(true)
        .frame(
            Frame::NONE
                .fill(kit::SURFACE)
                .inner_margin(Margin::symmetric(16, 10)),
        )
        .show(ui, |ui| request_bar(ui, ready, &mut answer));
    columns::detail_body(ui, ("request", request.id), |ui| {
        super::shell::banners(app, ui, pending);
        notifications_notice(app, ui);
        request_header(ui, request);
        ui.add_space(16.0);
        kit::section(ui, None, None, |s| {
            s.labeled(
                "For",
                kit::text(&request.purpose, Font::Body).color(kit::SECONDARY),
            );
            s.row(|ui| get_it_at(ui, &request.where_to_get));
            s.row(|ui| {
                ui.horizontal(|ui| {
                    ui.label(kit::text("Saves to", Font::Body).color(kit::LABEL));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let label = tree.path_label(folder.as_deref());
                        let menu = kit::picker(
                            ui,
                            ("request-folder", request.id),
                            &mut folder,
                            &tree.choices(),
                            label.as_str(),
                            170.0,
                        );
                        ui.ctx().accesskit_node_builder(menu.id, |node| {
                            node.set_label(format!("Saves to, {label}"));
                        });
                    });
                });
            });
        });
        kit::section(ui, Some("Key"), None, |s| {
            s.row(|ui| paste_field(ui, &mut app.ui.decisions.paste.0));
        });
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
        kit::note(
            ui,
            format!(
                "{} never sees the value. The bouncer decides each use of it.",
                request.agent_name
            ),
        );
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
    ui.horizontal(|ui| {
        kit::tile(
            ui,
            &kit::Tile::letter(
                super::agents::agent_color(&request.agent_name),
                &request.agent_name,
            ),
            48.0,
        );
        ui.add_space(6.0);
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 2.0;
            ui.add(
                Label::new(kit::text(request_title(request), Font::Title3).color(kit::LABEL))
                    .wrap(),
            );
            ui.label(kit::text(request_project(request), Font::Callout).color(kit::SECONDARY));
        });
    });
}

/// "Get it at": the domain in bold as plain text, then the whole text of the agent. Not
/// a link: the text came from an agent, and a link can hide where it goes.
fn get_it_at(ui: &mut egui::Ui, where_to_get: &str) {
    let domains = where_domains(where_to_get);
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
        if ui
            .add_enabled_ui(ready, |ui| kit::button(ui, "Save", Style::Prominent))
            .inner
            .clicked()
        {
            *answer = Some(RequestAnswer::Save);
        }
        if kit::button(ui, "Not Now", Style::Bordered).clicked() {
            *answer = Some(RequestAnswer::NotNow);
        }
        let caption = if ready {
            "Save adds a new credential. Apassy shows no value."
        } else {
            "Paste the key to save it."
        };
        ui.add(Label::new(kit::text(caption, Font::Callout).color(kit::SECONDARY)).truncate());
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
    egui::Panel::bottom(egui::Id::new(("suggestion-bar", correction.id)))
        .resizable(false)
        .show_separator_line(true)
        .frame(
            Frame::NONE
                .fill(kit::SURFACE)
                .inner_margin(Margin::symmetric(16, 10)),
        )
        .show(ui, |ui| suggestion_bar(ui, app, correction, &mut answer));
    columns::detail_body(ui, ("suggestion", correction.id), |ui| {
        super::shell::banners(app, ui, pending);
        notifications_notice(app, ui);
        let tile = item_tile(app, item.id, &item.name);
        ui.horizontal(|ui| {
            kit::tile(ui, &tile, 48.0);
            ui.add_space(6.0);
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 2.0;
                ui.add(
                    Label::new(
                        kit::text(suggestion_question(correction, &item.name), Font::Title3)
                            .color(kit::LABEL),
                    )
                    .wrap(),
                );
                ui.label(
                    kit::text("Apassy noticed this from how agents use it.", Font::Callout)
                        .color(kit::SECONDARY),
                );
            });
        });
        ui.add_space(16.0);
        let facts = fact_rows(&correction.facts);
        kit::section(ui, None, None, |s| {
            s.labeled(
                "Credential",
                kit::text(&item.name, Font::Body).color(kit::SECONDARY),
            );
            for (label, value) in &facts {
                s.labeled(label, kit::text(value, Font::Body).color(kit::SECONDARY));
            }
        });
        kit::note(ui, suggestion_note(correction));
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
        if kit::button(ui, "Ignore", Style::Bordered).clicked() {
            *answer = Some(SuggestionAnswer::Ignore);
        }
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            for (index, (label, choice)) in choices.iter().enumerate() {
                let style = if index == 0 {
                    Style::Prominent
                } else {
                    Style::Bordered
                };
                if kit::button(ui, label, style).clicked() {
                    *answer = Some(*choice);
                }
            }
            ui.add(Label::new(kit::text(caption, Font::Callout).color(kit::SECONDARY)).truncate());
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
