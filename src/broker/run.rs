//! Process runs with secrets in the environment (ADR 0006, ADR 0025).
//!
//! Check order:
//!
//! 1. The vault is open and unlocked.
//! 2. The token belongs to an active agent, and the token has not expired.
//! 3. The request has a valid form: items, command, working directory, purpose, and `PATH`.
//! 4. The working directory exists.
//! 5. For each item: the agent may see it (ADR 0025 §3f: no "Not for this agent"
//!    exception, and for an agent with "only these items" the item is listed; an unknown
//!    item gives the same `not_granted`), the owner reviewed the item after a restore,
//!    the item is not archived, the item has a process binding (a one-time-code setup key
//!    is never chosen automatically), and the variables differ. A process grant is no
//!    authority and is not read: the upgrade to schema 18 turned each grant that asked or
//!    had a rule into "Always ask for this agent".
//! 6. The bouncer decides the use (ADR 0025 §3), in this order. The command analysis
//!    gets the known hosts of the provider of each item (goal item B4), and the user
//!    request comes from the host hook when there is one (goal item B6).
//!    1. Hard rules and security vetoes ask the owner, whatever was remembered: a rule
//!       flag of the analysis (for example `secret_output`, a secret that goes to a
//!       host that is not a host of its provider, or a production word); a database
//!       host from the command that is not a known host of the items; "Always ask me"
//!       of the item or "Always ask for this agent"; and a production item (production from the owner, a value signal, or
//!       usage) without a production allowance that fits the run (ADR 0010, ADR 0025
//!       §3b): one for the item, the project, and the kind of action, where the rules are
//!       certain of that kind, and where each destination host of the run is a host of
//!       the allowance or a known host of the item.
//!    2. Without a running bouncer, each run asks the owner. Every remembered route
//!       below needs it.
//!    3. A working directory that is no project (the root, the home folder, and its
//!       parents) asks the owner: nothing can be remembered there.
//!    4. An item that is production only by default (no signal) asks at its first use
//!       in the project with a kind of action, until the owner answered for them.
//!    5. A remembered answer of the owner for each item, the project, and the kind of
//!       action starts the run, when each destination host of the run is a host of the
//!       answer or a known host of the item. For a production item (also by default),
//!       the rules must be certain of the kind of action. An answer that exists but
//!       does not cover the run (another host, an unsure kind) asks the owner.
//!    6. An item whose declaration names another project asks the owner (only an
//!       answer of the owner for this project, step 5, covers it).
//!    7. A missing user request or a missing declaration asks the owner (ADR 0008).
//!    8. An active remembered pattern starts the run (ADR 0009, ADR 0010). Patterns
//!       belong to the project key.
//!    9. A declaration value that is only a default (`declaration_source`) asks the
//!       owner: a weak signal makes the bouncer stricter.
//!    10. An item that this agent did not use in the project with this kind of action
//!        (history: a use that the bouncer allowed, after the last stricter
//!        declaration) asks the owner, unless its declaration is development (or local)
//!        with low risk.
//!    11. The model decides (contract v7, ADR 0008). History never starts a run by
//!        itself. Unclear asks the owner. A candidate in shadow mode answers in parallel
//!        and has no effect (goal item B9).
//! 7. A question waits for the owner (at most one per agent; the same request again
//!    joins it while the state that step 8 checks is the same, else it asks again). It
//!    names the answers that can take effect. "Allow ACTION in PROJECT"
//!    and "Allow production" remember an answer with the destination hosts of the run
//!    after step 8; a production item that already has its allowance is skipped. An
//!    owner denial blocks the pattern of the request.
//! 8. After a decision, the broker checks the vault, the agent, and the rules again.
//!    The vault epoch must be the same as in step 1. A lock, an unlock, or a restore
//!    in between makes the decision invalid (goal item V3).
//!    The credential revision, process binding, declaration and its sources, provider,
//!    exceptions, "Always ask me", the project, and canonical directories must also be
//!    the same as in the original check.
//! 9. The broker reads the secrets, releases the vault lock, and starts the process.
//!    A variable in placeholder mode (ADR 0011) gets a placeholder. The broker then
//!    starts a run proxy that puts the real value into HTTPS requests to the hosts of
//!    the variable, and on macOS the process can connect only to that proxy.
//!
//! Each refusal after step 2 and each result is stored in the activity log. Each decided
//! use of each item is stored in the use log (`item_use`).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;

use super::action_kind::{ActionKind, classify, classify_certain};
use super::approvals::{
    AnswerChoice, AnswerKind, ApprovalOutcome, CheckMethod, PendingRun, QuestionInfo, QuestionItem,
    QuestionRefusal, Settled, action_words, baseline_of,
};
use super::bouncer::{BouncerRequest, BouncerVerdict, DecisionContext, Learned, decide_learned};
use super::decide::{BrokerContext, authenticate, lock, locked_response};
use super::exec::{self, Network, SecretEnv};
use super::learning::{self, LoggedRequest, Outcome, RuleDenial, RunScope};
use super::project::{Project, project_of};
use super::proxy::{
    HostRule, OtherHosts, ProxyEvent, ProxyOptions, ProxyOutcome, ProxySecret, RunProxy,
    mint_placeholder,
};
use super::shadow::{self, ShadowInput};
use super::shell_risk::{self, Analysis, DB_HOST_FLAG, ProviderHosts, analyze_run, injection_flag};
use crate::agent::wire::{WireResponse, codes};
use crate::vault::answers::{AnswerScope, ProjectRef, normal_host};
use crate::vault::exceptions::Standing;
use crate::vault::providers;
use crate::vault::usage::{
    CUT_MARK, InteractionKind, MAX_COMMAND_SUMMARY_BYTES, NewItemUse, UseDecidedBy, UseOutcome,
};
use crate::vault::{
    ActivityDecision, AgentSummary, DecisionEntry, Declaration, DeclarationSource,
    DeclarationSources, EnvBinding, EnvDelivery, Environment, NewActivity, OwnerLabel, RealOutcome,
    RiskLevel, Vault, VaultErrorKind,
};

/// A shadow thread waits this long after the owner time limit for the real outcome.
const SHADOW_MARGIN: Duration = Duration::from_secs(30);

const MAX_ITEMS: usize = 16;
const MAX_ARGS: usize = 64;
const MAX_ARG_BYTES: usize = 4096;
const MAX_PURPOSE_BYTES: usize = 500;
const MAX_PATH_BYTES: usize = 4096;
/// The Activity text of a run ([`RunRequest::label`]).
const MAX_LABEL_BYTES: usize = 64;

/// The start of the activity text of a run that the owner approved on the iPhone. It
/// starts with "Owner approved", so the desktop inbox classifies it as before.
const OWNER_APPROVED_ON_IPHONE: &str = "Owner approved on the iPhone";
const INVALIDATED: &str = "The vault was locked, or Apassy stopped, before the run started. The approval is not valid. Send the request again after the owner unlocks the vault.";
/// ADR 0025 §3: an agent has at most one waiting question.
pub(super) const QUESTION_WAITING: &str = "Another question of this agent waits for the owner in Apassy (up to 5 minutes). Wait for that answer, then call again with the same request. The same request again joins the waiting question.";
const QUESTION_SUPERSEDED: &str = "A newer call with the same request took over the waiting question. The answer goes to that call.";
/// The start of the activity text of a run that the owner approved and remembered for the
/// project. It starts with "Owner approved", so the desktop inbox classifies it as before.
const OWNER_REMEMBERED: &str = "Owner approved and remembered the answer";
const RELOCKED: &str =
    "The vault was locked while Apassy checked this request. Send the request again.";
/// The device of an answer on the Mac.
const ANSWERED_ON_MAC: &str = "this Mac";
const ANSWERED_ON_IPHONE: &str = "iPhone";

/// A run request from the wire. Borrowed from the parsed request.
#[derive(Debug)]
pub struct RunRequest<'a> {
    pub items: &'a [u64],
    pub command: &'a [String],
    pub cwd: &'a str,
    pub purpose: &'a str,
    pub path: Option<&'a str>,
    pub user_request: Option<&'a str>,
    /// The agent host session of the adapter (goal item B6).
    pub host_session: Option<&'a str>,
}

impl RunRequest<'_> {
    /// The whole command, as the use log masks and then cuts it.
    fn command_text(&self) -> String {
        format!("run {}", self.command.join(" "))
    }

    /// Short text for the activity log: the whole command masked with the values of every
    /// item of the request, and only then cut, as the use log does (`store_uses`). An
    /// agent can put a value in the command; the Activity never shows it, nor a part of
    /// it at the cut. Without the values, only "run" and the cut mark.
    fn label(&self, vault: &Vault) -> String {
        match vault.command_mask(self.items) {
            Ok(mask) => mask.summary(&self.command_text(), MAX_LABEL_BYTES),
            Err(_) => format!("run {CUT_MARK}"),
        }
    }

    fn validate(&self) -> Result<(), String> {
        let unique: BTreeSet<u64> = self.items.iter().copied().collect();
        if self.items.is_empty() || self.items.len() > MAX_ITEMS || unique.len() != self.items.len()
        {
            return Err(format!("Name 1 to {MAX_ITEMS} different items."));
        }
        if self.command.is_empty() || self.command.len() > MAX_ARGS {
            return Err(format!("The command must have 1 to {MAX_ARGS} arguments."));
        }
        if self.command[0].is_empty()
            || self.command[0].starts_with('-')
            || self
                .command
                .iter()
                .any(|arg| arg.len() > MAX_ARG_BYTES || arg.contains('\0'))
        {
            return Err(
                "A command argument is empty, too long, or has a NUL byte, or the program name starts with -."
                    .to_owned(),
            );
        }
        let purpose = self.purpose.trim();
        if purpose.is_empty() || purpose.len() > MAX_PURPOSE_BYTES {
            return Err(format!(
                "State the purpose in 1 to {MAX_PURPOSE_BYTES} bytes."
            ));
        }
        if !self.cwd.starts_with('/') || self.cwd.contains('\0') {
            return Err("The working directory must be an absolute path.".to_owned());
        }
        if self
            .path
            .is_some_and(|path| path.len() > MAX_PATH_BYTES || path.contains('\0'))
        {
            return Err("The PATH value is not valid.".to_owned());
        }
        Ok(())
    }
}

struct Checked {
    agent: AgentSummary,
    /// Vault epoch of the first check. Every lock and unlock changes it.
    epoch: [u8; 32],
    /// The vault file of the first check. Each entry of the run goes only to it, also
    /// when the owner opens another vault during the run (ADR 0013).
    vault_file: PathBuf,
    cwd: PathBuf,
    /// The project of the working directory (ADR 0025 §3a). `None`: no project.
    project: Option<Project>,
    /// Canonical project directory: the root of the project, else the working
    /// directory. Remembered patterns generalize paths below it.
    project_dir: PathBuf,
    /// Working directory relative to the project directory.
    relative_dir: String,
    env_names: Vec<String>,
    /// The variables in placeholder mode (ADR 0011).
    placeholder_names: Vec<String>,
    /// Owner declarations, one per item. `None` when an item has none.
    declarations: Vec<Option<Declaration>>,
    /// The known hosts of the provider of each item with a provider (goal item B4).
    provider_hosts: Vec<ProviderHosts>,
    /// Exact item and permission state used by the owner or model. A later check
    /// must match this state before the broker reads any secret.
    authorization: Vec<ItemAuthorization>,
    /// What the bouncer knows about each item, in the order of the request.
    facts: Vec<ItemFacts>,
}

/// What the broker checks again after the answer of the owner, before it reads a secret.
type Rechecked<'a> = (
    &'a [ItemAuthorization],
    &'a Path,
    Option<&'a Project>,
    &'a [ProviderHosts],
);

impl Checked {
    /// The state that must not change between the question and the run.
    fn rechecked(&self) -> Rechecked<'_> {
        (
            &self.authorization,
            &self.cwd,
            self.project.as_ref(),
            &self.provider_hosts,
        )
    }
}

/// What the decision order (ADR 0025 §3) needs of one item.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ItemFacts {
    name: String,
    standing: Standing,
    /// "Always ask me" of the item.
    always_ask: bool,
    /// The environment or the risk of the declaration is only a default.
    weak_source: bool,
    /// The declaration is development or local, with low risk.
    dev_low: bool,
    /// Production from the owner, a value signal, or usage: the hard rule of ADR 0010.
    production: bool,
    /// Production only by default, without a signal: unconfirmed (ADR 0025 §4, §5).
    unconfirmed: bool,
    /// The project that the declaration names, when it is not the project of the run.
    foreign_project: Option<String>,
    /// The hosts where the secret may go: the hosts of the provider, the hosts of a
    /// placeholder, and the `host` field of the item. Lowercase, without a port.
    known_hosts: Vec<String>,
}

impl ItemFacts {
    /// "Always ask me" or "Always ask for this agent".
    fn asks_always(&self) -> bool {
        self.always_ask || self.standing == Standing::AlwaysAsk
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ItemAuthorization {
    binding: EnvBinding,
    revision: u64,
    declaration: Option<Declaration>,
    sources: DeclarationSources,
    provider: Option<String>,
    standing: Standing,
    always_ask: bool,
    host_field: Option<String>,
}

/// What the owner said before about each item of a run (ADR 0025 §3).
#[derive(Debug, Clone, Default)]
struct Known {
    /// A remembered answer that fits the run: for the item, the project, and the kind of
    /// action, with each destination host of the run among its hosts or the known hosts
    /// of the item. A production item needs a production allowance, and a production
    /// item (also by default) needs a kind of action that the rules are certain of.
    answer: Vec<bool>,
    /// An answer for the item, the project, and the kind of action exists, but it does
    /// not fit the run. The card says why.
    unfit: Vec<Option<&'static str>>,
    /// This agent used the item in the project with this kind of action before, and the
    /// bouncer allowed it, after the last stricter declaration.
    history: Vec<bool>,
}

/// How a use is decided.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Route {
    /// The owner decides. The text says why, for the card.
    Ask(String),
    /// A remembered answer of the owner.
    Answer,
    /// A remembered pattern.
    Pattern,
    /// The model step.
    Model,
}

/// The facts of one run that the decision order reads besides the items.
struct RunFacts<'a> {
    analysis: &'a Analysis,
    has_user_request: bool,
    pattern: bool,
    action: ActionKind,
    /// The destination hosts of the run, in the form of [`normal_host`].
    hosts: &'a [String],
}

/// The bouncer runs: a model is set, and the gate of Settings > Agents lets it answer.
/// The gate can start the model server, so it runs at most once per request.
struct Readiness<F: FnMut() -> Result<(), String>> {
    check: F,
    known: Option<Result<(), String>>,
}

impl<F: FnMut() -> Result<(), String>> Readiness<F> {
    fn new(check: F) -> Self {
        Self { check, known: None }
    }

    fn get(&mut self) -> Result<(), String> {
        if self.known.is_none() {
            self.known = Some((self.check)());
        }
        self.known
            .clone()
            .unwrap_or_else(|| Err("not checked".to_owned()))
    }
}

/// True when `host` is `known` or matches a known `*.domain`.
fn host_matches(host: &str, known: &str) -> bool {
    host == known
        || known
            .strip_prefix("*.")
            .is_some_and(|domain| host.ends_with(&format!(".{domain}")))
}

/// Each host of `hosts` is in `allowed`.
fn hosts_within<'a>(hosts: &[String], allowed: impl Iterator<Item = &'a String> + Clone) -> bool {
    hosts
        .iter()
        .all(|host| allowed.clone().any(|known| host_matches(host, known)))
}

/// The security vetoes and hard rules of step 6.1. Each gives one sentence for the card.
fn hard_rules(checked: &Checked, run: &RunFacts<'_>, known: &Known, place: &str) -> Vec<String> {
    let mut why = Vec::new();
    if !run.analysis.flags.is_empty() {
        why.push(format!("Rule flags: {}.", run.analysis.flags.join(", ")));
    }
    if let Some((host, name)) = foreign_db_host(checked, run) {
        why.push(format!(
            "The command connects to the database host {host}, which is not a host of \"{name}\"."
        ));
    }
    for (index, facts) in checked.facts.iter().enumerate() {
        if facts.production && !known.answer.get(index).copied().unwrap_or(false) {
            let mut text = format!(
                "\"{}\" is a production credential: you approve each run, unless you allow production for {place}: {}.",
                facts.name,
                action_words(run.action)
            );
            if let Some(Some(unfit)) = known.unfit.get(index) {
                text.push_str(&format!(" The allowance does not cover this run: {unfit}."));
            }
            why.push(text);
        }
        if facts.standing == Standing::AlwaysAsk {
            why.push(format!(
                "\"{}\" is set to always ask for this agent.",
                facts.name
            ));
        } else if facts.always_ask {
            why.push(format!("\"{}\" is set to always ask.", facts.name));
        }
    }
    why
}

/// A database host from the command that is not a known host of each item of the run,
/// with the name of an item that does not know it ([`uncovered_host`]).
fn foreign_db_host(checked: &Checked, run: &RunFacts<'_>) -> Option<(String, String)> {
    if !db_host_from_command(run.analysis) {
        return None;
    }
    uncovered_host(&checked.facts, run.hosts)
        .map(|(host, facts)| (host.clone(), facts.name.clone()))
}

/// A destination host of the run that an item of the run does not know, with that item
/// (Gate 1, NEW-1). The secret of each item goes to the process, so each item must know
/// each host by its own known hosts. One item never vouches for another: an item that an
/// agent added, with its own `host` field, does not bring that host to an item of the
/// owner.
fn uncovered_host<'a, 'b>(
    facts: &'b [ItemFacts],
    hosts: &'a [String],
) -> Option<(&'a String, &'b ItemFacts)> {
    hosts.iter().find_map(|host| {
        facts
            .iter()
            .find(|facts| {
                !facts
                    .known_hosts
                    .iter()
                    .any(|known| host_matches(host, known))
            })
            .map(|facts| (host, facts))
    })
}

/// The decision order of ADR 0025 §3 up to the model step.
fn route<F: FnMut() -> Result<(), String>>(
    checked: &Checked,
    run: &RunFacts<'_>,
    known: &Known,
    ready: &mut Readiness<F>,
) -> Route {
    let place = checked.project.as_ref().map_or_else(
        || "this folder".to_owned(),
        |project| format!("\"{}\"", project.label),
    );
    let why = hard_rules(checked, run, known, &place);
    if !why.is_empty() {
        return Route::Ask(why.join(" "));
    }
    if let Err(reason) = ready.get() {
        return Route::Ask(format!(
            "No bouncer runs, so each run waits for you: {reason}"
        ));
    }
    if checked.project.is_none() {
        return Route::Ask(
            "The folder is not a project (the root, the home folder, or a parent of it), so Apassy remembers nothing there.".to_owned(),
        );
    }
    for (index, facts) in checked.facts.iter().enumerate() {
        if facts.unconfirmed && !known.answer.get(index).copied().unwrap_or(false) {
            let mut text = format!(
                "\"{}\" is production only by default (no signal found it). Its first use in {place} for {} asks you. Correct it to development, or allow it.",
                facts.name,
                action_words(run.action)
            );
            if let Some(Some(unfit)) = known.unfit.get(index) {
                text.push_str(&format!(" Your answer does not cover this run: {unfit}."));
            }
            return Route::Ask(text);
        }
    }
    if !known.answer.is_empty() && known.answer.iter().all(|answer| *answer) {
        return Route::Answer;
    }
    // An answer of the owner that does not cover this run, for example a run to another
    // host (Gate 1, A-2), asks: the owner decides the difference, not the model.
    for (index, facts) in checked.facts.iter().enumerate() {
        if let Some(Some(unfit)) = known.unfit.get(index) {
            return Route::Ask(format!(
                "Your answer for \"{}\" in {place} for {} does not cover this run: {unfit}.",
                facts.name,
                action_words(run.action)
            ));
        }
    }
    // The item of another project (ADR 0025 §3): only the owner decides, and an answer
    // of the owner for this project counts.
    for (index, facts) in checked.facts.iter().enumerate() {
        if let Some(declared) = &facts.foreign_project
            && !known.answer.get(index).copied().unwrap_or(false)
        {
            return Route::Ask(format!(
                "\"{}\" is declared for the project \"{declared}\", not for {place}.",
                facts.name
            ));
        }
    }
    if !run.has_user_request {
        return Route::Ask("The agent did not send the user request.".to_owned());
    }
    if let Some(index) = checked.declarations.iter().position(Option::is_none) {
        return Route::Ask(format!(
            "\"{}\" has no declaration.",
            checked.facts[index].name
        ));
    }
    if run.pattern {
        return Route::Pattern;
    }
    if let Some(facts) = checked.facts.iter().find(|facts| facts.weak_source) {
        return Route::Ask(format!(
            "The environment or the risk of \"{}\" is only a default, so the bouncer does not decide.",
            facts.name
        ));
    }
    for (index, facts) in checked.facts.iter().enumerate() {
        if !known.history.get(index).copied().unwrap_or(false) && !facts.dev_low {
            return Route::Ask(format!(
                "This agent did not use \"{}\" in {place} for {} before, and its declaration is not development with low risk.",
                facts.name,
                action_words(run.action)
            ));
        }
    }
    Route::Model
}

/// The answers that a question can take now (ADR 0025 §3): a remembered answer only
/// when it can take effect for a later run of the same kind.
fn valid_answers<F: FnMut() -> Result<(), String>>(
    checked: &Checked,
    run: &RunFacts<'_>,
    certain: Option<ActionKind>,
    production_waiting: bool,
    ready: &mut Readiness<F>,
) -> Vec<AnswerKind> {
    let mut valid = vec![
        AnswerKind::Once,
        AnswerKind::NeverForAgent,
        AnswerKind::AlwaysAskForAgent,
        AnswerKind::Disconnect,
    ];
    let sure = certain == Some(run.action)
        || checked
            .facts
            .iter()
            .all(|facts| !facts.production && !facts.unconfirmed);
    // "Always ask me" of an item asks every agent, so nothing can be remembered for it.
    // "Always ask for this agent" asks this agent only: an answer covers the others.
    let can_remember = checked.project.is_some()
        && run.analysis.flags.is_empty()
        && foreign_db_host(checked, run).is_none()
        && checked.facts.iter().all(|facts| !facts.always_ask)
        && sure
        && ready.get().is_ok();
    if can_remember {
        valid.push(if production_waiting {
            AnswerKind::Production(run.action)
        } else {
            AnswerKind::InProject(run.action)
        });
    }
    if checked.facts.iter().any(|facts| facts.unconfirmed) {
        valid.push(AnswerKind::CorrectEnvironment);
    }
    valid
}

/// Read the answers and the history of each item (ADR 0025 §3). A read error counts as
/// no answer and no history, so the owner decides.
fn known(
    vault: &Vault,
    items: &[u64],
    checked: &Checked,
    action: ActionKind,
    certain: Option<ActionKind>,
    hosts: &[String],
) -> Known {
    let Some(project) = &checked.project else {
        return known_nothing(items.len());
    };
    let mut known = Known::default();
    for (item, facts) in items.iter().zip(&checked.facts) {
        let scope = if facts.production {
            AnswerScope::Production
        } else {
            AnswerScope::Project
        };
        let answer = vault
            .answer_for(*item, &project.key, action, scope)
            .ok()
            .flatten();
        let unfit = answer.as_ref().and_then(|answer| {
            if (facts.production || facts.unconfirmed) && certain != Some(action) {
                Some("the rules are not certain of the kind of action")
            } else if !hosts_within(hosts, answer.hosts.iter().chain(&facts.known_hosts)) {
                Some("the command goes to another host")
            } else {
                None
            }
        });
        known.answer.push(answer.is_some() && unfit.is_none());
        known.unfit.push(unfit);
        known.history.push(
            vault
                .item_used_in_project(*item, &project.key, action, checked.agent.id)
                .unwrap_or(false),
        );
    }
    known
}

pub(super) fn run(ctx: &BrokerContext, token: &str, request: &RunRequest<'_>) -> WireResponse {
    let (checked, label) = {
        let mut guard = lock(&ctx.vault);
        let Some(vault) = guard.as_mut().filter(|vault| !vault.is_locked()) else {
            return locked_response();
        };
        let label = request.label(vault);
        let agent = match authenticate(vault, token, &label) {
            Ok(agent) => agent,
            Err(response) => return response,
        };
        match check(vault, &agent, request) {
            Ok(checked) => (checked, label),
            Err((code, reason)) => {
                record(
                    vault,
                    &agent,
                    request,
                    &label,
                    ActivityDecision::Deny,
                    &reason,
                );
                record_refused(vault, &agent, request, code);
                let user_request = request.user_request.unwrap_or_default();
                let _ = vault.record_decision(
                    &RuleDenial {
                        at: learning::now(),
                        agent_id: agent.id,
                        agent_name: &agent.name,
                        items: request.items,
                        user_request,
                        user_request_source: learning::agent_source(user_request),
                        command: request.command,
                        purpose: request.purpose,
                        reason: &reason,
                    }
                    .entry(),
                );
                return WireResponse::failure(code, reason);
            }
        }
    };

    // The bouncer runs without the vault lock. Its state has no secret value.
    let mut analysis = analyze_run(
        request.command,
        request.purpose,
        &checked.env_names,
        &checked.provider_hosts,
    );
    // Goal item B6: a user request from the host hook replaces the text from the agent.
    let resolved = ctx.prompts.resolve(
        checked.agent.id,
        &checked.epoch,
        request.host_session,
        &checked.cwd,
        request.user_request.unwrap_or_default(),
    );
    analysis.flags.extend(resolved.flags.iter().cloned());
    let user_request = resolved.text.as_str();
    // Dev round 2: an instruction to the reviewer in the user request asks the owner,
    // as one in the purpose does (`shell_risk::injection_flag`).
    if let Some(flag) = injection_flag(user_request)
        && !analysis.flags.iter().any(|known| known == flag)
    {
        analysis.flags.push(flag.to_owned());
        analysis.flags.sort();
        analysis.known_safe = false;
        analysis.known_command = false;
    }
    // ADR 0025 §3a: hard rules on the words, then the flags of the analysis. The kind
    // counts for a production item only when a rule is certain of it.
    let action = classify(request.command, &analysis);
    let certain = classify_certain(request.command, &analysis);
    let hosts = run_hosts(request.command);
    // `db_host_from_command` says only that the command names its database host. A
    // known host of each item settles it; a host that one item does not know keeps the
    // flag, so the owner decides (Gate 1, A-2, NEW-1).
    if db_host_from_command(&analysis) && uncovered_host(&checked.facts, &hosts).is_none() {
        analysis.flags.retain(|flag| flag != DB_HOST_FLAG);
    }
    let context = DecisionContext {
        analysis: &analysis,
        declarations: &checked.declarations,
        has_user_request: !user_request.is_empty(),
    };
    // Learning (ADR 0009, ADR 0010): the calibrated level and a remembered pattern.
    let now = learning::now();
    let scope = RunScope {
        agent_id: checked.agent.id,
        project_dir: &checked.project_dir,
        cwd: &checked.cwd,
        cwd_rel: &checked.relative_dir,
        items: request.items,
        declarations: &checked.declarations,
        instruction: "",
    };
    // ADR 0025 §3a: a pattern belongs to the project key, so all worktrees of one
    // repository share it.
    let pattern = learning::request_pattern(scope, request.command).map(|mut pattern| {
        if let Some(project) = &checked.project {
            pattern.key.project_dir.clone_from(&project.key);
        }
        pattern
    });
    // Goal item B9: the active model (the default bouncer or a promoted model) and the
    // candidate in shadow mode come from the vault. ADR 0025: the answers and the
    // history of each item.
    let (learned, models, known) = lock(&ctx.vault)
        .as_ref()
        .filter(|vault| !vault.is_locked() && vault.epoch() == checked.epoch)
        .map(|vault| {
            (
                learning::lookup(vault, pattern.as_ref(), now),
                shadow::models(vault, ctx.bouncer.as_ref()),
                known(vault, request.items, &checked, action, certain, &hosts),
            )
        })
        .unwrap_or_else(|| {
            (
                learning::LearningState::default(),
                shadow::Models::default(),
                known_nothing(request.items.len()),
            )
        });
    let always_asks = checked.facts.iter().any(ItemFacts::asks_always);
    // The setting of Settings > Agents: "Off" asks no model, and "When a run needs it"
    // starts the model server first. Unavailable asks the owner.
    let mut ready = Readiness::new(|| match &models.active {
        Some(_) => ctx
            .model_gate
            .as_ref()
            .map_or(Ok(()), |gate| gate.before_model()),
        None => Err("no bouncer is set.".to_owned()),
    });
    let run_facts = RunFacts {
        analysis: &analysis,
        has_user_request: context.has_user_request,
        pattern: learned.learned.pattern.is_some(),
        action,
        hosts: &hosts,
    };
    let route = route(&checked, &run_facts, &known, &mut ready);
    let bouncer_request = BouncerRequest {
        user_request: user_request.to_owned(),
        command: request.command.join(" "),
        relative_dir: checked.relative_dir.clone(),
        purpose: request.purpose.trim().to_owned(),
        env_names: checked.env_names.clone(),
        instruction: String::new(),
    };
    // Shadow mode (ADR 0010): for a request that reaches the model step, the candidate
    // answers on its own thread. Its answer goes only to the vault. The decision below
    // uses the active model only, and the broker does not wait for the candidate.
    let mut shadow_call = if route == Route::Model {
        models.candidate.clone().and_then(|candidate| {
            shadow::begin(
                Arc::clone(&ctx.vault),
                checked.epoch,
                candidate,
                bouncer_request.clone(),
                ShadowInput {
                    analysis: analysis.clone(),
                    declarations: checked.declarations.clone(),
                    has_user_request: context.has_user_request,
                    thresholds: learned.learned.thresholds,
                },
                ctx.approval_timeout + SHADOW_MARGIN,
            )
        })
    } else {
        None
    };
    let verdict = match (&route, &models.active) {
        (Route::Model, Some(bouncer)) => bouncer.evaluate(&bouncer_request),
        _ => BouncerVerdict::Unavailable("not asked".to_owned()),
    };
    // The model step: a remembered pattern never acts here, it acted in `route`.
    let route = if route == Route::Model {
        let decision = decide_learned(
            &verdict,
            &context,
            &Learned {
                thresholds: learned.learned.thresholds,
                pattern: None,
            },
        );
        if decision.ask_owner {
            Route::Ask(decision.note)
        } else {
            Route::Model
        }
    } else {
        route
    };
    let project_text = checked
        .project
        .as_ref()
        .map_or_else(String::new, |project| project.label.clone());
    let risk_note = match &route {
        Route::Ask(why) => why.clone(),
        Route::Answer => format!(
            "Remembered answer of the owner: allow {} in \"{project_text}\".",
            action_words(action)
        ),
        Route::Pattern => format!(
            "Remembered pattern allowed: {}.",
            learned.learned.pattern.as_deref().unwrap_or_default()
        ),
        Route::Model => {
            decide_learned(
                &verdict,
                &context,
                &Learned {
                    thresholds: learned.learned.thresholds,
                    pattern: None,
                },
            )
            .note
        }
    };
    let log_note = format!("{} {risk_note}", resolved.log_note());
    let needs_approval = matches!(route, Route::Ask(_));
    let (decided_by, mut use_decided_by) = match route {
        Route::Ask(_) => ("Owner approved", UseDecidedBy::Owner),
        Route::Answer => ("Remembered answer", UseDecidedBy::Answer),
        Route::Pattern => ("Remembered pattern", UseDecidedBy::Pattern),
        Route::Model => ("Bouncer allowed", UseDecidedBy::Bouncer),
    };
    let production_waiting = checked
        .facts
        .iter()
        .zip(&known.answer)
        .any(|(facts, answer)| facts.production && !answer);
    // ADR 0025 §3: the card offers only the answers that can take effect.
    let (valid, remember) = if needs_approval {
        let valid = valid_answers(
            &checked,
            &run_facts,
            certain,
            production_waiting,
            &mut ready,
        );
        // A pattern acts only with a running bouncer.
        let remember = learned
            .offer(pattern.as_ref(), &context, always_asks)
            .filter(|_| ready.get().is_ok());
        (valid, remember)
    } else {
        (Vec::new(), None)
    };
    let question_items: Vec<QuestionItem> = request
        .items
        .iter()
        .zip(&checked.facts)
        .map(|(item, facts)| QuestionItem {
            item_id: *item,
            name: facts.name.clone(),
            production: facts.production,
            unconfirmed: facts.unconfirmed,
            always_ask: facts.asks_always(),
        })
        .collect();
    // The activity log names an approval on the iPhone. The answer to the agent keeps
    // `decided_by`, and the inbox reads the prefix "Owner approved" in both cases.
    let mut logged_decided_by = decided_by;
    let mut answered_on = String::new();
    // The decision log entry (ADR 0009). It has no secret value.
    let logged = LoggedRequest {
        at: now,
        agent_id: checked.agent.id,
        agent_name: &checked.agent.name,
        scope,
        user_request,
        user_request_source: learning::resolved_source(user_request, &resolved.source),
        command: request.command,
        purpose: request.purpose.trim(),
        env_names: &checked.env_names,
        analysis: &analysis,
        verdict: &verdict,
        pattern: pattern.as_ref(),
        grant_asks: always_asks,
        thresholds: learned.learned.thresholds,
    };
    let mut remembered = false;
    let mut answer_choice: Option<AnswerChoice> = None;

    if !needs_approval {
        let outcome = match route {
            Route::Answer => Outcome::Remembered,
            Route::Pattern => Outcome::Automatic { by_pattern: true },
            _ => Outcome::Automatic { by_pattern: false },
        };
        let entry = logged.entry(outcome, &risk_note);
        record_decision_locked(ctx, &checked, &entry, pattern.as_ref());
        if let Some(call) = shadow_call.take() {
            call.finish(RealOutcome::Run, OwnerLabel::None);
        }
    }
    if needs_approval {
        // Goal item N3: a durable record of the wait. A crash leaves it, and the next
        // unlock gives the run its final entry.
        let wait = lock(&ctx.vault)
            .as_mut()
            .filter(|vault| !vault.is_locked())
            .and_then(|vault| {
                vault
                    .start_wait(&NewActivity {
                        agent_id: Some(checked.agent.id),
                        agent_name: checked.agent.name.clone(),
                        item_id: request.items.first().copied(),
                        operation: label.clone(),
                        decision: ActivityDecision::Deny,
                        reason: request.purpose.trim().to_owned(),
                    })
                    .ok()
            });
        // The wait ends when the vault session of the first check ends.
        let same_session = || {
            lock(&ctx.vault)
                .as_ref()
                .is_some_and(|vault| !vault.is_locked() && vault.epoch() == checked.epoch)
        };
        let pending = PendingRun {
            id: 0,
            agent: checked.agent.name.clone(),
            command: request.command.to_vec(),
            cwd: checked.cwd.display().to_string(),
            env_names: checked.env_names.clone(),
            purpose: request.purpose.trim().to_owned(),
            risk: risk_note.clone(),
            user_request: user_request.to_owned(),
            request_source: resolved.source.clone(),
            agent_request: resolved.agent_text.clone().unwrap_or_default(),
            remember,
            question: QuestionInfo {
                id: 0,
                item_ids: request.items.to_vec(),
                project: checked.project.clone(),
                action,
                production: production_waiting,
                why: risk_note.clone(),
                items: question_items,
                valid_answers: valid,
            },
        };
        // A call joins the waiting question only when it saw the same credentials.
        let settled = ctx.approvals.wait_for_question(
            pending,
            checked.agent.id,
            checked.epoch,
            baseline_of(&checked.rechecked()),
            ctx.approval_timeout,
            same_session,
        );
        // The wait record goes. False when a lock or a quit already gave the run its
        // final entry, or when the vault is locked now. Then the ticket goes, so the
        // next unlock ends a record that is still there.
        let own_entry = {
            let mut guard = lock(&ctx.vault);
            guard
                .as_mut()
                .filter(|vault| !vault.is_locked() && vault.path() == checked.vault_file)
                .is_some_and(|vault| {
                    wait.as_ref()
                        .is_none_or(|ticket| vault.end_wait(ticket).unwrap_or(true))
                })
        };
        drop(wait);
        let Settled {
            outcome,
            method: checked_with,
            answer: chosen,
            attached,
            ..
        } = match settled {
            Ok(settled) => settled,
            Err(refusal) => {
                let text = match refusal {
                    QuestionRefusal::Busy => QUESTION_WAITING,
                    QuestionRefusal::Superseded => QUESTION_SUPERSEDED,
                };
                if own_entry {
                    let mut guard = lock(&ctx.vault);
                    if let Some(vault) = guard
                        .as_mut()
                        .filter(|vault| !vault.is_locked() && vault.path() == checked.vault_file)
                    {
                        record(
                            vault,
                            &checked.agent,
                            request,
                            &label,
                            ActivityDecision::Deny,
                            text,
                        );
                        if refusal == QuestionRefusal::Busy {
                            record_uses(
                                vault,
                                &checked,
                                request,
                                action,
                                UseOutcome::Refused,
                                UseDecidedBy::Rule,
                                "",
                            );
                        }
                    }
                }
                return WireResponse::failure(codes::QUESTION_WAITING, text);
            }
        };
        answer_choice = chosen;
        if checked_with == Some(CheckMethod::Companion) {
            logged_decided_by = OWNER_APPROVED_ON_IPHONE;
            ANSWERED_ON_IPHONE.clone_into(&mut answered_on);
        } else if checked_with.is_some() {
            ANSWERED_ON_MAC.clone_into(&mut answered_on);
        }
        // Every owner answer goes to the decision log. A denial blocks the pattern.
        let mut entry = logged.entry(Outcome::Owner(outcome), &risk_note);
        entry.at = learning::now();
        record_decision_locked(ctx, &checked, &entry, pattern.as_ref());
        if !attached {
            let mut guard = lock(&ctx.vault);
            if let Some(vault) = guard
                .as_mut()
                .filter(|vault| !vault.is_locked() && vault.path() == checked.vault_file)
            {
                // One answer is one interaction: the owner check of an approval is
                // not counted again (`OwnerGate`).
                let _ = vault.record_interaction(InteractionKind::Question, &label, request.items);
            }
        }
        if let Some(call) = shadow_call.take() {
            let owner = match outcome {
                ApprovalOutcome::Approved
                | ApprovalOutcome::ApprovedAndRemembered
                | ApprovalOutcome::ApprovedAndGranted => OwnerLabel::Allow,
                ApprovalOutcome::Denied => OwnerLabel::Deny,
                ApprovalOutcome::TimedOut | ApprovalOutcome::Invalidated => OwnerLabel::None,
            };
            call.finish(RealOutcome::Ask, owner);
        }
        remembered = outcome == ApprovalOutcome::ApprovedAndRemembered;
        let refusal = match outcome {
            ApprovalOutcome::Approved
            | ApprovalOutcome::ApprovedAndRemembered
            | ApprovalOutcome::ApprovedAndGranted => None,
            ApprovalOutcome::Denied => Some((
                "approval_denied",
                "The owner denied this run.".to_owned(),
                UseOutcome::Denied,
                UseDecidedBy::Owner,
            )),
            ApprovalOutcome::TimedOut => Some((
                "approval_timeout",
                format!(
                    "The owner did not decide in {:.1} seconds.",
                    ctx.approval_timeout.as_secs_f32()
                ),
                UseOutcome::TimedOut,
                UseDecidedBy::Owner,
            )),
            ApprovalOutcome::Invalidated => Some((
                "approval_invalidated",
                INVALIDATED.to_owned(),
                UseOutcome::Refused,
                UseDecidedBy::Rule,
            )),
        };
        if let Some((code, reason, use_outcome, by)) = refusal {
            let reason = format!("{reason} {log_note}.");
            if own_entry {
                let mut guard = lock(&ctx.vault);
                if let Some(vault) = guard
                    .as_mut()
                    .filter(|vault| !vault.is_locked() && vault.path() == checked.vault_file)
                {
                    record(
                        vault,
                        &checked.agent,
                        request,
                        &label,
                        ActivityDecision::Deny,
                        &reason,
                    );
                    record_uses(
                        vault,
                        &checked,
                        request,
                        action,
                        use_outcome,
                        by,
                        &answered_on,
                    );
                }
            }
            return WireResponse::failure(code, reason);
        }
        use_decided_by = UseDecidedBy::Owner;
    }

    // The owner can lock, revoke, or change settings while a run waits. Check again.
    let secrets = {
        let mut guard = lock(&ctx.vault);
        let Some(vault) = guard.as_mut().filter(|vault| !vault.is_locked()) else {
            return if needs_approval {
                WireResponse::failure("approval_invalidated", INVALIDATED)
            } else {
                locked_response()
            };
        };
        let agent = match authenticate(vault, token, &label) {
            Ok(agent) => agent,
            Err(response) => return response,
        };
        // A decision belongs to one vault session. After a lock and an unlock, the
        // agent must send the request again.
        if vault.epoch() != checked.epoch {
            let (code, reason) = if needs_approval {
                ("approval_invalidated", INVALIDATED)
            } else {
                ("vault_locked", RELOCKED)
            };
            record(
                vault,
                &agent,
                request,
                &label,
                ActivityDecision::Deny,
                reason,
            );
            return WireResponse::failure(code, reason);
        }
        let rechecked = match check(vault, &agent, request) {
            Ok(rechecked) => rechecked,
            Err((code, reason)) => {
                record(
                    vault,
                    &agent,
                    request,
                    &label,
                    ActivityDecision::Deny,
                    &reason,
                );
                record_refused(vault, &agent, request, code);
                return WireResponse::failure(code, reason);
            }
        };
        if rechecked.rechecked() != checked.rechecked() {
            let reason = "The credential or its access changed while Apassy checked this run. Send the request again.";
            record(
                vault,
                &agent,
                request,
                &label,
                ActivityDecision::Deny,
                reason,
            );
            record_uses(
                vault,
                &checked,
                request,
                action,
                UseOutcome::Refused,
                UseDecidedBy::Rule,
                "",
            );
            return WireResponse::failure("authorization_changed", reason);
        }
        // ADR 0025: "Allow ACTION in PROJECT" and "Allow production" are saved now, in
        // the session of the decision and after the second check.
        if let Some(choice) = &answer_choice {
            let saved = save_answer(vault, &checked, request.items, choice, &answered_on, &hosts);
            if let Err(reason) = saved {
                record(
                    vault,
                    &agent,
                    request,
                    &label,
                    ActivityDecision::Deny,
                    &reason,
                );
                record_uses(
                    vault,
                    &checked,
                    request,
                    action,
                    UseOutcome::Refused,
                    UseDecidedBy::Rule,
                    &answered_on,
                );
                return WireResponse::failure(codes::ANSWER_FAILED, reason);
            }
            if saved == Ok(0) {
                answer_choice = None;
            } else if logged_decided_by != OWNER_APPROVED_ON_IPHONE {
                logged_decided_by = OWNER_REMEMBERED;
            }
        }
        // The run starts in the session of the decision. Now learning can count it.
        if remembered && let Some(pattern) = &pattern {
            let _ = learning::remember(vault, pattern, learning::now());
        }
        if route == Route::Pattern
            && let Some(id) = learned.active_id
        {
            let _ = vault.record_pattern_use(id, learning::now());
        }
        record_uses(
            vault,
            &checked,
            request,
            action,
            UseOutcome::Allowed,
            use_decided_by,
            &answered_on,
        );
        super::corrections::consider_items(vault, request.items);
        match read_secrets(vault, request.items) {
            Ok(secrets) => {
                for item_id in request.items {
                    let _ = vault.record_run(agent.id, *item_id);
                }
                secrets
            }
            Err(reason) => {
                record(
                    vault,
                    &agent,
                    request,
                    &label,
                    ActivityDecision::Deny,
                    &reason,
                );
                return WireResponse::failure("missing_secret", reason);
            }
        }
    };

    let mut secrets = secrets;
    let proxy = if secrets.proxied.is_empty() {
        None
    } else {
        let options = ProxyOptions {
            tls: ctx.tls.clone(),
            other_hosts: OtherHosts::Tunnel,
            enforce: true,
        };
        match RunProxy::start(std::mem::take(&mut secrets.proxied), options) {
            Ok(proxy) => Some(proxy),
            Err(_) => {
                let reason = "The run proxy did not start. The command did not run.";
                record_locked(
                    ctx,
                    &checked,
                    request,
                    &label,
                    ActivityDecision::Error,
                    reason,
                );
                return WireResponse::failure("proxy_failed", reason);
            }
        }
    };
    let network = proxy.as_ref().map(RunProxy::network);
    let result = exec::run_with(
        request.command,
        &checked.cwd,
        request.path,
        &secrets.env,
        &secrets.masks,
        network.map_or_else(Network::default, |network| Network {
            env: &network.env,
            sandbox_profile: network.sandbox_profile.as_deref(),
        }),
        ctx.run_timeout,
    );
    let enforced = network.is_some_and(|network| network.sandbox_profile.is_some());
    let requests = proxy.map(RunProxy::finish).unwrap_or_default();
    drop(secrets);
    let proxy_note = proxy_summary(&requests);
    match result {
        Ok(output) => {
            let reason = if output.timed_out {
                format!(
                    "{logged_decided_by}. The run timed out and was stopped. Directory: {}. {log_note}.",
                    checked.cwd.display()
                )
            } else {
                format!(
                    "{logged_decided_by}. Exit code {}. Directory: {}. {log_note}.{proxy_note}",
                    output
                        .exit_code
                        .map_or_else(|| "none".to_owned(), |code| code.to_string()),
                    checked.cwd.display()
                )
            };
            let decision = if output.timed_out {
                ActivityDecision::Error
            } else {
                ActivityDecision::Allow
            };
            record_locked(ctx, &checked, request, &label, decision, &reason);
            let mut answer = json!({
                "exit_code": output.exit_code,
                "timed_out": output.timed_out,
                "truncated": output.truncated,
                "stdout": output.stdout,
                "stderr": output.stderr,
                "secrets_in_environment": checked.env_names,
                "decided_by": decided_by,
                "note": "Secret values in the output are replaced with [apassy:NAME].",
            });
            if let Some(choice) = &answer_choice {
                answer["remembered"] = json!(format!(
                    "The owner allowed {} with these credentials in \"{}\". Later uses there of this kind may start without asking.{}",
                    action_words(choice.action),
                    choice.project.label,
                    if choice.production {
                        " This includes production for this kind of action only."
                    } else {
                        ""
                    }
                ));
            }
            if !checked.placeholder_names.is_empty() {
                answer["placeholders"] = json!(checked.placeholder_names);
                answer["network"] = json!({
                    "proxy": true,
                    "only_proxy": enforced,
                    "requests": requests,
                });
                answer["note"] = json!(PLACEHOLDER_NOTE);
            }
            WireResponse::success(answer)
        }
        Err(_) => {
            let reason = "The command did not start. Check the program name and PATH.";
            record_locked(
                ctx,
                &checked,
                request,
                &label,
                ActivityDecision::Error,
                reason,
            );
            WireResponse::failure("start_failed", reason)
        }
    }
}

fn known_nothing(items: usize) -> Known {
    Known {
        answer: vec![false; items],
        unfit: vec![None; items],
        history: vec![false; items],
    }
}

/// The canonical home folder, if `HOME` is usable.
fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .and_then(|home| canonical_dir(Path::new(&home)))
}

fn not_granted(item_id: u64) -> (&'static str, String) {
    (
        codes::NOT_GRANTED,
        format!("The owner did not let this agent use item {item_id}."),
    )
}

/// Letters and digits of `text` in lowercase, so "Demo project" and `demo-project`
/// compare equal.
fn project_words(text: &str) -> String {
    text.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// The project that a declaration names, when it is not `project` (ADR 0025 §3: the
/// item of another project asks). An empty name fits every project. A name fits the
/// label, the folder of the project, or its key; a path fits the root or the key.
pub(super) fn foreign_project(declared: &str, project: Option<&Project>) -> Option<String> {
    let declared = declared.trim();
    let project = project?;
    if declared.is_empty() {
        return None;
    }
    let path = Path::new(declared);
    if path.is_absolute() {
        let fits = canonical_dir(path)
            .is_some_and(|dir| dir == project.root || dir.display().to_string() == project.key);
        return (!fits).then(|| declared.to_owned());
    }
    let wanted = project_words(declared);
    let root_name = project
        .root
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let fits = !wanted.is_empty()
        && [project.label.as_str(), root_name.as_str()]
            .iter()
            .any(|name| project_words(name) == wanted);
    (!fits).then(|| declared.to_owned())
}

fn check(
    vault: &Vault,
    agent: &AgentSummary,
    request: &RunRequest<'_>,
) -> Result<Checked, (&'static str, String)> {
    request
        .validate()
        .map_err(|reason| ("invalid_request", reason))?;
    let cwd = canonical_dir(Path::new(request.cwd)).ok_or((
        "invalid_request",
        "The working directory does not exist.".to_owned(),
    ))?;
    // ADR 0025 §3f: a connected agent may use each item that its exceptions do not hide.
    // A process grant is no authority, and the broker does not read it.
    let view = vault.agent_view(agent.id).map_err(|_| {
        (
            "broker_error",
            "The broker cannot read the agent settings.".to_owned(),
        )
    })?;
    let project = project_of(&cwd, home_dir().as_deref());
    let mut env_names = Vec::new();
    let mut unique_env_names = BTreeSet::new();
    let mut placeholder_names = Vec::new();
    let mut declarations = Vec::new();
    let mut provider_hosts = Vec::new();
    let mut authorization = Vec::new();
    let mut facts = Vec::new();
    for item_id in request.items {
        // A hidden item and an unknown item give the same answer, so a refusal does
        // not tell which items exist.
        let details = match vault.details(*item_id) {
            Ok(details) => details,
            Err(err) if err.kind() == VaultErrorKind::NotFound => {
                return Err(not_granted(*item_id));
            }
            Err(_) => {
                return Err((
                    "broker_error",
                    "The broker cannot read the credential revision.".to_owned(),
                ));
            }
        };
        if !view.visible(*item_id) {
            return Err(not_granted(*item_id));
        }
        // Goal item V4: settings from a restored backup wait for the owner review.
        if vault.needs_review(*item_id).unwrap_or(true) {
            return Err(("review_required", review_reason(*item_id)));
        }
        // An archived item stays in the vault, but agents cannot use it.
        if vault.is_archived(*item_id).unwrap_or(true) {
            return Err(("item_archived", archived_reason(*item_id)));
        }
        let binding = vault.process_binding(*item_id).map_err(|_| {
            ("broker_error", "The broker cannot read the process field.".to_owned())
        })?.ok_or((
            "needs_field",
            format!("The owner must select one secret field for item {item_id} in Apassy before a process can use it."),
        ))?;
        // Old synced records can have a name that belongs to another local item.
        // Never let one item replace another item's value in the process environment.
        if !unique_env_names.insert(binding.env_name.clone()) {
            return Err((
                "duplicate_env_name",
                format!(
                    "Two requested credentials use the process variable {}. The owner must select different variable names in Apassy before this run.",
                    binding.env_name
                ),
            ));
        }
        let declaration = vault.declaration(*item_id).map_err(|_| {
            (
                "broker_error",
                "The broker cannot read the owner declaration.".to_owned(),
            )
        })?;
        let settings_error = |_| {
            (
                "broker_error",
                "The broker cannot read the settings of the credential.".to_owned(),
            )
        };
        let always_ask = vault.always_ask(*item_id).map_err(settings_error)?;
        let sources = vault
            .declaration_sources(*item_id)
            .map_err(settings_error)?;
        let host_field = vault.item_host_field(*item_id).map_err(settings_error)?;
        let standing = view.standing(*item_id);
        let is_production = declaration.as_ref().is_some_and(Declaration::is_production);
        // ADR 0025 §4: production from a value signal, usage, or the owner is strict. A
        // production value without a signal is only the most careful default.
        let unconfirmed = is_production && sources.environment == DeclarationSource::Default;
        let mut known_hosts = Vec::new();
        push_item(
            vault,
            *item_id,
            binding.clone(),
            ItemAuthorization {
                binding,
                revision: details.summary.revision,
                declaration: declaration.clone(),
                sources,
                provider: None,
                standing,
                always_ask,
                host_field: host_field.clone(),
            },
            &mut Collected {
                env_names: &mut env_names,
                placeholder_names: &mut placeholder_names,
                declarations: &mut declarations,
                provider_hosts: &mut provider_hosts,
                authorization: &mut authorization,
                known_hosts: &mut known_hosts,
            },
        )?;
        known_hosts.extend(host_field);
        known_hosts.sort();
        known_hosts.dedup();
        facts.push(ItemFacts {
            name: details.summary.title.clone(),
            standing,
            always_ask,
            weak_source: sources.environment == DeclarationSource::Default
                || sources.risk == DeclarationSource::Default,
            dev_low: declaration.as_ref().is_some_and(|declaration| {
                matches!(
                    declaration.environment,
                    Environment::Local | Environment::Development
                ) && declaration.risk == RiskLevel::Low
            }),
            production: is_production && !unconfirmed,
            unconfirmed,
            foreign_project: declaration
                .as_ref()
                .and_then(|declaration| foreign_project(&declaration.project, project.as_ref())),
            known_hosts,
        });
    }
    let project_dir = project
        .as_ref()
        .map(|project| project.root.clone())
        .filter(|dir| cwd.starts_with(dir))
        .unwrap_or_else(|| cwd.clone());
    let relative_dir = cwd
        .strip_prefix(&project_dir)
        .map(|rest| rest.display().to_string())
        .ok()
        .filter(|rest| !rest.is_empty())
        .unwrap_or_else(|| ".".to_owned());
    Ok(Checked {
        agent: agent.clone(),
        epoch: vault.epoch(),
        vault_file: vault.path().to_path_buf(),
        project,
        project_dir,
        cwd,
        relative_dir,
        env_names,
        placeholder_names,
        declarations,
        provider_hosts,
        authorization,
        facts,
    })
}

/// The lists that [`check`] collects for each item.
struct Collected<'a> {
    env_names: &'a mut Vec<String>,
    placeholder_names: &'a mut Vec<String>,
    declarations: &'a mut Vec<Option<Declaration>>,
    provider_hosts: &'a mut Vec<ProviderHosts>,
    authorization: &'a mut Vec<ItemAuthorization>,
    /// The known hosts of this item: its provider and its placeholder hosts.
    known_hosts: &'a mut Vec<String>,
}

/// Add the variable, the declaration, the provider hosts, and the authorization of one
/// item. `authorization` comes without its binding and provider; this fills them in.
fn push_item(
    vault: &Vault,
    item_id: u64,
    binding: EnvBinding,
    mut authorization: ItemAuthorization,
    out: &mut Collected<'_>,
) -> Result<(), (&'static str, String)> {
    out.declarations.push(authorization.declaration.clone());
    // Goal item B4: only the stored provider name. The broker does not run the
    // detection. An unknown provider has no hosts, as an item without a provider.
    let provider = vault.declaration_provider(item_id).map_err(|_| {
        (
            "broker_error",
            "The broker cannot read the credential provider.".to_owned(),
        )
    })?;
    let mut hosts = provider
        .as_deref()
        .map(|provider| providers::known_hosts(provider).to_vec())
        .unwrap_or_default();
    // A placeholder can go only to the hosts of the variable, so they are its
    // known hosts too.
    if let EnvDelivery::Placeholder(rules) = &binding.delivery {
        for rule in rules {
            if let Ok(rule) = HostRule::parse(rule)
                && !hosts.iter().any(|host| host == rule.host())
            {
                hosts.push(rule.host().to_owned());
            }
        }
        out.placeholder_names.push(binding.env_name.clone());
    }
    out.known_hosts
        .extend(hosts.iter().filter_map(|host| normal_host(host)));
    if !hosts.is_empty() {
        out.provider_hosts.push(ProviderHosts {
            env_name: binding.env_name.clone(),
            hosts,
        });
    }
    out.env_names.push(binding.env_name.clone());
    authorization.binding = binding;
    authorization.provider = provider;
    out.authorization.push(authorization);
    Ok(())
}

/// Save "Allow ACTION in PROJECT" or "Allow production" (ADR 0025 §3, §3b) after the
/// second check, with the destination hosts of the run and the known hosts of each item:
/// a production allowance for each production item when the owner allowed production,
/// and a project answer for each other item (also for an item that is production only
/// by default). A production item is skipped when the owner answered "Allow ACTION in
/// PROJECT": it already has its allowance, or the question would have asked for one. The
/// run passed the second check, so the items, their declarations, and the project are
/// as the owner saw them. A failed save of one item does not stop the others. Returns
/// how many answers were saved.
fn save_answer(
    vault: &mut Vault,
    checked: &Checked,
    items: &[u64],
    choice: &AnswerChoice,
    answered_on: &str,
    hosts: &[String],
) -> Result<usize, String> {
    if checked.project.as_ref() != Some(&choice.project) {
        return Err(
            "The project changed while Apassy checked this run. Nothing was saved. The command did not run."
                .to_owned(),
        );
    }
    let project = ProjectRef {
        key: choice.project.key.clone(),
        label: choice.project.label.clone(),
    };
    let on = if answered_on.is_empty() {
        ANSWERED_ON_MAC
    } else {
        answered_on
    };
    let mut saved = 0;
    for (item, facts) in items.iter().zip(&checked.facts) {
        let mut covered = hosts.to_vec();
        covered.extend(facts.known_hosts.iter().cloned());
        let result = if facts.production {
            if !choice.production {
                continue;
            }
            vault.allow_production(*item, &project, choice.action, on, &covered)
        } else {
            vault.remember_answer(*item, &project, choice.action, on, &covered)
        };
        if result.is_ok() {
            saved += 1;
        }
    }
    Ok(saved)
}

/// Refusal text for an item from a restored backup that the owner did not review yet.
pub(super) fn review_reason(item_id: u64) -> String {
    format!(
        "The vault was restored from a backup. The owner must review the agent settings of item {item_id} in Apassy (open the credential, Confirm settings) before an agent can use it."
    )
}

pub(super) fn archived_reason(item_id: u64) -> String {
    format!(
        "The owner archived item {item_id} in Apassy. An archived credential stays in the vault, but agents cannot use it."
    )
}

fn canonical_dir(path: &Path) -> Option<PathBuf> {
    let canonical = std::fs::canonicalize(path).ok()?;
    canonical.is_dir().then_some(canonical)
}

/// The database host of the command comes from the command line.
fn db_host_from_command(analysis: &Analysis) -> bool {
    analysis.flags.iter().any(|flag| flag == DB_HOST_FLAG)
}

/// The destination hosts of a run, in normal form ([`normal_host`]): the URLs, the
/// database hosts, and the HTTP proxies and targets of the command
/// (`shell_risk::command_hosts`).
fn run_hosts(command: &[String]) -> Vec<String> {
    let mut hosts: Vec<String> = shell_risk::command_hosts(command)
        .iter()
        .filter_map(|host| normal_host(host))
        .collect();
    hosts.sort();
    hosts.dedup();
    hosts
}

/// Store one use of each item of the run (ADR 0025 §5).
fn record_uses(
    vault: &mut Vault,
    checked: &Checked,
    request: &RunRequest<'_>,
    action: ActionKind,
    outcome: UseOutcome,
    decided_by: UseDecidedBy,
    answered_on: &str,
) {
    store_uses(
        vault,
        &checked.agent,
        request,
        checked.project.as_ref(),
        action,
        outcome,
        decided_by,
        answered_on,
    );
}

/// Store a use of each known item of a request that a check refused. A request with a
/// wrong form names no use.
fn record_refused(vault: &mut Vault, agent: &AgentSummary, request: &RunRequest<'_>, code: &str) {
    if code == "invalid_request" || request.validate().is_err() {
        return;
    }
    let project = canonical_dir(Path::new(request.cwd))
        .and_then(|cwd| project_of(&cwd, home_dir().as_deref()));
    let analysis = analyze_run(request.command, request.purpose, &[], &[]);
    let action = classify(request.command, &analysis);
    store_uses(
        vault,
        agent,
        request,
        project.as_ref(),
        action,
        UseOutcome::Refused,
        UseDecidedBy::Rule,
        "",
    );
}

#[allow(clippy::too_many_arguments)]
fn store_uses(
    vault: &mut Vault,
    agent: &AgentSummary,
    request: &RunRequest<'_>,
    project: Option<&Project>,
    action: ActionKind,
    outcome: UseOutcome,
    decided_by: UseDecidedBy,
    answered_on: &str,
) {
    let hosts = run_hosts(request.command);
    // The whole command, masked with the values of every item of the request, and only
    // then cut: a value of one item never shows in the row of another, and a value at
    // the cut never leaves a part (relay-feed-v1 section 7.2).
    let Ok(mask) = vault.command_mask(request.items) else {
        return;
    };
    let command_summary = mask.summary(&request.command_text(), MAX_COMMAND_SUMMARY_BYTES);
    drop(mask);
    for item_id in request.items {
        // Only an item that exists gets a row.
        if vault.details(*item_id).is_err() {
            continue;
        }
        let _ = vault.record_item_use(&NewItemUse {
            item_id: *item_id,
            agent_id: Some(agent.id),
            agent_name: agent.name.clone(),
            project_key: project.map_or_else(String::new, |project| project.key.clone()),
            project_label: project.map_or_else(String::new, |project| project.label.clone()),
            action,
            command_summary: command_summary.clone(),
            hosts: hosts.clone(),
            outcome,
            decided_by,
            answered_on: answered_on.to_owned(),
            decision_log_id: None,
        });
    }
}

/// The variables of a run. `env` has a real value or a placeholder for each item.
/// `masks` has the real value behind each placeholder, so the output never shows it.
struct RunSecrets {
    env: Vec<SecretEnv>,
    masks: Vec<SecretEnv>,
    proxied: Vec<ProxySecret>,
}

fn read_secrets(vault: &Vault, items: &[u64]) -> Result<RunSecrets, String> {
    let mut secrets = RunSecrets {
        env: Vec::new(),
        masks: Vec::new(),
        proxied: Vec::new(),
    };
    for item_id in items {
        let binding = vault
            .process_binding(*item_id)
            .map_err(|_| format!("The broker cannot read the process field of item {item_id}."))?
            .ok_or_else(|| {
                format!("The owner must select one secret field for item {item_id} in Apassy.")
            })?;
        let value = vault
            .reveal(*item_id, &binding.field)
            .map_err(|_| format!("Item {item_id} has no value in field {}.", binding.field))?
            .into_zeroizing();
        let EnvDelivery::Placeholder(hosts) = &binding.delivery else {
            secrets.env.push(SecretEnv {
                name: binding.env_name,
                value,
            });
            continue;
        };
        let placeholder = mint_placeholder(&value).ok_or_else(|| {
            format!(
                "The value of item {item_id} is too short for a placeholder. The owner can use the real value mode for {}.",
                binding.env_name
            )
        })?;
        let hosts = hosts
            .iter()
            .map(|host| HostRule::parse(host))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| format!("Item {item_id} has a host that is not valid."))?;
        secrets.env.push(SecretEnv {
            name: binding.env_name.clone(),
            value: zeroize::Zeroizing::new(placeholder.clone()),
        });
        secrets.masks.push(SecretEnv {
            name: binding.env_name.clone(),
            value: value.clone(),
        });
        secrets.proxied.push(ProxySecret {
            name: binding.env_name,
            placeholder,
            value,
            hosts,
        });
    }
    Ok(secrets)
}

const PLACEHOLDER_NOTE: &str = "Secret values in the output are replaced with [apassy:NAME]. The variables in `placeholders` hold a placeholder, not the real value. Apassy puts the real value into HTTPS requests to the hosts of each variable, in the Authorization header, a known API key header, or a known key parameter. `network.requests` lists each request. A request that Apassy stopped has the header X-Apassy-Proxy: refused and a reason.";

/// One sentence about the proxy for the activity log.
fn proxy_summary(requests: &[ProxyEvent]) -> String {
    if requests.is_empty() {
        return String::new();
    }
    let count = |outcome| {
        requests
            .iter()
            .filter(|event| event.outcome == outcome)
            .count()
    };
    format!(
        " Proxy: {} with a real value, {} without, {} tunneled, {} stopped, {} failed.",
        count(ProxyOutcome::Swapped),
        count(ProxyOutcome::Passed),
        count(ProxyOutcome::Tunneled),
        count(ProxyOutcome::Refused),
        count(ProxyOutcome::Failed),
    )
}

fn record(
    vault: &mut Vault,
    agent: &AgentSummary,
    request: &RunRequest<'_>,
    label: &str,
    decision: ActivityDecision,
    reason: &str,
) {
    // The history of each item of the run shows the entry (schema 10).
    let extra_items = request.items.get(1..).unwrap_or_default();
    let _ = vault.record_activity_for_items(
        &NewActivity {
            agent_id: Some(agent.id),
            agent_name: agent.name.clone(),
            item_id: request.items.first().copied(),
            operation: label.to_owned(),
            decision,
            reason: format!("{reason} Purpose: {}", request.purpose.trim()),
        },
        extra_items,
    );
}

/// Store a decision log entry when the vault is unlocked (ADR 0009).
fn record_decision_locked(
    ctx: &BrokerContext,
    checked: &Checked,
    entry: &DecisionEntry,
    pattern: Option<&learning::RequestPattern>,
) {
    let mut guard = lock(&ctx.vault);
    if let Some(vault) = guard
        .as_mut()
        .filter(|vault| !vault.is_locked() && vault.path() == checked.vault_file)
    {
        let _ = learning::record(vault, entry, pattern);
    }
}

fn record_locked(
    ctx: &BrokerContext,
    checked: &Checked,
    request: &RunRequest<'_>,
    label: &str,
    decision: ActivityDecision,
    reason: &str,
) {
    let mut guard = lock(&ctx.vault);
    if let Some(vault) = guard
        .as_mut()
        .filter(|vault| !vault.is_locked() && vault.path() == checked.vault_file)
    {
        record(vault, &checked.agent, request, label, decision, reason);
    }
}
