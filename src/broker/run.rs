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
//!    the item is not archived, ordinary values have a process binding and codes have
//!    one unambiguous OTP setting, and the variables differ. OTP seeds never enter runs. A process grant is no
//!    authority and is not read: the upgrade to schema 18 turned each grant that asked or
//!    had a rule into "Always ask for this agent".
//! 6. The bouncer decides the use (ADR 0025 §3), in this order. The command analysis
//!    gets the known hosts of the provider of each item (goal item B4), and the user
//!    request comes from the host hook when there is one (goal item B6).
//!    1. Hard rules and security vetoes ask the owner, whatever was remembered: a rule
//!       flag of the analysis (for example `secret_output`, a secret that goes to a
//!       host that is not a host of its provider, or a production word); a database
//!       host from the command that is not a known host of the items; "Always ask me"
//!       of the item or "Always ask for this agent"; and a production item with
//!       read-write or admin scope (ADR 0010, ADR 0031 of 2026-11-02): production of
//!       every source, also the careful default of an item without a label, and no
//!       production allowance or remembered answer waives it. Production with declared
//!       read-only scope goes on.
//!       A requested code additionally needs an explicit code-covering owner answer
//!       for this item/project/action. Patterns and models cannot waive that veto.
//!    2. Without a running bouncer, each run asks the owner. Every remembered route
//!       below needs it.
//!    3. A working directory that is no project (the root, the home folder, and its
//!       parents) asks the owner: nothing can be remembered there.
//!    4. Missing user request or declaration asks, including with a remembered answer.
//!    5. Fitting remembered execution answers keep their action/host checks. An
//!       existing answer that does not cover this run asks the owner.
//!    6. A foreign host or project asks. Each credential must cover each host;
//!       an explicit execution answer can add hosts or cover the foreign project.
//!    7. An active owner-taught pattern starts the run.
//!    8. Otherwise the model decides, including first use, read-only production and
//!       default-source classifications (ADR 0031). Default sources need 80% task
//!       match even for known safe commands and reads. Calibration cannot lower it.
//!       Low confidence asks. Evaluation scopes are retained data, not routing gates.
//!       A credential that the owner labeled development or local is judged with the
//!       development defaults for its default risk and reversibility
//!       ([`DeclarationSources::judged`], ADR 0031 of 2026-11-03), so that default
//!       risk is no default source.
//! 7. A question waits for the owner (at most one per agent; the same request again
//!    joins it while the state that step 8 checks is the same, else it asks again). It
//!    names the answers that can take effect. "Allow ACTION in PROJECT"
//!    and "Allow production" remember an answer with the destination hosts of the run
//!    after step 8; a production item that already has its allowance is skipped. An
//!    owner denial blocks the pattern of the request. "Allow once" changes neither
//!    classification nor future authorization. The evaluation setup offer is hidden.
//! 8. After a decision, the broker checks the vault, the agent, and the rules again.
//!    The vault epoch must be the same as in step 1. A lock, an unlock, or a restore
//!    in between makes the decision invalid (goal item V3).
//!    The credential revision, process binding, declaration and its sources, provider,
//!    exceptions, "Always ask me", the project, and canonical directories must also be
//!    the same as in the original check. Command bindings are rechecked before
//!    secrets are read. Evaluation scopes do not affect authorization.
//! 9. The broker rechecks the epoch and expiry before spawning. A session delivery
//!    guard serializes lock and spawn without holding the vault mutex over spawn.
//!    A variable in placeholder mode (ADR 0011) gets a placeholder. The broker then
//!    starts a run proxy that puts the real value into HTTPS requests to the hosts of
//!    the variable, and on macOS the process can connect only to that proxy.
//!
//! Each refusal after step 2 and each result is stored in the activity log. Each decided
//! use of each item is stored in the use log (`item_use`).
//!
//! A run of a cloud agent of the Mac's own node ([`evaluate_cloud`], ADR 0037 cloud slice,
//! decision 5) takes the same order with these differences: step 2 finds the active cloud
//! agent by its vault id (the node checked its token); the working directory is `/`, so
//! the run has no project and nothing can be remembered; the user request is the text
//! of the agent, "from the cloud agent, not verified" (no host hook; the injection flag
//! still applies); step 6 always asks the owner (`ReasonKind::CloudAgent`) with the hard
//! rules in the text, without a model, a pattern, or an answer; the card offers "Allow
//! once" only; and it stops after step 8, as the local evaluation does, with the
//! bindings of the second check. The node then releases the values.

use super::route_diagnostics::{Attempt, ReasonKind, RouteKind, TaskMatchBucket, VerdictKind};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use serde_json::json;

use super::action_kind::{ActionKind, classify, classify_certain};
use super::approvals::{
    AnswerChoice, AnswerKind, ApprovalOutcome, CheckMethod, EvaluationChoice, PendingRun,
    QuestionInfo, QuestionItem, QuestionRefusal, Settled, action_words, baseline_of,
};
use super::bouncer::{
    BouncerClient, BouncerRequest, BouncerVerdict, DecisionContext, Learned, decide_routed,
};
use super::decide::{BrokerContext, authenticate, lock, locked_response};
use super::exec::{self, Network, SecretEnv};
use super::learning::{self, LoggedRequest, Outcome, RuleDenial, RunScope};
use super::project::{Project, project_of};
use super::proxy::{
    HostRule, NetworkRule, OtherHosts, ProxyEvent, ProxyOptions, ProxyOutcome, ProxySecret,
    RunNetwork, RunProxy, mint_placeholder,
};
use super::shadow::{self, ShadowInput};
use super::shell_risk::{self, Analysis, DB_HOST_FLAG, ProviderHosts, analyze_run, injection_flag};
use crate::agent::wire::{WireResponse, codes};
use crate::decision_log;
use crate::vault::answers::{AnswerScope, ProjectRef, normal_host};
use crate::vault::exceptions::Standing;
use crate::vault::providers;
use crate::vault::usage::{
    CUT_MARK, InteractionKind, MAX_COMMAND_SUMMARY_BYTES, NewItemUse, UseDecidedBy, UseOutcome,
};
use crate::vault::{
    ActivityDecision, AgentSummary, DecisionEntry, DecisionMeta, DecisionWhy, Declaration,
    DeclarationSource, DeclarationSources, EnvBinding, EnvDelivery, NewActivity, OwnerLabel,
    RealOutcome, RequestKind, Vault, VaultErrorKind,
};

#[cfg(test)]
#[path = "run_tests.rs"]
mod tests;

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
const ANSWERED_ON_MAC: &str = concat!("this ", crate::computer!());
const ANSWERED_ON_IPHONE: &str = "iPhone";
/// Where the user request of a cloud run comes from, for the card and the log. It
/// starts with "from the cloud agent", which `learning::resolved_source` reads as text of
/// the agent.
pub const CLOUD_REQUEST_SOURCE: &str = "from the cloud agent, not verified";
/// Why a cloud run asks, before the notes of the hard rules.
const CLOUD_ASK: &str = concat!(
    "A cloud agent asks to run this through the node of this ",
    crate::computer!(),
    ". Every cloud run waits for you, and Apassy remembers nothing for it."
);
/// The `place` of the hard rules of a cloud run.
const CLOUD_PLACE: &str = "the cloud";

/// A run that a cloud agent asked the node for (ADR 0037, cloud slice, decision 5). The
/// node has its token and its own checks; the broker decides with the vault.
#[derive(Debug, Clone, Copy)]
pub struct CloudRequest<'a> {
    /// Vault items, in the order of the node's run.
    pub items: &'a [u64],
    pub command: &'a [String],
    pub purpose: &'a str,
    /// The text of the agent. Nothing verifies it.
    pub user_request: Option<&'a str>,
}

/// What the broker needs besides the request of a cloud run.
#[derive(Debug, Clone)]
pub struct CloudContext {
    /// The run of the node, for the log.
    pub relay_run: u64,
    /// The folder that the agent named in its own environment. It is not a folder of
    /// this Mac, has no function on a cloud run, and the card does not show it: it is
    /// text of the agent that could pose as a label of Apassy.
    pub agent_cwd: Option<String>,
    /// True when the node stops: a waiting question ends as invalidated.
    pub stop: Arc<AtomicBool>,
}

impl CloudContext {
    /// The folder line of the card: a fixed label, never `agent_cwd`.
    fn card_cwd(&self) -> String {
        concat!("(the cloud agent, not on this ", crate::computer!(), ")").to_owned()
    }

    fn stopped(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }
}

/// The answer of the broker to a cloud run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloudDecision {
    /// The owner approved and the second check passed: the node may release.
    Approved(CloudApproval),
    /// Denied, timed out, invalidated, or refused by a check. `reason` is for the agent
    /// and the log; it has no secret value.
    Refused { code: String, reason: String },
}

/// An approved cloud run, as the second check left it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudApproval {
    /// The vault session of the decision: the values are read in it or not at all.
    pub epoch: [u8; 32],
    /// The binding of each item of the run, in its order, as the second check read it.
    pub bindings: Vec<EnvBinding>,
    /// "Owner approved", or "Owner approved on the iPhone".
    pub decided_by: String,
    /// "this Mac", "iPhone", or empty.
    pub answered_on: String,
}

/// Who asks for a run.
#[derive(Clone, Copy)]
enum Caller<'a> {
    /// An agent on this Mac, with its vault token.
    Token(&'a str),
    /// A cloud agent of the node, by its vault agent id.
    Cloud {
        agent_id: u64,
        context: &'a CloudContext,
    },
}

impl<'a> Caller<'a> {
    fn cloud(self) -> Option<&'a CloudContext> {
        match self {
            Self::Token(_) => None,
            Self::Cloud { context, .. } => Some(context),
        }
    }

    fn label(&self, request: &RunRequest<'_>, vault: &Vault) -> String {
        match self {
            Self::Token(_) => request.label(vault),
            Self::Cloud { .. } => {
                request.label_of(vault, &format!("cloud {}", request.command_text()))
            }
        }
    }

    fn agent(&self, vault: &mut Vault, label: &str) -> Result<AgentSummary, WireResponse> {
        match self {
            Self::Token(token) => authenticate(vault, token, label),
            Self::Cloud { agent_id, .. } => authenticate_cloud(vault, *agent_id, label),
        }
    }
}

/// Step 2 of a cloud run: the active cloud agent `agent_id` whose node token has not
/// expired. The node checked the token itself; this is the vault's own check.
fn authenticate_cloud(
    vault: &mut Vault,
    agent_id: u64,
    action: &str,
) -> Result<AgentSummary, WireResponse> {
    match vault.cloud_agent_summary(agent_id) {
        Ok(agent) if agent.token_expired_at(learning::now()) => {
            let _ = vault.record_activity(&NewActivity {
                agent_id: Some(agent.id),
                agent_name: agent.name.clone(),
                item_id: None,
                operation: action.to_owned(),
                decision: ActivityDecision::Deny,
                reason: "The token of the remote agent expired. Connect the agent again: give it the MCP address of Bouncer > Agents.".to_owned(),
            });
            Err(WireResponse::failure(
                "token_expired",
                "The token of this cloud agent expired. Ask the owner to add the agent again in Apassy.",
            ))
        }
        Ok(agent) => Ok(agent),
        Err(err) if err.kind() == VaultErrorKind::NotFound => {
            let _ = vault.record_activity(&NewActivity {
                agent_id: None,
                agent_name: "Unknown cloud agent".to_owned(),
                item_id: None,
                operation: action.to_owned(),
                decision: ActivityDecision::Deny,
                reason: "The cloud agent is revoked or not in this vault.".to_owned(),
            });
            Err(WireResponse::failure(
                "unauthenticated",
                "This cloud agent is revoked, or it belongs to another vault than the one open now.",
            ))
        }
        Err(_) => Err(WireResponse::failure(
            "broker_error",
            "The broker cannot read the vault.",
        )),
    }
}

/// A run request from the wire. Borrowed from the parsed request.
#[derive(Debug)]
pub struct RunRequest<'a> {
    pub access_request_id: Option<u64>,
    pub items: &'a [u64],
    pub codes: &'a [u64],
    pub command: &'a [String],
    pub cwd: &'a str,
    pub purpose: &'a str,
    pub path: Option<&'a str>,
    pub user_request: Option<&'a str>,
    /// The agent host session of the adapter (goal item B6).
    pub host_session: Option<&'a str>,
}

impl RunRequest<'_> {
    fn all_items(&self) -> Vec<u64> {
        let mut items = self.items.to_vec();
        for item in self.codes {
            if !items.contains(item) {
                items.push(*item);
            }
        }
        items
    }

    /// The whole command, as the use log masks and then cuts it.
    fn command_text(&self) -> String {
        format!("run {}", self.command.join(" "))
    }

    /// Short text for the activity log: the whole command masked with the values of every
    /// item of the request, and only then cut, as the use log does (`store_uses`). An
    /// agent can put a value in the command; the Activity never shows it, nor a part of
    /// it at the cut. Without the values, only "run" and the cut mark.
    fn label(&self, vault: &Vault) -> String {
        self.label_of(vault, &self.command_text())
    }

    /// [`RunRequest::label`] of `text`, a text with the command in it.
    fn label_of(&self, vault: &Vault, text: &str) -> String {
        match vault.command_mask(&self.all_items()) {
            Ok(mask) => mask.summary(text, MAX_LABEL_BYTES),
            Err(_) => format!("run {CUT_MARK}"),
        }
    }

    fn validate(&self) -> Result<(), String> {
        let unique: BTreeSet<u64> = self.items.iter().copied().collect();
        let code_unique: BTreeSet<u64> = self.codes.iter().copied().collect();
        if self.all_items().is_empty()
            || self.all_items().len() > MAX_ITEMS
            || unique.len() != self.items.len()
            || code_unique.len() != self.codes.len()
        {
            return Err(format!("Name 1 to {MAX_ITEMS} different items."));
        }
        if !self.codes.is_empty() && self.access_request_id.is_some() {
            return Err("Scoped access consent does not cover one-time codes. Submit a code run for owner approval.".to_owned());
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
    includes_code: bool,
    standing: Standing,
    /// "Always ask me" of the item.
    always_ask: bool,
    /// The environment or the risk of the declaration is only a default.
    weak_source: bool,
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
    code_field: Option<String>,
    includes_value: bool,
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
}

/// How a use is decided.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Route {
    /// The owner decides. The text says why, for the card.
    Ask(String, ReasonKind),
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
    /// The active bouncer brain runs on another host (ADR 0035). Then every production
    /// declaration, read-only too, is a hard rule: a hostile host never allows one.
    remote_brain: bool,
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

/// Where the injection flag of a run found its phrase, as a closed word of the decision
/// (ADR 0046): `SOURCE:NUMBER`, the first match in the order of the confirmed host
/// prompt (or the agent's task text), the agent's purpose, and the command. Empty
/// without the flag. The text itself is never stored.
fn injection_source(
    analysis: &Analysis,
    user_request: &str,
    request_source: &str,
    request: &RunRequest<'_>,
) -> String {
    if !analysis
        .flags
        .iter()
        .any(|flag| flag == shell_risk::INJECTION_FLAG)
    {
        return String::new();
    }
    let task = if learning::resolved_source(user_request, request_source)
        == crate::vault::RequestSource::Host
    {
        "prompt"
    } else {
        "task"
    };
    std::iter::once((task, user_request))
        .chain(std::iter::once(("purpose", request.purpose)))
        .chain(request.command.iter().map(|arg| ("command", arg.as_str())))
        .find_map(|(source, text)| {
            shell_risk::injection_match(text).map(|(index, _)| format!("{source}:{index}"))
        })
        .unwrap_or_default()
}

/// Each host of `hosts` is in `allowed`.
fn hosts_within<'a>(hosts: &[String], allowed: impl Iterator<Item = &'a String> + Clone) -> bool {
    hosts
        .iter()
        .all(|host| allowed.clone().any(|known| host_matches(host, known)))
}

/// The security vetoes and hard rules of step 6.1. Each gives one sentence for the card.
fn hard_rules(
    checked: &Checked,
    run: &RunFacts<'_>,
    known: &Known,
    place: &str,
) -> Vec<(String, ReasonKind)> {
    let mut why = Vec::new();
    if !run.analysis.flags.is_empty() {
        why.push((
            super::reasons::flags_sentence(&run.analysis.flags),
            if run
                .analysis
                .flags
                .iter()
                .any(|flag| flag == super::prompts::FLAG_UNVERIFIED)
            {
                ReasonKind::HookUnverified
            } else if run
                .analysis
                .flags
                .iter()
                .any(|flag| flag == super::prompts::FLAG_AMBIGUOUS)
            {
                ReasonKind::HookAmbiguous
            } else {
                ReasonKind::HookFlags
            },
        ));
    }
    // Decision (a) still requires the agent to state a task. Report this even
    // when a production write guard or a remembered answer also applies.
    if !run.has_user_request {
        why.push((
            "The agent did not send the user request.".to_owned(),
            ReasonKind::MissingTask,
        ));
    }
    if let Some((host, name)) = foreign_db_host(checked, run) {
        why.push((format!(
            "The command connects to the database host {host}, which is not a host of \"{name}\"."
        ), ReasonKind::ForeignHost));
    }
    for (index, facts) in checked.facts.iter().enumerate() {
        if facts.includes_code
            && ((facts.production
                || checked
                    .declarations
                    .get(index)
                    .and_then(Option::as_ref)
                    .is_some_and(Declaration::is_production))
                || !known.answer.get(index).copied().unwrap_or(false))
        {
            why.push((format!("\"{}\" includes a one-time code: only an explicit owner project answer covering codes can skip this question.", facts.name), ReasonKind::OneTimeCode));
        }
        let (production, read_only) = production_and_read_only(checked, index);
        if production && read_only && run.remote_brain {
            why.push((format!(
                "\"{}\" is a production credential and the bouncer brain runs on another host: you approve each run in {place}: {}.",
                facts.name,
                action_words(run.action)
            ), ReasonKind::Production));
        } else if production && !read_only {
            let mut text = format!(
                "\"{}\" is a production credential with write or admin scope: you approve each run in {place}: {}.",
                facts.name,
                action_words(run.action)
            );
            if let Some(Some(unfit)) = known.unfit.get(index) {
                text.push_str(&format!(" The allowance does not cover this run: {unfit}."));
            }
            why.push((text, ReasonKind::Production));
        }
        if facts.standing == Standing::AlwaysAsk {
            why.push((
                format!("\"{}\" is set to always ask for this agent.", facts.name),
                ReasonKind::AlwaysAsk,
            ));
        } else if facts.always_ask {
            why.push((
                format!("\"{}\" is set to always ask.", facts.name),
                ReasonKind::AlwaysAsk,
            ));
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
    if let Some((_, reason)) = why.first() {
        return Route::Ask(
            why.iter()
                .map(|(note, _)| note.as_str())
                .collect::<Vec<_>>()
                .join(" "),
            *reason,
        );
    }
    if let Err(reason) = ready.get() {
        return Route::Ask(
            format!("No bouncer runs, so each run waits for you: {reason}"),
            ReasonKind::ModelUnavailable,
        );
    }
    if checked.project.is_none() {
        return Route::Ask(
            "The folder is not a project (the root, the home folder, or a parent of it), so Apassy remembers nothing there.".to_owned(),
        ReasonKind::NotProject);
    }
    if let Some(index) = checked.declarations.iter().position(Option::is_none) {
        return Route::Ask(
            format!("\"{}\" has no declaration.", checked.facts[index].name),
            ReasonKind::MissingDeclaration,
        );
    }
    if !checked
        .declarations
        .iter()
        .flatten()
        .any(Declaration::is_production)
        && !known.answer.is_empty()
        && known.answer.iter().all(|answer| *answer)
    {
        return Route::Answer;
    }
    // An answer of the owner that does not cover this run, for example a run to another
    // host (Gate 1, A-2), asks: the owner decides the difference, not the model.
    for (index, facts) in checked.facts.iter().enumerate() {
        if let Some(Some(unfit)) = known.unfit.get(index) {
            return Route::Ask(
                format!(
                    "Your answer for \"{}\" in {place} for {} does not cover this run: {unfit}.",
                    facts.name,
                    action_words(run.action)
                ),
                ReasonKind::UnfitAnswer,
            );
        }
    }
    // Every requested secret enters the process environment. A client may use it
    // implicitly, without spelling its variable in argv. Each item must cover
    // every detected destination; only an explicit fitting owner answer can add
    // hosts for that item. The database veto above is stricter and never waived.
    for (index, facts) in checked.facts.iter().enumerate() {
        if !known.answer.get(index).copied().unwrap_or(false)
            && let Some(host) = run.hosts.iter().find(|host| {
                !facts
                    .known_hosts
                    .iter()
                    .any(|known| host_matches(host, known))
            })
        {
            return Route::Ask(
                format!(
                    "The command goes to another host, {host}, which is not a host of \"{}\". You decide whether it may use this credential there.",
                    facts.name
                ),
                ReasonKind::ForeignHost,
            );
        }
    }
    // The item of another project (ADR 0025 §3): only the owner decides, and an answer
    // of the owner for this project counts.
    for (index, facts) in checked.facts.iter().enumerate() {
        if let Some(declared) = &facts.foreign_project
            && !known.answer.get(index).copied().unwrap_or(false)
        {
            return Route::Ask(
                format!(
                    "\"{}\" is declared for the project \"{declared}\", not for {place}.",
                    facts.name
                ),
                ReasonKind::ForeignProject,
            );
        }
    }
    if run.pattern
        && !checked
            .declarations
            .iter()
            .flatten()
            .any(Declaration::is_production)
    {
        return Route::Pattern;
    }
    Route::Model
}

/// The route of a cloud run: always the owner, with the notes of the hard rules, so the
/// card still says that an item is production or always asks.
fn cloud_route(checked: &Checked, run: &RunFacts<'_>, known: &Known) -> Route {
    let mut text = CLOUD_ASK.to_owned();
    for (note, _) in hard_rules(checked, run, known, CLOUD_PLACE) {
        text.push(' ');
        text.push_str(&note);
    }
    Route::Ask(text, ReasonKind::CloudAgent)
}

/// Whether an item of the run is production (from any source), and whether its declared
/// scope is read-only: the facts of the production rule (ADR 0031, 2026-11-02).
fn production_and_read_only(checked: &Checked, index: usize) -> (bool, bool) {
    let declaration = checked.declarations.get(index).and_then(Option::as_ref);
    let production = checked
        .facts
        .get(index)
        .is_some_and(|facts| facts.production)
        || declaration.is_some_and(Declaration::is_production);
    let read_only = declaration.is_some_and(|d| d.scope == crate::vault::Scope::ReadOnly);
    (production, read_only)
}

/// The first condition of a remembered answer that the run does not meet, in the order
/// of the checks, as a closed word (ADR 0046); `None` when an answer can be remembered.
/// "Always ask me" of an item asks every agent, so nothing can be remembered for it.
/// "Always ask for this agent" asks this agent only: an answer covers the others.
fn remember_blocker<F: FnMut() -> Result<(), String>>(
    checked: &Checked,
    run: &RunFacts<'_>,
    certain: Option<ActionKind>,
    ready: &mut Readiness<F>,
) -> Option<&'static str> {
    let sure = certain == Some(run.action)
        || checked
            .facts
            .iter()
            .all(|facts| !facts.production && !facts.unconfirmed);
    if checked.project.is_none() {
        Some("project")
    } else if !run.has_user_request {
        Some("task")
    } else if !checked.declarations.iter().all(Option::is_some) {
        Some("undeclared")
    } else if !run.analysis.flags.is_empty() {
        Some("flags")
    } else if foreign_db_host(checked, run).is_some() {
        Some("dbhost")
    } else if !checked.facts.iter().all(|facts| !facts.always_ask) {
        Some("always_ask")
    } else if !sure {
        Some("uncertain")
    } else if ready.get().is_err() {
        Some("brain")
    } else {
        None
    }
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
    let can_remember = remember_blocker(checked, run, certain, ready).is_none();
    // The production rule asks whatever the owner answered before, so a new allowance
    // would change nothing: the owner ticks "Remember" and the same question comes back.
    let production_asks = (0..checked.facts.len()).any(|index| {
        let (production, read_only) = production_and_read_only(checked, index);
        production && (!read_only || run.remote_brain)
    });
    // A project answer saves nothing for a production item, so with only those it is the
    // same empty promise.
    let saves_nothing = production_asks && checked.facts.iter().all(|facts| facts.production);
    if can_remember && !production_waiting && !saves_nothing {
        valid.push(AnswerKind::InProject(run.action));
    } else if can_remember && production_waiting && !production_asks {
        valid.push(AnswerKind::Production(run.action));
    }
    // "Development" or "Production" labels one item, the first unconfirmed item of the
    // run ([`QuestionInfo::classifiable_item`]). Each other one asks at a later run.
    if first_unconfirmed(checked).is_some() {
        valid.push(AnswerKind::CorrectEnvironment);
    }
    valid
}

/// The items of the run whose environment is production only by default, or that have
/// no declaration: the items that "Allow as dev" or "Allow as prod" can label.
fn item_unconfirmed(checked: &Checked, index: usize) -> bool {
    checked.facts[index].unconfirmed || checked.declarations[index].is_none()
}

fn first_unconfirmed(checked: &Checked) -> Option<usize> {
    (0..checked.facts.len()).find(|index| item_unconfirmed(checked, *index))
}

/// The index of `item_id` in the run when it is the first unconfirmed item, the item
/// that a classification labels. `None` for any other item.
fn classified_index(checked: &Checked, items: &[u64], item_id: u64) -> Option<usize> {
    let index = items.iter().position(|item| *item == item_id)?;
    (first_unconfirmed(checked) == Some(index)).then_some(index)
}

/// Save "Allow as dev" or "Allow as prod" ([`Settled::classification`]): label the one
/// item that the owner check named, never the other items of the run. A development
/// label lowers the default risk and reversibility of the item, so a bundled production
/// credential without a signal must keep its careful defaults. False when nothing was
/// saved: the item is not the first unconfirmed item, or the vault failed.
fn save_classification(
    vault: &mut Vault,
    checked: &Checked,
    items: &[u64],
    (environment, item_id): (crate::vault::Environment, u64),
) -> bool {
    classified_index(checked, items, item_id).is_some_and(|index| {
        vault
            .set_declaration_environment(items[index], environment)
            .is_ok()
    })
}

/// Read remembered execution answers. Evaluation scopes no longer affect routing.
fn known_state(
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
    for (index, (item, facts)) in items.iter().zip(&checked.facts).enumerate() {
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
            if checked.authorization[index].includes_value && !answer.includes_values {
                Some("the earlier answer covers codes only, not the stored secret")
            } else if facts.includes_code && !answer.includes_codes {
                Some("the earlier answer does not include one-time codes")
            } else if (facts.production || facts.unconfirmed) && certain != Some(action) {
                Some("the rules are not certain of the kind of action")
            } else if !hosts_within(hosts, answer.hosts.iter().chain(&facts.known_hosts)) {
                Some("the command goes to another host")
            } else {
                None
            }
        });
        known.answer.push(answer.is_some() && unfit.is_none());
        known.unfit.push(unfit);
    }
    known
}

pub(super) fn run(ctx: &BrokerContext, token: &str, request: &RunRequest<'_>) -> WireResponse {
    run_inner(ctx, Caller::Token(token), request, false, None, &mut None)
}

pub(super) fn evaluate(ctx: &BrokerContext, token: &str, request: &RunRequest<'_>) -> WireResponse {
    run_inner(ctx, Caller::Token(token), request, true, None, &mut None)
}

pub(super) fn fill_browser(
    ctx: &BrokerContext,
    token: &str,
    request: &RunRequest<'_>,
    fill: &super::browser_fill::Fill,
) -> WireResponse {
    run_inner(
        ctx,
        Caller::Token(token),
        request,
        false,
        Some(fill),
        &mut None,
    )
}

/// Decide a run of the cloud agent `agent_id` (the vault id of the agent) for the
/// node: the order of the module text for a cloud run, as the local evaluation runs it,
/// without a token, a host hook, or a project. It asks the owner every time, on this Mac
/// and on the iPhone, and reads no secret value.
pub fn evaluate_cloud(
    ctx: &BrokerContext,
    agent_id: u64,
    request: &CloudRequest<'_>,
    context: &CloudContext,
) -> CloudDecision {
    let run = RunRequest {
        access_request_id: None,
        items: request.items,
        codes: &[],
        command: request.command,
        // The root is no project: nothing can be remembered (step 6.3).
        cwd: "/",
        purpose: request.purpose,
        path: None,
        user_request: request.user_request,
        host_session: None,
    };
    let mut approved = None;
    let response = run_inner(
        ctx,
        Caller::Cloud { agent_id, context },
        &run,
        true,
        None,
        &mut approved,
    );
    match (response.ok, approved) {
        (true, Some(approval)) => CloudDecision::Approved(approval),
        (true, None) => CloudDecision::Refused {
            code: "broker_error".to_owned(),
            reason: "The broker did not decide this cloud run.".to_owned(),
        },
        (false, _) => {
            let (code, reason) = response.error.map_or_else(
                || {
                    (
                        "broker_error".to_owned(),
                        "The broker refused this cloud run.".to_owned(),
                    )
                },
                |error| (error.code, error.message),
            );
            CloudDecision::Refused { code, reason }
        }
    }
}

fn run_inner(
    ctx: &BrokerContext,
    caller: Caller<'_>,
    request: &RunRequest<'_>,
    evaluation_only: bool,
    browser_fill: Option<&super::browser_fill::Fill>,
    approved: &mut Option<CloudApproval>,
) -> WireResponse {
    let mut diagnostic = Attempt::new();
    let started = Instant::now();
    let items = request.all_items();
    let cloud = caller.cloud();
    let (checked, label) = {
        let mut guard = lock(&ctx.vault);
        let Some(vault) = guard.as_mut().filter(|vault| !vault.is_locked()) else {
            return locked_response();
        };
        let label = caller.label(request, vault);
        let agent = match caller.agent(vault, &label) {
            Ok(agent) => agent,
            Err(response) => return response,
        };
        match check_inner(vault, &agent, request, browser_fill) {
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
                if decision_log::enabled() {
                    decision_log::append(&decision_log::Line {
                        at: learning::now(),
                        request: if browser_fill.is_some() {
                            "browser_fill"
                        } else {
                            "run"
                        }
                        .to_owned(),
                        agent: agent.name.clone(),
                        items: items
                            .iter()
                            .map(|id| decision_log::Item {
                                id: *id,
                                name: String::new(),
                            })
                            .collect(),
                        route: format!("{:?}", RouteKind::Refused),
                        reason: format!("{:?}", ReasonKind::AccessCheck),
                        headline: super::reasons::words(ReasonKind::AccessCheck, &[], code)
                            .line
                            .to_owned(),
                        why: vault
                            .command_mask(&items)
                            .map(|mask| mask.summary(&reason, decision_log::MAX_TEXT))
                            .unwrap_or_default(),
                        outcome: "refused".to_owned(),
                        code: code.to_owned(),
                        millis: millis(started),
                        ..decision_log::Line::default()
                    });
                }
                let user_request = request.user_request.unwrap_or_default();
                let _ = vault.record_decision_with(
                    &RuleDenial {
                        at: learning::now(),
                        agent_id: agent.id,
                        agent_name: &agent.name,
                        items: &items,
                        user_request,
                        user_request_source: learning::agent_source(user_request),
                        command: request.command,
                        purpose: request.purpose,
                        reason: &reason,
                    }
                    .entry()
                    .with_why(&DecisionWhy {
                        reason: format!("{:?}", ReasonKind::AccessCheck),
                        code: code.to_owned(),
                        ..DecisionWhy::default()
                    }),
                    &decision_meta(browser_fill.is_some(), None),
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
    if browser_fill.is_some_and(|f| f.agent_can_read_page) {
        analysis.flags.push("secret_output".to_owned());
    }
    // Goal item B6: a user request from the host hook replaces the text from the agent.
    // A cloud agent has no hook: its text stays, marked as not verified.
    let resolved = match cloud {
        Some(_) => super::prompts::Resolved {
            text: request.user_request.unwrap_or_default().trim().to_owned(),
            source: CLOUD_REQUEST_SOURCE.to_owned(),
            agent_text: None,
            flags: Vec::new(),
            provenance: None,
        },
        None => ctx.prompts.resolve(
            checked.agent.id,
            &checked.epoch,
            request.host_session,
            &checked.cwd,
            request.user_request.unwrap_or_default(),
        ),
    };
    analysis.flags.extend(resolved.flags.iter().cloned());
    let user_request = resolved.text.as_str();
    // Dev round 2: an instruction to the reviewer in the user request asks the owner,
    // as one in the purpose does (`shell_risk::injection_flag`).
    if let Some(flag) = std::iter::once(user_request)
        .chain(request.command.iter().map(String::as_str))
        .find_map(injection_flag)
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
    let access_admission = if let Some(id) = request.access_request_id {
        if evaluation_only || items.len() != 1 {
            return WireResponse::failure(
                "access_once_unavailable",
                "A referenced access request requires one credential and a live run.",
            );
        }
        let Some(exact) = super::access_once::exact_run_hosts(request.command) else {
            return WireResponse::failure(
                "access_once_unavailable",
                concat!(
                    "This command's complete exact destination ports cannot be established. Review on this ",
                    crate::computer!(),
                    "."
                ),
            );
        };
        let Some(action) =
            certain.and_then(|a| serde_json::from_value(serde_json::json!(a.as_str())).ok())
        else {
            return WireResponse::failure(
                "access_once_unavailable",
                "This command's action is not certain.",
            );
        };
        let Some(cwd) = checked.cwd.to_str() else {
            return WireResponse::failure(
                "access_once_unavailable",
                "The folder has no lossless identity.",
            );
        };
        let Some(project) = checked.project.as_ref() else {
            return WireResponse::failure("access_once_unavailable", "This folder has no project.");
        };
        match super::access_once::Admission::consume(
            &ctx.vault,
            id,
            &crate::vault::access_once::CheckedScope {
                agent: checked.agent.id,
                item: items[0],
                cwd,
                project: &project.key,
                action,
                hosts: &exact,
            },
        ) {
            Ok(ticket) => Some(ticket),
            Err(e) => return e,
        }
    } else {
        None
    };
    let command_binding = super::evaluation_binding::command_binding(
        request.command,
        &checked.cwd,
        &checked.project_dir,
        certain.is_some(),
        request.path,
    );
    // `db_host_from_command` says only that the command names its database host. A
    // known host of each item settles it; a host that one item does not know keeps the
    // flag, so the owner decides (Gate 1, A-2, NEW-1).
    if db_host_from_command(&analysis) && uncovered_host(&checked.facts, &hosts).is_none() {
        analysis.flags.retain(|flag| flag != DB_HOST_FLAG);
    }
    // A default source keeps its sensitive declaration and needs 80% task match at
    // the model step (ADR 0031). Production write/admin asks in `route`, before it.
    let default_source = checked.facts.iter().any(|facts| facts.weak_source);
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
        items: &items,
        declarations: &checked.declarations,
        instruction: "",
    };
    // ADR 0025 §3a: a pattern belongs to the project key, so all worktrees of one
    // repository share it. A cloud run neither uses nor teaches one.
    let pattern = if cloud.is_some() {
        None
    } else {
        learning::request_pattern(scope, request.command).map(|mut pattern| {
            if let Some(project) = &checked.project {
                pattern.key.project_dir.clone_from(&project.key);
            }
            pattern
        })
    };
    // Goal item B9: the active model (the default bouncer or a promoted model) and the
    // candidate in shadow mode come from the vault, together with execution answers
    // (ADR 0031); stored evaluation scopes no longer affect routing. The bouncer brain
    // client is the current one of this request (ADR 0035): a hosting change in
    // Settings applies at the next run. It is read before the vault lock.
    let bouncer = super::decide::current_bouncer(ctx);
    let (learned, models, known, brain_mask) = lock(&ctx.vault)
        .as_ref()
        .filter(|vault| !vault.is_locked() && vault.epoch() == checked.epoch)
        .map(|vault| {
            (
                learning::lookup(vault, pattern.as_ref(), now),
                shadow::models(vault, bouncer.as_ref()),
                known_state(vault, &items, &checked, action, certain, &hosts),
                vault.command_mask(&items).ok(),
            )
        })
        .unwrap_or_else(|| {
            (
                learning::LearningState::default(),
                shadow::Models::default(),
                known_nothing(items.len()),
                None,
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
        remote_brain: models.active.as_ref().is_some_and(BouncerClient::is_remote),
    };
    let route = match cloud {
        Some(_) => cloud_route(&checked, &run_facts, &known),
        None => route(&checked, &run_facts, &known, &mut ready),
    };
    let bouncer_request = BouncerRequest {
        user_request: user_request.to_owned(),
        command: request.command.join(" "),
        relative_dir: checked.relative_dir.clone(),
        purpose: request.purpose.trim().to_owned(),
        env_names: checked.env_names.clone(),
        instruction: String::new(),
        task_provenance: resolved.provenance.unwrap_or_default().to_owned(),
    }
    .sanitized(Some(&checked.project_dir), home_dir().as_deref(), |text| {
        brain_mask.as_ref().map_or_else(
            || "[masked]".to_owned(),
            |mask| mask.summary(text, usize::MAX),
        )
    });
    diagnostic.event.inference_attempted = route == Route::Model && models.active.is_some();
    // Shadow mode (ADR 0010, ADR 0035): for a request that reaches the model step, the
    // candidate rides in the same request as `shadow_heads` when the host has its head
    // file. Its answer goes only to the vault. The decision below uses the active answer
    // only; a shadow failure never changes it.
    let shadow_pin = models
        .candidate
        .as_ref()
        .and_then(|candidate| candidate.pin.as_ref());
    let (verdict, shadow_verdict) = match (&route, &models.active) {
        (Route::Model, Some(bouncer)) => bouncer.evaluate_with_shadow(&bouncer_request, shadow_pin),
        _ => (BouncerVerdict::Unavailable("not asked".to_owned()), None),
    };
    let mut shadow_call = match (&route, &models.candidate) {
        (Route::Model, Some(candidate)) => Some(shadow::begin(
            Arc::clone(&ctx.vault),
            checked.epoch,
            candidate,
            shadow_verdict.as_ref(),
            &ShadowInput {
                analysis: analysis.clone(),
                declarations: checked.declarations.clone(),
                has_user_request: context.has_user_request,
                thresholds: learned.learned.thresholds,
                routed: true,
                default_source,
            },
        )),
        _ => None,
    };
    // The model step: a remembered pattern never acts here, it acted in `route`.
    let route = if route == Route::Model {
        let decision = decide_routed(
            &verdict,
            &context,
            &Learned {
                thresholds: learned.learned.thresholds,
                pattern: None,
            },
            default_source,
        );
        if decision.ask_owner {
            Route::Ask(decision.note, decision.reason)
        } else {
            Route::Model
        }
    } else {
        route
    };
    let (route_kind, reason_kind, verdict_kind) = match &route {
        Route::Ask(_, reason) => (RouteKind::Owner, *reason, VerdictKind::Asked),
        Route::Model => (
            RouteKind::Bouncer,
            ReasonKind::ModelAllowed,
            VerdictKind::Allowed,
        ),
        Route::Answer => (
            RouteKind::Answer,
            ReasonKind::RememberedAnswer,
            VerdictKind::Allowed,
        ),
        Route::Pattern => (
            RouteKind::Pattern,
            ReasonKind::RememberedPattern,
            VerdictKind::Allowed,
        ),
    };
    diagnostic.event.route = route_kind;
    diagnostic.event.reason = reason_kind;
    diagnostic.event.verdict = verdict_kind;
    diagnostic.event.task_match = TaskMatchBucket::of(verdict.fact("task_match"));
    diagnostic.finish_route();
    let project_text = checked
        .project
        .as_ref()
        .map_or_else(String::new, |project| project.label.clone());
    let risk_note = match &route {
        Route::Ask(why, _) => why.clone(),
        Route::Answer => format!(
            "Remembered answer of the owner: allow {} in \"{project_text}\".",
            action_words(action)
        ),
        Route::Pattern => format!(
            "Remembered pattern allowed: {}.",
            learned.learned.pattern.as_deref().unwrap_or_default()
        ),
        Route::Model => {
            decide_routed(
                &verdict,
                &context,
                &Learned {
                    thresholds: learned.learned.thresholds,
                    pattern: None,
                },
                default_source,
            )
            .note
        }
    };
    // The texts that end with this note add their own full stop.
    let log_note = format!("{} {risk_note}", resolved.log_note())
        .trim_end()
        .trim_end_matches('.')
        .to_owned();
    let risk_note = if request.codes.is_empty() {
        risk_note
    } else {
        format!("This run includes one-time codes. {risk_note}")
    };
    // The line of the decision log file. It has no command, user request, or purpose:
    // a remembered pattern names the command, so its note stays out.
    let (brain, brain_model, brain_error) = brain_answers(&verdict);
    let mut debug_line = decision_log::Line {
        at: now,
        request: if browser_fill.is_some() {
            "browser_fill"
        } else {
            "run"
        }
        .to_owned(),
        agent: checked.agent.name.clone(),
        items: items
            .iter()
            .zip(&checked.facts)
            .map(|(id, facts)| decision_log::Item {
                id: *id,
                name: facts.name.clone(),
            })
            .collect(),
        project: project_text.clone(),
        action: action.as_str().to_owned(),
        route: format!("{route_kind:?}"),
        reason: format!("{reason_kind:?}"),
        headline: super::reasons::words(reason_kind, &analysis.flags, "")
            .line
            .to_owned(),
        why: if route == Route::Pattern {
            "Remembered pattern allowed.".to_owned()
        } else {
            risk_note.clone()
        },
        flags: analysis.flags.clone(),
        task_source: learning::resolved_source(user_request, &resolved.source)
            .as_str()
            .to_owned(),
        default_source,
        brain,
        brain_model,
        brain_error,
        hosts: hosts.clone(),
        ..decision_log::Line::default()
    };
    let mut decision_id = None;
    let needs_approval = matches!(route, Route::Ask(..));
    let (decided_by, mut use_decided_by) = match route {
        Route::Ask(..) => ("Owner approved", UseDecidedBy::Owner),
        Route::Answer => ("Remembered answer", UseDecidedBy::Answer),
        Route::Pattern => ("Remembered pattern", UseDecidedBy::Pattern),
        Route::Model => ("Bouncer allowed", UseDecidedBy::Bouncer),
    };
    let production_waiting = checked
        .facts
        .iter()
        .zip(&known.answer)
        .any(|(facts, answer)| facts.production && !answer);
    // ADR 0025 §3: the card offers only the answers that can take effect. A cloud run
    // remembers nothing: "Allow once" only.
    let (valid, remember) = if needs_approval && cloud.is_some() {
        (vec![AnswerKind::Once], None)
    } else if needs_approval {
        let valid = valid_answers(
            &checked,
            &run_facts,
            certain,
            production_waiting,
            &mut ready,
        );
        // A pattern acts only with a running bouncer.
        // Pattern keys predate field/code selection. A code-only approval must not
        // teach a pattern that later authorizes the item's stored password.
        let remember = learned
            .offer(pattern.as_ref(), &context, always_asks)
            .filter(|_| request.codes.is_empty() && ready.get().is_ok());
        (valid, remember)
    } else {
        (Vec::new(), None)
    };
    // The closed words of the decision (ADR 0046): its reason kind, the remembered answer
    // that the question offers, the one-time codes of a run with one credential, and
    // where the injection flag found its phrase.
    let mut why_words = DecisionWhy {
        reason: format!("{reason_kind:?}"),
        code: String::new(),
        offered: valid
            .iter()
            .find_map(|answer| match answer {
                AnswerKind::InProject(action) => Some(format!("in_project:{}", action.as_str())),
                _ => None,
            })
            .or_else(|| {
                valid.iter().find_map(|answer| match answer {
                    AnswerKind::Production(action) => {
                        Some(format!("production:{}", action.as_str()))
                    }
                    _ => None,
                })
            })
            .unwrap_or_default(),
        codes: if items.len() == 1 && !request.codes.is_empty() {
            if request.items.is_empty() {
                "only"
            } else {
                "with_value"
            }
        } else {
            ""
        }
        .to_owned(),
        inject: injection_source(&analysis, user_request, &resolved.source, request),
        noremember: String::new(),
    };
    // Why the question offers no remembered answer, when no other sentence says so.
    if needs_approval
        && cloud.is_none()
        && why_words.offered.is_empty()
        && super::reasons::every_time(reason_kind, &analysis.flags).is_none()
        && let Some(blocker) = remember_blocker(&checked, &run_facts, certain, &mut ready)
    {
        blocker.clone_into(&mut why_words.noremember);
    }
    debug_line.offered.clone_from(&why_words.offered);
    let question_items: Vec<QuestionItem> = items
        .iter()
        .zip(&checked.facts)
        .enumerate()
        .map(|(index, (item, facts))| QuestionItem {
            item_id: *item,
            name: facts.name.clone(),
            production: facts.production,
            unconfirmed: item_unconfirmed(&checked, index),
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
    let mut evaluation_choice: Option<EvaluationChoice> = None;
    let mut classification_choice = None;

    if !needs_approval {
        let outcome = match route {
            Route::Answer => Outcome::Remembered,
            Route::Pattern => Outcome::Automatic { by_pattern: true },
            _ => Outcome::Automatic { by_pattern: false },
        };
        let entry = logged.entry(outcome, &risk_note).with_why(&why_words);
        let meta = decision_meta(browser_fill.is_some(), None);
        decision_id = record_decision_locked(ctx, &checked, &entry, &meta, pattern.as_ref());
        "allowed".clone_into(&mut debug_line.outcome);
        debug_line.millis = millis(started);
        log_decision(ctx, &items, debug_line.clone());
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
                        item_id: items.first().copied(),
                        operation: label.clone(),
                        decision: ActivityDecision::Deny,
                        reason: request.purpose.trim().to_owned(),
                    })
                    .ok()
            });
        // The wait ends when the vault session of the first check ends, and for a cloud
        // run when the node stops.
        let same_session = || {
            cloud.is_none_or(|cloud| !cloud.stopped())
                && lock(&ctx.vault).as_ref().is_some_and(|vault| {
                    !vault.is_locked()
                        && vault.epoch() == checked.epoch
                        && access_admission.as_ref().is_none_or(|a| a.live_in(vault))
                })
        };
        let pending = PendingRun {
            id: 0,
            agent: checked.agent.name.clone(),
            command: request.command.to_vec(),
            cwd: cloud.map_or_else(|| checked.cwd.display().to_string(), CloudContext::card_cwd),
            env_names: checked.env_names.clone(),
            purpose: browser_fill.map_or_else(
                || request.purpose.trim().to_owned(),
                |fill| {
                    format!(
                        "{} wants to fill {} on {} in the connected browser. {}{}",
                        checked.agent.name,
                        checked
                            .facts
                            .first()
                            .map_or("credential", |f| f.name.as_str()),
                        fill.site_label(),
                        request.purpose.trim(),
                        if fill.agent_can_read_page {
                            format!(
                                " {} can read this page through remote debugging.",
                                checked.agent.name
                            )
                        } else {
                            String::new()
                        }
                    )
                },
            ),
            risk: risk_note.clone(),
            user_request: user_request.to_owned(),
            request_source: resolved.source.clone(),
            agent_request: resolved.agent_text.clone().unwrap_or_default(),
            remember,
            question: QuestionInfo {
                id: 0,
                item_ids: items.to_vec(),
                project: checked.project.clone(),
                action,
                production: production_waiting,
                why: risk_note.clone(),
                reason: if browser_fill.is_some() {
                    ReasonKind::BrowserFill
                } else {
                    reason_kind
                },
                items: question_items,
                valid_answers: valid,
                flags: analysis.flags.clone(),
            },
        };
        // The answer time of the decision log (schema 27) starts with the question.
        let asked_at = Instant::now();
        // A call joins the waiting question only when it saw the same credentials.
        let settled = ctx.approvals.wait_for_evaluation_question(
            pending,
            checked.agent.id,
            checked.epoch,
            access_admission.as_ref().map_or_else(
                || baseline_of(&(checked.rechecked(), &command_binding)),
                |a| baseline_of(&(checked.rechecked(), &command_binding, a.identity())),
            ),
            None, // ADR 0031: no per-credential evaluation setup.
            access_admission.as_ref().map_or(ctx.approval_timeout, |a| {
                ctx.approval_timeout.min(a.remaining())
            }),
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
        if access_admission.as_ref().is_some_and(|a| !a.live()) {
            return WireResponse::failure(
                "access_once_unavailable",
                "The admitted access request expired or was revoked. Nothing ran.",
            );
        }
        let Settled {
            outcome,
            method: checked_with,
            answer: chosen,
            evaluation: chosen_evaluation,
            attached,
            refusal_comment,
            classification,
            classified_item,
            answered_on: relay_device,
            ..
        } = match settled {
            Ok(settled) => settled,
            Err(refusal) => {
                if access_admission.is_some() {
                    return WireResponse::failure(
                        "access_once_unavailable",
                        "This admission could not wait for execution approval. Its allowance was consumed; query status.",
                    );
                }
                let text = match refusal {
                    QuestionRefusal::Busy => QUESTION_WAITING,
                    QuestionRefusal::Superseded => QUESTION_SUPERSEDED,
                };
                debug_line.outcome = match refusal {
                    QuestionRefusal::Busy => "question_waiting",
                    QuestionRefusal::Superseded => "superseded",
                }
                .to_owned();
                codes::QUESTION_WAITING.clone_into(&mut debug_line.code);
                debug_line.millis = millis(started);
                log_decision(ctx, &items, debug_line.clone());
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
                                None,
                            );
                        }
                    }
                }
                return WireResponse::failure(codes::QUESTION_WAITING, text);
            }
        };
        // A cloud run remembers nothing, whatever the answer was.
        if cloud.is_none() {
            answer_choice = chosen;
            evaluation_choice = chosen_evaluation;
            classification_choice = classification.zip(classified_item);
        }
        answered_on = answered_on_of(checked_with, relay_device);
        if answered_on == ANSWERED_ON_IPHONE {
            logged_decided_by = OWNER_APPROVED_ON_IPHONE;
        }
        // Every owner answer goes to the decision log. A denial blocks the pattern. The
        // vault keeps the answer time for an owner answer only (not a timeout).
        let mut entry = logged
            .entry(Outcome::Owner(outcome), &risk_note)
            .with_why(&why_words);
        entry.at = learning::now();
        let meta = decision_meta(browser_fill.is_some(), Some(millis(asked_at)));
        decision_id = record_decision_locked(ctx, &checked, &entry, &meta, pattern.as_ref());
        approval_text(outcome).clone_into(&mut debug_line.outcome);
        debug_line.answered_on.clone_from(&answered_on);
        debug_line.millis = millis(started);
        log_decision(ctx, &items, debug_line.clone());
        if !attached {
            let mut guard = lock(&ctx.vault);
            if let Some(vault) = guard
                .as_mut()
                .filter(|vault| !vault.is_locked() && vault.path() == checked.vault_file)
            {
                // One answer is one interaction: the owner check of an approval is
                // not counted again (`OwnerGate`).
                let _ = vault.record_interaction(InteractionKind::Question, &label, &items);
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
        remembered = outcome == ApprovalOutcome::ApprovedAndRemembered && cloud.is_none();
        let refusal = match outcome {
            ApprovalOutcome::Approved
            | ApprovalOutcome::ApprovedAndRemembered
            | ApprovalOutcome::ApprovedAndGranted => None,
            ApprovalOutcome::Denied => Some((
                "approval_denied",
                super::approvals::owner_refusal(refusal_comment),
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
                        decision_id,
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
        let agent = match caller.agent(vault, &label) {
            Ok(agent) => agent,
            Err(response) => return response,
        };
        if access_admission.as_ref().is_some_and(|a| !a.live_in(vault)) {
            return WireResponse::failure(
                "access_once_unavailable",
                "The admitted access request expired or was revoked. Nothing ran.",
            );
        }
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
        let rechecked = match check_inner(vault, &agent, request, browser_fill) {
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
        let current_binding = super::evaluation_binding::command_binding(
            request.command,
            &rechecked.cwd,
            &rechecked.project_dir,
            certain.is_some(),
            request.path,
        );
        if rechecked.rechecked() != checked.rechecked() || current_binding != command_binding {
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
                decision_id,
            );
            return WireResponse::failure("authorization_changed", reason);
        }
        // Persist classification only after the original authorization baseline passed.
        if let Some(choice) = classification_choice
            && !save_classification(vault, &checked, &items, choice)
        {
            return WireResponse::failure(
                "classification_failed",
                "Could not save the environment. Nothing ran.",
            );
        }
        // A cloud run stops here, as the local evaluation does: the node releases the
        // values of the bindings that this check read, in this vault session.
        if cloud.is_some() {
            record_uses(
                vault,
                &checked,
                request,
                action,
                UseOutcome::Allowed,
                use_decided_by,
                &answered_on,
                decision_id,
            );
            for item_id in &items {
                let _ = vault.record_run(agent.id, *item_id);
            }
            let _ = vault.touch_cloud_agent(agent.id, learning::now());
            *approved = Some(CloudApproval {
                epoch: checked.epoch,
                bindings: rechecked
                    .authorization
                    .iter()
                    .map(|authorization| authorization.binding.clone())
                    .collect(),
                decided_by: logged_decided_by.to_owned(),
                answered_on: answered_on.clone(),
            });
            return WireResponse::success(json!({"would_run": true, "decided_by": decided_by}));
        }
        // The opt-in local evaluator stops before preparing the secret environment or starting any
        // process/proxy. This mode is not available through the agent wire protocol.
        if evaluation_only {
            return WireResponse::success(json!({"would_run": true, "decided_by": decided_by}));
        }
        // The current run has an owner proof. Classification and future model eligibility
        // are committed together only after the unchanged-state check above.
        if let Some(choice) = &evaluation_choice {
            let project = ProjectRef {
                key: choice.offer.project.key.clone(),
                label: choice.offer.project.label.clone(),
            };
            if vault
                .authorize_evaluation(
                    checked.agent.id,
                    &project,
                    action,
                    &choice.confirmations,
                    choice.offer.command_binding.as_deref(),
                    &answered_on,
                )
                .is_err()
            {
                return WireResponse::failure(
                    codes::ANSWER_FAILED,
                    "Apassy could not save the classification and bouncer permission. Nothing ran.",
                );
            }
            logged_decided_by = "Owner approved once and enabled bouncer evaluation";
        }
        // ADR 0025: "Allow ACTION in PROJECT" and "Allow production" are saved now, in
        // the session of the decision and after the second check.
        if let Some(choice) = &answer_choice {
            let saved = save_answer(vault, &checked, &items, choice, &answered_on, &hosts);
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
                    decision_id,
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
        if remembered
            && request.codes.is_empty()
            && let Some(pattern) = &pattern
        {
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
            decision_id,
        );
        super::corrections::consider_items(vault, &items);
        if vault.is_locked() {
            return locked_response();
        }
        if let Some(fill) = browser_fill {
            let response = fill.deliver(vault, &ctx.vault);
            record(
                vault,
                &agent,
                request,
                &label,
                if response.ok {
                    ActivityDecision::Allow
                } else {
                    ActivityDecision::Deny
                },
                "Browser fill delivery requested; extension acknowledgement determines completion.",
            );
            return response;
        }
        match read_secrets(vault, request.items, request.codes) {
            Ok(secrets) => {
                for item_id in &items {
                    let _ = vault.record_run(agent.id, *item_id);
                }
                secrets
            }
            Err((code, reason)) => {
                record(
                    vault,
                    &agent,
                    request,
                    &label,
                    ActivityDecision::Deny,
                    &reason,
                );
                return WireResponse::failure(code, reason);
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
        match RunProxy::start_with_access(
            std::mem::take(&mut secrets.proxied),
            options,
            access_admission.clone(),
            !request.codes.is_empty(),
        ) {
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
    let result = exec::run_with_codes_spawn(
        request.command,
        &checked.cwd,
        request.path,
        &secrets.env,
        &secrets.masks,
        &secrets.codes,
        network.map_or_else(Network::default, Network::from),
        ctx.run_timeout,
        |cmd, prepare| {
            if let Some(a) = &access_admission {
                let guard = lock(&ctx.vault);
                let Some(vault) = guard.as_ref().filter(|v| a.live_in(v)) else {
                    return Err(std::io::Error::other("access consent expired or revoked"));
                };
                vault
                    .delivery_fence()
                    .deliver(|| {
                        prepare(cmd)?;
                        cmd.spawn()
                    })
                    .unwrap_or_else(|| Err(std::io::Error::other("vault locked")))
            } else {
                spawn_in_session(&ctx.vault, checked.epoch, cmd, prepare)
            }
        },
    );
    let enforced = network.is_some_and(|network| network.rule != NetworkRule::None);
    let rule = network.map(RunNetwork::report);
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
                answer["network"] = network_report(enforced, &requests, !request.codes.is_empty());
                // broker-v0 `network.rule` (unit X2): the rule, and without one on
                // Linux the reason and the fix.
                if let (Some(report), Some(fields)) = (
                    rule.as_ref().and_then(serde_json::Value::as_object),
                    answer["network"].as_object_mut(),
                ) {
                    fields.extend(report.clone());
                }
                answer["note"] = json!(if request.codes.is_empty() {
                    PLACEHOLDER_NOTE
                } else {
                    "Secret values in stdout/stderr are masked. Per-request network details are omitted for runs with one-time codes."
                });
            }
            WireResponse::success(answer)
        }
        Err(err) => {
            let reason = exec::sandbox_refusal(&err).unwrap_or_else(|| {
                "The command did not start. Check the program name and PATH.".to_owned()
            });
            record_locked(
                ctx,
                &checked,
                request,
                &label,
                ActivityDecision::Error,
                &reason,
            );
            WireResponse::failure("start_failed", reason)
        }
    }
}

fn known_nothing(items: usize) -> Known {
    Known {
        answer: vec![false; items],
        unfit: vec![None; items],
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

#[cfg(test)]
fn check(
    vault: &Vault,
    agent: &AgentSummary,
    request: &RunRequest<'_>,
) -> Result<Checked, (&'static str, String)> {
    check_inner(vault, agent, request, None)
}

fn check_inner(
    vault: &Vault,
    agent: &AgentSummary,
    request: &RunRequest<'_>,
    browser_fill: Option<&super::browser_fill::Fill>,
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
    for item_id in &request.all_items() {
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
        let includes_code = request.codes.contains(item_id);
        let code_field = if includes_code {
            Some(
                vault
                    .code_field(*item_id)
                    .map_err(|_| {
                        (
                            "invalid_code",
                            "The item must have exactly one readable one-time password detail."
                                .to_owned(),
                        )
                    })?
                    .ok_or((
                        "no_code",
                        format!("Item {item_id} has no one-time password detail."),
                    ))?,
            )
        } else {
            None
        };
        let code_name = crate::vault::mfa::code_env_name(*item_id);
        if let Some(fill) = browser_fill {
            fill.validate_site(vault)
                .map_err(|reason| ("refused", reason))?;
        }
        // Way C on without a lease in this build is `lease_failed` before the owner is
        // asked; a static source adds the variables of its static form (S6, rule 4).
        let extra = if browser_fill.is_none() && request.items.contains(item_id) {
            vault
                .run_extra_bindings(*item_id)
                .map_err(|error| (error.code(), error.message(*item_id)))?
        } else {
            Vec::new()
        };
        let binding = if browser_fill.is_some() && request.items.contains(item_id) {
            Some(EnvBinding { item_id: *item_id, env_name: format!("APASSY_BROWSER_{item_id}"), field: "password".to_owned(), delivery: EnvDelivery::Value })
        } else if !request.items.contains(item_id) {
            Some(EnvBinding { item_id: *item_id, env_name: code_name.clone(), field: code_field.clone().expect("code-only item"), delivery: EnvDelivery::Value })
        } else { vault.process_binding(*item_id).map_err(|_| {
            ("broker_error", "The broker cannot read the process field.".to_owned())
        })? }.ok_or((
            "needs_field",
            format!("The owner must select one secret field for item {item_id} in Apassy before a process can use it."),
        ))?;
        // Old synced records can have a name that belongs to another local item.
        // Never let one item replace another item's value in the process environment.
        for name in
            std::iter::once(&binding.env_name).chain(extra.iter().map(|extra| &extra.env_name))
        {
            if !unique_env_names.insert(name.clone()) {
                return Err((
                    "duplicate_env_name",
                    format!(
                        "Two requested credentials use the process variable {name}. The owner must select different variable names in Apassy before this run.",
                    ),
                ));
            }
        }
        env_names.extend(extra.into_iter().map(|extra| extra.env_name));
        if includes_code && request.items.contains(item_id) {
            if !unique_env_names.insert(code_name.clone()) {
                return Err((
                    "duplicate_env_name",
                    "A code variable conflicts with another process variable.".to_owned(),
                ));
            }
            env_names.push(code_name);
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
                code_field,
                includes_value: request.items.contains(item_id),
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
            name: if includes_code {
                format!("{} (includes one-time code)", details.summary.title)
            } else {
                details.summary.title.clone()
            },
            includes_code,
            standing,
            always_ask,
            // ADR 0031, 2026-11-03: a default risk of a credential that the owner
            // labeled development follows the label, so it is no weak source.
            weak_source: sources.weak(declaration.as_ref()),
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

/// Add the variable, the declaration as the bouncer judges it
/// ([`DeclarationSources::judged`]), the provider hosts, and the authorization of one
/// item. `authorization` comes without its binding and provider; this fills them in.
fn push_item(
    vault: &Vault,
    item_id: u64,
    binding: EnvBinding,
    mut authorization: ItemAuthorization,
    out: &mut Collected<'_>,
) -> Result<(), (&'static str, String)> {
    // The bouncer judges a development label with the development defaults (ADR 0031,
    // 2026-11-03), also for a label from before 0.5.16. The authorization keeps the
    // stored values, so the recheck compares what the vault has.
    out.declarations.push(
        authorization
            .declaration
            .as_ref()
            .map(|declaration| authorization.sources.judged(declaration)),
    );
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
    for (index, (item, facts)) in items.iter().zip(&checked.facts).enumerate() {
        let mut covered = hosts.to_vec();
        covered.extend(facts.known_hosts.iter().cloned());
        let result = if facts.production {
            if !choice.production {
                continue;
            }
            if facts.includes_code {
                vault.store_answer(
                    *item,
                    &project,
                    choice.action,
                    AnswerScope::Production,
                    on,
                    &covered,
                    true,
                    checked.authorization[index].includes_value,
                )
            } else {
                vault.allow_production(*item, &project, choice.action, on, &covered)
            }
        } else if facts.includes_code {
            vault.store_answer(
                *item,
                &project,
                choice.action,
                AnswerScope::Project,
                on,
                &covered,
                true,
                checked.authorization[index].includes_value,
            )
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
        // A parsed destination that cannot be stored as an answer host is still
        // a destination. Dropping it would hide encoded DNS names or IPv6 zones
        // and could even clear the foreign-database flag before routing.
        .map(|host| normal_host(host).unwrap_or_else(|| host.clone()))
        .collect();
    hosts.sort();
    hosts.dedup();
    hosts
}

/// Store one use of each item of the run (ADR 0025 §5), with the decision log entry of
/// the run when it has one.
#[allow(clippy::too_many_arguments)]
fn record_uses(
    vault: &mut Vault,
    checked: &Checked,
    request: &RunRequest<'_>,
    action: ActionKind,
    outcome: UseOutcome,
    decided_by: UseDecidedBy,
    answered_on: &str,
    decision_id: Option<u64>,
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
        decision_id,
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
        None,
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
    decision_id: Option<u64>,
) {
    let hosts = run_hosts(request.command);
    // The whole command, masked with the values of every item of the request, and only
    // then cut: a value of one item never shows in the row of another, and a value at
    // the cut never leaves a part (relay-feed-v1 section 7.2).
    let Ok(mask) = vault.command_mask(&request.all_items()) else {
        return;
    };
    let command_summary = mask.summary(&request.command_text(), MAX_COMMAND_SUMMARY_BYTES);
    drop(mask);
    for item_id in &request.all_items() {
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
            decision_log_id: decision_id,
        });
    }
}

/// Serialize credential delivery with lock. The vault mutex is released before
/// process creation; the session guard is held only until spawn returns.
pub(super) fn spawn_in_session(
    vault: &super::SharedVault,
    epoch: [u8; 32],
    cmd: &mut std::process::Command,
    prepare: &mut dyn FnMut(&mut std::process::Command) -> std::io::Result<()>,
) -> std::io::Result<std::process::Child> {
    if !super::operations::start_effect() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "Operation cancelled before spawn.",
        ));
    }
    let delivery = {
        let guard = lock(vault);
        guard
            .as_ref()
            .filter(|v| !v.is_locked() && v.epoch() == epoch)
            .map(Vault::delivery_fence)
    };
    delivery
        .and_then(|fence| {
            fence.deliver(|| {
                prepare(cmd)?;
                cmd.spawn()
            })
        })
        .unwrap_or_else(|| {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                RELOCKED,
            ))
        })
}

/// The variables of a run. `env` has a real value or a placeholder for each item.
/// `masks` has the real value behind each placeholder, so the output never shows it.
struct RunSecrets {
    env: Vec<SecretEnv>,
    masks: Vec<SecretEnv>,
    proxied: Vec<ProxySecret>,
    codes: Vec<(String, crate::otp::Totp)>,
}

fn read_secrets(
    vault: &Vault,
    items: &[u64],
    codes: &[u64],
) -> Result<RunSecrets, (&'static str, String)> {
    // The second check of rule 4: way C turned on after the plan still gets no value.
    for item_id in items {
        if let Err(error) = vault.run_extra_bindings(*item_id) {
            return Err((error.code(), error.message(*item_id)));
        }
    }
    read_secret_values(vault, items, codes).map_err(|reason| ("missing_secret", reason))
}

fn read_secret_values(vault: &Vault, items: &[u64], codes: &[u64]) -> Result<RunSecrets, String> {
    let mut secrets = RunSecrets {
        env: Vec::new(),
        masks: Vec::new(),
        proxied: Vec::new(),
        codes: Vec::new(),
    };
    for item in codes {
        let field = vault
            .code_field(*item)
            .map_err(|_| "The one-time password detail is ambiguous.".to_owned())?
            .ok_or("This item has no one-time password detail.")?;
        let totp = vault
            .totp(*item, &field)
            .map_err(|_| "The one-time password setting is invalid.".to_owned())?;
        secrets
            .codes
            .push((crate::vault::mfa::code_env_name(*item), totp));
    }
    for item_id in items {
        let binding = vault
            .process_binding(*item_id)
            .map_err(|_| format!("The broker cannot read the process field of item {item_id}."))?
            .ok_or_else(|| {
                format!("The owner must select one secret field for item {item_id} in Apassy.")
            })?;
        let extra = vault
            .run_extra_bindings(*item_id)
            .map_err(|error| error.message(*item_id))?;
        for binding in std::iter::once(binding).chain(extra) {
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
    }
    Ok(secrets)
}

const PLACEHOLDER_NOTE: &str = "Secret values in the output are replaced with [apassy:NAME]. The variables in `placeholders` hold a placeholder, not the real value. Apassy puts the real value into HTTPS requests to the hosts of each variable, in the Authorization header, a known API key header, or a known key parameter. `network.requests` lists each request. A request that Apassy stopped has the header X-Apassy-Proxy: refused and a reason.";

/// One sentence about the proxy for the activity log.
/// A generated code may enter any free-text request field, including host, method
/// and path. Proxy events predate code injection and cannot mask its generated
/// value. For code-bearing runs release only counts, never those event details.
fn network_report(
    enforced: bool,
    requests: &[ProxyEvent],
    includes_codes: bool,
) -> serde_json::Value {
    if includes_codes {
        json!({
            "proxy": true,
            "only_proxy": enforced,
            "request_count": requests.len(),
            "details_omitted": true,
        })
    } else {
        json!({"proxy": true, "only_proxy": enforced, "requests": requests})
    }
}

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
    let items = request.all_items();
    let extra_items = items.get(1..).unwrap_or_default();
    let _ = vault.record_activity_for_items(
        &NewActivity {
            agent_id: Some(agent.id),
            agent_name: agent.name.clone(),
            item_id: items.first().copied(),
            operation: label.to_owned(),
            decision,
            reason: format!("{reason} Purpose: {}", request.purpose.trim()),
        },
        extra_items,
    );
}

/// Store a decision log entry when the vault is unlocked (ADR 0009). Returns its id
/// for the uses of the run.
fn record_decision_locked(
    ctx: &BrokerContext,
    checked: &Checked,
    entry: &DecisionEntry,
    meta: &DecisionMeta,
    pattern: Option<&learning::RequestPattern>,
) -> Option<u64> {
    let mut guard = lock(&ctx.vault);
    guard
        .as_mut()
        .filter(|vault| !vault.is_locked() && vault.path() == checked.vault_file)
        .and_then(|vault| learning::record_with(vault, entry, meta, pattern).ok())
}

/// Where the owner answered, as the uses, the answers, and the decision log file name it:
/// "iPhone" for the paired iPhone and for an iPhone through the relay, the device that
/// the questions worker named for another answer through the relay
/// (`Settled::answered_on`), "this Mac" for an owner check here, and empty without one
/// (a denial on this Mac, or no answer).
pub(super) fn answered_on_of(method: Option<CheckMethod>, relay_device: Option<String>) -> String {
    if method == Some(CheckMethod::Companion) || relay_device.as_deref() == Some(ANSWERED_ON_IPHONE)
    {
        ANSWERED_ON_IPHONE.to_owned()
    } else if let Some(device) = relay_device {
        device
    } else if method.is_some() {
        ANSWERED_ON_MAC.to_owned()
    } else {
        String::new()
    }
}

/// The schema 27 columns of a decision of this run: a browser fill or a run, and the
/// milliseconds from the question to the owner's answer. The vault drops the time for
/// an entry that the owner did not answer.
fn decision_meta(browser_fill: bool, wait_ms: Option<u64>) -> DecisionMeta {
    DecisionMeta {
        request: if browser_fill {
            RequestKind::BrowserFill
        } else {
            RequestKind::Run
        },
        wait_ms,
    }
}

/// Append `line` to the decision log file, with the secret values of `items` masked in
/// its reason. Without an unlocked vault the reason stays out.
pub(super) fn log_decision(ctx: &BrokerContext, items: &[u64], mut line: decision_log::Line) {
    if !decision_log::enabled() {
        return;
    }
    let why = std::mem::take(&mut line.why);
    if !why.is_empty() {
        let guard = lock(&ctx.vault);
        if let Some(mask) = guard
            .as_ref()
            .filter(|vault| !vault.is_locked())
            .and_then(|vault| vault.command_mask(items).ok())
        {
            line.why = mask.summary(&why, decision_log::MAX_TEXT);
        }
    }
    decision_log::append(&line);
}

/// The answers of the bouncer brain for the decision log file: the facts, the model
/// version, and the error when it gave no answer.
fn brain_answers(
    verdict: &BouncerVerdict,
) -> (std::collections::BTreeMap<String, f64>, String, String) {
    match verdict {
        BouncerVerdict::Scored { facts, model } => (
            facts
                .iter()
                .map(|fact| (fact.name.clone(), fact.probability))
                .collect(),
            model.clone().unwrap_or_default(),
            String::new(),
        ),
        // The run did not reach the brain.
        BouncerVerdict::Unavailable(reason) if reason == "not asked" => Default::default(),
        BouncerVerdict::Unavailable(reason) => (Default::default(), String::new(), reason.clone()),
    }
}

/// The owner answer as the decision log file names it.
fn approval_text(outcome: ApprovalOutcome) -> &'static str {
    match outcome {
        ApprovalOutcome::Approved => "approved",
        ApprovalOutcome::ApprovedAndRemembered => "approved_and_remembered",
        ApprovalOutcome::ApprovedAndGranted => "approved_and_granted",
        ApprovalOutcome::Denied => "denied",
        ApprovalOutcome::TimedOut => "timed_out",
        ApprovalOutcome::Invalidated => "invalidated",
    }
}

/// Milliseconds since `started`.
pub(super) fn millis(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
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
