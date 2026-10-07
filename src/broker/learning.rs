//! Learning glue for the broker and the replay tool (ADR 0009 steps 1 and 3).
//!
//! The broker ([`super::run`]) and the replay ([`super::replay`]) call the same
//! functions. So a replay runs the real decision code:
//!
//! 1. [`request_pattern`] generalizes the command and binds it to the agent, the project,
//!    the working directory, the items, and the policy.
//! 2. [`lookup`] reads the active calibration and the pattern state.
//! 3. `bouncer::decide_learned` decides. A pattern replaces only the model step.
//! 4. [`record`] stores the decision. An owner denial blocks the pattern.
//! 5. [`remember`] adds one approval after "Approve and remember".

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use super::approvals::{ApprovalOutcome, RememberOffer};
use super::bouncer::{BouncerVerdict, DecisionContext, Learned, Thresholds, before_model};
use super::patterns::{self, Place};
use super::shell_risk::Analysis;
use crate::vault::{
    DecidedBy, DecisionEntry, Declaration, LoggedDecision, PATTERN_APPROVALS_NEEDED, PatternKey,
    PatternState, RequestSource, Vault, VaultResult,
};

/// The pattern of one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestPattern {
    pub key: PatternKey,
    /// The generalized command for the owner.
    pub display: String,
}

/// Where a request runs and what it uses.
#[derive(Debug, Clone, Copy)]
pub struct RunScope<'a> {
    pub agent_id: u64,
    /// Canonical project directory of the grant of the first item.
    pub project_dir: &'a Path,
    /// Canonical working directory.
    pub cwd: &'a Path,
    /// Working directory relative to the project directory.
    pub cwd_rel: &'a str,
    pub items: &'a [u64],
    /// One entry per item, in the order of `items`.
    pub declarations: &'a [Option<Declaration>],
    /// Owner instructions of the grants, joined.
    pub instruction: &'a str,
}

/// Generalize the command and bind it (ADR 0010). `None` when the command has no
/// pattern, for example when it is too long.
pub fn request_pattern(scope: RunScope<'_>, command: &[String]) -> Option<RequestPattern> {
    let pattern = patterns::generalize(
        command,
        Place {
            project_dir: scope.project_dir,
            cwd: scope.cwd,
        },
    )?;
    let mut items = scope.items.to_vec();
    items.sort_unstable();
    items.dedup();
    Some(RequestPattern {
        key: PatternKey {
            agent_id: scope.agent_id,
            project_dir: scope.project_dir.display().to_string(),
            items,
            policy: policy(scope),
            cwd_rel: scope.cwd_rel.to_owned(),
            template: pattern.template(),
        },
        display: pattern.display(),
    })
}

/// Declarations in ascending item order, and the owner instruction. A change of either
/// starts a new pattern.
fn policy(scope: RunScope<'_>) -> String {
    let mut parts: Vec<(u64, String)> = scope
        .items
        .iter()
        .zip(scope.declarations)
        .map(|(item, declaration)| {
            let text = declaration.as_ref().map_or_else(
                || "none".to_owned(),
                |d| {
                    format!(
                        "{}/{}/{}/{}/{}",
                        d.project,
                        d.environment.as_str(),
                        d.risk.as_str(),
                        d.scope.as_str(),
                        d.reversibility.as_str()
                    )
                },
            );
            (*item, text)
        })
        .collect();
    parts.sort();
    let declarations: Vec<String> = parts
        .into_iter()
        .map(|(item, text)| format!("{item}={text}"))
        .collect();
    format!("{}|{}", declarations.join(";"), scope.instruction.trim())
}

/// What learning knows about one request now.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LearningState {
    /// The active calibration and an active pattern.
    pub learned: Learned,
    /// The active pattern record. The broker counts a use after the run starts.
    pub active_id: Option<u64>,
    /// Approvals of the pattern now. 0 when there is no pattern yet or it expired.
    pub approvals: u32,
    /// An owner denial blocked the pattern.
    pub blocked: bool,
}

impl LearningState {
    /// The offer for the approval card. Only a run that can teach a pattern gets one:
    /// no production item, no rule flag, a user request, declarations, and no grant in
    /// "ask" mode. A blocked pattern gets no offer.
    pub fn offer(
        &self,
        pattern: Option<&RequestPattern>,
        context: &DecisionContext<'_>,
        grant_asks: bool,
    ) -> Option<RememberOffer> {
        let pattern = pattern?;
        let eligible = !grant_asks && !self.blocked && before_model(context).is_none();
        eligible.then(|| RememberOffer {
            pattern: pattern.display.clone(),
            approvals: self.approvals,
            needed: PATTERN_APPROVALS_NEEDED,
        })
    }
}

/// Read the active calibration and the state of the pattern. A read error gives the
/// default level and no pattern, so the owner decides.
pub fn lookup(vault: &Vault, pattern: Option<&RequestPattern>, now: u64) -> LearningState {
    let mut state = LearningState::default();
    if let Ok(Some(calibration)) = vault.calibration() {
        state.learned.thresholds = Thresholds {
            task_match: calibration.task_match,
        };
    }
    let Some(pattern) = pattern else {
        return state;
    };
    let Ok(Some(record)) = vault.pattern(&pattern.key) else {
        return state;
    };
    match record.state(now) {
        PatternState::Active => {
            state.learned.pattern = Some(record.display.clone());
            state.active_id = Some(record.id);
            state.approvals = record.approvals;
        }
        PatternState::Learning { approvals } => state.approvals = approvals,
        PatternState::Blocked => state.blocked = true,
        PatternState::Expired => {}
    }
    state
}

/// How the request ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The bouncer allowed the run without the owner.
    Automatic { by_pattern: bool },
    /// The run waited for the owner.
    Owner(ApprovalOutcome),
}

/// One request as the decision log sees it. No secret values.
#[derive(Debug, Clone)]
pub struct LoggedRequest<'a> {
    pub at: u64,
    pub agent_id: u64,
    pub agent_name: &'a str,
    pub scope: RunScope<'a>,
    pub user_request: &'a str,
    pub user_request_source: RequestSource,
    pub command: &'a [String],
    pub purpose: &'a str,
    pub env_names: &'a [String],
    pub analysis: &'a Analysis,
    pub verdict: &'a BouncerVerdict,
    pub pattern: Option<&'a RequestPattern>,
    pub grant_asks: bool,
    pub thresholds: Thresholds,
}

impl LoggedRequest<'_> {
    pub fn entry(&self, outcome: Outcome, note: &str) -> DecisionEntry {
        let (asked, decision, decided_by, remembered) = match outcome {
            Outcome::Automatic { by_pattern } => (
                false,
                LoggedDecision::Allow,
                if by_pattern {
                    DecidedBy::Pattern
                } else {
                    DecidedBy::Model
                },
                false,
            ),
            Outcome::Owner(ApprovalOutcome::Approved) => {
                (true, LoggedDecision::Allow, DecidedBy::Owner, false)
            }
            Outcome::Owner(ApprovalOutcome::ApprovedAndRemembered) => {
                (true, LoggedDecision::Allow, DecidedBy::Owner, true)
            }
            Outcome::Owner(ApprovalOutcome::Denied) => {
                (true, LoggedDecision::Deny, DecidedBy::Owner, false)
            }
            Outcome::Owner(ApprovalOutcome::TimedOut | ApprovalOutcome::Invalidated) => {
                (true, LoggedDecision::Deny, DecidedBy::NoAnswer, false)
            }
        };
        let model_facts = match self.verdict {
            BouncerVerdict::Scored { facts, .. } => facts
                .iter()
                .map(|fact| (fact.name.clone(), fact.probability))
                .collect(),
            BouncerVerdict::Unavailable(_) => Vec::new(),
        };
        DecisionEntry {
            at: self.at,
            agent_id: self.agent_id,
            agent_name: self.agent_name.to_owned(),
            project_dir: self.scope.project_dir.display().to_string(),
            cwd_rel: self.scope.cwd_rel.to_owned(),
            items: self.scope.items.to_vec(),
            user_request: self.user_request.to_owned(),
            user_request_source: self.user_request_source,
            command: self.command.to_vec(),
            purpose: self.purpose.to_owned(),
            env_names: self.env_names.to_vec(),
            declarations: self.scope.declarations.to_vec(),
            rule_flags: self.analysis.flags.clone(),
            known_safe: self.analysis.known_safe,
            model_facts,
            pattern: self
                .pattern
                .map(|pattern| pattern.display.clone())
                .unwrap_or_default(),
            grant_asks: self.grant_asks,
            asked,
            decision,
            decided_by,
            remembered,
            policy: self.thresholds.policy_label(),
            note: note.to_owned(),
            instruction: self.scope.instruction.trim().to_owned(),
        }
        // The export names the model that answered (`model_version`).
        .with_model_version(self.verdict.model())
    }
}

/// A hard rule or a request check denied the request before the bouncer.
pub struct RuleDenial<'a> {
    pub at: u64,
    pub agent_id: u64,
    pub agent_name: &'a str,
    pub items: &'a [u64],
    pub user_request: &'a str,
    pub user_request_source: RequestSource,
    pub command: &'a [String],
    pub purpose: &'a str,
    pub reason: &'a str,
}

impl RuleDenial<'_> {
    pub fn entry(&self) -> DecisionEntry {
        DecisionEntry {
            at: self.at,
            agent_id: self.agent_id,
            agent_name: self.agent_name.to_owned(),
            project_dir: String::new(),
            cwd_rel: String::new(),
            items: self.items.to_vec(),
            user_request: self.user_request.to_owned(),
            user_request_source: self.user_request_source,
            command: self.command.to_vec(),
            purpose: self.purpose.to_owned(),
            env_names: Vec::new(),
            declarations: Vec::new(),
            rule_flags: Vec::new(),
            known_safe: false,
            model_facts: Vec::new(),
            pattern: String::new(),
            grant_asks: false,
            asked: false,
            decision: LoggedDecision::Deny,
            decided_by: DecidedBy::Rule,
            remembered: false,
            policy: Thresholds::default().policy_label(),
            note: self.reason.to_owned(),
            instruction: String::new(),
        }
    }
}

/// Store a decision. An owner denial also blocks the pattern of the request, for every
/// run, also a run that could not teach a pattern. So no denied request can become an
/// automatic allowance through a pattern, also after a rule change.
pub fn record(
    vault: &mut Vault,
    entry: &DecisionEntry,
    pattern: Option<&RequestPattern>,
) -> VaultResult<()> {
    vault.record_decision(entry)?;
    if entry.owner_denied()
        && let Some(pattern) = pattern
    {
        vault.block_pattern(&pattern.key, &pattern.display, entry.at)?;
    }
    Ok(())
}

/// "Approve and remember": one more approval for the pattern.
pub fn remember(vault: &mut Vault, pattern: &RequestPattern, now: u64) -> VaultResult<()> {
    vault
        .remember_approval(&pattern.key, &pattern.display, now)
        .map(|_| ())
}

/// Unix time now.
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// The source of a user request that the agent sent.
pub fn agent_source(user_request: &str) -> RequestSource {
    if user_request.trim().is_empty() {
        RequestSource::None
    } else {
        RequestSource::Agent
    }
}

/// The source of a user request after the host hook check (goal item B6). `label` is
/// the source text of `broker::prompts`: it starts with "from the agent" when the text
/// comes from the agent, and names the hook when the text comes from the host.
pub fn resolved_source(user_request: &str, label: &str) -> RequestSource {
    if user_request.trim().is_empty() {
        RequestSource::None
    } else if label.starts_with("from the agent") {
        RequestSource::Agent
    } else {
        RequestSource::Host
    }
}
