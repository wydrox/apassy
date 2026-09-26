//! Replay a chronological request sequence through the real decision code, with owner
//! decisions and learning (goal items B3 and B5).
//!
//! Each request goes through the command analysis, the pattern lookup, the bouncer
//! policy, the simulated owner, the decision log, and the pattern update. These are the
//! functions that the broker uses ([`super::learning`]). There are no hard rule checks
//! and no processes. The replay writes to the vault that the caller gives, so the
//! caller uses a new synthetic vault.
//!
//! The simulated owner approves with "Approve and remember" when the approval card
//! offers it, and approves once when it does not. A request labeled for denial is
//! denied. The report gives the ask rate for each window of requests and checks that
//! no request that the owner denied ever runs without the owner: at each later request,
//! and again with the final state after the replay.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use serde::Serialize;

use super::approvals::ApprovalOutcome;
use super::bouncer::{
    BouncerRequest, BouncerVerdict, DecisionContext, decide_learned, owner_required,
};
use super::learning::{self, LoggedRequest, Outcome, RequestPattern, RunScope};
use super::shell_risk::{Analysis, analyze};
use crate::contracts::CredentialKind;
use crate::vault::{
    Declaration, ExecMode, Field, ItemDraft, PatternState, SecretValue, Vault, VaultResult,
};

/// The synthetic secret of the replay item. The decision log masks it.
pub const REPLAY_SECRET: &str = "FAKE-replay-secret-3141";

/// The fixed part of a replay.
#[derive(Debug, Clone)]
pub struct ReplaySetup {
    /// Canonical project directory. It does not need to exist.
    pub project_dir: PathBuf,
    pub declaration: Declaration,
    pub env_name: String,
    pub instruction: String,
    /// Patterns learn from owner answers. `false` gives the baseline without learning.
    pub learning: bool,
    /// Requests in each window of the ask-rate curve.
    pub window: usize,
}

/// One request and the simulated owner answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayRequest {
    /// Unix time of the request. The sequence is in time order.
    pub at: u64,
    pub command: Vec<String>,
    /// Working directory relative to the project directory.
    pub cwd_rel: String,
    pub purpose: String,
    pub user_request: String,
    /// The owner approves this request when Apassy asks. `false` means a denial.
    pub owner_approves: bool,
}

/// Ask rate in one window of requests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Window {
    /// Index of the first request in the window.
    pub first: usize,
    pub requests: usize,
    pub asked: usize,
}

impl Window {
    pub fn ask_rate(&self) -> f64 {
        if self.requests == 0 {
            0.0
        } else {
            self.asked as f64 / self.requests as f64
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct ReplayReport {
    pub requests: usize,
    /// Requests with a rule flag. They always ask.
    pub flagged: usize,
    pub asked: usize,
    pub model_allowed: usize,
    pub pattern_allowed: usize,
    pub owner_approved: usize,
    pub owner_remembered: usize,
    pub owner_denied: usize,
    pub windows: Vec<Window>,
    /// Requests that the owner denied earlier and that ran later without the owner.
    /// It must be empty.
    pub denied_then_allowed: Vec<String>,
    /// Requests with a denial label that ran without the owner the first time. The
    /// owner did not see them, so this is a miss of the rules, the model, or a pattern.
    pub unwanted_allowed: Vec<String>,
    /// Denied requests that the final state (patterns and calibration) allows. It must
    /// be empty.
    pub final_denied_allowed: Vec<String>,
    pub patterns_active: usize,
    pub patterns_learning: usize,
    pub patterns_blocked: usize,
}

impl ReplayReport {
    pub fn ask_rate(&self) -> f64 {
        if self.requests == 0 {
            0.0
        } else {
            self.asked as f64 / self.requests as f64
        }
    }
}

/// The agent and the item of a replay in its vault.
struct Actors {
    agent_id: u64,
    agent_name: String,
    item_id: u64,
}

/// Run the sequence. `model` answers the model step. Use a function that returns
/// [`BouncerVerdict::Unavailable`] to measure without a model.
pub fn replay(
    vault: &mut Vault,
    setup: &ReplaySetup,
    requests: &[ReplayRequest],
    model: &mut dyn FnMut(&BouncerRequest) -> BouncerVerdict,
) -> VaultResult<ReplayReport> {
    let actors = prepare(vault, setup)?;
    let env_names = vec![setup.env_name.clone()];
    let declarations = [Some(setup.declaration.clone())];
    let items = [actors.item_id];
    let window = setup.window.max(1);
    let mut report = ReplayReport::default();
    let mut windows: BTreeMap<usize, Window> = BTreeMap::new();
    let mut denied: BTreeSet<(String, String)> = BTreeSet::new();
    let mut denied_requests: Vec<&ReplayRequest> = Vec::new();

    for (index, request) in requests.iter().enumerate() {
        let cwd = lexical_join(&setup.project_dir, &request.cwd_rel);
        let analysis = analyze(&request.command, &request.purpose, &env_names);
        let scope = RunScope {
            agent_id: actors.agent_id,
            project_dir: &setup.project_dir,
            cwd: &cwd,
            cwd_rel: &request.cwd_rel,
            items: &items,
            declarations: &declarations,
            instruction: &setup.instruction,
        };
        let step = evaluate(vault, setup, scope, request, &analysis, request.at, model);
        let fingerprint = fingerprint(request);
        let slot = windows.entry(index / window).or_insert(Window {
            first: index / window * window,
            ..Window::default()
        });
        slot.requests += 1;
        report.requests += 1;
        report.flagged += usize::from(!analysis.flags.is_empty());

        let logged = LoggedRequest {
            at: request.at,
            agent_id: actors.agent_id,
            agent_name: &actors.agent_name,
            scope,
            user_request: request.user_request.trim(),
            user_request_source: learning::agent_source(&request.user_request),
            command: &request.command,
            purpose: request.purpose.trim(),
            env_names: &env_names,
            analysis: &analysis,
            verdict: &step.verdict,
            pattern: step.pattern.as_ref(),
            grant_asks: false,
            thresholds: step.state.learned.thresholds,
        };
        if step.ask_owner {
            slot.asked += 1;
            report.asked += 1;
            let context = DecisionContext {
                analysis: &analysis,
                declarations: &declarations,
                has_user_request: !request.user_request.trim().is_empty(),
            };
            let offer = step.state.offer(step.pattern.as_ref(), &context, false);
            let outcome = match (request.owner_approves, setup.learning && offer.is_some()) {
                (false, _) => ApprovalOutcome::Denied,
                (true, true) => ApprovalOutcome::ApprovedAndRemembered,
                (true, false) => ApprovalOutcome::Approved,
            };
            let entry = logged.entry(Outcome::Owner(outcome), &step.note);
            learning::record(vault, &entry, step.pattern.as_ref())?;
            match outcome {
                ApprovalOutcome::Denied => {
                    report.owner_denied += 1;
                    if denied.insert(fingerprint) {
                        denied_requests.push(request);
                    }
                }
                ApprovalOutcome::ApprovedAndRemembered => {
                    report.owner_remembered += 1;
                    if let Some(pattern) = &step.pattern {
                        learning::remember(vault, pattern, request.at)?;
                    }
                }
                _ => report.owner_approved += 1,
            }
        } else {
            let by_pattern = step.state.learned.pattern.is_some();
            let entry = logged.entry(Outcome::Automatic { by_pattern }, &step.note);
            learning::record(vault, &entry, step.pattern.as_ref())?;
            if by_pattern {
                report.pattern_allowed += 1;
                if let Some(id) = step.state.active_id {
                    vault.record_pattern_use(id, request.at)?;
                }
            } else {
                report.model_allowed += 1;
            }
            if denied.contains(&fingerprint) {
                report.denied_then_allowed.push(masked_line(request));
            }
            if !request.owner_approves {
                report.unwanted_allowed.push(masked_line(request));
            }
        }
    }

    // The final state must still ask the owner for every request that the owner denied.
    let end = requests.last().map_or(0, |request| request.at);
    for request in denied_requests {
        let cwd = lexical_join(&setup.project_dir, &request.cwd_rel);
        let analysis = analyze(&request.command, &request.purpose, &env_names);
        let scope = RunScope {
            agent_id: actors.agent_id,
            project_dir: &setup.project_dir,
            cwd: &cwd,
            cwd_rel: &request.cwd_rel,
            items: &items,
            declarations: &declarations,
            instruction: &setup.instruction,
        };
        let step = evaluate(vault, setup, scope, request, &analysis, end, model);
        if !step.ask_owner {
            report.final_denied_allowed.push(masked_line(request));
        }
    }
    for pattern in vault.patterns()? {
        match pattern.state(end) {
            PatternState::Active => report.patterns_active += 1,
            PatternState::Learning { .. } => report.patterns_learning += 1,
            PatternState::Blocked => report.patterns_blocked += 1,
            PatternState::Expired => {}
        }
    }
    report.windows = windows.into_values().collect();
    Ok(report)
}

struct Step {
    pattern: Option<RequestPattern>,
    state: learning::LearningState,
    verdict: BouncerVerdict,
    ask_owner: bool,
    note: String,
}

/// The broker decision for one request at one time, without the hard rule checks.
fn evaluate(
    vault: &Vault,
    setup: &ReplaySetup,
    scope: RunScope<'_>,
    request: &ReplayRequest,
    analysis: &Analysis,
    now: u64,
    model: &mut dyn FnMut(&BouncerRequest) -> BouncerVerdict,
) -> Step {
    let user_request = request.user_request.trim();
    let context = DecisionContext {
        analysis,
        declarations: scope.declarations,
        has_user_request: !user_request.is_empty(),
    };
    let pattern = if setup.learning {
        learning::request_pattern(scope, &request.command)
    } else {
        None
    };
    let state = learning::lookup(vault, pattern.as_ref(), now);
    let verdict = if !analysis.flags.is_empty()
        || owner_required(&context).is_some()
        || state.learned.pattern.is_some()
    {
        BouncerVerdict::Unavailable("not asked".to_owned())
    } else {
        model(&BouncerRequest {
            user_request: user_request.to_owned(),
            command: request.command.join(" "),
            relative_dir: request.cwd_rel.clone(),
            purpose: request.purpose.trim().to_owned(),
            env_names: vec![setup.env_name.clone()],
            instruction: setup.instruction.clone(),
        })
    };
    let decision = decide_learned(&verdict, &context, &state.learned);
    Step {
        pattern,
        state,
        verdict,
        ask_owner: decision.ask_owner,
        note: decision.note,
    }
}

/// Add the replay agent and item to the vault.
fn prepare(vault: &mut Vault, setup: &ReplaySetup) -> VaultResult<Actors> {
    let item = vault.add(ItemDraft {
        title: "Replay credential".to_owned(),
        kind: CredentialKind::ApiKey,
        notes: String::new(),
        tags: Vec::new(),
        fields: vec![Field {
            name: "token".to_owned(),
            value: SecretValue::new(REPLAY_SECRET.to_owned()),
            secret: true,
        }],
    })?;
    vault.set_env_binding(item.id, &setup.env_name, "token")?;
    vault.set_declaration(item.id, &setup.declaration)?;
    let (agent, _token) = vault.register_agent("Replay agent")?;
    vault.set_exec_grant(
        agent.id,
        item.id,
        &setup.project_dir.display().to_string(),
        ExecMode::Bouncer,
    )?;
    Ok(Actors {
        agent_id: agent.id,
        agent_name: agent.name,
        item_id: item.id,
    })
}

fn fingerprint(request: &ReplayRequest) -> (String, String) {
    (request.command.join("\u{1f}"), request.cwd_rel.clone())
}

/// A short command line for the report. Long tokens are masked, so a printed sample
/// does not show a secret that a real command can contain.
fn masked_line(request: &ReplayRequest) -> String {
    let line: Vec<String> = request
        .command
        .join(" ")
        .split(' ')
        .map(|word| {
            let long = word.len() >= 24
                && word
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-_.=+/".contains(c));
            if long || word.contains('@') {
                "[masked]".to_owned()
            } else {
                word.to_owned()
            }
        })
        .collect();
    let mut text = line.join(" ");
    if text.len() > 160 {
        let mut end = 157;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
        text.push_str("...");
    }
    text
}

/// Join a relative directory without the file system. `..` cannot leave the root.
fn lexical_join(base: &Path, relative: &str) -> PathBuf {
    let mut path = base.to_path_buf();
    for component in Path::new(relative).components() {
        match component {
            Component::ParentDir => {
                if path != base {
                    path.pop();
                }
            }
            Component::Normal(part) => path.push(part),
            _ => {}
        }
    }
    path
}
