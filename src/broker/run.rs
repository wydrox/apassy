//! Process runs with secrets in the environment (ADR 0006).
//!
//! Check order:
//!
//! 1. The vault is open and unlocked.
//! 2. The token belongs to an active agent, and the token has not expired.
//! 3. The request has a valid form: items, command, working directory, purpose, and `PATH`.
//! 4. The working directory exists.
//! 5. For each item: the agent has process access, or it sees all credentials and this
//!    is a first use (ADR 0024), the owner reviewed the item after a restore, the working directory is in the granted project directory (a grant for
//!    any folder skips this, ADR 0012), the item has a process binding, and the
//!    hard rule passes (expiry, command prefixes, forbidden words, hourly limit). A grant
//!    for any folder with a variable that holds the real value asks the owner.
//! 6. A production declaration needs the owner (ADR 0010). The model is not asked.
//! 7. The bouncer scores the request (ADR 0007, ADR 0008). A rule flag skips the model.
//!    The command analysis gets the known hosts of the provider of each item (goal item
//!    B4). A bound secret that goes to another host is a rule flag.
//!    The user request comes from the host hook when there is one (goal item B6,
//!    [`super::prompts`]). An unverified hook request or a command that names the hook
//!    channel is a rule flag. An active remembered pattern replaces the model step
//!    (ADR 0009, ADR 0010). It cannot change steps 5 and 6, a rule flag, or a missing
//!    user request or declaration. The active model is the default bouncer or a model
//!    that the owner promoted, pinned to its version. When the model step decides, a
//!    candidate in shadow mode answers in parallel on its own thread (goal item B9,
//!    [`super::shadow`]). Its answer goes only to the vault and has no effect.
//! 8. A first use, a grant in "ask" mode, a high risk, or an unavailable bouncer needs
//!    the owner. A first use does not ask the model: a model never gives new access.
//!    "Allow in this folder" saves the grant and the declaration after step 9.
//!    A clean request with only "bouncer" grants runs without a prompt. Each decision
//!    goes to the decision log. An owner denial blocks the pattern of the request.
//! 9. After a decision, the broker checks the vault, the agent, and the rules again.
//!    The vault epoch must be the same as in step 1. A lock, an unlock, or a restore
//!    in between makes the decision invalid (goal item V3).
//!    The credential revision, process binding, grant, declaration, provider, and
//!    canonical directories must also be the same as in the original check.
//! 10. The broker reads the secrets, releases the vault lock, and starts the process.
//!     A variable in placeholder mode (ADR 0011) gets a placeholder. The broker then
//!     starts a run proxy that puts the real value into HTTPS requests to the hosts of
//!     the variable, and on macOS the process can connect only to that proxy.
//!
//! Each refusal after step 2 and each result is stored in the activity log.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;

use super::approvals::{
    ApprovalOutcome, CheckMethod, FirstUseBusy, FirstUseItem, FirstUseOffer, GrantChoice,
    PendingRun, Settled, folder_is_broad,
};
use super::bouncer::{
    BouncerRequest, BouncerVerdict, DecisionContext, before_model, decide_learned, owner_required,
};
use super::decide::{BrokerContext, authenticate, lock, locked_response};
use super::exec::{self, Network, SecretEnv};
use super::learning::{self, LoggedRequest, Outcome, RuleDenial, RunScope};
use super::proxy::{
    HostRule, OtherHosts, ProxyEvent, ProxyOptions, ProxyOutcome, ProxySecret, RunProxy,
    mint_placeholder,
};
use super::shadow::{self, ShadowInput};
use super::shell_risk::{ProviderHosts, analyze_run, injection_flag};
use crate::agent::wire::WireResponse;
use crate::vault::providers;
use crate::vault::{
    ActivityDecision, AgentSummary, DecisionEntry, Declaration, EnvBinding, EnvDelivery, ExecGrant,
    ExecMode, GrantPlace, NewActivity, OwnerLabel, RealOutcome, Vault,
};

/// A shadow thread waits this long after the owner time limit for the real outcome.
const SHADOW_MARGIN: Duration = Duration::from_secs(30);

const MAX_ITEMS: usize = 16;
const MAX_ARGS: usize = 64;
const MAX_ARG_BYTES: usize = 4096;
const MAX_PURPOSE_BYTES: usize = 500;
const MAX_PATH_BYTES: usize = 4096;

/// The start of the activity text of a run that the owner approved on the iPhone. It
/// starts with "Owner approved", so the desktop inbox classifies it as before.
const OWNER_APPROVED_ON_IPHONE: &str = "Owner approved on the iPhone";
const INVALIDATED: &str = "The vault was locked, or Apassy stopped, before the run started. The approval is not valid. Send the request again after the owner unlocks the vault.";
const FIRST_USE_WAITING: &str = "Another first use of this agent waits for the owner in Apassy. Wait for that answer, then send this request again.";
/// The start of the activity text of a first use that the owner allowed in a folder. It
/// starts with "Owner approved", so the desktop inbox classifies it as before.
const OWNER_GRANTED: &str = "Owner approved at first use and gave access";
const RELOCKED: &str =
    "The vault was locked while Apassy checked this request. Send the request again.";

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
    /// Short text for the activity log. It has no secret value, because the agent does not have one.
    fn label(&self) -> String {
        let mut text = format!("run {}", self.command.join(" "));
        if text.len() > 64 {
            let mut end = 61;
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            text.truncate(end);
            text.push_str("...");
        }
        text
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
    /// Canonical project directory of the first item. Remembered patterns bind to it.
    project_dir: PathBuf,
    /// Working directory relative to the project directory of the first item.
    relative_dir: String,
    env_names: Vec<String>,
    /// The variables in placeholder mode (ADR 0011).
    placeholder_names: Vec<String>,
    /// At least one grant is in "ask" mode.
    any_ask: bool,
    /// Owner instructions of the grants, joined.
    instruction: String,
    /// Owner declarations, one per item. `None` when an item has none.
    declarations: Vec<Option<Declaration>>,
    /// The known hosts of the provider of each item with a provider (goal item B4).
    provider_hosts: Vec<ProviderHosts>,
    /// Exact item and permission state used by the owner or model. A later check
    /// must match this state before the broker reads any secret.
    authorization: Vec<ItemAuthorization>,
    /// The items without a process grant (ADR 0024). Empty for a run with grants only.
    first_use: Vec<FirstUseItem>,
    /// The folder of a first-use grant. Set when `first_use` has an item.
    first_use_folder: Option<PathBuf>,
}

#[derive(PartialEq, Eq)]
struct ItemAuthorization {
    binding: EnvBinding,
    /// `None` for a first use.
    grant: Option<ExecGrant>,
    revision: u64,
    declaration: Option<Declaration>,
    provider: Option<String>,
    project: PathBuf,
}

pub(super) fn run(ctx: &BrokerContext, token: &str, request: &RunRequest<'_>) -> WireResponse {
    let label = request.label();
    let checked = {
        let mut guard = lock(&ctx.vault);
        let Some(vault) = guard.as_mut().filter(|vault| !vault.is_locked()) else {
            return locked_response();
        };
        let agent = match authenticate(vault, token, &label) {
            Ok(agent) => agent,
            Err(response) => return response,
        };
        match check(vault, &agent, request) {
            Ok(checked) => checked,
            Err((code, reason)) => {
                record(
                    vault,
                    &agent,
                    request,
                    &label,
                    ActivityDecision::Deny,
                    &reason,
                );
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
    // A rule flag (ADR 0008) or a hard owner rule (ADR 0010) skips the model.
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
    let context = DecisionContext {
        analysis: &analysis,
        declarations: &checked.declarations,
        has_user_request: !user_request.is_empty(),
    };
    // Learning (ADR 0009, ADR 0010): the calibrated level and a remembered pattern. A
    // pattern replaces only the model step, so an active pattern also skips the model.
    let now = learning::now();
    let scope = RunScope {
        agent_id: checked.agent.id,
        project_dir: &checked.project_dir,
        cwd: &checked.cwd,
        cwd_rel: &checked.relative_dir,
        items: request.items,
        declarations: &checked.declarations,
        instruction: &checked.instruction,
    };
    let pattern = learning::request_pattern(scope, request.command);
    // Goal item B9: the active model (the default bouncer or a promoted model) and the
    // candidate in shadow mode come from the vault.
    let (learned, models) = lock(&ctx.vault)
        .as_ref()
        .filter(|vault| !vault.is_locked())
        .map(|vault| {
            (
                learning::lookup(vault, pattern.as_ref(), now),
                shadow::models(vault, ctx.bouncer.as_ref()),
            )
        })
        .unwrap_or_default();
    let bouncer_request = BouncerRequest {
        user_request: user_request.to_owned(),
        command: request.command.join(" "),
        relative_dir: checked.relative_dir.clone(),
        purpose: request.purpose.trim().to_owned(),
        env_names: checked.env_names.clone(),
        instruction: checked.instruction.clone(),
    };
    // Shadow mode (ADR 0010): for a request that reaches the model step, the candidate
    // answers on its own thread. Its answer goes only to the vault. The decision below
    // uses the active model only, and the broker does not wait for the candidate.
    let first_use = !checked.first_use.is_empty();
    let model_step =
        before_model(&context).is_none() && learned.learned.pattern.is_none() && !first_use;
    let mut shadow_call = if model_step {
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
    let verdict = if !analysis.flags.is_empty()
        || owner_required(&context).is_some()
        || learned.learned.pattern.is_some()
        || first_use
    {
        BouncerVerdict::Unavailable("not asked".to_owned())
    } else {
        match &models.active {
            // The setting of Settings > Agents: "Off" asks no model, and "When a run
            // needs it" starts the model server first. Unavailable asks the owner.
            Some(bouncer) => match ctx
                .model_gate
                .as_ref()
                .map_or(Ok(()), |gate| gate.before_model())
            {
                Ok(()) => bouncer.evaluate(&bouncer_request),
                Err(reason) => BouncerVerdict::Unavailable(reason),
            },
            None => BouncerVerdict::Unavailable("no bouncer is set".to_owned()),
        }
    };
    let decision = decide_learned(&verdict, &context, &learned.learned);
    // ADR 0024: a first use always waits for the owner. The note names the new items.
    let risk_note = if first_use {
        first_use_note(&checked.first_use, &analysis.flags)
    } else {
        decision.note.clone()
    };
    let log_note = format!("{} {risk_note}", resolved.log_note());
    let needs_approval = checked.any_ask || first_use || decision.ask_owner;
    let by_pattern = !decision.ask_owner && learned.learned.pattern.is_some() && !first_use;
    let decided_by = if needs_approval {
        "Owner approved"
    } else if by_pattern {
        "Remembered pattern"
    } else {
        "Bouncer allowed"
    };
    // The activity log names an approval on the iPhone. The answer to the agent keeps
    // `decided_by`, and the inbox reads the prefix "Owner approved" in both cases.
    let mut logged_decided_by = decided_by;
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
        grant_asks: checked.any_ask,
        thresholds: learned.learned.thresholds,
    };
    let mut remembered = false;
    let mut grant_choice: Option<GrantChoice> = None;

    if !needs_approval {
        let entry = logged.entry(Outcome::Automatic { by_pattern }, &risk_note);
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
            // A first use teaches no pattern: the owner gives access instead.
            remember: if first_use {
                None
            } else {
                learned.offer(pattern.as_ref(), &context, checked.any_ask)
            },
        };
        let settled = match (&checked.first_use_folder, first_use) {
            (Some(folder), true) => ctx.approvals.wait_for_first_use(
                pending,
                FirstUseOffer {
                    agent_id: checked.agent.id,
                    folder: folder.display().to_string(),
                    items: checked.first_use.clone(),
                },
                ctx.approval_timeout,
                same_session,
            ),
            _ => {
                let (outcome, method) =
                    ctx.approvals
                        .wait_for_decision(pending, ctx.approval_timeout, same_session);
                Ok(Settled {
                    outcome,
                    method,
                    grant: None,
                })
            }
        };
        let Settled {
            outcome,
            method: checked_with,
            grant: chosen,
        } = match settled {
            Ok(settled) => settled,
            Err(FirstUseBusy) => {
                let mut guard = lock(&ctx.vault);
                if let Some(vault) = guard
                    .as_mut()
                    .filter(|vault| !vault.is_locked() && vault.path() == checked.vault_file)
                    && wait
                        .as_ref()
                        .is_none_or(|ticket| vault.end_wait(ticket).unwrap_or(true))
                {
                    record(
                        vault,
                        &checked.agent,
                        request,
                        &label,
                        ActivityDecision::Deny,
                        FIRST_USE_WAITING,
                    );
                }
                return WireResponse::failure("first_use_waiting", FIRST_USE_WAITING);
            }
        };
        grant_choice = chosen;
        if checked_with == Some(CheckMethod::Companion) {
            logged_decided_by = OWNER_APPROVED_ON_IPHONE;
        }
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
        // Every owner answer goes to the decision log. A denial blocks the pattern.
        let mut entry = logged.entry(Outcome::Owner(outcome), &risk_note);
        entry.at = learning::now();
        record_decision_locked(ctx, &checked, &entry, pattern.as_ref());
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
            ApprovalOutcome::Denied => {
                Some(("approval_denied", "The owner denied this run.".to_owned()))
            }
            ApprovalOutcome::TimedOut => Some((
                "approval_timeout",
                format!(
                    "The owner did not decide in {:.1} seconds.",
                    ctx.approval_timeout.as_secs_f32()
                ),
            )),
            ApprovalOutcome::Invalidated => Some(("approval_invalidated", INVALIDATED.to_owned())),
        };
        if let Some((code, reason)) = refusal {
            let reason = format!("{reason} {log_note}.");
            if own_entry {
                record_locked(
                    ctx,
                    &checked,
                    request,
                    &label,
                    ActivityDecision::Deny,
                    &reason,
                );
            }
            return WireResponse::failure(code, reason);
        }
    }

    // The owner can lock, revoke, or change grants while a run waits. Check again.
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
                return WireResponse::failure(code, reason);
            }
        };
        if rechecked.authorization != checked.authorization
            || rechecked.cwd != checked.cwd
            || rechecked.provider_hosts != checked.provider_hosts
        {
            let reason = "The credential or its process access changed while Apassy checked this run. Send the request again.";
            record(
                vault,
                &agent,
                request,
                &label,
                ActivityDecision::Deny,
                reason,
            );
            return WireResponse::failure("authorization_changed", reason);
        }
        // ADR 0024: "Allow in this folder" saves the grant and the declarations now, in
        // the session of the decision and after the second check.
        if let Some(choice) = &grant_choice {
            if let Err(reason) = save_first_use(vault, &agent, &checked, choice) {
                record(
                    vault,
                    &agent,
                    request,
                    &label,
                    ActivityDecision::Deny,
                    &reason,
                );
                return WireResponse::failure("grant_failed", reason);
            }
            logged_decided_by = OWNER_GRANTED;
        }
        // The run starts in the session of the decision. Now learning can count it.
        if remembered && let Some(pattern) = &pattern {
            let _ = learning::remember(vault, pattern, learning::now());
        }
        if by_pattern && let Some(id) = learned.active_id {
            let _ = vault.record_pattern_use(id, learning::now());
        }
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
            if let Some(choice) = &grant_choice {
                let production = choice
                    .declarations
                    .iter()
                    .map(|chosen| Some(&chosen.declaration))
                    .chain(
                        checked
                            .first_use
                            .iter()
                            .map(|item| item.declaration.as_ref()),
                    )
                    .flatten()
                    .chain(checked.declarations.iter().flatten())
                    .any(|declaration| declaration.is_production());
                answer["access"] = json!(format!(
                    "The owner gave this agent access to these credentials in {}. Later clean runs there may start without asking.{}",
                    choice.folder,
                    if production {
                        " A production credential still waits for the owner at each run."
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
    let grants = vault.exec_grants_for_agent(agent.id).map_err(|_| {
        (
            "broker_error",
            "The broker cannot read the grants.".to_owned(),
        )
    })?;
    // ADR 0024: an agent that sees all credentials can use one without a grant. The
    // owner decides at the first use.
    let sees_all = vault.agent_sees_all(agent.id).map_err(|_| {
        (
            "broker_error",
            "The broker cannot read the agent settings.".to_owned(),
        )
    })?;
    let mut first_use = Vec::new();
    let mut first_use_folder = None;
    let mut env_names = Vec::new();
    let mut unique_env_names = BTreeSet::new();
    let mut placeholder_names = Vec::new();
    let mut any_ask = false;
    let mut declarations = Vec::new();
    let mut provider_hosts = Vec::new();
    let mut authorization = Vec::new();
    let mut instructions: Vec<String> = Vec::new();
    let mut relative_dir = None;
    let mut project_dir = None;
    let command_text = request.command.join(" ");
    let command_lower = command_text.to_lowercase();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    for item_id in request.items {
        let grant = grants.iter().find(|grant| grant.item_id == *item_id);
        if grant.is_none() && !sees_all {
            return Err((
                "not_granted",
                format!("The owner did not give process access to item {item_id}."),
            ));
        }
        // Goal item V4: settings from a restored backup wait for the owner review.
        if vault.needs_review(*item_id).unwrap_or(true) {
            return Err(("review_required", review_reason(*item_id)));
        }
        // An archived item stays in the vault, but agents cannot use it.
        if vault.is_archived(*item_id).unwrap_or(true) {
            return Err(("item_archived", archived_reason(*item_id)));
        }
        // ADR 0012: a grant for any folder takes the working directory as its project.
        // ADR 0024: a first use takes the folder of its offer.
        let project = match grant.map(|grant| &grant.place) {
            Some(GrantPlace::Folder(dir)) => canonical_dir(Path::new(dir)),
            Some(GrantPlace::AnyFolder) => Some(cwd.clone()),
            None => Some(
                first_use_folder
                    .get_or_insert_with(|| offer_folder(&cwd))
                    .clone(),
            ),
        };
        let inside = project
            .as_ref()
            .is_some_and(|project| cwd.starts_with(project));
        if relative_dir.is_none()
            && let Some(project) = &project
            && let Ok(rest) = cwd.strip_prefix(project)
        {
            let rest = rest.display().to_string();
            relative_dir = Some(if rest.is_empty() {
                ".".to_owned()
            } else {
                rest
            });
            project_dir = Some(project.clone());
        }
        if !inside {
            return Err((
                "outside_project",
                format!(
                    "The working directory is not inside the project directory for item {item_id}."
                ),
            ));
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
        let details = vault.details(*item_id).map_err(|_| {
            (
                "broker_error",
                "The broker cannot read the credential revision.".to_owned(),
            )
        })?;
        let Some(grant) = grant else {
            first_use.push(FirstUseItem {
                item_id: *item_id,
                name: details.summary.title.clone(),
                declaration: declaration.clone(),
            });
            push_item(
                vault,
                *item_id,
                binding,
                None,
                details.summary.revision,
                declaration,
                project.expect("the offer folder contains cwd"),
                &mut Collected {
                    env_names: &mut env_names,
                    placeholder_names: &mut placeholder_names,
                    declarations: &mut declarations,
                    provider_hosts: &mut provider_hosts,
                    authorization: &mut authorization,
                },
            )?;
            continue;
        };
        let rule = &grant.rule;
        if rule.expires_at.is_some_and(|at| now >= at) {
            return Err((
                "rule_expired",
                format!("The rule for item {item_id} expired."),
            ));
        }
        let prefix_ok = rule.allowed_prefixes.is_empty()
            || rule.allowed_prefixes.iter().any(|prefix| {
                command_text == *prefix || command_text.starts_with(&format!("{prefix} "))
            });
        if !prefix_ok {
            return Err((
                "rule_command_not_permitted",
                format!(
                    "The rule for item {item_id} permits only commands that start with: {}.",
                    rule.allowed_prefixes.join(", ")
                ),
            ));
        }
        if let Some(word) = rule
            .forbidden_words
            .iter()
            .find(|word| command_lower.contains(&word.to_lowercase()))
        {
            return Err((
                "rule_forbidden_word",
                format!("The rule for item {item_id} forbids \"{word}\" in the command."),
            ));
        }
        if let Some(max) = rule.max_runs_per_hour {
            let used = vault.runs_in_last_hour(agent.id, *item_id).map_err(|_| {
                (
                    "broker_error",
                    "The broker cannot read the run log.".to_owned(),
                )
            })?;
            if used >= max {
                return Err((
                    "rule_rate_limit",
                    format!("The rule for item {item_id} permits {max} runs in one hour."),
                ));
            }
        }
        if !rule.instruction.is_empty() {
            instructions.push(rule.instruction.clone());
        }
        // ADR 0008: the bouncer decides with the owner declaration. An item without a
        // declaration makes the decision ask the owner.
        any_ask |= grant.mode == ExecMode::Ask;
        // ADR 0012: in any folder, a process with the real value waits for the owner.
        any_ask |= grant.place == GrantPlace::AnyFolder && binding.delivery == EnvDelivery::Value;
        push_item(
            vault,
            *item_id,
            binding,
            Some(grant.clone()),
            details.summary.revision,
            declaration,
            project.expect("the granted project contains cwd"),
            &mut Collected {
                env_names: &mut env_names,
                placeholder_names: &mut placeholder_names,
                declarations: &mut declarations,
                provider_hosts: &mut provider_hosts,
                authorization: &mut authorization,
            },
        )?;
    }
    Ok(Checked {
        agent: agent.clone(),
        epoch: vault.epoch(),
        vault_file: vault.path().to_path_buf(),
        project_dir: project_dir.unwrap_or_else(|| cwd.clone()),
        cwd,
        relative_dir: relative_dir.unwrap_or_else(|| ".".to_owned()),
        env_names,
        placeholder_names,
        any_ask,
        instruction: instructions.join(" "),
        declarations,
        provider_hosts,
        authorization,
        first_use,
        first_use_folder,
    })
}

/// The lists that [`check`] collects for each item.
struct Collected<'a> {
    env_names: &'a mut Vec<String>,
    placeholder_names: &'a mut Vec<String>,
    declarations: &'a mut Vec<Option<Declaration>>,
    provider_hosts: &'a mut Vec<ProviderHosts>,
    authorization: &'a mut Vec<ItemAuthorization>,
}

/// Add the variable, the declaration, the provider hosts, and the authorization of one
/// item, with a grant or at first use.
#[allow(clippy::too_many_arguments)]
fn push_item(
    vault: &Vault,
    item_id: u64,
    binding: EnvBinding,
    grant: Option<ExecGrant>,
    revision: u64,
    declaration: Option<Declaration>,
    project: PathBuf,
    out: &mut Collected<'_>,
) -> Result<(), (&'static str, String)> {
    out.declarations.push(declaration.clone());
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
    if !hosts.is_empty() {
        out.provider_hosts.push(ProviderHosts {
            env_name: binding.env_name.clone(),
            hosts,
        });
    }
    out.env_names.push(binding.env_name.clone());
    out.authorization.push(ItemAuthorization {
        binding,
        grant,
        revision,
        declaration,
        provider,
        project,
    });
    Ok(())
}

/// The folder of a first-use grant (ADR 0024): the nearest parent of `cwd` with
/// `.git`, below the home folder. Without one, `cwd`. `cwd` is canonical.
fn offer_folder(cwd: &Path) -> PathBuf {
    let home = std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .and_then(|home| canonical_dir(Path::new(&home)));
    for dir in cwd.ancestors() {
        if home.as_deref() == Some(dir) || dir.parent().is_none() {
            break;
        }
        if dir.join(".git").exists() {
            return dir.to_path_buf();
        }
    }
    cwd.to_path_buf()
}

/// The risk note of a first use: the new items and the rule flags.
fn first_use_note(items: &[FirstUseItem], flags: &[String]) -> String {
    let names = items
        .iter()
        .map(|item| format!("\"{}\"", item.name))
        .collect::<Vec<_>>()
        .join(", ");
    let mut note = format!("First use: this agent has no access to {names} yet. You decide.");
    if !flags.is_empty() {
        note.push_str(&format!(" Rule flags: {}.", flags.join(", ")));
    }
    note
}

/// Save "Allow in this folder" (ADR 0024): the declarations that the owner accepted,
/// then one grant in "Bouncer decides" for each first-use item. The run passed the
/// second check, so the items, their declarations, and the folder are as the owner saw.
fn save_first_use(
    vault: &mut Vault,
    agent: &AgentSummary,
    checked: &Checked,
    choice: &GrantChoice,
) -> Result<(), String> {
    let folder = checked
        .first_use_folder
        .as_ref()
        .map(|folder| folder.display().to_string());
    if folder.as_deref() != Some(choice.folder.as_str()) {
        return Err(
            "The folder of the access changed while Apassy checked this run. Nothing was saved. Send the request again."
                .to_owned(),
        );
    }
    // The queue refused a broad folder already. Save checks it again, with the HOME of
    // this moment, so a lasting grant for the root or the home folder never reaches the vault.
    if folder_is_broad(&choice.folder) {
        return Err(
            "This folder is too wide for a lasting access. Nothing was saved. The command did not run. Use \"Allow once\"."
                .to_owned(),
        );
    }
    for chosen in &choice.declarations {
        let undeclared = checked
            .first_use
            .iter()
            .any(|item| item.item_id == chosen.item_id && item.declaration.is_none());
        if !undeclared {
            return Err(
                "A declaration does not belong to a new credential of this run. Nothing was saved."
                    .to_owned(),
            );
        }
        vault
            .save_declaration(
                chosen.item_id,
                &chosen.declaration,
                chosen.provider.as_deref(),
                chosen.suggested.as_ref(),
            )
            .map_err(|_| {
                "Apassy could not save the declaration. Nothing more was saved. The command did not run."
                    .to_owned()
            })?;
    }
    let items: Vec<u64> = checked.first_use.iter().map(|item| item.item_id).collect();
    vault
        .set_exec_grants(
            agent.id,
            &items,
            &GrantPlace::Folder(choice.folder.clone()),
            ExecMode::Bouncer,
        )
        .map_err(|_| {
            "Apassy could not save the access. The command did not run. Send the request again."
                .to_owned()
        })
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
