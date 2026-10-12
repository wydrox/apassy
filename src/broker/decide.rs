//! Request checks and execution. The order of the checks is part of the contract.
//!
//! 1. The vault is open and unlocked.
//! 2. The token belongs to an active agent, and the token has not expired.
//! 3. The agent may see the item (ADR 0025 §3f: no "Not for this agent", and the item is
//!    listed for an agent with "only these items"), and the owner set up the operation
//!    for the item (a connector grant).
//! 4. After a restore, the owner reviewed the agent settings of the item (goal item V4).
//! 5. The item has a destination with a known profile and a loopback URL.
//! 6. The parameters match the operation.
//! 7. The standing rules of ADR 0025 §3 decide, as for a run: "Always ask me", "Always
//!    ask for this agent", and a production declaration ask the owner (a connector use
//!    has no project, so no production allowance covers it). The question waits as a
//!    question of the agent. The model does not decide a connector use: the operation
//!    is a fixed read of its profile that the owner set up with an owner check. Without
//!    a running bouncer (no model is set, or the gate of Settings > Agents refuses),
//!    each use waits for the owner, as a run does.
//! 8. The broker checks steps 1 to 6 again; the item, its declaration, and the
//!    exceptions must be the same as in the first check. Only then does it read the
//!    secret, release the vault lock, and call the destination. Each decided use is in
//!    the use log (`item_use`).
//!
//! Each refusal after step 2 and each call result is stored in the activity log.
//! Process runs (ADR 0006) have their own check order in [`super::run`].
//! User prompts from host hooks (goal item B6) are in [`super::prompts`].

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use super::SharedVault;
use super::action_kind::ActionKind;
use super::approvals::{
    AnswerKind, ApprovalOutcome, ApprovalQueue, CheckMethod, PendingRun, QuestionInfo,
    QuestionItem, QuestionRefusal,
};
use super::bouncer::BouncerClient;
use super::http::{self, HttpFailure, TlsClient, parse_destination};
use super::model_server::ModelGate;
use super::profile::{self, OperationSpec};
use super::prompts::PromptStore;
use crate::agent::wire::{Action, WIRE_VERSION, WireRequest, WireResponse, codes};
use crate::vault::answers::normal_host;
use crate::vault::exceptions::Standing;
use crate::vault::usage::{InteractionKind, NewItemUse, UseDecidedBy, UseOutcome};
use crate::vault::{
    ActivityDecision, AgentSummary, Declaration, DeclarationSource, DeclarationSources,
    NewActivity, Vault, VaultErrorKind, format_utc,
};

const MAX_OUTPUT_TEXT_BYTES: usize = 256;

/// Shared state for request handling.
#[derive(Debug, Clone)]
pub struct BrokerContext {
    pub vault: SharedVault,
    pub tls: TlsClient,
    pub approvals: Arc<ApprovalQueue>,
    /// How long a run in "ask" mode waits for the owner.
    pub approval_timeout: Duration,
    /// How long a process can run before the broker stops it.
    pub run_timeout: Duration,
    /// Local decision model (ADR 0007). `None` means that every run needs the owner.
    pub bouncer: Option<BouncerClient>,
    /// The hook before each model request (Settings > Agents). It can start the model
    /// server first, or say that the bouncer is off. `None`: ask the model directly.
    pub model_gate: Option<Arc<dyn ModelGate>>,
    /// User requests from host hooks (goal item B6).
    pub prompts: Arc<PromptStore>,
}

/// Handle one request from an agent. The response never contains a secret value.
pub fn handle(ctx: &BrokerContext, request: &WireRequest) -> WireResponse {
    let vault = &ctx.vault;
    if request.v != WIRE_VERSION {
        return WireResponse::failure("unsupported_version", "The wire version is not supported.");
    }
    match &request.action {
        Action::ListAccess => list_access(vault, &request.token),
        Action::Call {
            item_id,
            operation,
            params,
        } => call(ctx, &request.token, *item_id, operation, params),
        Action::Run {
            items,
            command,
            cwd,
            purpose,
            path,
            user_request,
        } => super::run::run(
            ctx,
            &request.token,
            &super::run::RunRequest {
                items,
                command,
                cwd,
                purpose,
                path: path.as_deref(),
                user_request: user_request.as_deref(),
                host_session: request.host_session.as_deref(),
            },
        ),
        Action::RequestAccess {
            item_id,
            reason,
            cwd,
        } => request_access(ctx, &request.token, *item_id, reason, cwd.as_deref()),
        Action::SubmitUserRequest {
            host,
            cwd,
            prompt,
            transcript_path,
            truncated,
        } => super::prompts::submit(
            ctx,
            &request.token,
            &super::prompts::Submission {
                host,
                host_session: request.host_session.as_deref(),
                cwd,
                prompt,
                transcript_path: transcript_path.as_deref(),
                truncated: *truncated,
            },
        ),
    }
}

pub(super) fn locked_response() -> WireResponse {
    WireResponse::failure(
        "vault_locked",
        "The Apassy vault is locked. Ask the owner to unlock it.",
    )
}

/// The owner can keep several vaults, and only one is open (ADR 0013). The text says
/// that, but it names no other vault and no count.
fn unauthenticated_response() -> WireResponse {
    WireResponse::failure(
        "unauthenticated",
        "The agent token is not valid for the Apassy vault that is open now. The owner may have another vault open, or the owner revoked the token.",
    )
}

/// Lock the shared vault. A poisoned mutex still holds a consistent SQLite state.
pub(super) fn lock(vault: &SharedVault) -> std::sync::MutexGuard<'_, Option<Vault>> {
    vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Find the agent of the token. An expired token gives `token_expired` (goal item P1).
/// The activity log names the agent, so the owner knows which token to rotate.
pub(super) fn authenticate(
    vault: &mut Vault,
    token: &str,
    action: &str,
) -> Result<AgentSummary, WireResponse> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    match vault.identify_agent(token) {
        Ok(agent) if agent.token_expired_at(now) => {
            let expired = format_utc(agent.token_expires_at);
            let _ = vault.record_activity(&NewActivity {
                agent_id: Some(agent.id),
                agent_name: agent.name.clone(),
                item_id: None,
                operation: action.to_owned(),
                decision: ActivityDecision::Deny,
                reason: format!(
                    "The agent token expired on {expired}. Rotate the token in Agents."
                ),
            });
            Err(WireResponse::failure(
                "token_expired",
                format!(
                    "The Apassy agent token expired on {expired}. Ask the owner to rotate the token in the Apassy app (Agents, Rotate token) and to put the new token in APASSY_AGENT_TOKEN of this MCP server."
                ),
            ))
        }
        Ok(agent) => Ok(agent),
        Err(err) if err.kind() == VaultErrorKind::NotFound => {
            let _ = vault.record_activity(&NewActivity {
                agent_id: None,
                agent_name: "Unknown agent".to_owned(),
                item_id: None,
                operation: action.to_owned(),
                decision: ActivityDecision::Deny,
                reason: "The token is not valid or the agent is revoked.".to_owned(),
            });
            Err(unauthenticated_response())
        }
        Err(_) => Err(WireResponse::failure(
            "broker_error",
            "The broker cannot read the vault.",
        )),
    }
}

fn list_access(vault: &SharedVault, token: &str) -> WireResponse {
    let mut guard = lock(vault);
    let Some(vault) = guard.as_mut().filter(|vault| !vault.is_locked()) else {
        return locked_response();
    };
    let agent = match authenticate(vault, token, "list_access") {
        Ok(agent) => agent,
        Err(response) => return response,
    };
    let Ok(grants) = vault.grants_for_agent(agent.id) else {
        return WireResponse::failure("broker_error", "The broker cannot read the grants.");
    };
    // ADR 0025 §3f: an item of a "Not for this agent" exception, or an item that is not
    // on the list of an agent with "only these items", is hidden everywhere.
    let Ok(view) = vault.agent_view(agent.id) else {
        return WireResponse::failure("broker_error", "The broker cannot read the agent settings.");
    };
    let mut by_item: BTreeMap<u64, Vec<String>> = BTreeMap::new();
    for grant in grants {
        by_item
            .entry(grant.item_id)
            .or_default()
            .push(grant.operation);
    }
    let mut items = Vec::new();
    for (item_id, operations) in by_item {
        // An archived item is not for agents. The broker refuses each request with it.
        if vault.is_archived(item_id).unwrap_or(true) || !view.visible(item_id) {
            continue;
        }
        let Ok(details) = vault.details(item_id) else {
            continue;
        };
        let Ok(Some(destination)) = vault.destination(item_id) else {
            continue;
        };
        let Some(profile) = profile::find(&destination.profile) else {
            continue;
        };
        let described: Vec<Value> = operations
            .iter()
            .filter_map(|name| profile.operation(name))
            .map(OperationSpec::describe)
            .collect();
        items.push(json!({
            "item_id": item_id,
            "item_name": details.summary.title,
            "profile": profile.id,
            "operations": described,
            "owner_review_needed": vault.needs_review(item_id).unwrap_or(true),
        }));
    }
    let mut process_access = Vec::new();
    for grant in vault.exec_grants_for_agent(agent.id).unwrap_or_default() {
        if vault.is_archived(grant.item_id).unwrap_or(true) || !view.visible(grant.item_id) {
            continue;
        }
        let Ok(details) = vault.details(grant.item_id) else {
            continue;
        };
        let Ok(Some(binding)) = vault.process_binding(grant.item_id) else {
            continue;
        };
        let production = vault
            .declaration(grant.item_id)
            .ok()
            .flatten()
            .is_some_and(|declaration| declaration.is_production());
        let (holds, hosts) = match &binding.delivery {
            crate::vault::EnvDelivery::Value => ("the real value", Vec::new()),
            crate::vault::EnvDelivery::Placeholder(hosts) => ("a placeholder", hosts.clone()),
        };
        process_access.push(json!({
            "item_id": grant.item_id,
            "item_name": details.summary.title,
            "env_name": binding.env_name,
            "env_holds": holds,
            "real_value_only_for_hosts": hosts,
            "project_dir": grant.place.folder(),
            "any_folder": grant.place == crate::vault::GrantPlace::AnyFolder,
            "permitted_command_prefixes": grant.rule.allowed_prefixes,
            "owner_instruction": grant.rule.instruction,
            "approval": match grant.mode {
                crate::vault::ExecMode::Ask => "the owner approves each run",
                crate::vault::ExecMode::Bouncer if production => {
                    "production credential: the owner approves each run"
                }
                crate::vault::ExecMode::Bouncer => "the bouncer decides; a risky run waits for the owner",
            },
            "owner_review_needed": vault.needs_review(grant.item_id).unwrap_or(true),
        }));
    }
    let sees_all = vault.agent_sees_all(agent.id).unwrap_or(false) && !view.restricted;
    let mut answer = json!({
        "agent": agent.name,
        "items": items,
        "process_access": process_access,
        "sees_all_credentials": sees_all,
        "catalog": catalog(vault, agent.id),
        "note": "Secret values are never returned. `catalog` lists the credentials that this agent may use, without secret values, with the folder of each. A credential with access \"can_use\" works in apassy_run_with_secrets with its env_name: the bouncer decides each use, and it can ask the owner in the Apassy app while the call waits (up to 5 minutes). When the call fails with question_waiting, another question of this agent waits: wait, then call again with the same request, which joins the waiting question. Use apassy_use_credential for a connector operation.",
    });
    let requests: Vec<Value> = vault
        .agent_access_requests(agent.id, 20)
        .unwrap_or_default()
        .iter()
        .map(|request| {
            json!({
                "request_id": request.id,
                "item_id": request.item_id,
                "state": request.state.as_str(),
            })
        })
        .collect();
    if !requests.is_empty() {
        answer["access_requests"] = json!(requests);
    }
    WireResponse::success(answer)
}

/// Every credential that is not archived and that the exceptions of the agent do not
/// hide, without values (ADR 0012, ADR 0025 §3f), with its folder and what the agent
/// can do with it. A process grant is no authority (ADR 0025): each credential with a
/// process field is `can_use`, and the bouncer decides each use.
fn catalog(vault: &Vault, agent_id: u64) -> Value {
    let entries: Vec<Value> = vault
        .catalog_for_agent(agent_id)
        .unwrap_or_default()
        .into_iter()
        .map(|entry| {
            let access = if entry.can_use_in_process {
                "can_use"
            } else {
                "needs_field"
            };
            let details: serde_json::Map<String, Value> = entry
                .details
                .into_iter()
                .map(|(name, value)| (name, Value::String(value)))
                .collect();
            let mut entry_json = json!({
                "item_id": entry.item_id,
                "item_name": entry.name,
                "kind": entry.kind,
                "details": details,
                "access": access,
                "folder": entry.folder,
            });
            // ADR 0024: the agent can use the item at once, so it needs the name now.
            if entry.can_use_in_process
                && let Ok(Some(binding)) = vault.process_binding(entry.item_id)
            {
                entry_json["env_name"] = json!(binding.env_name);
            }
            entry_json
        })
        .collect();
    json!(entries)
}

/// An agent asks for process access to one item (ADR 0012). The answer comes at once.
fn request_access(
    ctx: &BrokerContext,
    token: &str,
    item_id: u64,
    reason: &str,
    cwd: Option<&str>,
) -> WireResponse {
    let label = format!("request access to item {item_id}");
    let mut guard = lock(&ctx.vault);
    let Some(vault) = guard.as_mut().filter(|vault| !vault.is_locked()) else {
        return locked_response();
    };
    let agent = match authenticate(vault, token, &label) {
        Ok(agent) => agent,
        Err(response) => return response,
    };
    let result = vault.request_access(agent.id, item_id, reason, cwd.unwrap_or_default());
    let (decision, answer) = match result {
        Ok((request_id, created)) => (
            ActivityDecision::Allow,
            WireResponse::success(json!({
                "request_id": request_id,
                "state": "open",
                "new": created,
                "note": "The owner decides in the Apassy app. This call does not wait. Tell the user that the request waits in Apassy (Activity). When the owner gives access, the credential shows in process_access of apassy_list_access.",
            })),
        ),
        Err(err) => {
            let (code, message) = match err.kind() {
                VaultErrorKind::NotFound => (
                    "not_visible",
                    "The owner did not let this agent see this credential, or it is archived or gone.",
                ),
                VaultErrorKind::InvalidInput => (
                    "invalid_request",
                    "State the reason in 1 to 500 characters, use an absolute cwd, and ask only for a credential whose access is \"can_request\". For access \"needs_field\", the owner must select one secret field in Apassy first.",
                ),
                VaultErrorKind::AlreadyExists => (
                    "already_granted",
                    "The agent already has process access to this credential. See process_access.",
                ),
                VaultErrorKind::Busy => (
                    "too_many_requests",
                    "This agent has 20 open access requests. Wait for the owner.",
                ),
                _ => ("broker_error", "The broker cannot record the request."),
            };
            (ActivityDecision::Deny, WireResponse::failure(code, message))
        }
    };
    let reason_text = match &answer.error {
        Some(error) => error.message.clone(),
        None => "The agent asked for process access. It waits for the owner.".to_owned(),
    };
    let _ = vault.record_activity(&NewActivity {
        agent_id: Some(agent.id),
        agent_name: agent.name.clone(),
        item_id: Some(item_id),
        operation: "request access".to_owned(),
        decision,
        reason: reason_text,
    });
    drop(guard);
    if answer.ok {
        ctx.approvals.notify_owner();
    }
    answer
}

/// Everything the network step needs. The vault lock is released before the call.
struct Prepared {
    agent: AgentSummary,
    destination: http::DestinationUrl,
    path: String,
    /// Erased on drop.
    secret: Zeroizing<String>,
    op: &'static OperationSpec,
}

/// A connector use that passed the checks, before the decision (ADR 0025 §3). It has no
/// secret value.
#[derive(PartialEq, Eq)]
struct CallChecked {
    agent: AgentSummary,
    /// The vault session and the vault file of the check.
    epoch: [u8; 32],
    vault_file: std::path::PathBuf,
    destination: String,
    profile: &'static str,
    secret_field: &'static str,
    op_name: &'static str,
    /// The state of the item that the decision used. A later check must match it.
    revision: u64,
    name: String,
    declaration: Option<Declaration>,
    sources: DeclarationSources,
    standing: Standing,
    always_ask: bool,
}

/// The connector rules of ADR 0025 §3 that do not need the model: "Always ask me",
/// "Always ask for this agent", and production (a connector use has no project, so no
/// production allowance can cover it) ask the owner. Each sentence is for the card.
fn connector_rules(checked: &CallChecked) -> Vec<String> {
    let mut why = Vec::new();
    if checked.standing == Standing::AlwaysAsk {
        why.push(format!(
            "\"{}\" is set to always ask for this agent.",
            checked.name
        ));
    } else if checked.always_ask {
        why.push(format!("\"{}\" is set to always ask.", checked.name));
    }
    if checked
        .declaration
        .as_ref()
        .is_some_and(Declaration::is_production)
    {
        why.push(format!(
            "\"{}\" is a production credential: you approve each connector use.",
            checked.name
        ));
    }
    why
}

/// The bouncer runs (ADR 0025 §3): a model is set, and the gate of Settings > Agents
/// lets it answer. The gate can start the model server.
fn bouncer_runs(ctx: &BrokerContext, model_set: bool) -> Result<(), String> {
    if !model_set {
        return Err("no bouncer is set.".to_owned());
    }
    ctx.model_gate
        .as_ref()
        .map_or(Ok(()), |gate| gate.before_model())
}

fn call(
    ctx: &BrokerContext,
    token: &str,
    item_id: u64,
    operation: &str,
    params: &BTreeMap<String, String>,
) -> WireResponse {
    let vault = &ctx.vault;
    let (checked, model_set) = {
        let mut guard = lock(vault);
        let Some(vault) = guard.as_mut().filter(|vault| !vault.is_locked()) else {
            return locked_response();
        };
        match check_call(vault, token, item_id, operation, params) {
            Ok(checked) => {
                let model_set = super::shadow::models(vault, ctx.bouncer.as_ref())
                    .active
                    .is_some();
                (checked, model_set)
            }
            Err(response) => return response,
        }
    };
    // ADR 0025 §3: the standing rules of a run. The model does not decide a connector
    // use: the operation is a fixed read of its profile that the owner set up with an
    // owner check. A use without a rule that asks starts only while the bouncer runs;
    // without it, each use waits for the owner. The gate runs without the vault lock,
    // and only when no rule asks, as for a run.
    let mut why = connector_rules(&checked);
    if why.is_empty()
        && let Err(reason) = bouncer_runs(ctx, model_set)
    {
        why.push(format!(
            "No bouncer runs, so each use waits for you: {reason}"
        ));
    }
    let asked = !why.is_empty();
    let mut answered_on = "";
    if asked {
        match ask_owner(ctx, &checked, item_id, params, &why.join(" ")) {
            Ok(on) => answered_on = on,
            Err(response) => return response,
        }
    }
    let decided_by = if asked {
        UseDecidedBy::Owner
    } else {
        UseDecidedBy::Bouncer
    };
    let prepared = {
        let mut guard = lock(vault);
        let Some(vault) = guard
            .as_mut()
            .filter(|vault| !vault.is_locked() && vault.epoch() == checked.epoch)
        else {
            return WireResponse::failure(
                "approval_invalidated",
                "The vault was locked while Apassy checked this use. Send the request again.",
            );
        };
        // The owner can change the item or the agent while a use waits. Check again.
        let rechecked = match check_call(vault, token, item_id, operation, params) {
            Ok(rechecked) => rechecked,
            Err(response) => return response,
        };
        if rechecked != checked {
            let reason = "The credential or its access changed while Apassy checked this use. Send the request again.";
            record_call_use(vault, &checked, item_id, UseOutcome::Refused, UseDecidedBy::Rule, "");
            return WireResponse::failure("authorization_changed", reason);
        }
        match read_call_secret(vault, &checked, item_id, operation, params) {
            Ok(prepared) => {
                record_call_use(
                    vault,
                    &checked,
                    item_id,
                    UseOutcome::Allowed,
                    decided_by,
                    answered_on,
                );
                prepared
            }
            Err(response) => return response,
        }
    };

    let outcome = execute(&prepared, &ctx.tls);
    let (decision, reason) = match &outcome {
        Ok(_) => (ActivityDecision::Allow, "The operation ran.".to_owned()),
        Err(response) => (
            ActivityDecision::Error,
            response
                .error
                .as_ref()
                .map_or_else(String::new, |error| error.message.clone()),
        ),
    };
    {
        // The entry goes only to the vault of the call. The owner can open another
        // vault during the call (ADR 0013).
        let mut guard = lock(vault);
        if let Some(vault) = guard
            .as_mut()
            .filter(|vault| !vault.is_locked() && vault.path() == checked.vault_file)
        {
            let _ = vault.record_activity(&NewActivity {
                agent_id: Some(prepared.agent.id),
                agent_name: prepared.agent.name.clone(),
                item_id: Some(item_id),
                operation: operation.to_owned(),
                decision,
                reason,
            });
        }
    }
    match outcome {
        Ok(result) => WireResponse::success(result),
        Err(response) => response,
    }
}

/// A connector use waits for the owner, as a question of the agent (ADR 0025 §3). The
/// question has no project, so only "Allow once" and the stricter answers can take
/// effect. Returns the device where the owner answered.
fn ask_owner(
    ctx: &BrokerContext,
    checked: &CallChecked,
    item_id: u64,
    params: &BTreeMap<String, String>,
    why: &str,
) -> Result<&'static str, WireResponse> {
    let unconfirmed = checked
        .declaration
        .as_ref()
        .is_some_and(Declaration::is_production)
        && checked.sources.environment == DeclarationSource::Default;
    let mut valid_answers = vec![
        AnswerKind::Once,
        AnswerKind::NeverForAgent,
        AnswerKind::AlwaysAskForAgent,
        AnswerKind::Disconnect,
    ];
    if unconfirmed {
        valid_answers.push(AnswerKind::CorrectEnvironment);
    }
    let mut command = vec![
        "apassy_use_credential".to_owned(),
        checked.profile.to_owned(),
        checked.op_name.to_owned(),
    ];
    command.extend(params.iter().map(|(name, value)| format!("{name}={value}")));
    let pending = PendingRun {
        id: 0,
        agent: checked.agent.name.clone(),
        command,
        cwd: String::new(),
        env_names: Vec::new(),
        purpose: format!(
            "Connector operation {} of {} on {}.",
            checked.op_name, checked.profile, checked.destination
        ),
        risk: why.to_owned(),
        user_request: String::new(),
        request_source: String::new(),
        agent_request: String::new(),
        remember: None,
        question: QuestionInfo {
            id: 0,
            item_ids: vec![item_id],
            project: None,
            action: ActionKind::Read,
            production: false,
            why: why.to_owned(),
            items: vec![QuestionItem {
                item_id,
                name: checked.name.clone(),
                production: !unconfirmed
                    && checked
                        .declaration
                        .as_ref()
                        .is_some_and(Declaration::is_production),
                unconfirmed,
                always_ask: checked.always_ask || checked.standing == Standing::AlwaysAsk,
            }],
            valid_answers,
        },
    };
    let same_session = || {
        lock(&ctx.vault)
            .as_ref()
            .is_some_and(|vault| !vault.is_locked() && vault.epoch() == checked.epoch)
    };
    let settled = ctx.approvals.wait_for_question(
        pending,
        checked.agent.id,
        checked.epoch,
        ctx.approval_timeout,
        same_session,
    );
    let mut guard = lock(&ctx.vault);
    let vault = guard
        .as_mut()
        .filter(|vault| !vault.is_locked() && vault.path() == checked.vault_file);
    let settled = match settled {
        Ok(settled) => settled,
        Err(refusal) => {
            if let Some(vault) = vault
                && refusal == QuestionRefusal::Busy
            {
                record_call_use(vault, checked, item_id, UseOutcome::Refused, UseDecidedBy::Rule, "");
            }
            return Err(WireResponse::failure(
                codes::QUESTION_WAITING,
                super::run::QUESTION_WAITING,
            ));
        }
    };
    let on = match settled.method {
        Some(CheckMethod::Companion) => "iPhone",
        Some(_) => "this Mac",
        None => "",
    };
    let refusal = match settled.outcome {
        ApprovalOutcome::Approved
        | ApprovalOutcome::ApprovedAndRemembered
        | ApprovalOutcome::ApprovedAndGranted => None,
        ApprovalOutcome::Denied => Some((
            "approval_denied",
            "The owner denied this use.".to_owned(),
            UseOutcome::Denied,
            UseDecidedBy::Owner,
        )),
        ApprovalOutcome::TimedOut => Some((
            "approval_timeout",
            format!(
                "The owner did not decide in {:.1} seconds. Call again with the same request.",
                ctx.approval_timeout.as_secs_f32()
            ),
            UseOutcome::TimedOut,
            UseDecidedBy::Owner,
        )),
        ApprovalOutcome::Invalidated => Some((
            "approval_invalidated",
            "The vault was locked, or Apassy stopped, before the use. Send the request again after the owner unlocks the vault.".to_owned(),
            UseOutcome::Refused,
            UseDecidedBy::Rule,
        )),
    };
    if let Some(vault) = vault {
        if !settled.attached {
            let _ = vault.record_interaction(
                InteractionKind::Question,
                &format!("use {}", checked.op_name),
                &[item_id],
            );
        }
        if let Some((_, reason, outcome, by)) = &refusal {
            record_call_use(vault, checked, item_id, *outcome, *by, on);
            let _ = vault.record_activity(&NewActivity {
                agent_id: Some(checked.agent.id),
                agent_name: checked.agent.name.clone(),
                item_id: Some(item_id),
                operation: checked.op_name.to_owned(),
                decision: ActivityDecision::Deny,
                reason: reason.clone(),
            });
        }
    }
    match refusal {
        Some((code, reason, ..)) => Err(WireResponse::failure(code, reason)),
        None => Ok(on),
    }
}

/// Store one connector use in the use log (ADR 0025 §5). A connector use has no project.
fn record_call_use(
    vault: &mut Vault,
    checked: &CallChecked,
    item_id: u64,
    outcome: UseOutcome,
    decided_by: UseDecidedBy,
    answered_on: &str,
) {
    let _ = vault.record_item_use(&NewItemUse {
        item_id,
        agent_id: Some(checked.agent.id),
        agent_name: checked.agent.name.clone(),
        project_key: String::new(),
        project_label: String::new(),
        action: ActionKind::Read,
        command_summary: format!("use {} {}", checked.profile, checked.op_name),
        hosts: vec![checked.destination.clone()],
        outcome,
        decided_by,
        answered_on: answered_on.to_owned(),
        decision_log_id: None,
    });
}

/// The checks of a connector use, before the decision. No secret is read.
fn check_call(
    vault: &mut Vault,
    token: &str,
    item_id: u64,
    operation: &str,
    params: &BTreeMap<String, String>,
) -> Result<CallChecked, WireResponse> {
    let agent = authenticate(vault, token, operation)?;
    let deny = |vault: &mut Vault, code: &str, reason: &str| {
        let _ = vault.record_activity(&NewActivity {
            agent_id: Some(agent.id),
            agent_name: agent.name.clone(),
            item_id: Some(item_id),
            operation: operation.to_owned(),
            decision: ActivityDecision::Deny,
            reason: reason.to_owned(),
        });
        WireResponse::failure(code, reason)
    };

    // ADR 0025 §3f: an exception that hides the item wins over a connector grant. The
    // connector grant names the operations that the owner set up for the item; it is
    // no process grant, and the rules below still apply to each use.
    let view = vault.agent_view(agent.id).ok();
    let visible = view.as_ref().is_some_and(|view| view.visible(item_id));
    match vault.has_grant(agent.id, item_id, operation) {
        Ok(true) if visible => {}
        Ok(_) => {
            return Err(deny(
                vault,
                "not_granted",
                "The owner did not permit this operation on this item.",
            ));
        }
        Err(_) => {
            return Err(deny(
                vault,
                "broker_error",
                "The broker cannot read the grants.",
            ));
        }
    }
    if vault.needs_review(item_id).unwrap_or(true) {
        let reason = super::run::review_reason(item_id);
        return Err(deny(vault, "review_required", &reason));
    }
    if vault.is_archived(item_id).unwrap_or(true) {
        let reason = super::run::archived_reason(item_id);
        return Err(deny(vault, "item_archived", &reason));
    }
    let Ok(Some(destination)) = vault.destination(item_id) else {
        return Err(deny(
            vault,
            "no_destination",
            "The item has no connector destination.",
        ));
    };
    let Some(profile) = profile::find(&destination.profile) else {
        return Err(deny(
            vault,
            "unknown_profile",
            "The connector profile is not known.",
        ));
    };
    let Some(op) = profile.operation(operation) else {
        return Err(deny(
            vault,
            "unknown_operation",
            "The operation is not in the connector profile.",
        ));
    };
    if let Err(message) = op.validate(params) {
        return Err(deny(vault, "invalid_params", &message));
    }
    if parse_destination(&destination.base_url).is_err() {
        return Err(deny(
            vault,
            "destination_not_permitted",
            "The destination must be https://, or http:// on this computer.",
        ));
    }
    let Ok(details) = vault.details(item_id) else {
        return Err(deny(
            vault,
            "wrong_credential_kind",
            "The item category does not match the connector profile.",
        ));
    };
    if details.summary.kind != profile.credential_kind {
        return Err(deny(
            vault,
            "wrong_credential_kind",
            "The item category does not match the connector profile.",
        ));
    }
    let declaration = vault.declaration(item_id);
    let sources = vault.declaration_sources(item_id);
    let always_ask = vault.always_ask(item_id);
    let (Ok(declaration), Ok(sources), Ok(always_ask), Some(view)) =
        (declaration, sources, always_ask, view)
    else {
        return Err(deny(
            vault,
            "broker_error",
            "The broker cannot read the settings of the credential.",
        ));
    };
    let host = destination
        .base_url
        .split("://")
        .nth(1)
        .and_then(|rest| rest.split(['/', '?', '#']).next())
        .and_then(normal_host)
        .unwrap_or_default();
    Ok(CallChecked {
        epoch: vault.epoch(),
        vault_file: vault.path().to_path_buf(),
        destination: host,
        profile: profile.id,
        secret_field: profile.secret_field,
        op_name: op.name,
        revision: details.summary.revision,
        name: details.summary.title,
        declaration,
        sources,
        standing: view.standing(item_id),
        always_ask,
        agent,
    })
}

/// Read the secret of a connector use that the decision allowed.
fn read_call_secret(
    vault: &mut Vault,
    checked: &CallChecked,
    item_id: u64,
    operation: &str,
    params: &BTreeMap<String, String>,
) -> Result<Prepared, WireResponse> {
    let deny = |vault: &mut Vault, code: &str, reason: &str| {
        let _ = vault.record_activity(&NewActivity {
            agent_id: Some(checked.agent.id),
            agent_name: checked.agent.name.clone(),
            item_id: Some(item_id),
            operation: operation.to_owned(),
            decision: ActivityDecision::Deny,
            reason: reason.to_owned(),
        });
        WireResponse::failure(code, reason)
    };
    let destination = vault
        .destination(item_id)
        .ok()
        .flatten()
        .and_then(|destination| parse_destination(&destination.base_url).ok());
    let (Some(destination), Some(op)) = (
        destination,
        profile::find(checked.profile).and_then(|profile| profile.operation(operation)),
    ) else {
        return Err(deny(
            vault,
            "authorization_changed",
            "The connector changed while Apassy checked this use. Send the request again.",
        ));
    };
    let Ok(secret) = vault.reveal(item_id, checked.secret_field) else {
        return Err(deny(
            vault,
            "missing_secret",
            "The item has no value for the connector.",
        ));
    };
    Ok(Prepared {
        agent: checked.agent.clone(),
        destination,
        path: op.path(params),
        secret: secret.into_zeroizing(),
        op,
    })
}

fn execute(prepared: &Prepared, tls: &TlsClient) -> Result<Value, WireResponse> {
    let response = http::get(&prepared.destination, &prepared.path, &prepared.secret, tls)
        .map_err(|failure| match failure {
            HttpFailure::Tls => WireResponse::failure(
                "tls_failed",
                "The TLS connection failed. The certificate is not trusted or does not match the host.",
            ),
            HttpFailure::TooLarge => WireResponse::failure(
                "bad_output",
                "The destination response is larger than 64 KiB.",
            ),
            HttpFailure::Connect | HttpFailure::Protocol => WireResponse::failure(
                "destination_unreachable",
                "The destination did not answer correctly.",
            ),
        })?;
    match response.status {
        200..=299 => {}
        300..=399 => {
            return Err(WireResponse::failure(
                "destination_error",
                "The destination sent a redirect. Apassy does not follow redirects.",
            ));
        }
        401 | 403 => {
            return Err(WireResponse::failure(
                "destination_refused",
                "The destination refused the stored credential.",
            ));
        }
        404 => {
            return Err(WireResponse::failure(
                "destination_not_found",
                "The destination has no record for these parameters.",
            ));
        }
        _ => {
            return Err(WireResponse::failure(
                "destination_error",
                "The destination returned an error.",
            ));
        }
    }
    let body: Value = serde_json::from_slice(&response.body)
        .map_err(|_| WireResponse::failure("bad_output", "The destination output is not JSON."))?;
    let object = body.as_object().ok_or_else(|| {
        WireResponse::failure("bad_output", "The destination output is not one record.")
    })?;
    let mut output = Map::new();
    for field in prepared.op.output_fields {
        let Some(value) = object.get(*field) else {
            continue;
        };
        let clean = match value {
            Value::String(text) => Value::String(bounded(text)),
            Value::Number(_) | Value::Bool(_) | Value::Null => value.clone(),
            Value::Array(_) | Value::Object(_) => continue,
        };
        output.insert((*field).to_owned(), clean);
    }
    let output = Value::Object(output);
    // Defense in depth: a destination must not echo the stored secret to the agent.
    let rendered = output.to_string();
    if !prepared.secret.is_empty() && rendered.contains(prepared.secret.as_str()) {
        return Err(WireResponse::failure(
            "output_blocked",
            "The output contained the stored secret. Apassy blocked it.",
        ));
    }
    Ok(output)
}

fn bounded(text: &str) -> String {
    let clean: String = text.chars().filter(|c| !c.is_control()).collect();
    if clean.len() <= MAX_OUTPUT_TEXT_BYTES {
        return clean;
    }
    let mut end = MAX_OUTPUT_TEXT_BYTES;
    while !clean.is_char_boundary(end) {
        end -= 1;
    }
    clean[..end].to_owned()
}
