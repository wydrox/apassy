//! Request checks and execution. The order of the checks is part of the contract.
//!
//! 1. The vault is open and unlocked.
//! 2. The token belongs to an active agent, and the token has not expired.
//! 3. The agent has a grant for the item and the operation.
//! 4. After a restore, the owner reviewed the agent settings of the item (goal item V4).
//! 5. The item has a destination with a known profile and a loopback URL.
//! 6. The parameters match the operation.
//! 7. Only then does the broker read the secret, release the vault lock, and call the destination.
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
use super::approvals::ApprovalQueue;
use super::bouncer::BouncerClient;
use super::http::{self, HttpFailure, TlsClient, parse_destination};
use super::profile::{self, OperationSpec};
use super::prompts::PromptStore;
use crate::agent::wire::{Action, WIRE_VERSION, WireRequest, WireResponse};
use crate::vault::{
    ActivityDecision, AgentSummary, NewActivity, Vault, VaultErrorKind, format_utc,
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

fn unauthenticated_response() -> WireResponse {
    WireResponse::failure(
        "unauthenticated",
        "The agent token is not valid, or the owner revoked it.",
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
        if vault.is_archived(item_id).unwrap_or(true) {
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
        if vault.is_archived(grant.item_id).unwrap_or(true) {
            continue;
        }
        let Ok(details) = vault.details(grant.item_id) else {
            continue;
        };
        let Ok(Some(binding)) = vault.env_binding(grant.item_id) else {
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
    let sees_all = vault.agent_sees_all(agent.id).unwrap_or(false);
    let mut answer = json!({
        "agent": agent.name,
        "items": items,
        "process_access": process_access,
        "sees_all_credentials": sees_all,
        "note": "Secret values are never returned. Use apassy_use_credential for a connector operation. Use apassy_run_with_secrets to run a command with process_access items in its environment.",
    });
    if sees_all {
        answer["catalog"] = catalog(vault, agent.id);
        answer["note"] = json!(
            "Secret values are never returned. `catalog` lists every credential of the owner without secret values. For a credential with access \"can_request\", call apassy_request_access with the reason in the user's own words. The owner decides in the Apassy app; the call does not wait. When the owner gives access, the credential shows in process_access."
        );
    }
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

/// Every credential that is not archived, without values (ADR 0012), with what the
/// agent can do with it.
fn catalog(vault: &Vault, agent_id: u64) -> Value {
    let granted: Vec<u64> = vault
        .exec_grants_for_agent(agent_id)
        .unwrap_or_default()
        .iter()
        .map(|grant| grant.item_id)
        .collect();
    let open: Vec<u64> = vault
        .agent_access_requests(agent_id, crate::vault::MAX_OPEN_REQUESTS)
        .unwrap_or_default()
        .iter()
        .filter(|request| request.state == crate::vault::RequestState::Open)
        .map(|request| request.item_id)
        .collect();
    let entries: Vec<Value> = vault
        .catalog()
        .unwrap_or_default()
        .into_iter()
        .map(|entry| {
            let access = if granted.contains(&entry.item_id) {
                "can_use"
            } else if open.contains(&entry.item_id) {
                "requested"
            } else if entry.has_variable {
                "can_request"
            } else {
                "no_variable"
            };
            let details: serde_json::Map<String, Value> = entry
                .details
                .into_iter()
                .map(|(name, value)| (name, Value::String(value)))
                .collect();
            json!({
                "item_id": entry.item_id,
                "item_name": entry.name,
                "kind": entry.kind,
                "details": details,
                "access": access,
            })
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
                    "State the reason in 1 to 500 characters, use an absolute cwd, and ask only for a credential whose access is \"can_request\". A credential without an environment variable needs the owner first.",
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

fn call(
    ctx: &BrokerContext,
    token: &str,
    item_id: u64,
    operation: &str,
    params: &BTreeMap<String, String>,
) -> WireResponse {
    let vault = &ctx.vault;
    let prepared = {
        let mut guard = lock(vault);
        let Some(vault) = guard.as_mut().filter(|vault| !vault.is_locked()) else {
            return locked_response();
        };
        match prepare(vault, token, item_id, operation, params) {
            Ok(prepared) => prepared,
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
        let mut guard = lock(vault);
        if let Some(vault) = guard.as_mut().filter(|vault| !vault.is_locked()) {
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

fn prepare(
    vault: &mut Vault,
    token: &str,
    item_id: u64,
    operation: &str,
    params: &BTreeMap<String, String>,
) -> Result<Prepared, WireResponse> {
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

    match vault.has_grant(agent.id, item_id, operation) {
        Ok(true) => {}
        Ok(false) => {
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
    let Ok(target) = parse_destination(&destination.base_url) else {
        return Err(deny(
            vault,
            "destination_not_permitted",
            "The destination must be https://, or http:// on this computer.",
        ));
    };
    let kind_matches = vault
        .details(item_id)
        .is_ok_and(|details| details.summary.kind == profile.credential_kind);
    if !kind_matches {
        return Err(deny(
            vault,
            "wrong_credential_kind",
            "The item category does not match the connector profile.",
        ));
    }
    let Ok(secret) = vault.reveal(item_id, profile.secret_field) else {
        return Err(deny(
            vault,
            "missing_secret",
            "The item has no value for the connector.",
        ));
    };
    Ok(Prepared {
        agent,
        destination: target,
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
