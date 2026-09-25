//! Request checks and execution. The order of the checks is part of the contract.
//!
//! 1. The vault is open and unlocked.
//! 2. The token belongs to an active agent.
//! 3. The agent has a grant for the item and the operation.
//! 4. The item has a destination with a known profile and a loopback URL.
//! 5. The parameters match the operation.
//! 6. Only then does the broker read the secret, release the vault lock, and call the destination.
//!
//! Each refusal after step 2 and each call result is stored in the activity log.

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};

use super::SharedVault;
use super::http::{self, parse_loopback_base};
use super::profile::{self, OperationSpec};
use crate::agent::wire::{Action, WIRE_VERSION, WireRequest, WireResponse};
use crate::vault::{ActivityDecision, AgentSummary, NewActivity, Vault, VaultErrorKind};

const MAX_OUTPUT_TEXT_BYTES: usize = 256;

/// Handle one request from an agent. The response never contains a secret value.
pub fn handle(vault: &SharedVault, request: &WireRequest) -> WireResponse {
    if request.v != WIRE_VERSION {
        return WireResponse::failure("unsupported_version", "The wire version is not supported.");
    }
    match &request.action {
        Action::ListAccess => list_access(vault, &request.token),
        Action::Call {
            item_id,
            operation,
            params,
        } => call(vault, &request.token, *item_id, operation, params),
    }
}

fn locked_response() -> WireResponse {
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
fn lock(vault: &SharedVault) -> std::sync::MutexGuard<'_, Option<Vault>> {
    vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn authenticate(
    vault: &mut Vault,
    token: &str,
    action: &str,
) -> Result<AgentSummary, WireResponse> {
    match vault.authenticate_agent(token) {
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
        }));
    }
    WireResponse::success(json!({
        "agent": agent.name,
        "items": items,
        "note": "Secret values are never returned. Use apassy_use_credential to run an operation.",
    }))
}

/// Everything the network step needs. The vault lock is released before the call.
struct Prepared {
    agent: AgentSummary,
    base: http::LoopbackBase,
    path: String,
    secret: String,
    op: &'static OperationSpec,
}

impl Drop for Prepared {
    fn drop(&mut self) {
        self.secret.clear();
    }
}

fn call(
    vault: &SharedVault,
    token: &str,
    item_id: u64,
    operation: &str,
    params: &BTreeMap<String, String>,
) -> WireResponse {
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

    let outcome = execute(&prepared);
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
    let Ok(base) = parse_loopback_base(&destination.base_url) else {
        return Err(deny(
            vault,
            "destination_not_permitted",
            "The destination is not permitted in this phase.",
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
        base,
        path: op.path(params),
        secret: secret.expose().to_owned(),
        op,
    })
}

fn execute(prepared: &Prepared) -> Result<Value, WireResponse> {
    let response = http::get(&prepared.base, &prepared.path, &prepared.secret).map_err(|_| {
        WireResponse::failure(
            "destination_unreachable",
            "The destination did not answer correctly.",
        )
    })?;
    match response.status {
        200..=299 => {}
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
