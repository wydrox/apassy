//! Process runs with secrets in the environment (ADR 0006).
//!
//! Check order:
//!
//! 1. The vault is open and unlocked.
//! 2. The token belongs to an active agent.
//! 3. The request has a valid form: items, command, working directory, purpose, and `PATH`.
//! 4. The working directory exists.
//! 5. For each item: the agent has process access, the working directory is in the
//!    granted project directory, and the item has an environment binding.
//! 6. If a grant is in "ask" mode, the owner approves in the desktop app.
//! 7. After the approval, the broker checks the vault, the agent, and the grants again.
//! 8. The broker reads the secrets, releases the vault lock, and starts the process.
//!
//! Each refusal after step 2 and each result is stored in the activity log.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::json;

use super::approvals::{ApprovalOutcome, PendingRun};
use super::decide::{BrokerContext, authenticate, lock, locked_response};
use super::exec::{self, SecretEnv};
use crate::agent::wire::WireResponse;
use crate::vault::{ActivityDecision, AgentSummary, ExecMode, NewActivity, Vault};

const MAX_ITEMS: usize = 16;
const MAX_ARGS: usize = 64;
const MAX_ARG_BYTES: usize = 4096;
const MAX_PURPOSE_BYTES: usize = 500;
const MAX_PATH_BYTES: usize = 4096;

/// A run request from the wire. Borrowed from the parsed request.
#[derive(Debug)]
pub struct RunRequest<'a> {
    pub items: &'a [u64],
    pub command: &'a [String],
    pub cwd: &'a str,
    pub purpose: &'a str,
    pub path: Option<&'a str>,
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
            || self
                .command
                .iter()
                .any(|arg| arg.len() > MAX_ARG_BYTES || arg.contains('\0'))
        {
            return Err("A command argument is empty, too long, or has a NUL byte.".to_owned());
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
    cwd: PathBuf,
    env_names: Vec<String>,
    needs_approval: bool,
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
                return WireResponse::failure(code, reason);
            }
        }
    };

    if checked.needs_approval {
        let outcome = ctx.approvals.wait_for(
            PendingRun {
                id: 0,
                agent: checked.agent.name.clone(),
                command: request.command.to_vec(),
                cwd: checked.cwd.display().to_string(),
                env_names: checked.env_names.clone(),
                purpose: request.purpose.trim().to_owned(),
            },
            ctx.approval_timeout,
        );
        let refusal = match outcome {
            ApprovalOutcome::Approved => None,
            ApprovalOutcome::Denied => {
                Some(("approval_denied", "The owner denied this run.".to_owned()))
            }
            ApprovalOutcome::TimedOut => Some((
                "approval_timeout",
                format!(
                    "The owner did not decide in {} seconds.",
                    ctx.approval_timeout.as_secs()
                ),
            )),
        };
        if let Some((code, reason)) = refusal {
            record_locked(
                ctx,
                &checked.agent,
                request,
                &label,
                ActivityDecision::Deny,
                &reason,
            );
            return WireResponse::failure(code, reason);
        }
    }

    // The owner can lock, revoke, or change grants while a run waits. Check again.
    let secrets = {
        let mut guard = lock(&ctx.vault);
        let Some(vault) = guard.as_mut().filter(|vault| !vault.is_locked()) else {
            return locked_response();
        };
        let agent = match authenticate(vault, token, &label) {
            Ok(agent) => agent,
            Err(response) => return response,
        };
        if let Err((code, reason)) = check(vault, &agent, request) {
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
        match read_secrets(vault, request.items) {
            Ok(secrets) => secrets,
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

    let result = exec::run(
        request.command,
        &checked.cwd,
        request.path,
        &secrets,
        ctx.run_timeout,
    );
    drop(secrets);
    match result {
        Ok(output) => {
            let reason = if output.timed_out {
                format!(
                    "The run timed out and was stopped. Directory: {}",
                    checked.cwd.display()
                )
            } else {
                format!(
                    "Exit code {}. Directory: {}",
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
            record_locked(ctx, &checked.agent, request, &label, decision, &reason);
            WireResponse::success(json!({
                "exit_code": output.exit_code,
                "timed_out": output.timed_out,
                "truncated": output.truncated,
                "stdout": output.stdout,
                "stderr": output.stderr,
                "secrets_in_environment": checked.env_names,
                "note": "Secret values in the output are replaced with [apassy:NAME].",
            }))
        }
        Err(_) => {
            let reason = "The command did not start. Check the program name and PATH.";
            record_locked(
                ctx,
                &checked.agent,
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
    let mut env_names = Vec::new();
    let mut needs_approval = false;
    for item_id in request.items {
        let Some(grant) = grants.iter().find(|grant| grant.item_id == *item_id) else {
            return Err((
                "not_granted",
                format!("The owner did not give process access to item {item_id}."),
            ));
        };
        let inside = canonical_dir(Path::new(&grant.project_dir))
            .is_some_and(|project| cwd.starts_with(project));
        if !inside {
            return Err((
                "outside_project",
                format!(
                    "The working directory is not inside the project directory for item {item_id}."
                ),
            ));
        }
        let binding = vault.env_binding(*item_id).ok().flatten().ok_or((
            "no_env_binding",
            format!("Item {item_id} has no environment variable."),
        ))?;
        needs_approval |= grant.mode == ExecMode::Ask;
        env_names.push(binding.env_name);
    }
    Ok(Checked {
        agent: agent.clone(),
        cwd,
        env_names,
        needs_approval,
    })
}

fn canonical_dir(path: &Path) -> Option<PathBuf> {
    let canonical = std::fs::canonicalize(path).ok()?;
    canonical.is_dir().then_some(canonical)
}

fn read_secrets(vault: &Vault, items: &[u64]) -> Result<Vec<SecretEnv>, String> {
    let mut secrets = Vec::new();
    for item_id in items {
        let binding = vault
            .env_binding(*item_id)
            .ok()
            .flatten()
            .ok_or_else(|| format!("Item {item_id} has no environment variable."))?;
        let value = vault
            .reveal(*item_id, &binding.field)
            .map_err(|_| format!("Item {item_id} has no value in field {}.", binding.field))?;
        secrets.push(SecretEnv {
            name: binding.env_name,
            value: value.expose().to_owned(),
        });
    }
    Ok(secrets)
}

fn record(
    vault: &mut Vault,
    agent: &AgentSummary,
    request: &RunRequest<'_>,
    label: &str,
    decision: ActivityDecision,
    reason: &str,
) {
    let _ = vault.record_activity(&NewActivity {
        agent_id: Some(agent.id),
        agent_name: agent.name.clone(),
        item_id: request.items.first().copied(),
        operation: label.to_owned(),
        decision,
        reason: format!("{reason} Purpose: {}", request.purpose.trim()),
    });
}

fn record_locked(
    ctx: &BrokerContext,
    agent: &AgentSummary,
    request: &RunRequest<'_>,
    label: &str,
    decision: ActivityDecision,
    reason: &str,
) {
    let mut guard = lock(&ctx.vault);
    if let Some(vault) = guard.as_mut().filter(|vault| !vault.is_locked()) {
        record(vault, agent, request, label, decision, reason);
    }
}
