//! Process runs with secrets in the environment (ADR 0006).
//!
//! Check order:
//!
//! 1. The vault is open and unlocked.
//! 2. The token belongs to an active agent.
//! 3. The request has a valid form: items, command, working directory, purpose, and `PATH`.
//! 4. The working directory exists.
//! 5. For each item: the agent has process access, the working directory is in the
//!    granted project directory, the item has an environment binding, and the hard
//!    rule passes (expiry, command prefixes, forbidden words, hourly limit).
//! 6. The bouncer scores the request (ADR 0007). Heuristic flags add to the model.
//! 7. A grant in "ask" mode, a high risk, or an unavailable bouncer needs the owner.
//!    A clean request with only "bouncer" grants runs without a prompt.
//! 8. After a decision, the broker checks the vault, the agent, and the rules again.
//! 9. The broker reads the secrets, releases the vault lock, and starts the process.
//!
//! Each refusal after step 2 and each result is stored in the activity log.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::json;

use super::approvals::{ApprovalOutcome, PendingRun};
use super::bouncer::{BouncerRequest, BouncerVerdict, heuristic_flags};
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
    /// Working directory relative to the project directory of the first item.
    relative_dir: String,
    env_names: Vec<String>,
    /// At least one grant is in "ask" mode.
    any_ask: bool,
    /// Owner instructions of the grants, joined.
    instruction: String,
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

    // The bouncer runs without the vault lock. Its state has no secret value.
    let flags = heuristic_flags(request.command, request.purpose, &checked.env_names);
    let verdict = match &ctx.bouncer {
        Some(bouncer) => bouncer.evaluate(&BouncerRequest {
            agent: checked.agent.name.clone(),
            command: request.command.join(" "),
            relative_dir: checked.relative_dir.clone(),
            purpose: request.purpose.trim().to_owned(),
            env_names: checked.env_names.clone(),
            instruction: checked.instruction.clone(),
        }),
        None => BouncerVerdict::Unavailable("no bouncer is set".to_owned()),
    };
    let mut risk_note = verdict.summary();
    if !flags.is_empty() {
        risk_note.push_str(&format!(". Heuristic flags: {}", flags.join(", ")));
    }
    let clean = verdict.is_clean() && flags.is_empty();
    let needs_approval = checked.any_ask || !clean;
    let decided_by = if needs_approval {
        "Owner approved"
    } else {
        "Bouncer allowed"
    };

    if needs_approval {
        let outcome = ctx.approvals.wait_for(
            PendingRun {
                id: 0,
                agent: checked.agent.name.clone(),
                command: request.command.to_vec(),
                cwd: checked.cwd.display().to_string(),
                env_names: checked.env_names.clone(),
                purpose: request.purpose.trim().to_owned(),
                risk: risk_note.clone(),
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
                    "The owner did not decide in {:.1} seconds.",
                    ctx.approval_timeout.as_secs_f32()
                ),
            )),
        };
        if let Some((code, reason)) = refusal {
            let reason = format!("{reason} {risk_note}.");
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
                    "{decided_by}. The run timed out and was stopped. Directory: {}. {risk_note}.",
                    checked.cwd.display()
                )
            } else {
                format!(
                    "{decided_by}. Exit code {}. Directory: {}. {risk_note}.",
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
                "decided_by": decided_by,
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
    let mut any_ask = false;
    let mut instructions: Vec<String> = Vec::new();
    let mut relative_dir = None;
    let command_text = request.command.join(" ");
    let command_lower = command_text.to_lowercase();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    for item_id in request.items {
        let Some(grant) = grants.iter().find(|grant| grant.item_id == *item_id) else {
            return Err((
                "not_granted",
                format!("The owner did not give process access to item {item_id}."),
            ));
        };
        let project = canonical_dir(Path::new(&grant.project_dir));
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
        }
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
        // ADR 0007: the bouncer alone is not enough. It decides only inside a
        // command allowlist. Without prefixes, every run waits for the owner.
        any_ask |= grant.mode == ExecMode::Ask || rule.allowed_prefixes.is_empty();
        env_names.push(binding.env_name);
    }
    Ok(Checked {
        agent: agent.clone(),
        cwd,
        relative_dir: relative_dir.unwrap_or_else(|| ".".to_owned()),
        env_names,
        any_ask,
        instruction: instructions.join(" "),
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
