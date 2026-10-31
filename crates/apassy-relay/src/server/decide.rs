//! The decision per run (docs/SPEC.md, "Decision per run").
//!
//! Order: validation, access, hard rules, analysis, user request, context, decision,
//! then the run row and the audit. An error never allows a run. The relay's verdict
//! (`allow` or `ask`) is a suggestion to the owner's host: every run that passes the
//! hard rules becomes `pending` and waits for a release.

use std::collections::HashSet;

use apassy::broker::proxy::HostRule;
use rusqlite::{Connection, params};
use serde_json::json;

use crate::api::{self, PolicyMode, RunRequest, RunStatus, RunView, Suggestion};
use crate::decision::{self, ItemFacts};
use crate::error::{RelayError, RelayResult, codes};
use crate::hostkeys::RunKey;
use crate::ids::{CollectionId, ItemId, MemberId, RunId};
use crate::secret::SecretString;
use crate::server::Core;
use crate::server::approvals::{RunRow, insert_run, run_view};
use crate::server::audit::{RELAY_ACTOR, agent_actor};
use crate::server::auth::AgentAuth;
use crate::server::env::EnvItem;
use crate::server::store::{ItemRow, db, has_grant, load_item, to_i, to_u};

/// Checks the shape of a run request (the core `RunRequest::validate`).
pub fn validate(request: &RunRequest, max_ttl: u64) -> RelayResult<()> {
    let bad = |text: &str| Err(RelayError::invalid(text.to_string()));
    if request.items.is_empty() || request.items.len() > api::MAX_RUN_ITEMS {
        return bad("A run names 1 to 16 items.");
    }
    let distinct: HashSet<ItemId> = request.items.iter().copied().collect();
    if distinct.len() != request.items.len() {
        return bad("The items of a run are distinct.");
    }
    if request.command.is_empty() || request.command.len() > api::MAX_COMMAND_ARGS {
        return bad("The command has 1 to 64 arguments.");
    }
    if request
        .command
        .iter()
        .any(|arg| arg.len() > api::MAX_ARG_BYTES || arg.contains('\0'))
    {
        return bad("An argument is at most 4096 bytes and has no NUL.");
    }
    if request.command[0].is_empty() || request.command[0].starts_with('-') {
        return bad("The first argument is a program name.");
    }
    let purpose = request.purpose.trim();
    if purpose.is_empty() || purpose.len() > api::MAX_PURPOSE_BYTES || purpose.contains('\0') {
        return bad("The purpose is 1 to 500 bytes.");
    }
    if let Some(text) = &request.user_request
        && (text.len() > api::MAX_USER_REQUEST_BYTES || text.contains('\0'))
    {
        return bad("The user request is at most 32 KiB and has no NUL.");
    }
    if let Some(cwd) = &request.cwd
        && (!cwd.starts_with('/') || cwd.contains('\0'))
    {
        return bad("The working directory is an absolute path.");
    }
    if let Some(ttl) = request.ttl_secs
        && (ttl < 60 || ttl > max_ttl)
    {
        return bad("The session lifetime is from 60 seconds to the relay maximum.");
    }
    Ok(())
}

/// The items of a run: each exists, has a live grant for the member, and is live.
/// An unknown item and an ungranted item give the same answer.
pub fn check_access(
    conn: &Connection,
    member: MemberId,
    ids: &[ItemId],
) -> RelayResult<Vec<ItemRow>> {
    let not_granted = || {
        RelayError::new(
            codes::NOT_GRANTED,
            "An item is unknown, or the member has no access to it.",
        )
    };
    let mut items = Vec::with_capacity(ids.len());
    for id in ids {
        let item = load_item(conn, *id)?.ok_or_else(not_granted)?;
        if !has_grant(conn, member, item.collection_id)? {
            return Err(not_granted());
        }
        if item.archived {
            return Err(RelayError::new(
                codes::ITEM_ARCHIVED,
                "An item of this run was archived.",
            ));
        }
        items.push(item);
    }
    let mut names = HashSet::new();
    if !items.iter().all(|item| names.insert(item.env_name.clone())) {
        return Err(RelayError::invalid(
            "Two items of this run have the same variable name.",
        ));
    }
    Ok(items)
}

/// The items of a run as the input of a session. `values[i]` is the decrypted value
/// of `items[i]`.
pub fn env_items(items: &[ItemRow], values: Vec<SecretString>) -> RelayResult<Vec<EnvItem>> {
    if items.len() != values.len() {
        return Err(RelayError::internal(
            "The values of a run do not match its items.",
        ));
    }
    items
        .iter()
        .zip(values)
        .map(|(item, value)| {
            let hosts = item
                .hosts
                .iter()
                .map(|host| HostRule::parse(host))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| RelayError::internal("An item has a host that cannot be read."))?;
            Ok(EnvItem {
                item_id: item.id,
                env_name: item.env_name.clone(),
                value,
                hosts,
            })
        })
        .collect()
}

/// The hard rules of the core for each distinct collection. `Err` names the rule.
fn hard_rules(
    conn: &Connection,
    agent: &AgentAuth,
    items: &[ItemRow],
    command: &[String],
    now: u64,
) -> RelayResult<()> {
    let command_text = command.join(" ");
    let lower = command_text.to_lowercase();
    let mut seen: HashSet<CollectionId> = HashSet::new();
    for item in items {
        if !seen.insert(item.collection_id) {
            continue;
        }
        let rule = &item.policy.rule;
        let name = &item.collection;
        if rule.expires_at.is_some_and(|at| now >= at) {
            return Err(RelayError::new(
                codes::RULE_EXPIRED,
                format!("The rule of collection {name} expired."),
            ));
        }
        let prefix_ok = rule.allowed_prefixes.is_empty()
            || rule
                .allowed_prefixes
                .iter()
                .any(|p| command_text == *p || command_text.starts_with(&format!("{p} ")));
        if !prefix_ok {
            return Err(RelayError::new(
                codes::RULE_COMMAND_NOT_PERMITTED,
                format!(
                    "The rule of collection {name} permits only commands that start with: {}.",
                    rule.allowed_prefixes.join(", ")
                ),
            ));
        }
        if rule
            .forbidden_words
            .iter()
            .any(|w| lower.contains(&w.to_lowercase()))
        {
            return Err(RelayError::new(
                codes::RULE_FORBIDDEN_WORD,
                format!("The rule of collection {name} forbids a word in the command."),
            ));
        }
        if let Some(max) = rule.max_runs_per_hour {
            let used = runs_in_last_hour(conn, agent, item.collection_id, now)?;
            if used >= u64::from(max) {
                return Err(RelayError::new(
                    codes::RULE_RATE_LIMIT,
                    format!("The rule of collection {name} permits {max} runs in one hour."),
                ));
            }
        }
    }
    Ok(())
}

/// The runs of this agent in the last hour (any status) with an item of the collection.
fn runs_in_last_hour(
    conn: &Connection,
    agent: &AgentAuth,
    collection: CollectionId,
    now: u64,
) -> RelayResult<u64> {
    let mut items = conn
        .prepare("SELECT id FROM item WHERE collection_id = ?1")
        .map_err(db)?;
    let of_collection: HashSet<u64> = items
        .query_map(params![to_i(collection.0)], |row| Ok(to_u(row.get(0)?)))
        .map_err(db)?
        .collect::<Result<_, _>>()
        .map_err(db)?;
    let mut runs = conn
        .prepare("SELECT items FROM run WHERE agent_id = ?1 AND created_at >= ?2")
        .map_err(db)?;
    let lists: Vec<String> = runs
        .query_map(
            params![to_i(agent.id.0), to_i(now.saturating_sub(3600))],
            |row| row.get(0),
        )
        .map_err(db)?
        .collect::<Result<_, _>>()
        .map_err(db)?;
    Ok(lists
        .iter()
        .filter(|text| {
            serde_json::from_str::<Vec<u64>>(text)
                .is_ok_and(|ids| ids.iter().any(|id| of_collection.contains(id)))
        })
        .count() as u64)
}

/// The outcome of the decision.
struct Verdict {
    ask: bool,
    note: String,
    flags: Vec<String>,
}

fn decide(core: &Core, items: &[ItemRow], request: &RunRequest) -> RelayResult<Verdict> {
    let hosts: Vec<&[String]> = items.iter().map(|i| i.hosts.as_slice()).collect();
    let facts: Vec<ItemFacts<'_>> = items
        .iter()
        .zip(&hosts)
        .map(|(item, hosts)| ItemFacts {
            env_name: &item.env_name,
            hosts,
            project: &item.collection,
            environment: &item.environment,
            risk: &item.risk,
            scope: &item.scope,
            reversibility: &item.reversibility,
        })
        .collect();
    let assessment = decision::assess(
        &core.rules,
        &request.command,
        request.purpose.trim(),
        request.user_request.as_deref(),
        &facts,
        &core.public_host,
    )?;
    let flags = assessment.flags.clone();
    if let Some(note) = assessment.ask_note {
        return Ok(Verdict {
            ask: true,
            note,
            flags,
        });
    }
    if let Some(item) = items.iter().find(|i| i.policy.mode == PolicyMode::Ask) {
        return Ok(Verdict {
            ask: true,
            note: format!(
                "The policy of collection {} asks for every run.",
                item.collection
            ),
            flags,
        });
    }
    if assessment.known_safe {
        return Ok(Verdict {
            ask: false,
            note: "Known safe command. No rule asked.".to_string(),
            flags,
        });
    }
    Ok(Verdict {
        ask: true,
        note: "Not a known safe command. The relay has no model, so a person decides.".to_string(),
        flags,
    })
}

/// `POST /v1/runs`. A hard-rule failure or an access failure is an `Err` (HTTP 403).
///
/// A run that passes becomes `pending`, whatever the relay's own verdict is. The
/// verdict is kept as the suggestion to the owner's host, next to the one-time key of
/// the run. The key is made here and kept in memory only.
pub fn request_run(
    core: &Core,
    agent: &AgentAuth,
    request: &RunRequest,
    now: u64,
) -> RelayResult<RunView> {
    validate(request, core.config.session_ttl_secs)?;
    let mut pending_key: Option<(RunId, RunKey, Suggestion)> = None;
    let result = core.store.tx(|tx| {
        let current = crate::server::auth::agent_by_id(tx, agent.id, now)?;
        if current.member != agent.member {
            return Err(RelayError::unauthenticated());
        }
        let actor = agent_actor(agent.id.0);
        let items = match check_access(tx, agent.member.id, &request.items) {
            Ok(items) => items,
            Err(error) => {
                core.audit.write_on(
                    tx,
                    now,
                    &actor,
                    "run_denied",
                    None,
                    &json!({"code": error.code, "items": request.items}),
                )?;
                return Ok(Err(error));
            }
        };
        let limits = core.limits();
        let runs: i64 = tx
            .query_row(
                "SELECT count(*) FROM run WHERE created_at >= ?1",
                params![to_i(now.saturating_sub(3600))],
                |row| row.get(0),
            )
            .map_err(db)?;
        if to_u(runs) >= limits.runs_per_hour {
            return Ok(Err(core.limit_error_on(tx, now, "runs_per_hour")?));
        }
        let pending: i64 = tx
            .query_row(
                "SELECT count(*) FROM run WHERE status = 'pending'",
                [],
                |row| row.get(0),
            )
            .map_err(db)?;
        if to_u(pending) >= limits.pending_runs {
            return Ok(Err(core.limit_error_on(tx, now, "pending_runs")?));
        }
        let ttl = request.ttl_secs.unwrap_or(core.config.session_ttl_secs);
        let mask = |text: &str| core.audit.mask_text(text);
        let mut row = RunRow {
            id: RunId(0),
            agent_id: agent.id,
            member_id: agent.member.id,
            items: request.items.clone(),
            command: request.command.iter().map(|a| mask(a)).collect(),
            purpose: mask(request.purpose.trim()),
            user_request: request.user_request.as_deref().map(mask),
            cwd: request.cwd.as_deref().map(mask),
            ttl_secs: ttl,
            flags: Vec::new(),
            note: String::new(),
            status: RunStatus::Pending,
            decided_by: None,
            approver_id: None,
            code: None,
            created_at: now,
            expires_at: None,
            decided_at: None,
            session_expires_at: None,
        };
        let requested = json!({
            "items": request.items,
            "command": request.command,
            "purpose": request.purpose.trim(),
            "user_request": request.user_request,
            "cwd": request.cwd,
        });
        if let Err(error) = hard_rules(tx, agent, &items, &request.command, now) {
            row.status = RunStatus::Denied;
            row.code = Some(error.code.to_string());
            row.note = mask(&error.message);
            row.decided_at = Some(now);
            let id = insert_run(tx, &row)?;
            core.audit
                .write_on(tx, now, &actor, "run_requested", Some(id), &requested)?;
            core.audit.write_on(
                tx,
                now,
                RELAY_ACTOR,
                "run_denied",
                Some(id),
                &json!({"code": error.code, "note": error.message}),
            )?;
            return Ok(Err(error));
        }
        let verdict = decide(core, &items, request)?;
        let suggestion = if verdict.ask {
            Suggestion::Ask
        } else {
            Suggestion::Allow
        };
        // A key that cannot be made is an error, and an error never allows a run.
        let key = RunKey::generate()
            .map_err(|_| RelayError::internal("The system has no random source."))?;
        row.flags = verdict.flags.clone();
        row.note = mask(&verdict.note);
        row.status = RunStatus::Pending;
        row.expires_at = Some(now + core.config.approval_timeout_secs);
        let id = insert_run(tx, &row)?;
        row.id = id;
        pending_key = Some((id, key, suggestion));
        let mut detail = requested;
        detail["flags"] = json!(verdict.flags);
        detail["note"] = json!(verdict.note);
        core.audit
            .write_on(tx, now, &actor, "run_requested", Some(id), &detail)?;
        core.audit.write_on(
            tx,
            now,
            RELAY_ACTOR,
            "run_pending",
            Some(id),
            &json!({
                "note": verdict.note,
                "suggestion": if verdict.ask { "ask" } else { "allow" },
                "expires_at": row.expires_at,
            }),
        )?;
        Ok(Ok(run_view(core, tx, &row, true, now)?))
    });
    match result {
        Ok(outcome) => {
            // The key goes into the table only after the run is stored, and before the
            // host is woken.
            if let Some((id, key, suggestion)) = pending_key {
                core.run_keys.insert(id, key, suggestion);
            }
            core.notify.notify();
            outcome
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> RunRequest {
        RunRequest {
            items: vec![ItemId(1)],
            command: vec!["git".into(), "status".into()],
            purpose: "look".into(),
            user_request: Some("check the repo".into()),
            cwd: Some("/work".into()),
            ttl_secs: None,
        }
    }

    #[test]
    fn validation_rules() {
        assert!(validate(&request(), 900).is_ok());
        let mut r = request();
        r.items = vec![];
        assert!(validate(&r, 900).is_err());
        let mut r = request();
        r.items = vec![ItemId(1), ItemId(1)];
        assert!(validate(&r, 900).is_err());
        let mut r = request();
        r.command = vec!["-x".into()];
        assert!(validate(&r, 900).is_err());
        let mut r = request();
        r.command = vec!["ls".into(), "a\0b".into()];
        assert!(validate(&r, 900).is_err());
        let mut r = request();
        r.purpose = "  ".into();
        assert!(validate(&r, 900).is_err());
        let mut r = request();
        r.cwd = Some("relative".into());
        assert!(validate(&r, 900).is_err());
        let mut r = request();
        r.ttl_secs = Some(59);
        assert!(validate(&r, 900).is_err());
        r.ttl_secs = Some(901);
        assert!(validate(&r, 900).is_err());
        r.ttl_secs = Some(120);
        assert!(validate(&r, 900).is_ok());
    }
}
