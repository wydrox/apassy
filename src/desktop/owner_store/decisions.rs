//! The Decisions and Agents views of the owner session (ADR 0025 §1, §3f; ADR 0026 §2).
//!
//! The figures of the week, the overview of one agent, the note for the bouncer, the
//! answers to a question that make an agent stricter, the credential requests of agents
//! (ADR 0025 §6), and the suggestions from the use log (ADR 0025 §5). Each method here
//! takes authority away or moves none, so none needs an owner check. Each answer that
//! gives authority (allow once, allow in a project, allow production, a correction toward
//! development, removing an exception) is an `OwnerRequest` and passes the owner check
//! first.
//!
//! - A saved credential request adds a new item, as a paste does: it moves no authority
//!   that an item has, and the bouncer decides each use. No owner check. The item has
//!   the origin of the request (`ask_owner`), so it is not an own item of the agent.
//! - A suggestion that leaves its credential at an environment other than production
//!   makes the bouncer less careful: [`OwnerSession::answer_correction`] refuses it
//!   without a proof. Production, a project, and an ignored suggestion that changes
//!   nothing need none.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{OwnerSession, OwnerSummary, fail, map_err};
use crate::broker::approvals::{ApprovalQueue, OwnerAction, OwnerProof, StricterAnswer};
use crate::desktop::model::ModelResult;
use crate::vault::agent_items::{
    Correction, CorrectionAnswer, CorrectionKind, CorrectionState, CredentialRequest,
    CredentialRequestState, RAISED_FROM_FACT, RequestOutcome,
};
use crate::vault::detect::Detected;
use crate::vault::exceptions::{AgentException, ExceptionKind, MAX_AGENT_NOTE_BYTES};
use crate::vault::usage::{InteractionKind, ItemUse};
use crate::vault::{Environment, ItemSummary, VaultErrorKind};

const DAY: u64 = 86_400;
const WEEK: u64 = 7 * DAY;
/// How many uses of one agent the overview reads, newest first.
const AGENT_USES: usize = 2_000;
/// How many uses of one agent the list reads for its count of the week.
const LIST_USES: usize = 500;
/// How many recent uses the agent page shows.
const RECENT_USES: usize = 5;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// The line under the Decisions title (ADR 0025 §1, ADR 0026 §2).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WeekCounts {
    /// Owner interactions in the last 7 days: questions, approvals, owner checks, and
    /// corrections.
    pub by_you: u64,
    /// Decisions of the last 7 days that did not wait for the owner.
    pub automatic: u64,
}

impl WeekCounts {
    /// "3 by you · 128 automatic this week".
    pub fn line(&self) -> String {
        format!(
            "{} by you · {} automatic this week",
            self.by_you, self.automatic
        )
    }
}

/// One exception of an agent with its credential, for the agent page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExceptionRow {
    pub exception: AgentException,
    /// `None` when the credential is gone.
    pub item: Option<OwnerSummary>,
}

/// One recent use of an agent, with the name of its credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecentUse {
    pub item_use: ItemUse,
    /// The name of the credential, or "Credential N" when it is gone.
    pub item_name: String,
}

/// What the agent page shows about one agent (ADR 0025 §3f: it shows, it does not
/// configure).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentOverview {
    pub uses_this_week: usize,
    /// The projects of its uses, the most used first.
    pub projects: Vec<String>,
    /// The sentence of the owner for the bouncer. Empty when there is none.
    pub note: String,
    /// The agent sees only the listed credentials ("only these items", ADR 0025 §3f).
    pub restricted: bool,
    /// "Not for this agent", "Always ask for this agent", and the listed items of a
    /// restricted agent, by credential.
    pub exceptions: Vec<ExceptionRow>,
    /// The newest uses, newest first.
    pub recent: Vec<RecentUse>,
}

/// The projects of `labels`, the most frequent first, then by name.
fn projects_by_use<'a>(labels: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for label in labels.filter(|label| !label.is_empty()) {
        *counts.entry(label).or_default() += 1;
    }
    let mut projects: Vec<(&str, usize)> = counts.into_iter().collect();
    projects.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    projects
        .into_iter()
        .map(|(label, _)| label.to_owned())
        .collect()
}

impl OwnerSession {
    /// The owner interactions and the automatic decisions of the last 7 days.
    pub fn week_counts(&self) -> ModelResult<WeekCounts> {
        let now = now();
        let vault = self.unlocked()?;
        let by_you = vault
            .interactions_per_week(1)
            .map_err(map_err)?
            .last()
            .map_or(0, |(_, count)| *count);
        let since = (now / DAY).saturating_sub(6) * DAY;
        let automatic = vault
            .ask_rate_by_day(since)
            .map_err(map_err)?
            .iter()
            .map(|day| u64::from(day.decisions.saturating_sub(day.asked)))
            .sum();
        Ok(WeekCounts { by_you, automatic })
    }

    /// The uses, the projects, the note, and the exceptions of one agent.
    pub fn agent_overview(&self, agent_id: u64) -> ModelResult<AgentOverview> {
        let since = now().saturating_sub(WEEK);
        let (uses, note, view, exceptions) = {
            let vault = self.unlocked()?;
            (
                vault.agent_uses(agent_id, AGENT_USES).map_err(map_err)?,
                vault.agent_note(agent_id).map_err(map_err)?,
                vault.agent_view(agent_id).map_err(map_err)?,
                vault.agent_exceptions(agent_id).map_err(map_err)?,
            )
        };
        // The vault lock is free again: `search` takes it.
        let items: BTreeMap<u64, OwnerSummary> = self
            .search("")?
            .into_iter()
            .map(|item| (item.id, item))
            .collect();
        let recent = uses
            .iter()
            .take(RECENT_USES)
            .map(|item_use| RecentUse {
                item_name: items.get(&item_use.item_id).map_or_else(
                    || format!("Credential {}", item_use.item_id),
                    |item| item.name.clone(),
                ),
                item_use: item_use.clone(),
            })
            .collect();
        Ok(AgentOverview {
            uses_this_week: uses.iter().filter(|item_use| item_use.at >= since).count(),
            projects: projects_by_use(uses.iter().map(|item_use| item_use.project_label.as_str())),
            note,
            restricted: view.restricted,
            recent,
            exceptions: exceptions
                .into_iter()
                .map(|exception| ExceptionRow {
                    item: items.get(&exception.item_id).cloned(),
                    exception,
                })
                .collect(),
        })
    }

    /// The uses of one agent in the last 7 days, for the list. It reads at most the
    /// newest [`LIST_USES`].
    pub fn agent_uses_this_week(&self, agent_id: u64) -> ModelResult<usize> {
        let since = now().saturating_sub(WEEK);
        Ok(self
            .unlocked()?
            .agent_uses(agent_id, LIST_USES)
            .map_err(map_err)?
            .iter()
            .filter(|item_use| item_use.at >= since)
            .count())
    }

    /// Save the sentence about an agent (ADR 0025 §3f). It is a hint for the bouncer,
    /// not a limit, so it moves no authority and needs no owner check.
    pub fn set_agent_note(&mut self, agent_id: u64, note: &str) -> ModelResult<()> {
        if note.trim().len() > MAX_AGENT_NOTE_BYTES {
            return Err(fail(
                "invalid_input",
                format!("The note is too long: at most {MAX_AGENT_NOTE_BYTES} bytes."),
            ));
        }
        self.unlocked()?
            .set_agent_note(agent_id, note)
            .map_err(map_err)
    }

    /// Remove a listed credential of a restricted agent ("only these items"). The agent
    /// then no longer sees it: stricter, so no owner check. "Not for this agent" and
    /// "Always ask for this agent" give authority back when they go; they need
    /// `OwnerRequest::RemoveAgentException`.
    pub fn remove_listed_item(&mut self, agent_id: u64, item_id: u64) -> ModelResult<bool> {
        self.unlocked()?
            .remove_agent_exception(agent_id, item_id, ExceptionKind::Only)
            .map_err(map_err)
    }

    /// Deny a waiting question and make its agent stricter (ADR 0025 §3f): "Not for this
    /// agent", "Always ask for this agent", or "Disconnect the agent". No owner check.
    /// `Ok(false)`: the question no longer waits. The vault lock comes first, then the
    /// queue lock, as in the broker.
    pub fn deny_stricter(
        &mut self,
        queue: &ApprovalQueue,
        run_id: u64,
        stricter: StricterAnswer,
    ) -> ModelResult<bool> {
        let mut vault = self.unlocked()?;
        match queue.deny_stricter(run_id, stricter, &mut vault) {
            Ok(done) => Ok(done),
            Err(err) if err.kind() == VaultErrorKind::InvalidInput => Err(fail(
                "invalid_input",
                "Apassy does not know the agent of this question. Nothing changed. Use Deny.",
            )),
            Err(err) => Err(map_err(err)),
        }
    }

    /// Mark a credential as production from a question (ADR 0025 §3): stricter, so no
    /// owner check. The source of the environment becomes the owner, and the answer
    /// counts as a correction.
    pub fn mark_production(&mut self, item_id: u64) -> ModelResult<()> {
        let mut vault = self.unlocked()?;
        vault
            .set_declaration_environment(item_id, Environment::Production)
            .map_err(map_err)?;
        let _ = vault.record_interaction(InteractionKind::Correction, "production", &[item_id]);
        Ok(())
    }

    /// Correct the environment of a credential from a question with `proof` for its
    /// agent settings (`OwnerAction::ChangeItemRules`). Toward development the bouncer is
    /// less careful, so the owner check comes first.
    pub fn correct_environment(
        &mut self,
        item_id: u64,
        environment: Environment,
        proof: OwnerProof,
    ) -> ModelResult<()> {
        self.unlocked_for(proof, &OwnerAction::ChangeItemRules { item_id })?
            .set_declaration_environment(item_id, environment)
            .map_err(map_err)
    }

    // ---- Credential requests (ADR 0025 §6). ----

    /// The open credential requests of agents, oldest first.
    pub fn open_credential_requests(&self) -> ModelResult<Vec<CredentialRequest>> {
        self.unlocked()?.credential_requests(true).map_err(map_err)
    }

    /// Save the credential that the owner pasted for an open request: a new item in
    /// `folder` (a folder UUID; `None`: the top level) with the origin of the request,
    /// then the request is settled with it. The vault stays locked for the app between
    /// both steps, so no other answer comes between them. No owner check: a new item
    /// moves no authority.
    pub fn save_credential_request(
        &mut self,
        request_id: u64,
        detected: &Detected,
        folder: Option<&str>,
    ) -> ModelResult<ItemSummary> {
        // TODO(gate2/tools): switch to `Vault::save_for_request`, which adds and settles
        // in one transaction. Until then both steps run under one vault lock.
        let mut vault = self.unlocked()?;
        let request = vault.credential_request(request_id).map_err(map_err)?;
        if request.state != CredentialRequestState::Open {
            return Err(fail(
                "conflict",
                "The request no longer waits. Nothing was saved.",
            ));
        }
        let added = match vault.add_detected(detected, folder, Some(&request.origin())) {
            Err(err) if err.kind() == VaultErrorKind::NotFound => {
                return Err(fail(
                    "not_found",
                    "The folder is gone. Select another folder.",
                ));
            }
            other => other.map_err(map_err)?,
        };
        vault
            .settle_credential_request(request_id, RequestOutcome::Saved { item_id: added.id })
            .map_err(map_err)?;
        Ok(added)
    }

    /// "Not Now": dismiss an open credential request. The agent gets no credential, so
    /// no owner check.
    pub fn dismiss_credential_request(&mut self, request_id: u64) -> ModelResult<()> {
        match self
            .unlocked()?
            .settle_credential_request(request_id, RequestOutcome::Dismissed)
        {
            Err(err) if err.kind() == VaultErrorKind::Conflict => {
                Err(fail("conflict", "The request no longer waits."))
            }
            other => other.map_err(map_err),
        }
    }

    // ---- Suggestions (ADR 0025 §5). ----

    /// The open corrections with their credential, oldest first. A correction of a
    /// credential that the list does not show (deleted, archived) is left out.
    pub fn open_suggestions(&self) -> ModelResult<Vec<(Correction, OwnerSummary)>> {
        let corrections = self.unlocked()?.corrections(true).map_err(map_err)?;
        if corrections.is_empty() {
            return Ok(Vec::new());
        }
        // The vault lock is free again: `search` takes it.
        let items: BTreeMap<u64, OwnerSummary> = self
            .search("")?
            .into_iter()
            .map(|item| (item.id, item))
            .collect();
        Ok(corrections
            .into_iter()
            .filter_map(|correction| {
                let item = items.get(&correction.item_id)?.clone();
                Some((correction, item))
            })
            .collect())
    }

    /// The environment that `answer` to `correction` gives its credential, if it sets
    /// one: the proposed environment when accepted, and the environment before a raise
    /// ([`RAISED_FROM_FACT`]) when ignored.
    ///
    /// TODO(gate2/tools): switch the owner-check rule to the vault helper
    /// `needs_owner_check_for_correction` when it lands; this is the same matrix.
    pub fn suggestion_environment(
        correction: &Correction,
        answer: CorrectionAnswer,
    ) -> Option<Environment> {
        match (answer, correction.kind) {
            (CorrectionAnswer::Accepted, CorrectionKind::Environment) => {
                Environment::parse(&correction.proposed).ok()
            }
            (CorrectionAnswer::Accepted, CorrectionKind::Project) => None,
            (CorrectionAnswer::Ignored, _) => correction
                .facts
                .get(RAISED_FROM_FACT)
                .and_then(serde_json::Value::as_str)
                .and_then(|text| Environment::parse(text).ok()),
        }
    }

    /// Answer an open correction of `item_id`. `chosen`: the owner chose this
    /// environment instead of the proposal; the correction is ignored, then the
    /// environment is set as the owner's answer. Returns the environment that the
    /// credential got, if any.
    ///
    /// An answer that leaves the credential at an environment other than production
    /// needs `proof` for its agent settings (`OwnerAction::ChangeItemRules`): without
    /// it the answer is refused and nothing changes.
    pub fn answer_correction(
        &mut self,
        correction_id: u64,
        item_id: u64,
        answer: CorrectionAnswer,
        chosen: Option<Environment>,
        proof: Option<OwnerProof>,
    ) -> ModelResult<Option<Environment>> {
        let checked = proof.is_some();
        let mut vault = match proof {
            Some(proof) => self.unlocked_for(proof, &OwnerAction::ChangeItemRules { item_id })?,
            None => self.unlocked()?,
        };
        let correction = vault
            .item_corrections(item_id)
            .map_err(map_err)?
            .into_iter()
            .find(|correction| {
                correction.id == correction_id && correction.state == CorrectionState::Open
            })
            .ok_or_else(|| {
                fail(
                    "conflict",
                    "The suggestion no longer waits. Nothing changed.",
                )
            })?;
        let result = chosen.or_else(|| Self::suggestion_environment(&correction, answer));
        if !checked && result.is_some_and(|environment| environment != Environment::Production) {
            return Err(fail(
                "owner_check_required",
                "This answer makes the bouncer less careful. It needs Touch ID or the passphrase.",
            ));
        }
        vault
            .settle_correction(correction_id, answer)
            .map_err(map_err)?;
        if let Some(environment) = chosen {
            vault
                .set_declaration_environment(item_id, environment)
                .map_err(map_err)?;
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_week_line_and_the_projects_by_use() {
        assert_eq!(
            WeekCounts {
                by_you: 7,
                automatic: 128
            }
            .line(),
            "7 by you · 128 automatic this week"
        );
        assert_eq!(
            projects_by_use(["apassy", "", "acme", "apassy", "zeta", "acme", "apassy"].into_iter()),
            ["apassy", "acme", "zeta"]
        );
    }
}
