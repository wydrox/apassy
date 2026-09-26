//! Threshold calibration with a replay gate (ADR 0009 step 3, goal item B5).
//!
//! Apassy proposes a lower `task_match` level from the decision log. The owner applies a
//! proposal in the app. Nothing changes the active level without the owner.
//!
//! 1. The log is split by time: the older 70% is the fit part, the newer 30% is the
//!    held-out part.
//! 2. On the fit part, Apassy tries levels from the current level down to the floor, in
//!    steps of 0.05. It stops at the first level that allows an owner denial, also at
//!    0.05 under the level (the margin). It takes the lowest level before that stop that
//!    lets more owner approvals run.
//! 3. The held-out part gives the ask rate before and after, and the misses: owner
//!    denials that the proposal allows.
//! 4. The gate: a replay on all past decisions. The proposal is valid only if it allows
//!    no request that the owner denied. [`apply`] checks the gate again.
//!
//! Only the `task_match` level changes. The production rule, rule flags, vetoes, the
//! read-only check, and the hard rules are not calibrated.

use serde::Serialize;

use super::bouncer::{
    BouncerVerdict, DEFAULT_TASK_MATCH, DecisionContext, Fact, Learned, Thresholds, before_model,
    decide_learned,
};
use super::shell_risk::Analysis;
use crate::vault::{
    CALIBRATION_CEILING, CALIBRATION_FLOOR, DecidedBy, DecisionRecord, Vault, VaultErrorKind,
};

/// Step between levels, in hundredths.
const STEP: u32 = 5;
/// A proposed level must also allow no owner denial this far under it, in hundredths.
const MARGIN: u32 = 5;
/// Share of the newest decisions in the held-out part.
pub const HELD_OUT_SHARE: f64 = 0.3;
/// Owner decisions at the model step that the fit part needs before a proposal.
pub const MIN_OWNER_DECISIONS: usize = 30;

/// Replay counts for one level on a set of decisions.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct ReplayCounts {
    /// Decisions that reached the bouncer.
    pub decisions: usize,
    /// Decisions that wait for the owner at this level.
    pub asked: usize,
    /// Owner approvals that run without the owner at this level.
    pub approvals_allowed: usize,
    /// Owner denials that run without the owner at this level. The gate needs zero.
    pub denied_allowed: usize,
}

impl ReplayCounts {
    pub fn ask_rate(&self) -> f64 {
        if self.decisions == 0 {
            0.0
        } else {
            self.asked as f64 / self.decisions as f64
        }
    }
}

/// A proposed level with its replay numbers. It has no request data.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Proposal {
    pub current: f64,
    pub proposed: f64,
    pub decisions: usize,
    pub owner_decisions: usize,
    pub owner_denials: usize,
    pub fit_decisions: usize,
    /// Owner decisions at the model step in the fit part.
    pub fit_owner_decisions: usize,
    pub held_out_decisions: usize,
    pub held_out_before: ReplayCounts,
    pub held_out_after: ReplayCounts,
    /// The gate: a replay on all past decisions at the proposed level.
    pub all_after: ReplayCounts,
    /// The proposal is lower than the current level and passes the gate.
    pub valid: bool,
    /// Short text for the owner.
    pub reason: String,
}

impl Proposal {
    /// Owner denials in the held-out part that the proposal allows.
    pub fn held_out_misses(&self) -> usize {
        self.held_out_after.denied_allowed
    }
}

/// Replay logged decisions at one level. Rule denials do not count. A decision of a
/// remembered pattern stays allowed. A grant in "ask" mode always asks.
pub fn replay(records: &[DecisionRecord], thresholds: Thresholds) -> ReplayCounts {
    let mut counts = ReplayCounts::default();
    for record in records {
        let entry = &record.entry;
        if !entry.decided_by.reached_bouncer() {
            continue;
        }
        counts.decisions += 1;
        let asks = asks_at(record, thresholds);
        if asks {
            counts.asked += 1;
        } else if entry.decided_by == DecidedBy::Owner {
            if entry.owner_denied() {
                counts.denied_allowed += 1;
            } else {
                counts.approvals_allowed += 1;
            }
        }
    }
    counts
}

/// The decision of the real policy for one logged request at one level.
fn asks_at(record: &DecisionRecord, thresholds: Thresholds) -> bool {
    let entry = &record.entry;
    if entry.grant_asks {
        return true;
    }
    if entry.decided_by == DecidedBy::Pattern {
        return false;
    }
    // The log does not record `known_command`. Without it the replay needs `task_match`
    // for every command that is not known safe, so the task match step is never less
    // strict than the policy (v5). The log does not record `known_write` (v7) either.
    // The replay reads it as false and uses the model's `writes` answer for a sensitive
    // credential, as policy v6 did. That check does not depend on the level, so it
    // changes the replay at the old and at the new level in the same way.
    let analysis = Analysis {
        flags: entry.rule_flags.clone(),
        known_safe: entry.known_safe,
        ..Analysis::default()
    };
    let context = DecisionContext {
        analysis: &analysis,
        declarations: &entry.declarations,
        has_user_request: !entry.user_request.trim().is_empty(),
    };
    let verdict = verdict_of(record);
    decide_learned(
        &verdict,
        &context,
        &Learned {
            thresholds,
            pattern: None,
        },
    )
    .ask_owner
}

fn verdict_of(record: &DecisionRecord) -> BouncerVerdict {
    if record.entry.model_facts.is_empty() {
        BouncerVerdict::Unavailable("no model answer in the log".to_owned())
    } else {
        BouncerVerdict::Scored {
            facts: record
                .entry
                .model_facts
                .iter()
                .map(|(name, probability)| Fact {
                    name: name.clone(),
                    probability: *probability,
                })
                .collect(),
            model: None,
        }
    }
}

/// An owner decision where the model step decides: model answers, no rule flag, no
/// production item, a user request, and declarations.
fn owner_model_step(record: &DecisionRecord) -> bool {
    let entry = &record.entry;
    if entry.decided_by != DecidedBy::Owner || entry.model_facts.is_empty() || entry.grant_asks {
        return false;
    }
    let analysis = Analysis {
        flags: entry.rule_flags.clone(),
        known_safe: entry.known_safe,
        ..Analysis::default()
    };
    before_model(&DecisionContext {
        analysis: &analysis,
        declarations: &entry.declarations,
        has_user_request: !entry.user_request.trim().is_empty(),
    })
    .is_none()
}

fn level(hundredths: u32) -> Thresholds {
    Thresholds {
        task_match: f64::from(hundredths) / 100.0,
    }
}

fn hundredths(value: f64) -> u32 {
    // The level is in [0.5, 0.8], so the cast cannot overflow.
    (value.clamp(0.0, 1.0) * 100.0).round() as u32
}

/// Propose a `task_match` level from the decision log (oldest first).
pub fn propose(records: &[DecisionRecord], current: Thresholds) -> Proposal {
    let current_level = hundredths(current.task_match_level());
    let floor = hundredths(CALIBRATION_FLOOR);
    let reached = reached(records);
    let (fit, _) = split(&reached);
    let fit_owner_decisions = fit.iter().filter(|record| owner_model_step(record)).count();
    if fit_owner_decisions < MIN_OWNER_DECISIONS {
        let mut proposal = evaluate(records, current, current);
        proposal.reason = format!(
            "Not enough owner decisions at the model step: {fit_owner_decisions} of {MIN_OWNER_DECISIONS} in the older part of the log."
        );
        return proposal;
    }
    let mut proposed = current_level;
    let mut gained = replay(fit, level(current_level)).approvals_allowed;
    let mut candidate = current_level;
    while candidate >= floor + STEP {
        candidate -= STEP;
        let at = replay(fit, level(candidate));
        let margin = replay(fit, level(candidate.saturating_sub(MARGIN).max(floor)));
        if at.denied_allowed > 0 || margin.denied_allowed > 0 {
            break;
        }
        if at.approvals_allowed > gained {
            gained = at.approvals_allowed;
            proposed = candidate;
        }
    }
    let mut proposal = evaluate(records, current, level(proposed));
    if proposed == current_level {
        proposal.reason =
            "No lower level lets more owner approvals run without a denial.".to_owned();
    }
    proposal
}

/// Replay numbers for one level: the held-out part before and after, and the gate on
/// all past decisions. `valid` is true when the level is lower than the current level
/// and the gate allows no owner denial.
pub fn evaluate(records: &[DecisionRecord], current: Thresholds, wanted: Thresholds) -> Proposal {
    let current_level = hundredths(current.task_match_level());
    let wanted_level = hundredths(wanted.task_match_level());
    let reached = reached(records);
    let (fit, held) = split(&reached);
    let all_after = replay(&reached, level(wanted_level));
    let valid = wanted_level < current_level && all_after.denied_allowed == 0;
    let reason = if all_after.denied_allowed > 0 {
        format!(
            "The replay on all past decisions allows {} request(s) that the owner denied.",
            all_after.denied_allowed
        )
    } else {
        format!(
            "The replay on all {} past decisions allows no request that the owner denied.",
            all_after.decisions
        )
    };
    Proposal {
        current: f64::from(current_level) / 100.0,
        proposed: f64::from(wanted_level) / 100.0,
        decisions: reached.len(),
        owner_decisions: reached
            .iter()
            .filter(|record| record.entry.decided_by == DecidedBy::Owner)
            .count(),
        owner_denials: reached
            .iter()
            .filter(|record| record.entry.owner_denied())
            .count(),
        fit_decisions: fit.len(),
        fit_owner_decisions: fit.iter().filter(|record| owner_model_step(record)).count(),
        held_out_decisions: held.len(),
        held_out_before: replay(held, level(current_level)),
        held_out_after: replay(held, level(wanted_level)),
        all_after,
        valid,
        reason,
    }
}

fn reached(records: &[DecisionRecord]) -> Vec<DecisionRecord> {
    records
        .iter()
        .filter(|record| record.entry.decided_by.reached_bouncer())
        .cloned()
        .collect()
}

/// Older part and newer part, split by time. The log is oldest first.
fn split(records: &[DecisionRecord]) -> (&[DecisionRecord], &[DecisionRecord]) {
    let held_out = ((records.len() as f64) * HELD_OUT_SHARE).ceil() as usize;
    records.split_at(records.len() - held_out.min(records.len()))
}

/// The owner applies a level. Apassy computes the proposal and the gate again at this
/// time, so a denial that came after the proposal also counts. A lower level must be
/// at or above a valid proposal. A higher level is stricter and needs no gate. The
/// production rule, the rule flags, and the hard rules do not change.
pub fn apply(vault: &mut Vault, task_match: f64, now: u64) -> Result<Proposal, String> {
    if !(CALIBRATION_FLOOR..=CALIBRATION_CEILING).contains(&task_match) {
        return Err(format!(
            "The level must be from {:.0}% to {:.0}%.",
            CALIBRATION_FLOOR * 100.0,
            CALIBRATION_CEILING * 100.0
        ));
    }
    let records = vault.decision_log().map_err(vault_message)?;
    let current = Thresholds {
        task_match: vault
            .calibration()
            .map_err(vault_message)?
            .map_or(DEFAULT_TASK_MATCH, |calibration| calibration.task_match),
    };
    let wanted = level(hundredths(task_match));
    let report = evaluate(&records, current, wanted);
    if report.all_after.denied_allowed > 0 {
        return Err(format!("Not applied. {}", report.reason));
    }
    if report.proposed < report.current {
        let proposal = propose(&records, current);
        if !proposal.valid || report.proposed < proposal.proposed {
            return Err(format!(
                "Not applied. The lowest level that the replay supports now is {:.0}%. {}",
                proposal.proposed * 100.0,
                proposal.reason
            ));
        }
    }
    let text = serde_json::to_string(&report).unwrap_or_default();
    vault
        .apply_calibration(report.proposed, &text, now)
        .map_err(vault_message)?;
    Ok(report)
}

/// Go back to the default level. A stricter level needs no replay gate.
pub fn reset(vault: &mut Vault, now: u64) -> Result<(), String> {
    vault
        .apply_calibration(CALIBRATION_CEILING, "{\"reset\":true}", now)
        .map_err(vault_message)
}

fn vault_message(err: crate::vault::VaultError) -> String {
    match err.kind() {
        VaultErrorKind::Locked => "The vault is locked.".to_owned(),
        _ => "The vault did not store the calibration.".to_owned(),
    }
}
