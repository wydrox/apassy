//! Candidate models, shadow mode, and model promotion (schema v9, ADR 0010, goal items
//! B9 and B10).
//!
//! - A local fine-tune gives a candidate model. The candidate starts in shadow mode. The
//!   broker asks it in parallel at the model step, and the answer has no effect. A newer
//!   candidate replaces the candidate in shadow mode.
//! - Each shadow answer is one row: the candidate outcome (run, ask, or no answer), the
//!   real outcome of the request (run or ask), and the owner decision when the owner
//!   decided. A row has no request data. It has the model answers as probabilities.
//! - A promotion makes the candidate the active model of the bouncer. It needs 100
//!   shadow decisions of the owner, 95% agreement, and no owner denial that the
//!   candidate would allow (`CandidateAgreement::can_promote`). Only the owner promotes,
//!   with a fresh owner check (`broker::shadow::promote`). A rollback returns to the
//!   model before the promotion. Each change goes to the activity log in the same
//!   transaction.

use rusqlite::{OptionalExtension, Row, TransactionBehavior};
use serde_json::{Map, Value, json};

use super::agents::{
    ActivityDecision, MAX_ACTIVITY_REASON_BYTES, MAX_ACTIVITY_ROWS, MAX_OPERATION_BYTES,
};
use super::learning::CandidateAgreement;
use super::types::{VaultErrorKind, VaultResult, err};
use super::{Vault, to_public_id, to_sql_id};

/// Tables added in schema version 9: candidate models, shadow answers, and the history
/// of the active model.
pub(super) const SCHEMA_V9_SQL: &str = "
CREATE TABLE model_candidate (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    version TEXT NOT NULL,
    url TEXT NOT NULL,
    checkpoint TEXT NOT NULL,
    checkpoint_sha256 TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('shadow', 'promoted', 'replaced', 'rolled_back')),
    ended_at INTEGER,
    report TEXT NOT NULL
);
CREATE TABLE shadow_decision (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    candidate_id INTEGER NOT NULL,
    at INTEGER NOT NULL,
    real_outcome TEXT NOT NULL CHECK (real_outcome IN ('run', 'ask')),
    candidate_outcome TEXT NOT NULL CHECK (candidate_outcome IN ('run', 'ask', 'no_answer')),
    owner_decision TEXT NOT NULL CHECK (owner_decision IN ('allow', 'deny', 'none')),
    facts TEXT NOT NULL
);
CREATE INDEX shadow_decision_candidate ON shadow_decision(candidate_id);
CREATE TABLE model_activation (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at INTEGER NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('promote', 'rollback')),
    version TEXT NOT NULL,
    url TEXT NOT NULL,
    candidate_id INTEGER,
    previous_version TEXT NOT NULL,
    previous_url TEXT NOT NULL,
    report TEXT NOT NULL
);
UPDATE vault_meta SET schema_version = 9 WHERE id = 1;
PRAGMA user_version = 9;
";

pub(super) const SCHEMA_V9_COLUMNS: [&str; 3] = [
    "SELECT id, version, url, checkpoint, checkpoint_sha256, created_at, state, ended_at,
            report FROM model_candidate LIMIT 0",
    "SELECT id, candidate_id, at, real_outcome, candidate_outcome, owner_decision, facts
            FROM shadow_decision LIMIT 0",
    "SELECT id, at, action, version, url, candidate_id, previous_version, previous_url, report
            FROM model_activation LIMIT 0",
];

/// Candidates that the vault keeps. At the limit, the oldest candidate that is not in
/// shadow mode and not active goes, with its shadow rows.
pub const MAX_CANDIDATES: usize = 50;
/// Shadow rows that the vault keeps, newest first.
pub const MAX_SHADOW_ROWS: usize = 20_000;
/// Activations (promotions and rollbacks) that the vault keeps, newest first.
pub const MAX_ACTIVATIONS: usize = 100;
/// Longest model version. The same limit as the version in the activity log.
pub const MAX_MODEL_VERSION: usize = 64;
const MAX_URL_BYTES: usize = 200;
const MAX_PATH_BYTES: usize = 4096;
const MAX_REPORT_BYTES: usize = 8192;
/// A prune reads the table, so it runs once every this many rows.
const PRUNE_EVERY: u64 = 64;

const CANDIDATE_COLUMNS: &str =
    "id, version, url, checkpoint, checkpoint_sha256, created_at, state, ended_at, report";
const ACTIVATION_COLUMNS: &str =
    "id, at, action, version, url, candidate_id, previous_version, previous_url, report";

/// A model version is short and has only ASCII letters, digits, and `.`, `_`, `+`, `-`.
pub fn valid_model_version(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_MODEL_VERSION
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'))
}

/// Where a candidate is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateState {
    /// The broker asks the candidate in parallel. Its answers have no effect.
    Shadow,
    /// The owner promoted the candidate. It is or was the active model.
    Promoted,
    /// A newer candidate took its place before a promotion.
    Replaced,
    /// The owner promoted the candidate and then rolled it back.
    RolledBack,
}

impl CandidateState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Shadow => "shadow",
            Self::Promoted => "promoted",
            Self::Replaced => "replaced",
            Self::RolledBack => "rolled_back",
        }
    }

    fn parse(text: &str) -> VaultResult<Self> {
        match text {
            "shadow" => Ok(Self::Shadow),
            "promoted" => Ok(Self::Promoted),
            "replaced" => Ok(Self::Replaced),
            "rolled_back" => Ok(Self::RolledBack),
            _ => Err(err(VaultErrorKind::Storage)),
        }
    }
}

/// A candidate model from a local fine-tune.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewCandidate {
    /// The version that the model server reports, for example `apassy-local-v1+1a2b3c4d`.
    pub version: String,
    /// The loopback address of the candidate server.
    pub url: String,
    /// The checkpoint file on this computer.
    pub checkpoint: String,
    pub checkpoint_sha256: String,
    /// Training numbers as JSON: time, memory, and example counts. No request data.
    pub report: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateRecord {
    pub id: u64,
    pub version: String,
    pub url: String,
    pub checkpoint: String,
    pub checkpoint_sha256: String,
    /// Unix time of the registration. Shadow mode starts at this time.
    pub created_at: u64,
    pub state: CandidateState,
    /// Unix time of the promotion, the replacement, or the rollback.
    pub ended_at: Option<u64>,
    pub report: String,
}

/// What the broker did with a request that reached the model step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RealOutcome {
    /// The request ran without the owner.
    Run,
    /// The request waited for the owner.
    Ask,
}

impl RealOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Run => "run",
            Self::Ask => "ask",
        }
    }
}

/// What the candidate would do with the same policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShadowAnswer {
    Run,
    Ask,
    /// The candidate server did not answer, or it answered with another model version.
    NoAnswer,
}

impl ShadowAnswer {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Run => "run",
            Self::Ask => "ask",
            Self::NoAnswer => "no_answer",
        }
    }
}

/// The owner decision on the request, when the owner decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerLabel {
    Allow,
    Deny,
    /// The request ran without the owner, or the owner did not answer in time.
    None,
}

impl OwnerLabel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::None => "none",
        }
    }
}

/// One shadow answer. No request data.
#[derive(Debug, Clone, PartialEq)]
pub struct ShadowEntry {
    pub candidate_id: u64,
    pub at: u64,
    pub real: RealOutcome,
    pub candidate: ShadowAnswer,
    pub owner: OwnerLabel,
    /// The candidate answers by name, each a probability. Empty without an answer.
    pub facts: Vec<(String, f64)>,
}

/// The shadow numbers of one candidate.
#[derive(Debug, Clone, PartialEq)]
pub struct ShadowSummary {
    /// Agreement with the owner. Only rows with an owner decision and a candidate
    /// answer count.
    pub agreement: CandidateAgreement,
    /// Requests that reached the model step while the candidate was in shadow mode.
    pub requests: u32,
    /// Requests where the candidate did not answer.
    pub no_answer: u32,
    /// Requests where the candidate gave the same outcome as the active model.
    pub same_as_active: u32,
}

/// A change of the active model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationAction {
    Promote,
    Rollback,
}

impl ActivationAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Promote => "promote",
            Self::Rollback => "rollback",
        }
    }

    fn parse(text: &str) -> VaultResult<Self> {
        match text {
            "promote" => Ok(Self::Promote),
            "rollback" => Ok(Self::Rollback),
            _ => Err(err(VaultErrorKind::Storage)),
        }
    }
}

/// One promotion or rollback. The newest row names the active model. An empty version
/// and address mean the default bouncer (`APASSY_BOUNCER_URL`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelActivation {
    pub id: u64,
    pub at: u64,
    pub action: ActivationAction,
    pub version: String,
    pub url: String,
    pub candidate_id: Option<u64>,
    pub previous_version: String,
    pub previous_url: String,
    /// Shadow numbers at the time of the change, as JSON.
    pub report: String,
}

impl ModelActivation {
    /// The row names the default bouncer.
    pub fn is_default(&self) -> bool {
        self.url.is_empty()
    }
}

/// Text for the owner: the model version, or the default bouncer.
pub fn model_label(version: &str) -> String {
    if version.is_empty() {
        "the default model".to_owned()
    } else {
        version.to_owned()
    }
}

impl Vault {
    /// Register a candidate from a local fine-tune. It starts in shadow mode. A candidate
    /// that is still in shadow mode is replaced.
    pub fn register_candidate(
        &mut self,
        candidate: &NewCandidate,
        now: u64,
    ) -> VaultResult<CandidateRecord> {
        let sha_ok = candidate.checkpoint_sha256.len() == 64
            && candidate
                .checkpoint_sha256
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase());
        if !valid_model_version(&candidate.version)
            || !candidate.url.starts_with("http://")
            || candidate.url.len() > MAX_URL_BYTES
            || candidate.checkpoint.is_empty()
            || candidate.checkpoint.len() > MAX_PATH_BYTES
            || candidate.checkpoint.contains('\0')
            || !sha_ok
            || candidate.report.len() > MAX_REPORT_BYTES
        {
            return Err(err(VaultErrorKind::InvalidInput));
        }
        let at = to_sql_time(now)?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        tx.execute(
            "UPDATE model_candidate SET state = 'replaced', ended_at = ?1 WHERE state = 'shadow'",
            [at],
        )
        .map_err(|_| err(VaultErrorKind::Storage))?;
        tx.execute(
            "INSERT INTO model_candidate (version, url, checkpoint, checkpoint_sha256,
                 created_at, state, ended_at, report)
             VALUES (?1, ?2, ?3, ?4, ?5, 'shadow', NULL, ?6)",
            rusqlite::params![
                candidate.version,
                candidate.url,
                candidate.checkpoint,
                candidate.checkpoint_sha256,
                at,
                candidate.report,
            ],
        )
        .map_err(|_| err(VaultErrorKind::Storage))?;
        let id = tx.last_insert_rowid();
        prune_candidates(&tx)?;
        let record = find_candidate(&tx, id)?.ok_or_else(|| err(VaultErrorKind::Storage))?;
        tx.commit().map_err(|_| err(VaultErrorKind::Storage))?;
        Ok(record)
    }

    /// The candidate in shadow mode, if there is one.
    pub fn shadow_candidate(&self) -> VaultResult<Option<CandidateRecord>> {
        let conn = self.conn_ref()?;
        conn.query_row(
            &format!(
                "SELECT {CANDIDATE_COLUMNS} FROM model_candidate WHERE state = 'shadow'
                 ORDER BY id DESC LIMIT 1"
            ),
            [],
            candidate_row,
        )
        .optional()
        .map_err(|_| err(VaultErrorKind::Storage))?
        .map(candidate_from)
        .transpose()
    }

    pub fn candidate(&self, id: u64) -> VaultResult<Option<CandidateRecord>> {
        find_candidate(self.conn_ref()?, to_sql_id(id)?)
    }

    /// Candidates, newest first.
    pub fn candidates(&self, limit: usize) -> VaultResult<Vec<CandidateRecord>> {
        let limit = i64::try_from(limit).map_err(|_| err(VaultErrorKind::InvalidInput))?;
        let conn = self.conn_ref()?;
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {CANDIDATE_COLUMNS} FROM model_candidate ORDER BY id DESC LIMIT ?1"
            ))
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let rows = stmt
            .query_map([limit], candidate_row)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(candidate_from(
                row.map_err(|_| err(VaultErrorKind::Storage))?,
            )?);
        }
        Ok(out)
    }

    /// Store one shadow answer. Returns false when the candidate is no longer in shadow
    /// mode. Then nothing is stored.
    pub fn record_shadow(&mut self, entry: &ShadowEntry) -> VaultResult<bool> {
        let candidate = to_sql_id(entry.candidate_id)?;
        let at = to_sql_time(entry.at)?;
        let facts: Map<String, Value> = entry
            .facts
            .iter()
            .filter(|(_, p)| p.is_finite())
            .map(|(name, p)| (name.clone(), json!(p)))
            .collect();
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let stored = tx
            .execute(
                "INSERT INTO shadow_decision (candidate_id, at, real_outcome, candidate_outcome,
                     owner_decision, facts)
                 SELECT ?1, ?2, ?3, ?4, ?5, ?6
                 WHERE EXISTS (SELECT 1 FROM model_candidate WHERE id = ?1 AND state = 'shadow')",
                rusqlite::params![
                    candidate,
                    at,
                    entry.real.as_str(),
                    entry.candidate.as_str(),
                    entry.owner.as_str(),
                    Value::Object(facts).to_string(),
                ],
            )
            .map_err(|_| err(VaultErrorKind::Storage))?;
        if stored > 0 {
            let id = to_public_id(tx.last_insert_rowid())?;
            if id % PRUNE_EVERY == 0 {
                tx.execute(
                    "DELETE FROM shadow_decision WHERE id IN (
                         SELECT id FROM shadow_decision ORDER BY id DESC LIMIT -1 OFFSET ?1)",
                    [i64::try_from(MAX_SHADOW_ROWS).map_err(|_| err(VaultErrorKind::Storage))?],
                )
                .map_err(|_| err(VaultErrorKind::Storage))?;
            }
        }
        tx.commit().map_err(|_| err(VaultErrorKind::Storage))?;
        Ok(stored > 0)
    }

    /// The shadow numbers of one candidate.
    pub fn shadow_summary(&self, candidate_id: u64) -> VaultResult<ShadowSummary> {
        let candidate = self
            .candidate(candidate_id)?
            .ok_or_else(|| err(VaultErrorKind::NotFound))?;
        let counts: [i64; 6] = self
            .conn_ref()?
            .query_row(
                "SELECT COUNT(*),
                     COALESCE(SUM(candidate_outcome = 'no_answer'), 0),
                     COALESCE(SUM(candidate_outcome != 'no_answer' AND owner_decision != 'none'), 0),
                     COALESCE(SUM((candidate_outcome = 'run' AND owner_decision = 'allow')
                         OR (candidate_outcome = 'ask' AND owner_decision = 'deny')), 0),
                     COALESCE(SUM(candidate_outcome = 'run' AND owner_decision = 'deny'), 0),
                     COALESCE(SUM(candidate_outcome = real_outcome), 0)
                 FROM shadow_decision WHERE candidate_id = ?1",
                [to_sql_id(candidate_id)?],
                |row| {
                    Ok([
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ])
                },
            )
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let count = |n: i64| u32::try_from(n).map_err(|_| err(VaultErrorKind::Storage));
        Ok(ShadowSummary {
            agreement: CandidateAgreement {
                model_version: candidate.version,
                started_at: candidate.created_at,
                shadow_decisions: count(counts[2])?,
                agreed: count(counts[3])?,
                allowed_owner_denials: count(counts[4])?,
            },
            requests: count(counts[0])?,
            no_answer: count(counts[1])?,
            same_as_active: count(counts[5])?,
        })
    }

    /// Owner decisions and owner denials in the decision log, for the training gate in
    /// the Learning view (ADR 0010). `broker::finetune::gate` counts the same rows.
    pub fn owner_decision_counts(&self) -> VaultResult<(u32, u32)> {
        let (decisions, denials): (i64, i64) = self
            .conn_ref()?
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(decision = 'deny'), 0)
                 FROM decision_log WHERE decided_by = 'owner'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let count = |n: i64| u32::try_from(n).map_err(|_| err(VaultErrorKind::Storage));
        Ok((count(decisions)?, count(denials)?))
    }

    /// The newest promotion or rollback. `None` means that the default bouncer is active
    /// and no promotion happened.
    pub fn active_model(&self) -> VaultResult<Option<ModelActivation>> {
        Ok(self.model_activations(1)?.into_iter().next())
    }

    /// Promotions and rollbacks, newest first.
    pub fn model_activations(&self, limit: usize) -> VaultResult<Vec<ModelActivation>> {
        let limit = i64::try_from(limit).map_err(|_| err(VaultErrorKind::InvalidInput))?;
        let conn = self.conn_ref()?;
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {ACTIVATION_COLUMNS} FROM model_activation ORDER BY id DESC LIMIT ?1"
            ))
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let rows = stmt
            .query_map([limit], activation_row)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(activation_from(
                row.map_err(|_| err(VaultErrorKind::Storage))?,
            )?);
        }
        Ok(out)
    }

    /// Make a candidate in shadow mode the active model, and record it in the activity
    /// log, in one transaction. The shadow gate of ADR 0010 is checked here again with
    /// the rows of this session. Only `broker::shadow::promote` calls this, after it
    /// checks the owner proof.
    pub(crate) fn promote_candidate(
        &mut self,
        candidate_id: u64,
        now: u64,
    ) -> VaultResult<ModelActivation> {
        let candidate = self
            .candidate(candidate_id)?
            .ok_or_else(|| err(VaultErrorKind::NotFound))?;
        if candidate.state != CandidateState::Shadow {
            return Err(err(VaultErrorKind::InvalidInput));
        }
        let summary = self.shadow_summary(candidate_id)?;
        if !summary.agreement.can_promote() {
            return Err(err(VaultErrorKind::InvalidInput));
        }
        let previous = self.active_model()?;
        let (previous_version, previous_url) = previous
            .map(|active| (active.version, active.url))
            .unwrap_or_default();
        let agreement = &summary.agreement;
        let report = json!({
            "shadow_decisions": agreement.shadow_decisions,
            "agreed": agreement.agreed,
            "allowed_owner_denials": agreement.allowed_owner_denials,
            "requests": summary.requests,
            "no_answer": summary.no_answer,
        })
        .to_string();
        let reason = format!(
            "The owner promoted model {} (candidate {candidate_id}). Before: {}. Shadow mode: {} owner decisions, agreement {:.1}%, {} owner denials that it would allow.",
            candidate.version,
            model_label(&previous_version),
            agreement.shadow_decisions,
            agreement.agreement().unwrap_or(0.0) * 100.0,
            agreement.allowed_owner_denials,
        );
        let at = to_sql_time(now)?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        tx.execute(
            "INSERT INTO model_activation (at, action, version, url, candidate_id,
                 previous_version, previous_url, report)
             VALUES (?1, 'promote', ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                at,
                candidate.version,
                candidate.url,
                to_sql_id(candidate_id)?,
                previous_version,
                previous_url,
                report,
            ],
        )
        .map_err(|_| err(VaultErrorKind::Storage))?;
        let id = tx.last_insert_rowid();
        tx.execute(
            "UPDATE model_candidate SET state = 'promoted', ended_at = ?1 WHERE id = ?2",
            (at, to_sql_id(candidate_id)?),
        )
        .map_err(|_| err(VaultErrorKind::Storage))?;
        finish_activation(&tx, at, "promote model", &reason)?;
        let activation = find_activation(&tx, id)?.ok_or_else(|| err(VaultErrorKind::Storage))?;
        tx.commit().map_err(|_| err(VaultErrorKind::Storage))?;
        Ok(activation)
    }

    /// Return to the model before the newest promotion, and record it in the activity
    /// log, in one transaction. `activation_id` must be the newest row, and it must be a
    /// promotion. Only `broker::shadow::roll_back` calls this, after it checks the owner
    /// proof.
    pub(crate) fn roll_back_model(
        &mut self,
        activation_id: u64,
        now: u64,
    ) -> VaultResult<ModelActivation> {
        let active = self
            .active_model()?
            .ok_or_else(|| err(VaultErrorKind::NotFound))?;
        if active.id != activation_id || active.action != ActivationAction::Promote {
            return Err(err(VaultErrorKind::InvalidInput));
        }
        let reason = format!(
            "The owner rolled back model {} to {}.",
            model_label(&active.version),
            model_label(&active.previous_version)
        );
        let at = to_sql_time(now)?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        tx.execute(
            "INSERT INTO model_activation (at, action, version, url, candidate_id,
                 previous_version, previous_url, report)
             VALUES (?1, 'rollback', ?2, ?3, ?4, ?5, ?6, '{}')",
            rusqlite::params![
                at,
                active.previous_version,
                active.previous_url,
                active.candidate_id.map(to_sql_id).transpose()?,
                active.version,
                active.url,
            ],
        )
        .map_err(|_| err(VaultErrorKind::Storage))?;
        let id = tx.last_insert_rowid();
        if let Some(candidate) = active.candidate_id {
            tx.execute(
                "UPDATE model_candidate SET state = 'rolled_back', ended_at = ?1 WHERE id = ?2",
                (at, to_sql_id(candidate)?),
            )
            .map_err(|_| err(VaultErrorKind::Storage))?;
        }
        finish_activation(&tx, at, "roll back model", &reason)?;
        let activation = find_activation(&tx, id)?.ok_or_else(|| err(VaultErrorKind::Storage))?;
        tx.commit().map_err(|_| err(VaultErrorKind::Storage))?;
        Ok(activation)
    }
}

/// The activity entry of a model change, and the limits of both tables.
fn finish_activation(
    tx: &rusqlite::Transaction<'_>,
    at: i64,
    operation: &str,
    reason: &str,
) -> VaultResult<()> {
    tx.execute(
        "INSERT INTO activity (at, agent_id, agent_name, item_id, operation, decision, reason)
         VALUES (?1, NULL, 'Owner', NULL, ?2, ?3, ?4)",
        rusqlite::params![
            at,
            cut(operation, MAX_OPERATION_BYTES),
            ActivityDecision::Allow.as_str(),
            cut(reason, MAX_ACTIVITY_REASON_BYTES),
        ],
    )
    .map_err(|_| err(VaultErrorKind::Storage))?;
    tx.execute(
        "DELETE FROM activity WHERE id NOT IN
         (SELECT id FROM activity ORDER BY id DESC LIMIT ?1)",
        [i64::try_from(MAX_ACTIVITY_ROWS).map_err(|_| err(VaultErrorKind::Storage))?],
    )
    .map_err(|_| err(VaultErrorKind::Storage))?;
    tx.execute(
        "DELETE FROM model_activation WHERE id IN (
             SELECT id FROM model_activation ORDER BY id DESC LIMIT -1 OFFSET ?1)",
        [i64::try_from(MAX_ACTIVATIONS).map_err(|_| err(VaultErrorKind::Storage))?],
    )
    .map_err(|_| err(VaultErrorKind::Storage))?;
    Ok(())
}

/// Keep the newest candidates. A candidate in shadow mode and the candidate of the
/// newest activation stay.
fn prune_candidates(tx: &rusqlite::Transaction<'_>) -> VaultResult<()> {
    let keep = i64::try_from(MAX_CANDIDATES).map_err(|_| err(VaultErrorKind::Storage))?;
    let old: Vec<i64> = {
        let mut stmt = tx
            .prepare(
                "SELECT id FROM model_candidate
                 WHERE state != 'shadow'
                   AND id NOT IN (SELECT candidate_id FROM model_activation
                                  WHERE candidate_id IS NOT NULL
                                  ORDER BY id DESC LIMIT 1)
                   AND id NOT IN (SELECT id FROM model_candidate ORDER BY id DESC LIMIT ?1)",
            )
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let rows = stmt
            .query_map([keep], |row| row.get::<_, i64>(0))
            .map_err(|_| err(VaultErrorKind::Storage))?;
        rows.collect::<Result<_, _>>()
            .map_err(|_| err(VaultErrorKind::Storage))?
    };
    for id in old {
        tx.execute("DELETE FROM shadow_decision WHERE candidate_id = ?1", [id])
            .map_err(|_| err(VaultErrorKind::Storage))?;
        tx.execute("DELETE FROM model_candidate WHERE id = ?1", [id])
            .map_err(|_| err(VaultErrorKind::Storage))?;
    }
    Ok(())
}

type CandidateRow = (
    i64,
    String,
    String,
    String,
    String,
    i64,
    String,
    Option<i64>,
    String,
);

fn candidate_row(row: &Row<'_>) -> rusqlite::Result<CandidateRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
    ))
}

fn candidate_from(row: CandidateRow) -> VaultResult<CandidateRecord> {
    let (id, version, url, checkpoint, checkpoint_sha256, created_at, state, ended_at, report) =
        row;
    Ok(CandidateRecord {
        id: to_public_id(id)?,
        version,
        url,
        checkpoint,
        checkpoint_sha256,
        created_at: from_sql_time(created_at)?,
        state: CandidateState::parse(&state)?,
        ended_at: ended_at.map(from_sql_time).transpose()?,
        report,
    })
}

fn find_candidate(conn: &rusqlite::Connection, id: i64) -> VaultResult<Option<CandidateRecord>> {
    conn.query_row(
        &format!("SELECT {CANDIDATE_COLUMNS} FROM model_candidate WHERE id = ?1"),
        [id],
        candidate_row,
    )
    .optional()
    .map_err(|_| err(VaultErrorKind::Storage))?
    .map(candidate_from)
    .transpose()
}

type ActivationRow = (
    i64,
    i64,
    String,
    String,
    String,
    Option<i64>,
    String,
    String,
    String,
);

fn activation_row(row: &Row<'_>) -> rusqlite::Result<ActivationRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
    ))
}

fn activation_from(row: ActivationRow) -> VaultResult<ModelActivation> {
    let (id, at, action, version, url, candidate_id, previous_version, previous_url, report) = row;
    Ok(ModelActivation {
        id: to_public_id(id)?,
        at: from_sql_time(at)?,
        action: ActivationAction::parse(&action)?,
        version,
        url,
        candidate_id: candidate_id.map(to_public_id).transpose()?,
        previous_version,
        previous_url,
        report,
    })
}

fn find_activation(conn: &rusqlite::Connection, id: i64) -> VaultResult<Option<ModelActivation>> {
    conn.query_row(
        &format!("SELECT {ACTIVATION_COLUMNS} FROM model_activation WHERE id = ?1"),
        [id],
        activation_row,
    )
    .optional()
    .map_err(|_| err(VaultErrorKind::Storage))?
    .map(activation_from)
    .transpose()
}

/// Without control characters, cut at a character boundary.
fn cut(text: &str, max: usize) -> String {
    let clean: String = text.chars().filter(|c| !c.is_control()).collect();
    if clean.len() <= max {
        return clean;
    }
    let mut end = max;
    while !clean.is_char_boundary(end) {
        end -= 1;
    }
    clean[..end].to_owned()
}

fn to_sql_time(at: u64) -> VaultResult<i64> {
    i64::try_from(at).map_err(|_| err(VaultErrorKind::Storage))
}

fn from_sql_time(at: i64) -> VaultResult<u64> {
    u64::try_from(at).map_err(|_| err(VaultErrorKind::Storage))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASS: &str = "candidate-unit-pass";
    const SHA: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn temp_vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::TempDir::new().expect("dir");
        let mut vault = Vault::create(&dir.path().join("candidate.db"), PASS).expect("create");
        vault.unlock(PASS).expect("unlock");
        (dir, vault)
    }

    fn new_candidate(version: &str) -> NewCandidate {
        NewCandidate {
            version: version.to_owned(),
            url: "http://127.0.0.1:8775".to_owned(),
            checkpoint: "/tmp/candidate.safetensors".to_owned(),
            checkpoint_sha256: SHA.to_owned(),
            report: "{}".to_owned(),
        }
    }

    fn shadow(vault: &mut Vault, candidate: u64, answer: ShadowAnswer, owner: OwnerLabel) -> bool {
        vault
            .record_shadow(&ShadowEntry {
                candidate_id: candidate,
                at: 1_790_000_000,
                real: RealOutcome::Ask,
                candidate: answer,
                owner,
                facts: vec![("task_match".to_owned(), 0.9)],
            })
            .expect("shadow")
    }

    /// A new candidate replaces the candidate in shadow mode. Its rows stop counting.
    #[test]
    fn a_new_candidate_replaces_the_shadow_candidate() {
        let (_dir, mut vault) = temp_vault();
        let first = vault
            .register_candidate(&new_candidate("apassy-local-v1+aaaaaaaa"), 10)
            .expect("first");
        assert_eq!(first.state, CandidateState::Shadow);
        assert!(shadow(
            &mut vault,
            first.id,
            ShadowAnswer::Run,
            OwnerLabel::Allow
        ));
        let second = vault
            .register_candidate(&new_candidate("apassy-local-v1+bbbbbbbb"), 20)
            .expect("second");
        assert_eq!(
            vault.shadow_candidate().expect("read").map(|c| c.id),
            Some(second.id)
        );
        let first = vault.candidate(first.id).expect("read").expect("first");
        assert_eq!(first.state, CandidateState::Replaced);
        assert_eq!(first.ended_at, Some(20));
        assert!(
            !shadow(&mut vault, first.id, ShadowAnswer::Run, OwnerLabel::Allow),
            "a replaced candidate gets no rows"
        );
        assert_eq!(vault.shadow_summary(first.id).expect("summary").requests, 1);
    }

    #[test]
    fn a_candidate_needs_a_valid_version_address_and_digest() {
        let (_dir, mut vault) = temp_vault();
        for bad in [
            NewCandidate {
                version: "a b".to_owned(),
                ..new_candidate("x")
            },
            NewCandidate {
                version: "v".repeat(MAX_MODEL_VERSION + 1),
                ..new_candidate("x")
            },
            NewCandidate {
                url: "https://example.com".to_owned(),
                ..new_candidate("x")
            },
            NewCandidate {
                checkpoint_sha256: "ABC".to_owned(),
                ..new_candidate("x")
            },
            NewCandidate {
                checkpoint: String::new(),
                ..new_candidate("x")
            },
        ] {
            assert_eq!(
                vault.register_candidate(&bad, 1).unwrap_err().kind(),
                VaultErrorKind::InvalidInput,
                "{bad:?}"
            );
        }
        assert!(vault.shadow_candidate().expect("read").is_none());
    }

    /// Agreement counts only owner decisions with a candidate answer. A run of an owner
    /// denial is an allowed denial.
    #[test]
    fn shadow_summary_counts_agreement_with_the_owner() {
        let (_dir, mut vault) = temp_vault();
        let candidate = vault
            .register_candidate(&new_candidate("apassy-local-v1+cccccccc"), 1)
            .expect("candidate");
        let rows = [
            (ShadowAnswer::Run, OwnerLabel::Allow),
            (ShadowAnswer::Ask, OwnerLabel::Deny),
            (ShadowAnswer::Ask, OwnerLabel::Allow),
            (ShadowAnswer::Run, OwnerLabel::Deny),
            (ShadowAnswer::NoAnswer, OwnerLabel::Deny),
            (ShadowAnswer::Run, OwnerLabel::None),
        ];
        for (answer, owner) in rows {
            assert!(shadow(&mut vault, candidate.id, answer, owner));
        }
        let summary = vault.shadow_summary(candidate.id).expect("summary");
        assert_eq!(summary.requests, 6);
        assert_eq!(summary.no_answer, 1);
        assert_eq!(summary.agreement.shadow_decisions, 4);
        assert_eq!(summary.agreement.agreed, 2);
        assert_eq!(summary.agreement.allowed_owner_denials, 1);
        // The real outcome of every row is "ask".
        assert_eq!(summary.same_as_active, 2);
        assert!(!summary.agreement.can_promote());
    }
}
