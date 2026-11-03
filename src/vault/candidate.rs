//! Candidate models, shadow mode, and model promotion (schema v9, ADR 0010, goal items
//! B9 and B10).
//!
//! - A local fine-tune (or a remote training job, schema 29) gives a candidate model: a
//!   head set whose file is on this Mac. The candidate starts in shadow mode. Its hash
//!   rides in each request of the active model as `shadow_heads` (ADR 0035, contract
//!   bouncer-brain-v1 section 3), and the answer has no effect. It answers only on the
//!   host that has its head file (`uploaded_to`). A newer candidate replaces the
//!   candidate in shadow mode.
//! - Each shadow answer is one row: the candidate outcome (run, ask, or no answer), the
//!   real outcome of the request (run or ask), and the owner decision when the owner
//!   decided. A row has no request data. It has the model answers as probabilities.
//! - A promotion makes the candidate the active model of the bouncer. It needs 100
//!   shadow decisions of the owner, 95% agreement, and no owner denial that the
//!   candidate would allow (`CandidateAgreement::can_promote`). Only the owner promotes,
//!   with a fresh owner check (`broker::shadow::promote`). A rollback returns to the
//!   model before the promotion. Each change goes to the activity log in the same
//!   transaction. Since schema 29 a promotion pins the head hash (`heads_sha256`); the
//!   `url` of a row is kept for old rows and is no longer read.

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
    "id, version, url, checkpoint, checkpoint_sha256, created_at, state, ended_at,
     report, origin, job_host, job_id, uploaded_to";
const ACTIVATION_COLUMNS: &str =
    "id, at, action, version, url, candidate_id, previous_version, previous_url,
     report, heads_sha256";
/// The host key of the bouncer brain on this Mac, in `model_candidate.uploaded_to`. A
/// remote host has its `https://` address (trimmed, without a trailing `/`) instead.
pub const THIS_MAC_HOST: &str = "this-mac";
/// Longest job id of a remote training job.
const MAX_JOB_ID_BYTES: usize = 128;

/// A SHA-256 as 64 lowercase hex characters.
fn is_sha256(text: &str) -> bool {
    text.len() == 64
        && text
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

/// A host key: [`THIS_MAC_HOST`], or an `https://` address of at most 200 bytes.
fn valid_host_key(host: &str) -> bool {
    host == THIS_MAC_HOST
        || (host.starts_with("https://")
            && host.len() <= MAX_URL_BYTES
            && !host.ends_with('/')
            && host.chars().all(|c| c.is_ascii_graphic()))
}

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

/// Where a head set was trained (schema 29).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CandidateOrigin {
    /// A fine-tune on this Mac.
    Local,
    /// A training job on a server: its host key and its job id. The head file is on this
    /// Mac after the download, as for a local fine-tune.
    RemoteJob { host: String, job_id: String },
}

/// A candidate model from a local fine-tune.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewCandidate {
    /// The version that the model server reports, for example `apassy-local-v1+1a2b3c4d`.
    pub version: String,
    /// Before schema 29: the loopback address of a separate candidate server. Kept for
    /// old rows and no longer read; it can be empty. The candidate answers in the
    /// request of the active model (`shadow_heads`).
    pub url: String,
    /// The checkpoint file on this computer. Every head set is on this Mac first.
    pub checkpoint: String,
    /// The SHA-256 of the head file: the `heads` hash of contract bouncer-brain-v1.
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
    /// Where the head set was trained (schema 29).
    pub origin: CandidateOrigin,
    /// The host key ([`THIS_MAC_HOST`] or an `https://` address) that has the head file
    /// now. `None`: no host has it yet, so the candidate gives no shadow answer and
    /// cannot be promoted.
    pub uploaded_to: Option<String>,
}

impl CandidateRecord {
    /// The head hash that a request names as `heads` or `shadow_heads`.
    pub fn heads_sha256(&self) -> &str {
        &self.checkpoint_sha256
    }

    /// The head file is on the host with the key `host`.
    pub fn is_on_host(&self, host: &str) -> bool {
        self.uploaded_to.as_deref() == Some(host)
    }
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
    /// The shadow head set gave no valid answer: the request failed, the answer had no
    /// shadow part or a `shadow.error`, it named another head set or model version, or
    /// the head file is not on the host.
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

/// One promotion or rollback. The newest row names the active model. No address and no
/// head hash mean the default bouncer (the default head set of the host).
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
    /// The head hash of the active model (schema 29). `None` for the default bouncer and
    /// for a row from before schema 29 (see [`Vault::activation_heads`]).
    pub heads_sha256: Option<String>,
}

impl ModelActivation {
    /// The row names the default bouncer: no address and no head hash.
    pub fn is_default(&self) -> bool {
        self.url.is_empty() && self.heads_sha256.is_none()
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
        self.register_candidate_from(candidate, &CandidateOrigin::Local, now)
    }

    /// Register a candidate with its origin (schema 29). The head file must be on this
    /// Mac (`checkpoint`), also for a remote job. No host has it yet: unit G marks the
    /// upload with [`Vault::mark_candidate_uploaded`].
    pub fn register_candidate_from(
        &mut self,
        candidate: &NewCandidate,
        origin: &CandidateOrigin,
        now: u64,
    ) -> VaultResult<CandidateRecord> {
        let sha_ok = is_sha256(&candidate.checkpoint_sha256);
        let (origin_text, job_host, job_id) = match origin {
            CandidateOrigin::Local => ("local", None, None),
            CandidateOrigin::RemoteJob { host, job_id } => {
                if !valid_host_key(host)
                    || host == THIS_MAC_HOST
                    || job_id.is_empty()
                    || job_id.len() > MAX_JOB_ID_BYTES
                    || !job_id.chars().all(|c| c.is_ascii_graphic())
                {
                    return Err(err(VaultErrorKind::InvalidInput));
                }
                ("remote_job", Some(host.as_str()), Some(job_id.as_str()))
            }
        };
        if !valid_model_version(&candidate.version)
            || candidate.url.len() > MAX_URL_BYTES
            || candidate.url.chars().any(char::is_control)
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
                 created_at, state, ended_at, report, origin, job_host, job_id, uploaded_to)
             VALUES (?1, ?2, ?3, ?4, ?5, 'shadow', NULL, ?6, ?7, ?8, ?9, NULL)",
            rusqlite::params![
                candidate.version,
                candidate.url,
                candidate.checkpoint,
                candidate.checkpoint_sha256,
                at,
                candidate.report,
                origin_text,
                job_host,
                job_id,
            ],
        )
        .map_err(|_| err(VaultErrorKind::Storage))?;
        let id = tx.last_insert_rowid();
        prune_candidates(&tx)?;
        let record = find_candidate(&tx, id)?.ok_or_else(|| err(VaultErrorKind::Storage))?;
        tx.commit().map_err(|_| err(VaultErrorKind::Storage))?;
        Ok(record)
    }

    /// The head file of candidate `id` is on the host `host` now ([`THIS_MAC_HOST`] or an
    /// `https://` address), or on no host with `None`. Unit G calls it after an upload
    /// (`PUT /v1/heads/<sha256>`) and before a hosting change completes. Returns false
    /// when there is no such candidate.
    pub fn mark_candidate_uploaded(&mut self, id: u64, host: Option<&str>) -> VaultResult<bool> {
        if host.is_some_and(|host| !valid_host_key(host)) {
            return Err(err(VaultErrorKind::InvalidInput));
        }
        let changed = self
            .conn_mut()?
            .execute(
                "UPDATE model_candidate SET uploaded_to = ?1 WHERE id = ?2",
                rusqlite::params![host, to_sql_id(id)?],
            )
            .map_err(|_| err(VaultErrorKind::Storage))?;
        Ok(changed > 0)
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

    /// The head hash that `activation` pins. `Ok(None)`: the default bouncer, or a row
    /// from before schema 29 that cannot name its head set (a rollback to an older
    /// promotion). A promotion from before schema 29 has no `heads_sha256`; its
    /// candidate's head hash pins it.
    pub fn activation_heads(&self, activation: &ModelActivation) -> VaultResult<Option<String>> {
        if let Some(heads) = &activation.heads_sha256 {
            return Ok(Some(heads.clone()));
        }
        if activation.is_default() || activation.action != ActivationAction::Promote {
            return Ok(None);
        }
        let Some(id) = activation.candidate_id else {
            return Ok(None);
        };
        Ok(self
            .candidate(id)?
            .map(|candidate| candidate.checkpoint_sha256)
            .filter(|heads| is_sha256(heads)))
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
        if !is_sha256(&candidate.checkpoint_sha256) {
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
                 previous_version, previous_url, report, heads_sha256)
             VALUES (?1, 'promote', ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                at,
                candidate.version,
                candidate.url,
                to_sql_id(candidate_id)?,
                previous_version,
                previous_url,
                report,
                candidate.checkpoint_sha256,
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
        // The model before the promotion: the row before it names its head set. Without
        // that row (pruned, or the default bouncer) the head hash stays empty; a
        // non-default model without a head hash makes the owner decide.
        let previous_heads = match self.activation_before(active.id)? {
            Some(before) if !active.previous_version.is_empty() => {
                self.activation_heads(&before)?
            }
            _ => None,
        };
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
                 previous_version, previous_url, report, heads_sha256)
             VALUES (?1, 'rollback', ?2, ?3, ?4, ?5, ?6, '{}', ?7)",
            rusqlite::params![
                at,
                active.previous_version,
                active.previous_url,
                active.candidate_id.map(to_sql_id).transpose()?,
                active.version,
                active.url,
                previous_heads,
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

    /// The newest activation before the row `id`.
    fn activation_before(&self, id: u64) -> VaultResult<Option<ModelActivation>> {
        self.conn_ref()?
            .query_row(
                &format!(
                    "SELECT {ACTIVATION_COLUMNS} FROM model_activation WHERE id < ?1
                     ORDER BY id DESC LIMIT 1"
                ),
                [to_sql_id(id)?],
                activation_row,
            )
            .optional()
            .map_err(|_| err(VaultErrorKind::Storage))?
            .map(activation_from)
            .transpose()
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

/// The columns of schema 29 of a candidate row.
type CandidateRow29 = (String, Option<String>, Option<String>, Option<String>);

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
    CandidateRow29,
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
        (row.get(9)?, row.get(10)?, row.get(11)?, row.get(12)?),
    ))
}

fn origin_from(
    origin: &str,
    job_host: Option<String>,
    job_id: Option<String>,
) -> VaultResult<CandidateOrigin> {
    match (origin, job_host, job_id) {
        ("local", _, _) => Ok(CandidateOrigin::Local),
        ("remote_job", Some(host), Some(job_id)) => Ok(CandidateOrigin::RemoteJob { host, job_id }),
        _ => Err(err(VaultErrorKind::Storage)),
    }
}

fn candidate_from(row: CandidateRow) -> VaultResult<CandidateRecord> {
    let (
        id,
        version,
        url,
        checkpoint,
        checkpoint_sha256,
        created_at,
        state,
        ended_at,
        report,
        (origin, job_host, job_id, uploaded_to),
    ) = row;
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
        origin: origin_from(&origin, job_host, job_id)?,
        uploaded_to,
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
    Option<String>,
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
        row.get(9)?,
    ))
}

fn activation_from(row: ActivationRow) -> VaultResult<ModelActivation> {
    let (
        id,
        at,
        action,
        version,
        url,
        candidate_id,
        previous_version,
        previous_url,
        report,
        heads_sha256,
    ) = row;
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
        heads_sha256,
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
                url: "u".repeat(MAX_URL_BYTES + 1),
                ..new_candidate("x")
            },
            NewCandidate {
                url: "http://127.0.0.1:8775\n".to_owned(),
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

    /// The shadow gate of ADR 0010 for `candidate`: 100 owner approvals that it runs.
    fn pass_the_gate(vault: &mut Vault, candidate: u64) {
        for _ in 0..100 {
            assert!(shadow(
                vault,
                candidate,
                ShadowAnswer::Run,
                OwnerLabel::Allow
            ));
        }
    }

    /// Schema 29: the candidate answers in the request of the active model, so its
    /// address is no longer read. An empty address or an `https://` address is
    /// accepted; the head file on this Mac and its hash are still required.
    #[test]
    fn a_candidate_needs_no_server_address_since_29() {
        let (_dir, mut vault) = temp_vault();
        for url in ["", "https://brain.synthetic.ts.net"] {
            let record = vault
                .register_candidate(
                    &NewCandidate {
                        url: url.to_owned(),
                        ..new_candidate("apassy-local-v1+01234567")
                    },
                    1,
                )
                .expect(url);
            assert_eq!(record.url, url);
            assert_eq!(record.origin, CandidateOrigin::Local);
            assert_eq!(record.uploaded_to, None, "no host has the head file yet");
            assert_eq!(record.heads_sha256(), SHA);
        }
    }

    /// A remote training job keeps its host and job id. The head file is on this Mac;
    /// the upload mark names the host that has it.
    #[test]
    fn a_remote_job_candidate_and_its_upload_mark_round_trip() {
        let (_dir, mut vault) = temp_vault();
        let origin = CandidateOrigin::RemoteJob {
            host: "https://brain.synthetic.ts.net".to_owned(),
            job_id: "job-0001".to_owned(),
        };
        let record = vault
            .register_candidate_from(&new_candidate("apassy-local-v1+01234567"), &origin, 5)
            .expect("remote job");
        assert_eq!(record.origin, origin);
        for bad in [
            CandidateOrigin::RemoteJob {
                host: THIS_MAC_HOST.to_owned(),
                job_id: "job".to_owned(),
            },
            CandidateOrigin::RemoteJob {
                host: "http://brain.synthetic".to_owned(),
                job_id: "job".to_owned(),
            },
            CandidateOrigin::RemoteJob {
                host: "https://brain.synthetic.ts.net".to_owned(),
                job_id: String::new(),
            },
        ] {
            assert_eq!(
                vault
                    .register_candidate_from(&new_candidate("v"), &bad, 6)
                    .unwrap_err()
                    .kind(),
                VaultErrorKind::InvalidInput,
                "{bad:?}"
            );
        }
        assert!(
            vault
                .mark_candidate_uploaded(record.id, Some(THIS_MAC_HOST))
                .expect("mark")
        );
        let read = vault.candidate(record.id).expect("read").expect("some");
        assert!(read.is_on_host(THIS_MAC_HOST));
        assert!(!read.is_on_host("https://brain.synthetic.ts.net"));
        assert!(
            vault
                .mark_candidate_uploaded(record.id, Some("https://brain.synthetic.ts.net"))
                .expect("mark")
        );
        assert!(
            vault
                .candidate(record.id)
                .expect("read")
                .expect("some")
                .is_on_host("https://brain.synthetic.ts.net")
        );
        assert!(
            vault
                .mark_candidate_uploaded(record.id, None)
                .expect("unmark")
        );
        assert_eq!(
            vault
                .candidate(record.id)
                .expect("read")
                .expect("some")
                .uploaded_to,
            None
        );
        for bad in ["http://127.0.0.1:8770", "https://brain.synthetic/", ""] {
            assert_eq!(
                vault
                    .mark_candidate_uploaded(record.id, Some(bad))
                    .unwrap_err()
                    .kind(),
                VaultErrorKind::InvalidInput,
                "{bad}"
            );
        }
        assert!(
            !vault
                .mark_candidate_uploaded(record.id + 99, None)
                .expect("none")
        );
    }

    /// A promotion writes the head hash; a rollback writes the head hash of the model
    /// before it, or none for the default bouncer.
    #[test]
    fn a_promotion_pins_the_head_hash_and_a_rollback_restores_the_one_before() {
        let (_dir, mut vault) = temp_vault();
        let other = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
        let first = vault
            .register_candidate(&new_candidate("apassy-local-v1+01234567"), 1)
            .expect("first");
        pass_the_gate(&mut vault, first.id);
        let promoted = vault.promote_candidate(first.id, 2).expect("promote");
        assert_eq!(promoted.heads_sha256.as_deref(), Some(SHA));
        assert!(!promoted.is_default());
        let second = vault
            .register_candidate(
                &NewCandidate {
                    url: String::new(),
                    checkpoint_sha256: other.to_owned(),
                    ..new_candidate("apassy-local-v1+fedcba98")
                },
                3,
            )
            .expect("second");
        pass_the_gate(&mut vault, second.id);
        let newer = vault.promote_candidate(second.id, 4).expect("promote");
        assert_eq!(newer.heads_sha256.as_deref(), Some(other));
        assert!(newer.url.is_empty());
        assert!(
            !newer.is_default(),
            "a head hash without an address is not the default"
        );
        let back = vault.roll_back_model(newer.id, 5).expect("roll back");
        assert_eq!(back.version, "apassy-local-v1+01234567");
        assert_eq!(back.heads_sha256.as_deref(), Some(SHA));
        assert_eq!(
            vault.activation_heads(&back).expect("heads").as_deref(),
            Some(SHA)
        );
    }

    /// A promotion from before schema 29 has no head hash: its candidate pins it. A
    /// rollback to the default bouncer has none and is the default.
    #[test]
    fn an_activation_from_before_29_is_pinned_by_its_candidate_hash() {
        let (_dir, mut vault) = temp_vault();
        let candidate = vault
            .register_candidate(&new_candidate("apassy-local-v1+01234567"), 1)
            .expect("candidate");
        pass_the_gate(&mut vault, candidate.id);
        let promoted = vault.promote_candidate(candidate.id, 2).expect("promote");
        vault
            .conn_mut()
            .expect("conn")
            .execute("UPDATE model_activation SET heads_sha256 = NULL", [])
            .expect("old row");
        let old = vault.active_model().expect("read").expect("some");
        assert_eq!(old.id, promoted.id);
        assert_eq!(old.heads_sha256, None);
        assert!(!old.is_default(), "the old row has its candidate address");
        assert_eq!(
            vault.activation_heads(&old).expect("heads").as_deref(),
            Some(SHA)
        );
        let back = vault.roll_back_model(old.id, 3).expect("roll back");
        assert!(back.is_default());
        assert_eq!(vault.activation_heads(&back).expect("heads"), None);
    }
}
