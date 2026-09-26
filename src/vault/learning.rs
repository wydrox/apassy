//! Decision log, remembered patterns, and threshold calibration (schema v7, ADR 0009).
//!
//! - The decision log keeps each bouncer, rule, and owner decision as one example. The
//!   vault masks the secret values of the items in the run before it stores an entry.
//!   So an entry has no secret value of those items. The log keeps the newest
//!   [`MAX_DECISION_ROWS`] entries and the newest [`MAX_KEPT_DENIALS`] owner denials.
//!   It removes older entries once every 64 new entries.
//! - A remembered pattern belongs to one agent, one project directory, one working
//!   directory, one item set, and one policy (declarations and owner instruction). It
//!   runs without a prompt after [`PATTERN_APPROVALS_NEEDED`] approvals. One denial
//!   blocks it until the owner removes it. A pattern that nobody used for
//!   [`PATTERN_IDLE_DAYS`] days expires.
//! - A calibration is a `task_match` level that the owner applied. Only the owner
//!   applies one. The newest row is active. No row means the default level.

use rusqlite::{OptionalExtension, Row, TransactionBehavior};
use serde_json::{Map, Value, json};

use super::agents::{Declaration, Environment, Reversibility, RiskLevel, Scope, format_utc};
use super::types::{VaultErrorKind, VaultResult, err};
use super::{Vault, to_public_id, to_sql_id};

/// Newest entries that the decision log keeps, owner denials not counted.
pub const MAX_DECISION_ROWS: usize = 10_000;
/// Newest owner denials that the decision log keeps. A denial stays longer than other
/// entries, because the calibration replay needs it.
pub const MAX_KEPT_DENIALS: usize = 2_000;
/// A pattern runs without a prompt after this many "Approve and remember" answers.
pub const PATTERN_APPROVALS_NEEDED: u32 = 3;
/// A pattern that nobody approved or used in this time expires.
pub const PATTERN_IDLE_DAYS: u64 = 30;
/// Learning and active patterns. When the list is full, the least recently used
/// learning pattern goes. When all are active, a new pattern is not stored.
pub const MAX_PATTERNS: usize = 1_000;
/// Blocked patterns. At the limit, the oldest block goes.
pub const MAX_BLOCKED_PATTERNS: usize = 5_000;
/// Lowest `task_match` level that a calibration can apply.
pub const CALIBRATION_FLOOR: f64 = 0.5;
/// Highest `task_match` level that a calibration can apply. It is the default level.
pub const CALIBRATION_CEILING: f64 = 0.8;
const MAX_CALIBRATION_ROWS: usize = 100;
/// Format version of one export line (`docs/operations/learning.md`).
pub const EXPORT_SCHEMA: &str = "apassy-decision-v1";
/// The log can hold up to `PRUNE_EVERY - 1` entries more than its limits.
const PRUNE_EVERY: u64 = 64;

const DAY_SECONDS: u64 = 86_400;
/// Secret values shorter than this are not masked. They would damage ordinary text.
const MIN_MASK_BYTES: usize = 4;
const MASK: &str = "[apassy:secret]";
const MAX_COMMAND_BYTES: usize = 8192;
const MAX_USER_REQUEST_BYTES: usize = 2000;
const MAX_PURPOSE_BYTES: usize = 500;
const MAX_NOTE_BYTES: usize = 1000;
const MAX_TEXT_BYTES: usize = 2048;

/// Tables added in schema version 7 (ADR 0009, ADR 0010): the decision log, remembered
/// patterns, and calibrations. Also the durable record of a run that waits for the
/// owner (goal item N3, `super::waiting`).
pub(super) const SCHEMA_V7_SQL: &str = "
CREATE TABLE decision_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at INTEGER NOT NULL,
    agent_id INTEGER NOT NULL,
    agent_name TEXT NOT NULL,
    project_dir TEXT NOT NULL,
    cwd_rel TEXT NOT NULL,
    items TEXT NOT NULL,
    user_request TEXT NOT NULL,
    user_request_source TEXT NOT NULL,
    command TEXT NOT NULL,
    purpose TEXT NOT NULL,
    env_names TEXT NOT NULL,
    declarations TEXT NOT NULL,
    rule_flags TEXT NOT NULL,
    known_safe INTEGER NOT NULL,
    model_facts TEXT NOT NULL,
    pattern TEXT NOT NULL,
    grant_asks INTEGER NOT NULL,
    asked INTEGER NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('allow', 'deny')),
    decided_by TEXT NOT NULL
        CHECK (decided_by IN ('rule', 'model', 'pattern', 'owner', 'no_answer')),
    remembered INTEGER NOT NULL,
    policy TEXT NOT NULL,
    note TEXT NOT NULL,
    instruction TEXT NOT NULL
);
CREATE INDEX decision_log_at ON decision_log(at);
CREATE TABLE remembered_pattern (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id INTEGER NOT NULL,
    project_dir TEXT NOT NULL,
    items TEXT NOT NULL,
    policy TEXT NOT NULL,
    cwd_rel TEXT NOT NULL,
    template TEXT NOT NULL,
    display TEXT NOT NULL,
    approvals INTEGER NOT NULL,
    blocked INTEGER NOT NULL CHECK (blocked IN (0, 1)),
    created_at INTEGER NOT NULL,
    last_used_at INTEGER NOT NULL,
    uses INTEGER NOT NULL,
    UNIQUE (agent_id, project_dir, items, policy, cwd_rel, template)
);
CREATE TABLE calibration (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at INTEGER NOT NULL,
    task_match REAL NOT NULL,
    report TEXT NOT NULL
);
CREATE TABLE waiting_run (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at INTEGER NOT NULL,
    agent_id INTEGER,
    agent_name TEXT NOT NULL,
    item_id INTEGER,
    operation TEXT NOT NULL,
    purpose TEXT NOT NULL
);
UPDATE vault_meta SET schema_version = 7 WHERE id = 1;
PRAGMA user_version = 7;
";

pub(super) const SCHEMA_V7_COLUMNS: [&str; 4] = [
    "SELECT id, at, agent_id, agent_name, item_id, operation, purpose FROM waiting_run LIMIT 0",
    "SELECT id, at, agent_id, agent_name, project_dir, cwd_rel, items, user_request,
            user_request_source, command, purpose, env_names, declarations, rule_flags,
            known_safe, model_facts, pattern, grant_asks, asked, decision, decided_by,
            remembered, policy, note, instruction FROM decision_log LIMIT 0",
    "SELECT id, agent_id, project_dir, items, policy, cwd_rel, template, display, approvals,
            blocked, created_at, last_used_at, uses FROM remembered_pattern LIMIT 0",
    "SELECT id, at, task_match, report FROM calibration LIMIT 0",
];

const DECISION_COLUMNS: &str = "id, at, agent_id, agent_name, project_dir, cwd_rel, items,
    user_request, user_request_source, command, purpose, env_names, declarations, rule_flags,
    known_safe, model_facts, pattern, grant_asks, asked, decision, decided_by, remembered,
    policy, note, instruction";
const PATTERN_COLUMNS: &str = "id, agent_id, project_dir, items, policy, cwd_rel, template,
    display, approvals, blocked, created_at, last_used_at, uses";

/// The final answer for a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoggedDecision {
    Allow,
    Deny,
}

impl LoggedDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }

    fn parse(text: &str) -> VaultResult<Self> {
        match text {
            "allow" => Ok(Self::Allow),
            "deny" => Ok(Self::Deny),
            _ => Err(err(VaultErrorKind::Storage)),
        }
    }
}

/// Who made the decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecidedBy {
    /// A hard rule or a request check denied the request. The bouncer did not decide.
    Rule,
    /// The model allowed the request without the owner.
    Model,
    /// A remembered pattern allowed the request without the owner.
    Pattern,
    /// The owner approved or denied.
    Owner,
    /// The request waited, and the owner did not answer in time.
    NoAnswer,
}

impl DecidedBy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rule => "rule",
            Self::Model => "model",
            Self::Pattern => "pattern",
            Self::Owner => "owner",
            Self::NoAnswer => "no_answer",
        }
    }

    fn parse(text: &str) -> VaultResult<Self> {
        match text {
            "rule" => Ok(Self::Rule),
            "model" => Ok(Self::Model),
            "pattern" => Ok(Self::Pattern),
            "owner" => Ok(Self::Owner),
            "no_answer" => Ok(Self::NoAnswer),
            _ => Err(err(VaultErrorKind::Storage)),
        }
    }

    /// The request passed the hard rules and reached the bouncer.
    pub fn reached_bouncer(self) -> bool {
        self != Self::Rule
    }
}

/// Where the user request came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestSource {
    /// No user request.
    None,
    /// The agent sent it in `user_request`. The agent can change it.
    Agent,
    /// A host adapter sent it, for example a Claude Code `UserPromptSubmit` hook.
    Host,
}

impl RequestSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Agent => "agent",
            Self::Host => "host",
        }
    }

    fn parse(text: &str) -> VaultResult<Self> {
        match text {
            "none" => Ok(Self::None),
            "agent" => Ok(Self::Agent),
            "host" => Ok(Self::Host),
            _ => Err(err(VaultErrorKind::Storage)),
        }
    }
}

/// One decision of the log. Text must not contain secret values. The vault also masks
/// the secret values of `items` before it stores the entry.
#[derive(Debug, Clone, PartialEq)]
pub struct DecisionEntry {
    /// Unix time of the decision.
    pub at: u64,
    pub agent_id: u64,
    pub agent_name: String,
    /// Project directory of the grant. Empty when a check failed before the grant.
    pub project_dir: String,
    /// Working directory relative to the project directory.
    pub cwd_rel: String,
    pub items: Vec<u64>,
    pub user_request: String,
    pub user_request_source: RequestSource,
    pub command: Vec<String>,
    pub purpose: String,
    pub env_names: Vec<String>,
    /// One entry per item. `None` when the item has no declaration.
    pub declarations: Vec<Option<Declaration>>,
    pub rule_flags: Vec<String>,
    pub known_safe: bool,
    /// Model answers. Empty when the broker did not ask the model or had no answer.
    pub model_facts: Vec<(String, f64)>,
    /// The generalized command, as the owner sees it. Empty when there is none.
    pub pattern: String,
    /// A grant in "ask" mode made the request wait, whatever the bouncer decided.
    pub grant_asks: bool,
    /// The request waited for the owner.
    pub asked: bool,
    pub decision: LoggedDecision,
    pub decided_by: DecidedBy,
    /// The owner used "Approve and remember".
    pub remembered: bool,
    /// Bouncer contract and active thresholds.
    pub policy: String,
    /// The decision note. No secret values.
    pub note: String,
    /// Owner instructions of the grants, joined. The model gets them as the owner rule.
    pub instruction: String,
}

impl DecisionEntry {
    pub fn fact(&self, name: &str) -> Option<f64> {
        self.model_facts
            .iter()
            .find(|(fact, _)| fact == name)
            .map(|(_, p)| *p)
    }

    /// The owner denied this request.
    pub fn owner_denied(&self) -> bool {
        self.decided_by == DecidedBy::Owner && self.decision == LoggedDecision::Deny
    }
}

/// A stored decision.
#[derive(Debug, Clone, PartialEq)]
pub struct DecisionRecord {
    pub id: u64,
    pub entry: DecisionEntry,
}

/// Decisions of one UTC day that reached the bouncer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DayRate {
    /// Unix time of the start of the day.
    pub day: u64,
    pub decisions: u32,
    pub asked: u32,
    pub by_model: u32,
    pub by_pattern: u32,
}

impl DayRate {
    pub fn ask_rate(&self) -> f64 {
        if self.decisions == 0 {
            0.0
        } else {
            f64::from(self.asked) / f64::from(self.decisions)
        }
    }
}

/// What a pattern is bound to, and its template (ADR 0010).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternKey {
    pub agent_id: u64,
    pub project_dir: String,
    /// Item IDs in ascending order.
    pub items: Vec<u64>,
    /// Declarations and owner instruction when the owner taught the pattern. A change
    /// starts a new pattern.
    pub policy: String,
    pub cwd_rel: String,
    /// Canonical template from `broker::patterns`.
    pub template: String,
}

/// State of a remembered pattern at one time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternState {
    /// Fewer than [`PATTERN_APPROVALS_NEEDED`] approvals. The owner still decides.
    Learning { approvals: u32 },
    /// A matching request runs without a prompt.
    Active,
    /// The owner denied a matching request. The pattern never runs without a prompt.
    Blocked,
    /// Nobody approved or used the pattern for [`PATTERN_IDLE_DAYS`] days.
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternRecord {
    pub id: u64,
    pub key: PatternKey,
    pub display: String,
    pub approvals: u32,
    pub blocked: bool,
    pub created_at: u64,
    pub last_used_at: u64,
    /// Runs that the pattern allowed without a prompt.
    pub uses: u64,
}

impl PatternRecord {
    pub fn state(&self, now: u64) -> PatternState {
        if self.blocked {
            PatternState::Blocked
        } else if now.saturating_sub(self.last_used_at) > PATTERN_IDLE_DAYS * DAY_SECONDS {
            PatternState::Expired
        } else if self.approvals >= PATTERN_APPROVALS_NEEDED {
            PatternState::Active
        } else {
            PatternState::Learning {
                approvals: self.approvals,
            }
        }
    }
}

/// One calibration that the owner applied.
#[derive(Debug, Clone, PartialEq)]
pub struct CalibrationRecord {
    pub id: u64,
    pub at: u64,
    pub task_match: f64,
    /// Replay numbers at the time of the change, as JSON. No request data.
    pub report: String,
}

/// Agreement of a candidate model with the owner in shadow mode (ADR 0010, goal items
/// B9 and B10). A candidate decides in parallel with no effect. `Vault::shadow_summary`
/// computes it from the shadow rows (schema 9).
#[derive(Debug, Clone, PartialEq)]
pub struct CandidateAgreement {
    pub model_version: String,
    /// Unix time when shadow mode started.
    pub started_at: u64,
    /// Owner decisions that the candidate also decided.
    pub shadow_decisions: u32,
    /// Decisions where the candidate gave the same answer as the owner.
    pub agreed: u32,
    /// Owner denials that the candidate would allow. Promotion needs zero.
    pub allowed_owner_denials: u32,
}

impl CandidateAgreement {
    /// Shadow decisions before the owner can promote a candidate (ADR 0010).
    pub const NEEDED_DECISIONS: u32 = 100;
    /// Agreement that promotion needs (ADR 0010).
    pub const NEEDED_AGREEMENT: f64 = 0.95;

    pub fn agreement(&self) -> Option<f64> {
        (self.shadow_decisions > 0)
            .then(|| f64::from(self.agreed) / f64::from(self.shadow_decisions))
    }

    /// The owner can promote the candidate manually. Apassy never promotes it.
    pub fn can_promote(&self) -> bool {
        self.shadow_decisions >= Self::NEEDED_DECISIONS
            && self.allowed_owner_denials == 0
            && self
                .agreement()
                .is_some_and(|agreement| agreement >= Self::NEEDED_AGREEMENT)
    }
}

impl Vault {
    /// Store one decision. Secret values of the items in the run are masked first.
    pub fn record_decision(&mut self, entry: &DecisionEntry) -> VaultResult<u64> {
        let values = self.secret_values(&entry.items)?;
        let mask = |text: &str, max: usize| cut(&mask_values(text, &values), max);
        let mut command = Vec::new();
        let mut used = 0usize;
        for arg in &entry.command {
            let arg = mask(arg, MAX_COMMAND_BYTES);
            used += arg.len();
            if used > MAX_COMMAND_BYTES {
                command.push("[truncated]".to_owned());
                break;
            }
            command.push(arg);
        }
        let at = to_sql_time(entry.at)?;
        let agent = to_sql_id(entry.agent_id)?;
        let items = json!(entry.items).to_string();
        let declarations = Value::Array(
            entry
                .declarations
                .iter()
                .map(|declaration| declaration.as_ref().map_or(Value::Null, declaration_json))
                .collect(),
        )
        .to_string();
        let facts: Map<String, Value> = entry
            .model_facts
            .iter()
            .map(|(name, p)| (name.clone(), json!(p)))
            .collect();
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        tx.execute(
            "INSERT INTO decision_log (at, agent_id, agent_name, project_dir, cwd_rel, items,
                 user_request, user_request_source, command, purpose, env_names, declarations,
                 rule_flags, known_safe, model_facts, pattern, grant_asks, asked, decision,
                 decided_by, remembered, policy, note, instruction)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16,
                 ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24)",
            rusqlite::params![
                at,
                agent,
                cut(&entry.agent_name, MAX_TEXT_BYTES),
                cut(&entry.project_dir, MAX_TEXT_BYTES),
                cut(&entry.cwd_rel, MAX_TEXT_BYTES),
                items,
                mask(&entry.user_request, MAX_USER_REQUEST_BYTES),
                entry.user_request_source.as_str(),
                json!(command).to_string(),
                mask(&entry.purpose, MAX_PURPOSE_BYTES),
                json!(entry.env_names).to_string(),
                declarations,
                json!(entry.rule_flags).to_string(),
                entry.known_safe,
                Value::Object(facts).to_string(),
                mask(&entry.pattern, MAX_COMMAND_BYTES),
                entry.grant_asks,
                entry.asked,
                entry.decision.as_str(),
                entry.decided_by.as_str(),
                entry.remembered,
                cut(&entry.policy, MAX_TEXT_BYTES),
                mask(&entry.note, MAX_NOTE_BYTES),
                mask(&entry.instruction, MAX_TEXT_BYTES),
            ],
        )
        .map_err(|_| err(VaultErrorKind::Storage))?;
        let id = to_public_id(tx.last_insert_rowid())?;
        // A prune reads the whole log, so it runs once every PRUNE_EVERY entries.
        if id % PRUNE_EVERY == 0 {
            prune_decisions(&tx, MAX_DECISION_ROWS, MAX_KEPT_DENIALS)?;
        }
        tx.commit().map_err(|_| err(VaultErrorKind::Storage))?;
        Ok(id)
    }

    /// Every stored decision, oldest first.
    pub fn decision_log(&self) -> VaultResult<Vec<DecisionRecord>> {
        self.query_decisions(
            &format!("SELECT {DECISION_COLUMNS} FROM decision_log ORDER BY at ASC, id ASC"),
            rusqlite::params![],
        )
    }

    /// Decisions without the owner (model or pattern), newest first.
    pub fn automatic_decisions(&self, limit: usize) -> VaultResult<Vec<DecisionRecord>> {
        let limit = i64::try_from(limit).map_err(|_| err(VaultErrorKind::InvalidInput))?;
        self.query_decisions(
            &format!(
                "SELECT {DECISION_COLUMNS} FROM decision_log
                 WHERE decided_by IN ('model', 'pattern') ORDER BY id DESC LIMIT ?1"
            ),
            [limit],
        )
    }

    pub fn decision(&self, id: u64) -> VaultResult<Option<DecisionRecord>> {
        let rows = self.query_decisions(
            &format!("SELECT {DECISION_COLUMNS} FROM decision_log WHERE id = ?1"),
            [to_sql_id(id)?],
        )?;
        Ok(rows.into_iter().next())
    }

    /// Decisions per UTC day from `since`, oldest day first. Rule denials do not count:
    /// the ask rate is the share of requests that reached the bouncer and waited.
    pub fn ask_rate_by_day(&self, since: u64) -> VaultResult<Vec<DayRate>> {
        let conn = self.conn_ref()?;
        let mut stmt = conn
            .prepare(
                "SELECT at / 86400, COUNT(*), SUM(asked), SUM(decided_by = 'model'),
                     SUM(decided_by = 'pattern')
                 FROM decision_log WHERE decided_by != 'rule' AND at >= ?1
                 GROUP BY at / 86400 ORDER BY at / 86400 ASC",
            )
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let rows = stmt
            .query_map([to_sql_time(since)?], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let count = |n: i64| u32::try_from(n).map_err(|_| err(VaultErrorKind::Storage));
        let mut days = Vec::new();
        for row in rows {
            let (day, decisions, asked, by_model, by_pattern) =
                row.map_err(|_| err(VaultErrorKind::Storage))?;
            days.push(DayRate {
                day: from_sql_time(day)? * DAY_SECONDS,
                decisions: count(decisions)?,
                asked: count(asked)?,
                by_model: count(by_model)?,
                by_pattern: count(by_pattern)?,
            });
        }
        Ok(days)
    }

    /// All decisions as JSON Lines, oldest first (`docs/operations/learning.md`). The
    /// lines have no secret values of the run items. They have commands and user
    /// requests, so the owner keeps the output on this computer.
    pub fn export_decisions_jsonl(&self) -> VaultResult<String> {
        let mut out = String::new();
        for record in self.decision_log()? {
            out.push_str(&export_line(&record.entry).to_string());
            out.push('\n');
        }
        Ok(out)
    }

    // ---- Remembered patterns ----

    pub fn pattern(&self, key: &PatternKey) -> VaultResult<Option<PatternRecord>> {
        let conn = self.conn_ref()?;
        find_pattern(conn, key)
    }

    /// Add one "Approve and remember" answer. A blocked pattern stays blocked. An
    /// expired pattern starts again at one approval. `None` when the list is full.
    pub fn remember_approval(
        &mut self,
        key: &PatternKey,
        display: &str,
        now: u64,
    ) -> VaultResult<Option<PatternRecord>> {
        self.remember_within(key, display, now, MAX_PATTERNS)
    }

    fn remember_within(
        &mut self,
        key: &PatternKey,
        display: &str,
        now: u64,
        max_patterns: usize,
    ) -> VaultResult<Option<PatternRecord>> {
        let at = to_sql_time(now)?;
        let idle = to_sql_time(now.saturating_sub(PATTERN_IDLE_DAYS * DAY_SECONDS))?;
        let display = cut(display, MAX_COMMAND_BYTES);
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        match find_pattern(&tx, key)? {
            Some(pattern) if pattern.blocked => return Ok(Some(pattern)),
            Some(pattern) => {
                let restart = pattern.state(now) == PatternState::Expired;
                tx.execute(
                    "UPDATE remembered_pattern SET
                         approvals = CASE WHEN ?1 THEN 1 ELSE approvals + 1 END,
                         created_at = CASE WHEN ?1 THEN ?2 ELSE created_at END,
                         uses = CASE WHEN ?1 THEN 0 ELSE uses END,
                         last_used_at = ?2, display = ?3
                     WHERE id = ?4",
                    rusqlite::params![restart, at, display, to_sql_id(pattern.id)?],
                )
                .map_err(|_| err(VaultErrorKind::Storage))?;
            }
            None => {
                tx.execute(
                    "DELETE FROM remembered_pattern WHERE blocked = 0 AND last_used_at < ?1",
                    [idle],
                )
                .map_err(|_| err(VaultErrorKind::Storage))?;
                let stored: i64 = tx
                    .query_row(
                        "SELECT COUNT(*) FROM remembered_pattern WHERE blocked = 0",
                        [],
                        |row| row.get(0),
                    )
                    .map_err(|_| err(VaultErrorKind::Storage))?;
                if usize::try_from(stored).map_err(|_| err(VaultErrorKind::Storage))?
                    >= max_patterns
                {
                    // The least recently used pattern that still learns makes room. An
                    // active pattern stays. This only takes learning progress away.
                    let freed = tx
                        .execute(
                            "DELETE FROM remembered_pattern WHERE id IN (
                                 SELECT id FROM remembered_pattern
                                 WHERE blocked = 0 AND approvals < ?1
                                 ORDER BY last_used_at ASC, id ASC LIMIT 1)",
                            [i64::from(PATTERN_APPROVALS_NEEDED)],
                        )
                        .map_err(|_| err(VaultErrorKind::Storage))?;
                    if freed == 0 {
                        return Ok(None);
                    }
                }
                insert_pattern(&tx, key, &display, false, at)?;
            }
        }
        let pattern = find_pattern(&tx, key)?;
        tx.commit().map_err(|_| err(VaultErrorKind::Storage))?;
        Ok(pattern)
    }

    /// The owner denied a request with this pattern. The pattern never runs without a
    /// prompt again, until the owner removes it.
    pub fn block_pattern(&mut self, key: &PatternKey, display: &str, now: u64) -> VaultResult<()> {
        self.block_within(key, display, now, MAX_BLOCKED_PATTERNS)
    }

    fn block_within(
        &mut self,
        key: &PatternKey,
        display: &str,
        now: u64,
        max_blocked: usize,
    ) -> VaultResult<()> {
        let at = to_sql_time(now)?;
        let display = cut(display, MAX_COMMAND_BYTES);
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        match find_pattern(&tx, key)? {
            Some(pattern) => {
                tx.execute(
                    "UPDATE remembered_pattern SET blocked = 1, last_used_at = ?1 WHERE id = ?2",
                    (at, to_sql_id(pattern.id)?),
                )
                .map_err(|_| err(VaultErrorKind::Storage))?;
            }
            None => {
                tx.execute(
                    "DELETE FROM remembered_pattern WHERE id IN (
                         SELECT id FROM remembered_pattern WHERE blocked = 1
                         ORDER BY last_used_at DESC, id DESC LIMIT -1 OFFSET ?1)",
                    [i64::try_from(max_blocked.saturating_sub(1))
                        .map_err(|_| err(VaultErrorKind::Storage))?],
                )
                .map_err(|_| err(VaultErrorKind::Storage))?;
                insert_pattern(&tx, key, &display, true, at)?;
            }
        }
        tx.commit().map_err(|_| err(VaultErrorKind::Storage))
    }

    /// An active pattern allowed a run.
    pub fn record_pattern_use(&mut self, id: u64, now: u64) -> VaultResult<()> {
        self.conn_mut()?
            .execute(
                "UPDATE remembered_pattern SET uses = uses + 1, last_used_at = ?1
                 WHERE id = ?2 AND blocked = 0",
                (to_sql_time(now)?, to_sql_id(id)?),
            )
            .map_err(|_| err(VaultErrorKind::Storage))?;
        Ok(())
    }

    /// Every pattern for the owner list: active and learning first, then blocked.
    pub fn patterns(&self) -> VaultResult<Vec<PatternRecord>> {
        let conn = self.conn_ref()?;
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {PATTERN_COLUMNS} FROM remembered_pattern
                 ORDER BY blocked ASC, last_used_at DESC, id DESC"
            ))
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let rows = stmt
            .query_map([], pattern_row)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let mut patterns = Vec::new();
        for row in rows {
            patterns.push(pattern_from(
                row.map_err(|_| err(VaultErrorKind::Storage))?,
            )?);
        }
        Ok(patterns)
    }

    /// The owner removes a pattern. A removed block lets the pattern learn again.
    pub fn remove_pattern(&mut self, id: u64) -> VaultResult<()> {
        let changed = self
            .conn_mut()?
            .execute(
                "DELETE FROM remembered_pattern WHERE id = ?1",
                [to_sql_id(id)?],
            )
            .map_err(|_| err(VaultErrorKind::Storage))?;
        if changed == 0 {
            Err(err(VaultErrorKind::NotFound))
        } else {
            Ok(())
        }
    }

    // ---- Calibration ----

    /// The active calibration, or `None` for the default level.
    pub fn calibration(&self) -> VaultResult<Option<CalibrationRecord>> {
        Ok(self.calibration_history(1)?.into_iter().next())
    }

    /// Newest first.
    pub fn calibration_history(&self, limit: usize) -> VaultResult<Vec<CalibrationRecord>> {
        let limit = i64::try_from(limit).map_err(|_| err(VaultErrorKind::InvalidInput))?;
        let conn = self.conn_ref()?;
        let mut stmt = conn
            .prepare("SELECT id, at, task_match, report FROM calibration ORDER BY id DESC LIMIT ?1")
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let rows = stmt
            .query_map([limit], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, f64>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let mut records = Vec::new();
        for row in rows {
            let (id, at, task_match, report) = row.map_err(|_| err(VaultErrorKind::Storage))?;
            records.push(CalibrationRecord {
                id: to_public_id(id)?,
                at: from_sql_time(at)?,
                task_match,
                report,
            });
        }
        Ok(records)
    }

    /// The owner applies a `task_match` level. The caller checks the replay gate first
    /// (`broker::calibration`). The level must be in the calibration range.
    pub fn apply_calibration(
        &mut self,
        task_match: f64,
        report: &str,
        now: u64,
    ) -> VaultResult<()> {
        if !(CALIBRATION_FLOOR..=CALIBRATION_CEILING).contains(&task_match) {
            return Err(err(VaultErrorKind::InvalidInput));
        }
        let at = to_sql_time(now)?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        tx.execute(
            "INSERT INTO calibration (at, task_match, report) VALUES (?1, ?2, ?3)",
            (at, task_match, cut(report, MAX_COMMAND_BYTES)),
        )
        .map_err(|_| err(VaultErrorKind::Storage))?;
        tx.execute(
            "DELETE FROM calibration WHERE id IN (
                 SELECT id FROM calibration ORDER BY id DESC LIMIT -1 OFFSET ?1)",
            [i64::try_from(MAX_CALIBRATION_ROWS).map_err(|_| err(VaultErrorKind::Storage))?],
        )
        .map_err(|_| err(VaultErrorKind::Storage))?;
        tx.commit().map_err(|_| err(VaultErrorKind::Storage))
    }

    // ---- Internal ----

    fn secret_values(&self, items: &[u64]) -> VaultResult<Vec<String>> {
        let conn = self.conn_ref()?;
        let mut stmt = conn
            .prepare("SELECT value FROM item_field WHERE item_id = ?1 AND secret = 1")
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let mut values = Vec::new();
        for item in items {
            let rows = stmt
                .query_map([to_sql_id(*item)?], |row| row.get::<_, String>(0))
                .map_err(|_| err(VaultErrorKind::Storage))?;
            for row in rows {
                let value = row.map_err(|_| err(VaultErrorKind::Storage))?;
                if value.len() >= MIN_MASK_BYTES {
                    values.push(value);
                }
            }
        }
        // Longer values first, so a value inside another value does not leave a part.
        values.sort_by_key(|value| std::cmp::Reverse(value.len()));
        Ok(values)
    }

    fn query_decisions<P: rusqlite::Params>(
        &self,
        sql: &str,
        params: P,
    ) -> VaultResult<Vec<DecisionRecord>> {
        let conn = self.conn_ref()?;
        let mut stmt = conn
            .prepare(sql)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let rows = stmt
            .query_map(params, decision_row)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let mut records = Vec::new();
        for row in rows {
            records.push(decision_from(
                row.map_err(|_| err(VaultErrorKind::Storage))?,
            )?);
        }
        Ok(records)
    }
}

/// Keep the newest `max_rows` entries that are not owner denials, and the newest
/// `max_denials` owner denials.
fn prune_decisions(
    tx: &rusqlite::Transaction<'_>,
    max_rows: usize,
    max_denials: usize,
) -> VaultResult<()> {
    let limit = |n: usize| i64::try_from(n).map_err(|_| err(VaultErrorKind::Storage));
    tx.execute(
        "DELETE FROM decision_log WHERE id IN (
             SELECT id FROM decision_log
             WHERE NOT (decided_by = 'owner' AND decision = 'deny')
             ORDER BY id DESC LIMIT -1 OFFSET ?1)",
        [limit(max_rows)?],
    )
    .map_err(|_| err(VaultErrorKind::Storage))?;
    tx.execute(
        "DELETE FROM decision_log WHERE id IN (
             SELECT id FROM decision_log
             WHERE decided_by = 'owner' AND decision = 'deny'
             ORDER BY id DESC LIMIT -1 OFFSET ?1)",
        [limit(max_denials)?],
    )
    .map_err(|_| err(VaultErrorKind::Storage))?;
    Ok(())
}

/// Remove the patterns of a revoked agent. Its token no longer works.
pub(super) fn forget_agent(tx: &rusqlite::Transaction<'_>, agent: i64) -> VaultResult<()> {
    tx.execute(
        "DELETE FROM remembered_pattern WHERE agent_id = ?1",
        [agent],
    )
    .map_err(|_| err(VaultErrorKind::Storage))?;
    Ok(())
}

/// Remove the patterns that include a deleted item.
pub(super) fn forget_item(tx: &rusqlite::Transaction<'_>, item: i64) -> VaultResult<()> {
    let mut stmt = tx
        .prepare("SELECT id, items FROM remembered_pattern")
        .map_err(|_| err(VaultErrorKind::Storage))?;
    let rows = stmt
        .query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|_| err(VaultErrorKind::Storage))?;
    let mut remove = Vec::new();
    for row in rows {
        let (id, items) = row.map_err(|_| err(VaultErrorKind::Storage))?;
        let items: Vec<i64> =
            serde_json::from_str(&items).map_err(|_| err(VaultErrorKind::Storage))?;
        if items.contains(&item) {
            remove.push(id);
        }
    }
    drop(stmt);
    for id in remove {
        tx.execute("DELETE FROM remembered_pattern WHERE id = ?1", [id])
            .map_err(|_| err(VaultErrorKind::Storage))?;
    }
    Ok(())
}

/// A restore revokes every agent (goal item V4). Their patterns go too.
pub(super) fn forget_all_patterns(tx: &rusqlite::Transaction<'_>) -> VaultResult<()> {
    tx.execute("DELETE FROM remembered_pattern", [])
        .map_err(|_| err(VaultErrorKind::Storage))?;
    Ok(())
}

type PatternRow = (
    i64,
    i64,
    String,
    String,
    String,
    String,
    String,
    String,
    i64,
    i64,
    i64,
    i64,
    i64,
);

fn pattern_row(row: &Row<'_>) -> rusqlite::Result<PatternRow> {
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
        row.get(10)?,
        row.get(11)?,
        row.get(12)?,
    ))
}

fn pattern_from(row: PatternRow) -> VaultResult<PatternRecord> {
    let (
        id,
        agent_id,
        project_dir,
        items,
        policy,
        cwd_rel,
        template,
        display,
        approvals,
        blocked,
        created_at,
        last_used_at,
        uses,
    ) = row;
    let items: Vec<u64> = serde_json::from_str(&items).map_err(|_| err(VaultErrorKind::Storage))?;
    Ok(PatternRecord {
        id: to_public_id(id)?,
        key: PatternKey {
            agent_id: to_public_id(agent_id)?,
            project_dir,
            items,
            policy,
            cwd_rel,
            template,
        },
        display,
        approvals: u32::try_from(approvals).map_err(|_| err(VaultErrorKind::Storage))?,
        blocked: blocked != 0,
        created_at: from_sql_time(created_at)?,
        last_used_at: from_sql_time(last_used_at)?,
        uses: u64::try_from(uses).map_err(|_| err(VaultErrorKind::Storage))?,
    })
}

fn items_text(items: &[u64]) -> String {
    let mut sorted = items.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    json!(sorted).to_string()
}

fn find_pattern(
    conn: &rusqlite::Connection,
    key: &PatternKey,
) -> VaultResult<Option<PatternRecord>> {
    let row = conn
        .query_row(
            &format!(
                "SELECT {PATTERN_COLUMNS} FROM remembered_pattern
                 WHERE agent_id = ?1 AND project_dir = ?2 AND items = ?3 AND policy = ?4
                     AND cwd_rel = ?5 AND template = ?6"
            ),
            rusqlite::params![
                to_sql_id(key.agent_id)?,
                key.project_dir,
                items_text(&key.items),
                key.policy,
                key.cwd_rel,
                key.template,
            ],
            pattern_row,
        )
        .optional()
        .map_err(|_| err(VaultErrorKind::Storage))?;
    row.map(pattern_from).transpose()
}

fn insert_pattern(
    tx: &rusqlite::Transaction<'_>,
    key: &PatternKey,
    display: &str,
    blocked: bool,
    at: i64,
) -> VaultResult<()> {
    tx.execute(
        "INSERT INTO remembered_pattern (agent_id, project_dir, items, policy, cwd_rel, template,
             display, approvals, blocked, created_at, last_used_at, uses)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10, 0)",
        rusqlite::params![
            to_sql_id(key.agent_id)?,
            key.project_dir,
            items_text(&key.items),
            key.policy,
            key.cwd_rel,
            key.template,
            display,
            if blocked { 0 } else { 1 },
            blocked,
            at,
        ],
    )
    .map_err(|_| err(VaultErrorKind::Storage))?;
    Ok(())
}

type DecisionRow = ([i64; 3], [String; 18], [i64; 4]);

fn decision_row(row: &Row<'_>) -> rusqlite::Result<DecisionRow> {
    // Columns in DECISION_COLUMNS order.
    Ok((
        [row.get(0)?, row.get(1)?, row.get(2)?],
        [
            row.get(3)?,
            row.get(4)?,
            row.get(5)?,
            row.get(6)?,
            row.get(7)?,
            row.get(8)?,
            row.get(9)?,
            row.get(10)?,
            row.get(11)?,
            row.get(12)?,
            row.get(13)?,
            row.get(15)?,
            row.get(16)?,
            row.get(19)?,
            row.get(20)?,
            row.get(22)?,
            row.get(23)?,
            row.get(24)?,
        ],
        [row.get(14)?, row.get(17)?, row.get(18)?, row.get(21)?],
    ))
}

fn decision_from(row: DecisionRow) -> VaultResult<DecisionRecord> {
    let ([id, at, agent_id], text, [known_safe, grant_asks, asked, remembered]) = row;
    let [
        agent_name,
        project_dir,
        cwd_rel,
        items,
        user_request,
        source,
        command,
        purpose,
        env_names,
        declarations,
        rule_flags,
        model_facts,
        pattern,
        decision,
        decided_by,
        policy,
        note,
        instruction,
    ] = text;
    let storage = |_| err(VaultErrorKind::Storage);
    let declarations: Vec<Value> = serde_json::from_str(&declarations).map_err(storage)?;
    let facts: Map<String, Value> = serde_json::from_str(&model_facts).map_err(storage)?;
    Ok(DecisionRecord {
        id: to_public_id(id)?,
        entry: DecisionEntry {
            at: from_sql_time(at)?,
            agent_id: to_public_id(agent_id)?,
            agent_name,
            project_dir,
            cwd_rel,
            items: serde_json::from_str(&items).map_err(storage)?,
            user_request,
            user_request_source: RequestSource::parse(&source)?,
            command: serde_json::from_str(&command).map_err(storage)?,
            purpose,
            env_names: serde_json::from_str(&env_names).map_err(storage)?,
            declarations: declarations
                .iter()
                .map(declaration_from_json)
                .collect::<VaultResult<_>>()?,
            rule_flags: serde_json::from_str(&rule_flags).map_err(storage)?,
            known_safe: known_safe != 0,
            model_facts: facts
                .into_iter()
                .map(|(name, p)| {
                    p.as_f64()
                        .map(|p| (name, p))
                        .ok_or_else(|| err(VaultErrorKind::Storage))
                })
                .collect::<VaultResult<_>>()?,
            pattern,
            grant_asks: grant_asks != 0,
            asked: asked != 0,
            decision: LoggedDecision::parse(&decision)?,
            decided_by: DecidedBy::parse(&decided_by)?,
            remembered: remembered != 0,
            policy,
            note,
            instruction,
        },
    })
}

fn declaration_json(declaration: &Declaration) -> Value {
    json!({
        "project": declaration.project,
        "environment": declaration.environment.as_str(),
        "risk": declaration.risk.as_str(),
        "scope": declaration.scope.as_str(),
        "reversibility": declaration.reversibility.as_str(),
    })
}

fn declaration_from_json(value: &Value) -> VaultResult<Option<Declaration>> {
    if value.is_null() {
        return Ok(None);
    }
    let text = |name: &str| {
        value
            .get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| err(VaultErrorKind::Storage))
    };
    let storage = |_| err(VaultErrorKind::Storage);
    Ok(Some(Declaration {
        project: text("project")?.to_owned(),
        environment: Environment::parse(text("environment")?).map_err(storage)?,
        risk: RiskLevel::parse(text("risk")?).map_err(storage)?,
        scope: Scope::parse(text("scope")?).map_err(storage)?,
        reversibility: Reversibility::parse(text("reversibility")?).map_err(storage)?,
    }))
}

/// One export line. Field names are in `docs/operations/learning.md`.
fn export_line(entry: &DecisionEntry) -> Value {
    let facts: Map<String, Value> = entry
        .model_facts
        .iter()
        .map(|(name, p)| (name.clone(), json!(p)))
        .collect();
    json!({
        "schema": EXPORT_SCHEMA,
        "time": rfc3339(entry.at),
        "at": entry.at,
        "agent": entry.agent_name,
        "user_request": entry.user_request,
        "user_request_source": entry.user_request_source.as_str(),
        "command": entry.command,
        "cwd_rel": entry.cwd_rel,
        "purpose": entry.purpose,
        "instruction": entry.instruction,
        "env_names": entry.env_names,
        "declaration": entry
            .declarations
            .iter()
            .map(|declaration| declaration.as_ref().map_or(Value::Null, declaration_json))
            .collect::<Vec<_>>(),
        "rule_flags": entry.rule_flags,
        "model_facts": facts,
        "decision": entry.decision.as_str(),
        "decided_by": entry.decided_by.as_str(),
        "remembered": entry.remembered,
    })
}

/// `YYYY-MM-DDTHH:MM:SSZ`.
fn rfc3339(unix: u64) -> String {
    let text = format_utc(unix);
    let text = text.trim_end_matches(" UTC");
    format!("{}Z", text.replacen(' ', "T", 1))
}

fn mask_values(text: &str, values: &[String]) -> String {
    let mut out = text.to_owned();
    for value in values {
        if out.contains(value.as_str()) {
            out = out.replace(value.as_str(), MASK);
        }
    }
    out
}

/// Cut at a character boundary.
fn cut(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_owned();
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
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

    const PASS: &str = "learning-unit-pass";

    fn temp_vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::TempDir::new().expect("dir");
        let mut vault = Vault::create(&dir.path().join("learning.db"), PASS).expect("create");
        vault.unlock(PASS).expect("unlock");
        (dir, vault)
    }

    fn entry(at: u64, decided_by: DecidedBy, decision: LoggedDecision) -> DecisionEntry {
        DecisionEntry {
            at,
            agent_id: 1,
            agent_name: "Unit agent".to_owned(),
            project_dir: "/p".to_owned(),
            cwd_rel: ".".to_owned(),
            items: Vec::new(),
            user_request: "Run the tests.".to_owned(),
            user_request_source: RequestSource::Agent,
            command: vec!["npm".to_owned(), "test".to_owned()],
            purpose: "Test.".to_owned(),
            env_names: Vec::new(),
            declarations: Vec::new(),
            rule_flags: Vec::new(),
            known_safe: false,
            model_facts: Vec::new(),
            pattern: String::new(),
            grant_asks: false,
            asked: decided_by == DecidedBy::Owner,
            decision,
            decided_by,
            remembered: false,
            policy: String::new(),
            note: String::new(),
            instruction: String::new(),
        }
    }

    fn key(template: &str) -> PatternKey {
        PatternKey {
            agent_id: 1,
            project_dir: "/p".to_owned(),
            items: vec![1],
            policy: String::new(),
            cwd_rel: ".".to_owned(),
            template: template.to_owned(),
        }
    }

    /// The log keeps the newest entries. Owner denials have their own, separate limit.
    #[test]
    fn prune_keeps_newest_entries_and_owner_denials_separately() {
        let (_dir, mut vault) = temp_vault();
        for at in 0..6 {
            vault
                .record_decision(&entry(at, DecidedBy::Model, LoggedDecision::Allow))
                .expect("record");
        }
        for at in 6..10 {
            vault
                .record_decision(&entry(at, DecidedBy::Owner, LoggedDecision::Deny))
                .expect("record");
        }
        {
            let conn = vault.conn_mut().expect("conn");
            let tx = conn.transaction().expect("tx");
            prune_decisions(&tx, 3, 2).expect("prune");
            tx.commit().expect("commit");
        }
        let kept: Vec<u64> = vault
            .decision_log()
            .expect("log")
            .iter()
            .map(|record| record.entry.at)
            .collect();
        assert_eq!(kept, vec![3, 4, 5, 8, 9]);
    }

    /// A full list drops the least recently used learning pattern. A list full of active
    /// patterns refuses a new pattern. An expired pattern leaves room. Blocks have their
    /// own limit, and the oldest block goes first.
    #[test]
    fn pattern_limits() {
        let (_dir, mut vault) = temp_vault();
        let day = DAY_SECONDS;
        let remember = |vault: &mut Vault, name: &str, at: u64| {
            vault
                .remember_within(&key(name), name, at, 2)
                .expect("remember")
        };
        assert!(remember(&mut vault, "a", 0).is_some());
        assert!(remember(&mut vault, "b", day).is_some());
        // Full of learning patterns: "a" is the oldest and goes.
        assert!(remember(&mut vault, "c", day).is_some());
        assert!(vault.pattern(&key("a")).expect("a").is_none());
        // "b" and "c" become active. Then the list refuses a new pattern.
        for _ in 0..2 {
            remember(&mut vault, "b", day);
            remember(&mut vault, "c", day);
        }
        assert!(remember(&mut vault, "d", day).is_none(), "the list is full");
        // After 30 idle days, "b" and "c" expired. They go, and "d" fits.
        let later = (PATTERN_IDLE_DAYS + 1) * day + day;
        assert!(remember(&mut vault, "d", later).is_some());
        assert!(vault.pattern(&key("b")).expect("b").is_none());

        for (index, name) in ["x", "y", "z"].into_iter().enumerate() {
            vault
                .block_within(&key(name), name, later + index as u64, 2)
                .expect("block");
        }
        let blocked: Vec<String> = vault
            .patterns()
            .expect("patterns")
            .into_iter()
            .filter(|pattern| pattern.blocked)
            .map(|pattern| pattern.display)
            .collect();
        assert_eq!(blocked, vec!["z".to_owned(), "y".to_owned()]);
    }

    #[test]
    fn mask_prefers_longer_values() {
        let values = vec!["abcdefgh".to_owned(), "abcd".to_owned()];
        assert_eq!(
            mask_values("x abcdefgh y abcd", &values),
            format!("x {MASK} y {MASK}")
        );
    }

    #[test]
    fn rfc3339_time() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_790_380_800), "2026-09-26T00:00:00Z");
    }

    #[test]
    fn candidate_promotion_needs_100_decisions_95_percent_and_no_allowed_denial() {
        let mut candidate = CandidateAgreement {
            model_version: "laya-local-1".to_owned(),
            started_at: 0,
            shadow_decisions: 100,
            agreed: 95,
            allowed_owner_denials: 0,
        };
        assert!(candidate.can_promote());
        candidate.agreed = 94;
        assert!(!candidate.can_promote());
        candidate.agreed = 99;
        candidate.shadow_decisions = 99;
        assert!(!candidate.can_promote(), "too few shadow decisions");
        candidate.shadow_decisions = 100;
        candidate.allowed_owner_denials = 1;
        assert!(
            !candidate.can_promote(),
            "an allowed owner denial blocks promotion"
        );
        candidate.shadow_decisions = 0;
        assert_eq!(candidate.agreement(), None);
    }

    #[test]
    fn pattern_state_over_time() {
        let mut pattern = PatternRecord {
            id: 1,
            key: PatternKey {
                agent_id: 1,
                project_dir: "/p".to_owned(),
                items: vec![1],
                policy: String::new(),
                cwd_rel: ".".to_owned(),
                template: "[]".to_owned(),
            },
            display: "x".to_owned(),
            approvals: 2,
            blocked: false,
            created_at: 0,
            last_used_at: 1000,
            uses: 0,
        };
        assert_eq!(pattern.state(1000), PatternState::Learning { approvals: 2 });
        pattern.approvals = 3;
        assert_eq!(pattern.state(1000), PatternState::Active);
        let limit = 1000 + PATTERN_IDLE_DAYS * DAY_SECONDS;
        assert_eq!(pattern.state(limit), PatternState::Active);
        assert_eq!(pattern.state(limit + 1), PatternState::Expired);
        pattern.blocked = true;
        assert_eq!(pattern.state(1000), PatternState::Blocked);
    }
}
