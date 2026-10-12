//! The use log of each item and the count of owner interactions (ADR 0025 §1, §5). The
//! tables `item_use` and `owner_interaction` are in schema 18 (`schema18.rs`).
//!
//! The broker writes one row for each item of each decided use: allowed, denied,
//! refused, or timed out, and who decided. A row has no secret value: the command is a
//! short summary that the agent sent. The bouncer counts a use of an item in a project
//! with a kind of action that it allowed itself as history (`item_used_in_project`), but
//! only a use by an agent that is still connected: a restore revokes every agent, so a restored log
//! never lets a run start without a question.

use rusqlite::OptionalExtension;

use super::agents::{from_sql_time, now_unix, to_sql_time};
use super::types::{VaultErrorKind, VaultResult, err};
use super::{Vault, to_public_id, to_sql_id};
use crate::broker::action_kind::ActionKind;

/// The longest command summary, in bytes.
pub const MAX_COMMAND_SUMMARY_BYTES: usize = 256;
/// At most this many hosts are stored for one use.
pub const MAX_USE_HOSTS: usize = 16;
/// The log keeps at most this many rows. Older rows go first.
pub const MAX_ITEM_USE_ROWS: i64 = 50_000;
/// The interaction count keeps at most this many rows.
pub const MAX_INTERACTION_ROWS: i64 = 20_000;
const WEEK_SECONDS: u64 = 7 * 24 * 3600;

/// The end of one use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UseOutcome {
    Allowed,
    Denied,
    Refused,
    TimedOut,
}

impl UseOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Denied => "denied",
            Self::Refused => "refused",
            Self::TimedOut => "timed_out",
        }
    }

    fn parse(text: &str) -> VaultResult<Self> {
        match text {
            "allowed" => Ok(Self::Allowed),
            "denied" => Ok(Self::Denied),
            "refused" => Ok(Self::Refused),
            "timed_out" => Ok(Self::TimedOut),
            _ => Err(err(VaultErrorKind::Storage)),
        }
    }
}

/// Who decided one use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UseDecidedBy {
    /// The bouncer: the context or the model.
    Bouncer,
    /// A remembered pattern (ADR 0010).
    Pattern,
    /// A remembered answer of the owner (ADR 0025 §3).
    Answer,
    /// The owner answered the question of this use.
    Owner,
    /// A hard rule or a request check.
    Rule,
}

impl UseDecidedBy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bouncer => "bouncer",
            Self::Pattern => "pattern",
            Self::Answer => "answer",
            Self::Owner => "owner",
            Self::Rule => "rule",
        }
    }

    fn parse(text: &str) -> VaultResult<Self> {
        match text {
            "bouncer" => Ok(Self::Bouncer),
            "pattern" => Ok(Self::Pattern),
            "answer" => Ok(Self::Answer),
            "owner" => Ok(Self::Owner),
            "rule" => Ok(Self::Rule),
            _ => Err(err(VaultErrorKind::Storage)),
        }
    }
}

/// One use to store. The project key and label are empty when the working directory
/// is too wide to be a project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewItemUse {
    pub item_id: u64,
    pub agent_id: Option<u64>,
    pub agent_name: String,
    pub project_key: String,
    pub project_label: String,
    pub action: ActionKind,
    pub command_summary: String,
    pub hosts: Vec<String>,
    pub outcome: UseOutcome,
    pub decided_by: UseDecidedBy,
    /// The device where the owner answered. Empty for a decision without the owner.
    pub answered_on: String,
    pub decision_log_id: Option<u64>,
}

/// One stored use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemUse {
    pub id: u64,
    pub at: u64,
    pub item_id: u64,
    pub agent_id: Option<u64>,
    pub agent_name: String,
    pub project_key: String,
    pub project_label: String,
    pub action: ActionKind,
    pub command_summary: String,
    pub hosts: Vec<String>,
    pub outcome: UseOutcome,
    pub decided_by: UseDecidedBy,
    pub answered_on: String,
    pub decision_log_id: Option<u64>,
}

/// A summary of the use of one item.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UseSummary {
    pub total: u64,
    pub allowed: u64,
    pub projects: u64,
    pub agents: u64,
    pub last_at: Option<u64>,
}

/// One kind of owner interaction (ADR 0025 §1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InteractionKind {
    /// A question waited for the owner.
    Question,
    /// The owner approved a run.
    Approval,
    /// The owner passed an owner check.
    OwnerCheck,
    /// The owner answered a correction.
    Correction,
}

impl InteractionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Question => "question",
            Self::Approval => "approval",
            Self::OwnerCheck => "owner_check",
            Self::Correction => "correction",
        }
    }
}

/// Printable text without control characters, cut at `max` bytes.
fn clean(text: &str, max: usize) -> String {
    let clean: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let clean = clean.trim();
    let mut end = clean.len().min(max);
    while !clean.is_char_boundary(end) {
        end -= 1;
    }
    clean[..end].to_owned()
}

type UseRow = (
    i64,
    i64,
    i64,
    Option<i64>,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    Option<i64>,
);

const USE_COLUMNS: &str = "id, at, item_id, agent_id, agent_name, project_key, project_label,
     action_kind, command_summary, hosts, outcome, decided_by, answered_on, decision_log_id";

fn use_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<UseRow> {
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
        row.get(13)?,
    ))
}

fn parse_use(row: UseRow) -> VaultResult<ItemUse> {
    let (id, at, item, agent, agent_name, key, label, action, summary, hosts, outcome, by, on, log) =
        row;
    fn storage<E>(_: E) -> super::types::VaultError {
        err(VaultErrorKind::Storage)
    }
    Ok(ItemUse {
        id: to_public_id(id)?,
        at: from_sql_time(at)?,
        item_id: to_public_id(item)?,
        agent_id: agent.map(to_public_id).transpose()?,
        agent_name,
        project_key: key,
        project_label: label,
        action: ActionKind::parse(&action).ok_or_else(|| err(VaultErrorKind::Storage))?,
        command_summary: summary,
        hosts: serde_json::from_str(&hosts).map_err(storage)?,
        outcome: UseOutcome::parse(&outcome)?,
        decided_by: UseDecidedBy::parse(&by)?,
        answered_on: on,
        decision_log_id: log
            .map(|id| u64::try_from(id).map_err(storage))
            .transpose()?,
    })
}

impl Vault {
    /// Store one use. The log drops its oldest rows above [`MAX_ITEM_USE_ROWS`].
    pub fn record_item_use(&mut self, item_use: &NewItemUse) -> VaultResult<u64> {
        let item = to_sql_id(item_use.item_id)?;
        let agent = item_use.agent_id.map(to_sql_id).transpose()?;
        let hosts: Vec<String> = item_use
            .hosts
            .iter()
            .take(MAX_USE_HOSTS)
            .map(|host| clean(host, 253))
            .filter(|host| !host.is_empty())
            .collect();
        let hosts = serde_json::to_string(&hosts).map_err(|_| err(VaultErrorKind::Storage))?;
        let log = item_use
            .decision_log_id
            .map(|id| i64::try_from(id).map_err(|_| err(VaultErrorKind::InvalidInput)))
            .transpose()?;
        let at = to_sql_time(now_unix())?;
        let conn = self.conn_mut()?;
        conn.execute(
            "INSERT INTO item_use (at, item_id, agent_id, agent_name, project_key, project_label,
                 action_kind, command_summary, hosts, outcome, decided_by, answered_on,
                 decision_log_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            rusqlite::params![
                at,
                item,
                agent,
                clean(&item_use.agent_name, 64),
                clean(&item_use.project_key, 4096),
                clean(&item_use.project_label, 256),
                item_use.action.as_str(),
                clean(&item_use.command_summary, MAX_COMMAND_SUMMARY_BYTES),
                hosts,
                item_use.outcome.as_str(),
                item_use.decided_by.as_str(),
                clean(&item_use.answered_on, 64),
                log,
            ],
        )
        .map_err(|_| err(VaultErrorKind::Storage))?;
        let id = conn.last_insert_rowid();
        if id % 256 == 0 {
            conn.execute(
                "DELETE FROM item_use WHERE id <= ?1",
                [id - MAX_ITEM_USE_ROWS],
            )
            .map_err(|_| err(VaultErrorKind::Storage))?;
        }
        to_public_id(id)
    }

    /// The newest uses of one item, newest first.
    pub fn item_uses(&self, item_id: u64, limit: usize) -> VaultResult<Vec<ItemUse>> {
        self.query_uses("item_id", to_sql_id(item_id)?, limit)
    }

    /// The newest uses by one agent, newest first.
    pub fn agent_uses(&self, agent_id: u64, limit: usize) -> VaultResult<Vec<ItemUse>> {
        self.query_uses("agent_id", to_sql_id(agent_id)?, limit)
    }

    fn query_uses(&self, column: &str, id: i64, limit: usize) -> VaultResult<Vec<ItemUse>> {
        let limit = i64::try_from(limit).map_err(|_| err(VaultErrorKind::InvalidInput))?;
        let conn = self.conn_ref()?;
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {USE_COLUMNS} FROM item_use WHERE {column} = ?1 ORDER BY id DESC LIMIT ?2"
            ))
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let rows = stmt
            .query_map((id, limit), use_row)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let mut uses = Vec::new();
        for row in rows {
            uses.push(parse_use(row.map_err(|_| err(VaultErrorKind::Storage))?)?);
        }
        Ok(uses)
    }

    /// Counts for the item screen.
    pub fn item_use_summary(&self, item_id: u64) -> VaultResult<UseSummary> {
        let item = to_sql_id(item_id)?;
        let row: (i64, i64, i64, i64, Option<i64>) = self
            .conn_ref()?
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(outcome = 'allowed'), 0),
                     COUNT(DISTINCT NULLIF(project_key, '')), COUNT(DISTINCT agent_id), MAX(at)
                 FROM item_use WHERE item_id = ?1",
                [item],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let count = |n: i64| u64::try_from(n).map_err(|_| err(VaultErrorKind::Storage));
        Ok(UseSummary {
            total: count(row.0)?,
            allowed: count(row.1)?,
            projects: count(row.2)?,
            agents: count(row.3)?,
            last_at: row.4.map(from_sql_time).transpose()?,
        })
    }

    /// True when an agent that is still connected used the item in the project with
    /// this kind of action, and the bouncer allowed the use. This is the history that
    /// lets the bouncer start a run without a question (ADR 0025 §3). Only a use that the
    /// bouncer allowed counts: "Allow once" of the owner stays once, and a use by a
    /// remembered answer or pattern stops when the owner removes the answer or a
    /// denial blocks the pattern. A use by a revoked agent, for example every use
    /// before a restore, does not count.
    pub fn item_used_in_project(
        &self,
        item_id: u64,
        project_key: &str,
        action: ActionKind,
    ) -> VaultResult<bool> {
        if project_key.is_empty() {
            return Ok(false);
        }
        let item = to_sql_id(item_id)?;
        let found: Option<i64> = self
            .conn_ref()?
            .query_row(
                "SELECT u.id FROM item_use u JOIN agent a ON a.id = u.agent_id
                 WHERE u.item_id = ?1 AND u.project_key = ?2 AND u.action_kind = ?3
                     AND u.outcome = 'allowed' AND u.decided_by = 'bouncer'
                     AND a.revoked_at IS NULL
                 LIMIT 1",
                (item, project_key, action.as_str()),
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| err(VaultErrorKind::Storage))?;
        Ok(found.is_some())
    }

    /// Count one owner interaction. `detail` has no secret value.
    pub fn record_interaction(&mut self, kind: InteractionKind, detail: &str) -> VaultResult<()> {
        let at = to_sql_time(now_unix())?;
        let conn = self.conn_mut()?;
        conn.execute(
            "INSERT INTO owner_interaction (at, kind, detail) VALUES (?1, ?2, ?3)",
            (at, kind.as_str(), clean(detail, 200)),
        )
        .map_err(|_| err(VaultErrorKind::Storage))?;
        let id = conn.last_insert_rowid();
        if id % 256 == 0 {
            conn.execute(
                "DELETE FROM owner_interaction WHERE id <= ?1",
                [id - MAX_INTERACTION_ROWS],
            )
            .map_err(|_| err(VaultErrorKind::Storage))?;
        }
        Ok(())
    }

    /// The count of owner interactions in each of the last `weeks` weeks, oldest first:
    /// (start of the week as Unix time, count). A week starts 7 days before the next one,
    /// and the last week ends now.
    pub fn interactions_per_week(&self, weeks: usize) -> VaultResult<Vec<(u64, u64)>> {
        let now = now_unix();
        let weeks = u64::try_from(weeks).map_err(|_| err(VaultErrorKind::InvalidInput))?;
        let conn = self.conn_ref()?;
        let mut out = Vec::new();
        for back in (0..weeks).rev() {
            let end = now.saturating_sub(back * WEEK_SECONDS);
            let start = end.saturating_sub(WEEK_SECONDS);
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM owner_interaction WHERE at > ?1 AND at <= ?2",
                    (to_sql_time(start)?, to_sql_time(end)?),
                    |row| row.get(0),
                )
                .map_err(|_| err(VaultErrorKind::Storage))?;
            out.push((
                start,
                u64::try_from(count).map_err(|_| err(VaultErrorKind::Storage))?,
            ));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::CredentialKind;
    use crate::vault::{Field, ItemDraft, SecretValue};

    const PASS: &str = "synthetic-usage-pass";

    #[test]
    fn uses_round_trip_and_history_needs_a_connected_agent() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut vault = Vault::create(&dir.path().join("usage.db"), PASS).unwrap();
        vault.unlock(PASS).unwrap();
        let item = vault
            .add(ItemDraft {
                title: "Synthetic".to_owned(),
                kind: CredentialKind::ApiKey,
                notes: String::new(),
                tags: Vec::new(),
                fields: vec![Field {
                    name: "token".to_owned(),
                    value: SecretValue::new("SYNTH-usage".to_owned()),
                    secret: true,
                }],
            })
            .unwrap()
            .id;
        let (agent, _) = vault.register_agent("Synthetic").unwrap();
        let mut new = NewItemUse {
            item_id: item,
            agent_id: Some(agent.id),
            agent_name: "Synthetic".to_owned(),
            project_key: "/tmp/p/.git".to_owned(),
            project_label: "p".to_owned(),
            action: ActionKind::Read,
            command_summary: "run gh api\nuser".to_owned(),
            hosts: vec!["api.github.com".to_owned()],
            outcome: UseOutcome::Denied,
            decided_by: UseDecidedBy::Owner,
            answered_on: String::new(),
            decision_log_id: Some(4),
        };
        vault.record_item_use(&new).unwrap();
        assert!(
            !vault
                .item_used_in_project(item, "/tmp/p/.git", ActionKind::Read)
                .unwrap(),
            "a denial is no history"
        );
        for by in [
            UseDecidedBy::Owner,
            UseDecidedBy::Answer,
            UseDecidedBy::Pattern,
        ] {
            new.outcome = UseOutcome::Allowed;
            new.decided_by = by;
            vault.record_item_use(&new).unwrap();
            assert!(
                !vault
                    .item_used_in_project(item, "/tmp/p/.git", ActionKind::Read)
                    .unwrap(),
                "{by:?} is no history"
            );
        }
        new.outcome = UseOutcome::Allowed;
        new.decided_by = UseDecidedBy::Bouncer;
        vault.record_item_use(&new).unwrap();
        assert!(
            vault
                .item_used_in_project(item, "/tmp/p/.git", ActionKind::Read)
                .unwrap()
        );
        for (key, action) in [
            ("/tmp/p/.git", ActionKind::Change),
            ("/tmp/q", ActionKind::Read),
            ("", ActionKind::Read),
        ] {
            assert!(!vault.item_used_in_project(item, key, action).unwrap());
        }
        let uses = vault.item_uses(item, 10).unwrap();
        assert_eq!(uses.len(), 5);
        assert_eq!(uses[0].outcome, UseOutcome::Allowed);
        assert_eq!(uses[0].command_summary, "run gh api user");
        assert_eq!(uses[0].hosts, vec!["api.github.com".to_owned()]);
        assert_eq!(vault.agent_uses(agent.id, 1).unwrap().len(), 1);
        let summary = vault.item_use_summary(item).unwrap();
        assert_eq!((summary.total, summary.allowed), (5, 4));
        assert_eq!((summary.projects, summary.agents), (1, 1));
        // A revoked agent builds no history.
        vault.revoke_agent(agent.id).unwrap();
        assert!(
            !vault
                .item_used_in_project(item, "/tmp/p/.git", ActionKind::Read)
                .unwrap()
        );
    }

    #[test]
    fn interactions_are_counted_per_week() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut vault = Vault::create(&dir.path().join("usage.db"), PASS).unwrap();
        vault.unlock(PASS).unwrap();
        vault
            .record_interaction(InteractionKind::OwnerCheck, "approve a run")
            .unwrap();
        vault
            .record_interaction(InteractionKind::Question, "question")
            .unwrap();
        let weeks = vault.interactions_per_week(3).unwrap();
        assert_eq!(weeks.len(), 3);
        assert_eq!(weeks[2].1, 2);
        assert_eq!(weeks[0].1 + weeks[1].1, 0);
        assert!(weeks[0].0 < weeks[1].0);
    }
}
