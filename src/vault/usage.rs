//! The use log of each item and the count of owner interactions (ADR 0025 §1, §5). The
//! tables `item_use` and `owner_interaction` are in schema 18 (`schema18.rs`).
//!
//! The broker writes one row for each item of each decided use: allowed, denied,
//! refused, or timed out, and who decided. A row has no secret value: the command is a
//! short summary that the agent sent, and the vault masks the secret values of the item
//! in it before it stores the row, as in the decision log. The detail of an owner
//! interaction is masked the same way.
//!
//! The bouncer counts a use of an item in a project with a kind of action that it allowed
//! itself as history (`item_used_in_project`), but only a use by the same agent, while it
//! is still connected (a restore revokes every agent, so a restored log never counts), and
//! only a use after the last change that made the declaration of the item stricter.
//! History never starts a run: it only lets the run reach the model (ADR 0025 §3).

use rusqlite::OptionalExtension;

use super::agents::{
    Environment, Reversibility, RiskLevel, Scope, from_sql_time, now_unix, to_sql_time,
};
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
    /// Store one use. The secret values of the item are masked in the command summary.
    /// The log drops its oldest rows above [`MAX_ITEM_USE_ROWS`].
    pub fn record_item_use(&mut self, item_use: &NewItemUse) -> VaultResult<u64> {
        let values = self.secret_values(&[item_use.item_id])?;
        let summary = super::learning::mask_values(&item_use.command_summary, &values);
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
                clean(&summary, MAX_COMMAND_SUMMARY_BYTES),
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

    /// True when `agent_id`, while still connected, used the item in the project with
    /// this kind of action, and the bouncer allowed the use. This history lets a run of
    /// an item that is not development with low risk reach the model; it never starts a
    /// run by itself (ADR 0025 §3). Only a use that the bouncer allowed counts: "Allow
    /// once" of the owner stays once, and a use by a remembered answer or pattern stops
    /// when the owner removes the answer or a denial blocks the pattern. A use of another
    /// agent does not count, so a new agent has no history. A use by a revoked agent, for
    /// example every use before a restore, does not count. A use before the last change
    /// that made the declaration of the item stricter does not count either.
    pub fn item_used_in_project(
        &self,
        item_id: u64,
        project_key: &str,
        action: ActionKind,
        agent_id: u64,
    ) -> VaultResult<bool> {
        if project_key.is_empty() {
            return Ok(false);
        }
        let item = to_sql_id(item_id)?;
        let agent = to_sql_id(agent_id)?;
        let conn = self.conn_ref()?;
        let since = stricter_since(conn, item)?;
        let found: Option<i64> = conn
            .query_row(
                "SELECT u.id FROM item_use u JOIN agent a ON a.id = u.agent_id
                 WHERE u.item_id = ?1 AND u.project_key = ?2 AND u.action_kind = ?3
                     AND u.agent_id = ?4 AND u.at > ?5
                     AND u.outcome = 'allowed' AND u.decided_by = 'bouncer'
                     AND a.revoked_at IS NULL
                 LIMIT 1",
                rusqlite::params![item, project_key, action.as_str(), agent, since],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| err(VaultErrorKind::Storage))?;
        Ok(found.is_some())
    }

    /// Count one owner interaction. The secret values of `items` are masked in `detail`.
    pub fn record_interaction(
        &mut self,
        kind: InteractionKind,
        detail: &str,
        items: &[u64],
    ) -> VaultResult<()> {
        let values = self.secret_values(items)?;
        let detail = super::learning::mask_values(detail, &values);
        let at = to_sql_time(now_unix())?;
        let conn = self.conn_mut()?;
        conn.execute(
            "INSERT INTO owner_interaction (at, kind, detail) VALUES (?1, ?2, ?3)",
            (at, kind.as_str(), clean(&detail, 200)),
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

/// One declaration as a declaration event of the item history names it:
/// `ENVIRONMENT, RISK risk, SCOPE, REVERSIBILITY[, provider P]`.
type EventDeclaration = (Environment, RiskLevel, Scope, Reversibility);

fn event_declaration(detail: &str) -> Option<EventDeclaration> {
    let mut parts = detail.split(", ");
    let environment = Environment::parse(parts.next()?).ok()?;
    let risk = RiskLevel::parse(parts.next()?.strip_suffix(" risk")?).ok()?;
    let scope = Scope::parse(parts.next()?).ok()?;
    let reversibility = Reversibility::parse(parts.next()?).ok()?;
    Some((environment, risk, scope, reversibility))
}

/// The time of the last declaration event that made the declaration of `item` stricter:
/// an environment nearer to production, a higher risk, a wider scope, or a less
/// reversible action. An event that does not read counts as stricter; the first
/// declaration does not. 0 when there is none, so every use counts.
fn stricter_since(conn: &rusqlite::Connection, item: i64) -> VaultResult<i64> {
    let mut stmt = conn
        .prepare(
            "SELECT at, detail FROM item_event
             WHERE item_id = ?1 AND kind = 'declaration' ORDER BY at, id",
        )
        .map_err(|_| err(VaultErrorKind::Storage))?;
    let rows = stmt
        .query_map([item], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|_| err(VaultErrorKind::Storage))?;
    let mut since = 0;
    let mut seen = false;
    let mut before: Option<EventDeclaration> = None;
    for row in rows {
        let (at, detail) = row.map_err(|_| err(VaultErrorKind::Storage))?;
        let now = event_declaration(&detail);
        let stricter = match (before, now) {
            (Some(old), Some(new)) => {
                new.0 > old.0 || new.1 > old.1 || new.2 > old.2 || new.3 > old.3
            }
            // The first declaration: no use was allowed without one.
            (None, Some(_)) if !seen => false,
            _ => true,
        };
        if stricter {
            since = since.max(at);
        }
        seen = true;
        before = now;
    }
    Ok(since)
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
                .item_used_in_project(item, "/tmp/p/.git", ActionKind::Read, agent.id)
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
                    .item_used_in_project(item, "/tmp/p/.git", ActionKind::Read, agent.id)
                    .unwrap(),
                "{by:?} is no history"
            );
        }
        new.outcome = UseOutcome::Allowed;
        new.decided_by = UseDecidedBy::Bouncer;
        vault.record_item_use(&new).unwrap();
        assert!(
            vault
                .item_used_in_project(item, "/tmp/p/.git", ActionKind::Read, agent.id)
                .unwrap()
        );
        for (key, action) in [
            ("/tmp/p/.git", ActionKind::Change),
            ("/tmp/q", ActionKind::Read),
            ("", ActionKind::Read),
        ] {
            assert!(!vault.item_used_in_project(item, key, action, agent.id).unwrap());
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
                .item_used_in_project(item, "/tmp/p/.git", ActionKind::Read, agent.id)
                .unwrap()
        );
    }

    /// Gate 1 (B-4): the use log and the interaction count mask the secret values of the
    /// item.
    #[test]
    fn summaries_and_interaction_details_are_masked() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut vault = Vault::create(&dir.path().join("usage.db"), PASS).unwrap();
        vault.unlock(PASS).unwrap();
        let secret = "SYNTH-mask-me-4471";
        let item = vault
            .add(ItemDraft {
                title: "Synthetic".to_owned(),
                kind: CredentialKind::ApiKey,
                notes: String::new(),
                tags: Vec::new(),
                fields: vec![Field {
                    name: "token".to_owned(),
                    value: SecretValue::new(secret.to_owned()),
                    secret: true,
                }],
            })
            .unwrap()
            .id;
        vault
            .record_item_use(&NewItemUse {
                item_id: item,
                agent_id: None,
                agent_name: "Synthetic".to_owned(),
                project_key: String::new(),
                project_label: String::new(),
                action: ActionKind::Read,
                command_summary: format!("run curl -H 'Bearer {secret}'"),
                hosts: Vec::new(),
                outcome: UseOutcome::Denied,
                decided_by: UseDecidedBy::Owner,
                answered_on: String::new(),
                decision_log_id: None,
            })
            .unwrap();
        let uses = vault.item_uses(item, 1).unwrap();
        assert!(!uses[0].command_summary.contains(secret));
        assert!(uses[0].command_summary.contains("[apassy:secret]"));
        vault
            .record_interaction(
                InteractionKind::Question,
                &format!("run echo {secret}"),
                &[item],
            )
            .unwrap();
        let detail: String = vault
            .conn_ref()
            .unwrap()
            .query_row("SELECT detail FROM owner_interaction", [], |row| row.get(0))
            .unwrap();
        assert_eq!(detail, "run echo [apassy:secret]");
    }

    /// Gate 1 (A-3): a stricter declaration ends the history of the item; a looser one
    /// does not.
    #[test]
    fn a_stricter_declaration_clears_history() {
        use crate::vault::Declaration;
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
                    value: SecretValue::new("SYNTH-history".to_owned()),
                    secret: true,
                }],
            })
            .unwrap()
            .id;
        let (agent, _) = vault.register_agent("Synthetic").unwrap();
        let declaration = |environment, risk| Declaration {
            project: "p".to_owned(),
            environment,
            risk,
            scope: Scope::ReadWrite,
            reversibility: Reversibility::Reversible,
        };
        vault
            .set_declaration(item, &declaration(Environment::Staging, RiskLevel::Medium))
            .unwrap();
        let use_at = |vault: &mut Vault, at: i64| {
            vault
                .conn_mut()
                .unwrap()
                .execute(
                    "INSERT INTO item_use (at, item_id, agent_id, agent_name, project_key,
                         project_label, action_kind, command_summary, hosts, outcome,
                         decided_by)
                     VALUES (?1, ?2, ?3, 'a', '/tmp/p', 'p', 'read', 'run', '[]',
                         'allowed', 'bouncer')",
                    rusqlite::params![
                        at,
                        i64::try_from(item).unwrap(),
                        i64::try_from(agent.id).unwrap()
                    ],
                )
                .unwrap();
        };
        let used = |vault: &Vault| {
            vault
                .item_used_in_project(item, "/tmp/p", ActionKind::Read, agent.id)
                .unwrap()
        };
        // A use long ago: the first declaration is no cutoff.
        use_at(&mut vault, 1);
        assert!(used(&vault));
        // A looser declaration keeps the history.
        vault
            .set_declaration(item, &declaration(Environment::Development, RiskLevel::Low))
            .unwrap();
        assert!(used(&vault));
        // A stricter one ends it, also for a later environment change toward production.
        vault
            .set_declaration(item, &declaration(Environment::Development, RiskLevel::High))
            .unwrap();
        assert!(!used(&vault));
        // A use after the change counts again.
        use_at(&mut vault, i64::MAX / 2);
        assert!(used(&vault));
    }

    #[test]
    fn interactions_are_counted_per_week() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut vault = Vault::create(&dir.path().join("usage.db"), PASS).unwrap();
        vault.unlock(PASS).unwrap();
        vault
            .record_interaction(InteractionKind::OwnerCheck, "approve a run", &[])
            .unwrap();
        vault
            .record_interaction(InteractionKind::Question, "question", &[])
            .unwrap();
        let weeks = vault.interactions_per_week(3).unwrap();
        assert_eq!(weeks.len(), 3);
        assert_eq!(weeks[2].1, 2);
        assert_eq!(weeks[0].1 + weeks[1].1, 0);
        assert!(weeks[0].0 < weeks[1].0);
    }
}
