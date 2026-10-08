//! Schema version 10: the change history of each item, the archive, and the extra
//! items of an agent request.
//!
//! The history names what changed. It never holds a secret value: an edit names the
//! fields, a variable its name, a connector its address, a grant its agent.
//!
//! An archived item stays in the vault. The broker refuses each agent request with it,
//! as for an item that waits for the owner review after a restore.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior};

use super::agents::{ActivityRecord, query_activity};
use super::types::{VaultErrorKind, VaultResult, err};
use super::{Vault, to_public_id, to_sql_id};

/// Tables added in schema version 10. Each item that exists at the migration gets a
/// "tracked" event: the history starts then.
pub(super) const SCHEMA_V10_SQL: &str = "
CREATE TABLE item_event (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id INTEGER NOT NULL,
    at INTEGER NOT NULL,
    kind TEXT NOT NULL,
    detail TEXT NOT NULL
);
CREATE INDEX item_event_item ON item_event(item_id, id);
CREATE TABLE item_archive (
    item_id INTEGER PRIMARY KEY,
    archived_at INTEGER NOT NULL
);
CREATE TABLE activity_item (
    activity_id INTEGER NOT NULL,
    item_id INTEGER NOT NULL
);
CREATE INDEX activity_item_item ON activity_item(item_id);
INSERT INTO item_event (item_id, at, kind, detail)
    SELECT id, CAST(strftime('%s', 'now') AS INTEGER), 'tracked', '' FROM item;
UPDATE vault_meta SET schema_version = 10 WHERE id = 1;
PRAGMA user_version = 10;
";

pub(super) const SCHEMA_V10_COLUMNS: [&str; 3] = [
    "SELECT id, item_id, at, kind, detail FROM item_event LIMIT 0",
    "SELECT item_id, archived_at FROM item_archive LIMIT 0",
    "SELECT activity_id, item_id FROM activity_item LIMIT 0",
];

/// The detail of a [`ItemEventKind::Revealed`] event of a fill in the browser starts
/// with this text, then the origin of the page (ADR 0021).
pub const FILL_DETAIL_PREFIX: &str = "browser ";

/// The history keeps this many events for each item. Older events go. The stable
/// conflict-origin metadata is retained separately from this limit.
pub const MAX_ITEM_EVENTS: usize = 200;
/// Longer detail text is cut.
const MAX_EVENT_DETAIL_BYTES: usize = 300;

/// What happened to an item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemEventKind {
    /// The owner added the item.
    Created,
    /// The item existed before schema version 10. Its history starts here.
    Tracked,
    /// The owner changed the item. The detail names the changes (see [`EditChange`]).
    Edited,
    /// The owner showed the secret values.
    Revealed,
    Archived,
    Unarchived,
    /// The detail is the declaration, for example `production, high risk`.
    Declaration,
    /// The detail is the variable name.
    Variable,
    VariableRemoved,
    /// The detail is the connector address.
    Connector,
    ConnectorRemoved,
    /// The detail names the agent, the mode, and the project directory.
    AccessGiven,
    /// The detail names the agent.
    AccessRemoved,
    /// An agent asked for process access (ADR 0012). The detail names the agent.
    AccessRequested,
    /// The owner denied an access request. The detail names the agent.
    AccessDenied,
    /// The detail names the agent.
    RuleChanged,
    /// The detail names the agent and the operation.
    OperationAllowed,
    OperationRemoved,
    /// The item came from a restored backup.
    Restored,
    /// The owner confirmed the agent settings after a restore.
    ReviewConfirmed,
}

impl ItemEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Tracked => "tracked",
            Self::Edited => "edited",
            Self::Revealed => "revealed",
            Self::Archived => "archived",
            Self::Unarchived => "unarchived",
            Self::Declaration => "declaration",
            Self::Variable => "variable",
            Self::VariableRemoved => "variable_removed",
            Self::Connector => "connector",
            Self::ConnectorRemoved => "connector_removed",
            Self::AccessGiven => "access_given",
            Self::AccessRemoved => "access_removed",
            Self::AccessRequested => "access_requested",
            Self::AccessDenied => "access_denied",
            Self::RuleChanged => "rule_changed",
            Self::OperationAllowed => "operation_allowed",
            Self::OperationRemoved => "operation_removed",
            Self::Restored => "restored",
            Self::ReviewConfirmed => "review_confirmed",
        }
    }

    fn parse(text: &str) -> VaultResult<Self> {
        Ok(match text {
            "created" => Self::Created,
            "tracked" => Self::Tracked,
            "edited" => Self::Edited,
            "revealed" => Self::Revealed,
            "archived" => Self::Archived,
            "unarchived" => Self::Unarchived,
            "declaration" => Self::Declaration,
            "variable" => Self::Variable,
            "variable_removed" => Self::VariableRemoved,
            "connector" => Self::Connector,
            "connector_removed" => Self::ConnectorRemoved,
            "access_given" => Self::AccessGiven,
            "access_removed" => Self::AccessRemoved,
            "access_requested" => Self::AccessRequested,
            "access_denied" => Self::AccessDenied,
            "rule_changed" => Self::RuleChanged,
            "operation_allowed" => Self::OperationAllowed,
            "operation_removed" => Self::OperationRemoved,
            "restored" => Self::Restored,
            "review_confirmed" => Self::ReviewConfirmed,
            _ => return Err(err(VaultErrorKind::Storage)),
        })
    }
}

/// One event of the history. It has no secret value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemEvent {
    pub id: u64,
    pub at: u64,
    pub kind: ItemEventKind,
    pub detail: String,
}

/// One change of an edit, from the detail of an [`ItemEventKind::Edited`] event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditChange {
    Title,
    Notes,
    Tags,
    /// A plain field changed, came, or went.
    Field(String),
    /// A secret field changed, came, or went. The value is not in the history.
    Secret(String),
}

impl EditChange {
    fn token(&self) -> String {
        match self {
            Self::Title => "title".to_owned(),
            Self::Notes => "notes".to_owned(),
            Self::Tags => "tags".to_owned(),
            Self::Field(name) => format!("field:{name}"),
            Self::Secret(name) => format!("secret:{name}"),
        }
    }

    /// The changes in the detail of an edit event.
    pub fn parse_detail(detail: &str) -> Vec<Self> {
        detail
            .split(',')
            .filter_map(|token| match token {
                "title" => Some(Self::Title),
                "notes" => Some(Self::Notes),
                "tags" => Some(Self::Tags),
                other => other
                    .strip_prefix("field:")
                    .map(|name| Self::Field(name.to_owned()))
                    .or_else(|| {
                        other
                            .strip_prefix("secret:")
                            .map(|name| Self::Secret(name.to_owned()))
                    }),
            })
            .collect()
    }

    pub(super) fn detail(changes: &[Self]) -> String {
        changes
            .iter()
            .map(Self::token)
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// When an item was added, last changed, and last used by an agent.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ItemTimes {
    /// The first event: the add, or the start of the history.
    pub added: Option<u64>,
    /// The newest event that is not a reveal.
    pub changed: Option<u64>,
    /// The newest agent request with the item that Apassy allowed.
    pub used: Option<u64>,
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        })
}

fn cut(text: &str) -> &str {
    if text.len() <= MAX_EVENT_DETAIL_BYTES {
        return text;
    }
    let mut end = MAX_EVENT_DETAIL_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// Add an event in the transaction of the change, and drop the oldest events of the
/// item above [`MAX_ITEM_EVENTS`].
pub(super) fn record(
    conn: &Connection,
    item: i64,
    kind: ItemEventKind,
    detail: &str,
) -> VaultResult<()> {
    conn.execute(
        "INSERT INTO item_event (item_id, at, kind, detail) VALUES (?1, ?2, ?3, ?4)",
        (item, now_unix(), kind.as_str(), cut(detail)),
    )
    .map_err(|_| err(VaultErrorKind::Storage))?;
    let keep = i64::try_from(MAX_ITEM_EVENTS).map_err(|_| err(VaultErrorKind::Storage))?;
    conn.execute(
        "DELETE FROM item_event WHERE item_id = ?1
             AND NOT (kind = 'created' AND detail LIKE 'apassy:conflict-origin:v1:%')
             AND id NOT IN (SELECT id FROM item_event WHERE item_id = ?1
                 AND NOT (kind = 'created' AND detail LIKE 'apassy:conflict-origin:v1:%')
                 ORDER BY id DESC LIMIT ?2)",
        (item, keep),
    )
    .map_err(|_| err(VaultErrorKind::Storage))?;
    Ok(())
}

/// The name of an agent for an event detail.
pub(super) fn agent_name(conn: &Connection, agent: i64) -> VaultResult<String> {
    conn.query_row("SELECT name FROM agent WHERE id = ?1", [agent], |row| {
        row.get::<_, String>(0)
    })
    .optional()
    .map_err(|_| err(VaultErrorKind::Storage))
    .map(|name| name.unwrap_or_else(|| format!("agent {agent}")))
}

/// Remove the history and the archive state of a deleted item.
pub(super) fn forget_item(conn: &Connection, item: i64) -> VaultResult<()> {
    conn.execute("DELETE FROM item_event WHERE item_id = ?1", [item])
        .map_err(|_| err(VaultErrorKind::Storage))?;
    conn.execute("DELETE FROM item_archive WHERE item_id = ?1", [item])
        .map_err(|_| err(VaultErrorKind::Storage))?;
    Ok(())
}

/// A "restored" event for each item of a restored backup.
pub(super) fn record_restore(conn: &Connection) -> VaultResult<()> {
    conn.execute(
        "INSERT INTO item_event (item_id, at, kind, detail)
         SELECT id, ?1, 'restored', '' FROM item",
        [now_unix()],
    )
    .map_err(|_| err(VaultErrorKind::Storage))?;
    Ok(())
}

/// Link an activity entry to the items of its request after the first one.
pub(super) fn link_activity(conn: &Connection, activity: i64, items: &[u64]) -> VaultResult<()> {
    for item in items {
        conn.execute(
            "INSERT INTO activity_item (activity_id, item_id) VALUES (?1, ?2)",
            (activity, to_sql_id(*item)?),
        )
        .map_err(|_| err(VaultErrorKind::Storage))?;
    }
    Ok(())
}

/// Drop the links of activity entries that are gone.
pub(super) fn prune_activity_links(conn: &Connection) -> VaultResult<()> {
    conn.execute(
        "DELETE FROM activity_item WHERE activity_id NOT IN (SELECT id FROM activity)",
        [],
    )
    .map_err(|_| err(VaultErrorKind::Storage))?;
    Ok(())
}

impl Vault {
    /// The history of one item, newest first.
    pub fn item_events(&self, item_id: u64, limit: usize) -> VaultResult<Vec<ItemEvent>> {
        let item = to_sql_id(item_id)?;
        let limit = i64::try_from(limit.min(MAX_ITEM_EVENTS))
            .map_err(|_| err(VaultErrorKind::InvalidInput))?;
        let conn = self.conn_ref()?;
        let mut stmt = conn
            .prepare(
                "SELECT e.id, e.at, e.kind, e.detail, e.uuid, i.uuid
                 FROM item_event e JOIN item i ON i.id = e.item_id
                 WHERE e.item_id = ?1 ORDER BY e.id DESC LIMIT ?2",
            )
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let rows = stmt
            .query_map((item, limit), |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let mut events = Vec::new();
        for row in rows {
            let (id, at, kind, mut detail, event_uuid, item_uuid) =
                row.map_err(|_| err(VaultErrorKind::Storage))?;
            if kind == "created"
                && super::merge::verified_conflict_origin(&item_uuid, &detail, &event_uuid)
                    .is_some()
            {
                detail = "Sync kept this conflict copy.".to_owned();
            }
            events.push(ItemEvent {
                id: to_public_id(id)?,
                at: u64::try_from(at).map_err(|_| err(VaultErrorKind::Storage))?,
                kind: ItemEventKind::parse(&kind)?,
                detail,
            });
        }
        Ok(events)
    }

    /// Record that the owner showed the secret values of an item. The caller checked
    /// the owner first.
    pub fn record_reveal(&mut self, item_id: u64) -> VaultResult<()> {
        self.record_revealed(item_id, "")
    }

    /// Record a fill in the browser (ADR 0021): a [`ItemEventKind::Revealed`] event with
    /// the detail [`FILL_DETAIL_PREFIX`] and the origin of the page. An older Apassy
    /// reads it as a reveal.
    pub fn record_fill(&mut self, item_id: u64, origin: &str) -> VaultResult<()> {
        self.record_revealed(item_id, &format!("{FILL_DETAIL_PREFIX}{origin}"))
    }

    fn record_revealed(&mut self, item_id: u64, detail: &str) -> VaultResult<()> {
        let item = to_sql_id(item_id)?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        super::agents::require_item(&tx, item)?;
        record(&tx, item, ItemEventKind::Revealed, detail)?;
        tx.commit().map_err(|_| err(VaultErrorKind::Storage))
    }

    /// Archive an item, or bring it back. An archived item stays in the vault, and the
    /// broker refuses each agent request with it. A call that changes nothing records
    /// nothing.
    pub fn set_archived(&mut self, item_id: u64, archived: bool) -> VaultResult<()> {
        let item = to_sql_id(item_id)?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        super::agents::require_item(&tx, item)?;
        let changed = if archived {
            tx.execute(
                "INSERT OR IGNORE INTO item_archive (item_id, archived_at) VALUES (?1, ?2)",
                (item, now_unix()),
            )
        } else {
            tx.execute("DELETE FROM item_archive WHERE item_id = ?1", [item])
        }
        .map_err(|_| err(VaultErrorKind::Storage))?;
        if changed > 0 {
            let kind = if archived {
                ItemEventKind::Archived
            } else {
                ItemEventKind::Unarchived
            };
            record(&tx, item, kind, "")?;
        }
        tx.commit().map_err(|_| err(VaultErrorKind::Storage))
    }

    pub fn is_archived(&self, item_id: u64) -> VaultResult<bool> {
        let item = to_sql_id(item_id)?;
        let found: Option<i64> = self
            .conn_ref()?
            .query_row(
                "SELECT item_id FROM item_archive WHERE item_id = ?1",
                [item],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| err(VaultErrorKind::Storage))?;
        Ok(found.is_some())
    }

    /// Archived items and the time of the archive.
    pub fn archived_items(&self) -> VaultResult<BTreeMap<u64, u64>> {
        let conn = self.conn_ref()?;
        let mut stmt = conn
            .prepare("SELECT item_id, archived_at FROM item_archive")
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let rows = stmt
            .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let mut items = BTreeMap::new();
        for row in rows {
            let (item, at) = row.map_err(|_| err(VaultErrorKind::Storage))?;
            items.insert(
                to_public_id(item)?,
                u64::try_from(at).map_err(|_| err(VaultErrorKind::Storage))?,
            );
        }
        Ok(items)
    }

    /// When each item was added, last changed, and last used, for sorting.
    pub fn item_times(&self) -> VaultResult<BTreeMap<u64, ItemTimes>> {
        let conn = self.conn_ref()?;
        let mut times: BTreeMap<u64, ItemTimes> = BTreeMap::new();
        let time = |at: Option<i64>| at.and_then(|at| u64::try_from(at).ok());
        {
            let mut stmt = conn
                .prepare(
                    "SELECT item_id, MIN(at), MAX(CASE WHEN kind != 'revealed' THEN at END)
                     FROM item_event GROUP BY item_id",
                )
                .map_err(|_| err(VaultErrorKind::Storage))?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Option<i64>>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                    ))
                })
                .map_err(|_| err(VaultErrorKind::Storage))?;
            for row in rows {
                let (item, added, changed) = row.map_err(|_| err(VaultErrorKind::Storage))?;
                let entry = times.entry(to_public_id(item)?).or_default();
                entry.added = time(added);
                entry.changed = time(changed);
            }
        }
        let mut stmt = conn
            .prepare(
                "SELECT item_id, MAX(at) FROM (
                     SELECT item_id, at FROM activity
                         WHERE decision = 'allow' AND item_id IS NOT NULL
                     UNION ALL
                     SELECT activity_item.item_id, activity.at FROM activity_item
                         JOIN activity ON activity.id = activity_item.activity_id
                         WHERE activity.decision = 'allow'
                 ) GROUP BY item_id",
            )
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, Option<i64>>(1)?))
            })
            .map_err(|_| err(VaultErrorKind::Storage))?;
        for row in rows {
            let (item, used) = row.map_err(|_| err(VaultErrorKind::Storage))?;
            times.entry(to_public_id(item)?).or_default().used = time(used);
        }
        Ok(times)
    }

    /// Agent requests with one item, newest first. A request with several items shows
    /// for each of them.
    pub fn item_activity(&self, item_id: u64, limit: usize) -> VaultResult<Vec<ActivityRecord>> {
        let item = to_sql_id(item_id)?;
        let limit = i64::try_from(limit.min(super::MAX_ACTIVITY_ROWS))
            .map_err(|_| err(VaultErrorKind::InvalidInput))?;
        query_activity(
            self.conn_ref()?,
            "SELECT id, at, agent_id, agent_name, item_id, operation, decision, reason
             FROM activity
             WHERE item_id = ?1
                OR id IN (SELECT activity_id FROM activity_item WHERE item_id = ?1)
             ORDER BY id DESC LIMIT ?2",
            (item, limit),
        )
    }

    /// Requests of one agent, newest first.
    pub fn agent_activity(&self, agent_id: u64, limit: usize) -> VaultResult<Vec<ActivityRecord>> {
        let agent = to_sql_id(agent_id)?;
        let limit = i64::try_from(limit.min(super::MAX_ACTIVITY_ROWS))
            .map_err(|_| err(VaultErrorKind::InvalidInput))?;
        query_activity(
            self.conn_ref()?,
            "SELECT id, at, agent_id, agent_name, item_id, operation, decision, reason
             FROM activity WHERE agent_id = ?1 ORDER BY id DESC LIMIT ?2",
            (agent, limit),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edit_details_round_trip_and_hold_names_only() {
        let changes = vec![
            EditChange::Title,
            EditChange::Field("username".to_owned()),
            EditChange::Secret("token".to_owned()),
        ];
        let detail = EditChange::detail(&changes);
        assert_eq!(detail, "title,field:username,secret:token");
        assert_eq!(EditChange::parse_detail(&detail), changes);
        assert!(EditChange::parse_detail("").is_empty());
    }

    #[test]
    fn event_kinds_round_trip() {
        for kind in [
            ItemEventKind::Created,
            ItemEventKind::Tracked,
            ItemEventKind::Edited,
            ItemEventKind::Revealed,
            ItemEventKind::Archived,
            ItemEventKind::Unarchived,
            ItemEventKind::Declaration,
            ItemEventKind::Variable,
            ItemEventKind::VariableRemoved,
            ItemEventKind::Connector,
            ItemEventKind::ConnectorRemoved,
            ItemEventKind::AccessGiven,
            ItemEventKind::AccessRemoved,
            ItemEventKind::RuleChanged,
            ItemEventKind::OperationAllowed,
            ItemEventKind::OperationRemoved,
            ItemEventKind::Restored,
            ItemEventKind::ReviewConfirmed,
        ] {
            assert_eq!(ItemEventKind::parse(kind.as_str()).expect("parse"), kind);
        }
        assert!(ItemEventKind::parse("other").is_err());
    }

    #[test]
    fn a_long_detail_is_cut_on_a_character_boundary() {
        let long = "ż".repeat(MAX_EVENT_DETAIL_BYTES);
        let cut = cut(&long);
        assert!(cut.len() <= MAX_EVENT_DETAIL_BYTES);
        assert!(long.starts_with(cut));
    }
}
