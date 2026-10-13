//! Exceptions of one agent for one item (ADR 0025 §3f): "Not for this agent", "Always
//! ask for this agent", and "only these items". The table `agent_exception` is in
//! schema 18 (`schema18.rs`).
//!
//! Without an exception, a connected agent may use every item that is not archived; the
//! bouncer decides each use. An exception only makes this stricter:
//!
//! - `never`: the agent never gets the item. The catalog hides it and a run gets
//!   `not_granted`.
//! - `always_ask`: each use of the item by the agent waits for the owner.
//! - `only`: the agent is restricted to its listed items. The row with item
//!   [`ONLY_MARKER_ITEM`] marks the restriction, so an agent with no listed item sees
//!   nothing. An agent that does not see all credentials (`agent.see_all = 0`, ADR 0012)
//!   is restricted the same way, and its process and connector grants count as listed
//!   items: the owner gave each with an owner check. A `never` row wins over a listed item.
//!
//! Adding `never` or `always_ask` takes authority away and needs no owner check. Removing
//! one, and adding an item to the `only` list, gives authority: the caller asks for the
//! owner check first (`OwnerAction::RemoveAgentException`).

use std::collections::BTreeSet;

use rusqlite::{Connection, OptionalExtension, TransactionBehavior};

use super::agents::{from_sql_time, now_unix, require_active_agent, require_item, to_sql_time};
use super::schema18::ONLY_MARKER_ITEM;
use super::types::{VaultErrorKind, VaultResult, err};
use super::{Vault, to_public_id, to_sql_id};

/// The longest sentence about an agent, in bytes (ADR 0025 §3f).
pub const MAX_AGENT_NOTE_BYTES: usize = 500;

/// One kind of exception.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ExceptionKind {
    /// "Not for this agent".
    Never,
    /// "Always ask for this agent".
    AlwaysAsk,
    /// "Only these items": the item is on the list of the agent.
    Only,
}

impl ExceptionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Never => "never",
            Self::AlwaysAsk => "always_ask",
            Self::Only => "only",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "never" => Some(Self::Never),
            "always_ask" => Some(Self::AlwaysAsk),
            "only" => Some(Self::Only),
            _ => None,
        }
    }
}

/// What one agent may do with one item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// The bouncer decides each use.
    Normal,
    /// Each use waits for the owner.
    AlwaysAsk,
    /// The agent never gets the item, and does not see it.
    Never,
}

/// One stored exception.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentException {
    pub agent_id: u64,
    pub item_id: u64,
    pub kind: ExceptionKind,
    pub created_at: u64,
}

/// The exceptions of one agent, read once. The broker and the catalog ask it for each
/// item.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentView {
    /// The agent is restricted to `listed`.
    pub restricted: bool,
    /// The listed items of a restricted agent: `only` rows, process grants, and
    /// connector grants.
    pub listed: BTreeSet<u64>,
    pub never: BTreeSet<u64>,
    pub always_ask: BTreeSet<u64>,
}

impl AgentView {
    /// The agent sees the item in the catalog and may use it.
    pub fn visible(&self, item_id: u64) -> bool {
        item_id != ONLY_MARKER_ITEM
            && !self.never.contains(&item_id)
            && (!self.restricted || self.listed.contains(&item_id))
    }

    pub fn standing(&self, item_id: u64) -> Standing {
        if !self.visible(item_id) {
            Standing::Never
        } else if self.always_ask.contains(&item_id) {
            Standing::AlwaysAsk
        } else {
            Standing::Normal
        }
    }
}

fn storage<E>(_: E) -> super::types::VaultError {
    err(VaultErrorKind::Storage)
}

/// Read the view of `agent`. An unknown or revoked agent sees nothing.
pub(super) fn view_in(conn: &Connection, agent: i64) -> VaultResult<AgentView> {
    let see_all: Option<(i64, Option<i64>)> = conn
        .query_row(
            "SELECT see_all, revoked_at FROM agent WHERE id = ?1",
            [agent],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(storage)?;
    let Some((see_all, None)) = see_all else {
        return Ok(AgentView {
            restricted: true,
            ..AgentView::default()
        });
    };
    let mut view = AgentView {
        restricted: see_all != 1,
        ..AgentView::default()
    };
    let mut stmt = conn
        .prepare("SELECT item_id, kind FROM agent_exception WHERE agent_id = ?1")
        .map_err(storage)?;
    let rows = stmt
        .query_map([agent], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(storage)?;
    for row in rows {
        let (item, kind) = row.map_err(storage)?;
        let item = u64::try_from(item).map_err(storage)?;
        match ExceptionKind::parse(&kind).ok_or_else(|| err(VaultErrorKind::Storage))? {
            ExceptionKind::Never => {
                view.never.insert(item);
            }
            ExceptionKind::AlwaysAsk => {
                view.always_ask.insert(item);
            }
            ExceptionKind::Only => {
                view.restricted = true;
                if item != ONLY_MARKER_ITEM {
                    view.listed.insert(item);
                }
            }
        }
    }
    if view.restricted {
        let mut grants = conn
            .prepare(
                "SELECT item_id FROM exec_grant WHERE agent_id = ?1
                 UNION SELECT item_id FROM grant_rule WHERE agent_id = ?1",
            )
            .map_err(storage)?;
        let rows = grants
            .query_map([agent], |row| row.get::<_, i64>(0))
            .map_err(storage)?;
        for row in rows {
            view.listed
                .insert(u64::try_from(row.map_err(storage)?).map_err(storage)?);
        }
    }
    Ok(view)
}

/// Add the marker of "only these items" to `agent`. The agent then sees only its listed
/// items. It takes authority away.
pub(super) fn restrict_in(tx: &rusqlite::Transaction<'_>, agent: i64) -> VaultResult<()> {
    tx.execute(
        "INSERT OR IGNORE INTO agent_exception (agent_id, item_id, kind, created_at)
         VALUES (?1, ?2, 'only', ?3)",
        (
            agent,
            i64::try_from(ONLY_MARKER_ITEM).map_err(storage)?,
            to_sql_time(now_unix())?,
        ),
    )
    .map_err(storage)?;
    Ok(())
}

/// Remove "only these items" of `agent`: the marker and the listed items.
pub(super) fn unrestrict_in(tx: &rusqlite::Transaction<'_>, agent: i64) -> VaultResult<()> {
    tx.execute(
        "DELETE FROM agent_exception WHERE agent_id = ?1 AND kind = 'only'",
        [agent],
    )
    .map_err(storage)?;
    Ok(())
}

impl Vault {
    /// The sentence of the owner about an agent. Empty when there is none.
    /// `NotFound`: no such agent.
    pub fn agent_note(&self, agent_id: u64) -> VaultResult<String> {
        let agent = to_sql_id(agent_id)?;
        self.conn_ref()?
            .query_row("SELECT note FROM agent WHERE id = ?1", [agent], |row| {
                row.get(0)
            })
            .optional()
            .map_err(storage)?
            .ok_or_else(|| err(VaultErrorKind::NotFound))
    }

    /// Store the sentence about an active agent. It is a hint for the bouncer, not a
    /// limit. Control characters become spaces. `InvalidInput`: longer than
    /// [`MAX_AGENT_NOTE_BYTES`].
    pub fn set_agent_note(&mut self, agent_id: u64, note: &str) -> VaultResult<()> {
        let agent = to_sql_id(agent_id)?;
        let note: String = note
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
        let note = note.trim();
        if note.len() > MAX_AGENT_NOTE_BYTES {
            return Err(err(VaultErrorKind::InvalidInput));
        }
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        require_active_agent(&tx, agent)?;
        tx.execute("UPDATE agent SET note = ?1 WHERE id = ?2", (note, agent))
            .map_err(storage)?;
        tx.commit().map_err(storage)
    }

    /// Add one exception. The same exception again changes nothing.
    ///
    /// `never` and `always_ask` take authority away and need no owner check. An `only`
    /// row restricts the agent to its listed items (the marker is added with the first
    /// one); adding an item to the list of an agent that is already restricted gives
    /// access, so the caller asks for the owner check first.
    /// `NotFound`: no such agent or item. `InvalidInput`: the agent is revoked, or the
    /// item is the marker.
    pub fn add_agent_exception(
        &mut self,
        agent_id: u64,
        item_id: u64,
        kind: ExceptionKind,
    ) -> VaultResult<()> {
        if item_id == ONLY_MARKER_ITEM {
            return Err(err(VaultErrorKind::InvalidInput));
        }
        let agent = to_sql_id(agent_id)?;
        let item = to_sql_id(item_id)?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        require_active_agent(&tx, agent)?;
        require_item(&tx, item)?;
        if kind == ExceptionKind::Only {
            restrict_in(&tx, agent)?;
        }
        tx.execute(
            "INSERT OR IGNORE INTO agent_exception (agent_id, item_id, kind, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            (agent, item, kind.as_str(), to_sql_time(now_unix())?),
        )
        .map_err(storage)?;
        tx.commit().map_err(storage)
    }

    /// Remove one exception. Returns false when there was none.
    ///
    /// Removing `never` or `always_ask` gives authority back: the caller asks for the
    /// owner check first. Removing a listed `only` item takes authority away. The
    /// marker ([`ONLY_MARKER_ITEM`]) is removed only with all listed items, by
    /// `set_agent_sees_all(agent, true)`, so it is refused here.
    pub fn remove_agent_exception(
        &mut self,
        agent_id: u64,
        item_id: u64,
        kind: ExceptionKind,
    ) -> VaultResult<bool> {
        if kind == ExceptionKind::Only && item_id == ONLY_MARKER_ITEM {
            return Err(err(VaultErrorKind::InvalidInput));
        }
        let agent = to_sql_id(agent_id)?;
        let item = to_sql_id(item_id)?;
        let removed = self
            .conn_mut()?
            .execute(
                "DELETE FROM agent_exception WHERE agent_id = ?1 AND item_id = ?2 AND kind = ?3",
                (agent, item, kind.as_str()),
            )
            .map_err(storage)?;
        Ok(removed > 0)
    }

    /// The exceptions of one agent, without the marker, by item.
    pub fn agent_exceptions(&self, agent_id: u64) -> VaultResult<Vec<AgentException>> {
        self.query_exceptions(
            "SELECT agent_id, item_id, kind, created_at FROM agent_exception
             WHERE agent_id = ?1 AND item_id <> 0 ORDER BY item_id, kind",
            to_sql_id(agent_id)?,
        )
    }

    /// The exceptions of all agents for one item, by agent.
    pub fn item_exceptions(&self, item_id: u64) -> VaultResult<Vec<AgentException>> {
        if item_id == ONLY_MARKER_ITEM {
            return Ok(Vec::new());
        }
        self.query_exceptions(
            "SELECT agent_id, item_id, kind, created_at FROM agent_exception
             WHERE item_id = ?1 ORDER BY agent_id, kind",
            to_sql_id(item_id)?,
        )
    }

    fn query_exceptions(&self, sql: &str, id: i64) -> VaultResult<Vec<AgentException>> {
        let conn = self.conn_ref()?;
        let mut stmt = conn.prepare(sql).map_err(storage)?;
        let rows = stmt
            .query_map([id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .map_err(storage)?;
        let mut out = Vec::new();
        for row in rows {
            let (agent, item, kind, at) = row.map_err(storage)?;
            out.push(AgentException {
                agent_id: to_public_id(agent)?,
                item_id: u64::try_from(item).map_err(storage)?,
                kind: ExceptionKind::parse(&kind).ok_or_else(|| err(VaultErrorKind::Storage))?,
                created_at: from_sql_time(at)?,
            });
        }
        Ok(out)
    }

    /// The exceptions of one agent, read once.
    pub fn agent_view(&self, agent_id: u64) -> VaultResult<AgentView> {
        view_in(self.conn_ref()?, to_sql_id(agent_id)?)
    }

    /// What `agent_id` may do with `item_id`. An item that the agent may not see is
    /// [`Standing::Never`], also for a revoked agent.
    pub fn agent_item_standing(&self, agent_id: u64, item_id: u64) -> VaultResult<Standing> {
        Ok(self.agent_view(agent_id)?.standing(item_id))
    }

    /// The items that a restricted agent may see, without its `never` items. `None`: the
    /// agent is not restricted and sees every item except its `never` items
    /// ([`AgentView::never`]).
    pub fn visible_items_for_agent(&self, agent_id: u64) -> VaultResult<Option<BTreeSet<u64>>> {
        let view = self.agent_view(agent_id)?;
        Ok(view.restricted.then(|| {
            view.listed
                .iter()
                .copied()
                .filter(|item| view.visible(*item))
                .collect()
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::CredentialKind;
    use crate::vault::{Field, ItemDraft, SecretValue};

    const PASS: &str = "synthetic-exceptions-pass";

    fn vault_with_items(dir: &tempfile::TempDir, count: usize) -> (Vault, Vec<u64>) {
        let mut vault = Vault::create(&dir.path().join("exceptions.db"), PASS).unwrap();
        vault.unlock(PASS).unwrap();
        let items = (0..count)
            .map(|index| {
                vault
                    .add(ItemDraft {
                        title: format!("Synthetic {index}"),
                        kind: CredentialKind::ApiKey,
                        notes: String::new(),
                        tags: Vec::new(),
                        fields: vec![Field {
                            name: "token".to_owned(),
                            value: SecretValue::new(format!("SYNTH-exception-{index}")),
                            secret: true,
                        }],
                    })
                    .unwrap()
                    .id
            })
            .collect();
        (vault, items)
    }

    #[test]
    fn exceptions_make_an_agent_stricter_and_never_wins() {
        let dir = tempfile::TempDir::new().unwrap();
        let (mut vault, items) = vault_with_items(&dir, 3);
        let (agent, _) = vault.register_agent("Synthetic").unwrap();
        // A new agent does not see all credentials: it is restricted to nothing.
        assert_eq!(
            vault.visible_items_for_agent(agent.id).unwrap(),
            Some(BTreeSet::new())
        );
        vault.set_agent_sees_all(agent.id, true).unwrap();
        assert_eq!(vault.visible_items_for_agent(agent.id).unwrap(), None);
        for item in &items {
            assert_eq!(
                vault.agent_item_standing(agent.id, *item).unwrap(),
                Standing::Normal
            );
        }
        vault
            .add_agent_exception(agent.id, items[0], ExceptionKind::Never)
            .unwrap();
        vault
            .add_agent_exception(agent.id, items[1], ExceptionKind::AlwaysAsk)
            .unwrap();
        assert_eq!(
            vault.agent_item_standing(agent.id, items[0]).unwrap(),
            Standing::Never
        );
        assert_eq!(
            vault.agent_item_standing(agent.id, items[1]).unwrap(),
            Standing::AlwaysAsk
        );
        // "Only" restricts the agent to the listed item; never still wins.
        vault
            .add_agent_exception(agent.id, items[1], ExceptionKind::Only)
            .unwrap();
        vault
            .add_agent_exception(agent.id, items[0], ExceptionKind::Only)
            .unwrap();
        assert_eq!(
            vault.visible_items_for_agent(agent.id).unwrap(),
            Some(BTreeSet::from([items[1]]))
        );
        assert_eq!(
            vault.agent_item_standing(agent.id, items[2]).unwrap(),
            Standing::Never
        );
        // Removing the last listed item keeps the marker: the agent sees nothing.
        assert!(
            vault
                .remove_agent_exception(agent.id, items[1], ExceptionKind::Only)
                .unwrap()
        );
        assert!(
            vault
                .remove_agent_exception(agent.id, items[0], ExceptionKind::Only)
                .unwrap()
        );
        assert_eq!(
            vault.visible_items_for_agent(agent.id).unwrap(),
            Some(BTreeSet::new())
        );
        assert_eq!(
            vault
                .remove_agent_exception(agent.id, ONLY_MARKER_ITEM, ExceptionKind::Only)
                .unwrap_err()
                .kind(),
            VaultErrorKind::InvalidInput
        );
        // The marker is not an exception of an item.
        assert!(
            vault
                .agent_exceptions(agent.id)
                .unwrap()
                .iter()
                .all(|e| e.item_id != ONLY_MARKER_ITEM)
        );
        vault.set_agent_sees_all(agent.id, true).unwrap();
        assert_eq!(vault.visible_items_for_agent(agent.id).unwrap(), None);
        assert_eq!(vault.item_exceptions(items[0]).unwrap().len(), 1);
        assert!(
            vault
                .remove_agent_exception(agent.id, items[0], ExceptionKind::Never)
                .unwrap()
        );
        assert!(
            !vault
                .remove_agent_exception(agent.id, items[0], ExceptionKind::Never)
                .unwrap()
        );
        // A revoked agent sees nothing.
        vault.revoke_agent(agent.id).unwrap();
        assert_eq!(
            vault.agent_item_standing(agent.id, items[2]).unwrap(),
            Standing::Never
        );
    }

    #[test]
    fn notes_are_short_plain_text() {
        let dir = tempfile::TempDir::new().unwrap();
        let (mut vault, _) = vault_with_items(&dir, 0);
        let (agent, _) = vault.register_agent("Synthetic").unwrap();
        assert_eq!(vault.agent_note(agent.id).unwrap(), "");
        vault
            .set_agent_note(agent.id, " CI agent\nfor client X ")
            .unwrap();
        assert_eq!(vault.agent_note(agent.id).unwrap(), "CI agent for client X");
        assert_eq!(
            vault
                .set_agent_note(agent.id, &"x".repeat(MAX_AGENT_NOTE_BYTES + 1))
                .unwrap_err()
                .kind(),
            VaultErrorKind::InvalidInput
        );
        assert_eq!(
            vault.agent_note(999).unwrap_err().kind(),
            VaultErrorKind::NotFound
        );
    }
}
