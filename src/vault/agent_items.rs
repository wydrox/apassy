//! Credentials that agents add, credential requests, and corrections (ADR 0025 §5, §6).
//! The tables `item_origin`, `credential_request`, and `correction` are in schema 18
//! (`schema18.rs`). They are local: each Mac keeps its own.
//!
//! - **Origin.** [`Vault::add_detected`] stores the origin of an item that an agent
//!   added. An item is the agent's *own* item when the agent made its value: capture,
//!   generate, or save ([`OriginTool::is_agent_value`]). Only an own item can get a new
//!   value or a new description from the agent, and only own items take part in the
//!   value check ("a value that exists returns the existing item"), so the check tells
//!   the agent nothing about the other items of the vault.
//! - **Credential requests.** An agent asks the owner to paste a credential. The owner
//!   saves it (the app adds the item with [`CredentialRequest::origin`]) or dismisses
//!   the request.
//! - **Corrections.** The broker proposes a change of the declaration when the use log
//!   does not fit it (`broker::corrections`). Each `(item, kind, proposed)` exists once:
//!   an ignored proposal is never made again. Accepting applies the change through the
//!   declaration API, as an answer of the owner.
//!
//! No function here returns or logs a secret value. The value check compares in memory.

use rusqlite::{Connection, OptionalExtension, TransactionBehavior};
use serde_json::Value;

use super::add::{ItemOrigin, OriginTool};
use super::agents::{
    EnvDelivery, Environment, MAX_PLACEHOLDER_HOSTS, checked_env_name, from_sql_time, now_unix,
    parse_placeholder_host, process_binding_in, to_sql_time,
};
use super::exceptions::ExceptionKind;
use super::history::{self, EditChange, ItemEventKind};
use super::types::{
    ItemSummary, MAX_FIELD_VALUE_BYTES, MAX_NOTES_BYTES, MAX_TITLE_BYTES, VaultErrorKind,
    VaultResult, err, kind_from_str,
};
use super::usage::InteractionKind;
use super::{Vault, to_public_id, to_sql_id};

/// An agent adds at most this many items in one hour (ADR 0025 §6).
pub const MAX_AGENT_ITEMS_PER_HOUR: usize = 10;
/// The longest name, purpose, or "where to get it" of a credential request, in bytes.
pub const MAX_REQUEST_TEXT_BYTES: usize = 500;
/// An agent has at most this many open credential requests.
pub const MAX_OPEN_REQUESTS_PER_AGENT: usize = 5;
const HOUR_SECONDS: u64 = 3600;

fn storage<E>(_: E) -> super::types::VaultError {
    err(VaultErrorKind::Storage)
}

/// One item that an agent added.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentItem {
    pub item_id: u64,
    pub origin: ItemOrigin,
    pub created_at: u64,
}

/// What `describe_credential` changes. `None` keeps the value.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ItemDescription {
    pub title: Option<String>,
    pub notes: Option<String>,
    pub env_name: Option<String>,
    /// The hosts of a placeholder (ADR 0011). They can only narrow where the value goes:
    /// a placeholder for these hosts instead of the real value, or a subset of the
    /// placeholder hosts that the item has.
    pub hosts: Option<Vec<String>>,
}

/// The state of a credential request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialRequestState {
    Open,
    Saved,
    Dismissed,
}

impl CredentialRequestState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Saved => "saved",
            Self::Dismissed => "dismissed",
        }
    }

    fn parse(text: &str) -> VaultResult<Self> {
        match text {
            "open" => Ok(Self::Open),
            "saved" => Ok(Self::Saved),
            "dismissed" => Ok(Self::Dismissed),
            _ => Err(err(VaultErrorKind::Storage)),
        }
    }
}

/// A request to store: what the agent asks for, and where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewCredentialRequest {
    pub agent_id: u64,
    pub agent_name: String,
    pub project_key: String,
    pub project_label: String,
    /// The name of the credential, as the agent wants it.
    pub name: String,
    /// Why the agent needs it. The owner reads it.
    pub purpose: String,
    /// Where the owner gets it, for example a page of the provider. May be empty.
    pub where_to_get: String,
    /// The folder UUID of the new item. `None`: the top level.
    pub folder: Option<String>,
}

impl NewCredentialRequest {
    /// The request as the vault stores it: the texts without control characters and
    /// trimmed. `InvalidInput`: an empty name or purpose, a name longer than the longest
    /// title, or a text longer than [`MAX_REQUEST_TEXT_BYTES`].
    pub fn normalized(&self) -> VaultResult<Self> {
        Ok(Self {
            name: checked_line(&self.name, MAX_TITLE_BYTES, false)?,
            purpose: checked_line(&self.purpose, MAX_REQUEST_TEXT_BYTES, false)?,
            where_to_get: checked_line(&self.where_to_get, MAX_REQUEST_TEXT_BYTES, true)?,
            ..self.clone()
        })
    }
}

/// One stored credential request. It has no secret value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialRequest {
    pub id: u64,
    pub agent_id: u64,
    pub agent_name: String,
    pub project_key: String,
    pub project_label: String,
    pub name: String,
    pub purpose: String,
    pub where_to_get: String,
    pub folder: Option<String>,
    pub created_at: u64,
    pub state: CredentialRequestState,
    /// The item that the owner saved.
    pub item_id: Option<u64>,
    pub decided_at: Option<u64>,
}

impl CredentialRequest {
    /// The origin of the item that the owner saves for this request. The app passes it
    /// to [`Vault::add_detected`], so the history says who asked.
    pub fn origin(&self) -> ItemOrigin {
        ItemOrigin {
            agent_id: self.agent_id,
            agent_name: self.agent_name.clone(),
            project_key: self.project_key.clone(),
            project_label: self.project_label.clone(),
            tool: OriginTool::AskOwner,
        }
    }

    /// The same request: the agent, the name, the purpose, the place to get it, the
    /// folder, and the project.
    pub fn same_as(&self, new: &NewCredentialRequest) -> bool {
        self.agent_id == new.agent_id
            && self.name == new.name
            && self.purpose == new.purpose
            && self.where_to_get == new.where_to_get
            && self.folder == new.folder
            && self.project_key == new.project_key
    }
}

/// How the owner settles a credential request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestOutcome {
    /// The owner saved the credential as this item.
    Saved {
        item_id: u64,
    },
    Dismissed,
}

/// What a correction changes (ADR 0025 §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorrectionKind {
    /// The environment of the declaration: `proposed` is `development` or `production`.
    Environment,
    /// The project of the declaration: `proposed` is the project label.
    Project,
}

impl CorrectionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Environment => "environment",
            Self::Project => "project",
        }
    }

    fn parse(text: &str) -> VaultResult<Self> {
        match text {
            "environment" => Ok(Self::Environment),
            "project" => Ok(Self::Project),
            _ => Err(err(VaultErrorKind::Storage)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorrectionState {
    Open,
    Accepted,
    Ignored,
}

impl CorrectionState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Accepted => "accepted",
            Self::Ignored => "ignored",
        }
    }

    fn parse(text: &str) -> VaultResult<Self> {
        match text {
            "open" => Ok(Self::Open),
            "accepted" => Ok(Self::Accepted),
            "ignored" => Ok(Self::Ignored),
            _ => Err(err(VaultErrorKind::Storage)),
        }
    }
}

/// One proposed correction. `facts` is what the use log showed (hosts, projects,
/// counts, the kind of signal); it never has a secret value.
#[derive(Debug, Clone, PartialEq)]
pub struct Correction {
    pub id: u64,
    pub item_id: u64,
    pub kind: CorrectionKind,
    pub proposed: String,
    pub facts: Value,
    pub created_at: u64,
    pub state: CorrectionState,
    pub decided_at: Option<u64>,
}

/// The answer of the owner to a correction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorrectionAnswer {
    Accepted,
    Ignored,
}

/// The fact key of an environment that the use log already made stricter until the
/// owner answers (ADR 0025 §5: "the bouncer uses the more careful value"). Ignoring the
/// correction gives the item this environment back.
pub const RAISED_FROM_FACT: &str = "raised_from";

/// Text of at most `max` bytes without control characters, trimmed. `InvalidInput` when
/// empty (unless `allow_empty`) or too long.
fn checked_line(text: &str, max: usize, allow_empty: bool) -> VaultResult<String> {
    let clean: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let clean = clean.trim();
    if (clean.is_empty() && !allow_empty) || clean.len() > max {
        return Err(err(VaultErrorKind::InvalidInput));
    }
    Ok(clean.to_owned())
}

/// Constant-time comparison of two values of the same length.
fn same_value(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |diff, (x, y)| diff | (x ^ y))
        == 0
}

type OriginRow = (i64, i64, String, String, String, String, i64);

fn origin_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<OriginRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
    ))
}

fn parse_origin(row: OriginRow) -> VaultResult<AgentItem> {
    let (item, agent, agent_name, project_key, project_label, tool, at) = row;
    Ok(AgentItem {
        item_id: to_public_id(item)?,
        origin: ItemOrigin {
            agent_id: to_public_id(agent)?,
            agent_name,
            project_key,
            project_label,
            tool: OriginTool::parse(&tool).ok_or_else(|| err(VaultErrorKind::Storage))?,
        },
        created_at: from_sql_time(at)?,
    })
}

const ORIGIN_COLUMNS: &str =
    "item_id, agent_id, agent_name, project_key, project_label, tool, created_at";

/// The origin of `item` when it is an own item of `agent`. An item that does not exist
/// has no origin row (deleting an item deletes it).
fn own_origin(conn: &Connection, agent: i64, item: i64) -> VaultResult<Option<OriginTool>> {
    let tool: Option<String> = conn
        .query_row(
            "SELECT o.tool FROM item_origin o JOIN item i ON i.id = o.item_id
             WHERE o.item_id = ?1 AND o.agent_id = ?2",
            (item, agent),
            |row| row.get(0),
        )
        .optional()
        .map_err(storage)?;
    Ok(tool
        .and_then(|tool| OriginTool::parse(&tool))
        .filter(|tool| tool.is_agent_value()))
}

/// `title`, or `title 2`, `title 3`, ... when another item than `item` has the title
/// (without regard to case), as for a new item.
fn free_title_for(conn: &Connection, item: i64, title: &str) -> VaultResult<String> {
    let mut stmt = conn
        .prepare("SELECT title FROM item WHERE id != ?1")
        .map_err(storage)?;
    let used: std::collections::BTreeSet<String> = stmt
        .query_map([item], |row| row.get::<_, String>(0))
        .map_err(storage)?
        .map(|row| row.map(|title| title.to_lowercase()))
        .collect::<Result<_, _>>()
        .map_err(storage)?;
    if !used.contains(&title.to_lowercase()) {
        return Ok(title.to_owned());
    }
    for number in 2u64.. {
        let suffix = format!(" {number}");
        let mut end = title
            .len()
            .min(MAX_TITLE_BYTES.saturating_sub(suffix.len()));
        while !title.is_char_boundary(end) {
            end -= 1;
        }
        let candidate = format!("{}{suffix}", title[..end].trim_end());
        if !used.contains(&candidate.to_lowercase()) {
            return Ok(candidate);
        }
    }
    Err(err(VaultErrorKind::Storage))
}

/// The hosts of a placeholder as the vault stores them: `host`, or `host:port` when the
/// port is not 443, without repeats.
fn normal_hosts(hosts: &[String]) -> VaultResult<Vec<String>> {
    if hosts.is_empty() || hosts.len() > MAX_PLACEHOLDER_HOSTS {
        return Err(err(VaultErrorKind::InvalidInput));
    }
    let mut lines: Vec<String> = Vec::with_capacity(hosts.len());
    for host in hosts {
        let (name, port) =
            parse_placeholder_host(host).ok_or_else(|| err(VaultErrorKind::InvalidInput))?;
        let line = if port == 443 {
            name
        } else {
            format!("{name}:{port}")
        };
        if !lines.contains(&line) {
            lines.push(line);
        }
    }
    Ok(lines)
}

impl Vault {
    /// Store the origin of an item that an agent added. `AlreadyExists`: the item has an
    /// origin. `NotFound`: no such item.
    pub fn set_item_origin(&mut self, item_id: u64, origin: &ItemOrigin) -> VaultResult<()> {
        let item = to_sql_id(item_id)?;
        let agent = to_sql_id(origin.agent_id)?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        super::agents::require_item(&tx, item)?;
        let inserted = tx
            .execute(
                "INSERT OR IGNORE INTO item_origin (item_id, agent_id, agent_name, project_key,
                     project_label, tool, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    item,
                    agent,
                    origin.agent_name,
                    origin.project_key,
                    origin.project_label,
                    origin.tool.as_str(),
                    to_sql_time(now_unix())?,
                ],
            )
            .map_err(storage)?;
        if inserted == 0 {
            return Err(err(VaultErrorKind::AlreadyExists));
        }
        tx.commit().map_err(storage)
    }

    /// The origin of an item that an agent added. `None` for an item of the owner.
    pub fn item_origin(&self, item_id: u64) -> VaultResult<Option<AgentItem>> {
        let item = to_sql_id(item_id)?;
        let row = self
            .conn_ref()?
            .query_row(
                &format!("SELECT {ORIGIN_COLUMNS} FROM item_origin WHERE item_id = ?1"),
                [item],
                origin_row,
            )
            .optional()
            .map_err(storage)?;
        row.map(parse_origin).transpose()
    }

    /// The items that `agent_id` added at `since` (Unix time) or later, newest first.
    /// Every tool counts, also `ask_owner`.
    pub fn items_created_by(&self, agent_id: u64, since: u64) -> VaultResult<Vec<AgentItem>> {
        let agent = to_sql_id(agent_id)?;
        let conn = self.conn_ref()?;
        let mut stmt = conn
            .prepare(&format!(
                "SELECT {ORIGIN_COLUMNS} FROM item_origin
                 WHERE agent_id = ?1 AND created_at >= ?2 ORDER BY created_at DESC, item_id DESC"
            ))
            .map_err(storage)?;
        let rows = stmt
            .query_map((agent, to_sql_time(since)?), origin_row)
            .map_err(storage)?;
        let mut items = Vec::new();
        for row in rows {
            items.push(parse_origin(row.map_err(storage)?)?);
        }
        Ok(items)
    }

    /// How many items `agent_id` made in the last hour with capture, generate, or save.
    /// The limit is [`MAX_AGENT_ITEMS_PER_HOUR`]. An item that the owner deleted no
    /// longer counts: its origin goes with it, and only the owner deletes.
    pub fn agent_items_in_last_hour(&self, agent_id: u64) -> VaultResult<usize> {
        let since = now_unix().saturating_sub(HOUR_SECONDS);
        Ok(self
            .items_created_by(agent_id, since)?
            .iter()
            .filter(|item| item.origin.tool.is_agent_value())
            .count())
    }

    /// True when `item_id` exists and is an own item of `agent_id`: the agent made its
    /// value with capture, generate, or save.
    pub fn agent_owns_item(&self, agent_id: u64, item_id: u64) -> VaultResult<bool> {
        let conn = self.conn_ref()?;
        Ok(own_origin(conn, to_sql_id(agent_id)?, to_sql_id(item_id)?)?.is_some())
    }

    /// The own item of `agent_id` that has `value` in a secret field, if one exists
    /// (ADR 0025 §6: "a value that exists returns the existing item"). Only own items
    /// are read, so the answer says nothing about the other items of the vault.
    pub fn own_item_with_value(&self, agent_id: u64, value: &str) -> VaultResult<Option<u64>> {
        let agent = to_sql_id(agent_id)?;
        let conn = self.conn_ref()?;
        let mut stmt = conn
            .prepare(
                "SELECT o.item_id, o.tool, f.value FROM item_origin o
                 JOIN item_field f ON f.item_id = o.item_id
                 WHERE o.agent_id = ?1 AND f.secret = 1
                 ORDER BY o.item_id",
            )
            .map_err(storage)?;
        let mut rows = stmt.query([agent]).map_err(storage)?;
        let mut found = None;
        while let Some(row) = rows.next().map_err(storage)? {
            let tool: String = row.get(1).map_err(storage)?;
            let stored = zeroize::Zeroizing::new(row.get::<_, String>(2).map_err(storage)?);
            let own = OriginTool::parse(&tool).is_some_and(OriginTool::is_agent_value);
            if own && found.is_none() && same_value(&stored, value) {
                found = Some(to_public_id(row.get(0).map_err(storage)?)?);
            }
        }
        Ok(found)
    }

    /// Give an own item of `agent_id` a new value (ADR 0025 §6, `update_credential`):
    /// the field of its variable, or its first secret field. The revision grows, and an
    /// edit event names the field, not the value.
    ///
    /// - `NotFound`: the item does not exist or is not an own item of the agent.
    /// - `InvalidInput`: the value is empty or too long, the item has no secret field, or
    ///   the item sends a placeholder and the value is too short for one.
    pub fn replace_own_item_value(
        &mut self,
        agent_id: u64,
        item_id: u64,
        value: &str,
    ) -> VaultResult<ItemSummary> {
        let agent = to_sql_id(agent_id)?;
        let item = to_sql_id(item_id)?;
        if value.is_empty() || value.len() > MAX_FIELD_VALUE_BYTES {
            return Err(err(VaultErrorKind::InvalidInput));
        }
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        if own_origin(&tx, agent, item)?.is_none() {
            return Err(err(VaultErrorKind::NotFound));
        }
        let binding = process_binding_in(&tx, item)?;
        let field = match &binding {
            Some(binding) => binding.field.clone(),
            None => tx
                .query_row(
                    "SELECT name FROM item_field WHERE item_id = ?1 AND secret = 1
                     ORDER BY position LIMIT 1",
                    [item],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(storage)?
                .ok_or_else(|| err(VaultErrorKind::InvalidInput))?,
        };
        if super::types::is_passkey_field(&field) {
            return Err(err(VaultErrorKind::InvalidInput));
        }
        if let Some(binding) = &binding
            && matches!(binding.delivery, EnvDelivery::Placeholder(_))
            && crate::broker::proxy::mint_placeholder(value).is_none()
        {
            return Err(err(VaultErrorKind::InvalidInput));
        }
        let changed = tx
            .execute(
                "UPDATE item_field SET value = ?1 WHERE item_id = ?2 AND name = ?3 AND secret = 1",
                (value, item, field.as_str()),
            )
            .map_err(storage)?;
        if changed != 1 {
            return Err(err(VaultErrorKind::InvalidInput));
        }
        tx.execute(
            "UPDATE item SET revision = revision + 1 WHERE id = ?1",
            [item],
        )
        .map_err(storage)?;
        history::record(
            &tx,
            item,
            ItemEventKind::Edited,
            &EditChange::detail(&[EditChange::Secret(field)]),
        )?;
        let (title, kind, revision): (String, String, i64) = tx
            .query_row(
                "SELECT title, kind, revision FROM item WHERE id = ?1",
                [item],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(storage)?;
        tx.commit().map_err(storage)?;
        Ok(ItemSummary {
            id: item_id,
            title,
            kind: kind_from_str(&kind)?,
            revision: u64::try_from(revision).map_err(storage)?,
        })
    }

    /// Change the title, the notes, the variable, or the hosts of an own item of
    /// `agent_id` (ADR 0025 §6, `describe_credential`). A title that another item has
    /// gets a number. All checks run before any change.
    ///
    /// - `NotFound`: the item does not exist or is not an own item of the agent.
    /// - `InvalidInput`: an empty or too long title, too long notes, a variable name that
    ///   is not valid or is reserved, hosts that are not valid, hosts that would widen
    ///   where the value goes, or nothing to change.
    /// - `AlreadyExists`: another item uses the variable name.
    pub fn describe_own_item(
        &mut self,
        agent_id: u64,
        item_id: u64,
        change: &ItemDescription,
    ) -> VaultResult<ItemSummary> {
        let agent = to_sql_id(agent_id)?;
        let item = to_sql_id(item_id)?;
        if change == &ItemDescription::default() {
            return Err(err(VaultErrorKind::InvalidInput));
        }
        let title = change
            .title
            .as_deref()
            .map(|title| checked_line(title, MAX_TITLE_BYTES, false))
            .transpose()?;
        let notes = match change.notes.as_deref() {
            Some(notes) if notes.len() > MAX_NOTES_BYTES || notes.contains('\0') => {
                return Err(err(VaultErrorKind::InvalidInput));
            }
            other => other.map(str::to_owned),
        };
        let env_name = change
            .env_name
            .as_deref()
            .map(|name| checked_env_name(name.trim()).map(str::to_owned))
            .transpose()?;
        let hosts = change.hosts.as_deref().map(normal_hosts).transpose()?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        if own_origin(&tx, agent, item)?.is_none() {
            return Err(err(VaultErrorKind::NotFound));
        }
        let binding = process_binding_in(&tx, item)?;
        if (env_name.is_some() || hosts.is_some()) && binding.is_none() {
            return Err(err(VaultErrorKind::InvalidInput));
        }
        if let Some(name) = &env_name {
            let taken: Option<i64> = tx
                .query_row(
                    "SELECT item_id FROM env_binding WHERE env_name = ?1 AND item_id != ?2",
                    (name.as_str(), item),
                    |row| row.get(0),
                )
                .optional()
                .map_err(storage)?;
            if taken.is_some() {
                return Err(err(VaultErrorKind::AlreadyExists));
            }
        }
        let delivery = match (&binding, hosts) {
            (Some(binding), None) => binding.delivery.clone(),
            (Some(binding), Some(new)) => {
                match &binding.delivery {
                    // Only a subset of the hosts that the item has.
                    EnvDelivery::Placeholder(current) => {
                        if !new.iter().all(|host| current.contains(host)) {
                            return Err(err(VaultErrorKind::InvalidInput));
                        }
                    }
                    // A placeholder instead of the real value: the value must be long
                    // enough, and the provider must not sign requests with it.
                    EnvDelivery::Value => {
                        let value = zeroize::Zeroizing::new(
                            tx.query_row(
                                "SELECT value FROM item_field WHERE item_id = ?1 AND name = ?2",
                                (item, binding.field.as_str()),
                                |row| row.get::<_, String>(0),
                            )
                            .map_err(storage)?,
                        );
                        let provider: Option<String> = tx
                            .query_row(
                                "SELECT provider FROM declaration WHERE item_id = ?1",
                                [item],
                                |row| row.get(0),
                            )
                            .optional()
                            .map_err(storage)?;
                        let signs = provider
                            .as_deref()
                            .and_then(super::providers::find)
                            .is_some_and(|provider| provider.real_value);
                        if signs || crate::broker::proxy::mint_placeholder(&value).is_none() {
                            return Err(err(VaultErrorKind::InvalidInput));
                        }
                    }
                }
                EnvDelivery::Placeholder(new)
            }
            (None, _) => EnvDelivery::Value,
        };
        let mut changes = Vec::new();
        if let Some(title) = &title {
            let title = free_title_for(&tx, item, title)?;
            let current: String = tx
                .query_row("SELECT title FROM item WHERE id = ?1", [item], |row| {
                    row.get(0)
                })
                .map_err(storage)?;
            if current != title {
                tx.execute("UPDATE item SET title = ?1 WHERE id = ?2", (&title, item))
                    .map_err(storage)?;
                changes.push(EditChange::Title);
            }
        }
        if let Some(notes) = &notes {
            let updated = tx
                .execute(
                    "UPDATE item SET notes = ?1 WHERE id = ?2 AND notes != ?1",
                    (notes, item),
                )
                .map_err(storage)?;
            if updated > 0 {
                changes.push(EditChange::Notes);
            }
        }
        if !changes.is_empty() {
            tx.execute(
                "UPDATE item SET revision = revision + 1 WHERE id = ?1",
                [item],
            )
            .map_err(storage)?;
            history::record(
                &tx,
                item,
                ItemEventKind::Edited,
                &EditChange::detail(&changes),
            )?;
        }
        if let Some(binding) = &binding
            && (env_name.is_some() || change.hosts.is_some())
        {
            let stored_name: Option<String> = tx
                .query_row(
                    "SELECT env_name FROM env_binding WHERE item_id = ?1",
                    [item],
                    |row| row.get(0),
                )
                .optional()
                .map_err(storage)?;
            let name = env_name.or(stored_name).unwrap_or_default();
            let hosts_text = match &delivery {
                EnvDelivery::Value => None,
                EnvDelivery::Placeholder(hosts) => Some(hosts.join("\n")),
            };
            tx.execute(
                "INSERT INTO env_binding (item_id, env_name, field, placeholder_hosts)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(item_id) DO UPDATE SET env_name = excluded.env_name,
                     field = excluded.field, placeholder_hosts = excluded.placeholder_hosts",
                (
                    item,
                    name.as_str(),
                    binding.field.as_str(),
                    hosts_text.as_deref(),
                ),
            )
            .map_err(storage)?;
            let display = if name.is_empty() {
                "Automatic"
            } else {
                name.as_str()
            };
            let detail = match delivery.history_text() {
                Some(text) => format!("{display}, {text}"),
                None => display.to_owned(),
            };
            history::record(&tx, item, ItemEventKind::Variable, &detail)?;
        }
        let (title, kind, revision): (String, String, i64) = tx
            .query_row(
                "SELECT title, kind, revision FROM item WHERE id = ?1",
                [item],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(storage)?;
        tx.commit().map_err(storage)?;
        Ok(ItemSummary {
            id: item_id,
            title,
            kind: kind_from_str(&kind)?,
            revision: u64::try_from(revision).map_err(storage)?,
        })
    }

    // ---- Credential requests ----

    /// Store an open credential request. The texts lose control characters.
    /// `InvalidInput`: an empty name or purpose, or a text longer than
    /// [`MAX_REQUEST_TEXT_BYTES`]. `NotFound`: the folder is not a folder.
    pub fn open_credential_request(&mut self, request: &NewCredentialRequest) -> VaultResult<u64> {
        let agent = to_sql_id(request.agent_id)?;
        let request = request.normalized()?;
        let (name, purpose, where_to_get) =
            (&request.name, &request.purpose, &request.where_to_get);
        if let Some(folder) = request.folder.as_deref() {
            self.folder_path(Some(folder))?;
        }
        let conn = self.conn_mut()?;
        conn.execute(
            "INSERT INTO credential_request (agent_id, agent_name, project_key, project_label,
                 name, purpose, where_to_get, folder_uuid, created_at, state)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'open')",
            rusqlite::params![
                agent,
                request.agent_name,
                request.project_key,
                request.project_label,
                name,
                purpose,
                where_to_get,
                request.folder,
                to_sql_time(now_unix())?,
            ],
        )
        .map_err(storage)?;
        to_public_id(conn.last_insert_rowid())
    }

    /// One credential request. `NotFound`: no such request.
    pub fn credential_request(&self, id: u64) -> VaultResult<CredentialRequest> {
        let id = to_sql_id(id)?;
        self.query_credential_requests("WHERE id = ?1", [id])?
            .pop()
            .ok_or_else(|| err(VaultErrorKind::NotFound))
    }

    /// The credential requests, oldest first. `open_only`: only the open ones (the
    /// list of the owner).
    pub fn credential_requests(&self, open_only: bool) -> VaultResult<Vec<CredentialRequest>> {
        let filter = if open_only {
            "WHERE state = 'open'"
        } else {
            ""
        };
        self.query_credential_requests(filter, [])
    }

    /// The credential requests of one agent, oldest first.
    pub fn agent_credential_requests(&self, agent_id: u64) -> VaultResult<Vec<CredentialRequest>> {
        self.query_credential_requests("WHERE agent_id = ?1", [to_sql_id(agent_id)?])
    }

    fn query_credential_requests<P: rusqlite::Params>(
        &self,
        filter: &str,
        params: P,
    ) -> VaultResult<Vec<CredentialRequest>> {
        let conn = self.conn_ref()?;
        let mut stmt = conn
            .prepare(&format!(
                "SELECT id, agent_id, agent_name, project_key, project_label, name, purpose,
                     where_to_get, folder_uuid, created_at, state, item_id, decided_at
                 FROM credential_request {filter} ORDER BY id"
            ))
            .map_err(storage)?;
        let rows = stmt
            .query_map(params, |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, Option<i64>>(11)?,
                    row.get::<_, Option<i64>>(12)?,
                ))
            })
            .map_err(storage)?;
        let mut out = Vec::new();
        for row in rows {
            let row = row.map_err(storage)?;
            out.push(CredentialRequest {
                id: to_public_id(row.0)?,
                agent_id: to_public_id(row.1)?,
                agent_name: row.2,
                project_key: row.3,
                project_label: row.4,
                name: row.5,
                purpose: row.6,
                where_to_get: row.7,
                folder: row.8,
                created_at: from_sql_time(row.9)?,
                state: CredentialRequestState::parse(&row.10)?,
                item_id: row.11.map(to_public_id).transpose()?,
                decided_at: row.12.map(from_sql_time).transpose()?,
            });
        }
        Ok(out)
    }

    /// The owner settles an open credential request: saved as an item, or dismissed.
    /// One interaction is counted (ADR 0025 §1). A saved item is listed for an agent with
    /// "only these items", so the agent can use what the owner saved for it; this is an
    /// answer of the owner, as an approval is.
    ///
    /// - `NotFound`: no such request, or the saved item does not exist.
    /// - `Conflict`: the request is not open.
    pub fn settle_credential_request(
        &mut self,
        id: u64,
        outcome: RequestOutcome,
    ) -> VaultResult<()> {
        let request = self.credential_request(id)?;
        if request.state != CredentialRequestState::Open {
            return Err(err(VaultErrorKind::Conflict));
        }
        let sql_id = to_sql_id(id)?;
        let agent = to_sql_id(request.agent_id)?;
        let now = to_sql_time(now_unix())?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let updated = match outcome {
            RequestOutcome::Saved { item_id } => {
                let item = to_sql_id(item_id)?;
                super::agents::require_item(&tx, item)?;
                let view = super::exceptions::view_in(&tx, agent)?;
                let active: bool = tx
                    .query_row(
                        "SELECT COUNT(*) FROM agent WHERE id = ?1 AND revoked_at IS NULL",
                        [agent],
                        |row| row.get::<_, i64>(0),
                    )
                    .map_err(storage)?
                    > 0;
                if active && view.restricted && !view.listed.contains(&item_id) {
                    tx.execute(
                        "INSERT OR IGNORE INTO agent_exception (agent_id, item_id, kind, created_at)
                         VALUES (?1, ?2, ?3, ?4)",
                        (agent, item, ExceptionKind::Only.as_str(), now),
                    )
                    .map_err(storage)?;
                }
                tx.execute(
                    "UPDATE credential_request SET state = 'saved', item_id = ?1, decided_at = ?2
                     WHERE id = ?3 AND state = 'open'",
                    (item, now, sql_id),
                )
                .map_err(storage)?
            }
            RequestOutcome::Dismissed => tx
                .execute(
                    "UPDATE credential_request SET state = 'dismissed', decided_at = ?1
                     WHERE id = ?2 AND state = 'open'",
                    (now, sql_id),
                )
                .map_err(storage)?,
        };
        if updated != 1 {
            return Err(err(VaultErrorKind::Conflict));
        }
        tx.commit().map_err(storage)?;
        let _ = self.record_interaction(
            InteractionKind::Question,
            &format!("credential request \"{}\"", request.name),
            &[],
        );
        Ok(())
    }

    // ---- Corrections ----

    /// Propose a correction. Returns its ID, or `None` when the same correction (item,
    /// kind, proposed value) exists in any state: an ignored correction is never
    /// proposed again. `NotFound`: no such item. `InvalidInput`: an empty proposal.
    pub fn propose_correction(
        &mut self,
        item_id: u64,
        kind: CorrectionKind,
        proposed: &str,
        facts: &Value,
    ) -> VaultResult<Option<u64>> {
        let item = to_sql_id(item_id)?;
        let proposed = checked_line(proposed, MAX_REQUEST_TEXT_BYTES, false)?;
        let facts = serde_json::to_string(facts).map_err(storage)?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        super::agents::require_item(&tx, item)?;
        let inserted = tx
            .execute(
                "INSERT OR IGNORE INTO correction (item_id, kind, proposed, facts, created_at, state)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'open')",
                (
                    item,
                    kind.as_str(),
                    proposed.as_str(),
                    facts.as_str(),
                    to_sql_time(now_unix())?,
                ),
            )
            .map_err(storage)?;
        let id = tx.last_insert_rowid();
        tx.commit().map_err(storage)?;
        if inserted == 0 {
            Ok(None)
        } else {
            to_public_id(id).map(Some)
        }
    }

    /// The corrections, oldest first. `open_only`: only those that wait for the owner.
    pub fn corrections(&self, open_only: bool) -> VaultResult<Vec<Correction>> {
        let filter = if open_only {
            "WHERE state = 'open'"
        } else {
            ""
        };
        self.query_corrections(filter, [])
    }

    /// The corrections of one item, in any state, oldest first.
    pub fn item_corrections(&self, item_id: u64) -> VaultResult<Vec<Correction>> {
        self.query_corrections("WHERE item_id = ?1", [to_sql_id(item_id)?])
    }

    fn query_corrections<P: rusqlite::Params>(
        &self,
        filter: &str,
        params: P,
    ) -> VaultResult<Vec<Correction>> {
        let conn = self.conn_ref()?;
        let mut stmt = conn
            .prepare(&format!(
                "SELECT id, item_id, kind, proposed, facts, created_at, state, decided_at
                 FROM correction {filter} ORDER BY id"
            ))
            .map_err(storage)?;
        let rows = stmt
            .query_map(params, |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                ))
            })
            .map_err(storage)?;
        let mut out = Vec::new();
        for row in rows {
            let row = row.map_err(storage)?;
            out.push(Correction {
                id: to_public_id(row.0)?,
                item_id: to_public_id(row.1)?,
                kind: CorrectionKind::parse(&row.2)?,
                proposed: row.3,
                facts: serde_json::from_str(&row.4).map_err(storage)?,
                created_at: from_sql_time(row.5)?,
                state: CorrectionState::parse(&row.6)?,
                decided_at: row.7.map(from_sql_time).transpose()?,
            });
        }
        Ok(out)
    }

    /// The owner answers a correction. One interaction is counted (ADR 0025 §1).
    ///
    /// - Accepted: an environment correction sets the environment as an answer of the
    ///   owner ([`Vault::set_declaration_environment`]); a project correction sets the
    ///   project of the declaration.
    /// - Ignored: the correction stays as ignored and is never proposed again. When the
    ///   use log already made the environment stricter until the answer
    ///   ([`RAISED_FROM_FACT`]), the item gets its environment back, as the owner's answer.
    ///
    /// The caller does the owner check that the change needs (U2): accepting
    /// "development" loosens the declaration.
    ///
    /// - `NotFound`: no such correction, or a project correction for an item without a
    ///   declaration.
    /// - `Conflict`: the correction is not open.
    /// - `InvalidInput`: a stored proposal that does not read.
    pub fn settle_correction(&mut self, id: u64, answer: CorrectionAnswer) -> VaultResult<()> {
        let sql_id = to_sql_id(id)?;
        let correction = self
            .query_corrections("WHERE id = ?1", [sql_id])?
            .pop()
            .ok_or_else(|| err(VaultErrorKind::NotFound))?;
        if correction.state != CorrectionState::Open {
            return Err(err(VaultErrorKind::Conflict));
        }
        match (answer, correction.kind) {
            (CorrectionAnswer::Accepted, CorrectionKind::Environment) => {
                let environment = Environment::parse(&correction.proposed)
                    .map_err(|_| err(VaultErrorKind::InvalidInput))?;
                self.set_declaration_environment(correction.item_id, environment)?;
            }
            (CorrectionAnswer::Accepted, CorrectionKind::Project) => {
                let mut declaration = self
                    .declaration(correction.item_id)?
                    .ok_or_else(|| err(VaultErrorKind::NotFound))?;
                declaration.project.clone_from(&correction.proposed);
                self.set_declaration(correction.item_id, &declaration)?;
            }
            (CorrectionAnswer::Ignored, _) => {
                if let Some(previous) = correction
                    .facts
                    .get(RAISED_FROM_FACT)
                    .and_then(Value::as_str)
                    .and_then(|text| Environment::parse(text).ok())
                {
                    self.set_declaration_environment(correction.item_id, previous)?;
                }
            }
        }
        let state = match answer {
            CorrectionAnswer::Accepted => CorrectionState::Accepted,
            CorrectionAnswer::Ignored => CorrectionState::Ignored,
        };
        let updated = self
            .conn_mut()?
            .execute(
                "UPDATE correction SET state = ?1, decided_at = ?2 WHERE id = ?3 AND state = 'open'",
                (state.as_str(), to_sql_time(now_unix())?, sql_id),
            )
            .map_err(storage)?;
        if updated != 1 {
            return Err(err(VaultErrorKind::Conflict));
        }
        let _ = self.record_interaction(
            InteractionKind::Correction,
            &format!(
                "{} {} {}",
                correction.kind.as_str(),
                correction.proposed,
                state.as_str()
            ),
            &[],
        );
        Ok(())
    }
}
