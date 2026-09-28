//! Record-level sync of the credentials (schema 14, ADR 0014).
//!
//! The unit of sync is a credential: the item row with its tags, fields, archive state,
//! declaration, environment variable, and connector. Each item has a stable `uuid`,
//! `updated_at` (Unix milliseconds), `updated_by` (the random device ID of the vault
//! file that changed it), and a version vector `clock` (device ID to a count of its
//! changes). SQL triggers keep the time and the device: an insert gives a random UUID,
//! and each change of the item or of one of its child rows sets them. A delete leaves a
//! tombstone. So each write path of the app is covered without an edit. Before each
//! merge and each push, [`stamp`] counts each change since the last stamp in the clock of
//! this device.
//!
//! A merge compares clocks. A copy whose clock the local one contains is old: it changes
//! nothing, so an old copy cannot undo a newer change. A copy whose clock contains the
//! local one is newer: it replaces the credential. Two clocks that each have a change
//! the other lacks are a conflict: the later change (time, then device ID) wins, and the
//! other version stays as an archived conflict copy.
//!
//! Everything else stays on each Mac ([`LOCAL_TABLES`]): agents, grants, rules,
//! activity, learning data, requests, waits, review marks, and the sync bookkeeping. A
//! pushed copy has none of their rows.
//!
//! A merge reads the other copy through `ATTACH` on the open connection, without a key
//! argument: SQLCipher then uses the key of the vault. A copy that another Mac rekeyed
//! does not open, and the app asks for the new passphrase.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use ring::digest;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior};
use zeroize::Zeroizing;

use super::sync::{SyncIdentity, content_digest, read_sync_row, to_hex};
use super::types::{SCHEMA_VERSION, VaultErrorKind, VaultResult, err};
use super::{MAX_ITEM_EVENTS, Vault, agents, history, verify_expected_columns_in};

/// Tables of a credential besides the item row. Each row names its item in `item_id`.
pub(super) const CHILD_TABLES: [&str; 6] = [
    "item_tag",
    "item_field",
    "item_archive",
    "declaration",
    "env_binding",
    "destination",
];

/// Tables that stay on each Mac. A pushed copy has none of their rows, and a merge never
/// reads them from another copy.
pub const LOCAL_TABLES: [&str; 18] = [
    "agent",
    "grant_rule",
    "activity",
    "activity_item",
    "exec_grant",
    "run_log",
    "restore_review",
    "access_request",
    "decision_log",
    "remembered_pattern",
    "calibration",
    "waiting_run",
    "model_candidate",
    "shadow_decision",
    "model_activation",
    "suggestion_outcome",
    "sync_stamp",
    "sync_device",
];

/// Tables whose rows sync. `vault_meta` syncs as the one row of the file; its token
/// lifetime is set to the default in a pushed copy, because it is a setting of each Mac.
pub const SYNCED_TABLES: [&str; 13] = [
    "vault_meta",
    "item",
    "item_tag",
    "item_field",
    "item_archive",
    "declaration",
    "env_binding",
    "destination",
    "item_event",
    "sync_meta",
    "sync_tombstone",
    "sync_peer",
    "sqlite_sequence",
];

/// History events of a credential that sync. The others (a reveal, agent access, a
/// restore, a review) are about this Mac and stay on it.
pub const SYNCED_EVENT_KINDS: [&str; 10] = [
    "created",
    "tracked",
    "edited",
    "archived",
    "unarchived",
    "declaration",
    "variable",
    "variable_removed",
    "connector",
    "connector_removed",
];

/// A tombstone stays this long. A copy that is older than this can bring a deleted
/// credential back.
pub const TOMBSTONE_DAYS: i64 = 180;

/// The alias of the other copy during a merge.
const REMOTE: &str = "sync_remote";
/// The alias of the copy that a push strips.
pub(super) const PUSH: &str = "sync_push";

/// Tables and columns added in schema version 14 (ADR 0014). The UUIDs of existing rows
/// come from Rust ([`add_schema_v14`]), then [`triggers_sql`] runs.
const SCHEMA_V14_SQL: &str = "
ALTER TABLE item ADD COLUMN uuid TEXT;
ALTER TABLE item ADD COLUMN updated_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE item ADD COLUMN updated_by TEXT NOT NULL DEFAULT '';
ALTER TABLE item ADD COLUMN clock TEXT NOT NULL DEFAULT '';
ALTER TABLE item_event ADD COLUMN uuid TEXT;
CREATE TABLE sync_tombstone (
    uuid TEXT PRIMARY KEY,
    deleted_at INTEGER NOT NULL,
    deleted_by TEXT NOT NULL,
    clock TEXT NOT NULL DEFAULT ''
);
CREATE TABLE sync_stamp (
    uuid TEXT PRIMARY KEY,
    updated_at INTEGER NOT NULL,
    updated_by TEXT NOT NULL
);
CREATE TABLE sync_device (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    device_id TEXT NOT NULL,
    device_name TEXT NOT NULL,
    applying INTEGER NOT NULL DEFAULT 0 CHECK (applying IN (0, 1))
);
CREATE TABLE sync_peer (
    device_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    seen_at INTEGER NOT NULL
);
INSERT INTO sync_device (id, device_id, device_name) VALUES (1, lower(hex(randomblob(16))), '');
";

pub(super) const SCHEMA_V14_COLUMNS: [&str; 6] = [
    "SELECT uuid, updated_at, updated_by, clock FROM item LIMIT 0",
    "SELECT uuid FROM item_event LIMIT 0",
    "SELECT uuid, deleted_at, deleted_by, clock FROM sync_tombstone LIMIT 0",
    "SELECT uuid, updated_at, updated_by FROM sync_stamp LIMIT 0",
    "SELECT id, device_id, device_name, applying FROM sync_device LIMIT 0",
    "SELECT device_id, name, seen_at FROM sync_peer LIMIT 0",
];

/// Now in Unix milliseconds, in SQL.
const NOW_MS: &str = "CAST(ROUND((julianday('now') - 2440587.5) * 86400000.0) AS INTEGER)";
/// The device ID of this vault file, in SQL.
const DEVICE: &str = "COALESCE((SELECT device_id FROM sync_device WHERE id = 1), '')";
/// True unless a merge applies rows of another copy, in SQL.
const NOT_APPLYING: &str = "COALESCE((SELECT applying FROM sync_device WHERE id = 1), 0) = 0";

/// The triggers of schema 14.
fn triggers_sql() -> String {
    let mut sql = format!(
        "
CREATE UNIQUE INDEX item_uuid ON item(uuid);
CREATE UNIQUE INDEX item_event_uuid ON item_event(uuid);
CREATE TRIGGER item_sync_insert AFTER INSERT ON item WHEN NEW.uuid IS NULL BEGIN
    UPDATE item SET uuid = lower(hex(randomblob(16))), updated_at = {NOW_MS},
        updated_by = {DEVICE} WHERE id = NEW.id;
END;
CREATE TRIGGER item_sync_update AFTER UPDATE ON item
WHEN NEW.updated_at = OLD.updated_at AND {NOT_APPLYING} BEGIN
    UPDATE item SET updated_at = {NOW_MS}, updated_by = {DEVICE} WHERE id = NEW.id;
END;
CREATE TRIGGER item_sync_delete AFTER DELETE ON item
WHEN OLD.uuid IS NOT NULL AND {NOT_APPLYING} BEGIN
    INSERT OR REPLACE INTO sync_tombstone (uuid, deleted_at, deleted_by, clock)
        VALUES (OLD.uuid, {NOW_MS}, {DEVICE}, OLD.clock);
END;
CREATE TRIGGER item_event_sync_insert AFTER INSERT ON item_event WHEN NEW.uuid IS NULL BEGIN
    UPDATE item_event SET uuid = lower(hex(randomblob(16))) WHERE id = NEW.id;
END;
"
    );
    for table in CHILD_TABLES {
        sql.push_str(&format!(
            "
CREATE TRIGGER {table}_sync_insert AFTER INSERT ON {table} WHEN {NOT_APPLYING} BEGIN
    UPDATE item SET updated_at = {NOW_MS}, updated_by = {DEVICE} WHERE id = NEW.item_id;
END;
CREATE TRIGGER {table}_sync_update AFTER UPDATE ON {table} WHEN {NOT_APPLYING} BEGIN
    UPDATE item SET updated_at = {NOW_MS}, updated_by = {DEVICE}
        WHERE id IN (NEW.item_id, OLD.item_id);
END;
CREATE TRIGGER {table}_sync_delete AFTER DELETE ON {table} WHEN {NOT_APPLYING} BEGIN
    UPDATE item SET updated_at = {NOW_MS}, updated_by = {DEVICE} WHERE id = OLD.item_id;
END;
"
        ));
    }
    sql.push_str(
        "
UPDATE vault_meta SET schema_version = 14 WHERE id = 1;
PRAGMA user_version = 14;
",
    );
    sql
}

/// A record UUID from `parts`: 32 hexadecimal characters of a SHA-256. Two copies of the
/// same vault agree on it.
fn derived_uuid(parts: &[&str]) -> String {
    let mut ctx = digest::Context::new(&digest::SHA256);
    ctx.update(b"apassy-record-v1");
    for part in parts {
        ctx.update(b"\0");
        ctx.update(part.as_bytes());
    }
    to_hex(&ctx.finish().as_ref()[..16])
}

/// Add schema version 14 in the migration or create transaction. Existing items and
/// history events get UUIDs from the vault ID, the table, and the row ID, so two copies
/// of the same vault give each record the same UUID. Existing items count as stamped,
/// with an empty clock: the two copies agree on them.
pub(super) fn add_schema_v14(tx: &rusqlite::Transaction<'_>) -> VaultResult<()> {
    let storage = |_| err(VaultErrorKind::Storage);
    tx.execute_batch(SCHEMA_V14_SQL).map_err(storage)?;
    let vault_id: String = tx
        .query_row("SELECT vault_id FROM sync_meta WHERE id = 1", [], |row| {
            row.get(0)
        })
        .map_err(storage)?;
    for table in ["item", "item_event"] {
        let ids: Vec<i64> = {
            let mut stmt = tx
                .prepare(&format!("SELECT id FROM {table} WHERE uuid IS NULL"))
                .map_err(storage)?;
            stmt.query_map([], |row| row.get(0))
                .map_err(storage)?
                .collect::<Result<_, _>>()
                .map_err(storage)?
        };
        for id in ids {
            let uuid = derived_uuid(&[&vault_id, table, &id.to_string()]);
            tx.execute(
                &format!("UPDATE {table} SET uuid = ?1 WHERE id = ?2"),
                (uuid, id),
            )
            .map_err(storage)?;
        }
    }
    tx.execute(
        "INSERT INTO sync_stamp (uuid, updated_at, updated_by)
         SELECT uuid, updated_at, updated_by FROM item",
        [],
    )
    .map_err(storage)?;
    tx.execute_batch(&triggers_sql()).map_err(storage)
}

/// Give a vault file its own device row. A copy from another Mac has none: a pushed
/// copy leaves it out. A file that has the row is not written, so an unlock stays a read.
pub(super) fn ensure_device(conn: &Connection) -> VaultResult<()> {
    let present: i64 = conn
        .query_row("SELECT count(*) FROM sync_device WHERE id = 1", [], |row| {
            row.get(0)
        })
        .map_err(|_| err(VaultErrorKind::Storage))?;
    if present > 0 {
        return Ok(());
    }
    conn.execute(
        "INSERT OR IGNORE INTO sync_device (id, device_id, device_name)
         VALUES (1, lower(hex(randomblob(16))), '')",
        [],
    )
    .map(|_| ())
    .map_err(|_| err(VaultErrorKind::Storage))
}

/// A new device ID, for a restored file: it is a new copy, not the old writer.
pub(super) fn new_device(conn: &Connection) -> VaultResult<()> {
    ensure_device(conn)?;
    conn.execute(
        "UPDATE sync_device SET device_id = lower(hex(randomblob(16))) WHERE id = 1",
        [],
    )
    .map(|_| ())
    .map_err(|_| err(VaultErrorKind::Storage))
}

/// What a sync covers: which records, which file, and which key. Now there is one
/// scope, the whole vault with the key of the vault. A later scope (a shared collection
/// with its own file and its own random key) adds a variant here; the merge takes the
/// scope and does not change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncScope {
    kind: ScopeKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ScopeKind {
    /// Every credential. The copy has the key of the vault: `ATTACH` without a key.
    Vault,
}

impl SyncScope {
    /// Every credential of the vault, in one file with the key of the vault.
    pub fn vault() -> Self {
        Self {
            kind: ScopeKind::Vault,
        }
    }

    /// The name of the scope, for the state of a sync.
    pub fn id(&self) -> &'static str {
        match self.kind {
            ScopeKind::Vault => "vault",
        }
    }

    /// The SQL condition on the item alias `i` for the records of the scope.
    fn item_filter(&self) -> &'static str {
        match self.kind {
            ScopeKind::Vault => "1",
        }
    }

    /// Attach the copy at `path` as `alias` with the key of the scope.
    fn attach(&self, conn: &Connection, path: &Path, alias: &str) -> VaultResult<()> {
        let path = path
            .to_str()
            .ok_or_else(|| err(VaultErrorKind::InvalidInput))?;
        match self.kind {
            ScopeKind::Vault => conn
                .execute(&format!("ATTACH DATABASE ?1 AS {alias}"), [path])
                .map(|_| ())
                .map_err(|_| err(VaultErrorKind::WrongKeyOrCorrupt)),
        }
    }
}

fn detach(conn: &Connection, alias: &str) {
    let _ = conn.execute_batch(&format!("DETACH DATABASE {alias}"));
}

/// A version: the time in milliseconds, then the device ID for a tie. It picks the
/// winner of a conflict and marks a local change for [`stamp`].
type Version = (i64, String);

/// A version vector: for each device ID, the count of its changes to a record.
type Clock = BTreeMap<String, u64>;

/// How two clocks relate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Order {
    Equal,
    /// The first clock has every change of the second, and more.
    Newer,
    /// The second clock has every change of the first, and more.
    Older,
    /// Each clock has a change that the other lacks.
    Concurrent,
}

/// Read a clock: `device=count` pairs separated by `;`. A bad pair is left out.
fn parse_clock(text: &str) -> Clock {
    text.split(';')
        .filter_map(|pair| {
            let (device, count) = pair.split_once('=')?;
            let count: u64 = count.parse().ok()?;
            (!device.is_empty()).then(|| (device.to_owned(), count))
        })
        .collect()
}

/// Write a clock in the order of the device IDs, so equal clocks are equal text.
fn clock_text(clock: &Clock) -> String {
    clock
        .iter()
        .filter(|(_, count)| **count > 0)
        .map(|(device, count)| format!("{device}={count}"))
        .collect::<Vec<_>>()
        .join(";")
}

fn compare(a: &Clock, b: &Clock) -> Order {
    let (mut a_more, mut b_more) = (false, false);
    for device in a.keys().chain(b.keys()) {
        let (x, y) = (
            a.get(device).copied().unwrap_or(0),
            b.get(device).copied().unwrap_or(0),
        );
        a_more |= x > y;
        b_more |= y > x;
    }
    match (a_more, b_more) {
        (false, false) => Order::Equal,
        (true, false) => Order::Newer,
        (false, true) => Order::Older,
        (true, true) => Order::Concurrent,
    }
}

/// The clock with every change of both.
fn joined(a: &Clock, b: &Clock) -> Clock {
    let mut out = a.clone();
    for (device, count) in b {
        let entry = out.entry(device.clone()).or_insert(0);
        *entry = (*entry).max(*count);
    }
    out
}

/// One credential of a copy, with its child rows.
struct Record {
    id: i64,
    uuid: String,
    updated_at: i64,
    updated_by: String,
    clock: Clock,
    title: String,
    kind: String,
    notes: String,
    tags: Vec<String>,
    fields: Vec<(String, Zeroizing<String>, i64)>,
    archived_at: Option<i64>,
    declaration: Option<[String; 6]>,
    env: Option<(String, String, Option<String>)>,
    destination: Option<(String, String)>,
}

impl Record {
    fn version(&self) -> Version {
        (self.updated_at, self.updated_by.clone())
    }

    /// SHA-256 of the content: everything but the row ID and the version. The archive
    /// counts as on or off.
    fn content_hash(&self) -> [u8; 32] {
        let mut ctx = digest::Context::new(&digest::SHA256);
        let mut text = |value: &str| {
            ctx.update(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
            ctx.update(value.as_bytes());
        };
        text(&self.title);
        text(&self.kind);
        text(&self.notes);
        text(&self.tags.len().to_string());
        for tag in &self.tags {
            text(tag);
        }
        text(&self.fields.len().to_string());
        for (name, value, secret) in &self.fields {
            text(name);
            text(value);
            text(&secret.to_string());
        }
        text(if self.archived_at.is_some() { "1" } else { "0" });
        match &self.declaration {
            Some(values) => {
                text("d");
                for value in values {
                    text(value);
                }
            }
            None => text("-"),
        }
        match &self.env {
            Some((name, field, hosts)) => {
                text("e");
                text(name);
                text(field);
                text(hosts.as_deref().unwrap_or("\u{0}"));
            }
            None => text("-"),
        }
        match &self.destination {
            Some((profile, url)) => {
                text("c");
                text(profile);
                text(url);
            }
            None => text("-"),
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(ctx.finish().as_ref());
        out
    }
}

fn storage<E>(_: E) -> super::VaultError {
    err(VaultErrorKind::Storage)
}

/// Rows of `sql` as a map from the first column (an item ID) to the rest.
fn grouped<T>(
    conn: &Connection,
    sql: &str,
    row: impl Fn(&rusqlite::Row<'_>) -> rusqlite::Result<(i64, T)>,
) -> VaultResult<BTreeMap<i64, Vec<T>>> {
    let mut map: BTreeMap<i64, Vec<T>> = BTreeMap::new();
    let mut stmt = conn.prepare(sql).map_err(storage)?;
    let rows = stmt.query_map([], row).map_err(storage)?;
    for pair in rows {
        let (id, value) = pair.map_err(storage)?;
        map.entry(id).or_default().push(value);
    }
    Ok(map)
}

/// The credentials of the scope in `schema`, by UUID.
fn load_records(
    conn: &Connection,
    schema: &str,
    scope: &SyncScope,
) -> VaultResult<BTreeMap<String, Record>> {
    let filter = scope.item_filter();
    let mut tags = grouped(
        conn,
        &format!("SELECT item_id, tag FROM {schema}.item_tag ORDER BY item_id, position, rowid"),
        |row| Ok((row.get(0)?, row.get::<_, String>(1)?)),
    )?;
    let mut fields = grouped(
        conn,
        &format!(
            "SELECT item_id, name, value, secret FROM {schema}.item_field
             ORDER BY item_id, position, rowid"
        ),
        |row| {
            Ok((
                row.get(0)?,
                (
                    row.get::<_, String>(1)?,
                    Zeroizing::new(row.get::<_, String>(2)?),
                    row.get::<_, i64>(3)?,
                ),
            ))
        },
    )?;
    let mut archive = grouped(
        conn,
        &format!("SELECT item_id, archived_at FROM {schema}.item_archive"),
        |row| Ok((row.get(0)?, row.get::<_, i64>(1)?)),
    )?;
    let mut declarations = grouped(
        conn,
        &format!(
            "SELECT item_id, project, environment, risk, scope, reversibility, provider
             FROM {schema}.declaration"
        ),
        |row| {
            Ok((
                row.get(0)?,
                [
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                ],
            ))
        },
    )?;
    let mut envs = grouped(
        conn,
        &format!("SELECT item_id, env_name, field, placeholder_hosts FROM {schema}.env_binding"),
        |row| {
            Ok((
                row.get(0)?,
                (
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ),
            ))
        },
    )?;
    let mut destinations = grouped(
        conn,
        &format!("SELECT item_id, profile, base_url FROM {schema}.destination"),
        |row| {
            Ok((
                row.get(0)?,
                (row.get::<_, String>(1)?, row.get::<_, String>(2)?),
            ))
        },
    )?;
    let mut records = BTreeMap::new();
    let mut stmt = conn
        .prepare(&format!(
            "SELECT i.id, i.uuid, i.updated_at, i.updated_by, i.title, i.kind, i.notes, i.clock
             FROM {schema}.item i WHERE i.uuid IS NOT NULL AND ({filter})"
        ))
        .map_err(storage)?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
            ))
        })
        .map_err(storage)?;
    for row in rows {
        let (id, uuid, updated_at, updated_by, title, kind, notes, clock) = row.map_err(storage)?;
        let record = Record {
            id,
            uuid: uuid.clone(),
            updated_at,
            updated_by,
            clock: parse_clock(&clock),
            title,
            kind,
            notes,
            tags: tags.remove(&id).unwrap_or_default(),
            fields: fields.remove(&id).unwrap_or_default(),
            archived_at: archive.remove(&id).and_then(|mut all| all.pop()),
            declaration: declarations.remove(&id).and_then(|mut all| all.pop()),
            env: envs.remove(&id).and_then(|mut all| all.pop()),
            destination: destinations.remove(&id).and_then(|mut all| all.pop()),
        };
        records.insert(uuid, record);
    }
    Ok(records)
}

/// A tombstone: the time and the device of the delete, and the clock of the record with
/// the delete counted.
#[derive(Debug, Clone)]
struct Tombstone {
    deleted_at: i64,
    deleted_by: String,
    clock: Clock,
}

/// Tombstones in `schema`, by UUID.
fn load_tombstones(conn: &Connection, schema: &str) -> VaultResult<BTreeMap<String, Tombstone>> {
    let mut stmt = conn
        .prepare(&format!(
            "SELECT uuid, deleted_at, deleted_by, clock FROM {schema}.sync_tombstone"
        ))
        .map_err(storage)?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                Tombstone {
                    deleted_at: row.get(1)?,
                    deleted_by: row.get(2)?,
                    clock: parse_clock(&row.get::<_, String>(3)?),
                },
            ))
        })
        .map_err(storage)?;
    rows.collect::<Result<_, _>>().map_err(storage)
}

fn event_kinds_sql() -> String {
    SYNCED_EVENT_KINDS
        .iter()
        .map(|kind| format!("'{kind}'"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// SHA-256 of the synced content of the scope in `schema`: each credential with its
/// version, the tombstones, and the synced history events. Local data (agents,
/// activity, and the others) is not in it, so agent use does not count as a change.
pub(super) fn sync_content_digest(
    conn: &Connection,
    schema: &str,
    scope: &SyncScope,
) -> VaultResult<[u8; 32]> {
    let mut ctx = digest::Context::new(&digest::SHA256);
    ctx.update(b"apassy-sync-records-v1");
    for (uuid, record) in load_records(conn, schema, scope)? {
        ctx.update(b"\0r");
        ctx.update(uuid.as_bytes());
        ctx.update(&record.updated_at.to_be_bytes());
        ctx.update(record.updated_by.as_bytes());
        ctx.update(b"\0");
        ctx.update(clock_text(&record.clock).as_bytes());
        ctx.update(b"\0");
        ctx.update(&record.content_hash());
    }
    for (uuid, tomb) in load_tombstones(conn, schema)? {
        ctx.update(b"\0t");
        ctx.update(uuid.as_bytes());
        ctx.update(&tomb.deleted_at.to_be_bytes());
        ctx.update(tomb.deleted_by.as_bytes());
        ctx.update(b"\0");
        ctx.update(clock_text(&tomb.clock).as_bytes());
    }
    let mut stmt = conn
        .prepare(&format!(
            "SELECT uuid FROM {schema}.item_event
             WHERE uuid IS NOT NULL AND kind IN ({}) ORDER BY uuid",
            event_kinds_sql()
        ))
        .map_err(storage)?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(storage)?;
    for uuid in rows {
        ctx.update(b"\0e");
        ctx.update(uuid.map_err(storage)?.as_bytes());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(ctx.finish().as_ref());
    Ok(out)
}

/// Check an attached copy: the SQLCipher page checks, the SQLite integrity, the schema
/// version and columns, and the digest of the last push (it catches a file that mixes
/// pages of different copies). Returns its sync record.
fn check_attached(conn: &Connection, alias: &str) -> VaultResult<SyncIdentity> {
    let damaged = |_| err(VaultErrorKind::Damaged);
    let mut problem = false;
    conn.pragma_query(Some(alias), "cipher_integrity_check", |_| {
        problem = true;
        Ok(())
    })
    .map_err(|_| err(VaultErrorKind::WrongKeyOrCorrupt))?;
    if problem {
        return Err(err(VaultErrorKind::Damaged));
    }
    let integrity: String = conn
        .query_row(&format!("PRAGMA {alias}.integrity_check"), [], |row| {
            row.get(0)
        })
        .map_err(damaged)?;
    if integrity != "ok" {
        return Err(err(VaultErrorKind::Damaged));
    }
    let version: i64 = conn
        .query_row(&format!("PRAGMA {alias}.user_version"), [], |row| {
            row.get(0)
        })
        .map_err(damaged)?;
    if version != SCHEMA_VERSION {
        return Err(err(VaultErrorKind::UnsupportedSchema));
    }
    verify_expected_columns_in(conn, alias, version)?;
    let (identity, stored) = read_sync_row(conn, alias)?;
    match stored {
        Some(stored) if stored.as_slice() == content_digest(conn, alias)?.as_slice() => {
            Ok(identity)
        }
        None if identity.generation == 0 => Ok(identity),
        _ => Err(err(VaultErrorKind::Damaged)),
    }
}

/// Remove the local data from the attached copy `alias`, shrink it, and store the digest
/// of its content. The copy is then what the other Macs get.
pub(super) fn strip_attached(conn: &mut Connection, alias: &str) -> VaultResult<()> {
    conn.execute_batch(&format!("PRAGMA {alias}.secure_delete = ON"))
        .map_err(storage)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(storage)?;
    for table in LOCAL_TABLES {
        tx.execute(&format!("DELETE FROM {alias}.{table}"), [])
            .map_err(storage)?;
    }
    tx.execute(
        &format!(
            "DELETE FROM {alias}.item_event WHERE uuid IS NULL OR kind NOT IN ({})",
            event_kinds_sql()
        ),
        [],
    )
    .map_err(storage)?;
    tx.execute(
        &format!("UPDATE {alias}.vault_meta SET token_lifetime_days = 30"),
        [],
    )
    .map_err(storage)?;
    let names = LOCAL_TABLES
        .iter()
        .map(|name| format!("'{name}'"))
        .collect::<Vec<_>>()
        .join(", ");
    tx.execute(
        &format!("DELETE FROM {alias}.sqlite_sequence WHERE name IN ({names})"),
        [],
    )
    .map_err(storage)?;
    tx.commit().map_err(storage)?;
    conn.execute_batch(&format!("VACUUM {alias}"))
        .map_err(storage)?;
    let digest = content_digest(conn, alias)?;
    conn.execute(
        &format!("UPDATE {alias}.sync_meta SET content_digest = ?1 WHERE id = 1"),
        [digest.as_slice()],
    )
    .map(|_| ())
    .map_err(storage)
}

/// A credential that a merge kept twice: the other version is an archived copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConflictCopy {
    /// The title of the credential.
    pub title: String,
    /// The title of the archived copy: "<title> (conflict copy, <device>)".
    pub copy_title: String,
    /// The device whose version became the copy.
    pub device: String,
}

/// What a merge did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeReport {
    /// Credentials that came from the other copy.
    pub inserted: usize,
    /// Credentials that took the version of the other copy.
    pub updated: usize,
    /// Credentials that a tombstone of the other copy deleted.
    pub deleted: usize,
    /// Credentials that both sides changed: the other version is an archived copy.
    pub conflicts: Vec<ConflictCopy>,
    /// Variable names that another credential of this Mac has already. The incoming
    /// credential came without its variable.
    pub skipped_variables: Vec<String>,
    /// The sync record of the other copy.
    pub remote: SyncIdentity,
    /// The synced-content digest of the other copy.
    pub remote_content: [u8; 32],
}

impl MergeReport {
    /// Whether the merge changed the credentials of this vault.
    pub fn changed_local(&self) -> bool {
        self.inserted + self.updated + self.deleted + self.conflicts.len() > 0
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
        })
}

fn now_secs() -> i64 {
    now_ms() / 1000
}

/// "<title> (conflict copy, <device>)", within the longest title.
fn copy_title(title: &str, device: &str) -> String {
    let suffix = format!(" (conflict copy, {device})");
    let room = super::types::MAX_TITLE_BYTES.saturating_sub(suffix.len());
    let mut head = String::new();
    for ch in title.chars() {
        if head.len() + ch.len_utf8() > room {
            break;
        }
        head.push(ch);
    }
    let mut out = format!("{}{suffix}", head.trim_end());
    while out.len() > super::types::MAX_TITLE_BYTES {
        out.pop();
    }
    out
}

/// The readable name of `device_id`, from the device list of the vault.
fn device_label(tx: &rusqlite::Transaction<'_>, device_id: &str) -> VaultResult<String> {
    let own: Option<(String, String)> = tx
        .query_row(
            "SELECT device_id, device_name FROM sync_device WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(storage)?;
    if let Some((id, name)) = own
        && id == device_id
        && !name.is_empty()
    {
        return Ok(name);
    }
    let name: Option<String> = tx
        .query_row(
            "SELECT name FROM sync_peer WHERE device_id = ?1",
            [device_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(storage)?;
    Ok(name
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "another device".to_owned()))
}

/// Write the child rows of `record` for the item `id` of this vault. A variable name that
/// another credential has already is left out and reported.
fn write_children(
    tx: &rusqlite::Transaction<'_>,
    id: i64,
    record: &Record,
    with_settings: bool,
    report: &mut MergeReport,
) -> VaultResult<()> {
    for (position, tag) in record.tags.iter().enumerate() {
        tx.execute(
            "INSERT INTO item_tag (item_id, position, tag) VALUES (?1, ?2, ?3)",
            (id, i64::try_from(position).map_err(storage)?, tag),
        )
        .map_err(storage)?;
    }
    for (position, (name, value, secret)) in record.fields.iter().enumerate() {
        tx.execute(
            "INSERT INTO item_field (item_id, position, name, value, secret)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            (
                id,
                i64::try_from(position).map_err(storage)?,
                name,
                value.as_str(),
                secret,
            ),
        )
        .map_err(storage)?;
    }
    if !with_settings {
        return Ok(());
    }
    if let Some(at) = record.archived_at {
        tx.execute(
            "INSERT INTO item_archive (item_id, archived_at) VALUES (?1, ?2)",
            (id, at),
        )
        .map_err(storage)?;
    }
    if let Some([project, environment, risk, scope, reversibility, provider]) = &record.declaration
    {
        tx.execute(
            "INSERT INTO declaration (item_id, project, environment, risk, scope,
                 reversibility, provider) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            (
                id,
                project,
                environment,
                risk,
                scope,
                reversibility,
                provider,
            ),
        )
        .map_err(storage)?;
    }
    if let Some((name, field, hosts)) = &record.env {
        let taken: Option<i64> = tx
            .query_row(
                "SELECT item_id FROM env_binding WHERE env_name = ?1 AND item_id != ?2",
                (name, id),
                |row| row.get(0),
            )
            .optional()
            .map_err(storage)?;
        if taken.is_some() {
            report.skipped_variables.push(name.clone());
        } else {
            tx.execute(
                "INSERT INTO env_binding (item_id, env_name, field, placeholder_hosts)
                 VALUES (?1, ?2, ?3, ?4)",
                (id, name, field, hosts),
            )
            .map_err(storage)?;
        }
    }
    if let Some((profile, url)) = &record.destination {
        tx.execute(
            "INSERT INTO destination (item_id, profile, base_url) VALUES (?1, ?2, ?3)",
            (id, profile, url),
        )
        .map_err(storage)?;
    }
    Ok(())
}

fn delete_children(tx: &rusqlite::Transaction<'_>, id: i64) -> VaultResult<()> {
    for table in CHILD_TABLES {
        tx.execute(&format!("DELETE FROM {table} WHERE item_id = ?1"), [id])
            .map_err(storage)?;
    }
    Ok(())
}

fn insert_record(
    tx: &rusqlite::Transaction<'_>,
    record: &Record,
    report: &mut MergeReport,
) -> VaultResult<i64> {
    tx.execute(
        "INSERT INTO item (uuid, title, kind, notes, revision, updated_at, updated_by, clock)
         VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6, ?7)",
        (
            &record.uuid,
            &record.title,
            &record.kind,
            &record.notes,
            record.updated_at,
            &record.updated_by,
            clock_text(&record.clock),
        ),
    )
    .map_err(storage)?;
    let id = tx.last_insert_rowid();
    write_children(tx, id, record, true, report)?;
    set_stamp(tx, &record.uuid, &record.version())?;
    Ok(id)
}

/// Replace the local credential `local` with the content and the version of `record`,
/// with `clock`. The revision grows, so an open edit form refuses its stale save.
fn replace_record(
    tx: &rusqlite::Transaction<'_>,
    local: &Record,
    record: &Record,
    clock: &Clock,
    report: &mut MergeReport,
) -> VaultResult<()> {
    delete_children(tx, local.id)?;
    tx.execute(
        "UPDATE item SET title = ?1, kind = ?2, notes = ?3, revision = revision + 1,
             updated_at = ?4, updated_by = ?5, clock = ?6 WHERE id = ?7",
        (
            &record.title,
            &record.kind,
            &record.notes,
            record.updated_at,
            &record.updated_by,
            clock_text(clock),
            local.id,
        ),
    )
    .map_err(storage)?;
    set_stamp(tx, &record.uuid, &record.version())?;
    write_children(tx, local.id, record, true, report)?;
    // As at "remove variable": without a variable, the process grants go.
    let has_env: Option<i64> = tx
        .query_row(
            "SELECT item_id FROM env_binding WHERE item_id = ?1",
            [local.id],
            |row| row.get(0),
        )
        .optional()
        .map_err(storage)?;
    if local.env.is_some() && has_env.is_none() {
        tx.execute("DELETE FROM exec_grant WHERE item_id = ?1", [local.id])
            .map_err(storage)?;
    }
    Ok(())
}

/// Delete the local credential `id` as a delete by the owner does: its child rows, its
/// agent links and grants, its history, and the item.
fn delete_record(tx: &rusqlite::Transaction<'_>, id: i64) -> VaultResult<()> {
    tx.execute("DELETE FROM item_field WHERE item_id = ?1", [id])
        .map_err(storage)?;
    tx.execute("DELETE FROM item_tag WHERE item_id = ?1", [id])
        .map_err(storage)?;
    agents::delete_item_links(tx, id)?;
    history::forget_item(tx, id)?;
    tx.execute("DELETE FROM item WHERE id = ?1", [id])
        .map_err(storage)?;
    Ok(())
}

/// Keep `loser` as an archived credential "<title> (conflict copy, <device>)", without
/// its agent settings, so no variable or connector is there twice. Its UUID, version, and
/// clock come from the loser, so each Mac that sees the conflict makes the same copy.
fn keep_conflict_copy(
    tx: &rusqlite::Transaction<'_>,
    loser: &Record,
    report: &mut MergeReport,
) -> VaultResult<()> {
    let device = device_label(tx, &loser.updated_by)?;
    let copy_title = copy_title(&loser.title, &device);
    report.conflicts.push(ConflictCopy {
        title: loser.title.clone(),
        copy_title: copy_title.clone(),
        device,
    });
    let clock = clock_text(&loser.clock);
    let uuid = derived_uuid(&[
        "conflict",
        &loser.uuid,
        &clock,
        &loser.updated_at.to_string(),
        &loser.updated_by,
    ]);
    let exists: Option<i64> = tx
        .query_row("SELECT id FROM item WHERE uuid = ?1", [&uuid], |row| {
            row.get(0)
        })
        .optional()
        .map_err(storage)?;
    if exists.is_some() {
        return Ok(());
    }
    tx.execute(
        "INSERT INTO item (uuid, title, kind, notes, revision, updated_at, updated_by, clock)
         VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6, ?7)",
        (
            &uuid,
            &copy_title,
            &loser.kind,
            &loser.notes,
            loser.updated_at,
            &loser.updated_by,
            &clock,
        ),
    )
    .map_err(storage)?;
    let id = tx.last_insert_rowid();
    write_children(tx, id, loser, false, report)?;
    set_stamp(tx, &uuid, &loser.version())?;
    tx.execute(
        "INSERT INTO item_archive (item_id, archived_at) VALUES (?1, ?2)",
        (id, now_secs()),
    )
    .map_err(storage)?;
    Ok(())
}

fn set_applying(tx: &rusqlite::Transaction<'_>, on: bool) -> VaultResult<()> {
    tx.execute(
        "UPDATE sync_device SET applying = ?1 WHERE id = 1",
        [i64::from(on)],
    )
    .map(|_| ())
    .map_err(storage)
}

/// Record that `version` of `uuid` is counted in its clock: it is not a local change.
fn set_stamp(tx: &rusqlite::Transaction<'_>, uuid: &str, version: &Version) -> VaultResult<()> {
    tx.execute(
        "INSERT INTO sync_stamp (uuid, updated_at, updated_by) VALUES (?1, ?2, ?3)
         ON CONFLICT(uuid) DO UPDATE SET updated_at = excluded.updated_at,
             updated_by = excluded.updated_by",
        (uuid, version.0, &version.1),
    )
    .map(|_| ())
    .map_err(storage)
}

/// Count each local change since the last stamp in the clock of this device: a
/// credential or a tombstone whose version differs from its stamp. Runs in the
/// transaction of a merge or a push, with `applying` on, so the change of the clock does
/// not count as a change of the credential.
fn stamp(tx: &rusqlite::Transaction<'_>) -> VaultResult<()> {
    let own: String = tx
        .query_row(
            "SELECT device_id FROM sync_device WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .map_err(storage)?;
    for (table, at, by) in [
        ("item", "updated_at", "updated_by"),
        ("sync_tombstone", "deleted_at", "deleted_by"),
    ] {
        let changed: Vec<(String, i64, String, String)> = {
            let mut stmt = tx
                .prepare(&format!(
                    "SELECT t.uuid, t.{at}, t.{by}, t.clock FROM {table} t
                     LEFT JOIN sync_stamp s ON s.uuid = t.uuid
                     WHERE t.uuid IS NOT NULL AND (s.uuid IS NULL
                         OR s.updated_at != t.{at} OR s.updated_by != t.{by})"
                ))
                .map_err(storage)?;
            stmt.query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .map_err(storage)?
            .collect::<Result<_, _>>()
            .map_err(storage)?
        };
        for (uuid, at_value, by_value, clock) in changed {
            let mut clock = parse_clock(&clock);
            *clock.entry(own.clone()).or_insert(0) += 1;
            tx.execute(
                &format!("UPDATE {table} SET clock = ?1 WHERE uuid = ?2"),
                (clock_text(&clock), &uuid),
            )
            .map_err(storage)?;
            set_stamp(tx, &uuid, &(at_value, by_value))?;
        }
    }
    tx.execute(
        "DELETE FROM sync_stamp WHERE uuid NOT IN (SELECT uuid FROM item WHERE uuid IS NOT NULL)
             AND uuid NOT IN (SELECT uuid FROM sync_tombstone)",
        [],
    )
    .map_err(storage)?;
    Ok(())
}

/// Stamp the local changes in their own transaction, before a push.
pub(super) fn stamp_conn(conn: &mut Connection) -> VaultResult<()> {
    ensure_device(conn)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(storage)?;
    set_applying(&tx, true)?;
    stamp(&tx)?;
    set_applying(&tx, false)?;
    tx.commit().map_err(storage)
}

/// Record every credential and tombstone as stamped, for a vault made from a copy: its
/// content is the copy, not a change of this device.
pub(super) fn mark_seen(conn: &mut Connection) -> VaultResult<()> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(storage)?;
    tx.execute("DELETE FROM sync_stamp", []).map_err(storage)?;
    tx.execute(
        "INSERT INTO sync_stamp (uuid, updated_at, updated_by)
         SELECT uuid, updated_at, updated_by FROM item WHERE uuid IS NOT NULL
         UNION ALL SELECT uuid, deleted_at, deleted_by FROM sync_tombstone",
        [],
    )
    .map_err(storage)?;
    tx.commit().map_err(storage)
}

/// Merge the attached copy `REMOTE` into the vault, in one transaction.
fn merge_attached(conn: &mut Connection, scope: &SyncScope) -> VaultResult<MergeReport> {
    ensure_device(conn)?;
    let remote_identity = check_attached(conn, REMOTE)?;
    let remote_content = sync_content_digest(conn, REMOTE, scope)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(storage)?;
    let (local_identity, _) = read_sync_row(&tx, "main")?;
    if local_identity.vault_id != remote_identity.vault_id {
        return Err(err(VaultErrorKind::OtherVault));
    }
    set_applying(&tx, true)?;
    stamp(&tx)?;
    let mut report = MergeReport {
        inserted: 0,
        updated: 0,
        deleted: 0,
        conflicts: Vec::new(),
        skipped_variables: Vec::new(),
        remote: remote_identity,
        remote_content,
    };
    // Device names first, for the titles of conflict copies.
    tx.execute(
        &format!(
            "INSERT INTO sync_peer (device_id, name, seen_at)
             SELECT device_id, name, seen_at FROM {REMOTE}.sync_peer WHERE true
             ON CONFLICT(device_id) DO UPDATE SET name = excluded.name,
                 seen_at = excluded.seen_at WHERE excluded.seen_at > sync_peer.seen_at"
        ),
        [],
    )
    .map_err(storage)?;
    let local = load_records(&tx, "main", scope)?;
    let remote = load_records(&tx, REMOTE, scope)?;
    let local_tombs = load_tombstones(&tx, "main")?;
    let remote_tombs = load_tombstones(&tx, REMOTE)?;
    let uuids: BTreeSet<&String> = local.keys().chain(remote.keys()).collect();
    for uuid in uuids {
        match (local.get(uuid), remote.get(uuid)) {
            (None, Some(theirs)) => {
                // A local delete that saw this version of the record keeps it deleted.
                let deleted_here = local_tombs.get(uuid).is_some_and(|tomb| {
                    matches!(
                        compare(&tomb.clock, &theirs.clock),
                        Order::Newer | Order::Equal
                    )
                });
                let exists: Option<i64> = tx
                    .query_row("SELECT id FROM item WHERE uuid = ?1", [uuid], |row| {
                        row.get(0)
                    })
                    .optional()
                    .map_err(storage)?;
                if !deleted_here && exists.is_none() {
                    insert_record(&tx, theirs, &mut report)?;
                    tx.execute("DELETE FROM sync_tombstone WHERE uuid = ?1", [uuid])
                        .map_err(storage)?;
                    report.inserted += 1;
                }
            }
            (Some(ours), None) => {
                // A delete on the other side that saw this version deletes the
                // credential. A change here that the delete did not see keeps it.
                if remote_tombs.get(uuid).is_some_and(|tomb| {
                    matches!(
                        compare(&tomb.clock, &ours.clock),
                        Order::Newer | Order::Equal
                    )
                }) {
                    delete_record(&tx, ours.id)?;
                    report.deleted += 1;
                }
            }
            (Some(ours), Some(theirs)) => match compare(&ours.clock, &theirs.clock) {
                // The same version, or an older copy: nothing to take.
                Order::Equal | Order::Newer => {}
                Order::Older => {
                    replace_record(&tx, ours, theirs, &theirs.clock, &mut report)?;
                    report.updated += 1;
                }
                Order::Concurrent => {
                    let clock = joined(&ours.clock, &theirs.clock);
                    let later = ours.version().max(theirs.version());
                    if ours.content_hash() == theirs.content_hash() {
                        tx.execute(
                            "UPDATE item SET updated_at = ?1, updated_by = ?2, clock = ?3
                             WHERE id = ?4",
                            (later.0, &later.1, clock_text(&clock), ours.id),
                        )
                        .map_err(storage)?;
                        set_stamp(&tx, uuid, &later)?;
                    } else if theirs.version() > ours.version() {
                        keep_conflict_copy(&tx, ours, &mut report)?;
                        replace_record(&tx, ours, theirs, &clock, &mut report)?;
                        report.updated += 1;
                    } else {
                        keep_conflict_copy(&tx, theirs, &mut report)?;
                        tx.execute(
                            "UPDATE item SET clock = ?1 WHERE id = ?2",
                            (clock_text(&clock), ours.id),
                        )
                        .map_err(storage)?;
                    }
                }
            },
            (None, None) => {}
        }
    }
    // Tombstones: keep the delete that saw more, drop a tombstone of a record that is
    // here, and drop the old ones.
    for (uuid, theirs) in &remote_tombs {
        let take = match local_tombs.get(uuid) {
            None => true,
            Some(ours) => matches!(compare(&theirs.clock, &ours.clock), Order::Newer),
        };
        if take {
            tx.execute(
                "INSERT OR REPLACE INTO sync_tombstone (uuid, deleted_at, deleted_by, clock)
                 VALUES (?1, ?2, ?3, ?4)",
                (
                    uuid,
                    theirs.deleted_at,
                    &theirs.deleted_by,
                    clock_text(&theirs.clock),
                ),
            )
            .map_err(storage)?;
            set_stamp(&tx, uuid, &(theirs.deleted_at, theirs.deleted_by.clone()))?;
        } else if let Some(ours) = local_tombs.get(uuid)
            && compare(&theirs.clock, &ours.clock) == Order::Concurrent
        {
            let clock = joined(&theirs.clock, &ours.clock);
            tx.execute(
                "UPDATE sync_tombstone SET clock = ?1 WHERE uuid = ?2",
                (clock_text(&clock), uuid),
            )
            .map_err(storage)?;
        }
    }
    tx.execute(
        "DELETE FROM sync_tombstone WHERE uuid IN (SELECT uuid FROM item WHERE uuid IS NOT NULL)",
        [],
    )
    .map_err(storage)?;
    tx.execute(
        "DELETE FROM sync_tombstone WHERE deleted_at < ?1",
        [now_ms() - TOMBSTONE_DAYS * 86_400_000],
    )
    .map_err(storage)?;
    merge_events(&tx)?;
    set_applying(&tx, false)?;
    tx.commit().map_err(storage)?;
    Ok(report)
}

/// Add the synced history events of the other copy that this vault does not have, for
/// the credentials that are here. Then keep the newest events of each credential.
fn merge_events(tx: &rusqlite::Transaction<'_>) -> VaultResult<()> {
    let rows: Vec<(String, String, i64, String, String)> = {
        let mut stmt = tx
            .prepare(&format!(
                "SELECT e.uuid, i.uuid, e.at, e.kind, e.detail
                 FROM {REMOTE}.item_event e JOIN {REMOTE}.item i ON i.id = e.item_id
                 WHERE e.uuid IS NOT NULL AND i.uuid IS NOT NULL AND e.kind IN ({})",
                event_kinds_sql()
            ))
            .map_err(storage)?;
        stmt.query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })
        .map_err(storage)?
        .collect::<Result<_, _>>()
        .map_err(storage)?
    };
    let mut touched = BTreeSet::new();
    for (event_uuid, item_uuid, at, kind, detail) in rows {
        let item: Option<i64> = tx
            .query_row("SELECT id FROM item WHERE uuid = ?1", [&item_uuid], |row| {
                row.get(0)
            })
            .optional()
            .map_err(storage)?;
        let Some(item) = item else {
            continue;
        };
        let added = tx
            .execute(
                "INSERT INTO item_event (item_id, at, kind, detail, uuid)
                 SELECT ?1, ?2, ?3, ?4, ?5
                 WHERE NOT EXISTS (SELECT 1 FROM item_event WHERE uuid = ?5)",
                (item, at, kind, detail, &event_uuid),
            )
            .map_err(storage)?;
        if added > 0 {
            touched.insert(item);
        }
    }
    let keep = i64::try_from(MAX_ITEM_EVENTS).map_err(storage)?;
    for item in touched {
        tx.execute(
            "DELETE FROM item_event WHERE item_id = ?1 AND id NOT IN
                 (SELECT id FROM item_event WHERE item_id = ?1 ORDER BY at DESC, id DESC LIMIT ?2)",
            (item, keep),
        )
        .map_err(storage)?;
    }
    Ok(())
}

impl Vault {
    /// The synced-content digest of the scope: each credential with its version, the
    /// tombstones, and the synced history. A change of local data (agents, activity) does
    /// not change it. The vault must be unlocked.
    pub fn sync_content(&self, scope: &SyncScope) -> VaultResult<[u8; 32]> {
        sync_content_digest(self.conn_ref()?, "main", scope)
    }

    /// Check a copy at `path` with the key of this vault and return its sync record. The
    /// copy does not change. A copy that does not open with the key (another vault, or a
    /// passphrase that changed on another Mac) is `WrongKeyOrCorrupt`; a copy that opens
    /// but fails a check is `Damaged`.
    pub fn check_sync_copy(&self, path: &Path, scope: &SyncScope) -> VaultResult<SyncIdentity> {
        let conn = self.conn_ref()?;
        scope.attach(conn, path, REMOTE)?;
        let result = check_attached(conn, REMOTE);
        detach(conn, REMOTE);
        result
    }

    /// Merge the copy at `path` into this vault, record by record (ADR 0014). The vault
    /// must be unlocked. The copy is a local file, never a file in a synced folder. It
    /// must pass the checks of [`Vault::check_sync_copy`] and have the vault ID of this
    /// vault (`OtherVault`).
    pub fn merge_from(&mut self, path: &Path, scope: &SyncScope) -> VaultResult<MergeReport> {
        self.require_unlocked()?;
        let conn = self.conn_mut()?;
        scope.attach(conn, path, REMOTE)?;
        let result = merge_attached(conn, scope);
        if result.is_err() {
            let _ = conn.execute_batch("ROLLBACK");
        }
        detach(conn, REMOTE);
        result
    }

    /// The random device ID of this vault file, for the versions of its changes.
    pub fn sync_device_id(&self) -> VaultResult<String> {
        self.conn_ref()?
            .query_row(
                "SELECT device_id FROM sync_device WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .map_err(storage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_uuids_are_stable_and_distinct() {
        let a = derived_uuid(&["vault", "item", "1"]);
        assert_eq!(a, derived_uuid(&["vault", "item", "1"]));
        assert_ne!(a, derived_uuid(&["vault", "item", "2"]));
        assert_ne!(a, derived_uuid(&["vault", "item_event", "1"]));
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn clocks_order_and_join() {
        let a = parse_clock("aa=2;bb=1");
        let b = parse_clock("aa=1;bb=1");
        assert_eq!(compare(&a, &b), Order::Newer);
        assert_eq!(compare(&b, &a), Order::Older);
        assert_eq!(compare(&a, &a), Order::Equal);
        let c = parse_clock("bb=2");
        assert_eq!(compare(&a, &c), Order::Concurrent);
        assert_eq!(clock_text(&joined(&a, &c)), "aa=2;bb=2");
        assert_eq!(compare(&parse_clock(""), &Clock::new()), Order::Equal);
        assert_eq!(clock_text(&parse_clock("x=1;bad;=3;y=q")), "x=1");
    }

    #[test]
    fn conflict_titles_fit_and_name_the_device() {
        assert_eq!(
            copy_title("Stripe", "Mac mini"),
            "Stripe (conflict copy, Mac mini)"
        );
        let long = copy_title(&"ż".repeat(100), "Studio");
        assert!(long.len() <= super::super::types::MAX_TITLE_BYTES);
        assert!(long.ends_with(" (conflict copy, Studio)"), "{long}");
    }

    #[test]
    fn every_table_is_synced_or_local() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut vault = Vault::create(&dir.path().join("t.db"), "synthetic-table-pass").unwrap();
        vault.unlock("synthetic-table-pass").unwrap();
        let conn = vault.conn_ref().unwrap();
        let mut stmt = conn
            .prepare("SELECT name FROM sqlite_schema WHERE type = 'table' ORDER BY name")
            .unwrap();
        let names: Vec<String> = stmt
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        for name in names {
            assert!(
                SYNCED_TABLES.contains(&name.as_str()) || LOCAL_TABLES.contains(&name.as_str()),
                "table {name} must be in SYNCED_TABLES or LOCAL_TABLES"
            );
        }
    }
}
