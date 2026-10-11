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
//!
//! A copy of the schema before passkeys ([`UPGRADABLE_SCHEMA`]) passes the checks of its
//! own schema first. Then the merge gives its records the field names of the current
//! schema in memory ([`upgrade_records`]); the copy does not change.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use ring::digest;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior};
use zeroize::Zeroizing;

use super::sync::{SyncIdentity, content_digest, read_sync_row, to_hex};
use super::types::{SCHEMA_VERSION, VaultErrorKind, VaultResult, err, is_passkey_field};
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

/// Tables that stay on each Mac. A pushed copy keeps only the default companion setting, and a merge never
/// reads them from another copy.
pub const LOCAL_TABLES: [&str; 22] = [
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
    "companion_setting",
    "companion_certificate",
    "companion_device",
    "relay_device",
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

/// The one earlier schema of a copy that a merge takes: schema 16, before passkeys. The
/// app of an installed device still writes it. A copy of another schema is
/// `UnsupportedSchema`.
pub(super) const UPGRADABLE_SCHEMA: i64 = super::RELAY_DEVICE_SCHEMA_VERSION;

// [`upgrade_records`] does the step from schema 16 to schema 17 only. A new schema needs
// its own step for a copy, or a refusal of the old copies.
const _: () = assert!(SCHEMA_VERSION == UPGRADABLE_SCHEMA + 1);

/// A tombstone stays this long. A copy that is older than this can bring a deleted
/// credential back.
pub const TOMBSTONE_DAYS: i64 = 180;

/// The alias of the other copy during a merge.
const REMOTE: &str = "sync_remote";
/// A synced creation event records the origin without a schema change. Its UUID binds
/// the copy UUID to the origin UUID; no editable item text establishes this relation.
pub(super) const CONFLICT_ORIGIN_PREFIX: &str = "apassy:conflict-origin:v1:";
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
        return preserve_legacy_conflict_origins(conn);
    }
    conn.execute(
        "INSERT OR IGNORE INTO sync_device (id, device_id, device_name)
         VALUES (1, lower(hex(randomblob(16))), '')",
        [],
    )
    .map_err(|_| err(VaultErrorKind::Storage))?;
    preserve_legacy_conflict_origins(conn)
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

    /// Attach the copy at `path` as `alias` with the key of `passphrase`, for a copy
    /// under another passphrase than the vault.
    fn attach_with(
        &self,
        conn: &Connection,
        path: &Path,
        alias: &str,
        passphrase: &str,
    ) -> VaultResult<()> {
        let path = path
            .to_str()
            .ok_or_else(|| err(VaultErrorKind::InvalidInput))?;
        match self.kind {
            ScopeKind::Vault => conn
                .execute(
                    &format!("ATTACH DATABASE ?1 AS {alias} KEY ?2"),
                    [path, passphrase],
                )
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
/// pages of different copies). Returns its sync record and its schema version.
///
/// A schema 16 copy gets the checks of schema 16: its columns, and the stored digest
/// of its own content. The version in the header and in `vault_meta` must agree, so a
/// copy of schema 17 with the header of schema 16 fails.
fn check_attached(conn: &Connection, alias: &str) -> VaultResult<(SyncIdentity, i64)> {
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
    if version != SCHEMA_VERSION && version != UPGRADABLE_SCHEMA {
        return Err(err(VaultErrorKind::UnsupportedSchema));
    }
    verify_expected_columns_in(conn, alias, version)?;
    let (identity, stored) = read_sync_row(conn, alias)?;
    match stored {
        Some(stored) if stored.as_slice() == content_digest(conn, alias)?.as_slice() => {
            Ok((identity, version))
        }
        None if identity.generation == 0 => Ok((identity, version)),
        _ => Err(err(VaultErrorKind::Damaged)),
    }
}

/// The private tables that [`super::passkey::add_schema_v17`] reads and writes, for
/// [`upgrade_records`]. They hold names only, never a value.
const UPGRADE_TABLES_SQL: &str = "
CREATE TABLE vault_meta (id INTEGER PRIMARY KEY, schema_version INTEGER NOT NULL);
INSERT INTO vault_meta (id, schema_version) VALUES (1, 16);
PRAGMA user_version = 16;
CREATE TABLE sync_device (
    id INTEGER PRIMARY KEY,
    device_id TEXT NOT NULL DEFAULT '',
    device_name TEXT NOT NULL DEFAULT '',
    applying INTEGER NOT NULL DEFAULT 0
);
INSERT INTO sync_device (id) VALUES (1);
CREATE TABLE item (
    id INTEGER PRIMARY KEY,
    uuid TEXT,
    title TEXT NOT NULL DEFAULT '',
    kind TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    revision INTEGER NOT NULL DEFAULT 1,
    updated_at INTEGER NOT NULL DEFAULT 0,
    updated_by TEXT NOT NULL DEFAULT '',
    clock TEXT NOT NULL DEFAULT ''
);
CREATE TABLE item_field (
    item_id INTEGER NOT NULL,
    position INTEGER NOT NULL,
    name TEXT NOT NULL,
    value TEXT NOT NULL DEFAULT '',
    secret INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE env_binding (
    item_id INTEGER PRIMARY KEY,
    env_name TEXT NOT NULL,
    field TEXT NOT NULL,
    placeholder_hosts TEXT
);
";

/// Give the records of a schema 16 copy the field names of schema 17, in memory.
///
/// The names come from the migration itself ([`super::passkey::add_schema_v17`]), so
/// each record gets the names that the unlock of a schema 16 vault gives: an ordinary
/// field with a reserved name gets a free name, and a variable of that field follows it.
/// The migration runs on a private in-memory database that holds only the field names,
/// the secret flags, and the variable fields of the records with a reserved name. No
/// value goes into it. Values, versions, and clocks stay, so the merge compares the
/// same content on both sides and makes no conflict from the upgrade.
fn upgrade_records(records: &mut BTreeMap<String, Record>) -> VaultResult<()> {
    let mut legacy: Vec<&mut Record> = records
        .values_mut()
        .filter(|record| {
            record
                .fields
                .iter()
                .any(|(name, ..)| is_passkey_field(name))
        })
        .collect();
    if legacy.is_empty() {
        return Ok(());
    }
    let mut conn = Connection::open_in_memory().map_err(storage)?;
    conn.execute_batch(UPGRADE_TABLES_SQL).map_err(storage)?;
    let tx = conn.transaction().map_err(storage)?;
    for (index, record) in legacy.iter().enumerate() {
        let item = i64::try_from(index).map_err(storage)?;
        tx.execute("INSERT INTO item (id) VALUES (?1)", [item])
            .map_err(storage)?;
        for (position, (name, _, secret)) in record.fields.iter().enumerate() {
            tx.execute(
                "INSERT INTO item_field (item_id, position, name, secret)
                 VALUES (?1, ?2, ?3, ?4)",
                (
                    item,
                    i64::try_from(position).map_err(storage)?,
                    name,
                    secret,
                ),
            )
            .map_err(storage)?;
        }
        if let Some((env_name, field, _)) = &record.env {
            tx.execute(
                "INSERT INTO env_binding (item_id, env_name, field) VALUES (?1, ?2, ?3)",
                (item, env_name, field),
            )
            .map_err(storage)?;
        }
    }
    super::passkey::add_schema_v17(&tx)?;
    let version: i64 = tx
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(storage)?;
    if version != SCHEMA_VERSION {
        return Err(err(VaultErrorKind::Storage));
    }
    for (index, record) in legacy.iter_mut().enumerate() {
        let item = i64::try_from(index).map_err(storage)?;
        let names: Vec<String> = {
            let mut stmt = tx
                .prepare("SELECT name FROM item_field WHERE item_id = ?1 ORDER BY position")
                .map_err(storage)?;
            stmt.query_map([item], |row| row.get(0))
                .map_err(storage)?
                .collect::<Result<_, _>>()
                .map_err(storage)?
        };
        if names.len() != record.fields.len() || names.iter().any(|name| is_passkey_field(name)) {
            return Err(err(VaultErrorKind::Storage));
        }
        for ((name, ..), new) in record.fields.iter_mut().zip(names) {
            *name = new;
        }
        if let Some((_, field, _)) = record.env.as_mut() {
            *field = tx
                .query_row(
                    "SELECT field FROM env_binding WHERE item_id = ?1",
                    [item],
                    |row| row.get(0),
                )
                .map_err(storage)?;
        }
    }
    Ok(())
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
    // A new Mac needs a valid setting row. Never export this Mac's enabled state or port.
    tx.execute(
        &format!("INSERT INTO {alias}.companion_setting (id, enabled, port) VALUES (1, 0, ?1)"),
        [super::companion::DEFAULT_COMPANION_PORT],
    )
    .map_err(storage)?;
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
    /// The synced-content digest of the other copy, as the copy holds it (before an
    /// upgrade of its schema).
    pub remote_content: [u8; 32],
    /// The schema version of the other copy: [`SCHEMA_VERSION`], or 16 for a copy of
    /// an installed app before passkeys.
    pub remote_schema: i64,
}

impl MergeReport {
    /// Whether the merge changed the credentials of this vault.
    pub fn changed_local(&self) -> bool {
        self.inserted + self.updated + self.deleted + self.conflicts.len() > 0
    }

    /// Whether the other copy has an earlier schema than this vault. Then the caller
    /// writes a new copy, also when the content is the same: the copy of the current
    /// schema replaces it. The merge never changes the other copy.
    pub fn remote_outdated(&self) -> bool {
        self.remote_schema < SCHEMA_VERSION
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

fn conflict_origin_event_uuid(copy: &str, origin: &str) -> String {
    derived_uuid(&["conflict-origin-v1", copy, origin])
}

pub(super) fn verified_conflict_origin<'a>(
    copy: &str,
    detail: &'a str,
    event_uuid: &str,
) -> Option<&'a str> {
    let origin = detail.strip_prefix(CONFLICT_ORIGIN_PREFIX)?;
    (origin.len() == 32
        && origin.bytes().all(|byte| byte.is_ascii_hexdigit())
        && origin != copy
        && event_uuid == conflict_origin_event_uuid(copy, origin))
    .then_some(origin)
}

fn record_conflict_origin(conn: &Connection, id: i64, copy: &str, origin: &str) -> VaultResult<()> {
    let event_uuid = conflict_origin_event_uuid(copy, origin);
    let present: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM item_event WHERE uuid = ?1)",
            [&event_uuid],
            |row| row.get(0),
        )
        .map_err(storage)?;
    if present {
        return Ok(());
    }
    conn.execute(
        "INSERT OR IGNORE INTO item_event (item_id, at, kind, detail, uuid)
         VALUES (?1, ?2, 'created', ?3, ?4)",
        (
            id,
            now_secs(),
            format!("{CONFLICT_ORIGIN_PREFIX}{origin}"),
            event_uuid,
        ),
    )
    .map(|_| ())
    .map_err(storage)
}

/// Read only sync metadata, never fields or secret values. Older unmodified copies
/// are recognized by the exact UUID derivation, independently of their title.
fn conflict_origins(conn: &Connection, include_legacy: bool) -> VaultResult<BTreeMap<i64, String>> {
    let mut origins = BTreeMap::new();
    let mut stmt = conn
        .prepare(
            "SELECT e.item_id, i.uuid, e.detail, e.uuid
             FROM item_event e JOIN item i ON i.id = e.item_id
             WHERE e.kind = 'created' AND e.detail LIKE 'apassy:conflict-origin:v1:%'",
        )
        .map_err(storage)?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(storage)?;
    for row in rows {
        let (id, copy, detail, event_uuid) = row.map_err(storage)?;
        let Some(origin) = verified_conflict_origin(&copy, &detail, &event_uuid) else {
            continue;
        };
        origins.insert(id, origin.to_owned());
    }
    if !include_legacy {
        return Ok(origins);
    }
    let mut stmt = conn
        .prepare(
            "SELECT i.id, i.uuid, i.clock, i.updated_at, i.updated_by FROM item i
             JOIN item_archive a ON a.item_id = i.id
             WHERE i.title LIKE '% (conflict copy, %)'",
        )
        .map_err(storage)?;
    let records: Vec<(i64, String, String, i64, String)> = stmt
        .query_map([], |row| {
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
        .map_err(storage)?;
    if records.iter().all(|(id, ..)| origins.contains_key(id)) {
        return Ok(origins);
    }
    let mut stmt = conn
        .prepare("SELECT uuid FROM item UNION SELECT uuid FROM sync_tombstone")
        .map_err(storage)?;
    let candidates: Vec<String> = stmt
        .query_map([], |row| row.get(0))
        .map_err(storage)?
        .collect::<Result<_, _>>()
        .map_err(storage)?;
    for (id, copy, clock, at, by) in records {
        if origins.contains_key(&id) || clock.is_empty() || by.is_empty() {
            continue;
        }
        let clock = clock_text(&parse_clock(&clock));
        let at = at.to_string();
        if let Some(origin) = candidates.iter().find(|origin| {
            **origin != copy && derived_uuid(&["conflict", origin, &clock, &at, &by]) == copy
        }) {
            origins.insert(id, origin.clone());
        }
    }
    Ok(origins)
}

/// Upgrade verified legacy copies before an edit can change their version metadata.
/// Existing files keep their schema and normal unlocks with no copies stay read-only.
fn preserve_legacy_conflict_origins(conn: &Connection) -> VaultResult<()> {
    for (id, origin) in conflict_origins(conn, true)? {
        let copy: String = conn
            .query_row("SELECT uuid FROM item WHERE id = ?1", [id], |row| {
                row.get(0)
            })
            .map_err(storage)?;
        record_conflict_origin(conn, id, &copy, &origin)?;
    }
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
    if let Some(id) = exists {
        record_conflict_origin(tx, id, &uuid, &loser.uuid)?;
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
    record_conflict_origin(tx, id, &uuid, &loser.uuid)?;
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
    let (remote_identity, remote_schema) = check_attached(conn, REMOTE)?;
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
        remote_schema,
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
    let mut remote = load_records(&tx, REMOTE, scope)?;
    if remote_schema == UPGRADABLE_SCHEMA {
        upgrade_records(&mut remote)?;
    }
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
    preserve_legacy_conflict_origins(&tx)?;
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
            "DELETE FROM item_event WHERE item_id = ?1
                 AND NOT (kind = 'created' AND detail LIKE 'apassy:conflict-origin:v1:%')
                 AND id NOT IN (SELECT id FROM item_event WHERE item_id = ?1
                     AND NOT (kind = 'created' AND detail LIKE 'apassy:conflict-origin:v1:%')
                     ORDER BY at DESC, id DESC LIMIT ?2)",
            (item, keep),
        )
        .map_err(storage)?;
    }
    Ok(())
}

impl Vault {
    /// Conflict copies by local item ID. The value is the original local item ID, or
    /// `None` when that item was deleted. A title never establishes the relation.
    /// Restored copies remain in this map; callers can filter by archive state.
    pub fn conflict_copies(&self) -> VaultResult<BTreeMap<u64, Option<u64>>> {
        let conn = self.conn_ref()?;
        conflict_origins(conn, false)?
            .into_iter()
            .map(|(copy, origin)| {
                let id: Option<i64> = conn
                    .query_row("SELECT id FROM item WHERE uuid = ?1", [&origin], |row| {
                        row.get(0)
                    })
                    .optional()
                    .map_err(storage)?;
                Ok((
                    super::to_public_id(copy)?,
                    id.map(super::to_public_id).transpose()?,
                ))
            })
            .collect()
    }

    /// The synced-content digest of the scope: each credential with its version, the
    /// tombstones, and the synced history. A change of local data (agents, activity) does
    /// not change it. The vault must be unlocked.
    pub fn sync_content(&self, scope: &SyncScope) -> VaultResult<[u8; 32]> {
        sync_content_digest(self.conn_ref()?, "main", scope)
    }

    /// Check a copy at `path` with the key of this vault and return its sync record. The
    /// copy does not change. A copy that does not open with the key (another vault, or a
    /// passphrase that changed on another Mac) is `WrongKeyOrCorrupt`; a copy that opens
    /// but fails a check is `Damaged`. A schema 16 copy gets the checks of schema 16; a
    /// copy of another earlier or a later schema is `UnsupportedSchema`.
    pub fn check_sync_copy(&self, path: &Path, scope: &SyncScope) -> VaultResult<SyncIdentity> {
        let conn = self.conn_ref()?;
        scope.attach(conn, path, REMOTE)?;
        let result = check_attached(conn, REMOTE).map(|(identity, _)| identity);
        detach(conn, REMOTE);
        result
    }

    /// Merge the copy at `path` into this vault, record by record (ADR 0014). The vault
    /// must be unlocked. The copy is a local file, never a file in a synced folder. It
    /// must pass the checks of [`Vault::check_sync_copy`] and have the vault ID of this
    /// vault (`OtherVault`). A schema 16 copy merges with the field names of the current
    /// schema, and the report says so ([`MergeReport::remote_outdated`]).
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

    /// [`Vault::merge_from`] for a copy under another passphrase: `passphrase` opens
    /// the copy only, and the vault keeps its own passphrase. A wrong passphrase is
    /// `WrongKeyOrCorrupt`, and nothing changes.
    pub fn merge_from_with_passphrase(
        &mut self,
        path: &Path,
        scope: &SyncScope,
        passphrase: &str,
    ) -> VaultResult<MergeReport> {
        self.require_unlocked()?;
        super::types::validate_unlock_passphrase(passphrase)?;
        let conn = self.conn_mut()?;
        scope.attach_with(conn, path, REMOTE, passphrase)?;
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

    const PASS: &str = "synthetic-conflict-pass";

    fn draft(title: &str, value: &str) -> super::super::ItemDraft {
        super::super::ItemDraft {
            title: title.to_owned(),
            kind: crate::contracts::CredentialKind::ApiKey,
            notes: String::new(),
            tags: Vec::new(),
            fields: vec![super::super::Field {
                name: "token".to_owned(),
                value: super::super::SecretValue::new(value.to_owned()),
                secret: true,
            }],
        }
    }

    fn edit(vault: &mut Vault, id: u64, title: &str, value: &str) {
        let revision = vault.details(id).unwrap().summary.revision;
        vault.update(id, revision, draft(title, value)).unwrap();
    }

    /// Two actual device versions of one credential, with a merge-created copy.
    fn conflict_world() -> (tempfile::TempDir, Vault, Vault, u64, u64) {
        let dir = tempfile::TempDir::new().unwrap();
        let mut a = Vault::create(&dir.path().join("a.db"), PASS).unwrap();
        a.unlock(PASS).unwrap();
        let origin = a.add(draft("Alpha", "SYNTH-seed")).unwrap().id;
        let seed = dir.path().join("seed.db");
        a.write_sync_copy(&seed, "Mac A").unwrap();
        let (mut b, _) = Vault::adopt_sync_copy(&seed, &dir.path().join("b.db"), PASS).unwrap();
        b.unlock(PASS).unwrap();
        edit(&mut a, origin, "Alpha", "SYNTH-a");
        edit(&mut b, origin, "Alpha", "SYNTH-b");
        let remote = dir.path().join("remote.db");
        b.write_sync_copy(&remote, "Mac B").unwrap();
        let report = a.merge_from(&remote, &SyncScope::vault()).unwrap();
        assert_eq!(report.conflicts.len(), 1);
        let copies = a.conflict_copies().unwrap();
        assert_eq!(copies.len(), 1);
        let (&copy, &related) = copies.first_key_value().unwrap();
        assert_eq!(related, Some(origin));
        assert!(a.is_archived(copy).unwrap());
        let events = a.item_events(copy, MAX_ITEM_EVENTS).unwrap();
        assert!(events.iter().any(|event| {
            event.kind == super::super::ItemEventKind::Created
                && event.detail == "Sync kept this conflict copy."
        }));
        assert!(
            events
                .iter()
                .all(|event| !event.detail.contains(CONFLICT_ORIGIN_PREFIX))
        );
        assert_ne!(
            a.reveal(copy, "token").unwrap().expose(),
            a.reveal(origin, "token").unwrap().expose()
        );
        (dir, a, b, origin, copy)
    }

    #[test]
    fn a_copy_under_another_passphrase_merges_with_it_and_the_vault_keeps_its_own() {
        const OTHER: &str = "synthetic-other-copy-pass";
        let dir = tempfile::TempDir::new().unwrap();
        let mut a = Vault::create(&dir.path().join("a.db"), PASS).unwrap();
        a.unlock(PASS).unwrap();
        a.add(draft("Alpha", "SYNTH-alpha")).unwrap();
        let seed = dir.path().join("seed.db");
        a.write_sync_copy(&seed, "Mac A").unwrap();
        let (mut b, _) = Vault::adopt_sync_copy(&seed, &dir.path().join("b.db"), PASS).unwrap();
        b.unlock(PASS).unwrap();
        b.change_passphrase(PASS, OTHER).unwrap();
        b.add(draft("Beta", "SYNTH-beta")).unwrap();
        let remote = dir.path().join("remote.db");
        b.write_sync_copy(&remote, "Mac B").unwrap();
        let scope = SyncScope::vault();
        assert_eq!(
            a.merge_from(&remote, &scope).unwrap_err().kind(),
            VaultErrorKind::WrongKeyOrCorrupt
        );
        assert_eq!(
            a.merge_from_with_passphrase(&remote, &scope, "synthetic-wrong-pass")
                .unwrap_err()
                .kind(),
            VaultErrorKind::WrongKeyOrCorrupt
        );
        let report = a
            .merge_from_with_passphrase(&remote, &scope, OTHER)
            .unwrap();
        assert_eq!(report.inserted, 1);
        let mut titles: Vec<String> = a.search("").unwrap().into_iter().map(|s| s.title).collect();
        titles.sort();
        assert_eq!(titles, ["Alpha", "Beta"]);
        a.lock().unwrap();
        assert_eq!(
            a.unlock(OTHER).unwrap_err().kind(),
            VaultErrorKind::WrongKeyOrCorrupt
        );
        a.unlock(PASS).unwrap();
    }

    #[test]
    fn conflict_metadata_ignores_user_text_and_invalid_event_proof() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut vault = Vault::create(&dir.path().join("fake.db"), PASS).unwrap();
        vault.unlock(PASS).unwrap();
        let origin = vault.add(draft("Alpha", "SYNTH-original")).unwrap().id;
        let fake = vault
            .add(draft("Alpha (conflict copy, Mac A)", "SYNTH-fake"))
            .unwrap()
            .id;
        vault.set_archived(fake, true).unwrap();
        let origin_uuid: String = vault
            .conn_ref()
            .unwrap()
            .query_row(
                "SELECT uuid FROM item WHERE id = ?1",
                [origin as i64],
                |row| row.get(0),
            )
            .unwrap();
        // Even a marker-looking detail cannot establish the relation without its
        // deterministic event UUID. Ordinary item text never reaches this channel.
        vault
            .conn_ref()
            .unwrap()
            .execute(
                "INSERT INTO item_event (item_id, at, kind, detail)
                 VALUES (?1, 1, 'created', ?2)",
                (
                    fake as i64,
                    format!("{CONFLICT_ORIGIN_PREFIX}{origin_uuid}"),
                ),
            )
            .unwrap();
        vault.lock().unwrap();
        vault.unlock(PASS).unwrap();
        assert!(vault.conflict_copies().unwrap().is_empty());
        assert_eq!(vault.reveal(fake, "token").unwrap().expose(), "SYNTH-fake");
    }

    #[test]
    fn conflict_metadata_survives_sync_reopen_rename_restore_and_origin_deletion() {
        let (dir, mut a, mut b, origin, copy) = conflict_world();
        edit(&mut a, origin, "Original renamed", "SYNTH-original-renamed");
        edit(&mut a, copy, "Saved other version", "SYNTH-copy-renamed");
        a.set_archived(copy, false).unwrap();
        assert_eq!(a.conflict_copies().unwrap().get(&copy), Some(&Some(origin)));

        let pushed = dir.path().join("renamed.db");
        a.write_sync_copy(&pushed, "Mac A").unwrap();
        b.merge_from(&pushed, &SyncScope::vault()).unwrap();
        let related = b.conflict_copies().unwrap();
        assert_eq!(related.len(), 1);
        let (&b_copy, &b_origin) = related.first_key_value().unwrap();
        assert_eq!(
            b.details(b_copy).unwrap().summary.title,
            "Saved other version"
        );
        assert_eq!(
            b.details(b_origin.unwrap()).unwrap().summary.title,
            "Original renamed"
        );
        assert!(!b.is_archived(b_copy).unwrap());
        let before = b.sync_content(&SyncScope::vault()).unwrap();
        b.lock().unwrap();
        b.unlock(PASS).unwrap();
        assert_eq!(b.conflict_copies().unwrap(), related);
        assert_eq!(b.sync_content(&SyncScope::vault()).unwrap(), before);

        let backup = dir.path().join("backup.db");
        b.backup(&backup).unwrap();
        b.unlock(PASS).unwrap();
        let mut restored = Vault::restore(&backup, &dir.path().join("restored.db"), PASS).unwrap();
        restored.unlock(PASS).unwrap();
        assert_eq!(restored.conflict_copies().unwrap(), related);

        let revision = a.details(origin).unwrap().summary.revision;
        a.delete(origin, revision).unwrap();
        assert_eq!(a.conflict_copies().unwrap().get(&copy), Some(&None));
        let deleted = dir.path().join("deleted.db");
        a.write_sync_copy(&deleted, "Mac A").unwrap();
        b.merge_from(&deleted, &SyncScope::vault()).unwrap();
        assert_eq!(b.conflict_copies().unwrap().get(&b_copy), Some(&None));
        let b_push = dir.path().join("b-converged.db");
        b.write_sync_copy(&b_push, "Mac B").unwrap();
        a.merge_from(&b_push, &SyncScope::vault()).unwrap();
        assert_eq!(
            a.sync_content(&SyncScope::vault()).unwrap(),
            b.sync_content(&SyncScope::vault()).unwrap()
        );
    }

    #[test]
    fn conflict_metadata_upgrades_unmodified_legacy_copies_before_edits() {
        let (_dir, mut a, _b, origin, copy) = conflict_world();
        a.conn_ref()
            .unwrap()
            .execute(
                "DELETE FROM item_event WHERE detail LIKE 'apassy:conflict-origin:v1:%'",
                [],
            )
            .unwrap();
        assert!(a.conflict_copies().unwrap().is_empty());
        // Unlock verifies the original copy UUID, then saves the stable marker.
        a.lock().unwrap();
        a.unlock(PASS).unwrap();
        assert_eq!(a.conflict_copies().unwrap().get(&copy), Some(&Some(origin)));
        edit(&mut a, copy, "Renamed legacy copy", "SYNTH-legacy");
        a.set_archived(copy, false).unwrap();
        a.lock().unwrap();
        a.unlock(PASS).unwrap();
        assert_eq!(a.conflict_copies().unwrap().get(&copy), Some(&Some(origin)));
    }

    #[test]
    fn conflict_metadata_survives_local_and_merge_history_pruning() {
        let (dir, mut a, mut b, origin, copy) = conflict_world();
        for index in 0..MAX_ITEM_EVENTS + 5 {
            history::record(
                a.conn_ref().unwrap(),
                copy as i64,
                super::super::ItemEventKind::Edited,
                &format!("synthetic-{index}"),
            )
            .unwrap();
        }
        assert_eq!(a.conflict_copies().unwrap().get(&copy), Some(&Some(origin)));
        let push = dir.path().join("many-events.db");
        a.write_sync_copy(&push, "Mac A").unwrap();
        b.merge_from(&push, &SyncScope::vault()).unwrap();
        let related = b.conflict_copies().unwrap();
        assert_eq!(related.len(), 1);
        let (&b_copy, &b_origin) = related.first_key_value().unwrap();
        assert!(b_origin.is_some());
        let events = b.item_events(b_copy, MAX_ITEM_EVENTS).unwrap();
        assert_eq!(events.len(), MAX_ITEM_EVENTS);
        assert!(events.iter().all(|event| !event.detail.contains("SYNTH-")));
    }

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

/// Copies of an installed app before passkeys (schema 16). The copies are real sync
/// copies of the same vault, made old the way that app wrote them.
#[cfg(test)]
mod schema16_tests {
    use std::fs;
    use std::path::Path;

    use super::super::{
        Field, ItemDraft, OPEN_EXISTING, OPEN_READONLY, SecretValue, apply_key, close_conn,
    };
    use super::*;
    use crate::contracts::CredentialKind;
    use crate::sync::{FolderSync, SyncConfig};

    const PASS: &str = "synthetic-schema16-pass";
    const OTHER: &str = "synthetic-schema16-other";
    /// The names of the fields now, and the reserved names that they had in schema 16.
    const RENAMES: [(&str, &str); 2] = [("aaa", "passkey_rp_id"), ("bbb", "passkey_key")];

    fn field(name: &str, value: &str, secret: bool) -> Field {
        Field {
            name: name.to_owned(),
            value: SecretValue::new(value.to_owned()),
            secret,
        }
    }

    fn login(password: &str) -> ItemDraft {
        ItemDraft {
            title: "Mail".to_owned(),
            kind: CredentialKind::Login,
            notes: String::new(),
            tags: Vec::new(),
            fields: vec![
                field("username", "synthetic-user", false),
                field("password", password, true),
            ],
        }
    }

    fn custom(secret: &str) -> ItemDraft {
        ItemDraft {
            title: "Legacy".to_owned(),
            kind: CredentialKind::Custom,
            notes: String::new(),
            tags: Vec::new(),
            fields: vec![
                field("aaa", "SYNTH-plain", false),
                field("bbb", secret, true),
            ],
        }
    }

    /// The name that the schema 17 migration gives a field with the reserved `name`.
    fn label(name: &str) -> String {
        format!("x_{}", to_hex(name.as_bytes()))
    }

    fn sha(path: &Path) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(digest::digest(&digest::SHA256, &fs::read(path).unwrap()).as_ref());
        out
    }

    /// Run `sql` on the closed file at `path` with the test key. `digest` stores a new
    /// content digest, as a push does.
    fn raw(path: &Path, sql: &str, digest: bool) {
        let conn = Connection::open_with_flags(path, OPEN_EXISTING).unwrap();
        apply_key(&conn, PASS).unwrap();
        conn.execute_batch(sql).unwrap();
        if digest {
            let stored = content_digest(&conn, "main").unwrap();
            conn.execute(
                "UPDATE sync_meta SET content_digest = ?1 WHERE id = 1",
                [stored.as_slice()],
            )
            .unwrap();
        }
        close_conn(conn).unwrap();
    }

    /// The version in the header and in `vault_meta`.
    fn versions(path: &Path) -> (i64, i64) {
        let conn = Connection::open_with_flags(path, OPEN_READONLY).unwrap();
        apply_key(&conn, PASS).unwrap();
        let header = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        let meta = conn
            .query_row("SELECT schema_version FROM vault_meta", [], |row| {
                row.get(0)
            })
            .unwrap();
        close_conn(conn).unwrap();
        (header, meta)
    }

    /// Make the closed file at `path` a file of schema 16: the fields of [`RENAMES`] and
    /// their variable get the reserved names that the owner gave them then, and the
    /// version is 16. `applying` keeps the versions of the records: this is the old
    /// state, not an edit. A sync copy (`copy`) gets the digest of the push of that app.
    fn make_schema16(path: &Path, copy: bool) {
        let mut sql = String::from(
            "INSERT OR IGNORE INTO sync_device (id, device_id, device_name)
                 VALUES (1, 'fixture', '');
             UPDATE sync_device SET applying = 1;",
        );
        for (now, old) in RENAMES {
            sql.push_str(&format!(
                "UPDATE item_field SET name = '{old}' WHERE name = '{now}';
                 UPDATE env_binding SET field = '{old}' WHERE field = '{now}';"
            ));
        }
        sql.push_str(if copy {
            "DELETE FROM sync_device;"
        } else {
            "UPDATE sync_device SET applying = 0;"
        });
        sql.push_str(
            "UPDATE vault_meta SET schema_version = 16 WHERE id = 1;
             PRAGMA user_version = 16;",
        );
        raw(path, &sql, copy);
    }

    fn adopt(seed: &Path, path: &Path) -> Vault {
        let (mut vault, _) = Vault::adopt_sync_copy(seed, path, PASS).unwrap();
        vault.unlock(PASS).unwrap();
        vault
    }

    /// Lock, make the vault file schema 16, and unlock: the migration of an update.
    fn update_app(vault: &mut Vault) {
        vault.lock().unwrap();
        make_schema16(vault.path(), false);
        vault.unlock(PASS).unwrap();
    }

    fn id_of(vault: &Vault, title: &str) -> u64 {
        let found = vault.search("").unwrap();
        assert_eq!(found.iter().filter(|item| item.title == title).count(), 1);
        found.iter().find(|item| item.title == title).unwrap().id
    }

    fn edit(vault: &mut Vault, id: u64, draft: ItemDraft) {
        let revision = vault.details(id).unwrap().summary.revision;
        vault.update(id, revision, draft).unwrap();
    }

    /// The fields of the migrated "Legacy" item: names, secret flags, values, variable.
    fn assert_legacy(vault: &Vault, secret: &str) {
        let id = id_of(vault, "Legacy");
        let details = vault.details(id).unwrap();
        let (rp, key) = (label("passkey_rp_id"), label("passkey_key"));
        let fields: Vec<(&str, bool)> = details
            .fields
            .iter()
            .map(|field| (field.name.as_str(), field.secret))
            .collect();
        assert_eq!(fields, [(rp.as_str(), false), (key.as_str(), true)]);
        assert_eq!(vault.reveal(id, &rp).unwrap().expose(), "SYNTH-plain");
        assert_eq!(vault.reveal(id, &key).unwrap().expose(), secret);
        let binding = vault.env_binding(id).unwrap().unwrap();
        assert_eq!(
            (binding.env_name.as_str(), binding.field.as_str()),
            ("LEGACY_TOKEN", key.as_str())
        );
        assert!(vault.all_passkeys().unwrap().is_empty());
    }

    /// Mac A and Mac B updated to schema 17; an old Mac still pushes schema 16 copies.
    struct World {
        dir: tempfile::TempDir,
        a: Vault,
        b: Vault,
        old: Vault,
    }

    fn world() -> World {
        let dir = tempfile::TempDir::new().unwrap();
        let mut a = Vault::create(&dir.path().join("a.db"), PASS).unwrap();
        a.unlock(PASS).unwrap();
        a.add(login("SYNTH-password")).unwrap();
        let legacy = a.add(custom("SYNTH-secret")).unwrap().id;
        a.set_env_binding(legacy, "LEGACY_TOKEN", "bbb").unwrap();
        let seed = dir.path().join("seed.db");
        a.write_sync_copy(&seed, "Mac A").unwrap();
        let b = adopt(&seed, &dir.path().join("b.db"));
        let old = adopt(&seed, &dir.path().join("old.db"));
        let mut world = World { dir, a, b, old };
        update_app(&mut world.a);
        update_app(&mut world.b);
        assert_legacy(&world.a, "SYNTH-secret");
        assert_legacy(&world.b, "SYNTH-secret");
        world
    }

    /// A push of the old Mac: a schema 16 copy with the reserved names.
    fn old_push(world: &mut World, name: &str) -> std::path::PathBuf {
        let path = world.dir.path().join(name);
        world.old.write_sync_copy(&path, "Old Mac").unwrap();
        make_schema16(&path, true);
        assert_eq!(versions(&path), (16, 16));
        path
    }

    #[test]
    fn a_schema16_copy_merges_with_the_names_of_the_migration_and_does_not_change() {
        let mut w = world();
        let scope = SyncScope::vault();
        // The same content: nothing to take, but the copy is old.
        let same = old_push(&mut w, "same.db");
        let before = sha(&same);
        let content = w.a.sync_content(&scope).unwrap();
        let report = w.a.merge_from(&same, &scope).unwrap();
        assert!(!report.changed_local());
        assert!(report.remote_outdated());
        assert_eq!(report.remote_schema, UPGRADABLE_SCHEMA);
        assert_eq!(w.a.sync_content(&scope).unwrap(), content);
        assert_eq!(sha(&same), before);
        assert_eq!(versions(&same), (16, 16));
        assert_eq!(
            w.a.check_sync_copy(&same, &scope).unwrap().vault_id,
            w.a.sync_identity().unwrap().vault_id
        );

        // The old Mac changes the legacy secret; Mac A changes the login.
        let legacy = id_of(&w.old, "Legacy");
        edit(&mut w.old, legacy, custom("SYNTH-secret-old-mac"));
        let mail = id_of(&w.a, "Mail");
        edit(&mut w.a, mail, login("SYNTH-password-a"));
        let changed = old_push(&mut w, "changed.db");
        let before = sha(&changed);
        let report = w.a.merge_from(&changed, &scope).unwrap();
        assert_eq!((report.inserted, report.updated, report.deleted), (0, 1, 0));
        assert!(report.conflicts.is_empty());
        assert!(report.skipped_variables.is_empty());
        assert!(report.remote_outdated());
        assert_eq!(sha(&changed), before);
        assert_eq!(w.a.search("").unwrap().len(), 2);
        assert_legacy(&w.a, "SYNTH-secret-old-mac");
        let mail = id_of(&w.a, "Mail");
        assert_eq!(
            w.a.reveal(mail, "password").unwrap().expose(),
            "SYNTH-password-a"
        );
        // A second merge of the same copy changes nothing.
        let again = w.a.merge_from(&changed, &scope).unwrap();
        assert!(!again.changed_local());

        // Mac A writes the current schema; the other updated Mac takes it.
        let push = w.dir.path().join("a-push.db");
        w.a.write_sync_copy(&push, "Mac A").unwrap();
        assert_eq!(versions(&push), (SCHEMA_VERSION, SCHEMA_VERSION));
        let report = w.b.merge_from(&push, &scope).unwrap();
        assert_eq!((report.inserted, report.updated, report.deleted), (0, 2, 0));
        assert!(report.conflicts.is_empty());
        assert!(!report.remote_outdated());
        assert_legacy(&w.b, "SYNTH-secret-old-mac");
        assert_eq!(w.b.search("").unwrap().len(), 2);
        assert_eq!(
            w.a.sync_content(&scope).unwrap(),
            w.b.sync_content(&scope).unwrap()
        );

        // Mac B changes the login; the old copy comes again after it.
        let mail = id_of(&w.b, "Mail");
        edit(&mut w.b, mail, login("SYNTH-password-b"));
        let push = w.dir.path().join("b-push.db");
        w.b.write_sync_copy(&push, "Mac B").unwrap();
        let report = w.a.merge_from(&push, &scope).unwrap();
        assert_eq!((report.inserted, report.updated), (0, 1));
        assert!(report.conflicts.is_empty());
        let report = w.b.merge_from(&changed, &scope).unwrap();
        assert!(!report.changed_local());
        for vault in [&w.a, &w.b] {
            assert_eq!(vault.search("").unwrap().len(), 2);
            assert!(vault.conflict_copies().unwrap().is_empty());
            let mail = id_of(vault, "Mail");
            assert_eq!(
                vault.reveal(mail, "password").unwrap().expose(),
                "SYNTH-password-b"
            );
            assert_legacy(vault, "SYNTH-secret-old-mac");
        }
    }

    #[test]
    fn schema16_copies_keep_every_check_and_other_schemas_fail() {
        let mut w = world();
        let scope = SyncScope::vault();
        let content = w.a.sync_content(&scope).unwrap();
        let refuse = |a: &mut Vault, path: &Path, kind: VaultErrorKind| {
            let before = sha(path);
            assert_eq!(a.merge_from(path, &scope).unwrap_err().kind(), kind);
            assert_eq!(a.check_sync_copy(path, &scope).unwrap_err().kind(), kind);
            assert_eq!(sha(path), before);
        };

        // A changed row without the digest of a push.
        let mixed = old_push(&mut w, "mixed.db");
        raw(
            &mixed,
            "UPDATE item SET title = 'Changed' WHERE title = 'Mail';",
            false,
        );
        refuse(&mut w.a, &mixed, VaultErrorKind::Damaged);

        // A copy of schema 17 with the header of schema 16.
        let header = w.dir.path().join("header.db");
        w.old.write_sync_copy(&header, "Old Mac").unwrap();
        raw(&header, "PRAGMA user_version = 16;", false);
        refuse(&mut w.a, &header, VaultErrorKind::UnsupportedSchema);
        // ... and in `vault_meta` too, without a new digest.
        raw(&header, "UPDATE vault_meta SET schema_version = 16;", false);
        refuse(&mut w.a, &header, VaultErrorKind::Damaged);

        // A later and an older schema, each with a valid digest.
        for version in [SCHEMA_VERSION + 1, UPGRADABLE_SCHEMA - 1] {
            let path = w.dir.path().join(format!("v{version}.db"));
            w.old.write_sync_copy(&path, "Old Mac").unwrap();
            raw(
                &path,
                &format!(
                    "UPDATE vault_meta SET schema_version = {version};
                     PRAGMA user_version = {version};"
                ),
                true,
            );
            refuse(&mut w.a, &path, VaultErrorKind::UnsupportedSchema);
        }

        // Another vault with the same passphrase, and a copy of this vault under another
        // key.
        let other = w.dir.path().join("other.db");
        let mut foreign = Vault::create(&other, PASS).unwrap();
        foreign.unlock(PASS).unwrap();
        foreign.add(custom("SYNTH-foreign")).unwrap();
        let foreign_copy = w.dir.path().join("foreign.db");
        foreign.write_sync_copy(&foreign_copy, "Foreign").unwrap();
        make_schema16(&foreign_copy, true);
        // The key of the vault does not open it (another salt). The passphrase does,
        // and the vault ID refuses it.
        refuse(&mut w.a, &foreign_copy, VaultErrorKind::WrongKeyOrCorrupt);
        let before = sha(&foreign_copy);
        assert_eq!(
            w.a.merge_from_with_passphrase(&foreign_copy, &scope, PASS)
                .unwrap_err()
                .kind(),
            VaultErrorKind::OtherVault
        );
        assert_eq!(sha(&foreign_copy), before);
        let rekeyed = old_push(&mut w, "rekeyed.db");
        raw(&rekeyed, &format!("PRAGMA rekey = '{OTHER}';"), false);
        refuse(&mut w.a, &rekeyed, VaultErrorKind::WrongKeyOrCorrupt);

        assert_eq!(w.a.sync_content(&scope).unwrap(), content);
        assert_legacy(&w.a, "SYNTH-secret");
    }

    /// The real folder sync: enable links to a schema 16 file and writes schema 17, also
    /// with the same content; a later old push merges once and is replaced once.
    #[test]
    fn folder_sync_links_a_schema16_file_and_replaces_it_with_the_current_schema() {
        let mut w = world();
        let folder = w.dir.path().join("Dropbox").join("Apassy");
        fs::create_dir_all(&folder).unwrap();
        let file = folder.join("Personal.apassy");
        w.old.write_sync_copy(&file, "Old Mac").unwrap();
        make_schema16(&file, true);
        let data = w.dir.path().join("a-data");
        fs::create_dir_all(&data).unwrap();
        let sync = FolderSync::new(SyncConfig::in_data_dir(&data, w.a.path(), &folder, "vault"));
        let content = w.a.sync_content(&SyncScope::vault()).unwrap();
        let enabled = sync.enable(&mut w.a, "Personal").unwrap();
        assert!(enabled.linked);
        assert!(enabled.outcome.pushed);
        let merge = enabled.outcome.merge.unwrap();
        assert!(!merge.changed_local());
        assert!(merge.remote_outdated());
        assert_eq!(w.a.sync_content(&SyncScope::vault()).unwrap(), content);
        assert_eq!(versions(&file), (SCHEMA_VERSION, SCHEMA_VERSION));
        let again = sync.sync(&mut w.a).unwrap();
        assert!(again.merge.is_none());
        assert!(!again.pushed);

        // The old Mac pushes a change in schema 16 through the folder.
        let legacy = id_of(&w.old, "Legacy");
        edit(&mut w.old, legacy, custom("SYNTH-secret-folder"));
        let pushed = old_push(&mut w, "old-folder-push.db");
        fs::rename(&pushed, &file).unwrap();
        let outcome = sync.sync(&mut w.a).unwrap();
        let merge = outcome.merge.unwrap();
        assert_eq!((merge.inserted, merge.updated), (0, 1));
        assert!(merge.conflicts.is_empty());
        assert!(outcome.pushed);
        assert_eq!(versions(&file), (SCHEMA_VERSION, SCHEMA_VERSION));
        assert_legacy(&w.a, "SYNTH-secret-folder");
        assert_eq!(w.a.search("").unwrap().len(), 2);
        let again = sync.sync(&mut w.a).unwrap();
        assert!(again.merge.is_none());
        assert!(!again.pushed);

        // The other updated Mac reads the file of the current schema.
        let local = w.dir.path().join("b-local.db");
        fs::copy(&file, &local).unwrap();
        let report = w.b.merge_from(&local, &SyncScope::vault()).unwrap();
        assert!(report.conflicts.is_empty());
        assert!(!report.remote_outdated());
        assert_legacy(&w.b, "SYNTH-secret-folder");
        assert_eq!(
            w.a.sync_content(&SyncScope::vault()).unwrap(),
            w.b.sync_content(&SyncScope::vault()).unwrap()
        );
    }
}
