//! The sync record and the file copies for iCloud sync (schema v13, ADR 0014).
//!
//! The live vault stays a local file. iCloud Drive holds a closed copy with the same
//! format as a backup. This module writes that copy from an unlocked vault, checks a
//! copy with the passphrase, and puts a checked copy in the place of the local file.
//! The policy (status, rollback refusal, conflicts) is in `crate::cloud`.

use std::fs::{self, File};
use std::io::{self, Read, Seek, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use ring::digest;
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior};

use super::types::{SCHEMA_VERSION, VaultErrorKind, VaultResult, err, validate_unlock_passphrase};
use super::{
    OPEN_READONLY, Vault, apply_key, canonical_new_target, close_conn, copy_into_new_file,
    exclusive_create, fresh_epoch, map_open_err, refuse_sqlite_companions,
    require_unaliased_regular, verify_cipher_defaults, verify_readable_schema,
};

/// The table added in schema version 13 (ADR 0014). One row. `vault_id` is random and
/// stays the same in every copy of the vault. `generation` grows with each push.
/// `content_digest` is the SHA-256 of the rows of every other table at the last push.
pub(super) const SCHEMA_V13_SQL: &str = "
CREATE TABLE sync_meta (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    vault_id TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK (generation >= 0),
    pushed_by TEXT NOT NULL,
    pushed_at INTEGER,
    content_digest BLOB
);
UPDATE vault_meta SET schema_version = 13 WHERE id = 1;
PRAGMA user_version = 13;
";

pub(super) const SCHEMA_V13_COLUMNS: [&str; 1] = [
    "SELECT id, vault_id, generation, pushed_by, pushed_at, content_digest FROM sync_meta LIMIT 0",
];

/// A device name in the sync record has at most this many bytes.
pub const MAX_DEVICE_NAME_BYTES: usize = 64;

/// Name suffix of the file that a pull copies next to the vault before it replaces the
/// vault. The Seatbelt profile denies it like the vault file.
pub const INCOMING_SUFFIX: &str = ".sync-incoming";

/// The sync record of a vault. It has no secret. Only an unlocked vault, or a copy
/// opened with the passphrase, shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncIdentity {
    /// A random id (UUID version 4 text). Every copy of the vault has the same id.
    pub vault_id: String,
    /// 0 before the first push. Each push makes it larger.
    pub generation: u64,
    /// The device of the last push. Empty before the first push.
    pub pushed_by: String,
    /// The time of the last push, in Unix seconds.
    pub pushed_at: Option<u64>,
}

/// A copy that `Vault::write_sync_copy` wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncCopy {
    /// The sync record in the copy, with the new generation.
    pub identity: SyncIdentity,
    /// SHA-256 of the bytes of the copy.
    pub sha256: [u8; 32],
}

/// Add schema version 13 and the one sync row with a new vault id. Create and each
/// migration call this in their transaction.
pub(super) fn add_schema_v13(tx: &rusqlite::Transaction<'_>) -> VaultResult<()> {
    tx.execute_batch(SCHEMA_V13_SQL)
        .map_err(|_| err(VaultErrorKind::Storage))?;
    tx.execute(
        "INSERT INTO sync_meta (id, vault_id, generation, pushed_by) VALUES (1, ?1, 0, '')",
        [new_vault_id()?],
    )
    .map_err(|_| err(VaultErrorKind::Storage))?;
    Ok(())
}

/// A random UUID version 4 in lowercase text.
fn new_vault_id() -> VaultResult<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| err(VaultErrorKind::Io))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = to_hex(&bytes);
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    ))
}

/// Lowercase hexadecimal text of `bytes`.
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    text
}

fn valid_vault_id(id: &str) -> bool {
    id.len() == 36
        && id.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
}

/// The device name without control characters, at most `MAX_DEVICE_NAME_BYTES` bytes.
fn clean_device_name(name: &str) -> String {
    let mut clean = String::new();
    for ch in name.trim().chars().filter(|ch| !ch.is_control()) {
        if clean.len() + ch.len_utf8() > MAX_DEVICE_NAME_BYTES {
            break;
        }
        clean.push(ch);
    }
    clean
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// The sync row and the stored content digest.
fn read_sync_row(conn: &Connection) -> VaultResult<(SyncIdentity, Option<Vec<u8>>)> {
    let row = conn
        .query_row(
            "SELECT vault_id, generation, pushed_by, pushed_at, content_digest
             FROM sync_meta WHERE id = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, Option<Vec<u8>>>(4)?,
                ))
            },
        )
        .optional()
        .map_err(|_| err(VaultErrorKind::Storage))?
        .ok_or_else(|| err(VaultErrorKind::Storage))?;
    let (vault_id, generation, pushed_by, pushed_at, stored) = row;
    if !valid_vault_id(&vault_id) {
        return Err(err(VaultErrorKind::Storage));
    }
    let generation = u64::try_from(generation).map_err(|_| err(VaultErrorKind::Storage))?;
    let pushed_at = match pushed_at {
        Some(at) => Some(u64::try_from(at).map_err(|_| err(VaultErrorKind::Storage))?),
        None => None,
    };
    Ok((
        SyncIdentity {
            vault_id,
            generation,
            pushed_by,
            pushed_at,
        },
        stored,
    ))
}

/// SHA-256 of the logical content: the schema without page numbers, and every row of
/// every table except `sync_meta`, in rowid order.
///
/// SQLCipher authenticates each page with an HMAC, but not the file as a whole. All
/// copies of a vault share the key, so someone with an older copy can put an old page
/// into a newer copy, and the HMAC of that page still matches. The digest in the sync
/// row covers the rows of all pages, so such a mixed file fails the check at a pull.
fn content_digest(conn: &Connection) -> VaultResult<[u8; 32]> {
    let storage = |_| err(VaultErrorKind::Storage);
    let mut ctx = digest::Context::new(&digest::SHA256);
    ctx.update(b"apassy-sync-content-v1\0");
    let mut tables = Vec::new();
    {
        let mut stmt = conn
            .prepare("SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY type, name")
            .map_err(storage)?;
        let mut rows = stmt.query([]).map_err(storage)?;
        while let Some(row) = rows.next().map_err(storage)? {
            ctx.update(b"S");
            for index in 0..4 {
                hash_value(&mut ctx, row.get_ref(index).map_err(storage)?);
            }
            let kind: String = row.get(0).map_err(storage)?;
            let name: String = row.get(1).map_err(storage)?;
            if kind == "table" && name != "sync_meta" {
                tables.push(name);
            }
        }
    }
    for table in tables {
        ctx.update(b"T");
        hash_value(&mut ctx, ValueRef::Text(table.as_bytes()));
        let sql = format!(
            "SELECT * FROM \"{}\" ORDER BY rowid",
            table.replace('"', "\"\"")
        );
        let mut stmt = conn.prepare(&sql).map_err(storage)?;
        let columns = stmt.column_count();
        let mut rows = stmt.query([]).map_err(storage)?;
        while let Some(row) = rows.next().map_err(storage)? {
            ctx.update(b"R");
            for index in 0..columns {
                hash_value(&mut ctx, row.get_ref(index).map_err(storage)?);
            }
        }
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(ctx.finish().as_ref());
    Ok(out)
}

fn hash_value(ctx: &mut digest::Context, value: ValueRef<'_>) {
    let len = |bytes: &[u8]| u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes();
    match value {
        ValueRef::Null => ctx.update(b"n"),
        ValueRef::Integer(n) => {
            ctx.update(b"i");
            ctx.update(&n.to_be_bytes());
        }
        ValueRef::Real(x) => {
            ctx.update(b"r");
            ctx.update(&x.to_bits().to_be_bytes());
        }
        ValueRef::Text(bytes) => {
            ctx.update(b"t");
            ctx.update(&len(bytes));
            ctx.update(bytes);
        }
        ValueRef::Blob(bytes) => {
            ctx.update(b"b");
            ctx.update(&len(bytes));
            ctx.update(bytes);
        }
    }
}

/// Copy `source` into `dest`, which is open and empty, and sync it. Return the SHA-256
/// of the bytes.
pub(crate) fn copy_hashing(source: &mut File, dest: &mut File) -> io::Result<[u8; 32]> {
    let mut ctx = digest::Context::new(&digest::SHA256);
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = source.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        ctx.update(&buffer[..read]);
        dest.write_all(&buffer[..read])?;
    }
    dest.sync_all()?;
    let mut out = [0u8; 32];
    out.copy_from_slice(ctx.finish().as_ref());
    Ok(out)
}

/// SHA-256 of the bytes that `file` gives from its start.
pub(crate) fn hash_open_file(file: &mut File) -> io::Result<[u8; 32]> {
    file.rewind()?;
    let mut ctx = digest::Context::new(&digest::SHA256);
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        ctx.update(&buffer[..read]);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(ctx.finish().as_ref());
    Ok(out)
}

/// Sync the directory entry changes in `dir` (a create or a rename).
pub(crate) fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

impl Vault {
    /// The sync record of this vault. The vault must be unlocked.
    pub fn sync_identity(&self) -> VaultResult<SyncIdentity> {
        read_sync_row(self.conn_ref()?).map(|(identity, _)| identity)
    }

    /// Write a closed copy of the vault file to `destination` for iCloud sync. The vault
    /// stays unlocked.
    ///
    /// `destination` must not exist. The copy gets mode `0600` and is synced. Before the
    /// copy, one transaction sets the next generation (above the current one and above
    /// `above`), the device name, the time, and the content digest. The copy has them.
    /// The method refuses a vault file with a `-journal`, `-wal`, or `-shm` file next to
    /// it (`InvalidInput`). After a failure the generation can be one higher than before;
    /// that is harmless, because only the order of generations counts.
    ///
    /// Why a copy while the connection is open is safe: the vault uses DELETE journal
    /// mode (set at each unlock), so every committed page is in the main file and no
    /// page lives in a WAL. Each vault method ends its transaction before it returns, and
    /// `&mut self` means that no statement of this connection runs now. An idle SQLite
    /// connection in rollback-journal mode holds no file lock and no dirty page, so the
    /// file on disk is a complete, consistent database, as after `lock()`. The `.lock`
    /// sidecar keeps other Apassy processes out of the file. A write by an external
    /// SQLite client during the copy is not supported, as for `backup()`.
    pub fn write_sync_copy(
        &mut self,
        destination: &Path,
        device: &str,
        above: u64,
    ) -> VaultResult<SyncCopy> {
        self.require_unlocked()?;
        refuse_sqlite_companions(&self.path, VaultErrorKind::InvalidInput)?;
        let mut dest_file = exclusive_create(destination)?;
        let result = self.bump_and_copy(&mut dest_file, device, above);
        if result.is_err() {
            drop(dest_file);
            let _ = fs::remove_file(destination);
        }
        result
    }

    fn bump_and_copy(
        &mut self,
        dest_file: &mut File,
        device: &str,
        above: u64,
    ) -> VaultResult<SyncCopy> {
        let device = clean_device_name(device);
        let now = i64::try_from(unix_now()).map_err(|_| err(VaultErrorKind::Storage))?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let (current, _) = read_sync_row(&tx)?;
        let next = current
            .generation
            .max(above)
            .checked_add(1)
            .and_then(|next| i64::try_from(next).ok())
            .ok_or_else(|| err(VaultErrorKind::Storage))?;
        let digest = content_digest(&tx)?;
        tx.execute(
            "UPDATE sync_meta SET generation = ?1, pushed_by = ?2, pushed_at = ?3,
                 content_digest = ?4 WHERE id = 1",
            (next, device.as_str(), now, digest.as_slice()),
        )
        .map_err(|_| err(VaultErrorKind::Storage))?;
        tx.commit().map_err(|_| err(VaultErrorKind::Storage))?;
        let (identity, _) = read_sync_row(self.conn_ref()?)?;
        // The commit deleted the rollback journal. A companion now means that another
        // program uses the file, so the file on disk is not the whole database.
        refuse_sqlite_companions(&self.path, VaultErrorKind::InvalidInput)?;
        let mut source = File::open(&self.path).map_err(|_| err(VaultErrorKind::Io))?;
        let sha256 = copy_hashing(&mut source, dest_file).map_err(|_| err(VaultErrorKind::Io))?;
        Ok(SyncCopy { identity, sha256 })
    }

    /// Check a sync copy at `path` with `passphrase` and return its sync record. The
    /// file does not change.
    ///
    /// The check is the check of a restore (cipher settings, schema, columns, integrity)
    /// plus the content digest of the last push. A wrong passphrase, a damaged file, or
    /// a file that mixes pages of different copies returns `WrongKeyOrCorrupt`. A copy
    /// from before schema 13, or from a newer Apassy, returns `UnsupportedSchema`. A
    /// schema 13 vault file that was never pushed (generation 0) has no digest; it
    /// passes, so an owner can adopt a vault file that they put in iCloud Drive by hand.
    pub fn inspect_sync_copy(path: &Path, passphrase: &str) -> VaultResult<SyncIdentity> {
        validate_unlock_passphrase(passphrase)?;
        let meta = match fs::symlink_metadata(path) {
            Ok(meta) => meta,
            Err(io_err) if io_err.kind() == io::ErrorKind::NotFound => {
                return Err(err(VaultErrorKind::NotFound));
            }
            Err(_) => return Err(err(VaultErrorKind::Io)),
        };
        require_unaliased_regular(&meta)?;
        refuse_sqlite_companions(path, VaultErrorKind::InvalidInput)?;
        let conn = Connection::open_with_flags(path, OPEN_READONLY).map_err(map_open_err)?;
        let result = inspect_open_copy(&conn, passphrase);
        match close_conn(conn) {
            Ok(()) => result,
            Err(close_err) => result.and(Err(close_err)),
        }
    }

    /// Put the file `incoming` in the place of the vault file. The vault must be locked.
    ///
    /// `incoming` must be a regular file in the directory of the vault file, so the
    /// rename is atomic. The method refuses a vault file with a `-journal`, `-wal`, or
    /// `-shm` file next to it: SQLite would apply such a file to the new database at the
    /// next unlock. The vault keeps its `.lock` sidecar. It has no connection while
    /// locked, so the next unlock opens the new file. The caller checks `incoming`
    /// first (`inspect_sync_copy`).
    pub fn replace_file_with(&mut self, incoming: &Path) -> VaultResult<()> {
        if !self.is_locked() {
            return Err(err(VaultErrorKind::InvalidInput));
        }
        refuse_sqlite_companions(&self.path, VaultErrorKind::InvalidInput)?;
        let meta = fs::symlink_metadata(incoming).map_err(|_| err(VaultErrorKind::Io))?;
        require_unaliased_regular(&meta)?;
        let dir = self
            .path
            .parent()
            .ok_or_else(|| err(VaultErrorKind::InvalidInput))?;
        let incoming_dir = incoming
            .parent()
            .and_then(|parent| fs::canonicalize(parent).ok())
            .ok_or_else(|| err(VaultErrorKind::InvalidInput))?;
        if incoming_dir != dir {
            return Err(err(VaultErrorKind::InvalidInput));
        }
        fs::rename(incoming, &self.path).map_err(|_| err(VaultErrorKind::Io))?;
        sync_dir(dir).map_err(|_| err(VaultErrorKind::Io))
    }

    /// The path next to the vault file where a pull puts the new copy before it
    /// replaces the vault file.
    pub fn incoming_path(&self) -> std::path::PathBuf {
        let mut name = self.path.as_os_str().to_os_string();
        name.push(INCOMING_SUFFIX);
        std::path::PathBuf::from(name)
    }

    /// Make a new vault file at `destination` from the sync copy at `source`, and open
    /// it locked. Used to adopt a vault from iCloud Drive on a new Mac.
    ///
    /// The checks are those of `inspect_sync_copy`. Unlike a restore, the agents, grants,
    /// and rules stay: the passphrase authenticates the copy, and the caller refuses an
    /// old copy by its generation (ADR 0014).
    pub fn adopt_sync_copy(
        source: &Path,
        destination: &Path,
        passphrase: &str,
    ) -> VaultResult<(Self, SyncIdentity)> {
        let dest = canonical_new_target(destination)?;
        let dest_lock = super::acquire_sidecar_lock(&dest)?;
        let identity = Self::inspect_sync_copy(source, passphrase)?;
        copy_into_new_file(source, &dest)?;
        let epoch = match fresh_epoch() {
            Ok(epoch) => epoch,
            Err(epoch_err) => {
                let _ = fs::remove_file(&dest);
                return Err(epoch_err);
            }
        };
        Ok((
            Self {
                path: dest,
                _lock_file: dest_lock,
                conn: None,
                epoch,
            },
            identity,
        ))
    }
}

fn inspect_open_copy(conn: &Connection, passphrase: &str) -> VaultResult<SyncIdentity> {
    apply_key(conn, passphrase)?;
    verify_cipher_defaults(conn)?;
    let version = verify_readable_schema(conn)?;
    if version < SCHEMA_VERSION {
        return Err(err(VaultErrorKind::UnsupportedSchema));
    }
    let (identity, stored) = read_sync_row(conn)?;
    match stored {
        Some(stored) if stored.as_slice() == content_digest(conn)?.as_slice() => Ok(identity),
        None if identity.generation == 0 => Ok(identity),
        _ => Err(err(VaultErrorKind::WrongKeyOrCorrupt)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_ids_are_version_4_uuids() {
        let first = new_vault_id().unwrap();
        let second = new_vault_id().unwrap();
        assert_ne!(first, second);
        for id in [&first, &second] {
            assert!(valid_vault_id(id), "{id}");
            assert_eq!(&id[14..15], "4", "{id}");
            assert!(matches!(&id[19..20], "8" | "9" | "a" | "b"), "{id}");
        }
        assert!(!valid_vault_id("not-an-id"));
        assert!(!valid_vault_id(&first.to_uppercase()));
    }

    #[test]
    fn device_names_lose_control_characters_and_stay_short() {
        assert_eq!(clean_device_name("  Mac\u{7}mini\n "), "Macmini");
        let long = "ł".repeat(100);
        let clean = clean_device_name(&long);
        assert!(clean.len() <= MAX_DEVICE_NAME_BYTES);
        assert_eq!(clean.len() % 2, 0, "whole characters only");
    }

    #[test]
    fn hex_is_lowercase_and_padded() {
        assert_eq!(to_hex(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
    }
}
