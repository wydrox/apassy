//! Experimental passphrase SQLCipher vault.
//!
//! This backend is a trusted-process internal. It is not an agent endpoint,
//! a real-secret product, or a complete P2 acceptance claim. Desktop remains
//! a synthetic demo.
//!
//! Paths are normalized to absolute canonical form before SQL open. URI
//! filename semantics are not enabled. The lifetime lock is an adjacent
//! `<canonical-db-path>.lock` sidecar. That lock is advisory only and does
//! not protect against hostile parent-directory replacement or same-user
//! arbitrary SQLite clients.

mod types;

use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use rusqlite::types::ValueRef;
use rusqlite::{Connection, ErrorCode, OpenFlags, OptionalExtension, TransactionBehavior};

use crate::contracts::CredentialKind;

pub use types::{
    Field, FieldSummary, ItemDetails, ItemDraft, ItemSummary, SecretValue, VaultError,
    VaultErrorKind, VaultResult,
};
use types::{
    MAX_SEARCH_RESULTS, SCHEMA_VERSION, err, kind_as_str, kind_from_str,
    validate_create_passphrase, validate_draft, validate_unlock_passphrase,
};

const SQLCIPHER4_KDF_ITER: i64 = 256_000;
const SQLCIPHER4_PAGE_SIZE: i64 = 4096;
const SQLCIPHER4_HMAC: &str = "HMAC_SHA512";
const SQLCIPHER4_KDF: &str = "PBKDF2_HMAC_SHA512";

const OPEN_EXISTING: OpenFlags =
    OpenFlags::SQLITE_OPEN_READ_WRITE.union(OpenFlags::SQLITE_OPEN_NO_MUTEX);

const OPEN_READONLY: OpenFlags =
    OpenFlags::SQLITE_OPEN_READ_ONLY.union(OpenFlags::SQLITE_OPEN_NO_MUTEX);

const SCHEMA_SQL: &str = "
CREATE TABLE vault_meta (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    schema_version INTEGER NOT NULL
);
CREATE TABLE item (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    kind TEXT NOT NULL,
    notes TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision >= 1)
);
CREATE TABLE item_tag (
    item_id INTEGER NOT NULL,
    position INTEGER NOT NULL,
    tag TEXT NOT NULL
);
CREATE TABLE item_field (
    item_id INTEGER NOT NULL,
    position INTEGER NOT NULL,
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    secret INTEGER NOT NULL CHECK (secret IN (0, 1))
);
CREATE INDEX item_tag_item_id ON item_tag(item_id);
CREATE INDEX item_field_item_id ON item_field(item_id);
INSERT INTO vault_meta (id, schema_version) VALUES (1, 1);
PRAGMA user_version = 1;
";

/// Encrypted local vault. Connection state is private. Debug is redacted.
pub struct Vault {
    path: PathBuf,
    /// Advisory exclusive lock on the persistent `<db>.lock` sidecar.
    /// Held for the vault lifetime, including locked state. Never used for
    /// I/O after acquire; drop releases the lock. This is not a security
    /// boundary.
    _lock_file: File,
    conn: Option<Connection>,
    epoch: [u8; 32],
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("locked", &self.is_locked())
            .finish_non_exhaustive()
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            drop(close_conn(conn));
        }
        let _ = self._lock_file.unlock();
    }
}

impl Vault {
    pub fn create(path: &Path, passphrase: &str) -> VaultResult<Self> {
        validate_create_passphrase(passphrase)?;
        let db_path = canonical_new_target(path)?;
        let lock_file = acquire_sidecar_lock(&db_path)?;
        let db_file = exclusive_create(&db_path)?;
        let db_meta = match db_file.metadata() {
            Ok(meta) => meta,
            Err(_) => {
                drop(db_file);
                let _ = fs::remove_file(&db_path);
                return Err(err(VaultErrorKind::Io));
            }
        };
        if let Err(alias_err) = require_unaliased_regular(&db_meta) {
            drop(db_file);
            let _ = fs::remove_file(&db_path);
            return Err(alias_err);
        }
        drop(db_file);
        if let Err(init_err) = initialize_new_db(&db_path, passphrase) {
            let _ = fs::remove_file(&db_path);
            return Err(init_err);
        }
        let epoch = match fresh_epoch() {
            Ok(epoch) => epoch,
            Err(epoch_err) => {
                let _ = fs::remove_file(&db_path);
                return Err(epoch_err);
            }
        };
        Ok(Self {
            path: db_path,
            _lock_file: lock_file,
            conn: None,
            epoch,
        })
    }

    pub fn open(path: &Path) -> VaultResult<Self> {
        let db_path = canonical_existing_db(path)?;
        let lock_file = acquire_sidecar_lock(&db_path)?;
        Ok(Self {
            path: db_path,
            _lock_file: lock_file,
            conn: None,
            epoch: fresh_epoch()?,
        })
    }

    pub fn unlock(&mut self, passphrase: &str) -> VaultResult<()> {
        // End the previous epoch before any validation, including a refused
        // or incorrect passphrase. No old connection survives an error.
        self.lock()?;
        validate_unlock_passphrase(passphrase)?;
        self.conn = Some(open_working_conn(&self.path, passphrase)?);
        Ok(())
    }

    pub fn lock(&mut self) -> VaultResult<()> {
        let close_result = self.conn.take().map_or(Ok(()), close_conn);
        let epoch_result = fresh_epoch();
        if let Ok(epoch) = epoch_result {
            self.epoch = epoch;
        }
        close_result?;
        epoch_result.map(|_| ())
    }

    pub fn is_locked(&self) -> bool {
        self.conn.is_none()
    }

    pub fn epoch(&self) -> [u8; 32] {
        self.epoch
    }

    pub fn add(&mut self, draft: ItemDraft) -> VaultResult<ItemSummary> {
        self.require_unlocked()?;
        let draft = validate_draft(draft)?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        tx.execute(
            "INSERT INTO item (title, kind, notes, revision) VALUES (?1, ?2, ?3, 1)",
            (
                draft.title.as_str(),
                kind_as_str(draft.kind),
                draft.notes.as_str(),
            ),
        )
        .map_err(|_| err(VaultErrorKind::Storage))?;
        let id = tx.last_insert_rowid();
        insert_tags_and_fields(&tx, id, &draft)?;
        tx.commit().map_err(|_| err(VaultErrorKind::Storage))?;
        summary_from_parts(id, draft.title, draft.kind, 1)
    }

    pub fn update(
        &mut self,
        id: u64,
        expected_revision: u64,
        draft: ItemDraft,
    ) -> VaultResult<ItemSummary> {
        self.require_unlocked()?;
        let draft = validate_draft(draft)?;
        let sql_id = to_sql_id(id)?;
        let expected = to_sql_revision(expected_revision)?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let (current_revision, current_kind) = current_revision_and_kind(&tx, sql_id)?;
        if current_kind != draft.kind {
            return Err(err(VaultErrorKind::InvalidInput));
        }
        if current_revision != expected {
            return Err(err(VaultErrorKind::Conflict));
        }
        let next = expected
            .checked_add(1)
            .ok_or_else(|| err(VaultErrorKind::Storage))?;
        tx.execute(
            "UPDATE item SET title = ?1, notes = ?2, revision = ?3 WHERE id = ?4",
            (draft.title.as_str(), draft.notes.as_str(), next, sql_id),
        )
        .map_err(|_| err(VaultErrorKind::Storage))?;
        tx.execute("DELETE FROM item_tag WHERE item_id = ?1", [sql_id])
            .map_err(|_| err(VaultErrorKind::Storage))?;
        tx.execute("DELETE FROM item_field WHERE item_id = ?1", [sql_id])
            .map_err(|_| err(VaultErrorKind::Storage))?;
        insert_tags_and_fields(&tx, sql_id, &draft)?;
        tx.commit().map_err(|_| err(VaultErrorKind::Storage))?;
        let revision = u64::try_from(next).map_err(|_| err(VaultErrorKind::Storage))?;
        Ok(ItemSummary {
            id,
            title: draft.title,
            kind: draft.kind,
            revision,
        })
    }

    pub fn delete(&mut self, id: u64, expected_revision: u64) -> VaultResult<()> {
        self.require_unlocked()?;
        let sql_id = to_sql_id(id)?;
        let expected = to_sql_revision(expected_revision)?;
        let conn = self.conn_mut()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| err(VaultErrorKind::Storage))?;
        let current = current_revision(&tx, sql_id)?;
        if current != expected {
            return Err(err(VaultErrorKind::Conflict));
        }
        tx.execute("DELETE FROM item_field WHERE item_id = ?1", [sql_id])
            .map_err(|_| err(VaultErrorKind::Storage))?;
        tx.execute("DELETE FROM item_tag WHERE item_id = ?1", [sql_id])
            .map_err(|_| err(VaultErrorKind::Storage))?;
        tx.execute("DELETE FROM item WHERE id = ?1", [sql_id])
            .map_err(|_| err(VaultErrorKind::Storage))?;
        tx.commit().map_err(|_| err(VaultErrorKind::Storage))?;
        Ok(())
    }

    pub fn search(&self, query: &str) -> VaultResult<Vec<ItemSummary>> {
        let conn = self.conn_ref()?;
        search_metadata(conn, query)
    }

    pub fn details(&self, id: u64) -> VaultResult<ItemDetails> {
        let conn = self.conn_ref()?;
        let sql_id = to_sql_id(id)?;
        let (title, kind, notes, revision) = conn
            .query_row(
                "SELECT title, kind, notes, revision FROM item WHERE id = ?1",
                [sql_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| err(VaultErrorKind::Storage))?
            .ok_or_else(|| err(VaultErrorKind::NotFound))?;
        let tags = load_tags(conn, sql_id)?;
        let fields = load_field_summaries(conn, sql_id)?;
        Ok(ItemDetails {
            summary: ItemSummary {
                id,
                title,
                kind: kind_from_str(&kind)?,
                revision: to_public_revision(revision)?,
            },
            notes,
            tags,
            fields,
        })
    }

    pub fn reveal(&self, id: u64, field_name: &str) -> VaultResult<SecretValue> {
        let conn = self.conn_ref()?;
        let sql_id = to_sql_id(id)?;
        let value: Option<String> = conn
            .query_row(
                "SELECT value FROM item_field WHERE item_id = ?1 AND name = ?2",
                (sql_id, field_name),
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| err(VaultErrorKind::Storage))?;
        match value {
            Some(value) => Ok(SecretValue::new(value)),
            None => Err(err(VaultErrorKind::NotFound)),
        }
    }

    pub fn backup(&mut self, destination: &Path) -> VaultResult<()> {
        self.require_unlocked()?;
        self.lock()?;
        // All destination failures must leave the source locked, including
        // invalid paths, existing targets, and busy destination sidecars.
        refuse_sqlite_companions(&self.path, VaultErrorKind::InvalidInput)?;
        let dest = canonical_new_target(destination)?;
        let _dest_lock = acquire_sidecar_lock(&dest)?;
        copy_into_new_file(&self.path, &dest)
    }

    pub fn restore(backup: &Path, destination: &Path, passphrase: &str) -> VaultResult<Self> {
        let dest = canonical_new_target(destination)?;
        let dest_lock = acquire_sidecar_lock(&dest)?;
        let source = canonical_existing_db(backup)?;
        let _source_lock = acquire_sidecar_lock(&source)?;
        // Restore accepts a closed single-file backup, not a live WAL or a
        // database that needs journal recovery. Never discard its companions.
        refuse_sqlite_companions(&source, VaultErrorKind::InvalidInput)?;
        validate_encrypted_source(&source, passphrase)?;
        copy_into_new_file(&source, &dest)?;
        Ok(Self {
            path: dest,
            _lock_file: dest_lock,
            conn: None,
            epoch: fresh_epoch()?,
        })
    }

    fn require_unlocked(&self) -> VaultResult<()> {
        if self.conn.is_none() {
            Err(err(VaultErrorKind::Locked))
        } else {
            Ok(())
        }
    }

    fn conn_ref(&self) -> VaultResult<&Connection> {
        self.conn
            .as_ref()
            .ok_or_else(|| err(VaultErrorKind::Locked))
    }

    fn conn_mut(&mut self) -> VaultResult<&mut Connection> {
        self.conn
            .as_mut()
            .ok_or_else(|| err(VaultErrorKind::Locked))
    }
}

fn fresh_epoch() -> VaultResult<[u8; 32]> {
    let mut epoch = [0u8; 32];
    getrandom::fill(&mut epoch).map_err(|_| err(VaultErrorKind::Io))?;
    Ok(epoch)
}

fn sidecar_path(db_path: &Path) -> PathBuf {
    let mut os = db_path.as_os_str().to_os_string();
    os.push(".lock");
    PathBuf::from(os)
}

fn acquire_exclusive(file: &File) -> VaultResult<()> {
    file.try_lock().map_err(|lock_err| {
        let io_err: io::Error = lock_err.into();
        match io_err.kind() {
            ErrorKind::WouldBlock | ErrorKind::ResourceBusy => err(VaultErrorKind::Busy),
            _ => err(VaultErrorKind::Io),
        }
    })
}

fn require_unaliased_regular(meta: &fs::Metadata) -> VaultResult<()> {
    if meta.file_type().is_symlink() || !meta.is_file() || meta.nlink() != 1 {
        Err(err(VaultErrorKind::InvalidInput))
    } else {
        Ok(())
    }
}

fn refuse_existing(path: &Path) -> VaultResult<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(err(VaultErrorKind::AlreadyExists)),
        Err(io_err) if io_err.kind() == ErrorKind::NotFound => Ok(()),
        Err(_) => Err(err(VaultErrorKind::Io)),
    }
}

fn require_database_name(path: &Path) -> VaultResult<()> {
    let name = path
        .file_name()
        .ok_or_else(|| err(VaultErrorKind::InvalidInput))?
        .as_encoded_bytes()
        .to_ascii_lowercase();
    // These names belong to a database or its lifetime lock. Reserving them
    // also prevents another backend instance from creating a vault there.
    if [b".lock".as_slice(), b"-journal", b"-wal", b"-shm"]
        .iter()
        .any(|suffix| name.ends_with(suffix))
    {
        return Err(err(VaultErrorKind::InvalidInput));
    }
    Ok(())
}

fn refuse_sqlite_companions(path: &Path, kind: VaultErrorKind) -> VaultResult<()> {
    for suffix in ["-journal", "-wal", "-shm"] {
        let mut companion = path.as_os_str().to_os_string();
        companion.push(suffix);
        match fs::symlink_metadata(Path::new(&companion)) {
            Ok(_) => return Err(err(kind)),
            Err(io_err) if io_err.kind() == ErrorKind::NotFound => {}
            Err(_) => return Err(err(VaultErrorKind::Io)),
        }
    }
    Ok(())
}

fn parent_for_create(path: &Path) -> VaultResult<&Path> {
    match path.file_name() {
        None => Err(err(VaultErrorKind::InvalidInput)),
        Some(_) => {
            let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
            Ok(parent.unwrap_or(Path::new(".")))
        }
    }
}

fn canonical_new_target(path: &Path) -> VaultResult<PathBuf> {
    refuse_existing(path)?;
    require_database_name(path)?;
    let parent = parent_for_create(path)?;
    let name = path
        .file_name()
        .ok_or_else(|| err(VaultErrorKind::InvalidInput))?;
    let parent_canon = fs::canonicalize(parent).map_err(|_| err(VaultErrorKind::Io))?;
    let dest = parent_canon.join(name);
    refuse_existing(&dest)?;
    refuse_sqlite_companions(&dest, VaultErrorKind::AlreadyExists)?;
    Ok(dest)
}

fn canonical_existing_db(path: &Path) -> VaultResult<PathBuf> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(io_err) if io_err.kind() == ErrorKind::NotFound => {
            return Err(err(VaultErrorKind::NotFound));
        }
        Err(_) => return Err(err(VaultErrorKind::Io)),
    };
    require_unaliased_regular(&meta)?;
    require_database_name(path)?;
    let canonical = fs::canonicalize(path).map_err(|_| err(VaultErrorKind::Io))?;
    let canon_meta = fs::symlink_metadata(&canonical).map_err(|_| err(VaultErrorKind::Io))?;
    require_unaliased_regular(&canon_meta)?;
    Ok(canonical)
}

fn exclusive_create(path: &Path) -> VaultResult<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|io_err| {
            if io_err.kind() == ErrorKind::AlreadyExists {
                err(VaultErrorKind::AlreadyExists)
            } else {
                err(VaultErrorKind::Io)
            }
        })
}

fn open_existing_unaliased(path: &Path) -> VaultResult<File> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(io_err) if io_err.kind() == ErrorKind::NotFound => {
            return Err(err(VaultErrorKind::NotFound));
        }
        Err(_) => return Err(err(VaultErrorKind::Io)),
    };
    require_unaliased_regular(&meta)?;
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|_| err(VaultErrorKind::Io))
}

fn open_or_create_sidecar(lock_path: &Path) -> VaultResult<File> {
    match fs::symlink_metadata(lock_path) {
        Ok(meta) => {
            require_unaliased_regular(&meta)?;
            open_existing_unaliased(lock_path)
        }
        Err(io_err) if io_err.kind() == ErrorKind::NotFound => match exclusive_create(lock_path) {
            Ok(file) => Ok(file),
            Err(create_err) if create_err.kind() == VaultErrorKind::AlreadyExists => {
                open_existing_unaliased(lock_path)
            }
            Err(create_err) => Err(create_err),
        },
        Err(_) => Err(err(VaultErrorKind::Io)),
    }
}

fn acquire_sidecar_lock(db_path: &Path) -> VaultResult<File> {
    let lock_path = sidecar_path(db_path);
    let file = open_or_create_sidecar(&lock_path)?;
    let meta = file.metadata().map_err(|_| err(VaultErrorKind::Io))?;
    require_unaliased_regular(&meta)?;
    acquire_exclusive(&file)?;
    Ok(file)
}

fn copy_into_new_file(source: &Path, dest: &Path) -> VaultResult<()> {
    let mut dest_file = exclusive_create(dest)?;
    let copy_result = File::open(source).and_then(|mut src| {
        io::copy(&mut src, &mut dest_file)?;
        dest_file.sync_all()
    });
    if copy_result.is_err() {
        drop(dest_file);
        let _ = fs::remove_file(dest);
        return Err(err(VaultErrorKind::Io));
    }
    Ok(())
}

fn close_conn(conn: Connection) -> VaultResult<()> {
    conn.close()
        .map_err(|(_conn, _sql_err)| err(VaultErrorKind::Storage))
}

fn apply_key(conn: &Connection, passphrase: &str) -> VaultResult<()> {
    validate_unlock_passphrase(passphrase)?;
    conn.pragma_update(None, "key", passphrase)
        .map_err(|_| err(VaultErrorKind::Storage))?;
    // Keep temporary SQL storage in memory before schema or integrity reads,
    // including read-only validation during restore.
    conn.pragma_update(None, "temp_store", "MEMORY")
        .map_err(|_| err(VaultErrorKind::Storage))?;
    if require_pragma_i64(conn, "temp_store")? != 2 {
        return Err(err(VaultErrorKind::Storage));
    }
    Ok(())
}

fn require_cipher_version(conn: &Connection) -> VaultResult<String> {
    let version = conn
        .pragma_query_value(None, "cipher_version", |row| {
            row.get::<_, Option<String>>(0)
        })
        .map_err(|_| err(VaultErrorKind::Storage))?;
    match version {
        Some(value) if !value.trim().is_empty() => Ok(value),
        _ => Err(err(VaultErrorKind::Storage)),
    }
}

fn pragma_i64_from_value(value: ValueRef<'_>) -> Result<i64, ()> {
    match value {
        ValueRef::Integer(n) => Ok(n),
        ValueRef::Text(bytes) => {
            let text = std::str::from_utf8(bytes).map_err(|_| ())?;
            text.parse::<i64>().map_err(|_| ())
        }
        ValueRef::Null | ValueRef::Real(_) | ValueRef::Blob(_) => Err(()),
    }
}

fn require_pragma_i64(conn: &Connection, name: &str) -> VaultResult<i64> {
    match conn.pragma_query_value(None, name, |row| {
        let raw = row.get_ref(0)?;
        Ok(pragma_i64_from_value(raw))
    }) {
        Ok(Ok(n)) => Ok(n),
        _ => Err(err(VaultErrorKind::Storage)),
    }
}

fn require_pragma_text(conn: &Connection, name: &str) -> VaultResult<String> {
    let value = conn
        .pragma_query_value(None, name, |row| row.get::<_, Option<String>>(0))
        .map_err(|_| err(VaultErrorKind::Storage))?;
    match value {
        Some(text) if !text.trim().is_empty() => Ok(text),
        _ => Err(err(VaultErrorKind::Storage)),
    }
}

fn verify_cipher_defaults(conn: &Connection) -> VaultResult<()> {
    let _version = require_cipher_version(conn)?;
    let page_size = require_pragma_i64(conn, "cipher_page_size")?;
    let kdf_iter = require_pragma_i64(conn, "kdf_iter")?;
    let hmac_algorithm = require_pragma_text(conn, "cipher_hmac_algorithm")?;
    let kdf_algorithm = require_pragma_text(conn, "cipher_kdf_algorithm")?;
    let use_hmac = require_pragma_i64(conn, "cipher_use_hmac")?;
    let plaintext_header_size = require_pragma_i64(conn, "cipher_plaintext_header_size")?;
    let provider = require_pragma_text(conn, "cipher_provider")?;
    if page_size != SQLCIPHER4_PAGE_SIZE
        || kdf_iter != SQLCIPHER4_KDF_ITER
        || hmac_algorithm != SQLCIPHER4_HMAC
        || kdf_algorithm != SQLCIPHER4_KDF
        || use_hmac != 1
        || plaintext_header_size != 0
        || !provider.eq_ignore_ascii_case("openssl")
    {
        return Err(err(VaultErrorKind::Storage));
    }
    Ok(())
}

fn apply_session_pragmas(conn: &Connection) -> VaultResult<()> {
    conn.pragma_update(None, "temp_store", "MEMORY")
        .map_err(|_| err(VaultErrorKind::Storage))?;
    // Do not depend on the linked library's default for freed database cells.
    // This does not erase earlier backups, memory, or filesystem snapshots.
    conn.pragma_update(None, "secure_delete", "ON")
        .map_err(|_| err(VaultErrorKind::Storage))?;
    if require_pragma_i64(conn, "secure_delete")? != 1 {
        return Err(err(VaultErrorKind::Storage));
    }
    let journal: String = conn
        .pragma_update_and_check(None, "journal_mode", "DELETE", |row| row.get(0))
        .map_err(|_| err(VaultErrorKind::Storage))?;
    if !journal.eq_ignore_ascii_case("delete") {
        return Err(err(VaultErrorKind::Storage));
    }
    Ok(())
}

fn read_user_version(conn: &Connection) -> VaultResult<i64> {
    match conn.pragma_query_value(None, "user_version", |row| {
        let raw = row.get_ref(0)?;
        Ok(pragma_i64_from_value(raw))
    }) {
        Ok(Ok(n)) => Ok(n),
        _ => Err(err(VaultErrorKind::WrongKeyOrCorrupt)),
    }
}

fn verify_user_version(conn: &Connection) -> VaultResult<()> {
    match read_user_version(conn)? {
        SCHEMA_VERSION => Ok(()),
        _ => Err(err(VaultErrorKind::UnsupportedSchema)),
    }
}

fn verify_cipher_integrity(conn: &Connection) -> VaultResult<()> {
    // The verified SQLCipher runtime returns no rows on success. Any row,
    // including an unexpected NULL or "ok", must fail closed. Do not expose
    // native diagnostic text through the public error.
    let mut saw_problem = false;
    conn.pragma_query(None, "cipher_integrity_check", |_| {
        saw_problem = true;
        Ok(())
    })
    .map_err(|_| err(VaultErrorKind::WrongKeyOrCorrupt))?;
    if saw_problem {
        Err(err(VaultErrorKind::WrongKeyOrCorrupt))
    } else {
        Ok(())
    }
}

fn verify_sqlite_integrity(conn: &Connection) -> VaultResult<()> {
    let mut saw_ok = false;
    let mut saw_problem = false;
    conn.pragma_query(None, "integrity_check", |row| {
        let text: String = row.get(0)?;
        if text == "ok" && !saw_ok {
            saw_ok = true;
        } else {
            saw_problem = true;
        }
        Ok(())
    })
    .map_err(|_| err(VaultErrorKind::WrongKeyOrCorrupt))?;
    if saw_ok && !saw_problem {
        Ok(())
    } else {
        Err(err(VaultErrorKind::WrongKeyOrCorrupt))
    }
}

fn verify_expected_columns(conn: &Connection) -> VaultResult<()> {
    match conn.query_row(
        "SELECT id, schema_version FROM vault_meta WHERE id = 1",
        [],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
    ) {
        Ok((1, SCHEMA_VERSION)) => {}
        Ok(_) => return Err(err(VaultErrorKind::UnsupportedSchema)),
        Err(_) => return Err(err(VaultErrorKind::UnsupportedSchema)),
    }
    for sql in [
        "SELECT id, title, kind, notes, revision FROM item LIMIT 0",
        "SELECT item_id, position, tag FROM item_tag LIMIT 0",
        "SELECT item_id, position, name, value, secret FROM item_field LIMIT 0",
    ] {
        drop(
            conn.prepare(sql)
                .map_err(|_| err(VaultErrorKind::UnsupportedSchema))?,
        );
    }
    Ok(())
}

fn verify_readable_schema(conn: &Connection) -> VaultResult<()> {
    verify_user_version(conn)?;
    verify_cipher_integrity(conn)?;
    verify_sqlite_integrity(conn)?;
    verify_expected_columns(conn)
}

fn initialize_new_db(path: &Path, passphrase: &str) -> VaultResult<()> {
    let mut conn = Connection::open_with_flags(path, OPEN_EXISTING).map_err(map_open_err)?;
    apply_key(&conn, passphrase)?;
    verify_cipher_defaults(&conn)?;
    apply_session_pragmas(&conn)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| err(VaultErrorKind::Storage))?;
    tx.execute_batch(SCHEMA_SQL)
        .map_err(|_| err(VaultErrorKind::Storage))?;
    tx.commit().map_err(|_| err(VaultErrorKind::Storage))?;
    close_conn(conn)
}

fn open_working_conn(path: &Path, passphrase: &str) -> VaultResult<Connection> {
    let conn = Connection::open_with_flags(path, OPEN_EXISTING).map_err(map_open_err)?;
    if let Err(key_err) = apply_key(&conn, passphrase) {
        drop(conn);
        return Err(key_err);
    }
    if let Err(cipher_err) = verify_cipher_defaults(&conn) {
        drop(conn);
        return Err(cipher_err);
    }
    if let Err(schema_err) = verify_readable_schema(&conn) {
        drop(conn);
        return Err(schema_err);
    }
    if let Err(pragma_err) = apply_session_pragmas(&conn) {
        drop(conn);
        return Err(pragma_err);
    }
    Ok(conn)
}

fn validate_encrypted_source(path: &Path, passphrase: &str) -> VaultResult<()> {
    validate_unlock_passphrase(passphrase)?;
    let conn = Connection::open_with_flags(path, OPEN_READONLY).map_err(map_open_err)?;
    let result = apply_key(&conn, passphrase)
        .and_then(|()| verify_cipher_defaults(&conn))
        .and_then(|()| verify_readable_schema(&conn));
    match close_conn(conn) {
        Ok(()) => result,
        Err(close_err) => {
            if result.is_err() {
                result
            } else {
                Err(close_err)
            }
        }
    }
}

fn map_open_err(sql_err: rusqlite::Error) -> VaultError {
    match sql_err {
        rusqlite::Error::SqliteFailure(failure, _) => match failure.code {
            ErrorCode::CannotOpen | ErrorCode::SystemIoFailure | ErrorCode::PermissionDenied => {
                err(VaultErrorKind::Io)
            }
            ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked => err(VaultErrorKind::Busy),
            ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase => {
                err(VaultErrorKind::WrongKeyOrCorrupt)
            }
            _ => err(VaultErrorKind::Storage),
        },
        rusqlite::Error::InvalidPath(_) => err(VaultErrorKind::Io),
        rusqlite::Error::QueryReturnedNoRows => err(VaultErrorKind::NotFound),
        _ => err(VaultErrorKind::Storage),
    }
}

fn insert_tags_and_fields(
    tx: &rusqlite::Transaction<'_>,
    item_id: i64,
    draft: &ItemDraft,
) -> VaultResult<()> {
    for (position, tag) in draft.tags.iter().enumerate() {
        let position = i64::try_from(position).map_err(|_| err(VaultErrorKind::Storage))?;
        tx.execute(
            "INSERT INTO item_tag (item_id, position, tag) VALUES (?1, ?2, ?3)",
            (item_id, position, tag.as_str()),
        )
        .map_err(|_| err(VaultErrorKind::Storage))?;
    }
    for (position, field) in draft.fields.iter().enumerate() {
        let position = i64::try_from(position).map_err(|_| err(VaultErrorKind::Storage))?;
        let secret = i64::from(field.secret);
        tx.execute(
            "INSERT INTO item_field (item_id, position, name, value, secret)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            (
                item_id,
                position,
                field.name.as_str(),
                field.value.expose(),
                secret,
            ),
        )
        .map_err(|_| err(VaultErrorKind::Storage))?;
    }
    Ok(())
}

fn current_revision(tx: &rusqlite::Transaction<'_>, id: i64) -> VaultResult<i64> {
    tx.query_row("SELECT revision FROM item WHERE id = ?1", [id], |row| {
        row.get(0)
    })
    .optional()
    .map_err(|_| err(VaultErrorKind::Storage))?
    .ok_or_else(|| err(VaultErrorKind::NotFound))
}

fn current_revision_and_kind(
    tx: &rusqlite::Transaction<'_>,
    id: i64,
) -> VaultResult<(i64, CredentialKind)> {
    let row = tx
        .query_row(
            "SELECT revision, kind FROM item WHERE id = ?1",
            [id],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(|_| err(VaultErrorKind::Storage))?
        .ok_or_else(|| err(VaultErrorKind::NotFound))?;
    Ok((row.0, kind_from_str(&row.1)?))
}

struct SearchAcc {
    id: i64,
    title: String,
    kind: String,
    notes: String,
    revision: i64,
    tags: Vec<String>,
}

/// Literal case-insensitive match using Unicode simple lowercase mapping
/// (`str::to_lowercase`). This is not locale-aware and is not full Unicode
/// case folding. Field values are never inspected.
fn metadata_matches(title: &str, notes: &str, tags: &[String], needle_lower: &str) -> bool {
    title.to_lowercase().contains(needle_lower)
        || notes.to_lowercase().contains(needle_lower)
        || tags
            .iter()
            .any(|tag| tag.to_lowercase().contains(needle_lower))
}

fn push_search_match(
    matches: &mut Vec<ItemSummary>,
    acc: SearchAcc,
    needle_lower: &str,
) -> VaultResult<()> {
    if !metadata_matches(&acc.title, &acc.notes, &acc.tags, needle_lower) {
        return Ok(());
    }
    if matches.len() >= MAX_SEARCH_RESULTS {
        return Err(err(VaultErrorKind::InvalidInput));
    }
    matches.push(ItemSummary {
        id: to_public_id(acc.id)?,
        title: acc.title,
        kind: kind_from_str(&acc.kind)?,
        revision: to_public_revision(acc.revision)?,
    });
    Ok(())
}

fn search_metadata(conn: &Connection, query: &str) -> VaultResult<Vec<ItemSummary>> {
    let mut stmt = conn
        .prepare(
            "SELECT item.id, item.title, item.kind, item.notes, item.revision, item_tag.tag
             FROM item
             LEFT JOIN item_tag ON item_tag.item_id = item.id
             ORDER BY item.id ASC, item_tag.position ASC",
        )
        .map_err(|_| err(VaultErrorKind::Storage))?;
    let mut rows = stmt.query([]).map_err(|_| err(VaultErrorKind::Storage))?;
    let needle_lower = query.to_lowercase();
    let mut matches = Vec::new();
    let mut current: Option<SearchAcc> = None;
    while let Some(row) = rows.next().map_err(|_| err(VaultErrorKind::Storage))? {
        let id: i64 = row.get(0).map_err(|_| err(VaultErrorKind::Storage))?;
        let title: String = row.get(1).map_err(|_| err(VaultErrorKind::Storage))?;
        let kind: String = row.get(2).map_err(|_| err(VaultErrorKind::Storage))?;
        let notes: String = row.get(3).map_err(|_| err(VaultErrorKind::Storage))?;
        let revision: i64 = row.get(4).map_err(|_| err(VaultErrorKind::Storage))?;
        let tag: Option<String> = row.get(5).map_err(|_| err(VaultErrorKind::Storage))?;
        let start_new = current.as_ref().is_none_or(|acc| acc.id != id);
        if start_new {
            if let Some(acc) = current.take() {
                push_search_match(&mut matches, acc, &needle_lower)?;
            }
            current = Some(SearchAcc {
                id,
                title,
                kind,
                notes,
                revision,
                tags: Vec::new(),
            });
        }
        if let (Some(tag), Some(acc)) = (tag, current.as_mut()) {
            acc.tags.push(tag);
        }
    }
    if let Some(acc) = current.take() {
        push_search_match(&mut matches, acc, &needle_lower)?;
    }
    Ok(matches)
}

fn load_tags(conn: &Connection, item_id: i64) -> VaultResult<Vec<String>> {
    let mut stmt = conn
        .prepare("SELECT tag FROM item_tag WHERE item_id = ?1 ORDER BY position ASC")
        .map_err(|_| err(VaultErrorKind::Storage))?;
    let rows = stmt
        .query_map([item_id], |row| row.get::<_, String>(0))
        .map_err(|_| err(VaultErrorKind::Storage))?;
    let mut tags = Vec::new();
    for row in rows {
        tags.push(row.map_err(|_| err(VaultErrorKind::Storage))?);
    }
    Ok(tags)
}

fn load_field_summaries(conn: &Connection, item_id: i64) -> VaultResult<Vec<FieldSummary>> {
    let mut stmt = conn
        .prepare("SELECT name, secret FROM item_field WHERE item_id = ?1 ORDER BY position ASC")
        .map_err(|_| err(VaultErrorKind::Storage))?;
    let rows = stmt
        .query_map([item_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })
        .map_err(|_| err(VaultErrorKind::Storage))?;
    let mut fields = Vec::new();
    for row in rows {
        let (name, secret) = row.map_err(|_| err(VaultErrorKind::Storage))?;
        fields.push(FieldSummary {
            name,
            secret: secret != 0,
        });
    }
    Ok(fields)
}

fn summary_from_parts(
    id: i64,
    title: String,
    kind: CredentialKind,
    revision: u64,
) -> VaultResult<ItemSummary> {
    Ok(ItemSummary {
        id: to_public_id(id)?,
        title,
        kind,
        revision,
    })
}

fn to_sql_id(id: u64) -> VaultResult<i64> {
    if id == 0 {
        return Err(err(VaultErrorKind::InvalidInput));
    }
    i64::try_from(id).map_err(|_| err(VaultErrorKind::InvalidInput))
}

fn to_sql_revision(revision: u64) -> VaultResult<i64> {
    i64::try_from(revision).map_err(|_| err(VaultErrorKind::InvalidInput))
}

fn to_public_id(id: i64) -> VaultResult<u64> {
    if id < 1 {
        return Err(err(VaultErrorKind::Storage));
    }
    u64::try_from(id).map_err(|_| err(VaultErrorKind::Storage))
}

fn to_public_revision(revision: i64) -> VaultResult<u64> {
    if revision < 1 {
        return Err(err(VaultErrorKind::Storage));
    }
    u64::try_from(revision).map_err(|_| err(VaultErrorKind::Storage))
}
