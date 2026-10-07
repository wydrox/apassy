//! The team vault: one SQLCipher file for each team (docs/SPEC.md, "Team vault"), and
//! the same code for the directory of the relay (`server::directory`).
//!
//! A file is keyed with its passphrase and the core SQLCipher 4 parameters.
//! One connection sits behind a `Mutex`. The build must have the flags of
//! `.cargo/config.toml`, or the vault refuses to open.

use std::fs::{self, OpenOptions};
use std::io::ErrorKind;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::{Mutex, MutexGuard, PoisonError};

use rusqlite::config::DbConfig;
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use zeroize::Zeroizing;

use crate::api::Policy;
use crate::error::{RelayError, RelayResult, codes};
use crate::ids::{CollectionId, ItemId, MemberId};
use crate::secret::SecretString;

/// The schema version in `PRAGMA user_version`. Version 1 was the first alpha: it kept
/// the item values in the vault. Version 2 keeps only sealed values (`uid`, `sealed`).
/// Version 3 adds devices and permits members without member tokens. Version 4 adds
/// the heads and receipts of vault sync (docs/SPEC.md section 24).
pub const SCHEMA_VERSION: i64 = 4;

const KDF_ITER: i64 = 256_000;
const PAGE_SIZE: i64 = 4096;
const HMAC: &str = "HMAC_SHA512";
const KDF: &str = "PBKDF2_HMAC_SHA512";

const SCHEMA: &str = "
CREATE TABLE team (id INTEGER PRIMARY KEY CHECK (id = 1), name TEXT NOT NULL, created_at INTEGER NOT NULL,
  member_tokens_until INTEGER DEFAULT (unixepoch() + 1209600));
CREATE TABLE member (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('owner','manager','member')),
  kind TEXT NOT NULL DEFAULT 'person' CHECK (kind IN ('person','shared')),
  token_hash BLOB UNIQUE, created_at INTEGER NOT NULL, revoked_at INTEGER);
CREATE UNIQUE INDEX member_name_live ON member(name) WHERE revoked_at IS NULL;
CREATE TABLE invite (
  id INTEGER PRIMARY KEY, code_hash BLOB NOT NULL UNIQUE,
  role TEXT NOT NULL CHECK (role IN ('owner','manager','member')),
  name TEXT, grants TEXT NOT NULL DEFAULT '[]', shared INTEGER NOT NULL DEFAULT 0,
  created_by INTEGER NOT NULL REFERENCES member(id), created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL, used_by INTEGER REFERENCES member(id), used_at INTEGER,
  revoked_at INTEGER);
CREATE TABLE collection (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, policy TEXT NOT NULL,
  created_at INTEGER NOT NULL);
CREATE TABLE item (
  id INTEGER PRIMARY KEY, collection_id INTEGER NOT NULL REFERENCES collection(id),
  name TEXT NOT NULL, env_name TEXT NOT NULL, uid TEXT NOT NULL UNIQUE, sealed BLOB NOT NULL,
  provider TEXT, hosts TEXT NOT NULL,
  environment TEXT NOT NULL, risk TEXT NOT NULL, scope TEXT NOT NULL, reversibility TEXT NOT NULL,
  created_by INTEGER NOT NULL REFERENCES member(id), created_at INTEGER NOT NULL, archived_at INTEGER);
CREATE UNIQUE INDEX item_env ON item(collection_id, env_name) WHERE archived_at IS NULL;
CREATE TABLE access_grant (
  id INTEGER PRIMARY KEY, collection_id INTEGER NOT NULL REFERENCES collection(id),
  member_id INTEGER NOT NULL REFERENCES member(id), created_by INTEGER NOT NULL REFERENCES member(id),
  created_at INTEGER NOT NULL, revoked_at INTEGER);
CREATE UNIQUE INDEX grant_live ON access_grant(collection_id, member_id) WHERE revoked_at IS NULL;
CREATE TABLE agent (
  id INTEGER PRIMARY KEY, member_id INTEGER NOT NULL REFERENCES member(id), name TEXT NOT NULL,
  token_hash BLOB NOT NULL UNIQUE, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, revoked_at INTEGER);
CREATE TABLE run (
  id INTEGER PRIMARY KEY, agent_id INTEGER NOT NULL REFERENCES agent(id), member_id INTEGER NOT NULL REFERENCES member(id),
  items TEXT NOT NULL, command TEXT NOT NULL, purpose TEXT NOT NULL, user_request TEXT, cwd TEXT,
  ttl_secs INTEGER NOT NULL, flags TEXT NOT NULL, note TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending','ready','denied','timed_out','ended')),
  decided_by TEXT, approver_id INTEGER REFERENCES member(id), code TEXT,
  created_at INTEGER NOT NULL, expires_at INTEGER, decided_at INTEGER, session_expires_at INTEGER);
CREATE TABLE audit (
  id INTEGER PRIMARY KEY, at INTEGER NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
  run_id INTEGER, detail TEXT NOT NULL);
";

const DEVICE_SCHEMA: &str = "
CREATE TABLE device (
  id INTEGER PRIMARY KEY, member_id INTEGER NOT NULL REFERENCES member(id),
  name TEXT NOT NULL, public_key BLOB NOT NULL,
  key_holder INTEGER NOT NULL DEFAULT 0 CHECK (key_holder IN (0,1)),
  created_at INTEGER NOT NULL, last_seen_at INTEGER, revoked_at INTEGER);
CREATE UNIQUE INDEX device_key_live ON device(public_key) WHERE revoked_at IS NULL;
CREATE UNIQUE INDEX device_key_holder ON device(key_holder) WHERE key_holder = 1 AND revoked_at IS NULL;
CREATE INDEX device_member ON device(member_id);
CREATE TABLE join_request (
  id INTEGER PRIMARY KEY, invite_id INTEGER NOT NULL REFERENCES invite(id),
  name TEXT NOT NULL, device_name TEXT NOT NULL, public_key BLOB NOT NULL, safety TEXT NOT NULL,
  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
  state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','confirmed','refused','expired')),
  decided_by INTEGER REFERENCES member(id), decided_at INTEGER,
  member_id INTEGER REFERENCES member(id), device_id INTEGER REFERENCES device(id));
CREATE INDEX join_request_key ON join_request(public_key);
CREATE TABLE device_link (
  id INTEGER PRIMARY KEY, member_id INTEGER NOT NULL REFERENCES member(id),
  code_hash BLOB NOT NULL UNIQUE, made_by_device INTEGER NOT NULL REFERENCES device(id),
  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
  device_name TEXT, public_key BLOB, safety TEXT, requested_at INTEGER,
  state TEXT NOT NULL DEFAULT 'open' CHECK (state IN ('open','pending','confirmed','refused','expired')),
  decided_at INTEGER, device_id INTEGER REFERENCES device(id));
CREATE INDEX device_link_key ON device_link(public_key);
ALTER TABLE agent ADD COLUMN device_id INTEGER REFERENCES device(id);
";

const SYNC_SCHEMA: &str = "
CREATE TABLE sync_head (
  version INTEGER PRIMARY KEY CHECK (version >= 1),
  vault_id TEXT NOT NULL, snapshot_sha256 BLOB NOT NULL, size INTEGER NOT NULL,
  previous_sha256 BLOB NOT NULL, head_sha256 BLOB NOT NULL,
  device_id INTEGER NOT NULL REFERENCES device(id), head_time INTEGER NOT NULL,
  head TEXT NOT NULL, signature BLOB NOT NULL, pushed_at INTEGER NOT NULL);
CREATE TABLE sync_receipt (
  device_id INTEGER PRIMARY KEY REFERENCES device(id),
  version INTEGER NOT NULL, at INTEGER NOT NULL);
";

const REBUILD_V3: &str = "
CREATE TABLE member_v3 (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('owner','manager','member')),
  kind TEXT NOT NULL DEFAULT 'person' CHECK (kind IN ('person','shared')),
  token_hash BLOB UNIQUE, created_at INTEGER NOT NULL, revoked_at INTEGER);
INSERT INTO member_v3 (id, name, role, token_hash, created_at, revoked_at)
  SELECT id, name, role, token_hash, created_at, revoked_at FROM member;
CREATE TABLE invite_v3 (
  id INTEGER PRIMARY KEY, code_hash BLOB NOT NULL UNIQUE,
  role TEXT NOT NULL CHECK (role IN ('owner','manager','member')),
  name TEXT, grants TEXT NOT NULL DEFAULT '[]', shared INTEGER NOT NULL DEFAULT 0,
  created_by INTEGER NOT NULL REFERENCES member(id), created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL, used_by INTEGER REFERENCES member(id), used_at INTEGER,
  revoked_at INTEGER);
INSERT INTO invite_v3 (id, code_hash, role, created_by, created_at, expires_at, used_by, used_at)
  SELECT id, code_hash, role, created_by, created_at, expires_at, used_by, used_at FROM invite;
DROP TABLE member;
DROP TABLE invite;
ALTER TABLE member_v3 RENAME TO member;
ALTER TABLE invite_v3 RENAME TO invite;
CREATE UNIQUE INDEX member_name_live ON member(name) WHERE revoked_at IS NULL;
ALTER TABLE team ADD COLUMN member_tokens_until INTEGER;
";

#[cfg(test)]
const SCHEMA_V2: &str = "
CREATE TABLE team (id INTEGER PRIMARY KEY CHECK (id = 1), name TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE member (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE,
  role TEXT NOT NULL CHECK (role IN ('owner','manager','member')),
  token_hash BLOB NOT NULL UNIQUE, created_at INTEGER NOT NULL, revoked_at INTEGER);
CREATE TABLE invite (
  id INTEGER PRIMARY KEY, code_hash BLOB NOT NULL UNIQUE,
  role TEXT NOT NULL CHECK (role IN ('manager','member')),
  created_by INTEGER NOT NULL REFERENCES member(id), created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL, used_by INTEGER REFERENCES member(id), used_at INTEGER);
CREATE TABLE collection (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, policy TEXT NOT NULL,
  created_at INTEGER NOT NULL);
CREATE TABLE item (
  id INTEGER PRIMARY KEY, collection_id INTEGER NOT NULL REFERENCES collection(id),
  name TEXT NOT NULL, env_name TEXT NOT NULL, uid TEXT NOT NULL UNIQUE, sealed BLOB NOT NULL,
  provider TEXT, hosts TEXT NOT NULL,
  environment TEXT NOT NULL, risk TEXT NOT NULL, scope TEXT NOT NULL, reversibility TEXT NOT NULL,
  created_by INTEGER NOT NULL REFERENCES member(id), created_at INTEGER NOT NULL, archived_at INTEGER);
CREATE UNIQUE INDEX item_env ON item(collection_id, env_name) WHERE archived_at IS NULL;
CREATE TABLE access_grant (
  id INTEGER PRIMARY KEY, collection_id INTEGER NOT NULL REFERENCES collection(id),
  member_id INTEGER NOT NULL REFERENCES member(id), created_by INTEGER NOT NULL REFERENCES member(id),
  created_at INTEGER NOT NULL, revoked_at INTEGER);
CREATE UNIQUE INDEX grant_live ON access_grant(collection_id, member_id) WHERE revoked_at IS NULL;
CREATE TABLE agent (
  id INTEGER PRIMARY KEY, member_id INTEGER NOT NULL REFERENCES member(id), name TEXT NOT NULL,
  token_hash BLOB NOT NULL UNIQUE, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, revoked_at INTEGER);
CREATE TABLE run (
  id INTEGER PRIMARY KEY, agent_id INTEGER NOT NULL REFERENCES agent(id), member_id INTEGER NOT NULL REFERENCES member(id),
  items TEXT NOT NULL, command TEXT NOT NULL, purpose TEXT NOT NULL, user_request TEXT, cwd TEXT,
  ttl_secs INTEGER NOT NULL, flags TEXT NOT NULL, note TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending','ready','denied','timed_out','ended')),
  decided_by TEXT, approver_id INTEGER REFERENCES member(id), code TEXT,
  created_at INTEGER NOT NULL, expires_at INTEGER, decided_at INTEGER, session_expires_at INTEGER);
CREATE TABLE audit (
  id INTEGER PRIMARY KEY, at INTEGER NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
  run_id INTEGER, detail TEXT NOT NULL);
PRAGMA user_version = 2;
";

/// The one storage error. No SQL text, no value.
pub fn db(_error: rusqlite::Error) -> RelayError {
    RelayError::internal("The team vault failed.")
}

/// True when a SQLite error is a violated UNIQUE constraint.
pub fn is_unique_violation(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(failure, _)
            if failure.code == rusqlite::ErrorCode::ConstraintViolation
    )
}

/// A row id or time as SQLite integer.
pub fn to_i(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// A SQLite integer as a row id or time.
pub fn to_u(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

/// The team vault.
pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    /// Creates a new encrypted file with `schema`. Refuses when the file exists. The
    /// parent directory is made with mode 0700.
    pub fn create_at(path: &Path, key: &SecretString, schema: &str) -> RelayResult<Self> {
        if let Some(parent) = path.parent() {
            prepare_dir(parent)?;
        }
        let exists = || {
            RelayError::new(
                codes::CONFLICT,
                "The vault file already exists. Refusing to create it again.",
            )
        };
        if fs::symlink_metadata(path).is_ok() {
            return Err(exists());
        }
        let created = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path);
        match created {
            Ok(file) => drop(file),
            Err(error) if error.kind() == ErrorKind::AlreadyExists => return Err(exists()),
            Err(_) => return Err(RelayError::internal("The vault file cannot be created.")),
        }
        let conn = match open_keyed(path, key) {
            Ok(conn) => conn,
            Err(error) => {
                let _ = fs::remove_file(path);
                return Err(error);
            }
        };
        if let Err(error) = conn.execute_batch(schema) {
            drop(conn);
            let _ = fs::remove_file(path);
            return Err(db(error));
        }
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Opens an existing encrypted file. A wrong key or a wrong build is refused. The
    /// caller checks the schema version.
    pub fn open_at(path: &Path, key: &SecretString) -> RelayResult<Self> {
        if let Some(parent) = path.parent() {
            prepare_dir(parent)?;
        }
        let meta = fs::symlink_metadata(path)
            .map_err(|_| RelayError::internal("The vault file does not exist."))?;
        if !meta.is_file() {
            return Err(RelayError::internal("The vault is not a regular file."));
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|_| RelayError::internal("The vault file mode cannot be set to 0600."))?;
        let conn = open_keyed(path, key)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Creates the file of one team (the team schema).
    pub fn create_team(path: &Path, key: &SecretString) -> RelayResult<Self> {
        Self::create_at(
            path,
            key,
            &format!("{SCHEMA}{DEVICE_SCHEMA}{SYNC_SCHEMA}PRAGMA user_version = 4;"),
        )
    }

    /// Opens the file of one team and checks its schema version.
    pub fn open_team(path: &Path, key: &SecretString) -> RelayResult<Self> {
        let store = Self::open_at(path, key)?;
        let version = store.user_version()?;
        if version == 1 {
            return Err(RelayError::internal(
                "This team vault is from the first alpha and holds plaintext item values. Start with a new data volume: there is no migration.",
            ));
        }
        if version == 2 {
            store.migrate_v3(path).map_err(|error| {
                RelayError::internal(format!(
                    "The team file cannot be moved to schema version 3: {} It is still version 2 and unchanged; free disk space or read the log, then start the relay again.",
                    error.message
                ))
            })?;
        } else if version != 3 && version != SCHEMA_VERSION {
            return Err(RelayError::internal(
                "The team vault has an unknown schema version.",
            ));
        }
        if store.user_version()? == 3 {
            store.migrate_v4(path).map_err(|error| {
                RelayError::internal(format!(
                    "The team file cannot be moved to schema version 4: {} It is still version 3 and unchanged; free disk space or read the log, then start the relay again.",
                    error.message
                ))
            })?;
        }
        Ok(store)
    }

    /// Keeps an encrypted version 2 backup and changes the team schema in one transaction.
    fn migrate_v3(&self, path: &Path) -> RelayResult<()> {
        let mut conn = self.lock();
        write_pre(path, ".pre-v3")?;

        // SQLite ignores this change inside a transaction. Never rename the old
        // tables: that would change the names in the existing child foreign keys.
        conn.pragma_update(None, "foreign_keys", "OFF")
            .map_err(db)?;
        let migration = (|| {
            let tx = Transaction::new(&mut conn, TransactionBehavior::Immediate).map_err(db)?;
            tx.execute_batch(REBUILD_V3).map_err(db)?;
            tx.execute_batch(DEVICE_SCHEMA).map_err(db)?;
            tx.execute(
                "UPDATE team SET member_tokens_until = ?1",
                params![to_i(crate::now_unix().saturating_add(14 * 24 * 60 * 60))],
            )
            .map_err(db)?;
            let invalid = tx
                .query_row("PRAGMA foreign_key_check", [], |_| Ok(()))
                .optional()
                .map_err(db)?
                .is_some();
            if invalid {
                return Err(RelayError::internal(
                    "The team vault has invalid foreign keys. The schema change was rolled back.",
                ));
            }
            tx.pragma_update(None, "user_version", 3).map_err(db)?;
            tx.commit().map_err(db)
        })();
        // The transaction is committed or rolled back before this pragma runs,
        // including all error paths inside the migration.
        let foreign_keys = conn.pragma_update(None, "foreign_keys", "ON").map_err(db);
        migration?;
        foreign_keys
    }

    /// Keeps an encrypted version 3 backup and adds the sync tables in one transaction.
    /// The change is additive: no table is rebuilt.
    fn migrate_v4(&self, path: &Path) -> RelayResult<()> {
        let mut conn = self.lock();
        write_pre(path, ".pre-v4")?;
        let tx = Transaction::new(&mut conn, TransactionBehavior::Immediate).map_err(db)?;
        tx.execute_batch(SYNC_SCHEMA).map_err(db)?;
        tx.pragma_update(None, "user_version", 4).map_err(db)?;
        tx.commit().map_err(db)
    }

    /// Copies the file to `dest` (mode 0600) while no other statement can run: the
    /// connection is locked, so no transaction is open and the file on disk is whole
    /// (journal mode DELETE, one process: `relay.lock`). Returns the bytes copied.
    pub fn copy_to(&self, source: &Path, dest: &Path) -> RelayResult<u64> {
        let _conn = self.lock();
        copy_private(source, dest)
    }

    /// `PRAGMA user_version` of the file.
    pub fn user_version(&self) -> RelayResult<i64> {
        self.with(|conn| {
            conn.pragma_query_value(None, "user_version", |row| row.get(0))
                .map_err(db)
        })
    }

    /// Encrypts the file again with a new key (`PRAGMA rekey`).
    pub fn rekey(&self, key: &SecretString) -> RelayResult<()> {
        self.with(|conn| {
            conn.execute_batch(&key_statement_for("rekey", key.expose()))
                .map_err(|_| RelayError::internal("The vault cannot get a new key."))
        })
    }

    fn lock(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Runs `f` with the connection.
    pub fn with<T>(&self, f: impl FnOnce(&Connection) -> RelayResult<T>) -> RelayResult<T> {
        let conn = self.lock();
        f(&conn)
    }

    /// Runs `f` in one immediate transaction. It commits when `f` returns `Ok`.
    pub fn tx<T>(&self, f: impl FnOnce(&Transaction<'_>) -> RelayResult<T>) -> RelayResult<T> {
        let mut conn = self.lock();
        let tx = Transaction::new(&mut conn, TransactionBehavior::Immediate).map_err(db)?;
        let out = f(&tx)?;
        tx.commit().map_err(db)?;
        Ok(out)
    }
}

/// Copies a file to a new file with mode 0600. Refuses to overwrite.
pub fn copy_private(source: &Path, dest: &Path) -> RelayResult<u64> {
    let mut from = fs::File::open(source)
        .map_err(|_| RelayError::internal("A file to back up cannot be read."))?;
    let mut to = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dest)
        .map_err(|_| RelayError::internal("A backup file cannot be created."))?;
    to.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| RelayError::internal("The backup file mode cannot be set to 0600."))?;
    let bytes = std::io::copy(&mut from, &mut to)
        .map_err(|_| RelayError::internal("A file cannot be copied to the backup."))?;
    to.sync_all()
        .map_err(|_| RelayError::internal("A backup file cannot be written to disk."))?;
    Ok(bytes)
}

/// Writes `<file><suffix>` (`.pre-v3`, `.pre-v4`): a copy of the file before a schema
/// change, the way back for an image that cannot read the new version. The copy goes to
/// `<suffix>.tmp`, is synced, and is renamed over `<suffix>`, so a stop at any point
/// leaves either the old backup or the new one. A backup that exists while the file is
/// still at the old version comes from a migration that did not commit: the file itself
/// is the truth, so the backup is made again from it.
fn write_pre(path: &Path, suffix: &str) -> RelayResult<()> {
    let mut backup = path.as_os_str().to_os_string();
    backup.push(suffix);
    let mut temp = backup.clone();
    temp.push(".tmp");
    let (backup, temp) = (Path::new(&backup), Path::new(&temp));
    match fs::remove_file(temp) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(_) => {
            return Err(RelayError::internal(format!(
                "An old {suffix}.tmp cannot be removed."
            )));
        }
    }
    if let Err(error) = copy_private(path, temp) {
        let _ = fs::remove_file(temp);
        return Err(error);
    }
    fs::rename(temp, backup).map_err(|_| {
        RelayError::internal(format!("The {suffix} backup cannot be moved into place."))
    })?;
    if let Some(parent) = path.parent()
        && let Ok(dir) = fs::File::open(parent)
    {
        let _ = dir.sync_all();
    }
    Ok(())
}

/// The data directory gets mode 0700.
fn prepare_dir(dir: &Path) -> RelayResult<()> {
    fs::create_dir_all(dir)
        .map_err(|_| RelayError::internal("The data directory cannot be created."))?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
        .map_err(|_| RelayError::internal("The data directory mode cannot be set to 0700."))
}

/// Opens the file, checks the build, and applies the key and the cipher parameters.
fn open_keyed(path: &Path, key: &SecretString) -> RelayResult<Connection> {
    let conn =
        Connection::open(path).map_err(|_| RelayError::internal("The vault cannot be opened."))?;
    require_build_options(&conn)?;
    let defensive = conn
        .set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
        .map_err(db)?;
    if !defensive {
        return Err(RelayError::internal(
            "SQLite defensive mode is not available.",
        ));
    }
    conn.execute_batch("PRAGMA cipher_memory_security = ON")
        .map_err(db)?;
    if pragma_i64(&conn, "cipher_memory_security")? != 1 {
        return Err(RelayError::internal("SQLCipher memory security is not on."));
    }
    conn.execute_batch(&key_statement(key.expose()))
        .map_err(db)?;
    conn.execute_batch(&format!(
        "PRAGMA cipher_page_size = {PAGE_SIZE}; PRAGMA kdf_iter = {KDF_ITER}; \
         PRAGMA cipher_hmac_algorithm = {HMAC}; PRAGMA cipher_kdf_algorithm = {KDF};"
    ))
    .map_err(db)?;
    conn.pragma_update(None, "temp_store", "MEMORY")
        .map_err(db)?;
    // The first read checks the key.
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| {
        row.get::<_, i64>(0)
    })
    .map_err(|_| {
        RelayError::internal("The vault key is wrong, or the file is not a team vault.")
    })?;
    if pragma_i64(&conn, "cipher_page_size")? != PAGE_SIZE
        || pragma_i64(&conn, "kdf_iter")? != KDF_ITER
    {
        return Err(RelayError::internal(
            "The vault has unexpected cipher parameters.",
        ));
    }
    conn.pragma_update(None, "secure_delete", "ON")
        .map_err(db)?;
    conn.pragma_update(None, "foreign_keys", "ON").map_err(db)?;
    let mode: String = conn
        .pragma_update_and_check(None, "journal_mode", "DELETE", |row| row.get(0))
        .map_err(db)?;
    if !mode.eq_ignore_ascii_case("delete") {
        return Err(RelayError::internal(
            "The vault journal mode is not DELETE.",
        ));
    }
    Ok(conn)
}

fn pragma_i64(conn: &Connection, name: &str) -> RelayResult<i64> {
    // SQLCipher answers some pragmas as text, others as integers.
    conn.pragma_query_value(None, name, |row| {
        Ok(match row.get_ref(0)? {
            ValueRef::Integer(n) => Some(n),
            ValueRef::Text(bytes) => std::str::from_utf8(bytes)
                .ok()
                .and_then(|text| text.trim().parse::<i64>().ok()),
            _ => None,
        })
    })
    .optional()
    .map_err(db)?
    .flatten()
    .ok_or_else(|| RelayError::internal("A vault setting cannot be read."))
}

/// `PRAGMA key = '<passphrase>'` in a buffer that is erased on drop.
fn key_statement(passphrase: &str) -> Zeroizing<String> {
    key_statement_for("key", passphrase)
}

/// `PRAGMA <pragma> = '<passphrase>'` in a buffer that is erased on drop.
fn key_statement_for(pragma: &str, passphrase: &str) -> Zeroizing<String> {
    let quotes = passphrase.matches('\'').count();
    let mut sql = Zeroizing::new(String::with_capacity(
        "PRAGMA  = ''".len() + pragma.len() + passphrase.len() + quotes + 1,
    ));
    sql.push_str("PRAGMA ");
    sql.push_str(pragma);
    sql.push_str(" = '");
    for ch in passphrase.chars() {
        if ch == '\'' {
            sql.push('\'');
        }
        sql.push(ch);
    }
    sql.push('\'');
    sql
}

/// Refuses a SQLite build without the flags of `.cargo/config.toml`.
pub fn require_build_options(conn: &Connection) -> RelayResult<()> {
    let mut options = Vec::new();
    conn.pragma_query(None, "compile_options", |row| {
        options.push(row.get::<_, String>(0)?);
        Ok(())
    })
    .map_err(db)?;
    if build_options_ok(&options) {
        Ok(())
    } else {
        Err(RelayError::internal(
            "This SQLite build lacks the required flags (see .cargo/config.toml).",
        ))
    }
}

/// True when the options have `OMIT_LOAD_EXTENSION` and `DEFAULT_LOOKASIDE=0,0`, and
/// have neither `ENABLE_LOAD_EXTENSION` nor `USE_URI`.
pub fn build_options_ok(options: &[String]) -> bool {
    let has = |name: &str| options.iter().any(|option| option == name);
    has("OMIT_LOAD_EXTENSION")
        && has("DEFAULT_LOOKASIDE=0,0")
        && !has("ENABLE_LOAD_EXTENSION")
        && !has("USE_URI")
}

/// One item with its collection. It holds the sealed value, not a readable one: the
/// key is on the owner's host.
pub struct ItemRow {
    pub id: ItemId,
    pub collection_id: CollectionId,
    pub collection: String,
    pub policy: Policy,
    pub name: String,
    pub env_name: String,
    /// 32 lowercase hex characters. The host finds its item key by it.
    pub uid: String,
    /// `nonce || ciphertext || tag`. Ciphertext only.
    pub sealed: Vec<u8>,
    pub provider: Option<String>,
    pub hosts: Vec<String>,
    pub environment: String,
    pub risk: String,
    pub scope: String,
    pub reversibility: String,
    pub created_at: u64,
    pub archived: bool,
}

const ITEM_COLUMNS: &str = "i.id, i.collection_id, c.name, c.policy, i.name, i.env_name, i.uid, i.sealed, \
     i.provider, i.hosts, i.environment, i.risk, i.scope, i.reversibility, i.created_at, i.archived_at";

fn item_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ItemRow> {
    let policy_text: String = row.get(3)?;
    let hosts_text: String = row.get(9)?;
    Ok(ItemRow {
        id: ItemId(to_u(row.get(0)?)),
        collection_id: CollectionId(to_u(row.get(1)?)),
        collection: row.get(2)?,
        policy: serde_json::from_str(&policy_text).unwrap_or_default(),
        name: row.get(4)?,
        env_name: row.get(5)?,
        uid: row.get(6)?,
        sealed: row.get(7)?,
        provider: row.get(8)?,
        hosts: serde_json::from_str(&hosts_text).unwrap_or_default(),
        environment: row.get(10)?,
        risk: row.get(11)?,
        scope: row.get(12)?,
        reversibility: row.get(13)?,
        created_at: to_u(row.get(14)?),
        archived: row.get::<_, Option<i64>>(15)?.is_some(),
    })
}

/// One item by id, live or archived.
pub fn load_item(conn: &Connection, id: ItemId) -> RelayResult<Option<ItemRow>> {
    conn.query_row(
        &format!(
            "SELECT {ITEM_COLUMNS} FROM item i JOIN collection c ON c.id = i.collection_id WHERE i.id = ?1"
        ),
        params![to_i(id.0)],
        item_from_row,
    )
    .optional()
    .map_err(db)
}

/// The live items of one collection, or of all collections, in id order.
pub fn load_live_items(
    conn: &Connection,
    collection: Option<CollectionId>,
) -> RelayResult<Vec<ItemRow>> {
    let mut statement = conn
        .prepare(&format!(
            "SELECT {ITEM_COLUMNS} FROM item i JOIN collection c ON c.id = i.collection_id \
             WHERE i.archived_at IS NULL AND (?1 IS NULL OR i.collection_id = ?1) ORDER BY i.id"
        ))
        .map_err(db)?;
    let rows = statement
        .query_map(params![collection.map(|c| to_i(c.0))], item_from_row)
        .map_err(db)?;
    rows.map(|row| row.map_err(db)).collect()
}

/// True when the member has a live grant for the collection.
pub fn has_grant(
    conn: &Connection,
    member: MemberId,
    collection: CollectionId,
) -> RelayResult<bool> {
    conn.query_row(
        "SELECT count(*) FROM access_grant WHERE member_id = ?1 AND collection_id = ?2 AND revoked_at IS NULL",
        params![to_i(member.0), to_i(collection.0)],
        |row| row.get::<_, i64>(0),
    )
    .map(|n| n > 0)
    .map_err(db)
}

/// The name of the team.
pub fn team_name(conn: &Connection) -> RelayResult<String> {
    conn.query_row("SELECT name FROM team WHERE id = 1", [], |row| row.get(0))
        .map_err(db)
}

/// The name of a member.
pub fn member_name(conn: &Connection, id: MemberId) -> RelayResult<Option<String>> {
    conn.query_row(
        "SELECT name FROM member WHERE id = ?1",
        params![to_i(id.0)],
        |row| row.get(0),
    )
    .optional()
    .map_err(db)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v2_vault(path: &Path, key: &SecretString) -> Store {
        let store = Store::create_at(path, key, SCHEMA_V2).unwrap();
        store
            .with(|conn| {
                conn.execute_batch(
                    "INSERT INTO team VALUES (1, 'Old Team', 100);
                 INSERT INTO member VALUES (7, 'Owner', 'owner', X'0102', 100, NULL);
                 INSERT INTO member VALUES (19, 'Retired', 'member', X'0304', 101, 105);
                 INSERT INTO invite VALUES (23, X'0506', 'member', 7, 102, 1000, 19, 104);
                 INSERT INTO collection VALUES (31, 'Production', '{}', 100);
                 INSERT INTO item VALUES (41, 31, 'Key', 'KEY', 'uid', X'0708', NULL,
                    '[]', 'production', 'low', 'read', 'yes', 7, 100, NULL);
                 INSERT INTO access_grant VALUES (47, 31, 19, 7, 100, NULL);
                 INSERT INTO agent VALUES (53, 19, 'Agent', X'090A', 100, 1000, NULL);
                 INSERT INTO run VALUES (59, 53, 19, '[]', 'true', 'test', NULL, NULL,
                    60, '{}', '', 'ended', 'owner', 7, NULL, 100, 160, 101, 160);
                 INSERT INTO audit VALUES (61, 100, 'owner', 'test', 59, '{}');",
                )
                .map_err(db)
            })
            .unwrap();
        store
    }

    #[test]
    fn v3_migration_keeps_a_working_member_token() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("team.db");
        let key = SecretString::new("member token migration passphrase".into());
        let team = crate::ids::TeamId::parse("t_abcdefghij").unwrap();
        let token = crate::secret::new_token(crate::secret::TokenKind::Member, &team).unwrap();
        let hash = crate::secret::token_hash(token.expose());
        let old = v2_vault(&path, &key);
        old.with(|conn| {
            conn.execute(
                "UPDATE member SET token_hash = ?1 WHERE id = 7",
                params![hash.0.as_slice()],
            )
            .map(|_| ())
            .map_err(db)
        })
        .unwrap();
        drop(old);
        let store = Store::open_team(&path, &key).unwrap();
        let who = store
            .with(|conn| crate::server::auth::authenticate(conn, token.expose(), crate::now_unix()))
            .unwrap();
        assert_eq!(who.member().id, MemberId(7));
        assert_eq!(who.member().name, "Owner");
        assert!(who.member().device.is_none());
    }

    #[test]
    fn v3_migration_keeps_rows_foreign_keys_and_encrypted_backup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("team.db");
        let backup = dir.path().join("team.db.pre-v3");
        let key = SecretString::new("schema migration test passphrase".into());
        drop(v2_vault(&path, &key));
        let original = fs::read(&path).unwrap();
        let before = crate::now_unix();
        let store = Store::open_team(&path, &key).unwrap();
        let after = crate::now_unix();
        assert_eq!(store.user_version().unwrap(), 4);
        assert_eq!(fs::read(&backup).unwrap(), original);
        assert_eq!(
            fs::metadata(&backup).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(
            !original
                .windows(b"Old Team".len())
                .any(|bytes| bytes == b"Old Team")
        );
        store.with(|conn| {
            assert_eq!(pragma_i64(conn, "foreign_keys")?, 1);
            let deadline: i64 = conn.query_row("SELECT member_tokens_until FROM team", [], |r| r.get(0)).unwrap();
            assert!((to_i(before + 1209600)..=to_i(after + 1209600)).contains(&deadline));
            let member: (i64, Vec<u8>, String) = conn.query_row(
                "SELECT id, token_hash, kind FROM member WHERE id = 7", [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            ).unwrap();
            assert_eq!(member, (7, vec![1, 2], "person".into()));
            let invite: (i64, i64, i64, i64, String, i64) = conn.query_row(
                "SELECT id, created_by, used_by, used_at, grants, shared FROM invite", [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
            ).unwrap();
            assert_eq!(invite, (23, 7, 19, 104, "[]".into(), 0));
            for (table, id) in [("collection", 31), ("item", 41), ("access_grant", 47), ("agent", 53), ("run", 59), ("audit", 61)] {
                let found: i64 = conn.query_row(&format!("SELECT id FROM {table}"), [], |r| r.get(0)).unwrap();
                assert_eq!(found, id);
            }
            assert!(conn.query_row("PRAGMA foreign_key_check", [], |_| Ok(())).optional().unwrap().is_none());
            let old_names: i64 = conn.query_row(
                "SELECT count(*) FROM sqlite_master WHERE sql LIKE '%member_v3%' OR sql LIKE '%invite_v3%'", [], |r| r.get(0),
            ).unwrap();
            assert_eq!(old_names, 0);
            conn.execute_batch(
                "INSERT INTO member (name, role, created_at) VALUES ('Retired', 'member', 200);
                 INSERT INTO member (name, role, created_at) VALUES ('Other', 'owner', 200);
                 INSERT INTO invite (code_hash, role, created_by, created_at, expires_at)
                    VALUES (X'FFFF', 'owner', 7, 200, 1000);
                 INSERT INTO device (member_id, name, public_key, key_holder, created_at)
                    VALUES (7, 'Host', X'04AA', 1, 200);",
            ).unwrap();
            assert!(conn.execute("INSERT INTO device (member_id, name, public_key, key_holder, created_at) VALUES (7, 'Second', X'04BB', 1, 200)", []).is_err());
            assert!(conn.execute("INSERT INTO device (member_id, name, public_key, created_at) VALUES (999, 'Bad', X'04CC', 200)", []).is_err());
            Ok(())
        }).unwrap();
        drop(store);
        assert_eq!(
            Store::open_at(&backup, &key)
                .unwrap()
                .user_version()
                .unwrap(),
            2
        );
        assert_eq!(
            Store::open_at(&dir.path().join("team.db.pre-v4"), &key)
                .unwrap()
                .user_version()
                .unwrap(),
            3
        );
        assert_eq!(
            Store::open_team(&path, &key)
                .unwrap()
                .user_version()
                .unwrap(),
            4
        );
    }

    #[test]
    fn a_stale_backup_of_a_v2_file_is_made_again_and_the_migration_goes_on() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("team.db");
        let key = SecretString::new("schema migration test passphrase".into());
        drop(v2_vault(&path, &key));
        // A migration that stopped before its commit left these behind.
        fs::write(dir.path().join("team.db.pre-v3"), b"a half copy").unwrap();
        fs::write(dir.path().join("team.db.pre-v3.tmp"), b"a half temp copy").unwrap();
        let original = fs::read(&path).unwrap();
        let store = Store::open_team(&path, &key).unwrap();
        assert_eq!(store.user_version().unwrap(), 4);
        assert_eq!(
            fs::read(dir.path().join("team.db.pre-v3")).unwrap(),
            original
        );
        assert!(!dir.path().join("team.db.pre-v3.tmp").exists());
        drop(store);
        // A version 4 file opens again and keeps its backup.
        assert_eq!(
            Store::open_team(&path, &key)
                .unwrap()
                .user_version()
                .unwrap(),
            4
        );
        assert_eq!(
            fs::read(dir.path().join("team.db.pre-v3")).unwrap(),
            original
        );
    }

    #[test]
    fn v3_migration_rolls_back_invalid_foreign_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("team.db");
        let key = SecretString::new("schema migration test passphrase".into());
        let store = v2_vault(&path, &key);
        store.with(|conn| conn.execute_batch(
            "PRAGMA foreign_keys = OFF; UPDATE agent SET member_id = 999; PRAGMA foreign_keys = ON;",
        ).map_err(db)).unwrap();
        let original = fs::read(&path).unwrap();
        // Keep the connection so the failure path can also prove that FK checks
        // are on again after the transaction rolls back.
        assert!(store.migrate_v3(&path).is_err());
        assert_eq!(store.user_version().unwrap(), 2);
        store.with(|conn| {
            assert_eq!(pragma_i64(conn, "foreign_keys")?, 1);
            let new_tables: i64 = conn.query_row("SELECT count(*) FROM sqlite_master WHERE name IN ('device','join_request','device_link','member_v3','invite_v3')", [], |r| r.get(0)).unwrap();
            assert_eq!(new_tables, 0);
            let deadline_columns: i64 = conn.query_row("SELECT count(*) FROM pragma_table_info('team') WHERE name = 'member_tokens_until'", [], |r| r.get(0)).unwrap();
            assert_eq!(deadline_columns, 0);
            Ok(())
        }).unwrap();
        assert_eq!(fs::read(&path).unwrap(), original);
        assert_eq!(
            fs::read(dir.path().join("team.db.pre-v3")).unwrap(),
            original
        );
    }

    /// A version 3 file as `create_team` made it before vault sync.
    fn v3_vault(path: &Path, key: &SecretString) {
        let store = Store::create_at(
            path,
            key,
            &format!("{SCHEMA}{DEVICE_SCHEMA}PRAGMA user_version = 3;"),
        )
        .unwrap();
        store
            .with(|conn| {
                conn.execute_batch(
                    "INSERT INTO team (id, name, created_at) VALUES (1, 'Team', 100);
                     INSERT INTO member (name, role, created_at) VALUES ('owner', 'owner', 100);
                     INSERT INTO device (member_id, name, public_key, key_holder, created_at)
                        VALUES (1, 'Mac', X'04AA', 1, 100);",
                )
                .map_err(db)
            })
            .unwrap();
    }

    #[test]
    fn v4_migration_adds_the_sync_tables_and_keeps_a_v3_backup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("team.db");
        let key = SecretString::new("schema migration test passphrase".into());
        v3_vault(&path, &key);
        let original = fs::read(&path).unwrap();
        let store = Store::open_team(&path, &key).unwrap();
        assert_eq!(store.user_version().unwrap(), 4);
        let backup = dir.path().join("team.db.pre-v4");
        assert_eq!(fs::read(&backup).unwrap(), original);
        assert_eq!(
            fs::metadata(&backup).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(!dir.path().join("team.db.pre-v4.tmp").exists());
        store
            .with(|conn| {
                conn.execute_batch(
                    "INSERT INTO sync_head VALUES (1, 'v', X'00', 1, X'00', X'01', 1, 0, 'h', X'02', 100);
                     INSERT INTO sync_receipt VALUES (1, 1, 100);",
                )
                .map_err(db)?;
                assert!(conn.execute("INSERT INTO sync_head VALUES (0, 'v', X'00', 1, X'00', X'01', 1, 0, 'h', X'02', 100)", []).is_err());
                assert!(conn.execute("INSERT INTO sync_receipt VALUES (9, 1, 100)", []).is_err());
                let name: String = conn.query_row("SELECT name FROM team", [], |r| r.get(0)).map_err(db)?;
                assert_eq!(name, "Team");
                Ok(())
            })
            .unwrap();
        drop(store);
        assert_eq!(
            Store::open_at(&backup, &key)
                .unwrap()
                .user_version()
                .unwrap(),
            3
        );
        assert_eq!(
            Store::open_team(&path, &key)
                .unwrap()
                .user_version()
                .unwrap(),
            4
        );
        assert_eq!(fs::read(&backup).unwrap(), original);
    }

    #[test]
    fn a_failed_v4_backup_leaves_version_3() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("team.db");
        let key = SecretString::new("schema migration test passphrase".into());
        v3_vault(&path, &key);
        let original = fs::read(&path).unwrap();
        // A directory where the temporary copy goes cannot be removed as a file.
        fs::create_dir(dir.path().join("team.db.pre-v4.tmp")).unwrap();
        fs::write(dir.path().join("team.db.pre-v4.tmp/x"), b"x").unwrap();
        let error = Store::open_team(&path, &key).err().unwrap();
        assert!(error.message.contains("version 4"), "{error}");
        assert!(error.message.contains("still version 3"), "{error}");
        assert_eq!(fs::read(&path).unwrap(), original);
        assert!(!dir.path().join("team.db.pre-v4").exists());
        assert_eq!(
            Store::open_at(&path, &key).unwrap().user_version().unwrap(),
            3
        );
    }

    #[test]
    fn fresh_team_uses_v4_and_has_a_member_token_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let key = SecretString::new("new schema test passphrase".into());
        let store = Store::create_team(&dir.path().join("team.db"), &key).unwrap();
        assert_eq!(store.user_version().unwrap(), 4);
        store
            .with(|conn| {
                conn.execute(
                    "INSERT INTO team (id, name, created_at) VALUES (1, 'New', 100)",
                    [],
                )
                .unwrap();
                let deadline: i64 = conn
                    .query_row("SELECT member_tokens_until FROM team", [], |r| r.get(0))
                    .unwrap();
                assert!(deadline >= to_i(crate::now_unix() + 1209600 - 1));
                Ok(())
            })
            .unwrap();
    }

    fn options(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn build_options_rule() {
        let good = options(&[
            "OMIT_LOAD_EXTENSION",
            "DEFAULT_LOOKASIDE=0,0",
            "THREADSAFE=1",
        ]);
        assert!(build_options_ok(&good));
        assert!(!build_options_ok(&options(&["OMIT_LOAD_EXTENSION"])));
        assert!(!build_options_ok(&options(&[
            "OMIT_LOAD_EXTENSION",
            "DEFAULT_LOOKASIDE=0,0",
            "USE_URI"
        ])));
        assert!(!build_options_ok(&options(&[
            "OMIT_LOAD_EXTENSION",
            "DEFAULT_LOOKASIDE=0,0",
            "ENABLE_LOAD_EXTENSION"
        ])));
    }

    #[test]
    fn key_statement_doubles_quotes() {
        assert_eq!(key_statement("a'b").as_str(), "PRAGMA key = 'a''b'");
        assert_eq!(
            key_statement_for("rekey", "c'd").as_str(),
            "PRAGMA rekey = 'c''d'"
        );
    }

    #[test]
    fn this_build_passes_the_check() {
        let conn = Connection::open_in_memory().unwrap();
        require_build_options(&conn).unwrap();
    }
}
