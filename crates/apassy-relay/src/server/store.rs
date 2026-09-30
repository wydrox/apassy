//! The team vault: one SQLCipher file (docs/SPEC.md, "Team vault").
//!
//! The file is keyed with the vault passphrase and the core SQLCipher 4 parameters.
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
use crate::config::RelayConfig;
use crate::error::{RelayError, RelayResult, codes};
use crate::ids::{CollectionId, ItemId, MemberId};
use crate::secret::SecretString;

/// The schema version in `PRAGMA user_version`. Version 1 was the first alpha: it kept
/// the item values in the vault. Version 2 keeps only sealed values (`uid`, `sealed`).
pub const SCHEMA_VERSION: i64 = 2;

const KDF_ITER: i64 = 256_000;
const PAGE_SIZE: i64 = 4096;
const HMAC: &str = "HMAC_SHA512";
const KDF: &str = "PBKDF2_HMAC_SHA512";

const SCHEMA: &str = "
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
    /// Creates a new vault file. Refuses when the file exists.
    pub fn create(config: &RelayConfig) -> RelayResult<Self> {
        let path = config.vault_path();
        prepare_dir(&config.data_dir)?;
        if fs::symlink_metadata(&path).is_ok() {
            return Err(RelayError::new(
                codes::CONFLICT,
                "The team vault already exists. Refusing to create it again.",
            ));
        }
        let created = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path);
        match created {
            Ok(file) => drop(file),
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                return Err(RelayError::new(
                    codes::CONFLICT,
                    "The team vault already exists. Refusing to create it again.",
                ));
            }
            Err(_) => return Err(RelayError::internal("The vault file cannot be created.")),
        }
        let conn = match open_keyed(&path, &config.vault_key) {
            Ok(conn) => conn,
            Err(error) => {
                let _ = fs::remove_file(&path);
                return Err(error);
            }
        };
        if let Err(error) = conn.execute_batch(SCHEMA) {
            drop(conn);
            let _ = fs::remove_file(&path);
            return Err(db(error));
        }
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Opens an existing vault. A wrong key, a wrong build, or a wrong schema is refused.
    pub fn open(config: &RelayConfig) -> RelayResult<Self> {
        let path = config.vault_path();
        prepare_dir(&config.data_dir)?;
        let meta = fs::symlink_metadata(&path).map_err(|_| {
            RelayError::internal("There is no team vault. Run `apassy-relay init` first.")
        })?;
        if !meta.is_file() {
            return Err(RelayError::internal(
                "The team vault is not a regular file.",
            ));
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .map_err(|_| RelayError::internal("The vault file mode cannot be set to 0600."))?;
        let conn = open_keyed(&path, &config.vault_key)?;
        let version: i64 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(db)?;
        if version == 1 {
            return Err(RelayError::internal(
                "This team vault is from the first alpha and holds plaintext item values. Start with a new data volume: there is no migration.",
            ));
        }
        if version != SCHEMA_VERSION {
            return Err(RelayError::internal(
                "The team vault has an unknown schema version.",
            ));
        }
        Ok(Self {
            conn: Mutex::new(conn),
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
    let quotes = passphrase.matches('\'').count();
    let mut sql = Zeroizing::new(String::with_capacity(
        "PRAGMA key = ''".len() + passphrase.len() + quotes + 1,
    ));
    sql.push_str("PRAGMA key = '");
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
    }

    #[test]
    fn this_build_passes_the_check() {
        let conn = Connection::open_in_memory().unwrap();
        require_build_options(&conn).unwrap();
    }
}
