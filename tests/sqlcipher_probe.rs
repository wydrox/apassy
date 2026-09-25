//! Deterministic SQLCipher storage-direction probe.
//!
//! This target is not a production vault. It does not implement key lifecycle,
//! lock/unlock, isolation, or remote execution. It uses synthetic keys and
//! values only.
//!
//! Encryption is applied with `PRAGMA key` immediately after open and before
//! any schema read or write. The probe does not lower KDF iteration count,
//! disable HMAC, or add a plaintext header.
//!
//! Expected cipher PRAGMA names, types, and SQLCipher 4 values below are
//! inputs to the runtime check. They are not results from this worker.

use rusqlite::types::{Value, ValueRef};
use rusqlite::{Connection, Error, ErrorCode, TransactionBehavior};
use std::fs;
use std::num::IntErrorKind;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

const SYNTHETIC_KEY: &str = "probe-synthetic-key-not-a-real-secret-aaaaaaaa";
const WRONG_KEY: &str = "probe-synthetic-wrong-key-bbbbbbbbbbbbbbbbbbbb";

const CANARY_CREDENTIAL: &str = "CANARY_CREDENTIAL_ak-live-probe-9f3c2e1b7a44d8c0-not-real";
const CANARY_LABEL: &str = "CANARY_LABEL_payroll-db-staging-owner";
const CANARY_NOTE: &str = "CANARY_NOTE_vpn-gateway.internal.example.invalid";
const CANARY_NOTE_JOURNAL_UPDATE: &str =
    "CANARY_NOTE_JOURNAL_UPDATE_distinct-from-seed.example.invalid";
const CANARY_POLICY: &str = "CANARY_POLICY_allow-synthetic-reporting-agent-staging-only";
const CANARY_USERNAME: &str = "CANARY_USER_synthetic-owner@example.invalid";

const CANARIES: [&str; 6] = [
    CANARY_CREDENTIAL,
    CANARY_LABEL,
    CANARY_NOTE,
    CANARY_NOTE_JOURNAL_UPDATE,
    CANARY_POLICY,
    CANARY_USERNAME,
];

const SQLITE_MAGIC: &[u8] = b"SQLite format 3";

// Expected documented SQLCipher 4 values. Parent runtime must confirm PRAGMA
// result types and the actual values. This file does not record those results.
const SQLCIPHER4_KDF_ITER: i64 = 256_000;
const SQLCIPHER4_PAGE_SIZE: i64 = 4096;
const SQLCIPHER4_HMAC: &str = "HMAC_SHA512";
const SQLCIPHER4_KDF: &str = "PBKDF2_HMAC_SHA512";

const SCHEMA: &str = "
CREATE TABLE item (
    id TEXT PRIMARY KEY,
    revision INTEGER NOT NULL,
    use_count INTEGER NOT NULL,
    label TEXT NOT NULL,
    username TEXT NOT NULL,
    note TEXT NOT NULL,
    credential TEXT NOT NULL
);
CREATE TABLE active_policy (
    id TEXT PRIMARY KEY,
    item_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    body TEXT NOT NULL
);
CREATE TABLE request_intent (
    id TEXT PRIMARY KEY,
    item_id TEXT NOT NULL,
    item_revision INTEGER NOT NULL,
    policy_version INTEGER NOT NULL,
    digest TEXT NOT NULL UNIQUE
);
CREATE TABLE approval (
    id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL UNIQUE,
    consumed INTEGER NOT NULL CHECK (consumed IN (0, 1))
);
CREATE TABLE audit_event (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id TEXT NOT NULL,
    kind TEXT NOT NULL
);
CREATE TABLE outbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id TEXT NOT NULL,
    payload TEXT NOT NULL
);
";

#[derive(Debug)]
struct CipherDefaults {
    version: String,
    page_size: i64,
    kdf_iter: i64,
    hmac_algorithm: String,
    kdf_algorithm: String,
    use_hmac: i64,
    plaintext_header_size: i64,
    provider: String,
}

struct CoordinatedCounts {
    item_revision: i64,
    policy_version: i64,
    use_count: i64,
    intent: i64,
    consumed: i64,
    audit: i64,
    outbox: i64,
}

fn temp_store() -> TempDir {
    TempDir::new().expect("create owned temporary directory for the SQLCipher probe")
}

fn db_path(dir: &TempDir, name: &str) -> PathBuf {
    dir.path().join(name)
}

fn sidecar(db: &Path, suffix: &str) -> PathBuf {
    let mut name = db.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

fn close_db(conn: Connection) {
    conn.close()
        .map_err(|(_, err)| err)
        .expect("close SQLCipher connection");
}

fn apply_key(conn: &Connection, key: &str) -> rusqlite::Result<()> {
    conn.pragma_update(None, "key", key)
}

fn require_sqlcipher(conn: &Connection) -> String {
    let version = conn.pragma_query_value(None, "cipher_version", |row| {
        row.get::<_, Option<String>>(0)
    });
    match version {
        Ok(Some(value)) if !value.trim().is_empty() => value,
        Ok(Some(value)) => panic!(
            "PRAGMA cipher_version returned empty {value:?}; this probe requires SQLCipher, not ordinary SQLite"
        ),
        Ok(None) => panic!(
            "PRAGMA cipher_version returned NULL; this probe requires SQLCipher, not ordinary SQLite"
        ),
        Err(err) => panic!(
            "PRAGMA cipher_version failed ({err}); this probe requires SQLCipher, not ordinary SQLite"
        ),
    }
}

fn require_pragma_text(conn: &Connection, name: &str) -> String {
    let value = conn.pragma_query_value(None, name, |row| row.get::<_, Option<String>>(0));
    match value {
        Ok(Some(text)) if !text.trim().is_empty() => text,
        Ok(Some(text)) => {
            panic!(
                "PRAGMA {name} returned empty {text:?}; unsupported cipher feature or unverified result type"
            )
        }
        Ok(None) => panic!(
            "PRAGMA {name} returned NULL; unsupported cipher feature or unverified result type"
        ),
        Err(err) => panic!(
            "PRAGMA {name} failed ({err}); unsupported cipher feature or unverified result type"
        ),
    }
}

fn pragma_i64_from_value(value: ValueRef<'_>) -> Result<i64, &'static str> {
    match value {
        ValueRef::Integer(n) => Ok(n),
        ValueRef::Text(bytes) => {
            let text = std::str::from_utf8(bytes).map_err(|_| "non-utf8 text")?;
            strict_i64_text(text)
        }
        ValueRef::Null => Err("null"),
        ValueRef::Real(_) => Err("float"),
        ValueRef::Blob(_) => Err("blob"),
    }
}

fn strict_i64_text(text: &str) -> Result<i64, &'static str> {
    match text.parse::<i64>() {
        Ok(n) => Ok(n),
        Err(err) => match err.kind() {
            IntErrorKind::PosOverflow | IntErrorKind::NegOverflow => Err("out of i64 range"),
            _ => Err("invalid integer text"),
        },
    }
}

fn require_pragma_i64(conn: &Connection, name: &str) -> i64 {
    match conn.pragma_query_value(None, name, |row| {
        let raw = row.get_ref(0)?;
        Ok(pragma_i64_from_value(raw))
    }) {
        Ok(Ok(n)) => n,
        Ok(Err(err)) => {
            panic!("PRAGMA {name} result type is not a strict integer or integer-text ({err})")
        }
        Err(err) => panic!("PRAGMA {name} failed ({err}); unsupported cipher feature"),
    }
}

fn query_cipher_defaults(conn: &Connection) -> CipherDefaults {
    CipherDefaults {
        version: require_sqlcipher(conn),
        page_size: require_pragma_i64(conn, "cipher_page_size"),
        kdf_iter: require_pragma_i64(conn, "kdf_iter"),
        hmac_algorithm: require_pragma_text(conn, "cipher_hmac_algorithm"),
        kdf_algorithm: require_pragma_text(conn, "cipher_kdf_algorithm"),
        use_hmac: require_pragma_i64(conn, "cipher_use_hmac"),
        plaintext_header_size: require_pragma_i64(conn, "cipher_plaintext_header_size"),
        provider: require_pragma_text(conn, "cipher_provider"),
    }
}

fn assert_sqlcipher4_defaults(defaults: &CipherDefaults) {
    assert_eq!(
        defaults.kdf_iter, SQLCIPHER4_KDF_ITER,
        "kdf_iter must stay at the SQLCipher 4 default; this probe does not accept a weakened KDF"
    );
    assert_eq!(
        defaults.page_size, SQLCIPHER4_PAGE_SIZE,
        "cipher_page_size must stay at the SQLCipher 4 default"
    );
    assert_eq!(
        defaults.hmac_algorithm, SQLCIPHER4_HMAC,
        "cipher_hmac_algorithm must stay at the SQLCipher 4 default"
    );
    assert_eq!(
        defaults.kdf_algorithm, SQLCIPHER4_KDF,
        "cipher_kdf_algorithm must stay at the SQLCipher 4 default"
    );
    assert_eq!(
        defaults.use_hmac, 1,
        "cipher_use_hmac must stay enabled; this probe does not accept HMAC disabled"
    );
    assert_eq!(
        defaults.plaintext_header_size, 0,
        "cipher_plaintext_header_size must stay 0 so the SQLite header is not left in plaintext"
    );
    assert!(
        defaults.provider.to_ascii_lowercase().contains("openssl"),
        "cipher_provider must report OpenSSL for bundled-sqlcipher-vendored-openssl, got {}",
        defaults.provider
    );
    assert!(
        !defaults.version.trim().is_empty(),
        "cipher_version must be nonempty"
    );
}

fn open_encrypted(path: &Path, key: &str) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    apply_key(&conn, key)?;
    require_sqlcipher(&conn);
    Ok(conn)
}

fn open_encrypted_with_defaults(path: &Path, key: &str) -> rusqlite::Result<Connection> {
    let conn = open_encrypted(path, key)?;
    let defaults = query_cipher_defaults(&conn);
    assert_sqlcipher4_defaults(&defaults);
    Ok(conn)
}

fn set_journal_mode(conn: &Connection, mode: &str) -> String {
    let applied: String = conn
        .pragma_update_and_check(None, "journal_mode", mode, |row| row.get(0))
        .unwrap_or_else(|err| {
            panic!("PRAGMA journal_mode={mode} failed ({err}); unsupported cipher/journal feature");
        });
    if !applied.eq_ignore_ascii_case(mode) {
        panic!("PRAGMA journal_mode={mode} returned {applied}; unsupported journal feature");
    }
    applied
}

fn checkpoint_truncate(conn: &Connection) {
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint WAL before close");
}

fn create_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(SCHEMA)
}

fn seed_item_and_policy(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO item (id, revision, use_count, label, username, note, credential)
         VALUES ('item-1', 1, 0, ?1, ?2, ?3, ?4)",
        (
            CANARY_LABEL,
            CANARY_USERNAME,
            CANARY_NOTE,
            CANARY_CREDENTIAL,
        ),
    )?;
    conn.execute(
        "INSERT INTO active_policy (id, item_id, version, body)
         VALUES ('policy-1', 'item-1', 1, ?1)",
        [CANARY_POLICY],
    )?;
    conn.execute(
        "INSERT INTO approval (id, request_id, consumed)
         VALUES ('appr-1', 'req-1', 0)",
        [],
    )?;
    Ok(())
}

fn read_item_credential(conn: &Connection) -> rusqlite::Result<String> {
    conn.query_row(
        "SELECT credential FROM item WHERE id = 'item-1'",
        [],
        |row| row.get(0),
    )
}

fn assert_table_read_fails(result: rusqlite::Result<String>, context: &str) {
    if let Ok(value) = result {
        panic!("{context}: table read succeeded and returned {value:?}");
    }
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    assert!(!needle.is_empty(), "canary must be nonempty");
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn existing_artifacts(db: &Path) -> Vec<PathBuf> {
    let mut paths = vec![db.to_path_buf()];
    for suffix in ["-wal", "-shm", "-journal"] {
        let path = sidecar(db, suffix);
        if path.exists() {
            paths.push(path);
        }
    }
    paths
}

fn assert_encrypted_file(db: &Path) {
    let bytes = fs::read(db).expect("read database file");
    assert!(
        bytes.len() > 1024,
        "{} is too small to be an encrypted SQLCipher database",
        db.display()
    );
    assert!(
        !bytes.starts_with(SQLITE_MAGIC),
        "{} starts with the ordinary SQLite header; encryption was not applied",
        db.display()
    );
}

fn assert_artifacts_omit_canaries(db: &Path) {
    assert_encrypted_file(db);
    for path in existing_artifacts(db) {
        let bytes = fs::read(&path).unwrap_or_else(|err| {
            panic!("read artifact {} failed: {err}", path.display());
        });
        for canary in CANARIES {
            if contains_bytes(&bytes, canary.as_bytes()) {
                panic!(
                    "bounded plaintext scan found canary in {}; this is not a cryptographic proof, but the canary must not appear in the clear",
                    path.display()
                );
            }
        }
    }
}

fn require_artifact(db: &Path, suffix: &str) -> PathBuf {
    let path = sidecar(db, suffix);
    if !path.exists() {
        panic!(
            "expected {} artifact {} after the probe write",
            suffix,
            path.display()
        );
    }
    path
}

fn require_nonempty_artifact(db: &Path, suffix: &str) -> PathBuf {
    let path = require_artifact(db, suffix);
    let len = fs::metadata(&path)
        .unwrap_or_else(|err| panic!("stat artifact {} failed: {err}", path.display()))
        .len();
    if len == 0 {
        panic!(
            "expected nonempty {} artifact {}; empty journal is not a write artifact",
            suffix,
            path.display()
        );
    }
    path
}

fn write_authorization_boundary(conn: &Connection, request_id: &str) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE item SET revision = revision + 1, use_count = use_count + 1 WHERE id = 'item-1'",
        [],
    )?;
    let item_revision: i64 =
        conn.query_row("SELECT revision FROM item WHERE id = 'item-1'", [], |row| {
            row.get(0)
        })?;
    let policy_version: i64 = conn.query_row(
        "SELECT version FROM active_policy WHERE id = 'policy-1'",
        [],
        |row| row.get(0),
    )?;
    conn.execute(
        "INSERT INTO request_intent (id, item_id, item_revision, policy_version, digest)
         VALUES (?1, 'item-1', ?2, ?3, ?4)",
        (
            request_id,
            item_revision,
            policy_version,
            format!("digest-{request_id}"),
        ),
    )?;
    conn.execute(
        "UPDATE approval SET consumed = 1 WHERE request_id = ?1",
        [request_id],
    )?;
    conn.execute(
        "INSERT INTO audit_event (request_id, kind) VALUES (?1, 'intent_committed')",
        [request_id],
    )?;
    conn.execute(
        "INSERT INTO outbox (request_id, payload) VALUES (?1, 'synthetic-inbox-ref')",
        [request_id],
    )?;
    Ok(())
}

fn coordinated_counts(conn: &Connection) -> rusqlite::Result<CoordinatedCounts> {
    Ok(CoordinatedCounts {
        item_revision: conn.query_row(
            "SELECT revision FROM item WHERE id = 'item-1'",
            [],
            |row| row.get(0),
        )?,
        policy_version: conn.query_row(
            "SELECT version FROM active_policy WHERE id = 'policy-1'",
            [],
            |row| row.get(0),
        )?,
        use_count: conn.query_row(
            "SELECT use_count FROM item WHERE id = 'item-1'",
            [],
            |row| row.get(0),
        )?,
        intent: conn.query_row("SELECT COUNT(*) FROM request_intent", [], |row| row.get(0))?,
        consumed: conn.query_row(
            "SELECT consumed FROM approval WHERE id = 'appr-1'",
            [],
            |row| row.get(0),
        )?,
        audit: conn.query_row("SELECT COUNT(*) FROM audit_event", [], |row| row.get(0))?,
        outbox: conn.query_row("SELECT COUNT(*) FROM outbox", [], |row| row.get(0))?,
    })
}

fn seed_store(path: &Path) -> rusqlite::Result<()> {
    let conn = open_encrypted_with_defaults(path, SYNTHETIC_KEY)?;
    create_schema(&conn)?;
    seed_item_and_policy(&conn)?;
    close_db(conn);
    Ok(())
}

fn damage_encrypted_copy(path: &Path) {
    let mut bytes = fs::read(path).expect("read copy before damage");
    assert!(
        bytes.len() > 256,
        "encrypted copy is too small to damage with a page-level corruption"
    );
    for byte in bytes.iter_mut().skip(96).take(64) {
        *byte ^= 0xA5;
    }
    fs::write(path, bytes).expect("write damaged encrypted copy");
}

#[test]
fn cipher_version_is_nonempty_not_ordinary_sqlite() {
    let dir = temp_store();
    let path = db_path(&dir, "cipher-version.sqlite");
    let conn = Connection::open(&path).expect("open probe database");
    apply_key(&conn, SYNTHETIC_KEY).expect("set SQLCipher key before any schema access");
    let version = require_sqlcipher(&conn);
    assert!(
        !version.trim().is_empty(),
        "PRAGMA cipher_version must be nonempty"
    );
}

#[test]
fn queried_sqlcipher_defaults_match_sqlcipher4() {
    let dir = temp_store();
    let path = db_path(&dir, "defaults.sqlite");
    let conn = open_encrypted_with_defaults(&path, SYNTHETIC_KEY).expect("open encrypted store");
    let defaults = query_cipher_defaults(&conn);
    assert_sqlcipher4_defaults(&defaults);
    println!("checked CipherDefaults: {defaults:?}");
    let journal = require_pragma_text(&conn, "journal_mode");
    assert!(
        !journal.trim().is_empty(),
        "PRAGMA journal_mode must be queryable"
    );
}

#[test]
fn right_key_opens_and_reads_synthetic_rows() {
    let dir = temp_store();
    let path = db_path(&dir, "right-key.sqlite");
    seed_store(&path).expect("seed encrypted store");
    let conn = open_encrypted(&path, SYNTHETIC_KEY).expect("reopen with right key");
    let credential = read_item_credential(&conn).expect("read item with right key");
    assert_eq!(credential, CANARY_CREDENTIAL);
    let label: String = conn
        .query_row("SELECT label FROM item WHERE id = 'item-1'", [], |row| {
            row.get(0)
        })
        .expect("read sensitive label");
    assert_eq!(label, CANARY_LABEL);
}

#[test]
fn wrong_key_fails_on_actual_table_read() {
    let dir = temp_store();
    let path = db_path(&dir, "wrong-key.sqlite");
    seed_store(&path).expect("seed encrypted store");
    let conn = Connection::open(&path).expect("open existing encrypted file");
    apply_key(&conn, WRONG_KEY).expect("set wrong key");
    require_sqlcipher(&conn);
    assert_table_read_fails(
        read_item_credential(&conn),
        "wrong key must fail on actual table read",
    );
}

#[test]
fn missing_key_fails_on_actual_table_read() {
    let dir = temp_store();
    let path = db_path(&dir, "missing-key.sqlite");
    seed_store(&path).expect("seed encrypted store");
    let conn = Connection::open(&path).expect("open existing encrypted file");
    require_sqlcipher(&conn);
    assert_table_read_fails(
        read_item_credential(&conn),
        "missing key must fail on actual table read",
    );
}

#[test]
fn encrypted_db_wal_and_journal_omit_canary_plaintext() {
    let dir = temp_store();

    let wal_path = db_path(&dir, "wal-canary.sqlite");
    let wal_conn = open_encrypted_with_defaults(&wal_path, SYNTHETIC_KEY).expect("open WAL store");
    set_journal_mode(&wal_conn, "WAL");
    wal_conn
        .pragma_update(None, "wal_autocheckpoint", 0)
        .expect("disable WAL autocheckpoint so the WAL artifact remains for the scan");
    create_schema(&wal_conn).expect("create schema after encryption");
    seed_item_and_policy(&wal_conn).expect("write canaries under WAL");
    require_artifact(&wal_path, "-wal");
    assert_artifacts_omit_canaries(&wal_path);
    close_db(wal_conn);

    let journal_path = db_path(&dir, "journal-canary.sqlite");
    let mut journal_conn =
        open_encrypted_with_defaults(&journal_path, SYNTHETIC_KEY).expect("open journal store");
    set_journal_mode(&journal_conn, "DELETE");
    create_schema(&journal_conn).expect("create schema after encryption");
    seed_item_and_policy(&journal_conn).expect("seed before journal transaction");
    let tx = journal_conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("open DELETE-mode write transaction");
    tx.execute(
        "UPDATE item SET note = ?1 WHERE id = 'item-1'",
        [CANARY_NOTE_JOURNAL_UPDATE],
    )
    .expect("write a distinct note so SQLite cannot elide the journal");
    tx.cache_flush()
        .expect("flush cache so the rollback journal is on disk");
    require_nonempty_artifact(&journal_path, "-journal");
    assert_artifacts_omit_canaries(&journal_path);
    tx.rollback().expect("roll back journal transaction");
    let restored_note: String = journal_conn
        .query_row("SELECT note FROM item WHERE id = 'item-1'", [], |row| {
            row.get(0)
        })
        .expect("read note after journal rollback");
    assert_eq!(restored_note, CANARY_NOTE);
}

#[test]
fn one_transaction_commits_item_policy_intent_approval_audit_outbox_and_reopens() {
    let dir = temp_store();
    let path = db_path(&dir, "commit-reopen.sqlite");
    seed_store(&path).expect("seed encrypted store");

    {
        let mut conn = open_encrypted(&path, SYNTHETIC_KEY).expect("open for commit");
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("begin immediate transaction");
        write_authorization_boundary(&tx, "req-1").expect("write coordinated records");
        tx.commit().expect("commit coordinated records");
        let counts = coordinated_counts(&conn).expect("read committed counts");
        assert_eq!(counts.item_revision, 2);
        assert_eq!(counts.policy_version, 1);
        assert_eq!(counts.use_count, 1);
        assert_eq!(counts.intent, 1);
        assert_eq!(counts.consumed, 1);
        assert_eq!(counts.audit, 1);
        assert_eq!(counts.outbox, 1);
        close_db(conn);
    }

    let conn = open_encrypted(&path, SYNTHETIC_KEY).expect("reopen after commit");
    let counts = coordinated_counts(&conn).expect("read persisted counts");
    assert_eq!(counts.item_revision, 2);
    assert_eq!(counts.policy_version, 1);
    assert_eq!(counts.use_count, 1);
    assert_eq!(counts.intent, 1);
    assert_eq!(counts.consumed, 1);
    assert_eq!(counts.audit, 1);
    assert_eq!(counts.outbox, 1);
    let credential = read_item_credential(&conn).expect("read persisted credential");
    assert_eq!(credential, CANARY_CREDENTIAL);
    // Local commit of intent records is not remote exactly-once execution.
    // This probe makes no connector call and cannot prove remote effects.
}

#[test]
fn one_transaction_rolls_back_all_coordinated_writes_on_injected_constraint() {
    let dir = temp_store();
    let path = db_path(&dir, "rollback.sqlite");
    seed_store(&path).expect("seed encrypted store");
    let mut conn = open_encrypted(&path, SYNTHETIC_KEY).expect("open for rollback");
    let before = coordinated_counts(&conn).expect("baseline counts");
    assert_eq!(before.item_revision, 1);
    assert_eq!(before.policy_version, 1);
    assert_eq!(before.use_count, 0);
    assert_eq!(before.consumed, 0);
    assert_eq!(before.intent, 0);
    assert_eq!(before.audit, 0);
    assert_eq!(before.outbox, 0);

    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("begin immediate transaction");
    write_authorization_boundary(&tx, "req-1").expect("write coordinated records");
    let injected = tx.execute(
        "INSERT INTO request_intent (id, item_id, item_revision, policy_version, digest)
         VALUES ('req-1', 'item-1', 2, 1, 'digest-duplicate')",
        [],
    );
    let err = injected.expect_err("injected primary-key conflict must fail");
    let constraint_violation = match &err {
        Error::SqliteFailure(failure, _) => failure.code == ErrorCode::ConstraintViolation,
        _ => false,
    };
    assert!(
        constraint_violation,
        "injected error must be a constraint violation, got {err:?}"
    );
    tx.rollback().expect("roll back coordinated writes");

    let after = coordinated_counts(&conn).expect("counts after rollback");
    assert_eq!(after.item_revision, 1);
    assert_eq!(after.policy_version, 1);
    assert_eq!(after.use_count, 0);
    assert_eq!(after.intent, 0);
    assert_eq!(after.consumed, 0);
    assert_eq!(after.audit, 0);
    assert_eq!(after.outbox, 0);
}

#[test]
fn closed_checkpointed_encrypted_copy_reopens_with_right_key_and_refuses_wrong_key() {
    let dir = temp_store();
    let path = db_path(&dir, "source.sqlite");
    let copy = db_path(&dir, "closed-copy.sqlite");

    let conn = open_encrypted_with_defaults(&path, SYNTHETIC_KEY).expect("open source");
    set_journal_mode(&conn, "WAL");
    create_schema(&conn).expect("create schema after encryption");
    seed_item_and_policy(&conn).expect("write rows");
    checkpoint_truncate(&conn);
    close_db(conn);

    let wal = sidecar(&path, "-wal");
    if wal.exists() {
        let len = fs::metadata(&wal)
            .expect("stat WAL after checkpoint and close")
            .len();
        assert!(
            len <= 32,
            "WAL still has {len} bytes after checkpoint and close; the copy would not be a checkpointed database"
        );
    }

    fs::copy(&path, &copy).expect("copy closed checkpointed encrypted database file");
    assert_artifacts_omit_canaries(&copy);

    {
        let right = open_encrypted(&copy, SYNTHETIC_KEY).expect("open copy with right key");
        let credential = read_item_credential(&right).expect("read copy with right key");
        assert_eq!(credential, CANARY_CREDENTIAL);
        close_db(right);
    }

    let wrong = Connection::open(&copy).expect("open copy with wrong key");
    apply_key(&wrong, WRONG_KEY).expect("set wrong key on copy");
    require_sqlcipher(&wrong);
    assert_table_read_fails(
        read_item_credential(&wrong),
        "wrong key must refuse the closed encrypted copy on actual table read",
    );
}

#[test]
fn damaged_encrypted_copy_fails_read_or_integrity() {
    let dir = temp_store();
    let path = db_path(&dir, "intact.sqlite");
    let damaged = db_path(&dir, "damaged.sqlite");
    seed_store(&path).expect("seed encrypted store");
    fs::copy(&path, &damaged).expect("copy encrypted database before damage");
    damage_encrypted_copy(&damaged);

    let conn = Connection::open(&damaged).expect("open damaged copy");
    apply_key(&conn, SYNTHETIC_KEY).expect("set correct key on damaged copy");
    require_sqlcipher(&conn);

    let integrity = conn.pragma_query_value(None, "integrity_check", |row| row.get::<_, String>(0));
    let read = read_item_credential(&conn);
    let integrity_failed = match integrity {
        Ok(ref status) => status != "ok",
        Err(_) => true,
    };
    let read_failed = read.is_err();
    assert!(
        integrity_failed || read_failed,
        "damaged encrypted copy must fail integrity_check or the table read; integrity={integrity:?} read={read:?}"
    );
}

#[test]
fn pragma_i64_decoder_accepts_integer_and_numeric_text() {
    assert_eq!(pragma_i64_from_value(ValueRef::Integer(4096)), Ok(4096));
    assert_eq!(
        pragma_i64_from_value(ValueRef::Integer(256_000)),
        Ok(256_000)
    );
    assert_eq!(pragma_i64_from_value(ValueRef::Integer(0)), Ok(0));
    assert_eq!(pragma_i64_from_value(ValueRef::Integer(1)), Ok(1));
    assert_eq!(pragma_i64_from_value(ValueRef::Text(b"4096")), Ok(4096));
    assert_eq!(
        pragma_i64_from_value(ValueRef::Text(b"256000")),
        Ok(256_000)
    );
    assert_eq!(pragma_i64_from_value(ValueRef::Text(b"0")), Ok(0));
    let owned_page = Value::Text("4096".to_owned());
    assert_eq!(pragma_i64_from_value(ValueRef::from(&owned_page)), Ok(4096));
    let owned_kdf = Value::Integer(256_000);
    assert_eq!(
        pragma_i64_from_value(ValueRef::from(&owned_kdf)),
        Ok(256_000)
    );
}

#[test]
fn pragma_i64_decoder_rejects_invalid_text_and_unsupported_values() {
    assert_eq!(
        pragma_i64_from_value(ValueRef::Text(b"")),
        Err("invalid integer text")
    );
    assert_eq!(
        pragma_i64_from_value(ValueRef::Text(b"4096.0")),
        Err("invalid integer text")
    );
    assert_eq!(
        pragma_i64_from_value(ValueRef::Text(b"hmac")),
        Err("invalid integer text")
    );
    assert_eq!(
        pragma_i64_from_value(ValueRef::Text(b" 4096")),
        Err("invalid integer text")
    );
    assert_eq!(
        pragma_i64_from_value(ValueRef::Text(b"4096 ")),
        Err("invalid integer text")
    );
    assert_eq!(
        pragma_i64_from_value(ValueRef::Text(b"0x1000")),
        Err("invalid integer text")
    );
    assert_eq!(
        pragma_i64_from_value(ValueRef::Text(b"9223372036854775808")),
        Err("out of i64 range")
    );
    assert_eq!(pragma_i64_from_value(ValueRef::Null), Err("null"));
    assert_eq!(pragma_i64_from_value(ValueRef::Real(4096.0)), Err("float"));
    assert_eq!(pragma_i64_from_value(ValueRef::Blob(b"4096")), Err("blob"));
    let owned_null = Value::Null;
    assert_eq!(
        pragma_i64_from_value(ValueRef::from(&owned_null)),
        Err("null")
    );
}
