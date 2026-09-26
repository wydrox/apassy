//! Synthetic checks for SQLCipher passphrase interpretation and the passphrase change
//! (goal item V5). No real secrets.

use std::path::{Path, PathBuf};

use apassy::contracts::CredentialKind;
use apassy::vault::{Field, ItemDraft, SecretValue, Vault, VaultErrorKind};
use tempfile::TempDir;

const PASS: &str = "synthetic-normal-master-passphrase";

fn reserved_inputs() -> Vec<String> {
    vec![
        format!("x'{}'", "12".repeat(32)),
        format!("x'{}'", "12".repeat(48)),
        format!("X'{}'", "AB".repeat(32)),
        "x'reserved-prefix-even-without-hex".into(),
        "X'reserved-prefix-even-without-hex".into(),
        "synthetic-NUL\0-passphrase".into(),
    ]
}

fn item() -> ItemDraft {
    ItemDraft {
        title: "Synthetic passphrase regression".into(),
        kind: CredentialKind::ApiKey,
        notes: String::new(),
        tags: Vec::new(),
        fields: vec![Field {
            name: "token".into(),
            value: SecretValue::new("synthetic-passphrase-test-token".into()),
            secret: true,
        }],
    }
}

#[test]
fn details_debug_redacts_notes_without_hiding_explicit_metadata() {
    let dir = TempDir::new().unwrap();
    let mut vault = Vault::create(&dir.path().join("notes.db"), PASS).unwrap();
    vault.unlock(PASS).unwrap();
    let mut draft = item();
    draft.notes = "synthetic-owner-note-debug-canary".into();
    let summary = vault.add(draft).unwrap();
    let details = vault.details(summary.id).unwrap();
    assert_eq!(details.notes, "synthetic-owner-note-debug-canary");
    assert!(!format!("{details:?}").contains("synthetic-owner-note-debug-canary"));
    let epoch = vault.epoch();
    assert_eq!(
        vault
            .unlock("synthetic-wrong-passphrase")
            .unwrap_err()
            .kind(),
        VaultErrorKind::WrongKeyOrCorrupt
    );
    assert!(vault.is_locked());
    assert_ne!(vault.epoch(), epoch);
}

#[test]
fn raw_key_syntax_and_nul_cannot_create_a_vault() {
    let dir = TempDir::new().unwrap();
    for (index, pass) in reserved_inputs().iter().enumerate() {
        let path = dir.path().join(format!("refused-{index}.db"));
        assert_eq!(
            Vault::create(&path, pass).unwrap_err().kind(),
            VaultErrorKind::InvalidInput
        );
        assert!(!path.exists());
    }
}

#[test]
fn refused_passphrase_closes_an_existing_connection_but_keeps_the_lock() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("unlock.db");
    let mut vault = Vault::create(&path, PASS).unwrap();
    vault.unlock(PASS).unwrap();
    let summary = vault.add(item()).unwrap();
    for pass in reserved_inputs() {
        let epoch = vault.epoch();
        assert_eq!(
            vault.unlock(&pass).unwrap_err().kind(),
            VaultErrorKind::InvalidInput
        );
        assert!(vault.is_locked());
        assert_ne!(
            vault.epoch(),
            epoch,
            "a refused unlock must end the old epoch"
        );
        assert_eq!(
            vault.reveal(summary.id, "token").unwrap_err().kind(),
            VaultErrorKind::Locked
        );
        assert_eq!(Vault::open(&path).unwrap_err().kind(), VaultErrorKind::Busy);
        vault.unlock(PASS).unwrap();
        assert_ne!(vault.epoch(), epoch);
        assert_eq!(
            vault.reveal(summary.id, "token").unwrap().expose(),
            "synthetic-passphrase-test-token"
        );
    }
}

#[test]
fn refused_restore_input_preserves_backup_and_creates_no_destination() {
    let dir = TempDir::new().unwrap();
    let mut vault = Vault::create(&dir.path().join("source.db"), PASS).unwrap();
    vault.unlock(PASS).unwrap();
    vault.add(item()).unwrap();
    let backup = dir.path().join("backup.db");
    vault.backup(&backup).unwrap();
    let original = std::fs::read(&backup).unwrap();
    for (index, pass) in reserved_inputs().iter().enumerate() {
        let dest = dir.path().join(format!("restore-{index}.db"));
        assert_eq!(
            Vault::restore(&backup, &dest, pass).unwrap_err().kind(),
            VaultErrorKind::InvalidInput
        );
        assert!(!dest.exists());
        assert_eq!(std::fs::read(&backup).unwrap(), original);
    }
}

#[test]
fn quoted_unicode_passphrases_round_trip_without_sql_interpretation() {
    let dir = TempDir::new().unwrap();
    for (index, pass) in [
        "synthetic-'quoted\"-Zażółć-密碼-\n-passphrase",
        "synthetic-'; PRAGMA cipher_use_hmac=OFF; --",
    ]
    .into_iter()
    .enumerate()
    {
        let path = dir.path().join(format!("quoted-{index}.db"));
        let mut vault = Vault::create(&path, pass).unwrap();
        vault.unlock(pass).unwrap();
        let summary = vault.add(item()).unwrap();
        drop(vault);
        let mut reopened = Vault::open(&path).unwrap();
        reopened.unlock(pass).unwrap();
        assert_eq!(
            reopened.reveal(summary.id, "token").unwrap().expose(),
            "synthetic-passphrase-test-token"
        );
    }
}

const NEW_PASS: &str = "synthetic-new-master-passphrase";
const TOKEN_CANARY: &str = "synthetic-passphrase-test-token";

fn companions(path: &Path) -> Vec<PathBuf> {
    ["-journal", "-wal", "-shm"]
        .iter()
        .map(|suffix| {
            let mut name = path.as_os_str().to_os_string();
            name.push(suffix);
            PathBuf::from(name)
        })
        .filter(|companion| companion.exists())
        .collect()
}

/// A raw SQLCipher connection with explicit settings. `None` keeps the SQLCipher 4 defaults.
fn raw_opens(path: &Path, pass: &str, weaker: Option<&str>) -> bool {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.pragma_update(None, "key", pass).unwrap();
    // SQLCipher reads cipher settings after the key and before the first read.
    if let Some(pragma) = weaker {
        conn.execute_batch(pragma).unwrap();
    }
    let readable = conn
        .query_row("SELECT count(*) FROM item", [], |row| row.get::<_, i64>(0))
        .is_ok();
    let mut hmac_rows = 0;
    if readable {
        conn.pragma_query(None, "cipher_integrity_check", |_| {
            hmac_rows += 1;
            Ok(())
        })
        .unwrap();
    }
    readable && hmac_rows == 0
}

/// Goal item V5: the old passphrase fails after the change, the new one opens the vault,
/// and the data stays. The SQLCipher 4 KDF and HMAC settings stay in effect.
#[test]
fn change_passphrase_rekeys_and_keeps_the_data() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("rekey.db");
    let mut vault = Vault::create(&path, PASS).unwrap();
    vault.unlock(PASS).unwrap();
    let summary = vault.add(item()).unwrap();
    let (agent, token) = vault.register_agent("Rekey agent").unwrap();
    let token = token.expose().to_owned();
    let backup = dir.path().join("before-change.bak");
    vault.backup(&backup).unwrap();
    vault.unlock(PASS).unwrap();

    let epoch = vault.epoch();
    vault.change_passphrase(PASS, NEW_PASS).unwrap();
    assert!(
        !vault.is_locked(),
        "the vault stays open with the new passphrase"
    );
    assert_ne!(vault.epoch(), epoch, "the change ends the vault epoch");
    assert_eq!(
        vault.reveal(summary.id, "token").unwrap().expose(),
        TOKEN_CANARY
    );
    assert!(companions(&path).is_empty(), "no journal or WAL file stays");

    vault.lock().unwrap();
    assert_eq!(
        vault.unlock(PASS).unwrap_err().kind(),
        VaultErrorKind::WrongKeyOrCorrupt
    );
    assert!(vault.is_locked());
    vault.unlock(NEW_PASS).unwrap();
    assert_eq!(vault.details(summary.id).unwrap().summary, summary);
    assert_eq!(vault.authenticate_agent(&token).unwrap().id, agent.id);
    drop(vault);

    let mut reopened = Vault::open(&path).unwrap();
    reopened.unlock(NEW_PASS).unwrap();
    assert_eq!(
        reopened.reveal(summary.id, "token").unwrap().expose(),
        TOKEN_CANARY
    );
    drop(reopened);

    // The file opens only with the SQLCipher 4 defaults: 256000 PBKDF2-HMAC-SHA512
    // iterations and HMAC-SHA512 page checks. Weaker settings do not open it.
    assert!(raw_opens(&path, NEW_PASS, None));
    assert!(!raw_opens(&path, PASS, None));
    assert!(!raw_opens(
        &path,
        NEW_PASS,
        Some("PRAGMA kdf_iter = 64000;")
    ));
    assert!(!raw_opens(
        &path,
        NEW_PASS,
        Some("PRAGMA cipher_compatibility = 3;")
    ));
    let bytes = std::fs::read(&path).unwrap();
    for canary in [
        TOKEN_CANARY,
        "Synthetic passphrase regression",
        "Rekey agent",
    ] {
        assert!(
            !bytes
                .windows(canary.len())
                .any(|window| window == canary.as_bytes()),
            "plaintext {canary} in the file"
        );
    }

    // A backup keeps the passphrase of its time.
    assert_eq!(
        Vault::restore(&backup, &dir.path().join("with-new.db"), NEW_PASS)
            .unwrap_err()
            .kind(),
        VaultErrorKind::WrongKeyOrCorrupt
    );
    let mut old = Vault::restore(&backup, &dir.path().join("with-old.db"), PASS).unwrap();
    old.unlock(PASS).unwrap();
    assert_eq!(
        old.reveal(summary.id, "token").unwrap().expose(),
        TOKEN_CANARY
    );
}

/// Goal item V5: a refused or failed change leaves the old passphrase valid.
#[test]
fn failed_passphrase_change_keeps_the_old_passphrase() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("keep.db");
    let mut vault = Vault::create(&path, PASS).unwrap();
    assert_eq!(
        vault.change_passphrase(PASS, NEW_PASS).unwrap_err().kind(),
        VaultErrorKind::Locked
    );
    vault.unlock(PASS).unwrap();
    let summary = vault.add(item()).unwrap();

    // A wrong current passphrase changes nothing. The vault stays open.
    let epoch = vault.epoch();
    assert_eq!(
        vault
            .change_passphrase("synthetic-wrong-passphrase", NEW_PASS)
            .unwrap_err()
            .kind(),
        VaultErrorKind::WrongKeyOrCorrupt
    );
    assert!(!vault.is_locked());
    assert_eq!(vault.epoch(), epoch);

    // A new passphrase that create refuses, or the same passphrase, changes nothing.
    let mut refused = reserved_inputs();
    refused.push("short".into());
    refused.push(PASS.into());
    for new in &refused {
        assert_eq!(
            vault.change_passphrase(PASS, new).unwrap_err().kind(),
            VaultErrorKind::InvalidInput
        );
        assert!(!vault.is_locked());
    }

    // Another SQLite connection holds a read transaction, so the rekey cannot commit.
    // Without a check, SQLCipher answers "ok" and the file keeps the old key. The vault
    // takes the exclusive lock first, so the change stops before a page changes.
    let reader = rusqlite::Connection::open(&path).unwrap();
    reader.pragma_update(None, "key", PASS).unwrap();
    reader.execute_batch("BEGIN").unwrap();
    let count: i64 = reader
        .query_row("SELECT count(*) FROM item", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
    assert_eq!(
        vault.change_passphrase(PASS, NEW_PASS).unwrap_err().kind(),
        VaultErrorKind::Busy
    );
    assert!(vault.is_locked());
    assert!(companions(&path).is_empty(), "{:?}", companions(&path));
    reader.execute_batch("ROLLBACK").unwrap();
    reader.close().map_err(|(_, err)| err).unwrap();

    for pass in [NEW_PASS, "synthetic-wrong-passphrase"] {
        assert_eq!(
            vault.unlock(pass).unwrap_err().kind(),
            VaultErrorKind::WrongKeyOrCorrupt
        );
    }
    vault.unlock(PASS).unwrap();
    assert_eq!(
        vault.reveal(summary.id, "token").unwrap().expose(),
        TOKEN_CANARY
    );
    // After the failure, a new attempt works.
    vault.change_passphrase(PASS, NEW_PASS).unwrap();
    vault.lock().unwrap();
    vault.unlock(NEW_PASS).unwrap();
}

/// Goal item V5: a vault that an external tool switched to WAL mode goes back to DELETE
/// mode at unlock. No WAL file with pages of the old key stays after the change.
#[test]
fn wal_mode_file_changes_passphrase_without_a_wal_file() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("wal.db");
    {
        let mut vault = Vault::create(&path, PASS).unwrap();
        vault.unlock(PASS).unwrap();
        vault.add(item()).unwrap();
    }
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.pragma_update(None, "key", PASS).unwrap();
        let mode: String = conn
            .pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))
            .unwrap();
        assert_eq!(mode.to_ascii_lowercase(), "wal");
        conn.execute("UPDATE item SET notes = 'wal-note'", [])
            .unwrap();
        conn.close().map_err(|(_, err)| err).unwrap();
        let check = rusqlite::Connection::open(&path).unwrap();
        check.pragma_update(None, "key", PASS).unwrap();
        let mode: String = check
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .unwrap();
        assert_eq!(
            mode.to_ascii_lowercase(),
            "wal",
            "the file stays in WAL mode"
        );
        check.close().map_err(|(_, err)| err).unwrap();
    }
    let mut vault = Vault::open(&path).unwrap();
    vault.unlock(PASS).unwrap();
    vault.change_passphrase(PASS, NEW_PASS).unwrap();
    assert!(companions(&path).is_empty(), "{:?}", companions(&path));
    vault.lock().unwrap();
    assert_eq!(
        vault.unlock(PASS).unwrap_err().kind(),
        VaultErrorKind::WrongKeyOrCorrupt
    );
    vault.unlock(NEW_PASS).unwrap();
    let found = vault.search("wal-note").unwrap();
    assert_eq!(found.len(), 1, "the WAL write is in the rekeyed file");
    drop(vault);
    assert!(raw_opens(&path, NEW_PASS, None));
}
