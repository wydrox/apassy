//! Synthetic checks for SQLCipher passphrase interpretation. No real secrets.

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
