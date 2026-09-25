#![cfg(all(feature = "desktop", feature = "vault"))]

//! Owner vault session checks. Synthetic passphrases and canaries only.
//! This file does not prove memory erasure, native-window QA, or real-secret readiness.

use std::path::Path;

use apassy::contracts::CredentialKind;
use apassy::desktop::model::ItemDraft;
use apassy::desktop::owner_store::{OwnerSession, SecretForm};
use tempfile::TempDir;

const PASS: &str = "owner-vault-pass-ok";
const WRONG: &str = "owner-vault-pass-no";
const TOKEN: &str = "owner-secret-token-alpha";
const LOGIN_PASS: &str = "owner-secret-login-bravo";
const SSH_KEY: &str = "owner-secret-ssh-charlie";
const SSH_PHRASE: &str = "owner-secret-ssh-phrase";
const DB_PASS: &str = "owner-secret-db-delta";
const CUSTOM_SECRET: &str = "owner-secret-custom-echo";

fn session_at(dir: &TempDir, name: &str) -> (OwnerSession, std::path::PathBuf) {
    let path = dir.path().join(name);
    let mut session = OwnerSession::new();
    session
        .create_file(&path, PASS)
        .expect("create synthetic vault");
    (session, path)
}

fn unlock(session: &mut OwnerSession) {
    session.unlock(PASS).expect("unlock synthetic vault");
}

fn api_draft(name: &str, project: &str) -> ItemDraft {
    ItemDraft {
        name: name.to_owned(),
        kind: CredentialKind::ApiKey,
        project: project.to_owned(),
        service: "reporting-api".to_owned(),
        ..ItemDraft::default()
    }
}

fn token_form(token: &str) -> SecretForm {
    let mut secrets = SecretForm::default();
    secrets.token = token.to_owned();
    secrets
}

#[test]
fn create_starts_locked_and_wrong_passphrase_stays_locked() {
    let dir = TempDir::new().expect("temp dir");
    let (mut session, path) = session_at(&dir, "vault.db");
    assert!(session.has_file());
    assert!(session.is_locked());
    assert_eq!(session.location(), Some(path.as_path()));
    let err = {
        let mut blank = OwnerSession::new();
        blank
            .create_file(&dir.path().join("short.db"), "short")
            .expect_err("short create passphrase")
    };
    assert_eq!(err.code, "invalid_input");
    let err = session
        .unlock("short")
        .expect_err("short unlock passphrase");
    assert_eq!(err.code, "wrong_key");
    assert!(session.is_locked());
    let err = session.unlock(WRONG).expect_err("wrong passphrase");
    assert_eq!(err.code, "wrong_key");
    assert!(session.is_locked());
    assert!(!format!("{session:?}").contains(PASS));
    assert!(!format!("{session:?}").contains(WRONG));
}

#[test]
fn five_categories_round_trip_without_searching_secrets() {
    let dir = TempDir::new().expect("temp dir");
    let (mut session, _) = session_at(&dir, "items.db");
    unlock(&mut session);

    let api = session
        .add(&api_draft("Alpha API", "Project Alpha"), &token_form(TOKEN))
        .expect("add api key");
    let mut login_secrets = SecretForm::default();
    login_secrets.password = LOGIN_PASS.to_owned();
    session
        .add(
            &ItemDraft {
                name: "Bravo login".to_owned(),
                kind: CredentialKind::Login,
                username: "report-owner".to_owned(),
                ..ItemDraft::default()
            },
            &login_secrets,
        )
        .expect("add login");
    let mut ssh_secrets = SecretForm::default();
    ssh_secrets.private_key = SSH_KEY.to_owned();
    ssh_secrets.key_passphrase = SSH_PHRASE.to_owned();
    session
        .add(
            &ItemDraft {
                name: "Charlie key".to_owned(),
                kind: CredentialKind::SshKey,
                public_label: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFake".to_owned(),
                ..ItemDraft::default()
            },
            &ssh_secrets,
        )
        .expect("add ssh key");
    let mut db_secrets = SecretForm::default();
    db_secrets.password = DB_PASS.to_owned();
    session
        .add(
            &ItemDraft {
                name: "Delta database".to_owned(),
                kind: CredentialKind::Database,
                username: "reader".to_owned(),
                host: "db.internal".to_owned(),
                database_name: "reports".to_owned(),
                ..ItemDraft::default()
            },
            &db_secrets,
        )
        .expect("add database");
    let mut custom_secrets = SecretForm::default();
    custom_secrets.custom_value = CUSTOM_SECRET.to_owned();
    session
        .add(
            &ItemDraft {
                name: "Echo custom".to_owned(),
                kind: CredentialKind::Custom,
                field_name: "blob".to_owned(),
                ..ItemDraft::default()
            },
            &custom_secrets,
        )
        .expect("add custom");

    assert_eq!(session.search("").expect("list").len(), 5);
    assert_eq!(
        session
            .search("Project Alpha")
            .expect("project search")
            .len(),
        1
    );
    assert_eq!(
        session
            .search("reporting-api")
            .expect("service search")
            .len(),
        1
    );
    for secret in [
        TOKEN,
        LOGIN_PASS,
        SSH_KEY,
        SSH_PHRASE,
        DB_PASS,
        CUSTOM_SECRET,
    ] {
        assert!(
            session.search(secret).expect("secret search").is_empty(),
            "search must not match a secret field"
        );
    }

    let masked = session.details(api.id).expect("masked details");
    assert!(!masked.hidden);
    assert!(!masked.any_revealed());
    assert!(masked.secret_lines.iter().all(|line| line.display != TOKEN));
    assert!(!format!("{masked:?}").contains(TOKEN));

    let revealed = session.reveal(api.id).expect("reveal");
    assert_eq!(revealed.secret_lines.len(), 1);
    assert_eq!(revealed.secret_lines[0].display, TOKEN);
    assert!(!format!("{revealed:?}").contains(TOKEN));
    assert!(!format!("{session:?}").contains(TOKEN));

    session.lock().expect("lock");
    let hidden = session.details(api.id).expect("locked details");
    assert!(hidden.hidden);
    assert!(hidden.secret_lines.is_empty());
    assert!(!format!("{hidden:?}").contains(TOKEN));
    assert!(!format!("{session:?}").contains(TOKEN));
}

#[test]
fn update_keeps_blank_secret_and_conflict_rejects_stale_revision() {
    let dir = TempDir::new().expect("temp dir");
    let (mut session, _) = session_at(&dir, "edit.db");
    unlock(&mut session);
    let created = session
        .add(&api_draft("Before", "Project Edit"), &token_form(TOKEN))
        .expect("add");
    let updated = session
        .update(
            created.id,
            created.revision,
            &api_draft("After", "Project Edit"),
            &SecretForm::default(),
        )
        .expect("keep secret");
    assert_eq!(updated.name, "After");
    assert_ne!(updated.revision, created.revision);
    let revealed = session.reveal(created.id).expect("reveal kept secret");
    assert_eq!(revealed.secret_lines[0].display, TOKEN);

    let err = session
        .update(
            created.id,
            created.revision,
            &api_draft("Stale", "Project Edit"),
            &SecretForm::default(),
        )
        .expect_err("stale revision");
    assert_eq!(err.code, "conflict");
}

#[test]
fn delete_backup_and_restore_round_trip() {
    let dir = TempDir::new().expect("temp dir");
    let (mut session, _) = session_at(&dir, "live.db");
    unlock(&mut session);
    let created = session
        .add(
            &api_draft("Restore me", "Project Restore"),
            &token_form(TOKEN),
        )
        .expect("add");
    session.reveal(created.id).expect("reveal before backup");
    let backup = dir.path().join("live.backup");
    session.backup(&backup).expect("backup");
    assert!(session.is_locked());
    assert!(!format!("{session:?}").contains(TOKEN));

    let restored = dir.path().join("restored.db");
    session
        .restore(&backup, &restored, WRONG)
        .expect_err("wrong restore passphrase");
    assert_eq!(
        session.location(),
        Some(Path::new(&dir.path().join("live.db")))
    );
    session.restore(&backup, &restored, PASS).expect("restore");
    assert!(session.is_locked());
    unlock(&mut session);
    let found = session.search("Restore me").expect("restored search");
    assert_eq!(found.len(), 1);
    let revealed = session.reveal(found[0].id).expect("restored reveal");
    assert_eq!(revealed.secret_lines[0].display, TOKEN);
    session
        .delete(found[0].id, found[0].revision)
        .expect("delete");
    let err = session.details(found[0].id).expect_err("deleted item");
    assert_eq!(err.code, "not_found");
}

#[test]
fn missing_file_keeps_the_current_session() {
    let dir = TempDir::new().expect("temp dir");
    let (mut session, path) = session_at(&dir, "kept.db");
    let err = session
        .open_file(&dir.path().join("missing.db"))
        .expect_err("missing file");
    assert_eq!(err.code, "not_found");
    assert_eq!(session.location(), Some(path.as_path()));
    assert!(session.is_locked());
}
