#![cfg(all(feature = "desktop", feature = "vault"))]

//! Owner vault session checks. Synthetic passphrases and canaries only.
//! This file does not prove memory erasure, native-window QA, or real-secret readiness.

use std::path::Path;

use apassy::broker::approvals::{OwnerAction, OwnerCheck, OwnerGate, OwnerProof};
use apassy::contracts::CredentialKind;
use apassy::desktop::model::ItemDraft;
use apassy::desktop::owner_store::{
    DeclarationForm, OwnerDetails, OwnerSession, SecretForm, parse_lifetime_days,
};
use apassy::vault::{EnvDelivery, GrantPlace};
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

/// A proof after a passed passphrase check (goal item A4).
fn owner_ok(session: &OwnerSession, action: OwnerAction) -> OwnerProof {
    OwnerGate::new(session.shared_vault(), None)
        .authorize(action, OwnerCheck::passphrase(PASS))
        .expect("owner check")
}

fn reveal(session: &mut OwnerSession, item_id: u64) -> OwnerDetails {
    let proof = owner_ok(session, OwnerAction::Reveal { item_id });
    session.reveal(item_id, proof).expect("reveal")
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
    assert!(masked.secret_lines.iter().all(|line| !line.revealed));
    assert_eq!(session.revealed_value(api.id, "token"), None);
    assert!(!format!("{masked:?}").contains(TOKEN));

    let revealed = reveal(&mut session, api.id);
    assert_eq!(revealed.secret_lines.len(), 1);
    assert!(revealed.secret_lines[0].revealed);
    assert_eq!(session.revealed_value(api.id, "token"), Some(TOKEN));
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
    reveal(&mut session, created.id);
    assert_eq!(session.revealed_value(created.id, "token"), Some(TOKEN));

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
    reveal(&mut session, created.id);
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
    reveal(&mut session, found[0].id);
    assert_eq!(session.revealed_value(found[0].id, "token"), Some(TOKEN));
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

#[test]
fn owner_messages_name_the_problem() {
    let dir = TempDir::new().expect("temp dir");
    let mut blank = OwnerSession::new();
    let err = blank
        .create_file(&dir.path().join("short.db"), "short")
        .expect_err("short create passphrase");
    assert_eq!(err.code, "invalid_input");
    assert!(err.message.contains("minimum of 12"), "{}", err.message);
    assert!(!dir.path().join("short.db").exists());

    let (mut session, path) = session_at(&dir, "messages.db");
    let err = session.unlock("").expect_err("empty passphrase");
    assert_eq!(err.message, "Type the passphrase.");
    let err = session.unlock(WRONG).expect_err("wrong passphrase");
    assert_eq!(err.code, "wrong_key");
    let err = OwnerSession::new()
        .create_file(&path, PASS)
        .expect_err("existing target");
    assert_eq!(err.code, "already_exists");
    for message in [&err.message, &session.unlock(WRONG).unwrap_err().message] {
        assert!(
            message.starts_with(char::is_uppercase) && message.ends_with('.'),
            "owner text must be a full sentence: {message}"
        );
    }
}

#[test]
fn unchanged_form_is_detected_before_a_save() {
    let dir = TempDir::new().expect("temp dir");
    let (mut session, _) = session_at(&dir, "same.db");
    unlock(&mut session);
    let draft = api_draft("Same", "Project Same");
    let created = session.add(&draft, &token_form(TOKEN)).expect("add");
    assert!(
        session
            .is_unchanged(created.id, &draft, &SecretForm::default())
            .expect("compare")
    );
    assert!(
        !session
            .is_unchanged(created.id, &draft, &token_form("owner-secret-new"))
            .expect("compare secret")
    );
    assert!(
        !session
            .is_unchanged(
                created.id,
                &api_draft("Other", "Project Same"),
                &SecretForm::default()
            )
            .expect("compare name")
    );
}

/// Goal item V4 in the owner session: the backup and restore procedure. The restore
/// revokes every agent and lists the items that wait for the owner review.
#[test]
fn restore_lists_items_for_review_until_the_owner_confirms() {
    let dir = TempDir::new().expect("temp dir");
    let (mut session, _) = session_at(&dir, "procedure.db");
    // The app starts locked. A new vault file also starts locked.
    assert!(OwnerSession::new().is_locked());
    assert!(session.is_locked());
    unlock(&mut session);
    let used = session
        .add(
            &api_draft("Used by agents", "Project V4"),
            &token_form(TOKEN),
        )
        .expect("add");
    let unused = session
        .add(
            &api_draft("Not for agents", "Project V4"),
            &token_form(DB_PASS),
        )
        .expect("add");
    let mut form = DeclarationForm {
        project: "Project V4".to_owned(),
        ..DeclarationForm::default()
    };
    form.environment = apassy::vault::Environment::Staging;
    let proof = owner_ok(&session, OwnerAction::ChangeItemRules { item_id: used.id });
    session
        .set_declaration(used.id, &form, proof)
        .expect("declaration");
    let proof = owner_ok(&session, OwnerAction::ChangeItemRules { item_id: used.id });
    session
        .set_env_binding(used.id, "USED_KEY", "token", &EnvDelivery::Value, proof)
        .expect("binding");
    session.register_agent("Before restore").expect("register");
    assert!(session.items_needing_review().expect("review").is_empty());

    let backup = dir.path().join("procedure.backup");
    session.backup(&backup).expect("backup");
    assert!(session.is_locked(), "backup locks the vault");
    let restored = dir.path().join("procedure-restored.db");
    session.restore(&backup, &restored, PASS).expect("restore");
    assert!(session.is_locked(), "the restored vault starts locked");
    assert_eq!(session.location(), Some(restored.as_path()));
    unlock(&mut session);
    assert!(session.agents().expect("agents").iter().all(|a| a.revoked));
    assert_eq!(
        session.items_needing_review().expect("review"),
        vec![(used.id, "Used by agents".to_owned())]
    );
    assert!(session.needs_review(used.id).expect("review"));
    assert!(!session.needs_review(unused.id).expect("review"));
    assert_eq!(
        session.declaration(used.id).expect("declaration"),
        Some(form.to_declaration()),
        "the restore keeps the settings for the review"
    );
    let proof = owner_ok(&session, OwnerAction::ChangeItemRules { item_id: used.id });
    session.confirm_review(used.id, proof).expect("confirm");
    assert!(session.items_needing_review().expect("review").is_empty());
    reveal(&mut session, used.id);
    assert_eq!(session.revealed_value(used.id, "token"), Some(TOKEN));
}

/// Goal item V5 in the owner session: the new passphrase two times, clear refusals, and
/// the old passphrase stays valid after each refusal.
#[test]
fn owner_changes_the_passphrase_with_a_repeat() {
    const NEW: &str = "owner-vault-pass-new";
    let dir = TempDir::new().expect("temp dir");
    let (mut session, path) = session_at(&dir, "rekey.db");
    unlock(&mut session);
    let created = session
        .add(&api_draft("Rekey me", "Project V5"), &token_form(TOKEN))
        .expect("add");
    let refusals = [
        ("", NEW, NEW, "Type the current passphrase."),
        (PASS, NEW, "owner-vault-pass-other", "different"),
        (PASS, "short", "short", "minimum of 12"),
        (PASS, PASS, PASS, "same as the current"),
        (WRONG, NEW, NEW, "current passphrase is incorrect"),
    ];
    for (current, new, repeat, expected) in refusals {
        let err = session
            .change_passphrase(current, new, repeat)
            .expect_err("refused change");
        assert!(err.message.contains(expected), "{}", err.message);
        assert!(!session.is_locked(), "a refusal keeps the vault open");
    }
    session.lock().expect("lock");
    let err = session
        .change_passphrase(PASS, NEW, NEW)
        .expect_err("locked vault");
    assert_eq!(err.code, "vault_locked");
    unlock(&mut session);

    session.change_passphrase(PASS, NEW, NEW).expect("change");
    assert!(!session.is_locked());
    session.lock().expect("lock");
    assert_eq!(
        session.unlock(PASS).expect_err("old passphrase").code,
        "wrong_key"
    );
    session.unlock(NEW).expect("new passphrase");
    // The owner check uses the new passphrase now. The old one fails.
    let old = OwnerGate::new(session.shared_vault(), None).authorize(
        OwnerAction::Reveal {
            item_id: created.id,
        },
        OwnerCheck::passphrase(PASS),
    );
    assert!(
        old.is_err(),
        "the old passphrase does not pass the owner check"
    );
    let proof = OwnerGate::new(session.shared_vault(), None)
        .authorize(
            OwnerAction::Reveal {
                item_id: created.id,
            },
            OwnerCheck::passphrase(NEW),
        )
        .expect("owner check with the new passphrase");
    session.reveal(created.id, proof).expect("reveal");
    assert_eq!(session.revealed_value(created.id, "token"), Some(TOKEN));
    assert!(!format!("{session:?}").contains(NEW));

    let mut reopened = OwnerSession::new();
    drop(session);
    reopened.open_file(&path).expect("open");
    reopened.unlock(NEW).expect("new passphrase after reopen");
}

/// Goal item P1 in the owner session: the lifetime text and a token rotation.
#[test]
fn owner_changes_token_lifetime_and_rotates_a_token() {
    let dir = TempDir::new().expect("temp dir");
    let (mut session, _) = session_at(&dir, "tokens.db");
    unlock(&mut session);
    let (agent, first) = session.register_agent("Session agent").expect("register");
    assert_eq!(session.token_lifetime_days().expect("lifetime"), 30);
    for bad in ["", "0", "366", "abc", "-1"] {
        let err = parse_lifetime_days(bad).expect_err("bad lifetime");
        assert_eq!(err.code, "invalid_input");
        assert!(err.message.contains("from 1 to 365"), "{}", err.message);
    }
    let proof = owner_ok(&session, OwnerAction::ChangeTokenLifetime);
    assert_eq!(
        session
            .set_token_lifetime_days(" 14 ", proof)
            .expect("lifetime"),
        14
    );
    let listed = session.agents().expect("agents").remove(0);
    assert_eq!(
        listed.token_expires_at - listed.token_issued_at,
        14 * 86_400
    );
    let proof = owner_ok(&session, OwnerAction::RotateToken { agent_id: agent.id });
    let second = session.rotate_agent_token(agent.id, proof).expect("rotate");
    assert_ne!(first.expose(), second.expose());
    assert!(!format!("{second:?}").contains(second.expose()));
    session.revoke_agent(agent.id).expect("revoke");
    let proof = owner_ok(&session, OwnerAction::RotateToken { agent_id: agent.id });
    let err = session
        .rotate_agent_token(agent.id, proof)
        .expect_err("revoked agent");
    assert!(
        err.message.contains("Register the agent again"),
        "{}",
        err.message
    );
}

/// Goal item A4: the gate refuses a wrong, empty, or missing check, and each guarded
/// owner action refuses a proof for another action or from an earlier vault session.
/// Nothing changes after a refusal.
#[test]
fn owner_actions_refuse_without_a_matching_check() {
    use apassy::broker::approvals::OwnerAuthError;
    use apassy::desktop::model::ModelError;
    use apassy::vault::{ExecMode, ExecRule};

    let dir = TempDir::new().expect("temp dir");
    let project = dir.path().join("project");
    std::fs::create_dir_all(&project).expect("project dir");
    let project = project.display().to_string();
    let (mut session, _) = session_at(&dir, "gate.db");
    let gate = OwnerGate::new(session.shared_vault(), None);
    let reveal_one = |item_id| OwnerAction::Reveal { item_id };

    // A locked vault gives no proof.
    assert_eq!(
        gate.authorize(reveal_one(1), OwnerCheck::passphrase(PASS))
            .unwrap_err(),
        OwnerAuthError::VaultLocked
    );
    unlock(&mut session);
    let item = session
        .add(&api_draft("Guarded", "Project A4"), &token_form(TOKEN))
        .expect("add");
    let (agent, _token) = session.register_agent("Guarded agent").expect("register");

    // A wrong or empty passphrase gives no proof. Without a helper, Touch ID gives no
    // proof, and the owner can still type the passphrase.
    assert_eq!(
        gate.authorize(reveal_one(item.id), OwnerCheck::passphrase(WRONG))
            .unwrap_err(),
        OwnerAuthError::WrongPassphrase
    );
    assert_eq!(
        gate.authorize(reveal_one(item.id), OwnerCheck::passphrase(""))
            .unwrap_err(),
        OwnerAuthError::EmptyPassphrase
    );
    let touch_id = gate
        .authorize(reveal_one(item.id), OwnerCheck::TouchId)
        .unwrap_err();
    assert!(touch_id.passphrase_fallback(), "{touch_id:?}");
    assert!(touch_id.message().contains("Type the passphrase"));

    // Each guarded action refuses a proof for another action.
    let other = |session: &OwnerSession| owner_ok(session, OwnerAction::ChangeTokenLifetime);
    let refused = |result: Result<(), ModelError>| {
        let err = result.expect_err("refused without a matching check");
        assert_eq!(err.code, "owner_check_required", "{}", err.message);
    };
    let proof = other(&session);
    refused(session.reveal(item.id, proof).map(drop));
    assert_eq!(session.revealed_value(item.id, "token"), None);
    let proof = other(&session);
    refused(session.set_connector(item.id, "reporting-api-v0", "http://127.0.0.1:8787", proof));
    assert_eq!(session.connector(item.id).expect("connector"), None);
    let proof = other(&session);
    refused(session.set_env_binding(item.id, "GUARDED_KEY", "token", &EnvDelivery::Value, proof));
    assert_eq!(session.env_binding(item.id).expect("binding"), None);
    let form = DeclarationForm {
        project: "Project A4".to_owned(),
        ..DeclarationForm::default()
    };
    let proof = other(&session);
    refused(session.set_declaration(item.id, &form, proof));
    assert_eq!(session.declaration(item.id).expect("declaration"), None);
    let proof = owner_ok(&session, OwnerAction::RotateToken { agent_id: agent.id });
    refused(session.set_token_lifetime_days("7", proof).map(drop));
    assert_eq!(session.token_lifetime_days().expect("lifetime"), 30);
    let proof = other(&session);
    refused(session.rotate_agent_token(agent.id, proof).map(drop));

    // Set up the item with matching proofs, then check the grants and the rule.
    let item_rules = |session: &OwnerSession| {
        owner_ok(session, OwnerAction::ChangeItemRules { item_id: item.id })
    };
    let proof = item_rules(&session);
    session
        .set_connector(item.id, "reporting-api-v0", "http://127.0.0.1:8787", proof)
        .expect("connector");
    let proof = item_rules(&session);
    session
        .set_env_binding(item.id, "GUARDED_KEY", "token", &EnvDelivery::Value, proof)
        .expect("binding");
    let proof = other(&session);
    refused(session.allow_operation(agent.id, item.id, "get_sales_summary", proof));
    assert!(session.grants(agent.id).expect("grants").is_empty());
    let proof = other(&session);
    refused(session.set_exec_grant(
        agent.id,
        item.id,
        &GrantPlace::Folder(project.clone()),
        ExecMode::Bouncer,
        proof,
    ));
    assert!(session.exec_grants(agent.id).expect("grants").is_empty());
    // A proof for another item is also refused.
    let other_item = owner_ok(
        &session,
        OwnerAction::ChangeGrant {
            agent_id: agent.id,
            item_id: item.id + 1,
        },
    );
    refused(session.allow_operation(agent.id, item.id, "get_sales_summary", other_item));
    assert!(session.grants(agent.id).expect("grants").is_empty());

    let grant = |session: &OwnerSession| {
        owner_ok(
            session,
            OwnerAction::ChangeGrant {
                agent_id: agent.id,
                item_id: item.id,
            },
        )
    };
    let proof = grant(&session);
    session
        .allow_operation(agent.id, item.id, "get_sales_summary", proof)
        .expect("grant with a proof");
    let proof = grant(&session);
    session
        .set_exec_grant(
            agent.id,
            item.id,
            &GrantPlace::Folder(project.clone()),
            ExecMode::Ask,
            proof,
        )
        .expect("process access with a proof");
    let rule = ExecRule {
        allowed_prefixes: vec!["npm test".to_owned()],
        ..ExecRule::default()
    };
    let proof = grant(&session);
    refused(session.set_exec_rule(agent.id, item.id, rule.clone(), proof));
    let saved = session.exec_grants(agent.id).expect("grants");
    assert!(
        saved[0].rule.allowed_prefixes.is_empty(),
        "the rule did not change"
    );
    let proof = owner_ok(
        &session,
        OwnerAction::ChangeRule {
            agent_id: agent.id,
            item_id: item.id,
        },
    );
    session
        .set_exec_rule(agent.id, item.id, rule, proof)
        .expect("rule with a proof");

    // A removal takes authority away. It needs no check.
    session
        .remove_operation(agent.id, item.id, "get_sales_summary")
        .expect("remove");
    assert!(session.grants(agent.id).expect("grants").is_empty());

    // A proof from before a lock is not valid after the unlock.
    let before_lock = owner_ok(&session, reveal_one(item.id));
    session.lock().expect("lock");
    unlock(&mut session);
    refused(session.reveal(item.id, before_lock).map(drop));
    assert_eq!(session.revealed_value(item.id, "token"), None);
}

/// Key-memory review F10: `details()` never holds a revealed value. The value hides on
/// "Hide", after the time limit, and on lock.
#[test]
fn revealed_values_hide_on_time_hide_and_lock() {
    use apassy::desktop::owner_store::REVEAL_TIME;
    use std::time::{Duration, Instant};

    let dir = TempDir::new().expect("temp dir");
    let (mut session, _) = session_at(&dir, "hide.db");
    unlock(&mut session);
    let item = session
        .add(&api_draft("Hide me", "Project F10"), &token_form(TOKEN))
        .expect("add");

    let details = reveal(&mut session, item.id);
    assert!(details.any_revealed());
    assert_eq!(session.revealed_value(item.id, "token"), Some(TOKEN));
    assert!(!format!("{details:?}").contains(TOKEN));
    assert!(!format!("{session:?}").contains(TOKEN));
    let hidden = session.hide(item.id).expect("hide");
    assert!(!hidden.any_revealed());
    assert_eq!(session.revealed_value(item.id, "token"), None);

    reveal(&mut session, item.id);
    assert!(session.next_reveal_expiry().expect("expiry") <= REVEAL_TIME);
    session.expire_reveals_at(Instant::now() + REVEAL_TIME + Duration::from_secs(1));
    assert_eq!(session.revealed_value(item.id, "token"), None);
    assert!(!session.details(item.id).expect("details").any_revealed());
    assert_eq!(session.next_reveal_expiry(), None);

    reveal(&mut session, item.id);
    session.lock().expect("lock");
    assert_eq!(session.revealed_value(item.id, "token"), None);
    unlock(&mut session);
    assert_eq!(session.revealed_value(item.id, "token"), None);
    assert!(!session.details(item.id).expect("details").any_revealed());
}

/// Custom details keep any label. A visible detail keeps its value. A hidden detail is a
/// secret field: masked, shown only after the owner check, usable for a variable, and
/// kept when the owner renames it without typing it again.
#[test]
fn custom_details_keep_labels_and_hide_hidden_values() {
    use apassy::desktop::model::DetailDraft;

    const RECOVERY: &str = "owner-secret-recovery-foxtrot";
    let dir = TempDir::new().expect("temp dir");
    let (mut session, _) = session_at(&dir, "details.db");
    unlock(&mut session);
    let mut draft = api_draft("With details", "Project D");
    draft.details = vec![
        DetailDraft {
            label: "Account ID".to_owned(),
            value: "acct_123".to_owned(),
            ..DetailDraft::default()
        },
        DetailDraft {
            label: "Kod odzyskiwania".to_owned(),
            hidden: true,
            ..DetailDraft::default()
        },
    ];
    let mut secrets = token_form(TOKEN);
    secrets.details[1] = RECOVERY.to_owned();
    let item = session.add(&draft, &secrets).expect("add");
    let details = session.details(item.id).expect("details");
    assert_eq!(details.details.len(), 2);
    assert_eq!(details.details[0].label, "Account ID");
    assert_eq!(details.details[0].value.as_deref(), Some("acct_123"));
    assert_eq!(details.details[1].label, "Kod odzyskiwania");
    assert!(details.details[1].hidden);
    assert_eq!(
        details.details[1].value, None,
        "a hidden value is not in the details"
    );
    assert!(!format!("{details:?}").contains(RECOVERY));
    let hidden_name = details.details[1].name.clone();
    assert!(
        session
            .secret_fields(item.id)
            .expect("fields")
            .contains(&hidden_name),
        "a hidden detail can back a variable"
    );
    assert_eq!(session.revealed_value(item.id, &hidden_name), None);
    reveal(&mut session, item.id);
    assert_eq!(
        session.revealed_value(item.id, &hidden_name),
        Some(RECOVERY)
    );

    // A rename with a blank input keeps the stored hidden value.
    let mut edit = details.to_draft();
    edit.details[1].label = "Recovery code".to_owned();
    let updated = session
        .update(item.id, details.revision, &edit, &SecretForm::default())
        .expect("rename");
    let renamed = session.details(item.id).expect("details");
    assert_eq!(renamed.details[1].label, "Recovery code");
    reveal(&mut session, item.id);
    assert_eq!(
        session.revealed_value(item.id, &renamed.details[1].name),
        Some(RECOVERY)
    );
    assert!(
        session
            .is_unchanged(item.id, &renamed.to_draft(), &SecretForm::default())
            .expect("unchanged")
    );

    // Refused drafts: a blank label, the same label two times, a long label, and a
    // detail without a value.
    let mut refuse = |details: Vec<DetailDraft>, text: &str| {
        let mut bad = renamed.to_draft();
        bad.details = details;
        let err = session
            .update(item.id, updated.revision, &bad, &SecretForm::default())
            .expect_err("refused");
        assert!(err.message.contains(text), "{}", err.message);
    };
    let visible = |label: &str, value: &str| DetailDraft {
        label: label.to_owned(),
        value: value.to_owned(),
        ..DetailDraft::default()
    };
    refuse(vec![visible(" ", "x")], "Type a name");
    refuse(
        vec![visible("Region", "eu"), visible("region", "us")],
        "Two custom details",
    );
    refuse(vec![visible(&"L".repeat(32), "x")], "too long");
    refuse(vec![visible("Region", "")], "Type the value of “Region”");

    // Removing a detail removes its field.
    let mut fewer = renamed.to_draft();
    fewer.details.remove(1);
    session
        .update(item.id, updated.revision, &fewer, &SecretForm::default())
        .expect("remove");
    let after = session.details(item.id).expect("details");
    assert_eq!(after.details.len(), 1);
    assert!(
        !session
            .secret_fields(item.id)
            .expect("fields")
            .contains(&renamed.details[1].name)
    );
}

/// An archive takes authority away, so it needs no owner check. The way back gives it
/// back, so it needs a check for the agent settings of the item (goal item A4).
#[test]
fn archive_needs_no_check_and_the_way_back_needs_one() {
    let dir = TempDir::new().expect("temp dir");
    let (mut session, _) = session_at(&dir, "archive.db");
    unlock(&mut session);
    let item = session
        .add(&api_draft("Old key", "Project A"), &token_form(TOKEN))
        .expect("add");
    reveal(&mut session, item.id);
    session.archive(item.id).expect("archive");
    assert!(session.is_archived(item.id).expect("state"));
    assert_eq!(
        session.revealed_value(item.id, "token"),
        None,
        "an archive hides revealed values"
    );
    assert!(session.details(item.id).expect("details").archived);
    let wrong = owner_ok(&session, OwnerAction::Reveal { item_id: item.id });
    let err = session.unarchive(item.id, wrong).expect_err("wrong proof");
    assert_eq!(err.code, "owner_check_required");
    assert!(session.is_archived(item.id).expect("state"));
    let proof = owner_ok(&session, OwnerAction::ChangeItemRules { item_id: item.id });
    session.unarchive(item.id, proof).expect("unarchive");
    assert!(!session.is_archived(item.id).expect("state"));
    let kinds: Vec<_> = session
        .item_events(item.id, 10)
        .expect("history")
        .iter()
        .map(|event| event.kind)
        .collect();
    use apassy::vault::ItemEventKind;
    assert_eq!(
        kinds,
        vec![
            ItemEventKind::Unarchived,
            ItemEventKind::Archived,
            ItemEventKind::Revealed,
            ItemEventKind::Created,
        ]
    );
}
