#![cfg(feature = "vault")]

use apassy::contracts::CredentialKind;
use apassy::vault::{
    EnvDelivery, ExecMode, Field, GrantPlace, ItemDraft, RequestState, SecretValue, SyncScope,
    Vault, VaultErrorKind,
};
use tempfile::TempDir;

const PASS: &str = "automatic-access-synthetic-pass";

fn fixture() -> (TempDir, Vault) {
    let dir = TempDir::new().unwrap();
    let mut vault = Vault::create(&dir.path().join("vault.db"), PASS).unwrap();
    vault.unlock(PASS).unwrap();
    (dir, vault)
}

fn field(name: &str, value: &str, secret: bool) -> Field {
    Field {
        name: name.into(),
        value: SecretValue::new(value.into()),
        secret,
    }
}

fn add(vault: &mut Vault, kind: CredentialKind, fields: Vec<Field>) -> u64 {
    vault
        .add(ItemDraft {
            title: "Synthetic credential".into(),
            kind,
            notes: String::new(),
            tags: Vec::new(),
            fields,
        })
        .unwrap()
        .id
}

fn api(vault: &mut Vault) -> u64 {
    add(
        vault,
        CredentialKind::ApiKey,
        vec![
            field("token", "FAKE-primary-token", true),
            field("x_5265636f76657279", "FAKE-hidden-recovery-code", true),
        ],
    )
}

#[test]
fn builtin_defaults_grant_without_stored_bindings() {
    let (_dir, mut vault) = fixture();
    let key = api(&mut vault);
    let login = add(
        &mut vault,
        CredentialKind::Login,
        vec![
            field("username", "synthetic-user", false),
            field("password", "FAKE-password", true),
        ],
    );
    let database = add(
        &mut vault,
        CredentialKind::Database,
        vec![
            field("host", "db.example.invalid", false),
            field("database", "synthetic", false),
            field("username", "synthetic-user", false),
            field("password", "FAKE-database-password", true),
        ],
    );
    let ssh = add(
        &mut vault,
        CredentialKind::SshKey,
        vec![
            field("private_key", "FAKE-private-key", true),
            field("passphrase", "FAKE-passphrase", true),
        ],
    );
    let (agent, _) = vault.register_agent("Synthetic agent").unwrap();
    for (item, expected_field) in [
        (key, "token"),
        (login, "password"),
        (database, "password"),
        (ssh, "private_key"),
    ] {
        let binding = vault.process_binding(item).unwrap().unwrap();
        assert_eq!(binding.field, expected_field);
        assert_eq!(binding.env_name, format!("APASSY_ITEM_{item}"));
        assert_eq!(binding.delivery, EnvDelivery::Value);
        vault
            .set_exec_grant(agent.id, item, "/tmp", ExecMode::Ask)
            .unwrap();
        assert!(vault.env_binding(item).unwrap().is_none());
    }
    assert_eq!(vault.exec_grants_for_agent(agent.id).unwrap().len(), 4);
}

#[test]
fn custom_ambiguity_needs_a_selected_field_but_not_a_variable_name() {
    let (_dir, mut vault) = fixture();
    let item = add(
        &mut vault,
        CredentialKind::Custom,
        vec![
            field("first", "FAKE-first", true),
            field("second", "FAKE-second", true),
        ],
    );
    assert!(vault.process_binding(item).unwrap().is_none());
    assert!(!vault.catalog().unwrap()[0].can_use_in_process);
    assert_eq!(vault.agent_credentials().unwrap()[0].0, item);
    vault.set_env_binding(item, "", "second").unwrap();
    let binding = vault.process_binding(item).unwrap().unwrap();
    assert_eq!(binding.field, "second");
    assert_eq!(binding.env_name, format!("APASSY_ITEM_{item}"));
    vault
        .set_env_binding(item, &binding.env_name, "second")
        .unwrap();
    for invalid in [
        "APASSY_OTHER".to_owned(),
        format!("APASSY_ITEM_{}", item + 1),
    ] {
        assert_eq!(
            vault
                .set_env_binding(item, &invalid, "first")
                .unwrap_err()
                .kind(),
            VaultErrorKind::InvalidInput
        );
    }
}

#[test]
fn custom_default_ignores_empty_and_plain_fields_and_rejects_no_secret() {
    let (_dir, mut vault) = fixture();
    let item = add(
        &mut vault,
        CredentialKind::Custom,
        vec![
            field("empty", "", true),
            field("plain", "public", false),
            field("secret", "FAKE-value", true),
        ],
    );
    assert_eq!(
        vault.process_binding(item).unwrap().unwrap().field,
        "secret"
    );
    let plain = add(
        &mut vault,
        CredentialKind::Custom,
        vec![field("plain", "public", false)],
    );
    assert!(vault.process_binding(plain).unwrap().is_none());
    assert_eq!(vault.agent_credentials().unwrap().len(), 1);
    vault.set_env_binding(item, "EMPTY_FIELD", "empty").unwrap();
    assert!(
        vault.process_binding(item).unwrap().is_none(),
        "an unusable explicit binding must not fall back"
    );
}

#[test]
fn access_requests_and_batch_grants_use_process_eligibility() {
    let (_dir, mut vault) = fixture();
    let item = api(&mut vault);
    let invalid = add(
        &mut vault,
        CredentialKind::Custom,
        vec![field("plain", "public", false)],
    );
    let (agent, _) = vault.register_agent("Synthetic agent").unwrap();
    assert_eq!(
        vault
            .request_access(agent.id, item, "Use the test service", "/tmp")
            .unwrap_err()
            .kind(),
        VaultErrorKind::NotFound
    );
    vault.set_agent_sees_all(agent.id, true).unwrap();
    vault
        .request_access(agent.id, item, "Use the test service", "/tmp")
        .unwrap();
    assert_eq!(
        vault
            .request_access(agent.id, invalid, "Use the test service", "/tmp")
            .unwrap_err()
            .kind(),
        VaultErrorKind::InvalidInput
    );
    assert!(
        vault
            .set_exec_grants(
                agent.id,
                &[item, invalid],
                &GrantPlace::AnyFolder,
                ExecMode::Ask
            )
            .is_err()
    );
    assert!(vault.exec_grants_for_agent(agent.id).unwrap().is_empty());
    assert_eq!(
        vault.agent_access_requests(agent.id, 10).unwrap()[0].state,
        RequestState::Open
    );
    vault
        .set_exec_grant(agent.id, item, "/tmp", ExecMode::Ask)
        .unwrap();
    assert_eq!(
        vault.agent_access_requests(agent.id, 10).unwrap()[0].state,
        RequestState::Granted
    );
    assert!(vault.env_binding(item).unwrap().is_none());
}

#[test]
fn explicit_placeholder_and_binding_removal_keep_existing_authority_rules() {
    let (_dir, mut vault) = fixture();
    let item = api(&mut vault);
    let delivery = EnvDelivery::Placeholder(vec!["api.example.invalid".into()]);
    vault
        .set_env_binding_with(item, "SERVICE_TOKEN", "token", &delivery)
        .unwrap();
    assert_eq!(
        vault.process_binding(item).unwrap(),
        vault.env_binding(item).unwrap()
    );
    let (agent, _) = vault.register_agent("Synthetic agent").unwrap();
    vault
        .set_exec_grant(agent.id, item, "/tmp", ExecMode::Ask)
        .unwrap();
    vault.clear_env_binding(item).unwrap();
    assert!(vault.exec_grants_for_agent(agent.id).unwrap().is_empty());
    assert_eq!(
        vault.process_binding(item).unwrap().unwrap().delivery,
        EnvDelivery::Value
    );
}

#[test]
fn archive_and_revoke_prevent_new_automatic_authority() {
    let (_dir, mut vault) = fixture();
    let item = api(&mut vault);
    let (agent, _) = vault.register_agent("Synthetic agent").unwrap();
    vault.set_agent_sees_all(agent.id, true).unwrap();
    vault.set_archived(item, true).unwrap();
    assert!(vault.process_binding(item).unwrap().is_none());
    assert!(vault.catalog().unwrap().is_empty());
    assert!(vault.agent_credentials().unwrap().is_empty());
    assert!(
        vault
            .set_exec_grant(agent.id, item, "/tmp", ExecMode::Ask)
            .is_err()
    );
    assert_eq!(
        vault
            .request_access(agent.id, item, "Use the test service", "/tmp")
            .unwrap_err()
            .kind(),
        VaultErrorKind::NotFound
    );
    vault.set_archived(item, false).unwrap();
    vault
        .set_exec_grant(agent.id, item, "/tmp", ExecMode::Ask)
        .unwrap();
    vault.revoke_agent(agent.id).unwrap();
    assert!(vault.exec_grants_for_agent(agent.id).unwrap().is_empty());
    assert!(
        vault
            .set_exec_grant(agent.id, item, "/tmp", ExecMode::Ask)
            .is_err()
    );
}

#[test]
fn restored_automatic_grants_need_review_and_do_not_restore_authority() {
    let (dir, mut vault) = fixture();
    let item = api(&mut vault);
    let (agent, _) = vault.register_agent("Synthetic agent").unwrap();
    vault
        .set_exec_grant(agent.id, item, "/tmp", ExecMode::Ask)
        .unwrap();
    let backup = dir.path().join("backup.db");
    vault.backup(&backup).unwrap();
    let mut restored = Vault::restore(&backup, &dir.path().join("restored.db"), PASS).unwrap();
    restored.unlock(PASS).unwrap();
    assert!(restored.needs_review(item).unwrap());
    assert!(restored.env_binding(item).unwrap().is_none());
    assert!(restored.exec_grants_for_agent(agent.id).unwrap().is_empty());
    assert!(
        restored
            .set_exec_grant(agent.id, item, "/tmp", ExecMode::Ask)
            .is_err()
    );
}

fn named_custom(vault: &mut Vault, title: &str) -> u64 {
    vault
        .add(ItemDraft {
            title: title.into(),
            kind: CredentialKind::Custom,
            notes: String::new(),
            tags: Vec::new(),
            fields: vec![
                field("first", "FAKE-first-secret", true),
                field("second", "FAKE-second-secret", true),
            ],
        })
        .unwrap()
        .id
}

#[test]
fn sync_remaps_automatic_names_preserves_selected_fields_and_converges() {
    let (dir, mut source) = fixture();
    let seed = dir.path().join("seed.db");
    source.write_sync_copy(&seed, "Source").unwrap();
    let (mut target, _) =
        Vault::adopt_sync_copy(&seed, &dir.path().join("target.db"), PASS).unwrap();
    target.unlock(PASS).unwrap();

    let source_first = named_custom(&mut source, "Remote first");
    let source_second = named_custom(&mut source, "Remote second");
    let placeholder = EnvDelivery::Placeholder(vec!["api.example.invalid".into()]);
    source.set_env_binding(source_first, "", "second").unwrap();
    source
        .set_env_binding_with(source_second, "", "first", &placeholder)
        .unwrap();
    let local_first = api(&mut target);
    let local_second = named_custom(&mut target, "Local selected");
    target.set_env_binding(local_second, "", "second").unwrap();
    assert_eq!(source_first, local_first);
    assert_eq!(source_second, local_second);

    let remote = dir.path().join("remote.db");
    source.write_sync_copy(&remote, "Source").unwrap();
    let scope = SyncScope::vault();
    let report = target.merge_from(&remote, &scope).unwrap();
    assert_eq!(report.inserted, 2);
    assert!(report.skipped_variables.is_empty(), "{report:?}");
    let mut names = std::collections::BTreeSet::new();
    for item in target.search("").unwrap() {
        let binding = target.process_binding(item.id).unwrap().unwrap();
        assert_eq!(binding.env_name, format!("APASSY_ITEM_{}", item.id));
        assert!(
            names.insert(binding.env_name.clone()),
            "duplicate runtime name"
        );
        if item.title == "Remote first" || item.title == "Remote second" {
            assert_ne!(item.id, source_first);
            assert_ne!(item.id, source_second);
            let expected_field = if item.title == "Remote first" {
                "second"
            } else {
                "first"
            };
            assert_eq!(binding.field, expected_field);
            if item.title == "Remote second" {
                assert_eq!(binding.delivery, placeholder);
            }
            assert_eq!(target.env_binding(item.id).unwrap().unwrap(), binding);
            target
                .set_env_binding_with(
                    item.id,
                    &binding.env_name,
                    &binding.field,
                    &binding.delivery,
                )
                .unwrap();
        }
    }
    assert_eq!(names.len(), 4);

    let target_copy = dir.path().join("target-copy.db");
    target.write_sync_copy(&target_copy, "Target").unwrap();
    source.merge_from(&target_copy, &scope).unwrap();
    assert_eq!(
        source.sync_content(&scope).unwrap(),
        target.sync_content(&scope).unwrap()
    );
    let converged = dir.path().join("converged.db");
    source.write_sync_copy(&converged, "Source").unwrap();
    let report = target.merge_from(&converged, &scope).unwrap();
    assert!(!report.changed_local(), "{report:?}");
    assert_eq!(
        source.sync_content(&scope).unwrap(),
        target.sync_content(&scope).unwrap()
    );
}

#[test]
fn sync_keeps_explicit_name_conflict_checks() {
    let (dir, mut source) = fixture();
    let seed = dir.path().join("seed.db");
    source.write_sync_copy(&seed, "Source").unwrap();
    let (mut target, _) =
        Vault::adopt_sync_copy(&seed, &dir.path().join("target.db"), PASS).unwrap();
    target.unlock(PASS).unwrap();
    let remote_id = named_custom(&mut source, "Remote named");
    let local_id = named_custom(&mut target, "Local named");
    source
        .set_env_binding(remote_id, "SERVICE_KEY", "first")
        .unwrap();
    target
        .set_env_binding(local_id, "SERVICE_KEY", "second")
        .unwrap();
    let remote = dir.path().join("remote.db");
    source.write_sync_copy(&remote, "Source").unwrap();
    let report = target.merge_from(&remote, &SyncScope::vault()).unwrap();
    assert_eq!(report.skipped_variables, ["SERVICE_KEY"]);
    let imported = target.search("Remote named").unwrap()[0].id;
    assert!(target.env_binding(imported).unwrap().is_none());
    assert!(target.process_binding(imported).unwrap().is_none());
    assert_eq!(
        target.env_binding(local_id).unwrap().unwrap().field,
        "second"
    );
    assert_eq!(
        target
            .set_env_binding(imported, "SERVICE_KEY", "first")
            .unwrap_err()
            .kind(),
        VaultErrorKind::AlreadyExists
    );
}
