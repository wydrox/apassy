#![cfg(feature = "vault")]

//! Synthetic library operations. These checks do not prove desktop UI interaction.

use apassy::contracts::CredentialKind;
use apassy::vault::{
    ExecMode, Field, GrantPlace, ItemDraft, ItemEventKind, MAX_ITEM_EVENTS, SecretValue, Vault,
    VaultErrorKind,
};
use tempfile::TempDir;

const PASS: &str = "synthetic-library-passphrase";

fn vault(dir: &TempDir) -> Vault {
    let mut vault = Vault::create(&dir.path().join("library.db"), PASS).unwrap();
    vault.unlock(PASS).unwrap();
    vault
}

fn field(name: &str, value: &str, secret: bool) -> Field {
    Field {
        name: name.to_owned(),
        value: SecretValue::new(value.to_owned()),
        secret,
    }
}

fn api(title: &str) -> ItemDraft {
    ItemDraft {
        title: title.to_owned(),
        kind: CredentialKind::ApiKey,
        notes: "Synthetic library note".to_owned(),
        tags: vec!["synthetic".to_owned()],
        fields: vec![field("token", "SYNTH-library-secret", true)],
    }
}

#[test]
fn create_in_chosen_folder_is_atomic_when_destination_was_deleted() {
    let dir = TempDir::new().unwrap();
    let mut vault = vault(&dir);
    let a = vault.create_folder(None, "A").unwrap();
    let b = vault.create_folder(None, "B").unwrap();
    let saved = vault.add_in_folder(api("Chosen B"), Some(&b.uuid)).unwrap();
    assert_eq!(vault.item_folder(saved.id).unwrap(), Some(b.uuid.clone()));
    assert!(
        vault
            .items_in_folder(Some(&a.uuid), false)
            .unwrap()
            .is_empty()
    );
    vault.delete_folder(&b.uuid).unwrap();
    let before = vault.search("").unwrap();
    assert_eq!(
        vault
            .add_in_folder(api("Must stay unsaved"), Some(&b.uuid))
            .unwrap_err()
            .kind(),
        VaultErrorKind::NotFound
    );
    assert_eq!(vault.search("").unwrap(), before);
    assert!(vault.search("Must stay unsaved").unwrap().is_empty());
}

#[test]
fn twenty_exact_ids_move_and_undo_without_changing_authority_or_existing_history() {
    let dir = TempDir::new().unwrap();
    let mut vault = vault(&dir);
    let a = vault.create_folder(None, "A").unwrap();
    let b = vault.create_folder(None, "B").unwrap();
    let ids: Vec<_> = (0..20)
        .map(|n| {
            vault
                .add_in_folder(
                    api(&format!("Item {n}")),
                    (n % 2 == 0).then_some(a.uuid.as_str()),
                )
                .unwrap()
                .id
        })
        .collect();
    let unrelated = vault
        .add_in_folder(api("Unrelated"), Some(&a.uuid))
        .unwrap();
    let (agent, _token) = vault.register_agent("Synthetic organizer").unwrap();
    vault
        .set_exec_grants(agent.id, &ids, &GrantPlace::AnyFolder, ExecMode::Bouncer)
        .unwrap();
    let grants = vault.exec_grants_for_agent(agent.id).unwrap();
    let summaries = vault.search("").unwrap();
    let histories: Vec<_> = ids
        .iter()
        .map(|id| vault.item_events(*id, MAX_ITEM_EVENTS).unwrap())
        .collect();
    let moves = vault.move_items_to_folder(&ids, Some(&b.uuid)).unwrap();
    assert_eq!(moves.iter().map(|m| m.item_id).collect::<Vec<_>>(), ids);
    assert_eq!(vault.items_in_folder(Some(&b.uuid), false).unwrap(), ids);
    assert_eq!(
        vault.item_folder(unrelated.id).unwrap(),
        Some(a.uuid.clone())
    );
    vault.undo_item_folder_moves(&moves).unwrap();
    for (index, id) in ids.iter().enumerate() {
        assert_eq!(
            vault.item_folder(*id).unwrap(),
            (index % 2 == 0).then(|| a.uuid.clone())
        );
        let events = vault.item_events(*id, MAX_ITEM_EVENTS).unwrap();
        assert_eq!(&events[2..], histories[index].as_slice());
        assert_eq!(events[0].kind, ItemEventKind::Moved);
        assert_eq!(events[1].kind, ItemEventKind::Moved);
        assert_eq!(
            vault.reveal(*id, "token").unwrap().expose(),
            "SYNTH-library-secret"
        );
    }
    assert_eq!(vault.exec_grants_for_agent(agent.id).unwrap(), grants);
    assert_eq!(vault.search("").unwrap(), summaries);
    assert_eq!(vault.item_folder(unrelated.id).unwrap(), Some(a.uuid));
    assert_eq!(
        vault.undo_item_folder_moves(&moves).unwrap_err().kind(),
        VaultErrorKind::Conflict
    );
}

#[test]
fn invalid_batch_ids_or_destination_never_partially_move_items() {
    let dir = TempDir::new().unwrap();
    let mut vault = vault(&dir);
    let b = vault.create_folder(None, "B").unwrap();
    let first = vault.add(api("First")).unwrap().id;
    let second = vault.add(api("Second")).unwrap().id;
    let events = vault.item_events(first, MAX_ITEM_EVENTS).unwrap();
    for (ids, folder, expected) in [
        (
            vec![first, 999_999],
            Some(b.uuid.as_str()),
            VaultErrorKind::NotFound,
        ),
        (
            vec![first, first],
            Some(b.uuid.as_str()),
            VaultErrorKind::InvalidInput,
        ),
        (
            vec![first, second],
            Some("missing-folder"),
            VaultErrorKind::NotFound,
        ),
        (
            vec![first, u64::MAX],
            Some(b.uuid.as_str()),
            VaultErrorKind::InvalidInput,
        ),
    ] {
        assert_eq!(
            vault.move_items_to_folder(&ids, folder).unwrap_err().kind(),
            expected
        );
        assert_eq!(vault.item_folder(first).unwrap(), None);
        assert_eq!(vault.item_folder(second).unwrap(), None);
        assert_eq!(vault.item_events(first, MAX_ITEM_EVENTS).unwrap(), events);
    }
}

#[test]
fn stale_undo_rejects_later_moves_even_when_the_item_returns_to_destination() {
    let dir = TempDir::new().unwrap();
    let mut vault = vault(&dir);
    let b = vault.create_folder(None, "B").unwrap();
    let c = vault.create_folder(None, "C").unwrap();
    let ids = [
        vault.add(api("First")).unwrap().id,
        vault.add(api("Second")).unwrap().id,
    ];
    let moves = vault.move_items_to_folder(&ids, Some(&b.uuid)).unwrap();
    vault.set_item_folder(ids[1], Some(&c.uuid)).unwrap();
    vault.set_item_folder(ids[1], Some(&b.uuid)).unwrap();
    assert_eq!(
        vault.undo_item_folder_moves(&moves).unwrap_err().kind(),
        VaultErrorKind::Conflict
    );
    assert_eq!(vault.items_in_folder(Some(&b.uuid), false).unwrap(), ids);
}

#[test]
fn undo_with_deleted_original_folder_or_another_session_changes_nothing() {
    let dir = TempDir::new().unwrap();
    let mut vault = vault(&dir);
    let a = vault.create_folder(None, "A").unwrap();
    let b = vault.create_folder(None, "B").unwrap();
    let ids = [
        vault.add(api("Top level")).unwrap().id,
        vault
            .add_in_folder(api("A item"), Some(&a.uuid))
            .unwrap()
            .id,
    ];
    let moves = vault.move_items_to_folder(&ids, Some(&b.uuid)).unwrap();
    vault.delete_folder(&a.uuid).unwrap();
    assert_eq!(
        vault.undo_item_folder_moves(&moves).unwrap_err().kind(),
        VaultErrorKind::NotFound
    );
    assert_eq!(vault.items_in_folder(Some(&b.uuid), false).unwrap(), ids);
    let top = vault.move_items_to_folder(&ids, None).unwrap();
    vault.lock().unwrap();
    vault.unlock(PASS).unwrap();
    assert_eq!(
        vault.undo_item_folder_moves(&top).unwrap_err().kind(),
        VaultErrorKind::Conflict
    );
    assert_eq!(vault.items_in_folder(None, false).unwrap(), ids);
}

#[test]
fn undo_rejects_a_deleted_item_or_destination_without_restoring_other_items() {
    let dir = TempDir::new().unwrap();
    let mut vault = vault(&dir);
    let b = vault.create_folder(None, "B").unwrap();
    let first = vault.add(api("First")).unwrap();
    let second = vault.add(api("Second")).unwrap();
    let moves = vault
        .move_items_to_folder(&[first.id, second.id], Some(&b.uuid))
        .unwrap();
    vault.delete(second.id, second.revision).unwrap();
    assert_eq!(
        vault.undo_item_folder_moves(&moves).unwrap_err().kind(),
        VaultErrorKind::NotFound
    );
    assert_eq!(vault.item_folder(first.id).unwrap(), Some(b.uuid.clone()));
    let receipt = vault.move_items_to_folder(&[first.id], None).unwrap();
    vault.delete_folder(&b.uuid).unwrap();
    assert_eq!(
        vault.undo_item_folder_moves(&receipt).unwrap_err().kind(),
        VaultErrorKind::NotFound
    );
    assert_eq!(vault.item_folder(first.id).unwrap(), None);
}

#[test]
fn identity_search_finds_visible_email_domain_and_host_but_never_secret_or_custom_fields() {
    let dir = TempDir::new().unwrap();
    let mut vault = vault(&dir);
    let login = vault
        .add(ItemDraft {
            title: "Personal account".to_owned(),
            kind: CredentialKind::Login,
            notes: String::new(),
            tags: vec![],
            fields: vec![
                field("username", "person@identity.example", false),
                field("website", "https://portal.lookup.example/login", false),
                field("password", "SYNTH-identity-secret", true),
                field("x_custom", "SYNTH-custom-visible", false),
            ],
        })
        .unwrap();
    let host = vault
        .add(ItemDraft {
            fields: vec![
                field("token", "SYNTH-host-token", true),
                field("host", "db.lookup.example", false),
            ],
            ..api("Host account")
        })
        .unwrap();
    let hidden = vault
        .add(ItemDraft {
            fields: vec![
                field("token", "SYNTH-other-token", true),
                field("username", "hidden-identity@example.invalid", true),
            ],
            ..api("Hidden identity")
        })
        .unwrap();
    assert_eq!(
        vault.search_identities("PERSON@IDENTITY.EXAMPLE").unwrap()[0].id,
        login.id
    );
    assert_eq!(
        vault.search_identities("portal.lookup.example").unwrap()[0].id,
        login.id
    );
    assert_eq!(
        vault.search_identities("db.lookup.example").unwrap()[0].id,
        host.id
    );
    for excluded in [
        "SYNTH-identity-secret",
        "SYNTH-host-token",
        "SYNTH-custom-visible",
        "hidden-identity@example.invalid",
        "' OR 1=1 --",
    ] {
        assert!(
            vault.search_identities(excluded).unwrap().is_empty(),
            "matched {excluded}"
        );
    }
    assert!(
        vault.search("person@identity.example").unwrap().is_empty(),
        "legacy metadata API keeps its contract"
    );
    assert_eq!(vault.search_identities("").unwrap().len(), 3);
    assert_eq!(
        vault.details(hidden.id).unwrap().summary.revision,
        hidden.revision
    );
    vault.lock().unwrap();
    assert_eq!(
        vault
            .search_identities("lookup.example")
            .unwrap_err()
            .kind(),
        VaultErrorKind::Locked
    );
}

#[cfg(feature = "desktop")]
#[test]
fn owner_can_save_and_find_a_login_without_agent_configuration() {
    use apassy::desktop::model::ItemDraft as OwnerDraft;
    use apassy::desktop::owner_store::{OwnerSession, SecretForm};

    let dir = TempDir::new().unwrap();
    let mut owner = OwnerSession::new();
    owner
        .create_file(&dir.path().join("owner.db"), PASS)
        .unwrap();
    owner.unlock(PASS).unwrap();
    let b = owner
        .with_vault(|vault| vault.create_folder(None, "B"))
        .unwrap()
        .unwrap();
    let draft = OwnerDraft {
        name: "Ordinary login".to_owned(),
        kind: CredentialKind::Login,
        username: "owner@synthetic.example".to_owned(),
        website: "https://account.synthetic.example/login".to_owned(),
        ..OwnerDraft::default()
    };
    let mut secrets = SecretForm::default();
    secrets.password = "SYNTH-owner-password".to_owned();
    let saved = owner
        .add_in_folder(&draft, &secrets, Some(&b.uuid))
        .unwrap();
    assert_eq!(
        owner.search("owner@synthetic.example").unwrap()[0].id,
        saved.id
    );
    assert!(owner.search("SYNTH-owner-password").unwrap().is_empty());
    assert_eq!(
        owner
            .with_vault(|vault| vault.item_folder(saved.id))
            .unwrap()
            .unwrap(),
        Some(b.uuid.clone())
    );
    owner
        .with_vault(|vault| vault.delete_folder(&b.uuid))
        .unwrap()
        .unwrap();
    assert_eq!(
        owner
            .add_in_folder(&draft, &secrets, Some(&b.uuid))
            .unwrap_err()
            .code,
        "not_found"
    );
    assert_eq!(owner.search("").unwrap().len(), 1);
}
