#![cfg(feature = "vault")]

//! Duplicate cleanup (`src/vault/dedup.rs`): the groups of duplicate items, the
//! suggestion of the item to keep, the differences by label, and the merge with its
//! passkey, agent, and limit rules. Synthetic values only: each secret starts with
//! `SYNTH-DUP-`, and the tests compare values without printing them.

use std::path::Path;

use apassy::contracts::CredentialKind;
use apassy::vault::passkey::ES256;
use apassy::vault::{
    DuplicateGroup, Field, ItemDraft, ItemEventKind, MERGED_INTO_DETAIL, MergeOutcome,
    MergeRefusal, PasskeyCreate, PasskeyTarget, SecretValue, SyncScope, Vault, VaultErrorKind,
    VaultResult, merged_count,
};
use tempfile::TempDir;

const PASS: &str = "synthetic-dedup-pass";
const CANARY: &str = "SYNTH-DUP-";
const RP: &str = "example.com";
const HASH: [u8; 32] = [0x3c; 32];

fn vault(dir: &TempDir, name: &str) -> Vault {
    let mut vault = Vault::create(&dir.path().join(name), PASS).unwrap();
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

/// The field name of a custom detail, as the Mac writes it.
fn detail(label: &str) -> String {
    let mut name = String::from("x_");
    for byte in label.as_bytes() {
        name.push_str(&format!("{byte:02x}"));
    }
    name
}

fn login(title: &str, username: &str, password: &str, websites: &[&str]) -> ItemDraft {
    let mut fields = vec![
        field("username", username, false),
        field("password", password, true),
    ];
    for (index, website) in websites.iter().enumerate() {
        let label = if index == 0 {
            "Website".to_owned()
        } else {
            format!("Website {}", index + 1)
        };
        fields.push(field(&detail(&label), website, false));
    }
    ItemDraft {
        title: title.to_owned(),
        kind: CredentialKind::Login,
        notes: String::new(),
        tags: Vec::new(),
        fields,
    }
}

fn api_key(title: &str, token: &str) -> ItemDraft {
    ItemDraft {
        title: title.to_owned(),
        kind: CredentialKind::ApiKey,
        notes: String::new(),
        tags: Vec::new(),
        fields: vec![field("token", token, true)],
    }
}

fn custom(title: &str, name: &str, value: &str) -> ItemDraft {
    ItemDraft {
        title: title.to_owned(),
        kind: CredentialKind::Custom,
        notes: String::new(),
        tags: Vec::new(),
        fields: vec![field(name, value, true)],
    }
}

fn add(vault: &mut Vault, draft: ItemDraft) -> u64 {
    vault.add(draft).unwrap().id
}

/// The member IDs of each group.
fn ids(vault: &Vault) -> Vec<Vec<u64>> {
    vault
        .duplicate_groups()
        .unwrap()
        .iter()
        .map(|group| group.items.iter().map(|item| item.id).collect())
        .collect()
}

fn group_of(vault: &Vault, id: u64) -> DuplicateGroup {
    vault
        .duplicate_groups()
        .unwrap()
        .into_iter()
        .find(|group| group.items.iter().any(|item| item.id == id))
        .expect("group")
}

fn revision(vault: &Vault, id: u64) -> u64 {
    vault.details(id).unwrap().summary.revision
}

fn merge(vault: &mut Vault, keep: u64, others: &[u64]) -> VaultResult<MergeOutcome> {
    let keep = (keep, revision(vault, keep));
    let others: Vec<(u64, u64)> = others
        .iter()
        .map(|id| (*id, revision(vault, *id)))
        .collect();
    vault.merge_duplicates(keep, &others)
}

fn value(vault: &Vault, id: u64, name: &str) -> String {
    vault.reveal(id, name).unwrap().expose().to_owned()
}

fn names(vault: &Vault, id: u64) -> Vec<(String, bool)> {
    vault
        .details(id)
        .unwrap()
        .fields
        .into_iter()
        .map(|field| (field.name, field.secret))
        .collect()
}

/// Debug of the groups holds labels and titles, never a value.
fn assert_no_value(groups: &[DuplicateGroup]) {
    let text = format!("{groups:?}");
    assert!(!text.contains(CANARY), "a value is in the groups");
    for group in groups {
        for label in group.differences.iter().chain(group.reason.iter()) {
            assert!(!label.contains(CANARY), "a value is in a label");
        }
    }
}

fn new_passkey(vault: &mut Vault, title: &str, user_handle: &[u8]) -> u64 {
    vault
        .create_passkey(PasskeyCreate {
            rp_id: RP,
            user_handle,
            user_name: "alice",
            user_display_name: "Alice Example",
            client_data_hash: &HASH,
            algorithms: &[ES256],
            exclude: &[],
            target: PasskeyTarget::NewItem {
                title: title.to_owned(),
            },
        })
        .unwrap()
        .item_id
}

#[test]
fn logins_group_by_host_and_username_across_url_forms() {
    let dir = TempDir::new().unwrap();
    let mut vault = vault(&dir, "hosts.db");
    let a = add(
        &mut vault,
        login(
            "A",
            "Alice",
            "SYNTH-DUP-a",
            &["https://www.Example.com:443/login"],
        ),
    );
    let b = add(
        &mut vault,
        login("B", " alice ", "SYNTH-DUP-b", &["example.com"]),
    );
    let c = add(
        &mut vault,
        login(
            "C",
            "ALICE",
            "SYNTH-DUP-c",
            &["http://example.com:8080/path"],
        ),
    );
    // Another username, another host, and no host.
    add(
        &mut vault,
        login("D", "bob", "SYNTH-DUP-d", &["example.com"]),
    );
    add(
        &mut vault,
        login("E", "alice", "SYNTH-DUP-e", &["other.test"]),
    );
    add(&mut vault, login("F", "alice", "SYNTH-DUP-f", &[]));
    add(&mut vault, login("G", "alice", "SYNTH-DUP-g", &[]));
    assert_eq!(ids(&vault), [vec![a, b, c]]);
    let groups = vault.duplicate_groups().unwrap();
    assert_eq!(
        groups[0].differences,
        ["Username", "Password", "Website", "Title"]
    );
    assert!(!groups[0].identical);
    assert!(groups[0].mergeable && groups[0].reason.is_none());
    assert_no_value(&groups);
}

#[test]
fn identical_secrets_group_within_a_kind_and_never_without_a_value() {
    let dir = TempDir::new().unwrap();
    let mut vault = vault(&dir, "secrets.db");
    let k1 = add(&mut vault, api_key("Stripe", "SYNTH-DUP-token"));
    let k2 = add(&mut vault, api_key("Stripe live", "SYNTH-DUP-token"));
    let c1 = add(&mut vault, custom("Recovery", "secret", "SYNTH-DUP-token"));
    let c2 = add(
        &mut vault,
        custom("Recovery copy", "secret", "SYNTH-DUP-token"),
    );
    // No secret value: never a group.
    add(&mut vault, custom("Empty", "secret", ""));
    add(&mut vault, custom("Empty too", "secret", ""));
    // Another value.
    add(&mut vault, api_key("Other", "SYNTH-DUP-other"));
    assert_eq!(ids(&vault), [vec![k1, k2], vec![c1, c2]]);
    let groups = vault.duplicate_groups().unwrap();
    for group in &groups {
        assert_eq!(group.differences, ["Title"]);
        assert!(group.identical && group.mergeable);
    }
    assert_eq!(groups[0].items[0].kind, CredentialKind::ApiKey);
    assert_eq!(groups[1].items[0].kind, CredentialKind::Custom);
    assert_no_value(&groups);
}

#[test]
fn differences_name_labels_and_never_values() {
    let dir = TempDir::new().unwrap();
    let mut vault = vault(&dir, "differences.db");
    let mut first = api_key("Stripe", "SYNTH-DUP-token");
    first
        .fields
        .push(field(&detail("Org ID"), "SYNTH-DUP-org-one", true));
    first.notes = "First note".to_owned();
    first.tags = vec!["billing".to_owned()];
    let mut second = api_key("Stripe import", "SYNTH-DUP-token");
    second
        .fields
        .push(field(&detail("Org ID"), "SYNTH-DUP-org-two", true));
    second.notes = "Second note".to_owned();
    second.tags = vec!["1password".to_owned()];
    add(&mut vault, first);
    add(&mut vault, second);
    let groups = vault.duplicate_groups().unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].differences, ["Org ID", "Notes", "Tags", "Title"]);
    assert!(!groups[0].identical);
    assert_no_value(&groups);
}

#[test]
fn the_suggestion_prefers_agent_use_then_the_newest_then_the_lowest_id() {
    let dir = TempDir::new().unwrap();
    let mut vault = vault(&dir, "keep.db");
    // Agent use wins over the ID and the time.
    let used_low = add(&mut vault, api_key("Used A", "SYNTH-DUP-used"));
    let used_high = add(&mut vault, api_key("Used B", "SYNTH-DUP-used"));
    vault
        .set_env_binding(used_high, "SYNTH_DUP_USED", "token")
        .unwrap();
    assert_eq!(group_of(&vault, used_low).keep, used_high);

    // On the same clock second, the lowest ID; else the newest change.
    let old = add(&mut vault, api_key("Old", "SYNTH-DUP-time"));
    let new = add(&mut vault, api_key("New", "SYNTH-DUP-time"));
    let group = group_of(&vault, old);
    if group.items[0].changed_at == group.items[1].changed_at {
        assert_eq!(group.keep, old);
    }
    std::thread::sleep(std::time::Duration::from_millis(1100));
    vault
        .update(
            old,
            revision(&vault, old),
            api_key("Old renamed", "SYNTH-DUP-time"),
        )
        .unwrap();
    let group = group_of(&vault, new);
    assert_eq!(group.keep, old);
    assert!(group.items[0].changed_at > group.items[1].changed_at);
}

#[test]
fn a_merge_adds_missing_fields_previous_values_notes_and_tags() {
    let dir = TempDir::new().unwrap();
    let mut vault = vault(&dir, "merge.db");
    let mut kept = login("GitHub", "octo", "SYNTH-DUP-pw-1", &["https://github.com/"]);
    kept.notes = "Work account".to_owned();
    kept.tags = vec!["work".to_owned()];
    let kept = add(&mut vault, kept);
    let mut import = login(
        "GitHub import",
        "octo",
        "SYNTH-DUP-pw-2",
        &["github.com", "https://gist.github.com"],
    );
    import
        .fields
        .push(field(&detail("Recovery code"), "SYNTH-DUP-recovery", true));
    import.notes = "Imported".to_owned();
    import.tags = vec!["1password".to_owned(), "work".to_owned()];
    let import = add(&mut vault, import);
    let old = add(
        &mut vault,
        login("GitHub old", "octo", "SYNTH-DUP-pw-2", &["github.com"]),
    );
    assert_eq!(ids(&vault), [vec![kept, import, old]]);

    let outcome = merge(&mut vault, kept, &[import, old]).unwrap();
    assert_eq!(outcome.id, kept);
    assert_eq!(outcome.archived, [import, old]);
    assert_eq!(outcome.revision, 2);
    let details = vault.details(kept).unwrap();
    assert_eq!(details.summary.title, "GitHub");
    assert_eq!(details.notes, "Work account\n\nImported");
    assert_eq!(details.tags, ["work", "1password"]);
    assert!(value(&vault, kept, "password") == "SYNTH-DUP-pw-1");
    // The other password once, hidden, as "Previous password".
    let previous = detail("Previous password");
    assert!(names(&vault, kept).contains(&(previous.clone(), true)));
    assert!(value(&vault, kept, &previous) == "SYNTH-DUP-pw-2");
    assert!(
        !names(&vault, kept)
            .iter()
            .any(|(name, _)| *name == detail("Previous password 2"))
    );
    // The missing detail, hidden as it was.
    let recovery = detail("Recovery code");
    assert!(names(&vault, kept).contains(&(recovery.clone(), true)));
    assert!(value(&vault, kept, &recovery) == "SYNTH-DUP-recovery");
    // One website for github.com, and the new one.
    assert!(value(&vault, kept, &detail("Website")) == "https://github.com/");
    assert!(value(&vault, kept, &detail("Website 2")) == "https://gist.github.com");
    assert!(
        !names(&vault, kept)
            .iter()
            .any(|(name, _)| *name == detail("Website 3"))
    );
    // The others are archived, not deleted, and keep their values.
    for id in [import, old] {
        assert!(vault.is_archived(id).unwrap());
        assert!(value(&vault, id, "password") == "SYNTH-DUP-pw-2");
    }
    assert!(!vault.is_archived(kept).unwrap());

    // History: names only.
    let events = vault.item_events(kept, 10).unwrap();
    assert_eq!(events[0].kind, ItemEventKind::Edited);
    assert_eq!(merged_count(&events[0].detail), Some(2));
    for id in [import, old] {
        let events = vault.item_events(id, 10).unwrap();
        assert_eq!(events[0].kind, ItemEventKind::Archived);
        assert_eq!(events[0].detail, MERGED_INTO_DETAIL);
    }
    for id in [kept, import, old] {
        for event in vault.item_events(id, 50).unwrap() {
            assert!(!event.detail.contains(CANARY), "a value is in the history");
        }
    }
    // No group is left.
    assert!(vault.duplicate_groups().unwrap().is_empty());
}

#[test]
fn a_merge_over_a_limit_changes_nothing() {
    let dir = TempDir::new().unwrap();
    let mut vault = vault(&dir, "limits.db");
    let mut first = api_key("Tagged", "SYNTH-DUP-limit");
    first.tags = (0..30).map(|n| format!("t{n}")).collect();
    let first = add(&mut vault, first);
    let mut second = api_key("Tagged too", "SYNTH-DUP-limit");
    second.tags = (0..3).map(|n| format!("u{n}")).collect();
    let second = add(&mut vault, second);
    let group = group_of(&vault, first);
    assert!(!group.mergeable);
    assert_eq!(group.reason.as_deref(), Some("Too many fields"));
    assert!(group.keep_choices.is_empty());
    assert_eq!(
        vault.merge_refusal(first, &[second]).unwrap(),
        Some(MergeRefusal::TooManyFields)
    );
    let before = vault.details(first).unwrap();
    let events = vault.item_events(first, 50).unwrap().len();
    assert_eq!(
        merge(&mut vault, first, &[second]).unwrap_err().kind(),
        VaultErrorKind::InvalidInput
    );
    assert!(vault.details(first).unwrap() == before);
    assert_eq!(vault.item_events(first, 50).unwrap().len(), events);
    assert!(!vault.is_archived(second).unwrap());
    assert_no_value(&[group]);
}

#[test]
fn a_stale_revision_is_a_conflict_and_bad_requests_are_refused() {
    let dir = TempDir::new().unwrap();
    let mut vault = vault(&dir, "conflict.db");
    let first = add(&mut vault, api_key("One", "SYNTH-DUP-stale"));
    let second = add(&mut vault, api_key("Two", "SYNTH-DUP-stale"));
    let other = add(&mut vault, api_key("Other", "SYNTH-DUP-alone"));
    let stale = revision(&vault, second);
    vault
        .update(second, stale, api_key("Two renamed", "SYNTH-DUP-stale"))
        .unwrap();
    let kind = |result: VaultResult<MergeOutcome>| result.unwrap_err().kind();
    assert_eq!(
        kind(vault.merge_duplicates((first, 1), &[(second, stale)])),
        VaultErrorKind::Conflict
    );
    assert_eq!(
        kind(vault.merge_duplicates((first, 2), &[(second, stale + 1)])),
        VaultErrorKind::Conflict
    );
    assert_eq!(
        kind(vault.merge_duplicates((first, 1), &[])),
        VaultErrorKind::InvalidInput
    );
    assert_eq!(
        kind(vault.merge_duplicates((first, 1), &[(first, 1)])),
        VaultErrorKind::InvalidInput
    );
    assert_eq!(
        kind(vault.merge_duplicates((first, 1), &[(other, 1)])),
        VaultErrorKind::InvalidInput
    );
    assert_eq!(
        kind(vault.merge_duplicates((first, 1), &[(9_999, 1)])),
        VaultErrorKind::NotFound
    );
    assert!(!vault.is_archived(second).unwrap());
    assert_eq!(revision(&vault, first), 1);
    merge(&mut vault, first, &[second]).unwrap();
    assert!(vault.is_archived(second).unwrap());
}

#[test]
fn archived_items_leave_the_groups() {
    let dir = TempDir::new().unwrap();
    let mut vault = vault(&dir, "archive.db");
    let first = add(&mut vault, api_key("One", "SYNTH-DUP-archive"));
    let second = add(&mut vault, api_key("Two", "SYNTH-DUP-archive"));
    assert_eq!(ids(&vault), [vec![first, second]]);
    vault.set_archived(second, true).unwrap();
    assert!(ids(&vault).is_empty());
    assert_eq!(
        merge(&mut vault, first, &[second]).unwrap_err().kind(),
        VaultErrorKind::InvalidInput
    );
}

#[test]
fn a_variable_moves_only_alone_and_with_the_same_value() {
    let dir = TempDir::new().unwrap();
    let mut vault = vault(&dir, "agents.db");
    let kept = add(&mut vault, api_key("Kept", "SYNTH-DUP-bound"));
    let bound = add(&mut vault, api_key("Bound", "SYNTH-DUP-bound"));
    vault
        .set_env_binding(bound, "SYNTH_DUP_KEY", "token")
        .unwrap();
    vault.set_always_ask(bound, true).unwrap();
    assert_eq!(vault.merge_refusal(kept, &[bound]).unwrap(), None);
    merge(&mut vault, kept, &[bound]).unwrap();
    let binding = vault.env_binding(kept).unwrap().expect("moved");
    assert_eq!(binding.env_name, "SYNTH_DUP_KEY");
    assert_eq!(binding.field, "token");
    assert!(vault.env_binding(bound).unwrap().is_none());
    // "Always ask me" of the other item applies to the kept item.
    assert!(vault.always_ask(kept).unwrap());

    // Two items with a variable: the merge would drop one.
    let one = add(&mut vault, api_key("One", "SYNTH-DUP-two-vars"));
    let two = add(&mut vault, api_key("Two", "SYNTH-DUP-two-vars"));
    vault
        .set_env_binding(one, "SYNTH_DUP_ONE", "token")
        .unwrap();
    vault
        .set_env_binding(two, "SYNTH_DUP_TWO", "token")
        .unwrap();
    let group = group_of(&vault, one);
    assert!(!group.mergeable);
    assert_eq!(group.reason.as_deref(), Some("Used by agents"));
    assert_eq!(
        vault.merge_refusal(one, &[two]).unwrap(),
        Some(MergeRefusal::UsedByAgents)
    );
    assert_eq!(
        merge(&mut vault, one, &[two]).unwrap_err().kind(),
        VaultErrorKind::InvalidInput
    );
    assert!(!vault.is_archived(two).unwrap());
}

#[test]
fn a_passkey_rp_id_is_a_host_and_only_its_item_can_be_kept() {
    let dir = TempDir::new().unwrap();
    let mut vault = vault(&dir, "passkey.db");
    let password = add(
        &mut vault,
        login(
            "Site",
            "alice",
            "SYNTH-DUP-site",
            &["https://www.example.com"],
        ),
    );
    let passkey = new_passkey(&mut vault, "Site passkey", b"synthetic-user-1");
    assert_eq!(ids(&vault), [vec![password, passkey]]);
    let group = group_of(&vault, password);
    assert_eq!(group.keep, passkey);
    assert_eq!(group.keep_choices, [passkey]);
    assert!(group.items[1].has_passkey && !group.items[0].has_passkey);
    assert_eq!(
        vault.merge_refusal(password, &[passkey]).unwrap(),
        Some(MergeRefusal::KeepPasskey)
    );
    assert_eq!(
        merge(&mut vault, password, &[passkey]).unwrap_err().kind(),
        VaultErrorKind::InvalidInput
    );

    merge(&mut vault, passkey, &[password]).unwrap();
    assert!(vault.is_archived(password).unwrap());
    // The passkey stays, and the login gets the password and the website.
    assert_eq!(vault.passkey_info(passkey).unwrap().rp_id, RP);
    let canonical: Vec<u64> = vault
        .all_passkeys()
        .unwrap()
        .iter()
        .map(|info| info.item_id)
        .collect();
    assert_eq!(canonical, [passkey]);
    assert!(value(&vault, passkey, "password") == "SYNTH-DUP-site");
    assert!(value(&vault, passkey, &detail("Website")) == "https://www.example.com");
    assert!(
        !names(&vault, passkey)
            .iter()
            .any(|(name, _)| name.starts_with("passkey_"))
    );
}

#[test]
fn two_different_passkeys_never_merge() {
    let dir = TempDir::new().unwrap();
    let mut vault = vault(&dir, "two-passkeys.db");
    let one = new_passkey(&mut vault, "One", b"synthetic-user-1");
    let two = new_passkey(&mut vault, "Two", b"synthetic-user-2");
    let group = group_of(&vault, one);
    assert_eq!(
        group.items.iter().map(|item| item.id).collect::<Vec<_>>(),
        [one, two]
    );
    assert!(!group.mergeable);
    assert_eq!(group.reason.as_deref(), Some("Two different passkeys"));
    assert!(group.keep_choices.is_empty());
    assert_eq!(
        vault.merge_refusal(one, &[two]).unwrap(),
        Some(MergeRefusal::TwoPasskeys)
    );
    assert_eq!(
        merge(&mut vault, one, &[two]).unwrap_err().kind(),
        VaultErrorKind::InvalidInput
    );
    assert!(!vault.is_archived(two).unwrap());
}

/// Push `from` and merge it into `into`: the count of conflicts.
fn sync(into: &mut Vault, from: &mut Vault, path: &Path, device: &str) -> usize {
    from.write_sync_copy(path, device).unwrap();
    into.merge_from(path, &SyncScope::vault())
        .unwrap()
        .conflicts
        .len()
}

#[test]
fn a_restored_conflict_copy_with_the_same_passkey_merges_into_the_original() {
    let dir = TempDir::new().unwrap();
    let mut a = vault(&dir, "a.db");
    let original = add(&mut a, login("Site", "alice", "SYNTH-DUP-start", &[]));
    let revision_a = revision(&a, original);
    a.create_passkey(PasskeyCreate {
        rp_id: RP,
        user_handle: b"synthetic-user-1",
        user_name: "alice",
        user_display_name: "Alice Example",
        client_data_hash: &HASH,
        algorithms: &[ES256],
        exclude: &[],
        target: PasskeyTarget::Attach {
            item_id: original,
            revision: revision_a,
        },
    })
    .unwrap();
    let seed = dir.path().join("seed.copy");
    a.write_sync_copy(&seed, "Mac A").unwrap();
    let (mut b, _) = Vault::adopt_sync_copy(&seed, &dir.path().join("b.db"), PASS).unwrap();
    b.unlock(PASS).unwrap();
    let on_b = b.search("Site").unwrap()[0].id;

    // Both Macs change the password; B is later and wins on A.
    a.update(
        original,
        revision(&a, original),
        login("Site", "alice", "SYNTH-DUP-from-a", &[]),
    )
    .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(20));
    b.update(
        on_b,
        revision(&b, on_b),
        login("Site", "alice", "SYNTH-DUP-from-b", &[]),
    )
    .unwrap();
    assert_eq!(sync(&mut a, &mut b, &dir.path().join("b.copy"), "Mac B"), 1);
    let copies = a.conflict_copies().unwrap();
    let (&copy, _) = copies.first_key_value().expect("copy");
    assert!(a.is_archived(copy).unwrap());
    // The archived copy is in no group.
    assert!(ids(&a).is_empty());

    // The owner restores the copy: it holds the same passkey, and the original keeps it.
    a.set_archived(copy, false).unwrap();
    assert_eq!(
        a.passkey_info(copy).unwrap().credential_id,
        a.passkey_info(original).unwrap().credential_id
    );
    let group = group_of(&a, original);
    assert_eq!(group.keep, original);
    assert!(group.mergeable);
    assert_eq!(group.keep_choices, [original]);
    assert_eq!(
        a.merge_refusal(copy, &[original]).unwrap(),
        Some(MergeRefusal::KeepPasskey)
    );
    merge(&mut a, original, &[copy]).unwrap();
    assert!(a.is_archived(copy).unwrap());
    assert!(value(&a, original, "password") == "SYNTH-DUP-from-b");
    assert!(value(&a, original, &detail("Previous password")) == "SYNTH-DUP-from-a");
    let canonical: Vec<u64> = a
        .all_passkeys()
        .unwrap()
        .iter()
        .map(|info| info.item_id)
        .collect();
    assert_eq!(canonical, [original]);
    assert!(ids(&a).is_empty());
}
