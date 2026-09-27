#![cfg(feature = "vault")]

//! Schema 10: the change history of an item, the archive, and the request log of each
//! item. Synthetic values only.

use apassy::contracts::CredentialKind;
use apassy::vault::{
    ActivityDecision, Declaration, EditChange, Environment, Field, ItemDraft, ItemEventKind,
    MAX_ACTIVITY_ROWS, NewActivity, Reversibility, RiskLevel, Scope, SecretValue, Vault,
};
use tempfile::TempDir;

const PASS: &str = "item-history-pass-ok";
const SECRET_1: &str = "FAKE-history-secret-one-canary";
const SECRET_2: &str = "FAKE-history-secret-two-canary";

fn draft(title: &str, username: &str, token: &str) -> ItemDraft {
    ItemDraft {
        title: title.to_owned(),
        kind: CredentialKind::ApiKey,
        notes: String::new(),
        tags: Vec::new(),
        fields: vec![
            Field {
                name: "username".to_owned(),
                value: SecretValue::new(username.to_owned()),
                secret: false,
            },
            Field {
                name: "token".to_owned(),
                value: SecretValue::new(token.to_owned()),
                secret: true,
            },
        ],
    }
}

fn vault(dir: &TempDir) -> Vault {
    let mut vault = Vault::create(&dir.path().join("history.db"), PASS).expect("create");
    vault.unlock(PASS).expect("unlock");
    vault
}

fn kinds(vault: &Vault, item: u64) -> Vec<ItemEventKind> {
    vault
        .item_events(item, 50)
        .expect("history")
        .iter()
        .map(|event| event.kind)
        .collect()
}

#[test]
fn the_history_names_each_change_and_never_a_value() {
    let dir = TempDir::new().expect("temp dir");
    let mut vault = vault(&dir);
    let item = vault
        .add(draft("History key", "alice", SECRET_1))
        .expect("add");
    assert_eq!(kinds(&vault, item.id), vec![ItemEventKind::Created]);

    // Same values: the update records nothing.
    let same = vault
        .update(item.id, 1, draft("History key", "alice", SECRET_1))
        .expect("same");
    assert_eq!(kinds(&vault, item.id).len(), 1);
    // A new name, a new username, and a new secret.
    let updated = vault
        .update(
            item.id,
            same.revision,
            draft("Renamed key", "bob", SECRET_2),
        )
        .expect("update");
    let events = vault.item_events(item.id, 50).expect("history");
    assert_eq!(events[0].kind, ItemEventKind::Edited);
    assert_eq!(
        EditChange::parse_detail(&events[0].detail),
        vec![
            EditChange::Title,
            EditChange::Field("username".to_owned()),
            EditChange::Secret("token".to_owned()),
        ]
    );

    vault
        .set_env_binding(item.id, "HISTORY_KEY", "token")
        .expect("binding");
    vault
        .set_declaration(
            item.id,
            &Declaration {
                project: "history".to_owned(),
                environment: Environment::Staging,
                risk: RiskLevel::Medium,
                scope: Scope::ReadOnly,
                reversibility: Reversibility::Reversible,
            },
        )
        .expect("declaration");
    vault.record_reveal(item.id).expect("reveal");
    vault.clear_env_binding(item.id).expect("clear");
    // A second clear changes nothing and records nothing.
    vault.clear_env_binding(item.id).expect("clear again");
    assert_eq!(
        kinds(&vault, item.id),
        vec![
            ItemEventKind::VariableRemoved,
            ItemEventKind::Revealed,
            ItemEventKind::Declaration,
            ItemEventKind::Variable,
            ItemEventKind::Edited,
            ItemEventKind::Created,
        ]
    );
    let events = vault.item_events(item.id, 50).expect("history");
    assert_eq!(
        events[2].detail,
        "staging, medium risk, read-only, reversible"
    );
    assert_eq!(events[3].detail, "HISTORY_KEY");
    let text = format!("{events:?}");
    for value in [SECRET_1, SECRET_2, "alice", "bob"] {
        assert!(!text.contains(value), "the history has a value: {text}");
    }

    // A reveal is not a change for the "recently changed" order.
    let times = vault.item_times().expect("times");
    let events = vault.item_events(item.id, 50).expect("history");
    assert_eq!(times[&item.id].changed, Some(events[0].at));
    assert_eq!(times[&item.id].used, None);

    // A delete removes the history.
    vault.delete(item.id, updated.revision).expect("delete");
    assert!(vault.item_events(item.id, 50).expect("history").is_empty());
}

#[test]
fn archive_state_survives_a_backup_and_restore_marks_every_item() {
    let dir = TempDir::new().expect("temp dir");
    let mut vault = vault(&dir);
    let kept = vault.add(draft("Kept", "carol", SECRET_1)).expect("add");
    let old = vault.add(draft("Old", "dave", SECRET_2)).expect("add");
    vault.set_archived(old.id, true).expect("archive");
    assert!(vault.is_archived(old.id).expect("state"));
    assert!(!vault.is_archived(kept.id).expect("state"));
    assert_eq!(
        vault
            .archived_items()
            .expect("archived")
            .keys()
            .copied()
            .collect::<Vec<_>>(),
        vec![old.id]
    );
    let backup = dir.path().join("history.backup");
    vault.backup(&backup).expect("backup");
    let mut restored =
        Vault::restore(&backup, &dir.path().join("restored.db"), PASS).expect("restore");
    restored.unlock(PASS).expect("unlock");
    assert!(
        restored.is_archived(old.id).expect("state"),
        "the archive stays"
    );
    for item in [kept.id, old.id] {
        assert_eq!(
            kinds(&restored, item)[0],
            ItemEventKind::Restored,
            "item {item}"
        );
    }
    restored.set_archived(old.id, false).expect("unarchive");
    assert!(!restored.is_archived(old.id).expect("state"));
}

#[test]
fn the_request_log_of_an_item_includes_runs_with_several_items() {
    let dir = TempDir::new().expect("temp dir");
    let mut vault = vault(&dir);
    let first = vault.add(draft("First", "erin", SECRET_1)).expect("add");
    let second = vault.add(draft("Second", "frank", SECRET_2)).expect("add");
    let (agent, _token) = vault.register_agent("Log agent").expect("agent");
    let entry = |decision| NewActivity {
        agent_id: Some(agent.id),
        agent_name: "Log agent".to_owned(),
        item_id: Some(first.id),
        operation: "run true".to_owned(),
        decision,
        reason: "Synthetic.".to_owned(),
    };
    vault
        .record_activity_for_items(&entry(ActivityDecision::Allow), &[second.id])
        .expect("record");
    vault
        .record_activity(&entry(ActivityDecision::Deny))
        .expect("record");
    assert_eq!(vault.item_activity(first.id, 10).expect("log").len(), 2);
    let second_log = vault.item_activity(second.id, 10).expect("log");
    assert_eq!(second_log.len(), 1);
    assert_eq!(second_log[0].decision, ActivityDecision::Allow);
    assert_eq!(vault.agent_activity(agent.id, 10).expect("log").len(), 2);
    assert_eq!(vault.recent_activity(10).expect("recent").len(), 2);
    let times = vault.item_times().expect("times");
    assert!(times[&second.id].used.is_some());

    // The log keeps the last entries of all agents, and the links of the rest go.
    for _ in 0..MAX_ACTIVITY_ROWS {
        vault
            .record_activity(&entry(ActivityDecision::Deny))
            .expect("record");
    }
    assert!(vault.item_activity(second.id, 10).expect("log").is_empty());
    assert_eq!(
        vault
            .item_activity(first.id, 2 * MAX_ACTIVITY_ROWS)
            .expect("log")
            .len(),
        MAX_ACTIVITY_ROWS
    );
}
