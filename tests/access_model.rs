#![cfg(feature = "vault")]

//! ADR 0012: what an agent can see, grants for several items and for any folder, and
//! access requests. Synthetic values only.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use apassy::agent::client;
use apassy::agent::wire::{Action, WireResponse};
use apassy::broker::http::TlsClient;
use apassy::broker::{self, BrokerHandle, BrokerOptions, SharedVault};
use apassy::contracts::CredentialKind;
use apassy::vault::{
    ExecMode, Field, GrantPlace, ItemDraft, ItemEventKind, RequestState, SecretValue, Vault,
    VaultErrorKind,
};
use serde_json::Value;
use tempfile::TempDir;

const PASS: &str = "access-model-pass-ok";
const SECRET: &str = "FAKE-access-model-secret-canary";
const HIDDEN: &str = "FAKE-hidden-detail-canary";
const NOTES: &str = "FAKE-notes-with-a-pasted-key";

struct Fixture {
    _dir: TempDir,
    vault: SharedVault,
    socket: PathBuf,
    token: String,
    agent_id: u64,
    /// With a variable, a username, and two custom details (one hidden).
    bound: u64,
    /// Without a variable.
    plain: u64,
    /// Archived, with a variable.
    archived: u64,
    _broker: BrokerHandle,
}

fn draft(title: &str, fields: Vec<Field>) -> ItemDraft {
    ItemDraft {
        title: title.to_owned(),
        kind: CredentialKind::ApiKey,
        notes: NOTES.to_owned(),
        tags: Vec::new(),
        fields,
    }
}

fn field(name: &str, value: &str, secret: bool) -> Field {
    Field {
        name: name.to_owned(),
        value: SecretValue::new(value.to_owned()),
        secret,
    }
}

/// The field name of a custom detail: `x_` and the label in hexadecimal.
fn detail_name(label: &str) -> String {
    let hex: String = label.bytes().map(|b| format!("{b:02x}")).collect();
    format!("x_{hex}")
}

fn fixture() -> Fixture {
    let dir = TempDir::new().expect("temp dir");
    let mut vault = Vault::create(&dir.path().join("access.db"), PASS).expect("create");
    vault.unlock(PASS).expect("unlock");
    let bound = vault
        .add(draft(
            "Stripe staging",
            vec![
                field("token", SECRET, true),
                field("username", "ops@example.invalid", false),
                field(&detail_name("Region"), "eu-west", false),
                field(&detail_name("Recovery code"), HIDDEN, true),
            ],
        ))
        .expect("add")
        .id;
    vault
        .set_env_binding(bound, "STRIPE_KEY", "token")
        .expect("binding");
    let plain = vault
        .add(draft("Database", vec![field("token", SECRET, true)]))
        .expect("add")
        .id;
    let archived = vault
        .add(draft("Old key", vec![field("token", SECRET, true)]))
        .expect("add")
        .id;
    vault
        .set_env_binding(archived, "OLD_KEY", "token")
        .expect("binding");
    vault.set_archived(archived, true).expect("archive");
    let (agent, token) = vault.register_agent("Finder").expect("register");
    let shared: SharedVault = Arc::new(Mutex::new(Some(vault)));
    let socket = dir.path().join("run").join("broker.sock");
    let broker = broker::start_with(
        Arc::clone(&shared),
        &socket,
        BrokerOptions::with_tls(TlsClient::platform().expect("TLS")),
    )
    .expect("broker");
    Fixture {
        _dir: dir,
        vault: shared,
        socket,
        token: token.expose().to_owned(),
        agent_id: agent.id,
        bound,
        plain,
        archived,
        _broker: broker,
    }
}

fn with_vault<T>(fx: &Fixture, f: impl FnOnce(&mut Vault) -> T) -> T {
    let mut guard = fx.vault.lock().expect("vault");
    f(guard.as_mut().expect("open"))
}

fn send(fx: &Fixture, action: Action) -> WireResponse {
    client::send(&fx.socket, &fx.token, action).expect("broker answer")
}

fn list(fx: &Fixture) -> Value {
    let response = send(fx, Action::ListAccess);
    assert!(response.ok, "{response:?}");
    response.result.expect("result")
}

fn ask(fx: &Fixture, item_id: u64, reason: &str) -> WireResponse {
    send(
        fx,
        Action::RequestAccess {
            item_id,
            reason: reason.to_owned(),
            cwd: Some("/tmp".to_owned()),
        },
    )
}

fn code(response: &WireResponse) -> &str {
    assert!(!response.ok, "expected a refusal: {response:?}");
    response.error.as_ref().map_or("", |e| e.code.as_str())
}

fn no_secret(text: &str) {
    for canary in [SECRET, HIDDEN, NOTES] {
        assert!(!text.contains(canary), "{canary} leaked: {text}");
    }
}

#[test]
fn an_agent_sees_only_what_it_can_use_until_the_owner_lets_it_see_all() {
    let fx = fixture();
    let before = list(&fx);
    assert_eq!(before["sees_all_credentials"], false);
    assert!(before.get("catalog").is_none());
    assert_eq!(code(&ask(&fx, fx.bound, "Deploy the app.")), "not_visible");

    with_vault(&fx, |v| v.set_agent_sees_all(fx.agent_id, true)).expect("see all");
    let after = list(&fx);
    no_secret(&after.to_string());
    let catalog = after["catalog"].as_array().expect("catalog");
    let names: Vec<&str> = catalog
        .iter()
        .filter_map(|entry| entry["item_name"].as_str())
        .collect();
    assert_eq!(
        names,
        vec!["Database", "Stripe staging"],
        "no archived item"
    );
    let stripe = &catalog[1];
    assert_eq!(stripe["kind"], "api_key");
    assert_eq!(stripe["access"], "can_request");
    assert_eq!(stripe["details"]["username"], "ops@example.invalid");
    assert_eq!(stripe["details"]["Region"], "eu-west");
    assert_eq!(
        stripe["details"].as_object().map(serde_json::Map::len),
        Some(2),
        "no secret field and no hidden detail"
    );
    assert_eq!(catalog[0]["access"], "no_variable");
}

#[test]
fn an_access_request_waits_for_the_owner_and_a_grant_answers_it() {
    let fx = fixture();
    with_vault(&fx, |v| v.set_agent_sees_all(fx.agent_id, true)).expect("see all");

    let first = ask(&fx, fx.bound, "The user asked to deploy the staging app.");
    assert!(first.ok, "{first:?}");
    let first = first.result.expect("result");
    assert_eq!(first["new"], true);
    let again = ask(&fx, fx.bound, "Again.").result.expect("result");
    assert_eq!(again["request_id"], first["request_id"]);
    assert_eq!(again["new"], false);
    assert_eq!(code(&ask(&fx, fx.plain, "No variable.")), "invalid_request");
    assert_eq!(code(&ask(&fx, fx.archived, "Archived.")), "not_visible");
    assert_eq!(code(&ask(&fx, fx.bound, " ")), "invalid_request");
    assert_eq!(list(&fx)["catalog"][1]["access"], "requested");

    let open = with_vault(&fx, |v| v.access_requests(true, 10)).expect("requests");
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].agent_name, "Finder");
    assert_eq!(open[0].item_name, "Stripe staging");
    assert_eq!(open[0].cwd, "/tmp");
    assert_eq!(open[0].reason, "The user asked to deploy the staging app.");

    // The grant answers the request.
    with_vault(&fx, |v| {
        v.set_exec_grants(
            fx.agent_id,
            &[fx.bound],
            &GrantPlace::AnyFolder,
            ExecMode::Ask,
        )
    })
    .expect("grant");
    let after = list(&fx);
    assert_eq!(after["catalog"][1]["access"], "can_use");
    assert_eq!(after["process_access"][0]["any_folder"], true);
    assert_eq!(after["process_access"][0]["project_dir"], Value::Null);
    assert_eq!(after["access_requests"][0]["state"], "granted");
    assert_eq!(code(&ask(&fx, fx.bound, "Once more.")), "already_granted");
    let history = with_vault(&fx, |v| v.item_events(fx.bound, 10)).expect("history");
    assert_eq!(history[0].kind, ItemEventKind::AccessGiven);
    assert!(history[0].detail.ends_with("any folder"), "{history:?}");
    assert_eq!(history[1].kind, ItemEventKind::AccessRequested);
    let log = with_vault(&fx, |v| v.recent_activity(10)).expect("activity");
    assert!(log.iter().any(|entry| entry.operation == "request access"));
}

#[test]
fn a_denial_and_turning_see_all_off_close_requests() {
    let fx = fixture();
    let second = with_vault(&fx, |v| {
        v.set_agent_sees_all(fx.agent_id, true).expect("see all");
        let item = v
            .add(draft("Second", vec![field("token", SECRET, true)]))
            .expect("add")
            .id;
        v.set_env_binding(item, "SECOND_KEY", "token")
            .expect("binding");
        item
    });
    let denied = ask(&fx, fx.bound, "First.").result.expect("result")["request_id"]
        .as_u64()
        .expect("id");
    assert!(ask(&fx, second, "Second.").ok);
    with_vault(&fx, |v| v.deny_access_request(denied)).expect("deny");
    assert_eq!(
        with_vault(&fx, |v| v.deny_access_request(denied))
            .unwrap_err()
            .kind(),
        VaultErrorKind::NotFound,
        "a decided request stays decided"
    );
    let history = with_vault(&fx, |v| v.item_events(fx.bound, 5)).expect("history");
    assert_eq!(history[0].kind, ItemEventKind::AccessDenied);

    with_vault(&fx, |v| v.set_agent_sees_all(fx.agent_id, false)).expect("off");
    let states: Vec<RequestState> = with_vault(&fx, |v| v.access_requests(false, 10))
        .expect("requests")
        .iter()
        .map(|request| request.state)
        .collect();
    assert_eq!(states, vec![RequestState::Denied, RequestState::Denied]);
    assert_eq!(code(&ask(&fx, second, "Again.")), "not_visible");

    // A revoke removes the requests of the agent.
    with_vault(&fx, |v| v.revoke_agent(fx.agent_id)).expect("revoke");
    assert!(
        with_vault(&fx, |v| v.access_requests(false, 10))
            .expect("requests")
            .is_empty()
    );
}

#[test]
fn a_grant_for_several_items_changes_all_or_nothing() {
    let fx = fixture();
    let second = with_vault(&fx, |v| {
        let item = v
            .add(draft("Second", vec![field("token", SECRET, true)]))
            .expect("add")
            .id;
        v.set_env_binding(item, "SECOND_KEY", "token")
            .expect("binding");
        item
    });
    // `plain` has no variable, so nothing changes.
    let refused = with_vault(&fx, |v| {
        v.set_exec_grants(
            fx.agent_id,
            &[fx.bound, fx.plain],
            &GrantPlace::AnyFolder,
            ExecMode::Bouncer,
        )
    });
    assert_eq!(refused.unwrap_err().kind(), VaultErrorKind::InvalidInput);
    assert!(
        with_vault(&fx, |v| v.exec_grants_for_agent(fx.agent_id))
            .expect("grants")
            .is_empty()
    );
    for bad in [vec![], vec![fx.bound, fx.bound]] {
        let refused = with_vault(&fx, |v| {
            v.set_exec_grants(fx.agent_id, &bad, &GrantPlace::AnyFolder, ExecMode::Ask)
        });
        assert_eq!(refused.unwrap_err().kind(), VaultErrorKind::InvalidInput);
    }
    with_vault(&fx, |v| {
        v.set_exec_grants(
            fx.agent_id,
            &[fx.bound, second],
            &GrantPlace::Folder("/tmp/project".to_owned()),
            ExecMode::Bouncer,
        )
    })
    .expect("grant both");
    let grants = with_vault(&fx, |v| v.exec_grants_for_agent(fx.agent_id)).expect("grants");
    assert_eq!(grants.len(), 2);
    assert!(grants.iter().all(|grant| grant.place
        == GrantPlace::Folder("/tmp/project".to_owned())
        && grant.mode == ExecMode::Bouncer));
}
