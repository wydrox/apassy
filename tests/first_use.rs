#![cfg(feature = "vault")]

//! Access at first use (ADR 0024). Synthetic values only.

mod common;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use apassy::agent::client;
use apassy::agent::wire::{Action, WireResponse};
use apassy::broker::approvals::{
    ApprovalQueue, ApprovalRefusal, FirstUseDeclaration, FirstUseOffer, OwnerAction,
    OwnerAuthError, OwnerCheck, OwnerGate, PendingRun,
};
use apassy::broker::bouncer::BouncerClient;
use apassy::broker::http::TlsClient;
use apassy::broker::{self, BrokerHandle, BrokerOptions, SharedVault};
use apassy::contracts::CredentialKind;
use apassy::vault::{
    Declaration, Environment, ExecMode, Field, GrantPlace, ItemDraft, Reversibility, RiskLevel,
    Scope, SecretValue, Vault,
};
use tempfile::TempDir;

const PASS: &str = "first-use-pass-ok";
const SECRET: &str = "FAKE-first-use-secret-3307-canary";

struct Fixture {
    _dir: TempDir,
    vault: SharedVault,
    socket: PathBuf,
    /// A project with `.git`. Runs start in its `sub` folder.
    project: PathBuf,
    item_id: u64,
    agent_id: u64,
    token: String,
    broker: BrokerHandle,
    bouncer: common::FakeBouncer,
}

/// An agent without grants. `see_all`: the agent sees all credentials (ADR 0012).
fn fixture(see_all: bool) -> Fixture {
    let bouncer = common::fake_bouncer(&[]);
    let dir = TempDir::new().expect("temp dir");
    let project = dir.path().join("project");
    std::fs::create_dir_all(project.join("sub")).expect("project dir");
    std::fs::create_dir_all(project.join(".git")).expect("git dir");
    // A project script that uses the key and does not print it.
    let script = project.join("sub").join("deploy.sh");
    std::fs::write(&script, "#!/bin/sh\necho deployed\n").expect("script");
    std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755))
        .expect("chmod");
    let project = std::fs::canonicalize(project).expect("canonical project");
    let mut vault = Vault::create(&dir.path().join("vault.db"), PASS).expect("create");
    vault.unlock(PASS).expect("unlock");
    let item = vault
        .add(ItemDraft {
            title: "Synthetic deploy key".to_owned(),
            kind: CredentialKind::ApiKey,
            notes: String::new(),
            tags: Vec::new(),
            fields: vec![Field {
                name: "token".to_owned(),
                value: SecretValue::new(SECRET.to_owned()),
                secret: true,
            }],
        })
        .expect("add");
    let (agent, token) = vault.register_agent("First use agent").expect("register");
    if see_all {
        vault.set_agent_sees_all(agent.id, true).expect("see all");
    }
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
        item_id: item.id,
        agent_id: agent.id,
        token: token.expose().to_owned(),
        broker,
        bouncer,
    }
}

fn run_in(fx: &Fixture, cwd: &Path) -> WireResponse {
    client::send(
        &fx.socket,
        &fx.token,
        Action::Run {
            items: vec![fx.item_id],
            command: vec![
                "/bin/sh".into(),
                "-c".into(),
                format!("printf 'key=%s' \"$APASSY_ITEM_{}\"", fx.item_id),
            ],
            cwd: cwd.display().to_string(),
            purpose: "Deploy the synthetic project.".into(),
            path: Some("/usr/bin:/bin".into()),
            user_request: Some("Deploy the synthetic project.".into()),
        },
    )
    .expect("broker answer")
}

/// A run in the `sub` folder of the project, on another thread.
fn run_later(fx: &Fixture) -> std::thread::JoinHandle<WireResponse> {
    let socket = fx.socket.clone();
    let token = fx.token.clone();
    let item_id = fx.item_id;
    let cwd = fx.project.join("sub").display().to_string();
    std::thread::spawn(move || {
        client::send(
            &socket,
            &token,
            Action::Run {
                items: vec![item_id],
                command: vec![
                    "/bin/sh".into(),
                    "-c".into(),
                    format!("printf 'key=%s' \"$APASSY_ITEM_{item_id}\""),
                ],
                cwd,
                purpose: "Deploy the synthetic project.".into(),
                path: Some("/usr/bin:/bin".into()),
                user_request: Some("Deploy the synthetic project.".into()),
            },
        )
        .expect("broker answer")
    })
}

fn code(response: &WireResponse) -> &str {
    assert!(!response.ok, "expected a refusal: {response:?}");
    response.error.as_ref().map_or("", |e| e.code.as_str())
}

fn with_vault<T>(fx: &Fixture, f: impl FnOnce(&mut Vault) -> T) -> T {
    let mut guard = fx.vault.lock().expect("vault mutex");
    f(guard.as_mut().expect("open vault"))
}

fn waiting(approvals: &ApprovalQueue) -> (PendingRun, FirstUseOffer) {
    loop {
        if let Some(run) = approvals.pending().into_iter().next() {
            let offer = approvals.first_use(run.id).expect("a first-use offer");
            return (run, offer);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn declaration(environment: Environment) -> Declaration {
    Declaration {
        project: "project".to_owned(),
        environment,
        risk: RiskLevel::Medium,
        scope: Scope::ReadWrite,
        reversibility: Reversibility::Reversible,
    }
}

fn allow_in_folder(fx: &Fixture, run: PendingRun, offer: FirstUseOffer, environment: Environment) {
    let declarations = vec![FirstUseDeclaration {
        item_id: fx.item_id,
        declaration: declaration(environment),
        provider: None,
        suggested: None,
    }];
    let proof = OwnerGate::new(Arc::clone(&fx.vault), None)
        .authorize(
            OwnerAction::ApproveAndGrant {
                run,
                offer,
                declarations,
            },
            OwnerCheck::passphrase(PASS),
        )
        .expect("owner check");
    fx.broker.approvals().approve(proof).expect("approved");
}

fn stdout(response: &WireResponse) -> String {
    let data = response.result.as_ref().expect("result");
    data["stdout"].as_str().unwrap_or_default().to_owned()
}

#[test]
fn an_agent_that_does_not_see_all_credentials_still_gets_not_granted() {
    let fx = fixture(false);
    let response = run_in(&fx, &fx.project);
    assert_eq!(code(&response), "not_granted");
    assert!(fx.broker.approvals().pending().is_empty());
}

#[test]
fn a_first_use_waits_for_the_owner_without_the_model_and_a_denial_saves_nothing() {
    let fx = fixture(true);
    let handle = run_later(&fx);
    let (run, offer) = waiting(fx.broker.approvals());
    // The offer names the project root (it has .git), not the sub folder of the run.
    assert_eq!(offer.folder, fx.project.display().to_string());
    assert_eq!(offer.agent_id, fx.agent_id);
    assert_eq!(offer.items.len(), 1);
    assert_eq!(offer.items[0].item_id, fx.item_id);
    assert!(offer.items[0].declaration.is_none());
    assert!(run.risk.starts_with("First use"), "{}", run.risk);
    assert!(run.remember.is_none());
    assert!(!format!("{run:?} {offer:?}").contains(SECRET));
    // A model never gives new access.
    assert!(fx.bouncer.bodies.lock().expect("bodies").is_empty());
    assert!(fx.broker.approvals().deny(run.id));
    let response = handle.join().expect("run thread");
    assert_eq!(code(&response), "approval_denied");
    with_vault(&fx, |vault| {
        assert!(
            vault
                .exec_grants_for_agent(fx.agent_id)
                .expect("grants")
                .is_empty()
        );
        assert!(
            vault
                .declaration(fx.item_id)
                .expect("declaration")
                .is_none()
        );
    });
}

#[test]
fn allow_once_runs_and_saves_no_access() {
    let fx = fixture(true);
    let handle = run_later(&fx);
    let (run, _) = waiting(fx.broker.approvals());
    let proof = OwnerGate::new(Arc::clone(&fx.vault), None)
        .authorize(OwnerAction::ApproveRun(run), OwnerCheck::passphrase(PASS))
        .expect("owner check");
    fx.broker.approvals().approve(proof).expect("approved");
    let response = handle.join().expect("run thread");
    assert!(response.ok, "{response:?}");
    let out = stdout(&response);
    assert!(!out.contains(SECRET), "{out}");
    assert!(out.contains("[apassy:"), "{out}");
    assert!(
        response
            .result
            .as_ref()
            .expect("result")
            .get("access")
            .is_none()
    );
    with_vault(&fx, |vault| {
        assert!(
            vault
                .exec_grants_for_agent(fx.agent_id)
                .expect("grants")
                .is_empty()
        );
    });
    // The next run is a first use again.
    let handle = run_later(&fx);
    let (run, _) = waiting(fx.broker.approvals());
    assert!(fx.broker.approvals().deny(run.id));
    assert_eq!(code(&handle.join().expect("run thread")), "approval_denied");
}

#[test]
fn allow_in_folder_saves_the_grant_and_declaration_and_later_runs_use_the_bouncer() {
    let fx = fixture(true);
    let handle = run_later(&fx);
    let (run, offer) = waiting(fx.broker.approvals());
    allow_in_folder(&fx, run, offer, Environment::Development);
    let response = handle.join().expect("run thread");
    assert!(response.ok, "{response:?}");
    assert!(!stdout(&response).contains(SECRET));
    let data = response.result.as_ref().expect("result");
    assert!(
        data["access"]
            .as_str()
            .is_some_and(|text| text.contains("gave this agent access")),
        "{data}"
    );
    with_vault(&fx, |vault| {
        let grants = vault.exec_grants_for_agent(fx.agent_id).expect("grants");
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].item_id, fx.item_id);
        assert_eq!(grants[0].mode, ExecMode::Bouncer);
        assert_eq!(
            grants[0].place,
            GrantPlace::Folder(fx.project.display().to_string())
        );
        let saved = vault.declaration(fx.item_id).expect("declaration");
        assert_eq!(saved, Some(declaration(Environment::Development)));
    });
    // The second run has a grant and a declaration: the bouncer decides, no prompt.
    let response = client::send(
        &fx.socket,
        &fx.token,
        Action::Run {
            items: vec![fx.item_id],
            command: vec!["sh".into(), "-c".into(), "./deploy.sh".into()],
            cwd: fx.project.join("sub").display().to_string(),
            purpose: "Deploy the synthetic project.".into(),
            path: Some("/usr/bin:/bin".into()),
            user_request: Some("Deploy the synthetic project.".into()),
        },
    )
    .expect("broker answer");
    assert!(response.ok, "{response:?}");
    assert_eq!(
        response.result.as_ref().expect("result")["decided_by"],
        "Bouncer allowed"
    );
    assert!(!fx.bouncer.bodies.lock().expect("bodies").is_empty());
    assert!(fx.broker.approvals().pending().is_empty());
}

#[test]
fn a_production_declaration_still_asks_at_each_later_run() {
    let fx = fixture(true);
    let handle = run_later(&fx);
    let (run, offer) = waiting(fx.broker.approvals());
    allow_in_folder(&fx, run, offer, Environment::Production);
    assert!(handle.join().expect("run thread").ok);
    // ADR 0010: production waits for the owner, also with a grant.
    let handle = run_later(&fx);
    let run = loop {
        if let Some(run) = fx.broker.approvals().pending().into_iter().next() {
            break run;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    assert!(fx.broker.approvals().first_use(run.id).is_none());
    assert!(fx.broker.approvals().deny(run.id));
    assert_eq!(code(&handle.join().expect("run thread")), "approval_denied");
}

#[test]
fn allow_in_folder_needs_one_declaration_for_each_new_credential() {
    let fx = fixture(true);
    let handle = run_later(&fx);
    let (run, offer) = waiting(fx.broker.approvals());
    let proof = OwnerGate::new(Arc::clone(&fx.vault), None)
        .authorize(
            OwnerAction::ApproveAndGrant {
                run: run.clone(),
                offer,
                declarations: Vec::new(),
            },
            OwnerCheck::passphrase(PASS),
        )
        .expect("owner check");
    assert_eq!(
        fx.broker.approvals().approve(proof),
        Err(ApprovalRefusal::DeclarationsDoNotMatch)
    );
    // The run still waits.
    assert!(fx.broker.approvals().deny(run.id));
    assert_eq!(code(&handle.join().expect("run thread")), "approval_denied");
    with_vault(&fx, |vault| {
        assert!(
            vault
                .exec_grants_for_agent(fx.agent_id)
                .expect("grants")
                .is_empty()
        );
    });
}

#[test]
fn an_agent_has_at_most_one_waiting_first_use() {
    let fx = fixture(true);
    let handle = run_later(&fx);
    let (run, _) = waiting(fx.broker.approvals());
    let second = run_in(&fx, &fx.project);
    assert_eq!(code(&second), "first_use_waiting");
    assert_eq!(fx.broker.approvals().pending().len(), 1);
    assert!(fx.broker.approvals().deny(run.id));
    assert_eq!(code(&handle.join().expect("run thread")), "approval_denied");
}

#[test]
fn a_change_while_the_first_use_waits_saves_no_access() {
    let fx = fixture(true);
    let handle = run_later(&fx);
    let (run, offer) = waiting(fx.broker.approvals());
    let declarations = vec![FirstUseDeclaration {
        item_id: fx.item_id,
        declaration: declaration(Environment::Development),
        provider: None,
        suggested: None,
    }];
    let proof = OwnerGate::new(Arc::clone(&fx.vault), None)
        .authorize(
            OwnerAction::ApproveAndGrant {
                run,
                offer,
                declarations,
            },
            OwnerCheck::passphrase(PASS),
        )
        .expect("owner check");
    // The owner archives the item after the check and before the approval.
    with_vault(&fx, |vault| {
        vault.set_archived(fx.item_id, true).expect("archive")
    });
    fx.broker.approvals().approve(proof).expect("approved");
    assert_eq!(code(&handle.join().expect("run thread")), "item_archived");
    with_vault(&fx, |vault| {
        assert!(
            vault
                .exec_grants_for_agent(fx.agent_id)
                .expect("grants")
                .is_empty()
        );
        assert!(
            vault
                .declaration(fx.item_id)
                .expect("declaration")
                .is_none()
        );
    });
}

#[test]
fn a_phone_cannot_give_access_at_first_use() {
    let fx = fixture(true);
    let handle = run_later(&fx);
    let (run, offer) = waiting(fx.broker.approvals());
    let refused = OwnerGate::new(Arc::clone(&fx.vault), None).authorize(
        OwnerAction::ApproveAndGrant {
            run: run.clone(),
            offer,
            declarations: Vec::new(),
        },
        OwnerCheck::Companion {
            device_id: "synthetic-phone".to_owned(),
            time: 0,
            signature: vec![0; 8],
        },
    );
    assert!(matches!(refused, Err(OwnerAuthError::CompanionUnsupported)));
    assert!(fx.broker.approvals().deny(run.id));
    assert_eq!(code(&handle.join().expect("run thread")), "approval_denied");
}

#[test]
fn the_catalog_names_the_variable_of_each_usable_credential() {
    let fx = fixture(true);
    let response = client::send(&fx.socket, &fx.token, Action::ListAccess).expect("answer");
    assert!(response.ok, "{response:?}");
    let data = response.result.expect("result");
    let entry = &data["catalog"][0];
    assert_eq!(entry["access"], "can_request");
    assert_eq!(entry["env_name"], format!("APASSY_ITEM_{}", fx.item_id));
    assert!(!data.to_string().contains(SECRET));
}
