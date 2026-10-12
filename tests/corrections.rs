#![cfg(feature = "vault")]

//! Corrections from the use log (ADR 0025 §5): proposed once, never again after an
//! ignore, and applied through the declaration on accept. Synthetic values only.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use apassy::agent::client;
use apassy::agent::wire::{Action, WireResponse};
use apassy::broker::action_kind::ActionKind;
use apassy::broker::bouncer::BouncerClient;
use apassy::broker::corrections::{self, MIN_ENVIRONMENT_USES, MIN_PROJECT_USES};
use apassy::broker::http::TlsClient;
use apassy::broker::{self, BrokerOptions, SharedVault};
use apassy::contracts::CredentialKind;
use apassy::vault::agent_items::{CorrectionAnswer, CorrectionKind, CorrectionState};
use apassy::vault::detect::{self, Source};
use apassy::vault::usage::{NewItemUse, UseDecidedBy, UseOutcome};
use apassy::vault::{
    Declaration, DeclarationSource, Environment, Field, ItemDraft, Reversibility, RiskLevel, Scope,
    SecretValue, Vault,
};
use tempfile::TempDir;

const PASS: &str = "corrections-pass-ok";

fn fake(prefix: &str, len: usize) -> String {
    format!("{prefix}{}", &"EXAMPLE0".repeat(len / 8 + 1)[..len])
}

fn vault(dir: &TempDir) -> Vault {
    let mut vault = Vault::create(&dir.path().join("vault.db"), PASS).expect("create");
    vault.unlock(PASS).expect("unlock");
    vault
}

/// A pasted value without a signal: production by default (ADR 0025 §4).
fn pasted(vault: &mut Vault, value: &str) -> u64 {
    let found = detect::detect(value);
    vault.add_detected(&found[0], None, None).expect("add").id
}

fn uses(vault: &mut Vault, item: u64, count: usize, project: &str, hosts: &[&str]) {
    for _ in 0..count {
        vault
            .record_item_use(&NewItemUse {
                item_id: item,
                agent_id: None,
                agent_name: "Synthetic agent".to_owned(),
                project_key: if project.is_empty() {
                    String::new()
                } else {
                    format!("/synthetic/{project}/.git")
                },
                project_label: project.to_owned(),
                action: ActionKind::Read,
                command_summary: "run synthetic".to_owned(),
                hosts: hosts.iter().map(|host| (*host).to_owned()).collect(),
                outcome: UseOutcome::Allowed,
                decided_by: UseDecidedBy::Bouncer,
                answered_on: String::new(),
                decision_log_id: None,
            })
            .expect("use");
    }
}

fn development(project: &str) -> Declaration {
    Declaration {
        project: project.to_owned(),
        environment: Environment::Development,
        risk: RiskLevel::Low,
        scope: Scope::ReadWrite,
        reversibility: Reversibility::Reversible,
    }
}

#[test]
fn development_hosts_propose_development_once_and_never_after_an_ignore() {
    let dir = TempDir::new().unwrap();
    let mut vault = vault(&dir);
    let item = pasted(&mut vault, "FAKE-plain-value-0001");
    assert!(vault.declaration(item).unwrap().unwrap().is_production());
    uses(
        &mut vault,
        item,
        MIN_ENVIRONMENT_USES - 1,
        "",
        &["api.sandbox.example.com"],
    );
    assert!(
        corrections::consider(&mut vault, item).is_empty(),
        "too few uses"
    );
    uses(
        &mut vault,
        item,
        1,
        "",
        &["api.sandbox.example.com", "localhost"],
    );
    let proposed = corrections::consider(&mut vault, item);
    assert_eq!(proposed.len(), 1);
    assert!(
        corrections::consider(&mut vault, item).is_empty(),
        "made once"
    );
    let open = vault.corrections(true).unwrap();
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].kind, CorrectionKind::Environment);
    assert_eq!(open[0].proposed, "development");
    assert_eq!(open[0].facts["hosts"][0], "api.sandbox.example.com");
    // Looser: nothing changes before the owner answers.
    assert!(vault.declaration(item).unwrap().unwrap().is_production());
    vault
        .settle_correction(open[0].id, CorrectionAnswer::Ignored)
        .unwrap();
    assert!(vault.declaration(item).unwrap().unwrap().is_production());
    uses(&mut vault, item, 3, "", &["api.sandbox.example.com"]);
    assert!(
        corrections::consider(&mut vault, item).is_empty(),
        "not again"
    );
    assert!(vault.corrections(true).unwrap().is_empty());
    assert_eq!(
        vault.item_corrections(item).unwrap()[0].state,
        CorrectionState::Ignored
    );
    assert!(
        vault
            .settle_correction(open[0].id, CorrectionAnswer::Accepted)
            .is_err(),
        "settled once"
    );
}

#[test]
fn localhost_or_another_host_proposes_nothing_and_accept_sets_the_owner_source() {
    let dir = TempDir::new().unwrap();
    let mut vault = vault(&dir);
    let local = pasted(&mut vault, "FAKE-plain-value-0002");
    uses(&mut vault, local, 5, "", &["localhost:5432"]);
    assert!(
        corrections::consider(&mut vault, local).is_empty(),
        "localhost is no dev"
    );
    let mixed = pasted(&mut vault, "FAKE-plain-value-0003");
    uses(&mut vault, mixed, 4, "", &["api.sandbox.example.com"]);
    uses(&mut vault, mixed, 1, "", &["api.example.com"]);
    assert!(corrections::consider(&mut vault, mixed).is_empty());
    let dev = pasted(&mut vault, "FAKE-plain-value-0004");
    uses(&mut vault, dev, 3, "", &["dev.example.com"]);
    let id = corrections::consider(&mut vault, dev)[0];
    vault
        .settle_correction(id, CorrectionAnswer::Accepted)
        .unwrap();
    assert_eq!(
        vault.declaration(dev).unwrap().unwrap().environment,
        Environment::Development
    );
    assert_eq!(
        vault.declaration_sources(dev).unwrap().environment,
        DeclarationSource::Owner
    );
}

#[test]
fn a_live_value_declared_development_becomes_production_until_the_owner_answers() {
    let dir = TempDir::new().unwrap();
    let mut vault = vault(&dir);
    let live = fake("sk_live_", 24);
    let found = detect::detect(&live);
    assert_eq!(found[0].environment, Environment::Production);
    assert_eq!(found[0].sources.environment, Source::Signal);
    let item = vault
        .add(ItemDraft {
            title: "Synthetic key".to_owned(),
            kind: CredentialKind::ApiKey,
            notes: String::new(),
            tags: Vec::new(),
            fields: vec![Field {
                name: "token".to_owned(),
                value: SecretValue::new(live.clone()),
                secret: true,
            }],
        })
        .unwrap()
        .id;
    vault.set_env_binding(item, "SYNTH_KEY", "token").unwrap();
    vault
        .set_declaration(item, &development("synthetic"))
        .unwrap();
    uses(&mut vault, item, 1, "", &["api.stripe.com"]);
    let proposed = corrections::consider(&mut vault, item);
    assert_eq!(proposed.len(), 1);
    // Stricter at once, with the source "usage".
    assert!(vault.declaration(item).unwrap().unwrap().is_production());
    assert_eq!(
        vault.declaration_sources(item).unwrap().environment,
        DeclarationSource::Usage
    );
    let correction = &vault.corrections(true).unwrap()[0];
    assert_eq!(correction.proposed, "production");
    assert!(!format!("{correction:?}").contains(&live));
    // Ignore: the owner keeps development, and it is not proposed again.
    vault
        .settle_correction(proposed[0], CorrectionAnswer::Ignored)
        .unwrap();
    assert_eq!(
        vault.declaration(item).unwrap().unwrap().environment,
        Environment::Development
    );
    uses(&mut vault, item, 1, "", &["api.stripe.com"]);
    assert!(corrections::consider(&mut vault, item).is_empty());
    assert_eq!(
        vault.declaration(item).unwrap().unwrap().environment,
        Environment::Development
    );
}

#[test]
fn one_project_proposes_the_project_and_accept_declares_it() {
    let dir = TempDir::new().unwrap();
    let mut vault = vault(&dir);
    let item = pasted(&mut vault, "FAKE-plain-value-0005");
    uses(
        &mut vault,
        item,
        MIN_PROJECT_USES - 1,
        "billing",
        &["api.example.com"],
    );
    assert!(corrections::consider(&mut vault, item).is_empty());
    uses(&mut vault, item, 1, "billing", &["api.example.com"]);
    let id = corrections::consider(&mut vault, item)[0];
    let correction = &vault.corrections(true).unwrap()[0];
    assert_eq!(correction.kind, CorrectionKind::Project);
    assert_eq!(correction.proposed, "billing");
    assert_eq!(correction.facts["uses"], MIN_PROJECT_USES);
    vault
        .settle_correction(id, CorrectionAnswer::Accepted)
        .unwrap();
    assert_eq!(vault.declaration(item).unwrap().unwrap().project, "billing");
    // Two projects: nothing.
    let shared = pasted(&mut vault, "FAKE-plain-value-0006");
    uses(&mut vault, shared, 5, "billing", &["api.example.com"]);
    uses(&mut vault, shared, 1, "shop", &["api.example.com"]);
    assert!(corrections::consider(&mut vault, shared).is_empty());
}

/// The broker considers corrections after each allowed run (the hook in `run.rs`).
#[test]
fn an_allowed_run_proposes_a_correction() {
    let bouncer = common::fake_bouncer(&[]);
    let dir = TempDir::new().unwrap();
    let project = dir.path().join("project");
    std::fs::create_dir_all(project.join(".git")).unwrap();
    let project = std::fs::canonicalize(project).unwrap();
    let mut vault = vault(&dir);
    let live = fake("sk_live_", 24);
    let item = vault
        .add(ItemDraft {
            title: "Synthetic Sentry key".to_owned(),
            kind: CredentialKind::ApiKey,
            notes: String::new(),
            tags: Vec::new(),
            fields: vec![Field {
                name: "token".to_owned(),
                value: SecretValue::new(live.clone()),
                secret: true,
            }],
        })
        .unwrap()
        .id;
    vault
        .set_env_binding(item, "SYNTH_SENTRY_KEY", "token")
        .unwrap();
    vault
        .save_declaration(item, &development("project"), Some("sentry"), None)
        .unwrap();
    let (agent, token) = vault.register_agent("Corrections agent").unwrap();
    vault.set_agent_sees_all(agent.id, true).unwrap();
    let shared: SharedVault = Arc::new(Mutex::new(Some(vault)));
    let socket = dir.path().join("run").join("broker.sock");
    let mut options = BrokerOptions::with_tls(TlsClient::platform().expect("TLS"));
    options.approval_timeout = Duration::from_secs(5);
    options.run_timeout = Duration::from_secs(20);
    options.bouncer = Some(BouncerClient::new(&bouncer.url).expect("bouncer url"));
    let _broker = broker::start_with(Arc::clone(&shared), &socket, options).expect("broker");
    let response: WireResponse = client::send(
        &socket,
        token.expose(),
        Action::Run {
            items: vec![item],
            command: vec![
                "/bin/sh".into(),
                "-c".into(),
                "true || curl -s -H \"Authorization: Bearer $SYNTH_SENTRY_KEY\" https://sentry.io/api/0/".into(),
            ],
            cwd: project.display().to_string(),
            purpose: "Check the synthetic Sentry project.".into(),
            path: Some("/usr/bin:/bin".into()),
            user_request: Some("Check the synthetic Sentry project.".into()),
        },
    )
    .expect("broker answer");
    assert!(response.ok, "{response:?}");
    let guard = shared.lock().unwrap();
    let vault = guard.as_ref().unwrap();
    let open = vault.corrections(true).unwrap();
    assert_eq!(open.len(), 1, "{open:?}");
    assert_eq!(open[0].proposed, "production");
    assert!(vault.declaration(item).unwrap().unwrap().is_production());
    assert!(!format!("{open:?}").contains(&live));
}
