#![cfg(feature = "vault")]

//! Corrections from the use log (ADR 0025 §5): proposed once, never again after an
//! ignore, and applied through the declaration on accept. Synthetic values only.

use crate::common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use apassy::agent::client;
use apassy::agent::wire::{Action, WireResponse};
use apassy::broker::action_kind::ActionKind;
use apassy::broker::bouncer::BouncerClient;
use apassy::broker::corrections::{
    self, APPLIED_FACT, MIN_ENVIRONMENT_USES, MIN_PROJECT_USES, PREVIOUS_ENVIRONMENT_FACT,
    RECHECK_USES, UNVERIFIED_FACT,
};
use apassy::broker::http::TlsClient;
use apassy::broker::{self, BrokerOptions, SharedVault};
use apassy::contracts::CredentialKind;
use apassy::vault::agent_items::{
    CorrectionAnswer, CorrectionKind, CorrectionState, RAISED_FROM_FACT,
};
use apassy::vault::detect::{self, Source};
use apassy::vault::usage::{NewItemUse, UseDecidedBy, UseOutcome};
use apassy::vault::{
    Declaration, DeclarationSource, DeclarationSources, Environment, Field, ItemDraft,
    Reversibility, RiskLevel, Scope, SecretValue, Vault,
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

/// An API key item that the owner added, with the variable `variable`.
fn owner_key(vault: &mut Vault, title: &str, value: &str, variable: &str) -> u64 {
    let item = vault.add(key_draft(title, value)).unwrap().id;
    vault.set_env_binding(item, variable, "token").unwrap();
    item
}

fn key_draft(title: &str, value: &str) -> ItemDraft {
    ItemDraft {
        title: title.to_owned(),
        kind: CredentialKind::ApiKey,
        notes: String::new(),
        tags: Vec::new(),
        fields: vec![Field {
            name: "token".to_owned(),
            value: SecretValue::new(value.to_owned()),
            secret: true,
        }],
    }
}

/// Every declaration value from `source`.
fn all_from(source: DeclarationSource) -> DeclarationSources {
    DeclarationSources {
        environment: source,
        risk: source,
        scope: source,
        reversibility: source,
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
    // The agent chose the hosts: the facts say so.
    assert_eq!(open[0].facts[UNVERIFIED_FACT], true);
    assert_eq!(open[0].facts[PREVIOUS_ENVIRONMENT_FACT], "production");
    assert_eq!(open[0].facts[APPLIED_FACT], false);
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
    let item = owner_key(&mut vault, "Synthetic key", &live, "SYNTH_KEY");
    vault
        .set_declaration(item, &development("synthetic"))
        .unwrap();
    // A signal, not the owner, gave the environment (a test key whose value changed).
    vault
        .set_declaration_sources(item, &all_from(DeclarationSource::Signal))
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
    assert_eq!(correction.facts[APPLIED_FACT], true);
    assert_eq!(correction.facts[PREVIOUS_ENVIRONMENT_FACT], "development");
    assert_eq!(correction.facts[RAISED_FROM_FACT], "development");
    assert_eq!(correction.facts["previous_source"], "signal");
    assert!(!format!("{correction:?}").contains(&live));
    // Ignore: the item gets development back (looser), and it is not proposed again.
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
            access_request_id: None,
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
    // The owner declared development: it stays until the owner answers.
    assert_eq!(open[0].facts[APPLIED_FACT], false);
    assert_eq!(
        vault.declaration(item).unwrap().unwrap().environment,
        Environment::Development
    );
    assert!(!format!("{open:?}").contains(&live));
}

#[test]
fn an_environment_from_the_owner_is_never_raised_automatically() {
    let dir = TempDir::new().unwrap();
    let mut vault = vault(&dir);
    let live = fake("sk_live_", 24);
    let item = owner_key(&mut vault, "Owner key", &live, "OWNER_KEY");
    vault
        .set_declaration(item, &development("synthetic"))
        .unwrap();
    assert_eq!(
        vault.declaration_sources(item).unwrap().environment,
        DeclarationSource::Owner
    );
    uses(&mut vault, item, 1, "", &["api.stripe.com"]);
    let proposed = corrections::consider(&mut vault, item);
    assert_eq!(proposed.len(), 1, "a proposal for the owner");
    let correction = &vault.corrections(true).unwrap()[0];
    assert_eq!(correction.proposed, "production");
    assert_eq!(correction.facts[APPLIED_FACT], false);
    assert_eq!(correction.facts[PREVIOUS_ENVIRONMENT_FACT], "development");
    assert_eq!(correction.facts["previous_source"], "owner");
    assert!(correction.facts.get(RAISED_FROM_FACT).is_none());
    assert_eq!(
        vault.declaration(item).unwrap().unwrap().environment,
        Environment::Development,
        "the owner's environment stays"
    );
    assert_eq!(
        vault.declaration_sources(item).unwrap().environment,
        DeclarationSource::Owner
    );
    // The same for a new value (update_credential calls raise_for_value).
    let staged = owner_key(
        &mut vault,
        "Owner staging key",
        &fake("sk_test_", 24),
        "STAGED_KEY",
    );
    let mut staging = development("synthetic");
    staging.environment = Environment::Staging;
    vault.set_declaration(staged, &staging).unwrap();
    let staged_id = corrections::raise_for_value(&mut vault, staged, &live).expect("proposed");
    assert_eq!(
        vault.declaration(staged).unwrap().unwrap().environment,
        Environment::Staging
    );
    // Ignore: nothing to give back. Accept: production as the owner's answer.
    vault
        .settle_correction(proposed[0], CorrectionAnswer::Ignored)
        .unwrap();
    assert_eq!(
        vault.declaration(item).unwrap().unwrap().environment,
        Environment::Development
    );
    vault
        .settle_correction(staged_id, CorrectionAnswer::Accepted)
        .unwrap();
    assert!(vault.declaration(staged).unwrap().unwrap().is_production());
}

#[test]
fn development_hosts_never_beat_a_live_value() {
    let dir = TempDir::new().unwrap();
    let mut vault = vault(&dir);
    // Production only by default, but the value is live.
    let item = owner_key(
        &mut vault,
        "Default key",
        &fake("sk_live_", 24),
        "DEFAULT_KEY",
    );
    let mut production = development("synthetic");
    production.environment = Environment::Production;
    vault.set_declaration(item, &production).unwrap();
    vault
        .set_declaration_sources(item, &all_from(DeclarationSource::Default))
        .unwrap();
    uses(&mut vault, item, 5, "", &["api.sandbox.example.com"]);
    assert!(corrections::consider(&mut vault, item).is_empty());
    assert!(vault.corrections(false).unwrap().is_empty());
}

#[test]
fn consider_reveals_and_reads_the_log_only_after_a_change_or_every_recheck() {
    let dir = TempDir::new().unwrap();
    let mut vault = vault(&dir);
    let item = owner_key(
        &mut vault,
        "Staging key",
        &fake("sk_test_", 24),
        "STAGING_KEY",
    );
    let mut staging = development("synthetic");
    staging.environment = Environment::Staging;
    vault.set_declaration(item, &staging).unwrap();
    vault
        .set_declaration_sources(item, &all_from(DeclarationSource::Signal))
        .unwrap();
    // Enough uses that the log is not read at each run.
    uses(
        &mut vault,
        item,
        MIN_PROJECT_USES,
        "billing",
        &["api.stripe.com"],
    );
    uses(&mut vault, item, 1, "shop", &["api.stripe.com"]);
    assert!(corrections::consider(&mut vault, item).is_empty());
    let first = corrections::checks(&vault, item);
    assert_eq!((first.values, first.uses), (1, 1));
    for _ in 1..RECHECK_USES {
        uses(&mut vault, item, 1, "shop", &["api.stripe.com"]);
        assert!(corrections::consider(&mut vault, item).is_empty());
    }
    let skipped = corrections::checks(&vault, item);
    assert_eq!(skipped.values, 1, "no reveal without a change");
    assert_eq!(skipped.uses, 1, "no log read before the recheck");
    uses(&mut vault, item, 1, "shop", &["api.stripe.com"]);
    assert!(corrections::consider(&mut vault, item).is_empty());
    let rechecked = corrections::checks(&vault, item);
    assert_eq!(
        (rechecked.values, rechecked.uses),
        (1, 2),
        "every RECHECK_USES"
    );

    // A new value is a change: the next run checks it, and a live value raises.
    let revision = vault.details(item).unwrap().summary.revision;
    vault
        .update(
            item,
            revision,
            key_draft("Staging key", &fake("sk_live_", 24)),
        )
        .unwrap();
    assert_eq!(corrections::consider(&mut vault, item).len(), 1);
    assert!(vault.declaration(item).unwrap().unwrap().is_production());
    assert_eq!(corrections::checks(&vault, item).values, 2);
    // Its own raise is no change for the next run.
    assert!(corrections::consider(&mut vault, item).is_empty());
    assert_eq!(corrections::checks(&vault, item).values, 2);
}
