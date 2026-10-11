#![cfg(feature = "vault")]

//! A legacy visible setup key must not reach an agent through the catalog or a run.
//! An older Apassy kept it as a visible custom detail; the owner app now hides it at
//! the next save, but the vault still has the visible field until then. This fixture
//! has no deliberate owner grant of a hidden setup key. Synthetic values only.

mod common;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use apassy::agent::client;
use apassy::agent::wire::{Action, WireResponse};
use apassy::broker::approvals::{OwnerAction, OwnerCheck, OwnerGate};
use apassy::broker::bouncer::BouncerClient;
use apassy::broker::http::TlsClient;
use apassy::broker::{self, BrokerHandle, BrokerOptions, SharedVault};
use apassy::contracts::CredentialKind;
use apassy::vault::{
    DecidedBy, DecisionEntry, ExecMode, Field, GrantPlace, ItemDraft, LoggedDecision,
    RequestSource, SecretValue, Vault, VaultErrorKind,
};
use tempfile::TempDir;

const PASS: &str = "otp-agent-boundary-pass";
const PASSWORD: &str = "FAKE-otp-boundary-password-canary";
const ENV_NAME: &str = "GH_PASSWORD";
/// Seeds of visible legacy details. Synthetic Base32.
const URI_SEED: &str = "MFRGGZDFMZTWQ2LKNNWG23TPOBYXE43U";
const BARE_SEED: &str = "KRSXG5CTMVSWIQLQMFZXG6JAKRUGK4TF";
const CODE_SEED: &str = "ONXW2ZLUNBUW4ZZAONSWG4TFOQQGC5TF";
const FIELD_SEED: &str = "NBSWY3DPEB3W64TMMQQGC3TEEBTHE2LF";
const SEEDS: [&str; 4] = [URI_SEED, BARE_SEED, CODE_SEED, FIELD_SEED];

fn uri(seed: &str) -> String {
    format!("otpauth://totp/Example:ops?secret={seed}&issuer=Example")
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

fn no_seed(text: &str) {
    for seed in SEEDS {
        assert!(!text.contains(seed), "{seed} leaked: {text}");
    }
    assert!(
        !text.to_ascii_lowercase().contains("otpauth://totp"),
        "a setup link leaked: {text}"
    );
    assert!(!text.contains(PASSWORD), "the password leaked: {text}");
}

struct Fixture {
    dir: TempDir,
    vault: SharedVault,
    socket: PathBuf,
    token: String,
    agent_id: u64,
    login: u64,
    bouncer: common::FakeBouncer,
    broker: BrokerHandle,
}

/// A login as an older Apassy stored it: the setup keys are visible custom details.
/// The generic vault API keeps the flag that it gets, like a vault from before the
/// owner app hid setup keys.
fn fixture() -> Fixture {
    let dir = TempDir::new().expect("temp dir");
    let mut vault = Vault::create(&dir.path().join("otp.db"), PASS).expect("create");
    vault.unlock(PASS).expect("unlock");
    let login = vault
        .add(ItemDraft {
            title: "GitHub".to_owned(),
            kind: CredentialKind::Login,
            notes: String::new(),
            tags: Vec::new(),
            fields: vec![
                field("password", PASSWORD, true),
                field("username", "ops@example.invalid", false),
                // A link under a label that does not say "one-time password".
                field(&detail_name("Authenticator"), &uri(URI_SEED), false),
                // A bare key under the label of a one-time password.
                field(&detail_name("OTP"), BARE_SEED, false),
                // The label of the legacy command-line import.
                field(&detail_name("One-time code"), CODE_SEED, false),
                // A link in a field that is not a custom detail.
                field("website", &uri(FIELD_SEED), false),
                // Ordinary visible details stay in the catalog.
                field(&detail_name("Region"), "eu-west", false),
                field(
                    &detail_name("Docs"),
                    "https://example.test/otpauth-guide",
                    false,
                ),
            ],
        })
        .expect("add")
        .id;
    vault
        .set_env_binding(login, ENV_NAME, "password")
        .expect("binding");
    let (agent, token) = vault.register_agent("Seed finder").expect("register");
    vault.set_agent_sees_all(agent.id, true).expect("see all");
    let bouncer = common::fake_bouncer(&[]);
    let shared: SharedVault = Arc::new(Mutex::new(Some(vault)));
    let socket = dir.path().join("run").join("broker.sock");
    let mut options = BrokerOptions::with_tls(TlsClient::platform().expect("TLS"));
    options.approval_timeout = Duration::from_secs(5);
    options.run_timeout = Duration::from_secs(20);
    options.bouncer = Some(BouncerClient::new(&bouncer.url).expect("bouncer url"));
    let broker = broker::start_with(Arc::clone(&shared), &socket, options).expect("broker");
    Fixture {
        dir,
        vault: shared,
        socket,
        token: token.expose().to_owned(),
        agent_id: agent.id,
        login,
        bouncer,
        broker,
    }
}

fn with_vault<T>(fx: &Fixture, f: impl FnOnce(&mut Vault) -> T) -> T {
    let mut guard = fx.vault.lock().expect("vault");
    f(guard.as_mut().expect("open"))
}

fn send(fx: &Fixture, action: Action) -> WireResponse {
    client::send(&fx.socket, &fx.token, action).expect("broker answer")
}

#[test]
fn the_catalog_has_no_visible_setup_key() {
    let fx = fixture();
    let catalog = with_vault(&fx, |v| v.catalog()).expect("catalog");
    assert_eq!(catalog.len(), 1);
    no_seed(&format!("{catalog:?}"));
    let labels: Vec<&str> = catalog[0]
        .details
        .iter()
        .map(|(label, _)| label.as_str())
        .collect();
    assert_eq!(labels, vec!["username", "Region", "Docs"]);
    assert_eq!(
        catalog[0].details[2].1, "https://example.test/otpauth-guide",
        "an ordinary link stays"
    );

    let response = send(&fx, Action::ListAccess);
    assert!(response.ok, "{response:?}");
    let listed = response.result.expect("result");
    no_seed(&listed.to_string());
    let details = &listed["catalog"][0]["details"];
    assert_eq!(details["username"], "ops@example.invalid");
    assert_eq!(details["Region"], "eu-west");
    assert_eq!(
        details.as_object().map(serde_json::Map::len),
        Some(3),
        "{details}"
    );
    assert_eq!(listed["catalog"][0]["access"], "can_request");
}

#[test]
fn a_visible_setup_key_cannot_become_a_variable() {
    let fx = fixture();
    for name in [
        detail_name("Authenticator"),
        detail_name("OTP"),
        detail_name("One-time code"),
        "website".to_owned(),
    ] {
        let refused = with_vault(&fx, |v| v.set_env_binding(fx.login, "SEED_VAR", &name));
        assert_eq!(
            refused.unwrap_err().kind(),
            VaultErrorKind::InvalidInput,
            "{name}"
        );
    }
    let binding = with_vault(&fx, |v| v.env_binding(fx.login))
        .expect("binding")
        .expect("bound");
    assert_eq!(binding.env_name, ENV_NAME);
    assert_eq!(binding.field, "password");
}

#[test]
fn a_run_gets_the_password_variable_and_no_setup_key() {
    let fx = fixture();
    let project = std::fs::canonicalize(fx.dir.path()).expect("canonical dir");
    with_vault(&fx, |v| {
        v.set_exec_grants(
            fx.agent_id,
            &[fx.login],
            &GrantPlace::AnyFolder,
            ExecMode::Bouncer,
        )
    })
    .expect("grant");
    // Approve the run if the broker asks the owner. The thread stops after the run.
    let approvals = Arc::clone(fx.broker.approvals());
    let vault = Arc::clone(&fx.vault);
    let approver = std::thread::spawn(move || {
        let end = Instant::now() + Duration::from_secs(10);
        while Instant::now() < end {
            if let Some(run) = approvals.pending().into_iter().next() {
                assert_eq!(run.env_names, vec![ENV_NAME.to_owned()]);
                let proof = OwnerGate::new(vault, None)
                    .authorize(OwnerAction::ApproveRun(run), OwnerCheck::passphrase(PASS))
                    .expect("owner check");
                let _ = approvals.approve(proof);
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    });
    let response = send(
        &fx,
        Action::Run {
            items: vec![fx.login],
            command: vec![
                "/bin/sh".into(),
                "-c".into(),
                "echo len=${#GH_PASSWORD}; env".into(),
            ],
            cwd: project.display().to_string(),
            purpose: "List the environment.".into(),
            path: Some("/usr/bin:/bin".into()),
            user_request: Some("List the environment.".into()),
        },
    );
    approver.join().expect("approver");
    assert!(response.ok, "{response:?}");
    let result = response.result.clone().expect("result");
    assert_eq!(result["exit_code"], 0, "{result}");
    let stdout = result["stdout"].as_str().unwrap_or_default();
    assert!(
        stdout.contains(&format!("len={}", PASSWORD.len())),
        "{stdout}"
    );
    assert!(stdout.contains("[apassy:GH_PASSWORD]"), "{stdout}");
    no_seed(&format!("{response:?}"));
    for body in fx.bouncer.bodies.lock().expect("bodies").iter() {
        no_seed(body);
    }
    no_seed(&format!(
        "{:?}",
        with_vault(&fx, |v| v.recent_activity(10)).expect("activity")
    ));
    no_seed(&format!(
        "{:?}",
        with_vault(&fx, |v| v.decision_log()).expect("log")
    ));
}

#[test]
fn the_decision_log_masks_a_visible_setup_key() {
    let fx = fixture();
    // An agent that learned the keys elsewhere pastes them into its words.
    let pasted = format!(
        "{} {BARE_SEED} {CODE_SEED} {}",
        uri(URI_SEED),
        uri(FIELD_SEED)
    );
    let entry = DecisionEntry {
        at: 1_800_000_000,
        agent_id: fx.agent_id,
        agent_name: "Seed finder".to_owned(),
        project_dir: "/p".to_owned(),
        cwd_rel: ".".to_owned(),
        items: vec![fx.login],
        user_request: pasted.clone(),
        user_request_source: RequestSource::Agent,
        command: vec!["echo".to_owned(), pasted.clone(), PASSWORD.to_owned()],
        purpose: pasted.clone(),
        env_names: vec![ENV_NAME.to_owned()],
        declarations: vec![None],
        rule_flags: Vec::new(),
        known_safe: false,
        model_facts: Vec::new(),
        pattern: String::new(),
        grant_asks: false,
        asked: false,
        decision: LoggedDecision::Deny,
        decided_by: DecidedBy::Rule,
        remembered: false,
        policy: String::new(),
        note: pasted.clone(),
        instruction: String::new(),
    };
    with_vault(&fx, |v| v.record_decision(&entry)).expect("record");
    let log = with_vault(&fx, |v| v.decision_log()).expect("log");
    assert_eq!(log.len(), 1);
    let text = format!("{log:?}");
    no_seed(&text);
    // The ordinary visible values are not masked.
    let entry = DecisionEntry {
        user_request: "Check ops@example.invalid in eu-west.".to_owned(),
        ..entry
    };
    with_vault(&fx, |v| v.record_decision(&entry)).expect("record");
    let log = with_vault(&fx, |v| v.decision_log()).expect("log");
    assert!(
        format!("{:?}", log[1]).contains("Check ops@example.invalid in eu-west."),
        "{log:?}"
    );
}

#[test]
fn an_ordinary_plain_field_and_a_hidden_detail_keep_their_rules() {
    let fx = fixture();
    let notes = with_vault(&fx, |v| {
        let id = v
            .add(ItemDraft {
                title: "Notes item".to_owned(),
                kind: CredentialKind::ApiKey,
                notes: String::new(),
                tags: Vec::new(),
                fields: vec![
                    field("token", "FAKE-notes-token-canary", true),
                    field(&detail_name("Note"), "Rotate on Mondays.", false),
                    field(&detail_name("Recovery code"), "FAKE-recovery-canary", true),
                ],
            })
            .expect("add")
            .id;
        v.set_env_binding(id, "NOTES_TOKEN", "token")
            .expect("a secret field binds");
        id
    });
    let catalog = with_vault(&fx, |v| v.catalog()).expect("catalog");
    let entry = catalog
        .iter()
        .find(|entry| entry.item_id == notes)
        .expect("entry");
    assert_eq!(
        entry.details,
        vec![("Note".to_owned(), "Rotate on Mondays.".to_owned())]
    );
    assert!(!format!("{catalog:?}").contains("FAKE-recovery-canary"));
}
