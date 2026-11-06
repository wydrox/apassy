#![cfg(feature = "vault")]
//! Dormant adapter coverage: temporary vaults, synthetic records, no runtime activation.
use apassy::broker::action_kind::ActionKind;
use apassy::broker::bouncer::BouncerRequest;
use apassy::broker::context_adapter::{
    ContextAsk, RunContext, RunItem, context_input, item_run_match,
};
use apassy::broker::project::Project;
use apassy::broker::secret_facts::{ContextInput, HostFit, ItemRunMatch, ProjectFit};
use apassy::contracts::CredentialKind;
use apassy::vault::usage::{NewItemUse, UseDecidedBy, UseOutcome};
use apassy::vault::{
    Declaration, Environment, Field, ItemDraft, Reversibility, RiskLevel, Scope, SecretValue, Vault,
};
use serde_json::Value;
use tempfile::TempDir;

const PASS: &str = "synthetic-context-test-pass";

fn vault() -> (TempDir, Vault, u64) {
    let dir = TempDir::new().unwrap();
    let mut vault = Vault::create(&dir.path().join("context.db"), PASS).unwrap();
    vault.unlock(PASS).unwrap();
    let (agent, token) = vault.register_agent("synthetic-agent").unwrap();
    drop(token);
    (dir, vault, agent.id)
}

fn add(vault: &mut Vault, kind: CredentialKind) -> u64 {
    let fields = if kind == CredentialKind::Login {
        vec![
            Field {
                name: "username".into(),
                value: SecretValue::new("synthetic-user".into()),
                secret: false,
            },
            Field {
                name: "password".into(),
                value: SecretValue::new("synthetic-only-password".into()),
                secret: true,
            },
        ]
    } else {
        vec![Field {
            name: "token".into(),
            value: SecretValue::new("synthetic-only-value".into()),
            secret: true,
        }]
    };
    vault
        .add(ItemDraft {
            title: "synthetic item".into(),
            kind,
            notes: String::new(),
            tags: vec![],
            fields,
        })
        .unwrap()
        .id
}

fn request() -> BouncerRequest {
    BouncerRequest {
        user_request: "Check status".into(),
        command: "tool status".into(),
        purpose: String::new(),
        relative_dir: ".".into(),
        env_names: vec![],
        instruction: String::new(),
        task_provenance: String::new(),
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn run<'a>(
    request: &'a BouncerRequest,
    items: &'a [RunItem<'a>],
    agent: u64,
    now: u64,
) -> RunContext<'a> {
    RunContext {
        request,
        action: ActionKind::Read,
        project: None,
        project_key: "",
        agent_id: Some(agent),
        hosts: &[],
        items,
        now,
    }
}

fn item(id: u64) -> RunItem<'static> {
    RunItem {
        item_id: id,
        declaration: None,
        known_hosts: &[],
    }
}

fn declaration(project: &str) -> Declaration {
    Declaration {
        project: project.into(),
        environment: Environment::Development,
        risk: RiskLevel::Low,
        scope: Scope::ReadOnly,
        reversibility: Reversibility::Reversible,
    }
}

fn golden(bytes: &[u8]) -> (Value, BouncerRequest) {
    let fixture: Value = serde_json::from_slice(bytes).unwrap();
    let r = &fixture["request"];
    let text = |key: &str| r[key].as_str().unwrap().to_owned();
    let request = BouncerRequest {
        user_request: text("user_request"),
        command: text("command"),
        purpose: text("purpose"),
        relative_dir: text("relative_dir"),
        instruction: text("instruction"),
        task_provenance: text("task_provenance"),
        env_names: r["env_names"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect(),
    };
    (fixture, request)
}

fn assert_golden(input: &ContextInput, fixture: &Value) {
    assert!(fixture["refusal"].is_null());
    assert_eq!(
        input.model_text().as_bytes(),
        fixture["model_text"].as_str().unwrap().as_bytes()
    );
    assert_eq!(
        u64::from(input.token_bound()),
        fixture["token_bound"].as_u64().unwrap()
    );
    assert_eq!(
        input.secrets(),
        fixture["secrets"].as_array().unwrap().len()
    );
}

#[test]
fn golden_one_unknown_from_fresh_vault() {
    let (_dir, mut vault, agent) = vault();
    let items = [item(add(&mut vault, CredentialKind::ApiKey))];
    let (fixture, request) = golden(include_bytes!(
        "fixtures/secret-decision-context-v1/serializer/one-unknown.json"
    ));
    assert_golden(
        &context_input(&vault, &run(&request, &items, agent, now())).unwrap(),
        &fixture,
    );
}

#[test]
fn golden_unicode_from_fresh_vault() {
    let (_dir, mut vault, agent) = vault();
    let items = [item(add(&mut vault, CredentialKind::ApiKey))];
    let (fixture, request) = golden(include_bytes!(
        "fixtures/secret-decision-context-v1/serializer/unicode.json"
    ));
    assert_golden(
        &context_input(&vault, &run(&request, &items, agent, now())).unwrap(),
        &fixture,
    );
}

#[test]
fn legacy_declaration_keeps_unknown_provenance_and_requires_current_project() {
    let (_dir, mut vault, agent) = vault();
    let id = add(&mut vault, CredentialKind::ApiKey);
    // save_declaration records no source provenance; no raw SQL or owner proof needed.
    // Its public API requires a named project; the serializer's legacy golden has
    // an empty project and cannot be recreated with this API.
    let mut declared = declaration("synthetic-legacy-project");
    declared.environment = Environment::Production;
    declared.scope = Scope::Admin;
    vault.save_declaration(id, &declared, None, None).unwrap();
    let items = [RunItem {
        item_id: id,
        declaration: Some(&declared),
        known_hosts: &[],
    }];
    let request = request();
    let input = context_input(&vault, &run(&request, &items, agent, now())).unwrap();
    assert!(
        input.model_text().contains(
            "env=production env_from=legacy_unknown scope=admin scope_from=legacy_unknown sensitive=yes project=other hosts=none"
        )
    );
}

#[test]
fn golden_three_distinct_vault_items() {
    let (_dir, mut vault, agent) = vault();
    let items = [
        item(add(&mut vault, CredentialKind::ApiKey)),
        item(add(&mut vault, CredentialKind::ApiKey)),
        item(add(&mut vault, CredentialKind::ApiKey)),
    ];
    let (fixture, request) = golden(include_bytes!(
        "fixtures/secret-decision-context-v1/serializer/three.json"
    ));
    assert_golden(
        &context_input(&vault, &run(&request, &items, agent, now())).unwrap(),
        &fixture,
    );
}

#[test]
fn no_items_returns_only_no_secrets() {
    let (_dir, vault, agent) = vault();
    assert!(matches!(
        context_input(&vault, &run(&request(), &[], agent, now())),
        Err(ContextAsk::NoSecrets)
    ));
}

#[test]
fn four_distinct_items_return_only_too_many_secrets() {
    let (_dir, mut vault, agent) = vault();
    let items: Vec<_> = (0..4)
        .map(|_| item(add(&mut vault, CredentialKind::ApiKey)))
        .collect();
    assert!(matches!(
        context_input(&vault, &run(&request(), &items, agent, now())),
        Err(ContextAsk::TooManySecrets(4))
    ));
}

#[test]
fn long_request_returns_exact_golden_budget_refusal() {
    let (_dir, mut vault, agent) = vault();
    let items = [item(add(&mut vault, CredentialKind::ApiKey))];
    let (fixture, request) = golden(include_bytes!(
        "fixtures/secret-decision-context-v1/serializer/long-request.json"
    ));
    match context_input(&vault, &run(&request, &items, agent, now())) {
        Err(ContextAsk::OverBudget { bound, room }) => {
            assert_eq!(
                u64::from(bound),
                fixture["refusal"]["bound"].as_u64().unwrap()
            );
            assert_eq!(
                u64::from(room),
                fixture["refusal"]["room"].as_u64().unwrap()
            );
            assert!(bound > room);
        }
        other => panic!("expected only budget refusal, got {other:?}"),
    }
}

#[test]
fn missing_agent_always_asks_even_without_items_or_when_locked() {
    let (_dir, mut vault, agent) = vault();
    let items = [item(add(&mut vault, CredentialKind::ApiKey))];
    let request = request();
    let mut run = run(&request, &items, agent, now());
    run.agent_id = None;
    assert!(matches!(
        context_input(&vault, &run),
        Err(ContextAsk::MissingAgent)
    ));
    run.items = &[];
    assert!(matches!(
        context_input(&vault, &run),
        Err(ContextAsk::MissingAgent)
    ));
    vault.lock().unwrap();
    run.items = &items;
    assert!(matches!(
        context_input(&vault, &run),
        Err(ContextAsk::MissingAgent)
    ));
}

#[test]
fn duplicate_item_returns_only_duplicate_item() {
    let (_dir, mut vault, agent) = vault();
    let id = add(&mut vault, CredentialKind::ApiKey);
    let items = [item(id), item(id)];
    assert!(matches!(
        context_input(&vault, &run(&request(), &items, agent, now())),
        Err(ContextAsk::DuplicateItem)
    ));
}

#[test]
fn missing_second_item_discards_any_partial_input() {
    let (_dir, mut vault, agent) = vault();
    let id = add(&mut vault, CredentialKind::ApiKey);
    let items = [item(id), item(id + 1000)];
    assert!(matches!(
        context_input(&vault, &run(&request(), &items, agent, now())),
        Err(ContextAsk::Storage)
    ));
}

#[test]
fn locked_vault_returns_only_storage() {
    let (_dir, mut vault, agent) = vault();
    let items = [item(add(&mut vault, CredentialKind::ApiKey))];
    vault.lock().unwrap();
    assert!(matches!(
        context_input(&vault, &run(&request(), &items, agent, now())),
        Err(ContextAsk::Storage)
    ));
}

#[test]
fn project_and_host_fit_table_uses_only_each_items_hosts() {
    let dir = TempDir::new().unwrap();
    let project = Project {
        key: "synthetic-key".into(),
        label: "sample".into(),
        root: dir.path().join("sample"),
    };
    let named = declaration("sample");
    let other = declaration("elsewhere");
    let empty = declaration(" \t ");
    let known = vec!["*.example.test".into(), "exact.test".into()];
    let destinations = vec!["api.example.test".into(), "exact.test".into()];
    let cases = [
        ("absent", None, None, ProjectFit::Undeclared),
        ("empty", Some(&empty), None, ProjectFit::Undeclared),
        (
            "empty with project",
            Some(&empty),
            Some(&project),
            ProjectFit::Undeclared,
        ),
        (
            "named without current project",
            Some(&named),
            None,
            ProjectFit::Other,
        ),
        (
            "label matches",
            Some(&named),
            Some(&project),
            ProjectFit::Match,
        ),
        (
            "different project",
            Some(&other),
            Some(&project),
            ProjectFit::Other,
        ),
    ];
    for (label, declaration, project, expected) in cases {
        let item = RunItem {
            item_id: 1,
            declaration,
            known_hosts: &known,
        };
        assert_eq!(
            item_run_match(&item, project, &destinations),
            ItemRunMatch {
                project: expected,
                hosts: HostFit::Known
            },
            "{label}"
        );
        assert_eq!(
            item_run_match(&item, project, &[]).hosts,
            HostFit::None,
            "{label}"
        );
    }
    let a = RunItem {
        item_id: 1,
        declaration: None,
        known_hosts: &[],
    };
    let b = RunItem {
        item_id: 2,
        declaration: None,
        known_hosts: &known,
    };
    assert_eq!(
        item_run_match(&b, None, &destinations).hosts,
        HostFit::Known
    );
    assert_eq!(
        item_run_match(&a, None, &destinations).hosts,
        HostFit::Unknown
    );
    for hosts in [
        vec!["example.test".into()],
        vec!["badexample.test".into()],
        vec!["api.example.test".into(), "uncovered.test".into()],
    ] {
        assert_eq!(item_run_match(&b, None, &hosts).hosts, HostFit::Unknown);
    }
}

#[test]
fn same_snapshot_is_byte_deterministic_and_preserves_request_order() {
    let (_dir, mut vault, agent) = vault();
    let first = add(&mut vault, CredentialKind::ApiKey);
    let second = add(&mut vault, CredentialKind::Login);
    let third = add(&mut vault, CredentialKind::Custom);
    // Deliberately different from insertion/id order.
    let items = [item(third), item(first), item(second)];
    let request = request();
    let run = run(&request, &items, agent, now());
    let a = context_input(&vault, &run).unwrap();
    let b = context_input(&vault, &run).unwrap();
    assert_eq!(a.model_text().as_bytes(), b.model_text().as_bytes());
    assert_eq!(a.token_bound(), b.token_bound());
    assert_eq!(a.secrets(), 3);
    let text = a.model_text();
    assert!(text.contains("secret_1: kind=custom"));
    assert!(text.contains("secret_2: kind=api_key"));
    assert!(text.contains("secret_3: kind=login"));
}

#[test]
fn persisted_free_text_canaries_never_escape_input_debug_or_any_ask() {
    let (_dir, mut vault, _) = vault();
    let (agent, token) = vault.register_agent("CANARY_AGENT_NAME").unwrap();
    drop(token);
    let id = vault
        .add(ItemDraft {
            title: "CANARY_TITLE".into(),
            kind: CredentialKind::ApiKey,
            notes: "CANARY_NOTES".into(),
            tags: vec![],
            fields: vec![
                Field {
                    name: "token".into(),
                    value: SecretValue::new("CANARY_VALUE".into()),
                    secret: true,
                },
                Field {
                    name: "CANARY_CUSTOM_FIELD".into(),
                    value: SecretValue::new("CANARY_METADATA".into()),
                    secret: false,
                },
            ],
        })
        .unwrap()
        .id;
    let declared = declaration("CANARY_PROJECT_TEXT");
    vault.save_declaration(id, &declared, None, None).unwrap();
    let hosts: Vec<String> = vec!["canary-destination.test".into()];
    let known = vec!["canary-known.test".into(), hosts[0].clone()];
    vault
        .record_item_use(&NewItemUse {
            item_id: id,
            agent_id: Some(agent.id),
            agent_name: "CANARY_AGENT_NAME".into(),
            project_key: "CANARY_PROJECT_KEY".into(),
            project_label: "CANARY_USE_LABEL".into(),
            action: ActionKind::Read,
            command_summary: "CANARY_USE_COMMAND".into(),
            hosts: hosts.clone(),
            outcome: UseOutcome::Denied,
            decided_by: UseDecidedBy::Owner,
            answered_on: "synthetic-device".into(),
            decision_log_id: None,
        })
        .unwrap();
    vault
        .record_fill(id, "https://canary-event-detail.test")
        .unwrap();
    let uses = vault.item_uses(id, 10).unwrap();
    assert_eq!(uses.len(), 1);
    assert_eq!(uses[0].agent_name, "CANARY_AGENT_NAME");
    assert_eq!(uses[0].project_key, "CANARY_PROJECT_KEY");
    assert_eq!(uses[0].project_label, "CANARY_USE_LABEL");
    assert_eq!(uses[0].command_summary, "CANARY_USE_COMMAND");
    assert_eq!(uses[0].hosts, hosts);
    assert!(
        vault
            .item_events(id, 20)
            .unwrap()
            .iter()
            .any(|event| event.detail.contains("canary-event-detail.test"))
    );
    assert!(
        vault
            .list_agents()
            .unwrap()
            .iter()
            .any(|a| a.id == agent.id && a.name == "CANARY_AGENT_NAME")
    );
    let project = Project {
        key: "CANARY_PROJECT_KEY".into(),
        label: "CANARY_PROJECT_TEXT".into(),
        root: _dir.path().join("CANARY_PROJECT_ROOT"),
    };
    let items = [RunItem {
        item_id: id,
        declaration: Some(&declared),
        known_hosts: &known,
    }];
    // Caller has already sanitized these neutral texts; the adapter must not read values to mask them.
    let request = request();
    let mut run = run(&request, &items, agent.id, now());
    run.project = Some(&project);
    run.project_key = &project.key;
    run.hosts = &hosts;
    let input = context_input(&vault, &run).unwrap();
    assert!(
        input.model_text().contains("owner_denied=1"),
        "persisted history must be consumed"
    );
    for text in [input.model_text().to_owned(), format!("{input:?}")] {
        assert!(!text.to_ascii_lowercase().contains("canary"));
    }
    // Obtain every refusal from the real adapter with the same canary-bearing vault/run.
    run.agent_id = None;
    let missing = context_input(&vault, &run).unwrap_err();
    assert!(matches!(missing, ContextAsk::MissingAgent));
    run.agent_id = Some(agent.id);
    run.items = &[];
    let zero = context_input(&vault, &run).unwrap_err();
    assert!(matches!(zero, ContextAsk::NoSecrets));
    let duplicate = [item(id), item(id)];
    run.items = &duplicate;
    let duplicate = context_input(&vault, &run).unwrap_err();
    assert!(matches!(duplicate, ContextAsk::DuplicateItem));
    let four = [
        item(id),
        item(add(&mut vault, CredentialKind::ApiKey)),
        item(add(&mut vault, CredentialKind::ApiKey)),
        item(add(&mut vault, CredentialKind::ApiKey)),
    ];
    run.items = &four;
    let too_many = context_input(&vault, &run).unwrap_err();
    assert!(matches!(too_many, ContextAsk::TooManySecrets(4)));
    run.items = &items;
    let mut long = request.clone();
    long.user_request = "Inspect ".repeat(1000);
    run.request = &long;
    let budget = context_input(&vault, &run).unwrap_err();
    assert!(matches!(budget, ContextAsk::OverBudget { .. }));
    run.request = &request;
    vault.lock().unwrap();
    let storage = context_input(&vault, &run).unwrap_err();
    assert!(matches!(storage, ContextAsk::Storage));
    for ask in [missing, zero, duplicate, too_many, budget, storage] {
        assert!(!format!("{ask:?}").to_ascii_lowercase().contains("canary"));
    }
}
