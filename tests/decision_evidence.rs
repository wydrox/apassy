#![cfg(feature = "vault")]
//! Public API smoke test; private SQL boundary/cap/read-only tests live with the module.
use apassy::broker::action_kind::ActionKind;
use apassy::contracts::CredentialKind;
use apassy::vault::{EventAge, EvidenceQuery, Field, ItemDraft, SecretValue, UseCount, Vault};

#[test]
fn new_item_has_no_fabricated_provenance_or_local_history() {
    let dir = tempfile::TempDir::new().unwrap();
    let mut vault = Vault::create(
        &dir.path().join("public-evidence.db"),
        "synthetic-test-pass",
    )
    .unwrap();
    vault.unlock("synthetic-test-pass").unwrap();
    let item = vault
        .add(ItemDraft {
            title: "fixture".into(),
            kind: CredentialKind::Custom,
            notes: String::new(),
            tags: vec![],
            fields: vec![Field {
                name: "metadata".into(),
                value: SecretValue::new("fixture metadata".into()),
                secret: false,
            }],
        })
        .unwrap();
    let evidence = vault
        .decision_evidence(&EvidenceQuery {
            item_id: item.id,
            agent_id: None,
            project_key: "",
            action: ActionKind::Read,
            hosts: &[],
            now: 1,
        })
        .unwrap();
    assert_eq!(evidence.kind, CredentialKind::Custom);
    assert_eq!(evidence.declaration, None);
    assert_eq!(evidence.declaration_sources, None);
    assert_eq!(evidence.owner_allowed_same_scope, UseCount::Known(0));
    assert_eq!(evidence.last_secret_change, EventAge::None);
    assert!(!evidence.agent_created_here);
    assert!(!evidence.agent_allowed_before);
}

#[test]
fn vault_to_wire_keeps_secret_and_free_text_out_of_context() {
    use apassy::broker::bouncer::BouncerRequest;
    use apassy::broker::context_brain::{ContextPin, request_body};
    use apassy::broker::secret_facts::{
        ContextV1, HostFit, ItemRunMatch, ProjectFit, build_input, facts_from_evidence,
    };
    use apassy::vault::{
        Declaration, Environment, NewItemUse, Reversibility, RiskLevel, Scope, UseDecidedBy,
        UseOutcome,
    };

    let dir = tempfile::TempDir::new().unwrap();
    let mut vault =
        Vault::create(&dir.path().join("wire-evidence.db"), "synthetic-test-pass").unwrap();
    vault.unlock("synthetic-test-pass").unwrap();
    let item = vault
        .add(ItemDraft {
            title: "private-title-canary".into(),
            kind: CredentialKind::ApiKey,
            notes: "private-notes-canary".into(),
            tags: vec![],
            fields: vec![
                Field {
                    name: "token".into(),
                    value: SecretValue::new("synthetic-value-canary".into()),
                    secret: true,
                },
                Field {
                    name: "private_field_canary".into(),
                    value: SecretValue::new("private-metadata-canary".into()),
                    secret: false,
                },
            ],
        })
        .unwrap();
    vault
        .save_declaration(
            item.id,
            &Declaration {
                project: "private-project-canary".into(),
                environment: Environment::Development,
                risk: RiskLevel::Low,
                scope: Scope::ReadOnly,
                reversibility: Reversibility::Reversible,
            },
            Some("stripe"),
            None,
        )
        .unwrap();
    vault
        .record_item_use(&NewItemUse {
            item_id: item.id,
            agent_id: None,
            agent_name: "private-agent-canary".into(),
            project_key: "private-project-canary".into(),
            project_label: "private-label-canary".into(),
            action: ActionKind::Read,
            command_summary: "private-command-canary".into(),
            hosts: vec!["private-host-canary.test".into()],
            outcome: UseOutcome::Denied,
            decided_by: UseDecidedBy::Owner,
            answered_on: "private-device-canary".into(),
            decision_log_id: None,
        })
        .unwrap();
    vault
        .record_fill(item.id, "https://private-history-canary.test")
        .unwrap();
    assert_eq!(vault.item_uses(item.id, 1).unwrap().len(), 1);
    assert!(
        vault.item_events(item.id, 1).unwrap()[0]
            .detail
            .contains("canary")
    );
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let evidence = vault
        .decision_evidence(&EvidenceQuery {
            item_id: item.id,
            agent_id: None,
            project_key: "private-project-canary",
            action: ActionKind::Read,
            hosts: &[],
            now,
        })
        .unwrap();
    let facts = facts_from_evidence(
        &evidence,
        ItemRunMatch {
            project: ProjectFit::Match,
            hosts: HostFit::None,
        },
        now,
    );
    let input = build_input(
        &BouncerRequest {
            user_request: "Inspect service".into(),
            command: "inspect".into(),
            purpose: "Read".into(),
            instruction: "private-instruction-canary".into(),
            relative_dir: "private-directory-canary".into(),
            env_names: vec!["private-env-canary".into()],
            task_provenance: "private-provenance-canary".into(),
        },
        &ContextV1 {
            action: ActionKind::Read,
            secrets: vec![facts],
        },
    )
    .unwrap();
    let wire = request_body(
        &input,
        &ContextPin {
            heads: "a".repeat(64),
            model: "apassy-context-v1+aaaaaaaa".into(),
        },
    )
    .to_string();
    assert!(!wire.contains("canary"));
    assert!(
        input
            .model_text()
            .contains("env=development env_from=legacy_unknown")
    );
    assert!(input.model_text().contains("project=match hosts=none"));
    assert!(input.model_text().contains("provider=stripe"));
    assert!(input.model_text().contains("owner_denied_other=1"));
}
