use super::*;
use crate::contracts::CredentialKind;
use crate::vault::bouncer_scopes::EvaluationConfirmation;
use crate::vault::{Environment, Field, ItemDraft, Reversibility, RiskLevel, Scope, SecretValue};

#[test]
fn legacy_schema_twenty_scopes_neither_require_setup_nor_waive_vetoes() {
    for declared_project in ["project", "foreign-project"] {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().join("project");
        std::fs::create_dir_all(cwd.join(".git")).unwrap();
        let mut vault =
            Vault::create(&dir.path().join("vault.db"), "synthetic-review-pass").unwrap();
        vault.unlock("synthetic-review-pass").unwrap();
        let item = vault
            .add(ItemDraft {
                title: "Synthetic review key".into(),
                kind: CredentialKind::ApiKey,
                notes: String::new(),
                tags: vec![],
                fields: vec![Field {
                    name: "token".into(),
                    value: SecretValue::new("FAKE-review31-only".into()),
                    secret: true,
                }],
            })
            .unwrap();
        vault
            .set_env_binding(item.id, "SYNTH_REVIEW_KEY", "token")
            .unwrap();
        vault
            .save_declaration(
                item.id,
                &Declaration {
                    project: declared_project.into(),
                    environment: Environment::Staging,
                    risk: RiskLevel::Low,
                    scope: Scope::ReadWrite,
                    reversibility: Reversibility::Reversible,
                },
                None,
                None,
            )
            .unwrap();
        let (agent, _) = vault.register_agent("Synthetic reviewer").unwrap();
        vault.set_agent_sees_all(agent.id, true).unwrap();
        let project = project_of(&cwd, None).unwrap();
        // A real retained schema-20 row, deliberately for another action, host
        // and binding. It can neither veto fresh inference nor waive a hard gate.
        vault
            .authorize_evaluation(
                agent.id,
                &ProjectRef {
                    key: project.key,
                    label: project.label,
                },
                ActionKind::Change,
                &[EvaluationConfirmation {
                    item_id: item.id,
                    revision: item.revision,
                    environment: Environment::Staging,
                    risk: RiskLevel::Low,
                    hosts: vec!["foreign.example.test".into()],
                }],
                Some("obsolete-command-binding"),
                "synthetic test",
            )
            .unwrap();
        let items = [item.id];
        let command = vec!["git".to_owned(), "status".into()];
        let request = RunRequest {
            access_request_id: None,
            codes: Default::default(),
            items: &items,
            command: &command,
            cwd: cwd.to_str().unwrap(),
            purpose: "Check status.",
            path: Some("/usr/bin:/bin"),
            user_request: Some("Check status."),
            host_session: None,
        };
        let mut checked = check(&vault, &agent, &request).unwrap();
        let analysis = Analysis::default();
        let facts = RunFacts {
            analysis: &analysis,
            has_user_request: true,
            pattern: false,
            action: ActionKind::Read,
            hosts: &[],
        };
        let known = known_state(
            &vault,
            &items,
            &checked,
            ActionKind::Read,
            Some(ActionKind::Read),
            &[],
        );
        let mut ready = Readiness::new(|| Ok(()));
        let actual = route(&checked, &facts, &known, &mut ready);
        if declared_project == "project" {
            assert_eq!(actual, Route::Model);
        } else {
            assert!(matches!(actual, Route::Ask(ref reason) if reason.contains("foreign-project")));
        }
        assert_eq!(vault.evaluation_scopes(item.id).unwrap().len(), 1);
        assert!(vault.answers_for_item(item.id).unwrap().is_empty());
        assert!(vault.patterns().unwrap().is_empty());

        // A learned pattern never waives the code veto or reaches model routing.
        checked.facts[0].includes_code = true;
        let code_facts = RunFacts {
            pattern: true,
            ..facts
        };
        let mut forbidden_model =
            Readiness::new(|| panic!("code veto must precede model readiness"));
        assert!(
            matches!(route(&checked, &code_facts, &known_nothing(1), &mut forbidden_model), Route::Ask(ref why) if why.contains("one-time code"))
        );
        checked.facts[0].includes_code = false;

        // Even crafted pre-existing execution metadata cannot fill in a missing
        // declaration. This veto precedes both remembered execution paths.
        checked.declarations[0] = None;
        let known = Known {
            answer: vec![true],
            unfit: vec![None],
        };
        assert!(
            matches!(route(&checked, &code_facts, &known, &mut ready), Route::Ask(ref reason) if reason.contains("no declaration"))
        );
    }
}

#[test]
fn code_protocol_version_is_distinct_and_survives_tracking() {
    use crate::agent::wire::{Action, CODE_WIRE_VERSION, WIRE_VERSION};
    let action = Action::Run {
        access_request_id: None,
        items: vec![1],
        codes: vec![1],
        command: vec!["true".into()],
        cwd: "/tmp".into(),
        purpose: "Synthetic".into(),
        path: None,
        user_request: None,
    };
    assert_eq!(action.wire_version(), CODE_WIRE_VERSION);
    assert_ne!(action.wire_version(), WIRE_VERSION);
    let tracked = Action::Tracked {
        operation_id: "a".repeat(32),
        idempotency_key: None,
        action: Box::new(action),
    };
    assert_eq!(tracked.wire_version(), CODE_WIRE_VERSION);
    assert_eq!(Action::ListAccess.wire_version(), WIRE_VERSION);
}

#[test]
fn code_runs_never_return_unmasked_proxy_event_text() {
    let events = [ProxyEvent {
        host: "123456.example.invalid".into(),
        port: 443,
        method: Some("123456".into()),
        path: Some("/confirm/123456".into()),
        status: Some(200),
        outcome: ProxyOutcome::Passed,
        secrets: vec!["TOKEN".into()],
        reason: Some("synthetic 123456".into()),
    }];
    let report = network_report(true, &events, true);
    assert_eq!(report["request_count"], 1);
    assert_eq!(report["details_omitted"], true);
    assert!(report.get("requests").is_none());
    assert!(!report.to_string().contains("123456"));
    assert!(
        network_report(true, &events, false)
            .get("requests")
            .is_some()
    );
}
