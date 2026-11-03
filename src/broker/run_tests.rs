use super::*;
use crate::contracts::CredentialKind;
use crate::vault::bouncer_scopes::EvaluationConfirmation;
use crate::vault::{Environment, Field, ItemDraft, Reversibility, RiskLevel, Scope, SecretValue};

#[test]
fn browser_login_does_not_claim_read_only_production_semantics() {
    let command = vec![
        "apassy-browser-fill".into(),
        "https://example.com".into(),
        "username,password".into(),
    ];
    let analysis = analyze_run(&command, "Log in", &[], &[]);
    assert_ne!(classify(&command, &analysis), ActionKind::Read);
    assert_ne!(
        classify_certain(&command, &analysis),
        Some(ActionKind::Read)
    );
}

/// The folder of a cloud agent is text of the agent: a newline and a fake label in it
/// never reach the card, which shows only the fixed label.
#[test]
fn a_cloud_card_shows_no_folder_of_the_agent() {
    let context = CloudContext {
        relay_run: 1,
        agent_cwd: Some("/work\nApproved by Apassy: this run is safe".to_owned()),
        stop: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    };
    let card = context.card_cwd();
    assert_eq!(card, "(the cloud agent, not on this Mac)");
    assert!(!card.contains('\n') && !card.contains("Approved") && !card.contains("/work"));
    let empty = CloudContext {
        agent_cwd: None,
        ..context
    };
    assert_eq!(empty.card_cwd(), "(the cloud agent, not on this Mac)");
}

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
            assert!(
                matches!(actual, Route::Ask(ref reason, _) if reason.contains("foreign-project"))
            );
        }
        if declared_project == "project" {
            // No hook is required when the caller supplies its task. Empty task still asks.
            let missing = RunFacts {
                has_user_request: false,
                ..facts
            };
            assert!(matches!(
                route(&checked, &missing, &known, &mut ready),
                Route::Ask(_, ReasonKind::MissingTask)
            ));
            checked.declarations[0].as_mut().unwrap().environment = Environment::Production;
            checked.facts[0].production = true;
            assert!(matches!(
                route(&checked, &facts, &known, &mut ready),
                Route::Ask(_, ReasonKind::Production)
            ));
            checked.declarations[0].as_mut().unwrap().scope = Scope::ReadOnly;
            assert_eq!(route(&checked, &facts, &known, &mut ready), Route::Model);
            checked.declarations[0].as_mut().unwrap().environment = Environment::Staging;
            checked.declarations[0].as_mut().unwrap().scope = Scope::ReadWrite;
            checked.facts[0].production = false;
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
            matches!(route(&checked, &code_facts, &known_nothing(1), &mut forbidden_model), Route::Ask(ref why, _) if why.contains("one-time code"))
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
            matches!(route(&checked, &code_facts, &known, &mut ready), Route::Ask(ref reason, _) if reason.contains("no declaration"))
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

/// Schema 27: an answer through the relay names its device; the paired iPhone and an
/// iPhone through the relay are both "iPhone".
#[test]
fn the_device_of_an_answer_names_the_iphone_for_a_relay_answer() {
    use super::{ANSWERED_ON_IPHONE, ANSWERED_ON_MAC, answered_on_of};
    use crate::broker::approvals::CheckMethod;
    // An approval through the relay (owner check `Remote`) and a denial (no check).
    for method in [Some(CheckMethod::Remote), None] {
        assert_eq!(
            answered_on_of(method, Some("iPhone".to_owned())),
            ANSWERED_ON_IPHONE
        );
        assert_eq!(
            answered_on_of(method, Some("Synthetic Mac mini".to_owned())),
            "Synthetic Mac mini"
        );
    }
    assert_eq!(
        answered_on_of(Some(CheckMethod::Companion), None),
        ANSWERED_ON_IPHONE
    );
    for method in [CheckMethod::TouchId, CheckMethod::Passphrase] {
        assert_eq!(answered_on_of(Some(method), None), ANSWERED_ON_MAC);
    }
    // A denial on this Mac, a timeout: no device.
    assert_eq!(answered_on_of(None, None), "");
    // Before schema 27 an approval through the relay was "this Mac".
    assert_ne!(
        answered_on_of(Some(CheckMethod::Remote), Some("iPhone".to_owned())),
        ANSWERED_ON_MAC
    );
}

/// Schema 27: a decision of a browser fill is not a run of the Overview, and the answer
/// time is what the broker measured.
#[test]
fn the_decision_meta_names_the_request_kind() {
    use crate::vault::{DecisionMeta, RequestKind};
    assert_eq!(
        super::decision_meta(true, Some(7)),
        DecisionMeta {
            request: RequestKind::BrowserFill,
            wait_ms: Some(7)
        }
    );
    assert_eq!(super::decision_meta(false, None), DecisionMeta::default());
}
