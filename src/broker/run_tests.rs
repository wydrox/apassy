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
            remote_brain: false,
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
            // A remote bouncer brain never decides production, read-only too (ADR 0035).
            let remote = RunFacts {
                remote_brain: true,
                ..facts
            };
            assert!(matches!(
                route(&checked, &remote, &known, &mut ready),
                Route::Ask(ref why, ReasonKind::Production) if why.contains("another host")
            ));
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

/// ADR 0031, 2026-11-03: "Allow as dev" means development. An unlabeled credential asks
/// as production. After the label (the broker saves it with
/// `Vault::set_declaration_environment`), a writing command that matches the task goes
/// to the bouncer brain with the development thresholds and runs without a question. A
/// provider-strong or owner-set high risk keeps asking, and "Allow as prod" keeps the
/// production write/admin question.
#[test]
fn a_development_label_is_judged_with_the_development_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let cwd = dir.path().join("project");
    std::fs::create_dir_all(cwd.join(".git")).unwrap();
    let mut vault =
        Vault::create(&dir.path().join("vault.db"), "synthetic-dev-label-pass").unwrap();
    vault.unlock("synthetic-dev-label-pass").unwrap();
    let item = vault
        .add(ItemDraft {
            title: "Synthetic custom token".into(),
            kind: CredentialKind::ApiKey,
            notes: String::new(),
            tags: vec![],
            fields: vec![Field {
                name: "token".into(),
                value: SecretValue::new("FAKE-dev-label-only".into()),
                secret: true,
            }],
        })
        .unwrap();
    vault
        .set_env_binding(item.id, "SYNTH_DEV_TOKEN", "token")
        .unwrap();
    let all = |source| DeclarationSources {
        environment: source,
        risk: source,
        scope: source,
        reversibility: source,
    };
    // A value without a signal: production, high risk, admin, irreversible, and every
    // value only a default. (`save_declaration` needs a project; this one is the run's.)
    let unlabeled = Declaration {
        project: "project".to_owned(),
        environment: providers::DEFAULT_ENVIRONMENT,
        risk: providers::DEFAULT_RISK,
        scope: providers::DEFAULT_SCOPE,
        reversibility: providers::DEFAULT_REVERSIBILITY,
    };
    let store = |vault: &mut Vault, declaration: &Declaration, sources: DeclarationSources| {
        vault
            .save_declaration(item.id, declaration, None, None)
            .unwrap();
        vault.set_declaration_sources(item.id, &sources).unwrap();
    };
    store(&mut vault, &unlabeled, all(DeclarationSource::Default));
    let (agent, _) = vault.register_agent("Synthetic developer").unwrap();
    vault.set_agent_sees_all(agent.id, true).unwrap();
    let items = [item.id];
    // `node script.js`: project code, not known safe, and it writes.
    let command = vec!["node".to_owned(), "script.js".into()];
    let request = RunRequest {
        access_request_id: None,
        codes: Default::default(),
        items: &items,
        command: &command,
        cwd: cwd.to_str().unwrap(),
        purpose: "Seed the development database.",
        path: Some("/usr/bin:/bin"),
        user_request: Some("Seed the development database."),
        host_session: None,
    };
    let analysis = Analysis::default();
    let route_of = |vault: &Vault, checked: &Checked| {
        let facts = RunFacts {
            analysis: &analysis,
            has_user_request: true,
            pattern: false,
            action: ActionKind::Change,
            hosts: &[],
            remote_brain: false,
        };
        let known = known_state(vault, &items, checked, ActionKind::Change, None, &[]);
        let mut ready = Readiness::new(|| Ok(()));
        route(checked, &facts, &known, &mut ready)
    };
    let verdict = |task_match: f64| BouncerVerdict::Scored {
        facts: [
            ("task_match", task_match),
            ("writes", 0.7),
            ("leak", 0.05),
            ("destroy", 0.05),
        ]
        .into_iter()
        .map(|(name, probability)| crate::broker::bouncer::Fact {
            name: name.to_owned(),
            probability,
        })
        .collect(),
        model: None,
    };
    // The model step as `run` calls it: the judged declarations and the weak source.
    let decide = |checked: &Checked, task_match: f64| {
        let context = DecisionContext {
            analysis: &analysis,
            declarations: &checked.declarations,
            has_user_request: true,
        };
        let default_source = checked.facts.iter().any(|facts| facts.weak_source);
        decide_routed(
            &verdict(task_match),
            &context,
            &Learned::default(),
            default_source,
        )
    };

    // Unlabeled: production by default, and write/admin scope asks before the brain.
    let checked = check(&vault, &agent, &request).unwrap();
    assert!(checked.facts[0].unconfirmed);
    assert!(matches!(
        route_of(&vault, &checked),
        Route::Ask(_, ReasonKind::Production)
    ));

    // "Allow as dev".
    vault
        .set_declaration_environment(item.id, Environment::Development)
        .unwrap();
    let checked = check(&vault, &agent, &request).unwrap();
    assert_eq!(route_of(&vault, &checked), Route::Model);
    assert!(!checked.facts[0].weak_source);
    let judged = checked.declarations[0].clone().unwrap();
    assert_eq!(judged.risk, providers::DEVELOPMENT_RISK);
    assert_eq!(judged.reversibility, providers::DEVELOPMENT_REVERSIBILITY);
    assert!(!judged.is_sensitive());
    let decision = decide(&checked, 0.9);
    assert!(!decision.ask_owner, "{}", decision.note);
    assert!(
        decision.note.contains("normal credential"),
        "{}",
        decision.note
    );
    // The development thresholds: the task match level of ADR 0031 (75%), not the
    // 80% of a default source. A command that does not fit the task still asks.
    assert!(!decide(&checked, 0.77).ask_owner);
    let unmatched = decide(&checked, 0.5);
    assert!(unmatched.ask_owner);
    assert_eq!(unmatched.reason, ReasonKind::LowTaskMatch);

    // A label from before 0.5.16 kept the stored defaults; the bouncer judges it the
    // same, and the authorization keeps the stored values for the recheck.
    let earlier = Declaration {
        environment: Environment::Development,
        ..unlabeled.clone()
    };
    let labeled = DeclarationSources {
        environment: DeclarationSource::Owner,
        ..all(DeclarationSource::Default)
    };
    store(&mut vault, &earlier, labeled);
    let checked = check(&vault, &agent, &request).unwrap();
    assert_eq!(
        checked.authorization[0].declaration.as_ref(),
        Some(&earlier)
    );
    assert_eq!(checked.declarations[0].as_ref(), Some(&judged));
    assert!(!decide(&checked, 0.9).ask_owner);

    // A high risk and irreversibility from a strong provider signal stay: the writing
    // command needs a certain read and asks.
    store(
        &mut vault,
        &earlier,
        DeclarationSources {
            risk: DeclarationSource::Signal,
            reversibility: DeclarationSource::Signal,
            ..labeled
        },
    );
    vault
        .set_declaration_environment(item.id, Environment::Development)
        .unwrap();
    assert_eq!(vault.declaration(item.id).unwrap().as_ref(), Some(&earlier));
    let checked = check(&vault, &agent, &request).unwrap();
    assert_eq!(checked.declarations[0].as_ref(), Some(&earlier));
    let strong = decide(&checked, 0.9);
    assert!(strong.ask_owner);
    assert_eq!(strong.reason, ReasonKind::ModelUnsure);
    assert!(strong.note.contains("writes"), "{}", strong.note);

    // A risk that the owner set is never lowered.
    store(&mut vault, &earlier, DeclarationSources::default());
    vault
        .set_declaration_environment(item.id, Environment::Development)
        .unwrap();
    assert_eq!(
        vault.declaration(item.id).unwrap().unwrap().risk,
        RiskLevel::High
    );
    let checked = check(&vault, &agent, &request).unwrap();
    assert_eq!(
        checked.declarations[0].as_ref().unwrap().risk,
        RiskLevel::High
    );
    assert!(decide(&checked, 0.9).ask_owner);

    // "Allow as prod" on an unlabeled credential, and a development label changed to
    // production: production write/admin asks before the brain, with the careful
    // defaults again.
    for start in [Environment::Production, Environment::Development] {
        store(&mut vault, &unlabeled, all(DeclarationSource::Default));
        vault.set_declaration_environment(item.id, start).unwrap();
        vault
            .set_declaration_environment(item.id, Environment::Production)
            .unwrap();
        let checked = check(&vault, &agent, &request).unwrap();
        let declaration = checked.declarations[0].clone().unwrap();
        assert_eq!(declaration.risk, RiskLevel::High, "{start:?}");
        assert_eq!(
            declaration.reversibility,
            Reversibility::Irreversible,
            "{start:?}"
        );
        assert_eq!(declaration.scope, Scope::Admin, "{start:?}");
        assert!(checked.facts[0].production, "{start:?}");
        assert!(
            matches!(
                route_of(&vault, &checked),
                Route::Ask(_, ReasonKind::Production)
            ),
            "{start:?}"
        );
    }
}

/// Finding 1 of the 0.5.16 review: "Allow as dev" named one item, but the broker labeled
/// every unconfirmed item of the run, and a development label lowers the default risk
/// and reversibility. An answer labels only the first unconfirmed item, the one that
/// the devices name (ADR 0031, amended 2026-11-06), and the next run asks about the next.
#[test]
fn a_classification_labels_only_the_first_unconfirmed_item() {
    let dir = tempfile::tempdir().unwrap();
    let cwd = dir.path().join("project");
    std::fs::create_dir_all(cwd.join(".git")).unwrap();
    let mut vault = Vault::create(&dir.path().join("vault.db"), "synthetic-classify-pass").unwrap();
    vault.unlock("synthetic-classify-pass").unwrap();
    let add =
        |vault: &mut Vault, title: &str, kind: CredentialKind, field: &str, env_name: &str| {
            let mut fields = vec![Field {
                name: field.into(),
                value: SecretValue::new(format!("FAKE-{env_name}-only")),
                secret: true,
            }];
            // A login needs its username too.
            if kind == CredentialKind::Login {
                fields.insert(
                    0,
                    Field {
                        name: "username".into(),
                        value: SecretValue::new("synthetic-shop-user".to_owned()),
                        secret: false,
                    },
                );
            }
            let item = vault
                .add(ItemDraft {
                    title: title.into(),
                    kind,
                    notes: String::new(),
                    tags: vec![],
                    fields,
                })
                .unwrap();
            vault.set_env_binding(item.id, env_name, field).unwrap();
            // No signal: production only by default, every value a default.
            let unlabeled = Declaration {
                project: "project".to_owned(),
                environment: providers::DEFAULT_ENVIRONMENT,
                risk: providers::DEFAULT_RISK,
                scope: providers::DEFAULT_SCOPE,
                reversibility: providers::DEFAULT_REVERSIBILITY,
            };
            vault
                .save_declaration(item.id, &unlabeled, None, None)
                .unwrap();
            vault
                .set_declaration_sources(
                    item.id,
                    &DeclarationSources {
                        environment: DeclarationSource::Default,
                        risk: DeclarationSource::Default,
                        scope: DeclarationSource::Default,
                        reversibility: DeclarationSource::Default,
                    },
                )
                .unwrap();
            item.id
        };
    let dev_key = add(
        &mut vault,
        "Synthetic dev key",
        CredentialKind::ApiKey,
        "token",
        "SYNTH_DEV_KEY",
    );
    let password = add(
        &mut vault,
        "Synthetic shop password",
        CredentialKind::Login,
        "password",
        "SYNTH_SHOP_PASSWORD",
    );
    let (agent, _) = vault.register_agent("Synthetic classifier").unwrap();
    vault.set_agent_sees_all(agent.id, true).unwrap();
    let items = [dev_key, password];
    let command = vec!["node".to_owned(), "script.js".into()];
    let request = RunRequest {
        access_request_id: None,
        codes: Default::default(),
        items: &items,
        command: &command,
        cwd: cwd.to_str().unwrap(),
        purpose: "Seed the development database.",
        path: Some("/usr/bin:/bin"),
        user_request: Some("Seed the development database."),
        host_session: None,
    };
    let analysis = Analysis::default();
    let offers = |checked: &Checked| {
        let facts = RunFacts {
            analysis: &analysis,
            has_user_request: true,
            pattern: false,
            action: ActionKind::Change,
            hosts: &[],
            remote_brain: false,
        };
        let mut ready = Readiness::new(|| Ok(()));
        valid_answers(checked, &facts, None, false, &mut ready)
            .contains(&AnswerKind::CorrectEnvironment)
    };

    // Two unconfirmed items: the first is the one that an answer labels, never the other.
    let checked = check(&vault, &agent, &request).unwrap();
    assert!(checked.facts.iter().all(|facts| facts.unconfirmed));
    assert!(offers(&checked));
    assert_eq!(classified_index(&checked, &items, dev_key), Some(0));
    assert_eq!(classified_index(&checked, &items, password), None);
    assert!(!save_classification(
        &mut vault,
        &checked,
        &items,
        (Environment::Development, password)
    ));
    assert_eq!(
        vault.declaration(password).unwrap().unwrap().environment,
        providers::DEFAULT_ENVIRONMENT
    );

    // The owner labels the password production; the dev key is the one unconfirmed item.
    vault
        .set_declaration_environment(password, Environment::Production)
        .unwrap();
    let checked = check(&vault, &agent, &request).unwrap();
    assert!(checked.facts[0].unconfirmed);
    assert!(!checked.facts[1].unconfirmed);
    assert!(offers(&checked));
    assert_eq!(classified_index(&checked, &items, password), None);
    assert!(!save_classification(
        &mut vault,
        &checked,
        &items,
        (Environment::Development, password)
    ));
    let password_labeled = vault.declaration(password).unwrap();
    assert!(save_classification(
        &mut vault,
        &checked,
        &items,
        (Environment::Development, dev_key)
    ));
    assert_eq!(
        vault.declaration(dev_key).unwrap().unwrap().environment,
        Environment::Development
    );
    // The other item of the run keeps its declaration and its careful defaults.
    assert_eq!(vault.declaration(password).unwrap(), password_labeled);
    let password_now = vault.declaration(password).unwrap().unwrap();
    assert_eq!(password_now.environment, Environment::Production);
    assert_eq!(password_now.risk, providers::DEFAULT_RISK);
    assert_eq!(password_now.reversibility, providers::DEFAULT_REVERSIBILITY);

    // With both labeled, nothing is left to classify: the questions about them end.
    let checked = check(&vault, &agent, &request).unwrap();
    assert!(!offers(&checked));
    assert_eq!(first_unconfirmed(&checked), None);
}

/// The production rule asks at each write, so the card offers no allowance that it would
/// ignore. Declared read-only scope with a local brain is where an allowance still counts.
#[test]
fn only_a_production_allowance_that_can_count_is_offered() {
    let dir = tempfile::tempdir().unwrap();
    let cwd = dir.path().join("project");
    std::fs::create_dir_all(cwd.join(".git")).unwrap();
    let mut vault = Vault::create(&dir.path().join("vault.db"), "synthetic-allowance").unwrap();
    vault.unlock("synthetic-allowance").unwrap();
    let item = vault
        .add(ItemDraft {
            title: "Synthetic production key".into(),
            kind: CredentialKind::ApiKey,
            notes: String::new(),
            tags: vec![],
            fields: vec![Field {
                name: "token".into(),
                value: SecretValue::new("FAKE-allowance-token".to_owned()),
                secret: true,
            }],
        })
        .unwrap();
    vault
        .set_env_binding(item.id, "SYNTH_PRODUCTION_KEY", "token")
        .unwrap();
    let declare = |vault: &mut Vault, scope: Scope| {
        vault
            .save_declaration(
                item.id,
                &Declaration {
                    project: "project".to_owned(),
                    environment: Environment::Production,
                    risk: RiskLevel::Low,
                    scope,
                    reversibility: Reversibility::Reversible,
                },
                None,
                None,
            )
            .unwrap();
        vault
            .set_declaration_sources(
                item.id,
                &DeclarationSources {
                    environment: DeclarationSource::Owner,
                    risk: DeclarationSource::Owner,
                    scope: DeclarationSource::Owner,
                    reversibility: DeclarationSource::Owner,
                },
            )
            .unwrap();
    };
    let (agent, _) = vault.register_agent("Synthetic allowance").unwrap();
    vault.set_agent_sees_all(agent.id, true).unwrap();
    let items = [item.id];
    let command = vec!["true".to_owned()];
    let request = RunRequest {
        access_request_id: None,
        codes: Default::default(),
        items: &items,
        command: &command,
        cwd: cwd.to_str().unwrap(),
        purpose: "Change the record.",
        path: Some("/usr/bin:/bin"),
        user_request: Some("Change the record."),
        host_session: None,
    };
    let analysis = Analysis::default();
    let offers = |checked: &Checked, remote_brain: bool| {
        let facts = RunFacts {
            analysis: &analysis,
            has_user_request: true,
            pattern: false,
            action: ActionKind::Change,
            hosts: &[],
            remote_brain,
        };
        let mut ready = Readiness::new(|| Ok(()));
        valid_answers(checked, &facts, Some(ActionKind::Change), true, &mut ready)
            .contains(&AnswerKind::Production(ActionKind::Change))
    };
    declare(&mut vault, Scope::ReadWrite);
    let checked = check(&vault, &agent, &request).unwrap();
    assert!(!offers(&checked, false));
    // With an older allowance a project answer would save nothing for this item.
    let facts = RunFacts {
        analysis: &analysis,
        has_user_request: true,
        pattern: false,
        action: ActionKind::Change,
        hosts: &[],
        remote_brain: false,
    };
    let mut ready = Readiness::new(|| Ok(()));
    assert!(
        !valid_answers(
            &checked,
            &facts,
            Some(ActionKind::Change),
            false,
            &mut ready
        )
        .contains(&AnswerKind::InProject(ActionKind::Change))
    );
    declare(&mut vault, Scope::ReadOnly);
    let checked = check(&vault, &agent, &request).unwrap();
    assert!(offers(&checked, false));
    assert!(!offers(&checked, true));
}

/// An item without a declaration counts as unconfirmed, so the first answer writes its
/// declaration, and the second item of the run is next. No item stays undeclared.
#[test]
fn answers_describe_undeclared_items_one_by_one() {
    let dir = tempfile::tempdir().unwrap();
    let cwd = dir.path().join("project");
    std::fs::create_dir_all(cwd.join(".git")).unwrap();
    let mut vault = Vault::create(&dir.path().join("vault.db"), "synthetic-undeclared").unwrap();
    vault.unlock("synthetic-undeclared").unwrap();
    let mut add = |title: &str, env_name: &str| {
        let item = vault
            .add(ItemDraft {
                title: title.into(),
                kind: CredentialKind::ApiKey,
                notes: String::new(),
                tags: vec![],
                fields: vec![Field {
                    name: "token".into(),
                    value: SecretValue::new(format!("FAKE-{env_name}-only")),
                    secret: true,
                }],
            })
            .unwrap();
        vault.set_env_binding(item.id, env_name, "token").unwrap();
        item.id
    };
    let first = add("Synthetic first", "SYNTH_FIRST");
    let second = add("Synthetic second", "SYNTH_SECOND");
    let (agent, _) = vault.register_agent("Synthetic undeclared").unwrap();
    vault.set_agent_sees_all(agent.id, true).unwrap();
    let items = [first, second];
    let command = vec!["node".to_owned(), "script.js".into()];
    let request = RunRequest {
        access_request_id: None,
        codes: Default::default(),
        items: &items,
        command: &command,
        cwd: cwd.to_str().unwrap(),
        purpose: "Seed the development database.",
        path: Some("/usr/bin:/bin"),
        user_request: Some("Seed the development database."),
        host_session: None,
    };
    let checked = check(&vault, &agent, &request).unwrap();
    assert!(checked.declarations.iter().all(Option::is_none));
    assert_eq!(first_unconfirmed(&checked), Some(0));
    assert!(save_classification(
        &mut vault,
        &checked,
        &items,
        (Environment::Development, first)
    ));
    let checked = check(&vault, &agent, &request).unwrap();
    assert!(checked.declarations[0].is_some());
    assert_eq!(first_unconfirmed(&checked), Some(1));
    assert!(save_classification(
        &mut vault,
        &checked,
        &items,
        (Environment::Development, second)
    ));
    let checked = check(&vault, &agent, &request).unwrap();
    assert!(checked.declarations.iter().all(Option::is_some));
    assert_eq!(first_unconfirmed(&checked), None);
}
