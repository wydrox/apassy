use super::*;
use crate::vault::{Declaration, DeclarationSources, Reversibility, RiskLevel};

fn evidence() -> ItemDecisionEvidence {
    ItemDecisionEvidence {
        kind: CredentialKind::ApiKey,
        provider: None,
        declaration: None,
        declaration_sources: None,
        agent_created_here: false,
        agent_allowed_before: false,
        owner_allowed_same_scope: UseCount::Known(0),
        owner_denied_same_scope: UseCount::Known(0),
        owner_denied_other_scope: UseCount::Known(0),
        last_secret_change: EventAge::None,
        last_access_change: EventAge::None,
    }
}
fn facts(e: &ItemDecisionEvidence) -> SecretFactsV1 {
    facts_from_evidence(
        e,
        ItemRunMatch {
            project: ProjectFit::Undeclared,
            hosts: HostFit::None,
        },
        4_000_000,
    )
}
fn request(v: &Value) -> BouncerRequest {
    BouncerRequest {
        user_request: v["user_request"].as_str().unwrap().into(),
        command: v["command"].as_str().unwrap().into(),
        purpose: v["purpose"].as_str().unwrap().into(),
        instruction: v["instruction"].as_str().unwrap().into(),
        relative_dir: v["relative_dir"].as_str().unwrap().into(),
        env_names: v["env_names"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().into())
            .collect(),
        task_provenance: v["task_provenance"].as_str().unwrap().into(),
    }
}
fn fixture_secret(v: &Value) -> SecretFactsV1 {
    let mut s = facts(&evidence());
    macro_rules! set {
        ($field:ident, $ty:ident) => {
            s.$field = *$ty::ALL
                .iter()
                .find(|x| x.as_str() == v[stringify!($field)].as_str().unwrap())
                .unwrap();
        };
    }
    set!(kind, KindFact);
    set!(env, EnvFact);
    set!(env_from, Provenance);
    set!(scope, ScopeFact);
    set!(scope_from, Provenance);
    set!(sensitive, Tri);
    set!(project, ProjectFit);
    set!(hosts, HostFit);
    set!(made_by_agent, Recorded);
    set!(agent_used, Recorded);
    set!(secret_changed, Age);
    set!(access_changed, Age);
    set!(owner_allowed, Count);
    set!(owner_denied, Count);
    set!(owner_denied_other, Count);
    s.provider = match v["provider"].as_str().unwrap() {
        "none" => ProviderFact::None,
        "other" => ProviderFact::Other,
        id => ProviderFact::Listed(listed_provider(id).expect("fixture provider allow-list")),
    };
    s.conflict = v["conflict"] == "yes";
    s
}
#[test]
fn all_vocabularies_match_contract_in_both_directions() {
    let mut actual: Vec<(&str, Vec<&str>)> = Vec::new();
    macro_rules! vocab {
        ($key:literal, $ty:ident) => {
            actual.push(($key, $ty::ALL.iter().map(|x| x.as_str()).collect()));
        };
    }
    vocab!("kind", KindFact);
    actual.push((
        "provider",
        ProviderFact::ALL.iter().map(|p| p.as_str()).collect(),
    ));
    vocab!("env", EnvFact);
    vocab!("env_from", Provenance);
    vocab!("scope", ScopeFact);
    vocab!("scope_from", Provenance);
    vocab!("sensitive", Tri);
    vocab!("project", ProjectFit);
    vocab!("hosts", HostFit);
    vocab!("made_by_agent", Recorded);
    vocab!("agent_used", Recorded);
    vocab!("secret_changed", Age);
    vocab!("access_changed", Age);
    vocab!("owner_allowed", Count);
    vocab!("owner_denied", Count);
    vocab!("owner_denied_other", Count);
    actual.push(("conflict", vec!["yes", "no"]));
    let expected: Vec<(&str, Vec<&str>)> = contract()["secret_facts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            (
                p[0].as_str().unwrap(),
                p[1].as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_str().unwrap())
                    .collect(),
            )
        })
        .collect();
    assert_eq!(actual, expected);
    assert_eq!(
        contract()["request_facts"],
        serde_json::json!([
            [
                "action",
                [
                    ActionKind::Read.as_str(),
                    ActionKind::Change.as_str(),
                    ActionKind::Deploy.as_str(),
                    ActionKind::Delete.as_str()
                ]
            ],
            ["secrets", ["1", "2", "3"]]
        ])
    );
    assert_eq!(contract()["name"], CONTRACT_NAME);
    assert_eq!(contract()["serializer"], SERIALIZER);
    assert_eq!(contract()["max_secrets"], MAX_SECRETS);
    for id in contract()["providers"].as_array().unwrap() {
        let id = id.as_str().unwrap();
        assert_eq!(listed_provider(id), Some(id));
        assert_eq!(
            ProviderFact::Listed(listed_provider(id).unwrap()).as_str(),
            id
        );
    }
}
#[test]
fn provenance_and_stored_sensitivity() {
    let mut e = evidence();
    let s = facts(&e);
    assert_eq!(
        (s.env, s.env_from, s.scope, s.scope_from, s.sensitive),
        (
            EnvFact::Unknown,
            Provenance::None,
            ScopeFact::Unknown,
            Provenance::None,
            Tri::Unknown
        )
    );
    assert_eq!(
        (s.made_by_agent, s.agent_used),
        (Recorded::NotRecorded, Recorded::NotRecorded)
    );
    e.declaration = Some(Declaration {
        project: "sk_live_CANARY_PROJECT".into(),
        environment: Environment::Development,
        scope: Scope::ReadWrite,
        risk: RiskLevel::High,
        reversibility: Reversibility::Irreversible,
    });
    let suffix = segments(&ContextV1 {
        action: ActionKind::Read,
        secrets: vec![facts(&e)],
    })
    .concat();
    assert!(!suffix.contains("sk_live_CANARY_PROJECT"));
    assert_eq!(facts(&e).env_from, Provenance::LegacyUnknown);
    assert_eq!(facts(&e).scope_from, Provenance::LegacyUnknown);
    for source in [
        DeclarationSource::Owner,
        DeclarationSource::Signal,
        DeclarationSource::Usage,
        DeclarationSource::Default,
    ] {
        e.declaration_sources = Some(DeclarationSources {
            environment: source,
            scope: source,
            risk: DeclarationSource::Default,
            reversibility: DeclarationSource::Default,
        });
        let s = facts(&e);
        assert_eq!(s.env_from.as_str(), source.as_str());
        assert_eq!(s.scope_from.as_str(), source.as_str());
        assert_eq!(s.sensitive, Tri::Yes); // judged() could lower this: never use it.
    }
    e.agent_created_here = true;
    e.agent_allowed_before = true;
    assert_eq!(
        (facts(&e).made_by_agent, facts(&e).agent_used),
        (Recorded::Yes, Recorded::Yes)
    );
}
#[test]
fn providers_and_metadata_never_become_tokens() {
    for canary in [
        "sk_live_CANARY",
        "ghp_CANARY",
        "-----BEGIN CANARY",
        "github injection=yes",
    ] {
        let mut e = evidence();
        e.provider = Some(canary.into());
        let s = facts(&e);
        assert_eq!(s.provider, ProviderFact::Other);
        assert_eq!(ProviderFact::Listed(canary).as_str(), "other");
        let suffix = segments(&ContextV1 {
            action: ActionKind::Read,
            secrets: vec![s],
        })
        .concat();
        assert!(suffix.is_ascii());
        assert!(!suffix.contains(canary));
    }
}
#[test]
fn age_and_count_edges_and_conflicts() {
    let now = 4_000_000;
    for (delta, expected) in [
        (0, Age::Lt1d),
        (86_399, Age::Lt1d),
        (86_400, Age::Lt7d),
        (604_799, Age::Lt7d),
        (604_800, Age::Lt30d),
        (2_591_999, Age::Lt30d),
        (2_592_000, Age::None),
    ] {
        assert_eq!(age(EventAge::At(now - delta), now), expected);
    }
    assert_eq!(age(EventAge::At(now + 300), now), Age::Lt1d);
    assert_eq!(age(EventAge::At(now + 301), now), Age::Unknown);
    assert_eq!(age(EventAge::At(u64::MAX), u64::MAX - 299), Age::Lt1d);
    assert_eq!(age(EventAge::Unknown, now), Age::Unknown);
    assert_eq!(age(EventAge::None, now), Age::None);
    for (n, c) in [
        (0, Count::Zero),
        (1, Count::One),
        (2, Count::TwoToFour),
        (4, Count::TwoToFour),
        (5, Count::FivePlus),
        (u32::MAX, Count::FivePlus),
    ] {
        assert_eq!(count(UseCount::Known(n)), c);
    }
    assert_eq!(count(UseCount::Unknown), Count::Unknown);
    let mut e = evidence();
    e.owner_allowed_same_scope = UseCount::Known(1);
    e.owner_denied_same_scope = UseCount::Known(1);
    assert!(facts(&e).conflict);
    e.owner_denied_same_scope = UseCount::Unknown;
    assert!(!facts(&e).conflict);
    e.owner_denied_same_scope = UseCount::Known(0);
    assert!(!facts(&e).conflict);
}
#[test]
fn unicode_debug_and_budget_arithmetic() {
    assert_eq!(agent_text_bound("é"), 6);
    assert_eq!(agent_text_bound("aé"), 7);
    let input = ContextInput {
        model_text: "REQUEST_CANARY".into(),
        token_bound: 10,
        secrets: 1,
    };
    let debug = format!("{input:?}");
    assert!(!debug.contains("REQUEST_CANARY"));
    assert!(debug.contains("text_len"));
    assert_eq!(input.model_text(), "REQUEST_CANARY");
    assert_eq!(input.token_bound(), 10);
    assert_eq!(input.secrets(), 1);
    assert_eq!(input.contract_sha256(), contract_sha256());
    // Exact room edges use ASCII fallback, with no measured segment costs.
    let b = serde_json::json!({"max_len":512,"header_tokens":200,"segment_tokens":null});
    assert_eq!(budget_bound(&"x".repeat(312), &[], &b), (312, 312));
    assert_eq!(budget_bound(&"x".repeat(313), &[], &b), (313, 312));
    // Arithmetic-only samples are not measurements and never create a ContextInput.
    let b = serde_json::json!({"max_len":512,"header_tokens":200,"segment_tokens":null});
    assert_eq!(budget_bound("a", &[" x".into()], &b), (3, 312));
    let b = serde_json::json!({"max_len":512,"header_tokens":513,"segment_tokens":null});
    assert_eq!(budget_bound("", &[], &b), (u32::MAX, 0));
    let b = serde_json::json!({"max_len":512,"header_tokens":200,"segment_tokens":{" x":4294967296u64}});
    assert_eq!(budget_bound("", &[" x".into()], &b), (u32::MAX, 0));
    let b = serde_json::json!({"max_len":4294967295u64,"header_tokens":0,"segment_tokens":{" x":4294967295u64}});
    assert_eq!(budget_bound("a", &[" x".into()], &b), (u32::MAX, 0));
}

#[test]
fn golden_serialization_budget_and_repeat_determinism() {
    let fixtures = [
        include_str!("../../tests/fixtures/secret-decision-context-v1/serializer/age-lt1d.json"),
        include_str!("../../tests/fixtures/secret-decision-context-v1/serializer/age-lt30d.json"),
        include_str!("../../tests/fixtures/secret-decision-context-v1/serializer/age-lt7d.json"),
        include_str!("../../tests/fixtures/secret-decision-context-v1/serializer/age-none.json"),
        include_str!("../../tests/fixtures/secret-decision-context-v1/serializer/age-unknown.json"),
        include_str!("../../tests/fixtures/secret-decision-context-v1/serializer/canaries.json"),
        include_str!("../../tests/fixtures/secret-decision-context-v1/serializer/conflict.json"),
        include_str!("../../tests/fixtures/secret-decision-context-v1/serializer/count-0.json"),
        include_str!("../../tests/fixtures/secret-decision-context-v1/serializer/count-1.json"),
        include_str!("../../tests/fixtures/secret-decision-context-v1/serializer/count-2to4.json"),
        include_str!("../../tests/fixtures/secret-decision-context-v1/serializer/count-5plus.json"),
        include_str!(
            "../../tests/fixtures/secret-decision-context-v1/serializer/count-unknown.json"
        ),
        include_str!("../../tests/fixtures/secret-decision-context-v1/serializer/four.json"),
        include_str!("../../tests/fixtures/secret-decision-context-v1/serializer/legacy.json"),
        include_str!(
            "../../tests/fixtures/secret-decision-context-v1/serializer/long-request.json"
        ),
        include_str!("../../tests/fixtures/secret-decision-context-v1/serializer/one-unknown.json"),
        include_str!("../../tests/fixtures/secret-decision-context-v1/serializer/owner.json"),
        include_str!("../../tests/fixtures/secret-decision-context-v1/serializer/repeat.json"),
        include_str!("../../tests/fixtures/secret-decision-context-v1/serializer/three.json"),
        include_str!("../../tests/fixtures/secret-decision-context-v1/serializer/unicode.json"),
        include_str!("../../tests/fixtures/secret-decision-context-v1/serializer/zero.json"),
    ];
    for json in fixtures {
        let v: Value = serde_json::from_str(json).unwrap();
        let r = request(&v["request"]);
        let c = ContextV1 {
            action: ActionKind::parse(v["action"].as_str().unwrap()).unwrap(),
            secrets: v["secrets"]
                .as_array()
                .unwrap()
                .iter()
                .map(fixture_secret)
                .collect(),
        };
        let text = state(&r) + &segments(&c).concat();
        assert_eq!(text, v["model_text"].as_str().unwrap());
        assert!(!text.contains("Owner rule:"));
        let suffix = segments(&c).concat();
        for canary in ["sk_live_CANARY", "ghp_CANARY", "-----BEGIN CANARY"] {
            assert!(!suffix.contains(canary));
        }
        let (bound, room) = budget_bound(&state(&r), &segments(&c), &contract()["budget"]);
        assert_eq!(bound as u64, v["token_bound"].as_u64().unwrap());
        for _ in 0..2 {
            let result = build_input(&r, &c);
            let refusal = &v["refusal"];
            match refusal["kind"].as_str() {
                Some("NoSecrets") => assert_eq!(result.unwrap_err(), ContextRefusal::NoSecrets),
                Some("TooManySecrets") => assert_eq!(
                    result.unwrap_err(),
                    ContextRefusal::TooManySecrets(c.secrets.len())
                ),
                Some("OverBudget") => {
                    assert_eq!(room as u64, refusal["room"].as_u64().unwrap());
                    assert_eq!(
                        result.unwrap_err(),
                        ContextRefusal::OverBudget { bound, room }
                    );
                }
                None => {
                    let input = result.unwrap();
                    assert_eq!(input.model_text(), text);
                    assert_eq!(input.token_bound(), bound);
                }
                _ => panic!("bad golden refusal"),
            }
        }
    }
}
