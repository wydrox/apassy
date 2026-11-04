#![cfg(feature = "vault")]
//! Contract fixtures checked against product parsers and the built-in catalog.
use apassy::broker::action_kind::ActionKind;
use apassy::broker::bouncer::BouncerRequest;
use apassy::broker::context_brain::{self, ContextPin};
use apassy::broker::route_diagnostics::ReasonKind;
use apassy::broker::secret_facts::*;
use apassy::vault::providers;
use serde_json::Value;

const CONTRACT: &[u8] =
    include_bytes!("../tools/basemodel/contracts/secret-decision-context-v1.json");
const HASH: &str = include_str!("fixtures/secret-decision-context-v1/contract.sha256");
const DOC: &str = include_str!("../docs/contracts/secret-decision-context-v1.md");

fn canonical(v: &Value) -> String {
    match v {
        Value::Object(map) => {
            let sorted: std::collections::BTreeMap<_, _> = map.iter().collect();
            format!(
                "{{{}}}",
                sorted
                    .into_iter()
                    .map(|(k, v)| format!("{}:{}", serde_json::to_string(k).unwrap(), canonical(v)))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
        Value::Array(values) => format!(
            "[{}]",
            values.iter().map(canonical).collect::<Vec<_>>().join(",")
        ),
        Value::Number(n) => {
            assert!(n.is_u64() || n.is_i64(), "no floats in contract");
            n.to_string()
        }
        _ => serde_json::to_string(v).unwrap(),
    }
}

#[test]
fn exact_canonical_bytes_and_identity() {
    assert!(CONTRACT.is_ascii());
    let v: Value = serde_json::from_slice(CONTRACT).unwrap();
    assert_eq!(format!("{}\n", canonical(&v)).as_bytes(), CONTRACT);
    let digest = ring::digest::digest(&ring::digest::SHA256, CONTRACT);
    let actual: String = digest.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(HASH.len(), 64);
    assert_eq!(actual, HASH);
    assert_eq!(contract_json(), CONTRACT);
    assert_eq!(contract_sha256(), HASH);
    let measurement: Value = serde_json::from_slice(include_bytes!(
        "../docs/reviews/bouncer-context-token-budget-initial-2026-11-04.json"
    ))
    .unwrap();
    assert_eq!(v["budget"], measurement["proposed_budget"]);
    assert_eq!(v["budget"]["header_tokens"], 43);
}

#[test]
fn providers_equal_actual_nongeneric_builtin_catalog() {
    let v: Value = serde_json::from_slice(CONTRACT).unwrap();
    let ids: Vec<_> = v["providers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    let mut expected: Vec<_> = providers::builtin()
        .unwrap()
        .providers()
        .iter()
        .filter(|p| !p.is_generic())
        .map(|p| p.id.as_str())
        .collect();
    expected.sort_unstable();
    assert_eq!(ids, expected);
    for id in ids {
        assert!(!id.is_empty());
        assert!(
            id.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
        );
        assert!(!providers::find(id).unwrap().is_generic());
    }
}

// Deliberately exhaustive. Adding a ReasonKind requires a policy matrix review.
fn matrix_rows(reason: ReasonKind) -> &'static [&'static str] {
    match reason {
        ReasonKind::Other => &["Other"],
        ReasonKind::MissingTask => &["MissingTask"],
        ReasonKind::LowTaskMatch => &["LowTaskMatch"],
        ReasonKind::ModelUnavailable => &["ModelUnavailable"],
        ReasonKind::ModelTimeout => &["ModelTimeout"],
        ReasonKind::HookFlags => &["HookFlags"],
        ReasonKind::HookUnverified => &["HookUnverified"],
        ReasonKind::HookAmbiguous => &["HookAmbiguous"],
        ReasonKind::NotProject => &["NotProject"],
        ReasonKind::AlwaysAsk => &["AlwaysAsk"],
        ReasonKind::Production => &[
            "Production.write_admin",
            "Production.read_only_remote_brain",
            "Production.read_only_local_brain",
        ],
        ReasonKind::ForeignHost => &["ForeignHost.database", "ForeignHost.other"],
        ReasonKind::ForeignProject => &["ForeignProject"],
        ReasonKind::MissingDeclaration => &["MissingDeclaration", "MissingDeclaration.production"],
        ReasonKind::UnfitAnswer => &["UnfitAnswer"],
        ReasonKind::OneTimeCode => &["OneTimeCode"],
        ReasonKind::ModelUnsure => &["ModelUnsure"],
        ReasonKind::AccessCheck => &["AccessCheck"],
        ReasonKind::Connector => &["Connector"],
        ReasonKind::BrowserFill => &["BrowserFill"],
        ReasonKind::CloudAgent => &["CloudAgent"],
        ReasonKind::ModelAllowed => &["ModelAllowed"],
        ReasonKind::RememberedAnswer => &["RememberedAnswer"],
        ReasonKind::RememberedPattern => &["RememberedPattern"],
    }
}

#[test]
fn every_reason_and_policy_split_has_a_documented_row() {
    use ReasonKind::*;
    let reasons = [
        Other,
        MissingTask,
        LowTaskMatch,
        ModelUnavailable,
        ModelTimeout,
        HookFlags,
        HookUnverified,
        HookAmbiguous,
        NotProject,
        AlwaysAsk,
        Production,
        ForeignHost,
        ForeignProject,
        MissingDeclaration,
        UnfitAnswer,
        OneTimeCode,
        ModelUnsure,
        AccessCheck,
        Connector,
        BrowserFill,
        CloudAgent,
        ModelAllowed,
        RememberedAnswer,
        RememberedPattern,
    ];
    let mut rows = std::collections::BTreeSet::new();
    for reason in reasons {
        for row in matrix_rows(reason) {
            assert!(
                DOC.lines()
                    .any(|line| line.starts_with(&format!("| `{row}` |"))),
                "missing row: {row}"
            );
            assert!(rows.insert(*row), "duplicate row mapping: {row}");
        }
    }
    assert_eq!(rows.len(), 28);
}

#[test]
fn measured_golden_input_matches_the_wire_request() {
    // Exercise the real budget-checked builder after the measured contract revision.
    let golden: Value = serde_json::from_slice(include_bytes!(
        "fixtures/secret-decision-context-v1/serializer/one-unknown.json"
    ))
    .unwrap();
    let request = &golden["request"];
    let text = |name: &str| request[name].as_str().unwrap().to_owned();
    let request = BouncerRequest {
        user_request: text("user_request"),
        command: text("command"),
        purpose: text("purpose"),
        instruction: text("instruction"),
        relative_dir: text("relative_dir"),
        env_names: vec![],
        task_provenance: text("task_provenance"),
    };
    let context = ContextV1 {
        action: ActionKind::Read,
        secrets: vec![SecretFactsV1 {
            kind: KindFact::ApiKey,
            provider: ProviderFact::None,
            env: EnvFact::Unknown,
            env_from: Provenance::None,
            scope: ScopeFact::Unknown,
            scope_from: Provenance::None,
            sensitive: Tri::Unknown,
            project: ProjectFit::Undeclared,
            hosts: HostFit::None,
            made_by_agent: Recorded::NotRecorded,
            agent_used: Recorded::NotRecorded,
            secret_changed: Age::None,
            access_changed: Age::None,
            owner_allowed: Count::Zero,
            owner_denied: Count::Zero,
            owner_denied_other: Count::Zero,
            conflict: false,
        }],
    };
    let wire: Value = serde_json::from_slice(include_bytes!(
        "fixtures/secret-decision-context-v1/wire/request.json"
    ))
    .unwrap();
    assert_eq!(wire["model_text"], golden["model_text"]);
    let input = build_input(&request, &context).expect("measured golden input fits");
    assert!(golden["refusal"].is_null());
    assert_eq!(
        u64::from(input.token_bound()),
        golden["token_bound"].as_u64().unwrap()
    );
    let pin = ContextPin {
        heads: wire["heads"].as_str().unwrap().into(),
        model: "apassy-context-v1+a1b2c3d4".into(),
    };
    assert_eq!(context_brain::request_body(&input, &pin), wire);
    assert_eq!(wire.as_object().unwrap().len(), 4);
}

#[test]
fn manifest_and_wire_identity_are_aligned() {
    let manifest: Value = serde_json::from_slice(include_bytes!(
        "fixtures/secret-decision-context-v1/wire/head-manifest.json"
    ))
    .unwrap();
    let request: Value = serde_json::from_slice(include_bytes!(
        "fixtures/secret-decision-context-v1/wire/request.json"
    ))
    .unwrap();
    let contract: Value = serde_json::from_slice(CONTRACT).unwrap();
    assert_eq!(manifest["context_contract_sha256"], HASH);
    assert_eq!(manifest["question"], context_brain::QUESTION);
    assert_eq!(
        manifest["tokenizer_sha256"],
        contract["tokenizer"]["sha256"]
    );
    assert_eq!(manifest["base"]["revision"], contract["base"]["revision"]);
    assert_eq!(manifest["checkpoint"]["sha256"], request["heads"]);
    assert_eq!(request["contract_sha256"], HASH);
    assert_eq!(request.as_object().unwrap().len(), 4);
}
