//! Contract schema and validation tests.
//! These tests do not claim runtime authorization, encryption, or live connectors.

use apassy::contracts::{
    ActiveRuleRecord, AgentRequest, BoundDigest, CONTRACT_VERSION, ClauseDisposition,
    CredentialKind, CredentialMetadata, Decision, DecisionEnvelope, DraftStatus, ErrorCode,
    EventEnvelope, EventKind, MAX_CLAUSE_COUNT, MAX_CLAUSE_TEXT_LEN, MAX_DIAGNOSTIC_LEN,
    MAX_PARAMETER_COUNT, MAX_PARAMETER_TEXT_LEN, MAX_USAGE_LIMIT, OwnerConfirmation, RuleDraft,
    Severity, activate, parse_json, parse_json_value, to_json,
};
use serde_json::{Value, json};

fn assert_code<T: std::fmt::Debug>(
    result: Result<T, apassy::contracts::ContractError>,
    code: ErrorCode,
) {
    match result {
        Ok(value) => panic!("expected {code}, got success {value:?}"),
        Err(err) => assert_eq!(err.code(), code, "{err}"),
    }
}

fn assert_request_code(patch: impl FnOnce(&mut Value), code: ErrorCode) {
    let mut value = request_json();
    patch(&mut value);
    assert_code(parse_json_value::<AgentRequest>(&value), code);
}

fn credential_json() -> Value {
    json!({
        "contract_version": 1,
        "id": "cred_reporting",
        "kind": "api_key",
        "revision": 1,
        "label": "Project A reporting service",
        "tags": ["project_a"],
        "details": {
            "type": "api_key",
            "service_id": "svc_reporting_api"
        },
        "created_at": 1_700_000_000u64,
        "updated_at": 1_700_000_100u64
    })
}

fn ready_draft_json() -> Value {
    json!({
        "contract_version": 1,
        "id": "rule_project_a",
        "draft_version": 1,
        "original_text": "My reporting agent can read sales summaries from the staging database for Project A until Friday. Never use production. Ask me when the request does not fit the task.",
        "clauses": [
            {"index": 1, "text": "My reporting agent", "disposition": "enforceable_restriction"},
            {"index": 2, "text": "can read sales summaries", "disposition": "enforceable_restriction"},
            {"index": 3, "text": "from the staging database", "disposition": "enforceable_restriction"},
            {"index": 4, "text": "for Project A", "disposition": "contextual_check"},
            {"index": 5, "text": "until Friday", "disposition": "enforceable_restriction"},
            {"index": 6, "text": "Never use production", "disposition": "enforceable_restriction"},
            {"index": 7, "text": "Ask me when the request does not fit the task", "disposition": "contextual_check"}
        ],
        "restrictions": [
            {"restriction": "agent", "clause_index": 1, "agent_id": "agt_reporter"},
            {"restriction": "operation", "clause_index": 2, "operation": "read_sales_summary"},
            {"restriction": "destination", "clause_index": 3, "destination_id": "dst_staging_db"},
            {
                "restriction": "time_window",
                "clause_index": 5,
                "not_before": 1_700_000_000u64,
                "not_after": 1_800_000_000u64,
                "time_zone": "UTC"
            },
            {"restriction": "explicit_denial", "clause_index": 6, "reason_code": "production_forbidden"}
        ],
        "context_checks": [
            {"clause_index": 4, "dimension": "task_alignment", "on_failure": "require_approval"},
            {"clause_index": 7, "dimension": "task_alignment", "on_failure": "require_approval"}
        ],
        "unresolved_issues": [],
        "agent": {"id": "agt_reporter", "enrollment_revision": 1},
        "credential": {"id": "cred_reporting", "revision": 1, "kind": "database"},
        "created_at": 1_700_000_000u64
    })
}

fn confirmation_json() -> Value {
    json!({
        "contract_version": 1,
        "draft_id": "rule_project_a",
        "draft_version": 1,
        "owner_id": "own_local",
        "confirmed_at": 1_700_001_000u64
    })
}

fn denial_draft_json(clause_count: usize) -> Value {
    let clauses: Vec<Value> = (1..=clause_count)
        .map(|i| {
            json!({
                "index": i,
                "text": format!("clause {i}"),
                "disposition": "enforceable_restriction"
            })
        })
        .collect();
    let restrictions: Vec<Value> = (1..=clause_count)
        .map(|i| {
            json!({
                "restriction": "explicit_denial",
                "clause_index": i,
                "reason_code": "denied"
            })
        })
        .collect();
    let mut draft = ready_draft_json();
    draft["clauses"] = Value::Array(clauses);
    draft["restrictions"] = Value::Array(restrictions);
    draft["context_checks"] = json!([]);
    draft["unresolved_issues"] = json!([]);
    draft
}

fn event_json() -> Value {
    json!({
        "contract_version": 1,
        "event_id": "ev_denied_1",
        "kind": "request_denied",
        "severity": "error",
        "decision": {
            "contract_version": 1,
            "request_id": "req_report_1",
            "agent_id": "agt_reporter",
            "credential_id": "cred_reporting",
            "credential_revision": 1,
            "policy_version": 1,
            "decision": "deny",
            "reason_code": "production_forbidden",
            "created_at": 1_710_000_000u64
        },
        "occurred_at": 1_710_000_001u64,
        "diagnostic": "Blocked: production destination is denied"
    })
}

fn request_json() -> Value {
    json!({
        "contract_version": 1,
        "request_id": "req_report_1",
        "session": {
            "id": "ses_reporter_1",
            "agent_id": "agt_reporter",
            "epoch": 1,
            "not_before": 1_700_000_000u64,
            "expires_at": 1_800_000_000u64
        },
        "agent": {"id": "agt_reporter", "enrollment_revision": 1},
        "credential": {"id": "cred_reporting", "revision": 1, "kind": "database"},
        "policy": {"id": "rule_project_a", "version": 1},
        "connector_capability_version": 1,
        "epoch": 1,
        "operation": "read_sales_summary",
        "destination": {"id": "dst_staging_db", "kind": "registered_database"},
        "parameters": {
            "project": {"type": "identifier", "value": "project_a"},
            "row_limit": {"type": "integer", "value": 20}
        },
        "created_at": 1_710_000_000u64
    })
}

#[test]
fn frozen_ui_types_use_snake_case_and_version_one() {
    assert_eq!(CONTRACT_VERSION, 1);
    assert_eq!(
        CredentialKind::ALL,
        [
            CredentialKind::ApiKey,
            CredentialKind::Login,
            CredentialKind::SshKey,
            CredentialKind::Database,
            CredentialKind::Custom,
        ]
    );
    assert_eq!(CredentialKind::ApiKey.label(), "API key");
    assert_eq!(CredentialKind::Login.label(), "Login");
    assert_eq!(CredentialKind::SshKey.label(), "SSH key");
    assert_eq!(CredentialKind::Database.label(), "Database");
    assert_eq!(CredentialKind::Custom.label(), "Custom");
    assert_eq!(Decision::Allow.label(), "Allow");
    assert_eq!(Decision::RequireApproval.label(), "Require approval");
    assert_eq!(Decision::Deny.label(), "Deny");
    assert!(CredentialKind::ApiKey.supports_mediated_use());
    assert!(CredentialKind::Database.supports_mediated_use());
    assert!(!CredentialKind::Login.supports_mediated_use());
    assert!(!CredentialKind::SshKey.supports_mediated_use());
    assert!(!CredentialKind::Custom.supports_mediated_use());
    assert_eq!(
        serde_json::to_string(&CredentialKind::ApiKey).expect("kind json"),
        "\"api_key\""
    );
    assert_eq!(
        serde_json::to_string(&CredentialKind::SshKey).expect("kind json"),
        "\"ssh_key\""
    );
    assert_eq!(
        serde_json::to_string(&Decision::RequireApproval).expect("decision json"),
        "\"require_approval\""
    );
}

#[test]
fn credential_metadata_accepts_five_kinds_without_secrets() {
    let parsed: CredentialMetadata =
        parse_json_value(&credential_json()).expect("api key metadata");
    assert_eq!(parsed.kind(), CredentialKind::ApiKey);
    assert_eq!(parsed.revision().get(), 1);
    assert_eq!(parsed.id().as_str(), "cred_reporting");

    let mut login = credential_json();
    login["kind"] = json!("login");
    login["details"] = json!({"type": "login", "service_id": "svc_webmail", "username": "owner"});
    parse_json_value::<CredentialMetadata>(&login).expect("login metadata");

    let mut ssh = credential_json();
    ssh["kind"] = json!("ssh_key");
    ssh["details"] = json!({"type": "ssh_key", "comment": "laptop-2026"});
    parse_json_value::<CredentialMetadata>(&ssh).expect("ssh metadata");

    let mut database = credential_json();
    database["kind"] = json!("database");
    database["details"] = json!({
        "type": "database",
        "server_id": "svc_staging_db",
        "database_name": "sales"
    });
    parse_json_value::<CredentialMetadata>(&database).expect("database metadata");

    let mut custom = credential_json();
    custom["kind"] = json!("custom");
    custom["details"] = json!({
        "type": "custom",
        "fields": [
            {"name": "account_number", "secret": true},
            {"name": "branch", "secret": false}
        ]
    });
    parse_json_value::<CredentialMetadata>(&custom).expect("custom metadata");
}

#[test]
fn credential_metadata_rejects_unknown_fields_invalid_ids_and_zero_versions() {
    let mut unknown = credential_json();
    unknown["password"] = json!("super-secret");
    assert_code(
        parse_json_value::<CredentialMetadata>(&unknown),
        ErrorCode::UnknownField,
    );

    let mut bad_id = credential_json();
    bad_id["id"] = json!("Cred/../root");
    assert_code(
        parse_json_value::<CredentialMetadata>(&bad_id),
        ErrorCode::InvalidId,
    );

    let mut zero = credential_json();
    zero["revision"] = json!(0);
    assert_code(
        parse_json_value::<CredentialMetadata>(&zero),
        ErrorCode::ZeroVersion,
    );

    let mut order = credential_json();
    order["created_at"] = json!(1_800_000_000u64);
    order["updated_at"] = json!(1_700_000_000u64);
    assert_code(
        parse_json_value::<CredentialMetadata>(&order),
        ErrorCode::InvalidTimeOrdering,
    );

    let mut mismatch = credential_json();
    mismatch["kind"] = json!("login");
    assert_code(
        parse_json_value::<CredentialMetadata>(&mismatch),
        ErrorCode::InvalidRequestBounds,
    );

    let mut notes = credential_json();
    notes["notes"] = json!("-----BEGIN PRIVATE KEY-----abc");
    assert_code(
        parse_json_value::<CredentialMetadata>(&notes),
        ErrorCode::InvalidRequestBounds,
    );
}

#[test]
fn rule_draft_accepts_covered_clauses_and_unresolved_issues() {
    let draft: RuleDraft = parse_json_value(&ready_draft_json()).expect("ready draft");
    assert_eq!(draft.status(), DraftStatus::ReadyForReview);
    assert_eq!(draft.clauses().len(), 7);
    assert!(draft.unresolved_issues().is_empty());
    assert_eq!(
        draft.clauses()[3].disposition,
        ClauseDisposition::ContextualCheck
    );

    let mut unresolved = ready_draft_json();
    unresolved["clauses"][4]["disposition"] = json!("unresolved_issue");
    unresolved["restrictions"] = json!([
        {"restriction": "agent", "clause_index": 1, "agent_id": "agt_reporter"},
        {"restriction": "operation", "clause_index": 2, "operation": "read_sales_summary"},
        {"restriction": "destination", "clause_index": 3, "destination_id": "dst_staging_db"},
        {"restriction": "explicit_denial", "clause_index": 6, "reason_code": "production_forbidden"}
    ]);
    unresolved["unresolved_issues"] = json!([{
        "clause_index": 5,
        "code": "ambiguous_deadline",
        "detail": "until Friday needs an exact timestamp and time zone"
    }]);
    let draft: RuleDraft = parse_json_value(&unresolved).expect("draft with questions");
    assert_eq!(draft.status(), DraftStatus::NeedsClarification);
}

#[test]
fn rule_draft_rejects_uncovered_and_mismatched_clauses() {
    let mut uncovered = ready_draft_json();
    uncovered["restrictions"] = json!([
        {"restriction": "agent", "clause_index": 1, "agent_id": "agt_reporter"}
    ]);
    assert_code(
        parse_json_value::<RuleDraft>(&uncovered),
        ErrorCode::UncoveredClause,
    );

    let mut empty = ready_draft_json();
    empty["clauses"] = json!([]);
    empty["restrictions"] = json!([]);
    empty["context_checks"] = json!([]);
    assert_code(
        parse_json_value::<RuleDraft>(&empty),
        ErrorCode::UncoveredClause,
    );

    let mut mismatch = ready_draft_json();
    mismatch["clauses"][0]["disposition"] = json!("contextual_check");
    assert_code(
        parse_json_value::<RuleDraft>(&mismatch),
        ErrorCode::UncoveredClause,
    );

    let mut zero_window = ready_draft_json();
    zero_window["restrictions"][3]["not_after"] = json!(1_700_000_000u64);
    assert_code(
        parse_json_value::<RuleDraft>(&zero_window),
        ErrorCode::InvalidTimeOrdering,
    );

    let mut fail_open = ready_draft_json();
    fail_open["context_checks"][0]["on_failure"] = json!("allow");
    assert_code(
        parse_json_value::<RuleDraft>(&fail_open),
        ErrorCode::InvalidRequestBounds,
    );

    let mut zero_limit = ready_draft_json();
    zero_limit["clauses"] = json!([
        {"index": 1, "text": "limit uses", "disposition": "enforceable_restriction"}
    ]);
    zero_limit["restrictions"] = json!([{
        "restriction": "usage_limit",
        "clause_index": 1,
        "max_uses": 0
    }]);
    zero_limit["context_checks"] = json!([]);
    zero_limit["unresolved_issues"] = json!([]);
    assert_code(
        parse_json_value::<RuleDraft>(&zero_limit),
        ErrorCode::ZeroLimit,
    );
}

#[test]
fn rule_draft_enforces_clause_count_usage_limit_and_issue_detail_bounds() {
    parse_json_value::<RuleDraft>(&denial_draft_json(MAX_CLAUSE_COUNT)).expect("max clause count");
    assert_code(
        parse_json_value::<RuleDraft>(&denial_draft_json(MAX_CLAUSE_COUNT + 1)),
        ErrorCode::InvalidRequestBounds,
    );

    let mut over_limit = denial_draft_json(1);
    over_limit["restrictions"] = json!([{
        "restriction": "usage_limit",
        "clause_index": 1,
        "max_uses": MAX_USAGE_LIMIT + 1
    }]);
    assert_code(
        parse_json_value::<RuleDraft>(&over_limit),
        ErrorCode::InvalidRequestBounds,
    );

    let mut unresolved = ready_draft_json();
    unresolved["clauses"][4]["disposition"] = json!("unresolved_issue");
    unresolved["restrictions"] = json!([
        {"restriction": "agent", "clause_index": 1, "agent_id": "agt_reporter"},
        {"restriction": "operation", "clause_index": 2, "operation": "read_sales_summary"},
        {"restriction": "destination", "clause_index": 3, "destination_id": "dst_staging_db"},
        {"restriction": "explicit_denial", "clause_index": 6, "reason_code": "production_forbidden"}
    ]);
    unresolved["unresolved_issues"] = json!([{
        "clause_index": 5,
        "code": "ambiguous_deadline",
        "detail": "a".repeat(MAX_CLAUSE_TEXT_LEN)
    }]);
    parse_json_value::<RuleDraft>(&unresolved).expect("max clause-text issue detail");
    unresolved["unresolved_issues"][0]["detail"] = json!("a".repeat(MAX_CLAUSE_TEXT_LEN + 1));
    assert_code(
        parse_json_value::<RuleDraft>(&unresolved),
        ErrorCode::InvalidText,
    );
}

#[test]
fn activation_requires_matching_confirmation_and_resolved_clauses() {
    let draft: RuleDraft = parse_json_value(&ready_draft_json()).expect("draft");
    let confirmation: OwnerConfirmation =
        parse_json_value(&confirmation_json()).expect("confirmation");

    assert_code(activate(&draft, None), ErrorCode::MissingConfirmation);

    let mut other_version = confirmation_json();
    other_version["draft_version"] = json!(2);
    let changed: OwnerConfirmation = parse_json_value(&other_version).expect("other confirmation");
    assert_code(
        activate(&draft, Some(&changed)),
        ErrorCode::ChangedDraftBinding,
    );

    let mut unresolved = ready_draft_json();
    unresolved["clauses"][4]["disposition"] = json!("unresolved_issue");
    unresolved["restrictions"] = json!([
        {"restriction": "agent", "clause_index": 1, "agent_id": "agt_reporter"},
        {"restriction": "operation", "clause_index": 2, "operation": "read_sales_summary"},
        {"restriction": "destination", "clause_index": 3, "destination_id": "dst_staging_db"},
        {"restriction": "explicit_denial", "clause_index": 6, "reason_code": "production_forbidden"}
    ]);
    unresolved["unresolved_issues"] = json!([{
        "clause_index": 5,
        "code": "ambiguous_deadline",
        "detail": "until Friday needs an exact timestamp and time zone"
    }]);
    let blocked: RuleDraft = parse_json_value(&unresolved).expect("unresolved draft");
    assert_code(
        activate(&blocked, Some(&confirmation)),
        ErrorCode::UnresolvedClause,
    );

    let record = activate(&draft, Some(&confirmation)).expect("activation binding");
    assert_eq!(record.policy_version().get(), 1);
    assert_eq!(record.draft_id().as_str(), "rule_project_a");
    let encoded = to_json(&record).expect("active json");
    let parsed: ActiveRuleRecord = parse_json(&encoded).expect("active round-trip");
    assert_eq!(parsed.confirmation().owner_id().as_str(), "own_local");

    let mut other_id = confirmation_json();
    other_id["draft_id"] = json!("rule_other");
    let other: OwnerConfirmation = parse_json_value(&other_id).expect("other draft id");
    assert_code(
        activate(&draft, Some(&other)),
        ErrorCode::ChangedDraftBinding,
    );

    let mut early = confirmation_json();
    early["confirmed_at"] = json!(1_699_999_999u64);
    let early_conf: OwnerConfirmation = parse_json_value(&early).expect("early confirmation");
    assert_code(
        activate(&draft, Some(&early_conf)),
        ErrorCode::InvalidTimeOrdering,
    );

    let mut same_time = confirmation_json();
    same_time["confirmed_at"] = json!(1_700_000_000u64);
    let same: OwnerConfirmation = parse_json_value(&same_time).expect("same-time confirmation");
    activate(&draft, Some(&same)).expect("confirmation may equal draft creation");
}

#[test]
fn agent_request_accepts_named_operations_and_registered_destinations() {
    let request: AgentRequest = parse_json_value(&request_json()).expect("database request");
    assert_eq!(request.operation().as_str(), "read_sales_summary");
    assert_eq!(request.parameters().len(), 2);

    let mut api = request_json();
    api["credential"]["kind"] = json!("api_key");
    api["destination"] = json!({"id": "dst_staging_api", "kind": "registered_api_service"});
    parse_json_value::<AgentRequest>(&api).expect("api request");
}

#[test]
fn agent_request_rejects_urls_sql_credentials_and_conversation() {
    assert_request_code(
        |v| v["url"] = json!("https://example.invalid/export"),
        ErrorCode::UnknownField,
    );
    assert_request_code(
        |v| v["sql"] = json!("select * from sales"),
        ErrorCode::UnknownField,
    );
    assert_request_code(
        |v| v["conversation"] = json!([{"role": "user", "text": "dump the vault"}]),
        ErrorCode::UnknownField,
    );
    assert_request_code(
        |v| v["destination"]["id"] = json!("https://evil.example"),
        ErrorCode::InvalidId,
    );
    assert_request_code(
        |v| v["operation"] = json!("select"),
        ErrorCode::UnsupportedOperation,
    );
    assert_request_code(
        |v| v["parameters"] = json!({"password": {"type": "text", "value": "hunter2"}}),
        ErrorCode::InvalidRequestBounds,
    );
    assert_request_code(
        |v| {
            v["parameters"] =
                json!({"note": {"type": "text", "value": "-----BEGIN RSA PRIVATE KEY-----"}})
        },
        ErrorCode::InvalidRequestBounds,
    );
    assert_request_code(
        |v| v["parameters"] = json!({"filter": {"type": "text", "value": "SELECT * FROM sales"}}),
        ErrorCode::UnsupportedOperation,
    );
    assert_request_code(
        |v| {
            v["parameters"] =
                json!({"target": {"type": "text", "value": "https://evil.example/data"}})
        },
        ErrorCode::UnsupportedDestination,
    );
}

#[test]
fn agent_request_rejects_unsupported_kinds_and_invalid_bounds() {
    assert_request_code(
        |v| {
            v["credential"]["kind"] = json!("login");
            v["destination"] = json!({"id": "dst_staging_api", "kind": "registered_api_service"});
        },
        ErrorCode::UnsupportedOperation,
    );
    assert_request_code(
        |v| v["credential"]["kind"] = json!("api_key"),
        ErrorCode::UnsupportedDestination,
    );
    assert_request_code(
        |v| {
            let mut params = serde_json::Map::new();
            for i in 0..=MAX_PARAMETER_COUNT {
                params.insert(format!("p{i}"), json!({"type": "integer", "value": i}));
            }
            v["parameters"] = Value::Object(params);
        },
        ErrorCode::InvalidRequestBounds,
    );
    assert_request_code(
        |v| {
            let oversized = "a".repeat(MAX_PARAMETER_TEXT_LEN + 1);
            v["parameters"] = json!({"note": {"type": "text", "value": oversized}});
        },
        ErrorCode::InvalidText,
    );
    assert_request_code(|v| v["epoch"] = json!(0), ErrorCode::ZeroVersion);
    assert_request_code(
        |v| v["session"]["agent_id"] = json!("agt_other"),
        ErrorCode::InvalidRequestBounds,
    );
    assert_request_code(
        |v| v["created_at"] = json!(1_900_000_000u64),
        ErrorCode::InvalidTimeOrdering,
    );
    assert_request_code(
        |v| v["contract_version"] = json!(2),
        ErrorCode::ContractVersionMismatch,
    );
    // An epoch mismatch and the endpoints of the time window.
    assert_request_code(
        |v| v["agent"]["id"] = json!("agt_other"),
        ErrorCode::InvalidRequestBounds,
    );
    assert_request_code(|v| v["epoch"] = json!(2), ErrorCode::InvalidRequestBounds);

    let mut at_start = request_json();
    at_start["created_at"] = json!(1_700_000_000u64);
    parse_json_value::<AgentRequest>(&at_start).expect("created_at may equal not_before");

    assert_request_code(
        |v| v["created_at"] = json!(1_800_000_000u64),
        ErrorCode::InvalidTimeOrdering,
    );
}

#[test]
fn canonical_request_json_is_deterministic_and_is_not_a_digest() {
    let mut first = request_json();
    first["parameters"] = json!({
        "project": {"type": "identifier", "value": "project_a"},
        "row_limit": {"type": "integer", "value": 20}
    });
    let mut second = request_json();
    second["parameters"] = json!({
        "row_limit": {"type": "integer", "value": 20},
        "project": {"type": "identifier", "value": "project_a"}
    });
    let left: AgentRequest = parse_json_value(&first).expect("first request");
    let right: AgentRequest = parse_json_value(&second).expect("second request");
    let left_bytes = left.canonical_json_bytes().expect("left canonical");
    let right_bytes = right.canonical_json_bytes().expect("right canonical");
    assert_eq!(left_bytes, right_bytes);
    assert_eq!(left_bytes, left.canonical_json_bytes().expect("repeat"));

    let text = std::str::from_utf8(&left_bytes).expect("utf8");
    let expected = concat!(
        "{\"contract_version\":1,\"request_id\":\"req_report_1\",",
        "\"session\":{\"id\":\"ses_reporter_1\",\"agent_id\":\"agt_reporter\",\"epoch\":1,",
        "\"not_before\":1700000000,\"expires_at\":1800000000},",
        "\"agent\":{\"id\":\"agt_reporter\",\"enrollment_revision\":1},",
        "\"credential\":{\"id\":\"cred_reporting\",\"revision\":1,\"kind\":\"database\"},",
        "\"policy\":{\"id\":\"rule_project_a\",\"version\":1},",
        "\"connector_capability_version\":1,\"epoch\":1,\"operation\":\"read_sales_summary\",",
        "\"destination\":{\"id\":\"dst_staging_db\",\"kind\":\"registered_database\"},",
        "\"parameters\":{\"project\":{\"type\":\"identifier\",\"value\":\"project_a\"},",
        "\"row_limit\":{\"type\":\"integer\",\"value\":20}},\"created_at\":1710000000}"
    );
    assert_eq!(text, expected);

    let digest = BoundDigest::bind("sha256", &[0xab; 32]).expect("opaque digest");
    assert_eq!(digest.octets().len(), 32);
    assert_eq!(digest.algorithm().as_str(), "sha256");
    assert_ne!(digest.octets_hex().as_bytes(), left_bytes.as_slice());
    assert_eq!(left_bytes.first().copied(), Some(b'{'));
    assert_eq!(left_bytes, to_json(&left).expect("to_json").into_bytes());

    let mut invalid = request_json();
    invalid["session"]["agent_id"] = json!("agt_other");
    let representation: AgentRequest =
        serde_json::from_value(invalid).expect("unvalidated representation");
    assert_code(
        representation.canonical_json_bytes(),
        ErrorCode::InvalidRequestBounds,
    );
}

#[test]
fn bound_digest_rejects_invalid_lengths_and_does_not_hash() {
    assert_code(
        BoundDigest::bind("sha256", &[0u8; 15]),
        ErrorCode::InvalidRequestBounds,
    );
    assert_code(
        BoundDigest::bind("sha256", &[0u8; 65]),
        ErrorCode::InvalidRequestBounds,
    );
    let digest = BoundDigest::bind("sha256", &[0x11; 16]).expect("min digest");
    let json = to_json(&digest).expect("digest json");
    let parsed: BoundDigest = parse_json(&json).expect("digest round-trip");
    assert_eq!(parsed.octets(), digest.octets());

    let mut odd = json!({"algorithm": "sha256", "octets_hex": "abc"});
    assert_code(
        parse_json_value::<BoundDigest>(&odd),
        ErrorCode::InvalidRequestBounds,
    );
    odd["extra"] = json!(true);
    odd["octets_hex"] = Value::String("aa".repeat(16));
    assert_code(
        parse_json_value::<BoundDigest>(&odd),
        ErrorCode::UnknownField,
    );
}

#[test]
fn event_and_decision_envelopes_are_bounded() {
    let event = event_json();
    let parsed_decision: DecisionEnvelope =
        parse_json_value(&event["decision"]).expect("decision envelope");
    assert_eq!(parsed_decision.decision(), Decision::Deny);

    let parsed: EventEnvelope = parse_json_value(&event).expect("event envelope");
    assert_eq!(parsed.kind(), EventKind::RequestDenied);
    assert_eq!(parsed.severity(), Severity::Error);

    let mut at_bound = event.clone();
    at_bound["diagnostic"] = json!("a".repeat(MAX_DIAGNOSTIC_LEN));
    parse_json_value::<EventEnvelope>(&at_bound).expect("max diagnostic");

    let mut over_bound = event.clone();
    over_bound["diagnostic"] = json!("a".repeat(MAX_DIAGNOSTIC_LEN + 1));
    assert_code(
        parse_json_value::<EventEnvelope>(&over_bound),
        ErrorCode::InvalidText,
    );

    let mut secret_field = event.clone();
    secret_field["raw_conversation"] = json!("full prompt");
    assert_code(
        parse_json_value::<EventEnvelope>(&secret_field),
        ErrorCode::UnknownField,
    );

    let mut wrap = event.clone();
    wrap["kind"] = json!("approval_requested");
    assert_code(
        parse_json_value::<EventEnvelope>(&wrap),
        ErrorCode::InvalidRequestBounds,
    );

    let mut order = event;
    order["occurred_at"] = json!(1_700_000_000u64);
    assert_code(
        parse_json_value::<EventEnvelope>(&order),
        ErrorCode::InvalidTimeOrdering,
    );
}

// ---------------------------------------------------------------------------------------
// node-pairing-v1 and push-gateway-v1 (docs/contracts/, implementation plan S2–S3, N0).
// The contracts are not implemented yet: these checks hold a reference reader of each
// contract, recompute its vectors, and check that the contract text carries them. Units
// N3 and N5 check their code against the same vectors.
// ---------------------------------------------------------------------------------------

#[cfg(feature = "vault")]
const NODE_PAIRING_CONTRACT: &str = include_str!("../docs/contracts/node-pairing-v1.md");
#[cfg(feature = "vault")]
const PUSH_GATEWAY_CONTRACT: &str = include_str!("../docs/contracts/push-gateway-v1.md");

#[cfg(feature = "vault")]
mod node_pairing_v1 {
    //! A reference reader of the fragment grammar of node-pairing-v1 sections 5 to 7.
    use apassy::sync::decode_b64u;
    use std::net::{Ipv4Addr, Ipv6Addr};

    pub const PIN: &str = "u7Ri74l_xMBm74XnZDWpOC6Z4p6n4aUqwWmsV6firLE";
    pub const DER_SHA256: &str = "bbb462ef897fc4c066ef85e76435a9382e99e29ea7e1a52ac169ac57a7e2acb1";
    pub const ORIGIN: &str = "https://100.64.0.7:8444";
    pub const LINK_CODE: &str =
        "apassy_lnk_t_7k2m5q4x3c_abababababababababababababababababababababababababababababababab";
    pub const TEAM_CODE: &str =
        "apassy_tcd_cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
    pub const NAME: &str = "Mac mini “Studio”";
    pub const NAME_ENCODED: &str = "Mac%20mini%20%E2%80%9CStudio%E2%80%9D";
    pub const ALT: &str = "apassy-mini.tail0123.ts.net,[fd7a:115c:a1e0::7]:8444";
    pub const QID: &str = "oKGio6SlpqeoqaqrrK2urw";
    pub const HANDOFF_SECRET: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
    pub const MAC_PUBLIC: &str =
        "BAIX5hfwtkQ5KCePlpmeaaI6TywVK99tbN9m5bgCgtTtGUp968uXcS0t2jyoWqh2Wlb0X8dYWZZS8ol8ZTBuV5Q";
    pub const FULL_LINK: &str = "https://100.64.0.7:8444/link#apassy_lnk_t_7k2m5q4x3c_abababababababababababababababababababababababababababababababab&pin=u7Ri74l_xMBm74XnZDWpOC6Z4p6n4aUqwWmsV6firLE&alt=apassy-mini.tail0123.ts.net,[fd7a:115c:a1e0::7]:8444&name=Mac%20mini%20%E2%80%9CStudio%E2%80%9D&handoff=2.oKGio6SlpqeoqaqrrK2urw.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8.BAIX5hfwtkQ5KCePlpmeaaI6TywVK99tbN9m5bgCgtTtGUp968uXcS0t2jyoWqh2Wlb0X8dYWZZS8ol8ZTBuV5Q";
    pub const FULL_WITHOUT_HANDOFF: &str = "https://100.64.0.7:8444/link#apassy_lnk_t_7k2m5q4x3c_abababababababababababababababababababababababababababababababab&pin=u7Ri74l_xMBm74XnZDWpOC6Z4p6n4aUqwWmsV6firLE&alt=apassy-mini.tail0123.ts.net,[fd7a:115c:a1e0::7]:8444&name=Mac%20mini%20%E2%80%9CStudio%E2%80%9D";
    pub const PIN_HANDOFF_LINK: &str = "https://100.64.0.7:8444/link#apassy_lnk_t_7k2m5q4x3c_abababababababababababababababababababababababababababababababab&pin=u7Ri74l_xMBm74XnZDWpOC6Z4p6n4aUqwWmsV6firLE&handoff=2.oKGio6SlpqeoqaqrrK2urw.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8.BAIX5hfwtkQ5KCePlpmeaaI6TywVK99tbN9m5bgCgtTtGUp968uXcS0t2jyoWqh2Wlb0X8dYWZZS8ol8ZTBuV5Q";
    pub const PAIR_LINK: &str = "https://100.64.0.7:8444/pair#apassy_tcd_cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd&pin=u7Ri74l_xMBm74XnZDWpOC6Z4p6n4aUqwWmsV6firLE&alt=apassy-mini.tail0123.ts.net,[fd7a:115c:a1e0::7]:8444&name=build-box";
    pub const HOSTED_LINK: &str = "https://apassy-relay.wyderka.cc/link#apassy_lnk_t_7k2m5q4x3c_abababababababababababababababababababababababababababababababab&handoff=2.oKGio6SlpqeoqaqrrK2urw.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8.BAIX5hfwtkQ5KCePlpmeaaI6TywVK99tbN9m5bgCgtTtGUp968uXcS0t2jyoWqh2Wlb0X8dYWZZS8ol8ZTBuV5Q";

    pub fn handoff() -> String {
        format!("2.{QID}.{HANDOFF_SECRET}.{MAC_PUBLIC}")
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Kind {
        Device,
        Pair,
    }

    #[derive(Debug, PartialEq, Eq)]
    pub struct Paired {
        pub kind: Kind,
        pub origin: String,
        pub code: String,
        pub pin: Option<String>,
        /// `host:port`, the port always written.
        pub alt: Vec<String>,
        pub name: Option<String>,
        pub handoff: Option<String>,
        /// "The original full link without handoff" of the ADR 0032 AAD (section 8).
        pub without_handoff: String,
    }

    const KEYS: [&str; 4] = ["pin", "alt", "name", "handoff"];
    const MAX_LINK: usize = 2048;

    pub fn parse(text: &str) -> Result<Paired, &'static str> {
        let text = text.trim_matches(|c: char| c.is_ascii_whitespace());
        if text.len() > MAX_LINK {
            return Err("too_long");
        }
        let (base, fragment) = text.split_once('#').ok_or("bad_origin")?;
        if fragment.contains('#') || text.contains('?') {
            return Err("bad_origin");
        }
        let (origin, kind) = if let Some(origin) = base.strip_suffix("/link") {
            (origin, Kind::Device)
        } else if let Some(origin) = base.strip_suffix("/pair") {
            (origin, Kind::Pair)
        } else {
            return Err("bad_origin");
        };
        let mut parts = fragment.split('&');
        let code = parts.next().unwrap_or_default();
        let params: Vec<(Option<usize>, &str)> = parts
            .map(|part| match part.split_once('=') {
                Some((key, value)) => (KEYS.iter().position(|known| *known == key), value),
                None => (None, ""),
            })
            .collect();
        // The precedence of section 7: each category over all parameters.
        if params.iter().any(|(index, _)| index.is_none()) {
            return Err("unknown_key");
        }
        let indexes: Vec<usize> = params.iter().filter_map(|(index, _)| *index).collect();
        for (n, index) in indexes.iter().enumerate() {
            if indexes[..n].contains(index) {
                return Err("repeated_key");
            }
        }
        if indexes.windows(2).any(|pair| pair[1] < pair[0]) {
            return Err("key_order");
        }
        if params.iter().any(|(_, value)| value.is_empty()) {
            return Err("empty_value");
        }
        let mut values: [Option<&str>; 4] = [None; 4];
        for (index, value) in &params {
            values[index.expect("known key")] = Some(*value);
        }
        let [pin, alt, name, handoff] = values;

        let code_ok = match kind {
            Kind::Device => apassy::sync::link_code_team(code).is_some(),
            Kind::Pair => apassy::sync::valid_team_code(code),
        };
        if !code_ok {
            return Err("bad_code");
        }
        if pin.is_none() && (alt.is_some() || name.is_some() || kind == Kind::Pair) {
            return Err("needs_pin");
        }
        if kind == Kind::Pair && handoff.is_some() {
            return Err("handoff_on_pair");
        }
        let (origin_host, origin_port) = parse_origin(origin, pin.is_some())?;
        if let Some(pin) = pin
            && !valid_pin(pin)
        {
            return Err("bad_pin");
        }
        let alt = match alt {
            Some(list) => parse_alt(list, &origin_host, origin_port)?,
            None => Vec::new(),
        };
        let name = name.map(decode_name).transpose()?;
        if let Some(handoff) = handoff
            && !valid_handoff(handoff)
        {
            return Err("bad_handoff");
        }
        let without_handoff = text
            .split_once("&handoff=")
            .map_or(text, |(raw, _)| raw)
            .to_owned();
        Ok(Paired {
            kind,
            origin: origin.to_owned(),
            code: code.to_owned(),
            pin: pin.map(str::to_owned),
            alt,
            name,
            handoff: handoff.map(str::to_owned),
            without_handoff,
        })
    }

    pub fn valid_pin(pin: &str) -> bool {
        pin.len() == 43 && decode_b64u(pin).is_some_and(|bytes| bytes.len() == 32)
    }

    /// Section 3. A pinned origin is `https://host:port` with an explicit port other than 443.
    fn parse_origin(origin: &str, pinned: bool) -> Result<(String, u16), &'static str> {
        let rest = match origin.strip_prefix("https://") {
            Some(rest) => rest,
            None if pinned => return Err("bad_origin"),
            None => origin.strip_prefix("http://").ok_or("bad_origin")?,
        };
        if rest.contains('/') || rest.contains('@') {
            return Err("bad_origin");
        }
        let (host, port) = split_host_port(rest).ok_or("bad_origin")?;
        if pinned && (port.is_none() || port == Some(443)) {
            return Err("bad_origin");
        }
        Ok((host, port.unwrap_or(443)))
    }

    /// `host[:port]` with a canonical host (section 7) and a port without leading zeros.
    fn split_host_port(text: &str) -> Option<(String, Option<u16>)> {
        let (host, port) = if let Some(rest) = text.strip_prefix('[') {
            let (inside, after) = rest.split_once(']')?;
            let address: Ipv6Addr = inside.parse().ok()?;
            if address.to_string() != inside {
                return None;
            }
            let port = match after {
                "" => None,
                _ => Some(after.strip_prefix(':')?),
            };
            (format!("[{inside}]"), port)
        } else {
            let (host, port) = match text.rsplit_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (text, None),
            };
            if !valid_ipv4_or_name(host) {
                return None;
            }
            (host.to_owned(), port)
        };
        let port = match port {
            None => None,
            Some(text)
                if !text.is_empty()
                    && text.bytes().all(|byte| byte.is_ascii_digit())
                    && !text.starts_with('0') =>
            {
                Some(text.parse::<u16>().ok()?)
            }
            Some(_) => return None,
        };
        Some((host, port))
    }

    fn valid_ipv4_or_name(host: &str) -> bool {
        if host
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
        {
            return host
                .parse::<Ipv4Addr>()
                .is_ok_and(|address| address.to_string() == host);
        }
        let labels: Vec<&str> = host.split('.').collect();
        host.len() <= 253
            && labels.len() >= 2
            && labels.iter().all(|label| {
                (1..=63).contains(&label.len())
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            })
    }

    fn local_or_unspecified(host: &str) -> bool {
        if let Some(inside) = host
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        {
            let address: Ipv6Addr = inside.parse().expect("checked");
            return address.is_loopback()
                || address.is_unspecified()
                || (address.segments()[0] & 0xffc0) == 0xfe80;
        }
        match host.parse::<Ipv4Addr>() {
            Ok(address) => {
                address.is_loopback() || address.is_unspecified() || address.is_link_local()
            }
            Err(_) => false,
        }
    }

    fn parse_alt(
        list: &str,
        origin_host: &str,
        origin_port: u16,
    ) -> Result<Vec<String>, &'static str> {
        let entries: Vec<&str> = list.split(',').collect();
        if entries.is_empty() || entries.len() > 4 {
            return Err("bad_alt");
        }
        let mut out = Vec::new();
        for entry in entries {
            let (host, port) = split_host_port(entry).ok_or("bad_alt")?;
            let port = port.unwrap_or(origin_port);
            if local_or_unspecified(&host) || (host == origin_host && port == origin_port) {
                return Err("bad_alt");
            }
            let text = format!("{host}:{port}");
            if out.contains(&text) {
                return Err("bad_alt");
            }
            out.push(text);
        }
        Ok(out)
    }

    fn unreserved(byte: u8) -> bool {
        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
    }

    /// The canonical percent-encoding of section 7.
    pub fn encode_name(name: &str) -> String {
        let mut out = String::new();
        for byte in name.bytes() {
            if unreserved(byte) {
                out.push(char::from(byte));
            } else {
                out.push_str(&format!("%{byte:02X}"));
            }
        }
        out
    }

    fn decode_name(text: &str) -> Result<String, &'static str> {
        let bytes = text.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            let byte = bytes[i];
            if unreserved(byte) {
                out.push(byte);
                i += 1;
                continue;
            }
            if byte != b'%' {
                return Err("bad_name");
            }
            let hex = bytes.get(i + 1..i + 3).ok_or("bad_name")?;
            if !hex
                .iter()
                .all(|h| h.is_ascii_digit() || (b'A'..=b'F').contains(h))
            {
                return Err("bad_name");
            }
            let value = u8::from_str_radix(std::str::from_utf8(hex).expect("ascii"), 16)
                .map_err(|_| "bad_name")?;
            if unreserved(value) {
                return Err("bad_name");
            }
            out.push(value);
            i += 3;
        }
        let name = String::from_utf8(out).map_err(|_| "bad_name")?;
        let count = name.chars().count();
        if !(1..=40).contains(&count)
            || name
                .chars()
                .any(|c| c.is_control() || c == '\u{2028}' || c == '\u{2029}')
        {
            return Err("bad_name");
        }
        Ok(name)
    }

    fn valid_handoff(text: &str) -> bool {
        let parts: Vec<&str> = text.split('.').collect();
        let [version, qid, secret, public] = parts.as_slice() else {
            return false;
        };
        *version == "2"
            && apassy::questions::envelope::valid_qid(qid)
            && decode_b64u(secret).is_some_and(|bytes| bytes.len() == 32)
            && decode_b64u(public).is_some_and(|bytes| {
                bytes.len() == 65 && p256::PublicKey::from_sec1_bytes(&bytes).is_ok()
            })
    }

    /// The refused links of section 12: (text, reason).
    pub fn refused() -> Vec<(String, &'static str)> {
        let handoff = handoff();
        let pin_pair = format!("pin={PIN}");
        let second_pin = format!("&pin={PIN}&alt=");
        let short_pin = &PIN[..42];
        let padded_pin = format!("{short_pin}F");
        let with_alt = |list: &str| FULL_LINK.replace(ALT, list);
        let with_name = |name: &str| FULL_LINK.replace(NAME_ENCODED, name);
        let mut too_long = format!("{FULL_LINK}&x=");
        too_long.push_str(&"a".repeat(MAX_LINK + 1 - too_long.len()));
        vec![
            (
                FULL_LINK.replace("&handoff=", "&foo=1&handoff="),
                "unknown_key",
            ),
            (FULL_LINK.replace("&alt=", &second_pin), "repeated_key"),
            (
                format!("{ORIGIN}/link#{LINK_CODE}&name={NAME_ENCODED}&pin={PIN}"),
                "key_order",
            ),
            (
                format!("{ORIGIN}/link#{LINK_CODE}&handoff={handoff}&pin={PIN}"),
                "key_order",
            ),
            (
                HOSTED_LINK.replace("&handoff=", "&alt=relay2.example.com&handoff="),
                "needs_pin",
            ),
            (FULL_LINK.replace(pin_pair.as_str(), "pin="), "empty_value"),
            (FULL_LINK.replace(PIN, short_pin), "bad_pin"),
            (FULL_LINK.replace(PIN, &padded_pin), "bad_pin"),
            (FULL_LINK.replacen("https://", "http://", 1), "bad_origin"),
            (
                FULL_LINK.replacen(
                    "https://100.64.0.7:8444/link#",
                    "https://100.64.0.7/link#",
                    1,
                ),
                "bad_origin",
            ),
            (
                FULL_LINK.replacen(":8444/link#", ":8444//link#", 1),
                "bad_origin",
            ),
            (
                with_alt("a.example.com,b.example.com,c.example.com,d.example.com,e.example.com"),
                "bad_alt",
            ),
            (with_alt("100.64.0.7:8444"), "bad_alt"),
            (with_alt("[FD7A:115C:A1E0::7]"), "bad_alt"),
            (with_alt("127.0.0.1"), "bad_alt"),
            (
                with_name("Mac%20mini%20%e2%80%9cStudio%e2%80%9d"),
                "bad_name",
            ),
            (with_name("%4Dac"), "bad_name"),
            (with_name("Mac%0Amini"), "bad_name"),
            (with_name(&"a".repeat(41)), "bad_name"),
            (PAIR_LINK.replace(TEAM_CODE, LINK_CODE), "bad_code"),
            (format!("{PAIR_LINK}&handoff={handoff}"), "handoff_on_pair"),
            (format!("{ORIGIN}/pair#{TEAM_CODE}"), "needs_pin"),
            (too_long, "too_long"),
        ]
    }
}

#[cfg(feature = "vault")]
#[test]
fn node_pairing_v1_fixtures_match_the_contract() {
    use node_pairing_v1::*;
    let contract = NODE_PAIRING_CONTRACT;

    // The pin of the fixture certificate (section 4).
    let der = include_bytes!("fixtures/node-pairing-v1/node-cert.der");
    assert_eq!(der.len(), 297);
    assert_eq!(apassy::sync::sha256_hex(der), DER_SHA256);
    let digest = ring::digest::digest(&ring::digest::SHA256, der);
    assert_eq!(apassy::sync::encode_b64u(digest.as_ref()), PIN);
    assert!(valid_pin(PIN));

    // The contract carries every vector.
    for vector in [
        PIN,
        DER_SHA256,
        ORIGIN,
        LINK_CODE,
        TEAM_CODE,
        NAME,
        NAME_ENCODED,
        QID,
        HANDOFF_SECRET,
        MAC_PUBLIC,
        FULL_LINK,
        FULL_WITHOUT_HANDOFF,
        PIN_HANDOFF_LINK,
        PAIR_LINK,
        HOSTED_LINK,
    ] {
        assert!(contract.contains(vector), "the contract lacks {vector}");
    }
    assert_eq!(FULL_LINK.len(), 430);
    assert!(contract.contains("(430 bytes)"));
    assert_eq!(encode_name(NAME), NAME_ENCODED);
    assert_eq!(encode_name("build-box"), "build-box");
    assert_eq!(
        FULL_LINK,
        format!("{FULL_WITHOUT_HANDOFF}&handoff={}", handoff())
    );

    // The node origin is the canonical relay origin that the app stores and signs.
    let origin = apassy::sync::RelayUrl::parse(ORIGIN).expect("node origin");
    assert_eq!(origin.as_str(), ORIGIN);

    // Link 1: every key.
    let full = parse(&format!(" \n{FULL_LINK}\n")).expect("link 1");
    assert_eq!(
        full,
        Paired {
            kind: Kind::Device,
            origin: ORIGIN.to_owned(),
            code: LINK_CODE.to_owned(),
            pin: Some(PIN.to_owned()),
            alt: vec![
                "apassy-mini.tail0123.ts.net:8444".to_owned(),
                "[fd7a:115c:a1e0::7]:8444".to_owned(),
            ],
            name: Some(NAME.to_owned()),
            handoff: Some(handoff()),
            without_handoff: FULL_WITHOUT_HANDOFF.to_owned(),
        }
    );

    // Link 2: a handoff right after a pin.
    let pinned = parse(PIN_HANDOFF_LINK).expect("link 2");
    assert_eq!(pinned.pin.as_deref(), Some(PIN));
    assert!(pinned.alt.is_empty() && pinned.name.is_none());
    assert_eq!(pinned.handoff, Some(handoff()));
    assert_eq!(
        pinned.without_handoff,
        format!("{ORIGIN}/link#{LINK_CODE}&pin={PIN}")
    );

    // Link 3: a node pairing link.
    let pair = parse(PAIR_LINK).expect("link 3");
    assert_eq!(pair.kind, Kind::Pair);
    assert_eq!(pair.code, TEAM_CODE);
    assert_eq!(pair.name.as_deref(), Some("build-box"));
    assert!(pair.handoff.is_none());

    // Link 4: a hosted link keeps today's form, and today's reader takes it unchanged.
    let hosted = parse(HOSTED_LINK).expect("link 4");
    assert!(hosted.pin.is_none());
    let hosted_raw = format!("https://apassy-relay.wyderka.cc/link#{LINK_CODE}");
    assert_eq!(hosted.without_handoff, hosted_raw);
    let (url, code) =
        apassy::sync::PendingJoin::parse_link(HOSTED_LINK, apassy::sync::DEFAULT_RELAY_URL)
            .expect("today's reader takes a hosted link");
    assert_eq!(url.as_str(), "https://apassy-relay.wyderka.cc");
    assert_eq!(code.as_str(), LINK_CODE);
    let (raw, channel) = apassy::relay::pairing::PairingChannel::parse(HOSTED_LINK)
        .expect("today's handoff reader takes it");
    assert_eq!(
        raw, hosted_raw,
        "the handoff AAD of a link without a pin is unchanged"
    );
    assert_eq!(channel.qid(), QID);

    // Every refused link, with the reason of the contract.
    for (text, reason) in refused() {
        assert_eq!(parse(&text).err(), Some(reason), "{text}");
        assert!(
            contract.contains(&format!("`{reason}`")),
            "the contract lacks the reason {reason}"
        );
    }
}

#[cfg(feature = "vault")]
mod push_gateway_v1 {
    //! A reference of the handle, proof, and summary forms of push-gateway-v1.
    use apassy::sync::{decode_b64u, encode_b64u};
    use ring::aead::{AES_256_GCM, Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
    use serde::{Deserialize, Serialize};

    pub const GATEWAY_KEY: &str = "QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8";
    pub const KEY_ID: u8 = 1;
    pub const SECRET: &str = "YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn8";
    pub const WATCH_SECRET: &str = "gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp8";
    pub const HANDLE_PLAIN: &str = r#"{"v":1,"kind":"iphone","token":"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1","environment":"production","bundle_id":"com.wydrox.apassy.companion","secret":"YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn8","issued_at":1790000000,"expires_at":1805552000}"#;
    pub const HANDLE: &str = "AQEAAQIDBAUGBwgJCgtBJxpaTb1ogql77qaa1-7S86xCZwlugXGaT4PzL5NTfCFBpTDac2pO0SkZriCatsFILmsMt3V6FVKy5oQwVC_Xp0KbnZecVv6zArmDfifrV5jgi8MknGQGiRecJm9NW2etrseKbY4QHHDC16hpS29-n_ooa8Wf7_gDcl-gXUOCOht6OHZn7JjU2hewAbctZWpd_qZzpQMPBS4GKjewB9GMj8v0if9Q6ZZSlj1UQzXfSRw3Lme5AOFU5ggjW-mmefcljd5raXzDrJ-r7U7GcjJI-XAMcaScWgVAShGeklTDrvW8Qpt8C40X2UhL_GmK8G3vg9q7_5xrlTqrBrHrZRBMHwSQ3dMPyRp5zrrzBIgGn6IlRz7SLrGYTy4uHS4";
    pub const PROOF: &str = "-MmhDTmjMiBV6cNqCsq29jnlp9anOujN_dXLn6hbbnY";
    pub const WATCH_PLAIN: &str = r#"{"v":1,"kind":"watch","token":"b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2","environment":"production","bundle_id":"com.wydrox.apassy.companion.watchkitapp","secret":"gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp8","issued_at":1790000000,"expires_at":1805552000}"#;
    pub const WATCH_HANDLE: &str = "AQEQERITFBUWFxgZGhsCGEvzbKA4AcXPuDTJwi3BZGPnoSQ9aH8XBay_-VOQstGWIJlekXGdAALT_B73l_ZgGeZMEDAmyTp2zqYF69tWqZ_1R6DSxX2gstrWUC6hi0uL_AXLKTvezTUSly0XROF6ardVkVxMFK69c8oKF652vi9NMQVtpThfgcSo1b4B8urodIEdJzfJsnhSiQ2d5NFf0hi-5MRKb1hhk1whHjAU3e-pWX7QCq_bvnIu4-iml6auHpWStEPb5l8i9oVTE7ZxeOKQupMT1YV2MB-wVcUDzDx1kjox7A8NLoDDI84B00IU9fWhfFl2srTzPyfOPP8eKqBUfazI2uE1AUYBE8c3XkCdmXoCQiRLuWBv8G00W7pcFusI2_UX-MOYh1D253_JLDrQmxzREA";
    pub const WATCH_PROOF: &str = "KxRYEBo7r3KCRqcOBVc8OpRsPuz2rRb4LxFQtvzzaBI";
    pub const QUESTION_KEY: &str = "wMHCw8TFxsfIycrLzM3Oz9DR0tPU1dbX2Nna29zd3t8";
    pub const SUMMARY_KEY: &str = "K-iD_0Xo0XYWPOS-Iz7HiP6Cs2rdeAtf21jMtRLg-Zc";
    pub const SUMMARY_JSON: &str = r#"{"v":1,"team":"t_7k2m5q4x3c","qid":"oKGio6SlpqeoqaqrrK2urw","expires_at":1790000400,"kind":"access","title":"Access request","body":"Claude Code wants “Stripe test key”"}"#;
    pub const SUMMARY: &str = "ICEiIyQlJicoKSorLZYy_9V2mK8YOxL9BrISycdM3QC8LastsrSZ2rydHt5kH7FQOVw3Z9Fcdh4X0rBDP0peQmDtu1ueo2qMc8jG-HaJeH5MYA7UnBcbZRxtOLpdrfxf1XCmrKUi-gmLBZxFvggJiX35uKUAdZwfhwUqeu6y8tnLbItuN-Yk4e_Jkqawp39RHi3ux-0DNm4DCs1Nlnki8MWzWpS7q_Yf1-3uwYdSdBlr-qq7uI6GCJiJ-79H4cte4JJnY8GQ0RvTh9ZbxyqpdIhFpoe0V1w2ZgierYd-NuopbMxBWD0nepd9qDJGCGmbMZG1CwxXrjC_l2986y7k_EjhkwIbDdeBxTVnZ67guVWth1D8h-UMVEvCKR3zc2ANEQ1Qrr-skb_eNEo0hnj6Bvx6MiFWKwMUV_PcRAFVpb7so6XLs1i2bkYSzEv-w_buoaz-EnNnMD70ddE-FuZDqHiWaar_Wo0dSHz5qf5hcXNT6x185swuTpTL8sKUr32di0Qa0ObJE6BCpMOdFlxGtaKrb7bu1svCr0nLWDhMhi2Tp8ibOnvYKei4HFG251WGQ8AxcJl_7m_NTDOq4bDlEOOaOgSF7KiofJolVL4sBk8oFlaTgp2-Jvn4rFU1c04OaWJGQfOaJIvpnRXa883CBzSKZ2sNaovOg00TUiQ8Dc31pqs-ZzE8xHmg7E7YbmDyG3-UPiey7OE407l9";
    pub const SUMMARY_PROOF: &str = "gyriDrKhiUeSYbgOm5weYj7NG6isjzaE3IEJp9qDV3g";
    pub const AT: u64 = 1_790_000_100;
    pub const PUSH_EXPIRES_AT: u64 = 1_790_000_400;
    pub const COLLAPSE_ID: &str = "apassy-question";
    pub const PAYLOAD: &str = r#"{"aps":{"alert":{"title":"Apassy","body":"A question is waiting"},"sound":"default","interruption-level":"time-sensitive"}}"#;

    const HANDLE_DOMAIN: &[u8] = b"apassy-push-handle-v1";
    const SUMMARY_DOMAIN: &[u8] = b"apassy-push-summary-v1";
    const SUMMARY_PADDED: usize = 512;
    pub const SUMMARY_CHARS: usize = 720;

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct HandlePlain {
        pub v: u8,
        pub kind: String,
        pub token: String,
        pub environment: String,
        pub bundle_id: String,
        pub secret: String,
        pub issued_at: u64,
        pub expires_at: u64,
    }

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct HandleRequest {
        pub v: u8,
        pub kind: String,
        pub token: String,
        pub environment: String,
        pub bundle_id: String,
    }

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct HandleAnswer {
        pub v: u8,
        pub handle: String,
        pub secret: String,
        pub expires_at: u64,
    }

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct PushRequest {
        pub v: u8,
        pub handle: String,
        pub at: u64,
        pub expires_at: u64,
        pub collapse_id: String,
        pub proof: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub summary: Option<String>,
    }

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct PushAnswer {
        pub v: u8,
        pub status: u16,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub reason: Option<String>,
    }

    /// `PUT /v1/push/handle` on a node (section 10).
    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct HandleSet {
        pub v: u8,
        pub gateway: String,
        pub handle: String,
        pub secret: String,
    }

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Summary {
        pub v: u8,
        pub team: String,
        pub qid: String,
        pub expires_at: u64,
        pub kind: String,
        pub title: String,
        pub body: String,
    }

    pub fn bytes(start: u8, len: usize) -> Vec<u8> {
        (0..len).map(|i| start.wrapping_add(i as u8)).collect()
    }

    fn aead(algorithm: &'static ring::aead::Algorithm, key: &[u8]) -> LessSafeKey {
        LessSafeKey::new(UnboundKey::new(algorithm, key).expect("key"))
    }

    fn handle_aad(header: [u8; 2]) -> Vec<u8> {
        let mut aad = HANDLE_DOMAIN.to_vec();
        aad.push(0);
        aad.extend_from_slice(&header);
        aad
    }

    pub fn seal_handle(key: &[u8], key_id: u8, nonce: &[u8], plain: &str) -> String {
        let header = [1, key_id];
        let mut buffer = plain.as_bytes().to_vec();
        aead(&AES_256_GCM, key)
            .seal_in_place_append_tag(
                Nonce::try_assume_unique_for_key(nonce).expect("nonce"),
                Aad::from(handle_aad(header)),
                &mut buffer,
            )
            .expect("seal");
        let mut out = header.to_vec();
        out.extend_from_slice(nonce);
        out.extend_from_slice(&buffer);
        encode_b64u(&out)
    }

    /// The gateway's open (section 5), without the clock.
    pub fn open_handle(key: &[u8], key_id: u8, handle: &str) -> Option<HandlePlain> {
        let bytes = decode_b64u(handle)?;
        if bytes.len() < 2 + 12 + 16 || bytes.len() > 1024 || bytes[0] != 1 || bytes[1] != key_id {
            return None;
        }
        let header = [bytes[0], bytes[1]];
        let mut sealed = bytes[14..].to_vec();
        let plain = aead(&AES_256_GCM, key)
            .open_in_place(
                Nonce::try_assume_unique_for_key(&bytes[2..14]).ok()?,
                Aad::from(handle_aad(header)),
                &mut sealed,
            )
            .ok()?;
        serde_json::from_slice(plain).ok()
    }

    pub fn proof_message(
        handle: &str,
        at: u64,
        expires_at: u64,
        collapse_id: &str,
        summary: Option<&str>,
    ) -> Vec<u8> {
        let mut text = format!("apassy-push-v1\0{handle}\0{at}\0{expires_at}\0{collapse_id}");
        if let Some(summary) = summary {
            text.push('\0');
            text.push_str(summary);
        }
        text.into_bytes()
    }

    pub fn proof(secret: &str, message: &[u8]) -> String {
        let secret = decode_b64u(secret).expect("secret");
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &secret);
        encode_b64u(ring::hmac::sign(&key, message).as_ref())
    }

    pub fn proof_verifies(secret: &str, message: &[u8], proof: &str) -> bool {
        let secret = decode_b64u(secret).expect("secret");
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &secret);
        decode_b64u(proof).is_some_and(|tag| ring::hmac::verify(&key, message, &tag).is_ok())
    }

    pub fn summary_key(question_key: &[u8]) -> Vec<u8> {
        let prk = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, &[]).extract(question_key);
        let info = [SUMMARY_DOMAIN];
        let okm = prk.expand(&info, ring::hkdf::HKDF_SHA256).expect("expand");
        let mut out = vec![0; 32];
        okm.fill(&mut out).expect("fill");
        out
    }

    pub fn seal_summary(key: &[u8], nonce: &[u8], json: &str) -> String {
        let json = json.as_bytes();
        assert!(json.len() <= SUMMARY_PADDED - 2);
        let mut buffer = vec![0; SUMMARY_PADDED];
        buffer[..2].copy_from_slice(&(json.len() as u16).to_be_bytes());
        buffer[2..2 + json.len()].copy_from_slice(json);
        aead(&CHACHA20_POLY1305, key)
            .seal_in_place_append_tag(
                Nonce::try_assume_unique_for_key(nonce).expect("nonce"),
                Aad::from(SUMMARY_DOMAIN),
                &mut buffer,
            )
            .expect("seal");
        let mut out = nonce.to_vec();
        out.extend_from_slice(&buffer);
        encode_b64u(&out)
    }

    /// The extension's open (section 12): the JSON text, or `None`.
    pub fn open_summary(key: &[u8], summary: &str) -> Option<String> {
        if !valid_summary(summary) {
            return None;
        }
        let bytes = decode_b64u(summary)?;
        let mut sealed = bytes[12..].to_vec();
        let padded = aead(&CHACHA20_POLY1305, key)
            .open_in_place(
                Nonce::try_assume_unique_for_key(&bytes[..12]).ok()?,
                Aad::from(SUMMARY_DOMAIN),
                &mut sealed,
            )
            .ok()?;
        let len = usize::from(u16::from_be_bytes([padded[0], padded[1]]));
        let json = padded.get(2..2 + len)?;
        if padded[2 + len..].iter().any(|byte| *byte != 0) {
            return None;
        }
        String::from_utf8(json.to_vec()).ok()
    }

    /// The form check of the node and the gateway: 720 b64u characters, 540 bytes.
    pub fn valid_summary(text: &str) -> bool {
        text.len() == SUMMARY_CHARS
            && decode_b64u(text).is_some_and(|bytes| bytes.len() == 12 + SUMMARY_PADDED + 16)
    }
}

#[cfg(feature = "vault")]
#[test]
fn push_gateway_v1_fixtures_match_the_contract() {
    use apassy::sync::decode_b64u;
    use push_gateway_v1::*;
    let contract = PUSH_GATEWAY_CONTRACT;
    let gateway_key = decode_b64u(GATEWAY_KEY).expect("gateway key");
    assert_eq!(gateway_key, bytes(0x40, 32));
    assert_eq!(decode_b64u(SECRET).expect("secret"), bytes(0x60, 32));
    assert_eq!(
        decode_b64u(WATCH_SECRET).expect("watch secret"),
        bytes(0x80, 32)
    );

    for vector in [
        GATEWAY_KEY,
        SECRET,
        WATCH_SECRET,
        HANDLE_PLAIN,
        HANDLE,
        PROOF,
        WATCH_PLAIN,
        WATCH_HANDLE,
        WATCH_PROOF,
        QUESTION_KEY,
        SUMMARY_KEY,
        SUMMARY_JSON,
        SUMMARY,
        SUMMARY_PROOF,
        PAYLOAD,
        r#"{"v":1,"status":410,"reason":"Unregistered"}"#,
        "apassy-push-handle-v1",
        "apassy-push-summary-v1",
        "com.wydrox.apassy.companion.watchkitapp",
    ] {
        assert!(contract.contains(vector), "the contract lacks {vector}");
    }

    // The fixed payload is byte for byte the relay Worker's (relay-questions-v1 §14.1).
    let worker = include_str!("../crates/apassy-relay/deploy/worker/src/apns.ts");
    assert!(worker.contains(&format!("'{PAYLOAD}'")));
    let with_summary = format!(
        r#"{{"aps":{{"alert":{{"title":"Apassy","body":"A question is waiting"}},"sound":"default","interruption-level":"time-sensitive","mutable-content":1}},"s":"{SUMMARY}"}}"#
    );
    assert!(contract.contains(&with_summary.replace(SUMMARY, "<summary>")));
    assert!(
        with_summary.len() <= 4096,
        "APNs payloads are at most 4 KiB"
    );

    // Handles reproduce (section 5) and their plaintext is canonical and strict.
    assert_eq!(
        seal_handle(&gateway_key, KEY_ID, &bytes(0x00, 12), HANDLE_PLAIN),
        HANDLE
    );
    assert_eq!(
        seal_handle(&gateway_key, KEY_ID, &bytes(0x10, 12), WATCH_PLAIN),
        WATCH_HANDLE
    );
    let plain = open_handle(&gateway_key, KEY_ID, HANDLE).expect("the handle opens");
    assert_eq!(serde_json::to_string(&plain).expect("json"), HANDLE_PLAIN);
    assert_eq!(
        (plain.kind.as_str(), plain.secret.as_str()),
        ("iphone", SECRET)
    );
    assert_eq!(plain.expires_at, plain.issued_at + 15_552_000);
    let watch = open_handle(&gateway_key, KEY_ID, WATCH_HANDLE).expect("the watch handle opens");
    assert_eq!(serde_json::to_string(&watch).expect("json"), WATCH_PLAIN);
    assert_eq!(watch.kind, "watch");
    assert_eq!(watch.bundle_id, "com.wydrox.apassy.companion.watchkitapp");
    assert!(decode_b64u(HANDLE).expect("b64u").len() <= 1024);

    // Proofs reproduce (section 7).
    let message = proof_message(HANDLE, AT, PUSH_EXPIRES_AT, COLLAPSE_ID, None);
    assert_eq!(proof(SECRET, &message), PROOF);
    assert!(proof_verifies(SECRET, &message, PROOF));
    let watch_message = proof_message(WATCH_HANDLE, AT, PUSH_EXPIRES_AT, COLLAPSE_ID, None);
    assert_eq!(proof(WATCH_SECRET, &watch_message), WATCH_PROOF);
    let summary_message = proof_message(HANDLE, AT, PUSH_EXPIRES_AT, COLLAPSE_ID, Some(SUMMARY));
    assert_eq!(proof(SECRET, &summary_message), SUMMARY_PROOF);

    // The summary reproduces (section 12).
    let question_key = decode_b64u(QUESTION_KEY).expect("question key");
    assert_eq!(question_key, bytes(0xc0, 32));
    let key = summary_key(&question_key);
    assert_eq!(apassy::sync::encode_b64u(&key), SUMMARY_KEY);
    assert_eq!(SUMMARY_JSON.len(), 174);
    assert_eq!(seal_summary(&key, &bytes(0x20, 12), SUMMARY_JSON), SUMMARY);
    assert_eq!(SUMMARY.len(), SUMMARY_CHARS);
    assert!(valid_summary(SUMMARY));
    let opened = open_summary(&key, SUMMARY).expect("the summary opens");
    assert_eq!(opened, SUMMARY_JSON);
    let summary: Summary = serde_json::from_str(&opened).expect("strict summary");
    assert_eq!(serde_json::to_string(&summary).expect("json"), SUMMARY_JSON);
    assert_eq!(
        (summary.kind.as_str(), summary.expires_at),
        ("access", PUSH_EXPIRES_AT)
    );

    // Bodies parse strictly and serialize in the contract's field order.
    let push = PushRequest {
        v: 1,
        handle: HANDLE.to_owned(),
        at: AT,
        expires_at: PUSH_EXPIRES_AT,
        collapse_id: COLLAPSE_ID.to_owned(),
        proof: PROOF.to_owned(),
        summary: None,
    };
    let text = serde_json::to_string(&push).expect("json");
    assert!(text.starts_with(r#"{"v":1,"handle":""#));
    assert_eq!(
        serde_json::from_str::<PushRequest>(&text).expect("push"),
        push
    );
    for answer in [
        r#"{"v":1,"status":200}"#,
        r#"{"v":1,"status":410,"reason":"Unregistered"}"#,
        r#"{"v":1,"status":0,"reason":"Unreachable"}"#,
    ] {
        assert!(contract.contains(answer), "the contract lacks {answer}");
        let parsed: PushAnswer = serde_json::from_str(answer).expect("answer");
        assert_eq!(serde_json::to_string(&parsed).expect("json"), answer);
    }
    let request = HandleRequest {
        v: 1,
        kind: "iphone".to_owned(),
        token: "a1".repeat(32),
        environment: "production".to_owned(),
        bundle_id: "com.wydrox.apassy.companion".to_owned(),
    };
    let request_text = serde_json::to_string(&request).expect("json");
    assert!(contract.contains(&request_text.replace(&"a1".repeat(32), "<hex>")));
    let answer = HandleAnswer {
        v: 1,
        handle: HANDLE.to_owned(),
        secret: SECRET.to_owned(),
        expires_at: 1_805_552_000,
    };
    let answer_text = serde_json::to_string(&answer).expect("json");
    assert!(
        contract.contains(
            &answer_text
                .replace(HANDLE, "<b64u>")
                .replace(SECRET, "<b64u 43>")
        )
    );
    let set = HandleSet {
        v: 1,
        gateway: "https://push.apassy.wyderka.cc".to_owned(),
        handle: HANDLE.to_owned(),
        secret: SECRET.to_owned(),
    };
    let set_text = serde_json::to_string(&set).expect("json");
    assert!(
        contract.contains(
            &set_text
                .replace(HANDLE, "<b64u>")
                .replace(SECRET, "<b64u 43>")
        )
    );

    // What must fail.
    let mut other_key = gateway_key.clone();
    other_key[0] ^= 1;
    assert!(
        open_handle(&other_key, KEY_ID, HANDLE).is_none(),
        "another gateway key"
    );
    assert!(
        open_handle(&gateway_key, 2, HANDLE).is_none(),
        "another key id"
    );
    let mut flipped = decode_b64u(HANDLE).expect("b64u");
    flipped[19] ^= 1;
    let flipped = apassy::sync::encode_b64u(&flipped);
    assert!(
        open_handle(&gateway_key, KEY_ID, &flipped).is_none(),
        "a changed handle"
    );
    assert!(
        plain.expires_at < 1_805_552_001,
        "expired after its expires_at"
    );
    let late = proof_message(HANDLE, AT + 1, PUSH_EXPIRES_AT, COLLAPSE_ID, None);
    assert!(!proof_verifies(SECRET, &late, PROOF), "another at");
    assert!(
        !proof_verifies(WATCH_SECRET, &message, PROOF),
        "another secret"
    );
    assert!(
        !proof_verifies(SECRET, &summary_message, PROOF),
        "the summary is in the proof"
    );
    let mut with_token = serde_json::to_value(&push).expect("value");
    with_token["token"] = serde_json::json!("a1".repeat(32));
    assert!(
        serde_json::from_value::<PushRequest>(with_token).is_err(),
        "unknown field"
    );
    let duplicate = text.replacen(r#""v":1,"#, r#""v":1,"v":1,"#, 1);
    assert!(
        serde_json::from_str::<PushRequest>(&duplicate).is_err(),
        "repeated field"
    );
    let mut plain_extra = serde_json::to_value(&plain).expect("value");
    plain_extra["note"] = serde_json::json!("x");
    assert!(
        serde_json::from_value::<HandlePlain>(plain_extra).is_err(),
        "unknown plaintext field"
    );
    assert!(
        !valid_summary(&SUMMARY[..SUMMARY_CHARS - 1]),
        "a summary of 719 characters"
    );
    assert!(
        open_summary(&summary_key(&bytes(0xc1, 32)), SUMMARY).is_none(),
        "another vault"
    );
}
