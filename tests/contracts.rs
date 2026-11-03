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

// ---------------------------------------------------------------------------------------
// private-sharing-v1 (docs/contracts/private-sharing-v1.md; unit A of
// docs/design/implementation-plan-s6-sharing.md). The types in `private_sharing` are local
// to the test, not product code: they read the fixtures as a strict client and server of
// the contract would, so the units that implement it (C1, C2, D, F, G, H, L) code against
// the same shapes.
// ---------------------------------------------------------------------------------------

mod private_sharing {
    // The structs mirror the contract; some fields exist only to make the reader strict.
    #![allow(dead_code)]

    use std::collections::{BTreeMap, BTreeSet};

    use serde::de::DeserializeOwned;
    use serde::{Deserialize, Serialize};
    use serde_json::Value;

    pub const CONTRACT: &str = include_str!("../docs/contracts/private-sharing-v1.md");
    pub const CLOUD_AGENTS: &str = include_str!("../docs/contracts/cloud-agents-v1.md");

    pub const KINDS: &str = include_str!("fixtures/private-sharing-v1/kinds.json");
    pub const SOURCES: &str = include_str!("fixtures/private-sharing-v1/sources.json");
    pub const SETTINGS: [(&str, &str); 4] = [
        (
            "aws_sts",
            include_str!("fixtures/private-sharing-v1/settings-aws-sts.json"),
        ),
        (
            "github_app",
            include_str!("fixtures/private-sharing-v1/settings-github-app.json"),
        ),
        (
            "google_service_account",
            include_str!("fixtures/private-sharing-v1/settings-google-service-account.json"),
        ),
        (
            "oauth_refresh",
            include_str!("fixtures/private-sharing-v1/settings-oauth-refresh.json"),
        ),
    ];
    pub const LEASES: [(&str, &str); 4] = [
        (
            "aws_sts",
            include_str!("fixtures/private-sharing-v1/lease-aws-sts.json"),
        ),
        (
            "github_app",
            include_str!("fixtures/private-sharing-v1/lease-github-app.json"),
        ),
        (
            "google_service_account",
            include_str!("fixtures/private-sharing-v1/lease-google-service-account.json"),
        ),
        (
            "oauth_refresh",
            include_str!("fixtures/private-sharing-v1/lease-oauth-refresh.json"),
        ),
    ];
    pub const SESSION_VIEW: &str = include_str!("fixtures/private-sharing-v1/session-view.json");
    pub const ACCESS_VIEW: &str = include_str!("fixtures/private-sharing-v1/access-view.json");
    pub const SIGN_REQUEST: &str = include_str!("fixtures/private-sharing-v1/sign-request.json");
    pub const SIGN_ANSWER: &str = include_str!("fixtures/private-sharing-v1/sign-answer.json");
    pub const RUN_LEASE_FAILED: &str =
        include_str!("fixtures/private-sharing-v1/run-lease-failed.json");
    pub const AUDIT_ROWS: &str = include_str!("fixtures/private-sharing-v1/audit-rows.json");
    pub const ERRORS: [(&str, &str, &str); 5] = [
        (
            "error-lease-failed.json",
            include_str!("fixtures/private-sharing-v1/error-lease-failed.json"),
            "lease_failed",
        ),
        (
            "error-sign-refused-session.json",
            include_str!("fixtures/private-sharing-v1/error-sign-refused-session.json"),
            "sign_refused",
        ),
        (
            "error-sign-refused-presigned.json",
            include_str!("fixtures/private-sharing-v1/error-sign-refused-presigned.json"),
            "sign_refused",
        ),
        (
            "error-sign-refused-payload.json",
            include_str!("fixtures/private-sharing-v1/error-sign-refused-payload.json"),
            "sign_refused",
        ),
        (
            "error-sign-refused-limit.json",
            include_str!("fixtures/private-sharing-v1/error-sign-refused-limit.json"),
            "sign_refused",
        ),
    ];

    /// Section 7.2: the messages of `sign_refused`.
    pub const REFUSED_SESSION: &str = "This session is not yours or has ended.";
    pub const REFUSED_ITEM: &str = "This item does not sign requests in this session.";
    pub const REFUSED_HOST: &str = "The host is not covered by this item.";
    pub const REFUSED_DATE: &str = "The request date does not match.";
    pub const REFUSED_SERVICE: &str = "The service is not covered by this item.";
    pub const REFUSED_PRESIGNED: &str = "Presigned URLs are not signed.";
    pub const REFUSED_PAYLOAD: &str = "This payload hash is not signed.";
    pub const REFUSED_LIMIT: &str = "Too many signatures for this session. Wait a second.";
    /// A request that does not have the shape of section 7.2 (400, not `sign_refused`).
    pub const INVALID_REQUEST: &str = "invalid_request";

    /// The x-amz-date of the `get-vanilla` vector, as the host's clock in the checks.
    pub const VANILLA_NOW: u64 = 1_440_938_160;

    pub fn strict<T: DeserializeOwned>(name: &str, text: &str) -> T {
        serde_json::from_str(text).unwrap_or_else(|err| panic!("{name}: {err}"))
    }

    // ----- kinds.json and sources.json -------------------------------------------------

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Kinds {
        pub kinds: Vec<String>,
        pub reserved: Vec<String>,
        pub fields: BTreeMap<String, Vec<FieldRule>>,
        pub settings: BTreeMap<String, Vec<String>>,
        pub lease: BTreeMap<String, LeaseRule>,
        pub credential_form: Vec<String>,
        pub codes: Vec<String>,
        pub audit_actions: Vec<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct FieldRule {
        pub name: String,
        pub secret: bool,
        pub required: bool,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct LeaseRule {
        pub secrets: Vec<String>,
        pub plain: Vec<String>,
        pub max_secs: Option<u64>,
        pub revoke: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Source {
        pub env_name: String,
        pub fields: Vec<SourceField>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct SourceField {
        pub name: String,
        pub value: String,
        pub secret: bool,
    }

    pub fn kinds() -> Kinds {
        strict("kinds.json", KINDS)
    }

    pub fn sources() -> BTreeMap<String, Source> {
        strict("sources.json", SOURCES)
    }

    // ----- section 3.2: settings --------------------------------------------------------

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum LeaseKind {
        AwsSts,
        GithubApp,
        GoogleServiceAccount,
        OauthRefresh,
        CloudflareToken,
        PlanetscalePassword,
        NeonRole,
    }

    impl LeaseKind {
        pub fn name(self) -> &'static str {
            match self {
                Self::AwsSts => "aws_sts",
                Self::GithubApp => "github_app",
                Self::GoogleServiceAccount => "google_service_account",
                Self::OauthRefresh => "oauth_refresh",
                Self::CloudflareToken => "cloudflare_token",
                Self::PlanetscalePassword => "planetscale_password",
                Self::NeonRole => "neon_role",
            }
        }
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct AwsStsSettings {
        #[serde(default)]
        pub role_arn: Option<String>,
        #[serde(default)]
        pub policy: Option<String>,
        #[serde(default)]
        pub region: Option<String>,
        #[serde(default)]
        pub services: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum Permission {
        Read,
        Write,
        Admin,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct GithubAppSettings {
        #[serde(default)]
        pub repositories: Option<Vec<String>>,
        #[serde(default)]
        pub permissions: Option<BTreeMap<String, Permission>>,
        #[serde(default)]
        pub api_url: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct GoogleSettings {
        #[serde(default)]
        pub scopes: Option<Vec<String>>,
        #[serde(default)]
        pub impersonate: Option<String>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum ClientAuth {
        Basic,
        Body,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct OauthSettings {
        pub token_url: String,
        pub client_auth: ClientAuth,
        #[serde(default)]
        pub revoke_url: Option<String>,
        #[serde(default)]
        pub scope: Option<String>,
    }

    fn from_value<T: DeserializeOwned>(value: &Value) -> Result<T, String> {
        serde_json::from_value(value.clone()).map_err(|err| err.to_string())
    }

    fn ensure(ok: bool, what: &str) -> Result<(), String> {
        if ok { Ok(()) } else { Err(what.to_owned()) }
    }

    fn distinct(list: &[String]) -> bool {
        list.iter().collect::<BTreeSet<_>>().len() == list.len()
    }

    fn all_chars(text: &str, allowed: impl Fn(char) -> bool) -> bool {
        !text.is_empty() && text.chars().all(allowed)
    }

    /// Section 3.2: `https://` with a host, without userinfo, query, or fragment.
    pub fn is_https_url(url: &str) -> bool {
        let Some(rest) = url.strip_prefix("https://") else {
            return false;
        };
        let host = rest.split('/').next().unwrap_or("");
        !host.is_empty()
            && !rest.contains(['@', '?', '#'])
            && rest.chars().all(|c| c.is_ascii_graphic())
    }

    /// `[a-z]{2}(-[a-z]+)+-[0-9]+`.
    pub fn is_region(region: &str) -> bool {
        let parts: Vec<&str> = region.split('-').collect();
        parts.len() >= 3
            && parts[0].len() == 2
            && all_chars(parts[0], |c| c.is_ascii_lowercase())
            && all_chars(parts[parts.len() - 1], |c| c.is_ascii_digit())
            && parts[1..parts.len() - 1]
                .iter()
                .all(|part| all_chars(part, |c| c.is_ascii_lowercase()))
    }

    /// `[a-z0-9-]{1,32}`: an AWS service name, a region in a sign scope.
    pub fn is_aws_name(name: &str) -> bool {
        name.len() <= 32
            && all_chars(name, |c| {
                c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'
            })
    }

    fn check_aws_settings(settings: &AwsStsSettings) -> Result<(), String> {
        if let Some(arn) = &settings.role_arn {
            let rest = arn.strip_prefix("arn:aws:iam::").unwrap_or("");
            let (account, role) = rest.split_once(":role/").unwrap_or(("", ""));
            ensure(
                arn.len() <= 2048
                    && account.len() == 12
                    && all_chars(account, |c| c.is_ascii_digit())
                    && all_chars(role, |c| c.is_ascii_graphic()),
                "role_arn",
            )?;
        }
        if let Some(policy) = &settings.policy {
            let parsed: Result<Value, _> = serde_json::from_str(policy);
            ensure(
                policy.len() <= 2048 && matches!(parsed, Ok(Value::Object(_))),
                "policy",
            )?;
        }
        if let Some(region) = &settings.region {
            ensure(is_region(region), "region")?;
        }
        if let Some(services) = &settings.services {
            ensure(
                (1..=16).contains(&services.len())
                    && distinct(services)
                    && services.iter().all(|service| is_aws_name(service)),
                "services",
            )?;
        }
        Ok(())
    }

    fn check_github_settings(settings: &GithubAppSettings) -> Result<(), String> {
        if let Some(repositories) = &settings.repositories {
            ensure(
                (1..=500).contains(&repositories.len())
                    && distinct(repositories)
                    && repositories.iter().all(|name| {
                        name.len() <= 100
                            && all_chars(name, |c| {
                                c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')
                            })
                    }),
                "repositories",
            )?;
        }
        if let Some(permissions) = &settings.permissions {
            ensure(
                (1..=64).contains(&permissions.len())
                    && permissions.keys().all(|name| {
                        name.len() <= 64 && all_chars(name, |c| c.is_ascii_lowercase() || c == '_')
                    }),
                "permissions",
            )?;
        }
        if let Some(url) = &settings.api_url {
            ensure(is_https_url(url), "api_url")?;
        }
        Ok(())
    }

    fn check_google_settings(settings: &GoogleSettings) -> Result<(), String> {
        if let Some(scopes) = &settings.scopes {
            ensure(
                (1..=16).contains(&scopes.len())
                    && distinct(scopes)
                    && scopes.iter().all(|scope| is_https_url(scope)),
                "scopes",
            )?;
        }
        if let Some(email) = &settings.impersonate {
            let (name, domain) = email.split_once('@').unwrap_or(("", ""));
            let project = domain
                .strip_suffix(".iam.gserviceaccount.com")
                .unwrap_or("");
            ensure(
                !name.is_empty() && !project.is_empty() && !email.contains(char::is_whitespace),
                "impersonate",
            )?;
        }
        Ok(())
    }

    fn check_oauth_settings(settings: &OauthSettings) -> Result<(), String> {
        ensure(is_https_url(&settings.token_url), "token_url")?;
        if let Some(url) = &settings.revoke_url {
            ensure(is_https_url(url), "revoke_url")?;
            // Revision 2026-11-03: the revocation goes to the host of the token URL.
            let host = |url: &str| {
                url[8..]
                    .split('/')
                    .next()
                    .unwrap_or("")
                    .to_ascii_lowercase()
            };
            ensure(host(url) == host(&settings.token_url), "revoke_url")?;
        }
        if let Some(scope) = &settings.scope {
            ensure((1..=1024).contains(&scope.len()), "scope")?;
        }
        Ok(())
    }

    /// Section 3.2: strict settings per kind; a reserved kind has none yet.
    pub fn check_settings(kind: &str, settings: &Value) -> Result<(), String> {
        match kind {
            "aws_sts" => check_aws_settings(&from_value(settings)?),
            "github_app" => check_github_settings(&from_value(settings)?),
            "google_service_account" => check_google_settings(&from_value(settings)?),
            "oauth_refresh" => check_oauth_settings(&from_value(settings)?),
            _ => Err(format!(
                "{kind}: no settings in v1 (reserved or unknown kind)"
            )),
        }
    }

    // ----- section 4: the lease ----------------------------------------------------------

    #[derive(Debug, Clone, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Lease {
        pub kind: LeaseKind,
        pub secrets: Vec<LeaseSecret>,
        pub plain: Vec<LeasePlain>,
        pub made_at: u64,
        pub expires_at: u64,
        pub revoke: Option<Revoke>,
        pub update_field: Option<UpdateField>,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct LeaseSecret {
        pub name: String,
        pub value: String,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct LeasePlain {
        pub name: String,
        pub text: String,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum RevokeKind {
        Github,
        Oauth,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Revoke {
        #[serde(rename = "type")]
        pub kind: RevokeKind,
        pub url: String,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct UpdateField {
        pub field: String,
        pub value: String,
    }

    impl Lease {
        pub fn names(&self) -> Vec<String> {
            self.secrets
                .iter()
                .map(|secret| secret.name.clone())
                .chain(self.plain.iter().map(|plain| plain.name.clone()))
                .collect()
        }
    }

    pub fn lease(kind: &str) -> Lease {
        let (name, text) = LEASES
            .iter()
            .find(|(name, _)| *name == kind)
            .unwrap_or_else(|| panic!("no lease fixture for {kind}"));
        strict(name, text)
    }

    pub fn settings_value(kind: &str) -> Value {
        let (name, text) = SETTINGS
            .iter()
            .find(|(name, _)| *name == kind)
            .unwrap_or_else(|| panic!("no settings fixture for {kind}"));
        strict(name, text)
    }

    /// `[A-Z_][A-Z0-9_]{0,127}`.
    pub fn is_env_name(name: &str) -> bool {
        let mut chars = name.chars();
        name.len() <= 128
            && chars
                .next()
                .is_some_and(|c| c.is_ascii_uppercase() || c == '_')
            && chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    }

    /// The relay's `check_value`: printable ASCII without `"` and `\`, 1 to 4096 bytes.
    pub fn is_deliverable_value(value: &str) -> bool {
        (1..=4096).contains(&value.len())
            && value
                .bytes()
                .all(|b| (0x20..=0x7e).contains(&b) && b != b'"' && b != b'\\')
    }

    /// Section 4: the rules of one lease of `kind`, for a source bound to `binding`.
    pub fn check_lease(
        lease: &Lease,
        rule: &LeaseRule,
        binding: &str,
        settings: &Value,
    ) -> Result<(), String> {
        ensure((1..=4).contains(&lease.secrets.len()), "secrets count")?;
        ensure(lease.plain.len() <= 4, "plain count")?;
        let names = lease.names();
        ensure(names.iter().all(|name| is_env_name(name)), "variable name")?;
        ensure(distinct(&names), "distinct names")?;
        ensure(
            lease.secrets[0].name == binding,
            "first secret is the binding",
        )?;
        let fixed: Vec<&str> = lease.secrets[1..]
            .iter()
            .map(|secret| secret.name.as_str())
            .collect();
        ensure(
            fixed
                == rule.secrets[1..]
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>(),
            "fixed secret names",
        )?;
        let plain: Vec<&str> = lease.plain.iter().map(|p| p.name.as_str()).collect();
        ensure(
            plain == rule.plain.iter().map(String::as_str).collect::<Vec<_>>(),
            "fixed plain names",
        )?;
        ensure(
            lease
                .secrets
                .iter()
                .all(|secret| is_deliverable_value(&secret.value)),
            "secret value",
        )?;
        ensure(
            lease.plain.iter().all(|p| is_deliverable_value(&p.text)),
            "plain text",
        )?;
        ensure(lease.made_at < lease.expires_at, "made_at < expires_at")?;
        if let Some(max) = rule.max_secs {
            ensure(lease.expires_at - lease.made_at <= max, "lifetime")?;
        }
        match (rule.revoke.as_deref(), &lease.revoke) {
            (None, None) => {}
            (Some("github"), Some(revoke)) => {
                let api = settings
                    .get("api_url")
                    .and_then(Value::as_str)
                    .unwrap_or("https://api.github.com");
                ensure(
                    revoke.kind == RevokeKind::Github
                        && revoke.url == format!("{api}/installation/token"),
                    "github revoke",
                )?;
            }
            (Some("oauth"), revoke) => {
                let url = settings.get("revoke_url").and_then(Value::as_str);
                ensure(
                    match (url, revoke) {
                        (None, None) => true,
                        (Some(url), Some(revoke)) => {
                            revoke.kind == RevokeKind::Oauth && revoke.url == url
                        }
                        _ => false,
                    },
                    "oauth revoke",
                )?;
            }
            _ => return Err("revoke".to_owned()),
        }
        match (&lease.update_field, lease.kind) {
            (None, _) => {}
            (Some(update), LeaseKind::OauthRefresh) => ensure(
                update.field == "refresh_token" && is_deliverable_value(&update.value),
                "update_field",
            )?,
            (Some(_), _) => return Err("update_field outside oauth_refresh".to_owned()),
        }
        let first = &lease.secrets[0].value;
        match lease.kind {
            LeaseKind::AwsSts => {
                ensure(
                    first.len() == 20
                        && first.starts_with("ASIA")
                        && all_chars(&first[4..], |c| {
                            c.is_ascii_uppercase() || c.is_ascii_digit()
                        }),
                    "ASIA key id",
                )?;
                ensure(
                    lease.plain[0].text == rfc3339(lease.expires_at),
                    "AWS_CREDENTIAL_EXPIRATION equals expires_at",
                )?;
            }
            LeaseKind::GithubApp => ensure(first.starts_with("ghs_"), "ghs_ token")?,
            _ => {}
        }
        Ok(())
    }

    // ----- section 5: the views ----------------------------------------------------------

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct SessionView {
        pub session_id: u64,
        pub expires_at: u64,
        pub env: BTreeMap<String, String>,
        pub placeholders: Vec<String>,
        pub base_urls: BTreeMap<String, String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub short_lived: Vec<LeaseView>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub signers: Vec<SignerView>,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct LeaseView {
        pub item_id: u64,
        pub kind: LeaseKind,
        pub env_names: Vec<String>,
        pub expires_at: u64,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct SignerView {
        pub item_id: u64,
        pub env_name: String,
        pub access_key_id: String,
    }

    pub fn session_view() -> SessionView {
        strict("session-view.json", SESSION_VIEW)
    }

    /// Section 5.2: the rules of the two additions.
    pub fn check_session(view: &SessionView) -> Result<(), String> {
        let placeholders: BTreeSet<&str> = view.placeholders.iter().map(String::as_str).collect();
        ensure(
            view.env.get("APASSY_RELAY_SESSION_EXPIRES") == Some(&view.expires_at.to_string()),
            "APASSY_RELAY_SESSION_EXPIRES",
        )?;
        for lease in &view.short_lived {
            ensure(!lease.env_names.is_empty(), "lease env_names")?;
            for name in &lease.env_names {
                ensure(view.env.contains_key(name), "lease variable in env")?;
                ensure(
                    !placeholders.contains(name.as_str()),
                    "lease variable is no placeholder",
                )?;
                ensure(
                    !view.env.contains_key(&format!("APASSY_BASE_{name}")),
                    "lease variable has no base URL",
                )?;
            }
            ensure(
                view.expires_at.saturating_add(30) <= lease.expires_at,
                "session ends 30 s before its lease",
            )?;
        }
        for signer in &view.signers {
            let placeholder = view.env.get(&signer.env_name);
            ensure(
                placeholders.contains(signer.env_name.as_str())
                    && placeholder.is_some_and(|value| value.len() == 40),
                "signer placeholder",
            )?;
            ensure(
                view.env.get("AWS_ACCESS_KEY_ID") == Some(&signer.access_key_id)
                    && !placeholders.contains("AWS_ACCESS_KEY_ID"),
                "signer access key id",
            )?;
            ensure(
                !view
                    .env
                    .contains_key(&format!("APASSY_BASE_{}", signer.env_name)),
                "signer has no base URL",
            )?;
        }
        let lease_ids: Vec<u64> = view.short_lived.iter().map(|lease| lease.item_id).collect();
        let signer_ids: Vec<u64> = view.signers.iter().map(|signer| signer.item_id).collect();
        ensure(
            lease_ids.windows(2).all(|w| w[0] < w[1]),
            "short_lived order",
        )?;
        ensure(signer_ids.windows(2).all(|w| w[0] < w[1]), "signers order")?;
        ensure(
            lease_ids.iter().all(|id| !signer_ids.contains(id)),
            "an item is a lease or a signer",
        )?;
        let mut names: Vec<String> = view
            .short_lived
            .iter()
            .flat_map(|lease| lease.env_names.iter().cloned())
            .collect();
        names.extend(view.signers.iter().map(|signer| signer.env_name.clone()));
        ensure(distinct(&names), "no name in two items")?;
        Ok(())
    }

    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum CredentialForm {
        #[default]
        Placeholder,
        TemporaryCredentials,
        SignedRequests,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct AccessView {
        pub agent_id: u64,
        pub agent: String,
        pub member: String,
        pub items: Vec<AccessItem>,
        pub note: String,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct AccessItem {
        pub item_id: u64,
        pub item_name: String,
        pub collection: String,
        pub env_name: String,
        pub hosts: Vec<String>,
        pub environment: String,
        pub base_url_vars: Vec<String>,
        pub approval: String,
        pub rule: Value,
        #[serde(default)]
        pub credential_form: CredentialForm,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct RunView {
        pub run_id: u64,
        pub status: String,
        #[serde(default)]
        pub decided_by: Option<String>,
        #[serde(default)]
        pub approver: Option<String>,
        #[serde(default)]
        pub code: Option<String>,
        pub note: String,
        pub flags: Vec<String>,
        pub created_at: u64,
        #[serde(default)]
        pub expires_at: Option<u64>,
        #[serde(default)]
        pub session: Option<SessionView>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct AuditEntry {
        pub id: u64,
        pub at: u64,
        pub actor: String,
        pub action: String,
        #[serde(default)]
        pub run_id: Option<u64>,
        pub detail: serde_json::Map<String, Value>,
    }

    /// Section 10: the exact `detail` fields of each action.
    pub fn audit_fields(action: &str) -> Option<&'static [&'static str]> {
        let fields: &'static [&'static str] = match action {
            "lease_made" => &["expires_at", "item_id", "kind"],
            "lease_revoked" => &["item_id", "kind"],
            "lease_revoke_failed" | "lease_failed" => &["item_id", "kind", "status"],
            "sign_request" => &[
                "item_id",
                "method",
                "path",
                "region",
                "service",
                "session_id",
            ],
            "member_key_made" | "member_key_deleted" => {
                &["item_id", "manager", "member_id", "source_item_id"]
            }
            _ => return None,
        };
        Some(fields)
    }

    // ----- section 7: signing ------------------------------------------------------------

    #[derive(Debug, Clone, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct SignRequest {
        pub session_id: u64,
        pub item_id: u64,
        pub scope: SignScope,
        pub canonical_request: String,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct SignScope {
        pub date: String,
        pub region: String,
        pub service: String,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct SignAnswer {
        pub signature: String,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct WireError {
        pub code: String,
        pub message: String,
    }

    /// The relay envelope (`apassy::agent::wire::WireResponse`).
    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Envelope<T> {
        pub ok: bool,
        // A missing `Option` field reads as `None`; `#[serde(default)]` would ask for
        // `T: Default`.
        pub result: Option<T>,
        pub error: Option<WireError>,
    }

    pub fn sign_request() -> SignRequest {
        strict("sign-request.json", SIGN_REQUEST)
    }

    /// The parts of a SigV4 canonical request (section 7.2).
    pub struct Canonical<'a> {
        pub method: &'a str,
        pub uri: &'a str,
        pub query: &'a str,
        pub headers: Vec<(&'a str, &'a str)>,
        pub payload_hash: &'a str,
    }

    impl Canonical<'_> {
        pub fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| *value)
        }
    }

    pub fn parse_canonical(text: &str) -> Result<Canonical<'_>, &'static str> {
        if text.contains('\r') {
            return Err(INVALID_REQUEST);
        }
        let lines: Vec<&str> = text.split('\n').collect();
        let n = lines.len();
        if n < 7 || !lines[n - 3].is_empty() {
            return Err(INVALID_REQUEST);
        }
        let mut headers = Vec::new();
        for &line in &lines[3..n - 3] {
            let (name, value) = line.split_once(':').ok_or(INVALID_REQUEST)?;
            if !all_chars(name, |c| {
                c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'
            }) {
                return Err(INVALID_REQUEST);
            }
            headers.push((name, value));
        }
        let sorted = headers.windows(2).all(|w| w[0].0 < w[1].0);
        let signed: Vec<&str> = lines[n - 2].split(';').collect();
        let names: Vec<&str> = headers.iter().map(|(name, _)| *name).collect();
        if !sorted || signed != names {
            return Err(INVALID_REQUEST);
        }
        let canonical = Canonical {
            method: lines[0],
            uri: lines[1],
            query: lines[2],
            headers,
            payload_hash: lines[n - 1],
        };
        if canonical.method.len() > 16
            || !all_chars(canonical.method, |c| c.is_ascii_uppercase())
            || !canonical.uri.starts_with('/')
        {
            return Err(INVALID_REQUEST);
        }
        Ok(canonical)
    }

    pub fn is_lower_hex(text: &str, len: usize) -> bool {
        text.len() == len
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }

    /// Days since 1970-01-01 of a Gregorian date.
    pub fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
        let year = if month <= 2 { year - 1 } else { year };
        let era = year.div_euclid(400);
        let yoe = year - era * 400;
        let mp = (month + 9) % 12;
        let doy = (153 * mp + 2) / 5 + day - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        era * 146_097 + doe - 719_468
    }

    /// RFC 3339 UTC of Unix seconds, `YYYY-MM-DDTHH:MM:SSZ`.
    pub fn rfc3339(unix: u64) -> String {
        let days = i64::try_from(unix / 86_400).expect("days");
        let secs = unix % 86_400;
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = doy - (153 * mp + 2) / 5 + 1;
        let month = if mp < 10 { mp + 3 } else { mp - 9 };
        let year = yoe + era * 400 + i64::from(month <= 2);
        format!(
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
            secs / 3600,
            secs % 3600 / 60,
            secs % 60
        )
    }

    /// Unix seconds of an `x-amz-date` (`YYYYMMDDTHHMMSSZ`).
    pub fn amz_date_secs(date: &str) -> Option<i64> {
        let bytes = date.as_bytes();
        if bytes.len() != 16 || bytes[8] != b'T' || bytes[15] != b'Z' {
            return None;
        }
        let digits = |range: std::ops::Range<usize>| -> Option<i64> {
            let part = date.get(range)?;
            if !all_chars(part, |c| c.is_ascii_digit()) {
                return None;
            }
            part.parse().ok()
        };
        let (year, month, day) = (digits(0..4)?, digits(4..6)?, digits(6..8)?);
        let (hour, minute, second) = (digits(9..11)?, digits(11..13)?, digits(13..15)?);
        if !(1..=12).contains(&month)
            || !(1..=31).contains(&day)
            || hour > 23
            || minute > 59
            || second > 59
        {
            return None;
        }
        Some(days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second)
    }

    /// Section 7.2 without the session state (live session, member, item in the session,
    /// the limit): the checks that depend only on the request, the item's hosts and
    /// services, and the host's clock. `Err` is the `sign_refused` message, or
    /// `INVALID_REQUEST` for a request without the shape of the section.
    pub fn check_sign(
        request: &SignRequest,
        item_hosts: &[&str],
        services: Option<&[&str]>,
        now: u64,
    ) -> Result<(), &'static str> {
        let scope = &request.scope;
        if request.session_id == 0
            || request.item_id == 0
            || scope.date.len() != 8
            || !all_chars(&scope.date, |c| c.is_ascii_digit())
            || !is_aws_name(&scope.region)
            || !is_aws_name(&scope.service)
        {
            return Err(INVALID_REQUEST);
        }
        let canonical = parse_canonical(&request.canonical_request)?;
        let host = canonical.header("host").ok_or(REFUSED_HOST)?;
        let host = host.split(':').next().unwrap_or("");
        if !item_hosts
            .iter()
            .any(|item| host == *item || host.ends_with(&format!(".{item}")))
        {
            return Err(REFUSED_HOST);
        }
        let date = canonical.header("x-amz-date").ok_or(REFUSED_DATE)?;
        let at = amz_date_secs(date).ok_or(REFUSED_DATE)?;
        let now = i64::try_from(now).expect("now");
        if !date.starts_with(scope.date.as_str()) || (at - now).abs() > 900 {
            return Err(REFUSED_DATE);
        }
        if let Some(services) = services
            && !services.contains(&scope.service.as_str())
        {
            return Err(REFUSED_SERVICE);
        }
        let presigned = canonical.query.split('&').any(|pair| {
            let key = pair.split('=').next().unwrap_or("");
            ["X-Amz-Signature", "X-Amz-Credential", "X-Amz-Algorithm"]
                .iter()
                .any(|name| key.eq_ignore_ascii_case(name))
        });
        if presigned {
            return Err(REFUSED_PRESIGNED);
        }
        let hash = canonical.payload_hash;
        let bodiless = matches!(canonical.method, "GET" | "HEAD" | "DELETE")
            && canonical
                .header("content-length")
                .is_none_or(|len| len == "0");
        let hash_ok = if hash == "UNSIGNED-PAYLOAD" {
            bodiless
        } else {
            is_lower_hex(hash, 64)
        };
        let content_ok = canonical
            .header("x-amz-content-sha256")
            .is_none_or(|value| value == hash);
        if hash.starts_with("STREAMING-") || !hash_ok || !content_ok {
            return Err(REFUSED_PAYLOAD);
        }
        Ok(())
    }

    /// A canonical request from its parts, headers in the given order.
    pub fn canonical(
        method: &str,
        uri: &str,
        query: &str,
        headers: &[(&str, &str)],
        hash: &str,
    ) -> String {
        let lines: Vec<String> = headers
            .iter()
            .map(|(name, value)| format!("{name}:{value}"))
            .collect();
        let signed: Vec<&str> = headers.iter().map(|(name, _)| *name).collect();
        format!(
            "{method}\n{uri}\n{query}\n{}\n\n{}\n{hash}",
            lines.join("\n"),
            signed.join(";")
        )
    }

    #[cfg(feature = "vault")]
    pub fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The SigV4 signature of section 7.2, with `ring` as the product code uses it.
    #[cfg(feature = "vault")]
    pub fn sigv4_signature(
        secret: &str,
        scope: &SignScope,
        amz_date: &str,
        canonical_request: &str,
    ) -> String {
        use ring::{digest, hmac};
        let hashed = hex(digest::digest(&digest::SHA256, canonical_request.as_bytes()).as_ref());
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{}/{}/{}/aws4_request\n{hashed}",
            scope.date, scope.region, scope.service
        );
        let mut key = format!("AWS4{secret}").into_bytes();
        for part in [
            scope.date.as_str(),
            scope.region.as_str(),
            scope.service.as_str(),
            "aws4_request",
        ] {
            let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &key), part.as_bytes());
            key = tag.as_ref().to_vec();
        }
        let tag = hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, &key),
            string_to_sign.as_bytes(),
        );
        hex(tag.as_ref())
    }

    // ----- section 2 rule 6: the no-secret scan -------------------------------------------

    /// The armor-stripped body of a PEM text, or `None` for a text without armor.
    fn pem_body(text: &str) -> Option<String> {
        if !text.contains("-----BEGIN ") {
            return None;
        }
        let body: String = text
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        (!body.is_empty()).then_some(body)
    }

    /// Every long-lived synthetic secret of `sources.json`, with the PEM bodies and the
    /// private parts of a service-account key, and the rotated refresh token.
    pub fn long_lived_canaries() -> Vec<String> {
        let mut canaries = Vec::new();
        for source in sources().values() {
            for field in source.fields.iter().filter(|field| field.secret) {
                canaries.push(field.value.clone());
                canaries.extend(pem_body(&field.value));
                if let Ok(Value::Object(key)) = serde_json::from_str::<Value>(&field.value) {
                    for name in ["private_key", "private_key_id"] {
                        if let Some(part) = key.get(name).and_then(Value::as_str) {
                            canaries.push(part.to_owned());
                            canaries.extend(pem_body(part));
                        }
                    }
                }
            }
        }
        for (kind, _) in LEASES {
            if let Some(update) = lease(kind).update_field {
                canaries.push(update.value);
            }
        }
        canaries
    }

    /// Every short-lived value of the lease fixtures.
    pub fn lease_canaries() -> Vec<String> {
        LEASES
            .iter()
            .flat_map(|(kind, _)| lease(kind).secrets.into_iter().map(|secret| secret.value))
            .collect()
    }

    pub fn assert_no_canary(name: &str, text: &str, canaries: &[String]) {
        for canary in canaries {
            assert!(
                !text.contains(canary.as_str()),
                "{name} holds a synthetic secret of the no-secret rule"
            );
        }
    }
}

#[test]
fn private_sharing_v1_fixtures_match_the_contract() {
    use private_sharing as ps;

    let kinds = ps::kinds();
    let sources = ps::sources();
    let contract = ps::CONTRACT;

    // Section 3: every kind, the reserved ones, and their names in the vault CHECK list.
    let all = [
        ps::LeaseKind::AwsSts,
        ps::LeaseKind::GithubApp,
        ps::LeaseKind::GoogleServiceAccount,
        ps::LeaseKind::OauthRefresh,
        ps::LeaseKind::CloudflareToken,
        ps::LeaseKind::PlanetscalePassword,
        ps::LeaseKind::NeonRole,
    ];
    assert_eq!(
        kinds.kinds,
        all.iter().map(|kind| kind.name()).collect::<Vec<_>>()
    );
    for kind in all {
        let encoded = serde_json::to_string(&kind).expect("kind json");
        assert_eq!(encoded, format!("\"{}\"", kind.name()));
        assert!(contract.contains(&format!("`{}`", kind.name())), "{kind:?}");
    }
    let active: Vec<&String> = kinds
        .kinds
        .iter()
        .filter(|kind| !kinds.reserved.contains(kind))
        .collect();
    assert_eq!(active.len(), 4);
    for kind in &active {
        assert!(kinds.fields.contains_key(*kind), "{kind}: fields");
        assert!(kinds.settings.contains_key(*kind), "{kind}: settings");
        assert!(kinds.lease.contains_key(*kind), "{kind}: lease");
    }
    for reserved in &kinds.reserved {
        assert!(!kinds.fields.contains_key(reserved), "{reserved}: reserved");
        assert!(
            ps::check_settings(reserved, &json!({})).is_err(),
            "{reserved}"
        );
    }

    // Section 3.1: the field table of the contract and of kinds.json are the same, and
    // each synthetic source has exactly the fields of its kind with the secret flags.
    for (kind, fields) in &kinds.fields {
        for field in fields {
            let yes = |flag: bool| if flag { "yes" } else { "no" };
            let row = format!(
                "| `{kind}` | `{}` | {} | {} |",
                field.name,
                yes(field.secret),
                yes(field.required)
            );
            assert!(contract.contains(&row), "contract row {row}");
        }
        let source = sources
            .get(kind)
            .unwrap_or_else(|| panic!("{kind}: source"));
        let names: Vec<(&str, bool)> = source
            .fields
            .iter()
            .map(|field| (field.name.as_str(), field.secret))
            .collect();
        let expected: Vec<(&str, bool)> = fields
            .iter()
            .map(|field| (field.name.as_str(), field.secret))
            .collect();
        assert_eq!(names, expected, "{kind}: source fields");
        assert!(ps::is_env_name(&source.env_name), "{kind}: binding");
    }
    let aws = &sources["aws_sts"].fields;
    assert!(aws[0].value.starts_with("AKIA") && aws[0].value.len() == 20);
    assert_eq!(aws[1].value.len(), 40);
    assert_eq!(sources["aws_sts"].env_name, "AWS_ACCESS_KEY_ID");
    assert_eq!(
        sources["google_service_account"].env_name,
        "CLOUDSDK_AUTH_ACCESS_TOKEN"
    );
    let key_json: Value =
        serde_json::from_str(&sources["google_service_account"].fields[0].value).expect("key_json");
    assert_eq!(key_json["type"], "service_account");
    for name in ["client_email", "private_key", "token_uri"] {
        assert!(key_json[name].is_string(), "key_json.{name}");
    }

    // Section 3.2: the settings table, and each settings fixture passes the strict rules.
    for (kind, settings) in &kinds.settings {
        for setting in settings {
            let row = format!("| `{kind}` | `{setting}` |");
            assert!(contract.contains(&row), "contract row {row}");
        }
    }
    for (kind, _) in ps::SETTINGS {
        let value = ps::settings_value(kind);
        ps::check_settings(kind, &value).unwrap_or_else(|err| panic!("{kind}: {err}"));
        let mut keys: Vec<&String> = value.as_object().expect("settings object").keys().collect();
        let mut expected: Vec<&String> = kinds.settings[kind].iter().collect();
        keys.sort();
        expected.sort();
        assert_eq!(keys, expected, "{kind}: the fixture sets every setting");
    }

    // Section 4: each lease fixture follows the rules of its kind.
    for (kind, _) in ps::LEASES {
        let lease = ps::lease(kind);
        assert_eq!(lease.kind.name(), kind);
        ps::check_lease(
            &lease,
            &kinds.lease[kind],
            &sources[kind].env_name,
            &ps::settings_value(kind),
        )
        .unwrap_or_else(|err| panic!("{kind}: {err}"));
    }
    for rule in kinds.lease.values() {
        for name in rule.secrets.iter().chain(&rule.plain) {
            if name != "$binding" {
                assert!(contract.contains(&format!("`{name}`")), "{name}");
            }
        }
    }

    // Section 5.2: the session view, and its lease is the github_app lease fixture.
    let view = ps::session_view();
    ps::check_session(&view).unwrap_or_else(|err| panic!("session view: {err}"));
    let github = ps::lease("github_app");
    assert_eq!(view.short_lived.len(), 1);
    assert_eq!(view.short_lived[0].kind, ps::LeaseKind::GithubApp);
    assert_eq!(view.short_lived[0].env_names, github.names());
    assert_eq!(view.short_lived[0].expires_at, github.expires_at);
    for secret in &github.secrets {
        assert_eq!(view.env.get(&secret.name), Some(&secret.value));
    }
    assert_eq!(view.signers.len(), 1);
    assert_eq!(
        view.signers[0].access_key_id,
        sources["aws_sts"].fields[0].value
    );
    assert!(
        !view
            .env
            .keys()
            .any(|name| name.starts_with("AWS_ENDPOINT_URL"))
    );

    // Section 5.4: one access item of each credential form, matching the session view.
    let access: ps::AccessView = ps::strict("access-view.json", ps::ACCESS_VIEW);
    let forms: Vec<String> = access
        .items
        .iter()
        .map(|item| serde_json::to_value(item.credential_form).expect("credential form json"))
        .map(|value| value.as_str().expect("credential form text").to_owned())
        .collect();
    assert_eq!(forms, kinds.credential_form);
    for form in &kinds.credential_form {
        assert!(contract.contains(&format!("| `{form}` |")), "{form}");
    }
    for item in &access.items {
        match item.credential_form {
            ps::CredentialForm::Placeholder => assert!(!item.base_url_vars.is_empty()),
            ps::CredentialForm::TemporaryCredentials => {
                assert!(item.base_url_vars.is_empty());
                assert!(
                    view.short_lived
                        .iter()
                        .any(|lease| lease.item_id == item.item_id
                            && lease.env_names[0] == item.env_name)
                );
            }
            ps::CredentialForm::SignedRequests => {
                assert!(item.base_url_vars.is_empty());
                assert!(view.signers.iter().any(
                    |signer| signer.item_id == item.item_id && signer.env_name == item.env_name
                ));
            }
        }
        #[cfg(feature = "vault")]
        let _rule: apassy::vault::ExecRule =
            serde_json::from_value(item.rule.clone()).expect("rule");
    }

    // Section 7.2: the sign request and its answer.
    let request = ps::sign_request();
    ps::check_sign(&request, &["amazonaws.com"], None, ps::VANILLA_NOW).expect("vanilla request");
    assert_eq!(request.item_id, view.signers[0].item_id);
    assert_eq!(request.session_id, view.session_id);
    let answer: ps::Envelope<ps::SignAnswer> = ps::strict("sign-answer.json", ps::SIGN_ANSWER);
    assert!(answer.ok && answer.error.is_none());
    let signature = answer.result.expect("sign result").signature;
    assert!(ps::is_lower_hex(&signature, 64), "{signature}");

    // Section 9: the error answers, with messages of the contract.
    for (name, text, code) in ps::ERRORS {
        let envelope: ps::Envelope<Value> = ps::strict(name, text);
        assert!(!envelope.ok && envelope.result.is_none(), "{name}");
        let error = envelope.error.unwrap_or_else(|| panic!("{name}: error"));
        assert_eq!(error.code, code, "{name}");
        assert!(kinds.codes.contains(&error.code), "{name}");
        assert!(contract.contains(&error.message), "{name}: message");
    }
    for message in [
        ps::REFUSED_SESSION,
        ps::REFUSED_ITEM,
        ps::REFUSED_HOST,
        ps::REFUSED_DATE,
        ps::REFUSED_SERVICE,
        ps::REFUSED_PRESIGNED,
        ps::REFUSED_PAYLOAD,
        ps::REFUSED_LIMIT,
    ] {
        assert!(contract.contains(message), "{message}");
    }
    let run: ps::RunView = ps::strict("run-lease-failed.json", ps::RUN_LEASE_FAILED);
    assert_eq!(run.status, "denied");
    assert_eq!(run.code.as_deref(), Some("lease_failed"));
    assert_eq!(run.decided_by.as_deref(), Some("host"));
    assert!(run.session.is_none() && run.approver.is_none() && run.expires_at.is_none());
    assert!(run.run_id >= 1 && run.created_at > 0 && run.flags.is_empty());

    // Section 10: one audit row per action, with exactly the fields of the table.
    let rows: Vec<ps::AuditEntry> = ps::strict("audit-rows.json", ps::AUDIT_ROWS);
    let actions: Vec<&str> = rows.iter().map(|row| row.action.as_str()).collect();
    assert_eq!(actions, kinds.audit_actions);
    for row in &rows {
        let fields = ps::audit_fields(&row.action).unwrap_or_else(|| panic!("{}", row.action));
        let mut keys: Vec<&str> = row.detail.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, fields, "{}", row.action);
        assert!(
            contract.contains(&format!("| `{}` |", row.action)),
            "{}",
            row.action
        );
        let member = row.actor.strip_prefix("member:").map(str::parse::<u64>);
        if row.action == "sign_request" {
            assert!(matches!(member, Some(Ok(_))), "{}", row.actor);
            let path = row.detail["path"].as_str().expect("path");
            assert!(path.starts_with('/') && !path.contains('?'), "{path}");
        } else {
            assert_eq!(row.actor, "relay", "{}", row.action);
        }
        assert!(row.id >= 1 && row.at > 0);
        assert!(row.run_id.is_none_or(|run| run >= 1));
    }
    for code in &kinds.codes {
        assert!(contract.contains(&format!("| `{code}` |")), "{code}");
    }
}

#[test]
fn private_sharing_v1_settings_are_strict_and_hold_no_secret() {
    use private_sharing::check_settings;

    let refused = |kind: &str, patch: &dyn Fn(&mut Value)| {
        let mut value = private_sharing::settings_value(kind);
        patch(&mut value);
        assert!(check_settings(kind, &value).is_err(), "{kind}: {value}");
    };

    // An empty object is the default of the column, and valid where nothing is required.
    for kind in ["aws_sts", "github_app", "google_service_account"] {
        check_settings(kind, &json!({})).unwrap_or_else(|err| panic!("{kind}: {err}"));
    }
    assert!(check_settings("oauth_refresh", &json!({})).is_err());

    // A secret has no field in the settings: an unknown field is refused.
    refused("aws_sts", &|v| {
        v["secret_access_key"] = json!("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY")
    });
    refused("github_app", &|v| v["private_key"] = json!("pem"));
    refused("google_service_account", &|v| v["key_json"] = json!("{}"));
    refused("oauth_refresh", &|v| v["refresh_token"] = json!("token"));
    refused("oauth_refresh", &|v| v["client_secret"] = json!("secret"));

    refused("aws_sts", &|v| {
        v["role_arn"] = json!("arn:aws:iam::12345:role/x")
    });
    refused("aws_sts", &|v| {
        v["role_arn"] = json!("arn:aws:iam::123456789012:user/x")
    });
    refused("aws_sts", &|v| v["policy"] = json!("not json"));
    refused("aws_sts", &|v| v["policy"] = json!("[]"));
    refused("aws_sts", &|v| {
        v["policy"] = json!(format!("{{\"Version\":\"{}\"}}", "x".repeat(2040)))
    });
    refused("aws_sts", &|v| v["region"] = json!("EU-central-1"));
    refused("aws_sts", &|v| v["region"] = json!("eu-central"));
    refused("aws_sts", &|v| v["services"] = json!([]));
    refused("aws_sts", &|v| v["services"] = json!(["s3", "s3"]));
    refused("aws_sts", &|v| v["services"] = json!(["S3"]));
    refused("aws_sts", &|v| v["region"] = json!(1));

    refused("github_app", &|v| {
        v["permissions"] = json!({"contents": "owner"})
    });
    refused("github_app", &|v| v["permissions"] = json!({}));
    refused("github_app", &|v| {
        v["api_url"] = json!("http://api.github.com")
    });
    refused("github_app", &|v| {
        v["api_url"] = json!("https://user@api.github.com")
    });
    refused("github_app", &|v| v["repositories"] = json!(["owner/repo"]));
    refused("github_app", &|v| v["repositories"] = json!([]));

    refused("google_service_account", &|v| v["scopes"] = json!([]));
    refused("google_service_account", &|v| {
        v["scopes"] = json!(["cloud-platform"])
    });
    refused("google_service_account", &|v| {
        v["impersonate"] = json!("someone@example.com")
    });

    refused("oauth_refresh", &|v| v["client_auth"] = json!("post"));
    refused("oauth_refresh", &|v| {
        v.as_object_mut().expect("object").remove("client_auth");
    });
    refused("oauth_refresh", &|v| {
        v["token_url"] = json!("http://auth.example.test/token")
    });
    refused("oauth_refresh", &|v| {
        v["revoke_url"] = json!("https://auth.example.test/revoke?x=1")
    });
    refused("oauth_refresh", &|v| {
        v["revoke_url"] = json!("https://other.example.test/oauth/revoke")
    });
    refused("oauth_refresh", &|v| v["scope"] = json!(""));

    // Duplicate fields are refused by the strict reader too.
    let duplicate = r#"{"region": "eu-central-1", "region": "us-east-1"}"#;
    assert!(serde_json::from_str::<private_sharing::AwsStsSettings>(duplicate).is_err());
    assert!(check_settings("unknown_kind", &json!({})).is_err());
}

#[test]
fn private_sharing_v1_leases_have_the_fixed_names_and_lifetimes() {
    use private_sharing as ps;

    let kinds = ps::kinds();
    let sources = ps::sources();
    let check = |kind: &str, patch: &dyn Fn(&mut ps::Lease)| {
        let mut lease = ps::lease(kind);
        patch(&mut lease);
        ps::check_lease(
            &lease,
            &kinds.lease[kind],
            &sources[kind].env_name,
            &ps::settings_value(kind),
        )
    };
    for (kind, _) in ps::LEASES {
        check(kind, &|_| {}).unwrap_or_else(|err| panic!("{kind}: {err}"));
    }

    // AWS: 900 seconds at most, the fixed names, and the expiration text.
    assert_eq!(ps::rfc3339(1_793_700_900), "2026-11-03T10:15:00Z");
    assert_eq!(ps::rfc3339(951_782_400), "2000-02-29T00:00:00Z");
    assert!(check("aws_sts", &|l| l.expires_at = l.made_at + 901).is_err());
    assert!(check("aws_sts", &|l| l.expires_at = l.made_at).is_err());
    assert!(check("aws_sts", &|l| l.secrets[1].name = "AWS_SECRET_KEY".into()).is_err());
    assert!(check("aws_sts", &|l| l.secrets[0].name = "OTHER_KEY".into()).is_err());
    assert!(
        check("aws_sts", &|l| l.secrets[0].value =
            "AKIAIOSFODNN7EXAMPLE".into())
        .is_err()
    );
    assert!(
        check("aws_sts", &|l| l.plain[0].text =
            "2026-11-03T10:30:00Z".into())
        .is_err()
    );
    assert!(check("aws_sts", &|l| l.plain.clear()).is_err());
    assert!(check("aws_sts", &|l| l.secrets[2].value = "with\"quote".into()).is_err());
    assert!(check("aws_sts", &|l| l.secrets[2].value = "x".repeat(4097)).is_err());
    assert!(
        check("aws_sts", &|l| {
            l.update_field = Some(ps::UpdateField {
                field: "refresh_token".into(),
                value: "x".into(),
            })
        })
        .is_err()
    );

    // GitHub: one hour at most, revoked through the API of the settings.
    assert!(check("github_app", &|l| l.expires_at = l.made_at + 3601).is_err());
    assert!(check("github_app", &|l| l.revoke = None).is_err());
    assert!(
        check("github_app", &|l| {
            l.revoke = Some(ps::Revoke {
                kind: ps::RevokeKind::Github,
                url: "https://evil.example/installation/token".into(),
            })
        })
        .is_err()
    );
    assert!(check("github_app", &|l| l.secrets[0].value = "gho_token".into()).is_err());

    // Google: 900 seconds at most, no revoke.
    assert!(
        check("google_service_account", &|l| l.expires_at =
            l.made_at + 3600)
        .is_err()
    );
    assert!(
        check("google_service_account", &|l| {
            l.revoke = Some(ps::Revoke {
                kind: ps::RevokeKind::Oauth,
                url: "https://oauth2.googleapis.com/revoke".into(),
            })
        })
        .is_err()
    );

    // OAuth: the revoke URL of the settings; only the refresh token is stored back.
    assert!(check("oauth_refresh", &|l| l.revoke = None).is_err());
    assert!(
        check("oauth_refresh", &|l| {
            if let Some(update) = &mut l.update_field {
                update.field = "client_secret".into();
            }
        })
        .is_err()
    );
    assert!(
        check("oauth_refresh", &|l| {
            l.plain.push(ps::LeasePlain {
                name: "EXAMPLE_ACCESS_TOKEN".into(),
                text: "x".into(),
            })
        })
        .is_err()
    );

    // The strict reader refuses an unknown field and an unknown kind.
    let mut value: Value = serde_json::from_str(ps::LEASES[0].1).expect("lease json");
    value["refresh_token"] = json!("x");
    assert!(serde_json::from_value::<ps::Lease>(value).is_err());
    let mut value: Value = serde_json::from_str(ps::LEASES[0].1).expect("lease json");
    value["kind"] = json!("aws_session_token");
    assert!(serde_json::from_value::<ps::Lease>(value).is_err());
}

#[test]
fn private_sharing_v1_session_view_keeps_leases_out_of_placeholders() {
    use private_sharing as ps;

    let check = |patch: &dyn Fn(&mut ps::SessionView)| {
        let mut view = ps::session_view();
        patch(&mut view);
        ps::check_session(&view)
    };
    check(&|_| {}).expect("fixture");
    assert!(check(&|v| v.placeholders.push("GITHUB_TOKEN".into())).is_err());
    assert!(
        check(&|v| {
            v.env.insert(
                "APASSY_BASE_GITHUB_TOKEN".into(),
                "https://x.test/p/k/api.github.com".into(),
            );
        })
        .is_err()
    );
    assert!(
        check(&|v| {
            v.expires_at = v.short_lived[0].expires_at - 10;
            v.env.insert(
                "APASSY_RELAY_SESSION_EXPIRES".into(),
                v.expires_at.to_string(),
            );
        })
        .is_err()
    );
    assert!(
        check(&|v| {
            v.env.remove("GITHUB_TOKEN");
        })
        .is_err()
    );
    assert!(
        check(&|v| v
            .placeholders
            .retain(|name| name != "AWS_SECRET_ACCESS_KEY"))
        .is_err()
    );
    assert!(check(&|v| v.signers[0].access_key_id = "AKIAOTHEROTHEROTHER0".into()).is_err());
    assert!(check(&|v| v.placeholders.push("AWS_ACCESS_KEY_ID".into())).is_err());
    assert!(
        check(&|v| {
            v.env
                .insert("AWS_SECRET_ACCESS_KEY".into(), "short-placeholder".into());
        })
        .is_err()
    );
    assert!(check(&|v| v.short_lived[0].item_id = v.signers[0].item_id).is_err());
    assert!(check(&|v| v.signers[0].env_name = "GITHUB_TOKEN".into()).is_err());

    // Unknown fields and unknown kinds are refused by the strict reader.
    let mut value: Value = serde_json::from_str(ps::SESSION_VIEW).expect("view json");
    value["short_lived"][0]["value"] = json!("x");
    assert!(serde_json::from_value::<ps::SessionView>(value).is_err());
    let mut value: Value = serde_json::from_str(ps::SESSION_VIEW).expect("view json");
    value["short_lived"][0]["kind"] = json!("aws_session");
    assert!(serde_json::from_value::<ps::SessionView>(value).is_err());
}

#[test]
fn private_sharing_v1_old_session_views_and_access_items_still_parse() {
    use private_sharing as ps;

    // The example of cloud-agents-v1 section 8: no way C, so no new array, and the bytes
    // of such a session do not change.
    let old = json!({
        "session_id": 7,
        "expires_at": 1_793_700_600u64,
        "env": {
            "HTTPBIN_TOKEN": "httpbin-test-Qm4tZ8rV1xK0pL6sYw2nC9dF3hJ5aB7e",
            "APASSY_BASE_HTTPBIN_TOKEN": "https://my-mac.tailnet-example.ts.net:8443/p/apassy_ses_x/httpbingo.org",
            "APASSY_RELAY_SESSION_EXPIRES": "1793700600"
        },
        "placeholders": ["HTTPBIN_TOKEN"],
        "base_urls": {"httpbingo.org": "https://my-mac.tailnet-example.ts.net:8443/p/apassy_ses_x/httpbingo.org"}
    });
    let view: ps::SessionView = serde_json::from_value(old.clone()).expect("old view");
    assert!(view.short_lived.is_empty() && view.signers.is_empty());
    ps::check_session(&view).expect("old view rules");
    assert_eq!(serde_json::to_value(&view).expect("view json"), old);

    // The fixture keeps both arrays when they are not empty.
    let fixture = serde_json::to_value(ps::session_view()).expect("fixture json");
    assert!(fixture["short_lived"].is_array() && fixture["signers"].is_array());
    let original: Value = serde_json::from_str(ps::SESSION_VIEW).expect("fixture");
    assert_eq!(fixture, original);

    // An access item of an older node has no credential form: it is a placeholder item.
    let mut item: Value =
        serde_json::from_str::<Value>(ps::ACCESS_VIEW).expect("access")["items"][0].clone();
    item.as_object_mut()
        .expect("item")
        .remove("credential_form");
    let parsed: ps::AccessItem = serde_json::from_value(item.clone()).expect("old item");
    assert_eq!(parsed.credential_form, ps::CredentialForm::Placeholder);
    let mut wrong = item.clone();
    wrong["credential_form"] = json!("real_value");
    assert!(serde_json::from_value::<ps::AccessItem>(wrong).is_err());
    // The old name is not read as the credential form (strict access items refuse it).
    let mut renamed = item;
    renamed["delivery"] = json!("temporary_credentials");
    assert!(serde_json::from_value::<ps::AccessItem>(renamed).is_err());
}

#[test]
fn private_sharing_v1_sign_requests_follow_the_refusals() {
    use private_sharing as ps;

    let hosts = ["amazonaws.com"];
    let empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let date = "20150830T123600Z";
    let with = |canonical_request: String| {
        let mut request = ps::sign_request();
        request.canonical_request = canonical_request;
        request
    };
    let get = |query: &str, host: &str, amz_date: &str, hash: &str| {
        with(ps::canonical(
            "GET",
            "/",
            query,
            &[("host", host), ("x-amz-date", amz_date)],
            hash,
        ))
    };

    // The vector is exactly the canonical form of its parts.
    let vanilla = get("", "example.amazonaws.com", date, empty);
    assert_eq!(
        vanilla.canonical_request,
        ps::sign_request().canonical_request
    );
    let ok = |request: &ps::SignRequest| ps::check_sign(request, &hosts, None, ps::VANILLA_NOW);
    ok(&vanilla).expect("vanilla");
    ok(&get("", "example.amazonaws.com", date, "UNSIGNED-PAYLOAD")).expect("bodiless GET");
    ok(&get("", "example.amazonaws.com:443", date, empty)).expect("host with a port");
    ok(&get("Param1=value1", "example.amazonaws.com", date, empty)).expect("query");

    let refused =
        |request: &ps::SignRequest| ps::check_sign(request, &hosts, None, ps::VANILLA_NOW);
    // Presigned URLs (S6-8).
    for query in [
        "X-Amz-Signature=abc",
        "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=x",
        "a=1&x-amz-credential=x",
    ] {
        assert_eq!(
            refused(&get(query, "example.amazonaws.com", date, empty)),
            Err(ps::REFUSED_PRESIGNED),
            "{query}"
        );
    }
    // Payload hashes.
    for hash in [
        "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
        "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
        "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
        "abc",
    ] {
        assert_eq!(
            refused(&get("", "example.amazonaws.com", date, hash)),
            Err(ps::REFUSED_PAYLOAD),
            "{hash}"
        );
    }
    let put = with(ps::canonical(
        "PUT",
        "/bucket/key",
        "",
        &[("host", "s3.amazonaws.com"), ("x-amz-date", date)],
        "UNSIGNED-PAYLOAD",
    ));
    assert_eq!(refused(&put), Err(ps::REFUSED_PAYLOAD));
    let with_body = with(ps::canonical(
        "GET",
        "/",
        "",
        &[
            ("content-length", "5"),
            ("host", "example.amazonaws.com"),
            ("x-amz-date", date),
        ],
        "UNSIGNED-PAYLOAD",
    ));
    assert_eq!(refused(&with_body), Err(ps::REFUSED_PAYLOAD));
    let other_content_hash = with(ps::canonical(
        "GET",
        "/",
        "",
        &[
            ("host", "example.amazonaws.com"),
            ("x-amz-content-sha256", "UNSIGNED-PAYLOAD"),
            ("x-amz-date", date),
        ],
        empty,
    ));
    assert_eq!(refused(&other_content_hash), Err(ps::REFUSED_PAYLOAD));
    // Hosts.
    for host in [
        "example.com",
        "evilamazonaws.com",
        "amazonaws.com.evil.test",
    ] {
        assert_eq!(
            refused(&get("", host, date, empty)),
            Err(ps::REFUSED_HOST),
            "{host}"
        );
    }
    let no_host = with(ps::canonical(
        "GET",
        "/",
        "",
        &[("x-amz-date", date)],
        empty,
    ));
    assert_eq!(refused(&no_host), Err(ps::REFUSED_HOST));
    // Dates: another day than the scope, or more than 15 minutes from the clock.
    assert_eq!(
        refused(&get("", "example.amazonaws.com", "20150831T000100Z", empty)),
        Err(ps::REFUSED_DATE)
    );
    assert_eq!(
        ps::check_sign(&vanilla, &hosts, None, ps::VANILLA_NOW + 901),
        Err(ps::REFUSED_DATE)
    );
    ps::check_sign(&vanilla, &hosts, None, ps::VANILLA_NOW + 900).expect("15 minutes");
    assert_eq!(
        refused(&get(
            "",
            "example.amazonaws.com",
            "2015-08-30T12:36Z",
            empty
        )),
        Err(ps::REFUSED_DATE)
    );
    // Services.
    assert_eq!(
        ps::check_sign(&vanilla, &hosts, Some(&["s3"]), ps::VANILLA_NOW),
        Err(ps::REFUSED_SERVICE)
    );
    ps::check_sign(&vanilla, &hosts, Some(&["s3", "service"]), ps::VANILLA_NOW).expect("service");

    // Shape: 400 invalid_request, not sign_refused.
    let unsorted = with(ps::canonical(
        "GET",
        "/",
        "",
        &[("x-amz-date", date), ("host", "example.amazonaws.com")],
        empty,
    ));
    assert_eq!(refused(&unsorted), Err(ps::INVALID_REQUEST));
    let crlf = with(vanilla.canonical_request.replace('\n', "\r\n"));
    assert_eq!(refused(&crlf), Err(ps::INVALID_REQUEST));
    let lower_method = with(vanilla.canonical_request.replacen("GET", "get", 1));
    assert_eq!(refused(&lower_method), Err(ps::INVALID_REQUEST));
    let mut bad_scope = ps::sign_request();
    bad_scope.scope.date = "2015-08-30".into();
    assert_eq!(refused(&bad_scope), Err(ps::INVALID_REQUEST));
    let mut bad_region = ps::sign_request();
    bad_region.scope.region = "US-EAST-1".into();
    assert_eq!(refused(&bad_region), Err(ps::INVALID_REQUEST));

    // Strict JSON: an unknown field (for example a body) and a missing field are refused.
    let mut value: Value = serde_json::from_str(ps::SIGN_REQUEST).expect("request json");
    value["body"] = json!("aGVsbG8");
    assert!(serde_json::from_value::<ps::SignRequest>(value).is_err());
    let mut value: Value = serde_json::from_str(ps::SIGN_REQUEST).expect("request json");
    value.as_object_mut().expect("object").remove("scope");
    assert!(serde_json::from_value::<ps::SignRequest>(value).is_err());
    let mut value: Value = serde_json::from_str(ps::SIGN_ANSWER).expect("answer json");
    value["result"]["string_to_sign"] = json!("x");
    assert!(serde_json::from_value::<ps::Envelope<ps::SignAnswer>>(value).is_err());
    let body = ps::SIGN_REQUEST.to_owned();
    assert!(body.len() <= 64 * 1024, "section 7.2: at most 64 KiB");
}

#[cfg(feature = "vault")]
#[test]
fn private_sharing_v1_sign_answer_is_the_aws_get_vanilla_signature() {
    use private_sharing as ps;

    let request = ps::sign_request();
    let canonical = ps::parse_canonical(&request.canonical_request).expect("canonical");
    let amz_date = canonical.header("x-amz-date").expect("x-amz-date");
    // The AWS SigV4 test suite: get-vanilla, its published secret and signature.
    let sources = ps::sources();
    let secret = &sources["aws_sts"].fields[1].value;
    assert_eq!(secret, "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY");
    let hashed = ps::hex(
        ring::digest::digest(&ring::digest::SHA256, request.canonical_request.as_bytes()).as_ref(),
    );
    assert_eq!(
        hashed,
        "bb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63"
    );
    let signature =
        ps::sigv4_signature(secret, &request.scope, amz_date, &request.canonical_request);
    assert_eq!(
        signature,
        "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
    );
    let answer: ps::Envelope<ps::SignAnswer> = ps::strict("sign-answer.json", ps::SIGN_ANSWER);
    assert_eq!(answer.result.expect("result").signature, signature);
}

#[test]
fn private_sharing_v1_no_fixture_holds_a_secret() {
    use private_sharing as ps;

    let long_lived = ps::long_lived_canaries();
    let leases = ps::lease_canaries();
    // 2 AWS + 1 PEM with its body + key_json with its 2 parts and the PEM body + 2 OAuth
    // + the rotated refresh token.
    assert!(long_lived.len() >= 10, "{}", long_lived.len());
    assert_eq!(leases.len(), 6);
    let answer: ps::Envelope<ps::SignAnswer> = ps::strict("sign-answer.json", ps::SIGN_ANSWER);
    let signature = [answer.result.expect("result").signature];

    // Nothing that is not a delivery channel holds a long-lived value, a lease value, or
    // the signature.
    let mut never: Vec<(&str, &str)> = vec![
        ("kinds.json", ps::KINDS),
        ("access-view.json", ps::ACCESS_VIEW),
        ("sign-request.json", ps::SIGN_REQUEST),
        ("run-lease-failed.json", ps::RUN_LEASE_FAILED),
        ("audit-rows.json", ps::AUDIT_ROWS),
    ];
    never.extend(ps::SETTINGS);
    never.extend(ps::ERRORS.iter().map(|(name, text, _)| (*name, *text)));
    for (name, text) in never {
        ps::assert_no_canary(name, text, &long_lived);
        ps::assert_no_canary(name, text, &leases);
        ps::assert_no_canary(name, text, &signature);
    }

    // A lease holds no long-lived value (the rotated refresh token is only in its
    // `update_field`, for the vault).
    let sources = ps::sources();
    for (kind, text) in ps::LEASES {
        let source_secrets: Vec<String> = sources
            .values()
            .flat_map(|source| source.fields.iter().filter(|f| f.secret))
            .map(|field| field.value.clone())
            .collect();
        ps::assert_no_canary(kind, text, &source_secrets);
        let lease = ps::lease(kind);
        for secret in &lease.secrets {
            ps::assert_no_canary(kind, &secret.value, &long_lived);
        }
    }

    // The session view holds lease values only in the variables of its leases.
    let view = ps::session_view();
    ps::assert_no_canary("session-view.json", ps::SESSION_VIEW, &long_lived);
    ps::assert_no_canary("session-view.json", ps::SESSION_VIEW, &signature);
    let lease_names: Vec<&String> = view
        .short_lived
        .iter()
        .flat_map(|lease| &lease.env_names)
        .collect();
    for (name, value) in &view.env {
        if !lease_names.contains(&name) {
            ps::assert_no_canary(name, value, &leases);
        }
    }
    for (host, url) in &view.base_urls {
        ps::assert_no_canary(host, url, &leases);
    }

    // The sign answer has the signature only.
    ps::assert_no_canary("sign-answer.json", ps::SIGN_ANSWER, &long_lived);
    ps::assert_no_canary("sign-answer.json", ps::SIGN_ANSWER, &leases);

    // No audit detail has a key that could hold a value.
    let rows: Vec<ps::AuditEntry> = ps::strict("audit-rows.json", ps::AUDIT_ROWS);
    for row in &rows {
        for key in row.detail.keys() {
            for word in [
                "value",
                "token",
                "secret",
                "signature",
                "hash",
                "header",
                "query",
                "body",
                "placeholder",
            ] {
                assert!(!key.contains(word), "{}: {key}", row.action);
            }
        }
    }
}

#[test]
fn private_sharing_v1_contract_states_the_rules() {
    let contract = private_sharing::CONTRACT;
    for needle in [
        // S6-1 and D11.
        "The long-lived secret never leaves the key holder",
        "**Automatic (D11).**",
        "OwnerAction::ChangeDelivery { item, kind, on }",
        // The no-fallback rule.
        "**No fallback.**",
        "MUST NOT deliver the long-lived value, a placeholder of it, or an older lease instead",
        // The presign refusal (S6-8).
        "**Presigned URLs and streaming payloads are refused (S6-8).**",
        "`X-Amz-Signature`",
        // The no-secret rule.
        "**No-secret rule.**",
        "holds a long-lived value, a lease value, a placeholder, a signature, a payload hash, or a header",
        // The endpoint and its limits.
        "`POST /v1/sign`",
        "`Need::Member`",
        "`Scope::Public` does not serve it",
        "at most 64 KiB",
        "More than 120 signatures in the last minute for this session",
        // The lifetimes.
        "`DurationSeconds=900`",
        "`lifetime: \"900s\"`",
        "`GetSessionToken` MUST NOT be used",
        "lease.expires_at − 30)",
        // The frozen view types.
        "pub short_lived: Vec<LeaseView>",
        "pub signers: Vec<SignerView>",
        "`temporary_credentials`",
        "`signed_requests`",
        "`AccessItem.credential_form`",
        "`credential_form TEXT NOT NULL",
    ] {
        assert!(contract.contains(needle), "the contract lacks: {needle}");
    }
    for fixture in [
        "kinds.json",
        "sources.json",
        "session-view.json",
        "access-view.json",
        "sign-request.json",
        "sign-answer.json",
        "run-lease-failed.json",
        "audit-rows.json",
    ] {
        assert!(contract.contains(&format!("`{fixture}`")), "{fixture}");
    }
    assert!(
        private_sharing::CLOUD_AGENTS.contains("private-sharing-v1.md"),
        "cloud-agents-v1 section 8 points to private-sharing-v1"
    );
}

// ---------------------------------------------------------------------------
// Apassy Connect (ADR 0037 stage 7, unit D1 of docs/design/implementation-plan-s7-connect.md):
// docs/contracts/connect-account-v1.md, connect-billing-v1.md, connect-tunnel-v1.md and
// their fixtures. The types in `connect_v1` are local to this test, not product code: they
// read the fixtures as a strict party of each contract would. The checks that need `ring`
// (signatures, hashes, HMAC) run with the `vault` feature, as CI runs (`--all-features`).
// ---------------------------------------------------------------------------

#[test]
fn connect_account_v1_fixtures_match_the_contract() {
    connect_v1::account::check_examples();
    #[cfg(feature = "vault")]
    connect_v1::account::check_vectors();
}

#[test]
fn connect_billing_v1_webhook_fixtures_verify_with_the_endpoint_secret() {
    connect_v1::billing::check_webhook_bodies();
    #[cfg(feature = "vault")]
    connect_v1::billing::check_webhook_signatures();
}

#[test]
fn connect_billing_v1_prices_plan_states_and_examples_match_the_contract() {
    connect_v1::billing::check_prices();
    connect_v1::billing::check_plan_states();
    connect_v1::billing::check_examples();
}

#[test]
fn connect_tunnel_v1_frames_round_trip() {
    connect_v1::tunnel::check_frames();
    connect_v1::tunnel::check_sequences();
    connect_v1::tunnel::check_examples();
}

#[test]
fn connect_v1_contracts_define_every_error_code() {
    connect_v1::check_error_table();
}

#[allow(dead_code)]
mod connect_v1 {
    use serde::Deserialize;
    use serde::de::DeserializeOwned;
    use serde_json::Value;

    pub const ACCOUNT_CONTRACT: &str = include_str!("../docs/contracts/connect-account-v1.md");
    pub const BILLING_CONTRACT: &str = include_str!("../docs/contracts/connect-billing-v1.md");
    pub const TUNNEL_CONTRACT: &str = include_str!("../docs/contracts/connect-tunnel-v1.md");
    const RELAY_SYNC_CONTRACT: &str = include_str!("../docs/contracts/relay-sync-v1.md");
    const PLANS: &str = include_str!("../docs/product/plans.md");

    /// connect-account-v1 section 4: every Connect code with its status, and the
    /// relay-sync-v1 codes that the Connect examples use.
    const CODES: [(&str, u16); 14] = [
        ("account_required", 403),
        ("not_in_group", 403),
        ("plan_required", 403),
        ("account_limit", 403),
        ("seat_limit", 409),
        ("tunnel_limit", 429),
        ("node_unknown", 404),
        ("tunnel_offline", 503),
        ("free_connect_ended", 410),
        ("hosted_retired", 410),
        ("invalid_request", 400),
        ("forbidden", 403),
        ("join_pending", 403),
        ("not_found", 404),
    ];

    /// The codes that unit D1 of the stage 7 plan names.
    const PLAN_CODES: [&str; 9] = [
        "account_required",
        "not_in_group",
        "seat_limit",
        "plan_required",
        "tunnel_limit",
        "tunnel_offline",
        "node_unknown",
        "free_connect_ended",
        "hosted_retired",
    ];

    pub fn check_error_table() {
        for (code, status) in CODES.iter().take(10) {
            let row = format!("| {status} | `{code}` |");
            assert!(
                ACCOUNT_CONTRACT.contains(&row),
                "connect-account-v1 section 4 lacks {row}"
            );
        }
        for code in PLAN_CODES {
            assert!(CODES.iter().any(|(known, _)| *known == code), "{code}");
        }
        for (code, contract) in [
            ("seat_limit", BILLING_CONTRACT),
            ("not_in_group", BILLING_CONTRACT),
            ("plan_required", BILLING_CONTRACT),
            ("tunnel_limit", TUNNEL_CONTRACT),
            ("tunnel_offline", TUNNEL_CONTRACT),
            ("node_unknown", TUNNEL_CONTRACT),
            ("not_in_group", TUNNEL_CONTRACT),
            ("plan_required", TUNNEL_CONTRACT),
            ("account_limit", TUNNEL_CONTRACT),
        ] {
            assert!(names_code(contract, code), "{code}");
        }
    }

    /// The contract names the code as `` `code` `` or with its status, `` `403 code` ``.
    pub fn names_code(contract: &str, code: &str) -> bool {
        let status = CODES
            .iter()
            .find(|(known, _)| *known == code)
            .map(|(_, status)| *status);
        contract.contains(&format!("`{code}`"))
            || status.is_some_and(|status| contract.contains(&format!("`{status} {code}`")))
    }

    // --- Shared fixture shapes and encodings ------------------------------------

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ExampleFile {
        pub contract: String,
        pub examples: Vec<Example>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Example {
        pub name: String,
        pub route: String,
        pub part: String,
        pub status: Option<u16>,
        pub body: Value,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ErrorBody {
        pub code: String,
        pub message: String,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct PlanView {
        pub plan: Option<String>,
        pub status: String,
        pub entitled: bool,
        pub interval: Option<String>,
        pub quantity: Option<u32>,
        pub renews_at: Option<u64>,
        pub ends_at: Option<u64>,
        pub grace_until: Option<u64>,
        pub read_only_until: Option<u64>,
        pub delete_at: Option<u64>,
        pub group_id: Option<String>,
    }

    pub fn strict<T: DeserializeOwned>(example: &Example) -> T {
        serde_json::from_value(example.body.clone())
            .unwrap_or_else(|err| panic!("{}: {err}", example.name))
    }

    /// Reads an example file, checks the common rules, and hands each example to
    /// `check`, which must know its name (a new example needs a type).
    pub fn examples(name: &str, text: &str, contract: &str, check: impl Fn(&Example) -> bool) {
        let file: ExampleFile = serde_json::from_str(text).expect("example file");
        assert_eq!(file.contract, name);
        let mut names = std::collections::BTreeSet::new();
        for example in &file.examples {
            assert!(names.insert(example.name.clone()), "{} twice", example.name);
            assert!(
                contract.contains(&format!("`{}`", example.route)),
                "{}: {name} does not name the route `{}`",
                example.name,
                example.route
            );
            match example.part.as_str() {
                "request" | "result" | "stripe_request" => {
                    assert!(example.status.is_none(), "{}", example.name);
                }
                "error" => {
                    let body: ErrorBody = strict(example);
                    let status = CODES
                        .iter()
                        .find(|(code, _)| *code == body.code)
                        .map(|(_, status)| *status)
                        .unwrap_or_else(|| panic!("{}: unknown code {}", example.name, body.code));
                    assert_eq!(example.status, Some(status), "{}", example.name);
                    assert!(
                        names_code(contract, &body.code),
                        "{}: {name} does not define {}",
                        example.name,
                        body.code
                    );
                    assert!(is_text(&body.message) && body.message.len() <= 200);
                    assert!(!body.message.contains("apassy_"), "{}", example.name);
                    continue;
                }
                other => panic!("{}: part {other}", example.name),
            }
            assert!(check(example), "{}: no type for this example", example.name);
        }
    }

    const B64U: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    pub fn b64u_encode(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
        for chunk in bytes.chunks(3) {
            let b1 = chunk.get(1).copied().unwrap_or(0);
            let b2 = chunk.get(2).copied().unwrap_or(0);
            let n = (u32::from(chunk[0]) << 16) | (u32::from(b1) << 8) | u32::from(b2);
            for i in 0..=chunk.len() {
                out.push(char::from(B64U[((n >> (18 - 6 * i)) & 63) as usize]));
            }
        }
        out
    }

    /// Canonical base64url without padding, or `None`.
    pub fn b64u_decode(text: &str) -> Option<Vec<u8>> {
        let mut bits = 0u32;
        let mut count = 0u32;
        let mut out = Vec::with_capacity(text.len() * 3 / 4);
        for c in text.bytes() {
            let value = B64U.iter().position(|&x| x == c)? as u32;
            bits = (bits << 6) | value;
            count += 6;
            if count >= 8 {
                count -= 8;
                out.push((bits >> count) as u8);
                bits &= (1 << count) - 1;
            }
        }
        (b64u_encode(&out) == text).then_some(out)
    }

    pub fn is_hex(text: &str, len: usize) -> bool {
        text.len() == len
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }

    pub fn hex_decode(text: &str) -> Vec<u8> {
        assert!(
            text.len().is_multiple_of(2) && is_hex(text, text.len()),
            "hex: {text}"
        );
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
            .collect()
    }

    pub fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// `<prefix>` and 10 characters of `a-z2-7`.
    pub fn is_id(text: &str, prefix: &str) -> bool {
        text.strip_prefix(prefix).is_some_and(|rest| {
            rest.len() == 10
                && rest
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
        })
    }

    pub fn is_public_key(text: &str) -> bool {
        b64u_decode(text).is_some_and(|key| key.len() == 65 && key[0] == 4)
    }

    pub fn is_signature(text: &str) -> bool {
        b64u_decode(text).is_some_and(|sig| (8..=72).contains(&sig.len()) && sig[0] == 0x30)
    }

    /// A name of connect-account-v1 section 2.
    pub fn is_name(text: &str) -> bool {
        !text.is_empty() && text.len() <= 64 && text.trim() == text && is_text(text)
    }

    pub fn is_text(text: &str) -> bool {
        !text.chars().any(char::is_control)
    }

    pub fn is_uuid(text: &str) -> bool {
        text.len() == 36
            && text.char_indices().all(|(i, c)| {
                if [8, 13, 18, 23].contains(&i) {
                    c == '-'
                } else {
                    c.is_ascii_digit() || ('a'..='f').contains(&c)
                }
            })
    }

    pub fn is_https(text: &str) -> bool {
        text.strip_prefix("https://")
            .is_some_and(|rest| !rest.is_empty() && is_text(rest) && !rest.contains(' '))
    }

    /// The 256 words of relay-sync-v1 section 16.
    pub fn words() -> Vec<&'static str> {
        let section = RELAY_SYNC_CONTRACT
            .split("## 16. The word list")
            .nth(1)
            .expect("relay-sync-v1 section 16");
        let block = section.split("```").nth(1).expect("the word block");
        let words: Vec<&'static str> = block.split_whitespace().collect();
        assert_eq!(words.len(), 256);
        words
    }

    /// Parts joined with one zero byte, no trailing zero (connect-account-v1 section 5).
    pub fn joined(parts: &[&[u8]]) -> Vec<u8> {
        let mut message = Vec::new();
        for (i, part) in parts.iter().enumerate() {
            if i > 0 {
                message.push(0);
            }
            message.extend_from_slice(part);
        }
        message
    }

    pub fn plan_view_is_valid(view: &PlanView) -> bool {
        let entitled = matches!(view.status.as_str(), "active" | "trialing" | "past_due");
        let known = matches!(
            view.status.as_str(),
            "none" | "pending" | "active" | "trialing" | "past_due" | "read_only" | "suspended"
        );
        known
            && view.entitled == entitled
            && view
                .plan
                .as_deref()
                .is_none_or(|plan| ["personal", "family", "team"].contains(&plan))
            && view
                .interval
                .as_deref()
                .is_none_or(|interval| ["month", "year"].contains(&interval))
            && view.group_id.as_deref().is_none_or(|id| is_id(id, "grp_"))
            && (view.status != "none" || view.plan.is_none())
            && (view.renews_at.is_none() || view.ends_at.is_none())
    }

    // --- connect-account-v1 -----------------------------------------------------

    pub mod account {
        use super::*;

        const EXAMPLES: &str = include_str!("fixtures/connect-account-v1/examples.json");
        const VECTORS: &str = include_str!("fixtures/connect-account-v1/vectors.json");

        /// The device key of relay-sync-v1 section 15 is device A.
        const RELAY_SYNC_PUBLIC_KEY: &str = "BOpHkB5VvTHXawpUXZxgu44Q97I2bzq9G_uI6tFM9mj8De047e1fNWI8MIERDsaxhBC0ih1DPfXaM4mdBbExjrA";

        /// Section 5: the only messages that an account device key signs.
        pub const DEVICE_KEY_TAGS: [&str; 7] = [
            "apassy-connect account v1",
            "apassy-connect sign-in v1",
            "apassy-connect join v1",
            "apassy-connect recover v1",
            "apassy-bouncer sign-in v1",
            "apassy-relay sign-in v1",
            "apassy-relay-sync-head-v1",
        ];

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct AccountCreate {
            name: String,
            device_name: String,
            platform: String,
            public_key: String,
            recovery_hash: String,
            signature: String,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct AccountCreated {
            account_id: String,
            device_id: String,
            created_at: u64,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Challenge {
            account_id: String,
            public_key: String,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct ChallengeAnswer {
            nonce: String,
            expires_at: u64,
            origin: String,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct TokenRequest {
            account_id: String,
            public_key: String,
            nonce: String,
            signature: String,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct TokenAnswer {
            token: String,
            expires_at: u64,
            account_id: String,
            device_id: String,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct DeviceView {
            device_id: String,
            name: String,
            platform: String,
            public_key: String,
            created_at: u64,
            last_seen_at: Option<u64>,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct GroupRef {
            group_id: String,
            kind: String,
            role: String,
            state: String,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct AccountView {
            account_id: String,
            name: String,
            email: Option<String>,
            created_at: u64,
            plan: PlanView,
            devices: Vec<DeviceView>,
            group: Option<GroupRef>,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Empty {}

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct AccountDeleted {
            account_id: String,
            deleted_stores: u32,
            subscription_canceled: bool,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct LinkCreate {
            link_hash: String,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct LinkAnswer {
            link_id: u64,
            expires_at: u64,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Join {
            account_id: String,
            link_hash: String,
            device_name: String,
            platform: String,
            public_key: String,
            signature: String,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Confirmer {
            device_id: String,
            name: String,
            public_key: String,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct JoinAnswer {
            join_id: u64,
            account_id: String,
            confirmer: Confirmer,
            expires_at: u64,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct JoinCancel {
            account_id: String,
            link_hash: String,
            public_key: String,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct JoinId {
            join_id: u64,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct PendingJoin {
            join_id: u64,
            link_id: u64,
            device_name: String,
            platform: String,
            public_key: String,
            created_at: u64,
            expires_at: u64,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Confirm {
            public_key: String,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Revoked {
            device_id: String,
            removed_from_stores: u32,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct VaultCreate {
            vault_id: String,
            name: String,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct StoreDevice {
            store_device_id: u64,
            device_id: String,
            account_id: String,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct VaultStoreView {
            team_id: String,
            vault_id: String,
            name: String,
            created_at: u64,
            shared: bool,
            devices: Vec<StoreDevice>,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct StoreDeviceAdd {
            device_id: String,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct TeamId {
            team_id: String,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Recover {
            account_id: String,
            recovery: String,
            device_name: String,
            platform: String,
            public_key: String,
            recovery_hash: String,
            signature: String,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RecoverAnswer {
            account_id: String,
            device_id: String,
            deleted_stores: u32,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct EntitlementAnswer {
            token: String,
            expires_at: u64,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WellKnownKey {
            kid: String,
            alg: String,
            public_key: String,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WellKnown {
            v: u8,
            origin: String,
            keys: Vec<WellKnownKey>,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct BrainDevice {
            key_id: String,
            public_key_sha256: String,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct BrainDeviceAnswer {
            account: String,
            entitled_hosting: bool,
            entitled_training: bool,
            revoked: bool,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct BrainRevoke {
            key_id: String,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct BrainForget {
            account: String,
        }

        /// Entitlement claims (section 10), in the order of the compact payload.
        #[derive(Debug, Deserialize, serde::Serialize, PartialEq, Clone)]
        #[serde(deny_unknown_fields)]
        pub struct Claims {
            pub v: u8,
            pub kid: String,
            pub acc: String,
            pub plan: String,
            pub group: Option<String>,
            pub feats: Vec<String>,
            pub iat: u64,
            pub exp: u64,
        }

        fn is_platform(text: &str) -> bool {
            ["mac", "iphone", "linux"].contains(&text)
        }

        fn is_link_hash(text: &str) -> bool {
            b64u_decode(text).is_some_and(|hash| hash.len() == 32)
        }

        fn is_account_token(text: &str, account: &str) -> bool {
            text.strip_prefix("apassy_act_")
                .and_then(|rest| rest.strip_prefix(account))
                .and_then(|rest| rest.strip_prefix('_'))
                .is_some_and(|secret| is_hex(secret, 64))
        }

        fn device_view(view: &DeviceView) -> bool {
            is_id(&view.device_id, "dev_")
                && is_name(&view.name)
                && is_platform(&view.platform)
                && is_public_key(&view.public_key)
                && view
                    .last_seen_at
                    .is_none_or(|t| t.is_multiple_of(3600) && t >= view.created_at)
        }

        fn store_view(view: &VaultStoreView) -> bool {
            is_id(&view.team_id, "t_")
                && is_uuid(&view.vault_id)
                && is_name(&view.name)
                && !view.devices.is_empty()
                && view.devices.iter().all(|d| {
                    d.store_device_id > 0
                        && is_id(&d.device_id, "dev_")
                        && is_id(&d.account_id, "acc_")
                })
                && (view.shared
                    || view
                        .devices
                        .iter()
                        .all(|d| d.account_id == view.devices[0].account_id))
        }

        fn check_one(example: &Example) -> bool {
            match example.name.as_str() {
                "account_create" => {
                    let body: AccountCreate = strict(example);
                    assert!(is_name(&body.name) && is_name(&body.device_name));
                    assert!(is_platform(&body.platform) && is_public_key(&body.public_key));
                    assert!(is_hex(&body.recovery_hash, 64) && is_signature(&body.signature));
                }
                "account_created" => {
                    let body: AccountCreated = strict(example);
                    assert!(is_id(&body.account_id, "acc_") && is_id(&body.device_id, "dev_"));
                }
                "challenge" => {
                    let body: Challenge = strict(example);
                    assert!(is_id(&body.account_id, "acc_") && is_public_key(&body.public_key));
                }
                "challenge_answer" => {
                    let body: ChallengeAnswer = strict(example);
                    assert_eq!(b64u_decode(&body.nonce).map(|n| n.len()), Some(32));
                    assert!(is_https(&body.origin) && !body.origin.ends_with('/'));
                }
                "token" => {
                    let body: TokenRequest = strict(example);
                    assert!(is_public_key(&body.public_key) && is_signature(&body.signature));
                    assert!(is_id(&body.account_id, "acc_"));
                }
                "token_answer" => {
                    let body: TokenAnswer = strict(example);
                    assert!(is_account_token(&body.token, &body.account_id));
                    assert!(is_id(&body.device_id, "dev_"));
                }
                "account_view" | "account_view_family_member" => {
                    let body: AccountView = strict(example);
                    assert!(is_id(&body.account_id, "acc_") && is_name(&body.name));
                    assert!(plan_view_is_valid(&body.plan));
                    assert!(body.devices.iter().all(device_view));
                    if let Some(group) = &body.group {
                        assert!(is_id(&group.group_id, "grp_"));
                        assert!(["family", "team"].contains(&group.kind.as_str()));
                        assert!(["owner", "admin", "member"].contains(&group.role.as_str()));
                        assert!(["pending", "active"].contains(&group.state.as_str()));
                        assert_eq!(body.plan.group_id.as_ref(), Some(&group.group_id));
                    }
                }
                "account_delete" | "refuse" => {
                    let _: Empty = strict(example);
                }
                "account_deleted" => {
                    let body: AccountDeleted = strict(example);
                    assert!(is_id(&body.account_id, "acc_"));
                }
                "link" => {
                    let body: LinkCreate = strict(example);
                    assert!(is_link_hash(&body.link_hash));
                }
                "link_answer" => {
                    let body: LinkAnswer = strict(example);
                    assert!(body.link_id > 0 && body.expires_at > 0);
                }
                "join" => {
                    let body: Join = strict(example);
                    assert!(is_link_hash(&body.link_hash) && is_name(&body.device_name));
                    assert!(is_platform(&body.platform) && is_public_key(&body.public_key));
                    assert!(is_signature(&body.signature));
                }
                "join_answer" => {
                    let body: JoinAnswer = strict(example);
                    assert!(is_id(&body.confirmer.device_id, "dev_"));
                    assert!(is_public_key(&body.confirmer.public_key));
                }
                "join_cancel" => {
                    let body: JoinCancel = strict(example);
                    assert!(is_link_hash(&body.link_hash) && is_public_key(&body.public_key));
                }
                "join_cancel_answer" | "refuse_answer" => {
                    let body: JoinId = strict(example);
                    assert!(body.join_id > 0);
                }
                "pending" => {
                    let body: Vec<PendingJoin> = strict(example);
                    assert!(body.iter().all(|p| {
                        is_public_key(&p.public_key)
                            && is_platform(&p.platform)
                            && is_name(&p.device_name)
                            && p.created_at < p.expires_at
                    }));
                }
                "confirm" => {
                    let body: Confirm = strict(example);
                    assert!(is_public_key(&body.public_key));
                }
                "confirm_answer" => {
                    let body: DeviceView = strict(example);
                    assert!(device_view(&body));
                }
                "revoke_answer" => {
                    let body: Revoked = strict(example);
                    assert!(is_id(&body.device_id, "dev_"));
                }
                "vault_create" => {
                    let body: VaultCreate = strict(example);
                    assert!(is_uuid(&body.vault_id) && is_name(&body.name));
                }
                "vault_created" => {
                    let body: VaultStoreView = strict(example);
                    assert!(store_view(&body) && body.devices[0].store_device_id == 1);
                }
                "vaults" => {
                    let body: Vec<VaultStoreView> = strict(example);
                    assert!(body.iter().all(store_view));
                }
                "store_device" => {
                    let body: StoreDeviceAdd = strict(example);
                    assert!(is_id(&body.device_id, "dev_"));
                }
                "store_device_answer" => {
                    let body: StoreDevice = strict(example);
                    assert!(body.store_device_id > 0 && is_id(&body.account_id, "acc_"));
                }
                "vault_deleted" => {
                    let body: TeamId = strict(example);
                    assert!(is_id(&body.team_id, "t_"));
                }
                "recover" => {
                    let body: Recover = strict(example);
                    let code = body.recovery.strip_prefix("apassy_rec_");
                    assert!(code.is_some_and(|code| is_hex(code, 32)));
                    assert!(is_hex(&body.recovery_hash, 64) && is_signature(&body.signature));
                    assert!(is_public_key(&body.public_key) && is_platform(&body.platform));
                }
                "recover_answer" => {
                    let body: RecoverAnswer = strict(example);
                    assert!(is_id(&body.device_id, "dev_"));
                }
                "entitlement" => {
                    let body: EntitlementAnswer = strict(example);
                    let (payload, signature) = body.token.split_once('.').expect("two parts");
                    assert!(b64u_decode(payload).is_some() && !signature.contains('.'));
                    assert_eq!(b64u_decode(signature).map(|s| s.len()), Some(64));
                }
                "well_known" => {
                    let body: WellKnown = strict(example);
                    assert_eq!(body.v, 1);
                    assert!(is_https(&body.origin));
                    assert!(body.keys.iter().all(|key| key.alg == "Ed25519"
                        && b64u_decode(&key.public_key).is_some_and(|k| k.len() == 32)));
                }
                "brain_device" => {
                    let body: BrainDevice = strict(example);
                    assert!(is_id(&body.key_id, "dev_") && is_hex(&body.public_key_sha256, 64));
                }
                "brain_device_answer" | "brain_device_revoked" => {
                    let body: BrainDeviceAnswer = strict(example);
                    assert!(is_id(&body.account, "acc_"));
                    if body.revoked {
                        assert!(!body.entitled_hosting && !body.entitled_training);
                    }
                }
                "brain_revoke" => {
                    let body: BrainRevoke = strict(example);
                    assert!(is_id(&body.key_id, "dev_"));
                }
                "brain_forget" => {
                    let body: BrainForget = strict(example);
                    assert!(is_id(&body.account, "acc_"));
                }
                _ => return false,
            }
            true
        }

        pub fn check_examples() {
            examples("connect-account-v1", EXAMPLES, ACCOUNT_CONTRACT, check_one);
            for tag in DEVICE_KEY_TAGS {
                assert!(ACCOUNT_CONTRACT.contains(&format!("`{tag}`")), "{tag}");
            }
            for tag in [
                "apassy-connect entitlement v1",
                "apassy-connect link v1",
                "apassy-connect safety v1",
                "apassy-connect recovery v1",
            ] {
                assert!(ACCOUNT_CONTRACT.contains(&format!("`{tag}`")), "{tag}");
            }
        }

        // The vectors of section 15.

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Vectors {
            origin: String,
            brain_origin: String,
            account_id: String,
            device_a: VectorDevice,
            device_b: VectorDevice,
            nonce_b64u: String,
            messages: Vec<VectorMessage>,
            link: VectorLink,
            safety: VectorSafety,
            recovery: VectorRecovery,
            entitlement: VectorEntitlement,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct VectorDevice {
            device_id: String,
            private_hex: String,
            public_hex: String,
            public_b64u: String,
            public_key_sha256: String,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct VectorMessage {
            name: String,
            tag: String,
            signer: String,
            message_b64u: String,
            sha256: String,
            signature_b64u: String,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct VectorLink {
            code: String,
            link_hash: String,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct VectorSafety {
            sha256: String,
            words: String,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct VectorRecovery {
            bytes_hex: String,
            code: String,
            words: String,
            recovery_hash: String,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct VectorEntitlement {
            kid: String,
            seed_hex: String,
            public_b64u: String,
            tokens: Vec<VectorToken>,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct VectorToken {
            name: String,
            claims: Claims,
            payload_b64u: String,
            signature_b64u: String,
            token: String,
        }

        #[cfg(feature = "vault")]
        fn sha256(bytes: &[u8]) -> Vec<u8> {
            ring::digest::digest(&ring::digest::SHA256, bytes)
                .as_ref()
                .to_vec()
        }

        #[cfg(feature = "vault")]
        fn ecdsa_verifies(public: &[u8], message: &[u8], signature: &[u8]) -> bool {
            ring::signature::UnparsedPublicKey::new(
                &ring::signature::ECDSA_P256_SHA256_ASN1,
                public,
            )
            .verify(message, signature)
            .is_ok()
        }

        /// The service-side check of section 10, as the brain's `entitlements.py` does it.
        #[cfg(feature = "vault")]
        pub fn accept_entitlement(
            token: &str,
            keys: &[(&str, &[u8])],
            now: u64,
            feature: &str,
            account: &str,
        ) -> Result<Claims, &'static str> {
            let mut parts = token.split('.');
            let (Some(payload), Some(signature), None) = (parts.next(), parts.next(), parts.next())
            else {
                return Err("parts");
            };
            let json = b64u_decode(payload).ok_or("payload")?;
            let signature = b64u_decode(signature).ok_or("signature")?;
            let claims: Claims = serde_json::from_slice(&json).map_err(|_| "claims")?;
            let (_, public) = keys
                .iter()
                .find(|(kid, _)| *kid == claims.kid)
                .ok_or("kid")?;
            let signed = joined(&[b"apassy-connect entitlement v1", payload.as_bytes()]);
            ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public)
                .verify(&signed, &signature)
                .map_err(|_| "signature")?;
            if claims.v != 1 {
                return Err("version");
            }
            if now >= claims.exp {
                return Err("expired");
            }
            if claims.iat > now + 300 || claims.exp.saturating_sub(claims.iat) > 86_400 {
                return Err("times");
            }
            if !claims.feats.iter().any(|f| f == feature) {
                return Err("feature");
            }
            if claims.acc != account {
                return Err("account");
            }
            Ok(claims)
        }

        #[cfg(feature = "vault")]
        fn refuse(
            token: &str,
            keys: &[(&str, &[u8])],
            now: u64,
            feature: &str,
            account: &str,
        ) -> Option<&'static str> {
            accept_entitlement(token, keys, now, feature, account).err()
        }

        fn example_body<'a>(file: &'a ExampleFile, name: &str) -> &'a Value {
            &file
                .examples
                .iter()
                .find(|e| e.name == name)
                .unwrap_or_else(|| panic!("example {name}"))
                .body
        }

        #[cfg(feature = "vault")]
        fn message_signature<'a>(v: &'a Vectors, name: &str) -> &'a str {
            &v.messages
                .iter()
                .find(|m| m.name == name)
                .unwrap_or_else(|| panic!("message {name}"))
                .signature_b64u
        }

        #[cfg(feature = "vault")]
        pub fn check_vectors() {
            use ring::signature::{
                ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair,
            };

            let v: Vectors = serde_json::from_str(VECTORS).expect("vectors");
            let words = words();
            let rng = ring::rand::SystemRandom::new();
            assert_eq!(v.device_a.public_b64u, RELAY_SYNC_PUBLIC_KEY);
            assert!(is_id(&v.account_id, "acc_"));
            for device in [&v.device_a, &v.device_b] {
                let public = hex_decode(&device.public_hex);
                assert!(is_id(&device.device_id, "dev_"));
                assert_eq!(b64u_encode(&public), device.public_b64u);
                assert_eq!(hex_encode(&sha256(&public)), device.public_key_sha256);
                EcdsaKeyPair::from_private_key_and_public_key(
                    &ECDSA_P256_SHA256_ASN1_SIGNING,
                    &hex_decode(&device.private_hex),
                    &public,
                    &rng,
                )
                .expect("the private key matches the public key");
            }
            let a = hex_decode(&v.device_a.public_hex);
            let b = hex_decode(&v.device_b.public_hex);
            let (a64, b64) = (
                v.device_a.public_b64u.as_bytes(),
                v.device_b.public_b64u.as_bytes(),
            );
            let (origin, account) = (v.origin.as_bytes(), v.account_id.as_bytes());
            let nonce = v.nonce_b64u.as_bytes();
            assert_eq!(
                b64u_decode(&v.nonce_b64u),
                Some((0u8..32).collect::<Vec<u8>>())
            );

            // The link hash (section 2).
            let code = &v.link.code;
            let prefix = format!("apassy_alk_{}_", v.account_id);
            assert!(
                code.strip_prefix(&prefix)
                    .is_some_and(|rest| is_hex(rest, 64))
            );
            let link_hash = b64u_encode(&sha256(&joined(&[
                b"apassy-connect link v1",
                code.as_bytes(),
            ])));
            assert_eq!(link_hash, v.link.link_hash);

            // The messages of section 5.
            let mut names = Vec::new();
            for m in &v.messages {
                let expected = match m.name.as_str() {
                    "account" => joined(&[m.tag.as_bytes(), origin, a64]),
                    "sign_in" => joined(&[m.tag.as_bytes(), origin, account, a64, nonce]),
                    "join" => {
                        joined(&[m.tag.as_bytes(), origin, account, link_hash.as_bytes(), b64])
                    }
                    "recover" => joined(&[m.tag.as_bytes(), origin, account, b64]),
                    "brain_sign_in" => joined(&[
                        m.tag.as_bytes(),
                        v.brain_origin.as_bytes(),
                        account,
                        a64,
                        nonce,
                    ]),
                    other => panic!("unknown message {other}"),
                };
                names.push(m.name.as_str());
                assert!(DEVICE_KEY_TAGS.contains(&m.tag.as_str()), "{}", m.tag);
                let message = b64u_decode(&m.message_b64u).expect("message");
                assert_eq!(message, expected, "{}", m.name);
                assert!(message.starts_with(format!("{}\0", m.tag).as_bytes()));
                assert_ne!(message.last(), Some(&0));
                assert_eq!(hex_encode(&sha256(&message)), m.sha256, "{}", m.name);
                let public = match m.signer.as_str() {
                    "device_a" => &a,
                    "device_b" => &b,
                    other => panic!("unknown signer {other}"),
                };
                let other = if m.signer == "device_a" { &b } else { &a };
                assert!(is_signature(&m.signature_b64u), "{}", m.name);
                let signature = b64u_decode(&m.signature_b64u).expect("signature");
                assert!(ecdsa_verifies(public, &message, &signature), "{}", m.name);
                assert!(!ecdsa_verifies(other, &message, &signature), "{}", m.name);
                let mut changed = message.clone();
                *changed.last_mut().expect("bytes") ^= 1;
                assert!(!ecdsa_verifies(public, &changed, &signature), "{}", m.name);
            }
            assert_eq!(
                names,
                ["account", "sign_in", "join", "recover", "brain_sign_in"]
            );

            // A fresh signature with the vector key verifies too (ECDSA is randomized).
            let pair = EcdsaKeyPair::from_private_key_and_public_key(
                &ECDSA_P256_SHA256_ASN1_SIGNING,
                &hex_decode(&v.device_a.private_hex),
                &a,
                &rng,
            )
            .expect("key pair");
            let sign_in = joined(&[b"apassy-connect sign-in v1", origin, account, a64, nonce]);
            let fresh = pair.sign(&rng, &sign_in).expect("sign");
            assert!(ecdsa_verifies(&a, &sign_in, fresh.as_ref()));

            // The safety words of section 7.3: A confirms, B joins.
            let safety = sha256(&joined(&[
                b"apassy-connect safety v1",
                account,
                code.as_bytes(),
                &a,
                &b,
            ]));
            assert_eq!(hex_encode(&safety), v.safety.sha256);
            let six: Vec<&str> = safety[..6].iter().map(|&i| words[usize::from(i)]).collect();
            assert_eq!(six.join(" "), v.safety.words);
            let swapped = sha256(&joined(&[
                b"apassy-connect safety v1",
                account,
                code.as_bytes(),
                &b,
                &a,
            ]));
            assert_ne!(swapped[..6], safety[..6], "the order of the keys counts");

            // The recovery code of section 9.
            let recovery = hex_decode(&v.recovery.bytes_hex);
            assert_eq!(recovery.len(), 16);
            assert_eq!(
                v.recovery.code,
                format!("apassy_rec_{}", v.recovery.bytes_hex)
            );
            let sixteen: Vec<&str> = recovery.iter().map(|&i| words[usize::from(i)]).collect();
            assert_eq!(sixteen.join(" "), v.recovery.words);
            let hash = sha256(&joined(&[b"apassy-connect recovery v1", &recovery]));
            assert_eq!(hex_encode(&hash), v.recovery.recovery_hash);

            // The entitlement tokens of section 10.
            let seed = hex_decode(&v.entitlement.seed_hex);
            let key = Ed25519KeyPair::from_seed_unchecked(&seed).expect("seed");
            let public = b64u_decode(&v.entitlement.public_b64u).expect("public key");
            assert_eq!(key.public_key().as_ref(), public.as_slice());
            let keys: [(&str, &[u8]); 1] = [(v.entitlement.kid.as_str(), public.as_slice())];
            let other_seed = [7u8; 32];
            let other = Ed25519KeyPair::from_seed_unchecked(&other_seed).expect("seed");
            let other_keys: [(&str, &[u8]); 1] =
                [(v.entitlement.kid.as_str(), other.public_key().as_ref())];
            for t in &v.entitlement.tokens {
                let c = &t.claims;
                assert_eq!(c.kid, v.entitlement.kid);
                assert!(is_id(&c.acc, "acc_"));
                assert!(["personal", "family", "team"].contains(&c.plan.as_str()));
                assert!(c.group.as_deref().is_none_or(|g| is_id(g, "grp_")));
                assert_eq!(c.plan == "personal", c.group.is_none(), "{}", t.name);
                assert_eq!(c.feats, ["brain", "sync", "tunnel"]);
                assert_eq!(c.exp - c.iat, 86_400);
                let payload = serde_json::to_string(c).expect("claims");
                assert_eq!(
                    b64u_encode(payload.as_bytes()),
                    t.payload_b64u,
                    "{}",
                    t.name
                );
                assert_eq!(t.token, format!("{}.{}", t.payload_b64u, t.signature_b64u));
                let signed = joined(&[b"apassy-connect entitlement v1", t.payload_b64u.as_bytes()]);
                assert_eq!(b64u_encode(key.sign(&signed).as_ref()), t.signature_b64u);

                let ok = accept_entitlement(&t.token, &keys, c.iat + 60, "brain", &c.acc);
                assert_eq!(ok.as_ref(), Ok(c), "{}", t.name);
                assert_eq!(
                    refuse(&t.token, &keys[..], c.exp, "brain", &c.acc),
                    Some("expired")
                );
                assert_eq!(
                    refuse(&t.token, &keys[..], c.iat - 301, "brain", &c.acc),
                    Some("times")
                );
                assert_eq!(
                    refuse(&t.token, &keys[..], c.iat, "billing", &c.acc),
                    Some("feature")
                );
                assert_eq!(
                    refuse(&t.token, &keys[..], c.iat, "brain", "acc_aaaaaaaaaa"),
                    Some("account")
                );
                assert_eq!(
                    refuse(&t.token, &other_keys[..], c.iat, "brain", &c.acc),
                    Some("signature")
                );
                assert_eq!(refuse(&t.token, &[], c.iat, "brain", &c.acc), Some("kid"));
                let mut changed = c.clone();
                changed.plan = "team".into();
                let forged = format!(
                    "{}.{}",
                    b64u_encode(serde_json::to_string(&changed).expect("claims").as_bytes()),
                    t.signature_b64u
                );
                assert_eq!(
                    refuse(&forged, &keys[..], c.iat, "brain", &c.acc),
                    Some("signature")
                );
                assert_eq!(
                    refuse(&format!("{}.x", t.token), &keys[..], c.iat, "brain", &c.acc),
                    Some("parts")
                );
                let mut extra = serde_json::to_value(c).expect("claims");
                extra["admin"] = Value::Bool(true);
                let extra_payload = b64u_encode(extra.to_string().as_bytes());
                let extra_signed =
                    joined(&[b"apassy-connect entitlement v1", extra_payload.as_bytes()]);
                let extra_token = format!(
                    "{extra_payload}.{}",
                    b64u_encode(key.sign(&extra_signed).as_ref())
                );
                assert_eq!(
                    refuse(&extra_token, &keys[..], c.iat, "brain", &c.acc),
                    Some("claims")
                );
            }

            // The examples carry the vector values.
            let file: ExampleFile = serde_json::from_str(EXAMPLES).expect("examples");
            let body = |name: &str| example_body(&file, name).clone();
            let signature = |name: &str| message_signature(&v, name).to_owned();
            assert_eq!(
                body("account_create")["signature"],
                signature("account").as_str()
            );
            assert_eq!(
                body("account_create")["public_key"],
                v.device_a.public_b64u.as_str()
            );
            assert_eq!(
                body("account_create")["recovery_hash"],
                v.recovery.recovery_hash.as_str()
            );
            assert_eq!(body("token")["signature"], signature("sign_in").as_str());
            assert_eq!(body("token")["nonce"], v.nonce_b64u.as_str());
            assert_eq!(body("challenge_answer")["origin"], v.origin.as_str());
            assert_eq!(body("link")["link_hash"], v.link.link_hash.as_str());
            assert_eq!(body("join")["signature"], signature("join").as_str());
            assert_eq!(body("join")["public_key"], v.device_b.public_b64u.as_str());
            assert_eq!(
                body("join_answer")["confirmer"]["public_key"],
                v.device_a.public_b64u.as_str()
            );
            assert_eq!(
                body("confirm")["public_key"],
                v.device_b.public_b64u.as_str()
            );
            assert_eq!(body("recover")["signature"], signature("recover").as_str());
            assert_eq!(body("recover")["recovery"], v.recovery.code.as_str());
            assert_eq!(
                body("entitlement")["token"],
                v.entitlement.tokens[0].token.as_str()
            );
            assert_eq!(
                body("well_known")["keys"][0]["public_key"],
                v.entitlement.public_b64u.as_str()
            );
            assert_eq!(
                body("well_known")["keys"][0]["kid"],
                v.entitlement.kid.as_str()
            );
            assert_eq!(
                body("brain_device")["key_id"],
                v.device_a.device_id.as_str()
            );
            assert_eq!(
                body("brain_device")["public_key_sha256"],
                v.device_a.public_key_sha256.as_str()
            );
        }
    }

    // --- connect-billing-v1 -----------------------------------------------------

    pub mod billing {
        use super::*;

        const EXAMPLES: &str = include_str!("fixtures/connect-billing-v1/examples.json");
        const PLANS_JSON: &str = include_str!("fixtures/connect-billing-v1/plans.json");
        const TOTALS: &str = include_str!("fixtures/connect-billing-v1/totals.json");
        const PLAN_STATES: &str = include_str!("fixtures/connect-billing-v1/plan-states.json");
        const WEBHOOK_VECTORS: &str =
            include_str!("fixtures/connect-billing-v1/webhook-vectors.json");
        const WEBHOOKS: [(&str, &[u8]); 6] = [
            (
                "checkout-session-completed.json",
                include_bytes!(
                    "fixtures/connect-billing-v1/webhook/checkout-session-completed.json"
                ),
            ),
            (
                "customer-subscription-created.json",
                include_bytes!(
                    "fixtures/connect-billing-v1/webhook/customer-subscription-created.json"
                ),
            ),
            (
                "invoice-paid.json",
                include_bytes!("fixtures/connect-billing-v1/webhook/invoice-paid.json"),
            ),
            (
                "invoice-payment-failed.json",
                include_bytes!("fixtures/connect-billing-v1/webhook/invoice-payment-failed.json"),
            ),
            (
                "customer-subscription-updated.json",
                include_bytes!(
                    "fixtures/connect-billing-v1/webhook/customer-subscription-updated.json"
                ),
            ),
            (
                "customer-subscription-deleted.json",
                include_bytes!(
                    "fixtures/connect-billing-v1/webhook/customer-subscription-deleted.json"
                ),
            ),
        ];
        /// Section 7: the handled event types.
        const EVENT_TYPES: [&str; 6] = [
            "checkout.session.completed",
            "customer.subscription.created",
            "customer.subscription.updated",
            "customer.subscription.deleted",
            "invoice.paid",
            "invoice.payment_failed",
        ];
        const DAY: u64 = 86_400;

        #[derive(Debug, Deserialize, PartialEq)]
        #[serde(deny_unknown_fields)]
        struct Price {
            interval: String,
            lookup_key: String,
            amount: u64,
            extra: Option<u64>,
        }

        #[derive(Debug, Deserialize, PartialEq)]
        #[serde(deny_unknown_fields)]
        struct Offer {
            plan: String,
            name: String,
            unit: String,
            included: u32,
            max: u32,
            prices: Vec<Price>,
        }

        #[derive(Debug, Deserialize, PartialEq)]
        #[serde(deny_unknown_fields)]
        struct PlansView {
            currency: String,
            tax: String,
            plans: Vec<Offer>,
        }

        impl PlansView {
            fn price(&self, plan: &str, interval: &str) -> (&Offer, &Price) {
                let offer = self.plans.iter().find(|o| o.plan == plan).expect("plan");
                let price = offer
                    .prices
                    .iter()
                    .find(|p| p.interval == interval)
                    .expect("interval");
                (offer, price)
            }

            /// Section 2: `amount + max(0, n − included) × extra`, for `1 ≤ n ≤ max`.
            fn total(&self, plan: &str, interval: &str, count: u32) -> Option<u64> {
                let (offer, price) = self.price(plan, interval);
                if count == 0 || count > offer.max {
                    return None;
                }
                let further = u64::from(count.saturating_sub(offer.included));
                Some(price.amount + further * price.extra.unwrap_or(0))
            }
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Total {
            plan: String,
            interval: String,
            count: u32,
            amount: u64,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Refused {
            plan: String,
            interval: String,
            count: u32,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Totals {
            totals: Vec<Total>,
            seat_limit: Vec<Refused>,
        }

        pub fn check_prices() {
            let plans: PlansView = serde_json::from_str(PLANS_JSON).expect("plans.json");
            assert_eq!(plans.currency, "eur");
            assert_eq!(plans.tax, "inclusive");
            let names: Vec<&str> = plans.plans.iter().map(|o| o.plan.as_str()).collect();
            assert_eq!(names, ["personal", "family", "team"]);
            for offer in &plans.plans {
                let intervals: Vec<&str> =
                    offer.prices.iter().map(|p| p.interval.as_str()).collect();
                assert_eq!(intervals, ["month", "year"], "{}", offer.plan);
                assert!(offer.included >= 1 && offer.max >= offer.included);
                for price in &offer.prices {
                    let key = format!("connect_{}_{}", offer.plan, price.interval);
                    assert_eq!(price.lookup_key, key);
                    assert!(BILLING_CONTRACT.contains(&format!("`{key}`")), "{key}");
                    assert_eq!(price.extra.is_none(), offer.max == offer.included, "{key}");
                }
                // Plans section 3: a year costs 10 times the monthly price.
                let (month, year) = (&offer.prices[0], &offer.prices[1]);
                assert_eq!(year.amount, 10 * month.amount, "{}", offer.plan);
                assert_eq!(year.extra, month.extra.map(|e| 10 * e), "{}", offer.plan);
            }
            assert_eq!(
                [
                    plans.plans[0].name.as_str(),
                    plans.plans[1].name.as_str(),
                    plans.plans[2].name.as_str()
                ],
                ["Connect Personal", "Connect Family", "Connect Team"]
            );
            assert_eq!(
                [
                    plans.plans[0].unit.as_str(),
                    plans.plans[1].unit.as_str(),
                    plans.plans[2].unit.as_str()
                ],
                ["account", "person", "member"]
            );
            // The default configuration is the owner's table of plans section 3.
            for row in [
                "| Connect Personal | 3 | 30 |",
                "| Connect Family (4 people) | 5 | 50 |",
                "| Connect Team, per member | 4 | 40 |",
                "| Connect Family, each person after 4 | 1 | 10 |",
            ] {
                assert!(PLANS.contains(row), "plans.md lacks {row}");
            }
            assert_eq!(plans.price("personal", "month").1.amount, 300);
            assert_eq!(plans.price("family", "month").1.amount, 500);
            assert_eq!(plans.price("family", "month").1.extra, Some(100));
            assert_eq!(plans.plans[1].included, 4);
            assert_eq!(plans.price("team", "month").1.amount, 400);

            let totals: Totals = serde_json::from_str(TOTALS).expect("totals.json");
            for t in &totals.totals {
                assert_eq!(
                    plans.total(&t.plan, &t.interval, t.count),
                    Some(t.amount),
                    "{} {} {}",
                    t.plan,
                    t.interval,
                    t.count
                );
            }
            assert!(totals.totals.iter().any(|t| t.plan == "family"
                && t.interval == "month"
                && t.count == 6
                && t.amount == 700));
            for r in &totals.seat_limit {
                assert_eq!(
                    plans.total(&r.plan, &r.interval, r.count),
                    None,
                    "{}",
                    r.plan
                );
            }
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct StateInput {
            stripe_status: Option<String>,
            cancel_at_period_end: bool,
            period_end: Option<u64>,
            first_failed_at: Option<u64>,
            ended_at: Option<u64>,
            now: u64,
        }

        #[derive(Debug, Deserialize, PartialEq)]
        #[serde(deny_unknown_fields)]
        struct State {
            status: String,
            entitled: bool,
            renews_at: Option<u64>,
            ends_at: Option<u64>,
            grace_until: Option<u64>,
            read_only_until: Option<u64>,
            delete_at: Option<u64>,
            push: bool,
            pull: bool,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct StateCase {
            name: String,
            input: StateInput,
            expect: State,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct PlanStates {
            grace_days: u64,
            read_only_days: u64,
            delete_days: u64,
            cases: Vec<StateCase>,
        }

        fn state(status: &str, entitled: bool, pull: bool) -> State {
            State {
                status: status.into(),
                entitled,
                renews_at: None,
                ends_at: None,
                grace_until: None,
                read_only_until: None,
                delete_at: None,
                push: entitled,
                pull,
            }
        }

        /// Section 8.
        fn plan_state(input: &StateInput, grace: u64, read_only: u64, delete: u64) -> State {
            let Some(status) = input.stripe_status.as_deref() else {
                return state("none", false, false);
            };
            let grace_until = (status == "past_due")
                .then(|| input.first_failed_at.expect("a first failure") + grace * DAY);
            let end = match status {
                "active" | "trialing" => {
                    let mut s = state(status, true, true);
                    if input.cancel_at_period_end {
                        s.ends_at = input.period_end;
                    } else {
                        s.renews_at = input.period_end;
                    }
                    return s;
                }
                "incomplete" => return state("pending", false, false),
                "past_due" => {
                    let until = grace_until.expect("grace");
                    if input.now < until {
                        let mut s = state("past_due", true, true);
                        s.grace_until = grace_until;
                        return s;
                    }
                    until
                }
                "canceled" | "unpaid" | "incomplete_expired" | "paused" => {
                    input.ended_at.expect("an end")
                }
                other => panic!("unknown Stripe status {other}"),
            };
            let mut s = if input.now < end + read_only * DAY {
                let mut s = state("read_only", false, true);
                s.read_only_until = Some(end + read_only * DAY);
                s
            } else if input.now < end + delete * DAY {
                state("suspended", false, false)
            } else {
                return state("none", false, false);
            };
            s.grace_until = grace_until;
            s.delete_at = Some(end + delete * DAY);
            s
        }

        pub fn check_plan_states() {
            let states: PlanStates = serde_json::from_str(PLAN_STATES).expect("plan-states.json");
            assert_eq!(
                (states.grace_days, states.read_only_days, states.delete_days),
                (14, 30, 90)
            );
            let mut seen = std::collections::BTreeSet::new();
            for case in &states.cases {
                let got = plan_state(
                    &case.input,
                    states.grace_days,
                    states.read_only_days,
                    states.delete_days,
                );
                assert_eq!(got, case.expect, "{}", case.name);
                seen.insert(case.expect.status.clone());
                assert!(
                    BILLING_CONTRACT.contains(&format!("| `{}` |", case.expect.status)),
                    "{}",
                    case.name
                );
            }
            let all = [
                "none",
                "pending",
                "active",
                "trialing",
                "past_due",
                "read_only",
                "suspended",
            ];
            let all: std::collections::BTreeSet<String> =
                all.iter().map(|s| (*s).to_owned()).collect();
            assert_eq!(seen, all);
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Checkout {
            plan: String,
            interval: String,
            people: Option<u32>,
            seats: Option<u32>,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct CheckoutAnswer {
            url: String,
            session_id: String,
            expires_at: u64,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Empty {}

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Url {
            url: String,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Member {
            account_id: String,
            name: String,
            role: String,
            state: String,
            joined_at: Option<u64>,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct GroupView {
            group_id: String,
            kind: String,
            role: String,
            owner_account: String,
            included: u32,
            quantity: u32,
            members: Vec<Member>,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Invite {
            role: String,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct InviteAnswer {
            invite_id: u64,
            url: String,
            expires_at: u64,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct GroupJoin {
            code: String,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct GroupJoinAnswer {
            group_id: String,
            kind: String,
            state: String,
            owner_name: String,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct MemberRemoved {
            account_id: String,
            removed_from_stores: u32,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Seats {
            quantity: u32,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct SeatsAnswer {
            quantity: u32,
            pending: bool,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WebhookAnswer {
            received: bool,
            duplicate: bool,
        }

        fn is_group_code(code: &str) -> bool {
            code.strip_prefix("apassy_gin_").is_some_and(|rest| {
                rest.len() == 14 + 1 + 64
                    && is_id(&rest[..14], "grp_")
                    && rest.as_bytes()[14] == b'_'
                    && is_hex(&rest[15..], 64)
            })
        }

        fn member(m: &Member, kind: &str) -> bool {
            let roles: &[&str] = if kind == "family" {
                &["owner", "member"]
            } else {
                &["owner", "admin", "member"]
            };
            is_id(&m.account_id, "acc_")
                && is_name(&m.name)
                && roles.contains(&m.role.as_str())
                && ["pending", "active"].contains(&m.state.as_str())
                && (m.state == "active") == m.joined_at.is_some()
        }

        fn check_one(example: &Example) -> bool {
            match example.name.as_str() {
                "plans" => {
                    let body: PlansView = strict(example);
                    let file: PlansView = serde_json::from_str(PLANS_JSON).expect("plans.json");
                    assert_eq!(body, file, "the example is plans.json");
                }
                "checkout_personal" | "checkout_family" | "checkout_team" => {
                    let body: Checkout = strict(example);
                    assert!(["month", "year"].contains(&body.interval.as_str()));
                    match body.plan.as_str() {
                        "personal" => assert!(body.people.is_none() && body.seats.is_none()),
                        "family" => assert!(body.people.is_some() && body.seats.is_none()),
                        "team" => assert!(body.people.is_none() && body.seats.is_some()),
                        other => panic!("plan {other}"),
                    }
                }
                "checkout_answer" => {
                    let body: CheckoutAnswer = strict(example);
                    assert!(body.url.starts_with("https://checkout.stripe.com/"));
                    assert!(
                        body.session_id.starts_with("cs_") && body.url.ends_with(&body.session_id)
                    );
                }
                "stripe_checkout_form" => {
                    let form: Vec<(String, String)> = strict(example);
                    let get = |key: &str| {
                        form.iter()
                            .find(|(k, _)| k == key)
                            .map(|(_, v)| v.as_str())
                            .unwrap_or_else(|| panic!("form lacks {key}"))
                    };
                    assert_eq!(get("mode"), "subscription");
                    assert_eq!(get("automatic_tax[enabled]"), "true");
                    assert_eq!(get("billing_address_collection"), "required");
                    assert_eq!(get("consent_collection[terms_of_service]"), "required");
                    let account = get("client_reference_id");
                    assert!(is_id(account, "acc_"));
                    assert_eq!(get("metadata[account_id]"), account);
                    assert_eq!(get("subscription_data[metadata][account_id]"), account);
                    assert!(get("line_items[0][price]").starts_with("price_"));
                    assert!(get("line_items[0][quantity]").parse::<u32>().is_ok());
                    assert!(get("success_url").ends_with("?session_id={CHECKOUT_SESSION_ID}"));
                    assert!(is_https(get("success_url")) && is_https(get("cancel_url")));
                    // Section 1: nothing of the account beyond its id.
                    for (key, value) in &form {
                        assert!(BILLING_CONTRACT.contains(&format!("`{key}")), "{key}");
                        for word in ["email", "device", "vault", "token", "key", "secret"] {
                            assert!(!key.contains(word), "{key}");
                        }
                        assert!(!value.contains("apassy_"), "{key}");
                    }
                    assert!(!form.iter().any(|(k, _)| k == "customer_update[address]"
                        && !form.iter().any(|(c, _)| c == "customer")));
                }
                "portal" | "member_confirm" => {
                    let _: Empty = strict(example);
                }
                "portal_answer" => {
                    let body: Url = strict(example);
                    assert!(body.url.starts_with("https://billing.stripe.com/"));
                }
                "plan_active" | "plan_past_due" | "plan_read_only" | "plan_none"
                | "plan_family_member" => {
                    let body: PlanView = strict(example);
                    assert!(plan_view_is_valid(&body), "{}", example.name);
                }
                "group" => {
                    let body: GroupView = strict(example);
                    assert!(is_id(&body.group_id, "grp_") && is_id(&body.owner_account, "acc_"));
                    assert!(["family", "team"].contains(&body.kind.as_str()));
                    assert!(body.members.iter().all(|m| member(m, &body.kind)));
                    let owners: Vec<&Member> =
                        body.members.iter().filter(|m| m.role == "owner").collect();
                    assert_eq!(owners.len(), 1);
                    assert_eq!(owners[0].account_id, body.owner_account);
                    let active = body.members.iter().filter(|m| m.state == "active").count();
                    assert!(
                        u32::try_from(active).expect("count") <= body.quantity.max(body.included)
                    );
                }
                "invite" => {
                    let body: Invite = strict(example);
                    assert!(["member", "admin"].contains(&body.role.as_str()));
                }
                "invite_answer" => {
                    let body: InviteAnswer = strict(example);
                    let code = body
                        .url
                        .strip_prefix("https://apassy.wyderka.cc/connect/join#")
                        .expect("join page");
                    assert!(is_group_code(code), "{code}");
                }
                "group_join" => {
                    let body: GroupJoin = strict(example);
                    assert!(is_group_code(&body.code));
                }
                "group_join_answer" => {
                    let body: GroupJoinAnswer = strict(example);
                    assert_eq!(body.state, "pending");
                    assert!(is_id(&body.group_id, "grp_") && is_name(&body.owner_name));
                }
                "member_confirm_answer" => {
                    let body: Member = strict(example);
                    assert!(member(&body, "team") && body.state == "active");
                }
                "member_removed" => {
                    let body: MemberRemoved = strict(example);
                    assert!(is_id(&body.account_id, "acc_"));
                }
                "seats" => {
                    let body: Seats = strict(example);
                    assert!(body.quantity >= 1);
                }
                "seats_answer" => {
                    let body: SeatsAnswer = strict(example);
                    assert!(body.pending && body.quantity >= 1);
                }
                "webhook_answer" | "webhook_duplicate" => {
                    let body: WebhookAnswer = strict(example);
                    assert!(body.received);
                    assert_eq!(body.duplicate, example.name == "webhook_duplicate");
                }
                _ => return false,
            }
            true
        }

        pub fn check_examples() {
            examples("connect-billing-v1", EXAMPLES, BILLING_CONTRACT, check_one);
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WebhookCase {
            file: String,
            #[serde(rename = "type")]
            kind: String,
            event_id: String,
            t: u64,
            v1: String,
            header: String,
            sha256: String,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct HeaderCase {
            name: String,
            file: String,
            now: u64,
            header: String,
            accepted: bool,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WebhookVectors {
            endpoint_secret: String,
            tolerance_seconds: u64,
            api_version: String,
            events: Vec<WebhookCase>,
            headers: Vec<HeaderCase>,
        }

        /// The fields of section 7 that Connect reads. Stripe's body has more fields:
        /// this type, unlike the requests of the contract, accepts unknown fields.
        #[derive(Debug, Deserialize)]
        struct StripeEvent {
            id: String,
            #[serde(rename = "type")]
            kind: String,
            created: u64,
            livemode: bool,
            api_version: String,
            data: StripeData,
        }

        #[derive(Debug, Deserialize)]
        struct StripeData {
            object: Value,
        }

        fn body(file: &str) -> &'static [u8] {
            WEBHOOKS
                .iter()
                .find(|(name, _)| *name == file)
                .map(|(_, bytes)| *bytes)
                .unwrap_or_else(|| panic!("webhook body {file}"))
        }

        fn text<'a>(object: &'a Value, pointer: &str) -> &'a str {
            object
                .pointer(pointer)
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("{pointer}"))
        }

        pub fn check_webhook_bodies() {
            let vectors: WebhookVectors = serde_json::from_str(WEBHOOK_VECTORS).expect("vectors");
            assert_eq!(vectors.tolerance_seconds, 300);
            assert!(vectors.endpoint_secret.starts_with("whsec_SYNTHETIC_"));
            let plans: PlansView = serde_json::from_str(PLANS_JSON).expect("plans.json");
            let keys: Vec<&str> = plans
                .plans
                .iter()
                .flat_map(|o| o.prices.iter().map(|p| p.lookup_key.as_str()))
                .collect();
            let types: Vec<&str> = vectors.events.iter().map(|e| e.kind.as_str()).collect();
            for kind in EVENT_TYPES {
                assert!(types.contains(&kind), "no fixture for {kind}");
                assert!(BILLING_CONTRACT.contains(&format!("`{kind}`")), "{kind}");
            }
            assert_eq!(vectors.events.len(), WEBHOOKS.len());
            for case in &vectors.events {
                let bytes = body(&case.file);
                assert!(bytes.ends_with(b"}\n"), "{}", case.file);
                let event: StripeEvent = serde_json::from_slice(bytes).expect("event");
                assert_eq!(event.id, case.event_id);
                assert_eq!(event.kind, case.kind);
                assert_eq!(event.created, case.t);
                assert!(!event.livemode, "{}: fixtures are test mode", case.file);
                assert_eq!(event.api_version, vectors.api_version);
                assert_eq!(case.header, format!("t={},v1={}", case.t, case.v1));
                assert!(is_hex(&case.v1, 64) && is_hex(&case.sha256, 64));
                let object = &event.data.object;
                match event.kind.as_str() {
                    "checkout.session.completed" => {
                        let account = text(object, "/client_reference_id");
                        assert!(is_id(account, "acc_"));
                        assert_eq!(text(object, "/metadata/account_id"), account);
                        assert_eq!(text(object, "/mode"), "subscription");
                        assert!(text(object, "/customer").starts_with("cus_"));
                        assert!(text(object, "/subscription").starts_with("sub_"));
                        assert!(text(object, "/customer_details/email").ends_with(".test"));
                    }
                    "customer.subscription.created"
                    | "customer.subscription.updated"
                    | "customer.subscription.deleted" => {
                        assert!(text(object, "/id").starts_with("sub_"));
                        assert!(keys.contains(&text(object, "/items/data/0/price/lookup_key")));
                        assert!(
                            object
                                .pointer("/items/data/0/current_period_end")
                                .is_some_and(Value::is_u64)
                        );
                        assert!(
                            object
                                .pointer("/items/data/0/quantity")
                                .is_some_and(Value::is_u64)
                        );
                        assert!(
                            object
                                .pointer("/cancel_at_period_end")
                                .is_some_and(Value::is_boolean)
                        );
                        assert!(is_id(text(object, "/metadata/account_id"), "acc_"));
                        let status = text(object, "/status");
                        assert_eq!(
                            event.kind == "customer.subscription.deleted",
                            status == "canceled"
                        );
                    }
                    "invoice.paid" | "invoice.payment_failed" => {
                        let subscription =
                            text(object, "/parent/subscription_details/subscription");
                        assert!(subscription.starts_with("sub_"));
                        assert!(object.pointer("/attempt_count").is_some_and(Value::is_u64));
                    }
                    other => panic!("unexpected event {other}"),
                }
            }
        }

        /// Section 7, as the relay checks it.
        #[cfg(feature = "vault")]
        pub fn verify_stripe_signature(
            secret: &str,
            header: &str,
            body: &[u8],
            now: u64,
            tolerance: u64,
        ) -> bool {
            let mut t = None;
            let mut signatures = Vec::new();
            for part in header.split(',') {
                let Some((key, value)) = part.split_once('=') else {
                    return false;
                };
                match key {
                    "t" if t.is_none() => match value.parse::<u64>() {
                        Ok(value) => t = Some(value),
                        Err(_) => return false,
                    },
                    "t" => return false,
                    "v1" => signatures.push(value),
                    _ => {}
                }
            }
            let Some(t) = t else {
                return false;
            };
            if signatures.is_empty() || now.abs_diff(t) > tolerance {
                return false;
            }
            let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
            let mut signed = t.to_string().into_bytes();
            signed.push(b'.');
            signed.extend_from_slice(body);
            signatures.iter().any(|signature| {
                is_hex(signature, 64)
                    && ring::hmac::verify(&key, &signed, &hex_decode(signature)).is_ok()
            })
        }

        #[cfg(feature = "vault")]
        pub fn check_webhook_signatures() {
            let vectors: WebhookVectors = serde_json::from_str(WEBHOOK_VECTORS).expect("vectors");
            let secret = vectors.endpoint_secret.as_str();
            let tolerance = vectors.tolerance_seconds;
            let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
            for case in &vectors.events {
                let bytes = body(&case.file);
                let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
                assert_eq!(hex_encode(digest.as_ref()), case.sha256, "{}", case.file);
                let mut signed = case.t.to_string().into_bytes();
                signed.push(b'.');
                signed.extend_from_slice(bytes);
                let tag = ring::hmac::sign(&key, &signed);
                assert_eq!(hex_encode(tag.as_ref()), case.v1, "{}", case.file);
                assert!(verify_stripe_signature(
                    secret,
                    &case.header,
                    bytes,
                    case.t,
                    tolerance
                ));
                let mut changed = bytes.to_vec();
                let at = changed.len() / 2;
                changed[at] ^= 1;
                assert!(!verify_stripe_signature(
                    secret,
                    &case.header,
                    &changed,
                    case.t,
                    tolerance
                ));
                assert!(!verify_stripe_signature(
                    "whsec_SYNTHETIC_other",
                    &case.header,
                    bytes,
                    case.t,
                    tolerance
                ));
            }
            for case in &vectors.headers {
                assert_eq!(
                    verify_stripe_signature(
                        secret,
                        &case.header,
                        body(&case.file),
                        case.now,
                        tolerance
                    ),
                    case.accepted,
                    "{}",
                    case.name
                );
            }
            assert!(vectors.headers.iter().any(|h| h.accepted));
            assert!(vectors.headers.iter().any(|h| !h.accepted));
        }
    }

    // --- connect-tunnel-v1 ------------------------------------------------------

    pub mod tunnel {
        use super::*;
        use std::collections::BTreeMap;

        const EXAMPLES: &str = include_str!("fixtures/connect-tunnel-v1/examples.json");
        const FRAMES: &str = include_str!("fixtures/connect-tunnel-v1/frames.json");

        pub const OPEN: u8 = 0x01;
        pub const CLOSE: u8 = 0x02;
        pub const RESET: u8 = 0x04;
        pub const MAX_PAYLOAD: usize = 16_384;

        #[derive(Debug, PartialEq)]
        pub struct Frame {
            pub stream: u32,
            pub kind: u8,
            pub flags: u8,
            pub payload: Vec<u8>,
        }

        /// Section 4, the checks in their order.
        pub fn decode(bytes: &[u8]) -> Result<Frame, &'static str> {
            if bytes.len() < 8 {
                return Err("short_header");
            }
            let stream = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            let (kind, flags) = (bytes[4], bytes[5]);
            let len = usize::from(u16::from_be_bytes([bytes[6], bytes[7]]));
            if bytes.len() != 8 + len {
                return Err("length_mismatch");
            }
            if len > MAX_PAYLOAD {
                return Err("payload_too_large");
            }
            if stream == 0 {
                return Err("reserved_stream");
            }
            if !(1..=3).contains(&kind) {
                return Err("unknown_kind");
            }
            if flags & !(OPEN | CLOSE | RESET) != 0 {
                return Err("unknown_flags");
            }
            if flags & RESET != 0 && (flags != RESET || len != 0) {
                return Err("bad_reset");
            }
            if flags == 0 && len == 0 {
                return Err("empty_frame");
            }
            Ok(Frame {
                stream,
                kind,
                flags,
                payload: bytes[8..].to_vec(),
            })
        }

        pub fn encode(frame: &Frame) -> Vec<u8> {
            let len = u16::try_from(frame.payload.len()).expect("payload length");
            let mut out = Vec::with_capacity(8 + frame.payload.len());
            out.extend_from_slice(&frame.stream.to_be_bytes());
            out.push(frame.kind);
            out.push(frame.flags);
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(&frame.payload);
            out
        }

        struct Live {
            kind: u8,
            closed_to_node: bool,
            closed_to_connect: bool,
        }

        /// The stream rules of section 4 on one node WebSocket.
        #[derive(Default)]
        pub struct Streams {
            live: BTreeMap<u32, Live>,
            max_opened: u32,
        }

        impl Streams {
            pub fn step(&mut self, to_node: bool, frame: &Frame) -> Result<(), &'static str> {
                if frame.flags & OPEN != 0 {
                    if !to_node {
                        return Err("open_by_node");
                    }
                    if self.live.contains_key(&frame.stream) {
                        return Err("already_open");
                    }
                    if frame.stream <= self.max_opened {
                        return Err("reused");
                    }
                    self.max_opened = frame.stream;
                    self.live.insert(
                        frame.stream,
                        Live {
                            kind: frame.kind,
                            closed_to_node: false,
                            closed_to_connect: false,
                        },
                    );
                } else if !self.live.contains_key(&frame.stream) {
                    // A frame for an ended stream is dropped; one above every id is an error.
                    return if frame.stream > self.max_opened {
                        Err("not_open")
                    } else {
                        Ok(())
                    };
                }
                let live = self.live.get_mut(&frame.stream).expect("live stream");
                if live.kind != frame.kind {
                    return Err("kind_mismatch");
                }
                if frame.flags & RESET != 0 {
                    self.live.remove(&frame.stream);
                    return Ok(());
                }
                let closed = if to_node {
                    &mut live.closed_to_node
                } else {
                    &mut live.closed_to_connect
                };
                if *closed {
                    return Err("closed");
                }
                if frame.flags & CLOSE != 0 {
                    *closed = true;
                }
                if live.closed_to_node && live.closed_to_connect {
                    self.live.remove(&frame.stream);
                }
                Ok(())
            }
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Flags {
            open: u8,
            close: u8,
            reset: u8,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Kinds {
            device: u8,
            public: u8,
            acme: u8,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct ValidFrame {
            name: String,
            hex: String,
            stream: u32,
            kind: u8,
            flags: u8,
            payload_hex: String,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct InvalidFrame {
            name: String,
            hex: String,
            reason: String,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Sequence {
            name: String,
            frames: Vec<(String, String)>,
            error: Option<(usize, String)>,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct FramesFile {
            header_bytes: usize,
            max_payload: usize,
            flags: Flags,
            kinds: Kinds,
            frames: Vec<ValidFrame>,
            invalid: Vec<InvalidFrame>,
            sequences: Vec<Sequence>,
        }

        fn frames_file() -> FramesFile {
            serde_json::from_str(FRAMES).expect("frames.json")
        }

        pub fn check_frames() {
            let file = frames_file();
            assert_eq!(file.header_bytes, 8);
            assert_eq!(file.max_payload, MAX_PAYLOAD);
            assert_eq!(
                (file.flags.open, file.flags.close, file.flags.reset),
                (OPEN, CLOSE, RESET)
            );
            assert_eq!(
                (file.kinds.device, file.kinds.public, file.kinds.acme),
                (1, 2, 3)
            );
            for (name, code) in [("open", "0x01"), ("close", "0x02"), ("reset", "0x04")] {
                assert!(
                    TUNNEL_CONTRACT.contains(&format!("`{name}` ({code})")),
                    "{name}"
                );
            }
            for f in &file.frames {
                let bytes = hex_decode(&f.hex);
                let frame = decode(&bytes).unwrap_or_else(|err| panic!("{}: {err}", f.name));
                let expected = Frame {
                    stream: f.stream,
                    kind: f.kind,
                    flags: f.flags,
                    payload: hex_decode(&f.payload_hex),
                };
                assert_eq!(frame, expected, "{}", f.name);
                assert_eq!(encode(&frame), bytes, "{}", f.name);
            }
            assert!(
                file.frames
                    .iter()
                    .any(|f| f.payload_hex.len() == 2 * MAX_PAYLOAD)
            );
            assert!(file.frames.iter().any(|f| f.stream == u32::MAX));
            for f in &file.invalid {
                assert_eq!(
                    decode(&hex_decode(&f.hex)).err(),
                    Some(f.reason.as_str()),
                    "{}",
                    f.name
                );
                assert!(
                    TUNNEL_CONTRACT.contains(&format!("`{}`", f.reason)),
                    "{}",
                    f.reason
                );
            }
        }

        pub fn check_sequences() {
            let file = frames_file();
            for s in &file.sequences {
                let mut streams = Streams::default();
                let mut error = None;
                for (i, (direction, hex)) in s.frames.iter().enumerate() {
                    let to_node = match direction.as_str() {
                        "to_node" => true,
                        "to_connect" => false,
                        other => panic!("{}: direction {other}", s.name),
                    };
                    let frame =
                        decode(&hex_decode(hex)).unwrap_or_else(|err| panic!("{}: {err}", s.name));
                    if let Err(code) = streams.step(to_node, &frame) {
                        error = Some((i, code.to_owned()));
                        break;
                    }
                }
                assert_eq!(error, s.error, "{}", s.name);
                if let Some((_, code)) = &s.error {
                    assert!(TUNNEL_CONTRACT.contains(&format!("`{code}`")), "{code}");
                }
            }
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct NodeRegister {
            name: String,
            pin: String,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct NodeView {
            node_id: String,
            account_id: String,
            device_id: String,
            name: String,
            pin: String,
            public_name: String,
            online: bool,
            created_at: u64,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct NodeId {
            node_id: String,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct GrantCreate {
            node_id: String,
            account_id: String,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct GrantView {
            grant_id: String,
            node_id: String,
            account_id: String,
            created_at: u64,
        }

        #[derive(Debug, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct GrantDeleted {
            grant_id: String,
            closed_streams: u32,
        }

        fn is_pin(pin: &str) -> bool {
            b64u_decode(pin).is_some_and(|hash| hash.len() == 32)
        }

        fn node_view(view: &NodeView) -> bool {
            let label = view.node_id.strip_prefix("node_").unwrap_or_default();
            is_id(&view.node_id, "node_")
                && is_id(&view.account_id, "acc_")
                && is_id(&view.device_id, "dev_")
                && is_name(&view.name)
                && is_pin(&view.pin)
                && view.public_name == format!("{label}.node.apassy.wyderka.cc")
        }

        fn grant_view(view: &GrantView) -> bool {
            is_id(&view.grant_id, "tgr_")
                && is_id(&view.node_id, "node_")
                && is_id(&view.account_id, "acc_")
        }

        fn check_one(example: &Example) -> bool {
            match example.name.as_str() {
                "node_register" => {
                    let body: NodeRegister = strict(example);
                    assert!(is_name(&body.name) && is_pin(&body.pin));
                }
                "node_registered" => {
                    let body: NodeView = strict(example);
                    assert!(node_view(&body));
                }
                "nodes" => {
                    let body: Vec<NodeView> = strict(example);
                    assert!(body.iter().all(node_view));
                }
                "node_deleted" => {
                    let body: NodeId = strict(example);
                    assert!(is_id(&body.node_id, "node_"));
                }
                "grant" => {
                    let body: GrantCreate = strict(example);
                    assert!(is_id(&body.node_id, "node_") && is_id(&body.account_id, "acc_"));
                }
                "grant_answer" => {
                    let body: GrantView = strict(example);
                    assert!(grant_view(&body));
                }
                "grants" => {
                    let body: Vec<GrantView> = strict(example);
                    assert!(body.iter().all(grant_view));
                }
                "grant_deleted" => {
                    let body: GrantDeleted = strict(example);
                    assert!(is_id(&body.grant_id, "tgr_"));
                }
                _ => return false,
            }
            true
        }

        pub fn check_examples() {
            examples("connect-tunnel-v1", EXAMPLES, TUNNEL_CONTRACT, check_one);
        }
    }
}
