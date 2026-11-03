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
        pub delivery: Vec<String>,
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
    pub enum Delivery {
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
        pub delivery: Delivery,
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
        #[serde(default)]
        pub result: Option<T>,
        #[serde(default)]
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

    // Section 5.4: one access item of each delivery, matching the session view.
    let access: ps::AccessView = ps::strict("access-view.json", ps::ACCESS_VIEW);
    let deliveries: Vec<String> = access
        .items
        .iter()
        .map(|item| serde_json::to_value(item.delivery).expect("delivery json"))
        .map(|value| value.as_str().expect("delivery text").to_owned())
        .collect();
    assert_eq!(deliveries, kinds.delivery);
    for delivery in &kinds.delivery {
        assert!(
            contract.contains(&format!("| `{delivery}` |")),
            "{delivery}"
        );
    }
    for item in &access.items {
        match item.delivery {
            ps::Delivery::Placeholder => assert!(!item.base_url_vars.is_empty()),
            ps::Delivery::TemporaryCredentials => {
                assert!(item.base_url_vars.is_empty());
                assert!(
                    view.short_lived
                        .iter()
                        .any(|lease| lease.item_id == item.item_id
                            && lease.env_names[0] == item.env_name)
                );
            }
            ps::Delivery::SignedRequests => {
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

    // An access item of an older node has no delivery: it is a placeholder item.
    let mut item: Value =
        serde_json::from_str::<Value>(ps::ACCESS_VIEW).expect("access")["items"][0].clone();
    item.as_object_mut().expect("item").remove("delivery");
    let parsed: ps::AccessItem = serde_json::from_value(item.clone()).expect("old item");
    assert_eq!(parsed.delivery, ps::Delivery::Placeholder);
    item["delivery"] = json!("real_value");
    assert!(serde_json::from_value::<ps::AccessItem>(item).is_err());
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
