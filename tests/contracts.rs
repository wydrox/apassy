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
