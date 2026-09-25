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
}

#[test]
fn agent_request_rejects_epoch_mismatch_and_window_endpoints() {
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
