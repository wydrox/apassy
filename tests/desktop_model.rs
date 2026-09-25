#![cfg(feature = "desktop")]

use apassy::contracts::{CONTRACT_VERSION, CredentialKind, Decision};
use apassy::desktop::model::{
    AFTER_EXPIRY_ISO, AMBIGUOUS_SAMPLE_TEXT, CONFLICTING_SAMPLE_TEXT, DEFAULT_NOW_ISO, DEMO_BANNER,
    DemoScenario, DesktopModel, DraftStatus, INTERPRETER_ID, ItemDraft, MASKED_VALUE,
    OTHER_AGENT_ID, REPORTING_AGENT_ID, REPORTING_ITEM_ID, RequestStatus, SAMPLE_DESTINATION,
    SAMPLE_EXPIRY_ISO, SAMPLE_OPERATION, SAMPLE_RULE_TEXT, SAMPLE_USAGE_LIMIT,
    UNSUPPORTED_SAMPLE_TEXT,
};
use apassy::desktop::{DesktopApp, OwnerView, smoke_test};

fn ready_model() -> DesktopModel {
    let mut model = DesktopModel::new();
    assert!(model.unlock().is_ok());
    assert!(model.connect_agent(REPORTING_AGENT_ID).is_ok());
    let interpreted = model.interpret_rule(SAMPLE_RULE_TEXT).unwrap();
    assert_eq!(interpreted.status, DraftStatus::ReadyForReview);
    assert!(model.confirm_rule().is_ok());
    let activated = model.activate_rule().unwrap();
    assert_eq!(activated.status, "active");
    model
}

fn activity_blob(model: &DesktopModel) -> String {
    format!(
        "{:?}{:?}{:?}",
        model.list_activity(),
        model.list_alerts(),
        model.list_requests()
    )
}

#[test]
fn demo_starts_locked_and_unlock_is_not_authentication() {
    let mut model = DesktopModel::new();
    assert!(model.is_locked());
    assert_eq!(model.foundation_status().banner, DEMO_BANNER);
    let details = model.item_details(REPORTING_ITEM_ID).unwrap();
    assert!(details.hidden);
    assert!(details.synthetic_value.is_none());
    assert_eq!(details.display_value, MASKED_VALUE);
    model.unlock().unwrap();
    assert!(!model.is_locked());
    assert!(
        model
            .list_activity()
            .iter()
            .any(|event| event.message.contains("not owner authentication"))
    );
}

#[test]
fn foundation_status_is_honest() {
    let model = DesktopModel::new();
    let status = model.foundation_status();
    assert_eq!(status.storage, "not connected");
    assert_eq!(status.model, "unverified");
    assert_eq!(status.isolation, "unverified");
    assert_eq!(status.encryption, "not present");
    assert_eq!(status.interpreter, INTERPRETER_ID);
    assert_eq!(status.contract_version, CONTRACT_VERSION);
    assert!(status.persistence.contains("Not durable"));
}

#[test]
fn vault_lists_five_credential_categories() {
    let model = DesktopModel::new();
    let items = model.list_items("");
    assert_eq!(items.len(), 5);
    for kind in CredentialKind::ALL {
        assert!(
            items.iter().any(|item| item.kind == kind),
            "missing {}",
            kind.label()
        );
    }
}

#[test]
fn crud_and_search_cover_all_five_categories() {
    let mut model = DesktopModel::new();
    model.unlock().unwrap();
    for kind in CredentialKind::ALL {
        let created = model
            .create_item(ItemDraft {
                name: format!("Temp {}", kind.label()),
                kind,
                service: "temp-service".to_owned(),
                project: "Project A".to_owned(),
                notes: "Disposable fixture item".to_owned(),
                ..ItemDraft::default()
            })
            .unwrap();
        assert_eq!(created.kind, kind);
        assert_eq!(model.list_items(&created.name).len(), 1);
        let updated = model
            .update_item(
                &created.id,
                ItemDraft {
                    name: format!("Temp {} 2", kind.label()),
                    kind,
                    ..ItemDraft::default()
                },
            )
            .unwrap();
        assert_eq!(updated.revision, 2);
        assert_eq!(model.list_items(&updated.name).len(), 1);
        assert!(model.list_items("no-such-item").is_empty());
        model.delete_item(&created.id).unwrap();
        assert!(model.list_items(&updated.name).is_empty());
    }
}

#[test]
fn create_assigns_internal_synthetic_value_and_has_no_secret_field() {
    let mut model = DesktopModel::new();
    model.unlock().unwrap();
    let created = model
        .create_item(ItemDraft {
            name: "Safe".to_owned(),
            kind: CredentialKind::Login,
            ..ItemDraft::default()
        })
        .unwrap();
    model.reveal_item(&created.id).unwrap();
    let details = model.item_details(&created.id).unwrap();
    let value = details.synthetic_value.expect("revealed value");
    assert!(value.starts_with("SYNTH-LOGIN-"));
    assert!(value.ends_with("-NOT-A-SECRET"));
    assert!(!format!("{created:?}").contains(&value));
}

#[test]
fn category_change_is_refused_and_empty_search_returns_every_item() {
    let mut model = DesktopModel::new();
    model.unlock().unwrap();
    assert_eq!(model.list_items("").len(), 5);
    assert_eq!(model.list_items("   ").len(), 5);
    let result = model.update_item(
        REPORTING_ITEM_ID,
        ItemDraft {
            name: "Project A reporting service".to_owned(),
            kind: CredentialKind::Login,
            ..ItemDraft::default()
        },
    );
    assert_eq!(result.unwrap_err().code, "category_locked");
}

#[test]
fn values_stay_masked_until_deliberate_demo_reveal() {
    let mut model = DesktopModel::new();
    model.unlock().unwrap();
    let details = model.item_details(REPORTING_ITEM_ID).unwrap();
    assert!(!details.revealed);
    assert_eq!(details.display_value, MASKED_VALUE);
    assert!(details.synthetic_value.is_none());
    let revealed = model.reveal_item(REPORTING_ITEM_ID).unwrap();
    assert!(revealed.revealed);
    assert_ne!(revealed.display_value, MASKED_VALUE);
    assert!(revealed.reveal_warning.contains("demo reveal"));
}

#[test]
fn copy_control_warns_and_does_not_write_clipboard() {
    let mut model = DesktopModel::new();
    model.unlock().unwrap();
    let hidden = model.demo_copy_item(REPORTING_ITEM_ID).unwrap_err();
    assert_eq!(hidden.code, "not_revealed");
    model.reveal_item(REPORTING_ITEM_ID).unwrap();
    let copied = model.demo_copy_item(REPORTING_ITEM_ID).unwrap();
    assert!(!copied.wrote_clipboard);
    assert!(copied.warning.contains("does not write to the clipboard"));
}

#[test]
fn connect_and_revoke_fixture_agents() {
    let mut model = DesktopModel::new();
    model.unlock().unwrap();
    let catalog = model.catalog_agents();
    assert_eq!(catalog.len(), 2);
    let connected = model.connect_agent(REPORTING_AGENT_ID).unwrap();
    assert!(connected.connected);
    assert_eq!(connected.status_label, "connected");
    let other = model.connect_agent(OTHER_AGENT_ID).unwrap();
    assert!(other.connected);
    let revoked = model.revoke_agent(REPORTING_AGENT_ID).unwrap();
    assert!(!revoked.connected);
    assert_eq!(revoked.status_label, "revoked");
}

#[test]
fn supported_sample_review_and_confirmation() {
    let mut model = DesktopModel::new();
    model.unlock().unwrap();
    model.connect_agent(REPORTING_AGENT_ID).unwrap();
    let draft = model.interpret_rule(SAMPLE_RULE_TEXT).unwrap();
    assert_eq!(draft.status, DraftStatus::ReadyForReview);
    assert_eq!(draft.interpreter, INTERPRETER_ID);
    assert_eq!(draft.clauses.len(), 7);
    assert!(!draft.confirmed);
    assert!(draft.examples.unwrap().deny.contains("production"));
    model.confirm_rule().unwrap();
    let rule = model.activate_rule().unwrap();
    assert_eq!(rule.status, "active");
    assert_eq!(rule.expiry_iso, SAMPLE_EXPIRY_ISO);
    assert_eq!(rule.usage_limit, SAMPLE_USAGE_LIMIT);
}

#[test]
fn sample_does_not_activate_without_confirmation() {
    let mut model = DesktopModel::new();
    model.unlock().unwrap();
    model.connect_agent(REPORTING_AGENT_ID).unwrap();
    model.interpret_rule(SAMPLE_RULE_TEXT).unwrap();
    let blocked = model.activate_rule().unwrap_err();
    assert_eq!(blocked.code, "confirmation_required");
    assert!(model.active_rule().is_none());
}

#[test]
fn fixture_interpreter_refuses_unsupported_prose() {
    let mut model = DesktopModel::new();
    model.unlock().unwrap();
    model.connect_agent(REPORTING_AGENT_ID).unwrap();
    let cases = [
        (
            "Allow Bob to do stuff on Friday maybe.",
            DraftStatus::Blocked,
            "unfamiliar_text",
        ),
        (
            AMBIGUOUS_SAMPLE_TEXT,
            DraftStatus::NeedsClarification,
            "ambiguous_text",
        ),
        (
            CONFLICTING_SAMPLE_TEXT,
            DraftStatus::Blocked,
            "conflicting_text",
        ),
        (
            UNSUPPORTED_SAMPLE_TEXT,
            DraftStatus::Blocked,
            "unsupported_text",
        ),
    ];
    for (text, status, code) in cases {
        let draft = model.interpret_rule(text).unwrap();
        assert_eq!(draft.status, status, "{code}");
        assert_eq!(draft.reason_code, code);
        assert!(!draft.can_activate);
        assert!(model.confirm_rule().is_err());
        assert!(model.activate_rule().is_err());
        assert!(model.active_rule().is_none());
    }
}

#[test]
fn normal_allow_path_does_not_need_extra_approval() {
    let mut model = ready_model();
    let result = model.simulate(DemoScenario::Normal).unwrap();
    assert_eq!(result.decision, Decision::Allow);
    assert_eq!(result.reason_code, "automatic_permit");
    assert_eq!(result.status, RequestStatus::Completed);
    assert!(result.executed);
    assert!(!result.approvable);
    assert_eq!(model.active_rule().unwrap().use_count, 1);
}

#[test]
fn uncertain_ask_path_can_be_approved_once() {
    let mut model = ready_model();
    let result = model.simulate(DemoScenario::Uncertain).unwrap();
    assert_eq!(result.decision, Decision::RequireApproval);
    assert_eq!(result.status, RequestStatus::Pending);
    assert!(!result.executed);
    assert!(result.approvable);
    let approved = model.approve_once(&result.id, None).unwrap();
    assert_eq!(approved.status, RequestStatus::Completed);
    assert!(approved.executed);
    assert!(approved.approval_consumed);
    let second = model.approve_once(&result.id, None).unwrap_err();
    assert_eq!(second.code, "not_pending");
}

#[test]
fn owner_can_deny_a_waiting_request() {
    let mut model = ready_model();
    let result = model.simulate(DemoScenario::Uncertain).unwrap();
    let denied = model.deny_request(&result.id).unwrap();
    assert_eq!(denied.status, RequestStatus::Denied);
    assert!(!denied.executed);
    assert_eq!(denied.reason_code, "owner_denied");
}

#[test]
fn production_deny_path_cannot_be_approved() {
    let mut model = ready_model();
    let result = model.simulate(DemoScenario::Production).unwrap();
    assert_eq!(result.decision, Decision::Deny);
    assert_eq!(result.reason_code, "explicit_denial");
    assert_eq!(result.status, RequestStatus::Denied);
    assert!(!result.approvable);
    assert!(!result.executed);
    assert_eq!(
        model.approve_once(&result.id, None).unwrap_err().code,
        "not_pending"
    );
}

#[test]
fn approval_is_bound_to_one_request_digest() {
    let mut model = ready_model();
    let first = model
        .submit_request(
            REPORTING_AGENT_ID,
            REPORTING_ITEM_ID,
            SAMPLE_DESTINATION,
            SAMPLE_OPERATION,
            "unclear task",
        )
        .unwrap();
    let second = model
        .submit_request(
            REPORTING_AGENT_ID,
            REPORTING_ITEM_ID,
            SAMPLE_DESTINATION,
            SAMPLE_OPERATION,
            "unclear task, extra parameter",
        )
        .unwrap();
    assert_ne!(first.digest, second.digest);
    assert!(model.approve_once(&first.id, None).is_ok());
    assert_eq!(
        model
            .list_requests()
            .iter()
            .find(|request| request.id == second.id)
            .unwrap()
            .status,
        RequestStatus::Pending
    );
    let mismatch = model
        .approve_once(&second.id, Some("forged-digest"))
        .unwrap_err();
    assert_eq!(mismatch.code, "request_mismatch");
}

#[test]
fn revocation_denies_future_use_and_invalidates_waiting_requests() {
    let mut model = ready_model();
    let waiting = model.simulate(DemoScenario::Uncertain).unwrap();
    model.revoke_agent(REPORTING_AGENT_ID).unwrap();
    assert_eq!(
        model
            .list_requests()
            .iter()
            .find(|request| request.id == waiting.id)
            .unwrap()
            .status,
        RequestStatus::Invalidated
    );
    let later = model.simulate(DemoScenario::Normal).unwrap();
    assert_eq!(later.decision, Decision::Deny);
    assert_eq!(later.reason_code, "agent_revoked");
    assert_eq!(model.active_rule().unwrap().status, "revoked");
    model.connect_agent(REPORTING_AGENT_ID).unwrap();
    let restored = model.simulate(DemoScenario::Normal).unwrap();
    assert_eq!(restored.reason_code, "no_grant");
}

#[test]
fn lock_hides_details_and_invalidates_pending_authority() {
    let mut model = ready_model();
    model.reveal_item(REPORTING_ITEM_ID).unwrap();
    assert!(model.item_details(REPORTING_ITEM_ID).unwrap().revealed);
    let waiting = model.simulate(DemoScenario::Uncertain).unwrap();
    model.lock().unwrap();
    let details = model.item_details(REPORTING_ITEM_ID).unwrap();
    assert!(details.hidden);
    assert!(details.synthetic_value.is_none());
    assert_eq!(details.masked_value, MASKED_VALUE);
    assert_eq!(
        model.approve_once(&waiting.id, None).unwrap_err().code,
        "vault_locked"
    );
    assert_eq!(
        model
            .list_requests()
            .iter()
            .find(|request| request.id == waiting.id)
            .unwrap()
            .status,
        RequestStatus::Invalidated
    );
    let locked_request = model.simulate(DemoScenario::Normal).unwrap();
    assert_eq!(locked_request.reason_code, "vault_locked");
    model.unlock().unwrap();
    let after = model.item_details(REPORTING_ITEM_ID).unwrap();
    assert!(!after.hidden);
    assert!(!after.revealed);
    assert!(model.approve_once(&waiting.id, None).is_err());
}

#[test]
fn item_revision_change_invalidates_waiting_request() {
    let mut model = ready_model();
    let result = model.simulate(DemoScenario::Uncertain).unwrap();
    model
        .update_item(
            REPORTING_ITEM_ID,
            ItemDraft {
                name: "Project A reporting service".to_owned(),
                kind: CredentialKind::ApiKey,
                notes: "Changed label".to_owned(),
                ..ItemDraft::default()
            },
        )
        .unwrap();
    assert_eq!(
        model.approve_once(&result.id, None).unwrap_err().code,
        "not_pending"
    );
    assert_eq!(
        model
            .list_requests()
            .iter()
            .find(|request| request.id == result.id)
            .unwrap()
            .status,
        RequestStatus::Invalidated
    );
}

#[test]
fn failed_notification_keeps_waiting_request() {
    let mut model = ready_model();
    model.set_notification_healthy(false).unwrap();
    let result = model.simulate(DemoScenario::Uncertain).unwrap();
    assert_eq!(result.status, RequestStatus::Pending);
    assert_eq!(result.delivery_status, "failed");
    assert!(!result.executed);
    assert!(model.approve_once(&result.id, None).is_ok());
}

#[test]
fn activity_does_not_contain_synthetic_values() {
    let mut model = ready_model();
    let revealed = model.reveal_item(REPORTING_ITEM_ID).unwrap();
    let secret = revealed.synthetic_value.expect("secret");
    assert!(secret.starts_with("SYNTH-"));
    assert!(
        !model
            .demo_copy_item(REPORTING_ITEM_ID)
            .unwrap()
            .wrote_clipboard
    );
    model.simulate(DemoScenario::Normal).unwrap();
    model.simulate(DemoScenario::Uncertain).unwrap();
    model.simulate(DemoScenario::Production).unwrap();
    let blob = activity_blob(&model);
    assert!(!blob.contains(&secret));
    assert!(!blob.contains("SYNTH-"));
    assert!(!blob.contains("NOT-A-SECRET"));
}

#[test]
fn sample_usage_limit_and_expiry_deny_further_use() {
    let mut model = ready_model();
    for _ in 0..SAMPLE_USAGE_LIMIT {
        assert_eq!(
            model.simulate(DemoScenario::Normal).unwrap().decision,
            Decision::Allow
        );
    }
    let blocked = model.simulate(DemoScenario::Normal).unwrap();
    assert_eq!(blocked.decision, Decision::Deny);
    assert_eq!(blocked.reason_code, "usage_limit");
    assert_eq!(model.now_iso(), DEFAULT_NOW_ISO);
    model.set_now(AFTER_EXPIRY_ISO).unwrap();
    let mut fresh = ready_model();
    fresh.set_now(AFTER_EXPIRY_ISO).unwrap();
    let expired = fresh.simulate(DemoScenario::Normal).unwrap();
    assert_eq!(expired.reason_code, "expired");
}

#[test]
fn reset_reloads_fixtures_locked() {
    let mut model = ready_model();
    model.simulate(DemoScenario::Normal).unwrap();
    model.reset().unwrap();
    assert!(model.is_locked());
    assert_eq!(model.list_items("").len(), 5);
    assert!(model.active_rule().is_none());
    assert!(model.list_agents().is_empty());
    assert!(model.list_requests().is_empty());
}

#[test]
fn ui_tests_instantiate_model_only() {
    let app = DesktopApp::new();
    assert_eq!(app.view(), OwnerView::Vault);
    assert!(app.model().is_locked());
    assert_eq!(app.model().foundation_status().banner, DEMO_BANNER);
}

#[test]
fn smoke_test_exercises_model_without_a_window() {
    smoke_test().expect("smoke-test model check");
}

#[test]
fn approval_updates_current_state_but_keeps_initial_decision_and_delivery_failure() {
    let mut model = ready_model();
    model.set_notification_healthy(false).unwrap();
    let waiting = model.simulate(DemoScenario::Uncertain).unwrap();
    let history: Vec<_> = model.list_activity().into_iter().cloned().collect();
    let approved = model.approve_once(&waiting.id, None).unwrap();
    assert_eq!(approved.decision, Decision::Allow);
    assert_eq!(approved.reason_code, "owner_approved_once");
    assert_eq!(approved.initial_decision, Decision::RequireApproval);
    assert_eq!(approved.initial_reason_code, waiting.reason_code);
    assert_eq!(approved.status, RequestStatus::Completed);
    assert!(approved.executed && approved.approval_consumed);
    assert!(!approved.approvable);
    assert_eq!(approved.delivery_status, "failed");
    let alert = model
        .list_alerts()
        .into_iter()
        .find(|alert| alert.request_id == waiting.id)
        .unwrap();
    assert_eq!(alert.decision, Decision::Allow);
    assert_eq!(alert.status, RequestStatus::Completed);
    assert_eq!(alert.title, "Permitted request");
    assert_eq!(alert.message, approved.message);
    assert_eq!(alert.delivery_status, "failed");
    for event in &history {
        assert!(model.list_activity().contains(&event));
    }
    assert_eq!(
        model.approve_once(&waiting.id, None).unwrap_err().code,
        "not_pending"
    );
}

#[test]
fn lock_revoke_and_owner_denial_synchronize_alerts_without_rewriting_initial_decision() {
    for action in ["lock", "revoke", "deny"] {
        let mut model = ready_model();
        let waiting = model.simulate(DemoScenario::Uncertain).unwrap();
        let expected_status = match action {
            "lock" => {
                model.lock().unwrap();
                RequestStatus::Invalidated
            }
            "revoke" => {
                model.revoke_agent(REPORTING_AGENT_ID).unwrap();
                RequestStatus::Invalidated
            }
            "deny" => {
                model.deny_request(&waiting.id).unwrap();
                RequestStatus::Denied
            }
            _ => unreachable!(),
        };
        let current = model
            .list_requests()
            .iter()
            .find(|request| request.id == waiting.id)
            .unwrap();
        assert_eq!(current.status, expected_status, "{action}");
        assert_eq!(current.decision, Decision::Deny, "{action}");
        assert_eq!(
            current.initial_decision,
            Decision::RequireApproval,
            "{action}"
        );
        assert_eq!(current.initial_reason_code, waiting.reason_code, "{action}");
        assert!(!current.approvable && !current.executed, "{action}");
        let alert = model
            .list_alerts()
            .into_iter()
            .find(|alert| alert.request_id == waiting.id)
            .unwrap();
        assert_eq!(alert.status, expected_status, "{action}");
        assert_eq!(alert.decision, current.decision, "{action}");
        assert_eq!(alert.message, current.message, "{action}");
        assert_ne!(alert.title, "Request waits for a decision", "{action}");
        assert!(model.approve_once(&waiting.id, None).is_err(), "{action}");
    }
}

#[test]
fn expired_approval_updates_alert_and_never_executes() {
    let mut model = ready_model();
    let waiting = model.simulate(DemoScenario::Uncertain).unwrap();
    model.set_now(AFTER_EXPIRY_ISO).unwrap();
    assert_eq!(
        model.approve_once(&waiting.id, None).unwrap_err().code,
        "expired"
    );
    let current = model
        .list_requests()
        .iter()
        .find(|request| request.id == waiting.id)
        .unwrap();
    assert_eq!(current.status, RequestStatus::Denied);
    assert_eq!(current.decision, Decision::Deny);
    assert_eq!(current.initial_decision, Decision::RequireApproval);
    assert!(!current.executed && !current.approvable && !current.approval_consumed);
    let alert = model
        .list_alerts()
        .into_iter()
        .find(|alert| alert.request_id == waiting.id)
        .unwrap();
    assert_eq!(alert.status, current.status);
    assert_eq!(alert.decision, current.decision);
    assert_eq!(alert.message, current.message);
}
