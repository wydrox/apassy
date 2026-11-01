#![cfg(feature = "vault")]
//! Scoped broker integration, synthetic vault and executables; no external destination.
use apassy::agent::wire::{AccessAction, AccessScope, Action, WireRequest, WireResponse};
use apassy::broker::approvals::{ApprovalQueue, OwnerAction, OwnerCheck, OwnerGate};
use apassy::broker::prompts::PromptStore;
use apassy::broker::{
    SharedVault,
    decide::{BrokerContext, handle},
};
use apassy::contracts::CredentialKind;
use apassy::vault::{Field, ItemDraft, SecretValue, Vault};
use serde_json::json;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;
const PASS: &str = "synthetic-access-integration";
struct Fixture {
    dir: tempfile::TempDir,
    ctx: BrokerContext,
    token: String,
    agent: u64,
    item: u64,
    id: u64,
}
impl Fixture {
    fn request(&self, action: Action) -> WireRequest {
        WireRequest {
            v: 0,
            token: self.token.clone(),
            host_session: None,
            action,
        }
    }
    fn status(&self) -> serde_json::Value {
        handle(
            &self.ctx,
            &self.request(Action::AccessRequestStatus {
                request_id: self.id,
            }),
        )
        .result
        .unwrap()
    }
    fn allow(&self) {
        let digest = self
            .ctx
            .vault
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .scoped_access_request(self.id)
            .unwrap()
            .card
            .digest;
        let proof = OwnerGate::new(self.ctx.vault.clone(), None)
            .authorize(
                OwnerAction::AllowAccessOnce {
                    request_id: self.id,
                    digest,
                },
                OwnerCheck::Passphrase(Zeroizing::new(PASS.into())),
            )
            .unwrap();
        apassy::broker::access_once::local_answer(
            self.ctx.vault.lock().unwrap().as_mut().unwrap(),
            self.id,
            apassy::questions::access_request::Choice::AllowOnce,
            Some(proof),
        )
        .unwrap();
    }
    fn run(&self) -> WireRequest {
        self.request(Action::Run {
            access_request_id: Some(self.id),
            items: vec![self.item],
            command: vec![
                "stripe".into(),
                "payouts".into(),
                "list".into(),
                "--api-base".into(),
                "https://api.example.test/status".into(),
            ],
            cwd: self.dir.path().to_str().unwrap().into(),
            purpose: "Read synthetic status".into(),
            path: Some(format!("{}:/usr/bin:/bin", self.dir.path().display())),
            user_request: Some("Read the synthetic status.".into()),
        })
    }
    fn answer_execution(&self) {
        let start = Instant::now();
        let run = loop {
            if let Some(run) = self.ctx.approvals.pending().first().cloned() {
                break run;
            }
            assert!(start.elapsed() < Duration::from_secs(3));
            std::thread::sleep(Duration::from_millis(5));
        };
        let proof = OwnerGate::new(self.ctx.vault.clone(), None)
            .authorize(
                OwnerAction::ApproveRun(run),
                OwnerCheck::Passphrase(Zeroizing::new(PASS.into())),
            )
            .unwrap();
        self.ctx.approvals.approve(proof).unwrap();
    }
}
fn fixture() -> Fixture {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    // A synthetic known-name command. It never opens a socket.
    std::fs::write(dir.path().join("stripe"), "#!/bin/sh\nexit 17\n").unwrap();
    std::fs::set_permissions(
        dir.path().join("stripe"),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let mut v = Vault::create(&dir.path().join("vault.db"), PASS).unwrap();
    v.unlock(PASS).unwrap();
    let item = v
        .add(ItemDraft {
            title: "Synthetic API".into(),
            kind: CredentialKind::ApiKey,
            notes: String::new(),
            tags: vec![],
            fields: vec![Field {
                name: "token".into(),
                value: SecretValue::new("SYNTHETIC-ACCESS-ONLY-0033".into()),
                secret: true,
            }],
        })
        .unwrap()
        .id;
    v.set_env_binding(item, "API_TOKEN", "token").unwrap();
    let (agent, token) = v.register_agent("Synthetic agent").unwrap();
    v.set_agent_sees_all(agent.id, true).unwrap();
    let shared: SharedVault = Arc::new(Mutex::new(Some(v)));
    let ctx = BrokerContext {
        vault: shared,
        tls: apassy::broker::http::TlsClient::platform().unwrap(),
        approvals: Arc::new(ApprovalQueue::new()),
        approval_timeout: Duration::from_secs(3),
        run_timeout: Duration::from_secs(1),
        bouncer: None,
        model_gate: None,
        prompts: Arc::new(PromptStore::new(vec![])),
    };
    let mut f = Fixture {
        dir,
        ctx,
        token: token.expose().into(),
        agent: agent.id,
        item,
        id: 0,
    };
    let response = handle(
        &f.ctx,
        &f.request(Action::RequestAccess {
            item_id: item,
            reason: "Read synthetic status.".into(),
            cwd: Some(f.dir.path().to_str().unwrap().into()),
            scope: Some(AccessScope {
                action: AccessAction::Read,
                hosts: vec!["api.example.test".into()],
            }),
        }),
    );
    assert!(response.ok, "{response:?}");
    f.id = response.result.unwrap()["request_id"].as_u64().unwrap();
    f
}
#[test]
fn access_consent_does_not_answer_the_bouncer_and_failed_run_never_refunds_it() {
    let f = fixture();
    f.allow();
    let ctx = f.ctx.clone();
    let request = f.run();
    let task = std::thread::spawn(move || handle(&ctx, &request));
    f.answer_execution();
    let result = task.join().unwrap();
    assert!(result.ok, "{result:?}");
    assert_eq!(result.result.unwrap()["exit_code"], 17);
    assert_eq!(f.status()["permit"], "consumed");
    let retry = handle(&f.ctx, &f.run());
    assert_eq!(retry.error.unwrap().code, "access_once_unavailable");
}
#[test]
fn an_identical_inflight_retry_cannot_join_and_cancellation_fences_the_waiting_run() {
    let f = fixture();
    f.allow();
    let ctx = f.ctx.clone();
    let request = f.run();
    let task = std::thread::spawn(move || handle(&ctx, &request));
    let start = Instant::now();
    while f.status()["permit"] != "consumed" {
        assert!(start.elapsed() < Duration::from_secs(3));
        std::thread::sleep(Duration::from_millis(5));
    }
    let retry = handle(&f.ctx, &f.run());
    assert_eq!(retry.error.unwrap().code, "access_once_unavailable");
    assert!(
        handle(
            &f.ctx,
            &f.request(Action::CancelAccessRequest { request_id: f.id })
        )
        .ok
    );
    assert_eq!(
        task.join().unwrap().error.unwrap().code,
        "access_once_unavailable"
    );
    assert_eq!(f.status()["state"], "allowed_once");
}
#[test]
fn status_and_cancel_neither_create_nor_expose_another_agents_request() {
    let f = fixture();
    let count = f
        .ctx
        .vault
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .scoped_access_requests()
        .unwrap()
        .len();
    let (other, token) = f
        .ctx
        .vault
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .register_agent("Other synthetic agent")
        .unwrap();
    assert_ne!(other.id, f.agent);
    for action in [
        Action::AccessRequestStatus { request_id: f.id },
        Action::CancelAccessRequest { request_id: f.id },
        Action::AccessRequestStatus {
            request_id: f.id + 1,
        },
        Action::CancelAccessRequest {
            request_id: f.id + 1,
        },
    ] {
        let request = WireRequest {
            v: 0,
            token: token.expose().into(),
            host_session: None,
            action,
        };
        let result: WireResponse = handle(&f.ctx, &request);
        assert_eq!(result.error.unwrap().code, "not_found");
    }
    assert_eq!(
        f.ctx
            .vault
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .scoped_access_requests()
            .unwrap()
            .len(),
        count
    );
    assert_eq!(f.status()["state"], json!("open"));
}
