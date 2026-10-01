#![cfg(feature = "vault")]

//! The activity log names the check of an approval (ADR 0014). A run that the owner
//! approved on the iPhone says so, and the text still starts with "Owner approved", so
//! the desktop inbox classifies it as before (a unit test in `src/desktop/inbox.rs`). The answer to the agent keeps its
//! `decided_by`. All data is synthetic.

#[path = "support/companion.rs"]
mod companion_support;

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use apassy::agent::client::{self, SendOptions};
use apassy::agent::wire::Action;
use apassy::broker::approvals::{OwnerAction, OwnerCheck, PendingRun};
use apassy::broker::http::TlsClient;
use apassy::broker::{self, BrokerHandle, BrokerOptions};
use apassy::companion::crypto::{ApproveAction, approve_string};
use apassy::companion::digest::run_digest_hex;
use apassy::contracts::CredentialKind;
use apassy::vault::{ActivityDecision, ExecMode, Field, ItemDraft, SecretValue};
use companion_support::{DEVICE, Fixture, PASS, PhoneKey, fixture};
use tempfile::TempDir;

const SECRET: &str = "FAKE-activity-secret-5521-canary";

struct Setup {
    fx: Fixture,
    approval: PhoneKey,
    broker: BrokerHandle,
    socket: PathBuf,
    project: PathBuf,
    item_id: u64,
    token: String,
    _data: TempDir,
}

/// A vault with one item, one agent that asks for each run, one paired phone, and a
/// broker on a short socket path.
fn setup() -> Setup {
    let fx = fixture();
    let (request, approval) = (PhoneKey::generate(), PhoneKey::generate());
    fx.pair(DEVICE, "Test iPhone", &request.public(), &approval.public())
        .expect("pair");
    let data = TempDir::new().expect("temp dir");
    let base = std::fs::canonicalize(data.path()).expect("canonical temp dir");
    let project = base.join("project");
    std::fs::create_dir_all(&project).expect("project");
    let socket_dir = base.join("d");
    std::fs::create_dir_all(&socket_dir).expect("socket dir");
    std::fs::set_permissions(&socket_dir, std::fs::Permissions::from_mode(0o700)).expect("mode");
    let (item_id, token) = fx.with(|vault| {
        let item = vault
            .add(ItemDraft {
                title: "Activity staging key".to_owned(),
                kind: CredentialKind::ApiKey,
                notes: String::new(),
                tags: Vec::new(),
                fields: vec![Field {
                    name: "token".to_owned(),
                    value: SecretValue::new(SECRET.to_owned()),
                    secret: true,
                }],
            })
            .expect("add");
        vault
            .set_env_binding(item.id, "DEMO_KEY", "token")
            .expect("binding");
        let (agent, token) = vault.register_agent("Activity agent").expect("register");
        vault
            .set_exec_grant(
                agent.id,
                item.id,
                &project.display().to_string(),
                ExecMode::Ask,
            )
            .expect("grant");
        (item.id, token.expose().to_owned())
    });
    let mut options = BrokerOptions::with_tls(TlsClient::platform().expect("TLS"));
    options.approval_timeout = Duration::from_secs(30);
    options.run_timeout = Duration::from_secs(20);
    let socket = socket_dir.join("broker.sock");
    let broker =
        broker::start_with(Arc::clone(&fx.shared), &socket, options).expect("start broker");
    Setup {
        fx,
        approval,
        broker,
        socket,
        project,
        item_id,
        token,
        _data: data,
    }
}

/// How the owner confirms a run that waits.
#[derive(Clone, Copy)]
enum Confirm {
    Passphrase,
    Phone,
}

impl Setup {
    /// Send a run and let the owner approve it with `how`. Returns the answer of the
    /// broker and the newest activity entry.
    fn approved_run(&self, how: Confirm) -> (serde_json::Value, String) {
        let queue = Arc::clone(self.broker.approvals());
        let gate = self.fx.gate.clone();
        let owner = std::thread::scope(|scope| {
            let approver = scope.spawn(|| {
                let waiting: PendingRun = loop {
                    if let Some(run) = queue.pending().into_iter().next() {
                        break run;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                };
                let (check, action) = match how {
                    Confirm::Passphrase => (
                        OwnerCheck::passphrase(PASS),
                        OwnerAction::ApproveRun(waiting.clone()),
                    ),
                    Confirm::Phone => {
                        let time = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .expect("clock")
                            .as_secs();
                        let text = approve_string(
                            DEVICE,
                            ApproveAction::Approve,
                            waiting.id,
                            &run_digest_hex(&waiting),
                            time,
                        )
                        .expect("approval string");
                        (
                            OwnerCheck::Companion {
                                device_id: DEVICE.to_owned(),
                                time,
                                signature: self.approval.sign(&text),
                            },
                            OwnerAction::ApproveRun(waiting.clone()),
                        )
                    }
                };
                let proof = gate.authorize(action, check).expect("owner check");
                queue.approve(proof).expect("the queue accepts the proof");
            });
            let response = client::send_with(
                &self.socket,
                &self.token,
                Action::Run {
                    items: vec![self.item_id],
                    command: vec!["echo".to_owned(), "ok".to_owned()],
                    cwd: self.project.display().to_string(),
                    purpose: "Print ok.".to_owned(),
                    path: Some("/usr/bin:/bin".to_owned()),
                    user_request: Some("Print ok.".to_owned()),
                },
                SendOptions {
                    host_session: None,
                    timeout: None,
                },
            )
            .expect("broker answer");
            approver.join().expect("approver");
            response
        });
        assert!(owner.ok, "{owner:?}");
        let data = owner.result.clone().expect("run result");
        let reason = self.fx.with(|vault| {
            let entry = vault.recent_activity(1).expect("activity").remove(0);
            assert_eq!(entry.decision, ActivityDecision::Allow);
            entry.reason
        });
        (data, reason)
    }
}

#[test]
fn a_run_approved_on_the_iphone_says_so_in_the_activity_log() {
    let s = setup();
    let (answer, reason) = s.approved_run(Confirm::Phone);
    assert!(
        reason.starts_with("Owner approved on the iPhone. Exit code 0."),
        "{reason}"
    );
    // The answer to the agent does not change.
    assert_eq!(answer["decided_by"], "Owner approved");
    assert!(!reason.contains(SECRET) && !answer.to_string().contains(SECRET));
}

#[test]
fn a_run_approved_on_the_mac_keeps_the_plain_text() {
    let s = setup();
    let (answer, reason) = s.approved_run(Confirm::Passphrase);
    assert!(
        reason.starts_with("Owner approved. Exit code 0."),
        "{reason}"
    );
    assert!(!reason.contains("iPhone"), "{reason}");
    assert_eq!(answer["decided_by"], "Owner approved");
}
