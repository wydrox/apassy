//! Synthetic MCP connections and a disposable broker/vault. No host configuration,
//! owner data, keychain, running application, or provider is used.
use super::*;
use crate::broker::approvals::{OwnerAction, OwnerCheck, OwnerGate, PendingRun};
use crate::broker::http::TlsClient;
use crate::broker::{self, BrokerHandle, BrokerOptions, SharedVault};
use crate::contracts::CredentialKind;
use crate::vault::{Field, ItemDraft, SecretValue, Vault};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::thread::JoinHandle;
use tempfile::TempDir;

const PASS: &str = "synthetic-mcp-passphrase";
const SECRET: &str = "FAKE-mcp-vault-canary-73109";
const UNRELATED: &str = "FAKE-unrelated-output-canary-88902";

struct Fixture {
    dir: TempDir,
    vault: SharedVault,
    broker: BrokerHandle,
    token: String,
    item: u64,
    agent: u64,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut vault = Vault::create(&dir.path().join("vault.db"), PASS).unwrap();
        vault.unlock(PASS).unwrap();
        let item = vault
            .add(ItemDraft {
                title: "Synthetic key".into(),
                kind: CredentialKind::ApiKey,
                notes: String::new(),
                tags: vec![],
                fields: vec![Field {
                    name: "token".into(),
                    value: SecretValue::new(SECRET.into()),
                    secret: true,
                }],
            })
            .unwrap()
            .id;
        vault
            .set_env_binding(item, "SYNTHETIC_KEY", "token")
            .unwrap();
        let (agent, token) = vault.register_agent("Synthetic MCP host").unwrap();
        vault.set_agent_sees_all(agent.id, true).unwrap();
        let vault = Arc::new(Mutex::new(Some(vault)));
        let mut options = BrokerOptions::with_tls(TlsClient::platform().unwrap());
        options.approval_timeout = Duration::from_secs(10);
        options.run_timeout = Duration::from_secs(5);
        let broker = broker::start_with(
            Arc::clone(&vault),
            &dir.path().join("run/broker.sock"),
            options,
        )
        .unwrap();
        Self {
            dir,
            vault,
            broker,
            token: token.expose().into(),
            item,
            agent: agent.id,
        }
    }

    fn connect(&self) -> Host {
        Host::new(AdapterConfig {
            socket: self.broker.socket_path().to_owned(),
            token: Some(self.token.clone()),
            host_session: Some("synthetic-session".into()),
        })
    }

    fn run(&self, script: &str) -> Value {
        json!({"name":TOOL_RUN_WITH_SECRETS, "arguments":{"items":[self.item], "command":["/bin/sh","-c",script], "cwd":self.dir.path().display().to_string(), "purpose":"Test synthetic concurrency", "user_request":"Run the synthetic test", "idempotency_key":"synthetic-run-key"}, "_meta":{"progressToken":"synthetic-progress"}})
    }

    fn pending(&self) -> PendingRun {
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(run) = self.broker.approvals().pending().into_iter().next() {
                return run;
            }
            assert!(Instant::now() < end, "owner question did not appear");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn approve(&self) {
        let proof = OwnerGate::new(Arc::clone(&self.vault), None)
            .authorize(
                OwnerAction::ApproveRun(self.pending()),
                OwnerCheck::passphrase(PASS),
            )
            .unwrap();
        self.broker.approvals().approve(proof).unwrap();
    }

    fn status(&self, id: &str) -> Value {
        client::send(
            self.broker.socket_path(),
            &self.token,
            Action::OperationStatus {
                operation_id: id.into(),
            },
        )
        .unwrap()
        .result
        .unwrap()
    }

    fn completed(&self, id: &str) -> Value {
        let end = Instant::now() + Duration::from_secs(5);
        loop {
            let status = self.status(id);
            if status["state"] == "completed" {
                return status;
            }
            assert!(Instant::now() < end, "operation did not complete");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

struct Host {
    input: UnixStream,
    output: io::BufReader<UnixStream>,
    thread: Option<JoinHandle<io::Result<()>>>,
    seen: Vec<Value>,
}

impl Host {
    fn new(config: AdapterConfig) -> Self {
        let (input, server_input) = UnixStream::pair().unwrap();
        let (output, server_output) = UnixStream::pair().unwrap();
        output
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let thread = std::thread::spawn(move || {
            serve(
                &config,
                io::BufReader::new(server_input),
                server_output,
                Duration::from_millis(25),
            )
        });
        Self {
            input,
            output: io::BufReader::new(output),
            thread: Some(thread),
            seen: Vec::new(),
        }
    }

    fn send(&mut self, message: Value) {
        serde_json::to_writer(&mut self.input, &message).unwrap();
        self.input.write_all(b"\n").unwrap();
    }

    fn call(&mut self, id: u64, params: Value) {
        self.send(json!({"jsonrpc":"2.0", "id":id, "method":"tools/call", "params":params}));
    }

    fn next(&mut self) -> Value {
        let mut line = String::new();
        assert_ne!(
            self.output.read_line(&mut line).unwrap(),
            0,
            "adapter closed early"
        );
        let message = serde_json::from_str(&line).unwrap();
        self.seen.push(message);
        self.seen.last().unwrap().clone()
    }

    fn reply(&mut self, id: u64) -> Value {
        loop {
            let message = self.next();
            if message["id"] == id {
                return message["result"].clone();
            }
        }
    }

    fn operation(&mut self) -> String {
        loop {
            let message = self.next();
            if message["method"] == "notifications/progress" {
                return message["params"]["operation_id"].as_str().unwrap().into();
            }
        }
    }

    fn cancel(&mut self, id: u64) {
        self.send(
            json!({"jsonrpc":"2.0", "method":"notifications/cancelled", "params":{"requestId":id}}),
        );
    }

    fn close(&mut self) {
        if let Some(thread) = self.thread.take() {
            self.input.shutdown(Shutdown::Write).unwrap();
            thread.join().unwrap().unwrap();
        }
    }
}
impl Drop for Host {
    fn drop(&mut self) {
        self.close()
    }
}

#[test]
fn read_completes_while_run_waits_and_cancellation_withdraws_question() {
    let fx = Fixture::new();
    let mut host = fx.connect();
    host.call(1, fx.run("printf should-not-run"));
    let id = host.operation();
    fx.pending();
    host.call(2, json!({"name":TOOL_LIST_ACCESS}));
    let read = host.reply(2);
    assert_eq!(read["isError"], false);
    assert!(!fx.broker.approvals().pending().is_empty());
    host.cancel(1);
    let cancelled = host.reply(1);
    assert_eq!(cancelled["structuredContent"]["code"], "cancelled");
    assert!(fx.broker.approvals().pending().is_empty());
    let status = fx.completed(&id);
    assert_eq!(status["may_have_run"], false);
    assert_eq!(status["outcome"]["code"], "cancelled");
    assert!(!format!("{:?}", host.seen).contains(SECRET));
}

#[test]
fn execution_cancellation_is_honest_and_reconnect_retrieves_final_outcome() {
    let fx = Fixture::new();
    let mut host = fx.connect();
    host.call(
        1,
        fx.run(&format!(
            "printf '%s' \"$SYNTHETIC_KEY\"; printf '{UNRELATED}'; sleep 1; exit 7"
        )),
    );
    let id = host.operation();
    fx.approve();
    let end = Instant::now() + Duration::from_secs(5);
    while fx.status(&id)["state"] != "executing" {
        assert!(Instant::now() < end);
        std::thread::sleep(Duration::from_millis(5));
    }
    host.cancel(1);
    let cancelled = host.reply(1);
    assert_eq!(
        cancelled["structuredContent"]["code"],
        "cancellation_requested"
    );
    host.close();
    let status = fx.completed(&id);
    assert_eq!(status["outcome"]["result"]["exit_code"], 7);
    assert_eq!(status["may_have_run"], true);
    let mut reconnect = fx.connect();
    reconnect.call(
        2,
        json!({"name":TOOL_LIST_ACCESS, "arguments":{"operation_id":id}}),
    );
    let response = reconnect.reply(2);
    assert_eq!(response["structuredContent"]["result"], status);
    for payload in [response.to_string(), format!("{:?}", host.seen)] {
        assert!(!payload.contains(SECRET));
        assert!(!payload.contains(UNRELATED));
    }
}

#[test]
fn progress_repeats_without_arguments_and_eof_withdraws_question() {
    let fx = Fixture::new();
    let mut host = fx.connect();
    host.call(1, fx.run("printf secret-argument-canary"));
    let id = host.operation();
    fx.pending();
    let started = Instant::now();
    let mut values = Vec::new();
    while values.len() < 3 {
        let message = host.next();
        if message["method"] == "notifications/progress" {
            assert_eq!(message["params"]["progressToken"], "synthetic-progress");
            assert!(!message.to_string().contains("secret-argument-canary"));
            assert!(!message.to_string().contains(SECRET));
            values.push(message["params"]["progress"].as_u64().unwrap());
        }
    }
    assert!(values.windows(2).all(|v| v[0] < v[1]));
    assert!(started.elapsed() >= Duration::from_millis(50));
    host.close();
    assert!(fx.broker.approvals().pending().is_empty());
    assert_eq!(fx.completed(&id)["outcome"]["code"], "cancelled");
}

#[test]
fn idempotent_retry_reuses_outcome_and_different_arguments_are_refused() {
    let fx = Fixture::new();
    let args = json!({"name":TOOL_GENERATE_CREDENTIAL, "arguments":{"name":"Synthetic generated password", "cwd":fx.dir.path().display().to_string(), "idempotency_key":"synthetic-generate-key"}});
    let mut host = fx.connect();
    host.call(1, args.clone());
    let first = host.reply(1);
    assert_eq!(first["isError"], false, "{first}");
    let id = first["structuredContent"]["operation_id"].as_str().unwrap();
    host.close();
    let mut host = fx.connect();
    host.call(2, args.clone());
    let second = host.reply(2);
    assert_eq!(second["structuredContent"]["operation_id"], id);
    assert_eq!(
        second["structuredContent"]["result"]["outcome"]["result"]["item_id"],
        first["structuredContent"]["result"]["item_id"]
    );
    let mut different = args;
    different["arguments"]["name"] = json!("Different password");
    host.call(3, different);
    assert_eq!(
        host.reply(3)["structuredContent"]["code"],
        "idempotency_conflict"
    );
    let guard = fx.vault.lock().unwrap();
    assert_eq!(
        guard
            .as_ref()
            .unwrap()
            .items_created_by(fx.agent, 0)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn inflight_replay_does_not_take_over_owner_question_and_other_agents_cannot_read_receipt() {
    let fx = Fixture::new();
    let mut host = fx.connect();
    let args = fx.run("exit 0");
    host.call(1, args.clone());
    let id = host.operation();
    let question = fx.pending();
    host.call(2, args);
    let replay = host.reply(2);
    assert_eq!(replay["structuredContent"]["operation_id"], id);
    assert_eq!(fx.pending().id, question.id);
    let other_token = fx
        .vault
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .register_agent("Other synthetic agent")
        .unwrap()
        .1;
    let other = client::send(
        fx.broker.socket_path(),
        other_token.expose(),
        Action::OperationStatus {
            operation_id: id.clone(),
        },
    )
    .unwrap();
    assert_eq!(other.error.unwrap().code, "operation_not_found");
    let other_cancel = client::send(
        fx.broker.socket_path(),
        other_token.expose(),
        Action::CancelOperation {
            operation_id: id.clone(),
        },
    )
    .unwrap();
    assert_eq!(other_cancel.error.unwrap().code, "operation_not_found");
    assert_eq!(fx.status(&id)["state"], "waiting_for_owner");
    host.cancel(1);
    assert_eq!(host.reply(1)["structuredContent"]["code"], "cancelled");
}

#[test]
fn cancellation_before_submission_is_fenced_and_binds_the_retry_key() {
    let fx = Fixture::new();
    let id = "00000000000000000000000000000001";
    let cancelled = client::send(
        fx.broker.socket_path(),
        &fx.token,
        Action::CancelOperation {
            operation_id: id.into(),
        },
    )
    .unwrap();
    assert_eq!(cancelled.result.unwrap()["may_have_run"], false);
    let action = Action::GenerateCredential {
        name: "Synthetic cancelled generation".into(),
        length: None,
        alphabet: None,
        cwd: Some(fx.dir.path().display().to_string()),
        folder: None,
    };
    let tracked = |id: &str, action: Action| Action::Tracked {
        operation_id: id.into(),
        idempotency_key: Some("cancelled-key".into()),
        action: Box::new(action),
    };
    let response = client::send(
        fx.broker.socket_path(),
        &fx.token,
        tracked(id, action.clone()),
    )
    .unwrap();
    assert_eq!(response.result.unwrap()["outcome"]["code"], "cancelled");
    let repeated = client::send(
        fx.broker.socket_path(),
        &fx.token,
        tracked("00000000000000000000000000000002", action),
    )
    .unwrap();
    assert_eq!(repeated.operation_id.as_deref(), Some(id));
    let different = client::send(
        fx.broker.socket_path(),
        &fx.token,
        tracked(
            "00000000000000000000000000000003",
            Action::GenerateCredential {
                name: "Different".into(),
                length: None,
                alphabet: None,
                cwd: None,
                folder: None,
            },
        ),
    )
    .unwrap();
    assert_eq!(different.error.unwrap().code, "idempotency_conflict");
    assert!(
        fx.vault
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .items_created_by(fx.agent, 0)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn bounded_dispatch_reserves_a_read_slot_and_keeps_descriptions_available() {
    use std::os::unix::net::UnixListener;
    use std::sync::{Barrier, mpsc};
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("synthetic.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let barrier = Arc::new(Barrier::new(4));
    let release = Arc::clone(&barrier);
    let (accepted, ready) = mpsc::channel();
    let broker = std::thread::spawn(move || {
        std::thread::scope(|scope| {
            for _ in 0..4 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut line = String::new();
                io::BufReader::new(stream.try_clone().unwrap())
                    .read_line(&mut line)
                    .unwrap();
                let request: super::super::wire::WireRequest = serde_json::from_str(&line).unwrap();
                if matches!(request.action, Action::Tracked { .. }) {
                    accepted.send(()).unwrap();
                    let release = Arc::clone(&release);
                    scope.spawn(move || {
                        release.wait();
                        serde_json::to_writer(
                            &mut stream,
                            &WireResponse::success(json!({"item_id":1})),
                        )
                        .unwrap();
                        stream.write_all(b"\n").unwrap();
                    });
                } else {
                    assert_eq!(request.action, Action::ListAccess);
                    serde_json::to_writer(
                        &mut stream,
                        &WireResponse::success(json!({"catalog":[]})),
                    )
                    .unwrap();
                    stream.write_all(b"\n").unwrap();
                }
            }
        })
    });
    let mut host = Host::new(AdapterConfig {
        socket,
        token: Some("synthetic-token".into()),
        host_session: None,
    });
    for id in 1..=3 {
        host.call(id, json!({"name":TOOL_GENERATE_CREDENTIAL, "arguments":{"name":"Synthetic held mutation"}}));
    }
    for _ in 0..3 {
        ready.recv_timeout(Duration::from_secs(5)).unwrap();
    }
    host.call(
        4,
        json!({"name":TOOL_GENERATE_CREDENTIAL, "arguments":{"name":"Synthetic refused mutation"}}),
    );
    assert_eq!(host.reply(4)["structuredContent"]["code"], "busy");
    host.call(5, json!({"name":TOOL_LIST_ACCESS}));
    assert_eq!(host.reply(5)["isError"], false);
    host.send(json!({"jsonrpc":"2.0", "id":6, "method":"tools/list"}));
    assert_eq!(host.reply(6)["tools"].as_array().unwrap().len(), 10);
    host.call(1, json!({"name":TOOL_LIST_ACCESS}));
    assert_eq!(host.next()["error"]["code"], -32600);
    barrier.wait();
    let mut ids = Vec::new();
    for _ in 0..3 {
        ids.push(host.next()["id"].as_u64().unwrap());
    }
    ids.sort_unstable();
    assert_eq!(ids, vec![1, 2, 3]);
    broker.join().unwrap();
}

#[test]
fn cancelling_a_credential_request_dismisses_its_owner_inbox_entry() {
    let fx = Fixture::new();
    let mut host = fx.connect();
    host.call(1, json!({"name":TOOL_ASK_OWNER_FOR_CREDENTIAL, "arguments":{"name":"Synthetic missing credential", "purpose":"Test cancellation", "cwd":fx.dir.path().display().to_string()}, "_meta":{"progressToken":8}}));
    let id = host.operation();
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        if fx
            .vault
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .agent_credential_requests(fx.agent)
            .unwrap()
            .iter()
            .any(|r| r.state == crate::vault::agent_items::CredentialRequestState::Open)
        {
            break;
        }
        assert!(Instant::now() < end);
        std::thread::sleep(Duration::from_millis(5));
    }
    host.cancel(1);
    assert_eq!(host.reply(1)["structuredContent"]["code"], "cancelled");
    assert_eq!(fx.completed(&id)["outcome"]["code"], "cancelled");
    let guard = fx.vault.lock().unwrap();
    assert!(
        guard
            .as_ref()
            .unwrap()
            .agent_credential_requests(fx.agent)
            .unwrap()
            .iter()
            .all(|r| r.state != crate::vault::agent_items::CredentialRequestState::Open)
    );
}

#[test]
fn stdin_eof_drains_a_short_mutation_before_cancelling_remaining_waits() {
    let fx = Fixture::new();
    let mut host = fx.connect();
    host.call(1, json!({"name":TOOL_GENERATE_CREDENTIAL, "arguments":{"name":"Synthetic EOF credential", "cwd":fx.dir.path().display().to_string()}}));
    host.close();
    let reply = host.reply(1);
    assert_eq!(reply["isError"], false, "{reply}");
    assert!(reply["structuredContent"]["result"]["item_id"].is_u64());
    assert!(fx.broker.approvals().pending().is_empty());
}
