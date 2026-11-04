#![cfg(feature = "vault")]

//! Shadow mode, promotion, and rollback of a candidate model through the broker (ADR
//! 0010, goal items B9 and B10). Since plan 0035 unit F the candidate rides in the
//! request of the active model as `shadow_heads` (contract bouncer-brain-v1 section 3):
//! one fake model server on a loopback port knows the head sets. Synthetic values only.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use apassy::agent::client;
use apassy::agent::wire::{Action, WireResponse};
use apassy::broker::approvals::{OwnerAction, OwnerCheck, OwnerGate, OwnerProof};
use apassy::broker::bouncer::BouncerClient;
use apassy::broker::http::TlsClient;
use apassy::broker::model_server::ModelGate;
use apassy::broker::{self, BrokerHandle, BrokerOptions, SharedVault, shadow};
use apassy::contracts::CredentialKind;
use apassy::vault::exceptions::ExceptionKind;
use apassy::vault::{
    ActivationAction, CandidateState, Declaration, Environment, ExecMode, Field, ItemDraft,
    NewCandidate, OwnerLabel, RealOutcome, Reversibility, RiskLevel, Scope, SecretValue,
    ShadowAnswer, ShadowEntry, THIS_MAC_HOST, Vault,
};
use serde_json::{Value, json};
use tempfile::TempDir;

const PASS: &str = "shadow-mode-pass-ok";
const WRONG: &str = "shadow-mode-pass-no";
const SECRET: &str = "FAKE-shadow-secret-4471-canary";
const ENV_NAME: &str = "DEMO_KEY";
const BASE: &str = "apassy-base-v1+83224960";
const BASE_HEADS: &str = "83224960aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CANDIDATE: &str = "apassy-local-v1+0badc0de";
const SHA: &str = "0badc0de0123456789abcdef0123456789abcdef0123456789abcdef01234567";
/// A head set that the fake server does not have.
const SHA_UNKNOWN: &str = "deadbeef0123456789abcdef0123456789abcdef0123456789abcdef01234567";
/// A head set that the fake server has under another version.
const SHA_OTHER: &str = "111111110123456789abcdef0123456789abcdef0123456789abcdef01234567";
const OTHER_VERSION: &str = "apassy-local-v1+11111111";

/// One head set of the fake server.
#[derive(Clone, Copy)]
struct Heads {
    sha: &'static str,
    model: &'static str,
    answer: fn(&str) -> f64,
}

/// What the fake server does with `shadow_heads`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ShadowMode {
    /// The contract: the answers of a known head set, `unknown_heads` for another.
    Answer,
    /// `shadow.error: "shadow_failed"`, for example a shadow over its time or size cap.
    Failed,
    /// No `shadow` part at all.
    Missing,
    /// A shadow part that names another head set.
    WrongHeads,
}

/// A fake Laya server with head sets (contract bouncer-brain-v1). `task_match` comes
/// from the `answer` of the head set. `writes` is 0.5, so the policy needs
/// `task_match`. Every other fact is 0.02. Without `heads` the default head set
/// answers; an unknown `heads` is 409 `unknown_heads`. The server keeps each body.
struct FakeModel {
    url: String,
    bodies: Arc<Mutex<Vec<Value>>>,
    heads: Arc<Mutex<Vec<Heads>>>,
    shadow: Arc<Mutex<ShadowMode>>,
}

impl FakeModel {
    fn calls(&self) -> usize {
        self.bodies.lock().expect("bodies").len()
    }

    fn bodies(&self) -> Vec<Value> {
        self.bodies.lock().expect("bodies").clone()
    }

    /// The bodies after the first `from`.
    fn bodies_since(&self, from: usize) -> Vec<Value> {
        self.bodies().split_off(from)
    }

    fn add(&self, heads: Heads) {
        self.heads.lock().expect("heads").push(heads);
    }

    fn forget(&self, sha: &str) {
        self.heads.lock().expect("heads").retain(|h| h.sha != sha);
    }

    fn set_shadow(&self, mode: ShadowMode) {
        *self.shadow.lock().expect("mode") = mode;
    }
}

fn answers(request: &Value, state: &str, answer: fn(&str) -> f64) -> Value {
    let mut answers = serde_json::Map::new();
    if let Some(questions) = request["questions"].as_object() {
        for name in questions.keys() {
            let p = match name.as_str() {
                "task_match" => answer(state),
                "writes" => 0.5,
                _ => 0.02,
            };
            answers.insert(name.clone(), json!({"type": "noul", "noul": p}));
        }
    }
    Value::Object(answers)
}

fn respond(stream: &mut std::net::TcpStream, status: &str, body: &str) {
    let _ = write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
}

fn fake_model(default: Heads) -> FakeModel {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake model");
    let url = format!("http://{}", listener.local_addr().expect("addr"));
    let bodies = Arc::new(Mutex::new(Vec::new()));
    let heads = Arc::new(Mutex::new(vec![default]));
    let shadow = Arc::new(Mutex::new(ShadowMode::Answer));
    let (seen, known, mode) = (Arc::clone(&bodies), Arc::clone(&heads), Arc::clone(&shadow));
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut reader = BufReader::new(stream.try_clone().expect("clone"));
            let mut length = 0usize;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
                if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse().unwrap_or(0);
                }
            }
            let mut body = vec![0u8; length];
            if reader.read_exact(&mut body).is_err() {
                continue;
            }
            let request: Value = serde_json::from_slice(&body).unwrap_or_default();
            seen.lock().expect("bodies").push(request.clone());
            let state = request["state"].as_str().unwrap_or_default().to_owned();
            let sets = known.lock().expect("heads").clone();
            let find = |sha: &str| sets.iter().find(|h| h.sha == sha).copied();
            let mut stream = stream;
            let active = match request["heads"].as_str() {
                None => default,
                Some(sha) => match find(sha) {
                    Some(heads) => heads,
                    None => {
                        respond(
                            &mut stream,
                            "409 Conflict",
                            r#"{"detail":{"code":"unknown_heads","message":"the head set is not on this server"}}"#,
                        );
                        continue;
                    }
                },
            };
            let mut out = json!({
                "answers": answers(&request, &state, active.answer),
                "model": active.model,
                "heads": active.sha,
            });
            if let Some(sha) = request["shadow_heads"].as_str() {
                match (*mode.lock().expect("mode"), find(sha)) {
                    (ShadowMode::Answer, Some(heads)) => {
                        out["shadow"] = json!({
                            "heads": heads.sha,
                            "model": heads.model,
                            "answers": answers(&request, &state, heads.answer),
                        });
                    }
                    (ShadowMode::Answer, None) => {
                        out["shadow"] = json!({"heads": sha, "error": "unknown_heads"});
                    }
                    (ShadowMode::Failed, _) => {
                        out["shadow"] = json!({"heads": sha, "error": "shadow_failed"});
                    }
                    (ShadowMode::Missing, _) => {}
                    (ShadowMode::WrongHeads, heads) => {
                        out["shadow"] = json!({
                            "heads": SHA_UNKNOWN,
                            "model": heads.map_or(CANDIDATE, |h| h.model),
                            "answers": answers(&request, &state, opposite_answer),
                        });
                    }
                }
            }
            respond(&mut stream, "200 OK", &out.to_string());
        }
    });
    FakeModel {
        url,
        bodies,
        heads,
        shadow,
    }
}

/// A loopback address that counts its connections and never answers: the place of an
/// old candidate server on 8775, without a fixed port.
fn silent_listener() -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let url = format!("http://{}", listener.local_addr().expect("addr"));
    let count = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&count);
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            seen.fetch_add(1, Ordering::SeqCst);
            drop(stream);
        }
    });
    (url, count)
}

/// The active model: sure for a "fast" command, unsure for the others.
fn active_answer(state: &str) -> f64 {
    if state.contains("fast") { 0.95 } else { 0.3 }
}

/// The candidate: the opposite of the active model.
fn opposite_answer(state: &str) -> f64 {
    if state.contains("fast") { 0.3 } else { 0.95 }
}

/// Unsure about everything.
fn unsure_answer(_: &str) -> f64 {
    0.3
}

const BASE_SET: Heads = Heads {
    sha: BASE_HEADS,
    model: BASE,
    answer: active_answer,
};

const CANDIDATE_SET: Heads = Heads {
    sha: SHA,
    model: CANDIDATE,
    answer: opposite_answer,
};

struct Fixture {
    _dir: TempDir,
    vault: SharedVault,
    socket: PathBuf,
    project: PathBuf,
    item_id: u64,
    token: String,
    broker: BrokerHandle,
    active: FakeModel,
    owner_stop: Arc<AtomicBool>,
    owner: Option<JoinHandle<()>>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.owner_stop.store(true, Ordering::SeqCst);
        if let Some(owner) = self.owner.take() {
            let _ = owner.join();
        }
    }
}

/// Confirmed development/low reaches the model step under ADR 0029. Shadow and
/// promotion assertions need real inference eligibility, not fabricated use history.
fn model_declaration() -> Declaration {
    Declaration {
        project: "project".to_owned(),
        environment: Environment::Development,
        risk: RiskLevel::Low,
        scope: Scope::ReadWrite,
        reversibility: Reversibility::Reversible,
    }
}

/// The owner confirms `action` with the passphrase now (goal item A4).
fn owner_check(vault: &SharedVault, action: OwnerAction) -> OwnerProof {
    OwnerGate::new(Arc::clone(vault), None)
        .authorize(action, OwnerCheck::passphrase(PASS))
        .expect("owner check")
}

fn brain_client(url: &str) -> BouncerClient {
    BouncerClient::new(url)
        .expect("url")
        .with_timeout(Duration::from_secs(2))
}

/// A broker with the active fake model and a simulated owner. The owner denies a run
/// whose command has the word "deny" and approves every other run, with the owner check.
fn fixture() -> Fixture {
    fixture_with(None)
}

/// [`fixture`] with the hook of Settings > Agents `gate`.
fn fixture_with(gate: Option<Arc<dyn ModelGate>>) -> Fixture {
    let active = fake_model(BASE_SET);
    let dir = TempDir::new().expect("temp dir");
    let project = dir.path().join("project");
    std::fs::create_dir_all(&project).expect("project");
    let project = std::fs::canonicalize(project).expect("canonical");
    let script = project.join("report.sh");
    std::fs::write(&script, "#!/bin/sh\necho \"$@\"\n").expect("script");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    let mut vault = Vault::create(&dir.path().join("vault.db"), PASS).expect("create");
    vault.unlock(PASS).expect("unlock");
    let item = vault
        .add(ItemDraft {
            title: "Key".to_owned(),
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
        .set_env_binding(item.id, ENV_NAME, "token")
        .expect("binding");
    let (agent, token) = vault.register_agent("Shadow agent").expect("register");
    vault
        .set_exec_grant(
            agent.id,
            item.id,
            &project.display().to_string(),
            ExecMode::Bouncer,
        )
        .expect("grant");
    vault
        .set_declaration(item.id, &model_declaration())
        .expect("declaration");
    let shared: SharedVault = Arc::new(Mutex::new(Some(vault)));
    let mut options = BrokerOptions::with_tls(TlsClient::platform().expect("TLS"));
    options.approval_timeout = Duration::from_secs(20);
    options.run_timeout = Duration::from_secs(10);
    options.bouncer = Some(brain_client(&active.url));
    options.model_gate = gate;
    let socket = dir.path().join("run").join("broker.sock");
    let broker = broker::start_with(Arc::clone(&shared), &socket, options).expect("broker");
    let owner_stop = Arc::new(AtomicBool::new(false));
    let owner = {
        let approvals = Arc::clone(broker.approvals());
        let vault = Arc::clone(&shared);
        let stop = Arc::clone(&owner_stop);
        std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                for pending in approvals.pending() {
                    if pending.command.join(" ").contains("deny") {
                        approvals.deny(pending.id);
                    } else {
                        let proof = owner_check(&vault, OwnerAction::ApproveRun(pending));
                        let _ = approvals.approve(proof);
                    }
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        })
    };
    Fixture {
        _dir: dir,
        vault: shared,
        socket,
        project,
        item_id: item.id,
        token: token.expose().to_owned(),
        broker,
        active,
        owner_stop,
        owner: Some(owner),
    }
}

fn run(fx: &Fixture, script: &str) -> WireResponse {
    client::send(
        &fx.socket,
        &fx.token,
        Action::Run {
            access_request_id: None,
            codes: Default::default(),
            items: vec![fx.item_id],
            command: vec!["sh".to_owned(), "-c".to_owned(), script.to_owned()],
            cwd: fx.project.display().to_string(),
            purpose: "Print the report.".to_owned(),
            path: Some("/usr/bin:/bin".to_owned()),
            user_request: Some("Print the weekly report.".to_owned()),
        },
    )
    .expect("answer")
}

/// "Bouncer allowed", "Owner approved", or the refusal code.
fn outcome(response: &WireResponse) -> String {
    if response.ok {
        response.result.as_ref().expect("result")["decided_by"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    } else {
        response
            .error
            .as_ref()
            .map_or_else(String::new, |e| e.code.clone())
    }
}

fn with_vault<T>(fx: &Fixture, f: impl FnOnce(&mut Vault) -> T) -> T {
    let mut guard = fx.vault.lock().expect("vault");
    f(guard.as_mut().expect("open"))
}

/// Register a candidate with `version` and head hash `sha`. `url` is the old address
/// column, which the broker no longer reads.
fn register_as(fx: &Fixture, url: &str, version: &str, sha: &str) -> u64 {
    with_vault(fx, |vault| {
        vault
            .register_candidate(
                &NewCandidate {
                    version: version.to_owned(),
                    url: url.to_owned(),
                    checkpoint: "/tmp/apassy-test/candidate.safetensors".to_owned(),
                    checkpoint_sha256: sha.to_owned(),
                    report: "{}".to_owned(),
                },
                broker::learning::now(),
            )
            .expect("candidate")
            .id
    })
}

fn register(fx: &Fixture, url: &str) -> u64 {
    register_as(fx, url, CANDIDATE, SHA)
}

/// The head file of candidate `id` is on the bouncer brain of this Mac (unit G marks it
/// after the upload).
fn place(fx: &Fixture, id: u64) {
    assert!(with_vault(fx, |vault| {
        vault
            .mark_candidate_uploaded(id, Some(THIS_MAC_HOST))
            .expect("mark")
    }));
}

/// Register and place a candidate with `version` and `sha`.
fn placed_as(fx: &Fixture, version: &str, sha: &str) -> u64 {
    let id = register_as(fx, "", version, sha);
    place(fx, id);
    id
}

/// Wait until the candidate has `rows` shadow rows.
fn wait_for_rows(fx: &Fixture, candidate: u64, rows: u32) -> apassy::vault::ShadowSummary {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let summary = with_vault(fx, |vault| {
            vault.shadow_summary(candidate).expect("summary")
        });
        if summary.requests >= rows || Instant::now() > deadline {
            return summary;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// The request sequence: a sure run, an unsure run that the owner approves, an unsure
/// run that the owner denies, and a run with a rule flag (secret output).
const SEQUENCE: [&str; 4] = [
    "./report.sh fast 1",
    "./report.sh slow 2",
    "./report.sh slow deny 3",
    "printenv DEMO_KEY",
];

const BASELINE: [&str; 4] = [
    "Bouncer allowed",
    "Owner approved",
    "approval_denied",
    "Owner approved",
];

fn decisions(fx: &Fixture) -> Vec<String> {
    SEQUENCE
        .iter()
        .map(|script| outcome(&run(fx, script)))
        .collect()
}

/// The `shadow_heads` of each body.
fn shadow_heads(bodies: &[Value]) -> Vec<Option<String>> {
    bodies
        .iter()
        .map(|body| body["shadow_heads"].as_str().map(str::to_owned))
        .collect()
}

/// ADR 0010 with plan 0035 unit F: the candidate decides in the same request with no
/// effect. The broker gives the same decisions with and without a candidate that
/// answers the opposite, and asks one server once per model step. The vault records
/// each candidate answer next to the real outcome and the owner decision. A candidate
/// that the server does not have ("down"), whose head file is not on the host yet,
/// that answers as another version, or that the server gives up on ("slow",
/// `shadow_failed`) records no answer and changes nothing; a run does not wait for it.
#[test]
fn a_candidate_that_is_down_slow_or_another_version_changes_nothing() {
    let fx = fixture();
    let baseline = decisions(&fx);
    assert_eq!(baseline, BASELINE);
    assert_eq!(fx.active.calls(), 3, "a rule flag skips the model");
    assert!(
        shadow_heads(&fx.active.bodies())
            .iter()
            .all(Option::is_none),
        "no candidate, no shadow_heads"
    );

    // Opposite: the candidate answers the opposite of the active model. Its old address
    // is never asked.
    let (old_url, old_calls) = silent_listener();
    fx.active.add(CANDIDATE_SET);
    let id = register(&fx, &old_url);
    place(&fx, id);
    assert_eq!(decisions(&fx), baseline, "the candidate changed a decision");
    assert_eq!(fx.active.calls(), 6, "one request for each model step");
    let sent = fx.active.bodies_since(3);
    assert_eq!(shadow_heads(&sent), vec![Some(SHA.to_owned()); 3]);
    assert!(
        sent.iter().all(|body| body.get("heads").is_none()),
        "the default head set decides"
    );
    assert_eq!(old_calls.load(Ordering::SeqCst), 0, "no second server");
    let summary = wait_for_rows(&fx, id, 3);
    assert_eq!(summary.requests, 3);
    assert_eq!(summary.no_answer, 0);
    assert_eq!(
        summary.same_as_active, 0,
        "the candidate answers the opposite"
    );
    // Owner decisions: the approval of "slow 2" (the candidate runs it: agreement) and
    // the denial of "slow deny 3" (the candidate runs it: an allowed denial).
    assert_eq!(summary.agreement.shadow_decisions, 2);
    assert_eq!(summary.agreement.agreed, 1);
    assert_eq!(summary.agreement.allowed_owner_denials, 1);
    assert!(!summary.agreement.can_promote());
    // The decision log has no candidate data. The active model decided.
    let log = with_vault(&fx, |vault| vault.decision_log().expect("log"));
    assert_eq!(log.len(), 8);
    assert!(
        log.iter()
            .all(|record| !record.entry.note.contains(CANDIDATE))
    );

    // Down: the server does not have the head set (`shadow.error: unknown_heads`).
    let down = placed_as(&fx, CANDIDATE, SHA_UNKNOWN);
    assert_eq!(decisions(&fx), baseline);
    let summary = wait_for_rows(&fx, down, 3);
    assert_eq!((summary.requests, summary.no_answer), (3, 3));
    assert_eq!(summary.agreement.shadow_decisions, 0);

    // Not on the host: the request goes without `shadow_heads`, and no answer.
    let calls = fx.active.calls();
    let unplaced = register_as(&fx, "", CANDIDATE, SHA);
    assert_eq!(decisions(&fx), baseline);
    assert_eq!(
        shadow_heads(&fx.active.bodies_since(calls)),
        vec![None; 3],
        "nothing rides before the upload"
    );
    let summary = wait_for_rows(&fx, unplaced, 3);
    assert_eq!((summary.requests, summary.no_answer), (3, 3));

    // Another version under the candidate's head hash: no answer.
    fx.active.add(Heads {
        sha: SHA_OTHER,
        model: OTHER_VERSION,
        answer: opposite_answer,
    });
    let other = placed_as(&fx, CANDIDATE, SHA_OTHER);
    assert_eq!(decisions(&fx), baseline);
    let summary = wait_for_rows(&fx, other, 3);
    assert_eq!((summary.requests, summary.no_answer), (3, 3));

    // Slow: the server gives up on the shadow head set and answers the active part. The
    // sure run still ends at once, with the active answer.
    fx.active.set_shadow(ShadowMode::Failed);
    let slow = placed_as(&fx, CANDIDATE, SHA);
    let started = Instant::now();
    assert_eq!(outcome(&run(&fx, SEQUENCE[0])), "Bouncer allowed");
    let elapsed = started.elapsed();
    let summary = wait_for_rows(&fx, slow, 1);
    assert_eq!((summary.requests, summary.no_answer), (1, 1));
    assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
}

/// Plan 0035 unit F: a shadow error, a missing shadow part, or a shadow part of another
/// head set records `NoAnswer`. The active answer still decides each run.
#[test]
fn a_shadow_error_records_no_answer_and_the_active_decision_stands() {
    let fx = fixture();
    fx.active.add(CANDIDATE_SET);
    for mode in [
        ShadowMode::Failed,
        ShadowMode::Missing,
        ShadowMode::WrongHeads,
    ] {
        fx.active.set_shadow(mode);
        let id = placed_as(&fx, CANDIDATE, SHA);
        let calls = fx.active.calls();
        assert_eq!(decisions(&fx), BASELINE, "{mode:?}");
        assert_eq!(
            shadow_heads(&fx.active.bodies_since(calls)),
            vec![Some(SHA.to_owned()); 3],
            "{mode:?}"
        );
        let summary = wait_for_rows(&fx, id, 3);
        assert_eq!((summary.requests, summary.no_answer), (3, 3), "{mode:?}");
        assert_eq!(summary.agreement.shadow_decisions, 0, "{mode:?}");
    }
    // The decision log has the active answers: "fast 1" ran with task_match 0.95.
    let log = with_vault(&fx, |vault| vault.decision_log().expect("log"));
    let fast = log
        .iter()
        .rev()
        .find(|record| record.entry.note.contains("Model allowed"))
        .expect("a model decision");
    assert!(
        fast.entry
            .model_facts
            .iter()
            .any(|(name, p)| name == "task_match" && (*p - 0.95).abs() < 1e-9),
        "{:?}",
        fast.entry.model_facts
    );
    // Back to the contract: the candidate answers again.
    fx.active.set_shadow(ShadowMode::Answer);
    let id = placed_as(&fx, CANDIDATE, SHA);
    assert_eq!(decisions(&fx), BASELINE);
    let summary = wait_for_rows(&fx, id, 3);
    assert_eq!((summary.requests, summary.no_answer), (3, 0));
}

/// Add shadow rows straight in the vault: `agree` owner approvals that the candidate
/// runs, `ask_allow` approvals that it would ask, and `run_deny` denials that it runs.
fn shadow_rows(fx: &Fixture, id: u64, agree: u32, ask_allow: u32, run_deny: u32) {
    with_vault(fx, |vault| {
        let rows = [
            (agree, ShadowAnswer::Run, OwnerLabel::Allow),
            (ask_allow, ShadowAnswer::Ask, OwnerLabel::Allow),
            (run_deny, ShadowAnswer::Run, OwnerLabel::Deny),
        ];
        for (count, candidate, owner) in rows {
            for _ in 0..count {
                assert!(
                    vault
                        .record_shadow(&ShadowEntry {
                            candidate_id: id,
                            at: broker::learning::now(),
                            real: RealOutcome::Ask,
                            candidate,
                            owner,
                            facts: Vec::new(),
                        })
                        .expect("row")
                );
            }
        }
    });
}

fn promote(fx: &Fixture, id: u64, version: &str) -> Result<(), String> {
    let proof = owner_check(
        &fx.vault,
        OwnerAction::PromoteModel {
            candidate_id: id,
            version: version.to_owned(),
        },
    );
    with_vault(fx, |vault| {
        shadow::promote(vault, id, proof, broker::learning::now()).map(|_| ())
    })
}

/// ADR 0010: promotion needs 100 shadow decisions, 95% agreement, no allowed denial,
/// and the owner check. Each refusal leaves the default model active.
#[test]
fn promotion_is_refused_below_each_threshold_and_without_the_owner_check() {
    let fx = fixture();
    let active = |fx: &Fixture| with_vault(fx, |vault| vault.active_model().expect("active"));
    for (agree, ask_allow, run_deny, needle) in [
        (99, 0, 0, "99 of 100 owner decisions"),
        (94, 6, 0, "agreement with you is 94.0%"),
        (100, 0, 1, "would allow 1 request(s) that you denied"),
    ] {
        let id = register(&fx, "http://127.0.0.1:9");
        shadow_rows(&fx, id, agree, ask_allow, run_deny);
        let refused = promote(&fx, id, CANDIDATE).expect_err("refused");
        assert!(refused.contains(needle), "{refused}");
        assert_eq!(active(&fx), None, "{needle}");
    }

    // Before the promotion, the default model asks for "slow 2".
    assert_eq!(outcome(&run(&fx, SEQUENCE[1])), "Owner approved");

    // Exactly at the gate: 100 decisions, 95 agreed, no allowed denial.
    let (old_url, old_calls) = silent_listener();
    fx.active.add(CANDIDATE_SET);
    let id = register(&fx, &old_url);
    shadow_rows(&fx, id, 95, 5, 0);
    // Plan 0035 unit F: the head file must be on the host first.
    let refused = promote(&fx, id, CANDIDATE).expect_err("not on the host");
    assert!(
        refused.contains("not on the bouncer brain on this Mac"),
        "{refused}"
    );
    assert_eq!(active(&fx), None);
    place(&fx, id);
    // No owner check: a wrong passphrase gives no proof.
    let gate = OwnerGate::new(Arc::clone(&fx.vault), None);
    let action = OwnerAction::PromoteModel {
        candidate_id: id,
        version: CANDIDATE.to_owned(),
    };
    assert!(
        gate.authorize(action.clone(), OwnerCheck::passphrase(WRONG))
            .is_err()
    );
    // A proof for another action, another candidate, or another version is refused.
    let others = [
        OwnerAction::ChangeCalibration { level: 70 },
        OwnerAction::PromoteModel {
            candidate_id: id + 1,
            version: CANDIDATE.to_owned(),
        },
        OwnerAction::PromoteModel {
            candidate_id: id,
            version: "apassy-local-v1+11111111".to_owned(),
        },
        OwnerAction::RollbackModel { activation_id: 1 },
    ];
    for other in others {
        let proof = owner_check(&fx.vault, other.clone());
        let refused = with_vault(&fx, |vault| {
            shadow::promote(vault, id, proof, broker::learning::now())
        })
        .expect_err("a proof for another action");
        assert!(refused.contains("another action"), "{other:?}: {refused}");
        assert_eq!(active(&fx), None);
    }
    promote(&fx, id, CANDIDATE).expect("promoted");
    let activation = active(&fx).expect("activation");
    assert_eq!(activation.action, ActivationAction::Promote);
    assert_eq!(activation.version, CANDIDATE);
    assert_eq!(activation.url, old_url, "the old address is kept, not read");
    assert_eq!(activation.heads_sha256.as_deref(), Some(SHA));
    assert!(
        activation.previous_url.is_empty(),
        "the default model before"
    );
    let state = with_vault(&fx, |vault| {
        vault.candidate(id).expect("read").expect("some").state
    });
    assert_eq!(state, CandidateState::Promoted);
    let activity = with_vault(&fx, |vault| vault.recent_activity(10).expect("activity"));
    let entry = activity
        .iter()
        .find(|entry| entry.operation == "promote model")
        .expect("the promotion is in the activity log");
    assert!(entry.reason.contains(CANDIDATE), "{}", entry.reason);
    assert!(entry.reason.contains("agreement 95.0%"), "{}", entry.reason);
    // A second promotion of the same candidate is refused: it is not in shadow mode.
    let again = promote(&fx, id, CANDIDATE).expect_err("not in shadow mode");
    assert!(again.contains("not in shadow mode"), "{again}");

    // The promoted head set decides now, pinned by its hash: it is sure about "slow 2".
    let calls = fx.active.calls();
    assert_eq!(outcome(&run(&fx, SEQUENCE[1])), "Bouncer allowed");
    assert_eq!(fx.active.calls(), calls + 1);
    assert_eq!(fx.active.bodies_since(calls)[0]["heads"], json!(SHA));
    assert_eq!(old_calls.load(Ordering::SeqCst), 0);
    let activity = with_vault(&fx, |vault| vault.recent_activity(1).expect("activity"));
    assert!(
        activity[0].reason.contains(&format!("Model: {CANDIDATE}")),
        "{}",
        activity[0].reason
    );
}

/// A promoted model is pinned to its version. Another model at its address cannot
/// change the policy: the owner decides.
#[test]
fn a_promoted_model_is_pinned_to_its_version() {
    let fx = fixture();
    // The server has the candidate's head hash under another version.
    fx.active.add(Heads {
        sha: SHA,
        model: OTHER_VERSION,
        answer: opposite_answer,
    });
    let id = register(&fx, "");
    place(&fx, id);
    shadow_rows(&fx, id, 100, 0, 0);
    promote(&fx, id, CANDIDATE).expect("promoted");
    // The impostor is sure about "slow 2", but the broker does not accept its answer.
    assert_eq!(outcome(&run(&fx, SEQUENCE[1])), "Owner approved");
    assert_eq!(outcome(&run(&fx, SEQUENCE[0])), "Owner approved");
    let log = with_vault(&fx, |vault| vault.decision_log().expect("log"));
    let last = &log.last().expect("entry").entry;
    assert!(last.model_facts.is_empty(), "no answer was accepted");
    assert!(
        last.note.contains("not the active version"),
        "{}",
        last.note
    );
}

/// The owner can roll back a promotion. The rollback needs the owner check, and the
/// model before the promotion decides again.
#[test]
fn rollback_returns_to_the_previous_model_and_needs_the_owner_check() {
    let fx = fixture();
    fx.active.add(CANDIDATE_SET);
    let id = register(&fx, "");
    place(&fx, id);
    shadow_rows(&fx, id, 100, 0, 0);
    promote(&fx, id, CANDIDATE).expect("promoted");
    assert_eq!(outcome(&run(&fx, SEQUENCE[0])), "Owner approved");
    let promotion = with_vault(&fx, |vault| {
        vault.active_model().expect("read").expect("some")
    });

    let gate = OwnerGate::new(Arc::clone(&fx.vault), None);
    assert!(
        gate.authorize(
            OwnerAction::RollbackModel {
                activation_id: promotion.id
            },
            OwnerCheck::passphrase(WRONG)
        )
        .is_err()
    );
    let wrong = owner_check(
        &fx.vault,
        OwnerAction::PromoteModel {
            candidate_id: id,
            version: CANDIDATE.to_owned(),
        },
    );
    let refused = with_vault(&fx, |vault| {
        shadow::roll_back(vault, promotion.id, wrong, broker::learning::now())
    })
    .expect_err("a proof for another action");
    assert!(refused.contains("another action"), "{refused}");

    let proof = owner_check(
        &fx.vault,
        OwnerAction::RollbackModel {
            activation_id: promotion.id,
        },
    );
    let rollback = with_vault(&fx, |vault| {
        shadow::roll_back(vault, promotion.id, proof, broker::learning::now())
    })
    .expect("rolled back");
    assert_eq!(rollback.action, ActivationAction::Rollback);
    assert!(rollback.is_default(), "the default model is active again");
    assert_eq!(rollback.heads_sha256, None);
    assert_eq!(rollback.previous_version, CANDIDATE);
    // The default model decides again: sure about "fast", unsure about "slow".
    let before = fx.active.calls();
    assert_eq!(outcome(&run(&fx, SEQUENCE[0])), "Bouncer allowed");
    assert_eq!(fx.active.calls(), before + 1);
    assert!(
        fx.active.bodies_since(before)[0].get("heads").is_none(),
        "the default head set again"
    );
    let state = with_vault(&fx, |vault| {
        vault.candidate(id).expect("read").expect("some").state
    });
    assert_eq!(state, CandidateState::RolledBack);
    let activity = with_vault(&fx, |vault| vault.recent_activity(20).expect("activity"));
    assert!(
        activity
            .iter()
            .any(|entry| entry.operation == "roll back model" && entry.reason.contains(CANDIDATE))
    );
    // Only the newest promotion can be rolled back, once.
    let proof = owner_check(
        &fx.vault,
        OwnerAction::RollbackModel {
            activation_id: promotion.id,
        },
    );
    let again = with_vault(&fx, |vault| {
        shadow::roll_back(vault, promotion.id, proof, broker::learning::now())
    })
    .expect_err("nothing to roll back");
    assert!(again.contains("Not rolled back"), "{again}");
    // The broker keeps the fixture fields alive until here.
    let _ = &fx.broker;
}

/// Plan 0035 unit F: a promotion pins the head hash. Each request names it as `heads`,
/// and a server that no longer has that head set (409) makes the owner decide; it never
/// falls back to the default head set.
#[test]
fn a_promoted_head_set_is_pinned_by_hash() {
    let fx = fixture();
    fx.active.add(CANDIDATE_SET);
    let id = register(&fx, "");
    shadow_rows(&fx, id, 100, 0, 0);
    let refused = promote(&fx, id, CANDIDATE).expect_err("not placed");
    assert!(refused.starts_with("Not promoted."), "{refused}");
    place(&fx, id);
    promote(&fx, id, CANDIDATE).expect("promoted");
    let activation = with_vault(&fx, |vault| {
        vault.active_model().expect("read").expect("some")
    });
    assert_eq!(activation.heads_sha256.as_deref(), Some(SHA));
    assert!(activation.url.is_empty());
    assert!(!activation.is_default());
    // The promoted head set is sure about "slow 2", and its answer names the hash.
    let calls = fx.active.calls();
    assert_eq!(outcome(&run(&fx, SEQUENCE[1])), "Bouncer allowed");
    let sent = fx.active.bodies_since(calls);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0]["heads"], json!(SHA));
    assert!(
        sent[0].get("shadow_heads").is_none(),
        "no candidate in shadow mode after the promotion"
    );
    // The server loses the head set: 409, and the owner decides, also for "fast 1",
    // which the default head set would allow.
    fx.active.forget(SHA);
    assert_eq!(outcome(&run(&fx, SEQUENCE[0])), "Owner approved");
    let log = with_vault(&fx, |vault| vault.decision_log().expect("log"));
    let last = &log.last().expect("entry").entry;
    assert!(last.model_facts.is_empty(), "no answer was accepted");
    assert!(last.note.contains("pinned head set"), "{}", last.note);
}

/// Plan 0035 unit F: a candidate row from before schema 29 (an `http://127.0.0.1:8775`
/// address, origin "local", no upload mark) still works. The broker never asks its old
/// address. It records no answer until its head file is on the host, then rides as
/// `shadow_heads`, and its promotion pins its head hash.
#[test]
fn an_old_candidate_row_with_an_8775_url_still_works_after_29() {
    let fx = fixture();
    fx.active.add(CANDIDATE_SET);
    // The listener stands in for the old candidate server on 8775 (no fixed port).
    let (old_url, old_calls) = silent_listener();
    let id = register(&fx, &old_url);
    let record = with_vault(&fx, |vault| {
        vault.candidate(id).expect("read").expect("some")
    });
    assert_eq!(record.origin, apassy::vault::CandidateOrigin::Local);
    assert_eq!(record.uploaded_to, None);
    assert_eq!(decisions(&fx), BASELINE);
    let summary = wait_for_rows(&fx, id, 3);
    assert_eq!((summary.requests, summary.no_answer), (3, 3));
    place(&fx, id);
    let calls = fx.active.calls();
    // Without the run that the owner denies: the candidate answers "run" to it, and the
    // shadow gate keeps a candidate that would allow an owner denial from promotion.
    let placed: Vec<String> = [SEQUENCE[0], SEQUENCE[1], SEQUENCE[3]]
        .iter()
        .map(|script| outcome(&run(&fx, script)))
        .collect();
    assert_eq!(placed, [BASELINE[0], BASELINE[1], BASELINE[3]]);
    assert_eq!(
        shadow_heads(&fx.active.bodies_since(calls)),
        vec![Some(SHA.to_owned()); 2]
    );
    let summary = wait_for_rows(&fx, id, 5);
    assert_eq!((summary.requests, summary.no_answer), (5, 3));
    shadow_rows(&fx, id, 100, 0, 0);
    promote(&fx, id, CANDIDATE).expect("promoted");
    let activation = with_vault(&fx, |vault| {
        vault.active_model().expect("read").expect("some")
    });
    assert_eq!(activation.url, old_url);
    assert_eq!(activation.heads_sha256.as_deref(), Some(SHA));
    assert_eq!(outcome(&run(&fx, SEQUENCE[1])), "Bouncer allowed");
    assert_eq!(
        old_calls.load(Ordering::SeqCst),
        0,
        "the old address is not read"
    );
}

/// The hook of Settings > Agents with a client that the test changes, as a change of
/// the hosting choice changes the client of `ModelServer`.
#[derive(Debug, Default)]
struct SwitchGate {
    client: Mutex<Option<BouncerClient>>,
    asked: AtomicUsize,
}

impl SwitchGate {
    fn set(&self, client: Option<BouncerClient>) {
        *self.client.lock().expect("client") = client;
    }
}

impl ModelGate for SwitchGate {
    fn before_model(&self) -> Result<(), String> {
        Ok(())
    }

    fn bouncer_client(&self) -> Option<BouncerClient> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        self.client.lock().expect("client").clone()
    }
}

/// Plan 0035 unit F: the broker reads the bouncer brain client of the gate for each
/// request, so a change of the host in Settings applies at the next run without a
/// restart. Without a client from the gate, the client of the broker start decides.
#[test]
fn a_hosting_change_applies_at_the_next_run() {
    let gate = Arc::new(SwitchGate::default());
    let fx = fixture_with(Some(Arc::clone(&gate) as Arc<dyn ModelGate>));
    let other = fake_model(Heads {
        sha: SHA_OTHER,
        model: BASE,
        answer: unsure_answer,
    });
    gate.set(Some(brain_client(&fx.active.url)));
    assert_eq!(outcome(&run(&fx, SEQUENCE[0])), "Bouncer allowed");
    assert_eq!((fx.active.calls(), other.calls()), (1, 0));
    // The host changes: the next run asks the new host only.
    gate.set(Some(brain_client(&other.url)));
    assert_eq!(outcome(&run(&fx, SEQUENCE[0])), "Owner approved");
    assert_eq!((fx.active.calls(), other.calls()), (1, 1));
    // A candidate rides to the current host too.
    other.add(CANDIDATE_SET);
    let id = placed_as(&fx, CANDIDATE, SHA);
    assert_eq!(outcome(&run(&fx, SEQUENCE[0])), "Owner approved");
    assert_eq!(
        other.bodies().last().expect("body")["shadow_heads"],
        json!(SHA)
    );
    assert_eq!(fx.active.calls(), 1);
    let summary = wait_for_rows(&fx, id, 1);
    assert_eq!((summary.requests, summary.no_answer), (1, 0));
    // No client from the gate: the client of the broker start.
    gate.set(None);
    assert_eq!(outcome(&run(&fx, SEQUENCE[0])), "Bouncer allowed");
    assert_eq!((fx.active.calls(), other.calls()), (2, 2));
    assert!(gate.asked.load(Ordering::SeqCst) >= 4, "read for each run");
}

/// (ok, command line, purpose) of each labeled case.
fn fixture_cases(path: &str) -> Vec<(bool, String, String)> {
    let text = std::fs::read_to_string(path).expect("fixture");
    text.lines()
        .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
        .map(|line| {
            let parts: Vec<&str> = line.split('\t').collect();
            assert_eq!(parts.len(), 4, "bad case line: {line}");
            (parts[0] == "ok", parts[2].to_owned(), parts[3].to_owned())
        })
        .collect()
}

/// The shadow measurement on this Mac (goal item B9, `docs/operations/fine-tune.md`).
/// The active model is a real model server that has the candidate head set (uploaded
/// with `PUT /v1/heads/<sha256>`); the candidate rides as `shadow_heads`. The requests are the
/// labeled cases of `tests/fixtures/bouncer/independent.tsv`, each once. The simulated
/// owner approves `ok` and denies `risk`. `PATH` has no programs, so no command runs.
/// With `APASSY_SHADOW_ASK=1`, the grant is in "ask" mode: every request waits for the
/// owner, so every request at the model step has an owner decision.
///
/// `APASSY_EVAL_MODEL=http://127.0.0.1:8774 APASSY_CANDIDATE_DIR=<candidate folder>
/// cargo test --locked --release --all-features --test it
/// shadow_mode::shadow_session_on_synthetic_requests -- --ignored --nocapture`
#[test]
#[ignore = "needs a model server with the candidate head set: APASSY_EVAL_MODEL"]
fn shadow_session_on_synthetic_requests() {
    use apassy::broker::shell_risk::command_line_to_argv;
    use std::collections::BTreeMap;

    let active_url = std::env::var("APASSY_EVAL_MODEL").expect("APASSY_EVAL_MODEL");
    let folder =
        PathBuf::from(std::env::var("APASSY_CANDIDATE_DIR").expect("APASSY_CANDIDATE_DIR"));
    let ask_mode = std::env::var("APASSY_SHADOW_ASK").is_ok_and(|value| value == "1");
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(folder.join("manifest.json")).expect("manifest"),
    )
    .expect("json");
    let version = manifest["version"].as_str().expect("version").to_owned();
    let sha = manifest["checkpoint"]["sha256"]
        .as_str()
        .expect("sha")
        .to_owned();

    let dir = TempDir::new().expect("temp dir");
    let project = dir.path().join("project");
    std::fs::create_dir_all(&project).expect("project");
    let project = std::fs::canonicalize(project).expect("canonical");
    let mut vault = Vault::create(&dir.path().join("vault.db"), PASS).expect("create");
    vault.unlock(PASS).expect("unlock");
    let item = vault
        .add(ItemDraft {
            title: "Supabase".to_owned(),
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
        .set_env_binding(item.id, "SUPABASE_SERVICE_KEY", "token")
        .expect("binding");
    let declaration = model_declaration();
    vault
        .set_declaration(item.id, &declaration)
        .expect("declaration");
    let (agent, token) = vault.register_agent("Shadow agent").expect("register");
    let mode = if ask_mode {
        ExecMode::Ask
    } else {
        ExecMode::Bouncer
    };
    vault
        .set_exec_grant(agent.id, item.id, &project.display().to_string(), mode)
        .expect("grant");
    // The upgrade to schema 18 turned an "ask" grant into "Always ask for this agent"
    // (ADR 0025 §3f). A grant is no authority.
    if ask_mode {
        vault
            .add_agent_exception(agent.id, item.id, ExceptionKind::AlwaysAsk)
            .expect("always ask");
    }
    let candidate = vault
        .register_candidate(
            &NewCandidate {
                version: version.clone(),
                url: String::new(),
                checkpoint: folder.join("candidate.safetensors").display().to_string(),
                checkpoint_sha256: sha,
                report: "{}".to_owned(),
            },
            broker::learning::now(),
        )
        .expect("candidate")
        .id;
    vault
        .mark_candidate_uploaded(candidate, Some(THIS_MAC_HOST))
        .expect("placed");
    let shared: SharedVault = Arc::new(Mutex::new(Some(vault)));
    let mut options = BrokerOptions::with_tls(TlsClient::platform().expect("TLS"));
    options.approval_timeout = Duration::from_secs(60);
    options.run_timeout = Duration::from_secs(10);
    options.bouncer = Some(
        BouncerClient::new(&active_url)
            .expect("url")
            .with_timeout(Duration::from_secs(60)),
    );
    let socket = dir.path().join("run").join("broker.sock");
    let broker = broker::start_with(Arc::clone(&shared), &socket, options).expect("broker");

    // `APASSY_SHADOW_CASES` can name another labeled file, for example the training
    // cases for an in-sample check.
    let cases = fixture_cases(
        &std::env::var("APASSY_SHADOW_CASES")
            .unwrap_or_else(|_| "tests/fixtures/bouncer/independent.tsv".to_owned()),
    );
    // The same command can have two labels with two purposes, so the key has both.
    let key = |command: &[String], purpose: &str| {
        format!("{}\u{1e}{}", command.join("\u{1f}"), purpose.trim())
    };
    let labels: BTreeMap<String, bool> = cases
        .iter()
        .map(|(ok, line, purpose)| (key(&command_line_to_argv(line), purpose), *ok))
        .collect();
    let stop = Arc::new(AtomicBool::new(false));
    let owner = {
        let approvals = Arc::clone(broker.approvals());
        let vault = Arc::clone(&shared);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                for pending in approvals.pending() {
                    let ok = labels
                        .get(&key(&pending.command, &pending.purpose))
                        .copied()
                        .unwrap_or(false);
                    if ok {
                        let proof = owner_check(&vault, OwnerAction::ApproveRun(pending));
                        let _ = approvals.approve(proof);
                    } else {
                        approvals.deny(pending.id);
                    }
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        })
    };
    let started = Instant::now();
    for (_, line, purpose) in &cases {
        let response = client::send(
            &socket,
            token.expose(),
            Action::Run {
                access_request_id: None,
                codes: Default::default(),
                items: vec![item.id],
                command: command_line_to_argv(line),
                cwd: project.display().to_string(),
                purpose: purpose.clone(),
                path: Some("/nonexistent-apassy-shadow".to_owned()),
                user_request: Some(purpose.clone()),
            },
        )
        .expect("answer");
        let _ = outcome(&response);
    }
    let seconds = started.elapsed().as_secs_f64();
    // The rows are stored before the broker answers; wait until the count stays.
    let mut last = u32::MAX;
    let summary = loop {
        std::thread::sleep(Duration::from_secs(2));
        let summary = {
            let guard = shared.lock().expect("vault");
            guard
                .as_ref()
                .expect("open")
                .shadow_summary(candidate)
                .expect("summary")
        };
        if summary.requests == last {
            break summary;
        }
        last = summary.requests;
    };
    stop.store(true, Ordering::SeqCst);
    owner.join().expect("owner");
    let log = {
        let guard = shared.lock().expect("vault");
        guard.as_ref().expect("open").decision_log().expect("log")
    };
    // The active model at the model step: its note starts with "Model allowed" when it
    // would run the request. Only owner decisions at the model step count, as for the
    // candidate: model facts and no rule flag.
    let mut base = (0u32, 0u32, 0u32);
    let mut by: BTreeMap<String, u32> = BTreeMap::new();
    for record in &log {
        let entry = &record.entry;
        let key = format!("{} {}", entry.decided_by.as_str(), entry.decision.as_str());
        *by.entry(key).or_insert(0) += 1;
        let model_step = !entry.model_facts.is_empty() && entry.rule_flags.is_empty();
        if entry.decided_by == apassy::vault::DecidedBy::Owner && model_step {
            let runs = entry.note.starts_with("Model allowed");
            let denied = entry.owner_denied();
            base.0 += 1;
            base.1 += u32::from(runs != denied);
            base.2 += u32::from(runs && denied);
        }
    }
    let agreement = &summary.agreement;
    eprintln!(
        "SHADOW mode {} requests {} in {seconds:.1} s; decisions {by:?}",
        if ask_mode { "ask" } else { "bouncer" },
        cases.len()
    );
    eprintln!(
        "SHADOW candidate {version}: model-step requests {}, no answer {}, owner decisions {}, agreed {} ({:.1}%), owner denials it would allow {}, same outcome as the active model {}",
        summary.requests,
        summary.no_answer,
        agreement.shadow_decisions,
        agreement.agreed,
        agreement.agreement().unwrap_or(0.0) * 100.0,
        agreement.allowed_owner_denials,
        summary.same_as_active,
    );
    eprintln!(
        "SHADOW active model on the same owner decisions: {} decisions, agreed {} ({:.1}%), owner denials it would allow {}",
        base.0,
        base.1,
        if base.0 == 0 {
            0.0
        } else {
            f64::from(base.1) * 100.0 / f64::from(base.0)
        },
        base.2
    );
    assert_eq!(
        summary.no_answer, 0,
        "the candidate head set answered every request"
    );
    drop(broker);
}
