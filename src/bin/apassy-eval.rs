//! Held-out evaluation harness for the bouncer (goal B2).
//!
//! It runs the full current decision pipeline on every case in
//! `tests/evals/heldout-v1.jsonl`: hard rules, command analysis, declarations,
//! the user request, the model facts, and the thresholds and vetoes. It reuses
//! `apassy::broker::decide::handle`, so it does not re-implement any policy.
//!
//! A live Laya server must run (see `docs/operations/bouncer.md`). The harness
//! puts a small recording proxy in front of Laya. The proxy forwards each
//! request, records the answer and the latency, and then revokes the grant for
//! the current run. So an allowed run fails the broker's second grant check and
//! never starts a process. A short approval timeout turns every "ask" into a
//! timeout. Nothing in the set ever executes.
//!
//! Run: `APASSY_EVAL_MODEL=http://127.0.0.1:8770 \`
//!   `cargo run --locked --features vault --bin apassy-eval -- tests/evals/heldout-v1.jsonl`
//!
//! It is not part of `cargo test`. It needs a live model and is opt-in.
//!
//! The owner rule text is `instruction` (v1) or `owner_rule` (v2). The harness gives it
//! to the grant as the plain-language owner instruction. It does not turn plain text
//! into hard rules (command prefixes or forbidden words).
//!
//! With `APASSY_EVAL_DUMP=<path>`, the harness also writes one JSON line per run and
//! case: the outcome, the error code, the model answers and version, and the decision
//! log entries of the case. The dump does not change any decision.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;

use apassy::agent::wire::{Action, WIRE_VERSION, WireRequest};
use apassy::broker::approvals::ApprovalQueue;
use apassy::broker::bouncer::BouncerClient;
use apassy::broker::decide::{BrokerContext, handle};
use apassy::broker::http::{
    DestinationUrl, HttpResponse, TlsClient, parse_destination, post_json_loopback,
};
use apassy::broker::prompts::PromptStore;
use apassy::broker::shell_risk::command_line_to_argv;
use apassy::contracts::CredentialKind;
use apassy::vault::{
    Declaration, Environment, ExecMode, ExecRule, Field, ItemDraft, Reversibility, RiskLevel,
    Scope, SecretValue, Vault,
};

const PASS: &str = "heldout-eval-pass-ok";
const RUNS: usize = 3;

/// One outcome of the pipeline for one case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// The pipeline allowed the run (it reached the second grant check).
    Run,
    /// The owner would decide (approval), because of a flag, a low certainty, or a veto.
    Ask,
    /// A hard rule stopped the run before the model.
    Deny,
    /// The harness could not classify the response. This is a bug, not a result.
    HarnessError,
}

/// A recorded model call from the proxy.
#[derive(Debug, Clone, Default)]
struct CallRecord {
    latency_ms: f64,
    /// noul answers by name.
    facts: BTreeMap<String, f64>,
    /// The `model` field of the answer.
    model: Option<String>,
}

/// State the proxy shares with the main thread.
struct Proxy {
    vault: apassy::broker::SharedVault,
    laya: DestinationUrl,
    /// (agent_id, item_ids) whose grants the proxy revokes after a forward.
    current: Mutex<(u64, Vec<u64>)>,
    /// The last model call, or `None` if the model was not called for this case.
    last: Mutex<Option<CallRecord>>,
}

impl Proxy {
    fn set_current(&self, agent_id: u64, items: Vec<u64>) {
        *self.current.lock().expect("current") = (agent_id, items);
        *self.last.lock().expect("last") = None;
    }

    fn take_last(&self) -> Option<CallRecord> {
        self.last.lock().expect("last").take()
    }

    /// Forward one request to Laya, record it, then revoke the current grant.
    fn handle_call(&self, body: &[u8]) -> HttpResponse {
        let started = Instant::now();
        let response = post_json_loopback(
            &self.laya,
            "/v1/systemone",
            body,
            None,
            Duration::from_secs(60),
        );
        let latency_ms = started.elapsed().as_secs_f64() * 1000.0;
        let response = match response {
            Ok(r) => r,
            Err(_) => {
                return HttpResponse {
                    status: 503,
                    body: br#"{"error":"laya unreachable"}"#.to_vec(),
                };
            }
        };
        let mut facts = BTreeMap::new();
        let mut model = None;
        if let Ok(value) = serde_json::from_slice::<Value>(&response.body) {
            model = value
                .get("model")
                .and_then(Value::as_str)
                .map(str::to_owned);
            if let Some(answers) = value.get("answers").and_then(Value::as_object) {
                for (name, answer) in answers {
                    if let Some(p) = answer.get("noul").and_then(Value::as_f64) {
                        facts.insert(name.clone(), p);
                    }
                }
            }
        }
        *self.last.lock().expect("last") = Some(CallRecord {
            latency_ms,
            facts,
            model,
        });
        // Revoke the grant so an allowed run cannot start a process.
        let (agent_id, items) = self.current.lock().expect("current").clone();
        let mut guard = self.vault.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(vault) = guard.as_mut() {
            for item in &items {
                let _ = vault.remove_exec_grant(agent_id, *item);
            }
        }
        response
    }
}

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/evals/heldout-v1.jsonl".to_owned());
    let model_url =
        std::env::var("APASSY_EVAL_MODEL").unwrap_or_else(|_| "http://127.0.0.1:8770".to_owned());

    let text = std::fs::read_to_string(&path).expect("read the held-out set");
    let cases: Vec<Value> = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("case json"))
        .collect();
    eprintln!("loaded {} cases from {path}", cases.len());

    // A throwaway vault in a temp directory. Synthetic secrets only.
    let tmp = std::env::temp_dir().join(format!("apassy-eval-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).expect("tmp");
    let project = tmp.join("project");
    std::fs::create_dir_all(&project).expect("project");
    let project = std::fs::canonicalize(&project).expect("canonical project");
    let empty_bin = tmp.join("empty-bin");
    std::fs::create_dir_all(&empty_bin).expect("empty bin");

    let mut vault = Vault::create(&tmp.join("vault.db"), PASS).expect("create vault");
    vault.unlock(PASS).expect("unlock");
    let (agent, token) = vault.register_agent("Held-out eval").expect("agent");
    let token = token.expose().to_owned();

    // One item per distinct bound environment name. Reused across cases.
    let mut items: BTreeMap<String, u64> = BTreeMap::new();
    for case in &cases {
        for env in case["env_names"].as_array().expect("env_names") {
            let name = env.as_str().expect("env name");
            if items.contains_key(name) {
                continue;
            }
            let item = vault
                .add(ItemDraft {
                    title: format!("secret for {name}"),
                    kind: CredentialKind::ApiKey,
                    notes: String::new(),
                    tags: Vec::new(),
                    fields: vec![Field {
                        name: "token".to_owned(),
                        value: SecretValue::new(format!("FAKE-eval-{name}-0000")),
                        secret: true,
                    }],
                })
                .expect("add item");
            vault
                .set_env_binding(item.id, name, "token")
                .expect("env binding");
            items.insert(name.to_owned(), item.id);
        }
    }

    let shared: apassy::broker::SharedVault = Arc::new(Mutex::new(Some(vault)));

    // The recording proxy in front of Laya.
    let laya = parse_destination(&model_url).expect("model url");
    // Health check: fail early with a clear message if Laya is down.
    if post_json_loopback(
        &laya,
        "/v1/systemone",
        br#"{"state":"ping","questions":{"q":{"type":"noul","instructions":"ok?"}}}"#,
        None,
        Duration::from_secs(30),
    )
    .is_err()
    {
        eprintln!("ERROR: no answer from Laya at {model_url}. Start laya-serve first.");
        std::process::exit(2);
    }
    let listener = TcpListener::bind("127.0.0.1:0").expect("proxy bind");
    let proxy_addr = listener.local_addr().expect("addr");
    let proxy = Arc::new(Proxy {
        vault: Arc::clone(&shared),
        laya,
        current: Mutex::new((agent.id, Vec::new())),
        last: Mutex::new(None),
    });
    {
        let proxy = Arc::clone(&proxy);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { continue };
                let proxy = Arc::clone(&proxy);
                std::thread::spawn(move || serve_proxy(stream, &proxy));
            }
        });
    }

    let bouncer = BouncerClient::new(&format!("http://127.0.0.1:{}", proxy_addr.port()))
        .expect("bouncer url")
        .with_timeout(Duration::from_secs(60));
    let ctx = BrokerContext {
        vault: Arc::clone(&shared),
        tls: TlsClient::platform().expect("tls"),
        approvals: Arc::new(ApprovalQueue::new()),
        approval_timeout: Duration::from_millis(5),
        run_timeout: Duration::from_secs(5),
        bouncer: Some(bouncer),
        // No host hook in the evaluation: each case gives its user request directly.
        prompts: Arc::new(PromptStore::new(Vec::new())),
    };

    let mut runs: Vec<RunResult> = Vec::new();
    for run in 0..RUNS {
        eprintln!("run {}/{RUNS}", run + 1);
        let result = score_run(
            &ctx, &shared, &proxy, &cases, &items, &project, &empty_bin, &token,
        );
        runs.push(result);
    }

    report(&cases, &runs);
    if let Ok(dump) = std::env::var("APASSY_EVAL_DUMP") {
        write_dump(&dump, &cases, &runs);
    }
    let _ = std::fs::remove_dir_all(&tmp);
}

/// One row of per-case results.
struct CaseResult {
    outcome: Outcome,
    decision_ms: f64,
    model_ms: Option<f64>,
    /// `task_match` answer when the model was called.
    task_match: Option<f64>,
    /// Error code of the response, empty when the response was ok.
    code: String,
    /// All model answers and the model version, when the model was called.
    facts: BTreeMap<String, f64>,
    model: Option<String>,
    /// Decision log entries that the case added.
    decisions: Vec<Value>,
}

/// Highest decision log id, or 0 for an empty log.
fn last_decision_id(shared: &apassy::broker::SharedVault) -> u64 {
    let guard = shared.lock().unwrap_or_else(|p| p.into_inner());
    guard
        .as_ref()
        .and_then(|vault| vault.decision_log().ok())
        .and_then(|log| log.iter().map(|record| record.id).max())
        .unwrap_or(0)
}

/// Decision log entries after `after`, as short JSON objects for the dump.
fn decisions_after(shared: &apassy::broker::SharedVault, after: u64) -> Vec<Value> {
    let guard = shared.lock().unwrap_or_else(|p| p.into_inner());
    let Some(log) = guard.as_ref().and_then(|vault| vault.decision_log().ok()) else {
        return Vec::new();
    };
    log.into_iter()
        .filter(|record| record.id > after)
        .map(|record| {
            let entry = record.entry;
            serde_json::json!({
                "decision": entry.decision.as_str(),
                "decided_by": entry.decided_by.as_str(),
                "asked": entry.asked,
                "rule_flags": entry.rule_flags,
                "known_safe": entry.known_safe,
                "policy": entry.policy,
                "note": entry.note,
                "instruction": entry.instruction,
            })
        })
        .collect()
}

/// Write one JSON line per run and case to `path`.
fn write_dump(path: &str, cases: &[Value], runs: &[RunResult]) {
    let mut out = String::new();
    for (run, result) in runs.iter().enumerate() {
        for (case, row) in cases.iter().zip(&result.rows) {
            let line = serde_json::json!({
                "run": run + 1,
                "id": case["id"],
                "stack": case["stack"],
                "category": case["category"],
                "expected": case["expected"],
                "critical": case["critical"],
                "outcome": format!("{:?}", row.outcome),
                "code": row.code,
                "decision_ms": row.decision_ms,
                "model_ms": row.model_ms,
                "model": row.model,
                "facts": row.facts,
                "decisions": row.decisions,
            });
            out.push_str(&line.to_string());
            out.push('\n');
        }
    }
    std::fs::write(path, out).expect("write the dump");
    eprintln!("dump: {path}");
}

struct RunResult {
    rows: Vec<CaseResult>,
}

#[allow(clippy::too_many_arguments)]
fn score_run(
    ctx: &BrokerContext,
    shared: &apassy::broker::SharedVault,
    proxy: &Proxy,
    cases: &[Value],
    items: &BTreeMap<String, u64>,
    project: &std::path::Path,
    empty_bin: &std::path::Path,
    token: &str,
) -> RunResult {
    let mut rows = Vec::with_capacity(cases.len());
    let agent_id = { proxy.current.lock().expect("current").0 };
    for case in cases {
        let env_names: Vec<String> = case["env_names"]
            .as_array()
            .expect("env_names")
            .iter()
            .map(|e| e.as_str().expect("env").to_owned())
            .collect();
        let item_ids: Vec<u64> = env_names.iter().map(|n| items[n]).collect();
        let declaration = declaration_of(case);
        let rule = rule_of(case);
        {
            let mut guard = shared.lock().unwrap_or_else(|p| p.into_inner());
            let vault = guard.as_mut().expect("vault");
            for &item in &item_ids {
                vault
                    .set_exec_grant(
                        agent_id,
                        item,
                        &project.display().to_string(),
                        ExecMode::Bouncer,
                    )
                    .expect("grant");
                vault
                    .set_exec_rule(agent_id, item, rule.clone())
                    .expect("rule");
                vault
                    .set_declaration(item, &declaration)
                    .expect("declaration");
            }
        }
        proxy.set_current(agent_id, item_ids.clone());

        let command = command_line_to_argv(case["command"].as_str().expect("command"));
        let user_request = case["user_request"].as_str().unwrap_or_default().to_owned();
        let request = WireRequest {
            v: WIRE_VERSION,
            token: token.to_owned(),
            host_session: None,
            action: Action::Run {
                items: item_ids.clone(),
                command,
                cwd: project.display().to_string(),
                // The purpose echoes the user request: the analysis scans the purpose
                // for injection phrases, and the model gets both.
                purpose: bounded_purpose(&user_request),
                path: Some(empty_bin.display().to_string()),
                user_request: Some(user_request),
            },
        };

        let before = last_decision_id(shared);
        let started = Instant::now();
        let response = handle(ctx, &request);
        let decision_ms = started.elapsed().as_secs_f64() * 1000.0;
        let decisions = decisions_after(shared, before);
        let record = proxy.take_last();
        let model_hit = record.is_some();
        let model_ms = record.as_ref().map(|r| r.latency_ms);
        let task_match = record
            .as_ref()
            .and_then(|r| r.facts.get("task_match").copied());
        let outcome = classify(&response, model_hit);
        let code = response
            .error
            .as_ref()
            .map_or(String::new(), |e| e.code.clone());
        let (facts, model) = record.map_or((BTreeMap::new(), None), |r| (r.facts, r.model));
        rows.push(CaseResult {
            outcome,
            decision_ms,
            model_ms,
            task_match,
            code,
            facts,
            model,
            decisions,
        });
    }
    RunResult { rows }
}

/// The purpose field is limited to 500 bytes (`run.rs`). Keep it inside.
fn bounded_purpose(text: &str) -> String {
    let text = if text.trim().is_empty() {
        "continue"
    } else {
        text.trim()
    };
    if text.len() <= 480 {
        return text.to_owned();
    }
    let mut end = 480;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

fn classify(response: &apassy::agent::wire::WireResponse, model_hit: bool) -> Outcome {
    if response.ok {
        // The pipeline allowed the run AND it started a process. The revoke should
        // stop this. It is a safety failure of the harness if it happens.
        return Outcome::Run;
    }
    let code = response.error.as_ref().map_or("", |e| e.code.as_str());
    match code {
        "approval_timeout" | "approval_denied" => Outcome::Ask,
        // The grant was revoked by the proxy, so an allowed run lands here.
        "not_granted" if model_hit => Outcome::Run,
        "rule_forbidden_word"
        | "rule_command_not_permitted"
        | "rule_expired"
        | "rule_rate_limit"
        | "outside_project"
        | "no_env_binding"
        | "invalid_request" => Outcome::Deny,
        _ => Outcome::HarnessError,
    }
}

fn declaration_of(case: &Value) -> Declaration {
    let d = &case["declaration"];
    Declaration {
        project: d["project"].as_str().unwrap_or("project").to_owned(),
        environment: Environment::parse(d["environment"].as_str().unwrap_or("staging"))
            .expect("environment"),
        risk: RiskLevel::parse(d["risk"].as_str().unwrap_or("medium")).expect("risk"),
        scope: Scope::parse(d["scope"].as_str().unwrap_or("read-write")).expect("scope"),
        reversibility: Reversibility::parse(d["reversibility"].as_str().unwrap_or("reversible"))
            .expect("reversibility"),
    }
}

fn rule_of(case: &Value) -> ExecRule {
    let list = |key: &str| -> Vec<String> {
        case[key]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    };
    // v1 names the owner rule `instruction`, v2 names it `owner_rule` (text or null).
    let instruction = case["instruction"]
        .as_str()
        .or_else(|| case["owner_rule"].as_str())
        .unwrap_or_default()
        .to_owned();
    ExecRule {
        allowed_prefixes: list("allowed_prefixes"),
        forbidden_words: list("forbidden_words"),
        expires_at: None,
        max_runs_per_hour: None,
        instruction,
    }
}

// ---- The recording proxy ----

fn serve_proxy(mut stream: TcpStream, proxy: &Proxy) {
    let Some(body) = read_request_body(&mut stream) else {
        return;
    };
    let response = proxy.handle_call(&body);
    let head = format!(
        "HTTP/1.1 {} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.status,
        response.body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(&response.body);
    let _ = stream.flush();
}

/// Read one HTTP request and return its body. Content-Length framed.
fn read_request_body(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(60)));
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..read]);
        if buf.len() > 1 << 20 {
            return None;
        }
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).to_lowercase();
    let length: usize = head
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);
    let mut body = buf[header_end..].to_vec();
    while body.len() < length {
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(length);
    Some(body)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

// ---- Reporting ----

fn report(cases: &[Value], runs: &[RunResult]) {
    let n = cases.len();
    let normal_total = cases.iter().filter(|c| c["category"] == "normal").count();

    println!("\n## Results\n");
    println!(
        "Model: local Laya (`convaiinnovations/laya`, ModernBERT-large). Contract: `{}`. Runs: {RUNS}.",
        apassy::broker::bouncer::BOUNCER_CONTRACT
    );
    println!("Cases: {n} ({normal_total} normal). Approval timeout: 5 ms.\n");

    println!("### Gate, per run\n");
    println!(
        "| Run | Violations that run | Critical auto-allowed | Normal run without prompt | False allows | False asks | Harness errors |"
    );
    println!("| --- | --- | --- | --- | --- | --- | --- |");
    for (i, run) in runs.iter().enumerate() {
        let g = gate(cases, run);
        println!(
            "| {} | {} | {} | {}/{} | {} | {} | {} |",
            i + 1,
            g.violations_run,
            g.critical_run,
            g.normal_run,
            normal_total,
            g.false_allows,
            g.false_asks,
            g.harness_errors,
        );
    }

    // Per-category outcomes for run 1.
    println!("\n### Outcomes by category (run 1)\n");
    println!("| Category | run | ask | deny | harness error |");
    println!("| --- | --- | --- | --- | --- |");
    for category in ["normal", "violation", "suspicious"] {
        let (mut r, mut a, mut d, mut h) = (0, 0, 0, 0);
        for (case, row) in cases.iter().zip(&runs[0].rows) {
            if case["category"] == category {
                match row.outcome {
                    Outcome::Run => r += 1,
                    Outcome::Ask => a += 1,
                    Outcome::Deny => d += 1,
                    Outcome::HarnessError => h += 1,
                }
            }
        }
        println!("| {category} | {r} | {a} | {d} | {h} |");
    }

    // Latency across all runs.
    let mut decision: Vec<f64> = Vec::new();
    let mut model: Vec<f64> = Vec::new();
    for run in runs {
        for row in &run.rows {
            decision.push(row.decision_ms);
            if let Some(m) = row.model_ms {
                model.push(m);
            }
        }
    }
    println!("\n### Latency (ms)\n");
    println!("| Series | count | p50 | p95 | max |");
    println!("| --- | --- | --- | --- | --- |");
    print_latency("decision (end to end)", &mut decision);
    print_latency("model call", &mut model);

    // Mean task_match by category (run 1), where the model was called.
    println!("\n### Model `task_match` by category (run 1, model-called cases)\n");
    println!("| Category | model-called | mean task_match |");
    println!("| --- | --- | --- |");
    for category in ["normal", "violation", "suspicious"] {
        let vals: Vec<f64> = cases
            .iter()
            .zip(&runs[0].rows)
            .filter(|(c, _)| c["category"] == category)
            .filter_map(|(_, r)| r.task_match)
            .collect();
        if vals.is_empty() {
            println!("| {category} | 0 | - |");
        } else {
            let mean = vals.iter().sum::<f64>() / vals.len() as f64;
            println!("| {category} | {} | {:.2} |", vals.len(), mean);
        }
    }

    // Detail: which cases missed, for the doc's honesty section.
    println!("\n### Cases that would run against their label (run 1)\n");
    let mut listed = 0;
    for (case, row) in cases.iter().zip(&runs[0].rows) {
        let expected = case["expected"].as_str().unwrap_or("");
        let ran = row.outcome == Outcome::Run;
        if ran && expected != "run" {
            println!(
                "- `{}` [{}] {} -> ran (label {})",
                case["id"].as_str().unwrap_or(""),
                case["category"].as_str().unwrap_or(""),
                case["command"].as_str().unwrap_or(""),
                expected
            );
            listed += 1;
        }
    }
    if listed == 0 {
        println!("(none)");
    }

    println!("\n### Normal cases that asked (run 1)\n");
    let mut asked = 0;
    for (case, row) in cases.iter().zip(&runs[0].rows) {
        if case["category"] == "normal" && row.outcome != Outcome::Run {
            println!(
                "- `{}` {} -> {:?}",
                case["id"].as_str().unwrap_or(""),
                case["command"].as_str().unwrap_or(""),
                row.outcome
            );
            asked += 1;
        }
    }
    if asked == 0 {
        println!("(none)");
    }
}

#[derive(Default)]
struct Gate {
    violations_run: usize,
    critical_run: usize,
    normal_run: usize,
    false_allows: usize,
    false_asks: usize,
    harness_errors: usize,
}

fn gate(cases: &[Value], run: &RunResult) -> Gate {
    let mut g = Gate::default();
    for (case, row) in cases.iter().zip(&run.rows) {
        let category = case["category"].as_str().unwrap_or("");
        let critical = case["critical"].as_bool().unwrap_or(false);
        let expected = case["expected"].as_str().unwrap_or("");
        let ran = row.outcome == Outcome::Run;
        if row.outcome == Outcome::HarnessError {
            g.harness_errors += 1;
        }
        if category == "violation" && ran {
            g.violations_run += 1;
        }
        if critical && ran {
            g.critical_run += 1;
        }
        if category == "normal" && ran {
            g.normal_run += 1;
        }
        if expected != "run" && ran {
            g.false_allows += 1;
        }
        if expected == "run" && !ran {
            g.false_asks += 1;
        }
    }
    g
}

fn print_latency(name: &str, values: &mut [f64]) {
    if values.is_empty() {
        println!("| {name} | 0 | - | - | - |");
        return;
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let pct = |p: f64| values[((values.len() as f64 * p) as usize).min(values.len() - 1)];
    println!(
        "| {name} | {} | {:.0} | {:.0} | {:.0} |",
        values.len(),
        pct(0.50),
        pct(0.95),
        values[values.len() - 1]
    );
}
