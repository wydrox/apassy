#![cfg(feature = "vault")]

//! Replay measurement for learning (goal items B3 and B5, `docs/operations/learning.md`).
//!
//! A chronological request sequence goes through the real decision code with learning:
//! the command analysis, the pattern lookup, the bouncer policy, the decision log, and
//! the pattern update (`broker::replay`). The labeled sets in `tests/fixtures/bouncer/`
//! are the simulated owner: `ok` is an approval, `risk` is a denial. The frozen held-out
//! set in `tests/evals/` is not used.
//!
//! - `fixture_replay_learns_and_never_allows_a_denied_request` runs without a model. The
//!   model step then always asks, so the ask rate falls only by remembered patterns.
//! - `fixture_replay_with_model` asks a local Laya model (`APASSY_EVAL_MODEL`).
//! - `real_commands_replay` reads real agent commands from a local file
//!   (`APASSY_REAL_CTX`). The file stays outside the repository.

use std::collections::BTreeMap;
use std::path::PathBuf;

use apassy::broker::bouncer::{BouncerClient, BouncerRequest, BouncerVerdict, Thresholds};
use apassy::broker::calibration::{self, Proposal};
use apassy::broker::replay::{ReplayReport, ReplayRequest, ReplaySetup, replay};
use apassy::broker::shell_risk::{analyze, command_line_to_argv};
use apassy::vault::{Declaration, Environment, Reversibility, RiskLevel, Scope, Vault};
use tempfile::TempDir;

const PASS: &str = "learning-replay-pass";
/// 2026-08-01T00:00:00Z.
const START: u64 = 1_785_542_400;
const REQUESTS: usize = 3000;
const WINDOW: usize = 300;

struct Case {
    ok: bool,
    line: String,
    purpose: String,
}

/// FNV-1a. Stable across runs and platforms.
fn fnv(text: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in text.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

/// SplitMix64: a small deterministic generator.
struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

fn cases() -> Vec<Case> {
    let mut all = Vec::new();
    for text in [
        include_str!("fixtures/bouncer/cases.tsv"),
        include_str!("fixtures/bouncer/independent.tsv"),
    ] {
        for line in text
            .lines()
            .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
        {
            let parts: Vec<&str> = line.split('\t').collect();
            assert_eq!(parts.len(), 4, "bad case line: {line}");
            all.push(Case {
                ok: parts[0] == "ok",
                line: parts[2].to_owned(),
                purpose: parts[3].to_owned(),
            });
        }
    }
    // A stable order that does not follow the files: the rank of each case.
    all.sort_by_key(|case| fnv(&format!("{}\t{}", case.line, case.purpose)));
    all
}

/// A chronological sequence with repetition. Real agent traffic repeats: 31 templates
/// covered 50% of 6215 real commands (ADR 0009). Here a case of rank `r` has the weight
/// `1 / (r + 1)`. Requests are 1 to 30 minutes apart, so the sequence covers about
/// 32 days and the 30-day expiry can act.
fn sequence(cases: &[Case], count: usize) -> Vec<ReplayRequest> {
    let weights: Vec<f64> = (0..cases.len())
        .map(|rank| 1.0 / (rank as f64 + 1.0))
        .collect();
    let total: f64 = weights.iter().sum();
    let mut random = Random(0x0a55_2026);
    let mut at = START;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let mut pick = (random.below(1_000_000) as f64 / 1_000_000.0) * total;
        let mut index = cases.len() - 1;
        for (rank, weight) in weights.iter().enumerate() {
            if pick < *weight {
                index = rank;
                break;
            }
            pick -= weight;
        }
        let case = &cases[index];
        at += 60 + random.below(1740);
        out.push(ReplayRequest {
            at,
            command: command_line_to_argv(&case.line),
            cwd_rel: ".".to_owned(),
            purpose: case.purpose.clone(),
            // The labeled cases have a purpose, not a separate user request. The purpose
            // plays the user request, as in `tests/bouncer_eval.rs`.
            user_request: case.purpose.clone(),
            owner_approves: case.ok,
        });
    }
    out
}

fn setup(learning: bool, window: usize) -> ReplaySetup {
    ReplaySetup {
        project_dir: PathBuf::from("/work/odealo"),
        declaration: Declaration {
            project: "odealo".to_owned(),
            environment: Environment::Staging,
            risk: RiskLevel::Medium,
            scope: Scope::ReadWrite,
            reversibility: Reversibility::Reversible,
        },
        env_name: "SUPABASE_SERVICE_KEY".to_owned(),
        instruction: String::new(),
        learning,
        window,
    }
}

fn new_vault(dir: &TempDir, name: &str) -> Vault {
    let mut vault = Vault::create(&dir.path().join(name), PASS).expect("create");
    vault.unlock(PASS).expect("unlock");
    vault
}

fn print(name: &str, report: &ReplayReport) {
    eprintln!(
        "{name}: {} requests, asked {} ({:.1}%), rule flags {}, model allowed {}, pattern allowed {}, owner approved {} + remembered {}, denied {}",
        report.requests,
        report.asked,
        report.ask_rate() * 100.0,
        report.flagged,
        report.model_allowed,
        report.pattern_allowed,
        report.owner_approved,
        report.owner_remembered,
        report.owner_denied,
    );
    eprintln!(
        "{name}: patterns active {}, learning {}, blocked {}; denied then allowed {}; final denied allowed {}; label risk allowed without the owner {}",
        report.patterns_active,
        report.patterns_learning,
        report.patterns_blocked,
        report.denied_then_allowed.len(),
        report.final_denied_allowed.len(),
        report.unwanted_allowed.len(),
    );
    let curve: Vec<String> = report
        .windows
        .iter()
        .map(|window| format!("{:.0}%", window.ask_rate() * 100.0))
        .collect();
    eprintln!("{name}: ask rate per window: {}", curve.join(" "));
}

fn print_proposal(name: &str, proposal: &Proposal) {
    eprintln!(
        "{name}: calibration {:.2} -> {:.2}, valid {}, owner decisions {} (denials {}), fit owner decisions at the model step {}, held-out ask rate {:.1}% -> {:.1}%, held-out misses {}, all past decisions: denied allowed {}. {}",
        proposal.current,
        proposal.proposed,
        proposal.valid,
        proposal.owner_decisions,
        proposal.owner_denials,
        proposal.fit_owner_decisions,
        proposal.held_out_before.ask_rate() * 100.0,
        proposal.held_out_after.ask_rate() * 100.0,
        proposal.held_out_misses(),
        proposal.all_after.denied_allowed,
        proposal.reason,
    );
}

fn no_model(_: &BouncerRequest) -> BouncerVerdict {
    BouncerVerdict::Unavailable("no model in this replay".to_owned())
}

/// Both invariants of goal item B3: no request that the owner denied runs without the
/// owner later, and the final state still asks for each of them.
fn assert_no_denial_became_an_allowance(report: &ReplayReport) {
    assert!(
        report.denied_then_allowed.is_empty(),
        "denied then allowed: {:#?}",
        report.denied_then_allowed
    );
    assert!(
        report.final_denied_allowed.is_empty(),
        "the final state allows a denied request: {:#?}",
        report.final_denied_allowed
    );
}

#[test]
fn fixture_replay_learns_and_never_allows_a_denied_request() {
    let cases = cases();
    assert!(cases.len() >= 250, "{}", cases.len());
    let requests = sequence(&cases, REQUESTS);
    let dir = TempDir::new().expect("dir");

    let mut before = new_vault(&dir, "before.db");
    let baseline =
        replay(&mut before, &setup(false, WINDOW), &requests, &mut no_model).expect("baseline");
    print("fixtures, no learning", &baseline);

    let mut after = new_vault(&dir, "after.db");
    let learned =
        replay(&mut after, &setup(true, WINDOW), &requests, &mut no_model).expect("learning");
    print("fixtures, learning", &learned);

    assert_eq!(baseline.requests, REQUESTS);
    assert_eq!(
        baseline.asked, REQUESTS,
        "without a model, every request asks"
    );
    assert_no_denial_became_an_allowance(&learned);
    assert!(
        learned.unwanted_allowed.is_empty(),
        "a request with a denial label ran without the owner: {:#?}",
        learned.unwanted_allowed
    );
    assert!(learned.pattern_allowed > 0);
    assert!(learned.ask_rate() < baseline.ask_rate());
    let first = learned.windows.first().expect("windows").ask_rate();
    let last = learned.windows.last().expect("windows").ask_rate();
    assert!(
        last < first,
        "the ask rate falls over time: {first} -> {last}"
    );

    // The decision log of the replay has every decision. Without model answers, there
    // is no calibration proposal.
    let log = after.decision_log().expect("log");
    assert_eq!(log.len(), REQUESTS);
    let proposal = calibration::propose(&log, Thresholds::default());
    print_proposal("fixtures, learning", &proposal);
    assert!(!proposal.valid);
}

/// An active pattern allows a new variant that the owner did not see. One denial stops
/// the pattern for good. This is the known limit of patterns: they act on requests that
/// the owner never saw. The invariant is about denied requests.
#[test]
fn a_denial_blocks_a_pattern_and_later_approvals_cannot_open_it() {
    let dir = TempDir::new().expect("dir");
    let step = |at: u64, limit: &str, ok: bool| ReplayRequest {
        at,
        command: vec![
            "npx".to_owned(),
            "vitest".to_owned(),
            "run".to_owned(),
            format!("src/lib/{limit}.test.ts"),
        ],
        cwd_rel: ".".to_owned(),
        purpose: "Run the tests.".to_owned(),
        user_request: "Fix the failing tests.".to_owned(),
        owner_approves: ok,
    };
    // Two approvals, then a denial, then approvals: the pattern never runs alone.
    let blocked: Vec<ReplayRequest> = [
        ("a", true),
        ("b", true),
        ("c", false),
        ("d", true),
        ("e", true),
        ("f", true),
        ("c", true),
    ]
    .iter()
    .enumerate()
    .map(|(index, (name, ok))| step(START + index as u64 * 60, name, *ok))
    .collect();
    let mut vault = new_vault(&dir, "blocked.db");
    let report = replay(&mut vault, &setup(true, 10), &blocked, &mut no_model).expect("replay");
    assert_eq!(report.asked, blocked.len(), "every request asks");
    assert_eq!(report.patterns_blocked, 1);
    assert_no_denial_became_an_allowance(&report);

    // Three approvals first: the pattern is active. A variant with a denial label then
    // runs without the owner. The owner never saw it, so it is a miss, not a denied
    // request that became an allowance.
    let active: Vec<ReplayRequest> = [("a", true), ("b", true), ("c", true), ("x", false)]
        .iter()
        .enumerate()
        .map(|(index, (name, ok))| step(START + index as u64 * 60, name, *ok))
        .collect();
    let mut vault = new_vault(&dir, "active.db");
    let report = replay(&mut vault, &setup(true, 10), &active, &mut no_model).expect("replay");
    assert_eq!(report.pattern_allowed, 1);
    assert_eq!(report.unwanted_allowed.len(), 1);
    assert_no_denial_became_an_allowance(&report);

    // After 30 idle days, the pattern expired. The next request asks again.
    let mut expired = active[..3].to_vec();
    expired.push(step(START + 31 * 86_400, "y", true));
    let mut vault = new_vault(&dir, "expired.db");
    let report = replay(&mut vault, &setup(true, 10), &expired, &mut no_model).expect("replay");
    assert_eq!(report.pattern_allowed, 0);
    assert_eq!(report.asked, 4);
}

/// A model for a replay: a local Laya with a cache, so a repeated request asks once.
fn laya_model(url: &str) -> impl FnMut(&BouncerRequest) -> BouncerVerdict + use<> {
    let client = BouncerClient::new(url)
        .expect("url")
        .with_timeout(std::time::Duration::from_secs(60));
    let mut cache: BTreeMap<(String, String, String), BouncerVerdict> = BTreeMap::new();
    move |request: &BouncerRequest| {
        let key = (
            request.command.clone(),
            request.user_request.clone(),
            request.purpose.clone(),
        );
        cache
            .entry(key)
            .or_insert_with(|| client.evaluate(request))
            .clone()
    }
}

#[test]
#[ignore = "needs a local laya-serve; set APASSY_EVAL_MODEL"]
fn fixture_replay_with_model() {
    let Ok(url) = std::env::var("APASSY_EVAL_MODEL") else {
        panic!("APASSY_EVAL_MODEL is not set");
    };
    let requests = sequence(&cases(), REQUESTS);
    let dir = TempDir::new().expect("dir");
    let mut model = laya_model(&url);
    let mut before = new_vault(&dir, "before.db");
    let baseline =
        replay(&mut before, &setup(false, WINDOW), &requests, &mut model).expect("baseline");
    print("fixtures + model, no learning", &baseline);
    let mut after = new_vault(&dir, "after.db");
    let learned = replay(&mut after, &setup(true, WINDOW), &requests, &mut model).expect("learn");
    print("fixtures + model, learning", &learned);
    // Synthetic cases: the requests with the `risk` label that the rules and the model
    // let run without the owner.
    let mut missed = learned.unwanted_allowed.clone();
    missed.sort();
    missed.dedup();
    eprintln!("fixtures + model: risk label allowed without the owner: {missed:#?}");
    assert_no_denial_became_an_allowance(&learned);
    let proposal = calibration::propose(&after.decision_log().expect("log"), Thresholds::default());
    print_proposal("fixtures + model", &proposal);
    assert_eq!(proposal.all_after.denied_allowed, 0, "{proposal:?}");
}

/// Real agent commands in time order, from a local JSON file:
/// `[{"at": 1790000000, "cmd": "...", "cwd_rel": ".", "user_request": "..."}]`.
/// The simulated owner denies a request with a rule flag and approves the others. With
/// `APASSY_EVAL_MODEL`, the replay also asks a local Laya model.
#[test]
#[ignore = "needs APASSY_REAL_CTX"]
fn real_commands_replay() {
    let Ok(path) = std::env::var("APASSY_REAL_CTX") else {
        panic!("APASSY_REAL_CTX is not set");
    };
    let rows: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(path).expect("read")).expect("json");
    let window = std::env::var("APASSY_REPLAY_WINDOW")
        .ok()
        .and_then(|text| text.parse().ok())
        .unwrap_or(500);
    // The first `APASSY_REPLAY_LIMIT` requests, in time order. A model replay of all
    // requests takes hours.
    let limit = std::env::var("APASSY_REPLAY_LIMIT")
        .ok()
        .and_then(|text| text.parse().ok())
        .unwrap_or(usize::MAX);
    let env_names = vec!["SUPABASE_SERVICE_KEY".to_owned()];
    let requests: Vec<ReplayRequest> = rows
        .iter()
        .take(limit)
        .map(|row| {
            let line = row["cmd"].as_str().unwrap_or_default();
            let command = command_line_to_argv(line);
            let flagged = !analyze(&command, "", &env_names).flags.is_empty();
            ReplayRequest {
                at: row["at"].as_u64().unwrap_or(START),
                command,
                cwd_rel: row["cwd_rel"].as_str().unwrap_or(".").to_owned(),
                purpose: String::new(),
                user_request: row["user_request"].as_str().unwrap_or_default().to_owned(),
                owner_approves: !flagged,
            }
        })
        .collect();
    let dir = TempDir::new().expect("dir");
    let mut model: Box<dyn FnMut(&BouncerRequest) -> BouncerVerdict> =
        match std::env::var("APASSY_EVAL_MODEL") {
            Ok(url) => Box::new(laya_model(&url)),
            Err(_) => Box::new(no_model),
        };
    let mut before = new_vault(&dir, "before.db");
    let baseline =
        replay(&mut before, &setup(false, window), &requests, &mut *model).expect("baseline");
    print("real, no learning", &baseline);
    let mut after = new_vault(&dir, "after.db");
    let learned =
        replay(&mut after, &setup(true, window), &requests, &mut *model).expect("learning");
    print("real, learning", &learned);
    assert_no_denial_became_an_allowance(&learned);
    let proposal = calibration::propose(&after.decision_log().expect("log"), Thresholds::default());
    print_proposal("real", &proposal);
    assert_eq!(proposal.all_after.denied_allowed, 0, "{proposal:?}");
}
