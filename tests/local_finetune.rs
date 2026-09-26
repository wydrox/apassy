#![cfg(feature = "vault")]

//! The local fine-tune gate of ADR 0010 (goal item B9): 300 owner decisions with 30 or
//! more denials, AC power, and a hard time limit. Fake trainers only. Synthetic values.
//!
//! `local_training_on_a_synthetic_log` is the measurement on this Mac. It is ignored in
//! `cargo test`, because it needs the Laya environment and a model server.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use apassy::broker::SharedVault;
use apassy::broker::finetune::{
    self, Limits, MIN_OWNER_DECISIONS, MIN_OWNER_DENIALS, Power, Trainer, TrainingError,
};
use apassy::broker::learning;
use apassy::vault::{
    CandidateState, DecidedBy, DecisionEntry, Declaration, Environment, LoggedDecision,
    RequestSource, Reversibility, RiskLevel, Scope, Vault,
};
use tempfile::TempDir;

const PASS: &str = "local-finetune-pass";
const CANDIDATE_URL: &str = "http://127.0.0.1:8775";
const VERSION: &str = "apassy-local-v1+0123abcd";
const SHA: &str = "0123abcd0123456789abcdef0123456789abcdef0123456789abcdef01234567";

fn staging() -> Declaration {
    Declaration {
        project: "demo".to_owned(),
        environment: Environment::Staging,
        risk: RiskLevel::Medium,
        scope: Scope::ReadWrite,
        reversibility: Reversibility::Reversible,
    }
}

fn entry(n: usize, decided_by: DecidedBy, deny: bool) -> DecisionEntry {
    DecisionEntry {
        at: 1_790_000_000 + n as u64,
        agent_id: 1,
        agent_name: "Finetune agent".to_owned(),
        project_dir: "/work/app".to_owned(),
        cwd_rel: ".".to_owned(),
        items: vec![1],
        user_request: "Run the task.".to_owned(),
        user_request_source: RequestSource::Agent,
        command: vec!["npm".to_owned(), "run".to_owned(), format!("task-{n}")],
        purpose: "Run the task.".to_owned(),
        env_names: vec!["DEMO_KEY".to_owned()],
        declarations: vec![Some(staging())],
        rule_flags: Vec::new(),
        known_safe: false,
        model_facts: vec![("task_match".to_owned(), 0.5)],
        pattern: String::new(),
        grant_asks: false,
        asked: decided_by != DecidedBy::Model,
        decision: if deny {
            LoggedDecision::Deny
        } else {
            LoggedDecision::Allow
        },
        decided_by,
        remembered: false,
        policy: "apassy-bouncer-v4; task_match 0.80".to_owned(),
        note: String::new(),
        instruction: String::new(),
    }
}

/// A vault with `decisions` owner decisions, `denials` of them denials. Model, rule, and
/// "no answer" entries are also in the log. They do not count.
fn vault_with(dir: &TempDir, decisions: usize, denials: usize) -> SharedVault {
    let mut vault = Vault::create(&dir.path().join("vault.db"), PASS).expect("create");
    vault.unlock(PASS).expect("unlock");
    for n in 0..decisions {
        vault
            .record_decision(&entry(n, DecidedBy::Owner, n < denials))
            .expect("owner decision");
    }
    for n in 0..40 {
        let by = [DecidedBy::Model, DecidedBy::Rule, DecidedBy::NoAnswer][n % 3];
        vault
            .record_decision(&entry(10_000 + n, by, by != DecidedBy::Model))
            .expect("other decision");
    }
    Arc::new(Mutex::new(Some(vault)))
}

/// A trainer that is a shell script. It gets the job arguments as `$@`.
fn shell_trainer(dir: &TempDir, script: &str) -> Trainer {
    Trainer {
        program: PathBuf::from("/bin/sh"),
        args: vec![
            OsString::from("-c"),
            OsString::from(script),
            OsString::from("trainer"),
        ],
        models_dir: dir.path().join("models"),
        init: Some(dir.path().join("base.safetensors")),
        name: "apassy-local-v1".to_owned(),
    }
}

/// Reads `--data` and `--out`, writes a marker, a checkpoint, and `result.json` with the
/// number of training lines.
const GOOD_TRAINER: &str = r#"
while [ $# -gt 0 ]; do
  case "$1" in
    --data) data="$2";;
    --out) out="$2";;
    --init) init="$2";;
  esac
  shift
done
echo started > "$out/../marker"
lines=$(wc -l < "$data/train.jsonl" | tr -d ' ')
printf 'x' > "$out/candidate.safetensors"
printf '{"version":"apassy-local-v1+0123abcd","sha256":"0123abcd0123456789abcdef0123456789abcdef0123456789abcdef01234567","checkpoint":"%s/candidate.safetensors","train_examples":%s,"init":"%s"}' "$out" "$lines" "$init" > "$out/result.json"
"#;

fn run_training(
    vault: &SharedVault,
    trainer: &Trainer,
    power: Power,
) -> Result<finetune::TrainingReport, TrainingError> {
    let stop = AtomicBool::new(false);
    finetune::train(
        vault,
        trainer,
        CANDIDATE_URL,
        Limits::default(),
        &move || power,
        &stop,
    )
}

fn marker(dir: &TempDir) -> bool {
    dir.path().join("models/marker").exists()
}

fn shadow_candidate(vault: &SharedVault) -> Option<apassy::vault::CandidateRecord> {
    vault
        .lock()
        .expect("vault")
        .as_ref()
        .expect("open")
        .shadow_candidate()
        .expect("read")
}

/// ADR 0010: the gate opens at exactly 300 owner decisions with 30 denials on AC power.
/// It stays closed at 299 decisions, at 29 denials, on battery, and with an unknown
/// power source. A closed gate never starts the trainer.
#[test]
fn the_gate_opens_at_exactly_300_decisions_and_30_denials_on_ac_power() {
    assert_eq!((MIN_OWNER_DECISIONS, MIN_OWNER_DENIALS), (300, 30));
    let closed = [
        (299, 30, Power::Ac, "299 of 300 owner decisions"),
        (300, 29, Power::Ac, "29 of 30 owner denials"),
        (300, 30, Power::Battery, "power source: battery"),
        (300, 30, Power::Unknown, "power source: unknown"),
    ];
    for (decisions, denials, power, reason) in closed {
        let dir = TempDir::new().expect("dir");
        let vault = vault_with(&dir, decisions, denials);
        let trainer = shell_trainer(&dir, GOOD_TRAINER);
        match run_training(&vault, &trainer, power) {
            Err(TrainingError::GateClosed(gate)) => {
                assert_eq!(gate.owner_decisions, decisions);
                assert_eq!(gate.owner_denials, denials);
                assert!(!gate.is_open());
                let message = TrainingError::GateClosed(gate).message();
                assert!(message.contains(reason), "{message}");
            }
            other => panic!("{decisions}/{denials}/{power:?}: {other:?}"),
        }
        assert!(!marker(&dir), "the trainer started with a closed gate");
        assert!(shadow_candidate(&vault).is_none());
    }

    let dir = TempDir::new().expect("dir");
    let vault = vault_with(&dir, 300, 30);
    let records = vault
        .lock()
        .expect("vault")
        .as_ref()
        .expect("open")
        .decision_log()
        .expect("log");
    let gate = finetune::gate(&records, Power::Ac);
    assert_eq!((gate.owner_decisions, gate.owner_denials), (300, 30));
    assert!(gate.is_open());
    let trainer = shell_trainer(&dir, GOOD_TRAINER);
    let report = run_training(&vault, &trainer, Power::Ac).expect("trained");
    assert!(marker(&dir));
    assert_eq!(report.stats.owner_decisions, 300);
    assert_eq!(report.stats.owner_denials, 30);
    assert_eq!(report.stats.task_match_yes, 270);
    assert_eq!(report.stats.task_match_no, 30);
    assert_eq!(report.stats.denial_weight, 9, "270 approvals / 30 denials");
    assert!(report.result["train_examples"].as_u64().unwrap_or(0) > 0);
    assert_eq!(
        report.result["init"].as_str(),
        Some(dir.path().join("base.safetensors").to_str().expect("path")),
        "the trainer starts from the base checkpoint"
    );
    // The candidate is in shadow mode with the trainer version and the candidate address.
    let candidate = shadow_candidate(&vault).expect("candidate");
    assert_eq!(candidate.version, VERSION);
    assert_eq!(candidate.checkpoint_sha256, SHA);
    assert_eq!(candidate.url, CANDIDATE_URL);
    assert_eq!(candidate.state, CandidateState::Shadow);
    assert_eq!(candidate.id, report.candidate.id);
    // The example files with commands and user requests are gone. The checkpoint stays.
    let folder = Path::new(&candidate.checkpoint)
        .parent()
        .expect("folder")
        .to_path_buf();
    assert!(Path::new(&candidate.checkpoint).is_file());
    assert!(!folder.join("data").exists(), "the examples are deleted");
    // Nothing trains without a call to `train`: the vault has one candidate.
    let count = vault
        .lock()
        .expect("vault")
        .as_ref()
        .expect("open")
        .candidates(10)
        .expect("candidates")
        .len();
    assert_eq!(count, 1);
}

/// The trainer writes its process ID and waits. Returns the job and the PID file.
const SLOW_TRAINER: &str = r#"
while [ $# -gt 0 ]; do
  case "$1" in --out) out="$2";; esac
  shift
done
echo $$ > "$out/../pid"
sleep 60 &
wait
"#;

fn process_alive(pid: &str) -> bool {
    std::process::Command::new("/bin/kill")
        .args(["-0", pid])
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn wait_for_pid(dir: &TempDir) -> String {
    let path = dir.path().join("models/pid");
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Ok(text) = std::fs::read_to_string(&path)
            && !text.trim().is_empty()
        {
            return text.trim().to_owned();
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("the trainer did not start");
}

/// The candidate folders under `models`. A stopped training leaves none.
fn candidate_folders(dir: &TempDir) -> usize {
    std::fs::read_dir(dir.path().join("models"))
        .map(|entries| {
            entries
                .flatten()
                .filter(|entry| entry.path().is_dir())
                .count()
        })
        .unwrap_or(0)
}

/// ADR 0010: a training runs for one hour at most. The broker stops the trainer and
/// its process group at the limit. No candidate is made.
#[test]
fn the_time_limit_stops_the_training() {
    assert_eq!(finetune::TIME_LIMIT, Duration::from_secs(3600));
    let dir = TempDir::new().expect("dir");
    let vault = vault_with(&dir, 300, 30);
    let trainer = shell_trainer(&dir, SLOW_TRAINER);
    let stop = AtomicBool::new(false);
    let started = Instant::now();
    let result = finetune::train(
        &vault,
        &trainer,
        CANDIDATE_URL,
        Limits {
            time: Duration::from_secs(1),
            power_every: Duration::from_secs(60),
        },
        &|| Power::Ac,
        &stop,
    );
    let elapsed = started.elapsed();
    assert_eq!(
        result.expect_err("stopped"),
        TrainingError::TimedOut(Duration::from_secs(1))
    );
    assert!(elapsed < Duration::from_secs(10), "{elapsed:?}");
    let pid = wait_for_pid(&dir);
    assert!(!process_alive(&pid), "the trainer {pid} still runs");
    assert!(shadow_candidate(&vault).is_none());
    assert_eq!(
        candidate_folders(&dir),
        0,
        "a stopped training leaves nothing"
    );
    assert!(
        TrainingError::TimedOut(finetune::TIME_LIMIT)
            .message()
            .contains("after 60 minutes")
    );
}

/// The broker checks the power source during the training. On battery it stops the
/// trainer.
#[test]
fn leaving_ac_power_stops_the_training() {
    let dir = TempDir::new().expect("dir");
    let vault = vault_with(&dir, 300, 30);
    let trainer = shell_trainer(&dir, SLOW_TRAINER);
    let stop = AtomicBool::new(false);
    let checks = AtomicUsize::new(0);
    // AC power for the gate and the first check, then battery.
    let power = || {
        if checks.fetch_add(1, Ordering::SeqCst) < 2 {
            Power::Ac
        } else {
            Power::Battery
        }
    };
    let result = finetune::train(
        &vault,
        &trainer,
        CANDIDATE_URL,
        Limits {
            time: Duration::from_secs(60),
            power_every: Duration::from_millis(200),
        },
        &power,
        &stop,
    );
    assert_eq!(
        result.expect_err("stopped"),
        TrainingError::OnBattery(Power::Battery)
    );
    let pid = wait_for_pid(&dir);
    assert!(!process_alive(&pid));
    assert!(shadow_candidate(&vault).is_none());
}

/// The owner can stop a training.
#[test]
fn the_owner_can_stop_the_training() {
    let dir = TempDir::new().expect("dir");
    let vault = vault_with(&dir, 300, 30);
    let trainer = shell_trainer(&dir, SLOW_TRAINER);
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let stopper = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(500));
        flag.store(true, Ordering::SeqCst);
    });
    let result = finetune::train(
        &vault,
        &trainer,
        CANDIDATE_URL,
        Limits::default(),
        &|| Power::Ac,
        &stop,
    );
    stopper.join().expect("stopper");
    assert_eq!(result.expect_err("stopped"), TrainingError::Stopped);
    let pid = wait_for_pid(&dir);
    assert!(!process_alive(&pid));
    assert_eq!(candidate_folders(&dir), 0);
}

/// A trainer result must name its checkpoint in the candidate folder, with a version
/// that matches its SHA-256. A failed trainer makes no candidate.
#[test]
fn a_bad_or_failed_trainer_makes_no_candidate() {
    let bad_version = GOOD_TRAINER.replace("apassy-local-v1+0123abcd", "apassy-local-v1+ffffffff");
    let outside = GOOD_TRAINER.replace(
        r#""checkpoint":"%s/candidate.safetensors""#,
        r#""checkpoint":"/etc/hosts%s""#,
    );
    let failing = "echo 'loss exploded' >&2; exit 3".to_owned();
    for (script, expected) in [
        (bad_version, "the version does not match"),
        (outside, "checkpoint"),
        (failing, "loss exploded"),
    ] {
        let dir = TempDir::new().expect("dir");
        let vault = vault_with(&dir, 300, 30);
        let trainer = shell_trainer(&dir, &script);
        let error = run_training(&vault, &trainer, Power::Ac).expect_err("refused");
        assert!(error.message().contains(expected), "{}", error.message());
        assert!(shadow_candidate(&vault).is_none());
        assert_eq!(candidate_folders(&dir), 0);
    }
}

/// The measurement on this Mac (goal item B9, `docs/operations/fine-tune.md`). The
/// simulated owner comes from the labeled fixtures `tests/fixtures/bouncer/cases.tsv`:
/// `ok` is an approval and `risk` is a denial. Each request waits for the owner (a
/// grant in "ask" mode), so every request is one owner decision. With
/// `APASSY_EVAL_MODEL`, the log also has the model facts of that server. The label
/// mapping does not use them. The real trainer then runs through `finetune::train`
/// with the gate and the time limit, wrapped in `/usr/bin/time -l` for the memory.
///
/// `APASSY_TOOLS_DIR=$PWD/tools APASSY_FINETUNE_MODELS=<dir>
/// cargo test --locked --release --features vault --test local_finetune
/// local_training_on_a_synthetic_log -- --ignored --nocapture`
#[test]
#[ignore = "needs the Laya environment and the base checkpoint"]
fn local_training_on_a_synthetic_log() {
    use apassy::broker::approvals::ApprovalOutcome;
    use apassy::broker::bouncer::{BouncerClient, BouncerRequest};
    use apassy::broker::learning::{LoggedRequest, Outcome, RunScope};
    use apassy::broker::shell_risk::{analyze, command_line_to_argv};

    let client = std::env::var("APASSY_EVAL_MODEL").ok().map(|url| {
        BouncerClient::new(&url)
            .expect("url")
            .with_timeout(Duration::from_secs(60))
    });
    let dir = TempDir::new().expect("dir");
    let mut vault = Vault::create(&dir.path().join("vault.db"), PASS).expect("create");
    vault.unlock(PASS).expect("unlock");
    // Every case once, then repeats in a fixed order, to 300 requests.
    let cases = fixture_cases("tests/fixtures/bouncer/cases.tsv");
    let env_names = vec!["SUPABASE_SERVICE_KEY".to_owned()];
    let declarations = [Some(staging())];
    let project = PathBuf::from("/work/odealo");
    let mut facts_calls = 0;
    let t0 = Instant::now();
    for n in 0..300 {
        let (ok, line, purpose) = &cases[(n * 7) % cases.len()];
        let command = command_line_to_argv(line);
        let analysis = analyze(&command, purpose, &env_names);
        let verdict = match &client {
            Some(client) if analysis.flags.is_empty() => {
                facts_calls += 1;
                client.evaluate(&BouncerRequest {
                    user_request: purpose.clone(),
                    command: command.join(" "),
                    relative_dir: ".".to_owned(),
                    purpose: purpose.clone(),
                    env_names: env_names.clone(),
                    instruction: String::new(),
                })
            }
            _ => apassy::broker::bouncer::BouncerVerdict::Unavailable("not asked".to_owned()),
        };
        let scope = RunScope {
            agent_id: 1,
            project_dir: &project,
            cwd: &project,
            cwd_rel: ".",
            items: &[1],
            declarations: &declarations,
            instruction: "",
        };
        let logged = LoggedRequest {
            at: 1_790_000_000 + n as u64 * 600,
            agent_id: 1,
            agent_name: "Measurement agent",
            scope,
            user_request: purpose,
            user_request_source: learning::agent_source(purpose),
            command: &command,
            purpose,
            env_names: &env_names,
            analysis: &analysis,
            verdict: &verdict,
            pattern: None,
            grant_asks: true,
            thresholds: apassy::broker::bouncer::Thresholds::default(),
        };
        let outcome = if *ok {
            ApprovalOutcome::Approved
        } else {
            ApprovalOutcome::Denied
        };
        vault
            .record_decision(&logged.entry(Outcome::Owner(outcome), "synthetic owner"))
            .expect("decision");
    }
    eprintln!(
        "synthetic log: 300 owner decisions, {facts_calls} model calls in {:.1} s",
        t0.elapsed().as_secs_f64()
    );
    let vault: SharedVault = Arc::new(Mutex::new(Some(vault)));
    let mut trainer = Trainer::from_env().expect("trainer");
    if let Some(models) = std::env::var_os("APASSY_FINETUNE_MODELS") {
        trainer.models_dir = PathBuf::from(models);
    }
    // `/usr/bin/time -l` gives the peak memory of the trainer process.
    let mut args = vec![trainer.program.clone().into_os_string()];
    args.append(&mut trainer.args);
    trainer.args = std::iter::once(OsString::from("-l")).chain(args).collect();
    trainer.program = PathBuf::from("/usr/bin/time");
    let power = finetune::power_now();
    eprintln!("power at start: {power:?}; init: {:?}", trainer.init);
    let stop = AtomicBool::new(false);
    let started = Instant::now();
    let report = finetune::train(
        &vault,
        &trainer,
        CANDIDATE_URL,
        Limits::default(),
        &finetune::power_now,
        &stop,
    )
    .unwrap_or_else(|error| panic!("{}", error.message()));
    eprintln!(
        "TRAINED {} in {:.1} s (limit {} s); stats {}; result {}",
        report.candidate.version,
        started.elapsed().as_secs_f64(),
        finetune::TIME_LIMIT.as_secs(),
        serde_json::to_string(&report.stats).unwrap_or_default(),
        report.result
    );
    eprintln!("CHECKPOINT {}", report.candidate.checkpoint);
    let log = Path::new(&report.candidate.checkpoint)
        .parent()
        .expect("folder")
        .join("train.log");
    eprintln!("LOG {}", log.display());
    // `/usr/bin/time -l` writes the peak resident memory in bytes to the log.
    let text = std::fs::read_to_string(&log).expect("log");
    for line in text.lines().filter(|line| {
        line.contains("maximum resident set size")
            || line.contains("peak memory footprint")
            || line.contains(" real ")
    }) {
        eprintln!("TIME {}", line.trim());
    }
    assert!(report.seconds < finetune::TIME_LIMIT.as_secs_f64());
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
