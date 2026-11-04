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
    finetune::train(vault, trainer, Limits::default(), &move || power, &stop)
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
    // The candidate is in shadow mode with the trainer version, on no host yet: no
    // separate candidate server (plan 0035 unit G).
    let candidate = shadow_candidate(&vault).expect("candidate");
    assert_eq!(candidate.version, VERSION);
    assert_eq!(candidate.checkpoint_sha256, SHA);
    assert_eq!(candidate.url, "");
    assert_eq!(candidate.uploaded_to, None);
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
    let result = finetune::train(&vault, &trainer, Limits::default(), &|| Power::Ac, &stop);
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
/// cargo test --locked --release --all-features --test it
/// local_finetune::local_training_on_a_synthetic_log -- --ignored --nocapture`
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
                    task_provenance: String::new(),
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

// ---------------------------------------------------------------------------------
// Plan 0035 unit G: the head set of a training goes to the host of the bouncer brain.
// A fake bouncer brain over TLS on this computer takes `PUT` and `DELETE` of
// `/v1/heads/<sha256>` (contract bouncer-brain-v1 sections 5 and 6).
// ---------------------------------------------------------------------------------

mod placement {
    use super::*;

    use std::io::{Read, Write};

    use apassy::broker::approvals::{OwnerAction, OwnerCheck, OwnerGate};
    use apassy::broker::bouncer::{BouncerClient, ShadowPin, StaticBearer};
    use apassy::broker::heads_place::{self, PlaceFailure};
    use apassy::broker::http::TlsClient;
    use apassy::broker::shadow;
    use apassy::contracts::CredentialKind;
    use apassy::vault::{
        BouncerHostChange, BouncerHostKind, BouncerHostRole, Field, HOSTING_CONSENT_VERSION,
        ItemDraft, OwnerLabel, RealOutcome, SecretValue, ShadowAnswer, ShadowEntry,
    };
    use zeroize::Zeroizing;

    const BRAIN_TOKEN: &str = "SYNTH-finetune-brain-token-0123456789";
    const SYNTHETIC_SECRET: &str = "SYNTH-finetune-vault-secret-5521-canary";
    const SHA_A: &str = "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111";
    const SHA_B: &str = "bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222";

    fn version(sha: &str) -> String {
        format!("apassy-local-v1+{}", &sha[..8])
    }

    /// A request that the fake brain saw.
    #[derive(Debug, Clone)]
    struct Seen {
        method: String,
        path: String,
        /// The request head, as sent.
        head: String,
        body: Vec<u8>,
    }

    struct HeadsBrain {
        url: String,
        tls: Arc<TlsClient>,
        seen: Arc<Mutex<Vec<Seen>>>,
        stored: Arc<Mutex<Vec<String>>>,
        /// The most head sets it stores; then `PUT` answers 409 `heads_full`.
        capacity: Arc<AtomicUsize>,
    }

    impl HeadsBrain {
        fn client(&self) -> BouncerClient {
            let bearer = StaticBearer::new(Zeroizing::new(BRAIN_TOKEN.to_owned())).expect("bearer");
            BouncerClient::remote(&self.url, Arc::new(bearer), Arc::clone(&self.tls))
                .expect("remote")
        }

        fn seen(&self) -> Vec<Seen> {
            self.seen.lock().expect("seen").clone()
        }

        fn calls(&self) -> Vec<String> {
            self.seen()
                .iter()
                .map(|seen| format!("{} {}", seen.method, seen.path))
                .collect()
        }

        fn stored(&self) -> Vec<String> {
            self.stored.lock().expect("stored").clone()
        }
    }

    fn test_tls_pair() -> (Arc<rustls::ServerConfig>, TlsClient) {
        use rcgen::{
            BasicConstraints, CertificateParams, DistinguishedName, DnType,
            ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
        };
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

        // macOS refuses a server certificate valid for longer than 825 days.
        fn validity(params: &mut CertificateParams) {
            let now = time::OffsetDateTime::now_utc();
            params.not_before = now - time::Duration::hours(1);
            params.not_after = now + time::Duration::days(1);
        }

        let mut root = CertificateParams::default();
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, "Apassy head placement test root");
        root.distinguished_name = name;
        root.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        validity(&mut root);
        let root_key = KeyPair::generate().expect("root key");
        let root_cert = root.self_signed(&root_key).expect("root");
        let issuer = Issuer::new(root, root_key);
        let mut leaf = CertificateParams::new(vec!["localhost".to_owned()]).expect("leaf");
        leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf.use_authority_key_identifier_extension = true;
        validity(&mut leaf);
        let leaf_key = KeyPair::generate().expect("leaf key");
        let leaf_cert = leaf.signed_by(&leaf_key, &issuer).expect("leaf cert");
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf_cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        )
        .expect("server config");
        let client = TlsClient::with_extra_roots(vec![root_cert.der().clone()])
            .expect("TLS client with test root");
        (Arc::new(config), client)
    }

    fn reply<S: Write>(stream: &mut S, status: u16, body: &str) {
        let _ = write!(
            stream,
            "HTTP/1.1 {status} Synthetic\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.flush();
    }

    /// A fake bouncer brain that stores at most `capacity` head sets. It sends
    /// `100 Continue` before it reads an upload body, and answers 409 `heads_full`
    /// before the body when it is full.
    fn heads_brain(capacity: usize) -> HeadsBrain {
        let (config, client) = test_tls_pair();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = format!(
            "https://localhost:{}",
            listener.local_addr().expect("addr").port()
        );
        let seen = Arc::new(Mutex::new(Vec::new()));
        let stored = Arc::new(Mutex::new(Vec::<String>::new()));
        let capacity = Arc::new(AtomicUsize::new(capacity));
        let (log, heads, room) = (
            Arc::clone(&seen),
            Arc::clone(&stored),
            Arc::clone(&capacity),
        );
        std::thread::spawn(move || {
            for tcp in listener.incoming().flatten() {
                let _ = tcp.set_read_timeout(Some(Duration::from_secs(5)));
                let Ok(conn) = rustls::ServerConnection::new(Arc::clone(&config)) else {
                    continue;
                };
                let mut tls = rustls::StreamOwned::new(conn, tcp);
                let mut raw = Vec::new();
                let mut buf = [0u8; 4096];
                let end = loop {
                    if let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                        break Some(end);
                    }
                    match tls.read(&mut buf) {
                        Ok(0) | Err(_) => break None,
                        Ok(read) => raw.extend_from_slice(&buf[..read]),
                    }
                };
                let Some(end) = end else { continue };
                let head = String::from_utf8_lossy(&raw[..end]).into_owned();
                let lower = head.to_ascii_lowercase();
                let mut words = head.split(' ');
                let method = words.next().unwrap_or_default().to_owned();
                let path = words.next().unwrap_or_default().to_owned();
                let sha = path
                    .strip_prefix("/v1/heads/")
                    .unwrap_or_default()
                    .to_owned();
                let authorized = lower.contains(&format!(
                    "\r\nauthorization: bearer {}\r\n",
                    BRAIN_TOKEN.to_ascii_lowercase()
                ));
                let record = |body: Vec<u8>| {
                    log.lock().expect("seen").push(Seen {
                        method: method.clone(),
                        path: path.clone(),
                        head: head.clone(),
                        body,
                    });
                };
                if !authorized {
                    record(Vec::new());
                    reply(&mut tls, 401, r#"{"detail":"Unauthorized"}"#);
                } else if method == "PUT" {
                    let exists = heads.lock().expect("stored").contains(&sha);
                    if !exists && heads.lock().expect("stored").len() >= room.load(Ordering::SeqCst)
                    {
                        // The answer before the body: the client sends no body byte.
                        record(raw[end + 4..].to_vec());
                        reply(
                            &mut tls,
                            409,
                            r#"{"detail":{"code":"heads_full","message":"the server stores no more head sets"}}"#,
                        );
                    } else {
                        let early = raw.len() > end + 4;
                        let _ = tls.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
                        let _ = tls.flush();
                        let length = lower
                            .lines()
                            .find_map(|line| line.strip_prefix("content-length:"))
                            .map_or(0, |value| value.trim().parse::<usize>().unwrap_or(0));
                        while raw.len() < end + 4 + length {
                            match tls.read(&mut buf) {
                                Ok(0) | Err(_) => break,
                                Ok(read) => raw.extend_from_slice(&buf[..read]),
                            }
                        }
                        let body = raw[end + 4..].to_vec();
                        record(if early { b"EARLY BODY".to_vec() } else { body });
                        if !exists {
                            heads.lock().expect("stored").push(sha.clone());
                        }
                        let answer = format!(r#"{{"heads":"{sha}","model":"synthetic"}}"#);
                        reply(&mut tls, if exists { 200 } else { 201 }, &answer);
                    }
                } else if method == "DELETE" {
                    record(Vec::new());
                    let mut stored = heads.lock().expect("stored");
                    if let Some(at) = stored.iter().position(|kept| *kept == sha) {
                        stored.remove(at);
                        drop(stored);
                        let _ = tls.write_all(
                            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        );
                        let _ = tls.flush();
                    } else {
                        drop(stored);
                        reply(
                            &mut tls,
                            404,
                            r#"{"detail":{"code":"unknown_heads","message":"the head set is not on this server"}}"#,
                        );
                    }
                } else {
                    record(Vec::new());
                    reply(&mut tls, 404, r#"{"detail":"Not Found"}"#);
                }
                tls.conn.send_close_notify();
                let _ = tls.conn.complete_io(&mut tls.sock);
            }
        });
        HeadsBrain {
            url,
            tls: Arc::new(client),
            seen,
            stored,
            capacity,
        }
    }

    /// A trainer that writes a head file, its `manifest.json` (as `local_train.py`
    /// does), and `result.json`, for the head hash `sha`. With `leak`, the manifest
    /// names the candidate folder.
    fn placing_trainer(dir: &TempDir, sha: &str, models: &str, leak: bool) -> Trainer {
        let short = &sha[..8];
        let (extra, arg) = if leak {
            (r#","folder":"%s""#, r#" "$out""#)
        } else {
            ("", "")
        };
        let script = format!(
            r#"
while [ $# -gt 0 ]; do
  case "$1" in
    --out) out="$2";;
  esac
  shift
done
printf 'x' > "$out/candidate.safetensors"
printf '{{"schema":1,"name":"apassy-local-v1","version":"apassy-local-v1+{short}","checkpoint":{{"file":"candidate.safetensors","sha256":"{sha}","size_bytes":1}},"training":{{"examples":{{"owner_decisions":300}}}}{extra}}}'{arg} > "$out/manifest.json"
printf '{{"version":"apassy-local-v1+{short}","sha256":"{sha}","checkpoint":"%s/candidate.safetensors"}}' "$out" > "$out/result.json"
"#
        );
        let mut trainer = shell_trainer(dir, &script);
        trainer.models_dir = dir.path().join(models);
        trainer
    }

    /// A vault ready to train, with a synthetic secret item.
    fn training_vault(dir: &TempDir) -> SharedVault {
        let vault = vault_with(dir, 300, 30);
        with(&vault, |vault| {
            vault
                .add(ItemDraft {
                    title: "Staging API".to_owned(),
                    kind: CredentialKind::ApiKey,
                    notes: String::new(),
                    tags: Vec::new(),
                    fields: vec![Field {
                        name: "token".to_owned(),
                        value: SecretValue::new(SYNTHETIC_SECRET.to_owned()),
                        secret: true,
                    }],
                })
                .expect("item");
        });
        vault
    }

    fn with<T>(vault: &SharedVault, f: impl FnOnce(&mut Vault) -> T) -> T {
        let mut guard = vault.lock().expect("vault");
        f(guard.as_mut().expect("open"))
    }

    fn train(vault: &SharedVault, trainer: &Trainer) -> apassy::vault::CandidateRecord {
        run_training(vault, trainer, Power::Ac)
            .unwrap_or_else(|error| panic!("{}", error.message()))
            .candidate
    }

    fn shadow_rows(vault: &SharedVault, candidate_id: u64) {
        with(vault, |vault| {
            for _ in 0..100 {
                vault
                    .record_shadow(&ShadowEntry {
                        candidate_id,
                        at: learning::now(),
                        real: RealOutcome::Ask,
                        candidate: ShadowAnswer::Run,
                        owner: OwnerLabel::Allow,
                        facts: Vec::new(),
                    })
                    .expect("shadow row");
            }
        });
    }

    fn host_on(vault: &SharedVault, url: &str) {
        with(vault, |vault| {
            vault
                .set_bouncer_host(
                    BouncerHostRole::Hosting,
                    &BouncerHostChange {
                        kind: BouncerHostKind::OwnServer,
                        url: url.to_owned(),
                        bearer: Some(SecretValue::new(BRAIN_TOKEN.to_owned())),
                        consent_version: HOSTING_CONSENT_VERSION,
                    },
                    learning::now(),
                )
                .expect("hosting row");
        });
    }

    fn promote(vault: &SharedVault, record: &apassy::vault::CandidateRecord) -> Result<(), String> {
        let proof = OwnerGate::new(Arc::clone(vault), None)
            .authorize(
                OwnerAction::PromoteModel {
                    candidate_id: record.id,
                    version: record.version.clone(),
                },
                OwnerCheck::passphrase(PASS),
            )
            .expect("owner check");
        with(vault, |vault| {
            shadow::promote(vault, record.id, proof, learning::now()).map(|_| ())
        })
    }

    fn uploaded_to(vault: &SharedVault, id: u64) -> Option<String> {
        with(vault, |vault| {
            vault.candidate(id).expect("read").expect("row")
        })
        .uploaded_to
    }

    fn decode_b64u(text: &str) -> Vec<u8> {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = Vec::new();
        let (mut acc, mut bits) = (0u32, 0u32);
        for byte in text.bytes() {
            let value = ALPHABET.iter().position(|c| *c == byte).expect("base64url") as u32;
            acc = (acc << 6) | value;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
            }
        }
        out
    }

    /// Plan 0035 unit G: after a training, Apassy uploads the head set with its
    /// manifest (`PUT /v1/heads/<sha256>`, `Expect: 100-continue`), and only then does
    /// the candidate ride as `shadow_heads` on that host. The upload holds the head
    /// file and the manifest only: no secret value, no vault path, no folder of this
    /// Mac, no decision text.
    #[test]
    fn a_trained_head_set_is_uploaded_and_shadow_starts_after_the_upload() {
        let dir = TempDir::new().expect("dir");
        let vault = training_vault(&dir);
        let brain = heads_brain(4);
        let client = brain.client();
        let record = train(&vault, &placing_trainer(&dir, SHA_A, "models", false));
        assert_eq!(record.url, "", "no separate candidate server");
        assert_eq!(record.uploaded_to, None);
        let before = with(&vault, |vault| shadow::models(vault, Some(&client)));
        assert_eq!(
            before.candidate.as_ref().and_then(|c| c.pin.clone()),
            None,
            "no shadow answer before the upload"
        );

        let placed = heads_place::place(&vault, record.id, &client).expect("placed");
        assert_eq!(placed.host, brain.url);
        assert_eq!(placed.heads, SHA_A);
        assert!(placed.created);
        assert_eq!(
            uploaded_to(&vault, record.id).as_deref(),
            Some(brain.url.as_str())
        );
        let after = with(&vault, |vault| shadow::models(vault, Some(&client)));
        assert_eq!(
            after.candidate.and_then(|c| c.pin),
            Some(ShadowPin::new(SHA_A, &version(SHA_A)))
        );
        // The active model is unchanged: the default head set of the host.
        assert_eq!(
            after
                .active
                .and_then(|a| a.expected_heads().map(str::to_owned)),
            None
        );

        let seen = brain.seen();
        assert_eq!(seen.len(), 1, "{:?}", brain.calls());
        let put = &seen[0];
        assert_eq!(put.method, "PUT");
        assert_eq!(put.path, format!("/v1/heads/{SHA_A}"));
        let lower = put.head.to_ascii_lowercase();
        assert!(lower.contains("\r\nexpect: 100-continue"), "{}", put.head);
        assert!(lower.contains("\r\ncontent-type: application/octet-stream"));
        assert_eq!(put.body, b"x", "the head file, after 100 Continue");
        let manifest_header = put
            .head
            .lines()
            .find_map(|line| {
                line.split_once(':')
                    .filter(|(name, _)| name.eq_ignore_ascii_case("apassy-manifest"))
                    .map(|(_, value)| value.trim().to_owned())
            })
            .expect("Apassy-Manifest header");
        let manifest = decode_b64u(&manifest_header);
        let folder = Path::new(&record.checkpoint).parent().expect("folder");
        assert_eq!(
            manifest,
            std::fs::read(folder.join("manifest.json")).expect("manifest"),
            "the manifest goes up as written"
        );
        let vault_path = dir.path().join("vault.db");
        let mut everything = put.head.clone().into_bytes();
        everything.extend_from_slice(&manifest);
        everything.extend_from_slice(&put.body);
        let text = String::from_utf8_lossy(&everything);
        for hidden in [
            SYNTHETIC_SECRET,
            vault_path.to_str().expect("path"),
            folder.to_str().expect("path"),
            dir.path().to_str().expect("path"),
            "Run the task.",
            "task-1",
            "DEMO_KEY",
        ] {
            assert!(!text.contains(hidden), "{hidden} reached the brain");
        }

        // The vault names the host now: no second upload.
        heads_place::place(&vault, record.id, &client).expect("placed again");
        assert_eq!(brain.seen().len(), 1, "{:?}", brain.calls());
    }

    /// Plan 0035 unit G: a promotion needs the head set on the host of the bouncer
    /// brain. Before the upload the refusal names that host; after it the promotion
    /// pins the head hash.
    #[test]
    fn promotion_is_refused_until_the_head_set_is_on_the_host() {
        let dir = TempDir::new().expect("dir");
        let vault = training_vault(&dir);
        let brain = heads_brain(4);
        let record = train(&vault, &placing_trainer(&dir, SHA_A, "models", false));
        host_on(&vault, &brain.url);
        shadow_rows(&vault, record.id);
        let refused = promote(&vault, &record).expect_err("not on the host");
        assert_eq!(
            refused,
            format!(
                "Not promoted. Its head set is not on the bouncer brain server {} yet, so it gives no shadow answers there. Apassy uploads it first.",
                brain.url
            )
        );
        assert!(with(&vault, |vault| vault.active_model().expect("active")).is_none());

        heads_place::place(&vault, record.id, &brain.client()).expect("placed");
        promote(&vault, &record).expect("promoted");
        let active = with(&vault, |vault| vault.active_model().expect("active")).expect("row");
        assert_eq!(active.version, version(SHA_A));
        assert_eq!(active.heads_sha256.as_deref(), Some(SHA_A));
        assert_eq!(active.url, "");
    }

    /// Plan 0035 unit G: before a change of the host completes, the active and the
    /// shadow head sets go to the new host. A failed upload changes no row, so both
    /// stay on the old host; after a good one both name the new host.
    #[test]
    fn a_hosting_change_moves_the_active_and_shadow_head_sets_first() {
        let dir = TempDir::new().expect("dir");
        let vault = training_vault(&dir);
        let old = heads_brain(4);
        let active = train(&vault, &placing_trainer(&dir, SHA_A, "models-a", false));
        host_on(&vault, &old.url);
        heads_place::place(&vault, active.id, &old.client()).expect("placed");
        shadow_rows(&vault, active.id);
        promote(&vault, &active).expect("promoted");
        let candidate = train(&vault, &placing_trainer(&dir, SHA_B, "models-b", false));
        heads_place::place(&vault, candidate.id, &old.client()).expect("placed");

        // The new host takes one head set only, and none of ours can be deleted there.
        let new = heads_brain(1);
        let failed = heads_place::place_all(&vault, &new.client()).expect_err("full");
        assert_eq!(failed.host, new.url);
        assert_eq!(
            failed.failure,
            PlaceFailure::Refused {
                status: 409,
                code: Some("heads_full".to_owned())
            }
        );
        assert!(
            failed.message().contains("stores no more head sets"),
            "{}",
            failed.message()
        );
        for id in [active.id, candidate.id] {
            assert_eq!(
                uploaded_to(&vault, id).as_deref(),
                Some(old.url.as_str()),
                "{id}"
            );
        }
        assert_eq!(
            new.calls(),
            vec![
                format!("PUT /v1/heads/{SHA_A}"),
                format!("PUT /v1/heads/{SHA_B}")
            ]
        );
        assert_eq!(new.seen()[1].body, b"", "no body byte before 100 Continue");

        new.capacity.store(4, Ordering::SeqCst);
        let placed = heads_place::place_all(&vault, &new.client()).expect("moved");
        let heads: Vec<&str> = placed.iter().map(|one| one.heads.as_str()).collect();
        assert_eq!(heads, vec![SHA_A, SHA_B], "the active head set first");
        assert!(!placed[0].created, "it was there from the failed try");
        for id in [active.id, candidate.id] {
            assert_eq!(
                uploaded_to(&vault, id).as_deref(),
                Some(new.url.as_str()),
                "{id}"
            );
        }
        assert_eq!(new.stored(), vec![SHA_A.to_owned(), SHA_B.to_owned()]);

        // After the switch the promoted head set decides there, and the candidate rides.
        host_on(&vault, &new.url);
        let models = with(&vault, |vault| shadow::models(vault, Some(&new.client())));
        assert_eq!(
            models.active.as_ref().and_then(|a| a.expected_heads()),
            Some(SHA_A)
        );
        assert_eq!(
            models.candidate.and_then(|c| c.pin),
            Some(ShadowPin::new(SHA_B, &version(SHA_B)))
        );
        // Nothing to move any more.
        assert!(
            with(&vault, |vault| heads_place::missing_on(vault, &new.url))
                .expect("missing")
                .is_empty()
        );
    }

    /// Plan 0035 unit G, the switch that the app runs (`brain_host::switch`): the owner
    /// confirms a new server, and the head sets go up before the vault stores it. A
    /// failed upload keeps the old server; after a good one the new server is the host
    /// and has the promoted head set.
    #[test]
    fn the_hosting_switch_uploads_the_head_sets_before_it_stores_the_server() {
        use apassy::broker::brain_host;
        let dir = TempDir::new().expect("dir");
        let vault = training_vault(&dir);
        let old = heads_brain(4);
        let active = train(&vault, &placing_trainer(&dir, SHA_A, "models-a", false));
        host_on(&vault, &old.url);
        heads_place::place(&vault, active.id, &old.client()).expect("placed");
        shadow_rows(&vault, active.id);
        promote(&vault, &active).expect("promoted");
        let candidate = train(&vault, &placing_trainer(&dir, SHA_B, "models-b", false));
        heads_place::place(&vault, candidate.id, &old.client()).expect("placed");

        let new = heads_brain(1);
        let change = BouncerHostChange {
            kind: BouncerHostKind::OwnServer,
            url: new.url.clone(),
            bearer: Some(SecretValue::new(BRAIN_TOKEN.to_owned())),
            consent_version: HOSTING_CONSENT_VERSION,
        };
        let proof = || {
            OwnerGate::new(Arc::clone(&vault), None)
                .authorize(
                    brain_host::owner_action(BouncerHostRole::Hosting, &change),
                    OwnerCheck::passphrase(PASS),
                )
                .expect("owner check")
        };
        let hosting_url = || {
            with(&vault, |vault| {
                vault
                    .bouncer_host(BouncerHostRole::Hosting)
                    .expect("read")
                    .expect("row")
                    .url
            })
        };
        let refused = brain_host::switch(
            &vault,
            BouncerHostRole::Hosting,
            &change,
            proof(),
            &new.tls,
            learning::now(),
        )
        .expect_err("the new server is full");
        assert!(refused.starts_with("Nothing changed"), "{refused}");
        assert_eq!(hosting_url(), old.url, "the old server stays the host");
        assert_eq!(
            uploaded_to(&vault, active.id).as_deref(),
            Some(old.url.as_str())
        );

        new.capacity.store(4, Ordering::SeqCst);
        brain_host::switch(
            &vault,
            BouncerHostRole::Hosting,
            &change,
            proof(),
            &new.tls,
            learning::now(),
        )
        .expect("switched");
        assert_eq!(hosting_url(), new.url);
        assert_eq!(new.stored(), vec![SHA_A.to_owned(), SHA_B.to_owned()]);
        for id in [active.id, candidate.id] {
            assert_eq!(
                uploaded_to(&vault, id).as_deref(),
                Some(new.url.as_str()),
                "{id}"
            );
        }
    }

    /// Plan 0035 unit G: a full server (409 `heads_full`) loses the oldest replaced head
    /// set of this owner, and the upload is tried once more.
    #[test]
    fn a_full_server_loses_the_oldest_replaced_head_set_and_the_upload_is_tried_again() {
        let dir = TempDir::new().expect("dir");
        let vault = training_vault(&dir);
        let brain = heads_brain(1);
        let first = train(&vault, &placing_trainer(&dir, SHA_A, "models-a", false));
        heads_place::place(&vault, first.id, &brain.client()).expect("placed");
        let second = train(&vault, &placing_trainer(&dir, SHA_B, "models-b", false));
        let placed = heads_place::place(&vault, second.id, &brain.client()).expect("placed");
        assert_eq!(placed.freed, vec![first.id]);
        assert_eq!(
            brain.calls(),
            vec![
                format!("PUT /v1/heads/{SHA_A}"),
                format!("PUT /v1/heads/{SHA_B}"),
                format!("DELETE /v1/heads/{SHA_A}"),
                format!("PUT /v1/heads/{SHA_B}"),
            ]
        );
        assert_eq!(
            uploaded_to(&vault, first.id),
            None,
            "the replaced one lost the host"
        );
        assert_eq!(
            uploaded_to(&vault, second.id).as_deref(),
            Some(brain.url.as_str())
        );
        assert_eq!(brain.stored(), vec![SHA_B.to_owned()]);
    }

    /// A manifest that names a folder of this Mac never goes up; neither does a head
    /// set without its manifest. A wrong token is refused by the server and named.
    #[test]
    fn a_manifest_with_a_path_of_this_mac_or_a_wrong_token_uploads_nothing() {
        let dir = TempDir::new().expect("dir");
        let vault = training_vault(&dir);
        let brain = heads_brain(4);
        let record = train(&vault, &placing_trainer(&dir, SHA_A, "models", true));
        let refused = heads_place::place(&vault, record.id, &brain.client()).expect_err("leak");
        assert_eq!(
            refused.failure,
            PlaceFailure::Files("its manifest.json names a folder on this Mac")
        );
        assert!(brain.seen().is_empty(), "nothing was sent");
        assert_eq!(uploaded_to(&vault, record.id), None);

        let record = train(&vault, &placing_trainer(&dir, SHA_B, "models-b", false));
        let wrong = StaticBearer::new(Zeroizing::new("SYNTH-wrong-token-0123456789".to_owned()))
            .expect("bearer");
        let client = BouncerClient::remote(&brain.url, Arc::new(wrong), Arc::clone(&brain.tls))
            .expect("remote");
        let refused = heads_place::place(&vault, record.id, &client).expect_err("401");
        assert_eq!(
            refused.failure,
            PlaceFailure::Refused {
                status: 401,
                code: None
            }
        );
        assert!(
            refused.message().contains("refused the token (401)"),
            "{}",
            refused.message()
        );
        assert_eq!(uploaded_to(&vault, record.id), None);
        // The 401 ended the credential: the next call sends nothing.
        let again = heads_place::place(&vault, record.id, &client).expect_err("no key");
        assert_eq!(again.failure, PlaceFailure::NoKey);
        assert_eq!(brain.seen().len(), 1);
    }
}
