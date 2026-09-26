#![cfg(feature = "vault")]

//! Decision log, "Approve and remember", and calibration through the broker (ADR 0009,
//! ADR 0010, goal items B3 and B5). Synthetic values only.

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use apassy::agent::client;
use apassy::agent::wire::{Action, WireResponse};
use apassy::broker::approvals::{OwnerAnswer, PendingRun};
use apassy::broker::bouncer::{BouncerClient, Thresholds};
use apassy::broker::http::TlsClient;
use apassy::broker::learning::{self, RunScope};
use apassy::broker::{self, BrokerHandle, BrokerOptions, SharedVault, calibration};
use apassy::contracts::CredentialKind;
use apassy::vault::{
    DecidedBy, DecisionEntry, Declaration, Environment, ExecMode, ExecRule, Field, ItemDraft,
    LoggedDecision, PATTERN_APPROVALS_NEEDED, PatternState, RequestSource, Reversibility,
    RiskLevel, Scope, SecretValue, Vault,
};
use tempfile::TempDir;

const PASS: &str = "learning-pass-ok";
const SECRET: &str = "FAKE-learning-secret-7731-canary";
const ENV_NAME: &str = "DEMO_KEY";
/// The model step asks the owner for this answer: `task_match` 30%, `writes` 50%.
const UNSURE: &[(&str, f64)] = &[("task_match", 0.3), ("writes", 0.5)];

struct Fixture {
    dir: TempDir,
    vault: SharedVault,
    socket: PathBuf,
    project: PathBuf,
    item_id: u64,
    agent_id: u64,
    token: String,
    broker: BrokerHandle,
    model_calls: Arc<Mutex<Vec<String>>>,
}

fn staging() -> Declaration {
    Declaration {
        project: "demo".to_owned(),
        environment: Environment::Staging,
        risk: RiskLevel::Medium,
        scope: Scope::ReadWrite,
        reversibility: Reversibility::Reversible,
    }
}

fn fixture(model: &'static [(&'static str, f64)]) -> Fixture {
    fixture_with(model, Duration::from_secs(10))
}

fn fixture_with(model: &'static [(&'static str, f64)], approval_timeout: Duration) -> Fixture {
    let bouncer = common::fake_bouncer(model);
    let dir = TempDir::new().expect("temp dir");
    let project = dir.path().join("project");
    std::fs::create_dir_all(&project).expect("project");
    let project = std::fs::canonicalize(project).expect("canonical");
    let script = project.join("report.sh");
    std::fs::write(&script, "#!/bin/sh\necho \"$1 $2\"\n").expect("script");
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
    let (agent, token) = vault.register_agent("Learning agent").expect("register");
    vault
        .set_exec_grant(
            agent.id,
            item.id,
            &project.display().to_string(),
            ExecMode::Bouncer,
        )
        .expect("grant");
    vault
        .set_declaration(item.id, &staging())
        .expect("declaration");
    let shared: SharedVault = Arc::new(Mutex::new(Some(vault)));
    let mut options = BrokerOptions::with_tls(TlsClient::platform().expect("TLS"));
    options.approval_timeout = approval_timeout;
    options.run_timeout = Duration::from_secs(10);
    options.bouncer = Some(
        BouncerClient::new(&bouncer.url)
            .expect("url")
            .with_timeout(Duration::from_secs(2)),
    );
    let socket = dir.path().join("run").join("broker.sock");
    let broker = broker::start_with(Arc::clone(&shared), &socket, options).expect("broker");
    Fixture {
        dir,
        vault: shared,
        socket,
        project,
        item_id: item.id,
        agent_id: agent.id,
        token: token.expose().to_owned(),
        broker,
        model_calls: bouncer.bodies,
    }
}

fn report(limit: &str) -> Vec<String> {
    vec![
        "sh".to_owned(),
        "-c".to_owned(),
        format!("./report.sh --limit {limit}"),
    ]
}

fn send(
    fx: &Fixture,
    token: &str,
    items: Vec<u64>,
    command: &[String],
    user: Option<&str>,
) -> WireResponse {
    client::send(
        &fx.socket,
        token,
        Action::Run {
            items,
            command: command.to_vec(),
            cwd: fx.project.display().to_string(),
            purpose: "Print the report.".to_owned(),
            path: Some("/usr/bin:/bin".to_owned()),
            user_request: user.map(str::to_owned),
        },
    )
    .expect("answer")
}

fn run(fx: &Fixture, command: &[String]) -> WireResponse {
    send(
        fx,
        &fx.token,
        vec![fx.item_id],
        command,
        Some("Print the weekly report."),
    )
}

/// The next waiting run gets `answer`. The thread returns the run as the card saw it.
fn owner(fx: &Fixture, answer: OwnerAnswer) -> JoinHandle<PendingRun> {
    let approvals = Arc::clone(fx.broker.approvals());
    std::thread::spawn(move || {
        loop {
            if let Some(pending) = approvals.pending().into_iter().next() {
                assert!(approvals.answer(pending.id, answer), "{answer:?}");
                return pending;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    })
}

/// The request waits for the owner. The owner approves once. The waiting run is returned.
fn expect_prompt(fx: &Fixture, send_it: impl FnOnce() -> WireResponse) -> PendingRun {
    let approver = owner(fx, OwnerAnswer::Approve);
    let response = send_it();
    let pending = approver.join().expect("owner");
    assert!(response.ok, "{response:?}");
    assert_eq!(
        response.result.expect("result")["decided_by"],
        "Owner approved"
    );
    pending
}

fn with_vault<T>(fx: &Fixture, f: impl FnOnce(&mut Vault) -> T) -> T {
    let mut guard = fx.vault.lock().expect("vault");
    f(guard.as_mut().expect("open"))
}

fn decided_by(response: &WireResponse) -> String {
    assert!(response.ok, "{response:?}");
    response.result.as_ref().expect("result")["decided_by"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

fn code(response: &WireResponse) -> String {
    assert!(!response.ok, "expected a refusal: {response:?}");
    response
        .error
        .as_ref()
        .map_or_else(String::new, |e| e.code.clone())
}

/// Teach an active pattern straight in the vault, as three "Approve and remember"
/// answers would. The broker offers "Approve and remember" only for a run that can
/// teach a pattern, so this is the way to test a pattern for any other run.
fn teach(
    fx: &Fixture,
    items: &[u64],
    declarations: &[Option<Declaration>],
    instruction: &str,
    command: &[String],
) {
    let pattern = learning::request_pattern(
        RunScope {
            agent_id: fx.agent_id,
            project_dir: &fx.project,
            cwd: &fx.project,
            cwd_rel: ".",
            items,
            declarations,
            instruction,
        },
        command,
    )
    .expect("pattern");
    with_vault(fx, |vault| {
        for _ in 0..PATTERN_APPROVALS_NEEDED {
            learning::remember(vault, &pattern, learning::now()).expect("remember");
        }
        assert_eq!(
            vault
                .pattern(&pattern.key)
                .expect("read")
                .expect("pattern")
                .state(learning::now()),
            PatternState::Active
        );
    });
}

/// ADR 0010: a pattern runs without a prompt only after 3 approvals. It stays bound to
/// the agent.
#[test]
fn approve_and_remember_three_times_then_the_pattern_runs_without_a_prompt() {
    let fx = fixture(UNSURE);
    for (limit, approvals) in [("5", 0), ("6", 1), ("7", 2)] {
        let owner = owner(&fx, OwnerAnswer::ApproveAndRemember);
        let response = run(&fx, &report(limit));
        let card = owner.join().expect("owner");
        assert_eq!(decided_by(&response), "Owner approved");
        let offer = card.remember.expect("offer");
        assert_eq!(offer.pattern, "sh -c './report.sh --limit <number>'");
        assert_eq!(offer.approvals, approvals);
        assert_eq!(offer.needed, 3);
    }
    assert_eq!(fx.model_calls.lock().expect("calls").len(), 3);

    let response = run(&fx, &report("8"));
    assert_eq!(decided_by(&response), "Remembered pattern");
    assert_eq!(response.result.expect("result")["stdout"], "--limit 8\n");
    assert_eq!(
        fx.model_calls.lock().expect("calls").len(),
        3,
        "an active pattern replaces the model"
    );
    assert!(fx.broker.approvals().pending().is_empty());

    let (patterns, log) = with_vault(&fx, |vault| {
        (
            vault.patterns().expect("patterns"),
            vault.decision_log().expect("log"),
        )
    });
    assert_eq!(patterns.len(), 1);
    assert_eq!(patterns[0].approvals, 3);
    assert_eq!(patterns[0].uses, 1);
    assert_eq!(patterns[0].state(learning::now()), PatternState::Active);
    let by: Vec<(DecidedBy, bool, bool)> = log
        .iter()
        .map(|record| {
            (
                record.entry.decided_by,
                record.entry.asked,
                record.entry.remembered,
            )
        })
        .collect();
    assert_eq!(
        by,
        vec![
            (DecidedBy::Owner, true, true),
            (DecidedBy::Owner, true, true),
            (DecidedBy::Owner, true, true),
            (DecidedBy::Pattern, false, false),
        ]
    );

    // Another literal is another pattern.
    let card = expect_prompt(&fx, || {
        run(
            &fx,
            &[
                "sh".to_owned(),
                "-c".to_owned(),
                "./report.sh --page 8".to_owned(),
            ],
        )
    });
    assert_eq!(card.remember.expect("offer").approvals, 0);

    // The pattern belongs to one agent.
    let other = with_vault(&fx, |vault| {
        let (agent, token) = vault.register_agent("Other agent").expect("register");
        vault
            .set_exec_grant(
                agent.id,
                fx.item_id,
                &fx.project.display().to_string(),
                ExecMode::Bouncer,
            )
            .expect("grant");
        token.expose().to_owned()
    });
    expect_prompt(&fx, || {
        send(
            &fx,
            &other,
            vec![fx.item_id],
            &report("9"),
            Some("Print the weekly report."),
        )
    });
}

/// ADR 0010: one denial blocks the pattern. A blocked pattern gets no offer, and
/// approvals cannot activate it. The owner can remove it.
#[test]
fn one_denial_blocks_the_pattern() {
    let fx = fixture(UNSURE);
    for limit in ["5", "6"] {
        let owner = owner(&fx, OwnerAnswer::ApproveAndRemember);
        assert_eq!(decided_by(&run(&fx, &report(limit))), "Owner approved");
        owner.join().expect("owner");
    }
    let owner = owner(&fx, OwnerAnswer::Deny);
    assert_eq!(code(&run(&fx, &report("7"))), "approval_denied");
    assert_eq!(
        owner
            .join()
            .expect("owner")
            .remember
            .expect("offer")
            .approvals,
        2
    );

    // The next matching run asks. The card has no "Approve and remember".
    let approvals = Arc::clone(fx.broker.approvals());
    let refused = std::thread::spawn(move || {
        loop {
            if let Some(pending) = approvals.pending().into_iter().next() {
                assert!(pending.remember.is_none());
                assert!(!approvals.answer(pending.id, OwnerAnswer::ApproveAndRemember));
                assert!(approvals.answer(pending.id, OwnerAnswer::Approve));
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    });
    assert_eq!(decided_by(&run(&fx, &report("8"))), "Owner approved");
    refused.join().expect("owner");
    // The denied request itself still asks.
    expect_prompt(&fx, || run(&fx, &report("7")));

    let pattern = with_vault(&fx, |vault| {
        let patterns = vault.patterns().expect("patterns");
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].state(learning::now()), PatternState::Blocked);
        let log = vault.decision_log().expect("log");
        assert!(log.iter().any(|record| record.entry.owner_denied()));
        patterns[0].id
    });

    // The owner removes the block. The pattern can learn again.
    with_vault(&fx, |vault| vault.remove_pattern(pattern).expect("remove"));
    let card = expect_prompt(&fx, || run(&fx, &report("9")));
    assert_eq!(card.remember.expect("offer").approvals, 0);
}

/// ADR 0010: a remembered pattern replaces only the model step. A hard rule failure, the
/// production rule, a rule flag, a missing user request, and a missing declaration
/// still decide, also when an active pattern matches the request.
#[test]
fn an_active_pattern_never_overrides_the_earlier_steps() {
    let fx = fixture(UNSURE);
    let staged = [Some(staging())];
    let items = [fx.item_id];

    // Clean request: the pattern allows it without the model.
    teach(&fx, &items, &staged, "", &report("1"));
    assert_eq!(decided_by(&run(&fx, &report("2"))), "Remembered pattern");
    let calls = fx.model_calls.lock().expect("calls").len();

    // Missing user request.
    let card = expect_prompt(&fx, || {
        send(&fx, &fx.token, vec![fx.item_id], &report("3"), None)
    });
    assert!(
        card.risk.contains("did not send the user request"),
        "{}",
        card.risk
    );
    assert!(card.remember.is_none());

    // Rule flag. The pattern of the flagged command is taught straight in the vault.
    let leak = vec![
        "sh".to_owned(),
        "-c".to_owned(),
        format!("echo ${ENV_NAME} | base64"),
    ];
    teach(&fx, &items, &staged, "", &leak);
    let card = expect_prompt(&fx, || run(&fx, &leak));
    assert!(
        card.risk.contains("Rule flags: secret_output"),
        "{}",
        card.risk
    );
    assert!(card.remember.is_none());

    // Hard rules of the grant: forbidden word, run limit, and expiry deny.
    let set_rule = |rule: ExecRule| {
        with_vault(&fx, |vault| {
            vault
                .set_exec_rule(fx.agent_id, fx.item_id, rule)
                .expect("rule");
        });
    };
    set_rule(ExecRule {
        forbidden_words: vec!["limit".to_owned()],
        ..ExecRule::default()
    });
    assert_eq!(code(&run(&fx, &report("4"))), "rule_forbidden_word");
    set_rule(ExecRule {
        expires_at: Some(1),
        ..ExecRule::default()
    });
    assert_eq!(code(&run(&fx, &report("4"))), "rule_expired");
    set_rule(ExecRule {
        max_runs_per_hour: Some(1),
        ..ExecRule::default()
    });
    // Runs in this hour already happened. The limit denies the next one.
    assert_eq!(code(&run(&fx, &report("4"))), "rule_rate_limit");
    set_rule(ExecRule::default());

    // Production rule (ADR 0010, goal item P2). The pattern is taught under the
    // production declaration, so its key matches.
    let mut production = staging();
    production.environment = Environment::Production;
    with_vault(&fx, |vault| {
        vault
            .set_declaration(fx.item_id, &production)
            .expect("declaration");
    });
    teach(&fx, &items, &[Some(production)], "", &report("5"));
    let card = expect_prompt(&fx, || run(&fx, &report("6")));
    assert!(
        card.risk.starts_with("Production credential"),
        "{}",
        card.risk
    );
    assert!(card.remember.is_none());

    // Missing declaration: a second item without one.
    let second = with_vault(&fx, |vault| {
        let item = vault
            .add(ItemDraft {
                title: "Second".to_owned(),
                kind: CredentialKind::ApiKey,
                notes: String::new(),
                tags: Vec::new(),
                fields: vec![Field {
                    name: "token".to_owned(),
                    value: SecretValue::new("FAKE-second-4410".to_owned()),
                    secret: true,
                }],
            })
            .expect("add");
        vault
            .set_env_binding(item.id, "SECOND_KEY", "token")
            .expect("binding");
        vault
            .set_exec_grant(
                fx.agent_id,
                item.id,
                &fx.project.display().to_string(),
                ExecMode::Bouncer,
            )
            .expect("grant");
        item.id
    });
    teach(&fx, &[second], &[None], "", &report("7"));
    let card = expect_prompt(&fx, || {
        send(
            &fx,
            &fx.token,
            vec![second],
            &report("8"),
            Some("Print the weekly report."),
        )
    });
    assert!(card.risk.contains("no declaration"), "{}", card.risk);

    assert_eq!(
        fx.model_calls.lock().expect("calls").len(),
        calls,
        "no step after the pattern asked the model"
    );
    // The hard rule denials are in the decision log as rule decisions.
    let rules = with_vault(&fx, |vault| {
        vault
            .decision_log()
            .expect("log")
            .into_iter()
            .filter(|record| record.entry.decided_by == DecidedBy::Rule)
            .count()
    });
    assert_eq!(rules, 3);
}

/// Every decision goes to the log without secret values. The export has the documented
/// fields and no secret value.
#[test]
fn decision_log_and_export_have_no_secret_values() {
    let fx = fixture(&[]);
    // The model allows.
    assert_eq!(decided_by(&run(&fx, &report("1"))), "Bouncer allowed");
    // A command and a user request that contain the secret value.
    let response = send(
        &fx,
        &fx.token,
        vec![fx.item_id],
        &report(SECRET),
        Some(&format!("Use {SECRET} for the report.")),
    );
    assert_eq!(decided_by(&response), "Bouncer allowed");
    // A hard rule denial.
    with_vault(&fx, |vault| {
        vault
            .set_exec_rule(
                fx.agent_id,
                fx.item_id,
                ExecRule {
                    forbidden_words: vec!["forbidden".to_owned()],
                    ..ExecRule::default()
                },
            )
            .expect("rule");
    });
    assert_eq!(code(&run(&fx, &report("forbidden"))), "rule_forbidden_word");
    // A grant in "ask" mode, and the owner does not answer in time.
    with_vault(&fx, |vault| {
        vault
            .set_exec_grant(
                fx.agent_id,
                fx.item_id,
                &fx.project.display().to_string(),
                ExecMode::Ask,
            )
            .expect("grant");
    });
    let denier = owner(&fx, OwnerAnswer::Deny);
    assert_eq!(code(&run(&fx, &report("2"))), "approval_denied");
    // "Approve and remember" is not offered for a grant in "ask" mode.
    assert!(denier.join().expect("owner").remember.is_none());

    let (log, export, days) = with_vault(&fx, |vault| {
        (
            vault.decision_log().expect("log"),
            vault.export_decisions_jsonl().expect("export"),
            vault.ask_rate_by_day(0).expect("days"),
        )
    });
    let rows: Vec<(DecidedBy, LoggedDecision, bool)> = log
        .iter()
        .map(|record| {
            (
                record.entry.decided_by,
                record.entry.decision,
                record.entry.grant_asks,
            )
        })
        .collect();
    assert_eq!(
        rows,
        vec![
            (DecidedBy::Model, LoggedDecision::Allow, false),
            (DecidedBy::Model, LoggedDecision::Allow, false),
            (DecidedBy::Rule, LoggedDecision::Deny, false),
            (DecidedBy::Owner, LoggedDecision::Deny, true),
        ]
    );
    let first = &log[0].entry;
    assert_eq!(first.user_request, "Print the weekly report.");
    assert_eq!(first.user_request_source, RequestSource::Agent);
    assert_eq!(first.cwd_rel, ".");
    assert_eq!(first.env_names, vec![ENV_NAME.to_owned()]);
    assert_eq!(first.declarations, vec![Some(staging())]);
    assert_eq!(first.fact("task_match"), Some(0.95));
    assert_eq!(first.pattern, "sh -c './report.sh --limit <number>'");
    let masked = &log[1].entry;
    assert_eq!(masked.command[2], "./report.sh --limit [apassy:secret]");
    assert_eq!(masked.user_request, "Use [apassy:secret] for the report.");
    for record in &log {
        assert!(!format!("{:?}", record.entry).contains(SECRET));
    }

    assert!(!export.contains(SECRET), "the export has no secret value");
    let lines: Vec<serde_json::Value> = export
        .lines()
        .map(|line| serde_json::from_str(line).expect("json line"))
        .collect();
    assert_eq!(lines.len(), 4);
    let mut keys: Vec<&str> = lines[0]
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec![
            "command",
            "cwd_rel",
            "decided_by",
            "decision",
            "declaration",
            "env_names",
            "model_facts",
            "rule_flags",
            "time",
            "user_request",
            "user_request_source",
        ]
    );
    assert_eq!(lines[0]["command"], "sh -c ./report.sh --limit 1");
    assert_eq!(lines[0]["declaration"][0]["environment"], "staging");
    assert_eq!(lines[3]["decided_by"], "owner");
    assert_eq!(lines[3]["decision"], "deny");

    // Ask rate: rule denials do not count.
    assert_eq!(days.len(), 1);
    assert_eq!(
        (days[0].decisions, days[0].asked, days[0].by_model),
        (3, 1, 2)
    );

    // No owner answer in time: the log keeps a denial by nobody.
    let quick = fixture_with(&[], Duration::from_millis(300));
    with_vault(&quick, |vault| {
        vault
            .set_exec_grant(
                quick.agent_id,
                quick.item_id,
                &quick.project.display().to_string(),
                ExecMode::Ask,
            )
            .expect("grant");
    });
    assert_eq!(code(&run(&quick, &report("1"))), "approval_timeout");
    let last = with_vault(&quick, |vault| vault.decision_log().expect("log"))
        .pop()
        .expect("entry")
        .entry;
    assert_eq!(
        (last.decided_by, last.decision, last.asked, last.grant_asks),
        (DecidedBy::NoAnswer, LoggedDecision::Deny, true, true)
    );
}

/// A revoked agent and a deleted item lose their patterns. A restore removes all.
#[test]
fn revoke_delete_and_restore_remove_patterns() {
    let fx = fixture(UNSURE);
    let staged = [Some(staging())];
    teach(&fx, &[fx.item_id], &staged, "", &report("1"));
    let backup = fx.dir.path().join("learning.backup");
    let restored = fx.dir.path().join("restored.db");
    with_vault(&fx, |vault| {
        // A backup locks the source vault.
        vault.backup(&backup).expect("backup");
        vault.unlock(PASS).expect("unlock");
    });
    let mut copy = Vault::restore(&backup, &restored, PASS).expect("restore");
    copy.unlock(PASS).expect("unlock");
    assert!(
        copy.patterns().expect("patterns").is_empty(),
        "a restore removes patterns"
    );
    drop(copy);
    with_vault(&fx, |vault| {
        assert_eq!(vault.patterns().expect("patterns").len(), 1);
        vault.revoke_agent(fx.agent_id).expect("revoke");
        assert!(vault.patterns().expect("patterns").is_empty());
    });
    let (agent, item) = with_vault(&fx, |vault| {
        let (agent, _token) = vault.register_agent("Second agent").expect("register");
        (agent.id, fx.item_id)
    });
    let pattern = learning::request_pattern(
        RunScope {
            agent_id: agent,
            project_dir: &fx.project,
            cwd: &fx.project,
            cwd_rel: ".",
            items: &[item],
            declarations: &staged,
            instruction: "",
        },
        &report("1"),
    )
    .expect("pattern");
    with_vault(&fx, |vault| {
        learning::remember(vault, &pattern, learning::now()).expect("remember");
        let revision = vault.details(item).expect("details").summary.revision;
        vault.delete(item, revision).expect("delete");
        assert!(vault.patterns().expect("patterns").is_empty());
    });
}

fn owner_entry(at: u64, task_match: f64, approve: bool) -> DecisionEntry {
    DecisionEntry {
        at,
        agent_id: 1,
        agent_name: "Calibration agent".to_owned(),
        project_dir: "/work/app".to_owned(),
        cwd_rel: ".".to_owned(),
        items: vec![1],
        user_request: "Continue.".to_owned(),
        user_request_source: RequestSource::Agent,
        command: vec!["./report.sh".to_owned()],
        purpose: "Report.".to_owned(),
        env_names: vec![ENV_NAME.to_owned()],
        declarations: vec![Some(staging())],
        rule_flags: Vec::new(),
        known_safe: false,
        model_facts: vec![
            ("task_match".to_owned(), task_match),
            ("writes".to_owned(), 0.5),
            ("destroy".to_owned(), 0.05),
        ],
        pattern: String::new(),
        grant_asks: false,
        asked: true,
        decision: if approve {
            LoggedDecision::Allow
        } else {
            LoggedDecision::Deny
        },
        decided_by: DecidedBy::Owner,
        remembered: false,
        policy: Thresholds::default().policy_label(),
        note: String::new(),
    }
}

/// Goal item B5: a proposal is valid only if a replay on all past decisions allows no
/// request that the owner denied. The owner applies it, and the broker uses it. The
/// production rule stays.
#[test]
fn calibration_proposal_passes_the_replay_gate_and_the_owner_applies_it() {
    let fx = fixture(&[("task_match", 0.7), ("writes", 0.5)]);
    let start = learning::now() - 100_000;
    // Too few owner decisions: no proposal.
    with_vault(&fx, |vault| {
        for at in 0..10 {
            vault
                .record_decision(&owner_entry(start + at, 0.7, true))
                .expect("record");
        }
        let proposal =
            calibration::propose(&vault.decision_log().expect("log"), Thresholds::default());
        assert!(!proposal.valid);
        assert!(proposal.reason.starts_with("Not enough owner decisions"));
        assert!(calibration::apply(vault, 0.7, learning::now()).is_err());
    });
    // The owner approves general requests at 70% and denies requests at 30% or less.
    with_vault(&fx, |vault| {
        for at in 10..60 {
            let deny = at % 10 == 0;
            vault
                .record_decision(&owner_entry(
                    start + at,
                    if deny { 0.3 } else { 0.7 },
                    !deny,
                ))
                .expect("record");
        }
    });
    let proposal = with_vault(&fx, |vault| {
        calibration::propose(&vault.decision_log().expect("log"), Thresholds::default())
    });
    assert!(proposal.valid, "{proposal:?}");
    assert_eq!(proposal.proposed, 0.7);
    assert_eq!(proposal.all_after.denied_allowed, 0);
    assert_eq!(proposal.held_out_misses(), 0);
    assert!(proposal.held_out_after.ask_rate() < proposal.held_out_before.ask_rate());

    // Before the owner applies it, the broker asks for the 70% request.
    expect_prompt(&fx, || run(&fx, &report("1")));
    with_vault(&fx, |vault| {
        calibration::apply(vault, proposal.proposed, learning::now()).expect("apply");
        assert_eq!(
            vault.calibration().expect("read").expect("some").task_match,
            0.7
        );
    });
    let response = run(&fx, &report("2"));
    assert_eq!(decided_by(&response), "Bouncer allowed");

    // A lower level than the replay supports is refused.
    with_vault(&fx, |vault| {
        let refused = calibration::apply(vault, 0.5, learning::now()).expect_err("floor");
        assert!(refused.contains("lowest level"), "{refused}");
    });

    // The production rule is not calibrated.
    let mut production = staging();
    production.environment = Environment::Production;
    with_vault(&fx, |vault| {
        vault
            .set_declaration(fx.item_id, &production)
            .expect("declaration");
    });
    let card = expect_prompt(&fx, || run(&fx, &report("3")));
    assert!(card.risk.starts_with("Production credential"));

    // A denial at 70% after the proposal: the gate fails on all past decisions.
    with_vault(&fx, |vault| {
        vault
            .record_decision(&owner_entry(learning::now(), 0.72, false))
            .expect("record");
        let records = vault.decision_log().expect("log");
        let again = calibration::evaluate(
            &records,
            Thresholds::default(),
            Thresholds { task_match: 0.7 },
        );
        assert!(!again.valid);
        assert_eq!(again.all_after.denied_allowed, 1);
        assert_eq!(again.held_out_misses(), 1);
        let refused = calibration::apply(vault, 0.7, learning::now()).expect_err("gate");
        assert!(refused.contains("allows 1 request"), "{refused}");
    });
}
