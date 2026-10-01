//! A development server for the iPhone companion (ADR 0014, contract companion-v1).
//!
//! It is the Mac side for an interop test with a client in another language, such as the
//! Swift client in `ios/ApassyCompanionKit`. It makes a synthetic vault with a synthetic
//! passphrase in a temporary directory (never the vault of the owner), turns the
//! companion on, and starts the listener on `127.0.0.1` with `allow_local_peers`. The app
//! never sets that option. The temporary directory is removed when the server exits.
//!
//! ```text
//! cargo run --locked --features vault --example companion_dev -- [--port N] [--seconds N] [--approval-seconds N]
//! ```
//!
//! - `--port N`: the port. The default is 0, any free port. The link has the port.
//! - `--seconds N`: the server exits after this many seconds. The default is 600.
//! - `--approval-seconds N`: how long a run waits for a decision. The default is 120.
//!
//! # The protocol
//!
//! The driver reads lines from stdout and writes lines to stdin. Each line ends with `\n`.
//! stdout has only these lines, in this order; every value is plain ASCII.
//!
//! | Line on stdout | When |
//! | --- | --- |
//! | `PAIRING_URL=<link>` | Once, first: the pairing link of the contract (5.1), with the host `127.0.0.1`, the port, the certificate pin, and a fresh secret. The window lasts 5 minutes. |
//! | `PAIR_REQUEST device=<id>` | A valid pair request arrived (contract 5.3). The window waits for the code. |
//! | `CODE_REJECTED reason=<wrong\|closed\|no_request\|malformed> [remaining=<n>]` | The code of a `CODE` line did not pair. `wrong` has `remaining`. `closed` ends the server. |
//! | `PAIRED device=<id>` | The code was right, the passphrase owner check passed, and the device is stored. |
//! | `PAIR_FAILED reason=<text>` | The pairing window ended before the device paired. The server exits with status 1. |
//! | `RUN id=<id> remember=<true\|false>` | A synthetic run waits in the approval queue. Three lines, in this order: a run with a remember offer, a run without one, and a run for the driver to deny. |
//! | `ACCESS_REQUEST id=<id>` | An access request is open, after the three runs. The phone can deny it. |
//! | `EVENT run=<id> outcome=<approved\|approved_and_remembered\|denied\|timed_out\|invalidated>` | A run settled. |
//! | `EVENT access_request=<id> outcome=denied` | The access request is not open any more. |
//! | `DONE reason=<stdin_closed\|timeout>` | The server exits with status 0. |
//!
//! stdin has only this line:
//!
//! | Line on stdin | Meaning |
//! | --- | --- |
//! | `CODE <digits>` | The pairing code that the driver computed from the secret and both keys, as the phone would show it. It can have a space, `CODE 348 942`. The server sends it after `PAIR_REQUEST`. A `CODE` before the request gives `CODE_REJECTED reason=no_request`. The server runs the owner check with the synthetic passphrase itself. |
//!
//! Other lines are ignored. The server exits when stdin closes.
//!
//! The synthetic passphrase is not a secret. Nothing here touches the real vault, the
//! Keychain, or the network beyond the loopback address.

use std::io::{BufRead, Write};
use std::net::Ipv4Addr;
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use apassy::broker::SharedVault;
use apassy::broker::approvals::{
    ApprovalOutcome, ApprovalQueue, OwnerCheck, OwnerGate, PendingRun, RememberOffer,
};
use apassy::companion::pairing::{CodeError, PairingView};
use apassy::companion::{CompanionOptions, PairingController, start};
use apassy::contracts::CredentialKind;
use apassy::vault::{Field, ItemDraft, SecretValue, Vault};
use tempfile::TempDir;

/// A synthetic passphrase for a synthetic vault. It protects nothing.
const PASSPHRASE: &str = "apassy-companion-dev-passphrase";
const POLL: Duration = Duration::from_millis(50);

struct Args {
    port: u16,
    seconds: u64,
    approval_seconds: u64,
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        port: 0,
        seconds: 600,
        approval_seconds: 120,
    };
    let mut iter = std::env::args().skip(1);
    while let Some(flag) = iter.next() {
        let value = iter.next().ok_or_else(|| format!("{flag} needs a value"))?;
        let number = |text: &str| {
            text.parse::<u64>()
                .map_err(|_| format!("{flag} needs a number, not {text:?}"))
        };
        match flag.as_str() {
            "--port" => {
                args.port = u16::try_from(number(&value)?)
                    .map_err(|_| "--port must be at most 65535".to_owned())?;
            }
            "--seconds" => args.seconds = number(&value)?,
            "--approval-seconds" => args.approval_seconds = number(&value)?,
            _ => return Err(format!("unknown flag {flag}")),
        }
    }
    Ok(args)
}

/// Print one protocol line and flush it, so a driver that reads a pipe sees it now.
fn say(line: &str) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

/// A synthetic run. `pattern` is the remember offer, if any.
fn synthetic_run(command: &[&str], purpose: &str, pattern: Option<&str>) -> PendingRun {
    PendingRun {
        id: 0,
        agent: "Synthetic agent".to_owned(),
        command: command.iter().map(|part| (*part).to_owned()).collect(),
        cwd: "/tmp/synthetic-shop".to_owned(),
        env_names: vec!["SYNTHETIC_API_KEY".to_owned()],
        purpose: purpose.to_owned(),
        risk: "asks the owner".to_owned(),
        user_request: "Run the synthetic task.".to_owned(),
        request_source: "from the host hook".to_owned(),
        agent_request: String::new(),
        remember: pattern.map(|pattern| RememberOffer {
            pattern: pattern.to_owned(),
            approvals: 1,
            needed: 3,
        }),
    }
}

fn outcome_name(outcome: ApprovalOutcome) -> &'static str {
    match outcome {
        ApprovalOutcome::Approved => "approved",
        ApprovalOutcome::ApprovedAndRemembered => "approved_and_remembered",
        ApprovalOutcome::Denied => "denied",
        ApprovalOutcome::TimedOut => "timed_out",
        ApprovalOutcome::Invalidated => "invalidated",
    }
}

/// Put `run` in the queue on a thread, as the broker does, and print `RUN` when it waits.
/// The thread prints `EVENT` when the run settles, never before the `RUN` line.
fn spawn_run(
    queue: &Arc<ApprovalQueue>,
    vault: &SharedVault,
    epoch: [u8; 32],
    run: PendingRun,
    timeout: Duration,
) -> Result<thread::JoinHandle<()>, String> {
    let known: Vec<u64> = queue.pending().iter().map(|run| run.id).collect();
    let remember = run.remember.is_some();
    // The queue gives the run its ID. The main thread reads it from the queue and puts it
    // here after it printed the `RUN` line.
    let id_slot = Arc::new(AtomicU64::new(0));
    let (queue_for_thread, vault_for_thread, slot) =
        (Arc::clone(queue), Arc::clone(vault), Arc::clone(&id_slot));
    let handle = thread::Builder::new()
        .name("companion-dev-run".to_owned())
        .spawn(move || {
            let outcome = queue_for_thread.wait_for(run, timeout, || {
                vault_for_thread.lock().is_ok_and(|guard| {
                    guard
                        .as_ref()
                        .is_some_and(|vault| !vault.is_locked() && vault.epoch() == epoch)
                })
            });
            let begin = Instant::now();
            while slot.load(Ordering::SeqCst) == 0 && begin.elapsed() < Duration::from_secs(2) {
                thread::sleep(Duration::from_millis(5));
            }
            say(&format!(
                "EVENT run={} outcome={}",
                slot.load(Ordering::SeqCst),
                outcome_name(outcome)
            ));
        })
        .map_err(|error| error.to_string())?;
    let begin = Instant::now();
    loop {
        if let Some(waiting) = queue
            .pending()
            .into_iter()
            .find(|run| !known.contains(&run.id))
        {
            say(&format!("RUN id={} remember={remember}", waiting.id));
            id_slot.store(waiting.id, Ordering::SeqCst);
            return Ok(handle);
        }
        if begin.elapsed() > Duration::from_secs(10) {
            return Err("a synthetic run did not start to wait".to_owned());
        }
        thread::sleep(Duration::from_millis(5));
    }
}

/// Add an agent, an item, and an open access request to the synthetic vault. Returns the
/// ID of the request.
fn open_access_request(vault: &SharedVault) -> Result<u64, String> {
    let mut guard = vault.lock().map_err(|_| "the vault mutex is poisoned")?;
    let vault = guard.as_mut().ok_or("the vault is gone")?;
    let text = |error: apassy::vault::VaultError| error.to_string();
    let item = vault
        .add(ItemDraft {
            title: "Synthetic API key".to_owned(),
            kind: CredentialKind::ApiKey,
            notes: String::new(),
            tags: Vec::new(),
            fields: vec![Field {
                name: "token".to_owned(),
                value: SecretValue::new("FAKE-companion-dev-secret".to_owned()),
                secret: true,
            }],
        })
        .map_err(text)?;
    vault
        .set_env_binding(item.id, "SYNTHETIC_API_KEY", "token")
        .map_err(text)?;
    let (agent, _token) = vault.register_agent("Synthetic agent").map_err(text)?;
    vault.set_agent_sees_all(agent.id, true).map_err(text)?;
    let (id, _new) = vault
        .request_access(
            agent.id,
            item.id,
            "The user asked me to run the synthetic task.",
            "/tmp/synthetic-shop",
        )
        .map_err(text)?;
    Ok(id)
}

fn access_request_is_open(vault: &SharedVault, id: u64) -> bool {
    vault.lock().is_ok_and(|guard| {
        guard.as_ref().is_some_and(|vault| {
            vault
                .access_requests(true, 50)
                .is_ok_and(|open| open.iter().any(|request| request.id == id))
        })
    })
}

/// The next stdin line, or `None` when nothing came within `POLL`. `Err` when stdin closed.
fn next_line(lines: &mpsc::Receiver<String>) -> Result<Option<String>, ()> {
    match lines.recv_timeout(POLL) {
        Ok(line) => Ok(Some(line)),
        Err(RecvTimeoutError::Timeout) => Ok(None),
        Err(RecvTimeoutError::Disconnected) => Err(()),
    }
}

/// The end of the program: the phase 1 exit reason.
enum Phase1 {
    Paired,
    Exit(ExitCode),
}

/// Wait for the pair request and the code. Returns when the device is paired or the
/// server must exit.
fn pair(
    pairing: &PairingController,
    gate: &OwnerGate,
    lines: &mpsc::Receiver<String>,
    end: Instant,
) -> Phase1 {
    let mut announced = false;
    loop {
        if Instant::now() >= end {
            say("DONE reason=timeout");
            return Phase1::Exit(ExitCode::SUCCESS);
        }
        match pairing.view() {
            PairingView::Waiting { device_id, .. } if !announced => {
                announced = true;
                say(&format!("PAIR_REQUEST device={device_id}"));
            }
            PairingView::Closed => {
                say("PAIR_FAILED reason=window_closed");
                return Phase1::Exit(ExitCode::from(1));
            }
            _ => {}
        }
        let line = match next_line(lines) {
            Ok(Some(line)) => line,
            Ok(None) => continue,
            Err(()) => {
                say("DONE reason=stdin_closed");
                return Phase1::Exit(ExitCode::SUCCESS);
            }
        };
        let Some(typed) = line.strip_prefix("CODE ") else {
            continue;
        };
        match pairing.submit_code(typed.trim()) {
            Ok(action) => {
                let device_id = match &action {
                    apassy::broker::approvals::OwnerAction::PairCompanion { device_id, .. } => {
                        device_id.clone()
                    }
                    _ => String::new(),
                };
                let stored = gate
                    .authorize(action, OwnerCheck::passphrase(PASSPHRASE))
                    .map_err(|error| error.message())
                    .and_then(|proof| pairing.confirm(proof).map_err(|error| error.message()));
                match stored {
                    Ok(_) => {
                        say(&format!("PAIRED device={device_id}"));
                        return Phase1::Paired;
                    }
                    Err(message) => {
                        say(&format!("PAIR_FAILED reason={}", one_line(&message)));
                        return Phase1::Exit(ExitCode::from(1));
                    }
                }
            }
            Err(CodeError::Wrong { remaining }) => {
                say(&format!("CODE_REJECTED reason=wrong remaining={remaining}"));
            }
            Err(CodeError::Closed) => {
                say("CODE_REJECTED reason=closed");
                return Phase1::Exit(ExitCode::from(1));
            }
            Err(CodeError::NoRequest) => say("CODE_REJECTED reason=no_request"),
            Err(CodeError::Malformed) => say("CODE_REJECTED reason=malformed"),
        }
    }
}

fn one_line(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

fn run(args: &Args) -> Result<ExitCode, String> {
    let dir = TempDir::new().map_err(|error| error.to_string())?;
    let mut vault = Vault::create(&dir.path().join("companion-dev.db"), PASSPHRASE)
        .map_err(|e| e.to_string())?;
    vault.unlock(PASSPHRASE).map_err(|e| e.to_string())?;
    vault
        .set_companion_enabled(true)
        .map_err(|error| error.to_string())?;
    let epoch = vault.epoch();
    let shared: SharedVault = Arc::new(Mutex::new(Some(vault)));
    let queue = Arc::new(ApprovalQueue::new());
    let gate = OwnerGate::new(Arc::clone(&shared), None);
    let timeout = Duration::from_secs(args.approval_seconds);

    let mut options = CompanionOptions::new(
        Arc::clone(&shared),
        Arc::clone(&queue),
        gate.clone(),
        "Dev Mac",
        env!("CARGO_PKG_VERSION"),
        timeout,
    );
    options.allow_local_peers = true;
    options.bind = Ipv4Addr::LOCALHOST;
    options.port = Some(args.port);
    options.link_hosts = Some(vec![Ipv4Addr::LOCALHOST.to_string()]);
    let handle = start(options).map_err(|error| error.to_string())?;
    let invite = handle.pairing().open().map_err(|error| error.message())?;
    say(&format!("PAIRING_URL={}", invite.link.as_str()));

    let (sender, lines) = mpsc::channel();
    thread::Builder::new()
        .name("companion-dev-stdin".to_owned())
        .spawn(move || {
            for line in std::io::stdin().lock().lines() {
                let Ok(line) = line else { break };
                if sender.send(line).is_err() {
                    break;
                }
            }
        })
        .map_err(|error| error.to_string())?;
    let end = Instant::now() + Duration::from_secs(args.seconds);

    if let Phase1::Exit(code) = pair(handle.pairing(), &gate, &lines, end) {
        return Ok(code);
    }

    let mut runs = Vec::new();
    for (command, purpose, pattern) in [
        (
            &["npm", "run", "migrate"][..],
            "Apply the synthetic migration.",
            Some("npm run migrate"),
        ),
        (&["cargo", "test"][..], "Run the synthetic tests.", None),
        (
            &["rm", "-rf", "build"][..],
            "Clean the synthetic build.",
            None,
        ),
    ] {
        runs.push(spawn_run(
            &queue,
            &shared,
            epoch,
            synthetic_run(command, purpose, pattern),
            timeout,
        )?);
    }
    let request_id = open_access_request(&shared)?;
    say(&format!("ACCESS_REQUEST id={request_id}"));

    let mut request_open = true;
    let reason = loop {
        if Instant::now() >= end {
            break "timeout";
        }
        if request_open && !access_request_is_open(&shared, request_id) {
            request_open = false;
            say(&format!("EVENT access_request={request_id} outcome=denied"));
        }
        if next_line(&lines).is_err() {
            break "stdin_closed";
        }
    };
    // End the runs that still wait, so that their threads print and finish.
    queue.invalidate_all();
    for run in runs {
        let _ = run.join();
    }
    drop(handle);
    say(&format!("DONE reason={reason}"));
    Ok(ExitCode::SUCCESS)
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(args) => args,
        Err(message) => {
            eprintln!("companion_dev: {message}");
            return ExitCode::from(2);
        }
    };
    match run(&args) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("companion_dev: {message}");
            ExitCode::from(1)
        }
    }
}
