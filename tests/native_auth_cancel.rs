//! A cancel stops an owner check with Touch ID (`AuthCancel`).
//!
//! The fake helper is a shell script. It logs the request, writes its process ID, and
//! then acts on the file `mode`: it waits like an open Touch ID prompt (`hold`, the
//! default), answers and then keeps running (`answer-hold`), answers and exits
//! (`answer-exit`), or exits without an answer (`silent-exit`). The tests check that a
//! cancel kills and reaps that one process at once, that an answer near a cancel
//! gives nothing, and that the time limit and the protocol checks still work. There
//! is no real Touch ID, keychain, or vault of the owner. All data is synthetic.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use apassy::native::{AuthCancel, NativeError, NativeHelper, Timeouts};

const SCRIPT: &str = r#"#!/bin/sh
dir="$(dirname "$0")"
IFS= read -r line
printf '%s\n' "$line" >> "$dir/requests.log"
echo $$ > "$dir/pid.tmp" && mv "$dir/pid.tmp" "$dir/pid"
mode=$(cat "$dir/mode" 2>/dev/null)
case "$mode" in
answer-hold) printf '%s\n' '{"ok":true}'; : > "$dir/answered"; exec sleep 20 ;;
answer-exit) printf '%s\n' '{"ok":true}' ;;
silent-exit) exit 0 ;;
*) exec sleep 20 ;;
esac
"#;

/// The time limit of a check in these tests. A helper that stops only at this limit
/// fails the time checks below.
const LIMIT: Duration = Duration::from_secs(60);

struct Fake {
    dir: PathBuf,
}

impl Fake {
    fn new(name: &str) -> Self {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "auth-cancel-{name}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create fake dir");
        let script = dir.join("helper");
        fs::write(&script, SCRIPT).expect("write fake helper");
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).expect("chmod");
        Self { dir }
    }

    fn mode(&self, mode: &str) {
        fs::write(self.dir.join("mode"), mode).expect("write mode");
    }

    fn client(&self) -> NativeHelper {
        let path = self.dir.join("helper");
        NativeHelper::with_paths(&path, &path).with_timeouts(Timeouts {
            quick: LIMIT,
            notify: LIMIT,
            interactive: LIMIT,
        })
    }

    fn started(&self) -> bool {
        self.dir.join("pid").exists()
    }

    /// Wait until the helper got the request and wrote `file`.
    fn wait_for(&self, file: &str) {
        let start = Instant::now();
        while !self.dir.join(file).exists() {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "the helper did not write {file}"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn pid(&self) -> String {
        self.wait_for("pid");
        fs::read_to_string(self.dir.join("pid"))
            .expect("pid")
            .trim()
            .to_owned()
    }
}

impl Drop for Fake {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// True while the process exists. A zombie also exists, so false means killed and
/// reaped. The probe sends no signal to the process.
fn alive(pid: &str) -> bool {
    Command::new("/bin/kill")
        .args(["-0", pid])
        .stderr(Stdio::null())
        .status()
        .expect("run kill -0")
        .success()
}

#[test]
fn cancel_kills_and_reaps_a_waiting_helper() {
    let fake = Fake::new("hold");
    let client = fake.client();
    let cancel = AuthCancel::new();
    let worker = {
        let cancel = cancel.clone();
        thread::spawn(move || client.authenticate_cancellable("Synthetic reason", &cancel))
    };
    let pid = fake.pid();
    thread::sleep(Duration::from_millis(100));
    assert!(alive(&pid), "the prompt waits for the owner");
    assert!(!cancel.is_cancelled());

    let start = Instant::now();
    cancel.cancel();
    // `cancel` returns after the kill and the reap, not later.
    assert!(!alive(&pid), "the helper is killed and reaped");
    let result = worker.join().expect("worker");
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "{:?}",
        start.elapsed()
    );
    assert_eq!(result, Err(NativeError::Cancelled));
    assert!(cancel.is_cancelled());
    // A second cancel does nothing.
    cancel.cancel();
}

#[test]
fn a_cancelled_handle_starts_no_helper() {
    let fake = Fake::new("pre");
    let cancel = AuthCancel::new();
    cancel.cancel();
    assert_eq!(
        fake.client()
            .authenticate_cancellable("Synthetic reason", &cancel),
        Err(NativeError::Cancelled)
    );
    thread::sleep(Duration::from_millis(100));
    assert!(!fake.started(), "no helper started");
    // The client checks the reason before the handle.
    assert!(matches!(
        fake.client().authenticate_cancellable("", &cancel),
        Err(NativeError::InvalidArgument(_))
    ));
}

#[test]
fn an_answer_just_before_the_cancel_is_dropped() {
    let fake = Fake::new("late");
    fake.mode("answer-hold");
    let client = fake.client();
    let cancel = AuthCancel::new();
    let worker = {
        let cancel = cancel.clone();
        thread::spawn(move || client.authenticate_cancellable("Synthetic reason", &cancel))
    };
    let pid = fake.pid();
    fake.wait_for("answered");
    let start = Instant::now();
    cancel.cancel();
    let result = worker.join().expect("worker");
    // Without the cancel, the client waits 2 s for the helper to exit after its answer.
    assert!(
        start.elapsed() < Duration::from_millis(1500),
        "{:?}",
        start.elapsed()
    );
    assert_eq!(result, Err(NativeError::Cancelled));
    assert!(!alive(&pid), "the helper is killed and reaped");
}

#[test]
fn dropping_the_guard_cancels() {
    let fake = Fake::new("guard");
    let client = fake.client();
    let cancel = AuthCancel::new();
    let guard = cancel.cancel_on_drop();
    let worker = {
        let cancel = cancel.clone();
        thread::spawn(move || client.authenticate_cancellable("Synthetic reason", &cancel))
    };
    let pid = fake.pid();
    drop(guard);
    assert!(!alive(&pid), "the helper is killed and reaped");
    assert_eq!(worker.join().expect("worker"), Err(NativeError::Cancelled));
}

#[test]
fn a_live_handle_keeps_the_answer_the_time_limit_and_the_protocol() {
    let fake = Fake::new("live");
    let cancel = AuthCancel::new();

    fake.mode("answer-exit");
    fake.client()
        .authenticate_cancellable("Synthetic reason", &cancel)
        .expect("ok");
    // The same handle works for a second call while nobody cancels it.
    fake.client()
        .authenticate_cancellable("Synthetic reason", &cancel)
        .expect("ok again");
    assert_eq!(fake.client().authenticate("Synthetic reason"), Ok(()));

    fake.mode("silent-exit");
    assert!(matches!(
        fake.client()
            .authenticate_cancellable("Synthetic reason", &cancel),
        Err(NativeError::Protocol(_))
    ));

    fake.mode("hold");
    let _ = fs::remove_file(fake.dir.join("pid"));
    let limit = Duration::from_millis(400);
    let client = fake.client().with_timeouts(Timeouts {
        quick: limit,
        notify: limit,
        interactive: limit,
    });
    assert_eq!(
        client.authenticate_cancellable("Synthetic reason", &cancel),
        Err(NativeError::Timeout(limit))
    );
    assert!(!alive(&fake.pid()), "the time limit stops the helper");
    assert!(!cancel.is_cancelled());

    // A cancel after the calls changes nothing that came before, and stops later ones.
    cancel.cancel();
    fake.mode("answer-exit");
    assert_eq!(
        fake.client()
            .authenticate_cancellable("Synthetic reason", &cancel),
        Err(NativeError::Cancelled)
    );
    assert_eq!(fake.client().authenticate("Synthetic reason"), Ok(()));
}

#[test]
fn cancel_display_has_no_detail() {
    assert_eq!(
        NativeError::Cancelled.to_string(),
        "the native helper call was cancelled"
    );
    assert_eq!(
        format!("{:?}", AuthCancel::new()),
        "AuthCancel { cancelled: false }"
    );
}

/// The gate with a cancel handle. It needs an unlocked vault of the test.
#[cfg(all(feature = "desktop", feature = "vault"))]
mod gate {
    use super::*;

    use apassy::broker::approvals::{OwnerAction, OwnerAuthError, OwnerCheck, OwnerGate};
    use apassy::desktop::owner_store::OwnerSession;
    use tempfile::TempDir;

    const PASS: &str = "auth-cancel-pass-ok";

    fn unlocked(dir: &TempDir) -> OwnerSession {
        let mut session = OwnerSession::new();
        session
            .create_file(&dir.path().join("cancel.db"), PASS)
            .expect("create");
        session.unlock(PASS).expect("unlock");
        session
    }

    fn action() -> OwnerAction {
        OwnerAction::Reveal { item_id: 7 }
    }

    #[test]
    fn a_cancel_closes_the_prompt_and_gives_no_proof() {
        let dir = TempDir::new().expect("temp dir");
        let session = unlocked(&dir);
        let fake = Fake::new("gate-hold");
        let gate = OwnerGate::new(session.shared_vault(), Some(fake.client()));
        let cancel = AuthCancel::new();
        let worker = {
            let cancel = cancel.clone();
            thread::spawn(move || {
                gate.authorize_cancellable(action(), OwnerCheck::TouchId, &cancel)
            })
        };
        let pid = fake.pid();
        let start = Instant::now();
        cancel.cancel();
        assert!(!alive(&pid), "the helper is killed and reaped");
        let err = worker.join().expect("worker").unwrap_err();
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "{:?}",
            start.elapsed()
        );
        assert_eq!(err, OwnerAuthError::Cancelled);
        assert!(!err.passphrase_fallback());
    }

    #[test]
    fn a_touch_id_answer_near_the_cancel_gives_no_proof() {
        let dir = TempDir::new().expect("temp dir");
        let session = unlocked(&dir);
        let fake = Fake::new("gate-late");
        fake.mode("answer-hold");
        let gate = OwnerGate::new(session.shared_vault(), Some(fake.client()));
        let cancel = AuthCancel::new();
        let worker = {
            let cancel = cancel.clone();
            thread::spawn(move || {
                gate.authorize_cancellable(action(), OwnerCheck::TouchId, &cancel)
            })
        };
        let pid = fake.pid();
        fake.wait_for("answered");
        cancel.cancel();
        let err = worker.join().expect("worker").unwrap_err();
        assert_eq!(err, OwnerAuthError::Cancelled);
        assert!(!alive(&pid));
    }

    #[test]
    fn a_cancelled_handle_refuses_every_check() {
        let dir = TempDir::new().expect("temp dir");
        let session = unlocked(&dir);
        let fake = Fake::new("gate-pre");
        fake.mode("answer-exit");
        let gate = OwnerGate::new(session.shared_vault(), Some(fake.client()));
        let cancel = AuthCancel::new();
        cancel.cancel();
        for check in [OwnerCheck::TouchId, OwnerCheck::passphrase(PASS)] {
            assert_eq!(
                gate.authorize_cancellable(action(), check, &cancel)
                    .unwrap_err(),
                OwnerAuthError::Cancelled
            );
        }
        thread::sleep(Duration::from_millis(100));
        assert!(!fake.started(), "no helper started");
    }

    #[test]
    fn a_live_handle_and_the_old_call_give_a_proof() {
        let dir = TempDir::new().expect("temp dir");
        let session = unlocked(&dir);
        let fake = Fake::new("gate-ok");
        fake.mode("answer-exit");
        let gate = OwnerGate::new(session.shared_vault(), Some(fake.client()));
        let cancel = AuthCancel::new();
        let proof = gate
            .authorize_cancellable(action(), OwnerCheck::TouchId, &cancel)
            .expect("Touch ID proof");
        assert_eq!(proof.action(), &action());
        let proof = gate
            .authorize_cancellable(action(), OwnerCheck::passphrase(PASS), &cancel)
            .expect("passphrase proof");
        assert_eq!(proof.action(), &action());
        gate.authorize(action(), OwnerCheck::TouchId)
            .expect("the old call");
        // A cancel after the check takes nothing back and touches no other process.
        cancel.cancel();
        assert_eq!(proof.action(), &action());
    }
}
