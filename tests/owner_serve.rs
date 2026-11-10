//! `apassy owner serve` (ADR 0045): the owner process without a window, driven through
//! a scripted console in place of the terminal. A synthetic vault and a synthetic
//! relying party only: no browser, no real account.
//!
//! The approved create and get go over the real browser socket with the browser wire,
//! and the relying party side of the test verifies the assertion signature with the
//! public key of the registration. The peer check of guarded requests is replaced by
//! [`AcceptPeers`] there, because this test process is not the root-owned browser host;
//! [`an_unverified_browser_peer_is_refused_before_any_card`] runs the real check.
#![cfg(feature = "vault")]

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use apassy::broker::BrokerOptions;
use apassy::broker::http::TlsClient;
use apassy::browser::webauthn::{TYPE_CREATE, TYPE_GET, encode_bytes};
use apassy::browser::wire::WireError;
use apassy::native::session_lock::{SessionEvent, SessionIdle};
use apassy::owner::serve::browser::{PeerCheck, SystemPeers};
use apassy::owner::serve::console::{Console, Input};
use apassy::owner::serve::instance::OwnerInstance;
use apassy::owner::serve::{Ended, ServeOptions, Unlock, serve};
use apassy::vault::Vault;
use zeroize::Zeroizing;

const PASSPHRASE: &str = "synthetic-serve-passphrase";
const RID: &str = "3b241101-e2bb-4255-8caf-4136c566a962";
const ORIGIN: &str = "https://login.example.com";
const MAIN: &str = "apassy owner serve> ";
const CARD: &str = "approve or deny> ";
const SECRET: &str = "Vault passphrase to approve: ";
const UNLOCK: &str = "Vault passphrase: ";

/// The test stands in for the browser host and its browser.
struct AcceptPeers;

impl PeerCheck for AcceptPeers {
    fn check(_stream: &UnixStream) -> Result<(), WireError> {
        Ok(())
    }
}

/// A console that answers each prompt in turn from its script, and keeps what the
/// service showed. A prompt that is not the next one in the script waits.
#[derive(Clone, Default)]
struct Script {
    answers: Arc<Mutex<VecDeque<(&'static str, String)>>>,
    shown: Arc<Mutex<Vec<String>>>,
    asked: Arc<Mutex<Vec<String>>>,
}

impl Script {
    fn new(answers: &[(&'static str, &str)]) -> Self {
        let script = Self::default();
        for (prompt, answer) in answers {
            script.push(prompt, answer);
        }
        script
    }

    fn push(&self, prompt: &'static str, answer: &str) {
        self.answers
            .lock()
            .unwrap()
            .push_back((prompt, answer.to_owned()));
    }

    fn shown(&self) -> String {
        self.shown.lock().unwrap().join("\n")
    }

    fn take(&self, prompt: &str, wait: Duration) -> Input {
        let mut answers = self.answers.lock().unwrap();
        if answers.front().is_some_and(|(next, _)| *next == prompt) {
            let (_, answer) = answers.pop_front().unwrap();
            self.asked.lock().unwrap().push(prompt.to_owned());
            return Input::Line(Zeroizing::new(answer));
        }
        drop(answers);
        thread::sleep(wait.min(Duration::from_millis(20)));
        Input::Idle
    }
}

impl Console for Script {
    fn show(&mut self, text: &str) {
        self.shown.lock().unwrap().push(text.to_owned());
    }

    fn ask(&mut self, prompt: &str, wait: Duration) -> Input {
        self.take(prompt, wait)
    }

    fn ask_secret(&mut self, prompt: &str, wait: Duration) -> Input {
        self.take(prompt, wait)
    }
}

/// A short private directory: a socket path must stay under about 100 bytes.
fn short_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("aps")
        .tempdir_in("/tmp")
        .unwrap()
}

struct Setup {
    _dir: tempfile::TempDir,
    root: PathBuf,
    vault: PathBuf,
}

impl Setup {
    fn new() -> Self {
        let dir = short_dir();
        let root = dir.path().to_path_buf();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let vault = root.join("vault.db");
        let mut created = Vault::create(&vault, PASSPHRASE).unwrap();
        created.lock().unwrap();
        Self {
            _dir: dir,
            root,
            vault,
        }
    }

    fn data(&self) -> PathBuf {
        self.root.join("data")
    }

    fn browser(&self) -> PathBuf {
        self.root.join("data").join("browser.sock")
    }

    fn options(&self, browser_wait: Duration) -> ServeOptions {
        let mut broker = BrokerOptions::with_tls(TlsClient::platform().unwrap());
        broker.transcript_roots = Vec::new();
        ServeOptions {
            vault: self.vault.clone(),
            data_dir: self.data(),
            browser_socket: self.browser(),
            agent_socket: self.root.join("data").join("broker.sock"),
            broker: Some(broker),
            browser_wait,
            idle: Duration::from_secs(120),
            lock_on_session: false,
            unlock: Unlock::Terminal,
            lock_observer: None,
        }
    }

    /// Start the service on its own thread with `P` and the console `script`.
    fn start<P: PeerCheck>(
        &self,
        options: ServeOptions,
        script: &Script,
    ) -> thread::JoinHandle<Result<Ended, String>> {
        let mut console = script.clone();
        let handle = thread::spawn(move || serve::<P>(options, &mut console));
        let started = Instant::now();
        while UnixStream::connect(self.browser()).is_err() {
            assert!(
                started.elapsed() < Duration::from_secs(30),
                "the browser socket did not start: {}",
                script.shown()
            );
            assert!(!handle.is_finished(), "serve ended: {}", script.shown());
            thread::sleep(Duration::from_millis(20));
        }
        handle
    }
}

/// One request on a new connection, as the browser host sends it, and its answer.
fn ask(socket: &Path, request: &serde_json::Value) -> serde_json::Value {
    let mut stream = UnixStream::connect(socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    let mut line = request.to_string();
    line.push('\n');
    stream.write_all(line.as_bytes()).unwrap();
    let mut answer = String::new();
    BufReader::new(stream).read_line(&mut answer).unwrap();
    serde_json::from_str(&answer).unwrap()
}

fn b64url(bytes: &[u8]) -> String {
    encode_bytes(bytes)
        .trim_end_matches('=')
        .replace('+', "-")
        .replace('/', "_")
}

fn client_json(kind: &str, challenge: &[u8]) -> String {
    format!(
        r#"{{"type":"{kind}","challenge":"{}","origin":"{ORIGIN}","crossOrigin":false}}"#,
        b64url(challenge)
    )
}

fn create_request(challenge: &[u8]) -> serde_json::Value {
    serde_json::json!({
        "v": 1,
        "cmd": "passkey_create",
        "rid": RID,
        "origin": ORIGIN,
        "rp_id": "example.com",
        "client_data_json": encode_bytes(client_json(TYPE_CREATE, challenge).as_bytes()),
        "user_handle": encode_bytes(&[1, 2, 3, 4]),
        "user_name": "owner@example.com",
        "user_display_name": "Owner",
        "algorithms": [-7],
        "excluded": [],
        "title": "Synthetic RP",
    })
}

fn get_request(challenge: &[u8], allowed: &[String]) -> serde_json::Value {
    serde_json::json!({
        "v": 1,
        "cmd": "passkey_get",
        "rid": RID,
        "origin": ORIGIN,
        "rp_id": "example.com",
        "client_data_json": encode_bytes(client_json(TYPE_GET, challenge).as_bytes()),
        "allowed": allowed,
    })
}

fn bytes(value: &serde_json::Value) -> Vec<u8> {
    apassy::browser::webauthn::decode_bytes(value.as_str().unwrap(), 1, 1 << 20).unwrap()
}

/// The uncompressed P-256 point of the COSE key in registration authenticator data.
fn public_key(auth: &[u8], credential_id: &[u8]) -> Vec<u8> {
    let length = usize::from(u16::from_be_bytes([auth[53], auth[54]]));
    assert_eq!(&auth[55..55 + length], credential_id);
    let cose: ciborium::value::Value = ciborium::de::from_reader(&auth[55 + length..]).unwrap();
    let fields = cose.as_map().unwrap();
    let coordinate = |label: i128| {
        fields
            .iter()
            .find(|(key, _)| key.as_integer().is_some_and(|i| i128::from(i) == label))
            .unwrap()
            .1
            .as_bytes()
            .unwrap()
            .clone()
    };
    let mut point = vec![4];
    point.extend(coordinate(-2));
    point.extend(coordinate(-3));
    point
}

fn wait_for(script: &Script, text: &str) {
    let started = Instant::now();
    while !script.shown().contains(text) {
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "never shown: {text}\n{}",
            script.shown()
        );
        thread::sleep(Duration::from_millis(20));
    }
}

/// The owner unlocks in the "terminal", the browser asks to create a passkey and then
/// to sign in, the owner approves each with a typed answer and the passphrase, and the
/// relying party verifies the signature with the registered key.
#[test]
fn approved_create_and_get_verify_with_the_registered_key() {
    use ring::{digest, signature};

    let setup = Setup::new();
    let script = Script::new(&[
        (UNLOCK, PASSPHRASE),
        (CARD, "approve"),
        (SECRET, PASSPHRASE),
        (CARD, "approve"),
        (SECRET, PASSPHRASE),
    ]);
    let service = setup.start::<AcceptPeers>(setup.options(Duration::from_secs(60)), &script);

    let created = ask(&setup.browser(), &create_request(&[7; 32]));
    assert_eq!(created["code"], "ok", "{created}");
    let data = &created["data"];
    assert_eq!(data["type"], "passkey_created");
    assert_eq!(data["rid"], RID);
    let credential_id = bytes(&data["credential_id"]);
    let auth = bytes(&data["authenticator_data"]);
    assert_eq!(
        &auth[..32],
        digest::digest(&digest::SHA256, b"example.com").as_ref()
    );
    assert_eq!(auth[32] & 0x05, 0x05, "user presence and verification");
    let public = public_key(&auth, &credential_id);
    // The card showed what the window's dialog shows.
    let shown = script.shown();
    for fact in [
        "Create a passkey",
        ORIGIN,
        "RP ID: example.com",
        "owner@example.com",
        "User verification",
    ] {
        assert!(shown.contains(fact), "missing {fact}:\n{shown}");
    }

    let client = client_json(TYPE_GET, &[9; 32]);
    let signed = ask(
        &setup.browser(),
        &get_request(&[9; 32], &[encode_bytes(&credential_id)]),
    );
    assert_eq!(signed["code"], "ok", "{signed}");
    let data = &signed["data"];
    assert_eq!(data["type"], "passkey");
    assert_eq!(bytes(&data["credential_id"]), credential_id);
    assert_eq!(bytes(&data["client_data_json"]), client.as_bytes());
    let assertion_auth = bytes(&data["authenticator_data"]);
    assert_eq!(assertion_auth[32] & 0x05, 0x05);
    let verify = |client_data: &[u8]| {
        let mut message = assertion_auth.clone();
        message.extend_from_slice(digest::digest(&digest::SHA256, client_data).as_ref());
        signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, &public)
            .verify(&message, &bytes(&data["signature"]))
            .is_ok()
    };
    assert!(
        verify(client.as_bytes()),
        "the relying party refused the signature"
    );
    assert!(!verify(client_json(TYPE_GET, &[10; 32]).as_bytes()));

    script.push(MAIN, "quit");
    assert_eq!(service.join().unwrap(), Ok(Ended::Quit));
    let shown = script.shown();
    assert!(shown.contains("Vault locked"), "{shown}");
    assert!(
        !shown.contains(PASSPHRASE),
        "the passphrase reached the screen"
    );
    // The service stopped: no socket answers, and the lock is free for the next one.
    assert!(UnixStream::connect(setup.browser()).is_err());
    assert!(OwnerInstance::acquire(&setup.data()).is_ok());
}

/// A typed deny refuses: the browser gets `cancelled`, and no passkey is made.
#[test]
fn a_denied_create_makes_nothing() {
    let setup = Setup::new();
    let script = Script::new(&[(UNLOCK, PASSPHRASE), (CARD, "approve 2"), (CARD, "deny")]);
    let service = setup.start::<AcceptPeers>(setup.options(Duration::from_secs(60)), &script);
    let answer = ask(&setup.browser(), &create_request(&[3; 32]));
    assert_eq!(answer["code"], "cancelled", "{answer}");
    assert!(script.shown().contains("Type exactly one of the answers"));
    script.push(MAIN, "lock");
    assert_eq!(service.join().unwrap(), Ok(Ended::Quit));
    let mut vault = Vault::open(&setup.vault).unwrap();
    vault.unlock(PASSPHRASE).unwrap();
    assert!(vault.passkeys("example.com", &[]).unwrap().is_empty());
}

/// A wrong passphrase is no approval; three end the card with `owner_check_failed`.
#[test]
fn wrong_passphrases_refuse_the_request() {
    let setup = Setup::new();
    let script = Script::new(&[
        (UNLOCK, PASSPHRASE),
        (CARD, "approve"),
        (SECRET, "wrong-1"),
        (SECRET, "wrong-2"),
        (SECRET, "wrong-3"),
    ]);
    let service = setup.start::<AcceptPeers>(setup.options(Duration::from_secs(60)), &script);
    let answer = ask(&setup.browser(), &create_request(&[4; 32]));
    assert_eq!(answer["code"], "owner_check_failed", "{answer}");
    script.push(MAIN, "quit");
    service.join().unwrap().unwrap();
    assert!(!script.shown().contains("wrong-1"));
}

/// Nobody answers: the card closes at the browser's wait, the browser gets
/// `cancelled`, and a late approval cannot sign.
#[test]
fn an_unanswered_request_times_out() {
    let setup = Setup::new();
    let script = Script::new(&[(UNLOCK, PASSPHRASE)]);
    let service = setup.start::<AcceptPeers>(setup.options(Duration::from_secs(1)), &script);
    let started = Instant::now();
    let answer = ask(&setup.browser(), &create_request(&[5; 32]));
    assert_eq!(answer["code"], "cancelled", "{answer}");
    assert!(started.elapsed() < Duration::from_secs(20));
    wait_for(&script, "timed out");
    script.push(MAIN, "quit");
    service.join().unwrap().unwrap();
}

/// The real peer check: this test process is not the browser host that a verified
/// browser started, so a passkey request gets `unsupported` before any card, and the
/// browser can use its own passkeys. The socket is private to this user.
#[test]
fn an_unverified_browser_peer_is_refused_before_any_card() {
    let setup = Setup::new();
    let script = Script::new(&[(UNLOCK, PASSPHRASE)]);
    let service = setup.start::<SystemPeers>(setup.options(Duration::from_secs(60)), &script);
    let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&setup.browser()), 0o600);
    assert_eq!(mode(&setup.data()), 0o700);
    for request in [
        create_request(&[6; 32]),
        get_request(&[6; 32], &[]),
        serde_json::json!({"v": 1, "cmd": "fill_code", "url": "https://example.com/", "item": 1}),
    ] {
        let answer = ask(&setup.browser(), &request);
        assert_eq!(answer["code"], "unsupported", "{answer}");
    }
    // An unguarded request still works for the same user.
    let status = ask(
        &setup.browser(),
        &serde_json::json!({"v": 1, "cmd": "status"}),
    );
    assert_eq!(status["data"]["vault"], "unlocked", "{status}");
    script.push(MAIN, "quit");
    service.join().unwrap().unwrap();
    assert!(!script.shown().contains("A request waits for you"));
}

/// One owner process per data directory: while one runs (here: the lock that the
/// desktop window or another service holds), a second refuses before it opens the
/// vault, with a clear message.
#[test]
fn a_second_owner_process_is_refused() {
    let setup = Setup::new();
    let first = OwnerInstance::acquire(&setup.data()).unwrap();
    let mut script = Script::new(&[(UNLOCK, PASSPHRASE)]);
    let error =
        serve::<AcceptPeers>(setup.options(Duration::from_secs(5)), &mut script).unwrap_err();
    assert!(error.contains("Another Apassy owner process"), "{error}");
    assert!(
        script.asked.lock().unwrap().is_empty(),
        "it asked for the passphrase"
    );
    drop(first);
}

/// The inactivity time locks the vault and ends the service.
#[test]
fn the_inactivity_time_locks_and_ends() {
    let setup = Setup::new();
    let script = Script::new(&[(UNLOCK, PASSPHRASE)]);
    let mut options = setup.options(Duration::from_secs(5));
    options.idle = Duration::from_secs(1);
    let service = setup.start::<AcceptPeers>(options, &script);
    assert_eq!(service.join().unwrap(), Ok(Ended::Idle));
    assert!(UnixStream::connect(setup.browser()).is_err());
}

/// A switch that a test turns on, and the events that a fake observer then reports.
fn fake_observer(
    events: Vec<SessionEvent>,
) -> (
    Arc<std::sync::atomic::AtomicBool>,
    Box<dyn apassy::owner::serve::LockObserver>,
) {
    let fire = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let fired = Arc::clone(&fire);
    let observer = move || {
        if fired.swap(false, std::sync::atomic::Ordering::SeqCst) {
            events.clone()
        } else {
            Vec::new()
        }
    };
    (fire, Box::new(observer))
}

/// Unit L2's session events: with the device policy "When the screen locks or the
/// computer sleeps", each locking event locks the vault and ends the service.
#[test]
fn a_session_event_locks_and_ends_with_the_session_policy() {
    for (event, reason) in [
        (SessionEvent::ScreenLocked, "because the screen locked"),
        (SessionEvent::Sleep, "because the computer slept"),
        (
            SessionEvent::SessionInactive,
            "because another session became active",
        ),
        (
            SessionEvent::SessionEnded,
            "because the login session ended",
        ),
    ] {
        let setup = Setup::new();
        let script = Script::new(&[(UNLOCK, PASSPHRASE)]);
        let mut options = setup.options(Duration::from_secs(5));
        options.lock_on_session = true;
        let (fire, observer) = fake_observer(vec![SessionEvent::ScreenUnlocked, event]);
        options.lock_observer = Some(observer);
        let service = setup.start::<AcceptPeers>(options, &script);
        fire.store(true, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(service.join().unwrap(), Ok(Ended::Session(event)));
        assert!(
            script.shown().contains(&format!("Vault locked {reason}")),
            "{event:?}: {}",
            script.shown()
        );
        assert!(UnixStream::connect(setup.browser()).is_err());
    }
}

/// Without the session policy a screen lock or a sleep does not end the service, and
/// events that do not lock (unlock, active, a lost source) never do.
#[test]
fn session_events_do_not_end_the_service_without_the_session_policy() {
    let setup = Setup::new();
    let script = Script::new(&[(UNLOCK, PASSPHRASE)]);
    let mut options = setup.options(Duration::from_secs(5));
    let (fire, observer) = fake_observer(vec![
        SessionEvent::ScreenLocked,
        SessionEvent::Sleep,
        SessionEvent::SourceLost,
    ]);
    options.lock_observer = Some(observer);
    let service = setup.start::<AcceptPeers>(options, &script);
    fire.store(true, std::sync::atomic::Ordering::SeqCst);
    let started = Instant::now();
    while fire.load(std::sync::atomic::Ordering::SeqCst) {
        assert!(started.elapsed() < Duration::from_secs(10), "never polled");
        thread::sleep(Duration::from_millis(20));
    }
    thread::sleep(Duration::from_millis(300));
    script.push(MAIN, "quit");
    assert_eq!(service.join().unwrap(), Ok(Ended::Quit));

    let setup = Setup::new();
    let script = Script::new(&[(UNLOCK, PASSPHRASE)]);
    let mut options = setup.options(Duration::from_secs(5));
    options.lock_on_session = true;
    let (fire, observer) = fake_observer(vec![
        SessionEvent::ScreenUnlocked,
        SessionEvent::SessionActive,
        SessionEvent::SourceLost,
        SessionEvent::Idle(SessionIdle::Idle),
    ]);
    options.lock_observer = Some(observer);
    let service = setup.start::<AcceptPeers>(options, &script);
    fire.store(true, std::sync::atomic::Ordering::SeqCst);
    let started = Instant::now();
    while fire.load(std::sync::atomic::Ordering::SeqCst) {
        assert!(started.elapsed() < Duration::from_secs(10), "never polled");
        thread::sleep(Duration::from_millis(20));
    }
    thread::sleep(Duration::from_millis(300));
    script.push(MAIN, "quit");
    assert_eq!(service.join().unwrap(), Ok(Ended::Quit));
}

/// When the desktop's idle hint says the session is active (the owner works in another
/// app), the inactivity time does not lock, as on the desktop. A lost source returns
/// to typed input only, and the inactivity time locks again.
#[test]
fn an_active_idle_hint_keeps_the_service_open_until_the_source_is_lost() {
    let setup = Setup::new();
    let script = Script::new(&[(UNLOCK, PASSPHRASE)]);
    let mut options = setup.options(Duration::from_secs(5));
    options.idle = Duration::from_secs(1);
    let lost = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let lose = Arc::clone(&lost);
    let observer = move || {
        if lose.load(std::sync::atomic::Ordering::SeqCst) {
            vec![SessionEvent::SourceLost]
        } else {
            vec![SessionEvent::Idle(SessionIdle::Active)]
        }
    };
    options.lock_observer = Some(Box::new(observer));
    let service = setup.start::<AcceptPeers>(options, &script);
    thread::sleep(Duration::from_millis(2500));
    assert!(
        !service.is_finished(),
        "an active session must keep the vault open"
    );
    let locked_at = Instant::now();
    lost.store(true, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(service.join().unwrap(), Ok(Ended::Idle));
    assert!(locked_at.elapsed() < Duration::from_secs(5));
}
