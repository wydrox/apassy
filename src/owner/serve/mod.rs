//! `apassy owner serve`: the owner process without a window (ADR 0045).
//!
//! The owner unlocks the vault with the passphrase in a terminal. The service then
//! hosts what the desktop window hosts for the browser and for agents, with the same
//! code: the agent broker ([`crate::broker::start_with`], `broker.sock`) for runs with
//! secrets, access requests and bouncer questions, and the browser socket
//! ([`browser`], `browser.sock`) for passkeys, fills and saves, with the same peer
//! checks and the same private socket and file modes. The vault session is the
//! window's [`OwnerSession`].
//!
//! Each request that needs the owner shows as a card in the terminal with the facts
//! of the window's card, and is approved only by a typed `approve` and then the vault
//! passphrase (or, on Linux, `approve polkit`), checked by
//! [`OwnerGate::authorize`] for that one action. There is no owner window: no answer
//! is reused for another request. The browser's wait, the broker's question time and a
//! hang-up end a card as in the window.
//!
//! The service ends and locks the vault on `lock`, `quit`, the end of the terminal, the
//! inactivity time, and, with the device policy "When the screen locks or the computer
//! sleeps", a screen lock, sleep, user switch or session end ([`lock`], unit L2).
//! SIGTERM, SIGHUP and SIGINT keep their default action: the process ends at once, so
//! the kernel frees the key memory (no core file: [`crate::harden`]), closes the sockets
//! and releases the owner lock ([`instance`]). The vault file needs no lock step: the
//! key lives only in this process. Waiting agent runs and browser requests see a closed
//! socket. The crate forbids `unsafe`, and no safe API installs a signal handler. A
//! later start removes the stale socket files.
//!
//! Without a terminal on stdin and stdout the service refuses to start
//! ([`console::TtyConsole::open`]): no approval can come from a pipe, a file,
//! `/dev/null` or a service manager.

pub mod browser;
pub mod console;
pub mod instance;
pub mod lock;

use std::collections::{BTreeSet, VecDeque};
use std::path::PathBuf;
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use self::browser::{
    BrowserCard, HeadlessRequest, HeadlessWire, Intake, PeerCheck, clean_text, page_text,
};
use self::console::{Console, Input};
use self::instance::OwnerInstance;
pub use self::lock::{DEFAULT_IDLE, LockObserver, LockSettings};
use self::lock::{event_reason, sleep_inclusive_now};
use crate::broker::approvals::{OwnerAction, OwnerCheck, OwnerGate, PendingRun};
use crate::broker::{BrokerHandle, BrokerOptions};
use crate::browser::wire::Response;
use crate::native::session_lock::{LockRule, SessionEvent, SessionLock};
use crate::owner::owner_store::OwnerSession;
use crate::owner::socket::{self, Envelope, OwnerSocket};
use crate::vault::{AccessRequest, ExecMode, GrantPlace};

/// How often the service looks at its requests, the time, and the lock hook.
const TICK: Duration = Duration::from_millis(100);
/// A browser card closes this long before the socket stops waiting, as in the window.
const BROWSER_MARGIN: Duration = Duration::from_secs(15);
/// How often the open access requests are read from the vault.
const ACCESS_POLL: Duration = Duration::from_secs(2);
/// Wrong passphrases for one card before it is refused.
const MAX_TRIES: u32 = 3;

/// The session observer of this system for the service (unit L2, [`lock`]): D-Bus in a
/// build with the `session-bus` feature, else the clock gap that shows a past sleep.
/// [`ServeOptions::system`] calls this, and the loop polls the result on every tick.
pub fn lock_observer() -> Option<Box<dyn LockObserver>> {
    Some(lock::system_observer())
}

/// How the vault is unlocked at the start.
pub enum Unlock {
    /// The passphrase, typed in the terminal without echo.
    Terminal,
    /// A passphrase that the explicit Secret Service opt-in returned
    /// (`apassy owner keyring-enable`). Approvals still need the passphrase or polkit.
    Given(Zeroizing<String>),
}

/// The settings of one service.
pub struct ServeOptions {
    pub vault: PathBuf,
    /// The data directory: its `owner.lock` allows one owner process.
    pub data_dir: PathBuf,
    pub browser_socket: PathBuf,
    pub agent_socket: PathBuf,
    /// `None`: the platform settings of the window's broker.
    pub broker: Option<BrokerOptions>,
    /// How long a browser card waits for the owner.
    pub browser_wait: Duration,
    /// Lock and end after this long without a typed line (on the sleep-inclusive
    /// clock: time asleep counts).
    pub idle: Duration,
    /// Also lock and end at a screen lock, sleep, user switch or session end.
    pub lock_on_session: bool,
    pub unlock: Unlock,
    pub lock_observer: Option<Box<dyn LockObserver>>,
}

impl ServeOptions {
    /// The sockets and the data directory of this user, as the window uses them, and
    /// the system's session observer.
    pub fn system(vault: PathBuf, lock: &LockSettings, unlock: Unlock) -> Self {
        Self {
            vault,
            data_dir: crate::paths::data_dir(),
            browser_socket: crate::browser::wire::default_socket_path(),
            agent_socket: crate::agent::client::default_socket_path(),
            broker: None,
            browser_wait: socket::REPLY_TIMEOUT.saturating_sub(BROWSER_MARGIN),
            idle: lock.idle,
            lock_on_session: lock.on_session_lock,
            unlock,
            lock_observer: lock_observer(),
        }
    }
}

/// Why the service ended. The vault is locked in each case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ended {
    /// `lock`, `quit` or `exit`.
    Quit,
    /// The terminal closed.
    TerminalClosed,
    /// No typed line for the inactivity time.
    Idle,
    /// A session event locked the vault (the device policy "When the screen locks or
    /// the computer sleeps").
    Session(SessionEvent),
}

/// Run the service until it ends. The caller checks that this is an interactive
/// terminal (the console does). `P` is the peer check of guarded browser requests:
/// [`browser::SystemPeers`] in the program.
pub fn serve<P: PeerCheck>(
    mut options: ServeOptions,
    console: &mut dyn Console,
) -> Result<Ended, String> {
    let _instance = OwnerInstance::acquire(&options.data_dir).map_err(|e| e.to_string())?;
    let mut session = OwnerSession::new();
    session
        .open_file(&options.vault)
        .map_err(|e| format!("The vault did not open: {}", e.message))?;
    match std::mem::replace(&mut options.unlock, Unlock::Terminal) {
        Unlock::Given(passphrase) => session
            .unlock(&passphrase)
            .map_err(|e| format!("The vault did not unlock: {}", e.message))?,
        Unlock::Terminal => unlock_in_terminal(&mut session, console)?,
    }
    let broker = match options.broker.take() {
        Some(broker) => {
            crate::broker::start_with(session.shared_vault(), &options.agent_socket, broker)
        }
        None => crate::broker::start(session.shared_vault(), &options.agent_socket),
    };
    let broker = match broker {
        Ok(broker) => broker,
        Err(err) => {
            let _ = session.lock();
            return Err(socket_error("agent", &options.agent_socket, &err));
        }
    };
    let (browser_socket, inbox) =
        match socket::start_line::<HeadlessWire<P>>(&options.browser_socket, || {}) {
            Ok(started) => started,
            Err(err) => {
                let _ = session.lock_ending_runs(Some(broker.approvals().as_ref()), ENDED_HERE);
                return Err(socket_error("browser", &options.browser_socket, &err));
            }
        };
    let mut host = Host {
        console,
        session,
        broker,
        browser_socket: Some(browser_socket),
        inbox,
        browser_wait: options.browser_wait,
        idle: options.idle,
        inactivity: SessionLock::new(LockRule::After(options.idle), sleep_inclusive_now()),
        lock_on_session: options.lock_on_session,
        observer: options.lock_observer.take(),
        queue: VecDeque::new(),
        seen_runs: BTreeSet::new(),
        seen_access: BTreeSet::new(),
        access_read: None,
    };
    host.console.show(&format!(
        "Vault unlocked. Apassy serves the browser at {} and agents at {} until you type lock or quit, close this terminal, {}after {} minutes without input. Requests that need you show here. Type help for the commands.",
        options.browser_socket.display(),
        options.agent_socket.display(),
        if options.lock_on_session {
            "the screen locks, the computer sleeps, "
        } else {
            "or "
        },
        options.idle.as_secs().div_ceil(60)
    ));
    let ended = host.run();
    host.end(&ended);
    Ok(ended)
}

const ENDED_HERE: &str = "The vault was locked in apassy owner serve.";

fn socket_error(name: &str, path: &std::path::Path, err: &std::io::Error) -> String {
    if matches!(
        err.kind(),
        std::io::ErrorKind::AddrInUse | std::io::ErrorKind::AlreadyExists
    ) {
        format!(
            "The {name} socket {} is in use: another Apassy owner process (the desktop app or apassy owner serve) runs. Quit it first.",
            path.display()
        )
    } else {
        format!(
            "The {name} socket did not start at {}: {err}",
            path.display()
        )
    }
}

fn unlock_in_terminal(session: &mut OwnerSession, console: &mut dyn Console) -> Result<(), String> {
    for _ in 0..MAX_TRIES {
        let passphrase = loop {
            match console.ask_secret("Vault passphrase: ", Duration::from_secs(60)) {
                Input::Line(line) => break line,
                Input::Idle => continue,
                Input::Closed => return Err("The terminal closed. The vault stays locked.".into()),
            }
        };
        match session.unlock(&passphrase) {
            Ok(()) => return Ok(()),
            Err(err) => console.show(&format!("The vault did not unlock: {}", err.message)),
        }
    }
    Err("The vault did not unlock. It stays locked.".into())
}

/// One request that waits for the owner.
enum Card {
    Browser(Box<BrowserCard>),
    Run(Box<PendingRun>),
    Access(Box<AccessRequest>),
}

/// The answer of the owner to a card.
enum Answer {
    Approve { choice: usize, polkit: bool },
    Grant { any_folder: bool, polkit: bool },
    Deny,
    Later,
}

/// What a card did to the loop.
enum Flow {
    Next,
    End(Ended),
}

struct Host<'a> {
    console: &'a mut dyn Console,
    session: OwnerSession,
    broker: BrokerHandle,
    browser_socket: Option<OwnerSocket>,
    inbox: Receiver<Envelope<HeadlessRequest, Response>>,
    browser_wait: Duration,
    idle: Duration,
    /// The inactivity rule: typed lines are owner input, the idle hint can postpone.
    inactivity: SessionLock,
    lock_on_session: bool,
    observer: Option<Box<dyn LockObserver>>,
    queue: VecDeque<Card>,
    seen_runs: BTreeSet<u64>,
    seen_access: BTreeSet<u64>,
    access_read: Option<Instant>,
}

impl Host<'_> {
    fn run(&mut self) -> Ended {
        loop {
            if let Some(ended) = self.must_end() {
                return ended;
            }
            self.take_browser(false);
            self.take_runs();
            self.take_access(false);
            if let Some(card) = self.queue.pop_front() {
                match self.decide(card) {
                    Flow::Next => continue,
                    Flow::End(ended) => return ended,
                }
            }
            match self.console.ask("apassy owner serve> ", TICK) {
                Input::Line(line) => {
                    self.input();
                    if let Some(ended) = self.command(line.trim()) {
                        return ended;
                    }
                }
                Input::Idle => {}
                Input::Closed => return Ended::TerminalClosed,
            }
        }
    }

    /// The session events and the inactivity time.
    fn must_end(&mut self) -> Option<Ended> {
        let now = sleep_inclusive_now();
        if let Some(observer) = self.observer.as_mut() {
            let events = observer.events();
            let mut ended = None;
            for event in &events {
                if ended.is_none() && self.lock_on_session && event.locks_session() {
                    ended = Some(Ended::Session(*event));
                }
                // The idle hint and a lost source change the inactivity rule.
                let _ = self.inactivity.event(*event, now);
            }
            if ended.is_some() {
                // `end` locks the vault, then lets a held sleep go.
                return ended;
            }
            if events.contains(&SessionEvent::Sleep) {
                observer.sleep_decided();
            }
        }
        self.inactivity.due(now).map(|_| Ended::Idle)
    }

    fn input(&mut self) {
        self.inactivity.input(sleep_inclusive_now());
    }

    fn command(&mut self, line: &str) -> Option<Ended> {
        match line {
            "" => {}
            "lock" | "quit" | "exit" => return Some(Ended::Quit),
            "help" => self.console.show(
                "Commands: status (what waits), requests (show the open access requests again), lock or quit (lock the vault and stop). Each request shows as a card; answer it with approve or deny.",
            ),
            "status" => {
                let runs = self.broker.approvals().pending().len();
                let access = self.session.access_requests(true).map_or(0, |r| r.len());
                self.console.show(&format!(
                    "Vault unlocked. {runs} runs wait for you, {access} access requests are open. Locks after {} minutes without input.",
                    self.idle.as_secs().div_ceil(60)
                ));
            }
            "requests" => {
                self.seen_access.clear();
                self.take_access(true);
                if self.queue.is_empty() {
                    self.console.show("No access request is open.");
                }
            }
            // The line is never written back: it can be a mistyped secret.
            _ => self.console.show("Unknown command. Type help."),
        }
        None
    }

    /// New browser requests. While a card is open (`busy`), each request that needs the
    /// owner gets `busy`, as a second dialog does in the window.
    fn take_browser(&mut self, busy: bool) {
        let envelopes: Vec<_> = self.inbox.try_iter().collect();
        for Envelope { request, reply } in envelopes {
            let HeadlessRequest { command, gone } = request;
            let deadline = Instant::now() + self.browser_wait;
            match browser::intake(&self.session, command, reply, gone, deadline) {
                Intake::Answered => {}
                Intake::Card(mut card) => {
                    let waiting = busy
                        || self
                            .queue
                            .iter()
                            .any(|card| matches!(card, Card::Browser(_)));
                    if waiting {
                        card.send(Response::error(
                            "busy",
                            "Another request waits for the owner in the terminal. Finish it, then try again.",
                        ));
                    } else {
                        self.queue.push_back(Card::Browser(card));
                    }
                }
            }
        }
    }

    fn take_runs(&mut self) {
        let pending = self.broker.approvals().pending();
        let ids: BTreeSet<u64> = pending.iter().map(|run| run.id).collect();
        self.seen_runs.retain(|id| ids.contains(id));
        for run in pending {
            if self.seen_runs.insert(run.id) {
                self.queue.push_back(Card::Run(Box::new(run)));
            }
        }
    }

    fn take_access(&mut self, now: bool) {
        if !now
            && self
                .access_read
                .is_some_and(|at| at.elapsed() < ACCESS_POLL)
        {
            return;
        }
        self.access_read = Some(Instant::now());
        let Ok(open) = self.session.access_requests(true) else {
            return;
        };
        for request in open {
            if self.seen_access.insert(request.id) {
                self.queue.push_back(Card::Access(Box::new(request)));
            }
        }
    }

    /// The card is still the request that waits.
    fn live(&self, card: &Card) -> Result<(), String> {
        match card {
            Card::Browser(card) if card.hung_up() => Err(
                "The browser stopped waiting (the page closed or the request was cancelled)."
                    .into(),
            ),
            Card::Browser(card) if !card.is_live() => {
                Err("The request timed out. The browser got cancelled.".into())
            }
            Card::Browser(_) => Ok(()),
            Card::Run(run) => {
                if self
                    .broker
                    .approvals()
                    .pending()
                    .iter()
                    .any(|waiting| waiting == &**run)
                {
                    Ok(())
                } else {
                    Err("The run is no longer waiting: it timed out, the agent cancelled it, or it changed.".into())
                }
            }
            Card::Access(request) => match self.session.access_requests(true) {
                Ok(open) if open.iter().any(|r| r.id == request.id) => Ok(()),
                _ => Err("The access request is no longer open.".into()),
            },
        }
    }

    fn show_card(&mut self, card: &Card) {
        let mut text = String::from("\n--- A request waits for you ---\n");
        let facts: Vec<(&str, String)> = match card {
            Card::Browser(card) => card.op.facts(),
            Card::Run(run) => run_facts(run),
            Card::Access(request) => access_facts(request),
        };
        for (label, value) in facts {
            text.push_str(&format!("{label:>18}: {value}\n"));
        }
        text.push_str(match card {
            Card::Access(_) => {
                "Type grant (in the folder of the request), grant any (any folder), deny, or later."
            }
            Card::Browser(card) if card.op.choices() > 1 => {
                "Type approve NUMBER (the account) or deny. Then confirm with the vault passphrase."
            }
            _ => "Type approve or deny. Then confirm with the vault passphrase.",
        });
        if cfg!(target_os = "linux") {
            text.push_str(
                " Add polkit (approve polkit) to confirm with system authentication instead.",
            );
        }
        self.console.show(&text);
    }

    fn decide(&mut self, mut card: Card) -> Flow {
        self.show_card(&card);
        let answer = loop {
            if let Some(ended) = self.must_end() {
                return Flow::End(ended);
            }
            self.take_browser(true);
            self.take_runs();
            if let Err(why) = self.live(&card) {
                self.console.discard_typed();
                self.console.show(&format!("Closed: {why}"));
                return Flow::Next;
            }
            let prompt = match card {
                Card::Access(_) => "grant, grant any, deny or later> ",
                _ => "approve or deny> ",
            };
            match self.console.ask(prompt, TICK) {
                Input::Line(line) => {
                    self.input();
                    match parse_answer(line.trim(), &card) {
                        Some(answer) => break answer,
                        None => self.console.show("Type exactly one of the answers above."),
                    }
                }
                Input::Idle => {}
                Input::Closed => return Flow::End(Ended::TerminalClosed),
            }
        };
        let (action, polkit) = match (&answer, &mut card) {
            (Answer::Later, _) => {
                self.console
                    .show("It stays open. Type requests to see it again.");
                return Flow::Next;
            }
            (Answer::Deny, card) => {
                let text = self.deny(card);
                self.console.show(&text);
                return Flow::Next;
            }
            (Answer::Approve { choice, polkit }, Card::Browser(browser)) => {
                match browser.op.action(*choice) {
                    Some(action) => (action, *polkit),
                    None => {
                        self.console
                            .show("There is no account with that number. Nothing was signed.");
                        return Flow::Next;
                    }
                }
            }
            (Answer::Approve { polkit, .. }, Card::Run(run)) => {
                (OwnerAction::ApproveRun(PendingRun::clone(run)), *polkit)
            }
            (Answer::Grant { any_folder, polkit }, Card::Access(request)) => {
                match self.grant_action(request, *any_folder) {
                    Ok(action) => (action, *polkit),
                    Err(why) => {
                        self.console.show(&why);
                        return Flow::Next;
                    }
                }
            }
            _ => return Flow::Next,
        };
        for _ in 0..MAX_TRIES {
            let check = if polkit {
                match polkit_check() {
                    Some(check) => check,
                    None => {
                        self.console.show(
                            "polkit is not available here. Confirm with the vault passphrase.",
                        );
                        return Flow::Next;
                    }
                }
            } else {
                let passphrase = loop {
                    if let Some(ended) = self.must_end() {
                        return Flow::End(ended);
                    }
                    self.take_browser(true);
                    self.take_runs();
                    if let Err(why) = self.live(&card) {
                        self.console.discard_typed();
                        self.console.show(&format!("Closed: {why}"));
                        return Flow::Next;
                    }
                    match self
                        .console
                        .ask_secret("Vault passphrase to approve: ", TICK)
                    {
                        Input::Line(line) => break line,
                        Input::Idle => {}
                        Input::Closed => return Flow::End(Ended::TerminalClosed),
                    }
                };
                self.input();
                OwnerCheck::passphrase(&passphrase)
            };
            let gate = OwnerGate::new(self.session.shared_vault(), None)
                .with_window(self.session.owner_window.clone());
            match gate.authorize(action.clone(), check) {
                Ok(proof) => {
                    if let Err(why) = self.live(&card) {
                        drop(proof);
                        self.console.show(&format!("Closed: {why}"));
                        return Flow::Next;
                    }
                    let text = self.complete(&mut card, &action, proof);
                    self.console.show(&text);
                    return Flow::Next;
                }
                Err(err) => {
                    self.console
                        .show(&format!("Not approved: {}", err.message()));
                    if polkit {
                        return Flow::Next;
                    }
                }
            }
        }
        self.console
            .show("Not approved: too many wrong passphrases. The request is refused.");
        if let Card::Browser(browser) = &mut card {
            browser.send(Response::error(
                "owner_check_failed",
                "The owner check failed. Nothing changed.",
            ));
        }
        Flow::Next
    }

    fn deny(&mut self, card: &mut Card) -> String {
        match card {
            Card::Browser(browser) => {
                browser.send(Response::error(
                    "cancelled",
                    "The owner refused in the terminal. Nothing changed.",
                ));
                "Refused. The browser got cancelled.".into()
            }
            Card::Run(run) => {
                if self.broker.approvals().deny(run.id) {
                    "Denied. The run does not start.".into()
                } else {
                    "The run was no longer waiting.".into()
                }
            }
            Card::Access(request) => match self.session.deny_access_request(request.id) {
                Ok(()) => "The request is denied.".into(),
                Err(err) => format!("Not denied: {}", err.message),
            },
        }
    }

    fn grant_action(
        &self,
        request: &AccessRequest,
        any_folder: bool,
    ) -> Result<OwnerAction, String> {
        if self
            .session
            .process_binding(request.item_id)
            .map_err(|e| e.message)?
            .is_none()
        {
            return Err(format!(
                "\"{}\" has no variable for processes yet. Set one in the desktop app, then grant again.",
                page_text(&request.item_name)
            ));
        }
        let place = if any_folder {
            GrantPlace::AnyFolder
        } else if request.cwd.trim().is_empty() {
            return Err(
                "The request names no folder. Type grant any to allow it in any folder, or deny."
                    .into(),
            );
        } else {
            crate::owner::owner_store::checked_place(&GrantPlace::Folder(request.cwd.clone()))
                .map_err(|e| e.message)?
        };
        Ok(OwnerAction::GrantAccessRequest {
            request_id: request.id,
            agent_id: request.agent_id,
            item_id: request.item_id,
            place,
            mode: ExecMode::Ask,
        })
    }

    fn complete(
        &mut self,
        card: &mut Card,
        action: &OwnerAction,
        proof: crate::broker::approvals::OwnerProof,
    ) -> String {
        match card {
            Card::Browser(browser) => browser::complete(&mut self.session, browser, action, proof),
            Card::Run(_) => match self.broker.approvals().approve(proof) {
                Ok(()) => "Approved. The run starts.".into(),
                Err(refusal) => format!("Not approved: {}", refusal.message()),
            },
            Card::Access(request) => {
                let OwnerAction::GrantAccessRequest { place, mode, .. } = action else {
                    return "Not granted.".into();
                };
                match self
                    .session
                    .grant_access_request(request.id, place, *mode, proof)
                {
                    Ok(()) => format!(
                        "Granted: {} may ask to use \"{}\" in {}. Each run asks you here.",
                        page_text(&request.agent_name),
                        page_text(&request.item_name),
                        place.describe()
                    ),
                    Err(err) => format!("Not granted: {}", err.message),
                }
            }
        }
    }

    /// Lock the vault and stop the sockets. Each waiting run ends, and each waiting
    /// browser request gets `cancelled`.
    fn end(&mut self, ended: &Ended) {
        self.queue.clear();
        if let Some(mut socket) = self.browser_socket.take() {
            socket.stop();
        }
        let why = match ended {
            Ended::Idle => "The vault was locked after the inactivity time in apassy owner serve.",
            Ended::Session(_) => "The vault was locked when the session locked or slept.",
            _ => ENDED_HERE,
        };
        let locked = self
            .session
            .lock_ending_runs(Some(self.broker.approvals().as_ref()), why);
        // A sleep held for this lock may go now.
        if let Some(observer) = self.observer.as_mut() {
            observer.sleep_decided();
        }
        self.broker.stop();
        let reason = match ended {
            Ended::Quit => "on request".to_owned(),
            Ended::TerminalClosed => "because the terminal closed".to_owned(),
            Ended::Idle => format!(
                "after {} minutes without input",
                self.idle.as_secs().div_ceil(60)
            ),
            Ended::Session(event) => event_reason(*event).to_owned(),
        };
        match locked {
            Ok(()) => self
                .console
                .show(&format!("Vault locked {reason}. The service stopped.")),
            Err(err) => self.console.show(&format!(
                "The service stopped {reason}, but the lock reported: {}",
                err.message
            )),
        }
    }
}

#[cfg(target_os = "linux")]
fn polkit_check() -> Option<OwnerCheck> {
    Some(OwnerCheck::Polkit)
}

#[cfg(not(target_os = "linux"))]
fn polkit_check() -> Option<OwnerCheck> {
    None
}

/// The typed answer for `card`, or `None` for any other text.
fn parse_answer(line: &str, card: &Card) -> Option<Answer> {
    let mut words: Vec<&str> = line.split_whitespace().collect();
    let polkit = words.last() == Some(&"polkit");
    if polkit {
        words.pop();
    }
    let choices = match card {
        Card::Browser(card) => card.op.choices(),
        _ => 1,
    };
    match (card, words.as_slice()) {
        (_, ["deny"]) if !polkit => Some(Answer::Deny),
        (Card::Access(_), ["later"]) if !polkit => Some(Answer::Later),
        (Card::Access(_), ["grant"]) => Some(Answer::Grant {
            any_folder: false,
            polkit,
        }),
        (Card::Access(_), ["grant", "any"]) => Some(Answer::Grant {
            any_folder: true,
            polkit,
        }),
        (Card::Access(_), _) => None,
        (_, ["approve"]) if choices == 1 => Some(Answer::Approve { choice: 0, polkit }),
        (_, ["approve", number]) => {
            let number: usize = number.parse().ok()?;
            (1..=choices).contains(&number).then_some(Answer::Approve {
                choice: number - 1,
                polkit,
            })
        }
        _ => None,
    }
}

fn run_facts(run: &PendingRun) -> Vec<(&'static str, String)> {
    let items: Vec<String> = run
        .question
        .items
        .iter()
        .map(|item| format!("\"{}\"", page_text(&item.name)))
        .collect();
    let mut facts = vec![
        (
            "Request",
            "An agent asks to run a command with secrets".to_owned(),
        ),
        ("Agent", page_text(&run.agent)),
        (
            "Credentials",
            if items.is_empty() {
                run.env_names.join(", ")
            } else {
                items.join(", ")
            },
        ),
        ("Variables", run.env_names.join(", ")),
        (
            "Command",
            run.command
                .iter()
                .map(|word| clean_text(word, 1024))
                .collect::<Vec<_>>()
                .join(" "),
        ),
        ("Folder", clean_text(&run.cwd, 1024)),
    ];
    if !run.purpose.is_empty() {
        facts.push(("Purpose (agent)", page_text(&run.purpose)));
    }
    if !run.user_request.is_empty() {
        facts.push(("User request", page_text(&run.user_request)));
    }
    if !run.question.why.is_empty() {
        facts.push(("Why you are asked", page_text(&run.question.why)));
    }
    if !run.risk.is_empty() {
        facts.push(("Bouncer", page_text(&run.risk)));
    }
    facts
}

fn access_facts(request: &AccessRequest) -> Vec<(&'static str, String)> {
    vec![
        (
            "Request",
            "An agent asks for access to a credential".to_owned(),
        ),
        ("Agent", page_text(&request.agent_name)),
        ("Credential", page_text(&request.item_name)),
        ("Reason (agent)", page_text(&request.reason)),
        (
            "Folder",
            if request.cwd.is_empty() {
                "none named".to_owned()
            } else {
                clean_text(&request.cwd, 1024)
            },
        ),
        (
            "A grant",
            "asks you here for each run (mode ask); deny gives nothing".to_owned(),
        ),
    ]
}
