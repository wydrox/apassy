//! Screen lock, sleep and session observation over D-Bus (zbus, already in the Linux
//! desktop build through AccessKit; this module adds no second D-Bus stack).
//!
//! Sources, in order of trust:
//! - systemd-logind on the system bus. The session (found by `XDG_SESSION_ID`, else
//!   logind's `auto` session: the caller's, or the user's display session): signals
//!   `Lock` and `Unlock`, `PropertiesChanged` of `LockedHint`, `Active`, `State`. The
//!   manager: `PrepareForSleep` and `SessionRemoved`. A delay inhibitor (`Inhibit
//!   sleep … delay`) gives Apassy up to 2 seconds to lock before the sleep.
//! - A screen saver service on the session bus, `org.freedesktop.ScreenSaver` or
//!   `org.gnome.ScreenSaver`: `ActiveChanged` and `GetActive`.
//! - The clocks: a suspend gap (`CLOCK_BOOTTIME` ran, `CLOCK_MONOTONIC` did not) is a
//!   sleep, also with no bus at all.
//!
//! A heartbeat thread reads the session state every [`HEARTBEAT`]: lock state, active
//! state, the idle hint (`IdleHint`, `IdleSinceHint`). [`SessionObserver::verify`] reads
//! the same state synchronously at each reuse of an owner check. Any error, timeout or
//! closed stream is [`SessionEvent::SourceLost`]: the source counts as missing from then
//! on, and nothing is reconnected until Apassy restarts.
use crate::native::session_lock::{Observation, SessionEvent, SessionIdle, SuspendDetector};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::Duration;
use zbus::blocking::{Connection, MessageIterator, Proxy};
use zbus::message::Type as MessageType;
use zbus::zvariant::{OwnedFd, OwnedObjectPath, OwnedValue, Structure, Value};
use zbus::{MatchRule, Message};

const LOGIN1: &str = "org.freedesktop.login1";
const MANAGER_PATH: &str = "/org/freedesktop/login1";
const MANAGER: &str = "org.freedesktop.login1.Manager";
const SESSION: &str = "org.freedesktop.login1.Session";
const PROPERTIES: &str = "org.freedesktop.DBus.Properties";
/// (bus name, object path, interface) of the screen saver services.
const SCREEN_SAVERS: [(&str, &str, &str); 2] = [
    (
        "org.freedesktop.ScreenSaver",
        "/org/freedesktop/ScreenSaver",
        "org.freedesktop.ScreenSaver",
    ),
    (
        "org.gnome.ScreenSaver",
        "/org/gnome/ScreenSaver",
        "org.gnome.ScreenSaver",
    ),
];
/// The longest wait for one D-Bus reply: the reuse probe runs before an owner action.
pub const REPLY_TIMEOUT: Duration = Duration::from_millis(500);
/// The heartbeat. The desktop's idle sample is stale after 32 seconds.
pub const HEARTBEAT: Duration = Duration::from_secs(10);
/// How long the delay inhibitor holds the sleep for the vault lock.
pub const SLEEP_GRACE: Duration = Duration::from_secs(2);

/// Receives every event, on an observer thread. It must not block for long.
pub type Sink = Arc<dyn Fn(SessionEvent) + Send + Sync>;

/// The session state from logind's session properties.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionState {
    pub locked: bool,
    pub active: bool,
    pub closing: bool,
    pub idle: SessionIdle,
}

fn get<T: TryFrom<OwnedValue>>(props: &HashMap<String, OwnedValue>, key: &str) -> Option<T> {
    props
        .get(key)
        .and_then(|v| v.try_clone().ok())
        .and_then(|v| T::try_from(v).ok())
}

/// The state from `GetAll(org.freedesktop.login1.Session)`. `None` without the lock and
/// active properties: such a reply is not a usable observation.
pub fn session_state(props: &HashMap<String, OwnedValue>) -> Option<SessionState> {
    let locked = get::<bool>(props, "LockedHint")?;
    let active = get::<bool>(props, "Active")?;
    let closing = get::<String>(props, "State").is_some_and(|s| s == "closing");
    let idle = match (
        get::<bool>(props, "IdleHint"),
        get::<u64>(props, "IdleSinceHint"),
    ) {
        (Some(idle), Some(since)) => SessionIdle::from_hint(idle, since),
        _ => SessionIdle::Unknown,
    };
    Some(SessionState {
        locked,
        active,
        closing,
        idle,
    })
}

/// The uid of the session's `User` property, `(uo)`.
pub fn session_uid(props: &HashMap<String, OwnedValue>) -> Option<u32> {
    let user = get::<Structure<'static>>(props, "User")?;
    match user.fields().first()? {
        Value::U32(uid) => Some(*uid),
        _ => None,
    }
}

/// The events of a logind session `PropertiesChanged`. Idle changes come from the
/// heartbeat, which reads the hint and its time together.
pub fn property_events(changed: &HashMap<String, OwnedValue>) -> Vec<SessionEvent> {
    let mut out = Vec::new();
    match get::<bool>(changed, "LockedHint") {
        Some(true) => out.push(SessionEvent::ScreenLocked),
        Some(false) => out.push(SessionEvent::ScreenUnlocked),
        None => {}
    }
    match get::<bool>(changed, "Active") {
        Some(false) => out.push(SessionEvent::SessionInactive),
        Some(true) => out.push(SessionEvent::SessionActive),
        None => {}
    }
    if get::<String>(changed, "State").is_some_and(|s| s == "closing") {
        out.push(SessionEvent::SessionEnded);
    }
    out
}

/// What one logind signal means for this session.
#[derive(Debug, PartialEq, Eq)]
pub enum Login1Signal {
    Events(Vec<SessionEvent>),
    /// `PrepareForSleep(true)`: emit [`SessionEvent::Sleep`], then release the inhibitor.
    Sleeping,
    /// `PrepareForSleep(false)`: take a new inhibitor.
    Woke,
    Ignore,
}

/// Map one signal from `org.freedesktop.login1` (the bus already filtered the sender).
pub fn login1_signal(msg: &Message, session_path: Option<&str>) -> Login1Signal {
    let header = msg.header();
    let (Some(path), Some(interface), Some(member)) =
        (header.path(), header.interface(), header.member())
    else {
        return Login1Signal::Ignore;
    };
    let ours = session_path.is_some_and(|p| p == path.as_str());
    match (interface.as_str(), member.as_str()) {
        (SESSION, "Lock") if ours => Login1Signal::Events(vec![SessionEvent::ScreenLocked]),
        (SESSION, "Unlock") if ours => Login1Signal::Events(vec![SessionEvent::ScreenUnlocked]),
        (PROPERTIES, "PropertiesChanged") if ours => {
            match msg
                .body()
                .deserialize::<(String, HashMap<String, OwnedValue>, Vec<String>)>()
            {
                Ok((iface, changed, _)) if iface == SESSION => {
                    Login1Signal::Events(property_events(&changed))
                }
                Ok(_) => Login1Signal::Ignore,
                // A malformed change of our session is not a safe state.
                Err(_) => Login1Signal::Events(vec![SessionEvent::SourceLost]),
            }
        }
        (MANAGER, "PrepareForSleep") if path.as_str() == MANAGER_PATH => {
            match msg.body().deserialize::<bool>() {
                Ok(true) => Login1Signal::Sleeping,
                Ok(false) => Login1Signal::Woke,
                Err(_) => Login1Signal::Events(vec![SessionEvent::SourceLost]),
            }
        }
        (MANAGER, "SessionRemoved") if path.as_str() == MANAGER_PATH => {
            match msg.body().deserialize::<(String, OwnedObjectPath)>() {
                Ok((_, removed)) if session_path == Some(removed.as_str()) => {
                    Login1Signal::Events(vec![SessionEvent::SessionEnded])
                }
                _ => Login1Signal::Ignore,
            }
        }
        _ => Login1Signal::Ignore,
    }
}

/// `ActiveChanged(b)` of a screen saver service.
pub fn screen_saver_signal(msg: &Message) -> Option<SessionEvent> {
    let header = msg.header();
    if header.member().map(|m| m.as_str()) != Some("ActiveChanged") {
        return None;
    }
    Some(match msg.body().deserialize::<bool>() {
        Ok(true) => SessionEvent::ScreenLocked,
        Ok(false) => SessionEvent::ScreenUnlocked,
        Err(_) => SessionEvent::SourceLost,
    })
}

/// Lets the delay inhibitor go once the vault is locked (or after [`SLEEP_GRACE`]).
#[derive(Debug, Default)]
pub struct SleepAck {
    pending: Mutex<bool>,
    done: Condvar,
}
impl SleepAck {
    /// Call after the lock decision for a sleep event.
    pub fn ack(&self) {
        let mut pending = self.pending.lock().unwrap_or_else(|p| p.into_inner());
        if *pending {
            *pending = false;
            self.done.notify_all();
        }
    }
    fn arm(&self) {
        *self.pending.lock().unwrap_or_else(|p| p.into_inner()) = true;
    }
    fn wait(&self, limit: Duration) {
        let pending = self.pending.lock().unwrap_or_else(|p| p.into_inner());
        let _ = self.done.wait_timeout_while(pending, limit, |p| *p);
    }
}

struct Login {
    conn: Connection,
    session: Option<OwnedObjectPath>,
}

struct Shared {
    observation: Mutex<Observation>,
    login: Option<Login>,
    session_bus: Option<Connection>,
    /// The screen saver services that answered `GetActive`.
    screen_savers: Vec<(&'static str, &'static str, &'static str)>,
    suspend: SuspendDetector,
    sink: Mutex<Option<Sink>>,
    inhibitor: Mutex<Option<OwnedFd>>,
    ack: Arc<SleepAck>,
    stopped: AtomicBool,
}

impl Shared {
    fn emit(&self, event: SessionEvent) {
        if event == SessionEvent::SourceLost {
            tracing::info!(event = event.name(), "session observer source lost");
        }
        let sink = self.sink.lock().unwrap_or_else(|p| p.into_inner()).clone();
        if let Some(sink) = sink {
            sink(event);
        }
    }
    fn observation(&self) -> Observation {
        *self.observation.lock().unwrap_or_else(|p| p.into_inner())
    }
    fn lose(&self, edit: impl FnOnce(&mut Observation)) {
        edit(&mut self.observation.lock().unwrap_or_else(|p| p.into_inner()));
        self.emit(SessionEvent::SourceLost);
    }
    fn read_session(&self) -> Option<SessionState> {
        let login = self.login.as_ref()?;
        let path = login.session.as_ref()?;
        let props: HashMap<String, OwnedValue> =
            Proxy::new(&login.conn, LOGIN1, path.as_str(), PROPERTIES)
                .ok()?
                .call("GetAll", &(SESSION,))
                .ok()?;
        session_state(&props)
    }
    /// `Some(true)` if any answering screen saver is active, `None` on an error.
    fn screen_saver_active(&self) -> Option<bool> {
        let conn = self.session_bus.as_ref()?;
        let mut active = false;
        for (name, path, iface) in &self.screen_savers {
            let reply: bool = Proxy::new(conn, *name, *path, *iface)
                .ok()?
                .call("GetActive", &())
                .ok()?;
            active |= reply;
        }
        Some(active)
    }
    fn take_inhibitor(&self) {
        let Some(login) = &self.login else { return };
        let fd = Proxy::new(&login.conn, LOGIN1, MANAGER_PATH, MANAGER)
            .ok()
            .and_then(|m| {
                m.call::<_, _, OwnedFd>(
                    "Inhibit",
                    &("sleep", "Apassy", "Lock the vault before sleep", "delay"),
                )
                .ok()
            });
        let held = fd.is_some();
        *self.inhibitor.lock().unwrap_or_else(|p| p.into_inner()) = fd;
        self.observation
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .sleep_inhibitor = held;
    }
    fn sleeping(&self) {
        self.ack.arm();
        self.emit(SessionEvent::Sleep);
        self.ack.wait(SLEEP_GRACE);
        // Closing the descriptor releases the delay lock: the system may sleep now.
        drop(
            self.inhibitor
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .take(),
        );
    }
}

/// The observer. [`SessionObserver::connect`] finds the sources (no thread yet),
/// [`SessionObserver::start`] subscribes and starts the heartbeat.
pub struct SessionObserver {
    shared: Arc<Shared>,
    stop: Option<mpsc::Sender<()>>,
    heartbeat: Option<std::thread::JoinHandle<()>>,
}

fn connect_bus(system: bool) -> Option<Connection> {
    let builder = if system {
        zbus::blocking::connection::Builder::system()
    } else {
        zbus::blocking::connection::Builder::session()
    };
    builder.ok()?.method_timeout(REPLY_TIMEOUT).build().ok()
}

fn find_session(conn: &Connection) -> Option<OwnedObjectPath> {
    let manager = Proxy::new(conn, LOGIN1, MANAGER_PATH, MANAGER).ok()?;
    let explicit = std::env::var("XDG_SESSION_ID").ok().filter(|id| {
        !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric())
    });
    let uid = rustix::process::getuid().as_raw();
    for id in explicit.into_iter().chain(["auto".to_owned()]) {
        let Ok(path) = manager.call::<_, _, OwnedObjectPath>("GetSession", &(id.as_str(),)) else {
            continue;
        };
        // Only a session of this user: a foreign session's lock state says nothing.
        let props: Option<HashMap<String, OwnedValue>> =
            Proxy::new(conn, LOGIN1, path.as_str(), PROPERTIES)
                .ok()
                .and_then(|p| p.call("GetAll", &(SESSION,)).ok());
        if props
            .as_ref()
            .is_some_and(|p| session_uid(p) == Some(uid) && session_state(p).is_some())
        {
            return Some(path);
        }
    }
    None
}

impl SessionObserver {
    /// Find what this session offers. Never fails: missing sources are `false` in
    /// [`SessionObserver::observation`].
    pub fn connect() -> Self {
        Self::connect_with(connect_bus(true), connect_bus(false))
    }

    /// [`SessionObserver::connect`] on given system and session bus connections.
    fn connect_with(system: Option<Connection>, session_bus: Option<Connection>) -> Self {
        let logind = system.as_ref().is_some_and(|c| {
            Proxy::new(c, LOGIN1, MANAGER_PATH, PROPERTIES)
                .and_then(|p| p.call::<_, _, OwnedValue>("Get", &(MANAGER, "PreparingForSleep")))
                .is_ok()
        });
        let login = system.filter(|_| logind).map(|conn| Login {
            session: find_session(&conn),
            conn,
        });
        let screen_savers: Vec<_> = session_bus
            .as_ref()
            .map(|conn| {
                SCREEN_SAVERS
                    .into_iter()
                    .filter(|(name, path, iface)| {
                        Proxy::new(conn, *name, *path, *iface)
                            .and_then(|p| p.call::<_, _, bool>("GetActive", &()))
                            .is_ok()
                    })
                    .collect()
            })
            .unwrap_or_default();
        let observation = Observation {
            session_bus: session_bus.is_some(),
            logind,
            logind_session: login.as_ref().is_some_and(|l| l.session.is_some()),
            screen_saver: !screen_savers.is_empty(),
            idle_hint: false,
            sleep_inhibitor: false,
        };
        tracing::info!(
            logind = observation.logind,
            logind_session = observation.logind_session,
            screen_saver = observation.screen_saver,
            session_bus = observation.session_bus,
            "session observer sources"
        );
        Self {
            shared: Arc::new(Shared {
                observation: Mutex::new(observation),
                login,
                session_bus,
                screen_savers,
                suspend: SuspendDetector::default(),
                sink: Mutex::new(None),
                inhibitor: Mutex::new(None),
                ack: Arc::default(),
                stopped: AtomicBool::new(false),
            }),
            stop: None,
            heartbeat: None,
        }
    }

    /// What is observed now. A lost source is `false` from then on.
    pub fn observation(&self) -> Observation {
        self.shared.observation()
    }

    /// The handle that releases the sleep inhibitor after the lock.
    pub fn sleep_ack(&self) -> Arc<SleepAck> {
        self.shared.ack.clone()
    }

    /// Subscribe and start the heartbeat. The first heartbeat runs at once and reports
    /// the current state.
    pub fn start(&mut self, sink: Sink) {
        *self.shared.sink.lock().unwrap_or_else(|p| p.into_inner()) = Some(sink);
        let shared = &self.shared;
        if let Some(login) = &shared.login {
            shared.take_inhibitor();
            let rule = MatchRule::builder()
                .msg_type(MessageType::Signal)
                .sender(LOGIN1)
                .map(|b| b.build());
            match rule.and_then(|r| MessageIterator::for_match_rule(r, &login.conn, Some(64))) {
                Ok(iter) => spawn_login1(shared.clone(), iter),
                Err(_) => shared.lose(|o| {
                    o.logind = false;
                    o.logind_session = false;
                }),
            }
        }
        if let Some(conn) = &shared.session_bus {
            for (name, _, iface) in shared.screen_savers.clone() {
                let rule = MatchRule::builder()
                    .msg_type(MessageType::Signal)
                    .sender(name)
                    .and_then(|b| b.interface(iface))
                    .and_then(|b| b.member("ActiveChanged"))
                    .map(|b| b.build());
                match rule.and_then(|r| MessageIterator::for_match_rule(r, conn, Some(16))) {
                    Ok(iter) => spawn_screen_saver(shared.clone(), iter),
                    Err(_) => shared.lose(|o| o.screen_saver = false),
                }
            }
        }
        let (stop, wait) = mpsc::channel();
        self.stop = Some(stop);
        let shared = shared.clone();
        self.heartbeat = std::thread::Builder::new()
            .name("apassy-session-heartbeat".into())
            .spawn(move || heartbeat(&shared, &wait))
            .ok();
    }

    /// The synchronous check before an owner window is reused: no suspend since the
    /// last check, a lock source, and a fresh reading that says unlocked and active.
    pub fn verify(&self) -> bool {
        let shared = &self.shared;
        if shared.suspend.check() {
            shared.emit(SessionEvent::Sleep);
            return false;
        }
        let obs = shared.observation();
        if !obs.lock_observed() {
            return false;
        }
        if obs.logind_session {
            match shared.read_session() {
                Some(s) if !s.locked && s.active && !s.closing => {}
                Some(_) => return false,
                None => {
                    shared.lose(|o| o.logind_session = false);
                    return false;
                }
            }
        }
        if obs.screen_saver {
            match shared.screen_saver_active() {
                Some(false) => {}
                Some(true) => return false,
                None => {
                    shared.lose(|o| o.screen_saver = false);
                    return false;
                }
            }
        }
        true
    }
}

impl Drop for SessionObserver {
    fn drop(&mut self) {
        self.shared.stopped.store(true, Ordering::Relaxed);
        drop(self.stop.take());
        if let Some(thread) = self.heartbeat.take() {
            let _ = thread.join();
        }
        *self.shared.sink.lock().unwrap_or_else(|p| p.into_inner()) = None;
        // Signal threads end with their next message; they hold no vault state.
    }
}

fn spawn_login1(shared: Arc<Shared>, iter: MessageIterator) {
    let _ = std::thread::Builder::new()
        .name("apassy-session-logind".into())
        .spawn(move || {
            let session = shared
                .login
                .as_ref()
                .and_then(|l| l.session.as_ref())
                .map(|p| p.as_str().to_owned());
            for msg in iter {
                if shared.stopped.load(Ordering::Relaxed) {
                    return;
                }
                let Ok(msg) = msg else { break };
                match login1_signal(&msg, session.as_deref()) {
                    Login1Signal::Events(events) => events.into_iter().for_each(|e| shared.emit(e)),
                    Login1Signal::Sleeping => shared.sleeping(),
                    Login1Signal::Woke => shared.take_inhibitor(),
                    Login1Signal::Ignore => {}
                }
            }
            if !shared.stopped.load(Ordering::Relaxed) {
                shared.lose(|o| {
                    o.logind = false;
                    o.logind_session = false;
                    o.sleep_inhibitor = false;
                });
            }
        });
}

fn spawn_screen_saver(shared: Arc<Shared>, iter: MessageIterator) {
    let _ = std::thread::Builder::new()
        .name("apassy-session-screensaver".into())
        .spawn(move || {
            for msg in iter {
                if shared.stopped.load(Ordering::Relaxed) {
                    return;
                }
                let Ok(msg) = msg else { break };
                if let Some(event) = screen_saver_signal(&msg) {
                    shared.emit(event);
                }
            }
            if !shared.stopped.load(Ordering::Relaxed) {
                shared.lose(|o| o.screen_saver = false);
            }
        });
}

/// Every [`HEARTBEAT`]: the suspend gap, the session state (events on change, the
/// first reading always), the screen saver state, and the idle hint.
fn heartbeat(shared: &Shared, stop: &mpsc::Receiver<()>) {
    let mut last: Option<SessionState> = None;
    let mut saver_last: Option<bool> = None;
    loop {
        if shared.suspend.check() {
            shared.emit(SessionEvent::Sleep);
        }
        let obs = shared.observation();
        let mut idle = SessionIdle::Unknown;
        if obs.logind_session {
            match shared.read_session() {
                Some(state) => {
                    if last.is_none_or(|l| l.locked != state.locked) {
                        shared.emit(if state.locked {
                            SessionEvent::ScreenLocked
                        } else {
                            SessionEvent::ScreenUnlocked
                        });
                    }
                    if last.is_none_or(|l| l.active != state.active) {
                        shared.emit(if state.active {
                            SessionEvent::SessionActive
                        } else {
                            SessionEvent::SessionInactive
                        });
                    }
                    if state.closing && last.is_none_or(|l| !l.closing) {
                        shared.emit(SessionEvent::SessionEnded);
                    }
                    idle = state.idle;
                    last = Some(state);
                }
                None => shared.lose(|o| o.logind_session = false),
            }
        }
        if obs.screen_saver {
            match shared.screen_saver_active() {
                Some(active) => {
                    if saver_last != Some(active) {
                        shared.emit(if active {
                            SessionEvent::ScreenLocked
                        } else {
                            SessionEvent::ScreenUnlocked
                        });
                    }
                    saver_last = Some(active);
                }
                None => shared.lose(|o| o.screen_saver = false),
            }
        }
        shared
            .observation
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .idle_hint = idle != SessionIdle::Unknown;
        shared.emit(SessionEvent::Idle(idle));
        match stop.recv_timeout(HEARTBEAT) {
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            _ => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn props(pairs: &[(&str, OwnedValue)]) -> HashMap<String, OwnedValue> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.try_clone().unwrap()))
            .collect()
    }

    fn string(s: &str) -> OwnedValue {
        OwnedValue::try_from(Value::from(s)).unwrap()
    }

    #[test]
    fn session_state_needs_lock_and_active_and_reads_the_idle_hint() {
        let full = props(&[
            ("LockedHint", true.into()),
            ("Active", true.into()),
            ("State", string("active")),
            ("IdleHint", true.into()),
            ("IdleSinceHint", 12u64.into()),
        ]);
        assert_eq!(
            session_state(&full),
            Some(SessionState {
                locked: true,
                active: true,
                closing: false,
                idle: SessionIdle::Idle,
            })
        );
        let never_set = props(&[
            ("LockedHint", false.into()),
            ("Active", true.into()),
            ("IdleHint", false.into()),
            ("IdleSinceHint", 0u64.into()),
        ]);
        assert_eq!(
            session_state(&never_set).unwrap().idle,
            SessionIdle::Unknown
        );
        assert_eq!(session_state(&props(&[("Active", true.into())])), None);
        let closing = props(&[
            ("LockedHint", false.into()),
            ("Active", false.into()),
            ("State", string("closing")),
        ]);
        assert!(session_state(&closing).unwrap().closing);
    }

    #[test]
    fn property_changes_map_to_lock_switch_and_end_events() {
        assert_eq!(
            property_events(&props(&[("LockedHint", true.into())])),
            vec![SessionEvent::ScreenLocked]
        );
        assert_eq!(
            property_events(&props(&[
                ("LockedHint", false.into()),
                ("Active", false.into()),
                ("State", string("closing")),
            ])),
            vec![
                SessionEvent::ScreenUnlocked,
                SessionEvent::SessionInactive,
                SessionEvent::SessionEnded
            ]
        );
        assert!(property_events(&props(&[("IdleHint", true.into())])).is_empty());
    }

    const OURS: &str = "/org/freedesktop/login1/session/_32";

    fn signal<B>(path: &str, iface: &str, member: &str, body: &B) -> Message
    where
        B: serde::Serialize + zbus::zvariant::DynamicType,
    {
        Message::signal(path, iface, member)
            .unwrap()
            .build(body)
            .unwrap()
    }

    #[test]
    fn login1_signals_of_this_session_and_the_manager() {
        let lock = signal(OURS, SESSION, "Lock", &());
        assert_eq!(
            login1_signal(&lock, Some(OURS)),
            Login1Signal::Events(vec![SessionEvent::ScreenLocked])
        );
        // Another session's lock and a process without a session are ignored.
        let other = signal("/org/freedesktop/login1/session/c2", SESSION, "Lock", &());
        assert_eq!(login1_signal(&other, Some(OURS)), Login1Signal::Ignore);
        assert_eq!(login1_signal(&lock, None), Login1Signal::Ignore);
        let unlock = signal(OURS, SESSION, "Unlock", &());
        assert_eq!(
            login1_signal(&unlock, Some(OURS)),
            Login1Signal::Events(vec![SessionEvent::ScreenUnlocked])
        );
        let sleep = signal(MANAGER_PATH, MANAGER, "PrepareForSleep", &true);
        assert_eq!(login1_signal(&sleep, None), Login1Signal::Sleeping);
        let wake = signal(MANAGER_PATH, MANAGER, "PrepareForSleep", &false);
        assert_eq!(login1_signal(&wake, Some(OURS)), Login1Signal::Woke);
        let removed = signal(
            MANAGER_PATH,
            MANAGER,
            "SessionRemoved",
            &("_32", OwnedObjectPath::try_from(OURS).unwrap()),
        );
        assert_eq!(
            login1_signal(&removed, Some(OURS)),
            Login1Signal::Events(vec![SessionEvent::SessionEnded])
        );
        let mut changed = HashMap::new();
        changed.insert("LockedHint".to_owned(), Value::from(true));
        let props_changed = signal(
            OURS,
            PROPERTIES,
            "PropertiesChanged",
            &(SESSION, changed, Vec::<String>::new()),
        );
        assert_eq!(
            login1_signal(&props_changed, Some(OURS)),
            Login1Signal::Events(vec![SessionEvent::ScreenLocked])
        );
        // A malformed body is a lost source, never a quiet "unlocked".
        let bad = signal(MANAGER_PATH, MANAGER, "PrepareForSleep", &"yes");
        assert_eq!(
            login1_signal(&bad, None),
            Login1Signal::Events(vec![SessionEvent::SourceLost])
        );
    }

    #[test]
    fn screen_saver_active_changed() {
        let (_, path, iface) = SCREEN_SAVERS[1];
        let on = signal(path, iface, "ActiveChanged", &true);
        assert_eq!(screen_saver_signal(&on), Some(SessionEvent::ScreenLocked));
        let off = signal(path, iface, "ActiveChanged", &false);
        assert_eq!(
            screen_saver_signal(&off),
            Some(SessionEvent::ScreenUnlocked)
        );
        let bad = signal(path, iface, "ActiveChanged", &7u32);
        assert_eq!(screen_saver_signal(&bad), Some(SessionEvent::SourceLost));
        let other = signal(path, iface, "WakeUpScreen", &());
        assert_eq!(screen_saver_signal(&other), None);
    }

    #[test]
    fn sleep_ack_releases_early_and_times_out() {
        let ack = Arc::new(SleepAck::default());
        ack.arm();
        let other = ack.clone();
        let started = std::time::Instant::now();
        let thread = std::thread::spawn(move || other.ack());
        ack.wait(Duration::from_secs(30));
        thread.join().unwrap();
        assert!(started.elapsed() < Duration::from_secs(30));
        ack.arm();
        let started = std::time::Instant::now();
        ack.wait(Duration::from_millis(20));
        assert!(started.elapsed() >= Duration::from_millis(20));
    }
}

/// [`SessionObserver`] against real D-Bus daemons: each test starts two private
/// `dbus-daemon`s, one as the system bus and one as the session bus, and serves fake
/// systemd-logind and screen saver services on them. Nothing of the real buses is used.
/// The linux-vault CI job installs `dbus-daemon` and sets `APASSY_REQUIRE_DBUS=1`;
/// elsewhere a missing `dbus-daemon` is a reported skip. (`vault` brings `tempfile`.)
#[cfg(all(test, feature = "vault"))]
mod live_tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read};
    use std::os::unix::net::UnixStream;
    use std::process::{Child, Command, Stdio};
    use std::sync::atomic::AtomicU32;
    use std::time::Instant;
    use zbus::blocking::connection::Builder;
    use zbus::zvariant::OwnedFd as BusFd;

    const SESSION_PATH: &str = "/org/freedesktop/login1/session/_3apassy";
    const SAVER_PATH: &str = "/org/freedesktop/ScreenSaver";
    const SAVER: &str = "org.freedesktop.ScreenSaver";
    const WAIT: Duration = Duration::from_secs(5);

    /// A private bus for one test. Dropping it stops the daemon.
    struct Bus {
        child: Child,
        address: String,
        _dir: tempfile::TempDir,
    }

    impl Bus {
        fn start() -> Option<Self> {
            let dir = tempfile::Builder::new().prefix("apb").tempdir().unwrap();
            let spawned = Command::new("dbus-daemon")
                .arg("--session")
                .arg("--nofork")
                .arg("--nopidfile")
                .arg("--print-address=1")
                .arg(format!(
                    "--address=unix:path={}",
                    dir.path().join("bus").display()
                ))
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn();
            let mut child = match spawned {
                Ok(child) => child,
                Err(err) => {
                    assert!(
                        std::env::var_os("APASSY_REQUIRE_DBUS").is_none(),
                        "APASSY_REQUIRE_DBUS is set, but dbus-daemon did not start: {err}"
                    );
                    eprintln!("skipped: dbus-daemon is not installed ({err})");
                    return None;
                }
            };
            let mut address = String::new();
            BufReader::new(child.stdout.take().unwrap())
                .read_line(&mut address)
                .unwrap();
            let address = address.trim().to_owned();
            assert!(address.starts_with("unix:"), "no bus address: {address:?}");
            Some(Self {
                child,
                address,
                _dir: dir,
            })
        }

        fn builder(&self) -> Builder<'static> {
            Builder::address(self.address.as_str()).unwrap()
        }

        /// A client connection as [`connect_bus`] makes it.
        fn client(&self) -> Option<Connection> {
            self.builder().method_timeout(REPLY_TIMEOUT).build().ok()
        }
    }

    impl Drop for Bus {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    #[derive(Default)]
    struct Fake {
        locked: AtomicBool,
        inactive: AtomicBool,
        saver: AtomicBool,
        inhibits: AtomicU32,
        /// The far ends of the inhibitor descriptors that Apassy got.
        held: Mutex<Vec<UnixStream>>,
    }

    struct Manager(Arc<Fake>);
    #[zbus::interface(name = "org.freedesktop.login1.Manager")]
    impl Manager {
        fn get_session(&self, _id: &str) -> OwnedObjectPath {
            OwnedObjectPath::try_from(SESSION_PATH).unwrap()
        }
        fn inhibit(
            &self,
            what: &str,
            _who: &str,
            _why: &str,
            mode: &str,
        ) -> zbus::fdo::Result<BusFd> {
            assert_eq!((what, mode), ("sleep", "delay"));
            let (ours, theirs) =
                UnixStream::pair().map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
            ours.set_nonblocking(true).unwrap();
            self.0.held.lock().unwrap().push(ours);
            self.0.inhibits.fetch_add(1, Ordering::SeqCst);
            Ok(BusFd::from(std::os::fd::OwnedFd::from(theirs)))
        }
        #[zbus(property)]
        fn preparing_for_sleep(&self) -> bool {
            false
        }
    }

    struct Session(Arc<Fake>);
    #[zbus::interface(name = "org.freedesktop.login1.Session")]
    impl Session {
        #[zbus(property)]
        fn locked_hint(&self) -> bool {
            self.0.locked.load(Ordering::SeqCst)
        }
        #[zbus(property)]
        fn active(&self) -> bool {
            !self.0.inactive.load(Ordering::SeqCst)
        }
        #[zbus(property)]
        fn state(&self) -> String {
            "active".into()
        }
        #[zbus(property)]
        fn user(&self) -> (u32, OwnedObjectPath) {
            (
                rustix::process::getuid().as_raw(),
                OwnedObjectPath::try_from("/org/freedesktop/login1/user/_apassy").unwrap(),
            )
        }
        #[zbus(property)]
        fn idle_hint(&self) -> bool {
            false
        }
        #[zbus(property)]
        fn idle_since_hint(&self) -> u64 {
            1
        }
    }

    struct Saver(Arc<Fake>);
    #[zbus::interface(name = "org.freedesktop.ScreenSaver")]
    impl Saver {
        fn get_active(&self) -> bool {
            self.0.saver.load(Ordering::SeqCst)
        }
    }

    fn serve(fake: &Arc<Fake>, system: &Bus, session: &Bus) -> (Connection, Connection) {
        let system = system
            .builder()
            .name(LOGIN1)
            .unwrap()
            .serve_at(MANAGER_PATH, Manager(fake.clone()))
            .unwrap()
            .serve_at(SESSION_PATH, Session(fake.clone()))
            .unwrap()
            .build()
            .unwrap();
        let session = session
            .builder()
            .name(SAVER)
            .unwrap()
            .serve_at(SAVER_PATH, Saver(fake.clone()))
            .unwrap()
            .build()
            .unwrap();
        (system, session)
    }

    /// The next `want` among the events, skipping others (idle readings, heartbeats).
    fn expect(events: &mpsc::Receiver<SessionEvent>, want: SessionEvent) {
        let deadline = Instant::now() + WAIT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match events.recv_timeout(left) {
                Ok(event) if event == want => return,
                Ok(_) => {}
                Err(_) => panic!("no {want:?} event"),
            }
        }
    }

    fn emit<B: serde::Serialize + zbus::zvariant::DynamicType>(
        conn: &Connection,
        path: &str,
        iface: &str,
        member: &str,
        body: &B,
    ) {
        conn.emit_signal(None::<&str>, path, iface, member, body)
            .unwrap();
    }

    /// The far end of inhibitor `index` saw its last copy close.
    fn released(fake: &Fake, index: usize) -> bool {
        let mut held = fake.held.lock().unwrap();
        let mut byte = [0u8; 1];
        matches!(held[index].read(&mut byte), Ok(0))
    }

    #[test]
    fn live_logind_and_screen_saver_signals_reach_the_observer() {
        let (Some(system_bus), Some(session_bus)) = (Bus::start(), Bus::start()) else {
            return;
        };
        let fake = Arc::new(Fake::default());
        let (system, session) = serve(&fake, &system_bus, &session_bus);
        let mut observer = SessionObserver::connect_with(system_bus.client(), session_bus.client());
        let obs = observer.observation();
        assert!(
            obs.session_bus && obs.logind && obs.logind_session && obs.screen_saver,
            "{obs:?}"
        );
        assert_eq!(obs.coverage(), crate::native::session_lock::Coverage::Full);
        let (send, events) = mpsc::channel();
        observer.start(Arc::new(move |event| {
            let _ = send.send(event);
        }));
        // The first heartbeat reports the state; the delay inhibitor is held.
        expect(&events, SessionEvent::ScreenUnlocked);
        assert!(observer.observation().sleep_inhibitor);
        assert_eq!(fake.inhibits.load(Ordering::SeqCst), 1);
        assert!(observer.verify(), "unlocked and active: reuse may go on");

        // The screen saver.
        fake.saver.store(true, Ordering::SeqCst);
        emit(&session, SAVER_PATH, SAVER, "ActiveChanged", &true);
        expect(&events, SessionEvent::ScreenLocked);
        assert!(!observer.verify(), "an active screen saver ends reuse");
        fake.saver.store(false, Ordering::SeqCst);
        emit(&session, SAVER_PATH, SAVER, "ActiveChanged", &false);
        expect(&events, SessionEvent::ScreenUnlocked);
        assert!(observer.verify());

        // logind Lock and Unlock of this session, and a lock state read by verify.
        emit(&system, SESSION_PATH, SESSION, "Lock", &());
        expect(&events, SessionEvent::ScreenLocked);
        emit(&system, SESSION_PATH, SESSION, "Unlock", &());
        expect(&events, SessionEvent::ScreenUnlocked);
        fake.locked.store(true, Ordering::SeqCst);
        assert!(!observer.verify(), "LockedHint ends reuse");
        fake.locked.store(false, Ordering::SeqCst);
        fake.inactive.store(true, Ordering::SeqCst);
        assert!(!observer.verify(), "an inactive session ends reuse");
        fake.inactive.store(false, Ordering::SeqCst);
        assert!(observer.verify());
        // Another session's Lock is not ours.
        emit(
            &system,
            "/org/freedesktop/login1/session/_9other",
            SESSION,
            "Lock",
            &(),
        );

        // Sleep: the event, then the inhibitor stays until the ack.
        let ack = observer.sleep_ack();
        emit(&system, MANAGER_PATH, MANAGER, "PrepareForSleep", &true);
        expect(&events, SessionEvent::Sleep);
        std::thread::sleep(Duration::from_millis(200));
        assert!(!released(&fake, 0), "the inhibitor waits for the lock");
        ack.ack();
        let deadline = Instant::now() + WAIT;
        while !released(&fake, 0) {
            assert!(Instant::now() < deadline, "the ack releases the inhibitor");
            std::thread::sleep(Duration::from_millis(10));
        }
        // The wake takes a new inhibitor.
        emit(&system, MANAGER_PATH, MANAGER, "PrepareForSleep", &false);
        let deadline = Instant::now() + WAIT;
        while fake.inhibits.load(Ordering::SeqCst) < 2 {
            assert!(Instant::now() < deadline, "the wake takes a new inhibitor");
            std::thread::sleep(Duration::from_millis(10));
        }

        // The end of this session.
        emit(
            &system,
            MANAGER_PATH,
            MANAGER,
            "SessionRemoved",
            &("3apassy", OwnedObjectPath::try_from(SESSION_PATH).unwrap()),
        );
        expect(&events, SessionEvent::SessionEnded);

        // The screen saver goes away: the reuse check fails closed and reports the loss.
        drop(session);
        assert!(!observer.verify(), "a lost screen saver ends reuse");
        expect(&events, SessionEvent::SourceLost);
        assert!(!observer.observation().screen_saver);
        drop(system);
    }
}
