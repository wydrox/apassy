//! Session lock, sleep and inactivity: the events and the lock rule, without a UI.
//!
//! The Linux observer (`native::linux::session_bus`, systemd-logind and the screen saver
//! services over D-Bus) produces [`SessionEvent`]s. Two users apply them:
//! - the desktop (`desktop::session_watch`): the owner-check window and auto-lock;
//! - a terminal service (the headless owner commands): [`SessionLock`], which needs
//!   no window. Call [`SessionLock::input`] on owner input, [`SessionLock::event`] on
//!   each event and [`SessionLock::due`] on a timer; lock the vault on `Some`.
//!
//! Fail closed: a missing or lost signal never means "unlocked and safe". Without a
//! lock source the owner window stays off ([`Observation::lock_observed`]), and a lost
//! source switches the inactivity rule back to input seen by Apassy itself.
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// One observed change of the login session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEvent {
    /// The screen locked: logind `Lock` or `LockedHint` true, or a screen saver
    /// `ActiveChanged(true)`.
    ScreenLocked,
    /// The screen unlocked. It never restores an ended owner window.
    ScreenUnlocked,
    /// The system prepares to sleep (logind `PrepareForSleep(true)`), or a suspend
    /// gap of the clocks was seen after the wake.
    Sleep,
    /// The session is no longer the active one (user switch, logind `Active` false).
    SessionInactive,
    /// The session is the active one again. It never restores an ended owner window.
    SessionActive,
    /// The session ended (logind `SessionRemoved`, or the state `closing`).
    SessionEnded,
    /// A fresh reading of the desktop's idle hint.
    Idle(SessionIdle),
    /// A source stopped answering (bus closed, logind restarted, reply timeout).
    SourceLost,
}

impl SessionEvent {
    /// Ends the owner-check window and every issued approval.
    pub fn ends_owner_window(self) -> bool {
        matches!(
            self,
            Self::ScreenLocked
                | Self::Sleep
                | Self::SessionInactive
                | Self::SessionEnded
                | Self::SourceLost
        )
    }
    /// Locks the vault under [`LockRule::OnSessionLock`] ("when the screen locks or
    /// the computer sleeps"). A lost source is not a lock event: it ends the owner
    /// window and returns inactivity to the Apassy-only rule.
    pub fn locks_session(self) -> bool {
        matches!(
            self,
            Self::ScreenLocked | Self::Sleep | Self::SessionInactive | Self::SessionEnded
        )
    }
    /// The diagnostic name. No event carries user data.
    pub fn name(self) -> &'static str {
        match self {
            Self::ScreenLocked => "screen_locked",
            Self::ScreenUnlocked => "screen_unlocked",
            Self::Sleep => "system_sleep",
            Self::SessionInactive => "session_resigned",
            Self::SessionActive => "session_active",
            Self::SessionEnded => "session_ended",
            Self::Idle(_) => "idle_hint",
            Self::SourceLost => "observer_failure",
        }
    }
}

/// The desktop's idle hint (logind `IdleHint` and `IdleSinceHint`).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum SessionIdle {
    /// No hint: the desktop never set one (`IdleSinceHint` is 0), or no logind session.
    /// Inactivity then counts only input seen by Apassy.
    #[default]
    Unknown,
    /// The desktop reports input in the session (the owner works in another app).
    Active,
    /// The desktop reports the session idle.
    Idle,
}

impl SessionIdle {
    /// From logind's session properties. `since_usec` is `IdleSinceHint`: 0 means the
    /// desktop never set the hint, so the hint is not maintained.
    pub fn from_hint(idle: bool, since_usec: u64) -> Self {
        match (since_usec, idle) {
            (0, _) => Self::Unknown,
            (_, true) => Self::Idle,
            (_, false) => Self::Active,
        }
    }
    /// The "system idle" sample for the desktop's auto-lock timer, whose rule is
    /// "no input in Apassy for the limit, and a system idle time of at least the limit".
    /// `Active` gives 0 (postpone); `Unknown` and `Idle` give a time above every limit,
    /// so only input in Apassy decides.
    pub fn system_idle_sample(self) -> Duration {
        match self {
            Self::Active => Duration::ZERO,
            Self::Unknown | Self::Idle => UNBOUNDED_IDLE,
        }
    }
}

/// Above every auto-lock limit, and far from `Duration` overflow when time is added.
pub const UNBOUNDED_IDLE: Duration = Duration::from_secs(10 * 365 * 24 * 3600);

/// Which sources this session has. Built by the observer at start; a lost source
/// clears its flag.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Observation {
    /// A session bus connection.
    pub session_bus: bool,
    /// systemd-logind on the system bus (the manager: `PrepareForSleep`).
    pub logind: bool,
    /// This process's logind session: `Lock`, `Unlock`, `LockedHint`, `Active`.
    pub logind_session: bool,
    /// A screen saver service: `org.freedesktop.ScreenSaver` or `org.gnome.ScreenSaver`.
    pub screen_saver: bool,
    /// The desktop maintains logind's idle hint (`IdleSinceHint` was set).
    pub idle_hint: bool,
    /// A delay inhibitor: the vault locks before the system sleeps, not at the wake.
    pub sleep_inhibitor: bool,
}

/// How much of the session Apassy can observe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coverage {
    /// logind session, logind sleep signal and a screen saver service.
    Full,
    /// At least one lock source, but not all of them.
    Partial,
    /// No lock source: manual lock and inactivity in Apassy only; no owner window.
    None,
}

impl Observation {
    /// A lock source exists, so the owner window can work: it ends at lock and sleep.
    pub fn lock_observed(&self) -> bool {
        self.logind_session || self.screen_saver
    }
    pub fn coverage(&self) -> Coverage {
        if !self.lock_observed() {
            Coverage::None
        } else if self.logind && self.logind_session && self.screen_saver {
            Coverage::Full
        } else {
            Coverage::Partial
        }
    }
    /// One plain sentence per missing source, for the settings text.
    pub fn missing(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if !self.logind {
            out.push(
                "systemd-logind is not reachable on the system bus: sleep is detected only from the clock after the wake, and a session switch is not seen.",
            );
        } else if !self.logind_session {
            out.push(
                "This process has no systemd-logind session: its Lock and Unlock signals and the lock state are not seen.",
            );
        }
        if !self.session_bus {
            out.push("There is no session bus: no screen saver service is seen.");
        } else if !self.screen_saver {
            out.push(
                "No screen saver service answers on the session bus: a screen locker that does not report to systemd-logind is not seen.",
            );
        }
        out
    }
    /// How inactivity is measured now.
    pub fn inactivity_source(&self) -> &'static str {
        if self.idle_hint {
            "Inactivity means no input in Apassy while the desktop reports the session idle, so work in other apps keeps the vault open."
        } else {
            "Inactivity counts only input in the Apassy window: the desktop reports no idle time."
        }
    }
}

/// The auto-lock setting. The codes are those of the desktop's setting.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum LockRule {
    #[default]
    Never,
    /// No owner input for this time.
    After(Duration),
    /// Screen lock, sleep or session end.
    OnSessionLock,
}

impl LockRule {
    pub fn parse(code: &str) -> Option<Self> {
        Some(match code {
            "never" => Self::Never,
            "15m" => Self::After(Duration::from_secs(900)),
            "1h" => Self::After(Duration::from_secs(3600)),
            "4h" => Self::After(Duration::from_secs(14400)),
            "session" => Self::OnSessionLock,
            _ => return None,
        })
    }
}

/// Why the vault locks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockReason {
    Session(SessionEvent),
    Inactivity,
}

/// The lock rule over session events and owner input, with an injected clock (use
/// [`sleep_inclusive_now`]: it counts the time suspended).
#[derive(Debug, Clone)]
pub struct SessionLock {
    rule: LockRule,
    last_input: Duration,
    idle: SessionIdle,
}

impl SessionLock {
    pub fn new(rule: LockRule, now: Duration) -> Self {
        Self {
            rule,
            last_input: now,
            idle: SessionIdle::Unknown,
        }
    }
    pub fn rule(&self) -> LockRule {
        self.rule
    }
    /// A new setting starts its time now.
    pub fn set_rule(&mut self, rule: LockRule, now: Duration) {
        self.rule = rule;
        self.last_input = now;
    }
    /// Owner input that Apassy itself saw (a key in the window or the terminal).
    /// Agent and broker traffic are never owner input.
    pub fn input(&mut self, now: Duration) {
        self.last_input = self.last_input.max(now);
    }
    /// Apply one event; `Some` means lock the vault now.
    pub fn event(&mut self, event: SessionEvent, now: Duration) -> Option<LockReason> {
        match event {
            SessionEvent::Idle(idle) => self.idle = idle,
            SessionEvent::SourceLost => self.idle = SessionIdle::Unknown,
            _ => {}
        }
        if self.rule == LockRule::OnSessionLock && event.locks_session() {
            return Some(LockReason::Session(event));
        }
        self.due(now)
    }
    /// The inactivity check. Call it at least every 30 seconds.
    pub fn due(&self, now: Duration) -> Option<LockReason> {
        let LockRule::After(limit) = self.rule else {
            return None;
        };
        let quiet = now.saturating_sub(self.last_input);
        (quiet >= limit && self.idle.system_idle_sample() >= limit)
            .then_some(LockReason::Inactivity)
    }
}

/// Now on the sleep-inclusive clock (`CLOCK_BOOTTIME` on Linux, Darwin's
/// `CLOCK_MONOTONIC` on macOS). Zero if the system gives a negative time.
pub fn sleep_inclusive_now() -> Duration {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let id = rustix::time::ClockId::Boottime;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let id = rustix::time::ClockId::Monotonic;
    rustix::time::clock_gettime(id)
        .try_into()
        .unwrap_or_default()
}

/// Sees a suspend after the fact: the sleep-inclusive clock advanced more than the
/// awake clock (`Instant`) since the last check. It needs no bus, so it also works in a
/// container or over SSH. Every observer path (heartbeat and reuse probe) shares one.
#[derive(Debug)]
pub struct SuspendDetector {
    last: Mutex<(Duration, Instant)>,
}

/// Suspends shorter than this are not reported (clock jitter, a stopped VM tick).
pub const SUSPEND_THRESHOLD: Duration = Duration::from_secs(2);

impl Default for SuspendDetector {
    fn default() -> Self {
        Self {
            last: Mutex::new((sleep_inclusive_now(), Instant::now())),
        }
    }
}

impl SuspendDetector {
    /// True once per suspend gap since the previous call.
    pub fn check(&self) -> bool {
        self.check_at(sleep_inclusive_now(), Instant::now())
    }
    fn check_at(&self, clock: Duration, awake: Instant) -> bool {
        let mut last = self.last.lock().unwrap_or_else(|p| p.into_inner());
        let slept = clock.saturating_sub(last.0);
        let ran = awake.saturating_duration_since(last.1);
        *last = (clock, awake);
        slept > ran + SUSPEND_THRESHOLD
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN15: Duration = Duration::from_secs(900);

    /// A fake signal source: a script of owner input, timer ticks and events.
    #[derive(Clone, Copy)]
    enum Step {
        Input,
        Tick,
        Event(SessionEvent),
    }
    use Step::{Input, Tick};

    fn run(rule: LockRule, script: &[(u64, Step)]) -> Option<(u64, LockReason)> {
        let mut lock = SessionLock::new(rule, Duration::ZERO);
        for (at, step) in script {
            let now = Duration::from_secs(*at);
            let reason = match step {
                Input => {
                    lock.input(now);
                    None
                }
                Tick => lock.due(now),
                Step::Event(e) => lock.event(*e, now),
            };
            if let Some(r) = reason {
                return Some((*at, r));
            }
        }
        None
    }

    #[test]
    fn screen_lock_and_sleep_lock_the_vault_under_the_session_rule() {
        for event in [
            SessionEvent::ScreenLocked,
            SessionEvent::Sleep,
            SessionEvent::SessionInactive,
            SessionEvent::SessionEnded,
        ] {
            let e = Step::Event(event);
            assert_eq!(
                run(LockRule::OnSessionLock, &[(5, e)]),
                Some((5, LockReason::Session(event)))
            );
            assert!(event.ends_owner_window());
            // Never and a timeout keep the vault open on these events (as on macOS).
            assert_eq!(run(LockRule::Never, &[(5, e)]), None);
            assert_eq!(run(LockRule::After(MIN15), &[(5, e)]), None);
        }
        for event in [
            SessionEvent::ScreenUnlocked,
            SessionEvent::SessionActive,
            SessionEvent::Idle(SessionIdle::Idle),
            SessionEvent::SourceLost,
        ] {
            assert_eq!(
                run(LockRule::OnSessionLock, &[(5, Step::Event(event))]),
                None
            );
        }
        assert!(SessionEvent::SourceLost.ends_owner_window());
        assert!(!SessionEvent::ScreenUnlocked.ends_owner_window());
        assert!(!SessionEvent::SessionActive.ends_owner_window());
    }

    #[test]
    fn inactivity_without_a_hint_counts_input_in_apassy_only() {
        let rule = LockRule::After(MIN15);
        assert_eq!(run(rule, &[(899, Tick), (899, Input), (1798, Tick)]), None);
        assert_eq!(
            run(rule, &[(100, Input), (999, Tick), (1000, Tick)]),
            Some((1000, LockReason::Inactivity))
        );
        // A suspend is time without input: the sleep-inclusive clock counts it, so the
        // first tick after a long sleep locks before any wake input.
        assert_eq!(
            run(
                rule,
                &[
                    (10, Step::Event(SessionEvent::Sleep)),
                    (950, Tick),
                    (951, Input)
                ]
            ),
            Some((950, LockReason::Inactivity))
        );
        let lock = SessionLock::new(rule, Duration::ZERO);
        assert_eq!(lock.due(MIN15), Some(LockReason::Inactivity));
    }

    #[test]
    fn an_active_desktop_hint_postpones_and_a_lost_source_restores_the_apassy_rule() {
        let rule = LockRule::After(MIN15);
        let mut lock = SessionLock::new(rule, Duration::ZERO);
        assert_eq!(
            lock.event(
                SessionEvent::Idle(SessionIdle::Active),
                Duration::from_secs(1)
            ),
            None
        );
        assert_eq!(lock.due(Duration::from_secs(5000)), None);
        assert_eq!(
            lock.event(
                SessionEvent::Idle(SessionIdle::Idle),
                Duration::from_secs(5000)
            ),
            Some(LockReason::Inactivity)
        );
        let mut lock = SessionLock::new(rule, Duration::ZERO);
        lock.event(SessionEvent::Idle(SessionIdle::Active), Duration::ZERO);
        assert_eq!(
            lock.event(SessionEvent::SourceLost, Duration::from_secs(900)),
            Some(LockReason::Inactivity)
        );
    }

    #[test]
    fn idle_hint_needs_a_set_since_time() {
        assert_eq!(SessionIdle::from_hint(true, 0), SessionIdle::Unknown);
        assert_eq!(SessionIdle::from_hint(false, 0), SessionIdle::Unknown);
        assert_eq!(SessionIdle::from_hint(true, 7), SessionIdle::Idle);
        assert_eq!(SessionIdle::from_hint(false, 7), SessionIdle::Active);
        assert!(SessionIdle::Unknown.system_idle_sample() > Duration::from_secs(14400));
        // No overflow when the timer adds a long suspend to the sample.
        let _ = UNBOUNDED_IDLE + Duration::from_secs(365 * 24 * 3600);
    }

    #[test]
    fn coverage_full_partial_none_and_missing_texts() {
        let none = Observation::default();
        assert_eq!(none.coverage(), Coverage::None);
        assert!(!none.lock_observed());
        assert_eq!(none.missing().len(), 2);
        let full = Observation {
            session_bus: true,
            logind: true,
            logind_session: true,
            screen_saver: true,
            idle_hint: true,
            sleep_inhibitor: true,
        };
        assert_eq!(full.coverage(), Coverage::Full);
        assert!(full.missing().is_empty());
        let wm = Observation {
            screen_saver: false,
            ..full
        };
        assert_eq!(wm.coverage(), Coverage::Partial);
        assert!(wm.lock_observed());
        assert!(wm.missing()[0].contains("screen saver"));
        let no_logind = Observation {
            logind: false,
            logind_session: false,
            ..full
        };
        assert_eq!(no_logind.coverage(), Coverage::Partial);
        assert!(no_logind.missing()[0].contains("systemd-logind"));
    }

    #[test]
    fn lock_rule_codes_match_the_desktop_setting() {
        assert_eq!(LockRule::parse("never"), Some(LockRule::Never));
        assert_eq!(LockRule::parse("15m"), Some(LockRule::After(MIN15)));
        assert_eq!(LockRule::parse("session"), Some(LockRule::OnSessionLock));
        assert_eq!(LockRule::parse("damaged"), None);
    }

    #[test]
    fn suspend_detector_reports_a_gap_once() {
        let d = SuspendDetector::default();
        let (clock, awake) = *d.last.lock().unwrap();
        assert!(!d.check_at(
            clock + Duration::from_secs(1),
            awake + Duration::from_secs(1)
        ));
        assert!(d.check_at(
            clock + Duration::from_secs(901),
            awake + Duration::from_secs(1)
        ));
        assert!(!d.check_at(
            clock + Duration::from_secs(902),
            awake + Duration::from_secs(2)
        ));
    }
}
