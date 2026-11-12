//! When `apassy owner serve` locks the vault besides `lock`, `quit` and the end of the
//! terminal: the inactivity time and the session events of unit L2
//! ([`crate::native::session_lock`]).
//!
//! - **Inactivity:** a [`SessionLock`] with the rule "after N minutes" counts on the
//!   sleep-inclusive clock ([`sleep_inclusive_now`]), so the time that the computer
//!   slept counts as inactive time. Only a line typed in this terminal is owner input.
//!   When the desktop's idle hint says the session is active (the owner works in
//!   another app), the vault stays open, as the desktop does.
//! - **Session events:** with the device policy "When the screen locks or the computer
//!   sleeps", a screen lock, a sleep, a user switch and the end of the login session
//!   lock the vault and end the service.
//! - **Sources:** a build with the `session-bus` feature (the Linux desktop package)
//!   reads systemd-logind and the screen saver over D-Bus
//!   ([`crate::native::linux::session_bus`]). A build without it (the headless owner
//!   build links no D-Bus client) sees a sleep only after the wake, from the gap of the
//!   clocks ([`SuspendDetector`]), and sees no screen lock.
//!
//! The service never reuses an owner check, so these events do not end a "How often
//! to ask" window here: there is none.
use std::time::Duration;

use crate::native::device_policy::DevicePolicy;
use crate::native::session_lock::{LockRule, SessionEvent, SuspendDetector};

pub use crate::native::session_lock::sleep_inclusive_now;

/// The inactivity time when neither `--idle-minutes` nor the device policy names one.
pub const DEFAULT_IDLE: Duration = Duration::from_secs(15 * 60);

/// The session events of this system for the service, polled on every tick.
pub trait LockObserver: Send {
    /// The events since the last call, in order.
    fn events(&mut self) -> Vec<SessionEvent>;
    /// The service decided what a sleep event does (it locked, or the rule keeps the
    /// vault open): the system may sleep now.
    fn sleep_decided(&mut self) {}
}

/// A closure is an observer without a sleep inhibitor (tests, simple sources).
impl<F: FnMut() -> Vec<SessionEvent> + Send> LockObserver for F {
    fn events(&mut self) -> Vec<SessionEvent> {
        self()
    }
}

/// The inactivity time and the session rule of one service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockSettings {
    /// Lock after this long without a typed line.
    pub idle: Duration,
    /// Also lock at screen lock, sleep, user switch and session end.
    pub on_session_lock: bool,
    /// A sentence for the owner when the device policy could not be used.
    pub note: Option<String>,
}

/// The settings from `--idle-minutes` (`given`) and the device policy file:
/// `--idle-minutes` when given, else the policy's "Lock after inactivity" time when it
/// names one (15 minutes, 1 hour, 4 hours), else [`DEFAULT_IDLE`]. The policy "Never"
/// gives [`DEFAULT_IDLE`]: the service always has an inactivity time. The policy "When
/// the screen locks or the computer sleeps" adds the session rule. A damaged, foreign
/// or too-open policy file fails closed: the default time and the session rule.
pub fn lock_settings(
    given: Option<Duration>,
    policy: Result<DevicePolicy, String>,
) -> LockSettings {
    let (rule, note) = match policy {
        Ok(policy) => match LockRule::parse(&policy.auto_lock) {
            Some(rule) => (rule, None),
            None => (
                LockRule::OnSessionLock,
                Some("The device settings file names an unknown lock setting.".to_owned()),
            ),
        },
        Err(why) => (LockRule::OnSessionLock, Some(why)),
    };
    let note = note.map(|why| {
        format!(
            "{why} The vault locks after the inactivity time and when the screen locks or the computer sleeps."
        )
    });
    let policy_idle = match rule {
        LockRule::After(limit) => Some(limit),
        LockRule::Never | LockRule::OnSessionLock => None,
    };
    LockSettings {
        idle: given.or(policy_idle).unwrap_or(DEFAULT_IDLE),
        on_session_lock: rule == LockRule::OnSessionLock,
        note,
    }
}

/// The settings of this user: `given` and `device-policy.json` in the data directory.
pub fn system_lock_settings(given: Option<Duration>) -> LockSettings {
    lock_settings(
        given,
        crate::native::device_policy::read(&crate::native::device_policy::default_path()),
    )
}

/// Why the vault locked, for "Vault locked {reason}."
pub fn event_reason(event: SessionEvent) -> &'static str {
    match event {
        SessionEvent::ScreenLocked => "because the screen locked",
        SessionEvent::Sleep => "because the computer slept",
        SessionEvent::SessionInactive => "because another session became active",
        SessionEvent::SessionEnded => "because the login session ended",
        _ => "because the session changed",
    }
}

/// The observer of this system. With the `session-bus` feature on Linux: logind and the
/// screen saver over D-Bus, with a sleep delay inhibitor, and the clock gap (the
/// observer's heartbeat checks it). Otherwise the clock gap only.
pub fn system_observer() -> Box<dyn LockObserver> {
    #[cfg(all(target_os = "linux", feature = "session-bus"))]
    {
        Box::new(bus::BusObserver::start())
    }
    #[cfg(not(all(target_os = "linux", feature = "session-bus")))]
    {
        Box::new(ClockObserver::default())
    }
}

/// A sleep seen after the wake: the sleep-inclusive clock ran ahead of the awake clock.
#[derive(Debug, Default)]
pub struct ClockObserver {
    detector: SuspendDetector,
}

impl LockObserver for ClockObserver {
    fn events(&mut self) -> Vec<SessionEvent> {
        if self.detector.check() {
            vec![SessionEvent::Sleep]
        } else {
            Vec::new()
        }
    }
}

#[cfg(all(target_os = "linux", feature = "session-bus"))]
mod bus {
    use std::sync::Arc;
    use std::sync::mpsc::{self, Receiver};

    use super::LockObserver;
    use crate::native::linux::session_bus::{SessionObserver, SleepAck};
    use crate::native::session_lock::SessionEvent;

    pub(super) struct BusObserver {
        events: Receiver<SessionEvent>,
        ack: Arc<SleepAck>,
        /// Kept for its threads and the inhibitor; dropping it stops them.
        _observer: SessionObserver,
    }

    impl BusObserver {
        pub(super) fn start() -> Self {
            let mut observer = SessionObserver::connect();
            let (send, events) = mpsc::channel();
            observer.start(Arc::new(move |event| {
                let _ = send.send(event);
            }));
            Self {
                events,
                ack: observer.sleep_ack(),
                _observer: observer,
            }
        }
    }

    impl LockObserver for BusObserver {
        fn events(&mut self) -> Vec<SessionEvent> {
            self.events.try_iter().collect()
        }
        fn sleep_decided(&mut self) {
            self.ack.ack();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: Duration = Duration::from_secs(3600);

    fn policy(auto_lock: &str) -> Result<DevicePolicy, String> {
        Ok(DevicePolicy {
            owner_frequency: "every_time".into(),
            auto_lock: auto_lock.into(),
        })
    }

    #[test]
    fn idle_minutes_win_then_the_policy_time_then_fifteen_minutes() {
        let given = Duration::from_secs(300);
        for code in ["never", "15m", "1h", "4h", "session"] {
            assert_eq!(
                lock_settings(Some(given), policy(code)).idle,
                given,
                "{code}"
            );
        }
        assert_eq!(lock_settings(None, policy("1h")).idle, HOUR);
        assert_eq!(lock_settings(None, policy("4h")).idle, 4 * HOUR);
        assert_eq!(lock_settings(None, policy("15m")).idle, DEFAULT_IDLE);
        // No time in the policy: the service keeps its default inactivity time.
        assert_eq!(lock_settings(None, policy("never")).idle, DEFAULT_IDLE);
        assert_eq!(lock_settings(None, policy("session")).idle, DEFAULT_IDLE);
        // A missing file reads as the defaults ("Never").
        assert_eq!(
            lock_settings(None, Ok(DevicePolicy::default())),
            LockSettings {
                idle: DEFAULT_IDLE,
                on_session_lock: false,
                note: None
            }
        );
    }

    #[test]
    fn only_the_session_policy_locks_on_session_events() {
        for (code, on) in [
            ("never", false),
            ("15m", false),
            ("1h", false),
            ("4h", false),
            ("session", true),
        ] {
            let settings = lock_settings(None, policy(code));
            assert_eq!(settings.on_session_lock, on, "{code}");
            assert_eq!(settings.note, None, "{code}");
        }
    }

    #[test]
    fn a_damaged_or_unknown_policy_fails_closed() {
        for result in [
            Err("The device settings file is damaged.".to_owned()),
            policy("forever"),
        ] {
            let settings = lock_settings(None, result);
            assert_eq!(settings.idle, DEFAULT_IDLE);
            assert!(settings.on_session_lock);
            assert!(settings.note.is_some());
        }
        let given = Duration::from_secs(60);
        let settings = lock_settings(Some(given), Err("damaged".into()));
        assert_eq!(settings.idle, given);
        assert!(settings.on_session_lock);
    }

    #[test]
    fn every_locking_event_has_its_own_reason() {
        let events = [
            SessionEvent::ScreenLocked,
            SessionEvent::Sleep,
            SessionEvent::SessionInactive,
            SessionEvent::SessionEnded,
        ];
        let reasons: std::collections::BTreeSet<_> =
            events.iter().map(|e| event_reason(*e)).collect();
        assert_eq!(reasons.len(), events.len());
        assert!(events.iter().all(|e| e.locks_session()));
    }

    #[test]
    fn the_clock_observer_reports_no_sleep_without_a_suspend() {
        let mut observer = ClockObserver::default();
        assert!(observer.events().is_empty());
    }
}
