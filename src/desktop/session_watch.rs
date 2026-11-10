//! Linux session observation in the desktop: [`SessionEvent`]s of the D-Bus observer
//! (`native::linux::session_bus`) end the owner-check window and feed auto-lock.
//!
//! macOS has the helper's lifecycle stream (`native::owner_lifecycle`) for the same job.
//! [`Applier`] is platform-independent so the tests run everywhere; only
//! `SessionWatch::start` is Linux-only. The rules:
//! - Lock, sleep, a session switch, the session end and a lost source end the window
//!   and every issued approval (a new lifecycle counter, as on macOS).
//! - The window can be seeded and reused only while a lock source exists, nothing was
//!   lost, and the last readings say unlocked and active. Every reuse also runs
//!   `SessionObserver::verify` (`native::linux::session_bus`).
//! - Auto-lock gets the desktop's idle hint as its "system idle" sample: 0 while the
//!   desktop reports input, else unbounded, so input in the Apassy window decides
//!   ([`SessionIdle::system_idle_sample`]). The heartbeat refreshes it every 10 s, also
//!   with no bus, so "Lock after inactivity" always works on input in Apassy.
// Only the Linux observer delivers session events; macOS builds keep the code for tests.
#![cfg_attr(
    all(not(target_os = "linux"), not(test)),
    allow(dead_code, unused_imports)
)]
use crate::broker::approvals::owner_window::OwnerWindow;
use crate::desktop::auto_lock::IdleSource;
use crate::native::session_lock::{Coverage, Observation, SessionEvent, SessionIdle};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_IDENTITY: AtomicU64 = AtomicU64::new(1 << 32);

#[derive(Debug)]
struct ApplyState {
    counter: u64,
    locked: bool,
    active: bool,
    lost: bool,
}

/// Applies one observer's events to the owner window and the auto-lock source.
pub(crate) struct Applier {
    window: OwnerWindow,
    source: IdleSource,
    observation: Observation,
    identity: u64,
    state: Mutex<ApplyState>,
}

impl Applier {
    pub(crate) fn new(window: OwnerWindow, source: IdleSource, observation: Observation) -> Self {
        let applier = Self {
            window,
            source,
            observation,
            identity: NEXT_IDENTITY.fetch_add(1, Ordering::Relaxed),
            // Fail closed until the first reading: locked. Only logind reports a user
            // switch, so without a logind session the session counts as active.
            state: Mutex::new(ApplyState {
                counter: 0,
                locked: true,
                active: !observation.logind_session,
                lost: false,
            }),
        };
        applier.window.invalidate_for("helper_started");
        applier.publish(&applier.state.lock().unwrap());
        applier
    }

    fn publish(&self, s: &ApplyState) {
        let usable = self.observation.lock_observed() && !s.lost && !s.locked && s.active;
        self.window.snapshot(self.identity, s.counter, usable);
    }

    /// Apply one event. Returns true when the UI should look again (repaint).
    pub(crate) fn apply(&self, event: SessionEvent) -> bool {
        let mut s = self.state.lock().unwrap();
        match event {
            SessionEvent::ScreenLocked => s.locked = true,
            SessionEvent::ScreenUnlocked => s.locked = false,
            SessionEvent::SessionInactive | SessionEvent::SessionEnded => s.active = false,
            SessionEvent::SessionActive => s.active = true,
            SessionEvent::SourceLost => s.lost = true,
            SessionEvent::Sleep | SessionEvent::Idle(_) => {}
        }
        if event.ends_owner_window() {
            s.counter = s
                .counter
                .checked_add(1)
                .expect("lifecycle counter exhausted");
            self.window.invalidate_for(event.name());
        }
        self.publish(&s);
        drop(s);
        let idle = match event {
            SessionEvent::Idle(idle) => idle,
            // Lock events keep no hint: only input in Apassy counts until the next one.
            _ => SessionIdle::Unknown,
        };
        let session = event.locks_session();
        // `record` keeps a lock or sleep sticky until auto-lock takes it (as on macOS).
        self.source
            .record(Some(idle.system_idle_sample().as_secs_f64()), session)
            || event.ends_owner_window()
    }
}

/// The desktop's observer slot (one field of `OwnerFlows`).
#[derive(Default)]
pub(crate) struct SessionWatch {
    #[cfg(target_os = "linux")]
    observer: Option<std::sync::Arc<crate::native::linux::session_bus::SessionObserver>>,
    /// Tests show the texts of a chosen situation.
    #[cfg(test)]
    pub(crate) fixed: Option<Observation>,
}

impl SessionWatch {
    /// What is observed now. Without a started observer (tests, macOS): nothing.
    pub(crate) fn observation(&self) -> Observation {
        #[cfg(test)]
        if let Some(fixed) = self.fixed {
            return fixed;
        }
        #[cfg(target_os = "linux")]
        if let Some(observer) = &self.observer {
            return observer.observation();
        }
        Observation::default()
    }

    /// After a lock decision: let a held sleep go.
    pub(crate) fn ack_sleep(&self) {
        #[cfg(target_os = "linux")]
        if let Some(observer) = &self.observer {
            observer.sleep_ack().ack();
        }
    }

    /// Find the sources, wire them to the owner window and auto-lock, and start.
    #[cfg(target_os = "linux")]
    pub(crate) fn start(
        window: OwnerWindow,
        source: IdleSource,
        ctx: eframe::egui::Context,
    ) -> Self {
        use crate::broker::approvals::owner_window::LifecycleProbe;
        use crate::native::linux::session_bus::SessionObserver;
        use std::sync::Arc;
        let mut observer = SessionObserver::connect();
        let applier = Arc::new(Applier::new(window.clone(), source, observer.observation()));
        observer.start(Arc::new(move |event| {
            if applier.apply(event) {
                ctx.request_repaint();
            }
        }));
        let observer = Arc::new(observer);
        let probe = Arc::downgrade(&observer);
        window.set_probe(LifecycleProbe(Arc::new(move || {
            probe.upgrade().is_some_and(|o| o.verify())
        })));
        Self {
            observer: Some(observer),
            #[cfg(test)]
            fixed: None,
        }
    }
}

/// The note under "How often to ask" on Linux.
pub(crate) fn owner_note(obs: &Observation) -> String {
    match obs.coverage() {
        Coverage::None => format!(
            "Each sensitive action requires fresh confirmation with the vault passphrase or optional system authentication. Approval reuse is off: Apassy cannot observe the screen lock here. {}",
            obs.missing().join(" ")
        ),
        Coverage::Full => "After you confirm with your passphrase or system authentication, Apassy doesn't ask again for anything until this time is up. The window ends when the screen locks, the computer sleeps, or you switch user.".to_owned(),
        Coverage::Partial => format!(
            "After you confirm with your passphrase or system authentication, Apassy doesn't ask again for anything until this time is up. The window ends at every lock and sleep that Apassy observes. Not observed: {}",
            obs.missing().join(" ")
        ),
    }
}

/// The note under "Lock after inactivity" on Linux.
pub(crate) fn lock_note(obs: &Observation) -> String {
    let agents = "Agents cannot use credentials while the vault is locked.";
    match obs.coverage() {
        Coverage::None => format!(
            "Lock the vault manually when you finish. Screen lock is not observed here; sleep is detected only from the clock after the wake. {} {} {agents}",
            obs.missing().join(" "),
            obs.inactivity_source()
        ),
        Coverage::Full => format!(
            "Screen lock, sleep and session end are observed through systemd-logind and the screen saver service. {} {agents}",
            obs.inactivity_source()
        ),
        Coverage::Partial => format!(
            "Apassy observes only part of this session. Not observed: {} {} {agents}",
            obs.missing().join(" "),
            obs.inactivity_source()
        ),
    }
}

/// The device settings on Linux (`native::device_policy`): the setting values, parsed.
#[cfg(any(target_os = "linux", test))]
pub(crate) mod store {
    use crate::broker::approvals::OwnerFrequency;
    use crate::desktop::auto_lock::LockPolicy;
    use crate::native::device_policy;
    use std::path::Path;

    pub(crate) fn read_owner_frequency_at(path: &Path) -> Result<OwnerFrequency, String> {
        let p = device_policy::read(path)?;
        OwnerFrequency::parse(&p.owner_frequency).ok_or_else(|| "unknown owner-check policy".into())
    }
    pub(crate) fn write_owner_frequency_at(
        path: &Path,
        f: OwnerFrequency,
    ) -> Result<OwnerFrequency, String> {
        let p = device_policy::update(path, |p| p.owner_frequency = f.code().into())?;
        OwnerFrequency::parse(&p.owner_frequency)
            .ok_or_else(|| "owner policy readback failed".into())
    }
    pub(crate) fn read_auto_lock_at(path: &Path) -> Result<LockPolicy, String> {
        let p = device_policy::read(path)?;
        LockPolicy::parse(&p.auto_lock).ok_or_else(|| "unknown auto-lock policy".into())
    }
    pub(crate) fn write_auto_lock_at(path: &Path, l: LockPolicy) -> Result<LockPolicy, String> {
        let p = device_policy::update(path, |p| p.auto_lock = l.code().into())?;
        LockPolicy::parse(&p.auto_lock).ok_or_else(|| "auto-lock readback failed".into())
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn read_owner_frequency() -> Result<OwnerFrequency, String> {
        read_owner_frequency_at(&device_policy::default_path())
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn write_owner_frequency(f: OwnerFrequency) -> Result<OwnerFrequency, String> {
        write_owner_frequency_at(&device_policy::default_path(), f)
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn read_auto_lock() -> Result<LockPolicy, String> {
        read_auto_lock_at(&device_policy::default_path())
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn write_auto_lock(l: LockPolicy) -> Result<LockPolicy, String> {
        write_auto_lock_at(&device_policy::default_path(), l)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::approvals::{CheckMethod, OwnerFrequency};
    use crate::desktop::auto_lock::LockPolicy;

    pub(crate) const FULL: Observation = Observation {
        session_bus: true,
        logind: true,
        logind_session: true,
        screen_saver: true,
        idle_hint: true,
        sleep_inhibitor: true,
    };
    const PARTIAL: Observation = Observation {
        screen_saver: false,
        idle_hint: false,
        ..FULL
    };

    fn window() -> OwnerWindow {
        let w = OwnerWindow::default();
        w.configure(OwnerFrequency::UntilLock);
        w
    }

    /// A fake signal source: the events an observer would deliver.
    fn deliver(applier: &Applier, events: &[SessionEvent]) {
        for e in events {
            applier.apply(*e);
        }
    }

    #[test]
    fn session_watch_lock_ends_the_reuse_window_and_unlock_never_restores_it() {
        let w = window();
        let source = IdleSource::default();
        let applier = Applier::new(w.clone(), source.clone(), FULL);
        // Locked until the first reading: no seed.
        w.seed([1; 32], CheckMethod::Passphrase, w.generation());
        assert!(w.ticket([1; 32]).is_none());
        deliver(
            &applier,
            &[SessionEvent::ScreenUnlocked, SessionEvent::SessionActive],
        );
        w.seed([1; 32], CheckMethod::Passphrase, w.generation());
        let (proof, _) = w
            .ticket([1; 32])
            .expect("reuse while observed and unlocked");
        deliver(&applier, &[SessionEvent::ScreenLocked]);
        assert!(!proof.valid());
        assert!(w.ticket([1; 32]).is_none());
        let (_, session, _) = source.take();
        assert!(session, "auto-lock sees the lock");
        deliver(&applier, &[SessionEvent::ScreenUnlocked]);
        assert!(w.ticket([1; 32]).is_none(), "a fresh check is needed");
        w.seed([1; 32], CheckMethod::Polkit, w.generation());
        assert!(w.ticket([1; 32]).is_some(), "polkit is a local owner check");
    }

    #[test]
    fn session_watch_sleep_switch_end_and_loss_end_the_window() {
        for event in [
            SessionEvent::Sleep,
            SessionEvent::SessionInactive,
            SessionEvent::SessionEnded,
            SessionEvent::SourceLost,
        ] {
            let w = window();
            let source = IdleSource::default();
            let applier = Applier::new(w.clone(), source.clone(), PARTIAL);
            deliver(
                &applier,
                &[SessionEvent::ScreenUnlocked, SessionEvent::SessionActive],
            );
            w.seed([1; 32], CheckMethod::Passphrase, w.generation());
            let (proof, _) = w.ticket([1; 32]).unwrap();
            deliver(&applier, &[event]);
            assert!(!proof.valid(), "{event:?}");
            assert_eq!(source.take().1, event.locks_session(), "{event:?}");
            if event != SessionEvent::Sleep {
                // Inactive, ended or lost: no new window either.
                deliver(&applier, &[SessionEvent::ScreenUnlocked]);
                w.seed([1; 32], CheckMethod::Passphrase, w.generation());
                assert!(w.ticket([1; 32]).is_none(), "{event:?}");
            }
        }
    }

    #[test]
    fn session_watch_unavailable_signals_keep_reuse_off() {
        let w = window();
        let applier = Applier::new(w.clone(), IdleSource::default(), Observation::default());
        deliver(
            &applier,
            &[
                SessionEvent::ScreenUnlocked,
                SessionEvent::SessionActive,
                SessionEvent::Idle(SessionIdle::Unknown),
            ],
        );
        w.seed([1; 32], CheckMethod::Passphrase, w.generation());
        assert!(w.ticket([1; 32]).is_none());
    }

    #[test]
    fn session_watch_idle_hint_feeds_the_auto_lock_sample() {
        let source = IdleSource::default();
        let applier = Applier::new(window(), source.clone(), FULL);
        applier.apply(SessionEvent::Idle(SessionIdle::Active));
        assert_eq!(source.take().0, Some(std::time::Duration::ZERO));
        applier.apply(SessionEvent::Idle(SessionIdle::Unknown));
        assert!(source.take().0.unwrap() > std::time::Duration::from_secs(14400));
    }

    #[test]
    fn session_watch_texts_state_full_partial_and_none() {
        let none = Observation::default();
        let text = owner_note(&none);
        assert!(text.contains("Approval reuse is off"), "{text}");
        assert!(text.contains("systemd-logind is not reachable"), "{text}");
        assert!(text.contains("There is no session bus"), "{text}");
        let text = lock_note(&none);
        assert!(
            text.contains("Lock the vault manually when you finish."),
            "{text}"
        );
        assert!(
            text.contains("counts only input in the Apassy window"),
            "{text}"
        );

        let text = owner_note(&FULL);
        assert!(text.contains("until this time is up"), "{text}");
        assert!(
            text.contains("the screen locks, the computer sleeps"),
            "{text}"
        );
        assert!(!text.contains("Not observed"), "{text}");
        let text = lock_note(&FULL);
        assert!(text.contains("observed through systemd-logind"), "{text}");
        assert!(
            text.contains("while the desktop reports the session idle"),
            "{text}"
        );

        let text = owner_note(&PARTIAL);
        assert!(
            text.contains("Not observed: No screen saver service"),
            "{text}"
        );
        let text = lock_note(&PARTIAL);
        assert!(text.contains("only part of this session"), "{text}");
        assert!(
            text.contains("counts only input in the Apassy window"),
            "{text}"
        );
        for text in [owner_note(&none), owner_note(&FULL), lock_note(&PARTIAL)] {
            assert!(
                !text.contains("Touch ID") && !text.contains("Mac"),
                "{text}"
            );
        }
    }

    #[test]
    fn session_watch_store_roundtrips_and_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = crate::native::device_policy::path_in(dir.path());
        assert_eq!(
            store::read_owner_frequency_at(&path),
            Ok(OwnerFrequency::EveryTime)
        );
        assert_eq!(store::read_auto_lock_at(&path), Ok(LockPolicy::Never));
        store::write_owner_frequency_at(&path, OwnerFrequency::FiveMinutes).unwrap();
        store::write_auto_lock_at(&path, LockPolicy::Session).unwrap();
        assert_eq!(
            store::read_owner_frequency_at(&path),
            Ok(OwnerFrequency::FiveMinutes)
        );
        assert_eq!(store::read_auto_lock_at(&path), Ok(LockPolicy::Session));
        std::fs::write(
            &path,
            br#"{"owner_frequency":"forever","auto_lock":"never"}"#,
        )
        .unwrap();
        assert!(store::read_owner_frequency_at(&path).is_err());
    }
}
