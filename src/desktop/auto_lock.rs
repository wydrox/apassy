//! Optional device-local inactivity policy. Broker traffic never feeds owner input.
use super::{
    DesktopApp,
    owner_check::{Task, TaskPoll},
};
use eframe::egui;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LockPolicy {
    #[default]
    Never,
    FifteenMinutes,
    OneHour,
    FourHours,
    Session,
}
impl LockPolicy {
    pub(crate) const ALL: [Self; 5] = [
        Self::Never,
        Self::FifteenMinutes,
        Self::OneHour,
        Self::FourHours,
        Self::Session,
    ];
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Never => "Never",
            Self::FifteenMinutes => "15 minutes",
            Self::OneHour => "1 hour",
            Self::FourHours => "4 hours",
            Self::Session if cfg!(target_os = "linux") => {
                "When the screen locks or the computer sleeps"
            }
            Self::Session => concat!("When the ", crate::computer!(), " locks or sleeps"),
        }
    }
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::Never => "never",
            Self::FifteenMinutes => "15m",
            Self::OneHour => "1h",
            Self::FourHours => "4h",
            Self::Session => "session",
        }
    }
    pub(crate) fn parse(code: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.code() == code)
    }
    fn timeout(self) -> Option<Duration> {
        match self {
            Self::FifteenMinutes => Some(Duration::from_secs(900)),
            Self::OneHour => Some(Duration::from_secs(3600)),
            Self::FourHours => Some(Duration::from_secs(14400)),
            _ => None,
        }
    }
}

#[derive(Default)]
struct Sample {
    idle: Option<(Duration, Instant, Duration)>,
    peak: Option<Duration>,
    generation: u64,
    session: bool,
}
/// Native heartbeat snapshots plus a sticky lock/sleep event (survives wake).
#[derive(Clone, Default)]
pub(crate) struct IdleSource(Arc<Mutex<Sample>>);
impl IdleSource {
    pub(crate) fn record(&self, seconds: Option<f64>, session: bool) -> bool {
        self.record_at(seconds, session, clock_now())
    }
    fn record_at(&self, seconds: Option<f64>, session: bool, now: Duration) -> bool {
        let mut s = self.0.lock().unwrap();
        // Preserve inactivity across suspension even if wake input resets CGEventSource.
        let suspended = s.idle.and_then(|(idle, at, clock)| {
            let elapsed = now.saturating_sub(clock);
            (elapsed > at.elapsed() + Duration::from_millis(10)).then_some(idle + elapsed)
        });
        s.peak = s.peak.max(suspended);
        s.idle = seconds
            .and_then(|v| Duration::try_from_secs_f64(v).ok())
            .map(|d| (d, Instant::now(), now));
        s.peak = s.peak.max(s.idle.map(|(d, _, _)| d));
        // Keep inferred sleep sticky too: a fresh wake heartbeat may arrive
        // before either the UI or a broker worker checks the old sample.
        let session = session || suspended.is_some();
        if session {
            s.generation = s.generation.wrapping_add(1);
        }
        s.session |= session;
        session
    }
    /// Holds the sample, as a heartbeat that writes it does, until the guard drops.
    #[cfg(test)]
    pub(crate) fn hold_for_test(&self) -> std::sync::MutexGuard<'_, impl Sized> {
        self.0.lock().unwrap()
    }
    pub(super) fn take(&self) -> (Option<Duration>, bool, u64) {
        let mut s = self.0.lock().unwrap();
        // Missing/stale telemetry must not unexpectedly interrupt agent runs.
        let idle = sample_idle(&s).max(s.peak.take());
        (idle, std::mem::take(&mut s.session), s.generation)
    }
}
/// The sleep-inclusive clock of owner deadlines: Darwin's `CLOCK_MONOTONIC` on macOS,
/// `CLOCK_BOOTTIME` on Linux. `Instant` (the awake clock) pauses during sleep on both,
/// so the gap between the two is the time suspended.
fn clock_now() -> Duration {
    crate::broker::approvals::owner_window::sleep_inclusive_now().unwrap_or_default()
}
fn sample_idle(s: &Sample) -> Option<Duration> {
    s.idle.and_then(|(idle, at, clock)| {
        sampled_idle(idle, at.elapsed(), clock_now().saturating_sub(clock))
    })
}
fn sampled_idle(idle: Duration, awake: Duration, elapsed: Duration) -> Option<Duration> {
    // A stalled helper is not evidence of inactivity. Suspension is: the
    // sleep-inclusive clock advances while Instant pauses (macOS and Linux).
    if elapsed > awake + Duration::from_millis(10) {
        Some(idle + elapsed)
    } else {
        // Do not extrapolate awake time: input may have reset system idle since
        // the last 30-second sample. Wait for the next real sample instead.
        (awake < Duration::from_secs(32)).then_some(idle)
    }
}
fn session_due(s: &Sample, generation: u64, now: Duration) -> bool {
    s.generation != generation
        || s.idle.is_some_and(|(_, at, clock)| {
            // The helper's sleep notification can still be queued at wake.
            now.saturating_sub(clock) > at.elapsed() + Duration::from_millis(10)
        })
}
#[derive(Default)]
struct Timer {
    owner_at: Duration,
    unlocked: bool,
}
impl Timer {
    #[allow(clippy::too_many_arguments)] // Explicit injected inputs to the policy transition.
    fn due(
        &mut self,
        policy: LockPolicy,
        now: Duration,
        idle: Option<Duration>,
        owner_input: bool,
        unlocked: bool,
        session: bool,
    ) -> bool {
        let expired = unlocked
            && self.unlocked
            && (policy == LockPolicy::Session && session
                || policy.timeout().is_some_and(|limit| {
                    now.saturating_sub(self.owner_at) >= limit && idle.is_some_and(|d| d >= limit)
                }));
        if expired {
            return true;
        }
        if owner_input || unlocked && !self.unlocked {
            self.owner_at = now;
        }
        self.unlocked = unlocked;
        unlocked
            && (policy == LockPolicy::Session && session
                || policy.timeout().is_some_and(|limit| {
                    now.saturating_sub(self.owner_at) >= limit && idle.is_some_and(|d| d >= limit)
                }))
    }
}
pub(crate) struct AutoLock {
    pub(crate) policy: LockPolicy,
    pub(crate) source: IdleSource,
    pub(crate) note: Option<String>,
    task: Option<Task<Result<LockPolicy, String>>>,
    timer: Timer,
    input_time: Option<u64>,
}
impl Default for AutoLock {
    fn default() -> Self {
        Self {
            policy: LockPolicy::Never,
            source: IdleSource::default(),
            note: None,
            task: None,
            timer: Timer::default(),
            input_time: None,
        }
    }
}
impl AutoLock {
    fn owner_input(&mut self, ctx: &egui::Context) -> bool {
        let (time, input) = ctx.input(|i| {
            (
                i.time.to_bits(),
                i.events.iter().any(|e| {
                    matches!(
                        e,
                        egui::Event::Key { .. }
                            | egui::Event::Text(_)
                            | egui::Event::Paste(_)
                            | egui::Event::PointerMoved(_)
                            | egui::Event::PointerButton { .. }
                            | egui::Event::MouseWheel { .. }
                            | egui::Event::Touch { .. }
                    )
                }),
            )
        });
        // eframe run_logic preserves the last UI pass's input and time while
        // hidden. Consume that pass once, so stale events cannot postpone lock.
        self.input_time.replace(time) != Some(time) && input
    }
    fn now(&self) -> Duration {
        clock_now()
    }
    pub(crate) fn busy(&self) -> bool {
        self.task.is_some()
    }
}
impl DesktopApp {
    pub(crate) fn start_auto_lock_read(
        &mut self,
        helper: crate::native::NativeHelper,
        ctx: &egui::Context,
    ) {
        self.auto_lock.task = Some(Task::spawn(Some(ctx.clone()), move || {
            helper.auto_lock_read().map_err(|e| e.to_string())
        }));
    }
    /// Read or write the setting on a worker thread (Linux: the device settings file).
    #[cfg(target_os = "linux")]
    pub(crate) fn start_auto_lock_task(
        &mut self,
        ctx: &egui::Context,
        work: impl FnOnce() -> Result<LockPolicy, String> + Send + 'static,
    ) {
        self.auto_lock.task = Some(Task::spawn(Some(ctx.clone()), work));
    }
    /// Whether this build can keep the setting (the macOS helper, or Linux's file).
    pub(crate) fn auto_lock_storable(&self) -> bool {
        self.owner.helper.is_some() || cfg!(target_os = "linux")
    }
    pub(crate) fn save_auto_lock(&mut self, policy: LockPolicy, ctx: &egui::Context) {
        #[cfg(target_os = "linux")]
        self.start_auto_lock_task(ctx, move || {
            crate::desktop::session_watch::store::write_auto_lock(policy)
        });
        #[cfg(not(target_os = "linux"))]
        {
            let Some(helper) = self.owner.helper.clone() else {
                return;
            };
            self.auto_lock.task = Some(Task::spawn(Some(ctx.clone()), move || {
                helper
                    .auto_lock_write(policy)
                    .map(|()| policy)
                    .map_err(|e| e.to_string())
            }));
        }
    }
    pub(crate) fn poll_auto_lock(&mut self, ctx: &egui::Context) {
        if let Some(task) = &self.auto_lock.task {
            let result = match task.poll() {
                TaskPoll::Waiting => None,
                TaskPoll::Done(r) => Some(r),
                TaskPoll::Lost => Some(Err("Setting service stopped".into())),
            };
            if let Some(result) = result {
                self.auto_lock.task = None;
                self.auto_lock.policy = result.as_ref().copied().unwrap_or_default();
                self.auto_lock.note = result
                    .err()
                    .map(|_| "The setting could not be read or saved. Never is active.".into());
                self.auto_lock.timer.owner_at = self.auto_lock.now();
            }
        }
        let owner_input = self.auto_lock.owner_input(ctx);
        let fenced = self
            .owner_ui
            .session
            .with_vault(|v| v.access_expired())
            .unwrap_or(false);
        let (idle, session, generation) = self.auto_lock.source.take();
        // A sleep held by the Linux delay inhibitor may go once this pass decided.
        let sleep_held = session;
        let unlocked = fenced || !self.owner_ui.session.is_locked();
        if fenced
            || self.auto_lock.timer.due(
                self.auto_lock.policy,
                self.auto_lock.now(),
                idle,
                owner_input,
                unlocked,
                session,
            )
        {
            self.lock_vault(Some(ctx));
            self.auto_lock.timer.unlocked = false;
        }
        if sleep_held {
            self.owner.session.ack_sleep();
        }
        if unlocked && !self.owner_ui.session.is_locked() {
            let policy = self.auto_lock.policy;
            let owner_at = self.auto_lock.timer.owner_at;
            let source = self.auto_lock.source.clone();
            let expiry: Option<Arc<dyn Fn() -> bool + Send + Sync>> = (policy != LockPolicy::Never)
                .then(|| {
                    // Keep the generation of the consumed sample. An event that
                    // arrives during this UI pass must invalidate the new fence.
                    let expired = AtomicBool::new(false);
                    Arc::new(move || {
                        if expired.load(Ordering::Acquire) {
                            return true;
                        }
                        let s = source.0.lock().unwrap();
                        let due = policy == LockPolicy::Session
                            && session_due(&s, generation, clock_now())
                            || policy.timeout().is_some_and(|limit| {
                                clock_now().saturating_sub(owner_at) >= limit
                                    && sample_idle(&s).max(s.peak).is_some_and(|d| d >= limit)
                            });
                        if due {
                            expired.store(true, Ordering::Release);
                        }
                        // A concurrent delivery may have latched expiry while
                        // this caller waited for the sample mutex. Never clear it
                        // just because a later sample reports fresh input.
                        due || expired.load(Ordering::Acquire)
                    }) as Arc<dyn Fn() -> bool + Send + Sync>
                });
            self.owner_ui
                .session
                .with_vault(|v| v.set_access_expiry(expiry));
        }
        if self.auto_lock.busy() {
            ctx.request_repaint_after(Duration::from_millis(250));
        } else if self.auto_lock.policy != LockPolicy::Never {
            ctx.request_repaint_after(Duration::from_secs(30));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn auto_lock_hidden_logic_does_not_replay_owner_input() {
        let ctx = egui::Context::default();
        let mut lock = AutoLock::default();
        let raw = egui::RawInput {
            time: Some(1.0),
            events: vec![egui::Event::Text("synthetic".into())],
            ..Default::default()
        };
        ctx.run_ui(raw, |_| assert!(lock.owner_input(&ctx)))
            .drop_without_applying_deltas();
        for _ in 0..3 {
            let _ = ctx.run_logic(&egui::RawInput::default(), |_| {
                assert!(!lock.owner_input(&ctx))
            });
        }
        let raw = egui::RawInput {
            time: Some(2.0),
            events: vec![egui::Event::Text("new".into())],
            ..Default::default()
        };
        ctx.run_ui(raw, |_| assert!(lock.owner_input(&ctx)))
            .drop_without_applying_deltas();
    }
    #[test]
    fn auto_lock_wake_input_cannot_rescue_expired_deadline() {
        let mut timer = Timer::default();
        let p = LockPolicy::FifteenMinutes;
        assert!(!timer.due(p, Duration::ZERO, Some(Duration::ZERO), false, true, false));
        assert!(timer.due(
            p,
            Duration::from_secs(901),
            Some(Duration::from_secs(901)),
            true,
            true,
            false
        ));
        assert_eq!(timer.owner_at, Duration::ZERO);
    }

    #[test]
    fn auto_lock_sleep_gap_survives_reset_idle_sample() {
        let source = IdleSource::default();
        // Model 901 seconds of sleep: the awake clock has not advanced.
        source.0.lock().unwrap().idle = Some((Duration::ZERO, Instant::now(), Duration::ZERO));
        source.record_at(Some(0.0), false, Duration::from_secs(901));
        let (idle, session, _) = source.take();
        assert!(idle.unwrap() >= Duration::from_secs(901));
        assert!(session);
    }

    /// A suspend gap triggers auto-lock: the sleep-inclusive clock jumps, the awake clock
    /// (`Instant`) does not, and the wake input resets the system idle time to zero.
    #[test]
    fn auto_lock_suspend_gap_locks_on_wake() {
        for policy in [LockPolicy::FifteenMinutes, LockPolicy::Session] {
            let source = IdleSource::default();
            let mut timer = Timer::default();
            // The sample ages are read on the real clock: start the injected one there.
            let start = clock_now();
            source.record_at(Some(0.0), false, start);
            let (idle, session, _) = source.take();
            assert!(!timer.due(policy, start, idle, true, true, session));
            // 901 seconds of suspend; the first sample after the wake says "idle 0".
            let woke = start + Duration::from_secs(901);
            assert!(source.record_at(Some(0.0), false, woke));
            let (idle, session, _) = source.take();
            assert!(idle.unwrap() >= Duration::from_secs(901));
            assert!(session);
            assert!(
                timer.due(policy, woke, idle, true, true, session),
                "{policy:?} locks after the suspend"
            );
        }
    }

    /// The production clock counts suspension: `CLOCK_BOOTTIME` on Linux, Darwin's
    /// `CLOCK_MONOTONIC` on macOS (unchanged).
    #[test]
    fn auto_lock_production_clock_counts_suspended_time() {
        use crate::broker::approvals::owner_window::SLEEP_INCLUSIVE_CLOCK;
        #[cfg(target_os = "linux")]
        assert_eq!(SLEEP_INCLUSIVE_CLOCK, rustix::time::ClockId::Boottime);
        #[cfg(target_os = "macos")]
        assert_eq!(SLEEP_INCLUSIVE_CLOCK, rustix::time::ClockId::Monotonic);
        let read = || -> Duration {
            rustix::time::clock_gettime(SLEEP_INCLUSIVE_CLOCK)
                .try_into()
                .unwrap()
        };
        let before = read();
        let now = clock_now();
        let after = read();
        assert!(before <= now && now <= after);
    }

    #[test]
    fn auto_lock_session_sleep_fence_precedes_the_queued_notification() {
        let sample = Sample {
            idle: Some((Duration::ZERO, Instant::now(), Duration::ZERO)),
            ..Default::default()
        };
        assert!(!session_due(&sample, 0, Duration::ZERO));
        assert!(session_due(&sample, 0, Duration::from_secs(901)));
        assert!(session_due(&sample, 1, Duration::ZERO));
    }

    #[test]
    fn auto_lock_event_during_fence_install_keeps_the_consumed_generation() {
        let source = IdleSource::default();
        let (_, _, generation) = source.take();
        source.record(Some(0.0), true);
        let sample = source.0.lock().unwrap();
        assert!(session_due(&sample, generation, clock_now()));
    }

    #[test]
    fn auto_lock_access_fence_blocks_worker_before_ui_lock() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let dir = tempfile::tempdir().unwrap();
        let mut vault = crate::vault::Vault::create(
            &dir.path().join("test.apassy"),
            "synthetic review passphrase",
        )
        .unwrap();
        vault.unlock("synthetic review passphrase").unwrap();
        let expired = Arc::new(AtomicBool::new(false));
        let fence = expired.clone();
        vault.set_access_expiry(Some(Arc::new(move || fence.load(Ordering::SeqCst))));
        assert!(!vault.is_locked());
        expired.store(true, Ordering::SeqCst);
        assert!(vault.is_locked());
        vault.lock().unwrap();
        vault.unlock("synthetic review passphrase").unwrap();
        assert!(!vault.is_locked());
    }

    #[test]
    fn auto_lock_defaults_and_codes() {
        assert_eq!(LockPolicy::default(), LockPolicy::Never);
        assert_eq!(
            LockPolicy::parse("damaged").unwrap_or_default(),
            LockPolicy::Never
        );
        for p in LockPolicy::ALL {
            assert_eq!(LockPolicy::parse(p.code()), Some(p));
        }
    }

    #[test]
    fn auto_lock_idle_samples_do_not_extrapolate_awake_time() {
        let idle = Duration::from_secs(899);
        let awake = Duration::from_secs(29);
        assert_eq!(sampled_idle(idle, awake, awake), Some(idle));
        let stale = Duration::from_secs(33);
        assert_eq!(sampled_idle(idle, stale, stale), None);
        assert_eq!(
            sampled_idle(idle, awake, Duration::from_secs(930)),
            Some(Duration::from_secs(1829))
        );
    }

    #[test]
    fn auto_lock_each_option_with_injected_clock_and_idle() {
        for p in LockPolicy::ALL {
            let mut t = Timer::default();
            assert!(!t.due(p, Duration::ZERO, Some(Duration::ZERO), false, true, false));
            if let Some(d) = p.timeout() {
                assert!(!t.due(p, d - Duration::from_secs(1), Some(d), false, true, false));
                assert!(!t.due(p, d, Some(Duration::ZERO), false, true, false));
                assert!(!t.due(p, d, None, false, true, false));
                assert!(t.due(p, d, Some(d), false, true, false));
            } else {
                assert!(!t.due(
                    p,
                    Duration::from_secs(999999),
                    Some(Duration::from_secs(999999)),
                    false,
                    true,
                    false
                ));
                assert_eq!(
                    t.due(p, Duration::from_secs(999999), None, false, true, true),
                    p == LockPolicy::Session
                );
            }
        }
    }
    #[test]
    fn auto_lock_agent_polls_do_not_reset_but_owner_input_does() {
        let mut t = Timer::default();
        let p = LockPolicy::FifteenMinutes;
        let dir = tempfile::tempdir().unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket = dir.path().join("broker.sock");
        let mut vault = crate::vault::Vault::create(
            &dir.path().join("test.apassy"),
            "synthetic review passphrase",
        )
        .unwrap();
        vault.unlock("synthetic review passphrase").unwrap();
        let (_, token) = vault
            .register_agent("Synthetic MCP metadata agent")
            .unwrap();
        let _broker = crate::broker::start_with_tls(
            Arc::new(Mutex::new(Some(vault))),
            &socket,
            crate::broker::http::TlsClient::with_extra_roots(vec![]).unwrap(),
        )
        .unwrap();
        let ctx = egui::Context::default();
        let mut input = AutoLock::default();
        for seconds in (0..900).step_by(150) {
            // Real broker metadata traffic, as sent by the MCP adapter. It must
            // produce no owner input and cannot extend the injected deadline.
            let reply = crate::agent::client::send(
                &socket,
                token.expose(),
                crate::agent::wire::Action::ListAccess,
            )
            .unwrap();
            assert!(reply.ok);
            assert!(!input.owner_input(&ctx));
            assert!(!t.due(
                p,
                Duration::from_secs(seconds),
                Some(Duration::from_secs(seconds)),
                false,
                true,
                false
            ));
        }
        assert!(t.due(
            p,
            Duration::from_secs(900),
            Some(Duration::from_secs(900)),
            false,
            true,
            false
        ));
        assert!(!t.due(
            p,
            Duration::from_secs(900),
            Some(Duration::ZERO),
            true,
            true,
            false
        ));
        assert!(!t.due(
            p,
            Duration::from_secs(1799),
            Some(Duration::from_secs(1799)),
            false,
            true,
            false
        ));
        assert!(t.due(
            p,
            Duration::from_secs(1800),
            Some(Duration::from_secs(1800)),
            false,
            true,
            false
        ));
    }
    #[test]
    fn auto_lock_native_event_survives_wake() {
        let source = IdleSource::default();
        source.record(Some(0.0), true);
        source.record(Some(0.0), false);
        assert!(source.take().1);
        assert!(!source.take().1);
    }
}
