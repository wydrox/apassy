//! Optional device-local inactivity policy. Broker traffic never feeds owner input.
use super::{
    DesktopApp,
    owner_check::{Task, TaskPoll},
};
use eframe::egui;
use std::{
    sync::{Arc, Mutex},
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
            Self::Session => "When the Mac locks or sleeps",
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
    idle: Option<(Duration, Instant)>,
    session: bool,
}
/// Native heartbeat snapshots plus a sticky lock/sleep event (survives wake).
#[derive(Clone, Default)]
pub(crate) struct IdleSource(Arc<Mutex<Sample>>);
impl IdleSource {
    pub(crate) fn record(&self, seconds: Option<f64>, session: bool) {
        let mut s = self.0.lock().unwrap();
        s.idle = seconds
            .and_then(|v| Duration::try_from_secs_f64(v).ok())
            .map(|d| (d, Instant::now()));
        s.session |= session;
    }
    fn take(&self) -> (Option<Duration>, bool) {
        let mut s = self.0.lock().unwrap();
        // Missing/stale telemetry must not unexpectedly interrupt agent runs.
        let idle = s
            .idle
            .filter(|(_, at)| at.elapsed() < Duration::from_secs(2))
            .map(|(d, at)| d + at.elapsed());
        (idle, std::mem::take(&mut s.session))
    }
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
    start: Instant,
}
impl Default for AutoLock {
    fn default() -> Self {
        Self {
            policy: LockPolicy::Never,
            source: IdleSource::default(),
            note: None,
            task: None,
            timer: Timer::default(),
            start: Instant::now(),
        }
    }
}
impl AutoLock {
    fn now(&self) -> Duration {
        #[cfg(target_os = "macos")]
        {
            // CLOCK_MONOTONIC includes suspension on Darwin.
            rustix::time::clock_gettime(rustix::time::ClockId::Monotonic)
                .try_into()
                .unwrap_or_else(|_| self.start.elapsed())
        }
        #[cfg(not(target_os = "macos"))]
        {
            self.start.elapsed()
        }
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
    pub(crate) fn save_auto_lock(&mut self, policy: LockPolicy, ctx: &egui::Context) {
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
        let owner_input = ctx.input(|i| {
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
            })
        });
        let (idle, session) = self.auto_lock.source.take();
        let unlocked = !self.owner_ui.session.is_locked();
        if self.auto_lock.timer.due(
            self.auto_lock.policy,
            self.auto_lock.now(),
            idle,
            owner_input,
            unlocked,
            session,
        ) {
            self.lock_vault(Some(ctx));
            self.auto_lock.timer.unlocked = false;
        }
        if self.auto_lock.busy() || self.auto_lock.policy != LockPolicy::Never {
            ctx.request_repaint_after(Duration::from_millis(250));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        for seconds in 0..900 {
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
            Some(Duration::from_secs(900)),
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
