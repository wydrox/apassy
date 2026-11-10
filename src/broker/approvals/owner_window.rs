//! Device-local identity window (ADR 0030). No secrets or reusable bearer tokens.
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// The six owner-approved choices. Unknown stored values fail closed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum OwnerFrequency {
    #[default]
    EveryTime,
    OneMinute,
    FiveMinutes,
    FifteenMinutes,
    OneHour,
    UntilLock,
}
impl OwnerFrequency {
    pub const ALL: [Self; 6] = [
        Self::EveryTime,
        Self::OneMinute,
        Self::FiveMinutes,
        Self::FifteenMinutes,
        Self::OneHour,
        Self::UntilLock,
    ];
    pub fn label(self) -> &'static str {
        match self {
            Self::EveryTime => "Every time",
            Self::OneMinute => "1 minute",
            Self::FiveMinutes => "5 minutes",
            Self::FifteenMinutes => "15 minutes",
            Self::OneHour => "1 hour",
            Self::UntilLock if cfg!(target_os = "linux") => "Until the screen locks",
            Self::UntilLock => "Until the Mac locks",
        }
    }
    pub fn code(self) -> &'static str {
        match self {
            Self::EveryTime => "every_time",
            Self::OneMinute => "1m",
            Self::FiveMinutes => "5m",
            Self::FifteenMinutes => "15m",
            Self::OneHour => "1h",
            Self::UntilLock => "until_lock",
        }
    }
    pub fn parse(code: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.code() == code)
    }
    fn duration(self) -> Option<Duration> {
        match self {
            Self::EveryTime => Some(Duration::ZERO),
            Self::OneMinute => Some(Duration::from_secs(60)),
            Self::FiveMinutes => Some(Duration::from_secs(300)),
            Self::FifteenMinutes => Some(Duration::from_secs(900)),
            Self::OneHour => Some(Duration::from_secs(3600)),
            Self::UntilLock => None,
        }
    }
}

/// The clock of owner deadlines (this window and the idle measure of auto-lock):
/// monotonic, and it counts the time that the machine sleeps.
/// - Apple: `CLOCK_MONOTONIC`. Darwin's counts sleep; `Instant` there is
///   `CLOCK_UPTIME_RAW`, which pauses during sleep.
/// - Linux and Android: `CLOCK_BOOTTIME`. There `CLOCK_MONOTONIC`, and so `Instant`,
///   stops during suspend.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) const SLEEP_INCLUSIVE_CLOCK: rustix::time::ClockId = rustix::time::ClockId::Boottime;
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub(crate) const SLEEP_INCLUSIVE_CLOCK: rustix::time::ClockId = rustix::time::ClockId::Monotonic;

/// Now on [`SLEEP_INCLUSIVE_CLOCK`], from an unspecified start. `None` only if the
/// system gives a negative time.
pub(crate) fn sleep_inclusive_now() -> Option<Duration> {
    rustix::time::clock_gettime(SLEEP_INCLUSIVE_CLOCK)
        .try_into()
        .ok()
}

/// Injectable monotonic time; wall-clock changes cannot extend a window.
pub(crate) trait WindowClock: std::fmt::Debug + Send + Sync {
    fn now(&self) -> Duration;
}
/// The production clock: suspension counts, so a window ends during a sleep.
#[derive(Debug)]
struct SleepInclusive;
impl WindowClock for SleepInclusive {
    fn now(&self) -> Duration {
        sleep_inclusive_now().expect("nonnegative monotonic boot clock")
    }
}

#[derive(Debug, Clone, Copy)]
struct Verification {
    epoch: [u8; 32],
    at: Duration,
    lifecycle: Option<(u64, u64)>,
    #[cfg(any(feature = "desktop", test))]
    method: super::CheckMethod,
}
#[derive(Debug, Default)]
struct State {
    policy: OwnerFrequency,
    generation: u64,
    verified: Option<Verification>,
    healthy_at: Option<Duration>,
    lifecycle: Option<(u64, u64)>,
}
#[derive(Clone)]
pub(crate) struct LifecycleProbe(pub Arc<dyn Fn() -> bool + Send + Sync>);
impl std::fmt::Debug for LifecycleProbe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LifecycleProbe")
    }
}
#[derive(Debug, Clone)]
pub(crate) struct OwnerWindow {
    state: Arc<Mutex<State>>,
    clock: Arc<dyn WindowClock>,
    probe: Arc<Mutex<Option<LifecycleProbe>>>,
}
impl Default for OwnerWindow {
    fn default() -> Self {
        Self::with_clock(Arc::new(SleepInclusive))
    }
}
impl OwnerWindow {
    #[cfg(any(feature = "desktop", test))]
    pub(crate) fn set_probe(&self, probe: LifecycleProbe) {
        self.invalidate_for("helper_started");
        *self.probe.lock().unwrap() = Some(probe);
    }
    #[cfg(feature = "desktop")]
    pub(crate) fn clear_probe(&self) {
        self.invalidate_for("helper_stopped");
        *self.probe.lock().unwrap() = None;
        self.observe(false);
    }
    fn refresh(&self) -> bool {
        let probe = self.probe.lock().unwrap().clone();
        if probe.is_some_and(|p| !(p.0)()) {
            self.observe(false);
            return false;
        }
        true
    }
    #[cfg(any(feature = "desktop", test))]
    pub(crate) fn snapshot(&self, identity: u64, counter: u64, active: bool) {
        {
            let mut s = self.state.lock().unwrap();
            if s.lifecycle.is_some_and(|old| old != (identity, counter)) {
                s.generation = s.generation.checked_add(1).expect("generation exhausted");
                s.verified = None;
            }
            s.lifecycle = Some((identity, counter));
        }
        self.observe(active);
    }
    fn with_clock(clock: Arc<dyn WindowClock>) -> Self {
        Self {
            state: Arc::new(Mutex::new(State::default())),
            clock,
            probe: Default::default(),
        }
    }
    #[cfg(any(feature = "desktop", test))]
    pub(crate) fn policy(&self) -> OwnerFrequency {
        self.state.lock().unwrap().policy
    }
    #[cfg(any(feature = "desktop", test))]
    pub(crate) fn configure(&self, policy: OwnerFrequency) {
        let mut s = self.state.lock().unwrap();
        // A later setting write must not resurrect an already expired window.
        if s.policy != OwnerFrequency::EveryTime
            && s.verified.is_some_and(|v| {
                s.policy
                    .duration()
                    .is_some_and(|d| self.clock.now().saturating_sub(v.at) >= d)
            })
        {
            s.verified = None;
        }
        s.policy = policy;
    }
    /// Lock, sleep, session switch, quit or observer loss revoke issued proofs
    /// as well as the active window.
    #[cfg(any(feature = "desktop", test))]
    pub(crate) fn invalidate(&self) {
        self.invalidate_for("explicit_invalidation");
    }
    #[cfg(any(feature = "desktop", test))]
    pub(crate) fn invalidate_for(&self, event: &'static str) {
        tracing::info!(event, "owner window revoked");
        let mut s = self.state.lock().unwrap();
        s.generation = s
            .generation
            .checked_add(1)
            .expect("owner window generation exhausted");
        tracing::info!(generation = s.generation, "owner window generation changed");
        s.verified = None;
    }
    /// Start unlock atomically against a native check's original lifecycle fence.
    #[cfg(any(feature = "desktop", test))]
    pub(crate) fn begin_unlock(&self, expected: Option<u64>) -> Option<u64> {
        let mut s = self.state.lock().unwrap();
        let valid = expected.is_none_or(|g| g == s.generation);
        s.generation = s
            .generation
            .checked_add(1)
            .expect("owner window generation exhausted");
        tracing::info!(generation = s.generation, "owner window generation changed");
        s.verified = None;
        valid.then_some(s.generation)
    }

    pub(crate) fn generation(&self) -> u64 {
        self.state.lock().unwrap().generation
    }
    pub(crate) fn observe(&self, active: bool) {
        let now = self.clock.now();
        let mut state = self.state.lock().unwrap();
        // Revoke on loss/transition, not on every unavailable heartbeat: fresh
        // authentication must remain possible when reuse cannot be observed.
        // Explicit OS revocation events call invalidate independently.
        if !active && state.healthy_at.is_some() {
            state.generation = state
                .generation
                .checked_add(1)
                .expect("owner window generation exhausted");
            tracing::info!(
                generation = state.generation,
                reason = "session_inactive",
                "owner window revoked"
            );
            state.verified = None;
        }
        state.healthy_at = active.then_some(now);
    }
    pub(crate) fn seed(&self, epoch: [u8; 32], method: super::CheckMethod, generation: u64) {
        if !self.refresh() {
            return;
        }
        let mut s = self.state.lock().unwrap();
        let reason = if s.generation != generation {
            "generation_changed"
        } else if !healthy(&s, self.clock.now()) {
            "observer_unhealthy"
        } else if !matches!(
            method,
            // Polkit auth_self is Linux's local owner check (never cached by polkit).
            super::CheckMethod::TouchId
                | super::CheckMethod::Passphrase
                | super::CheckMethod::Polkit
        ) {
            "nonlocal_check"
        } else {
            "seeded"
        };
        tracing::info!(reason, generation = s.generation, "owner window seed");
        if reason == "seeded" {
            s.verified = Some(Verification {
                epoch,
                at: self.clock.now(),
                lifecycle: s.lifecycle,
                #[cfg(any(feature = "desktop", test))]
                method,
            });
        }
    }

    #[cfg(feature = "desktop")]
    pub(crate) fn heartbeat_age_ms(&self) -> Option<u64> {
        let s = self.state.lock().unwrap();
        s.healthy_at
            .map(|at| self.clock.now().saturating_sub(at).as_millis() as u64)
    }

    #[cfg(any(feature = "desktop", test))]
    pub(crate) fn ticket(&self, epoch: [u8; 32]) -> Option<(WindowProof, super::CheckMethod)> {
        if !self.refresh() {
            return None;
        }
        let s = self.state.lock().unwrap();
        let now = self.clock.now();
        let age_ms = s
            .healthy_at
            .map(|at| now.saturating_sub(at).as_millis() as u64);
        let reason = match s.verified {
            None => "no_verification",
            Some(v) if v.epoch != epoch => "vault_epoch",
            _ if s.policy == OwnerFrequency::EveryTime => "every_time",
            _ if !healthy(&s, now) => "observer_unhealthy",
            Some(v)
                if s.policy
                    .duration()
                    .is_some_and(|d| now.saturating_sub(v.at) >= d) =>
            {
                "expired"
            }
            _ => "granted",
        };
        tracing::info!(reason, heartbeat_age_ms = age_ms, "owner window reuse");
        let v = s.verified?;
        if v.epoch != epoch
            || s.policy == OwnerFrequency::EveryTime
            || !healthy(&s, now)
            || s.policy
                .duration()
                .is_some_and(|d| now.saturating_sub(v.at) >= d)
        {
            return None;
        }
        Some((
            WindowProof {
                window: self.clone(),
                generation: s.generation,
                epoch,
                verified_at: v.at,
            },
            v.method,
        ))
    }
}
fn healthy(s: &State, _now: Duration) -> bool {
    s.healthy_at.is_some() && s.verified.is_none_or(|v| v.lifecycle == s.lifecycle)
}
/// A fresh one-action proof retains this fence; reuse never updates `verified_at`.
#[derive(Debug, Clone)]
pub(crate) struct WindowProof {
    window: OwnerWindow,
    generation: u64,
    epoch: [u8; 32],
    verified_at: Duration,
}
impl WindowProof {
    pub(crate) fn valid(&self) -> bool {
        if !self.window.refresh() {
            return false;
        }
        let s = self.window.state.lock().unwrap();
        let now = self.window.clock.now();
        s.generation == self.generation
            && healthy(&s, now)
            && s.verified
                .is_some_and(|v| v.epoch == self.epoch && v.at == self.verified_at)
            && s.policy != OwnerFrequency::EveryTime
            && s.policy
                .duration()
                .is_none_or(|d| now.saturating_sub(self.verified_at) < d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    #[derive(Debug, Default)]
    struct Clock(AtomicU64);
    impl WindowClock for Clock {
        fn now(&self) -> Duration {
            Duration::from_secs(self.0.load(Ordering::SeqCst))
        }
    }
    fn fixture() -> (OwnerWindow, Arc<Clock>) {
        let c = Arc::new(Clock::default());
        let w = OwnerWindow::with_clock(c.clone());
        w.observe(true);
        (w, c)
    }
    #[test]
    fn synchronous_probe_timeout_counter_restart_and_inactive_fail_closed() {
        for cause in 0..4 {
            let (w, _) = fixture();
            w.configure(OwnerFrequency::UntilLock);
            w.snapshot(1, 0, true);
            w.seed([1; 32], super::super::CheckMethod::TouchId, w.generation());
            let (proof, _) = w.ticket([1; 32]).unwrap();
            match cause {
                0 => {
                    *w.probe.lock().unwrap() = Some(LifecycleProbe(Arc::new(|| false)));
                }
                1 => w.snapshot(1, 1, true),
                2 => w.snapshot(2, 0, true),
                _ => w.snapshot(1, 0, false),
            }
            assert!(!proof.valid());
            assert!(w.ticket([1; 32]).is_none());
            w.observe(true);
            assert!(w.ticket([1; 32]).is_none());
        }
    }
    #[test]
    fn unlock_seeds_both_local_methods_and_setting_preserves_absolute_start() {
        for method in [
            super::super::CheckMethod::TouchId,
            super::super::CheckMethod::Passphrase,
            super::super::CheckMethod::Polkit,
        ] {
            let (w, c) = fixture();
            w.configure(OwnerFrequency::OneMinute);
            let generation = w.begin_unlock(None).unwrap();
            w.seed([1; 32], method, generation);
            assert!(w.ticket([1; 32]).is_some());
            c.0.store(30, Ordering::SeqCst);
            w.configure(OwnerFrequency::FiveMinutes);
            assert!(w.ticket([1; 32]).is_some());
            c.0.store(300, Ordering::SeqCst);
            assert!(w.ticket([1; 32]).is_none());
        }
    }
    #[test]
    fn heartbeat_gaps_do_not_revoke() {
        #[derive(Debug, Default)]
        struct Millis(AtomicU64);
        impl WindowClock for Millis {
            fn now(&self) -> Duration {
                Duration::from_millis(self.0.load(Ordering::SeqCst))
            }
        }
        let clock = Arc::new(Millis::default());
        let w = OwnerWindow::with_clock(clock.clone());
        w.configure(OwnerFrequency::UntilLock);
        w.observe(true);
        w.seed([1; 32], super::super::CheckMethod::TouchId, w.generation());
        let (proof, _) = w.ticket([1; 32]).unwrap();
        clock.0.store(1999, Ordering::SeqCst);
        assert!(proof.valid());
        assert!(w.ticket([1; 32]).is_some());
        clock.0.store(2000, Ordering::SeqCst);
        assert!(proof.valid());
        assert!(w.ticket([1; 32]).is_some());
        w.observe(true);
        w.seed([1; 32], super::super::CheckMethod::TouchId, w.generation());
        assert!(w.ticket([1; 32]).is_some());
        assert!(!proof.valid());
    }
    #[test]
    fn owner_session_default_is_every_time() {
        let (w, _) = fixture();
        w.seed([1; 32], super::super::CheckMethod::TouchId, w.generation());
        assert!(w.ticket([1; 32]).is_none());
    }
    #[test]
    fn owner_session_absolute_deadline_does_not_slide() {
        let (w, c) = fixture();
        w.configure(OwnerFrequency::OneMinute);
        w.seed([1; 32], super::super::CheckMethod::TouchId, w.generation());
        for time in 1..=59 {
            c.0.store(time, Ordering::SeqCst);
            w.observe(true);
        }
        let (p, _) = w.ticket([1; 32]).unwrap();
        c.0.store(60, Ordering::SeqCst);
        w.observe(true);
        assert!(w.ticket([1; 32]).is_none());
        assert!(!p.valid());
    }
    #[test]
    fn owner_session_each_invalidation_fences_issued_proof() {
        for event in [
            "screen lock",
            "sleep",
            "session switch",
            "quit",
            "vault lock",
            "helper exited",
            "helper restarted",
            "auto-lock",
        ] {
            let (w, _) = fixture();
            w.configure(OwnerFrequency::UntilLock);
            w.seed(
                [1; 32],
                super::super::CheckMethod::Passphrase,
                w.generation(),
            );
            let (p, _) = w.ticket([1; 32]).unwrap();
            w.invalidate_for(event);
            assert!(!p.valid(), "{event}");
            assert!(w.ticket([1; 32]).is_none(), "{event}");
        }
    }
    #[test]
    fn owner_session_late_auth_result_cannot_reopen() {
        let (w, _) = fixture();
        w.configure(OwnerFrequency::OneHour);
        let generation = w.generation();
        w.invalidate();
        w.seed([1; 32], super::super::CheckMethod::TouchId, generation);
        assert!(w.ticket([1; 32]).is_none());
    }
    #[test]
    fn owner_session_remote_does_not_seed_and_wrong_vault_refused() {
        let (w, _) = fixture();
        w.configure(OwnerFrequency::FiveMinutes);
        w.seed([1; 32], super::super::CheckMethod::Remote, w.generation());
        assert!(w.ticket([1; 32]).is_none());
        w.seed(
            [1; 32],
            super::super::CheckMethod::Passphrase,
            w.generation(),
        );
        assert!(w.ticket([2; 32]).is_none());
    }
    #[test]
    fn owner_session_observer_loss_fails_closed() {
        let (w, c) = fixture();
        w.configure(OwnerFrequency::UntilLock);
        w.seed([1; 32], super::super::CheckMethod::TouchId, w.generation());
        c.0.store(2, Ordering::SeqCst);
        assert!(w.ticket([1; 32]).is_some());
        w.observe(false);
        w.observe(true);
        assert!(w.ticket([1; 32]).is_none());
    }

    #[test]
    fn owner_session_scheduling_gap_only_expires_timed_windows() {
        for policy in [OwnerFrequency::OneMinute, OwnerFrequency::UntilLock] {
            let (w, c) = fixture();
            w.configure(policy);
            w.seed([1; 32], super::super::CheckMethod::TouchId, w.generation());
            let (proof, _) = w.ticket([1; 32]).unwrap();
            c.0.store(3600, Ordering::SeqCst);
            assert_eq!(proof.valid(), policy == OwnerFrequency::UntilLock);
            assert_eq!(
                w.ticket([1; 32]).is_some(),
                policy == OwnerFrequency::UntilLock
            );
            w.observe(true);
            assert_eq!(proof.valid(), policy == OwnerFrequency::UntilLock);
            assert_eq!(
                w.ticket([1; 32]).is_some(),
                policy == OwnerFrequency::UntilLock
            );
        }
    }

    /// A suspend is a jump of the clock with no heartbeat in between. It ends a timed
    /// window; on Linux the production clock (`CLOCK_BOOTTIME`) makes that jump.
    #[test]
    fn owner_session_suspend_gap_ends_a_timed_window() {
        let (w, c) = fixture();
        w.configure(OwnerFrequency::FiveMinutes);
        w.seed([1; 32], super::super::CheckMethod::TouchId, w.generation());
        c.0.store(60, Ordering::SeqCst);
        w.observe(true);
        let (proof, _) = w.ticket([1; 32]).unwrap();
        assert!(proof.valid());
        // Two hours of suspend: no observe call, no heartbeat.
        c.0.store(60 + 7200, Ordering::SeqCst);
        assert!(!proof.valid());
        assert!(w.ticket([1; 32]).is_none());
        // Input after the wake does not reopen it.
        w.observe(true);
        assert!(!proof.valid());
        assert!(w.ticket([1; 32]).is_none());
    }

    /// The production clock counts suspension: `CLOCK_BOOTTIME` on Linux, Darwin's
    /// `CLOCK_MONOTONIC` on macOS (unchanged).
    #[test]
    fn owner_session_production_clock_counts_suspended_time() {
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
        let now = OwnerWindow::default().clock.now();
        let after = read();
        assert!(before <= now && now <= after);
    }
    /// On Linux the window's clock and `CLOCK_MONOTONIC` differ by exactly the time
    /// suspended since boot: the window's clock is never behind the one that stops.
    #[cfg(target_os = "linux")]
    #[test]
    fn owner_session_linux_clock_is_not_behind_the_suspend_paused_clock() {
        let monotonic: Duration = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic)
            .try_into()
            .unwrap();
        let boottime = OwnerWindow::default().clock.now();
        assert!(boottime >= monotonic);
    }
    #[cfg(feature = "desktop")]
    #[test]
    fn cli_code_never_reuses_a_window_and_fresh_proofs_are_exact() {
        use super::super::{LocalWindowSource, OwnerAction, OwnerCheck, OwnerGate, ProofRefusal};
        let dir = tempfile::tempdir().unwrap();
        let mut vault =
            crate::vault::Vault::create(&dir.path().join("synthetic.db"), "synthetic-window-pass")
                .unwrap();
        vault.unlock("synthetic-window-pass").unwrap();
        let epoch = vault.epoch();
        let shared = Arc::new(Mutex::new(Some(vault)));
        let (w, clock) = fixture();
        w.configure(OwnerFrequency::OneMinute);
        w.seed(epoch, super::super::CheckMethod::Passphrase, w.generation());
        let gate = OwnerGate::new(shared, None).with_window(w.clone());
        let action = OwnerAction::CliCode {
            item_id: 7,
            field: "x_OTP".into(),
            copy: false,
        };
        for source in [
            LocalWindowSource::BrowserGesture,
            LocalWindowSource::AutoFill,
            LocalWindowSource::AllowOnceClick,
        ] {
            assert!(gate.reuse_local(action.clone(), source).is_none());
        }
        let proof = gate
            .authorize(
                action.clone(),
                OwnerCheck::passphrase("synthetic-window-pass"),
            )
            .unwrap();
        assert_eq!(proof.check(&action, &epoch), Ok(()));
        for other in [
            OwnerAction::CliCode {
                item_id: 8,
                field: "x_OTP".into(),
                copy: false,
            },
            OwnerAction::CliCode {
                item_id: 7,
                field: "other".into(),
                copy: false,
            },
            OwnerAction::CliCode {
                item_id: 7,
                field: "x_OTP".into(),
                copy: true,
            },
        ] {
            assert_eq!(proof.check(&other, &epoch), Err(ProofRefusal::WrongAction));
        }
        assert!(
            gate.reuse_local(
                OwnerAction::ShowCode {
                    item_id: 7,
                    field: "x_OTP".into()
                },
                LocalWindowSource::BrowserGesture
            )
            .is_none()
        );
        assert!(
            gate.reuse_local(
                OwnerAction::CopyCode {
                    item_id: 7,
                    field: "x_OTP".into()
                },
                LocalWindowSource::AutoFill
            )
            .is_none()
        );
        for time in 1..=60 {
            clock.0.store(time, Ordering::SeqCst);
            w.observe(true);
        }
        w.invalidate();
        assert!(!proof.is_fresh());
    }

    #[cfg(feature = "desktop")]
    #[test]
    fn the_owner_window_never_covers_a_hosting_change() {
        use super::super::{LocalWindowSource, OwnerAction, OwnerCheck, OwnerGate};
        use crate::vault::{BouncerHostKind, HOSTING_CONSENT_VERSION};
        const PASS: &str = "synthetic-window-host-pass";
        let dir = tempfile::tempdir().unwrap();
        let mut vault =
            crate::vault::Vault::create(&dir.path().join("synthetic.db"), PASS).unwrap();
        vault.unlock(PASS).unwrap();
        let epoch = vault.epoch();
        let shared = Arc::new(Mutex::new(Some(vault)));
        let (w, _) = fixture();
        w.configure(OwnerFrequency::UntilLock);
        w.seed(epoch, super::super::CheckMethod::TouchId, w.generation());
        let gate = OwnerGate::new(shared, None).with_window(w.clone());
        // The window is open: it covers another action of the local owner.
        assert!(
            gate.reuse_local(
                OwnerAction::ChangeCalibration { level: 80 },
                LocalWindowSource::LocalOwner
            )
            .is_some()
        );
        let sources = [
            LocalWindowSource::LocalOwner,
            LocalWindowSource::BrowserDebuggingClick,
            LocalWindowSource::BrowserGesture,
            LocalWindowSource::AutoFill,
            LocalWindowSource::AllowOnceClick,
            LocalWindowSource::DevelopmentClick,
        ];
        for kind in BouncerHostKind::ALL {
            let (url, consent_version) = match kind {
                BouncerHostKind::ThisMac => (String::new(), 0),
                _ => (
                    "https://brain.synthetic.ts.net".to_owned(),
                    HOSTING_CONSENT_VERSION,
                ),
            };
            for action in [
                OwnerAction::ChangeBouncerHosting {
                    kind,
                    url: url.clone(),
                    consent_version,
                },
                OwnerAction::ChangeBouncerTraining {
                    kind,
                    url: url.clone(),
                    consent_version,
                },
            ] {
                assert!(action.needs_fresh_local_check(), "{action:?}");
                for source in sources {
                    assert!(
                        gate.reuse_local(action.clone(), source).is_none(),
                        "{action:?}: the window covered a hosting change"
                    );
                }
                // A fresh check gives a proof for exactly this change.
                let proof = gate
                    .authorize(action.clone(), OwnerCheck::passphrase(PASS))
                    .unwrap();
                assert_eq!(proof.check(&action, &epoch), Ok(()));
                // The fresh check also seeds the window, which still does not cover the
                // next change.
                assert!(
                    gate.reuse_local(action.clone(), LocalWindowSource::LocalOwner)
                        .is_none()
                );
            }
        }
    }

    /// Review 0.5.16: an open window covers a token rotation of the local owner, but
    /// never a new remote agent, whose bearer token works from the internet.
    #[cfg(feature = "desktop")]
    #[test]
    fn an_open_window_never_covers_a_new_remote_agent() {
        use super::super::{LocalWindowSource, OwnerAction, OwnerCheck, OwnerGate};
        let dir = tempfile::tempdir().unwrap();
        let mut vault =
            crate::vault::Vault::create(&dir.path().join("synthetic.db"), "synthetic-window-pass")
                .unwrap();
        vault.unlock("synthetic-window-pass").unwrap();
        let epoch = vault.epoch();
        let shared = Arc::new(Mutex::new(Some(vault)));
        let (w, _clock) = fixture();
        w.configure(OwnerFrequency::UntilLock);
        w.seed(epoch, super::super::CheckMethod::TouchId, w.generation());
        let gate = OwnerGate::new(shared, None).with_window(w.clone());
        let rotate = OwnerAction::RotateToken { agent_id: 3 };
        assert!(!rotate.needs_fresh_local_check());
        assert!(
            gate.reuse_local(rotate, LocalWindowSource::LocalOwner)
                .is_some(),
            "the window is open"
        );
        let remote = OwnerAction::AddRemoteAgent {
            name: "Grok Bot".into(),
            days: 90,
        };
        assert!(remote.needs_fresh_local_check());
        assert!(
            gate.reuse_local(remote.clone(), LocalWindowSource::LocalOwner)
                .is_none()
        );
        // A fresh check still gives its exact proof.
        let proof = gate
            .authorize(
                remote.clone(),
                OwnerCheck::passphrase("synthetic-window-pass"),
            )
            .unwrap();
        assert_eq!(proof.check(&remote, &epoch), Ok(()));
    }
}
