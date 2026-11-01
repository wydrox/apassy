//! Device-local identity window (ADR 0030). No secrets or reusable bearer tokens.
use std::sync::{Arc, Mutex};
use std::time::Duration;
#[cfg(not(target_os = "macos"))]
use std::time::Instant;

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

/// Injectable monotonic time; wall-clock changes cannot extend a window.
pub(crate) trait WindowClock: std::fmt::Debug + Send + Sync {
    fn now(&self) -> Duration;
}
#[cfg(not(target_os = "macos"))]
#[derive(Debug)]
struct Monotonic(Instant);
#[cfg(target_os = "macos")]
#[derive(Debug)]
struct Monotonic;
impl WindowClock for Monotonic {
    fn now(&self) -> Duration {
        #[cfg(target_os = "macos")]
        {
            // Darwin's std::time::Instant uses CLOCK_UPTIME_RAW, which pauses
            // during sleep. CLOCK_MONOTONIC advances during suspension, so an
            // overdue heartbeat fences reuse even before a queued sleep event.
            rustix::time::clock_gettime(rustix::time::ClockId::Monotonic)
                .try_into()
                .expect("nonnegative monotonic boot clock")
        }
        #[cfg(not(target_os = "macos"))]
        {
            self.0.elapsed()
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Verification {
    epoch: [u8; 32],
    at: Duration,
    #[cfg(any(feature = "desktop", test))]
    method: super::CheckMethod,
}
#[derive(Debug, Default)]
struct State {
    policy: OwnerFrequency,
    generation: u64,
    verified: Option<Verification>,
    healthy_at: Option<Duration>,
}
#[derive(Debug, Clone)]
pub(crate) struct OwnerWindow {
    state: Arc<Mutex<State>>,
    clock: Arc<dyn WindowClock>,
}
impl Default for OwnerWindow {
    fn default() -> Self {
        #[cfg(target_os = "macos")]
        let clock = Monotonic;
        #[cfg(not(target_os = "macos"))]
        let clock = Monotonic(Instant::now());
        Self::with_clock(Arc::new(clock))
    }
}
impl OwnerWindow {
    fn with_clock(clock: Arc<dyn WindowClock>) -> Self {
        Self {
            state: Arc::new(Mutex::new(State::default())),
            clock,
        }
    }
    #[cfg(any(feature = "desktop", test))]
    pub(crate) fn policy(&self) -> OwnerFrequency {
        self.state.lock().unwrap().policy
    }
    #[cfg(any(feature = "desktop", test))]
    pub(crate) fn configure(&self, policy: OwnerFrequency) {
        let mut s = self.state.lock().unwrap();
        s.generation = s
            .generation
            .checked_add(1)
            .expect("owner window generation exhausted");
        tracing::info!(generation = s.generation, "owner window generation changed");
        s.verified = None;
        s.policy = policy;
    }
    /// Lock, sleep, session switch, quit, failed/cancelled check, setting change,
    /// or observer loss all revoke issued proofs as well as the active window.
    pub(crate) fn invalidate(&self) {
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
    #[cfg(any(feature = "desktop", test))]
    pub(crate) fn observe(&self, active: bool) {
        let now = self.clock.now();
        let mut state = self.state.lock().unwrap();
        let gap = state
            .healthy_at
            .is_some_and(|at| now.saturating_sub(at) >= Duration::from_secs(2));
        // Revoke on loss/transition, not on every unavailable heartbeat: fresh
        // authentication must remain possible when reuse cannot be observed.
        // Explicit OS revocation events call invalidate independently.
        if (!active && state.healthy_at.is_some()) || gap {
            state.generation = state
                .generation
                .checked_add(1)
                .expect("owner window generation exhausted");
            tracing::info!(
                generation = state.generation,
                reason = if gap {
                    "heartbeat_gap"
                } else {
                    "session_inactive"
                },
                "owner window revoked"
            );
            state.verified = None;
        }
        state.healthy_at = active.then_some(now);
    }
    pub(crate) fn seed(&self, epoch: [u8; 32], method: super::CheckMethod, generation: u64) {
        let mut s = self.state.lock().unwrap();
        let reason = if s.generation != generation {
            "generation_changed"
        } else if !healthy(&s, self.clock.now()) {
            "observer_unhealthy"
        } else if !matches!(
            method,
            super::CheckMethod::TouchId | super::CheckMethod::Passphrase
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
                #[cfg(any(feature = "desktop", test))]
                method,
            });
        }
    }

    #[cfg(any(feature = "desktop", test))]
    pub(crate) fn ticket(&self, epoch: [u8; 32]) -> Option<(WindowProof, super::CheckMethod)> {
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
fn healthy(s: &State, now: Duration) -> bool {
    s.healthy_at
        .is_some_and(|at| now.saturating_sub(at) < Duration::from_secs(2))
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
    fn heartbeat_exact_boundary_and_recovery_fence_old_proofs() {
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
        assert!(!proof.valid());
        assert!(w.ticket([1; 32]).is_none());
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
            "setting change",
            "failed check",
            "cancelled check",
            "observer loss",
        ] {
            let (w, _) = fixture();
            w.configure(OwnerFrequency::UntilLock);
            w.seed(
                [1; 32],
                super::super::CheckMethod::Passphrase,
                w.generation(),
            );
            let (p, _) = w.ticket([1; 32]).unwrap();
            w.invalidate();
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
        assert!(w.ticket([1; 32]).is_none());
        w.observe(false);
        w.observe(true);
        assert!(w.ticket([1; 32]).is_none());
    }

    #[test]
    fn owner_session_suspension_revokes_before_the_next_heartbeat() {
        for policy in [OwnerFrequency::OneMinute, OwnerFrequency::UntilLock] {
            let (w, c) = fixture();
            w.configure(policy);
            w.seed([1; 32], super::super::CheckMethod::TouchId, w.generation());
            let (proof, _) = w.ticket([1; 32]).unwrap();
            c.0.store(3600, Ordering::SeqCst);
            assert!(!proof.valid());
            assert!(w.ticket([1; 32]).is_none());
            w.observe(true);
            assert!(!proof.valid());
            assert!(w.ticket([1; 32]).is_none());
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn owner_session_production_clock_uses_sleep_inclusive_macos_time() {
        let before: Duration = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic)
            .try_into()
            .unwrap();
        let now = OwnerWindow::default().clock.now();
        let after: Duration = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic)
            .try_into()
            .unwrap();
        assert!(before <= now && now <= after);
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
}
