//! Owned helper stream. EOF, malformed data, sequence gaps and inactive sessions
//! revoke; scheduling gaps alone do not. Every reuse probes this same process.
use super::{NativeError, NativeHelper};
use crate::broker::approvals::owner_window::OwnerWindow;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc,
};
use std::time::{Duration, Instant};

type Pending = Arc<Mutex<ProbeState>>;
static NEXT_HELPER: AtomicU64 = AtomicU64::new(1);

#[derive(Default)]
struct ProbeState {
    request: Option<(u64, mpsc::Sender<()>)>,
    unhealthy: bool,
    backoff: Backoff,
}

#[derive(Default)]
struct Backoff {
    failures: usize,
    retry_at: Option<Instant>,
}
impl Backoff {
    fn ready(&self, now: Instant) -> bool {
        self.retry_at.is_none_or(|at| now >= at)
    }
    fn fail(&mut self, now: Instant) -> Duration {
        let delay = Duration::from_secs(match self.failures {
            0 => 1,
            1 => 2,
            _ => 5,
        });
        self.failures = self.failures.saturating_add(1);
        self.retry_at = Some(now + delay);
        delay
    }
}
impl ProbeState {
    fn can_probe(&self, now: Instant) -> bool {
        self.request.is_none() && self.backoff.ready(now)
    }
    fn fail(&mut self, window: &OwnerWindow, event: &'static str) {
        self.unhealthy = true;
        self.backoff.fail(Instant::now());
        window.invalidate_for(event);
        window.observe(false);
        tracing::info!(event, "owner lifecycle unhealthy");
    }
    fn reply(&mut self, id: u64) {
        if self
            .request
            .as_ref()
            .is_some_and(|(expected, _)| *expected == id)
            && let Some((_, tx)) = self.request.take()
        {
            // Even a late reply drains the outstanding request, but it cannot
            // satisfy any subsequent probe or restore a revoked verification.
            if self.unhealthy {
                tracing::info!(event = "recovered", "owner lifecycle responsive");
                self.unhealthy = false;
            }
            let _ = tx.send(());
        }
    }
}

pub(crate) struct OwnerLifecycle {
    child: Arc<Mutex<Child>>,
    reader: Option<std::thread::JoinHandle<()>>,
    window: OwnerWindow,
    stopped: Arc<AtomicBool>,
    wake: mpsc::Sender<()>,
}
impl OwnerLifecycle {
    pub(crate) fn start(
        helper: &NativeHelper,
        window: OwnerWindow,
        source: crate::desktop::auto_lock::IdleSource,
        ctx: eframe::egui::Context,
    ) -> Result<Self, NativeError> {
        window.observe(false);
        let mut child = Command::new(helper.helper_path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| NativeError::Io(e.to_string()))?;
        let setup = (|| {
            child
                .stdin
                .as_mut()
                .ok_or_else(|| NativeError::Io("lifecycle stdin missing".into()))?
                .write_all(b"{\"cmd\":\"owner_lifecycle\"}\n")
                .map_err(|e| NativeError::Io(e.to_string()))?;
            child
                .stdout
                .take()
                .ok_or_else(|| NativeError::Io("lifecycle stdout missing".into()))
        })();
        let stdout = match setup {
            Ok(o) => o,
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(e);
            }
        };
        let shared = Arc::new(Mutex::new(child));
        let identity = NEXT_HELPER.fetch_add(1, Ordering::Relaxed);
        let pending: Pending = Default::default();
        let replies = pending.clone();
        let sender = shared.clone();
        let serial = Mutex::new(0u64);
        let probe_window = window.clone();
        window.set_probe(crate::broker::approvals::owner_window::LifecycleProbe(
            Arc::new(move || {
                // Serialize requests so a late reply can never satisfy a later probe.
                let mut id = serial.lock().unwrap();
                {
                    let state = pending.lock().unwrap();
                    if !state.can_probe(Instant::now()) {
                        return false;
                    }
                }
                *id = id.checked_add(1).expect("lifecycle request exhausted");
                let (tx, rx) = mpsc::channel();
                pending.lock().unwrap().request = Some((*id, tx));
                let sent = sender
                    .lock()
                    .unwrap()
                    .stdin
                    .as_mut()
                    .is_some_and(|stdin| writeln!(stdin, "{{\"probe\":{}}}", *id).is_ok());
                let ok = sent && rx.recv_timeout(Duration::from_millis(500)).is_ok();
                // Keep one timed-out request outstanding until its exact reply
                // arrives or the stream is replaced. Never queue more pipe data.
                if !ok {
                    let mut state = pending.lock().unwrap();
                    state.fail(
                        &probe_window,
                        if sent { "timeout" } else { "stream_broken" },
                    );
                    if !sent {
                        state.request = None;
                        drop(state);
                        // A broken input pipe need not close stdout by itself.
                        // Termination wakes the reader and its restart loop.
                        let _ = sender.lock().unwrap().kill();
                    }
                } else {
                    pending.lock().unwrap().backoff = Backoff::default();
                }
                ok
            }),
        ));
        let observed = window.clone();
        let stopped = Arc::new(AtomicBool::new(false));
        let stopping = stopped.clone();
        let restart_child = shared.clone();
        let path = helper.helper_path().to_path_buf();
        let (wake, stop_wait) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut stdout = stdout;
            let mut identity = identity;
            let mut restarts = Backoff::default();
            loop {
                let mut input = BufReader::new(stdout);
                let mut sequence = 0u64;
                let mut last_counter = 0u64;
                loop {
                    let mut bytes = Vec::new();
                    if Read::by_ref(&mut input)
                        .take(4097)
                        .read_until(b'\n', &mut bytes)
                        .ok()
                        .filter(|n| *n > 0 && *n <= 4096)
                        .is_none()
                    {
                        break;
                    }
                    if !apply_event(&bytes, &mut sequence, &observed) {
                        break;
                    }
                    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                        let Some(counter) = v["lock_counter"].as_u64() else {
                            break;
                        };
                        if counter < last_counter {
                            break;
                        }
                        last_counter = counter;
                        let Some(locked) = v["screen_locked"].as_bool() else {
                            break;
                        };
                        observed.snapshot(
                            identity,
                            counter,
                            v["active"].as_bool() == Some(true) && !locked,
                        );
                        if let Some(id) = v["probe"].as_u64() {
                            let mut pending = replies.lock().unwrap();
                            pending.reply(id);
                            // Reset restart backoff only after a synchronous reply,
                            // not after spawning a repeatedly failing process.
                            restarts = Backoff::default();
                        }
                    }
                    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes)
                        && v.get("idle_seconds").is_some()
                        && source.record(
                            v["idle_seconds"].as_f64(),
                            v["revoke"].as_bool() == Some(true),
                        )
                    {
                        ctx.request_repaint();
                    }
                }
                {
                    let mut pending = replies.lock().unwrap();
                    pending.fail(&observed, "stream_broken");
                    pending.request = None;
                }
                {
                    let mut child = restart_child.lock().unwrap();
                    let _ = child.kill();
                    let _ = child.wait();
                }
                loop {
                    let delay = restarts.fail(Instant::now());
                    if stopping.load(Ordering::Relaxed) || stop_wait.recv_timeout(delay).is_ok() {
                        return;
                    }
                    tracing::info!(event = "restart", "restarting owner lifecycle helper");
                    let Ok(mut child) = Command::new(&path)
                        .stdin(Stdio::piped())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::null())
                        .spawn()
                    else {
                        continue;
                    };
                    let sent = child.stdin.as_mut().is_some_and(|stdin| {
                        stdin.write_all(b"{\"cmd\":\"owner_lifecycle\"}\n").is_ok()
                    });
                    if sent && let Some(output) = child.stdout.take() {
                        // Shutdown and replacement share this lock: Drop can never
                        // miss a newly spawned child and hang joining its reader.
                        let mut current = restart_child.lock().unwrap();
                        if !stopping.load(Ordering::Relaxed) {
                            *current = child;
                            replies.lock().unwrap().request = None;
                            stdout = output;
                            identity = NEXT_HELPER.fetch_add(1, Ordering::Relaxed);
                            break;
                        }
                    }
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        });
        Ok(Self {
            child: shared,
            reader: Some(reader),
            window,
            stopped,
            wake,
        })
    }
}
impl Drop for OwnerLifecycle {
    fn drop(&mut self) {
        self.window.observe(false);
        self.stopped.store(true, Ordering::Relaxed);
        let _ = self.wake.send(());
        let mut child = self.child.lock().unwrap();
        let _ = child.kill();
        let _ = child.wait();
        drop(child);
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        // Break the probe's ownership cycle only after all snapshots stop.
        self.window.clear_probe();
    }
}

fn apply_event(bytes: &[u8], sequence: &mut u64, observed: &OwnerWindow) -> bool {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        tracing::info!(event = "observer_failure", "owner window revoked");
        observed.observe(false);
        return false;
    };
    if v["ok"].as_bool() != Some(true)
        || v["sequence"].as_u64() != sequence.checked_add(1)
        || v["active"].as_bool().is_none()
        || v["revoke"].as_bool().is_none()
    {
        tracing::info!(event = "observer_failure", "owner window revoked");
        observed.observe(false);
        return false;
    }
    *sequence += 1;
    if v["revoke"].as_bool() == Some(true) {
        // Only known enum-like event kinds enter diagnostics; never log helper data.
        let event = match v["event"].as_str() {
            Some("screen_locked") => "screen_locked",
            Some("system_sleep") => "system_sleep",
            Some("session_resigned") => "session_resigned",
            _ => "lifecycle_revocation",
        };
        tracing::info!(event, "owner window revoked");
        observed.invalidate();
    }
    observed.observe(v["active"].as_bool() == Some(true));
    true
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::approvals::{CheckMethod, OwnerFrequency};
    #[test]
    fn timeout_recovery_requires_fresh_authentication_for_same_or_new_helper() {
        for identity in [1, 2] {
            let window = OwnerWindow::default();
            window.configure(OwnerFrequency::UntilLock);
            let state = Arc::new(Mutex::new(ProbeState::default()));
            let injected = state.clone();
            let clock = Arc::new(Mutex::new(Instant::now()));
            let probe_clock = clock.clone();
            window.set_probe(crate::broker::approvals::owner_window::LifecycleProbe(
                Arc::new(move || {
                    let state = injected.lock().unwrap();
                    !state.unhealthy && state.can_probe(*probe_clock.lock().unwrap())
                }),
            ));
            window.snapshot(1, 0, true);
            window.seed([1; 32], CheckMethod::TouchId, window.generation());
            let (old, _) = window.ticket([1; 32]).unwrap();
            let generation = window.generation();
            let (tx, rx) = mpsc::channel();
            {
                let mut state = state.lock().unwrap();
                state.request = Some((7, tx));
                state.fail(&window, "timeout");
            }
            assert!(window.generation() > generation);
            assert!(!old.valid());
            assert!(window.ticket([1; 32]).is_none());
            window.seed([1; 32], CheckMethod::TouchId, window.generation());
            assert!(window.ticket([1; 32]).is_none());
            // A nonmatching response cannot recover or complete the request.
            state.lock().unwrap().reply(6);
            assert!(rx.try_recv().is_err());
            assert!(state.lock().unwrap().unhealthy);
            if identity == 2 {
                let mut state = state.lock().unwrap();
                state.fail(&window, "stream_broken");
                state.request = None;
                let (tx, _) = mpsc::channel();
                state.request = Some((8, tx));
            }
            window.snapshot(identity, 0, true);
            state
                .lock()
                .unwrap()
                .reply(if identity == 1 { 7 } else { 8 });
            assert!(!state.lock().unwrap().unhealthy);
            // Late replies do not bypass the retry delay.
            assert!(!state.lock().unwrap().can_probe(*clock.lock().unwrap()));
            *clock.lock().unwrap() += Duration::from_secs(60);
            assert!(window.ticket([1; 32]).is_none());
            assert!(!old.valid());
            // Authentication that began before failure must not seed either.
            window.seed([1; 32], CheckMethod::TouchId, generation);
            assert!(window.ticket([1; 32]).is_none());
            window.seed([1; 32], CheckMethod::TouchId, window.generation());
            assert!(window.ticket([1; 32]).is_some());
            assert!(!old.valid());
        }
    }

    #[test]
    fn repeated_failures_back_off_and_never_queue_behind_a_timeout() {
        let now = Instant::now();
        let mut backoff = Backoff::default();
        for seconds in [1, 2, 5, 5, 5] {
            assert_eq!(backoff.fail(now), Duration::from_secs(seconds));
            assert!(!backoff.ready(now));
            assert!(!backoff.ready(now + Duration::from_secs(seconds) - Duration::from_nanos(1)));
            assert!(backoff.ready(now + Duration::from_secs(seconds)));
        }
        let window = OwnerWindow::default();
        let (tx, rx) = mpsc::channel();
        let mut state = ProbeState {
            request: Some((1, tx)),
            ..Default::default()
        };
        state.fail(&window, "timeout");
        // Backoff expiry alone cannot clear the outstanding request or count
        // a timeout as success. Only its own reply permits another request.
        assert!(
            state
                .backoff
                .ready(Instant::now() + Duration::from_secs(60))
        );
        assert!(state.request.is_some());
        assert!(!state.can_probe(Instant::now() + Duration::from_secs(60)));
        assert!(state.unhealthy);
        assert!(rx.try_recv().is_err());
        state.reply(1);
        assert!(state.request.is_none());
        assert!(!state.unhealthy);
    }
    #[test]
    fn owner_lifecycle_sequence_gap_and_malformed_events_revoke() {
        for bad in [
            br#"{"ok":true,"sequence":3,"active":true,"revoke":false}"#.as_slice(),
            b"malformed",
            br#"{"ok":true,"sequence":2}"#,
        ] {
            let window = OwnerWindow::default();
            window.configure(OwnerFrequency::UntilLock);
            let mut seq = 0;
            assert!(apply_event(
                br#"{"ok":true,"sequence":1,"active":true,"revoke":false}"#,
                &mut seq,
                &window
            ));
            window.seed([1; 32], CheckMethod::TouchId, window.generation());
            let (proof, _) = window.ticket([1; 32]).unwrap();
            assert!(!apply_event(bad, &mut seq, &window));
            assert!(!proof.valid());
        }
    }
    #[test]
    fn owner_lifecycle_revocation_then_unlock_never_restores() {
        let window = OwnerWindow::default();
        window.configure(OwnerFrequency::UntilLock);
        let mut seq = 0;
        assert!(apply_event(
            br#"{"ok":true,"sequence":1,"active":true,"revoke":false}"#,
            &mut seq,
            &window
        ));
        window.seed([1; 32], CheckMethod::TouchId, window.generation());
        assert!(apply_event(
            br#"{"ok":true,"sequence":2,"active":true,"revoke":true}"#,
            &mut seq,
            &window
        ));
        assert!(apply_event(
            br#"{"ok":true,"sequence":3,"active":true,"revoke":false}"#,
            &mut seq,
            &window
        ));
        assert!(window.ticket([1; 32]).is_none());
    }
}

#[cfg(test)]
mod display_sleep_tests {
    use super::*;
    use crate::broker::approvals::{CheckMethod, OwnerFrequency};
    #[test]
    fn display_sleep_preserves_but_lock_snapshot_and_events_revoke() {
        for policy in OwnerFrequency::ALL {
            if policy == OwnerFrequency::EveryTime {
                continue;
            }
            for (event, active, revoke) in [
                ("screen_locked", true, true),
                ("system_sleep", true, true),
                ("session_resigned", true, true),
                ("heartbeat", false, false), // IOConsoleLocked while display stays asleep
            ] {
                let w = OwnerWindow::default();
                w.configure(policy);
                w.observe(true);
                w.seed([1; 32], CheckMethod::TouchId, w.generation());
                let (proof, _) = w.ticket([1; 32]).unwrap();
                let mut seq = 0;
                assert!(apply_event(br#"{"ok":true,"sequence":1,"active":true,"revoke":false,"event":"display_sleep"}"#, &mut seq, &w));
                assert!(proof.valid());
                let bytes = serde_json::to_vec(&serde_json::json!({"ok": true, "sequence": 2, "active": active, "revoke": revoke, "event": event})).unwrap();
                assert!(apply_event(&bytes, &mut seq, &w));
                assert!(!proof.valid());
                w.observe(true);
                assert!(w.ticket([1; 32]).is_none());
            }
        }
    }
}
