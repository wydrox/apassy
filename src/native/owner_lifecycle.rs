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
use std::time::Duration;

type Pending = Arc<Mutex<Option<(u64, mpsc::Sender<()>)>>>;
static NEXT_HELPER: AtomicU64 = AtomicU64::new(1);

pub(crate) struct OwnerLifecycle {
    child: Arc<Mutex<Child>>,
    reader: Option<std::thread::JoinHandle<()>>,
    window: OwnerWindow,
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
        let failed = AtomicBool::new(false);
        window.set_probe(crate::broker::approvals::owner_window::LifecycleProbe(
            Arc::new(move || {
                // Serialize requests so a late reply can never satisfy a later probe.
                let mut id = serial.lock().unwrap();
                if failed.load(Ordering::Relaxed) {
                    return false;
                }
                *id = id.checked_add(1).expect("lifecycle request exhausted");
                let (tx, rx) = mpsc::channel();
                *pending.lock().unwrap() = Some((*id, tx));
                let sent = sender
                    .lock()
                    .unwrap()
                    .stdin
                    .as_mut()
                    .is_some_and(|stdin| writeln!(stdin, "{{\"probe\":{}}}", *id).is_ok());
                let ok = sent && rx.recv_timeout(Duration::from_millis(500)).is_ok();
                // Stop sending after failure: a suspended helper must never fill its
                // stdin pipe and turn the next write into an unbounded wait.
                if !ok {
                    failed.store(true, Ordering::Relaxed);
                }
                *pending.lock().unwrap() = None;
                ok
            }),
        ));
        let observed = window.clone();
        let reader = std::thread::spawn(move || {
            let mut input = BufReader::new(stdout);
            let mut sequence = 0u64;
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
                        if pending
                            .as_ref()
                            .is_some_and(|(expected, _)| *expected == id)
                            && let Some((_, tx)) = pending.take()
                        {
                            let _ = tx.send(());
                        }
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
            observed.observe(false);
        });
        Ok(Self {
            child: shared,
            reader: Some(reader),
            window,
        })
    }
}
impl Drop for OwnerLifecycle {
    fn drop(&mut self) {
        self.window.observe(false);
        let mut child = self.child.lock().unwrap();
        let _ = child.kill();
        let _ = child.wait();
        drop(child);
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
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
