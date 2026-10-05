//! Bound cloud directory flushes and read-only File Provider operations.
//!
//! On macOS, even `open()` of an iCloud directory can wait indefinitely. The
//! worker holds only the path, so a timeout releases the caller's vault lock.
//! A timeout is a failure, never evidence that the rename is durable. Local
//! state files still use the ordinary synchronous directory flush.

use std::path::Path;
use std::sync::{Mutex, OnceLock, PoisonError, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::SyncError;

const TIMEOUT: Duration = Duration::from_secs(2);
const SLOT_POLL: Duration = Duration::from_millis(2);

pub(super) fn sync(path: &Path) -> Result<(), SyncError> {
    static WORKER: OnceLock<DirectorySync> = OnceLock::new();
    let path = path.to_owned();
    WORKER
        .get_or_init(DirectorySync::default)
        .run(TIMEOUT, move || {
            crate::vault::sync_dir(&path).map_err(|_| SyncError::Io)
        })
}

/// Read-only cloud operations have one separate worker and carry no vault or key.
pub(super) fn read<T: Send + 'static>(
    operation: impl FnOnce() -> Result<T, SyncError> + Send + 'static,
) -> Result<T, SyncError> {
    static READER: OnceLock<DirectorySync> = OnceLock::new();
    READER
        .get_or_init(DirectorySync::default)
        .run(TIMEOUT, operation)
}

/// A cooperative deadline stops a long copy once a blocked read returns.
pub(super) fn read_until<T: Send + 'static>(
    operation: impl FnOnce(Instant) -> Result<T, SyncError> + Send + 'static,
) -> Result<T, SyncError> {
    let deadline = Instant::now() + TIMEOUT;
    read(move || operation(deadline))
}

/// Keep at most one worker for this operation class, including after a timeout.
/// A blocked syscall cannot safely be cancelled. Repeated tries must not create
/// more blocked threads. Once the worker ends, a new try flushes the directory
/// again: completion of an earlier flush does not prove a later rename durable.
#[derive(Default)]
pub(super) struct DirectorySync {
    worker: Mutex<Option<Worker>>,
}

struct Worker {
    handle: JoinHandle<()>,
    deadline: Instant,
}

impl DirectorySync {
    pub(super) fn run<T: Send + 'static>(
        &self,
        timeout: Duration,
        flush: impl FnOnce() -> Result<T, SyncError> + Send + 'static,
    ) -> Result<T, SyncError> {
        let deadline = Instant::now() + timeout;
        let (send, receive) = mpsc::channel();
        loop {
            let mut worker = self.worker.lock().unwrap_or_else(PoisonError::into_inner);
            if worker
                .as_ref()
                .is_none_or(|worker| worker.handle.is_finished())
            {
                // A worker sends its result before it ends. Its old result is not
                // used by this caller; this call needs its own flush.
                if let Some(finished) = worker.take() {
                    let _ = finished.handle.join();
                }
                if Instant::now() >= deadline {
                    return Err(SyncError::TimedOut);
                }
                *worker = Some(Worker {
                    deadline,
                    handle: thread::Builder::new()
                        .name("apassy-sync-directory".to_owned())
                        .spawn(move || {
                            let _ = send.send(flush());
                        })
                        .map_err(|_| SyncError::Io)?,
                });
                break;
            }
            // Once this worker exceeds its deadline, later frames fail at once.
            // They cannot add a worker or wait for the same syscall again.
            if worker
                .as_ref()
                .is_some_and(|worker| Instant::now() >= worker.deadline)
            {
                return Err(SyncError::TimedOut);
            }
            // No filesystem work takes place with the slot mutex held.
            drop(worker);
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(SyncError::TimedOut);
            }
            thread::sleep(SLOT_POLL.min(remaining));
        }
        match receive.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => Err(SyncError::TimedOut),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(SyncError::Io),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn blocked_scan_is_a_timeout_not_an_empty_list() {
        let worker = DirectorySync::default();
        let (release, wait) = mpsc::channel();
        let result = worker.run(Duration::from_millis(25), move || {
            wait.recv().expect("release scan");
            Ok(Vec::<String>::new())
        });
        assert_eq!(result, Err(SyncError::TimedOut));
        release.send(()).expect("release scan worker");
    }

    #[test]
    fn directory_flush_keeps_success_and_error_results() {
        let worker = DirectorySync::default();
        let directory = tempfile::tempdir().expect("directory");
        let path = directory.path().to_owned();
        worker
            .run(Duration::from_secs(1), move || {
                crate::vault::sync_dir(&path).map_err(|_| SyncError::Io)
            })
            .expect("directory flushed");
        let error = worker
            .run(Duration::from_secs(1), || {
                Err::<(), _>(SyncError::FolderUnavailable)
            })
            .expect_err("a failed flush must not succeed");
        assert_eq!(error, SyncError::FolderUnavailable);
    }

    #[test]
    fn blocked_flush_times_out_without_more_workers_and_recovers() {
        let worker = DirectorySync::default();
        let (release, blocked) = mpsc::channel();
        let calls = Arc::new(AtomicUsize::new(0));
        let first_calls = Arc::clone(&calls);
        let start = Instant::now();
        let error = worker
            .run(Duration::from_millis(25), move || {
                first_calls.fetch_add(1, Ordering::SeqCst);
                blocked.recv().expect("release blocked worker");
                Ok(())
            })
            .expect_err("blocked flush must time out");
        assert_eq!(error, SyncError::TimedOut);
        assert!(start.elapsed() < Duration::from_secs(1));

        let retries_start = Instant::now();
        for _ in 0..3 {
            let retry_calls = Arc::clone(&calls);
            let error = worker
                .run(Duration::from_secs(1), move || {
                    retry_calls.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                })
                .expect_err("pending worker must block a new worker");
            assert_eq!(error, SyncError::TimedOut);
        }
        assert!(retries_start.elapsed() < Duration::from_millis(250));
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        release.send(()).expect("release worker");
        let recovery_deadline = Instant::now() + Duration::from_secs(1);
        while worker
            .worker
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|w| !w.handle.is_finished())
        {
            assert!(Instant::now() < recovery_deadline);
            thread::yield_now();
        }
        let next_calls = Arc::clone(&calls);
        worker
            .run(Duration::from_secs(1), move || {
                next_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .expect("next try must run a new flush");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}
