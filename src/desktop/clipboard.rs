//! Explicit desktop copies with conditional expiration. Ordinary secret fields need a
//! fresh item/field/revision owner proof; one-time codes keep their separate action.
//!
//! The native helper writes plain text with concealed, transient, and device-local
//! markers. These are advisory: another local process can still read or retain it.
//! Clears compare the exact write identity, never text equality, so a later copy of
//! the same text survives. NSPasteboard has no cross-process compare-and-clear API;
//! another app can still write during the final native check/clear interval.

use std::time::{Duration, Instant};

use zeroize::Zeroizing;

/// The earliest clear after a copy. A code that changes sooner stays this long, so the
/// owner has time to paste it.
pub(crate) const MIN_CLEAR: Duration = Duration::from_secs(10);
/// The latest clear after a copy.
pub(crate) const MAX_CLEAR: Duration = Duration::from_secs(30);

/// Why the pasteboard did not take the code. It has no secret value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PasteboardError;

impl PasteboardError {
    pub(crate) fn message(&self) -> &'static str {
        "Apassy could not confirm the copy. The clipboard may contain the value; replace its contents if needed."
    }
}

// A failed acknowledgement can follow a successful write, and cleanup can fail too.
// The desktop never forwards helper errors, which could contain unexpected text.
impl From<crate::native::NativeError> for PasteboardError {
    fn from(_: crate::native::NativeError) -> Self {
        Self
    }
}

/// The system pasteboard, or a pasteboard in memory for the tests.
pub(crate) trait Pasteboard {
    /// Make `text` the only content with privacy markers and return its exact identity.
    fn write_concealed(&mut self, text: &str) -> Result<WriteIdentity, PasteboardError>;
    /// Remove content only if this exact write remains. Never read another app's text.
    fn clear_if_unchanged(&mut self, identity: &WriteIdentity) -> Result<(), PasteboardError>;
}

/// Nonsecret native write identity. A random owner marker prevents another app's
/// write racing the write acknowledgement from becoming ours.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct WriteIdentity {
    change_count: u64,
    owner: String,
}

/// A copied value that waits for its clear.
struct PendingClear {
    _text: Option<Zeroizing<String>>,
    identity: WriteIdentity,
    clear_at: Instant,
    /// The vault session of the copy. Another session clears at once.
    epoch: [u8; 32],
}

/// The copy of codes and their clear. One field of the app.
#[derive(Default)]
pub(crate) struct CodeClipboard {
    /// Opened at the first copy, so a test or a run without a copy never touches the
    /// system pasteboard.
    board: Option<Box<dyn Pasteboard>>,
    pending: Option<PendingClear>,
}

impl CodeClipboard {
    /// A clipboard with `board`, for the tests.
    #[cfg(test)]
    pub(crate) fn with_board(board: Box<dyn Pasteboard>) -> Self {
        Self {
            board: Some(board),
            pending: None,
        }
    }

    /// Copy `code`, which changes in `left` seconds, in the vault session `epoch`.
    /// Returns the time until the clear.
    pub(crate) fn copy(
        &mut self,
        code: Zeroizing<String>,
        left: u64,
        epoch: [u8; 32],
        now: Instant,
    ) -> Result<Duration, PasteboardError> {
        self.copy_for(code, clear_delay(left), epoch, now)
    }

    /// Copy an ordinary secret for exactly 30 seconds, without changing TOTP timing.
    pub(crate) fn copy_secret(
        &mut self,
        value: Zeroizing<String>,
        epoch: [u8; 32],
        now: Instant,
    ) -> Result<Duration, PasteboardError> {
        self.copy_for(value, MAX_CLEAR, epoch, now)
    }

    fn copy_for(
        &mut self,
        value: Zeroizing<String>,
        after: Duration,
        epoch: [u8; 32],
        now: Instant,
    ) -> Result<Duration, PasteboardError> {
        // A failed replacement must not abandon the lifetime of the previous copy.
        if self.board.is_none() {
            self.board = Some(open_board()?);
        }
        let board = self.board.as_mut().ok_or(PasteboardError)?;
        let identity = board.write_concealed(&value)?;
        self.pending = Some(PendingClear {
            _text: Some(value),
            identity,
            clear_at: now + after,
            epoch,
        });
        Ok(after)
    }

    /// Clear when the time has come or the vault session `epoch` is not the session of
    /// the copy. Returns the time until the next clear, for a repaint.
    pub(crate) fn tick(&mut self, now: Instant, epoch: Option<[u8; 32]>) -> Option<Duration> {
        let pending = self.pending.as_ref()?;
        if epoch != Some(pending.epoch) || now >= pending.clear_at {
            self.clear_now();
            // A native transport failure gets another attempt while the app lives.
            return self.pending.as_ref().map(|_| Duration::from_secs(1));
        }
        Some(pending.clear_at - now)
    }

    /// The vault locks, switches, or the app quits: clear the copied code if the
    /// pasteboard still holds it, and erase the buffer.
    pub(crate) fn end_session(&mut self) {
        self.clear_now();
    }

    /// True while a copied code waits for its clear.
    #[cfg(test)]
    pub(crate) fn is_pending(&self) -> bool {
        self.pending.is_some()
    }

    fn clear_now(&mut self) {
        // `pending._text` erases itself when it drops at the end of this call.
        let Some(mut pending) = self.pending.take() else {
            return;
        };
        // Even when a native clear fails, lock/switch erases the app's value buffer.
        // Keep only the nonsecret identity so a later frame can retry safely.
        pending._text = None;
        if let Some(board) = self.board.as_mut()
            && board.clear_if_unchanged(&pending.identity).is_err()
        {
            self.pending = Some(pending);
        }
    }
}

/// The time from a copy to its clear: when the code changes, within
/// [`MIN_CLEAR`]..=[`MAX_CLEAR`].
pub(crate) fn clear_delay(left: u64) -> Duration {
    Duration::from_secs(left).clamp(MIN_CLEAR, MAX_CLEAR)
}

#[cfg(not(test))]
fn open_board() -> Result<Box<dyn Pasteboard>, PasteboardError> {
    Ok(Box::new(native::SystemPasteboard::open()?))
}

/// The tests never touch the system pasteboard.
#[cfg(test)]
fn open_board() -> Result<Box<dyn Pasteboard>, PasteboardError> {
    Ok(Box::new(memory::MemoryBoard::default()))
}

/// The signed helper supplies NSPasteboard write identity and privacy markers, which
/// the existing arboard API cannot expose. It receives the value only through stdin.
#[cfg(not(test))]
mod native {
    use super::{Pasteboard, PasteboardError, WriteIdentity};
    use crate::native::NativeHelper;

    pub(super) struct SystemPasteboard(NativeHelper);

    impl SystemPasteboard {
        pub(super) fn open() -> Result<Self, PasteboardError> {
            NativeHelper::locate()
                .map(Self)
                .map_err(PasteboardError::from)
        }
    }

    impl Pasteboard for SystemPasteboard {
        fn write_concealed(&mut self, text: &str) -> Result<WriteIdentity, PasteboardError> {
            let (change_count, owner) = self
                .0
                .clipboard_write(text)
                .map_err(PasteboardError::from)?;
            Ok(WriteIdentity {
                change_count,
                owner,
            })
        }

        fn clear_if_unchanged(&mut self, identity: &WriteIdentity) -> Result<(), PasteboardError> {
            self.0
                .clipboard_clear_if_unchanged(identity.change_count, &identity.owner)
                .map_err(PasteboardError::from)
        }
    }
}

/// A pasteboard in memory. A clone shares the content, so a test keeps a handle.
#[cfg(test)]
pub(crate) mod memory {
    use std::sync::{Arc, Mutex, PoisonError};

    use super::{Pasteboard, PasteboardError, WriteIdentity};

    #[derive(Debug, Default)]
    pub(crate) struct Board {
        pub(crate) text: Option<String>,
        pub(crate) concealed: bool,
        pub(crate) transient: bool,
        pub(crate) local_only: bool,
        change_count: u64,
        owner: Option<String>,
        pub(crate) writes: usize,
        pub(crate) clears: usize,
        /// The next write fails.
        pub(crate) fail_write: bool,
        /// The next clear fails before touching the board.
        pub(crate) fail_clear: bool,
    }

    #[derive(Debug, Default, Clone)]
    pub(crate) struct MemoryBoard(pub(crate) Arc<Mutex<Board>>);

    impl MemoryBoard {
        pub(crate) fn with<T>(&self, f: impl FnOnce(&mut Board) -> T) -> T {
            f(&mut self.0.lock().unwrap_or_else(PoisonError::into_inner))
        }

        /// Another app writes the pasteboard.
        pub(crate) fn other_app_writes(&self, text: &str) {
            self.with(|board| {
                board.text = Some(text.to_owned());
                board.concealed = false;
                board.change_count += 1;
                board.owner = None;
            });
        }

        pub(crate) fn text(&self) -> Option<String> {
            self.with(|board| board.text.clone())
        }
    }

    impl Pasteboard for MemoryBoard {
        fn write_concealed(&mut self, text: &str) -> Result<WriteIdentity, PasteboardError> {
            self.with(|board| {
                if std::mem::take(&mut board.fail_write) {
                    return Err(PasteboardError);
                }
                board.text = Some(text.to_owned());
                board.concealed = true;
                board.transient = true;
                board.local_only = true;
                board.writes += 1;
                board.change_count += 1;
                let owner = format!("memory-write-{}", board.change_count);
                board.owner = Some(owner.clone());
                Ok(WriteIdentity {
                    change_count: board.change_count,
                    owner,
                })
            })
        }

        fn clear_if_unchanged(&mut self, identity: &WriteIdentity) -> Result<(), PasteboardError> {
            self.with(|board| {
                if std::mem::take(&mut board.fail_clear) {
                    return Err(PasteboardError);
                }
                if board.change_count == identity.change_count
                    && board.owner.as_ref() == Some(&identity.owner)
                {
                    board.text = None;
                    board.concealed = false;
                    board.owner = None;
                    board.clears += 1;
                    board.change_count += 1;
                }
                Ok(())
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::memory::MemoryBoard;
    use super::*;

    const EPOCH: [u8; 32] = [7; 32];
    const OTHER_EPOCH: [u8; 32] = [8; 32];

    fn clipboard() -> (CodeClipboard, MemoryBoard) {
        let board = MemoryBoard::default();
        (CodeClipboard::with_board(Box::new(board.clone())), board)
    }

    fn code(text: &str) -> Zeroizing<String> {
        Zeroizing::new(text.to_owned())
    }

    #[test]
    fn the_clear_comes_when_the_code_changes_within_the_limits() {
        assert_eq!(clear_delay(0), MIN_CLEAR);
        assert_eq!(clear_delay(3), MIN_CLEAR);
        assert_eq!(clear_delay(17), Duration::from_secs(17));
        assert_eq!(clear_delay(30), MAX_CLEAR);
        assert_eq!(clear_delay(55), MAX_CLEAR);
        assert_eq!(clear_delay(u64::MAX), MAX_CLEAR);
    }

    #[test]
    fn a_copy_is_concealed_and_clears_at_its_time() {
        let (mut clip, board) = clipboard();
        let start = Instant::now();
        let after = clip.copy(code("287082"), 17, EPOCH, start).expect("copy");
        assert_eq!(after, Duration::from_secs(17));
        assert_eq!(board.text().as_deref(), Some("287082"));
        assert!(board.with(|b| b.concealed));
        assert!(clip.is_pending());

        // Before the time: nothing changes, and the app learns when to wake.
        let left = clip.tick(start + Duration::from_secs(5), Some(EPOCH));
        assert_eq!(left, Some(Duration::from_secs(12)));
        assert_eq!(board.text().as_deref(), Some("287082"));

        // At the time: the pasteboard still holds the code, so it is cleared.
        assert_eq!(clip.tick(start + after, Some(EPOCH)), None);
        assert_eq!(board.text(), None);
        assert_eq!(board.with(|b| b.clears), 1);
        assert!(!clip.is_pending());
        // A later tick does nothing.
        assert_eq!(clip.tick(start + after * 2, Some(EPOCH)), None);
        assert_eq!(board.with(|b| b.clears), 1);
    }

    #[test]
    fn a_newer_copy_of_another_app_is_never_cleared() {
        let (mut clip, board) = clipboard();
        let start = Instant::now();
        clip.copy(code("287082"), 30, EPOCH, start).expect("copy");
        board.other_app_writes("an address the owner copied");
        assert_eq!(clip.tick(start + MAX_CLEAR, Some(EPOCH)), None);
        assert_eq!(board.text().as_deref(), Some("an address the owner copied"));
        assert_eq!(board.with(|b| b.clears), 0);
        // The buffer of the code is gone all the same.
        assert!(!clip.is_pending());
    }

    #[test]
    fn a_lock_clears_the_code_at_once_and_ends_the_buffer() {
        let (mut clip, board) = clipboard();
        let start = Instant::now();
        clip.copy(code("287082"), 30, EPOCH, start).expect("copy");
        clip.end_session();
        assert_eq!(board.text(), None);
        assert!(!clip.is_pending());

        // A lock after the owner copied something else keeps it.
        clip.copy(code("94287082"), 30, EPOCH, start).expect("copy");
        board.other_app_writes("94287082 is not the copy");
        clip.end_session();
        assert_eq!(board.text().as_deref(), Some("94287082 is not the copy"));
        assert!(!clip.is_pending());
    }

    #[test]
    fn another_vault_session_clears_at_once() {
        let (mut clip, board) = clipboard();
        let start = Instant::now();
        clip.copy(code("287082"), 30, EPOCH, start).expect("copy");
        // Locked: no session.
        assert_eq!(clip.tick(start, None), None);
        assert_eq!(board.text(), None);

        clip.copy(code("287082"), 30, EPOCH, start).expect("copy");
        assert_eq!(clip.tick(start, Some(OTHER_EPOCH)), None);
        assert_eq!(board.text(), None);
        assert!(!clip.is_pending());
    }

    #[test]
    fn a_second_copy_replaces_the_first_and_keeps_one_clear() {
        let (mut clip, board) = clipboard();
        let start = Instant::now();
        clip.copy(code("111111"), 30, EPOCH, start).expect("copy");
        clip.copy(code("222222"), 12, EPOCH, start + Duration::from_secs(1))
            .expect("copy");
        assert_eq!(board.text().as_deref(), Some("222222"));
        assert_eq!(
            clip.tick(start + Duration::from_secs(13), Some(EPOCH)),
            None
        );
        assert_eq!(board.text(), None);
        assert_eq!(board.with(|b| (b.writes, b.clears)), (2, 1));
    }

    #[test]
    fn a_failed_write_leaves_nothing_pending() {
        let (mut clip, board) = clipboard();
        board.with(|b| b.fail_write = true);
        let err = clip
            .copy(code("287082"), 30, EPOCH, Instant::now())
            .unwrap_err();
        assert!(err.message().contains("clipboard may contain the value"));
        assert!(!clip.is_pending());
        assert_eq!(board.text(), None);
    }
    #[test]
    fn ordinary_secret_expires_after_thirty_seconds_and_preserves_a_later_identical_copy() {
        let (mut clip, board) = clipboard();
        let start = Instant::now();
        assert_eq!(
            clip.copy_secret(code("synthetic-secret"), EPOCH, start)
                .expect("copy"),
            MAX_CLEAR
        );
        assert_eq!(
            clip.tick(start + Duration::from_secs(29), Some(EPOCH)),
            Some(Duration::from_secs(1))
        );
        board.other_app_writes("synthetic-secret");
        assert_eq!(clip.tick(start + MAX_CLEAR, Some(EPOCH)), None);
        assert_eq!(board.text().as_deref(), Some("synthetic-secret"));
        assert_eq!(board.with(|b| b.clears), 0);
    }

    #[test]
    fn ordinary_secret_clears_on_expiry_switch_lock_and_quit_but_keeps_later_copies() {
        let (mut clip, board) = clipboard();
        let start = Instant::now();
        clip.copy_secret(code("synthetic-secret"), EPOCH, start)
            .expect("copy");
        clip.tick(start + MAX_CLEAR, Some(EPOCH));
        assert_eq!(board.text(), None);
        for epoch in [None, Some(OTHER_EPOCH)] {
            clip.copy_secret(code("synthetic-secret"), EPOCH, start)
                .expect("copy");
            clip.tick(start, epoch);
            assert_eq!(board.text(), None);
        }
        clip.copy_secret(code("synthetic-secret"), EPOCH, start)
            .expect("copy");
        clip.end_session();
        assert_eq!(board.text(), None);
        clip.copy_secret(code("synthetic-secret"), EPOCH, start)
            .expect("copy");
        board.other_app_writes("synthetic-secret");
        clip.end_session();
        assert_eq!(board.text().as_deref(), Some("synthetic-secret"));
    }

    #[test]
    fn failed_replacement_keeps_the_previous_copys_expiry() {
        let (mut clip, board) = clipboard();
        let start = Instant::now();
        clip.copy_secret(code("first-synthetic-secret"), EPOCH, start)
            .expect("copy");
        board.with(|b| b.fail_write = true);
        assert!(
            clip.copy_secret(code("second-synthetic-secret"), EPOCH, start)
                .is_err()
        );
        assert!(clip.is_pending());
        clip.tick(start + MAX_CLEAR, Some(EPOCH));
        assert_eq!(board.text(), None);
    }

    #[test]
    fn a_later_identical_totp_copy_is_also_preserved() {
        let (mut clip, board) = clipboard();
        let start = Instant::now();
        clip.copy(code("287082"), 17, EPOCH, start).expect("copy");
        board.other_app_writes("287082");
        clip.tick(start + Duration::from_secs(17), Some(EPOCH));
        assert_eq!(board.text().as_deref(), Some("287082"));
        assert_eq!(board.with(|b| b.clears), 0);
    }
    #[test]
    fn a_failed_clear_erases_the_local_value_and_retries_only_its_identity() {
        let (mut clip, board) = clipboard();
        let start = Instant::now();
        clip.copy_secret(code("synthetic-secret"), EPOCH, start)
            .expect("copy");
        board.with(|b| b.fail_clear = true);
        assert_eq!(
            clip.tick(start + MAX_CLEAR, Some(EPOCH)),
            Some(Duration::from_secs(1))
        );
        assert!(clip.pending.as_ref().expect("retry")._text.is_none());
        assert_eq!(
            clip.tick(start + MAX_CLEAR + Duration::from_secs(1), Some(EPOCH)),
            None
        );
        assert_eq!(board.text(), None);
    }
    #[cfg(unix)]
    #[test]
    fn failed_write_acknowledgement_and_failed_cleanup_report_uncertain_clipboard_state() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("temporary fixture");
        let path = dir.path().join("fake-failed-cleanup-helper");
        // This fixture records command names only; it has no real pasteboard API.
        std::fs::write(
            &path,
            r#"#!/usr/bin/env python3
import json, pathlib, sys
req = json.loads(sys.stdin.readline())
with (pathlib.Path(__file__).parent / 'commands').open('a') as log:
    log.write(req['cmd'] + '\n')
if req['cmd'] == 'clipboard_write':
    print(json.dumps({'ok': True}))
else:
    print(json.dumps({'ok': False, 'error': 'failed', 'message': 'Synthetic cleanup failure.'}))
"#,
        )
        .expect("write fake helper");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .expect("fixture permissions");
        let client = crate::native::NativeHelper::with_paths(&path, &path);
        let error = PasteboardError::from(
            client
                .clipboard_write("synthetic-copy-canary")
                .expect_err("lost acknowledgement"),
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("commands")).expect("commands"),
            "clipboard_write\nclipboard_clear\n"
        );
        assert!(error.message().contains("clipboard may contain the value"));
        assert!(!error.message().contains("Nothing was copied"));
        assert!(!error.message().contains("synthetic-copy-canary"));
    }
}
