//! The clipboard of a copied one-time code (TOTP).
//!
//! Apassy copies one thing only: the current code of a one-time password, after a fresh
//! owner check for that field ([`crate::broker::approvals::OwnerAction::CopyCode`]). A
//! password or another secret value is never copied.
//!
//! - The code goes to the system pasteboard as plain text with the
//!   `org.nspasteboard.ConcealedType` marker, so clipboard managers do not keep it.
//! - Apassy keeps the copied text in an erasing buffer until the clear. At the clear it
//!   reads the pasteboard and clears it only when it still holds the same text. A newer
//!   copy of the owner, in Apassy or in another app, stays.
//! - The clear comes when the code changes, after [`MIN_CLEAR`] at the earliest and
//!   [`MAX_CLEAR`] at the latest, at a lock, at a switch to another vault, and at quit.
//!
//! The check and the clear are two pasteboard calls, so a copy of another app between
//! them is lost. The window is a few microseconds.

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
        "Apassy could not use the clipboard. Nothing was copied."
    }
}

/// The system pasteboard, or a pasteboard in memory for the tests.
pub(crate) trait Pasteboard {
    /// Make `text` the only content, as plain text with the concealed marker.
    fn write_concealed(&mut self, text: &str) -> Result<(), PasteboardError>;
    /// True when the pasteboard holds exactly `text` as plain text.
    fn holds(&mut self, text: &str) -> bool;
    /// Remove all content.
    fn clear(&mut self) -> Result<(), PasteboardError>;
}

/// A copied code that waits for its clear.
struct PendingClear {
    text: Zeroizing<String>,
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
        // The new copy replaces an earlier one, so its buffer goes now.
        self.pending = None;
        if self.board.is_none() {
            self.board = Some(open_board()?);
        }
        let board = self.board.as_mut().ok_or(PasteboardError)?;
        board.write_concealed(&code)?;
        let after = clear_delay(left);
        self.pending = Some(PendingClear {
            text: code,
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
            return None;
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
        // `pending.text` erases itself when it drops at the end of this call.
        let Some(pending) = self.pending.take() else {
            return;
        };
        if let Some(board) = self.board.as_mut()
            && board.holds(&pending.text)
        {
            let _ = board.clear();
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

/// The system pasteboard through `arboard` (NSPasteboard on macOS).
#[cfg(not(test))]
mod native {
    use zeroize::Zeroizing;

    use super::{Pasteboard, PasteboardError};

    pub(super) struct SystemPasteboard(arboard::Clipboard);

    impl SystemPasteboard {
        pub(super) fn open() -> Result<Self, PasteboardError> {
            arboard::Clipboard::new()
                .map(Self)
                .map_err(|_| PasteboardError)
        }
    }

    impl Pasteboard for SystemPasteboard {
        fn write_concealed(&mut self, text: &str) -> Result<(), PasteboardError> {
            #[cfg(target_os = "macos")]
            let result = {
                use arboard::SetExtApple;
                self.0.set().exclude_from_history().text(text)
            };
            #[cfg(not(target_os = "macos"))]
            let result = self.0.set_text(text);
            result.map_err(|_| PasteboardError)
        }

        fn holds(&mut self, text: &str) -> bool {
            // The content may be a secret of another app: erase the copy.
            self.0
                .get_text()
                .map(Zeroizing::new)
                .is_ok_and(|current| current.as_str() == text)
        }

        fn clear(&mut self) -> Result<(), PasteboardError> {
            self.0.clear().map_err(|_| PasteboardError)
        }
    }
}

/// A pasteboard in memory. A clone shares the content, so a test keeps a handle.
#[cfg(test)]
pub(crate) mod memory {
    use std::sync::{Arc, Mutex, PoisonError};

    use super::{Pasteboard, PasteboardError};

    #[derive(Debug, Default)]
    pub(crate) struct Board {
        pub(crate) text: Option<String>,
        pub(crate) concealed: bool,
        pub(crate) writes: usize,
        pub(crate) clears: usize,
        /// The next write fails.
        pub(crate) fail_write: bool,
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
            });
        }

        pub(crate) fn text(&self) -> Option<String> {
            self.with(|board| board.text.clone())
        }
    }

    impl Pasteboard for MemoryBoard {
        fn write_concealed(&mut self, text: &str) -> Result<(), PasteboardError> {
            self.with(|board| {
                if std::mem::take(&mut board.fail_write) {
                    return Err(PasteboardError);
                }
                board.text = Some(text.to_owned());
                board.concealed = true;
                board.writes += 1;
                Ok(())
            })
        }

        fn holds(&mut self, text: &str) -> bool {
            self.with(|board| board.text.as_deref() == Some(text))
        }

        fn clear(&mut self) -> Result<(), PasteboardError> {
            self.with(|board| {
                board.text = None;
                board.concealed = false;
                board.clears += 1;
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
        assert!(err.message().contains("Nothing was copied"));
        assert!(!clip.is_pending());
        assert_eq!(board.text(), None);
    }
}
