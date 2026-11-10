//! The Linux clipboard with exact ownership (ADR 0045). Platform independent, so the
//! tests run on every host with a fake display server.
//!
//! On X11 and Wayland the clipboard holds no copy of the text: the owning client serves
//! it to each paste. Apassy owns the selection itself (no helper process) and knows when
//! another client takes it (X11 `SelectionClear`, Wayland `cancelled`). After that,
//! Apassy never touches the clipboard for that copy.
//!
//! The clear replaces Apassy's own copy with an empty Apassy-owned clipboard. Giving the
//! selection up is not enough: GNOME's Mutter keeps a copy of every `text/plain`
//! clipboard and restores it when the owner goes away, and it ignores the password hint
//! (mutter `src/core/meta-clipboard-manager.c`, `owner_changed_cb`). The empty
//! replacement is what Mutter then keeps.
//!
//! The copy offers `x-kde-passwordManagerHint` with the value `secret`, the convention
//! that KeePassXC and KWallet use. Klipper skips such copies (plasma-workspace
//! `klipper/klipper.cpp`, KDE review D12539, since 2018); CopyQ treats them as secret
//! (CopyQ docs, "Security"); wl-clipboard sets `CLIPBOARD_STATE=sensitive` for
//! `wl-paste --watch`, which cliphist honours (wl-clipboard(1)). GNOME Shell's own
//! clipboard keeping (above) and clipboard managers that ignore the hint can still keep
//! the value. Every client of the session can read the clipboard while Apassy owns it.

use std::sync::{Arc, Mutex, PoisonError};

use zeroize::Zeroizing;

use super::{Pasteboard, PasteboardError, WriteIdentity};

/// The largest value Apassy serves: the vault field limit, as on macOS.
pub(super) const MAX_VALUE: usize = 65_536;

/// The MIME type (Wayland) and target name (X11) of the password-manager hint.
pub(super) const PASSWORD_HINT: &str = "x-kde-passwordManagerHint";
/// The value of the hint for a secret.
const HINT_SECRET: &[u8] = b"secret";

/// What a paste asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Want {
    /// The text in UTF-8.
    Text,
    /// The password-manager hint.
    Hint,
}

impl Want {
    /// The Wayland MIME types Apassy serves.
    pub(super) fn of_mime(mime: &str) -> Option<Self> {
        match mime {
            "text/plain;charset=utf-8" | "text/plain" | "UTF8_STRING" => Some(Self::Text),
            PASSWORD_HINT => Some(Self::Hint),
            _ => None,
        }
    }
}

/// The content of one Apassy clipboard claim.
struct Claim {
    generation: u64,
    value: Zeroizing<Vec<u8>>,
    /// A copied secret has the hint. The empty replacement has not.
    secret: bool,
}

/// What Apassy serves now, shared by the UI thread and the display event thread. It
/// holds at most one claim; a claim lost to another client is gone at once.
#[derive(Default)]
pub(super) struct Served {
    inner: Mutex<ServedInner>,
}

#[derive(Default)]
struct ServedInner {
    next: u64,
    claim: Option<Claim>,
}

impl Served {
    fn with<T>(&self, f: impl FnOnce(&mut ServedInner) -> T) -> T {
        f(&mut self.inner.lock().unwrap_or_else(PoisonError::into_inner))
    }

    fn start(&self, value: &[u8], secret: bool) -> u64 {
        self.with(|inner| {
            inner.next += 1;
            // The previous claim, and its value, drop here.
            inner.claim = Some(Claim {
                generation: inner.next,
                value: Zeroizing::new(value.to_vec()),
                secret,
            });
            inner.next
        })
    }

    /// The claim `generation` is still the one Apassy serves.
    pub(super) fn owns(&self, generation: u64) -> bool {
        self.with(|inner| inner.claim.as_ref().map(|c| c.generation) == Some(generation))
    }

    /// The generation Apassy serves now, and whether it is a secret.
    pub(super) fn current(&self) -> Option<(u64, bool)> {
        self.with(|inner| inner.claim.as_ref().map(|c| (c.generation, c.secret)))
    }

    /// Another client owns the clipboard, or the claim failed: stop serving
    /// `generation` and erase its value. A later claim stays.
    pub(super) fn lost(&self, generation: u64) {
        self.with(|inner| {
            if inner.claim.as_ref().map(|c| c.generation) == Some(generation) {
                inner.claim = None;
            }
        });
    }

    /// The display connection ended: nothing can be served any more.
    pub(super) fn lost_all(&self) {
        self.with(|inner| inner.claim = None);
    }

    /// The bytes for one paste of `generation`. `None` refuses the paste.
    pub(super) fn serve(&self, generation: u64, want: Want) -> Option<Zeroizing<Vec<u8>>> {
        self.with(|inner| {
            let claim = inner
                .claim
                .as_ref()
                .filter(|c| c.generation == generation)?;
            match want {
                Want::Text => Some(claim.value.clone()),
                Want::Hint => claim.secret.then(|| Zeroizing::new(HINT_SECRET.to_vec())),
            }
        })
    }

    /// Apassy still serves `generation`: put an empty claim in its place and erase the
    /// value. Returns the empty claim's generation, or `None` when `generation` is no
    /// longer Apassy's copy.
    fn blank(&self, generation: u64) -> Option<u64> {
        self.owns(generation).then(|| self.start(b"", false))
    }
}

/// The display server side of a claim: X11 selection ownership or a Wayland
/// data-control source. It serves whatever [`Served`] holds.
pub(super) trait Display: Send {
    /// Make Apassy the clipboard owner for the claim `generation`. `Ok` only when the
    /// display server confirmed that Apassy owns the clipboard.
    fn claim(&mut self, generation: u64) -> Result<(), PasteboardError>;
    /// Process ownership events that the display server already sent.
    fn sync(&mut self) -> Result<(), PasteboardError>;
    /// Announce the empty claim `blank` in place of `previous`, only while the display
    /// server still shows Apassy's `previous` claim. Otherwise mark `blank` lost.
    fn replace(&mut self, previous: u64, blank: u64) -> Result<(), PasteboardError>;
}

/// The ownership state machine on a display.
pub(super) struct LinuxBoard<D> {
    served: Arc<Served>,
    display: D,
    /// A replacement that the display did not confirm: `(previous, blank)`. A retry of
    /// the clear announces it again.
    unannounced: Option<(u64, u64)>,
}

impl<D: Display> LinuxBoard<D> {
    pub(super) fn new(served: Arc<Served>, display: D) -> Self {
        Self {
            served,
            display,
            unannounced: None,
        }
    }
}

impl<D: Display> Pasteboard for LinuxBoard<D> {
    fn write_concealed(&mut self, text: &str) -> Result<WriteIdentity, PasteboardError> {
        if text.len() > MAX_VALUE {
            return Err(PasteboardError);
        }
        self.unannounced = None;
        let generation = self.served.start(text.as_bytes(), true);
        if let Err(err) = self.display.claim(generation) {
            // An unconfirmed claim may still be the clipboard: serve it empty, and stop
            // serving the value at once in any case.
            if let Some(blank) = self.served.blank(generation) {
                let _ = self.display.replace(generation, blank);
            }
            self.served.lost(generation);
            return Err(err);
        }
        Ok(WriteIdentity {
            change_count: generation,
            owner: format!("linux-selection-{generation}"),
        })
    }

    fn clear_if_unchanged(&mut self, identity: &WriteIdentity) -> Result<(), PasteboardError> {
        let previous = identity.change_count;
        if let Some((pending, blank)) = self.unannounced
            && pending == previous
        {
            self.display.replace(previous, blank)?;
            self.unannounced = None;
            return Ok(());
        }
        // A foreign copy that the display server already reported must win.
        let synced = self.display.sync();
        let Some(blank) = self.served.blank(previous) else {
            // Another client owns the clipboard, or this copy is already cleared.
            return Ok(());
        };
        // The value is erased from Apassy now; only the announcement can fail.
        let announced = synced.and_then(|()| self.display.replace(previous, blank));
        if announced.is_err() {
            self.unannounced = Some((previous, blank));
        }
        announced
    }
}

/// The display variables of the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SessionEnv {
    pub(super) wayland: bool,
    pub(super) x11: bool,
}

impl SessionEnv {
    #[cfg(all(target_os = "linux", not(test)))]
    pub(super) fn from_env() -> Self {
        let set = |name| std::env::var_os(name).is_some_and(|value| !value.is_empty());
        Self {
            wayland: set("WAYLAND_DISPLAY"),
            x11: set("DISPLAY"),
        }
    }
}

/// How the Wayland display answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WaylandProbe {
    /// No connection, or no seat.
    Failed,
    /// The compositor offers neither ext-data-control-v1 nor wlr-data-control.
    NoControl,
}

/// Why this session has no clipboard copy. Each note names the reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Unavailable {
    NoDisplay,
    WaylandFailed,
    WaylandAndX11Failed,
    NoControl,
    NoControlX11Failed,
    X11Failed,
    ProbeFailed,
}

/// Shown while the session check runs.
pub(super) const CHECKING_NOTE: &str = "Apassy is checking whether this desktop session supports a clipboard copy that Apassy can clear. Try again in a moment.";

impl Unavailable {
    pub(super) fn note(self) -> &'static str {
        match self {
            Self::NoDisplay => {
                "Clipboard copy needs a Wayland or X11 desktop session, and this session has no display. Use Show or browser fill instead."
            }
            Self::WaylandFailed => {
                "Clipboard copy is unavailable: Apassy could not connect to the Wayland display, so it could not confirm and clear its own copy. Use Show or browser fill instead."
            }
            Self::WaylandAndX11Failed => {
                "Clipboard copy is unavailable: Apassy could not connect to the Wayland or the X11 display, so it could not confirm and clear its own copy. Use Show or browser fill instead."
            }
            Self::NoControl => {
                "Clipboard copy is unavailable: this Wayland compositor offers neither ext-data-control-v1 nor wlr-data-control, which Apassy needs to confirm and clear its own copy, and the session has no X11 display (XWayland). Use Show or browser fill instead."
            }
            Self::NoControlX11Failed => {
                "Clipboard copy is unavailable: this Wayland compositor offers neither ext-data-control-v1 nor wlr-data-control, and Apassy could not connect to the X11 display (XWayland), so it could not confirm and clear its own copy. Use Show or browser fill instead."
            }
            Self::X11Failed => {
                "Clipboard copy is unavailable: Apassy could not connect to the X11 display, so it could not confirm and clear its own copy. Use Show or browser fill instead."
            }
            Self::ProbeFailed => {
                "Clipboard copy is unavailable: Apassy could not start its clipboard check. Use Show or browser fill instead."
            }
        }
    }
}

/// The reason after every display of `env` failed. `wayland` is the answer of the
/// Wayland display when the session has one; `x11_failed` says the X11 display failed.
pub(super) fn unavailable(
    env: SessionEnv,
    wayland: Option<WaylandProbe>,
    x11_failed: bool,
) -> Unavailable {
    match (env.wayland, wayland, env.x11 && x11_failed) {
        (true, Some(WaylandProbe::NoControl), true) => Unavailable::NoControlX11Failed,
        (true, Some(WaylandProbe::NoControl), false) => Unavailable::NoControl,
        (true, _, true) => Unavailable::WaylandAndX11Failed,
        (true, _, false) => Unavailable::WaylandFailed,
        (false, _, true) => Unavailable::X11Failed,
        (false, _, false) => Unavailable::NoDisplay,
    }
}

/// The system clipboard of this session: opened once, in the background, because an
/// X11 connection can start XWayland.
#[cfg(all(target_os = "linux", not(test)))]
pub(super) mod system {
    use std::sync::{Arc, Mutex, Once, OnceLock, PoisonError};

    use super::super::{Pasteboard, PasteboardError, WriteIdentity};
    use super::{CHECKING_NOTE, Display, LinuxBoard, Served, SessionEnv, Unavailable, unavailable};

    type Board = Mutex<LinuxBoard<Box<dyn Display>>>;

    static STARTED: Once = Once::new();
    static SESSION: OnceLock<Result<Board, Unavailable>> = OnceLock::new();

    impl Display for Box<dyn Display> {
        fn claim(&mut self, generation: u64) -> Result<(), PasteboardError> {
            (**self).claim(generation)
        }
        fn sync(&mut self) -> Result<(), PasteboardError> {
            (**self).sync()
        }
        fn replace(&mut self, previous: u64, blank: u64) -> Result<(), PasteboardError> {
            (**self).replace(previous, blank)
        }
    }

    fn open_session(env: SessionEnv) -> Result<Board, Unavailable> {
        let served = Arc::new(Served::default());
        let board =
            |display: Box<dyn Display>| Mutex::new(LinuxBoard::new(served.clone(), display));
        let mut wayland = None;
        if env.wayland {
            match super::super::wayland::WaylandDisplay::open(served.clone()) {
                Ok(display) => return Ok(board(Box::new(display))),
                Err(probe) => wayland = Some(probe),
            }
        }
        if env.x11 {
            if let Ok(display) = super::super::x11::X11Display::open(served.clone()) {
                return Ok(board(Box::new(display)));
            }
            return Err(unavailable(env, wayland, true));
        }
        Err(unavailable(env, wayland, false))
    }

    /// `Ok` when this session can copy with ownership. Starts the check once.
    pub(in crate::desktop::clipboard) fn availability() -> Result<(), &'static str> {
        STARTED.call_once(|| {
            let started = std::thread::Builder::new()
                .name("apassy-clipboard-check".into())
                .spawn(|| {
                    let _ = SESSION.set(open_session(SessionEnv::from_env()));
                });
            if started.is_err() {
                let _ = SESSION.set(Err(Unavailable::ProbeFailed));
            }
        });
        match SESSION.get() {
            None => Err(CHECKING_NOTE),
            Some(Ok(_)) => Ok(()),
            Some(Err(reason)) => Err(reason.note()),
        }
    }

    /// The session clipboard, once the check found one.
    pub(in crate::desktop::clipboard) fn open() -> Result<Box<dyn Pasteboard>, PasteboardError> {
        match SESSION.get() {
            Some(Ok(board)) => Ok(Box::new(Handle(board))),
            _ => Err(PasteboardError),
        }
    }

    struct Handle(&'static Board);

    impl Pasteboard for Handle {
        fn write_concealed(&mut self, text: &str) -> Result<WriteIdentity, PasteboardError> {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .write_concealed(text)
        }
        fn clear_if_unchanged(&mut self, identity: &WriteIdentity) -> Result<(), PasteboardError> {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clear_if_unchanged(identity)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;
    use crate::desktop::clipboard::{CodeClipboard, MAX_CLEAR};

    const EPOCH: [u8; 32] = [7; 32];

    /// Who owns the clipboard of the fake display server.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Owner {
        Nobody,
        Apassy(u64),
        Foreign(String),
    }

    /// A display server with one clipboard, and a compositor that, like Mutter, keeps
    /// the text of each new owner and restores it when the owner goes away.
    struct Server {
        owner: Owner,
        kept: Option<Vec<u8>>,
        /// Ownership events not yet processed by Apassy.
        unsent_loss: Option<u64>,
        claims: usize,
        replacements: usize,
        fail_claim: bool,
        fail_replace: bool,
        /// The claim succeeds but another client takes the clipboard at once.
        stolen_at_claim: bool,
    }

    #[derive(Clone)]
    struct Fake {
        server: Arc<Mutex<Server>>,
        served: Arc<Served>,
        /// Losses arrive only at `sync`, like events still in the socket.
        late_events: bool,
    }

    impl Fake {
        fn new() -> Self {
            Self {
                server: Arc::new(Mutex::new(Server {
                    owner: Owner::Nobody,
                    kept: None,
                    unsent_loss: None,
                    claims: 0,
                    replacements: 0,
                    fail_claim: false,
                    fail_replace: false,
                    stolen_at_claim: false,
                })),
                served: Arc::new(Served::default()),
                late_events: false,
            }
        }

        fn with<T>(&self, f: impl FnOnce(&mut Server) -> T) -> T {
            f(&mut self.server.lock().expect("server"))
        }

        /// Another client copies `text`. Apassy hears of it now or at the next sync.
        fn foreign_copy(&self, text: &str) {
            let lost = self.with(|server| {
                let lost = match server.owner {
                    Owner::Apassy(generation) => Some(generation),
                    _ => None,
                };
                server.owner = Owner::Foreign(text.to_owned());
                server.kept = Some(text.as_bytes().to_vec());
                lost
            });
            if let Some(generation) = lost {
                if self.late_events {
                    self.with(|server| server.unsent_loss = Some(generation));
                } else {
                    self.served.lost(generation);
                }
            }
        }

        /// What a paste in another app gets now.
        fn paste(&self) -> Option<String> {
            let owner = self.with(|server| server.owner.clone());
            match owner {
                Owner::Nobody => self.with(|server| server.kept.clone()).map(utf8),
                Owner::Apassy(generation) => self
                    .served
                    .serve(generation, Want::Text)
                    .map(|v| utf8(v.to_vec())),
                Owner::Foreign(text) => Some(text),
            }
        }

        fn hint(&self) -> Option<Vec<u8>> {
            match self.with(|server| server.owner.clone()) {
                Owner::Apassy(generation) => self
                    .served
                    .serve(generation, Want::Hint)
                    .map(|v| v.to_vec()),
                _ => None,
            }
        }

        /// Apassy's process ends: its claim goes, and the compositor restores what it kept.
        fn quit(&self) {
            self.with(|server| {
                if matches!(server.owner, Owner::Apassy(_)) {
                    server.owner = Owner::Nobody;
                }
            });
        }

        fn take_ownership(&self, generation: u64) {
            let kept = self
                .served
                .serve(generation, Want::Text)
                .map(|v| v.to_vec());
            self.with(|server| {
                server.owner = Owner::Apassy(generation);
                server.kept = kept;
            });
        }
    }

    fn utf8(bytes: Vec<u8>) -> String {
        String::from_utf8(bytes).expect("utf-8")
    }

    impl Display for Fake {
        fn claim(&mut self, generation: u64) -> Result<(), PasteboardError> {
            if self.with(|server| std::mem::take(&mut server.fail_claim)) {
                return Err(PasteboardError);
            }
            self.with(|server| server.claims += 1);
            self.take_ownership(generation);
            if self.with(|server| std::mem::take(&mut server.stolen_at_claim)) {
                self.foreign_copy("a racing copy");
                return Err(PasteboardError);
            }
            Ok(())
        }

        fn sync(&mut self) -> Result<(), PasteboardError> {
            if let Some(generation) = self.with(|server| server.unsent_loss.take()) {
                self.served.lost(generation);
            }
            Ok(())
        }

        fn replace(&mut self, previous: u64, blank: u64) -> Result<(), PasteboardError> {
            if self.with(|server| std::mem::take(&mut server.fail_replace)) {
                return Err(PasteboardError);
            }
            if self.with(|server| server.owner != Owner::Apassy(previous)) {
                self.served.lost(blank);
                return Ok(());
            }
            self.with(|server| server.replacements += 1);
            self.take_ownership(blank);
            Ok(())
        }
    }

    fn setup() -> (CodeClipboard, Fake) {
        setup_with(Fake::new())
    }

    fn setup_with(fake: Fake) -> (CodeClipboard, Fake) {
        let board = LinuxBoard::new(fake.served.clone(), fake.clone());
        (CodeClipboard::with_board(Box::new(board)), fake)
    }

    fn secret() -> Zeroizing<String> {
        Zeroizing::new("synthetic-linux-secret".to_owned())
    }

    #[test]
    fn a_copy_is_served_with_the_secret_hint() {
        let (mut clip, fake) = setup();
        clip.copy_secret(secret(), EPOCH, Instant::now())
            .expect("copy");
        assert_eq!(fake.paste().as_deref(), Some("synthetic-linux-secret"));
        assert_eq!(fake.hint().as_deref(), Some(&b"secret"[..]));
        assert_eq!(Want::of_mime(PASSWORD_HINT), Some(Want::Hint));
        assert_eq!(Want::of_mime("text/plain;charset=utf-8"), Some(Want::Text));
        assert_eq!(Want::of_mime("text/html"), None);
    }

    #[test]
    fn write_then_timeout_clears_and_the_compositor_keeps_only_the_empty_copy() {
        let (mut clip, fake) = setup();
        let start = Instant::now();
        clip.copy_secret(secret(), EPOCH, start).expect("copy");
        assert_eq!(
            clip.tick(start + MAX_CLEAR - Duration::from_secs(1), Some(EPOCH)),
            Some(Duration::from_secs(1))
        );
        assert_eq!(fake.paste().as_deref(), Some("synthetic-linux-secret"));

        assert_eq!(clip.tick(start + MAX_CLEAR, Some(EPOCH)), None);
        assert!(!clip.is_pending());
        assert_eq!(fake.paste().as_deref(), Some(""));
        assert_eq!(fake.hint(), None, "the empty copy is no secret");
        // A compositor that restores the last clipboard restores the empty one.
        fake.quit();
        assert_eq!(fake.paste().as_deref(), Some(""));
        assert_eq!(fake.with(|s| s.replacements), 1);
    }

    #[test]
    fn write_then_foreign_overwrite_is_never_cleared() {
        let (mut clip, fake) = setup();
        let start = Instant::now();
        clip.copy_secret(secret(), EPOCH, start).expect("copy");
        fake.foreign_copy("an address the owner copied");
        // Apassy stops serving its value as soon as it hears of the foreign copy.
        assert!(fake.served.current().is_none());
        assert_eq!(clip.tick(start + MAX_CLEAR, Some(EPOCH)), None);
        assert_eq!(fake.paste().as_deref(), Some("an address the owner copied"));
        assert_eq!(fake.with(|s| s.replacements), 0);
        assert!(!clip.is_pending());
    }

    #[test]
    fn a_foreign_overwrite_still_in_the_socket_wins_over_the_clear() {
        let mut late = Fake::new();
        late.late_events = true;
        let (mut clip, fake) = setup_with(late);
        let start = Instant::now();
        clip.copy_secret(secret(), EPOCH, start).expect("copy");
        fake.foreign_copy("synthetic-linux-secret");
        clip.end_session();
        assert_eq!(fake.paste().as_deref(), Some("synthetic-linux-secret"));
        assert_eq!(fake.with(|s| s.replacements), 0);
    }

    #[test]
    fn lock_clears_at_once() {
        let (mut clip, fake) = setup();
        let start = Instant::now();
        clip.copy_secret(secret(), EPOCH, start).expect("copy");
        // A lock ends the vault session: the next tick has no epoch.
        assert_eq!(clip.tick(start, None), None);
        assert_eq!(fake.paste().as_deref(), Some(""));
        assert!(!clip.is_pending());
    }

    #[test]
    fn quit_clears_before_the_process_ends() {
        let (mut clip, fake) = setup();
        clip.copy(
            Zeroizing::new("287082".to_owned()),
            17,
            EPOCH,
            Instant::now(),
        )
        .expect("copy");
        // `end_session` runs at quit, lock and vault switch.
        clip.end_session();
        fake.quit();
        assert_eq!(fake.paste().as_deref(), Some(""));
        assert!(!clip.is_pending());
    }

    #[test]
    fn a_second_copy_replaces_the_first_and_only_the_second_is_served() {
        let (mut clip, fake) = setup();
        let start = Instant::now();
        clip.copy_secret(Zeroizing::new("first-synthetic".to_owned()), EPOCH, start)
            .expect("copy");
        clip.copy_secret(Zeroizing::new("second-synthetic".to_owned()), EPOCH, start)
            .expect("copy");
        assert_eq!(fake.paste().as_deref(), Some("second-synthetic"));
        clip.tick(start + MAX_CLEAR, Some(EPOCH));
        assert_eq!(fake.paste().as_deref(), Some(""));
    }

    #[test]
    fn a_failed_claim_serves_nothing_and_reports_an_uncertain_clipboard() {
        let (mut clip, fake) = setup();
        fake.with(|s| s.fail_claim = true);
        let err = clip
            .copy_secret(secret(), EPOCH, Instant::now())
            .unwrap_err();
        assert!(err.message().contains("clipboard may contain the value"));
        assert!(!clip.is_pending());
        assert!(fake.served.current().is_none());
        assert_ne!(fake.paste().as_deref(), Some("synthetic-linux-secret"));
    }

    #[test]
    fn a_claim_stolen_before_confirmation_is_not_reported_as_copied() {
        let (mut clip, fake) = setup();
        fake.with(|s| s.stolen_at_claim = true);
        assert!(clip.copy_secret(secret(), EPOCH, Instant::now()).is_err());
        assert_eq!(fake.paste().as_deref(), Some("a racing copy"));
        assert!(fake.served.current().is_none());
        assert_eq!(fake.with(|s| s.replacements), 0);
    }

    #[test]
    fn a_value_above_the_limit_is_refused_before_any_claim() {
        let (mut clip, fake) = setup();
        let big = Zeroizing::new("x".repeat(MAX_VALUE + 1));
        assert!(clip.copy_secret(big, EPOCH, Instant::now()).is_err());
        assert_eq!(fake.with(|s| s.claims), 0);
    }

    #[test]
    fn a_failed_announcement_erases_the_value_and_retries_the_empty_copy() {
        let (mut clip, fake) = setup();
        let start = Instant::now();
        clip.copy_secret(secret(), EPOCH, start).expect("copy");
        fake.with(|s| s.fail_replace = true);
        assert_eq!(
            clip.tick(start + MAX_CLEAR, Some(EPOCH)),
            Some(Duration::from_secs(1))
        );
        // Apassy no longer serves the value, although the announcement failed.
        assert_ne!(fake.paste().as_deref(), Some("synthetic-linux-secret"));
        assert_eq!(
            clip.tick(start + MAX_CLEAR + Duration::from_secs(1), Some(EPOCH)),
            None
        );
        assert_eq!(fake.paste().as_deref(), Some(""));
        assert!(!clip.is_pending());
    }

    #[test]
    fn a_loss_of_an_old_claim_keeps_the_current_one() {
        let served = Served::default();
        let first = served.start(b"one", true);
        let second = served.start(b"two", true);
        served.lost(first);
        assert_eq!(served.current(), Some((second, true)));
        assert_eq!(served.serve(first, Want::Text), None);
        assert_eq!(
            served
                .serve(second, Want::Text)
                .as_deref()
                .map(Vec::as_slice),
            Some(&b"two"[..])
        );
        served.lost_all();
        assert_eq!(served.current(), None);
    }

    #[test]
    fn each_session_without_ownership_has_a_precise_refusal() {
        let env = |wayland, x11| SessionEnv { wayland, x11 };
        let cases = [
            (
                env(false, false),
                None,
                false,
                Unavailable::NoDisplay,
                "has no display",
            ),
            (
                env(false, true),
                None,
                true,
                Unavailable::X11Failed,
                "could not connect to the X11 display",
            ),
            (
                env(true, false),
                Some(WaylandProbe::Failed),
                false,
                Unavailable::WaylandFailed,
                "could not connect to the Wayland display",
            ),
            (
                env(true, true),
                Some(WaylandProbe::Failed),
                true,
                Unavailable::WaylandAndX11Failed,
                "Wayland or the X11 display",
            ),
            (
                env(true, false),
                Some(WaylandProbe::NoControl),
                false,
                Unavailable::NoControl,
                "neither ext-data-control-v1 nor wlr-data-control",
            ),
            (
                env(true, true),
                Some(WaylandProbe::NoControl),
                true,
                Unavailable::NoControlX11Failed,
                "could not connect to the X11 display (XWayland)",
            ),
        ];
        for (env, wayland, x11_failed, reason, words) in cases {
            assert_eq!(unavailable(env, wayland, x11_failed), reason, "{env:?}");
            let note = reason.note();
            assert!(note.contains(words), "{note}");
            assert!(note.contains("Use Show or browser fill instead."), "{note}");
            assert!(!note.contains("Touch ID"), "{note}");
        }
        assert!(Unavailable::ProbeFailed.note().contains("clipboard check"));
        assert!(CHECKING_NOTE.contains("checking"));
    }
}
