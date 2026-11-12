//! X11 `CLIPBOARD` ownership with a pure-Rust connection (x11rb, no libxcb, no unsafe).
//! Also the path for a Wayland session through XWayland when the compositor has no
//! data-control protocol (GNOME): Mutter bridges the X11 selection to Wayland clients.
//!
//! Apassy owns the selection with an unmapped window and a real server timestamp
//! (ICCCM 2.1), serves `UTF8_STRING`, `text/plain;charset=utf-8`, `TARGETS`,
//! `TIMESTAMP` and the password hint, and never answers `SAVE_TARGETS` or asks a
//! clipboard manager to take over. `SelectionClear`, checked against
//! `GetSelectionOwner`, ends the claim. Values above [`MAX_VALUE`] are refused, so no
//! INCR transfer is needed. Nothing here logs a value.

use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use x11rb::connection::Connection as _;
use x11rb::protocol::Event;
use x11rb::protocol::xproto::{
    AtomEnum, ConnectionExt as _, CreateWindowAux, EventMask, PropMode, SELECTION_NOTIFY_EVENT,
    SelectionNotifyEvent, SelectionRequestEvent, Timestamp, Window, WindowClass,
};
use x11rb::rust_connection::RustConnection;
use x11rb::wrapper::ConnectionExt as _;
use x11rb::{CURRENT_TIME, NONE};

use super::PasteboardError;
use super::linux::{Display, MAX_VALUE, Served, Want};

x11rb::atom_manager! {
    Atoms: AtomsCookie {
        CLIPBOARD,
        TARGETS,
        TIMESTAMP,
        UTF8_STRING,
        TEXT_PLAIN_UTF8: b"text/plain;charset=utf-8",
        PASSWORD_HINT: b"x-kde-passwordManagerHint",
        APASSY_TIME: b"_APASSY_CLIPBOARD_TIME",
    }
}

/// How long Apassy waits for the X server.
const TIMEOUT: Duration = Duration::from_secs(2);

/// The claim the X server knows, with the time Apassy took the selection.
#[derive(Clone, Copy)]
struct Owned {
    generation: u64,
    since: Timestamp,
}

/// Server timestamps from `PropertyNotify`, counted so a waiter knows its own.
#[derive(Default)]
struct Stamps {
    count: u64,
    time: Timestamp,
}

struct Inner {
    conn: RustConnection,
    window: Window,
    atoms: Atoms,
    served: Arc<Served>,
    owned: Mutex<Option<Owned>>,
    stamps: (Mutex<Stamps>, Condvar),
}

pub(super) struct X11Display {
    inner: Arc<Inner>,
}

fn fail<E>(_: E) -> PasteboardError {
    PasteboardError
}

impl X11Display {
    /// Connect to `$DISPLAY` and start the event thread.
    #[cfg(not(test))]
    pub(super) fn open(served: Arc<Served>) -> Result<Self, PasteboardError> {
        Self::open_on(served, None)
    }

    /// Connect to `display` (`None`: `$DISPLAY`) and start the event thread.
    fn open_on(served: Arc<Served>, display: Option<&str>) -> Result<Self, PasteboardError> {
        let (conn, screen) = x11rb::connect(display).map_err(fail)?;
        let root = conn.setup().roots.get(screen).ok_or(PasteboardError)?.root;
        let window = conn.generate_id().map_err(fail)?;
        conn.create_window(
            0,
            window,
            root,
            0,
            0,
            1,
            1,
            0,
            WindowClass::INPUT_ONLY,
            x11rb::COPY_FROM_PARENT,
            &CreateWindowAux::new().event_mask(EventMask::PROPERTY_CHANGE),
        )
        .map_err(fail)?
        .check()
        .map_err(fail)?;
        let atoms = Atoms::new(&conn).map_err(fail)?.reply().map_err(fail)?;
        let inner = Arc::new(Inner {
            conn,
            window,
            atoms,
            served,
            owned: Mutex::new(None),
            stamps: (Mutex::new(Stamps::default()), Condvar::new()),
        });
        let events = inner.clone();
        std::thread::Builder::new()
            .name("apassy-clipboard-x11".into())
            .spawn(move || events.run())
            .map_err(fail)?;
        Ok(Self { inner })
    }
}

impl Inner {
    fn run(&self) {
        loop {
            match self.conn.wait_for_event() {
                Ok(Event::PropertyNotify(event))
                    if event.window == self.window && event.atom == self.atoms.APASSY_TIME =>
                {
                    let (lock, ready) = &self.stamps;
                    let mut stamps = lock.lock().unwrap_or_else(PoisonError::into_inner);
                    stamps.count += 1;
                    stamps.time = event.time;
                    ready.notify_all();
                }
                Ok(Event::SelectionClear(event))
                    if event.owner == self.window && event.selection == self.atoms.CLIPBOARD =>
                {
                    // A late event of an earlier loss must not end the current claim.
                    if !self.still_owner() {
                        self.lose();
                    }
                }
                Ok(Event::SelectionRequest(request)) => self.answer(request),
                Ok(_) => {}
                Err(_) => {
                    // The display is gone; nothing can be pasted from Apassy any more.
                    self.lose();
                    self.served.lost_all();
                    return;
                }
            }
        }
    }

    fn owned(&self) -> Option<Owned> {
        *self.owned.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn lose(&self) {
        if let Some(owned) = self
            .owned
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            self.served.lost(owned.generation);
        }
    }

    fn still_owner(&self) -> bool {
        self.conn
            .get_selection_owner(self.atoms.CLIPBOARD)
            .ok()
            .and_then(|cookie| cookie.reply().ok())
            .is_some_and(|reply| reply.owner == self.window)
    }

    /// A server timestamp: append nothing to a property and wait for its notify.
    fn server_time(&self) -> Result<Timestamp, PasteboardError> {
        let (lock, ready) = &self.stamps;
        let before = lock.lock().unwrap_or_else(PoisonError::into_inner).count;
        self.conn
            .change_property8(
                PropMode::APPEND,
                self.window,
                self.atoms.APASSY_TIME,
                AtomEnum::STRING,
                &[],
            )
            .map_err(fail)?;
        self.conn.flush().map_err(fail)?;
        let deadline = Instant::now() + TIMEOUT;
        let mut stamps = lock.lock().unwrap_or_else(PoisonError::into_inner);
        while stamps.count == before {
            let left = deadline
                .checked_duration_since(Instant::now())
                .ok_or(PasteboardError)?;
            stamps = ready
                .wait_timeout(stamps, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        Ok(stamps.time)
    }

    fn claim(&self, generation: u64) -> Result<(), PasteboardError> {
        let since = self.server_time()?;
        // Serve the claim before the server can send the first request for it.
        *self.owned.lock().unwrap_or_else(PoisonError::into_inner) =
            Some(Owned { generation, since });
        self.conn
            .set_selection_owner(self.window, self.atoms.CLIPBOARD, since)
            .map_err(fail)?;
        self.conn.flush().map_err(fail)?;
        if !self.still_owner() {
            self.served.lost(generation);
            return Err(PasteboardError);
        }
        Ok(())
    }

    /// Answer one paste. Only the current claim is served, never to a request older
    /// than the claim (ICCCM 2.2).
    fn answer(&self, request: SelectionRequestEvent) {
        let property = if request.property == NONE {
            request.target
        } else {
            request.property
        };
        let done = self.convert(&request, property);
        let notify = SelectionNotifyEvent {
            response_type: SELECTION_NOTIFY_EVENT,
            sequence: 0,
            time: request.time,
            requestor: request.requestor,
            selection: request.selection,
            target: request.target,
            property: if done { property } else { NONE },
        };
        let _ = self
            .conn
            .send_event(false, request.requestor, EventMask::NO_EVENT, notify);
        let _ = self.conn.flush();
    }

    fn convert(&self, request: &SelectionRequestEvent, property: u32) -> bool {
        let atoms = &self.atoms;
        if request.owner != self.window || request.selection != atoms.CLIPBOARD {
            return false;
        }
        let Some(owned) = self.owned() else {
            return false;
        };
        if request.time != CURRENT_TIME && request.time < owned.since {
            return false;
        }
        let Some((generation, secret)) = self.served.current() else {
            return false;
        };
        if generation != owned.generation {
            return false;
        }
        let target = request.target;
        let written = if target == atoms.TARGETS {
            let mut targets = vec![
                atoms.TARGETS,
                atoms.TIMESTAMP,
                atoms.UTF8_STRING,
                atoms.TEXT_PLAIN_UTF8,
            ];
            if secret {
                targets.push(atoms.PASSWORD_HINT);
            }
            self.conn.change_property32(
                PropMode::REPLACE,
                request.requestor,
                property,
                AtomEnum::ATOM,
                &targets,
            )
        } else if target == atoms.TIMESTAMP {
            self.conn.change_property32(
                PropMode::REPLACE,
                request.requestor,
                property,
                AtomEnum::INTEGER,
                &[owned.since],
            )
        } else {
            let want = if target == atoms.UTF8_STRING || target == atoms.TEXT_PLAIN_UTF8 {
                Want::Text
            } else if target == atoms.PASSWORD_HINT {
                Want::Hint
            } else {
                // MULTIPLE, SAVE_TARGETS and other targets are refused.
                return false;
            };
            let Some(bytes) = self.served.serve(generation, want) else {
                return false;
            };
            debug_assert!(bytes.len() <= MAX_VALUE);
            self.conn.change_property8(
                PropMode::REPLACE,
                request.requestor,
                property,
                target,
                &bytes,
            )
        };
        written.is_ok()
    }
}

impl Display for X11Display {
    fn claim(&mut self, generation: u64) -> Result<(), PasteboardError> {
        self.inner.claim(generation)
    }

    fn sync(&mut self) -> Result<(), PasteboardError> {
        // `replace` asks the server directly.
        Ok(())
    }

    fn replace(&mut self, previous: u64, blank: u64) -> Result<(), PasteboardError> {
        let inner = &self.inner;
        let ours = inner
            .owned()
            .is_some_and(|owned| owned.generation == previous);
        if !ours || !inner.still_owner() {
            inner.lose();
            inner.served.lost(blank);
            return Ok(());
        }
        // A new owner timestamp, so XFixes listeners such as Mutter take the empty
        // value in place of the copy they kept.
        inner.claim(blank)
    }
}

/// The X11 protocol against a real display server: each test starts its own Xvfb on a
/// free display (`-displayfd`), so the tests run side by side and never touch the
/// session's clipboard. The linux-vault CI job installs Xvfb and sets
/// `APASSY_REQUIRE_X11=1`; elsewhere a missing Xvfb is a reported skip. Synthetic
/// values only.
#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader};
    use std::process::{Child, Command, Stdio};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use x11rb::connection::Connection as _;
    use x11rb::protocol::Event;
    use x11rb::protocol::xproto::{
        Atom, AtomEnum, ConnectionExt as _, CreateWindowAux, GetPropertyReply, Window, WindowClass,
    };
    use x11rb::rust_connection::RustConnection;
    use x11rb::{CURRENT_TIME, NONE};

    use super::X11Display;
    use crate::desktop::clipboard::Pasteboard;
    use crate::desktop::clipboard::linux::{LinuxBoard, Served};

    const VALUE: &str = "synthetic-x11-clipboard-value";
    const HINT: &str = "x-kde-passwordManagerHint";
    const WAIT: Duration = Duration::from_secs(5);

    /// A private X server for one test. Dropping it stops the server.
    struct Xvfb {
        child: Child,
        display: String,
    }

    impl Xvfb {
        /// `None` (a reported skip) when Xvfb is not installed, unless
        /// `APASSY_REQUIRE_X11` is set.
        fn start() -> Option<Self> {
            let spawned = Command::new("Xvfb")
                .args([
                    "-displayfd",
                    "1",
                    "-nolisten",
                    "tcp",
                    "-screen",
                    "0",
                    "64x64x24",
                ])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn();
            let mut child = match spawned {
                Ok(child) => child,
                Err(err) => {
                    assert!(
                        std::env::var_os("APASSY_REQUIRE_X11").is_none(),
                        "APASSY_REQUIRE_X11 is set, but Xvfb did not start: {err}"
                    );
                    eprintln!("skipped: Xvfb is not installed ({err})");
                    return None;
                }
            };
            // Xvfb writes the display number once it accepts connections.
            let mut line = String::new();
            BufReader::new(child.stdout.take().unwrap())
                .read_line(&mut line)
                .unwrap();
            let number = line.trim();
            assert!(
                !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit()),
                "Xvfb gave no display number: {line:?}"
            );
            Some(Self {
                display: format!(":{number}"),
                child,
            })
        }

        fn board(&self) -> (LinuxBoard<X11Display>, Arc<Served>) {
            let served = Arc::new(Served::default());
            let display = X11Display::open_on(served.clone(), Some(&self.display))
                .expect("the X11 display opens");
            (LinuxBoard::new(served.clone(), display), served)
        }

        fn peer(&self) -> Peer {
            Peer::new(&self.display)
        }
    }

    impl Drop for Xvfb {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
        let deadline = Instant::now() + WAIT;
        while !done() {
            assert!(Instant::now() < deadline, "timed out: {what}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Another client of the display: it pastes, and it copies.
    struct Peer {
        conn: RustConnection,
        window: Window,
        clipboard: Atom,
        property: Atom,
    }

    impl Peer {
        fn new(display: &str) -> Self {
            let (conn, screen) = x11rb::connect(Some(display)).expect("the X11 display");
            let root = conn.setup().roots[screen].root;
            let window = conn.generate_id().unwrap();
            conn.create_window(
                0,
                window,
                root,
                0,
                0,
                1,
                1,
                0,
                WindowClass::INPUT_ONLY,
                x11rb::COPY_FROM_PARENT,
                &CreateWindowAux::new(),
            )
            .unwrap()
            .check()
            .unwrap();
            let mut peer = Self {
                conn,
                window,
                clipboard: NONE,
                property: NONE,
            };
            peer.clipboard = peer.atom("CLIPBOARD");
            peer.property = peer.atom("APASSY_TEST_PASTE");
            peer
        }

        fn atom(&self, name: &str) -> Atom {
            self.conn
                .intern_atom(false, name.as_bytes())
                .unwrap()
                .reply()
                .unwrap()
                .atom
        }

        /// Paste `target` as a requestor does (ICCCM 2.4): the property, or `None` when
        /// the owner refused.
        fn paste(&self, target: &str) -> Option<GetPropertyReply> {
            let target = self.atom(target);
            self.conn
                .convert_selection(
                    self.window,
                    self.clipboard,
                    target,
                    self.property,
                    CURRENT_TIME,
                )
                .unwrap();
            self.conn.flush().unwrap();
            let deadline = Instant::now() + WAIT;
            loop {
                assert!(Instant::now() < deadline, "no SelectionNotify");
                match self.conn.poll_for_event().unwrap() {
                    Some(Event::SelectionNotify(event)) if event.requestor == self.window => {
                        if event.property == NONE {
                            return None;
                        }
                        return Some(
                            self.conn
                                .get_property(
                                    true,
                                    self.window,
                                    self.property,
                                    AtomEnum::ANY,
                                    0,
                                    u32::MAX / 4,
                                )
                                .unwrap()
                                .reply()
                                .unwrap(),
                        );
                    }
                    Some(_) => {}
                    None => std::thread::sleep(Duration::from_millis(5)),
                }
            }
        }

        fn text(&self) -> Option<Vec<u8>> {
            self.paste("UTF8_STRING").map(|reply| reply.value)
        }

        fn targets(&self) -> Vec<Atom> {
            self.paste("TARGETS")
                .and_then(|reply| reply.value32().map(Iterator::collect))
                .unwrap_or_default()
        }

        /// Copy something of its own: take the clipboard.
        fn copy(&self) {
            self.conn
                .set_selection_owner(self.window, self.clipboard, CURRENT_TIME)
                .unwrap();
            self.conn.flush().unwrap();
        }

        fn owner(&self) -> Window {
            self.conn
                .get_selection_owner(self.clipboard)
                .unwrap()
                .reply()
                .unwrap()
                .owner
        }
    }

    #[test]
    fn x11_a_copy_is_served_with_the_hint_and_the_clear_leaves_an_empty_own_copy() {
        let Some(server) = Xvfb::start() else {
            return;
        };
        let (mut board, _served) = server.board();
        let peer = server.peer();
        let copied = board.write_concealed(VALUE).expect("Apassy owns CLIPBOARD");
        let owner = peer.owner();
        assert!(owner != NONE && owner != peer.window, "Apassy is the owner");
        assert_eq!(peer.text().as_deref(), Some(VALUE.as_bytes()));
        assert_eq!(
            peer.paste("text/plain;charset=utf-8").map(|r| r.value),
            Some(VALUE.as_bytes().to_vec())
        );
        assert_eq!(peer.paste(HINT).map(|r| r.value), Some(b"secret".to_vec()));
        let targets = peer.targets();
        for name in ["TARGETS", "UTF8_STRING", "text/plain;charset=utf-8", HINT] {
            assert!(targets.contains(&peer.atom(name)), "{name} in TARGETS");
        }
        // A clipboard manager's save request and other targets get nothing.
        for refused in ["SAVE_TARGETS", "MULTIPLE", "STRING", "image/png"] {
            assert!(peer.paste(refused).is_none(), "{refused} is refused");
        }

        board.clear_if_unchanged(&copied).unwrap();
        // Still Apassy's clipboard, now empty and without the hint, so a keeping
        // clipboard manager (Mutter) keeps the empty copy.
        assert_eq!(peer.owner(), owner);
        assert_eq!(peer.text(), Some(Vec::new()));
        assert!(peer.paste(HINT).is_none());
        assert!(!peer.targets().contains(&peer.atom(HINT)));
    }

    #[test]
    fn x11_another_clients_copy_ends_the_claim_and_the_clear_never_touches_it() {
        let Some(server) = Xvfb::start() else {
            return;
        };
        let (mut board, served) = server.board();
        let peer = server.peer();
        let copied = board.write_concealed(VALUE).expect("Apassy owns CLIPBOARD");
        assert!(served.current().is_some());
        peer.copy();
        // SelectionClear reaches Apassy: it stops serving the value at once.
        wait_until("SelectionClear ends the claim", || {
            served.current().is_none()
        });
        assert_eq!(peer.owner(), peer.window);
        board.clear_if_unchanged(&copied).unwrap();
        assert_eq!(
            peer.owner(),
            peer.window,
            "the clear left the other copy alone"
        );
        assert!(served.current().is_none());

        // A new copy takes the clipboard again and serves only the new value.
        let again = board.write_concealed("synthetic-second-value").unwrap();
        assert_ne!(peer.owner(), peer.window);
        assert_eq!(peer.text().as_deref(), Some(&b"synthetic-second-value"[..]));
        board.clear_if_unchanged(&again).unwrap();
        assert_eq!(peer.text(), Some(Vec::new()));
    }

    #[test]
    fn x11_a_value_above_the_limit_never_takes_the_clipboard() {
        let Some(server) = Xvfb::start() else {
            return;
        };
        let (mut board, served) = server.board();
        let peer = server.peer();
        peer.copy();
        let big = "x".repeat(super::MAX_VALUE + 1);
        assert!(board.write_concealed(&big).is_err());
        assert_eq!(peer.owner(), peer.window);
        assert!(served.current().is_none());
    }
}
