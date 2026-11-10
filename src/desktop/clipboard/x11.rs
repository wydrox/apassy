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
    pub(super) fn open(served: Arc<Served>) -> Result<Self, PasteboardError> {
        let (conn, screen) = x11rb::connect(None).map_err(fail)?;
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
