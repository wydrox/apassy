//! Wayland clipboard ownership through ext-data-control-v1, or wlr-data-control on
//! older wlroots and KWin, on Apassy's own connection (no unsafe, no shared winit
//! queue). The core `wl_data_device` needs keyboard focus and an input serial, and it
//! has no way to give the clipboard up only while it is still Apassy's; data-control
//! has both: a `cancelled` event when another client replaces the source, and a new
//! source that Apassy sets itself. Mutter (GNOME) offers no data-control
//! (mutter issue 524), so GNOME uses the X11 path through XWayland.
//!
//! A source is used once (protocol rule). A paste gets the value through a
//! non-blocking write with a deadline, so a reader that never reads cannot stall
//! Apassy. Apassy never receives another client's offer. Nothing here logs a value.

use std::collections::HashSet;
use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
use rustix::io::Errno;
use wayland_client::backend::WaylandError;
use wayland_client::globals::{GlobalListContents, registry_queue_init};
use wayland_client::protocol::{wl_registry, wl_seat};
use wayland_client::{Connection, Dispatch, EventQueue, QueueHandle, event_created_child};
use wayland_protocols::ext::data_control::v1::client::{
    ext_data_control_device_v1 as ext_device, ext_data_control_manager_v1 as ext_manager,
    ext_data_control_offer_v1 as ext_offer, ext_data_control_source_v1 as ext_source,
};
use wayland_protocols_wlr::data_control::v1::client::{
    zwlr_data_control_device_v1 as wlr_device, zwlr_data_control_manager_v1 as wlr_manager,
    zwlr_data_control_offer_v1 as wlr_offer, zwlr_data_control_source_v1 as wlr_source,
};

use super::PasteboardError;
use super::linux::{Display, PASSWORD_HINT, Served, Want, WaylandProbe};

/// How long the UI waits for the clipboard thread.
const TIMEOUT: Duration = Duration::from_secs(3);
/// How long one paste may take to read the value.
const WRITE_TIMEOUT: Duration = Duration::from_secs(1);
/// How often the clipboard thread looks for commands while it waits for events.
const TICK: Timespec = Timespec {
    tv_sec: 0,
    tv_nsec: 50_000_000,
};
/// The text types Apassy offers, as wl-clipboard and GTK do.
const TEXT_MIMES: [&str; 3] = ["text/plain;charset=utf-8", "text/plain", "UTF8_STRING"];

enum Command {
    Claim(u64, Sender<bool>),
    Sync(Sender<bool>),
    Replace(u64, u64, Sender<bool>),
}

pub(super) struct WaylandDisplay {
    commands: Sender<Command>,
}

impl WaylandDisplay {
    /// Connect to `$WAYLAND_DISPLAY`, find a data-control manager and the seat, and start
    /// the clipboard thread.
    #[cfg(not(test))]
    pub(super) fn open(served: Arc<Served>) -> Result<Self, WaylandProbe> {
        let conn = Connection::connect_to_env().map_err(|_| WaylandProbe::Failed)?;
        Self::open_with(served, conn)
    }

    /// [`WaylandDisplay::open`] on the connection `conn`.
    fn open_with(served: Arc<Served>, conn: Connection) -> Result<Self, WaylandProbe> {
        let (globals, mut queue) =
            registry_queue_init::<State>(&conn).map_err(|_| WaylandProbe::Failed)?;
        let qh = queue.handle();
        let control = if let Ok(manager) =
            globals.bind::<ext_manager::ExtDataControlManagerV1, _, _>(&qh, 1..=1, ())
        {
            let seat = globals
                .bind::<wl_seat::WlSeat, _, _>(&qh, 1..=1, ())
                .map_err(|_| WaylandProbe::Failed)?;
            let device = manager.get_data_device(&seat, &qh, ());
            Control::Ext { manager, device }
        } else if let Ok(manager) =
            globals.bind::<wlr_manager::ZwlrDataControlManagerV1, _, _>(&qh, 1..=1, ())
        {
            let seat = globals
                .bind::<wl_seat::WlSeat, _, _>(&qh, 1..=1, ())
                .map_err(|_| WaylandProbe::Failed)?;
            let device = manager.get_data_device(&seat, &qh, ());
            Control::Wlr { manager, device }
        } else {
            return Err(WaylandProbe::NoControl);
        };
        let mut state = State {
            served,
            live: HashSet::new(),
            offer: None,
            finished: false,
        };
        queue
            .roundtrip(&mut state)
            .map_err(|_| WaylandProbe::Failed)?;
        if state.finished {
            return Err(WaylandProbe::Failed);
        }
        let (commands, inbox) = mpsc::channel();
        let worker = Worker {
            _conn: conn,
            queue,
            qh,
            state,
            control,
            inbox,
            dead: false,
        };
        std::thread::Builder::new()
            .name("apassy-clipboard-wayland".into())
            .spawn(move || worker.run())
            .map_err(|_| WaylandProbe::Failed)?;
        Ok(Self { commands })
    }

    fn ask(&self, command: impl FnOnce(Sender<bool>) -> Command) -> Result<(), PasteboardError> {
        let (reply, answer) = mpsc::channel();
        self.commands
            .send(command(reply))
            .map_err(|_| PasteboardError)?;
        match answer.recv_timeout(TIMEOUT) {
            Ok(true) => Ok(()),
            _ => Err(PasteboardError),
        }
    }
}

impl Display for WaylandDisplay {
    fn claim(&mut self, generation: u64) -> Result<(), PasteboardError> {
        self.ask(|reply| Command::Claim(generation, reply))
    }

    fn sync(&mut self) -> Result<(), PasteboardError> {
        self.ask(Command::Sync)
    }

    fn replace(&mut self, previous: u64, blank: u64) -> Result<(), PasteboardError> {
        self.ask(|reply| Command::Replace(previous, blank, reply))
    }
}

/// The data-control manager and the device of the seat, in one of the two protocols.
enum Control {
    Ext {
        manager: ext_manager::ExtDataControlManagerV1,
        device: ext_device::ExtDataControlDeviceV1,
    },
    Wlr {
        manager: wlr_manager::ZwlrDataControlManagerV1,
        device: wlr_device::ZwlrDataControlDeviceV1,
    },
}

impl Control {
    /// A new source for the claim `generation`, offered and set as the selection.
    fn set(&self, qh: &QueueHandle<State>, generation: u64, secret: bool) {
        let mimes = TEXT_MIMES
            .iter()
            .copied()
            .chain(secret.then_some(PASSWORD_HINT));
        match self {
            Self::Ext { manager, device } => {
                let source = manager.create_data_source(qh, generation);
                for mime in mimes {
                    source.offer(mime.to_owned());
                }
                device.set_selection(Some(&source));
            }
            Self::Wlr { manager, device } => {
                let source = manager.create_data_source(qh, generation);
                for mime in mimes {
                    source.offer(mime.to_owned());
                }
                device.set_selection(Some(&source));
            }
        }
    }
}

/// The last selection offer, kept only to destroy it. Apassy never reads it.
enum Offer {
    Ext(ext_offer::ExtDataControlOfferV1),
    Wlr(wlr_offer::ZwlrDataControlOfferV1),
}

impl Offer {
    fn destroy(self) {
        match self {
            Self::Ext(offer) => offer.destroy(),
            Self::Wlr(offer) => offer.destroy(),
        }
    }
}

struct State {
    served: Arc<Served>,
    /// Apassy's sources that the compositor has not cancelled.
    live: HashSet<u64>,
    offer: Option<Offer>,
    /// The compositor ended the data device.
    finished: bool,
}

impl State {
    fn selection(&mut self, offer: Option<Offer>) {
        if let Some(old) = std::mem::replace(&mut self.offer, offer) {
            old.destroy();
        }
    }

    fn cancelled(&mut self, generation: u64) {
        self.live.remove(&generation);
        self.served.lost(generation);
    }

    fn finish(&mut self) {
        self.finished = true;
        self.live.clear();
        self.served.lost_all();
    }

    fn send(&self, generation: u64, mime: &str, fd: OwnedFd) {
        let Some(want) = Want::of_mime(mime) else {
            return;
        };
        if let Some(bytes) = self.served.serve(generation, want) {
            deliver(&fd, &bytes);
        }
        // `fd` closes here: the reader sees the end of the value, or nothing.
    }
}

/// Write `bytes` without blocking past [`WRITE_TIMEOUT`].
fn deliver(fd: &OwnedFd, bytes: &[u8]) {
    let Ok(flags) = fcntl_getfl(fd) else {
        return;
    };
    if fcntl_setfl(fd, flags | OFlags::NONBLOCK).is_err() {
        return;
    }
    let deadline = Instant::now() + WRITE_TIMEOUT;
    let mut rest = bytes;
    while !rest.is_empty() {
        match rustix::io::write(fd, rest) {
            Ok(0) => return,
            Ok(written) => rest = &rest[written..],
            Err(Errno::INTR) => {}
            Err(Errno::AGAIN) => {
                let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                    return;
                };
                let wait = Timespec {
                    tv_sec: 0,
                    tv_nsec: i64::from(left.min(Duration::from_millis(100)).subsec_nanos()),
                };
                let mut fds = [PollFd::new(fd, PollFlags::OUT)];
                if poll(&mut fds, Some(&wait)).is_err() {
                    return;
                }
            }
            Err(_) => return,
        }
    }
}

struct Worker {
    _conn: Connection,
    queue: EventQueue<State>,
    qh: QueueHandle<State>,
    state: State,
    control: Control,
    inbox: Receiver<Command>,
    dead: bool,
}

impl Worker {
    fn run(mut self) {
        loop {
            if self.dead {
                // The connection ended: refuse every command, without spinning.
                match self.inbox.recv() {
                    Ok(command) => answer(command, false),
                    Err(_) => return,
                }
                continue;
            }
            loop {
                match self.inbox.try_recv() {
                    Ok(command) => self.handle(command),
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => return,
                }
            }
            if self.step().is_err() {
                self.dead = true;
                self.state.finish();
            }
        }
    }

    /// Read and dispatch what the compositor sent, waiting at most one tick.
    fn step(&mut self) -> Result<(), ()> {
        self.queue.dispatch_pending(&mut self.state).map_err(drop)?;
        match self.queue.flush() {
            Ok(()) => {}
            Err(WaylandError::Io(err)) if err.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => return Err(()),
        }
        if let Some(guard) = self.queue.prepare_read() {
            let readable = {
                let fd = guard.connection_fd();
                let mut fds = [PollFd::new(&fd, PollFlags::IN)];
                matches!(poll(&mut fds, Some(&TICK)), Ok(ready) if ready > 0)
            };
            if readable {
                match guard.read() {
                    Ok(_) => {}
                    Err(WaylandError::Io(err)) if err.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => return Err(()),
                }
            }
        }
        self.queue.dispatch_pending(&mut self.state).map_err(drop)?;
        Ok(())
    }

    fn roundtrip(&mut self) -> bool {
        let done = self.queue.roundtrip(&mut self.state).is_ok();
        if !done {
            self.dead = true;
            self.state.finish();
        }
        done && !self.state.finished
    }

    fn claim(&mut self, generation: u64) -> bool {
        let Some((current, secret)) = self.state.served.current() else {
            return false;
        };
        if current != generation || self.state.finished {
            return false;
        }
        self.control.set(&self.qh, generation, secret);
        self.state.live.insert(generation);
        // In order: a replacement by another client cancels the source before the
        // roundtrip ends.
        self.roundtrip() && self.state.live.contains(&generation)
    }

    fn handle(&mut self, command: Command) {
        match command {
            Command::Claim(generation, reply) => {
                let ok = self.claim(generation);
                let _ = reply.send(ok);
            }
            Command::Sync(reply) => {
                let ok = self.roundtrip();
                let _ = reply.send(ok);
            }
            Command::Replace(previous, blank, reply) => {
                let ok = if !self.roundtrip() {
                    false
                } else if self.state.live.contains(&previous) {
                    self.claim(blank)
                } else {
                    // Another client owns the clipboard: leave it alone.
                    self.state.served.lost(blank);
                    true
                };
                let _ = reply.send(ok);
            }
        }
    }
}

fn answer(command: Command, ok: bool) {
    let reply = match command {
        Command::Claim(_, reply) | Command::Sync(reply) | Command::Replace(_, _, reply) => reply,
    };
    let _ = reply.send(ok);
}

impl Dispatch<wl_registry::WlRegistry, GlobalListContents> for State {
    fn event(
        _: &mut Self,
        _: &wl_registry::WlRegistry,
        _: wl_registry::Event,
        _: &GlobalListContents,
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

impl Dispatch<wl_seat::WlSeat, ()> for State {
    fn event(
        _: &mut Self,
        _: &wl_seat::WlSeat,
        _: wl_seat::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

/// The same handling for both protocols, which have the same messages.
macro_rules! data_control {
    ($wrap:ident, $manager:ident::$manager_ty:ident, $device:ident::$device_ty:ident, $source:ident::$source_ty:ident, $offer:ident::$offer_ty:ident) => {
        impl Dispatch<$manager::$manager_ty, ()> for State {
            fn event(
                _: &mut Self,
                _: &$manager::$manager_ty,
                _: $manager::Event,
                _: &(),
                _: &Connection,
                _: &QueueHandle<Self>,
            ) {
            }
        }

        impl Dispatch<$device::$device_ty, ()> for State {
            fn event(
                state: &mut Self,
                device: &$device::$device_ty,
                event: $device::Event,
                _: &(),
                _: &Connection,
                _: &QueueHandle<Self>,
            ) {
                match event {
                    $device::Event::Selection { id } => state.selection(id.map(Offer::$wrap)),
                    $device::Event::PrimarySelection { id: Some(offer) } => offer.destroy(),
                    $device::Event::PrimarySelection { id: None } => {}
                    $device::Event::Finished => {
                        device.destroy();
                        state.finish();
                    }
                    // `data_offer` introduces the offer of the next selection event.
                    _ => {}
                }
            }

            event_created_child!(State, $device::$device_ty, [
                $device::EVT_DATA_OFFER_OPCODE => ($offer::$offer_ty, ()),
            ]);
        }

        impl Dispatch<$source::$source_ty, u64> for State {
            fn event(
                state: &mut Self,
                source: &$source::$source_ty,
                event: $source::Event,
                generation: &u64,
                _: &Connection,
                _: &QueueHandle<Self>,
            ) {
                match event {
                    $source::Event::Send { mime_type, fd } => state.send(*generation, &mime_type, fd),
                    $source::Event::Cancelled => {
                        source.destroy();
                        state.cancelled(*generation);
                    }
                    // The generated event enums are non-exhaustive.
                    _ => {}
                }
            }
        }

        /// Offered types of other clients are never read.
        impl Dispatch<$offer::$offer_ty, ()> for State {
            fn event(
                _: &mut Self,
                _: &$offer::$offer_ty,
                _: $offer::Event,
                _: &(),
                _: &Connection,
                _: &QueueHandle<Self>,
            ) {
            }
        }
    };
}

data_control!(
    Ext,
    ext_manager::ExtDataControlManagerV1,
    ext_device::ExtDataControlDeviceV1,
    ext_source::ExtDataControlSourceV1,
    ext_offer::ExtDataControlOfferV1
);
data_control!(
    Wlr,
    wlr_manager::ZwlrDataControlManagerV1,
    wlr_device::ZwlrDataControlDeviceV1,
    wlr_source::ZwlrDataControlSourceV1,
    wlr_offer::ZwlrDataControlOfferV1
);

/// The Wayland protocol against a real compositor: each test starts its own headless
/// sway (wlroots, wlr-data-control) in a private runtime directory, so the tests run
/// side by side and never touch the session's clipboard. The other client is
/// wl-clipboard (`wl-paste`, `wl-copy`) on that compositor. The linux-vault CI job
/// installs both and sets `APASSY_REQUIRE_WAYLAND=1`; elsewhere a missing sway or
/// wl-clipboard is a reported skip. Synthetic values only.
#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use wayland_client::Connection;

    use super::WaylandDisplay;
    use crate::desktop::clipboard::Pasteboard;
    use crate::desktop::clipboard::linux::{LinuxBoard, Served};

    const VALUE: &str = "synthetic-wayland-clipboard-value";
    const HINT: &str = "x-kde-passwordManagerHint";
    const TEXT: &str = "text/plain;charset=utf-8";
    const WAIT: Duration = Duration::from_secs(5);

    fn skip(why: &str) -> Option<Sway> {
        assert!(
            std::env::var_os("APASSY_REQUIRE_WAYLAND").is_none(),
            "APASSY_REQUIRE_WAYLAND is set, but {why}"
        );
        eprintln!("skipped: {why}");
        None
    }

    fn installed(program: &str) -> bool {
        Command::new(program)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }

    /// A private headless compositor for one test. Dropping it stops the compositor.
    struct Sway {
        child: Child,
        runtime: tempfile::TempDir,
        display: String,
    }

    impl Sway {
        fn start() -> Option<Self> {
            if !installed("sway") || !installed("wl-paste") {
                return skip("sway or wl-clipboard is not installed");
            }
            let runtime = tempfile::Builder::new().prefix("apw").tempdir().unwrap();
            let child = Command::new("sway")
                .args(["--config", "/dev/null"])
                .env("XDG_RUNTIME_DIR", runtime.path())
                .env("WLR_BACKENDS", "headless")
                .env("WLR_LIBINPUT_NO_DEVICES", "1")
                .env("WLR_RENDERER", "pixman")
                .env_remove("WAYLAND_DISPLAY")
                .env_remove("DISPLAY")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let mut sway = Self {
                child,
                runtime,
                display: String::new(),
            };
            let deadline = Instant::now() + WAIT;
            loop {
                let socket = std::fs::read_dir(sway.runtime.path())
                    .unwrap()
                    .filter_map(Result::ok)
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .find(|name| name.starts_with("wayland-") && !name.ends_with(".lock"));
                if let Some(name) = socket
                    && UnixStream::connect(sway.runtime.path().join(&name)).is_ok()
                {
                    sway.display = name;
                    return Some(sway);
                }
                if sway.child.try_wait().unwrap().is_some() || Instant::now() > deadline {
                    return skip("the headless sway did not start");
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }

        fn socket(&self) -> PathBuf {
            self.runtime.path().join(&self.display)
        }

        fn board(&self) -> (LinuxBoard<WaylandDisplay>, Arc<Served>) {
            let served = Arc::new(Served::default());
            let conn = Connection::from_socket(UnixStream::connect(self.socket()).unwrap())
                .expect("the Wayland display");
            let display = WaylandDisplay::open_with(served.clone(), conn)
                .unwrap_or_else(|probe| panic!("the Wayland display opens: {probe:?}"));
            (LinuxBoard::new(served.clone(), display), served)
        }

        /// A wl-clipboard program on this compositor.
        fn command(&self, program: &str) -> Command {
            let mut command = Command::new(program);
            command
                .env("XDG_RUNTIME_DIR", self.runtime.path())
                .env("WAYLAND_DISPLAY", &self.display)
                .env_remove("DISPLAY")
                .stdin(Stdio::null())
                .stderr(Stdio::null());
            command
        }

        /// `wl-paste ARGS` as another client: its output, or `None` when it found
        /// nothing to paste. A paste that hangs fails the test.
        fn paste(&self, args: &[&str]) -> Option<Vec<u8>> {
            let mut child = self
                .command("wl-paste")
                .args(args)
                .stdout(Stdio::piped())
                .spawn()
                .expect("wl-paste starts");
            let mut stdout = child.stdout.take().unwrap();
            let reader = std::thread::spawn(move || {
                let mut out = Vec::new();
                let _ = stdout.read_to_end(&mut out);
                out
            });
            let deadline = Instant::now() + WAIT;
            let status = loop {
                if let Some(status) = child.try_wait().unwrap() {
                    break status;
                }
                if Instant::now() > deadline {
                    let _ = child.kill();
                    panic!("wl-paste {args:?} did not end");
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            let out = reader.join().unwrap();
            status.success().then_some(out)
        }

        fn text(&self) -> Option<Vec<u8>> {
            self.paste(&["--no-newline", "--type", TEXT])
        }

        fn types(&self) -> Vec<String> {
            self.paste(&["--list-types"])
                .map(|out| {
                    String::from_utf8(out)
                        .unwrap()
                        .lines()
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default()
        }

        /// Another client's copy, served by `wl-copy` until it is replaced.
        fn foreign_copy(&self, value: &str) -> ForeignCopy {
            ForeignCopy(
                self.command("wl-copy")
                    .args(["--foreground", "--type", TEXT, value])
                    .stdout(Stdio::null())
                    .spawn()
                    .expect("wl-copy starts"),
            )
        }
    }

    impl Drop for Sway {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    struct ForeignCopy(Child);

    impl Drop for ForeignCopy {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
        let deadline = Instant::now() + WAIT;
        while !done() {
            assert!(Instant::now() < deadline, "timed out: {what}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn wayland_a_copy_is_served_with_the_hint_and_the_clear_leaves_an_empty_own_copy() {
        let Some(sway) = Sway::start() else {
            return;
        };
        let (mut board, served) = sway.board();
        let copied = board
            .write_concealed(VALUE)
            .expect("Apassy owns the clipboard");
        assert!(served.current().is_some());
        assert_eq!(sway.text().as_deref(), Some(VALUE.as_bytes()));
        let offered = sway.types();
        for mime in [TEXT, "text/plain", "UTF8_STRING", HINT] {
            assert!(offered.iter().any(|t| t == mime), "{mime} in {offered:?}");
        }
        assert_eq!(
            sway.paste(&["--no-newline", "--type", HINT]).as_deref(),
            Some(&b"secret"[..])
        );
        // A type that Apassy does not offer gets nothing.
        assert!(
            sway.paste(&["--no-newline", "--type", "image/png"])
                .is_none()
        );

        board.clear_if_unchanged(&copied).unwrap();
        // Still Apassy's clipboard, now empty and without the hint.
        assert_eq!(sway.text(), Some(Vec::new()));
        let offered = sway.types();
        assert!(offered.iter().any(|t| t == TEXT), "{offered:?}");
        assert!(!offered.iter().any(|t| t == HINT), "{offered:?}");
    }

    #[test]
    fn wayland_another_clients_copy_ends_the_claim_and_the_clear_never_touches_it() {
        let Some(sway) = Sway::start() else {
            return;
        };
        let (mut board, served) = sway.board();
        let copied = board
            .write_concealed(VALUE)
            .expect("Apassy owns the clipboard");
        let foreign = sway.foreign_copy("synthetic-foreign-value");
        // `cancelled` reaches Apassy: it stops serving the value at once.
        wait_until("cancelled ends the claim", || served.current().is_none());
        board.clear_if_unchanged(&copied).unwrap();
        assert_eq!(
            sway.text().as_deref(),
            Some(&b"synthetic-foreign-value"[..]),
            "the clear left the other copy alone"
        );
        assert!(served.current().is_none());

        // A new copy takes the clipboard again and serves only the new value.
        let again = board.write_concealed("synthetic-second-value").unwrap();
        assert_eq!(sway.text().as_deref(), Some(&b"synthetic-second-value"[..]));
        drop(foreign);
        board.clear_if_unchanged(&again).unwrap();
        assert_eq!(sway.text(), Some(Vec::new()));
    }
}
