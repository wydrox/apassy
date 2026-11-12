use crate::connection::Connection;
use std::io;
use std::net::{Shutdown, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

/// Apassy (connect keep-alive): sequential requests on the connections of a listener that
/// the server allows them on (`Server::http_with_deadlines_and_keep_alive`).
pub(crate) struct Keep {
    /// The longest wait for the first byte of the next request head.
    pub(crate) idle: Duration,
    /// Asked with the client's address and the listener's address when an answer is
    /// about to be written.
    pub(crate) allow: Arc<dyn Fn(SocketAddr, SocketAddr) -> bool + Send + Sync>,
    /// The listener's address.
    pub(crate) listen: SocketAddr,
}

/// The longest time that the reaper gives a kept connection past its idle wait.
const IDLE_SLACK: Duration = Duration::from_secs(5);

pub(crate) struct Deadline {
    socket: Connection,
    read_until: Mutex<Instant>,
    header: Duration,
    body: Duration,
    handle: Duration,
    /// Apassy: the reaper closes the transport at this time. One request's handle
    /// deadline from its first byte; on a kept connection, between two requests, the
    /// idle wait.
    handle_until: Mutex<Instant>,
    /// Apassy (connect-tunnel-v1): set by `Request::upgrade_split`. The request deadlines
    /// end; reads and writes keep this idle limit, and the reaper forgets the transport.
    released: Mutex<Option<Duration>>,
    /// Apassy: `Some` on a listener with sequential requests.
    keep: Option<Keep>,
    /// Apassy: the answer of the last request was written whole and keeps the
    /// connection open: the connection waits for the next request head.
    again: AtomicBool,
}
impl Deadline {
    pub(crate) fn new(
        socket: Connection,
        header: Duration,
        body: Duration,
        handle: Duration,
        keep: Option<Keep>,
    ) -> Arc<Self> {
        let now = Instant::now();
        Arc::new(Self {
            socket,
            read_until: Mutex::new(now + header),
            header,
            body,
            handle,
            handle_until: Mutex::new(now + handle),
            released: Mutex::new(None),
            keep,
            again: AtomicBool::new(false),
        })
    }
    pub(crate) fn body(&self) {
        *self.read_until.lock().unwrap() = Instant::now() + self.body;
    }
    /// Apassy: the time at which the reaper closes the transport.
    pub(crate) fn handle_until(&self) -> Instant {
        *self.handle_until.lock().unwrap()
    }
    /// Apassy: this connection may carry sequential requests, if the server allows them.
    pub(crate) fn keeps(&self) -> bool {
        self.keep.is_some()
    }
    /// Apassy: the server allows the connection of `remote` to stay open after an answer.
    pub(crate) fn allows(&self, remote: Option<SocketAddr>) -> bool {
        match (&self.keep, remote) {
            (Some(keep), Some(remote)) => (keep.allow)(remote, keep.listen),
            _ => false,
        }
    }
    /// Apassy: bytes (or the end of the stream) wait on the socket now. Read without
    /// blocking and without taking them; a socket that cannot tell counts as waiting.
    pub(crate) fn input_waiting(&self) -> bool {
        self.socket.input_waiting()
    }
    /// Apassy: the answer of the last request was written whole and keeps the
    /// connection open.
    pub(crate) fn answered_for_next(&self) {
        self.again.store(true, Ordering::SeqCst);
    }
    /// Apassy: whether the answer of the last request kept the connection open (once).
    pub(crate) fn take_again(&self) -> bool {
        self.again.swap(false, Ordering::SeqCst)
    }
    /// Apassy: between two requests of a kept connection, the first byte of the next
    /// head comes within the idle wait; the reaper closes the transport a little later.
    pub(crate) fn idle_wait(&self) {
        let idle = self.keep.as_ref().map_or(self.header, |keep| keep.idle);
        let now = Instant::now();
        *self.read_until.lock().unwrap() = now + idle;
        *self.handle_until.lock().unwrap() = now + idle + IDLE_SLACK;
    }
    /// Apassy: the read deadline passed.
    pub(crate) fn expired(&self) -> bool {
        Instant::now() >= *self.read_until.lock().unwrap()
    }
    /// Apassy: the first byte of the next request of a kept connection came: it has the
    /// header, body, and handle deadlines of a new connection, from now.
    pub(crate) fn next_request(&self) {
        let now = Instant::now();
        *self.read_until.lock().unwrap() = now + self.header;
        *self.handle_until.lock().unwrap() = now + self.handle;
    }
    /// Apassy: ends the header/body/handle deadlines of an upgraded transport. Reads and
    /// writes then fail after `idle` without progress; the owner closes it with `close`.
    pub(crate) fn release(&self, idle: Duration) {
        *self.released.lock().unwrap() = Some(idle);
        let _ = self.socket.read_timeout(idle);
        let _ = self.socket.set_write_timeout(idle);
    }
    pub(crate) fn released(&self) -> bool {
        self.released.lock().unwrap().is_some()
    }
    pub(crate) fn before_read(&self) -> io::Result<()> {
        if let Some(idle) = *self.released.lock().unwrap() {
            return self.socket.read_timeout(idle);
        }
        let left = self
            .read_until
            .lock()
            .unwrap()
            .saturating_duration_since(Instant::now());
        if left.is_zero() {
            self.close(Shutdown::Read);
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "request read deadline",
            ));
        }
        self.socket.read_timeout(left.min(Duration::from_secs(5)))
    }
    pub(crate) fn close(&self, how: Shutdown) {
        // Some platforms reject SHUT_RDWR once the read half was closed after
        // an empty body. Close each half independently so writes still cancel.
        if matches!(how, Shutdown::Write | Shutdown::Both) {
            let _ = self.socket.shutdown(Shutdown::Write);
        }
        if matches!(how, Shutdown::Read | Shutdown::Both) {
            let _ = self.socket.shutdown(Shutdown::Read);
        }
    }
}

pub(crate) type Reaper = Arc<Mutex<Vec<Weak<Deadline>>>>;
pub(crate) fn reaper(stop: Arc<std::sync::atomic::AtomicBool>) -> Reaper {
    let entries: Reaper = Arc::new(Mutex::new(Vec::new()));
    let work = entries.clone();
    std::thread::spawn(move || {
        while !stop.load(std::sync::atomic::Ordering::Relaxed) {
            work.lock().unwrap().retain(|weak| {
                if let Some(socket) = weak.upgrade() {
                    if socket.released() {
                        // Apassy: an upgraded transport has its own limits.
                        false
                    } else if Instant::now() >= socket.handle_until() {
                        socket.close(Shutdown::Both);
                        false
                    } else {
                        true
                    }
                } else {
                    false
                }
            });
            std::thread::sleep(Duration::from_millis(50));
        }
        for weak in work.lock().unwrap().drain(..) {
            if let Some(socket) = weak.upgrade() {
                socket.close(Shutdown::Both);
            }
        }
    });
    entries
}
