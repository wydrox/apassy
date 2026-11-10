use crate::connection::Connection;
use std::io;
use std::net::Shutdown;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

pub(crate) struct Deadline {
    socket: Connection,
    read_until: Mutex<Instant>,
    body: Duration,
    /// Apassy (connect-tunnel-v1): set by `Request::upgrade_split`. The request deadlines
    /// end; reads and writes keep this idle limit, and the reaper forgets the transport.
    released: Mutex<Option<Duration>>,
}
impl Deadline {
    pub(crate) fn new(socket: Connection, header: Duration, body: Duration) -> Arc<Self> {
        Arc::new(Self {
            socket,
            read_until: Mutex::new(Instant::now() + header),
            body,
            released: Mutex::new(None),
        })
    }
    pub(crate) fn body(&self) {
        *self.read_until.lock().unwrap() = Instant::now() + self.body;
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

pub(crate) type Reaper = Arc<Mutex<Vec<(Weak<Deadline>, Instant)>>>;
pub(crate) fn reaper(stop: Arc<std::sync::atomic::AtomicBool>) -> Reaper {
    let entries: Reaper = Arc::new(Mutex::new(Vec::new()));
    let work = entries.clone();
    std::thread::spawn(move || {
        while !stop.load(std::sync::atomic::Ordering::Relaxed) {
            work.lock().unwrap().retain(|(weak, until)| {
                if let Some(socket) = weak.upgrade() {
                    if socket.released() {
                        // Apassy: an upgraded transport has its own limits.
                        false
                    } else if Instant::now() >= *until {
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
        for (weak, _) in work.lock().unwrap().drain(..) {
            if let Some(socket) = weak.upgrade() {
                socket.close(Shutdown::Both);
            }
        }
    });
    entries
}
