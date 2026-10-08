//! The owner socket of the desktop app (ADR 0017), and the browser socket (ADR 0021).
//!
//! A thread accepts connections on the socket. Each connection has one request. The
//! thread hands the request to the UI thread and waits for the response: the UI thread
//! owns the vault session, the owner check dialog, and the command-line sessions. The
//! socket directory has mode `0700`, and the socket has mode `0600`. There is no
//! peer-credential check (ADR 0010).
//!
//! [`LineWire`] names the request and the response of one socket. Both sockets have one
//! line of JSON in each direction.

use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde::Serialize;
use zeroize::{Zeroize, Zeroizing};

use crate::broker::server::{prepare_directory, remove_stale_socket};
use crate::owner::wire::{MAX_REQUEST_BYTES, Request, Response};

const IO_TIMEOUT: Duration = Duration::from_secs(30);
const ACCEPT_POLL: Duration = Duration::from_millis(50);
/// Touch ID waits up to 180 s. The client waits 240 s.
pub(crate) const REPLY_TIMEOUT: Duration = Duration::from_secs(230);

/// The request and the response of one socket.
pub(crate) trait LineWire: 'static {
    type Request: Send + 'static;
    type Response: Serialize + Send + 'static;
    /// The middle of the thread names, for example `owner`.
    const NAME: &'static str;
    const MAX_REQUEST_BYTES: usize;
    const MAX_CONNECTIONS: usize;
    /// The answer when all connections are in use.
    const BUSY: &'static str;

    /// Parse one request line. An error is the response to send.
    fn parse(line: &[u8]) -> Result<Self::Request, Self::Response>;
    fn error(code: &'static str, message: &'static str) -> Self::Response;
}

/// The owner wire (ADR 0017).
pub(crate) struct OwnerWire;

impl LineWire for OwnerWire {
    type Request = Request;
    type Response = Response;
    const NAME: &'static str = "owner";
    const MAX_REQUEST_BYTES: usize = MAX_REQUEST_BYTES;
    const MAX_CONNECTIONS: usize = 8;
    const BUSY: &'static str = "Apassy has too many command-line connections.";

    fn parse(line: &[u8]) -> Result<Request, Response> {
        serde_json::from_slice::<Request>(line).map_err(|_| {
            Response::error("bad_request", "The request is not valid owner wire JSON.")
        })
    }

    fn error(code: &'static str, message: &'static str) -> Response {
        Response::error(code, message)
    }
}

/// One request for the UI thread, with the way back to its connection.
pub(crate) struct Envelope<Req = Request, Resp = Response> {
    pub(crate) request: Req,
    pub(crate) reply: Sender<Resp>,
}

/// The envelope of a request on the socket of `W`.
pub(crate) type WireEnvelope<W> = Envelope<<W as LineWire>::Request, <W as LineWire>::Response>;

/// The running owner socket. Drop stops the accept loop and removes the socket file.
pub(crate) struct OwnerSocket {
    socket: PathBuf,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for OwnerSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnerSocket")
            .field("socket", &self.socket)
            .finish_non_exhaustive()
    }
}

impl OwnerSocket {
    pub(crate) fn socket_path(&self) -> &Path {
        &self.socket
    }

    pub(crate) fn stop(&mut self) {
        if self.stop.swap(true, Ordering::SeqCst) {
            return;
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = fs::remove_file(&self.socket);
    }
}

impl Drop for OwnerSocket {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Start the owner socket. Requests go to the returned receiver. `wake` tells the UI
/// thread that a request waits, also when the window is hidden.
pub(crate) fn start(
    socket: &Path,
    wake: impl Fn() + Send + Sync + 'static,
) -> io::Result<(OwnerSocket, Receiver<Envelope>)> {
    start_line::<OwnerWire>(socket, wake)
}

/// Start the socket of `W`. Requests go to the returned receiver.
pub(crate) fn start_line<W: LineWire>(
    socket: &Path,
    wake: impl Fn() + Send + Sync + 'static,
) -> io::Result<(OwnerSocket, Receiver<WireEnvelope<W>>)> {
    prepare_directory(socket)?;
    remove_stale_socket(socket)?;
    let listener = UnixListener::bind(socket)?;
    fs::set_permissions(socket, fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    let (sender, inbox) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let wake: Arc<dyn Fn() + Send + Sync> = Arc::new(wake);
    let thread = thread::Builder::new()
        .name(format!("apassy-{}-socket", W::NAME))
        .spawn(move || accept_loop::<W>(&listener, &sender, &wake, &thread_stop))?;
    Ok((
        OwnerSocket {
            socket: socket.to_path_buf(),
            stop,
            thread: Some(thread),
        },
        inbox,
    ))
}

fn accept_loop<W: LineWire>(
    listener: &UnixListener,
    sender: &Sender<WireEnvelope<W>>,
    wake: &Arc<dyn Fn() + Send + Sync>,
    stop: &AtomicBool,
) {
    let active = Arc::new(AtomicUsize::new(0));
    while !stop.load(Ordering::SeqCst) {
        let stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(_) => {
                thread::sleep(ACCEPT_POLL);
                continue;
            }
        };
        if stream.set_nonblocking(false).is_err() {
            continue;
        }
        if active.fetch_add(1, Ordering::SeqCst) >= W::MAX_CONNECTIONS {
            active.fetch_sub(1, Ordering::SeqCst);
            let mut stream = stream;
            let _ = write_response(&mut stream, &W::error("busy", W::BUSY));
            continue;
        }
        let sender = sender.clone();
        let wake = Arc::clone(wake);
        let slot = Arc::clone(&active);
        let spawned = thread::Builder::new()
            .name(format!("apassy-{}-conn", W::NAME))
            .spawn(move || {
                let _ = serve::<W>(stream, &sender, &*wake);
                slot.fetch_sub(1, Ordering::SeqCst);
            });
        if spawned.is_err() {
            active.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

fn serve<W: LineWire>(
    stream: UnixStream,
    sender: &Sender<WireEnvelope<W>>,
    wake: &dyn Fn(),
) -> io::Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);
    // The line can hold a session token, a passphrase, or item secrets.
    let mut line = Zeroizing::new(Vec::new());
    (&mut reader)
        .take(W::MAX_REQUEST_BYTES as u64)
        .read_until(b'\n', &mut line)?;
    if line.last() != Some(&b'\n') {
        return write_response(
            &mut writer,
            &W::error("bad_request", "The request is too long or incomplete."),
        );
    }
    let parsed = W::parse(&line);
    line.zeroize();
    let request = match parsed {
        Ok(request) => request,
        Err(response) => return write_response(&mut writer, &response),
    };
    let response = ask_ui::<W>(sender, wake, request);
    write_response(&mut writer, &response)
}

/// Hand the request to the UI thread and wait for its response.
fn ask_ui<W: LineWire>(
    sender: &Sender<WireEnvelope<W>>,
    wake: &dyn Fn(),
    request: W::Request,
) -> W::Response {
    let (reply, answer) = mpsc::channel();
    if sender.send(Envelope { request, reply }).is_err() {
        return W::error("stopped", "Apassy is stopping. Nothing changed.");
    }
    wake();
    match answer.recv_timeout(REPLY_TIMEOUT) {
        Ok(response) => response,
        Err(RecvTimeoutError::Timeout) => W::error(
            "timeout",
            "Apassy did not answer in time. If an owner check is open, it can still finish in the app.",
        ),
        Err(RecvTimeoutError::Disconnected) => W::error(
            "stopped",
            "Apassy stopped before it answered. Nothing changed.",
        ),
    }
}

/// A response buffer starts with this size, so a response with a secret does not move
/// to a larger allocation and leave a copy behind. A larger response is not secret.
const RESPONSE_CAPACITY: usize = 256 * 1024;

fn write_response(stream: &mut UnixStream, response: &impl Serialize) -> io::Result<()> {
    // The response can hold a new token, or the password of a fill.
    let mut bytes = Zeroizing::new(Vec::with_capacity(RESPONSE_CAPACITY));
    serde_json::to_writer(&mut *bytes, response).map_err(io::Error::other)?;
    bytes.push(b'\n');
    stream.write_all(&bytes)?;
    stream.flush()
}
