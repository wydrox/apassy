//! The owner socket of the desktop app (ADR 0017).
//!
//! A thread accepts connections on `owner.sock`. Each connection has one request. The
//! thread hands the request to the UI thread and waits for the response: the UI thread
//! owns the vault session, the owner check dialog, and the command-line sessions. The
//! socket directory has mode `0700`, and the socket has mode `0600`. There is no
//! peer-credential check (ADR 0010).

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

use zeroize::{Zeroize, Zeroizing};

use crate::broker::server::{prepare_directory, remove_stale_socket};
use crate::owner::wire::{MAX_REQUEST_BYTES, Request, Response};

const MAX_CONNECTIONS: usize = 8;
const IO_TIMEOUT: Duration = Duration::from_secs(30);
const ACCEPT_POLL: Duration = Duration::from_millis(50);
/// Touch ID waits up to 180 s. The client waits 240 s.
const REPLY_TIMEOUT: Duration = Duration::from_secs(230);

/// One request for the UI thread, with the way back to its connection.
pub(crate) struct Envelope {
    pub(crate) request: Request,
    pub(crate) reply: Sender<Response>,
}

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
        .name("apassy-owner-socket".to_owned())
        .spawn(move || accept_loop(&listener, &sender, &wake, &thread_stop))?;
    Ok((
        OwnerSocket {
            socket: socket.to_path_buf(),
            stop,
            thread: Some(thread),
        },
        inbox,
    ))
}

fn accept_loop(
    listener: &UnixListener,
    sender: &Sender<Envelope>,
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
        if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            active.fetch_sub(1, Ordering::SeqCst);
            let mut stream = stream;
            let _ = write_response(
                &mut stream,
                &Response::error("busy", "Apassy has too many command-line connections."),
            );
            continue;
        }
        let sender = sender.clone();
        let wake = Arc::clone(wake);
        let slot = Arc::clone(&active);
        let spawned = thread::Builder::new()
            .name("apassy-owner-conn".to_owned())
            .spawn(move || {
                let _ = serve(stream, &sender, &*wake);
                slot.fetch_sub(1, Ordering::SeqCst);
            });
        if spawned.is_err() {
            active.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

fn serve(stream: UnixStream, sender: &Sender<Envelope>, wake: &dyn Fn()) -> io::Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);
    // The line can hold a session token, a passphrase, or item secrets.
    let mut line = Zeroizing::new(Vec::new());
    (&mut reader)
        .take(MAX_REQUEST_BYTES as u64)
        .read_until(b'\n', &mut line)?;
    if line.last() != Some(&b'\n') {
        return write_response(
            &mut writer,
            &Response::error("bad_request", "The request is too long or incomplete."),
        );
    }
    let parsed = serde_json::from_slice::<Request>(&line);
    line.zeroize();
    let request = match parsed {
        Ok(request) => request,
        Err(_) => {
            return write_response(
                &mut writer,
                &Response::error("bad_request", "The request is not valid owner wire JSON."),
            );
        }
    };
    let response = ask_ui(sender, wake, request);
    write_response(&mut writer, &response)
}

/// Hand the request to the UI thread and wait for its response.
fn ask_ui(sender: &Sender<Envelope>, wake: &dyn Fn(), request: Request) -> Response {
    let (reply, answer) = mpsc::channel();
    if sender.send(Envelope { request, reply }).is_err() {
        return Response::error("stopped", "Apassy is stopping. Nothing changed.");
    }
    wake();
    match answer.recv_timeout(REPLY_TIMEOUT) {
        Ok(response) => response,
        Err(RecvTimeoutError::Timeout) => Response::error(
            "timeout",
            "Apassy did not answer in time. If an owner check is open, it can still finish in the app.",
        ),
        Err(RecvTimeoutError::Disconnected) => Response::error(
            "stopped",
            "Apassy stopped before it answered. Nothing changed.",
        ),
    }
}

fn write_response(stream: &mut UnixStream, response: &Response) -> io::Result<()> {
    // The response can hold a new token.
    let mut bytes = Zeroizing::new(serde_json::to_vec(response).map_err(io::Error::other)?);
    bytes.push(b'\n');
    stream.write_all(&bytes)?;
    stream.flush()
}
