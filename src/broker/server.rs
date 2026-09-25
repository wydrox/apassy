//! Unix socket server for agent requests.
//!
//! The socket directory must have mode `0700`. The socket has mode `0600`.
//! There is no peer-credential check in this phase (ADR 0004).

use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use super::{SharedVault, decide};
use crate::agent::wire::{MAX_LINE_BYTES, WireRequest, WireResponse};

const MAX_CONNECTIONS: usize = 16;
const MAX_REQUESTS_PER_CONNECTION: usize = 64;
const IO_TIMEOUT: Duration = Duration::from_secs(30);
const ACCEPT_POLL: Duration = Duration::from_millis(50);

/// Running broker. Drop stops the accept loop and removes the socket file.
#[derive(Debug)]
pub struct BrokerHandle {
    socket: PathBuf,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl BrokerHandle {
    pub fn socket_path(&self) -> &Path {
        &self.socket
    }

    pub fn stop(&mut self) {
        if self.stop.swap(true, Ordering::SeqCst) {
            return;
        }
        // The accept loop polls the stop flag. It does not need the socket path to exist.
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = fs::remove_file(&self.socket);
    }
}

impl Drop for BrokerHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Start the broker on `socket`. The parent directory is created with mode `0700` if absent.
pub fn start(vault: SharedVault, socket: &Path) -> io::Result<BrokerHandle> {
    prepare_directory(socket)?;
    remove_stale_socket(socket)?;
    let listener = UnixListener::bind(socket)?;
    fs::set_permissions(socket, fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    let stop = Arc::new(AtomicBool::new(false));
    let active = Arc::new(AtomicUsize::new(0));
    let thread_stop = Arc::clone(&stop);
    let thread = thread::Builder::new()
        .name("apassy-broker".to_owned())
        .spawn(move || accept_loop(&listener, &vault, &thread_stop, &active))?;
    Ok(BrokerHandle {
        socket: socket.to_path_buf(),
        stop,
        thread: Some(thread),
    })
}

fn prepare_directory(socket: &Path) -> io::Result<()> {
    let parent = socket
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no socket directory"))?;
    match fs::symlink_metadata(parent) {
        Ok(meta) => {
            if !meta.is_dir() || meta.file_type().is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "the socket directory is not a real directory",
                ));
            }
            if meta.permissions().mode() & 0o077 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "the socket directory must have mode 0700",
                ));
            }
            Ok(())
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(parent)?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
        }
        Err(err) => Err(err),
    }
}

fn remove_stale_socket(socket: &Path) -> io::Result<()> {
    match fs::symlink_metadata(socket) {
        Ok(meta) if meta.file_type().is_socket() => {
            if UnixStream::connect(socket).is_ok() {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "another Apassy broker uses this socket",
                ));
            }
            fs::remove_file(socket)
        }
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "a file that is not a socket is at the socket path",
        )),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

fn accept_loop(
    listener: &UnixListener,
    vault: &SharedVault,
    stop: &Arc<AtomicBool>,
    active: &Arc<AtomicUsize>,
) {
    while !stop.load(Ordering::SeqCst) {
        let stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(ACCEPT_POLL);
                continue;
            }
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
                &WireResponse::failure("busy", "The broker has too many connections."),
            );
            continue;
        }
        let vault = Arc::clone(vault);
        let slot = Arc::clone(active);
        let spawned = thread::Builder::new()
            .name("apassy-broker-conn".to_owned())
            .spawn(move || {
                let _ = serve_connection(stream, &vault);
                slot.fetch_sub(1, Ordering::SeqCst);
            });
        if spawned.is_err() {
            // The closure did not run, so release its slot here.
            active.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

fn serve_connection(stream: UnixStream, vault: &SharedVault) -> io::Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);
    for _ in 0..MAX_REQUESTS_PER_CONNECTION {
        let mut line = Vec::new();
        let read = (&mut reader)
            .take(MAX_LINE_BYTES as u64)
            .read_until(b'\n', &mut line)?;
        if read == 0 {
            return Ok(());
        }
        if line.last() != Some(&b'\n') {
            write_response(
                &mut writer,
                &WireResponse::failure(
                    "bad_request",
                    "The request line is too long or incomplete.",
                ),
            )?;
            return Ok(());
        }
        let response = match serde_json::from_slice::<WireRequest>(&line) {
            Ok(request) => decide::handle(vault, &request),
            Err(_) => WireResponse::failure(
                "bad_request",
                "The request is not valid wire version 0 JSON.",
            ),
        };
        line.fill(0);
        write_response(&mut writer, &response)?;
    }
    Ok(())
}

fn write_response(stream: &mut UnixStream, response: &WireResponse) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(response).map_err(io::Error::other)?;
    bytes.push(b'\n');
    stream.write_all(&bytes)?;
    stream.flush()
}
