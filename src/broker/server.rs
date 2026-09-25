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

use super::SharedVault;
use super::approvals::ApprovalQueue;
use super::bouncer::BouncerClient;
use super::decide::{self, BrokerContext};
use super::http::TlsClient;
use crate::agent::wire::{MAX_LINE_BYTES, WireRequest, WireResponse};

const MAX_CONNECTIONS: usize = 16;
const MAX_REQUESTS_PER_CONNECTION: usize = 64;
const IO_TIMEOUT: Duration = Duration::from_secs(30);
const ACCEPT_POLL: Duration = Duration::from_millis(50);

/// Broker settings. [`BrokerOptions::platform`] gives the desktop defaults.
#[derive(Debug, Clone)]
pub struct BrokerOptions {
    pub tls: TlsClient,
    pub approval_timeout: Duration,
    pub run_timeout: Duration,
    pub bouncer: Option<BouncerClient>,
}

impl BrokerOptions {
    /// macOS trust store, 120 s for an owner decision, 300 s for a process, and the
    /// bouncer at `APASSY_BOUNCER_URL` or the default local address.
    pub fn platform() -> io::Result<Self> {
        let mut options = Self::with_tls(TlsClient::platform()?);
        options.bouncer = BouncerClient::from_env().ok();
        Ok(options)
    }

    pub fn with_tls(tls: TlsClient) -> Self {
        Self {
            tls,
            approval_timeout: Duration::from_secs(120),
            run_timeout: Duration::from_secs(300),
            bouncer: None,
        }
    }
}

/// Running broker. Drop stops the accept loop and removes the socket file.
#[derive(Debug)]
pub struct BrokerHandle {
    socket: PathBuf,
    approvals: Arc<ApprovalQueue>,
    bouncer_url: Option<String>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl BrokerHandle {
    pub fn socket_path(&self) -> &Path {
        &self.socket
    }

    /// Runs that wait for the owner. The desktop app shows them.
    pub fn approvals(&self) -> &Arc<ApprovalQueue> {
        &self.approvals
    }

    /// Address of the bouncer, if one is set.
    pub fn bouncer_url(&self) -> Option<&str> {
        self.bouncer_url.as_deref()
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

/// Start the broker on `socket` with the macOS trust store for TLS.
/// The parent directory is created with mode `0700` if absent.
pub fn start(vault: SharedVault, socket: &Path) -> io::Result<BrokerHandle> {
    start_with(vault, socket, BrokerOptions::platform()?)
}

/// Start the broker with a specific TLS client and default timeouts.
pub fn start_with_tls(
    vault: SharedVault,
    socket: &Path,
    tls: TlsClient,
) -> io::Result<BrokerHandle> {
    start_with(vault, socket, BrokerOptions::with_tls(tls))
}

/// Start the broker with specific options. Tests use short timeouts.
pub fn start_with(
    vault: SharedVault,
    socket: &Path,
    options: BrokerOptions,
) -> io::Result<BrokerHandle> {
    let approvals = Arc::new(ApprovalQueue::new());
    let bouncer_url = options.bouncer.as_ref().map(|b| b.url().to_owned());
    let ctx = BrokerContext {
        vault,
        tls: options.tls,
        approvals: Arc::clone(&approvals),
        approval_timeout: options.approval_timeout,
        run_timeout: options.run_timeout,
        bouncer: options.bouncer,
    };
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
        .spawn(move || accept_loop(&listener, &ctx, &thread_stop, &active))?;
    Ok(BrokerHandle {
        socket: socket.to_path_buf(),
        approvals,
        bouncer_url,
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
    ctx: &BrokerContext,
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
        let ctx = ctx.clone();
        let slot = Arc::clone(active);
        let spawned = thread::Builder::new()
            .name("apassy-broker-conn".to_owned())
            .spawn(move || {
                let _ = serve_connection(stream, &ctx);
                slot.fetch_sub(1, Ordering::SeqCst);
            });
        if spawned.is_err() {
            // The closure did not run, so release its slot here.
            active.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

fn serve_connection(stream: UnixStream, ctx: &BrokerContext) -> io::Result<()> {
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
            Ok(request) => decide::handle(ctx, &request),
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
