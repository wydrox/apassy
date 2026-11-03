//! The embedded Tailscale node of a team host (ADR 0037 D9; plan s4, decision 4 and T0).
//!
//! A [`TailnetNode`] is its own machine on a tailnet, made in this process by
//! libtailscale (tsnet built as a Go C archive): userspace networking, no TUN device,
//! no root, no NetworkExtension. It listens on the Apassy port only, and each accepted
//! connection is a [`UnixStream`] (one end of a socket pair that Go pumps to the
//! tailnet TCP connection), so a TLS front can take it like any accepted socket.
//!
//! Without the feature `tailnet`, the crate builds without Go and
//! [`TailnetNode::new`] returns [`Error::NotBuilt`].
//!
//! Safety: `src/ffi.rs` is the only module with `unsafe`; everything here is safe Rust
//! over it. libtailscale keeps the last error of a server in a Go string without a
//! lock, so every call that can set or read it holds the node's lock, except the
//! blocking calls (`up`, `dial`, `accept`), which take it only to read the message
//! after a failure.

#[cfg(feature = "tailnet")]
#[allow(unsafe_code)]
mod ffi;
#[cfg(not(feature = "tailnet"))]
#[path = "ffi_stub.rs"]
mod ffi;

mod loopback;
mod status;

use std::env;
use std::ffi::{CStr, CString, c_int};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io;
use std::net::IpAddr;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::Duration;

use zeroize::Zeroizing;

pub use loopback::LoopbackApi;
pub use status::{Peer, Status};

/// The Apassy port (ADR 0037): the only port a team host's node listens on.
pub const APASSY_PORT: u16 = 8443;

/// The environment variables that tsnet reads when the matching option is empty. A
/// node refuses to start while one is set, so that an auth key or a control server
/// never comes from the environment of the process.
pub const AMBIENT_VARIABLES: [&str; 8] = [
    "TS_AUTHKEY",
    "TS_AUTH_KEY",
    "TS_CLIENT_SECRET",
    "TS_CLIENT_ID",
    "TS_ID_TOKEN",
    "TS_AUDIENCE",
    "TS_CONTROL_URL",
    "TSNET_FORCE_LOGIN",
];

/// What this build linked.
#[derive(Clone, Copy, Debug)]
pub struct BuildInfo {
    /// The libtailscale archive is linked (feature `tailnet`).
    pub linked: bool,
    pub libtailscale_commit: &'static str,
    pub go_version: &'static str,
    pub tailscale_version: &'static str,
    /// The link flags that build.rs passed besides the archive.
    pub link_flags: &'static str,
    /// "built with Go" or "prebuilt" (`APASSY_LIBTAILSCALE_DIR`).
    pub archive_source: &'static str,
}

const fn or_empty(value: Option<&'static str>) -> &'static str {
    match value {
        Some(value) => value,
        None => "",
    }
}

pub const BUILD: BuildInfo = BuildInfo {
    linked: ffi::LINKED,
    libtailscale_commit: or_empty(option_env!("APASSY_TAILNET_LIBTAILSCALE_COMMIT")),
    go_version: or_empty(option_env!("APASSY_TAILNET_GO_VERSION")),
    tailscale_version: or_empty(option_env!("APASSY_TAILNET_TAILSCALE_VERSION")),
    link_flags: or_empty(option_env!("APASSY_TAILNET_LINK_FLAGS")),
    archive_source: or_empty(option_env!("APASSY_TAILNET_ARCHIVE_SOURCE")),
};

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
pub enum Error {
    /// The crate was built without the feature `tailnet`.
    NotBuilt,
    InvalidOption {
        option: &'static str,
        reason: String,
    },
    /// A variable of [`AMBIENT_VARIABLES`] is set.
    AmbientEnvironment(&'static str),
    /// libtailscale returned -1; the message is `tailscale_errmsg`, with auth keys
    /// removed.
    Tailscale {
        call: &'static str,
        message: String,
    },
    /// The node was closed (libtailscale returned EBADF).
    Closed {
        call: &'static str,
    },
    /// The node did not reach the state Running in time.
    UpTimeout {
        hostname: String,
        after: Duration,
        state: Option<String>,
        health: Vec<String>,
    },
    /// WhoIs: no node of the tailnet has this address.
    NotFound(IpAddr),
    Io(io::Error),
    Json {
        what: &'static str,
        message: String,
    },
    LocalApi {
        path: String,
        status: u16,
        body: String,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotBuilt => f.write_str(
                "the embedded tailnet is not in this build (feature `tailnet` of apassy-tailnet)",
            ),
            Self::InvalidOption { option, reason } => {
                write!(f, "the tailnet option {option} is not valid: {reason}")
            }
            Self::AmbientEnvironment(name) => write!(
                f,
                "the embedded tailnet node does not start while {name} is set in the environment; \
                 Apassy passes the auth key and the control server itself"
            ),
            Self::Tailscale { call, message } if message.is_empty() => {
                write!(f, "the tailnet node failed in {call}")
            }
            Self::Tailscale { call, message } => {
                write!(f, "the tailnet node failed in {call}: {message}")
            }
            Self::Closed { call } => write!(f, "the tailnet node is closed ({call})"),
            Self::UpTimeout {
                hostname,
                after,
                state,
                health,
            } => {
                write!(
                    f,
                    "the tailnet node {hostname} did not come up within {} s",
                    after.as_secs()
                )?;
                if let Some(state) = state {
                    write!(f, " (state {state}")?;
                    if !health.is_empty() {
                        write!(f, "; {}", health.join("; "))?;
                    }
                    f.write_str(")")?;
                }
                Ok(())
            }
            Self::NotFound(addr) => write!(f, "no node of the tailnet has the address {addr}"),
            Self::Io(error) => write!(f, "tailnet I/O: {error}"),
            Self::Json { what, message } => write!(f, "cannot read the {what} answer: {message}"),
            Self::LocalApi { path, status, body } => {
                write!(f, "the LocalAPI answered {status} to {path}: {body}")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Where tsnet writes its logs. They are verbose. They name the node, its peers, and
/// the login URL, never the auth key (checked by the spike, docs/design/spike-tsnet.md).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum LogTarget {
    #[default]
    Discard,
    /// A duplicate of this process's stderr.
    Stderr,
    /// Appended to this file, created with mode 0600.
    File(PathBuf),
}

#[derive(Clone)]
pub struct TailnetOptions {
    /// The state directory: `tailscaled.state` holds the node private key. Created
    /// with mode 0700; an existing directory that others can read is refused.
    pub dir: PathBuf,
    /// The machine name, one DNS label, for example `apassy-team-acme`.
    pub hostname: String,
    /// Read once when the node first registers; a node with state ignores it.
    pub auth_key: Option<Zeroizing<String>>,
    /// None: the Tailscale control server. A Headscale URL works too.
    pub control_url: Option<String>,
    pub ephemeral: bool,
    pub log: LogTarget,
    /// How long [`TailnetNode::up`] waits for the state Running.
    pub up_timeout: Duration,
}

impl TailnetOptions {
    pub fn new(dir: impl Into<PathBuf>, hostname: impl Into<String>) -> Self {
        Self {
            dir: dir.into(),
            hostname: hostname.into(),
            auth_key: None,
            control_url: None,
            ephemeral: false,
            log: LogTarget::Discard,
            up_timeout: Duration::from_secs(60),
        }
    }
}

impl fmt::Debug for TailnetOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TailnetOptions")
            .field("dir", &self.dir)
            .field("hostname", &self.hostname)
            .field("auth_key", &self.auth_key.as_ref().map(|_| "<auth key>"))
            .field("control_url", &self.control_url)
            .field("ephemeral", &self.ephemeral)
            .field("log", &self.log)
            .field("up_timeout", &self.up_timeout)
            .finish()
    }
}

struct Inner {
    handle: ffi::Handle,
    lock: Mutex<()>,
}

impl Inner {
    fn guard(&self) -> MutexGuard<'_, ()> {
        self.lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The error of a failed call; the lock must be held.
    fn error_locked(&self, call: &'static str, rc: c_int) -> Error {
        if rc == ffi::EBADF {
            return Error::Closed { call };
        }
        let (status, message) = ffi::errmsg(self.handle);
        if status == ffi::EBADF {
            return Error::Closed { call };
        }
        Error::Tailscale {
            call,
            message: redact(&message),
        }
    }

    fn error(&self, call: &'static str, rc: c_int) -> Error {
        let _guard = self.guard();
        self.error_locked(call, rc)
    }

    /// Runs a non-blocking call under the lock.
    fn call<T>(
        &self,
        name: &'static str,
        call: impl FnOnce(ffi::Handle) -> Result<T, c_int>,
    ) -> Result<T> {
        let _guard = self.guard();
        call(self.handle).map_err(|rc| self.error_locked(name, rc))
    }
}

fn code(rc: c_int) -> Result<(), c_int> {
    if rc == 0 { Ok(()) } else { Err(rc) }
}

/// One embedded tailnet node. Dropping it closes the node (`tailscale_close`, which
/// waits up to about 5 s for tsnet to stop); its listeners then stop accepting.
pub struct TailnetNode {
    inner: Arc<Inner>,
    hostname: String,
    dir: PathBuf,
}

impl fmt::Debug for TailnetNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TailnetNode")
            .field("hostname", &self.hostname)
            .field("dir", &self.dir)
            .finish_non_exhaustive()
    }
}

impl Drop for TailnetNode {
    fn drop(&mut self) {
        let _guard = self.inner.guard();
        // EBADF (already closed) and -1 (tsnet logged why) leave nothing to do.
        let _ = ffi::close(self.inner.handle);
    }
}

impl TailnetNode {
    /// Makes and configures a node without starting it: no network, no files yet
    /// except the state directory.
    pub fn new(options: &TailnetOptions) -> Result<Self> {
        if !ffi::LINKED {
            return Err(Error::NotBuilt);
        }
        refuse_ambient_environment()?;
        validate_hostname(&options.hostname)?;
        prepare_dir(&options.dir)?;
        let dir = c_string("dir", options.dir.as_os_str().as_bytes().to_vec())?;
        let hostname = c_string("hostname", options.hostname.clone().into_bytes())?;
        let control_url = match &options.control_url {
            Some(url) => Some(c_string("control_url", validate_url(url)?.into_bytes())?),
            None => None,
        };
        let auth_key = match &options.auth_key {
            Some(key) => Some(secret_c_string(key)?),
            None => None,
        };
        let log_fd = open_log(&options.log)?;

        let node = Self {
            inner: Arc::new(Inner {
                handle: ffi::new(),
                lock: Mutex::new(()),
            }),
            hostname: options.hostname.clone(),
            dir: options.dir.clone(),
        };
        let set = |name, setting, value: &CStr| {
            node.inner
                .call(name, |sd| code(ffi::set(sd, setting, value)))
        };
        set("tailscale_set_dir", ffi::Setting::Dir, dir.as_c_str())?;
        set(
            "tailscale_set_hostname",
            ffi::Setting::Hostname,
            hostname.as_c_str(),
        )?;
        if let Some(url) = &control_url {
            set(
                "tailscale_set_control_url",
                ffi::Setting::ControlUrl,
                url.as_c_str(),
            )?;
        }
        if let Some(key) = &auth_key {
            let key = CStr::from_bytes_with_nul(key).map_err(|_| Error::InvalidOption {
                option: "auth_key",
                reason: "has a NUL byte".to_owned(),
            })?;
            set("tailscale_set_authkey", ffi::Setting::AuthKey, key)?;
        }
        node.inner.call("tailscale_set_ephemeral", |sd| {
            code(ffi::set_ephemeral(sd, options.ephemeral))
        })?;
        node.inner.call("tailscale_set_logfd", |sd| {
            code(ffi::set_log_fd(sd, log_fd))
        })?;
        Ok(node)
    }

    /// Makes a node, starts it, and waits until it runs on the tailnet (at most
    /// `options.up_timeout`). The auth key is dropped (and erased) when this returns.
    pub fn up(options: TailnetOptions) -> Result<Self> {
        let node = Self::new(&options)?;
        let timeout = options.up_timeout;
        drop(options);
        node.wait_up(timeout)?;
        Ok(node)
    }

    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Starts the node in the background (`tailscale_start`): it contacts the control
    /// server, and a later [`Self::status`] shows the progress. A second call does
    /// nothing.
    pub fn start(&self) -> Result<()> {
        self.inner
            .call("tailscale_start", |sd| code(ffi::start(sd)))
    }

    /// Starts the node and waits until it runs. After a timeout the node stays open
    /// and keeps trying; drop it to stop.
    pub fn wait_up(&self, timeout: Duration) -> Result<Status> {
        // tailscale_close can end tailscale_up only for a started server.
        self.start()?;
        let (sender, receiver) = mpsc::channel();
        let inner = Arc::clone(&self.inner);
        thread::Builder::new()
            .name("apassy-tailnet-up".to_owned())
            .spawn(move || {
                let rc = ffi::up(inner.handle);
                let result = if rc == 0 {
                    Ok(())
                } else {
                    Err(inner.error("tailscale_up", rc))
                };
                let _ = sender.send(result);
            })?;
        match receiver.recv_timeout(timeout) {
            Ok(Ok(())) => self.status(),
            Ok(Err(error)) => Err(error),
            Err(RecvTimeoutError::Timeout) => {
                let status = self.status().ok();
                Err(Error::UpTimeout {
                    hostname: self.hostname.clone(),
                    after: timeout,
                    state: status.as_ref().map(|status| status.backend_state.clone()),
                    health: status.map(|status| status.health).unwrap_or_default(),
                })
            }
            Err(RecvTimeoutError::Disconnected) => Err(Error::Tailscale {
                call: "tailscale_up",
                message: "the waiting thread ended without an answer".to_owned(),
            }),
        }
    }

    /// Listens for TCP on `port` of the node's tailnet addresses. Works before the
    /// node is up. A second listener on the same port fails.
    pub fn listen(&self, port: u16) -> Result<Listener> {
        let addr = CString::new(format!(":{port}")).expect("a port has no NUL");
        let fd = self
            .inner
            .call("tailscale_listen", |sd| ffi::listen(sd, &addr))?;
        Ok(Listener {
            fd,
            port,
            inner: Arc::clone(&self.inner),
        })
    }

    /// Connects to `addr` ("host:port", a tailnet IP or MagicDNS name) over the
    /// tailnet. Blocks until connected or failed.
    pub fn dial(&self, addr: &str) -> Result<UnixStream> {
        let target = c_string("dial address", addr.as_bytes().to_vec())?;
        match ffi::dial(self.inner.handle, &target) {
            Ok(fd) => Ok(UnixStream::from(fd)),
            Err(rc) => Err(self.inner.error("tailscale_dial", rc)),
        }
    }

    /// The node's state over the in-memory LocalAPI (`tailscale_status_json`). It
    /// starts the node if it was not started.
    pub fn status(&self) -> Result<Status> {
        Status::parse(&self.status_json()?)
    }

    /// The raw JSON of `ipnstate.Status`. It holds the login URL (when there is one)
    /// and the public keys of the node and its peers, no private key.
    pub fn status_json(&self) -> Result<String> {
        self.inner.call("tailscale_status_json", ffi::status_json)
    }

    /// Who has `addr` on the tailnet (LocalAPI WhoIs, in memory). A team host calls it
    /// for each accepted connection before TLS, to refuse a peer outside the share.
    pub fn whois(&self, addr: IpAddr) -> Result<Peer> {
        let query = CString::new(addr.to_string()).expect("an address has no NUL");
        let guard = self.inner.guard();
        match ffi::whois_json(self.inner.handle, &query) {
            Ok(json) => {
                drop(guard);
                Peer::parse(&json)
            }
            Err(rc) if rc == ffi::ENOENT => Err(Error::NotFound(addr)),
            Err(rc) => Err(self.inner.error_locked("ApassyTailnetWhoisJSON", rc)),
        }
    }

    /// The node's tailnet addresses (`tailscale_getips`); empty before it is up.
    pub fn ips(&self) -> Result<Vec<IpAddr>> {
        let text = self.inner.call("tailscale_getips", |sd| {
            let (rc, text) = ffi::getips(sd);
            if rc == 0 || rc == ffi::ERANGE {
                Ok(text)
            } else {
                Err(rc)
            }
        })?;
        Ok(text
            .split(',')
            .filter_map(|part| part.trim().parse().ok())
            .collect())
    }

    /// Starts the loopback server of tsnet (`tailscale_loopback`): the LocalAPI over
    /// HTTP and a SOCKS5 proxy on 127.0.0.1, for the life of the node. Only the spike
    /// uses it, to check that the loopback LocalAPI answers status and WhoIs;
    /// [`Self::status`] and [`Self::whois`] need no TCP listener.
    pub fn loopback(&self) -> Result<LoopbackApi> {
        let (addr, credential) = self.inner.call("tailscale_loopback", ffi::loopback)?;
        let credential = Zeroizing::new(credential);
        let addr: std::net::SocketAddr = addr.parse().map_err(|_| Error::Tailscale {
            call: "tailscale_loopback",
            message: format!("not a socket address: {addr}"),
        })?;
        Ok(LoopbackApi::new(addr, credential))
    }
}

/// A TCP listener on the node. Dropping it closes the tailnet listener.
pub struct Listener {
    fd: OwnedFd,
    port: u16,
    inner: Arc<Inner>,
}

impl fmt::Debug for Listener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Listener")
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

/// An accepted tailnet connection.
#[derive(Debug)]
pub struct Accepted {
    pub stream: UnixStream,
    /// The peer's tailnet address, for [`TailnetNode::whois`].
    pub remote: IpAddr,
}

impl Listener {
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Waits for the next connection. Fails with [`Error::Closed`] after the node
    /// closes.
    pub fn accept(&self) -> Result<Accepted> {
        let conn =
            ffi::accept(self.fd.as_fd()).map_err(|rc| self.inner.error("tailscale_accept", rc))?;
        let (rc, text) = {
            let _guard = self.inner.guard();
            ffi::remote_addr(self.fd.as_fd(), conn.as_fd())
        };
        if rc != 0 {
            return Err(self.inner.error("tailscale_getremoteaddr", rc));
        }
        let remote = parse_remote(&text).ok_or_else(|| Error::Tailscale {
            call: "tailscale_getremoteaddr",
            message: format!("not an IP address: {text}"),
        })?;
        Ok(Accepted {
            stream: UnixStream::from(conn),
            remote,
        })
    }
}

/// "100.64.0.1" or "[fd7a:115c:a1e0::1]" (libtailscale's `extractIP`).
fn parse_remote(text: &str) -> Option<IpAddr> {
    let text = text.trim();
    let text = text
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(text);
    text.parse().ok()
}

fn refuse_ambient_environment() -> Result<()> {
    for name in AMBIENT_VARIABLES {
        if env::var_os(name).is_some_and(|value| !value.is_empty()) {
            return Err(Error::AmbientEnvironment(name));
        }
    }
    Ok(())
}

fn validate_hostname(hostname: &str) -> Result<()> {
    let invalid = |reason: &str| {
        Err(Error::InvalidOption {
            option: "hostname",
            reason: reason.to_owned(),
        })
    };
    if hostname.is_empty() || hostname.len() > 63 {
        return invalid("must be 1 to 63 characters");
    }
    if !hostname
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return invalid("may have only a-z, 0-9, and -");
    }
    if hostname.starts_with('-') || hostname.ends_with('-') {
        return invalid("must not start or end with -");
    }
    Ok(())
}

fn validate_url(url: &str) -> Result<String> {
    let ok = (url.starts_with("https://") || url.starts_with("http://"))
        && !url
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control());
    if ok {
        Ok(url.to_owned())
    } else {
        Err(Error::InvalidOption {
            option: "control_url",
            reason: "must be an http:// or https:// URL".to_owned(),
        })
    }
}

/// The state directory holds the node private key: mode 0700, nobody else's.
fn prepare_dir(dir: &Path) -> Result<()> {
    if !dir.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
    }
    let meta = fs::metadata(dir)?;
    if !meta.is_dir() {
        return Err(Error::InvalidOption {
            option: "dir",
            reason: format!("{} is not a directory", dir.display()),
        });
    }
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(Error::InvalidOption {
            option: "dir",
            reason: format!(
                "{} has mode {mode:o}; the node state holds the node private key, so the \
                 directory must be 0700",
                dir.display()
            ),
        });
    }
    Ok(())
}

fn c_string(option: &'static str, bytes: Vec<u8>) -> Result<CString> {
    CString::new(bytes).map_err(|_| Error::InvalidOption {
        option,
        reason: "has a NUL byte".to_owned(),
    })
}

/// The auth key with a NUL, in memory that is erased on drop.
fn secret_c_string(key: &Zeroizing<String>) -> Result<Zeroizing<Vec<u8>>> {
    let key = key.trim();
    if key.is_empty()
        || key
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_whitespace())
    {
        return Err(Error::InvalidOption {
            option: "auth_key",
            reason: "must be one word without spaces".to_owned(),
        });
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(key.len() + 1));
    bytes.extend_from_slice(key.as_bytes());
    bytes.push(0);
    Ok(bytes)
}

fn open_log(target: &LogTarget) -> Result<Option<OwnedFd>> {
    Ok(match target {
        LogTarget::Discard => None,
        LogTarget::Stderr => Some(io::stderr().as_fd().try_clone_to_owned()?),
        LogTarget::File(path) => Some(OwnedFd::from(
            OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(path)?,
        )),
    })
}

/// Removes Tailscale auth keys (`tskey-…`) from a message.
pub(crate) fn redact(message: &str) -> String {
    const PREFIX: &str = "tskey-";
    let mut out = String::with_capacity(message.len());
    let mut rest = message;
    while let Some(at) = rest.find(PREFIX) {
        out.push_str(&rest[..at]);
        out.push_str("tskey-[redacted]");
        let tail = &rest[at + PREFIX.len()..];
        let end = tail
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
            .unwrap_or(tail.len());
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

/// Probes of the spike binary (feature `spike`). Never for a shipped build.
#[cfg(feature = "spike")]
pub mod spike {
    pub use crate::ffi::spike::{Disposition, disposition, fault_in_rust};

    /// Makes Go panic inside a C API call of `node` (see `ffi::spike::go_panic`).
    pub fn go_panic(node: &crate::TailnetNode) {
        crate::ffi::spike::go_panic(node.inner.handle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_removes_every_auth_key() {
        assert_eq!(
            redact("invalid key tskey-auth-kAbC123-XyZ; again tskey-client-1."),
            "invalid key tskey-[redacted]; again tskey-[redacted]."
        );
        assert_eq!(redact("no key here"), "no key here");
    }

    #[test]
    fn hostnames_are_one_dns_label() {
        assert!(validate_hostname("apassy-team-acme").is_ok());
        for bad in ["", "-a", "a-", "Upper", "dot.ted", &"a".repeat(64)] {
            assert!(validate_hostname(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn remote_addresses_of_both_families_parse() {
        assert_eq!(parse_remote("100.64.0.1"), "100.64.0.1".parse().ok());
        assert_eq!(
            parse_remote("[fd7a:115c:a1e0::1]"),
            "fd7a:115c:a1e0::1".parse().ok()
        );
        assert_eq!(parse_remote(""), None);
    }

    #[test]
    fn options_never_show_the_auth_key() {
        let mut options = TailnetOptions::new("/tmp/x", "apassy-team-x");
        options.auth_key = Some(Zeroizing::new("tskey-auth-secret".to_owned()));
        assert!(!format!("{options:?}").contains("secret"));
    }

    #[test]
    fn a_shared_state_directory_is_refused() {
        let dir = std::env::temp_dir().join(format!("apassy-tailnet-mode-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            prepare_dir(&dir),
            Err(Error::InvalidOption { option: "dir", .. })
        ));
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(prepare_dir(&dir).is_ok());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(not(feature = "tailnet"))]
    #[test]
    fn without_the_feature_a_node_is_not_built() {
        let options = TailnetOptions::new(std::env::temp_dir(), "apassy-team-x");
        assert!(matches!(TailnetNode::new(&options), Err(Error::NotBuilt)));
    }
}
