//! Unix socket client for the local broker.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::wire::{
    Action, MAX_LINE_BYTES, MAX_RESPONSE_BYTES, WIRE_VERSION, WireRequest, WireResponse,
};

/// Environment variable that overrides the broker socket path.
pub const SOCKET_ENV: &str = "APASSY_BROKER_SOCKET";
/// Environment variable that holds the agent token for the MCP adapter.
pub const TOKEN_ENV: &str = "APASSY_AGENT_TOKEN";
const IO_TIMEOUT: Duration = Duration::from_secs(30);
/// A run can wait for the owner and then for the process.
const RUN_TIMEOUT: Duration = Duration::from_secs(600);

/// The socket path: `APASSY_BROKER_SOCKET`, or the default in Application Support.
pub fn default_socket_path() -> PathBuf {
    if let Some(path) = std::env::var_os(SOCKET_ENV).filter(|value| !value.is_empty()) {
        return PathBuf::from(path);
    }
    let home = std::env::var_os("HOME").map_or_else(|| PathBuf::from("."), PathBuf::from);
    home.join("Library")
        .join("Application Support")
        .join("Apassy")
        .join("broker.sock")
}

/// Settings of one request besides the token and the action.
#[derive(Debug, Clone, Copy, Default)]
pub struct SendOptions<'a> {
    /// The agent host session of the sender (goal item B6).
    pub host_session: Option<&'a str>,
    /// Read and write timeout. `None` uses the default for the action.
    pub timeout: Option<Duration>,
}

/// Send one request and read one response. The connection closes after the response.
pub fn send(socket: &Path, token: &str, action: Action) -> io::Result<WireResponse> {
    send_with(socket, token, action, SendOptions::default())
}

/// [`send`] with a host session or a shorter timeout.
pub fn send_with(
    socket: &Path,
    token: &str,
    action: Action,
    options: SendOptions<'_>,
) -> io::Result<WireResponse> {
    let timeout = options
        .timeout
        .unwrap_or(if matches!(action, Action::Run { .. }) {
            RUN_TIMEOUT
        } else {
            IO_TIMEOUT
        });
    let request = WireRequest {
        v: WIRE_VERSION,
        token: token.to_owned(),
        host_session: options.host_session.map(str::to_owned),
        action,
    };
    let mut line = serde_json::to_vec(&request).map_err(io::Error::other)?;
    line.push(b'\n');
    if line.len() > MAX_LINE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the request is too large",
        ));
    }
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout.min(IO_TIMEOUT)))?;
    stream.write_all(&line)?;
    stream.flush()?;
    let mut reader = BufReader::new(stream.take(MAX_RESPONSE_BYTES as u64));
    let mut response = String::new();
    reader.read_line(&mut response)?;
    if !response.ends_with('\n') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the broker response is incomplete or too large",
        ));
    }
    serde_json::from_str(&response).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "the broker response is not valid",
        )
    })
}
