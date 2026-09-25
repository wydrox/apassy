//! Unix socket client for the local broker.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::wire::{Action, MAX_LINE_BYTES, WIRE_VERSION, WireRequest, WireResponse};

/// Environment variable that overrides the broker socket path.
pub const SOCKET_ENV: &str = "APASSY_BROKER_SOCKET";
/// Environment variable that holds the agent token for the MCP adapter.
pub const TOKEN_ENV: &str = "APASSY_AGENT_TOKEN";
const IO_TIMEOUT: Duration = Duration::from_secs(30);

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

/// Send one request and read one response. The connection closes after the response.
pub fn send(socket: &Path, token: &str, action: Action) -> io::Result<WireResponse> {
    let request = WireRequest {
        v: WIRE_VERSION,
        token: token.to_owned(),
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
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    stream.write_all(&line)?;
    stream.flush()?;
    let mut reader = BufReader::new(stream.take(MAX_LINE_BYTES as u64));
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
