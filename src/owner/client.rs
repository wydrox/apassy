//! Unix socket client for the owner socket of the desktop app.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use zeroize::Zeroizing;

use super::wire::{
    Command, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, OWNER_WIRE_VERSION, Request, Response,
    SOCKET_ENV, SecretText,
};

/// An owner check waits up to 180 s for Touch ID. The app answers after it.
const READ_TIMEOUT: Duration = Duration::from_secs(240);
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// The socket path: `APASSY_OWNER_SOCKET`, or `owner.sock` in the data directory
/// ([`crate::paths::data_dir`]).
pub fn default_socket_path() -> PathBuf {
    if let Some(path) = std::env::var_os(SOCKET_ENV).filter(|value| !value.is_empty()) {
        return PathBuf::from(path);
    }
    crate::paths::data_dir().join("owner.sock")
}

/// Why a request did not get a response.
#[derive(Debug)]
pub enum SendError {
    /// No app listens on the socket.
    NotRunning(io::Error),
    /// The request is larger than [`MAX_REQUEST_BYTES`].
    TooLarge,
    Io(io::Error),
    /// The response is not valid owner wire JSON.
    BadResponse,
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotRunning(_) => f.write_str(
                "Apassy is not running. Open Apassy.app (or run `apassy` without arguments), then try again.",
            ),
            Self::TooLarge => f.write_str("The request is too large."),
            Self::Io(err) => write!(f, "The connection to Apassy failed: {err}"),
            Self::BadResponse => f.write_str("Apassy sent a response that is not valid."),
        }
    }
}

/// Send one command and read one response. The connection closes after the response.
pub fn send(
    socket: &Path,
    session: Option<&SecretText>,
    command: Command,
) -> Result<Response, SendError> {
    let request = Request {
        v: OWNER_WIRE_VERSION,
        session: session.map(|token| SecretText::new(token.expose().to_owned())),
        command,
    };
    // The line can hold secrets. `Zeroizing` erases it after the write.
    let mut line =
        Zeroizing::new(serde_json::to_vec(&request).map_err(|_| SendError::BadResponse)?);
    drop(request);
    line.push(b'\n');
    if line.len() > MAX_REQUEST_BYTES {
        return Err(SendError::TooLarge);
    }
    let mut stream = UnixStream::connect(socket).map_err(|err| match err.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => SendError::NotRunning(err),
        _ => SendError::Io(err),
    })?;
    stream
        .set_read_timeout(Some(READ_TIMEOUT))
        .map_err(SendError::Io)?;
    stream
        .set_write_timeout(Some(WRITE_TIMEOUT))
        .map_err(SendError::Io)?;
    stream.write_all(&line).map_err(SendError::Io)?;
    stream.flush().map_err(SendError::Io)?;
    drop(line);
    let mut reader = BufReader::new(stream.take(MAX_RESPONSE_BYTES as u64));
    // The response can hold a new token.
    let mut response = Zeroizing::new(Vec::new());
    reader
        .read_until(b'\n', &mut response)
        .map_err(SendError::Io)?;
    if response.last() != Some(&b'\n') {
        return Err(SendError::BadResponse);
    }
    serde_json::from_slice(&response).map_err(|_| SendError::BadResponse)
}
