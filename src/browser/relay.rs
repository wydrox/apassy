//! The native messaging host: it passes each message of the extension to the browser
//! socket of the app (ADR 0021, contract section 1).
//!
//! The browser starts the host with the origin of the calling extension as its first
//! argument. The host accepts only [`EXTENSION_ORIGIN`]. Each message is a 32-bit length
//! in the byte order of the Mac, then that many bytes of JSON. The host checks the size
//! and that the message is a JSON object, sends it as one line on a new connection, and
//! returns the line of the app. It keeps nothing: the buffer of a response with a
//! password is erased after the write, and the output has no buffer of its own.

use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use zeroize::Zeroizing;

use super::wire::{EXTENSION_ORIGIN, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, Response, WireError};

/// An owner check waits up to 180 s for Touch ID. The app answers after it.
const READ_TIMEOUT: Duration = Duration::from_secs(240);
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// Exit status when the caller is not the Apassy extension.
pub const EXIT_WRONG_CALLER: i32 = 2;
/// Exit status when the browser sends a message that is too long or cut off.
pub const EXIT_BAD_FRAME: i32 = 1;

/// The program `apassy-browser-host`.
pub fn main() -> i32 {
    let socket = super::wire::default_socket_path();
    // Copies of file descriptors 0 and 1 without the buffers of `Stdin` and `Stdout`, so
    // no buffer keeps a copy of a password: a save sends one, a fill gets one.
    let (Ok(stdin), Ok(stdout)) = (
        io::stdin().as_fd().try_clone_to_owned(),
        io::stdout().as_fd().try_clone_to_owned(),
    ) else {
        return EXIT_BAD_FRAME;
    };
    run(
        std::env::args_os(),
        std::fs::File::from(stdin),
        std::fs::File::from(stdout),
        &socket,
    )
}

/// Serve the browser until it closes the input. Returns the exit status.
pub fn run(
    args: impl IntoIterator<Item = OsString>,
    mut input: impl Read,
    mut output: impl Write,
    socket: &Path,
) -> i32 {
    let mut args = args.into_iter().skip(1);
    if args.next().as_deref() != Some(EXTENSION_ORIGIN.as_ref()) {
        eprintln!("apassy-browser-host: only the Apassy browser extension can start this program.");
        return EXIT_WRONG_CALLER;
    }
    loop {
        let message = match read_frame(&mut input) {
            Ok(Some(message)) => message,
            Ok(None) => return 0,
            Err(_) => return EXIT_BAD_FRAME,
        };
        let answer = answer(&message, socket);
        if write_frame(&mut output, &answer).is_err() {
            return 0;
        }
    }
}

/// The answer to one message: the line of the app, or an error of the host.
fn answer(message: &[u8], socket: &Path) -> Zeroizing<Vec<u8>> {
    let Some(line) = request_line(message) else {
        return encode(&Response::error(
            "bad_request",
            "The request is not a JSON object.",
        ));
    };
    match exchange(socket, &line) {
        Ok(answer) => answer,
        Err(error) => encode(&Response::from(error)),
    }
}

/// The message as one line for the socket, when it is a JSON object. The check parses
/// without a copy of any value (`IgnoredAny`), because a save has a password. A JSON
/// string cannot hold a raw line break, so each line break is white space between
/// tokens and becomes a space.
fn request_line(message: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    serde_json::from_slice::<serde::de::IgnoredAny>(message).ok()?;
    let first = message.iter().find(|byte| !byte.is_ascii_whitespace())?;
    if *first != b'{' {
        return None;
    }
    let mut line = Zeroizing::new(Vec::with_capacity(message.len() + 1));
    line.extend(message.iter().map(|byte| match byte {
        b'\n' | b'\r' => b' ',
        other => *other,
    }));
    Some(line)
}

/// Send one line to the app and read its line back.
fn exchange(socket: &Path, line: &[u8]) -> Result<Zeroizing<Vec<u8>>, WireError> {
    let mut stream = UnixStream::connect(socket).map_err(|err| match err.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => {
            WireError::new("not_running", "Open Apassy to fill logins.")
        }
        _ => WireError::new(
            "not_running",
            format!("Apassy cannot be reached: {err}. Open Apassy to fill logins."),
        ),
    })?;
    let failed = |err: io::Error| {
        WireError::new(
            "stopped",
            format!("The connection to Apassy failed: {err}. Nothing was filled."),
        )
    };
    stream
        .set_read_timeout(Some(READ_TIMEOUT))
        .map_err(failed)?;
    stream
        .set_write_timeout(Some(WRITE_TIMEOUT))
        .map_err(failed)?;
    let mut request = Zeroizing::new(Vec::with_capacity(line.len() + 1));
    request.extend_from_slice(line);
    request.push(b'\n');
    stream.write_all(&request).map_err(failed)?;
    stream.flush().map_err(failed)?;
    // The line can hold a password. The buffer has its full size from the start, so it
    // never moves to a larger allocation, and it is erased on drop. No reader buffer
    // keeps a copy.
    let mut answer = Zeroizing::new(vec![0u8; MAX_RESPONSE_BYTES + 1]);
    let mut filled = 0;
    let end = loop {
        if filled == answer.len() {
            return Err(WireError::new(
                "bad_response",
                "The answer of Apassy is too large.",
            ));
        }
        match stream.read(&mut answer[filled..]) {
            Ok(0) => {
                return Err(WireError::new(
                    "stopped",
                    "Apassy stopped before it answered. Nothing was filled.",
                ));
            }
            Ok(count) => {
                if let Some(at) = answer[filled..filled + count]
                    .iter()
                    .position(|byte| *byte == b'\n')
                {
                    break filled + at;
                }
                filled += count;
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Err(WireError::new(
                    "timeout",
                    "Apassy did not answer in time. Nothing was filled.",
                ));
            }
            Err(err) => return Err(failed(err)),
        }
    };
    answer.truncate(end);
    Ok(answer)
}

fn encode(response: &Response) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(serde_json::to_vec(response).unwrap_or_else(|_| {
        br#"{"ok":false,"code":"stopped","message":"The host failed.","data":{"type":"none"}}"#
            .to_vec()
    }))
}

/// Read one message. `None` when the browser closed the input between messages.
pub fn read_frame(input: &mut impl Read) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
    let mut length = [0u8; 4];
    let mut filled = 0;
    while filled < length.len() {
        match input.read(&mut length[filled..]) {
            Ok(0) if filled == 0 => return Ok(None),
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(count) => filled += count,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
    let length = u32::from_ne_bytes(length) as usize;
    if length > MAX_REQUEST_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the message is too long",
        ));
    }
    // The message of a save has a password.
    let mut message = Zeroizing::new(vec![0u8; length]);
    input.read_exact(&mut message)?;
    Ok(Some(message))
}

/// Write one message: its length in the byte order of the Mac, then the bytes.
pub fn write_frame(output: &mut impl Write, message: &[u8]) -> io::Result<()> {
    let length = u32::try_from(message.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "the message is too long"))?;
    output.write_all(&length.to_ne_bytes())?;
    output.write_all(message)?;
    output.flush()
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn frame(message: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        write_frame(&mut out, message).unwrap();
        out
    }

    fn frames(mut bytes: &[u8]) -> Vec<serde_json::Value> {
        let mut out = Vec::new();
        while let Some(message) = read_frame(&mut bytes).unwrap() {
            out.push(serde_json::from_slice(&message).unwrap());
        }
        out
    }

    fn args(origin: &str) -> Vec<OsString> {
        vec![
            OsString::from("apassy-browser-host"),
            OsString::from(origin),
        ]
    }

    #[test]
    fn another_caller_gets_nothing() {
        let mut out = Vec::new();
        let status = run(
            args("chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"),
            Cursor::new(frame(br#"{"v":1,"cmd":"status"}"#)),
            &mut out,
            Path::new("/nonexistent/browser.sock"),
        );
        assert_eq!(status, EXIT_WRONG_CALLER);
        assert!(out.is_empty());
        let status = run(
            vec![OsString::from("apassy-browser-host")],
            Cursor::new(Vec::new()),
            &mut out,
            Path::new("/nonexistent/browser.sock"),
        );
        assert_eq!(status, EXIT_WRONG_CALLER);
    }

    #[test]
    fn no_app_gives_not_running() {
        let mut out = Vec::new();
        let status = run(
            args(EXTENSION_ORIGIN),
            Cursor::new(frame(br#"{"v":1,"cmd":"status"}"#)),
            &mut out,
            Path::new("/nonexistent/browser.sock"),
        );
        assert_eq!(status, 0);
        let answers = frames(&out);
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0]["code"], "not_running");
    }

    #[test]
    fn a_message_that_is_not_an_object_is_refused_by_the_host() {
        let mut out = Vec::new();
        let mut input = frame(b"[1,2]");
        input.extend(frame(b"not json"));
        run(
            args(EXTENSION_ORIGIN),
            Cursor::new(input),
            &mut out,
            Path::new("/nonexistent/browser.sock"),
        );
        let answers = frames(&out);
        assert_eq!(answers.len(), 2);
        assert!(answers.iter().all(|a| a["code"] == "bad_request"));
    }

    #[test]
    fn a_request_line_is_one_line_of_the_same_json() {
        let line = request_line(b"{\"v\":1,\n \"cmd\":\"status\"}\r\n").unwrap();
        assert!(!line.contains(&b'\n') && !line.contains(&b'\r'));
        let value: serde_json::Value = serde_json::from_slice(&line).unwrap();
        assert_eq!(value["cmd"], "status");
        assert!(request_line(b"[1]").is_none());
        assert!(
            request_line(b"{\"a\":\"x\ny\"}").is_none(),
            "a raw line break in a string"
        );
        assert!(request_line(b"{} {}").is_none());
    }

    #[test]
    fn a_long_or_cut_message_closes_the_host() {
        let mut too_long = ((MAX_REQUEST_BYTES + 1) as u32).to_ne_bytes().to_vec();
        too_long.extend(vec![b' '; 16]);
        let status = run(
            args(EXTENSION_ORIGIN),
            Cursor::new(too_long),
            Vec::new(),
            Path::new("/nonexistent/browser.sock"),
        );
        assert_eq!(status, EXIT_BAD_FRAME);
        let mut cut = frame(br#"{"v":1,"cmd":"status"}"#);
        cut.truncate(10);
        let status = run(
            args(EXTENSION_ORIGIN),
            Cursor::new(cut),
            Vec::new(),
            Path::new("/nonexistent/browser.sock"),
        );
        assert_eq!(status, EXIT_BAD_FRAME);
    }

    /// Tests with a socket of a fake app. `tempfile` comes with the vault feature.
    #[cfg(feature = "vault")]
    mod with_app {
        use std::io::{BufRead, BufReader};
        use std::os::unix::net::UnixListener;
        use std::thread;

        use super::*;

        #[test]
        fn each_message_goes_to_the_app_on_its_own_connection() {
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("browser.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            let server = thread::spawn(move || {
                let mut seen = Vec::new();
                for _ in 0..2 {
                    let (stream, _) = listener.accept().unwrap();
                    let mut writer = stream.try_clone().unwrap();
                    let mut line = Vec::new();
                    BufReader::new(stream).read_until(b'\n', &mut line).unwrap();
                    let request: serde_json::Value = serde_json::from_slice(&line).unwrap();
                    seen.push(request["cmd"].as_str().unwrap().to_owned());
                    writer
                        .write_all(
                            b"{\"ok\":true,\"code\":\"ok\",\"message\":\"Done.\",\"data\":{\"type\":\"none\"}}\n",
                        )
                        .unwrap();
                }
                seen
            });
            let mut input = frame(br#"{"v":1,"cmd":"status"}"#);
            input.extend(frame(br#"{"v":1,"cmd":"show"}"#));
            let mut out = Vec::new();
            let status = run(
                args(EXTENSION_ORIGIN),
                Cursor::new(input),
                &mut out,
                &socket,
            );
            assert_eq!(status, 0);
            assert_eq!(server.join().unwrap(), vec!["status", "show"]);
            let answers = frames(&out);
            assert_eq!(answers.len(), 2);
            assert!(answers.iter().all(|a| a["ok"] == true));
        }

        #[test]
        fn an_app_that_closes_without_an_answer_gives_stopped() {
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("browser.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            let server = thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                let mut line = Vec::new();
                BufReader::new(stream).read_until(b'\n', &mut line).unwrap();
            });
            let mut out = Vec::new();
            run(
                args(EXTENSION_ORIGIN),
                Cursor::new(frame(br#"{"v":1,"cmd":"status"}"#)),
                &mut out,
                &socket,
            );
            server.join().unwrap();
            assert_eq!(frames(&out)[0]["code"], "stopped");
        }
    }
}
