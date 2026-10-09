//! The native messaging host: it passes each message of the extension to the browser
//! socket of the app (ADR 0021, contract section 1).
//!
//! The browser starts the host with the origin of the extension as its first
//! argument. The host accepts only [`EXTENSION_ORIGIN`]. Each message is a 32-bit length
//! in the byte order of the Mac, then that many bytes of JSON. The host checks the size
//! and that the message is a JSON object, sends it as one line on a new connection, and
//! returns the line of the app. It keeps nothing: the buffer of a response with a
//! password is erased after the write, and the output has no buffer of its own.
//!
//! The origin argument is not proof of the caller. Before a [guarded
//! command](super::wire::GUARDED_COMMANDS) (passkeys, one-time codes) the host runs
//! the caller check ([`super::caller::check_browser_parent`]); a failed check answers
//! `unsupported` and the app never sees the request.
//!
//! [`serve`] (the program) also reads the input while it waits for the app. When the
//! browser closes the input (the extension disconnected the port: the page went away,
//! the request was cancelled, or its deadline passed), the host shuts down the
//! connection to the app at once, so the app closes its owner dialog, and exits.

use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::mpsc::{self, TrySendError};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use zeroize::Zeroizing;

use super::wire::{
    EXTENSION_ORIGIN, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, Peek, Response, WireError,
    is_guarded_command,
};

/// An owner check waits up to 180 s for Touch ID. The app answers after it.
const READ_TIMEOUT: Duration = Duration::from_secs(240);
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// The most messages that wait while the host waits for the app. The extension sends
/// one message per port, so more is a broken or hostile sender.
const MAX_QUEUED: usize = 4;

/// Exit status when the caller is not the Apassy extension.
pub const EXIT_WRONG_CALLER: i32 = 2;
/// Exit status when the browser sends a message that is too long or cut off.
pub const EXIT_BAD_FRAME: i32 = 1;

/// The caller check of a guarded command.
type Gate<'a> = &'a dyn Fn() -> Result<(), WireError>;

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
    serve(
        std::env::args_os(),
        std::fs::File::from(stdin),
        std::fs::File::from(stdout),
        &socket,
    )
}

/// Serve the browser until it closes the input, one message after the other. Returns
/// the exit status. The input is read only between answers, so the host notices a
/// closed input only after the current answer; the program uses [`serve`].
pub fn run(
    args: impl IntoIterator<Item = OsString>,
    mut input: impl Read,
    mut output: impl Write,
    socket: &Path,
) -> i32 {
    if let Err(status) = check_args(args) {
        return status;
    }
    let gate: Gate<'_> = &super::caller::check_browser_parent;
    loop {
        let message = match read_frame(&mut input) {
            Ok(Some(message)) => message,
            Ok(None) => return 0,
            Err(_) => return EXIT_BAD_FRAME,
        };
        let answer = answer(&message, socket, gate, None);
        if write_frame(&mut output, &answer).is_err() {
            return 0;
        }
    }
}

/// Like [`run`], but a thread reads the input while the host waits for the app. When
/// the input ends, or a message is too long or cut off, the host shuts down the
/// connection to the app at once, answers nothing more, and returns: 0 for the end of
/// the input, [`EXIT_BAD_FRAME`] for a bad message. Messages that waited are dropped
/// unanswered, because the browser no longer listens.
///
/// The reading thread ends with the input. In the program it ends with the process.
pub fn serve(
    args: impl IntoIterator<Item = OsString>,
    input: impl Read + Send + 'static,
    output: impl Write,
    socket: &Path,
) -> i32 {
    serve_with(
        args,
        input,
        output,
        socket,
        &super::caller::check_browser_parent,
    )
}

fn serve_with(
    args: impl IntoIterator<Item = OsString>,
    mut input: impl Read + Send + 'static,
    mut output: impl Write,
    socket: &Path,
    gate: Gate<'_>,
) -> i32 {
    if let Err(status) = check_args(args) {
        return status;
    }
    let watch = Arc::new(Watch::default());
    let (sender, receiver) = mpsc::sync_channel::<Zeroizing<Vec<u8>>>(MAX_QUEUED);
    let reader = Arc::clone(&watch);
    let spawned = std::thread::Builder::new()
        .name("apassy-browser-host-input".to_owned())
        .spawn(move || {
            loop {
                match read_frame(&mut input) {
                    Ok(Some(message)) => match sender.try_send(message) {
                        Ok(()) => {}
                        Err(TrySendError::Full(_)) => return reader.close(EXIT_BAD_FRAME),
                        Err(TrySendError::Disconnected(_)) => return,
                    },
                    Ok(None) => return reader.close(0),
                    Err(_) => return reader.close(EXIT_BAD_FRAME),
                }
            }
        });
    if spawned.is_err() {
        return EXIT_BAD_FRAME;
    }
    loop {
        let next = receiver.recv();
        if let Some(status) = watch.closed() {
            return status;
        }
        let Ok(message) = next else {
            // The reader ended without a status: it cannot happen, but end cleanly.
            return watch.closed().unwrap_or(0);
        };
        let answer = answer(&message, socket, gate, Some(&watch));
        drop(message);
        if let Some(status) = watch.closed() {
            return status;
        }
        if write_frame(&mut output, &answer).is_err() {
            return 0;
        }
    }
}

fn check_args(args: impl IntoIterator<Item = OsString>) -> Result<(), i32> {
    let mut args = args.into_iter().skip(1);
    if args.next().as_deref() != Some(EXTENSION_ORIGIN.as_ref()) {
        eprintln!("apassy-browser-host: only the Apassy browser extension can start this program.");
        return Err(EXIT_WRONG_CALLER);
    }
    Ok(())
}

/// The state that the input thread shares with the host: whether the input ended, and
/// the connection to the app that waits for an answer.
#[derive(Default)]
struct Watch {
    state: Mutex<WatchState>,
}

#[derive(Default)]
struct WatchState {
    /// The exit status, once the input ended or broke.
    closed: Option<i32>,
    /// A copy of the connection to the app, while the host waits on it.
    stream: Option<UnixStream>,
}

impl Watch {
    fn lock(&self) -> std::sync::MutexGuard<'_, WatchState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn closed(&self) -> Option<i32> {
        self.lock().closed
    }

    /// The input ended: shut down the current connection, so the blocked read of the
    /// host returns and the app sees the hang-up.
    fn close(&self, status: i32) {
        let mut state = self.lock();
        state.closed.get_or_insert(status);
        if let Some(stream) = state.stream.take() {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }

    /// Watch `stream` while the host waits on it. False when the input already ended.
    fn attach(&self, stream: &UnixStream) -> bool {
        let mut state = self.lock();
        if state.closed.is_some() {
            return false;
        }
        match stream.try_clone() {
            Ok(copy) => {
                state.stream = Some(copy);
                true
            }
            Err(_) => false,
        }
    }

    fn detach(&self) {
        self.lock().stream = None;
    }
}

/// Detaches the connection from the watch when the exchange ends, on every path.
struct Attached<'a>(Option<&'a Watch>);

impl Drop for Attached<'_> {
    fn drop(&mut self) {
        if let Some(watch) = self.0 {
            watch.detach();
        }
    }
}

/// The answer to one message: the line of the app, or an error of the host.
fn answer(
    message: &[u8],
    socket: &Path,
    gate: Gate<'_>,
    watch: Option<&Watch>,
) -> Zeroizing<Vec<u8>> {
    let Some(line) = request_line(message) else {
        return encode(&Response::error(
            "bad_request",
            "The request is not a JSON object.",
        ));
    };
    match serde_json::from_slice::<Peek>(&line) {
        Ok(Peek { cmd: Some(cmd) }) if is_guarded_command(&cmd) => {
            if let Err(error) = gate() {
                return encode(&Response::from(error));
            }
        }
        Ok(_) => {}
        Err(_) => {
            return encode(&Response::error(
                "bad_request",
                "The request is not valid browser wire JSON.",
            ));
        }
    }
    match exchange(socket, &line, watch) {
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
fn exchange(
    socket: &Path,
    line: &[u8],
    watch: Option<&Watch>,
) -> Result<Zeroizing<Vec<u8>>, WireError> {
    let cancelled = || WireError::new("cancelled", "The browser closed the request.");
    if watch.is_some_and(|watch| watch.closed().is_some()) {
        return Err(cancelled());
    }
    let mut stream = UnixStream::connect(socket).map_err(|err| match err.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => {
            WireError::new("not_running", "Open Apassy to fill logins.")
        }
        _ => WireError::new(
            "not_running",
            format!("Apassy cannot be reached: {err}. Open Apassy to fill logins."),
        ),
    })?;
    // From here the input thread can shut the connection down. Then the read below
    // ends at once, and the app sees the hang-up.
    let _attached = Attached(watch);
    if watch.is_some_and(|watch| !watch.attach(&stream)) {
        let _ = stream.shutdown(Shutdown::Both);
        return Err(cancelled());
    }
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
        use std::time::Duration;

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

        const PASSKEY_GET: &[u8] = br#"{"v":1,"cmd":"passkey_get","rid":"00000000-0000-4000-8000-000000000000","origin":"https://example.com","rp_id":"example.com","client_data_json":"e30=","allowed":[]}"#;

        #[test]
        fn a_guarded_command_reaches_the_app_only_after_the_caller_check() {
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("browser.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            listener.set_nonblocking(true).unwrap();
            let refuse: Gate<'_> = &|| Err(WireError::new("unsupported", "No."));
            let refused = answer(PASSKEY_GET, &socket, refuse, None);
            let refused: serde_json::Value = serde_json::from_slice(&refused).unwrap();
            assert_eq!(refused["code"], "unsupported");
            assert!(listener.accept().is_err(), "the app saw a refused request");
            // The legacy commands need no caller check.
            let server = thread::spawn(move || {
                listener.set_nonblocking(false).unwrap();
                let mut seen = Vec::new();
                for _ in 0..2 {
                    let (stream, _) = listener.accept().unwrap();
                    let mut writer = stream.try_clone().unwrap();
                    let mut line = Vec::new();
                    BufReader::new(stream).read_until(b'\n', &mut line).unwrap();
                    let request: serde_json::Value = serde_json::from_slice(&line).unwrap();
                    seen.push(request["cmd"].as_str().unwrap().to_owned());
                    writer
                        .write_all(b"{\"ok\":true,\"code\":\"ok\",\"message\":\"\",\"data\":{\"type\":\"none\"}}\n")
                        .unwrap();
                }
                seen
            });
            let checks = std::cell::Cell::new(0);
            let allow = || {
                checks.set(checks.get() + 1);
                Ok(())
            };
            answer(br#"{"v":1,"cmd":"status"}"#, &socket, &allow, None);
            assert_eq!(checks.get(), 0);
            answer(PASSKEY_GET, &socket, &allow, None);
            assert_eq!(checks.get(), 1);
            assert_eq!(server.join().unwrap(), vec!["status", "passkey_get"]);
            // A command that cannot be read is answered by the host.
            let bad = answer(br#"{"v":1,"cmd":7}"#, &socket, &allow, None);
            let bad: serde_json::Value = serde_json::from_slice(&bad).unwrap();
            assert_eq!(bad["code"], "bad_request");
        }

        #[test]
        fn the_end_of_the_input_shuts_down_the_waiting_connection() {
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("browser.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            let (got_line, line_seen) = std::sync::mpsc::channel();
            let server = thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut line = Vec::new();
                let mut byte = [0u8; 1];
                while byte[0] != b'\n' {
                    stream.read_exact(&mut byte).unwrap();
                    line.push(byte[0]);
                }
                got_line.send(()).unwrap();
                // Like an open owner dialog: wait for an answer that never comes, but
                // watch the connection.
                stream
                    .set_read_timeout(Some(Duration::from_secs(20)))
                    .unwrap();
                let started = std::time::Instant::now();
                let read = stream.read(&mut byte);
                (matches!(read, Ok(0)), started.elapsed())
            });
            let (mut browser, host_input) = UnixStream::pair().unwrap();
            browser.write_all(&frame(PASSKEY_GET)).unwrap();
            let host = {
                let socket = socket.clone();
                thread::spawn(move || {
                    let mut out = Vec::new();
                    let status = serve_with(
                        args(EXTENSION_ORIGIN),
                        host_input,
                        &mut out,
                        &socket,
                        &|| Ok(()),
                    );
                    (status, out)
                })
            };
            line_seen.recv_timeout(Duration::from_secs(10)).unwrap();
            drop(browser);
            let (hang_up, waited) = server.join().unwrap();
            assert!(hang_up, "the app did not see the hang-up");
            assert!(waited < Duration::from_secs(10), "{waited:?}");
            let (status, out) = host.join().unwrap();
            assert_eq!(status, 0);
            assert!(out.is_empty(), "nothing is written for a closed request");
        }

        #[test]
        fn a_bad_frame_while_waiting_cancels_and_exits() {
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("browser.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            let server = thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(20)))
                    .unwrap();
                let mut all = Vec::new();
                // The line, then the end of the connection.
                stream.read_to_end(&mut all).is_ok() && all.ends_with(b"\n")
            });
            let (mut browser, host_input) = UnixStream::pair().unwrap();
            browser
                .write_all(&frame(
                    br#"{"v":1,"cmd":"fill","url":"https://a.example","item":1}"#,
                ))
                .unwrap();
            let host = {
                let socket = socket.clone();
                thread::spawn(move || {
                    serve_with(
                        args(EXTENSION_ORIGIN),
                        host_input,
                        Vec::new(),
                        &socket,
                        &|| Ok(()),
                    )
                })
            };
            thread::sleep(Duration::from_millis(100));
            browser
                .write_all(&((MAX_REQUEST_BYTES + 1) as u32).to_ne_bytes())
                .unwrap();
            assert!(server.join().unwrap());
            assert_eq!(host.join().unwrap(), EXIT_BAD_FRAME);
        }
    }
}
