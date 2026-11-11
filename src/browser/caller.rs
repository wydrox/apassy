//! Caller checks of passkey and one-time code requests (contract section 9).
//!
//! The browser starts the host with the origin of the extension as its first argument,
//! but any local process can start the host with that argument. So the origin argument
//! is not an authenticator. Before the host passes a [guarded
//! command](super::wire::GUARDED_COMMANDS) to the app, and before the app answers one,
//! on macOS the signed Swift guard `apassy-browser-guard` in the same Apassy.app checks the
//! callers from the operating system: audit tokens and code signatures
//! (`native/ApassyBrowserGuard/main.swift`). Linux uses kernel peer credentials and
//! a root-owned direct browser executable; see ADR 0045 and `caller_linux.rs` for
//! its explicitly narrower hardened-peer guarantee. Linux refuses unsafe browser
//! switches without offering the macOS signed-instance bypass.
//!
//! - [`check_browser_parent`] (host): the guard checks that its parent is the signed
//!   `apassy-browser-host` of this app, and that the parent of the host is a known
//!   signed browser.
//! - [`check_peer`] (app): the guard gets the accepted connection as its standard
//!   input. It checks that its parent is the signed Apassy app that contains it, that
//!   the peer of the socket is the signed `apassy-browser-host` of the same app, and
//!   that the parent of that host is a known signed browser.
//!
//! The crate forbids unsafe code, so Rust only duplicates the socket into the standard
//! input of the guard (`UnixStream` to `OwnedFd` to `Stdio`), with safe std APIs.
//! Before it starts the guard, Rust checks with `/usr/bin/codesign` that the guard is
//! the guard of the Apassy team, at its place in the bundle of the running program.
//! Every failure refuses the request: a missing or unsigned guard, a guard that does
//! not answer `ok` within the time limit, a source build. Debug builds may name another
//! guard with [`GUARD_ENV`]; release builds have no override.
//! Status 2 can report a bounded unsafe profile identity; malformed output refuses.
//! The process
//! that set the switch already knows it; this reveals nothing about the vault.

#[cfg(any(not(target_os = "linux"), test))]
use std::io::Read;
#[cfg(not(target_os = "linux"))]
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
#[cfg(any(not(target_os = "linux"), test))]
use std::path::{Path, PathBuf};
#[cfg(any(not(target_os = "linux"), test))]
use std::process::{Child, Command, Stdio};
#[cfg(any(not(target_os = "linux"), test))]
use std::time::{Duration, Instant};

use super::wire::WireError;

// Linux verifies the browser using procfs and kernel socket credentials. Its
// limitations differ from the signed macOS chain; see ADR 0045.
#[cfg(any(target_os = "linux", test))]
#[path = "caller_linux.rs"]
pub(super) mod linux;

/// The guard, relative to the `Contents` folder of Apassy.app.
pub const GUARD_FROM_CONTENTS: &str = "MacOS/apassy-browser-guard";
/// The signing identifier of the guard.
pub const GUARD_IDENTIFIER: &str = "com.wydrox.apassy.browser-guard";
/// The signing identifier of `apassy-browser-host`.
pub const HOST_IDENTIFIER: &str = "com.wydrox.apassy.browser-host";
/// The Developer ID team of Apassy.
pub const APASSY_TEAM: &str = "7S3F9767BM";
/// Debug builds only: the path of a guard to use instead of the one in the bundle. The
/// signature check before the start is skipped for it; the guard itself still refuses
/// without a team signature.
pub const GUARD_ENV: &str = "APASSY_BROWSER_GUARD";

#[cfg(not(target_os = "linux"))]
const CODESIGN: &str = "/usr/bin/codesign";
/// The guard answers in milliseconds. The limit covers a slow, loaded Mac.
#[cfg(not(target_os = "linux"))]
const GUARD_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(not(target_os = "linux"))]
const CODESIGN_TIMEOUT: Duration = Duration::from_secs(10);
/// The only answer of the guard that means yes.
#[cfg(any(not(target_os = "linux"), test))]
const GUARD_OK: &[u8] = b"ok\n";

/// The check that the guard runs.
#[cfg(not(target_os = "linux"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Check {
    BrowserParent,
    SocketPeer,
}

#[cfg(not(target_os = "linux"))]
impl Check {
    fn arg(self) -> &'static str {
        match self {
            Self::BrowserParent => "browser-parent",
            Self::SocketPeer => "socket-peer",
        }
    }
}

/// Host side: verify the installed host and its direct browser parent using the
/// platform boundary described above.
pub fn check_browser_parent() -> Result<(), WireError> {
    #[cfg(target_os = "linux")]
    {
        linux::check_browser_parent()
    }
    #[cfg(not(target_os = "linux"))]
    {
        run_guard(Check::BrowserParent, Stdio::null())
    }
}

/// App side: verify the socket peer using macOS signing or Linux kernel peer
/// credentials and its direct browser parent. The stream stays open and unread.
pub fn check_peer(stream: &UnixStream) -> Result<(), WireError> {
    #[cfg(target_os = "linux")]
    {
        linux::check_peer(stream)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let copy = stream.try_clone().map_err(|_| refused())?;
        run_guard(Check::SocketPeer, Stdio::from(OwnedFd::from(copy)))
    }
}

/// Verify the platform boundary, retaining a signed unsafe instance on macOS only.
pub fn peer_identity(
    stream: &UnixStream,
) -> Result<Option<super::trust::InstanceIdentity>, WireError> {
    #[cfg(target_os = "linux")]
    {
        linux::check_peer(stream).map(|()| None)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let copy = stream.try_clone().map_err(|_| refused())?;
        match run_guard(Check::SocketPeer, Stdio::from(OwnedFd::from(copy))) {
            Ok(()) => Ok(None),
            Err(e) => unsafe_identity(&e).map(Some).ok_or(e),
        }
    }
}

pub fn unsafe_identity(error: &WireError) -> Option<super::trust::InstanceIdentity> {
    if error.code != "unsafe_browser" {
        return None;
    }
    serde_json::from_str::<super::trust::InstanceIdentity>(&error.message)
        .ok()
        .filter(|p| p.valid())
}

/// The host still authenticates the chain; only Apassy may grant a bypass.
pub fn check_browser_parent_for_app() -> Result<(), WireError> {
    match check_browser_parent() {
        Err(e) if unsafe_identity(&e).is_some() => Ok(()),
        result => result,
    }
}

/// Generic refusal: only the unsafe-switch category is disclosed separately.
fn refused() -> WireError {
    WireError::new(
        "unsupported",
        "Apassy cannot verify this browser, so the browser handles this request itself.",
    )
}

/// Linux: the browser runs in another mount or user namespace than Apassy. The
/// explanation is the one of the "Not supported" state of a snap or Flatpak
/// ([`super::install::Unsupported::explain`]).
#[cfg(any(target_os = "linux", test))]
fn sandboxed() -> WireError {
    WireError::new("unsupported", super::install::sandboxed_browser())
}

#[cfg(not(target_os = "linux"))]
fn missing() -> WireError {
    WireError::new(
        "unsupported",
        "Apassy cannot find its browser check. Passkeys and codes work only from Apassy.app.",
    )
}

#[cfg(not(target_os = "linux"))]
fn run_guard(check: Check, stdin: Stdio) -> Result<(), WireError> {
    let guard = locate()?;
    if guard.verify {
        verify_guard(&guard.path)?;
    }
    let child = Command::new(&guard.path)
        .arg(check.arg())
        .env_clear()
        .stdin(stdin)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| refused())?;
    parse_answer(finish(child, GUARD_TIMEOUT))
}

#[cfg(any(not(target_os = "linux"), test))]
fn parse_answer(answer: Option<(Option<i32>, Vec<u8>)>) -> Result<(), WireError> {
    match answer {
        Some((Some(0), output)) if output == GUARD_OK => Ok(()),
        Some((Some(2), output))
            if output.len() <= 1039
                && output.starts_with(b"unsafe-switch ")
                && output.ends_with(b"\n") =>
        {
            let json = &output[14..output.len() - 1];
            if json.len() > 1024 {
                return Err(refused());
            }
            let identity: super::trust::InstanceIdentity =
                serde_json::from_slice(json).map_err(|_| refused())?;
            if !identity.valid() {
                return Err(refused());
            }
            Err(WireError::new(
                "unsafe_browser",
                String::from_utf8(json.to_vec()).map_err(|_| refused())?,
            ))
        }
        Some((Some(2), output)) if output == b"unsafe-switch\n" => Err(WireError::new(
            "unsupported",
            "This browser was started with remote debugging or a test extension, so other programs can control it. Apassy doesn't fill passkeys or codes there. Quit the browser and open it normally.",
        )),
        _ => Err(refused()),
    }
}

/// The guard to start, and whether its signature must be checked first.
#[cfg(not(target_os = "linux"))]
#[derive(Debug, PartialEq, Eq)]
struct Guard {
    path: PathBuf,
    verify: bool,
}

#[cfg(not(target_os = "linux"))]
fn locate() -> Result<Guard, WireError> {
    #[cfg(debug_assertions)]
    if let Some(path) = std::env::var_os(GUARD_ENV).filter(|path| !path.is_empty()) {
        return Ok(Guard {
            path: PathBuf::from(path),
            verify: false,
        });
    }
    let exe = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .map_err(|_| missing())?;
    let path = guard_for_executable(&exe).ok_or_else(missing)?;
    Ok(Guard { path, verify: true })
}

/// The guard of the Apassy.app that holds `exe` in `Contents/MacOS`. `None` for a
/// program outside an app bundle, or when the guard is missing, is not a regular file,
/// or resolves to a place outside the bundle.
#[cfg(any(not(target_os = "linux"), test))]
fn guard_for_executable(exe: &Path) -> Option<PathBuf> {
    let contents = super::install::bundle_contents(exe.parent()?)?;
    let guard = std::fs::canonicalize(contents.join(GUARD_FROM_CONTENTS)).ok()?;
    let in_place = guard == contents.join(GUARD_FROM_CONTENTS);
    let file = std::fs::symlink_metadata(&guard)
        .ok()?
        .file_type()
        .is_file();
    (in_place && file).then_some(guard)
}

/// The designated requirement that the guard must satisfy.
#[cfg(any(not(target_os = "linux"), test))]
fn guard_requirement() -> String {
    format!(
        "=anchor apple generic and identifier \"{GUARD_IDENTIFIER}\" and certificate leaf[subject.OU] = \"{APASSY_TEAM}\""
    )
}

/// `codesign --verify --strict` of the guard against [`guard_requirement`].
#[cfg(not(target_os = "linux"))]
fn verify_guard(path: &Path) -> Result<(), WireError> {
    let child = Command::new(CODESIGN)
        .args(["--verify", "--strict", "-R"])
        .arg(guard_requirement())
        .arg(path)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| refused())?;
    match finish(child, CODESIGN_TIMEOUT) {
        Some((Some(0), _)) => Ok(()),
        _ => Err(refused()),
    }
}

/// Wait for `child` until `timeout`. Returns its exit code and at most 1040 bytes of its
/// standard output, or `None` when it did not exit in time (it is then killed).
#[cfg(any(not(target_os = "linux"), test))]
fn finish(mut child: Child, timeout: Duration) -> Option<(Option<i32>, Vec<u8>)> {
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if start.elapsed() < timeout => std::thread::sleep(Duration::from_millis(5)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    };
    let mut output = Vec::new();
    if let Some(stdout) = child.stdout.take() {
        // The child exited, so the pipe ends; a larger answer is not `ok`.
        stdout.take(1040).read_to_end(&mut output).ok()?;
    }
    Some((status.code(), output))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_identity_wire_is_strict() {
        let json = r#"{"bundle_id":"net.imput.helium","team_id":"S4Q33XPHB4","profile_dir":"/tmp/owner","debugging":"9223","unsafe_switches":["remote-debugging-port"]}"#;
        let parse = |json: &str| {
            parse_answer(Some((
                Some(2),
                format!("unsafe-switch {json}\n").into_bytes(),
            )))
            .unwrap_err()
        };
        assert_eq!(unsafe_identity(&parse(json)).unwrap().debugging, "9223");
        assert_eq!(
            parse(&format!("{}{}", " ".repeat(1024), json)).message,
            refused().message
        );
        assert_eq!(
            parse(&json.replace("\"bundle_id\"", "\"unknown\"")).message,
            refused().message
        );
        assert_eq!(parse(&json.replace("9223", "0")).message, refused().message);
    }

    #[test]
    fn answers_disclose_only_the_exact_unsafe_switch_category() {
        assert!(parse_answer(Some((Some(0), b"ok\n".to_vec()))).is_ok());
        let unsafe_error = parse_answer(Some((Some(2), b"unsafe-switch\n".to_vec()))).unwrap_err();
        assert_eq!(unsafe_error.code, "unsupported");
        assert!(
            unsafe_error
                .message
                .contains("Quit the browser and open it normally.")
        );
        for answer in [
            None, // timeout
            Some((Some(1), vec![])),
            Some((Some(0), vec![])),
            Some((Some(2), b"garbage\n".to_vec())),
            Some((Some(1), b"unsafe-switch\n".to_vec())),
            Some((Some(0), b"unsafe-switch\n".to_vec())),
            Some((Some(2), b"unsafe-switch".to_vec())),
            Some((Some(2), b"ok\n".to_vec())),
            Some((None, b"unsafe-switch\n".to_vec())),
        ] {
            let error = parse_answer(answer).unwrap_err();
            assert_eq!(error.code, refused().code);
            assert_eq!(error.message, refused().message);
        }
    }

    #[test]
    fn the_guard_is_in_the_bundle_of_the_program() {
        let dir = std::env::temp_dir().join(format!("apassy-guard-{}", std::process::id()));
        let macos = dir.join("Apassy.app/Contents/MacOS");
        std::fs::create_dir_all(&macos).unwrap();
        let macos = std::fs::canonicalize(&macos).unwrap();
        let host = macos.join("apassy-browser-host");
        assert_eq!(guard_for_executable(&host), None, "no guard yet");
        std::fs::write(macos.join("apassy-browser-guard"), b"").unwrap();
        assert_eq!(
            guard_for_executable(&host),
            Some(macos.join("apassy-browser-guard"))
        );
        // A guard that is a symlink to another place is refused.
        std::fs::remove_file(macos.join("apassy-browser-guard")).unwrap();
        std::fs::write(dir.join("elsewhere"), b"").unwrap();
        std::os::unix::fs::symlink(dir.join("elsewhere"), macos.join("apassy-browser-guard"))
            .unwrap();
        assert_eq!(guard_for_executable(&host), None);
        // A program outside an app bundle has no guard.
        assert_eq!(
            guard_for_executable(Path::new("/usr/local/bin/apassy-browser-host")),
            None
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_requirement_names_the_guard_and_the_team() {
        let requirement = guard_requirement();
        assert!(requirement.starts_with("=anchor apple generic"));
        assert!(requirement.contains(r#"identifier "com.wydrox.apassy.browser-guard""#));
        assert!(requirement.contains(r#"leaf[subject.OU] = "7S3F9767BM""#));
    }

    #[test]
    fn only_ok_from_a_successful_guard_passes() {
        let run = |script: &str| {
            let child = Command::new("/bin/sh")
                .args(["-c", script])
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            finish(child, Duration::from_secs(5))
        };
        assert_eq!(run("echo ok"), Some((Some(0), b"ok\n".to_vec())));
        assert_eq!(run("echo ok; exit 1"), Some((Some(1), b"ok\n".to_vec())));
        let slow = Instant::now();
        let child = Command::new("/bin/sleep")
            .arg("30")
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        assert_eq!(finish(child, Duration::from_millis(200)), None);
        assert!(slow.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn a_test_program_is_not_in_a_bundle_so_every_check_fails() {
        if std::env::var_os(GUARD_ENV).is_some() {
            return;
        }
        assert_eq!(check_browser_parent().unwrap_err().code, "unsupported");
        let (one, _two) = UnixStream::pair().unwrap();
        assert_eq!(check_peer(&one).unwrap_err().code, "unsupported");
    }
}
