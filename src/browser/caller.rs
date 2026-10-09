//! Caller checks of passkey and one-time code requests (contract section 9).
//!
//! The browser starts the host with the origin of the extension as its first argument,
//! but any local process can start the host with that argument. So the origin argument
//! is not an authenticator. Before the host passes a [guarded
//! command](super::wire::GUARDED_COMMANDS) to the app, and before the app answers one,
//! the signed Swift guard `apassy-browser-guard` in the same Apassy.app checks the
//! callers from the operating system: audit tokens and code signatures
//! (`native/ApassyBrowserGuard/main.swift`).
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

use std::io::Read;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use super::wire::WireError;

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

const CODESIGN: &str = "/usr/bin/codesign";
/// The guard answers in milliseconds. The limit covers a slow, loaded Mac.
const GUARD_TIMEOUT: Duration = Duration::from_secs(10);
const CODESIGN_TIMEOUT: Duration = Duration::from_secs(10);
/// The only answer of the guard that means yes.
const GUARD_OK: &[u8] = b"ok\n";

/// The check that the guard runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Check {
    BrowserParent,
    SocketPeer,
}

impl Check {
    fn arg(self) -> &'static str {
        match self {
            Self::BrowserParent => "browser-parent",
            Self::SocketPeer => "socket-peer",
        }
    }
}

/// Host side: the parent of this process is a known signed browser, and this process
/// is the signed `apassy-browser-host` of its Apassy.app.
pub fn check_browser_parent() -> Result<(), WireError> {
    run_guard(Check::BrowserParent, Stdio::null())
}

/// App side: the peer of `stream` (an accepted connection of `browser.sock`) is the
/// signed `apassy-browser-host` of this Apassy.app, started by a known signed browser.
/// The stream stays open and unread.
pub fn check_peer(stream: &UnixStream) -> Result<(), WireError> {
    let copy = stream.try_clone().map_err(|_| refused())?;
    run_guard(Check::SocketPeer, Stdio::from(OwnedFd::from(copy)))
}

/// The error of every failed check. It names no reason: the reason stays with the
/// guard.
fn refused() -> WireError {
    WireError::new(
        "unsupported",
        "Apassy cannot verify this browser, so the browser handles this request itself.",
    )
}

fn missing() -> WireError {
    WireError::new(
        "unsupported",
        "Apassy cannot find its browser check. Passkeys and codes work only from Apassy.app.",
    )
}

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
    match finish(child, GUARD_TIMEOUT) {
        Some((true, output)) if output == GUARD_OK => Ok(()),
        _ => Err(refused()),
    }
}

/// The guard to start, and whether its signature must be checked first.
#[derive(Debug, PartialEq, Eq)]
struct Guard {
    path: PathBuf,
    verify: bool,
}

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
fn guard_requirement() -> String {
    format!(
        "=anchor apple generic and identifier \"{GUARD_IDENTIFIER}\" and certificate leaf[subject.OU] = \"{APASSY_TEAM}\""
    )
}

/// `codesign --verify --strict` of the guard against [`guard_requirement`].
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
        Some((true, _)) => Ok(()),
        _ => Err(refused()),
    }
}

/// Wait for `child` until `timeout`. Returns its success and at most 64 bytes of its
/// standard output, or `None` when it did not exit in time (it is then killed).
fn finish(mut child: Child, timeout: Duration) -> Option<(bool, Vec<u8>)> {
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
        stdout.take(64).read_to_end(&mut output).ok()?;
    }
    Some((status.success(), output))
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(run("echo ok"), Some((true, b"ok\n".to_vec())));
        assert_eq!(run("echo ok; exit 1"), Some((false, b"ok\n".to_vec())));
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
