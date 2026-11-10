//! Linux's browser check is defense in depth, not executable authentication of a
//! hardened socket peer. SO_PEERCRED authenticates its PID and user. We verify its
//! direct browser parent and refuse unreadable/stale process information. Linux
//! prevents reading a non-dumpable peer's exe; that one PermissionDenied case uses
//! the kernel ancestry, never a claimed process name or request PID. The host checks
//! its own image before relaying. Compromised same-user processes, including injected
//! browser subprocesses, remain outside this software vault's protection (ADR 0045).

use std::fs;
use std::io;
#[cfg(target_os = "linux")]
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
#[cfg(target_os = "linux")]
use std::path::PathBuf;

#[cfg(target_os = "linux")]
use super::WireError;
#[cfg(target_os = "linux")]
use std::os::unix::net::UnixStream;

#[cfg(target_os = "linux")]
pub(in crate::browser) const HOST: &str = "/usr/lib/apassy/apassy-browser-host";
const BROWSERS: &[&str] = &[
    "/opt/google/chrome/chrome",
    "/usr/lib/chromium/chromium",
    "/usr/lib/chromium-browser/chromium-browser",
];
#[cfg(target_os = "linux")]
const MAX_PROC_BYTES: u64 = 128 * 1024;

#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq, Eq)]
struct Process {
    parent: u32,
    start: u64,
    uids: [u32; 4],
}

fn invalid() -> io::Error {
    io::Error::other("unverifiable browser process")
}

/// `comm` can contain spaces and parentheses; the rightmost `) ` ends it. State is
/// field 3, parent field 4, and starttime field 22. Never use comm as identity.
fn parse_stat(text: &str) -> io::Result<(u32, u64)> {
    let (_, fields) = text.rsplit_once(") ").ok_or_else(invalid)?;
    let fields: Vec<_> = fields.split_ascii_whitespace().collect();
    if fields.len() < 20 || !matches!(fields[0], "R" | "S" | "D" | "T" | "t" | "I") {
        return Err(invalid());
    }
    let parent = fields[1].parse::<u32>().map_err(|_| invalid())?;
    let start = fields[19].parse::<u64>().map_err(|_| invalid())?;
    if parent == 0 || start == 0 {
        return Err(invalid());
    }
    Ok((parent, start))
}

fn parse_uids(text: &str) -> io::Result<[u32; 4]> {
    let mut lines = text.lines().filter_map(|line| line.strip_prefix("Uid:\t"));
    let values = lines.next().ok_or_else(invalid)?;
    if lines.next().is_some() {
        return Err(invalid());
    }
    let values: Vec<_> = values.split_ascii_whitespace().collect();
    if values.len() != 4 {
        return Err(invalid());
    }
    let mut uids = [0; 4];
    for (value, uid) in values.into_iter().zip(&mut uids) {
        *uid = value.parse().map_err(|_| invalid())?;
    }
    Ok(uids)
}

#[cfg(target_os = "linux")]
fn bounded(path: &Path) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(MAX_PROC_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_PROC_BYTES {
        return Err(invalid());
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn process(pid: u32, uid: u32) -> io::Result<Process> {
    let root = PathBuf::from(format!("/proc/{pid}"));
    let stat = bounded(&root.join("stat"))?;
    let (parent, start) = parse_stat(std::str::from_utf8(&stat).map_err(|_| invalid())?)?;
    let status = bounded(&root.join("status"))?;
    let uids = parse_uids(std::str::from_utf8(&status).map_err(|_| invalid())?)?;
    if uids != [uid; 4] {
        return Err(invalid());
    }
    Ok(Process {
        parent,
        start,
        uids,
    })
}

fn safe_mode(uid: u32, mode: u32, file: bool) -> bool {
    uid == 0 && mode & 0o022 == 0 && (!file || (mode & 0o111 != 0 && mode & 0o6000 == 0))
}

/// Every path component must be root-owned and non-writable by group/others. No
/// symlinks, set-ID executables, deleted images, relative paths or source builds.
pub(in crate::browser) fn trusted_binary(path: &Path) -> io::Result<()> {
    if !path.is_absolute()
        || path.components().any(|p| {
            matches!(
                p,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(invalid());
    }
    for (index, component) in path.ancestors().enumerate() {
        let metadata = fs::symlink_metadata(component)?;
        let file = index == 0;
        if !safe_mode(metadata.uid(), metadata.mode(), file)
            || (file && !metadata.is_file())
            || (!file && !metadata.is_dir())
        {
            return Err(invalid());
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn image(pid: u32, expected: &[&str]) -> io::Result<PathBuf> {
    let proc_exe = PathBuf::from(format!("/proc/{pid}/exe"));
    let path = fs::read_link(&proc_exe)?;
    if !expected
        .iter()
        .any(|candidate| path == Path::new(candidate))
    {
        return Err(invalid());
    }
    trusted_binary(&path)?;
    let executing = fs::metadata(&proc_exe)?;
    let installed = fs::metadata(&path)?;
    if (executing.dev(), executing.ino()) != (installed.dev(), installed.ino()) {
        return Err(invalid());
    }
    Ok(path)
}

/// Match conservatively, including switches after `--`, single dashes and unusual
/// case. Values are never logged, returned, or used as identity.
///
/// Chrome and Chromium rewrite their process title on Linux: `/proc/PID/cmdline`
/// then holds one NUL-terminated string, the arguments joined with spaces. So every
/// whitespace-separated word of every string is checked, `argv[0]` too. A value that
/// contains a space and a switch-like word is refused: this refuses more than the
/// browser reads, never less.
fn safe_arguments(bytes: &[u8]) -> bool {
    if bytes.is_empty() || bytes.last() != Some(&0) {
        return false;
    }
    !bytes
        .split(|b| *b == 0 || b.is_ascii_whitespace())
        .any(|arg| {
            let Some(first) = arg.first() else {
                return false;
            };
            if *first != b'-' {
                return false;
            }
            let switch = arg
                .iter()
                .copied()
                .skip_while(|b| *b == b'-')
                .take_while(|b| *b != b'=')
                .map(|b| b.to_ascii_lowercase())
                .collect::<Vec<_>>();
            switch.starts_with(b"remote-debugging")
                || switch == b"load-extension"
                || switch == b"disable-extensions-except"
                || switch == b"type"
        })
}

#[cfg(target_os = "linux")]
fn browser(pid: u32, uid: u32) -> io::Result<()> {
    let before = process(pid, uid)?;
    let path = image(pid, BROWSERS)?;
    if !safe_arguments(&bounded(Path::new(&format!("/proc/{pid}/cmdline")))?) {
        return Err(invalid());
    }
    if before != process(pid, uid)? || path != image(pid, BROWSERS)? {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn owner_uid() -> io::Result<u32> {
    let uid = rustix::process::getuid().as_raw();
    if uid == 0 || rustix::process::geteuid().as_raw() != uid {
        return Err(invalid());
    }
    Ok(uid)
}

#[cfg(target_os = "linux")]
pub(super) fn check_browser_parent() -> Result<(), WireError> {
    (|| -> io::Result<()> {
        let uid = owner_uid()?;
        let pid = std::process::id();
        image(pid, &[HOST])?;
        let before = process(pid, uid)?;
        browser(before.parent, uid)?;
        if before != process(pid, uid)? {
            return Err(invalid());
        }
        Ok(())
    })()
    .map_err(|_| super::refused())
}

/// True when procfs hides `pid`'s executable because the task is not dumpable:
/// the kernel then gives the `exe` link (and the other per-process files) to root.
/// The `/proc/PID` directory itself keeps the task's effective user even then
/// (`task_dump_owner` exempts world-readable directories), so it cannot tell a
/// hardened peer from any other refusal.
#[cfg(target_os = "linux")]
fn exe_hidden_by_kernel(pid: u32) -> io::Result<bool> {
    Ok(fs::symlink_metadata(format!("/proc/{pid}/exe"))?.uid() == 0)
}

#[cfg(target_os = "linux")]
pub(super) fn check_peer(stream: &UnixStream) -> Result<(), WireError> {
    (|| -> io::Result<()> {
        let uid = owner_uid()?;
        let credentials = rustix::net::sockopt::socket_peercred(stream)?;
        if credentials.uid.as_raw() != uid {
            return Err(invalid());
        }
        let pid = credentials.pid.as_raw_nonzero().get() as u32;
        // Hold a kernel PID handle throughout the snapshot checks. A vanished peer
        // or old kernel without pidfd support fails closed.
        let _peer =
            rustix::process::pidfd_open(credentials.pid, rustix::process::PidfdFlags::empty())?;
        let before = process(pid, uid)?;
        match fs::read_link(format!("/proc/{pid}/exe")) {
            Ok(_) => {
                image(pid, &[HOST])?;
            }
            Err(error)
                if error.kind() == io::ErrorKind::PermissionDenied
                    && exe_hidden_by_kernel(pid)? => {}
            Err(error) => return Err(error),
        }
        browser(before.parent, uid)?;
        if before != process(pid, uid)? {
            return Err(invalid());
        }
        Ok(())
    })()
    .map_err(|_| super::refused())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stat(state: &str, parent: &str, start: &str) -> String {
        format!(
            "42 (not a (browser)) {state} {parent} {} {start} 0 0",
            vec!["0"; 17].join(" ")
        )
    }

    #[test]
    fn kernel_stat_uses_fields_not_process_names_and_rejects_dead_processes() {
        assert_eq!(parse_stat(&stat("S", "7", "123")).unwrap(), (7, 123));
        for value in [
            stat("Z", "7", "123"),
            stat("X", "7", "123"),
            stat("S", "0", "123"),
            stat("S", "7", "0"),
            "42 (chrome) S 7".into(),
        ] {
            assert!(parse_stat(&value).is_err(), "{value}");
        }
    }

    #[test]
    fn all_kernel_user_ids_must_be_present_and_unambiguous() {
        assert_eq!(
            parse_uids("Name:\tchrome\nUid:\t1000 1000 1000 1000\n").unwrap(),
            [1000; 4]
        );
        for value in [
            "Uid:\t1000 1000 1000\n",
            "Uid:\t1000 1000 1000 1000\nUid:\t0 0 0 0\n",
            "Name:\tchrome\n",
            "Uid:\tx 1 1 1\n",
        ] {
            assert!(parse_uids(value).is_err());
        }
    }

    #[test]
    fn only_root_owned_nonwritable_regular_executables_are_trusted() {
        assert!(safe_mode(0, 0o100755, true));
        assert!(!safe_mode(1000, 0o100755, true));
        assert!(!safe_mode(0, 0o100775, true));
        assert!(!safe_mode(0, 0o100757, true));
        assert!(!safe_mode(0, 0o104755, true));
        assert!(!safe_mode(0, 0o100644, true));
        assert!(
            trusted_binary(&std::env::current_exe().unwrap()).is_err(),
            "a source-build executable cannot be trusted"
        );
        assert!(
            trusted_binary(Path::new("/proc/self/exe")).is_err(),
            "a symlink cannot be an installed executable path"
        );
        assert!(trusted_binary(Path::new("target/debug/apassy-browser-host")).is_err());
        assert!(
            !BROWSERS.contains(&"/usr/bin/google-chrome"),
            "wrappers are not executable identities"
        );
    }

    #[test]
    fn unsafe_switches_fail_closed_without_disclosing_their_values() {
        assert!(safe_arguments(
            b"/opt/google/chrome/chrome\0--profile-directory=Default\0"
        ));
        for switch in [
            "--remote-debugging-port=9223",
            "-remote-debugging-pipe",
            "---REMOTE-DEBUGGING-address=secret",
            "--load-extension=/secret",
            "--disable-extensions-except=/secret",
            "--type=renderer",
        ] {
            assert!(
                !safe_arguments(format!("chrome\0--\0{switch}\0").as_bytes()),
                "{switch}"
            );
        }
        assert!(!safe_arguments(b""));
        assert!(!safe_arguments(b"chrome\0--remote-debugging-port=0"));
    }

    /// Chrome 157 on Ubuntu 24.04, started with `--remote-debugging-port=9333`, showed
    /// this exact `/proc/PID/cmdline`: one string after its process-title rewrite.
    #[test]
    fn rewritten_browser_titles_are_checked_word_by_word() {
        assert!(safe_arguments(b"/opt/google/chrome/chrome\0"));
        assert!(safe_arguments(
            b"/opt/google/chrome/chrome --profile-directory=Default http://localhost:4174/\0"
        ));
        for title in [
            &b"/opt/google/chrome/chrome --remote-debugging-port=9333 http://localhost:4174/passkey.html\0"[..],
            b"/usr/lib/chromium/chromium --show-component-extension-options --load-extension=/tmp/x\0",
            b"/opt/google/chrome/chrome\t--disable-extensions-except=/tmp/x\0",
            b"/opt/google/chrome/chrome --type=utility --utility-sub-type=x\0",
            b"--remote-debugging-pipe\0",
        ] {
            assert!(!safe_arguments(title), "{}", String::from_utf8_lossy(title));
        }
    }

    /// Set by [`hidden_exe_of_a_non_dumpable_peer_is_recognized`] for its child.
    #[cfg(target_os = "linux")]
    const NON_DUMPABLE_CHILD: &str = "APASSY_TEST_NON_DUMPABLE_CHILD";

    /// Child mode of the test below: become non-dumpable, as the hardened host does,
    /// and wait until the parent closes standard input. A no-op in a normal run.
    #[cfg(target_os = "linux")]
    #[test]
    fn non_dumpable_child_process() {
        if std::env::var_os(NON_DUMPABLE_CHILD).is_none() {
            return;
        }
        rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
            .unwrap();
        let mut rest = Vec::new();
        let _ = io::stdin().read_to_end(&mut rest);
    }

    /// The real hardened host is non-dumpable. The app must still recognize the kernel
    /// refusal for it: the `/proc/PID` directory keeps the user of the task, only the
    /// files in it become root's (found in the Linux acceptance, 2026-11-10).
    #[cfg(target_os = "linux")]
    #[test]
    fn hidden_exe_of_a_non_dumpable_peer_is_recognized() {
        use std::process::{Command, Stdio};
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "browser::caller::linux::tests::non_dumpable_child_process",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(NON_DUMPABLE_CHILD, "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while !exe_hidden_by_kernel(pid).unwrap() {
            assert!(
                std::time::Instant::now() < deadline,
                "the child stayed dumpable"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let error = fs::read_link(format!("/proc/{pid}/exe")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(
            fs::metadata(format!("/proc/{pid}")).unwrap().uid(),
            rustix::process::getuid().as_raw(),
            "the directory owner does not reveal a non-dumpable task"
        );
        drop(child.stdin.take());
        assert!(child.wait().unwrap().success());
        // A dumpable process of the same user shows its executable.
        let mut plain = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        assert!(!exe_hidden_by_kernel(plain.id()).unwrap());
        plain.kill().unwrap();
        plain.wait().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn real_kernel_peer_credentials_cannot_turn_a_test_process_into_a_browser_host() {
        let (one, _two) = UnixStream::pair().unwrap();
        let credentials = rustix::net::sockopt::socket_peercred(&one).unwrap();
        assert_eq!(
            credentials.pid.as_raw_nonzero().get() as u32,
            std::process::id()
        );
        assert_eq!(check_peer(&one).unwrap_err().code, "unsupported");
        assert_eq!(check_browser_parent().unwrap_err().code, "unsupported");
    }
}
