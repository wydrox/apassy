//! The fresh-token sheet saves host settings on a worker. A saved configuration
//! is not evidence of an MCP connection. Child output never reaches the UI/logs.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::{Duration, Instant};

use eframe::egui;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Host {
    Claude,
    Codex,
}

impl Host {
    pub(super) fn from_index(index: usize) -> Self {
        if index == 1 {
            Self::Codex
        } else {
            Self::Claude
        }
    }

    pub(super) fn index(self) -> usize {
        usize::from(self == Self::Codex)
    }

    pub(super) fn id(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
        }
    }

    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Claude => "Claude Code",
            Self::Codex => "Codex",
        }
    }
}

struct Pending {
    host: Host,
    answer: Receiver<Result<(), String>>,
    cancel: Arc<AtomicBool>,
}

impl Drop for Pending {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}

#[derive(Default)]
pub(super) struct SetupState {
    identity: Option<[u8; 32]>,
    pending: Option<Pending>,
    pub(super) result: Option<Result<Host, String>>,
    pub(super) advanced: bool,
}

impl SetupState {
    /// Keep no extra plaintext token in UI state. Each new token starts a new
    /// sheet, including a rotation for an agent with the same name.
    pub(super) fn prepare(&mut self, token: &str, agent_name: &str, host: &mut usize) {
        let digest = ring::digest::digest(&ring::digest::SHA256, token.as_bytes());
        let mut identity = [0; 32];
        identity.copy_from_slice(digest.as_ref());
        if self.identity != Some(identity) {
            *self = Self::default();
            self.identity = Some(identity);
            let name = agent_name.trim().to_ascii_lowercase();
            if name.contains("codex") {
                *host = Host::Codex.index();
            } else if name.contains("claude") {
                *host = Host::Claude.index();
            }
        }
    }

    pub(super) fn busy(&self) -> bool {
        self.pending.is_some()
    }

    pub(super) fn poll(&mut self, ctx: &egui::Context) {
        let Some(pending) = &self.pending else { return };
        let result = match pending.answer.try_recv() {
            Ok(result) => result,
            Err(TryRecvError::Empty) => {
                ctx.request_repaint_after(Duration::from_millis(100));
                return;
            }
            Err(TryRecvError::Disconnected) => {
                Err("Setup stopped. Try again or use Advanced setup.".to_owned())
            }
        };
        let host = pending.host;
        self.pending = None;
        self.result = Some(result.map(|()| host));
    }

    pub(super) fn start(&mut self, host: Host, token: &str, ctx: &egui::Context) {
        self.start_with(host, token, ctx, setup);
    }

    fn start_with(
        &mut self,
        host: Host,
        token: &str,
        ctx: &egui::Context,
        operation: impl FnOnce(Host, Zeroizing<String>, Arc<AtomicBool>) -> Result<(), String>
        + Send
        + 'static,
    ) {
        if self.busy() {
            return;
        }
        let token = Zeroizing::new(token.to_owned());
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancel);
        let (reply, answer) = mpsc::channel();
        let repaint = ctx.clone();
        match std::thread::Builder::new()
            .name("apassy-agent-setup".to_owned())
            .spawn(move || {
                let result = operation(host, token, worker_cancel);
                let _ = reply.send(result);
                repaint.request_repaint();
            }) {
            Ok(_) => {
                self.pending = Some(Pending {
                    host,
                    answer,
                    cancel,
                });
                self.result = None;
            }
            Err(_) => {
                self.result = Some(Err(
                    "Cannot start setup. Try again or use Advanced setup.".to_owned()
                ))
            }
        }
    }
}

/// Finder launches can have a minimal PATH. Include the usual host installation
/// folders without evaluating shell profiles or changing this process's PATH.
fn host_path(
    home: &Path,
    inherited: Option<std::ffi::OsString>,
) -> Result<std::ffi::OsString, String> {
    let mut paths = vec![
        home.join(".local/bin"),
        PathBuf::from("/opt/homebrew/bin"),
        PathBuf::from("/usr/local/bin"),
    ];
    if let Some(inherited) = inherited {
        paths.extend(std::env::split_paths(&inherited));
    }
    // Pi-managed Node uses a stable `current` link for its installed host CLIs.
    paths.push(home.join(".local/share/pi-node/current/bin"));
    paths.extend([PathBuf::from("/usr/bin"), PathBuf::from("/bin")]);
    std::env::join_paths(paths).map_err(|_| "Cannot read PATH. Use Advanced setup.".to_owned())
}

fn executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

fn setup(host: Host, token: Zeroizing<String>, cancel: Arc<AtomicBool>) -> Result<(), String> {
    let exe = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .map_err(|_| "Cannot find Apassy. Use Advanced setup.".to_owned())?;
    let directory = exe
        .parent()
        .ok_or("Cannot find the app tools. Reinstall Apassy.app.")?;
    for tool in ["apassy-mcp", "apassy-hook"] {
        if !executable(&directory.join(tool)) {
            return Err(format!(
                "The app package needs {tool}. Reinstall the complete Apassy.app package."
            ));
        }
    }
    let home = std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .ok_or("Cannot find your home folder. Use Advanced setup.")?;
    let path = host_path(Path::new(&home), std::env::var_os("PATH"))?;
    if !std::env::split_paths(&path).any(|directory| executable(&directory.join(host.id()))) {
        return Err(format!("Install {}. Then try again.", host.name()));
    }
    let mut command = Command::new(exe);
    command.env("PATH", path);
    run_command(command, host, token, &cancel, Duration::from_secs(30))
}

fn stop(child: &mut std::process::Child) {
    // The CLI can start a host process. Stop the private group on timeout too.
    if let Some(pid) = rustix::process::Pid::from_raw(child.id() as i32) {
        let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn run_command(
    mut command: Command,
    host: Host,
    token: Zeroizing<String>,
    cancel: &AtomicBool,
    timeout: Duration,
) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::process::CommandExt;
    // Tokens are small. Keep the pipe write below its capacity, even if a
    // broken executable never reads stdin, so the timeout remains effective.
    if token.len() > 1024 || !token.starts_with("apassy_agt_") {
        return Err("The token is not valid. Use Advanced setup.".to_owned());
    }
    // This file contains only fixed status codes. It holds no child output.
    // The temporary directory and file stay private to this setup run.
    let status_directory = tempfile::tempdir()
        .map_err(|_| "Cannot prepare the setup result. Try again.".to_owned())?;
    let status_path = status_directory.path().join("status");
    let status_file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&status_path)
        .map_err(|_| "Cannot prepare the setup result. Try again.".to_owned())?;
    drop(status_file);
    // Never put the token in arguments, the environment, or child output.
    command
        .args([
            "setup",
            host.id(),
            "--token-stdin",
            "--write",
            "--desktop-status",
        ])
        .arg(&status_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0);
    if cancel.load(Ordering::Relaxed) {
        return Err("Setup stopped.".to_owned());
    }
    let mut child = command
        .spawn()
        .map_err(|_| "Cannot start Apassy setup. Use Advanced setup.".to_owned())?;
    let written = child
        .stdin
        .take()
        .ok_or(())
        .and_then(|mut stdin| stdin.write_all(token.as_bytes()).map_err(|_| ()));
    drop(token);
    if written.is_err() {
        stop(&mut child);
        return Err("Cannot send the token to setup. Try again or use Advanced setup.".to_owned());
    }
    let deadline = Instant::now() + timeout;
    loop {
        if cancel.load(Ordering::Relaxed) || Instant::now() >= deadline {
            stop(&mut child);
            return Err(
                "Setup stopped. Some settings can be saved. Try again or use Advanced setup."
                    .to_owned(),
            );
        }
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(_)) => return Err(read_failure_status(&status_path).to_owned()),
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(_) => {
                stop(&mut child);
                return Err("Cannot check the setup result. Use Advanced setup.".to_owned());
            }
        }
    }
}

/// Read a small allowlisted code. Never display file contents, even if a host
/// executable writes a token or an arbitrary diagnostic into this file.
fn read_failure_status(path: &Path) -> &'static str {
    let mut code = Zeroizing::new(Vec::new());
    let read = std::fs::File::open(path).and_then(|file| file.take(65).read_to_end(&mut code));
    if read.is_err() {
        return failure_message(b"");
    }
    failure_message(&code)
}

fn failure_message(code: &[u8]) -> &'static str {
    match code {
        b"missing_mcp" => {
            "The app package needs apassy-mcp. Reinstall the complete Apassy.app package."
        }
        b"missing_hook" => {
            "The app package needs apassy-hook. Reinstall the complete Apassy.app package."
        }
        b"home_missing" => "Cannot find your home folder. Use Advanced setup.",
        b"config_read" => {
            "Cannot read the host configuration. Check file permissions in Advanced setup."
        }
        b"config_invalid" => {
            "The host configuration is not valid. Correct it in Advanced setup, then try again."
        }
        b"config_conflict" => {
            "The host has different Apassy settings. Check the existing server in Advanced setup before you try again."
        }
        b"config_write" => {
            "Cannot save the host configuration. Some settings can be saved. Check file permissions in Advanced setup."
        }
        b"wrapper_write" => {
            "Cannot save the Apassy scripts. Check file permissions for ~/.config/apassy, then try again."
        }
        b"hooks_read" => {
            "Cannot read the host hook settings. Some settings can be saved. Check file permissions in Advanced setup."
        }
        b"hooks_invalid" => {
            "The host hook settings are not valid JSON. Some settings can be saved. Correct the hook settings in Advanced setup."
        }
        b"hooks_disabled" => {
            "The host settings disable all hooks. Enable hooks in the host settings, then try again."
        }
        b"hooks_write" => {
            "Cannot save the host hook settings. Some settings can be saved. Check file permissions in Advanced setup."
        }
        b"host_start" => {
            "Cannot start Claude Code. Check the installation with claude --version, then try again."
        }
        b"host_failed" => {
            "Claude Code did not add the Apassy server. Check claude mcp list and the existing server in Advanced setup."
        }
        b"host_verify" => {
            "Claude Code did not save the expected Apassy server. Check the existing server in Advanced setup."
        }
        b"token_read" => "Cannot read the agent token. Try again or use Advanced setup.",
        b"token_invalid" => "The agent token is not valid. Create a new token, then try again.",
        _ => {
            "Setup failed. Some settings can be saved. Check the host installation, then try again or use Advanced setup."
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_cli(directory: &Path, body: &str) -> Command {
        use std::os::unix::fs::PermissionsExt;
        let path = directory.join("apassy");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut command = Command::new(path);
        // No process-wide environment changes and no real host configuration.
        command.env("HOME", directory);
        command
    }

    #[test]
    fn runner_sends_the_existing_token_only_on_stdin() {
        let home = tempfile::tempdir().unwrap();
        let command = fake_cli(
            home.path(),
            "printf '%s\\n' \"$@\" > \"$HOME/args\"\ncat > \"$HOME/token\"",
        );
        run_command(
            command,
            Host::Claude,
            Zeroizing::new("apassy_agt_test-secret".to_owned()),
            &AtomicBool::new(false),
            Duration::from_secs(2),
        )
        .unwrap();
        let args = std::fs::read_to_string(home.path().join("args")).unwrap();
        let args: Vec<_> = args.lines().collect();
        assert_eq!(
            &args[..5],
            &[
                "setup",
                "claude",
                "--token-stdin",
                "--write",
                "--desktop-status"
            ]
        );
        assert_eq!(args.len(), 6);
        assert!(Path::new(args[5]).is_absolute());
        assert!(!Path::new(args[5]).exists());
        assert!(!args[5].contains("test-secret"));
        assert_eq!(
            std::fs::read_to_string(home.path().join("token")).unwrap(),
            "apassy_agt_test-secret"
        );
    }

    #[test]
    fn runner_discards_sensitive_child_output_and_reports_failure() {
        let home = tempfile::tempdir().unwrap();
        let command = fake_cli(
            home.path(),
            "token=$(cat)\nprintf '%s' \"$token\"\nprintf '%s' \"$token\" >&2\nexit 7",
        );
        let error = run_command(
            command,
            Host::Codex,
            Zeroizing::new("apassy_agt_test-secret".to_owned()),
            &AtomicBool::new(false),
            Duration::from_secs(2),
        )
        .unwrap_err();
        assert!(error.contains("Setup failed"));
        assert!(error.contains("Advanced setup"));
        assert!(!error.contains("test-secret"));
    }

    #[test]
    fn runner_reports_only_allowlisted_failure_status() {
        for code in [
            "config_conflict",
            "config_write",
            "hooks_invalid",
            "hooks_disabled",
            "host_failed",
        ] {
            let home = tempfile::tempdir().unwrap();
            let command = fake_cli(
                home.path(),
                &format!(
                    "token=$(cat)\nprintf '%s' \"$token\" >&2\nprintf '%s' '{code}' > \"$6\"\nexit 1"
                ),
            );
            let error = run_command(
                command,
                Host::Codex,
                Zeroizing::new("apassy_agt_test-secret".to_owned()),
                &AtomicBool::new(false),
                Duration::from_secs(2),
            )
            .unwrap_err();
            assert_eq!(error, failure_message(code.as_bytes()));
            assert!(!error.contains("test-secret"));
        }
    }

    #[test]
    fn runner_discards_sensitive_and_oversized_status_contents() {
        let home = tempfile::tempdir().unwrap();
        for body in [
            "token=$(cat)\nprintf '%s' \"$token\" > \"$6\"\nexit 1",
            "cat > /dev/null\nprintf '%s' 'config_conflict\napassy_agt_secret' > \"$6\"\nexit 1",
            "cat > /dev/null\ni=0; while [ $i -lt 200 ]; do printf 'x' >> \"$6\"; i=$((i + 1)); done\nexit 1",
        ] {
            let command = fake_cli(home.path(), body);
            let error = run_command(
                command,
                Host::Codex,
                Zeroizing::new("apassy_agt_test-secret".to_owned()),
                &AtomicBool::new(false),
                Duration::from_secs(2),
            )
            .unwrap_err();
            assert_eq!(error, failure_message(b""));
            assert!(!error.contains("test-secret"));
        }
    }

    #[test]
    fn runner_times_out_and_reaps_a_stalled_cli() {
        let home = tempfile::tempdir().unwrap();
        let command = fake_cli(home.path(), "cat > /dev/null\nsleep 10");
        let started = Instant::now();
        let error = run_command(
            command,
            Host::Claude,
            Zeroizing::new("apassy_agt_test-secret".to_owned()),
            &AtomicBool::new(false),
            Duration::from_millis(60),
        )
        .unwrap_err();
        assert!(error.contains("Some settings can be saved"));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn worker_keeps_the_ui_available_and_retains_the_token_on_failure() {
        let ctx = egui::Context::default();
        let mut state = SetupState::default();
        let token = Zeroizing::new("apassy_agt_test-secret".to_owned());
        let (release, wait) = mpsc::channel();
        let (finished, finish) = mpsc::channel();
        state.start_with(Host::Codex, &token, &ctx, move |host, sent, _| {
            assert_eq!(host, Host::Codex);
            assert_eq!(&*sent, "apassy_agt_test-secret");
            wait.recv_timeout(Duration::from_secs(2)).unwrap();
            finished.send(()).unwrap();
            Err("Test failure".to_owned())
        });
        assert!(state.busy());
        state.poll(&ctx);
        assert!(state.result.is_none());
        assert_eq!(&*token, "apassy_agt_test-secret");
        release.send(()).unwrap();
        finish.recv_timeout(Duration::from_secs(2)).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while state.busy() && Instant::now() < deadline {
            state.poll(&ctx);
            std::thread::yield_now();
        }
        assert_eq!(state.result, Some(Err("Test failure".to_owned())));
        assert_eq!(&*token, "apassy_agt_test-secret");
    }

    #[test]
    fn new_tokens_reset_the_result_and_keep_advanced_setup_closed() {
        let mut state = SetupState::default();
        let mut host = 0;
        state.prepare("apassy_agt_first", "My Codex", &mut host);
        assert_eq!(host, 1);
        assert!(!state.advanced);
        state.result = Some(Ok(Host::Codex));
        state.advanced = true;
        state.prepare("apassy_agt_second", "Claude Code", &mut host);
        assert_eq!(host, 0);
        assert!(state.result.is_none());
        assert!(!state.advanced);
    }

    #[test]
    fn child_path_finds_standard_host_locations_without_shell_profiles() {
        let path = host_path(Path::new("/test/home"), Some("/custom/bin:/usr/bin".into())).unwrap();
        let paths: Vec<_> = std::env::split_paths(&path).collect();
        assert_eq!(paths[0], Path::new("/test/home/.local/bin"));
        assert!(paths.contains(&PathBuf::from("/opt/homebrew/bin")));
        assert!(paths.contains(&PathBuf::from("/usr/local/bin")));
        assert!(paths.contains(&PathBuf::from("/custom/bin")));
        assert!(paths.contains(&PathBuf::from(
            "/test/home/.local/share/pi-node/current/bin"
        )));
    }
}
