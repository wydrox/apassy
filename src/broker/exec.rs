//! Start one agent process with secrets in its environment (ADR 0006).
//!
//! The process gets a small base environment, the requested `PATH`, and the
//! bound secrets. There is no shell. Output is limited and masked. The masking
//! finds only exact secret values. It cannot stop a process that encodes or
//! sends a secret.

use std::io::{self, Read};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use std::os::unix::process::CommandExt;

/// Output bytes kept for each stream. The rest is read and dropped.
pub const MAX_OUTPUT_BYTES: usize = 64 * 1024;
/// Shorter secret values are not masked. They would damage ordinary output.
const MIN_MASK_BYTES: usize = 4;
const POLL: Duration = Duration::from_millis(50);
/// Time to collect output after the main process ends.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
/// Environment variables copied from the broker process.
const BASE_ENV: [&str; 6] = ["HOME", "USER", "LOGNAME", "SHELL", "TMPDIR", "LANG"];
const DEFAULT_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

/// One environment variable with a secret value. Debug is redacted.
pub struct SecretEnv {
    pub name: String,
    pub value: String,
}

impl std::fmt::Debug for SecretEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretEnv({}=[redacted])", self.name)
    }
}

impl Drop for SecretEnv {
    fn drop(&mut self) {
        self.value.clear();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOutput {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
    pub timed_out: bool,
}

/// Run `command` in `cwd`. `command[0]` is the program. The caller validates the input.
pub fn run(
    command: &[String],
    cwd: &Path,
    path: Option<&str>,
    secrets: &[SecretEnv],
    timeout: Duration,
) -> io::Result<RunOutput> {
    let (program, args) = command
        .split_first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "empty command"))?;
    let mut cmd = Command::new(program);
    cmd.args(args)
        .current_dir(cwd)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // A new process group lets the broker stop the child and its children.
        .process_group(0);
    for name in BASE_ENV {
        if let Some(value) = std::env::var_os(name) {
            cmd.env(name, value);
        }
    }
    cmd.env(
        "PATH",
        path.filter(|p| !p.is_empty()).unwrap_or(DEFAULT_PATH),
    );
    for secret in secrets {
        cmd.env(&secret.name, &secret.value);
    }
    let mut child = cmd.spawn()?;
    let stdout = spawn_reader(child.stdout.take());
    let stderr = spawn_reader(child.stderr.take());

    let deadline = Instant::now() + timeout;
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break Some(status);
        }
        if Instant::now() >= deadline {
            timed_out = true;
            stop_group(&mut child);
            break child.wait().ok();
        }
        thread::sleep(POLL);
    };

    let (out, out_cut) = collect(&stdout, &mut child);
    let (err, err_cut) = collect(&stderr, &mut child);
    Ok(RunOutput {
        exit_code: status.and_then(|status| status.code()),
        stdout: mask(&String::from_utf8_lossy(&out), secrets),
        stderr: mask(&String::from_utf8_lossy(&err), secrets),
        truncated: out_cut || err_cut,
        timed_out,
    })
}

type Collected = (Vec<u8>, bool);

fn spawn_reader<R: Read + Send + 'static>(pipe: Option<R>) -> mpsc::Receiver<Collected> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut kept = Vec::new();
        let mut cut = false;
        if let Some(mut pipe) = pipe {
            let mut buf = [0u8; 8192];
            loop {
                match pipe.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => {
                        let room = MAX_OUTPUT_BYTES.saturating_sub(kept.len());
                        if read > room {
                            cut = true;
                        }
                        kept.extend_from_slice(&buf[..read.min(room)]);
                    }
                }
            }
        }
        let _ = tx.send((kept, cut));
    });
    rx
}

/// Wait a short time for a stream. A child that keeps the pipe open is stopped.
fn collect(rx: &mpsc::Receiver<Collected>, child: &mut Child) -> Collected {
    if let Ok(result) = rx.recv_timeout(DRAIN_TIMEOUT) {
        return result;
    }
    stop_group(child);
    rx.recv_timeout(DRAIN_TIMEOUT).unwrap_or((Vec::new(), true))
}

/// Stop the process group. The `kill` program avoids unsafe code in this crate.
fn stop_group(child: &mut Child) {
    let group = format!("-{}", child.id());
    let _ = Command::new("/bin/kill")
        .args(["-KILL", "--", &group])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let _ = child.kill();
}

/// Replace each secret value with `[apassy:NAME]`. Longer values go first.
pub fn mask(text: &str, secrets: &[SecretEnv]) -> String {
    let mut ordered: Vec<&SecretEnv> = secrets
        .iter()
        .filter(|secret| secret.value.len() >= MIN_MASK_BYTES)
        .collect();
    ordered.sort_by_key(|secret| std::cmp::Reverse(secret.value.len()));
    let mut out = text.to_owned();
    for secret in ordered {
        out = out.replace(&secret.value, &format!("[apassy:{}]", secret.name));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(name: &str, value: &str) -> SecretEnv {
        SecretEnv {
            name: name.to_owned(),
            value: value.to_owned(),
        }
    }

    #[test]
    fn process_sees_secret_and_output_is_masked() {
        let secrets = [secret("DEMO_TOKEN", "FAKE-value-123")];
        let command = [
            "/bin/sh".to_owned(),
            "-c".to_owned(),
            "printf 'len=%s\\n' \"${#DEMO_TOKEN}\"; echo \"$DEMO_TOKEN\"; echo \"$DEMO_TOKEN\" >&2; echo \"path=$PATH\"".to_owned(),
        ];
        let out = run(
            &command,
            Path::new("/tmp"),
            Some("/usr/bin:/bin"),
            &secrets,
            Duration::from_secs(10),
        )
        .expect("run");
        assert_eq!(out.exit_code, Some(0));
        assert!(out.stdout.contains("len=14"), "{out:?}");
        assert!(out.stdout.contains("[apassy:DEMO_TOKEN]"));
        assert!(out.stderr.contains("[apassy:DEMO_TOKEN]"));
        assert!(!out.stdout.contains("FAKE-value-123"));
        assert!(!out.stderr.contains("FAKE-value-123"));
        assert!(out.stdout.contains("path=/usr/bin:/bin"));
    }

    #[test]
    fn timeout_stops_the_process_group() {
        let command = [
            "/bin/sh".to_owned(),
            "-c".to_owned(),
            "sleep 30 & sleep 30".to_owned(),
        ];
        let started = Instant::now();
        let out = run(
            &command,
            Path::new("/tmp"),
            None,
            &[],
            Duration::from_millis(300),
        )
        .expect("run");
        assert!(out.timed_out);
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn mask_prefers_longer_values_and_skips_short_ones() {
        let secrets = [
            secret("A", "abcd"),
            secret("B", "abcdef"),
            secret("C", "xy"),
        ];
        assert_eq!(mask("abcdef abcd xy", &secrets), "[apassy:B] [apassy:A] xy");
    }
}
