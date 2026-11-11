//! Linux optional conveniences. Passphrase authentication never depends on either
//! service. Only a successful, non-cached auth_self policy result grants presence.
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

use super::AuthCancel;

/// Screen lock, sleep and session observation over D-Bus (systemd-logind, screen saver).
#[cfg(feature = "session-bus")]
pub mod session_bus;

pub const KEYRING_WARNING: &str = "Store this vault passphrase in Secret Service? Other programs running as your user can retrieve it while the keyring is unlocked. This does not provide biometric protection.";
const MAX_SECRET: usize = 4096;

fn trusted_program(path: &Path) -> Result<(), String> {
    for component in path.ancestors() {
        let meta = fs::symlink_metadata(component).map_err(|_| "System helper unavailable")?;
        if meta.file_type().is_symlink() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            return Err("System helper is not root-owned and protected".into());
        }
    }
    Ok(())
}

/// Fixed system paths; no shell, PATH lookup, inherited output or secret arguments.
fn run(
    program: &str,
    args: &[&str],
    input: Option<&str>,
    cancel: Option<&AuthCancel>,
) -> Result<Zeroizing<Vec<u8>>, String> {
    trusted_program(Path::new(program))?;
    if cancel.is_some_and(AuthCancel::is_cancelled) {
        return Err("Authentication cancelled".into());
    }
    let mut command = Command::new(program);
    command.env_clear();
    for key in [
        "HOME",
        "DBUS_SESSION_BUS_ADDRESS",
        "XDG_RUNTIME_DIR",
        "DISPLAY",
        "WAYLAND_DISPLAY",
        "XAUTHORITY",
        "LANG",
        "LC_ALL",
    ] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    let mut child = command
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "System helper unavailable")?;
    if let Some(secret) = input {
        let result = child
            .stdin
            .take()
            .ok_or("Missing helper input")
            .and_then(|mut pipe| {
                pipe.write_all(secret.as_bytes())
                    .map_err(|_| "Helper input failed")
            });
        if result.is_err() {
            let _ = child.kill();
            let _ = child.wait();
            return Err("Helper input failed".into());
        }
    }
    let output = child.stdout.take().ok_or("Missing helper output")?;
    let reader = std::thread::spawn(move || {
        let mut bytes = Zeroizing::new(Vec::new());
        output
            .take((MAX_SECRET + 1) as u64)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let started = Instant::now();
    let status = loop {
        if cancel.is_some_and(AuthCancel::is_cancelled)
            || started.elapsed() > Duration::from_secs(120)
        {
            let _ = child.kill();
            let _ = child.wait();
            break Err("Authentication cancelled or timed out");
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                break if status.success() {
                    Ok(())
                } else {
                    Err("System authentication or keyring request refused")
                };
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(25)),
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                break Err("System helper failed");
            }
        }
    };
    let bytes = reader
        .join()
        .map_err(|_| "Helper output failed")?
        .map_err(|_| "Helper output failed")?;
    status?;
    if cancel.is_some_and(AuthCancel::is_cancelled) || bytes.len() > MAX_SECRET {
        return Err("System helper result refused".into());
    }
    Ok(bytes)
}

/// The process subject includes kernel start time and UID, never an external PID.
/// The installed policy must use auth_self (not auth_self_keep), for every request.
pub fn authenticate(cancel: Option<&AuthCancel>) -> Result<(), String> {
    let stat = fs::read_to_string("/proc/self/stat").map_err(|_| "Cannot identify this process")?;
    let start = process_start(&stat).ok_or("Cannot identify this process")?;
    let subject = format!(
        "{},{},{}",
        std::process::id(),
        start,
        rustix::process::getuid().as_raw()
    );
    run("/usr/bin/pkcheck", &pkcheck_args(&subject), None, cancel)?;
    Ok(())
}

/// The polkit request. No `--detail`: polkitd refuses details from a caller that is
/// not root or the action owner ("Only trusted callers ... can use
/// CheckAuthorization() and pass details"), so a detail would fail every check. The
/// agent shows the fixed message of the action; Apassy's window shows the purpose.
fn pkcheck_args(subject: &str) -> [&str; 5] {
    [
        "--action-id",
        "com.wydrox.apassy.owner-presence",
        "--process",
        subject,
        "--allow-user-interaction",
    ]
}

fn process_start(stat: &str) -> Option<u64> {
    // comm can contain spaces and parentheses. Field 22 is index 19 after comm.
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

fn account(path: &Path) -> Result<String, String> {
    let canonical = fs::canonicalize(path).map_err(|_| "Cannot resolve vault file")?;
    // Use the full canonical path rather than a non-cryptographic hash key.
    canonical
        .to_str()
        .map(str::to_owned)
        .ok_or("Vault path is not UTF-8".into())
}

/// Call only following explicit user consent to KEYRING_WARNING. The passphrase is
/// supplied on a pipe, never through argv, an environment variable or a shell.
pub fn store_passphrase(path: &Path, passphrase: &str, consent: bool) -> Result<(), String> {
    if !consent {
        return Err("Secret Service storage requires explicit consent".into());
    }
    if passphrase.is_empty() || passphrase.len() >= MAX_SECRET || passphrase.contains(['\n', '\r'])
    {
        return Err("Passphrase cannot be stored in Secret Service".into());
    }
    let account = account(path)?;
    run(
        "/usr/bin/secret-tool",
        &[
            "store",
            "--label=Apassy vault unlock (same-user access)",
            "application",
            "apassy",
            "vault",
            &account,
        ],
        Some(passphrase),
        None,
    )?;
    Ok(())
}

/// Explicit keyring unlock only; never silently falls back to keyring lookup.
pub fn read_passphrase(path: &Path) -> Result<Zeroizing<String>, String> {
    let account = account(path)?;
    let mut bytes = run(
        "/usr/bin/secret-tool",
        &["lookup", "application", "apassy", "vault", &account],
        None,
        None,
    )?;
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    if bytes.is_empty() {
        return Err("No keyring unlock item exists".into());
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| "Invalid keyring unlock item")?;
    Ok(Zeroizing::new(text.to_owned()))
}

/// True when `/usr/bin/secret-tool` is installed. Without it Apassy never stored a
/// keyring unlock item: [`store_passphrase`] runs that program.
pub fn secret_tool_installed() -> bool {
    Path::new("/usr/bin/secret-tool").is_file()
}

pub fn delete_passphrase(path: &Path) -> Result<(), String> {
    let account = account(path)?;
    run(
        "/usr/bin/secret-tool",
        &["clear", "application", "apassy", "vault", &account],
        None,
        None,
    )?;
    Ok(())
}

/// The Secret Service attributes of the Apassy Connect key of this computer (one key
/// for each user, outside every vault).
const CONNECT_KEY_ATTRIBUTES: [&str; 4] = ["application", "apassy", "connect", "device-key"];

/// Call only following explicit user consent to `crate::connect::key_file::KEYRING_WARNING`.
/// `text` is the base64 text of the key; it goes on a pipe, never through argv, an
/// environment variable or a shell.
pub fn store_connect_key(text: &str, consent: bool) -> Result<(), String> {
    if !consent {
        return Err("Secret Service storage requires explicit consent".into());
    }
    if text.is_empty() || text.len() >= MAX_SECRET || text.contains(['\n', '\r']) {
        return Err("The Connect key cannot be stored in Secret Service".into());
    }
    let mut args = vec!["store", "--label=Apassy Connect key (same-user access)"];
    args.extend(CONNECT_KEY_ATTRIBUTES);
    run("/usr/bin/secret-tool", &args, Some(text), None)?;
    Ok(())
}

/// The Connect key text of the opt-in store. `secret-tool` ends the same way for no
/// item and for a refused lookup, so both are `None`: the account then shows as removed
/// on this computer, and nothing is deleted.
pub fn read_connect_key() -> Result<Option<Zeroizing<String>>, String> {
    let mut args = vec!["lookup"];
    args.extend(CONNECT_KEY_ATTRIBUTES);
    let Ok(mut bytes) = run("/usr/bin/secret-tool", &args, None, None) else {
        return Ok(None);
    };
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    if bytes.is_empty() {
        return Ok(None);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| "Invalid keyring Connect item")?;
    Ok(Some(Zeroizing::new(text.to_owned())))
}

/// Delete the Connect key of the opt-in store. True when the lookup found one before.
pub fn delete_connect_key() -> Result<bool, String> {
    let existed = read_connect_key()?.is_some();
    let mut args = vec!["clear"];
    args.extend(CONNECT_KEY_ATTRIBUTES);
    run("/usr/bin/secret-tool", &args, None, None)?;
    Ok(existed)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_consent_never_contacts_keyring() {
        assert!(
            store_passphrase(Path::new("/nonexistent"), "synthetic", false)
                .unwrap_err()
                .contains("consent")
        );
    }
    #[test]
    fn polkit_request_names_the_action_and_process_without_details() {
        let args = pkcheck_args("123,456,1000");
        assert_eq!(
            args,
            [
                "--action-id",
                "com.wydrox.apassy.owner-presence",
                "--process",
                "123,456,1000",
                "--allow-user-interaction",
            ]
        );
        // An unprivileged caller that passes details is refused by polkitd itself.
        assert!(!args.contains(&"--detail"));
    }
    #[test]
    fn process_start_handles_parentheses_in_comm() {
        let stat = format!(
            "123 (a ) tricky) S {} 987 0",
            (1..=18)
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join(" ")
        );
        assert_eq!(process_start(&stat), Some(987));
        assert_eq!(process_start("bad"), None);
    }
}
