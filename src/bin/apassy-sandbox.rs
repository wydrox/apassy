//! Launcher that starts an agent host inside the Apassy Seatbelt profile.
//!
//! It resolves the protected paths, finds the SBPL profile, and replaces
//! itself with `/usr/bin/sandbox-exec`. The host (Claude Code, Codex) and every
//! command that the host starts then run inside the profile. They cannot read,
//! copy, or replace the vault, the backup, or the Laya model. They can still
//! connect to the broker socket, so `apassy-mcp` keeps working.
//!
//! Usage:
//!   apassy-sandbox [OPTIONS] -- <host> [host args...]
//!
//! Options (each value is an absolute path):
//!   --data-dir DIR      The Apassy data directory. Default:
//!                       `$HOME/Library/Application Support/Apassy`.
//!   --vault-file FILE   The vault database. Default: `<data-dir>/vault.db`.
//!   --backup-file FILE  The backup database. Default: `<vault-file>.backup`.
//!   --socket FILE       The broker socket. Default: `$APASSY_BROKER_SOCKET`,
//!                       else `<data-dir>/broker.sock`.
//!   --profile FILE      The SBPL profile. Default: `$APASSY_SANDBOX_PROFILE`,
//!                       else a file found next to this program or in `sandbox/`.
//!   --print             Print the resolved sandbox-exec command. Do not run it.
//!   -h, --help          Print this help.
//!
//! The host name and its arguments follow `--`. Set the host environment (for
//! example `APASSY_AGENT_TOKEN`) before you start this launcher; the launcher
//! passes the environment through to the host.
//!
//! This program uses only `std` and no `unsafe`. `CommandExt::exec` replaces the
//! process image; it is a safe call that returns an error if the exec fails.

use std::env;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The system Seatbelt front end. Apple marks it deprecated but ships it.
const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";
/// The profile file name that the launcher looks for near the program.
const PROFILE_NAME: &str = "apassy-agent-host.sb";
/// Environment override for the profile path.
const PROFILE_ENV: &str = "APASSY_SANDBOX_PROFILE";
/// Environment override for the broker socket path. It matches the client.
const SOCKET_ENV: &str = "APASSY_BROKER_SOCKET";

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => {}
        Err(message) => {
            eprintln!("apassy-sandbox: {message}");
            std::process::exit(2);
        }
    }
}

/// Parse the arguments, resolve the paths, and exec `sandbox-exec`. On success
/// this call does not return, because it replaces the process image.
fn run(args: &[String]) -> Result<(), String> {
    let parsed = parse(args)?;
    if parsed.help {
        print!("{HELP}");
        return Ok(());
    }
    if parsed.host.is_empty() {
        return Err("no host command. Put the host after `--`. See --help.".to_owned());
    }

    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|home| !home.as_os_str().is_empty());

    let data_dir = match parsed.data_dir {
        Some(path) => PathBuf::from(path),
        None => {
            let home = home
                .clone()
                .ok_or("HOME is not set, so --data-dir is required")?;
            home.join("Library")
                .join("Application Support")
                .join("Apassy")
        }
    };
    let vault_file = parsed
        .vault_file
        .map_or_else(|| data_dir.join("vault.db"), PathBuf::from);
    let backup_file = parsed.backup_file.map_or_else(
        || {
            let mut name = vault_file.clone().into_os_string();
            name.push(".backup");
            PathBuf::from(name)
        },
        PathBuf::from,
    );
    let socket = parsed
        .socket
        .map(PathBuf::from)
        .or_else(|| env::var_os(SOCKET_ENV).map(PathBuf::from))
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| data_dir.join("broker.sock"));

    let profile = resolve_profile(parsed.profile.as_deref())?;

    // Resolve symlinks in each path. Seatbelt matches the resolved path, and on
    // macOS `/var` and `/tmp` are symlinks. Resolve the deepest ancestor that
    // exists, then re-add the missing tail, because a socket or a backup may
    // not exist yet.
    let data_dir = resolve(&data_dir);
    let vault_file = resolve(&vault_file);
    let backup_file = resolve(&backup_file);
    let socket = resolve(&socket);

    let mut command = Command::new(SANDBOX_EXEC);
    command.arg("-f").arg(&profile);
    command.arg("-D").arg(param("APASSY_DATA_DIR", &data_dir)?);
    command
        .arg("-D")
        .arg(param("APASSY_VAULT_FILE", &vault_file)?);
    command
        .arg("-D")
        .arg(param("APASSY_BACKUP_FILE", &backup_file)?);
    command.arg("-D").arg(param("APASSY_SOCKET", &socket)?);
    command.arg(&parsed.host[0]);
    command.args(&parsed.host[1..]);

    if parsed.print {
        print_command(
            &profile,
            &data_dir,
            &vault_file,
            &backup_file,
            &socket,
            &parsed.host,
        );
        return Ok(());
    }

    // Replace the process image. This call returns only on failure.
    let error = command.exec();
    Err(format!("cannot start {SANDBOX_EXEC}: {error}"))
}

/// The parsed command line.
struct Parsed {
    data_dir: Option<String>,
    vault_file: Option<String>,
    backup_file: Option<String>,
    socket: Option<String>,
    profile: Option<String>,
    print: bool,
    help: bool,
    host: Vec<String>,
}

fn parse(args: &[String]) -> Result<Parsed, String> {
    let mut parsed = Parsed {
        data_dir: None,
        vault_file: None,
        backup_file: None,
        socket: None,
        profile: None,
        print: false,
        help: false,
        host: Vec::new(),
    };
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--" => {
                parsed.host = iter.by_ref().cloned().collect();
                break;
            }
            "-h" | "--help" => parsed.help = true,
            "--print" => parsed.print = true,
            "--data-dir" => parsed.data_dir = Some(value(&mut iter, arg)?),
            "--vault-file" => parsed.vault_file = Some(value(&mut iter, arg)?),
            "--backup-file" => parsed.backup_file = Some(value(&mut iter, arg)?),
            "--socket" => parsed.socket = Some(value(&mut iter, arg)?),
            "--profile" => parsed.profile = Some(value(&mut iter, arg)?),
            other => {
                return Err(format!(
                    "unexpected argument `{other}`. Put the host after `--`. See --help."
                ));
            }
        }
    }
    Ok(parsed)
}

/// Take the next argument as the value of `flag`.
fn value<'a>(iter: &mut impl Iterator<Item = &'a String>, flag: &str) -> Result<String, String> {
    iter.next()
        .cloned()
        .ok_or_else(|| format!("{flag} needs a value"))
}

/// Build one `KEY=VALUE` parameter for `sandbox-exec -D`. The path must be
/// valid UTF-8, because `-D` takes a string.
fn param(key: &str, path: &Path) -> Result<String, String> {
    let text = path
        .to_str()
        .ok_or_else(|| format!("the path for {key} is not valid UTF-8: {}", path.display()))?;
    Ok(format!("{key}={text}"))
}

/// Resolve symlinks. Canonicalize the path, or, if it does not exist yet, the
/// deepest ancestor that exists, and then re-add the missing tail.
fn resolve(path: &Path) -> PathBuf {
    if let Ok(real) = std::fs::canonicalize(path) {
        return real;
    }
    let mut tail = Vec::new();
    let mut current = path;
    while let Some(parent) = current.parent() {
        if let Some(name) = current.file_name() {
            tail.push(name.to_owned());
        }
        if let Ok(real) = std::fs::canonicalize(parent) {
            let mut result = real;
            for name in tail.iter().rev() {
                result.push(name);
            }
            return result;
        }
        current = parent;
    }
    path.to_owned()
}

/// Find the SBPL profile. Order: the flag, the environment, next to the
/// program, then `sandbox/` in the working directory.
fn resolve_profile(flag: Option<&str>) -> Result<PathBuf, String> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(flag) = flag {
        candidates.push(PathBuf::from(flag));
    }
    if let Some(env_path) = env::var_os(PROFILE_ENV).filter(|value| !value.is_empty()) {
        candidates.push(PathBuf::from(env_path));
    }
    if let Ok(exe) = env::current_exe()
        && let Some(dir) = exe.parent()
    {
        candidates.push(dir.join(PROFILE_NAME));
        candidates.push(dir.join("sandbox").join(PROFILE_NAME));
        // From `target/<profile>/apassy-sandbox` up to the repository root.
        if let Some(root) = dir.parent().and_then(Path::parent) {
            candidates.push(root.join("sandbox").join(PROFILE_NAME));
        }
    }
    candidates.push(PathBuf::from("sandbox").join(PROFILE_NAME));

    for candidate in &candidates {
        if candidate.is_file() {
            return Ok(resolve(candidate));
        }
    }
    Err(format!(
        "cannot find the profile `{PROFILE_NAME}`. Use --profile or set {PROFILE_ENV}."
    ))
}

fn print_command(
    profile: &Path,
    data_dir: &Path,
    vault_file: &Path,
    backup_file: &Path,
    socket: &Path,
    host: &[String],
) {
    print!("{SANDBOX_EXEC} -f {}", profile.display());
    print!(" -D APASSY_DATA_DIR={}", data_dir.display());
    print!(" -D APASSY_VAULT_FILE={}", vault_file.display());
    print!(" -D APASSY_BACKUP_FILE={}", backup_file.display());
    print!(" -D APASSY_SOCKET={}", socket.display());
    for part in host {
        print!(" {part}");
    }
    println!();
}

const HELP: &str = "\
apassy-sandbox — run an agent host inside the Apassy Seatbelt profile.

Usage:
  apassy-sandbox [OPTIONS] -- <host> [host args...]

Options:
  --data-dir DIR      Apassy data directory (default: the Application Support path)
  --vault-file FILE   vault database (default: <data-dir>/vault.db)
  --backup-file FILE  backup database (default: <vault-file>.backup)
  --socket FILE       broker socket (default: <data-dir>/broker.sock)
  --profile FILE      SBPL profile (default: found near the program)
  --print             print the resolved sandbox-exec command; do not run it
  -h, --help          print this help

Examples:
  apassy-sandbox -- claude -p --settings '{\"sandbox\":{\"enabled\":false}}' 'hello'
  apassy-sandbox -- codex exec -c sandbox_mode=danger-full-access -c approval_policy=never 'hi'
";
