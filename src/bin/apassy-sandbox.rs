//! Launcher that starts an agent host inside the Apassy Seatbelt profile.
//!
//! It resolves the protected paths, finds the SBPL profile, and replaces
//! itself with `/usr/bin/sandbox-exec`. The host (Claude Code, Codex) and every
//! command that the host starts then run inside the profile. They cannot read,
//! copy, or replace a vault, the backup, the Laya model, or the iCloud copies of
//! the vaults. They cannot start, read, or change the programs in the Apassy app
//! bundle, except `apassy-mcp` and `apassy-hook`. They can still connect to the
//! broker socket, so `apassy-mcp` keeps working.
//!
//! Usage:
//!   apassy-sandbox [OPTIONS] -- <host> [host args...]
//!
//! Options (each value is an absolute path):
//!   --data-dir DIR      The Apassy data directory. Default:
//!                       `$HOME/Library/Application Support/Apassy`.
//!   --vault-file FILE   The vault database. Default: `<data-dir>/vault.db`.
//!                       Each vault in `<data-dir>/vaults.json` is denied too
//!                       (ADR 0013): the data directory covers a vault in it,
//!                       and a vault outside it gets its own profile parameter,
//!                       `APASSY_VAULT_FILE_2` to `APASSY_VAULT_FILE_16`.
//!   --backup-file FILE  The backup database. Default: `<vault-file>.backup`.
//!   --socket FILE       The broker socket. Default: `$APASSY_BROKER_SOCKET`,
//!                       else `<data-dir>/broker.sock`.
//!   --home DIR          The owner home directory. The profile denies a write to
//!                       the autostart locations under it. Default: `$HOME`.
//!   --app DIR           The installed Apassy app bundle. Default:
//!                       `/Applications/Apassy.app`.
//!   --app-build DIR     A second Apassy app bundle, for example a build. Default:
//!                       `<target>/Apassy.app` when this program runs from
//!                       `<target>/<profile>/`, else none.
//!   --cloud-dir DIR     The Apassy folder in iCloud Drive. Default:
//!                       `$HOME/Library/Mobile Documents/com~apple~CloudDocs/Apassy`.
//!                       The synced file of each vault in another folder (ADR
//!                       0014) gets its own profile parameter,
//!                       `APASSY_SYNC_FILE_1` to `APASSY_SYNC_FILE_16`.
//!   --profile FILE      The SBPL profile. Default: `$APASSY_SANDBOX_PROFILE`,
//!                       else a file found next to this program or in `sandbox/`.
//!   --print             Print the resolved sandbox-exec command. Do not run it.
//!   -h, --help          Print this help.
//!
//! The host name and its arguments follow `--`. Set the host environment (for
//! example `APASSY_AGENT_TOKEN`) before you start this launcher; the launcher
//! passes the environment through to the host.
//!
//! The launcher fails closed. It stops with an error when the vault list cannot
//! be read or is not valid, because then it cannot name each vault file, and
//! when the list has more vault files outside the data directory than the
//! profile has parameters for.
//!
//! This program uses only `std` and no `unsafe`. `CommandExt::exec` replaces the
//! process image; it is a safe call that returns an error if the exec fails.

// The launcher is for macOS. On Linux it only prints that, so its parts are unused.
#![cfg_attr(not(target_os = "macos"), allow(dead_code, unused_imports))]

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
/// The default installed app bundle.
const DEFAULT_APP: &str = "/Applications/Apassy.app";
/// The app bundle that `scripts/build-app.sh` writes into the target directory.
const BUILD_APP_NAME: &str = "Apassy.app";
/// The profile has the parameters `APASSY_VAULT_FILE_2` to `APASSY_VAULT_FILE_16`
/// for vault files outside the data directory.
const MAX_EXTRA_VAULTS: usize = 15;
/// The profile has the parameters `APASSY_SYNC_FILE_1` to `APASSY_SYNC_FILE_16` for
/// synced vault files outside the data directory and the iCloud Apassy folder.
const MAX_SYNC_FILES: usize = 16;
/// The Apassy folder in iCloud Drive, under the home directory (ADR 0014).
const CLOUD_DIR_IN_HOME: [&str; 4] = [
    "Library",
    "Mobile Documents",
    "com~apple~CloudDocs",
    "Apassy",
];

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("apassy-sandbox: the Seatbelt launcher runs only on macOS.");
    std::process::exit(2);
}

#[cfg(target_os = "macos")]
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
    // Every vault of the list (ADR 0013). A list that cannot be read stops the
    // launcher: the profile cannot deny a vault file that it does not know.
    let listed = listed_vaults(&data_dir)?;
    // The synced file of each vault (ADR 0014), with the same rule.
    let listed_sync = listed_sync_files(&data_dir)?;

    let app = parsed
        .app
        .map_or_else(|| PathBuf::from(DEFAULT_APP), PathBuf::from);
    let app_build = parsed
        .app_build
        .map(PathBuf::from)
        .or_else(default_build_app);

    // The iCloud copies of the vaults. The profile denies the folder also when it
    // does not exist yet, so a later sync cannot create a readable copy.
    let cloud_dir = parsed.cloud_dir.map(PathBuf::from).or_else(|| {
        home.as_ref().map(|home| {
            CLOUD_DIR_IN_HOME
                .iter()
                .fold(home.clone(), |dir, part| dir.join(part))
        })
    });

    // The home directory, for the autostart denials in the profile.
    let home_dir = match parsed.home {
        Some(path) => PathBuf::from(path),
        None => home
            .clone()
            .ok_or("HOME is not set, so --home is required")?,
    };

    let profile = resolve_profile(parsed.profile.as_deref())?;

    // Resolve symlinks in each path. Seatbelt matches the resolved path, and on
    // macOS `/var` and `/tmp` are symlinks. Resolve the deepest ancestor that
    // exists, then re-add the missing tail, because a socket or a backup may
    // not exist yet.
    let data_dir = resolve(&data_dir);
    let vault_file = resolve(&vault_file);
    let backup_file = resolve(&backup_file);
    let socket = resolve(&socket);
    let home_dir = resolve(&home_dir);
    let app = resolve(&app);
    let app_build = app_build.as_deref().map(resolve);
    let cloud_dir = cloud_dir.as_deref().map(resolve);
    let extra_vaults = extra_vault_files(&data_dir, &vault_file, &listed)?;
    let extra_params: Vec<(String, PathBuf)> = extra_vaults
        .into_iter()
        .enumerate()
        .map(|(index, path)| (format!("APASSY_VAULT_FILE_{}", index + 2), path))
        .collect();
    let sync_params: Vec<(String, PathBuf)> =
        sync_file_params(&data_dir, cloud_dir.as_deref(), &listed_sync)?
            .into_iter()
            .enumerate()
            .map(|(index, path)| (format!("APASSY_SYNC_FILE_{}", index + 1), path))
            .collect();

    let mut command = Command::new(SANDBOX_EXEC);
    command.arg("-f").arg(&profile);
    command.arg("-D").arg(param("APASSY_DATA_DIR", &data_dir)?);
    command
        .arg("-D")
        .arg(param("APASSY_VAULT_FILE", &vault_file)?);
    for (key, path) in &extra_params {
        command.arg("-D").arg(param(key, path)?);
    }
    command
        .arg("-D")
        .arg(param("APASSY_BACKUP_FILE", &backup_file)?);
    command.arg("-D").arg(param("APASSY_SOCKET", &socket)?);
    command.arg("-D").arg(param("APASSY_HOME", &home_dir)?);
    command.arg("-D").arg(param("APASSY_APP", &app)?);
    if let Some(app_build) = &app_build {
        command.arg("-D").arg(param("APASSY_APP_BUILD", app_build)?);
    }
    if let Some(cloud_dir) = &cloud_dir {
        command.arg("-D").arg(param("APASSY_CLOUD_DIR", cloud_dir)?);
    }
    for (key, path) in &sync_params {
        command.arg("-D").arg(param(key, path)?);
    }
    command.arg(&parsed.host[0]);
    command.args(&parsed.host[1..]);

    if parsed.print {
        let mut params: Vec<(&str, Option<&PathBuf>)> = vec![
            ("APASSY_DATA_DIR", Some(&data_dir)),
            ("APASSY_VAULT_FILE", Some(&vault_file)),
        ];
        params.extend(
            extra_params
                .iter()
                .map(|(key, path)| (key.as_str(), Some(path))),
        );
        params.extend([
            ("APASSY_BACKUP_FILE", Some(&backup_file)),
            ("APASSY_SOCKET", Some(&socket)),
            ("APASSY_HOME", Some(&home_dir)),
            ("APASSY_APP", Some(&app)),
            ("APASSY_APP_BUILD", app_build.as_ref()),
            ("APASSY_CLOUD_DIR", cloud_dir.as_ref()),
        ]);
        params.extend(
            sync_params
                .iter()
                .map(|(key, path)| (key.as_str(), Some(path))),
        );
        print_command(&profile, &params, &parsed.host);
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
    home: Option<String>,
    app: Option<String>,
    app_build: Option<String>,
    cloud_dir: Option<String>,
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
        home: None,
        app: None,
        app_build: None,
        cloud_dir: None,
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
            "--home" => parsed.home = Some(value(&mut iter, arg)?),
            "--app" => parsed.app = Some(value(&mut iter, arg)?),
            "--app-build" => parsed.app_build = Some(value(&mut iter, arg)?),
            "--cloud-dir" => parsed.cloud_dir = Some(value(&mut iter, arg)?),
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

/// The vault files of the list in `data_dir` (ADR 0013). No list gives none. A
/// list that cannot be read, or that is not valid, is an error.
fn listed_vaults(data_dir: &Path) -> Result<Vec<PathBuf>, String> {
    match apassy::vaults::Registry::read(data_dir) {
        Ok(None) => Ok(Vec::new()),
        Ok(Some(registry)) => Ok(registry
            .entries()
            .iter()
            .map(|entry| entry.path.clone())
            .collect()),
        Err(err) => Err(format!(
            "cannot use the vault list {}: {err}. The profile cannot deny a vault file that the launcher does not know, so the host does not start. Open Apassy once: it moves a damaged list aside and makes a new one. Then start the launcher again.",
            apassy::vaults::registry_path(data_dir).display()
        )),
    }
}

/// The synced vault files of the vault list (ADR 0014). A list that cannot be read, or
/// a synced vault without a valid file, stops the launcher: the profile cannot deny a
/// file that it does not know.
fn listed_sync_files(data_dir: &Path) -> Result<Vec<PathBuf>, String> {
    let registry = match apassy::vaults::Registry::read(data_dir) {
        Ok(None) => return Ok(Vec::new()),
        Ok(Some(registry)) => registry,
        Err(err) => {
            return Err(format!(
                "cannot use the vault list {}: {err}. The profile cannot deny a synced vault file that the launcher does not know, so the host does not start. Open Apassy once: it moves a damaged list aside and makes a new one. Then start the launcher again.",
                apassy::vaults::registry_path(data_dir).display()
            ));
        }
    };
    let mut files = Vec::new();
    for entry in registry.entries() {
        if entry.sync_state().is_none() {
            continue;
        }
        match entry.sync_file() {
            Some(file) => files.push(file),
            None => {
                return Err(format!(
                    "the vault “{}” syncs, but the vault list has no valid synced file for it, so the host does not start. In Apassy, turn its sync off and on again (Settings > Vaults).",
                    entry.name
                ));
            }
        }
    }
    Ok(files)
}

/// The synced files that need their own profile parameter: each one outside `data_dir`
/// and outside `cloud_dir` (their subtree denies cover the others), once, resolved.
/// More than [`MAX_SYNC_FILES`] is an error.
fn sync_file_params(
    data_dir: &Path,
    cloud_dir: Option<&Path>,
    listed: &[PathBuf],
) -> Result<Vec<PathBuf>, String> {
    let mut files: Vec<PathBuf> = Vec::new();
    for path in listed {
        let path = resolve(path);
        let covered =
            path.starts_with(data_dir) || cloud_dir.is_some_and(|dir| path.starts_with(dir));
        if covered || files.contains(&path) {
            continue;
        }
        files.push(path);
    }
    if files.len() > MAX_SYNC_FILES {
        return Err(format!(
            "the vault list has {} synced vault files outside iCloud Drive. The profile can deny at most {MAX_SYNC_FILES}, so the host does not start. Sync some vaults through iCloud Drive, or turn their sync off in Apassy (Settings > Vaults).",
            files.len()
        ));
    }
    Ok(files)
}

/// The listed vault files that need their own profile parameter: each one outside
/// `data_dir` (the subtree deny covers the others) and other than `vault_file`,
/// once, resolved. More than [`MAX_EXTRA_VAULTS`] is an error.
fn extra_vault_files(
    data_dir: &Path,
    vault_file: &Path,
    listed: &[PathBuf],
) -> Result<Vec<PathBuf>, String> {
    let mut extra: Vec<PathBuf> = Vec::new();
    for path in listed {
        let path = resolve(path);
        if path.starts_with(data_dir) || path == vault_file || extra.contains(&path) {
            continue;
        }
        extra.push(path);
    }
    if extra.len() > MAX_EXTRA_VAULTS {
        return Err(format!(
            "the vault list has {} vault files outside {}. The profile can deny at most {MAX_EXTRA_VAULTS}, so the host does not start. Move vaults into the data directory, or remove vaults from the list in Apassy (Settings > Vaults).",
            extra.len(),
            data_dir.display()
        ));
    }
    Ok(extra)
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

/// The build app bundle next to the target directory of this program:
/// `<target>/Apassy.app` when the program is `<target>/<profile>/apassy-sandbox`
/// and the directory is named `target`. `scripts/build-app.sh` writes the app
/// there.
fn default_build_app() -> Option<PathBuf> {
    let exe = env::current_exe().ok()?;
    let target = exe.parent()?.parent()?;
    (target.file_name()? == "target").then(|| target.join(BUILD_APP_NAME))
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

fn print_command(profile: &Path, params: &[(&str, Option<&PathBuf>)], host: &[String]) {
    print!("{SANDBOX_EXEC} -f {}", profile.display());
    for (key, path) in params {
        if let Some(path) = path {
            print!(" -D {key}={}", path.display());
        }
    }
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
  --vault-file FILE   vault database (default: <data-dir>/vault.db). Each vault
                      in <data-dir>/vaults.json is denied too; a vault outside
                      the data directory gets APASSY_VAULT_FILE_2 to _16. The
                      launcher stops when the list cannot be read or has more
                      than 15 such vaults.
  --backup-file FILE  backup database (default: <vault-file>.backup)
  --socket FILE       broker socket (default: <data-dir>/broker.sock)
  --home DIR          owner home directory for the autostart denials (default: $HOME)
  --app DIR           installed app bundle (default: /Applications/Apassy.app)
  --app-build DIR     second app bundle (default: <target>/Apassy.app when this
                      program runs from <target>/<profile>/)
  --cloud-dir DIR     Apassy folder in iCloud Drive (default: $HOME/Library/Mobile
                      Documents/com~apple~CloudDocs/Apassy)
  --profile FILE      SBPL profile (default: found near the program)
  --print             print the resolved sandbox-exec command; do not run it
  -h, --help          print this help

Examples (turn off only the host's inner sandbox; keep its approval prompts):
  apassy-sandbox -- claude --settings '{\"sandbox\":{\"enabled\":false}}'
  apassy-sandbox -- codex -c sandbox_mode=danger-full-access
";

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = env::temp_dir().join(format!(
            "apassy-sandbox-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_nanos())
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        resolve(&dir)
    }

    #[test]
    fn only_vaults_outside_the_data_directory_get_a_parameter() {
        let root = temp_dir("extra");
        let data = root.join("d");
        let vault = data.join("vault.db");
        let listed = vec![
            vault.clone(),
            data.join("vaults").join("work.db"),
            root.join("elsewhere").join("client.db"),
            root.join("elsewhere").join("client.db"),
            root.join("other.db"),
        ];
        let extra = extra_vault_files(&data, &vault, &listed).expect("extra");
        assert_eq!(
            extra,
            vec![
                root.join("elsewhere").join("client.db"),
                root.join("other.db")
            ]
        );
        // A vault outside the data directory can be the --vault-file one.
        let chosen = root.join("other.db");
        let extra = extra_vault_files(&data, &chosen, &listed).expect("extra");
        assert_eq!(extra, vec![root.join("elsewhere").join("client.db")]);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn more_vaults_than_the_profile_supports_fail_closed() {
        let root = temp_dir("many");
        let data = root.join("d");
        let listed: Vec<PathBuf> = (0..MAX_EXTRA_VAULTS)
            .map(|index| root.join(format!("v{index}.db")))
            .collect();
        let extra = extra_vault_files(&data, &data.join("vault.db"), &listed).expect("15 fit");
        assert_eq!(extra.len(), MAX_EXTRA_VAULTS);
        let mut too_many = listed;
        too_many.push(root.join("v-last.db"));
        let err =
            extra_vault_files(&data, &data.join("vault.db"), &too_many).expect_err("16 do not fit");
        assert!(err.contains("16 vault files outside"), "{err}");
        assert!(err.contains("does not start"), "{err}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_damaged_vault_list_fails_closed_and_no_list_is_fine() {
        let data = temp_dir("list");
        assert_eq!(
            listed_vaults(&data).expect("no list"),
            Vec::<PathBuf>::new()
        );
        std::fs::write(data.join("vaults.json"), "{ not json").expect("bad list");
        let err = listed_vaults(&data).expect_err("a damaged list");
        assert!(err.contains("cannot use the vault list"), "{err}");
        assert!(err.contains("does not start"), "{err}");
        std::fs::write(data.join("vaults.json"), r#"{"version":7,"vaults":[]}"#)
            .expect("newer list");
        assert!(listed_vaults(&data).is_err(), "a newer list fails closed");
        let mut registry = apassy::vaults::Registry::new();
        registry
            .add("Work", Path::new("/Volumes/Work/work.db"), 1)
            .expect("add");
        registry.save(&data).expect("save");
        assert_eq!(
            listed_vaults(&data).expect("list"),
            vec![PathBuf::from("/Volumes/Work/work.db")]
        );
        let _ = std::fs::remove_dir_all(data);
    }

    /// The profile has one rule for each parameter that the launcher can pass.
    #[test]
    fn the_profile_has_a_rule_for_each_vault_parameter() {
        let profile = include_str!("../../sandbox/apassy-agent-host.sb");
        for number in 2..=MAX_EXTRA_VAULTS + 1 {
            let rule = format!(
                "(if (param \"APASSY_VAULT_FILE_{number}\") (apassy-protect-vault (param \"APASSY_VAULT_FILE_{number}\")))"
            );
            assert!(profile.contains(&rule), "missing: {rule}");
        }
        assert!(!profile.contains(&format!("APASSY_VAULT_FILE_{}", MAX_EXTRA_VAULTS + 2)));
        for number in 1..=MAX_SYNC_FILES {
            let rule = format!(
                "(if (param \"APASSY_SYNC_FILE_{number}\") (apassy-protect-sync-file (param \"APASSY_SYNC_FILE_{number}\")))"
            );
            assert!(profile.contains(&rule), "missing: {rule}");
        }
        assert!(!profile.contains(&format!("APASSY_SYNC_FILE_{}", MAX_SYNC_FILES + 1)));
    }

    /// ADR 0014: a synced file outside the data directory and outside the iCloud Apassy
    /// folder gets a parameter; a synced vault without a valid file stops the launcher.
    #[test]
    fn synced_files_outside_the_denied_folders_get_a_parameter() {
        let root = temp_dir("sync");
        let data = root.join("d");
        let icloud = root.join("icloud").join("Apassy");
        let dropbox = root.join("Dropbox").join("Apassy");
        let mut registry = apassy::vaults::Registry::new();
        for (name, folder) in [("A", &dropbox), ("B", &icloud), ("C", &data)] {
            let id = registry
                .add(name, &root.join(format!("{name}.db")), 1)
                .expect("add");
            registry.entry_mut(&id).expect("entry").sync = Some(apassy::vaults::SyncLink::new(
                &id,
                folder,
                &format!("{name}.apassy"),
            ));
        }
        registry
            .add("Plain", &root.join("plain.db"), 1)
            .expect("add");
        registry.save(&data).expect("save");
        let listed = listed_sync_files(&data).expect("list");
        assert_eq!(listed.len(), 3);
        assert_eq!(
            sync_file_params(&data, Some(&icloud), &listed).expect("params"),
            vec![dropbox.join("A.apassy")]
        );
        let many: Vec<PathBuf> = (0..=MAX_SYNC_FILES)
            .map(|index| dropbox.join(format!("v{index}.apassy")))
            .collect();
        let err = sync_file_params(&data, None, &many).expect_err("17 do not fit");
        assert!(err.contains("17 synced vault files"), "{err}");
        assert_eq!(
            sync_file_params(&data, None, &many[..MAX_SYNC_FILES])
                .expect("16 fit")
                .len(),
            MAX_SYNC_FILES
        );
        // A synced vault whose file the list does not name fails closed.
        let id = registry.entries()[0].id.clone();
        registry.entry_mut(&id).expect("entry").sync = Some(apassy::vaults::SyncLink::new(
            &id,
            Path::new("relative"),
            "A.apassy",
        ));
        registry.save(&data).expect("save");
        let err = listed_sync_files(&data).expect_err("no valid file");
        assert!(err.contains("does not start"), "{err}");
        let _ = std::fs::remove_dir_all(root);
    }
}
