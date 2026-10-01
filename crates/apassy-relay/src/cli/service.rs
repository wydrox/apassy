//! Per-user service files for the owner's host. No root service is installed.

use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use super::CliError;
use super::host::{self, HostOptions};
use super::settings::{self, Settings};
use crate::ids::TeamId;

pub const LABEL: &str = "com.wydrox.apassy.team-host";
pub const UNIT: &str = "apassy-team-host.service";

fn path_text(path: &Path) -> Result<&str, CliError> {
    if !path.is_absolute() {
        return Err(CliError::usage("The service path must be absolute."));
    }
    path.to_str()
        .ok_or_else(|| CliError::usage("The service path must contain valid UTF-8 text."))
}

fn xml(text: &str) -> Result<String, CliError> {
    let mut escaped = String::new();
    for ch in text.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            '\t' | '\n' | '\r' => escaped.push(ch),
            ch if ch.is_control() || matches!(ch, '\u{fffe}' | '\u{ffff}') => {
                return Err(CliError::usage(
                    "The service path contains an invalid XML character.",
                ));
            }
            ch => escaped.push(ch),
        }
    }
    Ok(escaped)
}

fn host_args(team: &TeamId, options: HostOptions) -> Vec<String> {
    let mut args = vec![
        "--team".to_string(),
        team.to_string(),
        "host".to_string(),
        "--dialog".to_string(),
    ];
    if options.ask_all {
        args.push("--ask-all".to_string());
    }
    args.extend(["--auto-limit".to_string(), options.auto_limit.to_string()]);
    args
}

/// Generate a plist without file writes, environment reads, or service commands.
pub fn generate_plist(
    exe: &Path,
    team: &TeamId,
    options: HostOptions,
    log: &Path,
    xdg: Option<&str>,
) -> Result<String, CliError> {
    let exe = xml(path_text(exe)?)?;
    let log = xml(path_text(log)?)?;
    let mut arguments = format!("        <string>{exe}</string>\n");
    for argument in host_args(team, options) {
        arguments.push_str(&format!("        <string>{}</string>\n", xml(&argument)?));
    }
    let environment = match xdg {
        Some(value) => {
            path_text(Path::new(value))?;
            format!(
                "    <key>EnvironmentVariables</key>\n    <dict>\n        <key>XDG_CONFIG_HOME</key>\n        <string>{}</string>\n    </dict>\n",
                xml(value)?
            )
        }
        None => String::new(),
    };
    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n    <key>Label</key>\n    <string>{LABEL}</string>\n    <key>ProgramArguments</key>\n    <array>\n{arguments}    </array>\n    <key>RunAtLoad</key>\n    <true/>\n    <key>KeepAlive</key>\n    <true/>\n    <key>ThrottleInterval</key>\n    <integer>30</integer>\n    <key>LimitLoadToSessionType</key>\n    <string>Aqua</string>\n    <key>ProcessType</key>\n    <string>Interactive</string>\n    <key>StandardOutPath</key>\n    <string>{log}</string>\n    <key>StandardErrorPath</key>\n    <string>{log}</string>\n{environment}</dict>\n</plist>\n"
    ))
}

fn unit_path(path: &Path) -> Result<&str, CliError> {
    let text = path_text(path)?;
    if !text
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || "/._-".contains(ch))
    {
        return Err(CliError::usage(
            "The systemd service path cannot contain spaces or special characters. Move the file to a simple absolute path.",
        ));
    }
    Ok(text)
}

/// Generate a user unit without file writes, environment reads, or service commands.
pub fn generate_unit(
    exe: &Path,
    team: &TeamId,
    options: HostOptions,
    xdg: Option<&str>,
) -> Result<String, CliError> {
    let exe = unit_path(exe)?;
    let (environment, log) = match xdg {
        Some(value) => {
            let value = unit_path(Path::new(value))?;
            (
                format!("Environment=XDG_CONFIG_HOME={value}\n"),
                format!("{value}/apassy-team/service.log"),
            )
        }
        None => (
            String::new(),
            "%h/.config/apassy-team/service.log".to_string(),
        ),
    };
    Ok(format!(
        "[Unit]\nDescription=Apassy team host\nAfter=graphical-session.target\n\n[Service]\nType=simple\nExecStart={exe} {}\nRestart=on-failure\nRestartSec=30\n{environment}StandardOutput=append:{log}\nStandardError=append:{log}\n\n[Install]\nWantedBy=default.target\n",
        host_args(team, options).join(" ")
    ))
}

fn home() -> Result<PathBuf, CliError> {
    let home = std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| CliError::usage("HOME is not set. The service needs a home directory."))?;
    let home = PathBuf::from(home);
    path_text(&home)?;
    Ok(home)
}

fn xdg_config() -> Result<Option<String>, CliError> {
    match std::env::var("XDG_CONFIG_HOME") {
        Ok(value) if !value.is_empty() => {
            path_text(Path::new(&value))?;
            Ok(Some(value))
        }
        Ok(_) | Err(std::env::VarError::NotPresent) => Ok(None),
        Err(_) => Err(CliError::usage(
            "XDG_CONFIG_HOME must contain valid UTF-8 text.",
        )),
    }
}

fn service_path() -> Result<PathBuf, CliError> {
    if cfg!(target_os = "macos") {
        Ok(home()?
            .join("Library/LaunchAgents")
            .join(format!("{LABEL}.plist")))
    } else if cfg!(target_os = "linux") {
        let config = match xdg_config()? {
            Some(value) => PathBuf::from(value),
            None => home()?.join(".config"),
        };
        Ok(config.join("systemd/user").join(UNIT))
    } else {
        Err(CliError::usage("Host services need macOS or Linux."))
    }
}

fn service_log() -> Result<PathBuf, CliError> {
    if cfg!(target_os = "macos") {
        Ok(home()?.join("Library/Logs/apassy-team-host.log"))
    } else {
        Ok(settings::settings_dir()?.join("service.log"))
    }
}

fn io_error(action: &str, error: std::io::Error) -> CliError {
    CliError::usage(format!("Cannot {action}: {}.", error.kind()))
}

fn write_service(path: &Path, text: &str) -> Result<(), CliError> {
    let parent = path
        .parent()
        .ok_or_else(|| CliError::usage("The service path has no directory."))?;
    fs::create_dir_all(parent).map_err(|error| io_error("create the service directory", error))?;
    let mut random = [0u8; 8];
    getrandom::fill(&mut random)
        .map_err(|_| CliError::usage("Cannot create a temporary service file name."))?;
    let suffix = u64::from_ne_bytes(random);
    let temporary = parent.join(format!(
        ".apassy-team-host-{}-{suffix:016x}.tmp",
        std::process::id()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&temporary)
        .map_err(|error| io_error("create the service file", error))?;
    let result = (|| {
        file.set_permissions(fs::Permissions::from_mode(0o644))
            .map_err(|error| io_error("set the service file mode", error))?;
        file.write_all(text.as_bytes())
            .map_err(|error| io_error("write the service file", error))?;
        file.sync_all()
            .map_err(|error| io_error("save the service file", error))?;
        fs::rename(&temporary, path).map_err(|error| io_error("replace the service file", error))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn protect_log(path: &Path) -> Result<(), CliError> {
    let parent = path
        .parent()
        .ok_or_else(|| CliError::usage("The log path has no directory."))?;
    fs::create_dir_all(parent).map_err(|error| io_error("create the log directory", error))?;
    let file = OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| io_error("create the service log", error))?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|error| io_error("set the service log mode", error))
}

fn clean_output(text: &str) -> String {
    let mut clean = String::new();
    for ch in text.chars() {
        if ch.is_control() {
            clean.extend(ch.escape_default());
        } else {
            clean.push(ch);
        }
    }
    clean
}

fn command(program: &str, args: &[&str]) -> Result<Output, CliError> {
    Command::new(program)
        .args(args)
        .output()
        .map_err(|error| io_error(&format!("run {program}"), error))
}

fn require_success(program: &str, output: Output) -> Result<(), CliError> {
    if output.status.success() {
        Ok(())
    } else {
        let stderr = clean_output(String::from_utf8_lossy(&output.stderr).trim());
        Err(CliError::usage(format!(
            "{program} failed ({}): {stderr}",
            output.status
        )))
    }
}

fn launch_domain() -> Result<String, CliError> {
    let output = command("/usr/bin/id", &["-u"])?;
    if !output.status.success() {
        return Err(CliError::usage("Cannot get the user ID."));
    }
    let uid = String::from_utf8_lossy(&output.stdout);
    let uid = uid.trim();
    if uid.is_empty() || !uid.chars().all(|ch| ch.is_ascii_digit()) {
        return Err(CliError::usage("The user ID is invalid."));
    }
    Ok(format!("gui/{uid}"))
}

fn launch_not_loaded(output: &Output) -> bool {
    let text = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
    text.contains("no such process")
        || text.contains("could not find service")
        || text.contains("could not find specified service")
}

fn bootout(domain: &str) -> Result<(), CliError> {
    let service = format!("{domain}/{LABEL}");
    let output = command("/bin/launchctl", &["bootout", &service])?;
    if output.status.success() || launch_not_loaded(&output) {
        Ok(())
    } else {
        require_success("launchctl bootout", output)
    }
}

/// The service file deliberately contains no credentials. Refuse shell-only
/// credentials rather than install a service for a different account or relay.
fn check_saved_settings(settings: &Settings, path: &Path) -> Result<(), CliError> {
    let text = zeroize::Zeroizing::new(fs::read_to_string(path).map_err(|_| {
        CliError::usage(
            "The service needs saved settings. Run `apassy-team init` with the owner token first.",
        )
    })?);
    let saved: SavedServiceSettings = serde_json::from_str(&text).map_err(|_| {
        CliError::usage("The saved service settings are invalid. Check settings.json.")
    })?;
    let entry = if saved.version == Some(2) {
        let selected = settings.team_id.as_ref().ok_or_else(|| {
            CliError::usage("The service needs a selected team. Use `--team ID` or `team use ID`.")
        })?;
        saved.teams.get(selected).ok_or_else(|| {
            CliError::usage("The selected team is missing from the saved settings.")
        })?
    } else if saved.version.is_none() || saved.version == Some(1) {
        &saved.legacy
    } else {
        return Err(CliError::usage(
            "The saved settings version is not supported.",
        ));
    };
    let relay = entry
        .relay_url
        .as_deref()
        .and_then(|url| settings::normalize_url(url).ok());
    if relay.as_deref() != Some(settings.relay()?)
        || entry.member_token.as_ref().map(|token| token.expose())
            != settings.member_token.as_ref().map(|token| token.expose())
        || entry.device_id != settings.device_id
        || entry.member_token.is_none() && entry.device_id.is_none()
    {
        return Err(CliError::usage(
            "The shell settings differ from the saved settings. Use the selected team's saved relay and credentials before `host install`.",
        ));
    }
    if settings.edge_secret.is_some() {
        return Err(CliError::usage(
            "The user service cannot keep APASSY_EDGE_SECRET. Use a relay endpoint that does not need this variable.",
        ));
    }
    Ok(())
}

#[derive(serde::Deserialize)]
struct SavedServiceSettings {
    version: Option<u32>,
    #[serde(default)]
    teams: std::collections::BTreeMap<crate::ids::TeamId, SavedServiceEntry>,
    #[serde(flatten)]
    legacy: SavedServiceEntry,
}

#[derive(serde::Deserialize)]
struct SavedServiceEntry {
    relay_url: Option<String>,
    member_token: Option<crate::secret::SecretString>,
    device_id: Option<crate::ids::DeviceId>,
}

/// Check the owner, write the per-user service, and start it.
pub fn install(settings: &Settings, options: HostOptions) -> Result<i32, CliError> {
    let path = service_path()?;
    let exe = std::env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(|error| io_error("get the executable path", error))?;
    let xdg = xdg_config()?;
    let log = service_log()?;
    let settings_path = settings::settings_path()?;
    check_saved_settings(settings, &settings_path)?;
    // A legacy entry needs its saved team ID before the service can select it.
    let migrated;
    let settings = if settings.team_id.is_none() {
        settings::migrate_legacy()?;
        migrated = settings::load_for(None)?;
        &migrated
    } else {
        settings
    };
    check_saved_settings(settings, &settings_path)?;
    let team = settings.team_id.as_ref().ok_or_else(|| {
        CliError::usage("The service needs a saved team. Run `apassy-team init` first.")
    })?;
    host::check_owner(settings)?;
    let text = if cfg!(target_os = "macos") {
        generate_plist(&exe, team, options, &log, xdg.as_deref())?
    } else {
        generate_unit(&exe, team, options, xdg.as_deref())?
    };
    if cfg!(target_os = "linux") {
        settings::ensure_private_dir(&settings::settings_dir()?)?;
    }
    protect_log(&log)?;
    if cfg!(target_os = "macos") {
        let domain = launch_domain()?;
        write_service(&path, &text)?;
        bootout(&domain)?;
        require_success(
            "launchctl bootstrap",
            command("/bin/launchctl", &["bootstrap", &domain, path_text(&path)?])?,
        )?;
    } else {
        write_service(&path, &text)?;
        require_success(
            "systemctl daemon-reload",
            command("systemctl", &["--user", "daemon-reload"])?,
        )?;
        require_success(
            "systemctl enable",
            command("systemctl", &["--user", "enable", "--now", UNIT])?,
        )?;
        // enable --now does not restart an already active service after an edit.
        require_success(
            "systemctl restart",
            command("systemctl", &["--user", "restart", UNIT])?,
        )?;
        println!(
            "For GUI dialogs, run: systemctl --user import-environment DISPLAY WAYLAND_DISPLAY"
        );
        println!("Then run: systemctl --user restart {UNIT}");
        println!("Without a GUI, the host denies runs that need a dialog.");
    }
    println!("The host service is installed: {}", path.display());
    println!("Service output: {}", log.display());
    Ok(0)
}

/// Stop and remove the per-user service. Does not read credentials or contact the relay.
pub fn uninstall() -> Result<i32, CliError> {
    let path = service_path()?;
    if cfg!(target_os = "macos") {
        bootout(&launch_domain()?)?;
    } else {
        let output = command("systemctl", &["--user", "disable", "--now", UNIT])?;
        let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
        if !output.status.success()
            && !(stderr.contains("does not exist") || stderr.contains("not loaded"))
        {
            require_success("systemctl disable", output)?;
        }
    }
    match fs::remove_file(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(io_error("remove the service file", error)),
    }
    if cfg!(target_os = "linux") {
        require_success(
            "systemctl daemon-reload",
            command("systemctl", &["--user", "daemon-reload"])?,
        )?;
    }
    println!("The host service is removed. The settings, keys, and logs remain.");
    Ok(0)
}

fn recent_log(path: &Path) -> Result<(), CliError> {
    let mut file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            println!("No log file: {}", path.display());
            return Ok(());
        }
        Err(error) => return Err(io_error("read the log", error)),
    };
    let length = file
        .metadata()
        .map_err(|error| io_error("read the log size", error))?
        .len();
    let start = length.saturating_sub(65536);
    file.seek(SeekFrom::Start(start))
        .map_err(|error| io_error("read the end of the log", error))?;
    let mut bytes = Vec::new();
    file.take(65536)
        .read_to_end(&mut bytes)
        .map_err(|error| io_error("read the log", error))?;
    let text = String::from_utf8_lossy(&bytes);
    let lines: Vec<_> = text.lines().collect();
    // Omit the first line if the read began in the middle of a line.
    let first = usize::from(start != 0).min(lines.len());
    let first = first.max(lines.len().saturating_sub(10));
    println!("Recent log lines: {}", path.display());
    for line in &lines[first..] {
        println!("{}", clean_output(line));
    }
    Ok(())
}

/// Show local installation, service state, and the last ten lines of each log.
pub fn status() -> Result<i32, CliError> {
    let path = service_path()?;
    println!("Service file: {}", path.display());
    println!(
        "Installed: {}",
        if path
            .try_exists()
            .map_err(|error| io_error("read the service file state", error))?
        {
            "yes"
        } else {
            "no"
        }
    );
    if cfg!(target_os = "macos") {
        let service = format!("{}/{LABEL}", launch_domain()?);
        let output = command("/bin/launchctl", &["print", &service])?;
        if output.status.success() {
            println!("Loaded: yes");
            let text = String::from_utf8_lossy(&output.stdout);
            let state = text
                .lines()
                .find_map(|line| line.trim().strip_prefix("state = "))
                .unwrap_or("unknown");
            println!("State: {}", clean_output(state));
        } else if launch_not_loaded(&output) {
            println!("Loaded: no");
            println!("State: stopped");
        } else {
            require_success("launchctl print", output)?;
        }
    } else {
        let active = command("systemctl", &["--user", "is-active", UNIT])?;
        let state = String::from_utf8_lossy(&active.stdout);
        if active.status.success() || matches!(active.status.code(), Some(3 | 4)) {
            println!("State: {}", clean_output(state.trim()));
        } else {
            require_success("systemctl is-active", active)?;
        }
        let output = command(
            "systemctl",
            &[
                "--user",
                "show",
                UNIT,
                "--property=LoadState",
                "--property=ActiveState",
                "--property=SubState",
                "--no-pager",
            ],
        )?;
        let text = String::from_utf8_lossy(&output.stdout);
        if output.status.success() || text.lines().any(|line| line == "LoadState=not-found") {
            for line in text.lines() {
                println!("{}", clean_output(line));
            }
        } else {
            require_success("systemctl show", output)?;
        }
    }
    recent_log(&settings::settings_dir()?.join("host.log"))?;
    recent_log(&service_log()?)?;
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_team() -> TeamId {
        TeamId::parse("t_abcdefgh23").unwrap()
    }

    #[test]
    fn service_accepts_the_selected_saved_team_when_another_team_is_current() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let selected = crate::ids::TeamId::parse("t_abcdefgh23").unwrap();
        let current = crate::ids::TeamId::parse("t_abcdefgh24").unwrap();
        let settings = Settings {
            relay_url: Some("https://selected.example.test".into()),
            team_id: Some(selected.clone()),
            device_id: Some(crate::ids::DeviceId(3)),
            ..Settings::default()
        };
        for current in [Some(current), None] {
            fs::write(
                &path,
                serde_json::json!({"version":2,"current":current,"teams":{
                    selected.as_str():{"relay_url":"https://selected.example.test","device_id":3},
                    "t_abcdefgh24":{"relay_url":"https://current.example.test","device_id":4}
                }})
                .to_string(),
            )
            .unwrap();
            check_saved_settings(&settings, &path).unwrap();
        }
    }

    #[test]
    fn generated_service_arguments_parse_as_the_selected_host() {
        use crate::cli::args::{self, Command};
        let expected_team = "t_abcdefgh23";
        let options = HostOptions {
            ask_all: true,
            auto_limit: 7,
        };
        let plist = generate_plist(
            Path::new("/exe"),
            &test_team(),
            options,
            Path::new("/log"),
            None,
        )
        .unwrap();
        let unit = generate_unit(Path::new("/exe"), &test_team(), options, None).unwrap();
        let plist_args: Vec<String> = plist
            .split("<key>ProgramArguments</key>")
            .nth(1)
            .unwrap()
            .split("</array>")
            .next()
            .unwrap()
            .lines()
            .filter_map(|line| {
                line.trim()
                    .strip_prefix("<string>")
                    .and_then(|line| line.strip_suffix("</string>"))
            })
            .skip(1)
            .map(str::to_owned)
            .collect();
        let unit_args: Vec<String> = unit
            .lines()
            .find_map(|line| line.strip_prefix("ExecStart="))
            .unwrap()
            .split_whitespace()
            .skip(1)
            .map(str::to_owned)
            .collect();
        for arguments in [plist_args, unit_args] {
            assert_eq!(
                arguments.get(..3).unwrap(),
                ["--team", expected_team, "host"]
            );
            assert_eq!(
                args::parse(&arguments).unwrap(),
                Command::Selected {
                    team: expected_team.into(),
                    command: Box::new(Command::Host {
                        ask_all: true,
                        auto_limit: Some(7),
                        dialog: true
                    }),
                }
            );
        }
    }

    #[test]
    fn service_requires_the_same_saved_credentials_and_no_edge_variable() {
        use crate::secret::SecretString;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let mut settings = Settings {
            relay_url: Some("https://relay.example.test".into()),
            member_token: Some(SecretString::new("owner-token".into())),
            ..Settings::default()
        };
        assert_eq!(check_saved_settings(&settings, &path).unwrap_err().code, 2);
        for saved in [
            r#"{}"#,
            r#"{"relay_url":"https://other.example.test","member_token":"owner-token"}"#,
            r#"{"relay_url":"https://relay.example.test","member_token":"other-token"}"#,
            "invalid json",
        ] {
            fs::write(&path, saved).unwrap();
            let error = check_saved_settings(&settings, &path).unwrap_err();
            assert_eq!(error.code, 2);
            assert!(!error.message.contains("owner-token"));
            assert!(!error.message.contains("other-token"));
        }
        fs::write(
            &path,
            r#"{"relay_url":"https://relay.example.test/","member_token":"owner-token"}"#,
        )
        .unwrap();
        check_saved_settings(&settings, &path).unwrap();
        settings.edge_secret = Some(SecretString::new("secret-edge-value".into()));
        let error = check_saved_settings(&settings, &path).unwrap_err();
        assert_eq!(error.code, 2);
        assert!(!error.message.contains("secret-edge-value"));
    }

    #[test]
    fn saved_device_settings_use_the_selected_team_without_a_member_token() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let team = crate::ids::TeamId::parse("t_abcdefgh23").unwrap();
        let mut settings = Settings {
            relay_url: Some("https://relay.example.test".into()),
            team_id: Some(team.clone()),
            device_id: Some(crate::ids::DeviceId(3)),
            ..Settings::default()
        };
        fs::write(&path, serde_json::json!({"version":2,"current":team,"teams":{
            team.as_str():{"relay_url":"https://relay.example.test","device_id":3,"member_token":null}
        }}).to_string()).unwrap();
        check_saved_settings(&settings, &path).unwrap();
        settings.team_id = crate::ids::TeamId::parse("t_abcdefgh24");
        let error = check_saved_settings(&settings, &path).unwrap_err();
        assert_eq!(error.code, 2);
        assert!(error.message.contains("selected team is missing"));
    }

    #[test]
    fn plist_arguments_and_session_settings() {
        let text = generate_plist(
            Path::new("/Applications/apassy-team"),
            &test_team(),
            HostOptions::default(),
            Path::new("/Users/a/Library/Logs/host.log"),
            None,
        )
        .unwrap();
        assert!(text.contains("<string>/Applications/apassy-team</string>\n        <string>--team</string>\n        <string>t_abcdefgh23</string>\n        <string>host</string>\n        <string>--dialog</string>"));
        assert!(text.contains("<string>--auto-limit</string>\n        <string>30</string>"));
        assert!(!text.contains("--ask-all"));
        assert!(!text.contains("EnvironmentVariables"));
        for secret in [
            "APASSY_TEAM_TOKEN",
            "APASSY_TOKEN",
            "APASSY_EDGE_SECRET",
            "APASSY_RELAY_URL",
        ] {
            assert!(!text.contains(secret));
        }
        for required in [
            "<key>RunAtLoad</key>\n    <true/>",
            "<key>KeepAlive</key>\n    <true/>",
            "<integer>30</integer>",
            "<string>Aqua</string>",
            "<string>Interactive</string>",
        ] {
            assert!(text.contains(required), "{required}");
        }
        assert_eq!(
            text.matches("<string>/Users/a/Library/Logs/host.log</string>")
                .count(),
            2
        );
    }

    #[test]
    fn plist_escapes_all_xml_characters_and_keeps_options() {
        let text = generate_plist(
            Path::new("/a &<>'\"/apassy-team"),
            &test_team(),
            HostOptions {
                ask_all: true,
                auto_limit: 7,
            },
            Path::new("/log &<>'\""),
            Some("/config &<>'\""),
        )
        .unwrap();
        for expected in [
            "/a &amp;&lt;&gt;&apos;&quot;/apassy-team",
            "/log &amp;&lt;&gt;&apos;&quot;",
            "/config &amp;&lt;&gt;&apos;&quot;",
            "<string>--ask-all</string>",
            "<string>7</string>",
            "<key>XDG_CONFIG_HOME</key>",
        ] {
            assert!(text.contains(expected), "{expected}");
        }
    }

    #[test]
    fn plist_rejects_relative_paths_and_invalid_xml() {
        for exe in ["relative", "/a\0b", "/a\u{1b}b", "/a\u{ffff}b"] {
            assert!(
                generate_plist(
                    Path::new(exe),
                    &test_team(),
                    HostOptions::default(),
                    Path::new("/log"),
                    None
                )
                .is_err()
            );
        }
        assert!(
            generate_plist(
                Path::new("/exe"),
                &test_team(),
                HostOptions::default(),
                Path::new("log"),
                None
            )
            .is_err()
        );
        assert!(
            generate_plist(
                Path::new("/exe"),
                &test_team(),
                HostOptions::default(),
                Path::new("/log"),
                Some("config")
            )
            .is_err()
        );
    }

    #[test]
    fn unit_default_arguments_and_log_paths() {
        let text = generate_unit(
            Path::new("/usr/local/bin/apassy-team"),
            &test_team(),
            HostOptions::default(),
            None,
        )
        .unwrap();
        assert!(
            text.contains("ExecStart=/usr/local/bin/apassy-team --team t_abcdefgh23 host --dialog --auto-limit 30\n")
        );
        assert!(!text.contains("--ask-all"));
        assert!(!text.contains("Environment="));
        assert!(text.contains("Restart=on-failure\nRestartSec=30\n"));
        assert_eq!(
            text.matches("append:%h/.config/apassy-team/service.log")
                .count(),
            2
        );
        assert!(text.contains("WantedBy=default.target"));
    }

    #[test]
    fn unit_custom_options_and_xdg() {
        let text = generate_unit(
            Path::new("/opt/apassy-team"),
            &test_team(),
            HostOptions {
                ask_all: true,
                auto_limit: 9,
            },
            Some("/custom/config"),
        )
        .unwrap();
        assert!(
            text.contains("ExecStart=/opt/apassy-team --team t_abcdefgh23 host --dialog --ask-all --auto-limit 9\n")
        );
        assert!(text.contains("Environment=XDG_CONFIG_HOME=/custom/config\n"));
        assert_eq!(
            text.matches("append:/custom/config/apassy-team/service.log")
                .count(),
            2
        );
        assert!(!text.contains("%h"));
    }

    #[test]
    fn unit_rejects_paths_that_systemd_can_interpret() {
        for path in [
            "relative", "/a b", "/a%b", "/a$b", "/a\"b", "/a'b", "/a\\b", "/a\nb", "/a;b",
        ] {
            assert!(
                generate_unit(Path::new(path), &test_team(), HostOptions::default(), None).is_err(),
                "{path:?}"
            );
            assert!(
                generate_unit(
                    Path::new("/exe"),
                    &test_team(),
                    HostOptions::default(),
                    Some(path)
                )
                .is_err(),
                "{path:?}"
            );
        }
    }

    #[test]
    fn output_cannot_send_terminal_controls() {
        assert_eq!(
            clean_output("ok\u{1b}[31m\r\t\0"),
            "ok\\u{1b}[31m\\r\\t\\u{0}"
        );
        assert_eq!(clean_output("café"), "café");
    }

    #[test]
    fn service_file_replacement_is_atomic_and_mode_0644() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("services/host.service");
        write_service(&path, "first file\n").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "first file\n");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        write_service(&path, "second file\n").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "second file\n");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644
        );
        assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);
    }
}
