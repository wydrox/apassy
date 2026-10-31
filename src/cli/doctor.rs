//! `apassy doctor`: check the installation and say how to fix each problem.

use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::Path;

use super::args::Args;
use super::setup::sibling;
use super::{Cli, Failure, Outcome, print_json};
use crate::owner::wire::{Command, Data, SESSION_ENV, VaultState};

pub const HELP: &str = "\
apassy doctor [--json]

Checks the Apassy window, the vault, the broker, the command-line session, the programs
next to apassy, the data directory, and the agent hosts (Claude Code and Codex). Each
problem has a fix. The exit code is 1 when a check fails.
";

#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum Level {
    Unverified,
    Ok,
    Note,
    Problem,
}

#[derive(serde::Serialize)]
struct Check {
    level: Level,
    name: &'static str,
    detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    fix: Option<String>,
}

struct Report(Vec<Check>);

impl Report {
    fn add(
        &mut self,
        level: Level,
        name: &'static str,
        detail: impl Into<String>,
        fix: Option<&str>,
    ) {
        self.0.push(Check {
            level,
            name,
            detail: detail.into(),
            fix: fix.map(str::to_owned),
        });
    }
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

pub fn run(cli: &Cli, args: Args) -> Outcome {
    args.finish()?;
    let mut report = Report(Vec::new());
    let home = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_default();

    // The window and the vault.
    let status = match cli.send(Command::Status) {
        Ok(response) => match response.data {
            Data::Status(status) => Some(status),
            _ => None,
        },
        Err(Failure::NotRunning(message)) => {
            report.add(
                Level::Problem,
                "Apassy window",
                message,
                Some("Check the owner socket path. If Apassy is closed, open Apassy.app."),
            );
            None
        }
        Err(failure) => return Err(failure),
    };
    if let Some(status) = &status {
        let ours = env!("CARGO_PKG_VERSION");
        if status.version == ours {
            report.add(
                Level::Ok,
                "Apassy window",
                format!("running, version {ours}"),
                None,
            );
        } else {
            report.add(
                Level::Problem,
                "Apassy window",
                format!(
                    "version {} answers, but this apassy is {ours}",
                    status.version
                ),
                Some("Use the apassy program inside the running Apassy.app."),
            );
        }
        match status.vault {
            VaultState::Unlocked => report.add(Level::Ok, "Vault", "unlocked", None),
            VaultState::Locked => report.add(
                Level::Note,
                "Vault",
                "locked: agents get vault_locked",
                Some("apassy unlock, then unlock in the window."),
            ),
            VaultState::None => report.add(
                Level::Problem,
                "Vault",
                "no vault file is open",
                Some("Create or open a vault in the window."),
            ),
        }
        if status.broker == "running" {
            let socket = status.broker_socket.clone().unwrap_or_default();
            if UnixStream::connect(&socket).is_ok() {
                report.add(
                    Level::Unverified,
                    "Broker",
                    format!(
                        "socket accepts connections on {socket}; agent authentication unverified"
                    ),
                    None,
                );
            } else {
                report.add(
                    Level::Problem,
                    "Broker",
                    format!("the socket {socket} does not accept connections"),
                    Some("Quit and open Apassy again."),
                );
            }
        } else {
            report.add(
                Level::Problem,
                "Broker",
                status.broker.clone(),
                Some("Quit and open Apassy again. Settings > Agents > Broker and bouncer shows the reason."),
            );
        }
        report.add(
            if status.touch_id {
                Level::Ok
            } else {
                Level::Note
            },
            "Touch ID",
            if status.touch_id {
                "available for owner checks"
            } else {
                "not available: owner checks ask for the passphrase"
            },
            None,
        );
        match (status.session, cli.has_session()) {
            (true, _) => report.add(Level::Ok, "Session", "open", None),
            (false, true) => report.add(
                Level::Note,
                "Session",
                format!("{SESSION_ENV} is set, but the session ended"),
                Some("eval \"$(apassy login)\""),
            ),
            (false, false) => report.add(
                Level::Note,
                "Session",
                "none",
                Some("eval \"$(apassy login)\" for item, agent, and grant commands."),
            ),
        }
        if let Some(count) = status.waiting_runs.filter(|count| *count > 0) {
            report.add(
                Level::Note,
                "Runs waiting",
                count.to_string(),
                Some("apassy runs"),
            );
        }
        if let Some(count) = status.open_requests.filter(|count| *count > 0) {
            report.add(
                Level::Note,
                "Open requests",
                count.to_string(),
                Some("apassy request list"),
            );
        }
        if let Some(count) = status.items_to_review.filter(|count| *count > 0) {
            report.add(
                Level::Note,
                "To review",
                format!("{count} credentials wait for a review after a restore"),
                Some("apassy item review ITEM"),
            );
        }
    }

    // The release bundle ships all three programs next to apassy. Source builds
    // use the same layout in target/debug or target/release.
    for name in ["apassy-mcp", "apassy-hook", "apassy-sandbox"] {
        match sibling(name) {
            Some(path) => report.add(Level::Ok, "Program", path.display().to_string(), None),
            None => report.add(
                Level::Problem,
                "Program",
                format!("{name} is not next to apassy"),
                Some("Reinstall Apassy.app. For a source build, build all programs with cargo build --locked --features desktop,vault --bins."),
            ),
        }
    }
    report.add(
        Level::Unverified,
        "Sandbox enforcement",
        "unverified: static checks do not execute a sandbox",
        None,
    );
    // The data directory.
    let data = crate::paths::data_dir();
    match std::fs::metadata(&data) {
        Ok(meta) if meta.permissions().mode() & 0o077 == 0 => {
            report.add(
                Level::Ok,
                "Data directory",
                format!("{} (mode 0700)", data.display()),
                None,
            );
        }
        Ok(meta) => report.add(
            Level::Problem,
            "Data directory",
            format!(
                "{} has mode {:o}",
                data.display(),
                meta.permissions().mode() & 0o777
            ),
            Some("chmod 700 on the data directory. The broker refuses a shared directory."),
        ),
        Err(_) => report.add(
            Level::Note,
            "Data directory",
            format!("{} does not exist yet", data.display()),
            None,
        ),
    }

    // Inspect only configuration, never execute a referenced program.
    let claude_dir = std::env::var_os("CLAUDE_CONFIG_DIR")
        .filter(|dir| !dir.is_empty())
        .map(std::path::PathBuf::from);
    let config = claude_dir
        .as_ref()
        .map_or_else(|| home.join(".claude.json"), |dir| dir.join(".claude.json"));
    let settings = claude_dir
        .unwrap_or_else(|| home.join(".claude"))
        .join("settings.json");
    let mut effective = serde_json::json!({});
    let mut local_server = None;
    let mut locally_disabled = false;
    for path in [config, std::path::PathBuf::from(".mcp.json")] {
        if let Some(value) = json_config(&mut report, &path) {
            if let Some(entry) = value.pointer("/mcpServers/apassy") {
                effective = entry.clone();
            }
            if let Some(cwd) = std::env::current_dir()
                .ok()
                .and_then(|p| p.to_str().map(str::to_owned))
            {
                if let Some(entry) = value
                    .get("projects")
                    .and_then(|p| p.get(&cwd))
                    .and_then(|p| p.pointer("/mcpServers/apassy"))
                {
                    local_server = Some(entry.clone());
                }
                locally_disabled |= value
                    .get("projects")
                    .and_then(|p| p.get(&cwd))
                    .and_then(|p| p.get("disabledMcpServers"))
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|entries| entries.iter().any(|entry| entry == "apassy"));
            }
        }
    }
    if let Some(local) = local_server {
        effective = local;
    }
    if locally_disabled {
        effective["disabled"] = serde_json::json!(true);
    }
    server_check(&mut report, "Claude Code", &effective);
    let mut hooks_disabled = false;
    let mut mcp_disabled = false;
    for path in [
        settings,
        ".claude/settings.json".into(),
        ".claude/settings.local.json".into(),
    ] {
        if let Some(value) = json_config(&mut report, &path) {
            if let Some(disabled) = value
                .get("disableAllHooks")
                .and_then(serde_json::Value::as_bool)
            {
                hooks_disabled = disabled;
            }
            if let Some(disabled) = value
                .get("disabledMcpServers")
                .and_then(serde_json::Value::as_array)
            {
                mcp_disabled = disabled.iter().any(|x| x == "apassy");
            }
        }
    }
    if hooks_disabled || mcp_disabled {
        report.add(
            Level::Problem,
            "Claude Code",
            "Apassy MCP or hooks disabled in settings",
            Some("Review the effective Claude settings."),
        );
    }
    let codex_home = std::env::var_os("CODEX_HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| home.join(".codex"));
    let path = codex_home.join("config.toml");
    if path.exists() {
        match read(&path).parse::<toml_edit::DocumentMut>() {
            Ok(doc) => {
                let server = doc.get("mcp_servers").and_then(|v| v.get("apassy"));
                let value = serde_json::json!({"command": server.and_then(|v| v.get("command")).and_then(toml_edit::Item::as_str), "enabled": server.and_then(|v| v.get("enabled")).and_then(toml_edit::Item::as_bool).unwrap_or(true)});
                server_check(&mut report, "Codex", &value);
            }
            Err(_) => report.add(
                Level::Problem,
                "Codex",
                "invalid or unreadable config.toml",
                Some("Repair the TOML configuration."),
            ),
        }
    } else {
        report.add(
            Level::Note,
            "Codex",
            "MCP entry missing",
            Some("apassy setup codex --write"),
        );
    }
    report.add(Level::Unverified, "Host connection", "unverified: static config does not prove MCP reachability, hook execution, trust, or enforcement", Some("In the sandboxed host check /mcp, hook trust, and a synthetic first request."));
    if std::env::var_os(SESSION_ENV).is_some() && std::env::var_os("CLAUDECODE").is_some() {
        report.add(
            Level::Problem,
            "Session in an agent",
            format!("{SESSION_ENV} is set inside an agent host"),
            Some("Run apassy logout. Start agents from a shell without a session, or with apassy-sandbox."),
        );
    }

    let failed = report.0.iter().any(|check| check.level == Level::Problem);
    if cli.json {
        print_json(
            &serde_json::json!({ "ok": !failed, "code": if failed { "doctor" } else { "ok" }, "stage": "checks", "partial_state": {}, "checks": report.0 }),
        );
    } else {
        for check in &report.0 {
            let mark = match check.level {
                Level::Unverified => "unverified",
                Level::Ok => "ok  ",
                Level::Note => "note",
                Level::Problem => "FAIL",
            };
            println!("{mark}  {:<16} {}", check.name, check.detail);
            if let Some(fix) = &check.fix {
                println!("      {:<16} → {fix}", "");
            }
        }
    }
    if failed {
        if cli.json {
            return Err(Failure::Printed);
        }
        return Err(Failure::App {
            code: "doctor".to_owned(),
            message: "Some checks failed. See the fixes above.".to_owned(),
        });
    }
    Ok(())
}

fn json_config(report: &mut Report, path: &Path) -> Option<serde_json::Value> {
    match std::fs::read(path) {
        Ok(bytes) => match serde_json::from_slice(&bytes) {
            Ok(value) => Some(value),
            Err(_) => {
                report.add(
                    Level::Problem,
                    "Host config",
                    format!("{}: invalid JSON", path.display()),
                    Some("Repair the configuration."),
                );
                None
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => {
            report.add(
                Level::Problem,
                "Host config",
                format!("{}: unreadable", path.display()),
                None,
            );
            None
        }
    }
}

fn executable(command: &str) -> bool {
    let usable = |p: &Path| {
        std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    };
    if command.contains('/') {
        usable(Path::new(command))
    } else {
        std::env::var_os("PATH")
            .is_some_and(|path| std::env::split_paths(&path).any(|dir| usable(&dir.join(command))))
    }
}

fn server_check(report: &mut Report, host: &'static str, value: &serde_json::Value) {
    if value.get("disabled").and_then(serde_json::Value::as_bool) == Some(true)
        || value.get("enabled").and_then(serde_json::Value::as_bool) == Some(false)
    {
        report.add(
            Level::Problem,
            host,
            "MCP entry disabled",
            Some("Enable the Apassy MCP entry."),
        );
    } else if let Some(command) = value.get("command").and_then(serde_json::Value::as_str) {
        report.add(
            if executable(command) {
                Level::Unverified
            } else {
                Level::Problem
            },
            host,
            if executable(command) {
                "MCP executable exists; connection and prompt hook unverified"
            } else {
                "MCP executable missing or not executable"
            },
            Some("Check the configured command; verify the connection in the host."),
        );
    } else {
        report.add(
            Level::Note,
            host,
            "MCP entry missing",
            Some("Run apassy setup HOST --write."),
        );
    }
}

#[cfg(all(test, feature = "vault"))]
mod tests {
    use super::*;
    #[test]
    fn referenced_wrapper_requires_executable_bits_and_is_never_run() {
        let dir = tempfile::tempdir().unwrap();
        let wrapper = dir.path().join("wrapper");
        std::fs::write(&wrapper, "synthetic invalid executable contents").unwrap();
        std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o600)).unwrap();
        let value = serde_json::json!({"command":wrapper});
        let mut report = Report(vec![]);
        server_check(&mut report, "Claude", &value);
        assert!(report.0[0].level == Level::Problem);
        std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut report = Report(vec![]);
        server_check(&mut report, "Claude", &value);
        assert!(report.0[0].level == Level::Unverified);
    }

    #[test]
    fn static_configs_are_parsed_without_executing_or_showing_contents() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        let mut report = Report(vec![]);
        std::fs::write(&path, "not JSON synthetic-secret").unwrap();
        assert!(json_config(&mut report, &path).is_none());
        server_check(
            &mut report,
            "Claude",
            &serde_json::json!({"command":"/missing/wrapper"}),
        );
        server_check(
            &mut report,
            "Claude",
            &serde_json::json!({"command":"/bin/sh", "disabled":true}),
        );
        assert!(report.0.iter().all(|c| c.level == Level::Problem));
        assert!(
            !serde_json::to_string(&report.0)
                .unwrap()
                .contains("synthetic-secret")
        );
    }
}
