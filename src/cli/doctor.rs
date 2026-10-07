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
                    Level::Ok,
                    "Broker",
                    format!("accepts agents on {socket}"),
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
    if let Some(sandbox) = sibling("apassy-sandbox") {
        let printed = std::process::Command::new(&sandbox)
            .args(["--print", "--", "/usr/bin/true"])
            .output();
        match printed {
            Ok(output) if output.status.success() => {
                report.add(Level::Ok, "Sandbox profile", "found", None);
            }
            Ok(output) => report.add(
                Level::Problem,
                "Sandbox profile",
                String::from_utf8_lossy(&output.stderr).trim().to_owned(),
                Some("Reinstall Apassy.app, or set APASSY_SANDBOX_PROFILE."),
            ),
            Err(err) => report.add(Level::Problem, "Sandbox profile", err.to_string(), None),
        }
    }

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

    // The agent hosts.
    let claude_config =
        read(&home.join(".claude.json")) + &read(&std::path::PathBuf::from(".mcp.json"));
    let claude_settings = read(&home.join(".claude").join("settings.json"))
        + &read(&std::path::PathBuf::from(".claude/settings.json"))
        + &read(&std::path::PathBuf::from(".claude/settings.local.json"));
    let codex_home = std::env::var_os("CODEX_HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| home.join(".codex"));
    let codex_config = read(&codex_home.join("config.toml"));
    let codex_hooks = read(&codex_home.join("hooks.json"));
    host_checks(
        &mut report,
        "Claude Code",
        claude_config.contains("apassy-mcp"),
        claude_settings.contains("apassy-hook"),
        "apassy setup claude --write",
    );
    host_checks(
        &mut report,
        "Codex",
        codex_config.contains("[mcp_servers.apassy]") && codex_config.contains("apassy-mcp"),
        codex_hooks.contains("apassy-hook"),
        "apassy setup codex --write",
    );
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
        print_json(&serde_json::json!({ "ok": !failed, "checks": report.0 }));
    } else {
        for check in &report.0 {
            let mark = match check.level {
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
        return Err(Failure::App {
            code: "doctor".to_owned(),
            message: "Some checks failed. See the fixes above.".to_owned(),
        });
    }
    Ok(())
}

fn host_checks(report: &mut Report, host: &'static str, mcp: bool, hook: bool, fix: &str) {
    match (mcp, hook) {
        (true, true) => report.add(Level::Ok, host, "MCP server and prompt hook set", None),
        (false, false) => report.add(Level::Note, host, "not connected", Some(fix)),
        (true, false) => report.add(
            Level::Note,
            host,
            "MCP server set, prompt hook missing",
            Some(fix),
        ),
        (false, true) => report.add(
            Level::Problem,
            host,
            "prompt hook set, MCP server missing",
            Some(fix),
        ),
    }
}
