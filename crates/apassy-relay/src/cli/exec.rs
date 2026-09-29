//! `apassy-team run -- <cmd>`: request a session, wait for approval, then run the command with the session environment.
//!
//! The session environment (placeholders and base URLs) goes only into the child. It is
//! never printed. The child does not inherit the CLI's own credentials
//! (`APASSY_TOKEN`, `APASSY_TEAM_TOKEN`, `APASSY_EDGE_SECRET`).

use std::collections::BTreeMap;
use std::process::Stdio;
use std::time::{Duration, Instant};

use crate::api::{self, RunRequest, RunStatus, RunView};
use crate::cli::CliError;
use crate::cli::args::RunArgs;
use crate::cli::client::{CALL_TIMEOUT, CallError, Client, LONG_POLL_MARGIN, Method};
use crate::cli::commands::clean;
use crate::cli::settings::{CREDENTIAL_VARS, Settings};
use crate::ids::{ItemId, RunId};

/// How long `run` waits for an approver when `--wait` is not given.
pub const DEFAULT_WAIT_SECS: u64 = 900;
/// The long poll of `GET /v1/runs/{id}`, in seconds.
const POLL_SECS: u64 = 25;
/// Consecutive network failures that `run` rides out while it waits.
const POLL_RETRIES: u32 = 3;

pub fn run(settings: &Settings, args: RunArgs) -> Result<i32, CliError> {
    let client = Client::new(
        settings.relay()?,
        Some(settings.agent()?),
        settings.edge_secret.as_ref(),
    );
    let cwd = match &args.cwd {
        Some(dir) => std::path::absolute(dir),
        None => std::env::current_dir(),
    }
    .map_err(|e| CliError::usage(format!("Cannot find the working directory: {}.", e.kind())))?;
    let cwd_text = cwd
        .to_str()
        .ok_or_else(|| CliError::usage("The working directory is not UTF-8 text."))?
        .to_owned();

    let request = RunRequest {
        items: args.items.iter().copied().map(ItemId).collect(),
        command: args.command.clone(),
        purpose: args.purpose.clone(),
        user_request: args.request.clone(),
        cwd: Some(cwd_text),
        ttl_secs: args.ttl,
    };
    let payload = serde_json::to_string(&request)
        .map_err(|_| CliError::usage("Cannot encode the request."))?;
    let view: RunView =
        match client.call(Method::Post, api::paths::RUNS, Some(&payload), CALL_TIMEOUT) {
            Ok(view) => view,
            Err(CallError::Api(e)) if e.is_rule_denial() => {
                return Err(CliError::denied(format!(
                    "Run denied: {}: {}",
                    e.code,
                    clean(&e.message)
                )));
            }
            Err(other) => return Err(other.into_cli()),
        };

    let view = wait_until_decided(&client, view, args.wait.unwrap_or(DEFAULT_WAIT_SECS))?;
    match view.status {
        RunStatus::Ready => {
            let env = view
                .session
                .map(|s| s.env)
                .ok_or_else(|| CliError::relay("The relay said ready but sent no session."))?;
            spawn(&args.command, &env, args.cwd.as_deref())
        }
        RunStatus::Pending => unreachable_pending(view.run_id),
        status => Err(CliError::denied(format!(
            "Run {} {}{}: {}",
            view.run_id,
            match status {
                RunStatus::TimedOut => "timed out",
                RunStatus::Ended => "ended before it started",
                _ => "was denied",
            },
            view.code.map(|c| format!(" ({c})")).unwrap_or_default(),
            clean(&view.note)
        ))),
    }
}

fn unreachable_pending(id: RunId) -> Result<i32, CliError> {
    Err(CliError::relay(format!(
        "Run {id} is still pending after the wait ended."
    )))
}

/// Polls while the run is `pending`. Says once on stderr that it waits.
fn wait_until_decided(
    client: &Client,
    first: RunView,
    wait_secs: u64,
) -> Result<RunView, CliError> {
    let mut view = first;
    if view.status != RunStatus::Pending {
        return Ok(view);
    }
    eprintln!("Waiting for an approver (run {}).", view.run_id);
    let deadline = Instant::now() + Duration::from_secs(wait_secs);
    let mut failures = 0;
    while view.status == RunStatus::Pending {
        let left = deadline.saturating_duration_since(Instant::now()).as_secs();
        if left == 0 {
            return Err(CliError::denied(format!(
                "Gave up waiting for an approver (run {}). The run may still be approved later.",
                view.run_id
            )));
        }
        let path = format!(
            "{}/{}?wait={}",
            api::paths::RUNS,
            view.run_id,
            left.min(POLL_SECS)
        );
        match client.call::<RunView>(
            Method::Get,
            &path,
            None,
            Duration::from_secs(POLL_SECS) + LONG_POLL_MARGIN,
        ) {
            Ok(next) => {
                failures = 0;
                view = next;
            }
            Err(CallError::Transport(message)) => {
                failures += 1;
                if failures >= POLL_RETRIES {
                    return Err(CliError::relay(message));
                }
                std::thread::sleep(Duration::from_secs(2));
            }
            Err(api_error) => return Err(api_error.into_cli()),
        }
    }
    Ok(view)
}

/// Runs the child with `env` added, inherited stdio, and returns its exit code.
fn spawn(
    argv: &[String],
    env: &BTreeMap<String, String>,
    cwd: Option<&str>,
) -> Result<i32, CliError> {
    let mut command = std::process::Command::new(&argv[0]);
    command
        .args(&argv[1..])
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    for name in CREDENTIAL_VARS {
        command.env_remove(name);
    }
    command.envs(env);
    if let Some(dir) = cwd {
        command.current_dir(dir);
    }
    let status = command.status().map_err(|e| {
        let code = match e.kind() {
            std::io::ErrorKind::NotFound => 127,
            std::io::ErrorKind::PermissionDenied => 126,
            _ => 4,
        };
        CliError {
            code,
            message: format!("Cannot run `{}`: {}.", clean(&argv[0]), e.kind()),
        }
    })?;
    Ok(exit_code(status))
}

/// The exit code of a child: its code, or 128 plus the signal number.
pub fn exit_code(status: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    match status.code() {
        Some(code) => code,
        None => 128 + status.signal().unwrap_or(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    #[test]
    fn exit_codes_pass_through_and_signals_add_128() {
        assert_eq!(exit_code(ExitStatus::from_raw(0)), 0);
        assert_eq!(exit_code(ExitStatus::from_raw(7 << 8)), 7);
        // A raw status of 9 is "killed by signal 9".
        assert_eq!(exit_code(ExitStatus::from_raw(9)), 137);
    }
}
