//! `apassy setup claude|codex`: register an agent and write its host configuration.
//!
//! The token goes into two wrapper scripts with mode 0700 in `~/.config/apassy`: one
//! for `apassy-mcp` and one for `apassy-hook`. The host configuration names the
//! wrappers, so no host file holds the token, and a rotation changes only the wrappers.
//! The wrapper names keep `apassy-hook` and `apassy-mcp`, so the `hook_channel` check
//! of the bouncer still sees them (`docs/operations/host-hooks.md`, section 7).

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use super::args::{Args, usage};
use super::terminal;
use super::{Cli, Failure, Outcome};
use crate::owner::wire::{Command, Data, SecretText};

pub const HELP: &str = "\
apassy setup claude|codex [--name NAME] [--token-stdin] [--hook PATH] [--write] [--repair] [--agent-id ID]

Prepare an agent host for Apassy:
  Without --write, validate and preview only; no agent or files are changed.
  With --write:
  1. Connect an agent named NAME (default: Claude Code or Codex) and take its token.
     --token-stdin uses a token that you already have, from stdin.
  2. Write two scripts with mode 0700 that hold the token:
       ~/.config/apassy/apassy-mcp-HOST.sh    starts apassy-mcp
       ~/.config/apassy/apassy-hook-HOST.sh   starts apassy-hook (the prompt hook)
  3. Print the host configuration. With --write, also add it:
       claude   the MCP server through `claude mcp add --scope user`, and the hook in
                ~/.claude/settings.json (a copy of the old file stays next to it)
       codex    [mcp_servers.apassy] in ~/.codex/config.toml, and the hook in
                ~/.codex/hooks.json. Then trust the hook in Codex with /hooks.

Apassy.app includes the MCP server, prompt hook, and sandbox.
Use --hook PATH only to select a different prompt hook.
Agents, tokens, exceptions, and your answers stay on this Mac. A synced vault does not
copy them.
--repair --write restores missing managed files using the saved token; it never registers
an agent or changes catalog access. --agent-id ID records an explicit agent identity.
For an orphan with no wrappers, use --token-stdin --agent-id ID after an owner reconnect.
File apply failures restore prior bytes and modes. Process crashes during commit still
require a repair; this is not a crash-recovery journal.
This command writes configuration. It does not check the host connection or a first request.

Then there is nothing to give: the agent lists your credentials without values and uses
them, and the bouncer decides each use. When it asks you, the question is in Decisions.
Start the host in the Apassy sandbox (see docs/operations/isolation.md):
  claude: MCP_TOOL_TIMEOUT=660000 apassy-sandbox -- claude --settings '{\"sandbox\":{\"enabled\":false}}'
  codex:  apassy-sandbox -- codex -c sandbox_mode=danger-full-access
Host approval prompts stay active.
";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Host {
    Claude,
    Codex,
}

impl Host {
    fn id(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
        }
    }

    fn default_name(self) -> &'static str {
        match self {
            Self::Claude => "Claude Code",
            Self::Codex => "Codex",
        }
    }
}

fn home() -> Result<PathBuf, Failure> {
    std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| Failure::App {
            code: "home_missing".to_owned(),
            message: "HOME is not set.".to_owned(),
        })
}

/// The directory of this program. `apassy-mcp` and `apassy-hook` are next to it in
/// the app bundle and in a cargo build.
pub fn program_dir() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|exe| fs::canonicalize(exe).ok())
        .and_then(|exe| exe.parent().map(Path::to_path_buf))
}

/// The path of a sibling program, if it exists.
pub fn sibling(name: &str) -> Option<PathBuf> {
    program_dir()
        .map(|dir| dir.join(name))
        .filter(|path| path.is_file())
}

/// A shell word in single quotes.
fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

/// Write a wrapper with mode 0700. The directory gets mode 0700 too.
fn write_wrapper(path: &Path, program: &Path, token: &SecretText) -> Result<(), Failure> {
    let dir = path
        .parent()
        .ok_or_else(|| Failure::Other("The wrapper has no directory.".to_owned()))?;
    fs::create_dir_all(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    let body = zeroize::Zeroizing::new(format!(
        "#!/bin/sh\n# Written by apassy setup. It holds an agent token: keep mode 0700, never commit it.\nAPASSY_AGENT_TOKEN={} exec {} \"$@\"\n",
        quote(token.expose()),
        quote(&program.display().to_string())
    ));
    let temp = path.with_extension("sh.tmp");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o700)
        .open(&temp)?;
    file.write_all(body.as_bytes())?;
    file.sync_all()?;
    fs::rename(&temp, path)?;
    Ok(())
}

/// Fixed status codes let the desktop explain errors without reading child output.
/// The private status file is created by the desktop, never by this command.
pub fn run(cli: &Cli, mut args: Args) -> Outcome {
    let status_path = args.value(&["--desktop-status"])?;
    let mut status = status_path
        .map(|path| open_desktop_status(Path::new(&path)))
        .transpose()?;
    let mut stages = Vec::new();
    let result = run_host(cli, args, &mut stages);
    if let Err(failure) = &result {
        let message = match failure {
            Failure::App { message, .. }
            | Failure::Other(message)
            | Failure::NotRunning(message) => message.as_str(),
            Failure::Usage(usage) => usage.0.as_str(),
            Failure::Printed | Failure::PrintedExit(_) => "Setup failed.",
        };
        eprintln!("apassy setup: {}", super::print::clean(message));
    }
    let setup_json = cli.json && stages.first() != Some(&"browser_delegated");
    if setup_json {
        println!("{}", setup_report(&result, &stages));
    }
    if let Some(status) = status.as_mut() {
        status.write_all(status_code(&result).as_bytes())?;
    }
    // Keep the existing public CLI error format and exit behavior.
    let code = status_code(&result);
    result.map_err(|failure| {
        if setup_json {
            let exit = match failure {
                Failure::Usage(_) => super::EXIT_USAGE,
                Failure::NotRunning(_) => super::EXIT_NOT_RUNNING,
                _ => super::EXIT_FAILED,
            };
            Failure::PrintedExit(exit)
        } else {
            match failure {
                Failure::App { message, .. } if code != "failed" => Failure::Other(message),
                failure => failure,
            }
        }
    })
}

/// Accept only an existing empty private file. Do not create or truncate a path
/// supplied as an argument, and reject symlinks before any write.
fn open_desktop_status(path: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::MetadataExt;
    let before = fs::symlink_metadata(path)?;
    if !before.is_file() || before.len() != 0 || before.permissions().mode() & 0o777 != 0o600 {
        return Err(std::io::Error::other(
            "The desktop status file is not an empty private file.",
        ));
    }
    let file = fs::OpenOptions::new().write(true).open(path)?;
    let after = file.metadata()?;
    if before.dev() != after.dev() || before.ino() != after.ino() || after.len() != 0 {
        return Err(std::io::Error::other("The desktop status file changed."));
    }
    Ok(file)
}

fn status_code(result: &Outcome) -> &'static str {
    match result {
        Ok(()) => "ok",
        Err(Failure::App { code, .. }) => match code.as_str() {
            "missing_mcp" => "missing_mcp",
            "missing_hook" => "missing_hook",
            "home_missing" => "home_missing",
            "config_read" => "config_read",
            "config_invalid" => "config_invalid",
            "config_conflict" => "config_conflict",
            "config_write" => "config_write",
            "wrapper_write" => "wrapper_write",
            "hooks_read" => "hooks_read",
            "hooks_invalid" => "hooks_invalid",
            "hooks_disabled" => "hooks_disabled",
            "hooks_write" => "hooks_write",
            "host_start" => "host_start",
            "host_failed" => "host_failed",
            "host_verify" => "host_verify",
            "token_read" => "token_read",
            "token_invalid" => "token_invalid",
            _ => "failed",
        },
        Err(Failure::Usage(usage))
            if usage.0 == "The token on stdin does not start with apassy_agt_." =>
        {
            "token_invalid"
        }
        Err(_) => "failed",
    }
}

/// Add an allowlisted stage to an existing failure while keeping CLI messages.
fn at_stage(failure: Failure, code: &str) -> Failure {
    match failure {
        Failure::Other(message) => Failure::App {
            code: code.to_owned(),
            message,
        },
        failure => failure,
    }
}

fn run_host(cli: &Cli, mut args: Args, stages: &mut Vec<&'static str>) -> Outcome {
    let host = match args.required("host: claude, codex, or browser")?.as_str() {
        "claude" | "claude-code" => Host::Claude,
        "codex" => Host::Codex,
        // ADR 0021: the browser extension. It registers no agent.
        "browser" => {
            stages.push("browser_delegated");
            return super::browser::run(args);
        }
        other => {
            return Err(Failure::Usage(usage(format!(
                "Unknown host \"{other}\". Use claude, codex, or browser."
            ))));
        }
    };
    let name = args
        .value(&["--name"])?
        .unwrap_or_else(|| host.default_name().to_owned());
    let token_stdin = args.flag(&["--token-stdin"]);
    let repair = args.flag(&["--repair"]);
    let agent_id = args.value(&["--agent-id"])?;
    let write = args.flag(&["--write"]);
    let hook_path = args.value(&["--hook"])?;
    args.finish()?;

    let mcp = sibling("apassy-mcp")
        .ok_or_else(|| {
            Failure::Other(
                "apassy-mcp is not next to this program. Use the apassy program inside Apassy.app."
                    .to_owned(),
            )
        })
        .map_err(|failure| at_stage(failure, "missing_mcp"))?;
    // The release app and source build keep the hook next to apassy.
    let hook = match hook_path {
        Some(path) => {
            let path = fs::canonicalize(&path)
                .map_err(|err| Failure::Other(format!("Cannot find {path}: {err}")))?;
            if !path.is_file() {
                return Err(Failure::Usage(usage(
                    "--hook needs the path of apassy-hook.",
                )));
            }
            Some(path)
        }
        None => sibling("apassy-hook"),
    };
    if write && hook.is_none() {
        return Err(at_stage(Failure::Other(
            "The prompt hook is missing. Reinstall the complete Apassy.app package, then try setup again."
                .to_owned(),
        ), "missing_hook"));
    }
    let dir = home()?.join(".config").join("apassy");
    let mcp_wrapper = dir.join(format!("apassy-mcp-{}.sh", host.id()));
    if write && host == Host::Codex {
        // Detect an incompatible server before replacing a saved token.
        let config = codex_home()?.join("config.toml");
        codex_section_present(
            &read_optional_config(&config)?,
            &codex_section(&mcp_wrapper),
        )?;
    } else if write && host == Host::Claude {
        let (config, _) = claude_paths(&home()?, std::env::var_os("CLAUDE_CONFIG_DIR"));
        claude_server_present(&config, &mcp_wrapper)?;
    }

    let hook_wrapper_path = dir.join(format!("apassy-hook-{}.sh", host.id()));
    for program in std::iter::once(&mcp).chain(hook.iter()) {
        if fs::metadata(program)?.permissions().mode() & 0o111 == 0 {
            return Err(Failure::Other(
                "A required helper is not executable.".into(),
            ));
        }
    }
    let (config, hooks) = match host {
        Host::Claude => claude_paths(&home()?, std::env::var_os("CLAUDE_CONFIG_DIR")),
        Host::Codex => (
            codex_home()?.join("config.toml"),
            codex_home()?.join("hooks.json"),
        ),
    };
    if host == Host::Codex {
        codex_section_present(
            &read_optional_config(&config)?,
            &codex_section(&mcp_wrapper),
        )?;
    } else if !claude_server_present(&config, &mcp_wrapper)? && !executable_on_path("claude") {
        return Err(at_stage(Failure::Other("Cannot find an executable Claude Code command in PATH. Install Claude Code before connecting an agent.".into()), "host_start"));
    }
    merge_hook_checked(&hooks, &hook_wrapper_path, false)?;
    if host == Host::Claude {
        claude_timeout(&hooks, false)?;
    }
    for path in [&mcp_wrapper, &hook_wrapper_path, &config, &hooks] {
        writable_destination(path)?;
    }
    let mut existing = managed_token(&mcp_wrapper, &mcp)?;
    if let Some(hook) = &hook {
        let other = managed_token(&hook_wrapper_path, hook)?;
        if repair && existing.is_none() {
            existing = other;
        } else if !repair
            && !token_stdin
            && existing.as_ref().map(SecretText::expose) != other.as_ref().map(SecretText::expose)
        {
            return Err(Failure::Other("Managed wrappers are incomplete. Repair with the existing token using --token-stdin; do not register another agent.".into()));
        }
    }
    stages.push("preflight");
    if !write {
        stages.push("preview");
        eprintln!("Preflight passed. Run with --write to connect and save settings.");
        return match host {
            Host::Claude => claude(
                &mcp_wrapper,
                hook.as_ref().map(|_| hook_wrapper_path.as_path()),
                false,
                stages,
            ),
            Host::Codex => codex(
                &mcp_wrapper,
                hook.as_ref().map(|_| hook_wrapper_path.as_path()),
                false,
                stages,
            ),
        };
    }
    let identity_path = dir.join(format!("connection-{}.json", host.id()));
    let saved_identity: Option<serde_json::Value> = if identity_path.exists() {
        Some(
            serde_json::from_str(&read_optional_config(&identity_path)?).map_err(|_| {
                Failure::Other("Invalid connection identity. Review before reconnecting.".into())
            })?,
        )
    } else {
        None
    };
    let mut identity = agent_id.or_else(|| {
        saved_identity
            .as_ref()
            .and_then(|v| v["agent_id"].as_str().map(str::to_owned))
    });
    if let Some(id) = &identity
        && !token_stdin
    {
        let response = cli.call(Command::AgentShow { agent: id.clone() })?;
        if !matches!(response.data, Data::Agent(ref view) if !view.agent.revoked && !view.agent.token_expired)
        {
            return Err(Failure::Other("Connection points to a missing, revoked, or expired agent. Reconnect explicitly in Agents; catalog access is preserved.".into()));
        }
    }
    if repair && existing.is_none() && !token_stdin {
        return Err(Failure::Other("Orphaned connection: supply the existing agent token with --token-stdin and --agent-id ID, or reconnect in Agents. Repair never creates an agent.".into()));
    }
    let mut created = None;
    let token = if token_stdin {
        let token =
            terminal::read_stdin_secret().map_err(|error| at_stage(error.into(), "token_read"))?;
        if !token
            .expose()
            .starts_with(crate::owner::wire::AGENT_TOKEN_PREFIX)
        {
            return Err(Failure::Usage(usage(
                "The token on stdin does not start with apassy_agt_.",
            )));
        }
        token
    } else if let Some(token) = existing {
        stages.push("connection_reused");
        token
    } else {
        stages.push("connection_requested");
        let response = cli.call(Command::AgentConnect { name: name.clone() })?;
        match response.data {
            Data::Token { token, agent } => {
                identity = Some(agent.id.to_string());
                created = Some(agent.id);
                eprintln!("Connected {} (ID {}).", agent.name, agent.id);
                stages.push("agent_connected");
                token
            }
            _ => return Err(Failure::Other("Apassy sent no token.".to_owned())),
        }
    };

    let result = stage_connection(
        host,
        &mcp_wrapper,
        &hook_wrapper_path,
        &mcp,
        hook.as_deref()
            .ok_or_else(|| Failure::Other("Missing hook.".into()))?,
        &token,
        &config,
        &hooks,
        &identity_path,
        identity.as_deref(),
    );
    drop(token);
    if let Err(failure) = result {
        stages.push("files_rolled_back");
        if let Some(id) = created {
            if cli
                .call(Command::AgentRevoke {
                    agent: id.to_string(),
                })
                .is_ok()
            {
                stages.push("agent_revoked");
            } else {
                stages.push("orphan_requires_revocation");
            }
        }
        return Err(failure);
    }
    stages.push("host_config_written");
    eprintln!(
        "{}. The host connection and first request are not checked.",
        if write {
            "Host settings were written"
        } else {
            "Host configuration is shown above"
        }
    );
    eprintln!(
        "Keep Apassy.app open and the vault unlocked. Restart the host. Check Apassy with /mcp."
    );
    if host == Host::Codex {
        eprintln!("Use /hooks to trust the Apassy hook before the first request.");
    }
    eprintln!(
        "Next: nothing to give. The connected agent lists the credentials available to it without values and uses them; the bouncer decides each use."
    );
    eprintln!("When the bouncer asks you, answer in Decisions in the Apassy window.");
    eprintln!("From the project folder, start the host in the Apassy sandbox:");
    match host {
        Host::Claude => eprintln!(
            "MCP_TOOL_TIMEOUT=660000 apassy-sandbox -- claude --settings '{{\"sandbox\":{{\"enabled\":false}}}}'"
        ),
        Host::Codex => eprintln!("apassy-sandbox -- codex -c sandbox_mode=danger-full-access"),
    }
    eprintln!(
        "The Apassy sandbox replaces the host's inner sandbox. Host approval prompts stay active."
    );
    eprintln!(
        "Use a test credential for the first request. Check its result and its entry in Decisions."
    );
    Ok(())
}

fn setup_report(result: &Outcome, stages: &[&str]) -> serde_json::Value {
    let code = match result {
        Err(Failure::App { code, .. }) => code.as_str(),
        Err(Failure::Usage(_)) => "usage",
        Err(Failure::NotRunning(_)) => "not_running",
        _ => status_code(result),
    };
    serde_json::json!({
        "ok": result.is_ok(), "code": code,
        "message": if result.is_ok() { "Setup completed; connection and first use remain unverified." } else { "Setup failed. Check stderr and completed stages before retrying." },
        "stage": stages.last().copied().unwrap_or("preflight"),
        "partial_state": { "stages": stages,
            "partial": result.is_err() && stages.iter().any(|stage| stage.ends_with("_written") || *stage == "agent_connected"),
            "changes_unknown": matches!(result, Err(Failure::Other(_))) && stages.contains(&"connection_requested") && !stages.contains(&"agent_connected") },
        "data": { "type": "setup", "connection_verified": false }
    })
}

fn executable_on_path(name: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|paths| {
        std::env::split_paths(&paths).any(|dir| {
            fs::metadata(dir.join(name))
                .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
        })
    })
}

fn writable_destination(path: &Path) -> Outcome {
    let mut current = path;
    loop {
        match fs::symlink_metadata(current) {
            Ok(meta) => {
                if meta.file_type().is_symlink() || meta.permissions().readonly() {
                    return Err(Failure::Other(
                        "A setup destination is a symlink or read-only.".into(),
                    ));
                }
                return Ok(());
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                current = current
                    .parent()
                    .ok_or_else(|| Failure::Other("No writable parent.".into()))?;
            }
            Err(e) => return Err(e.into()),
        }
    }
}

/// Read only the exact private wrapper format generated by setup, never execute it.
fn managed_token(path: &Path, program: &Path) -> Result<Option<SecretText>, Failure> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let conflict = || {
        Failure::Other(
            "An existing wrapper is not managed by setup. No command was replaced.".into(),
        )
    };
    if !meta.is_file() || meta.permissions().mode() & 0o777 != 0o700 {
        return Err(conflict());
    }
    let text = zeroize::Zeroizing::new(fs::read_to_string(path)?);
    let prefix = "#!/bin/sh\n# Written by apassy setup. It holds an agent token: keep mode 0700, never commit it.\nAPASSY_AGENT_TOKEN=";
    let suffix = format!(" exec {} \"$@\"\n", quote(&program.display().to_string()));
    let encoded = text
        .strip_prefix(prefix)
        .and_then(|text| text.strip_suffix(&suffix))
        .ok_or_else(conflict)?;
    let value = encoded
        .strip_prefix('\'')
        .and_then(|text| text.strip_suffix('\''))
        .ok_or_else(conflict)?;
    let token = SecretText::new(value.replace("'\\''", "'"));
    if quote(token.expose()) != encoded
        || !token
            .expose()
            .starts_with(crate::owner::wire::AGENT_TOKEN_PREFIX)
    {
        return Err(conflict());
    }
    Ok(Some(token))
}

fn claude_timeout(file: &Path, write: bool) -> Outcome {
    let text = read_optional_config(file)?;
    let mut root: serde_json::Value = if text.trim().is_empty() {
        serde_json::json!({})
    } else {
        serde_json::from_str(&text)
            .map_err(|_| Failure::Other("Claude settings are not valid JSON.".into()))?
    };
    let env = root
        .as_object_mut()
        .ok_or_else(|| Failure::Other("Claude settings are not an object.".into()))?
        .entry("env")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .ok_or_else(|| Failure::Other("Claude settings env is not an object.".into()))?;
    let current = env.get("MCP_TOOL_TIMEOUT");
    if current.is_none() || current == Some(&serde_json::json!("330000")) {
        env.insert("MCP_TOOL_TIMEOUT".into(), serde_json::json!("660000"));
        if write {
            fs::write(
                file,
                format!("{}\n", serde_json::to_string_pretty(&root).unwrap()),
            )?;
        }
    }
    Ok(())
}

fn hook_entry(hook_wrapper: &Path) -> serde_json::Value {
    serde_json::json!({
        "hooks": [
            { "type": "command", "command": quote(&hook_wrapper.display().to_string()), "timeout": 5 }
        ]
    })
}

/// Add the hook to a hooks file. Returns false when it is there already.
fn merge_hook(file: &Path, hook_wrapper: &Path) -> Result<bool, Failure> {
    merge_hook_checked(file, hook_wrapper, true)
}

fn merge_hook_checked(file: &Path, hook_wrapper: &Path, write: bool) -> Result<bool, Failure> {
    let mut root: serde_json::Value = match fs::read_to_string(file) {
        Ok(text) if !text.trim().is_empty() => serde_json::from_str(&text).map_err(|err| {
            at_stage(
                Failure::Other(format!("{} is not valid JSON ({err}).", file.display())),
                "hooks_invalid",
            )
        })?,
        Ok(_) => serde_json::json!({}),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => serde_json::json!({}),
        Err(err) => return Err(at_stage(err.into(), "hooks_read")),
    };
    if root
        .get("disableAllHooks")
        .and_then(serde_json::Value::as_bool)
        == Some(true)
    {
        return Err(at_stage(
            Failure::Other(
                "The host settings disable all hooks. Check Advanced setup before you try again."
                    .to_owned(),
            ),
            "hooks_disabled",
        ));
    }
    let object = root.as_object_mut().ok_or_else(|| {
        at_stage(
            Failure::Other(format!("{} is not a JSON object.", file.display())),
            "hooks_invalid",
        )
    })?;
    let hooks = object
        .entry("hooks")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .ok_or_else(|| {
            at_stage(
                Failure::Other(format!("\"hooks\" in {} is not an object.", file.display())),
                "hooks_invalid",
            )
        })?;
    let list = hooks
        .entry("UserPromptSubmit")
        .or_insert_with(|| serde_json::json!([]))
        .as_array_mut()
        .ok_or_else(|| {
            at_stage(
                Failure::Other(format!(
                    "\"UserPromptSubmit\" in {} is not a list.",
                    file.display()
                )),
                "hooks_invalid",
            )
        })?;
    let command = quote(&hook_wrapper.display().to_string());
    for entry in list.iter_mut() {
        if let Some(hooks) = entry
            .get_mut("hooks")
            .and_then(serde_json::Value::as_array_mut)
        {
            for hook in hooks {
                if hook["type"] == "command"
                    && hook["command"] == hook_wrapper.display().to_string()
                {
                    hook["command"] = serde_json::json!(command);
                }
            }
        }
    }
    let present = list.iter().any(|entry| {
        entry
            .get("hooks")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|hooks| {
                hooks.iter().any(|hook| {
                    hook.get("type").and_then(serde_json::Value::as_str) == Some("command")
                        && hook.get("command").and_then(serde_json::Value::as_str)
                            == Some(command.as_str())
                })
            })
    });
    if !present {
        list.push(hook_entry(hook_wrapper));
    }
    if !write {
        return Ok(!present);
    }
    if fs::read_to_string(file)
        .ok()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
        .as_ref()
        == Some(&root)
    {
        return Ok(false);
    }
    if file.exists() {
        let backup = file.with_extension("json.before-apassy");
        fs::copy(file, &backup).map_err(|error| at_stage(error.into(), "hooks_write"))?;
        eprintln!(
            "Saved a copy of {} as {}.",
            file.display(),
            backup.display()
        );
    } else if let Some(parent) = file.parent() {
        fs::create_dir_all(parent).map_err(|error| at_stage(error.into(), "hooks_write"))?;
    }
    let mut pretty =
        serde_json::to_string_pretty(&root).map_err(|err| Failure::Other(err.to_string()))?;
    pretty.push('\n');
    fs::write(file, pretty).map_err(|error| at_stage(error.into(), "hooks_write"))?;
    Ok(true)
}

fn claude_paths(home: &Path, config_dir: Option<std::ffi::OsString>) -> (PathBuf, PathBuf) {
    match config_dir.filter(|dir| !dir.is_empty()) {
        Some(dir) => {
            let dir = PathBuf::from(dir);
            (dir.join(".claude.json"), dir.join("settings.json"))
        }
        None => (
            home.join(".claude.json"),
            home.join(".claude/settings.json"),
        ),
    }
}

/// Only reuse the user-scoped server created by `claude mcp add`. A custom
/// command, argument, or environment needs manual setup before token replacement.
fn claude_server_present(config: &Path, mcp_wrapper: &Path) -> Result<bool, Failure> {
    let text = read_optional_config(config)?;
    if text.trim().is_empty() {
        return Ok(false);
    }
    let root: serde_json::Value = serde_json::from_str(&text).map_err(|_| {
        at_stage(
            Failure::Other(
                "The Claude Code configuration is not valid JSON. Check Advanced setup.".to_owned(),
            ),
            "config_invalid",
        )
    })?;
    let object = root.as_object().ok_or_else(|| {
        at_stage(
            Failure::Other(
                "The Claude Code configuration is not a JSON object. Check Advanced setup."
                    .to_owned(),
            ),
            "config_invalid",
        )
    })?;
    let Some(servers) = object.get("mcpServers") else {
        return Ok(false);
    };
    let servers = servers.as_object().ok_or_else(|| {
        at_stage(
            Failure::Other(
                "The Claude Code MCP configuration is not an object. Check Advanced setup."
                    .to_owned(),
            ),
            "config_invalid",
        )
    })?;
    let Some(server) = servers.get("apassy") else {
        return Ok(false);
    };
    let expected = serde_json::json!({
        "type": "stdio", "command": mcp_wrapper.display().to_string(), "args": [], "env": {}
    });
    if server != &expected {
        return Err(at_stage(Failure::Other(
            "The existing Apassy server in Claude Code has different settings. Check Advanced setup before you try again.".to_owned(),
        ), "config_conflict"));
    }
    Ok(true)
}

fn claude(
    mcp_wrapper: &Path,
    hook_wrapper: Option<&Path>,
    write: bool,
    stages: &mut Vec<&'static str>,
) -> Outcome {
    let (config, settings) = claude_paths(&home()?, std::env::var_os("CLAUDE_CONFIG_DIR"));
    let mcp_json = serde_json::json!({ "mcpServers": { "apassy": { "command": mcp_wrapper.display().to_string() } } });
    if !write {
        eprintln!(
            "\nAdd the MCP server (user scope):\n  claude mcp add --scope user apassy -- {}",
            quote(&mcp_wrapper.display().to_string())
        );
        eprintln!(
            "or put this in .mcp.json:\n{}",
            serde_json::to_string_pretty(&mcp_json).unwrap_or_default()
        );
        if let Some(hook_wrapper) = hook_wrapper {
            eprintln!(
                "\nAdd the prompt hook to {}:\n{}",
                settings.display(),
                serde_json::to_string_pretty(&serde_json::json!({
                    "hooks": { "UserPromptSubmit": [hook_entry(hook_wrapper)] }
                }))
                .unwrap_or_default()
            );
        }
        eprintln!("\nOr run this command again with --write.");
    } else {
        if claude_server_present(&config, mcp_wrapper)? {
            eprintln!("Claude Code has the Apassy settings already (user scope).");
        } else {
            if config.exists() {
                fs::copy(&config, config.with_extension("json.before-apassy"))?;
            }
            let added = std::process::Command::new("claude")
                .args(["mcp", "add", "--scope", "user", "apassy", "--"])
                .arg(mcp_wrapper)
                .output();
            match added {
                Ok(output) if output.status.success() => {
                    eprintln!("Added the MCP server apassy to Claude Code (user scope).")
                }
                Ok(output) => {
                    let status = output.status;
                    return Err(at_stage(
                        Failure::Other(format!(
                            "Claude Code setup failed ({status}). Check `claude mcp list`. If an old apassy server exists, remove it with `claude mcp remove apassy --scope user`, then run setup again."
                        )),
                        "host_failed",
                    ));
                }
                Err(error) => {
                    return Err(at_stage(
                        Failure::Other(format!(
                            "Cannot start Claude Code: {error}. Make sure `claude --version` works in this terminal, then run setup again."
                        )),
                        "host_start",
                    ));
                }
            }
            if !claude_server_present(&config, mcp_wrapper)? {
                return Err(at_stage(Failure::Other(
                    "Claude Code did not save the expected Apassy server. Check Advanced setup."
                        .to_owned(),
                ), "host_verify"));
            }
        }
        stages.push("mcp_config_written");
        if let Some(hook_wrapper) = hook_wrapper {
            if merge_hook(&settings, hook_wrapper)? {
                eprintln!("Added the prompt hook to {}.", settings.display());
            } else {
                eprintln!("{} has the prompt hook already.", settings.display());
            }
        }
    }
    if write {
        stages.push("hook_config_written");
        claude_timeout(&settings, true)?;
        stages.push("timeout_written");
    }
    eprintln!(
        "Set MCP_TOOL_TIMEOUT to at least 660000 for Claude Code: a question can wait 5 minutes for you. In the Apassy sandbox, also set \"sandbox\": {{\"enabled\": false}} in the Claude Code settings."
    );
    Ok(())
}

fn codex_home() -> Result<PathBuf, Failure> {
    std::env::var_os("CODEX_HOME")
        .filter(|dir| !dir.is_empty())
        .map(PathBuf::from)
        .map_or_else(|| home().map(|home| home.join(".codex")), Ok)
}

fn codex_section(mcp_wrapper: &Path) -> String {
    format!(
        "[mcp_servers.apassy]\ncommand = \"{}\"\ntool_timeout_sec = 660\n",
        mcp_wrapper
            .display()
            .to_string()
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
    )
}

fn read_optional_config(config: &Path) -> Result<String, Failure> {
    match fs::read_to_string(config) {
        Ok(text) => Ok(text),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(error) => Err(at_stage(error.into(), "config_read")),
    }
}

fn codex(
    mcp_wrapper: &Path,
    hook_wrapper: Option<&Path>,
    write: bool,
    stages: &mut Vec<&'static str>,
) -> Outcome {
    let codex_home = codex_home()?;
    let config = codex_home.join("config.toml");
    let hooks = codex_home.join("hooks.json");
    let section = codex_section(mcp_wrapper);
    if !write {
        eprintln!("\nAdd to {}:\n\n{section}", config.display());
        if let Some(hook_wrapper) = hook_wrapper {
            eprintln!(
                "Add the prompt hook to {}:\n{}",
                hooks.display(),
                serde_json::to_string_pretty(&serde_json::json!({
                    "hooks": { "UserPromptSubmit": [hook_entry(hook_wrapper)] }
                }))
                .unwrap_or_default()
            );
        }
        eprintln!("\nOr run this command again with --write.");
    } else {
        let current = read_optional_config(&config)?;
        if codex_section_present(&current, &section)? {
            let migrated = migrate_codex_timeout(&current);
            if migrated != current {
                fs::copy(&config, config.with_extension("toml.before-apassy"))?;
                fs::write(&config, migrated)?;
            }
            eprintln!("{} has the Apassy settings already.", config.display());
        } else {
            if config.exists() {
                let backup = config.with_extension("toml.before-apassy");
                fs::copy(&config, &backup)?;
                eprintln!(
                    "Saved a copy of {} as {}.",
                    config.display(),
                    backup.display()
                );
            } else {
                fs::create_dir_all(&codex_home)?;
            }
            let mut file = fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(&config)?;
            let separator = if current.is_empty() || current.ends_with("\n\n") {
                ""
            } else if current.ends_with('\n') {
                "\n"
            } else {
                "\n\n"
            };
            write!(file, "{separator}{section}")?;
            eprintln!("Added [mcp_servers.apassy] to {}.", config.display());
        }
        stages.push("mcp_config_written");
        if let Some(hook_wrapper) = hook_wrapper {
            if merge_hook(&hooks, hook_wrapper)? {
                eprintln!("Added the prompt hook to {}.", hooks.display());
            } else {
                eprintln!("{} has the prompt hook already.", hooks.display());
            }
        }
    }
    if write {
        stages.push("hook_config_written");
    }
    if hook_wrapper.is_some() {
        eprintln!(
            "Start Codex, open /hooks, and trust the hook. Codex does not run it before that."
        );
    }
    Ok(())
}

/// Called only after the exact managed block has passed validation.
fn migrate_codex_timeout(current: &str) -> String {
    let mut managed = false;
    current
        .split_inclusive('\n')
        .map(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with('[') {
                managed = trimmed == "[mcp_servers.apassy]";
            }
            if managed && trimmed == "tool_timeout_sec = 330" {
                line.replacen("330", "660", 1)
            } else {
                line.to_owned()
            }
        })
        .collect()
}

/// Recognize only the block that this setup command writes. Do not report success
/// for an existing server that points elsewhere or disables Apassy. Leave custom
/// configuration for manual setup rather than silently replacing it.
fn codex_section_present(current: &str, expected: &str) -> Result<bool, Failure> {
    let document = current.parse::<toml_edit::DocumentMut>().map_err(|_| {
        at_stage(
            Failure::Other(
                "The Codex configuration is not valid TOML. Check Advanced setup.".to_owned(),
            ),
            "config_invalid",
        )
    })?;
    let Some(servers) = document.get("mcp_servers") else {
        return codex_append_is_valid(current, expected);
    };
    let servers = servers.as_table_like().ok_or_else(|| {
        at_stage(
            Failure::Other(
                "The Codex MCP configuration is not a table. Check Advanced setup.".to_owned(),
            ),
            "config_invalid",
        )
    })?;
    let Some(server) = servers.get("apassy") else {
        // Project paths, comments, and other values can contain "apassy".
        // Only an actual server definition needs conflict checks.
        return codex_append_is_valid(current, expected);
    };
    let conflict = || {
        at_stage(Failure::Other(
        "The existing Apassy server in Codex has different settings. Check it in Advanced setup before you try again."
            .to_owned(),
    ), "config_conflict")
    };
    let expected_owned;
    let expected = if let Some(timeout) = server
        .get("tool_timeout_sec")
        .and_then(toml_edit::Item::as_integer)
        .filter(|n| *n > 0)
    {
        expected_owned = expected.replace(
            "tool_timeout_sec = 660",
            &format!("tool_timeout_sec = {timeout}"),
        );
        expected_owned.as_str()
    } else {
        expected
    };
    let expected_document = expected
        .parse::<toml_edit::DocumentMut>()
        .map_err(|_| conflict())?;
    let expected_server = &expected_document["mcp_servers"]["apassy"];
    let Some(server) = server.as_table() else {
        return Err(conflict());
    };
    if server.len() != 2
        || server.get("command").and_then(toml_edit::Item::as_str)
            != expected_server["command"].as_str()
        || server
            .get("tool_timeout_sec")
            .and_then(toml_edit::Item::as_integer)
            != expected_server["tool_timeout_sec"].as_integer()
    {
        return Err(conflict());
    }
    // Reuse only the managed block. Quoted, dotted, or inline definitions
    // remain manual work, even if their values happen to match.
    let lines: Vec<_> = current.lines().map(str::trim).collect();
    let start = lines
        .iter()
        .position(|line| *line == "[mcp_servers.apassy]")
        .ok_or_else(conflict)?;
    let end = lines[start + 1..]
        .iter()
        .position(|line| line.starts_with('['))
        .map_or(lines.len(), |offset| start + 1 + offset);
    let actual: Vec<_> = lines[start..end]
        .iter()
        .copied()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    let expected: Vec<_> = expected.lines().map(str::trim).collect();
    if actual != expected {
        return Err(conflict());
    }
    Ok(true)
}

/// A valid input can still reject an appended table, for example when
/// `mcp_servers` is an inline table. Check the complete result before a config write.
fn codex_append_is_valid(current: &str, expected: &str) -> Result<bool, Failure> {
    let appended = zeroize::Zeroizing::new(format!("{current}\n\n{expected}"));
    appended.parse::<toml_edit::DocumentMut>().map_err(|_| {
        at_stage(
            Failure::Other(
                "The existing Codex settings cannot accept the Apassy server table. Check Advanced setup before you try again.".to_owned(),
            ),
            "config_conflict",
        )
    })?;
    Ok(false)
}

#[cfg(all(test, feature = "vault"))]
mod tests {
    use super::*;

    #[test]
    fn preflight_leaves_invalid_hooks_unchanged_and_recovers() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("hooks.json");
        fs::write(&file, r#"{"disableAllHooks":true}"#).unwrap();
        assert!(merge_hook_checked(&file, Path::new("/tmp/hook"), false).is_err());
        assert_eq!(
            fs::read_to_string(&file).unwrap(),
            r#"{"disableAllHooks":true}"#
        );
        fs::write(&file, "{}").unwrap();
        assert!(merge_hook_checked(&file, Path::new("/tmp/hook"), false).unwrap());
        assert_eq!(fs::read_to_string(&file).unwrap(), "{}");
        assert!(merge_hook(&file, Path::new("/tmp/hook")).unwrap());
        assert!(!merge_hook(&file, Path::new("/tmp/hook")).unwrap());
    }

    #[test]
    fn managed_wrapper_repair_reuses_token_and_rejects_user_commands() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("wrapper.sh");
        let program = Path::new("/tmp/App space/mcp");
        assert!(managed_token(&file, program).unwrap().is_none());
        let token = SecretText::new("apassy_agt_synthetic'quote".into());
        write_wrapper(&file, program, &token).unwrap();
        assert_eq!(
            managed_token(&file, program).unwrap().unwrap().expose(),
            token.expose()
        );
        fs::write(&file, "#!/bin/sh\necho custom\n").unwrap();
        assert!(managed_token(&file, program).is_err());
        assert_eq!(
            fs::read_to_string(&file).unwrap(),
            "#!/bin/sh\necho custom\n"
        );
    }

    #[test]
    fn timeouts_migrate_legacy_values_and_preserve_custom_values() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("settings.json");
        for (old, expected) in [("330000", "660000"), ("900000", "900000")] {
            let text =
                serde_json::json!({"env":{"MCP_TOOL_TIMEOUT":old,"OTHER":"keep"}}).to_string();
            fs::write(&file, &text).unwrap();
            claude_timeout(&file, false).unwrap();
            assert_eq!(fs::read_to_string(&file).unwrap(), text);
            claude_timeout(&file, true).unwrap();
            let value: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
            assert_eq!(value["env"]["MCP_TOOL_TIMEOUT"], expected);
            assert_eq!(value["env"]["OTHER"], "keep");
            let migrated = fs::read(&file).unwrap();
            claude_timeout(&file, true).unwrap();
            assert_eq!(fs::read(&file).unwrap(), migrated);
        }
        let expected = codex_section(Path::new("/tmp/mcp"));
        for timeout in [330, 660, 900] {
            assert!(
                codex_section_present(&expected.replace("660", &timeout.to_string()), &expected)
                    .unwrap()
            );
        }
    }

    #[test]
    fn codex_migration_changes_only_the_legacy_managed_timeout() {
        let current = "# tool_timeout_sec = 330\n[mcp_servers.other]\ntool_timeout_sec = 330\n[mcp_servers.apassy]\ncommand = \"/tmp/mcp\"\ntool_timeout_sec = 330\n";
        let migrated = migrate_codex_timeout(current);
        assert!(
            migrated.starts_with(
                "# tool_timeout_sec = 330\n[mcp_servers.other]\ntool_timeout_sec = 330"
            )
        );
        assert!(migrated.ends_with("tool_timeout_sec = 660\n"));
        assert_eq!(migrate_codex_timeout(&migrated), migrated);
        assert_eq!(
            migrate_codex_timeout(&current.replace("= 330", "= 900")),
            current.replace("= 330", "= 900")
        );
    }

    #[test]
    fn setup_json_is_one_document_with_completed_stages_and_partial_state() {
        for (result, stages, partial) in [
            (Ok(()), vec!["preflight"], false),
            (
                Err(Failure::Other("synthetic failure".into())),
                vec![],
                false,
            ),
            (
                Err(Failure::Other("synthetic failure".into())),
                vec!["preflight", "mcp_wrapper_written"],
                true,
            ),
        ] {
            let text = setup_report(&result, &stages).to_string();
            let value: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert_eq!(value["ok"], result.is_ok());
            assert_eq!(value["partial_state"]["partial"], partial);
            assert_eq!(value["partial_state"]["stages"], serde_json::json!(stages));
            assert_eq!(
                value["stage"],
                stages.last().copied().unwrap_or("preflight")
            );
        }
    }

    #[test]
    fn claude_setup_reuses_only_its_managed_user_server() {
        let dir = tempfile::TempDir::new().unwrap();
        let config = dir.path().join(".claude.json");
        let wrapper = dir.path().join("apassy-mcp-claude.sh");
        assert!(!claude_server_present(&config, &wrapper).unwrap());
        let expected = serde_json::json!({
            "type": "stdio", "command": wrapper.display().to_string(), "args": [], "env": {}
        });
        let root = serde_json::json!({
            "mcpServers": { "apassy": expected }, "projects": { "/example": { "trusted": true } }
        });
        fs::write(&config, root.to_string()).unwrap();
        assert!(claude_server_present(&config, &wrapper).unwrap());
        for field in ["command", "args", "env", "type", "enabled"] {
            let mut custom = root.clone();
            custom["mcpServers"]["apassy"][field] = serde_json::json!("custom");
            let text = custom.to_string();
            fs::write(&config, &text).unwrap();
            assert!(claude_server_present(&config, &wrapper).is_err(), "{field}");
            assert_eq!(fs::read_to_string(&config).unwrap(), text);
        }
        fs::write(&config, "not JSON").unwrap();
        assert!(claude_server_present(&config, &wrapper).is_err());
    }

    #[test]
    fn claude_paths_use_the_cli_configuration_directory() {
        let home = Path::new("/fixture/home");
        assert_eq!(
            claude_paths(home, None),
            (
                home.join(".claude.json"),
                home.join(".claude/settings.json")
            )
        );
        assert_eq!(
            claude_paths(home, Some("/fixture/custom".into())),
            (
                PathBuf::from("/fixture/custom/.claude.json"),
                PathBuf::from("/fixture/custom/settings.json")
            )
        );
    }

    #[test]
    fn the_hook_merge_requires_a_prompt_command_hook() {
        let dir = tempfile::TempDir::new().unwrap();
        let settings = dir.path().join("settings.json");
        let wrapper = Path::new("/fixture/apassy-hook-claude.sh");
        let root = serde_json::json!({
            "note": wrapper.display().to_string(),
            "hooks": {
                "Stop": [hook_entry(wrapper)],
                "UserPromptSubmit": [{"hooks": [{"type": "prompt", "command": wrapper.display().to_string()}]}]
            }
        });
        fs::write(&settings, root.to_string()).unwrap();
        assert!(merge_hook(&settings, wrapper).unwrap());
        assert!(!merge_hook(&settings, wrapper).unwrap());
        let value: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&settings).unwrap()).unwrap();
        assert_eq!(value["hooks"]["Stop"], root["hooks"]["Stop"]);
        assert_eq!(
            value["hooks"]["UserPromptSubmit"].as_array().unwrap().len(),
            2
        );

        let disabled = serde_json::json!({ "disableAllHooks": true, "hooks": { "UserPromptSubmit": [hook_entry(wrapper)] } }).to_string();
        fs::write(&settings, &disabled).unwrap();
        assert!(merge_hook(&settings, wrapper).is_err());
        assert_eq!(fs::read_to_string(&settings).unwrap(), disabled);
    }

    #[test]
    fn codex_setup_accepts_only_its_existing_configuration() {
        let expected = "[mcp_servers.apassy]\ncommand = \"/tmp/apassy-mcp-codex.sh\"\ntool_timeout_sec = 660\n";
        assert!(!codex_section_present("model = \"test\"\n", expected).unwrap());
        let current = format!(
            "model = \"test\"\n{expected}\n# user note\n[mcp_servers.other]\ncommand = \"other\"\n"
        );
        assert!(codex_section_present(&current, expected).unwrap());
        for different in [
            expected.replace("/tmp/", "/old/"),
            format!("{expected}enabled = false\n"),
            format!("{expected}[mcp_servers.apassy.env]\nOTHER = \"value\"\n"),
            format!("{expected}{expected}"),
            expected.replace("mcp_servers.apassy", "mcp_servers.\"apassy\""),
        ] {
            assert!(codex_section_present(&different, expected).is_err());
        }
    }

    #[test]
    fn codex_setup_allows_unrelated_apassy_references() {
        let expected = codex_section(Path::new("/fixture/apassy-mcp-codex.sh"));
        for unrelated in [
            "# apassy server is not installed\nmodel = \"test\"\n",
            "[projects.\"/Users/fixture/Dev/apassy\"]\ntrust_level = \"trusted\"\n",
            "[mcp_servers.other]\ncommand = \"/fixture/apassy-helper\"\n",
        ] {
            assert!(!codex_section_present(unrelated, &expected).unwrap());
            let current = format!("{unrelated}\n{expected}");
            assert!(codex_section_present(&current, &expected).unwrap());
            if unrelated.starts_with('[') {
                let current = format!("{expected}\n{unrelated}");
                assert!(codex_section_present(&current, &expected).unwrap());
            }
        }
    }

    #[test]
    fn codex_setup_rejects_noncanonical_servers_and_invalid_toml() {
        let expected = codex_section(Path::new("/fixture/apassy-mcp-codex.sh"));
        for custom in [
            "[mcp_servers.\"apassy\"]\ncommand = \"other\"\n",
            "mcp_servers.apassy.command = \"other\"\n",
            "mcp_servers = { apassy = { command = \"other\" } }\n",
            "[mcp_servers.apassy.env]\nSECRET = \"canary-secret\"\n",
            "[mcp_servers.apassy]\ncommand = \"unterminated\n",
            "mcp_servers = 7\n",
        ] {
            assert!(codex_section_present(custom, &expected).is_err());
        }
    }

    #[test]
    fn codex_setup_rejects_inline_parent_tables_before_an_invalid_append() {
        let expected = codex_section(Path::new("/fixture/apassy-mcp-codex.sh"));
        for original in [
            "mcp_servers = {}\n",
            "mcp_servers = { other = { command = \"/fixture/apassy-helper\" } }\n",
        ] {
            assert!(original.parse::<toml_edit::DocumentMut>().is_ok());
            let failure = codex_section_present(original, &expected).unwrap_err();
            assert_eq!(status_code(&Err(failure)), "config_conflict");
        }
    }

    #[test]
    fn codex_setup_allows_appendable_dotted_and_normal_parent_tables() {
        let expected = codex_section(Path::new("/fixture/apassy-mcp-codex.sh"));
        for original in [
            "mcp_servers.other.command = \"/fixture/other\"\n",
            "mcp_servers.other = { command = \"/fixture/other\" }\n",
            "[mcp_servers]\n[mcp_servers.other]\ncommand = \"/fixture/other\"\n",
        ] {
            assert!(!codex_section_present(original, &expected).unwrap());
            let appended = format!("{original}\n\n{expected}");
            let document = appended.parse::<toml_edit::DocumentMut>().unwrap();
            assert_eq!(
                document["mcp_servers"]["other"]["command"].as_str(),
                Some("/fixture/other")
            );
            assert_eq!(
                document["mcp_servers"]["apassy"]["command"].as_str(),
                Some("/fixture/apassy-mcp-codex.sh")
            );
        }
    }

    #[test]
    fn desktop_status_refuses_to_replace_existing_data_or_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let status = dir.path().join("status");
        fs::write(&status, "apassy_agt_canary-secret").unwrap();
        fs::set_permissions(&status, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(open_desktop_status(&status).is_err());
        assert_eq!(
            fs::read_to_string(&status).unwrap(),
            "apassy_agt_canary-secret"
        );
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&status, &link).unwrap();
        assert!(open_desktop_status(&link).is_err());
        fs::write(&status, "").unwrap();
        open_desktop_status(&status)
            .unwrap()
            .write_all(b"config_conflict")
            .unwrap();
        assert_eq!(fs::read_to_string(&status).unwrap(), "config_conflict");
        assert!(open_desktop_status(&dir.path().join("missing")).is_err());
    }

    #[test]
    fn cli_writes_only_a_fixed_status_for_a_private_error() {
        let dir = tempfile::tempdir().unwrap();
        let status = dir.path().join("status");
        fs::write(&status, "").unwrap();
        fs::set_permissions(&status, fs::Permissions::from_mode(0o600)).unwrap();
        let cli = Cli {
            socket: dir.path().join("owner.sock"),
            json: false,
            session: None,
        };
        let result = run(
            &cli,
            Args::new([
                "apassy_agt_canary-secret".to_owned(),
                "--desktop-status".to_owned(),
                status.to_str().unwrap().to_owned(),
            ]),
        );
        assert!(matches!(result, Err(Failure::Usage(_))));
        assert_eq!(fs::read_to_string(&status).unwrap(), "failed");
    }

    #[test]
    fn status_codes_discard_error_details_and_unknown_codes() {
        assert_eq!(status_code(&Ok(())), "ok");
        let failure = at_stage(
            Failure::Other("apassy_agt_canary-secret".to_owned()),
            "config_write",
        );
        assert_eq!(status_code(&Err(failure)), "config_write");
        assert_eq!(
            status_code(&Err(Failure::App {
                code: "apassy_agt_canary-secret".to_owned(),
                message: "private configuration".to_owned(),
            })),
            "failed"
        );
        assert_eq!(
            status_code(&Err(Failure::Other("private configuration".to_owned()))),
            "failed"
        );
    }

    #[test]
    fn hook_failures_have_fixed_status_codes_and_preserve_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let hooks = dir.path().join("hooks.json");
        let wrapper = Path::new("/fixture/apassy-hook.sh");
        for (original, code) in [
            ("not JSON apassy_agt_canary-secret", "hooks_invalid"),
            ("[]", "hooks_invalid"),
            (r#"{"hooks": []}"#, "hooks_invalid"),
            (r#"{"hooks": {"UserPromptSubmit": {}}}"#, "hooks_invalid"),
            (r#"{"disableAllHooks": true}"#, "hooks_disabled"),
        ] {
            fs::write(&hooks, original).unwrap();
            let failure = merge_hook(&hooks, wrapper).unwrap_err();
            assert_eq!(status_code(&Err(failure)), code);
            assert_eq!(fs::read_to_string(&hooks).unwrap(), original);
        }
        assert_eq!(
            status_code(&Err(merge_hook(dir.path(), wrapper).unwrap_err())),
            "hooks_read"
        );
        assert_eq!(
            status_code(&Err(read_optional_config(dir.path()).unwrap_err())),
            "config_read"
        );
    }

    #[test]
    fn wrappers_quote_the_token_and_have_mode_0700() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let wrapper = dir.path().join("cfg").join("apassy-mcp-claude.sh");
        let token = SecretText::new("apassy_agt_it's-a-canary".to_owned());
        write_wrapper(
            &wrapper,
            Path::new("/Applications/Apassy.app/Contents/MacOS/apassy-mcp"),
            &token,
        )
        .expect("write");
        let text = fs::read_to_string(&wrapper).expect("read");
        assert!(
            text.contains("APASSY_AGENT_TOKEN='apassy_agt_it'\\''s-a-canary' exec"),
            "{text}"
        );
        let mode = fs::metadata(&wrapper).expect("meta").permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        let dir_mode = fs::metadata(wrapper.parent().unwrap())
            .expect("meta")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700);
    }

    #[test]
    fn the_hook_merge_keeps_other_settings_and_runs_once() {
        let dir = tempfile::TempDir::new().expect("temp dir");
        let settings = dir.path().join("settings.json");
        fs::write(
            &settings,
            r#"{"model":"opus","hooks":{"Stop":[{"hooks":[]}]}}"#,
        )
        .expect("write");
        let wrapper = Path::new("/Users/me/.config/apassy/apassy-hook-claude.sh");
        assert!(merge_hook(&settings, wrapper).expect("merge"));
        assert!(!merge_hook(&settings, wrapper).expect("merge again"));
        let value: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&settings).unwrap()).unwrap();
        assert_eq!(value["model"], "opus");
        assert!(value["hooks"]["Stop"].is_array());
        assert_eq!(
            value["hooks"]["UserPromptSubmit"][0]["hooks"][0]["command"],
            quote(&wrapper.display().to_string())
        );
        assert!(dir.path().join("settings.json.before-apassy").is_file());
    }
}

/// Every replacement is prepared on the destination filesystem before commit.
/// On an apply error, restore original bytes and modes in reverse order.
#[cfg(feature = "vault")]
fn apply_files(files: &[(PathBuf, Vec<u8>, u32)]) -> Outcome {
    apply_files_checked(files, |_| Ok(()))
}

#[cfg(feature = "vault")]
fn apply_files_checked(
    files: &[(PathBuf, Vec<u8>, u32)],
    before_apply: impl Fn(usize) -> std::io::Result<()>,
) -> Outcome {
    let mut prepared = Vec::new();
    let mut originals = Vec::new();
    for (path, bytes, mode) in files {
        writable_destination(path)?;
        let old = match fs::read(path) {
            Ok(bytes) => Some((
                zeroize::Zeroizing::new(bytes),
                fs::metadata(path)?.permissions(),
            )),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        fs::create_dir_all(
            path.parent()
                .ok_or_else(|| Failure::Other("Missing parent.".into()))?,
        )?;
        let mut temp = tempfile::NamedTempFile::new_in(path.parent().unwrap())?;
        temp.as_file()
            .set_permissions(fs::Permissions::from_mode(*mode))?;
        temp.write_all(bytes)?;
        temp.as_file().sync_all()?;
        prepared.push(temp);
        originals.push(old);
    }
    for (index, temp) in prepared.iter().enumerate() {
        if let Err(error) =
            before_apply(index).and_then(|()| fs::rename(temp.path(), &files[index].0))
        {
            for n in (0..index).rev() {
                let path = &files[n].0;
                let restored = match &originals[n] {
                    Some((bytes, permissions)) => (|| -> std::io::Result<()> {
                        let mut temp = tempfile::NamedTempFile::new_in(path.parent().unwrap())?;
                        temp.as_file().set_permissions(permissions.clone())?;
                        temp.write_all(bytes)?;
                        temp.as_file().sync_all()?;
                        fs::rename(temp.path(), path)
                    })(),
                    None => fs::remove_file(path),
                };
                if restored.is_err() {
                    return Err(Failure::Other("Setup failed and rollback is incomplete. Review host files before retrying.".into()));
                }
            }
            return Err(error.into());
        }
    }
    Ok(())
}

#[cfg(feature = "vault")]
#[allow(clippy::too_many_arguments)]
fn stage_connection(
    host: Host,
    mcp_wrapper: &Path,
    hook_wrapper: &Path,
    mcp: &Path,
    hook: &Path,
    token: &SecretText,
    config: &Path,
    hooks: &Path,
    identity_path: &Path,
    identity: Option<&str>,
) -> Outcome {
    let wrapper_dir = mcp_wrapper
        .parent()
        .ok_or_else(|| Failure::Other("Missing wrapper directory.".into()))?;
    fs::create_dir_all(wrapper_dir)?;
    fs::set_permissions(wrapper_dir, fs::Permissions::from_mode(0o700))?;
    let scratch = tempfile::tempdir()?;
    let staged_mcp = scratch.path().join("mcp.sh");
    let staged_hook = scratch.path().join("hook.sh");
    write_wrapper(&staged_mcp, mcp, token)?;
    write_wrapper(&staged_hook, hook, token)?;
    let staged_hooks = scratch.path().join("hooks.json");
    fs::write(&staged_hooks, read_optional_config(hooks)?)?;
    merge_hook(&staged_hooks, hook_wrapper)?;
    if host == Host::Claude {
        claude_timeout(&staged_hooks, true)?;
    }
    let current = read_optional_config(config)?;
    let config_bytes = if host == Host::Claude {
        let mut root: serde_json::Value = if current.trim().is_empty() {
            serde_json::json!({})
        } else {
            serde_json::from_str(&current)
                .map_err(|_| Failure::Other("Invalid Claude config.".into()))?
        };
        if root.get("mcpServers").is_none() {
            root["mcpServers"] = serde_json::json!({});
        }
        root["mcpServers"]["apassy"] =
            serde_json::json!({"type":"stdio", "command":mcp_wrapper, "args":[], "env":{}});
        serde_json::to_vec_pretty(&root).map_err(|e| Failure::Other(e.to_string()))?
    } else {
        let section = codex_section(mcp_wrapper);
        if codex_section_present(&current, &section)? {
            migrate_codex_timeout(&current).into_bytes()
        } else {
            format!("{current}\n{section}").into_bytes()
        }
    };
    let mut files = vec![
        (mcp_wrapper.to_owned(), fs::read(staged_mcp)?, 0o700),
        (hook_wrapper.to_owned(), fs::read(staged_hook)?, 0o700),
        (config.to_owned(), config_bytes, 0o600),
        (hooks.to_owned(), fs::read(staged_hooks)?, 0o600),
    ];
    files.push((identity_path.to_owned(), serde_json::to_vec(&serde_json::json!({"agent_id":identity, "host":host.id(), "version":env!("CARGO_PKG_VERSION")})).unwrap(), 0o600));
    files.push((
        wrapper_dir.join(format!(
            "hook-health-{}.json",
            if host == Host::Claude {
                "claude-code"
            } else {
                "codex"
            }
        )),
        b"{}".to_vec(),
        0o600,
    ));
    let result = apply_files(&files);
    use zeroize::Zeroize;
    for (_, bytes, _) in &mut files {
        bytes.zeroize();
    }
    result
}

#[cfg(not(feature = "vault"))]
#[allow(clippy::too_many_arguments)]
fn stage_connection(
    _: Host,
    _: &Path,
    _: &Path,
    _: &Path,
    _: &Path,
    _: &SecretText,
    _: &Path,
    _: &Path,
    _: &Path,
    _: Option<&str>,
) -> Outcome {
    Err(Failure::Other(
        "Connection setup requires a vault-enabled build.".into(),
    ))
}

#[cfg(all(test, feature = "vault"))]
mod transaction_tests {
    use super::*;
    #[test]
    fn rollback_restores_bytes_modes_and_removes_partial_new_files() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("original");
        let second = dir.path().join("new");
        fs::write(&first, "original").unwrap();
        fs::set_permissions(&first, fs::Permissions::from_mode(0o640)).unwrap();
        let files = vec![
            (first.clone(), b"replacement".to_vec(), 0o700),
            (second.clone(), b"new".to_vec(), 0o600),
            (dir.path().join("last"), vec![], 0o600),
        ];
        for failure in [1, 2] {
            assert!(
                apply_files_checked(&files, |n| if n == failure {
                    Err(std::io::Error::other("synthetic apply failure"))
                } else {
                    Ok(())
                })
                .is_err()
            );
            assert_eq!(fs::read(&first).unwrap(), b"original");
            assert_eq!(
                fs::metadata(&first).unwrap().permissions().mode() & 0o777,
                0o640
            );
            assert!(!second.exists());
        }
    }
    #[test]
    fn repair_recreates_missing_hook_without_touching_catalog() {
        let dir = tempfile::tempdir().unwrap();
        let mcp = dir.path().join("mcp.sh");
        let hook = dir.path().join("hook.sh");
        let config = dir.path().join("config.toml");
        let hooks = dir.path().join("hooks.json");
        stage_connection(
            Host::Codex,
            &mcp,
            &hook,
            Path::new("/bin/true"),
            Path::new("/bin/true"),
            &SecretText::new("apassy_agt_synthetic".into()),
            &config,
            &hooks,
            &dir.path().join("identity.json"),
            Some("42"),
        )
        .unwrap();
        fs::remove_file(&hook).unwrap();
        stage_connection(
            Host::Codex,
            &mcp,
            &hook,
            Path::new("/bin/true"),
            Path::new("/bin/true"),
            &SecretText::new("apassy_agt_synthetic".into()),
            &config,
            &hooks,
            &dir.path().join("identity.json"),
            Some("42"),
        )
        .unwrap();
        assert!(hook.exists());
        assert_eq!(
            managed_token(&mcp, Path::new("/bin/true"))
                .unwrap()
                .unwrap()
                .expose(),
            "apassy_agt_synthetic"
        );
    }
}
