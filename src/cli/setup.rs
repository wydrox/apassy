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
apassy setup claude|codex [--name NAME] [--token-stdin] [--hook PATH] [--write]

Prepare an agent host for Apassy:
  1. Register an agent named NAME (default: Claude Code or Codex) and take its token.
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
Agents, tokens, and grants stay on this Mac. A synced vault does not copy them.
This command writes configuration. It does not check the host connection or a first request.

Then give the agent access: apassy grant set AGENT ITEM --folder DIR
Start the host in the Apassy sandbox (see docs/operations/isolation.md):
  claude: MCP_TOOL_TIMEOUT=180000 apassy-sandbox -- claude --settings '{\"sandbox\":{\"enabled\":false}}'
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
    let _ = fs::remove_file(&temp);
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
    let result = run_host(cli, args);
    if let Some(status) = status.as_mut() {
        status.write_all(status_code(&result).as_bytes())?;
    }
    // Keep the existing public CLI error format and exit behavior.
    let code = status_code(&result);
    result.map_err(|failure| match failure {
        Failure::App { message, .. } if code != "failed" => Failure::Other(message),
        failure => failure,
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

fn run_host(cli: &Cli, mut args: Args) -> Outcome {
    let host = match args.required("host: claude, codex, or browser")?.as_str() {
        "claude" | "claude-code" => Host::Claude,
        "codex" => Host::Codex,
        // ADR 0021: the browser extension. It registers no agent.
        "browser" => return super::browser::run(args),
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
    } else {
        let response = cli.call(Command::AgentAdd { name: name.clone() })?;
        match response.data {
            Data::Token { token, agent } => {
                terminal::tell(&format!("Registered {} (ID {}).", agent.name, agent.id));
                token
            }
            _ => return Err(Failure::Other("Apassy sent no token.".to_owned())),
        }
    };

    write_wrapper(&mcp_wrapper, &mcp, &token)
        .map_err(|failure| at_stage(failure, "wrapper_write"))?;
    println!("Wrote {} (mode 0700).", mcp_wrapper.display());
    let hook_wrapper = match &hook {
        Some(hook) => {
            let wrapper = dir.join(format!("apassy-hook-{}.sh", host.id()));
            write_wrapper(&wrapper, hook, &token)
                .map_err(|failure| at_stage(failure, "wrapper_write"))?;
            println!("Wrote {} (mode 0700).", wrapper.display());
            Some(wrapper)
        }
        None => {
            println!(
                "The prompt hook is missing. Reinstall the complete Apassy.app package, then run setup again. The MCP server alone does not provide prompt context."
            );
            None
        }
    };
    drop(token);

    match host {
        Host::Claude => claude(&mcp_wrapper, hook_wrapper.as_deref(), write),
        Host::Codex => codex(&mcp_wrapper, hook_wrapper.as_deref(), write),
    }
    .map_err(|failure| at_stage(failure, "config_write"))?;
    println!(
        "{}. The host connection and first request are not checked.",
        if write {
            "Host settings were written"
        } else {
            "Host configuration is shown above"
        }
    );
    println!(
        "Keep Apassy.app open and the vault unlocked. Restart the host. Check Apassy with /mcp."
    );
    if host == Host::Codex {
        println!("Use /hooks to trust the Apassy hook before the first request.");
    }
    println!("Next: set an Environment variable for the credential in Apassy.");
    println!(
        "Give {name} access: apassy grant set {} ITEM --folder DIR",
        quote(&name)
    );
    println!("From the project folder, start the host in the Apassy sandbox:");
    match host {
        Host::Claude => println!(
            "MCP_TOOL_TIMEOUT=180000 apassy-sandbox -- claude --settings '{{\"sandbox\":{{\"enabled\":false}}}}'"
        ),
        Host::Codex => println!("apassy-sandbox -- codex -c sandbox_mode=danger-full-access"),
    }
    println!(
        "The Apassy sandbox replaces the host's inner sandbox. Host approval prompts stay active."
    );
    println!(
        "Use a test credential for the first request. Check its result and its entry in Activity."
    );
    Ok(())
}

fn hook_entry(hook_wrapper: &Path) -> serde_json::Value {
    serde_json::json!({
        "hooks": [
            { "type": "command", "command": hook_wrapper.display().to_string(), "timeout": 5 }
        ]
    })
}

/// Add the hook to a hooks file. Returns false when it is there already.
fn merge_hook(file: &Path, hook_wrapper: &Path) -> Result<bool, Failure> {
    let mut root: serde_json::Value = match fs::read_to_string(file) {
        Ok(text) if !text.trim().is_empty() => serde_json::from_str(&text).map_err(|err| {
            at_stage(
                Failure::Other(format!(
                    "{} is not valid JSON ({err}). Nothing was changed.",
                    file.display()
                )),
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
    let command = hook_wrapper.display().to_string();
    if list.iter().any(|entry| {
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
    }) {
        return Ok(false);
    }
    list.push(hook_entry(hook_wrapper));
    if file.exists() {
        let backup = file.with_extension("json.before-apassy");
        fs::copy(file, &backup).map_err(|error| at_stage(error.into(), "hooks_write"))?;
        println!(
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

fn claude(mcp_wrapper: &Path, hook_wrapper: Option<&Path>, write: bool) -> Outcome {
    let (config, settings) = claude_paths(&home()?, std::env::var_os("CLAUDE_CONFIG_DIR"));
    let mcp_json = serde_json::json!({ "mcpServers": { "apassy": { "command": mcp_wrapper.display().to_string() } } });
    if !write {
        println!(
            "\nAdd the MCP server (user scope):\n  claude mcp add --scope user apassy -- {}",
            mcp_wrapper.display()
        );
        println!(
            "or put this in .mcp.json:\n{}",
            serde_json::to_string_pretty(&mcp_json).unwrap_or_default()
        );
        if let Some(hook_wrapper) = hook_wrapper {
            println!(
                "\nAdd the prompt hook to {}:\n{}",
                settings.display(),
                serde_json::to_string_pretty(&serde_json::json!({
                    "hooks": { "UserPromptSubmit": [hook_entry(hook_wrapper)] }
                }))
                .unwrap_or_default()
            );
        }
        println!("\nOr run this command again with --write.");
    } else {
        if claude_server_present(&config, mcp_wrapper)? {
            println!("Claude Code has the Apassy settings already (user scope).");
        } else {
            if config.exists() {
                fs::copy(&config, config.with_extension("json.before-apassy"))?;
            }
            let added = std::process::Command::new("claude")
                .args(["mcp", "add", "--scope", "user", "apassy", "--"])
                .arg(mcp_wrapper)
                .status();
            match added {
                Ok(status) if status.success() => {
                    println!("Added the MCP server apassy to Claude Code (user scope).")
                }
                Ok(status) => {
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
        if let Some(hook_wrapper) = hook_wrapper {
            if merge_hook(&settings, hook_wrapper)? {
                println!("Added the prompt hook to {}.", settings.display());
            } else {
                println!("{} has the prompt hook already.", settings.display());
            }
        }
    }
    println!(
        "Set MCP_TOOL_TIMEOUT above 120000 for Claude Code: a run can wait 120 s for you. In the Apassy sandbox, also set \"sandbox\": {{\"enabled\": false}} in the Claude Code settings."
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
        "[mcp_servers.apassy]\ncommand = \"{}\"\ntool_timeout_sec = 180\n",
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

fn codex(mcp_wrapper: &Path, hook_wrapper: Option<&Path>, write: bool) -> Outcome {
    let codex_home = codex_home()?;
    let config = codex_home.join("config.toml");
    let hooks = codex_home.join("hooks.json");
    let section = codex_section(mcp_wrapper);
    if !write {
        println!("\nAdd to {}:\n\n{section}", config.display());
        if let Some(hook_wrapper) = hook_wrapper {
            println!(
                "Add the prompt hook to {}:\n{}",
                hooks.display(),
                serde_json::to_string_pretty(&serde_json::json!({
                    "hooks": { "UserPromptSubmit": [hook_entry(hook_wrapper)] }
                }))
                .unwrap_or_default()
            );
        }
        println!("\nOr run this command again with --write.");
    } else {
        let current = read_optional_config(&config)?;
        if codex_section_present(&current, &section)? {
            println!("{} has the Apassy settings already.", config.display());
        } else {
            if config.exists() {
                let backup = config.with_extension("toml.before-apassy");
                fs::copy(&config, &backup)?;
                println!(
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
            println!("Added [mcp_servers.apassy] to {}.", config.display());
        }
        if let Some(hook_wrapper) = hook_wrapper {
            if merge_hook(&hooks, hook_wrapper)? {
                println!("Added the prompt hook to {}.", hooks.display());
            } else {
                println!("{} has the prompt hook already.", hooks.display());
            }
        }
    }
    if hook_wrapper.is_some() {
        println!(
            "Start Codex, open /hooks, and trust the hook. Codex does not run it before that."
        );
    }
    Ok(())
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
        let expected = "[mcp_servers.apassy]\ncommand = \"/tmp/apassy-mcp-codex.sh\"\ntool_timeout_sec = 180\n";
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
            wrapper.display().to_string()
        );
        assert!(dir.path().join("settings.json.before-apassy").is_file());
    }
}
