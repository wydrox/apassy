//! `apassy setup claude|codex`: register an agent and connect its host.
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

Connect an agent host to Apassy:
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

Apassy.app has no apassy-hook. Without --hook PATH (an apassy-hook from a source build:
cargo build --release --locked --features desktop,vault --bin apassy-hook), setup
connects the MCP server and leaves out the prompt hook (docs/operations/host-hooks.md).

Then give the agent access: apassy grant set AGENT ITEM --folder DIR
Start the host in the sandbox: apassy-sandbox -- claude   (see docs/operations/isolation.md)
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
        .ok_or_else(|| Failure::Other("HOME is not set.".to_owned()))
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

pub fn run(cli: &Cli, mut args: Args) -> Outcome {
    let host = match args.required("host: claude or codex")?.as_str() {
        "claude" | "claude-code" => Host::Claude,
        "codex" => Host::Codex,
        other => {
            return Err(Failure::Usage(usage(format!(
                "Unknown host \"{other}\". Use claude or codex."
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

    let mcp = sibling("apassy-mcp").ok_or_else(|| {
        Failure::Other(
            "apassy-mcp is not next to this program. Use the apassy program inside Apassy.app."
                .to_owned(),
        )
    })?;
    // The app does not ship apassy-hook. A source build has it next to apassy.
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

    let token = if token_stdin {
        let token = terminal::read_stdin_secret()?;
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

    let dir = home()?.join(".config").join("apassy");
    let mcp_wrapper = dir.join(format!("apassy-mcp-{}.sh", host.id()));
    write_wrapper(&mcp_wrapper, &mcp, &token)?;
    println!("Wrote {} (mode 0700).", mcp_wrapper.display());
    let hook_wrapper = match &hook {
        Some(hook) => {
            let wrapper = dir.join(format!("apassy-hook-{}.sh", host.id()));
            write_wrapper(&wrapper, hook, &token)?;
            println!("Wrote {} (mode 0700).", wrapper.display());
            Some(wrapper)
        }
        None => {
            println!(
                "The prompt hook is left out: apassy-hook is not next to this program. Build it from source and run setup again with --hook PATH (docs/operations/host-hooks.md)."
            );
            None
        }
    };
    drop(token);

    match host {
        Host::Claude => claude(&mcp_wrapper, hook_wrapper.as_deref(), write),
        Host::Codex => codex(&mcp_wrapper, hook_wrapper.as_deref(), write),
    }?;
    println!(
        "Next: give {name} access with apassy grant set \"{name}\" ITEM --folder DIR, and start the host in the sandbox (apassy-sandbox -- {}).",
        host.id()
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
            Failure::Other(format!(
                "{} is not valid JSON ({err}). Nothing was changed.",
                file.display()
            ))
        })?,
        Ok(_) => serde_json::json!({}),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => serde_json::json!({}),
        Err(err) => return Err(err.into()),
    };
    let text = root.to_string();
    if text.contains(&hook_wrapper.display().to_string()) {
        return Ok(false);
    }
    let object = root
        .as_object_mut()
        .ok_or_else(|| Failure::Other(format!("{} is not a JSON object.", file.display())))?;
    let hooks = object
        .entry("hooks")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .ok_or_else(|| {
            Failure::Other(format!("\"hooks\" in {} is not an object.", file.display()))
        })?;
    let list = hooks
        .entry("UserPromptSubmit")
        .or_insert_with(|| serde_json::json!([]))
        .as_array_mut()
        .ok_or_else(|| {
            Failure::Other(format!(
                "\"UserPromptSubmit\" in {} is not a list.",
                file.display()
            ))
        })?;
    list.push(hook_entry(hook_wrapper));
    if file.exists() {
        let backup = file.with_extension("json.before-apassy");
        fs::copy(file, &backup)?;
        println!(
            "Saved a copy of {} as {}.",
            file.display(),
            backup.display()
        );
    } else if let Some(parent) = file.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut pretty =
        serde_json::to_string_pretty(&root).map_err(|err| Failure::Other(err.to_string()))?;
    pretty.push('\n');
    fs::write(file, pretty)?;
    Ok(true)
}

fn claude(mcp_wrapper: &Path, hook_wrapper: Option<&Path>, write: bool) -> Outcome {
    let settings = home()?.join(".claude").join("settings.json");
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
        let added = std::process::Command::new("claude")
            .args(["mcp", "add", "--scope", "user", "apassy", "--"])
            .arg(mcp_wrapper)
            .status();
        match added {
            Ok(status) if status.success() => {
                println!("Added the MCP server apassy to Claude Code (user scope).")
            }
            Ok(_) => println!(
                "claude mcp add did not succeed. If an apassy server exists, remove it first: claude mcp remove apassy --scope user"
            ),
            Err(_) => println!(
                "The claude program is not on PATH. Add the server by hand: claude mcp add --scope user apassy -- {}",
                mcp_wrapper.display()
            ),
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

fn codex(mcp_wrapper: &Path, hook_wrapper: Option<&Path>, write: bool) -> Outcome {
    let codex_home = std::env::var_os("CODEX_HOME")
        .filter(|dir| !dir.is_empty())
        .map(PathBuf::from)
        .map_or_else(|| home().map(|home| home.join(".codex")), Ok)?;
    let config = codex_home.join("config.toml");
    let hooks = codex_home.join("hooks.json");
    let section = format!(
        "[mcp_servers.apassy]\ncommand = \"{}\"\ntool_timeout_sec = 180\n",
        mcp_wrapper
            .display()
            .to_string()
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
    );
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
        let current = fs::read_to_string(&config).unwrap_or_default();
        if current
            .lines()
            .any(|line| line.trim() == "[mcp_servers.apassy]")
        {
            println!(
                "{} has [mcp_servers.apassy] already. Set its command to {} by hand.",
                config.display(),
                mcp_wrapper.display()
            );
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

#[cfg(all(test, feature = "vault"))]
mod tests {
    use super::*;

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
