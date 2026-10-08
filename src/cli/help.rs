//! Help for complete command paths. The command syntax stays in the command help.

use super::args::{Args, Usage, usage};
use super::{HELP, commands, help_for, setup};

pub(super) const TOPICS: &str = "status, login, logout, lock, unlock, item, import, agent, setup, grant, request, runs, pattern, activity, decisions, vault, backup, doctor, completions, version";

fn group(name: &str) -> &str {
    match name {
        "items" | "credential" | "credentials" => "item",
        "agents" => "agent",
        "grants" => "grant",
        "requests" => "request",
        "run" => "runs",
        "patterns" => "pattern",
        "log" => "activity",
        "show" | "open" => "unlock",
        other => other,
    }
}

pub(super) fn actions(group: &str) -> &'static [&'static str] {
    match group {
        "item" => &[
            "list",
            "show",
            "add",
            "edit",
            "delete",
            "archive",
            "unarchive",
            "history",
            "env",
            "declare",
            "connector",
            "review",
        ],
        "agent" => &[
            "list", "show", "add", "revoke", "rotate", "see-all", "lifetime", "setup",
        ],
        "grant" => &["set", "remove", "rule", "operation"],
        "request" => &["list", "grant", "deny"],
        "runs" => &["list", "approve", "deny"],
        "pattern" => &["list", "remove"],
        "decisions" => &["export"],
        "vault" => &["backup", "change-passphrase", "restore", "lock", "unlock"],
        "setup" => &["claude", "codex", "browser"],
        "completions" => &["zsh", "bash", "fish"],
        _ => &[],
    }
}

fn action<'a>(group: &str, name: &'a str) -> &'a str {
    match (group, name) {
        ("item", "ls" | "search") | ("agent" | "request" | "runs" | "pattern", "ls") => "list",
        ("item", "get" | "info") | ("agent", "info") => "show",
        ("item", "new" | "create") | ("agent", "register" | "new") => "add",
        ("item", "set" | "update") => "edit",
        ("item", "rm" | "remove") => "delete",
        ("item", "restore") => "unarchive",
        ("item", "variable" | "var") => "env",
        ("item", "declaration") => "declare",
        ("item", "confirm-review") => "review",
        ("agent", "seeall") => "see-all",
        ("grant", "add" | "give") => "set",
        ("grant", "rm" | "revoke") | ("pattern", "rm" | "forget") => "remove",
        ("grant", "op") => "operation",
        ("request", "approve") => "grant",
        ("vault", "passphrase") => "change-passphrase",
        ("vault", "show") => "unlock",
        (_, other) => other,
    }
}

fn unknown(path: &[String], alternatives: &[&str]) -> Usage {
    usage(format!(
        "Unknown help subject \"{}\". Valid subjects: {}. Run apassy --help.",
        path.join(" "),
        if alternatives.is_empty() {
            TOPICS.to_owned()
        } else {
            alternatives.join(", ")
        },
    ))
}

/// `--help` uses the command path and ignores its ordinary values and options.
pub(super) fn for_command(command: &str, mut args: Args) -> Result<String, Usage> {
    let mut path = vec![command.to_owned()];
    if !actions(group(command)).is_empty()
        && let Some(subcommand) = args.positional()
    {
        let nested_setup = group(command) == "agent" && subcommand == "setup";
        path.push(subcommand);
        if nested_setup && let Some(host) = args.positional() {
            path.push(host);
        }
    }
    text(&path)
}

pub(super) fn text(path: &[String]) -> Result<String, Usage> {
    let Some(first) = path.first() else {
        return Ok(HELP.to_owned());
    };
    let group = group(first);
    if group == "version" && path.len() == 1 {
        return Ok("apassy version\n\napassy --version\n\nShows the Apassy version.\n".to_owned());
    }
    let group_help = help_for(Some(group)).ok_or_else(|| unknown(path, &[]))?;
    if path.len() == 1 {
        return Ok(group_help.to_owned());
    }
    let choices = actions(group);
    let action = action(group, &path[1]);
    if !choices.contains(&action) {
        return Err(unknown(path, choices));
    }
    // `agent setup HOST` is also a complete command path.
    if group == "agent" && action == "setup" {
        let mut setup_path = vec!["setup".to_owned()];
        setup_path.extend_from_slice(&path[2..]);
        return text(&setup_path);
    }
    if path.len() > 2 {
        return Err(unknown(path, choices));
    }
    if group == "setup" && action == "browser" {
        return Ok(super::browser::HELP.to_owned());
    }
    if group == "setup" {
        return Ok(setup::HELP.replace("setup claude|codex", &format!("setup {action}")));
    }
    if group == "item" && action == "show" {
        return Ok("apassy item show ITEM\n\nITEM is an ID or the exact name.\nShows the credential details and secret field names. It does not show secret values.\n\nExample:\n  apassy item show \"Example API\"\n".to_owned());
    }
    if group == "runs" && action == "list" {
        return Ok("apassy runs list\n\nShows the runs that wait for you.\n".to_owned());
    }
    let prefix = format!("apassy {group} {action}");
    let mut text = String::new();
    let mut selected = false;
    for line in group_help.lines() {
        let line_start = line.trim_start();
        if line_start.starts_with("apassy ") {
            selected = line_start
                .strip_prefix(&prefix)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with(' '));
        } else if !line.starts_with(' ') {
            selected = false;
        }
        if selected {
            text.push_str(line);
            text.push('\n');
        }
    }
    if group == "vault" && matches!(action, "lock" | "unlock") {
        return Ok(help_for(Some(action))
            .unwrap_or(commands::VAULT_HELP)
            .to_owned());
    }
    if group == "item"
        && matches!(action, "add" | "edit")
        && let Some((_, fields)) = commands::ITEM_HELP.split_once("\nKIND:")
    {
        text.push_str("\nKIND:");
        text.push_str(fields);
    }
    // Every supported action must have syntax in its command group's help.
    if text.is_empty() {
        return Err(unknown(path, choices));
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn help(words: &[&str]) -> Result<String, Usage> {
        text(
            &words
                .iter()
                .map(|word| (*word).to_owned())
                .collect::<Vec<_>>(),
        )
    }

    #[test]
    fn each_complete_command_path_has_help() {
        for group in [
            "item",
            "agent",
            "grant",
            "request",
            "runs",
            "pattern",
            "decisions",
            "vault",
            "setup",
            "completions",
        ] {
            for action in actions(group) {
                assert!(help(&[group, action]).is_ok(), "{group} {action}");
            }
        }
        assert!(help(&["agent", "setup", "codex"]).is_ok());
        assert_eq!(
            help(&["credentials", "info"]).unwrap(),
            help(&["item", "show"]).unwrap()
        );
    }

    #[test]
    fn unknown_subjects_name_the_path_and_valid_alternatives() {
        let error = help(&["item", "nonsense"]).unwrap_err().0;
        assert!(error.contains("item nonsense"));
        assert!(error.contains("list, show, add"));
        assert!(help(&["nonsense"]).unwrap_err().0.contains("status, login"));
        assert!(help(&["item", "show", "nonsense"]).is_err());
        assert!(help(&["status", "show"]).is_err());
    }
}
