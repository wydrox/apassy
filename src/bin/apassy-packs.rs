//! `apassy-packs`: check rule pack files and provider files with the loaders of Apassy.
//!
//! The JSON Schemas in `packs/schema/` check the structure. This program runs the real
//! loaders (`src/broker/packs.rs`, `src/vault/providers.rs`), so a file that passes here
//! loads in the app. See `docs/operations/rule-packs.md` and `CONTRIBUTING.md`.
//!
//! ```text
//! apassy-packs validate [--local] <file>...
//! ```
//!
//! - A file with `signals` is a provider file (`packs/providers/`). Its name must be
//!   `<id>.json`.
//! - Any other file is a rule pack. Without `--local`, the check is the check of a
//!   built-in pack: the file name must be `<tool>.json`, and each rule, safe rule,
//!   exception, project command, write, and access read needs a `note`.
//! - With `--local`, a rule pack is checked as an owner pack: flag rules only, with the
//!   built-in packs loaded, as the broker does at start.
//!
//! The exit code is 0 when every file passes, and 1 otherwise. The program never reads
//! a vault and never runs a command.

#![forbid(unsafe_code)]

use std::path::Path;
use std::process::ExitCode;

use serde_json::Value;

use apassy::broker::packs::{self, PackSummary};
use apassy::vault::providers::Catalog;

const USAGE: &str = "usage: apassy-packs validate [--local] <file>...

Checks rule pack files (packs/*.json) and provider files (packs/providers/*.json)
with the loaders of Apassy. A pack is checked as a built-in pack unless --local
is given. Exit code 1 when a file fails.";

/// One MiB: the largest local pack file that the broker reads.
const MAX_LOCAL_PACK_BYTES: u64 = 1024 * 1024;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut args = args.iter();
    match args.next().map(String::as_str) {
        Some("validate") => {}
        Some("--help" | "-h" | "help") => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::FAILURE;
        }
    }
    let mut local = false;
    let mut files = Vec::new();
    for arg in args {
        match arg.as_str() {
            "--local" => local = true,
            "--help" | "-h" => {
                println!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            other if other.starts_with('-') => {
                eprintln!("unknown option `{other}`\n{USAGE}");
                return ExitCode::FAILURE;
            }
            _ => files.push(arg.clone()),
        }
    }
    if files.is_empty() {
        eprintln!("{USAGE}");
        return ExitCode::FAILURE;
    }
    let mut failed = 0usize;
    for file in &files {
        match check(Path::new(file), local) {
            Ok(line) => println!("ok    {file}: {line}"),
            Err(message) => {
                failed += 1;
                println!("FAIL  {file}: {message}");
            }
        }
    }
    let passed = files.len() - failed;
    println!("{passed} passed, {failed} failed");
    if failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Check one file. The result is one line for the report.
fn check(path: &Path, local: bool) -> Result<String, String> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "the path has no file name".to_owned())?;
    let size = std::fs::metadata(path)
        .map_err(|error| format!("cannot read: {error}"))?
        .len();
    let text = std::fs::read_to_string(path).map_err(|error| format!("cannot read: {error}"))?;
    let value: Value =
        serde_json::from_str(&text).map_err(|error| format!("not valid JSON: {error}"))?;
    let object = value.as_object().ok_or("a pack is a JSON object")?;
    if object.contains_key("signals") {
        return check_provider(name, &text);
    }
    if local {
        if size > MAX_LOCAL_PACK_BYTES {
            return Err(format!(
                "{size} bytes; the broker reads a local pack of {MAX_LOCAL_PACK_BYTES} bytes or less"
            ));
        }
        let summary = packs::validate_local(name, &text).map_err(|error| error.message.clone())?;
        return Ok(format!(
            "local pack `{}` v{}, {}, {}",
            summary.tool,
            summary.pack_version,
            programs(&summary),
            plural(summary.rules, "rule")
        ));
    }
    let summary = packs::validate_builtin(name, &text).map_err(|error| error.message.clone())?;
    let expected = format!("{}.json", summary.tool);
    if name != expected {
        return Err(format!(
            "the file of the built-in pack `{}` must be named `{expected}`",
            summary.tool
        ));
    }
    if !summary.without_note.is_empty() {
        return Err(format!(
            "each entry of a built-in pack needs a `note` with its reason; without one: {}",
            summary.without_note.join(", ")
        ));
    }
    let mut parts = vec![plural(summary.rules, "rule")];
    for (count, word) in [
        (summary.safe, "safe rule"),
        (summary.exemptions, "exemption"),
        (summary.project_commands, "project command"),
        (summary.writes, "write"),
        (summary.access_reads, "access read"),
    ] {
        if count > 0 {
            parts.push(plural(count, word));
        }
    }
    let mut line = format!(
        "pack `{}` v{}, {}, {}",
        summary.tool,
        summary.pack_version,
        programs(&summary),
        parts.join(", ")
    );
    if summary.replaces_builtin {
        line.push_str(" (replaces the embedded pack at the next build)");
    }
    Ok(line)
}

fn check_provider(name: &str, text: &str) -> Result<String, String> {
    let catalog = Catalog::from_files(&[(name, text)]).map_err(|error| error.message)?;
    let value: Value = serde_json::from_str(text).map_err(|error| error.to_string())?;
    let id = value["id"].as_str().unwrap_or("?");
    let kind = value["kind"].as_str().unwrap_or("?");
    let signals = value["signals"].as_array().map_or(0, Vec::len);
    let hosts = catalog
        .find(id)
        .map_or(0, |provider| provider.known_hosts.len());
    let version = value["provider_version"].as_u64().unwrap_or(0);
    let mut line = format!("{kind} `{id}` v{version}, {}", plural(signals, "signal"));
    if hosts > 0 {
        line.push_str(&format!(", {}", plural(hosts, "known host")));
    }
    Ok(line)
}

fn programs(summary: &PackSummary) -> String {
    if summary.programs.len() == 1 && summary.programs[0] == "*" {
        "every program".to_owned()
    } else {
        plural(summary.programs.len(), "program")
    }
}

fn plural(count: usize, word: &str) -> String {
    if count == 1 {
        format!("1 {word}")
    } else {
        format!("{count} {word}s")
    }
}
