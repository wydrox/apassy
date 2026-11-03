//! The node without a window (ADR 0037 stage 3; plan `docs/design/implementation-plan-s2-s3.md`,
//! decision D8, unit L1): the commands of `apassy` on Linux.
//!
//! - `apassy serve`: the relay with a headless embedded configuration (`config`), the TLS
//!   front of the core (`apassy::net`) on the tailnet addresses of this machine, push
//!   through the push gateway. It runs until `apassy serve --stop` (the unit's `ExecStop`)
//!   or a signal ends it (`serve`).
//! - `apassy up`: checks Tailscale, makes the data directory and the master key, writes
//!   and starts the systemd user unit, waits for the node, and prints `status` and `pair`
//!   (`up`).
//! - `apassy pair`: a node pairing link (node-pairing-v1 section 6) as text and as a QR
//!   code (`pair`, `qr`).
//! - `apassy status` and `apassy doctor`: the state of the node and its checks
//!   (`status`, `doctor`), as text or with `--json` (shapes in `docs/operations/linux-node.md`).
//! - `apassy team ...`: the team command line (`crate::cli`), the same as `apassy-team ...`
//!   (`team`).
//! - `apassy uninstall`: stops and removes the systemd user unit and keeps the node's
//!   files (`service`, `up`).
//!
//! Nothing here binds `0.0.0.0` or `::`: the relay listens on the loopback, and the front
//! binds only tailnet addresses (or the loopback, for the Tailscale Serve TCP fallback).
//! No command prints a secret except `pair`, whose link holds a one-use code by design.
//!
//! Exit codes: 0 success, 1 a check failed (`doctor`) or the node did not start, 2 usage,
//! 3 the node is not running (`status`, `pair`), 4 the node or the network failed.

pub mod config;
pub mod doctor;
pub mod keys;
pub mod pair;
pub mod qr;
pub mod serve;
pub mod service;
pub mod status;
pub mod team;
pub mod up;

use std::collections::BTreeMap;
use std::path::PathBuf;

pub use config::{HeadlessOptions, NodeFiles, NodeSettings, Route};
pub use keys::KeySource;

/// The name of the command in messages.
pub const PROGRAM: &str = "apassy";

/// The commands and their options.
pub const USAGE: &str = "\
apassy: the Apassy node without a window

Commands
  up [--port N] [--route direct|serve-tcp] [--push-gateway URL | --no-push]
     [--no-service] [--no-encrypt] [--no-pair] [--print-unit] [--json]
                     Check Tailscale, make the node's files, encrypt the key with
                     systemd-creds where it can, install and start the systemd user
                     service apassy-node.service, then pair.
  uninstall [--json] Stop and remove apassy-node.service. The node's files stay.
  serve              Run the node in the foreground (the service runs this).
  serve --stop       Stop the node that runs on this data directory.
  pair [--minutes N] [--json]
                     Print a one-use link and QR code that pairs a Mac with this
                     node (1 to 10 minutes, default 10).
  status [--json]    The service, the tailnet route, the pin, the teams, the push
                     gateway, and the key source.
  doctor [--json]    Check Tailscale, the port, the files, the service, linger, and
                     the clock.
  team ...           The team command line, the same as apassy-team.
  version            The version.

Every command takes --data-dir DIR (default: $XDG_DATA_HOME/apassy/node or
~/.local/share/apassy/node). Guide: docs/operations/linux-node.md.
";

/// An error that ends a node command with an exit code and one line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeCliError {
    pub code: i32,
    /// A stable word for `--json`: `usage`, `not_running`, `failed`, `node_error`.
    pub kind: &'static str,
    pub message: String,
}

impl NodeCliError {
    /// Exit 2: the command line or the local setup is wrong.
    pub fn usage(message: impl Into<String>) -> Self {
        Self {
            code: 2,
            kind: "usage",
            message: message.into(),
        }
    }

    /// Exit 1: the node did not start, or a step of `up` failed.
    pub fn failed(message: impl Into<String>) -> Self {
        Self {
            code: 1,
            kind: "failed",
            message: message.into(),
        }
    }

    /// Exit 3: the node is not running on this data directory.
    pub fn not_running(message: impl Into<String>) -> Self {
        Self {
            code: 3,
            kind: "not_running",
            message: message.into(),
        }
    }

    /// Exit 4: the node or the network failed.
    pub fn node(message: impl Into<String>) -> Self {
        Self {
            code: 4,
            kind: "node_error",
            message: message.into(),
        }
    }
}

impl std::fmt::Display for NodeCliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for NodeCliError {}

/// The parsed options of one node command.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Options {
    pub json: bool,
    pub data_dir: Option<PathBuf>,
    values: BTreeMap<&'static str, String>,
    flags: Vec<&'static str>,
}

impl Options {
    /// The value of `--name`, if given.
    pub fn value(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(String::as_str)
    }

    /// True when `--name` was given.
    pub fn flag(&self, name: &str) -> bool {
        self.flags.iter().any(|flag| *flag == name)
    }

    /// The number of `--name`, from `min` to `max`, or `default`.
    pub fn number(
        &self,
        name: &str,
        min: u64,
        max: u64,
        default: u64,
    ) -> Result<u64, NodeCliError> {
        match self.value(name) {
            None => Ok(default),
            Some(text) => text
                .parse::<u64>()
                .ok()
                .filter(|value| (min..=max).contains(value) && !text.starts_with('0'))
                .ok_or_else(|| {
                    NodeCliError::usage(format!("--{name} is a number from {min} to {max}."))
                }),
        }
    }
}

/// Parse `args`: `--json`, `--data-dir DIR`, the options with a value in `values`, and
/// the flags in `flags`. `--name value` and `--name=value` both work. A word that is not
/// an option, an unknown option, and an option given twice are refused.
pub fn parse_options(
    args: &[String],
    values: &[&'static str],
    flags: &[&'static str],
) -> Result<Options, NodeCliError> {
    let mut options = Options::default();
    let mut words = args.iter();
    while let Some(word) = words.next() {
        let Some(option) = word.strip_prefix("--") else {
            return Err(NodeCliError::usage(format!(
                "Unexpected argument {}. Run `{PROGRAM} help`.",
                printable(word)
            )));
        };
        let (name, inline) = match option.split_once('=') {
            Some((name, value)) => (name, Some(value.to_owned())),
            None => (option, None),
        };
        if name == "json" && inline.is_none() {
            if options.json {
                return Err(NodeCliError::usage("Option --json is given twice."));
            }
            options.json = true;
            continue;
        }
        if let Some(&flag) = flags.iter().find(|flag| **flag == name) {
            if inline.is_some() {
                return Err(NodeCliError::usage(format!(
                    "Option --{name} takes no value."
                )));
            }
            if options.flags.contains(&flag) {
                return Err(NodeCliError::usage(format!(
                    "Option --{name} is given twice."
                )));
            }
            options.flags.push(flag);
            continue;
        }
        let known = (name == "data-dir")
            .then_some("data-dir")
            .or_else(|| values.iter().copied().find(|value| *value == name));
        let Some(known) = known else {
            return Err(NodeCliError::usage(format!(
                "Unknown option --{}. Run `{PROGRAM} help`.",
                printable(name)
            )));
        };
        let value = match inline {
            Some(value) => value,
            None => words
                .next()
                .cloned()
                .ok_or_else(|| NodeCliError::usage(format!("Option --{known} needs a value.")))?,
        };
        if value.is_empty() {
            return Err(NodeCliError::usage(format!(
                "Option --{known} needs a value."
            )));
        }
        if known == "data-dir" {
            if options.data_dir.is_some() {
                return Err(NodeCliError::usage("Option --data-dir is given twice."));
            }
            let path = PathBuf::from(&value);
            if !path.is_absolute() {
                return Err(NodeCliError::usage("--data-dir must be an absolute path."));
            }
            options.data_dir = Some(path);
            continue;
        }
        if options.values.insert(known, value).is_some() {
            return Err(NodeCliError::usage(format!(
                "Option --{known} is given twice."
            )));
        }
    }
    Ok(options)
}

/// The node's directory: `--data-dir`, else `<Apassy data directory>/node`
/// (`$XDG_DATA_HOME/apassy/node` or `~/.local/share/apassy/node`). On a Mac the node runs
/// inside the app, whose own node directory is `<data>/node` too: there the command needs
/// `--data-dir`, so it never opens the app's node.
pub fn node_dir(options: &Options) -> Result<PathBuf, NodeCliError> {
    if let Some(dir) = &options.data_dir {
        return Ok(dir.clone());
    }
    if cfg!(target_os = "macos") {
        return Err(NodeCliError::usage(
            "On a Mac the node runs inside the Apassy app. To run a node without a window here, give --data-dir DIR.",
        ));
    }
    Ok(apassy::paths::data_dir().join(config::NODE_DIR))
}

/// Text without control characters, at most 80 characters, for messages.
pub fn printable(text: &str) -> String {
    text.chars()
        .map(|ch| if ch.is_control() { '?' } else { ch })
        .take(80)
        .collect()
}

/// `YYYY-MM-DD HH:MM:SS UTC` for seconds since the Unix epoch.
pub fn utc_text(secs: u64) -> String {
    let days = secs / 86_400;
    let rest = secs % 86_400;
    let (year, month, day) = civil_from_days(i64::try_from(days).unwrap_or(0));
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC",
        rest / 3600,
        (rest % 3600) / 60,
        rest % 60
    )
}

/// The proleptic Gregorian date of a day count since 1970-01-01 (H. Hinnant's algorithm).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = u32::try_from(doy - (153 * mp + 2) / 5 + 1).unwrap_or(1);
    let month = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).unwrap_or(1);
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// Days since 1970-01-01 of a proleptic Gregorian date (the inverse of `civil_from_days`).
pub(crate) fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year.rem_euclid(400);
    let month = i64::from(month);
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Print the error of a command: one line on stderr, and with `--json` the envelope on
/// stdout. Returns the exit code.
fn report(error: &NodeCliError, json: bool) -> i32 {
    if json {
        let envelope = serde_json::json!({
            "ok": false,
            "exit_code": error.code,
            "error": {"code": error.kind, "message": error.message},
        });
        println!("{envelope}");
    }
    eprintln!("{PROGRAM}: {}", error.message);
    error.code
}

/// Runs the node command line `args` (without the program name) and returns the exit
/// code. `apassy team ...` is `crate::cli` with the first word removed.
pub fn main(args: Vec<String>) -> i32 {
    let Some((command, rest)) = args.split_first() else {
        print!("{USAGE}");
        return 2;
    };
    let json = rest.iter().any(|arg| arg == "--json");
    let result = match command.as_str() {
        "team" => return team::run(rest.to_vec()),
        "serve" => serve::command(rest),
        "up" => up::command(rest),
        "uninstall" => up::uninstall(rest),
        "pair" => pair::command(rest),
        "status" => status::command(rest),
        "doctor" => doctor::command(rest),
        "help" | "--help" | "-h" => {
            print!("{USAGE}");
            Ok(0)
        }
        "version" | "--version" | "-V" => {
            println!("{PROGRAM} {}", env!("CARGO_PKG_VERSION"));
            Ok(0)
        }
        other => Err(NodeCliError::usage(format!(
            "Unknown command {}. Run `{PROGRAM} help` for the commands.",
            printable(other)
        ))),
    };
    match result {
        Ok(code) => code,
        Err(error) => report(&error, json),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(text: &str) -> Vec<String> {
        text.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn options_parse_values_flags_and_the_data_dir() {
        let options = parse_options(
            &args("--minutes 5 --json --data-dir /tmp/node --stop"),
            &["minutes"],
            &["stop"],
        )
        .unwrap();
        assert!(options.json);
        assert!(options.flag("stop"));
        assert_eq!(options.value("minutes"), Some("5"));
        assert_eq!(options.data_dir, Some(PathBuf::from("/tmp/node")));
        assert_eq!(options.number("minutes", 1, 10, 10).unwrap(), 5);
        let inline = parse_options(&args("--minutes=7"), &["minutes"], &[]).unwrap();
        assert_eq!(inline.number("minutes", 1, 10, 10).unwrap(), 7);
        assert_eq!(
            parse_options(&[], &["minutes"], &[])
                .unwrap()
                .number("minutes", 1, 10, 10)
                .unwrap(),
            10
        );
    }

    #[test]
    fn options_refuse_what_they_do_not_know() {
        for bad in [
            "extra",
            "--unknown",
            "--json --json",
            "--minutes",
            "--minutes 1 --minutes 2",
            "--data-dir relative/path",
            "--stop=yes",
            "--stop --stop",
        ] {
            let error = parse_options(&args(bad), &["minutes"], &["stop"]).unwrap_err();
            assert_eq!(error.code, 2, "{bad}");
        }
        let options = parse_options(&args("--minutes 0"), &["minutes"], &[]).unwrap();
        assert!(options.number("minutes", 1, 10, 10).is_err());
        let options = parse_options(&args("--minutes 11"), &["minutes"], &[]).unwrap();
        assert!(options.number("minutes", 1, 10, 10).is_err());
        let options = parse_options(&args("--minutes 05"), &["minutes"], &[]).unwrap();
        assert!(options.number("minutes", 1, 10, 10).is_err());
    }

    #[test]
    fn utc_text_and_days_agree() {
        assert_eq!(utc_text(0), "1970-01-01 00:00:00 UTC");
        // 2026-11-03 12:34:56 UTC.
        assert_eq!(utc_text(1_793_709_296), "2026-11-03 12:34:56 UTC");
        assert_eq!(utc_text(951_782_400), "2000-02-29 00:00:00 UTC");
        for days in [0_i64, 59, 60, 11_016, 20_760, 40_000] {
            let (year, month, day) = civil_from_days(days);
            assert_eq!(days_from_civil(year, month, day), days);
        }
    }

    #[test]
    fn the_mac_needs_a_data_dir() {
        let options = Options::default();
        if cfg!(target_os = "macos") {
            assert_eq!(node_dir(&options).unwrap_err().code, 2);
        } else {
            assert!(node_dir(&options).unwrap().ends_with("apassy/node"));
        }
    }
}
