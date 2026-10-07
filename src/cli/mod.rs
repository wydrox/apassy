//! The `apassy` command line (ADR 0017).
//!
//! `apassy` without arguments opens the window. With a command, it talks to the running
//! app over the owner socket ([`crate::owner`]). The app does each change with the same
//! checks as its views. The command line never prints a secret value of an item, and
//! never takes a secret as a program argument.

pub mod args;
mod commands;
mod completions;
mod doctor;
mod help;
pub mod import;
pub mod print;
mod setup;
pub mod terminal;

use std::path::PathBuf;

use args::{Args, Usage};

use crate::owner::client::{self, SendError};
use crate::owner::wire::{Command, Data, Response, SESSION_ENV, SecretText};

/// Exit codes.
pub const EXIT_OK: i32 = 0;
pub const EXIT_FAILED: i32 = 1;
pub const EXIT_USAGE: i32 = 2;
pub const EXIT_NOT_RUNNING: i32 = 3;

/// Why a command did not finish.
#[derive(Debug)]
pub enum Failure {
    Usage(Usage),
    /// The app answered with an error.
    App {
        code: String,
        message: String,
    },
    NotRunning(String),
    Other(String),
    /// The command printed its own JSON answer with `"ok": false`. Only the exit code
    /// is left, so `--json` prints one document.
    Printed,
}

impl From<Usage> for Failure {
    fn from(usage: Usage) -> Self {
        Self::Usage(usage)
    }
}

impl From<std::io::Error> for Failure {
    fn from(err: std::io::Error) -> Self {
        Self::Other(err.to_string())
    }
}

pub type Outcome = Result<(), Failure>;

/// Settings of one run of the command line.
pub struct Cli {
    pub socket: PathBuf,
    pub json: bool,
    session: Option<SecretText>,
}

impl Cli {
    /// Send one command. An error answer stays a [`Response`].
    pub fn send(&self, command: Command) -> Result<Response, Failure> {
        client::send(&self.socket, self.session.as_ref(), command).map_err(|err| match err {
            SendError::NotRunning(_) => Failure::NotRunning(err.to_string()),
            other => Failure::Other(other.to_string()),
        })
    }

    /// Send one command. An error answer becomes a [`Failure`].
    pub fn call(&self, command: Command) -> Result<Response, Failure> {
        let response = self.send(command)?;
        if response.ok {
            Ok(response)
        } else {
            Err(Failure::App {
                code: response.code,
                message: response.message,
            })
        }
    }

    /// Print a response: JSON with `--json`, else the message.
    pub fn print_message(&self, response: &Response) {
        if self.json {
            print_json(response);
        } else {
            println!("{}", print::clean(&response.message));
        }
    }

    pub fn has_session(&self) -> bool {
        self.session.is_some()
    }
}

pub fn print_json<T: serde::Serialize>(value: &T) {
    match serde_json::to_string_pretty(value) {
        Ok(text) => println!("{text}"),
        Err(err) => eprintln!("apassy: cannot write JSON: {err}"),
    }
}

/// Tell the owner to look at the window. Commands that need an owner check call this.
pub fn expect_owner_check() {
    terminal::tell("Confirm in the Apassy window (Touch ID or your passphrase)…");
}

/// Run the command line with the session in `APASSY_SESSION`. Returns the exit code.
pub fn run(words: Vec<String>) -> i32 {
    let session = std::env::var(SESSION_ENV)
        .ok()
        .filter(|token| !token.trim().is_empty())
        .map(|token| SecretText::new(token.trim().to_owned()));
    run_with(words, session)
}

/// Run the command line with a session token. Returns the exit code.
pub fn run_with(words: Vec<String>, session: Option<SecretText>) -> i32 {
    let mut args = Args::new(words);
    let json = args.flag(&["--json"]);
    let socket = match args.value(&["--socket"]) {
        Ok(path) => path.map_or_else(client::default_socket_path, PathBuf::from),
        Err(usage) => return report(Failure::Usage(usage), json),
    };
    let cli = Cli {
        socket,
        json,
        session,
    };
    let Some(command) = args.positional() else {
        if args.flag(&["-h", "--help"]) {
            print!("{HELP}");
            return EXIT_OK;
        }
        if args.flag(&["-V", "--version"]) {
            println!("apassy {}", env!("CARGO_PKG_VERSION"));
            return EXIT_OK;
        }
        return report(
            Failure::Usage(args::usage(
                "Name a command. Run apassy --help for the list.",
            )),
            json,
        );
    };
    match dispatch(&cli, &command, args) {
        Ok(()) => EXIT_OK,
        Err(failure) => report(failure, json),
    }
}

fn dispatch(cli: &Cli, command: &str, mut args: Args) -> Outcome {
    if command == "help" {
        args.flag(&["-h", "--help"]);
        let path = args.rest();
        args.finish()?;
        print!("{}", help::text(&path)?);
        return Ok(());
    }
    if args.flag(&["-h", "--help"]) {
        let text = help::for_command(command, args)?;
        print!("{text}");
        return Ok(());
    }
    match command {
        "version" | "--version" | "-V" => {
            args.finish()?;
            println!("apassy {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        "status" => commands::status(cli, args),
        "login" => commands::login(cli, args),
        "logout" => commands::logout(cli, args),
        "lock" => commands::simple(cli, args, Command::Lock),
        "unlock" | "show" | "open" => commands::simple(cli, args, Command::Show),
        "item" | "items" | "credential" | "credentials" => commands::item(cli, args),
        "import" => commands::import(cli, args),
        "agent" | "agents" => commands::agent(cli, args),
        "grant" | "grants" => commands::grant(cli, args),
        "request" | "requests" => commands::request(cli, args),
        "runs" | "run" => commands::runs(cli, args),
        "pattern" | "patterns" => commands::pattern(cli, args),
        "activity" | "log" => commands::activity(cli, args),
        "decisions" => commands::decisions(cli, args),
        "vault" => commands::vault(cli, args),
        "backup" => commands::backup(cli, args),
        "doctor" => doctor::run(cli, args),
        "setup" => setup::run(cli, args),
        "completions" => completions::run(args),
        other => Err(Failure::Usage(args::usage(format!(
            "Unknown command \"{other}\". Run apassy --help."
        )))),
    }
}

/// Print a failure and return its exit code.
fn report(failure: Failure, json: bool) -> i32 {
    let (code, message, exit) = match failure {
        Failure::Printed => return EXIT_FAILED,
        Failure::Usage(usage) if usage.0.contains("apassy help") || usage.0.contains("--help") => {
            ("usage".to_owned(), usage.0, EXIT_USAGE)
        }
        Failure::Usage(usage) => (
            "usage".to_owned(),
            format!("{usage} See apassy --help."),
            EXIT_USAGE,
        ),
        Failure::App { code, message } => (code, message, EXIT_FAILED),
        Failure::NotRunning(message) => ("not_running".to_owned(), message, EXIT_NOT_RUNNING),
        Failure::Other(message) => ("failed".to_owned(), message, EXIT_FAILED),
    };
    if json {
        print_json(&Response {
            ok: false,
            code,
            message,
            data: Data::None,
        });
    } else {
        eprintln!("apassy: {}", print::clean(&message));
    }
    exit
}

/// The help of one command group.
fn help_for(topic: Option<&str>) -> Option<&'static str> {
    Some(match topic? {
        "item" | "items" | "credential" | "credentials" => commands::ITEM_HELP,
        "import" => commands::IMPORT_HELP,
        "agent" | "agents" => commands::AGENT_HELP,
        "grant" | "grants" => commands::GRANT_HELP,
        "request" | "requests" => commands::REQUEST_HELP,
        "runs" | "run" => commands::RUNS_HELP,
        "pattern" | "patterns" => commands::PATTERN_HELP,
        "activity" | "log" | "decisions" => commands::ACTIVITY_HELP,
        "vault" | "backup" | "lock" | "unlock" | "show" | "open" => commands::VAULT_HELP,
        "login" | "logout" | "status" => commands::SESSION_HELP,
        "doctor" => doctor::HELP,
        "setup" => setup::HELP,
        "completions" => completions::HELP,
        _ => return None,
    })
}

const HELP: &str = "\
apassy — the Apassy owner command line

Usage:
  apassy                      Open the Apassy window.
  apassy COMMAND [OPTIONS]    Talk to the running Apassy window.

Session (the window must run):
  status                      The vault, the broker, and the session.
  login                       Open a session after Touch ID or the passphrase in the window.
                              Use it as: eval \"$(apassy login)\"
  logout                      End the session.
  lock                        Lock the vault. Every session ends.
  unlock                      Bring the window to the front to unlock it.

Credentials:
  item list|show|add|edit|delete|archive|unarchive|history
  item env|declare|connector|review       Agent settings of a credential.
  import FILE                 Add credentials from a .env file, or a 1Password or Bitwarden CSV export.

Agents and access:
  agent list|show|add|revoke|rotate|see-all|lifetime
  setup claude|codex          Register an agent and write the MCP server and the prompt hook.
  grant set|remove|rule|operation
  request list|grant|deny     Access requests of agents.
  runs list|approve|deny      Runs that wait for you.
  pattern list|remove         Remembered approvals.

History and vault:
  activity                    Agent requests and decisions.
  decisions export            All bouncer decisions as JSON Lines.
  vault backup|change-passphrase|restore
  doctor                      Check the installation.
  completions zsh|bash|fish   Print a shell completion script.

Options:
  --json                      Machine-readable output.
  --socket PATH               The owner socket. Default: $APASSY_OWNER_SOCKET, else
                              owner.sock in the Apassy data directory.
  -h, --help                  Help. apassy help COMMAND [SUBCOMMAND] for one command.
  -V, --version               The version.

The command line never shows a secret value, and never takes one as an argument: it
asks on the terminal with the echo off, or reads stdin or a file. Grants, approvals,
new tokens, and agent settings ask for Touch ID or the passphrase in the window for each
change, as the window does.
";
