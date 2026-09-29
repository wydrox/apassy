//! The relay server. `apassy-relay serve` (default) or `apassy-relay init --team <name> --owner <name>`.
//!
//! Exit codes: 0 success, 1 a failure (bad configuration, no vault, wrong key), 2 a
//! usage error. `init` prints the owner token once on stdout. Nothing else goes to
//! stdout, and no secret goes to stderr.
#![forbid(unsafe_code)]

use std::process::ExitCode;

use apassy_relay::config::RelayConfig;
use apassy_relay::server::Relay;

const USAGE: &str = "Usage:
  apassy-relay [serve]
  apassy-relay init --team <name> --owner <name>

The configuration is read from the environment:
  APASSY_RELAY_DATA, APASSY_RELAY_LISTEN, APASSY_RELAY_PUBLIC_URL,
  APASSY_RELAY_EDGE_SECRET or _FILE, APASSY_RELAY_KEY or _FILE,
  APASSY_RELAY_SESSION_TTL, APASSY_RELAY_APPROVAL_TIMEOUT.";

enum Command {
    Serve,
    Init { team: String, owner: String },
    Help,
}

fn parse(args: &[String]) -> Result<Command, String> {
    let Some(first) = args.first() else {
        return Ok(Command::Serve);
    };
    match first.as_str() {
        "serve" if args.len() == 1 => Ok(Command::Serve),
        "-h" | "--help" | "help" => Ok(Command::Help),
        "init" => {
            let mut team = None;
            let mut owner = None;
            let mut rest = args[1..].iter();
            while let Some(flag) = rest.next() {
                let slot = match flag.as_str() {
                    "--team" => &mut team,
                    "--owner" => &mut owner,
                    other => return Err(format!("Unknown option for init: {other}")),
                };
                let value = rest
                    .next()
                    .ok_or_else(|| format!("{flag} needs a value."))?;
                if slot.replace(value.clone()).is_some() {
                    return Err(format!("{flag} is given twice."));
                }
            }
            match (team, owner) {
                (Some(team), Some(owner)) => Ok(Command::Init { team, owner }),
                _ => Err("init needs --team and --owner.".to_string()),
            }
        }
        other => Err(format!("Unknown command: {other}")),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = match parse(&args) {
        Ok(command) => command,
        Err(message) => {
            eprintln!("apassy-relay: {message}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    if matches!(command, Command::Help) {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let config = match RelayConfig::from_env() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("apassy-relay: {}", error.message);
            return ExitCode::from(1);
        }
    };
    match command {
        Command::Init { team, owner } => match Relay::init(&config, &team, &owner) {
            Ok(token) => {
                println!("{}", token.expose());
                eprintln!(
                    "apassy-relay: the team vault is created. The owner token above is shown once."
                );
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("apassy-relay: {}", error.message);
                ExitCode::from(1)
            }
        },
        Command::Serve => match Relay::start(config) {
            Ok(running) => {
                eprintln!("apassy-relay: listening on {}", running.addr);
                running.wait();
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("apassy-relay: {}", error.message);
                ExitCode::from(1)
            }
        },
        Command::Help => ExitCode::SUCCESS,
    }
}
