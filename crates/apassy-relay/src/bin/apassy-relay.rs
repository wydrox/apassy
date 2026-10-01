//! The relay server.
//!
//! `apassy-relay serve` (default), `apassy-relay init [--team <name> --owner <name>]`,
//! `apassy-relay migrate`, and `apassy-relay admin <command>` for the operator.
//!
//! Exit codes: 0 success, 1 a failure (bad configuration, no relay, wrong key), 2 a
//! usage error. `init` with a team prints the owner token once on stdout, and
//! `admin team-code` prints the code once on stdout. Nothing else goes to stdout except
//! the JSON of `admin`, and no secret goes to stderr.
#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use apassy_relay::config::{ADMIN_SOCKET, RelayConfig, old_key_from_env};
use apassy_relay::ids::TeamId;
use apassy_relay::server::Relay;
use apassy_relay::server::operator::{self, Command as Operator};

const USAGE: &str = "Usage:
  apassy-relay [serve]
  apassy-relay init [--team <name> --owner <name>]
  apassy-relay migrate
  apassy-relay admin team-code [--hours <n>]
  apassy-relay admin teams
  apassy-relay admin suspend|resume|delete <team id>
  apassy-relay admin backup

The configuration is read from the environment:
  APASSY_RELAY_DATA, APASSY_RELAY_LISTEN, APASSY_RELAY_PUBLIC_URL,
  APASSY_RELAY_EDGE_SECRET or _FILE, APASSY_RELAY_KEY or _FILE (the master key),
  APASSY_RELAY_SESSION_TTL, APASSY_RELAY_APPROVAL_TIMEOUT,
  APASSY_RELAY_BLOCKED_ADDRESSES, APASSY_RELAY_BACKUP_DIR.
`migrate` also reads APASSY_RELAY_OLD_KEY or _FILE: the key of the old team.db.
`admin` reads only APASSY_RELAY_DATA and talks to the running relay.";

enum Command {
    Serve,
    Init { team: Option<(String, String)> },
    Migrate,
    Admin(Operator),
    Help,
}

fn parse_flags(args: &[String], names: &[&str]) -> Result<Vec<Option<String>>, String> {
    let mut values = vec![None; names.len()];
    let mut rest = args.iter();
    while let Some(flag) = rest.next() {
        let index = names
            .iter()
            .position(|name| name == flag)
            .ok_or_else(|| format!("Unknown option: {flag}"))?;
        let value = rest
            .next()
            .ok_or_else(|| format!("{flag} needs a value."))?;
        if values[index].replace(value.clone()).is_some() {
            return Err(format!("{flag} is given twice."));
        }
    }
    Ok(values)
}

fn team_arg(args: &[String]) -> Result<TeamId, String> {
    match args {
        [id] => TeamId::parse(id).ok_or_else(|| format!("Not a team id: {id}")),
        _ => Err("Give one team id, such as t_7k2m9q4x8c.".to_string()),
    }
}

fn parse_admin(args: &[String]) -> Result<Operator, String> {
    let Some(first) = args.first() else {
        return Err("admin needs a command.".to_string());
    };
    let rest = &args[1..];
    match first.as_str() {
        "team-code" => {
            let flags = parse_flags(rest, &["--hours"])?;
            let hours = match &flags[0] {
                Some(text) => text
                    .parse::<u64>()
                    .map_err(|_| "--hours is a number.".to_string())?,
                None => 72,
            };
            Ok(Operator::TeamCode { hours })
        }
        "teams" if rest.is_empty() => Ok(Operator::Teams),
        "suspend" => Ok(Operator::Suspend {
            team: team_arg(rest)?,
        }),
        "resume" => Ok(Operator::Resume {
            team: team_arg(rest)?,
        }),
        "delete" => Ok(Operator::Delete {
            team: team_arg(rest)?,
        }),
        "backup" if rest.is_empty() => Ok(Operator::Backup),
        other => Err(format!("Unknown admin command: {other}")),
    }
}

fn parse(args: &[String]) -> Result<Command, String> {
    let Some(first) = args.first() else {
        return Ok(Command::Serve);
    };
    match first.as_str() {
        "serve" if args.len() == 1 => Ok(Command::Serve),
        "migrate" if args.len() == 1 => Ok(Command::Migrate),
        "-h" | "--help" | "help" => Ok(Command::Help),
        "init" => {
            let flags = parse_flags(&args[1..], &["--team", "--owner"])?;
            match (&flags[0], &flags[1]) {
                (Some(team), Some(owner)) => Ok(Command::Init {
                    team: Some((team.clone(), owner.clone())),
                }),
                (None, None) => Ok(Command::Init { team: None }),
                _ => Err("init needs both --team and --owner, or neither.".to_string()),
            }
        }
        "admin" => parse_admin(&args[1..]).map(Command::Admin),
        other => Err(format!("Unknown command: {other}")),
    }
}

fn fail(message: &str) -> ExitCode {
    eprintln!("apassy-relay: {message}");
    ExitCode::from(1)
}

fn admin(command: &Operator) -> ExitCode {
    let data = std::env::var("APASSY_RELAY_DATA").unwrap_or_else(|_| "/data".to_string());
    let socket = PathBuf::from(data).join(ADMIN_SOCKET);
    match operator::send(&socket, command) {
        Ok(result) => {
            if let Operator::TeamCode { .. } = command {
                // The code alone on stdout, so it can go to a file.
                println!("{}", result["code"].as_str().unwrap_or_default());
                eprintln!(
                    "apassy-relay: a team code, shown once, valid until {}. Give it to the future owner: `apassy-team create`.",
                    result["expires_at"]
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&result).unwrap_or_default()
                );
            }
            ExitCode::SUCCESS
        }
        Err(error) => fail(&error.message),
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
    match &command {
        Command::Help => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Command::Admin(operator) => return admin(operator),
        _ => {}
    }
    let config = match RelayConfig::from_env() {
        Ok(config) => config,
        Err(error) => return fail(&error.message),
    };
    match command {
        Command::Init {
            team: Some((team, owner)),
        } => match Relay::init(&config, &team, &owner) {
            Ok(token) => {
                println!("{}", token.expose());
                eprintln!(
                    "apassy-relay: the relay and its first team are created. The owner token above is shown once."
                );
                ExitCode::SUCCESS
            }
            Err(error) => fail(&error.message),
        },
        Command::Init { team: None } => match Relay::init_empty(&config) {
            Ok(()) => {
                eprintln!(
                    "apassy-relay: the relay is created with no team. Make a team code with `apassy-relay admin team-code` while it runs."
                );
                ExitCode::SUCCESS
            }
            Err(error) => fail(&error.message),
        },
        Command::Migrate => {
            let old_key = match old_key_from_env() {
                Ok(key) => key,
                Err(error) => return fail(&error.message),
            };
            match Relay::migrate(&config, &old_key) {
                Ok(team) => {
                    println!("{team}");
                    eprintln!(
                        "apassy-relay: team.db is now team {team}, with a new key in relay.db. The old file is team.db.pre-teams; it opens with the old key only. Old member and agent tokens keep working for this team."
                    );
                    ExitCode::SUCCESS
                }
                Err(error) => fail(&error.message),
            }
        }
        Command::Serve => match Relay::start(config) {
            Ok(running) => {
                eprintln!("apassy-relay: listening on {}", running.addr);
                running.wait();
                ExitCode::SUCCESS
            }
            Err(error) => fail(&error.message),
        },
        Command::Help | Command::Admin(_) => ExitCode::SUCCESS,
    }
}
