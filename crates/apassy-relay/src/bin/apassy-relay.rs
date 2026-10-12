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
use apassy_relay::server::directory::{TeamLimits, TeamLimitsUpdate};
use apassy_relay::server::operator::{self, Command as Operator};

const USAGE: &str = "Usage:
  apassy-relay [serve]
  apassy-relay init [--team <name> --owner <name>]
  apassy-relay migrate
  apassy-relay admin team-code [--hours <n>]
  apassy-relay admin teams
  apassy-relay admin limits <team id> [--members <n>] [--items <n>] [--agents <n>]
    [--runs-per-hour <n>] [--pending-runs <n>] [--agent-requests <n>]
    [--sync-bytes <n>] [--sync-pushes-per-hour <n>] [--sync-transfers <n>]
    [--open-questions <n>] [--questions-per-hour <n>]
  apassy-relay admin suspend|resume|delete <team id>
  apassy-relay admin backup

The configuration is read from the environment:
  APASSY_RELAY_DATA, APASSY_RELAY_LISTEN, APASSY_RELAY_PUBLIC_URL,
  APASSY_RELAY_EDGE_SECRET or _FILE, APASSY_RELAY_KEY or _FILE (the master key),
  APASSY_RELAY_SESSION_TTL, APASSY_RELAY_APPROVAL_TIMEOUT,
  APASSY_RELAY_BLOCKED_ADDRESSES, APASSY_RELAY_BACKUP_DIR, and for push all of
  APASSY_RELAY_PUSH_URL, APASSY_RELAY_PUSH_TOPIC, APASSY_RELAY_PUSH_SECRET or _FILE.
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
        _ => Err("Give one team id, such as t_7k2m5q4x3c.".to_string()),
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
        "limits" => {
            let Some(id) = rest.first() else {
                return Err("Give one team id, such as t_7k2m5q4x3c.".to_string());
            };
            let team = team_arg(std::slice::from_ref(id))?;
            let names = [
                "--members",
                "--items",
                "--agents",
                "--runs-per-hour",
                "--pending-runs",
                "--agent-requests",
                "--sync-bytes",
                "--sync-pushes-per-hour",
                "--sync-transfers",
                "--open-questions",
                "--questions-per-hour",
            ];
            let flags = parse_flags(&rest[1..], &names)?;
            let mut values = [None; 11];
            for (index, text) in flags.iter().enumerate() {
                if let Some(text) = text {
                    values[index] =
                        Some(text.parse::<u64>().map_err(|_| {
                            format!("{} must be a positive integer.", names[index])
                        })?);
                }
            }
            let set = flags
                .iter()
                .any(Option::is_some)
                .then_some(TeamLimitsUpdate {
                    members: values[0],
                    items: values[1],
                    agents: values[2],
                    runs_per_hour: values[3],
                    pending_runs: values[4],
                    agent_requests: values[5],
                    sync_bytes: values[6],
                    sync_pushes_per_hour: values[7],
                    sync_transfers: values[8],
                    open_questions: values[9],
                    questions_per_hour: values[10],
                });
            if let Some(update) = set {
                TeamLimits::default()
                    .apply(update)
                    .map_err(|error| error.message)?;
            }
            Ok(Operator::Limits { team, set })
        }
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
                if running.hub().config.push.is_none() {
                    eprintln!(
                        "apassy-relay: push is off (APASSY_RELAY_PUSH_URL, APASSY_RELAY_PUSH_TOPIC, and APASSY_RELAY_PUSH_SECRET are not set): questions reach the devices by their long polls only"
                    );
                }
                running.wait();
                ExitCode::SUCCESS
            }
            Err(error) => fail(&error.message),
        },
        Command::Help | Command::Admin(_) => ExitCode::SUCCESS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn limits_command_reads_or_updates_selected_fields() {
        let team = TeamId::parse("t_abcdefgh23").unwrap();
        assert_eq!(
            parse_admin(&args(&["limits", team.as_str()])).unwrap(),
            Operator::Limits {
                team: team.clone(),
                set: None
            }
        );
        assert_eq!(
            parse_admin(&args(&[
                "limits",
                team.as_str(),
                "--members",
                "7",
                "--agent-requests",
                "224",
            ]))
            .unwrap(),
            Operator::Limits {
                team,
                set: Some(TeamLimitsUpdate {
                    members: Some(7),
                    agent_requests: Some(224),
                    ..Default::default()
                }),
            }
        );
    }

    #[test]
    fn limits_command_refuses_bad_arguments() {
        for values in [
            vec!["limits"],
            vec!["limits", "bad"],
            vec!["limits", "t_abcdefgh23", "--items"],
            vec!["limits", "t_abcdefgh23", "--items", "-1"],
            vec!["limits", "t_abcdefgh23", "--items", "0"],
            vec!["limits", "t_abcdefgh23", "--items", "1000001"],
            vec!["limits", "t_abcdefgh23", "--agent-requests", "225"],
            vec!["limits", "t_abcdefgh23", "--sync-bytes", "1048575"],
            vec!["limits", "t_abcdefgh23", "--sync-bytes", "268435457"],
            vec!["limits", "t_abcdefgh23", "--sync-pushes-per-hour", "0"],
            vec!["limits", "t_abcdefgh23", "--sync-transfers", "9"],
            vec!["limits", "t_abcdefgh23", "--open-questions", "1001"],
            vec!["limits", "t_abcdefgh23", "--questions-per-hour", "0"],
            vec!["limits", "t_abcdefgh23", "--items", "1", "--items", "2"],
            vec!["limits", "t_abcdefgh23", "--unknown", "1"],
            vec!["limits", "t_abcdefgh23", "t_bcdefgh234"],
        ] {
            assert!(parse_admin(&args(&values)).is_err(), "{values:?}");
        }
    }

    #[test]
    fn limits_command_accepts_each_flag() {
        assert_eq!(
            parse_admin(&args(&[
                "limits",
                "t_abcdefgh23",
                "--members",
                "1",
                "--items",
                "2",
                "--agents",
                "3",
                "--runs-per-hour",
                "4",
                "--pending-runs",
                "5",
                "--agent-requests",
                "6",
                "--sync-bytes",
                "1048576",
                "--sync-pushes-per-hour",
                "8",
                "--sync-transfers",
                "1",
                "--open-questions",
                "10",
                "--questions-per-hour",
                "11",
            ]))
            .unwrap(),
            Operator::Limits {
                team: TeamId::parse("t_abcdefgh23").unwrap(),
                set: Some(TeamLimitsUpdate {
                    members: Some(1),
                    items: Some(2),
                    agents: Some(3),
                    runs_per_hour: Some(4),
                    pending_runs: Some(5),
                    agent_requests: Some(6),
                    sync_bytes: Some(1_048_576),
                    sync_pushes_per_hour: Some(8),
                    sync_transfers: Some(1),
                    open_questions: Some(10),
                    questions_per_hour: Some(11),
                }),
            }
        );
    }
}
