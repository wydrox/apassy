//! The relay server.
//!
//! `apassy-relay serve` (default), `apassy-relay init [--team <name> --owner <name>]`,
//! `apassy-relay migrate`, `apassy-relay backup` and `apassy-relay connect-cutover` with the
//! relay stopped, and `apassy-relay admin <command>` for the operator.
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
use apassy_relay::server::hub::MAX_SWEEP_DAYS;
use apassy_relay::server::operator::{self, Command as Operator};

const USAGE: &str = "Usage:
  apassy-relay --version
  apassy-relay [serve]
  apassy-relay init [--team <name> --owner <name>]
  apassy-relay migrate
  apassy-relay rollback-check
  apassy-relay downgrade-schema-6
  apassy-relay downgrade-schema-7
  apassy-relay downgrade-directory-1003 [--delete-vault-stores]
  apassy-relay downgrade-directory-1004 [--delete-vault-stores]
  apassy-relay downgrade-directory-1005 [--delete-vault-stores]
  apassy-relay snapshot-check
  apassy-relay backup
  apassy-relay connect-cutover [--dry-run | --confirm-delete-teams <plan>] [--backup <folder>]
  apassy-relay admin team-code [--hours <n>]
  apassy-relay admin node-code [--minutes <n>]
  apassy-relay admin teams
  apassy-relay admin readiness
  apassy-relay admin limits <team id> [--members <n>] [--items <n>] [--agents <n>]
    [--runs-per-hour <n>] [--pending-runs <n>] [--agent-requests <n>]
    [--sync-bytes <n>] [--sync-pushes-per-hour <n>] [--sync-transfers <n>]
    [--open-questions <n>] [--questions-per-hour <n>] [--question-bytes <n>]
    [--member-open-questions <n>] [--member-questions-per-hour <n>]
    [--device-open-questions <n>] [--device-questions-per-hour <n>]
    [--feed-bytes <n>] [--feed-actions-per-hour <n>]
  apassy-relay admin suspend|resume <team id>
  apassy-relay admin delete <team id> [--free-connect-key]
  apassy-relay admin backup
  apassy-relay admin connect-sweep [--idle-days <n>] [--delete-days <n>] [--dry-run | --apply]
  apassy-relay admin billing [--resume-deletions] [--resolve <problem id>]

The configuration is read from the environment:
  APASSY_RELAY_DATA, APASSY_RELAY_LISTEN, APASSY_RELAY_PUBLIC_URL,
  APASSY_RELAY_EDGE_SECRET or _FILE, APASSY_RELAY_KEY or _FILE (the master key),
  APASSY_RELAY_SESSION_TTL, APASSY_RELAY_APPROVAL_TIMEOUT,
  APASSY_RELAY_BLOCKED_ADDRESSES, APASSY_RELAY_BACKUP_DIR, and for push all of
  APASSY_RELAY_PUSH_URL, APASSY_RELAY_PUSH_TOPIC, APASSY_RELAY_PUSH_SECRET or _FILE,
  APASSY_RELAY_QUESTIONS_TO_APPROVERS (0 or 1), APASSY_RELAY_CONNECT_TEAMS_PER_DAY,
  APASSY_RELAY_CONNECT_TEAMS_MAX, APASSY_RELAY_CONNECT_LONG_POLLS,
  APASSY_RELAY_FREE_CONNECT (0 or 1), APASSY_RELAY_MODE (relay or connect), and the
  Connect settings of docs/OPERATIONS.md sections 26 to 29.
`migrate` also reads APASSY_RELAY_OLD_KEY or _FILE: the key of the old team.db.
`admin` reads only APASSY_RELAY_DATA and talks to the running relay.
`rollback-check` reads relay.db and the team files read-only, with or without a running
relay, and prints what a rollback to schema 5 would undo (docs/OPERATIONS.md 21.3). It
exits 1 when any team is not clean.
`downgrade-schema-6` runs with the relay stopped: every team file of schema 7 or 8 goes
back to 6 in place, and each agent with an item list is revoked (docs/OPERATIONS.md 23.3).
It exits 1 when any team failed.
`downgrade-schema-7` runs with the relay stopped: every team file of schema 8 goes back
to 7 in place; the push handles stay for the next start of schema 8 (docs/OPERATIONS.md
25.2). It exits 1 when any team failed.
`downgrade-directory-1003` runs with the relay stopped: relay.db goes from 1004 or 1005
back to 1003 in place, and its OAuth clients, connect requests, refresh tokens, and unused
node pairing codes are dropped (docs/OPERATIONS.md 24.3).
`downgrade-directory-1004` runs with the relay stopped: relay.db goes from 1005 back to
1004 in place, and its unused node pairing codes are dropped (docs/OPERATIONS.md 25.3).
`downgrade-directory-1005` runs with the relay stopped: relay.db goes from 1006 (Apassy
Connect accounts) back to 1005 in place, and the vault stores of the accounts are deleted
with their snapshots; the accounts stay, unread by that image (docs/OPERATIONS.md 26.3).
The three directory downgrades delete the vault stores of the accounts only with
--delete-vault-stores; without it a relay.db that holds vault stores is refused unchanged.
The downgrades and `rollback-check` refuse APASSY_RELAY_MODE=connect: its files are plain.
`backup` runs with the relay stopped: a byte-for-byte copy of the data directory in a new
folder of APASSY_RELAY_BACKUP_DIR, with MANIFEST.json (\"stopped\": true); `admin backup`
is the one of a running relay.
`connect-cutover` runs with the relay stopped and the master key, once, at the end of the
hosted relay (docs/operations/connect.md): it checks the newest stopped backup (or
--backup <folder>), keeps relay.db and the vault stores of the accounts as plain files,
and deletes every other team with its files and keys; then the relay starts with
APASSY_RELAY_MODE=connect and no master key. --dry-run (the default) changes nothing and
prints the plan with its plan_sha256; --confirm-delete-teams <plan_sha256> does it, only if
the plan is still the one of the dry run, and writes cutover.json. A run that stopped is
finished by the next one. It exits 1 when a check fails.";

/// `connect-sweep`: days without a sign-in before a suspension, and days of suspension
/// before a deletion.
const DEFAULT_SWEEP_DAYS: u64 = 30;

/// Parsed once from the arguments: the size of `Admin` does not matter.
#[allow(clippy::large_enum_variant)]
enum Command {
    Serve,
    Init {
        team: Option<(String, String)>,
    },
    Migrate,
    RollbackCheck,
    DowngradeSchema6,
    DowngradeSchema7,
    DowngradeDirectory1003 {
        delete_vault_stores: bool,
    },
    DowngradeDirectory1004 {
        delete_vault_stores: bool,
    },
    DowngradeDirectory1005 {
        delete_vault_stores: bool,
    },
    SnapshotCheck,
    Backup,
    ConnectCutover {
        confirm: Option<String>,
        backup: Option<PathBuf>,
    },
    Admin(Operator),
    Help,
    Version,
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
        "node-code" => {
            let flags = parse_flags(rest, &["--minutes"])?;
            let minutes = match &flags[0] {
                Some(text) => text
                    .parse::<u64>()
                    .map_err(|_| "--minutes is a number.".to_string())?,
                None => apassy_relay::server::directory::MAX_NODE_CODE_MINUTES,
            };
            Ok(Operator::NodeCode { minutes })
        }
        "teams" if rest.is_empty() => Ok(Operator::Teams),
        "billing" => {
            let mut resume_deletions = false;
            let mut resolve = None;
            let mut args = rest.iter();
            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--resume-deletions" => resume_deletions = true,
                    "--resolve" => {
                        let id = args
                            .next()
                            .and_then(|text| text.parse::<u64>().ok())
                            .ok_or_else(|| "--resolve needs a problem id.".to_string())?;
                        resolve = Some(id);
                    }
                    other => return Err(format!("Unknown billing option: {other}")),
                }
            }
            Ok(Operator::Billing {
                resume_deletions,
                resolve,
            })
        }
        "readiness" if rest.is_empty() => Ok(Operator::Readiness),
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
                "--question-bytes",
                "--member-open-questions",
                "--member-questions-per-hour",
                "--device-open-questions",
                "--device-questions-per-hour",
                "--feed-bytes",
                "--feed-actions-per-hour",
            ];
            let flags = parse_flags(&rest[1..], &names)?;
            let mut values = [None; 18];
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
                    question_bytes: values[11],
                    member_open_questions: values[12],
                    member_questions_per_hour: values[13],
                    device_open_questions: values[14],
                    device_questions_per_hour: values[15],
                    feed_bytes: values[16],
                    feed_actions_per_hour: values[17],
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
        "delete" => {
            let free_connect_key = rest.iter().any(|arg| arg == "--free-connect-key");
            let others: Vec<String> = rest
                .iter()
                .filter(|arg| *arg != "--free-connect-key")
                .cloned()
                .collect();
            if others.len() + 1 < rest.len() {
                return Err("--free-connect-key is given twice.".to_string());
            }
            Ok(Operator::Delete {
                team: team_arg(&others)?,
                free_connect_key,
            })
        }
        "backup" if rest.is_empty() => Ok(Operator::Backup),
        "connect-sweep" => {
            let apply = rest.iter().filter(|arg| *arg == "--apply").count();
            let dry = rest.iter().filter(|arg| *arg == "--dry-run").count();
            if apply > 1 || dry > 1 || (apply > 0 && dry > 0) {
                return Err("Give --apply or --dry-run once.".to_string());
            }
            let dry_run = apply == 0;
            let others: Vec<String> = rest
                .iter()
                .filter(|arg| *arg != "--dry-run" && *arg != "--apply")
                .cloned()
                .collect();
            if others.len() + 1 < rest.len() {
                return Err("--dry-run is given twice.".to_string());
            }
            let flags = parse_flags(&others, &["--idle-days", "--delete-days"])?;
            let mut days = [DEFAULT_SWEEP_DAYS; 2];
            for (index, name) in ["--idle-days", "--delete-days"].iter().enumerate() {
                if let Some(text) = &flags[index] {
                    days[index] = text
                        .parse::<u64>()
                        .ok()
                        .filter(|days| (1..=MAX_SWEEP_DAYS).contains(days))
                        .ok_or_else(|| format!("{name} is a number from 1 to {MAX_SWEEP_DAYS}."))?;
                }
            }
            Ok(Operator::ConnectSweep {
                idle_days: days[0],
                delete_days: days[1],
                dry_run,
            })
        }
        other => Err(format!("Unknown admin command: {other}")),
    }
}

fn parse(args: &[String]) -> Result<Command, String> {
    let Some(first) = args.first() else {
        return Ok(Command::Serve);
    };
    match first.as_str() {
        "--version" | "-V" | "version" if args.len() == 1 => Ok(Command::Version),
        "serve" if args.len() == 1 => Ok(Command::Serve),
        "migrate" if args.len() == 1 => Ok(Command::Migrate),
        "rollback-check" if args.len() == 1 => Ok(Command::RollbackCheck),
        "downgrade-schema-6" if args.len() == 1 => Ok(Command::DowngradeSchema6),
        "downgrade-schema-7" if args.len() == 1 => Ok(Command::DowngradeSchema7),
        "downgrade-directory-1003" if args.len() == 1 => Ok(Command::DowngradeDirectory1003 {
            delete_vault_stores: false,
        }),
        "downgrade-directory-1003" if args.len() == 2 && args[1] == "--delete-vault-stores" => {
            Ok(Command::DowngradeDirectory1003 {
                delete_vault_stores: true,
            })
        }
        "downgrade-directory-1004" if args.len() == 1 => Ok(Command::DowngradeDirectory1004 {
            delete_vault_stores: false,
        }),
        "downgrade-directory-1004" if args.len() == 2 && args[1] == "--delete-vault-stores" => {
            Ok(Command::DowngradeDirectory1004 {
                delete_vault_stores: true,
            })
        }
        "downgrade-directory-1005" if args.len() == 1 => Ok(Command::DowngradeDirectory1005 {
            delete_vault_stores: false,
        }),
        "downgrade-directory-1005" if args.len() == 2 && args[1] == "--delete-vault-stores" => {
            Ok(Command::DowngradeDirectory1005 {
                delete_vault_stores: true,
            })
        }
        "snapshot-check" if args.len() == 1 => Ok(Command::SnapshotCheck),
        "backup" if args.len() == 1 => Ok(Command::Backup),
        "connect-cutover" => parse_cutover(&args[1..]),
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

/// `connect-cutover [--dry-run | --confirm-delete-teams <plan>] [--backup <folder>]`: a dry
/// run unless `--confirm-delete-teams` is given with the `plan_sha256` of the dry run.
fn parse_cutover(args: &[String]) -> Result<Command, String> {
    let mut confirm = None;
    let mut dry_run = false;
    let mut backup = None;
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--confirm-delete-teams" if confirm.is_none() => {
                let plan = rest
                    .next()
                    .filter(|plan| !plan.starts_with("--"))
                    .ok_or_else(|| {
                        "--confirm-delete-teams needs the plan_sha256 of the dry run.".to_string()
                    })?;
                confirm = Some(plan.clone());
            }
            "--dry-run" if !dry_run => dry_run = true,
            "--backup" if backup.is_none() => {
                let folder = rest
                    .next()
                    .ok_or_else(|| "--backup needs a folder.".to_string())?;
                backup = Some(PathBuf::from(folder));
            }
            "--confirm-delete-teams" | "--dry-run" | "--backup" => {
                return Err(format!("{arg} is given twice."));
            }
            other => return Err(format!("Unknown option: {other}")),
        }
    }
    if confirm.is_some() && dry_run {
        return Err("Give --dry-run or --confirm-delete-teams, not both.".to_string());
    }
    Ok(Command::ConnectCutover { confirm, backup })
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
            if matches!(command, Operator::Readiness) && result["ready"] != true
                || matches!(command, Operator::ConnectSweep { .. })
                    && result["failed"]
                        .as_array()
                        .is_some_and(|failed| !failed.is_empty())
            {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(error) => fail(&error.message),
    }
}

fn main() -> ExitCode {
    // ADR 0011 stage 6: first, before anything reads a secret.
    apassy::harden::harden_process_or_exit("apassy-relay");
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = match parse(&args) {
        Ok(command) => command,
        Err(message) => {
            eprintln!("apassy-relay: {message}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match &command {
        Command::Version => {
            println!("apassy-relay {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
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
        Command::RollbackCheck => match apassy_relay::server::rollback::check(&config) {
            Ok(teams) => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&teams).unwrap_or_default()
                );
                let unclean = teams.iter().filter(|team| !team.clean).count();
                if unclean == 0 {
                    eprintln!(
                        "apassy-relay: {} teams; a rollback undoes nothing of them but their feeds.",
                        teams.len()
                    );
                    ExitCode::SUCCESS
                } else {
                    eprintln!(
                        "apassy-relay: {unclean} of {} teams need a decision before a rollback (docs/OPERATIONS.md 21.3).",
                        teams.len()
                    );
                    ExitCode::from(1)
                }
            }
            Err(error) => fail(&error.message),
        },
        Command::DowngradeDirectory1003 {
            delete_vault_stores,
        } => {
            match apassy_relay::server::directory::Directory::downgrade_to_1003(
                &config,
                delete_vault_stores,
            ) {
                Ok((from, to)) => {
                    println!("{}", serde_json::json!({"from": from, "to": to}));
                    eprintln!(
                        "apassy-relay: relay.db is at version {to}; the image of directory 1003 can open it."
                    );
                    ExitCode::SUCCESS
                }
                Err(error) => fail(&error.message),
            }
        }
        Command::DowngradeDirectory1004 {
            delete_vault_stores,
        } => {
            match apassy_relay::server::directory::Directory::downgrade_to_1004(
                &config,
                delete_vault_stores,
            ) {
                Ok((from, to)) => {
                    println!("{}", serde_json::json!({"from": from, "to": to}));
                    eprintln!(
                        "apassy-relay: relay.db is at version {to}; the image of directory 1004 can open it."
                    );
                    ExitCode::SUCCESS
                }
                Err(error) => fail(&error.message),
            }
        }
        Command::DowngradeDirectory1005 {
            delete_vault_stores,
        } => {
            match apassy_relay::server::directory::Directory::downgrade_to_1005(
                &config,
                delete_vault_stores,
            ) {
                Ok((from, to, stores)) => {
                    println!(
                        "{}",
                        serde_json::json!({"from": from, "to": to, "vault_stores_deleted": stores})
                    );
                    eprintln!(
                        "apassy-relay: relay.db is at version {to}; the image of directory 1005 can open it."
                    );
                    ExitCode::SUCCESS
                }
                Err(error) => fail(&error.message),
            }
        }
        Command::DowngradeSchema7 => {
            match apassy_relay::server::rollback::downgrade_to_7(&config) {
                Ok(teams) => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&teams).unwrap_or_default()
                    );
                    let failed = teams.iter().filter(|team| team.error.is_some()).count();
                    if failed == 0 {
                        eprintln!(
                            "apassy-relay: {} teams are at schema 7 or below; the image of schema 7 can open them.",
                            teams.len()
                        );
                        ExitCode::SUCCESS
                    } else {
                        eprintln!(
                            "apassy-relay: {failed} of {} teams could not go back to schema 7 (docs/OPERATIONS.md 25.2).",
                            teams.len()
                        );
                        ExitCode::from(1)
                    }
                }
                Err(error) => fail(&error.message),
            }
        }
        Command::DowngradeSchema6 => {
            match apassy_relay::server::rollback::downgrade_to_6(&config) {
                Ok(teams) => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&teams).unwrap_or_default()
                    );
                    let failed = teams.iter().filter(|team| team.error.is_some()).count();
                    if failed == 0 {
                        eprintln!(
                            "apassy-relay: {} teams are at schema 6 or below; the image of schema 6 can open them.",
                            teams.len()
                        );
                        ExitCode::SUCCESS
                    } else {
                        eprintln!(
                            "apassy-relay: {failed} of {} teams could not go back to schema 6 (docs/OPERATIONS.md 23.3).",
                            teams.len()
                        );
                        ExitCode::from(1)
                    }
                }
                Err(error) => fail(&error.message),
            }
        }
        Command::Backup => {
            match apassy_relay::server::cutover::stopped_backup(&config, apassy_relay::now_unix()) {
                Ok(manifest) => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&manifest).unwrap_or_default()
                    );
                    eprintln!(
                        "apassy-relay: the stopped relay is copied to {} ({} files). The master key is not in it: keep it apart.",
                        manifest["dir"].as_str().unwrap_or_default(),
                        manifest["files"].as_array().map_or(0, Vec::len)
                    );
                    ExitCode::SUCCESS
                }
                Err(error) => fail(&error.message),
            }
        }
        Command::ConnectCutover { confirm, backup } => {
            let options = apassy_relay::server::cutover::Options {
                confirm,
                backup,
                ..Default::default()
            };
            match apassy_relay::server::cutover::run(&config, &options, apassy_relay::now_unix()) {
                Ok(report) => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&report).unwrap_or_default()
                    );
                    eprintln!(
                        "apassy-relay: {}",
                        apassy_relay::server::cutover::summary(&report)
                    );
                    ExitCode::SUCCESS
                }
                Err(error) => fail(&error.message),
            }
        }
        Command::SnapshotCheck => match apassy_relay::server::sync::verify_restored(&config) {
            Ok(teams) => {
                println!("Verified snapshots of {teams} teams.");
                ExitCode::SUCCESS
            }
            Err(error) => fail(&error.message),
        },
        Command::Serve => match Relay::start(config) {
            Ok(running) => {
                eprintln!(
                    "apassy-relay: listening on {} ({} mode)",
                    running.addr,
                    if running.hub().config.connect.plain_files() {
                        "connect"
                    } else {
                        "relay"
                    }
                );
                if running.hub().config.push.is_none() {
                    eprintln!(
                        "apassy-relay: push is off (APASSY_RELAY_PUSH_URL, APASSY_RELAY_PUSH_TOPIC, and APASSY_RELAY_PUSH_SECRET are not set): questions reach the devices by their long polls only"
                    );
                }
                match running.wait() {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(error) => fail(&error.message),
                }
            }
            Err(error) => fail(&error.message),
        },
        Command::Help | Command::Version | Command::Admin(_) => ExitCode::SUCCESS,
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
            vec!["limits", "t_abcdefgh23", "--members", "0"],
            vec!["limits", "t_abcdefgh23", "--items", "1000001"],
            vec!["limits", "t_abcdefgh23", "--agent-requests", "225"],
            vec!["limits", "t_abcdefgh23", "--sync-bytes", "1048575"],
            vec!["limits", "t_abcdefgh23", "--sync-bytes", "1"],
            vec!["limits", "t_abcdefgh23", "--sync-bytes", "268435457"],
            vec!["limits", "t_abcdefgh23", "--sync-pushes-per-hour", "0"],
            vec!["limits", "t_abcdefgh23", "--sync-transfers", "9"],
            vec!["limits", "t_abcdefgh23", "--open-questions", "1001"],
            vec!["limits", "t_abcdefgh23", "--questions-per-hour", "0"],
            vec!["limits", "t_abcdefgh23", "--question-bytes", "1048575"],
            vec!["limits", "t_abcdefgh23", "--member-open-questions", "0"],
            vec!["limits", "t_abcdefgh23", "--member-questions-per-hour", "0"],
            vec!["limits", "t_abcdefgh23", "--device-open-questions", "1001"],
            vec!["limits", "t_abcdefgh23", "--feed-bytes", "1048575"],
            vec!["limits", "t_abcdefgh23", "--feed-bytes", "67108865"],
            vec!["limits", "t_abcdefgh23", "--feed-actions-per-hour", "0"],
            vec![
                "limits",
                "t_abcdefgh23",
                "--device-questions-per-hour",
                "1000001",
            ],
            vec!["limits", "t_abcdefgh23", "--items", "1", "--items", "2"],
            vec!["limits", "t_abcdefgh23", "--unknown", "1"],
            vec!["limits", "t_abcdefgh23", "t_bcdefgh234"],
        ] {
            assert!(parse_admin(&args(&values)).is_err(), "{values:?}");
        }
    }

    #[test]
    fn limits_command_accepts_zero_items_agents_and_sync_bytes() {
        assert_eq!(
            parse_admin(&args(&[
                "limits",
                "t_abcdefgh23",
                "--items",
                "0",
                "--agents",
                "0",
                "--sync-bytes",
                "0",
            ]))
            .unwrap(),
            Operator::Limits {
                team: TeamId::parse("t_abcdefgh23").unwrap(),
                set: Some(TeamLimitsUpdate {
                    items: Some(0),
                    agents: Some(0),
                    sync_bytes: Some(0),
                    ..Default::default()
                }),
            }
        );
    }

    #[test]
    fn connect_sweep_command() {
        assert_eq!(
            parse_admin(&args(&["connect-sweep"])).unwrap(),
            Operator::ConnectSweep {
                idle_days: 30,
                delete_days: 30,
                dry_run: true
            }
        );
        assert_eq!(
            parse_admin(&args(&[
                "connect-sweep",
                "--dry-run",
                "--idle-days",
                "45",
                "--delete-days",
                "7",
            ]))
            .unwrap(),
            Operator::ConnectSweep {
                idle_days: 45,
                delete_days: 7,
                dry_run: true
            }
        );
        for values in [
            vec!["connect-sweep", "--idle-days", "0"],
            vec!["connect-sweep", "--delete-days", "3651"],
            vec!["connect-sweep", "--idle-days"],
            vec!["connect-sweep", "--dry-run", "--dry-run"],
            vec!["connect-sweep", "--force"],
            vec!["connect-sweep", "t_abcdefgh23"],
        ] {
            assert!(parse_admin(&args(&values)).is_err(), "{values:?}");
        }
    }

    #[test]
    fn delete_and_rollback_check_commands() {
        let team = TeamId::parse("t_abcdefgh23").unwrap();
        for (words, free_connect_key) in [
            (vec!["delete", "t_abcdefgh23"], false),
            (vec!["delete", "t_abcdefgh23", "--free-connect-key"], true),
            (vec!["delete", "--free-connect-key", "t_abcdefgh23"], true),
        ] {
            assert_eq!(
                parse_admin(&args(&words)).unwrap(),
                Operator::Delete {
                    team: team.clone(),
                    free_connect_key
                },
                "{words:?}"
            );
        }
        assert!(matches!(
            parse(&args(&["rollback-check"])).unwrap(),
            Command::RollbackCheck
        ));
        assert!(parse(&args(&["rollback-check", "t_abcdefgh23"])).is_err());
        assert!(matches!(
            parse(&args(&["downgrade-schema-6"])).unwrap(),
            Command::DowngradeSchema6
        ));
        assert!(parse(&args(&["downgrade-schema-6", "--now"])).is_err());
        assert!(matches!(
            parse(&args(&["downgrade-directory-1003"])).unwrap(),
            Command::DowngradeDirectory1003 {
                delete_vault_stores: false
            }
        ));
        assert!(matches!(
            parse(&args(&[
                "downgrade-directory-1003",
                "--delete-vault-stores"
            ]))
            .unwrap(),
            Command::DowngradeDirectory1003 {
                delete_vault_stores: true
            }
        ));
        assert!(parse(&args(&["downgrade-directory-1003", "--now"])).is_err());
        assert!(matches!(
            parse(&args(&["downgrade-schema-7"])).unwrap(),
            Command::DowngradeSchema7
        ));
        assert!(parse(&args(&["downgrade-schema-7", "--now"])).is_err());
        assert!(matches!(
            parse(&args(&["downgrade-directory-1004"])).unwrap(),
            Command::DowngradeDirectory1004 {
                delete_vault_stores: false
            }
        ));
        assert!(matches!(
            parse(&args(&[
                "downgrade-directory-1004",
                "--delete-vault-stores"
            ]))
            .unwrap(),
            Command::DowngradeDirectory1004 {
                delete_vault_stores: true
            }
        ));
        assert!(parse(&args(&["downgrade-directory-1004", "--now"])).is_err());
        assert!(matches!(
            parse(&args(&["downgrade-directory-1005"])).unwrap(),
            Command::DowngradeDirectory1005 {
                delete_vault_stores: false
            }
        ));
        assert!(matches!(
            parse(&args(&[
                "downgrade-directory-1005",
                "--delete-vault-stores"
            ]))
            .unwrap(),
            Command::DowngradeDirectory1005 {
                delete_vault_stores: true
            }
        ));
        assert!(parse(&args(&["downgrade-directory-1005", "--now"])).is_err());
        assert_eq!(
            parse_admin(&args(&["node-code"])).unwrap(),
            Operator::NodeCode { minutes: 10 }
        );
        assert_eq!(
            parse_admin(&args(&["node-code", "--minutes", "3"])).unwrap(),
            Operator::NodeCode { minutes: 3 }
        );
        assert!(parse_admin(&args(&["node-code", "--minutes", "x"])).is_err());
        assert!(parse_admin(&args(&["rollback-check"])).is_err());
        for values in [
            vec!["delete"],
            vec!["delete", "--free-connect-key"],
            vec![
                "delete",
                "t_abcdefgh23",
                "--free-connect-key",
                "--free-connect-key",
            ],
            vec!["delete", "t_abcdefgh23", "--force"],
        ] {
            assert!(parse_admin(&args(&values)).is_err(), "{values:?}");
        }
    }

    #[test]
    fn cutover_and_backup_commands() {
        let plan = "ab".repeat(32);
        let given = |value: &str| Some(value.to_string());
        for (words, confirm, backup) in [
            (vec!["connect-cutover"], None, None),
            (vec!["connect-cutover", "--dry-run"], None, None),
            (
                vec!["connect-cutover", "--confirm-delete-teams", plan.as_str()],
                given(&plan),
                None,
            ),
            (
                vec![
                    "connect-cutover",
                    "--backup",
                    "/backups/x",
                    "--confirm-delete-teams",
                    plan.as_str(),
                ],
                given(&plan),
                Some(PathBuf::from("/backups/x")),
            ),
        ] {
            match parse(&args(&words)).unwrap() {
                Command::ConnectCutover {
                    confirm: got,
                    backup: folder,
                } => assert_eq!((got, folder), (confirm, backup), "{words:?}"),
                _ => panic!("{words:?}"),
            }
        }
        for words in [
            vec![
                "connect-cutover",
                "--dry-run",
                "--confirm-delete-teams",
                plan.as_str(),
            ],
            // The plan of the dry run is required.
            vec!["connect-cutover", "--confirm-delete-teams"],
            vec!["connect-cutover", "--confirm-delete-teams", "--dry-run"],
            vec![
                "connect-cutover",
                "--confirm-delete-teams",
                plan.as_str(),
                "--confirm-delete-teams",
                plan.as_str(),
            ],
            vec!["connect-cutover", "--backup"],
            vec!["connect-cutover", "--force"],
            vec!["connect-cutover", "--yes"],
            vec!["backup", "--now"],
        ] {
            assert!(parse(&args(&words)).is_err(), "{words:?}");
        }
        assert!(matches!(
            parse(&args(&["backup"])).unwrap(),
            Command::Backup
        ));
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
                "--question-bytes",
                "1048576",
                "--member-open-questions",
                "13",
                "--member-questions-per-hour",
                "14",
                "--device-open-questions",
                "15",
                "--device-questions-per-hour",
                "16",
                "--feed-bytes",
                "1048576",
                "--feed-actions-per-hour",
                "18",
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
                    question_bytes: Some(1_048_576),
                    member_open_questions: Some(13),
                    member_questions_per_hour: Some(14),
                    device_open_questions: Some(15),
                    device_questions_per_hour: Some(16),
                    feed_bytes: Some(1_048_576),
                    feed_actions_per_hour: Some(18),
                }),
            }
        );
    }
}
