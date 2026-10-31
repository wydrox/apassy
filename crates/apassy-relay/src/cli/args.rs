//! The hand-written argument parser: `parse` turns the words after the program name into a `Command`.
//!
//! Options are long (`--name value` or `--name=value`). A word that starts with `-`
//! and is not a known option is a usage error. `run` takes everything after `--` as the command.

use crate::api::{Policy, PolicyMode, Role};
use crate::cli::CliError;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyFlags {
    pub mode: Option<PolicyMode>,
    pub allow_prefixes: Vec<String>,
    pub forbidden: Vec<String>,
    pub max_runs_per_hour: Option<u32>,
    pub instruction: Option<String>,
    pub expires_at: Option<u64>,
}

impl PolicyFlags {
    pub fn into_policy(self) -> Policy {
        let mut policy = Policy::default();
        if let Some(mode) = self.mode {
            policy.mode = mode;
        }
        policy.rule.allowed_prefixes = self.allow_prefixes;
        policy.rule.forbidden_words = self.forbidden;
        policy.rule.max_runs_per_hour = self.max_runs_per_hour;
        policy.rule.expires_at = self.expires_at;
        if let Some(text) = self.instruction {
            policy.rule.instruction = text;
        }
        policy
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemAddArgs {
    pub collection: u64,
    pub name: String,
    pub env_name: String,
    pub environment: String,
    pub provider: Option<String>,
    pub hosts: Vec<String>,
    pub risk: Option<String>,
    pub scope: Option<String>,
    pub reversibility: Option<String>,
    /// Allow a host that is a public suffix or a whole domain.
    pub allow_broad_host: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunArgs {
    pub items: Vec<u64>,
    pub purpose: String,
    pub request: Option<String>,
    pub ttl: Option<u64>,
    /// The most seconds to wait for an approver.
    pub wait: Option<u64>,
    pub cwd: Option<String>,
    pub command: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Selected {
        team: String,
        command: Box<Command>,
    },
    Help,
    Version,
    Init {
        relay: String,
    },
    Create {
        relay: String,
        team: String,
        name: String,
        device: Option<String>,
    },
    Join {
        relay: Option<String>,
        name: Option<String>,
        device: Option<String>,
        no_wait: bool,
        resume: bool,
    },
    Me {
        json: bool,
    },
    Invite {
        role: Role,
        hours: Option<u32>,
        name: Option<String>,
        grants: Vec<u64>,
        shared: bool,
    },
    Invites {
        json: bool,
    },
    Members {
        json: bool,
    },
    MemberRevoke {
        id: u64,
    },
    MemberRole {
        id: u64,
        role: Role,
    },
    DeviceEnroll {
        name: Option<String>,
    },
    DeviceList {
        json: bool,
    },
    DeviceRevoke {
        id: u64,
    },
    DeviceKeyHolder {
        id: u64,
    },
    DeviceAdd,
    DeviceLink {
        relay: Option<String>,
        device: Option<String>,
        no_wait: bool,
        resume: bool,
    },
    DevicePending {
        json: bool,
    },
    DeviceConfirm {
        id: u64,
        words: String,
    },
    DeviceRefuse {
        id: u64,
    },
    Joins {
        json: bool,
    },
    Confirm {
        id: u64,
        words: String,
    },
    Refuse {
        id: u64,
    },
    Leave,
    TeamList {
        json: bool,
    },
    TeamUse {
        id: String,
    },
    CollectionCreate {
        name: String,
        policy: PolicyFlags,
    },
    CollectionList {
        json: bool,
    },
    CollectionPolicy {
        id: u64,
        policy: PolicyFlags,
    },
    ItemAdd(ItemAddArgs),
    ItemList {
        collection: Option<u64>,
        json: bool,
    },
    ItemArchive {
        id: u64,
    },
    Grant {
        collection: u64,
        member: u64,
    },
    Grants {
        json: bool,
    },
    GrantRevoke {
        id: u64,
    },
    AgentCreate {
        name: String,
        days: Option<u32>,
    },
    AgentList {
        json: bool,
    },
    AgentRevoke {
        id: u64,
    },
    Pending {
        json: bool,
    },
    Approve {
        run: u64,
        reason: Option<String>,
    },
    Deny {
        run: u64,
        reason: Option<String>,
    },
    Audit {
        after: Option<u64>,
        limit: Option<u32>,
        json: bool,
    },
    Access {
        json: bool,
    },
    Run(RunArgs),
    Mcp,
    /// The owner's host: holds the item keys, releases them run by run.
    Host {
        ask_all: bool,
        auto_limit: Option<u32>,
        dialog: bool,
    },
    HostInstall {
        ask_all: bool,
        auto_limit: Option<u32>,
    },
    HostUninstall,
    HostStatus,
}

/// The options found in one command line.
struct Scan {
    values: Vec<(String, String)>,
    switches: Vec<String>,
    positional: Vec<String>,
}

fn scan(args: &[String], value_opts: &[&str], switches: &[&str]) -> Result<Scan, CliError> {
    let mut out = Scan {
        values: Vec::new(),
        switches: Vec::new(),
        positional: Vec::new(),
    };
    let mut iter = args.iter();
    while let Some(word) = iter.next() {
        let Some(long) = word.strip_prefix("--") else {
            if word.len() > 1 && word.starts_with('-') {
                return Err(CliError::usage(format!("Unknown option {word}.")));
            }
            out.positional.push(word.clone());
            continue;
        };
        if long.is_empty() {
            return Err(CliError::usage(
                "Unexpected `--`. Only `run` takes a command after it.",
            ));
        }
        let (name, inline) = match long.split_once('=') {
            Some((name, value)) => (name, Some(value.to_owned())),
            None => (long, None),
        };
        if switches.contains(&name) {
            if inline.is_some() {
                return Err(CliError::usage(format!("Option --{name} takes no value.")));
            }
            out.switches.push(name.to_owned());
        } else if value_opts.contains(&name) {
            let value = match inline {
                Some(value) => value,
                None => {
                    let value = iter.next().cloned().ok_or_else(|| {
                        CliError::usage(format!("Option --{name} needs a value."))
                    })?;
                    if value.starts_with("--") {
                        return Err(CliError::usage(format!("Option --{name} needs a value.")));
                    }
                    value
                }
            };
            out.values.push((name.to_owned(), value));
        } else {
            return Err(CliError::usage(format!("Unknown option --{name}.")));
        }
    }
    Ok(out)
}

impl Scan {
    fn many(&self, name: &str) -> Vec<String> {
        self.values
            .iter()
            .filter(|(n, _)| n == name)
            .map(|(_, v)| v.clone())
            .collect()
    }

    fn one(&self, name: &str) -> Result<Option<String>, CliError> {
        let mut all = self.many(name);
        if all.len() > 1 {
            return Err(CliError::usage(format!("Option --{name} is given twice.")));
        }
        Ok(all.pop())
    }

    fn required(&self, name: &str) -> Result<String, CliError> {
        self.one(name)?
            .ok_or_else(|| CliError::usage(format!("Option --{name} is required.")))
    }

    fn num<T: std::str::FromStr>(&self, name: &str) -> Result<Option<T>, CliError> {
        self.one(name)?
            .map(|text| parse_num(name, &text))
            .transpose()
    }

    fn json(&self) -> bool {
        self.switch("json")
    }

    fn switch(&self, name: &str) -> bool {
        self.switches.iter().any(|s| s == name)
    }

    /// Exactly `count` positional words.
    fn positional(&self, count: usize, usage: &str) -> Result<&[String], CliError> {
        if self.positional.len() != count {
            return Err(CliError::usage(format!("Usage: apassy-team {usage}")));
        }
        Ok(&self.positional)
    }
}

fn parse_num<T: std::str::FromStr>(what: &str, text: &str) -> Result<T, CliError> {
    text.parse::<T>()
        .map_err(|_| CliError::usage(format!("{what} must be a whole number, not `{text}`.")))
}

fn parse_id(what: &str, text: &str) -> Result<u64, CliError> {
    match text.parse::<u64>() {
        Ok(n) if n > 0 => Ok(n),
        _ => Err(CliError::usage(format!(
            "{what} must be a positive whole number, not `{text}`."
        ))),
    }
}

fn policy_flags(scan: &Scan) -> Result<PolicyFlags, CliError> {
    let mode = match scan.one("mode")?.as_deref() {
        None => None,
        Some("ask") => Some(PolicyMode::Ask),
        Some("bouncer") => Some(PolicyMode::Bouncer),
        Some(other) => {
            return Err(CliError::usage(format!(
                "--mode must be ask or bouncer, not `{other}`."
            )));
        }
    };
    Ok(PolicyFlags {
        mode,
        allow_prefixes: scan.many("allow-prefix"),
        forbidden: scan.many("forbid"),
        max_runs_per_hour: scan.num("max-runs-per-hour")?,
        instruction: scan.one("instruction")?,
        expires_at: scan.num("rule-expires-at")?,
    })
}

const POLICY_OPTS: [&str; 6] = [
    "mode",
    "allow-prefix",
    "forbid",
    "max-runs-per-hour",
    "instruction",
    "rule-expires-at",
];

pub const USAGE: &str = "\
apassy-team: the CLI of the Apassy team relay

Setup
  create --relay URL --team NAME --name NAME [--device NAME]
                                read a team code of the operator from stdin, make a new
                                team with you as its owner, save settings
  join --relay URL [--name NAME] [--device NAME] [--no-wait]
                                read an invite code or link from stdin, wait for confirmation
  join --resume                wait for a previous join
  me                            who am I

Team (owner or manager)
  invite [--role member|manager|owner] [--hours N] [--name NAME]
         [--grant ID]... [--shared]   print a one-time invite link
  invites | joins | confirm ID --words \"W1 W2\" | refuse ID
  members | member revoke ID | member role ID ROLE
  leave | team list | team use ID
  collection create NAME [policy flags] | collection list | collection policy ID [policy flags]
      policy flags: --mode ask|bouncer  --allow-prefix P  --forbid WORD
                    --max-runs-per-hour N  --instruction TEXT  --rule-expires-at UNIX
  item add --collection ID --name NAME --env ENV_NAME --environment ENV
           [--provider P] [--host H]... [--risk R] [--scope S] [--reversibility R]
           [--allow-broad-host]
           (the value comes from stdin and is sealed here; its key goes to keys.json on
            this machine and never to the relay; a host covers its subdomains too)
  item list [--collection ID] | item archive ID
  grant --collection ID --member ID | grants | revoke --grant ID
  pending | deny RUN_ID [--reason TEXT]
  audit [--after ID] [--limit N] [--json]

Devices
  device enroll [--name NAME]   change from a member token to a device key
  device list | device revoke ID | device key-holder ID
  device add                   print a one-time link code
  device link --relay URL [--device NAME] [--no-wait]
                                read a link code from stdin, wait for confirmation
  device link --resume          wait for a previous link
  device pending | device confirm ID --words \"W1 W2\" | device refuse ID

Owner's machine (the key-holder device; keys.json lives here, back it up)
  host [--ask-all] [--auto-limit N] [--dialog]
      keep the item keys and decide each run. A known safe run with a non-production
      item starts at once (at most N per item per hour, default 30). Other runs need
      approval on the terminal or in a desktop dialog (--dialog).
  host install [--ask-all] [--auto-limit N]
      install and start the user service with desktop dialogs at login
  host uninstall                stop and remove the user service
  host status                   show the user service status
      --ask-all asks for each run. The host must be online for any run to start.

Members
  agent create NAME [--days N]  print an agent token once
  agent list | agent revoke ID

Agents (APASSY_TOKEN)
  access                        list the items I may use
  run --items 1,2 --purpose TEXT [--request TEXT] [--ttl SECS] [--wait SECS]
      [--cwd DIR] -- CMD ARGS...   ask for a run, then run the command
  mcp                           stdio MCP adapter

Compatibility (legacy relays only)
  init --relay URL              import a legacy member token; current setup uses create/join
  approve RUN_ID                unavailable: the key-holder `host` decides runs
  Existing device recovery: device link --resume or device enroll to check saved enrollment

Finite commands take --json before the child delimiter: one success/error envelope on stdout,
progress on stderr. Lists and mutations use the same envelope. One-time secrets appear once.
For run --json, child output goes to stderr and its exit code is preserved.
MCP and foreground host use streaming protocols and cannot be wrapped with --json.
Member commands take --team ID.
Environment: APASSY_RELAY_URL, APASSY_TEAM, APASSY_TEAM_TOKEN, APASSY_TOKEN, APASSY_EDGE_SECRET.
Secrets are read from stdin, never from arguments.
Exit codes: 0 ok (or the child's code), 2 usage, 3 run denied or timed out, 4 relay or network error.
";

pub fn parse(args: &[String]) -> Result<Command, CliError> {
    // Create uses --team as the new team's name, not as an existing team selector.
    if args.first().is_some_and(|name| name == "create") {
        return parse_command(args);
    }
    let mut command_args = Vec::new();
    let mut team = None;
    let mut iter = args.iter();
    while let Some(word) = iter.next() {
        if word == "--" {
            command_args.push(word.clone());
            command_args.extend(iter.cloned());
            break;
        }
        let selection = if word == "--team" {
            Some(
                iter.next()
                    .cloned()
                    .ok_or_else(|| CliError::usage("Option --team needs a value."))?,
            )
        } else {
            word.strip_prefix("--team=").map(str::to_owned)
        };
        if let Some(selection) = selection {
            if team.is_some() {
                return Err(CliError::usage("Option --team is given twice."));
            }
            if selection.trim().is_empty() || selection.starts_with('-') {
                return Err(CliError::usage("Option --team needs a team ID."));
            }
            team = Some(selection);
        } else {
            command_args.push(word.clone());
        }
    }
    let command = parse_command(&command_args)?;
    let Some(team) = team else {
        return Ok(command);
    };
    if matches!(
        command,
        Command::Help
            | Command::Version
            | Command::Init { .. }
            | Command::Create { .. }
            | Command::Join { resume: false, .. }
            | Command::DeviceLink { resume: false, .. }
            | Command::TeamList { .. }
            | Command::TeamUse { .. }
            | Command::Access { .. }
            | Command::Run(_)
            | Command::Mcp
    ) {
        return Err(CliError::usage(
            "Option --team selects a team for a member command.",
        ));
    }
    Ok(Command::Selected {
        team,
        command: Box::new(command),
    })
}

fn parse_command(args: &[String]) -> Result<Command, CliError> {
    let Some(name) = args.first() else {
        return Err(CliError::usage("No command."));
    };
    let rest = &args[1..];
    match name.as_str() {
        "help" | "--help" | "-h" => Ok(Command::Help),
        "--version" | "-V" | "version" => Ok(Command::Version),
        "init" => {
            let s = scan(rest, &["relay"], &[])?;
            s.positional(0, "init --relay URL")?;
            Ok(Command::Init {
                relay: s.required("relay")?,
            })
        }
        "create" => {
            let s = scan(rest, &["relay", "team", "name", "device"], &[])?;
            s.positional(0, "create --relay URL --team NAME --name NAME")?;
            Ok(Command::Create {
                relay: s.required("relay")?,
                team: s.required("team")?,
                name: s.required("name")?,
                device: s.one("device")?,
            })
        }
        "join" => {
            let s = scan(rest, &["relay", "name", "device"], &["no-wait", "resume"])?;
            s.positional(
                0,
                "join --relay URL [--name NAME] [--device NAME] [--no-wait] | join --resume",
            )?;
            let (relay, device, resume) = enrollment_options(&s)?;
            let name = s.one("name")?;
            if resume && name.is_some() {
                return Err(CliError::usage(
                    "Option --name cannot be used with --resume.",
                ));
            }
            Ok(Command::Join {
                relay,
                name,
                device,
                no_wait: s.switch("no-wait"),
                resume,
            })
        }
        "me" => no_args(rest).map(|json| Command::Me { json }),
        "invite" => {
            let s = scan(rest, &["role", "hours", "name", "grant"], &["shared"])?;
            s.positional(0, "invite [--role member|manager|owner] [--hours N] [--name NAME] [--grant ID]... [--shared]")?;
            let role = parse_role(s.one("role")?.as_deref().unwrap_or("member"))?;
            if s.switch("shared") && role != Role::Member {
                return Err(CliError::usage("Option --shared needs role member."));
            }
            let mut grants = Vec::new();
            for value in s.many("grant") {
                for entry in value.split(',') {
                    let id = parse_id("--grant entry", entry.trim())?;
                    if grants.contains(&id) {
                        return Err(CliError::usage("Option --grant has a repeated ID."));
                    }
                    grants.push(id);
                }
            }
            Ok(Command::Invite {
                role,
                hours: s.num("hours")?,
                name: s.one("name")?,
                grants,
                shared: s.switch("shared"),
            })
        }
        "invites" => no_args(rest).map(|json| Command::Invites { json }),
        "members" => no_args(rest).map(|json| Command::Members { json }),
        "member" => match rest.first().map(String::as_str) {
            Some("revoke") => {
                let s = scan(&rest[1..], &[], &[])?;
                let words = s.positional(1, "member revoke ID")?;
                Ok(Command::MemberRevoke {
                    id: parse_id("ID", &words[0])?,
                })
            }
            Some("role") => {
                let s = scan(&rest[1..], &[], &[])?;
                let words = s.positional(2, "member role ID ROLE")?;
                Ok(Command::MemberRole {
                    id: parse_id("ID", &words[0])?,
                    role: parse_role(&words[1])?,
                })
            }
            _ => Err(CliError::usage(
                "Usage: apassy-team member revoke ID | member role ID ROLE",
            )),
        },
        "device" => device(rest),
        "team" => team(rest),
        "joins" => no_args(rest).map(|json| Command::Joins { json }),
        "confirm" => {
            let (id, words) = confirmation(rest, "confirm ID --words \"W1 W2\"")?;
            Ok(Command::Confirm { id, words })
        }
        "refuse" => Ok(Command::Refuse {
            id: id_argument(rest, "refuse ID")?,
        }),
        "leave" => {
            scan(rest, &[], &[])?.positional(0, "leave")?;
            Ok(Command::Leave)
        }
        "collection" => collection(rest),
        "item" => item(rest),
        "grant" => {
            let s = scan(rest, &["collection", "member"], &[])?;
            s.positional(0, "grant --collection ID --member ID")?;
            Ok(Command::Grant {
                collection: parse_id("--collection", &s.required("collection")?)?,
                member: parse_id("--member", &s.required("member")?)?,
            })
        }
        "grants" => no_args(rest).map(|json| Command::Grants { json }),
        "revoke" => {
            let s = scan(rest, &["grant"], &[])?;
            s.positional(0, "revoke --grant ID")?;
            Ok(Command::GrantRevoke {
                id: parse_id("--grant", &s.required("grant")?)?,
            })
        }
        "agent" => agent(rest),
        "pending" => no_args(rest).map(|json| Command::Pending { json }),
        "approve" | "deny" => {
            let s = scan(rest, &["reason"], &[])?;
            let words = s.positional(1, &format!("{name} RUN_ID [--reason TEXT]"))?;
            let run = parse_id("RUN_ID", &words[0])?;
            let reason = s.one("reason")?;
            Ok(if name == "approve" {
                Command::Approve { run, reason }
            } else {
                Command::Deny { run, reason }
            })
        }
        "audit" => {
            let s = scan(rest, &["after", "limit"], &["json"])?;
            s.positional(0, "audit [--after ID] [--limit N] [--json]")?;
            Ok(Command::Audit {
                after: s.num("after")?,
                limit: s.num("limit")?,
                json: s.json(),
            })
        }
        "access" => no_args(rest).map(|json| Command::Access { json }),
        "run" => run(rest),
        "mcp" => {
            scan(rest, &[], &[])?.positional(0, "mcp")?;
            Ok(Command::Mcp)
        }
        "host" => host(rest),
        other => Err(CliError::usage(format!("Unknown command `{other}`."))),
    }
}

fn parse_role(value: &str) -> Result<Role, CliError> {
    match value {
        "owner" => Ok(Role::Owner),
        "manager" => Ok(Role::Manager),
        "member" => Ok(Role::Member),
        _ => Err(CliError::usage(format!(
            "Role must be member, manager, or owner, not `{value}`."
        ))),
    }
}

fn enrollment_options(s: &Scan) -> Result<(Option<String>, Option<String>, bool), CliError> {
    let resume = s.switch("resume");
    let relay = s.one("relay")?;
    let device = s.one("device")?;
    if resume {
        if relay.is_some() || device.is_some() {
            return Err(CliError::usage(
                "Options --relay and --device cannot be used with --resume.",
            ));
        }
    } else if relay.is_none() {
        return Err(CliError::usage("Option --relay is required."));
    }
    Ok((relay, device, resume))
}

fn id_argument(rest: &[String], usage: &str) -> Result<u64, CliError> {
    let s = scan(rest, &[], &[])?;
    let words = s.positional(1, usage)?;
    parse_id("ID", &words[0])
}

fn confirmation(rest: &[String], usage: &str) -> Result<(u64, String), CliError> {
    let s = scan(rest, &["words"], &[])?;
    let ids = s.positional(1, usage)?;
    let id = parse_id("ID", &ids[0])?;
    let words = s.required("words")?;
    if words.split_whitespace().count() != 2 {
        return Err(CliError::usage("Option --words needs two safety words."));
    }
    Ok((id, words))
}

fn device(rest: &[String]) -> Result<Command, CliError> {
    let tail = rest.get(1..).unwrap_or_default();
    match rest.first().map(String::as_str) {
        Some("enroll") => {
            let s = scan(tail, &["name"], &[])?;
            s.positional(0, "device enroll [--name NAME]")?;
            Ok(Command::DeviceEnroll {
                name: s.one("name")?,
            })
        }
        Some("list") => Ok(Command::DeviceList {
            json: no_args(tail)?,
        }),
        Some("revoke") => Ok(Command::DeviceRevoke {
            id: id_argument(tail, "device revoke ID")?,
        }),
        Some("key-holder") => Ok(Command::DeviceKeyHolder {
            id: id_argument(tail, "device key-holder ID")?,
        }),
        Some("add") => {
            scan(tail, &[], &[])?.positional(0, "device add")?;
            Ok(Command::DeviceAdd)
        }
        Some("link") => {
            let s = scan(tail, &["relay", "device"], &["no-wait", "resume"])?;
            s.positional(
                0,
                "device link --relay URL [--device NAME] [--no-wait] | device link --resume",
            )?;
            let (relay, device, resume) = enrollment_options(&s)?;
            Ok(Command::DeviceLink {
                relay,
                device,
                resume,
                no_wait: s.switch("no-wait"),
            })
        }
        Some("pending") => Ok(Command::DevicePending {
            json: no_args(tail)?,
        }),
        Some("confirm") => {
            let (id, words) = confirmation(tail, "device confirm ID --words \"W1 W2\"")?;
            Ok(Command::DeviceConfirm { id, words })
        }
        Some("refuse") => Ok(Command::DeviceRefuse {
            id: id_argument(tail, "device refuse ID")?,
        }),
        _ => Err(CliError::usage(
            "Usage: apassy-team device enroll|list|revoke|key-holder|add|link|pending|confirm|refuse ...",
        )),
    }
}

fn team(rest: &[String]) -> Result<Command, CliError> {
    match rest.first().map(String::as_str) {
        Some("list") => Ok(Command::TeamList {
            json: no_args(&rest[1..])?,
        }),
        Some("use") => {
            let s = scan(&rest[1..], &[], &[])?;
            let words = s.positional(1, "team use ID")?;
            if words[0].trim().is_empty() {
                return Err(CliError::usage("Team ID must not be empty."));
            }
            Ok(Command::TeamUse {
                id: words[0].clone(),
            })
        }
        _ => Err(CliError::usage(
            "Usage: apassy-team team list | team use ID",
        )),
    }
}

fn host(rest: &[String]) -> Result<Command, CliError> {
    match rest.first().map(String::as_str) {
        Some("install") => {
            let s = scan(&rest[1..], &["auto-limit"], &["ask-all"])?;
            s.positional(0, "host install [--ask-all] [--auto-limit N]")?;
            Ok(Command::HostInstall {
                ask_all: s.switch("ask-all"),
                auto_limit: s.num("auto-limit")?,
            })
        }
        Some("uninstall") | Some("status") => {
            let action = rest[0].as_str();
            scan(&rest[1..], &[], &[])?.positional(0, &format!("host {action}"))?;
            Ok(if action == "uninstall" {
                Command::HostUninstall
            } else {
                Command::HostStatus
            })
        }
        _ => {
            let s = scan(rest, &["auto-limit"], &["ask-all", "dialog"])?;
            s.positional(0, "host [--dialog] [--ask-all] [--auto-limit N]")?;
            Ok(Command::Host {
                ask_all: s.switch("ask-all"),
                auto_limit: s.num("auto-limit")?,
                dialog: s.switch("dialog"),
            })
        }
    }
}

/// A command with no words, only `--json`.
fn no_args(rest: &[String]) -> Result<bool, CliError> {
    let s = scan(rest, &[], &["json"])?;
    s.positional(0, "COMMAND [--json]")?;
    Ok(s.json())
}

fn collection(rest: &[String]) -> Result<Command, CliError> {
    match rest.first().map(String::as_str) {
        Some("create") => {
            let s = scan(&rest[1..], &POLICY_OPTS, &[])?;
            let words = s.positional(1, "collection create NAME [policy flags]")?;
            Ok(Command::CollectionCreate {
                name: words[0].clone(),
                policy: policy_flags(&s)?,
            })
        }
        Some("list") => Ok(Command::CollectionList {
            json: no_args(&rest[1..])?,
        }),
        Some("policy") => {
            let s = scan(&rest[1..], &POLICY_OPTS, &[])?;
            let words = s.positional(1, "collection policy ID [policy flags]")?;
            Ok(Command::CollectionPolicy {
                id: parse_id("ID", &words[0])?,
                policy: policy_flags(&s)?,
            })
        }
        _ => Err(CliError::usage(
            "Usage: apassy-team collection create|list|policy ...",
        )),
    }
}

fn item(rest: &[String]) -> Result<Command, CliError> {
    match rest.first().map(String::as_str) {
        Some("add") => {
            let s = scan(
                &rest[1..],
                &[
                    "collection",
                    "name",
                    "env",
                    "environment",
                    "provider",
                    "host",
                    "risk",
                    "scope",
                    "reversibility",
                ],
                &["allow-broad-host"],
            )?;
            s.positional(
                0,
                "item add --collection ID --name NAME --env ENV_NAME --environment ENV",
            )?;
            Ok(Command::ItemAdd(ItemAddArgs {
                collection: parse_id("--collection", &s.required("collection")?)?,
                name: s.required("name")?,
                env_name: s.required("env")?,
                environment: s.required("environment")?,
                provider: s.one("provider")?,
                hosts: s.many("host"),
                risk: s.one("risk")?,
                scope: s.one("scope")?,
                reversibility: s.one("reversibility")?,
                allow_broad_host: s.switch("allow-broad-host"),
            }))
        }
        Some("list") => {
            let s = scan(&rest[1..], &["collection"], &["json"])?;
            s.positional(0, "item list [--collection ID]")?;
            let collection = s
                .one("collection")?
                .map(|t| parse_id("--collection", &t))
                .transpose()?;
            Ok(Command::ItemList {
                collection,
                json: s.json(),
            })
        }
        Some("archive") => {
            let s = scan(&rest[1..], &[], &[])?;
            let words = s.positional(1, "item archive ID")?;
            Ok(Command::ItemArchive {
                id: parse_id("ID", &words[0])?,
            })
        }
        _ => Err(CliError::usage(
            "Usage: apassy-team item add|list|archive ...",
        )),
    }
}

fn agent(rest: &[String]) -> Result<Command, CliError> {
    match rest.first().map(String::as_str) {
        Some("create") => {
            let s = scan(&rest[1..], &["days"], &[])?;
            let words = s.positional(1, "agent create NAME [--days N]")?;
            Ok(Command::AgentCreate {
                name: words[0].clone(),
                days: s.num("days")?,
            })
        }
        Some("list") => Ok(Command::AgentList {
            json: no_args(&rest[1..])?,
        }),
        Some("revoke") => {
            let s = scan(&rest[1..], &[], &[])?;
            let words = s.positional(1, "agent revoke ID")?;
            Ok(Command::AgentRevoke {
                id: parse_id("ID", &words[0])?,
            })
        }
        _ => Err(CliError::usage(
            "Usage: apassy-team agent create|list|revoke ...",
        )),
    }
}

fn run(rest: &[String]) -> Result<Command, CliError> {
    let usage = "run --items 1,2 --purpose TEXT [--request TEXT] [--ttl SECS] [--wait SECS] [--cwd DIR] -- CMD ARGS...";
    let Some(split) = rest.iter().position(|w| w == "--") else {
        return Err(CliError::usage(format!("Usage: apassy-team {usage}")));
    };
    let command = rest[split + 1..].to_vec();
    if command.is_empty() {
        return Err(CliError::usage("Give the command after `--`."));
    }
    let s = scan(
        &rest[..split],
        &["items", "purpose", "request", "ttl", "wait", "cwd"],
        &[],
    )?;
    s.positional(0, usage)?;
    let mut items = Vec::new();
    for part in s.required("items")?.split(',') {
        let id = parse_id("--items entry", part.trim())?;
        if items.contains(&id) {
            return Err(CliError::usage("--items has a repeated id."));
        }
        items.push(id);
    }
    let purpose = s.required("purpose")?;
    if purpose.trim().is_empty() {
        return Err(CliError::usage("--purpose must not be empty."));
    }
    Ok(Command::Run(RunArgs {
        items,
        purpose,
        request: s.one("request")?,
        ttl: s.num("ttl")?,
        wait: s.num("wait")?,
        cwd: s.one("cwd")?,
        command,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(line: &str) -> Result<Command, CliError> {
        let words: Vec<String> = line.split_whitespace().map(str::to_owned).collect();
        parse(&words)
    }

    #[test]
    fn every_command_parses() {
        assert_eq!(
            p("init --relay https://r.example").unwrap(),
            Command::Init {
                relay: "https://r.example".into()
            }
        );
        assert_eq!(
            p("create --relay https://r.example --team Family --name rafal").unwrap(),
            Command::Create {
                relay: "https://r.example".into(),
                team: "Family".into(),
                name: "rafal".into(),
                device: None
            }
        );
        assert_eq!(
            p("join --relay=https://r.example --name bob").unwrap(),
            Command::Join {
                relay: Some("https://r.example".into()),
                name: Some("bob".into()),
                device: None,
                no_wait: false,
                resume: false
            }
        );
        assert_eq!(p("me --json").unwrap(), Command::Me { json: true });
        assert_eq!(
            p("invite --role manager --hours 5").unwrap(),
            Command::Invite {
                role: Role::Manager,
                hours: Some(5),
                name: None,
                grants: vec![],
                shared: false
            }
        );
        assert_eq!(
            p("invite").unwrap(),
            Command::Invite {
                role: Role::Member,
                hours: None,
                name: None,
                grants: vec![],
                shared: false
            }
        );
        assert_eq!(
            p("member revoke 3").unwrap(),
            Command::MemberRevoke { id: 3 }
        );
        assert_eq!(
            p("grant --collection 1 --member 2").unwrap(),
            Command::Grant {
                collection: 1,
                member: 2
            }
        );
        assert_eq!(
            p("revoke --grant 4").unwrap(),
            Command::GrantRevoke { id: 4 }
        );
        assert_eq!(
            p("agent create ci --days 7").unwrap(),
            Command::AgentCreate {
                name: "ci".into(),
                days: Some(7)
            }
        );
        assert_eq!(p("agent revoke 2").unwrap(), Command::AgentRevoke { id: 2 });
        assert_eq!(
            p("approve 9 --reason ok").unwrap(),
            Command::Approve {
                run: 9,
                reason: Some("ok".into())
            }
        );
        assert_eq!(
            p("deny 9").unwrap(),
            Command::Deny {
                run: 9,
                reason: None
            }
        );
        assert_eq!(
            p("audit --after 5 --limit 10 --json").unwrap(),
            Command::Audit {
                after: Some(5),
                limit: Some(10),
                json: true
            }
        );
        assert_eq!(p("mcp").unwrap(), Command::Mcp);
        assert_eq!(
            p("host").unwrap(),
            Command::Host {
                ask_all: false,
                auto_limit: None,
                dialog: false
            }
        );
        assert_eq!(
            p("host --ask-all --auto-limit 5").unwrap(),
            Command::Host {
                ask_all: true,
                auto_limit: Some(5),
                dialog: false
            }
        );
        assert_eq!(p("--help").unwrap(), Command::Help);
    }

    fn exact(words: &[&str]) -> Result<Command, CliError> {
        parse(
            &words
                .iter()
                .map(|word| (*word).to_owned())
                .collect::<Vec<_>>(),
        )
    }

    #[test]
    fn device_join_invite_and_team_commands() {
        assert_eq!(
            p("create --relay r --team Family --name rafal --device mac").unwrap(),
            Command::Create {
                relay: "r".into(),
                team: "Family".into(),
                name: "rafal".into(),
                device: Some("mac".into())
            }
        );
        assert_eq!(
            p("join --relay r --device mac --no-wait").unwrap(),
            Command::Join {
                relay: Some("r".into()),
                name: None,
                device: Some("mac".into()),
                no_wait: true,
                resume: false
            }
        );
        assert_eq!(
            p("join --resume").unwrap(),
            Command::Join {
                relay: None,
                name: None,
                device: None,
                no_wait: false,
                resume: true
            }
        );
        assert_eq!(
            p("device enroll").unwrap(),
            Command::DeviceEnroll { name: None }
        );
        assert_eq!(
            p("device enroll --name mac").unwrap(),
            Command::DeviceEnroll {
                name: Some("mac".into())
            }
        );
        assert_eq!(
            p("device list --json").unwrap(),
            Command::DeviceList { json: true }
        );
        assert_eq!(
            p("device revoke 3").unwrap(),
            Command::DeviceRevoke { id: 3 }
        );
        assert_eq!(
            p("device key-holder 3").unwrap(),
            Command::DeviceKeyHolder { id: 3 }
        );
        assert_eq!(p("device add").unwrap(), Command::DeviceAdd);
        assert_eq!(
            p("device link --relay r --device mac --no-wait").unwrap(),
            Command::DeviceLink {
                relay: Some("r".into()),
                device: Some("mac".into()),
                no_wait: true,
                resume: false
            }
        );
        assert_eq!(
            p("device link --resume").unwrap(),
            Command::DeviceLink {
                relay: None,
                device: None,
                no_wait: false,
                resume: true
            }
        );
        assert_eq!(
            p("device pending --json").unwrap(),
            Command::DevicePending { json: true }
        );
        assert_eq!(
            exact(&["device", "confirm", "4", "--words", "W1 W2"]).unwrap(),
            Command::DeviceConfirm {
                id: 4,
                words: "W1 W2".into()
            }
        );
        assert_eq!(
            p("device refuse 4").unwrap(),
            Command::DeviceRefuse { id: 4 }
        );
        assert_eq!(
            p("invite --role owner --name alice --grant 1,2 --grant 3 --hours 4").unwrap(),
            Command::Invite {
                role: Role::Owner,
                hours: Some(4),
                name: Some("alice".into()),
                grants: vec![1, 2, 3],
                shared: false
            }
        );
        assert_eq!(
            p("invite --shared").unwrap(),
            Command::Invite {
                role: Role::Member,
                hours: None,
                name: None,
                grants: vec![],
                shared: true
            }
        );
        assert_eq!(p("joins --json").unwrap(), Command::Joins { json: true });
        assert_eq!(
            exact(&["confirm", "5", "--words=W1 W2"]).unwrap(),
            Command::Confirm {
                id: 5,
                words: "W1 W2".into()
            }
        );
        assert_eq!(p("refuse 5").unwrap(), Command::Refuse { id: 5 });
        assert_eq!(p("leave").unwrap(), Command::Leave);
        for (text, role) in [
            ("owner", Role::Owner),
            ("manager", Role::Manager),
            ("member", Role::Member),
        ] {
            assert_eq!(
                p(&format!("member role 6 {text}")).unwrap(),
                Command::MemberRole { id: 6, role }
            );
        }
        assert_eq!(
            p("team list --json").unwrap(),
            Command::TeamList { json: true }
        );
        assert_eq!(
            p("team use t_example").unwrap(),
            Command::TeamUse {
                id: "t_example".into()
            }
        );
    }

    #[test]
    fn team_selection_preserves_create_name_and_member_command() {
        for line in [
            "--team t_one me --json",
            "me --team=t_one --json",
            "me --json --team t_one",
        ] {
            assert_eq!(
                p(line).unwrap(),
                Command::Selected {
                    team: "t_one".into(),
                    command: Box::new(Command::Me { json: true })
                }
            );
        }
        for line in [
            "device list --team t_one --json",
            "invite --team t_one",
            "member role 3 owner --team t_one",
            "host --team t_one",
            "agent list --team t_one",
            "join --resume --team t_one",
            "device link --resume --team t_one",
        ] {
            assert!(
                matches!(p(line).unwrap(), Command::Selected { team, .. } if team == "t_one"),
                "{line}"
            );
        }
        assert!(
            matches!(p("create --relay r --team t_one --name n").unwrap(), Command::Create { team, .. } if team == "t_one")
        );
        let Command::Run(run) = p("run --items 1 --purpose check -- echo --team t_child").unwrap()
        else {
            panic!("wrong command")
        };
        assert_eq!(run.command, ["echo", "--team", "t_child"]);
    }

    #[test]
    fn new_commands_reject_unsafe_or_incomplete_arguments() {
        for line in [
            "join",
            "join --relay",
            "join --relay --no-wait",
            "join --resume --relay r",
            "join --resume --name n",
            "join --resume --device n",
            "join --relay r --code secret",
            "join --relay r --invite secret",
            "join --relay r secret",
            "device",
            "device enroll --key secret",
            "device enroll extra",
            "device list extra",
            "device add --json",
            "device revoke 0",
            "device revoke x",
            "device revoke",
            "device key-holder 0",
            "device key-holder 1 extra",
            "device link",
            "device link --resume --relay r",
            "device link --resume --device n",
            "device link --relay r --name n",
            "device link --relay r --code secret",
            "device pending --words one",
            "device confirm 1",
            "device confirm 0 --words=x",
            "device confirm 1 --words",
            "device refuse 0",
            "device refuse 1 extra",
            "confirm 1",
            "confirm 1 --words",
            "confirm --words=one",
            "refuse 0",
            "refuse 1 extra",
            "joins extra",
            "leave extra",
            "leave --json",
            "member role 0 owner",
            "member role 1 admin",
            "member role 1",
            "team",
            "team list extra",
            "team use",
            "team use a b",
            "invite --role owner --shared",
            "invite --role manager --shared",
            "invite --grant 0",
            "invite --grant 1,",
            "invite --grant x",
            "invite --grant 1 --grant 1",
            "invite --name a --name b",
            "--team",
            "me --team=",
            "me --team a --team b",
            "me --team --json",
            "init --relay r --team t_one",
            "join --relay r --team t_one",
            "device link --relay r --team t_one",
            "access --team t_one",
            "run --items 1 --purpose check --team t_one -- true",
            "mcp --team t_one",
            "team list --team t_one",
        ] {
            assert_eq!(p(line).unwrap_err().code, 2, "{line}");
        }
        for words in ["", "one", "one two three"] {
            for prefix in [vec!["confirm", "1"], vec!["device", "confirm", "1"]] {
                let mut args = prefix;
                args.extend(["--words", words]);
                assert_eq!(exact(&args).unwrap_err().code, 2, "{args:?}");
            }
        }
        assert_eq!(
            exact(&["confirm", "1", "--words", "one two", "--words", "one two"])
                .unwrap_err()
                .code,
            2
        );
    }

    #[test]
    fn host_dialog_and_service_commands() {
        assert_eq!(
            p("host --dialog").unwrap(),
            Command::Host {
                ask_all: false,
                auto_limit: None,
                dialog: true,
            }
        );
        assert_eq!(
            p("host --dialog --ask-all --auto-limit=0").unwrap(),
            Command::Host {
                ask_all: true,
                auto_limit: Some(0),
                dialog: true,
            }
        );
        assert_eq!(
            p("host install").unwrap(),
            Command::HostInstall {
                ask_all: false,
                auto_limit: None,
            }
        );
        assert_eq!(
            p("host install --ask-all --auto-limit 5").unwrap(),
            Command::HostInstall {
                ask_all: true,
                auto_limit: Some(5),
            }
        );
        assert_eq!(
            p("host install --auto-limit=0").unwrap(),
            Command::HostInstall {
                ask_all: false,
                auto_limit: Some(0),
            }
        );
        assert_eq!(p("host uninstall").unwrap(), Command::HostUninstall);
        assert_eq!(p("host status").unwrap(), Command::HostStatus);
    }

    #[test]
    fn collection_policy_flags() {
        let c = p("collection create pay --mode ask --allow-prefix stripe --allow-prefix git --forbid delete --max-runs-per-hour 3 --rule-expires-at 99 --instruction be_careful").unwrap();
        let Command::CollectionCreate { name, policy } = c else {
            panic!("wrong command")
        };
        assert_eq!(name, "pay");
        let policy = policy.into_policy();
        assert_eq!(policy.mode, PolicyMode::Ask);
        assert_eq!(policy.rule.allowed_prefixes, vec!["stripe", "git"]);
        assert_eq!(policy.rule.forbidden_words, vec!["delete"]);
        assert_eq!(policy.rule.max_runs_per_hour, Some(3));
        assert_eq!(policy.rule.expires_at, Some(99));
        assert_eq!(policy.rule.instruction, "be_careful");
        assert_eq!(
            p("collection policy 2").unwrap(),
            Command::CollectionPolicy {
                id: 2,
                policy: PolicyFlags::default()
            }
        );
        assert!(p("collection create pay --mode loud").is_err());
    }

    #[test]
    fn item_add_and_list() {
        let c = p("item add --collection 1 --name Stripe --env STRIPE_API_KEY --environment staging --provider stripe --host a.example --host b.example --risk low").unwrap();
        let Command::ItemAdd(a) = c else {
            panic!("wrong command")
        };
        assert_eq!((a.collection, a.env_name.as_str()), (1, "STRIPE_API_KEY"));
        assert_eq!(a.hosts, vec!["a.example", "b.example"]);
        assert_eq!(a.risk.as_deref(), Some("low"));
        assert!(!a.allow_broad_host);
        let c =
            p("item add --collection 1 --name N --env K --environment staging --allow-broad-host")
                .unwrap();
        let Command::ItemAdd(a) = c else {
            panic!("wrong command")
        };
        assert!(a.allow_broad_host);
        assert!(p("item add --collection 1 --name N --env K --environment staging --allow-broad-host=yes").is_err());
        assert_eq!(
            p("item list --collection 2").unwrap(),
            Command::ItemList {
                collection: Some(2),
                json: false
            }
        );
        assert_eq!(p("item archive 8").unwrap(), Command::ItemArchive { id: 8 });
    }

    #[test]
    fn run_takes_the_command_after_the_dashes() {
        let words: Vec<String> = [
            "run",
            "--items",
            "1,2",
            "--purpose",
            "check it",
            "--ttl",
            "120",
            "--",
            "sh",
            "-c",
            "echo --items",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let Command::Run(r) = parse(&words).unwrap() else {
            panic!("wrong command")
        };
        assert_eq!(r.items, vec![1, 2]);
        assert_eq!(r.purpose, "check it");
        assert_eq!(r.ttl, Some(120));
        assert_eq!(r.command, vec!["sh", "-c", "echo --items"]);
    }

    #[test]
    fn usage_errors_have_exit_code_2() {
        for line in [
            "",
            "nope",
            "init",
            "init --relay",
            "init --relay a --relay b",
            "init --bogus 1",
            "create --relay a --team T",
            "create --relay a --name n extra",
            "me extra",
            "member revoke",
            "member revoke zero",
            "member revoke 0",
            "grant --collection 1",
            "invite --role other",
            "invite --hours x",
            "approve",
            "approve 1 2",
            "run --items 1 --purpose x",
            "run --items 1 --purpose x --",
            "run --items 1,1 --purpose x -- ls",
            "run --items a --purpose x -- ls",
            "run --purpose x -- ls",
            "run --items 1 --purpose  -- ls",
            "audit --json=1",
            "host extra",
            "host --ask-all=yes",
            "host --auto-limit",
            "host --auto-limit many",
            "host --auto-limit -1",
            "host --auto-limit 4294967296",
            "host --auto-limit 1 --auto-limit 2",
            "host --dialog=yes",
            "host --unknown",
            "host start",
            "host --dialog install",
            "host install extra",
            "host install status",
            "host install --dialog",
            "host install --ask-all=yes",
            "host install --auto-limit",
            "host install --auto-limit many",
            "host install --auto-limit -1",
            "host install --auto-limit 4294967296",
            "host install --auto-limit 1 --auto-limit 2",
            "host install --unknown",
            "host uninstall extra",
            "host uninstall --ask-all",
            "host uninstall --auto-limit 1",
            "host uninstall --dialog",
            "host status extra",
            "host status --json",
            "host status --ask-all",
            "host status --auto-limit 1",
            "host status --dialog",
            "item add --collection 1",
            "agent",
            "-x",
        ] {
            match p(line) {
                Err(e) => assert_eq!(e.code, 2, "line: {line}"),
                Ok(c) => panic!("`{line}` parsed as {c:?}"),
            }
        }
    }
}
