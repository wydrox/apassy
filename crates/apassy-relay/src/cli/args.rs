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
    Help,
    Version,
    Init {
        relay: String,
    },
    Join {
        relay: String,
        name: String,
    },
    Me {
        json: bool,
    },
    Invite {
        role: Role,
        hours: Option<u32>,
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
    },
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
                None => iter
                    .next()
                    .cloned()
                    .ok_or_else(|| CliError::usage(format!("Option --{name} needs a value.")))?,
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
  init --relay URL              read a member token from stdin, check it, save settings
  join --relay URL --name NAME  read an invite code from stdin, join, save settings
  me                            who am I

Team (owner or manager)
  invite [--role member|manager] [--hours N]   print a one-time invite code
  invites | members | member revoke ID
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
  approve RUN_ID [--reason TEXT]   (refused: the keys are on the owner's host; use `host`)
  audit [--after ID] [--limit N] [--json]

Owner's machine (the owner token; keys.json lives here, back it up)
  host [--ask-all] [--auto-limit N]
      keep the item keys, and decide every run: a known safe run of a non-production
      item is released at once (at most N per item per hour, default 30); every other
      run asks on the terminal; --ask-all asks for every run. The host must be online
      for any run to start.

Members
  agent create NAME [--days N]  print an agent token once
  agent list | agent revoke ID

Agents (APASSY_TOKEN)
  access                        list the items I may use
  run --items 1,2 --purpose TEXT [--request TEXT] [--ttl SECS] [--wait SECS]
      [--cwd DIR] -- CMD ARGS...   ask for a run, then run the command
  mcp                           stdio MCP adapter

Most list commands take --json.
Environment: APASSY_RELAY_URL, APASSY_TEAM_TOKEN, APASSY_TOKEN, APASSY_EDGE_SECRET.
Secrets are read from stdin, never from arguments.
Exit codes: 0 ok (or the child's code), 2 usage, 3 run denied or timed out, 4 relay or network error.
";

pub fn parse(args: &[String]) -> Result<Command, CliError> {
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
        "join" => {
            let s = scan(rest, &["relay", "name"], &[])?;
            s.positional(0, "join --relay URL --name NAME")?;
            Ok(Command::Join {
                relay: s.required("relay")?,
                name: s.required("name")?,
            })
        }
        "me" => no_args(rest).map(|json| Command::Me { json }),
        "invite" => {
            let s = scan(rest, &["role", "hours"], &[])?;
            s.positional(0, "invite [--role member|manager] [--hours N]")?;
            let role = match s.one("role")?.as_deref() {
                None | Some("member") => Role::Member,
                Some("manager") => Role::Manager,
                Some(other) => {
                    return Err(CliError::usage(format!(
                        "--role must be member or manager, not `{other}`."
                    )));
                }
            };
            Ok(Command::Invite {
                role,
                hours: s.num("hours")?,
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
            _ => Err(CliError::usage("Usage: apassy-team member revoke ID")),
        },
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
        "host" => {
            let s = scan(rest, &["auto-limit"], &["ask-all"])?;
            s.positional(0, "host [--ask-all] [--auto-limit N]")?;
            Ok(Command::Host {
                ask_all: s.switch("ask-all"),
                auto_limit: s.num("auto-limit")?,
            })
        }
        other => Err(CliError::usage(format!("Unknown command `{other}`."))),
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
            p("join --relay=https://r.example --name bob").unwrap(),
            Command::Join {
                relay: "https://r.example".into(),
                name: "bob".into()
            }
        );
        assert_eq!(p("me --json").unwrap(), Command::Me { json: true });
        assert_eq!(
            p("invite --role manager --hours 5").unwrap(),
            Command::Invite {
                role: Role::Manager,
                hours: Some(5)
            }
        );
        assert_eq!(
            p("invite").unwrap(),
            Command::Invite {
                role: Role::Member,
                hours: None
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
                auto_limit: None
            }
        );
        assert_eq!(
            p("host --ask-all --auto-limit 5").unwrap(),
            Command::Host {
                ask_all: true,
                auto_limit: Some(5)
            }
        );
        assert_eq!(p("--help").unwrap(), Command::Help);
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
            "me extra",
            "member revoke",
            "member revoke zero",
            "member revoke 0",
            "grant --collection 1",
            "invite --role owner",
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
