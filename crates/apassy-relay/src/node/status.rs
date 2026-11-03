//! `apassy status [--json]`: the state of the node (plan D8).
//!
//! The service state (systemd), the routes (the tailnet origin and the addresses the
//! front listens on; Funnel n/a; LAN off), the pin, the teams of the node (through the
//! operator socket of the running relay: counts and last activity, read-only), the push
//! gateway, and the key source. The shape of `--json` is `Status`, documented in
//! `docs/operations/linux-node.md`.
//!
//! The relay holds its directory while it runs, so `status` reads the teams from the
//! running node and never opens its files. The operator socket shows no device: the
//! device list with last contact needs a later operator command (see the guide).

use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use apassy::node::funnel::{SystemTailscale, TailscaleCli};
use serde::Serialize;
use serde_json::Value;

use super::config::{FRONT_DIR, NodeSettings, Route, admin_socket};
use super::keys;
use super::serve::{self, ServeState};
use super::service;
use super::{NodeCliError, PROGRAM, node_dir, parse_options, printable, utc_text};
use crate::server::operator;

/// What `status` and `doctor` ask the system. Tests give a fake.
pub trait Probe {
    /// `systemctl --user <args>`: the exit code and stdout. `None`: no `systemctl`.
    fn systemctl(&self, args: &[&str]) -> Option<(i32, String)>;
    /// The Tailscale command line.
    fn tailscale(&self) -> &dyn TailscaleCli;
    /// True when a `serve` answers on the control socket of `dir`.
    fn running(&self, dir: &Path) -> bool;
    /// One operator command to the running node of `dir`.
    fn operator(&self, dir: &Path, command: &operator::Command) -> Result<Value, String>;
    /// The path of the node unit.
    fn unit_path(&self) -> Option<PathBuf>;
    /// The directory of the user units.
    fn unit_dir(&self) -> Option<PathBuf>;
    /// `loginctl show-user <user> --property=Linger`: `None` when it cannot be read.
    fn linger(&self) -> Option<bool>;
    /// The `Date` of `GET <gateway>/healthz`, in seconds since the epoch.
    fn gateway_date(&self, gateway: &str) -> Option<u64>;
    /// `Ok(())` when `ip:port` can be bound now; else the kind of the error.
    fn bind(&self, ip: IpAddr, port: u16) -> Result<(), std::io::ErrorKind>;
    /// The program that listens on TCP `port`, if `ss` names it.
    fn port_owner(&self, port: u16) -> Option<String>;
    /// `$CREDENTIALS_DIRECTORY`.
    fn credentials_dir(&self) -> Option<PathBuf>;
    /// Now, in seconds since the epoch.
    fn now(&self) -> u64;
}

/// The probe of the real system.
pub struct SystemProbe;

fn run_program(program: &str, args: &[&str]) -> Option<(i32, String)> {
    let output = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    Some((
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
    ))
}

impl Probe for SystemProbe {
    fn systemctl(&self, args: &[&str]) -> Option<(i32, String)> {
        let mut all = vec!["--user"];
        all.extend_from_slice(args);
        run_program("systemctl", &all)
    }

    fn tailscale(&self) -> &dyn TailscaleCli {
        &SystemTailscale
    }

    fn running(&self, dir: &Path) -> bool {
        serve::is_running(dir)
    }

    fn operator(&self, dir: &Path, command: &operator::Command) -> Result<Value, String> {
        operator::send(&admin_socket(dir), command).map_err(|error| error.message)
    }

    fn unit_path(&self) -> Option<PathBuf> {
        service::node_unit_path().ok()
    }

    fn unit_dir(&self) -> Option<PathBuf> {
        service::user_unit_dir().ok()
    }

    fn linger(&self) -> Option<bool> {
        let user = std::env::var("USER")
            .or_else(|_| std::env::var("LOGNAME"))
            .ok()
            .filter(|user| {
                !user.is_empty()
                    && user
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
            })?;
        let (code, text) = run_program(
            "loginctl",
            &["show-user", &user, "--property=Linger", "--value"],
        )?;
        match (code, text.trim()) {
            (0, "yes") => Some(true),
            (0, "no") => Some(false),
            _ => None,
        }
    }

    fn gateway_date(&self, gateway: &str) -> Option<u64> {
        let agent = ureq::Agent::new_with_config(
            ureq::Agent::config_builder()
                .http_status_as_error(false)
                .max_redirects(0)
                .timeout_global(Some(std::time::Duration::from_secs(10)))
                .build(),
        );
        let response = agent.get(format!("{gateway}/healthz")).call().ok()?;
        let date = response.headers().get("date")?.to_str().ok()?;
        parse_http_date(date)
    }

    fn bind(&self, ip: IpAddr, port: u16) -> Result<(), std::io::ErrorKind> {
        std::net::TcpListener::bind((ip, port))
            .map(drop)
            .map_err(|error| error.kind())
    }

    fn port_owner(&self, port: u16) -> Option<String> {
        let filter = format!("sport = :{port}");
        let (code, text) = run_program("ss", &["-H", "-l", "-t", "-n", "-p", &filter])?;
        if code != 0 {
            return None;
        }
        parse_ss_owner(&text)
    }

    fn credentials_dir(&self) -> Option<PathBuf> {
        keys::credentials_dir()
    }

    fn now(&self) -> u64 {
        crate::now_unix()
    }
}

/// The first program name of `ss -p` output: `users:(("name",pid=1,fd=3))`.
pub fn parse_ss_owner(text: &str) -> Option<String> {
    let rest = text.split("users:((\"").nth(1)?;
    let name = rest.split('"').next()?;
    (!name.is_empty()).then(|| printable(name))
}

/// An HTTP date (`Tue, 03 Nov 2026 12:34:56 GMT`, RFC 9110 IMF-fixdate) in seconds since
/// the epoch.
pub fn parse_http_date(text: &str) -> Option<u64> {
    let parts: Vec<&str> = text.split_whitespace().collect();
    let [_, day, month, year, time, "GMT"] = parts.as_slice() else {
        return None;
    };
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let month = u32::try_from(MONTHS.iter().position(|name| name == month)? + 1).ok()?;
    let day: u32 = day.parse().ok().filter(|day| (1..=31).contains(day))?;
    let year: i64 = year.parse().ok().filter(|year| *year >= 1970)?;
    let mut clock = time.split(':').map(|part| part.parse::<u64>().ok());
    let (Some(Some(hour)), Some(Some(minute)), Some(Some(second)), None) =
        (clock.next(), clock.next(), clock.next(), clock.next())
    else {
        return None;
    };
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let days = u64::try_from(super::days_from_civil(year, month, day)).ok()?;
    Some(days * 86_400 + hour * 3600 + minute * 60 + second)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServiceStatus {
    /// `apassy-node.service`.
    pub unit: String,
    /// The unit file exists.
    pub installed: bool,
    /// `systemctl --user is-enabled`, such as `enabled` or `disabled`; `null` without
    /// systemd.
    pub enabled: Option<String>,
    /// `systemctl --user is-active`, such as `active` or `inactive`.
    pub active: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TailnetRoute {
    /// The node origin: of the running node, else of its last start.
    pub origin: Option<String>,
    pub port: u16,
    pub route: Route,
    /// The addresses the front listens on; empty when the node does not run.
    pub bound: Vec<String>,
    pub alternatives: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Routes {
    pub tailnet: TailnetRoute,
    /// The Linux node has no Funnel route: `n/a`.
    pub funnel: &'static str,
    /// No LAN route yet (ADR 0037 D6): `off`.
    pub lan: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TeamStatus {
    pub id: String,
    pub name: String,
    /// `active` or `suspended`.
    pub state: String,
    pub members: Option<u64>,
    pub open_questions: Option<u64>,
    pub last_activity: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KeyStatus {
    /// `credential`, `file`, or `none` (no key yet).
    pub source: String,
    pub path: String,
}

/// `apassy status --json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Status {
    pub version: String,
    pub data_dir: String,
    /// A `serve` answers on the control socket.
    pub running: bool,
    pub pid: Option<u32>,
    pub started_at: Option<u64>,
    pub service: ServiceStatus,
    pub routes: Routes,
    /// The pin of the node certificate; `null` before the first start.
    pub pin: Option<String>,
    /// The teams, when the node runs; empty otherwise.
    pub teams: Vec<TeamStatus>,
    /// Why the teams are missing while the node runs, if they are.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub teams_error: Option<String>,
    pub push_gateway: Option<String>,
    pub key: KeyStatus,
}

fn team_of(value: &Value) -> Option<TeamStatus> {
    Some(TeamStatus {
        id: value["id"].as_str()?.to_owned(),
        name: printable(value["name"].as_str().unwrap_or_default()),
        state: value["state"].as_str().unwrap_or("unknown").to_owned(),
        members: value["members"].as_u64(),
        open_questions: value["open_questions"].as_u64(),
        last_activity: value["last_activity"].as_u64(),
    })
}

/// The pin of the certificate in `front/` without opening its key: the pin is public.
fn pin_on_disk(dir: &Path) -> Option<String> {
    let der = super::config::read_small(
        &dir.join(FRONT_DIR)
            .join(apassy::net::certificate::CERT_FILE),
    )
    .ok()
    .flatten()?;
    Some(apassy::net::pin::certificate_pin(&der))
}

/// The service state of the node unit.
pub fn service_status(probe: &dyn Probe) -> ServiceStatus {
    let installed = probe
        .unit_path()
        .is_some_and(|path| fs::symlink_metadata(path).is_ok());
    let word = |args: &[&str]| {
        probe
            .systemctl(args)
            .map(|(_, text)| printable(text.trim()))
            .filter(|text| !text.is_empty())
    };
    ServiceStatus {
        unit: service::NODE_UNIT.to_owned(),
        installed,
        enabled: word(&["is-enabled", service::NODE_UNIT]),
        active: word(&["is-active", service::NODE_UNIT]),
    }
}

/// The key source of `dir`: the running node's, else what a start would use.
pub fn key_status(dir: &Path, probe: &dyn Probe, state: Option<&ServeState>) -> KeyStatus {
    let source = keys::source_for(dir, probe.credentials_dir().as_deref());
    let exists = fs::symlink_metadata(source.path()).is_ok();
    let label = match state {
        Some(state) => state.key_source.clone(),
        None if exists => source.label().to_owned(),
        None => "none".to_owned(),
    };
    KeyStatus {
        source: label,
        path: source.path().display().to_string(),
    }
}

/// Collects the status of the node in `dir`.
pub fn collect(dir: &Path, probe: &dyn Probe) -> Result<Status, NodeCliError> {
    let settings = NodeSettings::load(dir)?;
    let running = probe.running(dir);
    let state = if running {
        ServeState::load(dir)?
    } else {
        None
    };
    let (teams, teams_error) = if running {
        match probe.operator(dir, &operator::Command::Teams) {
            Ok(Value::Array(list)) => (list.iter().filter_map(team_of).collect(), None),
            Ok(_) => (Vec::new(), Some("The node gave no team list.".to_owned())),
            Err(why) => (Vec::new(), Some(printable(&why))),
        }
    } else {
        (Vec::new(), None)
    };
    let tailnet = match &state {
        Some(state) => TailnetRoute {
            origin: Some(state.origin.clone()),
            port: state.port,
            route: state.route,
            bound: state.bound.clone(),
            alternatives: state.alternatives.clone(),
        },
        None => TailnetRoute {
            origin: settings.last_origin.clone(),
            port: settings.port,
            route: settings.route,
            bound: Vec::new(),
            alternatives: Vec::new(),
        },
    };
    Ok(Status {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        data_dir: dir.display().to_string(),
        running,
        pid: state.as_ref().map(|state| state.pid),
        started_at: state.as_ref().map(|state| state.started_at),
        service: service_status(probe),
        routes: Routes {
            tailnet,
            funnel: "n/a",
            lan: "off",
        },
        pin: state
            .as_ref()
            .map(|state| state.pin.clone())
            .or_else(|| pin_on_disk(dir)),
        teams,
        teams_error,
        push_gateway: state
            .as_ref()
            .map_or(settings.push_gateway.clone(), |state| {
                state.push_gateway.clone()
            }),
        key: key_status(dir, probe, state.as_ref()),
    })
}

/// Prints `status` for a person.
pub fn print_text(status: &Status) {
    let version = &status.version;
    match (status.running, status.pid) {
        (true, Some(pid)) => println!("Node:     running (apassy {version}, process {pid})"),
        (true, None) => println!("Node:     running (apassy {version})"),
        (false, _) => println!("Node:     not running (apassy {version})"),
    }
    let service = &status.service;
    if service.installed {
        println!(
            "Service:  {} {}, {}",
            service.unit,
            service.enabled.as_deref().unwrap_or("unknown"),
            service.active.as_deref().unwrap_or("unknown")
        );
    } else {
        println!("Service:  not installed (run `{PROGRAM} up`)");
    }
    let tailnet = &status.routes.tailnet;
    match (&tailnet.origin, tailnet.bound.is_empty()) {
        (Some(origin), false) => println!(
            "Tailnet:  {origin}, listening on {} ({})",
            tailnet.bound.join(", "),
            tailnet.route.text()
        ),
        (Some(origin), true) => println!("Tailnet:  {origin} (not listening)"),
        (None, _) => println!("Tailnet:  port {} (never started)", tailnet.port),
    }
    println!("Funnel:   {}", status.routes.funnel);
    println!("LAN:      {}", status.routes.lan);
    println!("Pin:      {}", status.pin.as_deref().unwrap_or("none yet"));
    match &status.teams_error {
        Some(why) => println!("Teams:    unknown ({why})"),
        None if !status.running => println!("Teams:    the node is not running"),
        None if status.teams.is_empty() => println!("Teams:    none (run `{PROGRAM} pair`)"),
        None => {
            println!("Teams:    {}", status.teams.len());
            for team in &status.teams {
                let members = team.members.map_or_else(String::new, |count| {
                    format!(", {count} member{}", if count == 1 { "" } else { "s" })
                });
                let last = team.last_activity.map_or_else(String::new, |at| {
                    format!(", last activity {}", utc_text(at))
                });
                println!(
                    "  {} {} ({}{members}{last})",
                    team.id, team.name, team.state
                );
            }
        }
    }
    println!(
        "Push:     {}",
        status
            .push_gateway
            .as_deref()
            .unwrap_or("off (no push gateway)")
    );
    println!("Key:      {} ({})", status.key.source, status.key.path);
    println!("Data:     {}", status.data_dir);
}

/// `apassy status [--json] [--data-dir DIR]`. Exit 0 when the node runs, 3 when not.
pub fn command(args: &[String]) -> Result<i32, NodeCliError> {
    let options = parse_options(args, &[], &[])?;
    let dir = node_dir(&options)?;
    let status = collect(&dir, &SystemProbe)?;
    if options.json {
        let text = serde_json::to_string(&status)
            .map_err(|_| NodeCliError::failed("The status cannot be written."))?;
        println!("{text}");
    } else {
        print_text(&status);
    }
    Ok(if status.running { 0 } else { 3 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_dates_parse() {
        assert_eq!(
            parse_http_date("Tue, 03 Nov 2026 12:34:56 GMT"),
            Some(1_793_709_296)
        );
        assert_eq!(parse_http_date("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        for bad in [
            "",
            "Tue, 03 Nov 2026 12:34:56 UTC",
            "Tue, 03 Xyz 2026 12:34:56 GMT",
            "Tue, 03 Nov 2026 25:00:00 GMT",
            "Tue, 03 Nov 2026 12:34 GMT",
            "Tue, 03 Nov 2026 12:34:56:00 GMT",
        ] {
            assert_eq!(parse_http_date(bad), None, "{bad}");
        }
    }

    #[test]
    fn ss_names_the_owner() {
        let line = "LISTEN 0 128 100.64.0.7:8444 0.0.0.0:* users:((\"caddy\",pid=812,fd=7))\n";
        assert_eq!(parse_ss_owner(line).as_deref(), Some("caddy"));
        assert_eq!(parse_ss_owner("LISTEN 0 128 *:8444 *:*\n"), None);
    }
}
