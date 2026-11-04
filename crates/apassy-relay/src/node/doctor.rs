//! `apassy doctor [--json]`: the checks of the node (plan D8).
//!
//! Each check has an id, a status (`pass`, `warn`, `fail`, `skip`), a detail, and a hint
//! with the next step. The ids, in order, are `CHECK_IDS`. `--json` prints
//! `{"ok": bool, "checks": [...]}`; `ok` is false when a check fails. The exit code is 0
//! when nothing fails, else 1.

use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use serde::Serialize;

use super::config::{NodeSettings, Route};
use super::serve::ServeState;
use super::status::{self, Probe, SystemProbe};
use super::{NodeCliError, PROGRAM, keys, node_dir, parse_options, printable};

/// The ids of the checks, in their order.
pub const CHECK_IDS: [&str; 13] = [
    "tailscale_installed",
    "tailscale_running",
    "tailscale_address",
    "origin",
    "port",
    "data_dir",
    "key",
    "service",
    "linger",
    "clock",
    "old_host_service",
    "serve_peer_addresses",
    "coding_agents",
];

/// A clock further than this from the gateway's gets a warning.
const SKEW_WARN_SECS: u64 = 60;
/// The gateway refuses a push whose time is 5 minutes off; this is the failure.
const SKEW_FAIL_SECS: u64 = 240;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Pass,
    Warn,
    Fail,
    Skip,
}

impl CheckStatus {
    fn mark(self) -> &'static str {
        match self {
            Self::Pass => "ok  ",
            Self::Warn => "warn",
            Self::Fail => "FAIL",
            Self::Skip => "skip",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Check {
    pub id: &'static str,
    pub status: CheckStatus,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

/// `apassy doctor --json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    pub ok: bool,
    pub checks: Vec<Check>,
}

fn check(id: &'static str, status: CheckStatus, detail: impl Into<String>) -> Check {
    Check {
        id,
        status,
        detail: detail.into(),
        hint: None,
    }
}

fn with_hint(mut check: Check, hint: impl Into<String>) -> Check {
    check.hint = Some(hint.into());
    check
}

/// What `tailscale status --json` says, for the first three checks.
struct TailscaleView {
    installed: bool,
    /// `Ok(state)`: running; `Err(state)`: the backend state when not running.
    running: Result<(), String>,
    ipv4: Option<Ipv4Addr>,
    /// The IPv4 address is on an interface of this machine.
    assigned: bool,
}

fn tailscale_view(probe: &dyn Probe) -> TailscaleView {
    let Some(output) = probe.tailscale().run(&["status", "--json"]) else {
        return TailscaleView {
            installed: false,
            running: Err("not installed".to_owned()),
            ipv4: None,
            assigned: false,
        };
    };
    let parsed = apassy::net::tailnet::parse_status(&output.stdout);
    let running = if parsed.running {
        Ok(())
    } else {
        Err(match apassy::node::funnel::parse_status(&output.stdout) {
            apassy::node::funnel::Tailscale::NotConnected { state } => state,
            _ => "not running".to_owned(),
        })
    };
    let ipv4 = parsed.ipv4();
    let assigned = ipv4.is_some_and(|v4| {
        apassy::net::tailnet::assigned(&[IpAddr::V4(v4)]).contains(&IpAddr::V4(v4))
    });
    TailscaleView {
        installed: true,
        running,
        ipv4,
        assigned,
    }
}

fn tailscale_checks(view: &TailscaleView, route: Route) -> Vec<Check> {
    let installed = if view.installed {
        check(
            "tailscale_installed",
            CheckStatus::Pass,
            "Tailscale is installed.",
        )
    } else {
        with_hint(
            check(
                "tailscale_installed",
                CheckStatus::Fail,
                "Tailscale is not installed.",
            ),
            "curl -fsSL https://tailscale.com/install.sh | sh",
        )
    };
    let running = match (&view.running, view.installed) {
        (_, false) => check("tailscale_running", CheckStatus::Skip, "No Tailscale."),
        (Ok(()), true) => check(
            "tailscale_running",
            CheckStatus::Pass,
            "Tailscale is connected.",
        ),
        (Err(state), true) => with_hint(
            check(
                "tailscale_running",
                CheckStatus::Fail,
                format!("Tailscale is not connected ({}).", printable(state)),
            ),
            "sudo tailscale up",
        ),
    };
    let address = match (view.ipv4, view.assigned, route) {
        (None, _, _) => check(
            "tailscale_address",
            if view.running.is_ok() {
                CheckStatus::Fail
            } else {
                CheckStatus::Skip
            },
            "No Tailscale IPv4 address.",
        ),
        (Some(v4), true, _) => check(
            "tailscale_address",
            CheckStatus::Pass,
            format!("{v4} is on an interface of this machine."),
        ),
        (Some(v4), false, Route::ServeTcp) => check(
            "tailscale_address",
            CheckStatus::Pass,
            format!("{v4} (through Tailscale Serve; no interface has it)."),
        ),
        (Some(v4), false, Route::Direct) => with_hint(
            check(
                "tailscale_address",
                CheckStatus::Fail,
                format!("No interface of this machine has {v4} (userspace networking?)."),
            ),
            format!("{PROGRAM} up --route serve-tcp"),
        ),
    };
    vec![installed, running, address]
}

fn origin_check(view: &TailscaleView, settings: &NodeSettings) -> Check {
    let now = view
        .ipv4
        .map(|v4| super::config::node_origin(v4, settings.port));
    match (&settings.last_origin, now) {
        (None, _) => check("origin", CheckStatus::Skip, "The node has not started yet."),
        (Some(last), Some(now)) if *last == now => check(
            "origin",
            CheckStatus::Pass,
            format!("The node origin is {now}."),
        ),
        (Some(last), Some(now)) => with_hint(
            check(
                "origin",
                CheckStatus::Warn,
                format!(
                    "The node origin changed from {last} to {now}: paired devices cannot reach it."
                ),
            ),
            format!("Restart the node, then pair every device again: {PROGRAM} pair"),
        ),
        (Some(last), None) => check(
            "origin",
            CheckStatus::Skip,
            format!("The last origin is {last}; Tailscale gives no address now."),
        ),
    }
}

fn port_check(
    probe: &dyn Probe,
    view: &TailscaleView,
    settings: &NodeSettings,
    state: Option<&ServeState>,
) -> Check {
    let port = settings.port;
    if let Some(state) = state
        && state.port == port
        && !state.bound.is_empty()
    {
        return check(
            "port",
            CheckStatus::Pass,
            format!("Port {port} is the node's ({}).", state.bound.join(", ")),
        );
    }
    let ip = match settings.route {
        Route::ServeTcp => IpAddr::V4(Ipv4Addr::LOCALHOST),
        Route::Direct => match view.ipv4 {
            Some(v4) if view.assigned => IpAddr::V4(v4),
            _ => {
                return check(
                    "port",
                    CheckStatus::Skip,
                    "No tailnet address to check the port on.",
                );
            }
        },
    };
    match probe.bind(ip, port) {
        Ok(()) => check(
            "port",
            CheckStatus::Pass,
            format!("Port {port} is free on {ip}."),
        ),
        Err(kind) => {
            let owner = probe
                .port_owner(port)
                .map_or_else(String::new, |name| format!(" by {name}"));
            with_hint(
                check(
                    "port",
                    CheckStatus::Fail,
                    format!("Port {port} on {ip} is taken{owner} ({kind:?})."),
                ),
                format!(
                    "Stop that program, or choose another port before the first pairing: {PROGRAM} up --port N"
                ),
            )
        }
    }
}

fn data_dir_check(dir: &Path) -> Check {
    match fs::symlink_metadata(dir) {
        Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {
            if meta.mode() & 0o777 == 0o700 {
                check(
                    "data_dir",
                    CheckStatus::Pass,
                    format!("{} has mode 0700.", dir.display()),
                )
            } else {
                with_hint(
                    check(
                        "data_dir",
                        CheckStatus::Fail,
                        format!(
                            "{} has mode {:o}, not 0700.",
                            dir.display(),
                            meta.mode() & 0o777
                        ),
                    ),
                    format!("chmod 700 {}", dir.display()),
                )
            }
        }
        Ok(_) => check(
            "data_dir",
            CheckStatus::Fail,
            format!("{} is not a directory.", dir.display()),
        ),
        Err(_) => with_hint(
            check(
                "data_dir",
                CheckStatus::Warn,
                format!("{} does not exist yet.", dir.display()),
            ),
            format!("{PROGRAM} up"),
        ),
    }
}

fn key_check(dir: &Path, probe: &dyn Probe, state: Option<&ServeState>) -> Check {
    if let Some(state) = state {
        return check(
            "key",
            CheckStatus::Pass,
            format!("The running node took its key from a {}.", state.key_source),
        );
    }
    let source = keys::source_for(dir, probe.credentials_dir().as_deref());
    let path = source.path();
    match (fs::metadata(path), &source) {
        (Ok(_), keys::KeySource::Credential(_)) => {
            check("key", CheckStatus::Pass, "The key is a systemd credential.")
        }
        (Ok(_), keys::KeySource::Encrypted(_)) => {
            let plain = dir.join(keys::KEY_FILE);
            if fs::symlink_metadata(&plain).is_ok() {
                with_hint(
                    check(
                        "key",
                        CheckStatus::Warn,
                        format!(
                            "The key is the encrypted credential {}, and a plain key file is left beside it.",
                            path.display()
                        ),
                    ),
                    format!(
                        "Check that the node runs (`{PROGRAM} status`), then remove {}",
                        plain.display()
                    ),
                )
            } else {
                check(
                    "key",
                    CheckStatus::Pass,
                    format!(
                        "The key is the encrypted credential {}; systemd gives it to the service only.",
                        path.display()
                    ),
                )
            }
        }
        (Ok(meta), keys::KeySource::File(_)) if meta.mode() & 0o077 == 0 => check(
            "key",
            CheckStatus::Pass,
            format!("The key is the file {} (mode 0600).", path.display()),
        ),
        (Ok(_), keys::KeySource::File(_)) => with_hint(
            check(
                "key",
                CheckStatus::Fail,
                format!("Other users can read the key file {}.", path.display()),
            ),
            format!("chmod 600 {}", path.display()),
        ),
        (Err(_), _) => check(
            "key",
            CheckStatus::Warn,
            "No key yet: the first start makes it.",
        ),
    }
}

fn service_check(probe: &dyn Probe) -> Check {
    let service = status::service_status(probe);
    let enabled = service.enabled.as_deref() == Some("enabled");
    let active = service.active.as_deref() == Some("active");
    match (service.installed, enabled, active) {
        (false, _, _) => with_hint(
            check(
                "service",
                CheckStatus::Warn,
                format!("{} is not installed.", service.unit),
            ),
            format!("{PROGRAM} up"),
        ),
        (true, true, true) => check(
            "service",
            CheckStatus::Pass,
            format!("{} is enabled and active.", service.unit),
        ),
        (true, _, _) => with_hint(
            check(
                "service",
                CheckStatus::Warn,
                format!(
                    "{} is {}, {}.",
                    service.unit,
                    service.enabled.as_deref().unwrap_or("unknown"),
                    service.active.as_deref().unwrap_or("unknown")
                ),
            ),
            format!("systemctl --user enable --now {}", service.unit),
        ),
    }
}

fn linger_check(probe: &dyn Probe) -> Check {
    match probe.linger() {
        Some(true) => check(
            "linger",
            CheckStatus::Pass,
            "Linger is on: the node starts at boot without a login.",
        ),
        Some(false) => with_hint(
            check(
                "linger",
                CheckStatus::Warn,
                "Linger is off: the node runs only while you are logged in.",
            ),
            "sudo loginctl enable-linger $USER",
        ),
        None => check("linger", CheckStatus::Skip, "loginctl cannot say."),
    }
}

fn clock_check(probe: &dyn Probe, gateway: Option<&str>) -> Check {
    let Some(gateway) = gateway else {
        return check(
            "clock",
            CheckStatus::Skip,
            "Push is off: no gateway to compare with.",
        );
    };
    let Some(date) = probe.gateway_date(gateway) else {
        return check(
            "clock",
            CheckStatus::Warn,
            format!("The push gateway {gateway} gave no date."),
        );
    };
    let skew = probe.now().abs_diff(date);
    if skew >= SKEW_FAIL_SECS {
        with_hint(
            check(
                "clock",
                CheckStatus::Fail,
                format!("The clock is {skew} s off the push gateway's: pushes are refused."),
            ),
            "timedatectl set-ntp true",
        )
    } else if skew >= SKEW_WARN_SECS {
        with_hint(
            check(
                "clock",
                CheckStatus::Warn,
                format!("The clock is {skew} s off."),
            ),
            "timedatectl set-ntp true",
        )
    } else {
        check(
            "clock",
            CheckStatus::Pass,
            format!("The clock is within {SKEW_WARN_SECS} s of the push gateway's."),
        )
    }
}

/// The host services that still run the `apassy-team` binary.
fn old_host_services(probe: &dyn Probe) -> Vec<String> {
    let Some(dir) = probe.unit_dir() else {
        return Vec::new();
    };
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !(name.starts_with("apassy-team-host") && name.ends_with(".service")) {
            continue;
        }
        let Ok(text) = fs::read_to_string(entry.path()) else {
            continue;
        };
        let program = text
            .lines()
            .find_map(|line| line.strip_prefix("ExecStart="))
            .and_then(|line| line.split_whitespace().next())
            .and_then(|program| Path::new(program).file_name().map(|name| name.to_owned()));
        if program.is_some_and(|program| program == "apassy-team") {
            found.push(printable(&name));
        }
    }
    found.sort();
    found
}

fn old_host_service_check(probe: &dyn Probe) -> Check {
    let found = old_host_services(probe);
    if found.is_empty() {
        check(
            "old_host_service",
            CheckStatus::Pass,
            "No host service runs apassy-team.",
        )
    } else {
        with_hint(
            check(
                "old_host_service",
                CheckStatus::Warn,
                format!(
                    "{} runs apassy-team, which goes in the next version.",
                    found.join(", ")
                ),
            ),
            format!(
                "{PROGRAM} team host install (it writes the same service for `{PROGRAM} team host`)"
            ),
        )
    }
}

fn serve_peer_check(without_peer_addresses: bool) -> Check {
    if without_peer_addresses {
        check(
            "serve_peer_addresses",
            CheckStatus::Warn,
            apassy::net::tailnet::SERVE_WITHOUT_PEER_ADDRESSES,
        )
    } else {
        check(
            "serve_peer_addresses",
            CheckStatus::Pass,
            "No Serve peer-address warning.",
        )
    }
}

fn coding_agents_check(home: Option<&Path>) -> Check {
    let Some(home) = home else {
        return check(
            "coding_agents",
            CheckStatus::Skip,
            "No home directory to check.",
        );
    };
    if [".claude", ".codex", ".cursor", ".config/opencode"]
        .iter()
        .any(|folder| home.join(folder).is_dir())
    {
        check(
            "coding_agents",
            CheckStatus::Warn,
            "Coding agents run as this user; they can reach the node's operator socket and key. Run the node as its own user.",
        )
    } else {
        check(
            "coding_agents",
            CheckStatus::Pass,
            "No known coding-agent config folders in this user's home.",
        )
    }
}

/// Runs every check on the node in `dir`.
pub fn collect(dir: &Path, probe: &dyn Probe) -> Result<Report, NodeCliError> {
    let settings = NodeSettings::load(dir)?;
    let state = if probe.running(dir) {
        ServeState::load(dir)?
    } else {
        None
    };
    let view = tailscale_view(probe);
    let mut checks = tailscale_checks(&view, settings.route);
    checks.push(origin_check(&view, &settings));
    checks.push(port_check(probe, &view, &settings, state.as_ref()));
    checks.push(data_dir_check(dir));
    checks.push(key_check(dir, probe, state.as_ref()));
    checks.push(service_check(probe));
    checks.push(linger_check(probe));
    checks.push(clock_check(probe, settings.push_gateway.as_deref()));
    checks.push(old_host_service_check(probe));
    checks.push(serve_peer_check(
        state
            .as_ref()
            .is_some_and(|state| state.serve_without_peer_addresses),
    ));
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    checks.push(coding_agents_check(home.as_deref()));
    let ok = checks.iter().all(|check| check.status != CheckStatus::Fail);
    Ok(Report { ok, checks })
}

/// Prints the report for a person.
pub fn print_text(report: &Report) {
    for check in &report.checks {
        println!("[{}] {}: {}", check.status.mark(), check.id, check.detail);
        if let Some(hint) = &check.hint {
            println!("       {hint}");
        }
    }
    if report.ok {
        println!("No check failed.");
    } else {
        println!("A check failed. Fix it, then run `{PROGRAM} doctor` again.");
    }
}

/// `apassy doctor [--json] [--data-dir DIR]`.
pub fn command(args: &[String]) -> Result<i32, NodeCliError> {
    let options = parse_options(args, &[], &[])?;
    let dir = node_dir(&options)?;
    let report = collect(&dir, &SystemProbe)?;
    if options.json {
        let text = serde_json::to_string(&report)
            .map_err(|_| NodeCliError::failed("The report cannot be written."))?;
        println!("{text}");
    } else {
        print_text(&report);
    }
    Ok(if report.ok { 0 } else { 1 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coding_agents_in_a_temporary_home_warn() {
        let home = tempfile::tempdir().unwrap();
        assert_eq!(
            coding_agents_check(Some(home.path())).status,
            CheckStatus::Pass
        );
        for folder in [".claude", ".codex", ".cursor", ".config/opencode"] {
            let path = home.path().join(folder);
            fs::create_dir_all(&path).unwrap();
            let found = coding_agents_check(Some(home.path()));
            assert_eq!(found.status, CheckStatus::Warn);
            assert!(found.detail.contains("Run the node as its own user."));
            fs::remove_dir(&path).unwrap();
        }
    }

    #[test]
    fn missing_serve_peer_addresses_warn() {
        assert_eq!(serve_peer_check(true).status, CheckStatus::Warn);
        assert_eq!(
            serve_peer_check(true).detail,
            apassy::net::tailnet::SERVE_WITHOUT_PEER_ADDRESSES
        );
        assert_eq!(serve_peer_check(false).status, CheckStatus::Pass);
    }

    #[test]
    fn the_ids_are_unique() {
        let mut ids = CHECK_IDS.to_vec();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), CHECK_IDS.len());
    }

    #[test]
    fn a_wrong_mode_of_the_data_dir_fails() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let node = dir.path().join("node");
        fs::create_dir(&node).unwrap();
        fs::set_permissions(&node, fs::Permissions::from_mode(0o755)).unwrap();
        let found = data_dir_check(&node);
        assert_eq!(found.status, CheckStatus::Fail);
        assert!(found.hint.unwrap().starts_with("chmod 700"));
        fs::set_permissions(&node, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(data_dir_check(&node).status, CheckStatus::Pass);
        assert_eq!(
            data_dir_check(&dir.path().join("none")).status,
            CheckStatus::Warn
        );
    }
}
