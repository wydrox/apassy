//! `apassy up`: set up and start the node on Linux (plan D8).
//!
//! 1. Tailscale: not installed gives the install line; not connected gives
//!    `sudo tailscale up`; no address on an interface gives `--route serve-tcp`.
//! 2. The settings (`--port`, `--route`, `--push-gateway`, `--no-push`) in
//!    `settings.json`, the node directory with mode 0700, and the master key (`keys`).
//! 3. The key as an encrypted systemd credential (`keys::seal`, unit L2), where
//!    `systemd-creds` can make one that a user service decrypts (systemd 256 or later);
//!    else, or with `--no-encrypt`, the 0600 key file stays.
//! 4. The systemd user unit `apassy-node.service` (`service::generate_node_unit`:
//!    `ExecStart=<exe> serve`, `LoadCredentialEncrypted=` for an encrypted key,
//!    `Restart=on-failure`, `WantedBy=default.target`), `daemon-reload`, `enable --now`,
//!    `restart`.
//! 5. It waits for `/healthz` of the relay on the loopback, prints `status`, then `pair`,
//!    and the `loginctl enable-linger` command when linger is off: linger needs root, so
//!    it stays the owner's step.
//!
//! `--no-service` stops after step 2 (for `apassy serve` by hand, or another service
//! manager). `--print-unit` prints the unit of step 4 and changes nothing.
//! `apassy uninstall` (`uninstall`) stops and removes the unit and keeps the files.

use std::time::{Duration, Instant};

use apassy::node::funnel::SystemTailscale;
use serde_json::json;

use super::config::{NodeSettings, Route, ensure_private_dir};
use super::keys::{KeySource, SystemdCreds};
use super::serve::{self, ServeState, tailnet_now};
use super::status::{self, Probe, SystemProbe};
use super::{NodeCliError, PROGRAM, keys, node_dir, pair, parse_options, printable, service};
use crate::cli::CliError;

/// The options of `up` with a value, and its flags.
const VALUES: [&str; 3] = ["port", "route", "push-gateway"];
const FLAGS: [&str; 5] = [
    "no-push",
    "no-service",
    "no-pair",
    "no-encrypt",
    "print-unit",
];

/// How long `up` waits for the node to answer.
const START_WAIT: Duration = Duration::from_secs(60);
const START_POLL: Duration = Duration::from_millis(250);

fn from_cli(error: CliError) -> NodeCliError {
    NodeCliError::failed(error.message)
}

/// The settings of `settings` with the options of the command line.
fn apply_options(
    mut settings: NodeSettings,
    options: &super::Options,
) -> Result<NodeSettings, NodeCliError> {
    if let Some(port) = options.value("port") {
        let port = port
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .ok_or_else(|| NodeCliError::usage("--port is a port from 1 to 65535."))?;
        if port != settings.port && settings.last_origin.is_some() {
            eprintln!(
                "{PROGRAM} up: the port changes from {} to {port}. The node origin changes: every paired device must pair again.",
                settings.port
            );
        }
        settings.port = port;
    }
    if let Some(route) = options.value("route") {
        settings.route = Route::parse(route)
            .ok_or_else(|| NodeCliError::usage("--route is direct or serve-tcp."))?;
    }
    match (options.value("push-gateway"), options.flag("no-push")) {
        (Some(_), true) => {
            return Err(NodeCliError::usage(
                "Give --push-gateway or --no-push, not both.",
            ));
        }
        (Some(gateway), false) => settings.push_gateway = Some(gateway.to_owned()),
        (None, true) => settings.push_gateway = None,
        (None, false) => {}
    }
    settings.check()?;
    Ok(settings)
}

/// Waits until the node of `dir` answers on its control socket and its relay answers
/// `/healthz`.
fn wait_until_up(dir: &std::path::Path) -> Result<ServeState, NodeCliError> {
    let started = Instant::now();
    loop {
        if serve::is_running(dir)
            && let Some(state) = ServeState::load(dir)?
            && serve::loopback_healthy(&state, Duration::from_secs(2))
        {
            return Ok(state);
        }
        if started.elapsed() >= START_WAIT {
            return Err(NodeCliError::failed(format!(
                "The node did not start within {} s. Look at `journalctl --user -u {}` and run `{PROGRAM} doctor`.",
                START_WAIT.as_secs(),
                service::NODE_UNIT
            )));
        }
        std::thread::sleep(START_POLL);
    }
}

/// The encrypted key of `source`, for `LoadCredentialEncrypted=`.
fn credential_of(source: &KeySource) -> Option<&std::path::Path> {
    match source {
        KeySource::Encrypted(path) => Some(path),
        KeySource::Credential(_) | KeySource::File(_) => None,
    }
}

/// The unit for this program and `source`.
fn unit_text(options: &super::Options, source: &KeySource) -> Result<String, NodeCliError> {
    let exe = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .map_err(|_| NodeCliError::failed("The path of this program cannot be read."))?;
    service::generate_node_unit(&exe, options.data_dir.as_deref(), credential_of(source))
        .map_err(from_cli)
}

/// Step 3: the key file becomes an encrypted credential where it can. The second value
/// says why the key file stays, for one line on stderr.
fn encrypt_key(dir: &std::path::Path, source: KeySource) -> (KeySource, Option<String>) {
    let KeySource::File(_) = source else {
        return (source, None);
    };
    let target = dir.join(keys::CREDENTIAL_FILE);
    if !service::fits_a_unit(&target) {
        return (
            source,
            Some(format!(
                "{} has spaces or special characters, which a unit line cannot hold",
                target.display()
            )),
        );
    }
    let Some(tool) = SystemdCreds::find() else {
        return (source, Some("systemd-creds is not installed".to_owned()));
    };
    match keys::seal(dir, &tool) {
        Ok(sealed) => (sealed, None),
        Err(why) => (source, Some(why)),
    }
}

/// `apassy up [--port N] [--route direct|serve-tcp] [--push-gateway URL | --no-push]
/// [--no-service] [--no-encrypt] [--no-pair] [--print-unit] [--json] [--data-dir DIR]`.
pub fn command(args: &[String]) -> Result<i32, NodeCliError> {
    let options = parse_options(args, &VALUES, &FLAGS)?;
    let dir = node_dir(&options)?;
    if options.flag("print-unit") {
        // The unit that `up` would write now, without Tailscale, files, or systemd.
        let source = keys::source_for(&dir, None);
        print!("{}", unit_text(&options, &source)?);
        return Ok(0);
    }
    let install = !options.flag("no-service");
    if install && !cfg!(target_os = "linux") {
        return Err(NodeCliError::usage(format!(
            "`{PROGRAM} up` installs a systemd user service, so it is for Linux. Use `{PROGRAM} up --no-service` and `{PROGRAM} serve` here."
        )));
    }
    let settings = apply_options(NodeSettings::load(&dir)?, &options)?;
    // 1. Tailscale, before anything is written.
    tailnet_now(&SystemTailscale, settings.route)
        .map_err(|why| NodeCliError::failed(format!("{why} Then run `{PROGRAM} up` again.")))?;
    // 2. The files.
    ensure_private_dir(&dir)?;
    settings.save(&dir)?;
    let source = keys::ensure(&dir)?;
    if !install {
        if !options.json {
            println!("Node files: {} (key: {})", dir.display(), source.label());
        }
        if options.json {
            println!(
                "{}",
                json!({"ok": true, "data_dir": dir.display().to_string(), "service": null})
            );
        } else {
            println!("Start the node with `{PROGRAM} serve` (add --data-dir if you gave one).");
        }
        return Ok(0);
    }
    // 3. The key, encrypted where systemd can give it to a user service.
    let source = if options.flag("no-encrypt") {
        source
    } else {
        let (source, kept) = encrypt_key(&dir, source);
        if let Some(why) = kept {
            eprintln!(
                "{PROGRAM} up: the key stays in the 0600 file: {}.",
                printable(&why)
            );
        }
        source
    };
    if !options.json {
        println!("Node files: {} (key: {})", dir.display(), source.label());
    }
    // 4. The service.
    let text = unit_text(&options, &source)?;
    let unit = service::write_node_unit(&text).map_err(from_cli)?;
    service::start_node_unit().map_err(from_cli)?;
    if !options.json {
        println!("Service: {} ({})", service::NODE_UNIT, unit.display());
    }
    // 5. Up, then status and pair.
    wait_until_up(&dir)?;
    let probe = SystemProbe;
    let current = status::collect(&dir, &probe)?;
    let paired = if options.flag("no-pair") {
        None
    } else {
        Some(pair::make(&dir, pair::DEFAULT_MINUTES)?)
    };
    let linger = probe.linger();
    if options.json {
        let value = json!({
            "ok": true,
            "service": {"unit": service::NODE_UNIT, "path": unit.display().to_string()},
            "status": current,
            "pair": paired.as_ref().map(pair::to_json),
            "linger": linger,
            "key": source.label(),
        });
        println!("{value}");
        return Ok(0);
    }
    println!();
    status::print_text(&current);
    if let Some(paired) = &paired {
        println!();
        pair::print_text(paired);
    }
    if linger == Some(false) {
        let user = std::env::var("USER").unwrap_or_else(|_| "$USER".to_owned());
        println!();
        println!(
            "Linger is off: the node runs only while you are logged in. To start it at boot, run: {}",
            service::linger_command(&printable(&user))
        );
    }
    Ok(0)
}

/// `apassy uninstall [--json] [--data-dir DIR]`: stops the service and removes its unit.
/// The node's files stay: the key and the teams of the paired devices.
pub fn uninstall(args: &[String]) -> Result<i32, NodeCliError> {
    let options = parse_options(args, &[], &[])?;
    let dir = node_dir(&options)?;
    if !cfg!(target_os = "linux") {
        return Err(NodeCliError::usage(format!(
            "`{PROGRAM} uninstall` removes a systemd user service, so it is for Linux. Stop a node here with `{PROGRAM} serve --stop`."
        )));
    }
    let removed = service::uninstall_node_unit().map_err(from_cli)?;
    if options.json {
        println!(
            "{}",
            json!({"ok": true, "unit": service::NODE_UNIT, "removed": removed, "data_dir": dir.display().to_string()})
        );
        return Ok(0);
    }
    if removed {
        println!("Stopped and removed {}.", service::NODE_UNIT);
    } else {
        println!("{} was not installed.", service::NODE_UNIT);
    }
    println!(
        "The node's files stay in {}: its key and the teams of your devices. Remove them only when no device uses this node.",
        dir.display()
    );
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DEFAULT_PUSH_GATEWAY;

    fn options(text: &str) -> super::super::Options {
        let args: Vec<String> = text.split_whitespace().map(str::to_owned).collect();
        parse_options(&args, &VALUES, &FLAGS).unwrap()
    }

    #[test]
    fn the_options_change_the_settings() {
        let changed = apply_options(
            NodeSettings::default(),
            &options("--port 9444 --route serve-tcp --no-push"),
        )
        .unwrap();
        assert_eq!(changed.port, 9444);
        assert_eq!(changed.route, Route::ServeTcp);
        assert_eq!(changed.push_gateway, None);
        let gateway = apply_options(
            NodeSettings::default(),
            &options("--push-gateway https://push.example.com"),
        )
        .unwrap();
        assert_eq!(
            gateway.push_gateway.as_deref(),
            Some("https://push.example.com")
        );
        let same = apply_options(NodeSettings::default(), &options("")).unwrap();
        assert_eq!(same.push_gateway.as_deref(), Some(DEFAULT_PUSH_GATEWAY));
    }

    #[test]
    fn bad_options_are_refused() {
        for bad in [
            "--port 0",
            "--port 70000",
            "--port 443",
            "--route lan",
            "--push-gateway https://push.example.com --no-push",
            "--push-gateway http://push.example.com",
        ] {
            assert!(
                apply_options(NodeSettings::default(), &options(bad)).is_err(),
                "{bad}"
            );
        }
    }
}
