//! The systemd user service of the node without a window (plan D8, unit L2).
//!
//! `apassy up` writes `~/.config/systemd/user/apassy-node.service` (or under
//! `$XDG_CONFIG_HOME`): `ExecStart=<exe> serve`, `ExecStop=<exe> serve --stop`,
//! `Restart=on-failure`, `WantedBy=default.target`, and, when the master key is an
//! encrypted credential (`keys::CREDENTIAL_FILE`),
//! `LoadCredentialEncrypted=apassy-node-key:<node dir>/master.key.cred`: systemd decrypts
//! it into `$CREDENTIALS_DIRECTORY/apassy-node-key` for the service only, and `serve`
//! reads it there (`keys`). Then `systemctl --user daemon-reload`, `enable --now`, and
//! `restart`. `apassy uninstall` reverses it and keeps the node's files.
//!
//! The `.deb` installs `packaging/linux/apassy-node.service` in `/usr/lib/systemd/user/`:
//! it is the unit of `/usr/bin/apassy` with the default data directory and the key file.
//! The unit that `apassy up` writes has the same name and, in the user's configuration
//! directory, takes precedence over it.
//!
//! Linger (`loginctl enable-linger`) needs root or a logind policy, so it stays an owner
//! step: `up` prints `linger_command` when it is off, and `doctor` checks it.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use crate::cli::CliError;
use crate::cli::service::{command, require_success, unit_path, write_service};

pub use crate::cli::service::user_unit_dir;

use super::keys::CREDENTIAL_NAME;

/// The systemd user unit of the node.
pub const NODE_UNIT: &str = "apassy-node.service";
/// The program of the packaged unit (`.deb`, `/usr/lib/systemd/user/apassy-node.service`).
pub const PACKAGED_EXE: &str = "/usr/bin/apassy";

/// The user unit of the node (plan D8): `ExecStart=<exe> serve`, and
/// `ExecStop=<exe> serve --stop`, which stops the TLS front before the relay and returns
/// when the node has stopped (the node installs no signal handler; see
/// `crate::node::serve`). `data_dir` is the node directory when it is not the default.
/// `credential` is the encrypted master key (`master.key.cred`), when there is one.
/// No file writes, environment reads, or service commands.
pub fn generate_node_unit(
    exe: &Path,
    data_dir: Option<&Path>,
    credential: Option<&Path>,
) -> Result<String, CliError> {
    let exe = unit_path(exe)?;
    let data = match data_dir {
        Some(dir) => format!(" --data-dir {}", unit_path(dir)?),
        None => String::new(),
    };
    let credential = match credential {
        Some(path) => format!(
            "LoadCredentialEncrypted={CREDENTIAL_NAME}:{}\n",
            unit_path(path)?
        ),
        None => String::new(),
    };
    Ok(format!(
        "[Unit]\nDescription=Apassy node\nDocumentation=https://github.com/wydrox/apassy/blob/main/docs/operations/linux-node.md\n\n[Service]\nType=simple\nExecStart={exe} serve{data}\nExecStop={exe} serve --stop{data}\n{credential}Restart=on-failure\nRestartSec=10\nTimeoutStopSec=20\nUMask=0077\nNoNewPrivileges=yes\n\n[Install]\nWantedBy=default.target\n"
    ))
}

/// True when `path` can stand in a unit line (an absolute path of letters, digits, and
/// `/._-`): the credential is used only then.
pub fn fits_a_unit(path: &Path) -> bool {
    unit_path(path).is_ok()
}

/// `~/.config/systemd/user/apassy-node.service` (or under `$XDG_CONFIG_HOME`).
pub fn node_unit_path() -> Result<PathBuf, CliError> {
    Ok(user_unit_dir()?.join(NODE_UNIT))
}

/// Writes the node unit (mode 0644, through a temporary file) and returns its path.
pub fn write_node_unit(text: &str) -> Result<PathBuf, CliError> {
    let path = node_unit_path()?;
    write_service(&path, text)?;
    Ok(path)
}

/// `systemctl --user daemon-reload`, `enable --now`, and `restart` of the node unit: an
/// edit of the unit takes effect, and a node that runs starts again with it.
pub fn start_node_unit() -> Result<(), CliError> {
    require_success(
        "systemctl daemon-reload",
        command("systemctl", &["--user", "daemon-reload"])?,
    )?;
    require_success(
        "systemctl enable",
        command("systemctl", &["--user", "enable", "--now", NODE_UNIT])?,
    )?;
    require_success(
        "systemctl restart",
        command("systemctl", &["--user", "restart", NODE_UNIT])?,
    )
}

/// `systemctl --user disable --now` of the node unit (its `ExecStop=` stops the node),
/// then the unit file goes and systemd reloads. `Ok(false)`: no unit was installed. The
/// node's files (the key, the teams) stay.
pub fn uninstall_node_unit() -> Result<bool, CliError> {
    let path = node_unit_path()?;
    let installed = fs::symlink_metadata(&path).is_ok();
    // A unit that systemd does not know makes `disable` fail: nothing to stop then.
    let _ = command("systemctl", &["--user", "disable", "--now", NODE_UNIT]);
    if installed {
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(CliError::usage(format!(
                    "Cannot remove {}: {}.",
                    path.display(),
                    error.kind()
                )));
            }
        }
    }
    require_success(
        "systemctl daemon-reload",
        command("systemctl", &["--user", "daemon-reload"])?,
    )?;
    Ok(installed)
}

/// The command that turns linger on for `user`: the node then starts at boot without a
/// login. It needs root, so `up` prints it and never runs it.
pub fn linger_command(user: &str) -> String {
    format!("sudo loginctl enable-linger {user}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_node_unit_serves_and_stops_through_the_control_socket() {
        let unit = generate_node_unit(Path::new("/usr/bin/apassy"), None, None).unwrap();
        assert!(
            unit.contains("\nExecStart=/usr/bin/apassy serve\n"),
            "{unit}"
        );
        assert!(
            unit.contains("\nExecStop=/usr/bin/apassy serve --stop\n"),
            "{unit}"
        );
        assert!(unit.contains("\nRestart=on-failure\n"), "{unit}");
        assert!(unit.contains("\nWantedBy=default.target\n"), "{unit}");
        assert!(unit.contains("\nUMask=0077\n"), "{unit}");
        // No secret and no environment in the unit.
        assert!(!unit.contains("Environment="), "{unit}");
        assert!(!unit.contains("Credential"), "{unit}");
        let custom = generate_node_unit(
            Path::new("/opt/apassy/bin/apassy"),
            Some(Path::new("/srv/node")),
            None,
        )
        .unwrap();
        assert!(
            custom.contains("\nExecStart=/opt/apassy/bin/apassy serve --data-dir /srv/node\n"),
            "{custom}"
        );
        assert!(
            custom
                .contains("\nExecStop=/opt/apassy/bin/apassy serve --stop --data-dir /srv/node\n"),
            "{custom}"
        );
        for bad in ["relative/apassy", "/opt/my apassy", "/opt/%h/apassy"] {
            assert!(
                generate_node_unit(Path::new(bad), None, None).is_err(),
                "{bad}"
            );
        }
        assert!(
            generate_node_unit(Path::new("/usr/bin/apassy"), Some(Path::new("/a b")), None)
                .is_err()
        );
    }

    #[test]
    fn an_encrypted_key_is_loaded_as_a_credential() {
        let unit = generate_node_unit(
            Path::new("/usr/bin/apassy"),
            None,
            Some(Path::new(
                "/home/me/.local/share/apassy/node/master.key.cred",
            )),
        )
        .unwrap();
        assert!(
            unit.contains(
                "\nLoadCredentialEncrypted=apassy-node-key:/home/me/.local/share/apassy/node/master.key.cred\n"
            ),
            "{unit}"
        );
        // The credential line is in [Service], before [Install].
        let service = unit.find("[Service]").unwrap();
        let install = unit.find("[Install]").unwrap();
        let line = unit.find("LoadCredentialEncrypted=").unwrap();
        assert!(service < line && line < install, "{unit}");
        for bad in [
            "/home/my node/master.key.cred",
            "relative.cred",
            "/x/%h.cred",
        ] {
            assert!(
                generate_node_unit(Path::new("/usr/bin/apassy"), None, Some(Path::new(bad)))
                    .is_err(),
                "{bad}"
            );
            assert!(!fits_a_unit(Path::new(bad)), "{bad}");
        }
    }

    #[test]
    fn the_packaged_unit_is_the_generated_unit_of_usr_bin_apassy() {
        let packaged = include_str!("../../../../packaging/linux/apassy-node.service");
        let generated = generate_node_unit(Path::new(PACKAGED_EXE), None, None).unwrap();
        assert_eq!(packaged, generated);
    }

    #[test]
    fn the_linger_command_names_the_user() {
        assert_eq!(linger_command("me"), "sudo loginctl enable-linger me");
    }
}
