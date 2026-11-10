//! Install user-owned links without overwriting another program.
use std::path::Path;
const TOOLS: [&str; 4] = ["apassy", "apassy-mcp", "apassy-hook", "apassy-sandbox"];

/// The command that the Linux vault package installs. The package ships only this
/// command, so the links of the macOS app (`TOOLS`) do not apply on Linux.
#[cfg(any(target_os = "linux", test))]
const PACKAGE_COMMAND: &str = "/usr/bin/apassy";

/// Where the `apassy` command comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Place {
    /// Linux: the package installed [`PACKAGE_COMMAND`].
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Package,
    /// macOS: the links of this app in `~/.local/bin`.
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    Links,
    Missing,
}

/// What Settings > Tools > Command line shows for a [`Place`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Row {
    pub(super) value: &'static str,
    pub(super) footer: &'static str,
    /// "Install tools…": links can be made (macOS only).
    pub(super) install: bool,
}

impl Place {
    pub(super) fn row(self) -> Row {
        match self {
            Self::Package => Row {
                value: "/usr/bin/apassy",
                footer: "Installed by the apassy-vault package. Commands never show a secret value.",
                install: false,
            },
            Self::Links => Row {
                value: "~/.local/bin",
                footer: "In Terminal: add ~/.local/bin to PATH, then run eval \"$(apassy login)\".",
                install: false,
            },
            Self::Missing if cfg!(target_os = "linux") => Row {
                value: "Not installed",
                footer: "Install the apassy-vault package to get the apassy command. Commands never show a secret value.",
                install: false,
            },
            Self::Missing => Row {
                value: "Not installed",
                footer: "Commands never show a secret value.",
                install: true,
            },
        }
    }
}

/// Where the command line comes from on this computer.
pub(super) fn place() -> Place {
    #[cfg(target_os = "linux")]
    {
        package_place(Path::new(PACKAGE_COMMAND))
    }
    #[cfg(not(target_os = "linux"))]
    {
        if links_present() {
            Place::Links
        } else {
            Place::Missing
        }
    }
}

/// True when the command line is installed: by the Linux package, or as the links of
/// this app. This does not establish the terminal PATH or a connection to an agent
/// host.
pub(super) fn installed() -> bool {
    place() != Place::Missing
}

#[cfg(any(target_os = "linux", test))]
fn package_place(command: &Path) -> Place {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(command) {
        Ok(metadata) if metadata.is_file() && metadata.permissions().mode() & 0o111 != 0 => {
            Place::Package
        }
        _ => Place::Missing,
    }
}

/// Check the links this app installs.
#[cfg(not(target_os = "linux"))]
fn links_present() -> bool {
    let Some(exe) = std::env::current_exe()
        .ok()
        .and_then(|path| std::fs::canonicalize(path).ok())
    else {
        return false;
    };
    let Some(source) = exe.parent() else {
        return false;
    };
    let Some(home) = std::env::var_os("HOME") else {
        return false;
    };
    links_installed(source, &Path::new(&home).join(".local/bin"))
}

#[cfg(any(not(target_os = "linux"), test))]
fn links_installed(source: &Path, destination: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    TOOLS.iter().all(|name| {
        let target = source.join(name);
        std::fs::read_link(destination.join(name)).ok().as_deref() == Some(target.as_path())
            && std::fs::metadata(&target).is_ok_and(|metadata| {
                metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
            })
    })
}

pub(super) fn install() -> Result<(), String> {
    let exe = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .map_err(|e| format!("Cannot locate Apassy: {e}"))?;
    let source = exe.parent().ok_or("Cannot locate the app tools.")?;
    let home = std::env::var_os("HOME").ok_or("Cannot locate your home folder.")?;
    install_in(source, &Path::new(&home).join(".local/bin"))
}

fn install_in(source: &Path, destination: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    // Validate the entire set before making any links.
    for name in TOOLS {
        let target = source.join(name);
        if !target.is_file() {
            return Err(format!(
                "The app package is missing {name}. Reinstall the complete Apassy.app package."
            ));
        }
        let metadata = std::fs::metadata(&target)
            .map_err(|e| format!("Cannot check {}: {e}", target.display()))?;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(format!(
                "The app tool {name} is not executable. Reinstall the complete Apassy.app package."
            ));
        }
        let link = destination.join(name);
        match std::fs::symlink_metadata(&link) {
            Ok(_) if std::fs::read_link(&link).ok().as_deref() == Some(target.as_path()) => {}
            Ok(_) => {
                return Err(format!(
                    "{} already exists. No commands were replaced. Move that file or choose another installation folder.",
                    link.display()
                ));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("Cannot check {}: {e}", link.display())),
        }
    }
    std::fs::create_dir_all(destination)
        .map_err(|e| format!("Cannot create {}: {e}", destination.display()))?;
    let mut created = Vec::new();
    for name in TOOLS {
        let target = source.join(name);
        let link = destination.join(name);
        if std::fs::read_link(&link).ok().as_deref() == Some(target.as_path()) {
            continue;
        }
        if let Err(e) = std::os::unix::fs::symlink(&target, &link) {
            for path in created {
                let _ = std::fs::remove_file(path);
            }
            return Err(format!(
                "Cannot install {}: {e}. No existing commands were replaced.",
                link.display()
            ));
        }
        created.push(link);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Linux package installs /usr/bin/apassy: Settings showed "Not installed" and
    /// offered links that the package cannot provide (Linux acceptance, 2026-11-10).
    #[test]
    fn the_package_command_counts_as_installed_and_offers_no_links() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let command = dir.path().join("apassy");
        assert_eq!(package_place(&command), Place::Missing);
        std::fs::write(&command, b"test").unwrap();
        std::fs::set_permissions(&command, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(package_place(&command), Place::Missing, "not executable");
        std::fs::set_permissions(&command, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(package_place(&command), Place::Package);
        assert_eq!(package_place(dir.path()), Place::Missing, "a folder");
        let row = Place::Package.row();
        assert_eq!(row.value, PACKAGE_COMMAND);
        assert!(!row.install);
        assert!(!Place::Links.row().install);
        assert_eq!(Place::Missing.row().value, "Not installed");
        assert_eq!(Place::Missing.row().install, !cfg!(target_os = "linux"));
    }

    #[test]
    fn installation_check_requires_all_links_and_executable_targets() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("app");
        let dest = dir.path().join("bin");
        std::fs::create_dir(&source).unwrap();
        for tool in TOOLS {
            let path = source.join(tool);
            std::fs::write(&path, b"test").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        assert!(!links_installed(&source, &dest));
        install_in(&source, &dest).unwrap();
        assert!(links_installed(&source, &dest));
        std::fs::set_permissions(
            source.join("apassy-hook"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert!(!links_installed(&source, &dest));
        assert!(install_in(&source, &dir.path().join("other-bin")).is_err());
        assert!(!dir.path().join("other-bin").exists());
        std::fs::remove_file(source.join("apassy-hook")).unwrap();
        assert!(!links_installed(&source, &dest));
    }
    #[test]
    fn installation_is_repeatable_and_does_not_replace_existing_commands() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("app");
        let dest = dir.path().join("bin");
        std::fs::create_dir(&source).unwrap();
        std::fs::create_dir(&dest).unwrap();
        for tool in TOOLS {
            std::fs::write(source.join(tool), b"test").unwrap();
            std::fs::set_permissions(source.join(tool), std::fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        std::fs::write(dest.join("apassy-sandbox"), b"existing").unwrap();
        assert!(install_in(&source, &dest).is_err());
        assert!(!dest.join("apassy").exists());
        assert_eq!(
            std::fs::read(dest.join("apassy-sandbox")).unwrap(),
            b"existing"
        );
        std::fs::remove_file(dest.join("apassy-sandbox")).unwrap();
        install_in(&source, &dest).unwrap();
        install_in(&source, &dest).unwrap();
        for tool in TOOLS {
            assert_eq!(
                std::fs::read_link(dest.join(tool)).unwrap(),
                source.join(tool)
            );
        }
    }
}
