//! Path rules of a proxied run in the Linux sandbox (ADR 0011 stage 2, unit X1).
//!
//! A network namespace stops TCP and UDP, not Unix sockets. A run that sees a host
//! folder with a socket of another program (an SSH or GPG agent in `/tmp`, the
//! session bus in `/run/user/<uid>`, a Docker socket in `/run`) can connect to it
//! and leave its namespace. The sandbox hides `/tmp`, `/var/tmp`, `/run`, and the
//! home folder, but a bind of the working directory or of a `PATH` folder shows a
//! part of them again. So a run:
//!
//! - never has its working directory in a shared folder ([`SHARED_ROOTS`]), in
//!   the home folder itself, or above a denied path ([`check_work_dir`]);
//! - never gets a `PATH` folder in a shared folder ([`in_shared_root`]);
//! - always has `/run/user/<real uid>` denied ([`runtime_dir_of`]), whatever
//!   `XDG_RUNTIME_DIR` says.
//!
//! The functions are pure (no file system), so they are tested on every system.
//! The callers resolve the paths first.

use std::path::{Path, PathBuf};

/// Folders that many programs share and keep sockets in.
pub(crate) const SHARED_ROOTS: [&str; 4] = ["/tmp", "/var/tmp", "/run", "/dev/shm"];

/// The shared folders as given and, where it differs, resolved on this computer.
pub(crate) fn shared_roots() -> Vec<PathBuf> {
    let mut out = Vec::new();
    for root in SHARED_ROOTS {
        let given = PathBuf::from(root);
        if let Ok(real) = std::fs::canonicalize(&given)
            && real != Path::new("/")
            && !out.contains(&real)
        {
            out.push(real);
        }
        if !out.contains(&given) {
            out.push(given);
        }
    }
    out
}

/// The runtime folder of the user `uid`: `/run/user/<uid>`.
pub(crate) fn runtime_dir_of(uid: u32) -> PathBuf {
    Path::new("/run/user").join(uid.to_string())
}

/// True when `path` is one of `roots` or inside one.
pub(crate) fn in_shared_root(path: &Path, roots: &[PathBuf]) -> bool {
    roots.iter().any(|root| path.starts_with(root))
}

/// Why a folder cannot be the working directory of a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WorkDirRefusal {
    /// In a shared folder such as `/tmp`.
    Shared { root: PathBuf },
    /// The home folder itself.
    Home,
    /// It holds a path that a run never sees.
    AboveDenied { denied: PathBuf },
}

impl WorkDirRefusal {
    /// The text for the user: what is wrong and which folder to use instead.
    pub(crate) fn message(&self, cwd: &Path, home: &Path) -> String {
        let instead = home.join("projects").join("<name>");
        match self {
            WorkDirRefusal::Shared { root } => format!(
                "the working directory {} is in {}, a folder that other programs share and keep sockets in; a run there could reach them past its network rule. Run it from a project folder in your home folder instead, for example {}",
                cwd.display(),
                root.display(),
                instead.display()
            ),
            WorkDirRefusal::Home => format!(
                "the working directory {} is your home folder; a run there would see the sockets and keys of the whole home folder. Run it from a project folder inside it instead, for example {}",
                cwd.display(),
                instead.display()
            ),
            WorkDirRefusal::AboveDenied { denied } => format!(
                "the working directory {} holds {}, which a run never sees. Run it from a project folder that does not hold it instead, for example {}",
                cwd.display(),
                denied.display(),
                instead.display()
            ),
        }
    }
}

/// Can `cwd` be the working directory (and the writable folder) of a run? Each
/// path should be resolved; `denied` may hold both forms of a path.
pub(crate) fn check_work_dir(
    cwd: &Path,
    home: &Path,
    roots: &[PathBuf],
    denied: &[PathBuf],
) -> Result<(), WorkDirRefusal> {
    if let Some(root) = roots.iter().find(|root| cwd.starts_with(root)) {
        return Err(WorkDirRefusal::Shared { root: root.clone() });
    }
    if cwd == home {
        return Err(WorkDirRefusal::Home);
    }
    if let Some(denied) = denied.iter().find(|denied| denied.starts_with(cwd)) {
        return Err(WorkDirRefusal::AboveDenied {
            denied: denied.clone(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roots() -> Vec<PathBuf> {
        SHARED_ROOTS.iter().map(PathBuf::from).collect()
    }

    fn denied() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/home/dev/.ssh"),
            PathBuf::from("/home/dev/.config/apassy"),
            runtime_dir_of(1000),
        ]
    }

    #[test]
    fn a_work_dir_in_a_shared_folder_is_refused() {
        let home = Path::new("/home/dev");
        for (cwd, root) in [
            ("/tmp", "/tmp"),
            ("/tmp/project", "/tmp"),
            ("/var/tmp/build", "/var/tmp"),
            ("/run/user/1000/x", "/run"),
            ("/dev/shm/work", "/dev/shm"),
        ] {
            let refusal = check_work_dir(Path::new(cwd), home, &roots(), &denied()).expect_err(cwd);
            assert_eq!(
                refusal,
                WorkDirRefusal::Shared {
                    root: PathBuf::from(root)
                },
                "{cwd}"
            );
            let text = refusal.message(Path::new(cwd), home);
            assert!(text.contains(root), "{text}");
            assert!(text.contains("/home/dev/projects/<name>"), "{text}");
        }
        // A name that only starts like a shared folder is not in it.
        assert_eq!(
            check_work_dir(Path::new("/tmpfiles/x"), home, &roots(), &denied()),
            Ok(())
        );
    }

    #[test]
    fn the_home_folder_itself_is_refused() {
        let home = Path::new("/home/dev");
        let refusal = check_work_dir(home, home, &roots(), &denied()).expect_err("home");
        assert_eq!(refusal, WorkDirRefusal::Home);
        let text = refusal.message(home, home);
        assert!(text.contains("home folder"), "{text}");
        assert!(text.contains("/home/dev/projects/<name>"), "{text}");
        assert_eq!(
            check_work_dir(
                Path::new("/home/dev/projects/app"),
                home,
                &roots(),
                &denied()
            ),
            Ok(())
        );
    }

    #[test]
    fn a_work_dir_above_a_denied_path_is_refused() {
        let home = Path::new("/home/dev");
        let refusal = check_work_dir(Path::new("/home/dev/.config"), home, &roots(), &denied())
            .expect_err("above the Apassy configuration");
        assert_eq!(
            refusal,
            WorkDirRefusal::AboveDenied {
                denied: PathBuf::from("/home/dev/.config/apassy")
            }
        );
        let text = refusal.message(Path::new("/home/dev/.config"), home);
        assert!(text.contains("/home/dev/.config/apassy"), "{text}");
        // The denied path itself counts too.
        assert!(check_work_dir(Path::new("/home/dev/.ssh"), home, &roots(), &denied()).is_err());
        // Above the home folder: the home holds the denied paths.
        assert!(check_work_dir(Path::new("/home"), home, &roots(), &denied()).is_err());
    }

    #[test]
    fn path_folders_in_shared_folders_are_found() {
        for path in [
            "/tmp/bin",
            "/var/tmp/tools/bin",
            "/run/wrappers/bin",
            "/dev/shm/x",
        ] {
            assert!(in_shared_root(Path::new(path), &roots()), "{path}");
        }
        for path in [
            "/usr/bin",
            "/home/dev/.local/bin",
            "/nix/store/x/bin",
            "/tmpx/bin",
        ] {
            assert!(!in_shared_root(Path::new(path), &roots()), "{path}");
        }
    }

    #[test]
    fn the_runtime_folder_follows_the_uid() {
        assert_eq!(runtime_dir_of(1000), Path::new("/run/user/1000"));
        assert_eq!(runtime_dir_of(0), Path::new("/run/user/0"));
        let roots = shared_roots();
        assert!(roots.contains(&PathBuf::from("/tmp")), "{roots:?}");
    }
}
