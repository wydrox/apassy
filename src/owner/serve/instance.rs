//! One owner process for each data directory: the desktop window or
//! `apassy owner serve`, never both (ADR 0045).
//!
//! The owner process holds an exclusive `flock` on `owner.lock` in the data directory
//! for as long as it runs. The kernel releases the lock when the process ends, also
//! after a signal, so a stale file never blocks a new start. The browser host and the
//! agents find whichever owner process runs: both bind the same sockets of the same
//! data directory.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use rustix::fs::{FlockOperation, OFlags, flock};

/// The lock file in the data directory.
pub const LOCK_FILE: &str = "owner.lock";

/// The held lock. Drop releases it.
#[derive(Debug)]
pub struct OwnerInstance {
    _file: File,
    path: PathBuf,
}

/// Why the lock was not taken.
#[derive(Debug)]
pub enum InstanceError {
    /// Another owner process holds the lock.
    Running(PathBuf),
    Io(io::Error),
}

impl std::fmt::Display for InstanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Running(dir) => write!(
                f,
                "Another Apassy owner process (the desktop app or `apassy owner serve`) runs for {}. Quit it first; only one owner process may serve a vault.",
                dir.display()
            ),
            Self::Io(err) => write!(f, "The owner lock did not open: {err}"),
        }
    }
}

impl std::error::Error for InstanceError {}

impl OwnerInstance {
    /// Take the lock of `data_dir`. The directory is made with mode `0700` when it is
    /// missing; an existing directory must have mode `0700` and must not be a link.
    pub fn acquire(data_dir: &Path) -> Result<Self, InstanceError> {
        let path = data_dir.join(LOCK_FILE);
        crate::broker::server::prepare_directory(&path).map_err(InstanceError::Io)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(OFlags::NOFOLLOW.bits() as i32)
            .open(&path)
            .map_err(InstanceError::Io)?;
        match flock(&file, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => Ok(Self { _file: file, path }),
            Err(err) if err == rustix::io::Errno::WOULDBLOCK => {
                Err(InstanceError::Running(data_dir.to_path_buf()))
            }
            Err(err) => Err(InstanceError::Io(err.into())),
        }
    }

    /// The path of the lock file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_second_owner_is_refused_until_the_first_ends() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        let first = OwnerInstance::acquire(&data).unwrap();
        let second = OwnerInstance::acquire(&data).unwrap_err();
        assert!(matches!(second, InstanceError::Running(_)), "{second}");
        assert!(second.to_string().contains("Another Apassy owner process"));
        drop(first);
        assert!(OwnerInstance::acquire(&data).is_ok());
    }
}
