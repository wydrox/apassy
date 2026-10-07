//! Where the synced copy of a vault lives (ADR 0022, design section 2).
//!
//! One engine, two transports. The engine merges a remote copy that changed and pushes
//! when the vault has content that the copy lacks. A transport only moves the bytes:
//!
//! - [`FolderTransport`]: a file in a folder that a sync service keeps in step
//!   (ADR 0014). It has no versions; the hash of the file is its identity, and a push
//!   ignores the precondition (version vectors keep it safe).
//! - [`super::RelayTransport`]: the Apassy relay. Each copy has a version and a signed
//!   head; a push is a compare-and-swap on the version.
//!
//! [`Transport`] holds either one, so a caller keeps a plain value.

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::folder::{self, Probe};
use super::relay::RelayTransport;
use super::relay_crypto::SignedHead;
use super::{SyncError, TempFile, copy_cloud_to_new, copy_to_new, directory, start_download};
use crate::vault::to_hex;

/// What a transport knows about the remote copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteHead {
    /// The version of the copy. Always 0 for a folder: its hash is its identity.
    pub version: u64,
    /// SHA-256 of the bytes of the copy.
    pub sha256: [u8; 32],
    /// The number of bytes. 0 when the transport does not know it (a folder).
    pub size: u64,
    /// The signed head of a relay copy. `None` for a folder.
    pub signed: Option<Box<SignedHead>>,
}

/// The remote side of a sync.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Remote {
    /// No copy yet. A push writes the first one.
    Empty,
    /// A copy.
    Head(RemoteHead),
    /// The folder or the relay is not there now.
    Unavailable,
    /// The copy exists but is not ready to read: iCloud has not downloaded it yet.
    NotReady,
}

/// The condition of a push.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Precondition {
    /// There is no copy yet.
    Absent,
    /// The copy has this version.
    Version(u64),
    /// Any copy. A folder push uses it.
    Any,
}

/// The moves of a sync. [`SyncError::PreconditionFailed`] from [`Self::put`] means that
/// another Mac pushed first: the engine fetches, merges, and pushes again.
pub trait SyncTransport {
    /// Look at the remote copy. No change to any file.
    fn head(&self) -> Result<Remote, SyncError>;
    /// Copy the remote copy of `head` to the new private file `dest`. Returns the open
    /// file and the lowercase hexadecimal SHA-256 of the bytes that arrived. The relay
    /// checks them against the head; a folder file can change after [`Self::head`], so
    /// the engine uses the hash of the bytes it read.
    fn fetch(&self, head: &RemoteHead, dest: &Path) -> Result<(File, String), SyncError>;
    /// Publish the local file `file`, whose SHA-256 is `sha256`, as the new copy, when
    /// `expect` holds.
    fn put(
        &self,
        file: &Path,
        sha256: &[u8; 32],
        expect: Precondition,
    ) -> Result<RemoteHead, SyncError>;
    /// Wait up to `timeout` for a copy newer than version `since`. Returns whether the
    /// caller should look now.
    fn wait_for_change(&self, since: u64, timeout: Duration) -> Result<bool, SyncError>;
}

/// The synced file `<folder>/<name>` (ADR 0014).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderTransport {
    folder: PathBuf,
    name: String,
}

impl FolderTransport {
    pub fn new(folder: &Path, name: &str) -> Self {
        Self {
            folder: folder.to_owned(),
            name: name.to_owned(),
        }
    }

    /// The path of the synced file.
    pub fn file_path(&self) -> PathBuf {
        self.folder.join(&self.name)
    }

    /// Make the synced folder when its parent exists.
    pub(super) fn ensure_folder(&self) -> Result<(), SyncError> {
        match folder::folder_missing(&self.folder)? {
            None => Ok(()),
            Some(Probe::NoFolder) => match fs::create_dir(&self.folder) {
                Ok(()) => Ok(()),
                Err(io_err) if io_err.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
                Err(_) => Err(SyncError::Io),
            },
            Some(_) => Err(SyncError::FolderUnavailable),
        }
    }

    /// Copy `file` to `<name>.apassy.push.nosync` in the synced folder, sync it, rename
    /// it to the file name, and flush the folder with `flush_directory`.
    pub(super) fn put_with(
        &self,
        file: &Path,
        sha256: &[u8; 32],
        flush_directory: impl FnOnce(&Path) -> Result<(), SyncError>,
    ) -> Result<RemoteHead, SyncError> {
        let mut temp = TempFile::new(self.folder.join(format!(
            "{}{}",
            self.name,
            folder::PUSH_SUFFIX
        )))?;
        let (_held, hash) = copy_to_new(file, &temp.path)?;
        if hash != to_hex(sha256) {
            return Err(SyncError::Io);
        }
        fs::rename(&temp.path, self.file_path()).map_err(|_| SyncError::Io)?;
        temp.keep = true;
        flush_directory(&self.folder)?;
        Ok(RemoteHead {
            version: 0,
            sha256: *sha256,
            size: 0,
            signed: None,
        })
    }
}

impl SyncTransport for FolderTransport {
    /// A missing folder whose parent exists is made. A file that iCloud has not
    /// downloaded gets a download request.
    fn head(&self) -> Result<Remote, SyncError> {
        match folder::probe(&self.folder, &self.name)? {
            Probe::Present(path) => {
                let hash = super::file_sha256(&path)?;
                let sha256 = super::relay_crypto::hash_from_hex(&hash).ok_or(SyncError::Io)?;
                Ok(Remote::Head(RemoteHead {
                    version: 0,
                    sha256,
                    size: 0,
                    signed: None,
                }))
            }
            Probe::Missing => Ok(Remote::Empty),
            Probe::NoFolder => {
                self.ensure_folder()?;
                Ok(Remote::Empty)
            }
            Probe::Evicted(path) => {
                start_download(&path);
                Ok(Remote::NotReady)
            }
            Probe::Unavailable => Ok(Remote::Unavailable),
        }
    }

    fn fetch(&self, _head: &RemoteHead, dest: &Path) -> Result<(File, String), SyncError> {
        copy_cloud_to_new(&self.file_path(), dest)
    }

    /// The precondition does not count: version vectors keep a folder push safe.
    fn put(
        &self,
        file: &Path,
        sha256: &[u8; 32],
        _expect: Precondition,
    ) -> Result<RemoteHead, SyncError> {
        self.put_with(file, sha256, directory::sync)
    }

    /// A folder gives no notice of a change: wait, then tell the caller to look.
    fn wait_for_change(&self, _since: u64, timeout: Duration) -> Result<bool, SyncError> {
        std::thread::sleep(timeout);
        Ok(true)
    }
}

/// The transport of one vault.
#[derive(Debug, Clone)]
pub enum Transport {
    Folder(FolderTransport),
    Relay(RelayTransport),
}

impl SyncTransport for Transport {
    fn head(&self) -> Result<Remote, SyncError> {
        match self {
            Self::Folder(folder) => folder.head(),
            Self::Relay(relay) => relay.head(),
        }
    }

    fn fetch(&self, head: &RemoteHead, dest: &Path) -> Result<(File, String), SyncError> {
        match self {
            Self::Folder(folder) => folder.fetch(head, dest),
            Self::Relay(relay) => relay.fetch(head, dest),
        }
    }

    fn put(
        &self,
        file: &Path,
        sha256: &[u8; 32],
        expect: Precondition,
    ) -> Result<RemoteHead, SyncError> {
        match self {
            Self::Folder(folder) => folder.put(file, sha256, expect),
            Self::Relay(relay) => relay.put(file, sha256, expect),
        }
    }

    fn wait_for_change(&self, since: u64, timeout: Duration) -> Result<bool, SyncError> {
        match self {
            Self::Folder(folder) => folder.wait_for_change(since, timeout),
            Self::Relay(relay) => relay.wait_for_change(since, timeout),
        }
    }
}
