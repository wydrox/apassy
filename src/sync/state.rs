//! The local sync state of one vault: a small JSON file under the Apassy data folder.
//!
//! The file has no secret: the name of the synced file, the vault ID, the SHA-256 of
//! the synced file after the last sync, and the synced-content digest of the vault at
//! that time. It is still protected (mode `0600`, inside the data folder that the
//! Seatbelt profile denies).

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::SyncError;
use super::folder::valid_file_name;
use crate::vault::sync_dir;

/// The format of the state file.
const STATE_FORMAT: u32 = 2;
/// A state file is small. A larger file is damaged.
const MAX_STATE_BYTES: u64 = 64 * 1024;

/// What this Mac knows about the last sync of one vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncState {
    /// The format of this file. Now 2.
    pub format: u32,
    /// The name of the vault file in the synced folder, for example `Personal.apassy`.
    pub file_name: String,
    /// The vault ID from the sync record of the vault (schema 13).
    pub vault_id: String,
    /// Lowercase hexadecimal SHA-256 of the synced file after the last merge or push. A
    /// file with another hash changed since then.
    pub last_file_sha256: Option<String>,
    /// Lowercase hexadecimal synced-content digest of the vault after the last sync. A
    /// vault with another digest has changes to push.
    pub last_content: Option<String>,
    /// The time of the last sync, in Unix seconds.
    pub last_sync_at: Option<u64>,
    /// The local vault file of this state. The app uses it to link the state to its
    /// vault again after the vault list was rebuilt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_path: Option<PathBuf>,
    /// The synced folder, for the same purpose.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder: Option<PathBuf>,
}

impl SyncState {
    pub(super) fn new(file_name: &str, vault_id: &str) -> Self {
        Self {
            format: STATE_FORMAT,
            file_name: file_name.to_owned(),
            vault_id: vault_id.to_owned(),
            last_file_sha256: None,
            last_content: None,
            last_sync_at: None,
            vault_path: None,
            folder: None,
        }
    }

    fn is_valid(&self) -> bool {
        let hex = |text: &str| {
            text.len() == 64
                && text
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        };
        self.format == STATE_FORMAT
            && valid_file_name(&self.file_name)
            && self.vault_id.len() == 36
            && self.vault_id.is_ascii()
            && self.last_file_sha256.as_deref().is_none_or(hex)
            && self.last_content.as_deref().is_none_or(hex)
    }
}

/// Read the state file. `None` when it does not exist.
pub(super) fn read(path: &Path) -> Result<Option<SyncState>, SyncError> {
    let mut file = match OpenOptions::new().read(true).open(path) {
        Ok(file) => file,
        Err(io_err) if io_err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(SyncError::Io),
    };
    let mut text = String::new();
    Read::by_ref(&mut file)
        .take(MAX_STATE_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|_| SyncError::State)?;
    if u64::try_from(text.len()).unwrap_or(u64::MAX) > MAX_STATE_BYTES {
        return Err(SyncError::State);
    }
    let state: SyncState = serde_json::from_str(&text).map_err(|_| SyncError::State)?;
    if state.is_valid() {
        Ok(Some(state))
    } else {
        Err(SyncError::State)
    }
}

/// Write the state file atomically: a new file with mode `0600` next to it, synced,
/// then renamed over the old file. The parent directory is made with mode `0700` when
/// it does not exist.
pub(super) fn write(path: &Path, state: &SyncState) -> Result<(), SyncError> {
    if !state.is_valid() {
        return Err(SyncError::State);
    }
    let dir = path.parent().ok_or(SyncError::Io)?;
    ensure_private_dir(dir)?;
    let mut temp_name = path.as_os_str().to_os_string();
    temp_name.push(".tmp");
    let temp = std::path::PathBuf::from(temp_name);
    remove_if_present(&temp)?;
    let text = serde_json::to_vec_pretty(state).map_err(|_| SyncError::State)?;
    let written = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .and_then(|mut file| {
            file.write_all(&text)?;
            file.write_all(b"\n")?;
            file.sync_all()
        })
        .and_then(|()| fs::rename(&temp, path))
        .and_then(|()| sync_dir(dir));
    if written.is_err() {
        let _ = fs::remove_file(&temp);
        return Err(SyncError::Io);
    }
    Ok(())
}

/// Remove the state file. Return whether it existed.
pub(super) fn remove(path: &Path) -> Result<bool, SyncError> {
    match fs::remove_file(path) {
        Ok(()) => {
            if let Some(dir) = path.parent() {
                let _ = sync_dir(dir);
            }
            Ok(true)
        }
        Err(io_err) if io_err.kind() == ErrorKind::NotFound => Ok(false),
        Err(_) => Err(SyncError::Io),
    }
}

/// Make `dir` and its missing parents with mode `0700`.
pub(super) fn ensure_private_dir(dir: &Path) -> Result<(), SyncError> {
    if dir.is_dir() {
        return Ok(());
    }
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|_| SyncError::Io)
}

/// Remove a file that Apassy left earlier. A missing file is fine.
pub(super) fn remove_if_present(path: &Path) -> Result<(), SyncError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(io_err) if io_err.kind() == ErrorKind::NotFound => Ok(()),
        Err(_) => Err(SyncError::Io),
    }
}
