//! The local sync state of one vault: a small JSON file under the Apassy data folder.
//!
//! The file has no secret: the name of the synced file, the vault ID, the SHA-256 of
//! the synced file after the last sync, and the synced-content digest of the vault at
//! that time. It is still protected (mode `0600`, inside the data folder that the
//! Seatbelt profile denies).
//!
//! A folder state has format 2. A relay state (ADR 0022) has format 3: it names the
//! relay, the team, the device, and the anchor (the version and the head hash that this
//! Mac saw last) instead of a file. A format 2 file reads as a folder state.

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::SyncError;
use super::folder::valid_file_name;
use crate::vault::sync_dir;

/// The format of a folder state file.
const STATE_FORMAT: u32 = 2;
/// The format of a relay state file (contract relay-sync-v1, section 14.2).
const RELAY_STATE_FORMAT: u32 = 3;
/// A state file is small. A larger file is damaged.
const MAX_STATE_BYTES: u64 = 64 * 1024;

/// Where a vault syncs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportKind {
    /// A folder that a sync service keeps in step (ADR 0014).
    #[default]
    Folder,
    /// The Apassy relay (ADR 0022).
    Relay,
}

impl TransportKind {
    fn is_folder(&self) -> bool {
        *self == Self::Folder
    }
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

/// What this Mac knows about the last sync of one vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncState {
    /// The format of this file: 2 for a folder, 3 for the relay.
    pub format: u32,
    /// Where the vault syncs. A format 2 file has no field: a folder.
    #[serde(default, skip_serializing_if = "TransportKind::is_folder")]
    pub transport: TransportKind,
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
    /// The relay origin of a relay state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_url: Option<String>,
    /// The team of the vault on the relay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
    /// The device number of this Mac on the relay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<u64>,
    /// The anchor: the relay version that this Mac saw last (it pushed or merged it). 0
    /// before the first one.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub last_remote_version: u64,
    /// The anchor: lowercase hexadecimal head hash of that version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_head_sha256: Option<String>,
}

impl SyncState {
    pub(super) fn new(file_name: &str, vault_id: &str) -> Self {
        Self {
            format: STATE_FORMAT,
            transport: TransportKind::Folder,
            file_name: file_name.to_owned(),
            vault_id: vault_id.to_owned(),
            last_file_sha256: None,
            last_content: None,
            last_sync_at: None,
            vault_path: None,
            folder: None,
            relay_url: None,
            team_id: None,
            device_id: None,
            last_remote_version: 0,
            last_head_sha256: None,
        }
    }

    /// A relay state with no anchor yet.
    pub(super) fn new_relay(
        relay_url: &str,
        team_id: &str,
        device_id: u64,
        vault_id: &str,
    ) -> Self {
        Self {
            format: RELAY_STATE_FORMAT,
            transport: TransportKind::Relay,
            relay_url: Some(relay_url.to_owned()),
            team_id: Some(team_id.to_owned()),
            device_id: Some(device_id),
            ..Self::new("", vault_id)
        }
    }

    fn is_valid(&self) -> bool {
        let hex = |text: &str| {
            text.len() == 64
                && text
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        };
        let common = self.vault_id.len() == 36
            && self.vault_id.is_ascii()
            && self.last_file_sha256.as_deref().is_none_or(hex)
            && self.last_content.as_deref().is_none_or(hex);
        let folder = self.transport == TransportKind::Folder
            && matches!(self.format, STATE_FORMAT | RELAY_STATE_FORMAT)
            && valid_file_name(&self.file_name);
        let relay = self.transport == TransportKind::Relay
            && self.format == RELAY_STATE_FORMAT
            && self
                .relay_url
                .as_deref()
                .is_some_and(|url| !url.is_empty() && url.is_ascii())
            && self
                .team_id
                .as_deref()
                .is_some_and(super::relay_crypto::valid_team_id)
            && self.device_id.is_some_and(|id| id >= 1)
            && self.last_head_sha256.as_deref().is_none_or(hex)
            && (self.last_remote_version == 0) == self.last_head_sha256.is_none();
        common && (folder || relay)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_relay_state_round_trips_and_a_format_2_file_is_a_folder() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("sync").join("a.json");
        let vault_id = "0f3c2a10-5b7e-4d9a-8c21-6f0e4b1d9a77";
        let mut relay = SyncState::new_relay("http://127.0.0.1:9", "t_7k2m5q4x3c", 2, vault_id);
        write(&path, &relay).unwrap();
        assert_eq!(read(&path).unwrap(), Some(relay.clone()));
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("\"format\": 3") && text.contains("\"transport\": \"relay\""));
        relay.last_remote_version = 4;
        assert_eq!(
            write(&path, &relay),
            Err(SyncError::State),
            "an anchor needs a hash"
        );
        relay.last_head_sha256 = Some("a".repeat(64));
        write(&path, &relay).unwrap();
        assert_eq!(read(&path).unwrap().unwrap().last_remote_version, 4);

        let folder = SyncState::new("Personal.apassy", vault_id);
        write(&path, &folder).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("\"format\": 2"));
        assert!(
            !text.contains("transport") && !text.contains("relay"),
            "{text}"
        );
        let old = format!(
            "{{\"format\":2,\"file_name\":\"Personal.apassy\",\"vault_id\":\"{vault_id}\",\"last_file_sha256\":null,\"last_content\":null,\"last_sync_at\":null}}"
        );
        fs::write(&path, old).unwrap();
        assert_eq!(
            read(&path).unwrap().unwrap().transport,
            TransportKind::Folder
        );
        let mut bad = SyncState::new_relay("", "t_7k2m5q4x3c", 2, vault_id);
        assert_eq!(write(&path, &bad), Err(SyncError::State));
        bad.relay_url = Some("https://r.example.test".to_owned());
        bad.format = STATE_FORMAT;
        assert_eq!(
            write(&path, &bad),
            Err(SyncError::State),
            "a relay needs format 3"
        );
    }
}
