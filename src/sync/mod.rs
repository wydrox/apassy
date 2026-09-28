//! Sync of a vault through a folder (ADR 0014, `docs/operations/sync.md`).
//!
//! The owner picks a folder that a sync service keeps in step on each Mac: iCloud Drive
//! (the default), Dropbox, Google Drive, OneDrive, Syncthing, or a network share. The
//! folder holds `<name>.apassy`, a closed, encrypted copy of the vault without the data
//! that stays on each Mac (agents, grants, activity, learning). The live vault stays a
//! local file; SQLite never opens a file in the synced folder.
//!
//! - A sync (vault unlocked) reads the synced file through a private local copy and
//!   merges it record by record into the vault with the key of the open connection
//!   ([`crate::vault::Vault::merge_from`]). A credential that both sides changed stays
//!   twice: the older version becomes an archived conflict copy. Then, when the vault
//!   has content that the file does not have, the sync pushes: it writes a stripped copy
//!   in the data folder, copies it to `<name>.apassy.push.nosync` in the synced folder,
//!   syncs it, and renames it to `<name>.apassy`.
//! - A status needs no key: it compares the hash of the file with the hash after the
//!   last sync.
//! - A copy that does not open with the key of the vault means that the passphrase
//!   changed on another Mac. The owner types the new passphrase once
//!   ([`FolderSync::take_new_passphrase`]).
//!
//! The engine does not know the vault list. The caller gives each path in
//! [`SyncConfig`]. One sync covers one [`SyncScope`]: now the whole vault.

mod folder;
mod state;

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::ErrorKind;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

pub use folder::{
    FOLDER_NAME, FolderEntry, PUSH_SUFFIX, SYNC_FILE_EXTENSION, SyncFolder, detect_folders_in,
    file_name_for, list_folder_vaults, start_download,
};
pub use state::SyncState;

use crate::vault::{
    MergeReport, SyncIdentity, SyncScope, Vault, VaultError, VaultErrorKind, copy_hashing,
    hash_open_file, sync_dir, to_hex,
};
use folder::Probe;

/// Enable tries at most this many file names (`Personal.apassy`, `Personal-2.apassy`,
/// ...).
const MAX_NAME_TRIES: u32 = 99;

/// The home directory, or `None` when `HOME` is not set.
fn home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .map(PathBuf::from)
}

/// The Apassy folder in iCloud Drive:
/// `$HOME/Library/Mobile Documents/com~apple~CloudDocs/Apassy`. The folder may not
/// exist yet. `None` on a system without iCloud Drive, or when `HOME` is not set.
#[cfg(target_os = "macos")]
pub fn icloud_folder() -> Option<PathBuf> {
    home().map(|home| folder::icloud_drive(&home).join(FOLDER_NAME))
}

/// There is no iCloud Drive on this system.
#[cfg(not(target_os = "macos"))]
pub fn icloud_folder() -> Option<PathBuf> {
    None
}

/// The synced folders of the owner: iCloud Drive, the folders of
/// `~/Library/CloudStorage`, and `~/Dropbox`, when they exist.
pub fn detect_folders() -> Vec<SyncFolder> {
    home().map_or_else(Vec::new, |home| detect_folders_in(&home))
}

/// The name of this computer for the sync record: `scutil --get ComputerName` on macOS,
/// else the host name, else "Unknown device". Read once for each process.
pub fn device_name() -> String {
    static NAME: OnceLock<String> = OnceLock::new();
    NAME.get_or_init(read_device_name).clone()
}

fn read_device_name() -> String {
    let clean = |text: &str| {
        let text: String = text.trim().chars().filter(|ch| !ch.is_control()).collect();
        (!text.is_empty()).then_some(text)
    };
    let command = |program: &str, args: &[&str]| {
        std::process::Command::new(program)
            .args(args)
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output()
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .and_then(|text| clean(&text))
    };
    if cfg!(target_os = "macos")
        && let Some(name) = command("/usr/sbin/scutil", &["--get", "ComputerName"])
    {
        return name;
    }
    if let Some(name) = fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .and_then(|text| clean(&text))
    {
        return name;
    }
    command("/bin/hostname", &[]).unwrap_or_else(|| "Unknown device".to_owned())
}

/// The paths for the sync of one vault. The engine does not change them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncConfig {
    /// The live local vault file.
    pub vault_path: PathBuf,
    /// The synced folder that holds `<name>.apassy`.
    pub folder: PathBuf,
    /// The local sync state file (JSON). Keep it in the Apassy data folder, which the
    /// Seatbelt profile denies.
    pub state_path: PathBuf,
    /// A private folder for the copies that a merge reads and a push strips. Keep it in
    /// the Apassy data folder.
    pub work_dir: PathBuf,
}

impl SyncConfig {
    /// The usual layout: the state file `<data_dir>/sync/<state_name>.json`, and the
    /// work folder `<data_dir>/sync`.
    pub fn in_data_dir(
        data_dir: &Path,
        vault_path: &Path,
        folder: &Path,
        state_name: &str,
    ) -> Self {
        let dir = data_dir.join("sync");
        Self {
            vault_path: vault_path.to_owned(),
            folder: folder.to_owned(),
            state_path: dir.join(format!("{state_name}.json")),
            work_dir: dir,
        }
    }
}

/// The state of the synced file, from the files only (no key).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileStatus {
    /// The file is as after the last sync.
    UpToDate,
    /// Another Mac changed the file. A sync merges it.
    Changed,
    /// The folder has no file. A sync writes it again.
    Missing,
    /// The file is in iCloud but not on this Mac yet ([`FolderSync::request_download`]).
    NotDownloaded,
    /// The folder is not there: the drive, the share, or the sync service is away.
    FolderUnavailable,
}

/// The result of [`FolderSync::status`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusReport {
    pub status: FileStatus,
    /// The synced file name, for example `Personal.apassy`.
    pub file_name: String,
    /// The path of the synced file.
    pub file_path: PathBuf,
    /// Duplicates that iCloud made next to the file (`Personal 2.apassy`, ...). Apassy
    /// does not use them.
    pub duplicates: Vec<String>,
    /// The time of the last sync, in Unix seconds.
    pub last_sync_at: Option<u64>,
}

/// What a sync did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncOutcome {
    pub file_name: String,
    /// The merge of the synced file, when it had changed.
    pub merge: Option<MergeReport>,
    /// Whether the sync wrote the synced file.
    pub pushed: bool,
}

/// The result of [`FolderSync::enable`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnableReport {
    /// The synced file name.
    pub file_name: String,
    /// `true` when the file of this vault was in the folder already and the vault
    /// merged with it. `false` when enable wrote a new file.
    pub linked: bool,
    pub outcome: SyncOutcome,
}

/// The result of [`FolderSync::adopt`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdoptReport {
    pub file_name: String,
    /// The sync record of the copy: its last writer.
    pub identity: SyncIdentity,
}

/// A sync failure. The text is for the owner and has no secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncError {
    /// Sync is off for this vault (no state file).
    NotEnabled,
    /// Sync is already on for this vault.
    AlreadyEnabled,
    /// The folder is not there.
    FolderUnavailable,
    /// The synced file is not downloaded to this Mac yet.
    NotDownloaded,
    /// The synced file does not open with the key of the vault: its passphrase changed
    /// on another Mac.
    NeedsPassphrase,
    /// The synced file opens but fails a check.
    Damaged,
    /// The synced file holds another vault.
    OtherVault,
    /// The vault does not match the sync settings (another path or vault ID).
    WrongVault,
    /// The file name is not valid, or enable found no free name.
    InvalidName,
    /// The sync state file is damaged.
    State,
    /// A vault operation failed.
    Vault(VaultErrorKind),
    /// A file operation failed.
    Io,
}

impl fmt::Display for SyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotEnabled => f.write_str("sync is off for this vault"),
            Self::AlreadyEnabled => f.write_str("sync is already on for this vault"),
            Self::FolderUnavailable => f.write_str("the synced folder is not available"),
            Self::NotDownloaded => {
                f.write_str("the synced file is not on this Mac yet; wait for the download")
            }
            Self::NeedsPassphrase => f.write_str(
                "the synced file has another passphrase: the passphrase changed on another Mac",
            ),
            Self::Damaged => f.write_str("the synced file is damaged"),
            Self::OtherVault => f.write_str("the synced file holds another vault"),
            Self::WrongVault => f.write_str("the vault does not match its sync settings"),
            Self::InvalidName => f.write_str("the name of the synced file is not valid"),
            Self::State => f.write_str("the sync state file is damaged"),
            Self::Vault(kind) => fmt::Display::fmt(&VaultError::new(*kind), f),
            Self::Io => f.write_str("a file operation for sync failed"),
        }
    }
}

impl std::error::Error for SyncError {}

impl From<VaultError> for SyncError {
    fn from(vault_err: VaultError) -> Self {
        match vault_err.kind() {
            VaultErrorKind::Damaged => Self::Damaged,
            VaultErrorKind::OtherVault => Self::OtherVault,
            kind => Self::Vault(kind),
        }
    }
}

/// The error of a read of the synced file with the key of the vault.
fn copy_error(vault_err: VaultError) -> SyncError {
    match vault_err.kind() {
        VaultErrorKind::WrongKeyOrCorrupt => SyncError::NeedsPassphrase,
        _ => SyncError::from(vault_err),
    }
}

/// A file that Apassy removes on drop unless it is kept.
struct TempFile {
    path: PathBuf,
    keep: bool,
}

impl TempFile {
    fn new(path: PathBuf) -> Result<Self, SyncError> {
        state::remove_if_present(&path)?;
        Ok(Self { path, keep: false })
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if !self.keep {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Sync of one vault through a folder.
#[derive(Debug, Clone)]
pub struct FolderSync {
    config: SyncConfig,
    scope: SyncScope,
}

impl FolderSync {
    pub fn new(config: SyncConfig) -> Self {
        Self {
            config,
            scope: SyncScope::vault(),
        }
    }

    pub fn config(&self) -> &SyncConfig {
        &self.config
    }

    /// The local sync state. `None` when sync is off.
    pub fn state(&self) -> Result<Option<SyncState>, SyncError> {
        state::read(&self.config.state_path)
    }

    fn require_state(&self) -> Result<SyncState, SyncError> {
        self.state()?.ok_or(SyncError::NotEnabled)
    }

    /// Write the state with the path of the local vault file and the time.
    fn write_state(&self, state: &SyncState) -> Result<(), SyncError> {
        let mut state = state.clone();
        state.vault_path = Some(
            fs::canonicalize(&self.config.vault_path)
                .unwrap_or_else(|_| self.config.vault_path.clone()),
        );
        state.folder = Some(self.config.folder.clone());
        state.last_sync_at = Some(unix_now());
        state::write(&self.config.state_path, &state)
    }

    /// The state of the synced file. No key, no change to any file.
    pub fn status(&self) -> Result<StatusReport, SyncError> {
        let state = self.require_state()?;
        let name = &state.file_name;
        let probe = folder::probe(&self.config.folder, name)?;
        let duplicates = match probe {
            Probe::Unavailable | Probe::NoFolder => Vec::new(),
            _ => folder::duplicates_of(&self.config.folder, name)?,
        };
        let status = match &probe {
            Probe::Unavailable => FileStatus::FolderUnavailable,
            Probe::NoFolder | Probe::Missing => FileStatus::Missing,
            Probe::Evicted(_) => FileStatus::NotDownloaded,
            Probe::Present(path) => {
                if Some(hash_path(path)?) == state.last_file_sha256 {
                    FileStatus::UpToDate
                } else {
                    FileStatus::Changed
                }
            }
        };
        Ok(StatusReport {
            status,
            file_name: name.clone(),
            file_path: self.config.folder.join(name),
            duplicates,
            last_sync_at: state.last_sync_at,
        })
    }

    /// Whether the vault has synced content that the last sync did not see: a change of
    /// a credential, not agent activity. The vault must be unlocked.
    pub fn local_changed(&self, vault: &Vault) -> Result<bool, SyncError> {
        let state = self.require_state()?;
        let content = to_hex(&vault.sync_content(&self.scope)?);
        Ok(state.last_content.as_deref() != Some(content.as_str()))
    }

    /// Ask iCloud Drive to download the synced file. Returns whether the request
    /// started.
    pub fn request_download(&self) -> Result<bool, SyncError> {
        let state = self.require_state()?;
        Ok(start_download(&self.config.folder.join(&state.file_name)))
    }

    /// Sync the unlocked vault: merge the synced file when it changed, then push when
    /// the vault has content that the file does not have. A missing file is written
    /// again. The vault stays unlocked.
    pub fn sync(&self, vault: &mut Vault) -> Result<SyncOutcome, SyncError> {
        let mut state = self.require_state()?;
        self.require_unlocked_vault(vault, &state)?;
        self.sync_with(vault, &mut state)
    }

    fn sync_with(
        &self,
        vault: &mut Vault,
        state: &mut SyncState,
    ) -> Result<SyncOutcome, SyncError> {
        let name = state.file_name.clone();
        let path = match self.probe_ready(&name)? {
            Some(path) => path,
            None => {
                self.push(vault, state)?;
                self.write_state(state)?;
                return Ok(SyncOutcome {
                    file_name: name,
                    merge: None,
                    pushed: true,
                });
            }
        };
        let mut merge = None;
        let mut file_content = state.last_content.clone();
        if Some(hash_path(&path)?) != state.last_file_sha256 {
            let work = TempFile::new(self.work_path(&name, "merge")?)?;
            let (_held, hash) = copy_to_new(&path, &work.path)?;
            let report = vault
                .merge_from(&work.path, &self.scope)
                .map_err(copy_error)?;
            file_content = Some(to_hex(&report.remote_content));
            state.last_file_sha256 = Some(hash);
            merge = Some(report);
        }
        let content = to_hex(&vault.sync_content(&self.scope)?);
        let pushed = file_content.as_deref() != Some(content.as_str());
        if pushed {
            self.push(vault, state)?;
        } else {
            state.last_content = Some(content);
        }
        self.write_state(state)?;
        Ok(SyncOutcome {
            file_name: name,
            merge,
            pushed,
        })
    }

    /// The path of the synced file when it is there. `None` when the folder has no file
    /// yet (a missing folder whose parent exists is made).
    fn probe_ready(&self, name: &str) -> Result<Option<PathBuf>, SyncError> {
        match folder::probe(&self.config.folder, name)? {
            Probe::Present(path) => Ok(Some(path)),
            Probe::Missing => Ok(None),
            Probe::NoFolder => {
                self.ensure_folder()?;
                Ok(None)
            }
            Probe::Evicted(path) => {
                start_download(&path);
                Err(SyncError::NotDownloaded)
            }
            Probe::Unavailable => Err(SyncError::FolderUnavailable),
        }
    }

    /// Write the stripped copy in the work folder, copy it to
    /// `<name>.apassy.push.nosync` in the synced folder, sync it, rename it to the file
    /// name, and sync the folder.
    fn push(&self, vault: &mut Vault, state: &mut SyncState) -> Result<(), SyncError> {
        let name = state.file_name.clone();
        let work = TempFile::new(self.work_path(&name, "push")?)?;
        let copy = vault.write_sync_copy(&work.path, &device_name())?;
        let mut temp = TempFile::new(self.config.folder.join(format!("{name}{PUSH_SUFFIX}")))?;
        let (_held, hash) = copy_to_new(&work.path, &temp.path)?;
        if hash != to_hex(&copy.sha256) {
            return Err(SyncError::Io);
        }
        fs::rename(&temp.path, self.config.folder.join(&name)).map_err(|_| SyncError::Io)?;
        temp.keep = true;
        sync_dir(&self.config.folder).map_err(|_| SyncError::Io)?;
        state.last_file_sha256 = Some(hash);
        state.last_content = Some(to_hex(&copy.content));
        Ok(())
    }

    /// Last resort for a damaged synced file: replace it with the vault of this Mac,
    /// without a merge. The vault must be unlocked.
    pub fn replace_synced_file(&self, vault: &mut Vault) -> Result<SyncOutcome, SyncError> {
        let mut state = self.require_state()?;
        self.require_unlocked_vault(vault, &state)?;
        let name = state.file_name.clone();
        if let Probe::NoFolder = folder::probe(&self.config.folder, &name)? {
            self.ensure_folder()?;
        }
        self.push(vault, &mut state)?;
        self.write_state(&state)?;
        Ok(SyncOutcome {
            file_name: name,
            merge: None,
            pushed: true,
        })
    }

    /// The passphrase changed on another Mac: take `passphrase` from the owner. It must
    /// open the synced file, and the file must hold this vault. Then the vault file is
    /// rekeyed to it, and the sync runs. The vault must be unlocked, and stays unlocked
    /// with the new passphrase.
    pub fn take_new_passphrase(
        &self,
        vault: &mut Vault,
        passphrase: &str,
    ) -> Result<SyncOutcome, SyncError> {
        let mut state = self.require_state()?;
        self.require_unlocked_vault(vault, &state)?;
        let name = state.file_name.clone();
        let Some(path) = self.probe_ready(&name)? else {
            return Err(SyncError::Vault(VaultErrorKind::NotFound));
        };
        let work = TempFile::new(self.work_path(&name, "passphrase")?)?;
        copy_to_new(&path, &work.path)?;
        vault.take_passphrase_of_copy(&work.path, passphrase)?;
        drop(work);
        self.sync_with(vault, &mut state)
    }

    /// Turn on sync for the unlocked vault in the folder of the config.
    ///
    /// The file name comes from `vault_name` ([`file_name_for`]). A file with that name
    /// that does not open with the key of the vault, or that holds another vault, belongs
    /// to someone else: enable tries `<name>-2`, `<name>-3`, and so on. A file of this
    /// vault (the same vault ID) links: the vault merges with it and pushes. Else enable
    /// writes a new file. No passphrase: the open connection has the key.
    pub fn enable(&self, vault: &mut Vault, vault_name: &str) -> Result<EnableReport, SyncError> {
        if self.state()?.is_some() {
            return Err(SyncError::AlreadyEnabled);
        }
        self.require_config_path(vault)?;
        if vault.is_locked() {
            return Err(SyncError::Vault(VaultErrorKind::Locked));
        }
        let local = vault.sync_identity()?;
        self.ensure_folder()?;
        let first = file_name_for(vault_name);
        for n in 1..=MAX_NAME_TRIES {
            let name = folder::candidate_name(&first, n);
            match folder::probe(&self.config.folder, &name)? {
                Probe::Missing => {
                    let mut state = SyncState::new(&name, &local.vault_id);
                    self.push(vault, &mut state)?;
                    self.write_state(&state)?;
                    return Ok(EnableReport {
                        file_name: name.clone(),
                        linked: false,
                        outcome: SyncOutcome {
                            file_name: name,
                            merge: None,
                            pushed: true,
                        },
                    });
                }
                Probe::Evicted(path) => {
                    start_download(&path);
                    return Err(SyncError::NotDownloaded);
                }
                Probe::Present(path) => {
                    let work = TempFile::new(self.work_path(&name, "check")?)?;
                    copy_to_new(&path, &work.path)?;
                    match vault.check_sync_copy(&work.path, &self.scope) {
                        Ok(theirs) if theirs.vault_id == local.vault_id => {
                            drop(work);
                            let mut state = SyncState::new(&name, &local.vault_id);
                            let outcome = self.sync_with(vault, &mut state)?;
                            return Ok(EnableReport {
                                file_name: name,
                                linked: true,
                                outcome,
                            });
                        }
                        Ok(_) => {}
                        Err(check_err)
                            if matches!(
                                check_err.kind(),
                                VaultErrorKind::WrongKeyOrCorrupt | VaultErrorKind::Damaged
                            ) => {}
                        Err(other) => return Err(SyncError::from(other)),
                    }
                }
                Probe::NoFolder | Probe::Unavailable => return Err(SyncError::FolderUnavailable),
            }
        }
        Err(SyncError::InvalidName)
    }

    /// Turn off sync: remove the local state file. The synced file stays. Returns whether
    /// sync was on.
    pub fn disable(&self) -> Result<bool, SyncError> {
        state::remove(&self.config.state_path)
    }

    /// Make a new local vault at `SyncConfig::vault_path` from the synced file
    /// `file_name` in the folder, and turn on sync for it (a new Mac, or a teammate).
    /// The new vault opens locked. `passphrase` must open the copy.
    pub fn adopt(
        &self,
        file_name: &str,
        passphrase: &str,
    ) -> Result<(Vault, AdoptReport), SyncError> {
        if !folder::valid_file_name(file_name) {
            return Err(SyncError::InvalidName);
        }
        if self.state()?.is_some() {
            return Err(SyncError::AlreadyEnabled);
        }
        let path = match folder::probe(&self.config.folder, file_name)? {
            Probe::Present(path) => path,
            Probe::Evicted(path) => {
                start_download(&path);
                return Err(SyncError::NotDownloaded);
            }
            Probe::Missing | Probe::NoFolder => {
                return Err(SyncError::Vault(VaultErrorKind::NotFound));
            }
            Probe::Unavailable => return Err(SyncError::FolderUnavailable),
        };
        let work = TempFile::new(self.work_path(file_name, "adopt")?)?;
        let (_held, hash) = copy_to_new(&path, &work.path)?;
        let (vault, adopted) =
            Vault::adopt_sync_copy(&work.path, &self.config.vault_path, passphrase)?;
        let mut state = SyncState::new(file_name, &adopted.identity.vault_id);
        state.last_file_sha256 = Some(hash);
        state.last_content = Some(to_hex(&adopted.content));
        if let Err(state_err) = self.write_state(&state) {
            let new_file = vault.path().to_owned();
            drop(vault);
            let _ = fs::remove_file(&new_file);
            return Err(state_err);
        }
        Ok((
            vault,
            AdoptReport {
                file_name: file_name.to_owned(),
                identity: adopted.identity,
            },
        ))
    }

    /// A private path in the work folder for a copy of the synced file `name`.
    fn work_path(&self, name: &str, purpose: &str) -> Result<PathBuf, SyncError> {
        state::ensure_private_dir(&self.config.work_dir)?;
        Ok(self.config.work_dir.join(format!(".{name}.{purpose}")))
    }

    /// Make the synced folder when its parent exists.
    fn ensure_folder(&self) -> Result<(), SyncError> {
        match folder::folder_missing(&self.config.folder)? {
            None => Ok(()),
            Some(Probe::NoFolder) => match fs::create_dir(&self.config.folder) {
                Ok(()) => Ok(()),
                Err(io_err) if io_err.kind() == ErrorKind::AlreadyExists => Ok(()),
                Err(_) => Err(SyncError::Io),
            },
            Some(_) => Err(SyncError::FolderUnavailable),
        }
    }

    /// The vault must be the vault of `SyncConfig::vault_path`.
    fn require_config_path(&self, vault: &Vault) -> Result<(), SyncError> {
        match fs::canonicalize(&self.config.vault_path) {
            Ok(path) if path == vault.path() => Ok(()),
            _ => Err(SyncError::WrongVault),
        }
    }

    /// The vault must be the configured one, unlocked, and have the vault ID of the
    /// state.
    fn require_unlocked_vault(&self, vault: &Vault, state: &SyncState) -> Result<(), SyncError> {
        self.require_config_path(vault)?;
        if vault.is_locked() {
            return Err(SyncError::Vault(VaultErrorKind::Locked));
        }
        if vault.sync_identity()?.vault_id != state.vault_id {
            return Err(SyncError::WrongVault);
        }
        Ok(())
    }
}

/// Read the sync state file at `path`. `None` when it does not exist.
pub fn read_state(path: &Path) -> Result<Option<SyncState>, SyncError> {
    state::read(path)
}

/// Lowercase hexadecimal SHA-256 of the file at `path`.
pub fn file_sha256(path: &Path) -> Result<String, SyncError> {
    hash_path(path)
}

/// Lowercase hexadecimal SHA-256 of the file at `path`. A missing file is
/// `Vault(NotFound)`.
fn hash_path(path: &Path) -> Result<String, SyncError> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(io_err) if io_err.kind() == ErrorKind::NotFound => {
            return Err(SyncError::Vault(VaultErrorKind::NotFound));
        }
        Err(_) => return Err(SyncError::Io),
    };
    hash_open_file(&mut file)
        .map(|hash| to_hex(&hash))
        .map_err(|_| SyncError::Io)
}

fn create_new_private(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

/// Copy `source` to the new file `dest` (mode `0600`) and sync it. Returns the open
/// copy and the hash of the bytes.
fn copy_to_new(source: &Path, dest: &Path) -> Result<(File, String), SyncError> {
    let mut dest_file = create_new_private(dest).map_err(|_| SyncError::Io)?;
    let copied = File::open(source).and_then(|mut src| copy_hashing(&mut src, &mut dest_file));
    match copied {
        Ok(hash) => Ok((dest_file, to_hex(&hash))),
        Err(_) => {
            drop(dest_file);
            let _ = fs::remove_file(dest);
            Err(SyncError::Io)
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
