//! iCloud sync of a vault (ADR 0014, `docs/operations/icloud.md`).
//!
//! The live vault stays a local file. SQLite never opens a file in iCloud Drive for
//! writing: iCloud can replace a file under an open connection, sync a rollback journal
//! apart from its database, or evict a file. iCloud Drive holds a closed copy of the
//! vault (the format of a backup) in `~/Library/Mobile Documents/com~apple~CloudDocs/
//! Apassy/<name>.apassy`.
//!
//! - A push (vault unlocked) raises the sync generation in the vault, copies the vault
//!   file to a `.nosync` file in the Apassy folder, syncs it, and renames it to the
//!   cloud name. The vault stays unlocked.
//! - A status compares the SHA-256 of the local file and of the cloud file with the
//!   hash of the last push or pull. It needs no passphrase.
//! - A pull (vault locked, typed passphrase) copies the cloud file next to the vault,
//!   checks it with the passphrase, refuses another vault and an older copy, and renames
//!   it over the vault file.
//! - In a conflict the owner chooses. Each choice first saves the other copy under
//!   `conflicts/`.
//!
//! The engine does not know the vault registry. The caller gives each path in
//! [`SyncConfig`]. On a system without iCloud Drive (Linux) [`default_cloud_dir`] is
//! `None`; the engine still works with any folder, which the tests use.

mod folder;
mod state;

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::ErrorKind;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

pub use folder::{
    CLOUD_FILE_EXTENSION, CloudEntry, cloud_file_name_for, list_cloud_vaults, start_download,
};
pub use state::SyncState;

use crate::vault::{
    SyncIdentity, Vault, VaultError, VaultErrorKind, copy_hashing, format_utc, hash_open_file,
    sync_dir, to_hex,
};
use folder::Probe;

/// The name of the Apassy folder in iCloud Drive.
pub const CLOUD_FOLDER_NAME: &str = "Apassy";
/// Enable tries at most this many cloud file names (`Personal.apassy`,
/// `Personal-2.apassy`, ...).
const MAX_NAME_TRIES: u32 = 99;
/// A conflict copy name gets at most this many numbers when the time is the same.
const MAX_CONFLICT_TRIES: u32 = 99;

/// The Apassy folder in iCloud Drive:
/// `$HOME/Library/Mobile Documents/com~apple~CloudDocs/Apassy`. The folder may not
/// exist yet. `None` when `HOME` is not set.
#[cfg(target_os = "macos")]
pub fn default_cloud_dir() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").filter(|home| !home.is_empty())?;
    Some(
        PathBuf::from(home)
            .join("Library")
            .join("Mobile Documents")
            .join("com~apple~CloudDocs")
            .join(CLOUD_FOLDER_NAME),
    )
}

/// There is no iCloud Drive on this system.
#[cfg(not(target_os = "macos"))]
pub fn default_cloud_dir() -> Option<PathBuf> {
    None
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
    /// The Apassy folder in iCloud Drive ([`default_cloud_dir`]). Its parent is the
    /// iCloud Drive folder; when the parent is missing, iCloud Drive is not available.
    pub cloud_dir: PathBuf,
    /// The local sync state file (JSON). Keep it in the Apassy data folder, which the
    /// Seatbelt profile denies. Its folder also holds short-lived copies during enable,
    /// adopt, and "Keep this Mac".
    pub state_path: PathBuf,
    /// The folder for conflict copies: `<data folder>/conflicts`.
    pub conflicts_dir: PathBuf,
}

impl SyncConfig {
    /// The usual layout: the state file `<data_dir>/icloud/<state_name>.json` and the
    /// conflict copies in `<data_dir>/conflicts`.
    pub fn in_data_dir(
        data_dir: &Path,
        vault_path: &Path,
        cloud_dir: &Path,
        state_name: &str,
    ) -> Self {
        Self {
            vault_path: vault_path.to_owned(),
            cloud_dir: cloud_dir.to_owned(),
            state_path: data_dir.join("icloud").join(format!("{state_name}.json")),
            conflicts_dir: data_dir.join("conflicts"),
        }
    }

    fn work_dir(&self) -> Result<&Path, CloudError> {
        self.state_path
            .parent()
            .filter(|dir| !dir.as_os_str().is_empty())
            .ok_or(CloudError::Io)
    }
}

/// The sync state of a vault, from the files only (no passphrase).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncStatus {
    /// The local file and the cloud file are the same as at the last sync, or the same
    /// as each other.
    InSync,
    /// This Mac changed the vault. The cloud file did not change.
    PushNeeded,
    /// The cloud file changed. This Mac did not change the vault.
    PullAvailable,
    /// Both changed. The owner chooses: "Keep this Mac" or "Use iCloud".
    Conflict,
    /// The Apassy folder or the cloud file is missing. A push writes it again.
    CloudMissing,
    /// The cloud file is in iCloud but not on this Mac. Start a download
    /// ([`CloudSync::request_download`]) and check again later.
    NotDownloaded,
    /// There is no iCloud Drive folder on this computer.
    Unavailable,
}

/// The result of [`CloudSync::status`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncReport {
    pub status: SyncStatus,
    /// The cloud file name, for example `Personal.apassy`.
    pub cloud_file_name: String,
    /// The path of the cloud file.
    pub cloud_path: PathBuf,
    /// iCloud conflict duplicates next to the cloud file (`Personal 2.apassy`, ...).
    /// Apassy does not use them. The owner can adopt one as a separate vault, or delete
    /// it in Finder.
    pub duplicates: Vec<String>,
    /// The generation at the last push or pull.
    pub last_generation: u64,
    /// The time of the last push or pull, in Unix seconds.
    pub last_sync_at: Option<u64>,
}

/// The result of a push, a pull, a conflict choice, or an adopt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncOutcome {
    /// `false` when there was nothing to copy (the files were already in sync).
    pub copied: bool,
    pub cloud_file_name: String,
    /// The generation of the copy that is now on both sides.
    pub generation: u64,
    /// The device of the push that made this copy. Empty when nothing was copied.
    pub pushed_by: String,
    /// The time of that push, in Unix seconds.
    pub pushed_at: Option<u64>,
    /// The conflict copy that the operation saved first, if any.
    pub conflict_copy: Option<PathBuf>,
}

/// The result of [`CloudSync::enable`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnableReport {
    /// The cloud file name that sync uses.
    pub cloud_file_name: String,
    /// `true` when enable wrote a new cloud file. `false` when the cloud file of the same
    /// vault was there already and enable linked to it.
    pub pushed: bool,
    /// `InSync` after a push or a link to an equal file. `Conflict` after a link to a
    /// different copy of the same vault: the owner chooses.
    pub status: SyncStatus,
    /// The generation that the state file now has.
    pub generation: u64,
}

/// An iCloud sync failure. The text is for the owner and has no secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudError {
    /// There is no iCloud Drive folder.
    Unavailable,
    /// Sync is off for this vault (no state file).
    NotEnabled,
    /// Sync is already on for this vault.
    AlreadyEnabled,
    /// The cloud file is missing.
    CloudMissing,
    /// The cloud file is not downloaded to this Mac.
    NotDownloaded,
    /// A push found a cloud file that changed since the last sync.
    CloudChanged,
    /// A pull found local changes that are not in iCloud.
    LocalChanged,
    /// The cloud copy is older than the copy of the last sync, or has the same
    /// generation and other content.
    Rollback {
        cloud_generation: u64,
        synced_generation: u64,
    },
    /// The cloud file holds another vault (another vault id).
    DifferentVault,
    /// A pull needs the vault locked.
    NotLocked,
    /// The vault does not match the sync settings (another path or vault id).
    WrongVault,
    /// The cloud file name is not valid, or enable found no free name.
    InvalidName,
    /// The sync state file is damaged.
    State,
    /// A vault operation failed. `WrongKeyOrCorrupt` means a wrong passphrase or a
    /// damaged copy.
    Vault(VaultErrorKind),
    /// A file operation failed, or a copy changed during its check.
    Io,
}

impl fmt::Display for CloudError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => f.write_str("iCloud Drive is not available on this computer"),
            Self::NotEnabled => f.write_str("iCloud sync is off for this vault"),
            Self::AlreadyEnabled => f.write_str("iCloud sync is already on for this vault"),
            Self::CloudMissing => f.write_str("the iCloud copy of the vault is missing"),
            Self::NotDownloaded => {
                f.write_str("the iCloud copy is not on this Mac yet; wait for the download")
            }
            Self::CloudChanged => f.write_str(
                "the iCloud copy changed since the last sync; get it first, or choose which copy to keep",
            ),
            Self::LocalChanged => f.write_str(
                "this Mac has changes that are not in iCloud; send them first, or choose which copy to keep",
            ),
            Self::Rollback {
                cloud_generation,
                synced_generation,
            } if cloud_generation == synced_generation => write!(
                f,
                "the iCloud copy has the generation of the last sync ({cloud_generation}) but other content; \
                 Apassy did not use it. Choose which copy to keep"
            ),
            Self::Rollback {
                cloud_generation,
                synced_generation,
            } => write!(
                f,
                "the iCloud copy is older than the copy that this Mac synced last (generation \
                 {cloud_generation}, last sync {synced_generation}); Apassy did not use it"
            ),
            Self::DifferentVault => f.write_str("the iCloud file holds another vault"),
            Self::NotLocked => f.write_str("lock the vault first"),
            Self::WrongVault => f.write_str("the vault does not match its iCloud sync settings"),
            Self::InvalidName => f.write_str("the name of the iCloud file is not valid"),
            Self::State => f.write_str("the iCloud sync state file is damaged"),
            Self::Vault(kind) => fmt::Display::fmt(&VaultError::new(*kind), f),
            Self::Io => f.write_str("a file operation for iCloud sync failed"),
        }
    }
}

impl std::error::Error for CloudError {}

impl From<VaultError> for CloudError {
    fn from(vault_err: VaultError) -> Self {
        Self::Vault(vault_err.kind())
    }
}

/// How a pull treats the generation of the cloud copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PullMode {
    /// Local changes refuse the pull. The generation must be higher than at the last
    /// sync.
    Normal,
    /// The owner chose the iCloud copy in a conflict. The local file is saved first. The
    /// generation must not be lower than at the last sync.
    UseICloud,
}

/// A file that Apassy removes on drop unless it is kept.
struct TempFile {
    path: PathBuf,
    keep: bool,
}

impl TempFile {
    fn new(path: PathBuf) -> Result<Self, CloudError> {
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

/// iCloud sync of one vault.
#[derive(Debug, Clone)]
pub struct CloudSync {
    config: SyncConfig,
}

impl CloudSync {
    pub fn new(config: SyncConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &SyncConfig {
        &self.config
    }

    /// The local sync state. `None` when sync is off.
    pub fn state(&self) -> Result<Option<SyncState>, CloudError> {
        state::read(&self.config.state_path)
    }

    fn require_state(&self) -> Result<SyncState, CloudError> {
        self.state()?.ok_or(CloudError::NotEnabled)
    }

    /// Write the state with the path of the local vault file.
    fn write_state(&self, state: &SyncState) -> Result<(), CloudError> {
        let mut state = state.clone();
        state.vault_path = Some(
            fs::canonicalize(&self.config.vault_path)
                .unwrap_or_else(|_| self.config.vault_path.clone()),
        );
        state::write(&self.config.state_path, &state)
    }

    /// Compare the local file and the cloud file with the last sync. No passphrase, no
    /// change to any file.
    pub fn status(&self) -> Result<SyncReport, CloudError> {
        let state = self.require_state()?;
        let name = &state.cloud_file_name;
        let probe = folder::probe(&self.config.cloud_dir, name)?;
        let duplicates = match probe {
            Probe::NoICloud | Probe::NoFolder => Vec::new(),
            _ => folder::duplicates_of(&self.config.cloud_dir, name)?,
        };
        let status = match &probe {
            Probe::NoICloud => SyncStatus::Unavailable,
            Probe::NoFolder | Probe::Missing => SyncStatus::CloudMissing,
            Probe::Evicted(_) => SyncStatus::NotDownloaded,
            Probe::Present(cloud_path) => {
                let local = hash_path(&self.config.vault_path)?;
                let cloud = hash_path(cloud_path)?;
                classify(&state, &local, &cloud)
            }
        };
        Ok(SyncReport {
            status,
            cloud_file_name: name.clone(),
            cloud_path: self.config.cloud_dir.join(name),
            duplicates,
            last_generation: state.last_generation,
            last_sync_at: state.last_sync_at,
        })
    }

    /// Ask iCloud Drive to download the cloud file. Call it when the status is
    /// `NotDownloaded`. Returns whether the request started.
    pub fn request_download(&self) -> Result<bool, CloudError> {
        let state = self.require_state()?;
        Ok(start_download(
            &self.config.cloud_dir.join(&state.cloud_file_name),
        ))
    }

    /// Turn on sync for an unlocked vault.
    ///
    /// `passphrase` must open the vault. The cloud file name comes from `vault_name`
    /// ([`cloud_file_name_for`]). When a file with that name holds another vault (another
    /// vault id, or it does not open with the passphrase), enable tries `<name>-2`,
    /// `<name>-3`, and so on. When the file holds this vault (the same vault id), enable
    /// links to it without a push: equal files are in sync, different files are a
    /// conflict for the owner. Else enable pushes the first copy.
    pub fn enable(
        &self,
        vault: &mut Vault,
        passphrase: &str,
        vault_name: &str,
    ) -> Result<EnableReport, CloudError> {
        if self.state()?.is_some() {
            return Err(CloudError::AlreadyEnabled);
        }
        self.require_config_path(vault)?;
        if vault.is_locked() {
            return Err(CloudError::Vault(VaultErrorKind::Locked));
        }
        Vault::verify_passphrase_at(vault.path(), passphrase)?;
        let local = vault.sync_identity()?;
        self.ensure_cloud_folder()?;
        let first = cloud_file_name_for(vault_name);
        for n in 1..=MAX_NAME_TRIES {
            let name = folder::candidate_name(&first, n);
            match folder::probe(&self.config.cloud_dir, &name)? {
                Probe::Missing => {
                    let state = SyncState::new(&name, &local.vault_id, None, local.generation);
                    let outcome = self.push_copy(vault, state, local.generation, None)?;
                    return Ok(EnableReport {
                        cloud_file_name: name,
                        pushed: true,
                        status: SyncStatus::InSync,
                        generation: outcome.generation,
                    });
                }
                Probe::Evicted(path) => {
                    start_download(&path);
                    return Err(CloudError::NotDownloaded);
                }
                Probe::Present(path) => match self.inspect_cloud_copy(&path, &name, passphrase) {
                    Ok((cloud, hash)) if cloud.vault_id == local.vault_id => {
                        let local_hash = hash_path(vault.path())?;
                        let (last, generation, status) = if local_hash == hash {
                            (Some(hash), cloud.generation, SyncStatus::InSync)
                        } else {
                            (None, local.generation, SyncStatus::Conflict)
                        };
                        let mut state = SyncState::new(&name, &local.vault_id, last, generation);
                        state.last_sync_at = Some(unix_now());
                        self.write_state(&state)?;
                        return Ok(EnableReport {
                            cloud_file_name: name,
                            pushed: false,
                            status,
                            generation,
                        });
                    }
                    Ok(_) | Err(CloudError::Vault(VaultErrorKind::WrongKeyOrCorrupt)) => {}
                    Err(other) => return Err(other),
                },
                Probe::NoFolder | Probe::NoICloud => return Err(CloudError::Unavailable),
            }
        }
        Err(CloudError::InvalidName)
    }

    /// Turn off sync: remove the local state file. The cloud file stays. Returns whether
    /// sync was on.
    pub fn disable(&self) -> Result<bool, CloudError> {
        state::remove(&self.config.state_path)
    }

    /// Send the changes of this Mac to iCloud. The vault must be unlocked, and stays
    /// unlocked.
    ///
    /// Refuses when the cloud file changed since the last sync (`CloudChanged`) or is
    /// not downloaded. A missing cloud file is written again. Nothing is copied when both
    /// files are as at the last sync.
    pub fn push(&self, vault: &mut Vault) -> Result<SyncOutcome, CloudError> {
        let state = self.require_state()?;
        self.require_unlocked_vault(vault, &state)?;
        let cloud_hash = match folder::probe(&self.config.cloud_dir, &state.cloud_file_name)? {
            Probe::NoICloud => return Err(CloudError::Unavailable),
            Probe::Evicted(_) => return Err(CloudError::NotDownloaded),
            Probe::NoFolder => {
                self.ensure_cloud_folder()?;
                None
            }
            Probe::Missing => None,
            Probe::Present(path) => Some(hash_path(&path)?),
        };
        if let Some(cloud) = cloud_hash {
            let local = hash_path(vault.path())?;
            let last = state.last_sha256.as_deref();
            if cloud == local {
                return self.record_equal(state, cloud);
            }
            if Some(cloud.as_str()) != last {
                return Err(CloudError::CloudChanged);
            }
        }
        let above = state.last_generation;
        self.push_copy(vault, state, above, None)
    }

    /// Get the iCloud copy. The vault must be locked. `passphrase` must open the copy.
    ///
    /// The pull refuses local changes that are not in iCloud (`LocalChanged`), a copy
    /// of another vault (`DifferentVault`), and a copy that is not newer than the last
    /// sync (`Rollback`). A wrong passphrase or a damaged copy gives
    /// `Vault(WrongKeyOrCorrupt)`. On each failure the local file does not change.
    /// Agents, grants, and rules stay, unlike a restore (ADR 0014).
    pub fn pull(&self, vault: &mut Vault, passphrase: &str) -> Result<SyncOutcome, CloudError> {
        self.pull_with(vault, passphrase, PullMode::Normal)
    }

    /// Conflict choice "Use iCloud". The vault must be locked. The local file goes to
    /// `conflicts/<name>-this-mac-<time>.apassy` first, then the pull runs. An iCloud
    /// copy with the generation of the last sync is accepted here; an older one is
    /// still refused.
    pub fn use_icloud(
        &self,
        vault: &mut Vault,
        passphrase: &str,
    ) -> Result<SyncOutcome, CloudError> {
        self.pull_with(vault, passphrase, PullMode::UseICloud)
    }

    /// Conflict choice "Keep this Mac". The vault must be unlocked, and stays unlocked.
    ///
    /// `passphrase` must open the iCloud copy. Apassy reads the generation of that copy,
    /// so the push gets a higher one and the other Macs accept it. The iCloud copy goes
    /// to `conflicts/<name>-icloud-<time>.apassy` first. A missing cloud file is written
    /// again.
    pub fn keep_this_mac(
        &self,
        vault: &mut Vault,
        passphrase: &str,
    ) -> Result<SyncOutcome, CloudError> {
        let state = self.require_state()?;
        self.require_unlocked_vault(vault, &state)?;
        // The push refuses these too. Check first, so no conflict copy stays behind.
        refuse_companions(vault.path())?;
        let name = state.cloud_file_name.clone();
        let mut above = state.last_generation;
        let mut conflict_copy = None;
        match folder::probe(&self.config.cloud_dir, &name)? {
            Probe::NoICloud => return Err(CloudError::Unavailable),
            Probe::Evicted(_) => return Err(CloudError::NotDownloaded),
            Probe::NoFolder => self.ensure_cloud_folder()?,
            Probe::Missing => {}
            Probe::Present(path) => {
                let work = TempFile::new(self.inspect_path(&name)?)?;
                let (_held, hash) = copy_to_new(&path, &work.path)?;
                let cloud = Vault::inspect_sync_copy(&work.path, passphrase)?;
                if cloud.vault_id != state.vault_id {
                    return Err(CloudError::DifferentVault);
                }
                above = above.max(cloud.generation);
                if hash != hash_path(vault.path())? {
                    conflict_copy = Some(self.save_conflict_copy(&work.path, &name, "icloud")?);
                }
            }
        }
        self.push_copy(vault, state, above, conflict_copy)
    }

    /// Make a new local vault at `SyncConfig::vault_path` from the cloud file
    /// `cloud_file_name`, and turn on sync for it (a new Mac). The new vault opens
    /// locked. `passphrase` must open the copy. There is no earlier generation, so any
    /// generation is accepted.
    pub fn adopt(
        &self,
        cloud_file_name: &str,
        passphrase: &str,
    ) -> Result<(Vault, SyncOutcome), CloudError> {
        if !folder::valid_cloud_file_name(cloud_file_name) {
            return Err(CloudError::InvalidName);
        }
        if self.state()?.is_some() {
            return Err(CloudError::AlreadyEnabled);
        }
        let path = match folder::probe(&self.config.cloud_dir, cloud_file_name)? {
            Probe::Present(path) => path,
            Probe::Evicted(path) => {
                start_download(&path);
                return Err(CloudError::NotDownloaded);
            }
            Probe::Missing | Probe::NoFolder => return Err(CloudError::CloudMissing),
            Probe::NoICloud => return Err(CloudError::Unavailable),
        };
        let work = TempFile::new(self.inspect_path(cloud_file_name)?)?;
        let (_held, hash) = copy_to_new(&path, &work.path)?;
        let (vault, identity) =
            Vault::adopt_sync_copy(&work.path, &self.config.vault_path, passphrase)?;
        let mut state = SyncState::new(
            cloud_file_name,
            &identity.vault_id,
            Some(hash.clone()),
            identity.generation,
        );
        state.last_sync_at = Some(unix_now());
        let installed = hash_path(vault.path())
            .and_then(|local| {
                if local == hash {
                    Ok(())
                } else {
                    Err(CloudError::Io)
                }
            })
            .and_then(|()| self.write_state(&state));
        if let Err(install_err) = installed {
            let new_file = vault.path().to_owned();
            drop(vault);
            let _ = fs::remove_file(&new_file);
            return Err(install_err);
        }
        Ok((
            vault,
            SyncOutcome {
                copied: true,
                cloud_file_name: cloud_file_name.to_owned(),
                generation: identity.generation,
                pushed_by: identity.pushed_by,
                pushed_at: identity.pushed_at,
                conflict_copy: None,
            },
        ))
    }

    fn pull_with(
        &self,
        vault: &mut Vault,
        passphrase: &str,
        mode: PullMode,
    ) -> Result<SyncOutcome, CloudError> {
        let state = self.require_state()?;
        self.require_config_path(vault)?;
        if !vault.is_locked() {
            return Err(CloudError::NotLocked);
        }
        let name = state.cloud_file_name.clone();
        let cloud_path = match folder::probe(&self.config.cloud_dir, &name)? {
            Probe::Present(path) => path,
            Probe::Evicted(_) => return Err(CloudError::NotDownloaded),
            Probe::Missing | Probe::NoFolder => return Err(CloudError::CloudMissing),
            Probe::NoICloud => return Err(CloudError::Unavailable),
        };
        // SQLite would apply a journal next to the vault file to the new file.
        refuse_companions(vault.path())?;
        let local = hash_path(vault.path())?;
        if mode == PullMode::Normal {
            let cloud = hash_path(&cloud_path)?;
            let last = state.last_sha256.as_deref();
            if cloud == local {
                return self.record_equal(state, cloud);
            }
            if Some(local.as_str()) != last {
                return Err(CloudError::LocalChanged);
            }
            if Some(cloud.as_str()) == last {
                return Ok(unchanged(&state));
            }
        }
        // SQLite opens only a local copy. The copy is next to the vault file, so the
        // rename below is atomic. The Seatbelt profile denies this name like the vault.
        let mut incoming = TempFile::new(vault.incoming_path())?;
        let (mut held, hash) = copy_to_new(&cloud_path, &incoming.path)?;
        let identity = Vault::inspect_sync_copy(&incoming.path, passphrase)?;
        if identity.vault_id != state.vault_id {
            return Err(CloudError::DifferentVault);
        }
        check_generation(&state, &identity, &hash, mode)?;
        let conflict_copy = if mode == PullMode::UseICloud && hash != local {
            Some(self.save_conflict_copy(vault.path(), &name, "this-mac")?)
        } else {
            None
        };
        // The checked file must still be the file that Apassy copied: the same inode and
        // the same bytes. The check runs just before the rename.
        require_unchanged(&mut held, &incoming.path, &hash)?;
        drop(held);
        vault.replace_file_with(&incoming.path)?;
        incoming.keep = true;
        let mut next = state;
        next.last_sha256 = Some(hash);
        next.last_generation = identity.generation;
        next.last_sync_at = Some(unix_now());
        self.write_state(&next)?;
        Ok(SyncOutcome {
            copied: true,
            cloud_file_name: name,
            generation: identity.generation,
            pushed_by: identity.pushed_by,
            pushed_at: identity.pushed_at,
            conflict_copy,
        })
    }

    /// Write the vault to a `.nosync` file in the Apassy folder, sync it, rename it to
    /// the cloud name, sync the folder, and write the state.
    fn push_copy(
        &self,
        vault: &mut Vault,
        state: SyncState,
        above: u64,
        conflict_copy: Option<PathBuf>,
    ) -> Result<SyncOutcome, CloudError> {
        let name = state.cloud_file_name.clone();
        // iCloud Drive does not sync a name that ends in `.nosync`, so it never uploads
        // a half-written copy.
        let mut temp = TempFile::new(self.config.cloud_dir.join(format!(".{name}.push.nosync")))?;
        let copy = vault.write_sync_copy(&temp.path, &device_name(), above)?;
        fs::rename(&temp.path, self.config.cloud_dir.join(&name)).map_err(|_| CloudError::Io)?;
        temp.keep = true;
        sync_dir(&self.config.cloud_dir).map_err(|_| CloudError::Io)?;
        let mut next = state;
        next.vault_id = copy.identity.vault_id.clone();
        next.last_sha256 = Some(to_hex(&copy.sha256));
        next.last_generation = copy.identity.generation;
        next.last_sync_at = Some(unix_now());
        self.write_state(&next)?;
        Ok(SyncOutcome {
            copied: true,
            cloud_file_name: name,
            generation: copy.identity.generation,
            pushed_by: copy.identity.pushed_by,
            pushed_at: copy.identity.pushed_at,
            conflict_copy,
        })
    }

    /// The local file and the cloud file are equal. Record the hash when the state has
    /// another one (a crash after a rename and before the state write), and copy
    /// nothing.
    fn record_equal(&self, state: SyncState, hash: String) -> Result<SyncOutcome, CloudError> {
        if state.last_sha256.as_deref() == Some(hash.as_str()) {
            return Ok(unchanged(&state));
        }
        let mut next = state;
        next.last_sha256 = Some(hash);
        next.last_sync_at = Some(unix_now());
        self.write_state(&next)?;
        Ok(unchanged(&next))
    }

    /// Copy a cloud file to a private local file and check it with the passphrase.
    /// Returns its sync record and the hash of its bytes.
    fn inspect_cloud_copy(
        &self,
        path: &Path,
        name: &str,
        passphrase: &str,
    ) -> Result<(SyncIdentity, String), CloudError> {
        let work = TempFile::new(self.inspect_path(name)?)?;
        let (_held, hash) = copy_to_new(path, &work.path)?;
        let identity = Vault::inspect_sync_copy(&work.path, passphrase)?;
        Ok((identity, hash))
    }

    /// A private local path for a copy of the cloud file `name`, in the folder of the
    /// state file.
    fn inspect_path(&self, name: &str) -> Result<PathBuf, CloudError> {
        let dir = self.config.work_dir()?;
        state::ensure_private_dir(dir)?;
        Ok(dir.join(format!(".{name}.inspect")))
    }

    /// Copy `source` to a new file in the conflicts folder. Returns the new path.
    fn save_conflict_copy(
        &self,
        source: &Path,
        cloud_name: &str,
        label: &str,
    ) -> Result<PathBuf, CloudError> {
        let dir = &self.config.conflicts_dir;
        state::ensure_private_dir(dir)?;
        let stem = cloud_name
            .strip_suffix(CLOUD_FILE_EXTENSION)
            .unwrap_or(cloud_name);
        let time = compact_utc(unix_now());
        for n in 1..=MAX_CONFLICT_TRIES {
            let name = if n == 1 {
                format!("{stem}-{label}-{time}{CLOUD_FILE_EXTENSION}")
            } else {
                format!("{stem}-{label}-{time}-{n}{CLOUD_FILE_EXTENSION}")
            };
            let dest = dir.join(name);
            match create_new_private(&dest) {
                Ok(mut dest_file) => {
                    let copied = File::open(source)
                        .and_then(|mut src| copy_hashing(&mut src, &mut dest_file));
                    if copied.is_err() {
                        drop(dest_file);
                        let _ = fs::remove_file(&dest);
                        return Err(CloudError::Io);
                    }
                    sync_dir(dir).map_err(|_| CloudError::Io)?;
                    return Ok(dest);
                }
                Err(io_err) if io_err.kind() == ErrorKind::AlreadyExists => {}
                Err(_) => return Err(CloudError::Io),
            }
        }
        Err(CloudError::Io)
    }

    fn ensure_cloud_folder(&self) -> Result<(), CloudError> {
        match folder::folder_missing(&self.config.cloud_dir)? {
            None => Ok(()),
            Some(Probe::NoFolder) => match fs::create_dir(&self.config.cloud_dir) {
                Ok(()) => Ok(()),
                Err(io_err) if io_err.kind() == ErrorKind::AlreadyExists => Ok(()),
                Err(_) => Err(CloudError::Io),
            },
            Some(_) => Err(CloudError::Unavailable),
        }
    }

    /// The vault must be the vault of `SyncConfig::vault_path`.
    fn require_config_path(&self, vault: &Vault) -> Result<(), CloudError> {
        match fs::canonicalize(&self.config.vault_path) {
            Ok(path) if path == vault.path() => Ok(()),
            _ => Err(CloudError::WrongVault),
        }
    }

    /// The vault must be the configured one, unlocked, and have the vault id of the
    /// state.
    fn require_unlocked_vault(&self, vault: &Vault, state: &SyncState) -> Result<(), CloudError> {
        self.require_config_path(vault)?;
        if vault.is_locked() {
            return Err(CloudError::Vault(VaultErrorKind::Locked));
        }
        if vault.sync_identity()?.vault_id != state.vault_id {
            return Err(CloudError::WrongVault);
        }
        Ok(())
    }
}

/// Read the sync state file at `path`. `None` when it does not exist.
pub fn read_state(path: &Path) -> Result<Option<SyncState>, CloudError> {
    state::read(path)
}

/// Lowercase hexadecimal SHA-256 of the file at `path`, as in the sync state.
pub fn file_sha256(path: &Path) -> Result<String, CloudError> {
    hash_path(path)
}

/// The status from three hashes: the local file, the cloud file, and the last sync.
fn classify(state: &SyncState, local: &str, cloud: &str) -> SyncStatus {
    let last = state.last_sha256.as_deref();
    match (Some(local) == last, Some(cloud) == last) {
        (true, true) => SyncStatus::InSync,
        (false, true) => SyncStatus::PushNeeded,
        (true, false) => SyncStatus::PullAvailable,
        (false, false) if local == cloud => SyncStatus::InSync,
        (false, false) => SyncStatus::Conflict,
    }
}

/// Refuse an older copy. A normal pull also refuses the generation of the last sync
/// with other content (two Macs pushed from the same copy); "Use iCloud" accepts it.
fn check_generation(
    state: &SyncState,
    identity: &SyncIdentity,
    hash: &str,
    mode: PullMode,
) -> Result<(), CloudError> {
    let rollback = CloudError::Rollback {
        cloud_generation: identity.generation,
        synced_generation: state.last_generation,
    };
    if identity.generation < state.last_generation {
        return Err(rollback);
    }
    if identity.generation == state.last_generation
        && mode == PullMode::Normal
        && state.last_sha256.as_deref() != Some(hash)
    {
        return Err(rollback);
    }
    Ok(())
}

fn unchanged(state: &SyncState) -> SyncOutcome {
    SyncOutcome {
        copied: false,
        cloud_file_name: state.cloud_file_name.clone(),
        generation: state.last_generation,
        pushed_by: String::new(),
        pushed_at: None,
        conflict_copy: None,
    }
}

/// Lowercase hexadecimal SHA-256 of the file at `path`. A missing file is
/// `Vault(NotFound)`.
fn hash_path(path: &Path) -> Result<String, CloudError> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(io_err) if io_err.kind() == ErrorKind::NotFound => {
            return Err(CloudError::Vault(VaultErrorKind::NotFound));
        }
        Err(_) => return Err(CloudError::Io),
    };
    hash_open_file(&mut file)
        .map(|hash| to_hex(&hash))
        .map_err(|_| CloudError::Io)
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
/// copy, for a later check, and the hash of the bytes.
fn copy_to_new(source: &Path, dest: &Path) -> Result<(File, String), CloudError> {
    let mut dest_file = create_new_private(dest).map_err(|_| CloudError::Io)?;
    let copied = File::open(source).and_then(|mut src| copy_hashing(&mut src, &mut dest_file));
    match copied {
        Ok(hash) => Ok((dest_file, to_hex(&hash))),
        Err(_) => {
            drop(dest_file);
            let _ = fs::remove_file(dest);
            Err(CloudError::Io)
        }
    }
}

/// The file at `path` must be the open file `held` (same device and inode, one link)
/// with the bytes of `hash`. A change means that another program replaced or changed
/// the copy during the check.
fn require_unchanged(held: &mut File, path: &Path, hash: &str) -> Result<(), CloudError> {
    let held_meta = held.metadata().map_err(|_| CloudError::Io)?;
    let path_meta = fs::symlink_metadata(path).map_err(|_| CloudError::Io)?;
    if !path_meta.is_file()
        || path_meta.nlink() != 1
        || held_meta.dev() != path_meta.dev()
        || held_meta.ino() != path_meta.ino()
    {
        return Err(CloudError::Io);
    }
    let now = hash_open_file(held).map_err(|_| CloudError::Io)?;
    if to_hex(&now) == hash {
        Ok(())
    } else {
        Err(CloudError::Io)
    }
}

/// Refuse a vault file with a `-journal`, `-wal`, or `-shm` file next to it: the file
/// alone is not the whole database.
fn refuse_companions(path: &Path) -> Result<(), CloudError> {
    for suffix in ["-journal", "-wal", "-shm"] {
        let mut companion = path.as_os_str().to_os_string();
        companion.push(suffix);
        match fs::symlink_metadata(Path::new(&companion)) {
            Ok(_) => return Err(CloudError::Vault(VaultErrorKind::InvalidInput)),
            Err(io_err) if io_err.kind() == ErrorKind::NotFound => {}
            Err(_) => return Err(CloudError::Io),
        }
    }
    Ok(())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// `YYYYMMDD-HHMMSS` in UTC, for conflict copy names.
fn compact_utc(unix: u64) -> String {
    let text = format_utc(unix);
    let digits: String = text
        .chars()
        .take_while(|ch| *ch != 'U')
        .filter(|ch| ch.is_ascii_digit() || *ch == ' ')
        .collect();
    digits.trim().replacen(' ', "-", 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(last: Option<&str>) -> SyncState {
        SyncState::new(
            "Personal.apassy",
            "00000000-0000-4000-8000-000000000000",
            last.map(str::to_owned),
            3,
        )
    }

    #[test]
    fn classify_covers_each_combination() {
        let s = state(Some("a"));
        assert_eq!(classify(&s, "a", "a"), SyncStatus::InSync);
        assert_eq!(classify(&s, "b", "a"), SyncStatus::PushNeeded);
        assert_eq!(classify(&s, "a", "b"), SyncStatus::PullAvailable);
        assert_eq!(classify(&s, "b", "c"), SyncStatus::Conflict);
        assert_eq!(classify(&s, "b", "b"), SyncStatus::InSync);
        let linked = state(None);
        assert_eq!(classify(&linked, "b", "c"), SyncStatus::Conflict);
        assert_eq!(classify(&linked, "b", "b"), SyncStatus::InSync);
    }

    #[test]
    fn generation_rules_for_each_pull_mode() {
        let s = state(Some("a"));
        let identity = |generation| SyncIdentity {
            vault_id: s.vault_id.clone(),
            generation,
            pushed_by: String::new(),
            pushed_at: None,
        };
        assert!(check_generation(&s, &identity(4), "b", PullMode::Normal).is_ok());
        assert!(check_generation(&s, &identity(3), "b", PullMode::Normal).is_err());
        assert!(check_generation(&s, &identity(2), "b", PullMode::Normal).is_err());
        assert!(check_generation(&s, &identity(3), "b", PullMode::UseICloud).is_ok());
        assert_eq!(
            check_generation(&s, &identity(2), "b", PullMode::UseICloud),
            Err(CloudError::Rollback {
                cloud_generation: 2,
                synced_generation: 3
            })
        );
    }

    #[test]
    fn compact_time_has_no_separators() {
        assert_eq!(compact_utc(0), "19700101-000000");
        assert_eq!(compact_utc(1_790_000_000), "20260921-141320");
    }

    #[test]
    fn rollback_messages_name_both_generations() {
        let older = CloudError::Rollback {
            cloud_generation: 2,
            synced_generation: 5,
        }
        .to_string();
        assert!(
            older.contains("generation 2") && older.contains("last sync 5"),
            "{older}"
        );
        let same = CloudError::Rollback {
            cloud_generation: 5,
            synced_generation: 5,
        }
        .to_string();
        assert!(same.contains("other content"), "{same}");
    }
}
