//! The list of vaults on this computer (ADR 0013).
//!
//! Apassy keeps one list in `<data dir>/vaults.json`. Each entry names one vault
//! file: a stable random ID, a name, the absolute path, and two times. The list also
//! names the vault that the owner used last. One vault is open at a time.
//!
//! The list is not secret. It has names and paths, no key and no item. The file has
//! mode `0600` in the data directory (mode `0700`). A write goes to a temporary file
//! first, then a rename replaces the list, so a crash leaves the old list or the new
//! one.
//!
//! A field that this version does not know stays in the file when this version
//! writes it. A later version adds an optional field to [`VaultEntry`] or
//! [`Registry`] with `#[serde(default, skip_serializing_if = "Option::is_none")]`.
//!
//! This module uses only `std`, `serde`, and `serde_json`, so `apassy-sandbox` reads
//! the list without the vault feature.

use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// The file name of the list in the data directory.
pub const REGISTRY_FILE: &str = "vaults.json";
/// The format version that this Apassy writes.
pub const REGISTRY_VERSION: u32 = 1;
/// The vault file of Apassy 0.2: `<data dir>/vault.db`. It stays where it is.
pub const LEGACY_VAULT_FILE: &str = "vault.db";
/// The folder of new vault files in the data directory.
pub const VAULTS_DIR: &str = "vaults";
/// The name of the vault from `vault.db` after the migration.
pub const LEGACY_VAULT_NAME: &str = "Personal";
/// The longest vault name, in characters.
pub const MAX_NAME_CHARS: usize = 40;
/// The most vaults in the list.
pub const MAX_VAULTS: usize = 100;

const MAX_ID_BYTES: usize = 64;

/// The path of the list in `data_dir`.
pub fn registry_path(data_dir: &Path) -> PathBuf {
    data_dir.join(REGISTRY_FILE)
}

/// The vault file of Apassy 0.2 in `data_dir`.
pub fn legacy_vault_path(data_dir: &Path) -> PathBuf {
    data_dir.join(LEGACY_VAULT_FILE)
}

/// The folder of new vault files in `data_dir`.
pub fn vaults_dir(data_dir: &Path) -> PathBuf {
    data_dir.join(VAULTS_DIR)
}

/// Unix time in seconds.
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// A valid vault name: the trimmed text, 1 to 40 characters, without a control
/// character.
pub fn check_name(name: &str) -> Result<String, RegistryError> {
    let name = name.trim();
    let count = name.chars().count();
    if count == 0 || count > MAX_NAME_CHARS || name.chars().any(char::is_control) {
        return Err(RegistryError::InvalidName);
    }
    Ok(name.to_owned())
}

/// A name from the file name of `path`, for example `work` for `work.db`. It has at
/// most 40 characters. "Vault" when the file name gives nothing.
pub fn name_from_path(path: &Path) -> String {
    let stem = path
        .file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .unwrap_or_default();
    let clean: String = stem
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let cut: String = clean.trim().chars().take(MAX_NAME_CHARS).collect();
    match cut.trim() {
        "" => "Vault".to_owned(),
        name => name.to_owned(),
    }
}

/// The file name part for a vault name: lower-case ASCII letters, digits, and `-`,
/// at most 40 bytes. "vault" when the name gives nothing.
pub fn slug(name: &str) -> String {
    let mut out = String::new();
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    let cut: String = out.trim_matches('-').chars().take(MAX_NAME_CHARS).collect();
    match cut.trim_end_matches('-') {
        "" => "vault".to_owned(),
        slug => slug.to_owned(),
    }
}

/// Sync of one vault through a folder (ADR 0014). The sync state is a file in the data
/// directory: `sync/<state>.json`. The synced file is `<folder>/<file>`; the sandbox
/// launcher reads it here and denies it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncLink {
    /// The name of the sync state file, without `.json`. An empty or invalid name
    /// means that sync is off.
    #[serde(default)]
    pub state: String,
    /// The synced folder, for example the Apassy folder in iCloud Drive.
    #[serde(default)]
    pub folder: PathBuf,
    /// The name of the synced file in the folder, for example `Personal.apassy`.
    #[serde(default)]
    pub file: String,
    /// Fields of a later Apassy. They stay when this version writes the list.
    #[serde(flatten)]
    extra: Map<String, Value>,
}

impl SyncLink {
    /// A link to the sync state file `sync/<state>.json` and the synced file
    /// `<folder>/<file>`.
    pub fn new(state: &str, folder: &Path, file: &str) -> Self {
        Self {
            state: state.to_owned(),
            folder: folder.to_owned(),
            file: file.to_owned(),
            extra: Map::new(),
        }
    }

    /// The synced file, when the folder is absolute and the name is a plain file name.
    pub fn file_path(&self) -> Option<PathBuf> {
        let plain = !self.file.is_empty()
            && !self.file.contains(['/', '\0'])
            && self.file != "."
            && self.file != "..";
        (plain && self.folder.is_absolute()).then(|| self.folder.join(&self.file))
    }

    /// The state name when it can be a file name: 1 to 64 ASCII letters, digits, `-`,
    /// or `_`.
    pub fn state_name(&self) -> Option<&str> {
        let name = self.state.as_str();
        let valid = !name.is_empty()
            && name.len() <= MAX_ID_BYTES
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        valid.then_some(name)
    }
}

/// One vault in the list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultEntry {
    /// A stable random ID. A rename or a move does not change it.
    pub id: String,
    /// The owner-facing name. It is unique in the list, without regard to case.
    pub name: String,
    /// The absolute path of the vault file.
    pub path: PathBuf,
    /// Unix time when the vault came into the list.
    pub added_at: u64,
    /// Unix time of the last open. `None` before the first open.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_opened_at: Option<u64>,
    /// Sync of the vault through a folder (ADR 0014). `None` when sync is off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync: Option<SyncLink>,
    /// Fields of a later Apassy. They stay when this version writes the list.
    #[serde(flatten)]
    extra: Map<String, Value>,
}

impl VaultEntry {
    /// The sync state name of the vault, when sync is on.
    pub fn sync_state(&self) -> Option<&str> {
        self.sync.as_ref().and_then(SyncLink::state_name)
    }

    /// The synced file of the vault, when sync is on.
    pub fn sync_file(&self) -> Option<PathBuf> {
        self.sync_state()?;
        self.sync.as_ref().and_then(SyncLink::file_path)
    }
}

/// The list of vaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registry {
    version: u32,
    /// The ID of the vault that the owner used last.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_used: Option<String>,
    #[serde(default)]
    vaults: Vec<VaultEntry>,
    /// Fields of a later Apassy. They stay when this version writes the list.
    #[serde(flatten)]
    extra: Map<String, Value>,
}

/// What [`Registry::load`] found.
#[derive(Debug)]
pub struct Loaded {
    pub registry: Registry,
    /// Text for the owner: the list was damaged and Apassy made a new one, or a write
    /// failed. `None` when all went well.
    pub note: Option<String>,
}

/// A refused change, or a list that Apassy cannot read.
#[derive(Debug)]
pub enum RegistryError {
    /// The name is empty, longer than 40 characters, or has a control character.
    InvalidName,
    /// Another vault in the list has this name.
    NameTaken(String),
    /// The path is not absolute, or it is not UTF-8.
    InvalidPath,
    /// The file is in the list already, with this name.
    AlreadyListed(String),
    /// No vault in the list has this ID.
    NotFound,
    /// The list has [`MAX_VAULTS`] vaults.
    Full,
    /// The file is not a valid list. The text says why.
    Corrupt(String),
    /// The file has a format version that this Apassy does not know.
    Newer(u32),
    /// A read or a write of the file failed.
    Io(io::Error),
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName => {
                write!(f, "Type a vault name of 1 to {MAX_NAME_CHARS} characters.")
            }
            Self::NameTaken(name) => write!(
                f,
                "Another vault has the name “{name}”. Choose another name."
            ),
            Self::InvalidPath => f.write_str("Type the absolute path of the vault file."),
            Self::AlreadyListed(name) => {
                write!(f, "This file is in the vault list already, as “{name}”.")
            }
            Self::NotFound => f.write_str("This vault is not in the list."),
            Self::Full => write!(
                f,
                "The vault list has {MAX_VAULTS} vaults. Remove one from the list first."
            ),
            Self::Corrupt(why) => write!(f, "the vault list is not valid ({why})"),
            Self::Newer(version) => write!(
                f,
                "the vault list has format {version}, from a newer Apassy. This Apassy reads format {REGISTRY_VERSION}"
            ),
            Self::Io(err) => write!(f, "the vault list cannot be read or written ({err})"),
        }
    }
}

impl std::error::Error for RegistryError {}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

impl Registry {
    /// An empty list.
    pub fn new() -> Self {
        Self {
            version: REGISTRY_VERSION,
            last_used: None,
            vaults: Vec::new(),
            extra: Map::new(),
        }
    }

    /// Read a list from its JSON text and check it.
    pub fn parse(text: &str) -> Result<Self, RegistryError> {
        let mut registry: Self =
            serde_json::from_str(text).map_err(|err| RegistryError::Corrupt(err.to_string()))?;
        if registry.version == 0 {
            return Err(RegistryError::Corrupt("the version is 0".to_owned()));
        }
        if registry.version > REGISTRY_VERSION {
            return Err(RegistryError::Newer(registry.version));
        }
        if registry.vaults.len() > MAX_VAULTS {
            return Err(RegistryError::Corrupt(format!(
                "more than {MAX_VAULTS} vaults"
            )));
        }
        let mut ids = BTreeSet::new();
        let mut names = BTreeSet::new();
        let mut paths = BTreeSet::new();
        for entry in &registry.vaults {
            if entry.id.is_empty()
                || entry.id.len() > MAX_ID_BYTES
                || !entry
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            {
                return Err(RegistryError::Corrupt("a vault has no valid ID".to_owned()));
            }
            if check_name(&entry.name).ok().as_deref() != Some(entry.name.as_str()) {
                return Err(RegistryError::Corrupt(
                    "a vault has no valid name".to_owned(),
                ));
            }
            if !entry.path.is_absolute() || entry.path.to_str().is_none() {
                return Err(RegistryError::Corrupt(
                    "a vault path is not absolute".to_owned(),
                ));
            }
            if !ids.insert(entry.id.as_str())
                || !names.insert(entry.name.to_lowercase())
                || !paths.insert(entry.path.as_path())
            {
                return Err(RegistryError::Corrupt(
                    "two vaults have the same ID, name, or path".to_owned(),
                ));
            }
        }
        if registry
            .last_used
            .as_ref()
            .is_some_and(|id| !ids.contains(id.as_str()))
        {
            registry.last_used = None;
        }
        Ok(registry)
    }

    /// The JSON text of the list.
    pub fn to_json(&self) -> String {
        let mut text = serde_json::to_string_pretty(self).unwrap_or_default();
        text.push('\n');
        text
    }

    /// Read the list in `data_dir`. `Ok(None)` when there is no list.
    pub fn read(data_dir: &Path) -> Result<Option<Self>, RegistryError> {
        let mut text = String::new();
        match fs::File::open(registry_path(data_dir)) {
            Ok(mut file) => {
                file.read_to_string(&mut text).map_err(|err| {
                    if err.kind() == io::ErrorKind::InvalidData {
                        RegistryError::Corrupt("the file is not UTF-8 text".to_owned())
                    } else {
                        RegistryError::Io(err)
                    }
                })?;
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(RegistryError::Io(err)),
        }
        Self::parse(&text).map(Some)
    }

    /// Write the list to `data_dir`: a temporary file with mode `0600`, a sync, and a
    /// rename over the list. A missing data directory gets mode `0700`.
    pub fn save(&self, data_dir: &Path) -> Result<(), RegistryError> {
        for entry in &self.vaults {
            if entry.path.to_str().is_none() {
                return Err(RegistryError::InvalidPath);
            }
        }
        private_dir(data_dir).map_err(RegistryError::Io)?;
        let target = registry_path(data_dir);
        let temp = data_dir.join(format!(".{REGISTRY_FILE}.tmp-{}", new_id()));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temp)?;
            file.write_all(self.to_json().as_bytes())?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temp, &target)?;
            // The rename is durable when the directory is synced. Best effort.
            if let Ok(dir) = fs::File::open(data_dir) {
                let _ = dir.sync_all();
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result.map_err(RegistryError::Io)
    }

    /// A new list from the files in `data_dir` (the migration rule): `vault.db` as
    /// "Personal", then each `vaults/*.db` with the name of its file. It is not saved.
    pub fn rebuild(data_dir: &Path) -> Self {
        let mut registry = Self::new();
        let at = now();
        let legacy = legacy_vault_path(data_dir);
        if legacy.is_file()
            && let Ok(id) = registry.add(LEGACY_VAULT_NAME, &legacy, at)
        {
            registry.last_used = Some(id);
        }
        let mut found: Vec<PathBuf> = fs::read_dir(vaults_dir(data_dir))
            .map(|dir| {
                dir.filter_map(Result::ok)
                    .map(|entry| entry.path())
                    .filter(|path| {
                        path.extension().is_some_and(|ext| ext == "db") && path.is_file()
                    })
                    .collect()
            })
            .unwrap_or_default();
        found.sort();
        for path in found {
            let name = registry.free_name(&name_from_path(&path));
            if let Ok(id) = registry.add(&name, &path, at)
                && registry.last_used.is_none()
            {
                registry.last_used = Some(id);
            }
        }
        registry
    }

    /// The list of `data_dir` for the app. It never fails:
    ///
    /// - No list: [`Registry::rebuild`], saved when it has a vault.
    /// - A list that Apassy cannot read: the file moves to `vaults.json.bad-<unix
    ///   time>`, and a rebuilt list replaces it. The note says so.
    pub fn load(data_dir: &Path) -> Loaded {
        match Self::read(data_dir) {
            Ok(Some(registry)) => Loaded {
                registry,
                note: None,
            },
            Ok(None) => {
                let registry = Self::rebuild(data_dir);
                let note = if registry.is_empty() {
                    None
                } else {
                    registry
                        .save(data_dir)
                        .err()
                        .map(|err| format!("Apassy could not save the vault list: {err}."))
                };
                Loaded { registry, note }
            }
            Err(err) => {
                let aside = move_aside(data_dir);
                let registry = Self::rebuild(data_dir);
                let saved = registry.save(data_dir);
                let mut note = match &aside {
                    Ok(path) => format!(
                        "Apassy could not use the vault list: {err}. Apassy moved it to {} and made a new list from the vault files in {}. A vault in another folder is not in the list now: open it again with “Open vault file…”.",
                        path.display(),
                        data_dir.display()
                    ),
                    Err(move_err) => format!(
                        "Apassy could not use the vault list: {err}. Apassy could not move it aside ({move_err}) and made a new list from the vault files in {}.",
                        data_dir.display()
                    ),
                };
                if let Err(save_err) = saved {
                    note.push_str(&format!(" Apassy could not save the new list: {save_err}."));
                }
                Loaded {
                    registry,
                    note: Some(note),
                }
            }
        }
    }

    /// The vaults, in the order they came into the list.
    pub fn entries(&self) -> &[VaultEntry] {
        &self.vaults
    }

    pub fn is_empty(&self) -> bool {
        self.vaults.is_empty()
    }

    pub fn get(&self, id: &str) -> Option<&VaultEntry> {
        self.vaults.iter().find(|entry| entry.id == id)
    }

    /// The entry with `id`, for a change of a later field. Change the name with
    /// [`Registry::rename`]: it checks the name.
    pub fn entry_mut(&mut self, id: &str) -> Option<&mut VaultEntry> {
        self.vaults.iter_mut().find(|entry| entry.id == id)
    }

    /// The entry of the file at `path`. Symlinks count: both paths are resolved.
    pub fn find_path(&self, path: &Path) -> Option<&VaultEntry> {
        if let Some(entry) = self.vaults.iter().find(|entry| entry.path == path) {
            return Some(entry);
        }
        let wanted = fs::canonicalize(path).ok()?;
        self.vaults
            .iter()
            .find(|entry| fs::canonicalize(&entry.path).is_ok_and(|real| real == wanted))
    }

    /// The ID of the vault that the owner used last, when it is in the list.
    pub fn last_used_id(&self) -> Option<&str> {
        self.last_used.as_deref()
    }

    /// The vault to open at start: the last used one, else the one opened last, else
    /// the first.
    pub fn last_used(&self) -> Option<&VaultEntry> {
        self.last_used
            .as_deref()
            .and_then(|id| self.get(id))
            .or_else(|| {
                self.vaults
                    .iter()
                    .filter(|entry| entry.last_opened_at.is_some())
                    .max_by_key(|entry| entry.last_opened_at)
            })
            .or_else(|| self.vaults.first())
    }

    /// Check a name and a path for a new entry. Returns the trimmed name.
    pub fn check_new(&self, name: &str, path: &Path) -> Result<String, RegistryError> {
        let name = self.check_free_name(name, None)?;
        if !path.is_absolute() || path.to_str().is_none() {
            return Err(RegistryError::InvalidPath);
        }
        if let Some(entry) = self.find_path(path) {
            return Err(RegistryError::AlreadyListed(entry.name.clone()));
        }
        if self.vaults.len() >= MAX_VAULTS {
            return Err(RegistryError::Full);
        }
        Ok(name)
    }

    /// Add a vault. Returns its new ID.
    pub fn add(&mut self, name: &str, path: &Path, now: u64) -> Result<String, RegistryError> {
        let name = self.check_new(name, path)?;
        let id = new_id();
        self.vaults.push(VaultEntry {
            id: id.clone(),
            name,
            path: path.to_path_buf(),
            added_at: now,
            last_opened_at: None,
            sync: None,
            extra: Map::new(),
        });
        Ok(id)
    }

    /// Give a vault a new name.
    pub fn rename(&mut self, id: &str, name: &str) -> Result<(), RegistryError> {
        let name = self.check_free_name(name, Some(id))?;
        let entry = self.entry_mut(id).ok_or(RegistryError::NotFound)?;
        entry.name = name;
        Ok(())
    }

    /// Take a vault out of the list. The file stays.
    pub fn remove(&mut self, id: &str) -> Result<VaultEntry, RegistryError> {
        let index = self
            .vaults
            .iter()
            .position(|entry| entry.id == id)
            .ok_or(RegistryError::NotFound)?;
        if self.last_used.as_deref() == Some(id) {
            self.last_used = None;
        }
        Ok(self.vaults.remove(index))
    }

    /// The owner opened the vault `id` at `now`. It is the last used vault.
    pub fn mark_opened(&mut self, id: &str, now: u64) -> Result<(), RegistryError> {
        let entry = self.entry_mut(id).ok_or(RegistryError::NotFound)?;
        entry.last_opened_at = Some(now);
        self.last_used = Some(id.to_owned());
        Ok(())
    }

    /// `base` when no vault has it, else `base 2`, `base 3`, and so on. The result
    /// has at most 40 characters.
    pub fn free_name(&self, base: &str) -> String {
        let base = check_name(base).unwrap_or_else(|_| "Vault".to_owned());
        if self.name_is_free(&base, None) {
            return base;
        }
        for number in 2..=MAX_VAULTS + 1 {
            let suffix = format!(" {number}");
            let keep = MAX_NAME_CHARS - suffix.chars().count();
            let head: String = base.chars().take(keep).collect();
            let name = format!("{}{suffix}", head.trim_end());
            if self.name_is_free(&name, None) {
                return name;
            }
        }
        base
    }

    /// The default file of a new vault: `<data dir>/vaults/<slug>.db`, or
    /// `<slug>-2.db` and so on when the file exists or is in the list.
    pub fn new_vault_path(&self, data_dir: &Path, name: &str) -> PathBuf {
        let dir = vaults_dir(data_dir);
        let slug = slug(name);
        let taken = |path: &Path| {
            fs::symlink_metadata(path).is_ok() || self.vaults.iter().any(|entry| entry.path == path)
        };
        let first = dir.join(format!("{slug}.db"));
        if !taken(&first) {
            return first;
        }
        (2..)
            .map(|number| dir.join(format!("{slug}-{number}.db")))
            .find(|path| !taken(path))
            .unwrap_or(first)
    }

    fn check_free_name(&self, name: &str, except: Option<&str>) -> Result<String, RegistryError> {
        let name = check_name(name)?;
        if !self.name_is_free(&name, except) {
            return Err(RegistryError::NameTaken(name));
        }
        Ok(name)
    }

    fn name_is_free(&self, name: &str, except: Option<&str>) -> bool {
        let lower = name.to_lowercase();
        !self
            .vaults
            .iter()
            .any(|entry| Some(entry.id.as_str()) != except && entry.name.to_lowercase() == lower)
    }
}

/// Create `dir` with mode `0700` when it is missing.
fn private_dir(dir: &Path) -> io::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

/// Move a list that Apassy cannot read to `vaults.json.bad-<unix time>`.
fn move_aside(data_dir: &Path) -> io::Result<PathBuf> {
    let from = registry_path(data_dir);
    let stamp = now();
    let mut to = data_dir.join(format!("{REGISTRY_FILE}.bad-{stamp}"));
    let mut number = 2;
    while fs::symlink_metadata(&to).is_ok() {
        to = data_dir.join(format!("{REGISTRY_FILE}.bad-{stamp}-{number}"));
        number += 1;
    }
    fs::rename(&from, &to)?;
    Ok(to)
}

/// 32 random hexadecimal characters from the system random source. Without it, a
/// hash of the time, the process, and a counter.
fn new_id() -> String {
    let mut bytes = [0u8; 16];
    let random = fs::File::open("/dev/urandom").and_then(|mut file| file.read_exact(&mut bytes));
    if random.is_err() {
        use std::collections::hash_map::RandomState;
        use std::hash::{BuildHasher, Hasher};
        use std::sync::atomic::{AtomicU64, Ordering};

        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos());
        for (index, chunk) in bytes.chunks_mut(8).enumerate() {
            let mut hasher = RandomState::new().build_hasher();
            hasher.write_u128(nanos);
            hasher.write_u32(std::process::id());
            hasher.write_u64(COUNTER.fetch_add(1, Ordering::Relaxed));
            hasher.write_usize(index);
            chunk.copy_from_slice(&hasher.finish().to_le_bytes());
        }
    }
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("apassy-vaults-{name}-{}", new_id()));
        fs::create_dir_all(&dir).expect("temp dir");
        fs::canonicalize(dir).expect("canonical")
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).expect("metadata").permissions().mode() & 0o777
    }

    #[test]
    fn names_are_trimmed_bounded_and_unique_without_case() {
        assert_eq!(check_name("  Work  ").expect("name"), "Work");
        assert!(check_name("   ").is_err());
        assert!(check_name(&"x".repeat(41)).is_err());
        assert_eq!(
            check_name(&"ż".repeat(40))
                .expect("40 chars")
                .chars()
                .count(),
            40
        );
        assert!(check_name("tab\there").is_err());

        let mut registry = Registry::new();
        let id = registry
            .add("Work", Path::new("/tmp/apassy-a.db"), 1)
            .expect("add");
        let taken = registry.add("  WORK ", Path::new("/tmp/apassy-b.db"), 2);
        assert!(matches!(taken, Err(RegistryError::NameTaken(name)) if name == "WORK"));
        assert!(matches!(
            registry.add("Other", Path::new("relative.db"), 2),
            Err(RegistryError::InvalidPath)
        ));
        assert!(matches!(
            registry.add("Other", Path::new("/tmp/apassy-a.db"), 2),
            Err(RegistryError::AlreadyListed(name)) if name == "Work"
        ));
        let other = registry
            .add("Home", Path::new("/tmp/apassy-b.db"), 2)
            .expect("add");
        assert!(matches!(
            registry.rename(&other, "work"),
            Err(RegistryError::NameTaken(_))
        ));
        registry
            .rename(&id, "work")
            .expect("a new case of its own name");
        assert_eq!(registry.get(&id).expect("entry").name, "work");
        assert!(matches!(
            registry.rename("missing", "New"),
            Err(RegistryError::NotFound)
        ));
        assert_eq!(registry.free_name("Home"), "Home 2");
        assert_eq!(registry.free_name("Fresh"), "Fresh");
        let long = "y".repeat(40);
        registry
            .add(&long, Path::new("/tmp/apassy-c.db"), 3)
            .expect("add");
        let free = registry.free_name(&long);
        assert_eq!(free.chars().count(), 40);
        assert!(free.ends_with(" 2"), "{free}");
    }

    #[test]
    fn slugs_and_default_paths() {
        assert_eq!(slug("Work"), "work");
        assert_eq!(slug("Client  A / staging"), "client-a-staging");
        assert_eq!(slug("Łódź"), "d");
        assert_eq!(slug("!!!"), "vault");
        assert_eq!(slug(&"ab".repeat(30)).len(), 40);
        assert_eq!(name_from_path(Path::new("/x/Client A.db")), "Client A");
        assert_eq!(name_from_path(Path::new("/")), "Vault");

        let dir = temp_dir("paths");
        let mut registry = Registry::new();
        let first = registry.new_vault_path(&dir, "Work");
        assert_eq!(first, dir.join("vaults").join("work.db"));
        fs::create_dir_all(dir.join("vaults")).expect("vaults dir");
        fs::write(&first, b"x").expect("file");
        assert_eq!(
            registry.new_vault_path(&dir, "work"),
            dir.join("vaults").join("work-2.db")
        );
        // A listed path counts as taken, also when its file is gone.
        registry
            .add("Old", &dir.join("vaults").join("work-2.db"), 1)
            .expect("add");
        assert_eq!(
            registry.new_vault_path(&dir, "Work"),
            dir.join("vaults").join("work-3.db")
        );
        fs::remove_dir_all(dir).expect("clean");
    }

    #[test]
    fn a_saved_list_reads_back_with_mode_0600_and_keeps_unknown_fields() {
        let dir = temp_dir("save").join("data");
        let mut registry = Registry::new();
        let id = registry
            .add("Personal", &dir.join("vault.db"), 100)
            .expect("add");
        registry.mark_opened(&id, 200).expect("open");
        registry.save(&dir).expect("save");
        assert_eq!(mode(&dir), 0o700, "a new data directory is private");
        assert_eq!(mode(&registry_path(&dir)), 0o600);
        let read = Registry::read(&dir).expect("read").expect("a list");
        assert_eq!(read, registry);
        assert_eq!(
            read.last_used().map(|entry| entry.id.as_str()),
            Some(id.as_str())
        );
        assert_eq!(
            read.get(&id).and_then(|entry| entry.last_opened_at),
            Some(200)
        );
        // No temporary file stays.
        let names: Vec<String> = fs::read_dir(&dir)
            .expect("list")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        assert_eq!(names, vec![REGISTRY_FILE.to_owned()]);

        // A later Apassy adds fields. This version keeps them on a write.
        let text = format!(
            r#"{{"version":1,"last_used":"{id}","sync_hint":{{"a":1}},"vaults":[{{"id":"{id}","name":"Personal","path":"{}","added_at":100,"cloud":{{"enabled":true}}}}]}}"#,
            dir.join("vault.db").display()
        );
        let mut later = Registry::parse(&text).expect("parse");
        later.rename(&id, "Private").expect("rename");
        later.save(&dir).expect("save");
        let written = fs::read_to_string(registry_path(&dir)).expect("text");
        let value: Value = serde_json::from_str(&written).expect("json");
        assert_eq!(value["sync_hint"]["a"], 1);
        assert_eq!(value["vaults"][0]["cloud"]["enabled"], true);
        assert_eq!(value["vaults"][0]["name"], "Private");
        fs::remove_dir_all(dir.parent().expect("parent")).expect("clean");
    }

    #[test]
    fn parse_refuses_a_damaged_or_newer_list() {
        for (text, why) in [
            ("not json", "json"),
            (r#"{"vaults":[]}"#, "no version"),
            (r#"{"version":0,"vaults":[]}"#, "version 0"),
            (
                r#"{"version":1,"vaults":[{"id":"a","name":"A","path":"rel.db","added_at":1}]}"#,
                "relative path",
            ),
            (
                r#"{"version":1,"vaults":[{"id":"a","name":" ","path":"/a.db","added_at":1}]}"#,
                "blank name",
            ),
            (
                r#"{"version":1,"vaults":[{"id":"a b","name":"A","path":"/a.db","added_at":1}]}"#,
                "bad id",
            ),
            (
                r#"{"version":1,"vaults":[{"id":"a","name":"A","path":"/a.db","added_at":1},{"id":"b","name":"a","path":"/b.db","added_at":1}]}"#,
                "same name",
            ),
            (
                r#"{"version":1,"vaults":[{"id":"a","name":"A","path":"/a.db","added_at":1},{"id":"b","name":"B","path":"/a.db","added_at":1}]}"#,
                "same path",
            ),
        ] {
            assert!(
                matches!(Registry::parse(text), Err(RegistryError::Corrupt(_))),
                "{why}"
            );
        }
        assert!(matches!(
            Registry::parse(r#"{"version":2,"vaults":[]}"#),
            Err(RegistryError::Newer(2))
        ));
        // A last used ID that is not in the list is ignored.
        let lenient = Registry::parse(
            r#"{"version":1,"last_used":"gone","vaults":[{"id":"a","name":"A","path":"/a.db","added_at":1}]}"#,
        )
        .expect("parse");
        assert_eq!(lenient.last_used_id(), None);
        assert_eq!(
            lenient.last_used().map(|entry| entry.name.as_str()),
            Some("A")
        );
    }

    #[test]
    fn load_migrates_vault_db_as_personal() {
        let dir = temp_dir("migrate");
        let empty = Registry::load(&dir);
        assert!(empty.registry.is_empty());
        assert!(empty.note.is_none());
        assert!(!registry_path(&dir).exists(), "no list without a vault");

        fs::write(legacy_vault_path(&dir), b"synthetic").expect("vault file");
        fs::create_dir_all(vaults_dir(&dir)).expect("vaults dir");
        fs::write(vaults_dir(&dir).join("client-a.db"), b"synthetic").expect("vault file");
        fs::write(vaults_dir(&dir).join("client-a.db.lock"), b"").expect("lock file");
        let loaded = Registry::load(&dir);
        assert!(loaded.note.is_none(), "{:?}", loaded.note);
        let names: Vec<&str> = loaded
            .registry
            .entries()
            .iter()
            .map(|entry| entry.name.as_str())
            .collect();
        assert_eq!(names, ["Personal", "client-a"]);
        let last = loaded.registry.last_used().expect("last used");
        assert_eq!(last.name, "Personal");
        assert_eq!(last.path, legacy_vault_path(&dir));
        // The migrated list is on disk, so the launcher reads the same vaults.
        let read = Registry::read(&dir).expect("read").expect("list");
        assert_eq!(read, loaded.registry);
        // A second load keeps the list.
        assert_eq!(Registry::load(&dir).registry, loaded.registry);
        fs::remove_dir_all(dir).expect("clean");
    }

    #[test]
    fn a_damaged_list_moves_aside_and_start_is_not_blocked() {
        let dir = temp_dir("corrupt");
        fs::write(legacy_vault_path(&dir), b"synthetic").expect("vault file");
        fs::write(registry_path(&dir), b"{\"version\":1,\"vaults\":[{").expect("bad list");
        let loaded = Registry::load(&dir);
        let note = loaded.note.expect("a note for the owner");
        assert!(note.contains("moved it to"), "{note}");
        assert!(note.contains("Open vault file"), "{note}");
        let aside: Vec<PathBuf> = fs::read_dir(&dir)
            .expect("list")
            .map(|entry| entry.expect("entry").path())
            .filter(|path| {
                path.file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with("vaults.json.bad-"))
            })
            .collect();
        assert_eq!(aside.len(), 1, "{aside:?}");
        assert_eq!(
            fs::read(&aside[0]).expect("bad"),
            b"{\"version\":1,\"vaults\":[{"
        );
        assert_eq!(loaded.registry.entries().len(), 1);
        assert_eq!(loaded.registry.entries()[0].name, "Personal");
        assert!(Registry::read(&dir).expect("read").is_some(), "a new list");

        // A list from a newer Apassy also moves aside. A second one gets its own name.
        fs::write(registry_path(&dir), br#"{"version":9,"vaults":[]}"#).expect("newer");
        let loaded = Registry::load(&dir);
        assert!(loaded.note.expect("note").contains("newer Apassy"));
        let count = fs::read_dir(&dir)
            .expect("list")
            .filter(|entry| {
                entry
                    .as_ref()
                    .is_ok_and(|entry| entry.file_name().to_string_lossy().contains(".bad-"))
            })
            .count();
        assert_eq!(count, 2);
        fs::remove_dir_all(dir).expect("clean");
    }

    #[test]
    fn a_sync_link_round_trips_and_needs_a_file_name() {
        let mut registry = Registry::new();
        let id = registry
            .add("Personal", Path::new("/tmp/apassy-sync.db"), 1)
            .expect("add");
        assert_eq!(registry.get(&id).expect("entry").sync_state(), None);
        let folder = Path::new("/Users/me/Dropbox/Apassy");
        registry.entry_mut(&id).expect("entry").sync =
            Some(SyncLink::new(&id, folder, "Personal.apassy"));
        let read = Registry::parse(&registry.to_json()).expect("parse");
        let entry = read.get(&id).expect("entry");
        assert_eq!(entry.sync_state(), Some(id.as_str()));
        assert_eq!(entry.sync_file(), Some(folder.join("Personal.apassy")));
        for bad in ["", "../x", "a b", &"x".repeat(65)] {
            assert_eq!(
                SyncLink::new(bad, folder, "x.apassy").state_name(),
                None,
                "{bad}"
            );
        }
        for bad in ["", "a/b.apassy", "..", "."] {
            assert_eq!(SyncLink::new("s", folder, bad).file_path(), None, "{bad}");
        }
        assert_eq!(
            SyncLink::new("s", Path::new("relative"), "x.apassy").file_path(),
            None
        );
        // Sync off writes no field.
        registry.entry_mut(&id).expect("entry").sync = None;
        assert!(!registry.to_json().contains("\"sync\""));
    }

    #[test]
    fn remove_and_last_used() {
        let mut registry = Registry::new();
        let a = registry.add("A", Path::new("/tmp/a.db"), 1).expect("add");
        let b = registry.add("B", Path::new("/tmp/b.db"), 2).expect("add");
        assert_eq!(
            registry.last_used().map(|entry| entry.id.as_str()),
            Some(a.as_str())
        );
        registry.mark_opened(&b, 10).expect("open");
        assert_eq!(registry.last_used_id(), Some(b.as_str()));
        let removed = registry.remove(&b).expect("remove");
        assert_eq!(removed.name, "B");
        assert_eq!(registry.last_used_id(), None);
        assert_eq!(
            registry.last_used().map(|entry| entry.id.as_str()),
            Some(a.as_str())
        );
        assert!(matches!(registry.remove(&b), Err(RegistryError::NotFound)));
        assert_ne!(new_id(), new_id());
        assert_eq!(new_id().len(), 32);
    }
}
