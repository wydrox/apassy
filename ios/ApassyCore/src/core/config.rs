//! `phone.json`: the vaults on this iPhone (contract section 6), and where their files
//! are. The app writes it; the AutoFill extension only reads it.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::errors::{CoreError, CoreResult};

const LIST_FILE: &str = "phone.json";
const LIST_VERSION: u32 = 1;

/// A vault on this iPhone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultEntry {
    /// The vault ID of the sync record: 32 lowercase hex characters.
    pub id: String,
    pub name: String,
    pub relay_url: Option<String>,
    pub team_id: Option<String>,
    pub device_id: Option<u64>,
    pub added_at: i64,
}

/// The list of vaults and the selected one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhoneList {
    pub version: u32,
    pub selected: Option<String>,
    pub vaults: Vec<VaultEntry>,
}

impl Default for PhoneList {
    fn default() -> Self {
        Self {
            version: LIST_VERSION,
            selected: None,
            vaults: Vec::new(),
        }
    }
}

/// Whether `id` is a vault ID: it names files, so nothing else may pass.
pub fn valid_id(id: &str) -> bool {
    (16..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b == b'-' || (b.is_ascii_hexdigit() && !b.is_ascii_uppercase()))
}

impl PhoneList {
    /// Read the list. A missing file is an empty list; a damaged one is an error, so
    /// nothing overwrites it.
    pub fn load(data_dir: &Path) -> CoreResult<Self> {
        let path = data_dir.join(LIST_FILE);
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(_) => return Err(CoreError::io()),
        };
        let list: Self = serde_json::from_str(&text).map_err(|_| {
            CoreError::new("storage", "The list of vaults on this iPhone is damaged.")
        })?;
        if list.version != LIST_VERSION || list.vaults.iter().any(|vault| !valid_id(&vault.id)) {
            return Err(CoreError::new(
                "unsupported_schema",
                "The list of vaults is from another version of Apassy.",
            ));
        }
        Ok(list)
    }

    /// Write the list: a private temporary file, then a rename.
    pub fn save(&self, data_dir: &Path) -> CoreResult<()> {
        let text = serde_json::to_vec_pretty(self).map_err(|_| CoreError::io())?;
        let temp = data_dir.join(format!(".{LIST_FILE}.tmp"));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temp)
            .map_err(|_| CoreError::io())?;
        file.write_all(&text)
            .and_then(|()| file.sync_all())
            .map_err(|_| CoreError::io())?;
        fs::rename(&temp, data_dir.join(LIST_FILE)).map_err(|_| CoreError::io())
    }

    pub fn get(&self, id: &str) -> Option<&VaultEntry> {
        self.vaults.iter().find(|vault| vault.id == id)
    }

    pub fn selected_entry(&self) -> Option<&VaultEntry> {
        self.selected.as_deref().and_then(|id| self.get(id))
    }

    /// Add or replace the entry of a vault, and select it.
    pub fn put(&mut self, entry: VaultEntry) {
        self.selected = Some(entry.id.clone());
        match self.vaults.iter_mut().find(|vault| vault.id == entry.id) {
            Some(vault) => *vault = entry,
            None => self.vaults.push(entry),
        }
    }

    /// Remove a vault. The next one, if any, is selected.
    pub fn remove(&mut self, id: &str) {
        self.vaults.retain(|vault| vault.id != id);
        if self.selected.as_deref() == Some(id) {
            self.selected = self.vaults.first().map(|vault| vault.id.clone());
        }
    }
}

/// The folders and files of the core under its data folder.
#[derive(Debug, Clone)]
pub struct Paths {
    pub data_dir: PathBuf,
}

impl Paths {
    /// Make the data folder and its `vaults` folder, private to this app.
    pub fn new(data_dir: PathBuf) -> CoreResult<Self> {
        if !data_dir.is_absolute() {
            return Err(CoreError::invalid(
                "The data folder must be an absolute path.",
            ));
        }
        for dir in [
            data_dir.clone(),
            data_dir.join("vaults"),
            data_dir.join("sync"),
        ] {
            fs::create_dir_all(&dir).map_err(|_| CoreError::io())?;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
                .map_err(|_| CoreError::io())?;
        }
        Ok(Self { data_dir })
    }

    pub fn vault_file(&self, id: &str) -> PathBuf {
        self.data_dir.join("vaults").join(format!("{id}.apassy"))
    }

    /// A new vault file before its ID is known.
    pub fn new_vault_file(&self, token: &str) -> PathBuf {
        self.data_dir
            .join("vaults")
            .join(format!(".new-{token}.apassy"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_name_files_only_as_hex() {
        assert!(valid_id("4f1c0a2b9d8e7f6a5b4c3d2e1f0a9b8c"));
        assert!(!valid_id("../../etc"));
        assert!(!valid_id("4F1C0A2B9D8E7F6A5B4C3D2E1F0A9B8C"));
        assert!(!valid_id("abc"));
    }

    #[test]
    fn the_list_round_trips_and_selects() {
        let dir = tempfile::tempdir().unwrap();
        let mut list = PhoneList::load(dir.path()).unwrap();
        assert!(list.vaults.is_empty());
        list.put(VaultEntry {
            id: "4f1c0a2b9d8e7f6a5b4c3d2e1f0a9b8c".into(),
            name: "Personal".into(),
            relay_url: None,
            team_id: None,
            device_id: None,
            added_at: 1,
        });
        list.save(dir.path()).unwrap();
        let read = PhoneList::load(dir.path()).unwrap();
        assert_eq!(read, list);
        assert_eq!(read.selected_entry().unwrap().name, "Personal");
        let mut read = read;
        read.remove("4f1c0a2b9d8e7f6a5b4c3d2e1f0a9b8c");
        assert!(read.selected.is_none());
    }
}
