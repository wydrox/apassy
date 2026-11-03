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
    /// Missing in older lists. Then `relay_url` determines relay or local storage.
    #[serde(default)]
    pub sync_source: Option<String>,
    pub relay_url: Option<String>,
    pub team_id: Option<String>,
    pub device_id: Option<u64>,
    pub added_at: i64,
    /// The pin of a node relay (contract node-pairing-v1 section 9): the b64u SHA-256 of
    /// its certificate. Missing in older lists and for a hosted relay: system trust. The
    /// list version stays 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin: Option<String>,
    /// The alternative destinations of a node relay, `host:port` each, in order. Missing
    /// in older lists and for a hosted relay.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alt: Vec<String>,
    /// The display name of a pinned node from its link (node-pairing-v1 section 7), for
    /// "via your Mac" in Settings: a label, never an authority. Missing for a hosted relay,
    /// for a link without `name`, and in older lists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_name: Option<String>,
}

impl VaultEntry {
    pub fn is_icloud(&self) -> bool {
        self.sync_source.as_deref() == Some("icloud")
    }

    /// The relay sync of this vault: its relay origin with the pin and the alternatives
    /// that the entry keeps. `None` for a vault without a relay.
    pub fn relay_config(
        &self,
        data_dir: &Path,
        vault_file: &Path,
    ) -> CoreResult<Option<apassy::sync::RelayConfig>> {
        let Some(url) = self.relay_url.as_deref() else {
            return Ok(None);
        };
        let trust = apassy::sync::TlsTrust::from_pin_text(self.pin.as_deref())?;
        let config = apassy::sync::RelayConfig::in_data_dir(data_dir, vault_file, url, &self.id)
            .with_trust(trust, &self.alt);
        config.relay_url()?;
        Ok(Some(config))
    }
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
        write_private(data_dir, LIST_FILE, &text)
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

/// Write `name` in `data_dir`: a private temporary file, then a rename.
pub fn write_private(data_dir: &Path, name: &str, text: &[u8]) -> CoreResult<()> {
    let temp = data_dir.join(format!(".{name}.tmp"));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temp)
        .map_err(|_| CoreError::io())?;
    file.write_all(text)
        .and_then(|()| file.sync_all())
        .map_err(|_| CoreError::io())?;
    fs::rename(&temp, data_dir.join(name)).map_err(|_| CoreError::io())?;
    fs::File::open(data_dir)
        .and_then(|dir| dir.sync_all())
        .map_err(|_| CoreError::io())
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
            data_dir.join("icloud-transfer"),
        ] {
            fs::create_dir_all(&dir).map_err(|_| CoreError::io())?;
            let meta = fs::symlink_metadata(&dir).map_err(|_| CoreError::io())?;
            if !meta.is_dir() || meta.file_type().is_symlink() {
                return Err(CoreError::invalid(
                    "Use a private data folder without links.",
                ));
            }
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
            sync_source: None,
            relay_url: None,
            team_id: None,
            device_id: None,
            added_at: 1,
            pin: None,
            alt: Vec::new(),
            node_name: None,
        });
        list.save(dir.path()).unwrap();
        let read = PhoneList::load(dir.path()).unwrap();
        assert_eq!(read, list);
        assert_eq!(read.selected_entry().unwrap().name, "Personal");
        let mut read = read;
        read.remove("4f1c0a2b9d8e7f6a5b4c3d2e1f0a9b8c");
        assert!(read.selected.is_none());
    }

    /// Contract node-pairing-v1 section 9: an entry of a node keeps its pin and its
    /// alternatives, a hosted entry writes neither, and a list of version 1 without them
    /// loads with no pin. A stored pin that is not a pin never becomes system trust.
    #[test]
    fn an_entry_keeps_the_pin_of_a_node_and_an_old_list_has_none() {
        const PIN: &str = "u7Ri74l_xMBm74XnZDWpOC6Z4p6n4aUqwWmsV6firLE";
        let dir = tempfile::tempdir().unwrap();
        let mut list = PhoneList::default();
        let entry = VaultEntry {
            id: "4f1c0a2b9d8e7f6a5b4c3d2e1f0a9b8c".into(),
            name: "Node".into(),
            sync_source: Some("relay".into()),
            relay_url: Some("https://100.64.0.7:8444".into()),
            team_id: Some("t_7k2m5q4x3c".into()),
            device_id: Some(3),
            added_at: 1,
            pin: Some(PIN.into()),
            alt: vec!["apassy-mini.tail0123.ts.net:8444".into()],
            node_name: Some("Mac mini “Studio”".into()),
        };
        list.put(entry.clone());
        list.save(dir.path()).unwrap();
        let text = std::fs::read_to_string(dir.path().join(LIST_FILE)).unwrap();
        assert!(text.contains(PIN), "{text}");
        let read = PhoneList::load(dir.path()).unwrap();
        assert_eq!(read.version, 1);
        assert_eq!(read.vaults, [entry.clone()]);
        let vault_file = dir.path().join("vault.apassy");
        let config = entry
            .relay_config(dir.path(), &vault_file)
            .unwrap()
            .unwrap();
        let url = config.relay_url().unwrap();
        assert_eq!(url.as_str(), "https://100.64.0.7:8444");
        assert_eq!(url.pin().map(|pin| pin.text()).as_deref(), Some(PIN));
        assert_eq!(url.alternative_list(), entry.alt);

        // A list of version 1 without the fields: no pin, no alternatives.
        let old = r#"{"version":1,"selected":null,"vaults":[{"id":"4f1c0a2b9d8e7f6a5b4c3d2e1f0a9b8c","name":"Old","sync_source":"relay","relay_url":"https://apassy-relay.wyderka.cc","team_id":"t_7k2m5q4x3c","device_id":2,"added_at":1}]}"#;
        std::fs::write(dir.path().join(LIST_FILE), old).unwrap();
        let read = PhoneList::load(dir.path()).unwrap();
        assert_eq!(read.vaults[0].pin, None);
        assert!(read.vaults[0].alt.is_empty());
        assert_eq!(read.vaults[0].node_name, None);
        let hosted = read.vaults[0]
            .relay_config(dir.path(), &vault_file)
            .unwrap()
            .unwrap();
        assert_eq!(
            hosted.relay_url().unwrap().trust(),
            apassy::sync::TlsTrust::System
        );
        let written = serde_json::to_string(&read.vaults[0]).unwrap();
        assert!(!written.contains("\"pin\"") && !written.contains("\"alt\""));
        assert!(!written.contains("\"node_name\""));

        // A damaged pin is an error, never system trust.
        let mut damaged = entry;
        damaged.pin = Some("short".into());
        assert!(damaged.relay_config(dir.path(), &vault_file).is_err());
    }
}
