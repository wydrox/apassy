//! The key store of the owner's host: `keys.json` next to `settings.json`
//! (docs/SPEC.md, "Host-held item keys").
//!
//! It holds one entry per item: the item key and the metadata that the host trusts
//! (the environment, the hosts, the variable name). The relay's word about an item
//! does not count. Directory 0700, file 0600, replaced atomically (a temp file with
//! mode 0600, then a rename). A lock file keeps two commands from losing each other's
//! change. The keys are plain text in this alpha: back the file up. Losing it means
//! adding the items again.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::cli::CliError;
use crate::cli::settings::{ensure_private_dir, settings_dir};
use crate::hostkeys::{self, Key32};
use crate::secret::SecretString;

pub const KEYS_FILE: &str = "keys.json";
/// Held while a command reads, changes, and writes `keys.json`.
const LOCK_FILE: &str = "keys.lock";
/// The decisions of `apassy-team host`, one JSON line each.
pub const LOG_FILE: &str = "host.log";
pub const FORMAT_VERSION: u32 = 1;

fn default_risk() -> String {
    "high".to_string()
}
fn default_scope() -> String {
    "admin".to_string()
}
fn default_reversibility() -> String {
    "irreversible".to_string()
}

/// One item of this host. Read side.
#[derive(Debug, Clone, Deserialize)]
pub struct KeyEntry {
    pub relay_url: String,
    pub team: String,
    pub uid: String,
    /// Set after the relay took the item. `None` while the upload is open, or when
    /// the answer of the relay was lost. The host finds an item by its uid.
    pub item_id: Option<u64>,
    pub name: String,
    pub env_name: String,
    pub environment: String,
    pub hosts: Vec<String>,
    #[serde(default = "default_risk")]
    pub risk: String,
    #[serde(default = "default_scope")]
    pub scope: String,
    #[serde(default = "default_reversibility")]
    pub reversibility: String,
    /// The item key: 32 bytes, base64url without padding.
    pub key: SecretString,
    pub created_at: u64,
}

impl KeyEntry {
    /// The item key, decoded.
    pub fn item_key(&self) -> Result<Key32, CliError> {
        hostkeys::decode_key(self.key.expose()).map_err(|_| {
            CliError::usage(format!(
                "The key of item {} in {KEYS_FILE} is not a valid key.",
                crate::cli::commands::clean(&self.name)
            ))
        })
    }
}

#[derive(Deserialize)]
struct KeyFile {
    version: u32,
    entries: Vec<KeyEntry>,
}

/// Write side of `KeyEntry`.
#[derive(Serialize)]
struct KeyEntryRef<'a> {
    relay_url: &'a str,
    team: &'a str,
    uid: &'a str,
    item_id: Option<u64>,
    name: &'a str,
    env_name: &'a str,
    environment: &'a str,
    hosts: &'a [String],
    risk: &'a str,
    scope: &'a str,
    reversibility: &'a str,
    key: &'a str,
    created_at: u64,
}

#[derive(Serialize)]
struct KeyFileRef<'a> {
    version: u32,
    entries: Vec<KeyEntryRef<'a>>,
}

/// The entry for `uid` of this relay, if the host has it.
pub fn find<'a>(entries: &'a [KeyEntry], relay_url: &str, uid: &str) -> Option<&'a KeyEntry> {
    entries
        .iter()
        .find(|entry| entry.relay_url == relay_url && entry.uid == uid)
}

/// The key store in one directory.
pub struct KeyStore {
    dir: PathBuf,
}

fn io_error(what: &str, err: &std::io::Error) -> CliError {
    CliError::relay(format!("Cannot {what}: {}.", err.kind()))
}

impl KeyStore {
    /// The store next to the settings file: `$XDG_CONFIG_HOME/apassy-team` or
    /// `~/.config/apassy-team`.
    pub fn open() -> Result<Self, CliError> {
        Ok(Self::at(settings_dir()?))
    }

    pub fn at(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn path(&self) -> PathBuf {
        self.dir.join(KEYS_FILE)
    }

    pub fn log_path(&self) -> PathBuf {
        self.dir.join(LOG_FILE)
    }

    /// The entries. A missing file is an empty store.
    pub fn load(&self) -> Result<Vec<KeyEntry>, CliError> {
        let path = self.path();
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => Zeroizing::new(text),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => {
                return Err(CliError::usage(format!(
                    "Cannot read the key file {}: {}.",
                    path.display(),
                    err.kind()
                )));
            }
        };
        if let Ok(meta) = std::fs::metadata(&path)
            && meta.permissions().mode() & 0o077 != 0
        {
            eprintln!(
                "apassy-team: warning: {} is readable by others. Run: chmod 600 {}",
                path.display(),
                path.display()
            );
        }
        let file: KeyFile = serde_json::from_str(&text).map_err(|_| {
            CliError::usage(format!(
                "The key file {} is not valid. Do not delete it: it holds the keys of your items.",
                path.display()
            ))
        })?;
        if file.version != FORMAT_VERSION {
            return Err(CliError::usage(format!(
                "The key file {} has version {}. This apassy-team reads version {FORMAT_VERSION}.",
                path.display(),
                file.version
            )));
        }
        Ok(file.entries)
    }

    /// Adds an entry and writes the file to disk before it returns. A second entry
    /// with the same uid is refused.
    pub fn add(&self, entry: KeyEntry) -> Result<(), CliError> {
        self.update(|entries| {
            if entries.iter().any(|e| e.uid == entry.uid) {
                return Err(CliError::usage("The key file already has this uid."));
            }
            entries.push(entry);
            Ok(())
        })
    }

    /// Sets the item id and the hosts that the relay confirmed, for the entry of `uid`.
    pub fn finish(&self, uid: &str, item_id: u64, hosts: &[String]) -> Result<(), CliError> {
        self.update(|entries| {
            let entry = entries
                .iter_mut()
                .find(|e| e.uid == uid)
                .ok_or_else(|| CliError::usage("The key file has no entry for this item."))?;
            entry.item_id = Some(item_id);
            if !hosts.is_empty() {
                entry.hosts = hosts.to_vec();
            }
            Ok(())
        })
    }

    /// Removes the entry of `uid`, if there is one.
    pub fn remove(&self, uid: &str) -> Result<(), CliError> {
        self.update(|entries| {
            entries.retain(|e| e.uid != uid);
            Ok(())
        })
    }

    /// Reads, changes, and writes the entries while the lock file is held.
    fn update<T>(
        &self,
        change: impl FnOnce(&mut Vec<KeyEntry>) -> Result<T, CliError>,
    ) -> Result<T, CliError> {
        ensure_private_dir(&self.dir)?;
        let lock = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(self.dir.join(LOCK_FILE))
            .map_err(|e| io_error("open the key file lock", &e))?;
        lock.lock().map_err(|e| io_error("lock the key file", &e))?;
        let mut entries = self.load()?;
        let out = change(&mut entries)?;
        self.save(&entries)?;
        drop(lock);
        Ok(out)
    }

    /// Writes the file: a temp file with mode 0600, synced, then renamed over the old one.
    fn save(&self, entries: &[KeyEntry]) -> Result<(), CliError> {
        let file = KeyFileRef {
            version: FORMAT_VERSION,
            entries: entries
                .iter()
                .map(|e| KeyEntryRef {
                    relay_url: &e.relay_url,
                    team: &e.team,
                    uid: &e.uid,
                    item_id: e.item_id,
                    name: &e.name,
                    env_name: &e.env_name,
                    environment: &e.environment,
                    hosts: &e.hosts,
                    risk: &e.risk,
                    scope: &e.scope,
                    reversibility: &e.reversibility,
                    key: e.key.expose(),
                    created_at: e.created_at,
                })
                .collect(),
        };
        let body = Zeroizing::new(
            serde_json::to_string_pretty(&file)
                .map_err(|_| CliError::relay("Cannot encode the key file."))?,
        );
        let path = self.path();
        let tmp = self.dir.join(format!("{KEYS_FILE}.tmp"));
        let _ = std::fs::remove_file(&tmp);
        let mut out = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| io_error("create the key file", &e))?;
        let written = out
            .write_all(body.as_bytes())
            .and_then(|()| out.write_all(b"\n"))
            .and_then(|()| out.sync_all());
        if let Err(err) = written {
            let _ = std::fs::remove_file(&tmp);
            return Err(io_error("write the key file", &err));
        }
        if let Err(err) = std::fs::rename(&tmp, &path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(io_error("replace the key file", &err));
        }
        // The rename is durable once the directory is synced.
        if let Ok(dir) = File::open(&self.dir) {
            let _ = dir.sync_all();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RELAY: &str = "https://relay.example.test";

    fn entry(uid: &str, key: &Key32) -> KeyEntry {
        KeyEntry {
            relay_url: RELAY.to_string(),
            team: "Test Team".to_string(),
            uid: uid.to_string(),
            item_id: None,
            name: "Stripe test key".to_string(),
            env_name: "STRIPE_API_KEY".to_string(),
            environment: "staging".to_string(),
            hosts: vec!["api.stripe.com".to_string()],
            risk: "high".to_string(),
            scope: "admin".to_string(),
            reversibility: "irreversible".to_string(),
            key: SecretString::new(hostkeys::encode_key(key).to_string()),
            created_at: 1,
        }
    }

    fn uid(n: u8) -> String {
        format!("{n:02x}").repeat(16)
    }

    #[test]
    fn the_file_is_private_and_holds_the_documented_fields() {
        let dir = tempfile::tempdir().unwrap();
        let store = KeyStore::at(dir.path().join("apassy-team"));
        assert!(store.load().unwrap().is_empty());
        let key = hostkeys::new_key().unwrap();
        store.add(entry(&uid(1), &key)).unwrap();
        let dir_mode = std::fs::metadata(store.dir()).unwrap().permissions().mode() & 0o777;
        let file_mode = std::fs::metadata(store.path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!((dir_mode, file_mode), (0o700, 0o600));
        let json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(store.path()).unwrap()).unwrap();
        assert_eq!(json["version"], 1);
        let first = &json["entries"][0];
        for field in [
            "relay_url",
            "team",
            "uid",
            "item_id",
            "name",
            "env_name",
            "environment",
            "hosts",
            "key",
            "created_at",
        ] {
            assert!(first.get(field).is_some(), "{field}");
        }
        assert!(first["item_id"].is_null());
        assert_eq!(first["key"], hostkeys::encode_key(&key).as_str());
        // No temp file is left behind.
        let names: Vec<String> = std::fs::read_dir(store.dir())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(!names.iter().any(|n| n.ends_with(".tmp")), "{names:?}");
    }

    #[test]
    fn a_wider_mode_is_repaired_by_the_next_write() {
        let dir = tempfile::tempdir().unwrap();
        let store = KeyStore::at(dir.path().join("apassy-team"));
        let key = hostkeys::new_key().unwrap();
        store.add(entry(&uid(1), &key)).unwrap();
        std::fs::set_permissions(store.path(), std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::set_permissions(store.dir(), std::fs::Permissions::from_mode(0o755)).unwrap();
        store.add(entry(&uid(2), &key)).unwrap();
        let dir_mode = std::fs::metadata(store.dir()).unwrap().permissions().mode() & 0o777;
        let file_mode = std::fs::metadata(store.path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!((dir_mode, file_mode), (0o700, 0o600));
    }

    #[test]
    fn add_finish_and_remove() {
        let dir = tempfile::tempdir().unwrap();
        let store = KeyStore::at(dir.path());
        let key = hostkeys::new_key().unwrap();
        store.add(entry(&uid(1), &key)).unwrap();
        store.add(entry(&uid(2), &key)).unwrap();
        assert!(
            store.add(entry(&uid(2), &key)).is_err(),
            "a uid is used once"
        );
        store
            .finish(
                &uid(1),
                42,
                &["api.stripe.com".to_string(), "x.example".to_string()],
            )
            .unwrap();
        let entries = store.load().unwrap();
        assert_eq!(entries.len(), 2);
        let first = find(&entries, RELAY, &uid(1)).unwrap();
        assert_eq!(first.item_id, Some(42));
        assert_eq!(first.hosts, vec!["api.stripe.com", "x.example"]);
        assert_eq!(*first.item_key().unwrap(), *key);
        assert!(find(&entries, "https://other.example", &uid(1)).is_none());
        store.remove(&uid(1)).unwrap();
        store.remove(&uid(9)).unwrap();
        let entries = store.load().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].uid, uid(2));
        assert!(store.finish(&uid(1), 1, &[]).is_err());
    }

    #[test]
    fn concurrent_adds_lose_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_path_buf();
        let key = hostkeys::new_key().unwrap();
        let threads: Vec<_> = (0..8u8)
            .map(|n| {
                let path = path.clone();
                let key = key.clone();
                std::thread::spawn(move || {
                    KeyStore::at(path).add(entry(&uid(n + 1), &key)).unwrap();
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        assert_eq!(KeyStore::at(&path).load().unwrap().len(), 8);
    }

    #[test]
    fn a_broken_or_newer_file_is_refused_and_kept() {
        let dir = tempfile::tempdir().unwrap();
        let store = KeyStore::at(dir.path());
        std::fs::write(store.path(), "not json").unwrap();
        assert!(store.load().is_err());
        let key = hostkeys::new_key().unwrap();
        assert!(store.add(entry(&uid(1), &key)).is_err());
        assert_eq!(std::fs::read_to_string(store.path()).unwrap(), "not json");
        std::fs::write(store.path(), r#"{"version":2,"entries":[]}"#).unwrap();
        assert!(store.load().unwrap_err().message.contains("version 2"));
    }
}
