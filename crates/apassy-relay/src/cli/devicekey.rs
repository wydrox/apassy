//! Device key stores. Tests select the file store and never open the Keychain.

use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use zeroize::Zeroizing;

use crate::cli::{CliError, settings};
use crate::device::DeviceKey;
use crate::hostkeys::{decode_b64, encode_b64};
use crate::ids::TeamId;

pub const ENV_KEY_STORE: &str = "APASSY_TEAM_KEY_STORE";

/// A replaceable store for a team's device key.
pub trait KeyStore: Send + Sync {
    fn load(&self, relay: &str, team: &TeamId) -> Result<Option<DeviceKey>, CliError>;
    /// Refuses to replace a key. Onboarding must keep the first key after errors.
    fn save(&self, relay: &str, team: &TeamId, key: &DeviceKey) -> Result<(), CliError>;
    fn remove(&self, relay: &str, team: &TeamId) -> Result<(), CliError>;
}

pub struct FileKeyStore {
    dir: PathBuf,
}

impl FileKeyStore {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }
    pub fn path(&self, team: &TeamId) -> PathBuf {
        self.dir.join(format!("device-{team}.key"))
    }
}

struct KeyLock(PathBuf);
impl KeyLock {
    fn acquire(dir: &std::path::Path, team: &TeamId) -> Result<Self, CliError> {
        settings::ensure_private_dir(dir)?;
        let path = dir.join(format!("device-{team}.lock"));
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|_| {
                CliError::usage(
                    "The device key store is locked. Try again after the other command stops.",
                )
            })?;
        Ok(Self(path))
    }
}
impl Drop for KeyLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn decode_key(text: &str) -> Result<DeviceKey, CliError> {
    let bytes = Zeroizing::new(
        decode_b64(text.trim(), 4096)
            .map_err(|_| CliError::usage("The device key is not valid."))?,
    );
    DeviceKey::from_pkcs8(&bytes).map_err(|_| CliError::usage("The device key is not valid."))
}

impl KeyStore for FileKeyStore {
    fn load(&self, _relay: &str, team: &TeamId) -> Result<Option<DeviceKey>, CliError> {
        let path = self.path(team);
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(CliError::usage("Cannot read the device key file.")),
        };
        if !meta.is_file() || meta.permissions().mode() & 0o077 != 0 {
            return Err(CliError::usage(format!(
                "The device key file {} is not private. Set mode 600.",
                path.display()
            )));
        }
        let text = Zeroizing::new(
            std::fs::read_to_string(&path)
                .map_err(|_| CliError::usage("Cannot read the device key file."))?,
        );
        decode_key(&text).map(Some)
    }
    fn save(&self, _relay: &str, team: &TeamId, key: &DeviceKey) -> Result<(), CliError> {
        settings::ensure_private_dir(&self.dir)?;
        let _lock = KeyLock::acquire(&self.dir, team)?;
        let path = self.path(team);
        if path
            .try_exists()
            .map_err(|_| CliError::usage("Cannot check the device key file."))?
        {
            return Err(CliError::usage(
                "This machine already has a device key for this team. Use another XDG_CONFIG_HOME.",
            ));
        }
        let tmp = self
            .dir
            .join(format!("device-{team}.{}.tmp", std::process::id()));
        let body = Zeroizing::new(encode_b64(key.pkcs8()));
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|_| CliError::relay("Cannot create the device key file."))?;
        let result = output
            .write_all(body.as_bytes())
            .and_then(|_| output.write_all(b"\n"))
            .and_then(|_| output.sync_all())
            .and_then(|_| std::fs::rename(&tmp, &path));
        let _ = std::fs::remove_file(&tmp);
        result.map_err(|_| {
            CliError::relay("Cannot save the device key. An existing key is not replaced.")
        })
    }
    fn remove(&self, _relay: &str, team: &TeamId) -> Result<(), CliError> {
        match std::fs::remove_file(self.path(team)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(CliError::relay("Cannot remove the device key file.")),
        }
    }
}

#[cfg(all(target_os = "macos", not(test)))]
pub struct KeychainStore;

#[cfg(all(target_os = "macos", not(test)))]
impl KeychainStore {
    fn account(relay: &str, team: &TeamId) -> Result<String, CliError> {
        let origin = settings::normalize_url(relay)?;
        let host = origin.split_once("://").map(|(_, h)| h).unwrap_or("");
        Ok(format!("{host} {team}"))
    }
}

#[cfg(all(target_os = "macos", not(test)))]
impl KeyStore for KeychainStore {
    fn load(&self, relay: &str, team: &TeamId) -> Result<Option<DeviceKey>, CliError> {
        let account = Self::account(relay, team)?;
        match security_framework::passwords::get_generic_password("apassy-team", &account) {
            Ok(bytes) => {
                let bytes = Zeroizing::new(bytes);
                let text = std::str::from_utf8(&bytes)
                    .map_err(|_| CliError::usage("The device key is not valid."))?;
                decode_key(text).map(Some)
            }
            Err(e) if e.code() == -25300 => Ok(None),
            Err(_) => Err(CliError::usage(
                "Cannot read the device key from the login Keychain.",
            )),
        }
    }
    fn save(&self, relay: &str, team: &TeamId, key: &DeviceKey) -> Result<(), CliError> {
        let _lock = KeyLock::acquire(&settings::settings_dir()?, team)?;
        if self.load(relay, team)?.is_some() {
            return Err(CliError::usage(
                "This machine already has a device key for this team. Use another XDG_CONFIG_HOME.",
            ));
        }
        let account = Self::account(relay, team)?;
        let body = Zeroizing::new(encode_b64(key.pkcs8()));
        security_framework::passwords::set_generic_password(
            "apassy-team",
            &account,
            body.as_bytes(),
        )
        .map_err(|_| CliError::relay("Cannot save the device key in the login Keychain."))
    }
    fn remove(&self, relay: &str, team: &TeamId) -> Result<(), CliError> {
        let account = Self::account(relay, team)?;
        match security_framework::passwords::delete_generic_password("apassy-team", &account) {
            Ok(()) => Ok(()),
            Err(e) if e.code() == -25300 => Ok(()),
            Err(_) => Err(CliError::relay(
                "Cannot remove the device key from the login Keychain.",
            )),
        }
    }
}

pub fn store() -> Result<Box<dyn KeyStore>, CliError> {
    let choice = std::env::var(ENV_KEY_STORE)
        .ok()
        .filter(|s| !s.trim().is_empty());
    if let Some(choice) = &choice
        && choice != "file"
    {
        return Err(CliError::usage(
            "APASSY_TEAM_KEY_STORE must be file, or unset.",
        ));
    }
    #[cfg(all(target_os = "macos", not(test)))]
    if choice.is_none() {
        return Ok(Box::new(KeychainStore));
    }
    Ok(Box::new(FileKeyStore::new(settings::settings_dir()?)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn file_store_keeps_a_private_key_and_never_replaces_it() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileKeyStore::new(dir.path().to_owned());
        let team = TeamId::parse("t_abcdefgh23").unwrap();
        let key = DeviceKey::generate().unwrap();
        let relay = "https://relay.example";
        assert!(store.load(relay, &team).unwrap().is_none());
        store.save(relay, &team, &key).unwrap();
        assert_eq!(
            store.load(relay, &team).unwrap().unwrap().public_key(),
            key.public_key()
        );
        assert!(
            store
                .save(relay, &team, &DeviceKey::generate().unwrap())
                .is_err()
        );
        let path = store.path(&team);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(store.load(relay, &team).is_err());
        store.remove(relay, &team).unwrap();
        assert!(store.load(relay, &team).unwrap().is_none());
    }
}
