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

struct KeyLock {
    file: std::fs::File,
}
impl KeyLock {
    fn acquire(dir: &std::path::Path, team: &TeamId) -> Result<Self, CliError> {
        settings::ensure_private_dir(dir)?;
        let path = dir.join(format!("device-{team}.lock"));
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&path)
            .map_err(|_| {
                CliError::usage(
                    "The device key store is locked. Try again after the other command stops.",
                )
            })?;
        file.try_lock().map_err(|_| {
            CliError::usage(
                "The device key store is locked. Try again after the other command stops.",
            )
        })?;
        Ok(Self { file })
    }
}
impl Drop for KeyLock {
    fn drop(&mut self) {
        // A child can inherit the file handle before exec. Closing our handle
        // alone does not release a lock while that inherited handle is open.
        let _ = self.file.unlock();
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

#[cfg(any(target_os = "macos", test))]
pub struct KeychainStore;

#[cfg(any(target_os = "macos", test))]
impl KeychainStore {
    fn account(relay: &str, team: &TeamId) -> Result<String, CliError> {
        let origin = settings::normalize_url(relay)?;
        let host = origin.split_once("://").map(|(_, h)| h).unwrap_or("");
        let dir = std::path::absolute(settings::settings_dir()?)
            .map_err(|_| CliError::usage("Cannot determine the settings directory."))?;
        Ok(format!("{host} {team} {}", dir.display()))
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
    fn stale_lock_file_does_not_block_save() {
        let dir = tempfile::tempdir().unwrap();
        let team = TeamId::parse("t_abcdefgh23").unwrap();
        let lock_path = dir.path().join(format!("device-{team}.lock"));
        std::fs::write(&lock_path, b"stale lock file").unwrap();
        std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let store = FileKeyStore::new(dir.path().to_owned());
        store
            .save(
                "https://relay.example",
                &team,
                &DeviceKey::generate().unwrap(),
            )
            .unwrap();
        assert_eq!(std::fs::read(&lock_path).unwrap(), b"stale lock file");
        assert_eq!(
            std::fs::metadata(lock_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn key_lock_drop_releases_os_lock_and_keeps_file() {
        let dir = tempfile::tempdir().unwrap();
        let team = TeamId::parse("t_abcdefgh23").unwrap();
        let lock = KeyLock::acquire(dir.path(), &team).unwrap();
        let path = dir.path().join(format!("device-{team}.lock"));
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(KeyLock::acquire(dir.path(), &team).is_err());
        let _inherited = lock.file.try_clone().unwrap();
        drop(lock);
        assert!(path.exists());
        let _lock = KeyLock::acquire(dir.path(), &team).unwrap();
    }

    #[test]
    fn key_lock_process_holder() {
        let Some(dir) = std::env::var_os("APASSY_TEST_KEY_LOCK_DIR") else {
            return;
        };
        let dir = PathBuf::from(dir);
        let team = TeamId::parse("t_abcdefgh23").unwrap();
        let _lock = KeyLock::acquire(&dir, &team).unwrap();
        std::fs::write(dir.join("ready"), b"ready").unwrap();
        loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }

    #[test]
    fn concurrent_save_is_locked_until_holder_process_exits() {
        struct Holder(std::process::Child);
        impl Drop for Holder {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let mut holder = Holder(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "cli::devicekey::tests::key_lock_process_holder"])
                .env("APASSY_TEST_KEY_LOCK_DIR", dir.path())
                .stdout(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        );
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !dir.path().join("ready").exists() {
            assert!(holder.0.try_wait().unwrap().is_none(), "lock holder exited");
            assert!(
                std::time::Instant::now() < deadline,
                "lock holder did not start"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let team = TeamId::parse("t_abcdefgh23").unwrap();
        let store = FileKeyStore::new(dir.path().to_owned());
        let key = DeviceKey::generate().unwrap();
        assert!(store.save("https://relay.example", &team, &key).is_err());
        assert!(
            store
                .load("https://relay.example", &team)
                .unwrap()
                .is_none()
        );
        holder.0.kill().unwrap();
        holder.0.wait().unwrap();
        store.save("https://relay.example", &team, &key).unwrap();
        assert_eq!(
            store
                .load("https://relay.example", &team)
                .unwrap()
                .unwrap()
                .public_key(),
            key.public_key()
        );
        assert!(dir.path().join(format!("device-{team}.lock")).exists());
    }

    #[test]
    fn keychain_account_matches_settings_directory() {
        let Ok(expected) = std::env::var("APASSY_TEST_KEYCHAIN_ACCOUNT") else {
            return;
        };
        let team = TeamId::parse("t_abcdefgh23").unwrap();
        assert_eq!(
            KeychainStore::account("https://relay.example/", &team).unwrap(),
            expected
        );
    }

    #[test]
    fn keychain_accounts_are_separate_for_each_xdg_config_home() {
        let dir = tempfile::tempdir().unwrap();
        for home in [
            dir.path().join("first config"),
            dir.path().join("second config"),
        ] {
            let settings_dir = home.join("apassy-team");
            let expected = format!("relay.example t_abcdefgh23 {}", settings_dir.display());
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "cli::devicekey::tests::keychain_account_matches_settings_directory",
                ])
                .env("XDG_CONFIG_HOME", &home)
                .env("APASSY_TEST_KEYCHAIN_ACCOUNT", expected)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stdout)
            );
        }
    }

    #[test]
    fn keychain_account_uses_absolute_settings_directory() {
        let dir = std::path::absolute("relative-home/.config/apassy-team").unwrap();
        let expected = format!("relay.example t_abcdefgh23 {}", dir.display());
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "cli::devicekey::tests::keychain_account_matches_settings_directory",
            ])
            .env("XDG_CONFIG_HOME", "relative-xdg")
            .env("HOME", "relative-home")
            .env("APASSY_TEST_KEYCHAIN_ACCOUNT", expected)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
    }

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
