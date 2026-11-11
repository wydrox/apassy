//! Where the account device key is kept on each platform (plan s7 decision 2, ADR 0045).
//!
//! - **macOS**: the Keychain through the signed helper
//!   ([`super::device_key::KeychainDeviceKeyStore`]): this device only, not
//!   synchronizable, behind Touch ID with the current fingerprints.
//! - **Linux**: [`FileKeyStore`], a private file of the user in the app's data directory:
//!   `connect/device-key` next to the account file, mode 0600 in a 0700 directory,
//!   owned by this user, never a symlink, written atomically (a new private file, then a
//!   rename). It is outside every vault. Linux has no boundary that keeps another
//!   program of the same user from reading it (ADR 0045, "Security boundary"): such a
//!   program can read the key and so sign in to the Connect account as this computer:
//!   see the account, its plan and its devices, make a device link, and read and write
//!   the encrypted copies of the vault stores. It gains no vault content: every copy is
//!   SQLCipher ciphertext under the vault's passphrase, which the key does not open. A
//!   new device still needs an owner check on this computer to join.
//! - **Linux, opt-in**: [`SecretServiceKeyStore`], the Secret Service of the desktop
//!   (`secret-tool`), only after the explicit consent of [`KEYRING_WARNING`], as for the
//!   vault passphrase (`crate::native::linux::store_passphrase`). Other programs of the
//!   same user can read an unlocked keyring item too.
//!
//! A damaged file (not a key), a file that is not private to this user, a link, or a
//! file of another owner is never used: the key counts as lost
//! ([`DeviceKeyError::Lost`], the removed state of Settings › Connect), and only the
//! owner's "Forget This Computer…" deletes it.

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use zeroize::Zeroizing;

use super::device_key::{DeviceKeyError, DeviceKeyStore};

/// The file name of the key, in the `connect` directory of the data directory.
pub const KEY_FILE: &str = "device-key";
/// The first bytes of the file: the format and its version, then the PKCS#8 document.
const MAGIC: &[u8] = b"apassy-connect-device-key v1\n";
/// The longest file that is read.
const MAX_FILE_BYTES: u64 = 4096;

/// The key file of the data directory `dir`.
pub fn key_file(dir: &Path) -> PathBuf {
    dir.join("connect").join(KEY_FILE)
}

/// The key store of this platform for the data directory `dir`: the Keychain on macOS
/// (`None` without the signed helper: a build outside Apassy.app has no account key),
/// the private file on Linux.
pub fn platform_store(dir: &Path) -> Option<Arc<dyn DeviceKeyStore>> {
    #[cfg(target_os = "macos")]
    {
        let _ = dir;
        crate::native::NativeHelper::locate().ok().map(|helper| {
            Arc::new(super::device_key::KeychainDeviceKeyStore::new(helper))
                as Arc<dyn DeviceKeyStore>
        })
    }
    #[cfg(not(target_os = "macos"))]
    {
        Some(Arc::new(FileKeyStore::new(key_file(dir))) as Arc<dyn DeviceKeyStore>)
    }
}

/// The account key in a private file of the user (Linux). See the module text.
#[derive(Debug, Clone)]
pub struct FileKeyStore {
    path: PathBuf,
}

impl FileKeyStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn failed(what: &str) -> DeviceKeyError {
    DeviceKeyError::Failed(format!("the Connect key file {what}"))
}

/// The directory of the file: made with mode 0700 when it is missing; it must be a
/// directory of this user, not a link, and not open to others.
fn private_dir(dir: &Path) -> Result<(), DeviceKeyError> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|_| failed("folder cannot be made"))?;
    let meta = fs::symlink_metadata(dir).map_err(|_| failed("folder cannot be read"))?;
    if !meta.is_dir() || meta.uid() != rustix::process::geteuid().as_raw() {
        return Err(failed("folder is not a folder of this user"));
    }
    if meta.mode() & 0o077 != 0 {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .map_err(|_| failed("folder cannot be made private"))?;
    }
    Ok(())
}

impl DeviceKeyStore for FileKeyStore {
    fn read(&self) -> Result<Option<Zeroizing<Vec<u8>>>, DeviceKeyError> {
        // The folder too: a link in its place, or a folder of another user, is not this
        // user's private folder.
        if let Some(dir) = self.path.parent() {
            match fs::symlink_metadata(dir) {
                Ok(meta) if !meta.is_dir() || meta.uid() != rustix::process::geteuid().as_raw() => {
                    return Err(DeviceKeyError::Lost);
                }
                Ok(_) => {}
                Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
                Err(_) => return Err(failed("folder cannot be read")),
            }
        }
        let meta = match fs::symlink_metadata(&self.path) {
            Ok(meta) => meta,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(failed("cannot be read")),
        };
        // A link, another kind of file, a file of another user, or one that others can
        // read is never used: the key may be known elsewhere.
        if !meta.file_type().is_file()
            || meta.uid() != rustix::process::geteuid().as_raw()
            || meta.mode() & 0o077 != 0
            || meta.len() > MAX_FILE_BYTES
        {
            return Err(DeviceKeyError::Lost);
        }
        let mut bytes = Zeroizing::new(Vec::new());
        OpenOptions::new()
            .read(true)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&self.path)
            .and_then(|file| file.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes))
            .map_err(|_| failed("cannot be read"))?;
        match bytes.strip_prefix(MAGIC) {
            Some(document) if !document.is_empty() => Ok(Some(Zeroizing::new(document.to_vec()))),
            _ => Err(DeviceKeyError::Lost),
        }
    }

    fn store(&self, pkcs8: &[u8]) -> Result<(), DeviceKeyError> {
        if pkcs8.is_empty() || (pkcs8.len() + MAGIC.len()) as u64 > MAX_FILE_BYTES {
            return Err(failed("is too long"));
        }
        let dir = self.path.parent().ok_or_else(|| failed("has no folder"))?;
        private_dir(dir)?;
        let name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| failed("has no name"))?;
        let temporary = dir.join(format!(".{name}.{}.new", std::process::id()));
        let _ = fs::remove_file(&temporary);
        let mut bytes = Zeroizing::new(Vec::with_capacity(MAGIC.len() + pkcs8.len()));
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(pkcs8);
        let written = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
                .open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            // The rename replaces a link at the path itself, never its target.
            fs::rename(&temporary, &self.path)?;
            // The rename is durable with the folder.
            fs::File::open(dir)?.sync_all()
        })();
        if written.is_err() {
            let _ = fs::remove_file(&temporary);
            return Err(failed("cannot be written"));
        }
        Ok(())
    }

    fn delete(&self) -> Result<bool, DeviceKeyError> {
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
            Err(_) => Err(failed("cannot be deleted")),
        }
    }
}

/// The warning that the owner accepts before the account key goes to the Secret
/// Service (Linux, opt-in).
pub const KEYRING_WARNING: &str = "Store the Apassy Connect key of this computer in Secret Service? Other programs running as your user can retrieve it while the keyring is unlocked. It signs in to your Connect account; it does not open a vault.";

/// The account key in the Secret Service (Linux), only after the owner accepted
/// [`KEYRING_WARNING`]. The key goes to `secret-tool` on a pipe, as base64 text.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
pub struct SecretServiceKeyStore(());

#[cfg(target_os = "linux")]
impl SecretServiceKeyStore {
    /// The store, only with the owner's explicit `consent` to [`KEYRING_WARNING`].
    pub fn with_consent(consent: bool) -> Option<Self> {
        consent.then_some(Self(()))
    }
}

#[cfg(target_os = "linux")]
impl DeviceKeyStore for SecretServiceKeyStore {
    fn read(&self) -> Result<Option<Zeroizing<Vec<u8>>>, DeviceKeyError> {
        let Some(text) =
            crate::native::linux::read_connect_key().map_err(DeviceKeyError::Failed)?
        else {
            return Ok(None);
        };
        crate::sync::decode_b64u(text.trim())
            .map(|bytes| Some(Zeroizing::new(bytes)))
            .ok_or(DeviceKeyError::Lost)
    }

    fn store(&self, pkcs8: &[u8]) -> Result<(), DeviceKeyError> {
        let text = Zeroizing::new(crate::sync::encode_b64u(pkcs8));
        crate::native::linux::store_connect_key(&text, true).map_err(DeviceKeyError::Failed)
    }

    fn delete(&self) -> Result<bool, DeviceKeyError> {
        crate::native::linux::delete_connect_key().map_err(DeviceKeyError::Failed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connect::{AccountSigner, ConnectError};

    fn store_in(dir: &Path) -> FileKeyStore {
        FileKeyStore::new(key_file(dir))
    }

    #[test]
    fn the_key_file_is_private_and_round_trips() {
        let dir = tempfile::tempdir().expect("dir");
        let store = store_in(dir.path());
        assert!(store.read().unwrap().is_none());
        let signer = AccountSigner::open_or_create(&store).expect("key");
        let meta = fs::symlink_metadata(store.path()).unwrap();
        assert_eq!(meta.mode() & 0o777, 0o600);
        let folder = fs::symlink_metadata(store.path().parent().unwrap()).unwrap();
        assert_eq!(folder.mode() & 0o777, 0o700);
        let again = AccountSigner::open(&store).unwrap().expect("the same key");
        assert_eq!(signer.public_key(), again.public_key());
        // No temporary file stays.
        let names: Vec<_> = fs::read_dir(store.path().parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, [KEY_FILE]);
        assert!(store.delete().unwrap());
        assert!(!store.delete().unwrap());
        assert!(AccountSigner::open(&store).unwrap().is_none());
    }

    #[test]
    fn a_new_key_replaces_the_file_atomically() {
        let dir = tempfile::tempdir().expect("dir");
        let store = store_in(dir.path());
        let first = AccountSigner::open_or_create(&store).expect("key");
        let inode = fs::metadata(store.path()).unwrap().ino();
        let other = crate::sync::DeviceKey::generate().expect("key");
        store.store(other.pkcs8().expect("pkcs8")).expect("store");
        // A new file took the place of the old one (a rename), not a write into it.
        assert_ne!(fs::metadata(store.path()).unwrap().ino(), inode);
        let read = AccountSigner::open(&store).unwrap().expect("key");
        assert_ne!(read.public_key(), first.public_key());
        assert_eq!(read.public_key(), other.public_key());
    }

    #[test]
    fn a_link_is_never_followed_or_used() {
        let dir = tempfile::tempdir().expect("dir");
        let store = store_in(dir.path());
        AccountSigner::open_or_create(&store).expect("key");
        let target = dir.path().join("elsewhere");
        fs::rename(store.path(), &target).unwrap();
        std::os::unix::fs::symlink(&target, store.path()).unwrap();
        assert_eq!(store.read().unwrap_err(), DeviceKeyError::Lost);
        assert_eq!(
            AccountSigner::open(&store).unwrap_err(),
            ConnectError::KeyLost
        );
        // A store replaces the link itself; the target stays as it was.
        let before = fs::read(&target).unwrap();
        let other = crate::sync::DeviceKey::generate().expect("key");
        store.store(other.pkcs8().unwrap()).expect("store");
        assert!(
            !fs::symlink_metadata(store.path())
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read(&target).unwrap(), before);
        // A link in the place of the `connect` folder is refused, for a read and a
        // write, and nothing is written through it.
        let real = dir.path().join("real");
        fs::create_dir(&real).unwrap();
        fs::write(real.join(KEY_FILE), b"planted").unwrap();
        fs::set_permissions(real.join(KEY_FILE), fs::Permissions::from_mode(0o600)).unwrap();
        let base = dir.path().join("base");
        fs::create_dir(&base).unwrap();
        std::os::unix::fs::symlink(&real, base.join("connect")).unwrap();
        let linked = FileKeyStore::new(key_file(&base));
        assert_eq!(linked.read().unwrap_err(), DeviceKeyError::Lost);
        assert!(linked.store(other.pkcs8().unwrap()).is_err());
        assert_eq!(fs::read(real.join(KEY_FILE)).unwrap(), b"planted");
    }

    #[test]
    fn an_open_or_damaged_file_is_a_lost_key() {
        let dir = tempfile::tempdir().expect("dir");
        let store = store_in(dir.path());
        AccountSigner::open_or_create(&store).expect("key");
        fs::set_permissions(store.path(), fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(store.read().unwrap_err(), DeviceKeyError::Lost);
        fs::set_permissions(store.path(), fs::Permissions::from_mode(0o600)).unwrap();
        assert!(store.read().unwrap().is_some());
        // Not the format: lost.
        fs::write(store.path(), b"not a key").unwrap();
        assert_eq!(store.read().unwrap_err(), DeviceKeyError::Lost);
        // The format, but not a P-256 document: the signer refuses it as a lost key.
        let mut damaged = MAGIC.to_vec();
        damaged.extend_from_slice(&[1, 2, 3]);
        fs::write(store.path(), &damaged).unwrap();
        assert_eq!(
            AccountSigner::open(&store).unwrap_err(),
            ConnectError::KeyLost
        );
        // A folder in the place of the file: lost, never followed.
        fs::remove_file(store.path()).unwrap();
        fs::create_dir(store.path()).unwrap();
        assert_eq!(store.read().unwrap_err(), DeviceKeyError::Lost);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_keyring_store_needs_consent() {
        assert!(SecretServiceKeyStore::with_consent(false).is_none());
        assert!(SecretServiceKeyStore::with_consent(true).is_some());
        assert!(
            crate::native::linux::store_connect_key("synthetic", false)
                .unwrap_err()
                .contains("consent")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_keeps_the_key_in_the_file_by_default() {
        let dir = tempfile::tempdir().expect("dir");
        let store = platform_store(dir.path()).expect("a store");
        AccountSigner::open_or_create(store.as_ref()).expect("key");
        assert!(key_file(dir.path()).is_file());
    }
}
