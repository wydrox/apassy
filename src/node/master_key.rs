//! The master key of the node (ADR 0037, cloud slice, decision 1).
//!
//! One 32-byte key for each Mac user opens the files of the node. It lives in a
//! Keychain generic password, account [`KEYCHAIN_ACCOUNT`], through the signed helper
//! (`NativeHelper::keychain_store`: this device only, not synchronizable, and behind
//! Touch ID). When the helper says `keychain_unavailable` (a development build without
//! a provisioning profile), the key is the file [`KEY_FILE`] in the node directory, mode
//! 0600, and [`KeySource::File`] tells the owner.
//!
//! The node holds metadata only, never a value (decision 2). So a lost key costs nothing
//! secret: the old node directory moves aside (`node-lost-<time>`), a new empty node
//! starts, and the owner adds the cloud agents again. A Touch ID that the owner cancels
//! makes no new key.

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use super::backend::{NodeError, NodeSecret};
use crate::native::{HelperErrorCode, KeychainSecret, NativeError, NativeHelper};

/// The Keychain account of the key.
pub const KEYCHAIN_ACCOUNT: &str = "node-master-key";
/// The file of the key when the Keychain is unavailable, in the node directory.
pub const KEY_FILE: &str = "master.key";
/// The relay file of a node. A new key next to it means the old node cannot be opened.
const NODE_FILE: &str = "relay.db";
const KEY_BYTES: usize = 32;
/// The text of the Touch ID prompt.
const READ_REASON: &str = "Apassy opens its node for your cloud agents.";

/// Why a key store gave no key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyStoreError {
    /// The Keychain cannot be used by this build: use the file.
    Unavailable,
    /// The owner cancelled Touch ID. Nothing changes.
    Cancelled,
    /// Another failure. The text has no secret.
    Failed(String),
}

/// Where the key is kept. Tests use a fake.
pub trait KeyStore: Send + Sync {
    /// The stored key, or `None` when there is none.
    fn read(&self) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError>;
    /// Store `key`, replacing an earlier one.
    fn store(&self, key: &[u8]) -> Result<(), KeyStoreError>;
}

/// The Keychain through the signed helper of the app.
pub struct KeychainStore {
    helper: NativeHelper,
}

impl KeychainStore {
    pub fn new(helper: NativeHelper) -> Self {
        Self { helper }
    }
}

fn keychain_error(error: &NativeError) -> KeyStoreError {
    match error.code() {
        Some(HelperErrorCode::KeychainUnavailable) => KeyStoreError::Unavailable,
        Some(HelperErrorCode::Cancelled | HelperErrorCode::Fallback) => KeyStoreError::Cancelled,
        _ => KeyStoreError::Failed(error.to_string()),
    }
}

impl KeyStore for KeychainStore {
    fn read(&self) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError> {
        let state = self
            .helper
            .keychain_exists(KEYCHAIN_ACCOUNT)
            .map_err(|error| keychain_error(&error))?;
        if !state.exists {
            return Ok(None);
        }
        if state.biometry_changed {
            // The item cannot be read any more: the fingerprints changed. A new node.
            let _ = self.helper.keychain_delete(KEYCHAIN_ACCOUNT);
            return Ok(None);
        }
        match self.helper.keychain_read(KEYCHAIN_ACCOUNT, READ_REASON) {
            Ok(secret) => Ok(Some(Zeroizing::new(secret.expose().to_vec()))),
            Err(error) if error.code() == Some(HelperErrorCode::NotFound) => Ok(None),
            Err(error) if error.code() == Some(HelperErrorCode::BiometryChanged) => {
                let _ = self.helper.keychain_delete(KEYCHAIN_ACCOUNT);
                Ok(None)
            }
            Err(error) => Err(keychain_error(&error)),
        }
    }

    fn store(&self, key: &[u8]) -> Result<(), KeyStoreError> {
        let secret = KeychainSecret::new(key.to_vec())
            .map_err(|error| KeyStoreError::Failed(error.to_string()))?;
        self.helper
            .keychain_store(KEYCHAIN_ACCOUNT, &secret)
            .map_err(|error| keychain_error(&error))
    }
}

/// A key store that is never available: the file is the key. For a process without
/// the helper.
pub struct NoKeychain;

impl KeyStore for NoKeychain {
    fn read(&self) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError> {
        Err(KeyStoreError::Unavailable)
    }

    fn store(&self, _key: &[u8]) -> Result<(), KeyStoreError> {
        Err(KeyStoreError::Unavailable)
    }
}

/// Where the key came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource {
    Keychain,
    /// The 0600 file: the Keychain is unavailable to this build. The UI says so.
    File,
}

/// The key of the node, ready for `NodeConfig::master_key`.
#[derive(Debug)]
pub struct MasterKey {
    /// 64 lowercase hex characters.
    pub secret: NodeSecret,
    pub source: KeySource,
    /// The key is new and an older node was there: it moved here. The vault forgets its
    /// cloud agents (`Vault::reset_cloud_node`).
    pub retired: Option<PathBuf>,
}

fn node_error(code: &str, message: impl Into<String>) -> NodeError {
    NodeError::new(code, message)
}

fn hex(bytes: &[u8]) -> Zeroizing<String> {
    let mut text = Zeroizing::new(String::with_capacity(bytes.len() * 2));
    for byte in bytes {
        text.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
        text.push(char::from(b"0123456789abcdef"[usize::from(byte & 0x0f)]));
    }
    text
}

fn fresh_key() -> Result<Zeroizing<Vec<u8>>, NodeError> {
    let mut key = Zeroizing::new(vec![0u8; KEY_BYTES]);
    getrandom::fill(&mut key)
        .map_err(|_| node_error("key_failed", "The node key cannot be made: no randomness."))?;
    Ok(key)
}

/// Make `dir` a real directory of this user with mode 0700.
pub(super) fn ensure_private_dir(dir: &Path) -> Result<(), NodeError> {
    match fs::symlink_metadata(dir) {
        Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {
            if meta.permissions().mode() & 0o077 != 0 {
                fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(|_| {
                    node_error("key_failed", "The node directory cannot be made private.")
                })?;
            }
            Ok(())
        }
        Ok(_) => Err(node_error(
            "key_failed",
            "The node directory is not a directory.",
        )),
        Err(error) if error.kind() == ErrorKind::NotFound => fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|_| node_error("key_failed", "The node directory cannot be made.")),
        Err(_) => Err(node_error(
            "key_failed",
            "The node directory cannot be read.",
        )),
    }
}

/// The key file: `None` when there is none. A file that others can read, a link, or a
/// file of the wrong length is refused: the owner removes it.
fn read_key_file(path: &Path) -> Result<Option<Zeroizing<Vec<u8>>>, NodeError> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(_) => {
            return Err(node_error(
                "key_failed",
                "The node key file cannot be read.",
            ));
        }
    };
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(node_error(
            "key_failed",
            "The node key file is not a plain file.",
        ));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(node_error(
            "key_failed",
            "Other users can read the node key file. Remove it; Apassy makes a new node.",
        ));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|_| node_error("key_failed", "The node key file cannot be read."))?;
    let mut key = Zeroizing::new(Vec::with_capacity(KEY_BYTES + 1));
    Read::by_ref(&mut file)
        .take(KEY_BYTES as u64 + 1)
        .read_to_end(&mut key)
        .map_err(|_| node_error("key_failed", "The node key file cannot be read."))?;
    if key.len() != KEY_BYTES {
        return Err(node_error(
            "key_failed",
            "The node key file has the wrong length. Remove it; Apassy makes a new node.",
        ));
    }
    Ok(Some(key))
}

/// Write a new key file with mode 0600. An existing file is not replaced.
fn write_key_file(path: &Path, key: &[u8]) -> Result<(), NodeError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| node_error("key_failed", "The node key file cannot be written."))?;
    file.write_all(key)
        .and_then(|()| file.sync_all())
        .map_err(|_| node_error("key_failed", "The node key file cannot be written."))
}

/// Move an older node that no key opens aside: `<dir>` becomes `<dir>-lost-<time>`, and
/// a new empty `<dir>` is made. Nothing in it is secret, so nothing is lost.
fn retire(dir: &Path) -> Result<Option<PathBuf>, NodeError> {
    if fs::symlink_metadata(dir.join(NODE_FILE)).is_err() {
        return Ok(None);
    }
    let name = dir
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "node".to_owned());
    let at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let lost = dir.with_file_name(format!("{name}-lost-{at}"));
    fs::rename(dir, &lost).map_err(|_| {
        node_error(
            "key_failed",
            "The node key is new, and the older node cannot be moved aside.",
        )
    })?;
    ensure_private_dir(dir)?;
    Ok(Some(lost))
}

/// The key of the node in `dir`, made at the first start: from the Keychain, or from
/// the file when the Keychain is unavailable. A key file of an earlier fallback moves
/// into the Keychain once the Keychain works.
pub fn open_key(store: &dyn KeyStore, dir: &Path) -> Result<MasterKey, NodeError> {
    ensure_private_dir(dir)?;
    let file = dir.join(KEY_FILE);
    match store.read() {
        Ok(Some(key)) if key.len() == KEY_BYTES => Ok(MasterKey {
            secret: NodeSecret::new(hex(&key).to_string()),
            source: KeySource::Keychain,
            retired: None,
        }),
        Ok(_) => {
            if let Some(key) = read_key_file(&file)? {
                store.store(&key).map_err(|error| store_error(&error))?;
                let _ = fs::remove_file(&file);
                return Ok(MasterKey {
                    secret: NodeSecret::new(hex(&key).to_string()),
                    source: KeySource::Keychain,
                    retired: None,
                });
            }
            let key = fresh_key()?;
            store.store(&key).map_err(|error| store_error(&error))?;
            let retired = retire(dir)?;
            Ok(MasterKey {
                secret: NodeSecret::new(hex(&key).to_string()),
                source: KeySource::Keychain,
                retired,
            })
        }
        Err(KeyStoreError::Unavailable) => {
            if let Some(key) = read_key_file(&file)? {
                return Ok(MasterKey {
                    secret: NodeSecret::new(hex(&key).to_string()),
                    source: KeySource::File,
                    retired: None,
                });
            }
            let key = fresh_key()?;
            let retired = retire(dir)?;
            write_key_file(&file, &key)?;
            Ok(MasterKey {
                secret: NodeSecret::new(hex(&key).to_string()),
                source: KeySource::File,
                retired,
            })
        }
        Err(error) => Err(store_error(&error)),
    }
}

fn store_error(error: &KeyStoreError) -> NodeError {
    match error {
        KeyStoreError::Cancelled => node_error(
            "cancelled",
            "Touch ID was cancelled, so the node did not start.",
        ),
        KeyStoreError::Unavailable => node_error(
            "key_failed",
            "The Keychain is not available for the node key.",
        ),
        KeyStoreError::Failed(text) => node_error(
            "key_failed",
            format!("The node key is not available: {text}"),
        ),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Mutex;

    use super::*;

    /// A Keychain in memory, or one that is unavailable or cancelled.
    pub(crate) struct FakeKeys {
        pub(crate) key: Mutex<Option<Vec<u8>>>,
        pub(crate) error: Option<KeyStoreError>,
    }

    impl FakeKeys {
        pub(crate) fn empty() -> Self {
            Self {
                key: Mutex::new(None),
                error: None,
            }
        }

        pub(crate) fn failing(error: KeyStoreError) -> Self {
            Self {
                key: Mutex::new(None),
                error: Some(error),
            }
        }
    }

    impl KeyStore for FakeKeys {
        fn read(&self) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError> {
            if let Some(error) = &self.error {
                return Err(error.clone());
            }
            Ok(self.key.lock().unwrap().clone().map(Zeroizing::new))
        }

        fn store(&self, key: &[u8]) -> Result<(), KeyStoreError> {
            if let Some(error) = &self.error {
                return Err(error.clone());
            }
            *self.key.lock().unwrap() = Some(key.to_vec());
            Ok(())
        }
    }

    #[test]
    fn the_keychain_keeps_one_key_and_no_file_is_written() {
        let dir = tempfile::tempdir().unwrap();
        let node = dir.path().join("node");
        let keys = FakeKeys::empty();
        let first = open_key(&keys, &node).unwrap();
        assert_eq!(first.source, KeySource::Keychain);
        assert_eq!(first.retired, None);
        assert_eq!(first.secret.expose().len(), 64);
        assert!(!node.join(KEY_FILE).exists());
        assert_eq!(fs::metadata(&node).unwrap().mode() & 0o777, 0o700);
        let again = open_key(&keys, &node).unwrap();
        assert_eq!(again.secret.expose(), first.secret.expose());
        assert!(!format!("{first:?}").contains(first.secret.expose()));
    }

    #[test]
    fn without_the_keychain_the_key_is_a_0600_file() {
        let dir = tempfile::tempdir().unwrap();
        let node = dir.path().join("node");
        let keys = FakeKeys::failing(KeyStoreError::Unavailable);
        let first = open_key(&keys, &node).unwrap();
        assert_eq!(first.source, KeySource::File);
        let meta = fs::symlink_metadata(node.join(KEY_FILE)).unwrap();
        assert_eq!(meta.mode() & 0o777, 0o600);
        assert_eq!(meta.len(), KEY_BYTES as u64);
        let again = open_key(&keys, &node).unwrap();
        assert_eq!(again.secret.expose(), first.secret.expose());
        assert_eq!(again.source, KeySource::File);

        // A file that others can read is refused, not used.
        fs::set_permissions(node.join(KEY_FILE), fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(open_key(&keys, &node).unwrap_err().code, "key_failed");

        // Once the Keychain works, the file key moves into it.
        fs::set_permissions(node.join(KEY_FILE), fs::Permissions::from_mode(0o600)).unwrap();
        let keychain = FakeKeys::empty();
        let moved = open_key(&keychain, &node).unwrap();
        assert_eq!(moved.source, KeySource::Keychain);
        assert_eq!(moved.secret.expose(), first.secret.expose());
        assert!(!node.join(KEY_FILE).exists());
    }

    #[test]
    fn a_lost_key_moves_the_old_node_aside_and_a_cancel_makes_no_key() {
        let dir = tempfile::tempdir().unwrap();
        let node = dir.path().join("node");
        ensure_private_dir(&node).unwrap();
        fs::write(node.join(NODE_FILE), b"synthetic old node").unwrap();

        let cancelled = FakeKeys::failing(KeyStoreError::Cancelled);
        assert_eq!(open_key(&cancelled, &node).unwrap_err().code, "cancelled");
        assert!(node.join(NODE_FILE).exists(), "a cancel changes nothing");

        let keys = FakeKeys::empty();
        let fresh = open_key(&keys, &node).unwrap();
        let lost = fresh.retired.expect("the old node moved");
        assert!(lost.join(NODE_FILE).exists());
        assert!(!node.join(NODE_FILE).exists());
        assert!(node.is_dir());
    }
}
