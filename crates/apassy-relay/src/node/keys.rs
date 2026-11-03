//! The master key of the node without a window (plan D8).
//!
//! The key opens the relay directory (`relay.db`) and seals the key of the node
//! certificate (`apassy::net::sealed_key`, HKDF info `apassy-node-front-v1`). It is 64
//! lowercase hex characters (32 random bytes). Where it comes from, in order:
//!
//! 1. a systemd credential: `$CREDENTIALS_DIRECTORY/apassy-node-key`, when systemd gives
//!    the service one (`LoadCredentialEncrypted=`, unit L2);
//! 2. the file `master.key` in the node directory, mode 0600, made at the first start.
//!
//! The key is never printed, logged, or put into an error. Who can read the node
//! directory as this user can be the node: the file is a convenience of a user service,
//! not a defence against that user (docs/operations/linux-node.md, "What the node holds").

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use serde::Serialize;
use zeroize::Zeroizing;

use super::NodeCliError;
use crate::secret::SecretString;

/// The name of the systemd credential.
pub const CREDENTIAL_NAME: &str = "apassy-node-key";
/// The key file in the node directory.
pub const KEY_FILE: &str = "master.key";
/// The key's length in hex characters.
pub const KEY_HEX_CHARS: usize = 64;

/// Where the master key of a node comes from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "path", rename_all = "kebab-case")]
pub enum KeySource {
    /// A systemd credential (`$CREDENTIALS_DIRECTORY/apassy-node-key`).
    Credential(PathBuf),
    /// The 0600 file `master.key` of the node directory.
    File(PathBuf),
}

impl KeySource {
    /// `credential` or `file`, as `status` shows it.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Credential(_) => "credential",
            Self::File(_) => "file",
        }
    }

    pub fn path(&self) -> &Path {
        match self {
            Self::Credential(path) | Self::File(path) => path,
        }
    }
}

/// The source that `load_or_make` uses for `node_dir`, without reading a key:
/// `credentials_dir` is the value of `$CREDENTIALS_DIRECTORY`.
pub fn source_for(node_dir: &Path, credentials_dir: Option<&Path>) -> KeySource {
    if let Some(dir) = credentials_dir {
        let path = dir.join(CREDENTIAL_NAME);
        if fs::symlink_metadata(&path).is_ok() {
            return KeySource::Credential(path);
        }
    }
    KeySource::File(node_dir.join(KEY_FILE))
}

/// `$CREDENTIALS_DIRECTORY`, when systemd set it to an absolute path.
pub fn credentials_dir() -> Option<PathBuf> {
    std::env::var_os("CREDENTIALS_DIRECTORY")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
}

fn bad_key(source: &KeySource) -> NodeCliError {
    NodeCliError::failed(format!(
        "The node key {} is not 64 hex characters. Restore it from a backup; a new key cannot open the node's teams.",
        source.path().display()
    ))
}

/// Reads the key text of a file: one line of 64 lowercase hex characters.
fn read_key(path: &Path, source: &KeySource, private: bool) -> Result<SecretString, NodeCliError> {
    let fail = |why: &str| NodeCliError::failed(format!("{}: {why}.", path.display()));
    let meta = fs::metadata(path).map_err(|_| fail("cannot be read"))?;
    if !meta.is_file() {
        return Err(fail("not a plain file"));
    }
    if private && meta.mode() & 0o077 != 0 {
        return Err(fail(
            "other users can read it; run `chmod 600` on it, then start the node again",
        ));
    }
    let mut text = Zeroizing::new(String::new());
    fs::File::open(path)
        .and_then(|file| file.take(256).read_to_string(&mut text))
        .map_err(|_| fail("cannot be read"))?;
    let key = text.trim();
    if key.len() != KEY_HEX_CHARS
        || !key
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(bad_key(source));
    }
    Ok(SecretString::new(key.to_owned()))
}

/// A new key: 32 random bytes as lowercase hex.
fn new_key() -> Result<Zeroizing<String>, NodeCliError> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *bytes)
        .map_err(|_| NodeCliError::failed("No random bytes for the node key."))?;
    let mut text = Zeroizing::new(String::with_capacity(KEY_HEX_CHARS));
    for &byte in bytes.iter() {
        text.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
        text.push(char::from(b"0123456789abcdef"[usize::from(byte & 0x0f)]));
    }
    Ok(text)
}

/// The master key of the node in `node_dir` (a directory of mode 0700): the systemd
/// credential when `credentials_dir` has it, else `master.key`, made with mode 0600 when
/// it is missing and `make` is true.
pub fn load(
    node_dir: &Path,
    credentials_dir: Option<&Path>,
    make: bool,
) -> Result<(SecretString, KeySource), NodeCliError> {
    let source = source_for(node_dir, credentials_dir);
    match &source {
        KeySource::Credential(path) => {
            // systemd makes the credential file readable by the service only.
            let key = read_key(path, &source, false)?;
            Ok((key, source))
        }
        KeySource::File(path) => match fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_symlink() => Err(NodeCliError::failed(format!(
                "{}: a link, not the key file.",
                path.display()
            ))),
            Ok(_) => {
                let key = read_key(path, &source, true)?;
                Ok((key, source))
            }
            Err(error) if error.kind() == ErrorKind::NotFound && make => {
                let key = new_key()?;
                let written = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path)
                    .and_then(|mut file| {
                        file.write_all(key.as_bytes())?;
                        file.write_all(b"\n")?;
                        file.sync_all()
                    });
                if written.is_err() {
                    let _ = fs::remove_file(path);
                    return Err(NodeCliError::failed(format!(
                        "The node key {} cannot be written.",
                        path.display()
                    )));
                }
                Ok((SecretString::new(key.as_str().to_owned()), source))
            }
            Err(error) if error.kind() == ErrorKind::NotFound => Err(NodeCliError::failed(
                format!("The node has no key yet ({}).", path.display()),
            )),
            Err(_) => Err(NodeCliError::failed(format!(
                "{} cannot be read.",
                path.display()
            ))),
        },
    }
}

/// `load` with `$CREDENTIALS_DIRECTORY`, making the key file at the first start.
pub fn load_or_make(node_dir: &Path) -> Result<(SecretString, KeySource), NodeCliError> {
    load(node_dir, credentials_dir().as_deref(), true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn the_key_file_is_made_once_with_mode_0600() {
        let dir = tempfile::tempdir().unwrap();
        let (first, source) = load(dir.path(), None, true).unwrap();
        assert_eq!(source, KeySource::File(dir.path().join(KEY_FILE)));
        assert_eq!(source.label(), "file");
        assert_eq!(first.len(), KEY_HEX_CHARS);
        let mode = fs::metadata(dir.path().join(KEY_FILE)).unwrap().mode();
        assert_eq!(mode & 0o777, 0o600);
        let (again, _) = load(dir.path(), None, true).unwrap();
        assert_eq!(first.expose(), again.expose());
    }

    #[test]
    fn a_key_that_others_can_read_or_a_bad_key_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        load(dir.path(), None, true).unwrap();
        let path = dir.path().join(KEY_FILE);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load(dir.path(), None, true).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&path, "not hex\n").unwrap();
        let error = load(dir.path(), None, true).unwrap_err();
        assert!(!error.message.contains("not hex"), "{}", error.message);
        let empty = tempfile::tempdir().unwrap();
        assert!(load(empty.path(), None, false).is_err());
        assert!(!empty.path().join(KEY_FILE).exists());
    }

    #[test]
    fn a_systemd_credential_wins() {
        let dir = tempfile::tempdir().unwrap();
        let credentials = tempfile::tempdir().unwrap();
        let key = "ab".repeat(32);
        fs::write(credentials.path().join(CREDENTIAL_NAME), format!("{key}\n")).unwrap();
        let (found, source) = load(dir.path(), Some(credentials.path()), true).unwrap();
        assert_eq!(found.expose(), key);
        assert_eq!(source.label(), "credential");
        assert!(!dir.path().join(KEY_FILE).exists());
        // Without the credential file, the node falls back to its own file.
        let other = tempfile::tempdir().unwrap();
        let (_, source) = load(dir.path(), Some(other.path()), true).unwrap();
        assert_eq!(source.label(), "file");
    }
}
