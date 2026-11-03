//! The master key of the node without a window (plan D8).
//!
//! The key opens the relay directory (`relay.db`) and seals the key of the node
//! certificate (`apassy::net::sealed_key`, HKDF info `apassy-node-front-v1`). It is 64
//! lowercase hex characters (32 random bytes). Where it comes from, in order:
//!
//! 1. a systemd credential: `$CREDENTIALS_DIRECTORY/apassy-node-key`, when systemd gives
//!    the service one (`LoadCredentialEncrypted=`, unit L2);
//! 2. the encrypted credential `master.key.cred` in the node directory, which `apassy up`
//!    makes with `systemd-creds --user encrypt` where systemd can decrypt it for a user
//!    service (systemd 256 or later): outside the service, `serve` opens it with
//!    `systemd-creds --user decrypt`;
//! 3. the file `master.key` in the node directory, mode 0600, made at the first start.
//!
//! `seal` turns 3 into 2: it encrypts the key, checks that the credential gives the same
//! key back, and only then removes the plain file. A credential is bound to this machine
//! (its systemd host key, and its TPM2 when it has one): back it up as the guide says.
//!
//! The key is never printed, logged, or put into an error. Who can read the node
//! directory as this user can be the node: the file is a convenience of a user service,
//! not a defence against that user (docs/operations/linux-node.md, "What the node holds").

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::Serialize;
use zeroize::Zeroizing;

use super::NodeCliError;
use crate::secret::SecretString;

/// The name of the systemd credential.
pub const CREDENTIAL_NAME: &str = "apassy-node-key";
/// The key file in the node directory.
pub const KEY_FILE: &str = "master.key";
/// The encrypted key in the node directory (`systemd-creds --user encrypt`).
pub const CREDENTIAL_FILE: &str = "master.key.cred";
/// The first systemd whose user service manager decrypts credentials
/// (`LoadCredentialEncrypted=` in a user unit, `systemd-creds --user`).
pub const MIN_SYSTEMD_FOR_USER_CREDENTIALS: u32 = 256;
/// Where `systemd-creds` is looked for.
const SYSTEMD_CREDS_PATHS: [&str; 3] = [
    "/usr/bin/systemd-creds",
    "/bin/systemd-creds",
    "/usr/local/bin/systemd-creds",
];
/// The key's length in hex characters.
pub const KEY_HEX_CHARS: usize = 64;

/// Where the master key of a node comes from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "path", rename_all = "kebab-case")]
pub enum KeySource {
    /// A systemd credential (`$CREDENTIALS_DIRECTORY/apassy-node-key`).
    Credential(PathBuf),
    /// The encrypted credential `master.key.cred` of the node directory, read outside
    /// the service.
    Encrypted(PathBuf),
    /// The 0600 file `master.key` of the node directory.
    File(PathBuf),
}

impl KeySource {
    /// `credential` or `file`, as `status` shows it.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Credential(_) => "credential",
            Self::Encrypted(_) => "encrypted",
            Self::File(_) => "file",
        }
    }

    pub fn path(&self) -> &Path {
        match self {
            Self::Credential(path) | Self::Encrypted(path) | Self::File(path) => path,
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
    let encrypted = node_dir.join(CREDENTIAL_FILE);
    if fs::symlink_metadata(&encrypted).is_ok() {
        return KeySource::Encrypted(encrypted);
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
    parse_key(&text, source)
}

/// The key of `text`: 64 lowercase hex characters, with white space around.
fn parse_key(text: &str, source: &KeySource) -> Result<SecretString, NodeCliError> {
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
        KeySource::Encrypted(path) => {
            let outside = |why: String| {
                NodeCliError::failed(format!(
                    "The node key is encrypted ({}) and cannot be opened here: {why}. Start the node with `systemctl --user start {}`.",
                    path.display(),
                    super::service::NODE_UNIT
                ))
            };
            let tool = SystemdCreds::find()
                .ok_or_else(|| outside("systemd-creds is not installed".to_owned()))?;
            let text = tool.decrypt(path).map_err(outside)?;
            let key = parse_key(&text, &source)?;
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

/// For `apassy up`: an encrypted key stays as it is (it is not opened), else the key
/// file is made at the first start. Never a second key.
pub fn ensure(node_dir: &Path) -> Result<KeySource, NodeCliError> {
    let source = source_for(node_dir, None);
    if matches!(source, KeySource::Encrypted(_)) {
        return Ok(source);
    }
    load(node_dir, None, true).map(|(_, source)| source)
}

/// The `systemd-creds` program. Tests give a fake one with `at`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemdCreds {
    program: PathBuf,
}

/// The first line of the error output of a program, without control characters.
fn first_line(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let line = text.lines().find(|line| !line.trim().is_empty());
    match line {
        Some(line) => super::printable(line.trim()),
        None => "no message".to_owned(),
    }
}

impl SystemdCreds {
    /// `systemd-creds` at one of the usual paths.
    pub fn find() -> Option<Self> {
        SYSTEMD_CREDS_PATHS
            .iter()
            .map(PathBuf::from)
            .find(|path| path.is_file())
            .map(Self::at)
    }

    pub fn at(program: PathBuf) -> Self {
        Self { program }
    }

    /// The systemd version of `systemd-creds --version` (`systemd 256 (256.5-1)`).
    pub fn version(&self) -> Option<u32> {
        let output = Command::new(&self.program)
            .arg("--version")
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&output.stdout);
        let mut words = text.lines().next()?.split_whitespace();
        if words.next()? != "systemd" {
            return None;
        }
        words.next()?.parse().ok()
    }

    /// `Ok(())` when a user service can load a credential that this program encrypts.
    pub fn check_user_credentials(&self) -> Result<(), String> {
        match self.version() {
            Some(version) if version >= MIN_SYSTEMD_FOR_USER_CREDENTIALS => Ok(()),
            Some(version) => Err(format!(
                "systemd {version} cannot decrypt a credential for a user service (that needs systemd {MIN_SYSTEMD_FOR_USER_CREDENTIALS})"
            )),
            None => Err("systemd-creds gives no version".to_owned()),
        }
    }

    /// `systemd-creds --user --name=apassy-node-key encrypt - <output>`, the key on stdin.
    pub fn encrypt(&self, key: &str, output: &Path) -> Result<(), String> {
        let mut child = Command::new(&self.program)
            .args([
                "--user",
                &format!("--name={CREDENTIAL_NAME}"),
                "encrypt",
                "-",
            ])
            .arg(output)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| format!("systemd-creds cannot run: {}", error.kind()))?;
        let written = child
            .stdin
            .take()
            .ok_or(ErrorKind::BrokenPipe)
            .and_then(|mut stdin| {
                stdin
                    .write_all(key.as_bytes())
                    .map_err(|error| error.kind())
            });
        let result = child
            .wait_with_output()
            .map_err(|error| format!("systemd-creds failed: {}", error.kind()))?;
        if !result.status.success() {
            return Err(format!(
                "systemd-creds encrypt failed: {}",
                first_line(&result.stderr)
            ));
        }
        written.map_err(|kind| format!("systemd-creds took no key: {kind}"))
    }

    /// `systemd-creds --user --name=apassy-node-key decrypt <input> -`: the key text.
    pub fn decrypt(&self, input: &Path) -> Result<Zeroizing<String>, String> {
        let output = Command::new(&self.program)
            .args(["--user", &format!("--name={CREDENTIAL_NAME}"), "decrypt"])
            .arg(input)
            .arg("-")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|error| format!("systemd-creds cannot run: {}", error.kind()))?;
        let stdout = Zeroizing::new(output.stdout);
        if !output.status.success() {
            return Err(format!(
                "systemd-creds decrypt failed: {}",
                first_line(&output.stderr)
            ));
        }
        if stdout.len() > 256 {
            return Err("the credential is not a node key".to_owned());
        }
        String::from_utf8(stdout.to_vec())
            .map(Zeroizing::new)
            .map_err(|_| "the credential is not a node key".to_owned())
    }
}

/// Encrypts the key file of `node_dir` into `master.key.cred` with `tool`, checks that
/// the credential gives the same key back, then removes `master.key`. An encrypted key
/// stays as it is. `Err`: why the plain file stays (nothing else changed).
pub fn seal(node_dir: &Path, tool: &SystemdCreds) -> Result<KeySource, String> {
    let target = node_dir.join(CREDENTIAL_FILE);
    if fs::symlink_metadata(&target).is_ok() {
        return Ok(KeySource::Encrypted(target));
    }
    tool.check_user_credentials()?;
    let (key, source) = load(node_dir, None, true).map_err(|error| error.message)?;
    let KeySource::File(plain) = source else {
        return Err("the key is not the key file".to_owned());
    };
    let temporary = node_dir.join(format!(".{CREDENTIAL_FILE}.{}.tmp", std::process::id()));
    let _ = fs::remove_file(&temporary);
    let made = (|| {
        tool.encrypt(key.expose(), &temporary)?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("the credential cannot be made private: {}", error.kind()))?;
        let back = tool.decrypt(&temporary)?;
        if back.trim() != key.expose() {
            return Err("the credential does not give the same key back".to_owned());
        }
        fs::rename(&temporary, &target)
            .map_err(|error| format!("the credential cannot be saved: {}", error.kind()))
    })();
    if let Err(why) = made {
        let _ = fs::remove_file(&temporary);
        return Err(why);
    }
    // Only now: the credential is in place and gives the key back. A file that cannot
    // be removed is left for `doctor` to name.
    let _ = fs::remove_file(&plain);
    Ok(KeySource::Encrypted(target))
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

    /// A fake `systemd-creds` of systemd `version`: it "encrypts" by mapping the hex
    /// digits to other letters and refuses arguments other than those of `SystemdCreds`.
    fn fake_creds(dir: &Path, version: u32) -> SystemdCreds {
        let program = dir.join("systemd-creds");
        let script = format!(
            "#!/bin/sh\n\
             if [ \"$1\" = --version ]; then echo 'systemd {version} ({version}.1-1)'; exit 0; fi\n\
             [ \"$1\" = --user ] && [ \"$2\" = --name=apassy-node-key ] || exit 9\n\
             case \"$3\" in\n\
             encrypt) [ \"$4\" = - ] || exit 9; {{ printf 'FAKECRED:'; tr '0-9a-f' 'g-v'; }} > \"$5\" ;;\n\
             decrypt) [ \"$5\" = - ] || exit 9; cut -c10- \"$4\" | tr 'g-v' '0-9a-f' ;;\n\
             *) exit 9 ;;\n\
             esac\n"
        );
        fs::write(&program, script).unwrap();
        fs::set_permissions(&program, fs::Permissions::from_mode(0o755)).unwrap();
        SystemdCreds::at(program)
    }

    #[test]
    fn seal_encrypts_the_key_and_removes_the_plain_file() {
        let dir = tempfile::tempdir().unwrap();
        let bin = tempfile::tempdir().unwrap();
        let tool = fake_creds(bin.path(), 257);
        assert_eq!(tool.version(), Some(257));
        let (key, _) = load(dir.path(), None, true).unwrap();
        let source = seal(dir.path(), &tool).unwrap();
        let encrypted = dir.path().join(CREDENTIAL_FILE);
        assert_eq!(source, KeySource::Encrypted(encrypted.clone()));
        assert_eq!(source.label(), "encrypted");
        assert!(!dir.path().join(KEY_FILE).exists());
        let sealed = fs::read_to_string(&encrypted).unwrap();
        assert!(
            !sealed.contains(key.expose()),
            "the credential holds the plain key"
        );
        assert_eq!(fs::metadata(&encrypted).unwrap().mode() & 0o777, 0o600);
        assert_eq!(tool.decrypt(&encrypted).unwrap().trim(), key.expose());
        assert_eq!(source_for(dir.path(), None), source);
        // `up` again: the encrypted key stays, and no second key file is made.
        assert_eq!(ensure(dir.path()).unwrap(), source);
        assert_eq!(seal(dir.path(), &tool).unwrap(), source);
        assert!(!dir.path().join(KEY_FILE).exists());
        // Under the service, the decrypted credential wins.
        let credentials = tempfile::tempdir().unwrap();
        fs::write(credentials.path().join(CREDENTIAL_NAME), key.expose()).unwrap();
        let (found, source) = load(dir.path(), Some(credentials.path()), true).unwrap();
        assert_eq!(found.expose(), key.expose());
        assert_eq!(source.label(), "credential");
        // No temporary file is left.
        let names: Vec<String> = fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, [CREDENTIAL_FILE]);
    }

    #[test]
    fn an_old_systemd_or_a_failing_tool_keeps_the_plain_file() {
        let dir = tempfile::tempdir().unwrap();
        let bin = tempfile::tempdir().unwrap();
        let old = fake_creds(bin.path(), 255);
        let why = seal(dir.path(), &old).unwrap_err();
        assert!(why.contains("systemd 255"), "{why}");
        // No key is made by a refused seal; `ensure` makes the 0600 file.
        assert!(!dir.path().join(KEY_FILE).exists());
        let source = ensure(dir.path()).unwrap();
        assert_eq!(source.label(), "file");
        let mode = fs::metadata(dir.path().join(KEY_FILE)).unwrap().mode();
        assert_eq!(mode & 0o777, 0o600);
        let broken = bin.path().join("broken");
        fs::write(
            &broken,
            "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'systemd 256'; exit 0; fi\necho 'No TPM2 and no host key' >&2\nexit 1\n",
        )
        .unwrap();
        fs::set_permissions(&broken, fs::Permissions::from_mode(0o755)).unwrap();
        let why = seal(dir.path(), &SystemdCreds::at(broken)).unwrap_err();
        assert!(why.contains("No TPM2"), "{why}");
        assert!(dir.path().join(KEY_FILE).exists());
        assert!(!dir.path().join(CREDENTIAL_FILE).exists());
        assert_eq!(source_for(dir.path(), None).label(), "file");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
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
