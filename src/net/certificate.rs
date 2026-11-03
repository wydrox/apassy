//! The node certificate of the TLS front (plan D2).
//!
//! rcgen, ECDSA P-256, self-signed, 10 years, subject `Apassy node <machine name>`. It is
//! made at the first start. The DER is in `<dir>/cert.der`; the PKCS#8 key is sealed
//! (`super::sealed_key`, info `apassy-node-front-v1`, the SHA-256 of the DER as the
//! associated data) in `<dir>/key.sealed`, mode 0600. `<dir>` is `node/front` and has
//! mode 0700.
//!
//! The pin is `b64u(SHA-256(DER))`. The clients ignore the name and the dates; only the
//! pin counts. A pin that pairings know must not change silently: when both files are
//! there and the key does not open (another master key), loading fails and the caller
//! decides ([`NodeCertificate::replace`] makes a new pin, so every device pairs again).

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose,
};
use time::{Duration, OffsetDateTime};
use zeroize::Zeroizing;

use super::pin::Pin;
use super::sealed_key::{self, FRONT_INFO, SealError};

/// The file of the certificate DER.
pub const CERT_FILE: &str = "cert.der";
/// The file of the sealed private key.
pub const KEY_FILE: &str = "key.sealed";
/// A file of the front is at most this long.
const MAX_FILE_BYTES: u64 = 64 * 1024;
/// The machine name in the subject has at most this many characters.
const MAX_NAME_CHARS: usize = 40;
const VALID_DAYS: i64 = 3650;

/// Why the certificate is not there.
#[derive(Debug)]
pub enum CertificateError {
    /// A file or the directory cannot be read or written, or is not private.
    Files(String),
    /// Both files are there and the key does not open with this master key, or does
    /// not belong to the certificate.
    Unreadable,
    /// The master key is too short.
    WeakKey,
    /// rcgen failed to make a certificate.
    Make(String),
}

impl std::fmt::Display for CertificateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Files(why) => write!(f, "the node certificate files: {why}"),
            Self::Unreadable => f.write_str(
                "the node certificate key does not open with this node key; pairing again makes a new certificate",
            ),
            Self::WeakKey => f.write_str("the node master key is too short"),
            Self::Make(why) => write!(f, "the node certificate cannot be made: {why}"),
        }
    }
}

impl std::error::Error for CertificateError {}

impl From<SealError> for CertificateError {
    fn from(error: SealError) -> Self {
        match error {
            SealError::WeakKey => Self::WeakKey,
            SealError::Random => Self::Make("no randomness".to_owned()),
            SealError::Open => Self::Unreadable,
        }
    }
}

/// The certificate of the front and its private key.
pub struct NodeCertificate {
    /// The certificate, DER.
    pub der: Vec<u8>,
    /// `SHA-256(der)`.
    pub pin: Pin,
    /// The private key, PKCS#8. It is erased on drop.
    pub key: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for NodeCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeCertificate")
            .field("pin", &self.pin)
            .field("der_bytes", &self.der.len())
            .field("key", &"[redacted]")
            .finish()
    }
}

/// The subject name: `Apassy node <name>`, no control character, at most 40
/// characters of the name, `Apassy node` alone when nothing is left.
pub fn subject_name(machine_name: &str) -> String {
    let clean: String = machine_name
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_NAME_CHARS)
        .collect();
    let clean = clean.trim();
    if clean.is_empty() {
        "Apassy node".to_owned()
    } else {
        format!("Apassy node {clean}")
    }
}

/// The associated data of the sealed key: it binds the key to its certificate.
fn seal_context(der: &[u8]) -> Vec<u8> {
    let mut context = b"apassy-node-front-cert\0".to_vec();
    context.extend_from_slice(Pin::of_certificate(der).as_bytes());
    context
}

impl NodeCertificate {
    /// Make a new certificate in memory. Nothing is written.
    pub fn generate(machine_name: &str) -> Result<Self, CertificateError> {
        let fail = |error: rcgen::Error| CertificateError::Make(error.to_string());
        let now = OffsetDateTime::now_utc();
        let mut params = CertificateParams::new(Vec::<String>::new()).map_err(fail)?;
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, subject_name(machine_name));
        name.push(DnType::OrganizationName, "Apassy");
        params.distinguished_name = name;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.not_before = now - Duration::days(1);
        params.not_after = now + Duration::days(VALID_DAYS);
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(fail)?;
        let cert = params.self_signed(&key).map_err(fail)?;
        let der = cert.der().to_vec();
        Ok(Self {
            pin: Pin::of_certificate(&der),
            der,
            key: Zeroizing::new(key.serialize_der()),
        })
    }

    /// Load the certificate of `dir`, or make and write one when either file is
    /// missing. Both files there and a key that does not open: [`CertificateError::Unreadable`].
    pub fn load_or_make(
        dir: &Path,
        master_key: &[u8],
        machine_name: &str,
    ) -> Result<Self, CertificateError> {
        ensure_private_dir(dir)?;
        let der = read_file(&dir.join(CERT_FILE), false)?;
        let sealed = read_file(&dir.join(KEY_FILE), true)?;
        match (der, sealed) {
            (Some(der), Some(sealed)) => {
                let key = sealed_key::open(master_key, FRONT_INFO, &seal_context(&der), &sealed)?;
                let certificate = Self {
                    pin: Pin::of_certificate(&der),
                    der,
                    key,
                };
                // The key must belong to the certificate.
                super::tls_front::server_config(&certificate.der, &certificate.key)
                    .map_err(|_| CertificateError::Unreadable)?;
                Ok(certificate)
            }
            // A start that stopped between the two writes, or a first start. No device
            // can know a pin of a front that never had both files.
            _ => Self::replace(dir, master_key, machine_name),
        }
    }

    /// Make a new certificate and write it over the files of `dir`. The pin changes:
    /// every paired device pairs again.
    pub fn replace(
        dir: &Path,
        master_key: &[u8],
        machine_name: &str,
    ) -> Result<Self, CertificateError> {
        ensure_private_dir(dir)?;
        let certificate = Self::generate(machine_name)?;
        let sealed = sealed_key::seal(
            master_key,
            FRONT_INFO,
            &seal_context(&certificate.der),
            &certificate.key,
        )?;
        // The key first: a key without its certificate never opens (the context is the
        // hash of the certificate), so a stop between the two renames makes a new pair
        // at the next start.
        write_replacing(&dir.join(KEY_FILE), &sealed)?;
        write_replacing(&dir.join(CERT_FILE), &certificate.der)?;
        Ok(certificate)
    }
}

fn files_error(why: &str, path: &Path) -> CertificateError {
    CertificateError::Files(format!("{why}: {}", path.display()))
}

/// Make `dir` a real directory of this user with mode 0700.
fn ensure_private_dir(dir: &Path) -> Result<(), CertificateError> {
    match fs::symlink_metadata(dir) {
        Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {
            if meta.permissions().mode() & 0o077 != 0 {
                fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
                    .map_err(|_| files_error("the directory cannot be made private", dir))?;
            }
            Ok(())
        }
        Ok(_) => Err(files_error("not a directory", dir)),
        Err(error) if error.kind() == ErrorKind::NotFound => fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|_| files_error("the directory cannot be made", dir)),
        Err(_) => Err(files_error("the directory cannot be read", dir)),
    }
}

/// A plain file of at most [`MAX_FILE_BYTES`], or `None` when it is missing. A link, a
/// file that is too long, and (for a `private` file) a file that others can read are
/// refused.
fn read_file(path: &Path, private: bool) -> Result<Option<Vec<u8>>, CertificateError> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(files_error("cannot be read", path)),
    };
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(files_error("not a plain file", path));
    }
    if private && meta.mode() & 0o077 != 0 {
        return Err(files_error("other users can read it", path));
    }
    let mut bytes = Vec::new();
    OpenOptions::new()
        .read(true)
        .open(path)
        .and_then(|file| file.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|_| files_error("cannot be read", path))?;
    if u64::try_from(bytes.len()).is_ok_and(|length| length > MAX_FILE_BYTES) || bytes.is_empty() {
        return Err(files_error("has a wrong length", path));
    }
    Ok(Some(bytes))
}

/// Write `bytes` to a new temporary file of mode 0600 next to `path` and rename it over
/// `path`.
fn write_replacing(path: &Path, bytes: &[u8]) -> Result<(), CertificateError> {
    let temporary: PathBuf = path.with_extension("tmp");
    let _ = fs::remove_file(&temporary);
    let result = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .and_then(|mut file| file.write_all(bytes).and_then(|()| file.sync_all()))
        .and_then(|()| fs::rename(&temporary, path));
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
        return Err(files_error("cannot be written", path));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASTER: &[u8] = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn the_subject_names_the_machine_cleanly() {
        assert_eq!(subject_name("Mac mini"), "Apassy node Mac mini");
        assert_eq!(subject_name("Mac\nmini"), "Apassy node Macmini");
        assert_eq!(subject_name(""), "Apassy node");
        assert_eq!(subject_name(" \n"), "Apassy node");
        assert_eq!(
            subject_name(&"m".repeat(60)),
            format!("Apassy node {}", "m".repeat(40))
        );
    }

    #[test]
    fn the_first_start_makes_the_files_and_the_next_start_loads_the_same_pin() {
        let dir = tempfile::tempdir().expect("dir");
        let front = dir.path().join("node").join("front");
        let first = NodeCertificate::load_or_make(&front, MASTER, "Mac mini").expect("make");
        assert_eq!(first.pin, Pin::of_certificate(&first.der));
        let key_meta = fs::metadata(front.join(KEY_FILE)).expect("key file");
        assert_eq!(key_meta.mode() & 0o777, 0o600);
        assert_eq!(fs::metadata(&front).expect("dir").mode() & 0o777, 0o700);
        let sealed = fs::read(front.join(KEY_FILE)).expect("sealed");
        assert!(
            !sealed
                .windows(first.key.len())
                .any(|window| window == &first.key[..]),
            "the key is not in the file in plain"
        );
        let second = NodeCertificate::load_or_make(&front, MASTER, "Other name").expect("load");
        assert_eq!(second.pin, first.pin);
        assert_eq!(second.der, first.der);
        assert_eq!(&second.key[..], &first.key[..]);
    }

    #[test]
    fn another_master_key_does_not_open_the_key_and_does_not_change_the_pin() {
        let dir = tempfile::tempdir().expect("dir");
        let first = NodeCertificate::load_or_make(dir.path(), MASTER, "Mac").expect("make");
        let mut other = MASTER.to_vec();
        other[5] ^= 1;
        assert!(matches!(
            NodeCertificate::load_or_make(dir.path(), &other, "Mac"),
            Err(CertificateError::Unreadable)
        ));
        // The files are unchanged: the right key still opens them.
        let again = NodeCertificate::load_or_make(dir.path(), MASTER, "Mac").expect("load");
        assert_eq!(again.pin, first.pin);
        let replaced = NodeCertificate::replace(dir.path(), &other, "Mac").expect("replace");
        assert_ne!(replaced.pin, first.pin);
        assert!(NodeCertificate::load_or_make(dir.path(), &other, "Mac").is_ok());
    }

    #[test]
    fn a_key_next_to_another_certificate_does_not_open() {
        let dir = tempfile::tempdir().expect("dir");
        NodeCertificate::load_or_make(dir.path(), MASTER, "Mac").expect("make");
        let other = NodeCertificate::generate("Mac").expect("other");
        fs::write(dir.path().join(CERT_FILE), &other.der).expect("swap the certificate");
        assert!(matches!(
            NodeCertificate::load_or_make(dir.path(), MASTER, "Mac"),
            Err(CertificateError::Unreadable)
        ));
    }

    #[test]
    fn a_missing_half_makes_a_new_pair_and_a_readable_key_file_is_refused() {
        let dir = tempfile::tempdir().expect("dir");
        let first = NodeCertificate::load_or_make(dir.path(), MASTER, "Mac").expect("make");
        fs::remove_file(dir.path().join(CERT_FILE)).expect("remove");
        let second = NodeCertificate::load_or_make(dir.path(), MASTER, "Mac").expect("remake");
        assert_ne!(second.pin, first.pin);
        fs::set_permissions(dir.path().join(KEY_FILE), fs::Permissions::from_mode(0o644))
            .expect("chmod");
        assert!(matches!(
            NodeCertificate::load_or_make(dir.path(), MASTER, "Mac"),
            Err(CertificateError::Files(_))
        ));
    }
}
