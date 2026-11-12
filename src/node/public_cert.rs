//! The certificates of the Connect tunnel streams (ADR 0037 stage 7, plan s7 unit M4;
//! docs/contracts/connect-tunnel-v1.md section 1).
//!
//! The TLS front ends the TLS of every tunnel stream on this Mac. It picks the
//! certificate by the kind of the stream and by the server name of the ClientHello:
//!
//! - A `device` stream (a dial of a device of the account) gets the pinned node
//!   certificate (`crate::net::certificate`), the one of the tailnet front: the device
//!   checks its pin. A ClientHello that names the public name gets no certificate: the
//!   node certificate is never served to the public name.
//! - A `public` stream (a cloud agent through the SNI ingress) gets the publicly trusted
//!   certificate of `<node>.node.<zone>` that ACME issued (`super::acme`), and only for a
//!   ClientHello that names exactly that name. Any other name, no name, or no certificate
//!   yet: no certificate, so the handshake ends with an alert. The public certificate is
//!   never served to a device dial, and the node certificate never to a public stream.
//!
//! The two kinds have separate TLS configurations, each with a resolver that holds only
//! the certificate it may serve ([`CertPicker::config`]): a bug in the name check cannot
//! hand the other kind's key out. A new public certificate (a renewal) takes effect at
//! the next handshake; open streams keep theirs.
//!
//! The public certificate and its key are one file of the node directory (`connect/`,
//! mode 0700): `public-cert.sealed`, mode 0600. The chain (PEM, as ACME gave it) and the
//! PKCS#8 key are sealed together under the node master key (`crate::net::sealed_key`,
//! info `apassy-node-connect-v1`), so they open only with this node's key and only as
//! the pair that was written. The file is written to a temporary file in the same
//! directory, synced, and renamed over the old one: a reader sees the old pair or the new
//! one, never half of each. A file that is cut or changed does not open, and the node
//! orders a new certificate. Before storing, the key is checked against the leaf. The
//! key never leaves this Mac.
//!
//! Earlier builds kept the chain and the key in two files (`public-chain.pem`,
//! `public-key.sealed`, before that `public-key.der`); they are removed when found, and
//! the node orders a new certificate.

use std::fs::{self, OpenOptions};
use std::io::{self, ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, PoisonError, RwLock};

use base64::Engine as _;
use rustls::ServerConfig;
use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use zeroize::Zeroizing;

use super::tunnel::frame::Kind;
use crate::net::certificate::NodeCertificate;
use crate::net::sealed_key::SealKey;

/// The directory of the Connect files in the node directory.
pub const CONNECT_DIR: &str = "connect";
/// The public certificate: its PEM chain (leaf first) and its PKCS#8 key, sealed
/// together under the node key.
pub const PUBLIC_FILE: &str = "public-cert.sealed";
/// The files of earlier builds (the chain and the key apart); removed when found.
const OLD_FILES: [&str; 3] = ["public-chain.pem", "public-key.sealed", "public-key.der"];
/// The associated data of the sealed public certificate.
const PUBLIC_CONTEXT: &[u8] = b"apassy-public-cert-v1";
/// A file of the public certificate is at most this long.
const MAX_FILE_BYTES: u64 = 64 * 1024;

/// The public name of a node (`<10 characters of a-z2-7>.<zone>`), lowercase.
pub fn valid_public_name(name: &str) -> bool {
    let Some((label, zone)) = name.split_once('.') else {
        return false;
    };
    label.len() == 10
        && label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
        && !zone.is_empty()
        && zone.len() <= 200
        && zone.split('.').all(|part| {
            !part.is_empty()
                && part.len() <= 63
                && part
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !part.starts_with('-')
                && !part.ends_with('-')
        })
}

fn certified(chain: Vec<CertificateDer<'static>>, key_pkcs8: &[u8]) -> io::Result<CertifiedKey> {
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pkcs8));
    let signing = any_supported_type(&key).map_err(io::Error::other)?;
    let certified = CertifiedKey::new(chain, signing);
    certified.keys_match().map_err(io::Error::other)?;
    Ok(certified)
}

/// The certificates of the tunnel streams of one node. See the module text.
pub struct CertPicker {
    public_name: String,
    node: Arc<CertifiedKey>,
    public: RwLock<Option<Arc<CertifiedKey>>>,
}

impl std::fmt::Debug for CertPicker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertPicker")
            .field("public_name", &self.public_name)
            .field("public", &self.has_public())
            .finish_non_exhaustive()
    }
}

impl CertPicker {
    /// The picker of the node certificate and the public name. The PKCS#8 bytes of the
    /// node key are read by reference; the parsed key lives in the picker.
    pub fn new(node: &NodeCertificate, public_name: &str) -> io::Result<Self> {
        let public_name = public_name.to_ascii_lowercase();
        if !valid_public_name(&public_name) {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "not a public name of a node",
            ));
        }
        let node = certified(vec![CertificateDer::from(node.der.clone())], &node.key)?;
        Ok(Self {
            public_name,
            node: Arc::new(node),
            public: RwLock::new(None),
        })
    }

    /// The public name, such as `k7m2q4x3ca.node.apassy.wyderka.cc`.
    pub fn public_name(&self) -> &str {
        &self.public_name
    }

    /// Serve this chain (DER, leaf first) and key for the public name from the next
    /// handshake on. The key must belong to the leaf.
    pub fn install_public(&self, chain: &[Vec<u8>], key_pkcs8: &[u8]) -> io::Result<()> {
        if chain.is_empty() {
            return Err(io::Error::new(ErrorKind::InvalidInput, "an empty chain"));
        }
        let chain = chain
            .iter()
            .map(|der| CertificateDer::from(der.clone()))
            .collect();
        let certified = certified(chain, key_pkcs8)?;
        *self.public.write().unwrap_or_else(PoisonError::into_inner) = Some(Arc::new(certified));
        Ok(())
    }

    /// A public certificate is installed.
    pub fn has_public(&self) -> bool {
        self.public
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
    }

    fn is_public_name(&self, server_name: Option<&str>) -> bool {
        server_name.is_some_and(|name| {
            name.trim_end_matches('.')
                .eq_ignore_ascii_case(&self.public_name)
        })
    }

    /// The certificate for a stream of `kind` whose ClientHello names `server_name`, or
    /// none (the handshake fails). The rules of the module text.
    pub fn pick(&self, kind: Kind, server_name: Option<&str>) -> Option<Arc<CertifiedKey>> {
        match kind {
            Kind::Device => (!self.is_public_name(server_name)).then(|| Arc::clone(&self.node)),
            Kind::Public => {
                if !self.is_public_name(server_name) {
                    return None;
                }
                self.public
                    .read()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone()
            }
            // Plain HTTP: no TLS on an ACME stream.
            Kind::Acme => None,
        }
    }

    /// The TLS configuration of the streams of `kind`.
    ///
    /// `device`: as the tailnet front, TLS 1.3 only, ALPN `http/1.1`, no tickets, no early
    /// data. `public`: TLS 1.2 and 1.3 (cloud agents are ordinary HTTPS clients), ALPN
    /// `http/1.1`, no tickets, no early data. `acme`: `None`.
    pub fn config(self: &Arc<Self>, kind: Kind) -> Option<Arc<ServerConfig>> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = ServerConfig::builder_with_provider(provider);
        let builder = match kind {
            Kind::Device => builder.with_protocol_versions(&[&rustls::version::TLS13]),
            Kind::Public => builder.with_safe_default_protocol_versions(),
            Kind::Acme => return None,
        }
        .ok()?;
        let mut config = builder
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(KindResolver {
                picker: Arc::clone(self),
                kind,
            }));
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        config.send_tls13_tickets = 0;
        config.max_early_data_size = 0;
        Some(Arc::new(config))
    }
}

/// The resolver of one kind: it asks the picker with its own kind only.
#[derive(Debug)]
struct KindResolver {
    picker: Arc<CertPicker>,
    kind: Kind,
}

impl ResolvesServerCert for KindResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.picker.pick(self.kind, client_hello.server_name())
    }
}

// ---- The files. ----

fn connect_dir(node_dir: &Path) -> PathBuf {
    node_dir.join(CONNECT_DIR)
}

/// Make `dir` with mode 0700, or tighten it.
pub(crate) fn ensure_private_dir(dir: &Path) -> io::Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    let meta = fs::symlink_metadata(dir)?;
    if !meta.is_dir() {
        return Err(io::Error::new(ErrorKind::InvalidData, "not a directory"));
    }
    if meta.permissions().mode() & 0o077 != 0 {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Write `bytes` to `path` with mode 0600 through a temporary file in the same
/// directory, synced before it is renamed over `path`. The directory is synced after the
/// rename where the system allows it.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let temporary = path.with_extension("new");
    let _ = fs::remove_file(&temporary);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, path)?;
    if let Some(dir) = path.parent()
        && let Ok(dir) = fs::File::open(dir)
    {
        let _ = dir.sync_all();
    }
    Ok(())
}

/// Read a private file: `None` when it is missing; an error when it is a link, not a
/// file, readable by others, or too long.
pub(crate) fn read_private(path: &Path) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !meta.is_file() || meta.permissions().mode() & 0o077 != 0 {
        return Err(io::Error::new(ErrorKind::InvalidData, "not a private file"));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    fs::File::open(path)?
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(io::Error::new(ErrorKind::InvalidData, "too long"));
    }
    Ok(Some(bytes))
}

/// The certificates of a PEM text (`-----BEGIN CERTIFICATE-----` blocks), DER, in
/// order. Text outside the blocks is ignored; a block that is not base64 is an error.
pub fn pem_certificates(pem: &str) -> io::Result<Vec<Vec<u8>>> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut out = Vec::new();
    let mut rest = pem;
    while let Some(start) = rest.find(BEGIN) {
        let after = &rest[start + BEGIN.len()..];
        let end = after
            .find(END)
            .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "an open PEM block"))?;
        let body: String = after[..end]
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();
        let der = base64::engine::general_purpose::STANDARD
            .decode(body.as_bytes())
            .map_err(|_| io::Error::new(ErrorKind::InvalidData, "a PEM block is not base64"))?;
        out.push(der);
        rest = &after[end + END.len()..];
    }
    Ok(out)
}

/// The public certificate of the node directory: the chain (DER, leaf first) and the
/// PKCS#8 key, which were stored together.
#[derive(Debug)]
pub struct StoredPublic {
    pub chain: Vec<Vec<u8>>,
    pub key: Zeroizing<Vec<u8>>,
}

/// Remove a file that an earlier build wrote, if there is one.
pub(crate) fn remove_plain(path: &Path) {
    if fs::symlink_metadata(path).is_ok() {
        let _ = fs::remove_file(path);
    }
}

/// The sealed content of [`PUBLIC_FILE`]: the length of the PEM chain (4 bytes, big
/// endian), the PEM chain, and the PKCS#8 key.
fn public_plaintext(chain_pem: &str, key_pkcs8: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
    let length = u32::try_from(chain_pem.len())
        .map_err(|_| io::Error::new(ErrorKind::InvalidData, "the chain is too long"))?;
    let mut plaintext = Zeroizing::new(Vec::with_capacity(4 + chain_pem.len() + key_pkcs8.len()));
    plaintext.extend_from_slice(&length.to_be_bytes());
    plaintext.extend_from_slice(chain_pem.as_bytes());
    plaintext.extend_from_slice(key_pkcs8);
    Ok(plaintext)
}

/// The chain (DER) and the key of an opened [`PUBLIC_FILE`]; an error unless both are
/// there whole.
fn split_public(plaintext: &[u8]) -> io::Result<StoredPublic> {
    let bad = || io::Error::new(ErrorKind::InvalidData, "not a public certificate");
    let (length, rest) = plaintext.split_first_chunk::<4>().ok_or_else(bad)?;
    let length = usize::try_from(u32::from_be_bytes(*length)).map_err(|_| bad())?;
    if length > rest.len() {
        return Err(bad());
    }
    let (chain_pem, key) = rest.split_at(length);
    let chain_pem = std::str::from_utf8(chain_pem).map_err(|_| bad())?;
    let chain = pem_certificates(chain_pem)?;
    if chain.is_empty() || key.is_empty() {
        return Err(bad());
    }
    Ok(StoredPublic {
        chain,
        key: Zeroizing::new(key.to_vec()),
    })
}

/// Read the public certificate of `node_dir`. `None` when there is none; an error when
/// the file does not open with `seal` (another node key, a cut or changed file) or does
/// not hold a chain and a key. The files of earlier builds are removed.
pub fn load_public(node_dir: &Path, seal: &SealKey) -> io::Result<Option<StoredPublic>> {
    let dir = connect_dir(node_dir);
    for old in OLD_FILES {
        remove_plain(&dir.join(old));
    }
    let Some(sealed) = read_private(&dir.join(PUBLIC_FILE))? else {
        return Ok(None);
    };
    let plaintext = seal
        .open(PUBLIC_CONTEXT, &sealed)
        .map_err(|error| io::Error::new(ErrorKind::InvalidData, error.to_string()))?;
    split_public(&plaintext).map(Some)
}

/// Write the public certificate (the PEM chain as ACME gave it) and its key, sealed
/// together with `seal`, into `node_dir`: one file, mode 0600, replaced in one rename.
/// The key must belong to the leaf. The files of earlier builds are removed.
pub fn store_public(
    node_dir: &Path,
    chain_pem: &str,
    key_pkcs8: &[u8],
    seal: &SealKey,
) -> io::Result<()> {
    let chain = pem_certificates(chain_pem)?;
    if chain.is_empty() {
        return Err(io::Error::new(ErrorKind::InvalidData, "an empty chain"));
    }
    certified(
        chain.into_iter().map(CertificateDer::from).collect(),
        key_pkcs8,
    )?;
    let sealed = seal
        .seal(PUBLIC_CONTEXT, &public_plaintext(chain_pem, key_pkcs8)?)
        .map_err(|error| io::Error::other(error.to_string()))?;
    if sealed.len() as u64 > MAX_FILE_BYTES {
        return Err(io::Error::new(ErrorKind::InvalidData, "too long"));
    }
    let dir = connect_dir(node_dir);
    ensure_private_dir(&dir)?;
    write_private(&dir.join(PUBLIC_FILE), &sealed)?;
    for old in OLD_FILES {
        remove_plain(&dir.join(old));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_names_are_checked() {
        assert!(valid_public_name("k7m2q4x3ca.node.apassy.wyderka.cc"));
        assert!(valid_public_name("aaaaaaaaaa.node.example.test"));
        for bad in [
            "k7m2q4x3c.node.example.test",
            "k7m2q4x3ca1.node.example.test",
            "K7M2Q4X3CA.node.example.test",
            "k7m2q4x3c1.node.example.test",
            "k7m2q4x3ca.",
            "k7m2q4x3ca",
            "k7m2q4x3ca.-node.test",
            "k7m2q4x3ca.no de.test",
        ] {
            assert!(!valid_public_name(bad), "{bad}");
        }
    }

    const NAME: &str = "aaaaaaaaaa.node.example.test";

    /// A self-signed certificate of [`NAME`]: its PEM and its PKCS#8 key.
    fn certificate() -> (String, Vec<u8>, Vec<u8>) {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = rcgen::CertificateParams::new(vec![NAME.to_owned()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        (cert.pem(), cert.der().to_vec(), key.serialize_der())
    }

    fn seal_key(byte: u8) -> SealKey {
        SealKey::derive(&[byte; 32], crate::net::sealed_key::CONNECT_INFO).unwrap()
    }

    #[test]
    fn the_chain_and_the_key_are_one_sealed_file_that_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let seal = seal_key(7);
        let (pem, der, pkcs8) = certificate();
        // The files of an earlier build go.
        let connect = dir.path().join(CONNECT_DIR);
        ensure_private_dir(&connect).unwrap();
        for old in OLD_FILES {
            write_private(&connect.join(old), &pkcs8).unwrap();
        }
        store_public(dir.path(), &pem, &pkcs8, &seal).unwrap();
        let mut names: Vec<String> = fs::read_dir(&connect)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, [PUBLIC_FILE], "one file, no temporary file left");
        let stored = fs::read(connect.join(PUBLIC_FILE)).unwrap();
        assert_eq!(stored.first(), Some(&crate::net::sealed_key::VERSION));
        assert!(
            !stored
                .windows(pkcs8.len())
                .any(|window| window == pkcs8.as_slice()),
            "the key is not in the file in the clear"
        );
        assert!(
            !stored
                .windows(27)
                .any(|window| window == b"-----BEGIN CERTIFICATE-----"),
            "the chain is sealed with the key"
        );
        let mode = fs::metadata(connect.join(PUBLIC_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let loaded = load_public(dir.path(), &seal).unwrap().unwrap();
        assert_eq!(&loaded.key[..], &pkcs8[..]);
        assert_eq!(loaded.chain, [der]);
        // Another node key does not open it.
        assert!(load_public(dir.path(), &seal_key(8)).is_err());
        // A new certificate replaces the pair as a whole.
        let (pem2, der2, pkcs8_2) = certificate();
        store_public(dir.path(), &pem2, &pkcs8_2, &seal).unwrap();
        let loaded = load_public(dir.path(), &seal).unwrap().unwrap();
        assert_eq!((loaded.chain, &loaded.key[..]), (vec![der2], &pkcs8_2[..]));
    }

    #[test]
    fn a_cut_or_changed_file_is_refused_not_half_read() {
        let dir = tempfile::tempdir().unwrap();
        let seal = seal_key(7);
        let (pem, _, pkcs8) = certificate();
        store_public(dir.path(), &pem, &pkcs8, &seal).unwrap();
        let path = dir.path().join(CONNECT_DIR).join(PUBLIC_FILE);
        let whole = fs::read(&path).unwrap();
        for length in [0, 1, 13, whole.len() / 2, whole.len() - 17, whole.len() - 1] {
            write_private(&path, &whole[..length]).unwrap();
            assert!(load_public(dir.path(), &seal).is_err(), "cut at {length}");
        }
        for index in [0, 5, whole.len() / 2, whole.len() - 1] {
            let mut changed = whole.clone();
            changed[index] ^= 0x01;
            write_private(&path, &changed).unwrap();
            assert!(load_public(dir.path(), &seal).is_err(), "byte {index}");
        }
        let mut longer = whole.clone();
        longer.push(0);
        write_private(&path, &longer).unwrap();
        assert!(load_public(dir.path(), &seal).is_err());
        // A sealed content that is not a chain and a key is refused too.
        let contents: [&[u8]; 4] = [b"", b"\0\0", b"\0\0\0\x09short", b"\0\0\0\0key"];
        for content in contents {
            write_private(&path, &seal.seal(PUBLIC_CONTEXT, content).unwrap()).unwrap();
            assert!(load_public(dir.path(), &seal).is_err(), "{content:?}");
        }
        let without_key = public_plaintext(&pem, b"").unwrap();
        write_private(&path, &seal.seal(PUBLIC_CONTEXT, &without_key).unwrap()).unwrap();
        assert!(load_public(dir.path(), &seal).is_err());
        write_private(&path, &whole).unwrap();
        assert!(load_public(dir.path(), &seal).unwrap().is_some());
    }

    #[test]
    fn the_two_files_of_earlier_builds_are_removed_and_not_read() {
        let dir = tempfile::tempdir().unwrap();
        let seal = seal_key(7);
        let (pem, _, pkcs8) = certificate();
        let connect = dir.path().join(CONNECT_DIR);
        ensure_private_dir(&connect).unwrap();
        write_private(&connect.join("public-chain.pem"), pem.as_bytes()).unwrap();
        write_private(&connect.join("public-key.sealed"), &pkcs8).unwrap();
        assert!(load_public(dir.path(), &seal).unwrap().is_none());
        assert_eq!(fs::read_dir(&connect).unwrap().count(), 0);
    }

    #[test]
    fn a_key_of_another_certificate_is_not_stored() {
        let dir = tempfile::tempdir().unwrap();
        let seal = seal_key(7);
        let (pem, _, _) = certificate();
        let (_, _, other_key) = certificate();
        assert!(store_public(dir.path(), &pem, &other_key, &seal).is_err());
        assert!(store_public(dir.path(), "no chain", &other_key, &seal).is_err());
        assert!(!dir.path().join(CONNECT_DIR).join(PUBLIC_FILE).exists());
    }

    #[test]
    fn pem_blocks_decode_in_order() {
        let pem = "junk\n-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n\
                   -----BEGIN CERTIFICATE-----\nBAUG\nBw==\n-----END CERTIFICATE-----\n";
        assert_eq!(
            pem_certificates(pem).unwrap(),
            vec![vec![1, 2, 3], vec![4, 5, 6, 7]]
        );
        assert!(pem_certificates("-----BEGIN CERTIFICATE-----\nAQID\n").is_err());
        assert!(
            pem_certificates("-----BEGIN CERTIFICATE-----\n!!\n-----END CERTIFICATE-----").is_err()
        );
        assert!(pem_certificates("none").unwrap().is_empty());
    }
}
