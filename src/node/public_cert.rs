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
//! The public certificate and its key are in the node directory (`connect/`, mode
//! 0700): `public-chain.pem` and `public-key.sealed`, each mode 0600, written through a
//! temporary file and a rename. The PKCS#8 key is sealed under the node master key as the
//! node certificate's key is (`crate::net::sealed_key`, info `apassy-node-connect-v1`,
//! the SHA-256 of the leaf DER in the associated data), so it opens only with this node's
//! key and next to its own certificate. The key never leaves this Mac.

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
/// The certificate chain of the public name, PEM, leaf first.
pub const CHAIN_FILE: &str = "public-chain.pem";
/// The private key of the public certificate, PKCS#8 DER sealed under the node key.
pub const KEY_FILE: &str = "public-key.sealed";
/// The plain key file of earlier builds; removed when it is found.
const OLD_KEY_FILE: &str = "public-key.der";
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

/// Write `bytes` to `path` with mode 0600 through a temporary file and a rename.
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
    fs::rename(&temporary, path)
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
/// PKCS#8 key, when both files are there.
#[derive(Debug)]
pub struct StoredPublic {
    pub chain: Vec<Vec<u8>>,
    pub key: Zeroizing<Vec<u8>>,
}

/// The associated data of the sealed public key: it binds the key to its leaf.
fn key_context(leaf: &[u8]) -> Vec<u8> {
    let mut context = b"apassy-public-key\0".to_vec();
    context.extend_from_slice(ring::digest::digest(&ring::digest::SHA256, leaf).as_ref());
    context
}

/// Remove a plain key file that an earlier build wrote, if there is one.
pub(crate) fn remove_plain(path: &Path) {
    if fs::symlink_metadata(path).is_ok() {
        let _ = fs::remove_file(path);
    }
}

/// Read the public certificate of `node_dir`. `None` when a file is missing or does not
/// make a chain; an error when the key does not open with `seal` next to this chain.
pub fn load_public(node_dir: &Path, seal: &SealKey) -> io::Result<Option<StoredPublic>> {
    let dir = connect_dir(node_dir);
    remove_plain(&dir.join(OLD_KEY_FILE));
    let (Some(chain), Some(sealed)) = (
        read_private(&dir.join(CHAIN_FILE))?,
        read_private(&dir.join(KEY_FILE))?,
    ) else {
        return Ok(None);
    };
    let text = String::from_utf8_lossy(&chain).into_owned();
    let chain = pem_certificates(&text)?;
    let Some(leaf) = chain.first() else {
        return Ok(None);
    };
    let key = seal
        .open(&key_context(leaf), &sealed)
        .map_err(|error| io::Error::new(ErrorKind::InvalidData, error.to_string()))?;
    Ok(Some(StoredPublic { chain, key }))
}

/// Write the public certificate (the PEM chain as ACME gave it) and its key, sealed with
/// `seal`, into `node_dir`, mode 0600 each.
pub fn store_public(
    node_dir: &Path,
    chain_pem: &str,
    key_pkcs8: &[u8],
    seal: &SealKey,
) -> io::Result<()> {
    let dir = connect_dir(node_dir);
    ensure_private_dir(&dir)?;
    let chain = pem_certificates(chain_pem)?;
    let leaf = chain
        .first()
        .ok_or_else(|| io::Error::new(ErrorKind::InvalidData, "an empty chain"))?;
    let sealed = seal
        .seal(&key_context(leaf), key_pkcs8)
        .map_err(|error| io::Error::other(error.to_string()))?;
    write_private(&dir.join(KEY_FILE), &sealed)?;
    write_private(&dir.join(CHAIN_FILE), chain_pem.as_bytes())?;
    remove_plain(&dir.join(OLD_KEY_FILE));
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

    #[test]
    fn the_public_key_is_sealed_and_opens_only_with_its_chain_and_node_key() {
        use crate::net::sealed_key::CONNECT_INFO;
        let dir = tempfile::tempdir().unwrap();
        let seal = SealKey::derive(&[7u8; 32], CONNECT_INFO).unwrap();
        let name = "aaaaaaaaaa.node.example.test";
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = rcgen::CertificateParams::new(vec![name.to_owned()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let pkcs8 = key.serialize_der();
        // A plain key file of an earlier build goes.
        let connect = dir.path().join(CONNECT_DIR);
        ensure_private_dir(&connect).unwrap();
        write_private(&connect.join(OLD_KEY_FILE), &pkcs8).unwrap();
        store_public(dir.path(), &cert.pem(), &pkcs8, &seal).unwrap();
        assert!(!connect.join(OLD_KEY_FILE).exists());
        let stored = fs::read(connect.join(KEY_FILE)).unwrap();
        assert!(
            !stored
                .windows(pkcs8.len())
                .any(|window| window == pkcs8.as_slice()),
            "the key is not in the file in the clear"
        );
        let mode = fs::metadata(connect.join(KEY_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let loaded = load_public(dir.path(), &seal).unwrap().unwrap();
        assert_eq!(&loaded.key[..], &pkcs8[..]);
        assert_eq!(loaded.chain[0], cert.der().to_vec());
        // Another node key does not open it.
        let other = SealKey::derive(&[8u8; 32], CONNECT_INFO).unwrap();
        assert!(load_public(dir.path(), &other).is_err());
        // Nor does another chain next to it.
        let key2 = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert2 = rcgen::CertificateParams::new(vec![name.to_owned()])
            .unwrap()
            .self_signed(&key2)
            .unwrap();
        write_private(&connect.join(CHAIN_FILE), cert2.pem().as_bytes()).unwrap();
        assert!(load_public(dir.path(), &seal).is_err());
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
