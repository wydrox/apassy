//! The certificate authority of one proxied run (ADR 0011).
//!
//! Each run gets a new authority. Its key stays in the memory of the broker and is
//! gone after the run. Only its certificate goes to the agent process, as a file.
//! The authority is valid for one day and, through name constraints, only for the
//! hosts of the run. It signs a certificate for a host when the process first
//! connects to it.

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
    GeneralSubtree, IsCa, Issuer, KeyPair, KeyUsagePurpose, NameConstraints,
};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use time::{Duration, OffsetDateTime};

/// Certificates start one hour in the past, for a small clock difference.
const CLOCK_SLACK: Duration = Duration::hours(1);
const VALIDITY: Duration = Duration::days(1);

/// The application protocols that the proxy offers to the program in the TLS
/// handshake.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum Alpn {
    /// HTTP/1.1 only. A client that asks for HTTP/2 falls back to it.
    #[default]
    Http11,
}

impl Alpn {
    fn protocols(self) -> Vec<Vec<u8>> {
        match self {
            Self::Http11 => vec![b"http/1.1".to_vec()],
        }
    }
}

pub(super) struct RunCa {
    issuer: Issuer<'static, KeyPair>,
    cert_der: CertificateDer<'static>,
    cert_pem: String,
    configs: Mutex<HashMap<(String, Alpn), Arc<ServerConfig>>>,
}

fn error(err: impl std::fmt::Display) -> io::Error {
    io::Error::other(format!("run certificate: {err}"))
}

impl RunCa {
    /// A new authority for `hosts`. Each host covers its subdomains.
    pub fn new(hosts: &[String]) -> io::Result<Self> {
        let now = OffsetDateTime::now_utc();
        let mut params = CertificateParams::default();
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, "Apassy run proxy");
        name.push(DnType::OrganizationName, "Apassy");
        params.distinguished_name = name;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params.not_before = now - CLOCK_SLACK;
        params.not_after = now + VALIDITY;
        params.name_constraints = Some(NameConstraints {
            permitted_subtrees: hosts
                .iter()
                .map(|host| GeneralSubtree::DnsName(host.clone()))
                .collect(),
            excluded_subtrees: Vec::new(),
        });
        let key = KeyPair::generate().map_err(error)?;
        let cert = params.self_signed(&key).map_err(error)?;
        Ok(Self {
            cert_der: cert.der().clone(),
            cert_pem: cert.pem(),
            issuer: Issuer::new(params, key),
            configs: Mutex::new(HashMap::new()),
        })
    }

    /// The authority certificate in PEM form, for the trust files of the process.
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// TLS settings with a certificate for `host` and the protocols of `alpn`, made
    /// on first use.
    pub fn server_config(&self, host: &str, alpn: Alpn) -> io::Result<Arc<ServerConfig>> {
        let mut configs = self
            .configs
            .lock()
            .map_err(|_| io::Error::other("certificate cache"))?;
        let cache_key = (host.to_owned(), alpn);
        if let Some(config) = configs.get(&cache_key) {
            return Ok(Arc::clone(config));
        }
        let now = OffsetDateTime::now_utc();
        let mut params = CertificateParams::new(vec![host.to_owned()]).map_err(error)?;
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, host);
        params.distinguished_name = name;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        params.not_before = now - CLOCK_SLACK;
        params.not_after = now + VALIDITY;
        let key = KeyPair::generate().map_err(error)?;
        let cert = params.signed_by(&key, &self.issuer).map_err(error)?;
        let chain = vec![cert.der().clone(), self.cert_der.clone()];
        let private = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(error)?
            .with_no_client_auth()
            .with_single_cert(chain, private)
            .map_err(error)?;
        config.alpn_protocols = alpn.protocols();
        let config = Arc::new(config);
        configs.insert(cache_key, Arc::clone(&config));
        Ok(config)
    }
}
