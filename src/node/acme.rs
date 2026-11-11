//! ACME v2 (RFC 8555) for the public certificate of the node (ADR 0037 stage 7, plan s7
//! unit M4; connect-tunnel-v1 section 7.2).
//!
//! The node gets a publicly trusted certificate for its public name
//! (`<node>.node.<zone>`) from an ACME CA (Let's Encrypt in the product) with the
//! HTTP-01 challenge. The CA fetches `http://<public name>/.well-known/acme-challenge/
//! <token>`; Connect's port 80 forwards exactly that request through the node's tunnel as
//! an `acme` stream, and the node answers it from [`Challenges`] ([`http01_answer`]).
//! The private key of the certificate is made here and never leaves this Mac; only the
//! CSR goes to the CA.
//!
//! - The account key is ECDSA P-256 (`ring`), kept as PKCS#8 sealed under the node
//!   master key (`crate::net::sealed_key`, info `apassy-node-connect-v1`) in
//!   `<node dir>/connect/acme-account.sealed`, mode 0600. Requests are flattened JWS with
//!   `ES256` (RFC 7518 3.4: `r || s`), the `jwk` for `newAccount` and the `kid` after it,
//!   a fresh `Replay-Nonce` for each request, one retry after `badNonce`, and POST-as-GET
//!   for reads (RFC 8555 6.3).
//! - The key authorization is `<token>.<b64u(SHA-256 of the JWK thumbprint input)>`
//!   (RFC 7638 with the members `crv`, `kty`, `x`, `y` in that order).
//! - The certificate key is a new ECDSA P-256 key for each order (`rcgen`), the CSR names
//!   the public name only. The chain and the key go into the node directory together,
//!   in one sealed file (`super::public_cert::store_public`, mode 0600). When storing or
//!   installing an issued certificate fails, the certificate thread keeps it in memory
//!   and stores it again with the backoff, without a new order, while it is usable
//!   ([`renew_step`]).
//! - Renewal: when 30 days or less are left ([`renewal_due`]).
//! - The directory URL is configuration ([`AcmeOptions::directory`]): the product uses
//!   Let's Encrypt (or `APASSY_CONNECT_ACME_DIRECTORY`, `https://` only). Every URL that
//!   the CA's answers name (the URLs of the directory, the `Location` of the account and
//!   of the order, the authorizations, the challenges, `finalize`, and the certificate)
//!   must be `https://` on the same host and port as the directory, with a host name and
//!   not an IP address. A URL that is not is refused before any request goes to it, so
//!   the node talks to its CA and nothing else. Tests run a fake CA on the loopback with
//!   plain `http://`, which only [`AcmeOptions::loopback_test_ca`] allows, and then only
//!   on the directory's own address and port.
//!
//! No value of this module is a secret of the vault. The account key and the certificate
//! key are secrets of the node and stay in its directory.

use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use base64::Engine as _;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};
use serde::Deserialize;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::public_cert::{self, pem_certificates};
use crate::broker::http::{
    Body, DestinationUrl, HttpRequest, HttpResponse, Method, TlsClient, parse_destination, send,
};
use crate::net::sealed_key::SealKey;

/// Let's Encrypt's production directory.
pub const LETS_ENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";
/// The setting that points the node at another ACME directory (the staging CA).
pub const DIRECTORY_ENV: &str = "APASSY_CONNECT_ACME_DIRECTORY";
/// Renew when this much is left (plan s7 M4: 30 days).
pub const RENEW_BEFORE: Duration = Duration::from_secs(30 * 86_400);
/// The file of the ACME account key (sealed) in the Connect directory of the node.
pub const ACCOUNT_KEY_FILE: &str = "acme-account.sealed";
/// The plain key file of earlier builds; removed when it is found.
const OLD_ACCOUNT_KEY_FILE: &str = "acme-account.der";
/// The associated data of the sealed account key.
const ACCOUNT_KEY_CONTEXT: &[u8] = b"apassy-acme-account-v1";
/// One request ends within this.
const REQUEST_DEADLINE: Duration = Duration::from_secs(30);
/// The answer to every ACME stream that is not the pending token (contract 7.2).
pub const NOT_FOUND: &[u8] =
    b"HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
const CHALLENGE_PREFIX: &str = "/.well-known/acme-challenge/";

fn b64u(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// The time source of the expiry checks: Unix seconds.
pub type Now = Arc<dyn Fn() -> u64 + Send + Sync>;

fn system_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// How the node talks to its ACME CA.
#[derive(Clone)]
pub struct AcmeOptions {
    /// The directory URL: `https://` with a host name; a plain `http://` URL on the
    /// loopback only with `loopback_test_ca`.
    pub directory: String,
    /// Tests only: the CA is a plain `http://` server on the loopback (the fake CA of the
    /// tests). Its URLs must still be on the directory's own address and port. `false`
    /// in the product.
    pub loopback_test_ca: bool,
    /// The TLS client of the CA; `None`: the platform roots.
    pub tls: Option<TlsClient>,
    pub renew_before: Duration,
    /// The certificate is looked at this often.
    pub check_every: Duration,
    /// After a failed order, the first wait (then doubling, up to `check_every`).
    pub retry_first: Duration,
    /// Authorizations and orders are polled this often, at most `poll_tries` times.
    pub poll_every: Duration,
    pub poll_tries: u32,
    pub now: Now,
}

impl std::fmt::Debug for AcmeOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcmeOptions")
            .field("directory", &self.directory)
            .finish_non_exhaustive()
    }
}

impl AcmeOptions {
    /// The options of a directory, with the product's times.
    pub fn new(directory: &str) -> Self {
        Self {
            directory: directory.to_owned(),
            loopback_test_ca: false,
            tls: None,
            renew_before: RENEW_BEFORE,
            check_every: Duration::from_secs(3600),
            retry_first: Duration::from_secs(60),
            poll_every: Duration::from_secs(2),
            poll_tries: 60,
            now: Arc::new(system_now),
        }
    }

    /// The product: [`DIRECTORY_ENV`] when it is set to an `https://` URL, else Let's
    /// Encrypt.
    pub fn configured() -> Self {
        let directory = std::env::var(DIRECTORY_ENV)
            .ok()
            .filter(|url| url.starts_with("https://"))
            .unwrap_or_else(|| LETS_ENCRYPT.to_owned());
        Self::new(&directory)
    }
}

/// Why an order did not give a certificate. The text is for "No certificate yet: …".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcmeError {
    /// The CA could not be reached.
    Unreachable(String),
    /// The CA refused a request (the ACME problem type and detail).
    Refused {
        status: u16,
        kind: String,
        detail: String,
    },
    /// The CA could not check the challenge through the tunnel.
    ChallengeFailed(String),
    /// An answer of the CA does not follow RFC 8555.
    BadAnswer(String),
    /// The CA did not finish in time.
    Timeout,
    /// The tunnel stopped.
    Stopped,
    /// A key or a file of this Mac.
    Local(String),
}

impl std::fmt::Display for AcmeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreachable(why) => {
                write!(f, "the certificate authority could not be reached ({why})")
            }
            Self::Refused { detail, kind, .. } if !detail.is_empty() => {
                write!(f, "the certificate authority refused: {detail} ({kind})")
            }
            Self::Refused { status, kind, .. } => {
                write!(f, "the certificate authority refused ({status} {kind})")
            }
            Self::ChallengeFailed(why) => {
                write!(
                    f,
                    "the certificate authority could not reach this Mac through Apassy Connect: {why}"
                )
            }
            Self::BadAnswer(why) => write!(
                f,
                "the certificate authority gave an unexpected answer ({why})"
            ),
            Self::Timeout => f.write_str("the certificate authority did not finish in time"),
            Self::Stopped => f.write_str("the tunnel stopped"),
            Self::Local(why) => write!(f, "{why}"),
        }
    }
}

impl std::error::Error for AcmeError {}

/// The HTTP-01 token of the pending order and its key authorization: the only thing the
/// node serves on `acme` streams.
#[derive(Debug, Default)]
pub struct Challenges {
    pending: Mutex<Option<(String, String)>>,
}

impl Challenges {
    pub fn set(&self, token: &str, key_authorization: &str) {
        *self.pending.lock().unwrap_or_else(PoisonError::into_inner) =
            Some((token.to_owned(), key_authorization.to_owned()));
    }

    pub fn clear(&self) {
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
    }

    /// The key authorization for `token`, when it is the pending one.
    pub fn answer(&self, token: &str) -> Option<String> {
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .filter(|(pending, _)| pending == token)
            .map(|(_, answer)| answer.clone())
    }
}

/// A token of contract 7.2: `[A-Za-z0-9_-]`, 1 to 128 characters.
pub fn valid_token(token: &str) -> bool {
    (1..=128).contains(&token.len())
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// The answer of the node to the request head of an `acme` stream: `200` with the key
/// authorization for `GET /.well-known/acme-challenge/<pending token> HTTP/1.1`, else
/// `404`.
pub fn http01_answer(challenges: &Challenges, head: &[u8]) -> Vec<u8> {
    let Ok(text) = std::str::from_utf8(head) else {
        return NOT_FOUND.to_vec();
    };
    let Some(line) = text.split("\r\n").next() else {
        return NOT_FOUND.to_vec();
    };
    let mut parts = line.split(' ');
    let (Some("GET"), Some(target), Some("HTTP/1.1"), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return NOT_FOUND.to_vec();
    };
    let Some(token) = target.strip_prefix(CHALLENGE_PREFIX) else {
        return NOT_FOUND.to_vec();
    };
    match (valid_token(token), challenges.answer(token)) {
        (true, Some(answer)) => format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{answer}",
            answer.len()
        )
        .into_bytes(),
        _ => NOT_FOUND.to_vec(),
    }
}

// ---- The account key and the JWS. ----

/// The ACME account key (ECDSA P-256).
pub struct AccountKey {
    pair: EcdsaKeyPair,
    rng: SystemRandom,
}

impl std::fmt::Debug for AccountKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountKey")
            .field("thumbprint", &self.thumbprint())
            .finish_non_exhaustive()
    }
}

impl AccountKey {
    /// A key from its PKCS#8 bytes.
    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, AcmeError> {
        let rng = SystemRandom::new();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8, &rng)
            .map_err(|_| AcmeError::Local("the ACME account key cannot be read".to_owned()))?;
        Ok(Self { pair, rng })
    }

    /// A new key and its PKCS#8 bytes.
    pub fn generate() -> Result<(Self, Zeroizing<Vec<u8>>), AcmeError> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_| AcmeError::Local("no ACME account key could be made".to_owned()))?;
        let pkcs8 = Zeroizing::new(pkcs8.as_ref().to_vec());
        Ok((Self::from_pkcs8(&pkcs8)?, pkcs8))
    }

    /// The key of `node_dir`, sealed with `seal`; made and written (mode 0600) at the
    /// first order, or again when the kept one does not open with this node key.
    pub fn load_or_make(node_dir: &Path, seal: &SealKey) -> Result<Self, AcmeError> {
        let dir = node_dir.join(public_cert::CONNECT_DIR);
        let path = dir.join(ACCOUNT_KEY_FILE);
        public_cert::remove_plain(&dir.join(OLD_ACCOUNT_KEY_FILE));
        let local =
            |error: std::io::Error| AcmeError::Local(format!("the ACME account key file: {error}"));
        if let Some(sealed) = public_cert::read_private(&path).map_err(local)?
            && let Ok(pkcs8) = seal.open(ACCOUNT_KEY_CONTEXT, &sealed)
        {
            return Self::from_pkcs8(&pkcs8);
        }
        let (key, pkcs8) = Self::generate()?;
        let sealed = seal
            .seal(ACCOUNT_KEY_CONTEXT, &pkcs8)
            .map_err(|error| AcmeError::Local(format!("the ACME account key: {error}")))?;
        public_cert::ensure_private_dir(&dir).map_err(local)?;
        public_cert::write_private(&path, &sealed).map_err(local)?;
        Ok(key)
    }

    /// The x and y coordinates of the public key.
    fn coordinates(&self) -> (&[u8], &[u8]) {
        let point = self.pair.public_key().as_ref();
        // X9.63 uncompressed: 0x04 || x || y.
        (&point[1..33], &point[33..65])
    }

    /// The public JWK (RFC 7517) of the key.
    pub fn jwk(&self) -> Value {
        let (x, y) = self.coordinates();
        json!({"crv": "P-256", "kty": "EC", "x": b64u(x), "y": b64u(y)})
    }

    /// The JWK thumbprint (RFC 7638), b64u.
    pub fn thumbprint(&self) -> String {
        let (x, y) = self.coordinates();
        let input = format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
            b64u(x),
            b64u(y)
        );
        b64u(ring::digest::digest(&ring::digest::SHA256, input.as_bytes()).as_ref())
    }

    /// The key authorization of an HTTP-01 `token` (RFC 8555 8.1).
    pub fn key_authorization(&self, token: &str) -> String {
        format!("{token}.{}", self.thumbprint())
    }

    /// A flattened JWS (RFC 8555 6.2) of `payload` (`None`: POST-as-GET, an empty
    /// payload) for `url` with `nonce`, with the `kid` when there is one, else the `jwk`.
    pub fn sign(
        &self,
        url: &str,
        nonce: &str,
        kid: Option<&str>,
        payload: Option<&Value>,
    ) -> Result<Vec<u8>, AcmeError> {
        let mut protected = json!({"alg": "ES256", "nonce": nonce, "url": url});
        match kid {
            Some(kid) => protected["kid"] = json!(kid),
            None => protected["jwk"] = self.jwk(),
        }
        let protected = b64u(protected.to_string().as_bytes());
        let payload = match payload {
            Some(payload) => b64u(payload.to_string().as_bytes()),
            None => String::new(),
        };
        let input = format!("{protected}.{payload}");
        let signature = self
            .pair
            .sign(&self.rng, input.as_bytes())
            .map_err(|_| AcmeError::Local("the ACME request cannot be signed".to_owned()))?;
        Ok(json!({
            "protected": protected,
            "payload": payload,
            "signature": b64u(signature.as_ref()),
        })
        .to_string()
        .into_bytes())
    }
}

// ---- The HTTP side. ----

/// A URL as an error text shows it: at most 100 characters, no control characters.
fn shown(url: &str) -> String {
    url.chars().filter(|c| !c.is_control()).take(100).collect()
}

/// A host that is an IP address (IPv4 in any form, IPv6) or looks like one: its last
/// label is digits only or starts with `0x`.
fn ip_literal(host: &str) -> bool {
    let last = host.rsplit('.').next().unwrap_or(host);
    host.contains(':')
        || host.parse::<IpAddr>().is_ok()
        || last.bytes().all(|b| b.is_ascii_digit())
        || last.starts_with("0x")
}

/// `scheme://host[:port]/path` → the destination and the path (`/` at least). An
/// `https://` URL must name a host name, not an IP address. A plain `http://` URL parses
/// only on the loopback; [`CaOrigin`] decides whether it is taken.
fn split_url(url: &str) -> Result<(DestinationUrl, String), AcmeError> {
    let bad = || AcmeError::BadAnswer(format!("not a URL of the CA: {}", shown(url)));
    let (scheme, rest) = url.split_once("://").ok_or_else(bad)?;
    let (authority, path) = match rest.find('/') {
        Some(at) => (&rest[..at], &rest[at..]),
        None => (rest, "/"),
    };
    let destination = parse_destination(&format!("{scheme}://{authority}")).map_err(|_| bad())?;
    if let DestinationUrl::Https { host, .. } = &destination
        && ip_literal(host)
    {
        return Err(bad());
    }
    if !path.bytes().all(|b| (0x21..0x7f).contains(&b)) {
        return Err(bad());
    }
    Ok((destination, path.to_owned()))
}

/// The scheme, host, and port of the configured directory. Every URL that the CA's
/// answers name must have exactly these, so the node sends its requests to the CA and
/// nowhere else.
#[derive(Debug, Clone)]
struct CaOrigin {
    destination: DestinationUrl,
}

impl CaOrigin {
    /// The origin of `directory`: `https://` with a host name; a plain `http://` URL on
    /// the loopback only with `loopback_test_ca` (the fake CA of the tests).
    fn of(directory: &str, loopback_test_ca: bool) -> Result<Self, AcmeError> {
        let refused = || AcmeError::Local("the ACME directory is not an https:// URL".to_owned());
        let (destination, _) = split_url(directory).map_err(|_| refused())?;
        if matches!(destination, DestinationUrl::Loopback { .. }) && !loopback_test_ca {
            return Err(refused());
        }
        Ok(Self { destination })
    }

    /// `url` → the destination and the path, when `url` is on this origin.
    fn split(&self, url: &str) -> Result<(DestinationUrl, String), AcmeError> {
        let (destination, path) = split_url(url)?;
        if destination != self.destination {
            return Err(AcmeError::BadAnswer(format!(
                "a URL that is not on the CA's own host: {}",
                shown(url)
            )));
        }
        Ok((destination, path))
    }

    /// Every URL of `urls` is on this origin.
    fn check<'a>(&self, urls: impl IntoIterator<Item = &'a String>) -> Result<(), AcmeError> {
        urls.into_iter()
            .try_for_each(|url| self.split(url).map(drop))
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Directory {
    new_nonce: String,
    new_account: String,
    new_order: String,
}

#[derive(Debug, Deserialize)]
struct Problem {
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default)]
    detail: String,
}

#[derive(Debug, Deserialize)]
struct Order {
    status: String,
    #[serde(default)]
    authorizations: Vec<String>,
    finalize: String,
    #[serde(default)]
    certificate: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Authorization {
    status: String,
    #[serde(default)]
    challenges: Vec<Challenge>,
}

#[derive(Debug, Deserialize)]
struct Challenge {
    #[serde(rename = "type")]
    kind: String,
    url: String,
    #[serde(default)]
    token: String,
    #[serde(default)]
    error: Option<Problem>,
}

struct Session<'a> {
    options: &'a AcmeOptions,
    tls: TlsClient,
    /// The origin of the configured directory: the only one that requests go to.
    origin: CaOrigin,
    key: AccountKey,
    kid: Option<String>,
    nonce: Option<String>,
    directory: Directory,
    stop: &'a AtomicBool,
}

fn json_of<T: serde::de::DeserializeOwned>(response: &HttpResponse) -> Result<T, AcmeError> {
    serde_json::from_slice(&response.body)
        .map_err(|error| AcmeError::BadAnswer(format!("{} {error}", response.status)))
}

/// One request to `url`, which must be on `origin`; a URL that is not is refused before
/// anything is sent.
fn exchange(
    tls: &TlsClient,
    origin: &CaOrigin,
    url: &str,
    method: Method,
    body: Option<&[u8]>,
    accept: Option<&str>,
) -> Result<HttpResponse, AcmeError> {
    let (destination, path) = origin.split(url)?;
    let accept_header;
    let headers: &[(&str, &str)] = match accept {
        Some(accept) => {
            accept_header = [("Accept", accept)];
            &accept_header
        }
        None => &[],
    };
    let request = HttpRequest {
        method,
        path: &path,
        bearer: None,
        headers,
        body: body.map(Body::Jose),
    };
    send(
        &destination,
        &request,
        Instant::now() + REQUEST_DEADLINE,
        Some(tls),
    )
    .map_err(|failure| AcmeError::Unreachable(format!("{failure:?}")))
}

impl Session<'_> {
    fn open<'a>(
        options: &'a AcmeOptions,
        node_dir: &Path,
        seal: &SealKey,
        stop: &'a AtomicBool,
    ) -> Result<Session<'a>, AcmeError> {
        let tls = match &options.tls {
            Some(tls) => tls.clone(),
            None => TlsClient::platform()
                .map_err(|error| AcmeError::Local(format!("TLS is not available: {error}")))?,
        };
        let origin = CaOrigin::of(&options.directory, options.loopback_test_ca)?;
        let response = exchange(&tls, &origin, &options.directory, Method::Get, None, None)?;
        if response.status != 200 {
            return Err(AcmeError::Unreachable(format!(
                "the directory answered {}",
                response.status
            )));
        }
        let directory: Directory = json_of(&response)?;
        origin.check([
            &directory.new_nonce,
            &directory.new_account,
            &directory.new_order,
        ])?;
        Ok(Session {
            options,
            tls,
            origin,
            key: AccountKey::load_or_make(node_dir, seal)?,
            kid: None,
            nonce: None,
            directory,
            stop,
        })
    }

    fn check_stop(&self) -> Result<(), AcmeError> {
        if self.stop.load(Ordering::SeqCst) {
            Err(AcmeError::Stopped)
        } else {
            Ok(())
        }
    }

    fn fresh_nonce(&self) -> Result<String, AcmeError> {
        let response = exchange(
            &self.tls,
            &self.origin,
            &self.directory.new_nonce,
            Method::Get,
            None,
            None,
        )?;
        response
            .header("replay-nonce")
            .map(str::to_owned)
            .ok_or_else(|| AcmeError::BadAnswer("no Replay-Nonce".to_owned()))
    }

    /// A signed POST (a POST-as-GET without `payload`), one retry after `badNonce`.
    fn post(
        &mut self,
        url: &str,
        payload: Option<&Value>,
        accept: Option<&str>,
    ) -> Result<HttpResponse, AcmeError> {
        for attempt in 0..2 {
            self.check_stop()?;
            let nonce = match self.nonce.take() {
                Some(nonce) => nonce,
                None => self.fresh_nonce()?,
            };
            let body = self.key.sign(url, &nonce, self.kid.as_deref(), payload)?;
            let response = exchange(
                &self.tls,
                &self.origin,
                url,
                Method::Post,
                Some(&body),
                accept,
            )?;
            self.nonce = response.header("replay-nonce").map(str::to_owned);
            if response.status < 400 {
                return Ok(response);
            }
            let problem: Problem = serde_json::from_slice(&response.body).unwrap_or(Problem {
                kind: String::new(),
                detail: String::new(),
            });
            if attempt == 0 && problem.kind == "urn:ietf:params:acme:error:badNonce" {
                continue;
            }
            return Err(AcmeError::Refused {
                status: response.status,
                kind: problem.kind,
                detail: problem.detail.chars().take(200).collect(),
            });
        }
        Err(AcmeError::BadAnswer("badNonce twice".to_owned()))
    }

    fn account(&mut self) -> Result<(), AcmeError> {
        let url = self.directory.new_account.clone();
        let response = self.post(&url, Some(&json!({"termsOfServiceAgreed": true})), None)?;
        let kid = response
            .header("location")
            .ok_or_else(|| AcmeError::BadAnswer("no account Location".to_owned()))?;
        self.origin.split(kid)?;
        self.kid = Some(kid.to_owned());
        Ok(())
    }

    fn wait(&self) -> Result<(), AcmeError> {
        let until = Instant::now() + self.options.poll_every;
        while Instant::now() < until {
            self.check_stop()?;
            std::thread::sleep(Duration::from_millis(20).min(self.options.poll_every));
        }
        Ok(())
    }

    fn authorize(&mut self, url: &str, challenges: &Challenges) -> Result<(), AcmeError> {
        let authorization: Authorization = json_of(&self.post(url, None, None)?)?;
        if authorization.status == "valid" {
            return Ok(());
        }
        let challenge = authorization
            .challenges
            .iter()
            .find(|challenge| challenge.kind == "http-01")
            .ok_or_else(|| AcmeError::BadAnswer("no http-01 challenge".to_owned()))?;
        if !valid_token(&challenge.token) {
            return Err(AcmeError::BadAnswer(
                "a challenge token of a bad shape".to_owned(),
            ));
        }
        let challenge_url = challenge.url.clone();
        self.origin.split(&challenge_url)?;
        challenges.set(
            &challenge.token,
            &self.key.key_authorization(&challenge.token),
        );
        self.post(&challenge_url, Some(&json!({})), None)?;
        for _ in 0..self.options.poll_tries {
            self.wait()?;
            let authorization: Authorization = json_of(&self.post(url, None, None)?)?;
            match authorization.status.as_str() {
                "valid" => return Ok(()),
                "pending" | "processing" => {}
                _ => {
                    let why = authorization
                        .challenges
                        .iter()
                        .find_map(|challenge| challenge.error.as_ref())
                        .map_or_else(
                            || authorization.status.clone(),
                            |problem| problem.detail.chars().take(200).collect(),
                        );
                    return Err(AcmeError::ChallengeFailed(why));
                }
            }
        }
        Err(AcmeError::Timeout)
    }

    fn poll_order(&mut self, url: &str) -> Result<Order, AcmeError> {
        for _ in 0..self.options.poll_tries {
            let order: Order = json_of(&self.post(url, None, None)?)?;
            self.origin.check(&order.certificate)?;
            match order.status.as_str() {
                "valid" => return Ok(order),
                "pending" | "ready" | "processing" => self.wait()?,
                other => return Err(AcmeError::BadAnswer(format!("the order is {other}"))),
            }
        }
        Err(AcmeError::Timeout)
    }
}

/// A certificate that an order gave.
pub struct Issued {
    /// The PEM chain as the CA gave it, leaf first.
    pub chain_pem: String,
    /// The same chain, DER.
    pub chain: Vec<Vec<u8>>,
    /// The PKCS#8 key of the leaf.
    pub key: Zeroizing<Vec<u8>>,
    pub not_after: u64,
}

impl std::fmt::Debug for Issued {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Issued")
            .field("chain", &self.chain.len())
            .field("not_after", &self.not_after)
            .field("key", &"[redacted]")
            .finish()
    }
}

/// A CSR for `name` with a new P-256 key: the DER of the CSR and the PKCS#8 key.
pub fn csr(name: &str) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), AcmeError> {
    let fail = |error: rcgen::Error| AcmeError::Local(format!("the CSR cannot be made: {error}"));
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(fail)?;
    let mut params = CertificateParams::new(vec![name.to_owned()]).map_err(fail)?;
    let mut subject = DistinguishedName::new();
    subject.push(DnType::CommonName, name);
    params.distinguished_name = subject;
    let request = params.serialize_request(&key).map_err(fail)?;
    Ok((request.der().to_vec(), Zeroizing::new(key.serialize_der())))
}

/// Order a certificate for `name` and answer its HTTP-01 challenge through
/// `challenges`. The pending token is cleared at the end, also on an error.
pub fn obtain(
    options: &AcmeOptions,
    node_dir: &Path,
    seal: &SealKey,
    name: &str,
    challenges: &Challenges,
    stop: &AtomicBool,
) -> Result<Issued, AcmeError> {
    let result = obtain_inner(options, node_dir, seal, name, challenges, stop);
    challenges.clear();
    result
}

fn obtain_inner(
    options: &AcmeOptions,
    node_dir: &Path,
    seal: &SealKey,
    name: &str,
    challenges: &Challenges,
    stop: &AtomicBool,
) -> Result<Issued, AcmeError> {
    let mut session = Session::open(options, node_dir, seal, stop)?;
    session.account()?;
    let new_order = session.directory.new_order.clone();
    let response = session.post(
        &new_order,
        Some(&json!({"identifiers": [{"type": "dns", "value": name}]})),
        None,
    )?;
    let order_url = response
        .header("location")
        .ok_or_else(|| AcmeError::BadAnswer("no order Location".to_owned()))?
        .to_owned();
    let order: Order = json_of(&response)?;
    session.origin.check([&order_url, &order.finalize])?;
    session.origin.check(&order.authorizations)?;
    for authorization in &order.authorizations {
        session.authorize(authorization, challenges)?;
    }
    challenges.clear();
    let (csr, key) = csr(name)?;
    session.post(&order.finalize, Some(&json!({"csr": b64u(&csr)})), None)?;
    let order = session.poll_order(&order_url)?;
    let certificate_url = order
        .certificate
        .ok_or_else(|| AcmeError::BadAnswer("a valid order without a certificate".to_owned()))?;
    let response = session.post(
        &certificate_url,
        None,
        Some("application/pem-certificate-chain"),
    )?;
    let chain_pem = String::from_utf8(response.body)
        .map_err(|_| AcmeError::BadAnswer("the chain is not text".to_owned()))?;
    let chain =
        pem_certificates(&chain_pem).map_err(|error| AcmeError::BadAnswer(error.to_string()))?;
    let leaf = chain
        .first()
        .ok_or_else(|| AcmeError::BadAnswer("an empty chain".to_owned()))?;
    if !covers(leaf, name) {
        return Err(AcmeError::BadAnswer(
            "the certificate is not for this name".to_owned(),
        ));
    }
    let not_after =
        not_after(leaf).ok_or_else(|| AcmeError::BadAnswer("no end date".to_owned()))?;
    Ok(Issued {
        chain_pem,
        chain,
        key,
        not_after,
    })
}

/// Whether a certificate that ends at `not_after` is due for renewal at `now`.
pub fn renewal_due(not_after: u64, now: u64, renew_before: Duration) -> bool {
    not_after.saturating_sub(now) <= renew_before.as_secs()
}

/// What the certificate thread does next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenewStep {
    /// The installed certificate has time left: look again later.
    Wait,
    /// Store and install the certificate that an earlier order gave and that could not be
    /// kept then; no new order.
    KeepIssued,
    /// Order a new certificate.
    Order,
}

/// Whether an issued certificate can still be kept for `name` at `now`: it has not
/// ended and its leaf names `name`.
pub fn issued_usable(issued: &Issued, name: &str, now: u64) -> bool {
    issued.not_after > now && issued.chain.first().is_some_and(|leaf| covers(leaf, name))
}

/// The next step for `name`: keep `pending` (an issued certificate that was not kept yet)
/// while it is usable; else order when the installed certificate (its end,
/// `installed_not_after`) is missing or due for renewal; else wait.
pub fn renew_step(
    pending: Option<&Issued>,
    name: &str,
    installed_not_after: Option<u64>,
    now: u64,
    renew_before: Duration,
) -> RenewStep {
    if pending.is_some_and(|issued| issued_usable(issued, name, now)) {
        return RenewStep::KeepIssued;
    }
    match installed_not_after {
        Some(not_after) if !renewal_due(not_after, now, renew_before) => RenewStep::Wait,
        _ => RenewStep::Order,
    }
}

// ---- A small DER reader: the end date and the DNS names of a certificate. ----

/// One TLV: the tag, the content, and the bytes after it.
fn tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (length, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 3 || rest.len() < count {
            return None;
        }
        let length = rest[..count]
            .iter()
            .fold(0usize, |acc, byte| (acc << 8) | usize::from(*byte));
        (length, &rest[count..])
    };
    if rest.len() < length {
        return None;
    }
    Some((tag, &rest[..length], &rest[length..]))
}

/// The fields of the TBSCertificate after the version: serial, signature, issuer,
/// validity, subject, key, and the rest.
fn tbs_fields(certificate: &[u8]) -> Option<Vec<(u8, &[u8])>> {
    let (0x30, body, _) = tlv(certificate)? else {
        return None;
    };
    let (0x30, mut tbs, _) = tlv(body)? else {
        return None;
    };
    let mut fields = Vec::new();
    while !tbs.is_empty() {
        let (tag, content, rest) = tlv(tbs)?;
        fields.push((tag, content));
        tbs = rest;
    }
    if fields.first().is_some_and(|(tag, _)| *tag == 0xA0) {
        fields.remove(0);
    }
    Some(fields)
}

/// Days from 1970-01-01 to a civil date (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The number of ASCII digits `digits` (all checked to be digits by the caller).
fn number(digits: &[u8]) -> i64 {
    digits
        .iter()
        .fold(0, |acc, digit| acc * 10 + i64::from(digit - b'0'))
}

/// A UTCTime (`0x17`, `YYMMDDHHMMSSZ`) or GeneralizedTime (`0x18`,
/// `YYYYMMDDHHMMSSZ`) as Unix seconds. It reads bytes, never slices text, so a malformed
/// value of any length or with any byte is `None`, never a panic.
fn time_of(tag: u8, content: &[u8]) -> Option<u64> {
    let digits = content.strip_suffix(b"Z")?;
    if !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let (year, rest) = match (tag, digits.len()) {
        (0x17, 12) => {
            let year = number(&digits[..2]);
            (
                if year >= 50 { 1900 + year } else { 2000 + year },
                &digits[2..],
            )
        }
        (0x18, 14) => (number(&digits[..4]), &digits[4..]),
        _ => return None,
    };
    let field = |at: usize| Some(number(rest.get(at..at + 2)?));
    let (month, day, hour, minute, second) =
        (field(0)?, field(2)?, field(4)?, field(6)?, field(8)?);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let seconds = days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second;
    u64::try_from(seconds).ok()
}

/// The `notAfter` of a certificate DER, as Unix seconds.
pub fn not_after(certificate: &[u8]) -> Option<u64> {
    let fields = tbs_fields(certificate)?;
    let (0x30, validity) = *fields.get(3)? else {
        return None;
    };
    let (_, _, rest) = tlv(validity)?;
    let (tag, content, _) = tlv(rest)?;
    time_of(tag, content)
}

/// The DNS names of the subject alternative names of a certificate DER, lowercase.
pub fn dns_names(certificate: &[u8]) -> Vec<String> {
    const SAN: &[u8] = &[0x55, 0x1d, 0x11];
    let mut names = Vec::new();
    let Some(fields) = tbs_fields(certificate) else {
        return names;
    };
    let Some((_, extensions)) = fields.iter().find(|(tag, _)| *tag == 0xA3) else {
        return names;
    };
    let Some((0x30, mut list, _)) = tlv(extensions) else {
        return names;
    };
    while let Some((_, extension, rest)) = tlv(list) {
        list = rest;
        let Some((0x06, oid, mut inner)) = tlv(extension) else {
            continue;
        };
        if oid != SAN {
            continue;
        }
        if let Some((0x01, _, after)) = tlv(inner) {
            inner = after;
        }
        let Some((0x04, value, _)) = tlv(inner) else {
            continue;
        };
        let Some((0x30, mut general, _)) = tlv(value) else {
            continue;
        };
        while let Some((tag, content, rest)) = tlv(general) {
            general = rest;
            if tag == 0x82
                && let Ok(name) = std::str::from_utf8(content)
            {
                names.push(name.to_ascii_lowercase());
            }
        }
    }
    names
}

/// Whether a certificate DER names `name` among its DNS names.
pub fn covers(certificate: &[u8], name: &str) -> bool {
    dns_names(certificate)
        .iter()
        .any(|dns| dns.eq_ignore_ascii_case(name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};

    #[test]
    fn the_end_date_and_the_names_are_read() {
        let mut params =
            CertificateParams::new(vec!["k7m2q4x3ca.node.example.test".to_owned()]).unwrap();
        params.not_after = rcgen::date_time_ymd(2027, 2, 8);
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let der = params.self_signed(&key).unwrap().der().to_vec();
        // 2027-02-08T00:00:00Z.
        assert_eq!(not_after(&der), Some(1_802_044_800));
        assert_eq!(dns_names(&der), ["k7m2q4x3ca.node.example.test"]);
        assert!(covers(&der, "K7M2Q4X3CA.node.example.test"));
        assert!(!covers(&der, "aaaaaaaaaa.node.example.test"));
        // A GeneralizedTime after 2049.
        params.not_after = rcgen::date_time_ymd(2051, 1, 1);
        let der = params.self_signed(&key).unwrap().der().to_vec();
        assert_eq!(not_after(&der), Some(2_556_144_000));
        assert_eq!(not_after(b"\x30\x00"), None);
        assert!(dns_names(b"junk").is_empty());
    }

    #[test]
    fn a_malformed_date_is_none_and_never_panics() {
        for (tag, text) in [
            (0x17u8, "1\u{20ac}12345678Z"),
            (0x18, "202\u{20ac}12345678Z"),
            (0x17, "+61130120000Z"),
            (0x17, "2611301200Z"),
            (0x17, "261130120000"),
            (0x18, "2026113012000Z"),
            (0x17, "261330120000Z"),
            (0x17, ""),
            (0x05, "261130120000Z"),
        ] {
            assert_eq!(time_of(tag, text.as_bytes()), None, "{text}");
        }
        // 2026-11-30T12:00:00Z.
        assert_eq!(time_of(0x17, b"261130120000Z"), Some(1_796_040_000));
        assert_eq!(time_of(0x18, b"20261130120000Z"), Some(1_796_040_000));
    }

    #[test]
    fn the_urls_of_the_ca_are_on_the_directory_host_with_https() {
        let origin = CaOrigin::of("https://acme.example.test/directory", false).unwrap();
        for url in [
            "https://acme.example.test/acme/new-order",
            "https://ACME.example.test:443/acme/order/1",
            "https://acme.example.test",
        ] {
            assert!(origin.split(url).is_ok(), "{url}");
        }
        for url in [
            "https://other.example.test/acme/new-order",
            "https://acme.example.test.other.test/x",
            "https://acme.example.test:8443/x",
            "http://acme.example.test/x",
            "http://127.0.0.1:8080/acme/new-order",
            "http://localhost:8080/x",
            "http://[::1]:8080/x",
            "https://10.0.0.7/x",
            "https://192.168.1.1:443/x",
            "https://127.0.0.1/x",
            "https://[::1]/x",
            "https://[fd00::1]:443/x",
            "https://127.1/x",
            "https://0x7f000001/x",
            "https://acme.example.test/a b",
            "acme.example.test/x",
        ] {
            assert!(origin.split(url).is_err(), "{url}");
        }
        // The directory itself: https:// with a host name.
        for directory in [
            "https://10.0.0.7/directory",
            "https://[fd00::1]/directory",
            "http://acme.example.test/directory",
            "http://127.0.0.1:14000/directory",
        ] {
            assert!(CaOrigin::of(directory, false).is_err(), "{directory}");
        }
        assert!(CaOrigin::of("https://[::1]/directory", true).is_err());
        assert!(CaOrigin::of(LETS_ENCRYPT, false).is_ok());
        assert!(!AcmeOptions::new(LETS_ENCRYPT).loopback_test_ca);
    }

    #[test]
    fn the_test_ca_on_the_loopback_is_held_to_its_own_address_and_port() {
        let origin = CaOrigin::of("http://127.0.0.1:14000/directory", true).unwrap();
        assert!(origin.split("http://127.0.0.1:14000/acme/nonce").is_ok());
        for url in [
            "http://127.0.0.1:14001/acme/nonce",
            "http://localhost:14000/acme/nonce",
            "http://[::1]:14000/acme/nonce",
            "https://acme.example.test/acme/nonce",
        ] {
            assert!(origin.split(url).is_err(), "{url}");
        }
    }

    #[test]
    fn urls_split_into_destination_and_path() {
        let (destination, path) = split_url("https://ca.test/acme/new-order").unwrap();
        assert_eq!(destination.host_header(), "ca.test");
        assert_eq!(path, "/acme/new-order");
        let (destination, path) = split_url("http://127.0.0.1:4000/dir").unwrap();
        assert_eq!(destination.host_header(), "127.0.0.1:4000");
        assert_eq!(path, "/dir");
        assert!(split_url("http://ca.test/dir").is_err());
        assert!(split_url("ca.test/dir").is_err());
    }

    /// What the scripted CA answers: the status, extra headers, and the body.
    type Answer = (u16, Vec<(&'static str, String)>, String);

    /// A scripted CA on the loopback: it answers by method and path, records each
    /// request, and checks no signature. A second listener (`another`) counts the
    /// connections that reach it.
    struct ScriptedCa {
        base: String,
        requests: Arc<Mutex<Vec<String>>>,
        another_hits: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl ScriptedCa {
        /// `answer(base, another, "METHOD /path")` gives each answer.
        fn start(answer: impl Fn(&str, &str, &str) -> Answer + Send + 'static) -> Self {
            use std::io::{Read, Write};
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let elsewhere = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let another = format!("http://{}", elsewhere.local_addr().unwrap());
            let requests = Arc::new(Mutex::new(Vec::new()));
            let another_hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let hits = Arc::clone(&another_hits);
            std::thread::spawn(move || {
                for stream in elsewhere.incoming() {
                    drop(stream);
                    hits.fetch_add(1, Ordering::SeqCst);
                }
            });
            let (thread_base, log) = (base.clone(), Arc::clone(&requests));
            std::thread::spawn(move || {
                for mut stream in listener.incoming().flatten() {
                    let mut head = Vec::new();
                    let mut byte = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") {
                        match stream.read(&mut byte) {
                            Ok(1) => head.push(byte[0]),
                            _ => break,
                        }
                    }
                    let text = String::from_utf8_lossy(&head).into_owned();
                    let length = text
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            if name.eq_ignore_ascii_case("content-length") {
                                value.trim().parse::<usize>().ok()
                            } else {
                                None
                            }
                        })
                        .unwrap_or(0);
                    let mut request_body = vec![0u8; length];
                    let _ = stream.read_exact(&mut request_body);
                    let line = text.lines().next().unwrap_or_default();
                    let mut parts = line.split(' ');
                    let request = format!(
                        "{} {}",
                        parts.next().unwrap_or_default(),
                        parts.next().unwrap_or_default()
                    );
                    let count = {
                        let mut log = log.lock().unwrap();
                        log.push(request.clone());
                        log.len()
                    };
                    let (status, headers, body) =
                        answer(thread_base.as_str(), another.as_str(), request.as_str());
                    let mut out = format!(
                        "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\
                         Replay-Nonce: n-{count}\r\nContent-Type: application/json\r\n",
                        body.len()
                    );
                    for (name, value) in headers {
                        out.push_str(&format!("{name}: {value}\r\n"));
                    }
                    out.push_str("\r\n");
                    out.push_str(&body);
                    let _ = stream.write_all(out.as_bytes());
                }
            });
            Self {
                base,
                requests,
                another_hits,
            }
        }

        /// An order for the public name against this CA, with a new node directory.
        fn obtain(&self) -> Result<Issued, AcmeError> {
            use crate::net::sealed_key::CONNECT_INFO;
            let dir = tempfile::tempdir().unwrap();
            let seal = SealKey::derive(&[9u8; 32], CONNECT_INFO).unwrap();
            let mut options = AcmeOptions::new(&format!("{}/directory", self.base));
            options.loopback_test_ca = true;
            options.poll_every = Duration::from_millis(10);
            options.poll_tries = 3;
            obtain(
                &options,
                dir.path(),
                &seal,
                "aaaaaaaaaa.node.example.test",
                &Challenges::default(),
                &AtomicBool::new(false),
            )
        }

        fn requests(&self) -> Vec<String> {
            self.requests.lock().unwrap().clone()
        }

        /// The order was refused as an answer of the CA, and nothing reached `another`.
        fn assert_refused(&self, result: Result<Issued, AcmeError>) {
            match result {
                Err(AcmeError::BadAnswer(why)) => assert!(
                    why.contains("not on the CA's own host") || why.contains("not a URL of the CA"),
                    "{why}"
                ),
                other => panic!("not refused: {other:?}"),
            }
            assert_eq!(self.another_hits.load(Ordering::SeqCst), 0);
        }
    }

    /// The answers of a CA that names its own URLs; the order has no authorization, and
    /// `finalize` is not there (404).
    fn own_urls(base: &str, request: &str) -> Answer {
        match request {
            "GET /directory" => (
                200,
                vec![],
                json!({
                    "newNonce": format!("{base}/nonce"),
                    "newAccount": format!("{base}/acct"),
                    "newOrder": format!("{base}/order"),
                })
                .to_string(),
            ),
            "GET /nonce" => (200, vec![], String::new()),
            "POST /acct" => (
                201,
                vec![("Location", format!("{base}/acct/1"))],
                "{}".to_owned(),
            ),
            "POST /order" => (
                201,
                vec![("Location", format!("{base}/order/1"))],
                json!({
                    "status": "pending",
                    "authorizations": [],
                    "finalize": format!("{base}/finalize"),
                })
                .to_string(),
            ),
            _ => (404, vec![], String::new()),
        }
    }

    /// The directory of [`own_urls`] with `newOrder` set to `new_order(base, another)`.
    fn directory_naming(base: &str, new_order: &str) -> Answer {
        (
            200,
            vec![],
            json!({
                "newNonce": format!("{base}/nonce"),
                "newAccount": format!("{base}/acct"),
                "newOrder": new_order,
            })
            .to_string(),
        )
    }

    #[test]
    fn a_ca_that_names_its_own_urls_is_followed_to_finalize() {
        let ca = ScriptedCa::start(|base, _, request| own_urls(base, request));
        assert!(matches!(
            ca.obtain(),
            Err(AcmeError::Refused { status: 404, .. })
        ));
        assert_eq!(
            ca.requests(),
            [
                "GET /directory",
                "GET /nonce",
                "POST /acct",
                "POST /order",
                "POST /finalize"
            ]
        );
    }

    #[test]
    fn a_directory_that_names_another_host_is_refused_before_any_request_goes_there() {
        let ca = ScriptedCa::start(|base, another, request| match request {
            "GET /directory" => directory_naming(base, &format!("{another}/order")),
            _ => own_urls(base, request),
        });
        ca.assert_refused(ca.obtain());
        assert_eq!(ca.requests(), ["GET /directory"]);
    }

    #[test]
    fn a_directory_that_names_an_ip_address_or_plain_http_is_refused() {
        for named in [
            "https://10.0.0.7/acme/new-order",
            "https://192.168.1.1:443/acme/new-order",
            "https://[fd00::1]/acme/new-order",
            "https://[::ffff:127.0.0.1]/acme/new-order",
            "http://acme.example.test/acme/new-order",
        ] {
            let ca = ScriptedCa::start(move |base, _, request| match request {
                "GET /directory" => directory_naming(base, named),
                _ => own_urls(base, request),
            });
            ca.assert_refused(ca.obtain());
            assert_eq!(ca.requests(), ["GET /directory"], "{named}");
        }
    }

    #[test]
    fn a_location_on_another_host_is_refused_before_any_request_goes_there() {
        // The account's Location (the kid).
        let ca = ScriptedCa::start(|base, another, request| match request {
            "POST /acct" => (
                201,
                vec![("Location", format!("{another}/acct/1"))],
                "{}".to_owned(),
            ),
            _ => own_urls(base, request),
        });
        ca.assert_refused(ca.obtain());
        assert_eq!(
            ca.requests(),
            ["GET /directory", "GET /nonce", "POST /acct"]
        );
        // The order's Location, and its finalize URL.
        for (location, finalize) in [(true, false), (false, true)] {
            let ca = ScriptedCa::start(move |base, another, request| match request {
                "POST /order" => (
                    201,
                    vec![(
                        "Location",
                        format!("{}/order/1", if location { another } else { base }),
                    )],
                    json!({
                        "status": "pending",
                        "authorizations": [],
                        "finalize": format!("{}/finalize", if finalize { another } else { base }),
                    })
                    .to_string(),
                ),
                _ => own_urls(base, request),
            });
            ca.assert_refused(ca.obtain());
            assert_eq!(
                ca.requests(),
                ["GET /directory", "GET /nonce", "POST /acct", "POST /order"]
            );
        }
    }

    #[test]
    fn a_failed_store_is_retried_with_the_issued_certificate_without_a_new_order() {
        use crate::net::sealed_key::CONNECT_INFO;
        let name = "aaaaaaaaaa.node.example.test";
        let mut params = CertificateParams::new(vec![name.to_owned()]).unwrap();
        params.not_after = rcgen::date_time_ymd(2027, 2, 8);
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = params.self_signed(&key).unwrap();
        let der = cert.der().to_vec();
        let issued = Issued {
            chain_pem: cert.pem(),
            chain: vec![der.clone()],
            key: Zeroizing::new(key.serialize_der()),
            not_after: not_after(&der).unwrap(),
        };
        let end = issued.not_after;
        let now = end - 60 * 86_400;
        let seal = SealKey::derive(&[9u8; 32], CONNECT_INFO).unwrap();
        // The store fails: the node directory is a file.
        let dir = tempfile::tempdir().unwrap();
        let blocked = dir.path().join("node");
        std::fs::write(&blocked, b"not a directory").unwrap();
        assert!(
            public_cert::store_public(&blocked, &issued.chain_pem, &issued.key, &seal).is_err()
        );
        // The next step keeps the issued certificate: no new order, with or without an
        // installed one, and also when that one is due.
        for installed in [None, Some(end), Some(now + 86_400)] {
            assert_eq!(
                renew_step(Some(&issued), name, installed, now, RENEW_BEFORE),
                RenewStep::KeepIssued,
                "{installed:?}"
            );
        }
        // The retry stores it.
        let node = dir.path().join("fixed");
        public_cert::store_public(&node, &issued.chain_pem, &issued.key, &seal).unwrap();
        let stored = public_cert::load_public(&node, &seal).unwrap().unwrap();
        assert_eq!(stored.chain, issued.chain);
        // An issued certificate that has ended, or that is for another name, is not kept:
        // a new order.
        assert_eq!(
            renew_step(Some(&issued), name, None, end, RENEW_BEFORE),
            RenewStep::Order
        );
        assert_eq!(
            renew_step(
                Some(&issued),
                "bbbbbbbbbb.node.example.test",
                None,
                now,
                RENEW_BEFORE
            ),
            RenewStep::Order
        );
        // Without one: wait while the installed certificate has time left, else order.
        assert_eq!(
            renew_step(None, name, Some(end), now, RENEW_BEFORE),
            RenewStep::Wait
        );
        assert_eq!(
            renew_step(None, name, Some(now + 86_400), now, RENEW_BEFORE),
            RenewStep::Order
        );
        assert_eq!(
            renew_step(None, name, None, now, RENEW_BEFORE),
            RenewStep::Order
        );
    }

    #[test]
    fn the_account_key_is_sealed_and_a_key_that_does_not_open_is_made_again() {
        use crate::net::sealed_key::CONNECT_INFO;
        let dir = tempfile::tempdir().unwrap();
        let seal = SealKey::derive(&[9u8; 32], CONNECT_INFO).unwrap();
        let first = AccountKey::load_or_make(dir.path(), &seal).unwrap();
        let again = AccountKey::load_or_make(dir.path(), &seal).unwrap();
        assert_eq!(first.thumbprint(), again.thumbprint());
        let path = dir
            .path()
            .join(public_cert::CONNECT_DIR)
            .join(ACCOUNT_KEY_FILE);
        let stored = std::fs::read(&path).unwrap();
        assert!(AccountKey::from_pkcs8(&stored).is_err(), "not plain PKCS#8");
        let other = SealKey::derive(&[10u8; 32], CONNECT_INFO).unwrap();
        let replaced = AccountKey::load_or_make(dir.path(), &other).unwrap();
        assert_ne!(replaced.thumbprint(), first.thumbprint());
    }

    #[test]
    fn renewal_starts_thirty_days_before_the_end() {
        let end = 1_802_044_800;
        let day = 86_400;
        assert!(!renewal_due(end, end - 31 * day, RENEW_BEFORE));
        assert!(renewal_due(end, end - 30 * day, RENEW_BEFORE));
        assert!(renewal_due(end, end + day, RENEW_BEFORE));
    }

    #[test]
    fn the_jws_verifies_and_the_thumbprint_is_rfc_7638() {
        let (key, _) = AccountKey::generate().unwrap();
        let body = key
            .sign(
                "https://ca.test/new-acct",
                "nonce-1",
                None,
                Some(&json!({"a": 1})),
            )
            .unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        let decode = |text: &str| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(text)
                .unwrap()
        };
        let protected: Value =
            serde_json::from_slice(&decode(body["protected"].as_str().unwrap())).unwrap();
        assert_eq!(protected["alg"], "ES256");
        assert_eq!(protected["nonce"], "nonce-1");
        assert_eq!(protected["url"], "https://ca.test/new-acct");
        assert_eq!(protected["jwk"], key.jwk());
        let signature = decode(body["signature"].as_str().unwrap());
        assert_eq!(signature.len(), 64, "ES256 is r || s");
        let input = format!(
            "{}.{}",
            body["protected"].as_str().unwrap(),
            body["payload"].as_str().unwrap()
        );
        let mut point = vec![4u8];
        point.extend(decode(protected["jwk"]["x"].as_str().unwrap()));
        point.extend(decode(protected["jwk"]["y"].as_str().unwrap()));
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &point)
            .verify(input.as_bytes(), &signature)
            .expect("the signature verifies");
        // With a kid: no jwk; POST-as-GET: an empty payload.
        let body = key
            .sign(
                "https://ca.test/o/1",
                "n2",
                Some("https://ca.test/a/1"),
                None,
            )
            .unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["payload"], "");
        let protected: Value =
            serde_json::from_slice(&decode(body["protected"].as_str().unwrap())).unwrap();
        assert_eq!(protected["kid"], "https://ca.test/a/1");
        assert!(protected.get("jwk").is_none());
        // RFC 7638: SHA-256 of the members in lexical order, no spaces.
        let jwk = key.jwk();
        let input = format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
            jwk["x"].as_str().unwrap(),
            jwk["y"].as_str().unwrap()
        );
        assert_eq!(
            key.thumbprint(),
            b64u(ring::digest::digest(&ring::digest::SHA256, input.as_bytes()).as_ref())
        );
        assert_eq!(
            key.key_authorization("tok"),
            format!("tok.{}", key.thumbprint())
        );
    }

    #[test]
    fn only_the_pending_token_is_answered() {
        let challenges = Challenges::default();
        let get = |token: &str| {
            format!("GET /.well-known/acme-challenge/{token} HTTP/1.1\r\nHost: x\r\n\r\n")
                .into_bytes()
        };
        assert_eq!(http01_answer(&challenges, &get("abc")), NOT_FOUND);
        challenges.set("abc_-1", "abc_-1.thumb");
        let answer = String::from_utf8(http01_answer(&challenges, &get("abc_-1"))).unwrap();
        assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(answer.ends_with("\r\n\r\nabc_-1.thumb"));
        assert_eq!(http01_answer(&challenges, &get("other")), NOT_FOUND);
        assert_eq!(
            http01_answer(
                &challenges,
                b"POST /.well-known/acme-challenge/abc_-1 HTTP/1.1\r\n\r\n"
            ),
            NOT_FOUND
        );
        assert_eq!(
            http01_answer(
                &challenges,
                b"GET /.well-known/acme-challenge/abc_-1 HTTP/1.0\r\n\r\n"
            ),
            NOT_FOUND
        );
        assert_eq!(
            http01_answer(&challenges, b"GET /v1/me HTTP/1.1\r\n\r\n"),
            NOT_FOUND
        );
        assert_eq!(http01_answer(&challenges, &get("a.b")), NOT_FOUND);
        challenges.clear();
        assert_eq!(http01_answer(&challenges, &get("abc_-1")), NOT_FOUND);
    }

    #[test]
    fn a_csr_names_only_the_public_name() {
        let (der, key) = csr("k7m2q4x3ca.node.example.test").unwrap();
        assert!(der.len() > 100);
        assert!(KeyPair::try_from(key.as_slice()).is_ok());
        let text = String::from_utf8_lossy(&der);
        assert!(text.contains("k7m2q4x3ca.node.example.test"));
        assert!(!text.contains("rcgen"));
    }
}
