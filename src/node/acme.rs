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
//! - The account key is ECDSA P-256 (`ring`), kept as PKCS#8 in
//!   `<node dir>/connect/acme-account.der`, mode 0600. Requests are flattened JWS with
//!   `ES256` (RFC 7518 3.4: `r || s`), the `jwk` for `newAccount` and the `kid` after it,
//!   a fresh `Replay-Nonce` for each request, one retry after `badNonce`, and POST-as-GET
//!   for reads (RFC 8555 6.3).
//! - The key authorization is `<token>.<b64u(SHA-256 of the JWK thumbprint input)>`
//!   (RFC 7638 with the members `crv`, `kty`, `x`, `y` in that order).
//! - The certificate key is a new ECDSA P-256 key for each order (`rcgen`), the CSR names
//!   the public name only. The chain and the key go into the node directory through
//!   `super::public_cert::store_public`, mode 0600.
//! - Renewal: when 30 days or less are left ([`renewal_due`]).
//! - The directory URL is configuration ([`AcmeOptions::directory`]): the product uses
//!   Let's Encrypt (or `APASSY_CONNECT_ACME_DIRECTORY`), tests a fake CA on the loopback.
//!
//! No value of this module is a secret of the vault. The account key and the certificate
//! key are secrets of the node and stay in its directory.

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

/// Let's Encrypt's production directory.
pub const LETS_ENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";
/// The setting that points the node at another ACME directory (the staging CA).
pub const DIRECTORY_ENV: &str = "APASSY_CONNECT_ACME_DIRECTORY";
/// Renew when this much is left (plan s7 M4: 30 days).
pub const RENEW_BEFORE: Duration = Duration::from_secs(30 * 86_400);
/// The file of the ACME account key in the Connect directory of the node.
pub const ACCOUNT_KEY_FILE: &str = "acme-account.der";
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
    /// The directory URL: `https://…`, or `http://` on the loopback (tests).
    pub directory: String,
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

    /// The key of `node_dir`, made and written (mode 0600) at the first order.
    pub fn load_or_make(node_dir: &Path) -> Result<Self, AcmeError> {
        let dir = node_dir.join(public_cert::CONNECT_DIR);
        let path = dir.join(ACCOUNT_KEY_FILE);
        let local =
            |error: std::io::Error| AcmeError::Local(format!("the ACME account key file: {error}"));
        if let Some(pkcs8) = public_cert::read_private(&path).map_err(local)? {
            return Self::from_pkcs8(&pkcs8);
        }
        let (key, pkcs8) = Self::generate()?;
        public_cert::ensure_private_dir(&dir).map_err(local)?;
        public_cert::write_private(&path, &pkcs8).map_err(local)?;
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

/// `https://host[:port]/path` → the destination and the path (`/` at least).
fn split_url(url: &str) -> Result<(DestinationUrl, String), AcmeError> {
    let bad = || AcmeError::BadAnswer(format!("not a URL of the CA: {url}"));
    let (scheme, rest) = url.split_once("://").ok_or_else(bad)?;
    let (authority, path) = match rest.find('/') {
        Some(at) => (&rest[..at], &rest[at..]),
        None => (rest, "/"),
    };
    let destination = parse_destination(&format!("{scheme}://{authority}")).map_err(|_| bad())?;
    if !path.bytes().all(|b| (0x21..0x7f).contains(&b)) {
        return Err(bad());
    }
    Ok((destination, path.to_owned()))
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

fn exchange(
    tls: &TlsClient,
    url: &str,
    method: Method,
    body: Option<&[u8]>,
    accept: Option<&str>,
) -> Result<HttpResponse, AcmeError> {
    let (destination, path) = split_url(url)?;
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
        stop: &'a AtomicBool,
    ) -> Result<Session<'a>, AcmeError> {
        let tls = match &options.tls {
            Some(tls) => tls.clone(),
            None => TlsClient::platform()
                .map_err(|error| AcmeError::Local(format!("TLS is not available: {error}")))?,
        };
        let response = exchange(&tls, &options.directory, Method::Get, None, None)?;
        if response.status != 200 {
            return Err(AcmeError::Unreachable(format!(
                "the directory answered {}",
                response.status
            )));
        }
        let directory: Directory = json_of(&response)?;
        Ok(Session {
            options,
            tls,
            key: AccountKey::load_or_make(node_dir)?,
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
            let response = exchange(&self.tls, url, Method::Post, Some(&body), accept)?;
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
    name: &str,
    challenges: &Challenges,
    stop: &AtomicBool,
) -> Result<Issued, AcmeError> {
    let result = obtain_inner(options, node_dir, name, challenges, stop);
    challenges.clear();
    result
}

fn obtain_inner(
    options: &AcmeOptions,
    node_dir: &Path,
    name: &str,
    challenges: &Challenges,
    stop: &AtomicBool,
) -> Result<Issued, AcmeError> {
    let mut session = Session::open(options, node_dir, stop)?;
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

fn time_of(tag: u8, content: &[u8]) -> Option<u64> {
    let text = std::str::from_utf8(content).ok()?;
    let text = text.strip_suffix('Z')?;
    let (year, rest) = match tag {
        0x17 if text.len() == 12 => {
            let year: i64 = text[..2].parse().ok()?;
            (
                if year >= 50 { 1900 + year } else { 2000 + year },
                &text[2..],
            )
        }
        0x18 if text.len() == 14 => (text[..4].parse().ok()?, &text[4..]),
        _ => return None,
    };
    if !rest.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let field = |at: usize| rest[at..at + 2].parse::<i64>().ok();
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
}
