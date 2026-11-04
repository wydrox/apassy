//! AWS Signature Version 4 (contract private-sharing-v1 section 7, plan s6 unit C1).
//!
//! One implementation for every place that signs or checks a SigV4 request:
//!
//! - the key holder's own AWS calls (STS here, IAM in unit J1): [`sign_request`];
//! - the signing proxies (units E1 and E2): [`parse_authorization`], [`is_presigned`],
//!   [`canonical_uri`], [`canonical_request`], [`verify`], [`sign_canonical`], and
//!   [`replace_signature`];
//! - the sign endpoint of the team host (unit H): [`parse_canonical_request`],
//!   [`check_payload_hash`], [`check_amz_date`], and [`sign_canonical`].
//!
//! Only the `Authorization: AWS4-HMAC-SHA256 …` header form is signed (S6-8). A presigned
//! URL is a credential that anyone who sees it can use ([`is_presigned`]), and a
//! `STREAMING-*` payload signs each chunk with a key that the signer would have to hand
//! out ([`check_payload_hash`]); the callers refuse both with the reason of
//! [`SigV4Error::reason`].
//!
//! HMAC-SHA256 and SHA-256 come from `ring`. The signing key and the intermediate keys
//! are kept in `Zeroizing` buffers; the key state inside `ring` is not erased (best
//! effort, as everywhere in the crate). Nothing here logs, and no error holds a value of
//! the request.

use std::fmt;

use ring::{digest, hmac};
use zeroize::Zeroizing;

/// The algorithm name of the `Authorization` header and of the string to sign.
pub const ALGORITHM: &str = "AWS4-HMAC-SHA256";
/// The SHA-256 of an empty payload, in lowercase hex.
pub const EMPTY_PAYLOAD_SHA256: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
/// The payload hash of a request whose body is not signed (S3).
pub const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";
/// The prefix of the chunked payload hashes (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`, …).
pub const STREAMING_PREFIX: &str = "STREAMING-";
/// The length of a signature in lowercase hex.
pub const SIGNATURE_HEX_BYTES: usize = 64;
/// Most signed headers of one request. A real SDK request signs fewer than ten.
pub const MAX_SIGNED_HEADERS: usize = 64;
/// The query keys that make a URL presigned (S6-8). Compared without case.
pub const PRESIGN_QUERY_KEYS: [&str; 3] =
    ["X-Amz-Signature", "X-Amz-Credential", "X-Amz-Algorithm"];
/// The services whose canonical URI is the path as sent, encoded once and not
/// normalized (S3 and its variants). Every other service encodes the path again and
/// removes dot segments and empty segments.
pub const SINGLE_ENCODED_SERVICES: [&str; 4] =
    ["s3", "s3-object-lambda", "s3-outposts", "s3express"];

const TERMINATOR: &str = "aws4_request";
const MAX_ACCESS_KEY_ID_BYTES: usize = 128;
const MAX_SCOPE_NAME_BYTES: usize = 32;
const MAX_METHOD_BYTES: usize = 16;

/// Why a SigV4 request was not signed or not verified. No variant holds a value of the
/// request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigV4Error {
    /// The `Authorization` value is not `AWS4-HMAC-SHA256 Credential=…, SignedHeaders=…,
    /// Signature=…` with a valid credential scope and a 64-hex signature.
    Authorization,
    /// The query has `X-Amz-Signature`, `X-Amz-Credential`, or `X-Amz-Algorithm`.
    Presigned,
    /// The payload hash is `STREAMING-*`, an `UNSIGNED-PAYLOAD` with a body, not 64
    /// lowercase hex, or differs from a signed `x-amz-content-sha256`.
    Payload,
    /// The date, region, or service of the scope is not valid.
    Scope,
    /// A signed header name is not lowercase, sorted, and distinct, a signed header is
    /// missing from the request or has a control character, or `host` is not signed.
    Headers,
    /// The path or the query is not valid: no leading `/`, a byte outside printable
    /// ASCII, or a broken percent escape.
    Uri,
    /// `x-amz-date` is missing, not `YYYYMMDDTHHMMSSZ`, or on another day than the scope.
    Date,
    /// The method is not 1 to 16 uppercase letters.
    Method,
    /// The canonical request text does not have the lines of contract section 7.2.
    CanonicalRequest,
}

impl SigV4Error {
    /// A sentence for the owner or for the program that sent the request. The texts of
    /// [`Self::Presigned`], [`Self::Payload`], and [`Self::Date`] are the `sign_refused`
    /// messages of contract section 7.2.
    pub fn reason(self) -> &'static str {
        match self {
            Self::Authorization => "The Authorization header is not an AWS4-HMAC-SHA256 signature.",
            Self::Presigned => "Presigned URLs are not signed.",
            Self::Payload => "This payload hash is not signed.",
            Self::Scope => "The signing scope is not valid.",
            Self::Headers => "The signed headers do not match the request.",
            Self::Uri => "The request path or query is not valid.",
            Self::Date => "The request date does not match.",
            Self::Method => "The request method is not valid.",
            Self::CanonicalRequest => "The canonical request is not valid.",
        }
    }
}

impl fmt::Display for SigV4Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason())
    }
}

impl std::error::Error for SigV4Error {}

/// The credential scope: `<date>/<region>/<service>/aws4_request`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    date: String,
    region: String,
    service: String,
}

impl Scope {
    /// `date` is `YYYYMMDD` (a real calendar day); `region` and `service` are
    /// `[a-z0-9-]{1,32}` (contract section 7.2).
    pub fn new(date: &str, region: &str, service: &str) -> Result<Self, SigV4Error> {
        if !is_scope_date(date) || !is_scope_name(region) || !is_scope_name(service) {
            return Err(SigV4Error::Scope);
        }
        Ok(Self {
            date: date.to_owned(),
            region: region.to_owned(),
            service: service.to_owned(),
        })
    }

    pub fn date(&self) -> &str {
        &self.date
    }

    pub fn region(&self) -> &str {
        &self.region
    }

    pub fn service(&self) -> &str {
        &self.service
    }

    /// `<date>/<region>/<service>/aws4_request`.
    pub fn credential_scope(&self) -> String {
        format!(
            "{}/{}/{}/{TERMINATOR}",
            self.date, self.region, self.service
        )
    }
}

/// The derived signing key of one secret and one scope. `Debug` is redacted and the
/// bytes are erased on drop.
pub struct SigningKey(Zeroizing<[u8; 32]>);

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SigningKey([redacted])")
    }
}

impl SigningKey {
    /// The key bytes, for a test that compares them with a published vector.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Zeroizing<[u8; 32]> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&key, data);
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(tag.as_ref());
    out
}

/// `kSigning` of the SigV4 specification: HMAC-SHA256 chained over the date, the
/// region, the service, and `aws4_request`, starting from `"AWS4" + secret`.
pub fn signing_key(secret: &str, scope: &Scope) -> SigningKey {
    let mut seed = Zeroizing::new(Vec::with_capacity(4 + secret.len()));
    seed.extend_from_slice(b"AWS4");
    seed.extend_from_slice(secret.as_bytes());
    let date = hmac_sha256(&seed, scope.date.as_bytes());
    let region = hmac_sha256(&date[..], scope.region.as_bytes());
    let service = hmac_sha256(&region[..], scope.service.as_bytes());
    SigningKey(hmac_sha256(&service[..], TERMINATOR.as_bytes()))
}

/// `AWS4-HMAC-SHA256\n<amz_date>\n<credential scope>\n<hex(SHA-256(canonical_request))>`.
pub fn string_to_sign(amz_date: &str, scope: &Scope, canonical_request: &str) -> String {
    format!(
        "{ALGORITHM}\n{amz_date}\n{}\n{}",
        scope.credential_scope(),
        sha256_hex(canonical_request.as_bytes())
    )
}

/// HMAC-SHA256 of `string_to_sign` with the signing key, in lowercase hex.
pub fn signature(key: &SigningKey, string_to_sign: &str) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, &key.0[..]);
    hex_lower(hmac::sign(&key, string_to_sign.as_bytes()).as_ref())
}

/// Whether `signature_hex` (64 lowercase hex) is the signature of `string_to_sign`. The
/// comparison takes the same time for every wrong signature (`ring::hmac::verify`).
pub fn verify_signature(key: &SigningKey, string_to_sign: &str, signature_hex: &str) -> bool {
    let Some(tag) = decode_signature(signature_hex) else {
        return false;
    };
    let key = hmac::Key::new(hmac::HMAC_SHA256, &key.0[..]);
    hmac::verify(&key, string_to_sign.as_bytes(), &tag).is_ok()
}

/// The signature of `canonical_request` with `secret` over `scope`: the answer of the
/// sign endpoint (contract section 7.2), and the new `Signature=` value of a proxy that
/// verified the placeholder signature (section 7.1).
pub fn sign_canonical(
    secret: &str,
    scope: &Scope,
    amz_date: &str,
    canonical_request: &str,
) -> String {
    signature(
        &signing_key(secret, scope),
        &string_to_sign(amz_date, scope, canonical_request),
    )
}

/// Whether the signature of `authorization` is the one that `secret` makes for
/// `canonical_request` at `amz_date`. A proxy calls it with the placeholder: it proves
/// that the program signed this canonical request (section 7).
pub fn verify(
    secret: &str,
    authorization: &Authorization,
    amz_date: &str,
    canonical_request: &str,
) -> bool {
    let key = signing_key(secret, &authorization.scope);
    verify_signature(
        &key,
        &string_to_sign(amz_date, &authorization.scope, canonical_request),
        &authorization.signature,
    )
}

/// A parsed `Authorization: AWS4-HMAC-SHA256 …` value. `Debug` hides the signature.
#[derive(Clone, PartialEq, Eq)]
pub struct Authorization {
    /// The access key id of the credential (not a secret).
    pub access_key_id: String,
    pub scope: Scope,
    /// The signed header names: lowercase, sorted, distinct.
    pub signed_headers: Vec<String>,
    /// 64 lowercase hex.
    pub signature: String,
}

impl fmt::Debug for Authorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Authorization")
            .field("access_key_id", &self.access_key_id)
            .field("scope", &self.scope)
            .field("signed_headers", &self.signed_headers)
            .field("signature", &"[redacted]")
            .finish()
    }
}

/// Parse `AWS4-HMAC-SHA256 Credential=<id>/<date>/<region>/<service>/aws4_request,
/// SignedHeaders=<names>, Signature=<hex>`. The three parts may come in any order,
/// separated by `,` with optional spaces; each exactly once; nothing else.
pub fn parse_authorization(value: &str) -> Result<Authorization, SigV4Error> {
    let rest = value
        .strip_prefix(ALGORITHM)
        .and_then(|rest| rest.strip_prefix(' '))
        .ok_or(SigV4Error::Authorization)?
        .trim_start_matches(' ');
    let mut credential = None;
    let mut signed = None;
    let mut signature = None;
    for part in rest.split(',') {
        let (name, field) = part
            .trim_matches(' ')
            .split_once('=')
            .ok_or(SigV4Error::Authorization)?;
        let slot = match name {
            "Credential" => &mut credential,
            "SignedHeaders" => &mut signed,
            "Signature" => &mut signature,
            _ => return Err(SigV4Error::Authorization),
        };
        if slot.replace(field).is_some() {
            return Err(SigV4Error::Authorization);
        }
    }
    let (Some(credential), Some(signed), Some(signature)) = (credential, signed, signature) else {
        return Err(SigV4Error::Authorization);
    };
    let mut pieces = credential.split('/');
    let (Some(id), Some(date), Some(region), Some(service), Some(TERMINATOR), None) = (
        pieces.next(),
        pieces.next(),
        pieces.next(),
        pieces.next(),
        pieces.next(),
        pieces.next(),
    ) else {
        return Err(SigV4Error::Authorization);
    };
    if !is_access_key_id(id) || !is_signature_hex(signature) {
        return Err(SigV4Error::Authorization);
    }
    let scope = Scope::new(date, region, service).map_err(|_| SigV4Error::Authorization)?;
    let names: Vec<&str> = signed.split(';').collect();
    check_signed_header_names(&names).map_err(|_| SigV4Error::Authorization)?;
    Ok(Authorization {
        access_key_id: id.to_owned(),
        scope,
        signed_headers: names.into_iter().map(str::to_owned).collect(),
        signature: signature.to_owned(),
    })
}

/// `value` with its `Signature=` value replaced by `signature_hex`; every other byte
/// stays as it was, so the header keeps its length (contract section 7).
pub fn replace_signature(value: &str, signature_hex: &str) -> Result<String, SigV4Error> {
    parse_authorization(value)?;
    if !is_signature_hex(signature_hex) {
        return Err(SigV4Error::Authorization);
    }
    // After the parse, `Signature=` occurs once: the credential and the header names
    // cannot hold `=`.
    let start = value
        .find("Signature=")
        .map(|at| at + "Signature=".len())
        .ok_or(SigV4Error::Authorization)?;
    let mut out = String::with_capacity(value.len());
    out.push_str(&value[..start]);
    out.push_str(signature_hex);
    out.push_str(&value[start + SIGNATURE_HEX_BYTES..]);
    Ok(out)
}

/// Whether the query makes the URL a presigned one: a key `X-Amz-Signature`,
/// `X-Amz-Credential`, or `X-Amz-Algorithm`, percent-decoded and in any case. Such a
/// request is refused, never signed (S6-8).
pub fn is_presigned(query: &str) -> bool {
    query.split('&').any(|pair| {
        let name = pair.split_once('=').map_or(pair, |(name, _)| name);
        let decoded = percent_decode(name).unwrap_or_else(|_| name.as_bytes().to_vec());
        PRESIGN_QUERY_KEYS
            .iter()
            .any(|key| decoded.eq_ignore_ascii_case(key.as_bytes()))
    })
}

/// The canonical URI of a request path as it went over the wire (percent-encoded, no
/// query). For S3 ([`SINGLE_ENCODED_SERVICES`]) that is the path as it is. For every
/// other service the dot segments and the empty segments are removed and the path is
/// URI-encoded once more (`%` becomes `%25`), as the AWS SDKs and AWS itself compute it.
pub fn canonical_uri(path: &str, service: &str) -> Result<String, SigV4Error> {
    if !path.starts_with('/') || !is_graphic(path) || path.contains(['?', '#']) {
        return Err(SigV4Error::Uri);
    }
    if SINGLE_ENCODED_SERVICES.contains(&service) {
        return Ok(path.to_owned());
    }
    let mut kept: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                kept.pop();
            }
            _ => kept.push(segment),
        }
    }
    let mut out = String::with_capacity(path.len() + 16);
    out.push('/');
    for (index, segment) in kept.iter().enumerate() {
        if index > 0 {
            out.push('/');
        }
        uri_encode_into(&mut out, segment.as_bytes(), true);
    }
    if path.ends_with('/') && !kept.is_empty() {
        out.push('/');
    }
    Ok(out)
}

/// The canonical query of a query string as it went over the wire (without `?`): each
/// name and value percent-decoded and URI-encoded again (RFC 3986 unreserved bytes
/// stay, everything else is `%XX` in uppercase), sorted by name and then by value, and
/// joined as `name=value` with `&`. An empty pair or an empty name is refused.
pub fn canonical_query(query: &str) -> Result<String, SigV4Error> {
    if query.is_empty() {
        return Ok(String::new());
    }
    if !is_graphic(query) || query.contains('#') {
        return Err(SigV4Error::Uri);
    }
    let mut pairs: Vec<(String, String)> = Vec::new();
    for pair in query.split('&') {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        if name.is_empty() {
            return Err(SigV4Error::Uri);
        }
        pairs.push((
            uri_encode(&percent_decode(name)?, true),
            uri_encode(&percent_decode(value)?, true),
        ));
    }
    pairs.sort();
    let mut out = String::with_capacity(query.len() + 16);
    for (index, (name, value)) in pairs.iter().enumerate() {
        if index > 0 {
            out.push('&');
        }
        out.push_str(name);
        out.push('=');
        out.push_str(value);
    }
    Ok(out)
}

/// The canonical request of the SigV4 specification:
///
/// ```text
/// <method>\n<uri>\n<canonical query>\n<name:value>\n…\n\n<signed;names>\n<payload hash>
/// ```
///
/// `uri` is a canonical URI already ([`canonical_uri`]); `query` is the query as it went
/// over the wire, canonicalized here ([`canonical_query`]). `headers` are the request's
/// header fields in any case; a repeated field is joined with `,` in its order. Each
/// value is trimmed and its runs of white space become one space. `signed_headers` are
/// lowercase, sorted, distinct, at most 64, and include `host`; each must be in
/// `headers`. The text can hold a header value (a session token), so it is erased on
/// drop.
pub fn canonical_request(
    method: &str,
    uri: &str,
    query: &str,
    headers: &[(&str, &str)],
    signed_headers: &[&str],
    payload_hash: &str,
) -> Result<Zeroizing<String>, SigV4Error> {
    if !is_method(method) {
        return Err(SigV4Error::Method);
    }
    if !uri.starts_with('/') || !is_graphic(uri) {
        return Err(SigV4Error::Uri);
    }
    check_signed_header_names(signed_headers)?;
    if !signed_headers.contains(&"host") {
        return Err(SigV4Error::Headers);
    }
    if payload_hash.is_empty() || !is_graphic(payload_hash) {
        return Err(SigV4Error::Payload);
    }
    let query = canonical_query(query)?;
    let mut out = Zeroizing::new(String::with_capacity(512));
    out.push_str(method);
    out.push('\n');
    out.push_str(uri);
    out.push('\n');
    out.push_str(&query);
    out.push('\n');
    for name in signed_headers {
        let mut values = headers
            .iter()
            .filter(|(field, _)| field.eq_ignore_ascii_case(name))
            .map(|(_, value)| *value)
            .peekable();
        if values.peek().is_none() {
            return Err(SigV4Error::Headers);
        }
        out.push_str(name);
        out.push(':');
        for (index, value) in values.enumerate() {
            if value
                .bytes()
                .any(|byte| (byte < 0x20 && byte != b'\t') || byte == 0x7f)
            {
                return Err(SigV4Error::Headers);
            }
            if index > 0 {
                out.push(',');
            }
            for (word_index, word) in value.split_ascii_whitespace().enumerate() {
                if word_index > 0 {
                    out.push(' ');
                }
                out.push_str(word);
            }
        }
        out.push('\n');
    }
    out.push('\n');
    for (index, name) in signed_headers.iter().enumerate() {
        if index > 0 {
            out.push(';');
        }
        out.push_str(name);
    }
    out.push('\n');
    out.push_str(payload_hash);
    Ok(out)
}

/// A canonical request read back from its text (the `canonical_request` of `POST
/// /v1/sign`, contract section 7.2). The slices point into the text. `Debug` shows the
/// method, the URI, and the header names only.
pub struct CanonicalRequest<'a> {
    pub method: &'a str,
    /// The canonical URI (starts with `/`, no query).
    pub uri: &'a str,
    /// The canonical query (may be empty).
    pub query: &'a str,
    /// The header lines: lowercase names, sorted, distinct, each with its value.
    pub headers: Vec<(&'a str, &'a str)>,
    /// The signed header names, equal to the names of `headers`.
    pub signed_headers: Vec<&'a str>,
    pub payload_hash: &'a str,
}

impl CanonicalRequest<'_> {
    /// The value of the signed header `name` (lowercase).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(field, _)| *field == name)
            .map(|(_, value)| *value)
    }
}

impl fmt::Debug for CanonicalRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CanonicalRequest")
            .field("method", &self.method)
            .field("uri", &self.uri)
            .field("signed_headers", &self.signed_headers)
            .finish_non_exhaustive()
    }
}

/// Read a canonical request text with the lines of contract section 7.2: the method
/// (`[A-Z]{1,16}`), the canonical URI (starts with `/`), the canonical query, one
/// `name:value` line per signed header (names lowercase, sorted, distinct; at least
/// one), an empty line, the signed header names joined by `;` (equal to the header
/// lines' names), and the payload hash. Lines are joined by `\n`; a `\r` or any other
/// control character is refused, and nothing may follow the payload hash. This checks
/// the form only: [`check_payload_hash`], [`is_presigned`], and [`check_amz_date`] check
/// the content.
pub fn parse_canonical_request(text: &str) -> Result<CanonicalRequest<'_>, SigV4Error> {
    const BAD: SigV4Error = SigV4Error::CanonicalRequest;
    if text
        .bytes()
        .any(|byte| (byte < 0x20 && byte != b'\n') || byte == 0x7f)
    {
        return Err(BAD);
    }
    let lines: Vec<&str> = text.split('\n').collect();
    if lines.len() < 7 {
        return Err(BAD);
    }
    let (method, uri, query) = (lines[0], lines[1], lines[2]);
    if !is_method(method) {
        return Err(BAD);
    }
    if !uri.starts_with('/') || !is_graphic(uri) || uri.contains(['?', '#']) {
        return Err(BAD);
    }
    if !query.is_empty() && !is_graphic(query) {
        return Err(BAD);
    }
    let blank = lines[3..]
        .iter()
        .position(|line| line.is_empty())
        .map(|at| at + 3)
        .ok_or(BAD)?;
    if blank == 3 || lines.len() != blank + 3 {
        return Err(BAD);
    }
    let mut headers = Vec::with_capacity(blank - 3);
    for line in &lines[3..blank] {
        let (name, value) = line.split_once(':').ok_or(BAD)?;
        if value.starts_with(' ') || value.ends_with(' ') || value.contains("  ") {
            return Err(BAD);
        }
        headers.push((name, value));
    }
    let signed_headers: Vec<&str> = lines[blank + 1].split(';').collect();
    let names: Vec<&str> = headers.iter().map(|(name, _)| *name).collect();
    check_signed_header_names(&names).map_err(|_| BAD)?;
    if signed_headers != names {
        return Err(BAD);
    }
    let payload_hash = lines[blank + 2];
    if payload_hash.is_empty() || !is_graphic(payload_hash) {
        return Err(BAD);
    }
    Ok(CanonicalRequest {
        method,
        uri,
        query,
        headers,
        signed_headers,
        payload_hash,
    })
}

/// The payload rule of the sign endpoint (contract section 7.2). Refused: a
/// `STREAMING-*` hash; a signed `x-amz-content-sha256` that differs from the hash; an
/// `UNSIGNED-PAYLOAD` unless the method is `GET`, `HEAD`, or `DELETE` and no
/// `content-length` other than `0` is signed; and anything else that is not 64
/// lowercase hex.
pub fn check_payload_hash(request: &CanonicalRequest<'_>) -> Result<(), SigV4Error> {
    let hash = request.payload_hash;
    if hash.starts_with(STREAMING_PREFIX) {
        return Err(SigV4Error::Payload);
    }
    if request
        .header("x-amz-content-sha256")
        .is_some_and(|declared| declared != hash)
    {
        return Err(SigV4Error::Payload);
    }
    if hash == UNSIGNED_PAYLOAD {
        let bodiless = matches!(request.method, "GET" | "HEAD" | "DELETE");
        let no_length = request
            .header("content-length")
            .is_none_or(|length| length == "0");
        return if bodiless && no_length {
            Ok(())
        } else {
            Err(SigV4Error::Payload)
        };
    }
    if !is_signature_hex(hash) {
        return Err(SigV4Error::Payload);
    }
    Ok(())
}

/// Read `x-amz-date` (`YYYYMMDDTHHMMSSZ`) and check that its day is the scope's date.
/// Returns the time in Unix seconds, for a caller that also bounds the clock difference
/// (the sign endpoint: 15 minutes).
pub fn check_amz_date(amz_date: &str, scope: &Scope) -> Result<u64, SigV4Error> {
    let unix = parse_amz_date(amz_date).ok_or(SigV4Error::Date)?;
    if amz_date.get(..8) != Some(scope.date()) {
        return Err(SigV4Error::Date);
    }
    Ok(unix)
}

/// `YYYYMMDDTHHMMSSZ` of Unix seconds (UTC), or `None` outside the years 1970 to 9999.
pub fn amz_date(unix: u64) -> Option<String> {
    let (year, month, day, hour, minute, second) = super::utc_parts(unix)?;
    Some(format!(
        "{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}Z"
    ))
}

/// Unix seconds of `YYYYMMDDTHHMMSSZ`, or `None` when the text is not exactly that form
/// of a real time.
pub fn parse_amz_date(text: &str) -> Option<u64> {
    let bytes = text.as_bytes();
    if bytes.len() != 16 || bytes[8] != b'T' || bytes[15] != b'Z' {
        return None;
    }
    let digits = |range: std::ops::Range<usize>| -> Option<u32> {
        let part = text.get(range)?;
        if !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        part.parse().ok()
    };
    super::unix_from_parts(
        i32::try_from(digits(0..4)?).ok()?,
        u8::try_from(digits(4..6)?).ok()?,
        u8::try_from(digits(6..8)?).ok()?,
        u8::try_from(digits(9..11)?).ok()?,
        u8::try_from(digits(11..13)?).ok()?,
        u8::try_from(digits(13..15)?).ok()?,
    )
}

/// One request of the key holder to AWS, before it is signed ([`sign_request`]).
#[derive(Clone, Copy)]
pub struct ClientRequest<'a> {
    /// `GET`, `POST`, …
    pub method: &'a str,
    /// The `Host` value that the HTTP client sends (`DestinationUrl::host_header`).
    pub host: &'a str,
    /// The path as it goes over the wire (percent-encoded), without the query.
    pub path: &'a str,
    /// The query as it goes over the wire, without `?`, or empty.
    pub query: &'a str,
    /// Other header fields to sign, sent by the caller exactly as given. Not `Host`,
    /// `X-Amz-Date`, or `Authorization`.
    pub headers: &'a [(&'a str, &'a str)],
    /// The exact body bytes.
    pub payload: &'a [u8],
}

impl fmt::Debug for ClientRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<&str> = self.headers.iter().map(|(name, _)| *name).collect();
        f.debug_struct("ClientRequest")
            .field("method", &self.method)
            .field("host", &self.host)
            .field("path", &self.path)
            .field("headers", &names)
            .field("payload_bytes", &self.payload.len())
            .finish()
    }
}

/// The two header fields that [`sign_request`] adds: `X-Amz-Date` and `Authorization`.
/// `Debug` hides the authorization (it holds the signature).
pub struct ClientSignature {
    pub amz_date: String,
    pub authorization: String,
}

impl fmt::Debug for ClientSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientSignature")
            .field("amz_date", &self.amz_date)
            .field("authorization", &"[redacted]")
            .finish()
    }
}

/// Sign `request` with a long-lived key at `now_unix` for the key holder's own call
/// (STS, IAM). The signed headers are `host`, `x-amz-date`, and the request's own
/// headers; the payload hash is the SHA-256 of `payload`. The secret is used only to
/// derive the signing key; neither is in the result.
pub fn sign_request(
    access_key_id: &str,
    secret: &str,
    region: &str,
    service: &str,
    request: &ClientRequest<'_>,
    now_unix: u64,
) -> Result<ClientSignature, SigV4Error> {
    if !is_access_key_id(access_key_id) {
        return Err(SigV4Error::Authorization);
    }
    let amz_date = amz_date(now_unix).ok_or(SigV4Error::Date)?;
    let scope = Scope::new(&amz_date[..8], region, service)?;
    let mut named: Vec<(String, &str)> = vec![
        ("host".to_owned(), request.host),
        ("x-amz-date".to_owned(), amz_date.as_str()),
    ];
    for (name, value) in request.headers {
        let lower = name.to_ascii_lowercase();
        if lower == "authorization" || named.iter().any(|(earlier, _)| *earlier == lower) {
            return Err(SigV4Error::Headers);
        }
        named.push((lower, *value));
    }
    named.sort_by(|left, right| left.0.cmp(&right.0));
    let signed: Vec<&str> = named.iter().map(|(name, _)| name.as_str()).collect();
    let fields: Vec<(&str, &str)> = named
        .iter()
        .map(|(name, value)| (name.as_str(), *value))
        .collect();
    let uri = canonical_uri(request.path, service)?;
    let payload_hash = sha256_hex(request.payload);
    let canonical = canonical_request(
        request.method,
        &uri,
        request.query,
        &fields,
        &signed,
        &payload_hash,
    )?;
    let signature = sign_canonical(secret, &scope, &amz_date, &canonical);
    let authorization = format!(
        "{ALGORITHM} Credential={access_key_id}/{}, SignedHeaders={}, Signature={signature}",
        scope.credential_scope(),
        signed.join(";")
    );
    drop(fields);
    drop(named);
    Ok(ClientSignature {
        amz_date,
        authorization,
    })
}

/// SHA-256 of `bytes` in lowercase hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex_lower(digest::digest(&digest::SHA256, bytes).as_ref())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

fn decode_signature(text: &str) -> Option<[u8; 32]> {
    if !is_signature_hex(text) {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, pair) in text.as_bytes().chunks(2).enumerate() {
        let high = hex_value(pair[0])?;
        let low = hex_value(pair[1])?;
        out[index] = (high << 4) | low;
    }
    Some(out)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// 64 lowercase hex: a signature or a SHA-256 payload hash.
fn is_signature_hex(text: &str) -> bool {
    text.len() == SIGNATURE_HEX_BYTES
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// `[A-Z0-9]{1,128}`: an access key id (`AKIA…`, `ASIA…`, the test suite's
/// `AKIDEXAMPLE`).
fn is_access_key_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ACCESS_KEY_ID_BYTES
        && id
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

fn is_scope_date(date: &str) -> bool {
    date.len() == 8
        && date.bytes().all(|byte| byte.is_ascii_digit())
        && parse_amz_date(&format!("{date}T000000Z")).is_some()
}

fn is_scope_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_SCOPE_NAME_BYTES
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn is_method(method: &str) -> bool {
    !method.is_empty()
        && method.len() <= MAX_METHOD_BYTES
        && method.bytes().all(|byte| byte.is_ascii_uppercase())
}

/// Printable ASCII without the space.
fn is_graphic(text: &str) -> bool {
    text.bytes().all(|byte| byte.is_ascii_graphic())
}

/// A lowercase header name (an RFC 9110 token in lowercase).
fn is_lower_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"!#$%&'*+-.^_`|~".contains(&byte)
        })
}

fn check_signed_header_names(names: &[&str]) -> Result<(), SigV4Error> {
    if names.is_empty() || names.len() > MAX_SIGNED_HEADERS {
        return Err(SigV4Error::Headers);
    }
    if !names.iter().all(|name| is_lower_header_name(name)) {
        return Err(SigV4Error::Headers);
    }
    if !names.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(SigV4Error::Headers);
    }
    Ok(())
}

fn percent_decode(text: &str) -> Result<Vec<u8>, SigV4Error> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = bytes.get(index + 1).copied().and_then(hex_value);
            let low = bytes.get(index + 2).copied().and_then(hex_value);
            let (Some(high), Some(low)) = (high, low) else {
                return Err(SigV4Error::Uri);
            };
            out.push((high << 4) | low);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    Ok(out)
}

fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

/// The `UriEncode` of the SigV4 specification (the bytes of `http::form_body`): RFC
/// 3986 unreserved bytes stay, `/` stays unless `encode_slash`, everything else is
/// `%XX` in uppercase hex.
fn uri_encode_into(out: &mut String, bytes: &[u8], encode_slash: bool) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &byte in bytes {
        if is_unreserved(byte) || (byte == b'/' && !encode_slash) {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(char::from(HEX[usize::from(byte >> 4)]));
            out.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
}

fn uri_encode(bytes: &[u8], encode_slash: bool) -> String {
    let mut out = String::with_capacity(bytes.len() * 3);
    uri_encode_into(&mut out, bytes, encode_slash);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The credentials and the time of the AWS SigV4 test suite
    /// (`aws-sig-v4-test-suite`, 2015-08-30): published example values, not a key.
    const SUITE_KEY_ID: &str = "AKIDEXAMPLE";
    const SUITE_SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    const SUITE_DATE: &str = "20150830T123600Z";
    const SUITE_UNIX: u64 = 1_440_938_160;
    const SUITE_HOST: &str = "example.amazonaws.com";

    struct Vector {
        name: &'static str,
        method: &'static str,
        path: &'static str,
        query: &'static str,
        headers: &'static [(&'static str, &'static str)],
        body: &'static [u8],
        canonical: &'static str,
        signature: &'static str,
    }

    /// The vectors named by the plan (unit C1), with the request as in the suite's `.req`
    /// file, the suite's `.creq` text, and the signature of its `.authz` file.
    const VECTORS: [Vector; 4] = [
        Vector {
            name: "get-vanilla",
            method: "GET",
            path: "/",
            query: "",
            headers: &[("Host", SUITE_HOST), ("X-Amz-Date", SUITE_DATE)],
            body: b"",
            canonical: "GET\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            signature: "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
        },
        Vector {
            name: "post-vanilla-query",
            method: "POST",
            path: "/",
            query: "Param1=value1",
            headers: &[("Host", SUITE_HOST), ("X-Amz-Date", SUITE_DATE)],
            body: b"",
            canonical: "POST\n/\nParam1=value1\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            signature: "28038455d6de14eafc1f9222cf5aa6f1a96197d7deb8263271d420d138af7f11",
        },
        Vector {
            name: "get-header-value-trim",
            method: "GET",
            path: "/",
            query: "",
            headers: &[
                ("Host", SUITE_HOST),
                ("My-Header1", " value1"),
                ("My-Header2", " \"a   b   c\""),
                ("X-Amz-Date", SUITE_DATE),
            ],
            body: b"",
            canonical: "GET\n/\n\nhost:example.amazonaws.com\nmy-header1:value1\nmy-header2:\"a b c\"\nx-amz-date:20150830T123600Z\n\nhost;my-header1;my-header2;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            signature: "acc3ed3afb60bb290fc8d2dd0098b9911fcaa05412b367055dee359757a9c736",
        },
        Vector {
            name: "post-x-www-form-urlencoded",
            method: "POST",
            path: "/",
            query: "",
            headers: &[
                ("Content-Type", "application/x-www-form-urlencoded"),
                ("Host", SUITE_HOST),
                ("X-Amz-Date", SUITE_DATE),
            ],
            body: b"Param1=value1",
            canonical: "POST\n/\n\ncontent-type:application/x-www-form-urlencoded\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\ncontent-type;host;x-amz-date\n9095672bbd1f56dfc5b65f3e153adc8731a4a654192329106275f4c7b24d0b6e",
            signature: "ff11897932ad3f4e8b18135d722051e5ac45fc38421b1da7b9d196a0fe09473a",
        },
    ];

    fn suite_scope() -> Scope {
        Scope::new("20150830", "us-east-1", "service").expect("suite scope")
    }

    fn signed_names(headers: &[(&str, &str)]) -> Vec<String> {
        let mut names: Vec<String> = headers
            .iter()
            .map(|(name, _)| name.to_ascii_lowercase())
            .collect();
        names.sort();
        names.dedup();
        names
    }

    #[test]
    fn sigv4_matches_the_aws_test_vectors() {
        assert_eq!(parse_amz_date(SUITE_DATE), Some(SUITE_UNIX));
        assert_eq!(amz_date(SUITE_UNIX).as_deref(), Some(SUITE_DATE));
        let scope = suite_scope();
        for vector in &VECTORS {
            let names = signed_names(vector.headers);
            let names: Vec<&str> = names.iter().map(String::as_str).collect();
            let uri = canonical_uri(vector.path, "service").expect(vector.name);
            let canonical = canonical_request(
                vector.method,
                &uri,
                vector.query,
                vector.headers,
                &names,
                &sha256_hex(vector.body),
            )
            .expect(vector.name);
            assert_eq!(
                &*canonical, vector.canonical,
                "{}: canonical request",
                vector.name
            );
            assert_eq!(
                sign_canonical(SUITE_SECRET, &scope, SUITE_DATE, &canonical),
                vector.signature,
                "{}: signature",
                vector.name
            );
            // The same vector as a proxy sees it: the Authorization header of the suite.
            let header = format!(
                "{ALGORITHM} Credential={SUITE_KEY_ID}/20150830/us-east-1/service/aws4_request, SignedHeaders={}, Signature={}",
                names.join(";"),
                vector.signature
            );
            let authorization = parse_authorization(&header).expect(vector.name);
            assert!(
                verify(SUITE_SECRET, &authorization, SUITE_DATE, &canonical),
                "{}: verify",
                vector.name
            );
            assert!(
                !verify(
                    "not-the-suite-secret",
                    &authorization,
                    SUITE_DATE,
                    &canonical
                ),
                "{}: a wrong secret must not verify",
                vector.name
            );
            // The sign endpoint reads the same text back.
            let parsed = parse_canonical_request(&canonical).expect(vector.name);
            assert_eq!(parsed.method, vector.method);
            assert_eq!(parsed.header("x-amz-date"), Some(SUITE_DATE));
            check_payload_hash(&parsed).expect(vector.name);
        }
    }

    /// The worked examples of the AWS documentation ("Create a signature for an AWS API
    /// request" and "Examples of how to derive a signing key"): IAM `ListUsers`.
    #[test]
    fn sigv4_matches_the_aws_documentation_examples() {
        let old = Scope::new("20120215", "us-east-1", "iam").expect("scope");
        assert_eq!(
            hex_lower(signing_key(SUITE_SECRET, &old).as_bytes()),
            "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"
        );
        let scope = Scope::new("20150830", "us-east-1", "iam").expect("scope");
        let headers = [
            (
                "Content-Type",
                "application/x-www-form-urlencoded; charset=utf-8",
            ),
            ("Host", "iam.amazonaws.com"),
            ("X-Amz-Date", SUITE_DATE),
        ];
        let canonical = canonical_request(
            "GET",
            "/",
            "Version=2010-05-08&Action=ListUsers",
            &headers,
            &["content-type", "host", "x-amz-date"],
            EMPTY_PAYLOAD_SHA256,
        )
        .expect("canonical");
        assert_eq!(
            &*canonical,
            "GET\n/\nAction=ListUsers&Version=2010-05-08\ncontent-type:application/x-www-form-urlencoded; charset=utf-8\nhost:iam.amazonaws.com\nx-amz-date:20150830T123600Z\n\ncontent-type;host;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(canonical.as_bytes()),
            "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59"
        );
        assert_eq!(
            sign_canonical(SUITE_SECRET, &scope, SUITE_DATE, &canonical),
            "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
        );
    }

    /// The `sign-request.json` and `sign-answer.json` fixtures of the contract are the
    /// get-vanilla vector as the sign endpoint sees it.
    #[test]
    fn the_sign_fixtures_are_the_get_vanilla_vector() {
        let request: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/private-sharing-v1/sign-request.json"
        ))
        .expect("sign request fixture");
        let answer: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/private-sharing-v1/sign-answer.json"
        ))
        .expect("sign answer fixture");
        let text = request["canonical_request"]
            .as_str()
            .expect("canonical text");
        let parsed = parse_canonical_request(text).expect("parse");
        check_payload_hash(&parsed).expect("payload");
        assert!(!is_presigned(parsed.query));
        let fixture_scope = &request["scope"];
        let scope = Scope::new(
            fixture_scope["date"].as_str().expect("date"),
            fixture_scope["region"].as_str().expect("region"),
            fixture_scope["service"].as_str().expect("service"),
        )
        .expect("scope");
        let amz = parsed.header("x-amz-date").expect("x-amz-date");
        check_amz_date(amz, &scope).expect("date");
        assert_eq!(
            sign_canonical(SUITE_SECRET, &scope, amz, text),
            answer["result"]["signature"].as_str().expect("signature")
        );
        assert_eq!(text, VECTORS[0].canonical);
    }

    #[test]
    fn sign_request_makes_the_suite_authorization_header() {
        let request = ClientRequest {
            method: "GET",
            host: SUITE_HOST,
            path: "/",
            query: "",
            headers: &[],
            payload: b"",
        };
        let signed = sign_request(
            SUITE_KEY_ID,
            SUITE_SECRET,
            "us-east-1",
            "service",
            &request,
            SUITE_UNIX,
        )
        .expect("sign");
        assert_eq!(signed.amz_date, SUITE_DATE);
        assert_eq!(
            signed.authorization,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
        let form = ClientRequest {
            method: "POST",
            headers: &[("Content-Type", "application/x-www-form-urlencoded")],
            payload: b"Param1=value1",
            ..request
        };
        let signed = sign_request(
            SUITE_KEY_ID,
            SUITE_SECRET,
            "us-east-1",
            "service",
            &form,
            SUITE_UNIX,
        )
        .expect("sign");
        assert!(signed.authorization.ends_with(VECTORS[3].signature));
        assert!(
            signed
                .authorization
                .contains("SignedHeaders=content-type;host;x-amz-date,")
        );
        // The secret is not in the result, and Debug hides the signature.
        assert!(!signed.authorization.contains(SUITE_SECRET));
        assert!(!format!("{signed:?}").contains(VECTORS[3].signature));
        // The client writes Host and X-Amz-Date itself; Authorization is the result.
        for header in [("Host", "x"), ("X-Amz-Date", "x"), ("authorization", "x")] {
            let bad = ClientRequest {
                headers: std::slice::from_ref(&header),
                ..request
            };
            assert_eq!(
                sign_request(
                    SUITE_KEY_ID,
                    SUITE_SECRET,
                    "us-east-1",
                    "service",
                    &bad,
                    SUITE_UNIX
                )
                .unwrap_err(),
                SigV4Error::Headers
            );
        }
        assert_eq!(
            sign_request(
                "akid",
                SUITE_SECRET,
                "us-east-1",
                "service",
                &request,
                SUITE_UNIX
            )
            .unwrap_err(),
            SigV4Error::Authorization
        );
        assert_eq!(
            sign_request(
                SUITE_KEY_ID,
                SUITE_SECRET,
                "US",
                "service",
                &request,
                SUITE_UNIX
            )
            .unwrap_err(),
            SigV4Error::Scope
        );
    }

    #[test]
    fn a_proxy_verifies_the_placeholder_and_re_signs_with_the_same_length() {
        // The SDK signed with a placeholder; the proxy proves it, then signs with the
        // real secret and changes only the Signature= value.
        let placeholder = "ph_PLACEHOLDERPLACEHOLDERPLACEHOLDER00000";
        let scope = suite_scope();
        let canonical = VECTORS[0].canonical;
        let sent = format!(
            "{ALGORITHM} Credential={SUITE_KEY_ID}/20150830/us-east-1/service/aws4_request,SignedHeaders=host;x-amz-date,Signature={}",
            sign_canonical(placeholder, &scope, SUITE_DATE, canonical)
        );
        let authorization = parse_authorization(&sent).expect("parse");
        assert!(verify(placeholder, &authorization, SUITE_DATE, canonical));
        assert!(!verify(SUITE_SECRET, &authorization, SUITE_DATE, canonical));
        let real = sign_canonical(SUITE_SECRET, &scope, SUITE_DATE, canonical);
        let resigned = replace_signature(&sent, &real).expect("replace");
        assert_eq!(resigned.len(), sent.len());
        assert_eq!(
            resigned.replace(&real, ""),
            sent.replace(&authorization.signature, "")
        );
        let again = parse_authorization(&resigned).expect("parse again");
        assert!(verify(SUITE_SECRET, &again, SUITE_DATE, canonical));
        assert_eq!(
            replace_signature(&sent, "ABC").unwrap_err(),
            SigV4Error::Authorization
        );
        // Debug never shows the signature.
        assert!(!format!("{authorization:?}").contains(&authorization.signature));
    }

    #[test]
    fn an_authorization_header_must_have_the_exact_form() {
        let good = format!(
            "{ALGORITHM} Credential={SUITE_KEY_ID}/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature={}",
            VECTORS[0].signature
        );
        let parsed = parse_authorization(&good).expect("good");
        assert_eq!(parsed.access_key_id, SUITE_KEY_ID);
        assert_eq!(parsed.scope, suite_scope());
        assert_eq!(parsed.signed_headers, ["host", "x-amz-date"]);
        // The parts in another order are the same value.
        let reordered = format!(
            "{ALGORITHM} Signature={}, Credential={SUITE_KEY_ID}/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date",
            VECTORS[0].signature
        );
        assert_eq!(parse_authorization(&reordered).expect("reordered"), parsed);
        let sig = VECTORS[0].signature;
        for bad in [
            format!(
                "AWS4-HMAC-SHA512 Credential={SUITE_KEY_ID}/20150830/us-east-1/service/aws4_request, SignedHeaders=host, Signature={sig}"
            ),
            format!(
                "{ALGORITHM}Credential={SUITE_KEY_ID}/20150830/us-east-1/service/aws4_request, SignedHeaders=host, Signature={sig}"
            ),
            format!(
                "{ALGORITHM} Credential={SUITE_KEY_ID}/20150830/us-east-1/service/aws4_request, SignedHeaders=host"
            ),
            format!(
                "{ALGORITHM} Credential={SUITE_KEY_ID}/20150830/us-east-1/service/aws4_request, SignedHeaders=host, Signature={sig}, Signature={sig}"
            ),
            format!(
                "{ALGORITHM} Credential={SUITE_KEY_ID}/20150830/us-east-1/service/aws4_request, SignedHeaders=host, Signature={sig}, Extra=1"
            ),
            format!(
                "{ALGORITHM} Credential={SUITE_KEY_ID}/20150830/us-east-1/service/aws4_requests, SignedHeaders=host, Signature={sig}"
            ),
            format!(
                "{ALGORITHM} Credential={SUITE_KEY_ID}/20150830/us-east-1/service, SignedHeaders=host, Signature={sig}"
            ),
            format!(
                "{ALGORITHM} Credential={SUITE_KEY_ID}/20150830/us-east-1/service/aws4_request/x, SignedHeaders=host, Signature={sig}"
            ),
            format!(
                "{ALGORITHM} Credential={SUITE_KEY_ID}/20151332/us-east-1/service/aws4_request, SignedHeaders=host, Signature={sig}"
            ),
            format!(
                "{ALGORITHM} Credential={SUITE_KEY_ID}/20150830/US-EAST-1/service/aws4_request, SignedHeaders=host, Signature={sig}"
            ),
            format!(
                "{ALGORITHM} Credential=akid/20150830/us-east-1/service/aws4_request, SignedHeaders=host, Signature={sig}"
            ),
            format!(
                "{ALGORITHM} Credential={SUITE_KEY_ID}/20150830/us-east-1/service/aws4_request, SignedHeaders=x-amz-date;host, Signature={sig}"
            ),
            format!(
                "{ALGORITHM} Credential={SUITE_KEY_ID}/20150830/us-east-1/service/aws4_request, SignedHeaders=Host, Signature={sig}"
            ),
            format!(
                "{ALGORITHM} Credential={SUITE_KEY_ID}/20150830/us-east-1/service/aws4_request, SignedHeaders=host;host, Signature={sig}"
            ),
            format!(
                "{ALGORITHM} Credential={SUITE_KEY_ID}/20150830/us-east-1/service/aws4_request, SignedHeaders=, Signature={sig}"
            ),
            format!(
                "{ALGORITHM} Credential={SUITE_KEY_ID}/20150830/us-east-1/service/aws4_request, SignedHeaders=host, Signature={}",
                sig.to_ascii_uppercase()
            ),
            format!(
                "{ALGORITHM} Credential={SUITE_KEY_ID}/20150830/us-east-1/service/aws4_request, SignedHeaders=host, Signature={}",
                &sig[..63]
            ),
        ] {
            assert_eq!(
                parse_authorization(&bad).unwrap_err(),
                SigV4Error::Authorization,
                "{bad}"
            );
        }
    }

    #[test]
    fn presigned_urls_are_recognized_in_any_form() {
        for query in [
            "X-Amz-Signature=abc",
            "a=1&X-Amz-Credential=AKID%2F20150830",
            "x-amz-algorithm=AWS4-HMAC-SHA256",
            "X%2DAmz%2DSignature=abc",
            "list-type=2&X-Amz-Algorithm",
        ] {
            assert!(is_presigned(query), "{query}");
        }
        for query in [
            "",
            "Param1=value1",
            "X-Amz-Date=20150830T123600Z",
            "x=X-Amz-Signature",
        ] {
            assert!(!is_presigned(query), "{query}");
        }
        assert_eq!(
            SigV4Error::Presigned.reason(),
            "Presigned URLs are not signed."
        );
    }

    fn canonical_from(text: &str) -> CanonicalRequest<'_> {
        parse_canonical_request(text).expect("canonical")
    }

    #[test]
    fn payload_hashes_follow_the_sign_endpoint_rule() {
        let hash = EMPTY_PAYLOAD_SHA256;
        let ok = [
            format!("GET\n/\n\nhost:h\n\nhost\n{hash}"),
            format!(
                "PUT\n/k\n\nhost:h\nx-amz-content-sha256:{hash}\n\nhost;x-amz-content-sha256\n{hash}"
            ),
            format!("GET\n/\n\nhost:h\n\nhost\n{UNSIGNED_PAYLOAD}"),
            format!(
                "DELETE\n/\n\ncontent-length:0\nhost:h\n\ncontent-length;host\n{UNSIGNED_PAYLOAD}"
            ),
            format!(
                "HEAD\n/\n\nhost:h\nx-amz-content-sha256:{UNSIGNED_PAYLOAD}\n\nhost;x-amz-content-sha256\n{UNSIGNED_PAYLOAD}"
            ),
        ];
        for text in &ok {
            check_payload_hash(&canonical_from(text)).expect(text);
        }
        let refused = [
            "PUT\n/k\n\nhost:h\n\nhost\nSTREAMING-AWS4-HMAC-SHA256-PAYLOAD".to_owned(),
            "PUT\n/k\n\nhost:h\n\nhost\nSTREAMING-UNSIGNED-PAYLOAD-TRAILER".to_owned(),
            format!("PUT\n/k\n\nhost:h\n\nhost\n{UNSIGNED_PAYLOAD}"),
            format!("POST\n/\n\nhost:h\n\nhost\n{UNSIGNED_PAYLOAD}"),
            format!(
                "GET\n/\n\ncontent-length:5\nhost:h\n\ncontent-length;host\n{UNSIGNED_PAYLOAD}"
            ),
            format!("GET\n/\n\nhost:h\n\nhost\n{}", hash.to_ascii_uppercase()),
            format!("GET\n/\n\nhost:h\n\nhost\n{}", &hash[..60]),
            format!(
                "PUT\n/k\n\nhost:h\nx-amz-content-sha256:{UNSIGNED_PAYLOAD}\n\nhost;x-amz-content-sha256\n{hash}"
            ),
        ];
        for text in &refused {
            assert_eq!(
                check_payload_hash(&canonical_from(text)).unwrap_err(),
                SigV4Error::Payload,
                "{text}"
            );
        }
        assert_eq!(
            SigV4Error::Payload.reason(),
            "This payload hash is not signed."
        );
    }

    #[test]
    fn a_canonical_request_text_must_have_the_contract_lines() {
        let hash = EMPTY_PAYLOAD_SHA256;
        let refused = [
            String::new(),
            format!("GET\n/\n\nhost:h\n\nhost\n{hash}\n"),
            format!("GET\n/\n\nhost:h\n\nhost\n{hash}\nextra"),
            format!("GET\r\n/\n\nhost:h\n\nhost\n{hash}"),
            format!("get\n/\n\nhost:h\n\nhost\n{hash}"),
            format!("GET\nx\n\nhost:h\n\nhost\n{hash}"),
            format!("GET\n/\n\n\nhost\n{hash}"),
            format!("GET\n/\n\nhost:h\n\nhost;x-amz-date\n{hash}"),
            format!("GET\n/\n\nx-amz-date:d\nhost:h\n\nx-amz-date;host\n{hash}"),
            format!("GET\n/\n\nHost:h\n\nHost\n{hash}"),
            format!("GET\n/\n\nhost:h\nhost:h\n\nhost;host\n{hash}"),
            format!("GET\n/\n\nhost: h\n\nhost\n{hash}"),
            format!("GET\n/\n\nhost:a  b\n\nhost\n{hash}"),
            format!("GET\n/\n\nhost\n\nhost\n{hash}"),
            "GET\n/\n\nhost:h\n\nhost\n".to_owned(),
            format!("GET\n/ x\n\nhost:h\n\nhost\n{hash}"),
            format!("GET\n/\n\nhost:h\tx\n\nhost\n{hash}"),
        ];
        for text in &refused {
            assert_eq!(
                parse_canonical_request(text).unwrap_err(),
                SigV4Error::CanonicalRequest,
                "{text:?}"
            );
        }
        let parsed = canonical_from(VECTORS[2].canonical);
        assert_eq!(
            parsed.signed_headers,
            ["host", "my-header1", "my-header2", "x-amz-date"]
        );
        assert_eq!(parsed.header("my-header2"), Some("\"a b c\""));
        assert!(!format!("{parsed:?}").contains("a b c"));
    }

    #[test]
    fn canonical_queries_are_sorted_and_encoded_once() {
        assert_eq!(canonical_query("").as_deref(), Ok(""));
        assert_eq!(
            canonical_query("Param2=value2&Param1=value1").as_deref(),
            Ok("Param1=value1&Param2=value2")
        );
        assert_eq!(canonical_query("b=2&a=2&a=1").as_deref(), Ok("a=1&a=2&b=2"));
        assert_eq!(canonical_query("Param1").as_deref(), Ok("Param1="));
        // Encoded once, uppercase hex, unreserved bytes as they are.
        assert_eq!(
            canonical_query("k=a%2fb&j=%7E*&i=a+b").as_deref(),
            Ok("i=a%2Bb&j=~%2A&k=a%2Fb")
        );
        for bad in ["a=1&&b=2", "=1", "a=%2", "a=%zz", "a=1#f", "a b=1"] {
            assert_eq!(canonical_query(bad).unwrap_err(), SigV4Error::Uri, "{bad}");
        }
    }

    #[test]
    fn canonical_uris_follow_the_service_rules() {
        // Every service but S3: dot and empty segments removed, encoded again.
        assert_eq!(canonical_uri("/", "sts").as_deref(), Ok("/"));
        assert_eq!(canonical_uri("/a/./b/../c", "iam").as_deref(), Ok("/a/c"));
        assert_eq!(canonical_uri("//a//b/", "iam").as_deref(), Ok("/a/b/"));
        assert_eq!(canonical_uri("/a%20b", "lambda").as_deref(), Ok("/a%2520b"));
        assert_eq!(canonical_uri("/example/..", "service").as_deref(), Ok("/"));
        // S3: the path as sent.
        assert_eq!(
            canonical_uri("//a/./b%20c", "s3").as_deref(),
            Ok("//a/./b%20c")
        );
        for bad in ["", "a", "/a b", "/a?b", "/a#b", "/\u{e9}"] {
            assert_eq!(
                canonical_uri(bad, "iam").unwrap_err(),
                SigV4Error::Uri,
                "{bad}"
            );
        }
    }

    #[test]
    fn canonical_requests_need_their_signed_headers() {
        let headers = [("Host", SUITE_HOST), ("X-Amz-Date", SUITE_DATE)];
        let hash = EMPTY_PAYLOAD_SHA256;
        assert_eq!(
            canonical_request("GET", "/", "", &headers, &["x-amz-date"], hash).unwrap_err(),
            SigV4Error::Headers
        );
        assert_eq!(
            canonical_request(
                "GET",
                "/",
                "",
                &headers,
                &["host", "x-amz-content-sha256"],
                hash
            )
            .unwrap_err(),
            SigV4Error::Headers
        );
        assert_eq!(
            canonical_request("GET", "/", "", &headers, &["x-amz-date", "host"], hash).unwrap_err(),
            SigV4Error::Headers
        );
        assert_eq!(
            canonical_request("GET", "/", "", &[("Host", "a\nb")], &["host"], hash).unwrap_err(),
            SigV4Error::Headers
        );
        assert_eq!(
            canonical_request("get", "/", "", &headers, &["host"], hash).unwrap_err(),
            SigV4Error::Method
        );
        assert_eq!(
            canonical_request("GET", "x", "", &headers, &["host"], hash).unwrap_err(),
            SigV4Error::Uri
        );
        assert_eq!(
            canonical_request("GET", "/", "", &headers, &["host"], "").unwrap_err(),
            SigV4Error::Payload
        );
        // A repeated field is joined with a comma in its order.
        let repeated = [("Host", "h"), ("X-A", "one"), ("x-a", " two  three ")];
        let text =
            canonical_request("GET", "/", "", &repeated, &["host", "x-a"], hash).expect("repeated");
        assert!(text.contains("\nx-a:one,two three\n"));
    }

    #[test]
    fn amz_dates_must_match_the_scope() {
        let scope = suite_scope();
        assert_eq!(check_amz_date(SUITE_DATE, &scope), Ok(SUITE_UNIX));
        for bad in [
            "20150831T123600Z",
            "20150830T123600",
            "20150830 123600Z",
            "2015-08-30T12:36:00Z",
            "20150830T246000Z",
            "",
        ] {
            assert_eq!(
                check_amz_date(bad, &scope).unwrap_err(),
                SigV4Error::Date,
                "{bad}"
            );
        }
        assert_eq!(
            Scope::new("20150230", "us-east-1", "s3").unwrap_err(),
            SigV4Error::Scope
        );
        assert_eq!(
            Scope::new("20150830", "", "s3").unwrap_err(),
            SigV4Error::Scope
        );
        assert_eq!(
            Scope::new("20150830", "us-east-1", &"s".repeat(33)).unwrap_err(),
            SigV4Error::Scope
        );
    }

    #[test]
    fn the_signing_key_is_redacted() {
        let key = signing_key(SUITE_SECRET, &suite_scope());
        assert_eq!(format!("{key:?}"), "SigningKey([redacted])");
        assert!(!verify_signature(&key, "text", "zz"));
        assert!(!verify_signature(&key, "text", &"0".repeat(64)));
        let good = signature(&key, "text");
        assert!(verify_signature(&key, "text", &good));
        assert!(!verify_signature(&key, "text", &good.to_ascii_uppercase()));
    }
}
