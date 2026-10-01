//! The bodies of the companion wire (contract companion-v1, sections 4, 5, and 7).
//!
//! A request type refuses unknown fields. A response type holds no secret value, no
//! placeholder, no agent token, no note, and no hidden detail: it is built from the
//! fields that the contract names. IDs of runs, access requests, and activity entries
//! are decimal strings, because a JSON number loses digits in a Swift `Double`.
//!
//! The helpers at the top check the formats of the four request headers, the device ID,
//! and the device name. The server checks a format before any signature.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::crypto::{MAX_SIGNATURE_BYTES, PUBLIC_KEY_BYTES, SECRET_BYTES, is_public_key_shape};
use super::digest::run_digest_hex;
use crate::broker::approvals::PendingRun;
use crate::native::base64::decode_url;
use crate::vault::{AccessRequest, ActivityRecord};

/// The version of the wire in a pair request and a status answer.
pub const CONTRACT_VERSION: u32 = 1;
/// A device name has at most this many characters.
pub const MAX_DEVICE_NAME_CHARS: usize = 40;
/// A time header has at most this many digits.
pub const MAX_TIME_DIGITS: usize = 12;
/// A nonce is 16 random bytes: 22 b64u characters.
pub const NONCE_BYTES: usize = 16;
const NONCE_TEXT_CHARS: usize = 22;
/// The shortest DER ECDSA P-256 signature.
const MIN_SIGNATURE_BYTES: usize = 8;
/// The summary and the reason of an activity entry have at most this many characters.
pub const MAX_ACTIVITY_TEXT_CHARS: usize = 300;

/// A device ID: 32 lowercase hexadecimal characters.
pub fn valid_device_id(text: &str) -> bool {
    text.len() == 32
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A device name (contract section 2, "Characters"): 1 to 40 Unicode scalar values, no
/// control character (`Cc`), and no Unicode `White_Space` scalar at the start or the
/// end.
pub fn valid_device_name(text: &str) -> bool {
    let chars = text.chars().count();
    (1..=MAX_DEVICE_NAME_CHARS).contains(&chars)
        && !text.chars().any(char::is_control)
        && !text.chars().next().is_some_and(char::is_whitespace)
        && !text.chars().next_back().is_some_and(char::is_whitespace)
}

/// The value of `X-Apassy-Time`: 1 to 12 decimal digits.
pub fn parse_time_header(text: &str) -> Option<u64> {
    if text.is_empty() || text.len() > MAX_TIME_DIGITS || !text.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    text.parse().ok()
}

/// The value of `X-Apassy-Nonce`: 22 b64u characters that decode to 16 bytes.
pub fn parse_nonce(text: &str) -> Option<[u8; NONCE_BYTES]> {
    if text.len() != NONCE_TEXT_CHARS {
        return None;
    }
    decode_url(text)?.try_into().ok()
}

/// A decimal ID in a path or a body: digits only, no leading zero, at least 1.
pub fn parse_id(text: &str) -> Option<u64> {
    if text.is_empty()
        || text.len() > 20
        || text.starts_with('0')
        || !text.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    text.parse().ok()
}

/// b64u text that decodes to exactly `N` bytes.
pub fn decode_fixed<const N: usize>(text: &str) -> Option<[u8; N]> {
    decode_url(text)?.try_into().ok()
}

/// b64u text of a P-256 public key: 65 bytes, X9.63 uncompressed.
pub fn decode_public_key(text: &str) -> Option<[u8; PUBLIC_KEY_BYTES]> {
    let key = decode_fixed::<PUBLIC_KEY_BYTES>(text)?;
    is_public_key_shape(&key).then_some(key)
}

/// b64u text of a DER signature, with the size limits of a P-256 signature.
pub fn decode_signature(text: &str) -> Option<Vec<u8>> {
    let signature = decode_url(text)?;
    (MIN_SIGNATURE_BYTES..=MAX_SIGNATURE_BYTES)
        .contains(&signature.len())
        .then_some(signature)
}

/// A run digest on the wire: 64 lowercase hexadecimal characters.
pub fn valid_digest(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Parse a JSON request body. The body must be one JSON object: an array or another
/// value is refused, also for a struct that serde could read from an array. Unknown
/// and duplicate fields fail through the type.
pub fn parse_body<T: serde::de::DeserializeOwned>(body: &[u8]) -> Option<T> {
    let first = body.iter().find(|b| !b.is_ascii_whitespace())?;
    if *first != b'{' {
        return None;
    }
    serde_json::from_slice(body).ok()
}

/// True when the body is exactly the empty JSON object `{}`.
pub fn is_empty_object(body: &[u8]) -> bool {
    matches!(
        parse_body::<serde_json::Map<String, serde_json::Value>>(body),
        Some(map) if map.is_empty()
    )
}

/// Cut `text` at `max` characters.
pub fn cut_chars(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

// ----- requests -----

/// `POST /v1/pair` (contract 5.3). Every field is text as sent. [`Self::validate`]
/// checks the formats.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairRequest {
    pub v: u32,
    pub device_id: String,
    pub device_name: String,
    pub request_key: String,
    pub approval_key: String,
    pub request_key_signature: String,
    pub approval_key_signature: String,
    pub proof: String,
}

impl fmt::Debug for PairRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairRequest")
            .field("device_id", &self.device_id)
            .field("device_name", &self.device_name)
            .field("proof", &"[redacted]")
            .finish_non_exhaustive()
    }
}

/// A pair request whose fields have the right formats. The signatures and the proof are
/// not checked yet.
#[derive(Clone)]
pub struct ValidPairRequest {
    pub device_id: String,
    pub device_name: String,
    pub request_key: [u8; PUBLIC_KEY_BYTES],
    pub approval_key: [u8; PUBLIC_KEY_BYTES],
    pub request_key_signature: Vec<u8>,
    pub approval_key_signature: Vec<u8>,
    pub proof: [u8; SECRET_BYTES],
}

impl fmt::Debug for ValidPairRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidPairRequest")
            .field("device_id", &self.device_id)
            .field("device_name", &self.device_name)
            .field("proof", &"[redacted]")
            .finish_non_exhaustive()
    }
}

impl PairRequest {
    /// Check the version and the format of every field. `None` means `400 bad_request`.
    pub fn validate(&self) -> Option<ValidPairRequest> {
        if self.v != CONTRACT_VERSION
            || !valid_device_id(&self.device_id)
            || !valid_device_name(&self.device_name)
        {
            return None;
        }
        Some(ValidPairRequest {
            device_id: self.device_id.clone(),
            device_name: self.device_name.clone(),
            request_key: decode_public_key(&self.request_key)?,
            approval_key: decode_public_key(&self.approval_key)?,
            request_key_signature: decode_signature(&self.request_key_signature)?,
            approval_key_signature: decode_signature(&self.approval_key_signature)?,
            proof: decode_fixed::<SECRET_BYTES>(&self.proof)?,
        })
    }
}

/// `POST /v1/runs/<id>/approve` (contract 7).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApproveRequest {
    pub digest: String,
    pub remember: bool,
    pub time: u64,
    pub approval_signature: String,
}

impl fmt::Debug for ApproveRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApproveRequest")
            .field("digest", &self.digest)
            .field("remember", &self.remember)
            .field("time", &self.time)
            .field("approval_signature", &"[redacted]")
            .finish()
    }
}

/// An approve request whose fields have the right formats.
#[derive(Clone)]
pub struct ValidApproveRequest {
    pub digest: String,
    pub remember: bool,
    pub time: u64,
    pub approval_signature: Vec<u8>,
}

impl fmt::Debug for ValidApproveRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidApproveRequest")
            .field("digest", &self.digest)
            .field("remember", &self.remember)
            .field("time", &self.time)
            .field("approval_signature", &"[redacted]")
            .finish()
    }
}

impl ApproveRequest {
    /// Check the format of the digest and the signature. `None` means `400 bad_request`.
    pub fn validate(&self) -> Option<ValidApproveRequest> {
        if !valid_digest(&self.digest) {
            return None;
        }
        Some(ValidApproveRequest {
            digest: self.digest.clone(),
            remember: self.remember,
            time: self.time,
            approval_signature: decode_signature(&self.approval_signature)?,
        })
    }
}

// ----- responses -----

/// The answer to a pair request: when the window ends, in Unix seconds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairAccepted {
    pub expires_at: u64,
}

/// The answer to `GET /v1/pair/<device_id>` (contract 5.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum PairStatus {
    /// The owner has not decided yet.
    Waiting,
    /// The owner confirmed. The Mac name is for the phone screen.
    Paired { mac_name: String },
    /// The owner cancelled, or three wrong codes closed the window.
    Denied,
    /// The window ended without an answer.
    Expired,
}

/// The paired device in a status answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub id: String,
    pub name: String,
    pub paired_at: u64,
}

/// The answer to `GET /v1/status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusResponse {
    pub v: u32,
    pub mac_name: String,
    pub app_version: String,
    pub approval_timeout_seconds: u64,
    pub device: DeviceInfo,
}

/// A remember offer of a run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboxRemember {
    pub pattern: String,
    pub approvals: u32,
    pub needed: u32,
}

/// A run that waits, as the phone sees it. Each field comes from the [`PendingRun`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboxRun {
    pub id: String,
    pub agent: String,
    pub command: Vec<String>,
    pub cwd: String,
    pub env_names: Vec<String>,
    pub purpose: String,
    pub risk: String,
    pub user_request: String,
    pub request_source: String,
    pub agent_request: String,
    pub remember: Option<InboxRemember>,
    pub digest: String,
    /// The time since the run started to wait, or `None` when the Mac does not know it.
    pub waiting_seconds: Option<u64>,
}

impl InboxRun {
    /// The phone view of `run`, with its digest.
    pub fn from_pending(run: &PendingRun, waiting_seconds: Option<u64>) -> Self {
        Self {
            id: run.id.to_string(),
            agent: run.agent.clone(),
            command: run.command.clone(),
            cwd: run.cwd.clone(),
            env_names: run.env_names.clone(),
            purpose: run.purpose.clone(),
            risk: run.risk.clone(),
            user_request: run.user_request.clone(),
            request_source: run.request_source.clone(),
            agent_request: run.agent_request.clone(),
            remember: run.remember.as_ref().map(|offer| InboxRemember {
                pattern: offer.pattern.clone(),
                approvals: offer.approvals,
                needed: offer.needed,
            }),
            digest: run_digest_hex(run),
            waiting_seconds,
        }
    }
}

/// An open access request. The phone can deny it and cannot give access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboxAccessRequest {
    pub id: String,
    pub agent: String,
    pub item_name: String,
    pub reason: String,
    /// `None` when the request names no folder.
    pub cwd: Option<String>,
    pub requested_at: u64,
}

impl InboxAccessRequest {
    pub fn from_request(request: &AccessRequest) -> Self {
        Self {
            id: request.id.to_string(),
            agent: request.agent_name.clone(),
            item_name: request.item_name.clone(),
            reason: request.reason.clone(),
            cwd: (!request.cwd.is_empty()).then(|| request.cwd.clone()),
            requested_at: request.created_at,
        }
    }
}

/// An entry of the activity log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboxActivity {
    pub id: String,
    pub at: u64,
    pub agent: String,
    /// `allow`, `deny`, or `error`.
    pub decision: String,
    /// The operation or the command, at most 300 characters.
    pub summary: String,
    /// At most 300 characters.
    pub reason: String,
}

impl InboxActivity {
    pub fn from_record(record: &ActivityRecord) -> Self {
        Self {
            id: record.id.to_string(),
            at: record.at,
            agent: record.agent_name.clone(),
            decision: record.decision.as_str().to_owned(),
            summary: cut_chars(&record.operation, MAX_ACTIVITY_TEXT_CHARS),
            reason: cut_chars(&record.reason, MAX_ACTIVITY_TEXT_CHARS),
        }
    }
}

/// The answer to `GET /v1/inbox`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboxResponse {
    pub runs: Vec<InboxRun>,
    pub access_requests: Vec<InboxAccessRequest>,
    pub activity: Vec<InboxActivity>,
}

/// The answer to an approval, a denial, or an unpairing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutcomeBody {
    pub outcome: String,
}

impl OutcomeBody {
    fn new(outcome: &str) -> Self {
        Self {
            outcome: outcome.to_owned(),
        }
    }

    pub fn approved() -> Self {
        Self::new("approved")
    }

    pub fn approved_and_remembered() -> Self {
        Self::new("approved_and_remembered")
    }

    pub fn denied() -> Self {
        Self::new("denied")
    }

    pub fn unpaired() -> Self {
        Self::new("unpaired")
    }
}

// ----- errors -----

/// The error codes of the contract (section 4). Each has one HTTP status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    BadRequest,
    Unauthorized,
    ClockSkew,
    Unpaired,
    OwnerCheckFailed,
    Stale,
    NotWaiting,
    NotFound,
    Changed,
    NothingToRemember,
    AlreadyPaired,
    TooLarge,
    VaultLocked,
    TooManyRequests,
    Internal,
}

impl ErrorCode {
    pub fn status(self) -> u16 {
        match self {
            Self::BadRequest => 400,
            Self::Unauthorized | Self::ClockSkew | Self::Unpaired => 401,
            Self::OwnerCheckFailed | Self::Stale => 403,
            Self::NotWaiting | Self::NotFound => 404,
            Self::Changed | Self::NothingToRemember | Self::AlreadyPaired => 409,
            Self::TooLarge => 413,
            Self::VaultLocked => 423,
            Self::TooManyRequests => 429,
            Self::Internal => 500,
        }
    }

    /// The `code` string of the body.
    pub fn code(self) -> &'static str {
        match self {
            Self::BadRequest => "bad_request",
            Self::Unauthorized => "unauthorized",
            Self::ClockSkew => "clock_skew",
            Self::Unpaired => "unpaired",
            Self::OwnerCheckFailed => "owner_check_failed",
            Self::Stale => "stale",
            Self::NotWaiting => "not_waiting",
            Self::NotFound => "not_found",
            Self::Changed => "changed",
            Self::NothingToRemember => "nothing_to_remember",
            Self::AlreadyPaired => "already_paired",
            Self::TooLarge => "too_large",
            Self::VaultLocked => "vault_locked",
            Self::TooManyRequests => "too_many_requests",
            Self::Internal => "internal",
        }
    }

    /// The text for the owner. It has no secret value, no vault path, and no key.
    pub fn message(self) -> &'static str {
        match self {
            Self::BadRequest => "The request is not valid. Nothing was changed.",
            Self::Unauthorized => "The Mac did not accept this request. Nothing was changed.",
            Self::ClockSkew => {
                "The clock of the iPhone and the clock of the Mac differ. Nothing was changed."
            }
            Self::Unpaired => "This iPhone is not paired with the Mac. Pair it again.",
            Self::OwnerCheckFailed => {
                "The Face ID confirmation did not match this iPhone. Nothing was approved."
            }
            Self::Stale => "The confirmation is too old. Confirm again. Nothing was approved.",
            Self::NotWaiting => "The run no longer waits. Nothing was approved.",
            Self::NotFound => "Not found. Nothing was changed.",
            Self::Changed => {
                "The request changed after you saw it. Nothing was approved. Review the request again."
            }
            Self::NothingToRemember => {
                "This run cannot teach a pattern. Nothing was approved. Use \"Approve once\"."
            }
            Self::AlreadyPaired => {
                "This iPhone is already paired with the Mac. Nothing was changed."
            }
            Self::TooLarge => "The request is too large. Nothing was changed.",
            Self::VaultLocked => "The vault is locked. Unlock it on the Mac. Nothing was approved.",
            Self::TooManyRequests => "Too many requests. Wait a moment and try again.",
            Self::Internal => "The Mac could not do this. Nothing was approved.",
        }
    }
}

/// The detail in an error body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
}

/// The body of every error: `{"error":{"code":"...","message":"..."}}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: ErrorDetail,
}

impl ErrorBody {
    /// The body with the standard message of `code`.
    pub fn new(code: ErrorCode) -> Self {
        Self::with_message(code, code.message())
    }

    /// The body with another message. The text has no secret value.
    pub fn with_message(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            error: ErrorDetail {
                code: code.code().to_owned(),
                message: message.into(),
            },
        }
    }

    /// The clock skew error. The message names the difference in seconds
    /// (`phone time - Mac time`).
    pub fn clock_skew(difference_seconds: i64) -> Self {
        Self::with_message(
            ErrorCode::ClockSkew,
            format!(
                "The clock of the iPhone differs from the clock of the Mac by {} seconds. Set the time automatically on both devices. Nothing was changed.",
                difference_seconds.unsigned_abs()
            ),
        )
    }

    /// The JSON text of the body.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| {
            r#"{"error":{"code":"internal","message":"The Mac could not do this."}}"#.to_owned()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::approvals::RememberOffer;
    use crate::companion::crypto::tests::{
        APPROVAL_KEY, DEVICE_ID, DEVICE_NAME, PAIR_SIGNATURE_BY_APPROVAL_KEY,
        PAIR_SIGNATURE_BY_REQUEST_KEY, PROOF, REQUEST_KEY,
    };
    use crate::vault::ActivityDecision;

    fn pair_json() -> String {
        format!(
            r#"{{"v":1,"device_id":"{DEVICE_ID}","device_name":"{DEVICE_NAME}","request_key":"{REQUEST_KEY}","approval_key":"{APPROVAL_KEY}","request_key_signature":"{PAIR_SIGNATURE_BY_REQUEST_KEY}","approval_key_signature":"{PAIR_SIGNATURE_BY_APPROVAL_KEY}","proof":"{PROOF}"}}"#
        )
    }

    #[test]
    fn device_ids_are_32_lowercase_hex() {
        assert!(valid_device_id(DEVICE_ID));
        assert!(valid_device_id(&"0".repeat(32)));
        for bad in [
            "",
            &DEVICE_ID[..31],
            &format!("{DEVICE_ID}0"),
            &DEVICE_ID.to_uppercase(),
            &format!("g{}", &DEVICE_ID[1..]),
            &format!(" {}", &DEVICE_ID[1..]),
            &format!("{}\n", &DEVICE_ID[1..]),
        ] {
            assert!(!valid_device_id(bad), "{bad:?}");
        }
    }

    #[test]
    fn device_names_follow_the_contract() {
        for good in [
            "Test iPhone",
            "a",
            &"n".repeat(40),
            "Rafa\u{142}'s iPhone",
            "a b",
            // White space inside a name is fine. Only the two ends are checked.
            "a\u{a0}b",
            "a\u{3000}b",
            // Not `Cc`, not `White_Space`: zero width space, BOM, joiner, combining mark.
            "a\u{200b}",
            "\u{feff}a",
            "a\u{200d}b",
            "e\u{301}",
            "\u{1f600}",
        ] {
            assert!(valid_device_name(good), "{good:?}");
        }
        for bad in [
            "",
            " ",
            " lead",
            "trail ",
            &"n".repeat(41),
            "new\nline",
            "tab\there",
            "nul\u{0}",
            "esc\u{1b}[0m",
            "del\u{7f}",
            "c1\u{85}",
            "c1\u{9f}",
            "\u{85}c1",
        ] {
            assert!(!valid_device_name(bad), "{bad:?}");
        }
        // Any Unicode `White_Space` scalar at the start or at the end is refused, not
        // only the ASCII space.
        for space in [
            '\t', '\n', '\u{b}', '\u{c}', '\r', ' ', '\u{85}', '\u{a0}', '\u{1680}', '\u{2000}',
            '\u{2003}', '\u{200a}', '\u{2028}', '\u{2029}', '\u{202f}', '\u{205f}', '\u{3000}',
        ] {
            assert!(char::is_whitespace(space), "{space:?} is White_Space");
            assert!(
                !valid_device_name(&format!("{space}name")),
                "{space:?} at the start"
            );
            assert!(
                !valid_device_name(&format!("name{space}")),
                "{space:?} at the end"
            );
            assert!(!valid_device_name(&space.to_string()), "{space:?} alone");
        }
        // The limit counts Unicode scalar values, not bytes and not grapheme clusters.
        assert!(valid_device_name(&"\u{142}".repeat(40)));
        assert!(!valid_device_name(&"\u{142}".repeat(41)));
        assert!(valid_device_name(&"\u{1f600}".repeat(40)));
        assert!(!valid_device_name(&"\u{1f600}".repeat(41)));
        assert!(valid_device_name(&"e\u{301}".repeat(20)));
        assert!(!valid_device_name(&"e\u{301}".repeat(21)));
    }

    #[test]
    fn the_time_header_is_at_most_12_digits() {
        assert_eq!(parse_time_header("1790000000"), Some(1_790_000_000));
        assert_eq!(parse_time_header("0"), Some(0));
        assert_eq!(parse_time_header("999999999999"), Some(999_999_999_999));
        for bad in [
            "",
            "9999999999999",
            "-1",
            "+1",
            "1.5",
            " 1",
            "1 ",
            "1e3",
            "\u{661}",
            "0x10",
        ] {
            assert_eq!(parse_time_header(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn the_nonce_is_22_characters_of_16_bytes() {
        assert_eq!(
            parse_nonce("AAECAwQFBgcICQoLDA0ODw"),
            Some([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
        );
        for bad in [
            "",
            "AAECAwQFBgcICQoLDA0OD",
            "AAECAwQFBgcICQoLDA0ODw=",
            "AAECAwQFBgcICQoLDA0ODw==",
            "AAECAwQFBgcICQoLDA0ODwA",
            // 22 characters with a set bit in the unused part.
            "AAECAwQFBgcICQoLDA0ODx",
            "AAECAwQFBgcICQoLDA0OD+",
            "AAECAwQFBgcICQoLDA0OD/",
        ] {
            assert_eq!(parse_nonce(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn decimal_ids() {
        assert_eq!(parse_id("123456789012345"), Some(123_456_789_012_345));
        assert_eq!(parse_id("1"), Some(1));
        assert_eq!(parse_id("18446744073709551615"), Some(u64::MAX));
        for bad in [
            "",
            "0",
            "01",
            "-1",
            "+1",
            "1.0",
            "18446744073709551616",
            "123456789012345678901",
            "1 ",
            "0x1",
        ] {
            assert_eq!(parse_id(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn keys_and_signatures_have_fixed_shapes() {
        assert!(decode_public_key(REQUEST_KEY).is_some());
        assert!(decode_public_key(APPROVAL_KEY).is_some());
        assert!(decode_public_key("AAAA").is_none());
        assert!(decode_public_key(&format!("{REQUEST_KEY}A")).is_none());
        assert!(decode_public_key(&format!("{REQUEST_KEY}=")).is_none());
        // A first byte other than 0x04.
        let mut key = decode_public_key(REQUEST_KEY).expect("key");
        key[0] = 0x02;
        assert!(decode_public_key(&crate::native::base64::encode_url(&key)).is_none());
        assert!(decode_signature(PAIR_SIGNATURE_BY_REQUEST_KEY).is_some());
        assert!(decode_signature("").is_none());
        assert!(decode_signature("AAAA").is_none());
        assert!(decode_signature(&"A".repeat(100)).is_none());
        assert!(decode_signature(&format!("{PAIR_SIGNATURE_BY_REQUEST_KEY}=")).is_none());
    }

    #[test]
    fn a_pair_request_parses_and_validates() {
        let request: PairRequest = parse_body(pair_json().as_bytes()).expect("parse");
        let valid = request.validate().expect("valid");
        assert_eq!(valid.device_id, DEVICE_ID);
        assert_eq!(valid.device_name, DEVICE_NAME);
        assert_eq!(valid.request_key.len(), 65);
        assert_eq!(valid.proof.len(), 32);
        let debug = format!("{request:?} {valid:?}");
        assert!(!debug.contains(PROOF), "{debug}");
        assert!(!debug.contains(PAIR_SIGNATURE_BY_REQUEST_KEY), "{debug}");
    }

    #[test]
    fn a_pair_request_with_a_bad_field_is_refused() {
        let good = pair_json();
        let cases = [
            good.replace(r#""v":1"#, r#""v":2"#),
            good.replace(DEVICE_ID, "D4C0FFEE00000000000000000000BEEF"),
            good.replace(DEVICE_NAME, " Test iPhone"),
            good.replace(DEVICE_NAME, "Test\\niPhone"),
            good.replace(PROOF, "AAAA"),
            good.replace(REQUEST_KEY, APPROVAL_KEY).replace(
                &format!(r#""approval_key":"{APPROVAL_KEY}""#),
                r#""approval_key":"AAAA""#,
            ),
            good.replace(PAIR_SIGNATURE_BY_REQUEST_KEY, "AAAA"),
        ];
        for case in &cases {
            let request: PairRequest = parse_body(case.as_bytes()).expect("still parses");
            assert!(request.validate().is_none(), "{case}");
        }
    }

    #[test]
    fn request_bodies_refuse_unknown_missing_duplicate_and_wrong_shaped_fields() {
        let good = pair_json();
        let unknown = good.replace(r#""v":1"#, r#""v":1,"extra":true"#);
        assert!(parse_body::<PairRequest>(unknown.as_bytes()).is_none());
        let missing = good.replace(r#""v":1,"#, "");
        assert!(parse_body::<PairRequest>(missing.as_bytes()).is_none());
        let duplicate = good.replace(r#""v":1"#, r#""v":1,"v":1"#);
        assert!(parse_body::<PairRequest>(duplicate.as_bytes()).is_none());
        let number = good.replace(r#""v":1"#, r#""v":"1""#);
        assert!(parse_body::<PairRequest>(number.as_bytes()).is_none());
        // The array form that serde would read for a struct.
        let array = format!(
            r#"[1,"{DEVICE_ID}","{DEVICE_NAME}","{REQUEST_KEY}","{APPROVAL_KEY}","{PAIR_SIGNATURE_BY_REQUEST_KEY}","{PAIR_SIGNATURE_BY_APPROVAL_KEY}","{PROOF}"]"#
        );
        assert!(parse_body::<PairRequest>(array.as_bytes()).is_none());
        assert!(parse_body::<PairRequest>(b"").is_none());
        assert!(parse_body::<PairRequest>(b"not json").is_none());
        assert!(parse_body::<PairRequest>(&[0xff, 0xfe]).is_none());
        assert!(parse_body::<PairRequest>(format!("{good} x").as_bytes()).is_none());
        assert!(parse_body::<PairRequest>(format!(" \n{good}\n").as_bytes()).is_some());
    }

    #[test]
    fn an_approve_request_parses_and_validates() {
        let digest = "ab".repeat(32);
        let body = format!(
            r#"{{"digest":"{digest}","remember":false,"time":1790000000,"approval_signature":"{PAIR_SIGNATURE_BY_APPROVAL_KEY}"}}"#
        );
        let request: ApproveRequest = parse_body(body.as_bytes()).expect("parse");
        let valid = request.validate().expect("valid");
        assert_eq!(valid.digest, digest);
        assert!(!valid.remember);
        assert_eq!(valid.time, 1_790_000_000);
        assert!(!format!("{request:?} {valid:?}").contains(PAIR_SIGNATURE_BY_APPROVAL_KEY));

        for changed in [
            body.replace(&digest, &"AB".repeat(32)),
            body.replace(&digest, &"ab".repeat(31)),
            body.replace(PAIR_SIGNATURE_BY_APPROVAL_KEY, "AAAA"),
        ] {
            let request: ApproveRequest = parse_body(changed.as_bytes()).expect("parses");
            assert!(request.validate().is_none(), "{changed}");
        }
        for refused in [
            body.replace(r#""remember":false"#, r#""remember":"no""#),
            body.replace(r#""time":1790000000"#, r#""time":-1"#),
            body.replace(r#""time":1790000000"#, r#""time":"1790000000""#),
            body.replace(r#""remember":false,"#, ""),
            body.replace(r#""time""#, r#""extra":1,"time""#),
        ] {
            assert!(
                parse_body::<ApproveRequest>(refused.as_bytes()).is_none(),
                "{refused}"
            );
        }
    }

    #[test]
    fn empty_bodies_are_the_empty_object_only() {
        assert!(is_empty_object(b"{}"));
        assert!(is_empty_object(b" { } "));
        for bad in [
            &b""[..],
            b"[]",
            b"null",
            b"{\"a\":1}",
            b"{} {}",
            b"0",
            b"\"{}\"",
        ] {
            assert!(!is_empty_object(bad), "{:?}", String::from_utf8_lossy(bad));
        }
    }

    fn sample_run() -> PendingRun {
        PendingRun {
            id: 123_456_789_012_345,
            agent: "claude-code".to_owned(),
            command: vec!["npm".to_owned(), "run".to_owned(), "migrate".to_owned()],
            cwd: "/tmp/synthetic-shop".to_owned(),
            env_names: vec!["DATABASE_URL".to_owned()],
            purpose: "Apply the new migration.".to_owned(),
            risk: "production credential: always asks the owner".to_owned(),
            user_request: "Deploy the new schema to staging.".to_owned(),
            request_source: "from the host hook".to_owned(),
            agent_request: String::new(),
            remember: Some(RememberOffer {
                pattern: "npm run migrate".to_owned(),
                approvals: 1,
                needed: 3,
            }),
        }
    }

    #[test]
    fn an_inbox_run_has_the_contract_fields_and_string_ids() {
        let run = sample_run();
        let view = InboxRun::from_pending(&run, Some(12));
        let json = serde_json::to_value(&view).expect("json");
        assert_eq!(json["id"], "123456789012345");
        assert_eq!(
            json["command"],
            serde_json::json!(["npm", "run", "migrate"])
        );
        assert_eq!(json["env_names"], serde_json::json!(["DATABASE_URL"]));
        assert_eq!(
            json["remember"],
            serde_json::json!({"pattern": "npm run migrate", "approvals": 1, "needed": 3})
        );
        assert_eq!(json["waiting_seconds"], 12);
        assert_eq!(json["digest"], run_digest_hex(&run));
        let mut keys: Vec<&str> = json
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "agent",
                "agent_request",
                "command",
                "cwd",
                "digest",
                "env_names",
                "id",
                "purpose",
                "remember",
                "request_source",
                "risk",
                "user_request",
                "waiting_seconds"
            ]
        );
        let none = InboxRun::from_pending(
            &PendingRun {
                remember: None,
                ..run
            },
            None,
        );
        let json = serde_json::to_value(&none).expect("json");
        assert!(json["remember"].is_null());
        assert!(json["waiting_seconds"].is_null());
        assert_ne!(none.digest, view.digest);
    }

    #[test]
    fn activity_and_access_requests_have_string_ids_and_cut_text() {
        let record = ActivityRecord {
            id: 991,
            at: 1_790_000_000,
            agent_id: Some(1),
            agent_name: "claude-code".to_owned(),
            item_id: Some(2),
            operation: "s".repeat(400),
            decision: ActivityDecision::Deny,
            reason: "r\u{142}".repeat(200),
        };
        let view = InboxActivity::from_record(&record);
        assert_eq!(view.id, "991");
        assert_eq!(view.decision, "deny");
        assert_eq!(view.summary.chars().count(), 300);
        assert_eq!(view.reason.chars().count(), 300);
        let json = serde_json::to_value(&view).expect("json");
        assert_eq!(json["id"], "991");
        assert!(json.get("item_id").is_none() && json.get("agent_id").is_none());

        let request = AccessRequest {
            id: 42,
            agent_id: 1,
            agent_name: "codex".to_owned(),
            item_id: 5,
            item_name: "Synthetic test key".to_owned(),
            reason: "The user asked me to test checkout.".to_owned(),
            cwd: String::new(),
            created_at: 1_790_000_000,
            state: crate::vault::RequestState::Open,
        };
        let view = InboxAccessRequest::from_request(&request);
        assert_eq!(view.id, "42");
        assert_eq!(view.cwd, None);
        let json = serde_json::to_value(&view).expect("json");
        assert!(json["cwd"].is_null());
        let with_cwd = AccessRequest {
            cwd: "/tmp/shop".to_owned(),
            ..request
        };
        assert_eq!(
            InboxAccessRequest::from_request(&with_cwd).cwd.as_deref(),
            Some("/tmp/shop")
        );
    }

    #[test]
    fn pair_status_and_outcome_bodies_match_the_contract() {
        assert_eq!(
            serde_json::to_string(&PairStatus::Waiting).unwrap(),
            r#"{"state":"waiting"}"#
        );
        assert_eq!(
            serde_json::to_string(&PairStatus::Paired {
                mac_name: "Mac mini".to_owned()
            })
            .unwrap(),
            r#"{"state":"paired","mac_name":"Mac mini"}"#
        );
        assert_eq!(
            serde_json::to_string(&PairStatus::Denied).unwrap(),
            r#"{"state":"denied"}"#
        );
        assert_eq!(
            serde_json::to_string(&PairStatus::Expired).unwrap(),
            r#"{"state":"expired"}"#
        );
        assert_eq!(
            serde_json::to_string(&PairAccepted {
                expires_at: 1_790_000_300
            })
            .unwrap(),
            r#"{"expires_at":1790000300}"#
        );
        assert_eq!(
            serde_json::to_string(&OutcomeBody::approved_and_remembered()).unwrap(),
            r#"{"outcome":"approved_and_remembered"}"#
        );
        for (body, text) in [
            (OutcomeBody::approved(), "approved"),
            (OutcomeBody::denied(), "denied"),
            (OutcomeBody::unpaired(), "unpaired"),
        ] {
            assert_eq!(body.outcome, text);
        }
        let status = StatusResponse {
            v: 1,
            mac_name: "Mac mini".to_owned(),
            app_version: "0.2.1".to_owned(),
            approval_timeout_seconds: 120,
            device: DeviceInfo {
                id: DEVICE_ID.to_owned(),
                name: DEVICE_NAME.to_owned(),
                paired_at: 1_790_000_000,
            },
        };
        assert_eq!(
            serde_json::to_string(&status).unwrap(),
            r#"{"v":1,"mac_name":"Mac mini","app_version":"0.2.1","approval_timeout_seconds":120,"device":{"id":"d4c0ffee00000000000000000000beef","name":"Test iPhone","paired_at":1790000000}}"#
        );
    }

    #[test]
    fn errors_have_the_status_code_and_a_message_that_says_nothing_was_done() {
        let table = [
            (ErrorCode::BadRequest, 400, "bad_request"),
            (ErrorCode::Unauthorized, 401, "unauthorized"),
            (ErrorCode::ClockSkew, 401, "clock_skew"),
            (ErrorCode::Unpaired, 401, "unpaired"),
            (ErrorCode::OwnerCheckFailed, 403, "owner_check_failed"),
            (ErrorCode::Stale, 403, "stale"),
            (ErrorCode::NotWaiting, 404, "not_waiting"),
            (ErrorCode::NotFound, 404, "not_found"),
            (ErrorCode::Changed, 409, "changed"),
            (ErrorCode::NothingToRemember, 409, "nothing_to_remember"),
            (ErrorCode::AlreadyPaired, 409, "already_paired"),
            (ErrorCode::TooLarge, 413, "too_large"),
            (ErrorCode::VaultLocked, 423, "vault_locked"),
            (ErrorCode::TooManyRequests, 429, "too_many_requests"),
            (ErrorCode::Internal, 500, "internal"),
        ];
        for (code, status, name) in table {
            assert_eq!(code.status(), status, "{name}");
            assert_eq!(code.code(), name);
            let body = ErrorBody::new(code);
            let json: serde_json::Value = serde_json::from_str(&body.to_json()).expect("json");
            assert_eq!(json["error"]["code"], name);
            assert_eq!(json["error"]["message"], code.message());
            assert_eq!(json.as_object().expect("object").len(), 1);
        }
        assert_eq!(
            ErrorBody::new(ErrorCode::NotWaiting).to_json(),
            r#"{"error":{"code":"not_waiting","message":"The run no longer waits. Nothing was approved."}}"#
        );
        let skew = ErrorBody::clock_skew(-125);
        assert_eq!(skew.error.code, "clock_skew");
        assert!(skew.error.message.contains("125 seconds"));
    }
}
