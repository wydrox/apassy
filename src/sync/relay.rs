//! Sync of a vault through the Apassy relay (ADR 0022, contract relay-sync-v1).
//!
//! The relay keeps one opaque, device-signed, versioned copy per vault: the same
//! stripped SQLCipher copy that a folder gets. A push is a compare-and-swap on the
//! version (`If-Match`). A `412` means that another Mac pushed first: the engine
//! fetches, merges, and pushes again, at most three rounds.
//!
//! Before a merge the Mac checks the head of the copy (section 13): a device of the
//! team signed it (a removed device only for the versions it pushed while it was a
//! member), the vault is this vault, the version is above the one this Mac saw last
//! (its anchor), and the chain of heads since the anchor links to the anchor. A Mac with
//! no anchor accepts the current head behind the owner's explicit action.
//!
//! The device key is in the vault (`Vault::relay_device`), so the app signs in and
//! syncs only while the vault is unlocked. [`RelaySync::forget`] drops the key and the
//! access token from memory at a lock, and ends every relay call of the session in
//! flight: a long poll, a download, an upload, a device call. A download or an upload
//! also ends after `TRANSFER_LIMIT`, and an upload starts with a token that lasts that
//! long.
//!
//! [`RelaySync::sync_shared`] takes the shared vault slot of the app and holds its
//! mutex only to read the vault, to merge, and to write the sync copy: every relay call
//! runs without it. One sync of a vault runs at a time (a clone shares the guard): a
//! `*_shared` call waits for the one that runs, and a call with the vault in hand
//! (`&mut Vault`, the vault mutex may be held) does not wait: it fails with
//! [`SyncError::Running`]. [`RelaySync::pause`] and [`RelaySync::stop_runs`] end the
//! sync that runs and keep others out until [`RelaySync::resume`], for "Turn off".
//!
//! The team and device calls (a new team, "Add a Mac", the device list) are in
//! [`devices`].

mod devices;

pub use devices::{DeviceView, KeySource, LinkCode, PendingLink};

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Seek;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError, TryLockError};
use std::time::{Duration, Instant};

use serde::de::{DeserializeOwned, IgnoredAny};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

use super::relay_crypto::{
    DeviceKey, HeadFields, MAX_SNAPSHOT_BYTES, NO_PREVIOUS, SignedHead, decode_b64u, hash_from_hex,
    link_code_team, safety_words, same_words, sha256_hex, sign_in_message, valid_team_code,
    valid_team_id,
};
use super::relay_http::{self, Answer, Body, Cancel, HttpError, RelayUrl, Request};
use super::state::{self, SyncState, TransportKind};
use super::transport::{Precondition, Remote, RemoteHead, SyncTransport};
use super::{RelayRefusal, SyncError, SyncOutcome, TempFile, copy_error, device_name, unix_now};
use crate::vault::{
    MergeReport, RelayDevice, SyncIdentity, SyncScope, Vault, VaultErrorKind, to_hex,
};
use crate::vaults::RelayLink;

/// A sync tries at most this many pushes before it leaves the change for the next one.
const MAX_ROUNDS: usize = 3;
/// A `503 busy` is tried again at most this many times.
const BUSY_RETRIES: usize = 3;
/// The longest wait for `Retry-After` of a `503`.
const MAX_BUSY_WAIT: Duration = Duration::from_secs(5);
/// The wait after a `429` without `Retry-After`, and the longest one honoured.
const RATE_WAIT: u64 = 60;
const MAX_RATE_WAIT: u64 = 300;
/// A chain answer has at most 1000 heads, oldest first; a Mac reads at most this many
/// answers (the relay keeps 10000 heads).
const MAX_CHAIN_PAGES: usize = 20;
/// The longest long poll that the relay holds.
pub(crate) const MAX_WAIT: Duration = Duration::from_secs(25);
/// An access token lasts 15 minutes.
const TOKEN_LIFETIME: Duration = Duration::from_secs(15 * 60);
/// The app signs in again when less than this is left of a token.
const TOKEN_MARGIN: Duration = Duration::from_secs(60);
/// A device that the relay refused asks the relay again after this long: the relay
/// gives the same `401` while it is suspended or stops (contract section 13).
pub(crate) const REMOVED_PROBE_EVERY: Duration = Duration::from_secs(15 * 60);
/// A team name and a device name have at most this many bytes.
const MAX_NAME_BYTES: usize = 64;
/// A pending join waits this long after a failed poll, doubling up to the second value.
const JOIN_RETRY_FIRST: Duration = Duration::from_secs(2);
const JOIN_RETRY_MAX: Duration = Duration::from_secs(60);
/// The first capacity of a JSON request body. A small body never moves.
const REQUEST_CAPACITY: usize = 4096;
/// A download or an upload of a snapshot ends after this long, whatever it is doing.
pub(crate) const TRANSFER_LIMIT: Duration = Duration::from_secs(10 * 60);

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// `text` trimmed, without control characters, cut to 64 bytes at a character
/// boundary. An empty result is `fallback`.
pub(crate) fn clean_name(text: &str, fallback: &str) -> String {
    let mut name = String::new();
    for ch in text.trim().chars().filter(|ch| !ch.is_control()) {
        if name.len() + ch.len_utf8() > MAX_NAME_BYTES {
            break;
        }
        name.push(ch);
    }
    let name = name.trim().to_owned();
    if name.is_empty() {
        fallback.to_owned()
    } else {
        name
    }
}

// ---- Calls. ----

/// Why a relay call failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ApiError {
    /// No relay answered, or something that is not the relay (no JSON envelope).
    Unreachable,
    /// The connection broke after the request started. A push may have landed.
    Broken,
    /// The relay answered with an error envelope.
    Relay {
        status: u16,
        code: String,
        retry_after: Option<u64>,
    },
    /// A failure on this Mac, before or after the call.
    Sync(SyncError),
}

impl From<SyncError> for ApiError {
    fn from(error: SyncError) -> Self {
        Self::Sync(error)
    }
}

/// The error of a call for the owner.
pub(crate) fn sync_error(error: ApiError) -> SyncError {
    match error {
        ApiError::Unreachable | ApiError::Broken => SyncError::RelayUnreachable,
        ApiError::Sync(error) => error,
        ApiError::Relay { status, code, .. } => match (status, code.as_str()) {
            (401, _) => SyncError::RemovedFromRelay,
            (412, _) => SyncError::PreconditionFailed,
            (413, _) => SyncError::TooLarge,
            (403, "invite_invalid") => SyncError::Relay(RelayRefusal::InviteInvalid),
            (403, "join_pending") => SyncError::Relay(RelayRefusal::JoinPending),
            (403, "join_refused") => SyncError::Relay(RelayRefusal::JoinRefused),
            (403, "sync_head_invalid") => SyncError::Relay(RelayRefusal::HeadInvalid),
            (403, "team_limit") => SyncError::Relay(RelayRefusal::TeamLimit),
            (403, _) => SyncError::Relay(RelayRefusal::Forbidden),
            (400, _) => SyncError::Relay(RelayRefusal::InvalidRequest),
            (404, _) => SyncError::Relay(RelayRefusal::NotFound),
            (409, _) => SyncError::Relay(RelayRefusal::Conflict),
            (429, _) => SyncError::Relay(RelayRefusal::RateLimited),
            (503, _) => SyncError::Relay(RelayRefusal::Busy),
            _ => SyncError::Relay(RelayRefusal::Error),
        },
    }
}

/// Whether a failure can pass by itself: the network, a busy or limiting relay, a
/// relay error, or another sync of the vault that runs.
pub(crate) fn is_transient(error: SyncError) -> bool {
    matches!(
        error,
        SyncError::RelayUnreachable
            | SyncError::RelayBusy
            | SyncError::Running
            | SyncError::Relay(
                RelayRefusal::RateLimited | RelayRefusal::Busy | RelayRefusal::Error
            )
    )
}

/// Whether a copy that failed to download or to merge with `error` fails the same way
/// again: it needs the new passphrase, it is damaged or too large, it holds another
/// vault, or it has a newer schema than this app. The network, a lock, and a file
/// error on this Mac can pass.
fn sticks(error: SyncError) -> bool {
    matches!(
        error,
        SyncError::NeedsPassphrase
            | SyncError::Damaged
            | SyncError::OtherVault
            | SyncError::TooLarge
            | SyncError::Vault(VaultErrorKind::UnsupportedSchema)
    )
}

#[derive(Deserialize)]
struct ErrorBody {
    #[serde(default)]
    code: String,
}

/// The JSON envelope of every answer, read straight from the answer bytes: no copy of
/// a token or a code stays in an intermediate value.
#[derive(Deserialize)]
struct Envelope<T> {
    ok: bool,
    #[serde(default = "Option::default")]
    result: Option<T>,
    #[serde(default)]
    error: Option<ErrorBody>,
}

/// The `result` of a `{"ok":true,...}` envelope as `T`, or the error of the answer.
fn decode<T: DeserializeOwned>(answer: &Answer) -> Result<T, ApiError> {
    let envelope: Envelope<T> =
        serde_json::from_slice(&answer.body).map_err(|_| ApiError::Unreachable)?;
    match envelope.ok {
        true if (200..300).contains(&answer.status) => match envelope.result {
            Some(result) => Ok(result),
            None => T::deserialize(Value::Null).map_err(|_| ApiError::Unreachable),
        },
        false if answer.status >= 400 => Err(ApiError::Relay {
            status: answer.status,
            code: envelope
                .error
                .map(|error| error.code)
                .filter(|code| !code.is_empty())
                .unwrap_or_else(|| "relay_error".to_owned()),
            retry_after: answer
                .header("retry-after")
                .and_then(|text| text.parse().ok()),
        }),
        _ => Err(ApiError::Unreachable),
    }
}

/// The `result` of a `{"ok":true,...}` envelope, or the error of the answer.
#[cfg(test)]
fn envelope(answer: &Answer) -> Result<Value, ApiError> {
    decode(answer)
}

fn http_error(error: HttpError) -> ApiError {
    match error {
        HttpError::Connect | HttpError::Protocol => ApiError::Unreachable,
        HttpError::Broken => ApiError::Broken,
    }
}

/// When each relay may be asked again after a `429` (contract section 3).
fn rate_limits() -> &'static Mutex<BTreeMap<String, Instant>> {
    static LIMITS: OnceLock<Mutex<BTreeMap<String, Instant>>> = OnceLock::new();
    LIMITS.get_or_init(Mutex::default)
}

/// The time left before `url` may be asked again, when a `429` asked to wait.
pub(crate) fn rate_limited(url: &RelayUrl) -> Option<Duration> {
    let mut limits = lock(rate_limits());
    let left = limits
        .get(url.as_str())
        .map(|until| until.saturating_duration_since(Instant::now()));
    match left {
        Some(left) if !left.is_zero() => Some(left),
        Some(_) => {
            limits.remove(url.as_str());
            None
        }
        None => None,
    }
}

fn rate_limit_error(left: Duration) -> ApiError {
    ApiError::Relay {
        status: 429,
        code: "rate_limited".to_owned(),
        retry_after: Some(left.as_secs().max(1)),
    }
}

/// Sleep `wait` in short steps. False when the cancel of `request` closes, or when its
/// deadline comes first.
fn pause(request: &Request<'_>, wait: Duration) -> bool {
    let end = Instant::now() + wait;
    if request.deadline.is_some_and(|deadline| deadline < end) {
        return false;
    }
    loop {
        if request.cancel.is_some_and(Cancel::is_closed) {
            return false;
        }
        let left = end.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return true;
        }
        std::thread::sleep(left.min(Duration::from_millis(50)));
    }
}

/// One call with the retries of `503 busy`. A `429` makes every call to that relay
/// fail at once, without the network, until its `Retry-After` passed (contract
/// section 3). A cancel or a deadline ends the wait before a retry.
fn call<T: DeserializeOwned>(url: &RelayUrl, request: &Request<'_>) -> Result<T, ApiError> {
    let mut attempt = 0;
    loop {
        if let Some(left) = rate_limited(url) {
            return Err(rate_limit_error(left));
        }
        let answer = relay_http::exchange(url, request).map_err(http_error)?;
        let result = decode(&answer);
        if let Err(ApiError::Relay {
            status: 503,
            retry_after,
            ..
        }) = &result
            && attempt < BUSY_RETRIES
        {
            let wait = Duration::from_secs(retry_after.unwrap_or(2)).min(MAX_BUSY_WAIT);
            if !pause(request, wait) {
                return result;
            }
            attempt += 1;
            continue;
        }
        match result {
            Err(ApiError::Relay {
                status: 429,
                retry_after,
                ..
            }) => {
                let wait =
                    Duration::from_secs(retry_after.unwrap_or(RATE_WAIT).clamp(1, MAX_RATE_WAIT));
                lock(rate_limits()).insert(url.as_str().to_owned(), Instant::now() + wait);
                return Err(rate_limit_error(wait));
            }
            other => return other,
        }
    }
}

/// A JSON request. The body is written into a buffer that is erased on drop: it can
/// hold a team code or a link code.
fn json_request<'a>(
    method: &'static str,
    path: &str,
    bearer: Option<&'a str>,
    body: &impl Serialize,
) -> Request<'a> {
    let mut request = Request::new(method, path.to_owned(), bearer);
    let mut bytes = Zeroizing::new(Vec::with_capacity(REQUEST_CAPACITY));
    if serde_json::to_writer(&mut *bytes, body).is_err() {
        bytes.clear();
    }
    request.body = Body::Json(bytes);
    request
}

// ---- Sign-in. ----

#[derive(Deserialize)]
struct Challenge {
    nonce: String,
    origin: String,
}

#[derive(Deserialize)]
struct TokenAnswer {
    token: String,
    expires_at: u64,
    team_id: String,
    device_id: u64,
}

struct Token {
    value: Zeroizing<String>,
    until: Instant,
}

/// The mark of a device that the relay refused (contract section 13): a challenge got
/// `401`, or a call got `401` again after a new sign-in. While it holds, no sign-in asks
/// the relay; after [`REMOVED_PROBE_EVERY`] one sign-in may ask again, and a sign-in
/// that works clears it.
#[derive(Debug)]
pub(crate) struct Removal {
    /// When a sign-in may ask the relay again; `None` while the device is not marked.
    until: Mutex<Option<Instant>>,
    every: Duration,
}

impl Removal {
    fn new(every: Duration) -> Self {
        Self {
            until: Mutex::new(None),
            every,
        }
    }

    /// When a sign-in may ask the relay again, while the relay refused the device and no
    /// sign-in worked since.
    pub(crate) fn until(&self) -> Option<Instant> {
        *lock(&self.until)
    }

    /// Whether a sign-in must not ask the relay now.
    fn holds(&self) -> bool {
        lock(&self.until).is_some_and(|until| Instant::now() < until)
    }

    /// The relay refused the device now.
    fn note(&self) {
        *lock(&self.until) = Some(Instant::now() + self.every);
    }

    /// Take the mark of another session, the later time of the two.
    fn note_until(&self, until: Instant) {
        let mut held = lock(&self.until);
        *held = Some(held.map_or(until, |held| held.max(until)));
    }

    /// The next sign-in may ask the relay now: an action of the owner.
    fn ask_now(&self) {
        if let Some(until) = lock(&self.until).as_mut() {
            *until = Instant::now();
        }
    }

    fn clear(&self) {
        *lock(&self.until) = None;
    }
}

/// A device of one team on one relay: its key, and an access token while it lasts.
/// Debug is redacted.
pub(crate) struct Session {
    url: RelayUrl,
    team_id: String,
    key: DeviceKey,
    device_id: Mutex<Option<u64>>,
    token: Mutex<Option<Token>>,
    devices: Mutex<Option<Vec<DeviceView>>>,
    /// Ends every call in flight and refuses every later one: the vault locked.
    cancel: Cancel,
    /// Set when the relay refused this device ([`Removal`]). [`RelaySync`] shares it
    /// with each session of its vault, so it outlives a lock.
    removed: Arc<Removal>,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("url", &self.url.as_str())
            .field("team_id", &self.team_id)
            .finish_non_exhaustive()
    }
}

impl Session {
    pub(crate) fn new(
        url: RelayUrl,
        team_id: &str,
        key: DeviceKey,
        device_id: Option<u64>,
    ) -> Self {
        Self {
            url,
            team_id: team_id.to_owned(),
            key,
            device_id: Mutex::new(device_id),
            token: Mutex::new(None),
            devices: Mutex::new(None),
            cancel: Cancel::default(),
            removed: Arc::new(Removal::new(REMOVED_PROBE_EVERY)),
        }
    }

    /// The session with the removal mark `removed` of its relay sync.
    fn sharing_removed(mut self, removed: &Arc<Removal>) -> Self {
        self.removed = Arc::clone(removed);
        self
    }

    pub(crate) fn device_id(&self) -> Option<u64> {
        *lock(&self.device_id)
    }

    /// Let the next sign-in ask the relay, also when it refused this device a moment
    /// ago: for an action of the owner, as "Turn off".
    pub(crate) fn ask_again(&self) {
        self.removed.ask_now();
    }

    /// Note a `401` that means "removed" and pass the error on.
    fn note_removed(&self, error: ApiError) -> ApiError {
        if matches!(error, ApiError::Relay { status: 401, .. }) {
            self.removed.note();
        }
        error
    }

    /// The vault locked: drop the token, end the calls in flight, and refuse every later
    /// call. The key goes with the last holder of this value.
    fn close(&self) {
        self.cancel.close();
        *lock(&self.token) = None;
        *lock(&self.devices) = None;
    }

    /// Let [`Self::close`] end `request`, and end it by `deadline`.
    fn bind<'a>(&'a self, request: &mut Request<'a>, deadline: Option<Instant>) {
        request.cancel = Some(&self.cancel);
        request.deadline = deadline;
    }

    /// Challenge and token (contract section 5). A `403 join_pending` is
    /// `Relay(JoinPending)`.
    fn sign_in(&self, deadline: Option<Instant>) -> Result<Token, ApiError> {
        let public_key = self.key.public_key_b64u();
        let mut request = json_request(
            "POST",
            "/v1/auth/challenge",
            None,
            &serde_json::json!({"team_id": self.team_id, "public_key": public_key}),
        );
        self.bind(&mut request, deadline);
        // A challenge for a key that is no live device of the team gets `401`.
        let challenge: Challenge =
            call(&self.url, &request).map_err(|error| self.note_removed(error))?;
        if challenge.origin.trim_end_matches('/') != self.url.as_str() {
            return Err(SyncError::OriginMismatch.into());
        }
        if decode_b64u(&challenge.nonce).is_none_or(|nonce| nonce.len() != 32) {
            return Err(ApiError::Unreachable);
        }
        let message = sign_in_message(
            self.url.as_str(),
            &self.team_id,
            &public_key,
            &challenge.nonce,
        );
        let signature = super::relay_crypto::encode_b64u(&self.key.sign(&message)?);
        let mut request = json_request(
            "POST",
            "/v1/auth/token",
            None,
            &serde_json::json!({
                "team_id": self.team_id,
                "public_key": public_key,
                "nonce": challenge.nonce,
                "signature": signature,
            }),
        );
        self.bind(&mut request, deadline);
        // A `401` here is a sign-in that failed (the nonce ended, the relay started
        // again), not a removal (contract section 5): it passes by itself.
        let answer: TokenAnswer = call(&self.url, &request).map_err(|error| match error {
            ApiError::Relay { status: 401, .. } => SyncError::Relay(RelayRefusal::Error).into(),
            other => other,
        })?;
        let token = Zeroizing::new(answer.token);
        let prefix = format!("apassy_acc_{}_", self.team_id);
        if answer.team_id != self.team_id
            || !token.starts_with(&prefix)
            || !token[prefix.len()..].bytes().all(|b| b.is_ascii_hexdigit())
            || answer.device_id == 0
        {
            return Err(ApiError::Unreachable);
        }
        let mut device_id = lock(&self.device_id);
        match *device_id {
            Some(known) if known != answer.device_id => {
                return Err(SyncError::WrongVault.into());
            }
            _ => *device_id = Some(answer.device_id),
        }
        drop(device_id);
        // The relay knows this device: a mark of an earlier refusal goes.
        self.removed.clear();
        let left = answer.expires_at.saturating_sub(unix_now());
        Ok(Token {
            value: token,
            until: Instant::now() + Duration::from_secs(left).min(TOKEN_LIFETIME),
        })
    }

    /// The access token: the one in memory, or a new sign-in that ends by `deadline`. A
    /// closed session signs in no more.
    fn bearer(&self, deadline: Option<Instant>) -> Result<Zeroizing<String>, ApiError> {
        self.bearer_until(deadline, None)
    }

    /// [`Self::bearer`] with a token in memory only when it lasts past `until` too: an
    /// upload needs a token that lasts to its end, since the relay reads it again after
    /// the body (contract section 5).
    fn bearer_until(
        &self,
        deadline: Option<Instant>,
        until: Option<Instant>,
    ) -> Result<Zeroizing<String>, ApiError> {
        if self.cancel.is_closed() {
            return Err(SyncError::Vault(VaultErrorKind::Locked).into());
        }
        // A removed device signs in no more until its next try ([`Removal`]), the owner
        // turns sync off, or joins again (contract section 13).
        if self.removed.holds() {
            return Err(SyncError::RemovedFromRelay.into());
        }
        let margin = Instant::now() + TOKEN_MARGIN;
        let needed = until.map_or(margin, |until| until.max(margin));
        if let Some(token) = lock(&self.token).as_ref()
            && token.until > needed
        {
            return Ok(token.value.clone());
        }
        let token = self.sign_in(deadline)?;
        let value = token.value.clone();
        if !self.cancel.is_closed() {
            *lock(&self.token) = Some(token);
        }
        Ok(value)
    }

    /// A call with the access token. A `401` signs in again once and repeats the call
    /// once; a second `401` stays, means "Removed from the relay", and holds the
    /// sign-ins of this device ([`Removal`]).
    pub(crate) fn authed<T>(
        &self,
        call: impl Fn(&str) -> Result<T, ApiError>,
    ) -> Result<T, ApiError> {
        self.authed_by(None, call)
    }

    /// [`Self::authed`] with a sign-in that ends by `deadline`.
    pub(crate) fn authed_by<T>(
        &self,
        deadline: Option<Instant>,
        call: impl Fn(&str) -> Result<T, ApiError>,
    ) -> Result<T, ApiError> {
        self.authed_until(deadline, None, call)
    }

    /// [`Self::authed_by`] with a token that lasts past `until` ([`Self::bearer_until`]).
    fn authed_until<T>(
        &self,
        deadline: Option<Instant>,
        until: Option<Instant>,
        call: impl Fn(&str) -> Result<T, ApiError>,
    ) -> Result<T, ApiError> {
        let mut retried = false;
        loop {
            let bearer = self.bearer_until(deadline, until)?;
            match call(&bearer) {
                Err(ApiError::Relay { status: 401, .. }) if !retried => {
                    *lock(&self.token) = None;
                    retried = true;
                }
                Err(error) => return Err(self.note_removed(error)),
                other => return other,
            }
        }
    }

    /// The live devices of the team. The list is kept for the session; `refresh` reads
    /// it again.
    pub(crate) fn devices(&self, refresh: bool) -> Result<Vec<DeviceView>, ApiError> {
        if !refresh && let Some(devices) = lock(&self.devices).clone() {
            return Ok(devices);
        }
        let devices: Vec<DeviceView> = self.authed(|bearer| {
            let mut request = Request::new("GET", "/v1/devices".to_owned(), Some(bearer));
            self.bind(&mut request, None);
            call(&self.url, &request)
        })?;
        *lock(&self.devices) = Some(devices.clone());
        Ok(devices)
    }
}

// ---- The head answer. ----

#[derive(Debug, Deserialize)]
pub(crate) struct HeadView {
    version: u64,
    #[serde(default)]
    head: Option<String>,
    #[serde(default)]
    signature: Option<String>,
    #[serde(default)]
    chain: Vec<ChainEntry>,
    #[serde(default)]
    chain_from: Option<u64>,
    #[serde(default)]
    receipts: Vec<Receipt>,
    #[serde(default)]
    signers: Vec<Signer>,
}

#[derive(Debug, Deserialize)]
struct ChainEntry {
    version: u64,
    head: String,
    signature: String,
}

/// A device that signed a head of the answer, with its key (contract section 9). A
/// removed device signs only the versions up to the last one it pushed.
#[derive(Debug, Clone, Deserialize)]
struct Signer {
    device_id: u64,
    public_key: String,
    #[serde(default)]
    removed: bool,
    #[serde(default)]
    last_version: Option<u64>,
}

/// Whether one of `signers` signed `head` (contract section 13, check 3): a live device
/// of the team for any version, a removed device only for a version up to the last one
/// it pushed while it was a member.
fn signed_by_member(head: &SignedHead, signers: &[Signer]) -> bool {
    signers
        .iter()
        .find(|signer| signer.device_id == head.fields.device_id)
        .is_some_and(|signer| {
            let in_time = !signer.removed
                || signer
                    .last_version
                    .is_some_and(|last| head.fields.version <= last);
            in_time
                && decode_b64u(&signer.public_key)
                    .filter(|key| key.len() == 65 && key[0] == 0x04)
                    .is_some_and(|key| head.verify(&key))
        })
}

/// "Device N merged version V" (contract section 9). The app sends it after a merge;
/// "Received by …" shows it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Receipt {
    pub device_id: u64,
    #[serde(default)]
    pub device_name: String,
    pub version: u64,
    pub at: u64,
}

/// Link the chain `entries` (versions `since + 1` onward) to the anchor: the first
/// `previous` is the anchor hash, each later `previous` is the hash of the entry
/// before, and `verify` accepts each entry. Returns the version and the hash of the
/// last entry. Any break is [`SyncError::ForkedCopy`] (contract section 13, check 5).
pub(crate) fn link_chain(
    since: u64,
    anchor: &str,
    chain_from: Option<u64>,
    entries: &[SignedHead],
    mut verify: impl FnMut(&SignedHead) -> Result<bool, SyncError>,
) -> Result<(u64, String), SyncError> {
    if entries.is_empty() || chain_from != Some(since + 1) {
        return Err(SyncError::ForkedCopy);
    }
    let mut version = since;
    let mut previous = anchor.to_owned();
    for entry in entries {
        if entry.fields.version != version + 1 || entry.fields.previous != previous {
            return Err(SyncError::ForkedCopy);
        }
        if !verify(entry)? {
            return Err(SyncError::ForkedCopy);
        }
        version += 1;
        previous = entry.hash();
    }
    Ok((version, previous))
}

// ---- The transport. ----

#[derive(Debug, Clone, Default)]
struct Anchor {
    /// The version that this Mac saw last, and its head hash. 0 and `None`: no anchor.
    version: u64,
    hash: Option<String>,
    /// The current head that the last [`RelayTransport::head`] accepted.
    current: Option<(u64, String)>,
}

/// The relay as a [`SyncTransport`]: the head with its checks, the snapshot download,
/// the push with `If-Match`, and the long poll.
#[derive(Debug, Clone)]
pub struct RelayTransport {
    session: Arc<Session>,
    /// The vault id that a head must name. `None` before an adoption: the copy
    /// decides, and the adoption checks it.
    vault_id: Option<String>,
    max_bytes: u64,
    anchor: Arc<Mutex<Anchor>>,
    /// Every relay call of this transport ends by then (the step before a lock).
    deadline: Option<Instant>,
}

impl RelayTransport {
    pub(crate) fn new(
        session: Arc<Session>,
        vault_id: Option<&str>,
        anchor_version: u64,
        anchor_hash: Option<&str>,
        max_bytes: u64,
    ) -> Self {
        Self {
            session,
            vault_id: vault_id.map(str::to_owned),
            max_bytes,
            anchor: Arc::new(Mutex::new(Anchor {
                version: anchor_version,
                hash: anchor_hash.map(str::to_owned),
                current: None,
            })),
            deadline: None,
        }
    }

    /// End every relay call of this transport by `deadline`.
    pub(crate) fn with_deadline(mut self, deadline: Option<Instant>) -> Self {
        self.deadline = deadline;
        self
    }

    /// The deadline of a download or an upload: `TRANSFER_LIMIT` from now, or the
    /// deadline of the transport when it comes first.
    fn transfer_deadline(&self) -> Option<Instant> {
        let limit = Instant::now() + TRANSFER_LIMIT;
        Some(self.deadline.map_or(limit, |deadline| deadline.min(limit)))
    }

    /// The Mac merged or pushed version `version` with head hash `hash`: the anchor
    /// of the next check.
    pub(crate) fn set_anchor(&self, version: u64, hash: &str) {
        let mut anchor = lock(&self.anchor);
        anchor.version = version;
        anchor.hash = Some(hash.to_owned());
        anchor.current = Some((version, hash.to_owned()));
    }

    /// `GET /v1/sync/head?since=N&wait=S`. A long poll ends at once when the session
    /// closes.
    pub(crate) fn head_view(&self, since: u64, wait: Duration) -> Result<HeadView, ApiError> {
        let seconds = wait.min(MAX_WAIT).as_secs();
        let path = if seconds > 0 {
            format!("/v1/sync/head?since={since}&wait={seconds}")
        } else {
            format!("/v1/sync/head?since={since}")
        };
        self.session.authed_by(self.deadline, |bearer| {
            let mut request = Request::new("GET", path.clone(), Some(bearer));
            request.wait = Duration::from_secs(seconds);
            self.session.bind(&mut request, self.deadline);
            call(&self.session.url, &request)
        })
    }

    /// `POST /v1/sync/receipt`: this Mac merged `version`. Best effort.
    fn send_receipt(&self, version: u64) {
        let _ = self.session.authed_by(self.deadline, |bearer| {
            let mut request = json_request(
                "POST",
                "/v1/sync/receipt",
                Some(bearer),
                &serde_json::json!({"version": version}),
            );
            self.session.bind(&mut request, self.deadline);
            call::<IgnoredAny>(&self.session.url, &request)
        });
    }

    /// Checks 1 to 3 of section 13: the team, the vault, and the signature of a device
    /// of the team that `signers` lists.
    fn check_identity(&self, head: &SignedHead, signers: &[Signer]) -> Result<(), SyncError> {
        if head.fields.team_id != self.session.team_id {
            return Err(SyncError::Damaged);
        }
        if let Some(vault_id) = &self.vault_id
            && &head.fields.vault_id != vault_id
        {
            return Err(SyncError::OtherVault);
        }
        if signed_by_member(head, signers) {
            Ok(())
        } else {
            Err(SyncError::Damaged)
        }
    }

    /// Accept `head` as the current copy.
    fn accept(&self, head: SignedHead) -> Result<Remote, SyncError> {
        if head.fields.size > self.max_bytes {
            return Err(SyncError::TooLarge);
        }
        let sha256 = hash_from_hex(&head.fields.snapshot_sha256).ok_or(SyncError::Damaged)?;
        lock(&self.anchor).current = Some((head.fields.version, head.hash()));
        Ok(Remote::Head(RemoteHead {
            version: head.fields.version,
            sha256,
            size: head.fields.size,
            signed: Some(Box::new(head)),
        }))
    }

    fn device_id(&self) -> Result<u64, SyncError> {
        self.session.device_id().ok_or(SyncError::NotEnabled)
    }
}

impl SyncTransport for RelayTransport {
    /// The current head after the checks of section 13. An empty relay is `Empty`; an
    /// empty relay after this Mac saw a version is `StaleCopy`. A chain of more than
    /// 1000 heads comes in pages, oldest first: the Mac reads on from the last one.
    fn head(&self) -> Result<Remote, SyncError> {
        let anchor = lock(&self.anchor).clone();
        let mut since = anchor.version;
        let mut link = anchor.hash.clone();
        for _ in 0..MAX_CHAIN_PAGES {
            let view = self.head_view(since, Duration::ZERO).map_err(sync_error)?;
            if view.version == 0 {
                if anchor.version > 0 {
                    return Err(SyncError::StaleCopy);
                }
                lock(&self.anchor).current = Some((0, NO_PREVIOUS.to_owned()));
                return Ok(Remote::Empty);
            }
            let head = view
                .head
                .as_deref()
                .zip(view.signature.as_deref())
                .and_then(|(head, signature)| SignedHead::from_wire(head, signature))
                .filter(|head| head.fields.version == view.version)
                .ok_or(SyncError::Damaged)?;
            self.check_identity(&head, &view.signers)?;
            if anchor.version == 0 {
                // No anchor: trust on first use, behind the owner's action.
                return self.accept(head);
            }
            let version = head.fields.version;
            if version < anchor.version
                || (version == anchor.version && Some(head.hash()) != anchor.hash)
            {
                return Err(SyncError::StaleCopy);
            }
            if version == anchor.version {
                return self.accept(head);
            }
            let mut entries = Vec::with_capacity(view.chain.len());
            for entry in &view.chain {
                let parsed = SignedHead::from_wire(&entry.head, &entry.signature)
                    .filter(|parsed| parsed.fields.version == entry.version)
                    .ok_or(SyncError::ForkedCopy)?;
                entries.push(parsed);
            }
            let anchor_hash = link.clone().ok_or(SyncError::ForkedCopy)?;
            let (last, hash) =
                link_chain(since, &anchor_hash, view.chain_from, &entries, |entry| {
                    let same_vault = self
                        .vault_id
                        .as_ref()
                        .is_none_or(|vault_id| &entry.fields.vault_id == vault_id);
                    Ok(entry.fields.team_id == self.session.team_id
                        && same_vault
                        && signed_by_member(entry, &view.signers))
                })?;
            if last == version {
                return match entries.last() {
                    Some(entry) if entry.text == head.text => self.accept(head),
                    _ => Err(SyncError::ForkedCopy),
                };
            }
            if last > version {
                return Err(SyncError::ForkedCopy);
            }
            // The answer holds the oldest 1000 heads: read on from the last one.
            since = last;
            link = Some(hash);
        }
        Err(SyncError::ForkedCopy)
    }

    /// `GET /v1/sync/snapshot?version=N`, streamed to `dest` while it is hashed. The
    /// bytes must have the hash and the size of the head. A lock ends it at once, and it
    /// ends after `TRANSFER_LIMIT`.
    fn fetch(&self, head: &RemoteHead, dest: &Path) -> Result<(File, String), SyncError> {
        let signed = head.signed.as_ref().ok_or(SyncError::Damaged)?;
        if head.size > self.max_bytes {
            return Err(SyncError::TooLarge);
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dest)
            .map_err(|_| SyncError::Io)?;
        let file = Mutex::new(file);
        let path = format!("/v1/sync/snapshot?version={}", head.version);
        let deadline = self.transfer_deadline();
        let result = self.session.authed_by(self.deadline, |bearer| {
            if let Some(left) = rate_limited(&self.session.url) {
                return Err(rate_limit_error(left));
            }
            let mut out = lock(&file);
            out.set_len(0).map_err(|_| SyncError::Io)?;
            out.rewind().map_err(|_| SyncError::Io)?;
            let mut request = Request::new("GET", path.clone(), Some(bearer));
            self.session.bind(&mut request, deadline);
            let (answer, got) =
                relay_http::download(&self.session.url, &request, &mut out, head.size)
                    .map_err(http_error)?;
            match got {
                Some(got) => Ok((answer, got)),
                None => Err(decode::<IgnoredAny>(&answer)
                    .err()
                    .unwrap_or(ApiError::Unreachable)),
            }
        });
        let checked = result.map_err(sync_error).and_then(|(answer, got)| {
            let header_matches = answer
                .header("x-apassy-sync-head")
                .is_none_or(|text| text == signed.head_b64u());
            if got.sha256 == head.sha256 && got.size == head.size && header_matches {
                Ok(to_hex(&got.sha256))
            } else {
                Err(SyncError::Damaged)
            }
        });
        let mut file = file.into_inner().unwrap_or_else(PoisonError::into_inner);
        match checked.and_then(|hash| {
            file.rewind().map_err(|_| SyncError::Io)?;
            Ok(hash)
        }) {
            Ok(hash) => Ok((file, hash)),
            Err(error) => {
                drop(file);
                let _ = fs::remove_file(dest);
                Err(error)
            }
        }
    }

    /// `PUT /v1/sync/snapshot` with a new signed head and `If-Match`. The relay
    /// transport never pushes without `If-Match`: `Any` uses the version that the last
    /// [`Self::head`] saw. A lock ends it at once, and it ends after `TRANSFER_LIMIT`.
    /// The token must last until then: the relay reads it again after the body.
    fn put(
        &self,
        file: &Path,
        sha256: &[u8; 32],
        expect: Precondition,
    ) -> Result<RemoteHead, SyncError> {
        let current = lock(&self.anchor).current.clone();
        let base = match expect {
            Precondition::Absent => 0,
            Precondition::Version(version) => version,
            Precondition::Any => current.as_ref().map_or(0, |(version, _)| *version),
        };
        let previous = if base == 0 {
            NO_PREVIOUS.to_owned()
        } else {
            match current {
                Some((version, hash)) if version == base => hash,
                // The head of that version was not checked: look again first.
                _ => return Err(SyncError::PreconditionFailed),
            }
        };
        let size = fs::metadata(file).map_err(|_| SyncError::Io)?.len();
        if size > self.max_bytes || size > MAX_SNAPSHOT_BYTES {
            return Err(SyncError::TooLarge);
        }
        let fields = HeadFields {
            vault_id: self.vault_id.clone().ok_or(SyncError::NotEnabled)?,
            version: base + 1,
            snapshot_sha256: to_hex(sha256),
            size,
            previous,
            team_id: self.session.team_id.clone(),
            device_id: self.device_id()?,
            time: unix_now(),
        };
        let signed = SignedHead::sign(fields, &self.session.key)?;
        let (head_header, signature_header) = (signed.head_b64u(), signed.signature_b64u());
        let deadline = self.transfer_deadline();
        let pushed = self
            .session
            .authed_until(self.deadline, deadline, |bearer| {
                let mut request = Request::new("PUT", "/v1/sync/snapshot".to_owned(), Some(bearer));
                self.session.bind(&mut request, deadline);
                request.headers.push(("If-Match", format!("\"{base}\"")));
                request
                    .headers
                    .push(("X-Apassy-Sync-Head", head_header.clone()));
                request
                    .headers
                    .push(("X-Apassy-Sync-Signature", signature_header.clone()));
                request.body = Body::File(file, size);
                call::<IgnoredAny>(&self.session.url, &request)
            });
        match pushed {
            Ok(_) => {}
            Err(ApiError::Broken) => {
                // Unknown outcome (section 10): the push landed when the relay has
                // this head as the next version.
                let view = self.head_view(base, Duration::ZERO).map_err(sync_error)?;
                if view.version != base + 1 || view.head.as_deref() != Some(head_header.as_str()) {
                    return Err(SyncError::RelayUnreachable);
                }
            }
            Err(error) => return Err(sync_error(error)),
        }
        let hash = signed.hash();
        lock(&self.anchor).current = Some((base + 1, hash));
        Ok(RemoteHead {
            version: base + 1,
            sha256: *sha256,
            size,
            signed: Some(Box::new(signed)),
        })
    }

    /// The long poll of section 11: `GET /v1/sync/head?since=N&wait=25`. True when the
    /// relay has another version than `since`.
    fn wait_for_change(&self, since: u64, timeout: Duration) -> Result<bool, SyncError> {
        let view = self.head_view(since, timeout).map_err(sync_error)?;
        Ok(view.version != since)
    }
}

// ---- How the engine reaches the vault. ----

/// The vault of a sync. The engine takes it only for a local step (read the vault,
/// merge, write the sync copy) and never across a relay call.
trait VaultAccess {
    fn with<T>(
        &mut self,
        step: impl FnOnce(&mut Vault) -> Result<T, SyncError>,
    ) -> Result<T, SyncError>;
}

impl VaultAccess for Vault {
    fn with<T>(
        &mut self,
        step: impl FnOnce(&mut Vault) -> Result<T, SyncError>,
    ) -> Result<T, SyncError> {
        step(self)
    }
}

/// The shared vault slot of the app, locked for one local step at a time. A vault that
/// was locked or switched in between ends the sync with `Locked`.
struct SharedSlot<'a, F> {
    slot: &'a Mutex<Option<Vault>>,
    accept: F,
}

impl<F: Fn(&Vault) -> bool> VaultAccess for SharedSlot<'_, F> {
    fn with<T>(
        &mut self,
        step: impl FnOnce(&mut Vault) -> Result<T, SyncError>,
    ) -> Result<T, SyncError> {
        let mut slot = lock(self.slot);
        match slot.as_mut() {
            Some(vault) if !vault.is_locked() && (self.accept)(vault) => step(vault),
            _ => Err(SyncError::Vault(VaultErrorKind::Locked)),
        }
    }
}

// ---- The engine. ----

/// A failure after the session closed (a lock, a pause, a quit) is `Locked`: the relay
/// call ended on purpose.
fn ended_by_lock<T>(session: &Session, result: Result<T, SyncError>) -> Result<T, SyncError> {
    match result {
        Err(_) if session.cancel.is_closed() => Err(SyncError::Vault(VaultErrorKind::Locked)),
        other => other,
    }
}

/// Whether this Mac saw a relay version: an anchor of the state.
fn has_anchor(state: &SyncState) -> bool {
    state.last_remote_version != 0 || state.last_head_sha256.is_some()
}

/// The purposes of the work files of a relay sync: `.<state>.relay.<purpose>` in the
/// work folder.
const WORK_PURPOSES: [&str; 3] = ["merge", "push", "passphrase"];

/// Remove the relay work files that a crash or a kill left in `<data_dir>/sync`: the
/// files `.<name>.relay.<purpose>` of every state name (also of "Turn on", whose state
/// name differs) and the downloads of a Mac that joins (`.<team>-<device>.relay.adopt`).
/// They are copies of a vault under the passphrase of that time. Call it at the start of
/// the app, before any relay call runs.
pub fn clear_relay_work(data_dir: &Path) {
    let Ok(entries) = fs::read_dir(data_dir.join("sync")) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name.starts_with('.')
            && name.contains(".relay.")
            && entry.file_type().is_ok_and(|kind| !kind.is_dir())
        {
            let _ = fs::remove_file(entry.path());
        }
    }
}

/// The paths and the relay of the sync of one vault. The engine does not change them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayConfig {
    /// The live local vault file.
    pub vault_path: PathBuf,
    /// The relay origin.
    pub url: String,
    /// The local sync state file (JSON), in the Apassy data folder.
    pub state_path: PathBuf,
    /// A private folder for the copies that a merge reads and a push strips.
    pub work_dir: PathBuf,
}

impl RelayConfig {
    /// The usual layout: the state file `<data_dir>/sync/<state_name>.json`, and the
    /// work folder `<data_dir>/sync`.
    pub fn in_data_dir(data_dir: &Path, vault_path: &Path, url: &str, state_name: &str) -> Self {
        let dir = data_dir.join("sync");
        Self {
            vault_path: vault_path.to_owned(),
            url: url.to_owned(),
            state_path: dir.join(format!("{state_name}.json")),
            work_dir: dir,
        }
    }
}

/// The result of turning relay sync on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayEnableReport {
    /// The link for the vault list (`SyncLink::relay`).
    pub link: RelayLink,
    /// The team name on the relay.
    pub team: String,
    pub outcome: SyncOutcome,
}

/// The result of [`RelaySync::adopt`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayAdoptReport {
    /// The link for the vault list (`SyncLink::relay`).
    pub link: RelayLink,
    /// The sync record of the copy: its last writer.
    pub identity: SyncIdentity,
}

/// What a long poll of [`RelaySync::poll`] saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayPoll {
    /// The version that this Mac saw last (the anchor of the state file).
    pub since: u64,
    /// The current version on the relay.
    pub version: u64,
}

impl RelayPoll {
    /// Whether the relay has another version than this Mac saw.
    pub fn changed(&self) -> bool {
        self.version != self.since
    }
}

/// Sync of one vault through the relay. A clone shares the key and the token in memory.
#[derive(Clone)]
pub struct RelaySync {
    config: RelayConfig,
    scope: SyncScope,
    max_bytes: u64,
    session: Arc<Mutex<Option<Arc<Session>>>>,
    /// The head hash of a copy that failed for a reason that does not pass by itself
    /// ([`sticks`]: it needs the new passphrase, its bytes are damaged, it has a newer
    /// schema), with that failure. A sync does not download the same copy again until
    /// the head changes, the owner acts, or the vault locks.
    refused: Arc<Mutex<Option<(String, SyncError)>>>,
    /// Held by each sync of this vault: one runs at a time.
    runs: Arc<Mutex<()>>,
    /// Set by [`Self::pause`] and [`Self::stop_runs`]: a sync that gets the guard then
    /// ends with `Locked`, until [`Self::resume`].
    paused: Arc<AtomicBool>,
    /// The relay refused the device of this Mac ([`Self::is_removed`]). It outlives a
    /// lock; a sign-in that works, turning sync off, or a new join clears it.
    removed: Arc<Removal>,
}

impl fmt::Debug for RelaySync {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelaySync")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl RelaySync {
    pub fn new(config: RelayConfig) -> Self {
        Self {
            config,
            scope: SyncScope::vault(),
            max_bytes: MAX_SNAPSHOT_BYTES,
            session: Arc::new(Mutex::new(None)),
            refused: Arc::new(Mutex::new(None)),
            runs: Arc::new(Mutex::new(())),
            paused: Arc::new(AtomicBool::new(false)),
            removed: Arc::new(Removal::new(REMOVED_PROBE_EVERY)),
        }
    }

    /// Ask the relay again `every` after it refused the device of this Mac, instead of
    /// [`REMOVED_PROBE_EVERY`]. For a test.
    pub fn with_removed_probe(mut self, every: Duration) -> Self {
        self.removed = Arc::new(Removal::new(every));
        self
    }

    /// Refuse to push or fetch a copy larger than `bytes` (at most 64 MiB). For a test,
    /// or a relay with a lower `sync_bytes`.
    pub fn with_snapshot_limit(mut self, bytes: u64) -> Self {
        self.max_bytes = bytes.min(MAX_SNAPSHOT_BYTES);
        self
    }

    pub fn config(&self) -> &RelayConfig {
        &self.config
    }

    /// The local sync state. `None` when sync is off.
    pub fn state(&self) -> Result<Option<SyncState>, SyncError> {
        state::read(&self.config.state_path)
    }

    fn require_state(&self) -> Result<SyncState, SyncError> {
        self.state()?
            .filter(|state| state.transport == TransportKind::Relay)
            .ok_or(SyncError::NotEnabled)
    }

    /// Drop the device key and the access token from memory: the vault locked. Every
    /// relay call in flight with them ends at once (a long poll, a download, an upload),
    /// and the dropped session signs in no more. The next sync reads the key from the
    /// unlocked vault again.
    pub fn forget(&self) {
        let session = lock(&self.session).take();
        if let Some(session) = session {
            // A session of a join or an adoption has a mark of its own.
            if let Some(until) = session.removed.until() {
                self.removed.note_until(until);
            }
            session.close();
        }
        *lock(&self.refused) = None;
    }

    /// Whether the key is in memory, so that [`Self::poll`] can sign in.
    pub fn has_session(&self) -> bool {
        lock(&self.session).is_some()
    }

    /// Whether the relay refused the device of this Mac: another Mac removed it
    /// (contract section 13, "Removed from the relay"). Every later relay call of this
    /// vault then fails at once with [`SyncError::RemovedFromRelay`], without a sign-in,
    /// also after a lock, until [`Self::removed_until`]: then one sign-in asks the relay
    /// again, since a suspended relay gives the same `401`, and a sign-in that works
    /// clears it. [`Self::disable`] and a new relay sync of the vault (a join with a new
    /// link) clear it too. A new start of the app asks the relay once more.
    pub fn is_removed(&self) -> bool {
        self.removed_until().is_some()
    }

    /// While [`Self::is_removed`]: when a sign-in may ask the relay again.
    pub fn removed_until(&self) -> Option<Instant> {
        let session = lock(&self.session)
            .as_ref()
            .and_then(|session| session.removed.until());
        match (self.removed.until(), session) {
            (Some(own), Some(session)) => Some(own.max(session)),
            (own, session) => own.or(session),
        }
    }

    /// No sync of this vault from now until [`Self::resume`], for "Turn off" while the
    /// device leaves the team: the key and the token leave the memory
    /// ([`Self::forget`]), which ends the relay calls of the sync that runs, and a sync
    /// that waits for it ends with `Locked`. The device calls still work.
    pub fn pause(&self) {
        self.paused.store(true, Ordering::SeqCst);
        self.forget();
    }

    /// Syncs of this vault run again after [`Self::pause`] or [`Self::stop_runs`].
    pub fn resume(&self) {
        self.paused.store(false, Ordering::SeqCst);
    }

    /// End the sync of this vault that runs, and keep others out while the guard lives
    /// and after it, until [`Self::resume`]: the key and the token leave the memory
    /// ([`Self::forget`]), which ends its relay calls at once, and this waits for its
    /// local step to end. Take it before the vault mutex, never with it held.
    pub fn stop_runs(&self) -> MutexGuard<'_, ()> {
        self.paused.store(true, Ordering::SeqCst);
        loop {
            self.forget();
            match self.runs.try_lock() {
                Ok(guard) => return guard,
                Err(TryLockError::Poisoned(poisoned)) => return poisoned.into_inner(),
                Err(TryLockError::WouldBlock) => std::thread::sleep(Duration::from_millis(10)),
            }
        }
    }

    /// Whether a sync of this vault runs now.
    pub fn is_running(&self) -> bool {
        matches!(self.runs.try_lock(), Err(TryLockError::WouldBlock))
    }

    /// The guard of a sync with the vault in hand: `Running` when another sync of this
    /// vault runs, since it may wait for the vault that the caller holds. `Locked` while
    /// paused.
    fn try_run(&self) -> Result<MutexGuard<'_, ()>, SyncError> {
        let guard = match self.runs.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => return Err(SyncError::Running),
        };
        self.not_paused()?;
        Ok(guard)
    }

    /// The guard of a sync with the shared vault slot: it waits for the sync that runs.
    /// `Locked` while paused, also when the pause came during the wait.
    fn run_shared(&self) -> Result<MutexGuard<'_, ()>, SyncError> {
        let guard = lock(&self.runs);
        self.not_paused()?;
        Ok(guard)
    }

    fn not_paused(&self) -> Result<(), SyncError> {
        if self.paused.load(Ordering::SeqCst) {
            return Err(SyncError::Vault(VaultErrorKind::Locked));
        }
        Ok(())
    }

    /// Whether the vault has synced content that the last sync did not see. The vault
    /// must be unlocked.
    pub fn local_changed(&self, vault: &Vault) -> Result<bool, SyncError> {
        let state = self.require_state()?;
        let content = to_hex(&vault.sync_content(&self.scope)?);
        Ok(state.last_content.as_deref() != Some(content.as_str()))
    }

    /// The session of the vault: the one in memory, or a new one from the relay row of
    /// the unlocked vault.
    pub(crate) fn session(&self, vault: &Vault) -> Result<Arc<Session>, SyncError> {
        if let Some(session) = lock(&self.session).clone() {
            return Ok(session);
        }
        let row = vault.relay_device()?.ok_or(SyncError::NotEnabled)?;
        let url = RelayUrl::parse(&self.config.url)?;
        if row.relay_url != url.as_str() {
            return Err(SyncError::WrongVault);
        }
        let key = DeviceKey::from_pkcs8(row.key_pkcs8)?;
        if key.public_key() != row.public_key.as_slice() {
            return Err(SyncError::Damaged);
        }
        let session = Arc::new(
            Session::new(url, &row.team_id, key, Some(row.device_id))
                .sharing_removed(&self.removed),
        );
        *lock(&self.session) = Some(Arc::clone(&session));
        Ok(session)
    }

    fn transport(&self, session: Arc<Session>, state: &SyncState) -> RelayTransport {
        RelayTransport::new(
            session,
            Some(&state.vault_id),
            state.last_remote_version,
            state.last_head_sha256.as_deref(),
            self.max_bytes,
        )
    }

    /// The transport of the vault, for a caller that drives it.
    pub fn relay_transport(&self, vault: &Vault) -> Result<RelayTransport, SyncError> {
        let state = self.require_state()?;
        let session = self.session(vault)?;
        Ok(self.transport(session, &state))
    }

    /// Write the state with the path of the local vault file and the time.
    fn write_state(&self, state: &SyncState) -> Result<(), SyncError> {
        let mut state = state.clone();
        state.vault_path = Some(
            fs::canonicalize(&self.config.vault_path)
                .unwrap_or_else(|_| self.config.vault_path.clone()),
        );
        state.last_sync_at = Some(unix_now());
        state::write(&self.config.state_path, &state)
    }

    /// The private path of a work file in the work folder. One sync of a vault runs at
    /// a time (the guard), so each purpose has one fixed name: a file that a crash left
    /// goes at the next sync ([`Self::clear_work`]).
    fn work_path(&self, purpose: &str) -> Result<PathBuf, SyncError> {
        state::ensure_private_dir(&self.config.work_dir)?;
        Ok(self.work_file(purpose))
    }

    fn work_file(&self, purpose: &str) -> PathBuf {
        let stem = self
            .config
            .state_path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("relay");
        self.config
            .work_dir
            .join(format!(".{stem}.relay.{purpose}"))
    }

    /// Remove the work files that a crash or a quit in a transfer left: copies of the
    /// vault, under the passphrase of that time. Call it with the guard held.
    fn clear_work(&self) {
        for purpose in WORK_PURPOSES {
            let _ = fs::remove_file(self.work_file(purpose));
        }
    }

    fn require_config_path(&self, vault: &Vault) -> Result<(), SyncError> {
        match fs::canonicalize(&self.config.vault_path) {
            Ok(path) if path == vault.path() => Ok(()),
            _ => Err(SyncError::WrongVault),
        }
    }

    fn require_unlocked(&self, vault: &Vault) -> Result<(), SyncError> {
        self.require_config_path(vault)?;
        if vault.is_locked() {
            return Err(SyncError::Vault(VaultErrorKind::Locked));
        }
        Ok(())
    }

    /// The session of a synced vault, checked against the state.
    fn checked_session(&self, vault: &Vault, state: &SyncState) -> Result<Arc<Session>, SyncError> {
        self.require_unlocked(vault)?;
        if vault.sync_identity()?.vault_id != state.vault_id {
            return Err(SyncError::WrongVault);
        }
        let session = self.session(vault)?;
        if state.team_id.as_deref() != Some(session.team_id.as_str())
            || state.device_id != session.device_id()
            || state.relay_url.as_deref() != Some(session.url.as_str())
        {
            return Err(SyncError::WrongVault);
        }
        Ok(session)
    }

    /// The failure of the copy with head hash `hash`, when it failed before for a
    /// reason that does not pass by itself.
    fn refused_before(&self, hash: &str) -> Result<(), SyncError> {
        match lock(&self.refused).as_ref() {
            Some((refused, error)) if refused == hash => Err(*error),
            _ => Ok(()),
        }
    }

    fn remember_refusal(&self, hash: &str, error: SyncError) {
        if sticks(error) {
            *lock(&self.refused) = Some((hash.to_owned(), error));
        }
    }

    /// Sync the unlocked vault (contract section 10): check and merge a newer copy,
    /// then push when the vault has content that the copy lacks, or when the copy has
    /// an earlier schema ([`MergeReport::remote_outdated`]), with `If-Match`. A
    /// `412` starts another round; after three the change stays for the next sync.
    /// `Running` when another sync of this vault runs.
    pub fn sync(&self, vault: &mut Vault) -> Result<SyncOutcome, SyncError> {
        self.sync_by(vault, None)
    }

    /// [`Self::sync`] for the step before a lock: every relay call ends within `limit`,
    /// and a sync that runs already is not waited for (`Running`).
    pub fn sync_within(
        &self,
        vault: &mut Vault,
        limit: Duration,
    ) -> Result<SyncOutcome, SyncError> {
        self.sync_by(vault, Some(Instant::now() + limit))
    }

    fn sync_by(
        &self,
        vault: &mut Vault,
        deadline: Option<Instant>,
    ) -> Result<SyncOutcome, SyncError> {
        let _run = self.try_run()?;
        self.clear_work();
        let mut state = self.require_state()?;
        let session = self.checked_session(vault, &state)?;
        let transport = self
            .transport(Arc::clone(&session), &state)
            .with_deadline(deadline);
        ended_by_lock(
            &session,
            self.rounds(vault, &mut state, &transport, true, None),
        )
    }

    /// [`Self::sync`] with the shared vault slot of the app. The slot's mutex is held
    /// only to read the vault, to merge, and to write the sync copy; the sign-in, the
    /// head, the download, and the upload run without it. `accept` tells whether the
    /// vault in the slot is still the one of this sync (a switch can change it). A
    /// vault that locks in between ends the sync with `Locked`.
    pub fn sync_shared(
        &self,
        slot: &Mutex<Option<Vault>>,
        accept: impl Fn(&Vault) -> bool,
    ) -> Result<SyncOutcome, SyncError> {
        let _run = self.run_shared()?;
        self.clear_work();
        let mut state = self.require_state()?;
        let mut access = SharedSlot { slot, accept };
        let session = access.with(|vault| self.checked_session(vault, &state))?;
        let transport = self.transport(Arc::clone(&session), &state);
        ended_by_lock(
            &session,
            self.rounds(&mut access, &mut state, &transport, true, None),
        )
    }

    /// The rounds of a sync. `fetched` is a copy that this sync downloaded already, with
    /// its head hash: the first round merges it instead of a new download when the head
    /// is still that one.
    fn rounds<A: VaultAccess + ?Sized>(
        &self,
        vault: &mut A,
        state: &mut SyncState,
        transport: &RelayTransport,
        persist: bool,
        mut fetched: Option<(TempFile, String)>,
    ) -> Result<SyncOutcome, SyncError> {
        let file_name = String::new();
        let mut merge: Option<MergeReport> = None;
        for _ in 0..MAX_ROUNDS {
            let head = match transport.head()? {
                Remote::Head(head) => Some(head),
                Remote::Empty => None,
                Remote::Unavailable | Remote::NotReady => {
                    return Err(SyncError::RelayUnreachable);
                }
            };
            let remote_version = head.as_ref().map_or(0, |head| head.version);
            let mut remote_content = state.last_content.clone();
            if let Some(head) = head.as_ref().filter(|head| {
                head.version > state.last_remote_version
                    || (state.last_remote_version == 0 && state.last_head_sha256.is_none())
            }) {
                let hash = head.signed.as_ref().ok_or(SyncError::Damaged)?.hash();
                let work = match fetched.take().filter(|(_, fetched)| *fetched == hash) {
                    Some((work, _)) => Ok(work),
                    None => {
                        self.refused_before(&hash)?;
                        let work = TempFile::new(self.work_path("merge")?)?;
                        transport.fetch(head, &work.path).map(|_| work)
                    }
                };
                let report = work.and_then(|work| {
                    vault.with(|vault| {
                        vault
                            .merge_from(&work.path, &self.scope)
                            .map_err(copy_error)
                    })
                });
                let report = report.inspect_err(|error| self.remember_refusal(&hash, *error))?;
                // A copy of an earlier schema gets a copy of the current schema, also with
                // the same content. No remote content forces the push, here and in a
                // later sync when this push fails.
                remote_content =
                    (!report.remote_outdated()).then(|| to_hex(&report.remote_content));
                state.last_remote_version = head.version;
                state.last_head_sha256 = Some(hash.clone());
                state.last_content = remote_content.clone();
                transport.set_anchor(head.version, &hash);
                if persist {
                    self.write_state(state)?;
                    transport.send_receipt(head.version);
                }
                merge = Some(match merge {
                    None => report,
                    Some(mut total) => {
                        total.inserted += report.inserted;
                        total.updated += report.updated;
                        total.deleted += report.deleted;
                        total.conflicts.extend(report.conflicts);
                        total.skipped_variables.extend(report.skipped_variables);
                        total.remote = report.remote;
                        total.remote_content = report.remote_content;
                        total.remote_schema = report.remote_schema;
                        total
                    }
                });
            }
            // Under the vault: the content, and the copy to push when it differs.
            let has_head = head.is_some();
            let copy = vault.with(|vault| {
                let content = to_hex(&vault.sync_content(&self.scope)?);
                if has_head && remote_content.as_deref() == Some(content.as_str()) {
                    return Ok(Err(content));
                }
                let work = TempFile::new(self.work_path("push")?)?;
                let copy = vault.write_sync_copy(&work.path, &device_name())?;
                Ok(Ok((work, copy)))
            })?;
            let (work, copy) = match copy {
                Ok(copy) => copy,
                Err(content) => {
                    state.last_content = Some(content);
                    if persist {
                        self.write_state(state)?;
                    }
                    return Ok(SyncOutcome {
                        file_name,
                        merge,
                        pushed: false,
                    });
                }
            };
            let pushed = transport.put(
                &work.path,
                &copy.sha256,
                Precondition::Version(remote_version),
            );
            drop(work);
            match pushed {
                Ok(pushed) => {
                    let hash = pushed.signed.as_ref().ok_or(SyncError::Damaged)?.hash();
                    state.last_remote_version = pushed.version;
                    state.last_head_sha256 = Some(hash.clone());
                    state.last_content = Some(to_hex(&copy.content));
                    transport.set_anchor(pushed.version, &hash);
                    if persist {
                        self.write_state(state)?;
                    }
                    return Ok(SyncOutcome {
                        file_name,
                        merge,
                        pushed: true,
                    });
                }
                Err(SyncError::PreconditionFailed) => {}
                Err(error) => return Err(error),
            }
        }
        Err(SyncError::RelayBusy)
    }

    /// The passphrase changed on another Mac: `passphrase` must open the relay copy,
    /// and the copy must hold this vault. Then the vault file is rekeyed to it, and the
    /// sync runs with the copy that was downloaded for the check. The vault must be
    /// unlocked.
    ///
    /// Without an anchor ([`Self::keeps_passphrase`], after "Use the relay copy") the
    /// vault is not rekeyed: `passphrase` only opens the copy for the merge, and the
    /// vault goes up under its own passphrase.
    ///
    /// `Err`: nothing changed. `Ok`: the vault uses the new passphrase now (or merged
    /// the copy), and the inner result is the sync after it; a failed sync tries again
    /// later.
    pub fn take_new_passphrase(
        &self,
        vault: &mut Vault,
        passphrase: &str,
    ) -> Result<Result<SyncOutcome, SyncError>, SyncError> {
        let _run = self.try_run()?;
        self.take_new_passphrase_in(vault, passphrase)
    }

    /// [`Self::take_new_passphrase`] with the shared vault slot of the app, as
    /// [`Self::sync_shared`]: the relay calls run without the slot's mutex.
    pub fn take_new_passphrase_shared(
        &self,
        slot: &Mutex<Option<Vault>>,
        accept: impl Fn(&Vault) -> bool,
        passphrase: &str,
    ) -> Result<Result<SyncOutcome, SyncError>, SyncError> {
        let _run = self.run_shared()?;
        self.take_new_passphrase_in(&mut SharedSlot { slot, accept }, passphrase)
    }

    fn take_new_passphrase_in<A: VaultAccess + ?Sized>(
        &self,
        vault: &mut A,
        passphrase: &str,
    ) -> Result<Result<SyncOutcome, SyncError>, SyncError> {
        let mut state = self.require_state()?;
        let session = vault.with(|vault| self.checked_session(vault, &state))?;
        *lock(&self.refused) = None;
        let transport = self.transport(Arc::clone(&session), &state);
        if !has_anchor(&state) {
            return self.merge_with_passphrase(vault, &mut state, &transport, &session, passphrase);
        }
        let fetched = ended_by_lock(&session, self.rekey_to_copy(vault, &transport, passphrase))?;
        // The vault uses the new passphrase now, whatever the sync after it does.
        Ok(ended_by_lock(
            &session,
            self.rounds(vault, &mut state, &transport, true, Some(fetched)),
        ))
    }

    /// Download the current relay copy and rekey the vault to `passphrase`, which must
    /// open the copy. Returns the copy and its head hash, for the merge after it.
    /// `Err`: the vault keeps its passphrase.
    fn rekey_to_copy<A: VaultAccess + ?Sized>(
        &self,
        vault: &mut A,
        transport: &RelayTransport,
        passphrase: &str,
    ) -> Result<(TempFile, String), SyncError> {
        let Remote::Head(head) = transport.head()? else {
            return Err(SyncError::RelayEmpty);
        };
        let hash = head.signed.as_ref().ok_or(SyncError::Damaged)?.hash();
        let work = TempFile::new(self.work_path("passphrase")?)?;
        transport.fetch(&head, &work.path)?;
        vault.with(|vault| Ok(vault.take_passphrase_of_copy(&work.path, passphrase)?))?;
        Ok((work, hash))
    }

    /// Whether [`Self::take_new_passphrase`] keeps the passphrase of this Mac: this Mac
    /// has no anchor ("Use the relay copy" forgot it), so the relay copy can be older
    /// than this vault, from before a passphrase change. The typed passphrase then only
    /// opens the copy for the merge.
    pub fn keeps_passphrase(&self) -> bool {
        self.state()
            .ok()
            .flatten()
            .is_some_and(|state| state.transport == TransportKind::Relay && !has_anchor(&state))
    }

    /// The passphrase step without an anchor: `passphrase` opens the relay copy only
    /// for the merge, the vault keeps its own passphrase, and the merged vault goes up
    /// under it. Rekeying to the copy's passphrase could bring back a passphrase that the
    /// owner changed (a relay restored from a backup).
    fn merge_with_passphrase<A: VaultAccess + ?Sized>(
        &self,
        vault: &mut A,
        state: &mut SyncState,
        transport: &RelayTransport,
        session: &Session,
        passphrase: &str,
    ) -> Result<Result<SyncOutcome, SyncError>, SyncError> {
        let merged = self.merge_copy_with_passphrase(vault, state, transport, passphrase);
        let (report, version) = ended_by_lock(session, merged)?;
        transport.send_receipt(version);
        // The merge is in the vault now, whatever the push after it does.
        Ok(
            ended_by_lock(session, self.rounds(vault, state, transport, true, None)).map(
                |mut outcome| {
                    outcome.merge.get_or_insert(report);
                    outcome
                },
            ),
        )
    }

    /// Download the current relay copy and merge it into the vault with `passphrase`,
    /// which opens only the copy: the vault keeps its own passphrase. The head becomes
    /// the anchor of `state`, and the next round pushes the vault, also when its
    /// content is the copy's. Returns the merge and the version.
    fn merge_copy_with_passphrase<A: VaultAccess + ?Sized>(
        &self,
        vault: &mut A,
        state: &mut SyncState,
        transport: &RelayTransport,
        passphrase: &str,
    ) -> Result<(MergeReport, u64), SyncError> {
        let Remote::Head(head) = transport.head()? else {
            return Err(SyncError::RelayEmpty);
        };
        let hash = head.signed.as_ref().ok_or(SyncError::Damaged)?.hash();
        let work = TempFile::new(self.work_path("passphrase")?)?;
        transport.fetch(&head, &work.path)?;
        let report = vault.with(|vault| {
            Ok(vault.merge_from_with_passphrase(&work.path, &self.scope, passphrase)?)
        })?;
        state.last_remote_version = head.version;
        state.last_head_sha256 = Some(hash.clone());
        // The copy is under another passphrase: the next round pushes the vault, also
        // when its content is the copy's.
        state.last_content = None;
        transport.set_anchor(head.version, &hash);
        self.write_state(state)?;
        Ok((report, head.version))
    }

    /// Replace the copy on the relay with this Mac's vault: push a new version over the
    /// current head, signed as usual, without checking or merging the relay copy. For a
    /// damaged relay copy (it fails a check, or its bytes are not its head's). The
    /// relay still checks the push: a copy of another vault there stays (`OtherVault`;
    /// "Delete the copy on the relay" is the way out). A Mac whose chain then does not
    /// link (it saw a head that failed the checks) uses the relay copy
    /// ([`Self::use_relay_copy`]).
    pub fn replace_relay_copy(&self, vault: &mut Vault) -> Result<SyncOutcome, SyncError> {
        let _run = self.try_run()?;
        self.replace_relay_copy_in(vault)
    }

    /// [`Self::replace_relay_copy`] with the shared vault slot of the app, as
    /// [`Self::sync_shared`]: the relay calls run without the slot's mutex.
    pub fn replace_relay_copy_shared(
        &self,
        slot: &Mutex<Option<Vault>>,
        accept: impl Fn(&Vault) -> bool,
    ) -> Result<SyncOutcome, SyncError> {
        let _run = self.run_shared()?;
        self.replace_relay_copy_in(&mut SharedSlot { slot, accept })
    }

    /// Use the relay copy as it is now, when this Mac refuses it (`StaleCopy` or
    /// `ForkedCopy`, contract section 13): a relay restored from a backup, or a history
    /// that does not include this Mac's last change. This Mac forgets its anchor, so it
    /// takes the current head as at a first sync, behind this action of the owner; the
    /// checks of the team, the vault, and the signature still apply. The vault merges
    /// the copy and pushes what the copy lacks. The device stays on the relay.
    pub fn use_relay_copy(&self, vault: &mut Vault) -> Result<SyncOutcome, SyncError> {
        let _run = self.try_run()?;
        self.use_relay_copy_in(vault)
    }

    /// [`Self::use_relay_copy`] with the shared vault slot of the app, as
    /// [`Self::sync_shared`]: the relay calls run without the slot's mutex.
    pub fn use_relay_copy_shared(
        &self,
        slot: &Mutex<Option<Vault>>,
        accept: impl Fn(&Vault) -> bool,
    ) -> Result<SyncOutcome, SyncError> {
        let _run = self.run_shared()?;
        self.use_relay_copy_in(&mut SharedSlot { slot, accept })
    }

    /// A copy that then fails the same way again ([`sticks`]: it needs another
    /// passphrase, or its bytes are damaged) keeps the forgotten anchor in the state, so
    /// the next step of the owner ("Type the passphrase of the copy…", which keeps the
    /// passphrase of this vault ([`Self::keeps_passphrase`]), or "Replace with this Mac's
    /// vault…") starts from the copy as it is now too.
    fn use_relay_copy_in<A: VaultAccess + ?Sized>(
        &self,
        vault: &mut A,
    ) -> Result<SyncOutcome, SyncError> {
        let mut state = self.require_state()?;
        let session = vault.with(|vault| self.checked_session(vault, &state))?;
        *lock(&self.refused) = None;
        state.last_remote_version = 0;
        state.last_head_sha256 = None;
        let transport = self.transport(Arc::clone(&session), &state);
        let mut result = ended_by_lock(
            &session,
            self.rounds(vault, &mut state, &transport, true, None),
        );
        if let Err(error) = result
            && sticks(error)
            && let Err(failed) = state::write(&self.config.state_path, &state)
        {
            result = Err(failed);
        }
        result
    }

    fn replace_relay_copy_in<A: VaultAccess + ?Sized>(
        &self,
        vault: &mut A,
    ) -> Result<SyncOutcome, SyncError> {
        let mut state = self.require_state()?;
        let session = vault.with(|vault| self.checked_session(vault, &state))?;
        *lock(&self.refused) = None;
        let transport = self.transport(Arc::clone(&session), &state);
        ended_by_lock(&session, self.replace_rounds(vault, &mut state, &transport))
    }

    fn replace_rounds<A: VaultAccess + ?Sized>(
        &self,
        vault: &mut A,
        state: &mut SyncState,
        transport: &RelayTransport,
    ) -> Result<SyncOutcome, SyncError> {
        for _ in 0..MAX_ROUNDS {
            let view = transport
                .head_view(state.last_remote_version, Duration::ZERO)
                .map_err(sync_error)?;
            let (base, previous) = if view.version == 0 {
                (0, NO_PREVIOUS.to_owned())
            } else {
                let text = view
                    .head
                    .as_deref()
                    .and_then(decode_b64u)
                    .ok_or(SyncError::Damaged)?;
                if let Some(fields) = std::str::from_utf8(&text).ok().and_then(HeadFields::parse)
                    && fields.vault_id != state.vault_id
                {
                    return Err(SyncError::OtherVault);
                }
                (view.version, sha256_hex(&text))
            };
            lock(&transport.anchor).current = Some((base, previous));
            let (work, copy) = vault.with(|vault| {
                let work = TempFile::new(self.work_path("push")?)?;
                let copy = vault.write_sync_copy(&work.path, &device_name())?;
                Ok((work, copy))
            })?;
            match transport.put(&work.path, &copy.sha256, Precondition::Version(base)) {
                Ok(pushed) => {
                    let hash = pushed.signed.as_ref().ok_or(SyncError::Damaged)?.hash();
                    state.last_remote_version = pushed.version;
                    state.last_head_sha256 = Some(hash.clone());
                    state.last_content = Some(to_hex(&copy.content));
                    transport.set_anchor(pushed.version, &hash);
                    self.write_state(state)?;
                    return Ok(SyncOutcome {
                        file_name: String::new(),
                        merge: None,
                        pushed: true,
                    });
                }
                Err(SyncError::PreconditionFailed) => {}
                Err(error) => return Err(error),
            }
        }
        Err(SyncError::RelayBusy)
    }

    /// Turn relay sync on with a new personal team (contract section 6): a new device
    /// key, `POST /v1/teams` with the operator team code, a sign-in, and the push of
    /// version 1. The key, the state, and the link are stored only after the push
    /// succeeded. The caller puts the link in the vault list.
    pub fn create_team(
        &self,
        vault: &mut Vault,
        vault_name: &str,
        team_code: &str,
        device: &str,
    ) -> Result<RelayEnableReport, SyncError> {
        let _run = self.try_run()?;
        self.create_team_in(vault, vault_name, team_code, device)
    }

    /// [`Self::create_team`] with the shared vault slot of the app, as
    /// [`Self::sync_shared`]: the relay calls and the upload of version 1 run without
    /// the slot's mutex.
    pub fn create_team_shared(
        &self,
        slot: &Mutex<Option<Vault>>,
        accept: impl Fn(&Vault) -> bool,
        vault_name: &str,
        team_code: &str,
        device: &str,
    ) -> Result<RelayEnableReport, SyncError> {
        let _run = self.run_shared()?;
        self.create_team_in(
            &mut SharedSlot { slot, accept },
            vault_name,
            team_code,
            device,
        )
    }

    fn create_team_in<A: VaultAccess + ?Sized>(
        &self,
        vault: &mut A,
        vault_name: &str,
        team_code: &str,
        device: &str,
    ) -> Result<RelayEnableReport, SyncError> {
        if self.state()?.is_some() {
            return Err(SyncError::AlreadyEnabled);
        }
        let local = vault.with(|vault| {
            self.require_unlocked(vault)?;
            Ok(vault.sync_identity()?)
        })?;
        let url = RelayUrl::parse(&self.config.url)?;
        let team_code = team_code.trim();
        if !valid_team_code(team_code) {
            return Err(SyncError::Relay(RelayRefusal::InviteInvalid));
        }
        let key = DeviceKey::generate()?;
        let team = clean_name(vault_name, "Vault");
        #[derive(Serialize)]
        struct NewTeam<'a> {
            code: &'a str,
            team: &'a str,
            owner: &'a str,
            device_name: &'a str,
            public_key: &'a str,
        }
        #[derive(Deserialize)]
        struct Created {
            team_id: String,
            device_id: u64,
        }
        let created: Created = call(
            &url,
            &json_request(
                "POST",
                "/v1/teams",
                None,
                &NewTeam {
                    code: team_code,
                    team: &team,
                    owner: "owner",
                    device_name: &clean_name(device, "Mac"),
                    public_key: &key.public_key_b64u(),
                },
            ),
        )
        .map_err(sync_error)?;
        if !valid_team_id(&created.team_id) || created.device_id == 0 {
            return Err(SyncError::RelayUnreachable);
        }
        let session = Arc::new(Session::new(
            url,
            &created.team_id,
            key,
            Some(created.device_id),
        ));
        self.finish_enable(vault, session, &local.vault_id, team, None)
    }

    /// Turn relay sync on for a vault that is already on the relay, with a device that
    /// a link added (contract section 6, last paragraph): the copy must hold this vault
    /// ("The relay copy holds another vault."); the vault merges it and pushes.
    pub fn enable_joined(
        &self,
        vault: &mut Vault,
        joined: &JoinedDevice,
    ) -> Result<RelayEnableReport, SyncError> {
        let _run = self.try_run()?;
        self.enable_joined_in(vault, joined)
    }

    /// [`Self::enable_joined`] with the shared vault slot of the app, as
    /// [`Self::sync_shared`]: the relay calls run without the slot's mutex.
    pub fn enable_joined_shared(
        &self,
        slot: &Mutex<Option<Vault>>,
        accept: impl Fn(&Vault) -> bool,
        joined: &JoinedDevice,
    ) -> Result<RelayEnableReport, SyncError> {
        let _run = self.run_shared()?;
        self.enable_joined_in(&mut SharedSlot { slot, accept }, joined)
    }

    /// [`Self::enable_joined`] for a relay copy under another passphrase than the vault
    /// (the join failed with `NeedsPassphrase`): `passphrase` must open the copy, the
    /// vault takes it (the copy of the team wins, as in a folder sync), merges the copy,
    /// and pushes (contract section 6). A wrong passphrase is `Vault(WrongKeyOrCorrupt)`,
    /// and nothing changed: the device can try again. Any other error after the
    /// passphrase opened the copy can leave the vault with the new passphrase
    /// (`Vault::verify_passphrase_at` tells).
    pub fn enable_joined_with_passphrase(
        &self,
        vault: &mut Vault,
        joined: &JoinedDevice,
        passphrase: &str,
    ) -> Result<RelayEnableReport, SyncError> {
        let _run = self.try_run()?;
        self.enable_joined_by(vault, joined, Some(passphrase))
    }

    /// [`Self::enable_joined_with_passphrase`] with the shared vault slot of the app, as
    /// [`Self::sync_shared`]: the relay calls run without the slot's mutex.
    pub fn enable_joined_with_passphrase_shared(
        &self,
        slot: &Mutex<Option<Vault>>,
        accept: impl Fn(&Vault) -> bool,
        joined: &JoinedDevice,
        passphrase: &str,
    ) -> Result<RelayEnableReport, SyncError> {
        let _run = self.run_shared()?;
        self.enable_joined_by(&mut SharedSlot { slot, accept }, joined, Some(passphrase))
    }

    fn enable_joined_in<A: VaultAccess + ?Sized>(
        &self,
        vault: &mut A,
        joined: &JoinedDevice,
    ) -> Result<RelayEnableReport, SyncError> {
        self.enable_joined_by(vault, joined, None)
    }

    fn enable_joined_by<A: VaultAccess + ?Sized>(
        &self,
        vault: &mut A,
        joined: &JoinedDevice,
        passphrase: Option<&str>,
    ) -> Result<RelayEnableReport, SyncError> {
        if self.state()?.is_some() {
            return Err(SyncError::AlreadyEnabled);
        }
        let local = vault.with(|vault| {
            self.require_unlocked(vault)?;
            Ok(vault.sync_identity()?)
        })?;
        if RelayUrl::parse(&self.config.url)?.as_str() != joined.session.url.as_str() {
            return Err(SyncError::WrongVault);
        }
        *lock(&self.refused) = None;
        self.finish_enable(
            vault,
            Arc::clone(&joined.session),
            &local.vault_id,
            joined.team.clone(),
            passphrase,
        )
    }

    /// The first sync of a new device, then its key, its state, and its link. The
    /// session is in memory from the start, so [`Self::forget`] (a lock, a quit) ends
    /// its relay calls; a failure drops it. `passphrase` is the passphrase of a relay
    /// copy under another passphrase, which the vault takes
    /// ([`Self::enable_joined_with_passphrase`]).
    fn finish_enable<A: VaultAccess + ?Sized>(
        &self,
        vault: &mut A,
        session: Arc<Session>,
        vault_id: &str,
        team: String,
        passphrase: Option<&str>,
    ) -> Result<RelayEnableReport, SyncError> {
        *lock(&self.session) = Some(Arc::clone(&session));
        self.removed.clear();
        let result = self.finish_enable_with(vault, &session, vault_id, team, passphrase);
        if result.is_err() {
            let mut held = lock(&self.session);
            if held
                .as_ref()
                .is_some_and(|held| Arc::ptr_eq(held, &session))
            {
                *held = None;
            }
        }
        ended_by_lock(&session, result)
    }

    fn finish_enable_with<A: VaultAccess + ?Sized>(
        &self,
        vault: &mut A,
        session: &Arc<Session>,
        vault_id: &str,
        team: String,
        passphrase: Option<&str>,
    ) -> Result<RelayEnableReport, SyncError> {
        let device_id = session.device_id().ok_or(SyncError::NotEnabled)?;
        let mut state =
            SyncState::new_relay(session.url.as_str(), &session.team_id, device_id, vault_id);
        let transport = self.transport(Arc::clone(session), &state);
        // The relay copy is the copy of the team: this vault takes its passphrase, as
        // a folder sync does, and merges it (contract section 6).
        let fetched = match passphrase {
            Some(passphrase) => Some(self.rekey_to_copy(vault, &transport, passphrase)?),
            None => None,
        };
        let outcome = self.rounds(vault, &mut state, &transport, false, fetched)?;
        let key = session.key.pkcs8().ok_or(SyncError::Damaged)?.clone();
        let row = RelayDevice {
            relay_url: session.url.as_str().to_owned(),
            team_id: session.team_id.clone(),
            device_id,
            public_key: session.key.public_key().to_vec(),
            key_pkcs8: key,
            created_at: 0,
        };
        vault.with(|vault| Ok(vault.set_relay_device(&row)?))?;
        self.write_state(&state)?;
        if outcome.merge.is_some() {
            transport.send_receipt(state.last_remote_version);
        }
        let link = RelayLink::new(session.url.as_str(), &session.team_id, device_id);
        Ok(RelayEnableReport {
            link,
            team,
            outcome,
        })
    }

    /// Make a new local vault at `RelayConfig::vault_path` from a relay copy that
    /// `download` holds, and turn on relay sync for it (contract section 7.2, steps 5
    /// and 6). `passphrase` must open the copy; a wrong one makes no file, and the
    /// owner can try again with the same download. The new vault opens locked.
    pub fn adopt(
        &self,
        joined: &JoinedDevice,
        download: &RelayDownload,
        passphrase: &str,
    ) -> Result<(Vault, RelayAdoptReport), SyncError> {
        if self.state()?.is_some() {
            return Err(SyncError::AlreadyEnabled);
        }
        let device_id = joined.session.device_id().ok_or(SyncError::NotEnabled)?;
        let (mut vault, adopted) =
            Vault::adopt_sync_copy(&download.file.path, &self.config.vault_path, passphrase)?;
        let new_file = vault.path().to_owned();
        let fail = |vault: Vault, error: SyncError| {
            drop(vault);
            let _ = fs::remove_file(&new_file);
            Err(error)
        };
        if adopted.identity.vault_id != download.head.fields.vault_id {
            return fail(vault, SyncError::OtherVault);
        }
        let session = &joined.session;
        let stored = vault
            .unlock(passphrase)
            .and_then(|()| {
                vault.set_relay_device(&RelayDevice {
                    relay_url: session.url.as_str().to_owned(),
                    team_id: session.team_id.clone(),
                    device_id,
                    public_key: session.key.public_key().to_vec(),
                    key_pkcs8: session.key.pkcs8().cloned().unwrap_or_default(),
                    created_at: 0,
                })
            })
            .and_then(|()| vault.lock());
        if let Err(error) = stored {
            return fail(vault, error.into());
        }
        let mut state = SyncState::new_relay(
            session.url.as_str(),
            &session.team_id,
            device_id,
            &adopted.identity.vault_id,
        );
        state.last_remote_version = download.head.fields.version;
        state.last_head_sha256 = Some(download.head.hash());
        // A copy of an earlier schema: the first sync pushes the current schema.
        state.last_content = (!adopted.outdated()).then(|| to_hex(&adopted.content));
        if let Err(error) = self.write_state(&state) {
            return fail(vault, error);
        }
        RelayTransport::new(Arc::clone(session), None, 0, None, self.max_bytes)
            .send_receipt(download.head.fields.version);
        *lock(&self.session) = Some(Arc::clone(session));
        Ok((
            vault,
            RelayAdoptReport {
                link: RelayLink::new(session.url.as_str(), &session.team_id, device_id),
                identity: adopted.identity,
            },
        ))
    }

    /// Turn relay sync off: remove the relay row of the vault (when it is given and
    /// unlocked) and the state file. The relay keeps the copy and the device. Returns
    /// whether sync was on.
    pub fn disable(&self, vault: Option<&mut Vault>) -> Result<bool, SyncError> {
        if let Some(vault) = vault {
            self.require_unlocked(vault)?;
            vault.remove_relay_device()?;
        }
        self.forget();
        self.removed.clear();
        state::remove(&self.config.state_path)
    }

    /// The long poll of section 11, with the key and the token in memory: the version
    /// that this Mac saw and the relay's version when the relay answered (at once when
    /// they differ, else after a push or `timeout`). `Locked` when the key is not in
    /// memory (no sync since the unlock) or the vault locked during the poll.
    pub fn poll(&self, timeout: Duration) -> Result<RelayPoll, SyncError> {
        let state = self.require_state()?;
        let session = lock(&self.session)
            .clone()
            .ok_or(SyncError::Vault(VaultErrorKind::Locked))?;
        let since = state.last_remote_version;
        let view = self
            .transport(Arc::clone(&session), &state)
            .head_view(since, timeout);
        drop(session);
        match view {
            Ok(view) => Ok(RelayPoll {
                since,
                version: view.version,
            }),
            Err(_) if !self.has_session() => Err(SyncError::Vault(VaultErrorKind::Locked)),
            Err(error) => Err(sync_error(error)),
        }
    }

    /// [`Self::poll`]: whether the relay has another version than this Mac saw.
    pub fn wait_for_change(&self, timeout: Duration) -> Result<bool, SyncError> {
        self.poll(timeout).map(|poll| poll.changed())
    }
}

// ---- A new Mac. ----

/// The new Mac of "Use a vault from another Mac" > "Apassy relay" (contract section
/// 7.2), after it sent its device link. The key and the link code are only in memory
/// until a vault holds the key. Debug is redacted.
pub struct PendingJoin {
    session: Arc<Session>,
    /// The link code, for a cancel before the confirmation.
    code: Zeroizing<String>,
    /// When the next poll may ask the relay, and the wait after the next failure.
    retry: Mutex<(Instant, Duration)>,
    /// The link id on the relay.
    pub link_id: u64,
    /// The team name.
    pub team: String,
    /// The safety words that both Macs show.
    pub safety: String,
    /// Unix time when the link expires.
    pub expires_at: u64,
}

impl fmt::Debug for PendingJoin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingJoin")
            .field("link_id", &self.link_id)
            .field("safety", &self.safety)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
struct LinkAnswer {
    id: u64,
    team_id: String,
    team: String,
    safety: String,
    expires_at: u64,
}

/// The body of `POST /v1/devices/link` and of its cancel.
#[derive(Serialize)]
struct LinkBody<'a> {
    code: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_name: Option<&'a str>,
    public_key: &'a str,
}

impl PendingJoin {
    /// Parse the pasted text: `<relay URL>/link#<code>`, or a bare code with the relay
    /// address `relay_url` from the field above it.
    pub fn parse_link(
        text: &str,
        relay_url: &str,
    ) -> Result<(RelayUrl, Zeroizing<String>), SyncError> {
        let text = text.trim();
        let (url, code) = match text.split_once("/link#") {
            Some((url, code)) => (RelayUrl::parse(url)?, code),
            None => (RelayUrl::parse(relay_url)?, text),
        };
        if link_code_team(code).is_none() {
            return Err(SyncError::Relay(RelayRefusal::Forbidden));
        }
        Ok((url, Zeroizing::new(code.to_owned())))
    }

    /// Make a device key and send the link (`POST /v1/devices/link`). The relay's
    /// safety words must be the ones that this Mac computes.
    pub fn request(text: &str, relay_url: &str, device: &str) -> Result<Self, SyncError> {
        Self::request_with_key(text, relay_url, device, DeviceKey::generate()?)
    }

    /// [`Self::request`] with the device key `key`. A retry of the same code after a
    /// failure sends the same key: the relay then gives the same answer (contract
    /// section 7.2, step 3), so an answer lost on the network does not use up the code.
    pub fn request_with_key(
        text: &str,
        relay_url: &str,
        device: &str,
        key: DeviceKey,
    ) -> Result<Self, SyncError> {
        let (url, code) = Self::parse_link(text, relay_url)?;
        let team_id = link_code_team(&code).unwrap_or_default().to_owned();
        let answer: LinkAnswer = call(
            &url,
            &json_request(
                "POST",
                "/v1/devices/link",
                None,
                &LinkBody {
                    code: code.as_str(),
                    device_name: Some(&clean_name(device, "Mac")),
                    public_key: &key.public_key_b64u(),
                },
            ),
        )
        .map_err(sync_error)?;
        if answer.team_id != team_id {
            return Err(SyncError::RelayUnreachable);
        }
        let safety = safety_words(&team_id, &code, key.public_key());
        if !same_words(&safety, &answer.safety) {
            return Err(SyncError::SafetyMismatch);
        }
        Ok(Self {
            session: Arc::new(Session::new(url, &team_id, key, None)),
            code,
            retry: Mutex::new((Instant::now(), Duration::ZERO)),
            link_id: answer.id,
            team: answer.team,
            safety,
            expires_at: answer.expires_at,
        })
    }

    /// Ask the relay whether the other Mac confirmed (every 5 s, section 7.2 step 4).
    /// `None` while it waits; the device after a confirmation;
    /// `Relay(JoinRefused)` after a refusal or the expiry. A failure that can pass by
    /// itself (no network, a busy or limiting relay) keeps the join waiting: the next
    /// polls skip the relay for 2 seconds, then 4, up to 60.
    pub fn poll(&self) -> Result<Option<JoinedDevice>, SyncError> {
        let waiting = || {
            if unix_now() < self.expires_at {
                Ok(None)
            } else {
                Err(SyncError::Relay(RelayRefusal::JoinRefused))
            }
        };
        if Instant::now() < lock(&self.retry).0 {
            return waiting();
        }
        match self.session.bearer(None) {
            Ok(_) => {
                *lock(&self.retry) = (Instant::now(), Duration::ZERO);
                Ok(Some(JoinedDevice {
                    session: Arc::clone(&self.session),
                    team: self.team.clone(),
                }))
            }
            Err(error) => match sync_error(error) {
                SyncError::Relay(RelayRefusal::JoinPending) => {
                    *lock(&self.retry) = (Instant::now(), Duration::ZERO);
                    waiting()
                }
                error if is_transient(error) => {
                    let mut retry = lock(&self.retry);
                    let wait = if retry.1.is_zero() {
                        JOIN_RETRY_FIRST
                    } else {
                        (retry.1 * 2).min(JOIN_RETRY_MAX)
                    };
                    let wait = wait.max(rate_limited(&self.session.url).unwrap_or_default());
                    *retry = (Instant::now() + wait, wait);
                    drop(retry);
                    waiting()
                }
                other => Err(other),
            },
        }
    }

    /// Cancel before the confirmation (`POST /v1/devices/link/cancel` with the code and
    /// the key): the first Mac no longer shows this Mac, and the link ends. When the
    /// other Mac confirmed in the meantime (`409`), this Mac removes its new device
    /// instead. The key goes with this value.
    pub fn cancel(self) -> Result<(), SyncError> {
        let public_key = self.session.key.public_key_b64u();
        let cancelled = call::<IgnoredAny>(
            &self.session.url,
            &json_request(
                "POST",
                "/v1/devices/link/cancel",
                None,
                &LinkBody {
                    code: self.code.as_str(),
                    device_name: None,
                    public_key: &public_key,
                },
            ),
        );
        match cancelled {
            Ok(_) => Ok(()),
            Err(ApiError::Relay { status: 409, .. }) => {
                JoinedDevice {
                    session: self.session,
                    team: self.team,
                }
                .cancel();
                Ok(())
            }
            Err(error) => Err(sync_error(error)),
        }
    }
}

/// A device that the other Mac confirmed, before a vault holds its key.
pub struct JoinedDevice {
    session: Arc<Session>,
    team: String,
}

impl fmt::Debug for JoinedDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JoinedDevice")
            .field("team", &self.team)
            .finish_non_exhaustive()
    }
}

/// A checked relay copy in the work folder. It is removed on drop.
pub struct RelayDownload {
    file: TempFile,
    head: SignedHead,
}

impl fmt::Debug for RelayDownload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayDownload")
            .field("version", &self.head.fields.version)
            .finish_non_exhaustive()
    }
}

impl RelayDownload {
    /// The version of the copy.
    pub fn version(&self) -> u64 {
        self.head.fields.version
    }
}

impl JoinedDevice {
    /// The team name.
    pub fn team(&self) -> &str {
        &self.team
    }

    /// The device number of this Mac on the relay.
    pub fn device_id(&self) -> u64 {
        self.session.device_id().unwrap_or_default()
    }

    /// Check the current head with no anchor (checks 1, 3, and 6 of section 13; the
    /// adoption checks the vault) and download the copy to `work_dir`. An empty relay
    /// is `RelayEmpty`.
    pub fn download(&self, work_dir: &Path) -> Result<RelayDownload, SyncError> {
        let transport =
            RelayTransport::new(Arc::clone(&self.session), None, 0, None, MAX_SNAPSHOT_BYTES);
        let head = match transport.head()? {
            Remote::Head(head) => head,
            Remote::Empty => return Err(SyncError::RelayEmpty),
            Remote::Unavailable | Remote::NotReady => return Err(SyncError::RelayUnreachable),
        };
        let signed = *head.signed.clone().ok_or(SyncError::Damaged)?;
        state::ensure_private_dir(work_dir)?;
        let file = TempFile::new(work_dir.join(format!(
            ".{}-{}.relay.adopt",
            self.session.team_id,
            self.device_id()
        )))?;
        transport.fetch(&head, &file.path)?;
        Ok(RelayDownload { file, head: signed })
    }

    /// Cancel after a confirmation: remove this device from the relay, best effort
    /// (section 7.2 step 7). The key goes with this value.
    pub fn cancel(self) {
        let _ = self.session.authed(|bearer| {
            // The sign-in before this call names the device.
            let id = self.device_id();
            call::<IgnoredAny>(
                &self.session.url,
                &Request::new("DELETE", format!("/v1/devices/{id}"), Some(bearer)),
            )
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::relay_crypto::{decode_b64u, is_hash_hex};

    const HEAD_1: &str = "YXBhc3N5LXJlbGF5LXN5bmMtaGVhZC12MQowZjNjMmExMC01YjdlLTRkOWEtOGMyMS02ZjBlNGIxZDlhNzcgMSA1Yjc3MzQzYmQ4ODFhNGY0MjViZGUxZWM5OTc5OTQ2ZWMxYWRkMTFkZTAyMDEwZDRjNjMxNTk5NzdiYWM0ZGU4IDE4CjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAgdF83azJtNXE0eDNjLzIgMTc5MDAwMDAwMA";
    const HEAD_2: &str = "YXBhc3N5LXJlbGF5LXN5bmMtaGVhZC12MQowZjNjMmExMC01YjdlLTRkOWEtOGMyMS02ZjBlNGIxZDlhNzcgMiA3ZGQ5MWFiMjFiMzBkZjEyYTk0M2M1MDdkNmU3ZDgwOGY2ZWEyNjA4ZmFhMzIzOWFhN2ZlZDYyMWVjYWUyNDFhIDIwCmQ1NjJhNGM5OTUxYWMzNmIyMTFlZDk3ODZhNjg5N2YxNjg3MDYzOWM1NGRmOWQxNjhjNTZjMzlkNGNlMzg3ZDkgdF83azJtNXE0eDNjLzIgMTc5MDAwMDA2MA";
    const SIGNATURE_1: &str = "MEUCIHD6Ih2lhM6u-hBJFTF2urGCw1UeM8vL3oM2mIDm0MvgAiEAxXcwrQRcPb0WAAgj4tylCij4Qxlbu7jISfCuxGIJDHA";
    const SIGNATURE_2: &str = "MEUCIQDpxvOaoLg8rz7vXW0U0xd6lGyttG8CeaRV76DrHTChYgIgIpwTtg1Z-BqkmTw1uDnO8FHS_YddNgbMPCWJP8KKa-g";
    const PUBLIC: &str =
        "BOpHkB5VvTHXawpUXZxgu44Q97I2bzq9G_uI6tFM9mj8De047e1fNWI8MIERDsaxhBC0ih1DPfXaM4mdBbExjrA";
    const HEAD_1_HASH: &str = "d562a4c9951ac36b211ed9786a6897f16870639c54df9d168c56c39d4ce387d9";
    const HEAD_2_HASH: &str = "2a3d34a3454acf98a897115ed30e8ea195852d7e943c780974c1f2489810cc3c";

    /// Contract section 15: the app accepts the chain [head 1, head 2] from the anchor
    /// (1, head 1 hash) and refuses it from an anchor whose hash differs.
    #[test]
    fn the_vector_chain_links_to_its_anchor_only() {
        let public = decode_b64u(PUBLIC).unwrap();
        let one = SignedHead::from_wire(HEAD_1, SIGNATURE_1).unwrap();
        let two = SignedHead::from_wire(HEAD_2, SIGNATURE_2).unwrap();
        let verify = |head: &SignedHead| Ok(head.verify(&public));
        // From no head at all: the chain starts with the 64 zeros.
        assert_eq!(
            link_chain(0, NO_PREVIOUS, Some(1), &[one.clone(), two.clone()], verify),
            Ok((2, HEAD_2_HASH.to_owned()))
        );
        assert_eq!(
            link_chain(1, HEAD_1_HASH, Some(2), std::slice::from_ref(&two), verify),
            Ok((2, HEAD_2_HASH.to_owned()))
        );
        let other = "1".repeat(64);
        assert_eq!(
            link_chain(1, &other, Some(2), std::slice::from_ref(&two), verify),
            Err(SyncError::ForkedCopy)
        );
        // A chain that starts later than the anchor, or that is empty, is refused.
        assert_eq!(
            link_chain(0, NO_PREVIOUS, Some(2), std::slice::from_ref(&two), verify),
            Err(SyncError::ForkedCopy)
        );
        assert_eq!(
            link_chain(1, HEAD_1_HASH, Some(2), &[], verify),
            Err(SyncError::ForkedCopy)
        );
        // A head signed by another key breaks the chain.
        let stranger = DeviceKey::generate().unwrap();
        assert_eq!(
            link_chain(1, HEAD_1_HASH, Some(2), &[two], |head| Ok(
                head.verify(stranger.public_key())
            )),
            Err(SyncError::ForkedCopy)
        );
    }

    /// Contract section 13, check 3: a live signer verifies any version; a removed one
    /// only up to the last version it pushed; another key, or no signer, never.
    #[test]
    fn a_removed_signer_verifies_only_its_own_versions() {
        let two = SignedHead::from_wire(HEAD_2, SIGNATURE_2).unwrap();
        let signer = |removed, last_version| Signer {
            device_id: 2,
            public_key: PUBLIC.to_owned(),
            removed,
            last_version,
        };
        assert!(signed_by_member(&two, &[signer(false, None)]));
        assert!(signed_by_member(&two, &[signer(true, Some(2))]));
        assert!(signed_by_member(&two, &[signer(true, Some(7))]));
        assert!(!signed_by_member(&two, &[signer(true, Some(1))]));
        assert!(!signed_by_member(&two, &[signer(true, None)]));
        assert!(!signed_by_member(&two, &[]));
        let stranger = DeviceKey::generate().unwrap();
        let other = Signer {
            public_key: stranger.public_key_b64u(),
            ..signer(false, None)
        };
        assert!(!signed_by_member(&two, &[other]));
        let elsewhere = Signer {
            device_id: 3,
            ..signer(false, None)
        };
        assert!(!signed_by_member(&two, &[elsewhere]));
    }

    #[test]
    fn the_start_clears_every_relay_work_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let sync = dir.path().join("sync");
        fs::create_dir_all(&sync).unwrap();
        let left = [
            ".v1.relay.push",
            ".v1.relay-new.relay.push",
            ".v1.relay-new.relay.merge",
            ".v1.relay.passphrase",
            ".t_7k2m5q4x3c-3.relay.adopt",
            ".v1.relay.push-journal",
        ];
        let kept = ["v1.json", "v1.relay-new.json", ".Personal.apassy.merge"];
        for name in left.iter().chain(kept.iter()) {
            fs::write(sync.join(name), b"x").unwrap();
        }
        clear_relay_work(dir.path());
        let mut names: Vec<String> = fs::read_dir(&sync)
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        let mut want: Vec<String> = kept.iter().map(|name| (*name).to_owned()).collect();
        want.sort();
        assert_eq!(names, want);
        // No sync folder: nothing to do.
        clear_relay_work(&dir.path().join("missing"));
    }

    #[test]
    fn transient_failures_are_told_apart() {
        assert!(is_transient(SyncError::RelayUnreachable));
        assert!(is_transient(SyncError::Relay(RelayRefusal::RateLimited)));
        assert!(is_transient(SyncError::Relay(RelayRefusal::Busy)));
        assert!(!is_transient(SyncError::Relay(RelayRefusal::JoinRefused)));
        assert!(!is_transient(SyncError::RemovedFromRelay));
        assert!(!is_transient(SyncError::NeedsPassphrase));
    }

    #[test]
    fn names_are_cut_at_a_character_boundary() {
        assert_eq!(clean_name("  Personal\n ", "Vault"), "Personal");
        assert_eq!(clean_name(" \t", "Vault"), "Vault");
        let long = clean_name(&"ż".repeat(40), "Vault");
        assert_eq!(long.len(), 64);
        assert!(long.chars().all(|ch| ch == 'ż'));
    }

    #[test]
    fn a_pasted_link_names_its_relay_and_a_bare_code_uses_the_field() {
        let code = format!("apassy_lnk_t_7k2m5q4x3c_{}", "ab".repeat(32));
        let (url, parsed) =
            PendingJoin::parse_link(&format!(" https://relay.example.test/link#{code} "), "")
                .unwrap();
        assert_eq!(url.as_str(), "https://relay.example.test");
        assert_eq!(parsed.as_str(), code);
        let (url, _) = PendingJoin::parse_link(&code, "http://127.0.0.1:8787").unwrap();
        assert_eq!(url.as_str(), "http://127.0.0.1:8787");
        assert_eq!(
            PendingJoin::parse_link(&code, "http://relay.example.test:80").unwrap_err(),
            SyncError::InvalidRelayAddress
        );
        assert!(PendingJoin::parse_link("apassy_lnk_bad", "https://r.example.test").is_err());
    }

    #[test]
    fn relay_errors_have_owner_texts() {
        let relay = |status, code: &str| ApiError::Relay {
            status,
            code: code.to_owned(),
            retry_after: None,
        };
        assert_eq!(
            sync_error(relay(412, "precondition_failed")),
            SyncError::PreconditionFailed
        );
        assert_eq!(
            sync_error(relay(401, "token_expired")),
            SyncError::RemovedFromRelay
        );
        assert_eq!(
            sync_error(relay(413, "payload_too_large")),
            SyncError::TooLarge
        );
        assert_eq!(
            sync_error(relay(403, "join_pending")),
            SyncError::Relay(RelayRefusal::JoinPending)
        );
        assert_eq!(sync_error(ApiError::Broken), SyncError::RelayUnreachable);
        assert!(
            SyncError::ForkedCopy
                .to_string()
                .contains("does not include this Mac's last change")
        );
        assert!(SyncError::TooLarge.to_string().contains("64 MiB"));
    }

    #[test]
    fn an_answer_without_an_envelope_is_not_the_relay() {
        let answer = |status, body: &str| Answer::for_test(status, body);
        assert_eq!(
            envelope(&answer(502, "relay unreachable")),
            Err(ApiError::Unreachable)
        );
        assert_eq!(envelope(&answer(200, "{\"ok\":true}")), Ok(Value::Null));
        let token: Result<TokenAnswer, _> = decode(&answer(
            200,
            "{\"ok\":true,\"result\":{\"token\":\"t\",\"expires_at\":1,\"team_id\":\"x\",\"device_id\":2}}",
        ));
        assert_eq!(token.map(|token| token.device_id).ok(), Some(2));
        assert_eq!(
            decode::<TokenAnswer>(&answer(200, "{\"ok\":true,\"result\":{}}")).err(),
            Some(ApiError::Unreachable)
        );
        assert_eq!(
            envelope(&answer(302, "{\"ok\":true,\"result\":1}")),
            Err(ApiError::Unreachable)
        );
        assert!(matches!(
            envelope(&answer(
                412,
                "{\"ok\":false,\"error\":{\"code\":\"precondition_failed\",\"message\":\"x\"}}"
            )),
            Err(ApiError::Relay { status: 412, .. })
        ));
        assert!(is_hash_hex(HEAD_1_HASH));
        let _ = HeadFields::parse("");
    }

    /// A lock ends the device calls in flight at once ("Devices…", "Remove", a new
    /// link), also when the relay never answers, and they fail with `Locked`.
    #[test]
    fn a_lock_ends_the_device_calls_at_once() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        // A relay that takes the requests and never answers.
        std::thread::spawn(move || {
            let mut held = Vec::new();
            for stream in listener.incoming().flatten() {
                held.push(stream);
            }
        });
        let dir = tempfile::TempDir::new().unwrap();
        let sync = RelaySync::new(RelayConfig::in_data_dir(
            dir.path(),
            &dir.path().join("vault.db"),
            &url,
            "vault",
        ));
        let session = Session::new(
            RelayUrl::parse(&url).unwrap(),
            "t_7k2m5q4x3c",
            DeviceKey::generate().unwrap(),
            Some(2),
        );
        // A token in memory: the calls go to the relay without a sign-in.
        *lock(&session.token) = Some(Token {
            value: Zeroizing::new("apassy_acc_t_7k2m5q4x3c_00".to_owned()),
            until: Instant::now() + TOKEN_LIFETIME,
        });
        *lock(&sync.session) = Some(Arc::new(session));
        let calls: Vec<_> = (0..3)
            .map(|call| {
                let sync = sync.clone();
                std::thread::spawn(move || {
                    let started = Instant::now();
                    let result = match call {
                        0 => sync.devices(KeySource::Memory).map(|_| ()),
                        1 => sync.remove_device(KeySource::Memory, 3),
                        _ => sync.create_link(KeySource::Memory).map(|_| ()),
                    };
                    (result, started.elapsed())
                })
            })
            .collect();
        std::thread::sleep(Duration::from_millis(500));
        sync.forget();
        for call in calls {
            let (result, took) = call.join().unwrap();
            assert_eq!(result, Err(SyncError::Vault(VaultErrorKind::Locked)));
            assert!(took < Duration::from_secs(3), "{took:?}");
        }
    }
}
