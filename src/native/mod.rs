//! Client for the Swift native helper in `Apassy.app` (ADR 0010).
//!
//! The crate forbids unsafe code. Touch ID (LocalAuthentication), the data
//! protection keychain, and native notifications need Apple APIs, so a small
//! Swift helper calls them. This module starts the helper, writes one JSON
//! request line, and reads one JSON response line within a time limit. The
//! protocol and the error codes are in `docs/operations/native-app.md`.
//!
//! The bundle has two copies of the helper:
//! - `Contents/MacOS/apassy-helper` runs `authenticate` and the notification
//!   commands. Notifications then belong to the `com.wydrox.apassy` bundle.
//! - `Contents/Helpers/ApassyKeychain.app/Contents/MacOS/ApassyKeychain` runs
//!   the keychain commands. It has its own provisioning profile, because
//!   macOS permits the keychain entitlements only for the main executable of
//!   a bundle with a matching profile.
//!
//! Secret handling: [`KeychainSecret`] has a redacted `Debug` and no
//! `Clone`. The client overwrites its own request and response buffers after
//! use. This is best effort. It does not erase copies in the helper, in the
//! allocator, in swap, or in crash dumps.

mod base64;

use std::fmt;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde_json::{Map, Value};

/// Protocol version that `ping` returns.
pub const PROTOCOL_VERSION: u64 = 1;
/// Debug builds only: path of the helper for tests and development.
pub const HELPER_ENV: &str = "APASSY_NATIVE_HELPER";
/// Debug builds only: path of the keychain helper. Defaults to [`HELPER_ENV`].
pub const KEYCHAIN_HELPER_ENV: &str = "APASSY_NATIVE_KEYCHAIN_HELPER";
/// File name of the helper next to the `apassy` executable.
pub const HELPER_FILE: &str = "apassy-helper";
/// Path of the keychain helper, relative to `Contents`.
pub const KEYCHAIN_HELPER_FROM_CONTENTS: &str =
    "Helpers/ApassyKeychain.app/Contents/MacOS/ApassyKeychain";
/// Keychain service of the Touch ID unlock item. It matches `keychainService` in
/// `native/ApassyHelper/Keychain.swift`.
pub const KEYCHAIN_SERVICE: &str = "com.wydrox.apassy.vault-unlock";
/// Prefix of the keychain account for one vault file.
pub const UNLOCK_ACCOUNT_PREFIX: &str = "vault-unlock-";
/// Largest keychain secret, in bytes. The helper has the same limit.
pub const MAX_SECRET_BYTES: usize = 4096;
/// Largest Touch ID reason, in characters. The helper has the same limit.
pub const MAX_REASON_CHARS: usize = 200;
/// Largest agent name in a notification, in characters.
pub const MAX_AGENT_NAME_CHARS: usize = 40;
const MAX_IDENTIFIER_CHARS: usize = 64;
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_MESSAGE_CHARS: usize = 400;
const EXIT_GRACE: Duration = Duration::from_secs(2);

/// Error codes from the helper. The list matches `ErrorCode` in
/// `native/ApassyHelper/Protocol.swift`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HelperErrorCode {
    /// The request was malformed. This is a bug in the caller.
    InvalidRequest,
    /// The owner or the system cancelled the Touch ID prompt.
    Cancelled,
    /// The owner selected "Use Apassy Passphrase". Ask for the passphrase.
    Fallback,
    /// Touch ID is not available: no sensor, or the keyboard is not paired.
    NotAvailable,
    /// No fingerprint is enrolled.
    NotEnrolled,
    /// Touch ID is locked after failed attempts. The Mac password resets it.
    LockedOut,
    /// Touch ID did not confirm the owner, or a keychain call failed.
    Failed,
    /// The keychain helper has no provisioning profile or entitlement.
    /// Touch ID can confirm actions but cannot unlock the vault.
    KeychainUnavailable,
    /// No unlock key is in the keychain.
    NotFound,
    /// The fingerprints changed after setup. The item is not usable.
    /// Unlock with the passphrase, delete the item, and set up again.
    BiometryChanged,
    /// The helper is not inside an app bundle.
    NotificationsUnavailable,
    /// The owner did not allow notifications. The event stays in the inbox.
    NotificationsDenied,
    /// The helper refused the request, because its parent process is not the
    /// signed Apassy app that contains it. A program other than Apassy.app
    /// started the helper.
    CallerNotAllowed,
    /// An unexpected helper error.
    Internal,
}

impl HelperErrorCode {
    pub const ALL: [Self; 14] = [
        Self::InvalidRequest,
        Self::Cancelled,
        Self::Fallback,
        Self::NotAvailable,
        Self::NotEnrolled,
        Self::LockedOut,
        Self::Failed,
        Self::KeychainUnavailable,
        Self::NotFound,
        Self::BiometryChanged,
        Self::NotificationsUnavailable,
        Self::NotificationsDenied,
        Self::CallerNotAllowed,
        Self::Internal,
    ];

    /// The code on the wire.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::Cancelled => "cancelled",
            Self::Fallback => "fallback",
            Self::NotAvailable => "not_available",
            Self::NotEnrolled => "not_enrolled",
            Self::LockedOut => "locked_out",
            Self::Failed => "failed",
            Self::KeychainUnavailable => "keychain_unavailable",
            Self::NotFound => "not_found",
            Self::BiometryChanged => "biometry_changed",
            Self::NotificationsUnavailable => "notifications_unavailable",
            Self::NotificationsDenied => "notifications_denied",
            Self::CallerNotAllowed => "caller_not_allowed",
            Self::Internal => "internal",
        }
    }

    pub fn from_wire(code: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|candidate| candidate.as_str() == code)
    }
}

impl fmt::Display for HelperErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A failed helper call. No variant holds a secret value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeError {
    /// A client check failed. The client did not start the helper.
    InvalidArgument(&'static str),
    /// No helper file at this path.
    HelperMissing(PathBuf),
    /// The helper did not start, or a pipe failed.
    Io(String),
    /// No response within the time limit. The client stopped the helper.
    Timeout(Duration),
    /// The response broke the protocol, or the helper exited without one.
    Protocol(String),
    /// The helper answered with an error code.
    Helper {
        code: HelperErrorCode,
        message: String,
    },
}

impl NativeError {
    /// The helper error code, if the helper answered with one.
    pub fn code(&self) -> Option<HelperErrorCode> {
        match self {
            Self::Helper { code, .. } => Some(*code),
            _ => None,
        }
    }
}

impl fmt::Display for NativeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArgument(what) => write!(f, "invalid argument: {what}"),
            Self::HelperMissing(path) => {
                write!(f, "the native helper is missing at {}", path.display())
            }
            Self::Io(err) => write!(f, "the native helper failed to run: {err}"),
            Self::Timeout(limit) => write!(
                f,
                "the native helper did not answer within {} s",
                limit.as_secs()
            ),
            Self::Protocol(err) => write!(f, "the native helper broke the protocol: {err}"),
            Self::Helper { code, message } => write!(f, "{code}: {message}"),
        }
    }
}

impl std::error::Error for NativeError {}

/// Secret bytes for the keychain, for example the vault unlock key.
/// `Debug` is redacted. There is no `Clone` and no `Serialize`. Drop
/// overwrites the bytes (best effort).
pub struct KeychainSecret(Vec<u8>);

impl KeychainSecret {
    /// Accepts 1 to [`MAX_SECRET_BYTES`] bytes.
    pub fn new(bytes: Vec<u8>) -> Result<Self, NativeError> {
        if bytes.is_empty() || bytes.len() > MAX_SECRET_BYTES {
            let mut bytes = bytes;
            wipe(&mut bytes);
            return Err(NativeError::InvalidArgument(
                "a keychain secret must have 1 to 4096 bytes",
            ));
        }
        Ok(Self(bytes))
    }

    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for KeychainSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeychainSecret([redacted])")
    }
}

impl Drop for KeychainSecret {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

fn wipe(bytes: &mut [u8]) {
    bytes.fill(0);
    std::hint::black_box(bytes);
}

fn wipe_string(text: String) {
    let mut bytes = text.into_bytes();
    wipe(&mut bytes);
}

/// Touch ID state from `ping`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Biometry {
    Available,
    /// `NotAvailable`, `NotEnrolled`, `LockedOut`, or another code.
    Unavailable(HelperErrorCode),
}

/// Result of `ping`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelperInfo {
    pub protocol: u64,
    pub helper_version: String,
    /// The bundle that the helper found. `None` outside an app bundle.
    pub bundle_id: Option<String>,
    /// The keychain access group from the signed entitlements. `None` means
    /// that keychain commands return `keychain_unavailable`.
    pub keychain_access_group: Option<String>,
    pub biometry: Biometry,
}

/// Result of `keychain_exists`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeychainItemState {
    pub exists: bool,
    /// True when the fingerprints changed after the item was stored.
    pub biometry_changed: bool,
}

/// Notification permission of the Apassy bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationAuthorization {
    NotDetermined,
    Denied,
    Authorized,
    Provisional,
    Unknown,
}

/// One notification setting of the Apassy bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationSetting {
    NotSupported,
    Disabled,
    Enabled,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertStyle {
    None,
    Banner,
    Alert,
    Unknown,
}

/// Result of `notify_status` and `notify_authorize`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotificationStatus {
    pub authorization: NotificationAuthorization,
    pub alert: NotificationSetting,
    pub alert_style: AlertStyle,
    pub notification_center: NotificationSetting,
    pub lock_screen: NotificationSetting,
    pub sound: NotificationSetting,
}

impl NotificationStatus {
    /// True when macOS can show an Apassy notification to the owner. When
    /// false, the app shows a delivery problem next to the inbox.
    pub fn can_deliver(&self) -> bool {
        matches!(
            self.authorization,
            NotificationAuthorization::Authorized | NotificationAuthorization::Provisional
        ) && (self.alert == NotificationSetting::Enabled
            || self.notification_center == NotificationSetting::Enabled)
    }
}

/// Result of `notify`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotifyOutcome {
    /// True when Notification Center lists the notification.
    pub delivered: bool,
    pub status: NotificationStatus,
}

/// Event types that can cause a notification (goal N1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationEvent {
    /// A run waits for the owner.
    ApprovalWaiting,
    /// The bouncer or a rule blocked a request.
    RequestBlocked,
}

/// A notification preview. The only inputs are the agent name and the event
/// type (goal N2). There is no constructor for free text, so a command, a
/// user request, or a value cannot get into a preview through this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notification {
    id: String,
    title: String,
    body: String,
}

impl Notification {
    /// `event_id` identifies the inbox event. A second notification with the
    /// same id replaces the first. `agent_name` is the owner's label for the
    /// agent.
    pub fn new(
        event_id: &str,
        agent_name: &str,
        event: NotificationEvent,
    ) -> Result<Self, NativeError> {
        check_identifier(event_id, EVENT_ID_RULE)?;
        if agent_name.trim().is_empty()
            || agent_name.chars().count() > MAX_AGENT_NAME_CHARS
            || agent_name.chars().any(char::is_control)
        {
            return Err(NativeError::InvalidArgument(
                "the agent name must have 1 to 40 characters and no control characters",
            ));
        }
        let (title, body) = match event {
            NotificationEvent::ApprovalWaiting => (
                "Approval waiting",
                format!("Agent \"{agent_name}\" waits for your decision. Open Apassy to review."),
            ),
            NotificationEvent::RequestBlocked => (
                "Request blocked",
                format!("Apassy blocked a request from agent \"{agent_name}\"."),
            ),
        };
        Ok(Self {
            id: event_id.to_owned(),
            title: title.to_owned(),
            body,
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn title(&self) -> &str {
        &self.title
    }

    pub fn body(&self) -> &str {
        &self.body
    }
}

/// Time limits for helper calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    /// `ping`, `keychain_store`, `keychain_exists`, `keychain_delete`,
    /// `notify_status`.
    pub quick: Duration,
    /// `notify`. The helper can wait 20 s for the first permission prompt.
    pub notify: Duration,
    /// `authenticate`, `keychain_read`, `notify_authorize`: they wait for
    /// the owner.
    pub interactive: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            quick: Duration::from_secs(10),
            notify: Duration::from_secs(40),
            interactive: Duration::from_secs(180),
        }
    }
}

/// Paths of the helper programs and the time limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeHelper {
    helper: PathBuf,
    keychain_helper: PathBuf,
    timeouts: Timeouts,
}

impl NativeHelper {
    /// Use explicit helper paths. Tests use this with a fake helper.
    pub fn with_paths(helper: impl Into<PathBuf>, keychain_helper: impl Into<PathBuf>) -> Self {
        Self {
            helper: helper.into(),
            keychain_helper: keychain_helper.into(),
            timeouts: Timeouts::default(),
        }
    }

    pub fn with_timeouts(mut self, timeouts: Timeouts) -> Self {
        self.timeouts = timeouts;
        self
    }

    /// Find the helpers in the bundle of the running executable.
    ///
    /// Debug builds first read [`HELPER_ENV`] and [`KEYCHAIN_HELPER_ENV`].
    /// Release builds ignore them: a process that can set the environment
    /// of the app must not replace the Touch ID check with a fake helper.
    pub fn locate() -> Result<Self, NativeError> {
        let exe = std::env::current_exe()
            .and_then(std::fs::canonicalize)
            .map_err(|err| NativeError::Io(format!("cannot find the running executable: {err}")))?;
        Ok(Self::resolve(
            cfg!(debug_assertions),
            env_path(HELPER_ENV),
            env_path(KEYCHAIN_HELPER_ENV),
            &exe,
        ))
    }

    fn resolve(
        allow_env: bool,
        env_helper: Option<PathBuf>,
        env_keychain: Option<PathBuf>,
        exe: &Path,
    ) -> Self {
        match env_helper {
            Some(helper) if allow_env => {
                let keychain = env_keychain.unwrap_or_else(|| helper.clone());
                Self::with_paths(helper, keychain)
            }
            _ => Self::for_executable(exe),
        }
    }

    /// Helper paths for an `apassy` executable at `exe`
    /// (`Apassy.app/Contents/MacOS/apassy`).
    pub fn for_executable(exe: &Path) -> Self {
        let macos = exe.parent().unwrap_or_else(|| Path::new("."));
        let contents = macos.parent().unwrap_or(macos);
        Self::with_paths(
            macos.join(HELPER_FILE),
            contents.join(KEYCHAIN_HELPER_FROM_CONTENTS),
        )
    }

    pub fn helper_path(&self) -> &Path {
        &self.helper
    }

    pub fn keychain_helper_path(&self) -> &Path {
        &self.keychain_helper
    }

    /// `ping` on the main helper.
    pub fn ping(&self) -> Result<HelperInfo, NativeError> {
        parse_info(&self.call(&self.helper, request("ping"), self.timeouts.quick)?)
    }

    /// `ping` on the keychain helper. `keychain_access_group` tells if Touch
    /// ID unlock is possible in this build.
    pub fn ping_keychain(&self) -> Result<HelperInfo, NativeError> {
        parse_info(&self.call(&self.keychain_helper, request("ping"), self.timeouts.quick)?)
    }

    /// Show the Touch ID prompt with `reason`. `Ok` means that the owner
    /// passed Touch ID now. `Fallback` and `Cancelled` mean: ask for the
    /// Apassy passphrase.
    pub fn authenticate(&self, reason: &str) -> Result<(), NativeError> {
        check_reason(reason)?;
        let mut req = request("authenticate");
        req.insert("reason".into(), Value::String(reason.to_owned()));
        self.call(&self.helper, req, self.timeouts.interactive)
            .map(drop)
    }

    /// Store `secret` under `account`. The item needs the current
    /// fingerprints. A stored item with the same account is replaced.
    pub fn keychain_store(
        &self,
        account: &str,
        secret: &KeychainSecret,
    ) -> Result<(), NativeError> {
        check_identifier(account, ACCOUNT_RULE)?;
        let mut req = request("keychain_store");
        req.insert("account".into(), Value::String(account.to_owned()));
        req.insert(
            "secret_b64".into(),
            Value::String(base64::encode(secret.expose())),
        );
        self.call(&self.keychain_helper, req, self.timeouts.quick)
            .map(drop)
    }

    /// Show the Touch ID prompt with `reason` and read the secret.
    pub fn keychain_read(
        &self,
        account: &str,
        reason: &str,
    ) -> Result<KeychainSecret, NativeError> {
        check_identifier(account, ACCOUNT_RULE)?;
        check_reason(reason)?;
        let mut req = request("keychain_read");
        req.insert("account".into(), Value::String(account.to_owned()));
        req.insert("reason".into(), Value::String(reason.to_owned()));
        let mut response = self.call(&self.keychain_helper, req, self.timeouts.interactive)?;
        let Some(Value::String(encoded)) = response.remove("secret_b64") else {
            return Err(NativeError::Protocol(
                "keychain_read has no secret_b64".into(),
            ));
        };
        let decoded = base64::decode(&encoded);
        wipe_string(encoded);
        match decoded {
            Some(bytes) => KeychainSecret::new(bytes)
                .map_err(|_| NativeError::Protocol("keychain_read returned a bad length".into())),
            None => Err(NativeError::Protocol(
                "keychain_read returned invalid base64".into(),
            )),
        }
    }

    /// Delete the item. Returns true when an item was deleted.
    pub fn keychain_delete(&self, account: &str) -> Result<bool, NativeError> {
        check_identifier(account, ACCOUNT_RULE)?;
        let mut req = request("keychain_delete");
        req.insert("account".into(), Value::String(account.to_owned()));
        let response = self.call(&self.keychain_helper, req, self.timeouts.quick)?;
        bool_field(&response, "deleted")
    }

    /// Check the item without a prompt.
    pub fn keychain_exists(&self, account: &str) -> Result<KeychainItemState, NativeError> {
        check_identifier(account, ACCOUNT_RULE)?;
        let mut req = request("keychain_exists");
        req.insert("account".into(), Value::String(account.to_owned()));
        let response = self.call(&self.keychain_helper, req, self.timeouts.quick)?;
        Ok(KeychainItemState {
            exists: bool_field(&response, "exists")?,
            biometry_changed: bool_field(&response, "biometry_changed")?,
        })
    }

    /// Post a notification. On first use, macOS asks the owner for
    /// permission. A notification is not an approval (goal N4).
    pub fn notify(&self, notification: &Notification) -> Result<NotifyOutcome, NativeError> {
        let mut req = request("notify");
        req.insert("id".into(), Value::String(notification.id.clone()));
        req.insert("title".into(), Value::String(notification.title.clone()));
        req.insert("body".into(), Value::String(notification.body.clone()));
        let response = self.call(&self.helper, req, self.timeouts.notify)?;
        Ok(NotifyOutcome {
            delivered: bool_field(&response, "delivered")?,
            status: parse_status(&response)?,
        })
    }

    /// Notification permission and settings. Never shows a prompt.
    pub fn notify_status(&self) -> Result<NotificationStatus, NativeError> {
        parse_status(&self.call(&self.helper, request("notify_status"), self.timeouts.quick)?)
    }

    /// Show the notification permission prompt if the owner has not decided.
    pub fn notify_authorize(&self) -> Result<NotificationStatus, NativeError> {
        parse_status(&self.call(
            &self.helper,
            request("notify_authorize"),
            self.timeouts.interactive,
        )?)
    }

    /// Send one request and return the fields of a successful response.
    fn call(
        &self,
        program: &Path,
        mut req: Map<String, Value>,
        timeout: Duration,
    ) -> Result<Map<String, Value>, NativeError> {
        let line = serde_json::to_vec(&req);
        if let Some(Value::String(secret)) = req.remove("secret_b64") {
            wipe_string(secret);
        }
        let mut line =
            line.map_err(|err| NativeError::Protocol(format!("cannot encode: {err}")))?;
        line.push(b'\n');
        let mut raw = exchange(program, line, timeout)?;
        let parsed = serde_json::from_slice::<Value>(&raw);
        wipe(&mut raw);
        let Ok(Value::Object(mut fields)) = parsed else {
            return Err(NativeError::Protocol(
                "the response is not a JSON object".into(),
            ));
        };
        match fields.get("ok") {
            Some(Value::Bool(true)) => Ok(fields),
            Some(Value::Bool(false)) => {
                let code = match fields.remove("error") {
                    Some(Value::String(code)) => code,
                    _ => return Err(NativeError::Protocol("an error has no code".into())),
                };
                let code = HelperErrorCode::from_wire(&code).ok_or_else(|| {
                    NativeError::Protocol(format!("unknown error code {:?}", truncate(&code)))
                })?;
                let message = match fields.remove("message") {
                    Some(Value::String(message)) => truncate(&message),
                    _ => String::new(),
                };
                Err(NativeError::Helper { code, message })
            }
            _ => Err(NativeError::Protocol("the response has no ok flag".into())),
        }
    }
}

/// Keychain account of the Touch ID unlock item for the vault file at `vault_path`
/// (goal item A3). Use the canonical path. The account is `vault-unlock-` and 16
/// hexadecimal digits of the 64-bit FNV-1a hash of the path bytes. The hash hides
/// the path in the keychain attributes. It does not change between Rust releases.
/// A vault file at another path has another account, so Touch ID unlock is off for
/// a moved or restored file until the owner turns it on again.
pub fn vault_unlock_account(vault_path: &Path) -> String {
    use std::os::unix::ffi::OsStrExt;
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in vault_path.as_os_str().as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{UNLOCK_ACCOUNT_PREFIX}{hash:016x}")
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn request(cmd: &str) -> Map<String, Value> {
    let mut map = Map::new();
    map.insert("cmd".into(), Value::String(cmd.to_owned()));
    map
}

fn truncate(text: &str) -> String {
    text.chars().take(MAX_MESSAGE_CHARS).collect()
}

const ACCOUNT_RULE: &str =
    "the account must have 1 to 64 characters from A-Z, a-z, 0-9, '.', '_', '-'";
const EVENT_ID_RULE: &str =
    "the event id must have 1 to 64 characters from A-Z, a-z, 0-9, '.', '_', '-'";

fn check_identifier(value: &str, rule: &'static str) -> Result<(), NativeError> {
    let valid = !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_CHARS
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if valid {
        Ok(())
    } else {
        Err(NativeError::InvalidArgument(rule))
    }
}

fn check_reason(reason: &str) -> Result<(), NativeError> {
    if reason.trim().is_empty()
        || reason.chars().count() > MAX_REASON_CHARS
        || reason.chars().any(char::is_control)
    {
        return Err(NativeError::InvalidArgument(
            "the reason must have 1 to 200 characters and no control characters",
        ));
    }
    Ok(())
}

fn bool_field(fields: &Map<String, Value>, name: &str) -> Result<bool, NativeError> {
    fields
        .get(name)
        .and_then(Value::as_bool)
        .ok_or_else(|| NativeError::Protocol(format!("the response has no boolean {name}")))
}

fn str_field<'a>(fields: &'a Map<String, Value>, name: &str) -> Result<&'a str, NativeError> {
    fields
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| NativeError::Protocol(format!("the response has no string {name}")))
}

fn optional_str(fields: &Map<String, Value>, name: &str) -> Result<Option<String>, NativeError> {
    match fields.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text.clone())),
        Some(_) => Err(NativeError::Protocol(format!(
            "{name} is not a string or null"
        ))),
    }
}

fn parse_info(fields: &Map<String, Value>) -> Result<HelperInfo, NativeError> {
    let protocol = fields
        .get("protocol")
        .and_then(Value::as_u64)
        .ok_or_else(|| NativeError::Protocol("ping has no protocol number".into()))?;
    if protocol != PROTOCOL_VERSION {
        return Err(NativeError::Protocol(format!(
            "the helper speaks protocol {protocol}, the app speaks {PROTOCOL_VERSION}"
        )));
    }
    let biometry = match str_field(fields, "biometry")? {
        "available" => Biometry::Available,
        code => Biometry::Unavailable(HelperErrorCode::from_wire(code).ok_or_else(|| {
            NativeError::Protocol(format!("unknown biometry state {:?}", truncate(code)))
        })?),
    };
    Ok(HelperInfo {
        protocol,
        helper_version: str_field(fields, "helper_version")?.to_owned(),
        bundle_id: optional_str(fields, "bundle_id")?,
        keychain_access_group: optional_str(fields, "keychain_access_group")?,
        biometry,
    })
}

fn parse_setting(
    fields: &Map<String, Value>,
    name: &str,
) -> Result<NotificationSetting, NativeError> {
    Ok(match str_field(fields, name)? {
        "not_supported" => NotificationSetting::NotSupported,
        "disabled" => NotificationSetting::Disabled,
        "enabled" => NotificationSetting::Enabled,
        _ => NotificationSetting::Unknown,
    })
}

fn parse_status(fields: &Map<String, Value>) -> Result<NotificationStatus, NativeError> {
    let authorization = match str_field(fields, "authorization")? {
        "not_determined" => NotificationAuthorization::NotDetermined,
        "denied" => NotificationAuthorization::Denied,
        "authorized" => NotificationAuthorization::Authorized,
        "provisional" => NotificationAuthorization::Provisional,
        _ => NotificationAuthorization::Unknown,
    };
    let alert_style = match str_field(fields, "alert_style")? {
        "none" => AlertStyle::None,
        "banner" => AlertStyle::Banner,
        "alert" => AlertStyle::Alert,
        _ => AlertStyle::Unknown,
    };
    Ok(NotificationStatus {
        authorization,
        alert: parse_setting(fields, "alert")?,
        alert_style,
        notification_center: parse_setting(fields, "notification_center")?,
        lock_screen: parse_setting(fields, "lock_screen")?,
        sound: parse_setting(fields, "sound")?,
    })
}

/// Start `program`, write `line`, and read one response line. The helper
/// stops after the time limit.
fn exchange(program: &Path, mut line: Vec<u8>, timeout: Duration) -> Result<Vec<u8>, NativeError> {
    if !program.is_file() {
        wipe(&mut line);
        return Err(NativeError::HelperMissing(program.to_path_buf()));
    }
    let spawned = Command::new(program)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();
    let mut child = match spawned {
        Ok(child) => child,
        Err(err) => {
            wipe(&mut line);
            return Err(NativeError::Io(format!(
                "cannot start {}: {err}",
                program.display()
            )));
        }
    };
    let (Some(mut stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
        wipe(&mut line);
        stop(&mut child);
        return Err(NativeError::Io("the helper pipes are missing".into()));
    };
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let written = stdin.write_all(&line).and_then(|()| stdin.flush());
        wipe(&mut line);
        drop(stdin);
        let result = match written {
            Ok(()) => read_line(stdout),
            Err(err) => Err(NativeError::Io(format!("cannot write the request: {err}"))),
        };
        let _ = sender.send(result);
    });
    match receiver.recv_timeout(timeout) {
        Ok(Ok(response)) => {
            reap(&mut child);
            Ok(response)
        }
        Ok(Err(err)) => {
            stop(&mut child);
            Err(err)
        }
        Err(_) => {
            stop(&mut child);
            Err(NativeError::Timeout(timeout))
        }
    }
}

fn read_line(stdout: impl Read) -> Result<Vec<u8>, NativeError> {
    let mut reader = BufReader::new(stdout.take(MAX_RESPONSE_BYTES as u64 + 1));
    let mut buffer = Vec::new();
    reader
        .read_until(b'\n', &mut buffer)
        .map_err(|err| NativeError::Io(format!("cannot read the response: {err}")))?;
    if buffer.last() != Some(&b'\n') {
        let reason = if buffer.len() > MAX_RESPONSE_BYTES {
            "the response is too long"
        } else {
            "the helper exited without a complete response"
        };
        wipe(&mut buffer);
        return Err(NativeError::Protocol(reason.into()));
    }
    buffer.pop();
    Ok(buffer)
}

/// Wait for the helper to exit after its response. Stop it after a grace time.
fn reap(child: &mut Child) {
    let start = Instant::now();
    while start.elapsed() < EXIT_GRACE {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => return,
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
        }
    }
    stop(child);
}

fn stop(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_round_trip() {
        for code in HelperErrorCode::ALL {
            assert_eq!(HelperErrorCode::from_wire(code.as_str()), Some(code));
        }
        assert_eq!(HelperErrorCode::from_wire("CANCELLED"), None);
        assert_eq!(HelperErrorCode::from_wire(""), None);
    }

    #[test]
    fn secret_debug_is_redacted_and_limits_hold() {
        let secret = KeychainSecret::new(b"synthetic-secret-123".to_vec()).expect("valid");
        let debug = format!("{secret:?}");
        assert_eq!(debug, "KeychainSecret([redacted])");
        assert!(!debug.contains("synthetic"));
        assert!(KeychainSecret::new(Vec::new()).is_err());
        assert!(KeychainSecret::new(vec![7; MAX_SECRET_BYTES]).is_ok());
        assert!(KeychainSecret::new(vec![7; MAX_SECRET_BYTES + 1]).is_err());
    }

    #[test]
    fn identifiers_and_reasons_are_checked() {
        assert!(check_identifier("vault-unlock.v1_A", ACCOUNT_RULE).is_ok());
        for bad in ["", "has space", "slash/x", "ünicode", &"a".repeat(65)] {
            assert!(check_identifier(bad, ACCOUNT_RULE).is_err(), "{bad:?}");
        }
        assert!(check_reason("Unlock the Apassy vault").is_ok());
        for bad in ["", "   ", "line\nbreak", &"r".repeat(201)] {
            assert!(check_reason(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn unlock_account_is_stable_and_valid() {
        // FNV-1a test vectors: the empty input and "a".
        assert_eq!(
            vault_unlock_account(Path::new("")),
            "vault-unlock-cbf29ce484222325"
        );
        assert_eq!(
            vault_unlock_account(Path::new("a")),
            "vault-unlock-af63dc4c8601ec8c"
        );
        let one = vault_unlock_account(Path::new("/Users/owner/vault.db"));
        let other = vault_unlock_account(Path::new("/Users/owner/vault2.db"));
        assert_ne!(one, other);
        assert!(check_identifier(&one, ACCOUNT_RULE).is_ok());
        assert!(!one.contains("owner"));
    }

    #[test]
    fn bundle_paths_follow_the_app_layout() {
        let helper = NativeHelper::for_executable(Path::new("/A/Apassy.app/Contents/MacOS/apassy"));
        assert_eq!(
            helper.helper_path(),
            Path::new("/A/Apassy.app/Contents/MacOS/apassy-helper")
        );
        assert_eq!(
            helper.keychain_helper_path(),
            Path::new(
                "/A/Apassy.app/Contents/Helpers/ApassyKeychain.app/Contents/MacOS/ApassyKeychain"
            )
        );
    }

    #[test]
    fn env_override_applies_only_when_allowed() {
        let exe = Path::new("/A/Apassy.app/Contents/MacOS/apassy");
        let fake = PathBuf::from("/tmp/fake-helper");
        let fake_kc = PathBuf::from("/tmp/fake-keychain");

        let release = NativeHelper::resolve(false, Some(fake.clone()), Some(fake_kc.clone()), exe);
        assert_eq!(release, NativeHelper::for_executable(exe));

        let debug = NativeHelper::resolve(true, Some(fake.clone()), Some(fake_kc.clone()), exe);
        assert_eq!(debug.helper_path(), fake);
        assert_eq!(debug.keychain_helper_path(), fake_kc);

        let one = NativeHelper::resolve(true, Some(fake.clone()), None, exe);
        assert_eq!(one.keychain_helper_path(), fake);

        let none = NativeHelper::resolve(true, None, Some(fake_kc), exe);
        assert_eq!(none, NativeHelper::for_executable(exe));
    }

    #[test]
    fn delivery_needs_permission_and_a_visible_setting() {
        let mut status = NotificationStatus {
            authorization: NotificationAuthorization::Authorized,
            alert: NotificationSetting::Enabled,
            alert_style: AlertStyle::Banner,
            notification_center: NotificationSetting::Enabled,
            lock_screen: NotificationSetting::Enabled,
            sound: NotificationSetting::Enabled,
        };
        assert!(status.can_deliver());
        status.alert = NotificationSetting::Disabled;
        assert!(status.can_deliver());
        status.notification_center = NotificationSetting::Disabled;
        assert!(!status.can_deliver());
        status.alert = NotificationSetting::Enabled;
        status.authorization = NotificationAuthorization::Denied;
        assert!(!status.can_deliver());
        status.authorization = NotificationAuthorization::NotDetermined;
        assert!(!status.can_deliver());
    }
}
