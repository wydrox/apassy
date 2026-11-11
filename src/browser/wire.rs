//! Browser wire version 1 (ADR 0021, `docs/contracts/browser-v1.md`).
//!
//! The extension sends one [`Request`] through the native messaging host, and the app
//! answers one [`Response`]. Two messages have a secret value: the request of a save
//! (the password that the owner typed on the page), and the answer of a fill or of a new
//! login (the password, after the owner check).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::owner::wire::SecretText;

pub const BROWSER_WIRE_VERSION: u32 = 1;
/// The name of the native messaging host in its manifest.
pub const HOST_NAME: &str = "com.wydrox.apassy";
/// The ID of the extension. The manifest of the extension has the public key of this ID.
pub const EXTENSION_ID: &str = "bbnpgnjnfjlbgggmpnhejpmfjhmmhiih";
/// The origin of the extension. The browser gives it to the host as the first argument.
pub const EXTENSION_ORIGIN: &str = "chrome-extension://bbnpgnjnfjlbgggmpnhejpmfjhmmhiih/";
/// Environment variable that overrides the browser socket path.
pub const SOCKET_ENV: &str = "APASSY_BROWSER_SOCKET";
/// Largest request, in both hops.
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
/// Largest response. The browser takes at most 1 MiB from a host.
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
/// Longest page address.
pub const MAX_URL_BYTES: usize = 2048;
/// The most logins in one answer.
pub const MAX_LOGINS: usize = 50;
/// The longest title of a new login, in bytes after trim.
pub const MAX_TITLE_BYTES: usize = 128;
/// The longest username of a new login, in bytes after trim.
pub const MAX_USERNAME_BYTES: usize = 1024;
/// The longest password that a save takes from a page, in bytes.
pub const MAX_PASSWORD_BYTES: usize = 4096;
/// The shortest and the longest new password, in characters.
pub const MIN_NEW_PASSWORD: u32 = 12;
pub const MAX_NEW_PASSWORD: u32 = 64;
/// The length of a new password when the request names none.
pub const DEFAULT_NEW_PASSWORD: u32 = 20;

/// The socket path: `APASSY_BROWSER_SOCKET`, or `browser.sock` in the data directory
/// ([`crate::paths::data_dir`]).
pub fn default_socket_path() -> PathBuf {
    if let Some(path) = std::env::var_os(SOCKET_ENV).filter(|value| !value.is_empty()) {
        return PathBuf::from(path);
    }
    crate::paths::data_dir().join("browser.sock")
}

/// One request, as the extension sends it.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// Set only after a trusted extension UI event. Absence always requires fresh authentication.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub trusted_gesture: bool,
    /// Added by the new caller-checked native host; older hosts require fresh checks.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub owner_window_host: u32,
    pub v: u32,
    pub cmd: String,
    /// The address of the active tab, from the browser.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// The item ID from `logins`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item: Option<u64>,
    /// The title of a new login (`save`, `create`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// The username of a new login (`save`, `create`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// The password that the owner typed on the page (`save`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<SecretText>,
    /// The length of a new password (`create`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length: Option<u32>,
    /// Symbols in a new password (`create`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbols: Option<bool>,
}

fn is_zero(value: &u32) -> bool {
    *value == 0
}

/// Browser-issued top-frame identity, scoped by the extension instance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserDocument {
    pub window_id: i64,
    pub tab_id: i64,
    pub frame_id: u32,
    pub document_id: String,
    pub generation: String,
}

/// A checked request. Debug output hides the password of a save.
#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    AgentWait {
        instance: String,
    },
    AgentBlocked {
        instance: String,
        url: String,
    },
    AgentPoll {
        instance: String,
        url: String,
        document: Option<BrowserDocument>,
        focused: bool,
        receipt: Option<String>,
        filled: Vec<String>,
        exposed: bool,
    },
    BypassStatus,
    BypassRequest(super::bypass::BypassScope),
    BypassEnd,
    Status,
    /// Bring the window to the front.
    Show,
    Logins {
        url: String,
    },
    Fill {
        url: String,
        item: u64,
    },
    /// Site-scoped metadata only. Focus does not authorize secret release.
    Suggestions {
        url: String,
        username: String,
    },
    /// Replace only the password of this exact existing login after a fresh check.
    Update {
        url: String,
        item: u64,
        username: String,
        password: SecretText,
    },
    /// Save the login that the owner typed on the page.
    Save {
        url: String,
        title: String,
        username: String,
        password: SecretText,
    },
    /// Make a login with a new password, then fill it.
    Create {
        url: String,
        title: String,
        username: String,
        length: u32,
        symbols: bool,
    },
    /// Sign in with a passkey of the vault (contract section 9).
    PasskeyGet(PasskeyGetRequest),
    /// Make a passkey in the vault (contract section 9).
    PasskeyCreate(PasskeyCreateRequest),
    /// The current one-time code of a login, for a visible `one-time-code` field.
    FillCode {
        url: String,
        item: u64,
        /// The label of the one-time code detail, when the login has more than one.
        field: Option<String>,
    },
}

/// The commands that the host passes to the app only after the caller check
/// ([`super::caller::check_browser_parent`]).
pub const GUARDED_COMMANDS: &[&str] = &[
    "agent_wait",
    "agent_poll",
    "passkey_get",
    "passkey_create",
    "fill_code",
    "fill",
    "save",
    "create",
    "update",
];

/// True for a command of [`GUARDED_COMMANDS`].
pub fn is_guarded_command(cmd: &str) -> bool {
    GUARDED_COMMANDS.contains(&cmd)
}

/// The longest user name and display name of a new passkey, in bytes.
pub const MAX_PASSKEY_NAME_BYTES: usize = 256;
/// The most algorithms in a `passkey_create`.
pub const MAX_ALGORITHMS: usize = 16;
/// The longest label of a one-time code detail, in bytes.
pub const MAX_FIELD_BYTES: usize = 128;
/// The most entries of `prf.eval_by_credential` in a `passkey_get`.
pub const MAX_PRF_CREDENTIALS: usize = 256;
/// The longest PRF input (`first`, `second`), in bytes. WebAuthn sets no minimum: an
/// empty input (the empty text) is valid.
pub const MAX_PRF_INPUT_BYTES: usize = 1024;
/// The longest largeBlob write, uncompressed, in bytes. The whole request is still at
/// most [`MAX_REQUEST_BYTES`], so a write above about 47 KiB does not fit.
pub const MAX_LARGE_BLOB_BYTES: usize = 65_536;

/// The two PRF inputs of one evaluation (WebAuthn `AuthenticationExtensionsPRFValues`),
/// as raw WebAuthn inputs. The app makes the salts.
#[derive(Clone, PartialEq, Eq)]
pub struct PasskeyPrfValues {
    pub first: Vec<u8>,
    pub second: Option<Vec<u8>>,
}

/// The PRF extension of a `passkey_get`: `eval` for any credential, and
/// `eval_by_credential` (credential ID, values), which wins for its credential.
#[derive(Clone, PartialEq, Eq)]
pub struct PasskeyPrfRequest {
    pub eval: Option<PasskeyPrfValues>,
    pub eval_by_credential: Vec<(Vec<u8>, PasskeyPrfValues)>,
}

/// The largeBlob extension of a `passkey_get`: a read, or a write of these bytes.
#[derive(Clone, PartialEq, Eq)]
pub enum PasskeyLargeBlobRequest {
    Read,
    Write(Vec<u8>),
}

impl std::fmt::Debug for PasskeyPrfValues {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasskeyPrfValues")
            .field("first", &self.first.len())
            .field("second", &self.second.as_ref().map(Vec::len))
            .finish()
    }
}

impl std::fmt::Debug for PasskeyPrfRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasskeyPrfRequest")
            .field("eval", &self.eval)
            .field("eval_by_credential", &self.eval_by_credential.len())
            .finish()
    }
}

impl std::fmt::Debug for PasskeyLargeBlobRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read => f.write_str("Read"),
            Self::Write(blob) => f.debug_tuple("Write").field(&blob.len()).finish(),
        }
    }
}

/// A checked `passkey_get`. The strings are as the extension sent them, after strict
/// syntax checks; the app checks the client data with
/// [`super::webauthn::client_data`]. `Debug` shows no client data and no IDs.
#[derive(Clone, PartialEq, Eq)]
pub struct PasskeyGetRequest {
    /// The random request ID of the extension (a lowercase UUID).
    pub rid: String,
    /// The origin of the page, from the browser.
    pub origin: String,
    pub rp_id: String,
    /// Standard base64 of `clientDataJSON`.
    pub client_data_json: String,
    /// Standard base64 credential IDs that the page allows. Empty: any passkey of
    /// `rp_id`.
    pub allowed: Vec<String>,
    /// The PRF extension, decoded and checked.
    pub prf: Option<PasskeyPrfRequest>,
    /// The largeBlob extension, decoded and checked.
    pub large_blob: Option<PasskeyLargeBlobRequest>,
}

/// A checked `passkey_create`. `Debug` shows no client data, no user handle, and no
/// IDs.
#[derive(Clone, PartialEq, Eq)]
pub struct PasskeyCreateRequest {
    pub rid: String,
    pub origin: String,
    pub rp_id: String,
    pub client_data_json: String,
    /// Standard base64 of the user handle of the page: 1 to 64 bytes.
    pub user_handle: String,
    /// From the page: untrusted text without control or bidirectional characters.
    pub user_name: String,
    pub user_display_name: String,
    /// COSE algorithms in the order of the page.
    pub algorithms: Vec<i64>,
    /// Standard base64 credential IDs that the page already has.
    pub excluded: Vec<String>,
    /// The title of the new login: 1 to 128 bytes after trim.
    pub title: String,
}

impl std::fmt::Debug for PasskeyGetRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasskeyGetRequest")
            .field("rid", &self.rid)
            .field("origin", &self.origin)
            .field("rp_id", &self.rp_id)
            .field("allowed", &self.allowed.len())
            .field("prf", &self.prf.is_some())
            .field(
                "large_blob",
                &self.large_blob.as_ref().map(|blob| match blob {
                    PasskeyLargeBlobRequest::Read => "read",
                    PasskeyLargeBlobRequest::Write(_) => "write",
                }),
            )
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for PasskeyCreateRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasskeyCreateRequest")
            .field("rid", &self.rid)
            .field("origin", &self.origin)
            .field("rp_id", &self.rp_id)
            .field("algorithms", &self.algorithms)
            .field("excluded", &self.excluded.len())
            .finish_non_exhaustive()
    }
}

/// An error answer before it becomes a [`Response`]. It is small, so a `Result` with
/// it stays small.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireError {
    pub code: &'static str,
    /// Text for the owner. It has no secret value.
    pub message: String,
}

impl WireError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl From<WireError> for Response {
    fn from(error: WireError) -> Self {
        Response::error(error.code, error.message)
    }
}

impl Request {
    /// Parse one request line. An error is the answer to send.
    pub fn parse(line: &[u8]) -> Result<Command, WireError> {
        let invalid =
            || WireError::new("bad_request", "The request is not valid browser wire JSON.");
        // The commands of section 9 have their own strict packets. The legacy
        // `Request` keeps its fields, so the old commands parse as before.
        if let Ok(Peek { cmd: Some(cmd) }) = serde_json::from_slice::<Peek>(line) {
            match cmd.as_str() {
                "agent_wait" => {
                    #[derive(Deserialize)]
                    #[serde(deny_unknown_fields)]
                    struct Wait {
                        v: u32,
                        cmd: String,
                        instance: String,
                    }
                    let p: Wait = serde_json::from_slice(line).map_err(|_| invalid())?;
                    if p.v != BROWSER_WIRE_VERSION
                        || p.cmd != "agent_wait"
                        || p.instance.len() != 32
                        || !p.instance.bytes().all(|b| b.is_ascii_hexdigit())
                    {
                        return Err(invalid());
                    }
                    return Ok(Command::AgentWait {
                        instance: p.instance,
                    });
                }
                "agent_poll" | "agent_blocked" => {
                    #[derive(Deserialize)]
                    #[serde(deny_unknown_fields)]
                    struct Poll {
                        v: u32,
                        cmd: String,
                        instance: String,
                        url: String,
                        document: Option<BrowserDocument>,
                        #[serde(default)]
                        focused: bool,
                        receipt: Option<String>,
                        #[serde(default)]
                        filled: Vec<String>,
                        #[serde(default)]
                        exposed: bool,
                    }
                    let p: Poll = serde_json::from_slice(line).map_err(|_| invalid())?;
                    if p.v != BROWSER_WIRE_VERSION
                        || p.instance.len() != 32
                        || !p.instance.bytes().all(|b| b.is_ascii_hexdigit())
                        || p.url.len() > MAX_URL_BYTES
                        || p.document.as_ref().is_some_and(|d| {
                            d.window_id < 0
                                || d.tab_id < 0
                                || d.frame_id != 0
                                || d.document_id.is_empty()
                                || d.document_id.len() > 128
                                || d.generation.is_empty()
                                || d.generation.len() > 128
                        })
                        || p.receipt.as_ref().is_some_and(|r| r.len() > 64)
                        || p.filled.len() > 3
                        || p.filled
                            .iter()
                            .any(|f| !["username", "password", "code"].contains(&f.as_str()))
                    {
                        return Err(invalid());
                    }
                    if p.cmd == "agent_blocked" {
                        return Ok(Command::AgentBlocked {
                            instance: p.instance,
                            url: p.url,
                        });
                    }
                    return Ok(Command::AgentPoll {
                        instance: p.instance,
                        url: p.url,
                        document: p.document,
                        focused: p.focused,
                        receipt: p.receipt,
                        filled: p.filled,
                        exposed: p.exposed,
                    });
                }
                "bypass_status" | "bypass_request" | "bypass_end" => {
                    #[derive(Deserialize)]
                    #[serde(deny_unknown_fields)]
                    struct Packet {
                        v: u32,
                        cmd: String,
                        scope: Option<super::bypass::BypassScope>,
                        bypass_nonce: Option<String>,
                        host_connection: Option<String>,
                    }
                    let p: Packet = serde_json::from_slice(line).map_err(|_| invalid())?;
                    if p.v != 1 {
                        return Err(invalid());
                    }
                    if p.cmd == "bypass_request" {
                        if !matches!((&p.bypass_nonce, &p.host_connection), (Some(nonce), Some(connection)) if super::bypass::RequestBinding { nonce: nonce.clone(), connection: connection.clone() }.valid())
                        {
                            return Err(invalid());
                        }
                    } else if p.bypass_nonce.is_some() || p.host_connection.is_some() {
                        return Err(invalid());
                    }
                    return match (p.cmd.as_str(), p.scope) {
                        ("bypass_status", None) => Ok(Command::BypassStatus),
                        ("bypass_end", None) => Ok(Command::BypassEnd),
                        ("bypass_request", Some(scope)) => Ok(Command::BypassRequest(scope)),
                        _ => Err(invalid()),
                    };
                }
                "suggestions" => {
                    let packet: SuggestionsPacket =
                        serde_json::from_slice(line).map_err(|_| invalid())?;
                    return packet.command();
                }
                "update" => {
                    let packet: UpdatePacket =
                        serde_json::from_slice(line).map_err(|_| invalid())?;
                    return packet.command();
                }
                "passkey_get" => {
                    let packet: PasskeyGetPacket =
                        serde_json::from_slice(line).map_err(|_| invalid())?;
                    return packet.command();
                }
                "passkey_create" => {
                    let packet: PasskeyCreatePacket =
                        serde_json::from_slice(line).map_err(|_| invalid())?;
                    return packet.command();
                }
                "fill_code" => {
                    let packet: FillCodePacket =
                        serde_json::from_slice(line).map_err(|_| invalid())?;
                    return packet.command();
                }
                _ => {}
            }
        }
        let request: Self = serde_json::from_slice(line).map_err(|_| invalid())?;
        request.command()
    }

    /// The command of the request. An error is the answer to send.
    pub fn command(self) -> Result<Command, WireError> {
        if self.v != BROWSER_WIRE_VERSION {
            return Err(WireError::new(
                "bad_version",
                concat!(
                    "This Apassy extension does not match the app. Load the extension from ",
                    crate::same_app!(),
                    "."
                ),
            ));
        }
        let url = |url: Option<String>| match url {
            Some(url) if !url.is_empty() && url.len() <= MAX_URL_BYTES => Ok(url),
            _ => Err(WireError::new(
                "bad_request",
                "The request needs the address of the page.",
            )),
        };
        match self.cmd.as_str() {
            "status" => Ok(Command::Status),
            "show" => Ok(Command::Show),
            "logins" => Ok(Command::Logins {
                url: url(self.url)?,
            }),
            "fill" => match self.item {
                Some(item) if item > 0 => Ok(Command::Fill {
                    url: url(self.url)?,
                    item,
                }),
                _ => Err(WireError::new(
                    "bad_request",
                    "The request needs the ID of a login.",
                )),
            },
            "save" => {
                let url = url(self.url)?;
                let (title, username) = new_login(self.title, self.username)?;
                match self.password {
                    Some(password)
                        if !password.is_empty()
                            && password.expose().len() <= MAX_PASSWORD_BYTES =>
                    {
                        Ok(Command::Save {
                            url,
                            title,
                            username,
                            password,
                        })
                    }
                    _ => Err(WireError::new(
                        "bad_request",
                        "The request needs the password from the page, at most 4096 bytes.",
                    )),
                }
            }
            "create" => {
                let url = url(self.url)?;
                let (title, username) = new_login(self.title, self.username)?;
                let length = self.length.unwrap_or(DEFAULT_NEW_PASSWORD);
                if !(MIN_NEW_PASSWORD..=MAX_NEW_PASSWORD).contains(&length) {
                    return Err(WireError::new(
                        "bad_request",
                        "A new password has 12 to 64 characters.",
                    ));
                }
                Ok(Command::Create {
                    url,
                    title,
                    username,
                    length,
                    symbols: self.symbols.unwrap_or(true),
                })
            }
            _ => Err(WireError::new(
                "bad_request",
                "The request has an unknown command.",
            )),
        }
    }
}

/// The extension, not the native host, binds these requests to a trusted browser
/// sender, origin, frame, document and focused form. These values do not attest a
/// webpage or authorize a fill. The app independently checks vault site eligibility.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SuggestionsPacket {
    v: u32,
    #[allow(dead_code)]
    cmd: String,
    url: String,
    #[serde(default)]
    username: String,
}

impl SuggestionsPacket {
    fn command(self) -> Result<Command, WireError> {
        check_version(self.v)?;
        check_page_url(&self.url)?;
        page_text(&self.username, MAX_USERNAME_BYTES)?;
        Ok(Command::Suggestions {
            url: self.url,
            username: self.username.trim().to_owned(),
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdatePacket {
    #[serde(default, rename = "trusted_gesture")]
    _trusted_gesture: bool,
    #[serde(default, rename = "owner_window_host")]
    _owner_window_host: u32,
    v: u32,
    #[allow(dead_code)]
    cmd: String,
    url: String,
    item: u64,
    username: String,
    password: SecretText,
}

impl UpdatePacket {
    fn command(self) -> Result<Command, WireError> {
        check_version(self.v)?;
        check_page_url(&self.url)?;
        page_text(&self.username, MAX_USERNAME_BYTES)?;
        if self.item == 0
            || self.password.is_empty()
            || self.password.expose().len() > MAX_PASSWORD_BYTES
        {
            return Err(WireError::new(
                "bad_request",
                "An update needs an exact login ID and a password of at most 4096 bytes.",
            ));
        }
        Ok(Command::Update {
            url: self.url,
            item: self.item,
            // Preserve the exact account identity; an update never changes it.
            username: self.username,
            password: self.password,
        })
    }
}

fn check_page_url(url: &str) -> Result<(), WireError> {
    if url.is_empty() || url.len() > MAX_URL_BYTES {
        return Err(WireError::new(
            "bad_request",
            "The request needs the address of the page.",
        ));
    }
    super::site::Page::parse(url)
        .map(|_| ())
        .map_err(|err| WireError::new("unsupported_page", err.message()))
}

/// True for a character that can change how a line reads in the owner check dialog: a
/// control character (also a line break) or a bidirectional format character.
pub fn hides_text(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061C}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}'
        )
}

/// The command of a request line, and nothing else. Other fields are skipped without
/// a copy of their values.
#[derive(Deserialize)]
pub(crate) struct Peek {
    #[serde(default)]
    pub(crate) cmd: Option<String>,
}

/// True for a request ID of the extension: a lowercase UUID from
/// `crypto.randomUUID()`, `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`.
pub fn is_request_id(rid: &str) -> bool {
    rid.len() == 36
        && rid.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
}

fn check_version(v: u32) -> Result<(), WireError> {
    if v == BROWSER_WIRE_VERSION {
        Ok(())
    } else {
        Err(WireError::new(
            "bad_version",
            concat!(
                "This Apassy extension does not match the app. Load the extension from ",
                crate::same_app!(),
                "."
            ),
        ))
    }
}

/// The fields that every passkey request has.
fn check_passkey_common(
    rid: &str,
    origin: &str,
    rp_id: &str,
    client_data_json: &str,
) -> Result<(), WireError> {
    if !is_request_id(rid) {
        return Err(WireError::new(
            "bad_request",
            "A passkey request needs a request ID.",
        ));
    }
    super::webauthn::parse_origin(origin)?;
    super::webauthn::check_rp_id(rp_id)?;
    super::webauthn::decode_bytes(client_data_json, 1, super::webauthn::MAX_CLIENT_DATA_BYTES)?;
    Ok(())
}

/// Untrusted text of a page: at most `max` bytes, without a control or a
/// bidirectional format character (they could hide the site in the owner dialog).
fn page_text(text: &str, max: usize) -> Result<(), WireError> {
    if text.len() > max || text.chars().any(hides_text) {
        return Err(WireError::new(
            "bad_request",
            "A name from the page is too long or has a control character.",
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasskeyGetPacket {
    #[serde(default, rename = "bypass_nonce")]
    _bypass_nonce: Option<String>,
    #[serde(default, rename = "host_connection")]
    _host_connection: Option<String>,
    #[serde(default, rename = "trusted_gesture")]
    _trusted_gesture: bool,
    #[serde(default, rename = "owner_window_host")]
    _owner_window_host: u32,
    v: u32,
    #[allow(dead_code)]
    cmd: String,
    rid: String,
    origin: String,
    rp_id: String,
    client_data_json: String,
    allowed: Vec<String>,
    #[serde(default)]
    prf: Option<PrfPacket>,
    #[serde(default)]
    large_blob: Option<LargeBlobPacket>,
}

/// `prf` of a `passkey_get`: WebAuthn `eval` and `evalByCredential`. The keys of
/// `eval_by_credential` are credential IDs in base64url without padding, as WebAuthn
/// has them.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrfPacket {
    #[serde(default)]
    eval: Option<PrfValuesPacket>,
    #[serde(default)]
    eval_by_credential: Option<std::collections::BTreeMap<String, PrfValuesPacket>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrfValuesPacket {
    first: String,
    #[serde(default)]
    second: Option<String>,
}

/// `large_blob` of a `passkey_get`: `{"read": true}` or `{"write": <bytes>}`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LargeBlobPacket {
    #[serde(default)]
    read: bool,
    #[serde(default)]
    write: Option<String>,
}

fn bad_extension(message: &str) -> WireError {
    WireError::new("bad_request", message)
}

impl PrfValuesPacket {
    fn values(&self) -> Result<PasskeyPrfValues, WireError> {
        let one = |text: &str| super::webauthn::decode_bytes(text, 0, MAX_PRF_INPUT_BYTES);
        Ok(PasskeyPrfValues {
            first: one(&self.first)?,
            second: self.second.as_deref().map(one).transpose()?,
        })
    }
}

impl PrfPacket {
    /// WebAuthn rules: each key of `eval_by_credential` is a credential ID of `allowed`,
    /// so a non-empty `eval_by_credential` needs a non-empty `allowed`.
    fn request(&self, allowed: &[Vec<u8>]) -> Result<PasskeyPrfRequest, WireError> {
        let eval = self
            .eval
            .as_ref()
            .map(PrfValuesPacket::values)
            .transpose()?;
        let by_credential = self.eval_by_credential.as_ref();
        if by_credential.is_some_and(|map| map.len() > MAX_PRF_CREDENTIALS) {
            return Err(bad_extension("The PRF request names too many passkeys."));
        }
        let mut eval_by_credential = Vec::new();
        for (id, values) in by_credential.into_iter().flatten() {
            let id = super::webauthn::decode_url_id(id)?;
            if !allowed.contains(&id) {
                return Err(bad_extension(
                    "A PRF input names a passkey that the request does not allow.",
                ));
            }
            eval_by_credential.push((id, values.values()?));
        }
        Ok(PasskeyPrfRequest {
            eval,
            eval_by_credential,
        })
    }
}

impl LargeBlobPacket {
    /// WebAuthn rules: a write names exactly one allowed credential.
    fn request(&self, allowed: usize) -> Result<PasskeyLargeBlobRequest, WireError> {
        match (self.read, &self.write) {
            (true, None) => Ok(PasskeyLargeBlobRequest::Read),
            (false, Some(_)) if allowed != 1 => Err(bad_extension(
                "A large blob write needs exactly one allowed passkey.",
            )),
            (false, Some(text)) => super::webauthn::decode_bytes(text, 0, MAX_LARGE_BLOB_BYTES)
                .map(PasskeyLargeBlobRequest::Write),
            _ => Err(bad_extension("The large blob request needs read or write.")),
        }
    }
}

impl PasskeyGetPacket {
    fn command(self) -> Result<Command, WireError> {
        check_version(self.v)?;
        check_passkey_common(&self.rid, &self.origin, &self.rp_id, &self.client_data_json)?;
        let allowed = super::webauthn::decode_ids(&self.allowed)?;
        let prf = self
            .prf
            .as_ref()
            .map(|prf| prf.request(&allowed))
            .transpose()?;
        let large_blob = self
            .large_blob
            .as_ref()
            .map(|blob| blob.request(allowed.len()))
            .transpose()?;
        Ok(Command::PasskeyGet(PasskeyGetRequest {
            rid: self.rid,
            origin: self.origin,
            rp_id: self.rp_id,
            client_data_json: self.client_data_json,
            allowed: self.allowed,
            prf,
            large_blob,
        }))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasskeyCreatePacket {
    #[serde(default, rename = "bypass_nonce")]
    _bypass_nonce: Option<String>,
    #[serde(default, rename = "host_connection")]
    _host_connection: Option<String>,
    #[serde(default, rename = "trusted_gesture")]
    _trusted_gesture: bool,
    #[serde(default, rename = "owner_window_host")]
    _owner_window_host: u32,
    v: u32,
    #[allow(dead_code)]
    cmd: String,
    rid: String,
    origin: String,
    rp_id: String,
    client_data_json: String,
    user_handle: String,
    user_name: String,
    user_display_name: String,
    algorithms: Vec<i64>,
    excluded: Vec<String>,
    title: String,
}

impl PasskeyCreatePacket {
    fn command(self) -> Result<Command, WireError> {
        check_version(self.v)?;
        check_passkey_common(&self.rid, &self.origin, &self.rp_id, &self.client_data_json)?;
        super::webauthn::decode_bytes(
            &self.user_handle,
            1,
            super::webauthn::MAX_USER_HANDLE_BYTES,
        )?;
        page_text(&self.user_name, MAX_PASSKEY_NAME_BYTES)?;
        page_text(&self.user_display_name, MAX_PASSKEY_NAME_BYTES)?;
        if self.algorithms.is_empty() || self.algorithms.len() > MAX_ALGORITHMS {
            return Err(WireError::new(
                "bad_request",
                "A new passkey needs 1 to 16 algorithms.",
            ));
        }
        super::webauthn::decode_ids(&self.excluded)?;
        let title = self.title.trim();
        if title.is_empty() || title.len() > MAX_TITLE_BYTES || title.chars().any(hides_text) {
            return Err(WireError::new(
                "bad_request",
                "A new passkey needs a title of 1 to 128 bytes without a control character.",
            ));
        }
        Ok(Command::PasskeyCreate(PasskeyCreateRequest {
            rid: self.rid,
            origin: self.origin,
            rp_id: self.rp_id,
            client_data_json: self.client_data_json,
            user_handle: self.user_handle,
            user_name: self.user_name,
            user_display_name: self.user_display_name,
            algorithms: self.algorithms,
            excluded: self.excluded,
            title: title.to_owned(),
        }))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FillCodePacket {
    #[serde(default, rename = "bypass_nonce")]
    _bypass_nonce: Option<String>,
    #[serde(default, rename = "host_connection")]
    _host_connection: Option<String>,
    #[serde(default, rename = "trusted_gesture")]
    _trusted_gesture: bool,
    #[serde(default, rename = "owner_window_host")]
    _owner_window_host: u32,
    v: u32,
    #[allow(dead_code)]
    cmd: String,
    url: String,
    item: u64,
    #[serde(default)]
    field: Option<String>,
}

impl FillCodePacket {
    fn command(self) -> Result<Command, WireError> {
        check_version(self.v)?;
        if self.url.is_empty() || self.url.len() > MAX_URL_BYTES {
            return Err(WireError::new(
                "bad_request",
                "The request needs the address of the page.",
            ));
        }
        if self.item == 0 {
            return Err(WireError::new(
                "bad_request",
                "The request needs the ID of a login.",
            ));
        }
        if let Some(field) = &self.field
            && (field.trim().is_empty()
                || field.len() > MAX_FIELD_BYTES
                || field.chars().any(hides_text))
        {
            return Err(WireError::new(
                "bad_request",
                "The label of a one-time code is empty, too long, or has a control character.",
            ));
        }
        Ok(Command::FillCode {
            url: self.url,
            item: self.item,
            field: self.field,
        })
    }
}

/// The trimmed title and username of a new login. They come from the browser and show
/// in the owner check dialog, so a line break or a bidirectional format character is
/// refused: it could hide the site of the request.
fn new_login(
    title: Option<String>,
    username: Option<String>,
) -> Result<(String, String), WireError> {
    let title = title.as_deref().map(str::trim).unwrap_or_default();
    if title.is_empty() || title.len() > MAX_TITLE_BYTES {
        return Err(WireError::new(
            "bad_request",
            "A new login needs a title of 1 to 128 bytes.",
        ));
    }
    let username = username.as_deref().map(str::trim).unwrap_or_default();
    if username.is_empty() || username.len() > MAX_USERNAME_BYTES {
        return Err(WireError::new(
            "bad_request",
            "A new login needs a username of 1 to 1024 bytes.",
        ));
    }
    if title.chars().chain(username.chars()).any(hides_text) {
        return Err(WireError::new(
            "bad_request",
            "A title or a username cannot have a line break or a control character.",
        ));
    }
    Ok((title.to_owned(), username.to_owned()))
}

/// One response.
#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    /// `ok`, or an error code.
    pub code: String,
    /// Text for the owner. It has no secret value.
    pub message: String,
    #[serde(default)]
    pub data: Data,
}

impl Response {
    pub fn ok(message: impl Into<String>, data: Data) -> Self {
        Self {
            ok: true,
            code: "ok".to_owned(),
            message: message.into(),
            data,
        }
    }

    pub fn error(code: &str, message: impl Into<String>) -> Self {
        Self {
            ok: false,
            code: code.to_owned(),
            message: message.into(),
            data: Data::None,
        }
    }
}

/// The data of a response. `Debug` shows no secret value, no signature, and no byte
/// field of a passkey.
#[derive(Default, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Data {
    AgentWait {
        pending: bool,
    },
    AgentFill {
        receipt: String,
        origin: String,
        document: BrowserDocument,
        username: SecretText,
        password: SecretText,
        code: SecretText,
    },
    Bypass {
        identity: Option<super::trust::InstanceIdentity>,
        remaining: Option<u64>,
    },
    #[default]
    None,
    Status {
        vault: VaultState,
        version: String,
    },
    Logins {
        /// The origin of the page: `scheme://host`, and the port when it is not the
        /// default.
        origin: String,
        host: String,
        logins: Vec<LoginRow>,
    },
    /// The only data with a secret value: the answer of `fill` and of `create`.
    Fill {
        item: u64,
        /// The extension fills only a frame with this `location.origin`.
        origin: String,
        username: String,
        password: SecretText,
    },
    /// A login that `save` added.
    Saved {
        item: u64,
    },
    /// A password-only update. It never returns the password to the page.
    Updated {
        item: u64,
        origin: String,
        username: String,
    },
    /// The answer of `passkey_get`. Byte fields are standard base64 with padding.
    Passkey {
        rid: String,
        credential_id: String,
        user_handle: String,
        authenticator_data: String,
        signature: String,
        /// The same bytes as the request.
        client_data_json: String,
        /// The COSE algorithm of the passkey: -7, -35, -8, or -257.
        algorithm: i64,
        /// The PRF outputs, when the request had PRF inputs and the passkey has PRF
        /// secrets.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prf: Option<PasskeyPrfResults>,
        /// The largeBlob result: the blob of a read (no entry without a stored blob), or
        /// the result of a write.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        large_blob: Option<PasskeyLargeBlobResult>,
    },
    /// The answer of `passkey_create`. Byte fields are standard base64 with padding.
    PasskeyCreated {
        rid: String,
        item: u64,
        credential_id: String,
        attestation_object: String,
        authenticator_data: String,
        /// DER SubjectPublicKeyInfo of the new key.
        public_key_spki: String,
        /// The COSE algorithm: -7 (ES256).
        algorithm: i64,
        client_data_json: String,
    },
    /// The answer of `fill_code`: a secret value.
    Code {
        item: u64,
        /// The extension fills only a frame with this `location.origin`.
        origin: String,
        /// 6 to 8 digits.
        code: SecretText,
        /// Seconds until the code changes.
        remaining: u64,
    },
}

impl std::fmt::Debug for Data {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AgentWait { pending } => f
                .debug_struct("AgentWait")
                .field("pending", pending)
                .finish(),
            Self::AgentFill { .. } => f.write_str("AgentFill([redacted])"),
            Self::Bypass {
                identity,
                remaining,
            } => f
                .debug_struct("Bypass")
                .field("identity", identity)
                .field("remaining", remaining)
                .finish(),
            Self::None => f.write_str("None"),
            Self::Status { vault, version } => f
                .debug_struct("Status")
                .field("vault", vault)
                .field("version", version)
                .finish(),
            Self::Logins {
                origin,
                host,
                logins,
            } => f
                .debug_struct("Logins")
                .field("origin", origin)
                .field("host", host)
                .field("logins", logins)
                .finish(),
            Self::Fill {
                item,
                origin,
                username,
                password,
            } => f
                .debug_struct("Fill")
                .field("item", item)
                .field("origin", origin)
                .field("username", username)
                .field("password", password)
                .finish(),
            Self::Saved { item } => f.debug_struct("Saved").field("item", item).finish(),
            Self::Updated {
                item,
                origin,
                username,
            } => f
                .debug_struct("Updated")
                .field("item", item)
                .field("origin", origin)
                .field("username", username)
                .finish(),
            Self::Passkey { rid, .. } => f
                .debug_struct("Passkey")
                .field("rid", rid)
                .finish_non_exhaustive(),
            Self::PasskeyCreated {
                rid,
                item,
                algorithm,
                ..
            } => f
                .debug_struct("PasskeyCreated")
                .field("rid", rid)
                .field("item", item)
                .field("algorithm", algorithm)
                .finish_non_exhaustive(),
            Self::Code {
                item,
                origin,
                remaining,
                ..
            } => f
                .debug_struct("Code")
                .field("item", item)
                .field("origin", origin)
                .field("remaining", remaining)
                .finish_non_exhaustive(),
        }
    }
}

/// The PRF outputs of `passkey_get`, standard base64 of 32 bytes each: secret values.
#[derive(Debug, Serialize, Deserialize)]
pub struct PasskeyPrfResults {
    pub first: SecretText,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub second: Option<SecretText>,
}

/// The largeBlob result of `passkey_get`: `{"data": …}` or `{"written": bool}`. The
/// data is standard base64 of the uncompressed blob.
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PasskeyLargeBlobResult {
    Data { data: SecretText },
    Written { written: bool },
}

/// The state of the vault for the extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultState {
    /// No vault file is open.
    None,
    Locked,
    Unlocked,
}

/// One login that matches the page. It has no secret value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginRow {
    pub item: u64,
    pub title: String,
    pub username: String,
    /// The login has a one-time code (`fill_code`). Never the code or the seed.
    #[serde(default)]
    pub has_totp: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_wait_is_value_free_and_strict() {
        let packet = r#"{"v":1,"cmd":"agent_wait","instance":"0123456789abcdef0123456789abcdef"}"#;
        assert!(matches!(
            Request::parse(packet.as_bytes()).unwrap(),
            Command::AgentWait { .. }
        ));
        for field in ["url", "document", "tab_id", "identity", "remote"] {
            let mut forged: serde_json::Value = serde_json::from_str(packet).unwrap();
            forged[field] = serde_json::json!(null);
            assert!(Request::parse(&serde_json::to_vec(&forged).unwrap()).is_err());
        }
        for pending in [true, false] {
            let value = serde_json::to_value(Data::AgentWait { pending }).unwrap();
            assert_eq!(
                value,
                serde_json::json!({"type":"agent_wait","pending":pending})
            );
        }
        assert!(is_guarded_command("agent_wait"));
    }

    #[test]
    fn bypass_requests_never_carry_approval_or_identity() {
        assert_eq!(
            Request::parse(br#"{"v":1,"cmd":"bypass_request","scope":"once","bypass_nonce":"3b241101-e2bb-4255-8caf-4136c566a962","host_connection":"123-456"}"#).unwrap(),
            Command::BypassRequest(super::super::bypass::BypassScope::Once)
        );
        for packet in [
            r#"{"v":1,"cmd":"bypass_request","scope":"forever"}"#,
            r#"{"v":1,"cmd":"bypass_request","scope":"once","approved":true}"#,
            r#"{"v":1,"cmd":"bypass_request","scope":"once","identity":{}}"#,
            r#"{"v":1,"cmd":"bypass_end","scope":"once"}"#,
        ] {
            assert!(Request::parse(packet.as_bytes()).is_err());
        }
    }

    fn parse(text: &str) -> Result<Command, WireError> {
        Request::parse(text.as_bytes())
    }

    #[test]
    fn suggestions_and_updates_use_strict_packets_and_hide_passwords() {
        assert_eq!(
            parse(r#"{"v":1,"cmd":"suggestions","url":"https://a.example","username":" AL "}"#)
                .unwrap(),
            Command::Suggestions {
                url: "https://a.example".to_owned(),
                username: "AL".to_owned()
            }
        );
        let update = parse(r#"{"v":1,"cmd":"update","url":"https://a.example","item":7,"username":"alice","password":"update-canary"}"#).unwrap();
        assert!(
            matches!(&update, Command::Update { item: 7, username, .. } if username == "alice")
        );
        assert!(!format!("{update:?}").contains("update-canary"));
        for text in [
            r#"{"v":1,"cmd":"update","url":"https://a.example","username":"alice","password":"x"}"#,
            r#"{"v":1,"cmd":"update","url":"https://a.example","item":0,"username":"alice","password":"x"}"#,
            r#"{"v":1,"cmd":"update","url":"https://a.example","item":7,"username":"alice","password":""}"#,
            r#"{"v":1,"cmd":"update","url":"https://a.example","item":7,"username":"alice","password":"x","title":"overwrite"}"#,
            r#"{"v":1,"cmd":"suggestions","url":"https://a.example","username":"alice","password":"x"}"#,
        ] {
            assert_eq!(parse(text).unwrap_err().code, "bad_request");
        }
        assert_eq!(parse(r#"{"v":2,"cmd":"update","url":"https://a.example","item":7,"username":"alice","password":"x"}"#).unwrap_err().code, "bad_version");
        assert_eq!(
            parse(r#"{"v":1,"cmd":"suggestions","url":"file:///test"}"#)
                .unwrap_err()
                .code,
            "unsupported_page"
        );
        let response = Response::ok(
            "Updated.",
            Data::Updated {
                item: 7,
                origin: "https://a.example".to_owned(),
                username: "alice".to_owned(),
            },
        );
        let json = serde_json::to_value(response).unwrap();
        assert_eq!(json["data"]["type"], "updated");
        assert!(json["data"].get("password").is_none());
    }

    #[test]
    fn commands_parse() {
        assert_eq!(parse(r#"{"v":1,"cmd":"status"}"#).unwrap(), Command::Status);
        assert_eq!(parse(r#"{"v":1,"cmd":"show"}"#).unwrap(), Command::Show);
        assert_eq!(
            parse(r#"{"v":1,"cmd":"logins","url":"https://github.com/login"}"#).unwrap(),
            Command::Logins {
                url: "https://github.com/login".to_owned()
            }
        );
        assert_eq!(
            parse(r#"{"v":1,"cmd":"fill","url":"https://github.com/","item":7}"#).unwrap(),
            Command::Fill {
                url: "https://github.com/".to_owned(),
                item: 7
            }
        );
    }

    #[test]
    fn bad_requests_get_a_code() {
        let code = |text: &str| parse(text).unwrap_err().code;
        assert_eq!(code("not json"), "bad_request");
        assert_eq!(code(r#"{"v":2,"cmd":"status"}"#), "bad_version");
        assert_eq!(code(r#"{"v":1,"cmd":"reveal"}"#), "bad_request");
        assert_eq!(code(r#"{"v":1,"cmd":"status","extra":1}"#), "bad_request");
        assert_eq!(code(r#"{"v":1,"cmd":"logins"}"#), "bad_request");
        assert_eq!(code(r#"{"v":1,"cmd":"logins","url":""}"#), "bad_request");
        assert_eq!(
            code(r#"{"v":1,"cmd":"fill","url":"https://a.example"}"#),
            "bad_request"
        );
        assert_eq!(
            code(r#"{"v":1,"cmd":"fill","url":"https://a.example","item":0}"#),
            "bad_request"
        );
        let long = format!(
            r#"{{"v":1,"cmd":"logins","url":"https://a.example/{}"}}"#,
            "a".repeat(MAX_URL_BYTES)
        );
        assert_eq!(code(&long), "bad_request");
    }

    #[test]
    fn save_and_create_parse_and_check_their_fields() {
        let save = parse(
            r#"{"v":1,"cmd":"save","url":"https://a.example/","title":" A ","username":" me ","password":"pw-canary"}"#,
        )
        .unwrap();
        let Command::Save {
            title,
            username,
            password,
            ..
        } = &save
        else {
            panic!("not a save");
        };
        assert_eq!((title.as_str(), username.as_str()), ("A", "me"));
        assert_eq!(password.expose(), "pw-canary");
        assert!(!format!("{save:?}").contains("pw-canary"));
        assert_eq!(
            parse(
                r#"{"v":1,"cmd":"create","url":"https://a.example/","title":"A","username":"me"}"#
            )
            .unwrap(),
            Command::Create {
                url: "https://a.example/".to_owned(),
                title: "A".to_owned(),
                username: "me".to_owned(),
                length: DEFAULT_NEW_PASSWORD,
                symbols: true,
            }
        );
        let code = |text: &str| parse(text).unwrap_err().code;
        assert_eq!(
            code(r#"{"v":1,"cmd":"save","url":"https://a.example/","title":"A","username":"me"}"#),
            "bad_request"
        );
        assert_eq!(
            code(
                r#"{"v":1,"cmd":"save","url":"https://a.example/","title":"A","username":"me","password":""}"#
            ),
            "bad_request"
        );
        assert_eq!(
            code(
                r#"{"v":1,"cmd":"save","url":"https://a.example/","title":"  ","username":"me","password":"x"}"#
            ),
            "bad_request"
        );
        assert_eq!(
            code(
                r#"{"v":1,"cmd":"create","url":"https://a.example/","title":"A","username":"","length":20}"#
            ),
            "bad_request"
        );
        // A line break or a bidirectional override could hide the site in the dialog.
        for username in [r"me\nfor https://github.com", r"me\u202egro", r"me\u2066x"] {
            let text = format!(
                r#"{{"v":1,"cmd":"save","url":"https://a.example/","title":"A","username":"{username}","password":"x"}}"#
            );
            assert_eq!(code(&text), "bad_request", "{username}");
        }
        assert_eq!(
            code(
                r#"{"v":1,"cmd":"create","url":"https://a.example/","title":"A","username":"me","length":8}"#
            ),
            "bad_request"
        );
        assert_eq!(
            code(
                r#"{"v":1,"cmd":"create","url":"https://a.example/","title":"A","username":"me","length":65}"#
            ),
            "bad_request"
        );
    }

    #[test]
    fn a_fill_answer_has_the_password_and_debug_hides_it() {
        let response = Response::ok(
            "Filled.",
            Data::Fill {
                item: 7,
                origin: "https://github.com".to_owned(),
                username: "rafal".to_owned(),
                password: SecretText::new("pw-canary".to_owned()),
            },
        );
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains(r#""type":"fill""#), "{json}");
        assert!(json.contains(r#""password":"pw-canary""#), "{json}");
        assert!(!format!("{response:?}").contains("pw-canary"));
    }

    #[test]
    fn status_and_logins_serialize_as_the_contract_says() {
        let status = Response::ok(
            "Apassy is unlocked.",
            Data::Status {
                vault: VaultState::Unlocked,
                version: "0.3.2".to_owned(),
            },
        );
        let json = serde_json::to_value(&status).unwrap();
        assert_eq!(json["data"]["type"], "status");
        assert_eq!(json["data"]["vault"], "unlocked");
        let logins = Response::ok(
            "1 login.",
            Data::Logins {
                origin: "https://github.com".to_owned(),
                host: "github.com".to_owned(),
                logins: vec![LoginRow {
                    item: 7,
                    title: "GitHub".to_owned(),
                    username: "rafal".to_owned(),
                    has_totp: true,
                }],
            },
        );
        let json = serde_json::to_value(&logins).unwrap();
        assert_eq!(json["data"]["logins"][0]["item"], 7);
        assert_eq!(json["data"]["logins"][0]["username"], "rafal");
        assert_eq!(json["data"]["logins"][0]["has_totp"], true);
        let old: LoginRow =
            serde_json::from_str(r#"{"item":7,"title":"GitHub","username":"rafal"}"#).unwrap();
        assert!(!old.has_totp);
    }
}
