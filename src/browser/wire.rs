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
pub const EXTENSION_ID: &str = "clopaaapnilhoeplaenolhdmjpompeeh";
/// The origin of the extension. The browser gives it to the host as the first argument.
pub const EXTENSION_ORIGIN: &str = "chrome-extension://clopaaapnilhoeplaenolhdmjpompeeh/";
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

/// A checked request. Debug output hides the password of a save.
#[derive(Debug, PartialEq, Eq)]
pub enum Command {
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
        let request: Self = serde_json::from_slice(line).map_err(|_| {
            WireError::new("bad_request", "The request is not valid browser wire JSON.")
        })?;
        request.command()
    }

    /// The command of the request. An error is the answer to send.
    pub fn command(self) -> Result<Command, WireError> {
        if self.v != BROWSER_WIRE_VERSION {
            return Err(WireError::new(
                "bad_version",
                "This Apassy extension does not match the app. Load the extension from the same Apassy.app.",
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

/// True for a character that can change how a line reads in the owner check dialog: a
/// control character (also a line break) or a bidirectional format character.
pub fn hides_text(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061C}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}'
        )
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

/// The data of a response.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Data {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<Command, WireError> {
        Request::parse(text.as_bytes())
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
                }],
            },
        );
        let json = serde_json::to_value(&logins).unwrap();
        assert_eq!(json["data"]["logins"][0]["item"], 7);
        assert_eq!(json["data"]["logins"][0]["username"], "rafal");
    }
}
