//! The browser socket of `apassy owner serve` (ADR 0021, ADR 0045).
//!
//! The same socket, the same wire and the same peer checks as the desktop window
//! (`src/desktop/browser.rs`): `browser.sock` in the data directory with mode `0600` in
//! a `0700` directory ([`crate::owner::socket`]); a passkey, a one-time code or an
//! agent wait comes only from a peer that [`crate::browser::caller::peer_identity`]
//! accepts (on Linux: kernel peer credentials of the same user, the root-owned host
//! executable and its direct browser parent). On Linux every connection must also come
//! from the same user, by kernel peer credentials, before its request is read further.
//!
//! The difference to the window: there is no owner window to reuse, so every request
//! that changes or gives out a secret waits for a typed answer and the vault passphrase
//! (or polkit) in the terminal, bound to that one request ([`super::cards`]). A
//! request that Apassy cannot serve answers before any card, as the window does, so the
//! browser can use its own passkeys.

use std::marker::PhantomData;
use std::os::unix::net::UnixStream;
use std::sync::mpsc::Sender;
use std::time::Instant;

use crate::broker::approvals::OwnerAction;
use crate::browser::site::Page;
use crate::browser::webauthn;
use crate::browser::wire::{
    self, Command, Data, LoginRow, PasskeyCreateRequest, PasskeyGetRequest,
    PasskeyLargeBlobRequest, PasskeyLargeBlobResult, PasskeyPrfResults, PasskeyPrfValues, Request,
    Response, VaultState, WireError,
};
use crate::owner::owner_store::OwnerSession;
use crate::owner::socket::{LineWire, PeerGone, PeerSeen};
use crate::owner::wire::SecretText;
use crate::vault::{
    LargeBlobOp, LargeBlobResult, PasskeyAssertion, PasskeyAssertionExtensions, PasskeyInfo,
    PasskeyPrfInput, PasskeyTarget,
};

/// The ES256 algorithm of COSE: the only passkey type that Apassy makes.
const ES256: i64 = -7;

/// The check of the program at the other end of a guarded request.
pub trait PeerCheck: 'static {
    /// The check before any card. What it saw goes to [`PeerCheck::again`].
    fn check(stream: &UnixStream) -> Result<PeerSeen, WireError>;

    /// The check after the owner answered, before the answer is written.
    fn again(stream: &UnixStream, seen: &PeerSeen) -> Result<(), WireError> {
        crate::browser::caller::check_same_peer(stream, seen)
    }
}

/// The checks of the platform: the same function as the desktop window. On Linux it has
/// no signed-instance bypass, so an unsafe browser profile is refused.
pub struct SystemPeers;

impl PeerCheck for SystemPeers {
    fn check(stream: &UnixStream) -> Result<PeerSeen, WireError> {
        match crate::browser::caller::peer_identity_seen(stream)? {
            (None, seen) => Ok(seen),
            (Some(_), _) => Err(WireError::new(
                "unsafe_browser",
                "This browser is controlled by other programs. apassy owner serve has no browser debugging permission; use a normal browser profile.",
            )),
        }
    }
}

/// One request of the browser socket, with the hang-up state of its connection.
pub(crate) struct HeadlessRequest {
    pub(crate) command: Command,
    pub(crate) gone: PeerGone,
}

/// The browser wire on the socket of the service, with the peer check `P`.
pub(crate) struct HeadlessWire<P>(PhantomData<P>);

/// The commands that need a checked peer, as in the window.
fn guarded(command: &Command) -> bool {
    matches!(
        command,
        Command::AgentWait { .. }
            | Command::AgentPoll { .. }
            | Command::PasskeyGet(_)
            | Command::PasskeyCreate(_)
            | Command::FillCode { .. }
    )
}

/// The peer of every connection is the same user (Linux, kernel peer credentials). The
/// socket modes already keep other users out; this check also refuses root.
#[cfg(target_os = "linux")]
fn same_user(stream: &UnixStream) -> Result<(), WireError> {
    let refused = || {
        WireError::new(
            "unsupported",
            "Apassy cannot verify this browser, so the browser handles this request itself.",
        )
    };
    let peer = rustix::net::sockopt::socket_peercred(stream).map_err(|_| refused())?;
    if peer.uid != rustix::process::geteuid() {
        return Err(refused());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn same_user(_stream: &UnixStream) -> Result<(), WireError> {
    Ok(())
}

impl<P: PeerCheck> LineWire for HeadlessWire<P> {
    type Request = HeadlessRequest;
    type Response = Response;
    const NAME: &'static str = "browser";
    const MAX_REQUEST_BYTES: usize = wire::MAX_REQUEST_BYTES;
    const MAX_CONNECTIONS: usize = 4;
    const BUSY: &'static str = "Apassy has too many browser connections.";

    fn parse(line: &[u8]) -> Result<HeadlessRequest, Response> {
        Request::parse(line)
            .map(|command| HeadlessRequest {
                command,
                gone: PeerGone::default(),
            })
            .map_err(Response::from)
    }

    fn error(code: &'static str, message: &'static str) -> Response {
        Response::error(code, message)
    }

    fn check_peer(stream: &UnixStream, request: &HeadlessRequest) -> Result<PeerSeen, Response> {
        same_user(stream).map_err(Response::from)?;
        if guarded(&request.command) {
            return P::check(stream).map_err(Response::from);
        }
        Ok(PeerSeen::default())
    }

    fn check_peer_again(stream: &UnixStream, seen: &PeerSeen) -> Result<(), Response> {
        P::again(stream, seen).map_err(Response::from)
    }

    fn watch(request: &HeadlessRequest) -> Option<PeerGone> {
        (guarded(&request.command)
            || matches!(
                request.command,
                Command::Fill { .. }
                    | Command::Update { .. }
                    | Command::Save { .. }
                    | Command::Create { .. }
            ))
        .then(|| request.gone.clone())
    }
}

/// The request ID and the client data of a passkey request, for the answer.
pub(crate) struct Echo {
    rid: String,
    client_data_json: String,
}

/// A browser request that waits for the owner in the terminal.
pub(crate) enum BrowserOp {
    Fill {
        item: u64,
        title: String,
        username: String,
        page: Page,
    },
    Update {
        item: u64,
        title: String,
        username: String,
        revision: u64,
        password: SecretText,
        page: Page,
    },
    Save {
        title: String,
        username: String,
        password: SecretText,
        page: Page,
    },
    Create {
        title: String,
        username: String,
        length: u32,
        symbols: bool,
        page: Page,
    },
    Code {
        item: u64,
        title: String,
        field: String,
        page: Page,
    },
    Sign {
        origin: String,
        rid: String,
        rp_id: String,
        client_data_hash: [u8; 32],
        accounts: Vec<PasskeyInfo>,
        prf: Option<PasskeyPrfInput>,
        prf_by_credential: Vec<(Vec<u8>, PasskeyPrfInput)>,
        large_blob: Option<LargeBlobOp>,
        echo: Echo,
    },
    Make {
        /// Boxed: an owner action is much larger than the other variants.
        action: Box<OwnerAction>,
        attach_name: Option<String>,
        echo: Echo,
    },
}

/// A waiting browser request and the way back to its connection.
pub(crate) struct BrowserCard {
    pub(crate) op: BrowserOp,
    reply: Option<Sender<Response>>,
    gone: PeerGone,
    deadline: Instant,
}

impl BrowserCard {
    /// True while the browser still waits: it did not hang up, and the deadline did not
    /// pass. A passkey signs and a value goes out only for a live card.
    pub(crate) fn is_live(&self) -> bool {
        self.reply.is_some() && !self.gone.is_set() && Instant::now() < self.deadline
    }

    pub(crate) fn hung_up(&self) -> bool {
        self.gone.is_set()
    }

    /// Send the answer. False when nobody waits for it any more; then a value is not
    /// sent.
    pub(crate) fn send(&mut self, response: Response) -> bool {
        if response.ok && !self.is_live() {
            return false;
        }
        self.reply
            .take()
            .is_some_and(|reply| reply.send(response).is_ok())
    }
}

impl Drop for BrowserCard {
    fn drop(&mut self) {
        if let Some(reply) = self.reply.take() {
            let _ = reply.send(Response::error(
                "cancelled",
                "The owner did not approve in the terminal. Nothing was filled, signed or saved.",
            ));
        }
    }
}

/// The vault state for the extension.
pub(crate) fn vault_state(session: &OwnerSession) -> VaultState {
    if !session.has_file() {
        VaultState::None
    } else if session.is_locked() {
        VaultState::Locked
    } else {
        VaultState::Unlocked
    }
}

fn unlocked(session: &OwnerSession) -> Result<(), WireError> {
    match vault_state(session) {
        VaultState::None => Err(WireError::new(
            "none_open",
            "No vault is open. Start apassy owner serve with a vault.",
        )),
        VaultState::Locked => Err(WireError::new(
            "vault_locked",
            "Apassy is locked. Unlock it in the terminal.",
        )),
        VaultState::Unlocked => Ok(()),
    }
}

fn page_of(session: &OwnerSession, url: &str) -> Result<Page, WireError> {
    unlocked(session)?;
    Page::parse(url).map_err(|err| WireError::new("unsupported_page", err.message()))
}

/// Text from a page for the terminal and the vault: no control, format or bidi
/// characters, at most 128 characters.
pub(crate) fn page_text(text: &str) -> String {
    clean_text(text, 128)
}

/// `text` without control, format or bidi characters, at most `max` characters.
pub(crate) fn clean_text(text: &str, max: usize) -> String {
    let clean: String = text
        .chars()
        .filter(|c| !c.is_control() && !wire::hides_text(*c) && !crate::text::is_hidden_char(*c))
        .collect();
    clean.trim().chars().take(max).collect()
}

/// What to do with one request of the socket.
pub(crate) enum Intake {
    /// The request is answered.
    Answered,
    /// The request waits for the owner.
    Card(Box<BrowserCard>),
}

/// Answer `command` at once, or make the card that waits for the owner. `deadline` is
/// when the card closes.
pub(crate) fn intake(
    session: &OwnerSession,
    command: Command,
    reply: Sender<Response>,
    gone: PeerGone,
    deadline: Instant,
) -> Intake {
    let answer = |response: Response| {
        let _ = reply.send(response);
        Intake::Answered
    };
    let op = match command {
        Command::Status => {
            let vault = vault_state(session);
            let message = match vault {
                VaultState::None => "No vault is open in Apassy.",
                VaultState::Locked => "Apassy is locked.",
                VaultState::Unlocked => "Apassy is unlocked.",
            };
            return answer(Response::ok(
                message,
                Data::Status {
                    vault,
                    version: env!("CARGO_PKG_VERSION").to_owned(),
                },
            ));
        }
        Command::Show => {
            return answer(Response::ok(
                "Apassy runs in a terminal (apassy owner serve). Look there.",
                Data::None,
            ));
        }
        Command::Logins { url } => return answer(logins(session, &url, None)),
        Command::Suggestions { url, username } => {
            return answer(logins(session, &url, Some(&username)));
        }
        Command::AgentWait { .. }
        | Command::AgentPoll { .. }
        | Command::AgentBlocked { .. }
        | Command::BypassStatus
        | Command::BypassRequest(_)
        | Command::BypassEnd => {
            return answer(Response::error(
                "unsupported",
                "apassy owner serve does not fill the browser for agents or allow browser debugging. Use the desktop app for that.",
            ));
        }
        Command::Fill { url, item } => match page_of(session, &url).and_then(|page| {
            session
                .page_login(item, &page)
                .map(|login| (page, login))
                .map_err(|err| WireError::new(err.code, err.message))
        }) {
            Ok((page, login)) => BrowserOp::Fill {
                item: login.id,
                title: login.title,
                username: login.username,
                page,
            },
            Err(error) => return answer(error.into()),
        },
        Command::Update {
            url,
            item,
            username,
            password,
        } => match page_of(session, &url).and_then(|page| {
            session
                .page_login_update_target(item, &page, &username)
                .map(|(login, revision)| (page, login, revision))
                .map_err(|err| WireError::new(err.code, err.message))
        }) {
            Ok((page, login, revision)) => BrowserOp::Update {
                item,
                title: login.title,
                username: login.username,
                revision,
                password,
                page,
            },
            Err(error) => return answer(error.into()),
        },
        Command::Save {
            url,
            title,
            username,
            password,
        } => match new_login(session, &url, &username) {
            Ok(page) => BrowserOp::Save {
                title,
                username,
                password,
                page,
            },
            Err(error) => return answer(error.into()),
        },
        Command::Create {
            url,
            title,
            username,
            length,
            symbols,
        } => match new_login(session, &url, &username) {
            Ok(page) => BrowserOp::Create {
                title,
                username,
                length,
                symbols,
                page,
            },
            Err(error) => return answer(error.into()),
        },
        Command::FillCode { url, item, field } => match page_of(session, &url).and_then(|page| {
            session
                .page_code(item, &page, field.as_deref())
                .map(|code| (page, code))
                .map_err(|err| WireError::new(err.code, err.message))
        }) {
            Ok((page, code)) => BrowserOp::Code {
                item: code.id,
                title: code.title,
                field: code.field,
                page,
            },
            Err(error) => return answer(error.into()),
        },
        Command::PasskeyGet(request) => match passkey_get(session, &request) {
            Ok(op) => op,
            Err(error) => return answer(error.into()),
        },
        Command::PasskeyCreate(request) => match passkey_create(session, &request) {
            Ok(op) => op,
            Err(error) => return answer(error.into()),
        },
    };
    Intake::Card(Box::new(BrowserCard {
        op,
        reply: Some(reply),
        gone,
        deadline,
    }))
}

fn logins(session: &OwnerSession, url: &str, username: Option<&str>) -> Response {
    let page = match page_of(session, url) {
        Ok(page) => page,
        Err(error) => return error.into(),
    };
    let found = match username {
        Some(username) => session.suggestions_for_page(&page, username),
        None => session.logins_for_page(&page),
    };
    match found {
        Ok(found) => {
            let message = match found.len() {
                0 => format!("No login is for {}.", page.host()),
                1 => format!("1 login is for {}.", page.host()),
                count => format!("{count} logins are for {}.", page.host()),
            };
            Response::ok(
                message,
                Data::Logins {
                    origin: page.origin(),
                    host: page.host(),
                    logins: found
                        .into_iter()
                        .map(|login| LoginRow {
                            item: login.id,
                            title: login.title,
                            username: login.username,
                            has_totp: login.has_totp,
                        })
                        .collect(),
                },
            )
        }
        Err(err) => Response::error(err.code, err.message),
    }
}

/// The page of a new login. A login with the same username for the page answers
/// `exists` before any card, as in the window.
fn new_login(session: &OwnerSession, url: &str, username: &str) -> Result<Page, WireError> {
    let page = page_of(session, url)?;
    match session.login_with_username(&page, username) {
        Ok(None) => Ok(page),
        Ok(Some(existing)) => Err(WireError::new(
            "exists",
            format!(
                "\"{}\" is in Apassy for this page with the username {}. Nothing was saved.",
                existing.title, existing.username
            ),
        )),
        Err(err) => Err(WireError::new(err.code, err.message)),
    }
}

fn prf_input(values: &PasskeyPrfValues) -> PasskeyPrfInput {
    PasskeyPrfInput {
        first: values.first.clone(),
        second: values.second.clone(),
        hashed: false,
    }
}

/// One assertion: the client data is checked and hashed first. No passkey for the
/// relying party answers `no_match` without a card.
fn passkey_get(
    session: &OwnerSession,
    request: &PasskeyGetRequest,
) -> Result<BrowserOp, WireError> {
    unlocked(session)?;
    let client = webauthn::client_data(
        &request.rid,
        &request.origin,
        &request.rp_id,
        &request.client_data_json,
        webauthn::TYPE_GET,
    )?;
    let allowed = webauthn::decode_ids(&request.allowed)?;
    let accounts = session
        .passkeys_for(&client.rp_id, &allowed)
        .map_err(|err| WireError::new(err.code, err.message))?;
    if accounts.is_empty() {
        return Err(WireError::new(
            "no_match",
            format!("Apassy has no passkey for {}.", client.rp_id),
        ));
    }
    let prf = request.prf.as_ref();
    Ok(BrowserOp::Sign {
        echo: Echo {
            rid: client.rid.clone(),
            client_data_json: webauthn::encode_bytes(&client.client_data_json),
        },
        origin: client.origin,
        rid: client.rid,
        rp_id: client.rp_id,
        client_data_hash: client.client_data_hash,
        accounts,
        prf: prf.and_then(|prf| prf.eval.as_ref()).map(prf_input),
        prf_by_credential: prf
            .map(|prf| {
                prf.eval_by_credential
                    .iter()
                    .map(|(id, values)| (id.clone(), prf_input(values)))
                    .collect()
            })
            .unwrap_or_default(),
        large_blob: request.large_blob.as_ref().map(|blob| match blob {
            PasskeyLargeBlobRequest::Read => LargeBlobOp::Read,
            PasskeyLargeBlobRequest::Write(bytes) => {
                LargeBlobOp::Write(zeroize::Zeroizing::new(bytes.clone()))
            }
        }),
    })
}

/// One registration: the client data is checked and hashed first. A request without
/// ES256 answers `unsupported` without a card. An excluded credential answers
/// `excluded` only after the owner check, as in the window.
fn passkey_create(
    session: &OwnerSession,
    request: &PasskeyCreateRequest,
) -> Result<BrowserOp, WireError> {
    unlocked(session)?;
    let client = webauthn::client_data(
        &request.rid,
        &request.origin,
        &request.rp_id,
        &request.client_data_json,
        webauthn::TYPE_CREATE,
    )?;
    let user_handle = webauthn::decode_bytes(&request.user_handle, 1, 64)?;
    let excluded = webauthn::decode_ids(&request.excluded)?;
    if !request.algorithms.is_empty() && !request.algorithms.contains(&ES256) {
        return Err(WireError::new(
            "unsupported",
            "The site asks for a passkey type that Apassy does not make.",
        ));
    }
    let user_name = page_text(&request.user_name);
    let user_display_name = page_text(&request.user_display_name);
    if user_name.is_empty() {
        return Err(WireError::new(
            "bad_request",
            "A new passkey needs the name of the account.",
        ));
    }
    let title = match page_text(&request.title) {
        title if title.is_empty() => client.rp_id.clone(),
        title => title,
    };
    let attach = match Page::parse(&client.origin)
        .map(|page| session.passkey_attach_target(&page, &user_name))
    {
        Ok(Ok(found)) => found,
        Ok(Err(err)) => return Err(WireError::new(err.code, err.message)),
        Err(_) => None,
    };
    let (target, attach_name) = match attach {
        Some((login, revision)) => (
            PasskeyTarget::Attach {
                item_id: login.id,
                revision,
            },
            Some(login.title),
        ),
        None => (PasskeyTarget::NewItem { title }, None),
    };
    Ok(BrowserOp::Make {
        echo: Echo {
            rid: client.rid.clone(),
            client_data_json: webauthn::encode_bytes(&client.client_data_json),
        },
        action: Box::new(OwnerAction::CreatePasskey {
            origin: Some(client.origin),
            rid: client.rid,
            rp_id: client.rp_id,
            client_data_hash: client.client_data_hash,
            user_handle,
            user_name,
            user_display_name,
            algorithms: request.algorithms.clone(),
            excluded,
            target,
        }),
        attach_name,
    })
}

impl BrowserOp {
    /// The facts of the card, as the window's dialog names them. No secret value.
    pub(crate) fn facts(&self) -> Vec<(&'static str, String)> {
        let site = |page: &Page| page.origin();
        match self {
            Self::Fill {
                title,
                username,
                page,
                ..
            } => vec![
                ("Request", "Fill a password in the browser".to_owned()),
                ("Site", site(page)),
                ("Login", page_text(title)),
                ("Username", page_text(username)),
            ],
            Self::Update {
                title,
                username,
                page,
                ..
            } => vec![
                (
                    "Request",
                    "Replace the saved password with the one from the page".to_owned(),
                ),
                ("Site", site(page)),
                ("Login", page_text(title)),
                ("Username", page_text(username)),
            ],
            Self::Save {
                title,
                username,
                page,
                ..
            } => vec![
                ("Request", "Save a new login from the page".to_owned()),
                ("Site", site(page)),
                ("Name", page_text(title)),
                ("Username", page_text(username)),
            ],
            Self::Create {
                title,
                username,
                length,
                symbols,
                page,
            } => vec![
                (
                    "Request",
                    "Create a login with a new password and fill it".to_owned(),
                ),
                ("Site", site(page)),
                ("Name", page_text(title)),
                ("Username", page_text(username)),
                (
                    "Password",
                    format!(
                        "{length} characters{}",
                        if *symbols { ", with symbols" } else { "" }
                    ),
                ),
            ],
            Self::Code {
                title, field, page, ..
            } => vec![
                ("Request", "Fill a one-time code".to_owned()),
                ("Site", site(page)),
                ("Login", page_text(title)),
                ("Code field", page_text(field)),
            ],
            Self::Sign {
                origin,
                rp_id,
                accounts,
                prf,
                prf_by_credential,
                large_blob,
                ..
            } => {
                let mut facts = vec![
                    ("Request", "Sign in with a passkey".to_owned()),
                    ("Origin", page_text(origin)),
                    ("RP ID", page_text(rp_id)),
                    (
                        "User verification",
                        "yes: the vault passphrase (or polkit) for this request".to_owned(),
                    ),
                ];
                if prf.is_some() || !prf_by_credential.is_empty() {
                    facts.push((
                        "Extension",
                        "PRF: the site gets a key derived from the passkey".to_owned(),
                    ));
                }
                match large_blob {
                    Some(LargeBlobOp::Read) => {
                        facts.push((
                            "Extension",
                            "largeBlob: the site reads its stored data".to_owned(),
                        ));
                    }
                    Some(LargeBlobOp::Write(_)) => {
                        facts.push((
                            "Extension",
                            "largeBlob: the site stores data with the passkey".to_owned(),
                        ));
                    }
                    None => {}
                }
                // The vault lists the newest first; the time tells two passkeys of
                // one account apart (Linux acceptance, 2026-11-10).
                for (index, account) in accounts.iter().enumerate() {
                    let added = account
                        .added
                        .map(|at| format!(", added {}", crate::vault::format_utc(at)))
                        .unwrap_or_default();
                    facts.push((
                        "Account",
                        format!(
                            "{}. {} ({}) in \"{}\"{added}",
                            index + 1,
                            page_text(&account.user_name),
                            page_text(&account.user_display_name),
                            page_text(&account.title)
                        ),
                    ));
                }
                facts
            }
            Self::Make {
                action,
                attach_name,
                ..
            } => match &**action {
                OwnerAction::CreatePasskey {
                    origin,
                    rp_id,
                    user_name,
                    user_display_name,
                    target,
                    ..
                } => vec![
                    ("Request", "Create a passkey".to_owned()),
                    ("Origin", page_text(origin.as_deref().unwrap_or_default())),
                    ("RP ID", page_text(rp_id)),
                    (
                        "Account",
                        format!(
                            "{} ({})",
                            page_text(user_name),
                            page_text(user_display_name)
                        ),
                    ),
                    (
                        "Saved in",
                        match (target, attach_name) {
                            (PasskeyTarget::Attach { .. }, Some(name)) => {
                                format!("the existing login \"{}\"", page_text(name))
                            }
                            (PasskeyTarget::NewItem { title }, _) => {
                                format!("a new login \"{}\"", page_text(title))
                            }
                            _ => "an existing login".to_owned(),
                        },
                    ),
                    (
                        "User verification",
                        "yes: the vault passphrase (or polkit) for this request".to_owned(),
                    ),
                ],
                _ => vec![("Request", "Create a passkey".to_owned())],
            },
        }
    }

    /// How many accounts the owner chooses from: more than one only for a sign-in.
    pub(crate) fn choices(&self) -> usize {
        match self {
            Self::Sign { accounts, .. } => accounts.len(),
            _ => 1,
        }
    }

    /// The action of the owner check for the choice `index` (0-based).
    pub(crate) fn action(&self, index: usize) -> Option<OwnerAction> {
        Some(match self {
            Self::Fill {
                item, title, page, ..
            } => OwnerAction::FillLogin {
                item_id: *item,
                login: title.clone(),
                origin: page.origin(),
            },
            Self::Update {
                item,
                title,
                username,
                revision,
                page,
                ..
            } => OwnerAction::UpdateLogin {
                item_id: *item,
                login: title.clone(),
                username: username.clone(),
                origin: page.origin(),
                revision: *revision,
            },
            Self::Save {
                title,
                username,
                page,
                ..
            } => OwnerAction::SaveLogin {
                title: title.clone(),
                username: username.clone(),
                origin: page.origin(),
            },
            Self::Create {
                title,
                username,
                length,
                symbols,
                page,
            } => OwnerAction::CreateLogin {
                title: title.clone(),
                username: username.clone(),
                origin: page.origin(),
                length: *length,
                symbols: *symbols,
            },
            Self::Code {
                item, field, page, ..
            } => OwnerAction::FillCode {
                item_id: *item,
                field: field.clone(),
                origin: page.origin(),
            },
            Self::Sign {
                origin,
                rid,
                rp_id,
                client_data_hash,
                accounts,
                prf,
                prf_by_credential,
                large_blob,
                ..
            } => {
                let account = accounts.get(index)?;
                let by_credential = prf_by_credential
                    .iter()
                    .find(|(id, _)| id.as_slice() == account.credential_id.as_slice())
                    .map(|(_, input)| input.clone());
                OwnerAction::SignPasskey {
                    origin: Some(origin.clone()),
                    rid: rid.clone(),
                    rp_id: rp_id.clone(),
                    item_id: account.item_id,
                    credential_id: account.credential_id.clone(),
                    client_data_hash: *client_data_hash,
                    extensions: PasskeyAssertionExtensions {
                        prf: by_credential.or_else(|| prf.clone()),
                        large_blob: large_blob.clone(),
                    },
                }
            }
            Self::Make { action, .. } => OwnerAction::clone(action),
        })
    }
}

/// The PRF outputs and the largeBlob result of an assertion, for the browser. A read
/// without a stored blob has no entry.
pub(crate) fn extension_results(
    assertion: &PasskeyAssertion,
) -> (Option<PasskeyPrfResults>, Option<PasskeyLargeBlobResult>) {
    let prf = assertion.prf.as_ref().map(|output| PasskeyPrfResults {
        first: SecretText::new(webauthn::encode_bytes(&*output.first)),
        second: output
            .second
            .as_ref()
            .map(|second| SecretText::new(webauthn::encode_bytes(&**second))),
    });
    let large_blob = match &assertion.large_blob {
        Some(LargeBlobResult::Read(Some(blob))) => Some(PasskeyLargeBlobResult::Data {
            data: SecretText::new(webauthn::encode_bytes(blob)),
        }),
        Some(LargeBlobResult::Read(None)) | None => None,
        Some(LargeBlobResult::Written(written)) => {
            Some(PasskeyLargeBlobResult::Written { written: *written })
        }
    };
    (prf, large_blob)
}

/// Do what the passed check allows, and answer the browser. Returns the text for the
/// terminal. The proof is used up, also on a failure.
pub(crate) fn complete(
    session: &mut OwnerSession,
    card: &mut BrowserCard,
    action: &OwnerAction,
    proof: crate::broker::approvals::OwnerProof,
) -> String {
    // The values go out only to a browser that still waits.
    if !card.is_live() {
        drop(proof);
        return "The browser stopped waiting. Nothing was filled, signed or saved.".to_owned();
    }
    let refused = |card: &mut BrowserCard, code: &str, message: String| {
        let code = match code {
            "excluded" | "unsupported" | "exists" | "not_found" | "no_match" => code,
            _ => "refused",
        };
        card.send(Response::error(code, message.clone()));
        format!("Refused: {message}")
    };
    match &mut card.op {
        BrowserOp::Fill { item, page, .. } => {
            let (item, page) = (*item, page.clone());
            match session.fill_login(item, &page, proof) {
                Ok(mut values) => {
                    let delivered = card.send(Response::ok(
                        "Login values sent to the browser. The extension checks the form before filling.",
                        Data::Fill {
                            item,
                            origin: page.origin(),
                            username: std::mem::take(&mut values.username),
                            password: SecretText::new(std::mem::take(&mut *values.password)),
                        },
                    ));
                    if !delivered {
                        return "The browser stopped waiting. Nothing was filled.".to_owned();
                    }
                    let _ = session.record_fill(item, &page.origin());
                    format!(
                        "Login values were sent to your browser for {}.",
                        page.host()
                    )
                }
                Err(err) => refused(card, err.code, err.message),
            }
        }
        BrowserOp::Update {
            item,
            username,
            revision,
            password,
            page,
            ..
        } => {
            let (item, revision, username, page) =
                (*item, *revision, username.clone(), page.clone());
            let password = std::mem::replace(password, SecretText::new(String::new()));
            match session.update_page_login(item, revision, &username, password, &page, proof) {
                Ok(item) => {
                    if card.send(Response::ok(
                        "Updated in Apassy.",
                        Data::Updated {
                            item,
                            origin: page.origin(),
                            username,
                        },
                    )) {
                        "The login password is updated in Apassy.".to_owned()
                    } else {
                        "The password is updated in Apassy, but the browser stopped waiting for the answer.".to_owned()
                    }
                }
                Err(err) => refused(card, err.code, err.message),
            }
        }
        BrowserOp::Save {
            title,
            username,
            password,
            page,
        } => {
            let (title, username, page) = (title.clone(), username.clone(), page.clone());
            let password = std::mem::replace(password, SecretText::new(String::new()));
            match session.save_login(&title, &username, password, &page, proof) {
                Ok(item) => {
                    if card.send(Response::ok("Saved.", Data::Saved { item })) {
                        format!("The login \"{}\" is saved.", page_text(&title))
                    } else {
                        "The login is saved in Apassy, but the browser stopped waiting for the answer.".to_owned()
                    }
                }
                Err(err) => refused(card, err.code, err.message),
            }
        }
        BrowserOp::Create {
            title,
            username,
            length,
            symbols,
            page,
        } => {
            let (title, username, length, symbols, page) = (
                title.clone(),
                username.clone(),
                *length,
                *symbols,
                page.clone(),
            );
            match session.create_login(&title, &username, &page, length, symbols, proof) {
                Ok((item, mut values)) => {
                    let delivered = card.send(Response::ok(
                        "Login values sent to the browser. The extension checks the form before filling.",
                        Data::Fill {
                            item,
                            origin: page.origin(),
                            username: std::mem::take(&mut values.username),
                            password: SecretText::new(std::mem::take(&mut *values.password)),
                        },
                    ));
                    if delivered {
                        let _ = session.record_fill(item, &page.origin());
                        format!(
                            "The new login \"{}\" is in Apassy and was sent to your browser.",
                            page_text(&title)
                        )
                    } else {
                        format!(
                            "The login \"{}\" is in Apassy, but the browser stopped waiting.",
                            page_text(&title)
                        )
                    }
                }
                Err(err) => refused(card, err.code, err.message),
            }
        }
        BrowserOp::Code {
            item, field, page, ..
        } => {
            let (item, field, page) = (*item, field.clone(), page.clone());
            match session.fill_code(item, &field, &page, proof) {
                Ok(mut code) => {
                    let delivered = card.send(Response::ok(
                        "Filled.",
                        Data::Code {
                            item,
                            origin: page.origin(),
                            code: SecretText::new(std::mem::take(&mut *code.digits)),
                            remaining: code.left,
                        },
                    ));
                    if !delivered {
                        return "The browser stopped waiting. No code was filled.".to_owned();
                    }
                    let _ = session.record_fill(item, &page.origin());
                    "The one-time code is filled in your browser.".to_owned()
                }
                Err(err) => refused(card, err.code, err.message),
            }
        }
        BrowserOp::Sign { echo, .. } => {
            let (rid, client_data_json) = (echo.rid.clone(), echo.client_data_json.clone());
            match session.sign_passkey(action, proof) {
                Ok(assertion) => {
                    let stored =
                        matches!(assertion.large_blob, Some(LargeBlobResult::Written(true)));
                    let (prf, large_blob) = extension_results(&assertion);
                    let delivered = card.send(Response::ok(
                        "Signed.",
                        Data::Passkey {
                            rid,
                            credential_id: webauthn::encode_bytes(&assertion.credential_id),
                            user_handle: webauthn::encode_bytes(&assertion.user_handle),
                            authenticator_data: webauthn::encode_bytes(
                                &assertion.authenticator_data,
                            ),
                            signature: webauthn::encode_bytes(&assertion.signature),
                            client_data_json,
                            algorithm: assertion.algorithm,
                            prf,
                            large_blob,
                        },
                    ));
                    match (delivered, stored) {
                        (true, _) => "You are signed in with a passkey from Apassy.".to_owned(),
                        (false, true) => "The browser stopped waiting. The page got no passkey. The data the page sent is stored with the passkey.".to_owned(),
                        (false, false) => "The browser stopped waiting. The page got no passkey.".to_owned(),
                    }
                }
                Err(err) => refused(card, err.code, err.message),
            }
        }
        BrowserOp::Make { echo, .. } => {
            let (rid, client_data_json) = (echo.rid.clone(), echo.client_data_json.clone());
            match session.create_passkey(action, proof) {
                Ok(created) => {
                    if card.send(Response::ok(
                        "Created.",
                        Data::PasskeyCreated {
                            rid,
                            item: created.item_id,
                            credential_id: webauthn::encode_bytes(&created.credential_id),
                            attestation_object: webauthn::encode_bytes(&created.attestation_object),
                            authenticator_data: webauthn::encode_bytes(&created.authenticator_data),
                            public_key_spki: webauthn::encode_bytes(&created.public_key_spki),
                            algorithm: created.algorithm,
                            client_data_json,
                        },
                    )) {
                        "The new passkey is saved in Apassy.".to_owned()
                    } else {
                        "The new passkey is saved in Apassy, but the page did not get it. Remove it, or sign in and add the passkey again.".to_owned()
                    }
                }
                Err(err) => refused(card, err.code, err.message),
            }
        }
    }
}
