//! The browser socket of the desktop app (ADR 0021).
//!
//! [`super::owner_socket`] hands each request of `browser.sock` to
//! [`DesktopApp::poll_browser`]. `status`, `show`, and `logins` answer at once. `fill`,
//! `save`, and `create` open the same owner check dialog as the views, with a note that
//! the browser asked for it, and answer after the owner confirms or cancels it. Each of
//! them needs its own check. Only the answer of a passed fill or create has a secret
//! value. The password of a save waits in the ticket of the dialog.
//!
//! `passkey_get`, `passkey_create`, and `fill_code` come only from a peer that
//! [`crate::browser::caller::check_peer`] accepts. Before any dialog the app checks the
//! client data that the extension built ([`crate::browser::webauthn::client_data`]: type,
//! challenge, origin, relying party), and hashes the exact bytes itself. A request that
//! Apassy cannot serve answers `none_open`, `vault_locked`, `no_match`, or `unsupported`
//! before any dialog, so the browser can use its own passkeys. After the dialog opens,
//! each end answers `cancelled`, `owner_check_failed`, `excluded`, or `refused`. The
//! socket watches the peer while the dialog is open: when the browser hangs up, the
//! dialog closes, and a late check signs and fills nothing. The proof names the origin
//! from the client data, the relying party, the credential, the hash, and the request.

use std::path::Path;
use std::sync::mpsc::{Receiver, Sender};
use std::time::{Duration, Instant};

use eframe::egui;

use std::os::unix::net::UnixStream;

use super::DesktopApp;
use super::owner_check::{NO_ACCOUNT, OwnerRequest, PasskeyAccount, PasskeyRequest, page_text};
use super::owner_cli::bring_to_front;
use super::owner_socket::{self, Envelope, LineWire, OwnerSocket, PeerGone, WireEnvelope};
use crate::broker::approvals::{OwnerAction, OwnerProof};
use crate::browser::site::Page;
use crate::browser::webauthn;
use crate::browser::wire::{
    self, Command, Data, LoginRow, PasskeyCreateRequest, PasskeyGetRequest, Request, Response,
    VaultState, WireError,
};
use crate::desktop::model::ModelError;
use crate::owner::wire::SecretText;
use crate::vault::{PasskeyAssertion, PasskeyCreated, PasskeyTarget};

/// A fill dialog closes this long before the socket stops waiting, so the extension
/// gets `cancelled`, and a late check fills nothing. The deadline starts when the UI
/// thread takes the request, a little after the socket starts to wait.
const TICKET_MARGIN: Duration = Duration::from_secs(15);

/// While a browser dialog is open, the app looks at least this often whether the
/// browser hung up. The socket thread also wakes the app when it sees the hang-up.
const HANG_UP_REPAINT: Duration = Duration::from_millis(500);

/// The note in the owner check dialog for a request of the browser.
pub(crate) const BROWSER_ORIGIN_NOTE: &str = "Your browser asked for this (the Apassy extension). If you did not ask for it in your browser just now, click Cancel.";

/// The ES256 algorithm of COSE: the only passkey type that Apassy makes.
const ES256: i64 = -7;

/// The browser wire on the socket.
pub(crate) struct BrowserWire;

/// One request of the browser socket, with the hang-up state of its connection.
pub(crate) struct BrowserRequest {
    pub(crate) command: Command,
    pub(crate) gone: PeerGone,
}

/// True for a command that needs a checked peer and ends when the peer hangs up: a
/// passkey or a one-time code. The older commands keep their behavior.
fn guarded(command: &Command) -> bool {
    matches!(
        command,
        Command::PasskeyGet(_) | Command::PasskeyCreate(_) | Command::FillCode { .. }
    )
}

impl LineWire for BrowserWire {
    type Request = BrowserRequest;
    type Response = Response;
    const NAME: &'static str = "browser";
    const MAX_REQUEST_BYTES: usize = wire::MAX_REQUEST_BYTES;
    const MAX_CONNECTIONS: usize = 4;
    const BUSY: &'static str = "Apassy has too many browser connections.";

    fn parse(line: &[u8]) -> Result<BrowserRequest, Response> {
        Request::parse(line)
            .map(|command| BrowserRequest {
                command,
                gone: PeerGone::default(),
            })
            .map_err(Response::from)
    }

    fn error(code: &'static str, message: &'static str) -> Response {
        Response::error(code, message)
    }

    /// A passkey or a code comes only from the signed Apassy host that the signed
    /// browser started. The check fails closed.
    fn check_peer(stream: &UnixStream, request: &BrowserRequest) -> Result<(), Response> {
        if guarded(&request.command) {
            crate::browser::caller::check_peer(stream).map_err(Response::from)?;
        }
        Ok(())
    }

    fn watch(request: &BrowserRequest) -> Option<PeerGone> {
        guarded(&request.command).then(|| request.gone.clone())
    }
}

/// The browser socket, and the values of a fill on their way to its ticket.
#[derive(Default)]
pub(crate) struct BrowserHost {
    socket: Option<OwnerSocket>,
    inbox: Option<Receiver<WireEnvelope<BrowserWire>>>,
    /// Why the browser socket did not start.
    pub(crate) problem: Option<String>,
    /// The values of the fill that the last owner check passed.
    filled: Option<Filled>,
    /// The password of a save, from its ticket, for the owner check that passed.
    pending: Option<SecretText>,
    /// The login that the last save added.
    saved: Option<u64>,
    /// The code of the fill that the last owner check passed.
    code: Option<FilledCode>,
    /// The result of the passkey check that passed, for the browser or for the macOS
    /// passkey sheet ([`super::passkey_socket`]).
    pub(crate) passkey: Option<Result<PasskeyDone, ModelError>>,
    /// When the extension last sent a request. Settings shows it.
    pub(crate) last_seen: Option<Instant>,
}

impl BrowserHost {
    #[cfg(test)]
    pub(crate) fn socket_path(&self) -> Option<&Path> {
        self.socket.as_ref().map(OwnerSocket::socket_path)
    }

    /// Stop the socket. Waiting requests get "stopped".
    pub(crate) fn stop(&mut self) {
        if let Some(mut socket) = self.socket.take() {
            socket.stop();
        }
        self.inbox = None;
        self.filled = None;
        self.pending = None;
        self.saved = None;
        self.code = None;
        self.passkey = None;
    }
}

/// A passkey that the vault signed or made after the owner check, on its way to the
/// ticket.
pub(crate) enum PasskeyDone {
    Signed(PasskeyAssertion),
    Created(PasskeyCreated),
}

/// One code for the browser. The digits are erased on drop.
struct FilledCode {
    item: u64,
    origin: String,
    code: SecretText,
    remaining: u64,
}

/// The values of a passkey request that its answer repeats: the request ID and the
/// client data, as the app checked them.
pub(crate) struct PasskeyEcho {
    rid: String,
    client_data_json: String,
}

/// The values of one fill. The password is erased on drop.
struct Filled {
    item: u64,
    origin: String,
    username: String,
    password: SecretText,
    /// The title of a login that `create` added, `None` for a fill.
    created: Option<String>,
}

/// The way back to one fill request. A ticket that drops without an answer tells the
/// extension that nothing was filled: for example when the owner closes the dialog.
pub(crate) struct BrowserTicket {
    reply: Option<Sender<Response>>,
    /// After this time the socket no longer waits for the answer.
    deadline: Instant,
    /// The password of a save. It is erased when the ticket drops.
    secret: Option<SecretText>,
    /// Set when the browser hung up. `None` for a request without a watched connection.
    gone: Option<PeerGone>,
    /// The request ID and the client data of a passkey request.
    echo: Option<PasskeyEcho>,
}

impl BrowserTicket {
    fn new(reply: Sender<Response>, gone: Option<PeerGone>) -> Self {
        Self {
            reply: Some(reply),
            deadline: Instant::now() + owner_socket::REPLY_TIMEOUT.saturating_sub(TICKET_MARGIN),
            secret: None,
            gone,
            echo: None,
        }
    }

    /// True when the browser hung up.
    pub(crate) fn hung_up(&self) -> bool {
        self.gone.as_ref().is_some_and(PeerGone::is_set)
    }

    /// True while the browser still waits: it did not hang up, and the deadline did not
    /// pass. A passkey signs and a code is made only for a live ticket.
    pub(crate) fn is_live(&self) -> bool {
        self.reply.is_some() && !self.hung_up() && !self.left().is_zero()
    }

    /// Send the answer. False when nobody waits for it any more.
    pub(crate) fn send(mut self, response: Response) -> bool {
        self.reply
            .take()
            .is_some_and(|reply| reply.send(response).is_ok())
    }

    /// The time until the deadline. Zero after it.
    fn left(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }
}

impl Drop for BrowserTicket {
    fn drop(&mut self) {
        if let Some(reply) = self.reply.take() {
            let _ = reply.send(Response::error(
                "cancelled",
                "The owner check closed before it passed. Nothing was filled.",
            ));
        }
    }
}

impl DesktopApp {
    /// Start the browser socket. A failure shows in Settings, and the app keeps working.
    pub(crate) fn start_browser(&mut self, socket: &Path, ctx: &egui::Context) {
        let repaint = ctx.clone();
        match owner_socket::start_line::<BrowserWire>(socket, move || repaint.request_repaint()) {
            Ok((handle, inbox)) => {
                self.browser.socket = Some(handle);
                self.browser.inbox = Some(inbox);
                self.browser.problem = None;
            }
            Err(err) => {
                self.browser.problem = Some(format!(
                    "The browser socket did not start at {}: {err}",
                    socket.display()
                ));
            }
        }
    }

    /// Answer the requests that wait. The app calls this each frame, also while the
    /// window is hidden.
    pub(crate) fn poll_browser(&mut self, ctx: &egui::Context) {
        // A browser that hung up closes its dialog, also while the window is hidden.
        self.expire_browser_check(ctx);
        let Some(inbox) = &self.browser.inbox else {
            return;
        };
        let envelopes: Vec<WireEnvelope<BrowserWire>> = inbox.try_iter().collect();
        for Envelope { request, reply } in envelopes {
            let BrowserRequest { command, gone } = request;
            self.handle_browser_watched(
                Envelope {
                    request: command,
                    reply,
                },
                Some(gone),
                ctx,
            );
        }
    }

    /// Answer one request. Tests call this with an envelope of their own.
    #[cfg(test)]
    pub(crate) fn handle_browser(
        &mut self,
        envelope: Envelope<Command, Response>,
        ctx: &egui::Context,
    ) {
        self.handle_browser_watched(envelope, None, ctx);
    }

    /// Answer one request whose connection sets `gone` when the browser hangs up.
    pub(crate) fn handle_browser_watched(
        &mut self,
        envelope: Envelope<Command, Response>,
        gone: Option<PeerGone>,
        ctx: &egui::Context,
    ) {
        let Envelope { request, reply } = envelope;
        self.browser.last_seen = Some(Instant::now());
        let ticket = BrowserTicket::new(reply, gone);
        match request {
            Command::Status => {
                ticket.send(self.browser_status());
            }
            Command::Show => {
                bring_to_front(ctx);
                ticket.send(Response::ok("Apassy is in front.", Data::None));
            }
            Command::Logins { url } => {
                ticket.send(self.browser_logins(&url));
            }
            Command::Fill { url, item } => self.browser_fill(&url, item, ticket, ctx),
            Command::Save {
                url,
                title,
                username,
                password,
            } => {
                let mut ticket = ticket;
                ticket.secret = Some(password);
                self.browser_new_login(&url, &title, &username, None, ticket, ctx);
            }
            Command::Create {
                url,
                title,
                username,
                length,
                symbols,
            } => self.browser_new_login(
                &url,
                &title,
                &username,
                Some((length, symbols)),
                ticket,
                ctx,
            ),
            Command::FillCode { url, item, field } => {
                self.browser_fill_code(&url, item, field.as_deref(), ticket, ctx);
            }
            Command::PasskeyGet(request) => self.browser_passkey_get(&request, ticket, ctx),
            Command::PasskeyCreate(request) => self.browser_passkey_create(&request, ticket, ctx),
        }
    }

    fn browser_vault(&self) -> VaultState {
        let session = &self.owner_ui.session;
        if !session.has_file() {
            VaultState::None
        } else if session.is_locked() {
            VaultState::Locked
        } else {
            VaultState::Unlocked
        }
    }

    fn browser_status(&self) -> Response {
        let vault = self.browser_vault();
        let message = match vault {
            VaultState::None => "No vault is open in Apassy.",
            VaultState::Locked => "Apassy is locked.",
            VaultState::Unlocked => "Apassy is unlocked.",
        };
        Response::ok(
            message,
            Data::Status {
                vault,
                version: env!("CARGO_PKG_VERSION").to_owned(),
            },
        )
    }

    /// The page of a request, when the vault is unlocked.
    fn browser_page(&self, url: &str) -> Result<Page, WireError> {
        match self.browser_vault() {
            VaultState::None => {
                return Err(WireError::new(
                    "none_open",
                    "No vault is open. Open and unlock a vault in Apassy.",
                ));
            }
            VaultState::Locked => {
                return Err(WireError::new(
                    "vault_locked",
                    "Apassy is locked. Unlock it to fill logins.",
                ));
            }
            VaultState::Unlocked => {}
        }
        Page::parse(url).map_err(|err| WireError::new("unsupported_page", err.message()))
    }

    fn browser_logins(&self, url: &str) -> Response {
        let page = match self.browser_page(url) {
            Ok(page) => page,
            Err(error) => return error.into(),
        };
        match self.owner_ui.session.logins_for_page(&page) {
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

    /// Open the owner check dialog for one fill. One dialog at a time: a second request
    /// gets `busy`, so a program cannot replace a dialog that the owner reads.
    fn browser_fill(&mut self, url: &str, item: u64, ticket: BrowserTicket, ctx: &egui::Context) {
        let page = match self.browser_page(url) {
            Ok(page) => page,
            Err(error) => {
                ticket.send(error.into());
                return;
            }
        };
        let login = match self.owner_ui.session.page_login(item, &page) {
            Ok(login) => login,
            Err(err) => {
                ticket.send(Response::error(err.code, err.message));
                return;
            }
        };
        if self.owner.check.is_some() {
            ticket.send(Response::error(
                "busy",
                "Another owner check is open in Apassy. Finish it, then try again.",
            ));
            return;
        }
        self.ask_owner(
            OwnerRequest::FillLogin {
                item_id: login.id,
                item_name: login.title,
                username: login.username,
                origin: page.origin(),
            },
            Some(ctx),
        );
        if let Some(dialog) = self.owner.check.as_mut() {
            dialog.browser = Some(ticket);
        }
        // The macOS Touch ID prompt shows over the browser. The passphrase field is in
        // the window.
        if !self.owner.touch_id_ready() {
            bring_to_front(ctx);
        }
    }

    /// Open the owner check dialog for a new login: a save (`generate` is `None`) or a
    /// create (`generate` names the length and the symbols). A login with the same
    /// username for the page gets `exists` before the dialog.
    fn browser_new_login(
        &mut self,
        url: &str,
        title: &str,
        username: &str,
        generate: Option<(u32, bool)>,
        ticket: BrowserTicket,
        ctx: &egui::Context,
    ) {
        let page = match self.browser_page(url) {
            Ok(page) => page,
            Err(error) => {
                ticket.send(error.into());
                return;
            }
        };
        match self.owner_ui.session.login_with_username(&page, username) {
            Ok(None) => {}
            Ok(Some(existing)) => {
                ticket.send(Response::error(
                    "exists",
                    format!(
                        "\"{}\" is in Apassy for this page with the username {}. Nothing was saved.",
                        existing.title, existing.username
                    ),
                ));
                return;
            }
            Err(err) => {
                ticket.send(Response::error(err.code, err.message));
                return;
            }
        }
        if self.owner.check.is_some() {
            ticket.send(Response::error(
                "busy",
                "Another owner check is open in Apassy. Finish it, then try again.",
            ));
            return;
        }
        let request = match generate {
            None => OwnerRequest::SaveLogin {
                title: title.to_owned(),
                username: username.to_owned(),
                origin: page.origin(),
            },
            Some((length, symbols)) => OwnerRequest::CreateLogin {
                title: title.to_owned(),
                username: username.to_owned(),
                origin: page.origin(),
                length,
                symbols,
            },
        };
        self.ask_owner(request, Some(ctx));
        if let Some(dialog) = self.owner.check.as_mut() {
            dialog.browser = Some(ticket);
        }
        if !self.owner.touch_id_ready() {
            bring_to_front(ctx);
        }
    }

    /// The vault state before a passkey request: an open, unlocked vault. Both answers
    /// let the browser use its own passkeys.
    fn browser_unlocked(&self) -> Result<(), WireError> {
        match self.browser_vault() {
            VaultState::None => Err(WireError::new(
                "none_open",
                "No vault is open. Open and unlock a vault in Apassy.",
            )),
            VaultState::Locked => Err(WireError::new(
                "vault_locked",
                "Apassy is locked. Unlock it to use passkeys.",
            )),
            VaultState::Unlocked => Ok(()),
        }
    }

    /// Open the owner check dialog for `request` with `ticket`, when no other check is
    /// open. One dialog at a time: a second request gets `busy`.
    fn ask_owner_for_browser(
        &mut self,
        request: OwnerRequest,
        ticket: BrowserTicket,
        ctx: &egui::Context,
    ) {
        if self.owner.check.is_some() {
            ticket.send(Response::error(
                "busy",
                "Another owner check is open in Apassy. Finish it, then try again.",
            ));
            return;
        }
        self.ask_owner(request, Some(ctx));
        if let Some(dialog) = self.owner.check.as_mut() {
            dialog.browser = Some(ticket);
        }
        if !self.owner.touch_id_ready() {
            bring_to_front(ctx);
        }
    }

    /// Open the owner check dialog for one code of login `item` on the page. The login
    /// must match the page as for a fill, and `field` must hold a one-time password.
    fn browser_fill_code(
        &mut self,
        url: &str,
        item: u64,
        field: Option<&str>,
        ticket: BrowserTicket,
        ctx: &egui::Context,
    ) {
        let page = match self.browser_page(url) {
            Ok(page) => page,
            Err(error) => {
                ticket.send(error.into());
                return;
            }
        };
        let code = match self.owner_ui.session.page_code(item, &page, field) {
            Ok(code) => code,
            Err(err) => {
                ticket.send(Response::error(err.code, err.message));
                return;
            }
        };
        self.ask_owner_for_browser(
            OwnerRequest::FillCode {
                item_id: code.id,
                item_name: code.title,
                field: code.field,
                origin: page.origin(),
            },
            ticket,
            ctx,
        );
    }

    /// Open the owner check dialog for one assertion. The client data is checked and
    /// hashed first. No passkey for the relying party answers `no_match` without a dialog.
    fn browser_passkey_get(
        &mut self,
        request: &PasskeyGetRequest,
        mut ticket: BrowserTicket,
        ctx: &egui::Context,
    ) {
        let checked = self.browser_unlocked().and_then(|()| {
            let client = webauthn::client_data(
                &request.rid,
                &request.origin,
                &request.rp_id,
                &request.client_data_json,
                "webauthn.get",
            )?;
            let allowed = webauthn::decode_ids(&request.allowed)?;
            Ok((client, allowed))
        });
        let (client, allowed) = match checked {
            Ok(checked) => checked,
            Err(error) => {
                ticket.send(error.into());
                return;
            }
        };
        let found = match self.owner_ui.session.passkeys_for(&client.rp_id, &allowed) {
            Ok(found) => found,
            Err(err) => {
                ticket.send(Response::error(err.code, err.message));
                return;
            }
        };
        if found.is_empty() {
            ticket.send(Response::error(
                "no_match",
                format!("Apassy has no passkey for {}.", client.rp_id),
            ));
            return;
        }
        let accounts: Vec<PasskeyAccount> = found
            .into_iter()
            .map(|info| PasskeyAccount {
                item_id: info.item_id,
                item_name: info.title,
                user_name: info.user_name,
                user_display_name: info.user_display_name,
                credential_id: info.credential_id,
            })
            .collect();
        // With several accounts the owner chooses one; no check starts before.
        let chosen = if accounts.len() > 1 { NO_ACCOUNT } else { 0 };
        ticket.echo = Some(PasskeyEcho {
            rid: client.rid.clone(),
            client_data_json: webauthn::encode_bytes(&client.client_data_json),
        });
        self.ask_owner_for_browser(
            OwnerRequest::SignPasskey {
                request: PasskeyRequest {
                    origin: Some(client.origin),
                    rid: client.rid,
                    rp_id: client.rp_id,
                    client_data_hash: client.client_data_hash,
                },
                accounts,
                chosen,
            },
            ticket,
            ctx,
        );
    }

    /// Open the owner check dialog for one registration. The client data is checked and
    /// hashed first. A request without ES256 answers `unsupported` without a dialog. An
    /// excluded credential answers `excluded` only after the check.
    fn browser_passkey_create(
        &mut self,
        request: &PasskeyCreateRequest,
        mut ticket: BrowserTicket,
        ctx: &egui::Context,
    ) {
        let checked = self.browser_unlocked().and_then(|()| {
            let client = webauthn::client_data(
                &request.rid,
                &request.origin,
                &request.rp_id,
                &request.client_data_json,
                "webauthn.create",
            )?;
            let user_handle = webauthn::decode_bytes(&request.user_handle, 1, 64)?;
            let excluded = webauthn::decode_ids(&request.excluded)?;
            Ok((client, user_handle, excluded))
        });
        let (client, user_handle, excluded) = match checked {
            Ok(checked) => checked,
            Err(error) => {
                ticket.send(error.into());
                return;
            }
        };
        if !request.algorithms.is_empty() && !request.algorithms.contains(&ES256) {
            ticket.send(Response::error(
                "unsupported",
                "The site asks for a passkey type that Apassy does not make.",
            ));
            return;
        }
        // The names come from the page. They are cut and cleaned for the dialog and the
        // vault, so they cannot hide the site.
        let user_name = page_text(&request.user_name);
        let user_display_name = page_text(&request.user_display_name);
        if user_name.is_empty() {
            ticket.send(Response::error(
                "bad_request",
                "A new passkey needs the name of the account.",
            ));
            return;
        }
        let title = match page_text(&request.title) {
            title if title.is_empty() => client.rp_id.clone(),
            title => title,
        };
        // A login for this page with this username and no passkey gets the passkey.
        let attach = match Page::parse(&client.origin).map(|page| {
            self.owner_ui
                .session
                .passkey_attach_target(&page, &user_name)
        }) {
            Ok(Ok(found)) => found,
            Ok(Err(err)) => {
                ticket.send(Response::error(err.code, err.message));
                return;
            }
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
            None => (
                PasskeyTarget::NewItem {
                    title: title.clone(),
                },
                None,
            ),
        };
        ticket.echo = Some(PasskeyEcho {
            rid: client.rid.clone(),
            client_data_json: webauthn::encode_bytes(&client.client_data_json),
        });
        self.ask_owner_for_browser(
            OwnerRequest::CreatePasskey {
                request: PasskeyRequest {
                    origin: Some(client.origin),
                    rid: client.rid,
                    rp_id: client.rp_id,
                    client_data_hash: client.client_data_hash,
                },
                user_handle,
                user_name,
                user_display_name,
                algorithms: request.algorithms.clone(),
                excluded,
                target,
                attach_name,
            },
            ticket,
            ctx,
        );
    }

    /// Sign or make the passkey of a passed check. The result waits for the ticket of
    /// the browser or of the macOS passkey sheet. The ticket was live just before.
    pub(crate) fn complete_passkey(&mut self, action: &OwnerAction, proof: OwnerProof) {
        let session = &mut self.owner_ui.session;
        let result = match action {
            OwnerAction::SignPasskey { .. } => {
                session.sign_passkey(action, proof).map(PasskeyDone::Signed)
            }
            _ => session
                .create_passkey(action, proof)
                .map(PasskeyDone::Created),
        };
        if let Err(err) = &result {
            self.set_err(err.message.clone());
        }
        self.browser.passkey = Some(result);
    }

    /// Make the code of a passed check. It waits for the ticket.
    pub(crate) fn complete_fill_code(
        &mut self,
        item_id: u64,
        field: &str,
        origin: &str,
        proof: OwnerProof,
    ) {
        let page = match Page::parse(origin) {
            Ok(page) => page,
            Err(err) => {
                drop(proof);
                return self.set_err(err.message());
            }
        };
        match self
            .owner_ui
            .session
            .fill_code(item_id, field, &page, proof)
        {
            Ok(mut code) => {
                self.browser.code = Some(FilledCode {
                    item: item_id,
                    origin: page.origin(),
                    code: SecretText::new(std::mem::take(&mut *code.digits)),
                    remaining: code.left,
                });
            }
            Err(err) => self.set_err(err.message),
        }
    }

    /// Move the password of a save from the ticket of a passed check to the app, for
    /// [`Self::complete_save`].
    pub(crate) fn hold_browser_secret(&mut self, ticket: &mut BrowserTicket) {
        self.browser.pending = ticket.secret.take();
    }

    /// Add the login of a save after the owner check.
    pub(crate) fn complete_save(
        &mut self,
        title: &str,
        username: &str,
        origin: &str,
        proof: OwnerProof,
    ) {
        let (Some(password), Ok(page)) = (self.browser.pending.take(), Page::parse(origin)) else {
            drop(proof);
            return self.set_err("The password from the page is gone. Nothing was saved.");
        };
        match self
            .owner_ui
            .session
            .save_login(title, username, password, &page, proof)
        {
            Ok(item) => {
                self.browser.saved = Some(item);
                self.set_ok(format!("The login \"{title}\" is saved."));
            }
            Err(err) => self.set_err(err.message),
        }
    }

    /// Add the login of a create after the owner check. Its values wait for the ticket.
    pub(crate) fn complete_create(
        &mut self,
        title: &str,
        username: &str,
        origin: &str,
        length: u32,
        symbols: bool,
        proof: OwnerProof,
    ) {
        let page = match Page::parse(origin) {
            Ok(page) => page,
            Err(err) => {
                drop(proof);
                return self.set_err(err.message());
            }
        };
        match self
            .owner_ui
            .session
            .create_login(title, username, &page, length, symbols, proof)
        {
            Ok((item, mut values)) => {
                self.browser.filled = Some(Filled {
                    item,
                    origin: page.origin(),
                    username: std::mem::take(&mut values.username),
                    password: SecretText::new(std::mem::take(&mut *values.password)),
                    created: Some(title.to_owned()),
                });
            }
            Err(err) => self.set_err(err.message),
        }
    }

    /// Take the values of one fill after the owner check. They wait for the ticket.
    pub(crate) fn complete_fill(&mut self, item_id: u64, origin: &str, proof: OwnerProof) {
        let page = match Page::parse(origin) {
            Ok(page) => page,
            Err(err) => {
                drop(proof);
                return self.set_err(err.message());
            }
        };
        match self.owner_ui.session.fill_login(item_id, &page, proof) {
            // The status and the history wait for the delivery to the browser.
            Ok(mut values) => {
                self.browser.filled = Some(Filled {
                    item: item_id,
                    origin: page.origin(),
                    username: std::mem::take(&mut values.username),
                    password: SecretText::new(std::mem::take(&mut *values.password)),
                    created: None,
                });
            }
            Err(err) => self.set_err(err.message),
        }
    }

    /// Close a fill dialog when the socket no longer waits for it. A late owner check
    /// then fills nothing. The app calls this each frame.
    pub(crate) fn expire_browser_check(&mut self, ctx: &egui::Context) {
        let Some((left, hung_up)) = self
            .owner
            .check
            .as_ref()
            .and_then(|dialog| dialog.browser.as_ref())
            .map(|ticket| (ticket.left(), ticket.hung_up()))
        else {
            return;
        };
        if hung_up {
            self.close_owner_check(Some(ctx));
            self.set_note(
                "The browser cancelled the request. Nothing was signed, filled, or saved.",
            );
        } else if left.is_zero() {
            self.close_owner_check(Some(ctx));
            self.set_err("The browser stopped waiting for the owner check. Nothing was filled.");
        } else {
            ctx.request_repaint_after(left.min(HANG_UP_REPAINT));
        }
    }

    /// Move the deadline of an open fill dialog to now, as if the time passed.
    #[cfg(test)]
    pub(crate) fn age_browser_check(&mut self) {
        if let Some(ticket) = self
            .owner
            .check
            .as_mut()
            .and_then(|dialog| dialog.browser.as_mut())
        {
            ticket.deadline = Instant::now();
        }
    }

    /// True when no fill values wait for a ticket.
    #[cfg(test)]
    pub(crate) fn browser_filled_is_empty(&self) -> bool {
        self.browser.filled.is_none()
    }

    /// True when no password of a save waits.
    #[cfg(test)]
    pub(crate) fn browser_pending_is_empty(&self) -> bool {
        self.browser.pending.is_none() && self.browser.saved.is_none()
    }

    /// Answer the browser request of a finished owner check. `before` is the status
    /// sequence before the action.
    pub(crate) fn answer_browser_ticket(&mut self, ticket: BrowserTicket, before: u64) {
        self.browser.pending = None;
        if let Some(result) = self.browser.passkey.take() {
            return self.answer_browser_passkey(ticket, result);
        }
        if let Some(code) = self.browser.code.take() {
            return self.answer_browser_code(ticket, code);
        }
        let filled = self.browser.filled.take();
        let failed = self.status_seq != before && self.status_kind == super::StatusKind::Error;
        if let Some(item) = self.browser.saved.take() {
            if !ticket.send(Response::ok("Saved.", Data::Saved { item })) {
                self.set_err(
                    "The login is saved in Apassy, but the browser stopped waiting for the answer.",
                );
            }
            return;
        }
        match filled {
            Some(filled) if !failed => {
                let item = filled.item;
                let origin = filled.origin.clone();
                let created = filled.created;
                let delivered = ticket.send(Response::ok(
                    "Filled.",
                    Data::Fill {
                        item,
                        origin: filled.origin,
                        username: filled.username,
                        password: filled.password,
                    },
                ));
                if !delivered {
                    self.set_err(match created {
                        Some(title) => format!(
                            "The login \"{title}\" is in Apassy, but the browser stopped waiting. Fill it from the Apassy button in the browser."
                        ),
                        None => "The browser stopped waiting. Nothing was filled.".to_owned(),
                    });
                    return;
                }
                let site = origin
                    .split_once("://")
                    .map_or(origin.as_str(), |(_, site)| site)
                    .to_owned();
                match self.owner_ui.session.record_fill(item, &origin) {
                    Ok(()) => self.set_ok(match created {
                        Some(title) => format!(
                            "The new login \"{title}\" is in Apassy and filled in your browser on {site}."
                        ),
                        None => format!("The login is filled in your browser on {site}."),
                    }),
                    Err(err) => self.set_err(format!(
                        "The login is filled in your browser on {site}, but the history did not save it: {}",
                        err.message
                    )),
                }
            }
            _ => {
                ticket.send(Response::error(
                    "refused",
                    if self.status_seq == before {
                        "Apassy did not fill the login.".to_owned()
                    } else {
                        self.status_text.clone()
                    },
                ));
            }
        }
    }

    /// Answer a passkey check. A passkey that the vault made stays in Apassy when the
    /// page did not get it: the status says so.
    fn answer_browser_passkey(
        &mut self,
        mut ticket: BrowserTicket,
        result: Result<PasskeyDone, ModelError>,
    ) {
        let echo = ticket.echo.take();
        let (done, echo) = match (result, echo) {
            (Ok(done), Some(echo)) => (done, echo),
            (Ok(_), None) => {
                ticket.send(Response::error("refused", "Apassy did not sign."));
                return;
            }
            (Err(err), _) => {
                let code = match err.code {
                    "excluded" | "unsupported" => err.code,
                    _ => "refused",
                };
                ticket.send(Response::error(code, err.message));
                return;
            }
        };
        match done {
            PasskeyDone::Signed(assertion) => {
                let delivered = ticket.send(Response::ok(
                    "Signed.",
                    Data::Passkey {
                        rid: echo.rid,
                        credential_id: webauthn::encode_bytes(&assertion.credential_id),
                        user_handle: webauthn::encode_bytes(&assertion.user_handle),
                        authenticator_data: webauthn::encode_bytes(&assertion.authenticator_data),
                        signature: webauthn::encode_bytes(&assertion.signature),
                        client_data_json: echo.client_data_json,
                    },
                ));
                if delivered {
                    self.set_ok("You are signed in with a passkey from Apassy.");
                } else {
                    self.set_err("The browser stopped waiting. The page got no passkey.");
                }
            }
            PasskeyDone::Created(created) => {
                let item = created.item_id;
                let delivered = ticket.send(Response::ok(
                    "Created.",
                    Data::PasskeyCreated {
                        rid: echo.rid,
                        item,
                        credential_id: webauthn::encode_bytes(&created.credential_id),
                        attestation_object: webauthn::encode_bytes(&created.attestation_object),
                        authenticator_data: webauthn::encode_bytes(&created.authenticator_data),
                        public_key_spki: webauthn::encode_bytes(&created.public_key_spki),
                        algorithm: created.algorithm,
                        client_data_json: echo.client_data_json,
                    },
                ));
                if delivered {
                    self.set_ok("The new passkey is saved in Apassy.");
                } else {
                    self.set_err(
                        "The new passkey is saved in Apassy, but the page did not get it. Remove it in Apassy, or sign in and add the passkey again.",
                    );
                }
            }
        }
    }

    /// Answer a code check, and record the fill in the history of the login.
    fn answer_browser_code(&mut self, ticket: BrowserTicket, code: FilledCode) {
        let FilledCode {
            item,
            origin,
            code,
            remaining,
        } = code;
        let delivered = ticket.send(Response::ok(
            "Filled.",
            Data::Code {
                item,
                origin: origin.clone(),
                code,
                remaining,
            },
        ));
        if !delivered {
            self.set_err("The browser stopped waiting. No code was filled.");
            return;
        }
        match self.owner_ui.session.record_fill(item, &origin) {
            Ok(()) => self.set_ok("The one-time code is filled in your browser."),
            Err(err) => self.set_err(format!(
                "The one-time code is filled in your browser, but the history did not save it: {}",
                err.message
            )),
        }
    }

    /// True when no code and no passkey result wait for a ticket.
    #[cfg(test)]
    pub(crate) fn browser_results_are_empty(&self) -> bool {
        self.browser.code.is_none() && self.browser.passkey.is_none()
    }
}
