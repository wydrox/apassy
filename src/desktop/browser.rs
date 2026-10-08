//! The browser socket of the desktop app (ADR 0021).
//!
//! [`super::owner_socket`] hands each request of `browser.sock` to
//! [`DesktopApp::poll_browser`]. `status`, `show`, and `logins` answer at once. `fill`,
//! `save`, and `create` open the same owner check dialog as the views, with a note that
//! the browser asked for it, and answer after the owner confirms or cancels it. Each of
//! them needs its own check. Only the answer of a passed fill or create has a secret
//! value. The password of a save waits in the ticket of the dialog.

use std::path::Path;
use std::sync::mpsc::{Receiver, Sender};
use std::time::{Duration, Instant};

use eframe::egui;

use super::DesktopApp;
use super::owner_check::OwnerRequest;
use super::owner_cli::bring_to_front;
use super::owner_socket::{self, Envelope, LineWire, OwnerSocket, WireEnvelope};
use crate::broker::approvals::OwnerProof;
use crate::browser::site::Page;
use crate::browser::wire::{
    self, Command, Data, LoginRow, Request, Response, VaultState, WireError,
};
use crate::owner::wire::SecretText;

/// A fill dialog closes this long before the socket stops waiting, so the extension
/// gets `cancelled`, and a late check fills nothing. The deadline starts when the UI
/// thread takes the request, a little after the socket starts to wait.
const TICKET_MARGIN: Duration = Duration::from_secs(15);

/// The note in the owner check dialog for a request of the browser.
pub(crate) const BROWSER_ORIGIN_NOTE: &str = "Your browser asked for this (the Apassy extension). If you did not ask for it in your browser just now, click Cancel.";

/// The browser wire on the socket.
pub(crate) struct BrowserWire;

impl LineWire for BrowserWire {
    type Request = Command;
    type Response = Response;
    const NAME: &'static str = "browser";
    const MAX_REQUEST_BYTES: usize = wire::MAX_REQUEST_BYTES;
    const MAX_CONNECTIONS: usize = 4;
    const BUSY: &'static str = "Apassy has too many browser connections.";

    fn parse(line: &[u8]) -> Result<Command, Response> {
        Request::parse(line).map_err(Response::from)
    }

    fn error(code: &'static str, message: &'static str) -> Response {
        Response::error(code, message)
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
    }
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
}

impl BrowserTicket {
    fn new(reply: Sender<Response>) -> Self {
        Self {
            reply: Some(reply),
            deadline: Instant::now() + owner_socket::REPLY_TIMEOUT.saturating_sub(TICKET_MARGIN),
            secret: None,
        }
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
        let Some(inbox) = &self.browser.inbox else {
            return;
        };
        let envelopes: Vec<WireEnvelope<BrowserWire>> = inbox.try_iter().collect();
        for envelope in envelopes {
            self.handle_browser(envelope, ctx);
        }
    }

    /// Answer one request. Tests call this with an envelope of their own.
    pub(crate) fn handle_browser(
        &mut self,
        envelope: WireEnvelope<BrowserWire>,
        ctx: &egui::Context,
    ) {
        let Envelope { request, reply } = envelope;
        self.browser.last_seen = Some(Instant::now());
        let ticket = BrowserTicket::new(reply);
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
        let Some(left) = self
            .owner
            .check
            .as_ref()
            .and_then(|dialog| dialog.browser.as_ref())
            .map(BrowserTicket::left)
        else {
            return;
        };
        if left.is_zero() {
            self.close_owner_check(Some(ctx));
            self.set_err("The browser stopped waiting for the owner check. Nothing was filled.");
        } else {
            ctx.request_repaint_after(left);
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
}
