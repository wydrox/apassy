//! The commands of the owner command line, on the UI thread (ADR 0017).
//!
//! [`super::owner_socket`] hands each request to [`DesktopApp::poll_cli`]. A command
//! uses the same vault session calls as the views. A command that needs an owner
//! check opens the same owner check dialog as the views, with a note that the command
//! line asked for it, and answers after the owner confirms or cancels it.
//!
//! A command-line session starts after the owner check for [`OwnerAction::OpenCliSession`].
//! The app keeps only a SHA-256 digest of each session token. A session ends after
//! [`SESSION_IDLE`] without a request, after [`SESSION_MAX`], at a lock or an unlock
//! (the vault epoch changes), at `apassy logout`, and when the app quits.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::PoisonError;
use std::sync::mpsc::{Receiver, Sender};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use eframe::egui;
use zeroize::Zeroizing;

use super::owner_check::{OwnerRequest, VariableBinding};
use super::owner_socket::{self, Envelope, OwnerSocket};
use super::owner_store::{
    DETAIL_PREFIX, MAX_DETAILS, OwnerDetails, OwnerSummary, RuleForm, SecretForm, detail_field_name,
};
use super::{BrokerState, DesktopApp, OwnerView};
use crate::broker::approvals::{OwnerAction, OwnerProof};
use crate::contracts::CredentialKind;
use crate::desktop::model::{DetailDraft, ItemDraft, ModelError, ModelResult};
use crate::owner::wire::{
    ActivityRow, AgentRow, AgentView, BindingRow, Command, Data, DeclarationInput, DeclarationView,
    DetailView, EventRow, GrantMode, GrantRow, ItemInput, ItemRow, ItemView, OWNER_WIRE_VERSION,
    OperationRow, PatternRow, Request, RequestRow, Response, RuleInput, RuleView, RunRow,
    SecretText, StatusView, VariableInput, VariableView, VaultState,
};
use crate::vault::{
    AccessRequest, AgentSummary, EnvDelivery, Environment, ExecMode, GrantPlace, PatternState,
    RequestState, Reversibility, RiskLevel, Scope, VaultErrorKind, checked_env_name,
};

/// A session ends after this time without a request.
pub const SESSION_IDLE: Duration = Duration::from_secs(30 * 60);
/// A session ends this long after the owner check, also when it is in use.
pub const SESSION_MAX: Duration = Duration::from_secs(12 * 60 * 60);
/// The first characters of a session token.
pub const SESSION_PREFIX: &str = "apassy_cli_";
/// At most this many sessions at one time. A new session ends the oldest.
const MAX_SESSIONS: usize = 8;
const DEFAULT_LIMIT: u32 = 50;
const MAX_LIMIT: u32 = 1000;
/// At most this many variables in one batch binding (ADR 0017, D1).
const MAX_BIND_VARIABLES: usize = 200;
/// The text for a variable name that the vault does not take.
const INVALID_VARIABLE: &str = "The name is not valid: use A-Z, 0-9, and _, start with a letter or _, and no system name such as PATH.";
const EXPLICIT_SETUP_KEY: &str = "Bind this setup key separately with apassy item env. Select the setup-key field explicitly. Programs can make one-time codes for this account.";

/// The note in the owner check dialog for a request from the command line.
pub(crate) const CLI_ORIGIN_NOTE: &str = "The command line asked for this (apassy). If you did not run an apassy command just now, click Cancel.";

/// The owner socket, the requests that wait, and the open sessions.
#[derive(Default)]
pub(crate) struct CliHost {
    socket: Option<OwnerSocket>,
    inbox: Option<Receiver<Envelope>>,
    /// Why the owner socket did not start.
    pub(crate) problem: Option<String>,
    sessions: Vec<CliSession>,
    /// The token of the session that the last owner check opened, for its ticket.
    issued: Option<SecretText>,
    /// The rows of the last batch binding, for its ticket.
    bound: Option<Vec<BindingRow>>,
}

impl CliHost {
    pub(crate) fn socket_path(&self) -> Option<&std::path::Path> {
        self.socket.as_ref().map(OwnerSocket::socket_path)
    }

    /// Stop the socket and end every session. Waiting requests get "stopped".
    pub(crate) fn stop(&mut self) {
        if let Some(mut socket) = self.socket.take() {
            socket.stop();
        }
        self.inbox = None;
        self.sessions.clear();
        self.issued = None;
        self.bound = None;
    }

    #[cfg(test)]
    pub(crate) fn session_count(&self) -> usize {
        self.sessions.len()
    }
}

struct CliSession {
    digest: [u8; 32],
    epoch: [u8; 32],
    opened: Instant,
    used: Instant,
}

/// The way back to one command-line request. A ticket that drops without an answer
/// tells the client that nothing happened: for example when the owner closes the owner
/// check dialog.
pub(crate) struct CliTicket {
    reply: Option<Sender<Response>>,
    /// What the answer carries after the owner check.
    after: After,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum After {
    Message,
    Session,
    Token {
        agent_id: u64,
    },
    /// A batch binding. `refused` has the variables that the app refused before the
    /// owner check.
    Bindings {
        refused: Vec<BindingRow>,
    },
}

impl CliTicket {
    fn new(reply: Sender<Response>) -> Self {
        Self {
            reply: Some(reply),
            after: After::Message,
        }
    }

    pub(crate) fn send(mut self, response: Response) {
        if let Some(reply) = self.reply.take() {
            let _ = reply.send(response);
        }
    }
}

impl Drop for CliTicket {
    fn drop(&mut self) {
        if let Some(reply) = self.reply.take() {
            let _ = reply.send(Response::error(
                "cancelled",
                "The owner check closed before it passed. Apassy did nothing.",
            ));
        }
    }
}

/// The result of one command on the UI thread.
enum Step {
    Reply(Response),
    /// Ask the owner, then do the request.
    Check(OwnerRequest),
    /// Ask the owner for a batch binding. `refused` goes into the answer.
    Bind {
        request: OwnerRequest,
        refused: Vec<BindingRow>,
    },
}

/// A command that the app refuses. It becomes an error [`Response`].
#[derive(Debug)]
pub(crate) struct Refusal {
    code: &'static str,
    message: String,
}

impl From<ModelError> for Refusal {
    fn from(err: ModelError) -> Self {
        Self {
            code: err.code,
            message: err.message,
        }
    }
}

impl From<Refusal> for Response {
    fn from(refusal: Refusal) -> Self {
        Response::error(refusal.code, refusal.message)
    }
}

fn refuse(code: &'static str, message: impl Into<String>) -> Refusal {
    Refusal {
        code,
        message: message.into(),
    }
}

type Run = Result<Step, Refusal>;

fn invalid(message: impl Into<String>) -> Refusal {
    refuse("invalid_input", message)
}

fn done(message: impl Into<String>) -> Run {
    Ok(Step::Reply(Response::ok(message, Data::None)))
}

fn data(message: impl Into<String>, data: Data) -> Run {
    Ok(Step::Reply(Response::ok(message, data)))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn sha256(text: &str) -> [u8; 32] {
    let digest = ring::digest::digest(&ring::digest::SHA256, text.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Bring the window to the front, also from the Dock or another Space.
pub(crate) fn bring_to_front(ctx: &egui::Context) {
    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
    ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
    ctx.send_viewport_cmd(egui::ViewportCommand::RequestUserAttention(
        egui::UserAttentionType::Informational,
    ));
    ctx.request_repaint();
}

impl DesktopApp {
    /// Start the owner socket. A failure shows in Settings, and the app keeps working.
    pub(crate) fn start_cli(&mut self, socket: &std::path::Path, ctx: &egui::Context) {
        let repaint = ctx.clone();
        match owner_socket::start(socket, move || repaint.request_repaint()) {
            Ok((handle, inbox)) => {
                self.cli.socket = Some(handle);
                self.cli.inbox = Some(inbox);
                self.cli.problem = None;
            }
            Err(err) => {
                self.cli.problem = Some(format!(
                    "The command line socket did not start at {}: {err}",
                    socket.display()
                ));
            }
        }
    }

    /// Answer the requests that wait. The app calls this each frame, also while the
    /// window is hidden ([`eframe::App::logic`]).
    pub(crate) fn poll_cli(&mut self, ctx: &egui::Context) {
        let Some(inbox) = &self.cli.inbox else {
            return;
        };
        let envelopes: Vec<Envelope> = inbox.try_iter().collect();
        for envelope in envelopes {
            self.handle_cli(envelope, ctx);
        }
    }

    /// Answer one request. Tests call this with an envelope of their own.
    pub(crate) fn handle_cli(&mut self, envelope: Envelope, ctx: &egui::Context) {
        let Envelope { request, reply } = envelope;
        let ticket = CliTicket::new(reply);
        let Request {
            v,
            session,
            command,
        } = request;
        if v != OWNER_WIRE_VERSION {
            ticket.send(Response::error(
                "bad_version",
                "This apassy command line does not match the app. Use the apassy program of the same Apassy.app.",
            ));
            return;
        }
        if command.needs_session() && !self.cli_session_valid(session.as_ref()) {
            ticket.send(Response::error(
                "session_required",
                "Start a session first: eval \"$(apassy login)\". A session ends after 30 idle minutes and when the vault locks.",
            ));
            return;
        }
        let step = self
            .cli_command(command, session.as_ref(), ctx)
            .unwrap_or_else(|refusal| Step::Reply(refusal.into()));
        match step {
            Step::Reply(response) => ticket.send(response),
            Step::Check(request) => self.ask_owner_for_cli(request, ticket, ctx),
            Step::Bind { request, refused } => {
                let mut ticket = ticket;
                ticket.after = After::Bindings { refused };
                self.ask_owner_for_cli(request, ticket, ctx);
            }
        }
    }

    /// Open the owner check dialog for a command-line request. One dialog at a time: a
    /// second request gets `busy`, so a program cannot replace a dialog that the owner
    /// reads.
    fn ask_owner_for_cli(
        &mut self,
        request: OwnerRequest,
        mut ticket: CliTicket,
        ctx: &egui::Context,
    ) {
        if self.owner.check.is_some() {
            ticket.send(Response::error(
                "busy",
                "Another owner check is open in Apassy. Finish it, then try again.",
            ));
            return;
        }
        match &request {
            OwnerRequest::OpenCliSession => ticket.after = After::Session,
            OwnerRequest::RotateToken { agent_id, .. } => {
                ticket.after = After::Token {
                    agent_id: *agent_id,
                };
            }
            // A batch binding has its refusals in the ticket already.
            _ => {}
        }
        self.ask_owner(request, Some(ctx));
        if let Some(dialog) = self.owner.check.as_mut() {
            dialog.origin = Some(ticket);
        }
        bring_to_front(ctx);
    }

    /// Answer the command-line request of a finished owner check. `before` is the status
    /// sequence before the action.
    pub(crate) fn answer_cli_ticket(&mut self, mut ticket: CliTicket, before: u64) {
        let failed = self.status_seq != before && self.status_kind == super::StatusKind::Error;
        let message = if self.status_seq == before {
            "Done.".to_owned()
        } else {
            self.status_text.clone()
        };
        let after = std::mem::replace(&mut ticket.after, After::Message);
        // A batch binding answers with a row for each variable, also when no variable
        // could be bound after the check.
        if let After::Bindings { mut refused } = after {
            let response = match self.cli.bound.take() {
                Some(rows) => {
                    refused.extend(rows);
                    Response::ok(message, Data::Bindings { results: refused })
                }
                None => Response::error("refused", message),
            };
            ticket.send(response);
            return;
        }
        if failed {
            ticket.send(Response::error("refused", message));
            return;
        }
        let response = match after {
            After::Message => Response::ok(message, Data::None),
            After::Session => match self.cli.issued.take() {
                Some(token) => Response::ok(
                    message,
                    Data::Session {
                        token,
                        idle_minutes: SESSION_IDLE.as_secs() / 60,
                    },
                ),
                None => Response::error("refused", message),
            },
            After::Token { agent_id } => {
                let fresh = self.owner_ui.fresh_token.take();
                let agent = self.owner_ui.session.agents().ok().and_then(|agents| {
                    agents
                        .into_iter()
                        .find(|agent| agent.id == agent_id)
                        .map(|agent| self.agent_row(agent))
                });
                match (fresh, agent) {
                    (Some(fresh), Some(agent)) => Response::ok(
                        message,
                        Data::Token {
                            agent,
                            token: SecretText::new(fresh.token.expose().to_owned()),
                        },
                    ),
                    _ => Response::error("refused", message),
                }
            }
            After::Bindings { .. } => Response::error("refused", message),
        };
        ticket.send(response);
    }

    /// Open a session after the owner check. The token goes to the ticket.
    pub(crate) fn open_cli_session(&mut self, proof: OwnerProof) {
        let result = self.new_cli_session(&proof);
        drop(proof);
        match result {
            Ok(token) => {
                self.cli.issued = Some(token);
                self.set_ok(
                    "A command-line session is open. It ends after 30 idle minutes, after 12 hours, or when the vault locks.",
                );
            }
            Err(err) => self.set_err(err.message),
        }
    }

    fn new_cli_session(&mut self, proof: &OwnerProof) -> ModelResult<SecretText> {
        let epoch = self.owner_ui.session.epoch().ok_or(ModelError {
            code: "vault_locked",
            message: "The vault is locked. Unlock it first.".to_owned(),
        })?;
        proof
            .check(&OwnerAction::OpenCliSession, &epoch)
            .map_err(|refusal| ModelError {
                code: "owner_check_invalid",
                message: refusal.message().to_owned(),
            })?;
        let mut bytes = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut *bytes).map_err(|_| ModelError {
            code: "io",
            message: "Apassy could not make a random session token.".to_owned(),
        })?;
        let token = SecretText::new(format!("{SESSION_PREFIX}{}", hex(&*bytes)));
        let now = Instant::now();
        self.prune_cli_sessions(now);
        if self.cli.sessions.len() >= MAX_SESSIONS {
            self.cli.sessions.remove(0);
        }
        self.cli.sessions.push(CliSession {
            digest: sha256(token.expose()),
            epoch,
            opened: now,
            used: now,
        });
        Ok(token)
    }

    /// The number of open sessions. Settings shows it.
    pub(crate) fn cli_sessions_open(&mut self) -> usize {
        self.prune_cli_sessions(Instant::now());
        self.cli.sessions.len()
    }

    /// End every command-line session.
    pub(crate) fn end_cli_sessions(&mut self) {
        self.cli.sessions.clear();
    }

    /// Move the times of every session back by `by`, as if the time passed.
    #[cfg(test)]
    pub(crate) fn age_cli_sessions(&mut self, by: Duration) {
        for session in &mut self.cli.sessions {
            session.used = session.used.checked_sub(by).unwrap_or(session.used);
            session.opened = session.opened.checked_sub(by).unwrap_or(session.opened);
        }
    }

    fn prune_cli_sessions(&mut self, now: Instant) {
        let epoch = self.owner_ui.session.epoch();
        self.cli.sessions.retain(|session| {
            Some(session.epoch) == epoch
                && now.saturating_duration_since(session.used) < SESSION_IDLE
                && now.saturating_duration_since(session.opened) < SESSION_MAX
        });
    }

    /// True when `token` names an open session of this vault session. A valid request
    /// keeps the session alive.
    fn cli_session_valid(&mut self, token: Option<&SecretText>) -> bool {
        let Some(token) = token.filter(|token| token.expose().starts_with(SESSION_PREFIX)) else {
            return false;
        };
        let now = Instant::now();
        self.prune_cli_sessions(now);
        let digest = sha256(token.expose());
        match self
            .cli
            .sessions
            .iter_mut()
            .find(|session| digest_eq(&session.digest, &digest))
        {
            Some(session) => {
                session.used = now;
                true
            }
            None => false,
        }
    }

    fn agent_row(&self, agent: AgentSummary) -> AgentRow {
        let sees_all = self
            .owner_ui
            .session
            .agent_sees_all(agent.id)
            .unwrap_or(false);
        AgentRow {
            id: agent.id,
            token_expired: agent.token_expired_at(now_unix()),
            name: agent.name,
            created_at: agent.created_at,
            revoked: agent.revoked,
            token_expires_at: agent.token_expires_at,
            sees_all,
        }
    }

    // ---- Lookups ----

    fn find_item(&self, reference: &str) -> Result<OwnerSummary, Refusal> {
        let items = self.owner_ui.session.search("")?;
        let reference = reference.trim();
        if let Ok(id) = reference.parse::<u64>()
            && let Some(item) = items.iter().find(|item| item.id == id)
        {
            return Ok(item.clone());
        }
        let wanted = reference.to_lowercase();
        let mut found: Vec<OwnerSummary> = items
            .into_iter()
            .filter(|item| item.name.to_lowercase() == wanted)
            .collect();
        match found.len() {
            0 => Err(refuse(
                "not_found",
                format!("No credential has the ID or the name \"{reference}\"."),
            )),
            1 => Ok(found.remove(0)),
            _ => Err(refuse(
                "ambiguous",
                format!(
                    "More than one credential has the name \"{reference}\". Use an ID: {}.",
                    found
                        .iter()
                        .map(|item| item.id.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            )),
        }
    }

    fn find_agent(&self, reference: &str) -> Result<AgentSummary, Refusal> {
        let agents = self.owner_ui.session.agents()?;
        let reference = reference.trim();
        if let Ok(id) = reference.parse::<u64>()
            && let Some(agent) = agents.iter().find(|agent| agent.id == id)
        {
            return Ok(agent.clone());
        }
        let wanted = reference.to_lowercase();
        let named: Vec<&AgentSummary> = agents
            .iter()
            .filter(|agent| agent.name.to_lowercase() == wanted)
            .collect();
        // A revoked agent keeps its name. Prefer the active one.
        let active: Vec<&&AgentSummary> = named.iter().filter(|agent| !agent.revoked).collect();
        match (named.len(), active.len()) {
            (0, _) => Err(refuse(
                "not_found",
                format!("No agent has the ID or the name \"{reference}\"."),
            )),
            (1, _) => Ok(named[0].clone()),
            (_, 1) => Ok((*active[0]).clone()),
            _ => Err(refuse(
                "ambiguous",
                format!(
                    "More than one agent has the name \"{reference}\". Use an ID: {}.",
                    named
                        .iter()
                        .map(|agent| agent.id.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            )),
        }
    }

    fn approval_queue(&self) -> Option<std::sync::Arc<crate::broker::approvals::ApprovalQueue>> {
        match &self.broker {
            BrokerState::Running(handle) => Some(std::sync::Arc::clone(handle.approvals())),
            _ => None,
        }
    }

    /// A write from the command line shows in the app too, so the owner sees it.
    fn cli_wrote(&mut self, message: &str) -> Run {
        self.set_ok(format!("Command line: {message}"));
        done(message)
    }

    // ---- Commands ----

    fn cli_command(
        &mut self,
        command: Command,
        session: Option<&SecretText>,
        ctx: &egui::Context,
    ) -> Run {
        match command {
            Command::Status => self.cli_status(session),
            Command::Login => {
                if self.owner_ui.session.is_locked() {
                    return Err(refuse(
                        "vault_locked",
                        "The vault is locked. Run apassy unlock, unlock it in the window, then run apassy login again.",
                    ));
                }
                Ok(Step::Check(OwnerRequest::OpenCliSession))
            }
            Command::Logout => {
                if let Some(token) = session {
                    let digest = sha256(token.expose());
                    self.cli
                        .sessions
                        .retain(|session| !digest_eq(&session.digest, &digest));
                }
                done("The session is closed.")
            }
            Command::Lock => {
                if !self.owner_ui.session.has_file() || self.owner_ui.session.is_locked() {
                    return done("The vault is already locked.");
                }
                self.lock_vault(Some(ctx));
                self.cli.sessions.clear();
                done("The vault is locked. Every command-line session ended.")
            }
            Command::Show => {
                bring_to_front(ctx);
                if self.owner_ui.session.is_locked() {
                    done("Apassy is in front. Unlock the vault there.")
                } else {
                    done("Apassy is in front.")
                }
            }
            Command::ItemList { query, archived } => self.cli_item_list(&query, archived),
            Command::ItemShow { item } => {
                let id = self.find_item(&item)?.id;
                let view = self.item_view(id)?;
                data(view.name.clone(), Data::Item(Box::new(view)))
            }
            Command::ItemAdd { item } => self.cli_item_add(item),
            Command::ItemEdit {
                item,
                revision,
                changes,
            } => self.cli_item_edit(&item, revision, changes),
            Command::ItemDelete { item, revision } => {
                let found = self.find_item(&item)?;
                let revision = revision.unwrap_or(found.revision);
                self.owner_ui.session.delete(found.id, revision)?;
                if self.selected_item_id.as_deref() == Some(found.id.to_string().as_str()) {
                    // A sheet of the item closes. Its typed secrets and their undo
                    // history are erased (key-memory review F1, F3).
                    super::ui::close_sheet(self, ctx);
                    self.pending_delete = false;
                    self.selected_item_id = None;
                    self.view = OwnerView::Vault;
                }
                self.cli_wrote(&format!("{} is deleted.", found.name))
            }
            Command::ItemArchive { item } => {
                let found = self.find_item(&item)?;
                self.owner_ui.session.archive(found.id)?;
                self.cli_wrote(&format!(
                    "{} is archived. Agents cannot use it.",
                    found.name
                ))
            }
            Command::ItemUnarchive { item } => {
                let found = self.find_item(&item)?;
                if !self.owner_ui.session.is_archived(found.id)? {
                    return done(format!("{} is not archived.", found.name));
                }
                Ok(Step::Check(OwnerRequest::Unarchive {
                    item_id: found.id,
                    name: found.name,
                }))
            }
            Command::ItemHistory { item, limit } => {
                let id = self.find_item(&item)?.id;
                let limit = limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT) as usize;
                let events = self
                    .owner_ui
                    .session
                    .item_events(id, limit)?
                    .into_iter()
                    .map(|event| EventRow {
                        id: event.id,
                        at: event.at,
                        kind: event.kind.as_str().to_owned(),
                        detail: event.detail,
                    })
                    .collect::<Vec<_>>();
                data(format!("{} events", events.len()), Data::Events { events })
            }
            Command::ItemSetVariable {
                item,
                name,
                field,
                hosts,
            } => self.cli_set_variable(&item, &name, field.as_deref(), hosts),
            Command::ItemBindVariables { variables } => self.cli_bind_variables(variables),
            Command::ItemClearVariable { item } => {
                let found = self.find_item(&item)?;
                self.owner_ui.session.clear_env_binding(found.id)?;
                self.cli_wrote(&format!(
                    "{} has no variable now. Its process grants are removed.",
                    found.name
                ))
            }
            Command::ItemSetDeclaration { item, declaration } => {
                self.cli_set_declaration(&item, declaration)
            }
            Command::ItemSetConnector { item, base_url } => {
                let found = self.find_item(&item)?;
                if found.kind != CredentialKind::ApiKey {
                    return Err(invalid("A connector needs an API key item."));
                }
                crate::broker::http::parse_destination(&base_url).map_err(invalid)?;
                Ok(Step::Check(OwnerRequest::SaveConnector {
                    item_id: found.id,
                    base_url: base_url.trim().to_owned(),
                }))
            }
            Command::ItemClearConnector { item } => {
                let found = self.find_item(&item)?;
                self.owner_ui.session.clear_connector(found.id)?;
                self.cli_wrote(&format!(
                    "{} has no connector now. Its operation grants are removed.",
                    found.name
                ))
            }
            Command::ItemConfirmReview { item } => {
                let found = self.find_item(&item)?;
                if !self.owner_ui.session.needs_review(found.id)? {
                    return done(format!("{} does not wait for a review.", found.name));
                }
                Ok(Step::Check(OwnerRequest::ConfirmReview {
                    item_id: found.id,
                }))
            }
            Command::AgentList => {
                let agents = self
                    .owner_ui
                    .session
                    .agents()?
                    .into_iter()
                    .map(|agent| self.agent_row(agent))
                    .collect::<Vec<_>>();
                data(format!("{} agents", agents.len()), Data::Agents { agents })
            }
            Command::AgentShow { agent } => {
                let agent = self.find_agent(&agent)?;
                let view = self.agent_view(agent)?;
                data(view.agent.name.clone(), Data::Agent(Box::new(view)))
            }
            Command::AgentAdd { name } => {
                let (agent, token) = self.owner_ui.session.register_agent(&name)?;
                let token = SecretText::new(token.expose().to_owned());
                let row = self.agent_row(agent);
                self.set_ok(format!(
                    "Command line: {} is registered. The command line got its token.",
                    row.name
                ));
                data(
                    format!(
                        "{} is registered. Save the token now. Apassy does not show it again.",
                        row.name
                    ),
                    Data::Token { agent: row, token },
                )
            }
            Command::AgentRevoke { agent } => {
                let agent = self.find_agent(&agent)?;
                if agent.revoked {
                    return done(format!("{} is already revoked.", agent.name));
                }
                self.owner_ui.session.revoke_agent(agent.id)?;
                self.cli_wrote(&format!(
                    "{} is revoked. Its token does not work.",
                    agent.name
                ))
            }
            Command::AgentRotate { agent } => {
                let agent = self.find_agent(&agent)?;
                if agent.revoked {
                    return Err(invalid(
                        "A revoked agent cannot get a new token. Register the agent again.",
                    ));
                }
                Ok(Step::Check(OwnerRequest::RotateToken {
                    agent_id: agent.id,
                    agent_name: agent.name,
                }))
            }
            Command::AgentSeeAll { agent, on } => {
                let agent = self.find_agent(&agent)?;
                if on {
                    return Ok(Step::Check(OwnerRequest::ShowAllCredentials {
                        agent_id: agent.id,
                        agent_name: agent.name,
                    }));
                }
                self.owner_ui
                    .session
                    .set_agent_sees_all(agent.id, false, None)?;
                self.cli_wrote(&format!(
                    "{} sees only the credentials it can use. Its open requests are denied.",
                    agent.name
                ))
            }
            Command::TokenLifetime { days } => match days {
                None => {
                    let days = self.owner_ui.session.token_lifetime_days()?;
                    data(
                        format!("A token works for {days} days after Apassy issues it."),
                        Data::Lifetime { days },
                    )
                }
                Some(days) => {
                    let text = days.to_string();
                    super::owner_store::parse_lifetime_days(&text)?;
                    Ok(Step::Check(OwnerRequest::SetTokenLifetime { days: text }))
                }
            },
            Command::GrantSet {
                agent,
                items,
                folder,
                mode,
            } => self.cli_grant_set(&agent, &items, folder, mode),
            Command::GrantRemove { agent, item } => {
                let agent = self.find_agent(&agent)?;
                let found = self.find_item(&item)?;
                self.owner_ui
                    .session
                    .remove_exec_grant(agent.id, found.id)?;
                self.cli_wrote(&format!(
                    "{} has no process access to {} now.",
                    agent.name, found.name
                ))
            }
            Command::GrantRule { agent, item, rule } => self.cli_grant_rule(&agent, &item, rule),
            Command::OperationAllow {
                agent,
                item,
                operation,
            } => {
                let agent = self.find_agent(&agent)?;
                let found = self.find_item(&item)?;
                let known = self
                    .owner_ui
                    .session
                    .connectors()?
                    .into_iter()
                    .find(|row| row.item_id == found.id)
                    .ok_or_else(|| {
                        invalid(format!(
                            "{} has no connector. Set one first: apassy item connector.",
                            found.name
                        ))
                    })?;
                if !known.operations.iter().any(|(name, _)| *name == operation) {
                    return Err(invalid(format!(
                        "The connector of {} has the operations {}.",
                        found.name,
                        known
                            .operations
                            .iter()
                            .map(|(name, _)| *name)
                            .collect::<Vec<_>>()
                            .join(", ")
                    )));
                }
                Ok(Step::Check(OwnerRequest::AllowOperation {
                    agent_id: agent.id,
                    item_id: found.id,
                    operation,
                }))
            }
            Command::OperationRemove {
                agent,
                item,
                operation,
            } => {
                let agent = self.find_agent(&agent)?;
                let found = self.find_item(&item)?;
                self.owner_ui
                    .session
                    .remove_operation(agent.id, found.id, &operation)?;
                self.cli_wrote(&format!(
                    "{} cannot use {operation} of {} now.",
                    agent.name, found.name
                ))
            }
            Command::RequestList { all } => {
                let requests = self
                    .owner_ui
                    .session
                    .access_requests(!all)?
                    .into_iter()
                    .map(request_row)
                    .collect::<Vec<_>>();
                data(
                    format!("{} requests", requests.len()),
                    Data::Requests { requests },
                )
            }
            Command::RequestGrant {
                request,
                folder,
                mode,
            } => {
                let open = self
                    .owner_ui
                    .session
                    .access_requests(true)?
                    .into_iter()
                    .find(|row| row.id == request)
                    .ok_or_else(|| refuse("not_found", "The request is not open any more."))?;
                if self.owner_ui.session.env_binding(open.item_id)?.is_none() {
                    return Err(invalid(format!(
                        "{} has no environment variable. Bind one first: apassy item env.",
                        open.item_name
                    )));
                }
                Ok(Step::Check(OwnerRequest::GrantRequest {
                    request_id: open.id,
                    agent_id: open.agent_id,
                    item_id: open.item_id,
                    agent_name: open.agent_name,
                    item_name: open.item_name,
                    place: place(folder)?,
                    mode: exec_mode(mode),
                }))
            }
            Command::RequestDeny { request } => {
                self.owner_ui.session.deny_access_request(request)?;
                self.cli_wrote("The request is denied.")
            }
            Command::RunList => {
                let runs = self
                    .approval_queue()
                    .map(|queue| queue.pending_with_age())
                    .unwrap_or_default()
                    .into_iter()
                    .map(|(run, age)| RunRow {
                        id: run.id,
                        can_remember: run.remember.is_some(),
                        agent: run.agent,
                        command: run.command,
                        cwd: run.cwd,
                        variables: run.env_names,
                        purpose: run.purpose,
                        risk: run.risk,
                        user_request: run.user_request,
                        request_source: run.request_source,
                        waiting_secs: age.as_secs(),
                    })
                    .collect::<Vec<_>>();
                data(format!("{} runs wait", runs.len()), Data::Runs { runs })
            }
            Command::RunApprove { run, remember } => {
                let queue = self
                    .approval_queue()
                    .ok_or_else(|| refuse("broker_stopped", "The broker is not running."))?;
                let waiting = queue
                    .pending()
                    .into_iter()
                    .find(|pending| pending.id == run)
                    .ok_or_else(|| refuse("not_found", "The run no longer waits."))?;
                if remember {
                    if waiting.remember.is_none() {
                        return Err(invalid(
                            "This run cannot teach a pattern. Approve it once without --remember.",
                        ));
                    }
                    Ok(Step::Check(OwnerRequest::ApproveAndRemember(waiting)))
                } else {
                    Ok(Step::Check(OwnerRequest::ApproveRun(waiting)))
                }
            }
            Command::RunDeny { run } => match self.approval_queue() {
                Some(queue) if queue.deny(run) => self.cli_wrote("The run is denied."),
                _ => Err(refuse("not_found", "The run no longer waits.")),
            },
            Command::PatternList => {
                let now = now_unix();
                let patterns = self
                    .owner_ui
                    .session
                    .patterns()?
                    .into_iter()
                    .map(|pattern| PatternRow {
                        state: match pattern.state(now) {
                            PatternState::Active => "active".to_owned(),
                            PatternState::Learning { approvals } => {
                                format!("learning ({approvals} approvals)")
                            }
                            PatternState::Blocked => "blocked".to_owned(),
                            PatternState::Expired => "expired".to_owned(),
                        },
                        id: pattern.id,
                        display: pattern.display,
                        approvals: pattern.approvals,
                        uses: pattern.uses,
                        last_used_at: pattern.last_used_at,
                    })
                    .collect::<Vec<_>>();
                data(
                    format!("{} patterns", patterns.len()),
                    Data::Patterns { patterns },
                )
            }
            Command::PatternRemove { pattern } => {
                self.owner_ui.session.remove_pattern(pattern)?;
                self.cli_wrote("The pattern is removed. Matching runs ask you again.")
            }
            Command::Activity { limit, agent, item } => {
                let limit = limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT) as usize;
                let item = item.map(|item| self.find_item(&item)).transpose()?;
                let rows = match (agent, &item) {
                    (Some(agent), item) => {
                        let agent = self.find_agent(&agent)?;
                        let rows = self.owner_ui.session.agent_activity(agent.id, limit)?;
                        match item {
                            Some(item) => rows
                                .into_iter()
                                .filter(|row| row.item == item.name)
                                .collect(),
                            None => rows,
                        }
                    }
                    (None, Some(item)) => self.owner_ui.session.item_activity(item.id, limit)?,
                    (None, None) => self.owner_ui.session.activity(limit)?,
                };
                let entries = rows
                    .into_iter()
                    .map(|row| ActivityRow {
                        id: row.id,
                        at: row.at,
                        agent: row.agent,
                        item: row.item,
                        operation: row.operation,
                        decision: row.decision.as_str().to_owned(),
                        reason: row.reason,
                    })
                    .collect::<Vec<_>>();
                data(
                    format!("{} entries", entries.len()),
                    Data::Activity { entries },
                )
            }
            Command::DecisionExport => {
                let jsonl = self.owner_ui.session.export_decisions()?;
                data(
                    format!("{} decisions", jsonl.lines().count()),
                    Data::Export { jsonl },
                )
            }
            Command::Backup { path } => {
                let path = std::path::PathBuf::from(path.trim());
                if !path.is_absolute() {
                    return Err(invalid("Use an absolute path for the backup file."));
                }
                let result = self.owner_ui.session.backup(&path);
                // A backup locks the vault, also when it fails. Typed secrets go, as at
                // a lock (key-memory review F1, F3).
                self.end_waiting_runs();
                self.erase_typed_secrets(Some(ctx));
                self.pending_delete = false;
                self.cli.sessions.clear();
                result?;
                self.set_ok("Command line: the backup is written. The vault is locked.");
                done(format!(
                    "The backup is written to {}. The vault is locked, and the session ended.",
                    path.display()
                ))
            }
            Command::ChangePassphrase { current, new } => {
                let result = self.owner_ui.session.change_passphrase(
                    current.expose(),
                    new.expose(),
                    new.expose(),
                );
                drop((current, new));
                self.end_waiting_runs();
                result?;
                // The Touch ID unlock key holds the old passphrase (goal item A3).
                self.after_passphrase_change(ctx);
                self.cli.sessions.clear();
                self.set_ok("Command line: the passphrase is changed.");
                done(
                    "The passphrase is changed. Old backups still need the old passphrase. Start a new session with apassy login.",
                )
            }
            Command::Restore { backup } => {
                let path = std::path::PathBuf::from(backup.trim());
                if !path.is_absolute() || !path.is_file() {
                    return Err(invalid(
                        "Name an existing backup file with an absolute path.",
                    ));
                }
                // An open sheet closes first, and its typed secrets are erased.
                super::ui::close_sheet(self, ctx);
                self.owner_ui.restore_source = path.display().to_string();
                super::ui::open_settings(self, super::ui::SettingsTab::Security);
                self.ui.sheet = Some(super::ui::Sheet::Restore);
                bring_to_front(ctx);
                done(
                    "The restore sheet is open in Apassy. Type the passphrase of the backup there. A restore revokes every agent.",
                )
            }
        }
    }

    fn cli_status(&mut self, session: Option<&SecretText>) -> Run {
        let valid = self.cli_session_valid(session);
        let vault_session = &self.owner_ui.session;
        let vault = if !vault_session.has_file() {
            VaultState::None
        } else if vault_session.is_locked() {
            VaultState::Locked
        } else {
            VaultState::Unlocked
        };
        let (broker, broker_socket) = match &self.broker {
            BrokerState::Running(handle) => (
                "running".to_owned(),
                Some(handle.socket_path().display().to_string()),
            ),
            BrokerState::Failed(message) => (message.clone(), None),
            BrokerState::NotStarted => ("not started".to_owned(), None),
        };
        let counts = valid && vault == VaultState::Unlocked;
        let view = StatusView {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            vault,
            vault_path: vault_session
                .vault_path()
                .map(|path| path.display().to_string()),
            broker,
            broker_socket,
            touch_id: self.owner.touch_id_ready(),
            session: valid,
            waiting_runs: counts.then(|| {
                self.approval_queue()
                    .map_or(0, |queue| queue.pending().len())
            }),
            open_requests: if counts {
                Some(vault_session.access_requests(true)?.len())
            } else {
                None
            },
            items_to_review: if counts {
                Some(vault_session.items_needing_review()?.len())
            } else {
                None
            },
        };
        data("Apassy is running.", Data::Status(view))
    }

    fn cli_item_list(&self, query: &str, with_archived: bool) -> Run {
        let session = &self.owner_ui.session;
        let archived = session.archived()?;
        let variables: BTreeMap<u64, String> = session
            .env_bound_items()?
            .into_iter()
            .map(|(id, _, name)| (id, name))
            .collect();
        let mut items: Vec<ItemRow> = session
            .search(query.trim())?
            .into_iter()
            .filter(|item| with_archived || !archived.contains_key(&item.id))
            .map(|item| ItemRow {
                archived: archived.contains_key(&item.id),
                variable: variables.get(&item.id).cloned(),
                id: item.id,
                name: item.name,
                kind: item.kind,
                service: item.service,
                project: item.project,
                revision: item.revision,
            })
            .collect();
        items.sort_by(|a, b| {
            a.name
                .to_lowercase()
                .cmp(&b.name.to_lowercase())
                .then(a.id.cmp(&b.id))
        });
        data(
            format!("{} credentials", items.len()),
            Data::Items { items },
        )
    }

    fn item_view(&self, id: u64) -> Result<ItemView, Refusal> {
        let session = &self.owner_ui.session;
        let details: OwnerDetails = session.details(id)?;
        if details.hidden {
            return Err(refuse("vault_locked", details.message));
        }
        let variable = session.env_binding(id)?.map(|binding| VariableView {
            name: binding.env_name,
            field: binding.field,
            placeholder_hosts: match binding.delivery {
                EnvDelivery::Value => Vec::new(),
                EnvDelivery::Placeholder(hosts) => hosts,
            },
        });
        let form = session.declaration_form(id)?;
        let times = session.item_times()?.remove(&id);
        let secret_fields = session
            .secret_fields(id)?
            .into_iter()
            .filter(|name| !name.starts_with(DETAIL_PREFIX))
            .collect();
        Ok(ItemView {
            id,
            name: details.name,
            kind: details.kind,
            service: details.service,
            project: details.project,
            notes: details.notes,
            username: details.username,
            host: details.host,
            database: details.database_name,
            field_name: details.field_name,
            public_key: details.public_label,
            revision: details.revision,
            archived: details.archived,
            secret_fields,
            details: details
                .details
                .into_iter()
                .map(|detail| DetailView {
                    label: detail.label,
                    value: detail.value,
                    hidden: detail.hidden,
                })
                .collect(),
            variable,
            declaration: DeclarationView {
                project: form.project.clone(),
                environment: form.environment.as_str().to_owned(),
                risk: form.risk.as_str().to_owned(),
                scope: form.scope.as_str().to_owned(),
                reversibility: form.reversibility.as_str().to_owned(),
                provider: form.provider.clone(),
                suggested: !form.stored,
            },
            connector: session
                .connector(id)?
                .map(|destination| destination.base_url),
            needs_review: session.needs_review(id)?,
            added: times.as_ref().and_then(|times| times.added),
            changed: times.as_ref().and_then(|times| times.changed),
            used: times.and_then(|times| times.used),
        })
    }

    fn cli_item_add(&mut self, input: ItemInput) -> Run {
        let kind = input.kind.ok_or_else(|| {
            invalid("Name the kind: api_key, login, ssh_key, database, or custom.")
        })?;
        let mut draft = ItemDraft {
            kind,
            ..ItemDraft::default()
        };
        let mut secrets = SecretForm::default();
        apply_input(&mut draft, &mut secrets, input)?;
        let summary = self.owner_ui.session.add(&draft, &secrets)?;
        drop(secrets);
        let row = ItemRow {
            id: summary.id,
            name: summary.name.clone(),
            kind: summary.kind,
            service: summary.service,
            project: summary.project,
            revision: summary.revision,
            archived: false,
            variable: None,
        };
        self.set_ok(format!("Command line: {} is added.", summary.name));
        data(
            format!("{} is added with ID {}.", summary.name, summary.id),
            Data::Items { items: vec![row] },
        )
    }

    fn cli_item_edit(&mut self, item: &str, revision: Option<u64>, changes: ItemInput) -> Run {
        let found = self.find_item(item)?;
        let details = self.owner_ui.session.details(found.id)?;
        if details.hidden {
            return Err(refuse("vault_locked", details.message));
        }
        let revision = revision.unwrap_or(details.revision);
        let mut draft = details.to_draft();
        let mut secrets = SecretForm::default();
        apply_input(&mut draft, &mut secrets, changes)?;
        if self
            .owner_ui
            .session
            .is_unchanged(found.id, &draft, &secrets)?
        {
            return done(format!("{} is unchanged.", found.name));
        }
        let summary = self
            .owner_ui
            .session
            .update(found.id, revision, &draft, &secrets)?;
        drop(secrets);
        // The page of the item shows the new revision. An open sheet stays: the owner
        // may be typing there, and its save then reports the conflict.
        if self.selected_item_id.as_deref() == Some(found.id.to_string().as_str())
            && self.ui.sheet.is_none()
        {
            let id = found.id.to_string();
            self.select_item(id);
        }
        self.cli_wrote(&format!(
            "{} is saved (revision {}).",
            summary.name, summary.revision
        ))
    }

    fn cli_set_variable(
        &mut self,
        item: &str,
        name: &str,
        field: Option<&str>,
        hosts: Vec<String>,
    ) -> Run {
        let found = self.find_item(item)?;
        let env_name = name.trim().to_owned();
        checked_env_name(&env_name).map_err(|_| {
            invalid(
                "Use A-Z, 0-9, and _ for the variable, and start with a letter or _. System names such as PATH or DYLD_* are not permitted.",
            )
        })?;
        let fields = self.owner_ui.session.secret_fields(found.id)?;
        let field = match field.map(str::trim).filter(|field| !field.is_empty()) {
            None => fields
                .iter()
                .find(|name| !name.starts_with(DETAIL_PREFIX))
                .or_else(|| fields.first())
                .cloned()
                .ok_or_else(|| invalid("This credential has no secret field."))?,
            Some(wanted) => {
                let as_detail = detail_field_name(wanted);
                fields
                    .iter()
                    .find(|name| name.as_str() == wanted || **name == as_detail)
                    .cloned()
                    .ok_or_else(|| {
                        invalid(format!(
                            "{} has no secret field \"{wanted}\". Its secret fields: {}.",
                            found.name,
                            fields
                                .iter()
                                .map(|name| super::owner_store::field_label(name))
                                .collect::<Vec<_>>()
                                .join(", ")
                        ))
                    })?
            }
        };
        let delivery = if hosts.is_empty() {
            EnvDelivery::Value
        } else {
            EnvDelivery::Placeholder(
                hosts
                    .into_iter()
                    .map(|host| host.trim().to_lowercase())
                    .filter(|host| !host.is_empty())
                    .collect(),
            )
        };
        Ok(Step::Check(OwnerRequest::SaveVariable {
            item_id: found.id,
            env_name,
            field,
            delivery,
        }))
    }

    /// Check each variable of a batch binding before the owner check (ADR 0017, D1). A
    /// refused variable gets a row with the reason. The dialog lists the others.
    fn cli_bind_variables(&mut self, variables: Vec<VariableInput>) -> Run {
        if variables.is_empty() {
            return Err(invalid("Name at least one variable."));
        }
        if variables.len() > MAX_BIND_VARIABLES {
            return Err(invalid(format!(
                "Bind at most {MAX_BIND_VARIABLES} variables at one time."
            )));
        }
        let session = &self.owner_ui.session;
        let names: BTreeMap<u64, String> = session
            .search("")?
            .into_iter()
            .map(|item| (item.id, item.name))
            .collect();
        let mut by_item = BTreeMap::new();
        let mut by_name = BTreeMap::new();
        for (item_id, item_name, env_name) in session.env_bound_items()? {
            by_item.insert(item_id, env_name.clone());
            by_name.insert(env_name, item_name);
        }
        let mut refused = Vec::new();
        let mut accepted: Vec<VariableBinding> = Vec::new();
        for VariableInput { item_id, name } in variables {
            let env_name = name.trim().to_owned();
            let reason = if !names.contains_key(&item_id) {
                Some(format!("No credential has the ID {item_id}."))
            } else if checked_env_name(&env_name).is_err() {
                Some(INVALID_VARIABLE.to_owned())
            } else if let Some(current) = by_item.get(&item_id) {
                Some(format!(
                    "The credential has the variable {current}. Change it with apassy item env."
                ))
            } else if let Some(other) = by_name.get(&env_name) {
                Some(format!("{other} uses this variable."))
            } else if accepted.iter().any(|binding| binding.item_id == item_id) {
                Some("The credential is named twice.".to_owned())
            } else if accepted.iter().any(|binding| binding.env_name == env_name) {
                Some("Another credential of this request has this variable.".to_owned())
            } else {
                None
            };
            if let Some(reason) = reason {
                refused.push(BindingRow {
                    item_id,
                    name: env_name,
                    bound: false,
                    reason,
                });
                continue;
            }
            // An empty secret is never stored, so an item without its main secret
            // field has no value to bind.
            let field = session
                .secret_fields(item_id)?
                .into_iter()
                .find(|field| !field.starts_with(DETAIL_PREFIX));
            let Some(field) = field else {
                refused.push(BindingRow {
                    item_id,
                    name: env_name,
                    bound: false,
                    reason: "The credential has no secret value.".to_owned(),
                });
                continue;
            };
            if session.holds_setup_key(item_id, &field)? {
                refused.push(BindingRow {
                    item_id,
                    name: env_name,
                    bound: false,
                    reason: EXPLICIT_SETUP_KEY.to_owned(),
                });
                continue;
            }
            accepted.push(VariableBinding {
                item_id,
                item_name: names[&item_id].clone(),
                env_name,
                field,
            });
        }
        if accepted.is_empty() {
            return data(
                "No variable can be bound. Apassy did nothing.",
                Data::Bindings { results: refused },
            );
        }
        Ok(Step::Bind {
            request: OwnerRequest::BindVariables {
                variables: accepted,
            },
            refused,
        })
    }

    /// Bind the variables of a passed batch check (ADR 0017, D1). The proof is checked
    /// once, with the vault mutex held, for exactly the variables of the dialog. Then
    /// each variable binds on its own, and the answer has a row for each.
    pub(crate) fn bind_variables(&mut self, variables: Vec<VariableBinding>, proof: OwnerProof) {
        let action = OwnerAction::BindVariables {
            variables: variables
                .iter()
                .map(|binding| (binding.item_id, binding.env_name.clone()))
                .collect(),
        };
        self.cli.bound = None;
        let shared = self.owner_ui.session.shared_vault();
        let result = {
            let mut slot = shared.lock().unwrap_or_else(PoisonError::into_inner);
            match slot.as_mut() {
                Some(vault) if !vault.is_locked() => match proof.check(&action, &vault.epoch()) {
                    Ok(()) => Ok(variables
                        .into_iter()
                        .map(|binding| {
                            // A sync or another owner action can change the value
                            // while the batch dialog is open. A setup key always
                            // needs its own field-specific owner check.
                            let setup_key = vault
                                .reveal(binding.item_id, &binding.field)
                                .is_ok_and(|value| {
                                    crate::vault::is_setup_key_field(&binding.field, value.expose())
                                });
                            let result = if setup_key {
                                Err(crate::vault::VaultError::new(VaultErrorKind::InvalidInput))
                            } else {
                                vault.set_env_binding_with(
                                    binding.item_id,
                                    &binding.env_name,
                                    &binding.field,
                                    &EnvDelivery::Value,
                                )
                            };
                            BindingRow {
                                item_id: binding.item_id,
                                name: binding.env_name,
                                bound: result.is_ok(),
                                reason: match result {
                                    Ok(()) => String::new(),
                                    Err(err) => match err.kind() {
                                        VaultErrorKind::AlreadyExists => {
                                            "Another credential uses this variable now.".to_owned()
                                        }
                                        VaultErrorKind::NotFound => {
                                            "The credential or its secret is gone.".to_owned()
                                        }
                                        VaultErrorKind::InvalidInput if setup_key => {
                                            EXPLICIT_SETUP_KEY.to_owned()
                                        }
                                        VaultErrorKind::InvalidInput => INVALID_VARIABLE.to_owned(),
                                        _ => format!("The vault did not save it ({err})."),
                                    },
                                },
                            }
                        })
                        .collect::<Vec<_>>()),
                    Err(refusal) => Err(refusal.message().to_owned()),
                },
                _ => Err("The vault is locked. No variable is bound.".to_owned()),
            }
        };
        drop(proof);
        match result {
            Ok(rows) => {
                let bound = rows.iter().filter(|row| row.bound).count();
                let message = match (bound, rows.len()) {
                    (1, 1) => "Command line: 1 variable is bound.".to_owned(),
                    (bound, total) if bound == total => {
                        format!("Command line: {bound} variables are bound.")
                    }
                    (bound, total) => {
                        format!("Command line: {bound} of {total} variables are bound.")
                    }
                };
                if bound == 0 {
                    self.set_err(message);
                } else {
                    self.set_ok(message);
                }
                self.cli.bound = Some(rows);
            }
            Err(message) => self.set_err(message),
        }
    }

    fn cli_set_declaration(&mut self, item: &str, input: DeclarationInput) -> Run {
        let found = self.find_item(item)?;
        let mut form = self.owner_ui.session.declaration_form(found.id)?;
        if let Some(project) = input.project {
            form.project = project;
        }
        if let Some(text) = input.environment {
            form.environment = Environment::parse(text.trim()).map_err(|_| {
                invalid("The environment is local, development, staging, or production.")
            })?;
        }
        if let Some(text) = input.risk {
            form.risk = RiskLevel::parse(text.trim())
                .map_err(|_| invalid("The risk is low, medium, or high."))?;
        }
        if let Some(text) = input.scope {
            form.scope = Scope::parse(text.trim())
                .map_err(|_| invalid("The scope is read-only, read-write, or admin."))?;
        }
        if let Some(text) = input.reversibility {
            form.reversibility = Reversibility::parse(text.trim()).map_err(|_| {
                invalid("The reversibility is reversible, partial, or irreversible.")
            })?;
        }
        if let Some(provider) = input.provider {
            let provider = provider.trim();
            form.provider = if provider.is_empty() {
                None
            } else if crate::vault::providers::find(provider).is_some() {
                Some(provider.to_owned())
            } else {
                return Err(invalid(format!(
                    "The provider \"{provider}\" is not known."
                )));
            };
        }
        if form.project.trim().is_empty() {
            return Err(invalid("Name the project: --project NAME."));
        }
        Ok(Step::Check(OwnerRequest::SaveDeclaration {
            item_id: found.id,
            form,
        }))
    }

    fn cli_grant_set(
        &mut self,
        agent: &str,
        items: &[String],
        folder: Option<String>,
        mode: GrantMode,
    ) -> Run {
        let agent = self.find_agent(agent)?;
        if agent.revoked {
            return Err(invalid("The agent is revoked. Register it again."));
        }
        if items.is_empty() {
            return Err(invalid("Name at least one credential."));
        }
        let mut ids = Vec::new();
        let mut seen = BTreeSet::new();
        for item in items {
            let found = self.find_item(item)?;
            if self.owner_ui.session.env_binding(found.id)?.is_none() {
                return Err(invalid(format!(
                    "{} has no environment variable. Bind one first: apassy item env \"{}\" NAME.",
                    found.name, found.name
                )));
            }
            if seen.insert(found.id) {
                ids.push(found.id);
            }
        }
        let place = place(folder)?;
        let mode = exec_mode(mode);
        if let [item_id] = ids[..] {
            return Ok(Step::Check(OwnerRequest::SetProcessAccess {
                agent_id: agent.id,
                item_id,
                place,
                mode,
            }));
        }
        Ok(Step::Check(OwnerRequest::GrantMany {
            agent_id: agent.id,
            item_ids: ids,
            place,
            mode,
        }))
    }

    fn cli_grant_rule(&mut self, agent: &str, item: &str, rule: RuleInput) -> Run {
        let agent = self.find_agent(agent)?;
        let found = self.find_item(item)?;
        let has_grant = self
            .owner_ui
            .session
            .exec_grants(agent.id)?
            .iter()
            .any(|grant| grant.item_id == found.id);
        if !has_grant {
            return Err(invalid(format!(
                "{} has no process access to {}. Give it first: apassy grant set.",
                agent.name, found.name
            )));
        }
        let form = RuleForm {
            prefixes: rule.allow.join("\n"),
            forbidden: rule.forbid.join("\n"),
            expires_hours: rule
                .expires_hours
                .map(|hours| hours.to_string())
                .unwrap_or_default(),
            max_runs: rule
                .max_runs_per_hour
                .map(|runs| runs.to_string())
                .unwrap_or_default(),
            instruction: rule.instruction,
        };
        let rule = form.to_rule(now_unix()).map_err(invalid)?;
        Ok(Step::Check(OwnerRequest::SaveRule {
            agent_id: agent.id,
            item_id: found.id,
            rule,
        }))
    }

    fn agent_view(&self, agent: AgentSummary) -> Result<AgentView, Refusal> {
        let session = &self.owner_ui.session;
        let names: BTreeMap<u64, String> = session
            .search("")?
            .into_iter()
            .map(|item| (item.id, item.name))
            .collect();
        let name_of = |id: u64| {
            names
                .get(&id)
                .cloned()
                .unwrap_or_else(|| format!("Item {id}"))
        };
        let grants = session
            .exec_grants(agent.id)?
            .into_iter()
            .map(|grant| GrantRow {
                item_name: name_of(grant.item_id),
                item_id: grant.item_id,
                folder: grant.place.folder().map(str::to_owned),
                mode: match grant.mode {
                    ExecMode::Ask => GrantMode::Ask,
                    ExecMode::Bouncer => GrantMode::Bouncer,
                },
                rule: RuleView {
                    allow: grant.rule.allowed_prefixes,
                    forbid: grant.rule.forbidden_words,
                    expires_at: grant.rule.expires_at,
                    max_runs_per_hour: grant.rule.max_runs_per_hour,
                    instruction: grant.rule.instruction,
                },
            })
            .collect();
        let operations = session
            .grants(agent.id)?
            .into_iter()
            .map(|(item_id, operation)| OperationRow {
                item_name: name_of(item_id),
                item_id,
                operation,
            })
            .collect();
        let requests = session
            .access_requests(false)?
            .into_iter()
            .filter(|request| request.agent_id == agent.id)
            .map(request_row)
            .collect();
        Ok(AgentView {
            agent: self.agent_row(agent),
            grants,
            operations,
            requests,
        })
    }
}

/// Constant-time comparison of two digests.
fn digest_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn request_row(request: AccessRequest) -> RequestRow {
    RequestRow {
        id: request.id,
        agent_id: request.agent_id,
        agent_name: request.agent_name,
        item_id: request.item_id,
        item_name: request.item_name,
        reason: request.reason,
        cwd: request.cwd,
        created_at: request.created_at,
        state: match request.state {
            RequestState::Open => "open",
            RequestState::Granted => "granted",
            RequestState::Denied => "denied",
        }
        .to_owned(),
    }
}

/// The place of a grant. The check runs before the owner check, so the dialog shows the
/// canonical folder.
fn place(folder: Option<String>) -> Result<GrantPlace, Refusal> {
    match folder.map(|folder| folder.trim().to_owned()) {
        None => Ok(GrantPlace::AnyFolder),
        Some(folder) if folder.is_empty() => Ok(GrantPlace::AnyFolder),
        Some(folder) => {
            if !std::path::Path::new(&folder).is_absolute() {
                return Err(invalid("Use an absolute path for the project folder."));
            }
            Ok(super::owner_store::checked_place(&GrantPlace::Folder(
                folder,
            ))?)
        }
    }
}

fn exec_mode(mode: GrantMode) -> ExecMode {
    match mode {
        GrantMode::Ask => ExecMode::Ask,
        GrantMode::Bouncer => ExecMode::Bouncer,
    }
}

/// Copy `value` into `slot`. The slot keeps the only copy in the app.
fn put_secret(slot: &mut String, value: &SecretText) {
    use zeroize::Zeroize;
    slot.zeroize();
    slot.push_str(value.expose());
}

/// Apply the input to a draft and a secret form. The form starts blank, so a secret
/// that the input does not name keeps its stored value.
fn apply_input(
    draft: &mut ItemDraft,
    secrets: &mut SecretForm,
    input: ItemInput,
) -> Result<(), Refusal> {
    let ItemInput {
        name,
        kind,
        service,
        project,
        notes,
        username,
        host,
        database,
        field_name,
        public_key,
        secret,
        key_passphrase,
        details,
        remove_details,
    } = input;
    if let Some(kind) = kind
        && kind != draft.kind
    {
        return Err(refuse(
            "category_locked",
            "The item category cannot change. Delete the item and add a new one.",
        ));
    }
    let plain = [
        (name, &mut draft.name),
        (service, &mut draft.service),
        (project, &mut draft.project),
        (notes, &mut draft.notes),
        (username, &mut draft.username),
        (host, &mut draft.host),
        (database, &mut draft.database_name),
        (field_name, &mut draft.field_name),
        (public_key, &mut draft.public_label),
    ];
    for (value, slot) in plain {
        if let Some(value) = value {
            *slot = value;
        }
    }
    for label in &remove_details {
        let label = label.trim().to_lowercase();
        let Some(index) = draft
            .details
            .iter()
            .position(|detail| detail.label.trim().to_lowercase() == label)
        else {
            return Err(invalid(format!(
                "The credential has no detail \"{label}\"."
            )));
        };
        draft.details.remove(index);
        secrets.remove_detail(index);
    }
    for detail in details {
        let wanted = detail.label.trim().to_lowercase();
        let index = match draft
            .details
            .iter()
            .position(|existing| existing.label.trim().to_lowercase() == wanted)
        {
            Some(index) => index,
            None => {
                if draft.details.len() >= MAX_DETAILS {
                    return Err(invalid(format!(
                        "A credential can have at most {MAX_DETAILS} custom details."
                    )));
                }
                draft.details.push(DetailDraft::default());
                draft.details.len() - 1
            }
        };
        let slot = &mut draft.details[index];
        slot.label = detail.label.trim().to_owned();
        slot.hidden = detail.hidden;
        if detail.hidden {
            slot.value.clear();
            put_secret(&mut secrets.details[index], &detail.value);
        } else {
            slot.stored = None;
            slot.value = detail.value.expose().to_owned();
        }
    }
    if let Some(secret) = secret {
        let slot = match draft.kind {
            CredentialKind::ApiKey => &mut secrets.token,
            CredentialKind::Login | CredentialKind::Database => &mut secrets.password,
            CredentialKind::SshKey => &mut secrets.private_key,
            CredentialKind::Custom => &mut secrets.custom_value,
        };
        put_secret(slot, &secret);
    }
    if let Some(passphrase) = key_passphrase {
        if draft.kind != CredentialKind::SshKey {
            return Err(invalid("Only an SSH key has a key passphrase."));
        }
        put_secret(&mut secrets.key_passphrase, &passphrase);
    }
    Ok(())
}
