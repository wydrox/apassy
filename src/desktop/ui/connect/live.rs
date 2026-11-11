//! The vault build of Settings > Connect: the account of this device (`crate::connect`)
//! on worker threads, the polling of the checkout and of the device links, and the owner
//! checks.
//!
//! - **One account session for the app** ([`AccountSession`], plan s7 unit M5b): the
//!   section, the sync of the vault stores ([`Live::sync_account`] and the sync worker),
//!   and the node's tunnel (`crate::node::tunnel::AccountAuth`) use the same account,
//!   key, and token. [`step`] runs at every frame of the app (also while Settings is not
//!   shown): it lets the session follow the vault session, so the session opens with the
//!   unlock (one read of the key store, on a worker; none after a Touch ID unlock, which
//!   read the key with the vault's own key) and closes at a lock, a quit, and a new vault
//!   session. After it opened, the section asks Connect for the account once ("Asking
//!   Apassy Connect…"), again every [`REFRESH_EVERY`], and after [`RETRY_UNREACHABLE`]
//!   when Connect could not be reached ("Connect unreachable"). Neither blocks the unlock
//!   or the vault.
//! - One step at a time runs on a worker ([`Task`]); the UI thread never waits on the
//!   network and never holds the account lock.
//! - The account file is read on the UI thread (a small file, no secret).
//! - A step that needs the owner check asks for it with an [`OwnerRequest`]; the owner
//!   flows keep the proof until [`OwnerFlows::take_connect_proof`] takes it here, once,
//!   and the account checks it again against the exact action before it calls Connect.
//! - When Connect says this device was removed (`403 device_removed`), or its key cannot
//!   be read any more, the session is removed for every part, the section shows it, and
//!   nothing is deleted: only "Forget This Mac…" and its confirmation delete the key,
//!   the account file, and the account rows of the open vault.
//!
//! [`OwnerFlows::take_connect_proof`]: crate::desktop::owner_check::OwnerFlows::take_connect_proof

use std::cell::OnceCell;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use eframe::egui;
use zeroize::Zeroizing;

use super::{
    Account, Action, ConnectView, DELETED, Device, FORGOT, Group, JOIN_POLL_EVERY, LEFT, Member,
    Offer, POLL_EVERY, Plan, Plans, Price, REMOVED_NOTE, Sheet, SheetChoice, Shown, WAIT_AT_MOST,
};
use crate::broker::approvals::{ConnectGroupChange, OwnerProof};
use crate::connect::{
    AccountSession, AccountSigner, AccountState, AccountView, CheckoutRequest, ConnectAccount,
    ConnectClient, ConnectError, DeviceKeyStore, DeviceLink, Follow, Forgotten, GroupDetail,
    JoinPoll, JoinRequest, OpenTicket, PendingJoin, PlansView, SessionState, drop_account_rows,
    forget_this_device,
};
use crate::desktop::DesktopApp;
use crate::desktop::owner_check::{OwnerRequest, Task, TaskPoll};
use crate::sync::StorePlan;

type Slot<T> = Arc<Mutex<Option<T>>>;

fn slot<T>() -> Slot<T> {
    Arc::new(Mutex::new(None))
}

/// The account is asked again this long after the last answer, so the plan state and
/// the device list of the sync stay fresh while Settings is closed.
pub(crate) const REFRESH_EVERY: Duration = Duration::from_secs(30 * 60);
/// A refresh that could not reach Connect is tried again after this long.
pub(crate) const RETRY_UNREACHABLE: Duration = Duration::from_secs(60);
/// A sync of a vault store that was refused asks for the account again after at least
/// this long since the last answer ([`Live::refresh_soon`]).
pub(crate) const REFRESH_SOON_AFTER: Duration = Duration::from_secs(60);

/// A step that waits for the proof of its owner check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Guarded {
    Confirm {
        join_id: u64,
    },
    Revoke {
        device_id: String,
    },
    Delete,
    /// "Forget the Account on This Mac…" of an account file of an earlier version.
    ForgetOld,
    Group {
        group_id: String,
        change: ConnectGroupChange,
    },
}

/// What Connect said at the last refresh.
#[derive(Debug, Clone)]
struct Snapshot {
    view: AccountView,
    group: Option<GroupDetail>,
    /// Which keys may sign the heads of a vault store: from the trust store of the account
    /// after this view (`crate::connect::signer_policy`), never from the view itself.
    signers: crate::sync::SignerPolicy,
}

/// The result of one worker step.
#[allow(clippy::large_enum_variant)] // One message at a time on the channel; a box buys nothing.
enum Outcome {
    Created(Result<(AccountState, Zeroizing<String>), ConnectError>),
    Refreshed(Result<(Snapshot, Option<PlansView>), ConnectError>),
    Plans(Result<PlansView, ConnectError>),
    Checkout(Result<(String, String), ConnectError>),
    Polled(Result<AccountView, ConnectError>),
    Portal(Result<String, ConnectError>),
    Linked(Result<(Zeroizing<String>, u64), ConnectError>),
    Pending(Result<Vec<PendingJoin>, ConnectError>),
    Confirmed(Result<String, ConnectError>),
    Refused(Result<(), ConnectError>),
    /// A revoke: `Some` when this device revoked itself.
    Revoked(Result<Option<Forgotten>, ConnectError>),
    Deleted(Result<Forgotten, ConnectError>),
    Invited(Result<(String, u64), ConnectError>),
    JoinedGroup(Result<String, ConnectError>),
    GroupChanged(Result<String, ConnectError>),
    JoinStarted(Result<(String, String), ConnectError>),
    /// A poll of this device's join: `None` waits, `Some(state)` is confirmed.
    JoinPolled(Result<Option<AccountState>, ConnectError>),
    JoinCancelled,
    /// A step that needed the account of the session and found none (signed out,
    /// removed, or a lock came first).
    Failed(ConnectError),
    /// "Forget This Mac…" after a removal, confirmed by the owner.
    Forgot(Result<Forgotten, ConnectError>),
}

impl Outcome {
    /// The error of the step, for the session ([`AccountSession::with_account`]).
    fn error(&self) -> Option<&ConnectError> {
        match self {
            Self::Created(Err(error))
            | Self::Refreshed(Err(error))
            | Self::Plans(Err(error))
            | Self::Checkout(Err(error))
            | Self::Polled(Err(error))
            | Self::Portal(Err(error))
            | Self::Linked(Err(error))
            | Self::Pending(Err(error))
            | Self::Confirmed(Err(error))
            | Self::Refused(Err(error))
            | Self::Revoked(Err(error))
            | Self::Deleted(Err(error))
            | Self::Invited(Err(error))
            | Self::JoinedGroup(Err(error))
            | Self::GroupChanged(Err(error))
            | Self::JoinStarted(Err(error))
            | Self::JoinPolled(Err(error))
            | Self::Failed(error)
            | Self::Forgot(Err(error)) => Some(error),
            _ => None,
        }
    }
}

/// The checkout that the waiting sheet follows.
#[derive(Debug, Clone)]
struct Waiting {
    started: Instant,
    polled: Option<Instant>,
}

/// What the sync of a vault store needs of the account (plan s7 unit M3).
#[derive(Clone)]
pub(crate) struct SyncAccount {
    /// The account of the session; a worker of the sync locks it for its Connect calls.
    pub(crate) account: Slot<ConnectAccount>,
    /// The Connect origin of the account.
    pub(crate) origin: String,
    /// The plan state of the last refresh; `None` before Connect answered once.
    pub(crate) plan: Option<StorePlan>,
    /// The account key of the session.
    pub(crate) signer: Option<Arc<AccountSigner>>,
    /// Which keys may sign the heads of a vault store (connect-account-v1 section 7.5,
    /// `crate::connect::signer_policy`): of the last refresh, else of the account file.
    pub(crate) signers: crate::sync::SignerPolicy,
}

/// The vault build's part of the section state.
#[derive(Default)]
pub(crate) struct Live {
    /// The one account session of the app (plan s7 unit M5b).
    session: Arc<AccountSession>,
    /// The read of the key for this vault session, on its worker.
    opening: Option<Task<SessionState>>,
    /// The account file, read once (again after a change).
    file: OnceCell<Option<AccountState>>,
    snapshot: Option<Snapshot>,
    plans: Option<Plans>,
    task: Option<Task<Outcome>>,
    error: Option<String>,
    /// The vault session that the section state belongs to.
    epoch: Option<Option<[u8; 32]>>,
    pub(crate) guarded: Option<Guarded>,
    waiting: Option<Waiting>,
    link: Slot<DeviceLink>,
    pending: Vec<PendingJoin>,
    pending_at: Option<Instant>,
    join: Slot<JoinRequest>,
    join_at: Option<Instant>,
    /// When the account was last asked; `None`: ask at the next frame.
    refreshed_at: Option<Instant>,
    /// The last refresh could not reach Connect, and when.
    unreachable: Option<(ConnectError, Instant)>,
    /// Tests: the Connect origin of a creation or a join.
    pub(crate) origin: Option<String>,
    /// Tests: shorter polls than [`POLL_EVERY`] and [`JOIN_POLL_EVERY`].
    pub(crate) poll_every: Option<Duration>,
    pub(crate) join_poll_every: Option<Duration>,
}

impl Live {
    /// The one account session of the app.
    pub(crate) fn session(&self) -> Arc<AccountSession> {
        Arc::clone(&self.session)
    }

    /// Use `store` and the data directory `dir` for the account (the window: the key
    /// store of this platform; a test: a store in memory and a temporary directory). The
    /// session closes first; the next frame opens it for an unlocked vault.
    pub(crate) fn configure(
        &mut self,
        store: Option<Arc<dyn DeviceKeyStore>>,
        dir: Option<PathBuf>,
    ) {
        self.session.configure(store, dir);
        self.reset();
        self.epoch = None;
    }

    fn path(&self) -> Option<PathBuf> {
        self.session.path()
    }

    fn store(&self) -> Option<Arc<dyn DeviceKeyStore>> {
        self.session.store()
    }

    fn file(&self) -> Option<&AccountState> {
        self.file
            .get_or_init(|| self.session.account_state())
            .as_ref()
    }

    fn client(&self) -> Result<ConnectClient, ConnectError> {
        match &self.origin {
            Some(origin) => ConnectClient::new(origin),
            None => ConnectClient::configured(),
        }
    }

    fn busy(&self) -> bool {
        self.task.is_some() || self.opening.is_some()
    }

    /// Forget what the section showed of the account, and read the account file again.
    /// The session itself follows the vault ([`step`]).
    fn reset(&mut self) {
        self.file = OnceCell::new();
        self.snapshot = None;
        self.guarded = None;
        self.waiting = None;
        self.link = slot();
        self.pending.clear();
        self.join = slot();
        self.refreshed_at = None;
        self.unreachable = None;
        self.error = None;
    }

    /// The account of this device for the sync through Apassy Connect (plan s7 unit M3):
    /// `Some` while the session is open. The sync of a vault store does not wait for an
    /// answer of Connect: before the first refresh the signers come from the trust store
    /// of the account file, and the plan is not known yet.
    pub(crate) fn sync_account(&self) -> Option<SyncAccount> {
        if !self.session.is_open() {
            return None;
        }
        let file = self.file()?;
        let snapshot = self.snapshot.as_ref();
        Some(SyncAccount {
            account: self.session.slot(),
            origin: file.origin.clone(),
            plan: snapshot.map(|snapshot| StorePlan::from_view(&snapshot.view.plan)),
            signer: self.session.signer(),
            signers: snapshot.map_or_else(
                || crate::connect::signer_policy(file),
                |snapshot| snapshot.signers.clone(),
            ),
        })
    }

    /// The account id of the account file of this device.
    pub(crate) fn account_id(&self) -> Option<String> {
        self.file().map(|file| file.account_id.clone())
    }

    /// The Connect origin of the account file of this device, also while the session is
    /// not open: a link for that origin needs the account ([`Self::sync_account`]).
    pub(crate) fn account_origin(&self) -> Option<String> {
        self.file().map(|file| file.origin.clone())
    }

    /// Ask Connect for the account at the next frame, at most once a minute: a sync of a
    /// vault store was refused or waits for a device, so a removal or a new device reaches
    /// the policy of the running sessions sooner than [`REFRESH_EVERY`].
    pub(crate) fn refresh_soon(&mut self) {
        if self
            .refreshed_at
            .is_some_and(|at| at.elapsed() >= REFRESH_SOON_AFTER)
        {
            self.refreshed_at = None;
        }
    }

    /// The poll intervals.
    fn poll_every(&self) -> Duration {
        self.poll_every.unwrap_or(POLL_EVERY)
    }

    fn join_poll_every(&self) -> Duration {
        self.join_poll_every.unwrap_or(JOIN_POLL_EVERY)
    }

    /// Run `work` on a worker thread. A step that it replaces is asked again later.
    fn spawn(&mut self, ctx: &egui::Context, work: impl FnOnce() -> Outcome + Send + 'static) {
        self.error = None;
        if self.task.is_some() {
            self.refreshed_at = None;
        }
        self.task = Some(Task::spawn(Some(ctx.clone()), work));
    }

    /// Run `work` with the account of the session on a worker thread. A removal that it
    /// meets is the state of the session for every part.
    fn with_account(
        &mut self,
        ctx: &egui::Context,
        work: impl FnOnce(&mut ConnectAccount) -> Outcome + Send + 'static,
    ) {
        let session = Arc::clone(&self.session);
        self.spawn(ctx, move || {
            let mut done = None;
            let result = session.with_account(|account| {
                let outcome = work(account);
                let error = outcome.error().cloned();
                done = Some(outcome);
                error.map_or(Ok(()), Err)
            });
            match (done, result) {
                (Some(outcome), _) => outcome,
                (None, Err(error)) => Outcome::Failed(error),
                (None, Ok(())) => Outcome::Failed(ConnectError::Local),
            }
        });
    }

    /// Read the key for `ticket` on a worker.
    fn open(&mut self, ctx: &egui::Context, ticket: OpenTicket) {
        let session = Arc::clone(&self.session);
        self.refreshed_at = None;
        self.unreachable = None;
        self.opening = Some(Task::spawn(Some(ctx.clone()), move || {
            session.open_now(ticket)
        }));
    }
}

impl DesktopApp {
    /// The one Apassy Connect account session of the app, for the node's tunnel and the
    /// sync worker.
    pub(crate) fn connect_session(&self) -> Arc<AccountSession> {
        self.ui.connect.live.session()
    }

    /// The window of the app: the account file of `data_dir` and the key store of this
    /// platform (the Keychain through the signed helper on macOS, a private file on
    /// Linux). The sync worker signs the vault stores with the key of this session.
    pub(crate) fn connect_use_platform(&mut self, data_dir: &Path) {
        let store = crate::connect::platform_store(data_dir);
        self.connect_configure(store, Some(data_dir.to_path_buf()));
    }

    /// Use `store` and the data directory `dir` for the account of the session.
    pub(crate) fn connect_configure(
        &mut self,
        store: Option<Arc<dyn DeviceKeyStore>>,
        dir: Option<PathBuf>,
    ) {
        self.ui.connect.live.configure(store, dir);
        self.sync.worker.set_connect(self.ui.connect.live.session());
    }

    /// The Keychain account of the account key when the next Touch ID unlock should read
    /// it with the vault's unlock key (the Mac, with an account file).
    pub(crate) fn connect_key_with_unlock(&self) -> Option<&'static str> {
        let session = &self.ui.connect.live.session;
        session
            .store()
            .and_then(|store| store.keychain_account())
            .filter(|_| session.has_account())
    }

    /// After an unlock: the session opens for the new vault session now, with the key
    /// that the Touch ID unlock offered, without a read of the store.
    pub(crate) fn connect_after_unlock(&mut self) {
        if let Some(epoch) = self.owner_ui.session.epoch() {
            self.ui.connect.live.session.open_offered(epoch);
        }
    }

    /// The steps of Settings › Connect at each frame of the app ([`step`]).
    pub(crate) fn poll_connect(&mut self, ctx: &egui::Context) {
        step(self, ctx);
    }

    /// A lock or a quit: the account session closes at once, and the section forgets
    /// what it showed.
    pub(crate) fn connect_lock(&mut self) {
        let live = &mut self.ui.connect.live;
        live.session.close();
        live.opening = None;
        live.reset();
        live.epoch = None;
        self.ui.connect.sheet = None;
        self.ui.connect.share.reset();
    }
}

fn plans_of(view: &PlansView) -> Plans {
    Plans {
        currency: view.currency.clone(),
        offers: view
            .plans
            .iter()
            .map(|offer| Offer {
                plan: offer.plan.clone(),
                name: offer.name.clone(),
                included: offer.included,
                max: offer.max,
                prices: offer
                    .prices
                    .iter()
                    .map(|price| Price {
                        interval: price.interval.clone(),
                        amount: price.amount,
                        extra: price.extra,
                    })
                    .collect(),
            })
            .collect(),
    }
}

/// The plans of `GET /v1/plans` as the section shows them (the tests read the fixture
/// through it).
#[cfg(test)]
pub(crate) fn plans_from(view: &PlansView) -> Plans {
    plans_of(view)
}

fn plan_of(view: &crate::connect::PlanView) -> Plan {
    Plan {
        plan: view.plan.clone(),
        status: view.status.clone(),
        entitled: view.entitled,
        interval: view.interval.clone(),
        quantity: view.quantity,
        renews_at: view.renews_at,
        ends_at: view.ends_at,
        grace_until: view.grace_until,
        read_only_until: view.read_only_until,
        delete_at: view.delete_at,
    }
}

/// The account as the section shows it. This Mac comes first among the devices.
fn account_of(snapshot: &Snapshot, this_device: &str) -> Account {
    let view = &snapshot.view;
    let mut devices: Vec<Device> = view
        .devices
        .iter()
        .map(|device| Device {
            id: device.device_id.clone(),
            // The name that the signed device list holds for the key, when it verified.
            name: device.shown_name().to_owned(),
            platform: device.platform.clone(),
            created_at: device.created_at,
            last_seen_at: device.last_seen_at,
            this: device.device_id == this_device,
            verified: device.verified,
            fingerprint: device.fingerprint.clone(),
        })
        .collect();
    devices.sort_by_key(|device| !device.this);
    let group = view.group.as_ref().map(|short| {
        let detail = snapshot
            .group
            .as_ref()
            .filter(|detail| detail.group_id == short.group_id);
        let members: Vec<Member> = detail
            .map(|detail| {
                detail
                    .members
                    .iter()
                    .map(|member| Member {
                        account_id: member.account_id.clone(),
                        name: member.name.clone(),
                        role: member.role.clone(),
                        state: member.state.clone(),
                        joined_at: member.joined_at,
                    })
                    .collect()
            })
            .unwrap_or_default();
        let owner_name = detail
            .and_then(|detail| {
                detail
                    .members
                    .iter()
                    .find(|member| member.account_id == detail.owner_account)
            })
            .map_or_else(|| "The organizer".to_owned(), |member| member.name.clone());
        Group {
            id: short.group_id.clone(),
            kind: short.kind.clone(),
            role: short.role.clone(),
            state: short.state.clone(),
            owner_name,
            quantity: detail
                .map(|detail| detail.quantity)
                .or(view.plan.quantity)
                .unwrap_or(0),
            members,
        }
    });
    let adds_left =
        crate::connect::trust::MAX_ADD_VERSION.saturating_sub(view.device_list.len() as u64);
    Account {
        account_id: view.account_id.clone(),
        name: view.name.clone(),
        email: view.email.clone(),
        plan: plan_of(&view.plan),
        devices,
        group,
        list_verified: view.list_verified,
        list_nearly_full: view.list_verified
            && adds_left <= crate::connect::trust::ADDS_LEFT_WARNING,
    }
}

/// The view of the section now.
pub(crate) fn view(app: &DesktopApp) -> ConnectView {
    let live = &app.ui.connect.live;
    let locked = app.owner_ui.session.epoch().is_none();
    let file = live.file();
    let state = live.session.state();
    let shown = match (file, &state) {
        (None, _) if live.session.has_old_account_file() => Shown::OldFile,
        (None, _) => Shown::None,
        (Some(file), SessionState::Removed(error)) => Shown::Removed {
            name: file.name.clone(),
            device_name: file.device_name.clone(),
            note: removed_note(error),
        },
        (Some(file), SessionState::Open) => match (&live.snapshot, &live.unreachable) {
            (Some(snapshot), _) => Shown::Account(account_of(snapshot, &file.device_id)),
            (None, Some((error, _))) if !live.busy() => Shown::Unreachable {
                name: file.name.clone(),
                device_name: file.device_name.clone(),
                note: message(error),
            },
            (None, _) => Shown::Loading {
                name: file.name.clone(),
            },
        },
        (Some(file), SessionState::Opening) if !locked => Shown::Loading {
            name: file.name.clone(),
        },
        (Some(file), _) => Shown::SignedOut {
            name: file.name.clone(),
            device_name: file.device_name.clone(),
        },
    };
    ConnectView {
        shown,
        plans: live.plans.clone(),
        locked,
        busy: live.busy(),
        error: if app.ui.connect.sheet.is_none() {
            live.error.clone()
        } else {
            None
        },
        now: crate::desktop::companion::now(),
    }
}

/// The status line of Settings > Connect.
pub(crate) fn status_line(app: &DesktopApp) -> String {
    view(app).status_line()
}

/// Draw the section, its sheet, and run its steps.
pub(crate) fn section(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let ctx = ui.ctx().clone();
    step(app, &ctx);
    let view = view(app);
    if let Some(action) = super::draw(ui, &view) {
        act(app, &ctx, action);
    }
    if matches!(view.shown, Shown::Account(_)) && !view.locked {
        super::share::section(app, ui);
    }
    let live = &app.ui.connect.live;
    let busy = live.busy();
    let error = live.error.clone();
    let now = view.now;
    let state = &mut app.ui.connect;
    let choice = state.sheet.as_mut().and_then(|sheet| {
        super::sheet(
            &ctx,
            sheet,
            state.live.plans.as_ref(),
            busy,
            error.as_deref(),
            now,
            &|ui, text| {
                if let Some(modules) = crate::desktop::companion::QrModules::new(text) {
                    super::super::companion::draw_qr(ui, &modules, 150.0, "QR code of the code");
                }
            },
        )
    });
    if let Some(choice) = choice {
        choose(app, &ctx, choice);
    }
    let live = &app.ui.connect.live;
    if live.waiting.is_some() || !live.pending.is_empty() || live.busy() {
        ctx.request_repaint_after(Duration::from_millis(250));
    } else if matches!(
        app.ui.connect.sheet,
        Some(Sheet::AddDevice { .. } | Sheet::JoinWaiting { .. })
    ) {
        ctx.request_repaint_after(Duration::from_secs(1));
    }
}

/// The steps of one frame, also while Settings is closed: the session follows the vault
/// session, then the result of the worker, the owner proof, the polls, and the refresh
/// of the account.
pub(crate) fn step(app: &mut DesktopApp, ctx: &egui::Context) {
    follow(app, ctx);
    finish(app, ctx);
    guarded(app, ctx);
    polls(app, ctx);
    keep_fresh(app, ctx);
}

/// The session follows the vault session: it closes at a lock and at another vault
/// session, and opens for an unlocked one with one read of the key store.
fn follow(app: &mut DesktopApp, ctx: &egui::Context) {
    let epoch = app.owner_ui.session.epoch();
    let live = &mut app.ui.connect.live;
    live.session.tidy();
    if live.epoch.is_some_and(|seen| seen != epoch) {
        // A lock or another unlock: what the section showed goes with the session.
        live.opening = None;
        live.reset();
        app.ui.connect.sheet = None;
    }
    let live = &mut app.ui.connect.live;
    live.epoch = Some(epoch);
    if let Follow::Read(ticket) = live.session.follow(epoch) {
        live.open(ctx, ticket);
    }
    if let Some(task) = &live.opening {
        match task.poll() {
            TaskPoll::Waiting => {}
            TaskPoll::Done(_) | TaskPoll::Lost => {
                live.opening = None;
                live.file = OnceCell::new();
            }
        }
    }
}

/// Ask Connect for the account after the session opened, every [`REFRESH_EVERY`], and
/// after [`RETRY_UNREACHABLE`] when it could not be reached.
fn keep_fresh(app: &mut DesktopApp, ctx: &egui::Context) {
    let live = &app.ui.connect.live;
    if !live.session.is_open() || live.busy() {
        return;
    }
    let due = match (&live.unreachable, live.refreshed_at) {
        (Some((_, at)), _) => at.elapsed() >= RETRY_UNREACHABLE,
        (None, None) => true,
        (None, Some(at)) => at.elapsed() >= REFRESH_EVERY,
    };
    if due {
        refresh(app, ctx);
    }
}

fn message(error: &ConnectError) -> String {
    error.to_string()
}

/// Apply the result of the worker, if it is there.
fn finish(app: &mut DesktopApp, ctx: &egui::Context) {
    let live = &mut app.ui.connect.live;
    let Some(task) = &live.task else {
        return;
    };
    let outcome = match task.poll() {
        TaskPoll::Waiting => return,
        TaskPoll::Lost => {
            live.task = None;
            live.error = Some(message(&ConnectError::Local));
            return;
        }
        TaskPoll::Done(outcome) => outcome,
    };
    live.task = None;
    apply(app, ctx, outcome);
}

/// Refresh the account, its group, and the plans.
fn refresh(app: &mut DesktopApp, ctx: &egui::Context) {
    let live = &mut app.ui.connect.live;
    if !live.session.is_open() || live.busy() {
        return;
    }
    let want_plans = live.plans.is_none();
    app.ui.connect.live.with_account(ctx, move |account| {
        let snapshot = account.view().and_then(|view| {
            let group = if view.group.is_some() {
                account.group()?
            } else {
                None
            };
            Ok(Snapshot {
                view,
                group,
                signers: crate::connect::signer_policy(account.state()),
            })
        });
        match snapshot {
            Ok(snapshot) => {
                let plans = want_plans.then(|| account.client().plans().ok()).flatten();
                Outcome::Refreshed(Ok((snapshot, plans)))
            }
            Err(error) => Outcome::Refreshed(Err(error)),
        }
    });
    app.ui.connect.live.refreshed_at = Some(Instant::now());
}

/// Connect could not be reached, or did not answer now: "Connect unreachable" until a
/// refresh works. Never a removal.
fn unreachable(error: &ConnectError) -> bool {
    matches!(
        error,
        ConnectError::Offline | ConnectError::Broken | ConnectError::RateLimited(_)
    ) || matches!(error, ConnectError::Refused { status, .. } if *status >= 500)
}

/// The note of the removed state for `error`: Connect said this device was removed, or
/// its key cannot be read any more.
fn removed_note(error: &ConnectError) -> String {
    match error {
        ConnectError::Revoked => REMOVED_NOTE.to_owned(),
        other => message(other),
    }
}

/// Drop the account rows of the open vault after this Mac was forgotten.
fn drop_rows(app: &DesktopApp, forgotten: &Forgotten) {
    let _ = app
        .owner_ui
        .session
        .with_vault(|vault| drop_account_rows(vault, forgotten));
}

#[allow(clippy::too_many_lines)]
fn apply(app: &mut DesktopApp, ctx: &egui::Context, outcome: Outcome) {
    let live = &mut app.ui.connect.live;
    match outcome {
        Outcome::Created(Ok((_, words))) => {
            live.file = OnceCell::new();
            live.refreshed_at = Some(Instant::now());
            app.ui.connect.sheet = Some(Sheet::Recovery { words });
        }
        Outcome::Refreshed(Ok((snapshot, plans))) => {
            live.snapshot = Some(snapshot);
            live.unreachable = None;
            if let Some(plans) = plans {
                live.plans = Some(plans_of(&plans));
            }
            // The key of the session goes to the sync of the vault stores, with the plan
            // state and the verified devices.
            app.relay_share_connect();
        }
        Outcome::Refreshed(Err(error)) if unreachable(&error) => {
            live.unreachable = Some((error.clone(), Instant::now()));
            if live.snapshot.is_some() {
                live.error = Some(message(&error));
            }
        }
        Outcome::Plans(Ok(plans)) => live.plans = Some(plans_of(&plans)),
        Outcome::Checkout(Ok((url, _session))) => {
            ctx.open_url(egui::OpenUrl::new_tab(url.clone()));
            live.waiting = Some(Waiting {
                started: Instant::now(),
                polled: Some(Instant::now()),
            });
            app.ui.connect.sheet = Some(Sheet::Waiting {
                url,
                stopped: false,
            });
        }
        Outcome::Polled(Ok(view)) => {
            let Some(_) = live.waiting else {
                return;
            };
            let entitled = view.plan.entitled;
            if let Some(snapshot) = &mut live.snapshot {
                snapshot.view = view.clone();
            }
            if entitled {
                live.waiting = None;
                let name = view
                    .plan
                    .plan
                    .as_deref()
                    .map(|key| {
                        live.plans
                            .as_ref()
                            .and_then(|plans| plans.offer(key))
                            .map_or_else(
                                || super::fallback_name(key).to_owned(),
                                |offer| offer.name.clone(),
                            )
                    })
                    .unwrap_or_default();
                let line = match (view.plan.ends_at, view.plan.renews_at) {
                    (Some(at), _) => format!("Ends {}.", super::day(at)),
                    (None, Some(at)) => format!("Renews {}.", super::day(at)),
                    _ => String::new(),
                };
                app.ui.connect.sheet = Some(Sheet::Active {
                    title: format!("{name} Is Active"),
                    line,
                });
                refresh(app, ctx);
            }
        }
        Outcome::Portal(Ok(url)) => ctx.open_url(egui::OpenUrl::new_tab(url)),
        Outcome::Linked(Ok((code, expires_at))) => {
            live.pending.clear();
            live.pending_at = Some(Instant::now());
            app.ui.connect.sheet = Some(Sheet::AddDevice { code, expires_at });
        }
        Outcome::Pending(Ok(pending)) => {
            live.pending_at = Some(Instant::now());
            if !matches!(app.ui.connect.sheet, Some(Sheet::AddDevice { .. })) {
                return;
            }
            if let Some(join) = pending.first() {
                app.ui.connect.sheet = Some(Sheet::Words {
                    join_id: join.join_id,
                    device_name: join.device_name.clone(),
                    platform: join.platform.clone(),
                    words: join.words.clone(),
                });
            }
            app.ui.connect.live.pending = pending;
        }
        Outcome::Confirmed(Ok(name)) => {
            live.link = slot();
            live.pending.clear();
            app.ui.connect.sheet = Some(Sheet::DeviceAdded { name });
            refresh(app, ctx);
        }
        Outcome::Refused(Ok(())) => {
            live.link = slot();
            live.pending.clear();
            app.ui.connect.sheet = None;
        }
        Outcome::Revoked(Ok(Some(forgotten))) => {
            drop_rows(app, &forgotten);
            app.ui.connect.live.session.forget();
            app.ui.connect.live.reset();
            app.set_ok(LEFT);
        }
        Outcome::Revoked(Ok(None)) => {
            app.set_ok("The device is revoked.");
            refresh(app, ctx);
        }
        Outcome::Deleted(Ok(forgotten)) => {
            drop_rows(app, &forgotten);
            app.ui.connect.live.session.forget();
            app.ui.connect.live.reset();
            app.ui.connect.sheet = None;
            app.set_ok(DELETED);
        }
        Outcome::Deleted(Err(error)) => {
            // The account left memory with the call: "Sign In…" reads it again.
            live.reset();
            if error == ConnectError::Conflict {
                app.ui.connect.sheet = Some(Sheet::MembersFirst);
            } else {
                live.error = Some(message(&error));
            }
        }
        Outcome::Invited(Ok((url, expires_at))) => {
            if let Some(Sheet::Invite { link, .. }) = &mut app.ui.connect.sheet {
                *link = Some((url, expires_at));
            }
        }
        Outcome::JoinedGroup(Ok(owner_name)) => {
            app.ui.connect.sheet = Some(Sheet::JoinSent { owner_name });
            refresh(app, ctx);
        }
        Outcome::JoinedGroup(Err(ConnectError::Conflict)) => {
            if let Some(Sheet::JoinGroup { refused, .. }) = &mut app.ui.connect.sheet {
                *refused = true;
            }
        }
        Outcome::GroupChanged(Ok(text)) => {
            app.ui.connect.sheet = None;
            app.set_ok(text);
            refresh(app, ctx);
        }
        Outcome::JoinStarted(Ok((confirmer, words))) => {
            live.join_at = Some(Instant::now());
            app.ui.connect.sheet = Some(Sheet::JoinWaiting { confirmer, words });
        }
        Outcome::JoinPolled(Ok(None)) => live.join_at = Some(Instant::now()),
        Outcome::JoinPolled(Ok(Some(_))) => {
            live.file = OnceCell::new();
            app.ui.connect.sheet = Some(Sheet::Joined);
            refresh(app, ctx);
        }
        Outcome::JoinPolled(Err(error)) => {
            live.join = slot();
            app.ui.connect.sheet = None;
            live.error = Some(message(&error));
        }
        Outcome::JoinCancelled => {
            live.join = slot();
        }
        Outcome::Forgot(Ok(forgotten)) => {
            drop_rows(app, &forgotten);
            app.ui.connect.live.session.forget();
            app.ui.connect.live.reset();
            app.ui.connect.sheet = None;
            app.set_ok(FORGOT);
        }
        Outcome::Forgot(Err(error)) => live.error = Some(message(&error)),
        Outcome::Polled(Err(error)) => {
            // A failed poll waits for the next one; it is not the owner's problem yet.
            if let Some(waiting) = &mut live.waiting {
                waiting.polled = Some(Instant::now());
            }
            let _ = error;
        }
        Outcome::Failed(error)
        | Outcome::Created(Err(error))
        | Outcome::Refreshed(Err(error))
        | Outcome::Plans(Err(error))
        | Outcome::Checkout(Err(error))
        | Outcome::Portal(Err(error))
        | Outcome::Linked(Err(error))
        | Outcome::Pending(Err(error))
        | Outcome::Confirmed(Err(error))
        | Outcome::Refused(Err(error))
        | Outcome::Revoked(Err(error))
        | Outcome::Invited(Err(error))
        | Outcome::JoinedGroup(Err(error))
        | Outcome::GroupChanged(Err(error))
        | Outcome::JoinStarted(Err(error)) => {
            live.session.note(&error);
            if matches!(live.session.state(), SessionState::Removed(_)) && live.file().is_some() {
                // Removed for every part: the section shows it, and nothing is deleted.
                live.snapshot = None;
                live.waiting = None;
                app.ui.connect.sheet = None;
                return;
            }
            live.error = Some(message(&error));
        }
    }
}

/// Run the step that waits for the owner check when its proof is there. A check that
/// ended without a proof (cancelled, or refused) drops the step.
fn guarded(app: &mut DesktopApp, ctx: &egui::Context) {
    let Some(step) = app.ui.connect.live.guarded.clone() else {
        return;
    };
    if app.ui.connect.live.busy() {
        return;
    }
    let Some(proof) = app.owner.take_connect_proof() else {
        if app.owner.check.is_none() {
            app.ui.connect.live.guarded = None;
        }
        return;
    };
    app.ui.connect.live.guarded = None;
    let Some(epoch) = app.owner_ui.session.epoch() else {
        app.ui.connect.live.error = Some(super::LOCKED.to_owned());
        return;
    };
    run_guarded(app, ctx, step, proof, epoch);
}

fn run_guarded(
    app: &mut DesktopApp,
    ctx: &egui::Context,
    step: Guarded,
    proof: OwnerProof,
    epoch: [u8; 32],
) {
    let store = app.ui.connect.live.store();
    let path = app.ui.connect.live.path();
    let live = &mut app.ui.connect.live;
    match step {
        Guarded::Confirm { join_id } => {
            let Some(join) = live
                .pending
                .iter()
                .find(|join| join.join_id == join_id)
                .cloned()
            else {
                return;
            };
            let link = Arc::clone(&live.link);
            live.with_account(ctx, move |account| {
                let link = link
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let Some(link) = link.as_ref() else {
                    return Outcome::Confirmed(Err(ConnectError::JoinRefused));
                };
                Outcome::Confirmed(
                    account
                        .confirm_join(link, &join, proof, &epoch)
                        .map(|device| device.name),
                )
            });
        }
        Guarded::Revoke { device_id } => {
            let Some(device) = live.snapshot.as_ref().and_then(|snapshot| {
                snapshot
                    .view
                    .devices
                    .iter()
                    .find(|device| device.device_id == device_id)
                    .cloned()
            }) else {
                return;
            };
            live.with_account(ctx, move |account| {
                Outcome::Revoked(account.revoke(&device, proof, &epoch).and_then(|outcome| {
                    if !outcome.this_device {
                        return Ok(None);
                    }
                    match (store, path) {
                        (Some(store), Some(path)) => {
                            forget_this_device(store.as_ref(), &path).map(Some)
                        }
                        _ => Err(ConnectError::Local),
                    }
                }))
            });
        }
        Guarded::ForgetOld => {
            let session = live.session();
            live.spawn(ctx, move || {
                drop(session.take_any());
                let (Some(store), Some(path)) = (store, path) else {
                    return Outcome::Forgot(Err(ConnectError::KeychainUnavailable));
                };
                Outcome::Forgot(crate::connect::forget_old_account_file(
                    store.as_ref(),
                    &path,
                    proof,
                    &epoch,
                ))
            });
        }
        Guarded::Delete => {
            let session = live.session();
            live.spawn(ctx, move || {
                let (Some(account), Some(store)) = (session.take(), store) else {
                    return Outcome::Deleted(Err(ConnectError::SignedOut));
                };
                Outcome::Deleted(
                    account
                        .delete(store.as_ref(), proof, &epoch)
                        .map(|(_, forgotten)| forgotten),
                )
            });
        }
        Guarded::Group { group_id, change } => {
            live.with_account(ctx, move |account| {
                let result = match change {
                    ConnectGroupChange::ConfirmMember { account_id, name } => account
                        .confirm_member(&group_id, &account_id, &name, proof, &epoch)
                        .map(|member| format!("{} is in the group now.", member.name)),
                    ConnectGroupChange::RemoveMember { account_id, name } => {
                        let own = account_id == account.state().account_id;
                        account
                            .remove_member(&group_id, &account_id, &name, proof, &epoch)
                            .map(|_| {
                                if own {
                                    "You left the group.".to_owned()
                                } else {
                                    format!("{name} is removed.")
                                }
                            })
                    }
                    ConnectGroupChange::SetSeats { quantity } => account
                        .set_seats(&group_id, quantity, proof, &epoch)
                        .map(|answer| format!("Stripe changes the plan to {}.", answer.quantity)),
                };
                Outcome::GroupChanged(result)
            });
        }
    }
}

/// The polls of the open sheets: the checkout every 3 s, the device link and this Mac's
/// join every 5 s. The checkout stops after 30 minutes.
fn polls(app: &mut DesktopApp, ctx: &egui::Context) {
    let live = &mut app.ui.connect.live;
    if live.busy() {
        return;
    }
    let now = Instant::now();
    let checkout_every = live.poll_every();
    if let Some(waiting) = &mut live.waiting {
        if now.duration_since(waiting.started) >= WAIT_AT_MOST {
            live.waiting = None;
            if let Some(Sheet::Waiting { stopped, .. }) = &mut app.ui.connect.sheet {
                *stopped = true;
            }
            return;
        }
        if waiting
            .polled
            .is_none_or(|at| now.duration_since(at) >= checkout_every)
        {
            waiting.polled = Some(now);
            live.with_account(ctx, |account| Outcome::Polled(account.view()));
        }
        return;
    }
    let every = live.join_poll_every();
    let due = |at: Option<Instant>| at.is_none_or(|at| now.duration_since(at) >= every);
    if matches!(app.ui.connect.sheet, Some(Sheet::AddDevice { .. })) && due(live.pending_at) {
        live.pending_at = Some(now);
        let link = Arc::clone(&live.link);
        live.with_account(ctx, move |account| {
            let link = link
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match link.as_ref() {
                Some(link) => Outcome::Pending(account.pending_joins(link)),
                None => Outcome::Pending(Ok(Vec::new())),
            }
        });
        return;
    }
    if matches!(app.ui.connect.sheet, Some(Sheet::JoinWaiting { .. })) && due(live.join_at) {
        live.join_at = Some(now);
        let join = Arc::clone(&live.join);
        let session = live.session();
        let epoch = live.epoch.flatten();
        live.spawn(ctx, move || {
            let mut guard = join
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(request) = guard.as_mut() else {
                return Outcome::JoinCancelled;
            };
            match request.poll() {
                Ok(JoinPoll::Waiting) => Outcome::JoinPolled(Ok(None)),
                Ok(JoinPoll::Refused) => {
                    *guard = None;
                    Outcome::JoinPolled(Err(ConnectError::JoinRefused))
                }
                Ok(JoinPoll::Confirmed(account)) => {
                    *guard = None;
                    let state = account.state().clone();
                    if session.install(*account, epoch) {
                        Outcome::JoinPolled(Ok(Some(state)))
                    } else {
                        Outcome::JoinPolled(Err(ConnectError::SignedOut))
                    }
                }
                Err(error) => Outcome::JoinPolled(Err(error)),
            }
        });
    }
}

/// What the owner chose in the section.
pub(crate) fn act(app: &mut DesktopApp, ctx: &egui::Context, action: Action) {
    let view = view(app);
    let account = match &view.shown {
        Shown::Account(account) => Some(account.clone()),
        _ => None,
    };
    match action {
        Action::Create => {
            app.ui.connect.live.error = None;
            app.ui.connect.sheet = Some(Sheet::Create {
                name: String::new(),
                device_name: crate::sync::device_name(),
            });
        }
        Action::AddThisMac => {
            app.ui.connect.live.error = None;
            app.ui.connect.sheet = Some(Sheet::JoinAccount {
                code: Zeroizing::new(String::new()),
            });
        }
        Action::SignIn => sign_in(app, ctx),
        Action::ChoosePlan => {
            app.ui.connect.sheet = Some(Sheet::Picker {
                plan: "personal".to_owned(),
                interval: "month".to_owned(),
                count: 1,
            });
            load_plans(app, ctx);
        }
        Action::ManageBilling => app.ui.connect.live.with_account(ctx, |account| {
            Outcome::Portal(account.portal().map(|answer| answer.url))
        }),
        Action::AddDevice => {
            let link = Arc::clone(&app.ui.connect.live.link);
            app.ui.connect.live.with_account(ctx, move |account| {
                Outcome::Linked(account.start_link().map(|made| {
                    let code = Zeroizing::new(made.code().to_owned());
                    let expires_at = made.expires_at();
                    *link
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(made);
                    (code, expires_at)
                }))
            });
        }
        Action::Revoke(index) => {
            if let Some(device) = account
                .as_ref()
                .and_then(|account| account.devices.get(index))
            {
                app.ui.connect.sheet = Some(Sheet::Revoke {
                    index,
                    name: device.name.clone(),
                    this: device.this,
                });
            }
        }
        Action::Invite => {
            let Some(group) = account.as_ref().and_then(|account| account.group.clone()) else {
                return;
            };
            let choose_role = group.kind == "team" && group.role == "owner";
            app.ui.connect.sheet = Some(Sheet::Invite {
                kind: group.kind.clone(),
                choose_role,
                role: "member".to_owned(),
                link: None,
            });
            if !choose_role {
                invite(app, ctx, "member".to_owned());
            }
        }
        Action::ConfirmMember(index) => {
            let Some((account, group)) = account.and_then(|account| {
                let group = account.group.clone()?;
                Some((account, group))
            }) else {
                return;
            };
            let Some(member) = group.members.get(index) else {
                return;
            };
            ask_group(
                app,
                ctx,
                &account.account_id,
                &group.id,
                ConnectGroupChange::ConfirmMember {
                    account_id: member.account_id.clone(),
                    name: member.name.clone(),
                },
            );
        }
        Action::RemoveMember(index) => {
            let Some(group) = account.as_ref().and_then(|account| account.group.clone()) else {
                return;
            };
            if let Some(member) = group.members.get(index) {
                app.ui.connect.sheet = Some(Sheet::RemoveMember {
                    account_id: member.account_id.clone(),
                    name: member.name.clone(),
                    kind: group.kind.clone(),
                    leave: false,
                });
            }
        }
        Action::Leave => {
            let Some(account) = account else {
                return;
            };
            if let Some(group) = &account.group {
                app.ui.connect.sheet = Some(Sheet::RemoveMember {
                    account_id: account.account_id.clone(),
                    name: account.name.clone(),
                    kind: group.kind.clone(),
                    leave: true,
                });
            }
        }
        Action::ChangeSeats => {
            let Some(group) = account.as_ref().and_then(|account| account.group.clone()) else {
                return;
            };
            app.ui.connect.sheet = Some(Sheet::Seats {
                kind: group.kind.clone(),
                quantity: group.quantity.max(1),
            });
            load_plans(app, ctx);
        }
        Action::JoinGroup => {
            app.ui.connect.sheet = Some(Sheet::JoinGroup {
                link: String::new(),
                refused: false,
            });
        }
        Action::Delete => app.ui.connect.sheet = Some(Sheet::Delete),
        Action::ForgetOld => {
            app.ui.connect.live.error = None;
            app.ui.connect.live.guarded = Some(Guarded::ForgetOld);
            app.ask_owner(OwnerRequest::ForgetOldConnectAccount, Some(ctx));
        }
        Action::ForgetRemoved => {
            app.ui.connect.live.error = None;
            app.ui.connect.sheet = Some(Sheet::ForgetRemoved);
        }
    }
}

/// "Sign In…" and "Try Again": refresh an open account, or read the key of the session
/// again after a cancelled or failed read. Never while Apassy is locked.
fn sign_in(app: &mut DesktopApp, ctx: &egui::Context) {
    if app.owner_ui.session.epoch().is_none() {
        app.ui.connect.live.error = Some(super::LOCKED.to_owned());
        return;
    }
    let live = &mut app.ui.connect.live;
    if live.session.is_open() {
        live.unreachable = None;
        refresh(app, ctx);
        return;
    }
    if live.busy() {
        return;
    }
    if live.store().is_none() {
        live.error = Some(message(&ConnectError::KeychainUnavailable));
        return;
    }
    if let Some(ticket) = live.session.retry() {
        live.error = None;
        live.open(ctx, ticket);
    }
}

fn load_plans(app: &mut DesktopApp, ctx: &egui::Context) {
    let live = &mut app.ui.connect.live;
    if live.plans.is_some() || live.busy() {
        return;
    }
    let Ok(client) = live.client() else {
        return;
    };
    live.spawn(ctx, move || Outcome::Plans(client.plans()));
}

fn invite(app: &mut DesktopApp, ctx: &egui::Context, role: String) {
    app.ui.connect.live.with_account(ctx, move |account| {
        Outcome::Invited(
            account
                .invite(&role)
                .map(|answer| (answer.url, answer.expires_at)),
        )
    });
}

/// Ask for the owner check of a change of the group, and remember the step.
fn ask_group(
    app: &mut DesktopApp,
    ctx: &egui::Context,
    account_id: &str,
    group_id: &str,
    change: ConnectGroupChange,
) {
    app.ui.connect.live.guarded = Some(Guarded::Group {
        group_id: group_id.to_owned(),
        change: change.clone(),
    });
    app.ask_owner(
        OwnerRequest::ChangeConnectGroup {
            account_id: account_id.to_owned(),
            group_id: group_id.to_owned(),
            change,
        },
        Some(ctx),
    );
}

/// What the owner chose in a sheet.
#[allow(clippy::too_many_lines)]
pub(crate) fn choose(app: &mut DesktopApp, ctx: &egui::Context, choice: SheetChoice) {
    let Some(sheet) = app.ui.connect.sheet.take() else {
        return;
    };
    let view = view(app);
    let account = match &view.shown {
        Shown::Account(account) => Some(account.clone()),
        _ => None,
    };
    if let SheetChoice::Copy(text) = &choice {
        ctx.copy_text(text.clone());
        app.ui.connect.sheet = Some(sheet);
        return;
    }
    match (sheet, choice) {
        (Sheet::Recovery { .. }, SheetChoice::Done) => refresh(app, ctx),
        (sheet @ Sheet::Recovery { .. }, _) => app.ui.connect.sheet = Some(sheet),
        (Sheet::Create { name, device_name }, SheetChoice::Go) => {
            let live = &app.ui.connect.live;
            let (Some(store), Some(path), Some(epoch)) =
                (live.store(), live.path(), app.owner_ui.session.epoch())
            else {
                app.ui.connect.live.error = Some(message(&ConnectError::KeychainUnavailable));
                app.ui.connect.sheet = Some(Sheet::Create { name, device_name });
                return;
            };
            let client = live.client();
            let session = live.session();
            let (typed, device) = (name.clone(), device_name.clone());
            app.ui.connect.live.spawn(ctx, move || {
                Outcome::Created(client.and_then(|client| {
                    let (account, recovery) =
                        ConnectAccount::create(client, store.as_ref(), &path, &typed, &device)?;
                    let state = account.state().clone();
                    // The vault locked meanwhile: the account file and the key stay, and
                    // the next unlock opens them.
                    session.install(account, Some(epoch));
                    Ok((state, recovery.words()))
                }))
            });
            app.ui.connect.sheet = Some(Sheet::Create { name, device_name });
        }
        (
            Sheet::Picker {
                plan,
                interval,
                count,
            },
            SheetChoice::Go,
        ) => {
            let request = CheckoutRequest::new(&plan, &interval, count);
            app.ui.connect.live.with_account(ctx, move |account| {
                Outcome::Checkout(
                    account
                        .checkout(&request)
                        .map(|answer| (answer.url, answer.session_id)),
                )
            });
            app.ui.connect.sheet = Some(Sheet::Picker {
                plan,
                interval,
                count,
            });
        }
        (Sheet::Waiting { url, stopped }, SheetChoice::OpenAgain) => {
            ctx.open_url(egui::OpenUrl::new_tab(url.clone()));
            app.ui.connect.sheet = Some(Sheet::Waiting { url, stopped });
        }
        (sheet @ Sheet::Picker { .. }, SheetChoice::TryAgain) => {
            app.ui.connect.sheet = Some(sheet);
            app.ui.connect.live.error = None;
            load_plans(app, ctx);
        }
        (Sheet::Waiting { url, .. }, SheetChoice::CheckAgain) => {
            app.ui.connect.live.waiting = Some(Waiting {
                started: Instant::now(),
                polled: None,
            });
            app.ui.connect.sheet = Some(Sheet::Waiting {
                url,
                stopped: false,
            });
        }
        (Sheet::Waiting { .. }, _) => {
            app.ui.connect.live.waiting = None;
            refresh(app, ctx);
        }
        (Sheet::AddDevice { .. }, _) => {
            app.ui.connect.live.link = slot();
            app.ui.connect.live.pending.clear();
        }
        (
            Sheet::Words {
                join_id,
                device_name,
                platform,
                words,
            },
            SheetChoice::Go,
        ) => {
            let sheet = Sheet::Words {
                join_id,
                device_name: device_name.clone(),
                platform,
                words: words.clone(),
            };
            let Some(account) = account else {
                return;
            };
            let Some(join) = app
                .ui
                .connect
                .live
                .pending
                .iter()
                .find(|join| join.join_id == join_id)
                .cloned()
            else {
                return;
            };
            let request = OwnerRequest::ConfirmConnectDevice {
                account_id: account.account_id.clone(),
                join_id,
                device_name: device_name.clone(),
                public_key: join.public_key.clone(),
                words: words.clone(),
            };
            app.ui.connect.live.guarded = Some(Guarded::Confirm { join_id });
            app.ui.connect.sheet = Some(sheet);
            app.ask_owner(request, Some(ctx));
        }
        (Sheet::Words { join_id, .. }, SheetChoice::Refuse) => {
            app.ui.connect.live.with_account(ctx, move |account| {
                Outcome::Refused(account.refuse_join(join_id))
            });
        }
        (sheet @ Sheet::Words { .. }, _) => {
            // Cancel: the join stays pending at Connect until its link expires.
            let _ = sheet;
            app.ui.connect.live.link = slot();
            app.ui.connect.live.pending.clear();
        }
        (Sheet::Revoke { index, name, this }, SheetChoice::Go) => {
            let Some((account, device)) = account.and_then(|account| {
                let device = account.devices.get(index).cloned()?;
                Some((account, device))
            }) else {
                return;
            };
            app.ui.connect.live.guarded = Some(Guarded::Revoke {
                device_id: device.id.clone(),
            });
            app.ask_owner(
                OwnerRequest::RevokeConnectDevice {
                    account_id: account.account_id,
                    device_id: device.id,
                    device_name: name,
                    fingerprint: device.fingerprint,
                    this_device: this,
                },
                Some(ctx),
            );
        }
        (Sheet::JoinAccount { code }, SheetChoice::Go) => {
            let (Some(store), Some(path)) =
                (app.ui.connect.live.store(), app.ui.connect.live.path())
            else {
                app.ui.connect.live.error = Some(message(&ConnectError::KeychainUnavailable));
                app.ui.connect.sheet = Some(Sheet::JoinAccount { code });
                return;
            };
            let client = app.ui.connect.live.client();
            let join = Arc::clone(&app.ui.connect.live.join);
            let pasted = code.clone();
            app.ui.connect.live.spawn(ctx, move || {
                Outcome::JoinStarted(client.and_then(|client| {
                    let request = JoinRequest::start(
                        client,
                        store.as_ref(),
                        &path,
                        pasted.trim(),
                        &crate::sync::device_name(),
                    )?;
                    let shown = (
                        request.confirmer_name().to_owned(),
                        request.words().to_owned(),
                    );
                    *join
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(request);
                    Ok(shown)
                }))
            });
            app.ui.connect.sheet = Some(Sheet::JoinAccount { code });
        }
        (Sheet::JoinWaiting { .. }, _) => {
            let join = Arc::clone(&app.ui.connect.live.join);
            if !app.ui.connect.live.busy() {
                app.ui.connect.live.spawn(ctx, move || {
                    let taken = join
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .take();
                    if let Some(request) = taken {
                        let _ = request.cancel();
                    }
                    Outcome::JoinCancelled
                });
            }
        }
        (
            Sheet::Invite {
                kind,
                choose_role,
                role,
                link: None,
            },
            SheetChoice::Go,
        ) => {
            invite(app, ctx, role.clone());
            app.ui.connect.sheet = Some(Sheet::Invite {
                kind,
                choose_role,
                role,
                link: None,
            });
        }
        (
            Sheet::RemoveMember {
                account_id, name, ..
            },
            SheetChoice::Go,
        ) => {
            let Some((own, group)) = account.and_then(|account| {
                let group = account.group.clone()?;
                Some((account.account_id, group))
            }) else {
                return;
            };
            ask_group(
                app,
                ctx,
                &own,
                &group.id,
                ConnectGroupChange::RemoveMember { account_id, name },
            );
        }
        (Sheet::Seats { kind, quantity }, SheetChoice::Go) => {
            let Some((own, group)) = account.and_then(|account| {
                let group = account.group.clone()?;
                Some((account.account_id, group))
            }) else {
                return;
            };
            app.ui.connect.sheet = Some(Sheet::Seats { kind, quantity });
            ask_group(
                app,
                ctx,
                &own,
                &group.id,
                ConnectGroupChange::SetSeats { quantity },
            );
        }
        (Sheet::JoinGroup { link, .. }, SheetChoice::Go) => {
            let pasted = link.clone();
            app.ui.connect.live.with_account(ctx, move |account| {
                Outcome::JoinedGroup(account.join_group(&pasted).map(|joined| joined.owner_name))
            });
            app.ui.connect.sheet = Some(Sheet::JoinGroup {
                link,
                refused: false,
            });
        }
        (Sheet::Delete, SheetChoice::Go) => {
            let Some(account) = account else {
                return;
            };
            app.ui.connect.live.guarded = Some(Guarded::Delete);
            app.ask_owner(
                OwnerRequest::DeleteConnectAccount {
                    account_id: account.account_id,
                },
                Some(ctx),
            );
        }
        (Sheet::ForgetRemoved, SheetChoice::Go) => {
            // Only the owner's confirmation deletes the key and the account file here.
            let (Some(store), Some(path)) =
                (app.ui.connect.live.store(), app.ui.connect.live.path())
            else {
                app.ui.connect.live.error = Some(message(&ConnectError::KeychainUnavailable));
                return;
            };
            let session = app.ui.connect.live.session();
            app.ui.connect.live.spawn(ctx, move || {
                drop(session.take_any());
                Outcome::Forgot(forget_this_device(store.as_ref(), &path))
            });
        }
        (Sheet::DeviceAdded { .. } | Sheet::Joined | Sheet::JoinSent { .. }, _) => {
            refresh(app, ctx);
        }
        // Cancel, Done, OK, and Close of every other sheet: it closes.
        _ => {}
    }
}
