//! The vault build of Settings > Connect: the account of this Mac (`crate::connect`) on
//! worker threads, the polling of the checkout and of the device links, and the owner
//! checks.
//!
//! - One step at a time runs on a worker ([`Task`]); the UI thread never waits on the
//!   network and never holds the account lock.
//! - The account file is read on the UI thread (a small file, no secret). The account
//!   key is read from the Keychain (Touch ID) only on "Sign In…", after the creation, or
//!   after this Mac joined an account. A lock or a new unlock drops the account from
//!   memory.
//! - A step that needs the owner check asks for it with an [`OwnerRequest`]; the owner
//!   flows keep the proof until [`OwnerFlows::take_connect_proof`] takes it here, once,
//!   and the account checks it again against the exact action before it calls Connect.
//!
//! [`OwnerFlows::take_connect_proof`]: crate::desktop::owner_check::OwnerFlows::take_connect_proof

use std::cell::OnceCell;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use eframe::egui;
use zeroize::Zeroizing;

use super::{
    Account, Action, ConnectView, DELETED, Device, Group, JOIN_POLL_EVERY, Member, Offer,
    POLL_EVERY, Plan, Plans, Price, Sheet, SheetChoice, Shown, WAIT_AT_MOST,
};
use crate::broker::approvals::{ConnectGroupChange, OwnerProof};
use crate::connect::{
    AccountState, AccountView, CheckoutRequest, ConnectAccount, ConnectClient, ConnectError,
    DeviceKeyStore, DeviceLink, Forgotten, GroupDetail, JoinPoll, JoinRequest,
    KeychainDeviceKeyStore, PendingJoin, PlansView, account_file, drop_account_rows,
    forget_this_device,
};
use crate::desktop::DesktopApp;
use crate::desktop::owner_check::{OwnerRequest, Task, TaskPoll};

type Slot<T> = Arc<Mutex<Option<T>>>;

fn slot<T>() -> Slot<T> {
    Arc::new(Mutex::new(None))
}

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
}

/// The result of one worker step.
enum Outcome {
    Opened(Result<AccountState, ConnectError>),
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
    /// A revoke: `Some` when this Mac revoked itself.
    Revoked(Result<Option<Forgotten>, ConnectError>),
    Deleted(Result<Forgotten, ConnectError>),
    Invited(Result<(String, u64), ConnectError>),
    JoinedGroup(Result<String, ConnectError>),
    GroupChanged(Result<String, ConnectError>),
    JoinStarted(Result<(String, String), ConnectError>),
    /// A poll of this Mac's join: `None` waits, `Some(state)` is confirmed.
    JoinPolled(Result<Option<AccountState>, ConnectError>),
    JoinCancelled,
    /// Connect said this Mac is no longer a device of its account: it was forgotten here.
    Gone(Option<Forgotten>, String),
}

/// The checkout that the waiting sheet follows.
#[derive(Debug, Clone)]
struct Waiting {
    started: Instant,
    polled: Option<Instant>,
}

/// The vault build's part of the section state.
#[derive(Default)]
pub(crate) struct Live {
    account: Slot<ConnectAccount>,
    /// The account is in memory (in `account`).
    open: bool,
    /// The account file, read once (again after a change).
    file: OnceCell<Option<AccountState>>,
    snapshot: Option<Snapshot>,
    plans: Option<Plans>,
    task: Option<Task<Outcome>>,
    error: Option<String>,
    /// The vault session that the account belongs to.
    epoch: Option<Option<[u8; 32]>>,
    pub(crate) guarded: Option<Guarded>,
    waiting: Option<Waiting>,
    link: Slot<DeviceLink>,
    pending: Vec<PendingJoin>,
    pending_at: Option<Instant>,
    join: Slot<JoinRequest>,
    join_at: Option<Instant>,
    /// Tests: the key store, the data directory, and the Connect origin. Without a data
    /// directory a test never reads the real account file.
    pub(crate) store: Option<Arc<dyn DeviceKeyStore>>,
    pub(crate) dir: Option<PathBuf>,
    pub(crate) origin: Option<String>,
    /// Tests: shorter polls than [`POLL_EVERY`] and [`JOIN_POLL_EVERY`].
    pub(crate) poll_every: Option<Duration>,
    pub(crate) join_poll_every: Option<Duration>,
}

impl Live {
    fn path(&self) -> Option<PathBuf> {
        match &self.dir {
            Some(dir) => Some(account_file(dir)),
            #[cfg(not(test))]
            None => Some(account_file(&crate::paths::data_dir())),
            #[cfg(test)]
            None => None,
        }
    }

    fn file(&self) -> Option<&AccountState> {
        self.file
            .get_or_init(|| {
                self.path()
                    .and_then(|path| AccountState::load(&path).ok().flatten())
            })
            .as_ref()
    }

    fn client(&self) -> Result<ConnectClient, ConnectError> {
        match &self.origin {
            Some(origin) => ConnectClient::new(origin),
            None => ConnectClient::configured(),
        }
    }

    fn busy(&self) -> bool {
        self.task.is_some()
    }

    /// Forget the account in memory, and read the account file again.
    fn reset(&mut self) {
        self.account = slot();
        self.open = false;
        self.file = OnceCell::new();
        self.snapshot = None;
        self.guarded = None;
        self.waiting = None;
        self.link = slot();
        self.pending.clear();
        self.join = slot();
    }

    /// The poll intervals.
    fn poll_every(&self) -> Duration {
        self.poll_every.unwrap_or(POLL_EVERY)
    }

    fn join_poll_every(&self) -> Duration {
        self.join_poll_every.unwrap_or(JOIN_POLL_EVERY)
    }

    /// Run `work` with the account on a worker thread.
    fn spawn(&mut self, ctx: &egui::Context, work: impl FnOnce() -> Outcome + Send + 'static) {
        self.error = None;
        self.task = Some(Task::spawn(Some(ctx.clone()), work));
    }

    fn with_account(
        &mut self,
        ctx: &egui::Context,
        work: impl FnOnce(&mut ConnectAccount) -> Outcome + Send + 'static,
    ) {
        let account = Arc::clone(&self.account);
        self.spawn(ctx, move || {
            let mut guard = account
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match guard.as_mut() {
                Some(account) => work(account),
                None => Outcome::Opened(Err(ConnectError::SignedOut)),
            }
        });
    }
}

/// The key store of this Mac: the Keychain through the signed helper, or the store of a
/// test.
fn store(app: &DesktopApp) -> Option<Arc<dyn DeviceKeyStore>> {
    if let Some(store) = &app.ui.connect.live.store {
        return Some(Arc::clone(store));
    }
    app.owner
        .helper
        .clone()
        .map(|helper| Arc::new(KeychainDeviceKeyStore::new(helper)) as Arc<dyn DeviceKeyStore>)
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
            name: device.name.clone(),
            platform: device.platform.clone(),
            created_at: device.created_at,
            last_seen_at: device.last_seen_at,
            this: device.device_id == this_device,
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
    Account {
        account_id: view.account_id.clone(),
        name: view.name.clone(),
        email: view.email.clone(),
        plan: plan_of(&view.plan),
        devices,
        group,
    }
}

/// The view of the section now.
pub(crate) fn view(app: &DesktopApp) -> ConnectView {
    let live = &app.ui.connect.live;
    let file = live.file();
    let shown = match (&live.snapshot, file) {
        (Some(snapshot), Some(state)) if live.open => {
            Shown::Account(account_of(snapshot, &state.device_id))
        }
        (_, Some(state)) if live.open && live.busy() => Shown::Loading {
            name: state.name.clone(),
        },
        (_, Some(state)) => Shown::SignedOut {
            name: state.name.clone(),
            device_name: state.device_name.clone(),
        },
        (_, None) => Shown::None,
    };
    ConnectView {
        shown,
        plans: live.plans.clone(),
        locked: app.owner_ui.session.epoch().is_none(),
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

/// The steps of one frame: the vault session, the result of the worker, the owner
/// proof, and the polls.
pub(crate) fn step(app: &mut DesktopApp, ctx: &egui::Context) {
    let epoch = app.owner_ui.session.epoch();
    let live = &mut app.ui.connect.live;
    match live.epoch {
        Some(seen) if seen != epoch => {
            // A lock or another unlock: the key and the token leave memory.
            if let Ok(mut account) = live.account.try_lock()
                && let Some(account) = account.as_mut()
            {
                account.sign_out();
            }
            live.reset();
            app.ui.connect.sheet = None;
        }
        _ => {}
    }
    app.ui.connect.live.epoch = Some(epoch);
    finish(app, ctx);
    guarded(app, ctx);
    polls(app, ctx);
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
    if !live.open || live.busy() {
        return;
    }
    let want_plans = live.plans.is_none();
    let store = store(app);
    let path = app.ui.connect.live.path();
    app.ui.connect.live.with_account(ctx, move |account| {
        let snapshot = account.view().and_then(|view| {
            let group = if view.group.is_some() {
                account.group()?
            } else {
                None
            };
            Ok(Snapshot { view, group })
        });
        match snapshot {
            Ok(snapshot) => {
                let plans = want_plans.then(|| account.client().plans().ok()).flatten();
                Outcome::Refreshed(Ok((snapshot, plans)))
            }
            Err(error @ ConnectError::Revoked) => gone(store.as_deref(), path, &error),
            Err(error) => Outcome::Refreshed(Err(error)),
        }
    });
}

/// This Mac is no longer a device of its account: forget it here.
fn gone(
    store: Option<&dyn DeviceKeyStore>,
    path: Option<PathBuf>,
    error: &ConnectError,
) -> Outcome {
    let forgotten = match (store, path) {
        (Some(store), Some(path)) => forget_this_device(store, &path).ok(),
        _ => None,
    };
    Outcome::Gone(forgotten, message(error))
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
        Outcome::Opened(Ok(_)) => {
            live.open = true;
            live.file = OnceCell::new();
            refresh(app, ctx);
        }
        Outcome::Created(Ok((_, words))) => {
            live.open = true;
            live.file = OnceCell::new();
            app.ui.connect.sheet = Some(Sheet::Recovery { words });
        }
        Outcome::Refreshed(Ok((snapshot, plans))) => {
            live.snapshot = Some(snapshot);
            if let Some(plans) = plans {
                live.plans = Some(plans_of(&plans));
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
            app.ui.connect.live.reset();
            app.set_ok("This Mac left the Connect account.");
        }
        Outcome::Revoked(Ok(None)) => {
            app.set_ok("The device is revoked.");
            refresh(app, ctx);
        }
        Outcome::Deleted(Ok(forgotten)) => {
            drop_rows(app, &forgotten);
            app.ui.connect.live.reset();
            app.ui.connect.sheet = None;
            app.set_ok(DELETED);
        }
        Outcome::Deleted(Err(error)) => {
            // The account left memory with the call: read it again from the file.
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
            live.open = true;
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
        Outcome::Gone(forgotten, text) => {
            if let Some(forgotten) = forgotten {
                drop_rows(app, &forgotten);
            }
            app.ui.connect.live.reset();
            app.ui.connect.sheet = None;
            app.ui.connect.live.error = Some(text);
        }
        Outcome::Polled(Err(error)) => {
            // A failed poll waits for the next one; it is not the owner's problem yet.
            if let Some(waiting) = &mut live.waiting {
                waiting.polled = Some(Instant::now());
            }
            let _ = error;
        }
        Outcome::Opened(Err(error))
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
            if error == ConnectError::Revoked {
                let store = store(app);
                let path = app.ui.connect.live.path();
                if let Outcome::Gone(forgotten, text) = gone(store.as_deref(), path, &error) {
                    apply(app, ctx, Outcome::Gone(forgotten, text));
                }
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
    let store = store(app);
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
        Guarded::Delete => {
            let account = Arc::clone(&live.account);
            live.spawn(ctx, move || {
                let taken = account
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take();
                let (Some(account), Some(store)) = (taken, store) else {
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
        let target = Arc::clone(&live.account);
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
                    *target
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(*account);
                    Outcome::JoinPolled(Ok(Some(state)))
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
    }
}

/// Read the account key (Touch ID) and open the account; or refresh an open account.
fn sign_in(app: &mut DesktopApp, ctx: &egui::Context) {
    if app.ui.connect.live.open {
        refresh(app, ctx);
        return;
    }
    let Some(store) = store(app) else {
        app.ui.connect.live.error = Some(message(&ConnectError::KeychainUnavailable));
        return;
    };
    let Some(path) = app.ui.connect.live.path() else {
        return;
    };
    let account = Arc::clone(&app.ui.connect.live.account);
    app.ui.connect.live.spawn(ctx, move || {
        Outcome::Opened(match ConnectAccount::open(store.as_ref(), &path) {
            Ok(Some(opened)) => {
                let state = opened.state().clone();
                *account
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(opened);
                Ok(state)
            }
            Ok(None) => Err(ConnectError::NoAccount),
            Err(error) => Err(error),
        })
    });
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
            let (Some(store), Some(path)) = (store(app), app.ui.connect.live.path()) else {
                app.ui.connect.live.error = Some(message(&ConnectError::KeychainUnavailable));
                app.ui.connect.sheet = Some(Sheet::Create { name, device_name });
                return;
            };
            let client = app.ui.connect.live.client();
            let slot = Arc::clone(&app.ui.connect.live.account);
            let (typed, device) = (name.clone(), device_name.clone());
            app.ui.connect.live.spawn(ctx, move || {
                Outcome::Created(client.and_then(|client| {
                    let (account, recovery) =
                        ConnectAccount::create(client, store.as_ref(), &path, &typed, &device)?;
                    let state = account.state().clone();
                    *slot
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(account);
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
                    this_device: this,
                },
                Some(ctx),
            );
        }
        (Sheet::JoinAccount { code }, SheetChoice::Go) => {
            let (Some(store), Some(path)) = (store(app), app.ui.connect.live.path()) else {
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
        (Sheet::DeviceAdded { .. } | Sheet::Joined | Sheet::JoinSent { .. }, _) => {
            refresh(app, ctx);
        }
        // Cancel, Done, OK, and Close of every other sheet: it closes.
        _ => {}
    }
}
