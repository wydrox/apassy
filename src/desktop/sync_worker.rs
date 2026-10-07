//! Folder and relay sync in the background (ADR 0014 and ADR 0022,
//! docs/operations/sync.md section 4).
//!
//! One worker thread owns the schedule of the sync of the open vault. It runs also when
//! the window is hidden, minimized, or covered, or when the display sleeps: the window
//! draws no frame then, so the schedule must not depend on one.
//!
//! What it does, in each step ([`SyncWorker::tick`]):
//!
//! - every [`LOCAL_EVERY`] it looks for a change of a credential in the open, unlocked
//!   vault, and pushes it [`SETTLE`] after it first saw it;
//! - every [`CHECK_EVERY`] (every [`DOWNLOAD_EVERY`] while iCloud downloads the file of
//!   the open vault) it reads the status of each synced vault of the list, asks iCloud
//!   once for a download, and merges the synced file of the open vault when it changed.
//!
//! A vault that syncs through the relay has no file to look at. The worker pulls it at
//! the first step after an unlock, every [`RELAY_PULL_EVERY`] as a fallback, at the
//! retry time after a failed pull, and at once when the waiter thread hears of a new
//! version: the waiter holds a long poll on the
//! relay (`GET /v1/sync/head?wait=25`) while the open vault is unlocked and its device
//! key is in memory. A lock drops the key and the access token and ends the relay calls
//! in flight, the long poll and a download or an upload of the worker
//! ([`crate::sync::RelaySync::forget`]): the window does it at the lock, and the worker
//! looks at the lock every [`LOCK_CHECK_EVERY`] while the key is in memory.
//!
//! Nothing spins on the relay. A relay sync that fails waits 5 seconds, then 10, 20,
//! 40, and 60 (at least 60 after a `429`), whatever asks for it; a command of the window
//! starts again at once. The waiter signals one version once: when the relay still
//! answers at once with the same versions (the pull failed, a run waits for the owner,
//! or the relay answers every poll at once), it waits 5 seconds, then doubles up to 60.
//!
//! A Mac that another Mac removed from the relay stops at once
//! ([`crate::sync::RelaySync::is_removed`]): the first refusal, of the waiter or of a
//! sync, shows "Removed from the relay" for that vault, and the waiter asks the relay
//! about it no more. The worker asks once more only at
//! [`crate::sync::RelaySync::removed_until`] (every 15 minutes), since a suspended relay
//! refuses the same way; a sync that works then clears the status and the waiter goes
//! on. Turning relay sync off or joining again ends it too. Folder sync and the other
//! vaults go on.
//! The relay steps of a sync run without the vault mutex
//! ([`crate::sync::RelaySync::sync_shared`]): the window and the agent broker keep the
//! vault during a download or an upload.
//!
//! It syncs only the open vault that the window tracks, only while that vault is
//! unlocked, and never while an agent run waits for the owner. The window reads the
//! statuses and takes the events ([`SyncEvent`]) in each frame; it shows them, and it
//! does no sync I/O for the schedule.
//!
//! Lock order. A folder sync takes the sync op lock ([`SyncWorker::op_lock`]) first and
//! the vault mutex second, here and in the window (`sync_quietly`, `sync_enable`,
//! `sync_disable`, `sync_take_passphrase`, `sync_replace_damaged`, `sync_open_vault`).
//! A relay sync never takes the op lock, so the window never waits for the network: it
//! takes the guard of its own vault ([`crate::sync::RelaySync`], one relay sync of a
//! vault at a time) and then the vault mutex, only for each local step. "Turn off"
//! takes that guard with [`crate::sync::RelaySync::stop_runs`], which ends the relay
//! calls of the sync that runs, then the op lock, then the vault mutex. The step before
//! a lock ([`crate::desktop::owner_store::BeforeLock`]) runs with the vault mutex held:
//! it never takes the op lock, it does not wait for a relay sync that runs (it skips its
//! push, and the change goes up after the next unlock), and its relay calls end within
//! [`BEFORE_LOCK_LIMIT`]. The worker holds its schedule mutex for a whole step, outside
//! all of them; the window never takes it. The plan, output, and wake mutexes are taken
//! last, one at a time, and only for a copy.
//!
//! The waiter thread never takes the op lock or the schedule mutex. It takes the plan
//! mutex for a copy, then the vault mutex alone and only to see whether the vault is
//! unlocked. It waits on the relay with no lock held, then sets the pull flag and takes
//! the wake mutex, or takes the output mutex alone to show a removal. Its own sleep uses
//! the waiter mutex, which nothing else holds with another lock.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use eframe::egui;

use crate::broker::SharedVault;
use crate::broker::approvals::ApprovalQueue;
use crate::sync::{
    FileStatus, FolderSync, RelayPoll, RelayRefusal, RelaySync, SyncError, SyncOutcome, VaultSync,
};
use crate::vault::{Vault, VaultErrorKind};

/// How often the worker looks at the synced file of each vault.
pub(crate) const CHECK_EVERY: Duration = Duration::from_secs(30);
/// How often it looks again while iCloud downloads the file of the open vault.
pub(crate) const DOWNLOAD_EVERY: Duration = Duration::from_secs(2);
/// How often it looks for a change of a credential in the open vault.
pub(crate) const LOCAL_EVERY: Duration = Duration::from_secs(3);
/// A change of a credential syncs this long after the worker first saw it: 5 to 8
/// seconds after the change.
pub(crate) const SETTLE: Duration = Duration::from_secs(5);
/// How often the worker pulls the open vault from the relay when the waiter hears
/// nothing: a fallback for a long poll that missed a push.
pub(crate) const RELAY_PULL_EVERY: Duration = Duration::from_secs(5 * 60);
/// The long poll of the waiter (the relay holds at most 25 seconds).
const RELAY_WAIT: Duration = Duration::from_secs(25);
/// The first wait after a failed relay sync, or of the waiter after an error or an
/// answer that brought nothing new. It doubles up to [`RELAY_RETRY_MAX`].
const RELAY_RETRY_FIRST: Duration = Duration::from_secs(5);
const RELAY_RETRY_MAX: Duration = Duration::from_secs(60);
/// The shortest wait after a `429` of the relay (`Retry-After: 60`).
const RELAY_RATE_WAIT: Duration = Duration::from_secs(60);
/// How often the worker looks at the lock while the device key is in memory, so that a
/// lock drops the key and ends the long poll soon.
pub(crate) const LOCK_CHECK_EVERY: Duration = Duration::from_secs(1);
/// How long the waiter sleeps while there is nothing to wait for.
const RELAY_IDLE: Duration = Duration::from_secs(2);
/// The shortest wait of the thread between two steps.
const MIN_WAIT: Duration = Duration::from_millis(200);
/// The longest wait of a stop for a step that runs. A relay transfer ends at once at the
/// stop; a step that still runs after this ends on its own.
const STOP_WAIT: Duration = Duration::from_secs(5);
/// The relay calls of the step before a lock end within this time.
pub(crate) const BEFORE_LOCK_LIMIT: Duration = Duration::from_secs(10);
/// The most events that wait for a frame. A hidden window can draw none for hours.
const MAX_EVENTS: usize = 32;

/// The lock around each sync operation that changes files. Take it before the vault
/// mutex.
pub(crate) type SyncOpLock = Arc<Mutex<()>>;

/// The status of a synced vault in plain words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UiStatus {
    /// Up to date. The time of the last sync, in Unix seconds.
    UpToDate(Option<u64>),
    /// A change waits to sync, on this Mac or in the folder.
    Syncing,
    /// iCloud has not downloaded the synced file to this Mac yet.
    Waiting,
    /// The synced file has a new passphrase from another Mac.
    NeedsPassphrase,
    /// The synced folder is not there.
    FolderUnavailable,
    /// The synced file is damaged.
    Damaged,
    /// Another problem, in words.
    Problem(String),
}

impl UiStatus {
    pub(crate) fn from_error(err: SyncError) -> Self {
        match err {
            SyncError::NotDownloaded => Self::Waiting,
            SyncError::NeedsPassphrase => Self::NeedsPassphrase,
            SyncError::FolderUnavailable => Self::FolderUnavailable,
            SyncError::Damaged => Self::Damaged,
            other => Self::Problem(other.to_string()),
        }
    }

    pub(crate) fn from_file(status: FileStatus, last: Option<u64>) -> Self {
        match status {
            FileStatus::UpToDate => Self::UpToDate(last),
            FileStatus::Changed | FileStatus::Missing => Self::Syncing,
            FileStatus::NotDownloaded => Self::Waiting,
            FileStatus::FolderUnavailable => Self::FolderUnavailable,
        }
    }
}

/// What a sync of the worker means for the window. Each event names the vault (its list
/// ID); the window drops an event about a vault that is not open any more.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SyncEvent {
    /// A sync finished. Its merge can have kept conflict copies or skipped variables.
    Synced { id: String, outcome: SyncOutcome },
    /// A failure for a note. The window shows the same text once.
    Failure { id: String, text: String },
    /// The passphrase changed on another Mac.
    NeedsPassphrase(String),
    /// The synced file is damaged.
    Damaged(String),
}

/// What the window hands to the worker.
#[derive(Default)]
struct Plan {
    /// Grows with each change of the open vault, and after a sync of the window. The
    /// next step starts its schedule again.
    generation: u64,
    /// The list ID and the sync of the open vault, when sync is on for it.
    open: Option<(String, VaultSync)>,
    /// Each synced vault of the list.
    synced: Vec<(String, VaultSync)>,
    /// The vault slot of the session.
    vault: Option<SharedVault>,
    /// The runs that wait for the owner.
    approvals: Option<Arc<ApprovalQueue>>,
}

/// The schedule. Only a step holds it.
#[derive(Default)]
struct Schedule {
    generation: u64,
    next_check: Option<Instant>,
    next_local_check: Option<Instant>,
    /// A change of a credential that waits to sync, and when the worker saw it.
    changed_since: Option<Instant>,
    /// List IDs of vaults for which the worker asked iCloud for a download.
    downloads: BTreeSet<String>,
    /// When the worker pulls the open vault from the relay next. `None`: at once.
    next_relay_pull: Option<Instant>,
    /// Relay syncs that failed in a row, and when the next one may run.
    relay_failures: u32,
    relay_retry_at: Option<Instant>,
}

/// What the window reads.
#[derive(Default)]
struct Output {
    /// The status of each synced vault of the list, by list ID.
    statuses: BTreeMap<String, UiStatus>,
    /// A change of a credential in the open vault waits to sync.
    change_waits: bool,
    events: Vec<SyncEvent>,
}

impl Output {
    /// Queue an event for the window. The oldest goes when the queue is full.
    fn push(&mut self, event: SyncEvent) {
        if self.events.len() >= MAX_EVENTS {
            self.events.remove(0);
        }
        self.events.push(event);
    }
}

#[derive(Default)]
struct Shared {
    op: SyncOpLock,
    plan: Mutex<Plan>,
    schedule: Mutex<Schedule>,
    out: Mutex<Output>,
    /// Set by a command of the window. The thread resets it.
    wake: Mutex<bool>,
    woken: Condvar,
    stop: AtomicBool,
    repaint: Mutex<Option<egui::Context>>,
    /// Set by the waiter: the relay has a new version of the open vault.
    pull: AtomicBool,
    /// The last relay sync of the open vault failed, and the next waits
    /// ([`relay_backoff`]). The step before a lock then does not push.
    relay_backoff: Arc<AtomicBool>,
    /// Wakes the waiter: a stop, or another open vault. The waiter resets it.
    waiter_wake: Mutex<bool>,
    waiter_woken: Condvar,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn is_unlocked(vault: &SharedVault) -> bool {
    lock(vault).as_ref().is_some_and(|open| !open.is_locked())
}

/// The vault in the slot is the one of `sync`. A switch can change the slot just
/// before the window tracks the new vault.
fn same_vault(sync: &VaultSync, vault: &Vault) -> bool {
    std::fs::canonicalize(sync.vault_path()).is_ok_and(|path| path == vault.path())
}

fn runs_wait(approvals: Option<&Arc<ApprovalQueue>>) -> bool {
    approvals.is_some_and(|queue| !queue.pending().is_empty())
}

/// The wait after `failures` failed relay syncs in a row: 5 seconds, doubling up to 60.
fn relay_backoff(failures: u32) -> Duration {
    let doublings = failures.saturating_sub(1).min(4);
    (RELAY_RETRY_FIRST * 2u32.pow(doublings)).min(RELAY_RETRY_MAX)
}

impl Shared {
    fn wake(&self) {
        *lock(&self.wake) = true;
        self.woken.notify_all();
    }

    fn wake_waiter(&self) {
        *lock(&self.waiter_wake) = true;
        self.waiter_woken.notify_all();
    }

    /// The waiter waits for a wake or `interval`. Returns false after `stop`.
    fn waiter_sleep(&self, interval: Duration) -> bool {
        let guard = lock(&self.waiter_wake);
        let (mut guard, _) = self
            .waiter_woken
            .wait_timeout_while(guard, interval, |woken| {
                !*woken && !self.stop.load(Ordering::SeqCst)
            })
            .unwrap_or_else(PoisonError::into_inner);
        *guard = false;
        !self.stop.load(Ordering::SeqCst)
    }

    /// Wait for a command or `interval`. Returns false after `stop`.
    fn sleep(&self, interval: Duration) -> bool {
        let guard = lock(&self.wake);
        let (mut guard, _) = self
            .woken
            .wait_timeout_while(guard, interval, |woken| {
                !*woken && !self.stop.load(Ordering::SeqCst)
            })
            .unwrap_or_else(PoisonError::into_inner);
        *guard = false;
        !self.stop.load(Ordering::SeqCst)
    }

    fn repaint(&self) {
        if let Some(ctx) = lock(&self.repaint).as_ref() {
            ctx.request_repaint();
        }
    }

    /// Start the schedule again after a command of the window.
    fn catch_up(&self, schedule: &mut Schedule, generation: u64) {
        if schedule.generation != generation {
            *schedule = Schedule {
                generation,
                downloads: std::mem::take(&mut schedule.downloads),
                ..Schedule::default()
            };
            self.relay_backoff.store(false, Ordering::SeqCst);
            lock(&self.out).change_waits = false;
        }
    }

    /// One step: see [`SyncWorker::tick`].
    fn tick(&self, now: Instant) -> Option<Instant> {
        let mut schedule = lock(&self.schedule);
        let (generation, open, vault, approvals) = {
            let plan = lock(&self.plan);
            (
                plan.generation,
                plan.open.clone(),
                plan.vault.clone(),
                plan.approvals.clone(),
            )
        };
        self.catch_up(&mut schedule, generation);
        let unlocked = vault.as_ref().is_some_and(is_unlocked);
        let relay = open.as_ref().and_then(|(_, sync)| sync.as_relay());
        if let Some(relay) = relay
            && !unlocked
        {
            // A lock ends the waiter and drops the token (contract section 5).
            relay.forget();
            self.pull.store(false, Ordering::SeqCst);
        }
        let waits = runs_wait(approvals.as_ref());
        // A removed Mac asks the relay only at its next try (contract section 13).
        let removed_until = relay.and_then(RelaySync::removed_until);
        let removed = removed_until.is_some_and(|until| now < until);
        if removed_until.is_some()
            && let Some((id, _)) = &open
        {
            self.show_removed(id);
        }
        if removed {
            self.pull.store(false, Ordering::SeqCst);
        }
        // A failed relay sync waits for its time, whatever asks for it.
        let relay_due =
            relay.is_none() || (!removed && schedule.relay_retry_at.is_none_or(|at| now >= at));
        // A relay pull: the waiter heard of a new version, or its time came (the first
        // step after an unlock, the retry after a failure, or RELAY_PULL_EVERY). The pull
        // flag stays set while a run waits or the relay sync backs off.
        if unlocked
            && relay.is_some()
            && !waits
            && relay_due
            && (self.pull.swap(false, Ordering::SeqCst)
                || schedule.next_relay_pull.is_none_or(|at| now >= at))
            && let (Some((id, sync)), Some(vault)) = (&open, &vault)
        {
            self.sync_open(now, &mut schedule, id, sync, vault);
        }
        if unlocked
            && let (Some((_, sync)), Some(vault)) = (&open, &vault)
            && schedule.next_local_check.is_none_or(|at| now >= at)
        {
            schedule.next_local_check = Some(now + LOCAL_EVERY);
            let changed = {
                let slot = lock(vault);
                slot.as_ref()
                    .filter(|open| !open.is_locked() && same_vault(sync, open))
                    .and_then(|open| sync.local_changed(open).ok())
                    .unwrap_or(false)
            };
            match (changed, schedule.changed_since) {
                (true, None) => schedule.changed_since = Some(now),
                (false, Some(_)) => schedule.changed_since = None,
                _ => {}
            }
            let waits = schedule.changed_since.is_some();
            let before = std::mem::replace(&mut lock(&self.out).change_waits, waits);
            if before != waits {
                self.repaint();
            }
        }
        let settled = schedule
            .changed_since
            .is_some_and(|since| now.saturating_duration_since(since) >= SETTLE);
        let relay_due =
            relay.is_none() || (!removed && schedule.relay_retry_at.is_none_or(|at| now >= at));
        if settled
            && unlocked
            && !waits
            && relay_due
            && let (Some((id, sync)), Some(vault)) = (&open, &vault)
        {
            self.sync_open(now, &mut schedule, id, sync, vault);
        }
        if schedule.next_check.is_none_or(|at| now >= at) {
            self.check(now, &mut schedule, open.as_ref(), vault.as_ref(), approvals);
        }
        let unlocked = vault.as_ref().is_some_and(is_unlocked);
        let local = schedule
            .next_local_check
            .filter(|_| open.is_some() && unlocked);
        // A pull time that passed waits for a run of the owner: the next step after it
        // comes from the other times, not every MIN_WAIT.
        let relay_pull = schedule
            .next_relay_pull
            .filter(|at| relay.is_some() && !removed && unlocked && *at > now);
        // The next try of a removed Mac.
        let removed_try = removed_until.filter(|at| unlocked && *at > now);
        // While the key is in memory, a lock must drop it soon.
        let lock_check = relay
            .filter(|relay| relay.has_session())
            .map(|_| now + LOCK_CHECK_EVERY);
        [
            schedule.next_check,
            local,
            relay_pull,
            removed_try,
            lock_check,
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// One look at the synced files: the statuses, a download request, and a sync of
    /// the open vault when its file changed.
    fn check(
        &self,
        now: Instant,
        schedule: &mut Schedule,
        open: Option<&(String, VaultSync)>,
        vault: Option<&SharedVault>,
        approvals: Option<Arc<ApprovalQueue>>,
    ) {
        self.refresh();
        // "Synced 2 minutes ago" changes with the time.
        self.repaint();
        let status = open.and_then(|(id, _)| lock(&self.out).statuses.get(id).cloned());
        schedule.next_check = Some(
            now + if status == Some(UiStatus::Waiting) {
                DOWNLOAD_EVERY
            } else {
                CHECK_EVERY
            },
        );
        let (Some((id, any_sync)), Some(vault)) = (open, vault) else {
            return;
        };
        let sync = match any_sync {
            VaultSync::Folder(sync) => sync,
            // No file to look at: the step pulls it at its own times (`tick`).
            VaultSync::Relay(_) => return,
        };
        if status != Some(UiStatus::Waiting) {
            schedule.downloads.remove(id);
        } else if schedule.downloads.insert(id.clone()) {
            let _ = sync.request_download();
        }
        let unlocked = is_unlocked(vault);
        let file_moved = matches!(
            sync.status().map(|report| report.status),
            Ok(FileStatus::Changed | FileStatus::Missing)
        );
        if unlocked && file_moved && !runs_wait(approvals.as_ref()) {
            self.sync_open(now, schedule, id, any_sync, vault);
        }
    }

    /// Sync the open vault, when it is unlocked. A result for the owner becomes an
    /// event. A relay sync holds the vault mutex only for its local steps and never the
    /// op lock; a failed one waits before the next ([`relay_backoff`]), and the same
    /// failure again makes no new event.
    fn sync_open(
        &self,
        now: Instant,
        schedule: &mut Schedule,
        id: &str,
        sync: &VaultSync,
        vault: &SharedVault,
    ) {
        let result = match sync {
            VaultSync::Relay(_) => sync.sync_shared(vault, |open| same_vault(sync, open)),
            VaultSync::Folder(_) => {
                let _op = lock(&self.op);
                sync.sync_shared(vault, |open| same_vault(sync, open))
            }
        };
        if result == Err(SyncError::Vault(VaultErrorKind::Locked)) {
            // The vault locked or changed: nothing to tell.
            return;
        }
        let relay = sync.as_relay().is_some();
        if relay {
            match result {
                Ok(_) => {
                    schedule.relay_failures = 0;
                    schedule.relay_retry_at = None;
                    schedule.next_relay_pull = Some(now + RELAY_PULL_EVERY);
                    self.relay_backoff.store(false, Ordering::SeqCst);
                }
                Err(SyncError::RemovedFromRelay)
                    if sync.as_relay().is_some_and(RelaySync::is_removed) =>
                {
                    // The next try of a removed Mac has a time of its own
                    // (`RelaySync::removed_until`).
                    self.relay_backoff.store(true, Ordering::SeqCst);
                    schedule.relay_failures = 0;
                    schedule.relay_retry_at = None;
                    schedule.next_relay_pull = None;
                }
                Err(err) => {
                    self.relay_backoff.store(true, Ordering::SeqCst);
                    schedule.relay_failures = schedule.relay_failures.saturating_add(1);
                    let mut wait = relay_backoff(schedule.relay_failures);
                    if err == SyncError::Relay(RelayRefusal::RateLimited) {
                        wait = wait.max(RELAY_RATE_WAIT);
                    }
                    schedule.relay_retry_at = Some(now + wait);
                    schedule.next_relay_pull = Some(now + wait);
                }
            }
        }
        schedule.changed_since = None;
        schedule.next_local_check = None;
        let last = result.is_ok().then(|| {
            sync.state()
                .ok()
                .flatten()
                .and_then(|state| state.last_sync_at)
        });
        let id = id.to_owned();
        {
            let mut out = lock(&self.out);
            out.change_waits = false;
            match result {
                Ok(outcome) => {
                    out.statuses
                        .insert(id.clone(), UiStatus::UpToDate(last.flatten()));
                    out.push(SyncEvent::Synced { id, outcome });
                }
                Err(err) => {
                    let status = UiStatus::from_error(err);
                    let before = out.statuses.insert(id.clone(), status.clone());
                    if relay && before.as_ref() == Some(&status) {
                        // The same failure again: the window has said it.
                    } else {
                        match err {
                            SyncError::NeedsPassphrase => {
                                out.push(SyncEvent::NeedsPassphrase(id));
                            }
                            SyncError::Damaged => out.push(SyncEvent::Damaged(id)),
                            SyncError::FolderUnavailable
                            | SyncError::NotDownloaded
                            | SyncError::RelayUnreachable
                            | SyncError::RelayBusy => {}
                            other => out.push(SyncEvent::Failure {
                                id,
                                text: format!("Sync: {other}."),
                            }),
                        }
                    }
                }
            }
        }
        self.repaint();
    }

    /// The relay refused the device of the vault `id`: show "Removed from the relay" for
    /// it, once, with a note. The step before a lock does not push to it.
    fn show_removed(&self, id: &str) {
        self.relay_backoff.store(true, Ordering::SeqCst);
        let status = UiStatus::from_error(SyncError::RemovedFromRelay);
        let shown = {
            let mut out = lock(&self.out);
            let before = out.statuses.insert(id.to_owned(), status.clone());
            let shown = before.as_ref() != Some(&status);
            if shown {
                out.push(SyncEvent::Failure {
                    id: id.to_owned(),
                    text: format!("Sync: {}.", SyncError::RemovedFromRelay),
                });
            }
            shown
        };
        if shown {
            self.repaint();
        }
    }

    /// See [`SyncWorker::refresh`].
    fn refresh(&self) {
        let (synced, open) = {
            let plan = lock(&self.plan);
            (
                plan.synced.clone(),
                plan.open.as_ref().map(|(id, _)| id.clone()),
            )
        };
        let previous = lock(&self.out).statuses.clone();
        let mut statuses = BTreeMap::new();
        for (id, sync) in synced {
            let kept = previous.get(&id).filter(|status| {
                matches!(
                    status,
                    UiStatus::NeedsPassphrase | UiStatus::Damaged | UiStatus::Problem(_)
                )
            });
            let status = match &sync {
                VaultSync::Folder(sync) => match (kept, sync.status()) {
                    (Some(kept), Ok(report)) if report.status == FileStatus::UpToDate => {
                        kept.clone()
                    }
                    (_, Ok(report)) => UiStatus::from_file(report.status, report.last_sync_at),
                    (_, Err(err)) => UiStatus::from_error(err),
                },
                // The relay status needs the key: the last known state, or the result
                // of the last sync of the worker.
                VaultSync::Relay(sync) => match (kept, sync.state()) {
                    (Some(kept), Ok(Some(_))) => kept.clone(),
                    (_, Ok(Some(state))) => UiStatus::UpToDate(state.last_sync_at),
                    (_, Ok(None)) => UiStatus::from_error(SyncError::NotEnabled),
                    (_, Err(err)) => UiStatus::from_error(err),
                },
            };
            statuses.insert(id, status);
        }
        let changed = {
            let mut out = lock(&self.out);
            if let Some(id) = open
                && out.change_waits
                && let Some(UiStatus::UpToDate(_)) = statuses.get(&id)
            {
                statuses.insert(id, UiStatus::Syncing);
            }
            let changed = out.statuses != statuses;
            out.statuses = statuses;
            changed
        };
        if changed {
            self.repaint();
        }
    }
}

/// The waiter thread (contract relay-sync-v1, section 11): a long poll on the relay for
/// the open vault while it is unlocked and its key is in memory. A new version sets the
/// pull flag and wakes the worker, once for each pair of versions. After an error, or
/// when the relay answers again with nothing new (the same versions, or the same version
/// well before the wait ran out), it waits 5 seconds, then doubles up to 60. A lock ends
/// a poll in flight. A removed device shows "Removed from the relay" at once, and the
/// waiter asks the relay about that vault no more until a sync of the worker works
/// again. A `401` that is no removal (a failed sign-in) is an error as any other.
fn wait_for_relay(shared: &Shared) {
    let mut retry = RELAY_RETRY_FIRST;
    let mut signalled: Option<RelayPoll> = None;
    loop {
        if shared.stop.load(Ordering::SeqCst) {
            return;
        }
        let (open, vault) = {
            let plan = lock(&shared.plan);
            (
                plan.open.as_ref().and_then(|(id, sync)| {
                    sync.as_relay().map(|relay| (id.clone(), relay.clone()))
                }),
                plan.vault.clone(),
            )
        };
        let ready = open
            .as_ref()
            .is_some_and(|(_, relay)| relay.has_session() && !relay.is_removed())
            && vault.as_ref().is_some_and(is_unlocked);
        let Some((id, relay)) = open.filter(|_| ready) else {
            signalled = None;
            if !shared.waiter_sleep(RELAY_IDLE) {
                return;
            }
            continue;
        };
        let started = Instant::now();
        let new = match relay.poll(RELAY_WAIT) {
            Ok(poll) if poll.changed() => {
                if signalled == Some(poll) {
                    // This Mac did not move since the last word: the pull failed,
                    // waits for a run, or is still on its way.
                    false
                } else {
                    signalled = Some(poll);
                    shared.pull.store(true, Ordering::SeqCst);
                    shared.wake();
                    true
                }
            }
            Ok(_) => {
                signalled = None;
                // A full long poll is the normal answer; an early one is not.
                started.elapsed() >= RELAY_WAIT / 2
            }
            Err(SyncError::RemovedFromRelay) if relay.is_removed() => {
                // The relay refused this device: the window shows it now, and the next
                // round finds the vault removed and asks no more.
                shared.show_removed(&id);
                shared.wake();
                false
            }
            Err(_) => false,
        };
        let wait = if new {
            retry = RELAY_RETRY_FIRST;
            MIN_WAIT
        } else {
            let wait = retry;
            retry = (retry * 2).min(RELAY_RETRY_MAX);
            wait
        };
        if !shared.waiter_sleep(wait) {
            return;
        }
    }
}

fn run(shared: &Shared) {
    loop {
        if shared.stop.load(Ordering::SeqCst) {
            return;
        }
        let next = shared.tick(Instant::now());
        let wait = next
            .map_or(CHECK_EVERY, |at| {
                at.saturating_duration_since(Instant::now())
            })
            .max(MIN_WAIT);
        if !shared.sleep(wait) {
            return;
        }
    }
}

/// The sync worker of the app. Idle until [`Self::start`]: a test calls [`Self::tick`]
/// itself.
#[derive(Default)]
pub(crate) struct SyncWorker {
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
    /// The waiter thread. A stop does not join it: it can be in a long poll of up to 40
    /// seconds. It ends at the next look at the stop flag, or at once when a lock ends
    /// its poll.
    waiter: Option<JoinHandle<()>>,
}

impl SyncWorker {
    /// Start the thread. It asks `ctx` for a repaint when what the window shows
    /// changes. A second call does nothing.
    pub(crate) fn start(&mut self, ctx: &egui::Context) {
        if self.thread.is_some() {
            return;
        }
        *lock(&self.shared.repaint) = Some(ctx.clone());
        self.shared.stop.store(false, Ordering::SeqCst);
        let shared = Arc::clone(&self.shared);
        self.thread = std::thread::Builder::new()
            .name("apassy-sync".to_owned())
            .spawn(move || run(&shared))
            .ok();
        if self
            .waiter
            .as_ref()
            .is_none_or(|waiter| waiter.is_finished())
        {
            let shared = Arc::clone(&self.shared);
            self.waiter = std::thread::Builder::new()
                .name("apassy-sync-relay".to_owned())
                .spawn(move || wait_for_relay(&shared))
                .ok();
        }
    }

    /// Stop the thread and wait for it, at most [`STOP_WAIT`]. The key and the token of
    /// the open relay vault leave the memory first, so a relay transfer and the long
    /// poll end at once; a folder sync that runs now finishes first.
    pub(crate) fn stop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        let open = lock(&self.shared.plan).open.clone();
        if let Some((_, VaultSync::Relay(relay))) = open {
            relay.forget();
        }
        self.shared.wake();
        self.shared.wake_waiter();
        if let Some(thread) = self.thread.take() {
            let deadline = Instant::now() + STOP_WAIT;
            while !thread.is_finished() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            if thread.is_finished() {
                let _ = thread.join();
            }
        }
        // A waiter in a long poll ends on its own; a sleeping one ends now.
        if self
            .waiter
            .as_ref()
            .is_some_and(|waiter| waiter.is_finished())
        {
            self.waiter = None;
        }
    }

    /// The lock around each sync operation that changes files. Take it before the
    /// vault mutex, and never with the vault mutex held.
    pub(crate) fn op_lock(&self) -> SyncOpLock {
        Arc::clone(&self.shared.op)
    }

    /// Set while the relay sync of the open vault waits after a failure. The step before
    /// a lock reads it: it does not push to a relay that failed a moment ago.
    pub(crate) fn relay_backoff_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.shared.relay_backoff)
    }

    /// Sync `open` from now on: the open vault, or `None`. The schedule starts again.
    pub(crate) fn track(
        &self,
        open: Option<(String, FolderSync)>,
        vault: SharedVault,
        approvals: Option<Arc<ApprovalQueue>>,
    ) {
        self.track_sync(open.map(|(id, sync)| (id, sync.into())), vault, approvals);
    }

    /// [`Self::track`] for a vault that syncs through a folder or through the relay.
    pub(crate) fn track_sync(
        &self,
        open: Option<(String, VaultSync)>,
        vault: SharedVault,
        approvals: Option<Arc<ApprovalQueue>>,
    ) {
        let (old, same) = {
            let mut plan = lock(&self.shared.plan);
            plan.generation += 1;
            plan.vault = Some(vault);
            plan.approvals = approvals;
            let old = std::mem::replace(&mut plan.open, open);
            let same = match (&old, &plan.open) {
                (Some((old_id, old)), Some((id, new))) => old_id == id && old.same_as(new),
                _ => false,
            };
            (old, same)
        };
        // The key and the token of a vault that is not open any more go.
        if !same {
            if let Some((_, VaultSync::Relay(relay))) = old {
                relay.forget();
            }
            self.shared.pull.store(false, Ordering::SeqCst);
        }
        lock(&self.shared.out).change_waits = false;
        self.shared.wake();
        self.shared.wake_waiter();
    }

    /// The synced vaults of the list, through a folder or through the relay. Wakes the
    /// thread when they changed.
    pub(crate) fn set_synced_all(&self, synced: Vec<(String, VaultSync)>) {
        let changed = {
            let mut plan = lock(&self.shared.plan);
            let same = plan.synced.len() == synced.len()
                && plan
                    .synced
                    .iter()
                    .zip(&synced)
                    .all(|(a, b)| a.0 == b.0 && a.1.same_as(&b.1));
            if !same {
                plan.synced = synced;
            }
            !same
        };
        if changed {
            self.shared.wake();
        }
    }

    /// The window synced, or the step before a lock did: the schedule starts again, and
    /// no change waits.
    pub(crate) fn reset(&self) {
        lock(&self.shared.plan).generation += 1;
        lock(&self.shared.out).change_waits = false;
        self.shared.wake();
    }

    /// One step of the schedule at `now`, without a wait. Returns when the next step is
    /// due. A test calls it with its own instants; the thread calls the same step.
    #[cfg(test)]
    pub(crate) fn tick(&self, now: Instant) -> Option<Instant> {
        self.shared.tick(now)
    }

    /// Read the file status of each synced vault of the list. The open vault also
    /// counts a change of a credential that waits to sync.
    pub(crate) fn refresh(&self) {
        self.shared.refresh();
    }

    /// A copy of the statuses.
    pub(crate) fn statuses(&self) -> BTreeMap<String, UiStatus> {
        lock(&self.shared.out).statuses.clone()
    }

    pub(crate) fn set_status(&self, id: &str, status: UiStatus) {
        lock(&self.shared.out)
            .statuses
            .insert(id.to_owned(), status);
    }

    pub(crate) fn remove_status(&self, id: &str) {
        lock(&self.shared.out).statuses.remove(id);
    }

    /// Take the events since the last call.
    pub(crate) fn take_events(&self) -> Vec<SyncEvent> {
        std::mem::take(&mut lock(&self.shared.out).events)
    }

    /// Whether a change of a credential in the open vault waits to sync.
    #[cfg(test)]
    pub(crate) fn change_waits(&self) -> bool {
        lock(&self.shared.out).change_waits
    }

    /// Pretend that a change of a credential waits to sync since `since`.
    #[cfg(test)]
    pub(crate) fn force_changed_since(&self, since: Instant) {
        let generation = lock(&self.shared.plan).generation;
        let mut schedule = lock(&self.shared.schedule);
        self.shared.catch_up(&mut schedule, generation);
        schedule.changed_since = Some(since);
        lock(&self.shared.out).change_waits = true;
    }

    /// Whether the thread runs.
    #[cfg(test)]
    pub(crate) fn running(&self) -> bool {
        self.thread.is_some()
    }
}

impl Drop for SyncWorker {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The fake relay of the tests reads the app's sync module under this name.
#[cfg(test)]
use crate::sync as relay_api;
/// The headless app tests (`ui/sync_tests.rs`) load the same file for their own use.
#[cfg(test)]
#[allow(clippy::duplicate_mod)]
#[path = "../../tests/common/fake_relay.rs"]
mod fake_relay;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::{DeviceKey, RelayConfig, RelaySync};
    use crate::vault::RelayDevice;

    const PASS: &str = "synthetic-worker-relay-pass";

    /// A vault with a relay row and a relay state for a relay that does not answer (a
    /// closed loopback port).
    fn relay_vault(dir: &std::path::Path) -> (SharedVault, RelaySync) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        drop(listener);
        let vault_path = dir.join("vault.db");
        let mut vault = Vault::create(&vault_path, PASS).expect("create");
        vault.unlock(PASS).expect("unlock");
        let key = DeviceKey::generate().expect("key");
        vault
            .set_relay_device(&RelayDevice {
                relay_url: url.clone(),
                team_id: "t_7k2m5q4x3c".to_owned(),
                device_id: 2,
                public_key: key.public_key().to_vec(),
                key_pkcs8: key.pkcs8().expect("pkcs8").clone(),
                created_at: 0,
            })
            .expect("row");
        let config = RelayConfig::in_data_dir(dir, &vault_path, &url, "relay");
        std::fs::create_dir_all(&config.work_dir).expect("sync dir");
        let state = serde_json::json!({
            "format": 3,
            "transport": "relay",
            "file_name": "",
            "vault_id": vault.sync_identity().expect("identity").vault_id,
            "last_file_sha256": null,
            "last_content": null,
            "last_sync_at": null,
            "relay_url": url,
            "team_id": "t_7k2m5q4x3c",
            "device_id": 2,
        });
        std::fs::write(&config.state_path, state.to_string()).expect("state");
        let sync = RelaySync::new(config);
        assert!(sync.state().expect("state").is_some());
        (Arc::new(Mutex::new(Some(vault))), sync)
    }

    /// ADR 0022: the worker pulls a relay vault at the first step, quietly when the relay
    /// is away, again at once when the waiter heard of a push, and a lock drops the key.
    #[test]
    fn the_worker_pulls_a_relay_vault_and_a_lock_drops_its_key() {
        let dir = tempfile::TempDir::new().expect("dir");
        let (vault, relay) = relay_vault(dir.path());
        let worker = SyncWorker::default();
        worker.track_sync(
            Some(("v1".to_owned(), VaultSync::Relay(relay.clone()))),
            Arc::clone(&vault),
            None,
        );
        worker.set_synced_all(vec![("v1".to_owned(), VaultSync::Relay(relay.clone()))]);
        let now = Instant::now();
        let next = worker.tick(now).expect("a next step");
        assert!(next <= now + CHECK_EVERY);
        assert!(relay.has_session(), "the sync loaded the key");
        let status = worker.statuses().get("v1").cloned();
        assert!(
            matches!(&status, Some(UiStatus::Problem(text)) if text.contains("relay not reachable")),
            "{status:?}"
        );
        assert!(worker.take_events().is_empty(), "an absent relay is quiet");
        assert!(
            worker.relay_backoff_flag().load(Ordering::SeqCst),
            "the step before a lock does not push to a relay that failed"
        );

        // The failed pull waits 5 seconds: the waiter's word waits with it.
        assert_eq!(
            lock(&worker.shared.schedule).relay_retry_at,
            Some(now + RELAY_RETRY_FIRST)
        );
        assert!(next <= now + LOCK_CHECK_EVERY, "the key is in memory");
        worker.shared.pull.store(true, Ordering::SeqCst);
        worker.tick(now + MIN_WAIT);
        assert!(worker.shared.pull.load(Ordering::SeqCst), "kept for later");
        // At its time the pull runs, fails again, and waits 10 seconds.
        let later = now + RELAY_RETRY_FIRST;
        worker.tick(later);
        assert!(!worker.shared.pull.load(Ordering::SeqCst));
        assert_eq!(
            lock(&worker.shared.schedule).relay_retry_at,
            Some(later + RELAY_RETRY_FIRST * 2)
        );
        assert!(
            worker.take_events().is_empty(),
            "no new note for the same failure"
        );

        // A lock drops the key and the token.
        lock(&vault).as_mut().expect("vault").lock().expect("lock");
        worker.tick(later + MIN_WAIT);
        assert!(!relay.has_session());
        // The status of a relay vault comes from its state, not from the relay.
        worker.refresh();
        assert!(worker.statuses().contains_key("v1"));
    }

    /// A failed pull is tried again at its retry time, not at the next check 30 seconds
    /// later, and no step asks for the next one at a time that passed (a wake every
    /// MIN_WAIT).
    #[test]
    fn a_failed_pull_is_retried_at_its_time_without_a_wake_burst() {
        let dir = tempfile::TempDir::new().expect("dir");
        let (vault, relay) = relay_vault(dir.path());
        let worker = SyncWorker::default();
        worker.track_sync(
            Some(("v1".to_owned(), VaultSync::Relay(relay.clone()))),
            Arc::clone(&vault),
            None,
        );
        let start = Instant::now();
        let mut now = start;
        let mut retries = Vec::new();
        let mut failures = 0;
        while now < start + Duration::from_secs(40) {
            let next = worker.tick(now).expect("a next step");
            assert!(
                next > now,
                "a wake at a time that passed, at {:?}",
                now - start
            );
            let seen = lock(&worker.shared.schedule).relay_failures;
            if seen != failures {
                failures = seen;
                retries.push((now - start).as_secs());
            }
            now = next;
        }
        // The first pull, then 5, 10, and 20 seconds after each failure.
        assert_eq!(retries, [0, 5, 15, 35]);
    }

    #[test]
    fn the_relay_backoff_doubles_up_to_a_minute() {
        let waits: Vec<u64> = (1..=7).map(|n| relay_backoff(n).as_secs()).collect();
        assert_eq!(waits, [5, 10, 20, 40, 60, 60, 60]);
        assert_eq!(relay_backoff(0).as_secs(), 5);
    }

    mod live {
        //! The worker and the waiter against the in-process fake relay.

        use super::*;
        use crate::contracts::CredentialKind;
        use crate::desktop::sync_worker::fake_relay::FakeRelay;
        use crate::sync::PendingJoin;
        use crate::vault::{Field, ItemDraft, SecretValue};

        fn item(title: &str) -> ItemDraft {
            ItemDraft {
                title: title.to_owned(),
                kind: CredentialKind::ApiKey,
                notes: String::new(),
                tags: Vec::new(),
                fields: vec![Field {
                    name: "token".to_owned(),
                    value: SecretValue::new("SYNTH-worker".to_owned()),
                    secret: true,
                }],
            }
        }

        /// One Mac: its relay sync and its unlocked vault.
        fn mac(root: &std::path::Path, name: &str, url: &str) -> (RelaySync, std::path::PathBuf) {
            let data = root.join(name);
            std::fs::create_dir_all(&data).expect("data");
            let vault_path = data.join("vault.db");
            let sync = RelaySync::new(RelayConfig::in_data_dir(&data, &vault_path, url, "vault"));
            (sync, vault_path)
        }

        /// Mac A makes the team; Mac B joins and adopts. Both unlocked.
        fn pair(root: &std::path::Path, relay: &FakeRelay) -> (RelaySync, Vault, RelaySync, Vault) {
            let (a, path_a) = mac(root, "a", &relay.url);
            let (b, _) = mac(root, "b", &relay.url);
            let mut vault_a = Vault::create(&path_a, PASS).expect("create");
            vault_a.unlock(PASS).expect("unlock");
            vault_a.add(item("Alpha")).expect("add");
            a.create_team(&mut vault_a, "Personal", &relay.team_code(), "Mac A")
                .expect("team");
            let code = a.create_link(&vault_a).expect("link");
            let pending = PendingJoin::request(&code.link, "", "Mac B").expect("request");
            let links = a.pending_links(&vault_a, Some(&code)).expect("links");
            a.confirm_link(&vault_a, &links[0]).expect("confirm");
            let joined = pending.poll().expect("poll").expect("confirmed");
            let download = joined.download(&root.join("b-work")).expect("download");
            let (mut vault_b, _) = b.adopt(&joined, &download, PASS).expect("adopt");
            vault_b.unlock(PASS).expect("unlock");
            (a, vault_a, b, vault_b)
        }

        /// A worker with its threads, syncing `vault` through `relay` as the open vault.
        fn running(id: &str, relay: &RelaySync, vault: &SharedVault) -> SyncWorker {
            let mut worker = SyncWorker::default();
            worker.track_sync(
                Some((id.to_owned(), VaultSync::Relay(relay.clone()))),
                Arc::clone(vault),
                None,
            );
            worker.start(&egui::Context::default());
            worker
        }

        /// A pull that keeps failing (the relay went back to an older copy) does not
        /// make the waiter and the worker ask the relay again and again: a few requests
        /// in three seconds, not dozens.
        #[test]
        fn a_failing_pull_does_not_spin() {
            let root = tempfile::TempDir::new().expect("dir");
            let relay = FakeRelay::start();
            let (_a, _vault_a, b, mut vault_b) = pair(root.path(), &relay);
            vault_b.add(item("Beta")).expect("add");
            b.sync(&mut vault_b).expect("push version 2");
            relay.roll_back_to(1);
            let vault: SharedVault = Arc::new(Mutex::new(Some(vault_b)));
            let heads = relay.count("GET /v1/sync/head");
            let worker = running("b", &b, &vault);
            std::thread::sleep(Duration::from_secs(3));
            let asked = relay.count("GET /v1/sync/head") - heads;
            drop(worker);
            assert!((1..=6).contains(&asked), "{asked} head requests in 3 s");
            assert_eq!(
                b.sync(lock(&vault).as_mut().unwrap()).unwrap_err(),
                SyncError::StaleCopy
            );
        }

        /// A relay that answers every long poll at once with the same version (a second
        /// poll of one device, a relay that stops) does not make the waiter ask again
        /// at once.
        #[test]
        fn an_early_long_poll_answer_does_not_spin() {
            let root = tempfile::TempDir::new().expect("dir");
            let relay = FakeRelay::start();
            let (_a, _vault_a, b, vault_b) = pair(root.path(), &relay);
            relay.answer_polls_at_once(true);
            let vault: SharedVault = Arc::new(Mutex::new(Some(vault_b)));
            let heads = relay.count("GET /v1/sync/head");
            let worker = running("b", &b, &vault);
            std::thread::sleep(Duration::from_secs(3));
            let asked = relay.count("GET /v1/sync/head") - heads;
            drop(worker);
            assert!((1..=6).contains(&asked), "{asked} head requests in 3 s");
        }

        /// Wait until the relay got one more request that starts with `prefix`.
        fn wait_for(relay: &FakeRelay, prefix: &str, seen: usize) {
            let deadline = Instant::now() + Duration::from_secs(10);
            while relay.count(prefix) == seen && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(20));
            }
            assert!(relay.count(prefix) > seen, "no {prefix}");
        }

        /// The status of a removed Mac.
        fn removed() -> UiStatus {
            UiStatus::from_error(SyncError::RemovedFromRelay)
        }

        /// Mac A removes Mac B from the relay. B keeps its key and its old token in
        /// memory, as a Mac that synced a moment ago.
        fn removed_b(root: &std::path::Path, relay: &FakeRelay) -> (RelaySync, SharedVault) {
            let (a, vault_a, b, vault_b) = pair(root, relay);
            let device = vault_b.relay_device().unwrap().unwrap().device_id;
            a.remove_device(&vault_a, device).expect("A removes B");
            assert!(b.has_session());
            (b, Arc::new(Mutex::new(Some(vault_b))))
        }

        /// The waiter of a removed Mac shows "Removed from the relay" within seconds, with
        /// one note, and then asks the relay no more: no sign-in, no long poll.
        #[test]
        fn the_waiter_of_a_removed_mac_tells_at_once_and_stops() {
            let root = tempfile::TempDir::new().expect("dir");
            let relay = FakeRelay::start();
            let (b, vault) = removed_b(root.path(), &relay);
            let worker = SyncWorker::default();
            worker.track_sync(
                Some(("b".to_owned(), VaultSync::Relay(b.clone()))),
                Arc::clone(&vault),
                None,
            );
            let challenges = relay.count("POST /v1/auth/challenge");
            std::thread::scope(|scope| {
                let waiter = scope.spawn(|| wait_for_relay(&worker.shared));
                let deadline = Instant::now() + Duration::from_secs(3);
                while worker.statuses().get("b") != Some(&removed()) && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(20));
                }
                assert_eq!(worker.statuses().get("b"), Some(&removed()));
                let asked = relay.log().len();
                std::thread::sleep(Duration::from_secs(3));
                assert_eq!(relay.log().len(), asked, "{:?}", relay.log());
                worker.shared.stop.store(true, Ordering::SeqCst);
                worker.shared.wake_waiter();
                waiter.join().expect("waiter");
            });
            assert_eq!(relay.count("POST /v1/auth/challenge"), challenges + 1);
            assert!(b.is_removed());
            let events = worker.take_events();
            assert_eq!(events.len(), 1, "{events:?}");
            assert!(
                matches!(&events[0], SyncEvent::Failure { id, text }
                    if id == "b" && text.contains("removed from the relay")),
                "{events:?}"
            );
        }

        /// A relay that refused the challenge for a moment (suspended, then resumed)
        /// looks like a removal: the status says "Removed from the relay". The worker
        /// asks once more at its next try, syncs, and the status goes; the waiter then
        /// polls again.
        #[test]
        fn a_mac_refused_for_a_moment_syncs_again_at_its_next_try() {
            let root = tempfile::TempDir::new().expect("dir");
            let relay = FakeRelay::start();
            let (_a, _vault_a, b, vault_b) = pair(root.path(), &relay);
            let b = b.with_removed_probe(Duration::from_secs(1));
            // The next sync signs in with the key of the vault.
            b.forget();
            relay.fail_next("POST /v1/auth/challenge", 1, 401);
            let vault: SharedVault = Arc::new(Mutex::new(Some(vault_b)));
            let heads = relay.count("GET /v1/sync/head");
            let worker = running("b", &b, &vault);
            let deadline = Instant::now() + Duration::from_secs(3);
            while worker.statuses().get("b") != Some(&removed()) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            assert_eq!(worker.statuses().get("b"), Some(&removed()));
            let deadline = Instant::now() + Duration::from_secs(5);
            while !matches!(worker.statuses().get("b"), Some(UiStatus::UpToDate(_)))
                && Instant::now() < deadline
            {
                std::thread::sleep(Duration::from_millis(20));
            }
            assert!(
                matches!(worker.statuses().get("b"), Some(UiStatus::UpToDate(_))),
                "{:?}",
                worker.statuses()
            );
            assert!(!b.is_removed());
            // The head of the sync, then the long poll of the waiter.
            let deadline = Instant::now() + Duration::from_secs(10);
            while relay.count("GET /v1/sync/head") < heads + 2 && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(20));
            }
            drop(worker);
            assert!(
                relay.count("GET /v1/sync/head") >= heads + 2,
                "the waiter polls again: {:?}",
                relay.log()
            );
        }

        /// The steps of the worker on a removed Mac ask the relay once, show the status,
        /// and then nothing more: not at the retry times, not for a change that waits, not
        /// at the 5-minute pull. Another relay vault then syncs as usual.
        #[test]
        fn the_worker_asks_a_removed_mac_nothing_more_and_other_vaults_go_on() {
            let root = tempfile::TempDir::new().expect("dir");
            let relay = FakeRelay::start();
            let (b, vault) = removed_b(root.path(), &relay);
            let worker = SyncWorker::default();
            worker.track_sync(
                Some(("b".to_owned(), VaultSync::Relay(b.clone()))),
                Arc::clone(&vault),
                None,
            );
            worker.set_synced_all(vec![("b".to_owned(), VaultSync::Relay(b.clone()))]);
            let challenges = relay.count("POST /v1/auth/challenge");
            let start = Instant::now();
            worker.tick(start);
            assert_eq!(worker.statuses().get("b"), Some(&removed()));
            assert_eq!(relay.count("POST /v1/auth/challenge"), challenges + 1);
            assert_eq!(worker.take_events().len(), 1);
            let asked = relay.log().len();
            lock(&vault)
                .as_mut()
                .unwrap()
                .add(item("Late"))
                .expect("add");
            for seconds in [1, 5, 10, 15, 35, 95, 400] {
                let now = start + Duration::from_secs(seconds);
                worker.force_changed_since(now - SETTLE);
                worker.tick(now);
            }
            assert_eq!(relay.log().len(), asked, "{:?}", relay.log());
            assert!(worker.take_events().is_empty(), "the note shows once");
            assert_eq!(worker.statuses().get("b"), Some(&removed()));

            // A lock and an unlock do not ask again either.
            b.forget();
            worker.tick(start + Duration::from_secs(401));
            assert_eq!(relay.log().len(), asked);

            // Another vault on the relay syncs.
            let (a, path_a) = mac(root.path(), "c", &relay.url);
            let mut vault_c = Vault::create(&path_a, PASS).expect("create");
            vault_c.unlock(PASS).expect("unlock");
            a.create_team(&mut vault_c, "Work", &relay.team_code(), "Mac C")
                .expect("team");
            let vault_c: SharedVault = Arc::new(Mutex::new(Some(vault_c)));
            worker.track_sync(
                Some(("c".to_owned(), VaultSync::Relay(a.clone()))),
                Arc::clone(&vault_c),
                None,
            );
            worker.set_synced_all(vec![
                ("b".to_owned(), VaultSync::Relay(b.clone())),
                ("c".to_owned(), VaultSync::Relay(a.clone())),
            ]);
            worker.tick(start + Duration::from_secs(402));
            assert!(
                matches!(worker.statuses().get("c"), Some(UiStatus::UpToDate(_))),
                "{:?}",
                worker.statuses()
            );
        }

        /// A stop ends a relay transfer of the worker at once: a quit does not wait for a
        /// slow download, and the key leaves the memory.
        #[test]
        fn a_stop_ends_a_relay_transfer_at_once() {
            let root = tempfile::TempDir::new().expect("dir");
            let relay = FakeRelay::start();
            let (a, mut vault_a, b, vault_b) = pair(root.path(), &relay);
            vault_a.add(item("Gamma")).expect("add");
            a.sync(&mut vault_a).expect("push version 2");
            relay.delay("GET /v1/sync/snapshot", Duration::from_secs(4));
            let downloads = relay.count("GET /v1/sync/snapshot");
            let vault: SharedVault = Arc::new(Mutex::new(Some(vault_b)));
            let mut worker = running("b", &b, &vault);
            wait_for(&relay, "GET /v1/sync/snapshot", downloads);
            let started = Instant::now();
            worker.stop();
            let took = started.elapsed();
            assert!(took < Duration::from_millis(1500), "the stop took {took:?}");
            assert!(!b.has_session(), "the key left the memory");
        }

        /// A relay sync of the worker never holds the sync op lock: the window takes it
        /// at once while a slow download runs.
        #[test]
        fn a_relay_transfer_leaves_the_op_lock_free() {
            let root = tempfile::TempDir::new().expect("dir");
            let relay = FakeRelay::start();
            let (a, mut vault_a, b, vault_b) = pair(root.path(), &relay);
            vault_a.add(item("Gamma")).expect("add");
            a.sync(&mut vault_a).expect("push version 2");
            relay.delay("GET /v1/sync/snapshot", Duration::from_millis(1500));
            let downloads = relay.count("GET /v1/sync/snapshot");
            let vault: SharedVault = Arc::new(Mutex::new(Some(vault_b)));
            let worker = SyncWorker::default();
            worker.track_sync(
                Some(("b".to_owned(), VaultSync::Relay(b.clone()))),
                Arc::clone(&vault),
                None,
            );
            let op = worker.op_lock();
            let now = Instant::now();
            let waited = std::thread::scope(|scope| {
                let pull = scope.spawn(|| worker.tick(now));
                wait_for(&relay, "GET /v1/sync/snapshot", downloads);
                let started = Instant::now();
                drop(lock(&op));
                let waited = started.elapsed();
                pull.join().expect("tick");
                waited
            });
            assert!(
                waited < Duration::from_millis(300),
                "the op lock waited {waited:?}"
            );
        }

        /// The relay steps of a sync run without the vault mutex: while a slow download
        /// runs, another thread (the window, the agent broker) takes the vault at once.
        #[test]
        fn a_slow_relay_transfer_does_not_hold_the_vault() {
            let root = tempfile::TempDir::new().expect("dir");
            let relay = FakeRelay::start();
            let (a, mut vault_a, b, vault_b) = pair(root.path(), &relay);
            vault_a.add(item("Gamma")).expect("add");
            a.sync(&mut vault_a).expect("push version 2");
            relay.delay("GET /v1/sync/snapshot", Duration::from_millis(1500));
            let vault: SharedVault = Arc::new(Mutex::new(Some(vault_b)));
            let worker = SyncWorker::default();
            worker.track_sync(
                Some(("b".to_owned(), VaultSync::Relay(b.clone()))),
                Arc::clone(&vault),
                None,
            );
            let now = Instant::now();
            let waited = std::thread::scope(|scope| {
                let pull = scope.spawn(|| worker.tick(now));
                std::thread::sleep(Duration::from_millis(400));
                let started = Instant::now();
                let titles = lock(&vault)
                    .as_ref()
                    .map(|open| open.search("").map(|found| found.len()));
                let waited = started.elapsed();
                assert!(titles.is_some());
                pull.join().expect("tick");
                waited
            });
            assert!(
                waited < Duration::from_millis(500),
                "the vault waited {waited:?}"
            );
            let slot = lock(&vault);
            let found = slot.as_ref().unwrap().search("Gamma").expect("search");
            assert_eq!(found.len(), 1, "the pull merged version 2");
        }
    }
}
