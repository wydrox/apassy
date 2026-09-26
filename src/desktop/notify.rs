//! Native notifications for the owner (goal items N1 to N4, ADR 0010).
//!
//! Two worker threads:
//!
//! - The watcher wakes when a run starts to wait (the approval queue calls it) and
//!   every [`POLL_INTERVAL`]. It finds new waiting runs and new blocked requests in
//!   the activity log.
//! - The sender posts each notification through the native helper. A call can block
//!   up to 40 s, so the sender never delays the watcher.
//!
//! A preview has the agent name and the event type only. [`Notification::new`] takes
//! no other text (N2). The result of each delivery and the channel state are visible
//! in the app. A failed delivery changes nothing in the queue: the run still waits,
//! and the event stays in the inbox (N3). A notification is never an approval (N4):
//! this module cannot make an owner proof.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::broker::SharedVault;
use crate::broker::approvals::ApprovalQueue;
use crate::desktop::inbox::{EventKey, needs_notification};
use crate::native::{
    HelperErrorCode, MAX_AGENT_NAME_CHARS, NativeError, NativeHelper, Notification,
    NotificationAuthorization, NotificationEvent, NotificationSetting, NotificationStatus,
    NotifyOutcome,
};

/// How often the watcher reads the activity log.
pub const POLL_INTERVAL: Duration = Duration::from_millis(1000);
/// How many new activity entries the watcher reads in one pass.
const ACTIVITY_WINDOW: usize = 50;

/// The result of one delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivery {
    /// The sender has the notification.
    Sending,
    /// Notification Center lists the notification.
    Delivered,
    /// The owner did not get a notification. The text has no secret value.
    Failed(String),
}

impl Delivery {
    pub fn label(&self) -> String {
        match self {
            Self::Sending => "Notification: sending.".to_owned(),
            Self::Delivered => "Notification: delivered.".to_owned(),
            Self::Failed(text) => {
                format!("Notification failed: {text} The event stays in this inbox.")
            }
        }
    }
}

/// What the app knows about the notification channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelState {
    /// No answer from the helper yet.
    Unknown,
    /// The settings of the Apassy bundle.
    Ready(NotificationStatus),
    /// The helper did not answer. The text has no secret value.
    Problem(String),
}

impl ChannelState {
    /// True when macOS can show an Apassy notification.
    pub fn can_deliver(&self) -> bool {
        matches!(self, Self::Ready(status) if status.can_deliver())
    }

    /// True when the owner has not decided about notifications.
    pub fn needs_permission(&self) -> bool {
        matches!(
            self,
            Self::Ready(status) if status.authorization == NotificationAuthorization::NotDetermined
        )
    }

    /// Text for the owner.
    pub fn summary(&self) -> String {
        match self {
            Self::Unknown => "Apassy is checking the notification settings.".to_owned(),
            Self::Problem(text) => {
                format!("Notifications do not work: {text} Events stay in the inbox.")
            }
            Self::Ready(status) => match status.authorization {
                NotificationAuthorization::NotDetermined => {
                    "You did not allow notifications yet. Select \"Allow notifications\". Until then, events stay in the inbox only.".to_owned()
                }
                NotificationAuthorization::Denied => {
                    "Notifications are not allowed for Apassy. Allow them in System Settings > Notifications > Apassy. Events stay in the inbox.".to_owned()
                }
                NotificationAuthorization::Authorized | NotificationAuthorization::Provisional
                    if status.can_deliver() =>
                {
                    let banners = if status.alert == NotificationSetting::Enabled {
                        "Banners are on."
                    } else {
                        "Banners are off. Notifications go to Notification Center only."
                    };
                    format!("Notifications are allowed. {banners}")
                }
                NotificationAuthorization::Authorized | NotificationAuthorization::Provisional => {
                    "Notifications are allowed, but alerts and Notification Center are off for Apassy. Turn them on in System Settings > Notifications > Apassy. Events stay in the inbox.".to_owned()
                }
                NotificationAuthorization::Unknown => {
                    "macOS gave an unknown notification permission. Events stay in the inbox.".to_owned()
                }
            },
        }
    }
}

/// A snapshot for the app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CenterView {
    pub channel: ChannelState,
    pub deliveries: BTreeMap<EventKey, Delivery>,
}

enum Job {
    Notify {
        key: EventKey,
        agent: String,
        event: NotificationEvent,
    },
    Status,
    Authorize,
}

struct Shared {
    view: Mutex<CenterView>,
    stop: AtomicBool,
    /// Set by the approval queue. The watcher resets it.
    wake: Mutex<bool>,
    woken: Condvar,
    on_change: Box<dyn Fn() + Send + Sync>,
}

impl Shared {
    fn update(&self, change: impl FnOnce(&mut CenterView)) {
        change(&mut self.view.lock().unwrap_or_else(PoisonError::into_inner));
        (self.on_change)();
    }

    fn wake(&self) {
        *self.wake.lock().unwrap_or_else(PoisonError::into_inner) = true;
        self.woken.notify_all();
    }

    /// Wait for a wake-up or the poll interval. Returns false after `stop`.
    fn sleep(&self, interval: Duration) -> bool {
        let guard = self.wake.lock().unwrap_or_else(PoisonError::into_inner);
        let (mut guard, _) = self
            .woken
            .wait_timeout_while(guard, interval, |woken| {
                !*woken && !self.stop.load(Ordering::SeqCst)
            })
            .unwrap_or_else(PoisonError::into_inner);
        *guard = false;
        !self.stop.load(Ordering::SeqCst)
    }
}

/// The notification service of the desktop app.
pub struct NotificationCenter {
    shared: Arc<Shared>,
    jobs: Mutex<Option<Sender<Job>>>,
    watcher: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for NotificationCenter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NotificationCenter").finish_non_exhaustive()
    }
}

impl NotificationCenter {
    /// Start the watcher and the sender. The center replaces the notifier of
    /// `approvals`: it wakes the watcher and then calls `on_change`. `on_change` also
    /// runs after each delivery, so the app can repaint.
    pub fn start(
        approvals: Arc<ApprovalQueue>,
        vault: SharedVault,
        helper: NativeHelper,
        on_change: impl Fn() + Send + Sync + 'static,
    ) -> Self {
        let shared = Arc::new(Shared {
            view: Mutex::new(CenterView {
                channel: ChannelState::Unknown,
                deliveries: BTreeMap::new(),
            }),
            stop: AtomicBool::new(false),
            wake: Mutex::new(false),
            woken: Condvar::new(),
            on_change: Box::new(on_change),
        });
        {
            let shared = Arc::clone(&shared);
            approvals.set_notifier(move || {
                shared.wake();
                (shared.on_change)();
            });
        }
        let (sender, receiver) = mpsc::channel();
        let _ = sender.send(Job::Status);
        // The sender is not joined at stop: a helper call can take 40 s. It ends after
        // its current call, because the channel closes.
        {
            let worker = Arc::clone(&shared);
            let started = std::thread::Builder::new()
                .name("apassy-notify-send".to_owned())
                .spawn(move || send_loop(&worker, &helper, &receiver));
            if let Err(err) = started {
                shared.update(|view| {
                    view.channel = ChannelState::Problem(format!(
                        "the notification thread did not start: {err}."
                    ));
                });
            }
        }
        let watcher = {
            let shared = Arc::clone(&shared);
            let jobs = sender.clone();
            std::thread::Builder::new()
                .name("apassy-notify-watch".to_owned())
                .spawn(move || watch_loop(&shared, &approvals, &vault, &jobs))
                .ok()
        };
        Self {
            shared,
            jobs: Mutex::new(Some(sender)),
            watcher,
        }
    }

    /// A copy of the channel state and the deliveries.
    pub fn view(&self) -> CenterView {
        self.shared
            .view
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The delivery of one event, if the center sent a notification for it.
    pub fn delivery(&self, key: EventKey) -> Option<Delivery> {
        self.view().deliveries.get(&key).cloned()
    }

    /// Read the notification settings again. It never shows a prompt.
    pub fn refresh_status(&self) {
        self.send(Job::Status);
    }

    /// Show the macOS permission prompt when the owner has not decided.
    pub fn request_permission(&self) {
        self.send(Job::Authorize);
    }

    fn send(&self, job: Job) {
        if let Some(jobs) = self
            .jobs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
        {
            let _ = jobs.send(job);
        }
    }

    /// Stop both threads. A notification that the sender posts now can still finish.
    pub fn stop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        self.shared.wake();
        self.jobs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(watcher) = self.watcher.take() {
            let _ = watcher.join();
        }
    }
}

impl Drop for NotificationCenter {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The agent name for a preview: printable characters, at most 40 characters.
fn preview_name(agent: &str) -> String {
    let name: String = agent
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_AGENT_NAME_CHARS)
        .collect();
    if name.trim().is_empty() {
        "unknown".to_owned()
    } else {
        name
    }
}

fn watch_loop(shared: &Shared, approvals: &ApprovalQueue, vault: &SharedVault, jobs: &Sender<Job>) {
    let mut notified_runs = BTreeSet::new();
    // `None` until the watcher sees an unlocked vault. Then the newest entry ID: older
    // entries are history and cause no notification.
    let mut last_entry: Option<u64> = None;
    loop {
        let pending = approvals.pending();
        for run in &pending {
            if notified_runs.insert(run.id) {
                queue_notification(
                    shared,
                    jobs,
                    EventKey::Run(run.id),
                    &run.agent,
                    NotificationEvent::ApprovalWaiting,
                );
            }
        }
        notified_runs.retain(|id| pending.iter().any(|run| run.id == *id));

        let rows = {
            let guard = vault.lock().unwrap_or_else(PoisonError::into_inner);
            match guard.as_ref() {
                Some(open) if !open.is_locked() => open.recent_activity(ACTIVITY_WINDOW).ok(),
                _ => None,
            }
        };
        match rows {
            None => last_entry = None,
            Some(rows) => {
                let newest = rows.first().map_or(0, |row| row.id);
                if let Some(last) = last_entry {
                    for row in rows.iter().rev().filter(|row| row.id > last) {
                        if needs_notification(row.decision, &row.reason) {
                            queue_notification(
                                shared,
                                jobs,
                                EventKey::Activity(row.id),
                                &row.agent_name,
                                NotificationEvent::RequestBlocked,
                            );
                        }
                    }
                }
                last_entry = Some(last_entry.map_or(newest, |last| last.max(newest)));
            }
        }
        if !shared.sleep(POLL_INTERVAL) {
            return;
        }
    }
}

fn queue_notification(
    shared: &Shared,
    jobs: &Sender<Job>,
    key: EventKey,
    agent: &str,
    event: NotificationEvent,
) {
    shared.update(|view| {
        view.deliveries.insert(key, Delivery::Sending);
    });
    let _ = jobs.send(Job::Notify {
        key,
        agent: preview_name(agent),
        event,
    });
}

fn send_loop(shared: &Shared, helper: &NativeHelper, jobs: &Receiver<Job>) {
    while let Ok(job) = jobs.recv() {
        if shared.stop.load(Ordering::SeqCst) {
            return;
        }
        match job {
            Job::Notify { key, agent, event } => {
                let result = Notification::new(&key.notification_id(), &agent, event)
                    .and_then(|notification| helper.notify(&notification));
                let (delivery, channel) = delivery_of(result);
                shared.update(|view| {
                    view.deliveries.insert(key, delivery);
                    if let Some(channel) = channel {
                        view.channel = channel;
                    }
                });
            }
            Job::Status => {
                let channel = channel_of(helper.notify_status());
                shared.update(|view| view.channel = channel);
            }
            Job::Authorize => {
                let channel = channel_of(helper.notify_authorize());
                shared.update(|view| view.channel = channel);
            }
        }
    }
}

fn channel_of(result: Result<NotificationStatus, NativeError>) -> ChannelState {
    match result {
        Ok(status) => ChannelState::Ready(status),
        Err(err) => ChannelState::Problem(failure_text(&err)),
    }
}

/// The delivery and, when the helper told it, the new channel state.
fn delivery_of(result: Result<NotifyOutcome, NativeError>) -> (Delivery, Option<ChannelState>) {
    match result {
        Ok(outcome) if outcome.delivered => (
            Delivery::Delivered,
            Some(ChannelState::Ready(outcome.status)),
        ),
        Ok(outcome) => (
            Delivery::Failed(
                "macOS did not list the notification. Notifications for Apassy are off or hidden."
                    .to_owned(),
            ),
            Some(ChannelState::Ready(outcome.status)),
        ),
        Err(err) => {
            let text = failure_text(&err);
            let channel = matches!(
                err.code(),
                Some(
                    HelperErrorCode::NotificationsDenied
                        | HelperErrorCode::NotificationsUnavailable
                )
            ) || matches!(err, NativeError::HelperMissing(_));
            (
                Delivery::Failed(text.clone()),
                channel.then_some(ChannelState::Problem(text)),
            )
        }
    }
}

/// Text for the owner. It has no secret value: the helper messages are fixed text.
fn failure_text(err: &NativeError) -> String {
    match err {
        NativeError::Helper {
            code: HelperErrorCode::NotificationsDenied,
            ..
        } => "notifications are not allowed for Apassy.".to_owned(),
        NativeError::Helper {
            code: HelperErrorCode::NotificationsUnavailable,
            ..
        } => "the notification helper is not inside Apassy.app.".to_owned(),
        NativeError::HelperMissing(_) => {
            "this build has no notification helper. Notifications work only in Apassy.app."
                .to_owned()
        }
        NativeError::Timeout(limit) => {
            format!("the helper did not answer in {} s.", limit.as_secs())
        }
        other => format!("{other}."),
    }
}
