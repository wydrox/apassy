//! Native notifications for the owner (goal items N1 to N4, ADR 0010).
//!
//! Two worker threads:
//!
//! - The watcher wakes when a question starts to wait (the approval queue calls it) and
//!   every [`POLL_INTERVAL`]. It finds new waiting questions and new blocked requests in
//!   the activity log. Each new question gets one notification ([`OwnerEvent`],
//!   ADR 0025 §3e).
//! - The sender posts each notification through the notifier
//!   (`Contents/Helpers/ApassyNotify.app`, see `apassy::native`). A call can block up
//!   to 40 s, so the sender never delays the watcher.
//!
//! A preview has the agent name and the event type only. [`Notification::new`] takes
//! no other text (N2). The result of each delivery and the channel state are visible
//! in the app. A failed delivery changes nothing in the queue: the run still waits,
//! and the event stays in the inbox (N3). A notification is never an approval (N4):
//! this module cannot make an owner proof.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
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
/// System Settings > Notifications, at the entry of the notifier bundle ("Apassy").
pub const NOTIFICATION_SETTINGS_URL: &str = "x-apple.systempreferences:com.apple.Notifications-Settings.extension?id=com.wydrox.apassy.notify";

/// Open System Settings > Notifications > Apassy. The URL is fixed text. A thread
/// waits for `open`, so no finished process stays.
pub fn open_notification_settings() -> std::io::Result<()> {
    let mut child = std::process::Command::new("/usr/bin/open")
        .arg(NOTIFICATION_SETTINGS_URL)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}

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
                format!(
                    "Notification failed: {text} A question still waits in Decisions; other events are in the activity log."
                )
            }
        }
    }
}

/// Something new that waits for the owner in Decisions (ADR 0025 §3e, §5, §6). Each one
/// gets one notification. The preview has the agent name and the kind of event only: no
/// item name, command, project, or value (N2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerEvent {
    /// A question of an agent waits in the approval queue.
    QuestionWaiting,
    /// An agent asks the owner to paste a credential (`credential_request`).
    CredentialRequested,
    /// Apassy proposes a correction of a declaration (`correction`).
    CorrectionProposed,
}

impl OwnerEvent {
    /// The key of the event with the ID of its question, request, or correction.
    pub fn key(self, id: u64) -> EventKey {
        match self {
            Self::QuestionWaiting => EventKey::Run(id),
            Self::CredentialRequested => EventKey::Request(id),
            Self::CorrectionProposed => EventKey::Correction(id),
        }
    }

    /// The template of the notifier. It has two fixed templates; each of these events
    /// waits for a decision of the owner, so each uses "waits for your decision".
    pub fn native(self) -> NotificationEvent {
        NotificationEvent::ApprovalWaiting
    }

    /// The name in the preview: the agent, or "Apassy" for a correction, which no agent
    /// asked for.
    pub fn preview_name(self, agent: &str) -> String {
        match self {
            Self::CorrectionProposed => "Apassy".to_owned(),
            Self::QuestionWaiting | Self::CredentialRequested => preview_name(agent),
        }
    }
}

/// What the app knows about the notification channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelState {
    /// No answer from the notifier yet.
    Unknown,
    /// The notifier asked macOS for permission. macOS shows its prompt until the
    /// owner answers, at most 120 s.
    Asking,
    /// The settings of the notifier bundle (display name "Apassy").
    Ready(NotificationStatus),
    /// The notifier did not answer. The text has no secret value.
    Problem(String),
}

impl ChannelState {
    /// True when macOS can show an Apassy notification.
    pub fn can_deliver(&self) -> bool {
        matches!(self, Self::Ready(status) if status.can_deliver())
    }

    /// True when the owner has not decided about notifications, and no prompt is
    /// on the screen now.
    pub fn needs_permission(&self) -> bool {
        matches!(
            self,
            Self::Ready(status) if status.authorization == NotificationAuthorization::NotDetermined
        )
    }

    /// True when only System Settings can turn the notifications on: the owner or
    /// macOS denied them, or alerts and Notification Center are off. macOS shows no
    /// new permission prompt after a denial.
    pub fn needs_settings(&self) -> bool {
        matches!(
            self,
            Self::Ready(status)
                if status.authorization == NotificationAuthorization::Denied
                    || (!status.can_deliver()
                        && status.authorization != NotificationAuthorization::NotDetermined)
        )
    }

    /// Text for the owner.
    pub fn summary(&self) -> String {
        match self {
            Self::Unknown => "Apassy is checking the notification settings.".to_owned(),
            Self::Asking => {
                "macOS asks you now: select \"Allow\" in the Apassy notification at the top right of the screen. Until then, questions wait in Decisions without a notification.".to_owned()
            }
            Self::Problem(text) => {
                format!("Notifications do not work: {text} Questions still wait in Decisions.")
            }
            Self::Ready(status) => match status.authorization {
                NotificationAuthorization::NotDetermined => {
                    "You did not allow notifications yet. Select \"Allow notifications\". Until then, questions wait in Decisions without a notification.".to_owned()
                }
                NotificationAuthorization::Denied => {
                    "Notifications are not allowed for Apassy. macOS does not ask again: allow them in System Settings > Notifications > Apassy. Questions still wait in Decisions.".to_owned()
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
                    "Notifications are allowed, but alerts and Notification Center are off for Apassy. Turn them on in System Settings > Notifications > Apassy. Questions still wait in Decisions.".to_owned()
                }
                NotificationAuthorization::Unknown => {
                    "macOS gave an unknown notification permission. Questions still wait in Decisions.".to_owned()
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
    /// Also called when a run starts to wait: the questions waiter posts it through the
    /// relay ([`NotificationCenter::set_question_hook`]).
    question_hook: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
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
            question_hook: Mutex::new(None),
        });
        {
            let shared = Arc::clone(&shared);
            approvals.set_notifier(move || {
                shared.wake();
                if let Some(hook) = shared
                    .question_hook
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .as_ref()
                {
                    hook();
                }
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

    /// Run `hook` too when a run starts to wait: the questions waiter
    /// (`crate::questions::QuestionsWorker::waker`) then posts it through the relay at once.
    pub fn set_question_hook(&self, hook: impl Fn() + Send + Sync + 'static) {
        *self
            .shared
            .question_hook
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(Box::new(hook));
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

    /// Forget the deliveries of activity entries. Another vault has other entries with
    /// the same IDs (ADR 0013). Waiting runs keep theirs.
    pub fn forget_activity(&self) {
        self.shared.update(|view| {
            view.deliveries
                .retain(|key, _| !matches!(key, EventKey::Activity(_)));
        });
    }

    /// Read the notification settings again. It never shows a prompt.
    pub fn refresh_status(&self) {
        self.send(Job::Status);
    }

    /// Show a channel problem, for example when System Settings does not open. The
    /// text must not contain a secret value.
    pub fn report_problem(&self, text: String) {
        self.shared
            .update(|view| view.channel = ChannelState::Problem(text));
    }

    /// Post one notification for `event` with the ID of its question, request, or
    /// correction. The same key again replaces the notification. The text has no secret
    /// value ([`OwnerEvent::preview_name`]).
    pub fn announce(&self, event: OwnerEvent, id: u64, agent: &str) {
        let jobs = self.jobs.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(jobs) = jobs.as_ref() {
            queue_event(&self.shared, jobs, event, id, agent);
        }
    }

    /// Show the macOS permission prompt when the owner has not decided. The channel
    /// shows [`ChannelState::Asking`] until the notifier answers.
    pub fn request_permission(&self) {
        self.shared
            .update(|view| view.channel = ChannelState::Asking);
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

/// The IDs of `ids` above `last`, oldest first, and the new mark. Without a mark yet
/// (`None`: the first look at this vault) nothing is new: the mark becomes the highest
/// ID.
fn fresh_ids(last: Option<u64>, ids: &[u64]) -> (Vec<u64>, u64) {
    let highest = ids.iter().copied().max().unwrap_or(0);
    match last {
        None => (Vec::new(), highest),
        Some(last) => {
            let mut fresh: Vec<u64> = ids.iter().copied().filter(|id| *id > last).collect();
            fresh.sort_unstable();
            (fresh, last.max(highest))
        }
    }
}

/// What waits for the owner in the vault besides the questions: the open credential
/// requests with the agent name, and the open corrections.
struct OwnerItems {
    requests: Vec<(u64, String)>,
    corrections: Vec<u64>,
}

/// The newest credential request and correction that the watcher saw in one vault file.
struct OwnerMarks {
    path: PathBuf,
    request: u64,
    correction: u64,
}

/// Announce the credential requests and the corrections that are newer than `marks`
/// (ADR 0025 §5, §6), and return the marks for the next pass. The first look at a vault
/// file announces nothing: what waited before is in Decisions already.
fn announce_owner_items(
    shared: &Shared,
    jobs: &Sender<Job>,
    marks: Option<OwnerMarks>,
    path: PathBuf,
    items: &OwnerItems,
) -> OwnerMarks {
    let marks = marks.filter(|marks| marks.path == path);
    let request_ids: Vec<u64> = items.requests.iter().map(|(id, _)| *id).collect();
    let (requests, request) = fresh_ids(marks.as_ref().map(|m| m.request), &request_ids);
    let (corrections, correction) =
        fresh_ids(marks.as_ref().map(|m| m.correction), &items.corrections);
    for id in requests {
        let agent = items
            .requests
            .iter()
            .find(|(request, _)| *request == id)
            .map_or("", |(_, agent)| agent.as_str());
        queue_event(shared, jobs, OwnerEvent::CredentialRequested, id, agent);
    }
    for id in corrections {
        queue_event(shared, jobs, OwnerEvent::CorrectionProposed, id, "");
    }
    OwnerMarks {
        path,
        request,
        correction,
    }
}

fn watch_loop(shared: &Shared, approvals: &ApprovalQueue, vault: &SharedVault, jobs: &Sender<Job>) {
    let mut notified_runs = BTreeSet::new();
    // `None` until the watcher sees an unlocked vault. Then that vault file and its
    // newest entry ID: older entries are history and cause no notification. Each vault
    // file has its own entry IDs, so another file starts again (ADR 0013).
    let mut last_entry: Option<(PathBuf, u64)> = None;
    // The same for the credential requests and the corrections.
    let mut owner_marks: Option<OwnerMarks> = None;
    loop {
        let pending = approvals.pending();
        for run in &pending {
            if notified_runs.insert(run.id) {
                queue_event(
                    shared,
                    jobs,
                    OwnerEvent::QuestionWaiting,
                    run.id,
                    &run.agent,
                );
            }
        }
        notified_runs.retain(|id| pending.iter().any(|run| run.id == *id));

        let (rows, owner_items) = {
            let guard = vault.lock().unwrap_or_else(PoisonError::into_inner);
            match guard.as_ref() {
                Some(open) if !open.is_locked() => {
                    let path = open.path().to_path_buf();
                    let owner_items = match (open.credential_requests(true), open.corrections(true))
                    {
                        (Ok(requests), Ok(corrections)) => Some((
                            path.clone(),
                            OwnerItems {
                                requests: requests
                                    .into_iter()
                                    .map(|request| (request.id, request.agent_name))
                                    .collect(),
                                corrections: corrections
                                    .into_iter()
                                    .map(|correction| correction.id)
                                    .collect(),
                            },
                        )),
                        _ => None,
                    };
                    (
                        open.recent_activity(ACTIVITY_WINDOW)
                            .ok()
                            .map(|rows| (path, rows)),
                        owner_items,
                    )
                }
                _ => (None, None),
            }
        };
        owner_marks = owner_items.map(|(path, items)| {
            announce_owner_items(shared, jobs, owner_marks.take(), path, &items)
        });
        match rows {
            None => last_entry = None,
            Some((path, rows)) => {
                let newest = rows.first().map_or(0, |row| row.id);
                let last = last_entry
                    .take()
                    .filter(|(last_path, _)| *last_path == path)
                    .map(|(_, last)| last);
                if let Some(last) = last {
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
                last_entry = Some((path, last.map_or(newest, |last| last.max(newest))));
            }
        }
        if !shared.sleep(POLL_INTERVAL) {
            return;
        }
    }
}

fn queue_event(shared: &Shared, jobs: &Sender<Job>, event: OwnerEvent, id: u64, agent: &str) {
    shared.update(|view| {
        view.deliveries.insert(event.key(id), Delivery::Sending);
    });
    let _ = jobs.send(Job::Notify {
        key: event.key(id),
        agent: event.preview_name(agent),
        event: event.native(),
    });
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
                let denied = matches!(&result, Err(err) if err.code() == Some(HelperErrorCode::NotificationsDenied));
                let (delivery, mut channel) = delivery_of(result);
                if denied {
                    // Show the real permission state: "not decided" keeps the "Allow
                    // notifications" button, "denied" shows the settings button.
                    if let Ok(status) = helper.notify_status() {
                        channel = Some(ChannelState::Ready(status));
                    }
                }
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
                        | HelperErrorCode::CallerNotAllowed
                )
            ) || matches!(err, NativeError::HelperMissing(_));
            (
                Delivery::Failed(text.clone()),
                channel.then_some(ChannelState::Problem(text)),
            )
        }
    }
}

/// Text for the owner. It has no secret value: the notifier messages are fixed text.
fn failure_text(err: &NativeError) -> String {
    match err {
        NativeError::Helper {
            code: HelperErrorCode::NotificationsDenied,
            ..
        } => "notifications are not allowed for Apassy.".to_owned(),
        NativeError::Helper {
            code: HelperErrorCode::NotificationsUnavailable,
            ..
        } => {
            "the notifier is not inside Apassy.app (Contents/Helpers/ApassyNotify.app).".to_owned()
        }
        NativeError::Helper {
            code: HelperErrorCode::CallerNotAllowed,
            ..
        } => {
            "the notifier refused this app. The Apassy.app bundle is broken or changed.".to_owned()
        }
        NativeError::HelperMissing(_) => {
            "this build has no notifier. Notifications work only in Apassy.app.".to_owned()
        }
        NativeError::Timeout(limit) => {
            format!("the notifier did not answer in {} s.", limit.as_secs())
        }
        other => format!("{other}."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(authorization: NotificationAuthorization) -> NotificationStatus {
        NotificationStatus {
            authorization,
            alert: NotificationSetting::Enabled,
            alert_style: crate::native::AlertStyle::Banner,
            notification_center: NotificationSetting::Enabled,
            lock_screen: NotificationSetting::Enabled,
            sound: NotificationSetting::Enabled,
        }
    }

    /// ADR 0025 §3e: each question, request, and correction has its own key, and the
    /// preview names only the agent (N2).
    #[test]
    fn owner_events_have_their_own_keys_and_name_only_the_agent() {
        assert_eq!(OwnerEvent::QuestionWaiting.key(4), EventKey::Run(4));
        assert_eq!(OwnerEvent::CredentialRequested.key(4), EventKey::Request(4));
        assert_eq!(
            OwnerEvent::CorrectionProposed.key(4),
            EventKey::Correction(4)
        );
        for event in [
            OwnerEvent::QuestionWaiting,
            OwnerEvent::CredentialRequested,
            OwnerEvent::CorrectionProposed,
        ] {
            let name = event.preview_name("Claude\u{7}Code");
            let preview = Notification::new(&event.key(4).notification_id(), &name, event.native())
                .expect("a valid preview");
            assert!(!preview.body().contains('\u{7}'), "{}", preview.body());
            assert_eq!(preview.title(), "Approval waiting");
        }
        assert_eq!(
            OwnerEvent::QuestionWaiting.preview_name("Claude Code"),
            "Claude Code"
        );
        assert_eq!(
            OwnerEvent::CorrectionProposed.preview_name("Codex"),
            "Apassy"
        );
        assert_eq!(OwnerEvent::QuestionWaiting.preview_name("  "), "unknown");
    }

    /// ADR 0025 §5, §6: a credential request or a correction gets one notification when
    /// it is new. What waited at the first look is not announced again.
    #[test]
    fn only_new_requests_and_corrections_are_announced() {
        assert_eq!(fresh_ids(None, &[3, 7, 5]), (Vec::new(), 7));
        assert_eq!(fresh_ids(Some(7), &[3, 9, 7, 8]), (vec![8, 9], 9));
        assert_eq!(fresh_ids(Some(9), &[3]), (Vec::new(), 9));
        assert_eq!(fresh_ids(None, &[]), (Vec::new(), 0));
        assert_eq!(fresh_ids(Some(0), &[1]), (vec![1], 1));
    }

    #[test]
    fn the_button_shows_only_before_a_decision_and_not_during_the_prompt() {
        assert!(
            ChannelState::Ready(status(NotificationAuthorization::NotDetermined))
                .needs_permission()
        );
        assert!(!ChannelState::Asking.needs_permission());
        assert!(!ChannelState::Asking.can_deliver());
        assert!(ChannelState::Asking.summary().contains("\"Allow\""));
        assert!(!ChannelState::Ready(status(NotificationAuthorization::Denied)).needs_permission());
        assert!(
            !ChannelState::Ready(status(NotificationAuthorization::Authorized)).needs_permission()
        );
        assert!(ChannelState::Ready(status(NotificationAuthorization::Authorized)).can_deliver());
    }

    #[test]
    fn only_system_settings_can_help_after_a_denial() {
        // Measured on macOS 27: after a denial, or after an unanswered prompt, a new
        // permission request fails at once with no prompt.
        assert!(ChannelState::Ready(status(NotificationAuthorization::Denied)).needs_settings());
        let mut off = status(NotificationAuthorization::Authorized);
        off.alert = NotificationSetting::Disabled;
        off.notification_center = NotificationSetting::Disabled;
        assert!(ChannelState::Ready(off).needs_settings());
        for state in [
            ChannelState::Ready(status(NotificationAuthorization::NotDetermined)),
            ChannelState::Ready(status(NotificationAuthorization::Authorized)),
            ChannelState::Asking,
            ChannelState::Unknown,
        ] {
            assert!(!state.needs_settings(), "{state:?}");
        }
        assert!(NOTIFICATION_SETTINGS_URL.ends_with("?id=com.wydrox.apassy.notify"));
        assert!(NOTIFICATION_SETTINGS_URL.ends_with(crate::native::NOTIFIER_BUNDLE_ID));
    }

    #[test]
    fn a_refused_or_missing_notifier_is_a_visible_channel_problem() {
        for err in [
            NativeError::Helper {
                code: HelperErrorCode::CallerNotAllowed,
                message: "synthetic".to_owned(),
            },
            NativeError::Helper {
                code: HelperErrorCode::NotificationsUnavailable,
                message: "synthetic".to_owned(),
            },
            NativeError::HelperMissing("/nowhere/ApassyNotify".into()),
        ] {
            let (delivery, channel) = delivery_of(Err(err.clone()));
            let Delivery::Failed(text) = &delivery else {
                panic!("{err:?} gave {delivery:?}");
            };
            assert!(text.contains("notifier"), "{text}");
            assert!(
                matches!(channel, Some(ChannelState::Problem(_))),
                "{err:?} gave {channel:?}"
            );
        }
        // A timeout is a failed delivery, but it says nothing about the channel.
        let (delivery, channel) = delivery_of(Err(NativeError::Timeout(Duration::from_secs(40))));
        assert!(matches!(delivery, Delivery::Failed(_)));
        assert_eq!(channel, None);
    }
}
