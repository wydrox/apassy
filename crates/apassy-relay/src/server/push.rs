//! The push trigger (docs/SPEC.md sections 25.6 and 32.5).
//!
//! After a question is posted, its handler hands the push targets of the routing set to
//! four push senders through a bounded fair queue, and never waits for it. Two modes:
//!
//! - **Worker** (the hosted relay): the push tokens of the devices. The thread asks the
//!   Worker's push route (`APASSY_RELAY_PUSH_URL`, header `X-Apassy-Push` with the push
//!   secret) to send the fixed notification, one call per environment and batch, retries
//!   with backoff, and marks the tokens that APNs refuses for good.
//! - **Gateway** (a node, push-gateway-v1): the push handles of the devices
//!   (`PUT /v1/push/handle`, team schema 8). One `POST <gateway>/v1/push` per handle with
//!   the proof of the handle's secret, no retry; the handles that the gateway or APNs
//!   refuses for good are marked. The node never holds a token.
//!
//! The relay sends Apple nothing itself and never logs a token, a handle, a secret, a
//! proof, a summary, or anything of a question.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use rusqlite::{Connection, OptionalExtension, params};
use serde::Deserialize;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::config::PushConfig;
use crate::error::{RelayError, RelayResult, codes};
use crate::hostkeys::{decode_b64, encode_b64};
use crate::ids::{DeviceId, TeamId};
use crate::secret::SecretString;
use crate::server::Core;
use crate::server::audit::{Audit, RELAY_ACTOR, member_actor};
use crate::server::auth::MemberAuth;
use crate::server::store::{Store, db, to_i};

/// The header that carries the push secret to the Worker.
pub const PUSH_HEADER: &str = "X-Apassy-Push";
/// The APNs collapse id of every question: a constant, so it tells Apple nothing, and
/// a new question replaces the notification on the screen.
pub const COLLAPSE_ID: &str = "apassy-question";
/// The most tokens in one call to the Worker. Each is one subrequest of the Worker.
pub const MAX_BATCH: usize = 50;
/// Queued, in-flight and retry jobs together. A full queue drops the new job.
const QUEUE: usize = 256;
/// The jobs of all Connect teams in the queue at once: half of it, so the pushes of
/// operator teams always find room (docs/SPEC.md section 26).
const CONNECT_JOBS: usize = QUEUE / 2;
/// The jobs of one Connect team in the queue at once.
const CONNECT_TEAM_JOBS: usize = 2;
const _: () = assert!(CONNECT_JOBS < QUEUE && CONNECT_TEAM_JOBS < CONNECT_JOBS);
/// One call to the Worker, from the connection to the last byte of the answer
/// (`PushConfig::timeout`).
pub(crate) const TIMEOUT: Duration = Duration::from_secs(10);
/// The unit of the retry backoff (`PushConfig::backoff_unit`).
pub(crate) const BACKOFF_UNIT: Duration = Duration::from_secs(1);
/// The largest answer of the Worker that is read.
const MAX_ANSWER_BYTES: u64 = 256 * 1024;
/// Seconds between two `push_failed` rows of one device, and two `push_dropped` rows
/// of one team.
const ROW_INTERVAL_SECS: u64 = 10;
const MAX_THROTTLES: usize = 4096;
/// The header of `POST /v1/questions` that carries a sealed summary (push-gateway-v1
/// section 12). Only a node in the gateway mode reads it.
pub const SUMMARY_HEADER: &str = "X-Apassy-Push-Summary";
/// The length of a sealed summary: b64u of 540 bytes.
pub const SUMMARY_CHARS: usize = 720;
const SUMMARY_BYTES: usize = 540;
/// The domain of the proof of a push (push-gateway-v1 section 7).
pub const PROOF_DOMAIN: &str = "apassy-push-v1";
/// The bytes of a handle after b64u decoding (push-gateway-v1 section 10).
pub const MIN_HANDLE_BYTES: usize = 16;
pub const MAX_HANDLE_BYTES: usize = 1024;
/// The bytes of a handle's secret.
pub const SECRET_BYTES: usize = 32;
/// The throttle key of the `push_failed {reason: "clock"}` row: one per team.
const CLOCK_THROTTLE: u64 = u64::MAX;

/// One push token of the routing set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushTarget {
    pub device: DeviceId,
    /// Lowercase hex, as the device sent it.
    pub token: String,
    /// `development` or `production`.
    pub environment: String,
}

/// One push handle of the routing set (gateway mode). The secret stays in memory and is
/// erased on drop; `Debug` names the device only.
#[derive(Clone, PartialEq, Eq)]
pub struct HandleTarget {
    pub device: DeviceId,
    /// The gateway origin the device named at `PUT /v1/push/handle`.
    pub gateway: String,
    /// The handle as b64u text, as sent to the gateway and in the proof.
    pub handle: String,
    secret: Zeroizing<Vec<u8>>,
}

impl HandleTarget {
    pub fn new(device: DeviceId, gateway: String, handle: String, secret: Vec<u8>) -> Self {
        Self {
            device,
            gateway,
            handle,
            secret: Zeroizing::new(secret),
        }
    }
}

impl std::fmt::Debug for HandleTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HandleTarget(device {})", self.device.0)
    }
}

/// The push targets of one question: the tokens of the Worker mode, or the handles of
/// the gateway mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Targets {
    Tokens(Vec<PushTarget>),
    Handles(Vec<HandleTarget>),
}

impl Targets {
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Tokens(targets) => targets.is_empty(),
            Self::Handles(targets) => targets.is_empty(),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Tokens(targets) => targets.len(),
            Self::Handles(targets) => targets.len(),
        }
    }
}

/// The pushes of one question.
struct Job {
    team: TeamId,
    /// The job of a Connect team: it holds a seat of the `Budget` until it is sent.
    connect: bool,
    store: Arc<Store>,
    audit: Arc<Audit>,
    expires_at: u64,
    targets: Targets,
    /// The sealed summary of the question (gateway mode): in memory only, never stored.
    summary: Option<String>,
    qid: String,
    closed: Arc<AtomicBool>,
    attempt: u32,
    due: Instant,
}

/// The queued jobs of Connect teams: of each team, and of all of them.
#[derive(Default)]
struct Budget {
    teams: HashMap<TeamId, usize>,
    all: usize,
}

impl Budget {
    /// A seat for one more job of the Connect team `team`, or false when the team has
    /// `CONNECT_TEAM_JOBS` queued or all Connect teams have `CONNECT_JOBS`.
    fn admit(&mut self, team: &TeamId) -> bool {
        let held = self.teams.get(team).copied().unwrap_or(0);
        if held >= CONNECT_TEAM_JOBS || self.all >= CONNECT_JOBS {
            return false;
        }
        self.teams.insert(team.clone(), held + 1);
        self.all += 1;
        true
    }

    /// Gives a seat back: its job was sent, or never queued.
    fn release(&mut self, team: &TeamId) {
        if let Some(held) = self.teams.get_mut(team) {
            *held = held.saturating_sub(1);
            if *held == 0 {
                self.teams.remove(team);
            }
            self.all = self.all.saturating_sub(1);
        }
    }
}

/// A bounded round-robin scheduler. Seats include in-flight jobs and retries.
#[derive(Default)]
struct Schedule {
    jobs: HashMap<TeamId, VecDeque<Job>>,
    order: VecDeque<TeamId>,
    busy: HashSet<TeamId>,
    ids: HashSet<(TeamId, String)>,
    held: HashMap<TeamId, usize>,
    budget: Budget,
}

impl Schedule {
    fn admit(&mut self, job: Job) -> bool {
        let key = (job.team.clone(), job.qid.clone());
        if self.ids.contains(&key) {
            return true;
        }
        if self.ids.len() >= QUEUE
            || self.held.get(&job.team).copied().unwrap_or(0) >= 16
            || (job.connect && !self.budget.admit(&job.team))
        {
            return false;
        }
        self.ids.insert(key);
        *self.held.entry(job.team.clone()).or_default() += 1;
        self.put(job);
        true
    }

    fn put(&mut self, job: Job) {
        let jobs = self.jobs.entry(job.team.clone()).or_default();
        if jobs.is_empty() {
            self.order.push_back(job.team.clone());
        }
        jobs.push_back(job);
    }

    fn take(&mut self, now: u64) -> Option<Job> {
        for _ in 0..self.order.len() {
            let team = self.order.pop_front()?;
            let jobs = self.jobs.get_mut(&team)?;
            let ready = if self.busy.contains(&team) {
                None
            } else {
                jobs.iter().position(|job| {
                    job.due <= Instant::now()
                        || job.expires_at <= now
                        || job.closed.load(Ordering::Relaxed)
                })
            };
            let job = ready.and_then(|index| jobs.remove(index));
            if jobs.is_empty() {
                self.jobs.remove(&team);
            } else {
                self.order.push_back(team.clone());
            }
            if job.is_some() {
                self.busy.insert(team);
                return job;
            }
        }
        None
    }

    fn finish(&mut self, job: Job, now: u64) {
        self.busy.remove(&job.team);
        if !job.targets.is_empty()
            && job.due < Instant::now() + Duration::from_secs(job.expires_at.saturating_sub(now))
            && job.expires_at > now
            && !job.closed.load(Ordering::Relaxed)
        {
            self.put(job);
            return;
        }
        self.ids.remove(&(job.team.clone(), job.qid));
        if job.connect {
            self.budget.release(&job.team);
        }
        if let Some(held) = self.held.get_mut(&job.team) {
            *held -= 1;
            if *held == 0 {
                self.held.remove(&job.team);
            }
        }
    }
}

type SharedSchedule = (Mutex<Schedule>, Condvar);

/// What the push trigger does.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Mode {
    Off,
    /// The Worker of the hosted relay, with the APNs topic of its push tokens.
    Worker {
        topic: String,
    },
    /// The push gateways that the devices of a node may name.
    Gateway {
        gateways: Vec<String>,
    },
}

/// The push trigger of the relay, shared by every team.
pub struct Push {
    mode: Mode,
    queue: Arc<SharedSchedule>,
    last_dropped: Mutex<HashMap<TeamId, u64>>,
}

impl Push {
    pub fn off() -> Arc<Self> {
        Arc::new(Self {
            mode: Mode::Off,
            queue: Arc::new((Mutex::new(Schedule::default()), Condvar::new())),
            last_dropped: Mutex::new(HashMap::new()),
        })
    }

    /// Four senders, at most one in-flight question per team. A stalled team cannot
    /// hold all senders, and backoff never occupies a sender.
    pub fn start(config: Option<PushConfig>, stop: Arc<AtomicBool>) -> RelayResult<Arc<Self>> {
        let Some(config) = config else {
            return Ok(Self::off());
        };
        let queue = Arc::new((Mutex::new(Schedule::default()), Condvar::new()));
        for index in 0..4 {
            let (config, queue, stop) = (config.clone(), queue.clone(), stop.clone());
            std::thread::Builder::new()
                .name(format!("relay-push-{index}"))
                .spawn(move || run(&config, &queue, &stop))
                .map_err(|_| RelayError::internal("The push thread cannot start."))?;
        }
        let mode = match config {
            PushConfig::Worker { topic, .. } => Mode::Worker { topic },
            PushConfig::Gateway { gateways, .. } => Mode::Gateway { gateways },
        };
        Ok(Arc::new(Self {
            mode,
            queue,
            last_dropped: Mutex::new(HashMap::new()),
        }))
    }

    /// The APNs topic of the Worker mode (`PUT /v1/push/token`); `None` without push and
    /// in the gateway mode.
    pub fn topic(&self) -> Option<&str> {
        match &self.mode {
            Mode::Worker { topic } => Some(topic.as_str()),
            Mode::Off | Mode::Gateway { .. } => None,
        }
    }

    /// True for a node that pushes through a gateway.
    pub fn is_gateway(&self) -> bool {
        matches!(self.mode, Mode::Gateway { .. })
    }

    /// The gateways that a device may name; empty outside the gateway mode.
    pub fn gateways(&self) -> &[String] {
        match &self.mode {
            Mode::Gateway { gateways } => gateways.as_slice(),
            Mode::Off | Mode::Worker { .. } => &[],
        }
    }

    /// True when push is on, in either mode.
    pub fn enabled(&self) -> bool {
        self.mode != Mode::Off
    }

    /// The push targets of `devices` that did not fail: their push tokens in the Worker
    /// mode, their push handles in the gateway mode, none without push.
    pub fn targets(&self, conn: &Connection, devices: &[DeviceId]) -> RelayResult<Targets> {
        match self.mode {
            Mode::Off => Ok(Targets::Tokens(Vec::new())),
            Mode::Worker { .. } => token_targets(conn, devices).map(Targets::Tokens),
            Mode::Gateway { .. } => handle_targets(conn, devices).map(Targets::Handles),
        }
    }

    pub fn has_team_jobs(&self, team: &TeamId) -> bool {
        self.queue
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .held
            .contains_key(team)
    }

    pub fn status(&self) -> serde_json::Value {
        let queue = self.queue.0.lock().unwrap_or_else(PoisonError::into_inner);
        let mode = match self.mode {
            Mode::Off => "off",
            Mode::Worker { .. } => "worker",
            Mode::Gateway { .. } => "gateway",
        };
        json!({"enabled": self.enabled(), "mode": mode, "held": queue.ids.len(),
            "in_flight_teams": queue.busy.len(), "capacity": QUEUE})
    }

    /// Never waits for network or queue space. Duplicate pending question ids coalesce.
    /// `summary`: the checked sealed summary of the question (gateway mode only).
    pub fn trigger(
        &self,
        core: &Core,
        qid: &str,
        targets: Targets,
        expires_at: u64,
        summary: Option<String>,
        now: u64,
    ) {
        let fits = matches!(
            (&self.mode, &targets),
            (Mode::Worker { .. }, Targets::Tokens(_)) | (Mode::Gateway { .. }, Targets::Handles(_))
        );
        if !fits || targets.is_empty() || expires_at <= now {
            return;
        }
        let job = Job {
            team: core.team.clone(),
            connect: core.kind == crate::api::TeamKind::Connect,
            store: core.store.clone(),
            audit: core.audit.clone(),
            expires_at,
            targets,
            summary: summary.filter(|_| self.is_gateway()),
            qid: qid.to_owned(),
            closed: core.closed.clone(),
            attempt: 0,
            due: Instant::now(),
        };
        let admitted = self
            .queue
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .admit(job);
        self.queue.1.notify_all();
        if !admitted {
            let mut last = self
                .last_dropped
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            last.retain(|_, at| now < at.saturating_add(ROW_INTERVAL_SECS));
            if last
                .get(&core.team)
                .is_none_or(|at| now >= at.saturating_add(ROW_INTERVAL_SECS))
                && last.len() < MAX_THROTTLES
            {
                last.insert(core.team.clone(), now);
                drop(last);
                let _ = core.audit.write(
                    &core.store,
                    now,
                    RELAY_ACTOR,
                    "push_dropped",
                    None,
                    &json!({}),
                );
            }
        }
    }
}

/// The answer of the Worker's push route.
#[derive(Debug, Deserialize)]
struct WorkerAnswer {
    results: Vec<TokenResult>,
}

#[derive(Debug, Deserialize)]
struct TokenResult {
    token: String,
    status: u16,
    #[serde(default)]
    reason: Option<String>,
}

/// True for an APNs answer that means the token will never work again: the device
/// must send `PUT /v1/push/token` before it gets another push.
pub fn is_final(status: u16, reason: &str) -> bool {
    status == 410
        || (status == 400 && matches!(reason, "BadDeviceToken" | "DeviceTokenNotForTopic"))
}

/// An APNs reason for the audit: one of Apple's words, else `Unknown`.
fn reason_word(reason: Option<&str>) -> String {
    match reason {
        Some(word)
            if (1..=64).contains(&word.len()) && word.bytes().all(|b| b.is_ascii_alphabetic()) =>
        {
            word.to_string()
        }
        _ => "Unknown".to_string(),
    }
}

fn run(config: &PushConfig, queue: &SharedSchedule, stop: &AtomicBool) {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .timeout_global(Some(config.timeout()))
        .build()
        .into();
    let mut last_failed = HashMap::new();
    while !stop.load(Ordering::Relaxed) {
        let mut schedule = queue.0.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(mut job) = schedule.take(crate::now_unix()) else {
            let _ = queue.1.wait_timeout(schedule, Duration::from_millis(200));
            continue;
        };
        drop(schedule);
        let tokens = matches!(job.targets, Targets::Tokens(_));
        let next = match config {
            PushConfig::Worker { url, secret, .. } if tokens => {
                let worker = WorkerRoute {
                    url,
                    secret,
                    timeout: config.timeout(),
                };
                Targets::Tokens(send_job(&worker, &agent, &job, &mut last_failed))
            }
            // A gateway push is sent once (push-gateway-v1 section 10): no retry.
            PushConfig::Gateway { gateways, .. } if !tokens => {
                send_handles(gateways, config.timeout(), &agent, &job, &mut last_failed);
                Targets::Handles(Vec::new())
            }
            _ => Targets::Tokens(Vec::new()),
        };
        job.targets = next;
        job.attempt = job.attempt.saturating_add(1);
        let now = crate::now_unix();
        let jitter = job.team.as_str().bytes().map(u64::from).sum::<u64>() % 3;
        job.due = Instant::now() + retry_delay(config.backoff_unit(), job.attempt, jitter);
        queue
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .finish(job, now);
        queue.1.notify_all();
    }
}

/// The Worker's push route and its secret.
struct WorkerRoute<'a> {
    url: &'a str,
    secret: &'a SecretString,
    timeout: Duration,
}

/// Exponential backoff (1..60 units) plus 0..2 units of per-team jitter.
fn retry_delay(unit: Duration, attempt: u32, jitter: u64) -> Duration {
    let units = (1u64 << attempt.saturating_sub(1).min(6)).min(60) + jitter;
    unit.saturating_mul(u32::try_from(units).unwrap_or(u32::MAX))
}

fn transient(status: u16) -> bool {
    status == 0 || status == 429 || status >= 500
}

/// Read the live question, route and token before *every* attempt. Settled, expired,
/// suspended, revoked, demoted and replaced tokens no longer receive retries.
fn current_targets(job: &Job, now: u64) -> Vec<PushTarget> {
    let Targets::Tokens(tokens) = &job.targets else {
        return Vec::new();
    };
    if now >= job.expires_at || job.closed.load(Ordering::Relaxed) {
        return Vec::new();
    }
    job.store.with(|conn| {
        let mut targets = Vec::new();
        for target in tokens {
            let live: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM question q JOIN device asker ON asker.id = q.device_id \
                 JOIN member am ON am.id = asker.member_id \
                 JOIN device d ON d.id = ?1 JOIN member m ON m.id = d.member_id \
                 JOIN push_token p ON p.device_id = d.id \
                 WHERE q.qid = ?2 AND q.state = 'open' AND q.expires_at > ?3 \
                 AND NOT EXISTS (SELECT 1 FROM question_answer a WHERE a.qid = q.qid) \
                 AND asker.revoked_at IS NULL AND am.revoked_at IS NULL \
                 AND d.revoked_at IS NULL AND m.revoked_at IS NULL AND d.id <> q.device_id \
                 AND (m.id = q.member_id OR (q.to_approvers = 1 AND m.role IN ('owner','manager'))) \
                 AND p.failed_at IS NULL AND p.token = ?4 AND p.environment = ?5)",
                params![to_i(target.device.0), job.qid, to_i(now), target.token.as_bytes(), target.environment],
                |r| r.get(0),
            ).map_err(db)?;
            if live { targets.push(target.clone()); }
        }
        Ok(targets)
    }).unwrap_or_default()
}

/// One call to the Worker: the HTTP status and the per-token results (`None` when the
/// answer is not one).
fn call_worker(
    config: &WorkerRoute<'_>,
    agent: &ureq::Agent,
    tokens: &[&str],
    environment: &str,
    expires_at: u64,
) -> (u16, Option<WorkerAnswer>) {
    let body = json!({
        "tokens": tokens,
        "environment": environment,
        "collapse_id": COLLAPSE_ID,
        "expires_at": expires_at,
    })
    .to_string();
    let Ok(request) = ureq::http::Request::builder()
        .method("POST")
        .uri(config.url)
        .header(PUSH_HEADER, config.secret.expose())
        .header("Content-Type", "application/json")
        .body(body)
    else {
        return (0, None);
    };
    let remaining = expires_at.saturating_sub(crate::now_unix());
    if remaining == 0 {
        return (0, None);
    }
    let request = agent
        .configure_request(request)
        .timeout_global(Some(config.timeout.min(Duration::from_secs(remaining))))
        .build();
    let Ok(mut response) = agent.run(request) else {
        return (0, None);
    };
    let status = response.status().as_u16();
    if status != 200 {
        return (status, None);
    }
    let answer = response
        .body_mut()
        .with_config()
        .limit(MAX_ANSWER_BYTES)
        .read_to_vec()
        .ok()
        .and_then(|bytes| serde_json::from_slice::<WorkerAnswer>(&bytes).ok());
    (status, answer)
}

/// Sends the pushes of one job and records what happened.
fn send_job(
    config: &WorkerRoute<'_>,
    agent: &ureq::Agent,
    job: &Job,
    last_failed: &mut HashMap<(TeamId, u64), u64>,
) -> Vec<PushTarget> {
    let current = current_targets(job, crate::now_unix());
    let mut retry = Vec::new();
    let mut by_environment: BTreeMap<&str, Vec<&PushTarget>> = BTreeMap::new();
    for target in &current {
        by_environment
            .entry(target.environment.as_str())
            .or_default()
            .push(target);
    }
    for (environment, targets) in by_environment {
        let mut sent = 0usize;
        for batch in targets.chunks(MAX_BATCH) {
            let tokens: Vec<&str> = batch.iter().map(|target| target.token.as_str()).collect();
            let (status, answer) = call_worker(config, agent, &tokens, environment, job.expires_at);
            let now = crate::now_unix();
            let Some(answer) = answer else {
                // The Worker did not answer, or not with results: no push of this batch
                // was sent. One row per team and ten seconds.
                if throttle(last_failed, &job.team, 0, now) {
                    let _ = job.audit.write(
                        &job.store,
                        now,
                        RELAY_ACTOR,
                        "push_failed",
                        None,
                        &json!({"count": batch.len(), "status": status, "reason": "worker"}),
                    );
                }
                if transient(status) || status == 200 {
                    retry.extend(batch.iter().map(|target| (*target).clone()));
                }
                continue;
            };
            for target in batch {
                // A token the Worker did not list counts as not sent.
                let Some(result) = answer.results.iter().find(|r| r.token == target.token) else {
                    retry.push((*target).clone());
                    continue;
                };
                if result.status == 200 {
                    sent += 1;
                    continue;
                }
                let reason = reason_word(result.reason.as_deref());
                if is_final(result.status, &reason) {
                    let _ = mark_failed(&job.store, target, now);
                } else if transient(result.status) {
                    retry.push((*target).clone());
                }
                if throttle(last_failed, &job.team, target.device.0, now) {
                    let _ = job.audit.write(
                        &job.store,
                        now,
                        RELAY_ACTOR,
                        "push_failed",
                        None,
                        &json!({"device_id": target.device, "status": result.status, "reason": reason}),
                    );
                }
            }
        }
        if sent > 0 {
            let _ = job.audit.write(
                &job.store,
                crate::now_unix(),
                RELAY_ACTOR,
                "push_sent",
                None,
                &json!({"count": sent, "environment": environment}),
            );
        }
    }
    retry
}

/// True at most once per ten seconds for one device of one team (device 0: the team).
fn throttle(last: &mut HashMap<(TeamId, u64), u64>, team: &TeamId, device: u64, now: u64) -> bool {
    last.retain(|_, at| now < at.saturating_add(ROW_INTERVAL_SECS));
    let key = (team.clone(), device);
    if last
        .get(&key)
        .is_some_and(|at| now < at.saturating_add(ROW_INTERVAL_SECS))
    {
        return false;
    }
    if last.len() >= MAX_THROTTLES {
        return false;
    }
    last.insert(key, now);
    true
}

/// Marks the token failed, if the device still has this token: a `PUT` that came in
/// between keeps its new token.
fn mark_failed(store: &Store, target: &PushTarget, now: u64) -> RelayResult<()> {
    store.with(|conn| {
        conn.execute(
            "UPDATE push_token SET failed_at = ?3 WHERE device_id = ?1 AND token = ?2 AND failed_at IS NULL",
            params![to_i(target.device.0), target.token.as_bytes(), to_i(now)],
        )
        .map(drop)
        .map_err(db)
    })
}

/// The live push handles of the job: the question is open, unanswered, and not expired,
/// the device is still in its routing set, and its handle is the one of the job and has
/// not failed. Read before the push.
fn current_handles(job: &Job, now: u64) -> Vec<HandleTarget> {
    let Targets::Handles(handles) = &job.targets else {
        return Vec::new();
    };
    if now >= job.expires_at || job.closed.load(Ordering::Relaxed) {
        return Vec::new();
    }
    job.store.with(|conn| {
        let mut targets = Vec::new();
        for target in handles {
            let live: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM question q JOIN device asker ON asker.id = q.device_id \
                 JOIN member am ON am.id = asker.member_id \
                 JOIN device d ON d.id = ?1 JOIN member m ON m.id = d.member_id \
                 JOIN push_handle h ON h.device_id = d.id \
                 WHERE q.qid = ?2 AND q.state = 'open' AND q.expires_at > ?3 \
                 AND NOT EXISTS (SELECT 1 FROM question_answer a WHERE a.qid = q.qid) \
                 AND asker.revoked_at IS NULL AND am.revoked_at IS NULL \
                 AND d.revoked_at IS NULL AND m.revoked_at IS NULL AND d.id <> q.device_id \
                 AND (m.id = q.member_id OR (q.to_approvers = 1 AND m.role IN ('owner','manager'))) \
                 AND h.failed_at IS NULL AND h.handle = ?4 AND h.gateway = ?5)",
                params![to_i(target.device.0), job.qid, to_i(now), decode_b64(&target.handle, MAX_HANDLE_BYTES).unwrap_or_default(), target.gateway],
                |r| r.get(0),
            ).map_err(db)?;
            if live { targets.push(target.clone()); }
        }
        Ok(targets)
    }).unwrap_or_default()
}

/// The proof of one push (push-gateway-v1 section 7): b64u of HMAC-SHA256 under the
/// handle's secret of `"apassy-push-v1" 0 handle 0 at 0 expires_at 0 collapse_id
/// [0 summary]`.
pub fn proof(
    secret: &[u8],
    handle: &str,
    at: u64,
    expires_at: u64,
    collapse_id: &str,
    summary: Option<&str>,
) -> String {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret);
    let (at, expires_at) = (at.to_string(), expires_at.to_string());
    let mut parts = vec![
        PROOF_DOMAIN,
        handle,
        at.as_str(),
        expires_at.as_str(),
        collapse_id,
    ];
    if let Some(summary) = summary {
        parts.push(summary);
    }
    let message = parts.join("\0");
    encode_b64(ring::hmac::sign(&key, message.as_bytes()).as_ref())
}

/// The body of `POST /v1/push` (push-gateway-v1 section 7), fields in the order of the
/// contract. Every value is b64u, a number, or the constant collapse id: nothing needs
/// escaping.
pub fn push_body(target: &HandleTarget, at: u64, expires_at: u64, summary: Option<&str>) -> String {
    let proof = proof(
        &target.secret,
        &target.handle,
        at,
        expires_at,
        COLLAPSE_ID,
        summary,
    );
    let summary = summary
        .map(|summary| format!(",\"summary\":\"{summary}\""))
        .unwrap_or_default();
    format!(
        "{{\"v\":1,\"handle\":\"{}\",\"at\":{at},\"expires_at\":{expires_at},\"collapse_id\":\"{COLLAPSE_ID}\",\"proof\":\"{proof}\"{summary}}}",
        target.handle
    )
}

/// What a gateway said to one push.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayOutcome {
    /// HTTP 200 with the APNs result: its status (0: APNs unreachable) and reason word.
    Apns { status: u16, reason: String },
    /// An error envelope of the gateway: the HTTP status and the error code.
    Refused { status: u16, code: String },
    /// No answer, or one that is not of the contract.
    Unreachable { status: u16 },
}

/// What the node does with an outcome (push-gateway-v1 section 10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayAction {
    Sent,
    /// The handle will never work again: `failed_at = now`.
    MarkFailed,
    /// The gateway's clock and the node's differ by more than 300 s: a
    /// `push_failed {reason: "clock"}` row, the handle stays.
    Clock,
    /// The push is dropped; the handle stays.
    Drop,
}

/// The action of an outcome: a final APNs answer or a handle the gateway refuses for
/// good marks the handle failed; a stale clock is reported; anything else (a 400 of
/// another version, a 429, a 5xx, status 0, no answer) drops the push.
pub fn gateway_action(outcome: &GatewayOutcome) -> GatewayAction {
    match outcome {
        GatewayOutcome::Apns { status: 200, .. } => GatewayAction::Sent,
        GatewayOutcome::Apns { status, reason } if is_final(*status, reason) => {
            GatewayAction::MarkFailed
        }
        GatewayOutcome::Refused { status: 403, code }
            if matches!(
                code.as_str(),
                "handle_invalid" | "handle_expired" | "proof_invalid"
            ) =>
        {
            GatewayAction::MarkFailed
        }
        GatewayOutcome::Refused { status: 403, code } if code == "stale_request" => {
            GatewayAction::Clock
        }
        _ => GatewayAction::Drop,
    }
}

/// The answer of the gateway to `POST /v1/push`.
#[derive(Debug, Deserialize)]
struct GatewayAnswer {
    status: u16,
    #[serde(default)]
    reason: Option<String>,
}

/// One `POST <gateway>/v1/push`.
fn call_gateway(
    agent: &ureq::Agent,
    timeout: Duration,
    target: &HandleTarget,
    body: String,
    expires_at: u64,
) -> GatewayOutcome {
    let remaining = expires_at.saturating_sub(crate::now_unix());
    if remaining == 0 {
        return GatewayOutcome::Unreachable { status: 0 };
    }
    let Ok(request) = ureq::http::Request::builder()
        .method("POST")
        .uri(format!("{}/v1/push", target.gateway))
        .header("Content-Type", "application/json")
        .body(body)
    else {
        return GatewayOutcome::Unreachable { status: 0 };
    };
    let request = agent
        .configure_request(request)
        .timeout_global(Some(timeout.min(Duration::from_secs(remaining))))
        .build();
    let Ok(mut response) = agent.run(request) else {
        return GatewayOutcome::Unreachable { status: 0 };
    };
    let status = response.status().as_u16();
    let bytes = response
        .body_mut()
        .with_config()
        .limit(MAX_ANSWER_BYTES)
        .read_to_vec()
        .unwrap_or_default();
    if status == 200 {
        return match serde_json::from_slice::<GatewayAnswer>(&bytes) {
            Ok(answer) => GatewayOutcome::Apns {
                status: answer.status,
                reason: reason_word(answer.reason.as_deref()),
            },
            Err(_) => GatewayOutcome::Unreachable { status },
        };
    }
    let code = serde_json::from_slice::<Value>(&bytes)
        .ok()
        .and_then(|value| value["error"]["code"].as_str().map(str::to_owned))
        .filter(|code| {
            (1..=64).contains(&code.len())
                && code.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
        });
    match code {
        Some(code) => GatewayOutcome::Refused { status, code },
        None => GatewayOutcome::Unreachable { status },
    }
}

/// Sends the pushes of one gateway job, once each, and records what happened. A handle
/// whose gateway is not (or no longer) one of the node's is not called.
fn send_handles(
    gateways: &[String],
    timeout: Duration,
    agent: &ureq::Agent,
    job: &Job,
    last_failed: &mut HashMap<(TeamId, u64), u64>,
) {
    let mut sent = 0usize;
    for target in current_handles(job, crate::now_unix()) {
        if !gateways.contains(&target.gateway) {
            continue;
        }
        let at = crate::now_unix();
        if job.expires_at <= at {
            break;
        }
        let body = push_body(&target, at, job.expires_at, job.summary.as_deref());
        let outcome = call_gateway(agent, timeout, &target, body, job.expires_at);
        let now = crate::now_unix();
        let action = gateway_action(&outcome);
        match action {
            GatewayAction::Sent => {
                sent += 1;
                continue;
            }
            GatewayAction::MarkFailed => {
                let _ = mark_handle_failed(&job.store, &target, now);
            }
            GatewayAction::Clock => {
                if throttle(last_failed, &job.team, CLOCK_THROTTLE, now) {
                    let _ = job.audit.write(
                        &job.store,
                        now,
                        RELAY_ACTOR,
                        "push_failed",
                        None,
                        &json!({"reason": "clock"}),
                    );
                }
                continue;
            }
            GatewayAction::Drop => {}
        }
        if throttle(last_failed, &job.team, target.device.0, now) {
            let detail = match &outcome {
                GatewayOutcome::Apns { status, reason } => {
                    json!({"device_id": target.device, "status": status, "reason": reason})
                }
                GatewayOutcome::Refused { status, code } => {
                    json!({"device_id": target.device, "status": status, "reason": code})
                }
                GatewayOutcome::Unreachable { status } => {
                    json!({"device_id": target.device, "status": status, "reason": "gateway"})
                }
            };
            let _ = job
                .audit
                .write(&job.store, now, RELAY_ACTOR, "push_failed", None, &detail);
        }
    }
    if sent > 0 {
        let _ = job.audit.write(
            &job.store,
            crate::now_unix(),
            RELAY_ACTOR,
            "push_sent",
            None,
            &json!({"count": sent, "via": "gateway"}),
        );
    }
}

/// Marks the handle failed, if the device still has this handle: a `PUT` that came in
/// between keeps its new handle.
fn mark_handle_failed(store: &Store, target: &HandleTarget, now: u64) -> RelayResult<()> {
    let handle = decode_b64(&target.handle, MAX_HANDLE_BYTES)
        .map_err(|_| RelayError::internal("A stored handle is not b64u."))?;
    store.with(|conn| {
        conn.execute(
            "UPDATE push_handle SET failed_at = ?3 WHERE device_id = ?1 AND handle = ?2 AND failed_at IS NULL",
            params![to_i(target.device.0), handle, to_i(now)],
        )
        .map(drop)
        .map_err(db)
    })
}

/// The push tokens of `devices` that did not fail (Worker mode).
fn token_targets(conn: &Connection, devices: &[DeviceId]) -> RelayResult<Vec<PushTarget>> {
    let mut statement = conn
        .prepare(
            "SELECT token, environment FROM push_token WHERE device_id = ?1 AND failed_at IS NULL",
        )
        .map_err(db)?;
    let mut targets = Vec::new();
    for device in devices {
        let row = statement
            .query_row(params![to_i(device.0)], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?))
            })
            .optional()
            .map_err(db)?;
        if let Some((token, environment)) = row {
            targets.push(PushTarget {
                device: *device,
                token: String::from_utf8_lossy(&token).into_owned(),
                environment,
            });
        }
    }
    Ok(targets)
}

/// The push handles of `devices` that did not fail (gateway mode).
fn handle_targets(conn: &Connection, devices: &[DeviceId]) -> RelayResult<Vec<HandleTarget>> {
    let mut statement = conn
        .prepare(
            "SELECT gateway, handle, secret FROM push_handle WHERE device_id = ?1 AND failed_at IS NULL",
        )
        .map_err(db)?;
    let mut targets = Vec::new();
    for device in devices {
        let row = statement
            .query_row(params![to_i(device.0)], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    Zeroizing::new(row.get::<_, Vec<u8>>(2)?),
                ))
            })
            .optional()
            .map_err(db)?;
        if let Some((gateway, handle, secret)) = row {
            targets.push(HandleTarget::new(
                *device,
                gateway,
                encode_b64(&handle),
                secret.to_vec(),
            ));
        }
    }
    Ok(targets)
}

/// The sealed summary of `POST /v1/questions` (push-gateway-v1 section 12), form only:
/// 720 canonical b64u characters that decode to 540 bytes. No header: `None`. The node
/// never stores or logs it.
pub fn checked_summary(header: Option<&str>) -> RelayResult<Option<String>> {
    let Some(text) = header else {
        return Ok(None);
    };
    let decoded = (text.len() == SUMMARY_CHARS)
        .then(|| decode_b64(text, SUMMARY_BYTES).ok())
        .flatten();
    if decoded.is_none_or(|bytes| bytes.len() != SUMMARY_BYTES) {
        return Err(RelayError::invalid(
            "X-Apassy-Push-Summary is 720 base64url characters (540 bytes).",
        ));
    }
    Ok(Some(text.to_string()))
}

/// `PUT /v1/push/handle` (push-gateway-v1 section 10).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PushHandlePut {
    pub v: u64,
    /// The origin of the gateway that made the handle: one of the node's gateways.
    pub gateway: String,
    /// b64u, 16 to 1024 bytes. The node never opens it.
    pub handle: String,
    /// b64u of 32 bytes. Never logged.
    pub secret: SecretString,
}

/// `PUT /v1/push/handle`: one handle per device, replaced on each call, which also
/// clears a failed mark. A `push_handle_set {device_id}` row only when the handle,
/// secret, or gateway changes. 409 `push_unavailable` on a relay that does not push
/// through a gateway (the hosted relay), 409 `push_gateway_refused` for a gateway that
/// is not the node's.
pub fn handle_put(
    core: &Core,
    by: &MemberAuth,
    request: &PushHandlePut,
    now: u64,
) -> RelayResult<Value> {
    let device = crate::server::questions::device_of(by)?;
    if !core.push.is_gateway() {
        return Err(push_unavailable());
    }
    if request.v != 1 {
        return Err(RelayError::invalid(
            "This relay speaks push handles of v 1.",
        ));
    }
    let gateway = crate::config::checked_gateway(&request.gateway)?;
    if gateway != request.gateway {
        return Err(RelayError::invalid(
            "The gateway is an origin without spaces, such as https://push.example.com.",
        ));
    }
    if !core.push.gateways().contains(&gateway) {
        return Err(RelayError::new(
            codes::PUSH_GATEWAY_REFUSED,
            "This node does not push through that gateway.",
        ));
    }
    let handle = decode_b64(&request.handle, MAX_HANDLE_BYTES)
        .ok()
        .filter(|bytes| bytes.len() >= MIN_HANDLE_BYTES)
        .ok_or_else(|| RelayError::invalid("The handle is base64url of 16 to 1024 bytes."))?;
    let secret = Zeroizing::new(
        (request.secret.expose().len() == 43)
            .then(|| decode_b64(request.secret.expose(), SECRET_BYTES).ok())
            .flatten()
            .filter(|bytes| bytes.len() == SECRET_BYTES)
            .ok_or_else(|| RelayError::invalid("The secret is base64url of 32 bytes."))?,
    );
    core.store.tx(|tx| {
        crate::server::auth::require_member(tx, by, crate::server::auth::Need::Member, now)?;
        let same: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM push_handle WHERE device_id = ?1 AND gateway = ?2 \
                 AND handle = ?3 AND secret = ?4)",
                params![to_i(device.0), gateway, handle, secret.as_slice()],
                |row| row.get(0),
            )
            .map_err(db)?;
        tx.execute(
            "INSERT INTO push_handle (device_id, gateway, handle, secret, updated_at, failed_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, NULL) ON CONFLICT(device_id) DO UPDATE SET \
             gateway = excluded.gateway, handle = excluded.handle, secret = excluded.secret, \
             updated_at = excluded.updated_at, failed_at = NULL",
            params![
                to_i(device.0),
                gateway,
                handle,
                secret.as_slice(),
                to_i(now)
            ],
        )
        .map_err(db)?;
        if !same {
            core.audit.write_on(
                tx,
                now,
                &member_actor(by.id.0),
                "push_handle_set",
                None,
                &json!({"device_id": device}),
            )?;
        }
        Ok(json!({"device_id": device, "updated_at": now}))
    })
}

/// `DELETE /v1/push/handle`: removes the handle of the calling device. No handle: the
/// same answer. 409 `push_unavailable` on a relay that does not push through a gateway.
pub fn handle_delete(core: &Core, by: &MemberAuth, now: u64) -> RelayResult<Value> {
    let device = crate::server::questions::device_of(by)?;
    if !core.push.is_gateway() {
        return Err(push_unavailable());
    }
    core.store.tx(|tx| {
        crate::server::auth::require_member(tx, by, crate::server::auth::Need::Member, now)?;
        let removed = tx
            .execute(
                "DELETE FROM push_handle WHERE device_id = ?1",
                params![to_i(device.0)],
            )
            .map_err(db)?;
        if removed > 0 {
            core.audit.write_on(
                tx,
                now,
                &member_actor(by.id.0),
                "push_handle_removed",
                None,
                &json!({"device_id": device}),
            )?;
        }
        Ok(json!({"device_id": device}))
    })
}

/// 409 `push_unavailable`: this relay has no push gateway.
fn push_unavailable() -> RelayError {
    RelayError::new(
        codes::PUSH_UNAVAILABLE,
        "This relay does not push through a push gateway.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_push_deadlines_are_those_of_the_spec() {
        let config = PushConfig::new(
            "https://worker.example/internal/push".into(),
            "com.example.apassy".into(),
            crate::secret::SecretString::new("p".repeat(40)),
        );
        assert_eq!(config.timeout(), Duration::from_secs(10));
        assert_eq!(config.backoff_unit(), Duration::from_secs(1));
        let gateway = PushConfig::gateway(vec!["https://push.example.com".into()]).unwrap();
        assert_eq!(gateway.timeout(), Duration::from_secs(10));
        let unit = config.backoff_unit();
        assert_eq!(retry_delay(unit, 1, 0), Duration::from_secs(1));
        assert_eq!(retry_delay(unit, 2, 2), Duration::from_secs(4));
        assert_eq!(retry_delay(unit, 4, 1), Duration::from_secs(9));
        assert_eq!(retry_delay(unit, 7, 0), Duration::from_secs(60));
        assert_eq!(retry_delay(unit, 40, 2), Duration::from_secs(62));
    }

    #[test]
    fn scheduler_is_fair_bounded_and_retains_retry_seats() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(
            Store::create_at(
                &dir.path().join("queue.db"),
                &crate::secret::SecretString::new("synthetic queue key".to_string()),
                "CREATE TABLE sample(id);",
            )
            .unwrap(),
        );
        let one = TeamId::parse("t_7k2m5q4x3c").unwrap();
        let two = TeamId::parse("t_abcdefgh23").unwrap();
        let job = |team: &TeamId, n: usize, connect| Job {
            team: team.clone(),
            connect,
            store: store.clone(),
            audit: Audit::new(),
            expires_at: crate::now_unix() + 300,
            targets: Targets::Tokens(vec![PushTarget {
                device: DeviceId(1),
                token: "a".repeat(64),
                environment: "production".into(),
            }]),
            summary: None,
            qid: n.to_string(),
            closed: Arc::new(AtomicBool::new(false)),
            attempt: 0,
            due: Instant::now(),
        };
        let mut queue = Schedule::default();
        for n in 0..16 {
            assert!(queue.admit(job(&one, n, false)));
        }
        assert!(!queue.admit(job(&one, 16, false)));
        assert!(queue.admit(job(&two, 1, false)));
        let mut first = queue.take(crate::now_unix()).unwrap();
        assert_eq!(first.team, one);
        let mut second = queue.take(crate::now_unix()).unwrap();
        assert_eq!(second.team, two, "a busy team cannot take another sender");
        assert!(queue.take(crate::now_unix()).is_none());
        first.due = Instant::now() + Duration::from_secs(60);
        queue.finish(first, crate::now_unix());
        assert_eq!(queue.held[&one], 16, "retry keeps its admission seat");
        second.targets = Targets::Tokens(Vec::new());
        queue.finish(second, crate::now_unix());
        assert!(!queue.held.contains_key(&two));
        assert!(queue.admit(job(&two, 2, true)));
        assert!(queue.admit(job(&two, 3, true)));
        assert!(!queue.admit(job(&two, 4, true)));
        assert_eq!(queue.budget.all, 2);
    }

    #[test]
    fn final_answers_and_reason_words() {
        assert!(is_final(410, "Unregistered"));
        assert!(is_final(400, "BadDeviceToken"));
        assert!(is_final(400, "DeviceTokenNotForTopic"));
        assert!(!is_final(400, "BadCollapseId"));
        assert!(!is_final(429, "TooManyRequests"));
        assert!(!is_final(0, "Unreachable"));
        assert_eq!(reason_word(Some("Unregistered")), "Unregistered");
        assert_eq!(reason_word(Some("<script>")), "Unknown");
        assert_eq!(reason_word(Some(&"A".repeat(65))), "Unknown");
        assert_eq!(reason_word(None), "Unknown");
    }

    #[test]
    fn connect_teams_have_a_share_of_the_queue() {
        let one = TeamId::parse("t_7k2m5q4x3c").unwrap();
        let two = TeamId::parse("t_abcdefgh23").unwrap();
        let three = TeamId::parse("t_cdefgh2345").unwrap();
        let mut budget = Budget::default();
        // One team: two jobs at once, then one more after one was sent.
        assert!(budget.admit(&one));
        assert!(budget.admit(&one));
        assert!(!budget.admit(&one));
        budget.release(&one);
        assert!(budget.admit(&one));
        budget.release(&one);
        budget.release(&one);
        assert_eq!((budget.all, budget.teams.len()), (0, 0));
        // All Connect teams together: half the queue.
        let mut budget = Budget {
            teams: HashMap::new(),
            all: CONNECT_JOBS - 1,
        };
        assert!(budget.admit(&one));
        assert!(!budget.admit(&two));
        budget.release(&one);
        assert!(budget.admit(&three));
        // A release of a team with no seat changes nothing.
        let before = budget.all;
        budget.release(&TeamId::parse("t_bcdefgh234").unwrap());
        assert_eq!(budget.all, before);
    }

    #[test]
    fn push_failure_throttles_do_not_retain_unbounded_device_history() {
        let team = TeamId::parse("t_7k2m5q4x3c").unwrap();
        let mut last = HashMap::new();
        for device in 0..MAX_THROTTLES as u64 + 50 {
            throttle(&mut last, &team, device, 100);
        }
        assert_eq!(last.len(), MAX_THROTTLES);
        assert!(throttle(&mut last, &team, 99999, 110));
        assert_eq!(last.len(), 1);
    }

    #[test]
    fn rows_are_throttled_per_device_and_team() {
        let team = TeamId::parse("t_7k2m5q4x3c").unwrap();
        let other = TeamId::parse("t_abcdefgh23").unwrap();
        let mut last = HashMap::new();
        assert!(throttle(&mut last, &team, 3, 100));
        assert!(!throttle(&mut last, &team, 3, 109));
        assert!(throttle(&mut last, &team, 4, 109));
        assert!(throttle(&mut last, &other, 3, 109));
        assert!(throttle(&mut last, &team, 3, 110));
    }

    /// The values of push-gateway-v1 section 18.
    const IPHONE_SECRET: &str = "YGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6e3x9fn8";
    const WATCH_SECRET: &str = "gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp8";
    const IPHONE_HANDLE: &str = "AQEAAQIDBAUGBwgJCgtBJxpaTb1ogql77qaa1-7S86xCZwlugXGaT4PzL5NTfCFBpTDac2pO0SkZriCatsFILmsMt3V6FVKy5oQwVC_Xp0KbnZecVv6zArmDfifrV5jgi8MknGQGiRecJm9NW2etrseKbY4QHHDC16hpS29-n_ooa8Wf7_gDcl-gXUOCOht6OHZn7JjU2hewAbctZWpd_qZzpQMPBS4GKjewB9GMj8v0if9Q6ZZSlj1UQzXfSRw3Lme5AOFU5ggjW-mmefcljd5raXzDrJ-r7U7GcjJI-XAMcaScWgVAShGeklTDrvW8Qpt8C40X2UhL_GmK8G3vg9q7_5xrlTqrBrHrZRBMHwSQ3dMPyRp5zrrzBIgGn6IlRz7SLrGYTy4uHS4";
    const WATCH_HANDLE: &str = "AQEQERITFBUWFxgZGhsCGEvzbKA4AcXPuDTJwi3BZGPnoSQ9aH8XBay_-VOQstGWIJlekXGdAALT_B73l_ZgGeZMEDAmyTp2zqYF69tWqZ_1R6DSxX2gstrWUC6hi0uL_AXLKTvezTUSly0XROF6ardVkVxMFK69c8oKF652vi9NMQVtpThfgcSo1b4B8urodIEdJzfJsnhSiQ2d5NFf0hi-5MRKb1hhk1whHjAU3e-pWX7QCq_bvnIu4-iml6auHpWStEPb5l8i9oVTE7ZxeOKQupMT1YV2MB-wVcUDzDx1kjox7A8NLoDDI84B00IU9fWhfFl2srTzPyfOPP8eKqBUfazI2uE1AUYBE8c3XkCdmXoCQiRLuWBv8G00W7pcFusI2_UX-MOYh1D253_JLDrQmxzREA";
    const SUMMARY: &str = "ICEiIyQlJicoKSorLZYy_9V2mK8YOxL9BrISycdM3QC8LastsrSZ2rydHt5kH7FQOVw3Z9Fcdh4X0rBDP0peQmDtu1ueo2qMc8jG-HaJeH5MYA7UnBcbZRxtOLpdrfxf1XCmrKUi-gmLBZxFvggJiX35uKUAdZwfhwUqeu6y8tnLbItuN-Yk4e_Jkqawp39RHi3ux-0DNm4DCs1Nlnki8MWzWpS7q_Yf1-3uwYdSdBlr-qq7uI6GCJiJ-79H4cte4JJnY8GQ0RvTh9ZbxyqpdIhFpoe0V1w2ZgierYd-NuopbMxBWD0nepd9qDJGCGmbMZG1CwxXrjC_l2986y7k_EjhkwIbDdeBxTVnZ67guVWth1D8h-UMVEvCKR3zc2ANEQ1Qrr-skb_eNEo0hnj6Bvx6MiFWKwMUV_PcRAFVpb7so6XLs1i2bkYSzEv-w_buoaz-EnNnMD70ddE-FuZDqHiWaar_Wo0dSHz5qf5hcXNT6x185swuTpTL8sKUr32di0Qa0ObJE6BCpMOdFlxGtaKrb7bu1svCr0nLWDhMhi2Tp8ibOnvYKei4HFG251WGQ8AxcJl_7m_NTDOq4bDlEOOaOgSF7KiofJolVL4sBk8oFlaTgp2-Jvn4rFU1c04OaWJGQfOaJIvpnRXa883CBzSKZ2sNaovOg00TUiQ8Dc31pqs-ZzE8xHmg7E7YbmDyG3-UPiey7OE407l9";

    fn secret(text: &str) -> Vec<u8> {
        decode_b64(text, SECRET_BYTES).unwrap()
    }

    #[test]
    fn the_proofs_are_those_of_the_contract_vectors() {
        let (at, expires_at) = (1_790_000_100, 1_790_000_400);
        assert_eq!(
            proof(
                &secret(IPHONE_SECRET),
                IPHONE_HANDLE,
                at,
                expires_at,
                COLLAPSE_ID,
                None
            ),
            "-MmhDTmjMiBV6cNqCsq29jnlp9anOujN_dXLn6hbbnY"
        );
        assert_eq!(
            proof(
                &secret(WATCH_SECRET),
                WATCH_HANDLE,
                at,
                expires_at,
                COLLAPSE_ID,
                None
            ),
            "KxRYEBo7r3KCRqcOBVc8OpRsPuz2rRb4LxFQtvzzaBI"
        );
        assert_eq!(
            proof(
                &secret(IPHONE_SECRET),
                IPHONE_HANDLE,
                at,
                expires_at,
                COLLAPSE_ID,
                Some(SUMMARY)
            ),
            "gyriDrKhiUeSYbgOm5weYj7NG6isjzaE3IEJp9qDV3g"
        );
        // A changed time or the other secret gives another proof.
        assert_ne!(
            proof(
                &secret(IPHONE_SECRET),
                IPHONE_HANDLE,
                at + 1,
                expires_at,
                COLLAPSE_ID,
                None
            ),
            "-MmhDTmjMiBV6cNqCsq29jnlp9anOujN_dXLn6hbbnY"
        );
        assert_ne!(
            proof(
                &secret(WATCH_SECRET),
                IPHONE_HANDLE,
                at,
                expires_at,
                COLLAPSE_ID,
                None
            ),
            "-MmhDTmjMiBV6cNqCsq29jnlp9anOujN_dXLn6hbbnY"
        );
    }

    #[test]
    fn a_push_body_has_exactly_the_fields_of_the_contract_and_no_token() {
        let target = HandleTarget::new(
            DeviceId(3),
            "https://push.example.com".into(),
            IPHONE_HANDLE.into(),
            secret(IPHONE_SECRET),
        );
        let body = push_body(&target, 1_790_000_100, 1_790_000_400, None);
        assert_eq!(
            body,
            format!(
                "{{\"v\":1,\"handle\":\"{IPHONE_HANDLE}\",\"at\":1790000100,\"expires_at\":1790000400,\"collapse_id\":\"apassy-question\",\"proof\":\"-MmhDTmjMiBV6cNqCsq29jnlp9anOujN_dXLn6hbbnY\"}}"
            )
        );
        let parsed: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed.as_object().unwrap().len(), 6);
        assert!(!body.contains("token") && !body.contains(IPHONE_SECRET));
        let with = push_body(&target, 1_790_000_100, 1_790_000_400, Some(SUMMARY));
        let parsed: Value = serde_json::from_str(&with).unwrap();
        assert_eq!(parsed["summary"], SUMMARY);
        assert_eq!(
            parsed["proof"],
            "gyriDrKhiUeSYbgOm5weYj7NG6isjzaE3IEJp9qDV3g"
        );
        assert!(with.ends_with(&format!(",\"summary\":\"{SUMMARY}\"}}")));
        // Debug names the device only.
        assert_eq!(format!("{target:?}"), "HandleTarget(device 3)");
    }

    #[test]
    fn gateway_answers_mark_report_or_drop() {
        let apns = |status, reason: &str| GatewayOutcome::Apns {
            status,
            reason: reason.into(),
        };
        let refused = |status, code: &str| GatewayOutcome::Refused {
            status,
            code: code.into(),
        };
        assert_eq!(gateway_action(&apns(200, "Unknown")), GatewayAction::Sent);
        for outcome in [
            apns(410, "Unregistered"),
            apns(400, "BadDeviceToken"),
            apns(400, "DeviceTokenNotForTopic"),
            refused(403, "handle_invalid"),
            refused(403, "handle_expired"),
            refused(403, "proof_invalid"),
        ] {
            assert_eq!(
                gateway_action(&outcome),
                GatewayAction::MarkFailed,
                "{outcome:?}"
            );
        }
        assert_eq!(
            gateway_action(&refused(403, "stale_request")),
            GatewayAction::Clock
        );
        for outcome in [
            apns(0, "Unreachable"),
            apns(429, "TooManyRequests"),
            apns(400, "BadCollapseId"),
            refused(400, "invalid_request"),
            refused(429, "rate_limited"),
            refused(409, "kind_unavailable"),
            refused(503, "push_unavailable"),
            GatewayOutcome::Unreachable { status: 0 },
            GatewayOutcome::Unreachable { status: 502 },
        ] {
            assert_eq!(gateway_action(&outcome), GatewayAction::Drop, "{outcome:?}");
        }
    }

    #[test]
    fn a_summary_is_720_canonical_characters() {
        assert_eq!(checked_summary(None).unwrap(), None);
        assert_eq!(
            checked_summary(Some(SUMMARY)).unwrap().as_deref(),
            Some(SUMMARY)
        );
        let bad_values = [
            SUMMARY[..719].to_string(),
            format!("{SUMMARY}A"),
            SUMMARY.replace('-', "+"),
            format!("{}=", &SUMMARY[..719]),
            String::new(),
        ];
        for bad in &bad_values {
            assert_eq!(
                checked_summary(Some(bad)).unwrap_err().code,
                codes::INVALID_REQUEST,
                "{} characters",
                bad.len()
            );
        }
    }

    #[test]
    fn the_modes_choose_their_targets() {
        let off = Push::off();
        assert!(!off.enabled() && !off.is_gateway());
        assert_eq!(off.topic(), None);
        assert!(off.gateways().is_empty());
        assert_eq!(off.status()["mode"], "off");
        let stop = Arc::new(AtomicBool::new(true));
        let gateway = Push::start(
            Some(PushConfig::gateway(vec!["https://push.example.com".into()]).unwrap()),
            stop.clone(),
        )
        .unwrap();
        assert!(gateway.enabled() && gateway.is_gateway());
        assert_eq!(gateway.topic(), None);
        assert_eq!(gateway.gateways(), ["https://push.example.com".to_string()]);
        assert_eq!(gateway.status()["mode"], "gateway");
        let worker = Push::start(
            Some(PushConfig::new(
                "https://worker.example/internal/push".into(),
                "com.example.apassy".into(),
                SecretString::new("p".repeat(40)),
            )),
            stop,
        )
        .unwrap();
        assert_eq!(worker.topic(), Some("com.example.apassy"));
        assert!(!worker.is_gateway() && worker.gateways().is_empty());
        assert_eq!(worker.status()["mode"], "worker");
    }
}
