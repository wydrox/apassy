//! The push trigger (docs/SPEC.md section 25.6).
//!
//! After a question is posted, its handler hands the push tokens of the routing set to
//! four push senders through a bounded fair queue, and never waits for it. The thread asks the
//! Worker's push route (`APASSY_RELAY_PUSH_URL`, header `X-Apassy-Push` with the push
//! secret) to send the fixed notification, one call per environment and batch, and
//! marks the tokens that APNs refuses for good. The relay sends Apple nothing itself
//! and never logs a token, the secret, or anything of a question.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use rusqlite::params;
use serde::Deserialize;
use serde_json::json;

use crate::config::PushConfig;
use crate::error::{RelayError, RelayResult};
use crate::ids::{DeviceId, TeamId};
use crate::server::Core;
use crate::server::audit::{Audit, RELAY_ACTOR};
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
/// One call to the Worker, from the connection to the last byte of the answer.
const TIMEOUT: Duration = Duration::from_secs(10);
/// The largest answer of the Worker that is read.
const MAX_ANSWER_BYTES: u64 = 256 * 1024;
/// Seconds between two `push_failed` rows of one device, and two `push_dropped` rows
/// of one team.
const ROW_INTERVAL_SECS: u64 = 10;
const MAX_THROTTLES: usize = 4096;

/// One push token of the routing set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushTarget {
    pub device: DeviceId,
    /// Lowercase hex, as the device sent it.
    pub token: String,
    /// `development` or `production`.
    pub environment: String,
}

/// The pushes of one question.
struct Job {
    team: TeamId,
    /// The job of a Connect team: it holds a seat of the `Budget` until it is sent.
    connect: bool,
    store: Arc<Store>,
    audit: Arc<Audit>,
    expires_at: u64,
    targets: Vec<PushTarget>,
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

/// The push trigger of the relay, shared by every team.
pub struct Push {
    topic: Option<String>,
    queue: Arc<SharedSchedule>,
    last_dropped: Mutex<HashMap<TeamId, u64>>,
}

impl Push {
    pub fn off() -> Arc<Self> {
        Arc::new(Self {
            topic: None,
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
        Ok(Arc::new(Self {
            topic: Some(config.topic),
            queue,
            last_dropped: Mutex::new(HashMap::new()),
        }))
    }

    pub fn topic(&self) -> Option<&str> {
        self.topic.as_deref()
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
        json!({"enabled": self.topic.is_some(), "held": queue.ids.len(),
            "in_flight_teams": queue.busy.len(), "capacity": QUEUE})
    }

    /// Never waits for network or queue space. Duplicate pending question ids coalesce.
    pub fn trigger(
        &self,
        core: &Core,
        qid: &str,
        targets: Vec<PushTarget>,
        expires_at: u64,
        now: u64,
    ) {
        if self.topic.is_none() || targets.is_empty() || expires_at <= now {
            return;
        }
        let job = Job {
            team: core.team.clone(),
            connect: core.kind == crate::api::TeamKind::Connect,
            store: core.store.clone(),
            audit: core.audit.clone(),
            expires_at,
            targets,
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
        .timeout_global(Some(TIMEOUT))
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
        job.targets = send_job(config, &agent, &job, &mut last_failed);
        job.attempt = job.attempt.saturating_add(1);
        let now = crate::now_unix();
        // Exponential backoff (1..60 seconds) plus 0..2 seconds of per-team jitter.
        let jitter = job.team.as_str().bytes().map(u64::from).sum::<u64>() % 3;
        job.due = Instant::now()
            + Duration::from_secs((1u64 << job.attempt.saturating_sub(1).min(6)).min(60) + jitter);
        queue
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .finish(job, now);
        queue.1.notify_all();
    }
}

fn transient(status: u16) -> bool {
    status == 0 || status == 429 || status >= 500
}

/// Read the live question, route and token before *every* attempt. Settled, expired,
/// suspended, revoked, demoted and replaced tokens no longer receive retries.
fn current_targets(job: &Job, now: u64) -> Vec<PushTarget> {
    if now >= job.expires_at || job.closed.load(Ordering::Relaxed) {
        return Vec::new();
    }
    job.store.with(|conn| {
        let mut targets = Vec::new();
        for target in &job.targets {
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
    config: &PushConfig,
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
        .uri(&config.url)
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
        .timeout_global(Some(TIMEOUT.min(Duration::from_secs(remaining))))
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
    config: &PushConfig,
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

#[cfg(test)]
mod tests {
    use super::*;

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
            targets: vec![PushTarget {
                device: DeviceId(1),
                token: "a".repeat(64),
                environment: "production".into(),
            }],
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
        second.targets.clear();
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
}
