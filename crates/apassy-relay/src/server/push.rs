//! The push trigger (docs/SPEC.md section 25.6).
//!
//! After a question is posted, its handler hands the push tokens of the routing set to
//! one push thread through a bounded queue, and never waits for it. The thread asks the
//! Worker's push route (`APASSY_RELAY_PUSH_URL`, header `X-Apassy-Push` with the push
//! secret) to send the fixed notification, one call per environment and batch, and
//! marks the tokens that APNs refuses for good. The relay sends Apple nothing itself
//! and never logs a token, the secret, or anything of a question.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

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
/// Jobs that wait for the push thread. A full queue drops the new job.
const QUEUE: usize = 256;
/// One call to the Worker, from the connection to the last byte of the answer.
const TIMEOUT: Duration = Duration::from_secs(10);
/// The largest answer of the Worker that is read.
const MAX_ANSWER_BYTES: u64 = 256 * 1024;
/// Seconds between two `push_failed` rows of one device, and two `push_dropped` rows
/// of one team.
const ROW_INTERVAL_SECS: u64 = 10;

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
    store: Arc<Store>,
    audit: Arc<Audit>,
    expires_at: u64,
    targets: Vec<PushTarget>,
}

/// The push trigger of the relay, shared by every team.
pub struct Push {
    topic: Option<String>,
    queue: Option<SyncSender<Job>>,
    last_dropped: Mutex<HashMap<TeamId, u64>>,
}

impl Push {
    /// Push off: no thread, no trigger, `PUT /v1/push/token` is 409.
    pub fn off() -> Arc<Self> {
        Arc::new(Self {
            topic: None,
            queue: None,
            last_dropped: Mutex::new(HashMap::new()),
        })
    }

    /// Starts the push thread when `config` is set. The thread ends when `stop` is set.
    pub fn start(config: Option<PushConfig>, stop: Arc<AtomicBool>) -> RelayResult<Arc<Self>> {
        let Some(config) = config else {
            return Ok(Self::off());
        };
        let (sender, receiver) = sync_channel(QUEUE);
        let topic = config.topic.clone();
        std::thread::Builder::new()
            .name("relay-push".to_string())
            .spawn(move || run(&config, &receiver, &stop))
            .map_err(|_| RelayError::internal("The push thread cannot start."))?;
        Ok(Arc::new(Self {
            topic: Some(topic),
            queue: Some(sender),
            last_dropped: Mutex::new(HashMap::new()),
        }))
    }

    /// The bundle id that a push token must name, or `None` when push is off.
    pub fn topic(&self) -> Option<&str> {
        self.topic.as_deref()
    }

    /// Hands the pushes of one question to the push thread. Never blocks. A full queue
    /// drops them, with a `push_dropped` row at most once per ten seconds per team.
    pub fn trigger(&self, core: &Core, targets: Vec<PushTarget>, expires_at: u64, now: u64) {
        let Some(queue) = &self.queue else {
            return;
        };
        if targets.is_empty() {
            return;
        }
        let job = Job {
            team: core.team.clone(),
            store: core.store.clone(),
            audit: core.audit.clone(),
            expires_at,
            targets,
        };
        match queue.try_send(job) {
            Ok(()) => {}
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                let mut last = self
                    .last_dropped
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                if last
                    .get(&core.team)
                    .is_none_or(|at| now >= at.saturating_add(ROW_INTERVAL_SECS))
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

/// The push thread: one job at a time, until `stop` is set or every sender is gone.
fn run(config: &PushConfig, jobs: &Receiver<Job>, stop: &AtomicBool) {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .timeout_global(Some(TIMEOUT))
        .build()
        .into();
    let mut last_failed: HashMap<(TeamId, u64), u64> = HashMap::new();
    loop {
        match jobs.recv_timeout(Duration::from_millis(500)) {
            Ok(job) => send_job(config, &agent, &job, &mut last_failed),
            Err(RecvTimeoutError::Timeout) => {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
            }
            Err(RecvTimeoutError::Disconnected) => return,
        }
    }
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
) {
    let mut by_environment: BTreeMap<&str, Vec<&PushTarget>> = BTreeMap::new();
    for target in &job.targets {
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
                continue;
            };
            for target in batch {
                // A token the Worker did not list counts as not sent.
                let Some(result) = answer.results.iter().find(|r| r.token == target.token) else {
                    continue;
                };
                if result.status == 200 {
                    sent += 1;
                    continue;
                }
                let reason = reason_word(result.reason.as_deref());
                if is_final(result.status, &reason) {
                    let _ = mark_failed(&job.store, target, now);
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
}

/// True at most once per ten seconds for one device of one team (device 0: the team).
fn throttle(last: &mut HashMap<(TeamId, u64), u64>, team: &TeamId, device: u64, now: u64) -> bool {
    let key = (team.clone(), device);
    if last
        .get(&key)
        .is_some_and(|at| now < at.saturating_add(ROW_INTERVAL_SECS))
    {
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
