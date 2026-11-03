//! The figures of the Bouncer section (docs/design/implementation-plan-bouncer-section.md,
//! sections 2 and 3): the Overview of this Mac ([`Vault::bouncer_stats`]), and the rows
//! of the Logs page and the Decisions history ([`Vault::bouncer_log`]).
//!
//! Both read the decision log of this Mac (`decision_log`, schema 7 and 27) joined to the
//! uses of each decision (`item_use`, schema 18) and, for the log, to the cloud runs
//! (`cloud_run`, schema 27). They read no secret value: the decision log has none, and
//! neither function reads a command, a user request, or a purpose.
//!
//! The definitions (section 3), over the decision rows with `request = 'run'` in the
//! window:
//!
//! | Figure | Definition |
//! | --- | --- |
//! | runs | the rows |
//! | allowed by bouncer | `asked = 0 AND decision = 'allow'` (the model, a pattern, a remembered answer) |
//! | asked you | `asked = 1` |
//! | denied | `decision = 'deny'`: by you, by a rule, or no answer |
//! | median answer | the median of `wait_ms` over `asked = 1 AND decided_by = 'owner'` |
//! | ask rate of an agent | asked / runs; "asks often" at 25 % or more with 10 runs or more |
//! | last active | the newest `item_use.at` of the agent |
//!
//! A run is in the project `p` when one of its uses has the project label `p`; a run
//! without a use (a request check refused it before it read a credential) is in no
//! project.

use std::collections::BTreeMap;

use serde_json::Value;

use super::agents::{from_sql_time, to_sql_time};
use super::types::{VaultErrorKind, VaultResult, err};
use super::{Vault, to_public_id, to_sql_id};

/// The bars of the Overview: one per local calendar day, today first.
pub const STATS_DAYS: usize = 7;
/// The window of the Overview: the last 7 × 24 h.
pub const STATS_WINDOW_SECS: u64 = 7 * 86_400;
/// An agent "asks often" from this share of its runs ...
pub const ASKS_OFTEN_RATE: f64 = 0.25;
/// ... with at least this many runs.
pub const ASKS_OFTEN_MIN_RUNS: u64 = 10;
/// The rows of one page of [`Vault::bouncer_log`].
pub const BOUNCER_LOG_PAGE: usize = 200;

const DAY: i64 = 86_400;

/// One bar of the Overview chart: the runs of one local day and those that asked you.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DayCount {
    pub runs: u64,
    pub asked: u64,
}

/// One day of one agent: its runs, those that asked you, and those that were denied.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AgentDay {
    pub runs: u64,
    pub asked: u64,
    pub not_allowed: u64,
}

/// The figures of one agent in the window.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgentStats {
    pub agent_id: u64,
    /// The name in its newest decision of the window.
    pub name: String,
    pub runs: u64,
    pub asked: u64,
    pub allowed_by_bouncer: u64,
    /// Denied: by you, by a rule, or no answer.
    pub not_allowed: u64,
    /// The newest use of the agent (`item_use.at`, in the project when one is chosen),
    /// at any time; its newest decision of the window when it has no use.
    pub last_at: Option<u64>,
    /// [`STATS_DAYS`] days, today first.
    pub days: Vec<AgentDay>,
}

impl AgentStats {
    /// asked / runs; 0 without runs.
    pub fn ask_rate(&self) -> f64 {
        if self.runs == 0 {
            0.0
        } else {
            self.asked as f64 / self.runs as f64
        }
    }

    /// The Overview marks the agent orange and lists it under Attention.
    pub fn asks_often(&self) -> bool {
        self.runs >= ASKS_OFTEN_MIN_RUNS && self.ask_rate() >= ASKS_OFTEN_RATE
    }
}

/// The Overview figures of this Mac for one window and one project (or all projects).
/// The app caches one (`BouncerCache`); the feed publisher sends its days and its median.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LocalStats {
    /// The window, a half-open interval of Unix times.
    pub since: u64,
    pub until: u64,
    pub runs: u64,
    pub allowed_by_bouncer: u64,
    pub asked: u64,
    pub denied: u64,
    /// The median answer, rounded to whole seconds. `None`: no owner answer with a time.
    pub answer_p50_secs: Option<u64>,
    /// The same median in milliseconds.
    pub answer_p50_ms: Option<u64>,
    /// The owner answers with a time: the sample of the median.
    pub owner_answers: u64,
    /// [`STATS_DAYS`] local days, today (the day of `until - 1`) first. A run of the
    /// window on an earlier local day (the window is 7 × 24 h, so its first hours can
    /// fall on an eighth day) counts in the totals and in no bar.
    pub days: Vec<DayCount>,
    /// The agents with a run in the window, the most runs first, then by name and id.
    pub agents: Vec<AgentStats>,
}

/// The name the plan gives to the cached aggregate.
pub type BouncerStats = LocalStats;

impl LocalStats {
    /// Allowed by the bouncer, as a share of the runs; 0 without runs.
    pub fn allowed_rate(&self) -> f64 {
        share(self.allowed_by_bouncer, self.runs)
    }

    /// Asked you, as a share of the runs; 0 without runs.
    pub fn asked_rate(&self) -> f64 {
        share(self.asked, self.runs)
    }
}

fn share(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        0.0
    } else {
        part as f64 / whole as f64
    }
}

/// One row of the Logs page and the Decisions history: one decision of this Mac.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogRow {
    pub decision_log_id: u64,
    pub at: u64,
    pub agent_id: u64,
    pub agent_name: String,
    /// The first credential of the request; `None` when it named none.
    pub item_id: Option<u64>,
    /// Its title now; empty when it is gone.
    pub item_name: String,
    /// Every credential of the request.
    pub items: Vec<u64>,
    /// The project label of its uses; empty: no project.
    pub project: String,
    /// `run`, `browser_fill`, or `connector`.
    pub request: String,
    pub asked: bool,
    pub allowed: bool,
    /// `rule`, `model`, `pattern`, `owner` (asked you), `answer` (a remembered answer of
    /// yours, without a question), or `no_answer`.
    pub decided_by: String,
    /// "iPhone", "Apple Watch", "this Mac", the name of another Mac, or empty (no
    /// answer of yours).
    pub answered_on: String,
    /// Milliseconds from the question to your answer.
    pub wait_ms: Option<u64>,
    /// The run id of the node for a cloud run (`cloud_run.relay_run_id`).
    pub relay_run: Option<u64>,
    /// A credential of the request was declared for production.
    pub production: bool,
}

/// The offset of the local time from UTC at `at`, in seconds, as macOS says it; 0 when
/// it does not say, and in a build without the desktop app.
pub fn local_offset(at: u64) -> i64 {
    #[cfg(feature = "desktop")]
    {
        i64::try_from(at)
            .ok()
            .and_then(|at| time::OffsetDateTime::from_unix_timestamp(at).ok())
            .and_then(|at| time::UtcOffset::local_offset_at(at).ok())
            .map_or(0, |offset| i64::from(offset.whole_seconds()))
    }
    #[cfg(not(feature = "desktop"))]
    {
        let _ = at;
        0
    }
}

/// The number of the local day of `at`.
fn local_day(at: u64, offset: &impl Fn(u64) -> i64) -> i64 {
    i64::try_from(at)
        .unwrap_or(i64::MAX)
        .saturating_add(offset(at))
        .div_euclid(DAY)
}

/// The bar of `at`: 0 for the day of `until - 1`, up to [`STATS_DAYS`] − 1.
fn bar_of(at: u64, today: i64, offset: &impl Fn(u64) -> i64) -> Option<usize> {
    let back = today - local_day(at, offset);
    usize::try_from(back).ok().filter(|back| *back < STATS_DAYS)
}

/// The median of `values`, sorted in place: the middle value, or the mean of the two
/// middle values rounded down. `None` for no value.
fn median(values: &mut [u64]) -> Option<u64> {
    values.sort_unstable();
    let n = values.len();
    match n {
        0 => None,
        _ if n % 2 == 1 => Some(values[n / 2]),
        _ => {
            let (a, b) = (values[n / 2 - 1], values[n / 2]);
            Some(a / 2 + b / 2 + (a % 2 + b % 2) / 2)
        }
    }
}

fn storage<E>(_: E) -> super::types::VaultError {
    err(VaultErrorKind::Storage)
}

/// One decision of the window with its uses, as the pass reads it.
struct Run {
    at: u64,
    agent_id: u64,
    agent_name: String,
    asked: bool,
    allowed: bool,
    owner: bool,
    wait_ms: Option<u64>,
    projects: Vec<String>,
}

impl Vault {
    /// The Overview figures of this Mac for the window `[since, until)`, with the local
    /// days of macOS ([`local_offset`]). `project`: the runs of that project label only.
    pub fn bouncer_stats(
        &self,
        since: u64,
        until: u64,
        project: Option<&str>,
    ) -> VaultResult<LocalStats> {
        self.bouncer_stats_with_offset(since, until, project, local_offset)
    }

    /// [`Vault::bouncer_stats`] with the local days of `offset` (seconds east of UTC at a
    /// Unix time), for tests and for another time zone.
    pub fn bouncer_stats_with_offset(
        &self,
        since: u64,
        until: u64,
        project: Option<&str>,
        offset: impl Fn(u64) -> i64,
    ) -> VaultResult<LocalStats> {
        let mut stats = LocalStats {
            since,
            until,
            days: vec![DayCount::default(); STATS_DAYS],
            ..LocalStats::default()
        };
        if until <= since {
            return Ok(stats);
        }
        let runs = self.window_runs(since, until)?;
        let today = local_day(until - 1, &offset);
        let mut waits = Vec::new();
        let mut agents: BTreeMap<u64, AgentStats> = BTreeMap::new();
        for run in runs.values() {
            if project.is_some_and(|project| !run.projects.iter().any(|p| p == project)) {
                continue;
            }
            let denied = !run.allowed;
            stats.runs += 1;
            stats.asked += u64::from(run.asked);
            stats.allowed_by_bouncer += u64::from(!run.asked && run.allowed);
            stats.denied += u64::from(denied);
            if run.asked && run.owner {
                waits.extend(run.wait_ms);
            }
            let bar = bar_of(run.at, today, &offset);
            if let Some(bar) = bar {
                stats.days[bar].runs += 1;
                stats.days[bar].asked += u64::from(run.asked);
            }
            let agent = agents.entry(run.agent_id).or_insert_with(|| AgentStats {
                agent_id: run.agent_id,
                days: vec![AgentDay::default(); STATS_DAYS],
                ..AgentStats::default()
            });
            // The runs come oldest first: the last name is the newest.
            agent.name.clone_from(&run.agent_name);
            agent.runs += 1;
            agent.asked += u64::from(run.asked);
            agent.allowed_by_bouncer += u64::from(!run.asked && run.allowed);
            agent.not_allowed += u64::from(denied);
            agent.last_at = agent.last_at.max(Some(run.at));
            if let Some(bar) = bar {
                let day = &mut agent.days[bar];
                day.runs += 1;
                day.asked += u64::from(run.asked);
                day.not_allowed += u64::from(denied);
            }
        }
        stats.owner_answers = waits.len() as u64;
        stats.answer_p50_ms = median(&mut waits);
        stats.answer_p50_secs = stats.answer_p50_ms.map(|ms| ms.saturating_add(500) / 1000);
        let last_uses = self.last_uses(project)?;
        let mut agents: Vec<AgentStats> = agents
            .into_values()
            .map(|mut agent| {
                if let Some(at) = last_uses.get(&agent.agent_id) {
                    agent.last_at = Some(*at);
                }
                agent
            })
            .collect();
        agents.sort_by(|a, b| {
            b.runs
                .cmp(&a.runs)
                .then_with(|| a.name.cmp(&b.name))
                .then(a.agent_id.cmp(&b.agent_id))
        });
        stats.agents = agents;
        Ok(stats)
    }

    /// The runs of `[since, until)` with the project labels of their uses, by decision id
    /// (oldest first): one pass over `decision_log` joined to `item_use`.
    fn window_runs(&self, since: u64, until: u64) -> VaultResult<BTreeMap<u64, Run>> {
        let conn = self.conn_ref()?;
        let mut stmt = conn
            .prepare(
                "SELECT d.id, d.at, d.agent_id, d.agent_name, d.asked, d.decision = 'allow',
                        d.decided_by = 'owner', d.wait_ms, u.project_label
                 FROM decision_log d LEFT JOIN item_use u ON u.decision_log_id = d.id
                 WHERE d.request = 'run' AND d.at >= ?1 AND d.at < ?2
                 ORDER BY d.id, u.id",
            )
            .map_err(storage)?;
        type Row = (
            i64,
            i64,
            i64,
            String,
            bool,
            bool,
            bool,
            Option<i64>,
            Option<String>,
        );
        let rows = stmt
            .query_map([to_sql_time(since)?, to_sql_time(until)?], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                ))
            })
            .map_err(storage)?;
        let mut runs: BTreeMap<u64, Run> = BTreeMap::new();
        for row in rows {
            let (id, at, agent, name, asked, allowed, owner, wait, project): Row =
                row.map_err(storage)?;
            let id = to_public_id(id)?;
            let run = match runs.entry(id) {
                std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
                std::collections::btree_map::Entry::Vacant(entry) => entry.insert(Run {
                    at: from_sql_time(at)?,
                    agent_id: u64::try_from(agent).map_err(storage)?,
                    agent_name: name,
                    asked,
                    allowed,
                    owner,
                    wait_ms: wait.map(u64::try_from).transpose().map_err(storage)?,
                    projects: Vec::new(),
                }),
            };
            if let Some(project) = project.filter(|p| !p.is_empty())
                && !run.projects.contains(&project)
            {
                run.projects.push(project);
            }
        }
        Ok(runs)
    }

    /// The newest use of each agent, at any time (in `project` when one is chosen).
    fn last_uses(&self, project: Option<&str>) -> VaultResult<BTreeMap<u64, u64>> {
        let conn = self.conn_ref()?;
        let mut stmt = conn
            .prepare(
                "SELECT agent_id, MAX(at) FROM item_use
                 WHERE agent_id IS NOT NULL AND (?1 IS NULL OR project_label = ?1)
                 GROUP BY agent_id",
            )
            .map_err(storage)?;
        let rows = stmt
            .query_map([project], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(storage)?;
        let mut out = BTreeMap::new();
        for row in rows {
            let (agent, at) = row.map_err(storage)?;
            if let Ok(agent) = u64::try_from(agent) {
                out.insert(agent, from_sql_time(at)?);
            }
        }
        Ok(out)
    }

    /// One page of the decisions of this Mac, newest first: at most `limit` (and at most
    /// [`BOUNCER_LOG_PAGE`]) rows with a `decision_log_id` below `before` (none: the
    /// newest). "Load More" passes the `decision_log_id` of the last row it shows.
    /// `project`: the decisions with a use in that project label only. Every request
    /// kind is a row; [`LogRow::request`] tells them apart.
    pub fn bouncer_log(
        &self,
        before: Option<u64>,
        limit: usize,
        project: Option<&str>,
    ) -> VaultResult<Vec<LogRow>> {
        let limit = i64::try_from(limit.min(BOUNCER_LOG_PAGE)).map_err(storage)?;
        if limit == 0 {
            return Ok(Vec::new());
        }
        let before = before.map(to_sql_id).transpose()?;
        let conn = self.conn_ref()?;
        let mut stmt = conn
            .prepare(
                "WITH page AS (
                     SELECT d.id FROM decision_log d
                     WHERE (?1 IS NULL OR d.id < ?1)
                       AND (?3 IS NULL OR EXISTS (SELECT 1 FROM item_use p
                            WHERE p.decision_log_id = d.id AND p.project_label = ?3))
                     ORDER BY d.id DESC LIMIT ?2)
                 SELECT d.id, d.at, d.agent_id, d.agent_name, d.items, d.request, d.asked,
                        d.decision = 'allow', d.decided_by, d.wait_ms, d.declarations,
                        (SELECT r.relay_run_id FROM cloud_run r WHERE r.decision_log_id = d.id
                         ORDER BY r.at DESC LIMIT 1),
                        u.project_label, u.answered_on
                 FROM page JOIN decision_log d ON d.id = page.id
                 LEFT JOIN item_use u ON u.decision_log_id = d.id
                 ORDER BY d.id DESC, u.id ASC",
            )
            .map_err(storage)?;
        type Row = (
            i64,
            i64,
            i64,
            String,
            String,
            String,
            bool,
            bool,
            String,
            Option<i64>,
            String,
            Option<i64>,
            Option<String>,
            Option<String>,
        );
        let rows = stmt
            .query_map(rusqlite::params![before, limit, project], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                    row.get(12)?,
                    row.get(13)?,
                ))
            })
            .map_err(storage)?;
        let mut out: Vec<LogRow> = Vec::new();
        for row in rows {
            let (
                id,
                at,
                agent,
                agent_name,
                items,
                request,
                asked,
                allowed,
                decided_by,
                wait,
                declarations,
                relay_run,
                project_label,
                answered_on,
            ): Row = row.map_err(storage)?;
            let id = to_public_id(id)?;
            if let Some(last) = out.last_mut().filter(|last| last.decision_log_id == id) {
                if last.project.is_empty() {
                    last.project = project_label.unwrap_or_default();
                }
                if last.answered_on.is_empty() {
                    last.answered_on = answered_on.unwrap_or_default();
                }
                continue;
            }
            let items: Vec<u64> = serde_json::from_str(&items).map_err(storage)?;
            out.push(LogRow {
                decision_log_id: id,
                at: from_sql_time(at)?,
                agent_id: u64::try_from(agent).map_err(storage)?,
                agent_name,
                item_id: items.first().copied(),
                item_name: String::new(),
                items,
                project: project_label.unwrap_or_default(),
                request,
                asked,
                allowed,
                // A remembered answer is stored as `owner` without a question (schema 7).
                decided_by: if decided_by == "owner" && !asked {
                    "answer".to_owned()
                } else {
                    decided_by
                },
                answered_on: answered_on.unwrap_or_default(),
                wait_ms: wait.map(u64::try_from).transpose().map_err(storage)?,
                relay_run: relay_run.map(to_public_id).transpose()?,
                production: declares_production(&declarations),
            });
        }
        drop(stmt);
        let mut titles: BTreeMap<u64, String> = BTreeMap::new();
        let mut title = conn
            .prepare("SELECT title FROM item WHERE id = ?1")
            .map_err(storage)?;
        for row in &mut out {
            let Some(item) = row.item_id else {
                continue;
            };
            if !titles.contains_key(&item) {
                let found: Option<String> = match to_sql_id(item) {
                    Ok(sql) => rusqlite::OptionalExtension::optional(
                        title.query_row([sql], |row| row.get(0)),
                    )
                    .map_err(storage)?,
                    Err(_) => None,
                };
                titles.insert(item, found.unwrap_or_default());
            }
            row.item_name.clone_from(&titles[&item]);
        }
        Ok(out)
    }
}

/// A declaration of the decision says production (the `declarations` JSON of
/// `learning::declaration_json`). Unreadable text says nothing.
fn declares_production(declarations: &str) -> bool {
    serde_json::from_str::<Value>(declarations).is_ok_and(|value| {
        value.as_array().is_some_and(|all| {
            all.iter()
                .any(|d| d.get("environment").and_then(Value::as_str) == Some("production"))
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::action_kind::ActionKind;
    use crate::contracts::CredentialKind;
    use crate::vault::usage::{NewItemUse, UseDecidedBy, UseOutcome};
    use crate::vault::{
        DecidedBy, DecisionEntry, DecisionMeta, Field, ItemDraft, LoggedDecision, NewCloudRun,
        RequestKind, RequestSource, SecretValue,
    };

    const PASS: &str = "synthetic-stats-pass";
    /// 2026-11-03T12:00:00Z, a Tuesday.
    const NOON: u64 = 1_793_707_200;
    const HOUR: u64 = 3_600;
    const D: u64 = 86_400;

    fn api_key(title: &str) -> ItemDraft {
        ItemDraft {
            title: title.to_owned(),
            kind: CredentialKind::ApiKey,
            notes: String::new(),
            tags: Vec::new(),
            fields: vec![Field {
                name: "token".to_owned(),
                value: SecretValue::new(format!("SYNTH-{title}-value-0123456789")),
                secret: true,
            }],
        }
    }

    fn entry(agent_id: u64, name: &str, at: u64, item: u64, how: How) -> DecisionEntry {
        let (asked, decision, decided_by) = match how {
            How::Model => (false, LoggedDecision::Allow, DecidedBy::Model),
            How::Answer => (false, LoggedDecision::Allow, DecidedBy::Answer),
            How::OwnerAllow(_) => (true, LoggedDecision::Allow, DecidedBy::Owner),
            How::OwnerDeny(_) => (true, LoggedDecision::Deny, DecidedBy::Owner),
            How::NoAnswer => (true, LoggedDecision::Deny, DecidedBy::NoAnswer),
            How::Rule => (false, LoggedDecision::Deny, DecidedBy::Rule),
        };
        DecisionEntry {
            at,
            agent_id,
            agent_name: name.to_owned(),
            project_dir: String::new(),
            cwd_rel: String::new(),
            items: vec![item],
            user_request: String::new(),
            user_request_source: RequestSource::None,
            command: vec!["true".to_owned()],
            purpose: "synthetic".to_owned(),
            env_names: Vec::new(),
            declarations: Vec::new(),
            rule_flags: Vec::new(),
            known_safe: false,
            model_facts: Vec::new(),
            pattern: String::new(),
            grant_asks: false,
            asked,
            decision,
            decided_by,
            remembered: false,
            policy: String::new(),
            note: String::new(),
            instruction: String::new(),
        }
    }

    #[derive(Clone, Copy)]
    enum How {
        Model,
        Answer,
        OwnerAllow(u64),
        OwnerDeny(u64),
        NoAnswer,
        Rule,
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        vault: Vault,
        a: u64,
        b: u64,
        item: u64,
    }

    /// Store one decision at `at` with one use in `project` at `at + 1`.
    fn add(
        fx: &mut Fixture,
        agent: u64,
        name: &str,
        at: u64,
        how: How,
        project: &str,
        request: RequestKind,
    ) -> u64 {
        let wait_ms = match how {
            How::OwnerAllow(ms) | How::OwnerDeny(ms) => Some(ms),
            // A time that the vault must drop: no owner answer.
            _ => Some(99_999),
        };
        let id = fx
            .vault
            .record_decision_with(
                &entry(agent, name, at, fx.item, how),
                &DecisionMeta { request, wait_ms },
            )
            .unwrap();
        let (outcome, by) = match how {
            How::Model => (UseOutcome::Allowed, UseDecidedBy::Bouncer),
            How::Answer => (UseOutcome::Allowed, UseDecidedBy::Answer),
            How::OwnerAllow(_) => (UseOutcome::Allowed, UseDecidedBy::Owner),
            How::OwnerDeny(_) => (UseOutcome::Denied, UseDecidedBy::Owner),
            How::NoAnswer => (UseOutcome::TimedOut, UseDecidedBy::Owner),
            How::Rule => (UseOutcome::Refused, UseDecidedBy::Rule),
        };
        let use_id = fx
            .vault
            .record_item_use(&NewItemUse {
                item_id: fx.item,
                agent_id: Some(agent),
                agent_name: name.to_owned(),
                project_key: format!("/synthetic/{project}"),
                project_label: project.to_owned(),
                action: ActionKind::Read,
                command_summary: "true".to_owned(),
                hosts: Vec::new(),
                outcome,
                decided_by: by,
                answered_on: if matches!(how, How::OwnerAllow(_) | How::OwnerDeny(_)) {
                    "iPhone".to_owned()
                } else {
                    String::new()
                },
                decision_log_id: Some(id),
            })
            .unwrap();
        // `record_item_use` stamps the time of now; the fixture moves it.
        fx.vault
            .conn_ref()
            .unwrap()
            .execute(
                "UPDATE item_use SET at = ?1 WHERE id = ?2",
                (
                    i64::try_from(at + 1).unwrap(),
                    i64::try_from(use_id).unwrap(),
                ),
            )
            .unwrap();
        id
    }

    /// Agent A ("Claude Code") and agent B ("Codex") with these decisions; UTC days, the
    /// window `[NOON − 7 d, NOON)`:
    ///
    /// | at | agent | how | project |
    /// | --- | --- | --- | --- |
    /// | NOON − 1 h | A | model | alpha |
    /// | NOON − 2 h | A | owner allow, 4 000 ms | alpha |
    /// | NOON − 3 h | A | owner deny, 10 000 ms | beta |
    /// | NOON − 1 d | A | remembered answer | alpha |
    /// | NOON − 1 d − 1 h | B | no answer | alpha |
    /// | NOON − 2 d | B | rule | beta |
    /// | NOON − 6 d − 13 h (10-27 23:00 UTC: 7 days back) | B | owner allow, 1 000 ms | alpha |
    /// | NOON − 3 d | A | browser fill, owner allow 2 000 ms (not a run) | alpha |
    /// | NOON − 8 d (outside) | A | model | alpha |
    /// | NOON (outside: the end is open) | B | model | alpha |
    fn fixture() -> Fixture {
        let dir = tempfile::TempDir::new().unwrap();
        let mut vault = Vault::create(&dir.path().join("stats.db"), PASS).unwrap();
        vault.unlock(PASS).unwrap();
        let item = vault.add(api_key("Synthetic")).unwrap().id;
        let (a, _) = vault.register_agent("Claude Code").unwrap();
        let (b, _) = vault.register_agent("Codex").unwrap();
        let mut fx = Fixture {
            _dir: dir,
            vault,
            a: a.id,
            b: b.id,
            item,
        };
        let (a, b, run, fill) = (fx.a, fx.b, RequestKind::Run, RequestKind::BrowserFill);
        add(
            &mut fx,
            a,
            "Claude Code",
            NOON - HOUR,
            How::Model,
            "alpha",
            run,
        );
        add(
            &mut fx,
            a,
            "Claude Code",
            NOON - 2 * HOUR,
            How::OwnerAllow(4_000),
            "alpha",
            run,
        );
        add(
            &mut fx,
            a,
            "Claude Code",
            NOON - 3 * HOUR,
            How::OwnerDeny(10_000),
            "beta",
            run,
        );
        add(
            &mut fx,
            a,
            "Claude Code",
            NOON - D,
            How::Answer,
            "alpha",
            run,
        );
        add(
            &mut fx,
            b,
            "Codex",
            NOON - D - HOUR,
            How::NoAnswer,
            "alpha",
            run,
        );
        add(&mut fx, b, "Codex", NOON - 2 * D, How::Rule, "beta", run);
        add(
            &mut fx,
            b,
            "Codex",
            NOON - 6 * D - 13 * HOUR,
            How::OwnerAllow(1_000),
            "alpha",
            run,
        );
        add(
            &mut fx,
            a,
            "Claude Code",
            NOON - 3 * D,
            How::OwnerAllow(2_000),
            "alpha",
            fill,
        );
        add(
            &mut fx,
            a,
            "Claude Code",
            NOON - 8 * D,
            How::Model,
            "alpha",
            run,
        );
        add(&mut fx, b, "Codex", NOON, How::Model, "alpha", run);
        fx
    }

    fn utc(_: u64) -> i64 {
        0
    }

    #[test]
    fn the_stats_of_the_fixture_are_the_hand_computed_numbers() {
        let fx = fixture();
        let stats = fx
            .vault
            .bouncer_stats_with_offset(NOON - 7 * D, NOON, None, utc)
            .unwrap();
        // 7 runs: the fill, the run 8 days ago, and the run at the open end are out.
        assert_eq!(stats.runs, 7);
        // Allowed by bouncer: the model run and the remembered answer.
        assert_eq!(stats.allowed_by_bouncer, 2);
        // Asked you: owner allow, owner deny, no answer, and the old owner allow.
        assert_eq!(stats.asked, 4);
        // Denied: owner deny, no answer, rule.
        assert_eq!(stats.denied, 3);
        // Median of 4 000, 10 000, 1 000 ms (the no answer's time was dropped): 4 000.
        assert_eq!(stats.owner_answers, 3);
        assert_eq!(stats.answer_p50_ms, Some(4_000));
        assert_eq!(stats.answer_p50_secs, Some(4));
        assert!((stats.allowed_rate() - 2.0 / 7.0).abs() < 1e-9);
        assert!((stats.asked_rate() - 4.0 / 7.0).abs() < 1e-9);
        // Today: 3 runs, 2 asked; yesterday: 2 runs, 1 asked; 2 days ago: the rule.
        // NOON − 6 d − 13 h is on the UTC day 7 days back: in the totals, in no bar.
        let days: Vec<(u64, u64)> = stats.days.iter().map(|d| (d.runs, d.asked)).collect();
        assert_eq!(
            days,
            [(3, 2), (2, 1), (1, 0), (0, 0), (0, 0), (0, 0), (0, 0)]
        );

        assert_eq!(stats.agents.len(), 2);
        let a = &stats.agents[0];
        assert_eq!(
            (
                a.agent_id,
                a.name.as_str(),
                a.runs,
                a.asked,
                a.allowed_by_bouncer
            ),
            (fx.a, "Claude Code", 4, 2, 2)
        );
        assert_eq!(a.not_allowed, 1);
        assert_eq!(
            a.days[..2],
            [
                AgentDay {
                    runs: 3,
                    asked: 2,
                    not_allowed: 1
                },
                AgentDay {
                    runs: 1,
                    asked: 0,
                    not_allowed: 0
                }
            ]
        );
        // The newest use of A at any time: the model run, NOON − 1 h, plus 1 s.
        assert_eq!(a.last_at, Some(NOON - HOUR + 1));
        assert!((a.ask_rate() - 0.5).abs() < 1e-9);
        // 50 % but only 4 runs.
        assert!(!a.asks_often());
        let b = &stats.agents[1];
        assert_eq!(
            (
                b.agent_id,
                b.runs,
                b.asked,
                b.allowed_by_bouncer,
                b.not_allowed
            ),
            (fx.b, 3, 2, 0, 2)
        );
        // B's newest use is the one at the open end of the window, NOON + 1 s.
        assert_eq!(b.last_at, Some(NOON + 1));
        assert_eq!(
            b.days.iter().map(|d| d.runs).collect::<Vec<_>>(),
            [0, 1, 1, 0, 0, 0, 0]
        );
    }

    #[test]
    fn a_project_and_a_time_zone_change_the_figures() {
        let fx = fixture();
        let beta = fx
            .vault
            .bouncer_stats_with_offset(NOON - 7 * D, NOON, Some("beta"), utc)
            .unwrap();
        // Beta: A's owner denial and B's rule denial.
        assert_eq!(
            (beta.runs, beta.asked, beta.denied, beta.allowed_by_bouncer),
            (2, 1, 2, 0)
        );
        assert_eq!(beta.answer_p50_ms, Some(10_000));
        assert_eq!(beta.answer_p50_secs, Some(10));
        // B's newest use in beta: the rule, NOON − 2 d + 1 s.
        let b = beta.agents.iter().find(|a| a.agent_id == fx.b).unwrap();
        assert_eq!(b.last_at, Some(NOON - 2 * D + 1));

        // UTC+2: today is still 11-03. NOON − 6 d − 13 h is 10-28 01:00 local, 6 days
        // back: in the last bar now.
        let east = fx
            .vault
            .bouncer_stats_with_offset(NOON - 7 * D, NOON, None, |_| 2 * 3_600)
            .unwrap();
        let runs: Vec<u64> = east.days.iter().map(|d| d.runs).collect();
        assert_eq!(runs, [3, 2, 1, 0, 0, 0, 1]);
        assert_eq!(east.runs, 7);
        // UTC−10: today is 11-03 (NOON is 02:00 local). The run of 09:00 UTC is 23:00
        // local of 11-02: yesterday; 10:00 and 11:00 UTC stay today.
        let west = fx
            .vault
            .bouncer_stats_with_offset(NOON - 7 * D, NOON, None, |_| -10 * 3_600)
            .unwrap();
        let runs: Vec<u64> = west.days.iter().map(|d| d.runs).collect();
        assert_eq!(runs, [2, 3, 1, 0, 0, 0, 0]);
        assert_eq!(west.days[0].asked, 1);
        assert_eq!(west.days[1].asked, 2);
    }

    #[test]
    fn an_empty_window_and_an_even_median() {
        let fx = fixture();
        let none = fx
            .vault
            .bouncer_stats_with_offset(NOON - 30 * D, NOON - 20 * D, None, utc)
            .unwrap();
        assert_eq!(none.runs, 0);
        assert_eq!(none.answer_p50_secs, None);
        assert_eq!(none.days.len(), STATS_DAYS);
        assert!(none.agents.is_empty());
        let backwards = fx
            .vault
            .bouncer_stats_with_offset(NOON, NOON - D, None, utc)
            .unwrap();
        assert_eq!(backwards.runs, 0);
        assert_eq!(median(&mut [4_000, 1_000, 10_000, 3_001]), Some(3_500));
        assert_eq!(median(&mut [u64::MAX, u64::MAX]), Some(u64::MAX));
        assert_eq!(median(&mut []), None);
    }

    #[test]
    fn an_agent_asks_often_at_a_quarter_with_ten_runs() {
        let mut agent = AgentStats {
            runs: 10,
            asked: 2,
            ..AgentStats::default()
        };
        assert!(!agent.asks_often());
        agent.asked = 3;
        assert!(agent.asks_often());
        agent.runs = 9;
        agent.asked = 9;
        assert!(!agent.asks_often());
    }

    #[test]
    fn the_log_pages_newest_first_with_cloud_runs_and_projects() {
        let mut fx = fixture();
        let a = fx.a;
        let cloud_decision = add(
            &mut fx,
            a,
            "Claude Code",
            NOON + HOUR,
            How::OwnerAllow(3_000),
            "gamma",
            RequestKind::Run,
        );
        fx.vault
            .record_cloud_run(&NewCloudRun {
                relay_run_id: 77,
                decision_log_id: Some(cloud_decision),
                agent_id: a,
                at: NOON + HOUR,
            })
            .unwrap();
        let first = fx.vault.bouncer_log(None, 3, None).unwrap();
        assert_eq!(first.len(), 3);
        let newest = &first[0];
        assert_eq!(newest.decision_log_id, cloud_decision);
        assert_eq!(newest.relay_run, Some(77));
        assert_eq!(newest.project, "gamma");
        assert_eq!(newest.item_name, "Synthetic");
        assert_eq!(newest.item_id, Some(fx.item));
        assert_eq!(newest.answered_on, "iPhone");
        assert_eq!(newest.wait_ms, Some(3_000));
        assert_eq!(newest.decided_by, "owner");
        assert!(newest.asked && newest.allowed && !newest.production);
        assert!(
            first
                .windows(2)
                .all(|w| w[0].decision_log_id > w[1].decision_log_id)
        );
        // The next page starts below the last row; every row comes once.
        let mut all = first.clone();
        let mut before = first.last().map(|row| row.decision_log_id);
        while let Some(cursor) = before {
            let page = fx.vault.bouncer_log(Some(cursor), 3, None).unwrap();
            before = page.last().map(|row| row.decision_log_id);
            all.extend(page);
        }
        assert_eq!(all.len(), 11);
        let fill = all
            .iter()
            .find(|row| row.request == "browser_fill")
            .unwrap();
        assert_eq!(fill.wait_ms, Some(2_000));
        let answer = all.iter().find(|row| row.decided_by == "answer").unwrap();
        assert!(!answer.asked && answer.allowed && answer.wait_ms.is_none());
        let rule = all.iter().find(|row| row.decided_by == "rule").unwrap();
        assert!(!rule.allowed && rule.wait_ms.is_none());
        let no_answer = all
            .iter()
            .find(|row| row.decided_by == "no_answer")
            .unwrap();
        assert_eq!(no_answer.wait_ms, None, "a timeout keeps no answer time");
        // A project filter, and the page limit.
        let beta = fx.vault.bouncer_log(None, 50, Some("beta")).unwrap();
        assert_eq!(beta.len(), 2);
        assert!(beta.iter().all(|row| row.project == "beta"));
        assert!(fx.vault.bouncer_log(None, 0, None).unwrap().is_empty());
        assert_eq!(
            fx.vault.bouncer_log(None, 10_000, None).unwrap().len(),
            11.min(BOUNCER_LOG_PAGE)
        );
    }

    #[test]
    fn a_production_declaration_marks_the_row() {
        assert!(declares_production(
            r#"[null,{"project":"","environment":"production","risk":"write","scope":"x","reversibility":"y"}]"#
        ));
        assert!(!declares_production(r#"[{"environment":"development"}]"#));
        assert!(!declares_production("not json"));
    }
}
