//! The vault build fills [`BouncerData`] here: from this Mac's vault (U3a:
//! `Vault::bouncer_stats`, `Vault::bouncer_log`), the waiting runs, the activity lines of
//! the node, the feeds of the other Macs (relay-feed v2), and the connect requests (U2b,
//! a seam that is empty until `Node::pending_connects` exists).
//!
//! The pages never call this per frame: [`refresh`] asks [`BouncerCache`] first, so the
//! vault is read at most once per `REFRESH_MIN` (`bouncer.rs`).

use std::collections::{BTreeMap, BTreeSet};

use eframe::egui;

use super::bouncer::{
    self, AgentLine, BouncerData, DayBar, DeviceScope, EnvStats, LOG_PAGE, LogEvent, LogKind,
    LogOutcome, LogSource, ProductionUse, ProxyRow, WEEK,
};
use super::kit;
use crate::broker::approvals::PendingRun;
use crate::desktop::DesktopApp;
use crate::desktop::remote_feeds::{self, RemoteFeedState, RemoteMac};
use crate::questions::feed::{Feed, FeedAgent};

/// A connect request that waits for the owner (decision 4, U2b `Node::pending_connects`).
/// Nothing makes one until U2b lands: [`pending_connects`] is the seam.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingConnect {
    pub(crate) id: String,
    pub(crate) client_name: String,
    pub(crate) at: u64,
}

/// The connect requests that wait now. Empty until U2b adds `Node::pending_connects()`;
/// then this reads them from `app.cloud_node()`.
pub(crate) fn pending_connects(app: &DesktopApp) -> Vec<PendingConnect> {
    let _ = app;
    Vec::new()
}

/// Compute the Bouncer data when the cache says so. Call it once per frame of a Bouncer
/// page; it reads nothing in a frame that needs no refresh.
pub(super) fn refresh(app: &mut DesktopApp, ctx: &egui::Context, pending: &[PendingRun]) {
    let time = ctx.input(|input| input.time);
    let stamp = change_stamp(app, pending);
    let project = app.ui.activity_scope.project.clone();
    if app
        .ui
        .bouncer
        .needs_refresh(time, stamp, project.as_deref())
    {
        let pages = app.ui.bouncer.pages();
        let data = load(app, pending, project.as_deref(), pages);
        app.ui.bouncer.store(time, stamp, project.as_deref(), data);
    }
    // A run that the bouncer allowed by itself shows within the idle refresh.
    ctx.request_repaint_after(std::time::Duration::from_secs_f64(bouncer::REFRESH_IDLE));
}

/// What the window can see change without reading the vault: the vault session, the
/// waiting runs, the status messages (each owner action sets one), the connect requests,
/// and the feeds.
fn change_stamp(app: &DesktopApp, pending: &[PendingRun]) -> u64 {
    let runs: Vec<u64> = pending.iter().map(|run| run.id).collect();
    let feeds: Vec<(&str, u64)> = app
        .remote_macs
        .iter()
        .map(|mac| (mac.device.as_str(), mac.received_at))
        .collect();
    let connects: Vec<String> = pending_connects(app).into_iter().map(|c| c.id).collect();
    bouncer::stamp((
        app.owner_ui.session.epoch(),
        runs,
        app.status_seq,
        connects,
        feeds,
    ))
}

/// Everything the pages show, read now.
pub(super) fn load(
    app: &DesktopApp,
    pending: &[PendingRun],
    project: Option<&str>,
    pages: usize,
) -> BouncerData {
    let now = kit::now();
    let since = now.saturating_sub(WEEK);
    let mut data = BouncerData::default();
    let local = app
        .owner_ui
        .session
        .with_vault(|vault| LocalRead::read(vault, since, now, project, pages))
        .unwrap_or_default();
    let agents = app.owner_ui.session.agents().unwrap_or_default();
    data.has_agents = !agents.is_empty();
    data.environments = remote_feeds::environments(
        &local.this_name,
        &local.own,
        &local.devices,
        &app.remote_macs,
    );
    let this_name = data
        .environment(&DeviceScope::ThisMac)
        .map_or_else(|| "This Mac".to_owned(), |env| env.name.clone());
    data.remote_access_on = local.route_on;

    // This Mac.
    if let Some(stats) = &local.stats {
        data.stats.insert(DeviceScope::ThisMac, local_stats(stats));
    }
    let waiting: BTreeSet<&str> = pending.iter().map(|run| run.agent.as_str()).collect();
    for agent in agents.iter().filter(|agent| !agent.revoked) {
        let found = local
            .stats
            .as_ref()
            .and_then(|stats| stats.agents.iter().find(|a| a.agent_id == agent.id));
        let projects = local
            .projects_of
            .get(&agent.id)
            .cloned()
            .unwrap_or_default();
        data.agents.push(AgentLine {
            name: bouncer::clip(&agent.name),
            env: DeviceScope::ThisMac,
            env_name: this_name.clone(),
            remote: local.cloud.contains(&agent.id),
            runs: Some(found.map_or(0, |a| a.runs)),
            asked: found.map_or(0, |a| a.asked),
            not_allowed: found.map_or(0, |a| a.not_allowed),
            last_active: found.and_then(|a| a.last_at),
            waits: waiting.contains(agent.name.as_str()),
            projects,
        });
    }
    data.production = production_uses(&local.rows, since, &this_name);
    data.more_events = local.more;
    for row in &local.rows {
        data.events.push(LogEvent {
            source: LogSource::Decision(row.decision_log_id),
            at: row.at,
            env: DeviceScope::ThisMac,
            env_name: this_name.clone(),
            agent: Some(bouncer::clip(&row.agent_name)),
            remote_agent: local.cloud.contains(&row.agent_id),
            kind: LogKind::Run,
            credential: Some(bouncer::clip(&row.item_name)),
            production: row.production,
            project: row.project.clone(),
            outcome: LogOutcome::of_decision(row.allowed, &row.decided_by, &row.answered_on),
            relay_run: row.relay_run,
            command: String::new(),
        });
    }
    for run in pending {
        let question = &run.question;
        data.events.push(LogEvent {
            source: LogSource::Waiting(run.id),
            at: now,
            env: DeviceScope::ThisMac,
            env_name: this_name.clone(),
            agent: Some(bouncer::clip(&run.agent)),
            remote_agent: matches!(
                question.reason,
                crate::broker::route_diagnostics::ReasonKind::CloudAgent
            ),
            kind: LogKind::Run,
            credential: question.items.first().map(|item| bouncer::clip(&item.name)),
            production: question.production,
            project: question
                .project
                .as_ref()
                .map(|project| project.label.clone())
                .unwrap_or_default(),
            outcome: LogOutcome::WaitsForYou,
            relay_run: None,
            command: String::new(),
        });
    }
    for connect in pending_connects(app) {
        data.events.push(LogEvent {
            source: LogSource::Connect(connect.id.clone()),
            at: connect.at,
            env: DeviceScope::ThisMac,
            env_name: this_name.clone(),
            agent: Some(format!("{} (new)", bouncer::clip(&connect.client_name))),
            remote_agent: true,
            kind: LogKind::Connect,
            credential: None,
            production: false,
            project: String::new(),
            outcome: LogOutcome::WaitsForYou,
            relay_run: None,
            command: String::new(),
        });
    }
    let selected_activity = app.ui.logs.activity_id();
    for row in app
        .owner_ui
        .session
        .activity(crate::vault::MAX_ACTIVITY_ROWS)
        .unwrap_or_default()
    {
        let kind = LogKind::of_operation(&row.operation);
        // A line of a run shows only when a notification asks for it: its run is a
        // decision row already.
        if kind.is_none() && selected_activity != Some(row.id) {
            continue;
        }
        let kind = kind.unwrap_or(LogKind::Run);
        let agent = (!row.agent.trim().is_empty()
            && !matches!(kind, LogKind::RemoteAccessOn | LogKind::RemoteAccessOff))
        .then(|| bouncer::clip(&row.agent));
        data.events.push(LogEvent {
            source: LogSource::Activity(row.id),
            at: row.at,
            env: DeviceScope::ThisMac,
            env_name: this_name.clone(),
            agent,
            remote_agent: matches!(kind, LogKind::Connect | LogKind::Disconnect),
            kind,
            credential: (kind == LogKind::Run).then(|| bouncer::clip(&row.item)),
            production: false,
            project: String::new(),
            outcome: match (kind, row.decision) {
                (LogKind::Run, crate::vault::ActivityDecision::Allow) => {
                    LogOutcome::AllowedByBouncer
                }
                (LogKind::Run, _) => LogOutcome::DeniedByBouncer,
                (LogKind::Connect, _) => LogOutcome::AllowedByYou,
                _ => LogOutcome::ByYou,
            },
            relay_run: None,
            command: String::new(),
        });
    }

    // The other Macs: their feeds, read-only.
    for mac in &app.remote_macs {
        let RemoteFeedState::Ready(feed) = &mac.state else {
            continue;
        };
        let scope = DeviceScope::Other(mac.device.clone());
        let name = data
            .environment(&scope)
            .map_or_else(|| bouncer::clip(&mac.name), |env| env.name.clone());
        data.stats.insert(scope.clone(), feed_stats(feed, project));
        remote_lines(&mut data, feed, &scope, &name, mac);
    }

    let mut projects: BTreeSet<String> = local.projects_of.values().flatten().cloned().collect();
    for agent in &data.agents {
        projects.extend(agent.projects.iter().cloned());
    }
    for event in &data.events {
        projects.insert(event.project.clone());
    }
    projects.remove("");
    data.projects = projects.into_iter().collect();
    let last_shown = project.and_then(|project| {
        data.events
            .iter()
            .filter(|event| event.kind == LogKind::Run && event.project == project)
            .max_by_key(|event| event.at)
            .and_then(|event| Some((event.at, event.agent.clone()?)))
    });
    data.last_in_project = local.last_in_project.or(last_shown);
    data.events.sort_by_key(|event| std::cmp::Reverse(event.at));
    data
}

/// The agents and the runs of one other Mac from its feed.
fn remote_lines(
    data: &mut BouncerData,
    feed: &Feed,
    scope: &DeviceScope,
    name: &str,
    mac: &RemoteMac,
) {
    for agent in feed.agents.iter().filter(|agent| !agent.revoked) {
        let remote = agent.place == "remote";
        let days = agent_days(agent);
        data.agents.push(AgentLine {
            name: bouncer::clip(&agent.name),
            env: scope.clone(),
            env_name: name.to_owned(),
            remote,
            runs: days.map(|(runs, _, _)| runs),
            asked: days.map_or(0, |(_, asked, _)| asked),
            not_allowed: days.map_or(0, |(_, _, not_allowed)| not_allowed),
            last_active: agent.last_use_at,
            waits: false,
            projects: agent.projects.iter().map(|p| bouncer::clip(p)).collect(),
        });
        for item_use in &agent.recent {
            let decided = if item_use.outcome == "timed_out" {
                "timed_out"
            } else {
                item_use.decided_by.as_str()
            };
            data.events.push(LogEvent {
                source: LogSource::Feed(bouncer::stamp((
                    &mac.device,
                    &agent.id,
                    item_use.at,
                    &item_use.item_title,
                    &item_use.command,
                    &item_use.outcome,
                ))),
                at: item_use.at,
                env: scope.clone(),
                env_name: name.to_owned(),
                agent: Some(bouncer::clip(&agent.name)),
                remote_agent: remote,
                kind: LogKind::Run,
                credential: Some(if item_use.item_title.trim().is_empty() {
                    "A credential".to_owned()
                } else {
                    bouncer::clip(&item_use.item_title)
                }),
                production: false,
                project: bouncer::clip(&item_use.project),
                outcome: LogOutcome::of_decision(
                    item_use.outcome == "allowed",
                    decided,
                    &item_use.answered_on,
                ),
                relay_run: None,
                command: crate::broker::approvals::shown_path(&item_use.command, 600),
            });
        }
    }
}

/// The runs, questions, and denials of an agent of a v2 feed. `None` for v1.
fn agent_days(agent: &FeedAgent) -> Option<(u64, u64, u64)> {
    (!agent.days.is_empty()).then(|| {
        agent.days.iter().fold((0, 0, 0), |(runs, asked, no), day| {
            (runs + day.runs, asked + day.asked, no + day.not_allowed)
        })
    })
}

/// The numbers of another Mac from its feed (v2 `week.days`, `agents[].days`). A feed of
/// v1 has no days: empty numbers, so the tiles show "—". With a project, only the agents
/// of that project count, and the median stays the Mac's.
fn feed_stats(feed: &Feed, project: Option<&str>) -> EnvStats {
    if feed.week.days.is_empty() {
        return EnvStats::default();
    }
    let agents: Vec<&FeedAgent> = feed
        .agents
        .iter()
        .filter(|agent| project.is_none_or(|p| agent.projects.iter().any(|a| a == p)))
        .collect();
    let days: Vec<DayBar> = match project {
        None => feed
            .week
            .days
            .iter()
            .map(|day| DayBar {
                runs: day.runs,
                asked: day.asked,
            })
            .collect(),
        Some(_) => (0..7)
            .map(|index| {
                agents
                    .iter()
                    .filter_map(|agent| agent.days.get(index))
                    .fold(DayBar::default(), |sum, day| DayBar {
                        runs: sum.runs + day.runs,
                        asked: sum.asked + day.asked,
                    })
            })
            .collect(),
    };
    let runs: u64 = days.iter().map(|day| day.runs).sum();
    let asked: u64 = days.iter().map(|day| day.asked).sum();
    let denied: u64 = agents
        .iter()
        .flat_map(|agent| agent.days.iter())
        .map(|day| day.not_allowed)
        .sum();
    EnvStats {
        runs,
        // The feed does not split the denials by "asked": count them as asked first,
        // so this is a lower bound (the ⓘ of the Overview says it is approximate).
        allowed_by_bouncer: runs
            .saturating_sub(asked)
            .saturating_sub(denied.saturating_sub(asked)),
        asked,
        denied,
        answer_p50_secs: feed.week.answer_p50_secs,
        answers: feed.week.by_you,
        days,
    }
}

/// The numbers of this Mac (U3a `LocalStats`).
fn local_stats(stats: &crate::vault::LocalStats) -> EnvStats {
    EnvStats {
        runs: stats.runs,
        allowed_by_bouncer: stats.allowed_by_bouncer,
        asked: stats.asked,
        denied: stats.denied,
        answer_p50_secs: stats.answer_p50_secs,
        answers: stats.owner_answers,
        days: stats
            .days
            .iter()
            .map(|day| DayBar {
                runs: day.runs,
                asked: day.asked,
            })
            .collect(),
    }
}

/// The production credentials of this Mac used in the window, by credential and agent.
fn production_uses(
    rows: &[crate::vault::LogRow],
    since: u64,
    this_name: &str,
) -> Vec<ProductionUse> {
    let mut counts: BTreeMap<(String, String), u64> = BTreeMap::new();
    for row in rows
        .iter()
        .filter(|row| row.production && row.allowed && row.at >= since)
    {
        *counts
            .entry((
                bouncer::clip(&row.item_name),
                bouncer::clip(&row.agent_name),
            ))
            .or_default() += 1;
    }
    let mut uses: Vec<ProductionUse> = counts
        .into_iter()
        .map(|((credential, agent), times)| ProductionUse {
            credential,
            agent,
            env: DeviceScope::ThisMac,
            env_name: this_name.to_owned(),
            times,
        })
        .collect();
    uses.sort_by(|a, b| b.times.cmp(&a.times));
    uses
}

/// What one read of this Mac's vault gives.
#[derive(Default)]
struct LocalRead {
    this_name: String,
    own: BTreeSet<String>,
    devices: Vec<crate::vault::TrustedDevice>,
    stats: Option<crate::vault::LocalStats>,
    rows: Vec<crate::vault::LogRow>,
    more: bool,
    last_in_project: Option<(u64, String)>,
    cloud: BTreeSet<u64>,
    projects_of: BTreeMap<u64, Vec<String>>,
    route_on: bool,
}

impl LocalRead {
    fn read(
        vault: &mut crate::vault::Vault,
        since: u64,
        now: u64,
        project: Option<&str>,
        pages: usize,
    ) -> Self {
        let mut read = Self {
            devices: vault.trusted_devices().unwrap_or_default(),
            stats: vault.bouncer_stats(since, now, project).ok(),
            ..Self::default()
        };
        // This Mac's own rows: the device of each relay membership of this vault file.
        for membership in vault.relay_memberships().unwrap_or_default() {
            if let Ok(Some(device)) =
                vault.trusted_device_by_relay_id(&membership.team_id, membership.device_id)
            {
                if read.this_name.is_empty() {
                    read.this_name = device.name.clone();
                }
                read.own.insert(device.uuid);
            }
        }
        // The newest rows, one page of `LOG_PAGE` after the other.
        let mut before = None;
        for _ in 0..pages {
            let page = vault
                .bouncer_log(before, LOG_PAGE, project)
                .unwrap_or_default();
            read.more = page.len() >= LOG_PAGE;
            before = page.last().map(|row| row.decision_log_id);
            read.rows.extend(page);
            if !read.more {
                break;
            }
        }
        for row in &read.rows {
            let projects = read.projects_of.entry(row.agent_id).or_default();
            if !row.project.is_empty() && !projects.contains(&row.project) {
                projects.push(row.project.clone());
            }
        }
        if let Some(project) = project {
            read.last_in_project = vault
                .bouncer_log(None, 1, Some(project))
                .ok()
                .and_then(|rows| rows.into_iter().next())
                .map(|row| (row.at, bouncer::clip(&row.agent_name)));
        }
        read.cloud = vault
            .cloud_agents()
            .unwrap_or_default()
            .into_iter()
            .map(|agent| agent.agent_id)
            .collect();
        read.route_on = vault
            .cloud_node_setting()
            .is_ok_and(|setting| setting.route_on);
        read
    }
}

/// The proxied requests of one cloud run of this Mac, from the relay audit: method, host,
/// and status only. The node gives its newest audit rows; a run older than those shows
/// none. (U2b: `Node::run_audit(run)` would read the rows of the run itself.)
pub(super) fn proxied_requests(app: &DesktopApp, relay_run: u64) -> Vec<ProxyRow> {
    let Some(node) = app.cloud_node() else {
        return Vec::new();
    };
    let mut rows: Vec<ProxyRow> = node
        .recent_activity()
        .into_iter()
        .filter(|row| row.action == "proxy_request")
        .filter(|row| row.run_id.is_some_and(|run| run.0 == relay_run))
        .filter_map(|row| ProxyRow::from_audit(&row.detail))
        .collect();
    rows.sort_by_key(|row| row.at);
    rows
}
