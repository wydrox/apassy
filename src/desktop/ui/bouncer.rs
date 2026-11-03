//! The Bouncer section of the sidebar: Overview, Decisions, Agents, and Logs
//! (`docs/design/implementation-plan-bouncer-section.md`, decisions 1, 3, and 7; the
//! mockup `docs/design/cloud-agents-mockup.html`).
//!
//! This module holds what the pages show, as plain data, and the rules that make it:
//! the environments of the scope bar, the numbers of the last 7 days, the attention
//! items, and the events of Logs. Nothing here reads the vault or draws: the vault build
//! fills [`BouncerData`] in `bouncer_load` (at most once per [`REFRESH_MIN`], never per
//! frame, through [`BouncerCache`]), and the demo build fills it from fixtures
//! (`demo.rs`). So the pages draw the same in both builds and the tests need no vault.
// The demo build draws the pages from fixtures and uses part of this module.
#![cfg_attr(not(feature = "vault"), allow(dead_code))]

use std::collections::BTreeMap;
use std::hash::{DefaultHasher, Hash, Hasher};

/// The window of the Overview: the last 7 × 24 hours.
pub(crate) const WEEK: u64 = 7 * DAY;
pub(crate) const DAY: u64 = 86_400;
/// A Mac whose last report is older than this is dimmed (relay-feed-v1 §8).
pub(crate) const STALE_AFTER: u64 = DAY;
/// "Active now": a use in the last 10 minutes.
pub(crate) const ACTIVE_NOW: u64 = 10 * 60;
/// An agent that asks this often, with at least [`ASKS_OFTEN_RUNS`] runs, is orange and
/// an attention item.
pub(crate) const ASKS_OFTEN_RATE: f64 = 0.25;
pub(crate) const ASKS_OFTEN_RUNS: u64 = 10;
/// The cache computes again at most this often, in seconds.
pub(crate) const REFRESH_MIN: f64 = 2.0;
/// Without a change that the window can see (a run that the bouncer allowed by itself
/// changes nothing in memory), the cache computes again after this many seconds.
pub(crate) const REFRESH_IDLE: f64 = 10.0;
/// The rows of Logs per page of this Mac (the "Load More" step).
pub(crate) const LOG_PAGE: usize = 200;
/// The longest name of a Mac, an agent, or a credential in a row.
const SHOWN_NAME: usize = 40;

// ---- The scope. ----

/// The environments that a Bouncer page shows.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum DeviceScope {
    /// This Mac and every other Mac of the vault.
    #[default]
    All,
    /// This Mac only.
    ThisMac,
    /// One other Mac, by its `trusted_device` id.
    Other(String),
}

/// The scope of the Bouncer pages: "Showing [environments] in [projects]". One scope
/// for all four pages (`app.ui.activity_scope`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub(crate) struct ActivityScope {
    pub(crate) device: DeviceScope,
    /// One project label, or `None` for all projects.
    pub(crate) project: Option<String>,
}

impl DeviceScope {
    /// Whether the environment `env` is in this scope.
    pub(crate) fn covers(&self, env: &DeviceScope) -> bool {
        match self {
            Self::All => true,
            scope => scope == env,
        }
    }
}

// ---- Environments. ----

/// One Mac of the vault, as the scope bar and the page headers show it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Environment {
    /// [`DeviceScope::ThisMac`] or [`DeviceScope::Other`].
    pub(crate) scope: DeviceScope,
    pub(crate) name: String,
    /// The `generated_at` of the last feed this Mac read (or, for a feed it cannot open,
    /// when it came). `None`: this Mac, or a Mac that never reported.
    pub(crate) reported_at: Option<u64>,
    /// A Mac of the vault whose feed never came.
    pub(crate) never_reported: bool,
    /// Why its numbers do not show: "Update Apassy to see …", "Sync this vault to …".
    pub(crate) note: Option<String>,
}

impl Environment {
    pub(crate) fn this_mac(name: &str) -> Self {
        let name = name.trim();
        Self {
            scope: DeviceScope::ThisMac,
            name: if name.is_empty() {
                "This Mac".to_owned()
            } else {
                clip(name)
            },
            reported_at: None,
            never_reported: false,
            note: None,
        }
    }

    pub(crate) fn is_this_mac(&self) -> bool {
        self.scope == DeviceScope::ThisMac
    }

    /// The Mac reported once, more than 24 hours ago.
    pub(crate) fn stale(&self, now: u64) -> bool {
        self.reported_at
            .is_some_and(|at| now.saturating_sub(at) > STALE_AFTER)
    }

    /// Dimmed everywhere: silent for 24 hours, or never reported.
    pub(crate) fn dimmed(&self, now: u64) -> bool {
        self.never_reported || self.stale(now)
    }

    /// The text at the right of its menu item: "This Mac", "Never reported", or the
    /// age of its report.
    pub(crate) fn menu_detail(&self, now: u64, offset: i64) -> String {
        if self.is_this_mac() {
            "This Mac".to_owned()
        } else if self.never_reported {
            "Never reported".to_owned()
        } else {
            self.reported_at
                .map_or_else(String::new, |at| report_age(at, now, offset))
        }
    }
}

/// The age of a report: "5 min ago" within the hour, the time today ("08:12"), else the
/// day ("1 Nov").
pub(crate) fn report_age(at: u64, now: u64, offset: i64) -> String {
    let age = now.saturating_sub(at);
    if age < 60 {
        "Just now".to_owned()
    } else if age < 3_600 {
        format!("{} min ago", age / 60)
    } else if days_ago(at, now, offset) == 0 {
        clock(at, offset)
    } else {
        day_month(at, offset)
    }
}

/// Sort the environments as the menu lists them: this Mac first, then the Macs that
/// reported, by name, then the Macs that never reported, by name.
pub(crate) fn sort_environments(envs: &mut [Environment]) {
    envs.sort_by(|a, b| {
        let rank = |env: &Environment| (!env.is_this_mac(), env.never_reported);
        rank(a)
            .cmp(&rank(b))
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
}

// ---- Local time. ----

/// The local calendar day of `at` minus that of `now`, in days: 0 today, 1 yesterday. A
/// time after `now` (the clock of another Mac) is today.
pub(crate) fn days_ago(at: u64, now: u64, offset: i64) -> i64 {
    let day = |time: u64| {
        i64::try_from(time)
            .unwrap_or(i64::MAX)
            .saturating_add(offset)
            .div_euclid(DAY as i64)
    };
    day(now).saturating_sub(day(at)).max(0)
}

/// "14:19", local time.
pub(crate) fn clock(at: u64, offset: i64) -> String {
    let local = i64::try_from(at).unwrap_or(i64::MAX).saturating_add(offset);
    let seconds = local.rem_euclid(DAY as i64);
    format!("{:02}:{:02}", seconds / 3_600, seconds % 3_600 / 60)
}

/// "14:12:08", local time.
pub(crate) fn clock_seconds(at: u64, offset: i64) -> String {
    let local = i64::try_from(at).unwrap_or(i64::MAX).saturating_add(offset);
    let seconds = local.rem_euclid(DAY as i64);
    format!("{}:{:02}", clock(at, offset), seconds % 60)
}

/// "1 Nov", local day.
pub(crate) fn day_month(at: u64, offset: i64) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let local = i64::try_from(at).unwrap_or(i64::MAX).saturating_add(offset);
    let (_, month, day) = civil_from_days(local.div_euclid(DAY as i64));
    format!("{day} {}", MONTHS[(month - 1) as usize])
}

/// The short weekday of a local day: "Tue".
pub(crate) fn weekday(at: u64, offset: i64) -> &'static str {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    let local = i64::try_from(at).unwrap_or(i64::MAX).saturating_add(offset);
    DAYS[local.div_euclid(DAY as i64).rem_euclid(7) as usize]
}

/// Year, month (1–12), and day of a count of days since 1970-01-01 (H. Hinnant's
/// `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// The offset of the local time from UTC at `now`, in seconds. 0 when macOS does not say
/// or the build has no time zone data (the demo).
pub(crate) fn local_offset(now: u64) -> i64 {
    #[cfg(feature = "vault")]
    {
        i64::try_from(now)
            .ok()
            .and_then(|now| time::OffsetDateTime::from_unix_timestamp(now).ok())
            .and_then(|at| time::UtcOffset::local_offset_at(at).ok())
            .map_or(0, |offset| i64::from(offset.whole_seconds()))
    }
    #[cfg(not(feature = "vault"))]
    {
        let _ = now;
        0
    }
}

/// A name cut to [`SHOWN_NAME`] characters, with control characters as `?`.
pub(crate) fn clip(name: &str) -> String {
    let clean: String = name
        .trim()
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect();
    if clean.chars().count() <= SHOWN_NAME {
        clean
    } else {
        let mut cut: String = clean.chars().take(SHOWN_NAME - 1).collect();
        cut.push('…');
        cut
    }
}

// ---- Numbers. ----

/// One bar of "Runs per day".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct DayBar {
    pub(crate) runs: u64,
    pub(crate) asked: u64,
}

/// The numbers of one environment over the last 7 days (decision 3).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct EnvStats {
    pub(crate) runs: u64,
    pub(crate) allowed_by_bouncer: u64,
    pub(crate) asked: u64,
    pub(crate) denied: u64,
    /// The median time to an answer of yours, in seconds. `None`: no answer.
    pub(crate) answer_p50_secs: Option<u64>,
    /// How many answers the median is of: its weight across Macs.
    pub(crate) answers: u64,
    /// Seven days, today first. Empty: the environment does not report days (a feed of
    /// v1): its tiles show "—".
    pub(crate) days: Vec<DayBar>,
}

impl EnvStats {
    fn known(&self) -> bool {
        !self.days.is_empty()
    }
}

/// The numbers of the environments in a scope, added.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Totals {
    /// `None` when no environment in the scope has numbers: the tiles show "—".
    pub(crate) runs: Option<u64>,
    pub(crate) allowed_by_bouncer: u64,
    pub(crate) asked: u64,
    pub(crate) denied: u64,
    pub(crate) answer_p50_secs: Option<u64>,
    /// Seven bars, today first.
    pub(crate) days: [DayBar; 7],
    /// An environment in the scope has no numbers: the totals leave it out.
    pub(crate) partial: bool,
}

impl Totals {
    /// "87%" of the runs, or nothing.
    pub(crate) fn share(&self, part: u64) -> Option<String> {
        let runs = self.runs.filter(|runs| *runs > 0)?;
        Some(format!(
            "{}%",
            (part as f64 * 100.0 / runs as f64).round() as u64
        ))
    }

    pub(crate) fn median_text(&self) -> String {
        self.answer_p50_secs
            .map_or_else(|| "—".to_owned(), duration_text)
    }
}

/// "14 s", "3 min", "2 h".
pub(crate) fn duration_text(seconds: u64) -> String {
    match seconds {
        0..120 => format!("{seconds} s"),
        120..7_200 => format!("{} min", seconds / 60),
        _ => format!("{} h", seconds / 3_600),
    }
}

/// Add the numbers of `stats`. The median across environments is the median of their
/// medians, each weighted by its number of answers (decision 2: approximate, and the ⓘ
/// says so).
pub(crate) fn totals<'a>(stats: impl IntoIterator<Item = &'a EnvStats>) -> Totals {
    let mut out = Totals::default();
    let mut medians: Vec<(u64, u64)> = Vec::new();
    for env in stats {
        if !env.known() {
            out.partial = true;
            continue;
        }
        *out.runs.get_or_insert(0) += env.runs;
        out.allowed_by_bouncer += env.allowed_by_bouncer;
        out.asked += env.asked;
        out.denied += env.denied;
        for (bar, day) in out.days.iter_mut().zip(&env.days) {
            bar.runs += day.runs;
            bar.asked += day.asked;
        }
        if let Some(p50) = env.answer_p50_secs {
            medians.push((p50, env.answers.max(1)));
        }
    }
    out.answer_p50_secs = weighted_median(&mut medians);
    out
}

/// The value at half of the total weight.
fn weighted_median(values: &mut [(u64, u64)]) -> Option<u64> {
    values.sort_unstable();
    let total: u64 = values.iter().map(|(_, weight)| weight).sum();
    let mut seen = 0;
    for (value, weight) in values.iter() {
        seen += weight;
        if seen * 2 >= total {
            return Some(*value);
        }
    }
    None
}

// ---- Agents. ----

/// One agent of one environment, for the Overview table and the Logs agent menu.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct AgentLine {
    pub(crate) name: String,
    pub(crate) env: DeviceScope,
    pub(crate) env_name: String,
    /// A remote agent (an MCP client on the internet): the cloud badge and "Remote".
    pub(crate) remote: bool,
    /// The runs and questions of the last 7 days. `None`: a feed of v1 ("—").
    pub(crate) runs: Option<u64>,
    pub(crate) asked: u64,
    pub(crate) not_allowed: u64,
    /// The newest use.
    pub(crate) last_active: Option<u64>,
    /// A question of this agent waits for you now.
    pub(crate) waits: bool,
    pub(crate) projects: Vec<String>,
}

impl AgentLine {
    /// "30%", or "—".
    pub(crate) fn ask_rate_text(&self) -> String {
        match self.runs {
            Some(runs) if runs > 0 => {
                format!(
                    "{}%",
                    (self.asked as f64 * 100.0 / runs as f64).round() as u64
                )
            }
            _ => "—".to_owned(),
        }
    }

    /// At least 25 % of at least 10 runs asked you. Every run of a remote agent asks
    /// you, so a remote agent never "asks often".
    pub(crate) fn asks_often(&self) -> bool {
        !self.remote
            && self.runs.is_some_and(|runs| {
                runs >= ASKS_OFTEN_RUNS && self.asked as f64 >= ASKS_OFTEN_RATE * runs as f64
            })
    }

    /// "Waits for you", "Active now", "25 min ago" today, or the day.
    pub(crate) fn status_text(&self, now: u64, offset: i64) -> String {
        if self.waits {
            return "Waits for you".to_owned();
        }
        match self.last_active {
            None => "—".to_owned(),
            Some(at) if now.saturating_sub(at) <= ACTIVE_NOW => "Active now".to_owned(),
            Some(at) if days_ago(at, now, offset) == 0 => {
                let age = now.saturating_sub(at);
                if age < 3_600 {
                    format!("{} min ago", age / 60)
                } else {
                    format!("{} h ago", age / 3_600)
                }
            }
            Some(at) => day_month(at, offset),
        }
    }

    fn in_project(&self, project: Option<&str>) -> bool {
        project.is_none_or(|project| self.projects.iter().any(|p| p == project))
    }
}

/// A production credential that an agent used in the window (this Mac only: the feed
/// does not say).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProductionUse {
    pub(crate) credential: String,
    pub(crate) agent: String,
    pub(crate) env: DeviceScope,
    pub(crate) env_name: String,
    pub(crate) times: u64,
}

/// One item of "Needs attention", in the order of decision 3.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Attention {
    /// A Mac silent 24 h after it reported before.
    Silent {
        scope: DeviceScope,
        name: String,
        last: u64,
    },
    Production(ProductionUse),
    AsksOften {
        agent: String,
        env: DeviceScope,
        env_name: String,
        rate: String,
    },
    /// A remote agent with a denial.
    RemoteDenied {
        agent: String,
        env: DeviceScope,
        env_name: String,
        denials: u64,
    },
}

impl Attention {
    /// The title line: "Codex asks often".
    pub(crate) fn title(&self) -> String {
        match self {
            Self::Silent { name, .. } => format!("{name} not reporting"),
            Self::Production(found) => format!(
                "{} used {}",
                found.credential,
                if found.times == 1 {
                    "once".to_owned()
                } else {
                    format!("{} times", found.times)
                }
            ),
            Self::AsksOften { agent, .. } => format!("{agent} asks often"),
            Self::RemoteDenied { agent, denials, .. } => format!(
                "{agent} was denied {}",
                if *denials == 1 {
                    "once".to_owned()
                } else {
                    format!("{denials} times")
                }
            ),
        }
    }

    /// The line under it: "Mac mini (studio) · 30% of runs".
    pub(crate) fn detail(&self, offset: i64) -> String {
        match self {
            Self::Silent { last, .. } => {
                format!(
                    "Last report {}, {}",
                    day_month(*last, offset),
                    clock(*last, offset)
                )
            }
            Self::Production(found) => format!("{} · {}", found.agent, found.env_name),
            Self::AsksOften { env_name, rate, .. } => format!("{env_name} · {rate} of runs"),
            Self::RemoteDenied { env_name, .. } => format!("{env_name} · Remote"),
        }
    }

    /// A red mark for production, gray for a silent Mac, orange else.
    pub(crate) fn severity(&self) -> Severity {
        match self {
            Self::Silent { .. } => Severity::Off,
            Self::Production(_) => Severity::Critical,
            Self::AsksOften { .. } | Self::RemoteDenied { .. } => Severity::Warning,
        }
    }

    /// The scope a click on the item opens: the Mac of the item.
    pub(crate) fn scope(&self) -> &DeviceScope {
        match self {
            Self::Silent { scope, .. } => scope,
            Self::Production(found) => &found.env,
            Self::AsksOften { env, .. } | Self::RemoteDenied { env, .. } => env,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Severity {
    Warning,
    Critical,
    Off,
}

// ---- Logs. ----

/// What happened in one row of Logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum LogKind {
    Run,
    Connect,
    Disconnect,
    RemoteAccessOn,
    RemoteAccessOff,
}

impl LogKind {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Run => "Run",
            Self::Connect => "Connect",
            Self::Disconnect => "Disconnect",
            Self::RemoteAccessOn => "Remote access on",
            Self::RemoteAccessOff => "Remote access off",
        }
    }

    pub(crate) fn is_connection(self) -> bool {
        !matches!(self, Self::Run)
    }

    /// The kind of an activity line of the node (U2b writes them), or `None` for any
    /// other line.
    pub(crate) fn of_operation(operation: &str) -> Option<Self> {
        match operation.trim() {
            "remote agent connected" => Some(Self::Connect),
            "agent disconnected" => Some(Self::Disconnect),
            "remote access on" => Some(Self::RemoteAccessOn),
            "remote access off" => Some(Self::RemoteAccessOff),
            _ => None,
        }
    }
}

/// How a row of Logs ended, in the words of the mockup.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum LogOutcome {
    AllowedByBouncer,
    AllowedByYou,
    /// Allowed on another device: "Allowed on iPhone".
    AllowedOn(String),
    DeniedByYou,
    DeniedOn(String),
    DeniedByBouncer,
    NoAnswer,
    WaitsForYou,
    /// A change that you made: remote access, a disconnect.
    ByYou,
    /// Anything else, as the source says it.
    Other(String),
}

impl LogOutcome {
    pub(crate) fn text(&self) -> String {
        match self {
            Self::AllowedByBouncer => "Allowed by bouncer".to_owned(),
            Self::AllowedByYou => "Allowed by you".to_owned(),
            Self::AllowedOn(device) => format!("Allowed on {device}"),
            Self::DeniedByYou => "Denied by you".to_owned(),
            Self::DeniedOn(device) => format!("Denied on {device}"),
            Self::DeniedByBouncer => "Denied by bouncer".to_owned(),
            Self::NoAnswer => "No answer".to_owned(),
            Self::WaitsForYou => "Waits for you".to_owned(),
            Self::ByYou => "By you".to_owned(),
            Self::Other(text) => text.clone(),
        }
    }

    pub(crate) fn denied(&self) -> bool {
        matches!(
            self,
            Self::DeniedByYou | Self::DeniedOn(_) | Self::DeniedByBouncer | Self::NoAnswer
        )
    }

    /// The outcome of a decision: `allowed`, whether it asked you, who decided
    /// (`rule`, `model`, `pattern`, `answer`, `bouncer`, `owner`, `no_answer`), and the
    /// device that answered ("" or this Mac: you, on this Mac).
    pub(crate) fn of_decision(allowed: bool, decided_by: &str, answered_on: &str) -> Self {
        let device = answered_on.trim();
        let elsewhere = (!device.is_empty()).then(|| clip(device));
        match (allowed, decided_by) {
            (_, "no_answer" | "timed_out") => Self::NoAnswer,
            (true, "owner") => elsewhere.map_or(Self::AllowedByYou, Self::AllowedOn),
            (false, "owner") => elsewhere.map_or(Self::DeniedByYou, Self::DeniedOn),
            (true, _) => Self::AllowedByBouncer,
            (false, _) => Self::DeniedByBouncer,
        }
    }
}

/// Where a row of Logs comes from, for its key and for a notification.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum LogSource {
    /// A `decision_log` row of this Mac.
    Decision(u64),
    /// An activity line of this Mac (a notification names it).
    Activity(u64),
    /// A run of this Mac that waits for you now.
    Waiting(u64),
    /// A connect request that waits for you now (U2b).
    Connect(String),
    /// A use in the feed of another Mac.
    Feed(u64),
}

/// One row of Logs (decision 7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LogEvent {
    pub(crate) source: LogSource,
    pub(crate) at: u64,
    pub(crate) env: DeviceScope,
    pub(crate) env_name: String,
    /// `None`: no agent (remote access on and off).
    pub(crate) agent: Option<String>,
    pub(crate) remote_agent: bool,
    pub(crate) kind: LogKind,
    pub(crate) credential: Option<String>,
    pub(crate) production: bool,
    /// Empty: no project.
    pub(crate) project: String,
    pub(crate) outcome: LogOutcome,
    /// The run of the node of a cloud run of this Mac: its expansion shows the proxied
    /// requests from the relay audit.
    pub(crate) relay_run: Option<u64>,
    /// The command summary, when the source keeps one (feeds do; a log row may not).
    pub(crate) command: String,
}

impl LogEvent {
    /// A key for the selection and the expansion, the same in each frame.
    pub(crate) fn key(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.source.hash(&mut hasher);
        self.env.hash(&mut hasher);
        hasher.finish()
    }

    /// The text that the filter field searches: agent, credential, Mac, project,
    /// event, outcome, and command.
    fn haystack(&self) -> String {
        [
            self.agent.as_deref().unwrap_or_default(),
            self.credential.as_deref().unwrap_or_default(),
            &self.env_name,
            &self.project,
            self.kind.label(),
            &self.outcome.text(),
            &self.command,
        ]
        .join("\n")
        .to_lowercase()
    }

    /// The row opens: a cloud run of this Mac shows its proxied requests, any run its
    /// command.
    pub(crate) fn expandable(&self) -> bool {
        self.kind == LogKind::Run && (self.relay_run.is_some() || !self.command.is_empty())
    }
}

/// The event filter of Logs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum LogKindFilter {
    #[default]
    All,
    Runs,
    Connections,
    Denied,
}

/// The filters of Logs, after the scope.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct LogFilter {
    pub(crate) kind: LogKindFilter,
    /// One agent by name, or `None` for all agents.
    pub(crate) agent: Option<String>,
    pub(crate) text: String,
}

impl LogFilter {
    pub(crate) fn is_set(&self) -> bool {
        self.kind != LogKindFilter::All || self.agent.is_some() || !self.text.trim().is_empty()
    }

    pub(crate) fn matches(&self, event: &LogEvent) -> bool {
        let kind = match self.kind {
            LogKindFilter::All => true,
            LogKindFilter::Runs => event.kind == LogKind::Run,
            LogKindFilter::Connections => event.kind.is_connection(),
            LogKindFilter::Denied => event.outcome.denied(),
        };
        let agent = self
            .agent
            .as_ref()
            .is_none_or(|agent| event.agent.as_ref() == Some(agent));
        let needle = self.text.trim().to_lowercase();
        kind && agent && (needle.is_empty() || event.haystack().contains(&needle))
    }
}

/// The events in the scope that pass the filter, newest first.
pub(crate) fn filter_events<'a>(
    events: &'a [LogEvent],
    scope: &ActivityScope,
    filter: &LogFilter,
) -> Vec<&'a LogEvent> {
    let mut shown: Vec<&LogEvent> = events
        .iter()
        .filter(|event| scope.device.covers(&event.env))
        .filter(|event| {
            scope
                .project
                .as_ref()
                .is_none_or(|project| event.project == *project || event.kind.is_connection())
        })
        .filter(|event| filter.matches(event))
        .collect();
    shown.sort_by_key(|event| std::cmp::Reverse(event.at));
    shown
}

/// One group of rows by local day: "Today", "Yesterday", or "1 Nov".
pub(crate) fn day_title(at: u64, now: u64, offset: i64) -> String {
    match days_ago(at, now, offset) {
        0 => "Today".to_owned(),
        1 => "Yesterday".to_owned(),
        _ => day_month(at, offset),
    }
}

/// One proxied request of a cloud run, from the relay audit. Never a path, a header, a
/// body, or a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProxyRow {
    pub(crate) at: u64,
    pub(crate) method: String,
    pub(crate) host: String,
    /// "200", or "Refused: wrong host".
    pub(crate) result: String,
    pub(crate) refused: bool,
}

impl ProxyRow {
    /// The row of one `proxy_request` audit detail (the relay's `ProxyEvent` as JSON).
    /// Only `at`, `method`, `host`, `status`, `outcome`, and `code` are read; the path
    /// and everything else stay unread.
    pub(crate) fn from_audit(detail: &str) -> Option<Self> {
        let value: serde_json::Value = serde_json::from_str(detail).ok()?;
        let at = value.get("at")?.as_u64()?;
        let method = value.get("method")?.as_str()?;
        let host = value.get("host")?.as_str()?;
        let status = value.get("status").and_then(serde_json::Value::as_u64);
        let outcome = value
            .get("outcome")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let code = value
            .get("code")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let refused = outcome == "refused";
        let result = if refused {
            format!("Refused: {}", refusal_words(code))
        } else if outcome == "upstream_failed" {
            "Host failed".to_owned()
        } else {
            status.map_or_else(|| "—".to_owned(), |status| status.to_string())
        };
        Some(Self {
            at,
            method: clip_ascii(method, 10),
            host: clip_ascii(host, 80),
            result,
            refused,
        })
    }
}

/// "wrong host" for the error code `wrong_host`.
fn refusal_words(code: &str) -> String {
    let words = clip_ascii(code, 40).replace('_', " ");
    if words.is_empty() {
        "refused".to_owned()
    } else {
        words
    }
}

/// Printable ASCII only, at most `max` bytes: a host or a method from the audit.
fn clip_ascii(text: &str, max: usize) -> String {
    text.chars()
        .filter(|c| c.is_ascii_graphic())
        .take(max)
        .collect()
}

// ---- What the pages show. ----

/// Everything the Bouncer pages show, made at most once per [`REFRESH_MIN`].
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct BouncerData {
    /// This Mac first ([`sort_environments`]).
    pub(crate) environments: Vec<Environment>,
    /// The numbers of each environment that has them, for the project of the scope.
    pub(crate) stats: BTreeMap<DeviceScope, EnvStats>,
    pub(crate) agents: Vec<AgentLine>,
    /// Any agent on any Mac, also disconnected: the first-run state needs none.
    pub(crate) has_agents: bool,
    pub(crate) production: Vec<ProductionUse>,
    /// Newest first.
    pub(crate) events: Vec<LogEvent>,
    /// This Mac has older rows than `events` holds: "Load More".
    pub(crate) more_events: bool,
    /// Every project of every environment, sorted.
    pub(crate) projects: Vec<String>,
    /// With a project in the scope: its newest run, and the agent, at any time.
    pub(crate) last_in_project: Option<(u64, String)>,
    /// The remote access of this Mac is on (the first-run state offers to turn it on).
    pub(crate) remote_access_on: bool,
}

impl BouncerData {
    pub(crate) fn environment(&self, scope: &DeviceScope) -> Option<&Environment> {
        self.environments.iter().find(|env| env.scope == *scope)
    }

    /// The environments in the scope, in the order of the menu.
    pub(crate) fn environments_in(&self, scope: &DeviceScope) -> Vec<&Environment> {
        self.environments
            .iter()
            .filter(|env| scope.covers(&env.scope))
            .collect()
    }

    pub(crate) fn totals(&self, scope: &DeviceScope) -> Totals {
        let mut out = totals(
            self.environments_in(scope)
                .into_iter()
                .filter_map(|env| self.stats.get(&env.scope)),
        );
        // An environment in the scope without numbers leaves the totals partial.
        if self
            .environments_in(scope)
            .iter()
            .any(|env| !self.stats.get(&env.scope).is_some_and(EnvStats::known))
        {
            out.partial = true;
        }
        out
    }

    /// The agents in the scope, the most runs first.
    pub(crate) fn agents_in(&self, scope: &ActivityScope) -> Vec<&AgentLine> {
        let mut agents: Vec<&AgentLine> = self
            .agents
            .iter()
            .filter(|agent| scope.device.covers(&agent.env))
            .filter(|agent| agent.in_project(scope.project.as_deref()))
            .collect();
        agents.sort_by(|a, b| {
            b.waits
                .cmp(&a.waits)
                .then(b.runs.unwrap_or(0).cmp(&a.runs.unwrap_or(0)))
                .then_with(|| a.name.cmp(&b.name))
        });
        agents
    }

    /// "Needs attention" in the scope, in the order of decision 3.
    pub(crate) fn attention(&self, scope: &ActivityScope, now: u64) -> Vec<Attention> {
        let mut items = Vec::new();
        for env in self.environments_in(&scope.device) {
            if let Some(last) = env.reported_at.filter(|_| env.stale(now)) {
                items.push(Attention::Silent {
                    scope: env.scope.clone(),
                    name: env.name.clone(),
                    last,
                });
            }
        }
        for found in &self.production {
            if scope.device.covers(&found.env) {
                items.push(Attention::Production(found.clone()));
            }
        }
        let agents = self.agents_in(scope);
        for agent in &agents {
            if agent.asks_often() {
                items.push(Attention::AsksOften {
                    agent: agent.name.clone(),
                    env: agent.env.clone(),
                    env_name: agent.env_name.clone(),
                    rate: agent.ask_rate_text(),
                });
            }
        }
        for agent in &agents {
            if agent.remote && agent.not_allowed > 0 {
                items.push(Attention::RemoteDenied {
                    agent: agent.name.clone(),
                    env: agent.env.clone(),
                    env_name: agent.env_name.clone(),
                    denials: agent.not_allowed,
                });
            }
        }
        items
    }

    /// The agent names of the events in the scope, for the agent menu of Logs.
    pub(crate) fn log_agents(&self, scope: &DeviceScope) -> Vec<String> {
        let mut names: Vec<String> = self
            .events
            .iter()
            .filter(|event| scope.covers(&event.env))
            .filter_map(|event| event.agent.clone())
            .collect();
        names.sort_by_key(|name| name.to_lowercase());
        names.dedup();
        names
    }
}

/// What the Overview shows instead of its numbers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OverviewEmpty {
    /// Frame 9a: no agent and no run anywhere.
    FirstRun,
    /// Frame 11b: a project without runs in the window. The newest run of the project,
    /// with its agent, when there is one.
    Project {
        project: String,
        last: Option<(u64, String)>,
    },
}

/// The empty state of the Overview, or `None` for the numbers.
pub(crate) fn overview_empty(data: &BouncerData, scope: &ActivityScope) -> Option<OverviewEmpty> {
    let totals = data.totals(&scope.device);
    let runs = totals.runs.unwrap_or(0);
    if runs > 0 {
        return None;
    }
    if let Some(project) = &scope.project {
        return Some(OverviewEmpty::Project {
            project: project.clone(),
            last: data.last_in_project.clone(),
        });
    }
    (!data.has_agents && totals.runs.is_some()).then_some(OverviewEmpty::FirstRun)
}

/// The text of the "Last run" line of frame 11b.
pub(crate) fn last_run_line(last: Option<&(u64, String)>, offset: i64) -> String {
    match last {
        Some((at, agent)) => format!("Last run {}, by {agent}.", day_month(*at, offset)),
        None => "No run used this project yet.".to_owned(),
    }
}

// ---- The cache. ----

/// The pages of the Bouncer section read this, never the vault (decision 3).
///
/// [`BouncerCache::needs_refresh`] says when to compute again: on the first frame, when
/// the project of the scope changes, when the feed poll brought changed rows, or when the
/// change stamp of the window moved — at most once per [`REFRESH_MIN`], and after
/// [`REFRESH_IDLE`] without a visible change (a run that the bouncer allowed by itself
/// changes nothing in memory).
#[derive(Debug, Default)]
pub(crate) struct BouncerCache {
    pub(crate) data: BouncerData,
    /// The window time of the last computation.
    computed_at: Option<f64>,
    /// The change stamp and the project of the last computation.
    stamp: u64,
    project: Option<String>,
    /// The feeds changed since the last computation.
    feeds_changed: bool,
    /// The newest rows of this Mac in Logs: one page more with each "Load More".
    pub(crate) log_pages: usize,
    /// How many times the data was computed (a test counts it).
    pub(crate) computations: u64,
}

impl BouncerCache {
    /// The feed poll copied changed rows.
    pub(crate) fn feeds_changed(&mut self) {
        self.feeds_changed = true;
    }

    /// Compute again in the next frame: a lock, a vault switch, "Load More".
    pub(crate) fn invalidate(&mut self) {
        self.computed_at = None;
    }

    /// Whether to compute again at `time` (window seconds) for `stamp` and `project`.
    pub(crate) fn needs_refresh(&self, time: f64, stamp: u64, project: Option<&str>) -> bool {
        let Some(at) = self.computed_at else {
            return true;
        };
        if self.project.as_deref() != project {
            return true;
        }
        let age = time - at;
        if age < 0.0 {
            return true;
        }
        age >= REFRESH_MIN && (self.feeds_changed || stamp != self.stamp || age >= REFRESH_IDLE)
    }

    /// Compute with `compute` when [`Self::needs_refresh`] says so. Returns true when
    /// it computed. The vault build splits it (`bouncer_load::refresh`), so the read can
    /// borrow the app.
    #[cfg(any(test, not(feature = "vault")))]
    pub(crate) fn refresh(
        &mut self,
        time: f64,
        stamp: u64,
        project: Option<&str>,
        compute: impl FnOnce(usize) -> BouncerData,
    ) -> bool {
        if !self.needs_refresh(time, stamp, project) {
            return false;
        }
        let data = compute(self.pages());
        self.store(time, stamp, project, data);
        true
    }

    /// The pages of this Mac's rows that Logs shows.
    pub(crate) fn pages(&self) -> usize {
        self.log_pages.max(1)
    }

    /// Keep `data`, computed at `time` for `stamp` and `project`.
    pub(crate) fn store(
        &mut self,
        time: f64,
        stamp: u64,
        project: Option<&str>,
        data: BouncerData,
    ) {
        self.data = data;
        self.computed_at = Some(time);
        self.stamp = stamp;
        self.project = project.map(str::to_owned);
        self.feeds_changed = false;
        self.computations += 1;
    }

    /// One more page of this Mac's rows in Logs.
    pub(crate) fn load_more(&mut self) {
        self.log_pages = self.pages() + 1;
        self.invalidate();
    }

    /// Forget everything: a lock or another vault.
    pub(crate) fn clear(&mut self) {
        *self = Self::default();
    }
}

/// A stamp of what the window can see change cheaply: a hash of `parts`.
pub(crate) fn stamp(parts: impl Hash) -> u64 {
    let mut hasher = DefaultHasher::new();
    parts.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
#[path = "bouncer_tests.rs"]
pub(crate) mod tests;
