//! Tests of the Bouncer data: the environments, the numbers, the attention items, the
//! filters of Logs, the relay audit rows, and the cache. Synthetic names only.

use super::*;

/// Tue 3 Nov 2026, 14:20 UTC: the "now" of the mockup.
pub(crate) const NOW: u64 = 1_793_715_600;
pub(crate) const STUDIO: &str = "6a1d3c5e-7b9f-4a2c-8e4d-1f3a5b7c9d0e";
pub(crate) const LAPTOP: &str = "0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d";

fn days(runs: [u64; 7], asked: [u64; 7]) -> Vec<DayBar> {
    runs.iter()
        .zip(asked)
        .map(|(runs, asked)| DayBar { runs: *runs, asked })
        .collect()
}

fn agent(name: &str, env: &Environment, runs: u64, asked: u64, ago: u64) -> AgentLine {
    AgentLine {
        name: name.to_owned(),
        env: env.scope.clone(),
        env_name: env.name.clone(),
        remote: false,
        runs: Some(runs),
        asked,
        not_allowed: 0,
        last_active: Some(NOW - ago),
        waits: false,
        projects: vec!["acme-billing".to_owned()],
        id: None,
        runs_today: None,
        connected_at: None,
    }
}

fn event(
    ago: u64,
    env: &Environment,
    agent: Option<&str>,
    kind: LogKind,
    outcome: LogOutcome,
    id: u64,
) -> LogEvent {
    LogEvent {
        source: LogSource::Decision(id),
        at: NOW - ago,
        env: env.scope.clone(),
        env_name: env.name.clone(),
        agent: agent.map(str::to_owned),
        remote_agent: false,
        kind,
        credential: (kind == LogKind::Run).then(|| "GitHub token".to_owned()),
        production: false,
        project: if kind == LogKind::Run {
            "acme-billing".to_owned()
        } else {
            String::new()
        },
        outcome,
        relay_run: None,
        command: String::new(),
    }
}

/// The three Macs of frame 1 with their numbers: 424 runs, 370 allowed by the bouncer
/// (87 %), 51 asked (12 %), 7 denied, a median answer of 14 s.
pub(crate) fn fixture(now_shift: u64) -> BouncerData {
    let at = |ago: u64| NOW + now_shift - ago;
    let office = Environment::this_mac("Mac mini (office)");
    let studio = Environment {
        scope: DeviceScope::Other(STUDIO.to_owned()),
        name: "Mac mini (studio)".to_owned(),
        reported_at: Some(at(120)),
        never_reported: false,
        note: None,
    };
    let laptop = Environment {
        scope: DeviceScope::Other(LAPTOP.to_owned()),
        name: "MacBook Pro".to_owned(),
        // 1 Nov, 18:40 UTC.
        reported_at: Some(1_793_558_400 + now_shift),
        never_reported: false,
        note: None,
    };
    let mut data = BouncerData::default();
    data.stats.insert(
        office.scope.clone(),
        EnvStats {
            runs: 215,
            allowed_by_bouncer: 190,
            asked: 22,
            denied: 3,
            answer_p50_secs: Some(12),
            answers: 22,
            days: days([38, 30, 31, 29, 33, 28, 26], [5, 3, 4, 2, 3, 3, 2]),
        },
    );
    data.stats.insert(
        studio.scope.clone(),
        EnvStats {
            runs: 169,
            allowed_by_bouncer: 140,
            asked: 25,
            denied: 4,
            answer_p50_secs: Some(16),
            answers: 25,
            days: days([30, 25, 22, 24, 26, 21, 21], [6, 4, 3, 3, 4, 3, 2]),
        },
    );
    data.stats.insert(
        laptop.scope.clone(),
        EnvStats {
            runs: 40,
            allowed_by_bouncer: 40,
            asked: 4,
            denied: 0,
            answer_p50_secs: Some(14),
            answers: 4,
            days: days([0, 0, 8, 7, 9, 8, 8], [0, 0, 1, 1, 1, 0, 1]),
        },
    );
    let shift = |mut line: AgentLine| {
        line.last_active = line.last_active.map(|at| at + now_shift);
        line
    };
    data.agents = vec![
        shift(agent("Claude Code", &office, 142, 9, 120)),
        shift(agent("Codex", &office, 61, 7, 25 * 60)),
        shift(AgentLine {
            remote: true,
            waits: true,
            not_allowed: 2,
            ..agent("Grok Bot", &office, 12, 12, 60)
        }),
        shift(agent("Claude Code", &studio, 98, 4, 300)),
        shift(agent("Codex", &studio, 44, 13, 3_600)),
        shift(agent("T3 Code", &studio, 27, 2, 3 * 3_600)),
        shift(agent("Claude Code", &laptop, 31, 3, 44 * 3_600)),
        shift(agent("Codex", &laptop, 9, 1, 3 * 86_400)),
    ];
    data.has_agents = true;
    data.production = vec![ProductionUse {
        credential: "Stripe live".to_owned(),
        agent: "Claude Code".to_owned(),
        env: DeviceScope::ThisMac,
        env_name: office.name.clone(),
        times: 3,
    }];
    let mut cloud = event(
        8 * 60,
        &office,
        Some("Grok Bot"),
        LogKind::Run,
        LogOutcome::AllowedOn("iPhone".to_owned()),
        3,
    );
    cloud.remote_agent = true;
    cloud.relay_run = Some(41);
    cloud.command = "gh api repos/acme/billing/issues --paginate".to_owned();
    data.events = vec![
        event(
            6 * 60,
            &studio,
            Some("Claude Code"),
            LogKind::Run,
            LogOutcome::AllowedByBouncer,
            1,
        ),
        cloud,
        event(
            62 * 60,
            &studio,
            Some("Codex"),
            LogKind::Run,
            LogOutcome::DeniedByYou,
            4,
        ),
        event(
            75 * 60,
            &office,
            None,
            LogKind::RemoteAccessOn,
            LogOutcome::ByYou,
            5,
        ),
        event(
            80 * 60,
            &office,
            Some("Grok Bot"),
            LogKind::Connect,
            LogOutcome::AllowedByYou,
            6,
        ),
    ];
    for event in &mut data.events {
        event.at += now_shift;
    }
    data.environments = vec![office, studio, laptop];
    data.projects = vec!["acme-billing".to_owned()];
    data.remote_access_on = true;
    data
}

#[test]
fn the_totals_of_all_environments_equal_the_fixture() {
    let data = fixture(0);
    let totals = data.totals(&DeviceScope::All);
    assert_eq!(totals.runs, Some(424));
    assert_eq!(totals.allowed_by_bouncer, 370);
    assert_eq!(totals.asked, 51);
    assert_eq!(totals.denied, 7);
    assert_eq!(
        totals.share(totals.allowed_by_bouncer).as_deref(),
        Some("87%")
    );
    assert_eq!(totals.share(totals.asked).as_deref(), Some("12%"));
    // 12 s (22 answers), 14 s (4), 16 s (25): half of 51 answers falls on 14 s.
    assert_eq!(totals.answer_p50_secs, Some(14));
    assert_eq!(totals.median_text(), "14 s");
    assert_eq!(
        totals.days[0],
        DayBar {
            runs: 68,
            asked: 11
        }
    );
    assert_eq!(
        totals.days.iter().map(|day| day.runs).sum::<u64>(),
        424,
        "the bars add up to the runs"
    );
    assert!(!totals.partial);
    // One Mac in the scope: its own numbers.
    let studio = data.totals(&DeviceScope::Other(STUDIO.to_owned()));
    assert_eq!(studio.runs, Some(169));
    assert_eq!(studio.answer_p50_secs, Some(16));
}

/// A feed of v1 has no days: its numbers show "—" and the totals say they are partial.
#[test]
fn a_mac_without_numbers_shows_a_dash_and_makes_the_totals_partial() {
    let mut data = fixture(0);
    data.stats
        .insert(DeviceScope::Other(LAPTOP.to_owned()), EnvStats::default());
    let totals = data.totals(&DeviceScope::All);
    assert_eq!(totals.runs, Some(384));
    assert!(totals.partial);
    let laptop = data.totals(&DeviceScope::Other(LAPTOP.to_owned()));
    assert_eq!(laptop.runs, None, "no numbers: —");
    assert_eq!(laptop.median_text(), "—");
}

#[test]
fn attention_lists_a_silent_mac_then_production_then_an_agent_that_asks_often() {
    // Frame 1: a remote agent with denials (Grok Bot, 2) is not an attention item.
    let data = fixture(0);
    let items = data.attention(&ActivityScope::default(), NOW);
    let titles: Vec<String> = items.iter().map(Attention::title).collect();
    assert_eq!(
        titles,
        [
            "MacBook Pro not reporting",
            "Stripe live used 3 times",
            "Codex asks often",
        ]
    );
    assert_eq!(items[0].detail(0), "Last report 1 Nov, 18:40");
    assert_eq!(items[2].detail(0), "Mac mini (studio) · 30% of runs");
    assert_eq!(items[0].severity(), Severity::Off);
    assert_eq!(items[1].severity(), Severity::Critical);
    // A remote agent asks you on every run: never "asks often".
    assert!(!data.agents[2].asks_often());
    // This Mac only: no silent Mac, no agent of the studio.
    let here = data.attention(
        &ActivityScope {
            device: DeviceScope::ThisMac,
            project: None,
        },
        NOW,
    );
    let titles: Vec<String> = here.iter().map(Attention::title).collect();
    assert_eq!(titles, ["Stripe live used 3 times"]);
}

#[test]
fn an_agent_asks_often_from_a_quarter_of_ten_runs() {
    let env = Environment::this_mac("Here");
    assert!(agent("A", &env, 10, 3, 0).asks_often());
    assert!(!agent("A", &env, 10, 2, 0).asks_often(), "20 %");
    assert!(
        !agent("A", &env, 9, 9, 0).asks_often(),
        "fewer than 10 runs"
    );
    assert_eq!(agent("A", &env, 44, 13, 0).ask_rate_text(), "30%");
    assert_eq!(
        AgentLine {
            runs: None,
            ..agent("A", &env, 0, 0, 0)
        }
        .ask_rate_text(),
        "—"
    );
}

#[test]
fn the_status_of_an_agent_reads_as_the_mockup() {
    let env = Environment::this_mac("Here");
    let line = |ago| agent("A", &env, 1, 0, ago);
    assert_eq!(line(120).status_text(NOW, 0), "Active now");
    assert_eq!(line(25 * 60).status_text(NOW, 0), "25 min ago");
    assert_eq!(line(3 * 3_600).status_text(NOW, 0), "3 h ago");
    assert_eq!(line(2 * 86_400).status_text(NOW, 0), "1 Nov");
    let waiting = AgentLine {
        waits: true,
        ..line(2 * 86_400)
    };
    assert_eq!(waiting.status_text(NOW, 0), "Waits for you");
}

#[test]
fn the_environments_sort_this_mac_first_and_never_reported_last() {
    let never = |name: &str| Environment {
        scope: DeviceScope::Other(name.to_owned()),
        name: name.to_owned(),
        reported_at: None,
        never_reported: true,
        note: None,
    };
    let reported = |name: &str| Environment {
        reported_at: Some(NOW),
        never_reported: false,
        ..never(name)
    };
    let mut envs = vec![
        never("Attic iMac"),
        reported("Studio"),
        Environment::this_mac("Office"),
        reported("Basement"),
    ];
    sort_environments(&mut envs);
    let names: Vec<&str> = envs.iter().map(|env| env.name.as_str()).collect();
    assert_eq!(names, ["Office", "Basement", "Studio", "Attic iMac"]);
    assert!(envs[3].dimmed(NOW));
    assert!(!envs[1].dimmed(NOW));
    assert!(envs[1].dimmed(NOW + STALE_AFTER + 1), "silent for 24 hours");
    assert_eq!(envs[3].menu_detail(NOW, 0), "Never reported");
    assert_eq!(envs[1].menu_detail(NOW + 300, 0), "5 min ago");
    // Later the same day: the time of the report.
    assert_eq!(envs[1].menu_detail(NOW + 3 * 3_600, 0), "14:20");
    assert_eq!(envs[1].menu_detail(NOW + 2 * 86_400, 0), "3 Nov");
}

#[test]
fn local_time_reads_as_clock_day_and_weekday() {
    assert_eq!(clock(NOW, 0), "14:20");
    assert_eq!(clock(NOW, 3_600), "15:20");
    assert_eq!(clock_seconds(NOW + 8, 0), "14:20:08");
    assert_eq!(day_month(NOW, 0), "3 Nov");
    assert_eq!(
        day_month(NOW, 10 * 3_600),
        "4 Nov",
        "past midnight in UTC+10"
    );
    assert_eq!(weekday(NOW, 0), "Tue");
    assert_eq!(day_month(0, 0), "1 Jan");
    assert_eq!(days_ago(NOW - 86_400, NOW, 0), 1);
    assert_eq!(days_ago(NOW + 600, NOW, 0), 0, "a clock ahead is today");
    assert_eq!(day_title(NOW - 3_600, NOW, 0), "Today");
    assert_eq!(day_title(NOW - 86_400, NOW, 0), "Yesterday");
    assert_eq!(day_title(NOW - 2 * 86_400, NOW, 0), "1 Nov");
}

#[test]
fn the_outcome_words_are_those_of_the_mockup() {
    let of = LogOutcome::of_decision;
    assert_eq!(of(true, "model", "").text(), "Allowed by bouncer");
    assert_eq!(of(true, "rule", "").text(), "Allowed by bouncer");
    assert_eq!(of(true, "owner", "").text(), "Allowed by you");
    assert_eq!(of(true, "owner", "iPhone").text(), "Allowed on iPhone");
    assert_eq!(of(false, "owner", "").text(), "Denied by you");
    assert_eq!(of(false, "owner", "iPhone").text(), "Denied on iPhone");
    assert_eq!(of(false, "rule", "").text(), "Denied by bouncer");
    assert_eq!(of(false, "no_answer", "").text(), "No answer");
    assert_eq!(of(false, "timed_out", "").text(), "No answer");
    assert!(of(false, "rule", "").denied());
    assert!(!of(true, "owner", "").denied());
    assert!(!LogOutcome::WaitsForYou.denied());
}

#[test]
fn the_log_filters_pick_runs_connections_denials_an_agent_and_text() {
    let data = fixture(0);
    let all = ActivityScope::default();
    let keys = |filter: &LogFilter, scope: &ActivityScope| -> Vec<LogSource> {
        filter_events(&data.events, scope, filter)
            .into_iter()
            .map(|event| event.source.clone())
            .collect()
    };
    let filter = |kind| LogFilter {
        kind,
        ..LogFilter::default()
    };
    assert_eq!(keys(&LogFilter::default(), &all).len(), 5);
    assert_eq!(
        keys(&filter(LogKindFilter::Runs), &all),
        [
            LogSource::Decision(1),
            LogSource::Decision(3),
            LogSource::Decision(4)
        ]
    );
    assert_eq!(
        keys(&filter(LogKindFilter::Connections), &all),
        [LogSource::Decision(5), LogSource::Decision(6)]
    );
    assert_eq!(
        keys(&filter(LogKindFilter::Denied), &all),
        [LogSource::Decision(4)]
    );
    let grok = LogFilter {
        agent: Some("Grok Bot".to_owned()),
        ..LogFilter::default()
    };
    assert_eq!(
        keys(&grok, &all),
        [LogSource::Decision(3), LogSource::Decision(6)]
    );
    let text = LogFilter {
        text: "  ISSUES ".to_owned(),
        ..LogFilter::default()
    };
    assert_eq!(keys(&text, &all), [LogSource::Decision(3)], "the command");
    let none = LogFilter {
        text: "delete".to_owned(),
        ..grok.clone()
    };
    assert!(keys(&none, &all).is_empty());
    assert!(none.is_set());
    assert!(!LogFilter::default().is_set());
    // The scope: one Mac, and a project (connections have none and stay).
    let studio = ActivityScope {
        device: DeviceScope::Other(STUDIO.to_owned()),
        project: None,
    };
    assert_eq!(
        keys(&LogFilter::default(), &studio),
        [LogSource::Decision(1), LogSource::Decision(4)]
    );
    let other_project = ActivityScope {
        device: DeviceScope::All,
        project: Some("shop".to_owned()),
    };
    assert_eq!(
        keys(&LogFilter::default(), &other_project),
        [LogSource::Decision(5), LogSource::Decision(6)]
    );
    assert_eq!(
        data.log_agents(&DeviceScope::All),
        ["Claude Code", "Codex", "Grok Bot"]
    );
}

#[test]
fn a_cloud_run_of_this_mac_opens_and_other_rows_do_not() {
    let data = fixture(0);
    let cloud = &data.events[1];
    assert!(cloud.expandable());
    assert!(!data.events[3].expandable(), "remote access on");
    assert_ne!(cloud.key(), data.events[0].key());
    assert_eq!(cloud.key(), data.events[1].clone().key(), "a steady key");
}

/// The audit row of a proxied request gives time, method, host, and status. The path,
/// the headers, and the variables stay unread.
#[test]
fn a_proxied_request_shows_method_host_and_status_never_the_path() {
    let detail = r#"{"session_id":"s-1","run_id":41,"agent_id":3,"at":1793715128,
        "method":"GET","host":"api.github.com","path":"/repos/acme/billing/SECRET-PATH",
        "status":200,"outcome":"forwarded","code":null,"swapped":["GITHUB_TOKEN"]}"#;
    let row = ProxyRow::from_audit(detail).expect("a row");
    assert_eq!(row.at, 1_793_715_128);
    assert_eq!(row.method, "GET");
    assert_eq!(row.host, "api.github.com");
    assert_eq!(row.result, "200");
    assert!(!row.refused);
    let shown = format!("{row:?}");
    for hidden in ["SECRET-PATH", "repos", "GITHUB_TOKEN", "s-1"] {
        assert!(!shown.contains(hidden), "{hidden} in {shown}");
    }
    let refused = ProxyRow::from_audit(
        r#"{"at":1,"method":"GET","host":"uploads.example.net","path":null,
            "status":403,"outcome":"refused","code":"wrong_host"}"#,
    )
    .expect("a row");
    assert_eq!(refused.result, "Refused: wrong host");
    assert!(refused.refused);
    let failed = ProxyRow::from_audit(
        r#"{"at":1,"method":"POST","host":"a.example","status":502,"outcome":"upstream_failed"}"#,
    )
    .expect("a row");
    assert_eq!(failed.result, "Host failed");
    assert!(ProxyRow::from_audit("not json").is_none());
    assert!(ProxyRow::from_audit(r#"{"at":1}"#).is_none());
}

#[test]
fn the_overview_is_empty_on_a_first_run_and_for_a_project_without_runs() {
    let mut first = BouncerData {
        environments: vec![Environment::this_mac("Office")],
        ..BouncerData::default()
    };
    first.stats.insert(
        DeviceScope::ThisMac,
        EnvStats {
            days: vec![DayBar::default(); 7],
            ..EnvStats::default()
        },
    );
    assert_eq!(
        overview_empty(&first, &ActivityScope::default()),
        Some(OverviewEmpty::FirstRun)
    );
    first.has_agents = true;
    assert_eq!(overview_empty(&first, &ActivityScope::default()), None);
    first.last_in_project = Some((NOW - 13 * 86_400, "Codex".to_owned()));
    let project = ActivityScope {
        device: DeviceScope::All,
        project: Some("billing-v2".to_owned()),
    };
    let Some(OverviewEmpty::Project { project, last }) = overview_empty(&first, &project) else {
        panic!("a project without runs");
    };
    assert_eq!(project, "billing-v2");
    assert_eq!(
        last_run_line(last.as_ref(), 0),
        "Last run 21 Oct, by Codex."
    );
    assert_eq!(last_run_line(None, 0), "No run used this project yet.");
    assert_eq!(overview_empty(&fixture(0), &ActivityScope::default()), None);
}

/// The empty states keep the text rules of the mockup.
#[test]
fn every_empty_state_keeps_the_text_rules() {
    use crate::desktop::ui::kit::empty_text_fits;
    for (title, line) in [
        (
            "No runs yet",
            Some("Connect an agent to see its runs here."),
        ),
        ("No runs in billing-v2", Some("Last run 21 Oct, by Codex.")),
        ("No activity yet", None),
        ("No matches", None),
    ] {
        assert!(empty_text_fits(title, line), "{title}");
    }
    assert!(!empty_text_fits("one two three four five six", None));
}

/// The cache computes once, then again only when something moved and 2 seconds passed;
/// a frame without a change reads nothing.
#[test]
fn the_cache_computes_at_most_every_two_seconds_and_only_on_a_change() {
    let mut cache = BouncerCache::default();
    let reads = std::cell::Cell::new(0);
    let frame = |cache: &mut BouncerCache, time: f64, stamp: u64, project: Option<&str>| {
        cache.refresh(time, stamp, project, |_| {
            reads.set(reads.get() + 1);
            BouncerData::default()
        })
    };
    assert!(frame(&mut cache, 0.0, 1, None), "the first frame");
    // 60 frames in one second: no read.
    for step in 1..60 {
        assert!(!frame(&mut cache, f64::from(step) / 60.0, 1, None));
    }
    assert!(
        !frame(&mut cache, 1.5, 2, None),
        "a change within 2 seconds waits"
    );
    assert!(frame(&mut cache, 2.1, 2, None), "then it reads");
    assert!(!frame(&mut cache, 4.5, 2, None), "nothing moved");
    cache.feeds_changed();
    assert!(frame(&mut cache, 4.6, 2, None), "the feed poll saw changes");
    assert!(
        frame(&mut cache, 4.7, 2, Some("shop")),
        "a project reads at once"
    );
    assert!(!frame(&mut cache, 14.0, 2, Some("shop")));
    assert!(
        frame(&mut cache, 14.8, 2, Some("shop")),
        "after 10 idle seconds"
    );
    cache.load_more();
    assert_eq!(cache.pages(), 2);
    assert!(frame(&mut cache, 14.9, 2, Some("shop")), "Load More");
    assert_eq!(reads.get(), 6);
    assert_eq!(cache.computations, 6);
    cache.clear();
    assert_eq!(cache.computations, 0);
    assert_eq!(cache.pages(), 1);
}

#[test]
fn a_long_or_odd_name_is_cut_and_cleaned() {
    assert_eq!(clip("  Mac\u{7}mini  "), "Mac?mini");
    let long = "x".repeat(60);
    assert_eq!(clip(&long).chars().count(), 40);
    assert!(clip(&long).ends_with('…'));
    assert_eq!(Environment::this_mac("  ").name, "This Mac");
}

#[test]
fn a_duration_reads_in_seconds_minutes_or_hours() {
    assert_eq!(duration_text(14), "14 s");
    assert_eq!(duration_text(119), "119 s");
    assert_eq!(duration_text(240), "4 min");
    assert_eq!(duration_text(3 * 3_600), "3 h");
}
