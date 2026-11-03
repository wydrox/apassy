//! Tests of what Agents and the agent page show (mockup frames 2, 3, 4, 8a–8d, 9b, 11a,
//! 12, 13), from fixtures of the Bouncer data: no vault, no window. Synthetic names only.

use super::*;
use crate::desktop::ui::bouncer::tests::{LAPTOP, NOW, STUDIO};
use crate::desktop::ui::bouncer::{DayBar, EnvStats, LogKind, LogSource, NO_TOKEN_END};

fn office() -> Environment {
    Environment::this_mac("Mac mini (office)")
}

fn studio() -> Environment {
    Environment {
        scope: DeviceScope::Other(STUDIO.to_owned()),
        name: "Mac mini (studio)".to_owned(),
        reported_at: Some(NOW - 60),
        never_reported: false,
        note: None,
    }
}

fn laptop() -> Environment {
    Environment {
        scope: DeviceScope::Other(LAPTOP.to_owned()),
        name: "MacBook Pro".to_owned(),
        reported_at: Some(NOW - 2 * 86_400),
        never_reported: false,
        note: None,
    }
}

fn line(name: &str, env: &Environment, id: AgentRef, runs: u64, asked: u64, ago: u64) -> AgentLine {
    AgentLine {
        name: name.to_owned(),
        env: env.scope.clone(),
        env_name: env.name.clone(),
        runs: Some(runs),
        asked,
        last_active: Some(NOW - ago),
        projects: vec!["acme-billing".to_owned()],
        id: Some(id),
        runs_today: Some(runs / 7),
        ..AgentLine::default()
    }
}

fn other(device: &str, id: &str) -> AgentRef {
    AgentRef::Other {
        device: device.to_owned(),
        id: id.to_owned(),
    }
}

/// Frame 2: three Macs; Grok Bot remote and waiting on this Mac; one disconnected agent.
fn frame_2() -> BouncerData {
    let (o, s, l) = (office(), studio(), laptop());
    let mut data = BouncerData::default();
    data.agents = vec![
        line("Claude Code", &o, AgentRef::Local(1), 287, 17, 60),
        line("Codex", &o, AgentRef::Local(2), 98, 11, 25 * 60),
        AgentLine {
            remote: true,
            waits: true,
            projects: Vec::new(),
            connected_at: Some(NOW - 6 * 86_400),
            ..line("Grok Bot", &o, AgentRef::Local(3), 12, 12, 60)
        },
        line("Claude Code", &s, other(STUDIO, "4"), 203, 8, 60),
        line("Codex", &s, other(STUDIO, "7"), 63, 19, 3_600),
        line("Claude Code", &l, other(LAPTOP, "4"), 31, 3, 2 * 86_400),
    ];
    data.disconnected = vec![line("Old agent", &o, AgentRef::Local(9), 0, 0, 30 * 86_400)];
    data.remote_access_of
        .insert(s.scope.clone(), RemoteAccessWord::Off);
    data.stats.insert(
        o.scope.clone(),
        EnvStats {
            days: vec![DayBar::default(); 7],
            ..EnvStats::default()
        },
    );
    data.environments = vec![o, s, l];
    data.has_agents = true;
    data
}

fn all() -> ActivityScope {
    ActivityScope::default()
}

fn only(device: DeviceScope) -> ActivityScope {
    ActivityScope {
        device,
        project: None,
    }
}

#[test]
fn each_environment_has_its_own_table_this_mac_first() {
    let view = AgentsView::of(&frame_2(), &all(), None, NOW, 0);
    let names: Vec<&str> = view.sections.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(
        names,
        ["Mac mini (office)", "Mac mini (studio)", "MacBook Pro"]
    );
    let office = &view.sections[0];
    assert!(office.this_mac);
    assert_eq!(office.detail, "");
    let rows: Vec<&str> = office.rows.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(rows, ["Claude Code", "Codex", "Grok Bot"]);
    // The disconnected agent is under "Disconnected (1)", not in the table.
    assert_eq!(office.disconnected.len(), 1);
    assert_eq!(office.disconnected[0].name, "Old agent");
    // Grok Bot: remote, waits, no project, every run asks.
    let grok = &office.rows[2];
    assert!(grok.remote);
    assert_eq!(grok.status, "Waits for you");
    assert_eq!(grok.tone, Tone::Warning);
    assert_eq!(grok.projects, "—");
    assert_eq!(grok.asks, "100%");
    assert!(!grok.asks_often, "a remote agent never asks often");
    // The studio says its remote access is off and the age of its report.
    let studio = &view.sections[1];
    assert!(!studio.this_mac);
    assert_eq!(studio.detail, "Remote access off · 1 min ago");
    assert_eq!(studio.rows.len(), 2);
    assert!(studio.rows[1].asks_often, "30% of 63 runs");
    // The laptop is silent for two days: dimmed, with the day of its last report.
    let laptop = &view.sections[2];
    assert!(laptop.dimmed);
    assert!(
        laptop.detail.starts_with("Last report "),
        "{}",
        laptop.detail
    );
    assert_eq!(view.count, 6);
}

#[test]
fn one_environment_shows_its_table_only() {
    let view = AgentsView::of(
        &frame_2(),
        &only(DeviceScope::Other(STUDIO.to_owned())),
        None,
        NOW,
        0,
    );
    assert_eq!(view.sections.len(), 1);
    assert_eq!(view.sections[0].name, "Mac mini (studio)");
    assert_eq!(view.count, 2);
    // A project leaves out the agents that are not in it.
    let mut scope = all();
    scope.project = Some("shop".to_owned());
    let view = AgentsView::of(&frame_2(), &scope, None, NOW, 0);
    assert_eq!(view.count, 0);
    assert_eq!(
        view.sections[0].empty,
        Some(SectionEmpty::NoneInProject("shop".to_owned()))
    );
}

#[test]
fn a_new_vault_a_new_mac_and_a_mac_that_never_reported_have_their_empty_states() {
    // 9b: one Mac, no agent.
    let mut data = BouncerData::default();
    data.environments = vec![office()];
    let view = AgentsView::of(&data, &all(), None, NOW, 0);
    assert_eq!(view.sections[0].empty, Some(SectionEmpty::ThisMac));
    // 11a: another Mac without agents, chosen in the scope: the link to all.
    let lab = Environment {
        scope: DeviceScope::Other("lab".to_owned()),
        name: "Mac mini (lab)".to_owned(),
        reported_at: Some(NOW - 300),
        never_reported: false,
        note: None,
    };
    // 12a: a Mac of the vault that never reported.
    let home = Environment {
        scope: DeviceScope::Other("home".to_owned()),
        name: "iMac (home)".to_owned(),
        reported_at: None,
        never_reported: true,
        note: None,
    };
    data.environments = vec![office(), lab.clone(), home.clone()];
    let view = AgentsView::of(&data, &only(lab.scope.clone()), None, NOW, 0);
    assert_eq!(
        view.sections[0].empty,
        Some(SectionEmpty::OtherMac {
            name: "Mac mini (lab)".to_owned(),
            link: true
        })
    );
    let view = AgentsView::of(&data, &all(), None, NOW, 0);
    assert_eq!(
        view.sections[1].empty,
        Some(SectionEmpty::OtherMac {
            name: "Mac mini (lab)".to_owned(),
            link: false
        })
    );
    assert_eq!(view.sections[2].empty, Some(SectionEmpty::NeverReported));
    assert_eq!(view.sections[2].detail, "Never reported");
    assert!(view.sections[2].dimmed);
    // Every empty state keeps the text rules of the mockup.
    for (title, line) in [
        (
            "No agents yet",
            "Connected agents and their runs show here.",
        ),
        ("No agents yet", "Connect agents on Mac mini (lab)."),
        (
            "No report yet",
            "Turn on Show agents on my other devices on that Mac.",
        ),
        ("Choose what it can see", "It sees no credentials yet."),
    ] {
        assert!(kit::empty_text_fits(title, Some(line)), "{title} / {line}");
    }
    // A long Mac name keeps the line within 12 words.
    let long = fit_line(
        "Connect agents on the very long name of a Mac in the back office.".to_owned(),
        "Connect agents on that Mac.",
    );
    assert_eq!(long, "Connect agents on that Mac.");
}

fn access(on: bool, problem: Option<AccessProblem>) -> AccessView {
    AccessView {
        on,
        address: on.then(|| "https://mac.tail0.ts.net:8443/mcp".to_owned()),
        problem,
        no_remote_agents: false,
        reading: false,
    }
}

#[test]
fn the_problems_of_remote_access_have_one_line_and_one_button() {
    // 8a: not installed, off: the switch cannot go on.
    let a = access(false, Some(AccessProblem::NotInstalled));
    assert!(!a.switch_enabled());
    assert_eq!(
        a.problem.as_ref().unwrap().line(),
        "Tailscale is not installed."
    );
    assert_eq!(
        a.problem.as_ref().unwrap().button(),
        Some(("Get Tailscale…".to_owned(), ProblemButton::GetTailscale))
    );
    // 8b: not connected.
    let b = access(false, Some(AccessProblem::NotConnected));
    assert!(!b.switch_enabled());
    assert_eq!(
        b.problem.as_ref().unwrap().line(),
        "Tailscale is not connected."
    );
    assert_eq!(
        b.problem.as_ref().unwrap().button(),
        Some(("Check Again".to_owned(), ProblemButton::CheckAgain))
    );
    // 8c: the tailnet policy, with the link of Tailscale's message or the admin page.
    let c = AccessProblem::Policy {
        link: Some("https://login.tailscale.com/f/funnel?node=n1".to_owned()),
    };
    assert_eq!(c.line(), "Your tailnet policy blocks Funnel.");
    assert_eq!(c.tone(), Tone::Critical);
    assert_eq!(
        c.button(),
        Some((
            "Open Admin Console…".to_owned(),
            ProblemButton::AdminConsole("https://login.tailscale.com/f/funnel?node=n1".to_owned())
        ))
    );
    let plain = AccessProblem::Policy {
        link: Some("javascript:alert(1)".to_owned()),
    };
    assert_eq!(
        plain.button().map(|(_, button)| button),
        Some(ProblemButton::AdminConsole(TAILSCALE_ADMIN.to_owned()))
    );
    // 8d: the port is taken; "Use Port 10000", and nothing more on 10000.
    let d = AccessProblem::PortTaken {
        port: 8443,
        alternative: Some(10000),
    };
    assert_eq!(d.line(), "Another app uses port 8443.");
    assert_eq!(
        d.button(),
        Some(("Use Port 10000".to_owned(), ProblemButton::UsePort(10000)))
    );
    let on_10000 = AccessProblem::PortTaken {
        port: 10000,
        alternative: None,
    };
    assert_eq!(on_10000.button(), None);
    // A route that is on can always go off.
    assert!(access(true, Some(d)).switch_enabled());
    assert!(access(true, None).switch_enabled());
    // Before the first read the switch waits.
    let mut reading = access(false, None);
    reading.reading = true;
    assert!(!reading.switch_enabled());
}

#[test]
fn the_page_of_a_remote_agent_has_four_tiles_its_runs_and_what_it_sees() {
    let mut data = frame_2();
    let o = office();
    let run = |ago: u64, credential: &str, outcome: LogOutcome, command: &str| LogEvent {
        source: LogSource::Decision(ago),
        at: NOW - ago,
        env: o.scope.clone(),
        env_name: o.name.clone(),
        agent: Some("Grok Bot".to_owned()),
        remote_agent: true,
        kind: LogKind::Run,
        credential: Some(credential.to_owned()),
        production: false,
        project: String::new(),
        outcome,
        relay_run: None,
        command: command.to_owned(),
    };
    data.events = (0..7)
        .map(|n| {
            run(
                60 + n * 600,
                "GitHub token",
                LogOutcome::AllowedOn("iPhone".to_owned()),
                "",
            )
        })
        .chain([run(
            30,
            "httpbin test token",
            LogOutcome::WaitsForYou,
            "curl -H … /bearer",
        )])
        .collect();
    data.agent_answer_p50.insert(AgentRef::Local(3), 21);
    let facts = LocalFacts {
        id: 3,
        name: "Grok Bot".to_owned(),
        remote: true,
        revoked: false,
        created_at: NOW - 6 * 86_400,
        token_end: bouncer::shown_token_end(NO_TOKEN_END),
        oauth: true,
        can_see: CanSee {
            all: false,
            rows: vec![
                SeeRow {
                    item: 5,
                    name: "httpbin test token".to_owned(),
                    kind: SeeKind::Only,
                },
                SeeRow {
                    item: 6,
                    name: "Stripe live".to_owned(),
                    kind: SeeKind::Never,
                },
            ],
        },
        note: String::new(),
    };
    let page = AgentPage::of(&data, &AgentRef::Local(3), Some(&facts), NOW, 0).expect("page");
    assert!(page.remote);
    assert_eq!(page.line, "Mac mini (office) · last seen now");
    let tiles: Vec<(&str, &str)> = page
        .tiles
        .iter()
        .map(|tile| (tile.label, tile.value.as_str()))
        .collect();
    assert_eq!(
        tiles,
        [
            ("Runs", "12"),
            ("Asked you", "12"),
            ("Denied", "0"),
            ("Median answer", "21 s")
        ]
    );
    assert_eq!(page.tiles[1].share.as_deref(), Some("100%"));
    assert_eq!(page.runs.len(), RECENT_RUNS);
    assert_eq!(page.runs[0].first, "curl -H … /bearer");
    assert!(page.runs[0].mono);
    assert_eq!(page.runs[0].second, "httpbin test token · Waits for you");
    assert_eq!(page.runs[1].second, "Allowed on iPhone");
    assert!(!page.can_see.as_ref().unwrap().nothing());
    // The ⓘ: what it is, how it connected, and no end of its access: never 9999.
    assert!(
        page.help
            .iter()
            .any(|line| line.contains("MCP client on the internet"))
    );
    assert!(
        page.help
            .iter()
            .any(|line| line.ends_with("with Touch ID."))
    );
    assert!(
        page.help.iter().all(|line| !line.contains("9999")),
        "{:?}",
        page.help
    );
    assert!(!page.token_expired);
}

#[test]
fn a_new_remote_agent_sees_nothing_and_has_no_runs_yet() {
    // 13a: just connected, no credential, no run.
    let o = office();
    let mut data = BouncerData::default();
    data.environments = vec![o.clone()];
    data.agents = vec![AgentLine {
        remote: true,
        runs: Some(0),
        last_active: None,
        connected_at: Some(NOW - 60),
        projects: Vec::new(),
        ..line("Grok Bot", &o, AgentRef::Local(3), 0, 0, 0)
    }];
    let facts = LocalFacts {
        id: 3,
        name: "Grok Bot".to_owned(),
        remote: true,
        created_at: NOW - 60,
        oauth: true,
        ..LocalFacts::default()
    };
    let page = AgentPage::of(&data, &AgentRef::Local(3), Some(&facts), NOW, 0).expect("page");
    assert!(page.can_see.as_ref().unwrap().nothing());
    assert!(page.runs.is_empty());
    assert_eq!(page.line, "Mac mini (office) · connected 1 min ago");
}

#[test]
fn the_page_of_an_agent_of_another_mac_has_three_tiles_and_no_actions() {
    let data = frame_2();
    let page = AgentPage::of(&data, &other(STUDIO, "7"), None, NOW, 0).expect("page");
    assert_eq!(page.env_name, "Mac mini (studio)");
    assert_eq!(page.line, "Mac mini (studio) · 1 h ago");
    assert_eq!(page.tiles.len(), 3, "a feed has no median of an agent");
    assert_eq!(page.tiles[1].share.as_deref(), Some("30%"));
    assert!(page.can_see.is_none());
    assert_eq!(page.local_id(), None);
    // A feed of v1 has no runs of the agent: the tiles say "—".
    let mut v1 = frame_2();
    v1.agents[4].runs = None;
    let page = AgentPage::of(&v1, &other(STUDIO, "7"), None, NOW, 0).expect("page");
    assert!(page.tiles.iter().all(|tile| tile.value == "—"));
}

#[test]
fn an_agent_that_is_gone_has_no_page() {
    assert!(AgentPage::of(&frame_2(), &other(STUDIO, "99"), None, NOW, 0).is_none());
}
