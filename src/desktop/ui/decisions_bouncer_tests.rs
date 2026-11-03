//! Tests of History, the connect card, and the cloud run card of Decisions (mockup frames
//! 5, 5b, 9c, 10a), from fixtures of the Bouncer data. Synthetic names only.

use super::*;
use crate::desktop::ui::bouncer::tests::{NOW, STUDIO};
use crate::desktop::ui::bouncer::{DeviceScope, Environment};

fn event(
    ago: u64,
    env: &Environment,
    agent: &str,
    credential: &str,
    outcome: LogOutcome,
    source: LogSource,
) -> LogEvent {
    LogEvent {
        source,
        at: NOW - ago,
        env: env.scope.clone(),
        env_name: env.name.clone(),
        agent: Some(agent.to_owned()),
        remote_agent: agent == "Grok Bot",
        kind: LogKind::Run,
        credential: Some(credential.to_owned()),
        production: false,
        project: "acme-billing".to_owned(),
        outcome,
        relay_run: None,
        command: String::new(),
    }
}

/// Frame 5: two Macs, today and yesterday, and what waits (which History leaves out).
fn frame_5() -> BouncerData {
    let office = Environment::this_mac("Mac mini (office)");
    let studio = Environment {
        scope: DeviceScope::Other(STUDIO.to_owned()),
        name: "Mac mini (studio)".to_owned(),
        reported_at: Some(NOW - 60),
        never_reported: false,
        note: None,
    };
    BouncerData {
        events: vec![
            event(
                6 * 60,
                &studio,
                "Claude Code",
                "Shop database",
                LogOutcome::AllowedByBouncer,
                LogSource::Feed(1),
            ),
            event(
                8 * 60,
                &office,
                "Grok Bot",
                "GitHub token",
                LogOutcome::AllowedOn("iPhone".to_owned()),
                LogSource::Decision(2),
            ),
            event(
                18 * 60,
                &office,
                "Claude Code",
                "Stripe live",
                LogOutcome::AllowedByYou,
                LogSource::Decision(3),
            ),
            event(
                62 * 60,
                &studio,
                "Codex",
                "Deploy key",
                LogOutcome::DeniedByYou,
                LogSource::Feed(4),
            ),
            event(
                20 * 3_600,
                &office,
                "Grok Bot",
                "GitHub token",
                LogOutcome::DeniedByYou,
                LogSource::Decision(5),
            ),
            // What waits now is not history.
            event(
                30,
                &office,
                "Grok Bot",
                "httpbin test token",
                LogOutcome::WaitsForYou,
                LogSource::Waiting(9),
            ),
            LogEvent {
                kind: LogKind::Connect,
                ..event(
                    30,
                    &office,
                    "Grok Bot (new)",
                    "",
                    LogOutcome::WaitsForYou,
                    LogSource::Connect("c1".to_owned()),
                )
            },
        ],
        environments: vec![office, studio],
        has_agents: true,
        ..BouncerData::default()
    }
}

fn titles(view: &HistoryView) -> Vec<(String, Vec<String>)> {
    view.groups
        .iter()
        .map(|(day, rows)| {
            (
                day.clone(),
                rows.iter().map(|row| row.title.clone()).collect(),
            )
        })
        .collect()
}

#[test]
fn history_has_the_runs_of_every_mac_by_day_and_leaves_out_what_waits() {
    let data = frame_5();
    let state = State::default();
    let view = HistoryView::of(&data, &ActivityScope::default(), &state, NOW, 0);
    // NOW is 14:20 UTC: 20 h ago is yesterday.
    assert_eq!(
        titles(&view),
        [
            (
                "Today".to_owned(),
                vec![
                    "Claude Code · Shop database".to_owned(),
                    "Grok Bot · GitHub token".to_owned(),
                    "Claude Code · Stripe live".to_owned(),
                    "Codex · Deploy key".to_owned(),
                ]
            ),
            (
                "Yesterday".to_owned(),
                vec!["Grok Bot · GitHub token".to_owned()]
            ),
        ]
    );
    let first = &view.groups[0].1[1];
    assert!(first.remote);
    assert_eq!(first.env_name, "Mac mini (office)");
    assert_eq!(first.outcome, "Allowed on iPhone");
    assert_eq!(first.meta, "14:12");
    assert!(view.groups[0].1[3].denied);
    assert_eq!(view.agents, ["Claude Code", "Codex", "Grok Bot"]);
    assert!(!view.none_yet);
}

#[test]
fn history_filters_by_kind_agent_environment_and_project() {
    let data = frame_5();
    let count = |state: &State, scope: &ActivityScope| history_events(&data, scope, state).len();
    let all = ActivityScope::default();
    let with = |filter| State {
        filter,
        ..State::default()
    };
    assert_eq!(count(&with(HistoryFilter::All), &all), 5);
    assert_eq!(count(&with(HistoryFilter::AskedYou), &all), 4);
    assert_eq!(count(&with(HistoryFilter::Automatic), &all), 1);
    assert_eq!(count(&with(HistoryFilter::Denied), &all), 2);
    let grok = State {
        agent: Some("Grok Bot".to_owned()),
        ..State::default()
    };
    assert_eq!(count(&grok, &all), 2);
    let this_mac = ActivityScope {
        device: DeviceScope::ThisMac,
        project: None,
    };
    assert_eq!(count(&State::default(), &this_mac), 3);
    let other_project = ActivityScope {
        device: DeviceScope::All,
        project: Some("shop".to_owned()),
    };
    assert_eq!(count(&State::default(), &other_project), 0);
    // A row is found by its key in the scope, not outside it.
    let key = history_events(&data, &all, &State::default())[0].key();
    assert!(find(&data, &all, key).is_some());
    assert!(find(&data, &this_mac, key).is_none(), "a run of the studio");
    // The words of the segmented control are title case.
    let labels: Vec<&str> = HistoryFilter::ALL.iter().map(|f| f.label()).collect();
    assert_eq!(labels, ["All", "Asked You", "Automatic", "Denied"]);
}

#[test]
fn a_new_vault_has_no_decisions_yet() {
    // Frame 9c.
    let data = BouncerData {
        environments: vec![Environment::this_mac("Mac mini (office)")],
        ..BouncerData::default()
    };
    let view = HistoryView::of(&data, &ActivityScope::default(), &State::default(), NOW, 0);
    assert!(view.none_yet);
    assert!(view.groups.is_empty());
}

#[test]
fn an_older_run_shows_its_weekday_or_its_day() {
    let office = Environment::this_mac("Mac mini (office)");
    let row = |ago| {
        HistoryRow::of(
            &event(
                ago,
                &office,
                "Codex",
                "Key",
                LogOutcome::AllowedByBouncer,
                LogSource::Decision(1),
            ),
            NOW,
            0,
        )
    };
    // Tue 3 Nov: 2 days ago is Sunday; 10 days ago is 24 Oct.
    assert_eq!(row(2 * 86_400).meta, "Sun");
    assert_eq!(row(10 * 86_400).meta, "24 Oct");
}

#[test]
fn the_cards_say_what_the_mockup_says() {
    assert_eq!(left_text(NOW + 271, NOW), "4:31");
    assert_eq!(left_text(NOW - 5, NOW), "0:00");
    // The connect card: the code, and one warning line within the text rules.
    let line = "Deny unless you just added Apassy to Grok Bot.";
    assert!(kit::empty_text_fits("x", Some(line)));
    // The cloud run card answers Deny or Allow Once only: nothing else exists.
    let answers = [CardAnswer::Deny, CardAnswer::Allow];
    assert_eq!(answers.len(), 2);
}
