//! Learning view (ADR 0009, goal item B10): the ask rate over time, the automatic
//! decisions, the remembered patterns, the threshold calibration, and the slot for the
//! agreement of a candidate model.
//!
//! The view reads the vault and calls the broker learning functions. Nothing here
//! changes the active policy without an owner action.

use eframe::egui::{self, RichText};

use super::DesktopApp;
use super::ui::{INK_MUTED, heading};

pub(crate) fn draw(app: &mut DesktopApp, ui: &mut egui::Ui) {
    heading(ui, "Learning");
    ui.label(
        RichText::new(
            "Apassy learns from your decisions. A remembered pattern and a calibrated level act only at the model step. They never change the hard rules, the production rule, or a rule flag.",
        )
        .color(INK_MUTED),
    );
    ui.add_space(8.0);
    #[cfg(feature = "vault")]
    vault_view::draw(app, ui);
    #[cfg(not(feature = "vault"))]
    {
        let _ = app;
        ui.label(
            RichText::new("Learning needs the vault build. The demo has no decision log.")
                .color(INK_MUTED),
        );
    }
}

#[cfg(feature = "vault")]
/// Text for the candidate model card. `None` until a later phase trains a candidate.
pub(crate) fn candidate_lines(candidate: Option<&CandidateView>) -> Vec<String> {
    let Some(candidate) = candidate else {
        return vec![
            "No candidate model.".to_owned(),
            "A later version trains a candidate model on this computer. It decides in shadow mode, with no effect. This card then shows its agreement with your decisions. You promote it by hand after 100 shadow decisions with 95% agreement and no allowed denial.".to_owned(),
        ];
    };
    vec![
        format!(
            "Candidate {}: {} shadow decisions, agreement {}.",
            candidate.model_version,
            candidate.shadow_decisions,
            candidate
                .agreement
                .map_or_else(|| "none yet".to_owned(), |a| format!("{:.0}%", a * 100.0))
        ),
        format!(
            "Denials that the candidate would allow: {}. {}",
            candidate.allowed_owner_denials,
            if candidate.can_promote {
                "You can promote it."
            } else {
                "It cannot be promoted yet."
            }
        ),
    ]
}

#[cfg(feature = "vault")]
/// What the candidate card shows. It comes from `vault::CandidateAgreement`.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CandidateView {
    pub model_version: String,
    pub shadow_decisions: u32,
    pub agreement: Option<f64>,
    pub allowed_owner_denials: u32,
    pub can_promote: bool,
}

#[cfg(feature = "vault")]
fn draw_candidate(ui: &mut egui::Ui, candidate: Option<&CandidateView>) {
    super::ui::card_frame().show(ui, |ui| {
        ui.label(
            RichText::new("Candidate model")
                .size(16.0)
                .strong()
                .color(super::ui::INK),
        );
        for line in candidate_lines(candidate) {
            ui.label(RichText::new(line).color(INK_MUTED));
        }
    });
}

#[cfg(feature = "vault")]
mod vault_view {
    use std::collections::BTreeMap;
    use std::sync::PoisonError;

    use eframe::egui::{self, RichText};

    use super::super::ui::{
        ALLOW, ASK, DENY, INK, INK_MUTED, accent_button, card_frame, danger_button, property_grid,
    };
    use super::{CandidateView, DesktopApp, draw_candidate};
    use crate::broker::approvals::{OwnerAction, OwnerProof};
    use crate::broker::bouncer::{MIN_CONFIDENCE, Thresholds};
    use crate::broker::calibration::{self, Proposal};
    use crate::broker::learning;
    use crate::desktop::owner_check::OwnerRequest;
    use crate::vault::{
        CalibrationRecord, CandidateAgreement, DayRate, DecidedBy, DecisionRecord, PatternRecord,
        PatternState, format_utc,
    };

    const DAY: u64 = 86_400;
    /// Days in the ask rate table.
    const DAYS_SHOWN: u64 = 14;
    const AUTOMATIC_SHOWN: usize = 25;

    /// Learning view state.
    #[derive(Debug, Default)]
    pub(crate) struct LearningUiState {
        /// The automatic decision that the owner inspects.
        pub(crate) inspected: Option<u64>,
        /// The last computed calibration proposal. It changes nothing until the owner
        /// applies it.
        pub(crate) proposal: Option<Proposal>,
    }

    struct Loaded {
        days: Vec<DayRate>,
        automatic: Vec<DecisionRecord>,
        inspected: Option<DecisionRecord>,
        patterns: Vec<PatternRecord>,
        calibration: Option<CalibrationRecord>,
        agents: BTreeMap<u64, String>,
        /// Shadow mode comes in a later phase (goal item B9).
        candidate: Option<CandidateAgreement>,
    }

    fn load(app: &DesktopApp, now: u64) -> Option<Result<Loaded, String>> {
        let shared = app.owner_ui.session.shared_vault();
        let guard = shared.lock().unwrap_or_else(PoisonError::into_inner);
        let vault = guard.as_ref().filter(|vault| !vault.is_locked())?;
        let since = (now / DAY).saturating_sub(DAYS_SHOWN - 1) * DAY;
        let result = (|| {
            Ok(Loaded {
                days: vault.ask_rate_by_day(since)?,
                automatic: vault.automatic_decisions(AUTOMATIC_SHOWN)?,
                inspected: match app.learning.inspected {
                    Some(id) => vault.decision(id)?,
                    None => None,
                },
                patterns: vault.patterns()?,
                calibration: vault.calibration()?,
                agents: vault
                    .list_agents()?
                    .into_iter()
                    .map(|agent| (agent.id, agent.name))
                    .collect(),
                candidate: None,
            })
        })();
        Some(result.map_err(|_: crate::vault::VaultError| {
            "The vault did not return the learning data.".to_owned()
        }))
    }

    pub(super) fn draw(app: &mut DesktopApp, ui: &mut egui::Ui) {
        let now = learning::now();
        let loaded = match load(app, now) {
            None => {
                ui.label(RichText::new("Unlock the vault to see learning.").color(INK_MUTED));
                return;
            }
            Some(Err(message)) => {
                ui.label(RichText::new(message).color(DENY));
                return;
            }
            Some(Ok(loaded)) => loaded,
        };
        draw_ask_rate(ui, &loaded.days);
        ui.add_space(8.0);
        draw_automatic(app, ui, &loaded);
        ui.add_space(8.0);
        draw_patterns(app, ui, &loaded, now);
        ui.add_space(8.0);
        draw_calibration(app, ui, loaded.calibration.as_ref(), now);
        ui.add_space(8.0);
        let candidate = loaded.candidate.as_ref().map(|candidate| CandidateView {
            model_version: candidate.model_version.clone(),
            shadow_decisions: candidate.shadow_decisions,
            agreement: candidate.agreement(),
            allowed_owner_denials: candidate.allowed_owner_denials,
            can_promote: candidate.can_promote(),
        });
        draw_candidate(ui, candidate.as_ref());
    }

    fn title(ui: &mut egui::Ui, text: &str) {
        ui.label(RichText::new(text).size(16.0).strong().color(INK));
    }

    fn draw_ask_rate(ui: &mut egui::Ui, days: &[DayRate]) {
        card_frame().show(ui, |ui| {
            title(ui, "Ask rate over time");
            ui.label(
                RichText::new(
                    "Share of requests that waited for you, per UTC day, for the last 14 days. Requests that a hard rule denied do not count.",
                )
                .color(INK_MUTED),
            );
            if days.is_empty() {
                ui.label(RichText::new("No decisions yet.").color(INK_MUTED));
                return;
            }
            egui::Grid::new("learning-ask-rate")
                .striped(true)
                .num_columns(6)
                .show(ui, |ui| {
                    for name in ["Day", "Requests", "Asked", "Model", "Pattern", "Ask rate"] {
                        ui.label(RichText::new(name).strong().color(INK));
                    }
                    ui.end_row();
                    for day in days {
                        let date = format_utc(day.day);
                        ui.label(date.split(' ').next().unwrap_or_default());
                        ui.label(day.decisions.to_string());
                        ui.label(day.asked.to_string());
                        ui.label(day.by_model.to_string());
                        ui.label(day.by_pattern.to_string());
                        ui.add(
                            egui::ProgressBar::new(day.ask_rate() as f32)
                                .desired_width(160.0)
                                .text(format!("{:.0}%", day.ask_rate() * 100.0)),
                        );
                        ui.end_row();
                    }
                });
        });
    }

    fn short(command: &[String]) -> String {
        let mut text = command.join(" ");
        if text.chars().count() > 80 {
            text = text.chars().take(77).collect::<String>() + "...";
        }
        text
    }

    fn draw_automatic(app: &mut DesktopApp, ui: &mut egui::Ui, loaded: &Loaded) {
        card_frame().show(ui, |ui| {
            title(ui, "Automatic decisions");
            ui.label(
                RichText::new(
                    "Runs that started without you: the model allowed them, or a remembered pattern did. Inspect a run to see what Apassy knew.",
                )
                .color(INK_MUTED),
            );
            if loaded.automatic.is_empty() {
                ui.label(RichText::new("No automatic decision yet.").color(INK_MUTED));
            } else {
                egui::Grid::new("learning-automatic")
                    .striped(true)
                    .num_columns(5)
                    .show(ui, |ui| {
                        for name in ["Time", "Agent", "By", "Command", ""] {
                            ui.label(RichText::new(name).strong().color(INK));
                        }
                        ui.end_row();
                        for record in &loaded.automatic {
                            let entry = &record.entry;
                            ui.label(RichText::new(format_utc(entry.at)).color(INK_MUTED));
                            ui.label(&entry.agent_name);
                            let by = if entry.decided_by == DecidedBy::Pattern {
                                "Pattern"
                            } else {
                                "Model"
                            };
                            ui.label(RichText::new(by).color(ALLOW));
                            ui.label(RichText::new(short(&entry.command)).monospace());
                            if ui.button("Inspect").clicked() {
                                app.learning.inspected = Some(record.id);
                            }
                            ui.end_row();
                        }
                    });
            }
            if let Some(record) = &loaded.inspected {
                ui.add_space(8.0);
                draw_inspected(app, ui, record);
            }
        });
    }

    fn draw_inspected(app: &mut DesktopApp, ui: &mut egui::Ui, record: &DecisionRecord) {
        let entry = &record.entry;
        ui.label(
            RichText::new(format!("Decision {}", record.id))
                .strong()
                .color(INK),
        );
        let declarations: Vec<String> = entry
            .declarations
            .iter()
            .zip(&entry.items)
            .map(|(declaration, item)| match declaration {
                Some(d) => format!(
                    "item {item}: {}, {}, {} risk, {}, {}",
                    d.project,
                    d.environment.as_str(),
                    d.risk.as_str(),
                    d.scope.as_str(),
                    d.reversibility.as_str()
                ),
                None => format!("item {item}: no declaration"),
            })
            .collect();
        let facts: Vec<String> = entry
            .model_facts
            .iter()
            .map(|(name, p)| format!("{name} {:.0}%", p * 100.0))
            .collect();
        let none = |list: Vec<String>| {
            if list.is_empty() {
                "None".to_owned()
            } else {
                list.join(", ")
            }
        };
        property_grid(
            ui,
            "learning-inspected",
            &[
                ("Time", format_utc(entry.at)),
                ("Agent", entry.agent_name.clone()),
                (
                    "User request",
                    format!(
                        "{} (source: {})",
                        if entry.user_request.is_empty() {
                            "None"
                        } else {
                            &entry.user_request
                        },
                        entry.user_request_source.as_str()
                    ),
                ),
                ("Command", entry.command.join(" ")),
                ("Directory", entry.cwd_rel.clone()),
                ("Owner rule", entry.instruction.clone()),
                ("Secrets", none(entry.env_names.clone())),
                ("Declarations", none(declarations)),
                ("Rule flags", none(entry.rule_flags.clone())),
                ("Model facts", none(facts)),
                ("Pattern", entry.pattern.clone()),
                (
                    "Decision",
                    format!(
                        "{} by {}",
                        entry.decision.as_str(),
                        entry.decided_by.as_str()
                    ),
                ),
                ("Policy", entry.policy.clone()),
                ("Note", entry.note.clone()),
            ],
        );
        if ui.button("Close").clicked() {
            app.learning.inspected = None;
        }
    }

    fn state_text(pattern: &PatternRecord, now: u64) -> (String, egui::Color32) {
        match pattern.state(now) {
            PatternState::Active => ("Runs without a prompt".to_owned(), ALLOW),
            PatternState::Learning { approvals } => (
                format!(
                    "Learning: {approvals} of {} approvals",
                    crate::vault::PATTERN_APPROVALS_NEEDED
                ),
                ASK,
            ),
            PatternState::Blocked => ("Blocked by your denial".to_owned(), DENY),
            PatternState::Expired => ("Expired: not used for 30 days".to_owned(), INK_MUTED),
        }
    }

    fn draw_patterns(app: &mut DesktopApp, ui: &mut egui::Ui, loaded: &Loaded, now: u64) {
        let mut remove = None;
        card_frame().show(ui, |ui| {
            title(ui, "Remembered patterns");
            ui.label(
                RichText::new(
                    "\"Approve and remember\" teaches a pattern for one agent, one project, and one set of items. It runs without a prompt after 3 approvals. One denial blocks it. It expires after 30 days without use.",
                )
                .color(INK_MUTED),
            );
            if loaded.patterns.is_empty() {
                ui.label(RichText::new("No pattern yet.").color(INK_MUTED));
                return;
            }
            egui::Grid::new("learning-patterns")
                .striped(true)
                .num_columns(7)
                .show(ui, |ui| {
                    for name in ["Pattern", "Agent", "Project", "Items", "State", "Runs", ""] {
                        ui.label(RichText::new(name).strong().color(INK));
                    }
                    ui.end_row();
                    for pattern in &loaded.patterns {
                        ui.label(RichText::new(&pattern.display).monospace());
                        ui.label(
                            loaded
                                .agents
                                .get(&pattern.key.agent_id)
                                .cloned()
                                .unwrap_or_else(|| format!("Agent {}", pattern.key.agent_id)),
                        );
                        let directory = if pattern.key.cwd_rel == "." {
                            pattern.key.project_dir.clone()
                        } else {
                            format!("{} ({})", pattern.key.project_dir, pattern.key.cwd_rel)
                        };
                        ui.label(directory);
                        ui.label(
                            pattern
                                .key
                                .items
                                .iter()
                                .map(u64::to_string)
                                .collect::<Vec<_>>()
                                .join(", "),
                        );
                        let (text, color) = state_text(pattern, now);
                        ui.label(RichText::new(text).color(color));
                        ui.label(pattern.uses.to_string());
                        if danger_button(ui, "Remove").clicked() {
                            remove = Some(pattern.id);
                        }
                        ui.end_row();
                    }
                });
        });
        if let Some(id) = remove {
            let result = app.owner_ui.session.shared_vault();
            let mut guard = result.lock().unwrap_or_else(PoisonError::into_inner);
            let removed = guard
                .as_mut()
                .filter(|vault| !vault.is_locked())
                .map(|vault| vault.remove_pattern(id));
            drop(guard);
            match removed {
                Some(Ok(())) => app.set_ok("The pattern is removed. Matching runs ask you again."),
                _ => app.set_err("The pattern was not removed."),
            }
        }
    }

    fn draw_calibration(
        app: &mut DesktopApp,
        ui: &mut egui::Ui,
        active: Option<&CalibrationRecord>,
        now: u64,
    ) {
        let level = active.map_or(MIN_CONFIDENCE, |calibration| calibration.task_match);
        let mut compute = false;
        let mut apply = None;
        let mut reset = false;
        card_frame().show(ui, |ui| {
            title(ui, "Threshold calibration");
            ui.label(
                RichText::new(
                    "Apassy can propose a lower task_match level from your decisions. A proposal is valid only if a replay of all your past decisions allows no request that you denied. Nothing changes until you apply it. The production rule and the hard rules are never calibrated.",
                )
                .color(INK_MUTED),
            );
            let since = active.map_or_else(
                || "default".to_owned(),
                |calibration| format!("applied {}", format_utc(calibration.at)),
            );
            ui.label(
                RichText::new(format!(
                    "Active task_match level: {:.0}% ({since}).",
                    level * 100.0
                ))
                .color(INK),
            );
            ui.horizontal(|ui| {
                if accent_button(ui, "Compute a proposal").clicked() {
                    compute = true;
                }
                if level < MIN_CONFIDENCE && ui.button("Back to 80%").clicked() {
                    reset = true;
                }
            });
            if let Some(proposal) = &app.learning.proposal {
                let color = if proposal.valid { ALLOW } else { ASK };
                ui.label(
                    RichText::new(format!(
                        "Proposal: {:.0}% (now {:.0}%). {}",
                        proposal.proposed * 100.0,
                        proposal.current * 100.0,
                        proposal.reason
                    ))
                    .color(color),
                );
                ui.label(
                    RichText::new(format!(
                        "Decisions {}, your decisions {}, your denials {}. Newer part of the log: ask rate {:.0}% now, {:.0}% with the proposal, denials allowed {}.",
                        proposal.decisions,
                        proposal.owner_decisions,
                        proposal.owner_denials,
                        proposal.held_out_before.ask_rate() * 100.0,
                        proposal.held_out_after.ask_rate() * 100.0,
                        proposal.held_out_misses()
                    ))
                    .color(INK_MUTED),
                );
                if proposal.valid
                    && accent_button(ui, &format!("Apply {:.0}%", proposal.proposed * 100.0))
                        .clicked()
                {
                    apply = Some(proposal.proposed);
                }
            }
        });
        if let Some(task_match) = apply {
            // Goal item A4: a lower level is a rule change. It needs the owner check. The
            // request completes in `apply_calibration`.
            let level = (task_match * 100.0).round() as u32;
            let ctx = ui.ctx().clone();
            app.ask_owner(OwnerRequest::ApplyCalibration { level }, Some(&ctx));
            return;
        }
        if !(compute || reset) {
            return;
        }
        let shared = app.owner_ui.session.shared_vault();
        let mut guard = shared.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(vault) = guard.as_mut().filter(|vault| !vault.is_locked()) else {
            drop(guard);
            app.set_err("The vault is locked.");
            return;
        };
        if compute {
            let proposal = vault
                .decision_log()
                .map(|records| calibration::propose(&records, Thresholds { task_match: level }));
            drop(guard);
            match proposal {
                Ok(proposal) => app.learning.proposal = Some(proposal),
                Err(_) => app.set_err("The vault did not return the decision log."),
            }
        } else {
            let result = calibration::reset(vault, now);
            drop(guard);
            app.learning.proposal = None;
            match result {
                Ok(()) => app.set_ok("The task_match level is 80% again."),
                Err(message) => app.set_err(message),
            }
        }
    }

    /// Apply a calibrated level with a fresh owner check (goal item A4). The proof must
    /// name this level, in this vault session. The replay gate runs again first.
    pub(crate) fn apply_calibration(app: &mut DesktopApp, level: u32, proof: OwnerProof) {
        let shared = app.owner_ui.session.shared_vault();
        let mut guard = shared.lock().unwrap_or_else(PoisonError::into_inner);
        let result = match guard.as_mut().filter(|vault| !vault.is_locked()) {
            None => Err("The vault is locked.".to_owned()),
            Some(vault) => proof
                .check(&OwnerAction::ChangeCalibration { level }, &vault.epoch())
                .map_err(|refusal| refusal.message().to_owned())
                .and_then(|()| {
                    calibration::apply(vault, f64::from(level) / 100.0, learning::now())
                }),
        };
        drop(guard);
        app.learning.proposal = None;
        match result {
            Ok(report) => app.set_ok(format!(
                "The task_match level is {:.0}%. The replay of {} past decisions allows no request that you denied.",
                report.proposed * 100.0,
                report.all_after.decisions
            )),
            Err(message) => app.set_err(message),
        }
    }
}

#[cfg(feature = "vault")]
pub(crate) use vault_view::{LearningUiState, apply_calibration};

#[cfg(all(test, feature = "vault"))]
mod tests {
    use super::*;

    #[test]
    fn candidate_card_says_no_candidate_until_shadow_mode() {
        let none = candidate_lines(None);
        assert_eq!(none[0], "No candidate model.");
        let some = candidate_lines(Some(&CandidateView {
            model_version: "laya-local-1".to_owned(),
            shadow_decisions: 120,
            agreement: Some(0.96),
            allowed_owner_denials: 0,
            can_promote: true,
        }));
        assert_eq!(
            some[0],
            "Candidate laya-local-1: 120 shadow decisions, agreement 96%."
        );
        assert!(some[1].ends_with("You can promote it."));
    }

    fn text_of(shape: &egui::Shape, out: &mut String) {
        match shape {
            egui::Shape::Text(text) => {
                out.push_str(text.galley.text());
                out.push('\n');
            }
            egui::Shape::Vec(nested) => nested.iter().for_each(|inner| text_of(inner, out)),
            _ => {}
        }
    }

    fn draw_view(app: &mut DesktopApp) -> String {
        let ctx = egui::Context::default();
        let mut text = String::new();
        for _ in 0..2 {
            let input = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::Vec2::new(1280.0, 3000.0),
                )),
                ..Default::default()
            };
            let output = ctx.run_ui(input, |ui| draw(app, ui));
            text.clear();
            for clipped in &output.shapes {
                text_of(&clipped.shape, &mut text);
            }
            output.drop_without_applying_deltas();
        }
        text
    }

    /// Goal item B10: the view shows the ask rate, an automatic decision with its
    /// details, a pattern, the calibration, and the empty candidate slot.
    #[test]
    fn learning_view_shows_the_ask_rate_decisions_patterns_and_candidate_slot() {
        use crate::broker::learning::now;
        use crate::vault::{DecidedBy, DecisionEntry, LoggedDecision, PatternKey, RequestSource};

        let dir = tempfile::TempDir::new().expect("dir");
        let pass = "learning-view-pass";
        let mut app = DesktopApp::new();
        app.owner_ui
            .session
            .create_file(&dir.path().join("view.db"), pass)
            .expect("create");
        app.owner_ui.session.unlock(pass).expect("unlock");
        let at = now();
        {
            let shared = app.owner_ui.session.shared_vault();
            let mut guard = shared.lock().expect("vault");
            let vault = guard.as_mut().expect("open");
            let id = vault
                .record_decision(&DecisionEntry {
                    at,
                    agent_id: 1,
                    agent_name: "View agent".to_owned(),
                    project_dir: "/work/app".to_owned(),
                    cwd_rel: ".".to_owned(),
                    items: vec![1],
                    user_request: "Show the last commits.".to_owned(),
                    user_request_source: RequestSource::Host,
                    command: vec![
                        "git".to_owned(),
                        "log".to_owned(),
                        "-n".to_owned(),
                        "5".to_owned(),
                    ],
                    purpose: "List commits.".to_owned(),
                    env_names: vec!["DEMO_KEY".to_owned()],
                    declarations: vec![None],
                    rule_flags: Vec::new(),
                    known_safe: true,
                    model_facts: vec![("task_match".to_owned(), 0.93)],
                    pattern: "git log -n <number>".to_owned(),
                    grant_asks: false,
                    asked: false,
                    decision: LoggedDecision::Allow,
                    decided_by: DecidedBy::Model,
                    remembered: false,
                    policy: "apassy-bouncer-v4; task_match 0.80".to_owned(),
                    note: "Model allowed.".to_owned(),
                    instruction: String::new(),
                })
                .expect("decision");
            app.learning.inspected = Some(id);
            let key = PatternKey {
                agent_id: 1,
                project_dir: "/work/app".to_owned(),
                items: vec![1],
                policy: String::new(),
                cwd_rel: ".".to_owned(),
                template: "[]".to_owned(),
            };
            for _ in 0..3 {
                vault
                    .remember_approval(&key, "git log -n <number>", at)
                    .expect("pattern");
            }
        }
        let text = draw_view(&mut app);
        for expected in [
            "Ask rate over time",
            "Automatic decisions",
            "git log -n 5",
            "Show the last commits. (source: host)",
            "task_match 93%",
            "Remembered patterns",
            "git log -n <number>",
            "Runs without a prompt",
            "Active task_match level: 80% (default).",
            "No candidate model.",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in {text}");
        }

        app.owner_ui.session.lock().expect("lock");
        assert!(draw_view(&mut app).contains("Unlock the vault to see learning."));
    }
}
