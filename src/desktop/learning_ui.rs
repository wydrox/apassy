//! Learning view (ADR 0009, goal items B9 and B10): the ask rate over time, the
//! automatic decisions, the remembered patterns, the threshold calibration, the local
//! fine-tune with its gate, the agreement of a candidate model in shadow mode, and the
//! promotion and rollback of a model.
//!
//! The view reads the vault and calls the broker learning functions. Nothing here
//! changes the active policy without an owner action. A training starts only when the
//! owner clicks "Train a candidate". A promotion and a rollback need the owner check.

use eframe::egui;

use super::DesktopApp;

pub(crate) fn draw(app: &mut DesktopApp, ui: &mut egui::Ui) {
    super::ui::kit::page_header(
        ui,
        "Learning",
        Some(
            "Apassy learns from your decisions. A remembered pattern and a calibrated level act only at the model step. They never change the hard rules, the production rule, or a rule flag.",
        ),
        |_| {},
    );
    vault_view::draw(app, ui);
}

/// Text for the candidate model card. `None` when no candidate is in shadow mode.
pub(crate) fn candidate_lines(candidate: Option<&CandidateView>) -> Vec<String> {
    let Some(candidate) = candidate else {
        return vec![
            "No candidate model.".to_owned(),
            "When the training gate is open, you can train a candidate model on this computer. It decides in shadow mode, with no effect. This card then shows its agreement with your decisions. You promote it by hand after 100 shadow decisions with 95% agreement and no allowed denial.".to_owned(),
        ];
    };
    let port = candidate
        .url
        .rsplit(':')
        .next()
        .filter(|port| port.chars().all(|c| c.is_ascii_digit()))
        .unwrap_or("8775");
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
            match &candidate.refusal {
                None => "You can promote it.".to_owned(),
                Some(reason) => format!("It cannot be promoted yet. {reason}"),
            }
        ),
        format!(
            "Requests in shadow mode: {}. No answer from the candidate: {}. Same outcome as the active model: {}.",
            candidate.requests, candidate.no_answer, candidate.same_as_active
        ),
        format!(
            "The candidate answers at {}. Start its server: APASSY_BASE_MODEL=\"{}\" LAYA_PORT={port} tools/basemodel/start.sh",
            candidate.url, candidate.checkpoint
        ),
    ]
}

/// What the candidate card shows. It comes from `vault::ShadowSummary`.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CandidateView {
    pub id: u64,
    pub model_version: String,
    pub url: String,
    pub checkpoint: String,
    pub shadow_decisions: u32,
    pub agreement: Option<f64>,
    pub allowed_owner_denials: u32,
    pub requests: u32,
    pub no_answer: u32,
    pub same_as_active: u32,
    /// Why the shadow gate refuses a promotion. `None`: the owner can promote.
    pub refusal: Option<String>,
}

impl CandidateView {
    fn new(record: &crate::vault::CandidateRecord, summary: &crate::vault::ShadowSummary) -> Self {
        let agreement = &summary.agreement;
        Self {
            id: record.id,
            model_version: record.version.clone(),
            url: record.url.clone(),
            checkpoint: record.checkpoint.clone(),
            shadow_decisions: agreement.shadow_decisions,
            agreement: agreement.agreement(),
            allowed_owner_denials: agreement.allowed_owner_denials,
            requests: summary.requests,
            no_answer: summary.no_answer,
            same_as_active: summary.same_as_active,
            refusal: crate::broker::shadow::promotion_refusal(agreement),
        }
    }

    /// The Promote button is on only when the shadow gate passes.
    pub(crate) fn can_promote(&self) -> bool {
        self.refusal.is_none()
    }
}

/// Text for the training part of the candidate card.
pub(crate) fn training_lines(
    gate: &crate::broker::finetune::TrainingGate,
    running: Option<std::time::Duration>,
) -> Vec<String> {
    use crate::broker::finetune::{MIN_OWNER_DECISIONS, MIN_OWNER_DENIALS, TIME_LIMIT};
    let mut lines = vec![format!(
        "Training gate: {} of {MIN_OWNER_DECISIONS} owner decisions, {} of {MIN_OWNER_DENIALS} owner denials, power source: {}. {}",
        gate.owner_decisions,
        gate.owner_denials,
        gate.power.label(),
        if gate.is_open() {
            "The gate is open."
        } else {
            "The gate is closed."
        }
    )];
    if let Some(elapsed) = running {
        lines.push(format!(
            "Training runs: {} min {} s of {} min. Apassy stops it at the limit or on battery power.",
            elapsed.as_secs() / 60,
            elapsed.as_secs() % 60,
            TIME_LIMIT.as_secs() / 60
        ));
    } else {
        lines.push(format!(
            "A training runs only when you start it, only on AC power, and for at most {} minutes. It trains the decision heads from the shipped base model on your decisions. The result is a candidate in shadow mode, with no effect.",
            TIME_LIMIT.as_secs() / 60
        ));
    }
    lines
}

/// Text for the active model: the default bouncer, or a promoted model.
pub(crate) fn active_lines(active: Option<&crate::vault::ModelActivation>) -> Vec<String> {
    use crate::vault::{ActivationAction, format_utc, model_label};
    match active {
        None => vec![
            "Active model: the default model (APASSY_BOUNCER_URL). You did not promote a model."
                .to_owned(),
        ],
        Some(activation) if activation.action == ActivationAction::Promote => vec![
            format!(
                "Active model: {} at {}, promoted {}.",
                activation.version,
                activation.url,
                format_utc(activation.at)
            ),
            format!(
                "The model before it stays available: {}. A rollback needs your confirmation.",
                model_label(&activation.previous_version)
            ),
        ],
        Some(activation) => vec![format!(
            "Active model: {}{}, after a rollback on {}.",
            model_label(&activation.version),
            if activation.is_default() {
                " (APASSY_BOUNCER_URL)".to_owned()
            } else {
                format!(" at {}", activation.url)
            },
            format_utc(activation.at)
        )],
    }
}

mod vault_view {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, PoisonError};
    use std::time::{Duration, Instant};

    use eframe::egui::{self, Label, Pos2, Rect, Sense, Stroke, Vec2};

    use super::super::ui::kit::{self, Font, Icon, Style, Tone};
    use super::{CandidateView, DesktopApp, active_lines, candidate_lines, training_lines};
    use crate::broker::approvals::{OwnerAction, OwnerProof};
    use crate::broker::bouncer::{DEFAULT_TASK_MATCH, Thresholds};
    use crate::broker::calibration::{self, Proposal};
    use crate::broker::finetune::{
        self, Limits, Power, Trainer, TrainingError, TrainingGate, TrainingReport,
    };
    use crate::broker::{learning, shadow};
    use crate::desktop::owner_check::{OwnerRequest, Task, TaskPoll};
    use crate::vault::{
        ActivationAction, CalibrationRecord, DayRate, DecidedBy, DecisionRecord, ModelActivation,
        PatternRecord, PatternState, format_utc, model_label,
    };

    const DAY: u64 = 86_400;
    /// The disclosure key of the calibration and model sections.
    const ADVANCED: &str = "learning-advanced";
    /// The disclosure key of the ask rate table.
    const TABLE: &str = "learning-ask-rate-table";
    /// Days in the ask rate table.
    const DAYS_SHOWN: u64 = 14;
    const AUTOMATIC_SHOWN: usize = 25;
    /// Automatic decisions before "Show all".
    const AUTOMATIC_FOLDED: usize = 8;
    /// The disclosure key of the full list of automatic decisions.
    const AUTOMATIC_ALL: &str = "learning-automatic-all";
    /// The view reads the power source again after this time.
    const POWER_REFRESH: Duration = Duration::from_secs(30);

    /// A local fine-tune on a worker thread (goal item B9).
    pub(crate) struct TrainingRun {
        task: Task<Result<TrainingReport, TrainingError>>,
        started: Instant,
        stop: Arc<AtomicBool>,
    }

    impl std::fmt::Debug for TrainingRun {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("TrainingRun")
                .field("started", &self.started)
                .finish_non_exhaustive()
        }
    }

    /// Learning view state.
    #[derive(Debug, Default)]
    pub(crate) struct LearningUiState {
        /// The automatic decision that the owner inspects.
        pub(crate) inspected: Option<u64>,
        /// The last computed calibration proposal. It changes nothing until the owner
        /// applies it.
        pub(crate) proposal: Option<Proposal>,
        /// The training that runs now. Only the owner starts one.
        pub(crate) training: Option<TrainingRun>,
        /// The power source at the last check, and the time of the check.
        pub(crate) power: Option<(Power, Instant)>,
    }

    impl LearningUiState {
        /// Stop a running training. The broker stops the process group of the trainer.
        pub(crate) fn stop_training(&self) {
            if let Some(run) = &self.training {
                run.stop.store(true, Ordering::SeqCst);
            }
        }
    }

    struct Loaded {
        days: Vec<DayRate>,
        automatic: Vec<DecisionRecord>,
        inspected: Option<DecisionRecord>,
        patterns: Vec<PatternRecord>,
        calibration: Option<CalibrationRecord>,
        agents: BTreeMap<u64, String>,
        /// Credential names by item id, for the pattern and decision details.
        item_names: BTreeMap<u64, String>,
        /// The candidate in shadow mode and its numbers (goal item B9).
        candidate: Option<CandidateView>,
        /// The newest promotion or rollback.
        active: Option<ModelActivation>,
        /// Owner decisions and owner denials, for the training gate.
        owner_counts: (u32, u32),
    }

    impl Loaded {
        /// No decision, pattern, calibration, or model yet: nothing to show.
        fn is_empty(&self) -> bool {
            self.owner_counts == (0, 0)
                && self.days.iter().all(|day| day.decisions == 0)
                && self.automatic.is_empty()
                && self.patterns.is_empty()
                && self.calibration.is_none()
                && self.candidate.is_none()
                && self.active.is_none()
        }
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
                item_names: vault
                    .search("")?
                    .into_iter()
                    .map(|item| (item.id, item.title))
                    .collect(),
                candidate: match vault.shadow_candidate()? {
                    Some(record) => Some(CandidateView::new(
                        &record,
                        &vault.shadow_summary(record.id)?,
                    )),
                    None => None,
                },
                active: vault.active_model()?,
                owner_counts: vault.owner_decision_counts()?,
            })
        })();
        Some(result.map_err(|_: crate::vault::VaultError| {
            "The vault did not return the learning data.".to_owned()
        }))
    }

    pub(super) fn draw(app: &mut DesktopApp, ui: &mut egui::Ui) {
        let now = learning::now();
        poll_training(app);
        let loaded = match load(app, now) {
            None => {
                kit::note(ui, "Unlock the vault to see learning.");
                return;
            }
            Some(Err(message)) => {
                kit::tone_note(ui, message, Tone::Critical);
                return;
            }
            Some(Ok(loaded)) => loaded,
        };
        if loaded.is_empty() {
            // A new vault: one explanation instead of zeros and empty lists. Learning
            // starts with agent requests, so the action leads to the agents.
            let agents = kit::empty_state(
                ui,
                Icon::Chart,
                "Nothing to learn from yet",
                "When agents run commands with your credentials, this page shows how often Apassy asks you, what ran without you, and the patterns that you taught it.",
                Some("Go to Agents"),
            );
            if agents {
                app.view = crate::desktop::OwnerView::Agents;
                app.owner_ui.selected_agent = None;
            }
            return;
        }
        draw_summary(ui, &loaded, now);
        draw_ask_rate(app, ui, &loaded.days, now);
        draw_patterns(app, ui, &loaded, now);
        draw_automatic(app, ui, &loaded, now);
        let mut advanced = app.ui.is_expanded(ADVANCED);
        if kit::disclosure(ui, &mut advanced, "Advanced: calibration and models").changed() {
            app.ui.set_expanded(ADVANCED, advanced);
        }
        if advanced {
            ui.add_space(10.0);
            draw_calibration(app, ui, loaded.calibration.as_ref(), now);
            draw_models(app, ui, &loaded);
        }
        if let Some(record) = &loaded.inspected {
            draw_inspected(app, ui.ctx(), record, &loaded.item_names);
        }
    }

    /// The power source, read again at most every 30 seconds.
    fn power(app: &mut DesktopApp) -> Power {
        match app.learning.power {
            Some((power, at)) if at.elapsed() < POWER_REFRESH => power,
            _ => {
                let power = finetune::power_now();
                app.learning.power = Some((power, Instant::now()));
                power
            }
        }
    }

    /// The candidate card: the training gate, the candidate in shadow mode, and the
    /// active model with promotion and rollback (goal items B9 and B10).
    fn draw_models(app: &mut DesktopApp, ui: &mut egui::Ui, loaded: &Loaded) {
        let (decisions, denials) = loaded.owner_counts;
        let gate = TrainingGate {
            owner_decisions: decisions as usize,
            owner_denials: denials as usize,
            power: power(app),
        };
        let running = app
            .learning
            .training
            .as_ref()
            .map(|run| run.started.elapsed());
        let mut train = false;
        let mut stop = false;
        let mut promote = None;
        let mut rollback = None;
        kit::section(
            ui,
            Some("Candidate model"),
            Some(
                "A candidate decides in shadow mode, with no effect. You promote it by hand. A promotion and a rollback need your passphrase.",
            ),
            |s| {
                s.row(|ui| {
                    for line in candidate_lines(loaded.candidate.as_ref()) {
                        kit::note(ui, line);
                    }
                    if let Some(candidate) = &loaded.candidate {
                        let clicked = ui
                            .add_enabled_ui(candidate.can_promote(), |ui| {
                                kit::small_button(ui, "Promote", Style::Prominent)
                            })
                            .inner
                            .clicked();
                        if clicked {
                            promote = Some((candidate.id, candidate.model_version.clone()));
                        }
                    }
                });
                s.row(|ui| {
                    for line in training_lines(&gate, running) {
                        kit::note(ui, line);
                    }
                    if running.is_some() {
                        stop = kit::small_button(ui, "Stop training", Style::Destructive).clicked();
                    } else {
                        train = ui
                            .add_enabled_ui(gate.is_open(), |ui| {
                                kit::small_button(ui, "Train a candidate", Style::Bordered)
                            })
                            .inner
                            .clicked();
                    }
                });
                s.row(|ui| {
                    for line in active_lines(loaded.active.as_ref()) {
                        kit::paragraph(ui, line, Font::Callout, kit::LABEL);
                    }
                    if let Some(active) = &loaded.active
                        && active.action == ActivationAction::Promote
                        && kit::small_button(
                            ui,
                            &format!("Roll back to {}", model_label(&active.previous_version)),
                            Style::Destructive,
                        )
                        .clicked()
                    {
                        rollback = Some(active.clone());
                    }
                });
            },
        );
        if running.is_some() {
            ui.ctx().request_repaint_after(Duration::from_secs(1));
        }
        let ctx = ui.ctx().clone();
        if stop {
            app.learning.stop_training();
        }
        if train {
            start_training(app, &ctx);
        }
        if let Some((candidate_id, version)) = promote {
            // Goal item B9: a promotion changes the active policy. It needs the owner
            // check. The request completes in `promote_model`.
            app.ask_owner(
                OwnerRequest::PromoteModel {
                    candidate_id,
                    version,
                },
                Some(&ctx),
            );
        }
        if let Some(active) = rollback {
            app.ask_owner(
                OwnerRequest::RollbackModel {
                    activation_id: active.id,
                    from: model_label(&active.version),
                    to: model_label(&active.previous_version),
                },
                Some(&ctx),
            );
        }
    }

    /// Start a training on a worker thread. The broker checks the gate again first.
    fn start_training(app: &mut DesktopApp, ctx: &egui::Context) {
        if app.learning.training.is_some() {
            return;
        }
        let trainer = match Trainer::from_env() {
            Ok(trainer) => trainer,
            Err(message) => {
                app.set_err(message);
                return;
            }
        };
        let vault = app.owner_ui.session.shared_vault();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let url = shadow::candidate_url();
        let task = Task::spawn(Some(ctx.clone()), move || {
            finetune::train(
                &vault,
                &trainer,
                &url,
                Limits::default(),
                &finetune::power_now,
                &flag,
            )
        });
        app.learning.training = Some(TrainingRun {
            task,
            started: Instant::now(),
            stop,
        });
        app.set_ok("The training started. It stops after one hour at the latest.");
    }

    /// Take the result of a finished training.
    fn poll_training(app: &mut DesktopApp) {
        let Some(run) = &app.learning.training else {
            return;
        };
        let result = match run.task.poll() {
            TaskPoll::Waiting => return,
            TaskPoll::Done(result) => result,
            TaskPoll::Lost => Err(TrainingError::Failed(
                "The training thread ended without a result.".to_owned(),
            )),
        };
        app.learning.training = None;
        match result {
            Ok(report) => app.set_ok(format!(
                "The candidate {} is in shadow mode. The training took {:.0} s. Start its server, then it answers in parallel with no effect.",
                report.candidate.version, report.seconds
            )),
            Err(error) => app.set_err(error.message()),
        }
    }

    /// Promote a candidate with a fresh owner check (goal items A4 and B9). The proof
    /// must name this candidate and version, in this vault session. The shadow gate
    /// runs again first.
    pub(crate) fn promote_model(app: &mut DesktopApp, candidate_id: u64, proof: OwnerProof) {
        let shared = app.owner_ui.session.shared_vault();
        let mut guard = shared.lock().unwrap_or_else(PoisonError::into_inner);
        let result = match guard.as_mut().filter(|vault| !vault.is_locked()) {
            None => Err("The vault is locked.".to_owned()),
            Some(vault) => shadow::promote(vault, candidate_id, proof, learning::now()),
        };
        drop(guard);
        match result {
            Ok(activation) => app.set_ok(format!(
                "The bouncer now uses {}. {} stays available for a rollback.",
                activation.version,
                model_label(&activation.previous_version)
            )),
            Err(message) => app.set_err(message),
        }
    }

    /// Roll back the newest promotion with a fresh owner check (goal item B9).
    pub(crate) fn roll_back_model(app: &mut DesktopApp, activation_id: u64, proof: OwnerProof) {
        let shared = app.owner_ui.session.shared_vault();
        let mut guard = shared.lock().unwrap_or_else(PoisonError::into_inner);
        let result = match guard.as_mut().filter(|vault| !vault.is_locked()) {
            None => Err("The vault is locked.".to_owned()),
            Some(vault) => shadow::roll_back(vault, activation_id, proof, learning::now()),
        };
        drop(guard);
        match result {
            Ok(activation) => app.set_ok(format!(
                "The bouncer uses {} again.",
                model_label(&activation.version)
            )),
            Err(message) => app.set_err(message),
        }
    }

    /// Owner decisions and model runs of the last 7 days.
    struct Week {
        decisions: u32,
        asked: u32,
        by_model: u32,
        by_pattern: u32,
    }

    fn week(days: &[DayRate], now: u64) -> Week {
        let since = (now / DAY).saturating_sub(6) * DAY;
        days.iter().filter(|day| day.day >= since).fold(
            Week {
                decisions: 0,
                asked: 0,
                by_model: 0,
                by_pattern: 0,
            },
            |week, day| Week {
                decisions: week.decisions + day.decisions,
                asked: week.asked + day.asked,
                by_model: week.by_model + day.by_model,
                by_pattern: week.by_pattern + day.by_pattern,
            },
        )
    }

    /// Three stat tiles: the ask rate of the week (goal item B12), the runs without the
    /// owner, and the patterns.
    fn draw_summary(ui: &mut egui::Ui, loaded: &Loaded, now: u64) {
        let week = week(&loaded.days, now);
        let (rate, rate_caption) = if week.decisions == 0 {
            ("–".to_owned(), "No decisions in 7 days".to_owned())
        } else {
            (
                format!(
                    "{:.0}%",
                    f64::from(week.asked) / f64::from(week.decisions) * 100.0
                ),
                format!(
                    "{} of {} runs · goal 10% or less",
                    week.asked, week.decisions
                ),
            )
        };
        let states: Vec<PatternState> = loaded
            .patterns
            .iter()
            .map(|pattern| pattern.state(now))
            .collect();
        let active = states
            .iter()
            .filter(|state| matches!(state, PatternState::Active))
            .count();
        let learning = states
            .iter()
            .filter(|state| matches!(state, PatternState::Learning { .. }))
            .count();
        let gap = 12.0;
        let width = (ui.available_width() - 2.0 * gap) / 3.0;
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = gap;
            kit::stat_tile(ui, width, "Asked you, last 7 days", &rate, &rate_caption);
            kit::stat_tile(
                ui,
                width,
                "Ran without you",
                &(week.by_model + week.by_pattern).to_string(),
                &format!("model {} · pattern {}", week.by_model, week.by_pattern),
            );
            kit::stat_tile(
                ui,
                width,
                "Remembered patterns",
                &active.to_string(),
                &format!("active · {learning} still learning"),
            );
        });
        ui.add_space(22.0);
    }

    fn short(command: &[String]) -> String {
        let mut text = command.join(" ");
        if text.chars().count() > 80 {
            text = text.chars().take(77).collect::<String>() + "...";
        }
        text
    }

    /// The date of a day as "MM-DD".
    fn month_day(day: u64) -> String {
        let date = format_utc(day);
        date.split(' ')
            .next()
            .and_then(|date| date.get(5..))
            .unwrap_or_default()
            .to_owned()
    }

    /// The goal of B12: the owner is asked on 10% or fewer of the runs.
    const GOAL: f32 = 0.10;

    /// A column chart of the daily ask rate for 14 days, with the goal line. Each column
    /// has a tooltip. A table shows the same numbers.
    fn draw_ask_rate(app: &mut DesktopApp, ui: &mut egui::Ui, days: &[DayRate], now: u64) {
        kit::section(
            ui,
            Some("Ask rate over time"),
            Some(
                "Share of requests that waited for you, per UTC day, for the last 14 days. Requests that a hard rule denied do not count.",
            ),
            |s| {
                s.row(|ui| {
                    if days.is_empty() {
                        kit::note(ui, "No decisions yet.");
                        return;
                    }
                    ask_rate_chart(ui, days, now);
                });
            },
        );
        if days.is_empty() {
            return;
        }
        let mut table = app.ui.is_expanded(TABLE);
        if kit::disclosure(ui, &mut table, "Show as a table").changed() {
            app.ui.set_expanded(TABLE, table);
        }
        if table {
            ui.add_space(6.0);
            kit::section(ui, None, None, |s| {
                s.row(|ui| {
                    egui::Grid::new("learning-ask-rate")
                        .num_columns(6)
                        .spacing([18.0, 6.0])
                        .show(ui, |ui| {
                            for name in ["Day", "Requests", "Asked", "Model", "Pattern", "Ask rate"]
                            {
                                ui.label(kit::medium(name, Font::Callout).color(kit::SECONDARY));
                            }
                            ui.end_row();
                            for day in days {
                                let date = format_utc(day.day);
                                ui.label(date.split(' ').next().unwrap_or_default());
                                ui.label(day.decisions.to_string());
                                ui.label(day.asked.to_string());
                                ui.label(day.by_model.to_string());
                                ui.label(day.by_pattern.to_string());
                                ui.label(format!("{:.0}%", day.ask_rate() * 100.0));
                                ui.end_row();
                            }
                        });
                });
            });
        }
        ui.add_space(18.0);
    }

    fn ask_rate_chart(ui: &mut egui::Ui, days: &[DayRate], now: u64) {
        let first = (now / DAY).saturating_sub(DAYS_SHOWN - 1) * DAY;
        let axis_width = 34.0;
        let height = 150.0;
        let (rect, _) = ui.allocate_exact_size(
            Vec2::new(ui.available_width(), height + 20.0),
            Sense::hover(),
        );
        let plot = Rect::from_min_max(
            Pos2::new(rect.left() + axis_width, rect.top() + 26.0),
            Pos2::new(rect.right() - 4.0, rect.top() + height),
        );
        let painter = ui.painter();
        let grid = Stroke::new(1.0 / ui.ctx().pixels_per_point(), kit::SEPARATOR);
        let y_of = |share: f32| plot.bottom() - share * plot.height();
        for share in [0.0_f32, 0.5, 1.0] {
            let y = y_of(share);
            painter.hline(plot.x_range(), y, grid);
            let label = kit::galley(
                ui,
                kit::text(format!("{:.0}%", share * 100.0), Font::Footnote),
            );
            painter.galley(
                Pos2::new(plot.left() - 8.0 - label.size().x, y - label.size().y / 2.0),
                label,
                kit::SECONDARY,
            );
        }
        // The goal line has a legend above the plot, so no label sits on a column.
        let goal_y = y_of(GOAL);
        let goal_stroke = Stroke::new(1.5, kit::Tone::Good.mark());
        painter.hline(plot.x_range(), goal_y, goal_stroke);
        let goal = kit::galley(ui, kit::text("Goal: 10% or less", Font::Footnote));
        let legend_y = rect.top() + 6.0 + goal.size().y / 2.0;
        let text_x = plot.right() - goal.size().x;
        painter.galley(
            Pos2::new(text_x, legend_y - goal.size().y / 2.0),
            goal,
            kit::SECONDARY,
        );
        painter.hline((text_x - 22.0)..=(text_x - 6.0), legend_y, goal_stroke);
        let slot = plot.width() / DAYS_SHOWN as f32;
        let bar = (slot * 0.56).min(22.0);
        for index in 0..DAYS_SHOWN {
            let day_start = first + index * DAY;
            let center = plot.left() + slot * (index as f32 + 0.5);
            let slot_rect = Rect::from_min_max(
                Pos2::new(center - slot / 2.0, plot.top()),
                Pos2::new(center + slot / 2.0, plot.bottom()),
            );
            let day = days.iter().find(|day| day.day == day_start);
            if let Some(day) = day.filter(|day| day.decisions > 0) {
                let share = day.ask_rate() as f32;
                let top = y_of(share).min(plot.bottom() - 2.0);
                let column = Rect::from_min_max(
                    Pos2::new(center - bar / 2.0, top),
                    Pos2::new(center + bar / 2.0, plot.bottom()),
                );
                let radius = egui::CornerRadius {
                    nw: 4,
                    ne: 4,
                    sw: 0,
                    se: 0,
                };
                ui.painter().rect_filled(column, radius, kit::ACCENT);
                let tip = format!(
                    "{}: {} of {} requests asked you ({:.0}%). Model {}, pattern {}.",
                    format_utc(day.day).split(' ').next().unwrap_or_default(),
                    day.asked,
                    day.decisions,
                    share * 100.0,
                    day.by_model,
                    day.by_pattern
                );
                ui.interact(
                    slot_rect,
                    ui.id().with(("ask-rate-day", index)),
                    Sense::hover(),
                )
                .on_hover_text(tip);
                if index == DAYS_SHOWN - 1 {
                    let value = kit::galley(
                        ui,
                        kit::medium(format!("{:.0}%", share * 100.0), Font::Footnote),
                    );
                    // Above the column, and above the goal line when the column is low.
                    let bottom = if column.top() > goal_y - 4.0 {
                        goal_y - 3.0
                    } else {
                        column.top() - 2.0
                    };
                    ui.painter().galley(
                        Pos2::new(center - value.size().x / 2.0, bottom - value.size().y),
                        value,
                        kit::LABEL,
                    );
                }
            }
            if index == 0 || index == DAYS_SHOWN / 2 || index == DAYS_SHOWN - 1 {
                let text = if index == DAYS_SHOWN - 1 {
                    "Today".to_owned()
                } else {
                    month_day(day_start)
                };
                let label = kit::galley(ui, kit::text(text, Font::Footnote));
                ui.painter().galley(
                    Pos2::new(center - label.size().x / 2.0, plot.bottom() + 5.0),
                    label,
                    kit::SECONDARY,
                );
            }
        }
    }

    /// Rows of a folded list to show: all when expanded, else at most
    /// `AUTOMATIC_FOLDED`.
    pub(super) fn rows_shown(total: usize, expanded: bool) -> usize {
        if expanded {
            total
        } else {
            total.min(AUTOMATIC_FOLDED)
        }
    }

    fn draw_automatic(app: &mut DesktopApp, ui: &mut egui::Ui, loaded: &Loaded, now: u64) {
        let mut inspect = None;
        let total = loaded.automatic.len();
        let expanded = app.ui.is_expanded(AUTOMATIC_ALL);
        let mut toggle = false;
        kit::section(
            ui,
            Some("Automatic decisions"),
            Some(
                "Runs that started without you: the model allowed them, or a remembered pattern did. Open a run to see what Apassy knew.",
            ),
            |s| {
                if loaded.automatic.is_empty() {
                    s.row(|ui| kit::note(ui, "No automatic decision yet."));
                    return;
                }
                for record in loaded.automatic.iter().take(rows_shown(total, expanded)) {
                    let entry = &record.entry;
                    let by = if entry.decided_by == DecidedBy::Pattern {
                        "Pattern"
                    } else {
                        "Model"
                    };
                    let name = format!(
                        "{} by {by}, {}, {}",
                        short(&entry.command),
                        entry.agent_name,
                        format_utc(entry.at)
                    );
                    let response = s
                        .clickable_row(&name, |ui| {
                            egui::Sides::new().shrink_left().truncate().show(
                                ui,
                                |ui| {
                                    ui.add(
                                        Label::new(
                                            kit::text(short(&entry.command), Font::Mono)
                                                .color(kit::LABEL),
                                        )
                                        .truncate(),
                                    );
                                },
                                |ui| {
                                    kit::paint_icon_in(ui, Icon::ChevronRight, 12.0, kit::TERTIARY);
                                    kit::tag(ui, by, Tone::Good);
                                },
                            );
                            kit::note(
                                ui,
                                format!(
                                    "{} · {}",
                                    kit::relative_time(entry.at, now),
                                    entry.agent_name
                                ),
                            );
                        })
                        .on_hover_text(format_utc(entry.at));
                    if response.clicked() {
                        inspect = Some(record.id);
                    }
                }
                if total > AUTOMATIC_FOLDED {
                    let label = if expanded {
                        "Show fewer".to_owned()
                    } else {
                        format!("Show all {total}")
                    };
                    toggle = s
                        .clickable_row(&label, |ui| {
                            ui.label(kit::text(&label, Font::Body).color(kit::ACCENT_TEXT));
                        })
                        .clicked();
                }
            },
        );
        if toggle {
            app.ui.set_expanded(AUTOMATIC_ALL, !expanded);
        }
        if inspect.is_some() {
            app.learning.inspected = inspect;
        }
    }

    /// The name of a credential, or "Credential {id}" when the vault has no such item.
    fn item_name(item_names: &BTreeMap<u64, String>, id: u64) -> String {
        item_names
            .get(&id)
            .cloned()
            .unwrap_or_else(|| format!("Credential {id}"))
    }

    /// The meta line of a pattern: "Claude Code · /work/app · Staging database · 1 run".
    /// A `cwd_rel` of "." or "" is the project root.
    pub(super) fn pattern_meta(
        agent: &str,
        project_dir: &str,
        cwd_rel: &str,
        items: &[u64],
        item_names: &BTreeMap<u64, String>,
        uses: u64,
    ) -> String {
        let directory = if cwd_rel.is_empty() || cwd_rel == "." {
            project_dir.to_owned()
        } else {
            format!("{project_dir} ({cwd_rel})")
        };
        let items = items
            .iter()
            .map(|id| item_name(item_names, *id))
            .collect::<Vec<_>>()
            .join(", ");
        let runs = if uses == 1 {
            "1 run".to_owned()
        } else {
            format!("{uses} runs")
        };
        format!("{agent} · {directory} · {items} · {runs}")
    }

    /// What Apassy knew for one automatic decision, in a sheet.
    fn draw_inspected(
        app: &mut DesktopApp,
        ctx: &egui::Context,
        record: &DecisionRecord,
        item_names: &BTreeMap<u64, String>,
    ) {
        let entry = &record.entry;
        let declarations: Vec<String> = entry
            .declarations
            .iter()
            .zip(&entry.items)
            .map(|(declaration, item)| match declaration {
                Some(d) => format!(
                    "{}: {}, {}, {} risk, {}, {}",
                    item_name(item_names, *item),
                    d.project,
                    d.environment.as_str(),
                    d.risk.as_str(),
                    d.scope.as_str(),
                    d.reversibility.as_str()
                ),
                None => format!("{}: no declaration", item_name(item_names, *item)),
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
        let rows = [
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
        ];
        let mut close = false;
        let response = kit::sheet(ctx, "learning-decision", 600.0, |ui| {
            kit::sheet_title(ui, &format!("Decision {}", record.id), None);
            kit::sheet_body(ui, |ui| {
                kit::code_block(ui, &entry.command.join(" "), 1);
                ui.add_space(10.0);
                kit::section(ui, None, None, |s| {
                    for (term, value) in rows.iter().filter(|(_, value)| !value.is_empty()) {
                        s.labeled(term, kit::text(value, Font::Callout).color(kit::SECONDARY));
                    }
                });
            });
            kit::sheet_buttons(
                ui,
                |_| {},
                |ui| close = kit::button(ui, "Close", Style::Bordered).clicked(),
            );
        });
        if close || response.escape {
            app.learning.inspected = None;
        }
    }

    fn state_text(pattern: &PatternRecord, now: u64) -> (String, Tone) {
        match pattern.state(now) {
            PatternState::Active => ("Runs without a prompt".to_owned(), Tone::Good),
            PatternState::Learning { approvals } => (
                format!(
                    "Learning: {approvals} of {} approvals",
                    crate::vault::PATTERN_APPROVALS_NEEDED
                ),
                Tone::Warning,
            ),
            PatternState::Blocked => ("Blocked by your denial".to_owned(), Tone::Critical),
            PatternState::Expired => ("Expired: not used for 30 days".to_owned(), Tone::Neutral),
        }
    }

    fn draw_patterns(app: &mut DesktopApp, ui: &mut egui::Ui, loaded: &Loaded, now: u64) {
        let mut remove = None;
        kit::section(
            ui,
            Some("Remembered patterns"),
            Some(
                "\"Approve and remember\" teaches a pattern for one agent, one project, and one set of items. It runs without a prompt after 3 approvals. One denial blocks it. It expires after 30 days without use.",
            ),
            |s| {
                if loaded.patterns.is_empty() {
                    s.row(|ui| kit::note(ui, "No pattern yet."));
                    return;
                }
                for pattern in &loaded.patterns {
                    s.row(|ui| {
                        let (state, tone) = state_text(pattern, now);
                        egui::Sides::new().shrink_left().truncate().show(
                            ui,
                            |ui| {
                                ui.add(
                                    Label::new(
                                        kit::text(&pattern.display, Font::Mono).color(kit::LABEL),
                                    )
                                    .truncate(),
                                );
                            },
                            |ui| {
                                let button = kit::small_button(ui, "Remove", Style::Destructive);
                                let name = format!("Remove the pattern {}", pattern.display);
                                ui.ctx().accesskit_node_builder(button.id, |node| {
                                    node.set_label(name);
                                });
                                if button.clicked() {
                                    remove = Some(pattern.id);
                                }
                                kit::tag(ui, &state, tone);
                            },
                        );
                        let agent = loaded
                            .agents
                            .get(&pattern.key.agent_id)
                            .cloned()
                            .unwrap_or_else(|| format!("Agent {}", pattern.key.agent_id));
                        kit::note(
                            ui,
                            pattern_meta(
                                &agent,
                                &pattern.key.project_dir,
                                &pattern.key.cwd_rel,
                                &pattern.key.items,
                                &loaded.item_names,
                                pattern.uses,
                            ),
                        );
                    });
                }
            },
        );
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
        let level = active.map_or(DEFAULT_TASK_MATCH, |calibration| calibration.task_match);
        let mut compute = false;
        let mut apply = None;
        let mut reset = false;
        kit::section(
            ui,
            Some("Threshold calibration"),
            Some(
                "Apassy can propose a lower task_match level from your decisions. A proposal is valid only if a replay of all your past decisions allows no request that you denied. Nothing changes until you apply it. The production rule and the hard rules are never calibrated.",
            ),
            |s| {
                s.row(|ui| {
                    let since = active.map_or_else(
                        || "default".to_owned(),
                        |calibration| format!("applied {}", format_utc(calibration.at)),
                    );
                    kit::paragraph(
                        ui,
                        format!("Active task_match level: {:.0}% ({since}).", level * 100.0),
                        Font::Body,
                        kit::LABEL,
                    );
                    ui.horizontal(|ui| {
                        compute =
                            kit::small_button(ui, "Compute a proposal", Style::Bordered).clicked();
                        if active.is_some() {
                            reset = kit::small_button(ui, "Back to the default (75%)", Style::Link)
                                .clicked();
                        }
                    });
                });
                if let Some(proposal) = &app.learning.proposal {
                    s.row(|ui| {
                        let tone = if proposal.valid { Tone::Good } else { Tone::Warning };
                        kit::tone_note(
                            ui,
                            format!(
                                "Proposal: {:.0}% (now {:.0}%). {}",
                                proposal.proposed * 100.0,
                                proposal.current * 100.0,
                                proposal.reason
                            ),
                            tone,
                        );
                        kit::note(
                            ui,
                            format!(
                                "Decisions {}, your decisions {}, your denials {}. Newer part of the log: ask rate {:.0}% now, {:.0}% with the proposal, denials allowed {}.",
                                proposal.decisions,
                                proposal.owner_decisions,
                                proposal.owner_denials,
                                proposal.held_out_before.ask_rate() * 100.0,
                                proposal.held_out_after.ask_rate() * 100.0,
                                proposal.held_out_misses()
                            ),
                        );
                        if proposal.valid
                            && kit::small_button(
                                ui,
                                &format!("Apply {:.0}%", proposal.proposed * 100.0),
                                Style::Prominent,
                            )
                            .clicked()
                        {
                            apply = Some(proposal.proposed);
                        }
                    });
                }
            },
        );
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
                Ok(()) => app.set_ok("The task_match level is the default (75%) again."),
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

pub(crate) use vault_view::{LearningUiState, apply_calibration, promote_model, roll_back_model};

#[cfg(test)]
mod tests {
    use super::*;

    fn view(shadow_decisions: u32, agreed: u32, allowed_owner_denials: u32) -> CandidateView {
        let agreement = crate::vault::CandidateAgreement {
            model_version: "laya-local-1".to_owned(),
            started_at: 0,
            shadow_decisions,
            agreed,
            allowed_owner_denials,
        };
        CandidateView {
            id: 1,
            model_version: "laya-local-1".to_owned(),
            url: "http://127.0.0.1:8775".to_owned(),
            checkpoint: "/models/candidate.safetensors".to_owned(),
            shadow_decisions,
            agreement: agreement.agreement(),
            allowed_owner_denials,
            requests: shadow_decisions + 10,
            no_answer: 2,
            same_as_active: 7,
            refusal: crate::broker::shadow::promotion_refusal(&agreement),
        }
    }

    #[test]
    fn candidate_card_says_no_candidate_until_shadow_mode() {
        let none = candidate_lines(None);
        assert_eq!(none[0], "No candidate model.");
        let promotable = view(120, 115, 0);
        assert!(promotable.can_promote());
        let some = candidate_lines(Some(&promotable));
        assert_eq!(
            some[0],
            "Candidate laya-local-1: 120 shadow decisions, agreement 96%."
        );
        assert!(some[1].ends_with("You can promote it."));
        assert!(some[2].contains("Requests in shadow mode: 130. No answer from the candidate: 2."));
        assert!(some[3].contains(
            "APASSY_BASE_MODEL=\"/models/candidate.safetensors\" LAYA_PORT=8775 tools/basemodel/start.sh"
        ));
        // The Promote button stays off below each threshold of ADR 0010.
        for (decisions, agreed, denials) in [(99, 99, 0), (100, 94, 0), (120, 119, 1)] {
            let blocked = view(decisions, agreed, denials);
            assert!(!blocked.can_promote(), "{decisions} {agreed} {denials}");
            assert!(candidate_lines(Some(&blocked))[1].contains("It cannot be promoted yet."));
        }
    }

    #[test]
    fn training_card_shows_the_gate_and_the_active_model() {
        use crate::broker::finetune::{Power, TrainingGate};
        let closed = TrainingGate {
            owner_decisions: 299,
            owner_denials: 30,
            power: Power::Ac,
        };
        let lines = training_lines(&closed, None);
        assert!(lines[0].starts_with(
            "Training gate: 299 of 300 owner decisions, 30 of 30 owner denials, power source: AC power. The gate is closed."
        ));
        let open = TrainingGate {
            owner_decisions: 300,
            ..closed
        };
        assert!(training_lines(&open, None)[0].ends_with("The gate is open."));
        let running = training_lines(&open, Some(std::time::Duration::from_secs(125)));
        assert!(running[1].starts_with("Training runs: 2 min 5 s of 60 min."));
        assert!(active_lines(None)[0].starts_with("Active model: the default model"));
    }

    #[test]
    fn pattern_meta_names_the_directory_credentials_and_runs() {
        use std::collections::BTreeMap;
        let names = BTreeMap::from([
            (5, "Staging database".to_owned()),
            (7, "Deploy key".to_owned()),
        ]);
        let meta = |cwd_rel: &str, items: &[u64], uses: u64| {
            vault_view::pattern_meta(
                "Claude Code",
                "/Users/you/code/acme-api",
                cwd_rel,
                items,
                &names,
                uses,
            )
        };
        assert_eq!(
            meta("", &[5], 0),
            "Claude Code · /Users/you/code/acme-api · Staging database · 0 runs"
        );
        assert_eq!(
            meta(".", &[5, 7], 1),
            "Claude Code · /Users/you/code/acme-api · Staging database, Deploy key · 1 run"
        );
        assert_eq!(
            meta("web", &[9], 12),
            "Claude Code · /Users/you/code/acme-api (web) · Credential 9 · 12 runs"
        );
    }

    #[test]
    fn automatic_decisions_fold_after_eight_rows() {
        use vault_view::rows_shown;
        assert_eq!(rows_shown(0, false), 0);
        assert_eq!(rows_shown(3, false), 3);
        assert_eq!(rows_shown(8, false), 8);
        assert_eq!(rows_shown(25, false), 8);
        assert_eq!(rows_shown(25, true), 25);
        assert_eq!(rows_shown(3, true), 3);
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

    /// A new vault shows one empty state, not zeros and empty lists.
    #[test]
    fn a_new_vault_shows_one_empty_state() {
        let dir = tempfile::TempDir::new().expect("dir");
        let pass = "learning-empty-pass";
        let mut app = DesktopApp::new();
        app.owner_ui
            .session
            .create_file(&dir.path().join("empty.db"), pass)
            .expect("create");
        app.owner_ui.session.unlock(pass).expect("unlock");
        let text = draw_view(&mut app);
        assert!(text.contains("Nothing to learn from yet"), "{text}");
        assert!(!text.contains("Remembered patterns"), "{text}");
        assert!(!text.contains("Ran without you"), "{text}");
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
        app.ui.set_expanded("learning-advanced", true);
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
            "Agent 1 · /work/app · Credential 1 · 0 runs",
            "just now · View agent",
            "Credential 1: no declaration",
            "Active task_match level: 75% (default).",
            "No candidate model.",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in {text}");
        }
        // The actionable patterns come before the read-only decision log.
        let position = |needle: &str| text.find(needle).expect(needle);
        assert!(position("Agent 1 · /work/app") < position("just now · View agent"));

        app.owner_ui.session.lock().expect("lock");
        assert!(draw_view(&mut app).contains("Unlock the vault to see learning."));
    }

    /// Goal items B9 and B10: the view shows the shadow numbers of the candidate. The
    /// promotion and the rollback need the owner check. A wrong passphrase changes
    /// nothing.
    #[test]
    fn promotion_and_rollback_in_the_view_need_the_owner_check() {
        use crate::broker::approvals::OwnerCheck;
        use crate::desktop::owner_check::OwnerRequest;
        use crate::vault::{
            ActivationAction, NewCandidate, OwnerLabel, RealOutcome, ShadowAnswer, ShadowEntry,
        };

        let dir = tempfile::TempDir::new().expect("dir");
        let pass = "learning-view-pass";
        let version = "apassy-local-v1+0badc0de";
        let mut app = DesktopApp::new();
        app.owner_ui
            .session
            .create_file(&dir.path().join("promote.db"), pass)
            .expect("create");
        app.owner_ui.session.unlock(pass).expect("unlock");
        let shared = app.owner_ui.session.shared_vault();
        let candidate_id = {
            let mut guard = shared.lock().expect("vault");
            let vault = guard.as_mut().expect("open");
            let candidate = vault
                .register_candidate(
                    &NewCandidate {
                        version: version.to_owned(),
                        url: "http://127.0.0.1:8775".to_owned(),
                        checkpoint: "/models/candidate.safetensors".to_owned(),
                        checkpoint_sha256: "0badc0de".repeat(8),
                        report: "{}".to_owned(),
                    },
                    crate::broker::learning::now(),
                )
                .expect("candidate");
            for n in 0..100u32 {
                let (candidate_answer, owner) = if n < 96 {
                    (ShadowAnswer::Run, OwnerLabel::Allow)
                } else {
                    (ShadowAnswer::Ask, OwnerLabel::Deny)
                };
                vault
                    .record_shadow(&ShadowEntry {
                        candidate_id: candidate.id,
                        at: crate::broker::learning::now(),
                        real: RealOutcome::Ask,
                        candidate: candidate_answer,
                        owner,
                        facts: Vec::new(),
                    })
                    .expect("row");
            }
            candidate.id
        };
        app.ui.set_expanded("learning-advanced", true);
        let text = draw_view(&mut app);
        for expected in [
            "Candidate apassy-local-v1+0badc0de: 100 shadow decisions, agreement 100%.",
            "Denials that the candidate would allow: 0. You can promote it.",
            "Promote",
            "Training gate: 0 of 300 owner decisions, 0 of 30 owner denials",
            "Active model: the default model",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in {text}");
        }
        let active = || {
            shared
                .lock()
                .expect("vault")
                .as_ref()
                .expect("open")
                .active_model()
                .expect("active")
        };
        let promote = OwnerRequest::PromoteModel {
            candidate_id,
            version: version.to_owned(),
        };
        app.ask_owner(promote.clone(), None);
        assert!(
            app.confirm_owner_now(OwnerCheck::passphrase("learning-view-wrong"))
                .is_err()
        );
        assert_eq!(active(), None, "a wrong passphrase promotes nothing");
        app.ask_owner(promote, None);
        app.confirm_owner_now(OwnerCheck::passphrase(pass))
            .expect("owner check");
        let promotion = active().expect("promoted");
        assert_eq!(promotion.action, ActivationAction::Promote);
        assert_eq!(promotion.version, version);
        let text = draw_view(&mut app);
        assert!(
            text.contains("Active model: apassy-local-v1+0badc0de at http://127.0.0.1:8775"),
            "{text}"
        );
        assert!(text.contains("Roll back to the default model"), "{text}");
        assert!(text.contains("No candidate model."), "{text}");

        let rollback = OwnerRequest::RollbackModel {
            activation_id: promotion.id,
            from: version.to_owned(),
            to: "the default model".to_owned(),
        };
        app.ask_owner(rollback.clone(), None);
        assert!(
            app.confirm_owner_now(OwnerCheck::passphrase("learning-view-wrong"))
                .is_err()
        );
        assert_eq!(active().map(|a| a.action), Some(ActivationAction::Promote));
        app.ask_owner(rollback, None);
        app.confirm_owner_now(OwnerCheck::passphrase(pass))
            .expect("owner check");
        let back = active().expect("rollback");
        assert_eq!(back.action, ActivationAction::Rollback);
        assert!(back.is_default());
        assert!(draw_view(&mut app).contains("Active model: the default model"));
    }
}
