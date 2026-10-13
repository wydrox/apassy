//! The plan in the window (ADR 0027, flow spec M3 to M5, Flows B to E):
//!
//! - Settings > Plan (M5): Free, or the paid plan with its renewal, its account, "Manage
//!   subscription", and "Sign out of this Mac"; the offline and payment notes.
//! - The Upgrade sheet (M4) at a paid pick: what you get, the full price, "Continue to
//!   checkout" in the browser, and "Not now" with the same weight. Then the wait for the
//!   payment, and "Personal is on." with the switch of the vault (C3).
//! - Compare plans: Free, Personal, and Team side by side, with what each has.
//! - "Switch “VAULT” to Apassy" for a paid plan (Flow B): the vault's own Apassy Connect
//!   team gets sync; a vault with no team gets one first. Never a second team. Sync for
//!   the team reaches every device in it, also one added for the questions only, so the
//!   switch is an owner check (`OwnerAction::SyncThroughApassy`) that lists those
//!   devices, and it runs only with that proof.
//! - "Personal ended" (Flow E): once per vault and session when a paid plan ended while
//!   the vault syncs through Apassy. Sync moves to iCloud Drive or stops; approvals
//!   stay, and the vault is never blocked.
//!
//! The plan comes from `DesktopApp::plan`. With no offer ([`crate::plan::NoPlanProvider`],
//! the app as it ships) none of this shows: no Plan section, no tag, no upgrade, and
//! "Apassy" in Vault > Sync opens "Use another relay…" as before.
//!
//! The ethics gate of the flow spec (§7) holds here: an upgrade shows only where the
//! owner picks a paid feature (Sync, Shared) and in Settings > Plan, never as a banner
//! or a badge; "Not now" is a button of the same size as the checkout; the price is the
//! whole price; cancel is in Settings > Plan, where the plan is; a plan that ends keeps
//! the vault and the approvals.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use eframe::egui::{self, Label};

use super::kit::{self, Font, Icon, Style, Tone};
use super::settings::rows;
use super::sync::SyncSheet;
use super::sync::relay::plan_switch::MembershipSwitch;
use super::{Sheet, close_sheet};
use crate::desktop::DesktopApp;
use crate::desktop::owner_check::{Task, TaskPoll};
use crate::plan::{
    Entitlement, Offer, Plan, PlanError, PlanNote, PlanStatus, Standing, UpgradeFrom,
};
use crate::relay::membership::existing_questions_team;

/// After this long in the browser without a paid plan, the sheet says that the payment
/// did not arrive yet.
pub(crate) const NOT_CONFIRMED_AFTER: Duration = Duration::from_secs(120);
/// How often the sheet asks the account service while the owner pays in the browser.
const CHECK_EVERY: Duration = Duration::from_secs(15);

/// The line under "iCloud Drive" in Vault > Sync when the app offers a plan.
pub(crate) const ICLOUD_LINE: &str =
    "Free. Your other devices get changes in about a minute while Apassy is open.";
/// The same line in a build with no plan: no price words.
pub(crate) const ICLOUD_LINE_NO_PLAN: &str =
    "Your other devices get changes in about a minute while Apassy is open.";
/// The line under "Apassy".
pub(crate) const APASSY_LINE: &str = "Changes reach your devices in seconds, also without iCloud. Encrypted on your Mac: Apassy can't read it.";
/// The line under "Off".
pub(crate) const OFF_LINE: &str = "This vault stays on this Mac.";
/// What Free has, in Settings > Plan.
pub(crate) const FREE_LINE: &str = "iCloud Drive sync · Approvals on all your devices";
/// The reassurance of the Upgrade sheet.
pub(crate) const REASSURANCE: &str =
    "Cancel any time in Settings > Plan. Your vault stays on your devices.";
/// The wait for the payment.
pub(crate) const WAITING_TITLE: &str = "Finish in your browser…";
/// The payment did not arrive after [`NOT_CONFIRMED_AFTER`].
pub(crate) const NOT_CONFIRMED: &str =
    "We didn't get the payment yet. If you paid, select Check again. If not, nothing changed.";
/// The tag of the Apassy choice on Free.
pub(crate) const TAG: &str = "Personal";
/// "Share a vault" in the sidebar on Free.
pub(crate) const SHARED_LINE: &str = "Share a vault with people. Part of Personal and Team.";
pub(crate) const SEE_PLANS: &str = "See plans";
/// The note of "New shared vault…" on a paid plan: shared vaults are not built.
pub(crate) const COMING_SOON: &str = "Coming soon";

/// The sheets of the plan that are not Upgrade or "Personal ended".
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PlanSheet {
    /// Free, Personal, and Team side by side. `back`: the Upgrade sheet that opened it,
    /// which "Back" shows again.
    Compare { back: Option<UpgradeFrom> },
    /// "Sign out of this Mac?"
    SignOut,
}

/// The browser checkout of the Upgrade sheet.
struct Checkout {
    from: UpgradeFrom,
    started: Instant,
    next_check: Instant,
}

/// The state of the plan in the window.
#[derive(Default)]
pub(crate) struct PlanUi {
    /// The owner pays in the browser: the Upgrade sheet waits.
    checkout: Option<Checkout>,
    /// The paid plan arrived while the Upgrade sheet waited: it shows C3.
    upgraded: Option<UpgradeFrom>,
    /// A check with the account service ("Check again", or the one every 15 seconds).
    checking: Option<Task<Result<Entitlement, PlanError>>>,
    /// Why the last check failed.
    check_error: Option<String>,
    /// "Sign out of this Mac" while the account service answers.
    signing_out: Option<Task<Result<(), PlanError>>>,
    /// A vault that moves to Apassy while the relay answers.
    switching: Option<MembershipSwitch>,
    /// A vault that moves to Apassy when its new Apassy Connect team is made: the owner
    /// check and the relay call of the team come first.
    switch_after_connect: Option<String>,
    /// The vaults whose "Personal ended" sheet showed in this session.
    ended_shown: BTreeSet<String>,
    /// Links stay in the app instead of the browser: the tests and the screenshot tour.
    hold_links: bool,
    /// The links that the plan opened, the last one last.
    pub(crate) opened: Vec<String>,
}

/// The plan that the app acts on now, and the entitlement it comes from.
fn standing(app: &DesktopApp) -> (Entitlement, Standing) {
    let entitlement = app.plan.current();
    let standing = entitlement.standing(kit::now());
    (entitlement, standing)
}

/// The offer of an upgrade at `from`, if the app has one.
fn offer(app: &DesktopApp, from: UpgradeFrom) -> Option<Offer> {
    app.plan.offer(from)
}

/// Whether the paid features work now: a paid plan, or a vault of an operator.
pub(crate) fn paid(app: &DesktopApp) -> bool {
    standing(app).1.paid()
}

/// The small gray tag of the Apassy sync choice: "Personal" on Free with an offer, else
/// none.
pub(crate) fn sync_tag(app: &DesktopApp) -> Option<&'static str> {
    (offer(app, UpgradeFrom::Sync).is_some() && !paid(app)).then_some(TAG)
}

/// The line under "iCloud Drive": with "Free." only when the app offers a plan.
pub(crate) fn icloud_line(app: &DesktopApp) -> &'static str {
    if app.plans_offered() {
        ICLOUD_LINE
    } else {
        ICLOUD_LINE_NO_PLAN
    }
}

/// The note when this Mac has no iCloud Drive folder. The free fix comes first. "or
/// sync through Apassy" only when Apassy can sync this vault: an offer, or a relay of an
/// operator that the vault uses.
pub(crate) fn icloud_off_note(app: &DesktopApp, id: &str) -> String {
    if app.plans_offered() || operator_relay(app, id) {
        "iCloud Drive is off on this Mac. Turn it on in System Settings, or sync through Apassy."
            .to_owned()
    } else {
        "iCloud Drive is off on this Mac. Turn it on in System Settings.".to_owned()
    }
}

/// Whether the vault `id` uses a relay of an operator: it syncs through a relay, or its
/// devices are on a relay other than Apassy Connect.
fn operator_relay(app: &DesktopApp, id: &str) -> bool {
    if app.is_relay(id) {
        return true;
    }
    if app.vault_list.current.as_deref() != Some(id) {
        return false;
    }
    let connect = app.connect_relay_url();
    app.owner_ui
        .session
        .with_vault(|vault| {
            crate::relay::membership::questions_membership(vault)
                .ok()
                .flatten()
                .is_some_and(|membership| membership.relay_url != connect)
        })
        .unwrap_or(false)
}

/// Whether the vault `id` moves to Apassy now.
pub(crate) fn switching(app: &DesktopApp, id: &str) -> bool {
    app.ui
        .plan
        .switching
        .as_ref()
        .is_some_and(|switch| switch.id() == id)
        || app.ui.plan.switch_after_connect.as_deref() == Some(id)
}

/// "Apassy" picked in Vault > Sync for the open vault `id` (flow spec M3):
/// - no offer: "Use another relay…" with the relay address and the team code, as before;
/// - an offer and no paid plan: the Upgrade sheet;
/// - a paid plan, or an operator: one confirmation, then the vault's own team.
pub(crate) fn pick_apassy(app: &mut DesktopApp, id: &str, ctx: &egui::Context) {
    if offer(app, UpgradeFrom::Sync).is_none() {
        app.sync_open_sheet(SyncSheet::RelaySetup { id: id.to_owned() }, Some(ctx));
    } else if !paid(app) {
        app.plan_open_upgrade(UpgradeFrom::Sync);
    } else {
        app.plan_switch_to_apassy(id, ctx);
    }
}

/// A day such as "Nov 12".
fn day(unix: u64) -> String {
    super::agents::short_date(unix, kit::now())
}

/// The status line of Settings > Plan in the list and in its header.
pub(super) fn status_line(app: &DesktopApp) -> String {
    let (entitlement, standing) = standing(app);
    if let Some(PlanNote::Unchecked { plan, .. }) = standing.note {
        return format!("Free · {} not checked", plan.label());
    }
    let name = standing.plan.label();
    match (standing.plan, standing.status) {
        (Plan::Free | Plan::Operator, _) => name.to_owned(),
        (_, Some(PlanStatus::Ended)) => format!("{name} ended"),
        (_, Some(PlanStatus::PastDue)) => format!("{name} · payment failed"),
        _ => match (standing.note, entitlement.renews_at) {
            (Some(PlanNote::Offline { checked_at, .. }), _) => {
                format!("{name} · checked {}", day(checked_at))
            }
            (_, Some(renews)) => format!("{name} · renews {}", day(renews)),
            _ => name.to_owned(),
        },
    }
}

/// What Settings > Plan asks for.
enum Action {
    Compare,
    Portal,
    SignOut,
    Check,
}

/// The groups of Settings > Plan (flow spec M5). Same rows as the other sections; no
/// plan color.
pub(super) fn section(app: &mut DesktopApp, ui: &mut egui::Ui) {
    if !app.plans_offered() {
        return;
    }
    let (entitlement, standing) = standing(app);
    let checking = app.ui.plan.checking.is_some();
    let mut action = None;
    match (standing.plan, standing.status) {
        (Plan::Free, _) => {
            rows::section(ui, None, None, |g| {
                g.row(|ui| {
                    ui.label(kit::row_title("Free"));
                    ui.add(Label::new(rows::note(FREE_LINE)).wrap());
                });
                if let Some(PlanNote::Unchecked { plan, checked_at }) = standing.note {
                    g.row(|ui| {
                        kit::tone_note(
                            ui,
                            format!(
                                "{} was last checked {}. Apassy works as Free until it can check it again.",
                                plan.label(),
                                day(checked_at)
                            ),
                            Tone::Warning,
                        );
                        ui.add_enabled_ui(!checking, |ui| {
                            if kit::small_button(ui, "Check again", Style::Bordered).clicked() {
                                action = Some(Action::Check);
                            }
                        });
                    });
                }
                if g.link("Compare plans").clicked() {
                    action = Some(Action::Compare);
                }
            });
        }
        (Plan::Operator, _) => {
            rows::section(ui, None, None, |g| {
                g.row(|ui| {
                    ui.label(kit::row_title("Operator"));
                    ui.add(
                        Label::new(rows::note(
                            "Sync through a relay that you run · Approvals on all your devices",
                        ))
                        .wrap(),
                    );
                });
            });
        }
        (plan, Some(PlanStatus::Ended)) => {
            rows::section(ui, None, None, |g| {
                g.row(|ui| {
                    ui.label(kit::row_title(format!("{} ended", plan.label())));
                    ui.add(
                        Label::new(rows::note(
                            "Your vault stays on all your devices. Approvals stay on all of them.",
                        ))
                        .wrap(),
                    );
                });
                if g.link("Compare plans").clicked() {
                    action = Some(Action::Compare);
                }
            });
        }
        (plan, status) => {
            let renews = entitlement
                .renews_at
                .map(|at| format!("renews {}", day(at)));
            rows::section(ui, None, None, |g| {
                g.line(plan.label(), renews.map(rows::value), |_| {});
                if status == Some(PlanStatus::PastDue) {
                    g.row(|ui| {
                        kit::tone_note(
                            ui,
                            "The last payment did not go through. Your plan works while you update it.",
                            Tone::Warning,
                        );
                        if kit::small_button(ui, "Update payment", Style::Bordered).clicked() {
                            action = Some(Action::Portal);
                        }
                    });
                }
                if let Some(PlanNote::Offline { checked_at, .. }) = standing.note {
                    g.note_row(format!(
                        "Plan checked {}. Works offline for 14 days.",
                        day(checked_at)
                    ));
                }
                if let Some(email) = &entitlement.email {
                    g.labeled("Account", rows::value(email));
                }
                g.line("Subscription", None, |ui| {
                    if kit::small_button(ui, "Manage subscription", Style::Bordered).clicked() {
                        action = Some(Action::Portal);
                    }
                });
            });
            rows::section(
                ui,
                None,
                Some("Sync through Apassy stops on this Mac after you sign out."),
                |g| {
                    g.line("This Mac", None, |ui| {
                        if kit::small_button(ui, "Sign out of this Mac", Style::Destructive)
                            .clicked()
                        {
                            action = Some(Action::SignOut);
                        }
                    });
                },
            );
        }
    }
    match action {
        Some(Action::Compare) => {
            app.ui.sheet = Some(Sheet::Plan(PlanSheet::Compare { back: None }));
        }
        Some(Action::Portal) => {
            let url = app.plan.portal_url();
            app.plan_open_link(url);
        }
        Some(Action::SignOut) => app.ui.sheet = Some(Sheet::Plan(PlanSheet::SignOut)),
        Some(Action::Check) => app.plan_check(None),
        None => {}
    }
}

/// The headline and the three lines of what you get, by the place of the pick.
fn upgrade_words(from: UpgradeFrom) -> (&'static str, [&'static str; 3]) {
    match from {
        UpgradeFrom::Shared => (
            "Share vaults with people",
            [
                "Shared vaults with a few people, when they are ready",
                "Changes on every device in seconds",
                "End-to-end encrypted. Apassy can't read your vault.",
            ],
        ),
        UpgradeFrom::Sync | UpgradeFrom::Plan => (
            "Sync through Apassy",
            [
                "Changes on every device in seconds",
                "Works without iCloud",
                "End-to-end encrypted. Apassy can't read your vault.",
            ],
        ),
    }
}

/// The price as the sheet shows it: "Personal · €1 a month", with ", or …" when there is
/// a yearly price.
pub(crate) fn price_line(offer: &Offer) -> String {
    match &offer.yearly {
        Some(yearly) => format!("{} · {}, or {yearly}", offer.plan.label(), offer.monthly),
        None => format!("{} · {}", offer.plan.label(), offer.monthly),
    }
}

/// A list line with a gray check: a list, not a success.
fn check_line(ui: &mut egui::Ui, line: &str) {
    ui.horizontal(|ui| {
        kit::paint_icon_in(ui, Icon::Check, 12.0, kit::SECONDARY);
        ui.add(Label::new(kit::text(line, Font::Body).color(kit::LABEL)).wrap());
    });
}

/// The open, unlocked vault that does not sync through Apassy yet: the one that C3
/// offers to switch.
fn vault_to_switch(app: &DesktopApp) -> Option<(String, String)> {
    let entry = app.current_vault()?;
    if app.owner_ui.session.is_locked() || app.is_relay(&entry.id) {
        return None;
    }
    Some((entry.id.clone(), entry.name.clone()))
}

/// The Upgrade sheet for a paid feature picked at `from` (flow spec M4, C1 to C3).
/// Returns whether Escape closes it. With no offer it closes at once.
pub(super) fn upgrade_sheet(app: &mut DesktopApp, ctx: &egui::Context, from: UpgradeFrom) -> bool {
    let Some(offer) = offer(app, from) else {
        close_sheet(app, ctx);
        return false;
    };
    if app.ui.plan.upgraded.is_some() {
        return upgraded_sheet(app, ctx, &offer);
    }
    if app.ui.plan.checkout.is_some() {
        return waiting_sheet(app, ctx, &offer);
    }
    let (headline, lines) = upgrade_words(from);
    let mut checkout = false;
    let mut not_now = false;
    let mut compare = false;
    let response = kit::sheet(ctx, "plan-upgrade", 460.0, |ui| {
        kit::sheet_title(ui, headline, None);
        for line in lines {
            check_line(ui, line);
        }
        ui.add_space(10.0);
        kit::paragraph(ui, price_line(&offer), Font::Body, kit::LABEL);
        if from == UpgradeFrom::Sync {
            kit::note(
                ui,
                "Includes shared vaults with a few people, when they are ready.",
            );
        }
        ui.add_space(10.0);
        kit::note(ui, REASSURANCE);
        ui.add_space(8.0);
        kit::sheet_buttons(
            ui,
            |ui| {
                compare = kit::button(ui, "Compare plans", Style::Link).clicked();
            },
            |ui| {
                checkout = kit::button(ui, "Continue to checkout", Style::Prominent).clicked();
                not_now = kit::button(ui, "Not now", Style::Bordered).clicked();
            },
        );
    });
    if checkout {
        let url = app.plan.checkout_url(from);
        if app.plan_open_link(url) {
            let now = Instant::now();
            app.ui.plan.check_error = None;
            app.ui.plan.checkout = Some(Checkout {
                from,
                started: now,
                next_check: now + CHECK_EVERY,
            });
        }
    } else if compare {
        app.ui.sheet = Some(Sheet::Plan(PlanSheet::Compare { back: Some(from) }));
    } else if not_now {
        close_sheet(app, ctx);
    }
    response.escape
}

/// C2: the owner pays in the browser. "Check again" asks the account service; "Cancel"
/// leaves everything as it was.
fn waiting_sheet(app: &mut DesktopApp, ctx: &egui::Context, offer: &Offer) -> bool {
    let checking = app.ui.plan.checking.is_some();
    let late = app
        .ui
        .plan
        .checkout
        .as_ref()
        .is_some_and(|checkout| checkout.started.elapsed() >= NOT_CONFIRMED_AFTER);
    let error = app.ui.plan.check_error.clone();
    let mut check = false;
    let mut cancel = false;
    let response = kit::sheet(ctx, "plan-upgrade-waiting", 460.0, |ui| {
        kit::sheet_title(
            ui,
            WAITING_TITLE,
            Some(&format!(
                "Apassy turns {} on when the payment is done.",
                offer.plan.label()
            )),
        );
        if checking {
            ui.horizontal(|ui| {
                ui.add(egui::Spinner::new().size(12.0));
                kit::note(ui, "Apassy checks your plan…");
            });
        }
        if let Some(error) = &error {
            kit::tone_note(ui, error, Tone::Warning);
        }
        if late {
            kit::paragraph(ui, NOT_CONFIRMED, Font::Callout, kit::SECONDARY);
        }
        ui.add_space(8.0);
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                check = ui
                    .add_enabled_ui(!checking, |ui| {
                        kit::button(ui, "Check again", Style::Prominent)
                    })
                    .inner
                    .clicked();
                cancel = kit::button(ui, "Cancel", Style::Bordered).clicked();
            },
        );
    });
    if check {
        app.plan_check(None);
    }
    if cancel {
        close_sheet(app, ctx);
        app.plan_forget_checkout();
    }
    response.escape
}

/// C3: "Personal is on." and the switch of the open vault, or "Done".
fn upgraded_sheet(app: &mut DesktopApp, ctx: &egui::Context, offer: &Offer) -> bool {
    let target = vault_to_switch(app);
    let mut switch = false;
    let mut later = false;
    let response = kit::sheet(ctx, "plan-upgraded", 460.0, |ui| {
        ui.horizontal(|ui| {
            kit::paint_icon_in(ui, Icon::CheckCircle, 18.0, Tone::Good.mark());
            ui.label(kit::text(
                format!("{} is on.", offer.plan.label()),
                Font::Title3,
            ));
        });
        ui.add_space(6.0);
        match &target {
            Some((_, name)) => {
                kit::paragraph(
                    ui,
                    format!("Switch “{name}” to Apassy now?"),
                    Font::Body,
                    kit::LABEL,
                );
                kit::note(ui, APASSY_LINE);
            }
            None => kit::note(ui, "A receipt is on its way to your email."),
        }
        ui.add_space(8.0);
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                if target.is_some() {
                    switch = kit::button(ui, "Switch to Apassy", Style::Prominent).clicked();
                    later = kit::button(ui, "Later", Style::Bordered).clicked();
                } else {
                    later = kit::button(ui, "Done", Style::Prominent).clicked();
                }
            },
        );
    });
    if switch && let Some((id, _)) = target {
        close_sheet(app, ctx);
        app.plan_forget_checkout();
        app.plan_switch_to_apassy(&id, ctx);
    } else if later {
        close_sheet(app, ctx);
        app.plan_forget_checkout();
    }
    response.escape
}

/// A sheet of [`PlanSheet`]. Returns whether Escape closes it.
pub(super) fn sheet(app: &mut DesktopApp, ctx: &egui::Context, sheet: &PlanSheet) -> bool {
    match sheet {
        PlanSheet::Compare { back } => compare_sheet(app, ctx, *back),
        PlanSheet::SignOut => sign_out_sheet(app, ctx),
    }
}

/// What each plan has (ADR 0027 §1), for Compare plans. No plan is preselected, and none
/// is marked as the one to pick.
fn plan_columns(app: &DesktopApp) -> [(Plan, String, Vec<&'static str>); 3] {
    let offer = offer(app, UpgradeFrom::Plan).filter(|offer| offer.plan == Plan::Personal);
    let team = offer
        .as_ref()
        .and_then(|offer| offer.team.clone())
        .unwrap_or_else(|| "Billed per person".to_owned());
    let personal = offer
        .map(|offer| match offer.yearly {
            Some(yearly) => format!("{}, or {yearly}", offer.monthly),
            None => offer.monthly,
        })
        .unwrap_or_default();
    [
        (
            Plan::Free,
            "No account".to_owned(),
            vec![
                "Sync through iCloud Drive",
                "Other folders: Dropbox, a network share",
                "Approvals on all your devices",
            ],
        ),
        (
            Plan::Personal,
            personal,
            vec![
                "Everything in Free",
                "Sync through Apassy, in seconds, also without iCloud",
                "Shared vaults with a few people, when they are ready",
            ],
        ),
        (
            Plan::Team,
            team,
            vec![
                "Everything in Personal",
                "Shared vaults with roles",
                "Members managed in one place",
            ],
        ),
    ]
}

/// Compare plans: three columns of the same weight.
fn compare_sheet(app: &mut DesktopApp, ctx: &egui::Context, back: Option<UpgradeFrom>) -> bool {
    let current = standing(app).1.plan;
    let free = current == Plan::Free;
    let columns = plan_columns(app);
    let mut choose = false;
    let mut close = false;
    let response = kit::sheet(ctx, "plan-compare", 620.0, |ui| {
        kit::sheet_title(
            ui,
            "Compare plans",
            Some("Approvals on all your devices are part of every plan."),
        );
        ui.columns(3, |cols| {
            for (col, (plan, price, lines)) in cols.iter_mut().zip(&columns) {
                egui::Frame::NONE
                    .fill(kit::SURFACE)
                    .stroke(egui::Stroke::new(1.0, kit::SECTION_EDGE))
                    .corner_radius(egui::CornerRadius::same(10))
                    .inner_margin(egui::Margin::same(12))
                    .show(col, |ui| {
                        ui.set_width(ui.available_width());
                        ui.set_min_height(176.0);
                        ui.spacing_mut().item_spacing.y = 6.0;
                        ui.horizontal(|ui| {
                            ui.label(kit::text(plan.label(), Font::Headline));
                            if *plan == current {
                                kit::tag(ui, "Your plan", Tone::Neutral);
                            }
                        });
                        if !price.is_empty() {
                            kit::note(ui, price);
                        }
                        for line in lines {
                            check_line_small(ui, line);
                        }
                        if *plan == Plan::Personal && free && back.is_none() {
                            ui.add_space(4.0);
                            choose = kit::small_button(ui, "Choose Personal…", Style::Bordered)
                                .clicked();
                        }
                    });
            }
        });
        ui.add_space(6.0);
        kit::note(ui, REASSURANCE);
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                let label = if back.is_some() { "Back" } else { "Done" };
                close = kit::button(ui, label, Style::Prominent).clicked();
            },
        );
    });
    if choose {
        app.plan_open_upgrade(UpgradeFrom::Plan);
    } else if close {
        match back {
            Some(from) => app.ui.sheet = Some(Sheet::Upgrade(from)),
            None => close_sheet(app, ctx),
        }
    }
    response.escape
}

fn check_line_small(ui: &mut egui::Ui, line: &str) {
    ui.horizontal_top(|ui| {
        kit::paint_icon_in(ui, Icon::Check, 11.0, kit::SECONDARY);
        ui.add(Label::new(kit::text(line, Font::Callout).color(kit::LABEL)).wrap());
    });
}

/// "Sign out of this Mac?": the plan becomes Free here; the vault stays.
fn sign_out_sheet(app: &mut DesktopApp, ctx: &egui::Context) -> bool {
    let busy = app.ui.plan.signing_out.is_some();
    let mut sign_out = false;
    let mut cancel = false;
    let response = kit::sheet(ctx, "plan-sign-out", 440.0, |ui| {
        kit::sheet_title(
            ui,
            "Sign out of this Mac?",
            Some(
                "Sync through Apassy stops on this Mac. Your vault stays here, and approvals stay on all your devices. Sign in again to sync through Apassy.",
            ),
        );
        kit::sheet_buttons(
            ui,
            |ui| {
                sign_out = ui
                    .add_enabled_ui(!busy, |ui| kit::button(ui, "Sign out", Style::Destructive))
                    .inner
                    .clicked();
            },
            |ui| {
                cancel = kit::alert_cancel(ui).clicked();
            },
        );
    });
    if sign_out {
        let provider = app.plan.clone();
        app.ui.plan.signing_out = Some(Task::spawn(Some(ctx.clone()), move || provider.sign_out()));
    }
    if cancel {
        close_sheet(app, ctx);
    }
    response.escape
}

/// "Personal ended" (flow spec Flow E). Returns whether Escape closes it.
pub(super) fn ended_sheet(app: &mut DesktopApp, ctx: &egui::Context) -> bool {
    let entry = app.current_vault().cloned();
    let Some(entry) = entry.filter(|entry| app.is_relay(&entry.id)) else {
        close_sheet(app, ctx);
        return false;
    };
    let plan = standing(app).1.plan;
    let plan = if plan.is_paid() { plan } else { Plan::Personal };
    let icloud = super::sync::icloud_on(app);
    let portal = app.plan.portal_url();
    let mut move_sync = false;
    let mut off = false;
    let mut manage = false;
    let response = kit::sheet(ctx, "plan-ended", 460.0, |ui| {
        kit::sheet_title(
            ui,
            &format!("{} ended", plan.label()),
            Some("Your vault stays on all your devices. Sync moves to iCloud Drive."),
        );
        kit::note(
            ui,
            format!(
                "Approvals stay on all your devices. Apassy deletes its copy of “{}” 30 days after the end.",
                entry.name
            ),
        );
        if icloud.is_none() {
            kit::tone_note(
                ui,
                "iCloud Drive is off on this Mac. Turn it on in System Settings, or turn sync off.",
                Tone::Warning,
            );
        }
        ui.add_space(8.0);
        kit::sheet_buttons(
            ui,
            |ui| {
                if portal.is_some() {
                    manage = kit::button(ui, "Manage subscription", Style::Link).clicked();
                }
            },
            |ui| {
                move_sync = ui
                    .add_enabled_ui(icloud.is_some(), |ui| {
                        kit::button(ui, "Move sync to iCloud Drive", Style::Prominent)
                    })
                    .inner
                    .clicked();
                off = kit::button(ui, "Turn sync off", Style::Bordered).clicked();
            },
        );
    });
    if move_sync && let Some(folder) = icloud {
        close_sheet(app, ctx);
        app.plan_leave_apassy(&entry.id, Some(folder), ctx);
    } else if off {
        close_sheet(app, ctx);
        app.plan_leave_apassy(&entry.id, None, ctx);
    } else if manage {
        app.plan_open_link(portal);
    }
    response.escape
}

impl DesktopApp {
    /// Open the Upgrade sheet for a pick at `from`. A wait of an earlier checkout goes.
    pub(crate) fn plan_open_upgrade(&mut self, from: UpgradeFrom) {
        self.plan_forget_checkout();
        self.ui.sheet = Some(Sheet::Upgrade(from));
    }

    /// The links of the plan stay in the window instead of the browser: the screenshot
    /// tour, which must not open a page of the synthetic account service.
    #[doc(hidden)]
    pub fn hold_plan_links(&mut self) {
        self.ui.plan.hold_links = true;
    }

    /// Open `url` of the account service in the browser. Returns whether it opened.
    pub(crate) fn plan_open_link(&mut self, url: Option<String>) -> bool {
        let Some(url) = url else {
            self.set_err("Apassy has no link for this yet.");
            return false;
        };
        // A test never opens the browser.
        if !self.ui.plan.hold_links
            && !cfg!(test)
            && let Err(text) = crate::desktop::update::open(std::ffi::OsStr::new(&url))
        {
            self.set_err(text);
            return false;
        }
        self.ui.plan.opened.push(url);
        true
    }

    /// The checkout of the Upgrade sheet started `age` ago, for a test.
    #[cfg(test)]
    pub(crate) fn plan_age_checkout_for_test(&mut self, age: Duration) {
        if let Some(checkout) = self.ui.plan.checkout.as_mut()
            && let Some(started) = Instant::now().checked_sub(age)
        {
            checkout.started = started;
        }
    }

    /// The Upgrade sheet stops waiting for the browser.
    fn plan_forget_checkout(&mut self) {
        let plan = &mut self.ui.plan;
        plan.checkout = None;
        plan.upgraded = None;
        plan.check_error = None;
    }

    /// Ask the account service for the plan on its own thread ("Check again"). `ctx`
    /// wakes the window with the answer.
    fn plan_check(&mut self, ctx: Option<&egui::Context>) {
        if self.ui.plan.checking.is_some() {
            return;
        }
        let provider = self.plan.clone();
        self.ui.plan.check_error = None;
        self.ui.plan.checking = Some(Task::spawn(ctx.cloned(), move || provider.refresh()));
    }

    /// The vault `id` moves to Apassy (flow spec Flow B): its own Apassy Connect team
    /// gets sync. A vault with no team gets one first, with the owner check of a new
    /// device list; a vault whose team another Mac made joins it first. Never a second
    /// team.
    pub(crate) fn plan_switch_to_apassy(&mut self, id: &str, ctx: &egui::Context) {
        if switching(self, id) {
            return;
        }
        if self.relay_membership_team(id).is_some() {
            self.plan_ask_switch(id, Some(ctx));
            return;
        }
        let Some(entry) = self.vault_list.registry.get(id).cloned() else {
            return;
        };
        if self.vault_list.current.as_deref() != Some(id) || self.owner_ui.session.is_locked() {
            return self.set_err("Unlock the vault first. Nothing changed.");
        }
        let other_mac = self
            .owner_ui
            .session
            .with_vault(|vault| existing_questions_team(vault).ok().flatten())
            .flatten();
        if other_mac.is_some() {
            return self.set_err(
                "Another Mac connected this vault to Apassy. Add this Mac from that Mac in Settings > Devices, then switch. Nothing changed.",
            );
        }
        // The new device list needs the owner check; the switch follows when it is made.
        let url = self.connect_relay_url();
        self.questions_ask_connect(&entry, &url, Some(ctx));
        self.ui.plan.switch_after_connect = Some(id.to_owned());
    }

    /// The other devices of the vault's team that would start to sync the vault: each
    /// row of the Devices hub but this Mac and the iPhones paired on this Wi-Fi only.
    pub(crate) fn plan_sync_devices(&mut self) -> Vec<String> {
        self.devices_hub()
            .rows
            .into_iter()
            .filter(|row| row.kind != super::devices::DeviceKind::ThisMac)
            .filter(|row| !matches!(row.remove, Some(super::devices::Removal::Wifi { .. })))
            .map(|row| row.name)
            .collect()
    }

    /// The owner check for the switch of the vault `id` to Apassy in its own team. The
    /// check names the team and the devices that start to sync the vault; nothing
    /// changes before it passes ([`Self::plan_switch_with`]).
    fn plan_ask_switch(&mut self, id: &str, ctx: Option<&egui::Context>) {
        let Some(team_id) = self.relay_membership_team(id) else {
            return self.set_err("Unlock the vault first. Nothing changed.");
        };
        let Some(name) = self
            .vault_list
            .registry
            .get(id)
            .map(|entry| entry.name.clone())
        else {
            return;
        };
        let devices = self.plan_sync_devices();
        self.ask_owner(
            crate::desktop::owner_check::OwnerRequest::SyncThroughApassy {
                vault: id.to_owned(),
                name,
                team_id,
                devices,
            },
            ctx,
        );
    }

    /// After the owner check of the switch: `proof` must name this team and these
    /// devices, in this vault session, and the team must still have exactly these
    /// devices. Then sync turns on in the team, on its own thread.
    pub(crate) fn plan_switch_with(
        &mut self,
        id: &str,
        team_id: &str,
        devices: Vec<String>,
        proof: crate::broker::approvals::OwnerProof,
    ) {
        let expected = crate::broker::approvals::OwnerAction::SyncThroughApassy {
            team_id: team_id.to_owned(),
            devices: devices.clone(),
        };
        let checked = self
            .owner_ui
            .session
            .with_vault(|vault| proof.check(&expected, &vault.epoch()));
        match checked {
            Some(Ok(())) => {}
            Some(Err(refusal)) => return self.set_err(refusal.message()),
            None => return self.set_err("Unlock the vault first. Nothing changed."),
        }
        if self.vault_list.current.as_deref() != Some(id)
            || self.relay_membership_team(id).as_deref() != Some(team_id)
        {
            return self.set_err("The open vault changed. Nothing changed.");
        }
        if self.plan_sync_devices() != devices {
            return self.set_err(
                "The devices of this vault changed during the check. Nothing changed. Switch again to see them.",
            );
        }
        match self.relay_enable_on_membership(id) {
            Ok(switch) => self.ui.plan.switching = Some(switch),
            Err(text) => self.set_err(text),
        }
    }

    /// Leave sync through Apassy for the vault `id` after a plan ended (flow spec Flow
    /// E): sync with `folder`, or off. The device of this Mac stays in the vault's team,
    /// so approvals stay; only the purpose `sync` goes, with no relay call. A vault
    /// whose relay team is only for sync uses the "Turn off" sheet of the relay.
    fn plan_leave_apassy(
        &mut self,
        id: &str,
        folder: Option<std::path::PathBuf>,
        ctx: &egui::Context,
    ) {
        let Some(name) = self
            .vault_list
            .registry
            .get(id)
            .map(|entry| entry.name.clone())
        else {
            return;
        };
        let shared_team = self
            .vault_list
            .registry
            .get(id)
            .and_then(|entry| entry.sync_relay())
            .map(|link| link.team_id.clone())
            .is_some_and(|team| self.relay_membership_team(id) == Some(team));
        if !shared_team {
            match folder {
                Some(folder) => self.relay_switch_to_folder(id, folder, Some(ctx)),
                None => self.sync_open_sheet(SyncSheet::TurnOff { id: id.to_owned() }, Some(ctx)),
            }
            return;
        }
        self.sync_disable(id);
        match folder {
            Some(folder) => match self.sync_enable(id, &folder) {
                Ok(text) => self.set_ok(format!("{text} Approvals stay on all your devices.")),
                Err(text) => self.set_err(format!(
                    "Sync through Apassy of “{name}” is off. {text}"
                )),
            },
            None => self.set_ok(format!(
                "Sync of “{name}” is off. The vault stays on this Mac, and approvals stay on all your devices."
            )),
        }
    }

    /// Each frame: the answers of the account service and of the relay, the wait of the
    /// Upgrade sheet, and "Personal ended" once.
    pub(crate) fn plan_poll(&mut self, ctx: &egui::Context) {
        self.plan_poll_checks();
        self.plan_poll_switch(ctx);
        let upgrading = matches!(self.ui.sheet, Some(Sheet::Upgrade(_)));
        if !upgrading {
            // The sheet closed: the wait ends with it.
            if self.ui.plan.checkout.is_some() || self.ui.plan.upgraded.is_some() {
                self.plan_forget_checkout();
            }
        } else if let Some(checkout) = &self.ui.plan.checkout {
            if paid(self) {
                self.ui.plan.upgraded = Some(checkout.from);
                self.ui.plan.checkout = None;
            } else if Instant::now() >= checkout.next_check {
                if let Some(checkout) = self.ui.plan.checkout.as_mut() {
                    checkout.next_check = Instant::now() + CHECK_EVERY;
                }
                self.plan_check(Some(ctx));
            } else {
                ctx.request_repaint_after(Duration::from_secs(1));
            }
        }
        self.plan_ended_once();
    }

    fn plan_poll_checks(&mut self) {
        let done = match self.ui.plan.checking.as_ref().map(Task::poll) {
            Some(TaskPoll::Done(result)) => Some(result.map(|_| ())),
            Some(TaskPoll::Lost) => Some(Err(PlanError::Unreachable)),
            _ => None,
        };
        if let Some(result) = done {
            self.ui.plan.checking = None;
            self.ui.plan.check_error = result.err().map(|error| sentence(&error.to_string()));
        }
        let signed_out = match self.ui.plan.signing_out.as_ref().map(Task::poll) {
            Some(TaskPoll::Done(result)) => Some(result),
            Some(TaskPoll::Lost) => Some(Err(PlanError::Unreachable)),
            _ => None,
        };
        if let Some(result) = signed_out {
            self.ui.plan.signing_out = None;
            if matches!(self.ui.sheet, Some(Sheet::Plan(PlanSheet::SignOut))) {
                self.ui.sheet = None;
            }
            match result {
                Ok(()) => self.set_ok(
                    "This Mac is signed out. Your vault stays here, and approvals stay on all your devices.",
                ),
                Err(error) => self.set_err(format!(
                    "This Mac is still signed in: {}",
                    sentence(&error.to_string())
                )),
            }
        }
    }

    fn plan_poll_switch(&mut self, ctx: &egui::Context) {
        if let Some(switch) = self.ui.plan.switching.take()
            && self.relay_membership_switch_poll(&switch).is_none()
        {
            self.ui.plan.switching = Some(switch);
            ctx.request_repaint_after(Duration::from_millis(200));
        }
        // The owner check and the new device list of a vault with no team come first.
        let Some(id) = self.ui.plan.switch_after_connect.clone() else {
            return;
        };
        let questions = &self.sync.relay.questions;
        let waits = self.owner.check.is_some() || questions.creating(&id);
        if waits {
            ctx.request_repaint_after(Duration::from_millis(200));
            return;
        }
        self.ui.plan.switch_after_connect = None;
        // The check was cancelled, or the team was not made: that said why already.
        self.sync.relay.questions.forget_connect();
        // The new team has only this Mac; the switch still asks, with what it names.
        if self.relay_membership_team(&id).is_some() {
            self.plan_ask_switch(&id, Some(ctx));
        }
    }

    /// "Personal ended" shows once per vault and session: the plan ended while the
    /// open, unlocked vault syncs through Apassy. It waits for another sheet to close.
    fn plan_ended_once(&mut self) {
        if self.ui.sheet.is_some() || self.owner.check.is_some() {
            return;
        }
        let entitlement = self.plan.current();
        let ended = entitlement.status == PlanStatus::Ended
            && matches!(entitlement.plan, Plan::Personal | Plan::Team);
        if !ended || self.owner_ui.session.is_locked() {
            return;
        }
        let Some(id) = self.vault_list.current.clone() else {
            return;
        };
        if !self.is_relay(&id) || self.ui.plan.ended_shown.contains(&id) {
            return;
        }
        self.ui.plan.ended_shown.insert(id);
        self.ui.sheet = Some(Sheet::PlanEnded);
    }
}

/// A message of the account service as a sentence.
fn sentence(text: &str) -> String {
    let mut chars = text.chars();
    let mut line = match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect::<String>(),
        None => String::new(),
    };
    if !line.ends_with('.') {
        line.push('.');
    }
    line
}

/// The Shared section of the sidebar with no shared vault (flow spec Flow D), when the
/// app offers a plan: on Free, a line and "See plans"; on a paid plan, "New shared
/// vault…" that is not built yet. Returns false when there is nothing to show.
pub(super) fn shared_empty(app: &mut DesktopApp, ui: &mut egui::Ui) -> bool {
    if offer(app, UpgradeFrom::Shared).is_none() {
        return false;
    }
    let paid = paid(app);
    let mut see_plans = false;
    ui.horizontal(|ui| {
        ui.add_space(8.0);
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 4.0;
            if paid {
                ui.add_enabled_ui(false, |ui| {
                    kit::small_button(ui, "New shared vault…", Style::Bordered)
                });
                ui.label(kit::text(COMING_SOON, Font::Footnote).color(kit::TERTIARY));
            } else {
                ui.add(
                    Label::new(kit::text(SHARED_LINE, Font::Callout).color(kit::SECONDARY)).wrap(),
                );
                see_plans = kit::small_button(ui, SEE_PLANS, Style::Link).clicked();
            }
        });
    });
    if see_plans {
        app.plan_open_upgrade(UpgradeFrom::Shared);
    }
    true
}
