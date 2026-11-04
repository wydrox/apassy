//! One-time passwords (TOTP) on the credential pages.
//!
//! A one-time password is a hidden custom detail whose label says so (`otp::is_otp_label`),
//! or whose stored value is an explicit `otpauth://totp/` link under any label. The owner
//! store makes this choice and sets `DetailLine::totp`; the page never reads the seed to
//! make it. The importers store it the same way. The value is a setup key or a link. So
//! the vault format does not change, and the label stays as the owner typed it.
//!
//! - The login form has one input for it. The input is a secret input. It never shows the
//!   value of a stored seed. A detail with the label of a one-time password, or with an
//!   explicit `otpauth://totp` link, is always a hidden detail in every form.
//! - The credential page shows each code as a row of its first group, after the password
//!   rows. The row has the label as the owner typed it, the mask of the Password row, and
//!   "Copy" and "Show", in the order of the Password row.
//! - "Show" asks for the check of [`OwnerRequest::ShowCode`] for that one field. The
//!   session then loads only that seed. The row shows the code, the seconds left, "Hide",
//!   and "Copy". "Hide" hides that row only. The page borrows the seed from the session
//!   for the frame. It never shows the seed, and it never writes a seed or a code to a
//!   log. The password and the other codes stay as they were.
//! - "Copy" needs no "Show" first. It asks for its own check with
//!   [`OwnerRequest::CopyCode`]. The desktop owns the copy and the clipboard. It clears
//!   the clipboard after [`MIN_CLEAR`] to [`MAX_CLEAR`] if the clipboard still holds the
//!   code.
//! - Both checks are the usual owner check: Touch ID or the passphrase, inside the window
//!   of "How often to ask". Only while a code is visible, the note under the group says
//!   how long it stays visible and when the clipboard clears.
//! - A visible custom detail that looks like a setup key is not drawn. The page says that
//!   it is hidden for safety (`exposes_setup_key`).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use eframe::egui::{self, Align, CornerRadius, Layout, Sense, Vec2};

use super::detail_rows as rows;
use super::items::set_hidden;
use super::kit::{self, Font, Section, Tone};
use super::{SECRET_VALUE_CAPACITY, forget_secret_field, presize, secure_input};
use crate::contracts::CredentialKind;
use crate::desktop::DesktopApp;
use crate::desktop::clipboard::{MAX_CLEAR, MIN_CLEAR};
use crate::desktop::model::{DetailDraft, ItemDraft};
use crate::desktop::owner_check::OwnerRequest;
use crate::desktop::owner_store::{DetailLine, MAX_DETAILS, OwnerDetails, SecretForm};
use crate::otp::{self, OtpError, Totp};

/// Below this many seconds the countdown turns to a warning color.
const LOW_SECONDS: u64 = 5;
/// The page shows whole seconds of the clock (`kit::now`): the code and its seconds
/// change only when the second changes. While it shows a code, it redraws this long
/// after each whole second. egui wakes a frame a little early (by the time that it
/// predicts for a frame, about 17 ms), so the margin keeps the frame after the change.
const AFTER_SECOND: Duration = Duration::from_millis(40);

/// How long until the frame after the next whole second of `now`.
pub(super) fn until_next_second(now: SystemTime) -> Duration {
    let into = now
        .duration_since(UNIX_EPOCH)
        .map_or(Duration::ZERO, |since| {
            Duration::from_nanos(u64::from(since.subsec_nanos()))
        });
    Duration::from_secs(1).saturating_sub(into) + AFTER_SECOND
}

// ---- The credential page. ----

/// A hidden custom detail that holds a one-time password. The owner store decides: the
/// detail has the label of a one-time password, or its stored value is an explicit
/// `otpauth://totp` link under any label. The page keeps the label as the owner typed it
/// and never gets the seed.
pub(super) fn is_otp_detail(detail: &DetailLine) -> bool {
    detail.hidden && detail.totp
}

fn is_otp_draft(detail: &DetailDraft) -> bool {
    detail.hidden && otp::is_otp_label(&detail.label)
}

/// A visible custom detail that holds a setup key: it has the label of a one-time
/// password, or its value is an explicit `otpauth://totp` link. The page does not draw its
/// value. A visible detail with another label and another value is an ordinary detail.
pub(super) fn exposes_setup_key(detail: &DetailLine) -> bool {
    !detail.hidden
        && detail
            .value
            .as_deref()
            .is_some_and(|value| otp::is_otp_label(&detail.label) || otp::is_totp_uri(value))
}

/// The content of the row for a visible detail with a setup key. It has the label and no
/// value.
pub(super) fn exposed_content(ui: &mut egui::Ui, detail: &DetailLine) {
    ui.label(kit::text(&detail.label, Font::Callout).color(kit::palette().secondary));
    rows::mask(ui);
    kit::note(
        ui,
        "Apassy hides this setup key. Edit the credential to store it as a one-time password.",
    );
}

/// Whether the owner must not see this draft detail as plain text: its label is the label
/// of a one-time password, or its value is an explicit `otpauth://totp` link.
fn needs_hiding(detail: &DetailDraft) -> bool {
    otp::is_otp_label(&detail.label) || otp::is_totp_uri(&detail.value)
}

/// Make a custom detail that holds a setup key a hidden detail, in the secret `secret`
/// buffer of its slot. The value moves into the secret form, so it has the fixed buffer
/// and the erase rules of the other hidden details. Returns whether the detail changed.
/// A visible detail with another label and another value stays as it is.
pub(super) fn hide_setup_key(
    ctx: &egui::Context,
    salt: &str,
    index: usize,
    detail: &mut DetailDraft,
    secret: &mut String,
) -> bool {
    if detail.hidden || !needs_hiding(detail) {
        return false;
    }
    presize(secret, SECRET_VALUE_CAPACITY);
    set_hidden(detail, secret, true);
    // The undo history of the slot never holds the text (F1).
    forget_secret_field(ctx, &format!("{salt}-detail-{index}"));
    true
}

/// [`hide_setup_key`] for each custom detail of the form. Returns whether one changed.
pub(super) fn protect_form(
    ctx: &egui::Context,
    salt: &str,
    form: &mut ItemDraft,
    secrets: &mut SecretForm,
) -> bool {
    let mut changed = false;
    for (index, detail) in form.details.iter_mut().enumerate().take(MAX_DETAILS) {
        changed |= hide_setup_key(ctx, salt, index, detail, &mut secrets.details[index]);
    }
    changed
}

/// Whether the row of a custom detail must keep its Hidden switch on.
pub(super) fn is_locked_hidden(detail: &DetailDraft) -> bool {
    detail.hidden && otp::is_otp_label(&detail.label)
}

/// A code for the screen.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Code {
    /// The digits, with no space.
    pub(super) digits: String,
    /// Seconds until the code changes.
    pub(super) left: u64,
    /// The length of one code period, in seconds.
    pub(super) period: u64,
}

impl Code {
    /// The code of `seed` at `unix` seconds.
    pub(super) fn at(seed: &str, unix: u64) -> Result<Self, OtpError> {
        let totp = Totp::parse(seed)?;
        let (digits, left) = totp.code_at(unix);
        Ok(Self {
            digits,
            left,
            period: totp.period(),
        })
    }

    /// The digits in two groups: "482 913".
    pub(super) fn grouped(&self) -> String {
        let (head, tail) = self.digits.split_at(self.digits.len().div_ceil(2));
        format!("{head} {tail}")
    }
}

/// The code rows of one credential page: whether a code is visible, and what the owner
/// asked on a row.
#[derive(Debug, Default)]
pub(super) struct CodeRows {
    action: Option<CodeAction>,
    visible: bool,
}

/// A row for each one-time password of a credential, in its first group after the
/// password rows. Nothing for a credential without one.
pub(super) fn code_rows(
    app: &DesktopApp,
    group: &mut rows::Group<'_>,
    details: &OwnerDetails,
) -> CodeRows {
    code_rows_at(app, group, details, kit::now())
}

fn code_rows_at(
    app: &DesktopApp,
    group: &mut rows::Group<'_>,
    details: &OwnerDetails,
    unix: u64,
) -> CodeRows {
    let mut codes = CodeRows::default();
    for line in details.details.iter().filter(|d| is_otp_detail(d)) {
        // The seed of this one field, opened by its own owner check. The page borrows it
        // from the session for this frame only.
        let code = app
            .owner_ui
            .session
            .code_seed(details.id, &line.name)
            .map(|seed| Code::at(seed, unix));
        codes.visible |= matches!(code, Some(Ok(_)));
        if let Some(clicked) = code_row(group, line, code.as_ref()) {
            codes.action = Some(clicked);
        }
    }
    codes
}

impl CodeRows {
    /// Whether the owner clicked a button of a code row.
    pub(super) fn clicked(&self) -> bool {
        self.action.is_some()
    }

    /// The note under the group while a code is visible. `None` while each code is
    /// masked.
    pub(super) fn note(&self) -> Option<String> {
        self.visible.then(|| {
            format!(
                "The code is visible for 30 seconds, or until you hide it or lock the vault. {}",
                clipboard_note()
            )
        })
    }

    /// Do what the owner asked on a code row, if anything.
    pub(super) fn answer(self, app: &mut DesktopApp, ctx: &egui::Context, item_id: u64) {
        match self.action {
            // Each row asks for its own field. The password and the other codes stay as
            // they are.
            Some(CodeAction::Show(field)) => {
                app.ask_owner(OwnerRequest::ShowCode { item_id, field }, Some(ctx));
            }
            Some(CodeAction::Hide(field)) => {
                app.owner_ui.session.hide_code(item_id, &field);
                app.set_ok("The code is hidden.");
            }
            Some(CodeAction::Copy(field)) => {
                app.ask_owner(OwnerRequest::CopyCode { item_id, field }, Some(ctx));
            }
            None => {}
        }
    }
}

/// When Apassy clears a copied code from the clipboard.
pub(super) fn clipboard_note() -> String {
    format!(
        "Apassy clears a copied code from the clipboard after {} to {} seconds if it still holds the code.",
        MIN_CLEAR.as_secs(),
        MAX_CLEAR.as_secs()
    )
}

/// What the owner asked on one code row. The value is the field of that row.
#[derive(Debug, PartialEq, Eq)]
enum CodeAction {
    Show(String),
    Hide(String),
    Copy(String),
}

/// One code, laid out as the Password row: the label, the mask, "Copy" and "Show". A
/// shown code has "Copy" and "Hide", and the code with its seconds under the line.
/// Returns what the owner asked on this row, if anything.
fn code_row(
    group: &mut rows::Group<'_>,
    line: &DetailLine,
    code: Option<&Result<Code, OtpError>>,
) -> Option<CodeAction> {
    group.row(|ui| {
        let mut action = None;
        let width = ui.available_width();
        ui.allocate_ui_with_layout(
            Vec2::new(width, 24.0),
            Layout::left_to_right(Align::Center),
            |ui| {
                ui.set_min_size(Vec2::new(width, 24.0));
                ui.label(kit::text(&line.label, Font::Body).color(kit::palette().label));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.spacing_mut().item_spacing.x = 10.0;
                    match code {
                        None => {
                            if show_button(ui, &line.label) {
                                action = Some(CodeAction::Show(line.name.clone()));
                            }
                            // Copy needs no Show first: it has its own owner check.
                            if copy_button(ui, &line.label) {
                                action = Some(CodeAction::Copy(line.name.clone()));
                            }
                            rows::mask(ui);
                        }
                        Some(code) => {
                            if hide_button(ui, &line.label) {
                                action = Some(CodeAction::Hide(line.name.clone()));
                            }
                            if code.is_ok() && copy_button(ui, &line.label) {
                                action = Some(CodeAction::Copy(line.name.clone()));
                            }
                        }
                    }
                });
            },
        );
        match code {
            None => {}
            Some(Ok(code)) => {
                ui.add_space(4.0);
                show_code(ui, code);
            }
            Some(Err(err)) => {
                ui.add_space(4.0);
                kit::tone_note(ui, err.to_string(), Tone::Critical);
            }
        }
        action
    })
}

fn show_code(ui: &mut egui::Ui, code: &Code) {
    let low = code.left <= LOW_SECONDS;
    let tone = if low { Tone::Warning } else { Tone::Accent };
    ui.horizontal(|ui| {
        let label = ui.label(
            kit::text(code.grouped(), Font::Mono)
                .size(26.0)
                .color(kit::palette().label),
        );
        ui.add_space(8.0);
        ui.label(
            kit::text(format!("{} s", code.left), Font::Callout).color(if low {
                tone.text()
            } else {
                kit::palette().secondary
            }),
        );
        let spoken = format!("One-time code {}, {} seconds left", code.digits, code.left);
        ui.ctx()
            .accesskit_node_builder(label.id, |node| node.set_label(spoken));
    });
    let width = ui.available_width().min(220.0);
    let (rect, _) = ui.allocate_exact_size(Vec2::new(width, 3.0), Sense::hover());
    let radius = CornerRadius::same(2);
    ui.painter()
        .rect_filled(rect, radius, kit::palette().separator);
    let fraction = code.left as f32 / code.period.max(1) as f32;
    let filled = egui::Rect::from_min_size(rect.min, Vec2::new(width * fraction.min(1.0), 3.0));
    ui.painter().rect_filled(filled, radius, tone.mark());
    ui.ctx()
        .request_repaint_after(until_next_second(SystemTime::now()));
}

/// The hover text of "Show" on a code row. The check is the usual owner check, as for
/// the Password row.
const SHOW_HOVER: &str = "Confirm with Touch ID or passphrase. The code is visible for 30 seconds.";

/// The hover text of "Copy" on a code row.
fn copy_hover() -> String {
    format!(
        "Confirm with Touch ID or passphrase. Clipboard clears after {} to {} seconds if unchanged.",
        MIN_CLEAR.as_secs(),
        MAX_CLEAR.as_secs()
    )
}

fn show_button(ui: &mut egui::Ui, label: &str) -> bool {
    rows::pill_button(ui, "Show", &format!("Show the code of {label}"))
        .on_hover_text(SHOW_HOVER)
        .clicked()
}

fn hide_button(ui: &mut egui::Ui, label: &str) -> bool {
    rows::pill_button(ui, "Hide", &format!("Hide the code of {label}"))
        .on_hover_text("Hide this code")
        .clicked()
}

fn copy_button(ui: &mut egui::Ui, label: &str) -> bool {
    rows::pill_button(ui, "Copy", &format!("Copy the code of {label}"))
        .on_hover_text(copy_hover())
        .clicked()
}

// ---- The login form. ----

/// The place of the one-time password in the custom details of a form. Only a login has
/// the dedicated input. Another kind keeps it in the list of custom details.
pub(super) fn dedicated_slot(form: &ItemDraft) -> Option<usize> {
    (form.kind == CredentialKind::Login)
        .then(|| form.details.iter().position(is_otp_draft))
        .flatten()
}

/// The input for the one-time password of a login. The typed value lives in the secret
/// form, in the slot of the detail, so it has the same fixed buffer and erase rules as
/// the other hidden details. A blank input keeps a stored value.
pub(super) fn form_row(
    section: &mut Section<'_>,
    salt: &str,
    form: &mut ItemDraft,
    secrets: &mut SecretForm,
) {
    if form.kind != CredentialKind::Login {
        return;
    }
    let found = dedicated_slot(form);
    // With no detail yet, the input uses the first free slot. It is blank.
    let index = found.unwrap_or(form.details.len());
    if index >= MAX_DETAILS {
        section.row(|ui| {
            kit::note(
                ui,
                format!(
                    "This login has {MAX_DETAILS} custom details. Remove one to add a one-time password."
                ),
            );
        });
        return;
    }
    let stored = found.is_some_and(|slot| form.details[slot].stored.is_some());
    let (hint, tone) = hint(&secrets.details[index], stored);
    let placeholder = if stored {
        "Unchanged"
    } else {
        "Setup key or otpauth:// link"
    };
    let response = section.field_with_hint("One-time password", Some((&hint, tone)), |ui| {
        secure_input(
            ui,
            &format!("{salt}-detail-{index}"),
            &mut secrets.details[index],
            SECRET_VALUE_CAPACITY,
            placeholder,
        )
    });
    let ctx = response.ctx;
    let remove = stored
        && section
            .clickable_row("Remove one-time password", |ui| {
                ui.label(
                    kit::text("Remove one-time password", Font::Body).color(Tone::Critical.text()),
                );
            })
            .clicked();
    let before = form.details.len();
    if remove {
        drop_slot(form, secrets, index);
    } else {
        sync_slot(form, secrets, index);
    }
    if form.details.len() < before {
        // The details moved, so no field keeps an undo history of another detail (F1).
        for index in 0..MAX_DETAILS {
            forget_secret_field(&ctx, &format!("{salt}-detail-{index}"));
        }
    }
}

/// The line under the input: what it takes, or what the typed value makes.
fn hint(typed: &str, stored: bool) -> (String, Tone) {
    if typed.trim().is_empty() {
        let text = if stored {
            "Leave blank to keep the stored value."
        } else {
            "Optional. Paste the setup key or the otpauth link of the website."
        };
        return (text.to_owned(), Tone::Neutral);
    }
    match Totp::parse(typed) {
        Ok(totp) => (
            format!(
                "Apassy makes a {}-digit code every {} seconds.",
                totp.digits(),
                totp.period()
            ),
            Tone::Neutral,
        ),
        Err(err) => (err.to_string(), Tone::Critical),
    }
}

/// Keep the detail of the form in step with the input in slot `index`: typed text makes
/// the detail, and a blank input removes a detail that is not stored.
fn sync_slot(form: &mut ItemDraft, secrets: &mut SecretForm, index: usize) {
    use zeroize::Zeroize;

    let typed = !secrets.details[index].trim().is_empty();
    match form.details.get(index) {
        None if typed => form.details.push(DetailDraft {
            label: unique_label(form),
            value: String::new(),
            hidden: true,
            stored: None,
        }),
        None => secrets.details[index].zeroize(),
        Some(detail) if !typed && detail.stored.is_none() => drop_slot(form, secrets, index),
        Some(_) => {}
    }
}

fn drop_slot(form: &mut ItemDraft, secrets: &mut SecretForm, index: usize) {
    form.details.remove(index);
    secrets.remove_detail(index);
}

/// "One-time password", or the first free "One-time password 2", "…3", and so on. The
/// label of a custom detail is unique on its item.
fn unique_label(form: &ItemDraft) -> String {
    let taken = |label: &str| {
        form.details
            .iter()
            .any(|detail| detail.label.trim().eq_ignore_ascii_case(label))
    };
    if !taken(otp::LABEL) {
        return otp::LABEL.to_owned();
    }
    (2..)
        .map(|number| format!("{} {number}", otp::LABEL))
        .find(|label| !taken(label))
        .unwrap_or_else(|| otp::LABEL.to_owned())
}

/// The check before a save. A typed one-time password must be a TOTP setting that
/// Apassy can read. Returns the message for the owner.
pub(super) fn check_form(form: &ItemDraft, secrets: &SecretForm) -> Result<(), String> {
    for (index, detail) in form.details.iter().enumerate() {
        let typed = secrets.details.get(index).map_or("", String::as_str);
        if is_otp_draft(detail) && !typed.trim().is_empty() {
            Totp::parse(typed).map_err(|err| format!("{}: {err}", detail.label.trim()))?;
        }
    }
    Ok(())
}
