//! Who runs the bouncer brain, in Settings > Bouncer (ADR 0035 sections 1, 2, 4 and 5;
//! plan 0035 unit J1; mockup `docs/design/bouncer-hosting-mockup.html`).
//!
//! - [`runs_on_rows`]: the "Runs on" row at the top of the "Bouncer brain" group. Its
//!   menu has This Mac, My Server… and Apassy Connect, which stays disabled ("Coming
//!   with Connect") until the Connect sign-in (unit C3). The row names the host of the
//!   vault row, never the token. When the chosen host cannot be used, the brain runs on
//!   this Mac and the row says why ([`fallback_lines`]).
//! - [`sheet`]: "Use My Server". Step 1 takes the `https://` address and the token: a
//!   token that Apassy generates, with the start commands of the server to copy (a token
//!   file and `docker run`, never the token on a command line), or the owner's own.
//!   Step 2 is the consent screen of version [`HOSTING_CONSENT_VERSION`]: what leaves
//!   this Mac, what never does, and the trust warning. Its button asks the fresh owner
//!   check of `OwnerRequest::ChangeBouncerHosting`, which the global owner window never
//!   covers. The sheet closes only after a passed check.
//! - This Mac asks the owner check at once, without a sheet: the check names the change.
//!
//! The draft with the token is in [`super::brain_host::BouncerHostFlows`], not in the
//! UI state: it erases the token on drop, and it ends with the sheet, a lock, or another
//! vault ([`forget_closed_draft`]).

use std::sync::PoisonError;

use eframe::egui;
use zeroize::{Zeroize, Zeroizing};

use super::DesktopApp;
use super::owner_check::OwnerRequest;
use super::ui::kit::{self, Font, Style, Tone};
use super::ui::settings_rows as rows;
use super::ui::{Sheet, close_sheet, forget_secret_field, secure_input};
use crate::vault::{
    BouncerHost, BouncerHostChange, BouncerHostKind, BouncerHostRole, HOSTING_CONSENT_VERSION,
    MAX_BEARER_BYTES, SecretValue, docker_run_lines, generate_bearer, normalize_url, valid_bearer,
    valid_host_url,
};

/// The label of the row.
pub(crate) const RUNS_ON: &str = "Runs on";
/// The menu item of the owner's server. It opens the sheet.
pub(crate) const MY_SERVER_ITEM: &str = "My Server…";
/// The disabled menu item of Apassy Connect, and its note.
pub(crate) const CONNECT_ITEM: &str = "Apassy Connect";
pub(crate) const COMING_WITH_CONNECT: &str = "Coming with Connect";
const CONNECT_HOVER: &str = "Apassy Connect hosting comes with the Connect sign-in.";
/// The note of the row while a server runs the brain, after its host name.
pub(crate) const GATE_STAYS: &str = "The bouncer gate still decides on this Mac.";
/// The headline when the chosen host cannot be used.
pub(crate) const FALLBACK_HEADLINE: &str =
    "The chosen host cannot be used, so the bouncer brain runs on this Mac.";
const HELP_TITLE: &str = "Where the bouncer brain runs";
const HELP: [&str; 4] = [
    "This Mac: nothing leaves this Mac.",
    "My Server: your server answers over https with a token. Free.",
    "Apassy Connect: Apassy runs it for you. Comes with Connect.",
    "The bouncer gate on this Mac decides every run. No answer means Apassy asks you.",
];

/// The sheet: its titles, notes and buttons.
pub(crate) const SERVER_TITLE: &str = "Use My Server";
const SERVER_LEAD: &str =
    "Your server runs the bouncer brain. The bouncer gate still decides on this Mac.";
const ADDRESS_PLACEHOLDER: &str = "https://brain.your-tailnet.ts.net";
/// Under the address while it is not an `https://` address with a host name.
pub(crate) const ADDRESS_HINT: &str = "Use https:// and a host name.";
const ADDRESS_HELP: [&str; 2] = [
    "Use a public certificate, for example Tailscale Serve: tailscale serve --bg 8770.",
    "A private certificate does not work.",
];
pub(crate) const RUN_HEADER: &str = "Start your server with this token";
pub(crate) const TOKEN_SHOWN_ONCE: &str =
    "The token shows only here. Apassy keeps it in the vault on this Mac.";
/// How the token gets into the token file of the start commands.
pub(crate) const START_NOTE: &str = "Run these on your server. At the cat line, paste the token, press Return, then Control-D. The token never goes on a command line.";
const PASTE_HEADER: &str = "Token";
const PASTE_NOTE: &str = "The LAYA_API_KEY of your server: 16 to 512 characters.";
const TOKEN_PLACEHOLDER: &str = "LAYA_API_KEY";
/// The field name of the pasted token (its undo history is erased with the draft).
const TOKEN_FIELD: &str = "brain-host-token";
/// The masked token.
const MASK: &str = "••••••••••••••••";
pub(crate) const CONSENT_TITLE: &str = "What Leaves This Mac";
/// What goes to the server: exactly what `bouncer::state_text` puts in the state, with
/// the command of `bouncer::shorten_paths`, and the head sets that the trainer uploads
/// (ADR 0035 sections 4 and 7, ADR 0007 state). The broker sends no owner rule.
pub(crate) const SENT: [&str; 3] = [
    "The user request and the purpose",
    "The shell command, with paths in your project and home folder shortened",
    "The bouncer heads trained on your decisions (numbers, no text)",
];
/// What never leaves this Mac (ADR 0035 section 3).
pub(crate) const NEVER_SENT: [&str; 2] = [
    "Secret values",
    "The vault and the full paths of your project and home folder",
];
/// The trust warning of ADR 0035 section 5, before the owner selects a remote host. A
/// remote brain decides no production run (`broker::run` hard rules), and the hard
/// checks, rule flags such as secret output, and foreign hosts come before the model.
pub(crate) const TRUST_WARNING: &str = "A server that someone else controls can make the bouncer run development and staging commands without asking you. It can never allow production, a hard check, secret output or another host.";
/// The button that asks the owner check.
pub(crate) const USE_SERVER: &str = "Use My Server";

/// The steps of the sheet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum HostingStep {
    /// The address and the token.
    #[default]
    Server,
    /// The consent screen.
    Consent,
}

/// The "Use My Server" sheet as the owner fills it. The token is erased on drop; `Debug`
/// shows no token.
pub(crate) struct HostingDraft {
    /// The vault session of the sheet. Another session ends the draft.
    epoch: [u8; 32],
    pub(crate) step: HostingStep,
    pub(crate) address: String,
    /// The token that Apassy generated when the sheet opened.
    generated: SecretValue,
    /// The owner pastes a token of their own instead.
    pub(crate) paste: bool,
    pasted: String,
    /// The sheet shows the generated token in clear.
    pub(crate) shown: bool,
}

impl std::fmt::Debug for HostingDraft {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostingDraft")
            .field("step", &self.step)
            .field("address", &self.address)
            .field("paste", &self.paste)
            .field("shown", &self.shown)
            .finish_non_exhaustive()
    }
}

impl Drop for HostingDraft {
    fn drop(&mut self) {
        self.pasted.zeroize();
    }
}

impl HostingDraft {
    /// A new draft with a new generated token, in the vault session `epoch`.
    pub(crate) fn new(epoch: [u8; 32]) -> Result<Self, String> {
        let generated = generate_bearer()
            .map_err(|_| "Apassy could not make a token. Nothing changed.".to_owned())?;
        Ok(Self {
            epoch,
            step: HostingStep::Server,
            address: String::new(),
            generated,
            paste: false,
            pasted: String::new(),
            shown: false,
        })
    }

    /// The token that the change will store.
    fn token(&self) -> &str {
        if self.paste {
            self.pasted.trim()
        } else {
            self.generated.expose()
        }
    }

    /// The address is an `https://` address with a host name.
    pub(crate) fn address_ok(&self) -> bool {
        valid_host_url(&normalize_url(&self.address))
    }

    /// Step 1 is complete: the address and the token are valid.
    pub(crate) fn ready(&self) -> bool {
        self.address_ok() && valid_bearer(self.token())
    }

    /// The host name of the address, for the texts.
    pub(crate) fn host(&self) -> String {
        host_of(&normalize_url(&self.address))
    }

    /// The generated token, to copy. It erases itself.
    pub(crate) fn token_copy(&self) -> Zeroizing<String> {
        Zeroizing::new(self.generated.expose().to_owned())
    }

    /// The generated token as the sheet shows it: masked unless the owner shows it.
    pub(crate) fn shown_token(&self) -> Zeroizing<String> {
        if self.shown {
            self.token_copy()
        } else {
            Zeroizing::new(MASK.to_owned())
        }
    }

    /// The change that the owner confirms: My Server, this address, this token, and
    /// the consent of this build. `None` while step 1 is not complete.
    pub(crate) fn change(&self) -> Option<BouncerHostChange> {
        self.ready().then(|| BouncerHostChange {
            kind: BouncerHostKind::OwnServer,
            url: normalize_url(&self.address),
            bearer: Some(SecretValue::new(self.token().to_owned())),
            consent_version: HOSTING_CONSENT_VERSION,
        })
    }

    /// Paste a token of the owner (tour and tests).
    pub(crate) fn set_pasted(&mut self, token: &str) {
        self.pasted.zeroize();
        self.pasted.push_str(token);
    }
}

/// The host name of an `https://` address, without the scheme and the path.
pub(crate) fn host_of(url: &str) -> String {
    let rest = url.strip_prefix("https://").unwrap_or(url);
    rest.split('/').next().unwrap_or_default().to_owned()
}

/// The menu label of a kind (macOS title case).
pub(crate) fn kind_title(kind: BouncerHostKind) -> &'static str {
    match kind {
        BouncerHostKind::ThisMac => "This Mac",
        BouncerHostKind::OwnServer => "My Server",
        BouncerHostKind::Connect => "Apassy Connect",
    }
}

/// The note of the row for a stored host: its host name and that the gate stays here.
/// The token never shows.
pub(crate) fn host_note(host: &BouncerHost) -> String {
    format!("{} · {GATE_STAYS}", host_of(&host.url))
}

/// The fallback words: the headline and the reason, without a second "runs on this
/// Mac".
pub(crate) fn fallback_lines(problem: &str) -> (&'static str, String) {
    let reason = problem
        .trim()
        .trim_end_matches("The bouncer brain runs on this Mac.")
        .trim()
        .to_owned();
    (FALLBACK_HEADLINE, reason)
}

/// What the owner chose in the "Runs on" menu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RunsOnAction {
    /// Back to this Mac: the owner check at once.
    ThisMac,
    /// Open "Use My Server".
    MyServer,
}

/// The stored hosting choice of the open vault. `None`: the vault is locked.
fn stored_host(app: &DesktopApp) -> Option<Result<Option<BouncerHost>, String>> {
    let shared = app.owner_ui.session.shared_vault();
    let guard = shared.lock().unwrap_or_else(PoisonError::into_inner);
    let vault = guard.as_ref().filter(|vault| !vault.is_locked())?;
    Some(
        vault
            .bouncer_host(BouncerHostRole::Hosting)
            .map_err(|error| format!("The host of the bouncer brain did not load ({error}).")),
    )
}

/// The "Runs on" row, and the fallback rows when the chosen host cannot be used.
/// Nothing while the vault is locked.
pub(crate) fn runs_on_rows(app: &DesktopApp, g: &mut rows::Group<'_>) -> Option<RunsOnAction> {
    let stored = stored_host(app)?;
    let host = match stored {
        Ok(host) => host,
        Err(message) => {
            g.tone_row(message, Tone::Warning.text());
            return None;
        }
    };
    let kind = host
        .as_ref()
        .map_or(BouncerHostKind::ThisMac, |host| host.kind);
    let note = host.as_ref().map(host_note);
    let mut action = None;
    g.line_note(RUNS_ON, None, note.as_deref().map(rows::note), |ui| {
        kit::menu("brain-runs-on", kind_title(kind), 160.0).show_ui(ui, |ui| {
            ui.set_min_width(240.0);
            if ui
                .selectable_label(
                    kind == BouncerHostKind::ThisMac,
                    kind_title(BouncerHostKind::ThisMac),
                )
                .clicked()
            {
                if kind != BouncerHostKind::ThisMac {
                    action = Some(RunsOnAction::ThisMac);
                }
                ui.close();
            }
            if ui
                .selectable_label(kind == BouncerHostKind::OwnServer, MY_SERVER_ITEM)
                .clicked()
            {
                action = Some(RunsOnAction::MyServer);
                ui.close();
            }
            ui.separator();
            ui.add_enabled(
                false,
                egui::Button::selectable(kind == BouncerHostKind::Connect, CONNECT_ITEM)
                    .right_text(COMING_WITH_CONNECT),
            )
            .on_disabled_hover_text(CONNECT_HOVER);
        });
        kit::help_button(ui, HELP_TITLE, &HELP);
    });
    if let Some(problem) = &app.bouncer_host.problem {
        let (headline, reason) = fallback_lines(problem);
        g.tone_row(headline, Tone::Warning.text());
        if !reason.is_empty() {
            g.note_row(reason);
        }
    }
    action
}

/// Apply the choice of the menu.
pub(crate) fn apply(app: &mut DesktopApp, action: RunsOnAction, ctx: Option<&egui::Context>) {
    match action {
        RunsOnAction::ThisMac => app.ask_owner(
            OwnerRequest::ChangeBouncerHosting {
                change: BouncerHostChange::this_mac(),
            },
            ctx,
        ),
        RunsOnAction::MyServer => open_server_sheet(app),
    }
}

/// Open "Use My Server" with a new generated token.
pub(crate) fn open_server_sheet(app: &mut DesktopApp) {
    let Some(epoch) = app.owner_ui.session.epoch() else {
        app.set_err("The vault is locked. Nothing changed.");
        return;
    };
    match HostingDraft::new(epoch) {
        Ok(draft) => {
            app.bouncer_host.draft = Some(draft);
            app.ui.sheet = Some(Sheet::BrainHosting);
        }
        Err(message) => app.set_err(message),
    }
}

/// End a draft whose sheet is closed or whose vault session ended. A sheet without its
/// draft closes. Cheap; the window calls it each frame.
pub(crate) fn forget_closed_draft(app: &mut DesktopApp) {
    let open = matches!(app.ui.sheet, Some(Sheet::BrainHosting));
    let epoch = app.owner_ui.session.epoch();
    let live = app
        .bouncer_host
        .draft
        .as_ref()
        .is_some_and(|draft| Some(draft.epoch) == epoch);
    if !open || !live {
        app.bouncer_host.draft = None;
    }
    if open && !live {
        app.ui.sheet = None;
    }
}

/// Erase the draft and the undo history of its token field (from [`close_sheet`]).
pub(crate) fn forget(app: &mut DesktopApp, ctx: &egui::Context) {
    app.bouncer_host.draft = None;
    forget_secret_field(ctx, TOKEN_FIELD);
}

/// Ask the owner check for the draft. The sheet stays open under it and closes after a
/// passed check (`ui::close_sheet_after_check`).
pub(crate) fn submit(app: &mut DesktopApp, ctx: Option<&egui::Context>) {
    let Some(change) = app
        .bouncer_host
        .draft
        .as_ref()
        .and_then(HostingDraft::change)
    else {
        return;
    };
    app.ui.close_after_check = Some(app.status_seq);
    app.ask_owner(OwnerRequest::ChangeBouncerHosting { change }, ctx);
}

/// What the owner did in the sheet in one frame.
#[derive(Default)]
struct SheetActions {
    next: bool,
    back: bool,
    submit: bool,
    copy: bool,
    cancel: bool,
}

/// "Use My Server". Returns true on Escape.
pub(crate) fn sheet(app: &mut DesktopApp, ctx: &egui::Context) -> bool {
    forget_closed_draft(app);
    let Some(step) = app.bouncer_host.draft.as_ref().map(|draft| draft.step) else {
        return false;
    };
    let mut actions = SheetActions::default();
    let response = kit::sheet(ctx, "brain-hosting", 500.0, |ui| {
        let Some(draft) = app.bouncer_host.draft.as_mut() else {
            return;
        };
        match step {
            HostingStep::Server => server_step(ui, draft, &mut actions),
            HostingStep::Consent => consent_step(ui, draft, &mut actions),
        }
    });
    if actions.copy
        && let (Some(draft), Some(epoch)) = (
            app.bouncer_host.draft.as_ref(),
            app.owner_ui.session.epoch(),
        )
    {
        let line = draft.token_copy();
        match app
            .owner
            .clipboard
            .copy_secret(line, epoch, std::time::Instant::now())
        {
            Ok(_) => app
                .set_ok("Copied. Clears in 30 seconds if the clipboard still holds Apassy's copy."),
            Err(err) => app.set_err(err.message()),
        }
    }
    if let Some(draft) = app.bouncer_host.draft.as_mut() {
        if actions.next && draft.ready() {
            draft.step = HostingStep::Consent;
        }
        if actions.back {
            draft.step = HostingStep::Server;
        }
    }
    if actions.submit {
        submit(app, Some(ctx));
    }
    if actions.cancel {
        close_sheet(app, ctx);
    }
    response.escape
}

/// Step 1: the address and the token.
fn server_step(ui: &mut egui::Ui, draft: &mut HostingDraft, actions: &mut SheetActions) {
    kit::sheet_title(ui, SERVER_TITLE, Some(SERVER_LEAD));
    kit::sheet_body(ui, |ui| {
        let mut enter = false;
        kit::section(ui, None, None, |s| {
            let field = s.field("Address", |ui| {
                // The control fills the rest of the row; the ⓘ sits at its right end.
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    kit::help_button(ui, "The address", &ADDRESS_HELP);
                    kit::text_input(
                        ui,
                        &mut draft.address,
                        "brain-host-address",
                        ADDRESS_PLACEHOLDER,
                    )
                })
                .inner
            });
            enter |=
                field.lost_focus() && field.ctx.input(|input| input.key_pressed(egui::Key::Enter));
        });
        if !draft.address.trim().is_empty() && !draft.address_ok() {
            kit::tone_note(ui, ADDRESS_HINT, Tone::Warning);
        }
        if draft.paste {
            kit::section(ui, Some(PASTE_HEADER), Some(PASTE_NOTE), |s| {
                let field = s.field("Token", |ui| {
                    secure_input(
                        ui,
                        TOKEN_FIELD,
                        &mut draft.pasted,
                        4 * MAX_BEARER_BYTES,
                        TOKEN_PLACEHOLDER,
                    )
                });
                enter |= field.lost_focus()
                    && field.ctx.input(|input| input.key_pressed(egui::Key::Enter));
                s.field("New token", |ui| {
                    let generate = kit::small_button(ui, "Generate a Token", Style::Bordered);
                    if generate.clicked() {
                        draft.paste = false;
                    }
                    generate
                });
            });
        } else {
            kit::section(ui, Some(RUN_HEADER), Some(TOKEN_SHOWN_ONCE), |s| {
                s.row(|ui| {
                    let token = draft.shown_token();
                    kit::code_block(ui, &token, 1);
                    ui.add_space(6.0);
                    // One line: a bare right-to-left layout would take the rest of the
                    // sheet height and push the rows below out of view.
                    ui.horizontal(|ui| {
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if kit::small_button(ui, "Copy", Style::Bordered).clicked() {
                                actions.copy = true;
                            }
                            let label = if draft.shown { "Hide" } else { "Show" };
                            if kit::small_button(ui, label, Style::Bordered).clicked() {
                                draft.shown = !draft.shown;
                            }
                        });
                    });
                });
                s.field("Own token", |ui| {
                    let paste = kit::small_button(ui, "Paste a Token", Style::Bordered);
                    if paste.clicked() {
                        draft.paste = true;
                        draft.shown = false;
                    }
                    paste
                });
            });
            kit::section(ui, None, Some(START_NOTE), |s| {
                s.row(|ui| {
                    let lines = docker_run_lines();
                    kit::code_block(ui, &lines, 5);
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if kit::small_button(ui, "Copy Commands", Style::Bordered).clicked() {
                                ui.ctx().copy_text(lines.clone());
                            }
                        });
                    });
                });
            });
        }
        actions.next |= enter;
    });
    let ready = draft.ready();
    kit::sheet_buttons(
        ui,
        |_| {},
        |ui| {
            actions.next |= ui
                .add_enabled_ui(ready, |ui| kit::button(ui, "Continue", Style::Prominent))
                .inner
                .clicked();
            actions.cancel |= kit::button(ui, "Cancel", Style::Bordered).clicked();
        },
    );
}

/// Step 2: the consent screen of [`HOSTING_CONSENT_VERSION`].
fn consent_step(ui: &mut egui::Ui, draft: &HostingDraft, actions: &mut SheetActions) {
    let lead = format!("Each bouncer request goes to {}.", draft.host());
    kit::sheet_title(ui, CONSENT_TITLE, Some(lead.as_str()));
    kit::sheet_body(ui, |ui| {
        kit::section(ui, Some("Sent"), None, |s| {
            for line in SENT {
                s.row(|ui| {
                    ui.label(kit::text(line, Font::Body));
                });
            }
        });
        kit::section(ui, Some("Never sent"), None, |s| {
            for line in NEVER_SENT {
                s.row(|ui| {
                    ui.label(kit::text(line, Font::Body));
                });
            }
        });
        ui.add_space(10.0);
        kit::tone_note(ui, TRUST_WARNING, Tone::Warning);
        ui.add_space(4.0);
        kit::note(ui, consent_note());
    });
    kit::sheet_buttons(
        ui,
        |ui| {
            actions.back |= kit::button(ui, "Back", Style::Bordered).clicked();
        },
        |ui| {
            actions.submit |= kit::button(ui, USE_SERVER, Style::Prominent).clicked();
            actions.cancel |= kit::button(ui, "Cancel", Style::Bordered).clicked();
        },
    );
}

/// The note under the consent: its version and the fresh check.
pub(crate) fn consent_note() -> String {
    format!("Consent version {HOSTING_CONSENT_VERSION}. Each change needs Touch ID.")
}

/// The synthetic address of the tour.
const TOUR_ADDRESS: &str = "https://brain.tail0a1b.ts.net";
/// The synthetic token that the tour pastes.
const TOUR_TOKEN: &str = "SYNTH-tour-token-0123456789abcdef";

impl DesktopApp {
    /// Open a state of the bouncer brain host for the screenshot tour
    /// (`examples/screenshots.rs`, tour step `brain-host STATE`), with synthetic values:
    /// `server`, `server-shown`, `paste`, `consent`, `check` (the owner check over the
    /// consent), `this-mac` (the owner check of the return). It never passes an owner
    /// check and never writes the vault. Returns false for an unknown state or a locked
    /// vault.
    #[doc(hidden)]
    pub fn tour_brain_hosting(&mut self, state: &str) -> bool {
        if state == "this-mac" {
            apply(self, RunsOnAction::ThisMac, None);
            return self.owner.check.is_some();
        }
        if !["server", "server-shown", "paste", "consent", "check"].contains(&state) {
            return false;
        }
        open_server_sheet(self);
        let Some(draft) = self.bouncer_host.draft.as_mut() else {
            return false;
        };
        draft.address = TOUR_ADDRESS.to_owned();
        match state {
            "server-shown" => draft.shown = true,
            "paste" => {
                draft.paste = true;
                draft.set_pasted(TOUR_TOKEN);
            }
            "consent" | "check" => draft.step = HostingStep::Consent,
            _ => {}
        }
        if state == "check" {
            submit(self, None);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EPOCH: [u8; 32] = [7; 32];

    #[test]
    fn a_draft_is_ready_only_with_an_https_address_and_a_valid_token() {
        let mut draft = HostingDraft::new(EPOCH).unwrap();
        assert!(!draft.ready(), "no address yet");
        for wrong in [
            "http://brain.synthetic.ts.net",
            "brain.synthetic.ts.net",
            "https://",
            "https://user@brain.synthetic.ts.net",
            "https://brain.synthetic.ts.net/?q=1",
            "https://brain.synthetic.ts.net/v1",
        ] {
            draft.address = wrong.to_owned();
            assert!(!draft.address_ok(), "{wrong}");
            assert!(draft.change().is_none(), "{wrong}");
        }
        draft.address = " https://brain.synthetic.ts.net/ ".to_owned();
        assert!(draft.ready(), "the generated token is valid");
        assert_eq!(draft.host(), "brain.synthetic.ts.net");
        let change = draft.change().unwrap();
        assert_eq!(change.kind, BouncerHostKind::OwnServer);
        assert_eq!(change.url, "https://brain.synthetic.ts.net");
        assert_eq!(change.consent_version, HOSTING_CONSENT_VERSION);
        assert_eq!(
            change.bearer.as_ref().unwrap().expose(),
            draft.generated.expose()
        );
        // A pasted token replaces the generated one, and must be valid.
        draft.paste = true;
        draft.set_pasted("short");
        assert!(!draft.ready());
        draft.set_pasted("  SYNTH-pasted-token-0123456789  ");
        assert_eq!(
            draft.change().unwrap().bearer.unwrap().expose(),
            "SYNTH-pasted-token-0123456789"
        );
        draft.set_pasted("SYNTH pasted token with spaces");
        assert!(!draft.ready(), "a header cannot carry a space");
    }

    #[test]
    fn the_shown_token_is_masked_until_the_owner_shows_it() {
        let mut draft = HostingDraft::new(EPOCH).unwrap();
        let token = draft.generated.expose().to_owned();
        let masked = draft.shown_token();
        assert_eq!(masked.as_str(), MASK);
        draft.shown = true;
        assert_eq!(draft.shown_token().as_str(), token);
        // The copy always has the token, and the start commands never do.
        draft.shown = false;
        assert_eq!(draft.token_copy().as_str(), token);
        let lines = docker_run_lines();
        assert!(!lines.contains(&token), "{lines}");
        assert!(lines.contains("LAYA_API_KEY_FILE="), "{lines}");
        assert!(lines.contains("127.0.0.1:8770:8770"), "{lines}");
    }

    #[test]
    fn the_draft_debug_output_holds_no_token() {
        let mut draft = HostingDraft::new(EPOCH).unwrap();
        draft.address = "https://brain.synthetic.ts.net".to_owned();
        draft.set_pasted("SYNTH-pasted-token-0123456789");
        let debug = format!("{draft:?}");
        assert!(!debug.contains(draft.generated.expose()), "{debug}");
        assert!(!debug.contains("SYNTH-pasted"), "{debug}");
        assert!(debug.contains("brain.synthetic.ts.net"), "{debug}");
    }

    #[test]
    fn the_fallback_names_this_mac_once() {
        let (headline, reason) = fallback_lines(crate::broker::brain_host::CONNECT_UNAVAILABLE);
        assert_eq!(headline, FALLBACK_HEADLINE);
        assert_eq!(
            reason,
            "Apassy Connect hosting needs the Connect sign-in, which this version does not have yet."
        );
        let (_, reason) = fallback_lines(
            "The server of the bouncer brain has no token in the vault. Choose the server again.",
        );
        assert!(reason.ends_with("Choose the server again."), "{reason}");
    }

    #[test]
    fn the_row_note_names_the_host_and_never_the_token() {
        let host = BouncerHost {
            role: BouncerHostRole::Hosting,
            kind: BouncerHostKind::OwnServer,
            url: "https://brain.synthetic.ts.net:8443".to_owned(),
            has_bearer: true,
            consent_version: HOSTING_CONSENT_VERSION,
            consented_at: 1,
            updated_at: 1,
        };
        assert_eq!(
            host_note(&host),
            "brain.synthetic.ts.net:8443 · The bouncer gate still decides on this Mac."
        );
        assert_eq!(kind_title(BouncerHostKind::OwnServer), "My Server");
        assert!(consent_note().contains(&HOSTING_CONSENT_VERSION.to_string()));
    }
}
