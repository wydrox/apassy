//! Headless UI tests of the one-time passwords (TOTP): the login form, the masked code,
//! the shown code, the per-code Show and Hide, and the request to copy a code. Synthetic
//! seeds and passwords only. The seed is the SHA-1 seed of RFC 6238 appendix B.

use eframe::egui::{self, Event, Key, Modifiers, Pos2, RawInput, Rect, Vec2};
use tempfile::TempDir;

use super::otp::{Code, MASKED_CODE};
use super::owner_tests::{PASS, locked_app};
use super::{Sheet, draw};
use crate::broker::approvals::{OwnerAction, OwnerCheck};
use crate::contracts::CredentialKind;
use crate::desktop::model::{DetailDraft, ItemDraft};
use crate::desktop::owner_check::OwnerRequest;
use crate::desktop::owner_store::{SecretForm, detail_field_name};
use crate::desktop::{DesktopApp, OwnerView};
use crate::otp::{self, OtpError};
use crate::vault::{Field, ItemDraft as VaultDraft, SecretValue};

const SEED: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
/// A second, different seed (RFC 6238 appendix B, SHA-256 key).
const SEED_TWO: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";
const PASSWORD: &str = "otp-ui-password-canary";
const SIZE: Vec2 = Vec2::new(1180.0, 1400.0);

/// One window that keeps its egui state between frames.
struct Window {
    ctx: egui::Context,
    time: f64,
    text: String,
    /// Each painted text and its position.
    texts: Vec<(String, Pos2)>,
    /// How many times a frame asked the system to write the clipboard.
    clipboard_writes: usize,
}

impl Window {
    fn new() -> Self {
        Self {
            ctx: egui::Context::default(),
            time: 0.0,
            text: String::new(),
            texts: Vec::new(),
            clipboard_writes: 0,
        }
    }

    fn frame(&mut self, app: &mut DesktopApp, events: Vec<Event>) {
        self.time += 0.1;
        let input = RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, SIZE)),
            time: Some(self.time),
            events,
            ..Default::default()
        };
        let output = self.ctx.run_ui(input, |ui| draw(app, ui));
        self.clipboard_writes += output
            .platform_output
            .commands
            .iter()
            .filter(|command| matches!(command, egui::OutputCommand::CopyText(_)))
            .count();
        self.text.clear();
        self.texts.clear();
        for clipped in &output.shapes {
            super::owner_tests::collect(&clipped.shape, &mut self.text);
            positions(&clipped.shape, &mut self.texts);
        }
        output.drop_without_applying_deltas();
    }

    /// Draw frames until a new sheet or dialog is visible and the layout is stable.
    fn idle(&mut self, app: &mut DesktopApp) {
        for _ in 0..4 {
            self.frame(app, Vec::new());
        }
    }

    fn at(&self, needle: &str) -> Pos2 {
        self.texts
            .iter()
            .find(|(text, _)| text == needle)
            .map(|(_, pos)| *pos + Vec2::new(4.0, 4.0))
            .unwrap_or_else(|| panic!("\"{needle}\" is not on the screen: {}", self.text))
    }

    fn click_at(&mut self, app: &mut DesktopApp, at: Pos2) {
        let button = |pressed| Event::PointerButton {
            pos: at,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: Modifiers::NONE,
        };
        self.frame(app, vec![Event::PointerMoved(at)]);
        self.frame(app, vec![button(true)]);
        self.frame(app, vec![button(false)]);
        self.idle(app);
    }

    /// Click the first painted text that is `needle`.
    fn click(&mut self, app: &mut DesktopApp, needle: &str) {
        let at = self.at(needle);
        self.click_at(app, at);
    }

    /// Click the input that shows `placeholder`, then type `text`.
    fn type_into(&mut self, app: &mut DesktopApp, placeholder: &str, text: &str) {
        self.click(app, placeholder);
        self.frame(app, vec![Event::Text(text.to_owned())]);
        self.idle(app);
    }

    /// Click the painted text `button` that sits on the same line as the painted text
    /// `row` and to the right of it.
    fn click_beside(&mut self, app: &mut DesktopApp, row: &str, button: &str) {
        let label = self.at(row);
        let at = self
            .texts
            .iter()
            .filter(|(text, pos)| {
                text == button && (pos.y - label.y).abs() < 24.0 && pos.x > label.x
            })
            .map(|(_, pos)| *pos + Vec2::new(4.0, 4.0))
            .next()
            .unwrap_or_else(|| panic!("no \"{button}\" beside \"{row}\": {}", self.text));
        self.click_at(app, at);
    }

    fn save(&mut self, app: &mut DesktopApp) {
        self.frame(
            app,
            vec![Event::Key {
                key: Key::S,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: Modifiers::COMMAND,
            }],
        );
        self.idle(app);
    }

    /// True when one painted text is exactly `needle`.
    fn has(&self, needle: &str) -> bool {
        self.texts.iter().any(|(text, _)| text == needle)
    }

    /// The page never shows a seed, in any state.
    fn assert_no_seed(&self) {
        assert!(!self.text.contains(SEED), "the seed is on the screen");
        assert!(
            !self.text.contains(SEED_TWO),
            "the second seed is on the screen"
        );
        assert!(
            !self.text.contains("GEZDGNBV"),
            "a part of the seed is on the screen"
        );
    }
}

fn positions(shape: &egui::Shape, out: &mut Vec<(String, Pos2)>) {
    match shape {
        egui::Shape::Text(text) => out.push((text.galley.text().to_owned(), text.pos)),
        egui::Shape::Vec(nested) => nested.iter().for_each(|inner| positions(inner, out)),
        _ => {}
    }
}

fn unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

/// A code of the seed at a time near now. The page and the test read the clock at
/// different moments, so the test accepts the codes of the seconds around now.
fn codes_near_now(seed: &str) -> Vec<Code> {
    let now = unix();
    (now - 2..=now + 2)
        .map(|time| Code::at(seed, time).expect("seed"))
        .collect()
}

fn shows_a_current_code(text: &str) -> bool {
    codes_near_now(SEED)
        .iter()
        .any(|code| text.contains(&code.grouped()))
}

fn shows_any_current_digits(text: &str) -> bool {
    codes_near_now(SEED)
        .iter()
        .any(|code| text.contains(&code.digits) || text.contains(&code.grouped()))
}

fn otp_draft(label: &str) -> DetailDraft {
    DetailDraft {
        label: label.to_owned(),
        value: String::new(),
        hidden: true,
        stored: None,
    }
}

/// An unlocked vault with one login. It has a password and a one-time password. The
/// login is selected.
fn app_with_login(dir: &TempDir) -> (DesktopApp, u64) {
    let mut app = locked_app(dir, "otp.db");
    app.owner_ui.session.unlock(PASS).expect("unlock");
    let mut secrets = SecretForm::default();
    secrets.password = PASSWORD.to_owned();
    secrets.details[0] = SEED.to_owned();
    let item = app
        .owner_ui
        .session
        .add(
            &ItemDraft {
                name: "Example login".to_owned(),
                kind: CredentialKind::Login,
                username: "user@example.test".to_owned(),
                details: vec![otp_draft(otp::LABEL)],
                ..ItemDraft::default()
            },
            &secrets,
        )
        .expect("add");
    app.select_item(item.id.to_string());
    app.view = OwnerView::Item;
    (app, item.id)
}

const FIRST_LABEL: &str = "OTP";
const SECOND_LABEL: &str = "OTP 2";

/// An unlocked vault with one login. It has a password and two one-time passwords with
/// two different seeds. The login is selected.
fn app_with_two_codes(dir: &TempDir) -> (DesktopApp, u64) {
    let mut app = locked_app(dir, "two.db");
    app.owner_ui.session.unlock(PASS).expect("unlock");
    let mut secrets = SecretForm::default();
    secrets.password = PASSWORD.to_owned();
    secrets.details[0] = SEED.to_owned();
    secrets.details[1] = SEED_TWO.to_owned();
    let item = app
        .owner_ui
        .session
        .add(
            &ItemDraft {
                name: "Two codes".to_owned(),
                kind: CredentialKind::Login,
                username: "user@example.test".to_owned(),
                details: vec![otp_draft(FIRST_LABEL), otp_draft(SECOND_LABEL)],
                ..ItemDraft::default()
            },
            &secrets,
        )
        .expect("add");
    app.select_item(item.id.to_string());
    app.view = OwnerView::Item;
    (app, item.id)
}

/// Pass the owner check of the open request, as the owner does with the passphrase.
fn pass_owner_check(app: &mut DesktopApp) -> OwnerRequest {
    let request = app
        .owner
        .check
        .as_ref()
        .expect("the owner check is open")
        .request
        .clone();
    let proof = app
        .owner_gate()
        .authorize(request.action(), OwnerCheck::passphrase(PASS))
        .expect("owner check");
    // The dialog closes, as after a passed check.
    app.close_owner_check(None);
    app.complete_owner_request(request.clone(), proof);
    request
}

/// Show one code with the owner check of its own field, as the owner does.
fn show_code(app: &mut DesktopApp, item_id: u64, label: &str) {
    let field = detail_field_name(label);
    let proof = app
        .owner_gate()
        .authorize(
            OwnerAction::ShowCode {
                item_id,
                field: field.clone(),
            },
            OwnerCheck::passphrase(PASS),
        )
        .expect("owner check");
    app.owner_ui
        .session
        .reveal_one_code_seed(item_id, &field, proof)
        .expect("show code");
}

fn reveal(app: &mut DesktopApp, item_id: u64) {
    let proof = app
        .owner_gate()
        .authorize(
            OwnerAction::Reveal { item_id },
            OwnerCheck::passphrase(PASS),
        )
        .expect("owner check");
    app.owner_ui.session.reveal(item_id, proof).expect("reveal");
}

fn open_add_login(app: &mut DesktopApp) {
    app.add_form = ItemDraft {
        name: "New login".to_owned(),
        username: "user@example.test".to_owned(),
        kind: CredentialKind::Login,
        ..ItemDraft::default()
    };
    app.ui.sheet = Some(Sheet::AddItem { kind_chosen: true });
}

fn open_edit(app: &mut DesktopApp, item_id: u64) {
    let details = app.owner_ui.session.details(item_id).expect("details");
    app.edit_form = details.to_draft();
    app.owner_ui.edit_revision = details.revision;
    app.ui.sheet = Some(Sheet::EditItem);
}

fn stored_otp_labels(app: &DesktopApp, item_id: u64) -> Vec<String> {
    app.owner_ui
        .session
        .details(item_id)
        .expect("details")
        .details
        .into_iter()
        .filter(|detail| otp::is_otp_label(&detail.label))
        .map(|detail| detail.label)
        .collect()
}

// ---- The code on the screen. ----

#[test]
fn the_code_has_the_digits_and_the_seconds_of_the_period() {
    // RFC 6238 appendix B, SHA-1, at 59 seconds.
    let code = Code::at(SEED, 59).expect("seed");
    assert_eq!(code.digits, "287082");
    assert_eq!(code.grouped(), "287 082");
    assert_eq!((code.left, code.period), (1, 30));
    let long = Code::at(
        &format!("otpauth://totp/Example?secret={SEED}&digits=8"),
        59,
    )
    .expect("link");
    assert_eq!(long.digits, "94287082");
    assert_eq!(long.grouped(), "9428 7082");
    let slow = Code::at(
        &format!("otpauth://totp/Example?secret={SEED}&period=60"),
        59,
    )
    .expect("link");
    assert_eq!((slow.left, slow.period), (1, 60));
    // The 60-second period keeps the code for the whole minute.
    assert_eq!(
        Code::at(
            &format!("otpauth://totp/Example?secret={SEED}&period=60"),
            0
        )
        .unwrap(),
        Code {
            digits: slow.digits.clone(),
            left: 60,
            period: 60
        }
    );
    let seven = Code::at(
        &format!("otpauth://totp/Example?secret={SEED}&digits=7"),
        59,
    )
    .expect("link");
    assert_eq!(seven.grouped().len(), 8);
    assert_eq!(Code::at("not a key!", 59).unwrap_err(), OtpError::Invalid);
    assert_eq!(
        Code::at(
            &format!("otpauth://hotp/Example?secret={SEED}&counter=1"),
            59
        )
        .unwrap_err(),
        OtpError::Hotp
    );
}

#[test]
fn the_code_is_masked_until_the_owner_shows_it() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, _) = app_with_login(&dir);
    let mut window = Window::new();
    window.idle(&mut app);
    for expected in ["One-time password", "Show code", MASKED_CODE] {
        assert!(
            window.text.contains(expected),
            "{expected}: {}",
            window.text
        );
    }
    assert!(!window.text.contains("Copy code"), "{}", window.text);
    assert!(!shows_any_current_digits(&window.text), "{}", window.text);
    // The seed is not a detail row, and the password stays masked.
    window.assert_no_seed();
    assert!(!window.text.contains(PASSWORD), "{}", window.text);
    assert!(window.text.contains("Add custom detail"), "{}", window.text);
    assert_eq!(window.clipboard_writes, 0);
}

#[test]
fn show_code_asks_for_the_code_of_that_field_and_not_for_the_password() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, item_id) = app_with_login(&dir);
    let mut window = Window::new();
    window.idle(&mut app);
    window.click(&mut app, "Show code");
    let check = app.owner.check.as_ref().expect("the owner check opens");
    let OwnerRequest::ShowCode { item_id: id, field } = &check.request else {
        panic!("wrong request: {:?}", check.request.action());
    };
    assert_eq!(*id, item_id);
    assert_eq!(*field, detail_field_name(otp::LABEL));
    assert_eq!(
        check.request.action(),
        OwnerAction::ShowCode {
            item_id,
            field: detail_field_name(otp::LABEL)
        },
        "the proof names this one field"
    );
    assert!(!matches!(check.request, OwnerRequest::Reveal { .. }));
    assert!(!shows_any_current_digits(&window.text), "{}", window.text);
    window.assert_no_seed();
    assert!(!window.text.contains(PASSWORD), "{}", window.text);
}

#[test]
fn the_check_of_one_code_shows_that_code_only() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, item_id) = app_with_two_codes(&dir);
    let mut window = Window::new();
    window.idle(&mut app);
    // The second row asks for the second field.
    window.click_beside(&mut app, SECOND_LABEL, "Show code");
    let request = pass_owner_check(&mut app);
    let second = detail_field_name(SECOND_LABEL);
    assert_eq!(
        request,
        OwnerRequest::ShowCode {
            item_id,
            field: second.clone()
        }
    );
    let session = &app.owner_ui.session;
    assert_eq!(session.code_seed(item_id, &second), Some(SEED_TWO));
    let first = detail_field_name(FIRST_LABEL);
    assert_eq!(session.code_seed(item_id, &first), None);
    assert_eq!(session.revealed_value(item_id, &first), None);
    assert_eq!(session.revealed_value(item_id, "password"), None);

    window.idle(&mut app);
    let near: Vec<String> = (unix() - 2..=unix() + 2)
        .map(|time| Code::at(SEED_TWO, time).expect("seed").grouped())
        .collect();
    assert!(
        near.iter().any(|code| window.text.contains(code)),
        "{}",
        window.text
    );
    assert!(
        !shows_any_current_digits(&window.text),
        "first code: {}",
        window.text
    );
    // The first row is still masked, the second row can hide, and the password is masked.
    assert!(window.text.contains(MASKED_CODE), "{}", window.text);
    assert!(window.has("Show code"), "{}", window.text);
    assert!(window.has("Hide"), "{}", window.text);
    assert!(!window.text.contains(PASSWORD), "{}", window.text);
    window.assert_no_seed();
}

#[test]
fn hide_hides_one_code_and_keeps_the_other_code_and_the_password() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, item_id) = app_with_two_codes(&dir);
    // The password is revealed, and both codes are shown.
    reveal(&mut app, item_id);
    show_code(&mut app, item_id, FIRST_LABEL);
    show_code(&mut app, item_id, SECOND_LABEL);
    let first = detail_field_name(FIRST_LABEL);
    let second = detail_field_name(SECOND_LABEL);
    let mut window = Window::new();
    window.idle(&mut app);
    window.click_beside(&mut app, SECOND_LABEL, "Hide");
    let session = &app.owner_ui.session;
    assert_eq!(session.code_seed(item_id, &second), None);
    assert_eq!(session.code_seed(item_id, &first), Some(SEED));
    assert_eq!(session.revealed_value(item_id, "password"), Some(PASSWORD));
    assert!(app.owner.check.is_none(), "hide needs no owner check");
    window.assert_no_seed();

    // The first row hides on its own too.
    window.click_beside(&mut app, FIRST_LABEL, "Hide");
    let session = &app.owner_ui.session;
    assert_eq!(session.code_seed(item_id, &first), None);
    assert_eq!(session.revealed_value(item_id, "password"), Some(PASSWORD));
}

#[test]
fn a_shown_code_does_not_change_the_generic_show_of_the_password() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, item_id) = app_with_login(&dir);
    let mut window = Window::new();
    window.idle(&mut app);
    window.click(&mut app, "Show code");
    pass_owner_check(&mut app);
    window.idle(&mut app);
    assert!(shows_a_current_code(&window.text), "{}", window.text);
    // The secret section still offers "Show": the password is masked.
    assert!(window.has("Show"), "{}", window.text);
    assert!(!window.text.contains(PASSWORD), "{}", window.text);
    window.click(&mut app, "Show");
    let check = app.owner.check.as_ref().expect("the owner check opens");
    assert!(
        matches!(check.request, OwnerRequest::Reveal { item_id: id } if id == item_id),
        "{:?}",
        check.request.action()
    );
}

#[test]
fn a_shown_code_follows_the_clock_and_hides_with_the_values() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, item_id) = app_with_login(&dir);
    show_code(&mut app, item_id, otp::LABEL);
    let mut window = Window::new();
    window.idle(&mut app);
    assert!(shows_a_current_code(&window.text), "{}", window.text);
    for expected in ["Hide", "Copy code", "s"] {
        assert!(
            window.text.contains(expected),
            "{expected}: {}",
            window.text
        );
    }
    assert!(!window.text.contains(MASKED_CODE), "{}", window.text);
    window.assert_no_seed();

    app.owner_ui.session.hide(item_id).expect("hide");
    window.idle(&mut app);
    assert!(window.text.contains("Show code"), "{}", window.text);
    assert!(window.text.contains(MASKED_CODE), "{}", window.text);
    assert!(!shows_any_current_digits(&window.text), "{}", window.text);
}

#[test]
fn copy_code_asks_for_a_new_owner_check_and_the_page_never_writes_the_clipboard() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, item_id) = app_with_login(&dir);
    show_code(&mut app, item_id, otp::LABEL);
    let mut window = Window::new();
    window.idle(&mut app);
    assert!(app.owner.check.is_none());
    window.click(&mut app, "Copy code");
    let check = app.owner.check.as_ref().expect("the owner check opens");
    let OwnerRequest::CopyCode { item_id: id, field } = &check.request else {
        panic!("wrong request: {:?}", check.request.action());
    };
    assert_eq!(*id, item_id);
    assert_eq!(*field, detail_field_name(otp::LABEL));
    assert_eq!(
        check.request.action(),
        OwnerAction::CopyCode {
            item_id,
            field: detail_field_name(otp::LABEL)
        },
        "the proof names the copy of this field"
    );
    // The page asks. The guarded call writes the clipboard after the check.
    assert_eq!(window.clipboard_writes, 0);
    window.assert_no_seed();
}

#[test]
fn an_unreadable_seed_shows_a_message_and_no_copy_button() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = locked_app(&dir, "bad.db");
    app.owner_ui.session.unlock(PASS).expect("unlock");
    let mut secrets = SecretForm::default();
    secrets.password = PASSWORD.to_owned();
    secrets.details[0] = format!("otpauth://hotp/Example?secret={SEED}&counter=1");
    let item = app
        .owner_ui
        .session
        .add(
            &ItemDraft {
                name: "Counter login".to_owned(),
                username: "user@example.test".to_owned(),
                kind: CredentialKind::Login,
                details: vec![otp_draft("OTP")],
                ..ItemDraft::default()
            },
            &secrets,
        )
        .expect("add");
    app.select_item(item.id.to_string());
    app.view = OwnerView::Item;
    show_code(&mut app, item.id, "OTP");
    let mut window = Window::new();
    window.idle(&mut app);
    assert!(
        window.text.contains(&OtpError::Hotp.to_string()),
        "{}",
        window.text
    );
    assert!(!window.text.contains("Copy code"), "{}", window.text);
    window.assert_no_seed();
}

// ---- The login form. ----

#[test]
fn the_add_form_of_a_login_has_one_input_for_the_one_time_password() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = locked_app(&dir, "form.db");
    app.owner_ui.session.unlock(PASS).expect("unlock");
    open_add_login(&mut app);
    let mut window = Window::new();
    window.idle(&mut app);
    for expected in [
        "One-time password",
        "Setup key or otpauth:// link",
        "Optional. Paste the setup key or the otpauth link of the website.",
    ] {
        assert!(
            window.text.contains(expected),
            "{expected}: {}",
            window.text
        );
    }
    assert!(!window.has("Custom details"), "{}", window.text);
    assert!(app.add_form.details.is_empty());

    // Another kind has no such input.
    app.add_form.kind = CredentialKind::ApiKey;
    window.idle(&mut app);
    assert!(
        !window.text.contains("Setup key or otpauth:// link"),
        "{}",
        window.text
    );
}

#[test]
fn typing_makes_a_hidden_detail_and_a_blank_input_removes_it() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = locked_app(&dir, "typing.db");
    app.owner_ui.session.unlock(PASS).expect("unlock");
    open_add_login(&mut app);
    let mut window = Window::new();
    window.idle(&mut app);
    window.type_into(&mut app, "Setup key or otpauth:// link", SEED);
    assert_eq!(app.add_form.details, vec![otp_draft(otp::LABEL)]);
    assert_eq!(app.owner_ui.add_secrets.details[0], SEED);
    // The value is in the secret form only. The draft and the screen have no seed.
    assert!(app.add_form.details[0].value.is_empty());
    window.assert_no_seed();
    assert!(
        window
            .text
            .contains("Apassy makes a 6-digit code every 30 seconds."),
        "{}",
        window.text
    );
    assert!(!window.has("Custom details"), "{}", window.text);

    // The owner erases the text: no stored value needs the detail.
    window.frame(
        &mut app,
        vec![
            Event::Key {
                key: Key::A,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: Modifiers::COMMAND,
            },
            Event::Key {
                key: Key::Backspace,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: Modifiers::NONE,
            },
        ],
    );
    window.idle(&mut app);
    assert!(
        app.add_form.details.is_empty(),
        "{:?}",
        app.add_form.details
    );
    assert!(app.owner_ui.add_secrets.is_blank());
}

#[test]
fn a_visible_detail_with_the_otp_label_becomes_the_hidden_input() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = locked_app(&dir, "label.db");
    app.owner_ui.session.unlock(PASS).expect("unlock");
    open_add_login(&mut app);
    // A visible detail with the label of a one-time password would show the setup key.
    app.add_form.details.push(DetailDraft {
        label: otp::LABEL.to_owned(),
        value: SEED.to_owned(),
        hidden: false,
        stored: None,
    });
    let mut window = Window::new();
    window.idle(&mut app);
    assert_eq!(app.add_form.details, vec![otp_draft(otp::LABEL)]);
    assert_eq!(app.owner_ui.add_secrets.details[0], SEED);
    window.assert_no_seed();
    // The login form edits it in its one input, not in the list of custom details.
    assert!(!window.has("Custom details"), "{}", window.text);
    assert!(
        window
            .text
            .contains("Apassy makes a 6-digit code every 30 seconds."),
        "{}",
        window.text
    );
}

#[test]
fn an_unreadable_value_blocks_the_save_with_a_message() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = locked_app(&dir, "save.db");
    app.owner_ui.session.unlock(PASS).expect("unlock");
    open_add_login(&mut app);
    app.owner_ui.add_secrets.password = PASSWORD.to_owned();
    let mut window = Window::new();
    window.idle(&mut app);
    window.type_into(&mut app, "Setup key or otpauth:// link", "not a key!");
    assert!(
        window.text.contains(&OtpError::Invalid.to_string()),
        "{}",
        window.text
    );
    window.save(&mut app);
    assert!(
        app.status_text.contains(&OtpError::Invalid.to_string()),
        "{}",
        app.status_text
    );
    assert!(app.owner_ui.session.search("").expect("search").is_empty());
    assert!(matches!(app.ui.sheet, Some(Sheet::AddItem { .. })));
}

#[test]
fn a_valid_value_saves_and_the_page_masks_the_code() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = locked_app(&dir, "valid.db");
    app.owner_ui.session.unlock(PASS).expect("unlock");
    open_add_login(&mut app);
    app.owner_ui.add_secrets.password = PASSWORD.to_owned();
    let mut window = Window::new();
    window.idle(&mut app);
    window.type_into(&mut app, "Setup key or otpauth:// link", SEED);
    window.save(&mut app);
    let items = app.owner_ui.session.search("").expect("search");
    assert_eq!(items.len(), 1, "{}", app.status_text);
    assert!(app.ui.sheet.is_none());
    assert!(app.owner_ui.add_secrets.is_blank());
    assert_eq!(stored_otp_labels(&app, items[0].id), [otp::LABEL]);
    app.select_item(items[0].id.to_string());
    app.view = OwnerView::Item;
    window.idle(&mut app);
    assert!(window.text.contains("Show code"), "{}", window.text);
    assert!(!shows_any_current_digits(&window.text), "{}", window.text);
    window.assert_no_seed();
}

#[test]
fn the_edit_form_keeps_a_stored_seed_and_can_remove_it() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, item_id) = app_with_login(&dir);
    open_edit(&mut app, item_id);
    let mut window = Window::new();
    window.idle(&mut app);
    for expected in [
        "Unchanged",
        "Leave blank to keep the stored value.",
        "Remove one-time password",
    ] {
        assert!(
            window.text.contains(expected),
            "{expected}: {}",
            window.text
        );
    }
    // The stored seed has no row in the custom details, and no value in the form.
    assert!(!window.has("Custom details"), "{}", window.text);
    window.assert_no_seed();
    assert!(app.owner_ui.edit_secrets.is_blank());

    // A save with a blank input keeps the seed.
    app.edit_form.notes = "A change".to_owned();
    window.save(&mut app);
    assert!(app.ui.sheet.is_none(), "{}", app.status_text);
    assert_eq!(stored_otp_labels(&app, item_id), [otp::LABEL]);
    show_code(&mut app, item_id, otp::LABEL);
    let field = detail_field_name(otp::LABEL);
    assert_eq!(app.owner_ui.session.code_seed(item_id, &field), Some(SEED));

    // "Remove one-time password" removes it with the next save.
    open_edit(&mut app, item_id);
    window.idle(&mut app);
    window.click(&mut app, "Remove one-time password");
    assert!(
        app.edit_form.details.is_empty(),
        "{:?}",
        app.edit_form.details
    );
    window.save(&mut app);
    assert!(app.ui.sheet.is_none(), "{}", app.status_text);
    assert!(stored_otp_labels(&app, item_id).is_empty());
    window.idle(&mut app);
    assert!(!window.text.contains("Show code"), "{}", window.text);
}

#[test]
fn another_kind_keeps_its_one_time_password_in_the_custom_details() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, item_id) = app_with_login(&dir);
    open_edit(&mut app, item_id);
    app.edit_form.kind = CredentialKind::Custom;
    let mut window = Window::new();
    window.idle(&mut app);
    assert!(window.has("Custom details"), "{}", window.text);
    assert!(
        !window.text.contains("Setup key or otpauth:// link"),
        "{}",
        window.text
    );
    window.assert_no_seed();
}

#[test]
fn a_full_list_of_details_says_why_there_is_no_input() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = locked_app(&dir, "full.db");
    app.owner_ui.session.unlock(PASS).expect("unlock");
    open_add_login(&mut app);
    app.add_form.details = (0..crate::desktop::owner_store::MAX_DETAILS)
        .map(|index| DetailDraft {
            label: format!("Detail {index}"),
            value: "x".to_owned(),
            hidden: false,
            stored: None,
        })
        .collect();
    let mut window = Window::new();
    window.idle(&mut app);
    assert!(
        window
            .text
            .contains("Remove one to add a one-time password."),
        "{}",
        window.text
    );
    assert!(
        !window.text.contains("Setup key or otpauth:// link"),
        "{}",
        window.text
    );
}

// ---- Setup keys are never plain details. ----

#[test]
fn a_visible_detail_with_a_setup_key_is_not_drawn() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = locked_app(&dir, "visible.db");
    app.owner_ui.session.unlock(PASS).expect("unlock");
    let mut secrets = SecretForm::default();
    secrets.password = PASSWORD.to_owned();
    let link = format!("otpauth://totp/Example?secret={SEED}");
    let visible = |label: &str, value: &str| DetailDraft {
        label: label.to_owned(),
        value: value.to_owned(),
        hidden: false,
        stored: None,
    };
    let item = app
        .owner_ui
        .session
        .add(
            &ItemDraft {
                name: "Old import".to_owned(),
                kind: CredentialKind::Login,
                username: "user@example.test".to_owned(),
                details: vec![
                    visible("TOTP", SEED),
                    visible("Authenticator link", &link),
                    visible("Region", "eu-west-1"),
                    visible("Docs", "https://example.test/otpauth-guide"),
                ],
                ..ItemDraft::default()
            },
            &secrets,
        )
        .expect("add");
    app.select_item(item.id.to_string());
    app.view = OwnerView::Item;
    let mut window = Window::new();
    window.idle(&mut app);
    window.assert_no_seed();
    assert!(!window.text.contains("otpauth://totp"), "{}", window.text);
    // The label stays, and the owner reads why there is no value. If the vault model hides
    // the detail, the code section shows it instead.
    assert!(
        window.text.contains("Apassy hides this setup key") || window.text.contains("Show code"),
        "{}",
        window.text
    );
    // Details that are not setup keys stay visible.
    assert!(window.text.contains("eu-west-1"), "{}", window.text);
    assert!(
        window.text.contains("https://example.test/otpauth-guide"),
        "{}",
        window.text
    );
}

#[test]
fn the_form_hides_a_setup_key_and_keeps_it_in_the_secret_form() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = locked_app(&dir, "protect.db");
    app.owner_ui.session.unlock(PASS).expect("unlock");
    open_add_login(&mut app);
    let link = format!("otpauth://totp/Example?secret={SEED}");
    let visible = |label: &str, value: &str| DetailDraft {
        label: label.to_owned(),
        value: value.to_owned(),
        hidden: false,
        stored: None,
    };
    app.add_form.details = vec![
        visible("Authenticator link", &link),
        visible("OTP 2", SEED_TWO),
        visible("Region", "eu-west-1"),
    ];
    let mut window = Window::new();
    window.idle(&mut app);
    let details = &app.add_form.details;
    // A link under another label is hidden, with its label, and it is not a code input.
    assert!(details[0].hidden && details[0].value.is_empty());
    assert_eq!(details[0].label, "Authenticator link");
    assert_eq!(app.owner_ui.add_secrets.details[0], link);
    // An OTP label is hidden.
    assert!(details[1].hidden && details[1].value.is_empty());
    assert_eq!(app.owner_ui.add_secrets.details[1], SEED_TWO);
    // An unrelated visible detail is not touched.
    assert!(!details[2].hidden);
    assert_eq!(details[2].value, "eu-west-1");
    assert!(app.owner_ui.add_secrets.details[2].is_empty());
    window.assert_no_seed();
    assert!(!window.text.contains("otpauth://totp"), "{}", window.text);
    assert!(window.text.contains("eu-west-1"), "{}", window.text);
    // The dedicated input takes the "OTP 2" slot of the login. The other details stay in
    // the list of custom details.
    assert!(window.has("Custom details"), "{}", window.text);
}

#[test]
fn the_edit_form_moves_a_stored_visible_setup_key_out_of_plain_text() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = locked_app(&dir, "old.db");
    app.owner_ui.session.unlock(PASS).expect("unlock");
    // An older Apassy stored the setup key as a visible detail. The owner store now
    // refuses to write that, so the test writes the old layout, as an import does.
    let field = |name: &str, value: &str, secret: bool| Field {
        name: name.to_owned(),
        value: SecretValue::new(value.to_owned()),
        secret,
    };
    let item = app
        .owner_ui
        .session
        .add_imported(VaultDraft {
            title: "Old import".to_owned(),
            kind: CredentialKind::Login,
            notes: String::new(),
            tags: Vec::new(),
            fields: vec![
                field("username", "user@example.test", false),
                field("password", PASSWORD, true),
                field(&detail_field_name("TOTP"), SEED, false),
            ],
        })
        .expect("add");
    app.select_item(item.id.to_string());
    open_edit(&mut app, item.id);
    let mut window = Window::new();
    window.idle(&mut app);
    let stored = detail_field_name("TOTP");
    // The owner store gives the setup key as a hidden, stored detail: the form never gets
    // the seed, and a blank secret keeps the stored value.
    assert!(app.edit_form.details[0].hidden);
    assert!(app.edit_form.details[0].value.is_empty());
    assert_eq!(app.edit_form.details[0].stored.as_deref(), Some(&*stored));
    assert!(app.owner_ui.edit_secrets.details[0].is_empty());
    assert!(
        !app.owner_ui
            .session
            .secret_fields(item.id)
            .expect("fields")
            .contains(&stored),
        "the old layout is a visible field"
    );
    window.assert_no_seed();
    // The login form has its one input for it.
    assert!(!window.has("Custom details"), "{}", window.text);
    // A save repairs the visible seed even without a change to the form.
    window.save(&mut app);
    assert!(app.ui.sheet.is_none(), "{}", app.status_text);
    assert_eq!(stored_otp_labels(&app, item.id), ["TOTP"]);
    // The save stored the same seed as a secret field.
    assert!(
        app.owner_ui
            .session
            .secret_fields(item.id)
            .expect("fields")
            .contains(&stored)
    );
    let field = detail_field_name("TOTP");
    assert!(
        app.owner_ui
            .session
            .details(item.id)
            .expect("details")
            .details
            .iter()
            .any(|detail| detail.name == field && detail.hidden && detail.value.is_none())
    );
}

// ---- A link under any label. ----

const URI_LABEL: &str = "Work VPN";
const NOTES_LABEL: &str = "Recovery codes";

/// An unlocked vault with one login. A hidden detail with an ordinary label holds an
/// explicit `otpauth://totp` link. Another hidden detail with an ordinary label holds
/// plain text. The login is selected.
fn app_with_uri_label(dir: &TempDir) -> (DesktopApp, u64) {
    let mut app = locked_app(dir, "uri-label.db");
    app.owner_ui.session.unlock(PASS).expect("unlock");
    let mut secrets = SecretForm::default();
    secrets.password = PASSWORD.to_owned();
    secrets.details[0] = format!("otpauth://totp/Work?secret={SEED}&issuer=Example");
    secrets.details[1] = "plain recovery text".to_owned();
    let item = app
        .owner_ui
        .session
        .add(
            &ItemDraft {
                name: "Uri label".to_owned(),
                kind: CredentialKind::Login,
                username: "user@example.test".to_owned(),
                details: vec![otp_draft(URI_LABEL), otp_draft(NOTES_LABEL)],
                ..ItemDraft::default()
            },
            &secrets,
        )
        .expect("add");
    app.select_item(item.id.to_string());
    app.view = OwnerView::Item;
    (app, item.id)
}

#[test]
fn a_link_under_a_custom_label_gets_the_code_controls_and_keeps_its_label() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, item_id) = app_with_uri_label(&dir);
    // The owner store keeps the label as typed. It marks the detail, and it gives no seed.
    let details = app.owner_ui.session.details(item_id).expect("details");
    let uri = details
        .details
        .iter()
        .find(|detail| detail.label == URI_LABEL)
        .expect("the label is unchanged");
    assert!(uri.totp && uri.hidden && uri.value.is_none());
    let notes = details
        .details
        .iter()
        .find(|detail| detail.label == NOTES_LABEL)
        .expect("the other detail");
    assert!(!notes.totp && notes.hidden && notes.value.is_none());

    let mut window = Window::new();
    window.idle(&mut app);
    // One code row, under the custom label, and masked.
    assert!(window.has("One-time password"), "{}", window.text);
    assert!(window.has(URI_LABEL), "{}", window.text);
    assert!(window.has("Show code"), "{}", window.text);
    assert!(window.has(MASKED_CODE), "{}", window.text);
    assert!(!shows_any_current_digits(&window.text), "{}", window.text);
    window.assert_no_seed();
    assert!(!window.text.contains("otpauth"), "{}", window.text);
    // The plain hidden detail is an ordinary masked detail: it has Show, not Show code.
    assert!(window.has(NOTES_LABEL), "{}", window.text);
    assert!(!window.text.contains("plain recovery text"));
    window.click(&mut app, "Show code");
    let request = &app.owner.check.as_ref().expect("check").request;
    assert_eq!(
        *request,
        OwnerRequest::ShowCode {
            item_id,
            field: detail_field_name(URI_LABEL),
        }
    );
}

#[test]
fn a_link_under_a_custom_label_shows_only_its_own_code() {
    let dir = TempDir::new().expect("temp dir");
    let (mut app, item_id) = app_with_uri_label(&dir);
    let mut window = Window::new();
    window.idle(&mut app);
    window.click(&mut app, "Show code");
    let request = pass_owner_check(&mut app);
    let field = detail_field_name(URI_LABEL);
    assert_eq!(
        request,
        OwnerRequest::ShowCode {
            item_id,
            field: field.clone()
        }
    );
    window.idle(&mut app);
    assert!(shows_a_current_code(&window.text), "{}", window.text);
    assert!(
        window.has("Hide") && window.has("Copy code"),
        "{}",
        window.text
    );
    // The page never draws the link or the seed, the password, or the plain detail.
    window.assert_no_seed();
    assert!(!window.text.contains("otpauth"), "{}", window.text);
    assert!(!window.text.contains(PASSWORD), "{}", window.text);
    assert!(!window.text.contains("plain recovery text"));
    let session = &app.owner_ui.session;
    assert_eq!(session.revealed_value(item_id, &field), None);
    assert_eq!(session.revealed_value(item_id, "password"), None);
    assert_eq!(
        session.revealed_value(item_id, &detail_field_name(NOTES_LABEL)),
        None
    );
}
