//! Headless UI tests of the header and the first group of the credential page: the
//! subtitle with and without a provider, the labeled Service and Project rows, Copy of
//! the username, and "Add website…" of a login without a website. Synthetic data only.
//! The credentials are made in a temporary vault.

use eframe::egui::{self, Event, Modifiers, Pos2, RawInput, Rect, Vec2};
use tempfile::TempDir;

use super::super::owner_tests::{PASS, collect, locked_app};
use super::super::{Sheet, draw};
use crate::contracts::CredentialKind;
use crate::desktop::DesktopApp;
use crate::desktop::model::{DetailDraft, ItemDraft};
use crate::desktop::owner_check::OwnerRequest;
use crate::desktop::owner_store::SecretForm;

const SIZE: Vec2 = Vec2::new(1280.0, 2400.0);
const PASSWORD: &str = "detail-fields-password-canary";
const USERNAME: &str = "owner@bano.example.test";

/// One window that keeps its egui state between frames, with the AccessKit names of
/// the last frame and every text that a frame copied to the clipboard.
struct Window {
    ctx: egui::Context,
    time: f64,
    text: String,
    texts: Vec<(String, Pos2)>,
    names: Vec<String>,
    copied: Vec<String>,
}

impl Window {
    fn new() -> Self {
        let ctx = egui::Context::default();
        ctx.enable_accesskit();
        Self {
            ctx,
            time: 0.0,
            text: String::new(),
            texts: Vec::new(),
            names: Vec::new(),
            copied: Vec::new(),
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
        for command in &output.platform_output.commands {
            if let egui::OutputCommand::CopyText(text) = command {
                self.copied.push(text.clone());
            }
        }
        self.names.clear();
        if let Some(update) = &output.platform_output.accesskit_update {
            for (_, node) in &update.nodes {
                if let Some(label) = node.label() {
                    self.names.push(label.to_owned());
                }
            }
        }
        self.text.clear();
        self.texts.clear();
        for clipped in &output.shapes {
            collect(&clipped.shape, &mut self.text);
            positions(&clipped.shape, &mut self.texts);
        }
        output.drop_without_applying_deltas();
    }

    fn idle(&mut self, app: &mut DesktopApp) {
        for _ in 0..4 {
            self.frame(app, Vec::new());
        }
    }

    fn has(&self, needle: &str) -> bool {
        self.texts.iter().any(|(text, _)| text == needle)
    }

    fn named(&self, name: &str) -> bool {
        self.names.iter().any(|named| named == name)
    }

    /// The first painted text that is `needle`, a little inside it.
    fn at(&self, needle: &str) -> Pos2 {
        self.texts
            .iter()
            .find(|(text, _)| text == needle)
            .map(|(_, pos)| *pos + Vec2::new(4.0, 4.0))
            .unwrap_or_else(|| panic!("\"{needle}\" is not on the screen: {}", self.text))
    }

    /// The painted text `value` on the same line as the painted text `row`, to the right
    /// of it.
    fn beside(&self, row: &str, value: &str) -> Option<Pos2> {
        let label = self.at(row);
        self.texts
            .iter()
            .filter(|(text, pos)| {
                text == value && (pos.y + 4.0 - label.y).abs() < 24.0 && pos.x + 4.0 > label.x
            })
            .map(|(_, pos)| *pos + Vec2::new(4.0, 4.0))
            .next()
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

    /// Click the painted text `button` on the line of the painted text `row`.
    fn click_beside(&mut self, app: &mut DesktopApp, row: &str, button: &str) {
        let at = self
            .beside(row, button)
            .unwrap_or_else(|| panic!("no \"{button}\" beside \"{row}\": {}", self.text));
        self.click_at(app, at);
    }
}

fn positions(shape: &egui::Shape, out: &mut Vec<(String, Pos2)>) {
    match shape {
        egui::Shape::Text(text) => out.push((text.galley.text().to_owned(), text.pos)),
        egui::Shape::Vec(nested) => nested.iter().for_each(|inner| positions(inner, out)),
        _ => {}
    }
}

fn unlocked_app(dir: &TempDir) -> DesktopApp {
    let mut app = locked_app(dir, "detail-fields.db");
    app.owner_ui.session.unlock(PASS).expect("unlock");
    app
}

fn password() -> SecretForm {
    let mut secrets = SecretForm::default();
    secrets.password = PASSWORD.to_owned();
    secrets
}

/// A login as an import makes it: a project, no service, and no website.
fn bano_login(app: &mut DesktopApp) -> u64 {
    add(
        app,
        &ItemDraft {
            name: "Bano Email".to_owned(),
            kind: CredentialKind::Login,
            username: USERNAME.to_owned(),
            project: "bano-wyderka".to_owned(),
            ..ItemDraft::default()
        },
        &password(),
    )
}

fn add(app: &mut DesktopApp, draft: &ItemDraft, secrets: &SecretForm) -> u64 {
    app.owner_ui
        .session
        .add(draft, secrets)
        .expect("add synthetic credential")
        .id
}

fn open(app: &mut DesktopApp, window: &mut Window, id: u64) {
    app.select_item(id.to_string());
    app.show_credentials();
    window.idle(app);
}

/// The subtitle under the title of the header: the painted text that starts at the
/// left edge of the title, in the 40 points under it. The header title is the rightmost
/// painted `title`; the list draws the same name further left.
fn header_subtitle(window: &Window, title: &str) -> String {
    let (_, top) = window
        .texts
        .iter()
        .filter(|(text, _)| text == title)
        .max_by(|(_, a), (_, b)| a.x.total_cmp(&b.x))
        .unwrap_or_else(|| panic!("no title \"{title}\": {}", window.text));
    window
        .texts
        .iter()
        .find(|(_, pos)| (pos.x - top.x).abs() < 2.0 && pos.y > top.y && pos.y < top.y + 40.0)
        .map(|(text, _)| text.clone())
        .unwrap_or_else(|| panic!("no subtitle under \"{title}\": {}", window.text))
}

/// Without a provider, the header names only the kind, not the project or the service
/// with no label. With a provider, it names the provider and the kind.
#[test]
fn the_header_names_the_provider_and_the_kind_or_only_the_kind() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = unlocked_app(&dir);
    let mut window = Window::new();

    let login = bano_login(&mut app);
    open(&mut app, &mut window, login);
    assert_eq!(
        header_subtitle(&window, "Bano Email"),
        CredentialKind::Login.label(),
        "{}",
        window.text
    );

    let mut token = SecretForm::default();
    token.token = "detail-fields-token-canary".to_owned();
    let key = add(
        &mut app,
        &ItemDraft {
            name: "Stripe live key".to_owned(),
            kind: CredentialKind::ApiKey,
            service: "stripe".to_owned(),
            project: "acme-billing".to_owned(),
            ..ItemDraft::default()
        },
        &token,
    );
    open(&mut app, &mut window, key);
    let details = app.owner_ui.session.details(key).expect("details");
    let looks = super::Looks::of(&app, key, details.kind, &details.service, &details.name);
    assert_eq!(looks.provider.as_deref(), Some("Stripe"));
    assert_eq!(
        header_subtitle(&window, "Stripe live key"),
        format!("Stripe · {}", looks.kind_label),
        "{}",
        window.text
    );
}

/// The service and the project are labeled rows of the first group, with a provider
/// and without one.
#[test]
fn service_and_project_are_labeled_rows() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = unlocked_app(&dir);
    let mut window = Window::new();

    let login = add(
        &mut app,
        &ItemDraft {
            name: "Bano Email".to_owned(),
            kind: CredentialKind::Login,
            username: USERNAME.to_owned(),
            service: "mail".to_owned(),
            project: "bano-wyderka".to_owned(),
            ..ItemDraft::default()
        },
        &password(),
    );
    open(&mut app, &mut window, login);
    assert!(
        window.beside("Service", "mail").is_some(),
        "{}",
        window.text
    );
    assert!(
        window.beside("Project", "bano-wyderka").is_some(),
        "{}",
        window.text
    );

    let mut token = SecretForm::default();
    token.token = "detail-fields-token-canary".to_owned();
    let key = add(
        &mut app,
        &ItemDraft {
            name: "Stripe live key".to_owned(),
            kind: CredentialKind::ApiKey,
            service: "stripe".to_owned(),
            project: "acme-billing".to_owned(),
            ..ItemDraft::default()
        },
        &token,
    );
    open(&mut app, &mut window, key);
    assert!(
        window.beside("Service", "stripe").is_some(),
        "{}",
        window.text
    );
    assert!(
        window.beside("Project", "acme-billing").is_some(),
        "{}",
        window.text
    );

    // An empty service or project has no row.
    let bare = bano_login(&mut app);
    open(&mut app, &mut window, bare);
    assert!(!window.has("Service"), "{}", window.text);
    assert!(
        window.beside("Project", "bano-wyderka").is_some(),
        "{}",
        window.text
    );
}

/// A username is no secret (ADR 0023: plain fields need no check; ADR 0027 and
/// `OwnerSession::can_copy_field` cover only secret fields). Its Copy writes the
/// clipboard at once, with no owner check. The Copy of the password still asks for the
/// fresh owner check and writes nothing.
#[test]
fn username_copy_writes_the_clipboard_without_an_owner_check() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = unlocked_app(&dir);
    let mut window = Window::new();
    let id = bano_login(&mut app);
    open(&mut app, &mut window, id);
    assert!(
        window.beside("Username", USERNAME).is_some(),
        "{}",
        window.text
    );
    assert!(
        window.beside("Username", "Copy").is_some(),
        "{}",
        window.text
    );
    assert!(window.named("Copy Username"), "{:?}", window.names);

    window.click_beside(&mut app, "Username", "Copy");
    assert_eq!(window.copied, vec![USERNAME.to_owned()]);
    assert!(app.owner.check.is_none(), "a username needs no owner check");
    assert_eq!(app.status_text, "The username is copied.");
    assert!(
        app.owner_ui
            .session
            .revealed_value(id, "password")
            .is_none()
    );

    window.copied.clear();
    let revision = app.owner_ui.session.details(id).expect("details").revision;
    window.click_beside(&mut app, "Password", "Copy");
    assert!(
        matches!(&app.owner.check.as_ref().expect("fresh check").request,
        OwnerRequest::CopyField { item_id, field, revision: submitted }
        if *item_id == id && field == "password" && *submitted == revision)
    );
    assert!(window.copied.is_empty(), "{:?}", window.copied);
    assert!(!window.text.contains(PASSWORD));
}

/// A session that cannot clear its own copy shows the Copy of a secret disabled, and a
/// click asks for no owner check. The Copy of the username, no secret, still works.
#[test]
fn password_copy_is_disabled_when_the_session_cannot_clear_its_copy() {
    let _session = crate::desktop::clipboard::test_session::unavailable(
        "Clipboard copy is unavailable: synthetic session reason.",
    );
    let dir = TempDir::new().expect("temp dir");
    let mut app = unlocked_app(&dir);
    let mut window = Window::new();
    let id = bano_login(&mut app);
    open(&mut app, &mut window, id);
    assert!(
        window.beside("Password", "Copy").is_some(),
        "{}",
        window.text
    );
    assert!(!window.named("Copy Password"), "{:?}", window.names);
    window.click_beside(&mut app, "Password", "Copy");
    assert!(
        app.owner.check.is_none(),
        "a disabled Copy asks for nothing"
    );
    assert!(window.copied.is_empty(), "{:?}", window.copied);
    assert!(!window.text.contains(PASSWORD));

    window.click_beside(&mut app, "Username", "Copy");
    assert_eq!(window.copied, vec![USERNAME.to_owned()]);
}

/// "Add website…" is on the Website row of a login without a website only: not for a
/// login with a website or a website detail, another kind, or an archived login.
#[test]
fn add_website_is_only_for_a_login_without_a_website() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = unlocked_app(&dir);
    let mut window = Window::new();

    let bare = bano_login(&mut app);
    open(&mut app, &mut window, bare);
    assert!(
        window.beside("Website", "Add website…").is_some(),
        "{}",
        window.text
    );
    assert!(window.named("Add website"), "{:?}", window.names);

    let with_site = add(
        &mut app,
        &ItemDraft {
            name: "Router login".to_owned(),
            kind: CredentialKind::Login,
            username: "admin".to_owned(),
            website: "https://router.example.test/login".to_owned(),
            ..ItemDraft::default()
        },
        &password(),
    );
    open(&mut app, &mut window, with_site);
    assert!(
        window.beside("Website", "router.example.test").is_some(),
        "{}",
        window.text
    );
    assert!(!window.has("Add website…"), "{}", window.text);

    // A website detail, as an import keeps it, is a website too.
    let with_detail = add(
        &mut app,
        &ItemDraft {
            name: "Imported login".to_owned(),
            kind: CredentialKind::Login,
            username: "admin".to_owned(),
            details: vec![DetailDraft {
                label: "Website".to_owned(),
                value: "https://imported.example.test".to_owned(),
                ..DetailDraft::default()
            }],
            ..ItemDraft::default()
        },
        &password(),
    );
    open(&mut app, &mut window, with_detail);
    assert!(window.has("Website"), "{}", window.text);
    assert!(!window.has("Add website…"), "{}", window.text);

    let mut token = SecretForm::default();
    token.token = "detail-fields-token-canary".to_owned();
    let key = add(
        &mut app,
        &ItemDraft {
            name: "Upload key".to_owned(),
            kind: CredentialKind::ApiKey,
            ..ItemDraft::default()
        },
        &token,
    );
    open(&mut app, &mut window, key);
    assert!(!window.has("Add website…"), "{}", window.text);

    app.owner_ui.session.archive(bare).expect("archive");
    open(&mut app, &mut window, bare);
    assert!(window.has("Archived"), "{}", window.text);
    assert!(!window.has("Add website…"), "{}", window.text);
}

/// "Add website…" opens the edit sheet with the focus in its Website field: the typed
/// address goes there, not into the Name field.
#[test]
fn add_website_opens_the_edit_sheet_with_the_focus_in_the_website_field() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = unlocked_app(&dir);
    let mut window = Window::new();
    let id = bano_login(&mut app);
    open(&mut app, &mut window, id);

    window.click_beside(&mut app, "Website", "Add website…");
    assert_eq!(app.ui.sheet, Some(Sheet::EditItem));
    assert!(
        !app.ui.focus_form_website,
        "the Website field took the focus"
    );
    window.frame(
        &mut app,
        vec![Event::Text("https://mail.bano.example.test".to_owned())],
    );
    assert_eq!(app.edit_form.website, "https://mail.bano.example.test");
    assert_eq!(app.edit_form.name, "Bano Email");
    assert_eq!(app.edit_form.username, USERNAME);

    // Edit opens the same sheet with no focus request for the Website field.
    app.ui.sheet = None;
    window.idle(&mut app);
    let details = app.owner_ui.session.details(id).expect("details");
    app.ui.focus_form_website = true;
    super::open_edit(&mut app, &details, false);
    assert!(!app.ui.focus_form_website);
}
