//! Headless UI tests of the credential page: the known hosts of "Hosts and risk", and
//! the import rows that the footer shows on "Import details…". Synthetic data only. The
//! credentials are made in a temporary vault.

use eframe::egui::{self, Event, Modifiers, Pos2, RawInput, Rect, Vec2};
use tempfile::TempDir;

use super::super::draw;
use super::super::owner_tests::{PASS, collect, locked_app};
use crate::contracts::CredentialKind;
use crate::desktop::DesktopApp;
use crate::desktop::model::{DetailDraft, ItemDraft};
use crate::desktop::owner_check::OwnerRequest;
use crate::desktop::owner_store::SecretForm;
use crate::vault::EnvDelivery;

const SIZE: Vec2 = Vec2::new(1280.0, 2400.0);
const PASSWORD: &str = "detail-page-password-canary";
const SOURCE: &str = "detail-page-source-record-canary";

/// One window that keeps its egui state between frames, with the AccessKit names of
/// the last frame.
struct Window {
    ctx: egui::Context,
    time: f64,
    text: String,
    texts: Vec<(String, Pos2)>,
    names: Vec<String>,
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

    /// Click the last painted text that is `needle`: the rows under the footer draw
    /// after the main card.
    fn click_last(&mut self, app: &mut DesktopApp, needle: &str) {
        let at = self
            .texts
            .iter()
            .rev()
            .find(|(text, _)| text == needle)
            .map(|(_, pos)| *pos + Vec2::new(4.0, 4.0))
            .unwrap_or_else(|| panic!("\"{needle}\" is not on the screen: {}", self.text));
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
}

fn positions(shape: &egui::Shape, out: &mut Vec<(String, Pos2)>) {
    match shape {
        egui::Shape::Text(text) => out.push((text.galley.text().to_owned(), text.pos)),
        egui::Shape::Vec(nested) => nested.iter().for_each(|inner| positions(inner, out)),
        _ => {}
    }
}

fn unlocked_app(dir: &TempDir) -> DesktopApp {
    let mut app = locked_app(dir, "detail-page.db");
    app.owner_ui.session.unlock(PASS).expect("unlock");
    app
}

fn add(app: &mut DesktopApp, draft: &ItemDraft, secrets: &SecretForm) -> u64 {
    app.owner_ui
        .session
        .add(draft, secrets)
        .expect("add synthetic credential")
        .id
}

/// Open the credential with "Agent Access" open.
fn open(app: &mut DesktopApp, window: &mut Window, id: u64) {
    app.select_item(id.to_string());
    app.show_credentials();
    app.ui
        .set_expanded(&format!("credential-agent-settings-{id}"), true);
    window.idle(app);
}

/// "Hosts and risk" names the hosts that the bouncer knows for the item: the `host`
/// field without its port, the hosts of a placeholder, or "Not set". The website of a
/// login is no known host of the bouncer, so it is never shown as one.
#[test]
fn hosts_and_risk_names_the_known_hosts_of_the_bouncer() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = unlocked_app(&dir);
    let mut window = Window::new();
    let mut secrets = SecretForm::default();
    secrets.password = PASSWORD.to_owned();

    let database = add(
        &mut app,
        &ItemDraft {
            name: "Billing database".to_owned(),
            kind: CredentialKind::Database,
            host: "db.synthetic.example:5432".to_owned(),
            database_name: "billing".to_owned(),
            username: "app".to_owned(),
            ..ItemDraft::default()
        },
        &secrets,
    );
    open(&mut app, &mut window, database);
    assert!(
        window.named("Hosts and risk, db.synthetic.example"),
        "{:?}",
        window.names
    );

    let login = add(
        &mut app,
        &ItemDraft {
            name: "Router login".to_owned(),
            kind: CredentialKind::Login,
            username: "admin".to_owned(),
            website: "https://router.example/login".to_owned(),
            ..ItemDraft::default()
        },
        &secrets,
    );
    open(&mut app, &mut window, login);
    assert!(
        window.named("Hosts and risk, Not set"),
        "{:?}",
        window.names
    );
    assert!(
        !window
            .names
            .iter()
            .any(|name| name.starts_with("Hosts and risk, ") && name.contains("router.example")),
        "{:?}",
        window.names
    );

    let mut token = SecretForm::default();
    token.token = PASSWORD.to_owned();
    let key = add(
        &mut app,
        &ItemDraft {
            name: "Synthetic upload key".to_owned(),
            ..ItemDraft::default()
        },
        &token,
    );
    app.owner_ui
        .session
        .with_vault(|vault| {
            vault.set_env_binding_with(
                key,
                "SYNTHETIC_UPLOAD_TOKEN",
                "token",
                &EnvDelivery::Placeholder(vec![
                    "api.synthetic.example".to_owned(),
                    "upload.synthetic.example:8443".to_owned(),
                ]),
            )
        })
        .expect("open")
        .expect("placeholder binding");
    open(&mut app, &mut window, key);
    assert!(
        window.named("Hosts and risk, 2 hosts"),
        "{:?}",
        window.names
    );
    assert!(!window.text.contains(PASSWORD), "a value is visible");
}

/// The import data of 1Password stays out of the main card. The footer says where the
/// credential came from, and "Import details…" shows and hides the import rows under
/// it. The masked source record keeps Show, which asks for the owner check.
#[test]
fn the_footer_names_the_import_and_import_details_toggles_its_rows() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = unlocked_app(&dir);
    let mut window = Window::new();
    let visible = |label: &str, value: &str| DetailDraft {
        label: label.to_owned(),
        value: value.to_owned(),
        ..DetailDraft::default()
    };
    let mut secrets = SecretForm::default();
    secrets.password = PASSWORD.to_owned();
    secrets.details[5] = SOURCE.to_owned();
    let id = add(
        &mut app,
        &ItemDraft {
            name: "Bano Email".to_owned(),
            kind: CredentialKind::Login,
            username: "owner@example.com".to_owned(),
            details: vec![
                visible("Recovery email", "backup@example.com"),
                visible("1Password item ID", "syntheticitemid"),
                visible("1Password account ID", "SYNTHETICACCOUNTID"),
                visible("1Password vault ID", "syntheticvaultid"),
                visible("1Password vault", "Synthetic vault"),
                DetailDraft {
                    label: "Source record".to_owned(),
                    hidden: true,
                    ..DetailDraft::default()
                },
            ],
            ..ItemDraft::default()
        },
        &secrets,
    );
    open(&mut app, &mut window, id);

    // The main card keeps an ordinary detail; the import rows wait behind the link.
    assert!(window.has("Recovery email"), "{}", window.text);
    for hidden in [
        "1Password item ID",
        "1Password account ID",
        "1Password vault ID",
        "1Password vault",
        "Source record",
        "SYNTHETICACCOUNTID",
        "Import data",
    ] {
        assert!(!window.text.contains(hidden), "{hidden}: {}", window.text);
    }
    assert!(
        window
            .texts
            .iter()
            .any(|(text, _)| text.starts_with("Imported from 1Password · Added ")),
        "{}",
        window.text
    );
    assert!(window.has("Import details…"), "{}", window.text);
    assert!(window.named("Import details…"), "{:?}", window.names);

    window.click_last(&mut app, "Import details…");
    assert!(app.ui.is_expanded(&format!("credential-import-{id}")));
    for shown in [
        "1Password item ID",
        "1Password account ID",
        "1Password vault ID",
        "1Password vault",
        "Source record",
        "SYNTHETICACCOUNTID",
    ] {
        assert!(window.has(shown), "{shown}: {}", window.text);
    }
    assert!(
        !window.text.contains(SOURCE),
        "the source record stays masked"
    );
    assert!(!window.text.contains(PASSWORD), "the password stays masked");

    // Show of the source record asks for the owner check; nothing shows before it.
    window.click_last(&mut app, "Show");
    let check = app.owner.check.as_ref().expect("the owner check opens");
    assert!(
        matches!(&check.request, OwnerRequest::Reveal { item_id } if *item_id == id),
        "{:?}",
        check.request
    );
    assert!(
        !window.text.contains(SOURCE),
        "nothing shows before the check"
    );
    app.close_owner_check(Some(&window.ctx));
    window.idle(&mut app);

    window.click_last(&mut app, "Import details…");
    assert!(!app.ui.is_expanded(&format!("credential-import-{id}")));
    assert!(
        !window.text.contains("1Password account ID"),
        "{}",
        window.text
    );
}

/// The import labels: each "1Password …" label and "Source record". Other details and a
/// one-time password stay where they are.
#[test]
fn import_data_is_each_1password_label_and_the_source_record() {
    let line = |label: &str| crate::desktop::owner_store::DetailLine {
        name: "x_synthetic".to_owned(),
        label: label.to_owned(),
        value: Some("synthetic".to_owned()),
        hidden: false,
        totp: false,
    };
    for label in [
        "1Password item ID",
        "1Password account ID",
        "1Password vault ID",
        "1Password vault",
        "1Password source JSON",
        "Source record",
    ] {
        assert!(super::is_import_data(&line(label)), "{label}");
    }
    for label in ["Recovery email", "1Password", "Source", "source record"] {
        assert!(!super::is_import_data(&line(label)), "{label}");
    }
    // A visible setup key stays in the main card, which never draws its value.
    let mut setup = line("1Password vault");
    setup.value = Some("otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP".to_owned());
    assert!(!super::is_import_data(&setup));
}
