//! The credential list: the selection bar, the look-alike credentials, their second
//! line, and the "Possible duplicates" filter. Synthetic values only.

use eframe::egui::RawInput;
use tempfile::TempDir;

use super::*;
use crate::desktop::owner_store::SecretForm;
use crate::desktop::ui::{draw, folders};

const PASS: &str = "list-ui-test-pass";
const CANARY: &str = "list-ui-secret-canary";
const SIZE: Vec2 = Vec2::new(1180.0, 800.0);

/// An unlocked synthetic vault. The directory must outlive the app.
fn unlocked(dir: &TempDir) -> DesktopApp {
    let mut app = DesktopApp::new();
    app.owner_ui
        .session
        .create_file(&dir.path().join("list.db"), PASS)
        .expect("create");
    app.owner_ui.session.unlock(PASS).expect("unlock");
    app
}

/// A synthetic credential. A login has the username and the website.
fn add(
    app: &mut DesktopApp,
    name: &str,
    kind: CredentialKind,
    username: &str,
    website: &str,
    folder: Option<&str>,
) -> u64 {
    let mut secrets = SecretForm::default();
    secrets.token = CANARY.to_owned();
    secrets.password = CANARY.to_owned();
    app.owner_ui
        .session
        .add_in_folder(
            &ItemDraft {
                name: name.to_owned(),
                kind,
                username: username.to_owned(),
                website: website.to_owned(),
                ..ItemDraft::default()
            },
            &secrets,
            folder,
        )
        .expect("add synthetic credential")
        .id
}

/// One window: a context across frames, as the real window has.
struct Window {
    ctx: egui::Context,
    text: String,
    placed: Vec<(String, Pos2)>,
}

impl Window {
    fn new() -> Self {
        Self {
            ctx: egui::Context::default(),
            text: String::new(),
            placed: Vec::new(),
        }
    }

    fn frame(&mut self, app: &mut DesktopApp, events: Vec<egui::Event>) {
        fn collect(shape: &egui::Shape, text: &mut String, placed: &mut Vec<(String, Pos2)>) {
            match shape {
                egui::Shape::Text(shape) => {
                    text.push_str(shape.galley.text());
                    text.push('\n');
                    placed.push((shape.galley.text().to_owned(), shape.pos));
                }
                egui::Shape::Vec(shapes) => {
                    shapes.iter().for_each(|shape| collect(shape, text, placed));
                }
                _ => {}
            }
        }
        let input = RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, SIZE)),
            events,
            ..Default::default()
        };
        let output = self.ctx.run_ui(input, |ui| draw(app, ui));
        self.text.clear();
        self.placed.clear();
        for clipped in &output.shapes {
            collect(&clipped.shape, &mut self.text, &mut self.placed);
        }
        output.drop_without_applying_deltas();
        assert!(!self.text.contains(CANARY), "a secret is on the screen");
    }

    fn idle(&mut self, app: &mut DesktopApp) {
        for _ in 0..3 {
            self.frame(app, Vec::new());
        }
    }

    fn key(&mut self, app: &mut DesktopApp, key: egui::Key, modifiers: egui::Modifiers) {
        self.frame(
            app,
            vec![egui::Event::Key {
                key,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers,
            }],
        );
        self.idle(app);
    }

    /// Click the last painted text `needle` (the top layer draws last).
    fn click(&mut self, app: &mut DesktopApp, needle: &str) {
        self.idle(app);
        let at = self
            .placed
            .iter()
            .rev()
            .find(|(text, _)| text == needle)
            .map(|(_, pos)| *pos + Vec2::new(4.0, 4.0))
            .unwrap_or_else(|| panic!("{needle} is not on the screen: {}", self.text));
        let button = |pressed| egui::Event::PointerButton {
            pos: at,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: egui::Modifiers::NONE,
        };
        self.frame(app, vec![egui::Event::PointerMoved(at)]);
        self.frame(app, vec![button(true)]);
        self.frame(app, vec![button(false)]);
        self.idle(app);
    }

    /// The top of the first painted text `needle`.
    fn top_of(&self, needle: &str) -> f32 {
        self.placed
            .iter()
            .filter(|(text, _)| text == needle)
            .map(|(_, pos)| pos.y)
            .reduce(f32::min)
            .unwrap_or_else(|| panic!("{needle} is not on the screen: {}", self.text))
    }

    /// A painted text is exactly `line`.
    fn has_line(&self, line: &str) -> bool {
        self.text.lines().any(|text| text == line)
    }
}

#[test]
fn look_alike_names_lose_case_spaces_and_one_trailing_tag() {
    assert_eq!(look_alike_key("Odealo admin [1P befydv]"), "odealo admin");
    assert_eq!(look_alike_key("  Odealo Admin  "), "odealo admin");
    assert_eq!(
        look_alike_key("Odealo admin   [1P befydv]  "),
        "odealo admin"
    );
    // One tag only, and only at the end.
    assert_eq!(look_alike_key("Odealo admin [a] [b]"), "odealo admin [a]");
    assert_eq!(look_alike_key("Odealo [a] admin"), "odealo [a] admin");
    assert_eq!(look_alike_key("Odealo admin [a]b"), "odealo admin [a]b");
    assert_eq!(look_alike_key("Odealo admin ]"), "odealo admin ]");
    // A name that is only a tag stays whole.
    assert_eq!(look_alike_key("[1P befydv]"), "[1p befydv]");
    assert_eq!(untagged_name(" Odealo admin [1P befydv] "), "Odealo admin");
}

#[test]
fn look_alikes_have_the_same_kind_and_name() {
    let items = [
        (1, CredentialKind::Login, "Odealo admin"),
        (2, CredentialKind::Login, "Odealo admin [1P befydv]"),
        (3, CredentialKind::ApiKey, "Odealo admin"),
        (4, CredentialKind::Login, "Odealo Twillio Recovery Password"),
        (5, CredentialKind::Login, "ODEALO ADMIN "),
    ];
    assert_eq!(look_alike_groups(items), vec![vec![1, 2, 5]]);
    let more = items
        .into_iter()
        .chain([(6, CredentialKind::ApiKey, "odealo admin [x]")]);
    assert_eq!(look_alike_groups(more), vec![vec![1, 2, 5], vec![3, 6]]);
    let distinct = [
        (1, CredentialKind::Login, "Odealo admin"),
        (2, CredentialKind::Login, "Odealo shop"),
    ];
    assert!(look_alike_groups(distinct).is_empty());
}

#[test]
fn a_look_alike_line_has_the_host_else_the_folder() {
    assert_eq!(
        list_host("https://odealo-admin.vercel.app/backoffice/login", ""),
        "odealo-admin.vercel.app"
    );
    assert_eq!(list_host("", "db.example.com:5432"), "db.example.com");
    assert_eq!(list_host("odealo.example/login", ""), "odealo.example");
    assert_eq!(list_host("https://me@a.example/login", ""), "a.example");
    // No part of user info shows when the split is not certain.
    assert_eq!(list_host("https://me:pa/ss@a.example/login", ""), "");
    assert_eq!(list_host("me:pass@a.example", ""), "");
    assert_eq!(list_host("not a host", ""), "");
    assert_eq!(list_host("", ""), "");
    assert_eq!(
        look_alike_line("me@x.io", "a.example", Some("Work")),
        "me@x.io · a.example"
    );
    assert_eq!(
        look_alike_line("me@x.io", "", Some("Work")),
        "me@x.io · Work"
    );
    assert_eq!(look_alike_line("me@x.io", "", None), "me@x.io");
    assert_eq!(look_alike_line("", "a.example", None), "a.example");
}

#[test]
fn the_duplicates_filter_hides_archived_credentials_until_a_search() {
    assert!(matches_filter(Filter::Duplicates, false, false, false));
    assert!(!matches_filter(Filter::Duplicates, false, true, false));
    assert!(matches_filter(Filter::Duplicates, true, true, false));
    assert!(!matches_filter(Filter::Duplicates, false, true, true));
}

/// A plain click selects one row without the selection bar. ⇧⌘M still moves that one
/// credential, and the undo notice follows.
#[test]
fn one_selected_row_has_no_bar_and_command_shift_m_still_moves_it() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = unlocked(&dir);
    let dest = folders::create(&mut app, None, "Destination").expect("dest");
    let alpha = add(&mut app, "Alpha key", CredentialKind::ApiKey, "", "", None);
    add(&mut app, "Beta key", CredentialKind::ApiKey, "", "", None);
    app.place = Place::CREDENTIALS;
    let mut window = Window::new();
    window.click(&mut app, "Alpha key");
    assert_eq!(app.ui.selected_items, [alpha].into_iter().collect());
    assert_eq!(app.selected_item_id, Some(alpha.to_string()));
    assert!(!window.text.contains("1 selected"), "{}", window.text);
    assert!(!window.text.contains("Clear Selection"), "{}", window.text);

    window.key(
        &mut app,
        egui::Key::M,
        egui::Modifiers::COMMAND | egui::Modifiers::SHIFT,
    );
    assert_eq!(
        app.ui.sheet,
        Some(Sheet::MoveItemsToFolder {
            item_ids: vec![alpha]
        })
    );
    window.click(&mut app, "Destination");
    window.click(&mut app, "Move");
    assert_eq!(app.ui.sheet, None, "{}", app.status_text);
    assert_eq!(
        app.owner_ui
            .session
            .with_vault(|vault| vault.item_folder(alpha))
            .expect("open vault")
            .expect("folder"),
        Some(dest.uuid.clone())
    );
    assert_eq!(app.ui.move_undo.len(), 1);
    window.idle(&mut app);
    assert!(window.text.contains("Undo Move"), "{}", window.text);
}

/// Two selected rows show the count, "Move…", and "Clear Selection".
#[test]
fn two_selected_rows_show_the_bar() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = unlocked(&dir);
    let alpha = add(&mut app, "Alpha key", CredentialKind::ApiKey, "", "", None);
    let beta = add(&mut app, "Beta key", CredentialKind::ApiKey, "", "", None);
    app.place = Place::CREDENTIALS;
    let mut window = Window::new();
    window.click(&mut app, "Alpha key");
    window.key(&mut app, egui::Key::A, egui::Modifiers::COMMAND);
    assert_eq!(app.ui.selected_items, [alpha, beta].into_iter().collect());
    for expected in ["2 selected", "Move…", "Clear Selection"] {
        assert!(
            window.text.contains(expected),
            "{expected}: {}",
            window.text
        );
    }
    window.click(&mut app, "Clear Selection");
    assert!(app.ui.selected_items.is_empty());
    assert!(!window.text.contains("Clear Selection"), "{}", window.text);
}

/// Look-alike rows add the host of the website, else the folder. Other rows keep the
/// username or the kind.
#[test]
fn look_alike_rows_tell_themselves_apart() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = unlocked(&dir);
    let work = folders::create(&mut app, None, "Work").expect("folder");
    let login = CredentialKind::Login;
    add(
        &mut app,
        "Odealo admin",
        login,
        "me@x.io",
        "https://a.example.com/login",
        None,
    );
    add(
        &mut app,
        "Odealo admin [1P befydv]",
        login,
        "me@x.io",
        "https://b.example.com/",
        None,
    );
    add(
        &mut app,
        "Odealo shop",
        login,
        "me@x.io",
        "https://c.example.com/",
        None,
    );
    let key = CredentialKind::ApiKey;
    add(&mut app, "Synthetic key", key, "", "", Some(&work.uuid));
    add(&mut app, "Synthetic key [1P abc]", key, "", "", None);
    app.place = Place::CREDENTIALS;
    let mut window = Window::new();
    window.idle(&mut app);
    assert!(
        window.has_line("me@x.io · a.example.com"),
        "{}",
        window.text
    );
    assert!(
        window.has_line("me@x.io · b.example.com"),
        "{}",
        window.text
    );
    // Not a look-alike: the username only, as before.
    assert!(window.has_line("me@x.io"), "{}", window.text);
    assert!(!window.text.contains("c.example.com"), "{}", window.text);
    // No host: the folder tells them apart.
    assert!(window.has_line("API key · Work"), "{}", window.text);
    assert!(window.has_line("API key · Personal"), "{}", window.text);
}

/// "Possible duplicates (N)" shows only with look-alikes. It lists only them, each set
/// next to each other even across folders, and "Show All" goes back.
#[test]
fn the_duplicates_filter_lists_look_alikes_together() {
    let dir = TempDir::new().expect("temp dir");
    let mut app = unlocked(&dir);
    let work = folders::create(&mut app, None, "Work").expect("folder");
    let key = CredentialKind::ApiKey;
    add(&mut app, "Zeta key", key, "", "", None);
    app.place = Place::CREDENTIALS;
    let mut window = Window::new();
    window.idle(&mut app);
    assert!(
        !window.text.contains("Possible duplicates"),
        "{}",
        window.text
    );

    add(&mut app, "Synthetic key", key, "", "", Some(&work.uuid));
    add(&mut app, "Synthetic key [1P abc]", key, "", "", None);
    let login = CredentialKind::Login;
    add(&mut app, "Bravo", login, "me@x.io", "", None);
    add(&mut app, "bravo [1P z]", login, "me@x.io", "", None);
    // The same name, another kind: not a look-alike.
    add(&mut app, "Zeta key", login, "me@x.io", "", None);
    window.idle(&mut app);
    // By folder, the top level comes first: the tagged copy is above the other.
    assert!(
        window.top_of("Synthetic key [1P abc]") < window.top_of("Synthetic key"),
        "{}",
        window.text
    );

    window.click(&mut app, "Possible duplicates (4)");
    assert_eq!(app.ui.credential_filter, Filter::Duplicates);
    assert!(window.text.contains("Show All"), "{}", window.text);
    assert!(!window.text.contains("Zeta key"), "{}", window.text);
    for expected in ["Bravo", "bravo [1P z]", "Synthetic key [1P abc]"] {
        assert!(
            window.text.contains(expected),
            "{expected}: {}",
            window.text
        );
    }
    // One set, one group: the untagged name comes first.
    assert!(
        window.top_of("Synthetic key") < window.top_of("Synthetic key [1P abc]"),
        "{}",
        window.text
    );
    assert!(
        window.top_of("bravo [1P z]") < window.top_of("Synthetic key"),
        "{}",
        window.text
    );

    window.click(&mut app, "Show All");
    assert_eq!(app.ui.credential_filter, Filter::All);
    assert!(window.text.contains("Zeta key"), "{}", window.text);
}
