//! Import from 1Password: Settings > Import. A sheet with three steps: the path of the
//! export file, a preview with a switch for each item, and the result.
//!
//! The parsed preview holds the secrets of the export in erasing buffers. The app drops
//! it on cancel, on lock, and after the import ([`ImportState::forget`]).

use std::path::{Path, PathBuf};

use eframe::egui;

use super::kit::{self, Font, Icon, Style, Tone};
use super::{Sheet, close_sheet};
use crate::contracts::CredentialKind;
use crate::desktop::DesktopApp;
use crate::desktop::owner_store::OwnerSession;
use crate::import::{Format, ImportItem, ImportPreview};

// The import builds items in the layout of the item forms.
const _: () = assert!(crate::import::MAX_DETAILS == crate::desktop::owner_store::MAX_DETAILS);
const _: () = assert!(
    crate::import::MAX_DETAIL_LABEL_BYTES == crate::desktop::owner_store::MAX_DETAIL_LABEL_BYTES
);

/// The import sheet state. The preview is the only copy of the parsed export.
#[derive(Debug, Default)]
pub(crate) struct ImportState {
    /// The path as the owner typed it.
    pub(crate) path: String,
    /// The export file that the preview came from.
    file: Option<PathBuf>,
    preview: Option<ImportPreview>,
    /// One flag for each item of the preview.
    selected: Vec<bool>,
    /// Why the last read failed.
    error: Option<String>,
    report: Option<Report>,
}

/// The result of one import.
#[derive(Debug)]
struct Report {
    imported: usize,
    /// Title and reason of each item that did not go into the vault.
    failed: Vec<(String, String)>,
    file: Option<PathBuf>,
    /// The result of "Delete the export file".
    deleted: Option<Result<(), String>>,
}

impl ImportState {
    /// Drop the parsed preview and the result. The secrets erase themselves.
    pub(crate) fn forget(&mut self) {
        self.preview = None;
        self.selected.clear();
        self.error = None;
        self.report = None;
        self.file = None;
    }

    /// True while a parsed export is in memory.
    #[cfg(test)]
    pub(crate) fn has_preview(&self) -> bool {
        self.preview.is_some()
    }

    /// Read the export file at the typed path. Items that are already in the vault are
    /// marked and not selected.
    pub(crate) fn read(&mut self, session: &OwnerSession) {
        self.forget();
        let path = expand_home(self.path.trim());
        match crate::import::read_file(&path) {
            Ok(mut preview) => {
                let existing = existing_items(session, &preview);
                preview.mark_existing(existing.iter().map(|(title, kind)| (title.as_str(), *kind)));
                self.selected = preview.default_selection();
                self.preview = Some(preview);
                self.file = Some(path);
            }
            Err(err) => self.error = Some(err.to_string()),
        }
    }

    /// Select every item that can be imported, or none.
    fn select_all(&mut self, on: bool) {
        let Some(preview) = &self.preview else {
            return;
        };
        for (flag, item) in self.selected.iter_mut().zip(&preview.items) {
            *flag = on && item.can_import();
        }
    }

    fn selected_count(&self) -> usize {
        self.selected.iter().filter(|on| **on).count()
    }

    /// Add each selected item through the owner session. A failed item does not stop
    /// the import. The preview is dropped afterwards. No agent gets access.
    pub(crate) fn run(&mut self, session: &mut OwnerSession) -> usize {
        let Some(mut preview) = self.preview.take() else {
            return 0;
        };
        let selected = std::mem::take(&mut self.selected);
        let mut imported = 0;
        let mut failed = Vec::new();
        for (item, on) in preview.items.iter_mut().zip(selected) {
            if !on {
                continue;
            }
            let Some(draft) = item.take_draft() else {
                continue;
            };
            match session.add_imported(draft.into_vault_draft()) {
                Ok(summary) => {
                    imported += 1;
                    if item.archived
                        && let Err(err) = session.archive(summary.id)
                    {
                        failed.push((
                            item.title.clone(),
                            format!("Imported, but not archived: {}", err.message),
                        ));
                    }
                }
                Err(err) => failed.push((item.title.clone(), err.message)),
            }
        }
        drop(preview);
        self.report = Some(Report {
            imported,
            failed,
            file: self.file.take(),
            deleted: None,
        });
        imported
    }

    /// Delete the export file of the last import.
    fn delete_file(&mut self) {
        let Some(report) = &mut self.report else {
            return;
        };
        let Some(file) = &report.file else {
            return;
        };
        report.deleted = Some(std::fs::remove_file(file).map_err(|err| match err.kind() {
            std::io::ErrorKind::NotFound => "The file is already gone.".to_owned(),
            std::io::ErrorKind::PermissionDenied => {
                "Apassy may not delete the file. Delete it in Finder.".to_owned()
            }
            _ => "Apassy could not delete the file. Delete it in Finder.".to_owned(),
        }));
    }
}

/// `~/…` from the home directory.
fn expand_home(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/")
        && let Some(home) = std::env::var_os("HOME")
    {
        return Path::new(&home).join(rest);
    }
    PathBuf::from(path)
}

/// Titles and kinds of the credentials in the vault. The search returns at most 1000
/// items. With more, Apassy searches for each title of the export.
fn existing_items(
    session: &OwnerSession,
    preview: &ImportPreview,
) -> Vec<(String, CredentialKind)> {
    if let Ok(rows) = session.search("") {
        return rows.into_iter().map(|row| (row.name, row.kind)).collect();
    }
    let mut out = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for item in &preview.items {
        let Some(draft) = item.draft() else {
            continue;
        };
        let title = draft.title().trim().to_lowercase();
        if !seen.insert(title.clone()) {
            continue;
        }
        for row in session.search(draft.title()).unwrap_or_default() {
            if row.name.trim().to_lowercase() == title {
                out.push((row.name, row.kind));
            }
        }
    }
    out
}

// ---- Settings section. ----

pub(super) fn section(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let mut open = false;
    kit::section(
        ui,
        Some("Import"),
        Some(
            "Apassy reads a 1Password export and shows each item before it adds anything. Agents get no access to imported credentials.",
        ),
        |s| {
            let blue = egui::Color32::from_rgb(10, 132, 255);
            open = s
                .nav(
                    Some((Icon::Key, blue)),
                    "Import from 1Password…",
                    Some("From a 1PUX or CSV export file."),
                    None,
                )
                .clicked();
        },
    );
    if open {
        app.import.forget();
        app.ui.sheet = Some(Sheet::Import);
    }
}

// ---- The sheet. ----

pub(super) fn sheet(app: &mut DesktopApp, ctx: &egui::Context) -> bool {
    if app.import.report.is_some() {
        report_sheet(app, ctx)
    } else if app.import.preview.is_some() {
        preview_sheet(app, ctx)
    } else {
        file_sheet(app, ctx)
    }
}

fn file_sheet(app: &mut DesktopApp, ctx: &egui::Context) -> bool {
    let mut read = false;
    let mut cancel = false;
    // A file dropped on the window fills the path.
    if let Some(dropped) = ctx.input(|input| {
        input
            .raw
            .dropped_files
            .iter()
            .map(|file| file.path())
            .find(|path| !path.as_os_str().is_empty())
            .map(Path::to_path_buf)
    }) {
        app.import.path = dropped.display().to_string();
    }
    let response = kit::sheet(ctx, "import", 540.0, |ui| {
        kit::sheet_title(
            ui,
            "Import from 1Password",
            Some(
                "Apassy reads the export file and shows what it finds. Nothing goes into the vault until you click Import.",
            ),
        );
        kit::section(
            ui,
            None,
            Some(
                "In 1Password 8, choose File > Export, select the account, and choose 1PUX. 1PUX keeps API credentials, SSH keys, databases, and servers. CSV has logins and passwords only. You can also drop the file on this window.",
            ),
            |s| {
                let field = s.field("Export file", |ui| {
                    super::files::path_input(
                        ui,
                        &mut app.files,
                        &mut app.import.path,
                        "import-path",
                        "~/Downloads/1PasswordExport.1pux",
                        super::files::DialogKind::ImportExport,
                    )
                });
                read = field.lost_focus()
                    && field.ctx.input(|input| input.key_pressed(egui::Key::Enter));
            },
        );
        if let Some(error) = &app.import.error {
            kit::tone_note(ui, error, Tone::Critical);
            ui.add_space(8.0);
        }
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                ui.add_enabled_ui(!app.import.path.trim().is_empty(), |ui| {
                    read |= kit::button(ui, "Read", Style::Prominent)
                        .on_hover_text("⌘S")
                        .clicked();
                });
                cancel = kit::button(ui, "Cancel", Style::Bordered).clicked();
            },
        );
    });
    read |= super::save_pressed(app, ctx) && !app.import.path.trim().is_empty();
    if read {
        app.import.read(&app.owner_ui.session);
    }
    if cancel {
        close_sheet(app, ctx);
    }
    response.escape
}

fn preview_sheet(app: &mut DesktopApp, ctx: &egui::Context) -> bool {
    let mut import = false;
    let mut back = false;
    let mut cancel = false;
    let mut select = None;
    let response = kit::sheet(ctx, "import", 600.0, |ui| {
        let state = &mut app.import;
        let Some(preview) = &state.preview else {
            return;
        };
        let subtitle = format!(
            "{} in the {}. Apassy can import {}. Apassy is for the credentials that agents use, so API credentials, SSH keys, databases, and servers are selected. Logins, passwords, and notes are not. Agents get no access.",
            count(preview.items.len(), "item", "items"),
            preview.format.label(),
            preview.importable(),
        );
        kit::sheet_title(ui, "Import from 1Password", Some(&subtitle));
        kit::sheet_body(ui, |ui| {
            if preview.items.is_empty() {
                kit::note(ui, "The export has no items.");
                return;
            }
            kit::section(ui, None, None, |s| {
                for (index, item) in preview.items.iter().enumerate() {
                    let on = &mut state.selected[index];
                    s.row(|ui| item_row(ui, index, item, preview.format, on));
                }
            });
        });
        kit::sheet_buttons(
            ui,
            |ui| {
                if kit::small_button(ui, "Select all", Style::Link).clicked() {
                    select = Some(true);
                }
                if kit::small_button(ui, "Select none", Style::Link).clicked() {
                    select = Some(false);
                }
            },
            |ui| {
                let selected = state.selected_count();
                ui.add_enabled_ui(selected > 0, |ui| {
                    import = kit::button(
                        ui,
                        &format!("Import {}", count(selected, "credential", "credentials")),
                        Style::Prominent,
                    )
                    .on_hover_text("⌘S")
                    .clicked();
                });
                cancel = kit::button(ui, "Cancel", Style::Bordered).clicked();
                back = kit::button(ui, "Back", Style::Bordered).clicked();
            },
        );
    });
    if let Some(on) = select {
        app.import.select_all(on);
    }
    import |= super::save_pressed(app, ctx) && app.import.selected_count() > 0;
    if import {
        let imported = app.import.run(&mut app.owner_ui.session);
        app.set_ok(format!(
            "Imported {}.",
            count(imported, "credential", "credentials")
        ));
    }
    if back {
        app.import.forget();
    }
    if cancel {
        close_sheet(app, ctx);
    }
    response.escape
}

/// One item of the preview: title, where it comes from, what it becomes, and notes.
fn item_row(ui: &mut egui::Ui, index: usize, item: &ImportItem, format: Format, on: &mut bool) {
    egui::Sides::new()
        .shrink_left()
        .wrap_mode(egui::TextWrapMode::Wrap)
        .show(
            ui,
            |ui| {
                ui.vertical(|ui| {
                    ui.label(kit::text(&item.title, Font::Body).color(kit::LABEL));
                    let source = if item.source_vault.is_empty() {
                        format.label().to_owned()
                    } else {
                        item.source_vault.clone()
                    };
                    let target = item.kind().map_or("Not imported", CredentialKind::label);
                    let line = if item.category_label.is_empty() || format == Format::Csv {
                        format!("{source} · {target}")
                    } else {
                        format!("{source} · {} → {target}", item.category_label)
                    };
                    kit::note(ui, line);
                    if item.duplicate {
                        kit::tag(ui, "Already in the vault", Tone::Warning);
                    }
                    if let Some(reason) = item.skip_reason() {
                        kit::tone_note(ui, reason, Tone::Neutral);
                    }
                    for warning in &item.warnings {
                        kit::tone_note(ui, warning, Tone::Warning);
                    }
                });
            },
            |ui| {
                ui.push_id(("import-item", index), |ui| {
                    ui.add_enabled_ui(item.can_import(), |ui| {
                        kit::toggle(ui, on, &item.title);
                    });
                });
            },
        );
}

fn report_sheet(app: &mut DesktopApp, ctx: &egui::Context) -> bool {
    let mut done = false;
    let mut delete = false;
    let response = kit::sheet(ctx, "import", 540.0, |ui| {
        let Some(report) = &app.import.report else {
            return;
        };
        kit::sheet_title(ui, "Import finished", None);
        kit::sheet_body(ui, |ui| {
            let tone = if report.failed.is_empty() {
                Tone::Good
            } else {
                Tone::Warning
            };
            kit::notice(
                ui,
                tone,
                &format!(
                    "Imported {}.",
                    count(report.imported, "credential", "credentials")
                ),
                Some(
                    "The export file holds your secrets in plain text. Delete it when you do not need it.",
                ),
                |_| {},
            );
            if !report.failed.is_empty() {
                kit::section(ui, Some("Problems"), None, |s| {
                    for (title, why) in &report.failed {
                        s.row(|ui| {
                            ui.label(kit::text(title, Font::Body).color(kit::LABEL));
                            kit::tone_note(ui, why, Tone::Critical);
                        });
                    }
                });
            }
            if let Some(file) = &report.file {
                kit::section(
                    ui,
                    Some("The export file"),
                    Some(
                        "On an SSD, a deletion is not a secure wipe: the data can stay on the disk until the disk reuses the space. FileVault keeps it encrypted. If the file is also in the Trash or in a backup, delete it there too.",
                    ),
                    |s| {
                        s.labeled(
                            "File",
                            kit::text(file.display().to_string(), Font::MonoSmall)
                                .color(kit::SECONDARY),
                        );
                        s.row(|ui| match &report.deleted {
                            Some(Ok(())) => {
                                kit::tone_note(ui, "The export file is deleted.", Tone::Good);
                            }
                            other => {
                                if let Some(Err(why)) = other {
                                    kit::tone_note(ui, why, Tone::Critical);
                                }
                                delete = kit::small_button(
                                    ui,
                                    "Delete the export file",
                                    Style::Destructive,
                                )
                                .clicked();
                            }
                        });
                    },
                );
            }
        });
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                done = kit::button(ui, "Done", Style::Prominent).clicked();
            },
        );
    });
    if delete {
        app.import.delete_file();
    }
    if done {
        close_sheet(app, ctx);
    }
    response.escape
}

fn count(n: usize, one: &str, many: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{n} {many}")
    }
}

#[cfg(test)]
mod tests {
    //! Headless tests of the import sheet. Synthetic data only: each secret starts with
    //! `SYNTH-OP-`.

    use eframe::egui::{Event, Key, Modifiers, Pos2, RawInput, Rect, Vec2};
    use serde_json::{Value, json};
    use tempfile::TempDir;

    use super::*;
    use crate::desktop::owner_store::SecretForm;
    use crate::desktop::{ItemDraft, OwnerView};

    #[allow(dead_code)]
    mod zip_fixture {
        include!("../../../tests/support/zip_fixture.rs");
    }

    const PASS: &str = "ui-import-pass-ok";
    const CANARY: &str = "SYNTH-OP-";
    const SIZE: Vec2 = Vec2::new(1280.0, 2400.0);

    /// A file that the owner drops on the window.
    #[derive(Debug)]
    struct Dropped(std::path::PathBuf);

    impl egui::DroppedFile for Dropped {
        fn path(&self) -> &Path {
            &self.0
        }

        fn bytes(&self) -> Result<Vec<u8>, String> {
            Err("The import reads the path, not the bytes.".to_owned())
        }
    }

    fn command_s() -> Event {
        Event::Key {
            key: Key::S,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: Modifiers::COMMAND,
        }
    }

    /// Three frames of the whole app, with `events` in the first. Returns the painted
    /// text of the last frame.
    fn frames(ctx: &egui::Context, app: &mut DesktopApp, events: Vec<Event>) -> String {
        let mut events = Some(events);
        let mut text = String::new();
        for _ in 0..3 {
            let input = RawInput {
                screen_rect: Some(Rect::from_min_size(Pos2::ZERO, SIZE)),
                events: events.take().unwrap_or_default(),
                ..Default::default()
            };
            let output = ctx.run_ui(input, |ui| super::super::draw(app, ui));
            text.clear();
            for clipped in &output.shapes {
                collect(&clipped.shape, &mut text);
            }
            output.drop_without_applying_deltas();
        }
        assert!(!text.contains(CANARY), "a secret is on screen: {text}");
        text
    }

    fn collect(shape: &egui::Shape, out: &mut String) {
        match shape {
            egui::Shape::Text(text) => {
                out.push_str(text.galley.text());
                out.push('\n');
            }
            egui::Shape::Vec(nested) => nested.iter().for_each(|inner| collect(inner, out)),
            _ => {}
        }
    }

    fn app_with_vault(dir: &TempDir) -> DesktopApp {
        let mut app = DesktopApp::new();
        app.owner_ui
            .session
            .create_file(&dir.path().join("import.db"), PASS)
            .expect("create");
        app.owner_ui.session.unlock(PASS).expect("unlock");
        app
    }

    fn item(category: &str, title: &str, details: Value) -> Value {
        json!({
            "categoryUuid": category,
            "state": "active",
            "overview": { "title": title, "tags": ["synthetic"] },
            "details": details,
        })
    }

    fn fields(fields: Vec<(&str, &str, Value)>) -> Value {
        let fields: Vec<Value> = fields
            .into_iter()
            .map(|(id, title, value)| json!({ "id": id, "title": title, "value": value }))
            .collect();
        json!([{ "title": "", "fields": fields }])
    }

    fn api(title: &str, token: &str) -> Value {
        item(
            "112",
            title,
            json!({ "sections": fields(vec![
                ("credential", "credential", json!({ "concealed": token })),
                ("hostname", "hostname", json!({ "string": "api.example.test" })),
                ("x1", "Org ID", json!({ "string": "SYNTH-OP-org" })),
            ]) }),
        )
    }

    fn database(title: &str) -> Value {
        item(
            "102",
            title,
            json!({ "sections": fields(vec![
                ("hostname", "server", json!({ "string": "db.example.test" })),
                ("port", "port", json!({ "string": "5432" })),
                ("database", "database", json!({ "string": "app" })),
                ("username", "username", json!({ "string": "app_user" })),
                ("password", "password", json!({ "concealed": "SYNTH-OP-ui-db" })),
            ]) }),
        )
    }

    fn login(title: &str) -> Value {
        item(
            "001",
            title,
            json!({
                "loginFields": [
                    { "value": "octo", "designation": "username" },
                    { "value": "SYNTH-OP-ui-login", "fieldType": "P", "designation": "password" },
                ],
                "notesPlain": "Synthetic notes.",
                "sections": fields(vec![(
                    "totp",
                    "one-time password",
                    json!({ "totp": "otpauth://totp/x?secret=SYNTH-OP-ui-totp" }),
                )]),
            }),
        )
    }

    fn ssh(title: &str) -> Value {
        item(
            "114",
            title,
            json!({ "sections": fields(vec![(
                "private_key",
                "private key",
                json!({ "sshKey": {
                    "privateKey": "SYNTH-OP-ui-pkcs8",
                    "metadata": {
                        "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\nSYNTH-OP-ui-ssh\n-----END OPENSSH PRIVATE KEY-----\n",
                        "publicKey": "ssh-ed25519 AAAA synthetic",
                        "fingerprint": "SHA256:synthetic",
                        "keyType": "ed25519",
                    },
                } }),
            )]) }),
        )
    }

    /// Write a 1PUX file with `items` in one vault "Engineering".
    fn write_export(dir: &TempDir, items: Vec<Value>) -> std::path::PathBuf {
        let data = json!({ "accounts": [{ "vaults": [
            { "attrs": { "name": "Engineering" }, "items": items },
        ] }] });
        let path = dir.path().join("1PasswordExport.1pux");
        std::fs::write(&path, zip_fixture::onepux(&data.to_string())).expect("write");
        path
    }

    fn add_database(app: &mut DesktopApp, name: &str) {
        let mut secrets = SecretForm::default();
        secrets.password = "SYNTH-OP-existing".to_owned();
        app.owner_ui
            .session
            .add(
                &ItemDraft {
                    name: name.to_owned(),
                    kind: CredentialKind::Database,
                    host: "db.example.test".to_owned(),
                    database_name: "app".to_owned(),
                    username: "app_user".to_owned(),
                    ..ItemDraft::default()
                },
                &secrets,
            )
            .expect("add");
    }

    fn names(app: &DesktopApp) -> Vec<(String, CredentialKind)> {
        let mut rows: Vec<_> = app
            .owner_ui
            .session
            .search("")
            .expect("search")
            .into_iter()
            .map(|row| (row.name, row.kind))
            .collect();
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        rows
    }

    #[test]
    fn the_sheet_reads_a_file_shows_the_preview_and_imports_the_selection() {
        let dir = TempDir::new().expect("temp dir");
        let mut app = app_with_vault(&dir);
        add_database(&mut app, "Prod DB");
        let file = write_export(
            &dir,
            vec![
                api("Stripe test key", "SYNTH-OP-ui-token"),
                login("GitHub"),
                database("Prod DB"),
                ssh("Deploy key"),
                item(
                    "002",
                    "Visa",
                    json!({ "sections": fields(vec![(
                        "ccnum",
                        "number",
                        json!({ "creditCardNumber": "SYNTH-OP-4111" }),
                    )]) }),
                ),
            ],
        );
        let ctx = egui::Context::default();

        // Settings has the section.
        app.view = OwnerView::Settings;
        let text = frames(&ctx, &mut app, Vec::new());
        assert!(text.contains("Import from 1Password…"), "{text}");

        // Step 1: the path and the hint. A file dropped on the window fills the path.
        app.ui.sheet = Some(Sheet::Import);
        let text = frames(&ctx, &mut app, Vec::new());
        assert!(text.contains("Export file"), "{text}");
        assert!(text.contains("File > Export"), "{text}");
        let drop = RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, SIZE)),
            dropped_files: vec![std::sync::Arc::new(Dropped(file.clone()))],
            ..Default::default()
        };
        ctx.run_ui(drop, |ui| super::super::draw(&mut app, ui))
            .drop_without_applying_deltas();
        assert_eq!(app.import.path, file.display().to_string());

        // Read (⌘S): the preview.
        let text = frames(&ctx, &mut app, vec![command_s()]);
        assert!(app.import.has_preview());
        for shown in [
            "5 items in the 1PUX export",
            "Stripe test key",
            "Engineering · API Credential → API key",
            "Engineering · Login → Login",
            "Engineering · SSH Key → SSH key",
            "Already in the vault",
            "Apassy does not import Credit Card items",
            "Import 2 credentials",
        ] {
            assert!(text.contains(shown), "missing {shown}: {text}");
        }
        assert_eq!(app.import.selected, [true, false, false, true, false]);

        // Select all takes each item that can be imported, and none clears the list.
        app.import.select_all(true);
        assert_eq!(app.import.selected, [true, true, true, true, false]);
        app.import.select_all(false);
        assert_eq!(app.import.selected_count(), 0);
        app.import.selected = vec![true, false, false, true, false];

        // Import (⌘S): the result, and no parsed data stays.
        let text = frames(&ctx, &mut app, vec![command_s()]);
        assert!(!app.import.has_preview());
        assert!(app.import.selected.is_empty());
        for shown in [
            "Imported 2 credentials.",
            "The export file holds your secrets in plain text.",
            "Delete the export file",
            "not a secure wipe",
        ] {
            assert!(text.contains(shown), "missing {shown}: {text}");
        }
        assert_eq!(
            names(&app),
            [
                ("Deploy key".to_owned(), CredentialKind::SshKey),
                ("Prod DB".to_owned(), CredentialKind::Database),
                ("Stripe test key".to_owned(), CredentialKind::ApiKey),
            ]
        );
        let session = &app.owner_ui.session;
        assert_eq!(session.search("1password").expect("search").len(), 2);
        assert_eq!(session.search("synthetic").expect("search").len(), 2);
        // No agent gets access.
        assert!(session.agents().expect("agents").is_empty());
        assert!(session.env_bound_items().expect("bound").is_empty());

        // Delete the export file.
        app.import.delete_file();
        assert!(!file.exists());
        let text = frames(&ctx, &mut app, Vec::new());
        assert!(text.contains("The export file is deleted."), "{text}");

        // Done: the sheet closes and the state is empty.
        close_sheet(&mut app, &ctx);
        assert!(app.import.report.is_none() && app.import.file.is_none());
    }

    #[test]
    fn cancel_back_and_lock_drop_the_parsed_export() {
        let dir = TempDir::new().expect("temp dir");
        let mut app = app_with_vault(&dir);
        let file = write_export(&dir, vec![api("Key", "SYNTH-OP-a")]);
        let ctx = egui::Context::default();
        app.import.path = file.display().to_string();

        app.ui.sheet = Some(Sheet::Import);
        app.import.read(&app.owner_ui.session);
        assert!(app.import.has_preview());
        close_sheet(&mut app, &ctx);
        assert!(!app.import.has_preview());
        assert_eq!(app.ui.sheet, None);

        // Back.
        app.ui.sheet = Some(Sheet::Import);
        app.import.read(&app.owner_ui.session);
        app.import.forget();
        let text = frames(&ctx, &mut app, Vec::new());
        assert!(text.contains("Export file"), "{text}");

        // Lock from the app.
        app.import.read(&app.owner_ui.session);
        assert!(app.import.has_preview());
        app.lock_vault(None);
        assert!(!app.import.has_preview());

        // A lock by another path (for example a backup) drops it at the next frame.
        app.owner_ui.session.unlock(PASS).expect("unlock");
        app.import.read(&app.owner_ui.session);
        assert!(app.import.has_preview());
        app.owner_ui.session.lock().expect("lock");
        frames(&ctx, &mut app, Vec::new());
        assert!(!app.import.has_preview());
        assert_eq!(app.ui.sheet, None);
        // Nothing was imported.
        app.owner_ui.session.unlock(PASS).expect("unlock");
        assert!(names(&app).is_empty());
    }

    #[test]
    fn a_read_error_is_shown_in_the_sheet() {
        let dir = TempDir::new().expect("temp dir");
        let mut app = app_with_vault(&dir);
        let ctx = egui::Context::default();
        app.ui.sheet = Some(Sheet::Import);
        app.import.path = dir.path().join("missing.1pux").display().to_string();
        let text = frames(&ctx, &mut app, vec![command_s()]);
        assert!(!app.import.has_preview());
        assert!(text.contains("Apassy cannot read the file"), "{text}");
    }

    #[test]
    fn a_failed_item_does_not_stop_the_import() {
        let dir = TempDir::new().expect("temp dir");
        let mut app = app_with_vault(&dir);
        // Each value fits the preview, but JSON escapes a control character to six
        // bytes, so the stored item is larger than the 1 MB limit of the vault. The
        // entry is stored: deflated, it would expand past the ratio limit.
        let control = "\u{1}".repeat(60_000);
        let big: Vec<(&str, &str, Value)> = ["a", "b", "c", "d"]
            .into_iter()
            .map(|id| (id, id, json!({ "concealed": control })))
            .collect();
        let data = json!({ "accounts": [{ "vaults": [{
            "attrs": { "name": "Engineering" },
            "items": [
                item("112", "Too big", json!({ "sections": fields(big) })),
                api("Fine key", "SYNTH-OP-fine"),
            ],
        }] }] });
        let file = dir.path().join("big.1pux");
        let entry = zip_fixture::ZipEntry::new(
            "export.data",
            data.to_string().as_bytes(),
            zip_fixture::Method::Stored,
        );
        std::fs::write(&file, zip_fixture::build_zip(&[entry])).expect("write");
        let ctx = egui::Context::default();
        app.ui.sheet = Some(Sheet::Import);
        app.import.path = file.display().to_string();
        app.import.read(&app.owner_ui.session);
        app.import.select_all(true);
        assert_eq!(app.import.run(&mut app.owner_ui.session), 1);
        let text = frames(&ctx, &mut app, Vec::new());
        for shown in ["Imported 1 credential.", "Problems", "Too big"] {
            assert!(text.contains(shown), "missing {shown}: {text}");
        }
        assert_eq!(
            names(&app),
            [("Fine key".to_owned(), CredentialKind::ApiKey)]
        );
    }

    #[test]
    fn imported_items_can_be_edited_in_the_desktop_forms() {
        let dir = TempDir::new().expect("temp dir");
        let mut app = app_with_vault(&dir);
        let file = write_export(
            &dir,
            vec![
                api("Stripe test key", "SYNTH-OP-ui-token"),
                login("GitHub"),
                database("Prod DB"),
                ssh("Deploy key"),
                item("005", "Wi-Fi", json!({ "password": "SYNTH-OP-wifi" })),
                item("003", "Recovery", json!({ "notesPlain": "SYNTH-OP-note" })),
            ],
        );
        app.import.path = file.display().to_string();
        app.import.read(&app.owner_ui.session);
        app.import.select_all(true);
        assert_eq!(app.import.run(&mut app.owner_ui.session), 6);
        let session = &mut app.owner_ui.session;
        let rows = session.search("").expect("search");
        assert_eq!(rows.len(), 6);
        for row in rows {
            let details = session.details(row.id).expect("details");
            let draft = details.to_draft();
            let saved = session
                .update(row.id, details.revision, &draft, &SecretForm::default())
                .unwrap_or_else(|err| panic!("{}: {}", row.name, err.message));
            assert_eq!(saved.revision, details.revision + 1);
            // The edit keeps the imported tags and every hidden value.
            let after = session.details(row.id).expect("details");
            assert!(after.details == details.details, "{}", row.name);
        }
        assert_eq!(session.search("1password").expect("search").len(), 6);
        assert_eq!(session.search("synthetic").expect("search").len(), 6);

        // A new service label replaces the old one. The imported tags stay.
        let id = session.search("Stripe test key").expect("search")[0].id;
        for service in ["billing", "payments"] {
            let details = session.details(id).expect("details");
            let mut draft = details.to_draft();
            draft.service = service.to_owned();
            session
                .update(id, details.revision, &draft, &SecretForm::default())
                .expect("update");
        }
        assert!(session.search("billing").expect("search").is_empty());
        assert_eq!(session.search("payments").expect("search").len(), 1);
        assert_eq!(session.search("1password").expect("search").len(), 6);

        let vault = session.shared_vault();
        let vault = vault.lock().expect("vault");
        let vault = vault.as_ref().expect("open");
        let find = |title: &str| {
            vault
                .search(title)
                .expect("search")
                .into_iter()
                .find(|row| row.title == title)
                .expect("row")
                .id
        };
        assert_eq!(
            vault
                .reveal(find("Stripe test key"), "token")
                .unwrap()
                .expose(),
            "SYNTH-OP-ui-token"
        );
        let org = crate::import::detail_field_name("Org ID");
        assert_eq!(
            org,
            crate::desktop::owner_store::detail_field_name("Org ID")
        );
        assert_eq!(
            vault
                .reveal(find("Stripe test key"), &org)
                .unwrap()
                .expose(),
            "SYNTH-OP-org"
        );
        assert_eq!(
            vault.reveal(find("Wi-Fi"), "secret").unwrap().expose(),
            "SYNTH-OP-wifi"
        );
        assert_eq!(
            vault.reveal(find("Recovery"), "note").unwrap().expose(),
            "SYNTH-OP-note"
        );
    }
}
