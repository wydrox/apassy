//! Find duplicates: Settings > Vault > Import > "Find duplicates…", and the result of a
//! 1Password import. A sheet lists each group of items that look like the same account,
//! with what differs (labels only), a picker for the item to keep, and "Merge". The
//! rules are the vault's (`src/vault/dedup.rs`): the kept item takes the fields of the
//! others, and the others are archived, not deleted.
//!
//! The state holds titles and labels, never a value.

use std::collections::BTreeMap;

use eframe::egui;

use super::kit::{self, Font, Style, Tone};
use super::{Sheet, close_sheet};
use crate::desktop::DesktopApp;
use crate::desktop::owner_store::OwnerSession;
use crate::vault::{DuplicateGroup, VaultErrorKind};

/// The sheet state.
#[derive(Debug, Default)]
pub(crate) struct State {
    /// The groups of the last read.
    groups: Vec<DuplicateGroup>,
    /// The vault session of the last read. Another session reads again.
    epoch: Option<[u8; 32]>,
    /// The item to keep that the owner picked, by the first ID of its group.
    keep: BTreeMap<u64, u64>,
    /// Why the last read or merge failed.
    error: Option<String>,
}

impl State {
    /// Read the groups again. A pick that still fits its group stays.
    pub(crate) fn refresh(&mut self, session: &OwnerSession) {
        self.error = None;
        self.epoch = session.epoch();
        match session.with_vault(|vault| vault.duplicate_groups()) {
            Some(Ok(groups)) => self.groups = groups,
            Some(Err(_)) | None => {
                self.groups.clear();
                self.error = Some("Apassy could not read the vault.".to_owned());
            }
        }
        let groups = &self.groups;
        self.keep.retain(|first, keep| {
            groups.iter().any(|group| {
                group.items.first().is_some_and(|item| item.id == *first)
                    && group.keep_choices.contains(keep)
            })
        });
    }

    #[cfg(test)]
    pub(crate) fn groups(&self) -> &[DuplicateGroup] {
        &self.groups
    }

    /// The item to keep of a group: the pick of the owner, else the suggestion, else the
    /// first item that the group can merge into. `None` when it cannot merge.
    fn chosen(&self, group: &DuplicateGroup) -> Option<u64> {
        let first = group.items.first()?.id;
        let keep = self.keep.get(&first).copied().unwrap_or(group.keep);
        if group.keep_choices.contains(&keep) {
            Some(keep)
        } else {
            group.keep_choices.first().copied()
        }
    }
}

/// The duplicate sets of the open vault, as member IDs, for the "Possible duplicates"
/// filter of the credential list. The list draws each frame, so the sets are read again
/// only when `key` changes: the caller hashes the vault session, each item with its
/// revision, and the archived items. One definition for the list and the sheet.
#[derive(Default)]
pub(crate) struct ListCache {
    key: Option<u64>,
    groups: Vec<Vec<u64>>,
}

impl ListCache {
    pub(crate) fn groups(&mut self, session: &OwnerSession, key: u64) -> &[Vec<u64>] {
        if self.key != Some(key) {
            self.groups = session
                .with_vault(|vault| vault.duplicate_groups())
                .and_then(Result::ok)
                .unwrap_or_default()
                .into_iter()
                .map(|group| group.items.into_iter().map(|item| item.id).collect())
                .collect();
            self.key = Some(key);
        }
        &self.groups
    }
}

/// Whether the open vault has duplicates, for the result of an import.
pub(crate) fn any(session: &OwnerSession) -> bool {
    session
        .with_vault(|vault| vault.duplicate_groups())
        .and_then(Result::ok)
        .is_some_and(|groups| !groups.is_empty())
}

/// Read the groups and show the sheet.
pub(super) fn open(app: &mut DesktopApp) {
    app.ui.duplicates = State::default();
    app.ui.duplicates.refresh(&app.owner_ui.session);
    app.ui.sheet = Some(Sheet::Duplicates);
}

/// Merge `group` into `keep`. The count of archived items, or the message for the owner.
fn merge(session: &mut OwnerSession, group: &DuplicateGroup, keep: u64) -> Result<usize, String> {
    let Some(kept) = group.items.iter().find(|item| item.id == keep) else {
        return Err("Choose the item to keep.".to_owned());
    };
    let others: Vec<(u64, u64)> = group
        .items
        .iter()
        .filter(|item| item.id != keep)
        .map(|item| (item.id, item.revision))
        .collect();
    let ids: Vec<u64> = others.iter().map(|(id, _)| *id).collect();
    let result = session.with_vault(|vault| {
        vault
            .merge_duplicates((keep, kept.revision), &others)
            .map_err(|error| match error.kind() {
                VaultErrorKind::InvalidInput => match vault.merge_refusal(keep, &ids) {
                    Ok(Some(refusal)) => format!("Cannot merge: {}.", refusal.reason()),
                    _ => "These items are not duplicates now.".to_owned(),
                },
                VaultErrorKind::Conflict => "An item changed. Look at the list again.".to_owned(),
                VaultErrorKind::NotFound => "An item is not in the vault any more.".to_owned(),
                VaultErrorKind::Locked => "The vault is locked.".to_owned(),
                _ => "Apassy could not merge the items.".to_owned(),
            })
    });
    let outcome = result.ok_or_else(|| "The vault is locked.".to_owned())??;
    // An archived item forgets its shown values, as an archive from its page does. The
    // item is archived already, so this records nothing.
    for id in &outcome.archived {
        let _ = session.archive(*id);
    }
    Ok(outcome.archived.len())
}

/// Merge each identical group into its suggested item. The count of merged groups and
/// the first failure.
fn merge_identical(app: &mut DesktopApp) -> (usize, Option<String>) {
    let groups: Vec<DuplicateGroup> = app
        .ui
        .duplicates
        .groups
        .iter()
        .filter(|group| group.identical && group.mergeable)
        .cloned()
        .collect();
    let mut merged = 0;
    let mut failed = None;
    for group in &groups {
        match merge(&mut app.owner_ui.session, group, group.keep) {
            Ok(_) => merged += 1,
            Err(message) => {
                failed.get_or_insert(message);
            }
        }
    }
    (merged, failed)
}

fn count(n: usize, one: &str, many: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{n} {many}")
    }
}

/// The line under the titles: the kind, and what differs.
fn summary(group: &DuplicateGroup) -> String {
    let kind = group.items.first().map_or("", |item| item.kind.label());
    if group.identical {
        format!("{kind} · Same values")
    } else {
        let labels: Vec<&str> = group
            .differences
            .iter()
            .map(String::as_str)
            .filter(|label| *label != "Title")
            .collect();
        format!("{kind} · Differs: {}", labels.join(", "))
    }
}

/// The picker labels: the title, with its place in the group when two titles are equal.
fn keep_options(group: &DuplicateGroup) -> Vec<(u64, String)> {
    group
        .keep_choices
        .iter()
        .filter_map(|id| {
            let position = group.items.iter().position(|item| item.id == *id)?;
            let item = &group.items[position];
            let twice = group
                .items
                .iter()
                .filter(|other| other.title == item.title)
                .count()
                > 1;
            Some(if twice {
                (*id, format!("{} ({})", item.title, position + 1))
            } else {
                (*id, item.title.clone())
            })
        })
        .collect()
}

/// One group: the titles, the line, and the controls.
fn group_row(
    ui: &mut egui::Ui,
    group: &DuplicateGroup,
    chosen: Option<u64>,
) -> (Option<u64>, bool) {
    let mut pick = chosen;
    let mut merge = false;
    let first = group.items.first().map_or(0, |item| item.id);
    let titles: Vec<&str> = group.items.iter().map(|item| item.title.as_str()).collect();
    ui.label(kit::text(titles.join(", "), Font::Body).color(kit::palette().label));
    kit::note(ui, summary(group));
    match chosen {
        Some(keep) => {
            let options = keep_options(group);
            let selected = options
                .iter()
                .find(|(id, _)| *id == keep)
                .map_or_else(String::new, |(_, label)| label.clone());
            ui.horizontal(|ui| {
                ui.label(kit::text("Keep", Font::Body).color(kit::palette().secondary));
                let mut value = keep;
                kit::picker(
                    ui,
                    ("duplicates-keep", first),
                    &mut value,
                    &options,
                    selected,
                    240.0,
                );
                pick = Some(value);
                merge = kit::small_button(ui, "Merge", Style::Bordered).clicked();
            });
        }
        None => {
            let reason = group.reason.as_deref().unwrap_or("Cannot merge");
            kit::tone_note(ui, reason, Tone::Warning);
        }
    }
    (pick, merge)
}

pub(super) fn sheet(app: &mut DesktopApp, ctx: &egui::Context) -> bool {
    if app.ui.duplicates.epoch != app.owner_ui.session.epoch() {
        app.ui.duplicates.refresh(&app.owner_ui.session);
    }
    let mut merge_one: Option<(usize, u64)> = None;
    let mut merge_all = false;
    let mut done = false;
    let mut picks: Vec<(u64, u64)> = Vec::new();
    let response = kit::sheet(ctx, "duplicates", 600.0, |ui| {
        let state = &app.ui.duplicates;
        kit::sheet_title(
            ui,
            "Find duplicates",
            Some(
                "Items that look like the same account: the same website and username, or the same secret values. Merge keeps one item, adds what the others have, and archives them.",
            ),
        );
        kit::sheet_body(ui, |ui| {
            if let Some(error) = &state.error {
                kit::tone_note(ui, error, Tone::Critical);
                ui.add_space(8.0);
            }
            if state.groups.is_empty() {
                kit::note(ui, "No duplicates found.");
                return;
            }
            kit::section(ui, None, None, |s| {
                for (index, group) in state.groups.iter().enumerate() {
                    let chosen = state.chosen(group);
                    let first = group.items.first().map_or(0, |item| item.id);
                    let (pick, merge) = s.row(|ui| {
                        ui.push_id(("duplicates-group", first), |ui| {
                            group_row(ui, group, chosen)
                        })
                        .inner
                    });
                    if let Some(pick) = pick
                        && Some(pick) != chosen
                    {
                        picks.push((first, pick));
                    }
                    if merge && let Some(keep) = pick {
                        merge_one = Some((index, keep));
                    }
                }
            });
        });
        let identical = state
            .groups
            .iter()
            .filter(|group| group.identical && group.mergeable)
            .count();
        kit::sheet_buttons(
            ui,
            |ui| {
                ui.add_enabled_ui(identical > 0, |ui| {
                    merge_all = kit::button(ui, "Merge all identical", Style::Bordered).clicked();
                });
            },
            |ui| {
                done = kit::button(ui, "Done", Style::Prominent).clicked();
            },
        );
    });
    for (first, pick) in picks {
        app.ui.duplicates.keep.insert(first, pick);
    }
    if let Some((index, keep)) = merge_one
        && let Some(group) = app.ui.duplicates.groups.get(index).cloned()
    {
        match merge(&mut app.owner_ui.session, &group, keep) {
            Ok(archived) => {
                let title = group
                    .items
                    .iter()
                    .find(|item| item.id == keep)
                    .map_or_else(String::new, |item| item.title.clone());
                app.set_ok(format!(
                    "Merged {} into “{title}”.",
                    count(archived, "item", "items")
                ));
                app.ui.duplicates.refresh(&app.owner_ui.session);
            }
            Err(message) => {
                app.ui.duplicates.refresh(&app.owner_ui.session);
                app.ui.duplicates.error = Some(message);
            }
        }
    }
    if merge_all {
        let (merged, failed) = merge_identical(app);
        app.ui.duplicates.refresh(&app.owner_ui.session);
        if merged > 0 {
            app.set_ok(format!("Merged {}.", count(merged, "group", "groups")));
        }
        app.ui.duplicates.error = failed;
    }
    if done {
        // From the result of an import, Done goes back to it: it still offers to delete
        // the export file.
        if app.import.has_report() {
            app.ui.duplicates = State::default();
            app.ui.sheet = Some(Sheet::Import);
        } else {
            close_sheet(app, ctx);
        }
    }
    response.escape
}

#[cfg(test)]
mod tests {
    //! Headless tests of the sheet. Synthetic data only: each secret starts with
    //! `SYNTH-DUP-`.

    use eframe::egui::{Pos2, RawInput, Rect, Vec2};
    use tempfile::TempDir;

    use super::*;
    use crate::contracts::CredentialKind;
    use crate::vault::{Field, ItemDraft as VaultDraft, SecretValue};

    const PASS: &str = "ui-duplicates-pass-ok";
    const CANARY: &str = "SYNTH-DUP-";
    const SIZE: Vec2 = Vec2::new(1280.0, 2400.0);

    fn frames(ctx: &egui::Context, app: &mut DesktopApp) -> String {
        let mut text = String::new();
        for _ in 0..3 {
            let input = RawInput {
                screen_rect: Some(Rect::from_min_size(Pos2::ZERO, SIZE)),
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
            .create_file(&dir.path().join("duplicates.db"), PASS)
            .expect("create");
        app.owner_ui.session.unlock(PASS).expect("unlock");
        app
    }

    fn field(name: &str, value: &str, secret: bool) -> Field {
        Field {
            name: name.to_owned(),
            value: SecretValue::new(value.to_owned()),
            secret,
        }
    }

    fn api_key(title: &str, token: &str, notes: &str) -> VaultDraft {
        VaultDraft {
            title: title.to_owned(),
            kind: CredentialKind::ApiKey,
            notes: notes.to_owned(),
            tags: Vec::new(),
            fields: vec![field("token", token, true)],
        }
    }

    fn add(app: &mut DesktopApp, draft: VaultDraft) -> u64 {
        app.owner_ui
            .session
            .with_vault(|vault| vault.add(draft))
            .expect("open")
            .expect("add")
            .id
    }

    fn archived(app: &DesktopApp, id: u64) -> bool {
        app.owner_ui
            .session
            .with_vault(|vault| vault.is_archived(id))
            .expect("open")
            .expect("archived")
    }

    #[test]
    fn the_sheet_opens_from_settings_and_shows_the_empty_state() {
        let dir = TempDir::new().expect("temp dir");
        let mut app = app_with_vault(&dir);
        let ctx = egui::Context::default();
        crate::desktop::ui::open_settings(&mut app, crate::desktop::ui::SettingsSection::Vault);
        let text = frames(&ctx, &mut app);
        assert!(text.contains("Find duplicates…"), "{text}");
        open(&mut app);
        let text = frames(&ctx, &mut app);
        assert!(text.contains("Find duplicates"), "{text}");
        assert!(text.contains("No duplicates found."), "{text}");
        close_sheet(&mut app, &ctx);
        assert_eq!(app.ui.sheet, None);
    }

    #[test]
    fn a_duplicate_pair_lists_merges_and_archives_one() {
        let dir = TempDir::new().expect("temp dir");
        let mut app = app_with_vault(&dir);
        let first = add(&mut app, api_key("Stripe", "SYNTH-DUP-token", "First note"));
        let second = add(
            &mut app,
            api_key("Stripe (1Password)", "SYNTH-DUP-token", "Second note"),
        );
        let ctx = egui::Context::default();
        open(&mut app);
        let text = frames(&ctx, &mut app);
        for shown in [
            "Stripe, Stripe (1Password)",
            "API key · Differs: Notes",
            "Keep",
            "Merge",
        ] {
            assert!(text.contains(shown), "missing {shown}: {text}");
        }
        let group = app.ui.duplicates.groups()[0].clone();
        assert_eq!(group.keep_choices, [first, second]);
        // The suggestion is the newer item, or the first on a tie of the clock second.
        let keep = group.keep;
        let other = if keep == first { second } else { first };
        assert_eq!(merge(&mut app.owner_ui.session, &group, keep), Ok(1));
        assert!(archived(&app, other));
        assert!(!archived(&app, keep));
        app.ui.duplicates.refresh(&app.owner_ui.session);
        let text = frames(&ctx, &mut app);
        assert!(text.contains("No duplicates found."), "{text}");
    }

    #[test]
    fn merge_all_identical_merges_only_the_identical_groups() {
        let dir = TempDir::new().expect("temp dir");
        let mut app = app_with_vault(&dir);
        let a = add(&mut app, api_key("Alpha", "SYNTH-DUP-alpha", ""));
        let a2 = add(&mut app, api_key("Alpha copy", "SYNTH-DUP-alpha", ""));
        let b = add(&mut app, api_key("Beta", "SYNTH-DUP-beta", "One"));
        let b2 = add(&mut app, api_key("Beta copy", "SYNTH-DUP-beta", "Two"));
        let ctx = egui::Context::default();
        open(&mut app);
        let text = frames(&ctx, &mut app);
        assert!(text.contains("API key · Same values"), "{text}");
        assert!(text.contains("Merge all identical"), "{text}");
        let (merged, failed) = merge_identical(&mut app);
        assert_eq!((merged, failed), (1, None));
        assert!(archived(&app, a2) != archived(&app, a));
        assert!(!archived(&app, b) && !archived(&app, b2));
        app.ui.duplicates.refresh(&app.owner_ui.session);
        assert_eq!(app.ui.duplicates.groups().len(), 1);
        assert_eq!(app.ui.duplicates.groups()[0].items[0].id, b);
    }

    #[test]
    fn a_lock_drops_the_groups() {
        let dir = TempDir::new().expect("temp dir");
        let mut app = app_with_vault(&dir);
        add(&mut app, api_key("Gamma", "SYNTH-DUP-gamma", ""));
        add(&mut app, api_key("Gamma copy", "SYNTH-DUP-gamma", ""));
        let ctx = egui::Context::default();
        open(&mut app);
        frames(&ctx, &mut app);
        assert_eq!(app.ui.duplicates.groups().len(), 1);
        app.owner_ui.session.lock().expect("lock");
        frames(&ctx, &mut app);
        assert_eq!(app.ui.sheet, None);
        assert!(app.ui.duplicates.groups().is_empty());
    }
}
