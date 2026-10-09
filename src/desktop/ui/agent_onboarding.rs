//! A guide for host settings, credential access, and a first host request.
//! Saved settings never count as a host connection or a successful request.

use std::collections::BTreeSet;
use std::path::PathBuf;

use eframe::egui;

use super::agent_setup::Host;
use super::kit::{self, Style, Tone};
use super::{Sheet, agents, items};
use crate::desktop::owner_check::OwnerRequest;
use crate::desktop::{DesktopApp, OwnerView};
use crate::vault::AgentSummary;

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Step {
    #[default]
    Connect,
    Credentials,
    Start,
}

#[derive(Default)]
pub(super) struct State {
    agent_id: Option<u64>,
    vault_path: Option<PathBuf>,
    host: Option<Host>,
    step: Step,
    settings_saved: bool,
    selection: BTreeSet<u64>,
}

impl State {
    pub(super) fn prepare(&mut self, agent_id: u64, name: &str) {
        if self.agent_id != Some(agent_id) {
            *self = Self {
                agent_id: Some(agent_id),
                host: Some(if name.to_ascii_lowercase().contains("codex") {
                    Host::Codex
                } else {
                    Host::Claude
                }),
                ..Self::default()
            };
        }
    }

    pub(super) fn saved(&mut self, agent_id: u64, host: Host) {
        if self.agent_id != Some(agent_id) {
            *self = Self {
                agent_id: Some(agent_id),
                ..Self::default()
            };
        }
        self.host = Some(host);
        self.settings_saved = true;
        self.step = Step::Credentials;
    }
}

/// Called only after the host settings save succeeds.
pub(super) fn connected(app: &mut DesktopApp, agent_id: u64, host: Host) {
    app.ui.agent_onboarding.saved(agent_id, host);
    app.ui.agent_onboarding.vault_path = app.owner_ui.session.vault_path();
    app.owner_ui.selected_agent = Some(agent_id);
    app.view = OwnerView::Agents;
}

pub(super) fn draw(app: &mut DesktopApp, ui: &mut egui::Ui, agent: &AgentSummary) {
    if agent.revoked {
        kit::note(
            ui,
            "This agent is revoked. Register a new agent before you set access.",
        );
        return;
    }
    let vault_path = app.owner_ui.session.vault_path();
    let mut state = std::mem::take(&mut app.ui.agent_onboarding);
    if state.vault_path.is_some() && state.vault_path != vault_path {
        state = State::default();
    }
    state.prepare(agent.id, &agent.name);
    state.vault_path = vault_path;
    let mut host = state.host.unwrap_or(Host::Claude);
    if token_expired(agent) {
        kit::tone_note(
            ui,
            "The token expired. Save new host settings before you send a request.",
            Tone::Critical,
        );
    }
    kit::section(ui, Some("Agent setup"), None, |s| {
        s.row(|ui| {
            ui.horizontal_wrapped(|ui| {
                for (step, label) in [
                    (Step::Connect, "1. Connect"),
                    (Step::Credentials, "2. Credentials"),
                    (Step::Start, "3. Start host"),
                ] {
                    let style = if state.step == step {
                        Style::Prominent
                    } else {
                        Style::Bordered
                    };
                    if kit::button(ui, label, style).clicked() {
                        state.step = step;
                    }
                }
            });
        });
    });

    let mut rotate = false;
    let mut variable = None;
    let mut grant = false;
    let mut activity = false;
    match state.step {
        Step::Connect => {
            kit::section(ui, Some("Connect the host"), None, |s| {
                s.row(|ui| {
                    let mut host_index = host.index();
                    kit::picker(ui, "onboarding-host", &mut host_index,
                        &[(0, "Claude Code".to_owned()), (1, "Codex".to_owned())], host.name(), 200.0);
                    let chosen_host = Host::from_index(host_index);
                    if chosen_host != host {
                        state.settings_saved = false;
                    }
                    host = chosen_host;
                    state.host = Some(host);
                    kit::note(ui, if state.settings_saved {
                        "Host settings are saved. Check the connection in the host with /mcp."
                    } else {
                        "Save the Apassy settings for your host. Then select the credentials that this agent can use."
                    });
                    kit::note(ui, "To save new settings, get a new token. The new token stops the old token immediately.");
                    ui.add_enabled_ui(app.owner.check.is_none() && app.owner_ui.fresh_token.is_none(), |ui| {
                        rotate = kit::button(ui, &format!("Connect {}…", host.name()), Style::Bordered).clicked();
                    });
                    if kit::button(ui, "Choose credentials", Style::Prominent).clicked() {
                        state.step = Step::Credentials;
                    }
                });
            });
        }
        Step::Credentials => {
            let rows = credential_rows(app);
            match rows {
                Err(message) => kit::tone_note(ui, message, Tone::Critical),
                Ok(rows) => {
                    state
                        .selection
                        .retain(|id| rows.iter().any(|row| row.0 == *id));
                    let grants = app.owner_ui.session.exec_grants(agent.id);
                    let all_bound = !state.selection.is_empty()
                        && rows
                            .iter()
                            .filter(|row| state.selection.contains(&row.0))
                            .all(|row| row.2.is_some());
                    let all_granted = can_continue(app, agent, &state.selection);
                    kit::section(ui, Some("Choose credentials"), None, |s| {
                        if rows.is_empty() {
                            s.row(|ui| {
                                kit::note(ui, "Add a credential with a secret value in Credentials. Then return to this guide.");
                                if kit::button(ui, "Go to Credentials", Style::Bordered).clicked() {
                                    app.view = OwnerView::Vault;
                                }
                            });
                        }
                        for (id, name, env_name) in &rows {
                            let mut selected = state.selection.contains(id);
                            let subtitle = env_name
                                .as_deref()
                                .unwrap_or("Set an environment variable first");
                            if s.toggle(name, Some(subtitle), &mut selected).changed() {
                                if selected {
                                    state.selection.insert(*id);
                                } else {
                                    state.selection.remove(id);
                                }
                            }
                            if selected {
                                s.row(|ui| {
                                    if kit::small_button(
                                        ui,
                                        &format!("Set variable for {name}…"),
                                        Style::Link,
                                    )
                                    .clicked()
                                    {
                                        variable = Some(*id);
                                    }
                                });
                            }
                        }
                        s.row(|ui| {
                            kit::note(ui, "Set a variable for each selected credential. Then set the project folder and access decision.");
                            if let Err(error) = &grants {
                                kit::tone_note(ui, &error.message, Tone::Critical);
                            }
                            ui.add_enabled_ui(all_bound, |ui| {
                                grant = kit::button(ui, "Set access…", Style::Prominent).clicked();
                            });
                            kit::note(ui, "You confirm each variable change and each access change. Adjust rules from the credential access rows below.");
                            if !all_granted {
                                kit::note(ui, "Give this agent access to all selected credentials before you continue.");
                            }
                            ui.horizontal_wrapped(|ui| {
                                if kit::button(ui, "Back", Style::Bordered).clicked() {
                                    state.step = Step::Connect;
                                }
                                ui.add_enabled_ui(all_granted, |ui| {
                                    if kit::button(ui, "Continue", Style::Prominent).clicked() {
                                        state.step = Step::Start;
                                    }
                                });
                            });
                        });
                    });
                }
            }
        }
        Step::Start => {
            kit::section(ui, Some("Start the host and check a request"), None, |s| {
                s.row(|ui| {
                    kit::note(ui, format!("Close {}. In your project folder, run this command. Keep Apassy open and the vault unlocked.", host.name()));
                    kit::code_block(ui, &launch_command(host), 2);
                    kit::note(ui, "This command uses the Apassy sandbox. The host approval prompts stay active.");
                    if host == Host::Codex {
                        kit::note(ui, "Use /hooks to trust the Apassy hook. Then use /mcp to check the Apassy connection.");
                    } else {
                        kit::note(ui, "Use /mcp to check the Apassy connection.");
                    }
                    kit::note(ui, "Send this test prompt to the host:");
                    kit::code_block(ui, "Use Apassy to list the credentials that this agent can use. Do not read or print secret values.", 3);
                    kit::note(ui, "Check the response in the host. A successful list request does not make an Activity entry. It does not test a command with a secret.");
                    match app.owner_ui.session.agent_activity(agent.id, 1) {
                        Ok(rows) => match rows.first() {
                            Some(row) => kit::note(ui, format!("Last recorded request: {} · {}", row.when, row.operation)),
                            None => kit::note(ui, "No request is recorded for this agent."),
                        },
                        Err(error) => kit::tone_note(ui, &error.message, Tone::Critical),
                    }
                    kit::note(ui, "Saved settings do not prove a connection. An Allowed entry does not prove a successful request.");
                    ui.horizontal_wrapped(|ui| {
                        if kit::button(ui, "Back", Style::Bordered).clicked() {
                            state.step = Step::Credentials;
                        }
                        activity = kit::button(ui, "Open Activity", Style::Prominent).clicked();
                    });
                });
            });
        }
    }
    let selection = state.selection.clone();
    app.ui.agent_onboarding = state;
    if rotate {
        app.ui.setup_host = host.index();
        let ctx = ui.ctx().clone();
        app.ask_owner(
            OwnerRequest::RotateToken {
                agent_id: agent.id,
                agent_name: agent.name.clone(),
            },
            Some(&ctx),
        );
    }
    if let Some(id) = variable {
        open_variable(app, id);
    }
    if grant {
        app.ui.grant = agents::GrantForm {
            selection,
            ..Default::default()
        };
        app.ui.sheet = Some(Sheet::GrantMany { agent_id: agent.id });
    }
    if activity {
        app.view = OwnerView::Activity;
    }
}

fn token_expired(agent: &AgentSummary) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    agent.token_expired_at(now)
}

fn can_continue(app: &DesktopApp, agent: &AgentSummary, selection: &BTreeSet<u64>) -> bool {
    if agent.revoked || token_expired(agent) || selection.is_empty() {
        return false;
    }
    let (Ok(rows), Ok(grants)) = (
        credential_rows(app),
        app.owner_ui.session.exec_grants(agent.id),
    ) else {
        return false;
    };
    selection.iter().all(|id| {
        rows.iter().any(|row| row.0 == *id && row.2.is_some())
            && grants.iter().any(|grant| grant.item_id == *id)
    })
}

fn open_variable(app: &mut DesktopApp, item_id: u64) {
    app.select_item(item_id.to_string());
    items::prepare_sheet(app, item_id, &Sheet::Variable);
    app.ui.sheet = Some(Sheet::Variable);
    app.view = OwnerView::Agents;
}

fn credential_rows(app: &DesktopApp) -> Result<Vec<(u64, String, Option<String>)>, String> {
    let session = &app.owner_ui.session;
    let archived = session.archived().map_err(|error| error.message)?;
    let mut rows = Vec::new();
    for item in session.search("").map_err(|error| error.message)? {
        if archived.contains_key(&item.id)
            || session
                .secret_fields(item.id)
                .map_err(|error| error.message)?
                .is_empty()
        {
            continue;
        }
        let variable = session
            .env_binding(item.id)
            .map_err(|error| error.message)?
            .map(|binding| binding.env_name);
        rows.push((item.id, item.name, variable));
    }
    Ok(rows)
}

fn launch_command(host: Host) -> String {
    let sandbox = std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|parent| parent.join("apassy-sandbox")))
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "apassy-sandbox".to_owned());
    let sandbox = format!("'{}'", sandbox.replace('\'', "'\\''"));
    match host {
        Host::Claude => format!(
            "MCP_TOOL_TIMEOUT=180000 {sandbox} -- claude --settings '{{\"sandbox\":{{\"enabled\":false}}}}'"
        ),
        Host::Codex => format!("{sandbox} -- codex -c sandbox_mode=danger-full-access"),
    }
}

#[cfg(test)]
mod tests {
    use super::super::owner_tests::{PASS, WRONG, unlocked_app_with_item};
    use super::*;
    use crate::broker::approvals::OwnerCheck;
    use crate::vault::{EnvDelivery, ExecMode, GrantPlace};

    #[test]
    fn saved_settings_keep_selection_but_a_different_agent_starts_a_new_guide() {
        let mut state = State::default();
        state.prepare(1, "Codex");
        state.selection.insert(9);
        state.saved(1, Host::Codex);
        state.prepare(1, "Codex");
        assert!(state.settings_saved);
        assert!(state.step == Step::Credentials);
        assert_eq!(state.selection, [9].into_iter().collect());
        state.prepare(2, "Claude Code");
        assert!(!state.settings_saved);
        assert!(state.step == Step::Connect);
        assert!(state.selection.is_empty());
        assert_eq!(state.host, Some(Host::Claude));
    }

    #[test]
    fn variable_sheet_keeps_agent_view_and_selection_and_waits_for_owner() {
        let dir = tempfile::TempDir::new().unwrap();
        let (mut app, item_id) = unlocked_app_with_item(&dir);
        let (agent, _) = app.owner_ui.session.register_agent("Codex").unwrap();
        connected(&mut app, agent.id, Host::Codex);
        app.ui.agent_onboarding.selection.insert(item_id);
        open_variable(&mut app, item_id);
        assert_eq!(app.view, OwnerView::Agents);
        assert_eq!(app.owner_ui.selected_agent, Some(agent.id));
        assert_eq!(app.ui.sheet, Some(Sheet::Variable));
        let request = OwnerRequest::SaveVariable {
            item_id,
            env_name: "GUIDE_TEST_KEY".to_owned(),
            field: "token".to_owned(),
            delivery: EnvDelivery::Value,
        };
        let ctx = egui::Context::default();
        super::super::ask_owner_from_sheet(&mut app, request.clone(), &ctx);
        assert!(app.owner_ui.session.env_binding(item_id).unwrap().is_none());
        assert!(
            app.confirm_owner_now(OwnerCheck::passphrase(WRONG))
                .is_err()
        );
        assert!(app.owner_ui.session.env_binding(item_id).unwrap().is_none());
        super::super::ask_owner_from_sheet(&mut app, request, &ctx);
        app.confirm_owner_now(OwnerCheck::passphrase(PASS)).unwrap();
        super::super::close_sheet_after_check(&mut app);
        assert!(app.ui.sheet.is_none());
        assert_eq!(app.view, OwnerView::Agents);
        assert_eq!(
            app.ui.agent_onboarding.selection,
            [item_id].into_iter().collect()
        );
        assert!(app.ui.agent_onboarding.step == Step::Credentials);
    }

    #[test]
    fn continue_needs_a_bound_credential_and_confirmed_grant_and_valid_token() {
        let dir = tempfile::TempDir::new().unwrap();
        let (mut app, item_id) = unlocked_app_with_item(&dir);
        let (mut agent, _) = app.owner_ui.session.register_agent("Codex").unwrap();
        let selection = [item_id].into_iter().collect();
        assert!(!can_continue(&app, &agent, &selection));
        app.ask_owner(
            OwnerRequest::SaveVariable {
                item_id,
                env_name: "GUIDE_TEST_KEY".to_owned(),
                field: "token".to_owned(),
                delivery: EnvDelivery::Value,
            },
            None,
        );
        app.confirm_owner_now(OwnerCheck::passphrase(PASS)).unwrap();
        assert!(!can_continue(&app, &agent, &selection));
        app.ask_owner(
            OwnerRequest::GrantMany {
                agent_id: agent.id,
                item_ids: vec![item_id],
                place: GrantPlace::AnyFolder,
                mode: ExecMode::Ask,
            },
            None,
        );
        assert!(!can_continue(&app, &agent, &selection));
        app.confirm_owner_now(OwnerCheck::passphrase(PASS)).unwrap();
        assert!(can_continue(&app, &agent, &selection));
        assert!(!can_continue(&app, &agent, &BTreeSet::new()));
        agent.token_expires_at = 1;
        assert!(!can_continue(&app, &agent, &selection));
        agent.token_expires_at = u64::MAX;
        agent.revoked = true;
        assert!(!can_continue(&app, &agent, &selection));
        agent.revoked = false;
        app.owner_ui.session.archive(item_id).unwrap();
        assert!(!can_continue(&app, &agent, &selection));
    }

    #[test]
    fn credential_choices_exclude_items_without_secrets_and_archived_items() {
        let dir = tempfile::TempDir::new().unwrap();
        let (mut app, item_id) = unlocked_app_with_item(&dir);
        let empty = app
            .owner_ui
            .session
            .add_imported(crate::vault::ItemDraft {
                title: "No secret".to_owned(),
                kind: crate::contracts::CredentialKind::Custom,
                notes: String::new(),
                tags: Vec::new(),
                fields: vec![crate::vault::Field {
                    name: "description".to_owned(),
                    value: crate::vault::SecretValue::new("Public description".to_owned()),
                    secret: false,
                }],
            })
            .unwrap();
        let rows = credential_rows(&app).unwrap();
        assert!(rows.iter().any(|row| row.0 == item_id));
        assert!(!rows.iter().any(|row| row.0 == empty.id));
        app.owner_ui.session.archive(item_id).unwrap();
        assert!(credential_rows(&app).unwrap().is_empty());
    }
}
