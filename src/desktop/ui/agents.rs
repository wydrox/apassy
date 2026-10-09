//! Agents: the list, one agent with its access, and the token sheets (vault build).
//!
//! An agent uses a credential through the Apassy broker (ADR 0004). The list shows
//! each agent and its token state. The agent page shows its token, what it can see
//! (ADR 0012), its process access for each credential with an environment variable,
//! and its API operations.

use eframe::egui::{self, Align, Layout};

use super::kit::{self, Font, Icon, Size, Style, Tone};
use super::{Sheet, ask_owner_from_sheet, close_sheet};
use crate::desktop::owner_check::OwnerRequest;
use crate::desktop::owner_store::{FreshToken, RuleForm, format_utc};
use crate::desktop::{DesktopApp, OwnerView};
use crate::vault::{AgentSummary, EnvDelivery, ExecMode, GrantPlace};

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// The date part of a UTC time.
fn date(unix: u64) -> String {
    format_utc(unix)
        .split(' ')
        .next()
        .unwrap_or_default()
        .to_owned()
}

pub(super) fn draw(app: &mut DesktopApp, ui: &mut egui::Ui) {
    match app.owner_ui.selected_agent {
        Some(agent_id) => draw_agent(app, ui, agent_id),
        None => draw_list(app, ui),
    }
}

fn status(agent: &AgentSummary, now: u64) -> (&'static str, Tone) {
    if agent.revoked {
        ("Revoked", Tone::Neutral)
    } else if agent.token_expired_at(now) {
        ("Token expired", Tone::Critical)
    } else {
        ("Active", Tone::Good)
    }
}

/// Continue after a synced vault opens. The caller ties panel visibility to the
/// vault identity. A host choice or Skip ends this panel; CLI keeps its steps open.
pub(super) fn next_steps_panel(app: &mut DesktopApp, ui: &mut egui::Ui) -> bool {
    if app.owner_ui.session.is_locked() {
        return false;
    }
    let intro = match (
        app.owner_ui.session.search(""),
        app.owner_ui.session.archived(),
    ) {
        (Ok(items), Ok(archived)) => {
            let count = items
                .iter()
                .filter(|item| !archived.contains_key(&item.id))
                .count();
            if count == 1 {
                "The vault is open. 1 active credential is available on this Mac.".to_owned()
            } else {
                format!("The vault is open. {count} active credentials are available on this Mac.")
            }
        }
        _ => "The vault is open. Check Credentials for the available items.".to_owned(),
    };
    let mut host = None;
    let mut skip = false;
    let mut cli = app.ui.is_expanded("next-step-cli");
    kit::section(ui, Some("Use this vault on this Mac"), Some(&intro), |s| {
        s.row(|ui| {
            kit::note(ui, "Agents and grants stay on this Mac. Set them here before an agent can use a credential.");
        });
        s.row(|ui| {
            ui.horizontal_wrapped(|ui| {
                if kit::button(ui, "Claude Code", Style::Bordered).clicked() {
                    host = Some(0);
                }
                if kit::button(ui, "Codex", Style::Bordered).clicked() {
                    host = Some(1);
                }
                if kit::button(ui, "CLI", Style::Bordered).clicked() {
                    cli = !cli;
                }
                skip = kit::button(ui, "Skip", Style::Link).clicked();
            });
        });
        s.row(|ui| {
            kit::note(
                ui,
                "You can do these steps later in Agents or Settings > Agents > Command line.",
            );
        });
    });
    app.ui.set_expanded("next-step-cli", cli);
    if cli {
        connection_progress(app, ui, true);
        cli_guidance(app, ui);
    }
    if let Some(host) = host {
        choose_host(app, host);
        return true;
    }
    skip
}

fn choose_host(app: &mut DesktopApp, host: usize) {
    let name = if host == 0 { "Claude Code" } else { "Codex" };
    app.ui.setup_host = host;
    app.ui.set_expanded("agent-setup", true);
    let existing = app.owner_ui.session.agents().ok().and_then(|agents| {
        agents
            .into_iter()
            .find(|agent| !agent.revoked && agent.name == name)
    });
    app.view = OwnerView::Agents;
    if let Some(agent) = existing {
        app.owner_ui.selected_agent = Some(agent.id);
        app.ui.sheet = None;
    } else {
        app.owner_ui.selected_agent = None;
        app.owner_ui.new_agent_name = name.to_owned();
        app.ui.sheet = Some(Sheet::RegisterAgent);
    }
}

/// The app knows the first three stages. A settings file or an allowed activity
/// entry cannot prove the last two: access requests can wait and runs can fail.
fn connection_progress(app: &mut DesktopApp, ui: &mut egui::Ui, cli: bool) {
    let links = super::cli_tools::installed();
    let window = app.cli.socket_path().is_some();
    let unlocked = !app.owner_ui.session.is_locked();
    let session = cli && app.cli_sessions_open() > 0;
    kit::section(ui, Some("Setup checks"), None, |s| {
        for (label, complete, detail) in [
            (
                "CLI tools installed",
                links,
                "Check in Settings > Agents > Command line",
            ),
            (
                "App available to CLI",
                window,
                "Check the owner socket in Settings",
            ),
            ("Vault unlocked", unlocked, "Unlock the vault"),
            (
                if cli {
                    "CLI connected"
                } else {
                    "Host connected"
                },
                session,
                if cli {
                    "Run apassy login, then apassy status"
                } else if app.ui.setup_host == 1 {
                    "Restart Codex. Trust the hook with /hooks. Check Apassy with /mcp."
                } else {
                    "Check Apassy in the host's /mcp view"
                },
            ),
            (
                "First successful request",
                false,
                "Check the result of a test request and its entry in Activity",
            ),
        ] {
            s.status(
                label,
                (!complete).then_some(detail),
                kit::text(if complete { "Checked" } else { "To check" }, Font::Callout).color(
                    if complete {
                        Tone::Good.text()
                    } else {
                        kit::SECONDARY
                    },
                ),
            );
        }
        s.row(|ui| kit::note(ui, "CLI links do not set PATH. Host settings do not prove a connection or a successful request."));
    });
}

fn cli_guidance(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let mut install = false;
    kit::section(ui, Some("Use the CLI"), None, |s| {
        s.row(|ui| {
            kit::note(ui, "Install the CLI tools. Then run these commands in Terminal.");
            install = kit::button(ui, "Install CLI tools", Style::Bordered).clicked();
            kit::code_block(ui, "export PATH=\"$HOME/.local/bin:$PATH\"\neval \"$(apassy login)\"\napassy status\napassy doctor", 4);
            kit::note(ui, "Confirm the login in Apassy. Keep the window open and the vault unlocked.");
            kit::note(ui, "The PATH command applies to this Terminal session. Add it to ~/.zshrc for new sessions.");
            kit::note(ui, "CLI login is separate from an agent token. It does not give an agent access to credentials.");
        });
    });
    if install {
        match super::cli_tools::install() {
            Ok(()) => app.set_ok("CLI tools are installed in ~/.local/bin. Run the Terminal commands to check the connection."),
            Err(error) => app.set_err(error),
        }
    }
}

fn draw_list(app: &mut DesktopApp, ui: &mut egui::Ui) {
    let agents = match app.owner_ui.session.agents() {
        Ok(agents) => agents,
        Err(err) => {
            kit::tone_note(ui, err.message, Tone::Critical);
            return;
        }
    };
    let mut register = false;
    // With no active agent, the empty state has the one main action. A second
    // prominent button in the header would say the same thing twice.
    let empty = agents.iter().all(|agent| agent.revoked);
    kit::page_header(
        ui,
        "Agents",
        Some("An agent uses a credential through Apassy. It never receives the secret value."),
        |ui| {
            if !empty {
                register = kit::button_with(
                    ui,
                    Some(Icon::Plus),
                    "Register",
                    Style::Prominent,
                    Size::Regular,
                )
                .clicked();
            }
        },
    );
    let now = now();
    let (revoked, active): (Vec<_>, Vec<_>) = agents.into_iter().partition(|agent| agent.revoked);
    if active.is_empty() {
        // Revoked agents stay in the folded list below, for their history. A restore
        // revokes every agent, so the owner registers them again here.
        let (title, message) = if revoked.is_empty() {
            (
                "No agents yet",
                "Register each agent host, such as Claude Code or Codex. Apassy gives it a token for the Apassy MCP server.",
            )
        } else {
            (
                "No active agents",
                "Every agent of this vault is revoked, for example after a restore. Register each agent host again; it gets a new token.",
            )
        };
        register |= kit::empty_state(ui, Icon::Person, title, message, Some("Register agent"));
    }
    let mut open = None;
    if !active.is_empty() {
        kit::section(ui, None, None, |s| {
            for agent in &active {
                let (label, tone) = status(agent, now);
                let subtitle = if agent.token_expired_at(now) {
                    format!(
                        "The token expired on {}. Rotate it.",
                        date(agent.token_expires_at)
                    )
                } else {
                    format!("Token until {}", date(agent.token_expires_at))
                };
                let detail = kit::text(label, Font::Callout).color(tone.text());
                if s.nav(
                    Some((Icon::Person, kit::ACCENT)),
                    &agent.name,
                    Some(&subtitle),
                    Some(detail),
                )
                .clicked()
                {
                    open = Some(agent.id);
                }
            }
        });
    }
    if !revoked.is_empty() {
        let mut expanded = app.ui.is_expanded("revoked-agents");
        if kit::disclosure(
            ui,
            &mut expanded,
            &format!("Revoked agents ({})", revoked.len()),
        )
        .changed()
        {
            app.ui.set_expanded("revoked-agents", expanded);
        }
        if expanded {
            ui.add_space(4.0);
            kit::section(ui, None, Some("A revoked token does not work."), |s| {
                for agent in &revoked {
                    s.labeled(
                        &agent.name,
                        kit::text(
                            format!("Registered {}", date(agent.created_at)),
                            Font::Callout,
                        )
                        .color(kit::SECONDARY),
                    );
                }
            });
        }
    }
    if let Some(agent_id) = open {
        app.owner_ui.selected_agent = Some(agent_id);
    }
    if register {
        app.owner_ui.new_agent_name.clear();
        app.ui.sheet = Some(Sheet::RegisterAgent);
    }
}

fn draw_agent(app: &mut DesktopApp, ui: &mut egui::Ui, agent_id: u64) {
    if kit::back_link(ui, "Agents") {
        app.owner_ui.selected_agent = None;
        return;
    }
    let Some(agent) = app
        .owner_ui
        .session
        .agents()
        .ok()
        .and_then(|agents| agents.into_iter().find(|agent| agent.id == agent_id))
    else {
        app.owner_ui.selected_agent = None;
        return;
    };
    let now = now();
    let (label, tone) = status(&agent, now);
    ui.horizontal(|ui| {
        kit::icon_tile_sized(ui, Icon::Person, kit::ACCENT, 40.0);
        ui.add_space(4.0);
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            ui.label(kit::text(&agent.name, Font::Title).color(kit::LABEL));
            ui.label(
                kit::text(
                    format!("Registered {}", date(agent.created_at)),
                    Font::Callout,
                )
                .color(kit::SECONDARY),
            );
        });
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            kit::tag(ui, label, tone);
        });
    });
    ui.add_space(20.0);
    if agent.revoked {
        kit::notice(
            ui,
            Tone::Neutral,
            "Revoked. The token does not work.",
            Some("Register the agent again to give it a new token."),
            |_| {},
        );
        return;
    }
    token_section(app, ui, &agent, now);
    connection_progress(app, ui, false);
    setup_guidance(&mut app.ui, ui, false);
    visibility_section(app, ui, &agent);
    process_access_section(app, ui, &agent);
    operations_section(app, ui, agent_id);
    let requests = app
        .owner_ui
        .session
        .agent_activity(agent_id, crate::vault::MAX_ACTIVITY_ROWS)
        .unwrap_or_default();
    super::timeline::access_timeline(
        app,
        ui,
        &requests,
        &format!("agent-access-{agent_id}"),
        "Recent requests",
        "This agent did not send a request yet.",
        true,
    );
    let mut revoke = false;
    kit::section(ui, None, None, |s| {
        revoke = s
            .clickable_row("Revoke agent…", |ui| {
                ui.label(kit::text("Revoke agent…", Font::Body).color(Tone::Critical.text()));
            })
            .clicked();
    });
    if revoke {
        app.ui.sheet = Some(Sheet::RevokeAgent {
            agent_id,
            name: agent.name.clone(),
        });
    }
}

/// The token expiry and rotation (goal item P1).
fn token_section(app: &mut DesktopApp, ui: &mut egui::Ui, agent: &AgentSummary, now: u64) {
    let lifetime = app.owner_ui.session.token_lifetime_days().ok();
    let footer = lifetime.map(|days| {
        format!("Token lifetime: {days} days after issue. You change it in Settings > Agents.")
    });
    let mut rotate = false;
    kit::section(ui, Some("Token"), footer.as_deref(), |s| {
        let expired = agent.token_expired_at(now);
        let when = format_utc(agent.token_expires_at);
        if expired {
            s.status(
                "Expired",
                Some("The agent gets token_expired. Rotate the token to give it a new one."),
                kit::text(when, Font::Callout).color(Tone::Critical.text()),
            );
        } else {
            s.labeled(
                "Expires",
                kit::text(when, Font::Callout).color(kit::SECONDARY),
            );
        }
        s.row(|ui| {
            egui::Sides::new().shrink_left().wrap().show(
                ui,
                |ui| {
                    kit::note(ui, "A new token replaces the old one at once.");
                },
                |ui| {
                    rotate = kit::small_button(ui, "Rotate token…", Style::Bordered).clicked();
                },
            );
        });
    });
    if rotate {
        let ctx = ui.ctx().clone();
        app.ask_owner(
            OwnerRequest::RotateToken {
                agent_id: agent.id,
                agent_name: agent.name.clone(),
            },
            Some(&ctx),
        );
    }
}

/// Process access for one agent: one row per credential with a variable.
fn process_access_section(app: &mut DesktopApp, ui: &mut egui::Ui, agent: &AgentSummary) {
    let items = match app.owner_ui.session.env_bound_items() {
        Ok(items) => items,
        Err(err) => {
            kit::tone_note(ui, err.message, Tone::Critical);
            return;
        }
    };
    let grants = app
        .owner_ui
        .session
        .exec_grants(agent.id)
        .unwrap_or_default();
    let kinds: std::collections::BTreeMap<u64, crate::contracts::CredentialKind> = app
        .owner_ui
        .session
        .search("")
        .unwrap_or_default()
        .into_iter()
        .map(|item| (item.id, item.kind))
        .collect();
    let mut open = None;
    let mut open_many = false;
    let mut go_to_credentials = false;
    kit::section(
        ui,
        Some("Process access"),
        Some(
            "The agent can ask Apassy to run a command with the secret in its environment, in one project folder or in any folder.",
        ),
        |s| {
            if items.is_empty() {
                s.row(|ui| {
                    kit::note(
                        ui,
                        "No credential has an environment variable yet. Open a credential and set one under Agent access.",
                    );
                    go_to_credentials =
                        kit::small_button(ui, "Go to Credentials", Style::Link).clicked();
                });
                return;
            }
            for (item_id, item_name, env_name) in &items {
                let grant = grants.iter().find(|grant| grant.item_id == *item_id);
                let (detail, tone) = match grant.map(|grant| grant.mode) {
                    Some(ExecMode::Ask) => ("Asks you each time", Tone::Accent),
                    Some(ExecMode::Bouncer) => ("Bouncer decides", Tone::Good),
                    None => ("Off", Tone::Neutral),
                };
                let subtitle = match grant {
                    Some(grant) => format!("{env_name} · {}", grant.place.describe()),
                    None => env_name.clone(),
                };
                // The icon of the credential kind, as in the credential list.
                let icon = kinds
                    .get(item_id)
                    .map_or((Icon::Terminal, kit::TERTIARY), |kind| {
                        super::kind_icon(*kind)
                    });
                if s.nav(
                    Some(icon),
                    item_name,
                    Some(&subtitle),
                    Some(kit::text(detail, Font::Callout).color(tone.text())),
                )
                .clicked()
                {
                    let mode = grant.map_or(ExecMode::Ask, |grant| grant.mode);
                    open = Some((*item_id, mode, grant.cloned()));
                }
            }
            if items.len() > 1 {
                let clicked = s
                    .clickable_row("Give access to several credentials…", |ui| {
                        ui.label(
                            kit::text("Give access to several credentials…", Font::Body)
                                .color(kit::ACCENT_TEXT),
                        );
                    })
                    .clicked();
                if clicked {
                    open_many = true;
                }
            }
        },
    );
    if go_to_credentials {
        app.view = OwnerView::Vault;
    }
    if open_many {
        app.ui.grant = GrantForm::default();
        app.ui.sheet = Some(Sheet::GrantMany { agent_id: agent.id });
    }
    if let Some((item_id, mode, grant)) = open {
        let key = (agent.id, item_id);
        let any_folder = grant
            .as_ref()
            .is_some_and(|grant| grant.place == GrantPlace::AnyFolder);
        let dir = grant
            .as_ref()
            .and_then(|grant| grant.place.folder().map(str::to_owned))
            .unwrap_or_default();
        app.owner_ui.exec_dir_inputs.insert(key, dir);
        match &grant {
            Some(grant) => {
                app.owner_ui
                    .rule_inputs
                    .insert(key, RuleForm::from_rule(&grant.rule, now()));
            }
            None => {
                app.owner_ui.rule_inputs.remove(&key);
            }
        }
        app.ui.sheet = Some(Sheet::ProcessAccess {
            agent_id: agent.id,
            item_id,
            mode,
            any_folder,
        });
    }
}

/// Connector operations as switches. A new grant needs the owner check.
fn operations_section(app: &mut DesktopApp, ui: &mut egui::Ui, agent_id: u64) {
    let Ok(connectors) = app.owner_ui.session.connectors() else {
        return;
    };
    if connectors.is_empty() {
        return;
    }
    let granted = app.owner_ui.session.grants(agent_id).unwrap_or_default();
    let mut allow = None;
    let mut remove = None;
    kit::section(
        ui,
        Some("API operations"),
        Some("Apassy calls the API for the agent and adds the token. The agent never receives it."),
        |s| {
            for row in &connectors {
                for (operation, description) in &row.operations {
                    let was = granted.contains(&(row.item_id, (*operation).to_owned()));
                    let mut allowed = was;
                    let title = format!("{} · {operation}", row.item_name);
                    s.toggle(&title, Some(description), &mut allowed);
                    if allowed && !was {
                        allow = Some((row.item_id, (*operation).to_owned()));
                    } else if !allowed && was {
                        remove = Some((row.item_id, *operation));
                    }
                }
            }
        },
    );
    if let Some((item_id, operation)) = allow {
        // A new grant needs an owner check (goal item A4).
        let ctx = ui.ctx().clone();
        app.ask_owner(
            OwnerRequest::AllowOperation {
                agent_id,
                item_id,
                operation,
            },
            Some(&ctx),
        );
    }
    if let Some((item_id, operation)) = remove {
        // A removal only takes authority away.
        let result = app
            .owner_ui
            .session
            .remove_operation(agent_id, item_id, operation);
        let _ = app.apply(result, &format!("The agent can no longer use {operation}."));
    }
}

// ---- Sheets. ----

pub(super) fn register_sheet(app: &mut DesktopApp, ctx: &egui::Context) -> bool {
    let mut register = false;
    let mut cancel = false;
    let response = kit::sheet(ctx, "register-agent", 440.0, |ui| {
        kit::sheet_title(
            ui,
            "Register an agent",
            Some(
                "Give each agent host its own name, for example Claude Code or Codex. Apassy then shows its token one time.",
            ),
        );
        kit::section(ui, None, None, |s| {
            let field = s.field("Name", |ui| {
                kit::text_input(
                    ui,
                    &mut app.owner_ui.new_agent_name,
                    "agent-name",
                    "Claude Code",
                )
            });
            if field.lost_focus() && field.ctx.input(|input| input.key_pressed(egui::Key::Enter)) {
                register = true;
            }
        });
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                register |= kit::button(ui, "Register", Style::Prominent)
                    .on_hover_text("⌘S")
                    .clicked();
                cancel = kit::button(ui, "Cancel", Style::Bordered).clicked();
            },
        );
    });
    register |= super::save_pressed(app, ctx);
    if register {
        let name = app.owner_ui.new_agent_name.clone();
        match app.owner_ui.session.register_agent(&name) {
            Ok((agent, token)) => {
                app.owner_ui.new_agent_name.clear();
                app.owner_ui.selected_agent = Some(agent.id);
                app.owner_ui.fresh_token = Some(FreshToken {
                    agent_name: agent.name.clone(),
                    token,
                    rotated: false,
                });
                app.ui.sheet = None;
                app.view = OwnerView::Agents;
                app.set_ok(format!(
                    "{} is registered. Connect the agent host.",
                    agent.name
                ));
            }
            Err(err) => app.set_err(err.message),
        }
    }
    if cancel {
        close_sheet(app, ctx);
    }
    response.escape
}

fn shell_word(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

fn cli_path() -> String {
    std::env::current_exe()
        .ok()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "apassy".to_owned())
}

/// These steps stay available after the one-time token sheet closes.
fn setup_guidance(state: &mut super::UiState, ui: &mut egui::Ui, fresh: bool) {
    let mut expanded = fresh || state.is_expanded("agent-setup");
    if !fresh {
        kit::disclosure(ui, &mut expanded, "Connect to an agent host");
    }
    state.set_expanded("agent-setup", expanded);
    if !expanded {
        // The gap of a section, so the next section header does not touch the label.
        ui.add_space(14.0);
        return;
    }
    let selected = if state.setup_host == 0 {
        "Claude Code"
    } else {
        "Codex"
    };
    kit::picker(
        ui,
        "setup-host",
        &mut state.setup_host,
        &[(0, "Claude Code".to_owned()), (1, "Codex".to_owned())],
        selected,
        200.0,
    );
    let host = if state.setup_host == 0 {
        "claude"
    } else {
        "codex"
    };
    kit::note(
        ui,
        format!("First, install {selected}. Make sure `{host} --version` works in Terminal."),
    );
    kit::note(
        ui,
        "1. Open Terminal. Run this command. Paste the token when Terminal waits, then press Return. The token is hidden as you type.",
    );
    let command = format!(
        "read -r -s APASSY_SETUP_TOKEN\nprintf '%s' \"$APASSY_SETUP_TOKEN\" | {} setup {host} --token-stdin --write\nunset APASSY_SETUP_TOKEN",
        shell_word(&cli_path())
    );
    kit::code_block(ui, &command, 3);
    kit::note(
        ui,
        "This writes the MCP server and prompt hook settings. It does not check the connection. Apassy keeps a copy of changed settings.",
    );
    if host == "codex" {
        kit::note(
            ui,
            "2. Restart Codex. Use /hooks to trust the Apassy hook. Check the Apassy server with /mcp.",
        );
    } else {
        kit::note(
            ui,
            "2. Restart Claude Code. Use /mcp to check that Apassy is connected.",
        );
    }
    kit::note(
        ui,
        "3. Open a credential and set its Environment variable. Return here to give this agent access to that credential and project.",
    );
    kit::note(
        ui,
        "4. In your project folder, run this command. Ask the agent to use the test credential. Check its request in Activity.",
    );
    let sandbox = std::path::Path::new(&cli_path())
        .parent()
        .map(|p| p.join("apassy-sandbox").display().to_string())
        .unwrap_or_else(|| "apassy-sandbox".to_owned());
    let launch = if host == "claude" {
        format!(
            "MCP_TOOL_TIMEOUT=180000 {} -- claude --settings '{{\"sandbox\":{{\"enabled\":false}}}}'",
            shell_word(&sandbox)
        )
    } else {
        format!(
            "{} -- codex -c sandbox_mode=danger-full-access",
            shell_word(&sandbox)
        )
    };
    kit::code_block(ui, &launch, 2);
    kit::note(
        ui,
        "This uses the Apassy sandbox instead of the host's inner sandbox. Your host approval prompts stay active.",
    );
    kit::note(
        ui,
        "Check the result of the test request. Then check its entry in Activity. An Allowed entry alone does not prove success.",
    );
    if !fresh {
        kit::note(
            ui,
            "Use the token you saved. If you lost it, select Rotate token to get a new one. The old token will stop working.",
        );
    }
}

/// A new token after registration or rotation. The main action saves host
/// settings. The token and manual commands stay in a closed disclosure group.
/// Escape does not discard the one-time token.
pub(super) fn draw_fresh_token(app: &mut DesktopApp, ctx: &egui::Context) {
    let Some(fresh) = &app.owner_ui.fresh_token else {
        return;
    };
    app.ui.agent_setup.prepare(
        fresh.token.expose(),
        &fresh.agent_name,
        &mut app.ui.setup_host,
    );
    app.ui.agent_setup.poll(ctx);
    let token = fresh.token.expose();
    let rotated = fresh.rotated;
    let title = format!("Connect {}", fresh.agent_name);
    let mut dismiss = false;
    let mut connect = false;
    let busy = app.ui.agent_setup.busy();
    let saved = app
        .ui
        .agent_setup
        .result
        .as_ref()
        .and_then(|result| result.as_ref().ok())
        .copied();
    kit::sheet(ctx, "fresh-token", 480.0, |ui| {
        kit::sheet_title(
            ui,
            &title,
            Some("Let this agent use credentials through Apassy."),
        );
        kit::sheet_body(ui, |ui| {
            if rotated {
                kit::note(
                    ui,
                    "The old token does not work. Save the new settings for your host.",
                );
            }
            if let Some(host) = saved {
                kit::tone_note(ui, "Setup saved.", Tone::Good);
                kit::note(
                    ui,
                    format!(
                        "Restart {}. Keep Apassy open and the vault unlocked.",
                        host.name()
                    ),
                );
                kit::note(
                    ui,
                    if host == super::agent_setup::Host::Codex {
                        "Use /hooks to trust the Apassy hook. Use /mcp to check the Apassy connection."
                    } else {
                        "Use /mcp to check the Apassy connection."
                    },
                );
                kit::note(ui, "The connection and first request are not checked.");
                kit::note(
                    ui,
                    "Next, open a credential and set its Environment variable. Give this agent access to the credential and project.",
                );
                kit::note(
                    ui,
                    "Open Advanced setup for the sandbox command and test steps.",
                );
            } else {
                let host = super::agent_setup::Host::from_index(app.ui.setup_host);
                ui.add_enabled_ui(!busy, |ui| {
                    kit::picker(
                        ui,
                        "fresh-setup-host",
                        &mut app.ui.setup_host,
                        &[(0, "Claude Code".to_owned()), (1, "Codex".to_owned())],
                        host.name(),
                        200.0,
                    );
                });
                kit::note(
                    ui,
                    "Apassy keeps a copy of changed host settings. This step does not check the connection.",
                );
                if busy {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        kit::note(ui, "Please wait. Apassy will save the host settings.");
                    });
                }
                if let Some(Err(error)) = &app.ui.agent_setup.result {
                    kit::tone_note(ui, error, Tone::Critical);
                }
            }
            ui.add_space(12.0);
            kit::disclosure(ui, &mut app.ui.agent_setup.advanced, "Advanced setup");
            if app.ui.agent_setup.advanced {
                kit::note(ui, "Apassy shows this token one time. Keep it private.");
                let heading = ui.label(kit::text("Token", Font::Headline).color(kit::LABEL));
                kit::code_block(ui, token, 1).labelled_by(heading.id);
                ui.add_enabled_ui(!busy, |ui| setup_guidance(&mut app.ui, ui, true));
                let mut manual = app.ui.is_expanded("manual-mcp-config");
                kit::disclosure(ui, &mut manual, "Other hosts: manual MCP configuration");
                app.ui.set_expanded("manual-mcp-config", manual);
                if manual {
                    let adapter = std::env::current_exe()
                        .ok()
                        .and_then(|p| p.parent().map(|p| p.join("apassy-mcp")))
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "apassy-mcp".to_owned());
                    let config = zeroize::Zeroizing::new(serde_json::to_string_pretty(&serde_json::json!({
                        "mcpServers": { "apassy": { "command": adapter, "env": { "APASSY_AGENT_TOKEN": token } } }
                    })).unwrap_or_default());
                    kit::code_block(ui, &config, 7);
                    kit::note(
                        ui,
                        "Add this server to your host. Keep the token private. Manual MCP setup does not install the prompt hook.",
                    );
                }
                if saved.is_none() {
                    ui.add_enabled_ui(!busy, |ui| {
                        dismiss = kit::button(ui, "I saved the token", Style::Link).clicked();
                    });
                }
            }
        });
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                if saved.is_some() {
                    dismiss = kit::button(ui, "Done", Style::Prominent).clicked();
                } else {
                    let host = super::agent_setup::Host::from_index(app.ui.setup_host);
                    ui.add_enabled_ui(!busy, |ui| {
                        connect =
                            kit::button(ui, &format!("Connect {}", host.name()), Style::Prominent)
                                .clicked();
                    });
                }
            },
        );
    });
    if connect {
        app.ui.agent_setup.start(
            super::agent_setup::Host::from_index(app.ui.setup_host),
            token,
            ctx,
        );
    }
    if dismiss {
        app.owner_ui.fresh_token = None;
        app.ui.agent_setup = Default::default();
        app.set_ok("The token is hidden. Apassy cannot show it again.");
    }
}

pub(super) fn revoke_sheet(
    app: &mut DesktopApp,
    ctx: &egui::Context,
    agent_id: u64,
    name: &str,
) -> bool {
    let mut revoke = false;
    let mut cancel = false;
    let response = kit::sheet(ctx, "revoke-agent", 400.0, |ui| {
        kit::sheet_title(
            ui,
            &format!("Revoke {name}?"),
            Some(
                "Its token stops working at once, and its grants end. You can register the agent again later.",
            ),
        );
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                revoke = kit::button(ui, "Revoke", Style::DestructiveProminent).clicked();
                cancel = kit::alert_cancel(ui).clicked();
            },
        );
    });
    if revoke {
        let message = format!("{name} is revoked. Its token does not work.");
        let result = app.owner_ui.session.revoke_agent(agent_id);
        if app.apply(result, &message).is_some() {
            app.ui.sheet = None;
        }
    }
    if cancel {
        close_sheet(app, ctx);
    }
    response.escape
}

/// Process access for one agent and one credential, with its optional rule (ADR 0007).
pub(super) fn access_sheet(
    app: &mut DesktopApp,
    ctx: &egui::Context,
    agent_id: u64,
    item_id: u64,
    mode: ExecMode,
    any_folder: bool,
) -> bool {
    let session = &app.owner_ui.session;
    let agent_name = session
        .agents()
        .ok()
        .and_then(|agents| agents.into_iter().find(|agent| agent.id == agent_id))
        .map(|agent| agent.name)
        .unwrap_or_default();
    let Some((_, item_name, env_name)) = session
        .env_bound_items()
        .ok()
        .and_then(|items| items.into_iter().find(|(id, _, _)| *id == item_id))
    else {
        app.ui.sheet = None;
        return false;
    };
    let grant = session
        .exec_grants(agent_id)
        .ok()
        .and_then(|grants| grants.into_iter().find(|grant| grant.item_id == item_id));
    let key = (agent_id, item_id);
    let real_value = session
        .env_binding(item_id)
        .ok()
        .flatten()
        .is_some_and(|binding| binding.delivery == EnvDelivery::Value);
    let mut chosen = mode;
    let mut anywhere = any_folder;
    let mut save = false;
    let mut remove = false;
    let mut save_rule = false;
    let mut cancel = false;
    let response = kit::sheet(ctx, "process-access", 560.0, |ui| {
        kit::sheet_title(
            ui,
            &format!("{item_name} for {agent_name}"),
            Some(&format!(
                "The agent can run a command with {env_name} in its environment."
            )),
        );
        kit::sheet_body(ui, |ui| {
            let dir = app.owner_ui.exec_dir_inputs.entry(key).or_default();
            place_section(
                ui,
                ("exec", agent_id, item_id),
                dir,
                &mut anywhere,
                &mut chosen,
                usize::from(real_value),
            );
            if let Some(grant) = &grant {
                let rule_key = format!("rule-{agent_id}-{item_id}");
                let mut open = app.ui.is_expanded(&rule_key);
                if kit::disclosure(ui, &mut open, "Rule").changed() {
                    app.ui.set_expanded(&rule_key, open);
                }
                if open {
                    ui.add_space(6.0);
                    let form = app
                        .owner_ui
                        .rule_inputs
                        .entry(key)
                        .or_insert_with(|| RuleForm::from_rule(&grant.rule, now()));
                    save_rule = rule_form(ui, form);
                }
            }
        });
        kit::sheet_buttons(
            ui,
            |ui| {
                if grant.is_some() {
                    remove = kit::button(ui, "Remove access", Style::Destructive).clicked();
                }
            },
            |ui| {
                save = kit::button(ui, "Save", Style::Prominent)
                    .on_hover_text("⌘S")
                    .clicked();
                cancel = kit::button(ui, "Cancel", Style::Bordered).clicked();
            },
        );
    });
    if chosen != mode || anywhere != any_folder {
        app.ui.sheet = Some(Sheet::ProcessAccess {
            agent_id,
            item_id,
            mode: chosen,
            any_folder: anywhere,
        });
    }
    save |= super::save_pressed(app, ctx);
    if save {
        let place = if anywhere {
            GrantPlace::AnyFolder
        } else {
            GrantPlace::Folder(
                app.owner_ui
                    .exec_dir_inputs
                    .get(&key)
                    .cloned()
                    .unwrap_or_default(),
            )
        };
        // A new or changed grant needs an owner check (goal item A4).
        ask_owner_from_sheet(
            app,
            OwnerRequest::SetProcessAccess {
                agent_id,
                item_id,
                place,
                mode: effective_mode(chosen, anywhere, usize::from(real_value)),
            },
            ctx,
        );
    }
    if save_rule && let Some(form) = app.owner_ui.rule_inputs.get(&key).cloned() {
        match form.to_rule(now()) {
            // A rule change needs an owner check (goal item A4).
            Ok(rule) => ask_owner_from_sheet(
                app,
                OwnerRequest::SaveRule {
                    agent_id,
                    item_id,
                    rule,
                },
                ctx,
            ),
            Err(message) => app.set_err(message),
        }
    }
    if remove {
        let result = app.owner_ui.session.remove_exec_grant(agent_id, item_id);
        if app.apply(result, "Process access is removed.").is_some() {
            app.ui.sheet = None;
        }
    }
    if cancel {
        close_sheet(app, ctx);
    }
    response.escape
}

/// The form of "Give access to several credentials" and of an access request (ADR 0012).
#[derive(Debug, Clone, Default)]
pub(crate) struct GrantForm {
    pub(crate) selection: std::collections::BTreeSet<u64>,
    pub(crate) dir: String,
    pub(crate) any_folder: bool,
    pub(crate) mode: Decision,
}

/// The decision of a grant in a form. `Ask` is the default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum Decision {
    #[default]
    Ask,
    Bouncer,
}

impl Decision {
    fn mode(self) -> ExecMode {
        match self {
            Self::Ask => ExecMode::Ask,
            Self::Bouncer => ExecMode::Bouncer,
        }
    }
}

impl GrantForm {
    pub(crate) fn place(&self) -> GrantPlace {
        if self.any_folder {
            GrantPlace::AnyFolder
        } else {
            GrantPlace::Folder(self.dir.trim().to_owned())
        }
    }
}

/// In any folder, a variable with the real value makes each run ask the owner, so a
/// grant with such a variable is saved as "Ask me each time" (ADR 0012).
fn effective_mode(mode: ExecMode, any_folder: bool, real_values: usize) -> ExecMode {
    if any_folder && real_values > 0 {
        ExecMode::Ask
    } else {
        mode
    }
}

/// "Where" and "Decision" of a grant. `real_values` counts the credentials whose
/// variable holds the real value.
pub(super) fn place_section(
    ui: &mut egui::Ui,
    salt: impl std::hash::Hash + std::fmt::Debug + Copy,
    dir: &mut String,
    any_folder: &mut bool,
    mode: &mut ExecMode,
    real_values: usize,
) {
    let forced = *any_folder && real_values > 0;
    let footer = if forced {
        "In any folder, a process with the real value of a secret can use it anywhere, so you approve each run with it. A variable in placeholder mode lets the bouncer decide."
    } else if *any_folder {
        match mode {
            ExecMode::Ask => {
                "The agent can use the credentials from any working directory. You approve each run."
            }
            ExecMode::Bouncer => {
                "The agent can use the credentials from any working directory. The bouncer decides; a risky run and a production run wait for you. The placeholders go only to their hosts."
            }
        }
    } else {
        match mode {
            ExecMode::Ask => {
                "You approve each run with your passphrase. Start here for a new project."
            }
            ExecMode::Bouncer => {
                "The bouncer decides from your declarations and rules. A risky run waits for you. A production run always waits for you."
            }
        }
    };
    kit::section(ui, None, Some(footer), |s| {
        s.field("Where", |ui| {
            kit::segmented(
                ui,
                ("grant-where", salt),
                any_folder,
                &[(false, "This folder"), (true, "Any folder")],
            )
        });
        if !*any_folder {
            s.field("Project folder", |ui| {
                kit::text_input(ui, dir, "exec-dir", "/Users/you/Dev/project")
            });
        }
        s.field("Decision", |ui| {
            if forced {
                *mode = ExecMode::Ask;
            }
            ui.add_enabled_ui(!forced, |ui| {
                kit::segmented(
                    ui,
                    ("exec-mode", salt),
                    mode,
                    &[
                        (ExecMode::Ask, "Ask me each time"),
                        (ExecMode::Bouncer, "Bouncer decides"),
                    ],
                )
            })
            .inner
        });
    });
}

/// "Give access to several credentials": one owner check for all of them (ADR 0012).
pub(super) fn grant_many_sheet(app: &mut DesktopApp, ctx: &egui::Context, agent_id: u64) -> bool {
    let session = &app.owner_ui.session;
    let agent_name = session
        .agents()
        .ok()
        .and_then(|agents| agents.into_iter().find(|agent| agent.id == agent_id))
        .map(|agent| agent.name)
        .unwrap_or_default();
    let archived = session.archived().unwrap_or_default();
    let items: Vec<(u64, String, String, bool)> = session
        .env_bound_items()
        .unwrap_or_default()
        .into_iter()
        .filter(|(id, _, _)| !archived.contains_key(id))
        .map(|(id, name, env_name)| {
            let real = session
                .env_binding(id)
                .ok()
                .flatten()
                .is_some_and(|binding| binding.delivery == EnvDelivery::Value);
            (id, name, env_name, real)
        })
        .collect();
    let granted: Vec<u64> = session
        .exec_grants(agent_id)
        .unwrap_or_default()
        .iter()
        .map(|grant| grant.item_id)
        .collect();
    let mut save = false;
    let mut cancel = false;
    let mut mode = app.ui.grant.mode.mode();
    let response = kit::sheet(ctx, "grant-many", 560.0, |ui| {
        kit::sheet_title(
            ui,
            &format!("Give {agent_name} access"),
            Some(
                "Select the credentials. The agent can run a command with each of them in its environment. You confirm once.",
            ),
        );
        kit::sheet_body(ui, |ui| {
            let form = &mut app.ui.grant;
            kit::section(
                ui,
                Some("Credentials"),
                Some(
                    "A credential needs an environment variable. A selected credential that the agent can use already gets the new place and decision.",
                ),
                |s| {
                    for (id, name, env_name, real) in &items {
                        let mut on = form.selection.contains(id);
                        let mut subtitle = env_name.clone();
                        if *real {
                            subtitle.push_str(" · real value");
                        } else {
                            subtitle.push_str(" · placeholder");
                        }
                        if granted.contains(id) {
                            subtitle.push_str(" · has access");
                        }
                        if s.toggle(name, Some(&subtitle), &mut on).changed() {
                            if on {
                                form.selection.insert(*id);
                            } else {
                                form.selection.remove(id);
                            }
                        }
                    }
                },
            );
            let real_values = items
                .iter()
                .filter(|(id, _, _, real)| *real && form.selection.contains(id))
                .count();
            place_section(
                ui,
                ("many", agent_id),
                &mut form.dir,
                &mut form.any_folder,
                &mut mode,
                real_values,
            );
        });
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                let count = app.ui.grant.selection.len();
                let label = if count == 1 {
                    "Give access to 1 credential".to_owned()
                } else {
                    format!("Give access to {count} credentials")
                };
                ui.add_enabled_ui(count > 0, |ui| {
                    save = kit::button(ui, &label, Style::Prominent)
                        .on_hover_text("⌘S")
                        .clicked();
                });
                cancel = kit::button(ui, "Cancel", Style::Bordered).clicked();
            },
        );
    });
    app.ui.grant.mode = match mode {
        ExecMode::Ask => Decision::Ask,
        ExecMode::Bouncer => Decision::Bouncer,
    };
    save |= super::save_pressed(app, ctx) && !app.ui.grant.selection.is_empty();
    if save {
        let form = app.ui.grant.clone();
        let item_ids: Vec<u64> = form.selection.iter().copied().collect();
        let real_values = items
            .iter()
            .filter(|(id, _, _, real)| *real && form.selection.contains(id))
            .count();
        // A new or changed grant needs an owner check (goal item A4).
        ask_owner_from_sheet(
            app,
            OwnerRequest::GrantMany {
                agent_id,
                item_ids,
                place: form.place(),
                mode: effective_mode(form.mode.mode(), form.any_folder, real_values),
            },
            ctx,
        );
    }
    if cancel {
        close_sheet(app, ctx);
    }
    response.escape
}

/// What the agent can see (ADR 0012). "All credentials" needs the owner check; turning
/// it off takes authority away and needs none.
fn visibility_section(app: &mut DesktopApp, ui: &mut egui::Ui, agent: &AgentSummary) {
    let was = app
        .owner_ui
        .session
        .agent_sees_all(agent.id)
        .unwrap_or(false);
    let mut on = was;
    kit::section(
        ui,
        Some("What it can see"),
        Some(if was {
            "The agent sees each credential that is not archived: its name, kind, and plain details such as username, host, and visible custom details. It never sees a secret, a hidden detail, or the notes. The provider of the agent model sees this list too. The agent can ask you for access in Activity."
        } else {
            "The agent sees only the credentials that it can use."
        }),
        |s| {
            s.toggle(
                "All credentials, without values",
                Some("The agent can find a credential and ask you for access."),
                &mut on,
            );
        },
    );
    if on && !was {
        let ctx = ui.ctx().clone();
        app.ask_owner(
            OwnerRequest::ShowAllCredentials {
                agent_id: agent.id,
                agent_name: agent.name.clone(),
            },
            Some(&ctx),
        );
    } else if !on && was {
        let result = app
            .owner_ui
            .session
            .set_agent_sees_all(agent.id, false, None);
        let _ = app.apply(
            result,
            "The agent sees only the credentials that it can use. Its open requests are denied.",
        );
    }
}

/// The rule of one process grant. Returns true on "Save rule".
fn rule_form(ui: &mut egui::Ui, form: &mut RuleForm) -> bool {
    kit::section(
        ui,
        Some("Hard limits"),
        Some(
            "Apassy checks hard limits before the bouncer. A request that fails a hard limit is denied.",
        ),
        |s| {
            s.row(|ui| {
                let label =
                    ui.label(kit::text("Allowed command prefixes", Font::Body).color(kit::LABEL));
                kit::note(ui, "One per line. Empty permits any command.");
                kit::text_area(
                    ui,
                    &mut form.prefixes,
                    "rule-prefixes",
                    "npm run migrate\nnpm test",
                    2,
                )
                .labelled_by(label.id);
            });
            s.row(|ui| {
                let label = ui.label(kit::text("Forbidden words", Font::Body).color(kit::LABEL));
                kit::note(ui, "One per line.");
                kit::text_area(
                    ui,
                    &mut form.forbidden,
                    "rule-forbidden",
                    "prod\n--force",
                    2,
                )
                .labelled_by(label.id);
            });
            s.field("Expires after", |ui| {
                let field = kit::number_input(ui, &mut form.expires_hours, "rule-expiry", "never");
                ui.label(kit::text("hours", Font::Body).color(kit::SECONDARY));
                field
            });
            s.field("Runs per hour", |ui| {
                kit::number_input(ui, &mut form.max_runs, "rule-runs", "no limit")
            });
        },
    );
    kit::section(
        ui,
        Some("Your instruction"),
        Some("In plain words. The bouncer checks each request against it."),
        |s| {
            s.row(|ui| {
                let field = kit::text_area(
                    ui,
                    &mut form.instruction,
                    "rule-instruction",
                    "Only run migrations and tests on staging. Never print or send keys.",
                    2,
                );
                ui.ctx()
                    .accesskit_node_builder(field.id, |node| node.set_label("Your instruction"));
            });
        },
    );
    kit::button(ui, "Save rule", Style::Bordered).clicked()
}

#[cfg(test)]
mod onboarding_tests {
    use super::*;

    #[test]
    fn setup_result_does_not_consume_the_fresh_token() {
        let dir = tempfile::TempDir::new().unwrap();
        let (mut app, _) = super::super::owner_tests::unlocked_app_with_item(&dir);
        let (agent, token) = app.owner_ui.session.register_agent("Codex").unwrap();
        app.owner_ui.fresh_token = Some(FreshToken {
            agent_name: agent.name,
            token,
            rotated: false,
        });
        let ctx = egui::Context::default();
        let draw = |app: &mut DesktopApp| {
            ctx.run_ui(egui::RawInput::default(), |ui| {
                draw_fresh_token(app, ui.ctx())
            })
            .drop_without_applying_deltas();
        };
        draw(&mut app);
        assert_eq!(app.ui.setup_host, 1);
        assert!(!app.ui.agent_setup.advanced);
        app.ui.agent_setup.result = Some(Err("Test failure".to_owned()));
        draw(&mut app);
        assert!(app.owner_ui.fresh_token.is_some());
        app.ui.agent_setup.result = Some(Ok(super::super::agent_setup::Host::Codex));
        draw(&mut app);
        assert!(app.owner_ui.fresh_token.is_some());
    }

    #[test]
    fn host_choice_prepares_registration_and_reuses_an_existing_agent() {
        let dir = tempfile::TempDir::new().unwrap();
        let (mut app, _) = super::super::owner_tests::unlocked_app_with_item(&dir);
        choose_host(&mut app, 1);
        assert_eq!(app.ui.setup_host, 1);
        assert_eq!(app.owner_ui.new_agent_name, "Codex");
        assert!(matches!(app.ui.sheet, Some(Sheet::RegisterAgent)));
        assert!(app.owner_ui.session.agents().unwrap().is_empty());
        assert!(app.owner_ui.fresh_token.is_none());

        let (agent, _token) = app.owner_ui.session.register_agent("Codex").unwrap();
        choose_host(&mut app, 1);
        assert_eq!(app.owner_ui.selected_agent, Some(agent.id));
        assert!(app.ui.sheet.is_none());
        assert!(app.ui.is_expanded("agent-setup"));
        assert_eq!(app.owner_ui.session.agents().unwrap(), vec![agent]);
        assert!(
            app.owner_ui.fresh_token.is_none(),
            "the token did not rotate"
        );
    }
}
