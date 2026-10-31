//! "Connect an Agent" (ADR 0025 §2, ADR 0026 §7): pick the host, confirm once, done.
//!
//! The sheet lists Claude Code, Codex, T3 Code, and Other. A choice registers the agent
//! (or takes the connected agent of that name) and asks for one owner check: a new token
//! and, for a new agent, the catalog of the credential names without values
//! (`OwnerRequest::ConnectAgent`). After the check, the token sheet saves the settings of
//! the host at once ([`super::agent_setup`]); for Other it shows the token and the MCP
//! configuration one time. There are no grants and no settings to pick: the bouncer
//! decides each use, and a question waits up to 5 minutes for the owner.

use eframe::egui::{self, Align, Color32, Label, Layout};

use super::agent_setup::Host;
use super::kit::{self, Font, Style};
use super::{Sheet, ask_owner_from_sheet, close_sheet};
use crate::desktop::owner_check::OwnerRequest;
use crate::desktop::{DesktopApp, Place};

/// How long Claude Code waits for a tool, in milliseconds: more than the 5 minutes that
/// a question waits for the owner (ADR 0025 §3e). Codex gets `tool_timeout_sec = 660`
/// from `apassy setup`.
pub(super) const CLAUDE_TOOL_TIMEOUT: &str = "MCP_TOOL_TIMEOUT=660000";

/// The hosts of "Connect an Agent".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum ConnectHost {
    #[default]
    Claude,
    Codex,
    /// T3 Code runs its agents through Claude Code or Codex.
    T3,
    /// Any other host: the token and the command line, also on another computer.
    Other,
}

impl ConnectHost {
    pub(super) const ALL: [Self; 4] = [Self::Claude, Self::Codex, Self::T3, Self::Other];

    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Claude => "Claude Code",
            Self::Codex => "Codex",
            Self::T3 => "T3 Code",
            Self::Other => "Other",
        }
    }

    /// The name of a new agent for this host.
    pub(super) fn agent_name(self) -> &'static str {
        match self {
            Self::Other => "Other agent",
            other => other.name(),
        }
    }

    fn detail(self) -> &'static str {
        match self {
            Self::Claude | Self::Codex => "MCP server and prompt hook",
            Self::T3 => "Through Claude Code or Codex",
            Self::Other => "Token and command line, also remote",
        }
    }

    fn color(self) -> Color32 {
        match self {
            Self::Claude => Color32::from_rgb(217, 119, 87),
            Self::Codex => Color32::from_rgb(16, 163, 127),
            Self::T3 => Color32::from_rgb(110, 90, 230),
            Self::Other => Color32::from_rgb(142, 142, 147),
        }
    }

    /// The host whose settings `apassy setup` writes. Other has none.
    pub(super) fn setup(self) -> Option<Host> {
        match self {
            Self::Claude | Self::T3 => Some(Host::Claude),
            Self::Codex => Some(Host::Codex),
            Self::Other => None,
        }
    }

    /// The host of an agent from its name, for a reconnect.
    pub(super) fn guess(name: &str) -> Self {
        let name = name.to_ascii_lowercase();
        if name.contains("codex") {
            Self::Codex
        } else if name.contains("t3") {
            Self::T3
        } else if name.contains("claude") {
            Self::Claude
        } else {
            Self::Other
        }
    }
}

#[derive(Debug, Default)]
pub(super) struct State {
    /// The host that the sheet selects.
    pub(super) host: ConnectHost,
    /// The agent whose connection waits for the owner check, and its host.
    pending: Option<(u64, ConnectHost)>,
    /// The host of the token sheet on screen. The sheet saves its settings at once.
    pub(super) shown: Option<ConnectHost>,
}

/// "+" in Agents and "Connect agent": the sheet with the hosts.
pub(super) fn open(app: &mut DesktopApp) {
    app.owner_ui.new_agent_name = app.ui.agent_onboarding.host.agent_name().to_owned();
    app.ui.sheet = Some(Sheet::RegisterAgent);
}

/// Connect `host` as the agent `name`: the connected agent of that name, or a new one.
/// One owner check gives the token; a new agent also sees the credential names without
/// values. Nothing changes before the check passes.
pub(super) fn connect(
    app: &mut DesktopApp,
    ctx: Option<&egui::Context>,
    host: ConnectHost,
    name: &str,
) {
    let name = match name.trim() {
        "" => host.agent_name(),
        name => name,
    };
    let existing = app.owner_ui.session.agents().ok().and_then(|agents| {
        agents
            .into_iter()
            .find(|agent| !agent.revoked && agent.name == name)
    });
    let agent = match existing {
        Some(agent) => agent,
        // The token of the registration is dropped: the check gives the token that the
        // host gets. Until then the new agent sees nothing.
        None => match app.owner_ui.session.register_agent(name) {
            Ok((agent, _unused)) => agent,
            Err(err) => return app.set_err(err.message),
        },
    };
    // An agent that sees no credential (a new one) gets the catalog of the names. An
    // agent restricted to its listed items ("only these items") keeps its list.
    let sees_nothing = app
        .owner_ui
        .session
        .with_vault(|vault| vault.visible_items_for_agent(agent.id))
        .and_then(Result::ok)
        .is_some_and(|visible| visible.is_some_and(|items| items.is_empty()));
    app.ui.agent_onboarding.host = host;
    app.ui.agent_onboarding.pending = Some((agent.id, host));
    if let Some(setup) = host.setup() {
        app.ui.setup_host = setup.index();
    }
    app.owner_ui.new_agent_name.clear();
    app.owner_ui.selected_agent = Some(agent.id);
    app.place = Place::Agents;
    let request = OwnerRequest::ConnectAgent {
        agent_id: agent.id,
        agent_name: agent.name.clone(),
        show_all: sees_nothing,
    };
    match ctx {
        Some(ctx) if app.ui.sheet.is_some() => ask_owner_from_sheet(app, request, ctx),
        _ => app.ask_owner(request, ctx),
    }
}

/// A new token for a connected agent, for example after its token expired.
pub(super) fn reconnect(app: &mut DesktopApp, ctx: &egui::Context, agent_name: &str) {
    connect(app, Some(ctx), ConnectHost::guess(agent_name), agent_name);
}

/// The token sheet opened: the host of the connection, and whether its settings are
/// saved at once.
pub(super) fn token_shown(app: &mut DesktopApp) -> (ConnectHost, bool) {
    let state = &mut app.ui.agent_onboarding;
    let pending = state.pending.take();
    let fresh = match (pending, app.owner_ui.selected_agent) {
        (Some((agent_id, host)), Some(selected)) if agent_id == selected => {
            state.shown = Some(host);
            true
        }
        _ => false,
    };
    let host = state.shown.unwrap_or_else(|| {
        let name = app
            .owner_ui
            .fresh_token
            .as_ref()
            .map_or("", |fresh| fresh.agent_name.as_str());
        ConnectHost::guess(name)
    });
    (host, fresh)
}

/// The sheet of "Connect an Agent". Returns true on Escape.
pub(super) fn sheet(app: &mut DesktopApp, ctx: &egui::Context) -> bool {
    let mut chosen = None;
    let mut submit = false;
    let mut cancel = false;
    let selected = app.ui.agent_onboarding.host;
    let response = kit::sheet(ctx, "register-agent", 440.0, |ui| {
        kit::sheet_title(
            ui,
            "Connect an Agent",
            Some("Apassy sets up the host. There is nothing else to configure."),
        );
        kit::section(ui, None, None, |s| {
            for host in ConnectHost::ALL {
                let row = s.clickable_row(&format!("{}, {}", host.name(), host.detail()), |ui| {
                    host_row(ui, host, host == selected);
                });
                if row.clicked() {
                    chosen = Some(host);
                }
            }
        });
        kit::section(
            ui,
            None,
            Some(
                "You confirm once with Touch ID or the passphrase. Then the bouncer decides each use, and a question waits up to 5 minutes for you.",
            ),
            |s| {
                let field = s.field("Name", |ui| {
                    kit::text_input(
                        ui,
                        &mut app.owner_ui.new_agent_name,
                        "agent-name",
                        selected.agent_name(),
                    )
                });
                if field.lost_focus()
                    && field.ctx.input(|input| input.key_pressed(egui::Key::Enter))
                {
                    submit = true;
                }
            },
        );
        kit::sheet_buttons(
            ui,
            |_| {},
            |ui| {
                submit |= kit::button(
                    ui,
                    &format!("Connect {}", selected.name()),
                    Style::Prominent,
                )
                .on_hover_text("⌘S")
                .clicked();
                cancel = kit::button(ui, "Cancel", Style::Bordered).clicked();
            },
        );
    });
    submit |= super::save_pressed(app, ctx);
    if let Some(host) = chosen {
        // A name that the owner did not type follows the host.
        let typed = app.owner_ui.new_agent_name.trim();
        if typed.is_empty()
            || ConnectHost::ALL
                .iter()
                .any(|other| other.agent_name() == typed)
        {
            app.owner_ui.new_agent_name = host.agent_name().to_owned();
        }
        app.ui.agent_onboarding.host = host;
        submit = true;
    }
    if submit && app.owner.check.is_none() {
        let host = app.ui.agent_onboarding.host;
        let name = app.owner_ui.new_agent_name.clone();
        connect(app, Some(ctx), host, &name);
    }
    if cancel {
        close_sheet(app, ctx);
    }
    response.escape
}

/// One host in the sheet: its tile, its name, and how it connects.
fn host_row(ui: &mut egui::Ui, host: ConnectHost, selected: bool) {
    ui.horizontal(|ui| {
        kit::tile(ui, &kit::Tile::letter(host.color(), host.name()), 28.0);
        ui.add_space(4.0);
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            ui.label(kit::medium(host.name(), Font::Body).color(kit::LABEL));
            ui.add(
                Label::new(kit::text(host.detail(), Font::Callout).color(kit::SECONDARY))
                    .truncate(),
            );
        });
        if selected {
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                kit::paint_icon_in(ui, kit::Icon::Check, 14.0, kit::ACCENT);
            });
        }
    });
}

/// The start of the host in a terminal, with the tool time-out of the 5-minute wait.
pub(super) fn launch_command(host: Host) -> String {
    let launcher = std::env::current_exe()
        .ok()
        .and_then(|exe| std::fs::canonicalize(exe).ok())
        .and_then(|exe| exe.parent().map(|dir| dir.join("apassy-sandbox")))
        .unwrap_or_else(|| {
            std::path::PathBuf::from("/Applications/Apassy.app/Contents/MacOS/apassy-sandbox")
        });
    launch_command_at(host, &launcher)
}

fn launch_command_at(host: Host, launcher: &std::path::Path) -> String {
    let launcher = format!(
        "'{}'",
        launcher.display().to_string().replace('\'', "'\\''")
    );
    match host {
        Host::Claude => format!(
            "{CLAUDE_TOOL_TIMEOUT} {launcher} -- claude --settings '{{\"sandbox\":{{\"enabled\":false}}}}'"
        ),
        Host::Codex => format!("{launcher} -- codex -c sandbox_mode=danger-full-access"),
    }
}

/// What the owner does after the settings are saved.
pub(super) fn after_setup_notes(ui: &mut egui::Ui, host: ConnectHost) {
    let Some(setup) = host.setup() else {
        return;
    };
    if host == ConnectHost::T3 {
        kit::note(
            ui,
            "T3 Code starts Claude Code with these settings. For Codex sessions, connect Codex too.",
        );
    }
    kit::note(
        ui,
        format!(
            "Configuration saved. Start {} in the Apassy sandbox on macOS with the command below. Keep Apassy open and the vault unlocked. Connection and first use still need verification.",
            setup.name()
        ),
    );
    kit::note(
        ui,
        if setup == Host::Codex {
            "Use /hooks to trust the Apassy hook, and /mcp to check the connection. A question waits up to 5 minutes for you; the setup gives Codex a tool time-out of 660 seconds."
        } else {
            "Use /mcp to check the connection. A question waits up to 5 minutes for you, so start Claude Code with a tool time-out of at least 660 seconds:"
        },
    );
    kit::code_block(ui, &launch_command(setup), 2);
    kit::note(
        ui,
        "For owner CLI commands, install the links in Settings > Tools. In this terminal, add them to PATH:",
    );
    kit::code_block(ui, "export PATH=\"$HOME/.local/bin:$PATH\"", 1);
    kit::note(
        ui,
        "For future zsh terminals, run the following once (use ~/.bashrc for Bash):",
    );
    kit::code_block(
        ui,
        "printf '%s\\n' 'export PATH=\"$HOME/.local/bin:$PATH\"' >> \"$HOME/.zshrc\"",
        2,
    );
}

#[cfg(test)]
mod tests {
    #[test]
    fn launch_commands_preserve_shell_words_in_bash_and_zsh() {
        let path = std::path::Path::new("/tmp/App space 'quote $dollar;/apassy-sandbox");
        for host in [Host::Claude, Host::Codex] {
            let command = launch_command_at(host, path);
            let words = command
                .strip_prefix("MCP_TOOL_TIMEOUT=660000 ")
                .unwrap_or(&command);
            for shell in ["/bin/bash"]
                .into_iter()
                .chain(cfg!(target_os = "macos").then_some("/bin/zsh"))
            {
                let output = std::process::Command::new(shell)
                    .args(["-c", &format!("printf '%s\\0' {words}")])
                    .output()
                    .unwrap();
                assert!(output.status.success());
                let fields: Vec<_> = output.stdout.split(|byte| *byte == 0).collect();
                assert_eq!(fields[0], path.as_os_str().as_encoded_bytes());
                assert_eq!(fields[1], b"--");
                if host == Host::Claude {
                    assert_eq!(fields[4], br#"{"sandbox":{"enabled":false}}"#);
                }
            }
        }
    }

    use super::super::owner_tests::{PASS, WRONG, unlocked_app_with_item};
    use super::*;
    use crate::broker::approvals::OwnerCheck;

    #[test]
    fn audit_hosts_have_names_setup_targets_and_a_guess_from_the_agent_name() {
        assert_eq!(
            launch_command_at(
                Host::Codex,
                std::path::Path::new("/tmp/App space/apassy-sandbox")
            ),
            "'/tmp/App space/apassy-sandbox' -- codex -c sandbox_mode=danger-full-access"
        );
        assert_eq!(ConnectHost::Claude.setup(), Some(Host::Claude));
        assert_eq!(ConnectHost::Codex.setup(), Some(Host::Codex));
        assert_eq!(ConnectHost::T3.setup(), Some(Host::Claude));
        assert_eq!(ConnectHost::Other.setup(), None);
        assert_eq!(ConnectHost::guess("My Codex"), ConnectHost::Codex);
        assert_eq!(ConnectHost::guess("T3 Code"), ConnectHost::T3);
        assert_eq!(ConnectHost::guess("Claude Code"), ConnectHost::Claude);
        assert_eq!(ConnectHost::guess("CI on GitHub"), ConnectHost::Other);
        assert_eq!(
            launch_command_at(
                Host::Claude,
                std::path::Path::new("/tmp/App space/apassy-sandbox")
            ),
            "MCP_TOOL_TIMEOUT=660000 '/tmp/App space/apassy-sandbox' -- claude --settings '{\"sandbox\":{\"enabled\":false}}'"
        );
    }

    /// ADR 0025 §2: connecting is the only setup and needs one owner check. A new agent
    /// sees the credential names after it; a wrong passphrase changes nothing.
    #[test]
    fn connect_registers_once_and_gives_the_token_after_one_owner_check() {
        let dir = tempfile::TempDir::new().unwrap();
        let (mut app, _) = unlocked_app_with_item(&dir);
        connect(&mut app, None, ConnectHost::Codex, "");
        let agents = app.owner_ui.session.agents().unwrap();
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].name, "Codex");
        let agent = agents[0].clone();
        assert!(!app.owner_ui.session.agent_sees_all(agent.id).unwrap());
        assert!(
            app.owner_ui.fresh_token.is_none(),
            "no token before the check"
        );
        assert_eq!(app.place, Place::Agents);
        assert_eq!(app.ui.setup_host, Host::Codex.index());
        assert!(
            app.confirm_owner_now(OwnerCheck::passphrase(WRONG))
                .is_err()
        );
        assert!(!app.owner_ui.session.agent_sees_all(agent.id).unwrap());
        assert!(app.owner_ui.fresh_token.is_none());

        // The same host again takes the agent of that name: no second agent.
        connect(&mut app, None, ConnectHost::Codex, "Codex");
        assert_eq!(app.owner_ui.session.agents().unwrap().len(), 1);
        app.confirm_owner_now(OwnerCheck::passphrase(PASS)).unwrap();
        assert!(app.owner_ui.fresh_token.is_some());
        assert!(app.owner_ui.session.agent_sees_all(agent.id).unwrap());
        let (host, fresh) = token_shown(&mut app);
        assert_eq!(host, ConnectHost::Codex);
        assert!(fresh, "the token sheet saves the settings at once");
        assert_eq!(token_shown(&mut app), (ConnectHost::Codex, false));

        // A new agent sees the credential names after the check.
        app.owner_ui.fresh_token = None;
        connect(&mut app, None, ConnectHost::Other, "CI on GitHub");
        app.confirm_owner_now(OwnerCheck::passphrase(PASS)).unwrap();
        let ci = app
            .owner_ui
            .session
            .agents()
            .unwrap()
            .into_iter()
            .find(|agent| agent.name == "CI on GitHub")
            .expect("registered");
        assert!(app.owner_ui.session.agent_sees_all(ci.id).unwrap());
        assert_eq!(token_shown(&mut app).0, ConnectHost::Other);
    }
}
