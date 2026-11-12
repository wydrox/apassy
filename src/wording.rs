//! Owner-check wording that differs by platform, as string literals for `concat!`:
//! macOS confirms with Touch ID or the passphrase, Linux with the vault passphrase or
//! system authentication (polkit, ADR 0045). A Linux user must never be told to use
//! Touch ID.

/// "Touch ID or the passphrase" on macOS.
#[cfg(not(target_os = "linux"))]
#[macro_export]
macro_rules! owner_check {
    () => {
        "Touch ID or the passphrase"
    };
}
/// "the passphrase or system authentication" on Linux.
#[cfg(target_os = "linux")]
#[macro_export]
macro_rules! owner_check {
    () => {
        "the passphrase or system authentication"
    };
}

/// Where macOS names Touch ID alone ("needs Touch ID"): "Touch ID" on macOS.
#[cfg(not(target_os = "linux"))]
#[macro_export]
macro_rules! touch_id {
    () => {
        "Touch ID"
    };
}
/// Where macOS names Touch ID alone: the Linux owner check.
#[cfg(target_os = "linux")]
#[macro_export]
macro_rules! touch_id {
    () => {
        "the passphrase or system authentication"
    };
}

/// The computer Apassy runs on, or another computer of the owner: "Mac" on macOS,
/// "computer" on Linux ("this Mac", "another Mac"). A device that really is a Mac
/// keeps the word "Mac".
#[cfg(not(target_os = "linux"))]
#[macro_export]
macro_rules! computer {
    () => {
        "Mac"
    };
}
/// On Linux: "computer".
#[cfg(target_os = "linux")]
#[macro_export]
macro_rules! computer {
    () => {
        "computer"
    };
}

/// [`computer!`] at the start of a sentence: "Mac" or "Computer".
#[cfg(not(target_os = "linux"))]
#[macro_export]
macro_rules! computer_cap {
    () => {
        "Mac"
    };
}
/// On Linux: "Computer".
#[cfg(target_os = "linux")]
#[macro_export]
macro_rules! computer_cap {
    () => {
        "Computer"
    };
}

/// The plural of [`computer!`]: "Macs" or "computers".
#[cfg(not(target_os = "linux"))]
#[macro_export]
macro_rules! computers {
    () => {
        "Macs"
    };
}
/// On Linux: "computers".
#[cfg(target_os = "linux")]
#[macro_export]
macro_rules! computers {
    () => {
        "computers"
    };
}

/// [`computers!`] at the start of a sentence: "Macs" or "Computers".
#[cfg(not(target_os = "linux"))]
#[macro_export]
macro_rules! computers_cap {
    () => {
        "Macs"
    };
}
/// On Linux: "Computers".
#[cfg(target_os = "linux")]
#[macro_export]
macro_rules! computers_cap {
    () => {
        "Computers"
    };
}

/// Where the owner deletes or finds a file: "in Finder" or "in your file manager".
#[cfg(not(target_os = "linux"))]
#[macro_export]
macro_rules! in_file_manager {
    () => {
        "in Finder"
    };
}
/// On Linux: "in your file manager".
#[cfg(target_os = "linux")]
#[macro_export]
macro_rules! in_file_manager {
    () => {
        "in your file manager"
    };
}

/// The window's shortcut to hide or show the sidebar: ⌃⌘S on macOS, F9 on Linux
/// (the side-pane key of GNOME and KDE applications; Ctrl+S means Save there).
#[cfg(not(target_os = "linux"))]
#[macro_export]
macro_rules! sidebar_shortcut {
    () => {
        "⌃⌘S"
    };
}
/// On Linux: "F9".
#[cfg(target_os = "linux")]
#[macro_export]
macro_rules! sidebar_shortcut {
    () => {
        "F9"
    };
}

/// The window's shortcut back to the list: ⌘[ on macOS, Alt+Left on Linux.
#[cfg(not(target_os = "linux"))]
#[macro_export]
macro_rules! back_shortcut {
    () => {
        "⌘["
    };
}
/// On Linux: "Alt+Left".
#[cfg(target_os = "linux")]
#[macro_export]
macro_rules! back_shortcut {
    () => {
        "Alt+Left"
    };
}

/// The installed app, in "Reinstall …": "Apassy.app" on macOS, "the Apassy package" on
/// Linux (apassy-vault, a .deb or the tarball).
#[cfg(not(target_os = "linux"))]
#[macro_export]
macro_rules! app_package {
    () => {
        "Apassy.app"
    };
}
/// On Linux: "Apassy" (the apassy-vault package).
#[cfg(target_os = "linux")]
#[macro_export]
macro_rules! app_package {
    () => {
        "Apassy"
    };
}

/// How an agent starts after its setup: "in the Apassy sandbox on macOS with the command
/// below.". Linux has
/// no sandbox launcher yet (Seatbelt is macOS only), so the agent runs as the owner.
#[cfg(not(target_os = "linux"))]
#[macro_export]
macro_rules! agent_sandbox {
    () => {
        "in the Apassy sandbox on macOS with the command below."
    };
}
/// On Linux: the agent runs without the Apassy sandbox ([`agents_unconfined!`]).
#[cfg(target_os = "linux")]
#[macro_export]
macro_rules! agent_sandbox {
    () => {
        concat!("with the command below. ", $crate::agents_unconfined!())
    };
}

/// Linux only: what it means that `apassy-sandbox` (Seatbelt) exists only on macOS. The
/// agent setup screens and `docs/operations/linux-vault.md` say it.
#[cfg(target_os = "linux")]
#[macro_export]
macro_rules! agents_unconfined {
    () => {
        "On Linux, agents run without Apassy's sandbox. The bouncer and your approvals still decide each use of a credential, but the agent process itself is not confined: it can read and change what your user can."
    };
}

/// What can hold up the open of a synced file: "a macOS permission request or a file
/// download" on macOS; on Linux "a stopped sync service or a file download".
#[cfg(not(target_os = "linux"))]
#[macro_export]
macro_rules! os_permission_or_download {
    () => {
        "a macOS permission request or a file download"
    };
}
/// On Linux: "a stopped sync service or a file download".
#[cfg(target_os = "linux")]
#[macro_export]
macro_rules! os_permission_or_download {
    () => {
        "a stopped sync service or a file download"
    };
}

/// The owner command line that belongs to the app: inside Apassy.app on macOS, the
/// `apassy` of the package on Linux.
#[cfg(not(target_os = "linux"))]
#[macro_export]
macro_rules! app_cli {
    () => {
        "the apassy program inside Apassy.app"
    };
}
/// On Linux: app_cli without the app bundle.
#[cfg(target_os = "linux")]
#[macro_export]
macro_rules! app_cli {
    () => {
        "the apassy program of the Apassy package (/usr/bin/apassy)"
    };
}

/// [`app_cli!`] of the running window.
#[cfg(not(target_os = "linux"))]
#[macro_export]
macro_rules! running_app_cli {
    () => {
        "the apassy program inside the running Apassy.app"
    };
}
/// On Linux: running_app_cli without the app bundle.
#[cfg(target_os = "linux")]
#[macro_export]
macro_rules! running_app_cli {
    () => {
        "the apassy program of the same package version as the running window"
    };
}

/// What the app brings for agent hosts. The Linux package has no sandbox launcher.
#[cfg(not(target_os = "linux"))]
#[macro_export]
macro_rules! app_includes {
    () => {
        "Apassy.app includes the MCP server, prompt hook, and sandbox."
    };
}
/// On Linux: app_includes without the app bundle.
#[cfg(target_os = "linux")]
#[macro_export]
macro_rules! app_includes {
    () => {
        "The Apassy package includes the MCP server and the prompt hook."
    };
}

/// How `apassy setup` tells the owner to start the host, one line per host.
#[cfg(not(target_os = "linux"))]
#[macro_export]
macro_rules! setup_start_help {
    () => {
        "Start the host in the Apassy sandbox (see docs/operations/isolation.md):
  claude: MCP_TOOL_TIMEOUT=660000 apassy-sandbox -- claude --settings '{\"sandbox\":{\"enabled\":false}}'
  codex:  apassy-sandbox -- codex -c sandbox_mode=danger-full-access
"
    };
}
/// On Linux: setup_start_help without the app bundle.
#[cfg(target_os = "linux")]
#[macro_export]
macro_rules! setup_start_help {
    () => {
        "Start the host as usual. On Linux, agents run without Apassy's sandbox (Seatbelt is
macOS only). The bouncer and your approvals still decide each use of a credential, but
the agent process itself is not confined: it can read and change what your user can.
A question waits up to 5 minutes:
  claude: MCP_TOOL_TIMEOUT=660000 claude
  codex:  codex
"
    };
}

/// How another computer of the vault confirms an answer: "Touch ID on it" on macOS.
/// From Linux the other computer can be a Mac or a Linux computer.
#[cfg(not(target_os = "linux"))]
#[macro_export]
macro_rules! touch_id_on_it {
    () => {
        "Touch ID on it"
    };
}
/// On Linux: "an owner check on it".
#[cfg(target_os = "linux")]
#[macro_export]
macro_rules! touch_id_on_it {
    () => {
        "an owner check on it"
    };
}

/// The desktop app as a place ("Mac Decisions"): "Mac" on macOS, "Apassy" on Linux.
#[cfg(not(target_os = "linux"))]
#[macro_export]
macro_rules! desktop_app {
    () => {
        "Mac"
    };
}
/// On Linux: "Apassy".
#[cfg(target_os = "linux")]
#[macro_export]
macro_rules! desktop_app {
    () => {
        "Apassy"
    };
}

/// The badge of a browser row when no installed app connects browsers: "Needs
/// Apassy.app" on macOS, "Needs the Apassy package" on Linux.
#[cfg(not(target_os = "linux"))]
#[macro_export]
macro_rules! needs_app {
    () => {
        "Needs Apassy.app"
    };
}
/// On Linux: "Needs the Apassy package".
#[cfg(target_os = "linux")]
#[macro_export]
macro_rules! needs_app {
    () => {
        "Needs the Apassy package"
    };
}

/// Where the extension must come from: "the same Apassy.app" on macOS, "the same
/// Apassy package" on Linux.
#[cfg(not(target_os = "linux"))]
#[macro_export]
macro_rules! same_app {
    () => {
        "the same Apassy.app"
    };
}
/// On Linux: "the same Apassy package".
#[cfg(target_os = "linux")]
#[macro_export]
macro_rules! same_app {
    () => {
        "the same Apassy package"
    };
}

/// How `apassy setup browser` tells a source build what to run instead.
#[cfg(not(target_os = "linux"))]
#[macro_export]
macro_rules! browser_source_build {
    () => {
        "Use the apassy program inside Apassy.app: /Applications/Apassy.app/Contents/MacOS/apassy setup browser. Source builds are not protected browser hosts."
    };
}
/// On Linux: install the package with its root-owned host.
#[cfg(target_os = "linux")]
#[macro_export]
macro_rules! browser_source_build {
    () => {
        "Install the Linux vault package with its root-owned host at /usr/lib/apassy/apassy-browser-host. Source builds are not accepted browser hosts."
    };
}

/// The hover of Copy and Show: how the owner confirms on this platform. The Linux owner
/// dialog offers the passphrase and "Use system authentication" (polkit).
#[cfg(not(target_os = "linux"))]
#[macro_export]
macro_rules! confirm_hint {
    () => {
        "Confirm with Touch ID or passphrase."
    };
}
/// On Linux: the vault passphrase or system authentication.
#[cfg(target_os = "linux")]
#[macro_export]
macro_rules! confirm_hint {
    () => {
        "Confirm with your vault passphrase or system authentication."
    };
}

/// The caller of a passkey request without a page: "the macOS passkey sheet" on macOS.
/// Linux has no system passkey sheet; such a request names an app on this computer.
#[cfg(not(target_os = "linux"))]
#[macro_export]
macro_rules! passkey_sheet {
    () => {
        "the macOS passkey sheet"
    };
}
/// On Linux: "an app on this computer".
#[cfg(target_os = "linux")]
#[macro_export]
macro_rules! passkey_sheet {
    () => {
        "an app on this computer"
    };
}

/// What an Allow on another device of the vault needs: "an Allow there needs Face ID or
/// Touch ID" on macOS (an iPhone or a Mac). From Linux the other device can be a Linux
/// computer too, so Linux names no Apple check.
#[cfg(not(target_os = "linux"))]
#[macro_export]
macro_rules! allow_there {
    () => {
        "an Allow there needs Face ID or Touch ID"
    };
}
/// On Linux: "an Allow there needs the owner check of that device".
#[cfg(target_os = "linux")]
#[macro_export]
macro_rules! allow_there {
    () => {
        "an Allow there needs the owner check of that device"
    };
}

/// The Shift key in a shortcut: "⇧Tab" on macOS, "Shift+Tab" on Linux.
#[cfg(not(target_os = "linux"))]
#[macro_export]
macro_rules! shift_key {
    () => {
        "⇧"
    };
}
/// On Linux: "Shift+".
#[cfg(target_os = "linux")]
#[macro_export]
macro_rules! shift_key {
    () => {
        "Shift+"
    };
}

/// A shortcut with the command key: `shortcut!("S")` is "⌘S" on macOS, "Ctrl+S" on Linux.
#[cfg(not(target_os = "linux"))]
#[macro_export]
macro_rules! shortcut {
    ($key:literal) => {
        concat!("⌘", $key)
    };
}
/// A shortcut with the command key: "Ctrl+S" on Linux.
#[cfg(target_os = "linux")]
#[macro_export]
macro_rules! shortcut {
    ($key:literal) => {
        concat!("Ctrl+", $key)
    };
}

/// Command and Shift, in the order "⌘⇧H" on macOS; "Ctrl+Shift+H" on Linux.
#[cfg(not(target_os = "linux"))]
#[macro_export]
macro_rules! shortcut_shift {
    ($key:literal) => {
        concat!("⌘⇧", $key)
    };
}
/// Command and Shift: "Ctrl+Shift+H" on Linux.
#[cfg(target_os = "linux")]
#[macro_export]
macro_rules! shortcut_shift {
    ($key:literal) => {
        concat!("Ctrl+Shift+", $key)
    };
}

/// Shift and Command, in the order "⇧⌘M" on macOS; "Ctrl+Shift+M" on Linux.
#[cfg(not(target_os = "linux"))]
#[macro_export]
macro_rules! shift_shortcut {
    ($key:literal) => {
        concat!("⇧⌘", $key)
    };
}
/// Shift and Command: "Ctrl+Shift+M" on Linux.
#[cfg(target_os = "linux")]
#[macro_export]
macro_rules! shift_shortcut {
    ($key:literal) => {
        concat!("Ctrl+Shift+", $key)
    };
}

/// A Connect key that cannot be used any more.
#[cfg(not(target_os = "linux"))]
#[macro_export]
macro_rules! connect_key_lost {
    () => {
        "This Mac's Apassy Connect key is gone (the Touch ID fingerprints changed). Add this Mac again from another device, or recover the account."
    };
}
/// On Linux: the file is missing, damaged, or not private.
#[cfg(target_os = "linux")]
#[macro_export]
macro_rules! connect_key_lost {
    () => {
        "This computer's Apassy Connect key cannot be used: its file is missing, damaged, or not private to your user. Add this computer again from another device, or recover the account."
    };
}

/// A build that has no place for the Connect key.
#[cfg(not(target_os = "linux"))]
#[macro_export]
macro_rules! connect_key_unavailable {
    () => {
        "The Keychain is not available to this build. Apassy Connect works only in Apassy.app."
    };
}
/// On Linux: the data folder of Apassy is not usable.
#[cfg(target_os = "linux")]
#[macro_export]
macro_rules! connect_key_unavailable {
    () => {
        "Apassy cannot keep the Apassy Connect key of this computer: its data folder is not usable."
    };
}

/// The owner cancelled the check that reads the Connect key.
#[cfg(not(target_os = "linux"))]
#[macro_export]
macro_rules! connect_key_cancelled {
    () => {
        "Touch ID was cancelled. Nothing changed."
    };
}
/// On Linux: the owner check or the keyring request.
#[cfg(target_os = "linux")]
#[macro_export]
macro_rules! connect_key_cancelled {
    () => {
        "The request was cancelled. Nothing changed."
    };
}

#[cfg(test)]
mod tests {
    /// The words of each macro on this platform, in the order of this file.
    fn all() -> Vec<&'static str> {
        vec![
            crate::owner_check!(),
            crate::touch_id!(),
            crate::computer!(),
            crate::computer_cap!(),
            crate::computers!(),
            crate::computers_cap!(),
            crate::in_file_manager!(),
            crate::sidebar_shortcut!(),
            crate::back_shortcut!(),
            crate::app_package!(),
            crate::agent_sandbox!(),
            crate::os_permission_or_download!(),
            crate::app_cli!(),
            crate::running_app_cli!(),
            crate::app_includes!(),
            crate::setup_start_help!(),
            crate::touch_id_on_it!(),
            crate::desktop_app!(),
            crate::needs_app!(),
            crate::same_app!(),
            crate::browser_source_build!(),
            crate::confirm_hint!(),
            crate::passkey_sheet!(),
            crate::allow_there!(),
            crate::shift_key!(),
            crate::shortcut!("S"),
            crate::shortcut_shift!("H"),
            crate::shift_shortcut!("M"),
            crate::connect_key_lost!(),
            crate::connect_key_unavailable!(),
            crate::connect_key_cancelled!(),
        ]
    }

    /// macOS keeps the words it had before the macros: each one, written out here.
    #[test]
    fn mac_wording_is_unchanged() {
        if cfg!(target_os = "linux") {
            return;
        }
        assert_eq!(
            all(),
            [
                "Touch ID or the passphrase",
                "Touch ID",
                "Mac",
                "Mac",
                "Macs",
                "Macs",
                "in Finder",
                "⌃⌘S",
                "⌘[",
                "Apassy.app",
                "in the Apassy sandbox on macOS with the command below.",
                "a macOS permission request or a file download",
                "the apassy program inside Apassy.app",
                "the apassy program inside the running Apassy.app",
                "Apassy.app includes the MCP server, prompt hook, and sandbox.",
                "Start the host in the Apassy sandbox (see docs/operations/isolation.md):
  claude: MCP_TOOL_TIMEOUT=660000 apassy-sandbox -- claude --settings '{\"sandbox\":{\"enabled\":false}}'
  codex:  apassy-sandbox -- codex -c sandbox_mode=danger-full-access
",
                "Touch ID on it",
                "Mac",
                "Needs Apassy.app",
                "the same Apassy.app",
                "Use the apassy program inside Apassy.app: /Applications/Apassy.app/Contents/MacOS/apassy setup browser. Source builds are not protected browser hosts.",
                "Confirm with Touch ID or passphrase.",
                "the macOS passkey sheet",
                "an Allow there needs Face ID or Touch ID",
                "⇧",
                "⌘S",
                "⌘⇧H",
                "⇧⌘M",
                "This Mac's Apassy Connect key is gone (the Touch ID fingerprints changed). Add this Mac again from another device, or recover the account.",
                "The Keychain is not available to this build. Apassy Connect works only in Apassy.app.",
                "Touch ID was cancelled. Nothing changed.",
            ]
        );
    }

    /// Linux names no Mac-only thing.
    #[test]
    fn linux_wording_names_no_mac_thing() {
        if !cfg!(target_os = "linux") {
            return;
        }
        assert_eq!(
            all(),
            [
                "the passphrase or system authentication",
                "the passphrase or system authentication",
                "computer",
                "Computer",
                "computers",
                "Computers",
                "in your file manager",
                "F9",
                "Alt+Left",
                "Apassy",
                "with the command below. On Linux, agents run without Apassy's sandbox. The bouncer and your approvals still decide each use of a credential, but the agent process itself is not confined: it can read and change what your user can.",
                "a stopped sync service or a file download",
                "the apassy program of the Apassy package (/usr/bin/apassy)",
                "the apassy program of the same package version as the running window",
                "The Apassy package includes the MCP server and the prompt hook.",
                "Start the host as usual. On Linux, agents run without Apassy's sandbox (Seatbelt is
macOS only). The bouncer and your approvals still decide each use of a credential, but
the agent process itself is not confined: it can read and change what your user can.
A question waits up to 5 minutes:
  claude: MCP_TOOL_TIMEOUT=660000 claude
  codex:  codex
",
                "an owner check on it",
                "Apassy",
                "Needs the Apassy package",
                "the same Apassy package",
                "Install the Linux vault package with its root-owned host at /usr/lib/apassy/apassy-browser-host. Source builds are not accepted browser hosts.",
                "Confirm with your vault passphrase or system authentication.",
                "an app on this computer",
                "an Allow there needs the owner check of that device",
                "Shift+",
                "Ctrl+S",
                "Ctrl+Shift+H",
                "Ctrl+Shift+M",
                "This computer's Apassy Connect key cannot be used: its file is missing, damaged, or not private to your user. Add this computer again from another device, or recover the account.",
                "Apassy cannot keep the Apassy Connect key of this computer: its data folder is not usable.",
                "The request was cancelled. Nothing changed.",
            ]
        );
        for text in all() {
            for word in [
                "Touch ID",
                "Finder",
                "Apassy.app",
                "⌘",
                "⌃",
                "⇧",
                "iCloud",
                "Keychain",
            ] {
                assert!(!text.contains(word), "{text}");
            }
            // "macOS" may say what Linux lacks; "Mac" alone never names this computer.
            assert!(!text.replace("macOS", "").contains("Mac"), "{text}");
        }
    }

    /// Linux says plainly that agents are not confined, and what still holds.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_says_that_agents_run_without_the_sandbox() {
        let text = crate::agents_unconfined!();
        for words in [
            "without Apassy's sandbox",
            "The bouncer and your approvals still decide each use of a credential",
            "not confined",
        ] {
            assert!(text.contains(words), "{text}");
        }
        assert!(crate::agent_sandbox!().ends_with(text));
    }

    #[test]
    fn linux_wording_never_names_touch_id() {
        for text in [crate::owner_check!(), crate::touch_id!()] {
            assert_eq!(
                text.contains("Touch ID"),
                !cfg!(target_os = "linux"),
                "{text}"
            );
        }
    }
}
