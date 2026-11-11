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
/// On Linux: the agent runs without the Apassy sandbox.
#[cfg(target_os = "linux")]
#[macro_export]
macro_rules! agent_sandbox {
    () => {
        "with the command below. On Linux it runs as your user: the Apassy sandbox is macOS only."
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
        "Start the host as usual. Linux has no Apassy sandbox launcher yet (Seatbelt is macOS
only), so the agent runs as your user. A question waits up to 5 minutes:
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

/// Where the Apassy Connect key of this computer is kept (plan s7 decision 2): "in the
/// Keychain" on macOS.
#[cfg(not(target_os = "linux"))]
#[macro_export]
macro_rules! connect_key_place {
    () => {
        "in the Keychain"
    };
}
/// On Linux: a private file of the user (ADR 0045).
#[cfg(target_os = "linux")]
#[macro_export]
macro_rules! connect_key_place {
    () => {
        "in a private file of your user"
    };
}

/// How a signed-out Settings › Connect reads the Connect key again.
#[cfg(not(target_os = "linux"))]
#[macro_export]
macro_rules! connect_key_read {
    () => {
        "Touch ID reads the Connect key of this Mac."
    };
}
/// On Linux: the private file, with no prompt.
#[cfg(target_os = "linux")]
#[macro_export]
macro_rules! connect_key_read {
    () => {
        "Apassy reads the Connect key of this computer from its private file."
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
            crate::shift_key!(),
            crate::shortcut!("S"),
            crate::shortcut_shift!("H"),
            crate::shift_shortcut!("M"),
            crate::connect_key_place!(),
            crate::connect_key_read!(),
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
                "⇧",
                "⌘S",
                "⌘⇧H",
                "⇧⌘M",
                "in the Keychain",
                "Touch ID reads the Connect key of this Mac.",
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
                "with the command below. On Linux it runs as your user: the Apassy sandbox is macOS only.",
                "a stopped sync service or a file download",
                "the apassy program of the Apassy package (/usr/bin/apassy)",
                "the apassy program of the same package version as the running window",
                "The Apassy package includes the MCP server and the prompt hook.",
                "Start the host as usual. Linux has no Apassy sandbox launcher yet (Seatbelt is macOS
only), so the agent runs as your user. A question waits up to 5 minutes:
  claude: MCP_TOOL_TIMEOUT=660000 claude
  codex:  codex
",
                "an owner check on it",
                "Apassy",
                "Shift+",
                "Ctrl+S",
                "Ctrl+Shift+H",
                "Ctrl+Shift+M",
                "in a private file of your user",
                "Apassy reads the Connect key of this computer from its private file.",
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
