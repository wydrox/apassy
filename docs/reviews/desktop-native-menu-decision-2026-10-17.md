# F06: native macOS menu implementation decision

Date: 2026-10-17.
Status: **IMPLEMENTED and locally validated** within the approved main-flow work. The initial proposal was followed by authorized implementation; no additional owner approval is pending. This records a scoped menu library addition, not adoption of a new application framework. Device/customer acceptance and the native inspection isolation exception remain in the [validation ledger](main-flows-validation-2026-10-17.md).

## Dependency impact

[Cargo.toml](../../Cargo.toml) pins optional, macOS-only `muda = 0.21.2` with default features disabled and includes it in `desktop`. [Cargo.lock](../../Cargo.lock) adds exactly **muda 0.21.2**, **crossbeam-channel 0.5.17**, and **keyboard-types 0.8.3**; existing package versions are unchanged. The existing AppKit/Foundation/CoreFoundation stack is reused. No Tauri, Tao, Wry, or other application framework was adopted.

```toml
[target.'cfg(target_os = "macos")'.dependencies]
muda = { version = "=0.21.2", optional = true, default-features = false }
```

The [published safe API](https://docs.rs/crate/muda/0.21.2/source/) supplies `Menu::init_for_nsapp()` and `MenuEvent::set_event_handler()`. Main-thread menu installation retains the app/window commands. Apassy retains `forbid(unsafe_code)`; direct unsafe objc2 dispatch was not introduced.

## Commands and guards

| Menu | Commands | Context |
| --- | --- | --- |
| Apassy / Window / File | Standard app/window actions, including Hide, Quit and Close Window | Native app/window behavior retained. |
| File | New Credential… (⌘N), New Folder… | Unlocked eligible vault; New Folder uses the selected personal folder. |
| Edit | Undo / Undo Move (⌘Z), Redo (⇧⌘Z), Cut/Copy/Paste (⌘X/C/V), Select All (⌘A) | Text commands stay with the focused editor; library Select All requires focused rows. Undo Move requires a valid move record outside text focus. Owner passphrase input allows Paste/Select All/Undo/Redo for that exact idle dialog; Copy/Cut are disabled. Menu Copy never starts secret reveal. |
| Item | Move to Folder… (⇧⌘M) | Eligible personal-vault selection, outside text focus. |
| Folder | Rename…, Move Folder…, Delete… | Existing selected personal folder; Delete opens the named confirmation. |

[Implementation](../../src/desktop/native_menu.rs) queues only command IDs with displayed vault/session, selection, navigation, modal and focus context. Dispatch revalidates that context and command eligibility; lock/unlock, a changed selection/folder, new modal/owner check, or changed focus rejects stale events. Organization commands cannot replace a sheet or approve an owner check. Duplicate accelerator delivery is discarded before the existing UI action executes.

[Menu context](../../src/desktop/ui.rs) validates selected IDs using a constant number of metadata queries independent of selection size. It does not read full credential details or secret values. Text editing and library organization share existing guarded operations without routing text undo into Move Undo.

## Validation and limits

- **Final menu tests: 10 PASS** after the metadata-only optimization ([log](/tmp/apassy-flow-ux-menu-final.log)); **keyboard 29 PASS** and **owner 20 PASS** precede that optimization. Stale session/selection/modal/focus, text editing, password Copy suppression and exact owner-dialog guards are covered.
- **Final all-feature/all-target Clippy**, **desktop-only feature**, and **binary build PASS** ([Clippy](/tmp/apassy-flow-ux-final-clippy.log), [feature](/tmp/apassy-flow-ux-menu-feature.log), [build](/tmp/apassy-flow-ux-final-build.log)). Formatting and diff checks passed. Earlier library/integration totals are separate snapshots, not rerun counts for this menu delta.
- **Actual temporary unsigned app/AX:** locked commands, File folder creation, Edit Select All/Undo/Redo, subtree reparent/path readback, named delete confirmation/cancel, inherited New Credential destination, all-12 Move and Undo, final Copy prompt editing guards, and Menu Quit exit status 0 were exercised with synthetic data. Full actions, final binary hash and retained artifact are in the [ledger](main-flows-validation-2026-10-17.md#actual-native-synthetic-walkthrough).

No owner confirmation or clipboard write occurred. The later computer-use AX read unexpectedly relaunched the temporary bundle without inherited isolation, showed the normal vault list and a file-in-use error, and was stopped. Startup bookkeeping effects were not established. That relaunch is excluded from acceptance; the launchable bundle was removed, with the validated binary retained. Future test bundles must pin their isolation independently of the launching process environment. Signed helpers, real pasteboard/biometrics, physical devices, VoiceOver and measured contrast remain unverified.
