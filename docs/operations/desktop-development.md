# Desktop development

Date: 2026-09-16.
Status: P1 desktop foundation. This is not a complete vault and not a complete P1.

The owner selected a macOS desktop app. The shell uses eframe/egui 0.36.2 with AccessKit, default fonts, and glow. Persistence is off.

This desktop is a demo. It is not a secure vault. It does not encrypt data. It does not connect storage. It does not verify isolation. It does not call a language model.

## Exact commands

Run the desktop model tests:

```
cargo test --locked --features desktop --test desktop_model
```

Open the native window:

```
cargo run --locked --features desktop --bin apassy
```

Exercise the native app model without a window. This check is not a graphical test. A failure exits with a non-zero status:

```
cargo run --locked --features desktop --bin apassy -- --smoke-test
```

The smoke-test option does not read secrets. It does not print secrets. The binary has no other command that reads or prints secrets.

The desktop crate also draws the owner views in memory with `egui::Context::run_ui`. Those tests do not open a native window. They do not prove pixel layout or OS window quality. egui ID-clash checks stay unverified. The public eframe/egui 0.36.2 API does not expose a documented ID-clash result on `FullOutput`.

## What the desktop does

The window starts in a locked demo view. Open vault is not authentication.

The shell has five owner views:

- Vault
- Item details
- Rules
- Agents
- Activity and approvals

The vault shows five credential categories. Add, edit, search, and delete use labels only. The model assigns a fixed synthetic value. There is no secret input field.

A demo reveal can show that synthetic value. The copy control shows a warning. The desktop does not write to the clipboard.

You can connect and revoke the fixture agents. The rule editor reviews one supported sample. The fixture interpreter refuses other text. This is not live natural-language support.

The activity view can send three fixture requests:

- Normal staging report: permit
- Uncertain task: wait, then approve once or deny
- Production report: deny, and the owner cannot approve this denial

Approval updates the current request and alert. The app retains the first decision and original activity records.
Lock, revoke, denial, and expired approval also update the alert state. Notification failure stays separate from approval.
The inbox and history stay in memory. They are not durable. There is no backup or export control.

## What the desktop does not do

- The `--features desktop` demo does not save files or encrypt credentials. The `desktop,vault` build does, for vault items only. See the vault feature section below.
- It does not copy values to the clipboard.
- It does not open a network socket.
- It does not ask for notification permission.
- It does not claim a complete secure vault.

Storage status on the foundation panel: not connected. That panel describes the demo model.
Model status: unverified.
Isolation status: unverified.

## Vault feature

`cargo run --locked --features desktop,vault --bin apassy` connects the Vault and Item details views to `apassy::vault`.
The owner types a file path and a passphrase. Create and open return a locked file. Unlock, add, edit, search, delete, reveal, backup, and restore use that file.
Secret fields are not search keys and are not copied into status text. Reveal keeps a value on screen until hide or lock. The desktop does not write the clipboard.
Rules, agents, and activity stay on the in-memory demo. Reset demo does not delete the vault file.
A build with only `--features desktop` keeps the older demo vault. See [desktop vault integration](desktop-vault.md).

## Verification

The parent ran the model tests, headless drawing tests, formatting, Clippy, and CLI smoke check.
See [foundation verification](foundation-verification.md) for exact commands and results.
Native-window visual QA, keyboard interaction, accessibility, and egui ID-clash diagnostics remain unverified.
