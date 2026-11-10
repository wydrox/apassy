# ADR 0045 — Linux vault and browser passkeys

Status: Accepted for implementation; runtime qualification remains required.
Date: 2026-11-10

Linux x86_64 and arm64 use the shared SQLCipher vault, WebAuthn implementation,
and egui owner UI. Ubuntu and Debian are the first supported distributions.
This extends ADR 0041: Chrome stable and Chromium native messaging are enabled.
A passphrase must remain sufficient without a session bus, screen lock, biometric
reader, or desktop. Headless owner operations require an interactive terminal.

## Security boundary

Linux has no macOS code-signing identity, Secure Enclave or Touch ID boundary.
Root and compromised same-user processes are outside the protection offered by
this software vault. Harden secret-bearing processes against dumps and ptrace;
keep sockets and files private. X11 permits input interception; prefer Wayland.
Browser identity uses kernel peer credentials and a verified direct browser parent,
with root-owned executable paths, never process names or caller-supplied PIDs.
The host verifies its own installed executable. The app verifies that host image
when readable; Linux hides a non-dumpable peer's executable, so only that kernel
permission refusal uses peer credentials and browser ancestry instead. This does
not authenticate a hardened host executable to the app. Injected browser children
and compromised same-user processes remain outside this boundary. Reject unknown
browsers, stale processes, mismatched users and writable browser binaries.
This is defense in depth, not an equivalent to macOS signing. Preserve origin,
RP ID, challenge, approval and user-verification checks in the shared flow.

Passphrase unlock is the default. Optional Secret Service storage requires explicit
opt-in explaining that other same-user clients can retrieve an unlocked keyring
item. Never silently store a passphrase, log it, or pass it on a command line.
Optional polkit auth_self presence may use system PAM/fprintd; unavailable or
cancelled authentication must not count as success. Passphrase confirmation is
always available. Presence approval remains bound to the pending operation.

## Delivery and verification

Ship desktop and headless owner commands, browser host, Chrome/Chromium manifests,
and optional polkit policy in architecture-specific deb and tar archives. Keep
node-only operation supported. Installers must select architecture explicitly.
CI must build and test Linux vault/browser paths, including refusal cases, and
synthetic WebAuthn create/get with signature verification. Never use real accounts.
Source tests, package checks and actual desktop/browser acceptance are separate
claims. No release or main-branch push is part of this implementation.
