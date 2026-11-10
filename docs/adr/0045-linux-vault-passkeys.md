# ADR 0045 — Linux vault and browser passkeys

Status: Accepted for implementation; runtime qualification remains required.
Date: 2026-11-10

Linux x86_64 and arm64 use the shared SQLCipher vault, WebAuthn implementation,
and egui owner UI. Ubuntu and Debian are the first supported distributions.
This extends ADR 0041: Chrome stable and Chromium native messaging are enabled.
A passphrase must remain sufficient without a session bus, screen lock, biometric
reader, or desktop. Headless owner operations require an interactive terminal.
`apassy owner serve` hosts the browser and agent services without a desktop, and
approves each request only with a typed answer and the passphrase (or polkit) in that
terminal. It locks after `--idle-minutes`, else the device policy's "Lock after
inactivity" time, else 15 minutes, counted on the sleep-inclusive clock; the policy
"When the screen locks or the computer sleeps" also ends it at screen lock, sleep,
user switch and session end. SIGTERM, SIGHUP and SIGINT keep their default action:
the process ends at once, the key leaves with its memory, the sockets close and
waiting requests fail. There is no handler, because the crate forbids `unsafe` and
no new dependency is added.

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

Unsafe browser switches are refused: `--remote-debugging-*`,
`--disable-extensions-except`, `--type` and `--load-extension`, read from every word
of the browser's rewritten process title. One exception, added 2026-11-10 after the
acceptance run: Debian's `chromium` package starts every browser with
`--load-extension=` and the folders in `/usr/share/chromium/extensions` that its
`webext-*` packages install (`/etc/chromium.d/extensions`). That switch is accepted
when its one value lists only absolute paths that, after resolving symlinks, are
directories strictly inside that folder, and that folder, each listed directory and
every folder up to `/` are owned by root and not writable by group or others. Then
only root chose what the switch loads, from the same root-owned tree as the browser
executable that this check already trusts; a user process cannot add an extension
there. Everything else stays refused: a path elsewhere, a relative, missing or empty
path, an empty value (Debian's default when no system extension is installed), a
second `--load-extension` with another value, and, because the title hides where an
argument ends, a comma in any other word while the switch is present.

Secret and code Copy is offered only where Apassy itself owns the X11 or Wayland
(ext/wlr data-control) clipboard, learns of foreign replacement, and clears only
its own copy by replacing it with an empty one; other sessions have no Copy.
GNOME on Wayland offers no data-control protocol, so Copy there uses the X11
clipboard through XWayland.

Passphrase unlock is the default. Optional Secret Service storage requires explicit
opt-in explaining that other same-user clients can retrieve an unlocked keyring
item. Never silently store a passphrase, log it, or pass it on a command line.
Optional polkit auth_self presence may use system PAM/fprintd; unavailable or
cancelled authentication must not count as success. Passphrase confirmation is
always available. Two rules apply, as on macOS. Approval binding: an approval of an
agent run or a browser request names one pending operation (the run exactly as
shown; the origin, RP ID, account and user verification of a passkey), and its proof
is valid for that operation only, also when the reuse window covered it. Reuse
window: "How often to ask" sets how long one owner check covers the owner's later
manual actions in the desktop. A passphrase or a polkit check opens it, as Touch ID
or the passphrase does on macOS, but only while lock observation is available (a
systemd-logind session or a screen saver service). It ends at screen lock, sleep,
user switch, session end and the loss of a source; the actions that always ask on
macOS ask again here too. Without lock observation every action asks again.
`apassy owner serve` has no reuse window. Auto-lock follows the same signals; while
the desktop's logind idle hint says the session is active, inactivity does not lock
the vault, as on macOS. Both settings live in `device-policy.json` in the data
directory (mode 0600, this user, no symlink). Another process of the same user can
change that file; that is outside the Linux boundary above. A damaged, foreign or
too open file gives "Every time" and "Never" in the desktop, and the default
inactivity time with the session rule in `owner serve`.

## Delivery and verification

Ship desktop and headless owner commands, browser host, Chrome/Chromium manifests,
and optional polkit policy in architecture-specific deb and tar archives. Keep
node-only operation supported. Installers must select architecture explicitly.
CI must build and test Linux vault/browser paths, including refusal cases, and
synthetic WebAuthn create/get with signature verification. Never use real accounts.
Source tests, package checks and actual desktop/browser acceptance are separate
claims. No release or main-branch push is part of this implementation.
