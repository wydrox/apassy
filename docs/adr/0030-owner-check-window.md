# ADR 0030 — How often to ask for Touch ID

Date: 2026-10-31. Status: owner-approved design; implementation proposed for review.
Supersedes ADR 0021's every-fill rule for the opt-in modes below. Every time remains
the default. The owner's final decisions supersede the narrower scope proposed in
`docs/reviews/audit-2026-10-31/approvals-frequency.md`.

## Decision

Settings > Security has one row, **How often to ask for Touch ID**:
**Every time**, **1 minute**, **5 minutes**, **15 minutes**, **1 hour**, and
**Until the Mac locks**. The setting is per Mac, shared across its vaults, and never
synced. The active verification is bound to the current unlocked vault epoch.
Changing the setting always requires a fresh local owner check. The change clears
the window, including when choosing a shorter period. The next covered action
checks again.

A successful fresh local Touch ID or vault-passphrase check, including vault
unlock and the passphrase check for Touch ID setup, starts an absolute window.
Setup records verification on its worker before Keychain I/O or delayed UI polling;
its cache deadline cannot slide while storage completes. Any fresh local check can restart that window,
except changing this setting and answering a remote question. Use never extends
it. Remote and iPhone answers neither use nor seed it.

Covered actions:

- Browser password and one-time-code fill, save, create and password update.
- macOS AutoFill password and code fill.
- Passkey sign-in/assertion through the extension or macOS AutoFill. Its signed
  authenticator data sets UP and UV, as after a fresh check: the owner verified
  locally within the configured window. This is the explicitly accepted session
  verification model, including requests that require user verification.
- Agent **Allow once**, only after the owner clicks that answer for each exact
  pending request. The window itself never answers a question.

A covered browser action with trusted provenance completes immediately inside the
window. There is no Apassy confirmation sheet or additional click. Multiple
passkey accounts still require selecting the exact account. No passkey is selected
by the window. The system's own AutoFill chooser and prompts remain OS-controlled.

Always fresh: vault unlock; reveal/show/copy/large type, including OTP; secret
export, backup and restore; Allow production, Allow in project and all durable
grants; Allow once and let the bouncer evaluate; rule and environment relaxations;
agent connect and token issue/rotate; devices and pairing; remote/iPhone answers;
passkey creation/removal; and this setting. Backup (window and CLI), CLI decision export and CLI agent registration/token
issuance now also take fresh exact-action proofs; the final owner decision
overrides the audit's earlier exemptions. Restore verifies the typed backup
passphrase afresh, and retains its locked result. Existing passphrase-change and
Touch ID setup checks are not relaxed. Unknown actions always stay fresh.

## Enforcement and storage

`OwnerGate` is the only proof issuer. The desktop vault session owns one shared
memory-only `OwnerWindow`, passed to every app gate. Reuse is available only to the
local controller with a live signed browser/AutoFill request or an explicit Allow
once click, and only for the source-specific action allowlist. No wire API accepts
an authorization window or a skip-auth instruction. Each use makes a new non-Clone
proof for one exact action, target and vault epoch. Consumption rechecks the window
generation and absolute deadline as well as the existing proof lifetime. A proof
cannot outlive the remaining window. Fresh local proofs also carry a generation
fence. A read-only delivery fence rechecks the vault epoch, window generation and
deadline immediately before browser or AutoFill response delivery; revocation
between computation and delivery erases the response rather than releasing it. Clocks are injected in tests; production uses monotonic `Instant` time.

The effective policy is a versioned Data Protection Keychain item:
service `com.wydrox.apassy.owner-policy`, account `frequency-v1`, the signed app's
existing access group, `WhenUnlockedThisDeviceOnly`, synchronizable false. Policy
reads do not request biometry. Every native command retains the signed containing
app parent check. The narrowly typed setter is called only after validating the
fresh setting-change proof. Writes read back the exact value. Missing, malformed,
unknown, unreadable or failed storage means Every time; there is no preferences
file fallback. A source build without the protected helper cannot enable reuse.

The extension has no window timer, cache, secret or window token. Inline-menu and
popup secret actions require `event.isTrusted`. The isolated passkey bridge checks
the browser's transient `navigator.userActivation.isActive`; a fabricated page
event without activation is refused, even if it claims a gesture. The new signed
native host adds a protocol marker after its caller check. The app independently
checks the signed peer. An old extension or host without both gesture provenance
and the host marker always takes the fresh path. Existing site, document, frame,
account, revision, peer, cancellation and response-erasure checks still apply.

## Revocation

Screen lock, system/display sleep, session resignation/fast user switch, app quit,
vault lock/switch/rekey/backup/restore, setting changes and failed/cancelled checks
revoke the window and issued reuse proofs. A late check cannot resurrect a revoked
window. A successful fresh fallback may start a new one.

A caller-checked native helper observes NSWorkspace sleep, display sleep and
session resignation, plus the distributed screen-lock notification. Distributed
events can only revoke. A CGSession snapshot must positively report on-console and logged-in, and the
kernel IORegistry root's `IOConsoleLocked` property must explicitly report false
before reuse. Current macOS omits the CGSession lock key when unlocked; absence
is never treated as unlocked. Missing/unknown registry state fails closed.
Sequenced 250 ms heartbeats, a two-second health bound, EOF, malformed messages,
sequence gaps and process loss revoke authority; a heartbeat gap cannot restore a
previous verification. The helper is killed and reaped when its owner is dropped.
Unlock notifications never grant authority. A fresh check also remains possible
when the observer is unavailable.

## Limits and validation boundary

Opting in reduces how often the owner's identity is checked. Someone controlling an
unlocked Mac or its trusted browser can exercise covered actions until revocation
or expiry. Browser automation can generate trusted browser events; `isTrusted`
does not prove a physical human or defeat full owner-account compromise. Browser
fills expose the filled password to the page as before. The native host and peer
checks still reject the caller/debug routes they previously rejected.

No iPhone source, remote signature policy, release version or production service
changes in this PR. Fixture tests are not signed-device acceptance. Native
Keychain round trips, physical Touch ID counts and real lock/sleep/user-switch
acceptance require an isolated signed app and synthetic vault; they are not claimed
from unit tests or the screenshot tour. The existing egui kit is light-only; dark
system appearance captures do not claim that this PR implements a dark theme.
