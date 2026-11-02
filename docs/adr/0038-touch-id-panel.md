# ADR 0038 — Touch ID in an Apassy panel

Date: 2026-11-02. Status: implemented, runtime validation pending.

The owner wants authentication to look like Apassy. On supported GUI sessions,
a small AppKit panel embeds Apple's `LAAuthenticationView`, attached to the same
`LAContext` before evaluating the biometric policy or keychain access control.
The panel supplies the purpose because Apple's view is non-textual. The
biometric check still happens through Apple's LocalAuthentication and Secure
Enclave; Apassy never receives fingerprint data. Keychain items retain their
current-device, current-biometric-set ACL. Broker owner proofs retain the exact
action and session binding described in ADR 0030.

A different app can draw a look-alike panel. Drawing it cannot read Apassy's
entitled keychain items or produce the broker's owner proof. No panel contains a
text field: the passphrase stays in the main Apassy window. Synthetic clicks can
only cancel or select the passphrase route; neither is biometric success. Titles
come from fixed Rust templates, never website or agent text. The existing reason
remains supporting detail and does not become a trusted title.

Cancel/Esc and Use Passphrase invalidate the context and close the panel. Return
does nothing. Kill-to-cancel closes the helper's windows with its process. The
helper reads stdin off main and handles requests sequentially on main, entering
the AppKit event loop for panel authentication only. Non-UI commands retain their
existing contract, including the long-running lifecycle command.

When embedded presentation is unavailable, the helper logs a data-free reason
and uses its previous system dialog. Keychain reads pre-evaluate equivalent
access control and prohibit a second dialog on the initial read; if the keychain
rejects the pre-evaluated context, a fresh system-context retry preserves unlock
availability without weakening the ACL. Physical Touch ID, non-activation,
accessibility, light/dark layout, and keychain context reuse need runtime review.
No release or runtime acceptance is asserted by this source change.
