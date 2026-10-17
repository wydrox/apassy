# Desktop credential use — F08 decision

Status: **accepted by the owner on 17 October 2026**: “Add authenticated Copy (Recommended)”, after reviewing the fresh-check, 30-second clearing and local pasteboard exposure described below. Implemented with passing synthetic authorization/clipboard tests and native-helper compilation. The temporary native app's Copy prompt and cancellation were checked; real Touch ID and pasteboard execution remain unverified. See the [validation ledger](main-flows-validation-2026-10-17.md) and [ADR 0027](../adr/0027-owner-desktop-copy.md).

Before this change, desktop intentionally copied only one-time codes. `src/desktop/clipboard.rs` stated: “A password or another secret value is never copied.” ADR 0021 §1 limited password release to owner reveal or browser fill; ADR 0023 explicitly added expiring, device-local copy on iPhone. The older product vision permitted owner copy. The accepted change below replaces the desktop restriction and aligns the implementation and contracts.

## Proposed owner action

Add a **Copy** action directly to each supported desktop secret field. Every copy requires a fresh Touch ID or vault-passphrase check bound to the exact item, field and revision. It does not require revealing the value first and cannot reuse a previous reveal/fill approval. Changed/deleted items, lock, vault switch or cancelled checks prevent the copy.

Use the macOS pasteboard with concealed/transient markers and remote-sharing exclusion where supported. Keep the copied value in an erasing buffer. Clear after 30 seconds and on lock/switch/quit only if the pasteboard still contains Apassy's exact write; preserve any later owner copy. Show a short Copied confirmation and inspectable expiry. Never log or persist the value. Keep passkey private keys unavailable to Copy.

This is deliberate disclosure: another local process may read the pasteboard during that interval. Concealed markers and expiration reduce exposure but cannot guarantee that another program has not retained the value. Broker, owner socket and automatic agent APIs still never return secrets; browser fills retain their own approval.

Implementation boundaries: add an exact-field owner action/proof and desktop handler, extend the existing tested pasteboard abstraction, expose per-field Copy in credential rows, and update the relevant ADR/operating contract. Synthetic tests must cover cancellation, wrong action/field/revision, expiry, lock/switch, later pasteboard writes and secret-free errors. No test writes real secrets or touches the user's live pasteboard.

## Alternative: retain the current clipboard restriction

For a login with a valid Website, put **Open Website** by the password and use the browser chooser/owner-approved fill. Missing Website has a direct Edit action and explanation. For other kinds, offer only genuinely implemented uses and retain owner reveal; do not show an inert “Use” button or pretend an agent setup step substitutes for human copy.

This alternative closes the login use route, but leaves deliberate manual use of generic tokens without direct Copy. Report that limitation explicitly rather than marking the entire friction point eliminated.
