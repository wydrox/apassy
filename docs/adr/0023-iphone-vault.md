# ADR 0023 — The vault on the iPhone

Date: 2026-10-07.
Status: ACCEPTED in scope by the owner on 2026-10-07 ("build a companion app for iOS … like the 1Password iOS app, and add it to TestFlight"). The owner chose on the same day: the vault comes through the relay only (no iCloud file yet); copying is allowed, device-local and expiring; the TestFlight build declares that it uses exempt encryption only.

## Context

- The iPhone companion of [ADR 0020](0020-iphone-companion.md) approves runs on the local network. It never holds a secret, and it shows nothing when the Mac is away.
- The owner wants a password manager on the phone, like the 1Password app: the vault offline, search, a secret to read or copy, Password AutoFill in Safari and apps, one-time codes, new and edited items, a password generator, and a check of weak and reused passwords.
- The vault is SQLCipher, opened and merged by the Rust code of the Mac app (`src/vault`). Relay sync ([ADR 0022](0022-relay-sync.md)) already lets a new device join a vault: a device link, two safety words on both screens, the owner's confirmation on the Mac with Touch ID, and the passphrase. A second Mac is such a device.
- The browser extension of ADR 0021 set the rule for a human: a password leaves the vault only for a reveal in the app or a fill, and each fill needs Touch ID or the passphrase.

## Decision

### 1. The iPhone is a device of the vault, as a Mac is

The iPhone joins the vault's relay team with the existing flow of ADR 0022: the Mac shows "Add a device…" with the link as text and as a QR code; the iPhone scans it, both show the same two words, the owner confirms on the Mac with Touch ID, the iPhone downloads the copy and opens it with the passphrase. From then on it syncs through the relay like a Mac: the same merge by credential, the same signed heads and chain checks, the same "Use the relay copy" and new-passphrase paths. A vault that syncs through a folder switches to relay sync first. The iPhone does not open a file from iCloud Drive (open: an iCloud source later).

What does not sync stays as on a Mac (`vault::LOCAL_TABLES`): the iPhone has no agents, grants, rules, activity, or learning. It shows every credential of the vault, with its secret fields after the owner check.

### 2. The same code on the phone

The vault and the relay client run on the iPhone as a static library: `ios/ApassyCore` (crate `apassy-core`) links the `apassy` crate with the `vault` feature and offers a JSON C interface (contract [ios-core-v1](../contracts/ios-core-v1.md)). The Swift package `ios/ApassyVaultKit` wraps it. There is no second implementation of the schema, the merge, or the relay protocol, so a phone and a Mac cannot drift apart; they must run the same schema, as two Macs must. The library builds for the iPhone, the Simulator, and macOS (for `swift test`); SQLCipher keeps its vendored OpenSSL.

The C interface is the only `unsafe` code, in its own crate; the `apassy` crate keeps `forbid(unsafe_code)`.

### 3. The passphrase and Face ID

- The passphrase is the root key, as on the Mac (ADR 0003). Unlock with Face ID is optional: the app keeps the passphrase in the keychain with `.biometryCurrentSet` and `WhenPasscodeSetThisDeviceOnly`. It never leaves the iPhone, iCloud Keychain does not carry it, and a new Face ID enrollment or a removed passcode deletes it; the owner types the passphrase once more.
- The keychain item is in a group that the app and its AutoFill extension share. Nothing else reads it.
- Auto-lock: by default the vault locks when the app leaves the screen. With a longer time (1 minute to 1 hour), the core keeps the passphrase in an erasing buffer in the app's memory for that time, so the vault opens again without Face ID; a lock erases it.

### 4. A secret for a human, after a check each time

- Each reveal, copy, large-type view, or one-time code of a secret field needs a fresh Face ID match (no reuse window), or the passphrase when Face ID fails or is not set up. Plain fields (a username, a host, a website) need no check.
- A copy goes to the pasteboard of this iPhone only (`localOnly`), so Universal Clipboard never carries it to a Mac where an agent could read the pasteboard. It expires after 60 seconds by default (30 seconds to 5 minutes in Settings), and a secret is marked concealed.
- The app covers its content whenever it is not active, as the companion does, and drops revealed values in the background and after 30 seconds on screen.
- Each reveal is in the item's history ("Secret values shown"), as on the Mac. The history of reveals is local.

### 5. Password AutoFill

- The AutoFill extension fills a login, or a one-time code, after one owner check per request: Face ID reads the passphrase from the keychain, the vault opens, one credential goes to iOS, and the vault locks. Without Face ID the owner types the passphrase. iOS never gets a password without the check: the "fill without the sheet" request always asks for the sheet.
- For the QuickType bar the app gives iOS each login's username and website host, never a password, after each unlock and sync.
- A website matches the page when the hosts are equal, or one is a subdomain of the other and the shorter has at least two labels (`www.` is ignored, a port must be equal). There is no public suffix list: a website stored as a bare suffix such as `co.uk` would match every site under it. The owner sees the login and confirms each fill.
- The extension never syncs and never writes.

### 6. The vault file on the phone

- The vault, the sync state, and the vault list are in the App Group container (`Library/Application Support/Apassy`), so the extension can read them. The files have the default data protection of iOS on top of SQLCipher.
- The vault holds an exclusive lock on `<file>.lock` while it is open, and iOS ends a suspended app that holds a file lock in an App Group container. So the core opens the vault only while it is unlocked and closes it when the app leaves the screen (`suspend`). While the app shows the vault, the extension gets "busy" and says so.

### 7. Approvals stay

The companion of ADR 0020 is one tab of the app ("Approvals") and works as before, with its own pairing on the local network. A phone can pair for approvals without a vault, and hold a vault without approvals.

### 8. Distribution

TestFlight first (ADR 0020 D5 said a development build; the owner asked for TestFlight). Bundle IDs `com.wydrox.apassy.companion` and `.autofill`, team 7S3F9767BM, App Group `group.com.wydrox.apassy.companion`. `scripts/ios-testflight.sh` archives with automatic signing and an App Store Connect API key, and uploads. The build declares `ITSAppUsesNonExemptEncryption = NO` by the owner's decision.

## What this does not protect

- **A phone with the passphrase holds everything.** As a second Mac: a stolen, unlocked phone with an unlocked vault shows the item list; a secret still needs the owner's Face ID. A thief who knows the passphrase has the vault, as on a Mac. Remove the device on the Mac ("Devices…") and change the passphrase.
- **The passphrase in the keychain.** Face ID unlock trusts the Secure Enclave and iOS to keep it. Owners who do not want that leave Face ID unlock off and type the passphrase.
- **Memory.** Revealed values pass through Swift strings, which cannot be erased; the core erases its own buffers. Best effort, as on the Mac.
- **The pasteboard.** Another app on the iPhone can read a copy while it lasts (iOS shows a paste notice). Expiry limits the time.
- **Usernames and hosts in iOS.** The QuickType identities are stored by iOS outside the vault.
- **The relay** sees what it sees for a Mac (ADR 0022): ciphertext, sizes, times, device names.

## Open decisions

| # | Decision | Proposal |
| --- | --- | --- |
| D1 | A vault from iCloud Drive or another folder | Later: read-only first. |
| D2 | Passkeys in the vault and in AutoFill | Later: it needs a new item kind on the Mac too. |
| D3 | Favorites | On the iPhone only for now (not synced). A synced favorite needs a schema change. |
| D4 | The App Store | After TestFlight, with a privacy policy and the export classification reviewed. |
| D5 | Sign-up without an operator team code | ADR 0022 open question 1: today a vault reaches the relay with a team code from the operator. |
