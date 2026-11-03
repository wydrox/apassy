# iOS

The iPhone app of Apassy: the vault on the iPhone ([ADR 0023](../docs/adr/0023-iphone-vault.md)), and the companion that approves agent runs ([ADR 0020](../docs/adr/0020-iphone-companion.md)). The wires are in [ios-core-v1](../docs/contracts/ios-core-v1.md) and [companion-v1](../docs/contracts/companion-v1.md).

| Folder | What it is |
| --- | --- |
| `ApassyCore` | The vault core: a Rust static library (crate `apassy-core`) with a JSON C interface over the vault and the relay sync code of the Mac app. `scripts/build-ios-core.sh` builds it as `ApassyCore/build/ApassyCore.xcframework` (not committed). |
| `ApassyVaultKit` | A Swift package. `ApassyVaultKit`: the typed calls of the core (`VaultService`), an in-memory vault for previews and tests, the Face ID passphrase store, the owner check, the local-only clipboard, and the QuickType identities. `ApassyVaultCore`: `VaultService` over the core. |
| `ApassyCompanionKit` | A Swift package with everything of the companion except the screens: the wire client, the signing strings, the pairing link, the Secure Enclave keys, the pinned TLS check, the pairing store, and the text of a command as the owner reads it. It uses Apple frameworks only (Foundation, CryptoKit, Security, LocalAuthentication). |
| `ApassyCompanion` | The iPhone app in SwiftUI, its AutoFill extension (`AutoFill/`), and the Apple Watch app (`Watch/`, target `ApassyWatch`, embedded in the iPhone app; it answers access requests only, [ADR 0039](../docs/adr/0039-apple-watch-access-requests.md)). See "The app" and "The Apple Watch" below. |

## The vault core

It needs Rust 1.97 with the targets `aarch64-apple-ios`, `aarch64-apple-ios-sim`, and `aarch64-apple-darwin` (the script adds them), and Xcode 27.

```
scripts/build-ios-core.sh                # iPhone, Simulator, macOS, Apple Watch, and watch Simulator
scripts/build-ios-core.sh device watch   # iPhone and Apple Watch only
cargo test -p apassy-core                # the calls of the contract, end to end
```

The watch slices (`watch`, `watchsim`, targets `aarch64-apple-watchos` and `aarch64-apple-watchos-sim`) are arm64 only and build SQLCipher with CommonCrypto (ADR 0039, section 4).

The tests drive the JSON calls as the app makes them. One test runs a Mac and an iPhone on the in-process fake relay of the Mac's tests (`tests/common/fake_relay.rs`): the iPhone joins with the device link and the safety words, the Mac confirms, and both sync changes to each other.

The Swift side over the real core runs on macOS:

```
cd ios/ApassyVaultKit
swift test
```

`CoreMultiVaultQuestionsTests` runs `ApassyCore/build/questions-macs` (from `examples/questions_macs.rs`, built with the `mac` slice): two fake Macs with two vaults on the fake relay. The iPhone joins both, lists and answers the questions of each with its `vault_id`, and opens the other vault again after a suspend with `questions_unlock`.

## The companion kit

It needs Xcode 27 (Swift 6.4). It builds for iOS 26 and macOS 15, and its tests run on macOS. No iOS simulator and no Secure Enclave are needed.

```
cd ios/ApassyCompanionKit
swift build
swift test
```

The tests use the vectors of contract section 9, the client with a scripted transport and with a URL protocol that captures requests, and a real TLS 1.3 server on the loopback interface with a throwaway certificate. The keychain tests write to the login keychain of the Mac and remove what they wrote.

To check the kit against the real Mac listener, run the interop check from the repository root. It builds the development server `examples/companion_dev.rs` and the driver `companion-interop` (a target of this package, for macOS), and lets the real client pair, read the inbox, approve, deny, and unpair over TLS with the pin. It uses a synthetic vault in a temporary directory and no real secret.

```
scripts/companion-interop.sh
```

It prints `companion-interop: PASSED` or `companion-interop: FAILED: <reason>`. See [the companion guide](../docs/operations/companion.md), section 9.

To check that the package compiles for a device, including the Secure Enclave code:

```
cd ios/ApassyCompanionKit
xcodebuild -scheme ApassyCompanionKit -destination 'generic/platform=iOS' -derivedDataPath /tmp/apassy-dd-kit build
```

The Secure Enclave keys are compiled out of a simulator build (`#if !targetEnvironment(simulator)`). A simulator build uses `SoftwareKeys`, and `CompanionKeyStore.usesSecureEnclave` is false so the screen can say so. The Secure Enclave code cannot run in `swift test`; a device is the only place that shows Face ID.

## Navigation titles

Use compact native navigation chrome. The root tabs do not repeat their tab names
as large headings:

- Requests starts with its actions toolbar, Waiting / History picker and list.
- Vault uses the active vault's name as a compact native menu with native toolbar sizing.
  Selecting another vault uses `VaultModel.select`: lock first, then the existing
  unlock screen. Never bypass owner authentication when switching from the toolbar.
- Search uses the native search field without an extra Search heading or introductory
  empty-state title. Keep search scoped to its own navigation stack.
- Folders, details, settings and forms use inline contextual titles and the native
  Back, Cancel or Done controls. Do not hide an entire navigation bar to remove a title.

Use system Liquid Glass navigation and controls; keep content on readable native
surfaces. Check Dynamic Type and native back navigation when changing these titles.
See [compact-header verification](../docs/product/ios-requests/compact-headers-2026-10-19.md).

## The app

`ApassyCompanion` is a SwiftUI app for iOS 26 (iPhone only) with the Liquid Glass design, and an AutoFill extension. It has no third-party code besides the vault core. Its bundle IDs are `com.wydrox.apassy.companion` and `com.wydrox.apassy.companion.autofill`, and its name on the home screen is Apassy.

### The vault (ADR 0023, ADR 0026)

For a personal vault, keep **iCloud Drive** selected on the Mac. On the iPhone, select **iCloud**, then select the matching `.apassy` file in **Files > iCloud Drive > Apassy**. Enter its passphrase. The app keeps an offline local vault and syncs changes in both directions while it is active and unlocked. iCloud does not need the companion QR code or a relay team. A "saved" result confirms the local iCloud file; receipt on another device needs a check on that device.

If file access expires, use "Select the iCloud file again" in Settings > Devices to select the same vault again. Removing the vault from the iPhone leaves its iCloud file. For an already connected vault, sync merges authenticated iCloud conflict versions and retains encrypted recovery copies before resolving the captured versions. Unreadable or incompatible versions stop publication; the provider versions stay intact. Importing or reconnecting a file with unresolved versions still requires resolving those versions first. Tap a sync problem above the credential list on the Vault tab to open Settings > Devices with the full status and recovery controls.

The unlocked app has three tabs: **Vault**, **Requests**, and **Search**. Vault opens the actual credential list. Settings is a sheet (the gear on Vault and Requests); **Agent Access** is a Settings destination and is also reachable from credential context. After connecting an iCloud vault, optional AutoFill setup offers Enable AutoFill and Later, and rechecks the actual iOS state when the app returns. Adding or importing credentials does not require connecting an agent.

| Part | What it does |
| --- | --- |
| Welcome and join | **iCloud** opens the personal vault file from iCloud Drive with its passphrase. **From your Mac · Apassy relay** uses the relay QR code from "Add a device…" on the Mac. Both offer Face ID unlock. "Only approve agent runs" goes to companion pairing. |
| Lock | With the passphrase stored behind Face ID, Face ID asks first over the cover of the app (the icon, as in the app switcher), so a launch or a return shows no form before the vault opens. The passphrase field, with the keyboard up and "Unlock with Face ID", shows only when Face ID did not open the vault or is off. Each return to the app tries Face ID first again. A new Face ID enrollment deletes the stored passphrase, and the screen asks for it. "Lock after": immediately (the default), 1, 5, 15 minutes, or 1 hour. |
| Vault tab | The nonarchived credential list, grouped by folder, with category/tag filters and sort. A sync problem and Watchtower issues remain above it; healthy sync and an empty Watchtower do not precede the list. Folders and tools in the toolbar opens folders, All credentials, Favorites, Archive, Watchtower, and Password generator. The gear opens Settings; New Credential adds a credential. An empty vault offers New Credential directly. |
| All credentials | Every credential that is not archived, grouped by folder as on the Mac (A to Z inside), with filters by kind and tag and a sort. |
| A folder | Its subfolders, then its credentials with provider tiles and a red dot for production. "⋯" or a swipe: new folder, rename, move, delete. Deleting a folder moves its credentials and subfolders to the parent; no credential is deleted. "+" adds a credential to the folder. |
| New Credential | Login, Paste, and Other entry points keep the selected folder. Login opens the normal username/password editor without agent setup. Paste detects a key, database URL, otpauth link, or .env batch, including QR scanning, and shows masked previews. Other chooses another kind. Failed saves retain the draft; a disappeared destination cannot silently redirect a save. The submitted snapshot is frozen while saving. Cancel or dismiss requires discarding unsaved changes and cannot pretend to cancel an in-flight save. A successful save shows the actual item and destination, returns to Vault, and opens the saved credential (or the saved batch folder). Sensitive paste buffers clear on foreground exit, cancellation, and vault lock. |
| A credential | The provider header, useful fields and actions, then passkey details, notes, real options, contextual Agent Access, tags, times, and history. A secret is masked: reveal, copy, a one-time code, and large type each need Face ID or the passphrase. Variable copies the name agents get; Folder moves the credential. Optional agent information no longer inserts unavailable placeholder sections. Always ask me and Environment retain their authority checks: less careful changes need Face ID or the passphrase, stricter changes do not. Edit, favorite, archive, and delete remain available; a website opens in Safari. |
| Edit | The full kind-specific form, Folder, custom details, tags, notes, generator, and one-time-password QR. A secret left empty keeps its stored value. A pending tag is included in the submitted snapshot. Unsaved changes require explicit discard, save failures retain the draft, and controls/dismissal cannot change or falsely cancel an in-flight submission. |
| Generator | Random, memorable (the EFF word list), or a PIN, with the strength. |
| Requests tab | Waiting work and outcomes; see “Requests” below. |
| Agent Access | Agent Access in Settings lists published Mac feeds for the unlocked vaults, grouped by Mac and by vault when needed (relay-feed-v1 and core feed_* calls). The feed runs while that Settings destination or its agent detail is visible and active, and stops on lock, suspend, or leaving it. The page shows permissions, exceptions, recent use, and From <Mac>, <time>; it does not claim a live connection merely because a feed exists. Stale provenance remains visible and disables actions. Removing an exception confirms the exact agent, credential, and Mac. Removing Never or Always ask signs the core's action string with the answer key of that vault's team after Face ID; removing an only-these-items entry needs no Face ID (the core signs it). The row reports Removed on <Mac> only after confirmation, or explains why the Mac did not apply it. Agent detail keeps names-only visibility, action restrictions, the read-only bouncer note, and provenance. Empty state directs the owner to Requests or Connect this iPhone, as applicable. |
| Search tab | Searches titles, usernames, tags, and websites. Archived credentials show in their own section. |
| Settings | Five destinations: Agent Access (permissions and exceptions), plus four groups. **General**: the vault (name or vault picker, "Add another vault", remove from this iPhone), "Move to another app" (import and export), and AutoFill. **Devices**: sync (service, state, last sync, "Sync now", team devices, "Select the iCloud file again", the new passphrase of the vault, "Use the relay copy"), questions through the relay, the Mac on Wi-Fi, the Apple Watch row (its state, and "Add Apple Watch" while it is not connected; see "The Apple Watch"), and "Open Requests". **Security**: "Unlock with Face ID", "Lock after", "Lock now", and "Clear copied secrets after". **Advanced**: the versions of the app and the vault core, and the licenses. |
| AutoFill | Logins, one-time codes, and passkeys in Safari and apps, after Face ID or the passphrase for each fill or sign-in. New passkeys are saved in a new login or in a login of the website. The QuickType bar shows usernames, hosts, and passkey accounts only. |
| Passkeys | A login holds at most one passkey (ES256). The credential shows its website, account, and the start of its ID. The ordinary screens never show or copy the key: it is not a field, so no reveal, copy, or large type shows it. After Face ID, the system export can move it to another app. A login with a password and a passkey offers "Remove passkey": Face ID, then the login keeps its fields. A login with a passkey and no password offers "Delete login" instead: removing the passkey of such a login deletes the entire item (notes, tags, websites, one-time passwords, custom details, history, and agent access) on this iPhone and, at the next sync, on the other devices. The dialog says this. To keep the data, add a password with Edit first, or archive the login. |
| Import and export | Apple's credential exchange (iOS 26): Settings > General > Move to another app exports logins, one-time passwords, and passkeys to an app that the owner picks in the sheet of iOS. To import, start the export in the other app (Passwords, 1Password) and pick Apassy. Both ask for Face ID first; the data goes app to app in memory, never to a file. |

What the app does with the vault:

- The vault, its sync state, and the list of vaults are in the App Group container, so the AutoFill extension reads them. The core opens the vault only while it is unlocked, and the app closes it when it leaves the screen (contract ios-core-v1, section 1).
- It syncs at unlock, at a return to the app, after each change, and when the relay or the iCloud file has a new version: a long poll of the relay, or a check every 5 s that asks iCloud for the latest version of the file, while the app is active. A failed sync is tried again. It never syncs in the background.
- A copy stays on this iPhone (no Universal Clipboard) and expires after the time in Settings (60 s by default).
- It drops a revealed value after 30 s and in the background, and covers its content whenever it is not active.
- It refuses keyboards of other apps (a third-party keyboard would see a pasted secret or a passphrase). The system keyboard stays.
- Folders, the paste detection, and the credential options need a core that has the calls of contract section 5.11. With an older core the screens show less (no folders, no Options group) and nothing fails.

### Requests (ADR 0026, ADR 0020)

The Requests tab has native **Waiting / History** destinations. Its badge counts waiting work, not unconfirmed outcomes. System navigation, segmented pickers, lists and menus inherit Liquid Glass; request content remains on readable native list surfaces.

| Part | What it does |
| --- | --- |
| Waiting | Relay questions and paired Mac Wi-Fi runs share a queue. Current routine non-production Read requests offer Deny / Allow Once after full visible context; production, unknown or elevated requests offer Deny / Review. Approval keeps the existing fresh owner signature. Wi-Fi runs require Review to grant. Access requests can only be denied on the phone. Submitted rows stay in place until Done. |
| Locked vaults | A lock or a suspend drops the questions of every vault, and a resume opens the selected vault only. Face ID never asks by itself. After an unlock and a resume, the other vaults whose passphrase is stored behind Face ID ("Unlock with Face ID" on for it) share one row: "Work, Family are locked. Unlock with Face ID to see their questions." One tap reads them all with one Face ID (`questions_unlock`). A Face ID unlock of the selected vault reads them in the same prompt: "Unlock Personal, and the questions of Work and Family". Any other vault with questions shows one row: "<vault> is locked. Unlock to see its questions." Its Unlock shows a passphrase sheet. The selected vault never gets a row. The sheet opens the questions only; the vault on screen does not change. Its field is cleared when the app leaves the screen. |
| History | Search and All / Allowed / Denied filters, date groups, read-only details and explicit per-vault clearing. Only relay requests observed on this iPhone are saved: 30 days from first observation, up to 1,000 entries per vault. Metadata is encrypted using a domain-separated vault question key and excluded from backups. Lock hides it; removal deletes it; corruption/key rotation requires explicit clearing. Unresolved live attempts cannot be cleared. Wi-Fi Activity stays separate. |
| Outcomes | A signed attempt, relay acceptance and verified Mac confirmation are separate facts. Attempt-only/restored unknown state is Not confirmed. Only a matching verified settle can report Allowed or Denied. Execution is never inferred. Live answer intent is saved before POST so a lock/restart cannot enable a different answer accidentally. |
| A question | The sentence, the facts, the command, and why the owner is asked. A fixed bar at the bottom has "Allow ACTION in PROJECT", "Deny", and "Allow Once". A production question shows a red "Allow production: ACTION in PROJECT". Its "⋯" menu holds the stricter answers and the environment of a credential. When the question has ended, the outcome takes the place of the bar. |
| Face ID | An answer that gives authority asks for Face ID, as the core decides. The stricter answers go without it. A changed Face ID enrollment makes a new answer key; the Mac removes the old device, and the owner connects this iPhone again. |
| Notification | The fixed text is only “A question is waiting”. Opening it selects Requests and refreshes the list. The payload has no vault or question identifier, so it never opens the newest question as if it were the announced one and never starts an unlock. Locked vault rows require an explicit owner action. A creation/edit draft remains intact if already open. |
| "⋯" menu | Connect this iPhone when available, and Mac on Wi-Fi (pairing, Activity, Mac). History has its own clear-history menu. |

While a refreshed, unlocked Requests list covers every vault, foreground pushes update it quietly. A detail, editor, Settings sheet, locked vault, or incomplete list does not suppress the alert. After a successful complete refresh with no waiting or unconfirmed question and no hidden locked vault, Apassy removes only the delivered request alerts captured before that refresh; a newly arrived alert is preserved. Generic APNs payloads remain unchanged.

### Mac on Wi-Fi (ADR 0020)

"Mac on Wi-Fi" in the "⋯" menu of Requests opens the companion: Inbox, Activity, and Mac in one sheet, with its own pairing on the local network. The runs of the paired Mac also show in Waiting.

| Part | What it does |
| --- | --- |
| Pairing flow | A welcome screen, the QR scanner (VisionKit), the 6-digit code that the owner types on the Mac, and the end states: paired, closed by the Mac, expired, and "This link does not work". |
| Inbox | The runs that wait, then the open access requests, under a floating glass capsule with the state of the connection. A run opens in a sheet with every field and the buttons Deny, Allow Once, and Allow and Remember. |
| Activity | The newest 50 entries of the activity log of the Mac. |
| Mac | The connection, the Mac, this iPhone, "Unpair this iPhone", and "Forget this Mac" when another device answers in place of the Mac. |

What the companion does with what it sees:

- It asks the Mac for the inbox every 2 s while it is active, and stops in the background.
- It keeps the inbox and the activity in memory only, writes no log of commands, and covers its content with a window of its own whenever it is not active, so the app switcher and a sheet never show a command. The cover waits while the Face ID prompt or the camera permission dialog of the app is up, and it always shows in the background. The polling stops in the background only.
- The run sheet sends the digest of the run as the owner opened it. When the inbox shows another digest for the same run, the sheet shows the new run and keeps the allow buttons off until the owner confirms that they read it.
- A key that cannot be used again (a changed Face ID enrollment) ends the pairing and shows the pairing flow with the reason. A failed Face ID match does not: the owner can try again.
- It offers no way to paste the pairing link, and registers no URL scheme: the code is scanned inside the app.

### The demo (every build)

"Try the Demo" lets App Review and new owners try the app without a Mac. It is a secondary button
on the first screen, and, when real vaults are on the iPhone, it is only in Settings > Advanced >
About. `-ApassyDemo` opens it at launch in every build (Simulator, TestFlight, App Store), for
screenshots: the real vaults stay closed until the owner leaves the demo.

- **What it is.** A vault "Demo" of synthetic data in memory (`ApassyVaultDemo`, `DemoVault` over
  `PreviewVaultService`): logins with websites and one-time codes (GitHub, Example Shop), a passkey
  (`demo.example.com`), API keys, an SSH key, a database, notes, folders, an archived item, a
  planted duplicate ("Netflix" and "Netflix (old)", and a conflict copy of GitHub), the agents of
  "Mac mini (demo)" and "MacBook Pro (demo)" with their uses, one waiting run question and one
  waiting access request from "Mac mini (demo)" (both wait 30 minutes from the start of the demo),
  and past decisions in History. The passphrase of the demo is `demo passphrase`; the lock screen
  and the passphrase prompt of the demo say so.
- **What it never touches.** No file, no App Group defaults, no keychain item, no Face ID
  frequency setting, no AutoFill identity (`ASCredentialIdentityStore`), no push registration, no
  relay, no iCloud, no network. The settings, the stored passphrase, and the answer key of the demo
  are in memory (`DemoSession`, `DemoAppSession`). The live root is built from an `AppWorld`; the
  demo gets it only for the pasteboard. The AutoFill extension does not link `ApassyVaultDemo`.
- **What works.** Reveal and copy (fake values, the normal owner check and clipboard expiry),
  ticking one-time codes, search, Watchtower, the generator, Find duplicates (Settings > General),
  Allow Once on the access request (the real Face ID prompt with the same reason text; the answer is
  signed with a key in memory and settles locally), Deny, the run question, Agent Access, and
  Settings. Pairing, the relay, Add Apple Watch, import and export, AutoFill setup, notifications,
  and the Face ID frequency say "Not available in the demo".
- **Leaving.** The banner "Demo — sample data only" stays above the screens and sheets of the
  demo. "Leave Demo" (in the banner, and in Settings > Advanced) drops the demo root with all its
  models and shows the first screen again, or the real vault where it was.
- **The watch.** A watch with no vault has "See a Sample": one synthetic access request of
  "Mac mini (demo)" with Allow once and Deny, answered in memory (`DemoWatch`). Allow once in the
  sample does not check the wrist: that check needs the key of a connected vault, and the sample
  says so. `-ApassyDemo` on the watch opens the sample at launch.

`-ApassyOpen <route>` (below) also works in the demo of every build. With `-ApassyDemo`, pass a
value to the flag when another flag follows it (`-ApassyDemo YES -ApassyOpen decisions`), so the
argument domain does not read the next flag as its value. The item ids of the demo:

| Id | Item |
| --- | --- |
| 100 | GitHub (login, website, one-time code, notes) |
| 101 | Stripe live key (API key, production) |
| 102 | OpenAI (API key) |
| 103 | Production Postgres (database, weak and reused password) |
| 104 | Deploy key (SSH key) |
| 105 | Netflix (login; duplicate of 111) |
| 106 | Wi-Fi at home (custom) |
| 107 | GitHub (conflict copy) |
| 108 | Old Heroku (archived) |
| 109 | Example Shop (login, website, one-time code) |
| 110 | Recovery notes (notes) |
| 111 | Netflix (old) (the planted duplicate) |
| 112 | Demo passkey (passkey) |

```
xcrun simctl launch booted com.wydrox.apassy.companion -ApassyDemo YES -ApassyOpen decisions
```

### Simulator launch arguments

A Simulator build (never a device build) takes these development aids:

| Argument | What it does |
| --- | --- |
| `-ApassyPreviewVault`, `-ApassyPreviewEmpty`, `-ApassyPreviewUnlocked` | The in-memory vault with synthetic items (passphrase `preview passphrase`), an empty iPhone, or the vault unlocked. |
| `-ApassyJoinLink <link>`, `-ApassyJoinPassphrase <passphrase>` | A join as if the code had been scanned, and the passphrase step. |
| `-ApassyUnlockPassphrase <passphrase>` | Unlock once at launch. |
| `-ApassyOpen <route>` | Open a screen. The routes are below. It works in the demo of every build too. |
| `-ApassyPasteDemo stripe\|env` | Fill New Credential with synthetic values that the preview vault detects: one Stripe key, or a `.env` with three lines. Use it with `-ApassyOpen newcredential`. |
| `-ApassyPreviewDecisions list\|detail\|vaults\|locked` | With `-ApassyPreviewVault`, give the preview vault synthetic questions and confirmed/unconfirmed history fixtures. Preview answer keys are ephemeral and never written to Keychain. `detail` explicitly opens the newest fixture question; real generic notification taps open the refreshed list. `vaults` adds the questions of a second vault, "Work". `locked` also adds a third vault, "Family", whose questions are locked; the preview passphrase opens them. |
| `-ApassyPreviewAgents list\|detail\|confirm\|stale\|restricted\|unverified\|othervault` | With `-ApassyPreviewVault`, give the preview vault the synthetic feeds of two Macs and two vaults. `detail` opens Claude Code on the Mac mini, `confirm` opens Codex and asks to remove its exception, `stale` opens the agent of a Mac that has not reported for three days, `restricted` opens the "only these items" agent of Work, `unverified` removes one of its rows and gets a settle that this iPhone cannot open, and `othervault` opens that agent of Work, a vault that is not selected, whose feed came after its keys were read: "Remove" reads them again first (the preview passphrase stands in for the one stored behind Face ID). Add `-ApassyPreviewAgentsScroll exceptions` (or `sees`) to scroll an agent's page to its exceptions (or to what it sees). |
| `-ApassyPairingLink <link>` | The companion pairing, as below. |

The `-ApassyOpen` routes:

| Route | Opens |
| --- | --- |
| `vault` | The Vault tab. |
| `items` or `all` | All credentials. |
| `watchtower` | Watchtower. |
| `folder:<uuid or name>` | A folder, with its parents pushed. |
| `newcredential` | New Credential. |
| `decisions`, `questions`, or `approvals` | The Requests tab; all three compatibility route names remain accepted. |
| `access:<request id>` | The detail of an access request in Requests, waiting or in History (the demo: `access:demo-81`, `access:demo-79`). |
| `agents` | Settings > Agent Access. |
| `settings` or `settings:general\|agents\|devices\|security\|advanced` | Settings, or one of its groups. |
| `generator` | The password generator. |
| `search:<text>` | The Search tab with the text. |
| `new:<kind>` | The editor for a new credential. The kinds are `login`, `api_key`, `ssh_key`, `database`, and `custom`. |
| `edit:<id>` | The editor for the credential with this id. |
| `item:<id>[:reveal\|:large\|:options]` | A credential; with its first secret revealed, in large type, or scrolled to Options (these three in the Simulator only). |

For a join with the real core, run a Mac on the fake relay of the tests, then launch the Simulator build with the link it prints:

```
cargo run -p apassy-core --example relay_mac -- synthetic-sim-pass
xcrun simctl launch booted com.wydrox.apassy.companion \
  -ApassyJoinLink '<the link>' -ApassyJoinPassphrase synthetic-sim-pass
```

### Passkeys and credential exchange

The AutoFill extension declares `ProvidesPasskeys`, `SupportsCredentialExchange`, and `SupportedCredentialExchangeVersions` (`1.0`); the app declares the activity `ASCredentialExchangeActivity` in `NSUserActivityTypes`, which iOS uses to open Apassy for an import.

- **Sign in.** The passkey sheet of iOS lists Apassy's passkeys for the website (`ASPasskeyCredentialIdentity`, published by the app at each unlock, save, and sync). The extension unlocks the vault for the request (Face ID with a new context, or the passphrase), finds the passkey by its credential ID, and the core signs. Without the sheet, iOS gets `userInteractionRequired`.
- **New passkey.** The extension checks the request before the vault opens: a 32-byte client data hash, a relying party, a user handle of 1 to 64 bytes, and ES256 in the algorithms (an empty list is the WebAuthn default). An exclude list that names a passkey of the vault answers `matchedExcludedCredential`. Large blob storage that the website requires fails with a reason; a preferred large blob and PRF are answered as not supported. A conditional registration is refused.
- **Import.** iOS opens the app with the import token. After the unlock and Face ID, the app reads the data with `ASCredentialImportManager`, keeps logins with a password or a passkey and their one-time passwords, normalizes each passkey key to PKCS#8 with CryptoKit, and refuses a passkey with PRF or large blob data (it would lose them). The result is counts only.
- **Export.** After Face ID, the export sheet of iOS (`ASCredentialExportManager`) picks the app; then the core's `credential_export` gives the logins with their passkey keys, and the app hands them to the system at once. If the vault locks while the owner picks the app (the sheet can send Apassy to the background), the export waits with nothing read: after the unlock, "Continue export" asks for Face ID again and uses the same pick. If iOS ended the pick in the meantime, the export fails with a message and the owner starts again.

Check on a device with synthetic accounts: a passkey on a test website (for example webauthn.io) in Safari, sign-in from the QuickType bar and from the passkey sheet, a second registration with the same account (refused), an import with two websites that share a credential ID (both appear in the QuickType bar), the removal of a passkey from a login with and without a password (the second deletes the login), an export to Passwords with a lock during the pick, and an import back.

### Check personal iCloud sync

Use a synthetic vault for these checks.

1. On the Mac, select iCloud Drive in Settings > General > Sync. Wait for the `.apassy` file in Files on the iPhone.
2. On the iPhone, select iCloud. Select that file and enter its passphrase.
3. Change a credential on the Mac. Check the new value on the iPhone after sync.
4. Change a different credential on the iPhone. Check the new value on the Mac after sync.
5. Disconnect the iPhone from the network. Check local unlock and AutoFill. Edit a credential, then reconnect and check both devices.
6. Edit the same credential differently on both devices before sync. Check the active item and the preserved conflict copy.
7. Change the passphrase on the Mac. Check the new-passphrase path and Face ID unlock on the iPhone.
8. Restart the iPhone app. Check that the bookmark still permits sync. Select the file again with "Select the iCloud file again" in Settings > Devices to check recovery.
9. Create divergent iCloud file versions of a connected synthetic vault. Sync on the iPhone, then check that both changes reach the Mac and that same-item conflicts remain as conflict copies. A damaged or different-vault version must leave provider versions unresolved. These provider checks are distinct from the local merge tests.
10. Remove the test vault from the iPhone. Check that its iCloud file and Mac vault remain.

Local core and adapter tests do not prove iCloud delivery, persistent file access on a physical iPhone, or Face ID behavior. These checks need the updated app on a physical device.

### Generate the project

The project is made by [XcodeGen](https://github.com/yonaskolb/XcodeGen) from `ApassyCompanion/project.yml`. The generated `ApassyCompanion.xcodeproj` and `Info.plist` are committed, as `native/ApassyKeychain/ApassyKeychain.xcodeproj` is. Run this after a change to `project.yml`:

```
cd ios/ApassyCompanion
xcodegen generate --spec project.yml
```

### Build

It needs Xcode 27. The app uses the local packages `ApassyCompanionKit` and `ApassyVaultKit`; build the vault core first (`scripts/build-ios-core.sh`). The build treats every warning as an error. A Simulator build is for Apple silicon only (the core has an arm64 Simulator slice).

```
scripts/build-ios-core.sh device sim
cd ios/ApassyCompanion
xcodebuild -project ApassyCompanion.xcodeproj -scheme ApassyCompanion \
  -destination 'generic/platform=iOS Simulator' -derivedDataPath /tmp/apassy-dd-app CODE_SIGNING_ALLOWED=NO build
xcodebuild -project ApassyCompanion.xcodeproj -scheme ApassyCompanion \
  -destination 'generic/platform=iOS' -derivedDataPath /tmp/apassy-dd-app CODE_SIGNING_ALLOWED=NO build
```

The tests of the models (the pairing flow, the session with the Mac, and the vault models: unlock and auto-lock, join, item details, the editor, the generator, the owner check, passkeys, and the credential exchange; and for v2 the decisions and the questions through the relay, the folder tree and folder changes, the credential options, the New Credential paste, and the older core that lacks the calls of contract section 5.11) run on macOS, without a Simulator, against the in-memory vault. They compile the same source files as the app:

```
cd ios/ApassyCompanion/ModelTests
swift test
```

The screens are checked by the build and by the `#Preview` of each view, which use synthetic data. A few checks of the tabs run in the Simulator (`UITests`, target `ApassyCompanionUITests`), with the synthetic preview vault only:

```
cd ios/ApassyCompanion
xcodebuild test -project ApassyCompanion.xcodeproj -scheme ApassyCompanion \
  -destination 'platform=iOS Simulator,name=iPhone 17' -derivedDataPath /tmp/apassy-dd-app
```

### Run on an iPhone

The Secure Enclave and Face ID exist only on a device, so an approval can only be tried on an iPhone with Face ID or Touch ID set up.

1. Open `ios/ApassyCompanion/ApassyCompanion.xcodeproj` in Xcode.
2. Select the target `ApassyCompanion`, then Signing & Capabilities. Select your team. `project.yml` sets no `DEVELOPMENT_TEAM`, and automatic signing makes the profile. To do it from the command line, add `DEVELOPMENT_TEAM=<your team ID>` to `xcodebuild`.
3. Connect the iPhone, select it as the destination, and run. If the bundle ID is taken for your team, change `PRODUCT_BUNDLE_IDENTIFIER` of both targets, the App Group in `project.yml`, and `SharedContainer.appGroup` in `ApassyVaultKit`. The App Group must be registered in the team: Xcode's Signing & Capabilities does it, `xcodebuild` does not.
4. On the iPhone, open Settings > General > VPN & Device Management, select your developer account, and select Trust. The iPhone also needs Developer Mode: Settings > Privacy & Security > Developer Mode.
5. The first time the app talks to the Mac, iOS asks for local network access. Allow it. If you refused, allow it in Settings > Privacy & Security > Local Network.

### Pair the iPhone

1. On the Mac, unlock Apassy and open Settings > Devices > iPhone. Turn on "Allow the iPhone app on this network". The iPhone and the Mac must be on the same Wi-Fi network or connected through Tailscale. For Tailscale, connect the Mac before you make the QR code. Existing pairings need a new pairing to store this address.
2. Select "Pair…". The Mac shows a QR code. It never puts the link on the pasteboard.
3. On the iPhone, open Apassy and go to Requests > "⋯" > Mac on Wi-Fi (an iPhone with no vault starts at the pairing flow with "Only approve agent runs"). Check the name of the iPhone, then select "Scan the code" and point the camera at the QR code. Approve the Face ID prompt: the approval key signs once, to prove that this iPhone holds it.
4. The iPhone shows a 6-digit code such as `348 942`. Type it in Apassy on the Mac and select Pair. The Mac then asks for Touch ID or your passphrase.
5. The iPhone says "Paired". Select Continue. Runs that wait show in the Inbox and in Waiting on the Requests tab.

If a companion QR is scanned in "Connect this iPhone" or the team-vault scanner, Apassy opens companion pairing and asks for Continue before Face ID and Mac confirmation. It does not connect that QR to the relay. Manage an existing companion pairing in Requests before pairing another Mac.

A wrong code pairs nothing, and three wrong codes close the window. If the iPhone says "This link does not work", another device may have used the link: select Cancel on the Mac and make a new code.

### The Simulator

The Simulator has no camera and no Secure Enclave. A Simulator build uses software keys in the keychain, and says "Simulator: keys are not in the Secure Enclave" on the welcome screen and in the Mac section of Mac on Wi-Fi. It is for development only.

Because the Simulator cannot scan, a Simulator build (never a device build) can start a pairing from a launch argument, as if the code had been scanned:

```
xcrun simctl launch booted com.wydrox.apassy.companion -ApassyPairingLink '<the link>'
```

The link is the text of the QR code. It is a secret for five minutes, so use a link of a Mac that you own and keep it out of shell history.

### The icon

`scripts/make-ios-icon.sh` renders `AppIcon.png` (1024x1024, no alpha channel) and the small `CoverIcon.png` of the privacy cover from `packaging/AppIcon.svg`, with `qlmanage` and `sips`. iOS masks the icon itself, so the script draws the mark across the whole square. Run it after a change to the SVG, and commit both files.

## The Apple Watch

`ApassyWatch` (bundle ID `com.wydrox.apassy.companion.watchkitapp`, watchOS 27, arm64 watches only) answers the access requests of ADR 0033 and nothing else: **Allow once** while the watch is unlocked on the wrist, or **Deny** ([ADR 0039](../docs/adr/0039-apple-watch-access-requests.md), [flow spec](../docs/product/apple-watch-access/flow-spec.md)). It never shows run questions, feed actions, or vault items, and holds no credential. The iPhone app embeds it as its Watch content.

| Part | What it does |
| --- | --- |
| Connect | The watch has no camera. Settings > Devices on the iPhone has an **Apple Watch** row: Not paired, Apassy not installed (with what the watch app needs: watchOS 27 on Series 9 or later, Ultra 2 or later, or SE 3), Not connected, Connected to "<vault>", or Removed by a Mac; the watch reports its connection with the WatchConnectivity application context (`WatchConnectionReport`). **Add Apple Watch** (shown while a paired watch is not connected; without Apassy on the watch it says what it needs, and the scan stays off) scans the Connect code of the Mac (Settings > Devices > Add an iPhone or a Mac…) and sends it to Apassy on the watch with WatchConnectivity; the watch must be open. The iPhone never uses or keeps the link. The watch makes its relay key and its answer key, shows the six safety words, and is connected once the owner confirms on the Mac with Touch ID. |
| Requests | The waiting access requests of the connected vault, newest first, with a long poll of the core while the app is active. Answered and expired rows stay 10 minutes with their outcome. Always On redacts every row. |
| Request | Every scope fact first (agent, credential, Mac, environment, delivery, action, hosts, project and folder, the reason, the host provenance, the expiry), then Allow once and Deny, then Exact identities. A request with an incomplete scope, or without Allow once, offers Deny only and says what is missing. After an answer: "Sent. Waiting for <Mac> to confirm.", "Not confirmed" after 60 s, or the confirmed outcome with a success haptic. No countdown and no automatic retry with a new signature. |
| This watch | The vault and the Macs that can ask, and Remove This Watch (with a confirmation): the core leaves the team and deletes the replica, and the watch deletes its keys and passphrase. Also remove the watch on the Mac. |

What the watch keeps (all `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`, never synchronized, in the keychain access group `com.wydrox.apassy.watch`):

- **The answer key**: one Secure Enclave P-256 key per questions team, with `.privateKeyUsage` and `.userPresence` (`WatchAnswerKeyPolicy`, the one place of the flags). Each Allow once evaluates a new `LAContext` with `.deviceOwnerAuthenticationWithWristDetection`, passes it to the signature, and invalidates it after the signature, a failure, the deadline, or the background. Deny is signed by the core with the relay key.
- **The replica passphrase**: 32 random bytes in b64u for the questions-only replica vault (no item, no sync). The replica opens when the app becomes active and suspends in the background; in the background a running check of the wrist is cancelled and the requests are dropped.

The relay HTTP of the core goes through URLSession on the watch (`URLSessionCoreTransport`, an ephemeral session with no cookie, cache, or credential storage; redirects are not followed). All watch calls of the core are in `ApassyVaultKit/Sources/ApassyVaultCore/WatchCoreService.swift`; the rules and the models, without UI, are in `ApassyVaultKit` (`WatchRequestRules`, `WatchRequestsModel`, `WatchAppModel`) with their tests in `ApassyVaultKitTests`.

Build (Xcode 27; the core needs its watch slices):

```
scripts/build-ios-core.sh watch watchsim device sim
cd ios/ApassyCompanion
xcodebuild -project ApassyCompanion.xcodeproj -scheme ApassyWatch -sdk watchsimulator \
  -destination 'generic/platform=watchOS Simulator' -derivedDataPath /tmp/apassy-dd-watch CODE_SIGNING_ALLOWED=NO build
```

The iPhone scheme builds and embeds the watch app too, so it needs the watch slices as well.

### Watch launch arguments

A Simulator or Debug build takes these development aids:

| Argument | What it does |
| --- | --- |
| `-ApassyWatchPreview <state>` | Synthetic data for screenshots, with in-memory keys and no core: `unpaired`, `failed` (the words did not match), `removed`, `words`, `connected`, `empty`, `requests`, `detail`, `denyonly`, `sent`, `notconfirmed`, `allowed`, `denied`, `expired`, `settings`. |
| `-ApassyWatchConnectLink <link>` | Start a connection with the real core as if the iPhone had sent the Connect code (the Simulator cannot scan). The link is a secret for its few minutes; use a code of a Mac that you own and keep it out of shell history. |

Every build also takes `-ApassyDemo`: the sample of "See a Sample" at launch, in memory only, with
no link to the iPhone.

```
xcrun simctl launch booted com.wydrox.apassy.companion.watchkitapp -ApassyWatchPreview detail
```

The Simulator has no Secure Enclave, no wrist, and no passcode: a Simulator build keeps a software answer key and the passphrase while unlocked (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`), and a pause stands in for the check of the wrist. Physical acceptance is still pending: the Secure Enclave key policy with wrist detection (`.userPresence` or `.devicePasscode`), the mirrored notification tap, LTE without the iPhone, and Always On redaction.

## TestFlight

`scripts/ios-testflight.sh` archives the app with its AutoFill extension and the Apple Watch app and uploads the build to App Store Connect. Xcode signs with automatic signing and makes the certificates and profiles it needs with the API key.

Once, in App Store Connect: Apps > + > New App, platform iOS, bundle ID `com.wydrox.apassy.companion` (the API cannot make the record). The bundle IDs `com.wydrox.apassy.companion`, `com.wydrox.apassy.companion.autofill` and `com.wydrox.apassy.companion.watchkitapp` are registered in team 7S3F9767BM. The watch app has no App Store Connect record of its own: it ships inside the iPhone app.

```
APASSY_TEAM=7S3F9767BM \
APASSY_NOTARY_KEY=~/.appstoreconnect/private_keys/AuthKey_<key id>.p8 \
APASSY_NOTARY_KEY_ID=<key id> APASSY_NOTARY_ISSUER=<issuer id> \
scripts/ios-testflight.sh
```

When the API key has no access to cloud-managed distribution certificates (the export says so), make App Store profiles with the "Apple Distribution" certificate of the Mac in App Store Connect (or through the API) for the three bundle IDs, install them, and name them in `APASSY_IOS_PROFILE`, `APASSY_IOS_AUTOFILL_PROFILE` and `APASSY_IOS_WATCH_PROFILE`: the export then signs manually. In team 7S3F9767BM they are "Apassy iOS App Store", "Apassy iOS AutoFill App Store" and "Apassy Watch App Store".

The build number is the minutes since 1970, so each run is higher than the last; the version is `MARKETING_VERSION` in `project.yml`. App Store Connect needs a few minutes to process a build. Internal testers of the team see it in TestFlight then. `--no-upload` writes the `.ipa` to `target/ios/export` instead.

The app and the watch app declare `ITSAppUsesNonExemptEncryption = YES` (owner, 2026-11-03; ADR 0023, section 8): the app has its own standard encryption (SQLCipher with OpenSSL, rustls, ring). Until Apple gives an `ITSEncryptionExportComplianceCode`, each processed build shows "Missing Compliance" and TestFlight holds it back from testers. Attach the app's encryption declaration to the build through the App Store Connect API (`appEncryptionDeclarations`, then its `builds` relationship), as [docs/store/app-store/export-compliance.md](../docs/store/app-store/export-compliance.md) section 2.2 describes. When the code exists, add it next to the flag in `project.yml` and later builds skip the step.

### Connect without an account

On the Mac, Settings > Devices > Get approvals on your iPhone creates a questions-only Connect connection. No operator code, paid sync, or account is required. Open the same vault from iCloud Drive on the iPhone, then Requests > Connect this iPhone; scan the Mac's code, compare the safety words and confirm on the Mac. Keep the Mac's pairing screen open while it sends the connection keys. The iPhone then offers Request Notifications and Open Requests. A reinstall needs a new code and confirmation; remove the previous iPhone in the Mac's Devices list.

Simulator UI fixtures accept `-ApassyConnectLink <synthetic link>` only together with `-ApassyPreviewVault`; the preview service simulates confirmation. These screenshots prove layout, not relay delivery, Face ID, or APNs. Local fake-relay Rust integration tests exercise the actual confirmed key transfer.

## App-wide Face ID window (2026-11-02)

The iPhone follows the global Mac owner-check decision: Settings > Security > Ask for
Face ID offers Every time (default), 1 minute, 5 minutes, 15 minutes, 1 hour, or
Until the iPhone locks. A change requires fresh biometry and is stored in the app's
device-only keychain, outside the synced vault and shared AutoFill settings.

Approval signatures, vault unlock, reveal and copy explicitly use one evaluated
`LAContext`. Key access controls remain unchanged (`biometryCurrentSet`, and
`privateKeyUsage` for the approval key). The system can still refuse an operation
or demand authentication. AutoFill receives no window and keeps fresh authentication
per fill. The context is invalidated on expiry, protected-data unavailability,
termination, setting change, enrollment change, and vault lock. Backgrounding alone
does not end it; an actual vault lock, including Lock after Immediately, does.

Residual risk: anyone holding the unlocked iPhone during the chosen window can
approve agent requests and see secrets in the app. Secure Enclave reuse of a
previously evaluated context across keys requires physical-device validation;
source inspection and unit tests cannot establish that iOS suppresses every prompt.

## Owner question answers

Relay command cards remain v1. Any unconfirmed item offers Allow as dev / Allow as prod;
otherwise Allow approves the request once. Dismiss and Dismiss with comment are always
available. Comments remove control scalars and U+2028/U+2029, keep the first 500 scalars,
then trim Unicode whitespace; empty comments send plain deny. The core signs the same
normalized comment it encodes. Approvals use the answer key through the Face ID window;
denials use the relay signing key. Legacy kinds remain decodable for older receipts but
are no longer offered for relay command questions. Wi-Fi companion runs retain their
legacy Allow Once / Allow and Remember / Deny controls because companion-v1 has no
environment classification or comment answer fields; access requests are unchanged.
