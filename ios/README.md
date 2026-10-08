# iOS

The iPhone app of Apassy: the vault on the iPhone ([ADR 0023](../docs/adr/0023-iphone-vault.md)), and the companion that approves agent runs ([ADR 0020](../docs/adr/0020-iphone-companion.md)). The wires are in [ios-core-v1](../docs/contracts/ios-core-v1.md) and [companion-v1](../docs/contracts/companion-v1.md).

| Folder | What it is |
| --- | --- |
| `ApassyCore` | The vault core: a Rust static library (crate `apassy-core`) with a JSON C interface over the vault and the relay sync code of the Mac app. `scripts/build-ios-core.sh` builds it as `ApassyCore/build/ApassyCore.xcframework` (not committed). |
| `ApassyVaultKit` | A Swift package. `ApassyVaultKit`: the typed calls of the core (`VaultService`), an in-memory vault for previews and tests, the Face ID passphrase store, the owner check, the local-only clipboard, and the QuickType identities. `ApassyVaultCore`: `VaultService` over the core. |
| `ApassyCompanionKit` | A Swift package with everything of the companion except the screens: the wire client, the signing strings, the pairing link, the Secure Enclave keys, the pinned TLS check, the pairing store, and the text of a command as the owner reads it. It uses Apple frameworks only (Foundation, CryptoKit, Security, LocalAuthentication). |
| `ApassyCompanion` | The iPhone app in SwiftUI, and its AutoFill extension (`AutoFill/`). See "The app" below. |

## The vault core

It needs Rust 1.97 with the targets `aarch64-apple-ios`, `aarch64-apple-ios-sim`, and `aarch64-apple-darwin` (the script adds them), and Xcode 27.

```
scripts/build-ios-core.sh            # iPhone, Simulator, and macOS
scripts/build-ios-core.sh device     # iPhone only
cargo test -p apassy-core            # the calls of the contract, end to end
```

The tests drive the JSON calls as the app makes them. One test runs a Mac and an iPhone on the in-process fake relay of the Mac's tests (`tests/common/fake_relay.rs`): the iPhone joins with the device link and the safety words, the Mac confirms, and both sync changes to each other.

The Swift side over the real core runs on macOS:

```
cd ios/ApassyVaultKit
swift test
```

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

## The app

`ApassyCompanion` is a SwiftUI app for iOS 26 (iPhone only) with the Liquid Glass design, and an AutoFill extension. It has no third-party code besides the vault core. Its bundle IDs are `com.wydrox.apassy.companion` and `com.wydrox.apassy.companion.autofill`, and its name on the home screen is Apassy.

### The vault (ADR 0023)

| Part | What it does |
| --- | --- |
| Welcome and join | "Add your vault": on the Mac, Settings > General > Sync > "Add a device…" shows a QR code; the iPhone scans it (or pastes the link), names itself, shows the two safety words, waits for the Mac's confirmation, and asks the passphrase. Then it offers Face ID unlock. "Only approve agent runs" goes to the companion pairing. |
| Lock | The passphrase, or Face ID when the passphrase is stored behind it. A new Face ID enrollment deletes it, and the screen says so. "Lock after": immediately (the default), 1, 5, 15 minutes, or 1 hour. |
| Home | Favorites (on this iPhone only), recently changed items, the kinds with counts, the archive, a Watchtower card, and the sync state. |
| Items and Search | All items A to Z with an index, filters by kind and tag, sorting, and swipe actions (favorite, archive, copy). The search tab searches titles, usernames, tags, and websites. |
| An item | Each field in the Mac's order and labels. A secret shows as dots: reveal, copy, a one-time code, and large type each need Face ID or the passphrase. A website opens in Safari. Notes, tags, times, history, and a note on a conflict copy. Edit, favorite, archive, delete. |
| New and edit | A form for each kind (login, API key, SSH key, database, other), custom details, tags, notes, the password generator, and a one-time password from its QR code. A secret left empty keeps its stored value. |
| Generator | Random, memorable (the EFF word list), or a PIN, with the strength. |
| Watchtower | Weak, reused, and old passwords, and conflict copies. |
| Settings | Sync (state, "Sync now", devices, the new passphrase of the vault, "Use the relay copy"), removing the vault from this iPhone, another vault, Face ID unlock, lock and clipboard times, AutoFill, the companion, the version, and the licenses. |
| AutoFill | Logins and one-time codes in Safari and apps, after Face ID or the passphrase for each fill. The QuickType bar shows usernames and hosts only. |

What the app does with the vault:

- The vault, its sync state, and the list of vaults are in the App Group container, so the AutoFill extension reads them. The core opens the vault only while it is unlocked, and the app closes it when it leaves the screen (contract ios-core-v1, section 1).
- It syncs at unlock, after each change, and when the relay has a new version (a long poll while the app is active). It never syncs in the background.
- A copy stays on this iPhone (no Universal Clipboard) and expires after the time in Settings (60 s by default).
- It drops a revealed value after 30 s and in the background, and covers its content whenever it is not active.

### Approvals (ADR 0020)

The Approvals tab is the companion: Inbox, Activity, and Mac in one screen, with its own pairing on the local network.

| Part | What it does |
| --- | --- |
| Pairing flow | A welcome screen, the QR scanner (VisionKit), the 6-digit code that the owner types on the Mac, and the end states: paired, closed by the Mac, expired, and "This link does not work". |
| Inbox | The runs that wait, then the open access requests, under a floating glass capsule with the state of the connection. A run opens in a sheet with every field and the buttons Deny, Approve, and Approve and remember. |
| Activity | The newest 50 entries of the activity log of the Mac. |
| Mac | The connection, the Mac, this iPhone, "Unpair this iPhone", and "Forget this Mac" when another device answers in place of the Mac. |

What the companion does with what it sees:

- It asks the Mac for the inbox every 2 s while it is active, and stops in the background.
- It keeps the inbox and the activity in memory only, writes no log of commands, and covers its content with a window of its own whenever it is not active, so the app switcher and a sheet never show a command. The cover waits while the Face ID prompt or the camera permission dialog of the app is up, and it always shows in the background. The polling stops in the background only.
- The run sheet sends the digest of the run as the owner opened it. When the inbox shows another digest for the same run, the sheet shows the new run and keeps Approve off until the owner confirms that they read it.
- A key that cannot be used again (a changed Face ID enrollment) ends the pairing and shows the pairing flow with the reason. A failed Face ID match does not: the owner can try again.
- It offers no way to paste the pairing link, and registers no URL scheme: the code is scanned inside the app.

### Simulator launch arguments

A Simulator build (never a device build) takes these development aids:

| Argument | What it does |
| --- | --- |
| `-ApassyPreviewVault`, `-ApassyPreviewEmpty`, `-ApassyPreviewUnlocked` | The in-memory vault with synthetic items (passphrase `preview passphrase`), an empty iPhone, or the vault unlocked. |
| `-ApassyJoinLink <link>`, `-ApassyJoinPassphrase <passphrase>` | A join as if the code had been scanned, and the passphrase step. |
| `-ApassyUnlockPassphrase <passphrase>` | Unlock once at launch. |
| `-ApassyOpen <route>` | Open a screen: `items`, `watchtower`, `approvals`, `settings`, `generator`, `search:<text>`, `new:<kind>`, `edit:<id>`, `item:<id>[:reveal|:large]`. |
| `-ApassyPairingLink <link>` | The companion pairing, as below. |

For a join with the real core, run a Mac on the fake relay of the tests, then launch the Simulator build with the link it prints:

```
cargo run -p apassy-core --example relay_mac -- synthetic-sim-pass
xcrun simctl launch booted com.wydrox.apassy.companion \
  -ApassyJoinLink '<the link>' -ApassyJoinPassphrase synthetic-sim-pass
```

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

The tests of the models (the pairing flow, the session with the Mac, and the vault models: unlock and auto-lock, join, item details, the editor, the generator, the owner check) run on macOS, without a Simulator, against the in-memory vault. They compile the same source files as the app:

```
cd ios/ApassyCompanion/ModelTests
swift test
```

The screens have no tests. They are checked by the build and by the `#Preview` of each view, which use synthetic data.

### Run on an iPhone

The Secure Enclave and Face ID exist only on a device, so an approval can only be tried on an iPhone with Face ID or Touch ID set up.

1. Open `ios/ApassyCompanion/ApassyCompanion.xcodeproj` in Xcode.
2. Select the target `ApassyCompanion`, then Signing & Capabilities. Select your team. `project.yml` sets no `DEVELOPMENT_TEAM`, and automatic signing makes the profile. To do it from the command line, add `DEVELOPMENT_TEAM=<your team ID>` to `xcodebuild`.
3. Connect the iPhone, select it as the destination, and run. If the bundle ID is taken for your team, change `PRODUCT_BUNDLE_IDENTIFIER` of both targets, the App Group in `project.yml`, and `SharedContainer.appGroup` in `ApassyVaultKit`. The App Group must be registered in the team: Xcode's Signing & Capabilities does it, `xcodebuild` does not.
4. On the iPhone, open Settings > General > VPN & Device Management, select your developer account, and select Trust. The iPhone also needs Developer Mode: Settings > Privacy & Security > Developer Mode.
5. The first time the app talks to the Mac, iOS asks for local network access. Allow it. If you refused, allow it in Settings > Privacy & Security > Local Network.

### Pair the iPhone

1. On the Mac, unlock Apassy and open Settings > iPhone companion. Turn on "Allow the iPhone app on this network". The iPhone and the Mac must be on the same Wi-Fi network or connected through Tailscale. For Tailscale, connect the Mac before you make the QR code. Existing pairings need a new pairing to store this address.
2. Select "Pair an iPhone". The Mac shows a QR code. It never puts the link on the pasteboard.
3. On the iPhone, open Apassy. Check the name of the iPhone, then select "Scan the code" and point the camera at the QR code. Approve the Face ID prompt: the approval key signs once, to prove that this iPhone holds it.
4. The iPhone shows a 6-digit code such as `348 942`. Type it in Apassy on the Mac and select Pair. The Mac then asks for Touch ID or your passphrase.
5. The iPhone says "Paired". Select Continue. Runs that wait show in the Inbox.

A wrong code pairs nothing, and three wrong codes close the window. If the iPhone says "This link does not work", another device may have used the link: select Cancel on the Mac and make a new code.

### The Simulator

The Simulator has no camera and no Secure Enclave. A Simulator build uses software keys in the keychain, and says "Simulator: keys are not in the Secure Enclave" on the welcome screen and in the Mac tab. It is for development only.

Because the Simulator cannot scan, a Simulator build (never a device build) can start a pairing from a launch argument, as if the code had been scanned:

```
xcrun simctl launch booted com.wydrox.apassy.companion -ApassyPairingLink '<the link>'
```

The link is the text of the QR code. It is a secret for five minutes, so use a link of a Mac that you own and keep it out of shell history.

### The icon

`scripts/make-ios-icon.sh` renders `AppIcon.png` (1024x1024, no alpha channel) and the small `CoverIcon.png` of the privacy cover from `packaging/AppIcon.svg`, with `qlmanage` and `sips`. iOS masks the icon itself, so the script draws the mark across the whole square. Run it after a change to the SVG, and commit both files.

## TestFlight

`scripts/ios-testflight.sh` archives the app with its AutoFill extension and uploads the build to App Store Connect. Xcode signs with automatic signing and makes the certificates and profiles it needs with the API key.

Once, in App Store Connect: Apps > + > New App, platform iOS, bundle ID `com.wydrox.apassy.companion` (the API cannot make the record). The bundle IDs `com.wydrox.apassy.companion` and `com.wydrox.apassy.companion.autofill` are registered in team 7S3F9767BM.

```
APASSY_TEAM=7S3F9767BM \
APASSY_NOTARY_KEY=~/.appstoreconnect/private_keys/AuthKey_<key id>.p8 \
APASSY_NOTARY_KEY_ID=<key id> APASSY_NOTARY_ISSUER=<issuer id> \
scripts/ios-testflight.sh
```

When the API key has no access to cloud-managed distribution certificates (the export says so), make App Store profiles with the "Apple Distribution" certificate of the Mac in App Store Connect (or through the API) for both bundle IDs, install them, and name them in `APASSY_IOS_PROFILE` and `APASSY_IOS_AUTOFILL_PROFILE`: the export then signs manually. In team 7S3F9767BM they are "Apassy iOS App Store" and "Apassy iOS AutoFill App Store".

The build number is the minutes since 1970, so each run is higher than the last; the version is `MARKETING_VERSION` in `project.yml`. App Store Connect needs a few minutes to process a build. Internal testers of the team see it in TestFlight then. `--no-upload` writes the `.ipa` to `target/ios/export` instead.

The app declares `ITSAppUsesNonExemptEncryption = NO` (ADR 0023, section 8), so a build needs no export compliance answer.
