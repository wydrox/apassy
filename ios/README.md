# iOS

The iPhone companion of Apassy ([ADR 0020](../docs/adr/0020-iphone-companion.md)). The wire is in [companion-v1](../docs/contracts/companion-v1.md).

| Folder | What it is |
| --- | --- |
| `ApassyCompanionKit` | A Swift package with everything except the screens: the wire client, the signing strings, the pairing link, the Secure Enclave keys, the pinned TLS check, the pairing store, and the text of a command as the owner reads it. It uses Apple frameworks only (Foundation, CryptoKit, Security, LocalAuthentication). |
| `ApassyCompanion` | The iPhone app in SwiftUI. It uses the kit. See "The app" below. |

## The kit

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

`ApassyCompanion` is a SwiftUI app for iOS 26 (iPhone only) with the Liquid Glass design. It has no third-party code. Its bundle ID is `com.wydrox.apassy.companion` and its name on the home screen is Apassy.

| Part | What it does |
| --- | --- |
| Pairing flow | A welcome screen, the QR scanner (VisionKit), the 6-digit code that the owner types on the Mac, and the end states: paired, closed by the Mac, expired, and "This link does not work". |
| Inbox | The runs that wait, then the open access requests, under a floating glass capsule with the state of the connection. A run opens in a sheet with every field and the buttons Deny, Approve, and Approve and remember. |
| Activity | The newest 50 entries of the activity log of the Mac. |
| Mac | The connection, the Mac, this iPhone, "Unpair this iPhone", and "Forget this Mac" when another device answers in place of the Mac. |

What the app does with what it sees:

- It asks the Mac for the inbox every 2 s while it is active, and stops in the background.
- It keeps the inbox and the activity in memory only, writes no log of commands, and covers its content with a window of its own whenever it is not active, so the app switcher and a sheet never show a command. The cover waits while the Face ID prompt or the camera permission dialog of the app is up, and it always shows in the background. The polling stops in the background only.
- The run sheet sends the digest of the run as the owner opened it. When the inbox shows another digest for the same run, the sheet shows the new run and keeps Approve off until the owner confirms that they read it.
- A key that cannot be used again (a changed Face ID enrollment) ends the pairing and shows the pairing flow with the reason. A failed Face ID match does not: the owner can try again.
- The glass buttons are in the floating bars (the pairing actions, and the actions of the run sheet), not in the content that scrolls.
- It offers no way to paste the pairing link, and registers no URL scheme: the code is scanned inside the app.

### Generate the project

The project is made by [XcodeGen](https://github.com/yonaskolb/XcodeGen) from `ApassyCompanion/project.yml`. The generated `ApassyCompanion.xcodeproj` and `Info.plist` are committed, as `native/ApassyKeychain/ApassyKeychain.xcodeproj` is. Run this after a change to `project.yml`:

```
cd ios/ApassyCompanion
xcodegen generate --spec project.yml
```

### Build

It needs Xcode 27. The app uses the local package `ApassyCompanionKit`. The build treats every warning as an error.

```
cd ios/ApassyCompanion
xcodebuild -project ApassyCompanion.xcodeproj -scheme ApassyCompanion \
  -destination 'generic/platform=iOS Simulator' -derivedDataPath /tmp/apassy-dd-app CODE_SIGNING_ALLOWED=NO build
xcodebuild -project ApassyCompanion.xcodeproj -scheme ApassyCompanion \
  -destination 'generic/platform=iOS' -derivedDataPath /tmp/apassy-dd-app CODE_SIGNING_ALLOWED=NO build
```

The tests of the models (the pairing flow and the session with the Mac) run on macOS, without a Simulator. They compile the same source files as the app:

```
cd ios/ApassyCompanion/ModelTests
swift test
```

The screens have no tests. They are checked by the build and by the `#Preview` of each view, which use synthetic data.

### Run on an iPhone

The Secure Enclave and Face ID exist only on a device, so an approval can only be tried on an iPhone with Face ID or Touch ID set up.

1. Open `ios/ApassyCompanion/ApassyCompanion.xcodeproj` in Xcode.
2. Select the target `ApassyCompanion`, then Signing & Capabilities. Select your team. `project.yml` sets no `DEVELOPMENT_TEAM`, and automatic signing makes the profile. To do it from the command line, add `DEVELOPMENT_TEAM=<your team ID>` to `xcodebuild`.
3. Connect the iPhone, select it as the destination, and run. If the bundle ID is taken for your team, change `PRODUCT_BUNDLE_IDENTIFIER` in Xcode.
4. On the iPhone, open Settings > General > VPN & Device Management, select your developer account, and select Trust. The iPhone also needs Developer Mode: Settings > Privacy & Security > Developer Mode.
5. The first time the app talks to the Mac, iOS asks for local network access. Allow it. If you refused, allow it in Settings > Privacy & Security > Local Network.

### Pair the iPhone

1. On the Mac, unlock Apassy and open Settings > iPhone companion. Turn on "Allow the iPhone app on this network". The iPhone and the Mac must be on the same Wi-Fi network.
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
