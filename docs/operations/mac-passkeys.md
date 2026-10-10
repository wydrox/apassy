# Mac passkeys: the AutoFill credential provider

Date: 2026-10-09.
Host: macOS 27.0, Xcode 27.0 (27A266a), MacOSX27.0.sdk, Swift 6.4. Deployment target macOS 15.0.
Scope: the native side of the Mac credential provider (passkeys, passwords, one-time codes). The app side is `src/desktop/passkey_socket.rs`.
Branch: `feat/passkeys-totp`, version 0.4.1, not released. Package checks below are at `11ca5b6`; the passkey flag correction is at `1ad43fb`. Status of the checks: [Checks on a Mac](#checks-on-a-mac-2026-10-09).
This document does not open the real-secret gate.

## What this is

macOS asks a credential provider extension for passkeys in Safari, in native apps, and in the system passkey sheet of Chrome. It also asks for passwords and one-time codes.
Apassy's provider is `ApassyAutoFill.appex`. It holds no key and no vault.
For each request it asks the Apassy app through a small Swift program, the credential bridge.
The app runs a fresh owner check (Touch ID or the passphrase) before it signs, saves, or fills.

The Rust crate forbids unsafe code. So the socket, the peer check, and every AuthenticationServices call live in Swift.

## Bundle layout

| Path in `Apassy.app/Contents` | Program | Signing ID | Entitlements |
| --- | --- | --- | --- |
| `PlugIns/ApassyAutoFill.appex` | the extension (`native/ApassyAutoFill`) | `com.wydrox.apassy.autofill` | `packaging/ApassyAutoFill.entitlements`: sandbox, AutoFill, app group. Needs a profile |
| `MacOS/apassy-credential-bridge` | the bridge (`native/ApassyCredentialBridge`) | `com.wydrox.apassy.credential-bridge` | `packaging/ApassyCredentialBridge.entitlements`: app group only. No profile |
| `MacOS/apassy` | the app | `com.wydrox.apassy` | `packaging/ApassyProvider.entitlements`: AutoFill. Needs a profile |

The app group `7S3F9767BM.com.wydrox.apassy` carries the team prefix. On macOS it needs no portal registration, and macOS 15 container protection lets programs of the same team use it.
The bridge has no AutoFill entitlement. A second executable in `Contents/MacOS` does not get the profile of the app ([native-app.md](native-app.md), evidence C1). The bridge does not need the entitlement: it never touches the identity store.

Without both profiles, the app ships no extension and keeps the empty `packaging/Apassy.entitlements`. A restricted entitlement without its profile makes AMFI stop the program at launch.

## Trust chain

```
Safari / app / Chrome --(macOS checks the origin)--> ApassyAutoFill.appex (sandboxed)
   --Unix socket, group container bridge/cp.sock (0700 / 0600)--> apassy-credential-bridge
   --stdin/stdout JSON lines--> Apassy app (Rust): fresh owner check, then Vault::sign_passkey / create_passkey
```

- **The bridge checks its parent once at start**, with the rule of `native/ApassyHelper/Caller.swift`. The parent is not launchd, and its audit token gives code that meets `anchor apple generic and identifier "com.wydrox.apassy" and certificate leaf[subject.OU] = "7S3F9767BM"`. The parent must also be the `.app` that contains the bridge, and the same process after the check. If any check fails, the bridge exits with `caller_not_allowed`.
- **The bridge checks each socket peer.** It reads the audit token with `LOCAL_PEERTOKEN`, and `LOCAL_PEERPID` must match the token. The peer must run as the same user, and its code must meet the requirement for `com.wydrox.apassy.autofill` of the same team. Its code path must be `<the same Apassy.app>/Contents/PlugIns/ApassyAutoFill.appex`. A peer that fails is closed with no answer, and the app sees nothing. The bridge never trusts a user ID alone, or a pid that a request names.
- **The extension checks the server.** The listener must be `com.wydrox.apassy.credential-bridge` of the same team, at `Contents/MacOS/apassy-credential-bridge` of its own Apassy.app. Another program on the socket gets nothing.
- **The server check needs a read of the bridge file.** `SecCodeCopyGuestWithAttributes` must read `Contents/MacOS/apassy-credential-bridge` from inside the sandbox of the extension. On macOS 27.0 the sandbox profile allows reads under `/Applications` and denies them under `/private/tmp`. For an app in `/tmp`, the call fails with error 100001 (`EPERM`), and the extension fails closed with `bridgeRefused`. The same signed bridge passes the check outside the sandbox. So the native peer check needs the app under `/Applications`. macOS still registers a provider from other places (it registered a copy in `/tmp`), so a registration alone says nothing about the peer check.
- **Provenance comes from the bridge.** The bridge adds `peer` to each request. It refuses any field that a call does not take, such as `verified` or `peer`, and it forwards a re-encoded copy of the checked fields.
- **The app decides on the owner check by the call, never by a request field.** The RP ID comes from macOS, which checked the origin or the associated domains.

## Protocol

The implemented envelope is in `native/ApassyCredentialBridge/BridgeWire.swift` (header comment). Limits: a request frame of up to 64 KiB, an answer frame of up to 1 MiB, and an answer within 180 s.

- Socket: one connection per request. The frame is a 4-byte big-endian length, then JSON.
- Bridge to app: `ready`, `request {rid, owner_check, peer, payload}`, `cancel {rid, reason}`, `error`.
- App to bridge: `response {rid, result}`, `shutdown`.

When the extension closes its connection, the app gets `cancel` (`peer_closed`). This happens when the owner closes the sheet, or when macOS ends the request. The app then closes its owner dialog and signs nothing. The bridge drops a late answer.

| Call | Owner check | App answer (`handle_platform`) |
| --- | --- | --- |
| `passkey_list {rp_id, allowed}` | no | `{passkeys}`: metadata |
| `passkey_assert {id, rp_id, credential_id, client_data_hash}` | yes | the assertion |
| `passkey_register {rp_id, user_name, user_display_name, user_handle, client_data_hash, algorithms, excluded, attach_id?, attach_revision?, title}` | yes | the new passkey |
| `autofill_list {domains}` | no | `{matches, others}`: logins with a password, metadata only (up to 16 domains) |
| `autofill_credential {id}` | yes | `{username, password}`. A login without a password answers `not_found` |
| `autofill_code {id}` | yes | `{code, remaining}`, from the first one-time password of the login |
| `credential_identities {}` | no | `{identities, passkeys, totp}`: metadata only |

Any other call answers `unsupported`: no import, no removal, and no export of a key or a seed through the sheet.
The three calls without an owner check return no password, seed, or key. A fill is recorded in the history of the login as "macOS AutoFill", with no value.

### App routing

The app routes all seven calls (`src/desktop/passkey_socket.rs`, `handle_platform`). An earlier version of this document said that it routed only the three passkey calls. That is no longer true.

What the build declares:

- `native/ApassyAutoFill/Info.plist` (source) declares `ProvidesPasskeys`, `ProvidesPasswords`, `ProvidesOneTimeCodes`, and `ShowsConfigurationUI`. It has no `SupportsConditionalPasskeyRegistration` and no `SupportsCredentialExchange`.
- `scripts/build-credential-provider.sh` deletes `ProvidesPasswords` and `ProvidesOneTimeCodes` from the built plist unless it gets `--with-passwords-and-codes`. Run directly without the flag, it builds a passkeys-only extension, and it fails if the built plist does not match the flag. It always fails if `SupportsConditionalPasskeyRegistration` or `SupportsCredentialExchange` is present.
- `scripts/build-app.sh` passes `--with-passwords-and-codes` and fails unless the provider status says `passkeys, passwords, one-time codes`. So a signed app with both profiles offers all three.
- Mac Credential Exchange is not implemented. The Info.plist has no `SupportsCredentialExchange`, and the script checks for its absence.

## Behaviour of the extension

- **Never without the sheet.** `provideCredentialWithoutUserInteraction` and the conditional registration always cancel with `userInteractionRequired`. `Info.plist` has no `SupportsConditionalPasskeyRegistration` and no `SupportsCredentialExchange`.
- **Sign-in.** The sheet lists the passkeys of the RP that match the allow list. The owner picks one, and the sheet says "Confirm in Apassy" and opens Apassy. Before the extension hands an answer to macOS, it checks the answer: the same credential ID, `rpIdHash == SHA256(rp_id)`, the UP, UV, BE, and BS flags, and the sizes. The corrected registration check parses the exact `none` attestation object and checks its credential ID and flags before the OS handoff.
- **Passwords and one-time codes.** The sheet lists the logins from `autofill_list` (website matches first, then the others), or a single identity that the owner picked in the system list. The fill sheet says "Confirm in Apassy". The app opens its own owner check for exactly that login (and code field). Then it returns the password or the code. A login that signs in with a passkey only never fills a password.
- **New passkey.** It needs ES256 (`-7`), and it refuses a large blob with support `required`. The excluded credentials go to the app, which answers `excluded` after the owner check. The extension then cancels with `matchedExcludedCredential`. The passkey is saved as a new login, or added to a login of the RP when the app sends `revision` in `autofill_list`.
- **Not running, or locked.** The sheet says "Open Apassy" or "Unlock your vault". It opens Apassy once and tries again every 2 s for up to 180 s. It never keeps a secret, a key, or a seed between requests.
- **Errors.** Cancel or a failed owner check gives `userCanceled`. A missing item gives `credentialIdentityNotFound`. Any other error shows a message, then `failed`.
- There is no LocalAuthentication check in the extension. The owner check runs once, in the app.

## Identity store and turning AutoFill on

Only a program with the AutoFill entitlement of this provider can write `ASCredentialIdentityStore`: the extension, or the containing app. The Rust app cannot call the store.
So the extension replaces the whole list from `credential_identities` in two cases: at the start of each request, and when the owner turns AutoFill on (`ShowsConfigurationUI`). The list holds all passkeys, not only those of one RP, plus the logins and the one-time-code logins. It is metadata only.
The app cannot start a refresh, so a new passkey shows up in the system suggestions after the next run of the provider.
The app routes `credential_identities`, so the store is filled at those two moments. If the store is empty or old, the owner still picks Apassy in the passkey sheet. The store writes only if AutoFill is turned on for Apassy in System Settings.

`ASSettingsHelper` must be called from the containing app, which is Rust. The Settings tab can open System Settings > General > AutoFill & Passwords instead. Check the URL on a device.

## Build

```
scripts/build-credential-provider.sh                   # unsigned; checks the bundle layout
scripts/build-credential-provider.sh --test            # + synthetic tests (157)
scripts/build-credential-provider.sh --sign "Apple Development" --test
                                                       # + signed probe of the code checks
scripts/build-credential-provider.sh --sign "Developer ID Application" \
  --appex-profile A.provisionprofile --app-profile B.provisionprofile --require-provider
```

The output goes to `target/credential-provider/`, with the reason in `provider-status.txt`.
The script checks each profile:

- it is for macOS
- it is for the team `7S3F9767BM` and the exact App ID (no wildcard)
- it has the AutoFill key
- it has not expired
- it contains the signing certificate
- it includes this Mac, unless it provisions all devices

After signing, the script verifies the identifier, the team, the hardened runtime, the entitlements (exact match), and the absence of forbidden entitlements.
A release bridge must not contain `APASSY_BRIDGE_DEV`, and the script checks for it.

`scripts/build-app.sh` integration (root):

1. Copy the extension to `Contents/PlugIns/` and the bridge to `Contents/MacOS/`.
2. Embed the app profile as `Contents/embedded.provisionprofile`.
3. Sign in this order: extension, bridge, other helpers, app (with `entitlements/Apassy-provider.entitlements`).
4. Update the checks for "8 programs" and "no entitlements".

Check the registration with `pluginkit -m -p com.apple.authentication-services-credential-provider-ui`. macOS also registers the provider of an app in another place, such as `/tmp`, and a stale registration of a removed test copy can stay in the list: remove it before a check. The registered provider in `/tmp` did not work: the sandboxed extension could not read the bridge there (see the trust chain). Install the app under `/Applications` for the native peer check.

## Profile prerequisites (owner, in the developer portal)

1. An explicit macOS App ID `com.wydrox.apassy` with AutoFill Credential Provider.
2. An App ID `com.wydrox.apassy.autofill` with AutoFill Credential Provider.
3. Two Developer ID provisioning profiles for these App IDs, made with the existing Developer ID certificate. For local runs, also development profiles that include this Mac.

None of this needs an App Store step. The app group needs no portal work.

## Tests

- Synthetic (`Tests/main.swift`, `Tests/AppexWireTests.swift`):
  - frames and their limits
  - every field rule of every call
  - refusal of `verified` and `peer`
  - the shapes of the app's lines
  - a round trip through the development bridge, with modes 0700 and 0600
  - cancel on close, and dropping a late answer
  - timeout, a busy second bridge, a stale socket, a file in the way
  - answers above 1 MiB
  - refusal of an unsigned peer
  - the extension's checks of answers and its error mapping
- Signed probe (`Tests/SignedProbe`, a fake `Apassy.app` at a separate path, removed and unregistered after the run). It uses the real checks, with only the container path overridden:
  - the bridge accepts its signed parent
  - it accepts the signed extension, and the provenance names the right pid and path
  - it refuses the same identifier at another path
  - it refuses another identifier inside the app
  - it refuses another identifier at the right path
  - it refuses an unsigned parent, and a signed parent outside its bundle
  - the extension refuses a server that is not the signed bridge

The original signed probe signs its fake extension without entitlements, so it cannot detect the `/tmp` sandbox read denial. A separate sandbox stage uses only the App Sandbox and shared app-group entitlements. It gives each run a unique probe identity and uses a test-only bridge peer override; the production client check stays intact. Each sandbox client must also fail to open an existing synthetic file outside its sandbox. This tests the sandboxed client's bridge check, not a real ExtensionKit launch with restricted AutoFill entitlements.

The corrected stage passed locally on 2026-10-10: 157 native tests and 61 signed-probe checks, no failures or warnings. The client accepted the bridge under `/Applications` and refused it under `/private/tmp` and `target/` with EPERM and code-check error 100001. Normal cleanup left no test files; the shared container, its contents, and the real bridge socket stayed intact. Cleanup can remove only the run's uniquely named folders; it never removes the whole shared group container. Waits in the probe and cleanup have deadlines. SIGKILL or power loss can leave test folders behind.

The separate interruption test stopped during signing at a possible keychain prompt, before reaching the sandbox stage. Cleanup of that signing interruption passed; SIGTERM cleanup of the sandbox stage is still untested. That interrupted build left the local provider output incomplete, so rebuild it before use. A clean macOS 15 signed CI run remains open.

## Checks on a Mac (2026-10-09)

Only synthetic data: a synthetic vault, a private fixture folder (`APASSY_DEBUG_DATA_DIR`), and a synthetic relying party on `http://localhost:4173`. No real vault, account, or secret.

**Signed build, source `11ca5b6`.** CI run `37959199289` on the branch passed. It built the Mac app with both provider profiles and `APASSY_REQUIRE_PROVIDER=1`, and it notarized the DMG (SHA-256 `e6c998f27a21766c45f3cbb07aebc4d1e83fd3b6cdc1615fddbba9a210278d4f`, test build, not a release). The parent verified the version, the commit, the signatures of the app, the extension, the bridge, and the browser guard, the AutoFill provisioning profiles, the staple, and Gatekeeper. This build was not installed, and it was not published.

**DEBUG build of version 0.4.1 with the native parts of commit `2d93004`.** The extension and the bridge in it still report the native version 0.3.6. It is not the signed DMG. Results:

- A real unlock of a synthetic vault, a fresh owner check with the passphrase, and a one-time code reveal passed. The code `419702` matched an independent RFC 6238 calculation (counter `59718791`). The passkey metadata screen passed.
- **In `/tmp`, AutoFill activation failed with `bridgeRefused`.** A read-only diagnosis found the cause: the sandbox of the extension denies `file-read-data` on the bridge, so `SecCodeCopyGuestWithAttributes` fails with 100001 (`EPERM`). The exact signed peer identity is valid without the sandbox. The notes are in a private file (`native-activation-diagnosis-v1/SUMMARY.md`), not in the repository.
- **Under `/Applications`, AutoFill activation passed.** The same DEBUG app ran from a separate folder, `/Applications/Apassy Synthetic Acceptance 041/Apassy.app`, with the isolated fixture. It did not replace the installed `/Applications/Apassy.app` (version 0.3.6). The stale registration of the `/tmp` copy was removed first. macOS showed "Apassy AutoFill is on. Apassy suggests 3 sign-ins." AutoFill was enabled with the owner's permission and restored to off after the test.
- **Save passkey in Helium failed at the OS handoff.** The system sheet offered Apassy, and the owner completed two fresh passphrase checks. Both saved a synthetic localhost key in the vault. macOS then rejected the returned credential with `AuthorizationError Code=14`, "AuthData is missing a required flag." The relying party still has zero credentials, registrations, and sign-ins. The first request also expired before completion; the second reached OS validation within 60 seconds. That build sets BE but clears BS. [Apple requires both flags for the provider API](https://developer.apple.com/forums/thread/742209). The flag correction is committed at `1ad43fb` and passed source checks. A new signed build and registration/sign-in test remain open. These local vault saves are not completed registrations.
- The browser preview of T3 rejects resident credentials with `NotSupportedError` before it reaches any provider. This is not a defect of Apassy.

Not shown by these results:

- Any check of the signed DMG on a Mac. The release build in `/Applications` has not been tried.
- A completed passkey registration or sign-in through the system sheet, with Touch ID or the passphrase.
- A password fill and a one-time code fill through macOS AutoFill. (The code reveal above is the item page of the app, not the fill.)
- The browser extension. The real Helium in use at the time had a remote-debugging port, and the guard of the extension refuses that switch. So the positive guard check, a normal launch of Helium or Chrome stable, was not run. The native OS provider flow does not use the browser extension.

## Still to verify on a device (needs the profiles)

- The sandboxed extension calls `SecCodeCheckValidity` on the bridge of the **signed** app under `/Applications`. Seen so far: the DEBUG build passes in `/Applications` and fails closed in `/tmp`. The signed DMG has not been tried.
- A passkey registration and a sign-in complete through the sheet, in Safari and in Chrome, with the owner check.
- The sheet stays open while Apassy is in front for the owner check (the Save passkey screen was reached, but the creation did not finish).
- How Safari and Chrome list the identities that the app now sends (passkeys, logins, one-time-code logins), and whether QuickType offers a password fill or a code fill and completes it.
- Mac credential exchange: macOS starts the containing app with `NSUserActivity`, so it needs native app work, and the extension does not declare `SupportsCredentialExchange`. Import on the iPhone instead, and let sync bring the passkeys to the Mac.
