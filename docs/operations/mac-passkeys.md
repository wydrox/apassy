# Mac passkeys: the AutoFill credential provider

Date: 2026-10-09.
Host: macOS 27.0, Xcode 27.0 (27A266a), MacOSX27.0.sdk, Swift 6.4. Deployment target macOS 15.0.
Scope: the native side of the Mac passkey provider. The app side is `src/desktop/passkey_socket.rs`.
This document does not open the real-secret gate.

## What this is

macOS asks a credential provider extension for passkeys in Safari, in native apps, and in the system passkey sheet of Chrome.
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
- **Provenance comes from the bridge.** The bridge adds `peer` to each request. It refuses any field that a call does not take, such as `verified` or `peer`, and it forwards a re-encoded copy of the checked fields.
- **The app decides on the owner check by the call, never by a request field.** The RP ID comes from macOS, which checked the origin or the associated domains.

## Protocol

The implemented envelope is in `native/ApassyCredentialBridge/BridgeWire.swift` (header comment). Limits: a request frame of up to 64 KiB, an answer frame of up to 1 MiB, and an answer within 180 s.

- Socket: one connection per request. The frame is a 4-byte big-endian length, then JSON.
- Bridge to app: `ready`, `request {rid, owner_check, peer, payload}`, `cancel {rid, reason}`, `error`.
- App to bridge: `response {rid, result}`, `shutdown`.

When the extension closes its connection, the app gets `cancel` (`peer_closed`). This happens when the owner closes the sheet, or when macOS ends the request. The app then closes its owner dialog and signs nothing. The bridge drops a late answer.

| Call | Owner check | The app routes it today |
| --- | --- | --- |
| `passkey_list {rp_id, allowed}` | no | yes |
| `passkey_assert {id, rp_id, credential_id, client_data_hash}` | yes | yes |
| `passkey_register {rp_id, user_name, user_display_name, user_handle, client_data_hash, algorithms, excluded, attach_id?, attach_revision?, title}` | yes | yes |
| `autofill_list {domains}` | no | no: `unsupported` |
| `autofill_credential {id}` → `{username, password}` | yes | no |
| `autofill_code {id}` → `{code}` | yes | no |
| `credential_identities {}` | no | no |

### App routing

The Swift side of passwords, one-time codes, and identity sync is written and compiles. It has not run against the app.
The app does not route these calls yet, so the default build ships the extension as **passkeys only**. `--with-passwords-and-codes` declares `ProvidesPasswords` and `ProvidesOneTimeCodes` again. Use it only after the app routes all four calls.

## Behaviour of the extension

- **Never without the sheet.** `provideCredentialWithoutUserInteraction` and the conditional registration always cancel with `userInteractionRequired`. `Info.plist` has no `SupportsConditionalPasskeyRegistration` and no `SupportsCredentialExchange`.
- **Sign-in.** The sheet lists the passkeys of the RP that match the allow list. The owner picks one, and the sheet says "Confirm in Apassy" and opens Apassy. Before the extension hands an answer to macOS, it checks the answer: the same credential ID, `rpIdHash == SHA256(rp_id)`, the UP and UV flags, and the sizes.
- **New passkey.** It needs ES256 (`-7`), and it refuses a large blob with support `required`. The excluded credentials go to the app, which answers `excluded` after the owner check. The extension then cancels with `matchedExcludedCredential`. The passkey is saved as a new login, or added to a login of the RP when the app sends `revision` in `autofill_list`.
- **Not running, or locked.** The sheet says "Open Apassy" or "Unlock your vault". It opens Apassy once and tries again every 2 s for up to 180 s. It never keeps a secret, a key, or a seed between requests.
- **Errors.** Cancel or a failed owner check gives `userCanceled`. A missing item gives `credentialIdentityNotFound`. Any other error shows a message, then `failed`.
- There is no LocalAuthentication check in the extension. The owner check runs once, in the app.

## Identity store and turning AutoFill on

Only a program with the AutoFill entitlement of this provider can write `ASCredentialIdentityStore`: the extension, or the containing app. The Rust app cannot call the store.
So the extension replaces the whole list from `credential_identities` in two cases: at the start of each request, and when the owner turns AutoFill on (`ShowsConfigurationUI`). The list holds all passkeys, not only those of one RP, plus the logins and the one-time-code logins. It is metadata only.
The app cannot start a refresh, so a new passkey shows up in the system suggestions after the next run of the provider.
Until the app routes `credential_identities`, the store stays empty, and the owner picks Apassy in the passkey sheet.

`ASSettingsHelper` must be called from the containing app, which is Rust. The Settings tab can open System Settings > General > AutoFill & Passwords instead. Check the URL on a device.

## Build

```
scripts/build-credential-provider.sh                   # unsigned; checks the bundle layout
scripts/build-credential-provider.sh --test            # + synthetic tests (131)
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

macOS registers the provider only for an app in `/Applications`. Check it with `pluginkit -m -p com.apple.authentication-services-credential-provider-ui`.

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
- Signed probe (`Tests/SignedProbe`, a fake `Apassy.app` with its own bundle ID, removed and unregistered after the run). It uses the real checks, with only the container path overridden:
  - the bridge accepts its signed parent
  - it accepts the signed extension, and the provenance names the right pid and path
  - it refuses the same identifier at another path
  - it refuses another identifier inside the app
  - it refuses another identifier at the right path
  - it refuses an unsigned parent, and a signed parent outside its bundle
  - the extension refuses a server that is not the signed bridge

## Still to verify on a device (needs the profiles)

- The sandboxed extension can call `SecCodeCheckValidity` on the bridge. It reads `/Applications/Apassy.app`. The extension fails closed.
- The sheet stays open while Apassy is in front for the owner check.
- How Safari and Chrome offer a provider whose identity store is empty.
- Mac credential exchange: macOS starts the containing app with `NSUserActivity`, so it needs native app work. Import on the iPhone instead, and let sync bring the passkeys to the Mac.
