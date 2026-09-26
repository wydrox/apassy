# Native app bundle and Swift helper

Date: 2026-09-26.
Host: Mac16,10 (Mac mini, Apple M4), macOS 27.0 (26A428), arm64. Xcode 26.3 (17C529), Swift 6.2.4, Rust 1.97.0.
Scope: goal item A1, and the native side of A3, A4, N1, and N2 ([goal](../goal.md), [ADR 0010](../adr/0010-closing-open-decisions.md)).
The desktop app calls the helper for the unlock method (A2, A3), the owner check (A4), and notifications (N1 to N3). See [Desktop integration](#desktop-integration) and [notifications.md](notifications.md).
This document does not open the real-secret gate.

## What this is

The Rust crate forbids unsafe code. Touch ID, the data protection keychain, and native notifications need Apple APIs.
A small Swift helper calls these APIs. The Rust module `apassy::native` starts the helper for each request.
The protocol is one JSON line in and one JSON line out.

## Bundle layout

`scripts/build-app.sh` makes `target/Apassy.app`:

| Path in `Apassy.app/Contents` | Program | Bundle ID or signing ID | Entitlements |
| --- | --- | --- | --- |
| `MacOS/apassy` | Rust desktop app, main executable | `com.wydrox.apassy` | none |
| `MacOS/apassy-mcp` | Rust MCP adapter for agents | `com.wydrox.apassy.mcp` | none |
| `MacOS/apassy-helper` | Swift helper: `authenticate`, notifications | `com.wydrox.apassy.helper` | none |
| `Helpers/ApassyKeychain.app` | the same Swift helper, in its own bundle: keychain commands | `com.wydrox.apassy.keychain` | keychain entitlements, only with a profile |

Each program uses the hardened runtime. The bundle ID `com.wydrox.apassy` matches the GitHub owner `wydrox`.
The keychain access group is `<TEAM_ID>.com.wydrox.apassy`.

The helpers answer only the signed Apassy app that contains them. See [Caller check](#caller-check).
The agent profile denies the start, the read, and a change of each program in the bundle, except `apassy-mcp` and `apassy-hook` ([isolation.md](isolation.md), section 1).

Why two copies of the helper:

- AMFI permits the keychain entitlements only for the main executable of a bundle that has a matching `embedded.provisionprofile`. A second executable in `Contents/MacOS` does not get the profile of the app (evidence C1 below).
- Notifications belong to the bundle of the process. The copy in `Contents/MacOS` belongs to `com.wydrox.apassy`. A notification click then opens Apassy, not a background helper.

The `apassy` program does not need a restricted entitlement. So the main app does not need a profile.

## Build

```
scripts/build-app.sh
```

The script:

1. Selects the only valid "Apple Development" identity, or `APASSY_SIGN_IDENTITY`. It refuses ad hoc signing.
2. Finds a profile for the keychain helper: `APASSY_KEYCHAIN_PROFILE`, or a valid profile in the Xcode profile folders. It checks the platform, team, App ID, expiry, keychain group, this Mac, and the signing certificate.
3. Runs `cargo build --release --locked --features desktop,vault --bin apassy --bin apassy-mcp --bin apassy-sandbox`. `apassy-sandbox` does not go into the bundle. Step 8 uses it.
4. Builds the helper with `xcrun --sdk macosx swiftc -O -swift-version 5 -warnings-as-errors -target arm64-apple-macos15.0`, without `-D APASSY_HELPER_DEV`. It fails when the helper contains the development override `APASSY_HELPER_DEV_ANY_CALLER`. It builds the caller probe (`native/ApassyCallerProbe/main.swift`) in a temporary directory. The probe never goes into the bundle.
5. Assembles the bundle in `target/app-stage`, signs from the inside out, and verifies with `codesign --verify --deep --strict`.
6. Checks the hardened runtime flag, the team, and the entitlements of each program. `apassy`, `apassy-mcp`, and `apassy-helper` must have no entitlements.
7. Runs the signed programs: `apassy --smoke-test`, `apassy-mcp --version`, and the caller checks of the helpers (see [Caller check](#caller-check)).
8. Runs the agent profile with the signed bundle: the helpers and the main program do not start, `apassy-mcp` starts, a copy of the keychain helper fails, and a copy that exists outside the bundle refuses the caller.
9. Moves the bundle to `target/Apassy.app`.

Each run starts from an empty bundle. A failed step stops the script with `build-app: FAILED:` and a non-zero exit.

Without a profile, the script prints a warning and builds a signed app.
Then each keychain command returns `keychain_unavailable`. Touch ID can confirm actions, but it cannot unlock the vault (ADR 0010, Limits).
Set `APASSY_REQUIRE_KEYCHAIN=1` to make a missing profile a failure.

Use a bare `xcrun` with care on this host. It selects the Command Line Tools 27.0 SDK, and the Xcode 26.3 linker fails on it: `ld: tapi error: malformed file ... unknown architecture arm64e.x1-macos`.
The script uses `xcrun --sdk macosx`, which selects the Xcode MacOSX26.2 SDK.

### Options

| Variable or flag | Effect |
| --- | --- |
| `--provision` | Runs Xcode automatic signing for `native/ApassyKeychain/ApassyKeychain.xcodeproj` with `-allowProvisioningUpdates`. This registers the App ID and gets a development profile. It needs an Apple ID in Xcode. |
| `APASSY_SIGN_IDENTITY` | SHA-1 or name of the signing identity. |
| `APASSY_KEYCHAIN_PROFILE` | Path to a macOS development profile for the keychain helper. |
| `APASSY_TEAM_ID` | Team for `--provision`. Default: the team (OU) of the certificate. |
| `APASSY_KEYCHAIN_BUNDLE_ID` | Bundle ID and App ID of the keychain helper. Default: `com.wydrox.apassy.keychain`. |
| `APASSY_REQUIRE_KEYCHAIN=1` | Fails when no valid profile is found. |

XcodeGen 2.46.0 made the Xcode project from `native/ApassyKeychain/project.yml`.
The script uses the project only to get the profile. `swiftc` builds the helper that goes into the bundle.

## Signing and provisioning finding

The identity `Apple Development: Rafał Wyderka (8469UQ298L)` is in team `7S3F9767BM` ("Apprife Konrad Alfaro"). `8469UQ298L` is the personal ID of the certificate, not a team.
Xcode has no Apple ID account on this Mac (`DVTDeveloperAccountManagerAppleIDLists` is empty).
No installed profile is for an Apassy App ID.
The only macOS profile is "Mac Catalyst Team Provisioning Profile: com.revision.stream" for team `7S3F9767BM`. It includes this Mac and this certificate. It permits the keychain groups `7S3F9767BM.*`.

Experiments with synthetic items (scratch bundles in `target/scratch`, signed with the Apple Development identity and the hardened runtime):

| Case | Setup | Result |
| --- | --- | --- |
| A | No entitlements, no profile. `SecItemAdd` with `kSecUseDataProtectionKeychain`. | `-34018` "A required entitlement is not present." |
| B | `keychain-access-groups` only, no profile | `Killed: 9` at launch. amfid: `AppleMobileFileIntegrityError Code=-413 "No matching profile found"` |
| B2 | `com.apple.application-identifier`, team ID, and keychain group, no profile | `Killed: 9`, same amfid error |
| C1 | Profile in the app. The probe is a second executable in `Contents/MacOS`. | `Killed: 9`, amfid `-413`. The same result with signing ID `com.revision.stream` and `com.revision.stream.kcprobe`. |
| C2 | Profile in the app. The probe is the main executable. | Add, read, and delete of a plain item: `0`. |
| D | Nested bundle `Contents/Helpers/Probe.app` with its own profile | Add, read, and delete: `0`. Access group `7S3F9767BM.com.wydrox.apassy`. |
| E | The real helper in a nested bundle with the profile | See below. |
| F | `.biometryCurrentSet` item when Touch ID is not paired | `SecItemAdd` returns `-25293` (`errSecAuthFailed`) |

Case E, requests to the real helper:

```
{"biometry":"not_available","bundle_id":"com.revision.stream","helper_version":"0.1.0","keychain_access_group":"7S3F9767BM.com.wydrox.apassy","ok":true,"protocol":1}
{"biometry_changed":false,"exists":false,"ok":true}
{"deleted":false,"ok":true}
{"error":"not_available","message":"Touch ID is not available on this Mac.","ok":false}
{"error":"not_found","message":"No Apassy unlock key is in the keychain.","ok":false}
```

A plain synthetic item was then added under the helper service. The helper found it, `keychain_read` returned `biometry_changed` (the item had no biometric state), and `keychain_delete` returned `{"deleted":true}`.
After that run, the helper checks Touch ID before it compares the fingerprint state. So a disconnected keyboard now gives `not_available`, not `biometry_changed`. The message for a keyboard that is not paired is now "The Touch ID keyboard is not connected or not paired."

Conclusions:

- The data protection keychain needs a provisioning profile. The Apple Development identity alone is not sufficient.
- The keychain helper must be the main executable of its own bundle, with its own profile.
- A development profile for a new App ID needs the owner: an Apple ID in Xcode, or the developer portal. See the owner steps.
- Touch ID is not usable on this Mac now. `LAContext.canEvaluatePolicy` returns LAError `-12` ("Biometric accessory is not paired."). The Magic Keyboard is in the Bluetooth list as "Not Connected". `bioutil -c` shows 0 biometric templates for user 501.

Xcode automatic signing, run by `scripts/build-app.sh --provision`:

```
xcodebuild -project native/ApassyKeychain/ApassyKeychain.xcodeproj -scheme ApassyKeychain \
  -configuration Debug -derivedDataPath target/xcode-provision \
  -allowProvisioningUpdates DEVELOPMENT_TEAM=7S3F9767BM build
```

Result: `BUILD FAILED`:

```
error: No Accounts: Add a new account in Accounts settings.
error: No profiles for 'com.wydrox.apassy.keychain' were found: Xcode couldn't find any Mac App Development provisioning profiles matching 'com.wydrox.apassy.keychain'.
```

A build of the same project with `CODE_SIGNING_ALLOWED=NO` passed. The project and the Swift sources are valid.

To test the script path with a profile, the script ran once with the Revision profile and `APASSY_KEYCHAIN_BUNDLE_ID=com.revision.stream`.
This was a local check only. Nothing went to Apple. The final `target/Apassy.app` does not use that profile.
Result: `Keychain: enabled (team 7S3F9767BM, group 7S3F9767BM.com.wydrox.apassy)`. AMFI accepted the helper. `keychain_exists` returned `{"biometry_changed":false,"exists":false,"ok":true}`. `keychain_store` returned `not_available`, because Touch ID was not paired.

The profile check refuses a wrong profile. With the Revision profile and the default bundle ID, the script stopped before the build:

```
build-app: FAILED: APASSY_KEYCHAIN_PROFILE is not usable: the App ID is "7S3F9767BM.com.revision.stream", not 7S3F9767BM.com.wydrox.apassy.keychain
```

## Helper protocol

The helper reads JSON lines on stdin. It writes exactly one JSON line on stdout for each request. It skips empty lines and exits at end of input.
It takes no arguments. It writes nothing to stderr during normal work.
A request is an object with `cmd` and the fields of the command. The largest request is 64 KiB.
Before each request, the helper checks its caller ([Caller check](#caller-check)). When the caller is not allowed, each request, also `ping` and a malformed request, gets `caller_not_allowed`.

A success has `"ok": true` and the result fields. A failure has `"ok": false`, `"error"`, and `"message"`.
A message is English text for logs. It never contains a secret. Code must use `error`, not `message`.

| Command | Request fields | Success fields | Runs in | Prompt |
| --- | --- | --- | --- | --- |
| `ping` | none | `protocol` (1), `helper_version`, `bundle_id` (or null), `keychain_access_group` (or null), `biometry` (`available` or an error code) | both | no |
| `authenticate` | `reason` (1 to 200 characters) | none | `apassy-helper` | Touch ID |
| `keychain_store` | `account`, `secret_b64` (standard base64, 1 to 4096 bytes) | `access_group` | keychain helper | no |
| `keychain_read` | `account`, `reason` | `secret_b64` | keychain helper | Touch ID |
| `keychain_delete` | `account` | `deleted` (bool) | keychain helper | no |
| `keychain_exists` | `account` | `exists`, `biometry_changed` (bool) | keychain helper | no |
| `notify` | `id`, `title` (1 to 80), `body` (0 to 200) | `delivered` (bool) and the status fields | `apassy-helper` | permission, first use only |
| `notify_status` | none | `authorization`, `alert`, `alert_style`, `notification_center`, `lock_screen`, `sound` | `apassy-helper` | no |
| `notify_authorize` | none | `granted` and the status fields | `apassy-helper` | permission |

An `account` or an `id` has 1 to 64 characters from `A-Z`, `a-z`, `0-9`, `.`, `_`, `-`.
Text fields have no control characters.
`authorization` is `not_determined`, `denied`, `authorized`, or `provisional`. A setting is `enabled`, `disabled`, or `not_supported`. `alert_style` is `none`, `banner`, or `alert`.

Error codes:

| Code | Meaning | App action |
| --- | --- | --- |
| `invalid_request` | Bad JSON, unknown command, or a bad field | Bug in the caller |
| `cancelled` | The owner or the system cancelled Touch ID | Ask for the passphrase, or stop the action |
| `fallback` | The owner selected "Use Apassy Passphrase" | Ask for the passphrase |
| `not_available` | No Touch ID sensor, keyboard not paired, or no Mac password | Use the passphrase |
| `not_enrolled` | No fingerprint is enrolled | Use the passphrase |
| `locked_out` | Too many failed attempts. The Mac password resets it. | Use the passphrase |
| `failed` | Touch ID did not match, or a keychain call failed | Show the message. Allow a new try or the passphrase. |
| `keychain_unavailable` | No profile or entitlement for the keychain helper | Touch ID confirms actions only. Unlock needs the passphrase. |
| `not_found` | No unlock key in the keychain | Unlock with the passphrase |
| `biometry_changed` | The fingerprints changed after setup | Unlock with the passphrase. Delete the item. Offer Touch ID setup again. |
| `notifications_unavailable` | The helper is not in an app bundle | Delivery failure. Keep the event in the inbox. |
| `notifications_denied` | Notifications are not allowed | Delivery failure. Keep the event in the inbox. |
| `caller_not_allowed` | The parent process of the helper is not the signed Apassy app that contains the helper | Do not retry. Touch ID, the keychain, and notifications are not available to this caller. In the app, this means a broken or changed bundle. |
| `internal` | Unexpected helper error | Show the message |

Touch ID policy: `authenticate` uses `LAPolicy.deviceOwnerAuthenticationWithBiometrics`. The macOS login password is not a fallback. The fallback button is "Use Apassy Passphrase" and gives `fallback`.

Keychain item: a generic password in the data protection keychain (`kSecUseDataProtectionKeychain = true`), service `com.wydrox.apassy.vault-unlock`, group `<TEAM_ID>.com.wydrox.apassy`.
The access control is `SecAccessControlCreateWithFlags(kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .biometryCurrentSet)`. macOS makes the item invalid after a fingerprint change.
`kSecAttrGeneric` holds `LAContext.domainState.biometry.stateHash` from the store time. This hash is not a secret. When the current hash is different, `keychain_exists` gives `biometry_changed: true`, and `keychain_read` gives `biometry_changed` without a prompt.
`keychain_store` needs Touch ID to work at store time, and it replaces an earlier item with the same account.

## Caller check

Code: `native/ApassyHelper/Caller.swift`. Goal I2: a process in the agent profile must not use the helpers.

The agent profile denies the start of the helpers ([isolation.md](isolation.md)). The caller check is a second layer. It stops a helper that another program started, for example LaunchServices (`open`), launchctl, a terminal, or a copy of the helper bundle in another place.

Before each request, the helper checks its parent process:

1. The parent is not launchd (pid 1). LaunchServices, launchctl, and login items start a program with launchd as the parent.
2. The helper gets the audit token of the parent: `task_name_for_pid(mach_task_self_, getppid(), &port)`, then `task_info(port, TASK_AUDIT_TOKEN, ...)`. An audit token names one process image. A later exec in the parent gives a different token.
3. `SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributeAudit: token], [], &code)` gives the running code of the parent. `SecCodeCheckValidityWithErrors(code, [], requirement, nil)` checks it against this requirement:

   ```
   anchor apple generic and identifier "com.wydrox.apassy" and certificate leaf[subject.OU] = "<TEAM_ID>"
   ```

   `<TEAM_ID>` is the team of the helper itself: `SecCodeCopySelf`, `SecCodeCheckValidity`, `SecCodeCopyStaticCode`, and `SecCodeCopySigningInformation` with `kSecCSSigningInformation` (`kSecCodeInfoTeamIdentifier`). A helper without a team signature (unsigned or ad hoc) refuses every request.
4. The parent is the app bundle that contains the helper. The helper compares `SecCodeCopyPath` of the parent with its own bundle: its main executable (`kSecCodeInfoMainExecutable`, resolved with `realpath`) without `/Contents/MacOS/apassy-helper` or `/Contents/Helpers/ApassyKeychain.app/Contents/MacOS/ApassyKeychain`. So a program signed as `com.wydrox.apassy` in another place does not pass.
5. After the check, `getppid()` is the same, and the audit token of the parent is the same.

A failed step gives `caller_not_allowed` with a message for logs. The helper does not parse the request.
`SecCodeCheckValidity` checks the dynamic validity of the running parent. Its documentation says that the call "is secure against attempts to modify the file system source of the SecCode".
Measured on this Mac: 20 starts and `ping` requests through a signed parent took 75.4 ms each on average, with the start of the parent and the helper.

### Development override

A helper built with `-D APASSY_HELPER_DEV` skips the check when its environment has `APASSY_HELPER_DEV_ANY_CALLER=1`.
Only the tests use this flag: `tests/native_helper.rs` builds the helper with it, and a small script sets the variable for the protocol checks. The isolation tests build the helper with the flag, but never set the variable.
`scripts/build-app.sh` does not use the flag. The release helper does not contain the override code or the variable name. The script and the test `a_helper_built_without_the_dev_flag_ignores_the_override` check this.
To run the debug desktop app with a helper outside the bundle, build the helper with `-D APASSY_HELPER_DEV`, and set `APASSY_NATIVE_HELPER`, `APASSY_NATIVE_KEYCHAIN_HELPER`, and `APASSY_HELPER_DEV_ANY_CALLER=1` in the environment of the app. The app passes its environment to the helper.

### Measured results

`scripts/build-app.sh` starts the signed helpers with these parents. The caller probe (`native/ApassyCallerProbe/main.swift`) starts one program as its child. The script signs it as the main program of scratch copies of the bundle in a temporary directory, and deletes them at the end. The script checks the error code. The messages in the table are from a manual run of the same cases with `target/Apassy.app`.

| Parent | Helper | Answer |
| --- | --- | --- |
| the shell of the script | `apassy-helper`, the keychain helper | `caller_not_allowed`: "The parent process is not the signed Apassy app (-67050)." `-67050` is `errSecCSReqFailed`. |
| the shell, with `APASSY_HELPER_DEV_ANY_CALLER=1` | `apassy-helper` | `caller_not_allowed` |
| the probe, signed as `com.wydrox.apassy`, main program of the copy that contains the helper | `apassy-helper` | `ping` with `"bundle_id":"com.wydrox.apassy"`, `notify_status`, and `invalid_request` for an unknown command |
| the same probe | the keychain helper of the copy | `ping` with `"bundle_id":"com.wydrox.apassy.keychain"`, and `keychain_unavailable` (no provisioning profile) |
| the same probe | a helper of another bundle (the staged `Apassy.app` in the script, `target/Apassy.app` in a manual run) | `caller_not_allowed`: "The parent process is not the Apassy app that contains this helper." |
| a probe signed as `com.wydrox.apassy.probe`, in its own copy | both helpers of that copy | `caller_not_allowed` (-67050) |
| launchd: `open -W -n --stdin req --stdout out <keychain helper app>` outside any sandbox (manual) | the keychain helper | `caller_not_allowed`: "launchd started the helper. Only Apassy.app can start it." |

The desktop app starts the helpers as their parent from `Contents/MacOS/apassy`. The probe stands for it: the same bundle layout, bundle ID, team, and signature. The agent did not watch a helper start from the real desktop window.

### Limits of the caller check

- The check trusts each program that is signed by the team with the identifier `com.wydrox.apassy`, at the path of the app that contains the helper. A process that can sign with the owner's certificate and write that path passes the check. The agent profile denies a write to the protected bundles.
- The check uses the parent process at the time of each request. A program that starts the helper and then replaces itself with the real `Apassy.app/Contents/MacOS/apassy` (exec) before the check can pass it with its own request in the pipe. This needs a start of the Apassy program. The agent profile denies it. A program outside the profile is not in the scope of this check (ADR 0010, Limits).
- A copy of the whole bundle in another place is a new "app that contains the helper". The agent profile denies a read of the protected bundles, so a process in the profile cannot make such a copy. A copy that the owner makes is not protected by the profile.

## Rust client

`apassy::native::NativeHelper`:

- `NativeHelper::locate()` finds the helpers next to the running `apassy` in the bundle. Debug builds first read `APASSY_NATIVE_HELPER` and `APASSY_NATIVE_KEYCHAIN_HELPER`. Release builds ignore these variables, so a process that sets the app environment cannot replace Touch ID with a fake helper.
- `NativeHelper::with_paths(helper, keychain_helper)` is for tests.
- Methods: `ping`, `ping_keychain`, `authenticate`, `keychain_store`, `keychain_read`, `keychain_delete`, `keychain_exists`, `notify`, `notify_status`, `notify_authorize`. Keychain methods use the keychain helper. The other methods use `apassy-helper`.
- Time limits: 10 s for quick commands, 40 s for `notify`, 180 s for commands that wait for the owner. After the limit, the client stops the helper and returns `NativeError::Timeout`.
- Errors: `NativeError::Helper { code: HelperErrorCode, message }` for a helper error. `HelperErrorCode::CallerNotAllowed` is `caller_not_allowed`. Other variants: `InvalidArgument` (the client did not start the helper), `HelperMissing`, `Io`, `Timeout`, `Protocol`. The test `swift_and_rust_error_codes_match` compares the Swift and the Rust lists.
- `KeychainSecret` holds the secret bytes. `Debug` prints `KeychainSecret([redacted])`. It has no `Clone`. Drop overwrites the bytes.
- The client overwrites its request and response buffers after use. This is best effort. Copies in the helper, the allocator, swap, and crash dumps stay possible.
- The crate keeps `#![forbid(unsafe_code)]`. The client uses std and serde_json only. Base64 is a small std implementation.

A call blocks the thread. The desktop must call the client from a worker thread, not from the UI thread.

## Notification preview rule (N2)

A preview shows the agent name and the event type only. It never shows the command, the user request, or a value.
`apassy::native::Notification::new(event_id, agent_name, event)` is the only constructor. It takes no free text.

| Event | Title | Body |
| --- | --- | --- |
| `ApprovalWaiting` | Approval waiting | Agent "NAME" waits for your decision. Open Apassy to review. |
| `RequestBlocked` | Request blocked | Apassy blocked a request from agent "NAME". |

The agent name has 1 to 40 characters and no control characters.
The helper cannot check the meaning of a title or a body. It only limits the length and refuses control characters. A caller that uses the raw protocol must follow the rule.
A notification only tells the owner about an event. It is not an approval (N4).

When Apassy is the front app, macOS can put the notification in Notification Center without a banner.

## Desktop integration

The desktop calls the helper from worker threads only (`src/desktop/owner_check.rs`, `Task`). The UI thread reads the results each frame.
At start, the window runs `ping` once. The result tells the owner check if Touch ID is available.

### Unlock method (A2, A3)

Code: `src/desktop/unlock.rs`, the "Unlock method" card, and "Unlock with Touch ID" in the Vault file card (`src/desktop/ui/unlock_view.rs`).

- The unlock method is an owner setting: passphrase or Touch ID. The master passphrase stays the root key.
- Source of truth: the keychain item itself. `keychain_exists` answers without a prompt, so Apassy reads the setting before unlock, when the owner opens, creates, or restores a vault file. The encrypted vault cannot hold the setting, because Apassy needs it before the vault opens. Apassy keeps no preference file. An item means "Touch ID". No item means "passphrase".
- Keychain item: service `com.wydrox.apassy.vault-unlock` (`KEYCHAIN_SERVICE`), account `vault-unlock-` and 16 hexadecimal digits of the FNV-1a hash of the canonical vault path (`vault_unlock_account`). Each vault file has its own item. A moved or restored file has Touch ID unlock off until the owner turns it on.
- The item holds the master passphrase. The helper stores it with `.biometryCurrentSet` access control.
- Turn on: the vault is unlocked, and the owner types the passphrase now. Apassy checks it on a second, read-only SQLCipher connection (`Vault::verify_passphrase_at`), then calls `keychain_store`. The typed text is in a `Zeroizing` buffer.
- Unlock: `keychain_read` with the fixed reason "unlock the Apassy vault". The key goes to `OwnerSession::unlock` on the UI thread and is erased after.
- `biometry_changed` from `keychain_exists` or `keychain_read`: Apassy deletes the item, shows "The fingerprints on this Mac changed ...", and the owner unlocks with the passphrase.
- A key that does not open the vault, for example after a passphrase change in another copy: Apassy deletes the item. After a passphrase change in this app, Apassy deletes the item and asks the owner to turn Touch ID unlock on again.
- Turn off: `keychain_delete`.
- Backup restore, passphrase change, and recovery need the typed passphrase. Touch ID never supplies it.
- `keychain_unavailable` (no provisioning profile, the state on this Mac): the Vault file card and the Unlock method card show "Touch ID can confirm actions, but cannot unlock the vault until the app has a provisioning profile. Unlock with the passphrase." The setup controls are hidden. Passphrase unlock works as before.

### Owner check (A4)

Code: `src/broker/approvals/owner_auth.rs`, `src/desktop/owner_check.rs`, `src/desktop/ui/owner_check_view.rs`.

`OwnerGate::authorize(action, check)` is the one owner-authorization function. It checks the owner now and returns an `OwnerProof` for that action only:

- The check is Touch ID (`authenticate`, the reason names the action) or the master passphrase (a second, read-only SQLCipher connection, then the buffer is erased).
- A proof names one action and its target. For an approval, the target is the waiting run exactly as the owner saw it.
- A proof is valid for 60 s, only in the vault session of the check, and for one use. It has no `Clone`. Only `authorize` makes one.
- If the vault locks or changes during the check, the gate gives no proof.

These calls take a proof. Without a matching proof, they refuse with `owner_check_required` and change nothing:

| Owner action | Call | Proof action |
| --- | --- | --- |
| Reveal | `OwnerSession::reveal` | `Reveal { item_id }` |
| Approval of a run | `ApprovalQueue::approve` | `ApproveRun(run)` |
| "Approve and remember" | `ApprovalQueue::approve` | `ApproveAndRemember(run)` |
| New connector operation | `OwnerSession::allow_operation` | `ChangeGrant { agent_id, item_id }` |
| Process access (new or changed mode) | `OwnerSession::set_exec_grant` | `ChangeGrant { agent_id, item_id }` |
| Rule of a process grant | `OwnerSession::set_exec_rule` | `ChangeRule { agent_id, item_id }` |
| Declaration, environment variable, connector, review after restore | `set_declaration`, `set_env_binding`, `set_connector`, `confirm_review` | `ChangeItemRules { item_id }` |
| Token rotation | `OwnerSession::rotate_agent_token` | `RotateToken { agent_id }` |
| Token lifetime | `OwnerSession::set_token_lifetime_days` | `ChangeTokenLifetime` |

A denial of a run, a revoke, and a removal of access need no check. They only take authority away.
`ApprovalQueue::decide(id, bool)` does not exist anymore, so an approval button that skips the gate does not compile.

The dialog starts Touch ID at once when `ping` reported Touch ID as available. Otherwise it says why, for example "Touch ID is not available: the Touch ID keyboard is not connected or not paired, or this Mac has no Touch ID sensor. Type the passphrase to confirm." The owner can try Touch ID again or type the passphrase. `cancelled`, `fallback`, `failed`, `not_available`, `not_enrolled`, and `locked_out` keep the dialog open for the passphrase.

### Key memory in the desktop (review F1, F3, F4, F10)

- F1: each passphrase and secret field has a global widget ID. After Create, Unlock, Restore, a passphrase change, a save of an item, the owner check, and on lock, the app clears the egui undo history of the field. A headless test shows that Cmd+Z restores the typed passphrase without this and restores nothing with it.
- F3: `Ephemeral`, `SecretForm`, and `RevealedValue` erase their text with `zeroize`. `SecretForm` has no `Clone`, and the forms are borrowed, not cloned.
- F4: a passphrase field has 4096 bytes of capacity and takes at most 1024 characters. An item secret field has 256 KiB and takes at most 65536 characters. So typing never moves the text. `Ephemeral::take` leaves a buffer with the same capacity.
- F10: `OwnerDetails` has no revealed value. The view borrows it from the session. A revealed value hides after 30 s, on "Hide values", and on lock. egui still copies the text for its layout.

### Notifications (N1 to N4)

See [notifications.md](notifications.md).

## Checks run by the agent

All commands ran from the repository root in the worktree.

| Command | Result |
| --- | --- |
| `cargo fmt --check` | PASS |
| `cargo clippy --locked --all-targets --features desktop,vault -- -D warnings` | PASS. No warnings. |
| `cargo clippy --locked --all-features --all-targets -- -D warnings` | PASS. No warnings. |
| `cargo clippy --locked --all-targets -- -D warnings` | PASS. No warnings. `apassy::native` has no feature gate. |
| `cargo test --locked --features desktop,vault` | PASS. lib 41, agent_path 8, agent_run 8, bouncer_eval 2, bouncer_rules 7, contracts 14, desktop_model 29, native_helper 15, owner_vault 7, vault_lifecycle 28, vault_passphrase 5, doc tests 6. No failures. The 5 ignored tests are earlier tests outside this task (network and model evaluation). |
| `cargo test --locked --test native_helper` | PASS. 15 tests. Two tests build the real Swift helper and check the protocol. None is ignored. |
| `cargo test --locked --lib native` | PASS. 9 tests: base64 vectors, error codes, redaction, limits, paths, the environment override, delivery status. |
| `scripts/build-app.sh` | PASS, exit 0. See below. The script ran four times in this task: three passes, and one intended failure with a wrong profile. Each run started from an empty bundle. |

`scripts/build-app.sh` without a profile, final lines:

```
Identifier=com.wydrox.apassy flags=0x10000(runtime)
Identifier=com.wydrox.apassy.mcp flags=0x10000(runtime)
Identifier=com.wydrox.apassy.helper flags=0x10000(runtime)
Identifier=com.wydrox.apassy.keychain flags=0x10000(runtime)
Entitlements of ApassyKeychain.app: {}
Entitlements of apassy, apassy-mcp, apassy-helper: {}
ok: apassy --smoke-test
ok: apassy-mcp --version
ok: helper ping
ok: helper notify_status
ok: helper unknown command
ok: keychain helper ping
ok: keychain_exists
Keychain: DISABLED (no provisioning profile). Touch ID can confirm actions but cannot unlock the vault.
```

`codesign --verify --deep --strict --verbose=2 target/Apassy.app`: "valid on disk" and "satisfies its Designated Requirement".

The helper in the bundle, without a prompt (this run was before the caller check; now a start from a shell gives `caller_not_allowed`):

```
$ printf '%s\n' '{"cmd":"ping"}' '{"cmd":"notify_status"}' | target/Apassy.app/Contents/MacOS/apassy-helper
{"biometry":"not_available","bundle_id":"com.wydrox.apassy","helper_version":"0.1.0","keychain_access_group":null,"ok":true,"protocol":1}
{"alert":"not_supported","alert_style":"none","authorization":"not_determined","lock_screen":"not_supported","notification_center":"not_supported","ok":true,"sound":"not_supported"}
```

The helper found the `com.wydrox.apassy` bundle. The owner has not decided about notifications yet.

The keychain helper in the bundle: `ping` gives `"bundle_id":"com.wydrox.apassy.keychain","keychain_access_group":null`, and `keychain_exists` gives `keychain_unavailable`.

`spctl --assess --type execute -vv target/Apassy.app` gives `rejected` and `origin=Apple Development: Rafał Wyderka (8469UQ298L)`, exit 3.
Gatekeeper accepts only Developer ID or App Store signatures. This is expected for a development build. A local build runs, because the files have no quarantine attribute. Notarization is out of scope.

### Earlier failures

These failures are not counted as passes:

- The first scratch link failed: `ld: tapi error: malformed file`. A bare `xcrun clang` selected the Command Line Tools 27.0 SDK. The script now uses `xcrun --sdk macosx`.
- The first Swift build failed: `'ephemeral' is unavailable in macOS`. The helper no longer uses that status.
- In case C2, the probe first had no entitlements. The signature of the bundle replaced the signature of the main executable, and that signature had no `--entitlements`. The script signs the keychain helper at the bundle level with its entitlements for this reason.
- Clippy failed once with `manual implementation of .is_multiple_of()` in the base64 decoder. The code now uses `is_multiple_of`.

### Checks for the desktop integration (A2 to A4, N1 to N4)

Worktree branch of the desktop worker, after a merge with `goal-v1` at `6e64c69`. All commands ran from the repository root.

| Command | Result |
| --- | --- |
| `cargo fmt --check` | PASS |
| `cargo clippy --locked --all-targets --features desktop,vault -- -D warnings` | PASS. No warnings. |
| `cargo clippy --locked --all-targets -- -D warnings` and `--features desktop` | PASS. The build without the vault feature keeps working. |
| `cargo test --locked --features desktop,vault` | PASS. lib 88, main 1, agent_path 11, agent_run 13, analysis_replay 1, bouncer_eval 2, bouncer_rules 8, contracts 14, desktop_model 29, host_hook 7, isolation_profile 10, native_helper 15, notifications 6, owner_auth 8, owner_vault 12, rule_packs 5, vault_lifecycle 28, vault_migration 3, vault_passphrase 8, doc tests 6. No failures. The 8 ignored tests are earlier tests that need the network, a live Laya model, or a real host. |
| `scripts/build-app.sh` | PASS, exit 0. Hardened runtime on all 4 programs. `ok:` for the smoke test, `apassy-mcp --version`, helper `ping`, `notify_status`, an unknown command, keychain helper `ping`, and `keychain_exists`. "Keychain: DISABLED (no provisioning profile)." |

New tests for this work: `tests/owner_auth.rs` (A2, A3, A4 with a fake helper), `tests/notifications.rs` (N1 to N4 with a real broker and a fake helper), `tests/owner_vault.rs` (`owner_actions_refuse_without_a_matching_check`, `revealed_values_hide_on_time_hide_and_lock`), `src/desktop/ui/owner_tests.rs` (F1, F4, the owner check dialog, "Mark as seen"), `src/broker/approvals.rs` (`approve_refuses_without_a_matching_fresh_proof`), `src/desktop/inbox.rs`, and `tests/isolation/product_profile.rs` (`keychain_item_is_not_readable_in_profile`, with the signed helper from `target/Apassy.app`).

Start of the built app without a window check (the process has a window, but the agent did not look at the screen). The data directory on this Mac has mode `0755`, so the broker refuses it. The start used a temporary socket directory with mode `0700`:

```
$ APASSY_BROKER_SOCKET=/tmp/apassy-launch-check2/broker.sock target/Apassy.app/Contents/MacOS/apassy &
$ ps -o pid,stat,etime,command -p <pid>        # after 7 s: running
$ ls -la /tmp/apassy-launch-check2              # srw------- broker.sock
$ printf '%s\n' '{"cmd":"ping"}' '{"cmd":"notify_status"}' | target/Apassy.app/Contents/MacOS/apassy-helper
{"biometry":"not_available","bundle_id":"com.wydrox.apassy","helper_version":"0.1.0","keychain_access_group":null,"ok":true,"protocol":1}
{"alert":"not_supported","alert_style":"none","authorization":"not_determined","lock_screen":"not_supported","notification_center":"not_supported","ok":true,"sound":"not_supported"}
$ printf '%s\n' '{"cmd":"ping"}' | target/Apassy.app/Contents/Helpers/ApassyKeychain.app/Contents/MacOS/ApassyKeychain
{"biometry":"not_available","bundle_id":"com.wydrox.apassy.keychain","helper_version":"0.1.0","keychain_access_group":null,"ok":true,"protocol":1}
```

The app started, the broker listened, and the app wrote nothing to stdout or stderr. The agent stopped it with `SIGTERM`. Touch ID answers `not_available` (the keyboard is not paired), the keychain helper has no access group, and the owner has not decided about notifications yet. So on this Mac today: the owner check uses the passphrase, the vault unlocks with the passphrase, and the Inbox card shows "You did not allow notifications yet."

### Checks for the caller check and the agent profile (I2)

Worktree branch of the isolation worker, after a fast-forward to `goal-v1` at `85e0a55`. All commands ran from the repository root.

| Command | Result |
| --- | --- |
| `cargo fmt --check` | PASS |
| `cargo clippy --locked --all-targets --features desktop,vault -- -D warnings` | PASS. No warnings. |
| `cargo test --locked --features desktop,vault` | PASS. 283 tests passed, 0 failed, 8 ignored (the earlier tests that need the network, a live Laya model, or a real host). `isolation_profile` 16, `native_helper` 17. |
| `cargo test --locked --features desktop,vault --test native_helper` | PASS. New: `real_helper_refuses_a_parent_that_is_not_apassy` (each request, also `ping` and a malformed request, gets `caller_not_allowed`; the Rust client maps it to `HelperErrorCode::CallerNotAllowed`), `a_helper_built_without_the_dev_flag_ignores_the_override`. `swift_and_rust_error_codes_match` includes `caller_not_allowed`. |
| `scripts/build-app.sh` | PASS, exit 0. See the lines below. "Keychain: DISABLED (no provisioning profile)." |

`scripts/build-app.sh`, the new lines:

```
ok: the helper has no development caller override
ok: apassy --smoke-test
ok: apassy-mcp --version
ok: apassy-helper refuses the shell, line 1
ok: apassy-helper refuses the shell, line 2
ok: apassy-helper refuses the shell, line 3
ok: apassy-helper ignores APASSY_HELPER_DEV_ANY_CALLER
ok: keychain helper refuses the shell, line 1
ok: keychain helper refuses the shell, line 2
ok: apassy-helper with the signed parent, line 1
ok: apassy-helper with the signed parent, line 2
ok: apassy-helper with the signed parent, line 3
ok: keychain helper with the signed parent, line 1
ok: keychain helper with the signed parent, line 2
ok: helper refuses the signed parent of another bundle
ok: keychain helper refuses the signed parent of another bundle
ok: helper refuses a parent with another identifier
ok: keychain helper refuses a parent with another identifier

==> Check the agent profile with the signed bundle
ok: the agent profile denies the start of Contents/Helpers/ApassyKeychain.app/Contents/MacOS/ApassyKeychain
ok: the agent profile denies the start of Contents/MacOS/apassy-helper
ok: the agent profile denies the start of Contents/MacOS/apassy
ok: apassy-mcp --version in the agent profile
ok: the agent profile denies a copy of the keychain helper
ok: keychain helper copy in the agent profile refuses the caller, line 1
ok: keychain helper copy in the agent profile refuses the caller, line 2
```

Research runs before the code (scratch bundle signed with the Apple Development identity and the hardened runtime): `task_name_for_pid` and `task_info(TASK_AUDIT_TOKEN)` for the parent returned `KERN_SUCCESS` from a signed helper with the hardened runtime. `SecCodeCopyGuestWithAttributes` with the audit token returned `0`. For the signed parent, `SecCodeCopyPath` gave the bundle directory `.../Apassy.app`, and `kSecCodeInfoMainExecutable` gave `.../Apassy.app/Contents/MacOS/apassy`. For `apassy-helper`, `SecCodeCopySelf` gave the helper file itself, not the app bundle. For the keychain helper, it gave `ApassyKeychain.app`. `kSecCodeInfoTeamIdentifier` of both helpers was `7S3F9767BM`. With `/bin/bash` as the parent, `SecCodeCheckValidityWithErrors` returned `-67050`.

## Not verified by the agent

- A real Touch ID prompt. The keyboard is not paired, and a real prompt needs a finger.
- `keychain_store` and `keychain_read` of an item with `.biometryCurrentSet`. They need a profile for the App ID and a paired Touch ID keyboard.
- The invalid item after a fingerprint change.
- The notification permission prompt, a delivered notification, and the 5-second limit of N1. They need a click on "Allow".
- Notifications from a second executable in `Contents/MacOS`. `notify_status` works from it. If macOS does not show its notifications, move the notification commands into a nested bundle, as for the keychain.
- The desktop flows with the real helper: Touch ID unlock, the owner check with a real finger, and a real banner from the app. The tests use a fake helper with the same protocol. Section 3 of the owner steps has the checks.

## Owner steps

### 1. Select the team and get the profile

1. Decide which team owns the App ID `com.wydrox.apassy.keychain`. The only certificate on this Mac is in team `7S3F9767BM` ("Apprife Konrad Alfaro"). A personal team is also possible. An App ID is unique across all teams.
2. Open Xcode > Settings > Accounts. Add the Apple ID that is a member of the team.
3. Connect the Magic Keyboard with Touch ID. Open System Settings > Touch ID & Password. Make sure that at least one fingerprint is enrolled.
4. Run:

   ```
   APASSY_TEAM_ID=<TEAM_ID> scripts/build-app.sh --provision
   ```

   Xcode registers the App ID and gets a "Mac Team Provisioning Profile". The script embeds the profile and signs the keychain helper with the keychain entitlements.
   The script ends with `Keychain: enabled (team <TEAM_ID>, group <TEAM_ID>.com.wydrox.apassy)`.
   If the certificate is in a different team, set `APASSY_SIGN_IDENTITY` to the SHA-1 of an identity in that team.
5. Later builds find the profile in the Xcode profile folder. Use `APASSY_REQUIRE_KEYCHAIN=1 scripts/build-app.sh` so that a missing profile stops the build.

Alternative without Xcode sign-in: in the developer portal, register the macOS App ID `com.wydrox.apassy.keychain`, make a "macOS App Development" profile with this Mac and the certificate, download it, and run `APASSY_KEYCHAIN_PROFILE=<path> scripts/build-app.sh`.

### 2. Manual checks

Use synthetic values only. Record each result in this document.
Run the steps from the repository root, in one shell, outside the agent profile.
The helpers answer only the signed Apassy app (see [Caller check](#caller-check)). So the steps use a temporary signed parent: a copy of the app with the caller probe as the main program, as in `scripts/build-app.sh`.
Stop the agent hosts during the checks, and delete the copy after the checks: the copy is not in a path that the agent profile protects.
First set, with the SHA-1 of your signing identity:

```
SIGN=<SHA-1 of the Apple Development identity>
P="$(mktemp -d)"
cp -R target/Apassy.app "$P/Apassy.app"
xcrun --sdk macosx swiftc -O -swift-version 5 -target arm64-apple-macos15.0 \
  -o "$P/Apassy.app/Contents/MacOS/apassy" native/ApassyCallerProbe/main.swift
codesign --force --sign "$SIGN" --options runtime --timestamp=none \
  --identifier com.wydrox.apassy --entitlements packaging/Apassy.entitlements "$P/Apassy.app"
H() { "$P/Apassy.app/Contents/MacOS/apassy" "$P/Apassy.app/Contents/MacOS/apassy-helper"; }
KC() { "$P/Apassy.app/Contents/MacOS/apassy" "$P/Apassy.app/Contents/Helpers/ApassyKeychain.app/Contents/MacOS/ApassyKeychain"; }
H=H; KC=KC
```

In the steps, `| $H` and `| $KC` then run the helper through the signed parent. After the checks, run `rm -rf "$P"`.
The copy has the bundle ID `com.wydrox.apassy` at another path. The notification steps 6 to 8 were written for `target/Apassy.app`. The agent did not check them with the copy.

1. Touch ID confirmation (A4). Run `printf '%s\n' '{"cmd":"authenticate","reason":"confirm a manual check"}' | $H`. Touch the sensor. Expect `{"ok":true}`. Run it again and press Cancel. Expect `cancelled`. Run it again. Touch the sensor with a finger that is not enrolled, then select "Use Apassy Passphrase". Expect `fallback`.
2. Store and read (A3). Run `printf '%s\n' '{"cmd":"keychain_store","account":"manual-check","secret_b64":"bWFudWFsLWNoZWNr"}' '{"cmd":"keychain_read","account":"manual-check","reason":"read a manual check value"}' | $KC`. Touch the sensor. Expect `{"access_group":"<TEAM_ID>.com.wydrox.apassy","ok":true}` and `"secret_b64":"bWFudWFsLWNoZWNr"`.
3. Other process. Run `security find-generic-password -s com.wydrox.apassy.vault-unlock`. Expect "The specified item could not be found". The login keychain does not show the item.
4. Fingerprint change (A3). Add a fingerprint in System Settings. Run `printf '%s\n' '{"cmd":"keychain_exists","account":"manual-check"}' '{"cmd":"keychain_read","account":"manual-check","reason":"read a manual check value"}' | $KC`. Expect `"biometry_changed":true` and the error `biometry_changed`, with no prompt. Remove the new fingerprint if you do not need it.
5. Delete (A3). Run `printf '%s\n' '{"cmd":"keychain_delete","account":"manual-check"}' '{"cmd":"keychain_exists","account":"manual-check"}' | $KC`. Expect `"deleted":true`, then `"exists":false`.
6. Notification permission (N1). Run `open target/Apassy.app` once, then quit it. This registers the bundle. Run `printf '%s\n' '{"cmd":"notify_authorize"}' | $H`. Click "Allow". Expect `"authorization":"authorized"`.
7. Notification time and preview (N1, N2). Run `time (printf '%s\n' '{"cmd":"notify","id":"manual-1","title":"Approval waiting","body":"Agent \"Manual\" waits for your decision. Open Apassy to review."}' | $H)`. Expect a banner from Apassy within 5 seconds and `"delivered":true`. The banner must show only the title and the body.
8. Delivery failure (N3). Turn off notifications for Apassy in System Settings > Notifications. Run step 7 again. Expect `notifications_denied`, or `"delivered":false` with `alert` and `notification_center` set to `disabled`. Turn notifications on again.

### 3. App checks (A2, A3, A4)

Use a vault file with synthetic values. Start the app with `open target/Apassy.app`. Record each result in this document.

1. Owner check without Touch ID (A4, this Mac today). Unlock the vault with the passphrase. Open an item and select "Reveal values". Expect the dialog "Confirm that it is you" with "Touch ID is not available: the Touch ID keyboard is not connected or not paired ...". Type a wrong passphrase: expect "The passphrase is incorrect" and no value. Type the passphrase: expect the value, and that it hides after 30 s.
2. Owner check with Touch ID (A4). With the keyboard paired, select "Reveal values". Expect the macOS prompt "Apassy is trying to show the secret values of an item". Touch the sensor: expect the value. Repeat and select Cancel: expect "Touch ID was cancelled" and no value. Repeat for "Approve once", "Rotate token", a grant checkbox, and "Save rule": each shows a prompt, and nothing changes before the check.
3. Setup without a profile (A2, this Mac today). Open Vault > "Vault file, passphrase, unlock method, and backup". Expect "Touch ID can confirm actions, but cannot unlock the vault until the app has a provisioning profile." and no setup button. Lock: the Vault file card shows the same text, and passphrase unlock works.
4. Setup with a profile (A2, A3). After owner step 1, type the passphrase in the Unlock method card and select "Turn on Touch ID unlock". Touch the sensor. Expect "Touch ID unlock is on". Run `security find-generic-password -s com.wydrox.apassy.vault-unlock`: expect "could not be found". Lock, then select "Unlock with Touch ID" and touch the sensor: expect the vault unlocked.
5. Fingerprint change (A3). Add a fingerprint in System Settings. Open the vault file again. Expect "The fingerprints on this Mac changed ..." without a prompt, and passphrase unlock. Expect "Current: passphrase." after unlock.
6. Turn off (A3). Turn Touch ID unlock on again, then select "Turn off Touch ID unlock". Expect "Apassy deleted the unlock key", and after a lock, no "Unlock with Touch ID" button.
7. Passphrase change (A3). With Touch ID unlock on, change the passphrase. Expect "Touch ID unlock is off, because the passphrase changed."
8. Agent profile (I2). After owner step 1, run `APASSY_REQUIRE_KEYCHAIN=1 scripts/build-app.sh` and `cargo test --locked --features desktop,vault --test isolation_profile`. Expect the lines under "Check the agent profile with the signed bundle", and "keychain helper with the signed parent" with `"keychain_access_group":"<TEAM_ID>.com.wydrox.apassy"`. The provisioned keychain helper does not start in the agent profile, and a copy outside the bundle answers `caller_not_allowed`. Record the result.

## Limits

- A development signature is valid on Macs in the profile only. It is not a release.
- Touch ID unlock needs a provisioning profile. Without one, Touch ID can confirm owner actions (A4), but the vault unlocks with the passphrase only.
- The Touch ID unlock item holds the master passphrase. Anyone who passes Touch ID on this Mac for Apassy gets the passphrase through the helper. The passphrase stays the root key.
- The agent profile denies the start, the read, and a change of the helpers in `/Applications/Apassy.app` and in the build bundle ([isolation.md](isolation.md)). A copy of the app in another place is not protected by the profile. The helper caller check still refuses each caller that is not the signed Apassy app that contains the helper. See [Limits of the caller check](#limits-of-the-caller-check).
- `KeychainSecret` and the buffer overwrites do not protect against memory inspection, swap, or crash dumps. The key-memory review (V2) covers this.
- A process that can replace files in `Apassy.app` can replace the helper. The bundle signature does not stop that at run time.
