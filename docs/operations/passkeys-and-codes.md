# Passkeys and one-time codes

Date: 2026-10-09. Status updated 2026-10-11.
Branch: `feat/passkeys-totp`. Contract: [ios-core-v1](../contracts/ios-core-v1.md) (iPhone core) and [browser-v1](../contracts/browser-v1.md) section 9 (browser). The Mac AutoFill extension is in [mac-passkeys](mac-passkeys.md).
Use only synthetic values for tests. This document does not open the real-secret gate.

## 1. Status

The sources for passkeys and one-time codes are in the branch `feat/passkeys-totp`. The target release is 0.4.1 (Mac app, browser extension, iPhone core, and iPhone app). It is not released: the package versions are 0.4.1, and the changelog keeps the target note under "Unreleased". Nothing is published, tagged, or uploaded to a store. Do not tell users that these features work on their devices until the [acceptance checklist](#9-acceptance-checklist) is complete.

Source integration and release validation are different things:

- **Source integration.** The source merge to `main` requires the owner's final approval. A merge is a source decision. It is not a release, and it does not accept any build.
- **Release validation.** The checks below, and the open ones in section 9. The release workflow now holds production until `Cargo.toml` names a version that has a dated section in `CHANGELOG.md` and the `Unreleased` section is empty ([release](release.md#release-eligibility)). While 0.4.1 is under "Unreleased", a green CI run on `main` signs and publishes nothing. The site derives its version from the dated sections, so it still shows 0.3.6.

Current evidence, at source commit `82c641d11aa186c73def49e47a6ce22aabc6291c` (version 0.4.1), by level. The results for `11ca5b6` and `29ea550` that follow are historical and are kept with their own labels.

- **Source and CI:** all 12 required pull request checks passed at `82c641d` (GitHub lists 13, with a redundant site check).
- **Signed Mac build (test build, not a release):** CI run `38076031420`, a manual run of the provider check, passed all steps, and its production job was skipped. It ran 208 native tests with no failures and the signed probe with 61 checks, including the sandbox stage. The DMG is notarized (SHA-256 `3487ee357ab50c8ba248d7da96186b59d530c9c2289c9ce322524f63647a1045`). An independent read-only check of the artifact confirmed the DMG integrity, the version 0.4.1, `ApassyBuildCommit` `82c641d`, the strict signatures of the app, every helper, and the AutoFill extension (team `7S3F9767BM`, hardened runtime), the embedded provisioning profiles and provider entitlements, the staple, and Gatekeeper. That check did not launch or install the app. This DMG is not published and is not the release DMG: no check has accepted a DMG as the release.
- **Mac native acceptance, isolated signed DEBUG build (not the DMG):** the build is version 0.4.1 from `82c641d`. Its main program is a DEBUG binary that replaced the main program of a copy of the signed CI app, so the copy is not notarized as a whole. Its native parts (extension, bridge, helpers) are the exact `82c641d` parts from the verified CI artifact. It ran from its own folder under `/Applications`, with an isolated synthetic vault, and it did not touch the installed `/Applications/Apassy.app`. In Helium, against the synthetic relying party on `http://localhost:4187`, the **native registration and an immediate sign-in with the allow list passed**. The relying party verified both: one credential, one registration, one sign-in. The owner confirmed the key creation. The sign-in used the routine owner check with the public fixture passphrase (not Touch ID). The new identity was offered at once, with no manual AutoFill refresh between the registration and the sign-in. The private wrapper of the relying party used a 240 s challenge deadline; the production deadlines are unchanged. After the test, AutoFill was off (read back from the system), the provider was unregistered, the owned processes were stopped, and the synthetic vault was kept. Details: [mac-passkeys](mac-passkeys.md#native-registration-and-sign-in-on-82c641d-2026-10-11).
- **iPhone package:** an optimized, signed IPA of version 0.4.1, build `29860429`, was exported from source `29ea550` with the optimized Rust release profile and manual Apple Distribution profiles (SHA-256 `2d19097493852d49251c4997e2399a981924316a4a70ef8b67e44be346cd793b`). The diff from `29ea550` to `82c641d` changes the iPhone tree only in a test file (`ios/ApassyCore/tests/core_flow.rs`). An independent check confirmed the strict signatures, the profiles, the AutoFill entitlement, the extension capabilities (passkeys, passwords, one-time codes, Credential Exchange 1.0), and the versions. It is not uploaded, and no device or simulator has run it. It supersedes the earlier 0.4.1 IPA of build `29859389` (`11ca5b6`).
- **Not run:** checks on a real iPhone (no physical iPhone is available), a passkey check with Touch ID on the Mac, a password or code fill through macOS AutoFill, Credential Exchange with other apps, real passkeys, migration, import, sync, and end-to-end runs, and the positive acceptance of the 0.4.1 browser extension in a normal browser. The official Chrome Web Store listing is still version 0.3.4, so the 0.4.1 extension cannot be installed from the store yet. A launch with a remote-debugging port or an extension loader must be refused by the guard, so a debug launch is a negative check only. A user report that Face ID unlocked the vault on an iPhone exists. It names no build, and it is a vault unlock, not a passkey Face ID check (D1). Public availability on Mac and iPhone is open.

Historical results at `11ca5b6` and `2d93004` (superseded by the evidence above):

- **Source and CI at `2d93004`:** the full Rust suite passed 1,435 tests, with 19 ignored and no failures. The Swift tests (247) and the native tests (131) passed before the 0.4.1 version update.
- **Signed Mac build at `11ca5b6`:** CI run `37959199289` passed (DMG SHA-256 `e6c998f27a21766c45f3cbb07aebc4d1e83fd3b6cdc1615fddbba9a210278d4f`, test build). It predates the flag correction and cannot register a passkey. It must not be released.
- **iPhone package at `11ca5b6`:** the IPA of build `29859389` (SHA-256 `418dcb2949f5931b965eeb02461a13ef66ae551aa0d58090fc8f229627dc21fc`) is obsolete.
- **Mac, synthetic acceptance at `11ca5b6` (DEBUG build with native parts of `2d93004`):** a real unlock, a fresh owner passphrase check, and a one-time code reveal passed. The code `419702` matched an independent RFC 6238 calculation (counter `59718791`), and the passkey metadata screen passed. Native AutoFill activation failed from `/tmp` (`bridgeRefused`), because the sandbox of the extension cannot read the bridge there. From a separate folder under `/Applications`, it passed. Two "Save passkey" attempts in Helium were rejected by macOS (missing required authData flag), so no registration completed. Details: [mac-passkeys](mac-passkeys.md#checks-on-a-mac-2026-10-09).

## 2. What Apassy supports

| | Passkeys | One-time codes |
| --- | --- | --- |
| Standard | WebAuthn, ES256 (ECDSA P-256 with SHA-256) | RFC 6238 TOTP |
| Limits | One passkey for each login. No other algorithm. | SHA-1, SHA-256, or SHA-512. 6 to 8 digits. A period of 15 to 120 seconds. |
| Not supported | PRF, large blob, attestation other than "none" | HOTP (counter-based), Steam codes |
| iPhone | Sign in, register, remove, Credential Exchange import and export | Show a code, AutoFill a code, Credential Exchange import and export |
| Mac | Item page (metadata and remove), AutoFill extension (see section 7) | Codes on the item page, AutoFill extension fills a code (see section 7) |
| Browser | Extension, two verified browsers (see section 8) | Extension fills a code |

A website that needs an unsupported feature gets an answer that says "not supported". Apassy never makes up a PRF value or a blob. When the website can fall back, the system or the browser handles the request with its own passkey provider.

## 3. How a passkey is kept

- A passkey is part of a login. The key is in the encrypted vault and syncs with it.
- No screen shows or copies the key. An agent cannot read it. A generic read of the item hides it.
- Each sign-in and each registration needs a fresh owner check. Use Face ID or the passphrase on the iPhone. Use Touch ID or the passphrase on the Mac.
- A passkey that is in a vault that syncs counts as a backup-eligible credential. The signature counter is always zero.

Apple's credential provider API requires backup eligibility (BE) and backup state (BS) together. Apassy sets both on registration and sign-in on every route. These flags describe its provider policy; they do not confirm that another copy of your vault exists. Enable vault sync and verify it on another device, or keep an encrypted backup, before relying on a passkey as your only way to access an account. A credential registered by an earlier build with BS clear now signs with BS set; BE stays unchanged, and no vault migration is needed for this flag change.

### Conflict copies

When two devices change one login at the same time, a sync keeps the older version as an archived conflict copy. If only that copy has the passkey, the owner can restore it from the archive.

- A login that is not a conflict copy has priority. When it has the same passkey (same website and credential ID), active or archived, no copy signs.
- If no such login exists, the restored copy with the lowest item ID signs. This also works after the owner deletes the original.
- An archived item never signs.

### Remove a passkey

"Remove passkey" asks for a fresh owner check. The check applies to the revision of the login that you saw.

- If the login has a password, the login stays. Only the passkey goes.
- If the login has no password, or the password is empty, Apassy deletes the whole login. This includes notes, tags, websites, one-time codes, custom details, history, and agent access. The deletion syncs. The screen says this before you confirm. To keep the data, add a password first, or archive the login.

The website keeps its copy of the public key. Remove the passkey in the account settings of the website too.

## 4. One-time codes

- Add a code in the login form with a hidden detail. The default label is "One-time password". A label of "OTP", "TOTP", or "One-time code" also works.
- Apassy shows a code, not the seed. A code is masked until you pass the owner check, and "Copy code" asks again.
- An imported code can keep a custom title. When its value is an `otpauth://totp` link, Apassy still treats it as a code. A plain Base32 value under a custom title is only a secret.
- The Mac editor hides a visible detail that has an OTP label or looks like a setup key, also when you save without a change.
- Credential Exchange export gives the seed to the other app, after the owner check.

The agent catalog hides setup keys, including visible fields from an earlier build. The decision log masks their stored values. An owner can still bind a hidden setup key to an environment variable and grant process access. The dialog names the field and says that programs can make one-time codes. The owner proof names the field, variable, delivery mode, and setup-key status. Automatic batch binding refuses setup keys, including a field that becomes a setup key while its dialog is open.

## 5. Upgrade to schema 17

Passkeys need vault schema 17. Earlier builds use schema 16.

1. Make a backup of the vault ([backup-restore](backup-restore.md)).
2. Update every Mac and iPhone that shares the vault to builds that have schema 17.
3. Unlock the vault on one device. The build migrates the file. You cannot undo this with a build of schema 16: it cannot open a vault of schema 17. Restore the backup if you must go back.
4. Sync the other devices. A device of schema 17 reads a copy of schema 16 and uploads a copy of schema 17.

For release 0.4.1, do not do these steps on a real vault until the open checks in section 9 pass. The backup must be encrypted. An older client cannot sync or read a vault of schema 17, so update all clients before you upgrade the vault.

After the first schema 17 upload, a device of schema 16 cannot sync that vault. It shows that the schema is not supported. Update it. Local tests cover schema 17 publication over a schema 16 copy on the relay, in the iCloud core, and in a folder. Device acceptance remains open (check D9).

## 6. Move to or from another app (iOS 26)

The iPhone app uses the Apple Credential Exchange. The data goes from app to app in memory. Apassy writes no file.

- **Import** reads passwords, TOTP, and ES256 passkeys. Cards, Wi-Fi networks, documents, and notes alone are not imported. A passkey with a damaged key, another algorithm, or PRF or large blob data is not imported. The report gives counts only.
- **Export** gives logins with their passwords, codes, and passkeys. Items of other kinds stay in Apassy.
- Each import and each export asks for its own owner check, before Apassy reads the data or the keys.
- If the vault locks while you pick the other app, the export pauses and sends no credentials. Unlock the same vault to continue. Another vault cannot take its place.
- The history shows "Prepared for a Credential Exchange transfer". This means that the export was prepared. It does not mean that the other app finished the import. Check the other app.

## 7. Mac AutoFill extension and the profile gate

The Mac extension needs two provisioning profiles. A build without both profiles has no AutoFill extension and no bridge. It cannot offer Apassy as a provider of passkeys, passwords, or codes in other apps. `scripts/build-app.sh` prints `PROVIDER NOT INCLUDED` for such a build. With `APASSY_REQUIRE_PROVIDER=1`, the script fails instead.

A build with both valid profiles offers passkeys, passwords, and one-time codes. The app routes all seven calls of the credential bridge (`autofill_list`, `autofill_credential`, `autofill_code`, and `credential_identities` as well as the three passkey calls), and `scripts/build-app.sh` fails unless the provider status says that all three are offered. The extension has no `SupportsConditionalPasskeyRegistration` and no `SupportsCredentialExchange`: a Mac passkey is saved only after the owner check, and Mac Credential Exchange is not implemented. See [native-app](native-app.md#credential-provider-variants) and [mac-passkeys](mac-passkeys.md).

Install the app under `/Applications` for the native check. macOS also registers a provider from other places (it registered a copy in `/tmp`), but the sandboxed extension cannot read the bridge file there, so the peer check fails closed with `bridgeRefused`. The signed Mac CI build of `82c641d` passed its provider tests. On a Mac, a native passkey registration and an immediate sign-in passed in Helium with the exact `82c641d` native parts in an isolated signed DEBUG test app under `/Applications` ([native check](mac-passkeys.md#native-registration-and-sign-in-on-82c641d-2026-10-11)). That is not the acceptance of the release DMG. A Touch ID passkey check, a password fill, and a code fill through macOS AutoFill have not completed yet.

## 8. Browser

The browser extension asks for site access to https pages and `localhost` as an optional permission. The browser asks for it only after you turn on passkeys in the extension popup. Code filling is a separate command of the extension that uses the same Apassy owner check. The caller check ([browser-v1](../contracts/browser-v1.md) section 9.4) accepts signed Helium and Google Chrome stable. It refuses extension-loader and remote-debugging switches. Chrome Beta, Dev, Canary, and other browsers keep their own passkeys. A signature check does not prove a completed passkey sign-in. The acceptance checks with the signed app in a normal browser remain open. The official Chrome Web Store listing is version 0.3.4, so the positive acceptance of the 0.4.1 extension is open. The negative check is expected from a debug launch: a browser with a remote-debugging port or an extension loader is refused by the guard. The Mac native check above does not use the browser extension. The browser preview of T3 rejects resident credentials before any provider runs, so it cannot test Apassy.

## 9. Acceptance checklist

Rules for this list:

- A local test is not a signed-build test. A signed browser or native test is not a real-device test. Mark each item at its own level only.
- "Prepared" is not "completed". The history of an export says "prepared". Only the receiving app can show that it finished.
- Use synthetic data and a test vault. Do not use a real vault or a real account.
- Section 1 records the source, signed-package, and isolated native Mac checks at commit `82c641d` (iPhone package at `29ea550`), and keeps the `11ca5b6` results as history. The normal-browser and real-device checks remain open. Write the date, the build, the device, and the outcome in a new dated section, or in the review file, when you run an item.

### Local tests (source level, no signed build)

| # | Check | Command or place |
| --- | --- | --- |
| L1 | Vault, passkey, merge, and migration tests of the Rust crate | `cargo test --locked --features vault` (includes `tests/vault_migration.rs` and the tests in `src/vault/passkey.rs`) |
| L2 | iPhone core: passkey flow, export, code import, removal metadata | `cargo test -p apassy-core` (see `ios/README.md`) |
| L3 | Swift wrapper | `swift test` in `ios/ApassyVaultKit` |
| L4 | App model tests | `swift test` in `ios/ApassyCompanion/ModelTests` |
| L5 | Extension tests with the mock host | `npm test` in `extension-tests` (Helium only) |
| L6 | The synthetic relying party | `npm run passkey-rp:check` and `npm run passkey-rp:core-check` in `extension-tests` |
| L7 | Desktop controller and UI tests | `cargo test --locked --features desktop,vault` |

### Signed build, simulator, and browser

| # | Check |
| --- | --- |
| S1 | `scripts/build-ios-core.sh` builds the XCFramework for device and simulator. |
| S2 | The iOS app and the AutoFill extension build and sign. The extension has the passkey capability. |
| S3 | `scripts/build-app.sh` makes a signed Mac app with both provider profiles and `APASSY_REQUIRE_PROVIDER=1`. The extension and the bridge pass the signature and entitlement checks. |
| S4 | The signed browser guard accepts normal Helium and Chrome stable. It refuses an unknown browser and unsafe browser switches. |
| S5 | In the signed Mac app, the extension signs in and registers on the synthetic relying party. |

### Real device

| # | Check |
| --- | --- |
| D1 | iPhone: register a passkey on the synthetic site in Safari. Sign in with it. Face ID is required for each action. |
| D2 | iPhone: AutoFill suggests a code and a passkey. A login with only a passkey does not offer a password. |
| D3 | iPhone: remove a passkey from a login with a password. The login stays. Then remove a passkey from a login without a password. The whole login goes, after the warning. |
| D4 | iPhone: Credential Exchange import from another app (ES256 and TOTP SHA-1, SHA-256, SHA-512). Count the results. |
| D5 | iPhone: Credential Exchange export to another app. Check in the receiving app that the data arrived. Do not use the "prepared" event as proof. |
| D6 | iPhone: lock the vault during the pick of the other app. The export pauses. A different vault cannot continue it. |
| D7 | Two devices: make a conflict copy that holds a passkey. Restore it. It signs once. Delete the original. It still signs. |
| D8 | Mac: Safari or an app uses the Apassy extension for a passkey, with Touch ID. |
| D9 | Schema upgrade: a copy of schema 16 on the relay and in iCloud Drive upgrades to schema 17 with an equal content. A device of schema 16 shows the unsupported-schema message. |
| D10 | Browser: a passkey sign-in and a code fill in Helium and Chrome stable on the synthetic site. An unsupported browser keeps its own passkeys. |

### Status on 2026-10-11 (source `82c641d`)

Only the checks with a recorded result are listed. Every item not listed has no result in this document and counts as open. A result at an older commit is labeled with it and is history, not current evidence.

| # | Status |
| --- | --- |
| L1, L7 | Rust suite at `2d93004` passed: 1,435 tests, 19 ignored, 0 failures (history). The 12 required PR checks passed at `82c641d`. |
| L3, L4 | Swift tests passed (247 in all) before `11ca5b6` (history). The 208 native tests (`scripts/build-credential-provider.sh --test`) passed in the signed CI run `38076031420` at `82c641d`. |
| S2 | Done for the optimized IPA of version 0.4.1, build `29860429`, from `29ea550`: the app and the AutoFill extension are signed with Distribution profiles, and the capabilities are set. The IPA is not uploaded. Not run on a device or simulator. |
| S3 | Done by CI run `38076031420` at `82c641d` (signed, notarized test build with both profiles, 61 signed-probe checks) and an independent read-only artifact check. The DMG was not installed or launched. It is not release acceptance. |
| S4 | Partly. The signed host refusal test passed in the earlier CI run (`2d93004`) and is not re-recorded for `82c641d`. The positive check (normal Helium or Chrome stable accepted) is unrun. |
| S5 | Passed natively on 2026-10-11 at `82c641d`: in Helium, a native registration and an immediate allow-list sign-in on the synthetic relying party (one credential, one registration, one sign-in, no manual AutoFill refresh). The owner confirmed the registration. The sign-in used the public fixture passphrase, not Touch ID. The app was an isolated signed DEBUG test app with the exact native parts of the CI artifact, not the release DMG. The failure at `11ca5b6` (missing authData flag) is fixed. |
| D1 | Open. No physical iPhone is available. The Face ID report was a vault unlock only. |
| D8 | Open. The native registration and sign-in passed with the fixture passphrase. A Touch ID passkey request has not completed. |
| D10 | Open. The 0.4.1 extension is not in the store (the listing is 0.3.4). |
| D2–D7, D9 | Open. |

Real-device passkeys, vault migration, import, sync, and end-to-end runs stay unrun.

### Flag correction checks on 2026-10-10 (source `1ad43fb`)

Commit `1ad43fb` changes the shared Rust builder. It now sets `0x5d` for registration and `0x1d` for sign-in. The Mac wire checks reject missing flags before the OS handoff and parse the actual `none` attestation object. Independent review found no defect in the four changed source/test files. Checks passed: 9 Rust passkey integration tests, 8 Rust module tests, 157 native tests, and 48 private integration checks using real Rust output in the Swift validator. The parent also ran the RP core check: 9 checks passed with `@simplewebauthn/server`, covering registration, sign-in, encrypted persistence, and refusal of bad inputs. After matching the synthetic browser and iPhone preview generators to the new policy, 159 browser unit tests and 30 Swift preview/model tests also passed. The latter used an isolated package containing only `ApassyVaultKit` and its tests; it did not use the Rust XCFramework or test the device adapter.

These source checks did not prove acceptance by the native system sheet. The later native run at `82c641d` did (see section 1 and S5), for the isolated signed DEBUG app. iPhone device acceptance remains open. All 12 PR checks passed at `1ad43fb` (CI run `38041218759`). The packages at `11ca5b6` predate this correction and are obsolete.

## 10. Sources

| Part | Place |
| --- | --- |
| Passkey vault code and canonical policy | `src/vault/passkey.rs`, `src/vault/merge.rs` |
| TOTP | `src/otp.rs` |
| iPhone core | `ios/ApassyCore/src/core/passkey.rs`, `credential_export.rs`, `items.rs`, `autofill.rs` |
| Swift wrapper | `ios/ApassyVaultKit/Sources/ApassyVaultKit/Passkeys.swift`, `CredentialExchange.swift`, `PasskeyRemoval.swift` |
| App | `ios/ApassyCompanion/Sources/Vault/CredentialExchangeModel.swift` |
| Mac | `src/desktop/passkey_socket.rs`, `src/desktop/ui/otp.rs`, `native/ApassyAutoFill/` |
| Browser | `src/browser/`, `extension/passkey-bridge.js`, `extension/passkey-page.js` |

### Sandboxed probe checks on 2026-10-10

The corrected signed probe passed locally: 157 native tests, 61 signed-probe checks, no failures or warnings. Its sandboxed client accepted the bridge under `/Applications` and refused the same bundle under `/private/tmp` and `target/`. It independently proved sandbox denial of an existing synthetic file in all three cases. Normal cleanup preserved the shared container and real bridge socket and left no test folders. The cleanup race is fixed: the shared group container can never be deleted, and each run has unique socket and probe-container paths.

This is a synthetic executable test, not a real ExtensionKit launch with restricted AutoFill entitlements. The signed CI run `38076031420` at `82c641d` ran the same probe (208 native tests, 61 signed-probe checks) on its runner. Signed CI on a clean macOS 15 runner remains open.

An earlier SIGTERM test stopped at signing, before the sandbox stage. A new SIGTERM test at `82c641d` reached the sandbox stage: the script exited with status 143 one second after the signal, and cleanup passed. The shared group container and the real bridge socket kept their inodes, the unique probe folders, the container, the application scripts, and the probe app were gone, and no probe process remained. Caveat on timing: the signal arrived about one second after the snapshot, when the first probe (under `/Applications`) had finished its checks, so it hit the second probe (under `/private/tmp`). That probe ended with a trace trap (SIGTRAP) instead of exiting through its own SIGTERM handler. The cause is not investigated. The test did not cover a signal during the first probe, a blocked `codesign`, SIGKILL, power loss, or a real ExtensionKit launch.
