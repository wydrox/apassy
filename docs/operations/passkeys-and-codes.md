# Passkeys and one-time codes

Date: 2026-10-09.
Branch: `feat/passkeys-totp`. Contract: [ios-core-v1](../contracts/ios-core-v1.md) (iPhone core) and [browser-v1](../contracts/browser-v1.md) section 9 (browser). The Mac AutoFill extension is in [mac-passkeys](mac-passkeys.md).
Use only synthetic values for tests. This document does not open the real-secret gate.

## 1. Status

The sources for passkeys and one-time codes are in the branch. The target release is 0.4.1 (Mac app, browser extension, iPhone core, and iPhone app). Only the preparation is done: the package versions are 0.4.1 and the changelog has the target note under "Unreleased". Nothing is published, tagged, or uploaded, and the release stays a draft. Do not tell users that these features work on their devices until the [acceptance checklist](#9-acceptance-checklist) is complete.

Evidence at source commit `11ca5b6410aa24c072b6f283cccd6b924d598d4e` (version 0.4.1), by level:

- **Source and CI:** all 12 required pull request checks passed (GitHub lists 13, with a redundant site check). The full Rust suite at `2d93004` passed 1,435 tests, with 19 ignored and no failures. The Swift tests (247) also passed before the version-only update to `11ca5b6`. The native tests (131) passed again in the signed Mac CI run at `11ca5b6`.
- **Signed Mac build:** CI run `37959199289` on the branch passed. It is a test build, not a release: the DMG is notarized (SHA-256 `e6c998f27a21766c45f3cbb07aebc4d1e83fd3b6cdc1615fddbba9a210278d4f`). An independent check of the artifact confirmed the version and the commit, the signatures of the app, the AutoFill extension, the credential bridge, and the browser guard, the AutoFill provisioning profiles, the staple, and Gatekeeper. It is not published, and no real Mac has installed it.
- **iPhone package:** an IPA of version 0.4.1, build `29859389`, was built from `11ca5b6` with the optimized Rust release profile and exported with a manual Apple Distribution profile (SHA-256 `418dcb2949f5931b965eeb02461a13ef66ae551aa0d58090fc8f229627dc21fc`). An independent check confirmed the signatures and profiles of the app and the AutoFill extension, the AutoFill entitlement, the extension capabilities (passkeys, passwords, one-time codes, Credential Exchange 1.0), and the versions. It supersedes the earlier unoptimized 0.4.0 test IPA. It is not uploaded, and no device has installed it.
- **Mac, synthetic acceptance (DEBUG build, not the signed DMG):** on a synthetic vault, a real unlock, a fresh owner passphrase check, and a one-time code reveal passed. The code `419702` matched an independent RFC 6238 calculation (counter `59718791`), and the passkey metadata screen passed. The DEBUG build is version 0.4.1 with native parts from the older commit `2d93004` (native version 0.3.6). Native AutoFill activation failed from `/tmp` (`bridgeRefused`), because the sandbox of the extension cannot read the bridge there. From a separate folder under `/Applications`, activation passed: macOS showed "Apassy AutoFill is on. Apassy suggests 3 sign-ins." The system "Save passkey" sheet in Helium offered Apassy and led to the Apassy "Save passkey" screen. **No passkey registration or sign-in has completed.** Details: [mac-passkeys](mac-passkeys.md#checks-on-a-mac-2026-10-09).
- **Not run:** checks on a real iPhone (no physical iPhone is available), a completed passkey registration or sign-in on a Mac, a password or code fill through macOS AutoFill, a passkey sign-in and registration in a normal browser with the extension, the positive check of the browser guard (a normal Helium or Chrome stable launch), and Credential Exchange with other apps. A report that Face ID unlocked the vault on an iPhone exists. It names no build, and it is not a passkey Face ID check (D1). Real passkeys, migration, import, sync, and end-to-end runs stay unrun. Public availability on Mac and iPhone is open.

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

Install the app under `/Applications` for the native check. macOS also registers a provider from other places (it registered a copy in `/tmp`), but the sandboxed extension cannot read the bridge file there, so the peer check fails closed with `bridgeRefused`. The signed Mac CI build passed its provider tests. Acceptance of the provider on a real Mac remains open: the DEBUG build activated AutoFill from `/Applications` on a synthetic vault, and no passkey, password, or code request has completed through macOS yet ([checks on a Mac](mac-passkeys.md#checks-on-a-mac-2026-10-09)).

## 8. Browser

The browser extension asks for site access to https pages and `localhost` as an optional permission. The browser asks for it only after you turn on passkeys in the extension popup. Code filling is a separate command of the extension that uses the same Apassy owner check. The caller check ([browser-v1](../contracts/browser-v1.md) section 9.4) accepts signed Helium and Google Chrome stable. It refuses extension-loader and remote-debugging switches. Chrome Beta, Dev, Canary, and other browsers keep their own passkeys. A signature check does not prove a completed passkey sign-in. The acceptance checks with the signed app in a normal browser remain open, and so does the positive check of the guard: the real Helium used for the Mac checks was running with a remote-debugging port, which the guard refuses. The browser preview of T3 rejects resident credentials before any provider runs, so it cannot test Apassy.

## 9. Acceptance checklist

Rules for this list:

- A local test is not a signed-build test. A signed browser or native test is not a real-device test. Mark each item at its own level only.
- "Prepared" is not "completed". The history of an export says "prepared". Only the receiving app can show that it finished.
- Use synthetic data and a test vault. Do not use a real vault or a real account.
- Section 1 records the source, signed-package, and synthetic Mac checks at commit `11ca5b6`. The normal-browser and real-device checks remain open. Write the date, the build, the device, and the outcome in a new dated section, or in the review file, when you run an item.

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

### Status on 2026-10-09 (source `11ca5b6`)

Only the checks with a recorded result are listed. Every item not listed has no result in this document and counts as open.

| # | Status |
| --- | --- |
| L1, L7 | Rust suite at `2d93004` passed: 1,435 tests, 19 ignored, 0 failures. |
| L3, L4 | Swift tests passed (247 in all). The 131 native provider tests (`scripts/build-credential-provider.sh --test`) passed. |
| S2 | Done for the 0.4.1 optimized IPA (build `29859389`): the app and the AutoFill extension are signed with Distribution profiles, and the capabilities are set. The IPA is not uploaded. Not run on a device. |
| S3 | Done by CI run `37959199289` (signed, notarized test build with both profiles). Not installed on a real Mac. |
| S4 | Partly. The signed host refusal test passed in the earlier CI run (`2d93004`) and is not re-recorded for `11ca5b6`. The positive check (normal Helium or Chrome stable accepted) is unrun. |
| S5 | Failed on the DEBUG build: two owner-confirmed local key saves were rejected by macOS (missing required authData flag). The relying party has zero registrations and sign-ins. The flag correction and repeat test are open. |
| D1 | Open. No physical iPhone is available. The Face ID report was a vault unlock only. |
| D8 | Open. AutoFill activation passed on the DEBUG build under `/Applications`. No passkey request completed with Touch ID. |
| D10 | Open. |
| D2–D7, D9 | Open. |

Real-device passkeys, vault migration, import, sync, and end-to-end runs stay unrun.

### Flag correction checks on 2026-10-10 (source `1ad43fb`)

Commit `1ad43fb` changes the shared Rust builder. It now sets `0x5d` for registration and `0x1d` for sign-in. The Mac wire checks reject missing flags before the OS handoff and parse the actual `none` attestation object. Independent review found no defect in the four changed source/test files. Checks passed: 9 Rust passkey integration tests, 8 Rust module tests, 157 native tests, and 48 private integration checks using real Rust output in the Swift validator. The parent also ran the RP core check: 9 checks passed with `@simplewebauthn/server`, covering registration, sign-in, encrypted persistence, and refusal of bad inputs. After matching the synthetic browser and iPhone preview generators to the new policy, 159 browser unit tests and 30 Swift preview/model tests also passed. The latter used an isolated package containing only `ApassyVaultKit` and its tests; it did not use the Rust XCFramework or test the device adapter.

These checks do not prove acceptance by the native system sheet. A corrected signed Mac build, native registration and sign-in in Helium, and iPhone device acceptance remain open. All 12 PR checks passed at `1ad43fb` (CI run `38041218759`). The packages at `11ca5b6` above predate this correction and must be rebuilt before release.

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

This is a synthetic executable test, not a real ExtensionKit launch with restricted AutoFill entitlements. The separate SIGTERM test stopped at signing, before reaching the sandbox; interruption of the sandbox stage is untested. Signed CI on a clean macOS 15 runner remains open.
