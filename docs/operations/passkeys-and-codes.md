# Passkeys and one-time codes

Date: 2026-10-09.
Branch: `feat/passkeys-totp`. Contract: [ios-core-v1](../contracts/ios-core-v1.md) (iPhone core) and [browser-v1](../contracts/browser-v1.md) section 9 (browser). The Mac AutoFill extension is in [mac-passkeys](mac-passkeys.md).
Use only synthetic values for tests. This document does not open the real-secret gate.

## 1. Status

The sources for passkeys and one-time codes are in the branch. The target release is 0.4.1 (Mac app, browser extension, iPhone core, and iPhone app). Only the preparation is done: the package versions are 0.4.1 and the changelog has the target note under "Unreleased". Nothing is published, tagged, or uploaded, and the release stays a draft. Do not tell users that these features work on their devices until the [acceptance checklist](#9-acceptance-checklist) is complete.

Evidence at source commit `2d93004`, by level:

- **Source and CI:** all 12 pull request checks passed. The Rust suite passed 1,435 tests, with 19 ignored and no failures. The Swift tests (247) and the native tests (131) passed.
- **Signed Mac build:** CI run `37956053234` built the app from this source, ran the provider tests, and notarized it. Release checks of the signed DMG and app passed (Gatekeeper, hash, strict provisioning profiles), and so did the signed host refusal test.
- **iPhone test package:** a 0.4.0 IPA with Distribution signing exists (SHA-256 `97de55885c031e269f29428defa23a9bc7e7d4f0cb5f5afccb6e8bd7129c726a`). It uses unoptimized Rust and the old build number 1. It is a test package, not the production build. A production build must use optimized Rust. It is not uploaded.
- **Not run:** checks on a real iPhone, checks on a real Mac, a passkey sign-in and registration in a normal browser, and Credential Exchange with other apps. Public availability on Mac and iPhone is open.

## 2. What Apassy supports

| | Passkeys | One-time codes |
| --- | --- | --- |
| Standard | WebAuthn, ES256 (ECDSA P-256 with SHA-256) | RFC 6238 TOTP |
| Limits | One passkey for each login. No other algorithm. | SHA-1, SHA-256, or SHA-512. 6 to 8 digits. A period of 15 to 120 seconds. |
| Not supported | PRF, large blob, attestation other than "none" | HOTP (counter-based), Steam codes |
| iPhone | Sign in, register, remove, Credential Exchange import and export | Show a code, AutoFill a code, Credential Exchange import and export |
| Mac | Item page (metadata and remove), AutoFill extension (see section 7) | Codes on the item page |
| Browser | Extension, two verified browsers (see section 8) | Extension fills a code |

A website that needs an unsupported feature gets an answer that says "not supported". Apassy never makes up a PRF value or a blob. When the website can fall back, the system or the browser handles the request with its own passkey provider.

## 3. How a passkey is kept

- A passkey is part of a login. The key is in the encrypted vault and syncs with it.
- No screen shows or copies the key. An agent cannot read it. A generic read of the item hides it.
- Each sign-in and each registration needs a fresh owner check. Use Face ID or the passphrase on the iPhone. Use Touch ID or the passphrase on the Mac.
- A passkey that is in a vault that syncs counts as a backup-eligible credential. The signature counter is always zero.

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

The Mac extension needs two provisioning profiles. A build without both profiles has no AutoFill extension and no bridge. It cannot offer Apassy as a provider of passkeys, passwords, or codes in other apps. `scripts/build-app.sh` prints `PROVIDER NOT INCLUDED` for such a build. With `APASSY_REQUIRE_PROVIDER=1`, the script fails instead. A build with both valid profiles can include passwords, codes, and passkeys. See [native-app](native-app.md#credential-provider-variants) and [mac-passkeys](mac-passkeys.md). The signed Mac CI build passed its provider tests. Acceptance of the provider on a real Mac remains open.

## 8. Browser

The browser extension asks for site access to https pages and `localhost` as an optional permission. The browser asks for it only after you turn on passkeys in the extension popup. Code filling is a separate command of the extension that uses the same Apassy owner check. The caller check ([browser-v1](../contracts/browser-v1.md) section 9.4) accepts signed Helium and Google Chrome stable. It refuses extension-loader and remote-debugging switches. Chrome Beta, Dev, Canary, and other browsers keep their own passkeys. A signature check does not prove a completed passkey sign-in. The acceptance checks with the signed app in a normal browser remain open.

## 9. Acceptance checklist

Rules for this list:

- A local test is not a signed-build test. A signed browser or native test is not a real-device test. Mark each item at its own level only.
- "Prepared" is not "completed". The history of an export says "prepared". Only the receiving app can show that it finished.
- Use synthetic data and a test vault. Do not use a real vault or a real account.
- Section 1 records the source and signed-package checks at commit `2d93004`. The normal-browser and real-device checks remain open. Write the date, the build, the device, and the outcome in a new dated section, or in the review file, when you run an item.

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
