# Export compliance: Apassy for iPhone and Apple Watch

Unit M18 (Appendix A.3 of [implementation-plan-misc.md](../../design/implementation-plan-misc.md)).
This is a **fact sheet and the answers that follow from the owner's decision of 2026-11-03**
("describe the app correctly", section 2). It is not legal advice. The U.S. and France sections stay
recommendations for the owner's legal check. Check the exact questions in App Store Connect when you
answer them, because Apple changes their wording.

## 1. Inventory: what encryption the app uses

Checked against the code of 2026-11-03.

| Use | Algorithms | Implementation | Code |
| --- | --- | --- | --- |
| The vault at rest (iPhone) | AES-256-CBC with HMAC-SHA512 per page, key from PBKDF2-HMAC-SHA512 (SQLCipher 4 defaults; ADR 0003 forbids weaker settings) | SQLCipher with **vendored OpenSSL**, linked into the app | `Cargo.toml` (`rusqlite` with `bundled-sqlcipher`), `ios/ApassyCore/Cargo.toml` (feature `openssl`), `src/vault/mod.rs` (`SQLCIPHER4_KDF`) |
| The replica vault at rest (watch) | The same SQLCipher settings | SQLCipher with **Apple CommonCrypto** | ADR 0039 §4; `ios/ApassyCore/Cargo.toml` (watch builds without `openssl`) |
| Relay transport (iPhone) | TLS 1.2 and TLS 1.3: ECDHE (X25519, P-256, P-384), AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305, ECDSA and RSA certificates | **rustls 0.23 with ring 0.17**, linked into the app; the system trust store (`rustls-platform-verifier`) | `Cargo.toml` (`rustls`, `ring`) |
| Relay transport (watch) | TLS of the system | **URLSession** with App Transport Security | ADR 0039 §5; `ios/ApassyVaultKit/Sources/ApassyVaultCore/URLSessionCoreTransport.swift` |
| Questions, access requests, answers, the agents feed | ChaCha20-Poly1305 (RFC 8439) under a 256-bit question key; SHA-256 | ring (iPhone core); CryptoKit `ChaChaPoly` is the equivalent | `src/questions/envelope.rs`; contract `relay-questions-v1` §6 |
| Handoff of the question key to a new device | ECDH P-256, HKDF-SHA256, ChaCha20-Poly1305; HMAC-SHA256 for the safety words | `p256` crate and ring | contract `relay-questions-v1` (Connect handoff v2) |
| Device keys and answer keys | ECDSA P-256 signatures | Secure Enclave (CryptoKit) and ring | `ios/ApassyCompanionKit/Sources/ApassyCompanionKit/SecureEnclaveKeys.swift`; ADR 0039 §3 |
| Passkeys (WebAuthn) | ES256 (new passkeys); ES384, EdDSA (Ed25519) and RS256 for imported passkeys; PRF (HMAC-SHA256) | the app's core | changelog `[Unreleased]` "More passkeys" |
| One-time codes (TOTP) | HMAC-SHA1, HMAC-SHA256, HMAC-SHA512 | ring | `ios/ApassyCore/Cargo.toml` |
| Wi-Fi companion (ADR 0020) | TLS 1.3 with a pinned certificate; ECDSA P-256 | Apple frameworks (Network, Security, CryptoKit) | `ios/ApassyCompanionKit/Sources/ApassyCompanionKit/PinnedTLS.swift` |
| Passphrase in the keychain | iOS Data Protection | iOS | ADR 0023 §3 |

What the app does **not** have:

- No proprietary or non-standard algorithm. Every algorithm above is an IETF, NIST or ISO standard.
- No user-selectable or adjustable cryptography, no open cryptographic interface for other apps, and
  no network infrastructure function.
- AES-GCM appears only inside TLS (rustls and URLSession). The app's own sealing is ChaCha20-Poly1305.

Its **main function is information security**: a password manager that keeps secrets confidential.
So the narrow exemptions for "authentication only", "copy protection", or "encryption only inside
Apple's operating system" do not describe this app.

## 2. The decision and the answers

**Owner decision (2026-11-03): "describe the app correctly".** The app implements its own standard
encryption (SQLCipher with OpenSSL, rustls, ring, the ChaCha20-Poly1305 sealing of section 1), and the
purpose of that encryption is the confidentiality of data. It is not limited to the encryption of
Apple's operating system, and it is not one of the narrow exemptions. So:

**What App Store Connect accepts (checked 2026-11-04).** With `true` and no code, Apple's upload check refuses the build (`altool` error 90592, "Invalid Export Compliance Code"), and the API refuses to make a declaration for these answers: `409 Cannot create appEncryptionDeclarations unless either containsProprietaryCryptography is True or containsThirdPartyCryptography and availableOnFrenchStore are both True`. Apple's system needs no documentation and no code for standard algorithms outside France, and it records that answer as `false`. So both `Info.plist` files say **`false`**, and the facts stay as section 1 and the answers of section 2.1 say: standard encryption, mass market, no France. The U.S. obligations of section 3 (the self-classification report) do not depend on this key and stay with the owner. When France is added (section 4), Apple makes a declaration and a code, and the key becomes `true` with `ITSEncryptionExportComplianceCode`.

- `ITSAppUsesNonExemptEncryption` is **`false`** for the iPhone app and the watch app (see above):
  `ios/ApassyCompanion/project.yml` (the `info` properties of the targets `ApassyCompanion` and
  `ApassyWatch`), and the generated `ios/ApassyCompanion/Info.plist` and
  `ios/ApassyCompanion/Watch/Info.plist`. The AutoFill extension's `Info.plist` has no such key;
  App Store Connect reads the key of the app bundle, and the extension ships inside it.
- `ITSEncryptionExportComplianceCode` is not set: Apple gives no code for these answers (section 2.3).

### 2.1 The App Store Connect answers

App Store Connect asks these questions for a build that says `true` and has no compliance code, in
the build's "Missing Compliance" dialog, or in App Store Connect › App Information › App Encryption
Documentation (wording of 2025–2026; check it when you answer, because Apple changes it).

| Question | Answer | Reason |
| --- | --- | --- |
| Does your app use encryption? | **Yes** | Section 1 |
| What type of encryption algorithms does your app implement? | **Standard encryption algorithms instead of, or in addition to, using or accessing the encryption within Apple's operating system** | SQLCipher with OpenSSL, rustls and ring are linked into the app, beside CryptoKit, CommonCrypto and URLSession |
| Proprietary or non-standard algorithms (not accepted by international standard bodies such as IEEE, IETF, ITU)? | **No** | Every algorithm of section 1 is an IETF, NIST or ISO standard |
| Is your app going to be available on the App Store in France? | **No** (the default, section 4) | France is left out of the first App Store version until the ANSSI declaration is filed |
| Category 5, Part 2 exemption (if Apple asks it) | **No exemption**: mass market | The main function is information security, so the narrow exemptions do not apply |
| U.S. classification (if App Store Connect shows or asks it) | **5D992.c, mass market**, License Exception ENC § 740.17(b)(1) | Section 3 |

With the API (section 2.2) the same answers are the attributes of the declaration:

| Attribute of `appEncryptionDeclarations` | Value |
| --- | --- |
| `appDescription` | "A password manager. The app encrypts its vault with SQLCipher (AES-256, OpenSSL), seals requests and answers with ChaCha20-Poly1305, signs with ECDSA P-256, and connects to its relay with TLS (rustls). Only standard algorithms; no proprietary cryptography; no user-adjustable cryptography." |
| `containsProprietaryCryptography` | `false` |
| `containsThirdPartyCryptography` | `true` (OpenSSL, rustls, ring are third-party libraries) |
| `availableOnFrenchStore` | `false` (section 4) |

### 2.2 TestFlight (superseded on 2026-11-04: with `false` a build needs no answer)

- A build that says `true` and has no `ITSEncryptionExportComplianceCode` stops in App Store Connect
  with **"Missing Compliance"** after processing. Until a declaration is attached, TestFlight does not
  give the build to testers, internal testers included.
- Answer it through the **App Store Connect API**, with the same API key that
  `scripts/ios-testflight.sh` uses, so that uploads stay automatic:
  1. Once: make the declaration. `POST /v1/appEncryptionDeclarations` with the attributes of the table
     above and the relationship `app` (the app record of `com.wydrox.apassy.companion`). Keep its id.
     `GET /v1/apps/{app id}/appEncryptionDeclarations` lists existing ones; reuse an approved one
     instead of making a new one.
  2. After each upload: wait until the build is processed. Find it with
     `GET /v1/builds?filter[app]={app id}&filter[version]={build number}` and wait for
     `processingState` `VALID`.
  3. Attach the declaration to the build: `POST /v1/appEncryptionDeclarations/{declaration id}/relationships/builds`
     with `{"data":[{"type":"builds","id":"{build id}"}]}`. The build then leaves "Missing
     Compliance", and the TestFlight group assignment continues.
  4. Read back `GET /v1/builds/{build id}/appEncryptionDeclaration` and the build's TestFlight state
     before the release report claims a processed build in the intended group (AGENTS.md).
- Do not answer with `PATCH /v1/builds/{id}` `usesNonExemptEncryption = false`: that would say the
  opposite of the `Info.plist` and of this file.
- This is an account action. An agent runs it only when the owner has approved the TestFlight upload
  of that release.

### 2.3 Later: the compliance code

- When Apple approves the declaration, App Store Connect › App Information › App Encryption
  Documentation shows the declaration's code and the key to add: `ITSEncryptionExportComplianceCode`.
- Then add `ITSEncryptionExportComplianceCode: <code>` next to `ITSAppUsesNonExemptEncryption: true`
  in both `info` blocks of `project.yml` (and so in both generated `Info.plist` files). Later builds
  with the code skip "Missing Compliance", and step 3 of section 2.2 is no longer needed.
- Make a new declaration (and a new code) if the encryption of section 1 changes in a way that changes
  an answer of section 2.1, or when France is added (section 4).

## 3. United States (EAR): the facts for the owner's check

Recommendations, not legal advice.

- **Classification draft:** mass-market encryption software, ECCN **5D992.c**, under License Exception
  ENC § 740.17(b)(1). It is sold freely to the public, the user cannot change the cryptography, and it
  needs no technical support from the developer to install.
- **Reporting:** since the BIS rule of March 2021, a mass-market end item under § 740.17(b)(1) no longer
  needs the annual self-classification report, except for some components and toolkits. Apassy is an
  end item. The owner confirms that this is still current.
- **Open source:** the source of the whole app is public under Apache-2.0 (github.com/wydrox/apassy).
  Publicly available encryption source code with standard cryptography is not subject to the EAR
  (§ 742.15(b)), and since 2021 it needs no e-mail notification to BIS and NSA. Object code compiled
  from it is treated the same. The App Store binary is compiled from that source, but it is signed and
  distributed by the developer through Apple; the owner's legal check decides if this treatment covers
  the App Store build.
- **Embargoed countries:** Apple already removes the App Store from the embargoed destinations. No
  action is needed in App Store Connect.

## 4. France

Recommendations, not legal advice.

- France controls the supply and import of "means of cryptology" (Law 2004-575 and Decree 2007-663).
  A means that gives confidentiality, such as this app, needs a **declaration to ANSSI** before it is
  supplied in France, unless an exemption of the decree applies.
- Apple asks the France question and, if the answer is "Yes", may ask for the ANSSI document.
- **Default for the first App Store version (recorded 2026-11-03):** France is **not** in the
  availability of the app (App Store Connect › Pricing and Availability), and the declaration says
  `availableOnFrenchStore = false` ("No" to the France question).
- **When the owner files the ANSSI declaration** (no fee; the decision takes about one month): make a
  new encryption declaration that says France "Yes", upload the ANSSI document that App Store Connect
  asks for (`appEncryptionDeclarationDocuments`, or the upload in App Store Connect), add France to the
  availability, and update `ITSEncryptionExportComplianceCode` to the new declaration's code.
- An exemption under the decree is possible only with legal advice; if the owner concludes that one
  applies, record the reason here before adding France without a declaration.

## 5. Other countries

Some other countries have their own rules for encryption imports. Apple does not ask about them. The owner decides whether to make the app available
there; no document is prepared here.
