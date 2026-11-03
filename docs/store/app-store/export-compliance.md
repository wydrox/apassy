# Export compliance: Apassy for iPhone and Apple Watch

Unit M18 (Appendix A.3 of [implementation-plan-misc.md](../../design/implementation-plan-misc.md)).
This is a **fact sheet and a set of draft answers for the owner's legal check**. It is not legal
advice. Every answer below is a recommendation; the owner decides, and checks the exact questions
in App Store Connect at upload time, because Apple changes their wording.

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

## 2. Draft answers to the App Store Connect questions

App Store Connect asks these questions for the first build when `ITSAppUsesNonExemptEncryption` is not
set, or at App Review submission (wording of 2025–2026; check it at upload).

| Question | Draft answer | Reason |
| --- | --- | --- |
| Does your app use encryption? | **Yes** | Rows of section 1 |
| What type of encryption algorithms does your app implement? | **Standard encryption algorithms instead of, or in addition to, using or accessing the encryption within Apple's operating system** | SQLCipher with OpenSSL, rustls and ring are in the app, beside CryptoKit, CommonCrypto and URLSession |
| Proprietary or non-standard algorithms? | **No** | Section 1 |
| Is your app going to be available on the App Store in France? | **The owner's call** (section 4) | |
| Does your app qualify for an exemption of Category 5, Part 2 (if Apple asks it)? | **The owner's call** (section 3). The draft: the app is a mass-market item (5D992.c), not an exempt item | |

### `ITSAppUsesNonExemptEncryption`

- Today the iPhone and the watch `Info.plist` say `false` (`ios/ApassyCompanion/project.yml`, keys of
  the app and of the watch app). ADR 0023 §8 records that the owner chose this for the TestFlight build.
- With the inventory above, `false` ("only exempt encryption") is **not an accurate description**: the
  app implements standard encryption beyond Apple's, and its main function is confidentiality.
- **Recommendation for the owner:** before the App Store submission, either
  - set `ITSAppUsesNonExemptEncryption` to `true` in `project.yml` for the app and the watch app,
    answer the questions above in App Store Connect, and upload any document that App Store Connect
    asks for (for France: the ANSSI declaration, section 4). After Apple approves, App Store Connect
    gives a code; set `ITSEncryptionExportComplianceCode` to it, so that later builds skip the questions; or
  - keep `false` only if the owner's legal check concludes that the app is exempt from the document
    requirement (for example because the U.S. treatment of publicly available open-source encryption
    applies, section 3) **and** that France needs no declaration. Write the reason down in ADR 0023 D4.
- The change of `project.yml` is a code change and a new build. It is not part of this unit.

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
- **Options for the owner:**
  1. Make the ANSSI declaration (no fee; the decision takes about one month), then make the app
     available in France and answer "Yes".
  2. Remove France from the availability of the first App Store version, answer "No", and add France
     after the declaration.
  3. Conclude, with legal advice, that an exemption applies, and record the reason.
- Recommendation of this unit: option 2 for the first version, then option 1. It does not delay the
  rest of the world.

## 5. Other countries

Some other countries have their own rules for encryption imports. Apple does not ask about them. The owner decides whether to make the app available
there; no document is prepared here.
