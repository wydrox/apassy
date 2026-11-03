# ADR 0039: Answer access requests from an Apple Watch

Date: 2026-11-03.
Status: accepted by the owner (plan and decisions of 2026-11-03), in implementation on
`feat/apple-watch-access`. Physical Apple Watch acceptance is pending: the Secure Enclave key policy
with wrist detection, the mirrored notification tap, LTE without the iPhone, and Always On redaction.
No release, deployment, account change, or App ID registration is authorized by this ADR.

UX: [flow spec](../product/apple-watch-access/flow-spec.md) (Gate A accepted 2026-11-03).
Builds on [ADR 0033](0033-iphone-access-requests.md), [ADR 0032](0032-connect-onboarding.md) and
contracts [relay-questions-v1](../contracts/relay-questions-v1.md) and
[relay-access-request-v1](../contracts/relay-access-request-v1.md).

## Owner decisions

1. **An independent answering device.**
   - The watch has its own relay device key and its own membership in the vault's questions team.
   - It has its own Secure Enclave answer key.
   - It works over Wi‑Fi or LTE without the iPhone nearby.
   - It is not a remote screen of the iPhone.
2. **Access requests only.**
   - The watch answers ADR 0033 access requests with **Allow once** or **Deny**.
   - It never shows or answers run questions, feed actions, or credential requests.
   - It holds no vault items.
3. **Allow once while the watch is unlocked on the wrist.**
   - This replaces ADR 0033's "fresh Face ID" for this device kind only.
   - It is weaker than Face ID: anyone wearing the owner's unlocked watch can allow.
   - The owner accepted this.
4. **arm64 watches only** (stable Rust has no `arm64_32` std). Older watches cannot install the app.
   The minimum is **watchOS 27**: App Store Connect refuses a watch app without `arm64_32` when its
   minimum is below watchOS 27 (found at the first TestFlight upload, 2026-11-03), and watchOS 27
   runs only on arm64 watches.

## 1. Device kind `watch` (vault schema 24)

- **The kind.**
  - `trusted_device.kind` gains the value `watch`.
  - The schema-19 table has `CHECK (kind IN ('mac', 'iphone'))`. Schema 24 rebuilds `trusted_device`
    with `CHECK (kind IN ('mac', 'iphone', 'watch'))` in one transaction and keeps every row, tombstone
    and column.
  - `TrustedDeviceKind::Watch` stores `watch`.
- **Older clients.**
  - Devices at schema 23 or older refuse schema-24 copies until they update, as with every earlier
    schema step.
  - An old Mac that confirms a watch link does not know the watch marker (section 2). It keeps the
    whole name and writes no answer key, so the watch cannot allow through it.
  - The watch says "Update Apassy on your Mac to connect this watch" when its row has no answer key.
- **The row of a watch is written only by the Mac that confirms its link** (owner check
  `ConfirmQuestionsDevice` / Connect), exactly as for an iPhone. The watch never writes its own row.

## 2. The link name carries the kind

- **The format.** A watch sends its answer key in the device name as
  `<name> ~W<44 characters: b64u compressed P-256 point>`. An iPhone sends
  `<name> ~<44 characters>`, unchanged.
- **Size.** The whole name is at most 64 bytes, so a watch name is at most 17 bytes before the marker.
- **The owner check covers the kind.** The proof of the confirmation names the whole `device_name`,
  so it covers the kind and the key, as it does for an iPhone.
- **A relay that changes the marker gains nothing:**
  - `~W` → `~` makes the Mac write an `iphone` row. That row holds the watch's answer key, whose policy
    is weaker, but the owner check showed "Apple Watch". The confirmation copy (below) makes the kind
    visible before Touch ID.
  - The watch then refuses a row of the wrong kind (`answer_key_changed` path).
- **The Mac confirmation for a watch link says:**
  - "Connect Apple Watch “<name>”"
  - "This watch can allow an access request once while it is unlocked on a wrist. It cannot approve
    runs or change access."

  The safety words are unchanged.

## 3. Answer authentication

| Answer | Watch signs with | Local check | Mac verification |
| --- | --- | --- | --- |
| Access request **Deny** | `sign_key` (relay device key) | none | `access_once`: a row of kind `iphone` **or `watch`**, mapped to this team; signature with `sign_key` |
| Access request **Allow once** | `answer_key` (Secure Enclave P-256) | a fresh `LAContext` evaluated with `.deviceOwnerAuthenticationWithWristDetection`, passed to the signature | `access_once`: as above with `answer_key`, and `answer_key != sign_key` |
| Any **run question** answer (approve, deny, never, always ask, disconnect, correct environment) | — | — | **Refused** for a `watch` row: `owner_auth` treats the device as unknown (`Identity`) for every kind, fail closed |
| Any **feed action** | — | — | **Refused** for a `watch` row |

**The answer key on the watch:**

- A Secure Enclave P-256 key with `.privateKeyUsage` and `.userPresence`, and
  `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`. Removing the passcode destroys the key.
- Each signature gets a new `LAContext`. The context is evaluated with
  `.deviceOwnerAuthenticationWithWristDetection` (it fails when the watch is locked or off the wrist)
  and invalidated after the signature, a failure, a cancel, or the scene going to the background.
- There is one key per questions team.

**What the Mac cannot verify:**

- The Mac cannot attest the key policy from a signature. As for the iPhone, the policy rests on the
  trusted app and the confirmed registration.
- The precise ACL flags (`.userPresence` versus `.devicePasscode`) are confirmed on a physical watch
  before release. The flags live in one function.

The answer bytes, freshness bounds, three-post cap, guards, settle checks and receipts are those of
relay-access-request-v1 §4 to §6, unchanged.

## 4. State on the watch: a questions-only replica vault

- **The replica vault.**
  - The watch keeps one local SQLCipher vault that holds no items. It has the asking vault's sync
    identity (`vault_id` from the handoff), the questions membership, the question key, and the public
    `trusted_device` rows from the ADR 0032 handoff, written by the existing
    `Vault::adopt_question_handoff`.
  - It never syncs: the watch core role has no sync, item, join or iCloud operation.
- **SQLCipher uses Apple's CommonCrypto on watchOS.** `openssl-src` cannot configure OpenSSL for
  watchOS. The iPhone and the Mac keep vendored OpenSSL.
- **The passphrase** is 32 random bytes made by the watch app and kept in the watch keychain
  (`kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`, this device only, no iCloud). The app unlocks
  the replica when it becomes active and suspends it in the background, like the iPhone.
- **One connected vault per watch in v1.** A key rotation or a removal on a Mac makes new requests
  unreadable or refused. The watch then asks to connect again.

## 5. Transport

- **Why.** watchOS does not allow BSD sockets for this kind of app; URLSession is the supported API.
- **The seam.** The core's relay HTTP exchange (`relay_http::exchange`) goes through a process-wide
  external transport when the host installs one (`apassy_core_set_http_transport`, before
  `apassy_core_new`).
  - The host performs each request with URLSession and returns the status, the headers and the body.
  - `Cancel::close` cancels the in-flight external requests.
- **The rules are unchanged:** the same paths, bearer, deadlines, body limits and errors (`Connect`,
  `Broken`, `Protocol`). TLS is the system's (URLSession, with ATS).
- The iPhone and the Mac keep their own client.

## 6. Pairing through the iPhone

- **The iPhone forwards the link.**
  - The watch has no camera. In Settings › Devices › Add Apple Watch, the iPhone scans the Mac's
    Connect code and sends the full link to the watch with WatchConnectivity (`sendMessage`, the watch
    app in the foreground).
  - The iPhone never uses the link itself and does not keep it.
- **What the watch does next.**
  - It makes its relay key and its answer key, and registers the link with the `~W` name.
  - It shows the six safety words.
  - It receives the handoff after the owner confirms on the Mac with Touch ID.
- **The iPhone learns the handoff secret.** It is the owner's trusted vault holder: the same trust
  class (relay-questions-v1 §18). A link scanned on the iPhone is visible to the iPhone in any case.
- **The iPhone shows the state of the watch** (added 2026-11-03, after the first test on a device
  found no place that said why nothing happened).
  - Settings › Devices has an Apple Watch row: Not paired, Apassy not installed, Not connected,
    Connected to "<vault>", or Removed by a Mac.
  - When Apassy is not installed, the row says what the watch app needs: watchOS 27 on Apple Watch
    Series 9 or later, Ultra 2 or later, or SE 3.
  - The watch publishes its connection with `updateApplicationContext`
    (`WatchConnectionReport`: `apassy.watch-state`, and `apassy.watch-vault` for the vault name). It
    sends only the state and the vault name, never a key, a link or a request.
  - The watch's Requests screen says "Connected to "<vault>"".

## 7. Notifications

- The watch registers no push token in v1. The relay's APNs topic is the iPhone app's bundle ID, and a
  watch topic would need a relay change.
- The iPhone's fixed "A question is waiting" alert is mirrored to the watch when the iPhone is locked.
  A tap opens the watch app on Requests.
- There are no notification actions (ADR 0033 §7).

## 8. Threats

| Threat | Control | Residual risk |
| --- | --- | --- |
| Someone wears or holds the owner's unlocked watch | The key works only while the watch is unlocked and on a wrist; taking it off locks it; Allow once is one scoped attempt; the bouncer still checks the run; no durable authority from the watch | A person who coerces the owner, or who has the owner's watch unlocked on their own wrist, can allow one attempt. Taking the watch off the owner's wrist locks it, so a grab-and-run gives no Allow once |
| Stolen watch | Locked off the wrist; the passcode is needed; the owner removes it on a Mac (row tombstone, key rotation) | Deny-only denial of service while unlocked |
| Watch key used for runs | Mac refuses `watch` rows in run and feed paths | none known |
| Relay strips or adds the `~W` marker | Owner check covers the name; Mac copy shows the kind; watch refuses a wrong-kind row | Owner inattention at confirmation |
| iPhone sees the handoff link | Trusted vault holder, same class as today | A compromised iPhone already holds the vault |
| Watch replica file theft | SQLCipher with a keychain passphrase, this device only | — |

## 9. What changes where

- **Mac and shared Rust:**
  - schema 24 and `TrustedDeviceKind::Watch`;
  - the `~W` link name;
  - the confirmation copy;
  - `access_once` accepts `watch`; `owner_auth` and feed refuse `watch`;
  - Devices and Activity show "(Apple Watch)".
- **Core:**
  - the `commoncrypto` build;
  - the external transport;
  - role `watch` with its connect, forget and status operations, and the access-request operations;
  - `scripts/build-ios-core.sh` gains `watch` and `watchsim` slices.
- **Apps:**
  - the watch app (`com.wydrox.apassy.companion.watchkitapp`, embedded in the iPhone app);
  - iPhone Settings › Devices › Add Apple Watch.
- **Relay:** no change.
