# App Privacy answers: Apassy for iPhone and Apple Watch

Unit M18 (Appendix A.2 of [implementation-plan-misc.md](../../design/implementation-plan-misc.md)).
This file gives the answers for **App Store Connect › App Privacy** and the reason for each one.
Every answer is a **recommendation for the owner**, not legal advice. Declaring more than the
minimum is always allowed.

Apple's rule, in short: data is "collected" when it leaves the device and the developer (or a
partner of the developer) can access it for longer than it takes to serve the request in real time.
Apple's guidance also says that data that is end-to-end encrypted, so that the developer cannot read
it, does not need to be declared.

## 1. What stays on the iPhone and the watch

| Data | Where | Leaves the device? |
| --- | --- | --- |
| The vault (logins, passwords, codes, passkeys, notes, other items, history of reveals) | SQLCipher file in the App Group container (ADR 0023 §6) | Only as an encrypted copy, for sync (rows 2.1 and 2.2) |
| The vault passphrase | Keychain, `WhenPasscodeSetThisDeviceOnly`, `.biometryCurrentSet` (ADR 0023 §3) | No. iCloud Keychain does not carry it |
| Face ID results | iOS (LocalAuthentication) | No. The app gets only "matched" or "not matched" |
| Camera frames | Only while the code scanner is open | No. The scanner reads the Mac's code and saves no picture |
| QuickType identities (username and website host of each login) | iOS credential identity store (ADR 0023 §5) | No (iOS keeps them on the device) |
| Copied secrets | Local pasteboard, `localOnly`, 60 s by default (ADR 0023 §4) | No. Universal Clipboard does not carry them |
| Watch replica vault and its 32-byte passphrase | Watch, SQLCipher with CommonCrypto, watch keychain (ADR 0039 §4) | No |
| Watch answer key | Secure Enclave of the watch (ADR 0039 §3) | Only the public key (row 2.4) |
| iPhone answer key | Secure Enclave of the iPhone | Only the public key (row 2.4) |

## 2. What leaves the device, and to whom

| # | Flow | Recipient | Content | Readable by the developer? | Code |
| --- | --- | --- | --- | --- | --- |
| 2.1 | iCloud Drive sync of a personal vault | Apple (the owner's iCloud) | The encrypted `.apassy` file and its file metadata | No. Apple holds it for the owner; the developer has no access | `ios/ApassyCompanion/Sources/Vault/ICloudVaultModel.swift`, ADR 0023 §1 |
| 2.2 | Relay sync ("From your Mac · Apassy relay") | The Apassy relay (`apassy-relay.wyderka.cc`, behind a Cloudflare Worker) | The encrypted SQLCipher snapshot, a head signed by the device, versions, sizes, times | Ciphertext: no. Sizes, times, versions, device ids: yes | ADR 0022; relay `docs/OPERATIONS.md` "Vault sync" |
| 2.3 | Questions, access requests, answers, the agents feed | The Apassy relay | Envelopes sealed with ChaCha20-Poly1305 under the question key (relay-questions-v1 §6), the device ids, times, state | Envelopes: no. Device ids, times, states: yes | `src/questions/envelope.rs`; contract `relay-questions-v1`, `relay-access-request-v1`, `relay-feed-v1` |
| 2.4 | Device registration (device link, join, Connect code, Add Apple Watch) | The Apassy relay | The device name, the relay device public key (P-256), the answer public key inside the name (`<name> ~<key>`, a watch `~W<key>`), the device id that the relay assigns | Yes | ADR 0039 §2; `ios/ApassyCompanion/Sources/Models/DeviceName.swift`, `Watch/Sources/Shared/WatchDeviceName.swift` |
| 2.5 | Push notifications (only after the owner turns them on) | The relay keeps the APNs device token (hex) and its environment; it gives tokens to the Cloudflare Worker, and the Worker sends a fixed alert with no content to Apple Push Notification service | The token, `development` or `production`, a constant collapse id | Yes (the token) | `ios/ApassyCompanion/Sources/PushRegistrar.swift`, `crates/apassy-relay/src/server/push.rs`, `crates/apassy-relay/deploy/worker/src/apns.ts` |
| 2.6 | Network metadata of every relay request | Cloudflare (Worker, rate limits) and the relay server | IP address, time, request size | Yes, in transit and in the usual request logs; IP rate limits are counted per Cloudflare location | relay `docs/OPERATIONS.md` (rate limits) |
| 2.7 | Wi-Fi companion (approvals, ADR 0020) | The owner's Mac on the local network, TLS 1.3 with a pinned certificate | Approvals and decisions | No developer server is involved | `ios/ApassyCompanionKit/Sources/ApassyCompanionKit/PinnedTLS.swift` |
| 2.8 | iPhone to watch link (Add Apple Watch) | The owner's watch, through WatchConnectivity | The Mac's Connect link | No developer server is involved; the iPhone does not keep the link (ADR 0039 §6) | `Watch/Sources/Shared/WatchLinkReceiver.swift` |
| 2.9 | Credential Exchange import and export | Another app on the same iPhone, through iOS | Items that the owner selects | No developer server is involved | `ios/ApassyVaultKit/Sources/ApassyVaultKit/CredentialExchange.swift` |
| 2.10 | "Open" on a website row | Safari | The website address | No | `Views/Vault/VaultComponents.swift` |

Not present in the code (checked 2026-11-03): no analytics SDK, no crash reporter, no ad SDK, no
tracking, no web view, no favicon or icon download (credential tiles use local colors,
`Sources/Vault/CredentialLooks.swift`), no breach-check service, no purchase.

Retention at the relay (relay `docs/OPERATIONS.md` §19 and §21):

- A question's sealed card, answers and settle: deleted 10 minutes after it is settled or expires;
  its row (devices, times, state) 24 hours after the post.
- A feed: deleted when its device is removed, by `DELETE /v1/feed`, or 30 days after its last update.
- A vault snapshot: the current and the previous version, until relay sync is turned off for the vault.
- Device rows, device names, public keys and push tokens: until the device is removed on a Mac. A push
  token that Apple refuses for good is marked and no longer used.
- Expired or refused device links: 7 days.

## 3. The answers

### Do you or your third-party partners collect data from this app?

**Yes.** Reason: rows 2.4 and 2.5 are stored on the relay, which the developer runs.

### Tracking

**No, this app does not track.** No data is linked with data of other companies for advertising, and
no data goes to a data broker. The app does not use the AdSupport framework or the advertising
identifier, so it needs no App Tracking Transparency prompt.

### Data types

| Apple category | Type | Declare? | Purposes | Linked to the user? | Used for tracking? | Reason |
| --- | --- | --- | --- | --- | --- | --- |
| Identifiers | Device ID | **Yes** | App Functionality | No (plan value; see the note below) | No | The APNs device token (row 2.5) and the relay device id (row 2.4) |
| Other Data | Other Data Types | **Yes** | App Functionality | No (plan value; see the note below) | No | Device names and device public keys (row 2.4). Describe it as "device names and public keys of your devices, for sync and requests" |
| Contact Info | Name, Email, Phone, Address, Other | No | | | | The app asks for none. A device name can contain a person's name only if the owner types it (iOS gives apps the generic name "iPhone"). See the note below |
| Health and Fitness | all | No | | | | |
| Financial Info | all | No | | | | Cards imported into the vault are vault content: on the device, and only end-to-end encrypted off it |
| Location | Precise, Coarse | No | | | | The app reads no location. IP addresses are not used to find a location |
| Sensitive Info | | No | | | | |
| Contacts | | No | | | | |
| User Content | Emails or Text Messages, Photos or Videos, Audio, Gameplay, Customer Support, Other User Content | No | | | | The vault, the requests and the answers leave the device only end-to-end encrypted (rows 2.1 to 2.3). The camera saves no picture |
| Browsing History | | No | | | | |
| Search History | | No | | | | Search runs in the local vault |
| Identifiers | User ID | No (plan value; see the note below) | | | | No Apassy account. The relay team id of a vault is random |
| Purchases | Purchase History | No | | | | No purchase in the app |
| Usage Data | Product Interaction, Advertising Data, Other Usage Data | No | | | | No analytics. The history of reveals is local |
| Diagnostics | Crash Data, Performance Data, Other Diagnostic Data | No | | | | No crash or analytics SDK. Crash reports that iPhone users share with developers through Apple are Apple's flow and need no declaration |
| Surroundings, Body | | No | | | | |

### Notes for the owner (recommendations)

1. **"Linked to the user."** The plan answers "No" because there is no Apassy account. But the relay
   stores the push token, the device id, the device name and the public keys of a device together
   under the relay team of one vault, and the vault is one person's. Apple counts data as linked when it
   is tied to an account or a device of the user. A pseudonymous team can be read as an account.
   Answering **"Linked to you"** for Device ID and Other Data is always allowed and cannot cause a
   rejection. Recommendation: choose "linked" if in doubt; the label then reads "Data Linked to You:
   Identifiers, Other Data".
2. **User ID.** With the reading of note 1, the relay team id and the device id are an "assigned user
   ID". If the owner chooses "linked", also declare Identifiers › User ID (App Functionality).
3. **Device names.** iOS gives apps the generic name "iPhone" (the app has no user-assigned device name
   entitlement); the owner can type another name in the app. A watch sends `WKInterfaceDevice.current().name`,
   cut to 17 bytes. If names such as "Rafal's iPhone" are expected, Contact Info › Name is a careful
   extra declaration; the plan does not make it.
4. **End-to-end encrypted content.** The vault copies, sealed questions, answers and feeds are not
   declared, by Apple's end-to-end encryption guidance. The developer runs the relay, but has no key:
   the vault passphrase and the question key stay on the owner's devices.
5. **IP addresses.** They are seen in transit by Cloudflare and the relay and kept in the usual request
   logs. They are not used to find a location, to identify a person, or for analytics, so no data type
   is declared. The privacy policy names them.
6. **Stage 7 (Apassy Connect).** A Connect account adds Contact Info › Email (linked, App
   Functionality), and maybe Purchases if the plan state reaches the app. Update these answers in the
   same release that ships the account on the iPhone.
7. **Privacy manifest.** The app has no `PrivacyInfo.xcprivacy` (checked 2026-11-03). App Store
   Connect asks for one when an app or an SDK uses a "required reason API" (for example
   `UserDefaults`, which the app uses, or file timestamps). It is a code change outside this unit: add
   `ios/ApassyCompanion/Resources/PrivacyInfo.xcprivacy` (and one for the watch app and the AutoFill
   extension) with `NSPrivacyTracking = false`, no tracking domains, the collected types of the table
   above, and the API reasons (`CA92.1` for `UserDefaults` in the app's own container; `1C8F.1` for the
   App Group defaults; `C617.1` or `3B52.1` for file timestamps if used). Upload a build and read the
   email from App Store Connect: it names each missing reason.

## 4. The label that App Store Connect will show (with the plan values)

- **Data Not Linked to You:** Identifiers, Other Data.
- **Data Used to Track You:** none.
