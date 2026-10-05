# ADR 0020 — The iPhone companion: approve runs from your phone on the local network

Date: 2026-09-30.
Status: ACCEPTED in scope by the owner on 2026-09-30 ("Let's add mobile companion app (native iOS)"). The design choices below are proposals; the open decisions are D1 to D6 in the last section. In the code behind a setting that is off by default.

## Context

- A run that the bouncer does not allow waits for the owner for 120 s ([ADR 0006](0006-process-secrets.md)). The owner decides in the Mac app. When the owner is away from the Mac, the run times out and the agent stops.
- An approval needs a fresh owner check: Touch ID or the passphrase (goal item A4). A notification is never an approval (goal item N4).
- The broker listens only on a Unix socket. Nothing in Apassy listens on the network.
- [ADR 0016](0016-team-alpha-relay.md) proposes a relay for teams. It does not exist yet.

The owner asked for a native iOS companion app in SwiftUI with the Liquid Glass design.

## Decision

### 1. What the companion does

| The phone can | The phone cannot |
| --- | --- |
| See the runs that wait, with the command, the folder, the variable names, the bouncer reason, and the user request | See, copy, or receive a secret value, a placeholder, an agent token, a note, or a hidden detail |
| Approve a run, or approve and remember, with Face ID | Unlock the vault, or approve anything while the vault is locked |
| Deny a run or an access request | Give access, change a grant, a rule, a declaration, or a setting |
| See the newest 50 activity entries | Pair another device, or remove another device |
| Remove its own pairing | Reach the Mac outside the local network |

### 2. Parts

| Part | Where | What it does |
| --- | --- | --- |
| Companion listener | `src/companion/`, in the Mac app process | HTTPS on the local network, TLS 1.3 with a self-signed certificate from the vault. It runs only while the setting is on and the vault is unlocked. |
| Settings > iPhone companion | the Mac app | The setting, the pairing QR code, the pairing confirmation with the owner check, the paired devices, "Remove" and "Reset pairing". |
| Device store | the vault, schema 15 | The certificate and its key, the port, the setting, and each device: name, two public keys, pairing time, last seen. |
| iPhone app | `ios/ApassyCompanion` | SwiftUI, iOS 26, Liquid Glass. Inbox, Activity, Mac. |
| Wire kit | `ios/ApassyCompanionKit` | The wire client, the pinned TLS check, the Secure Enclave keys, the signing strings. It builds and tests on macOS with `swift test`. |

The wire is in [companion-v1](../contracts/companion-v1.md).

### 3. Pairing

The owner selects "Pair an iPhone" on the Mac. The Mac shows a QR code with a one-time link: the hosts, the port, the pin of its certificate, a 32-byte secret, and an expiry 5 minutes later. The Mac never puts the link on the pasteboard, because an agent can read the pasteboard ([isolation](../operations/isolation.md), section 4). The iPhone app scans the code itself; it registers no URL scheme, so no other app can receive the link.

The phone connects with the pin and sends its device ID, its two public keys, a signature by each key, and an HMAC of the secret. Then the phone shows a 6-digit code computed from the secret and both keys. The Mac does not show the code: the owner types it on the Mac. A wrong code pairs nothing, and three wrong codes close the window. A right code starts the owner check (`OwnerAction::PairCompanion`). Pairing gives authority, so it needs the check.

So a leaked link alone pairs nothing. A program that reads the link and pairs first gets a code that only its own device shows. The owner's phone gets "This link does not work", and the owner cancels on the Mac.

### 4. The owner check on the phone

The phone has two Secure Enclave keys. The request key signs each request; it proves that the request comes from the paired phone. The approval key has `.biometryCurrentSet` and no passcode fallback: the Secure Enclave asks for Face ID for each signature, with a new authentication context each time. An approval is a signature by the approval key over the run ID, a digest of the run exactly as the Mac showed it, the action, and the time.

The Mac passes the signature to `OwnerGate::authorize` as a third kind of check, `OwnerCheck::Companion`. The gate loads the approval key of the device from the vault, rebuilds the signed text from the action, checks the time against `PROOF_LIFETIME`, verifies the signature, and checks the vault session before and after, as for Touch ID. `authorize` stays the only function that makes an `OwnerProof`. The proof has the new method `CheckMethod::Companion`. The approval queue takes it as any other proof: it names the run exactly as it waits, it is valid for `PROOF_LIFETIME`, and only in the vault session of the check. A changed run gets `changed` and nothing runs.

So a phone approval is as strong as Touch ID on the Mac: the owner's biometry, now, for this run. It also applies to a production credential: the owner decides, on the Mac or on the phone.

### 5. The network

- The listener is off by default. The owner turns it on in Settings > iPhone companion. Turning it on gives no authority: every endpoint except pairing needs a paired device, and pairing needs the owner check.
- It runs only while the vault is unlocked. A lock stops it at once, drops its TLS key from memory, and ends every waiting run, as today.
- It closes each connection from the Mac itself (a loopback address, or any address of the Mac). An agent on the Mac cannot use it.
- The phone trusts only the pinned certificate. It does not use the system trust store, so a certificate from a public authority cannot replace it.
- Each request has a time within 60 s and a new nonce. A replayed request gets `unauthorized`. A replayed approval finds no waiting run: each run settles once.
- The listener limits the size of a request, the time to send it, the connections from one address, and the rate of requests.

### 6. Dependencies

- `ring` becomes a direct dependency, at the version that `rustls` already uses (0.17.14): ECDSA P-256 verification, HMAC-SHA256, SHA-256. No new code is compiled.
- base64url comes from the crate's own encoder (`src/native/base64.rs`). No base64 dependency.
- `qrcode` 0.14.1 without default features (no `image`): the QR code on the Mac. It has no dependencies. The Mac app draws its modules with egui.
- The iPhone app uses Apple frameworks only: SwiftUI, CryptoKit, Security, LocalAuthentication, VisionKit.

## What this does not protect

- **The phone shows commands.** A run can show a folder path, a host, a command line, and the user request. The phone does not store them on disk and hides them in the app switcher. A person who holds the unlocked phone can read the inbox, but cannot approve without the owner's Face ID.
- **Local network only.** The phone reaches the Mac on the same network. Away from home the companion does not work. A relay (ADR 0013) could carry the same wire later; that is its own decision (D1).
- **No push notifications.** Apple push needs a server of Apassy. The phone sees a new run only while its app is open. The 120 s timeout still applies (D2).
- **A compromised Mac.** The Mac is the trust root. A Mac under the attacker's control can show the phone a false run; it can already run anything.
- **A new Face ID enrollment** makes the approval key unusable, by design. The owner pairs again.
- **The simulator** has no Secure Enclave. A simulator build uses software keys and says so. It is for development only.
- **A stolen, unlocked phone can deny.** The request key needs no biometry, so a person with the unlocked phone can deny runs and access requests. A denial by the owner also blocks a remembered pattern (ADR 0010). The owner removes the device on the Mac.
- **Virtual machines and containers on the Mac.** A process in a VM or a container (for example a Docker guest on a bridge interface) has an address that is not the Mac's, so the listener serves it as a network peer. It still needs a paired key or the owner's typed code.
- **Every network the Mac joins.** While the setting is on and the vault is unlocked, the listener answers on each network of the Mac, also hotel Wi-Fi. Without a paired key it answers nothing useful.
- **The TLS key in memory.** While the listener runs, `rustls` and `ring` hold their own copy of the certificate key. They do not erase it when the listener stops at a lock; the memory is freed, not overwritten. The vault copy is erased. The key only proves the Mac to the phone; it gives no access to the vault.
- **The listener adds a network surface.** A bug in the HTTP parser or the TLS stack is reachable from the local network while the setting is on. The listener reuses `rustls` and the HTTP/1.1 parser of the run proxy, limits sizes and rates, and answers nothing useful without a paired key.

## Open decisions for the owner

| # | Decision | Proposal |
| --- | --- | --- |
| D1 | Access away from the local network. | Later, through the relay of ADR 0013 with the same wire. |
| D2 | Push notifications (APNs needs a server and an Apple developer key). | Later, with the relay. The Mac app notifications stay the only push. |
| D3 | Approval of a production credential from the phone. | Yes, with Face ID, as section 4 says. |
| D4 | Giving access to an access request from the phone. | No in v1: it needs the place and the decision of ADR 0012. Deny only. |
| D5 | Distribution: TestFlight, the App Store, or a development build only. | A development build for the owner first. |
| D6 | The number of paired devices. | At most 5. |

## Relation to other records

- ADR 0006 and ADR 0010 stay valid: an approval needs a fresh owner check; the phone adds one more method.
- ADR 0012 stays valid: the phone can deny an access request, not give access.
- ADR 0013: the relay could carry this wire later. The companion does not need it.
