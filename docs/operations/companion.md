# The iPhone companion

Date: 2026-09-30.
Scope: [ADR 0014](../adr/0014-iphone-companion.md) and the wire in [companion-v1](../contracts/companion-v1.md). The setting is off by default.
Use only synthetic values for tests. This document does not open the real-secret gate.

## 1. What it does

The iPhone app shows the runs that wait for you, and lets you approve or deny them with Face ID. Use it when you are away from the Mac but on the same network, and an agent waits for a decision (120 s).

| The iPhone can | The iPhone cannot |
| --- | --- |
| See a waiting run: the command, the folder, the variable names, the bouncer reason, and the user request | See, copy, or receive a secret value, a placeholder, an agent token, a note, or a hidden detail |
| Approve a run, or approve and remember its pattern, with Face ID | Unlock the vault, or approve anything while the vault is locked |
| Deny a run or an access request | Give access, or change a grant, a rule, a declaration, or a setting |
| See the newest 50 entries of the activity log | Pair another iPhone, or remove another iPhone |
| Remove its own pairing | Reach the Mac outside the local network |

An approval on the iPhone is as strong as Touch ID on the Mac: your Face ID, now, for this run. It goes through the same owner check as every other approval. A notification is never an approval.

## 2. Turn it on

1. Unlock the vault.
2. Open Settings > iPhone companion.
3. Turn on "Allow the iPhone app on this network".

The status then says "Listening on port 48620". Turning it on gives no access: an iPhone must pair first, and pairing needs your owner check.

The listener runs only while the setting is on and the vault is unlocked. A lock, a quit, a backup, a restore, opening another vault file, and a passphrase change stop it at once and drop its key from memory. It starts again after the next unlock when the setting is on. A restore from a backup turns the setting off and removes the paired iPhones and the certificate.

The first start makes a self-signed certificate and keeps it in the vault. The iPhone trusts only that certificate (its pin), not the system trust store.

## 3. Pair an iPhone

Pair on the same Wi-Fi as the Mac. Have the iPhone app open.

1. In Settings > Pair an iPhone, select "Pair an iPhone". The Mac shows a QR code, its name, and a countdown. The code works for 5 minutes and for one pairing.
2. In the iPhone app, select "Scan the code" and scan the QR code. Give the iPhone a name if the app asks. The app asks for Face ID once, and then shows a 6-digit code.
3. On the Mac, the page now says `"NAME" wants to pair. Type the 6-digit code that the iPhone shows.` Type the code and select "Pair". Spaces are ignored. The Mac never shows the code: only the iPhone does.
4. The Mac asks for your owner check (Touch ID or the passphrase). It names the iPhone.
5. The iPhone appears in "Paired iPhones". On the iPhone, select "Continue" to open the Inbox.

"Cancel" closes the pairing window at any step. It needs no owner check.

Why it takes these steps:

- The Mac shows the QR code only. It never puts the link on the pasteboard, because an agent can read the pasteboard. The iPhone app scans the code itself and registers no URL scheme.
- A leaked link alone pairs nothing. A program that reads the link and pairs first gets a code that only its own device shows. You then see a device name that you do not know, and you select "Cancel".
- A wrong code pairs nothing. Three wrong codes close the window. A code that is not 6 digits does not count.
- A right code starts the owner check. Pairing gives authority, so it needs the check.

The Mac keeps at most 5 paired iPhones and one pairing window at a time.

## 4. Daily use

Open the app on the iPhone. The Inbox shows each run that waits, with the time it has waited. Select a run, read it, and select "Approve" (Face ID) or "Deny". "Approve and remember" also teaches the pattern of the run, as on the Mac, when the run has an offer ([learning](learning.md)).

- The iPhone asks the Mac every 2 s while its app is in the foreground. It does not ask in the background, and there are no push notifications. A run that starts to wait while the app is closed shows on the next open, if it still waits.
- The 120 s timeout of the run does not change.
- If you approve on the iPhone and the Mac at the same time, the first approval wins. A run settles once.
- If the run changed after the iPhone showed it, the Mac refuses the approval ("changed") and nothing runs. Read the run again.
- A denial from the iPhone is recorded as a denial by the owner, so it also blocks a remembered pattern ([ADR 0010](../adr/0010-closing-open-decisions.md)).
- An access request can be denied on the iPhone. To give access, use Apassy on the Mac.
- The activity log of the Mac says "Owner approved on the iPhone." for a run that you approved there.

## 5. Remove an iPhone, and reset

- **Remove**: in Settings > Paired iPhones, select "Remove" next to the device. It needs no owner check, because it only takes authority away. It works at once: the iPhone gets `unpaired` and deletes its pairing. An iPhone can also remove its own pairing: "Unpair this iPhone" in its app.
- **Reset pairing**: select "Reset pairing…" and confirm. It removes every iPhone and makes a new certificate. The listener restarts with the new certificate. Use it when you lost an iPhone and do not know which one it was, or when you doubt the certificate. Each iPhone must pair again.
- **A new Face ID enrollment** on the iPhone makes its approval key unusable, by design. The app then asks you to pair again. Remove the old entry on the Mac first.

## 6. What the iPhone sees

For each waiting run the iPhone sees: the agent name, the command, the folder, the variable names, the purpose, the bouncer reason, the user request and where it comes from, the remember offer, and how long the run waits. For an access request: the agent, the credential name, the reason, and the folder. In the activity list: the operation or command and the reason of the newest 50 entries, each cut at 300 characters. The access requests are the newest 50 that are open.

It never gets a secret value, a placeholder, an agent token, a note, or a hidden detail. The iPhone app does not store these texts on disk, and it hides its content in the app switcher. A person who holds the unlocked iPhone can read the inbox, but cannot approve without your Face ID.

## 7. Troubleshooting

| Symptom | What to check |
| --- | --- |
| The iPhone says the Mac is not reachable | The Mac and the iPhone are on the same Wi-Fi. The vault is unlocked (a lock stops the listener). Settings > iPhone companion says "Listening on port …". Some guest and hotel networks stop devices from talking to each other. |
| The iPhone app says to allow local network access | In the iPhone Settings > Privacy & Security > Local Network, turn on Apassy. iOS asks the first time the app connects. If you refused, turn it on there. |
| The Mac asks "Do you want the application Apassy to accept incoming network connections?" | Select "Allow". macOS asks once, the first time the listener starts. If the firewall is on and you refused, open System Settings > Network > Firewall, and allow incoming connections for Apassy. |
| "Nothing listens on the network", or "another program already uses port 48620" | Another program uses the port. Close it, then select "Try again". |
| "The agent broker is not running" | The listener needs the broker of the app. Restart Apassy. |
| The pairing page says "Apassy found no network address for this Mac" | Connect the Mac to Wi-Fi or Ethernet, then select "Pair an iPhone" again. |
| The iPhone says "This link does not work. Another device may have used it." | The link works once. Another device may have used it, or the window ended. Select "Cancel" on the Mac and make a new code. If you do not know the device name on the Mac, do not type its code. |
| The QR code expired | It works for 5 minutes. Select "Cancel", then "Pair an iPhone". |
| The iPhone says the Mac's certificate does not match (pin mismatch), and offers "Forget this Mac" | You reset the pairing, or restored a backup, or another device answers at that address. If you did it, select "Forget this Mac" and pair again. If not, do not pair; check the network. |
| The iPhone is removed from the Mac list but still shows the Inbox | The next request gets `unpaired`, and the app deletes its pairing. Open the app. It shows that it is unpaired. |
| An approval says "changed" or "no longer waits" | The run changed, ended, timed out, or someone else decided. Nothing was approved. |
| The iPhone says the time is wrong (clock skew) | A request must be within 60 s of the Mac time. Set the date and time to automatic on both. |
| The iPhone cannot pair: no Secure Enclave or no Face ID | The iPhone needs a Secure Enclave and enrolled biometry. The Simulator uses software keys and is for development only. |

## 8. Limits

These come from [ADR 0014](../adr/0014-iphone-companion.md), "What this does not protect".

- **The iPhone shows commands.** A run can show a folder path, a host, a command line, and the user request. The iPhone does not store them on disk. Whoever holds the unlocked iPhone can read them.
- **Local network only.** It does not work away from home. A relay ([ADR 0013](../adr/0013-team-alpha-relay.md)) is a later decision.
- **No push notifications.** The iPhone sees a new run only while its app is open. The Mac notifications stay the only push.
- **A compromised Mac.** The Mac is the trust root. A Mac under an attacker's control can show the iPhone a false run. It can already run anything.
- **A stolen, unlocked iPhone can deny.** The request key needs no biometry, so whoever holds the unlocked iPhone can deny runs and access requests, and a denial blocks a remembered pattern. It cannot approve without Face ID. Remove the device on the Mac.
- **Every network of the Mac.** While the setting is on and the vault is unlocked, the listener answers on each network the Mac joins, also a hotel Wi-Fi. Without a paired key it answers nothing useful. Turn the setting off when you do not want this.
- **A new network surface.** A bug in the HTTP parser or the TLS stack is reachable from the local network while the setting is on. The listener reuses `rustls`, limits the size and the time of a request, the connections, and the rate, and refuses each connection from the Mac itself, from any of its addresses, so an agent on the Mac cannot use it.
- **The key of the listener in memory.** `rustls` keeps a copy of the private key in its configuration and does not erase it when the listener stops. A lock drops the configuration, but the memory is not overwritten. Apassy makes no other copy of the key and erases the vault copy, but the parsed key inside `rustls` and `ring` is out of its reach, so "Reset pairing" is how to retire a key.
- **Production credentials.** The owner can approve a run with a production credential on the iPhone, with Face ID, as on the Mac.
- **Give access is not on the iPhone.** It needs the place and the decision of [ADR 0012](../adr/0012-agent-visibility-and-access-requests.md).

## 9. Check the wire (development)

`scripts/companion-interop.sh` checks that the Swift client and the Rust listener work together over the real wire. It builds `examples/companion_dev.rs` and the Swift driver `companion-interop` of `ios/ApassyCompanionKit`, and runs them against each other on `127.0.0.1`.

```
scripts/companion-interop.sh
```

The server uses a synthetic vault in a temporary directory, so the vault of the owner is never touched. The driver uses the real client with software keys in memory. It pairs, reads the inbox, approves a run, approves and remembers a run, denies a run and an access request, checks that a bad signature and a wrong pin fail, and unpairs. The script ends with `companion-interop: PASSED` or `companion-interop: FAILED: <reason>`. It needs macOS with Xcode 27 and takes a few seconds after the build. The protocol of the server is in the header of the example.

