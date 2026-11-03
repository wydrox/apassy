# App Review notes: Apassy for iPhone and Apple Watch

Unit M18 (Appendix A.4 and A.6 of [implementation-plan-misc.md](../../design/implementation-plan-misc.md)).
This file has the text for **App Store Connect › App Review Information**, the demo that the reviewer
uses, and the rules behind "no In-App Purchase".

## 1. App Review Information fields

| Field | Value |
| --- | --- |
| Sign-in required | **No** (there is no account). Leave the user name and password fields empty |
| Contact first name, last name, phone, e-mail | The owner fills them in. Use an address that is read during review |
| Notes | The text of section 2 (at most 4000 characters) |
| Attachment | The demo video of unit M19 (at most 2 minutes, demo data only) |

## 2. Notes (paste this text)

The text has no placeholder: the demo is in the app. Paste it as it is.

```text
Apassy for iPhone is the phone part of Apassy, a free password manager for the Mac that people use with coding agents. The iPhone app is free. It has no account, no ads, no analytics, and no In-App Purchase.

HOW TO TRY IT WITHOUT A MAC (demo)
1. Open Apassy. On the first screen, tap "Try the Demo".
2. A vault of sample data opens at once. A banner at the top says "Demo — sample data only". Nothing of the demo is saved, and nothing is sent.
3. Tap "Leave Demo" in the banner to go back to the first screen.
What you can try: the vault list, search, folders, a login page, Show and Copy of a password and a one-time code (each needs Face ID), the password generator, Watchtower, Find duplicates (Settings > General), and Settings.
Requests: open the Requests tab. A sample Mac, "Mac mini (demo)", waits for two answers: a run question of a coding agent, and an access request of Codex for one key. Tap the access request, then Allow Once, and confirm with Face ID; or tap Deny. The answer stays on the iPhone. Agent Access (Settings) shows the agents of the sample Mac and their uses.
If Face ID is not set up, the passphrase prompt shows; the demo passphrase is "demo passphrase".
In the demo, pairing with a Mac, the relay, the Apple Watch link, import and export, AutoFill, and notifications say "Not available in the demo": they need a real vault.

APPLE WATCH WITHOUT A MAC
On a watch with Apassy and no vault, tap "See a Sample": a sample access request with Allow once and Deny, answered on the watch only.

WITH A MAC
The attached video shows the full flow: a coding agent on the Mac asks for a credential, the iPhone shows the request, the owner taps Allow Once and confirms with Face ID, and the Mac gives the credential to that one run. It also shows Settings > Devices > Add Apple Watch and Allow once on the watch.
To try it with a Mac: install Apassy from https://apassy.wyderka.cc, make a vault, and open it on the iPhone through iCloud Drive or with "From your Mac · Apassy relay".

PERMISSIONS
- Face ID: unlocks the vault and checks each show, copy, fill, and Allow Once (each time by default; Settings > Security > Ask for Face ID can set a time).
- Camera: only to scan the code that the Mac shows. It saves no picture.
- Local Network: only for the older Wi-Fi pairing with a Mac on the same network.
- Notifications (time-sensitive): only after the owner turns them on. The alert says "A question is waiting" and has no other content. A coding agent waits for the answer, so the alert is time-sensitive.
- AutoFill credential provider: fills passwords, one-time codes, and passkeys after Face ID.

APPLE WATCH
The watch app answers access requests of the owner's Mac with Allow once (while the watch is unlocked on the wrist) or Deny. It holds no passwords. It needs watchOS 27 (arm64 watches).

PURCHASES
The app has no purchase, no price, and no link or instruction to buy. All features in this app work without payment.

ENCRYPTION
The app includes its own standard encryption, in addition to Apple's: SQLCipher with OpenSSL for the vault, TLS with rustls, ChaCha20-Poly1305 and ECDSA P-256. Its purpose is the confidentiality of the owner's data. Only standard algorithms; no proprietary cryptography. The Info.plist says ITSAppUsesNonExemptEncryption = YES, and the export compliance answers say the same (mass market). The app is not offered in France until the ANSSI declaration is filed. The source code is public under Apache-2.0: https://github.com/wydrox/apassy

PRIVACY
No tracking. The relay that carries sync and requests keeps device ids, device names, public keys and push tokens for app functionality; the App Privacy answers declare them as linked to the user. The vault, the requests and the answers are end-to-end encrypted. Privacy policy: https://apassy.wyderka.cc/privacy
```

## 3. The demo (what the reviewer uses)

The store build has a demo mode ([ios/README.md](../../../ios/README.md), "The demo"): "Try the
Demo" on the first screen, and `-ApassyDemo` at launch in every build. It is a vault of synthetic
data in memory (module `ApassyVaultDemo`): nothing is written to disk, and nothing touches the
network, the relay, push, iCloud, the keychain, the App Group, or AutoFill. So the reviewer needs no
file, no address, and no passphrase from the owner, and the notes have no placeholder.

What the demo has, so each part of the notes shows something:

- logins with websites and one-time codes, a passkey, API keys, an SSH key, a database, notes,
  folders, one weak and reused password (Watchtower), and a planted duplicate (Find duplicates);
- in Requests, one waiting run question and one waiting access request from "Mac mini (demo)",
  for 30 minutes from the start of the demo (leaving and opening it again starts new ones), and
  past decisions in History;
- in Settings > Agent Access, the agents of two sample Macs with their uses.

Allow Once on the access request runs the real Face ID prompt, with the same reason text as for a
real request, and settles in memory. Deny works without Face ID. The actions that need a real vault
(pairing, the relay, Add Apple Watch, import and export, AutoFill setup, notifications, the Face ID
frequency) say "Not available in the demo".

Before the submission, check on the TestFlight build of the release:

1. A fresh install shows "Try the Demo" under the three ways to start, as a secondary button.
2. The demo opens, the banner shows on every screen and sheet, and "Leave Demo" returns to the
   first screen.
3. Allow Once asks Face ID and shows the answer as sent; Deny settles; Find duplicates finds
   "Netflix (old)".
4. With a real vault on the iPhone, "Try the Demo" is only in Settings > Advanced > About, and the
   real vault is unchanged after leaving the demo.
5. On the watch with no vault, "See a Sample" shows the sample request.

AutoFill with the demo is not possible on purpose: the extension never sees demo items. A reviewer
who asks to try AutoFill needs a vault of their own (make one on a Mac, or with "iCloud · Free").

## 4. No In-App Purchase (Appendix A.6)

- [plans.md](../../product/plans.md) §3: the purchase of Apassy Connect is on the Mac, through a web
  checkout. "The iPhone shows the plan only. There is no In-App Purchase."
- App Review guideline **3.1.3(f), Free Stand-alone Apps**: a free app that is a stand-alone
  companion of a paid web-based service does not need In-App Purchase, **provided there is no
  purchasing inside the app, or calls to action for purchase outside of the app**.
- So no iPhone or watch text, and no App Store metadata, has:
  - a price or a currency sign;
  - "Upgrade", "Subscribe", "Buy", "Purchase", "Pro", "Trial", or "Get Connect";
  - a link to a checkout, a pricing page, or the account page of the web service;
  - an instruction to buy on the Mac or on the website.
- A plan row shows only the plan name and its state (for example "Connect Personal · Active"). Stage 7
  (implementation-plan-s7-connect.md §6) applies the same rule.
- `scripts/check-ios-no-purchase.py` (unit M19) checks the iPhone and watch sources in CI. Its word
  list is shared with stage 7.
- On 2026-11-03 the iPhone and watch sources have no such text (checked with a search for "Upgrade",
  "Subscribe", "€", "checkout", "pricing", and the plan names). The word "Free" in "iCloud · Free"
  names a free sync choice, not a price.
- Guideline 3.1.1 also does not apply: nothing in the app unlocks a feature for money. A Connect
  account on the iPhone (stage 7) only shows its state.

Recommendation for the owner: if App Review asks whether the app is a "reader" app (3.1.3(a)) or a
"multiplatform service" (3.1.3(b)), answer that it is a free stand-alone companion (3.1.3(f)): the
iPhone app has no paid content, and today every feature of the iPhone app works without Connect.

## 5. Other guidelines that a reviewer may raise

| Guideline | Likely question | Answer |
| --- | --- | --- |
| 2.1 App Completeness | "We cannot use the app without a Mac" | "Try the Demo" on the first screen (section 3), "See a Sample" on the watch, and the video. The app is useful alone as a vault with AutoFill |
| 4.2 Minimum Functionality | "The app is only a companion" | It is a full vault with AutoFill, passkeys, a generator, and Watchtower |
| 5.1.1(i) Privacy policy | The policy must cover the iPhone app | Publish [privacy-policy-ios-draft.md](privacy-policy-ios-draft.md) on `/privacy` first |
| 5.1.1(v) Account deletion | — | There is no account, so there is nothing to delete. "Remove from this iPhone" removes the local vault; removing the device on a Mac removes its relay rows |
| 4.5.4 Push notifications | Notifications must not be required | They are optional and only after the owner turns them on |
| AutoFill and passkeys | The extension asks for Face ID for each fill | ADR 0023 §5 |
| 5.1.2 Data use | What is sent to the relay | [app-privacy.md](app-privacy.md) section 2: device ids, names, public keys and push tokens, declared as linked, App Functionality; content only end-to-end encrypted |
| Export compliance | The build says `ITSAppUsesNonExemptEncryption = YES` | [export-compliance.md](export-compliance.md) §2: standard algorithms, mass market, no France until the ANSSI declaration |
| 2.3.10 Other platforms | The description names the Mac | The Mac app is the developer's own app; the text names it to say what the iPhone app needs |
