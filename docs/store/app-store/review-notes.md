# App Review notes: Apassy for iPhone and Apple Watch

Unit M18 (Appendix A.4 and A.6 of [implementation-plan-misc.md](../../design/implementation-plan-misc.md)).
This file has the text for **App Store Connect › App Review Information**, the review vault that the
owner prepares, and the rules behind "no In-App Purchase".

## 1. App Review Information fields

| Field | Value |
| --- | --- |
| Sign-in required | **No** (there is no account). Leave the user name and password fields empty |
| Contact first name, last name, phone, e-mail | The owner fills them in. Use an address that is read during review |
| Notes | The text of section 2 (at most 4000 characters) |
| Attachment | The demo video of unit M19 (at most 2 minutes, demo data only) |

## 2. Notes (paste this text)

Replace the two placeholders `<REVIEW VAULT URL>` and `<REVIEW PASSPHRASE>` (section 3) before you
paste it.

```text
Apassy for iPhone is the phone part of Apassy, a free password manager for the Mac that people use with coding agents. The iPhone app is free. It has no account, no ads, no analytics, and no In-App Purchase.

HOW TO TRY IT WITHOUT A MAC (review vault)
1. On the iPhone, open this address in Safari and download the file: <REVIEW VAULT URL>
   Safari saves "App Review.apassy" in Files > On My iPhone > Downloads.
2. Open Apassy. Tap "iCloud · Free". Tap the button to select the file, tap Browse, and select On My iPhone > Downloads > App Review.apassy.
3. Type the passphrase: <REVIEW PASSPHRASE>
4. The vault opens. It holds demo data only (no real accounts).
What you can try: the vault list, search, folders, a login page, Show and Copy of a password and a one-time code (each needs Face ID or the passphrase), the password generator, Watchtower, Find duplicates, Settings, and AutoFill (Settings > General > AutoFill & Passwords > Apassy, then a login form in Safari).

WHAT NEEDS THE OWNER'S MAC
Requests from coding agents, and the Apple Watch app, need Apassy for the Mac with an agent that asks for a credential. The attached video shows the full flow with demo data: a coding agent on the Mac asks for a credential, the iPhone shows the request, the owner taps Allow Once and confirms with Face ID, and the Mac gives the credential to that one run. It also shows the Apple Watch: Settings > Devices > Add Apple Watch on the iPhone, the safety words, and Allow once or Deny on the watch.
To try it with a Mac: install Apassy from https://apassy.wyderka.cc, make a vault, and open it on the iPhone through iCloud Drive or with "From your Mac · Apassy relay" (the Mac shows a code to scan in Add an iPhone or a Mac...).

PERMISSIONS
- Face ID: unlocks the vault and checks each show, copy, fill, and Allow Once.
- Camera: only to scan the code that the Mac shows. It saves no picture.
- Local Network: only for the older Wi-Fi pairing with a Mac on the same network.
- Notifications (time-sensitive): only after the owner turns them on. The alert says "A question is waiting" and has no other content. A coding agent waits for the answer, so the alert is time-sensitive.
- AutoFill credential provider: fills passwords, one-time codes, and passkeys after Face ID.

APPLE WATCH
The watch app answers access requests of the owner's Mac with Allow once (while the watch is unlocked on the wrist) or Deny. It holds no passwords. It needs watchOS 27 (arm64 watches).

PURCHASES
The app has no purchase, no price, and no link or instruction to buy. All features in this app work without payment.

ENCRYPTION
The app uses standard encryption (SQLCipher for the vault, TLS, ChaCha20-Poly1305, ECDSA P-256). See the export compliance answers. The source code is public under Apache-2.0: https://github.com/wydrox/apassy
```

## 3. The review vault (owner)

The store build has no demo mode: the `-ApassyOpen` routes and the preview vault exist only in the
Simulator (`#if targetEnvironment(simulator)` in `Views/Vault/VaultTabView.swift`). So the reviewer
gets a real vault with demo data.

1. On the Mac, make a new vault named **App Review** with a new, random passphrase that you use only
   for this. Do not use relay sync, iCloud Drive, or a questions team for it.
2. Add demo data only, the same set as the screenshots ([screenshots.md](screenshots.md), "Demo
   data"): logins with `example.com` hosts and generated passwords, one login with a one-time code (a
   random TOTP secret), an API key, an SSH key, a note, two folders, one weak and one reused password
   (so Watchtower shows something), and one duplicate pair (so Find duplicates shows something).
3. Export or copy the `.apassy` file. Put it at a stable address that Safari on an iPhone can
   download without a sign-in, for example `https://apassy.wyderka.cc/review/App-Review.apassy`
   (a site change), or a GitHub release asset. The file is encrypted, and its content is demo data,
   so it can be public.
4. **Test the path on a TestFlight build first:** Safari download → Files › On My iPhone › Downloads →
   "iCloud · Free" → Browse → the file → passphrase. `ICloudVaultModel.selectFile` checks only the
   `.apassy` extension, so a file outside iCloud Drive should open. Check that the vault opens, that
   AutoFill works with it, and that the app shows no sync error that would confuse a reviewer. If a
   file outside iCloud Drive does not work, tell the reviewer to save the file to iCloud Drive › Apassy
   instead, and change step 1 and 2 of the notes.
5. Put the address and the passphrase into the notes. Keep the vault and the address unchanged until
   the review ends; App Review can come back weeks later for an update.

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
| 2.1 App Completeness | "We cannot use the app without a Mac" | The review vault (section 3) and the video. The app is useful alone as a vault with AutoFill |
| 4.2 Minimum Functionality | "The app is only a companion" | It is a full vault with AutoFill, passkeys, a generator, and Watchtower |
| 5.1.1(i) Privacy policy | The policy must cover the iPhone app | Publish [privacy-policy-ios-draft.md](privacy-policy-ios-draft.md) on `/privacy` first |
| 5.1.1(v) Account deletion | — | There is no account, so there is nothing to delete. "Remove from this iPhone" removes the local vault; removing the device on a Mac removes its relay rows |
| 4.5.4 Push notifications | Notifications must not be required | They are optional and only after the owner turns them on |
| AutoFill and passkeys | The extension asks for Face ID for each fill | ADR 0023 §5 |
| 5.1.2 Data use | What is sent to the relay | [app-privacy.md](app-privacy.md) section 2 |
| 2.3.10 Other platforms | The description names the Mac | The Mac app is the developer's own app; the text names it to say what the iPhone app needs |
