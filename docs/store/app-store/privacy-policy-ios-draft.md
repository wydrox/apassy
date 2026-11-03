# Privacy policy draft: the iPhone and Apple Watch apps

Unit M18. The App Store listing links to `https://apassy.wyderka.cc/privacy`
(`site/src/pages/privacy.astro`, updated 2026-10-17). That page covers the Mac app, the browser
extension, and the site. It says "The iPhone companion talks to your Mac on your local network only",
which is **no longer true**: the iPhone app syncs through iCloud Drive or the relay, and gets questions
and push notifications through the relay.

**Published in the source on 2026-11-03** (owner: "describe the app correctly"): the factual sections
of this draft are in `site/src/pages/privacy.astro` ("The iPhone and Apple Watch apps" and "The Apassy
relay"), and that line is gone. They go live with the next site deploy. **Not on the page yet: the
legal parts (the controller, the legal bases, the rights, the processors, the countries).** They stay
recommendations for the owner and need the owner's check; under the GDPR the owner is the controller
of the relay data. The event log row and the backups are on the page as the relay docs state them
(no fixed end date for the log; backups 14 days).

Every flow of [app-privacy.md](app-privacy.md) section 2 (Appendix A.2) is named below:

| Flow (app-privacy.md) | Section of the draft |
| --- | --- |
| 2.1 iCloud Drive sync | "Where your vault goes" |
| 2.2 Relay sync (encrypted vault copies) | "Where your vault goes", "What the Apassy relay keeps" |
| 2.3 Questions, access requests, answers, feeds (sealed) | "Requests from your agents", "What the Apassy relay keeps" |
| 2.4 Device names, device public keys, device ids | "What the Apassy relay keeps" |
| 2.5 Push tokens (Device ID) | "Notifications", "What the Apassy relay keeps" |
| 2.6 IP addresses | "What the Apassy relay keeps" |
| 2.7 Wi-Fi companion | "Requests from your agents" |
| 2.8 iPhone to watch link | "Apple Watch" |
| 2.9 Credential Exchange | "Your vault on the iPhone" |
| 2.10 Websites in Safari | "Your vault on the iPhone" |

---

## The iPhone and Apple Watch apps

*(Text for the page. The headings are `h2` and `h3` of the page.)*

### Your vault on the iPhone

- Your vault is an encrypted file on your iPhone (SQLCipher), opened with your passphrase. If you turn
  on Face ID unlock, the passphrase is kept in the iPhone's keychain on this device only. It never goes
  to iCloud Keychain or to us.
- Apassy asks for Face ID, or your passphrase, each time you show, copy, or fill a secret. A copied
  secret stays on this iPhone and expires after 60 seconds by default.
- For AutoFill, iOS keeps the username and the website host of each login on the iPhone, so it can
  suggest them. Passwords are never given to iOS without your check.
- The camera is used only to scan the code that your Mac shows. No picture is saved.
- When you move items to or from another app (Credential Exchange), iOS carries them between the two
  apps on this iPhone. Nothing goes to us.
- "Open" on a website opens it in Safari.
- There are no Apassy accounts, no ads, no analytics, no crash reporting, and no tracking.

### Where your vault goes

You choose one of these, or none:

- **iCloud Drive.** Apassy reads and writes the encrypted vault file in your iCloud Drive. Apple holds
  it for you under Apple's terms. We have no access to it. Nobody can read it without your passphrase.
- **The Apassy relay.** Apassy sends the encrypted vault file to the Apassy relay and gets the copies
  of your other devices. We cannot read the copies: the key is your passphrase, which never leaves
  your devices.

### Requests from your agents

- When a coding agent on your Mac asks for a credential, your Mac sends the question to your iPhone
  and your Apple Watch through the Apassy relay. The question, your answer, and the list of agents of
  your Macs are sealed on your devices (ChaCha20-Poly1305) with a key that only your devices have. The
  relay passes them on and cannot read them.
- The older Wi-Fi pairing with a Mac talks to your Mac on your local network only, over TLS with a
  pinned certificate.

### Notifications

If you turn on notifications, iOS gives Apassy a push token. Apassy sends it to the Apassy relay, so
the relay can wake your iPhone when a question waits. The relay gives the token to our push service
(a Cloudflare Worker), which asks Apple Push Notification service to show "A question is waiting".
The notification has no other content: no agent, no credential, no vault. Turn notifications off in
Apassy or in iOS Settings, and remove the iPhone on your Mac to delete the token at the relay.

### Apple Watch

- The watch app holds no passwords. It keeps a small encrypted database with the keys it needs to read
  and answer access requests, and its own keys in the watch's Secure Enclave and keychain.
- To connect the watch, your iPhone passes the Mac's code to the watch on your devices
  (WatchConnectivity). The iPhone does not keep it.
- The watch talks to the Apassy relay itself, over Wi-Fi or cellular, as the iPhone does. It registers
  no push token.

### What the Apassy relay keeps

The hosted Apassy relay runs at `apassy-relay.wyderka.cc`. Its code is open source in the Apassy
repository (`crates/apassy-relay`). For each vault that uses it, it keeps:

| Data | Why | How long |
| --- | --- | --- |
| The encrypted vault copy (the current and the previous version), its signed head, versions, sizes, times | Sync between your devices | Until you turn relay sync off for the vault |
| Sealed questions, answers, and their state (devices, times) | Requests from your agents | Sealed content: 10 minutes after the question ends. The row: 24 hours after the question |
| Sealed agent feeds of your Macs | Agent Access on your other devices | Until the Mac is removed, or 30 days after the last update |
| The name of each device (for example "iPhone", or the name you type), its public keys, and the id that the relay gives it | To know which devices belong to the vault and to check their signatures | Until you remove the device on a Mac |
| The push token of each iPhone with notifications on | Notifications | Until you turn notifications off and remove the iPhone, or until Apple says that the token is no longer valid |
| A log of events (device ids, versions, sizes, times; no names of items, no content) | Security and operation | No fixed end date today: as long as the vault's relay team exists, and an encrypted archive after the relay deletes an unused team *(owner: set a limit if wanted)* |
| Backups of the relay data (encrypted) | Recovery | 14 days on the server, with a copy off the server *(owner: state the retention of the off-server copy)* |
| IP address and time of each request | To deliver and protect the service (rate limits, abuse) | In the usual request logs of Cloudflare and the server, for a short time |

We use this data only to run the relay. We do not sell it, share it for advertising, or use it to
profile you.

### Who processes the data *(recommendation for the owner: confirm each line)*

- **Cloudflare, Inc.** runs the Worker in front of the relay, the push service, and this site.
- **Contabo GmbH** hosts the server of the relay *(owner: confirm the provider and the country of the
  server)*.
- **Apple Inc.** delivers push notifications and, if you choose it, holds your vault file in iCloud
  Drive.

### Your rights *(recommendation for the owner: legal check)*

- The controller of the relay data is *(owner: legal name and address)*. Contact: *(owner: e-mail)*,
  or an issue on GitHub.
- The legal basis is the performance of the service that you ask for (GDPR Art. 6(1)(b)), and our
  legitimate interest in protecting it (Art. 6(1)(f)) for the request logs.
- You can see what the relay keeps for your devices on your Mac (Settings › Devices), and delete it:
  remove a device, or turn relay sync off. You can ask us for access, correction, deletion, or a copy
  at the contact above, and complain to your data protection authority (in Poland: the President of
  the Personal Data Protection Office, UODO).
- Apassy is not directed at children under 13 *(owner: confirm the age wording)*.

### Changes

We change this page when the apps change what they send. The date at the top shows the last change.

---

## Notes for the site change

- Done 2026-11-03: the line "The iPhone companion talks to your Mac on your local network only." is
  replaced, and `UPDATED` is 2026-11-03.
- Change "There are no Apassy accounts" only when stage 7 ships the Connect account; then add the
  account e-mail and the Stripe checkout (on the Mac) to the page.
- Keep the page true to [app-privacy.md](app-privacy.md): the App Privacy label and the policy must say
  the same.
