# App Store listing: Apassy for iPhone and Apple Watch

Unit M18 of [implementation-plan-misc.md](../../design/implementation-plan-misc.md) (Appendix A.1).
The values are chosen by that plan. The owner can change any of them before submission.

- App: `com.wydrox.apassy.companion` (iPhone), with the embedded watch app
  `com.wydrox.apassy.companion.watchkitapp` and the AutoFill extension `com.wydrox.apassy.companion.autofill`.
- Team: 7S3F9767BM. Minimum iOS 26.0, watchOS 27.0 (ADR 0039 decision 4).
- Language of the listing: English (U.S.). No other localization in v1.

## Limits checked

| Field | Apple limit | Length here |
| --- | --- | --- |
| Name | 30 | 6 (`Apassy`) |
| Subtitle | 30 | 25 |
| Promotional text | 170 | 158 |
| Keywords | 100 bytes | 83 |
| Description | 4000 | 2,217 |
| What's New | 4000 | 625 |

Count again with `python3 -c 'print(len(open(0).read().strip()))'` after an edit.

## App information

| Field | Value |
| --- | --- |
| Name | Apassy |
| Subtitle | Secrets for coding agents |
| Primary category | Developer Tools |
| Secondary category | Utilities |
| Price | Free (tier 0) |
| In-App Purchases | None. Do not add any (see [review-notes.md](review-notes.md), "No In-App Purchase") |
| Content rights | The app shows no third-party content. Answer "No" to "Does your app contain, show, or access third-party content?" |
| Copyright | `2026 Rafal Wyderka` (the owner confirms the legal name or company) |
| Support URL | `https://github.com/wydrox/apassy/issues` |
| Marketing URL | `https://apassy.wyderka.cc` |
| Privacy policy URL | `https://apassy.wyderka.cc/privacy` (the iPhone, watch and relay sections are in `site/src/pages/privacy.astro` since 2026-11-03; check them live after the site deploy) |
| Age rating | 4+ (answers below) |

The name "Apassy" must be free in the App Store. App Store Connect refuses a name that another app
uses. If it is taken, use `Apassy Vault` (12) and keep the subtitle.

## Promotional text (170)

```text
Your vault on your iPhone, opened with Face ID. AutoFill passwords, codes and passkeys. Answer your coding agents' requests from your Mac: Allow Once or Deny.
```

## Keywords (100)

```text
password manager,passkeys,autofill,secrets,api keys,totp,2fa,agents,developer,vault
```

Apple indexes the name and the subtitle too, so the keywords do not repeat "Apassy", "secrets for",
or "coding". 17 bytes are free. Candidates, if the owner wants them: `ssh`, `otp`, `keys`, `claude`
(a third-party name in keywords can cause a rejection under guideline 2.3.7; this plan does not add it).

## Description (4000)

```text
Apassy is the iPhone part of Apassy for the Mac: a password manager made for people who work with coding agents.

Your vault on your iPhone
- Open the same encrypted vault as your Mac, from iCloud Drive or from your Mac through the Apassy relay.
- The vault is a SQLCipher file on this iPhone. It opens with your passphrase, or with Face ID after you turn it on.
- Before you show, copy or fill a secret, Face ID checks that it is you: each time, or once for a time that you choose in Settings. Plain fields such as a username or a website need no check.
- A copied secret stays on this iPhone only and expires after 60 seconds by default.
- Search, folders, a password generator, and Watchtower, which finds weak and reused passwords.
- Find duplicates and merge them.

AutoFill
- Fill passwords and one-time codes in Safari and in apps, after Face ID.
- Sign in with passkeys, and save new passkeys in Apassy. Passkeys with the PRF extension work too.
- Move your passwords, passkeys, cards, notes and other items from another app, such as Passwords or 1Password, with Credential Exchange.

Your agents ask, you answer
- When a coding agent asks your Mac for a credential, your iPhone shows the request: which agent, which credential, which project and command.
- Answer with Allow Once or Deny. Allow Once needs Face ID. The agent gets the credential for that one use only.
- The Mac stays in control: it checks each answer, and its bouncer still checks each run.

Apple Watch
- Answer access requests on your wrist with Allow once or Deny, also when your iPhone is not near.
- Allow once works only while the watch is unlocked on your wrist.
- The watch holds no passwords and never shows a secret.

Private by design
- No Apassy account. No ads. No analytics. No tracking.
- Your vault, your requests and your answers are encrypted on your devices before they go to the Apassy relay. The relay cannot read them.
- The code is open source under the Apache-2.0 license: github.com/wydrox/apassy

You need Apassy for the Mac to make a vault and to connect agents. Get it at apassy.wyderka.cc.

The Apple Watch app needs an Apple Watch Series 9 or later, or an Apple Watch Ultra 2 or later, with watchOS 27 or later.
```

Rules that this text follows ([plans.md](../../product/plans.md) §5 and §3, App Review 3.1):

- It says the same as the App Privacy answers ([app-privacy.md](app-privacy.md)) and the privacy
  page: the vault, the requests and the answers go to the relay only encrypted; device ids, names and
  push tokens are not content, so the text does not call everything on the relay encrypted.
- "No tracking" matches the App Privacy answer "Data Used to Track You: none". "No Apassy account" is
  true, although App Privacy declares a pseudonymous User ID (the relay's ids).
- Face ID: the "Ask for Face ID" setting (every time by default, or a chosen time) is described.

- No price, no plan name, no "Upgrade", "Subscribe", or "Buy", and no word about Apassy Connect. A
  free stand-alone companion (3.1.3(f)) may not have a call to action to buy outside the app, and the
  App Store metadata counts.
- "Free" is not used for the hosted relay. iCloud Drive sync is free, but the description does not need
  the word.
- The description does not say that the hosted relay is for teams.
- "Get it at apassy.wyderka.cc" points to the free Mac app, not to a purchase. Recommendation for the
  owner: keep it. If App Review objects (guideline 2.3.10 or 3.1.3), remove the address and keep "You
  need Apassy for the Mac".

## What's New (4000)

App Store Connect does not show "What's New" for the first version of an app. Use this text from the
second App Store version. Write it from the dated changelog of that release, only with what the
iPhone and the watch change. The text for 0.5.17, from its changelog section. It names no
price and no plan (App Review 3.1); the push gateway is left out until it is live:

```text
- Your Mac over Tailscale: approvals and sync can go straight to your Mac on any network while Tailscale is on. Settings > Devices shows "via your Mac" and the node words to compare with the Mac.
- Your own Linux node can be the home of your approvals and sync.
- Apple Watch: reaches your Mac over Tailscale too.
```

## Age rating

Apple's age rating questionnaire (the version of 2025, with the ratings 4+, 9+, 13+, 16+ and 18+).
The answers describe the app as the code is on 2026-11-03.

| Question | Answer | Why |
| --- | --- | --- |
| Parental controls | No | The app has none. |
| Age assurance | No | The app does not check an age. |
| Unrestricted web access | No | The app has no web view. "Open" on a website row opens Safari (`openURL`). |
| User-generated content | No | The vault is private to the owner and is never shown to other people. |
| Messaging and chat | No | Requests come from the owner's own Mac. People cannot write to each other. |
| Advertising | No | No ads. |
| Cartoon or fantasy violence | None | |
| Realistic violence | None | |
| Prolonged graphic or sadistic realistic violence | None | |
| Profanity or crude humor | None | |
| Mature or suggestive themes | None | |
| Horror or fear themes | None | |
| Medical or treatment information | None | |
| Health or wellness topics | No | |
| Alcohol, tobacco, or drug use or references | None | |
| Simulated gambling | None | |
| Gambling (real money) | No | |
| Contests | None | |
| Sexual content or nudity | None | |
| Graphic sexual content and nudity | None | |
| Loot boxes | No | |

Expected result: **4+**. The watch app has the same rating as the iPhone app.

## Availability

- All countries and regions **except France** (default of 2026-11-03,
  [export-compliance.md](export-compliance.md) §4). Add France after the owner files the ANSSI
  declaration and a new encryption declaration says France "Yes".
- Recommendation for the owner: no pre-order. Release manually after approval, so that the website
  privacy page and the Mac app at the same version are live first (AGENTS.md: all six components at one
  version).

## The marketing and support pages

- Support URL: the GitHub issues of the repository. It is public and needs no account to read; a
  GitHub account is needed to write. Recommendation for the owner: also accept e-mail on the site
  (a `support` address or a contact line on `apassy.wyderka.cc`), because App Review asks that the
  support page leads to a way to contact the developer, and some people have no GitHub account.
- Marketing URL: the site. It must not show a price or a purchase link for the iPhone app
  (3.1.3(f) is about the app, but the reviewer reads the linked pages). The site's pricing page for
  Apassy Connect is a page of the web service, which is allowed. The listing does not link to it.
