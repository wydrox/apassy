# App Store screenshots: Apassy for iPhone and Apple Watch

Unit M18 writes this list (Appendix A.5 of
[implementation-plan-misc.md](../../design/implementation-plan-misc.md)). Unit M19 makes the files
with `ios/ApassyCompanion/UITests/AppStoreScreenshotsUITests.swift` and
`scripts/app-store-screenshots.sh` into `target/app-store/`, and writes the final list here.

## Rules

- **The demo of the app only** (section "Demo data"): launch with `-ApassyDemo YES`, which opens
  the in-memory demo vault in every build ([ios/README.md](../../../ios/README.md), "The demo"). No
  real name, e-mail, host, or secret. A revealed value is a synthetic demo value.
- The banner "Demo — sample data only" shows at the top of every demo screen. Keep it: it is what
  the build shows, and it says that the values are samples.
- **Light appearance**, English (U.S.), the default text size.
- **Status bar** fixed on every iPhone Simulator before the run:
  `xcrun simctl status_bar <device> override --time 9:41 --dataNetwork wifi --wifiMode active --wifiBars 3 --cellularMode active --cellularBars 4 --batteryState charged --batteryLevel 100`.
- **No price, no plan, no purchase word** in any screenshot (review-notes.md section 4). No Connect
  plan row.
- No text over the screenshots in v1 (plain captures). The owner may add captions later; a caption
  follows the same rules.
- Each screenshot shows the app as it is in the submitted build. A screen that a later unit changes
  (for example Settings after M7) is captured from the build that is submitted.
- **Look at each file before upload** next to the approved mockups (owner rule of 0.5.0).

## Sizes

| Device class | Required | Size (portrait) | Simulator |
| --- | --- | --- | --- |
| iPhone 6.9-inch | Yes (Apple scales it down for the smaller iPhones) | 1320 × 2868 | iPhone 17 Pro Max |
| iPad | No: the app is iPhone only (`TARGETED_DEVICE_FAMILY: "1"`) | — | — |
| Apple Watch | Yes, one size for all watches | 422 × 514 (Ultra) or 416 × 496 (46 mm); use the size that App Store Connect asks for at upload | Apple Watch Ultra 3 (49 mm) or Series 11 (46 mm) |

At most 10 screenshots per class; this list has 8 for the iPhone and 3 for the watch. The first three
iPhone screenshots show in the search results, so they carry the main message.

## iPhone 6.9-inch (1320 × 2868)

Every launch below starts with `-ApassyDemo YES` (give the flag a value when another flag follows
it). `-ApassyOpen` works in the demo of every build; the `:reveal`, `:large`, and `:options` forms
of `item:` only in the Simulator.

| # | Screen | Exact state | Launch arguments |
| --- | --- | --- | --- |
| 1 | **Vault list** (tab Vault) | The demo vault "Demo", unlocked; the folders "Acme" and "Personal" and the items visible; no sheet, no toast | `-ApassyDemo YES -ApassyOpen vault` |
| 2 | **Credential page** of the login "GitHub" (demo, id 100) | Username visible, password **masked**, the one-time code tile with its countdown, the website row with Open | `-ApassyDemo YES -ApassyOpen item:100` |
| 3 | **AutoFill sheet** in Safari | Not possible with the demo: the AutoFill extension never sees demo items. Capture it with a vault of demo data of your own (a Mac vault with the items of "Demo data"), or leave it out | — |
| 4 | **Requests** (tab Requests) with the waiting requests | The run question of Claude Code for "Stripe live key" and the access request of Codex for "OpenAI", both from "Mac mini (demo)" | `-ApassyDemo YES -ApassyOpen decisions` |
| 5 | **Agent Access** | The agents of "Mac mini (demo)" and "MacBook Pro (demo)" with their uses | `-ApassyDemo YES -ApassyOpen agents` |
| 6 | **Watchtower** | The weak, reused, and old passwords of the demo ("Production Postgres" and "Netflix") | `-ApassyDemo YES -ApassyOpen watchtower` |
| 7 | **Settings** | The groups of Settings with their tiles | `-ApassyDemo YES -ApassyOpen settings` |
| 8 | **Lock** with Face ID over the cover | The Apassy icon on the cover while the Face ID sheet asks (Simulator: Features › Face ID › Enrolled; capture before the match) | `-ApassyDemo YES`, then Settings › Security › Lock now (the demo has "Unlock with Face ID" on) |

More demo states, for the video or a replacement screenshot:

| State | Launch arguments, then |
| --- | --- |
| The welcome with "Try the Demo" | No argument, on a fresh Simulator |
| The access request, before the answer | `-ApassyDemo YES -ApassyOpen decisions`, tap the request of Codex |
| Allow Once with Face ID | The same, tap Allow Once (Simulator: Features › Face ID › Matching Face) |
| Find duplicates | `-ApassyDemo YES -ApassyOpen settings:general`, tap Find duplicates |
| A revealed password | `-ApassyDemo YES -ApassyOpen item:109:reveal` (Simulator only) |
| History | `-ApassyDemo YES -ApassyOpen decisions`, tap History |
| "Not available in the demo" | Settings › Devices › Pair with a Mac |

Notes:

- Screenshot 3 cannot come from the demo: the AutoFill extension never sees a demo item (by
  design). It needs a vault of demo data of its own on the Simulator (the items of "Demo data",
  made on a Mac or with "iCloud · Free") and the AutoFill extension turned on in Settings › General
  › AutoFill & Passwords. If that is too much for v1, leave screenshot 3 out (7 screenshots).
- The demo names real agent products ("Claude Code", "Codex", "T3 Code") and real services
  (GitHub, Stripe, OpenAI, Netflix) as sample items, as password managers do in their demos.
  Recommendation for the owner: keep them in the app; if the owner does not accept the risk of a
  2.3.7 or 5.2 question for the store screenshots, rename the agents in `DemoVault.feed` and the two
  waiting requests before M19 captures them.

## Apple Watch (the size that App Store Connect asks for)

| # | Screen | Exact state | How to reach it |
| --- | --- | --- | --- |
| 1 | **Requests** | Two waiting access requests from the Mac "Studio", rows with the agent and the credential | `-ApassyWatchPreview requests` (`WatchPreviewState`, `WatchPreview.swift`; Simulator or Debug only) |
| 2 | **Request** detail | One request with the agent, the credential, the project, and the buttons **Allow once** and **Deny** | `-ApassyDemo YES` (every build: the sample of "See a Sample", from "Mac mini (demo)"), or `-ApassyWatchPreview detail`; add `-ApassyWatchScrollToEnd YES` for the buttons (Simulator or Debug) |
| 3 | **This watch** | The connected vault "Personal" and the Mac "Studio"; connected state | `-ApassyWatchPreview connected` |

## Demo data

The demo of the app (`DemoVault` in `ios/ApassyVaultKit/Sources/ApassyVaultDemo`) is the one set
for the screenshots, the reviewer ([review-notes.md](review-notes.md) section 3), and the demo
video. The ids are those of `-ApassyOpen item:<id>`:

| Id | Item | Kind | Folder | Values |
| --- | --- | --- | --- | --- |
| 100 | GitHub | Login + one-time code | Acme | `octocat`, synthetic password, synthetic TOTP secret, `https://github.com`, a note |
| 101 | Stripe live key | API key (production) | Acme › Billing | a synthetic `sk_synthetic_` token |
| 102 | OpenAI | API key | — | a synthetic token |
| 103 | Production Postgres | Database | Acme › Billing | the weak password `short1` (Watchtower) |
| 104 | Deploy key | SSH key | Acme | a synthetic key |
| 105 | Netflix | Login | Personal | `family@example.com`, `short1` (reused, Watchtower) |
| 106 | Wi-Fi at home | Custom | Personal | synthetic words |
| 107 | GitHub (conflict copy) | Login | Acme | an older synthetic password (a conflict copy) |
| 108 | Old Heroku | API key | — (archived) | a synthetic token |
| 109 | Example Shop | Login + one-time code | Personal | `demo@example.com`, `https://shop.example.com` |
| 110 | Recovery notes | Custom | Personal | a note |
| 111 | Netflix (old) | Login | Personal | the same website and username as Netflix (Find duplicates) |
| 112 | Demo passkey | Login + passkey | Personal | `demo@example.com` on `demo.example.com` |

Vault name: "Demo". Macs: "Mac mini (demo)" (it asks) and "MacBook Pro (demo)" (stale). Agents of
the sample feed: Claude Code, Codex, T3 Code, and "CI on GitHub" (see the note above about agent
product names). Passphrase: `demo passphrase`.

## Demo video (M19)

At most 2 minutes, demo data only, for the App Review attachment (and optionally the App Preview):

1. The Mac: a coding agent in a terminal asks for "Stripe test key" (10 s).
2. The iPhone: the alert "A question is waiting", the Requests tab, the request, Allow Once, Face ID
   (25 s).
3. The Mac: the run gets the credential (10 s).
4. The iPhone: Settings › Devices › Add Apple Watch, the scan of the Mac's code, the safety words on
   the watch and on the Mac, Touch ID on the Mac (35 s).
5. The watch: a new request, Allow once while on the wrist; a second one, Deny (25 s).

An App Preview for the store page has stricter rules (only captured app footage, 15–30 s, no Mac
footage). Recommendation: use the video only as the review attachment in v1.
