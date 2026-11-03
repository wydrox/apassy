# App Store screenshots: Apassy for iPhone and Apple Watch

Unit M18 writes this list (Appendix A.5 of
[implementation-plan-misc.md](../../design/implementation-plan-misc.md)). Unit M19 makes the files
with `ios/ApassyCompanion/UITests/AppStoreScreenshotsUITests.swift` and
`scripts/app-store-screenshots.sh` into `target/app-store/`, and writes the final list here.

## Rules

- **Demo data only** (section "Demo data"). No real name, e-mail, host, or secret. A revealed value is
  a generated demo value.
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

| # | Screen | Exact state | How to reach it in the Simulator |
| --- | --- | --- | --- |
| 1 | **Vault list** (tab Vault) | The demo vault "Personal", unlocked; the folders "Work" and "Side project" and the recent items visible; no sheet, no toast | `-ApassyOpen vault` |
| 2 | **Credential page** of the login "GitHub" (demo) | Username visible, password **masked**, the one-time code tile with its countdown, the website row `github.example.com` with Open | `-ApassyOpen item:<id of GitHub>` |
| 3 | **AutoFill sheet** in Safari | Safari on a demo login page of `github.example.com`; the Apassy credential list of the AutoFill extension shows the match "GitHub · demo@example.com" | UI test opens Safari to the local demo page and taps the password field, then the key icon; or `xcrun simctl` with the AutoFill extension enabled in Settings |
| 4 | **Requests** (tab Requests) with a waiting question | One request: agent "coding agent" on the Mac "Studio", credential "Stripe test key", project `~/Dev/shop`, the buttons **Allow Once** and **Deny** | `-ApassyOpen questions` with the preview questions of `PreviewVaultService+Questions.swift` |
| 5 | **Agent Access** | Two agents with their credentials and states, from the preview feed; no "restricted" or "stale" banner | `-ApassyOpen agents` |
| 6 | **Watchtower** | The counts of weak, reused and old passwords with the demo items "Router" (weak) and two "Reused" items | `-ApassyOpen watchtower` |
| 7 | **Settings** | The list grouped as on the Mac (D5 after M7: Vault, Security, Devices, Agent Access, Tools, About), each row with its tile and status line. Without M7 in the build: the current list (General, Security, Devices, Advanced) | `-ApassyOpen settings` |
| 8 | **Lock** with Face ID over the cover | The Apassy icon on the cover while the Face ID sheet asks (Simulator: Features › Face ID › Enrolled; capture before the match) | Launch with the vault locked and Face ID unlock on |

Notes:

- Screenshot 3 needs the AutoFill extension turned on in the Simulator's Settings › General ›
  AutoFill & Passwords. If the UI test cannot capture Safari reliably, M19 captures it by hand with
  the same demo data.
- The preview data may name a real agent product (for example "Claude Code"), a third-party name.
  Recommendation for the owner: use a neutral demo name such as "coding agent" unless the owner accepts the risk of a 2.3.7 or
  5.2 question; the plan does not decide it. M19 uses the neutral name by default.

## Apple Watch (the size that App Store Connect asks for)

| # | Screen | Exact state | How to reach it |
| --- | --- | --- | --- |
| 1 | **Requests** | Two waiting access requests from the Mac "Studio", rows with the agent and the credential | `-ApassyWatchPreview requests` (`WatchPreviewState`, `WatchPreview.swift`; Simulator or Debug only) |
| 2 | **Request** detail | One request with the agent, the credential, the project, and the buttons **Allow once** and **Deny** | `-ApassyWatchPreview detail` (with `-ApassyWatchScrollToEnd YES` for the buttons) |
| 3 | **This watch** | The connected vault "Personal" and the Mac "Studio"; connected state | `-ApassyWatchPreview connected` |

## Demo data

The same set in the screenshots, the review vault ([review-notes.md](review-notes.md) section 3), and
the demo video:

| Item | Kind | Folder | Values |
| --- | --- | --- | --- |
| GitHub | Login + one-time code | Work | `demo@example.com`, generated password, random TOTP secret, `github.example.com` |
| Stripe test key | API key | Side project | `sk_test_` followed by random characters (not a real key format check) |
| Deploy server | SSH key | Work | a new random Ed25519 key |
| Router | Login | — | `admin`, password `password1` (weak, for Watchtower) |
| Mail | Login | — | `demo@example.com`, the same password as "Forum" (reused) |
| Forum | Login | — | `demo@example.com`, the same password as "Mail" (reused) |
| GitHub (copy) | Login | Work | the same as GitHub (for Find duplicates) |
| Wi-Fi at home | Custom (`wifi`) | — | network name `DemoNet`, a generated password |
| Notes | Custom (`note`) | — | "Demo note" |

Mac name: "Studio". Agent: "coding agent" (see the note above). Vault name: "Personal" for the
screenshots, "App Review" for the review vault.

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
