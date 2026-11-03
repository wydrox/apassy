# App Store package: Apassy for iPhone and Apple Watch

Unit M18 of [implementation-plan-misc.md](../../design/implementation-plan-misc.md) (D4 and
Appendix A), for ADR 0023 D4 ("After TestFlight, with a privacy policy and the export classification
reviewed") and ADR 0039. Prepared 2026-11-03. Nothing here is submitted: **the submission is the
owner's.**

- App: `com.wydrox.apassy.companion` (iPhone, in TestFlight), with the watch app
  `com.wydrox.apassy.companion.watchkitapp` and the AutoFill extension
  `com.wydrox.apassy.companion.autofill`. Team 7S3F9767BM.
- Free. No In-App Purchase ([plans.md](../../product/plans.md) §3; App Review 3.1.3(f)).

## Files

| File | App Store Connect place | Contents |
| --- | --- | --- |
| [listing.md](listing.md) | App Information; the version page; Pricing and Availability; Age Rating | Name, subtitle, promotional text, keywords, description, What's New, categories, URLs, copyright, age rating answers, availability |
| [app-privacy.md](app-privacy.md) | App Privacy | Every data flow with its code, the answer for each data type with its reason, the privacy manifest gap |
| [export-compliance.md](export-compliance.md) | Build › Encryption; `Info.plist` | The encryption inventory, draft answers, `ITSAppUsesNonExemptEncryption`, U.S. and France |
| [review-notes.md](review-notes.md) | App Review Information | The notes to paste, the review vault, the no-purchase rule, likely guideline questions |
| [screenshots.md](screenshots.md) | The version page › Previews and Screenshots | Sizes, the 8 iPhone and 3 watch screenshots with their exact state, the demo data, the demo video |
| [privacy-policy-ios-draft.md](privacy-policy-ios-draft.md) | Privacy Policy URL (`/privacy` on the site) | The text to add to the site's privacy page for the iPhone and watch apps |

Every legal judgement in these files is a **recommendation for the owner**, not legal advice.

## Owner-only checklist

Do these in order. An agent does not do them: they are account changes, publications, or legal
decisions (CLAUDE.md "Git i deploy", AGENTS.md "Apassy releases").

### Before the build

1. **Export answer: decided 2026-11-03** ([export-compliance.md](export-compliance.md) §2):
   `ITSAppUsesNonExemptEncryption` is `true` for the app and the watch. Each TestFlight build needs the
   encryption declaration attached through the API until `ITSEncryptionExportComplianceCode` is set
   (§2.2, §2.3).
2. **France: left out by default** of the first version's availability (§4). The owner can file the
   ANSSI declaration and then add France.
3. **Privacy manifest:** have `PrivacyInfo.xcprivacy` added for the app, the AutoFill extension, and
   the watch app ([app-privacy.md](app-privacy.md) note 7). A code change and a new build.
4. **Publish the privacy page:** the factual iPhone, watch and relay sections are in
   `site/src/pages/privacy.astro` (2026-11-03). Deploy the site and check them live. Add the
   controller name, address, contact and legal bases of
   [privacy-policy-ios-draft.md](privacy-policy-ios-draft.md) if the legal check asks for them.
5. **Support contact:** decide whether GitHub issues alone is enough, or add an e-mail contact on the
   site ([listing.md](listing.md), "The marketing and support pages").
6. **Physical tests that ADR 0039 still lists as pending** (the Secure Enclave key policy with wrist
   detection, the mirrored notification tap, LTE without the iPhone, Always On redaction). App Review
   tests on devices.

### The build

7. Pick the build: the release version shared by all six components (AGENTS.md), with a higher
   `CURRENT_PROJECT_VERSION` than every build in App Store Connect. Upload it with
   `scripts/ios-testflight.sh`. The App Store export signs `aps-environment` as production, and a
   release build registers its push token as `.production` (`PushRegistrar.environment`).
8. Watch the build process in App Store Connect. The build shows "Missing Compliance" until the
   encryption declaration is attached ([export-compliance.md](export-compliance.md) §2.2).

### App Store Connect (the owner's account)

9. **Create the App Store version** of the app record (it exists for TestFlight). Fill in from
   [listing.md](listing.md): name (check that "Apassy" is free), subtitle, categories, promotional
   text, description, keywords, support and marketing URLs, privacy policy URL, copyright.
10. **App Privacy:** enter the answers of [app-privacy.md](app-privacy.md) §3 (all linked; User ID,
    Device ID, Other Data; App Functionality; no tracking). Publish the answers.
11. **Age rating:** answer the questionnaire as in [listing.md](listing.md); expect 4+.
12. **Pricing and availability:** Free; all countries except France (item 2). **Turn off "Make this app
    available on Mac" (Apple silicon) and on Apple Vision Pro** unless wanted: the Mac has its own
    Apassy app, and an iPhone vault app on a Mac would be a second, untested Mac client.
13. **No In-App Purchase** and no subscription group on the app record.
14. **Review vault** ([review-notes.md](review-notes.md) §3): make it, host it, test the download and
    open path on a TestFlight build, and put the address and the passphrase into the notes.
15. **Screenshots** (unit M19 makes them; [screenshots.md](screenshots.md)): look at each one next to
    the approved mockup before upload; upload the iPhone 6.9-inch set and the Apple Watch set.
16. **App Review Information:** contact details, the notes of [review-notes.md](review-notes.md) §2,
    the demo video as the attachment. "Sign-in required" off.
17. **Version release:** choose "Manually release this version", so that the site and the other five
    components go live at the same version first.
18. **Submit for review.** Answer App Review messages from the owner's account. Pending review is not
    published (AGENTS.md).
19. After approval: release, then check the live App Store page (version, screenshots, privacy label,
    price "Free", no In-App Purchases line) and record it in the release report with the other five
    components.

### Later

- Stage 7 (Apassy Connect on the iPhone): update App Privacy (Contact Info › Email, linked) and the
  privacy page in the same release, and keep the plan row without price or purchase words.
- When s2-s3 W2 removes the Wi-Fi companion: remove the Local Network line from the review notes and
  `NSLocalNetworkUsageDescription`, and update [app-privacy.md](app-privacy.md) row 2.7.

## Open questions (legal and policy, for the owner)

Decided on 2026-11-03 ("describe the app correctly"): `ITSAppUsesNonExemptEncryption = true`, France
left out until an ANSSI declaration, App Privacy all linked with User ID, device names as Other Data.

1. The U.S. treatment of an open-source app distributed as a signed App Store binary, and whether the
   mass-market classification needs any report (export-compliance.md §3).
2. When to file the ANSSI declaration for France (export-compliance.md §4).
3. The controller, address, contact, legal bases, processors (Contabo country), a retention limit for
   the relay's event log, and the retention of the off-server backup copy (privacy-policy-ios-draft.md).
4. A third-party agent name ("Claude Code") in screenshots and the demo (screenshots.md).
5. The link to `apassy.wyderka.cc` in the description under 3.1.3(f) (listing.md).
