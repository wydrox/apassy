# Release and download site

Date: 2026-09-28.

Each push to `main` that passes CI publishes a signed and notarized `Apassy.dmg` at <https://apassy.wyderka.cc/download/Apassy.dmg>. A push that changes only `site/` or `design/` runs no CI, so it publishes no new build.
The site is a static Astro page in `site/`, served by a Cloudflare Worker on the same domain.

## How it works

| Part | File | What it does |
| --- | --- | --- |
| Site | `site/src/pages/index.astro` | The home page, one component per section in `site/src/components`. Light or dark from the system setting. The design follows [t3.codes](https://t3.codes), as the footer says. |
| Changelog page | `site/src/pages/changelog.astro` | Renders `CHANGELOG.md` at `/changelog`. Links to `docs/...` go to GitHub. |
| Screenshots | `scripts/screenshots.sh` | Takes `docs/images/app-*.png` from the real app with synthetic data (`examples/screenshots.rs`). The README and the site use them. |
| Worker | `site/worker/index.ts` | Serves the files of the site. Adds `/download` (302), `/download/Apassy.dmg`, and `/latest.json` from the R2 bucket `apassy-downloads`. |
| Site workflow | `.github/workflows/site.yml` | On a change in `site/`: type check and build. On `main`: `wrangler deploy`. Makes the bucket on the first deploy. |
| Release workflow | `.github/workflows/release.yml` | After each green CI run of a push to `main`: build, sign, notarize, and upload. |
| Disk image | `scripts/build-dmg.sh` | Packages `target/Apassy.app` into `target/dist/Apassy.dmg` and writes `target/dist/latest.json`. |

Before the owner adds the Apple secrets, the release workflow publishes nothing and shows a warning. Without `CLOUDFLARE_API_TOKEN`, the site workflow builds the site and skips the deploy with a warning. The site then says "Coming soon for macOS", because `/latest.json` does not exist.

The release workflow runs on `macos-15`:

1. It checks that the commit is still the head of `main`. CI runs finish in any order, and an older commit must not replace a newer image.
2. It builds the Rust binaries. Then it imports the Developer ID certificate into a temporary keychain, so the build scripts of the dependencies never run while the signing key is in a keychain.
3. If the bucket has `models/apassy-base-v1.safetensors`, it downloads the checkpoint. `scripts/build-app.sh` checks it against `tools/basemodel/manifest.json`. Without it, the app ships without the base model, and the run shows a warning.
4. If the secret `MACOS_KEYCHAIN_PROFILE` is set, it embeds the keychain profile for Touch ID unlock. See [Touch ID unlock](#touch-id-unlock).
5. `scripts/build-app.sh` builds and signs the app with the hardened runtime and a secure timestamp, and runs all of its checks. The app gets its build identity: the commit and the build time, in the program and in the signed `Info.plist` ([updates](updates.md)).
6. `scripts/build-dmg.sh --notarize` notarizes the app, staples it, makes the disk image, signs it, notarizes it, and staples it. `spctl` must accept both.
7. It uploads `Apassy.dmg`, then `latest.json`, to the bucket. The run summary shows `latest.json`.

The bucket keeps only the latest build. The Worker serves only `Apassy.dmg` and `latest.json`. Other keys, such as `models/`, stay private. The upload sets `Cache-Control: no-cache` on both, and the Worker passes it on, so the app and the site get a new `latest.json` at once.

`latest.json`. The site reads `version` and `build`. The app checks every field before an update ([updates](updates.md)) and ignores fields it does not know:

```json
{
  "version": "0.1.0",
  "build": "e710914",
  "commit": "e710914de97c988f775bf180ab1f9f43c2ee20ee",
  "date": "2026-09-28T10:58:05Z",
  "file": "Apassy.dmg",
  "size": 111033131,
  "sha256": "…",
  "notarized": true,
  "minimum_macos": "15.0",
  "arch": "arm64"
}
```

## One-time setup

### 1. Apple

1. A Developer ID Application certificate. Only the Account Holder of the team can make it: developer.apple.com > Certificates > "+" > "Developer ID Application". Install it, then export it with its private key from Keychain Access as a `.p12` file with a password.
2. An App Store Connect API key for the notary service: App Store Connect > Users and Access > Integrations > Team Keys > "+", role "Developer". Download `AuthKey_<KEY_ID>.p8` (only once), and note the key ID and the issuer ID.

### 2. Cloudflare

1. The zone `wyderka.cc` must be in the Cloudflare account. `apassy.wyderka.cc` must have no DNS record: the deploy adds the custom domain and its record.
2. Make an API token from the template "Edit Cloudflare Workers". Limit it to the account and the zone `wyderka.cc`. It needs Account > Workers Scripts > Edit, Account > Workers R2 Storage > Edit, and Zone > Workers Routes > Edit. If the deploy cannot add the custom domain, add Zone > DNS > Edit.
3. Note the account ID: `npx wrangler whoami`, or the dashboard > Workers & Pages, right column.

### 3. GitHub secrets

Run these from the repository root. `gh` asks for a value when there is no input file.

```
base64 -i DeveloperID.p12 | gh secret set MACOS_CERTIFICATE_P12
gh secret set MACOS_CERTIFICATE_PASSWORD
gh secret set APPLE_API_KEY_P8 < AuthKey_<KEY_ID>.p8
gh secret set APPLE_API_KEY_ID
gh secret set APPLE_API_ISSUER_ID
gh secret set CLOUDFLARE_API_TOKEN
gh secret set CLOUDFLARE_ACCOUNT_ID
```

The release workflow stops with a list of the missing secrets. `MACOS_KEYCHAIN_PROFILE` is optional: see [Touch ID unlock](#touch-id-unlock).

### 4. First run

1. Actions > Site > "Run workflow" on `main`. This makes the bucket and deploys the site.
2. Optional: upload the base model once. Use the checkpoint with the SHA-256 in `tools/basemodel/manifest.json`:

   ```
   cd site && npx wrangler login
   npx wrangler r2 object put apassy-downloads/models/apassy-base-v1.safetensors --remote \
     --file "$HOME/Library/Application Support/Apassy/laya/models/apassy-base-v1.safetensors"
   ```

3. Actions > Release > "Run workflow" on `main`, or push to `main`.

## Touch ID unlock

Touch ID has two uses (goal items A2 to A4). Confirming an owner action needs no setup. Unlocking the vault needs a Keychain item with biometric access control, and the keychain helper (`Contents/Helpers/ApassyKeychain.app`) can only write it with the entitlement `keychain-access-groups`. macOS starts a program with that entitlement only when its bundle has a matching provisioning profile (see [native app](native-app.md)). Without the profile, the helper answers `keychain_unavailable`, and the app offers only the passphrase.

The code is ready. Touch ID unlock is paused by the owner (ADR 0010, fourth round). To turn it on for the published app:

1. In the team of the Developer ID certificate: developer.apple.com > Identifiers > "+" > App IDs > macOS, bundle ID `com.wydrox.apassy.keychain` (explicit), no capabilities. The keychain group `<TEAM_ID>.com.wydrox.apassy` must be in the keychain groups of the profile, usually as `<TEAM_ID>.*`. The build checks it.
2. Profiles > "+" > Distribution > "Developer ID". Select the App ID and the Developer ID Application certificate. Download the `.provisionprofile` file.
3. Add it as a secret:

   ```
   base64 -i Apassy_Keychain_Developer_ID.provisionprofile | gh secret set MACOS_KEYCHAIN_PROFILE
   ```

4. Run the release workflow. `scripts/build-app.sh` checks the profile (team, App ID, expiry, keychain group, certificate), embeds it, and signs the helper with `packaging/ApassyKeychain.entitlements`. With the secret set, a profile that does not fit stops the build (`APASSY_REQUIRE_KEYCHAIN=1`). The build log ends with `Keychain: enabled (team <TEAM_ID>, group <TEAM_ID>.com.wydrox.apassy)`.
5. In the app: Settings > Security > type the passphrase > "Turn on Touch ID unlock", and touch the sensor.

A Developer ID profile is valid on every Mac. For a local build on this Mac only, `scripts/build-app.sh --provision` gets a development profile through Xcode ([native app](native-app.md), owner steps).

## App icon

`packaging/AppIcon.svg` is the dark app icon of the brand on the macOS icon grid. `scripts/make-icon.sh` renders `packaging/AppIcon.icns` from it with the tools of macOS. `scripts/build-app.sh` copies the icon into the app, the notifier (the icon of each notification), and the keychain helper (the icon of its Touch ID prompt). Run the script after a change to the SVG, and commit both files.

## Local builds

A disk image with the development certificate. Gatekeeper on another Mac blocks it:

```
scripts/build-app.sh
scripts/build-dmg.sh
```

A notarized image, with a Developer ID certificate in the login keychain. Save the notary credentials once with `xcrun notarytool store-credentials apassy`:

```
APASSY_SIGN_IDENTITY="Developer ID Application" scripts/build-app.sh
APASSY_NOTARY_PROFILE=apassy scripts/build-dmg.sh --notarize
```

The site:

```
cd site
npm ci
npm run dev       # the page only, http://localhost:4321
npm run preview   # the page and the Worker, with a local bucket, http://localhost:8787
```

For `npm run preview`, put test files in the local bucket with `npx wrangler r2 object put apassy-downloads/Apassy.dmg --file <file> --local`, and the same for `latest.json`.

## Limits

- Without `MACOS_KEYCHAIN_PROFILE`, the published app cannot unlock with Touch ID. See [Touch ID unlock](#touch-id-unlock).
- The app runs on Apple silicon with macOS 15 or later only. The site shows a Linux button with a note: the isolation of agents uses macOS Seatbelt, and Linux needs its own version first.
- From 0.3.0, the app reads `latest.json`, downloads a newer build, and installs it at "Restart now" or at the next quit ([updates](updates.md), [ADR 0015](../adr/0015-automatic-updates.md)). An app before 0.3.0 does not update itself: install 0.3.0 from the site once. A copy with no team in its signature (an ad hoc build), or one outside an app bundle, only shows the new version and the download page.
- The updater trusts the Developer ID team and Apple notarization, not the site. A green CI run on `main` is a release: each installed app with automatic install on gets it within about 6 hours.
