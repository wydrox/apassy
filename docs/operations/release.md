# Release and download site

Date: 2026-10-09.

Each push to `main` that passes CI, names a released version (see [Release eligibility](#release-eligibility)), and has a version strictly newer than public `latest.json` publishes a signed and notarized `Apassy-<version>.dmg`. <https://apassy.wyderka.cc/download> redirects to it, for example `/download/Apassy-0.5.0.dmg`. The same image stays at `/download/Apassy.dmg` for apps before 0.5.0 ([Image names](#image-names)). A push that changes only `site/` or `design/` runs no CI, so it publishes no new build.
The site is a static Astro page in `site/`, served by a Cloudflare Worker on the same domain.

## Coordinated six-component release policy

From 0.5.5, every release uses one new version for all six components: iOS app,
macOS app, Linux CLI (`apassy-team`), browser extension, relay, and website. Bump
every component even if its code did not change. A same-version rebuild is not a
new release: installed clients compare versions and do not receive it as an update.
The production Mac workflow checks the public `latest.json` before entering the
signing job, and again inside the serialized release job. An equal version skips
signing/publication. A lower proposed version, an unreachable manifest (including
404), malformed JSON/version, or missing exact public source commit fails closed.
Only a strictly higher SemVer precedence proceeds; build metadata alone is equal.
Prereleases sort below the corresponding stable version. Existing exact-CI,
artifact/source, and current-`main` checks still apply.

`release-versions.json` records the shared version and the six required components.
Update it together with both app/core Cargo manifests and their lockfile, iOS
`MARKETING_VERSION`, extension manifest, and the dated changelog. The website keeps
deriving `VERSION` from the first dated changelog section; its npm package has no
separate product version. In the separate relay checkout, update the relay Cargo
package and lockfile: both `apassy-relay` and the Linux `apassy-team` binary inherit
that package version.

Before publication, use Python 3.12 to check both exact release checkouts:

```sh
python3 scripts/check-release-versions.py --relay-checkout ../apassy-relay-release-055 --require-relay
```

CI checks the source files in this repository. Without `--relay-checkout`, the
checker explicitly reports that the relay and Linux CLI were not checked. The
existing eligibility helper remains separate: populated `Unreleased` entries still
skip production signing and deployment without failing that helper. Neither source
consistency nor eligibility proves that any component was published.

iOS `CURRENT_PROJECT_VERSION` / `APASSY_IOS_BUILD` is an upload build number, not
the shared marketing version. Before upload, read App Store Connect and choose a
valid higher build number; a build-number increment alone does not replace the
marketing-version bump. Keep the iOS 26 deployment target and required toolchain.

Read back all six destinations after delivery: the signed macOS download and
`latest.json` (including hashes/source), processed TestFlight marketing version and
build in the intended group, public extension listing/package, public Linux binary
with checksum and `--version`, running relay version/source, and live website and
changelog. A submitted extension awaiting store review is pending, not published.
Do not report the release complete until all six are live at the shared version.
If a destination is blocked, report its actual version and the exact unfinished
step; retain the shared target version for the remaining deliveries.

## How it works

| Part | File | What it does |
| --- | --- | --- |
| Site | `site/src/pages/index.astro` | The home page, one component per section in `site/src/components`. Light or dark from the system setting. The design follows [t3.codes](https://t3.codes), as the footer says. |
| Changelog page | `site/src/pages/changelog.astro` | Renders `CHANGELOG.md` at `/changelog`. Links to `docs/...` go to GitHub. |
| Site version | `site/src/lib/site.ts` | `VERSION` is the first dated release section of `CHANGELOG.md`, not the version of `Cargo.toml`. The site never advertises a version that is not released. |
| Installer | `scripts/install.sh`, served at `/install.sh` (`site/src/pages/install.sh.ts`, `site/public/_headers`) | Builds the newest release from source, signs it with the Apple Development identity of the person who runs it, and installs it in `/Applications`. Until `/latest.json` exists, the "Coming soon for macOS" button opens a note with its command. |
| Screenshots | `scripts/screenshots.sh [OUT_DIR]` | Takes one image of each view (`ui-*.png`) and `docs/images/app-*.png` from the real app with synthetic data (`examples/screenshots.rs`). The README and the site use the `app-*.png` images. |
| Worker | `site/worker/index.ts` | Serves the files of the site. Adds `/download` (302 to the versioned image of `latest.json`), `/download/Apassy-<version>.dmg`, `/download/Apassy.dmg`, and `/latest.json` from the R2 bucket `apassy-downloads`. |
| Site workflow | `.github/workflows/site.yml` | On a change in `site/` or in a file that the site builds from (`scripts/install.sh`, `Cargo.toml`, `CHANGELOG.md`, `docs/images/`): type check and build. On `main`, for an eligible released version: `wrangler deploy`. Makes the bucket on the first deploy. |
| Release workflow | `.github/workflows/release.yml` | After each green CI run of a push to `main`: check that the version is released, verify the CI binaries, sign, notarize, and upload. |
| Release eligibility | `scripts/ci-release-ready.py` | Decides whether `Cargo.toml` names a released version of `CHANGELOG.md`. Runs in the job `ready`, before any signing. |
| Disk image | `scripts/build-dmg.sh`, `scripts/layout-dmg.sh` | Packages `target/Apassy.app` into `target/dist/Apassy-<version>.dmg` (the version of `Cargo.toml`), saves the Finder install window, and writes `target/dist/latest.json`. |

Before the owner adds the Apple secrets, the release workflow publishes nothing and shows a warning. If only some of the Apple secrets exist, the workflow fails. Without `CLOUDFLARE_API_TOKEN`, the site workflow builds the site and skips the deploy with a warning. The site then says "Coming soon for macOS", because `/latest.json` does not exist.

### Source releases

A GitHub source release does not prove that an installer is available. For 0.3.2, the release tag is `0.3.2`. The compatibility tag `v0.3.2` points to the same commit, because existing copies of `scripts/install.sh` select tags with a `v` prefix.

Before a source release, push the release commit to `main` and check CI on that exact commit. Then create both tags and the GitHub release. A tag push does not start app CI or publish a disk image. If release credentials are absent, the release notes must state that the release contains source code only. Do not attach an Apple Development build as a public installer.

The release workflow first runs the job `ready` on `ubuntu-24.04`, then the job `macos` on `macos-15`. See [Release eligibility](#release-eligibility) for `ready`. The job `macos` does these steps:

1. It checks that the commit is still the head of `main`. CI runs finish in any order, and an older commit must not replace a newer image.
2. It verifies the successful CI run through the GitHub API. The run must be a push to `main` in this repository for the same commit. It downloads that run's unsigned binary artifact and checks its commit, build date, run ID, attempt, version, architecture, and file hashes. Only then can it import the Developer ID certificate into a temporary keychain. The signing job does not compile Rust.
3. If the bucket has `models/apassy-base-v1.safetensors`, it downloads the checkpoint. `scripts/build-app.sh` checks it against `tools/basemodel/manifest.json`. Without it, the app ships without the base model, and the run shows a warning.
4. It selects Xcode 26.3 (`/Applications/Xcode_26.3.app`, macOS SDK 26.2). See [Xcode and SDK](#xcode-and-sdk).
5. If the secret `MACOS_KEYCHAIN_PROFILE` is set, it embeds the keychain profile for Touch ID unlock. See [Touch ID unlock](#touch-id-unlock).
6. It decodes the two provider profiles `MACOS_AUTOFILL_PROFILE` and `MACOS_PROVIDER_APP_PROFILE` into private files, and sets `APASSY_REQUIRE_PROVIDER=1`. See [AutoFill provider profiles](#autofill-provider-profiles).
7. `scripts/build-app.sh` checks the binary artifact again, builds the native helpers and the AutoFill provider, and signs the app with the hardened runtime and a secure timestamp. It runs all existing bundle and signature checks. With `APASSY_REQUIRE_PROVIDER=1`, the build stops if the provider is not in the app. The program and the signed `Info.plist` use the commit and build date from CI ([updates](updates.md)).
8. `scripts/build-dmg.sh --notarize` checks the provider in the app and in the mounted image, notarizes the app, staples it, makes the disk image `Apassy-<version>.dmg`, signs it, notarizes it, and staples it. `spctl` must accept both. The script stops when the version of the app is not the version of `Cargo.toml`, or has build metadata (`+...`), which the image name cannot carry.
9. It checks the head of `main` again. If the commit still matches, it reads the version of the `latest.json` in the bucket, uploads the image as `Apassy-<version>.dmg` and as `Apassy.dmg`, then uploads `latest.json`. Then it deletes the versioned image of the previous `latest.json`, unless that is the image it just uploaded. A failed delete is a warning, not a failure. The run summary names the versioned URL and shows `latest.json`.

The bucket keeps only the latest build: `Apassy-<version>.dmg`, the same bytes as `Apassy.dmg`, and `latest.json`. The Worker serves only these keys. Other keys, such as `models/`, stay private. Both image keys download as `Apassy-<version>.dmg` (`Content-Disposition`). The upload sets `Cache-Control: no-cache` on each key, and the Worker passes it on, so the app and the site get a new `latest.json` at once. The redirect of `/download` has `Cache-Control: no-store`.

`latest.json`. The site reads `version` and `build`. The app checks every field before an update ([updates](updates.md)) and ignores fields it does not know. `file` stays `Apassy.dmg` ([Image names](#image-names)):

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

### Image names

Date: 2026-10-12.

From 0.5.0, the disk image has the version in its name: `Apassy-<version>.dmg`. Apps 0.3.0 to 0.4.1 accept only `"file": "Apassy.dmg"` in `latest.json`, and they download only `/download/Apassy.dmg`. So that they still update:

- `latest.json` keeps `"file": "Apassy.dmg"`.
- The bucket has the same image under the key `Apassy.dmg`, and the Worker serves it at `/download/Apassy.dmg`.

Apps from 0.5.0 accept `"file"` equal to `Apassy.dmg` or to `Apassy-<version>.dmg` with the exact `version` of `latest.json`, and they download `/download/<file>`. They keep the checked image as `update/Apassy-<version>.dmg` ([updates](updates.md)).

`/download` reads the version of `latest.json` and redirects to `/download/Apassy-<version>.dmg`. When `latest.json` cannot be read, or the versioned key is not in the bucket (a release before 0.5.0), it redirects to `/download/Apassy.dmg`. The Worker serves only `/download/Apassy-MAJOR.MINOR.PATCH[-PRE].dmg`. Other names get the 404 page.

Later step, not done yet: when every installed app runs 0.5.0 or later, one release can change `latest.json` to `"file": "Apassy-<version>.dmg"` (in `scripts/build-dmg.sh`). After that release, the workflow can stop uploading `Apassy.dmg`, the Worker can drop `/download/Apassy.dmg` and the fallback of `/download`, and the bucket key `Apassy.dmg` can go. An app before 0.5.0 then no longer updates itself: its owner downloads the new version from the site once.

## CI duration and binary artifacts

CI runs the quality checks, advisory check, test groups, and the unsigned release build at the same time.
macOS uses three test groups. Linux uses four.
This keeps the total at five macOS jobs, within the [standard macOS concurrency limit](https://docs.github.com/en/actions/reference/limits#job-concurrency-limits-for-github-hosted-runners) for Free, Pro, and Team plans.
Other workflows can still use these shared runner slots.
The existing `macos` and `linux` checks remain. Release waits for the complete CI workflow to succeed.
`scripts/ci-test-shard.py` reads Cargo metadata to include every target, including new targets.
Group 0 runs the library tests. The other groups contain all remaining targets, balanced with measured test times.
Each test process uses `--test-threads=1`.
Use `python3 scripts/ci-test-shard.py --list --shard-count 3` to see the macOS groups.
Use `--shard-count 4` for Linux.

Rust dependency caches separate the OS, architecture, compiler, Cargo configuration, lockfile, and job group.
The release build has its own cache. Only pushes to `main` save these caches; pull requests only restore them.
The advisory job caches the pinned `cargo-audit` executable and refreshes the advisory database on each run.
No test or advisory check is removed.

The binary artifact contains five executables and `manifest.json`.
Its name is `apassy-release-COMMIT-ATTEMPT`, and GitHub retains it for seven days.
Release selects it from a specific successful CI run; it never selects the newest artifact by name alone.
Pull request artifacts cannot enter the release process.
A manual Release run requires `ci_run_id` for a successful push to `main` at the selected commit.
If that attempt has no artifact, or the artifact expired, rerun all CI jobs for the current main commit first.
The manual path does not bypass CI or build replacement binaries.

The target is less than ten minutes from a push to public availability, with cached dependencies.
CI run `37786303163` took 13 minutes 9 seconds with six macOS jobs and no saved caches from this configuration.
The library test job waited 6 minutes 51 seconds, then ran for 6 minutes 17 seconds.
The five-job configuration reduces competition for macOS slots. Its duration still requires measurement.
The first run, a dependency change, runner queues, or notarization delays can take longer.
Confirm the target with live CI and Release timings before treating it as a release time guarantee.
The artifact tools require Python 3.11 or later; CI selects Python 3.12.

## Release eligibility

Every green CI run of a push to `main` starts the release workflow, and the site derives its version from the repository. So a version in `Cargo.toml` that is not ready to ship must not reach the signing job. The job `ready` runs `scripts/ci-release-ready.py` on `Cargo.toml` and `CHANGELOG.md` of the commit that passed CI, before the job `macos` starts. The job `macos` needs `ready` and runs only when it answers `production=true`.

A version is eligible only when all of these hold:

- `Cargo.toml` has a plain package version, such as `0.3.6`.
- The first section of `CHANGELOG.md` below the intro that is not `## [Unreleased]` is `## [VERSION] - YYYY-MM-DD` for exactly that version, with a real date. A newer release section, a missing date, a different version, a yanked marker, or any other `##` heading there makes the version ineligible.
- Every `## [Unreleased]` section above that release is empty. A standard empty heading is allowed. A single line of text, list item, or subsection under it is not.

Any other state, including a file that cannot be parsed, skips the production release. A skip is not an error: the job `ready` ends green, the job `macos` is skipped, and the run shows a notice with the reason. No secret is read, nothing is signed, and nothing is uploaded. This applies to a manual run with `ci_run_id` as well. To release a version, move its entries from `Unreleased` into a dated section, and set the same version in `Cargo.toml`, in one commit.

A skipped run is still a green CI on `main`. The existing checks for the exact head of `main`, the same CI run, and the artifact stay as they are.

The job `provider-check` does not depend on `ready`. It is a test build of a branch and never publishes.

The site workflow also runs the eligibility helper before deployment. An ineligible version still gets a site check and build, but no Cloudflare deployment, including a manual run on `main`. The existing public site stays unchanged. `VERSION` in `site/src/lib/site.ts` is the first dated release section of `CHANGELOG.md`. While `Cargo.toml` names a version that has no dated section, the site still shows the last released version and `/latest.json` is unchanged.

## Relay first

A release that uses relay sync needs the relay in step with the app, so deploy in this order. The relay code is in the separate repository `apassy-relay` (the branch that holds SPEC section 24); its deploy commands are in its `docs/OPERATIONS.md`, section 16. Stop at the first step that fails.

1. Commit the relay branch. Deploy only a commit, so the image tag names it.
2. Back up on the VPS: `ssh ottervibe 'cd /opt/apassy && docker compose exec -T relay apassy-relay admin backup'`. Check that the new folder in `/opt/apassy/backups/relay` has `MANIFEST.json`.
3. Build and deploy the relay image as in OPERATIONS section 16: send `git archive` of the commit to the VPS, `docker build -t apassy-relay:<tag>`, set the tag in `/opt/apassy/compose.yaml`, then `docker compose up -d --wait`. On the first start every team file migrates to schema 4 and keeps `teams/<id>.db.pre-v4`. An image of schema 3 cannot open a migrated file. A restart ends every session.
   - Rollback: stop the relay, put the `.pre-v4` copy back as `teams/<id>.db` (or restore the backup of step 2), start the old image. Pushes made after the migration are lost with it.
4. Confirm that the sync routes exist: `GET https://apassy-relay.wyderka.cc/v1/sync/head` without a token must answer 401, not 404. A 404 means the old image still runs.
5. In `deploy/worker`: `npm test` and `npm run typecheck`, then `wrangler deploy`. This adds the new routes, the body length checks, and the rate limits (`SYNC_LIMITER`, `CREATE_LIMITER` for `link/cancel`). Put the CLI binaries in `public/dl/` first, as OPERATIONS section 18 says.
6. Verify a `PUT /v1/sync/snapshot` of a few MiB through the real edge and the tunnel, with a test team and its device (or the app against a scratch vault). The relay must see the `Content-Length` header: the Worker refuses `Transfer-Encoding`, and the relay refuses a chunked body. Check that an oversized declared length gets 413 at the edge, and that the 64 MiB limit of the Cloudflare plan holds (ADR 0022, open question 3). Delete the test team with `admin delete`.
7. Only then publish the app: the source release and tags of [Source releases](#source-releases), or the push to `main` that runs the release workflow.

Vault schema 17 (it was 16). A build of schema 17 migrates a vault of schema 16 when the owner unlocks it, and it reads a copy of schema 16. A build of schema 16 cannot open a vault of schema 17 (`verify_user_version`) or read a copy of it, and a merge refuses a copy of a newer schema (`src/vault/merge.rs`). So every Mac and iPhone that shares one vault through a folder, iCloud Drive, or the relay must update, and the owner must make an encrypted backup first. Say this in the release notes: the "Upgrade notes" of the changelog do.

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
base64 -i Apassy_AutoFill_Developer_ID.provisionprofile | gh secret set MACOS_AUTOFILL_PROFILE
base64 -i Apassy_App_Developer_ID.provisionprofile | gh secret set MACOS_PROVIDER_APP_PROFILE
```

The release workflow stops with a list of the missing secrets. `MACOS_AUTOFILL_PROFILE` and `MACOS_PROVIDER_APP_PROFILE` are required: see [AutoFill provider profiles](#autofill-provider-profiles). `MACOS_KEYCHAIN_PROFILE` is optional: see [Touch ID unlock](#touch-id-unlock).

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

## AutoFill provider profiles

The AutoFill extension offers Apassy for passkeys, passwords, and one-time codes ([Mac passkeys](mac-passkeys.md)). Its entitlement is restricted. macOS stops a program that has the entitlement without a matching profile. So the release needs two Developer ID profiles. Both secrets are required. The release workflow never publishes an app without the provider.

| Secret | App ID | Capability |
| --- | --- | --- |
| `MACOS_AUTOFILL_PROFILE` | `com.wydrox.apassy.autofill` | AutoFill Credential Provider |
| `MACOS_PROVIDER_APP_PROFILE` | `com.wydrox.apassy` | AutoFill Credential Provider |

1. In the team of the Developer ID certificate (`7S3F9767BM`): developer.apple.com > Identifiers. Add the App ID `com.wydrox.apassy.autofill` (explicit). Add the capability "AutoFill Credential Provider" to it. Add the same capability to the App ID `com.wydrox.apassy`.
2. Profiles > "+" > Distribution > "Developer ID". Make one profile for each App ID. Select the Developer ID Application certificate that signs the release. Download both `.provisionprofile` files.
3. Add each file as a secret with `base64 -i FILE | gh secret set NAME`, as in [GitHub secrets](#3-github-secrets).
4. Run the release workflow. The workflow decodes each secret into a private file in `RUNNER_TEMP`, checks that the file is a signed profile, and removes it at the end. It does not print the bytes.

What checks the profiles:

- `scripts/build-credential-provider.sh` checks team, App ID, expiry, AutoFill capability, and certificate. `scripts/build-app.sh` calls it.
- With `APASSY_REQUIRE_PROVIDER=1`, `scripts/build-app.sh` stops unless the app has `PlugIns/ApassyAutoFill.appex`, `MacOS/apassy-credential-bridge`, and the profile of the main app. Without a valid profile and without the flag, the build leaves the provider out and shows a warning. This is for a local build only.
- `scripts/build-dmg.sh` checks the provider again in `target/Apassy.app` and in the mounted copy. It checks the layout, the signatures, the AutoFill entitlement of the main app and of the extension, the declared capabilities, and the embedded profiles (team, AutoFill entitlement, expiry). With the flag, a missing part is an error. Without the flag, an app with no provider part is packaged as a development image, and an app with only a part of the provider is an error.

A profile expires. Make a new profile before the expiry date and replace the secret. After expiry, the release fails.

## Xcode and SDK

The provider uses macOS 26 APIs (`ASOneTimeCode…`) behind availability checks. The deployment target stays macOS 15, but the code needs the macOS 26 SDK to compile. The `macos-15` runner image has Xcode 16.4 (SDK 15.5) as default. Xcode 26.0.1, 26.1.1, 26.2, and 26.3 are installed too. SDK 26.2 is in Xcode 26.2 and 26.3 ([image list](https://github.com/actions/runner-images/blob/main/images/macos/macos-15-Readme.md), image `20260907.0337.1`).

The release workflow selects `/Applications/Xcode_26.3.app` with `DEVELOPER_DIR`, and checks that the SDK is 26 or later. If the runner image no longer has this Xcode, the workflow fails early with the list of installed Xcode versions. Change `XCODE_APP` in the step "Select Xcode 26" then. CI keeps the default Xcode. It does not run `scripts/build-app.sh`, so it does not compile the Swift provider.

## Test build of a branch

To test the signed provider without a release, start the job `provider-check` of the release workflow by hand:

```
gh workflow run release.yml --ref BRANCH -f ci_run_id=provider-check
```

The value `provider-check` of `ci_run_id` is a switch. It only works for a branch of this repository that is not `main`. The job builds the exact commit of the branch (Rust included), signs it with a private, temporary keychain, embeds the profiles, notarizes the app and the image, and keeps `Apassy-<version>.dmg` and `test-build.json` (image name, commit, SHA-256, SDK, run) as a GitHub Actions artifact for 3 days. It does not use R2, the site, or the CI artifact, and the job `macos` does not run. The artifact is test output. It is not a release, and it does not prove that macOS lists Apassy as a provider. That needs a manual check on a Mac.

## App icon

`packaging/AppIcon.svg` is the dark app icon of the brand on the macOS icon grid. `scripts/make-icon.sh` renders `packaging/AppIcon.icns` from it with the tools of macOS. `scripts/build-app.sh` copies the icon into the app, the notifier (the icon of each notification), and the keychain helper (the icon of its Touch ID prompt). Run the script after a change to the SVG, and commit both files.

## Local builds

A disk image with the development certificate. Gatekeeper on another Mac blocks it:

```
scripts/build-app.sh
scripts/build-dmg.sh
```

The disk image contains a 720 × 480 install window with the Apassy background.
Finder shows the app and the Applications link as 96-pixel icons.
The native labels stay below the icons.
`swift scripts/render-dmg-background.swift` creates the PNG and the TIFF with two image sizes for Retina displays.
The build copies `packaging/dmg-background.tiff` into the hidden `.background` folder.
It saves the layout in a writable image, then compresses the image before it signs it.
The app signature, notarization steps, and download manifest use the same release checks.

The build needs Finder and a macOS desktop session.
If macOS asks for Automation access, permit the terminal or runner to control Finder.
A CI runner without a desktop session cannot save the layout.
The build stops with an error and gives instructions.
It does not publish an image without the layout.
Use `scripts/layout-dmg.sh --check` to check Finder access before a build.
After a change to the background, open a new image and check both icon positions and the native labels.

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

For `npm run preview`, put test files in the local bucket with `npx wrangler r2 object put apassy-downloads/Apassy-<version>.dmg --file <file> --local`, the same for `Apassy.dmg`, and for a `latest.json` with that version.

## Limits

- Without `MACOS_AUTOFILL_PROFILE` and `MACOS_PROVIDER_APP_PROFILE`, the release workflow fails. A local build without the profiles has no AutoFill extension. See [AutoFill provider profiles](#autofill-provider-profiles).
- The workflow checks files, signatures, and notarization. It cannot show that macOS registers the extension. A release needs a manual check on a Mac: System Settings > General > AutoFill & Passwords must list Apassy.
- Without `MACOS_KEYCHAIN_PROFILE`, the published app cannot unlock with Touch ID. See [Touch ID unlock](#touch-id-unlock).
- The app runs on Apple silicon with macOS 15 or later only. The Linux button of the site opens a note with the team CLI `apassy-team` for Linux (x86-64), which the relay serves at `/dl/` with `SHA256SUMS` (relay OPERATIONS section 18); the note says that the app needs macOS, because the isolation of agents uses macOS Seatbelt.
- From 0.3.0, the app reads `latest.json`, downloads a newer build, and installs it at "Restart now" or at the next quit ([updates](updates.md), [ADR 0015](../adr/0015-automatic-updates.md)). An app before 0.3.0 does not update itself: install 0.3.0 from the site once. A copy without a Developer ID signature (an ad hoc build, or a build from source signed with Apple Development), or one outside an app bundle, only shows the new version and the download page. A build from source updates when its owner runs `scripts/install.sh` again.
- The updater trusts the Developer ID team and Apple notarization, not the site. Each green CI run on `main` that names a released version strictly newer than public `latest.json` can publish a new image on the site. Installed apps install only a higher version: bump all six components and the files named in the coordinated release policy above to release. Each installed app with automatic install on then gets it within about 6 hours.
