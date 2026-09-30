# Automatic updates

Date: 2026-09-28.
Scope: the macOS app from <https://apassy.wyderka.cc>. Decision: [ADR 0015](../adr/0015-automatic-updates.md). Release pipeline: [release](release.md).

## 1. What the app does

- About 15 seconds after the start, and then every 6 hours while it runs, the app reads <https://apassy.wyderka.cc/latest.json>.
- When `latest.json` names a newer build, the app downloads `Apassy.dmg`, checks it, and keeps the new app in `~/Library/Application Support/Apassy/update/Apassy.app`.
- The main window then shows "Apassy X is ready." with "Restart now". Settings > Updates shows the same.
- "Restart now" locks the vault, ends each run that waits for you (as a quit does), installs the new version, and opens it.
- Without "Restart now", the new version installs when you quit Apassy. It opens at your next start.
- The next start shows the result of the install in a message and in Settings > Updates.

The app never installs an older version.

## 2. Settings > Updates

| Control | Default | What it does |
| --- | --- | --- |
| Version | | The version, the build (the first 7 digits of the commit), and the build date. A local build says "development build". |
| Check for updates automatically | on | The check at the start and every 6 hours. Off: only "Check now" checks. |
| Download and install automatically | on | A check downloads a new version, and a quit installs it. Off: a check only reports the version; "Download now" downloads it, and only "Restart now" installs it. |
| Check now | | One check at once. |
| Last check | | The time and the result of the last check. |
| Last install | | The result of the last install. |
| What's new in Apassy | | Opens <https://apassy.wyderka.cc/changelog>. |

The settings and the last results are in `~/Library/Application Support/Apassy/update.json`, mode `0600`. The file has no secret.

On Linux, Settings says that updates are available only for the macOS app. The app does not check.

## 3. Which build is newer

- A higher version is newer. The app compares versions as Semantic Versioning does: `0.3.0-rc.1` < `0.3.0` < `0.3.1`.
- Another build of the same version is not newer. Each green CI run on `main` publishes a new image on the site, but an installed app updates only when the version number in `Cargo.toml` goes up. So a merge without a version change reaches no installed app.
- A lower version is never newer.

## 4. The checks

`latest.json`:

- HTTPS only, at most 16 KiB, with `/usr/bin/curl` and the macOS trust store.
- `version` has the form `1.2.3` or `1.2.3-rc.1`. `commit` has 40 lowercase hex digits, and `build` is its start. `date` is `YYYY-MM-DDTHH:MM:SSZ`.
- `file` is `Apassy.dmg`. `size` is more than 0 and at most 1 GiB. `sha256` has 64 lowercase hex digits.
- `notarized` is `true`. `arch` is `arm64`. `minimum_macos` is not later than the macOS of this Mac.
- The app ignores unknown fields, so a release can add one.

The disk image:

1. The size and the SHA-256 match `latest.json`. Otherwise the app deletes the file.
2. `hdiutil attach -nobrowse -readonly -noautoopen` at a private folder in `update/`.
3. `Apassy.app` in the image has the bundle ID `com.wydrox.apassy` and the version of `latest.json`.
4. The build in its signed `Info.plist` (`ApassyBuildCommit`) is the commit of `latest.json`.
5. It has a Developer ID signature of the same team as the running app, and `codesign --verify --deep --strict` passes against `identifier "com.wydrox.apassy" and anchor apple generic` with the Developer ID certificate fields and that team.
6. Gatekeeper accepts it: `spctl --assess --type exec`. This needs notarization.
7. `ditto` copies it to `update/Apassy.app`, and the signature check runs on the copy. Then the app detaches and deletes the image.

When the running app has no Developer ID signature (an ad hoc build, or a build from source that `scripts/build-app.sh` or `install.sh` signed with an "Apple Development" certificate), or does not run from an app bundle, the app does not download: no new version could pass the check of step 5 for it. Settings shows the version and "Open the download page". A build from source updates when you run the installer again.

## 5. The install

The installer is a constant `/bin/sh` script (`src/desktop/update/install.rs`). The app passes the paths as arguments. The script:

1. waits until the app has quit (at most 2 minutes),
2. checks `update/Apassy.app` again with `codesign --verify --deep --strict` and the same requirement,
3. moves the installed bundle aside, moves the new one into place (`ditto` when it is on another volume), checks it again, and removes the old one. A failure puts the old bundle back.
4. writes the result to `update/install.log`,
5. opens the new app after "Restart now". An install at quit does not open it.

The next start reads the log. After a failure, the log stays as `update/install-failed.log`, and the next check downloads the version again.

When Apassy cannot replace itself (the folder is not writable, the bundle belongs to another user, or macOS runs the app from a translocated or read-only place), the app keeps the checked disk image in `update/Apassy.dmg`. The banner says "Apassy X is downloaded" with "Open the disk image". Quit Apassy and drag the new app to Applications.

## 6. Files

In `~/Library/Application Support/Apassy/` (the agent profile denies the whole folder, [isolation](isolation.md)):

| File | What it is |
| --- | --- |
| `update.json` | The settings and the last results. |
| `update/Apassy.dmg.part` | A download in progress. |
| `update/mount-*` | The mount point of the image during the check. |
| `update/Apassy.app` | The checked new version. |
| `update/Apassy.dmg` | The checked image, when Apassy cannot replace itself. |
| `update/install.log` | The log of the last install, until the next start reads it. |
| `update/install-failed.log` | The log of the last failed install. |

## 7. Development

A debug build takes another HTTPS server from `APASSY_UPDATE_BASE`, for example `https://localhost:8443`. It reads `<base>/latest.json` and `<base>/download/Apassy.dmg`. A release build does not have this code. Every check of the image still applies.

Tests (no network; a fake system and test doubles of the tools):

```
cargo test --locked --features desktop,vault --lib update
```

Two manual tests run the real tools on macOS with a throwaway image of a notarized app of another developer. The Apassy requirement refuses it:

```
APASSY_UPDATE_PROBE_APP=/Applications/<an app>.app \
  cargo test --locked --features desktop,vault --lib real_ -- --ignored
```

| File (`src/desktop/`) | What its tests show |
| --- | --- |
| `update/version.rs` | Version order with pre-releases, and invalid versions. |
| `update/manifest.rs` | Each field of `latest.json` that is not valid refuses it. The newer-build rule. |
| `update/pipeline.rs` | Check, download, and staging. A SHA-256 or size mismatch, and each failed check of the app, delete the image. Only a higher version downloads. A copy without a team only reports the version. A folder that Apassy cannot write keeps the image. |
| `update/store.rs` | `update.json` defaults, atomic write, mode `0600`. |
| `update/install.rs` | The installer body with test doubles: it waits for the process, replaces the bundle, refuses a bad staged app or bad arguments, and treats paths as data. |
| `update/mod.rs` | The state: idle, checking, downloading, verifying, then ready or error. The install result at the next start. |
| `ui/updates.rs` | Settings > Updates in each phase, and the banner. |

## 8. Limits

- An app before 0.3.0 has no updater. Install 0.3.0 from the site once.
- The tests do not install a real signed release. A release build checks the whole path.
- The app does not verify the signature of the disk image itself. The SHA-256 of `latest.json`, the Developer ID team, and notarization of the app decide.
- A quit during the check of an image can leave the image attached until the next restart of the Mac.
- The banner shows only when the vault is unlocked. A quit installs the version also when the vault is locked.
