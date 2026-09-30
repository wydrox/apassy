# ADR 0015 — Automatic updates of the macOS app

Date: 2026-09-28.
Status: PROPOSED for 0.3.0. In the code.

## Context

Each green CI run on `main` publishes a signed and notarized `Apassy.dmg` and `latest.json` ([release](../operations/release.md)). Before this decision, the app did not update itself. The owner downloaded each new build from the site.

The app holds the vault key while it is unlocked. An updater that installs code is a path to that key. It must not be weaker than the path it replaces: a download from the site, which Gatekeeper checks.

## Decision

### 1. Check

- A background thread reads `https://apassy.wyderka.cc/latest.json` about 15 seconds after the start, then every 6 hours. The owner can turn this off and check by hand.
- `/usr/bin/curl` with `--proto =https`, TLS 1.2 or later, the macOS trust store, a time limit, and a size limit. The rustls client of the broker reads at most 64 KiB and does not stream, so it does not fit an image of about 110 MB.
- The app checks each field of `latest.json`: the version form, 40-digit commit, UTC date, `file` = `Apassy.dmg`, size at most 1 GiB, 64-digit SHA-256, `notarized` = true, `arch` = `arm64`, and `minimum_macos` not later than the running macOS.
- Newer means a higher version (Semantic Versioning order). Another build of the same version is never newer (owner decision of 2026-09-28): a merge to `main` publishes a new image on the site, but it reaches installed apps only with a higher version number. `scripts/build-app.sh` embeds the commit and the build time (`APASSY_BUILD_COMMIT`, `APASSY_BUILD_DATE`) in the program and in the signed `Info.plist`; Settings shows them, and the check below uses the commit.
- A debug build can use another HTTPS server for development (`APASSY_UPDATE_BASE`). A release build does not contain this code.

### 2. Download and verify

The image goes to `<data dir>/update/`, which the agent profile denies. The app installs it only when all of these hold:

1. The size and the SHA-256 match `latest.json`.
2. The app in the image has the bundle ID `com.wydrox.apassy` and the version of `latest.json`.
3. The commit in its signed `Info.plist` is the commit of `latest.json`.
4. It is signed with a Developer ID Application certificate of the same team as the running app: `codesign --verify --deep --strict -R '=identifier "com.wydrox.apassy" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = "<team>"'`.
5. Gatekeeper accepts it (`spctl --assess --type exec`), so Apple notarized it.

The app reads its own team from the signature of the running process (`codesign -d <pid>`). A running app without a Developer ID signature, for example an ad hoc build or a build from source signed with Apple Development, or a program outside an app bundle, does not download. It offers the download page. (Changed after 0.3.0: at first only a signature without a team stopped the download.)

### 3. Install

- "Restart now", or the next quit when automatic install is on (the default), locks the vault and ends each waiting run with the text of a quit. Then the app starts the installer and quits.
- The installer is a constant `/bin/sh` script. Paths are arguments only. It waits for the app to exit, checks the staged app again with the same requirement, moves the old bundle aside, moves the new one into place (`ditto` across volumes), checks it again, and removes the old one. A failure puts the old bundle back.
- The result goes to `<data dir>/update/install.log`. The next start shows it.
- When the folder of the bundle is not writable, the app keeps the checked image and opens it in Finder on request. The owner copies the app.

## Threat model

| Attacker | Result |
| --- | --- |
| Changes `latest.json` or the image on the site or in R2 | The app installs only an app with the Apassy bundle ID, a Developer ID signature of the same team as the running app, and an Apple notarization. The attacker cannot make such an app without the signing key of the owner and a notarization in the owner's Apple account. A changed image with the old `latest.json` fails the SHA-256. |
| Offers an older release | Only a higher version is newer. An older notarized image of a lower or the same version fails the version check against `latest.json`, because the version in its signed `Info.plist` must be the version of `latest.json`. |
| On the network path | TLS with the macOS trust store. Even without TLS, the checks of the image decide. |
| An agent on this Mac | The agent profile denies `<data dir>`, so an agent cannot change the staged app, the log, or `update.json`. It also denies `/Applications/Apassy.app`. The installer checks the staged app again right before the move. |
| A process of the owner's user outside the agent profile | Not covered. Such a process can change the app bundle or `update/` without the updater. |

## What this does not protect

- A theft of the Developer ID key and of the notary credentials together. Then the attacker can publish an update. The same attacker can already publish a download on the site.
- A build of the owner that is bad but signed and notarized. The updater installs it like any release.
- The signature of the disk image itself is not checked. The SHA-256 of `latest.json` and the checks of the app decide.
- The old bundle is outside the agent-denied path for the moment between the two moves. It is removed right after.
- An app before 0.3.0 has no updater.

## Relation to other records

- ADR 0003: the vault key lives only in the app process. The install locks the vault first.
- ADR 0010: the owner decides. Automatic install can be turned off, and "Restart now" is always the owner's action.
- [Release](../operations/release.md): the pipeline that publishes `latest.json` and the image. [Updates](../operations/updates.md): the steps and the files.
