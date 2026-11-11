# Linux vault acceptance, 2026-11-10 (unit L4)

Runtime acceptance of the Linux vault package of draft PR #110 (ADR 0045) on real
Linux, with real browsers, a real logind seat session, gnome-keyring and polkit.
The kit that produced it is `packaging/linux/acceptance/`; rerun it on the final head.
Synthetic accounts and a local relying party only; no real account or website.

Result: the PR head as built by CI does **not** work in a browser on Linux. Three
defects in Apassy blocked or weakened it; all three are fixed on
`fix/linux-acceptance` and the fixed build passed passkey create, sign-in, password
save and fill, polkit approval and the refusal cases with Google Chrome on Ubuntu
24.04 and Debian 13 (x86_64). arm64 was not run. Chromium works on neither
distribution as packaged (snap on Ubuntu; a wrapper switch on Debian).

## Builds under test

| Build | Source | Files (SHA-256) |
| --- | --- | --- |
| CI | run 42801653341, PR #110 head `f53fd475`; the package records `3954eb9f`, the PR merge commit | `apassy-vault_0.5.19_amd64.deb` `45c7437de6c97ebe63ad04ff8d31537e3d96926195ae968e8cc9eb28efb36175`, `apassy-vault-0.5.19-linux-x86_64.tar.gz` `0f8ac8d8fd1e9d7fcd962f875fc21b5aaa63f097faa1a9582a69e0b31c542c69`; arm64 deb `55fba0bd688731b45cb611861ddc77e978cb1f316e53b8a866c44cc292d72ae8`, tar `fc86822da3643553d720607546efba23be1fa5674391188c6d0b68588cc407a6` |
| c47deb40 | this branch, fixes 1 and 2; `build-on-devbox.sh` | deb `979701fcd607ea0cc67c6599adb3b887ac53f1954bf6b0310b6448ce46a2ea77`, tar `597164c52e98bf4839739c86613b0d0085f10fe1e4e880ef53e4bb9f06a7f475` |
| de92940d | this branch, fixes 1 to 3 | deb `19186ff7e99948fe20d71f1bcde4f4fdb1bbbad5255d16f2c5fe5b37673c4d19`, tar `008330b05a542a5c27f3eddbd2abe3bfa4d67052fd2aebac395fcb18e433eb84` |

All are debug builds, stripped, as the CI job packages them (Settings › Updates shows
"development build"). Version 0.5.19, `glibc_max` 2.39.

## Environment

- Host `devbox-x86`: Hetzner CPX32, Ubuntu 24.04.5 LTS, kernel 6.8.0-147-generic,
  `kernel.apparmor_restrict_unprivileged_userns=1`. The owner `l4owner` logged in
  automatically on tty3: logind `Type=tty Class=user Seat=seat0 Active=yes
  Remote=no`. Xvfb 21.1.12 at 1600x1000 (X11; authenticated display), openbox 3.6.1,
  xdotool 3.20160805.1, user D-Bus 1.14.10, gnome-keyring 46.1, libsecret-tools
  0.21.4, polkitd 124-2ubuntu1.24.04.4, pkttyagent.
- Browsers on Ubuntu: Google Chrome 157.0.8103.50 (Google apt repository);
  Chromium 157.0.8103.38, snap revision 3590. Ubuntu has no Chromium deb:
  `apt-cache show chromium-browser` is "Transitional package - chromium-browser ->
  chromium snap" (2:1snap1-0ubuntu2).
- Debian: `debian:trixie` container on the same host (privileged, no logind seat),
  Debian 13, libc6 2.41-12+deb13u4, Chromium 156.0.8078.79-1~deb13u1 (deb, with
  chromium-sandbox), Google Chrome 157.0.8103.50, polkitd 126-2, gnome-keyring 48.0,
  Xvfb 21.1.16. Debian 12 (`debian:bookworm`, glibc 2.36) for the install check.
- Relying party: `packaging/linux/acceptance/rp`, Node.js 22.23.4,
  `@simplewebauthn/server` 14.0.3, `http://localhost:4174`.
- arm64: Google ships `google-chrome-stable` 157.0.8103.50 for arm64 in its apt
  repository (`dists/stable/Release`: "Architectures: amd64 arm64", checked
  2026-11-10). `devbox-arm` was not started: both owner approvals through
  `apassy_run_with_secrets` timed out.

## Matrix

PASS and FAIL are observed. NOT RUN is not tested. "(CI)" is the PR head build,
"(fix)" is c47deb40 or de92940d as named.

### Package and owner

| Check | Ubuntu 24.04 x86_64 (host) | Debian 13 x86_64 (container) | Debian 12 x86_64 | arm64 (Ubuntu, Debian) |
| --- | --- | --- | --- | --- |
| `sha256sum -c`, then `sudo apt install ./…deb` | PASS (CI); PASS (de92940d, over a tar install) | PASS (CI) | FAIL: `Depends: libc6 (>= 2.39) but 2.36-9+deb12u14` | NOT RUN (static: checksums OK, ELF aarch64, `Architecture: arm64`) |
| tar, `sudo sh ./…/install-vault.sh` | PASS (c47deb40) | PASS (de92940d) | NOT RUN | NOT RUN |
| Headless owner commands, account without bus, display or logind session (11 checks) | PASS 11/11 (CI) | PASS 11/11 (CI) | – | NOT RUN |
| Window: first run, create vault, unlock, item list, owner check, Settings › Security (X11) | PASS (CI, c47deb40, de92940d) | PASS (de92940d) | – | NOT RUN |
| Window under Wayland | NOT RUN | NOT RUN | – | NOT RUN |
| Secret Service opt-in (8 checks) | PASS 8/8 (CI) | NOT RUN | – | NOT RUN |
| polkit `auth_self` through `pkttyagent` | FAIL (CI): polkitd refuses every check; PASS (fix): wrong password refused, right password approves one-shot | NOT RUN (no seat in a container) | – | NOT RUN |

Headless checks: no session bus/display/runtime dir; create; add; list; wrong
passphrase refused; redirected input refused; encrypted backup (mode 600); change
passphrase; shell session; the backup opens with the old passphrase; no passphrase
or secret echoed. Keyring checks: declined consent stores nothing; consent stores
it; another same-user client (`secret-tool lookup`) reads the item, as documented;
`unlock-keyring` opens without typing; no bus refuses; locked keyring refuses;
`keyring-disable` removes; no echo.

### Browser

| Check | Ubuntu Chrome 157 | Ubuntu Chromium snap 157 | Debian 13 Chrome 157 | Debian 13 Chromium 156 (deb) |
| --- | --- | --- | --- | --- |
| `apassy setup browser --browser …` writes the manifest | PASS | written, but the snap reads `~/snap/chromium/common/chromium` | PASS | PASS |
| Load unpacked `/usr/share/apassy/browser-extension`, ID `bbnpgnjnfjlbgggmpnhejpmfjhmmhiih` | PASS (real UI) | NOT POSSIBLE: `/usr/share/apassy` and `/usr/lib/apassy` do not exist in the snap | PASS | PASS |
| Popup "Connected to Apassy" (unguarded status) | PASS (CI and fix) | – | PASS | PASS |
| Passkey create, verified by the RP | FAIL (CI): falls back to the browser; PASS (fix) | UNSUPPORTED (exe `/snap/chromium/3590/usr/lib/chromium-browser/chrome`) | PASS (de92940d) | REFUSED as packaged (see R1); PASS with the `--load-extension` line disabled by root |
| Passkey sign-in, discoverable, UV, verified | PASS (c47deb40: passphrase and polkit; de92940d: passphrase after a Chrome restart) | – | PASS (de92940d) | as create |
| Wrong RP ID (`example.com`) create and sign-in | PASS: `SecurityError`, no Apassy card | – | NOT RUN | NOT RUN |
| Cancel in the card | PASS: `NotAllowedError`, nothing signed | – | NOT RUN | NOT RUN |
| Locked vault | PASS: the browser handles the request | – | NOT RUN | NOT RUN |
| Existing credential in `excludeCredentials` | PASS: `InvalidStateError` after the approval | – | PASS | – |
| Browser killed while the card is open | PASS: card closes, "Nothing was signed, filled, or saved." | – | NOT RUN | NOT RUN |
| Password save, fill, RP login | FAIL (CI): save refused; PASS (fix): `passwordMatches: true` | – | NOT RUN | NOT RUN |
| Refused: `--remote-debugging-port` in the browser's argv | FAIL (c47deb40): approval card; PASS (de92940d) | – | NOT RUN | NOT RUN (the wrapper's own `--load-extension` is refused, R1) |
| Refused: copied Chrome at `/opt/l4-fakechrome/chrome` (root-owned) | PASS | – | NOT RUN | – |
| Refused: `chmod o+w /opt/google/chrome/chrome` | PASS; PASS again after `chmod 755` | – | NOT RUN | – |
| Refused: host under python3 or bash, host as root, root peer on the socket, the owner's own non-host process, another user, another extension origin | PASS 7/7 (de92940d, `refusals.sh api`) | – | NOT RUN | NOT RUN |
| Stale process (PID reuse) | NOT RUN (not constructed) | – | – | – |

Each verified ceremony also passed the RP's negative re-checks: the same response
with origin `http://localhost:1`, with RP ID `example.com`, and (sign-in) with one
signature bit flipped was refused by `@simplewebauthn/server`. Attestation format
`none`, AAGUID `00000000-0000-0000-0000-000000000000`, authenticator attachment
`platform`, flags backup-eligible and backed-up (`multiDevice`).

## Defects

1. **Every Linux passkey, one-time code and toolbar save or fill was refused**
   (fixed, `c916b6e0`). Symptom: Chrome showed its own security-key dialog; save
   showed "Apassy cannot verify this browser". strace: the host passed its own
   check; the app's `readlink(/proc/HOST/exe)` returned `EACCES` (the host is
   non-dumpable by design), then `statx("/proc/HOST")` and refusal. Root cause: the
   app accepted that case only when `/proc/PID` is root-owned, but the kernel keeps
   the directory owned by the task's user (`task_dump_owner` exempts world-readable
   directories); only the files in it become root's. Observed on kernel 6.8: `dir
   /proc/PID uid=1001`, `/proc/PID/exe uid=0`. Fix: test the owner of the
   `/proc/PID/exe` link; regression test with a real non-dumpable child.
2. **polkit presence never worked** (fixed, `c47deb40`). Symptom: "System
   authentication did not succeed" at once, no agent prompt. `pkcheck` with Apassy's
   arguments printed `GDBus.Error:org.freedesktop.PolicyKit1.Error.NotAuthorized:
   Only trusted callers (e.g. uid 0 or an action owner) can use CheckAuthorization()
   and pass details`. Root cause: `--detail operation …`. Fix: no details; unit test.
3. **The unsafe-switch check was blind on Linux** (security; fixed, `de92940d`).
   Symptom: Chrome started with `--remote-debugging-port=9333` got a passkey
   approval card. Root cause: Chrome rewrites its process title, so
   `/proc/PID/cmdline` was one NUL-terminated string (`od -c`: one `\0`, the
   arguments joined by spaces); `safe_arguments` split on NUL and skipped the first
   string, so it checked nothing. `--load-extension`, `--disable-extensions-except`
   and `--type` were invisible too. Fix: check every whitespace-separated word of
   every string, `argv[0]` included (refuses more than the browser reads); test with
   the observed cmdline.
4. **The deb suggested a package Debian 13 does not have** (fixed, `d7a7e923`):
   `Suggests: policykit-1`; now `polkitd | policykit-1`.

Reported, not fixed:

- R1. Debian's `chromium` package adds `--load-extension=$(ls -dm
  /usr/share/chromium/extensions/*)` to every start (`/etc/chromium.d/extensions`),
  empty when no system extension is installed. Apassy refuses that switch, so
  Debian's Chromium, started normally, gets no passkeys, fill or save. Allowing it
  would weaken the check; owner decision (question 1).
- R2. Ubuntu's Chromium snap cannot run the host and reads other manifest paths,
  but Settings › Tools shows "Chromium Connected" because
  `~/.config/chromium/NativeMessagingHosts` exists.
- R3. Mac wording on Linux: welcome "one encrypted file on this Mac", "Use a vault
  from another Mac", vault switcher "On this Mac", Devices "This Mac only", Sync
  "your other Macs", Tools "Fills ask for Touch ID as set in Security › How often to
  ask"; the extension description says "on your Mac" and "Touch ID".
- R4. Settings › Tools shows "apassy: Not installed" and "Install tools…" although
  the package installed `/usr/bin/apassy`.
- R5. A wrong passphrase in `apassy owner` prints SQLCipher's internal
  `ERROR CORE sqlcipher_page_cipher: hmac check failed` lines before the message.
- R6. `apassy owner change-passphrase` asks for the passphrase twice and, without a
  keyring, prints the keyring-item warning anyway.
- R7. After a failed polkit check the card closes and the page gets
  `NotAllowedError`; the toast still says "Confirm with the passphrase".
- R8. Two passkeys with the same site and account name look identical in the
  account chooser; once the older, server-unknown one was pre-selected.
- R9. The CI package records the PR merge commit (`3954eb9f`), not the head
  (`f53fd475`): `APASSY_RELEASE_COMMIT: ${{ github.sha }}` on `pull_request`.
- R10. The vault never locks by itself on Linux ("Lock after inactivity: Never",
  no screen-lock observer). This is the lock-observer unit on `feat/linux-parity`.
- R11. egui acts on a click only after a frame with the pointer over the widget;
  instant synthetic clicks were lost (automation only, not a user problem).

## Documentation errors

1. "Ubuntu and Debian" without versions (ADR 0045, linux-vault.md, VAULT.md): the
   artifacts need glibc 2.39, so Ubuntu 24.04+ and Debian 13+; Debian 12 refuses
   the deb. Corrected in linux-vault.md and VAULT.md.
2. extension/README.md: "packaged Chromium on Ubuntu/Debian". Ubuntu has only the
   snap; Debian's packaged Chromium is refused (R1). Corrected to the observation.
3. linux-vault.md did not name `apassy owner unlock-keyring` (only `--help` does)
   or say that the window never reads the keyring item. Corrected.
4. "`pkcheck` needs a session authentication agent": nothing on text sessions
   (`pkttyagent --process PID`; without `--process` it serves only its parent) or on
   SSH sessions (refused without prompt). Corrected.
5. "Use Apassy's browser extension installation flow": no steps. `apassy setup
   browser` without `--browser` writes nothing on a fresh account ("no browser
   profile found", exit 1); Load unpacked was not described. Corrected with steps.
6. linux-vault.md builds with `cargo build --release`; the CI artifacts are debug
   builds (Settings › Updates: "development build"). Not changed.
7. ADR 0041 §3 promises Settings › Security › "Check with: Linux login (default) or
   Passphrase only". The build has passphrase by default and a "Use system
   authentication" link, no such setting. Not changed (ADR 0045 makes passphrase
   the default).
8. The `apassy setup browser` output tells Linux users to add the extension from the
   Chrome Web Store; the store listing's version was not checked and is not part of
   the package. Not changed.

## Observed and assumed

Observed: everything in the matrix marked PASS or FAIL, the strace and `od` output
above, the polkit journal lines ("successfully authenticated … ONE-SHOT
authorization"; "FAILED to authenticate"), the RP events. Assumed, not observed:

- The locked-vault fallback answered `vault_locked`: only the browser's own dialog
  was seen; the answer code was not traced.
- The wrong-RP-ID refusal came from the extension or the browser before Apassy: no
  Apassy card appeared; the host was not traced.
- Ubuntu 22.04 refuses the deb like Debian 12 (glibc 2.35): not run.
- The fixes behave the same on arm64: not run.

## Not covered

arm64 (owner approval timed out twice); Wayland; a real desktop environment (GNOME
or KDE agent, gnome-keyring prompter, fprintd); polkit and Secret Service on
Debian; on Debian Chrome: refusals, wrong RP ID, save and fill; one-time code fill,
PRF, largeBlob, frames; stale process by PID reuse; Flatpak browsers; the Chrome
Web Store extension; upgrade from the node-only `apassy` package; suspend, screen
lock and user switching. The Rust tests of the fixes did not run on the devbox (the
test build was OOM-killed at 3.5 GB); CI on the pull request runs them.

## Commands

```sh
# Mac: build a commit like CI, on the devbox
packaging/linux/acceptance/build-on-devbox.sh x86 de92940d
# devbox: one command per target, then the browser steps of the kit README
bash run-target.sh ubuntu   ~/work/l4/artifacts/build-x86_64-de92940d tar
bash run-target.sh debian13 ~/work/l4/artifacts/build-x86_64-de92940d deb
bash refusals.sh browser
# evidence
sudo strace -f -p "$(pgrep -u l4owner -xo apassy)" -e trace=readlink,openat,statx,getsockopt,pidfd_open
od -c /proc/"$(pgrep -u l4owner -xo chrome)"/cmdline
pkcheck --action-id com.wydrox.apassy.owner-presence --process PID,START,UID --allow-user-interaction --detail operation x
```

## Screenshots

In `docs/reviews/linux-acceptance-2026-11/` (1600x1000, synthetic data):
`ubuntu-01-first-run`, `ubuntu-02-unlock`, `ubuntu-03-item-list`,
`ubuntu-04-extension-loaded`, `ubuntu-05-ci-build-passkey-falls-back`,
`ubuntu-06-ci-build-save-refused`, `ubuntu-07-create-approval-card`,
`ubuntu-08-passkey-saved`, `ubuntu-09-sign-in-approval-card`,
`ubuntu-10-polkit-wrong-password-refused`, `ubuntu-11-show-owner-check`,
`ubuntu-12-before-fix-debug-switch-got-a-card`,
`ubuntu-13-after-fix-debug-switch-refused`,
`ubuntu-14-browser-killed-nothing-signed`, `ubuntu-15-settings-security`,
`ubuntu-16-settings-tools`, `debian13-01-chromium-as-packaged-refused`,
`debian13-02-chromium-without-load-extension-card`.

## Second run, 2026-11-10: commit c8f05170 (unit L5)

The fixes of unit L5 (branch `feat/linux-browser-rules`, stacked on PR #110): Debian's
system extensions in the browser check, honest browser states, the small defects
R2, R4, R5, R6, R8 and R9 of the first run, and the passkey chooser. Same kit, with a run
prefix (`L4_RUN=l5`, `~/work/l5`, accounts `l5owner` and `l5headless`), a one-time
code page on the RP (RFC 6238, checked by the server) and a headless sway session.

Result: everything that ran passed. Debian 13's packaged Chromium now creates and
uses passkeys and fills and saves logins when it loads a Debian system extension;
without one (Debian's default) it stays refused, and so does an extension folder of
the owner's own. The Wayland window ran natively; Copy under Wayland was **not run**.
arm64 was not run.

### Build under test

| Build | Source | Files (SHA-256) |
| --- | --- | --- |
| c8f05170 | `c8f05170f9d4eeb8a8437e5b3ae7c87747511edf`, exported with `git archive`; built on devbox-x86 in an `ubuntu:24.04` container with Rust 1.97.0 by the commands of `build-on-devbox.sh` (debug build, stripped, `build-vault.sh`, shellcheck of the kit) | `apassy-vault_0.5.19_amd64.deb` `043da637f8afa6042219aeaa8e70b61375f3f75206d4d173e8edda013ebe55bd`, `apassy-vault-0.5.19-linux-x86_64.tar.gz` `a01e8416775fecdc490406252645a1272938ef92bd8b5068212d158cbba4e915` |

`release-vault-linux-x86_64.json` records `"commit"` and the new `"built_from"`, both
`c8f05170…` for this local build (R9: in CI on a pull request, `built_from` is the merge
and `commit` the head). Version 0.5.19, `glibc_max` 2.39, Settings > Updates "0.5.19
(development build)". Later commits of the branch change tests, the kit and this record
only, and a `cfg` of a test helper; the packaged code is that of c8f05170.

### Environment

- Host `devbox-x86` (Hetzner CPX32): Ubuntu 24.04.5 LTS, kernel 6.8.0-147-generic,
  x86_64. Seat session of `l5owner` on tty3 (logind `Type=tty Class=user Seat=seat0
  Active=yes Remote=no`). Xvfb 2:21.1.12-1ubuntu1.9 at 1600x1000, openbox 3.6.1,
  xdotool 3.20160805.1, gnome-keyring 46.1, libsecret-tools 0.21.4, polkitd 124.
  Google Chrome 157.0.8103.50; Chromium snap 157.0.8103.38 (revision 3590).
- Wayland: sway 1.9-1build2, headless backend (`WLR_BACKENDS=headless`), in the
  owner's logind session, `DISPLAY` unset; grim 1.4.0, wtype 0.4, wlrctl 0.2.2,
  wl-clipboard 2.2.1 (installed for the run, removed after).
- Debian: `debian:trixie` container `l5-debian13` (privileged, no logind seat), Debian
  13.7, libc6 2.41-12+deb13u4, Xvfb 2:21.1.16, Chromium 156.0.8078.79-1~deb13u1, Google
  Chrome 157.0.8103.50-1; later `chromium-lwn4chrome` 1.0-3 (a Debian system extension).
- RP: `packaging/linux/acceptance/rp`, Node.js 22.23.4, `@simplewebauthn/server` 14.0.3.

### Matrix

PASS and FAIL are observed on c8f05170. NOT RUN was not tested in this run (the first
run's result, where there was one, is named).

| Check | Ubuntu 24.04 host | Debian 13 container |
| --- | --- | --- |
| `sha256sum -c`, `apt-get install ./…deb` | PASS (after `apt-get remove` of the first run's package) | PASS |
| Headless owner commands, 13 checks | PASS 13/13 | PASS 13/13 |
| …wrong passphrase: one line, no SQLCipher lines (R5) | PASS: `apassy owner: The passphrase is wrong, or the vault file is damaged. The vault stays locked.` | PASS |
| …`change-passphrase` asks once (R6) | PASS: one `Current passphrase:`; without a bus the keyring note names `keyring-disable` in the desktop session | PASS |
| Secret Service opt-in, 8 checks | PASS 8/8 | NOT RUN |
| polkit `auth_self` | NOT RUN (first run: PASS with the fix) | NOT RUN (no seat) |
| Window under X11: first run, create vault, item list | PASS | PASS |
| Window under Wayland (sway): native start, unlock | PASS: app_id `apassy`, no X | – |
| Copy under Wayland | NOT RUN (see below) | – |
| Settings > Tools: command line (R4) | PASS: `apassy  /usr/bin/apassy`, "Installed by the apassy-vault package", no Install tools | NOT RUN |
| Settings > Tools: Chromium snap (R2, item 2) | PASS: "Not supported", the reason and "Use Google Chrome, or Chromium from a .deb.", no Connect | – |
| `apassy setup browser --browser chromium` | PASS: snap refused with the reason, nothing written, exit 1; `--json`: `"state": "unsupported", "reason": "snap"` | PASS: deb Chromium written |
| API refusals (`refusals.sh api`, 7 cases) | PASS 7/7 | NOT RUN |

| Browser check | Ubuntu Chrome 157 | Debian Chrome 157 | Debian Chromium 156, as packaged (no system extension) | Debian Chromium 156 + `chromium-lwn4chrome` |
| --- | --- | --- | --- | --- |
| Load unpacked, ID `bbnpgnjnfjlbgggmpnhejpmfjhmmhiih` | PASS | PASS | PASS | (same profile) |
| Passkey create, verified by the RP | PASS | PASS | REFUSED as intended: the browser's own security-key dialog, no Apassy card | PASS |
| Passkey sign-in, verified | PASS | PASS | NOT RUN | PASS |
| Two passkeys of one account: chooser (R8, item 4) | PASS: newest first and selected, both with "Added … UTC"; the RP (which knew only the newest) verified the sign-in | PASS: same | – | – |
| Wrong RP ID create and sign-in | PASS: `SecurityError`, no card | NOT RUN | – | NOT RUN |
| One-time code fill (otp.html) | PASS: card "fill the current code…", RP `otp_login` `codeMatches: true` | NOT RUN | – | NOT RUN |
| Password save, then fill and RP login | NOT RUN (first run: PASS) | NOT RUN | – | PASS: save card, saved, fill card, RP `passwordMatches: true` |
| Refused: `--remote-debugging-port=9333`, a copied Chrome under `/opt`, `chmod o+w` Chrome | PASS 3/3: security-key dialog, no card; positive control after restoring the mode verified | NOT RUN | – | – |
| Refused: the owner's own folder added (`--load-extension=/home/l5owner/l5-user-ext`) | – | – | – | PASS: security-key dialog, no card, no verified sign-in |

Each verified ceremony also passed the RP's negative re-checks (wrong origin, wrong RP
ID, and for sign-in a damaged signature: all `refused`); attestation `none`, AAGUID
zero, user verification true.

The first attempt at the three Chrome refusals is not counted: Chrome's search-engine
choice dialog covered the page, so no request was made. The rerun after dismissing it
is the result above; each screenshot shows the browser's dialog.

First-run items: R1 (as decided by the parent agent: only root-owned system
extensions), R2, R4, R5, R6, R8 and R9 are fixed and observed fixed above, except R9,
which only a CI run on a pull request shows. Documentation errors 6 and 7 are
corrected (debug builds; ADR 0041 describes the owner check that exists). R3 (macOS
wording), R7 (toast after a failed polkit check), R10 and R11 are not part of this unit.

### Debian's Chromium, observed

- `/usr/bin/chromium` sources `/etc/chromium.d/*`; `/etc/chromium.d/extensions` adds
  `--enable-remote-extensions` and `--load-extension=$(ls -dm
  /usr/share/chromium/extensions/* | tr -d '\n')`. The three Debian 13 packages checked
  (`webext-keepassxc-browser`, `webext-ublock-origin-chromium`, `chromium-lwn4chrome`)
  install real directories there, root-owned, mode 0755; without such a package the
  folder does not exist.
- The browser process's `/proc/PID/cmdline` is one NUL-terminated string (title
  rewritten). Without a system extension it ends with `--enable-remote-extensions
  --load-extension` (no `=`, no value): refused. With `chromium-lwn4chrome`:
  `--load-extension=/usr/share/chromium/extensions/lwn4chrome`: accepted. With the
  owner's own folder: `--load-extension=/usr/share/chromium/extensions/lwn4chrome
  --load-extension=/home/l5owner/l5-user-ext`: refused. These three titles are the
  test `observed_debian_13_titles`.

### Wayland, observed and not

- Observed: the window ran as a native Wayland client of sway 1.9 with `DISPLAY` unset
  and unlocked with the passphrase (typed through the virtual-keyboard protocol). Its
  `WAYLAND_DEBUG` log shows the registry advertising `zwlr_data_control_manager_v1`
  version 2 and no `ext_data_control_manager_v1`; the clipboard's probe connections
  read it.
- Not observed: a Copy. The headless sway had no input device; `wlrctl` makes a
  virtual pointer per call, so no click reached the window, and keyboard navigation did
  not open an item. So the protocol path of Copy under Wayland is not shown by this run.
  From the advertised globals and `src/desktop/clipboard/wayland.rs` it would be
  wlr-data-control: an inference, not an observation. Tests of the clipboard against a
  headless sway with wl-clipboard run in CI (`desktop::clipboard::`).

### Not run in this run

arm64 (`devbox-arm` stopped; its start needs the owner); polkit; Copy under Wayland; a
real desktop (GNOME, KDE); Secret Service on Debian; on Debian: wrong RP ID, OTP,
refusals other than the extension folder; on Ubuntu: password save and fill, cancel,
locked vault, a killed browser (all PASS in the first run, code unchanged); Flatpak
browsers (only the unit tests of the "not supported" state); the tar install.

### Host changes undone

`cleanup-host.sh --packages` (new in the kit) removed the automatic login on tty3,
the accounts `l5owner` and `l5headless` with their homes and processes, and sway,
grim, wtype, wlrctl and wl-clipboard; ydotool (tried for pointer input) was removed;
the containers `l5-debian13` and `l5-dev` were deleted. The host keeps the Apassy
package of this build (it replaced the first run's), Chrome, the Chromium snap and the
other packages of `setup-host.sh`, as after the first run. The first run's accounts
`l4owner` and `l4headless` still exist on the host; they are not this run's.

### Screenshots

In `docs/reviews/linux-acceptance-2026-11/` (1600x1000, synthetic data):
`l5-ubuntu-01-chooser-newest-selected`, `l5-ubuntu-02-settings-tools`,
`l5-ubuntu-03-remote-debugging-refused`, `l5-ubuntu-04-otp-card`,
`l5-ubuntu-05-otp-verified`, `l5-wayland-01-native-window`,
`l5-wayland-02-unlocked`, `l5-debian13-01-chromium-default-refused`,
`l5-debian13-02-chromium-system-extension-card`,
`l5-debian13-03-chromium-user-extension-refused`, `l5-debian13-04-save-card`,
`l5-debian13-05-password-filled`, `l5-debian13-06-chrome-chooser`.

## Release packages, 2026-11-10 (unit L6)

The release path of the vault package: release mode, built in `rust:1.97.0-bullseye`
(glibc 2.31) by `packaging/linux/build-vault-release.sh`, the same script in PR CI
(`linux-vault-package`) and in `relay-image.yml` (`linux-vault`). Packages under test:
CI run 42903422377 of draft PR #122, head `1f998a4c`; `release-vault-linux-*.json`
records `commit` `1f998a4c8948775ad4330edab1872b4b7b0561b7`, the head, not a merge
commit (R9 fixed for these jobs). Version 0.5.19, release build, stripped.

| File | Size (bytes) | SHA-256 |
| --- | --- | --- |
| `apassy-vault_0.5.19_amd64.deb` | 16750076 | `967389334d6a56cd564d6cbb82607446f32a346866f9acf937e86d24959e6849` |
| `apassy-vault-0.5.19-linux-x86_64.tar.gz` | 23692382 | `37fda34fdad24277e1eddabab7ed12ad17543571c07c9e870f5f475bf1720275` |
| `apassy-vault_0.5.19_arm64.deb` | 15201868 | `829746688d68891f949f9f5428fb528b0efb069f5dc5054697d18c6dbe75076e` |
| `apassy-vault-0.5.19-linux-aarch64.tar.gz` | 22280813 | `be637a14d616a24af18d3f8573b1c13bdc1436df1be4a61a7e77c38d94140d88` |

The debug packages of the first run were 22.5 MB (deb) and 34.6 MB (tar). The largest
release file, the x86_64 tarball, is 90% of the 25 MiB (26214400 bytes) that the relay
Worker's `/dl/` can serve; the build refuses a larger one.

glibc requirement (newest `GLIBC_` symbol version, `readelf --version-info`): `apassy`
2.30 and `apassy-browser-host` 2.30, on both architectures (was 2.39 and 2.38). Shared
libraries linked (`NEEDED`): libc, libm, libdl, libgcc_s, the loader.

### Matrix

Minimal containers, x86_64 on `devbox-x86` (`packaging/linux/acceptance/release-matrix.sh`),
and both architectures in CI (`verify-vault.sh --containers` on `ubuntu-24.04` and
`ubuntu-24.04-arm`). PASS is observed.

| Check | Debian 12 (glibc 2.36) | Debian 13 (2.41) | Ubuntu 22.04 (2.35) | Ubuntu 24.04 (2.39) |
| --- | --- | --- | --- | --- |
| x86_64: `install.sh` vault from `file://`, deb with apt, no Recommends (packages added) | PASS (56) | PASS (52) | PASS (56) | PASS (52) |
| x86_64: `ldd -r` of `apassy` and `apassy-browser-host` | PASS | PASS | PASS | PASS |
| x86_64: window maps on Xvfb (X11), "Apassy" 1180x800, still running after 4 s | PASS | PASS | PASS | PASS |
| x86_64: headless owner checks of the kit (11) | PASS 11/11 | PASS 11/11 | PASS 11/11 | PASS 11/11 |
| x86_64: `install.sh` vault tar (`APASSY_VAULT_FORMAT=tar`, Depends installed first), window | PASS | PASS | PASS | PASS |
| x86_64 CI: apt install, `ldd -r`, tar `--version`, window | PASS | PASS | PASS | PASS |
| aarch64 CI (native arm64 runner): apt install, `ldd -r`, tar `--version`, window | PASS | PASS | PASS | PASS |
| aarch64: headless owner checks, `install.sh` deb path | NOT RUN (`devbox-arm` not available) | NOT RUN | NOT RUN | NOT RUN |

Also observed: on the CI runners (Ubuntu 24.04, both architectures) the deb installs,
`apassy owner create` refuses piped input, the deb removes, and `install.sh` installs
the tarball twice. `install.sh` refuses Debian 11 and Ubuntu 20.04 before any download:
"The vault package supports Debian 12 or later and Ubuntu 22.04 or later; this system
is Debian GNU/Linux 11 (bullseye). Set APASSY_ALLOW_UNSUPPORTED=1 to try it anyway
(untested)."

### Dependencies found

The window under X11 loaded (LD_DEBUG, the same on all four): libX11, libX11-xcb,
libxcb (and its dri2, dri3, glx, present, randr, shm, sync, xfixes, xkb extensions,
through Mesa), libXcursor, libXi, libxkbcommon, libxkbcommon-x11, libGL, libGLX and
libGLX_mesa with `swrast_dri.so`; no libEGL, no Wayland library, no libXrandr. With
the previous `Depends` minus `libstdc++6` and `libxrandr2`, the window starts on all
four. `Depends` now: `libc6 (>= 2.30), libgcc-s1, libx11-6, libx11-xcb1, libxcb1,
libxcursor1, libxi6, libxkbcommon0, libxkbcommon-x11-0, libgl1, libegl1,
libwayland-client0, libwayland-cursor0, libwayland-egl1`; the Wayland and EGL entries
are what winit and glutin load in a Wayland session, which was not run. `Suggests:
libsecret-tools, polkitd | policykit-1, xdg-desktop-portal`.

Not covered by this section: Wayland sessions; arm64 headless owner checks; Secret
Service and polkit on Debian 12 and Ubuntu 22.04; browsers on the release build (the
browser matrix above is of debug builds); the release workflow itself (no `image-*`
tag was pushed); the published `/dl/` download.

## Browser check hardening, 2026-11-11 (unit L8)

The hardened browser check of `feat/linux-caller-hardening` (stacked on PR #110): the
refused switches of the current Chromium switch list, an allow list next to Debian's
system extensions, the same mount and user namespace as Apassy, and ADR 0045's
section "What the switch check sees". Same kit, run prefix `l8` (`~/work/l8`, accounts
`l8owner` and `l8headless`).

Result: everything that ran passed. Google Chrome and Debian's Chromium with a Debian
system extension still create and use passkeys with their default start and with
display, GPU and language switches; every newly refused switch that let Chrome start
was refused on the real browser; a browser in another mount namespace was refused
with the sandbox explanation. arm64 was not run.

### Build under test

| Build | Source | Files (SHA-256) |
| --- | --- | --- |
| 69a73575 | `69a73575`, exported with `git archive`; built on devbox-x86 in an `ubuntu:24.04` container with Rust 1.97.0 by the commands of `build-on-devbox.sh` (debug build, stripped, `build-vault.sh`) | `apassy-vault_0.5.19_amd64.deb` `13b2ecdae17706fbcafd01f911117a2ab308a15a30ec2a49e5292caf759e4d09`, `apassy-vault-0.5.19-linux-x86_64.tar.gz` `7cda9e0ea19f2d1844625c6f70e8946048a8258110707d7edd4f7923bd67f82e` |

Later commits of the branch change documents only.

### Environment

- Host `devbox-x86`: Ubuntu 24.04.5 LTS, kernel 6.8.0-147-generic, x86_64, seat session
  of `l8owner` on tty3, Xvfb at 1600x1000, Google Chrome 157.0.8103.50. Wayland: sway
  1.9 (headless backend) in the owner's session, grim and wtype (installed for the run,
  removed after).
- Debian: `debian:trixie` container `l8-debian13`, Chromium 156.0.8078.79-1~deb13u1 with
  `chromium-lwn4chrome` 1.0-3. Chromium 156 cannot load that Manifest V2 extension
  ("Error Loading Extension" at each start); the wrapper still passes its folder, so the
  title is the one the check sees on a real install.
- RP: the kit's `rp/`, Node.js 22, `@simplewebauthn/server` 14.0.3.

### Matrix

PASS: a sign-in (or creation) reached the Apassy card, was approved with the passphrase
and verified by the RP; for a refusal, the browser showed its own security-key dialog,
no card appeared and no sign-in verified (each screenshot checked). Every title was
read from `/proc/PID/cmdline` of the browser process.

| Case | Ubuntu Chrome 157 | Debian Chromium 156 + system extension |
| --- | --- | --- |
| Default start: passkey create | PASS | PASS (title `… --enable-remote-extensions --load-extension=/usr/share/chromium/extensions/lwn4chrome`) |
| Default start: sign-in | PASS (three times, also last) | PASS (also last) |
| `--force-device-scale-factor=1.25` | PASS | PASS |
| `--ozone-platform=x11` | PASS | PASS |
| `--ozone-platform=wayland`, native on sway | PASS | NOT RUN |
| `--lang=pl` | – | PASS |
| `--enable-features=WaylandWindowDecorations` | – | PASS |
| Outside the allow list: `--password-store=basic`, `--proxy-server=socks5://127.0.0.1:9`, `--disable-sync`, `--enable-features=UseOzonePlatform,WaylandWindowDecorations` (comma), `--enable-features=NotAboutTheDisplay` | – (accepted in Chrome by design) | REFUSED 5/5 |
| Newly refused, next to the system extension: `--enable-automation`, `--renderer-cmd-prefix=/usr/bin/env` | – | REFUSED 2/2 |
| Newly refused, each alone (31): `--allowlisted-extension-id`, `--extensions-on-chrome-urls`, `--extensions-on-extension-urls`, `--extension-test-api-on-web-pages`, `--install-isolated-web-app-from-file`, `--install-isolated-web-app-from-url`, `--custom-devtools-frontend`, `--load-webui-from-disk`, `--remote-allow-origins`, `--enable-automation`, `--dom-automation`, `--test-type`, `--silent-debugger-extension-api`, `--browser-subprocess-path`, `--renderer-cmd-prefix`, `--utility-cmd-prefix`, `--zygote-cmd-prefix`, `--gpu-launcher`, `--enable-service-binary-launcher`, `--disable-web-security`, `--allow-file-access-from-files`, `--allow-insecure-localhost`, `--use-mock-cert-verifier-for-testing`, `--mock-cert-verifier-default-result-for-testing`, `--ignore-certificate-errors`, `--ignore-certificate-errors-spki-list`, `--unsafely-treat-insecure-origin-as-secure`, `--ssl-key-log-file`, `--allow-running-insecure-content`, `--host-resolver-rules`, `--host-rules` | REFUSED 31/31 | NOT RUN |
| `--load-apps=<empty folder>` | NOT RUN: Chrome 157 exits at once with it | NOT RUN |
| Chrome started by `unshare --mount` (then `setpriv` to the owner): browser `mnt:[4026532447]`, Apassy `mnt:[4026531841]`, same user namespace | REFUSED, tooltip of the Apassy button: "Apassy: This browser runs in a sandbox, so the browser handles this request itself. Apassy works only with a browser that runs outside any sandbox and sees the files of this computer as Apassy sees them. Use Google Chrome, or Chromium from a .deb." | – |
| Message of a refused switch (`--enable-automation`) | the tooltip says "Apassy: Apassy cannot verify this browser, so the browser handles this request itself." | – |

Not counted: the first run of the Chrome cases (Chrome's search-engine choice dialog
covered the page, as in the second run); the first `--host-resolver-rules` and
`--host-rules` cases (the shell split the rule `MAP l8.example 127.0.0.1`, so Chrome
opened `l8.example` as the active tab; rerun with the rule as one argument, title above
unchanged); four Wayland attempts whose key press did not reach the page (`wtype` drops
the first key of each call; a page that starts the ceremony itself is refused by the
extension, which requires the browser's user activation).

### `chrome://flags`, observed

With `enable-quic@2` and `ignore-gpu-blocklist` in `browser.enabled_labs_experiments` of
the profile's `Local State`, Chrome 157's browser process title stayed
`/opt/google/chrome/chrome http://localhost:4174/passkey.html`: the flags reached the
child processes (the network utility process carried the QUIC setting), never the
browser's title. So the switch check does not see `chrome://flags`, as ADR 0045 now says.

### Not run in this run

arm64; Wayland Chromium on Debian; a user namespace on a real browser (unit tests
only: Ubuntu 24.04 restricts unprivileged user namespaces, and Chrome's own sandbox
needs them); real snap and Flatpak browsers against the new namespace check (their
"Not supported" state is unchanged and shares the explanation); `--load-apps`; GNOME or
KDE.

### Host changes undone

`cleanup-host.sh --packages` removed the automatic login on tty3, the accounts
`l8owner` and `l8headless` with their homes and processes, and sway, grim, wtype,
wlrctl and wl-clipboard; the run's files in `/tmp` and the container `l8-debian13` were
deleted. The host keeps the Apassy package of this build and Chrome, as after the
earlier runs.

### Screenshots

In `docs/reviews/linux-acceptance-2026-11/` (1600x1000, synthetic data):
`l8-ubuntu-01-sandbox-refused-tooltip`, `l8-ubuntu-02-switch-refused-tooltip`,
`l8-ubuntu-03-wayland-card`, `l8-ubuntu-04-wayland-verified`,
`l8-debian13-01-system-extension-card`, `l8-debian13-02-extra-switch-refused`.
