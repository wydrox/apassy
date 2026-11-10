# Linux vault acceptance kit

Runtime acceptance of the Linux vault package (ADR 0045) on real Linux with real
browsers: install, headless owner commands, desktop window, Secret Service, polkit,
native messaging refusals, passkey create and sign-in, and password save and fill.
The record of the first run is `docs/reviews/linux-acceptance-2026-11.md`.

Use disposable machines only (the devboxes). A second run keeps its files apart with
`L4_RUN=l5 L4_WORK=$HOME/work/l5 L4_USER=l5owner L4_HEADLESS_USER=l5headless`. The scripts install system packages,
add Google's apt repository, create synthetic accounts (`l4owner`, `l4headless`),
add an automatic login on virtual terminal 3 and change files under `/opt`. All
accounts, passphrases and websites are synthetic. Never use a real account or a
real relying party.

## Files

| File | Purpose |
| --- | --- |
| `build-on-devbox.sh` | On the Mac: build and package a commit like the CI `linux-vault` job, in a container on the devbox (`git archive`, Ubuntu 24.04, Rust 1.97.0, debug build stripped, `build-vault.sh`) |
| `release-matrix.sh` | On the devbox: one release build (CI artifact `apassy-vault-linux-x86_64`) in minimal Debian 12, 13 and Ubuntu 22.04, 24.04 containers: `install.sh` deb and tar from a `file://` origin, `ldd -r`, the window under Xvfb with the libraries it loads, the headless owner checks; Debian 11 and Ubuntu 20.04 refused |
| `setup-host.sh` | Install Xvfb, openbox, xdotool, ImageMagick, gnome-keyring, libsecret-tools, polkitd, Google Chrome stable, Chromium (Debian: deb; Ubuntu: snap), Node.js 22 and the RP's dependency |
| `container.sh` | Create the disposable `debian:trixie` container for the Debian target |
| `run-target.sh` | One command per target: install the package as documented, run the scripted checks, create the vault in the window, start the RP |
| `headless-owner.sh` | `apassy owner` commands in a real terminal of an account without session bus, display or logind session |
| `keyring-polkit.sh` | Secret Service opt-in, refusal, unlock, no bus, locked keyring, disable; polkit agent for the window |
| `refusals.sh` | Caller-check refusals: `api` (wrong parents, root, other user, other origin) and `browser` (remote-debugging switch, copied Chrome, writable Chrome) |
| `rp/` | Local relying party on `http://localhost:4174` (also `otp.html`: a one-time code checked against the synthetic seed `L4_TOTP_SEED`), verified with `@simplewebauthn/server` 14.0.3; ES256 only, user verification required, discoverable sign-in, and a wrong origin, wrong RP ID and damaged signature that must be refused for each accepted response; `passkey.html` (keys `c`, `g`, `w`, `x`) and `login.html` |
| `lib/l4.sh` | Session plumbing: the seat session, Xvfb, screenshots, xdotool input, the RP |
| `lib/flows.sh` | Window and browser steps by real X input, at 1600x1000 |
| `lib/native_frame.py` | Send one synthetic `passkey_get` to the host or the app socket; prints only the answer code |
| `lib/wayland.sh`, `lib/sway.conf` | A headless sway in the owner's session (no `DISPLAY`): `l4_wayland_up`, `l4_wl_spawn`, `l4_wl_shot` (grim), `l4_wl_type`/`l4_wl_key` (wtype). Each `wlrctl` call makes a new virtual pointer, so clicks do not reach the window; drive it by keyboard |
| `cleanup-host.sh` | Undo host mode: the automatic login, the synthetic accounts, the copied Chrome; `--packages` also removes the Wayland test tools |

## Run

1. On the Mac, build the commit to qualify (or download its CI artifact):

   ```sh
   packaging/linux/acceptance/build-on-devbox.sh x86 HEAD    # or: arm
   rsync -a --delete packaging/linux/acceptance/ dev@devbox-x86:work/l4/kit/
   ```

2. On the devbox: `cd ~/work/l4/kit && bash setup-host.sh`, then one of:

   ```sh
   bash run-target.sh ubuntu   ~/work/l4/artifacts/build-x86_64-<commit> deb
   bash run-target.sh ubuntu   ~/work/l4/artifacts/build-x86_64-<commit> tar
   bash run-target.sh debian13 ~/work/l4/artifacts/build-x86_64-<commit> deb
   ```

   Ubuntu runs on the host: polkit's `allow_active` needs the local seat session
   that `l4_seat_up` creates. Debian runs in a container without a seat, so polkit
   is not tested there. Install the deb or the tar on a host, not both: remove the
   deb first (`apt-get remove apassy-vault`).

3. Browser (Chrome; the same steps for Debian Chromium with `dy=-22`), in a shell
   with `. lib/l4.sh; . lib/flows.sh` (and `L4_CONTAINER=l4-debian13
   L4_OUT=$HOME/work/l4/out-l4-debian13` for Debian):

   ```sh
   flow_chrome_first_run ubuntu            # Chrome only; Debian Chromium has no terms dialog
   flow_load_unpacked ubuntu 0             # -22 for Debian Chromium, -56 without the banner
   flow_enable_passkeys ubuntu             # pin the extension first in Chromium
   flow_ceremony ubuntu c                  # create, approved with the passphrase
   flow_ceremony ubuntu g                  # sign in
   flow_ceremony ubuntu w no; flow_ceremony ubuntu x no   # wrong RP ID: SecurityError
   bash keyring-polkit.sh polkit           # then "Use system authentication" in a card
   bash refusals.sh browser
   ```

   Check each screenshot in `$L4_OUT/shots`. A Chrome banner or dialog moves the
   page; then click by the screenshot. Do not use Ctrl+L while the Apassy window has
   focus: it locks the vault.

## What counts

- Passkey create: an RP `registration` event with `ok: true`, `userVerified: true`,
  AAGUID zero (Apassy) and `negative` all `refused`.
- Sign-in: an `authentication` event with `ok: true`, `discoverable: true` and
  `negative` all `refused`.
- Refusals: the browser shows its own security-key dialog, no Apassy card appears,
  and no RP event verifies.
- Password fill: a `password_login` event with `passwordMatches: true`.
- A cancelled, wrong or unavailable polkit check never approves: the card closes
  and the page gets `NotAllowedError`.

Remote debugging is refused by design, so the kit never drives a browser through
DevTools: it uses xdotool on the private display. Chrome 157 also refuses
DevTools on the default profile.
