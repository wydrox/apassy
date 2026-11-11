# ADR 0045 — Linux vault and browser passkeys

Status: Accepted for implementation; runtime qualification remains required.
Date: 2026-11-10

Linux x86_64 and arm64 use the shared SQLCipher vault, WebAuthn implementation,
and egui owner UI. Ubuntu and Debian are the first supported distributions.
This extends ADR 0041: Chrome stable and Chromium native messaging are enabled.
A passphrase must remain sufficient without a session bus, screen lock, biometric
reader, or desktop. Headless owner operations require an interactive terminal.
`apassy owner serve` hosts the browser and agent services without a desktop, and
approves each request only with a typed answer and the passphrase (or polkit) in that
terminal. It locks after `--idle-minutes`, else the device policy's "Lock after
inactivity" time, else 15 minutes, counted on the sleep-inclusive clock; the policy
"When the screen locks or the computer sleeps" also ends it at screen lock, sleep,
user switch and session end. SIGTERM, SIGHUP and SIGINT keep their default action:
the process ends at once, the key leaves with its memory, the sockets close and
waiting requests fail. There is no handler, because the crate forbids `unsafe` and
no new dependency is added.

## Security boundary

Linux has no macOS code-signing identity, Secure Enclave or Touch ID boundary.
Root and compromised same-user processes are outside the protection offered by
this software vault. Harden secret-bearing processes against dumps and ptrace;
keep sockets and files private. X11 permits input interception; prefer Wayland.
Browser identity uses kernel peer credentials and a verified direct browser parent,
with root-owned executable paths, never process names or caller-supplied PIDs.
The host verifies its own installed executable. The app verifies that host image
when readable; Linux hides a non-dumpable peer's executable, so only that kernel
permission refusal uses peer credentials and browser ancestry instead. This does
not authenticate a hardened host executable to the app. Injected browser children
and compromised same-user processes remain outside this boundary. Reject unknown
browsers, stale processes, mismatched users and writable browser binaries.
This is defense in depth, not an equivalent to macOS signing. Preserve origin,
RP ID, challenge, approval and user-verification checks in the shared flow.

When the kernel hides the host's executable (a non-dumpable peer), the app still
verifies, on the kernel's data only: the peer's user (`SO_PEERCRED` and all four user
IDs of `/proc/PID/status`), its PID and start time, that the kernel itself hid the link
(`/proc/PID/exe` owned by root), and of its direct parent (`/proc/PID/stat`) the user,
start time, root-owned browser executable, mount and user namespaces and switches; the
peer's own namespaces are not readable then, and nothing is taken from the peer's
messages, title or environment. Each property is read twice within one check, after
the request line arrived, and since 2026-11-11 the whole check runs again after the
owner answered: the answer leaves only for the same peer process and the same browser
process (by PID and start time), else the request gets the generic refusal
(`check_same_peer`, tests in `caller_linux.rs` and `passkey_controller_tests.rs`).

Unsafe browser switches are refused, read from every word of the browser's
rewritten process title: `--remote-debugging-*`, `--load-extension` (one exception,
below), and, since 2026-11-11, every switch of the current Chromium switch list that
loads code or apps by path or gives extensions more power (`--disable-extensions-except`,
`--load-apps`, `--allowlisted-extension-id`, `--extensions-on-chrome-urls`,
`--extensions-on-extension-urls`, `--extension-test-api-on-web-pages`,
`--install-isolated-web-app-from-file`, `--install-isolated-web-app-from-url`,
`--custom-devtools-frontend`, `--load-webui-from-disk`), automates the browser
(`--remote-allow-origins`, `--enable-automation`, `--dom-automation`, `--test-type`,
`--silent-debugger-extension-api`), replaces the programs it starts (`--type`,
`--browser-subprocess-path`, `--renderer-cmd-prefix`, `--utility-cmd-prefix`,
`--zygote-cmd-prefix`, `--gpu-launcher`, `--enable-service-binary-launcher`), or
silently weakens how it treats pages, certificates and names
(`--disable-web-security`, `--allow-file-access-from-files`, `--allow-insecure-localhost`,
`--use-mock-cert-verifier-for-testing`, `--mock-cert-verifier-default-result-for-testing`,
`--ignore-certificate-errors`, `--ignore-certificate-errors-spki-list`,
`--unsafely-treat-insecure-origin-as-secure`, `--ssl-key-log-file`,
`--allow-running-insecure-content`, `--host-resolver-rules`, `--host-rules`). Since
2026-11-11 every browser is also refused when it was started with a switch that turns
off its sandbox or its site isolation or hands flags to its JavaScript engine
(`--no-sandbox`, `--disable-setuid-sandbox`, `--disable-site-isolation-trials`,
`--disable-site-isolation-for-policy`, `--js-flags`), or with a `--disable-features`
value that names a site-isolation or sandbox feature (a name with "Isolat",
"SitePerProcess", "OriginKeyedProcesses" or "Sandbox", the Privacy Sandbox ads features
excepted). That refusal names the switch, never its value, and says to start the browser
without it. The source files are named in `src/browser/caller_linux.rs`. Switches for the display,
the GPU, the language, the profile folder, the password store and a proxy stay
accepted (for example `--ozone-platform=wayland`, `--enable-features=…Wayland…`,
`--force-device-scale-factor`, `--password-store`, `--user-data-dir`,
`--proxy-server`): a false refusal breaks real users.

The exception, added 2026-11-10 after the acceptance run: Debian's `chromium` package
starts every browser with `--load-extension=` and the folders in
`/usr/share/chromium/extensions` that its `webext-*` packages install
(`/etc/chromium.d/extensions`). That switch is accepted when its one value lists only
absolute paths that, after resolving symlinks, are directories strictly inside that
folder, and that folder, each listed directory and every folder up to `/` are owned
by root and not writable by group or others. Then only root chose what the switch
loads, from the same root-owned tree as the browser executable that this check
already trusts; a user process cannot add an extension there. Everything else stays
refused: a path elsewhere, a relative, missing or empty path, an empty value
(Debian's default when no system extension is installed), a second
`--load-extension` with another value, and, because the title hides where an
argument ends, a comma in any other word while the switch is present. Since
2026-11-11 the rest of such a title is an allow list, not a block list: the browser
executable as the first word, the switches that Debian's wrapper and
`/etc/chromium.d/*` add (`--show-component-extension-options`,
`--enable-gpu-rasterization`, `--no-default-browser-check`, `--disable-pings`,
`--media-router`, `--disable-dev-shm-usage`, `--enable-remote-extensions`,
`--disable-background-networking`), display, GPU and language switches
(`--ozone-platform`, `--ozone-platform-hint`, `--enable-wayland-ime`,
`--wayland-text-input-version`, `--gtk-version`, `--force-device-scale-factor`,
`--force-dark-mode`, `--start-maximized`, `--disable-gpu`, `--disable-gpu-compositing`,
`--disable-gpu-rasterization`, `--ignore-gpu-blocklist`, `--enable-zero-copy`,
`--use-gl`, `--use-angle`, `--num-raster-threads`, `--lang`, `--accept-lang`,
`--enable-features` and `--disable-features` with one plain feature name that
contains Wayland, Ozone, Vaapi, Vulkan or AcceleratedVideo), since 2026-11-11 the
profile, password-store and proxy switches (`--profile-directory`, which Chromium's own
per-profile desktop shortcuts use, with the number of a `Profile N` folder as the next
word, `--user-data-dir`, `--password-store`, `--proxy-server`: accepted for every
other browser already, and what a profile holds is outside what the check can see in
every case), and `http://` or `https://` page addresses. Any other word refuses the
browser. The bare, empty `--load-extension` stays refused.

The browser process must be in Apassy's mount namespace and user namespace
(`/proc/PID/ns/mnt` and `/proc/PID/ns/user`, compared by device and inode with
`/proc/thread-self/ns/*` of the checking thread). Apassy checks executable paths,
owners and `--load-extension` folders in its own view of the files, at the time of
the request; a browser in another mount namespace read other files, and in another
user namespace owners and user IDs mean something else. The namespaces are read
between the two reads of the browser's process identity, like the executable, and
once more after the title. Such a browser is "not supported", with the same
explanation as a snap or a Flatpak in Settings > Tools and `apassy setup browser`
(`SANDBOX_REASON` in `src/browser/install.rs`): this covers snaps, Flatpaks,
firejail, bubblewrap, `unshare` and a browser in another container.

### What the switch check sees

The check reads `/proc/PID/cmdline` of the browser process: the browser's own
process title, which lists the switches of its command line. That covers the
switches of a desktop file, of a wrapper script such as `/usr/bin/chromium` and
`/etc/chromium.d/*`, and of a terminal. It cannot see:

- the environment of the browser (for example `LD_PRELOAD`, `GTK_MODULES`,
  `GTK_PATH`, `SSLKEYLOGFILE`, `http_proxy`, `GOOGLE_API_KEY`);
- what a wrapper does other than add switches, and what `/etc/chromium.d/*` exports;
- the profile: `Preferences`, `Local State` and so `chrome://flags`, the installed
  and unpacked extensions and their files, the NSS certificate database
  (`~/.pki/nssdb`), all of them files of the same user;
- policy files (`/etc/opt/chrome/policies`, `/etc/chromium/policies`) and other
  configuration the browser reads after its start;
- whether the title is the browser's real command line: a process can rewrite its
  own title.

So against another program of the same user the switch check is best effort: such a
program can change the profile, the environment of the next start or the files of
the user, which the Linux boundary does not protect. The check stops the common
ways a browser is started for automation or with extra code, which leave a switch
in the title.

Secret and code Copy is offered only where Apassy itself owns the X11 or Wayland
(ext/wlr data-control) clipboard, learns of foreign replacement, and clears only
its own copy by replacing it with an empty one; other sessions have no Copy.
GNOME on Wayland offers no data-control protocol, so Copy there uses the X11
clipboard through XWayland.

Passphrase unlock is the default. Optional Secret Service storage requires explicit
opt-in explaining that other same-user clients can retrieve an unlocked keyring
item. Never silently store a passphrase, log it, or pass it on a command line.
Optional polkit auth_self presence may use system PAM/fprintd; unavailable or
cancelled authentication must not count as success. Passphrase confirmation is
always available. Two rules apply, as on macOS. Approval binding: an approval of an
agent run or a browser request names one pending operation (the run exactly as
shown; the origin, RP ID, account and user verification of a passkey), and its proof
is valid for that operation only, also when the reuse window covered it. Reuse
window: "How often to ask" sets how long one owner check covers the owner's later
manual actions in the desktop. A passphrase or a polkit check opens it, as Touch ID
or the passphrase does on macOS, but only while lock observation is available (a
systemd-logind session or a screen saver service). It ends at screen lock, sleep,
user switch, session end and the loss of a source; the actions that always ask on
macOS ask again here too. Without lock observation every action asks again.
`apassy owner serve` has no reuse window. Auto-lock follows the same signals; while
the desktop's logind idle hint says the session is active, inactivity does not lock
the vault, as on macOS. Both settings live in `device-policy.json` in the data
directory (mode 0600, this user, no symlink). Another process of the same user can
change that file; that is outside the Linux boundary above. A damaged, foreign or
too open file gives "Every time" and "Never" in the desktop, and the default
inactivity time with the session rule in `owner serve`.

## Delivery and verification

Ship desktop and headless owner commands, browser host, Chrome/Chromium manifests,
and optional polkit policy in architecture-specific deb and tar archives. Keep
node-only operation supported. Installers must select architecture explicitly.
CI must build and test Linux vault/browser paths, including refusal cases, and
synthetic WebAuthn create/get with signature verification. Never use real accounts.
Source tests, package checks and actual desktop/browser acceptance are separate
claims. No release or main-branch push is part of this implementation.
