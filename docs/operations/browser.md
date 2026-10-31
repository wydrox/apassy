# The browser extension

Updated: 2026-11-01.
Decision: [ADR 0021](../adr/0021-browser-extension.md). Wire: [browser-v1](../contracts/browser-v1.md). Code: `extension/` (the extension), `src/bin/apassy-browser-host.rs` and `src/browser/` (the host, the wire, the site match, the new passwords, and the install), `src/desktop/browser.rs` (the app side), `src/desktop/ui/browser_settings.rs` (Settings), `src/cli/browser.rs` (`apassy setup browser`).

The Apassy extension fills a login on a website in Helium, Google Chrome, Chromium, Brave, Microsoft Edge, Arc, or Vivaldi. It also saves a login that you type on a page, and makes a new password for a sign-up. Each fill and each save asks for Touch ID or the passphrase in Apassy. Agents never get the password: it needs you, every time.

## Owner-check frequency (ADR 0030)

On this Mac, Settings > Security > **How often to ask for Touch ID** offers
Every time (default), 1 minute, 5 minutes, 15 minutes, 1 hour, and Until the Mac
locks. A fresh local Touch ID or passphrase check, including unlock, starts an
absolute window. Browser password/code fill, save, create/update, macOS AutoFill
password/code fill, passkey sign-in, and an explicitly clicked Allow once can reuse
it. Browser fills complete without an Apassy sheet. Passkey assertions still set
UP and UV using the recent local owner verification. Passkey create/remove,
reveal/copy (including OTP), exports/backups/restores, durable permissions,
production/project approvals, bouncer evaluation permission, rule relaxations,
tokens/connections, pairing and the setting itself stay fresh. Remote/iPhone
answers neither spend nor start the window. The iPhone app is unchanged.

Use does not extend the deadline. Lock, sleep, user switch, quit, vault lock or
switch, setting changes, failed/cancelled checks and observer loss revoke it.
The policy is protected in this Mac's app-owned device-only Keychain item; the
window exists only in memory. Missing/unverified storage or lifecycle state means
Every time. Older extension/host requests without trusted gesture provenance take
the fresh path. See [ADR 0030](../adr/0030-owner-check-window.md) for the exact
allowlist, residual browser-automation exposure and native acceptance limits.
This section supersedes unqualified per-fill/per-sign-in freshness wording below;
historical device acceptance remains historical.


## 1. Set up

1. Open Apassy.app and go to Settings > Tools > Browser extension.
2. Click **Connect** next to your browser. Apassy connects the browser and opens the Apassy page of the Chrome Web Store in it: <https://chromewebstore.google.com/detail/apassy/bbnpgnjnfjlbgggmpnhejpmfjhmmhiih>.
3. Click **Add to Chrome**.
4. Pin the Apassy button to the toolbar, open a login page, and click it. Settings shows "Last request just now" when the extension reached Apassy.

Do steps 2 and 3 once for each browser. The store updates the extension by itself.

From a terminal, `apassy setup browser` does step 2 for every browser on this Mac and prints the store address. `--browser helium` selects one browser. `--remove` disconnects them. Settings and the command work only from Apassy.app: a source build is not protected from agents.

Without the store, the folder `Contents/Resources/browser-extension` of Apassy.app has the same extension with the same ID: turn on **Developer mode** on the extensions page of the browser, and drag the folder onto the page. `apassy setup browser` prints its path. An update of Apassy.app updates that folder, and the browser loads it at its next start.

## 2. Make a login fillable

A login fills only on the sites of its websites.

- The login form has the field **Website**. Type the address of the login page, for example `https://github.com/login`. Apassy refuses a value that is not a web address.
- A login from the 1Password import gets its first address in Website, and the others as the details "Website 2", "Website 3", and so on. The import does not select logins at first: select them in the preview.
- A visible detail whose label starts with "Website" or "URL" adds another site.
- "Save this login" and "New password" (section 4) set the Website for you.

## 3. Fill

1. Open the login page.
2. Click the Apassy button, or press ⌘⇧L.
3. The popup shows the logins for the site. Choose one with the mouse, or with the arrow keys and Return.
4. Confirm with Touch ID, or type the passphrase in the Apassy window. The Touch ID prompt names the login and the site. The window comes to the front only when the passphrase is needed. After about 3 minutes the owner check ends, and nothing is filled.
5. Apassy fills the username and the password. The page gets the values once. The history of the login shows "You filled it in your browser" with the site.

To fill nothing, click Cancel in the Apassy window. When you cancel the Touch ID prompt, the window comes to the front and asks for the passphrase; click Cancel there.

Each fill asks again. There is no setting that turns the check off.

### Inline suggestions

With broad HTTPS and localhost access, **Suggest logins on all sites** is on by default, including after an update from per-site suggestions. Existing passkey access is sufficient. Without access, click **Allow suggestions on all sites** once in the popup. Browser permission requests need a click. Settings contains the global switch, passkeys and **Not on this site**. The site exclusion is stored locally by hostname and can be undone there. Turning suggestions off does not revoke passkey access.

Focus a username or password field, including on a username-first page, to see account titles and usernames. An already-focused field is queried on injection and reload. Labels, aria-label and placeholders can identify a username; search, OTP, hidden, read-only, newsletter-only and shown-as-text password fields are excluded. Press Option-Down (or Down on the field) to enter the chooser, use arrows and Return to choose, and Escape to dismiss and return to the field. The account list scrolls separately. The menu aligns below the field and flips above when it would cover Submit and fits there. It stays within the viewport and follows scrolling/resizing; it never moves beside the form. If space is insufficient, use the field button or toolbar.

Typing a username filters matching accounts. **No login matches this username** offers **Show all accounts**; **No logins for this site** means there are no site matches. If a saved login has no Website, add one in Apassy. An empty result does not prove that a Website is missing. Popup search filters only this site's returned metadata, not the vault. Account **Details** contains Update login and Fill code when available.

No focus or unlock fills a field. Every fill needs a trusted account choice and the app's owner check. Same-origin frames, including `srcdoc` and `about:blank`, are document-bound. Cross-origin frames and form actions are refused with an own-tab instruction. A username-only fill does not automatically fill the next password step.

## 4. Save a login, or make a new password

**After submitting.** With suggestions and site access enabled, typing a password
and submitting a login/sign-up can show a top-right **Save this login in Apassy?**
banner after a same-origin navigation or a form transition. A matching
username instead shows **Update the password in Apassy?**. Username-first flows
remember the previous step for up to three minutes in the same tab and origin.
The banner detects submission; it does not prove that the website accepted it.
Choose **Save** or **Update** to send the typed password through the app's existing
owner check. ADR 0030's local Touch ID window applies. Focus and submission alone
send only site/username metadata to the app, never the password.

**Not now** discards the captured password. **Never for this site** also turns off
suggestions for that hostname, sharing **Not on this site** in toolbar Settings.
Choose **Suggest on this site again** there to restore both features. Apassy-filled
passwords without editing, search/OTP forms and cross-origin actions produce no
offer. New-password confirmations must match.

Captured passwords exist only in content-script/worker memory, bound to tab and
exact origin. Dismissal, save/update consumption, tab close, another origin,
disabled site access or three minutes erases the references. A submission with no
transition expires after 15 seconds. Browser/worker restart loses pending offers;
there is no disk-backed recovery. No captured password is stored in extension
storage or displayed by the banner.

**Save this login.** Type the username and the password on the login page, but do not submit yet. Open the popup and click **Save this login**. Check the title and the username, and click **Save**. Apassy asks for Touch ID or the passphrase ("For https://example.com: save the login "Example" (rafal)"), then adds a login with the website of the page. The popup never sees the password.

**New password.** On a sign-up page, type your email or username, open the popup, and click **New password**. Check the title and the username, choose the length (12 to 64) and symbols, and click **Create and fill**. After Touch ID or the passphrase, Apassy makes the password, keeps it in the vault, and fills it into the page, also into the "repeat password" field. Then submit the form. The password never goes to the pasteboard.

A login with the same username for the site is refused: the popup names it. To change an existing password, open that account’s Details, choose Update login, review the exact account, then approve Update this login on your Mac. Only its password changes. New-password confirmations must agree. After an uncertain save or update, check Apassy before trying again.

## 5. Which site gets a login

- The page must be `https:`. `http:` works only for `localhost` and `127.0.0.1`.
- `github.com` fills on `github.com` and on its subdomains, for example `gist.github.com`.
- `www.tumblr.com` fills on `www.tumblr.com` and `tumblr.com`, but not on `someone.tumblr.com`.
- `accounts.google.com` does not fill on `google.com`. `github.com` does not fill on `github.com.evil.example`.
- The port must match. `localhost` fills only on `http://localhost/`. For a development server, store the port: `localhost:3000`. An IP address fills only on itself.
- Unicode and punycode hosts canonicalize identically. A Website that is a public suffix, such as `co.uk` or `github.io`, is refused. Matching does not widen to sibling sites.
- Archived logins never fill.

The app checks the site when the popup opens, before the owner check, and again after it. The extension fills only a page whose origin is still the origin that Apassy answered. A page that went to another site while you confirmed gets nothing.

## 6. What the popup says

| The popup says | Do this |
| --- | --- |
| Apassy is not connected to this browser. | Click Connect in Settings > Tools > Browser extension, then restart the browser. |
| Open Apassy to fill logins. | Open Apassy.app. |
| Unlock Apassy to fill logins. | Click "Open Apassy" and unlock the vault. |
| Apassy fills logins on https pages only. | The page is not `https:`. |
| No login for this site. | Set the Website of the login (section 2), or save it from the page (section 4). |
| Type your password on the page first. | "Save this login" found no typed password. Type it, then save. |
| "…" is in Apassy for this page with the username … | The login exists. Fill it, or change it in Apassy. |
| Another owner check is open in Apassy. | Finish the other check in Apassy, then try again. |
| The page changed. Nothing was filled. | The tab went to another site. Open the login page again. |
| A red "!" on the Apassy button | The fill failed after the popup closed. Hover over the button for the reason. |

## 7. Agents and the sandbox

- An agent in `apassy-sandbox` cannot connect to `browser.sock` and cannot start `apassy-browser-host`. Both are in places that the profile denies.
- The profile denies a write to every `NativeMessagingHosts` folder. A browser starts the program of a host manifest outside the sandbox, so a planted manifest could replace the Apassy host ([isolation](isolation.md), section 7).
- The profile denies a change of `Preferences`, `Secure Preferences`, and `Local State` of the browsers in section 1, and a new or renamed profile folder. So an agent cannot point the Apassy extension at its own code. A browser that an agent starts with your real profile folder cannot start in the sandbox; a temporary profile works.
- With Every time, each fill waits for fresh local verification. Opt-in windows permit covered gestures without another Apassy sheet; browser automation can generate trusted browser events. See ADR 0030 above.
- After a fill, the page has the password. A program that controls the browser (DevTools Protocol, Playwright, an AI browser extension) can read it there. Do not fill in a browser window that an agent controls.

## 8. Limits

- Cross-origin frames and form actions are not filled. Open the sign-in site in its own tab. Same-origin blank/srcdoc frames are supported.
- Post-submit offers support the top frame on granted sites. Closed page shadow roots are not accessible. Offers require a same-origin document navigation, URL change or removal/hiding of the submitted form within 15 seconds; a site that keeps the same form visible can still use the toolbar's Save this login. Ambiguous or capped metadata results suppress an offer.
- Metadata lists contain at most 50 accounts, with username filtering before that limit. Targets and nonsecret result messages expire after five minutes. Owner checks wait up to 180 seconds; native transport waits up to 240 seconds and the extension timeout is 250 seconds.
- A process of your user outside the sandbox can ask for the titles and usernames of the logins of a site while the vault is unlocked. It gets no password without your Touch ID (ADR 0021, D1).

## 9. Development

The extension is plain JavaScript without a build step. The end-to-end tests run in Helium against a mock host, and one test runs the real `apassy-browser-host`:

```sh
cargo build --bin apassy-browser-host
cd extension-tests
npm install
APASSY_BROWSER_HOST="$PWD/../target/debug/apassy-browser-host" npx playwright test
```

The tests never use Google Chrome or a browser that Playwright downloads. `HEADED=1` shows the browser. Without the host binary, the real-host test is skipped.

For a Playwright-free smoke and paired screenshots in an isolated Helium profile:

```sh
node extension-tests/cdp/suggest-smoke.mjs /absolute/path/to/evidence
```

This uses CDP port 9371, a profile-local mock host and synthetic metadata only. It checks broad access, autofocus, labels, exclusions, empty reasons, frames, refusals and public-page geometry. It never opens the owner's profile or vault. Render-state screenshots are UI fixtures, not proof of native Touch ID or successful sign-in.

For typed submission offers and placement (Helium/CDP only, port 9401):

```sh
node --test extension-tests/fixtures/login-journey/*.unit.mjs
node extension-tests/cdp/save-offer-smoke.mjs /absolute/path/to/evidence
```

The second command creates and removes its own profile, registers the mock host
only there, types synthetic fixture credentials, and captures light/dark pairs.
GitHub, Google and Vercel checks only load and focus empty fields. Ports 9222 and
9223 are not used. Mock requests redact password fields. The fixture round trips
do not qualify native Touch ID or the owner's vault. CI runs the corresponding
Playwright specifications; local smoke verification needs no Playwright.

The Rust side has unit tests in `src/browser/`, the app tests in `src/desktop/ui/browser_tests.rs`, and the profile tests `profile_denies_the_browser_socket` and `profile_denies_native_messaging_host_manifests` in `tests/isolation/product_profile.rs`.

`scripts/build-app.sh` copies `extension/` into `Contents/Resources/browser-extension`, checks that its version is the version in `Cargo.toml`, signs `apassy-browser-host`, and checks that the host refuses another extension and that the agent profile denies its start.
