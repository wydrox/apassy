# The browser extension

Date: 2026-10-06.
Decision: [ADR 0021](../adr/0021-browser-extension.md). Wire: [browser-v1](../contracts/browser-v1.md). Code: `extension/` (the extension), `src/bin/apassy-browser-host.rs` and `src/browser/` (the host, the wire, the site match, the new passwords, and the install), `src/desktop/browser.rs` (the app side), `src/desktop/ui/browser_settings.rs` (Settings), `src/cli/browser.rs` (`apassy setup browser`).

The Apassy extension fills a login on a website in Helium, Google Chrome, Chromium, Brave, Microsoft Edge, Arc, or Vivaldi. It also saves a login that you type on a page, and makes a new password for a sign-up. Each fill and each save asks for Touch ID or the passphrase in Apassy. Agents never get the password: it needs you, every time.

## 1. Set up

1. Open Apassy.app and go to Settings > General > Browser extension.
2. Click **Connect** next to your browser. Apassy connects the browser, opens its extensions page, and shows the folder `browser-extension` in the Finder.
3. On the extensions page, turn on **Developer mode**. Drag the folder `browser-extension` from the Finder onto the page.
4. Pin the Apassy button to the toolbar, open a login page, and click it. Settings shows "Last request just now" when the extension reached Apassy.

Do steps 2 and 3 once for each browser. A browser takes an extension from another app only through the Chrome Web Store, so the Developer mode step stays until Apassy is in the store (ADR 0021, D5).

From a terminal, `apassy setup browser` does step 2 for every browser on this Mac and prints the folder. `--browser helium` selects one browser. `--remove` disconnects them. Settings and the command work only from Apassy.app: a source build is not protected from agents.

An update of Apassy.app updates the extension folder. The browser loads the new version at its next start.

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
4. Confirm with Touch ID, or type the passphrase in the Apassy window. The Touch ID prompt names the login and the site. The window comes to the front only when the passphrase is needed. After about 4 minutes the request ends, and nothing is filled.
5. Apassy fills the username and the password. The page gets the values once. The history of the login shows "You filled it in your browser" with the site.

To fill nothing, click Cancel in the Apassy window. When you cancel the Touch ID prompt, the window comes to the front and asks for the passphrase; click Cancel there.

Each fill asks again. There is no setting that turns the check off.

## 4. Save a login, or make a new password

**Save this login.** Type the username and the password on the login page, but do not submit yet. Open the popup and click **Save this login**. Check the title and the username, and click **Save**. Apassy asks for Touch ID or the passphrase ("For https://example.com: save the login "Example" (rafal)"), then adds a login with the website of the page. The popup never sees the password.

**New password.** On a sign-up page, type your email or username, open the popup, and click **New password**. Check the title and the username, choose the length (12 to 64) and symbols, and click **Create and fill**. After Touch ID or the passphrase, Apassy makes the password, keeps it in the vault, and fills it into the page, also into the "repeat password" field. Then submit the form. The password never goes to the pasteboard.

A login with the same username for the site is refused: the popup names it. To change the password of a login that exists, edit it in Apassy.

## 5. Which site gets a login

- The page must be `https:`. `http:` works only for `localhost` and `127.0.0.1`.
- `github.com` fills on `github.com` and on its subdomains, for example `gist.github.com`.
- `www.tumblr.com` fills on `www.tumblr.com` and `tumblr.com`, but not on `someone.tumblr.com`.
- `accounts.google.com` does not fill on `google.com`. `github.com` does not fill on `github.com.evil.example`.
- The port must match. `localhost` fills only on `http://localhost/`. For a development server, store the port: `localhost:3000`. An IP address fills only on itself.
- Archived logins never fill.

The app checks the site when the popup opens, before the owner check, and again after it. The extension fills only a page whose origin is still the origin that Apassy answered. A page that went to another site while you confirmed gets nothing.

## 6. What the popup says

| The popup says | Do this |
| --- | --- |
| Apassy is not connected to this browser. | Click Connect in Settings > General > Browser extension, then restart the browser. |
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
- An agent that drives a browser cannot fill: each fill waits for you.
- After a fill, the page has the password. A program that controls the browser (DevTools Protocol, Playwright, an AI browser extension) can read it there. Do not fill in a browser window that an agent controls.

## 8. Limits

- Logins in a frame of another site are not filled. Copy the password from the Apassy window there.
- The extension does not change the password of a login that exists.
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

The Rust side has unit tests in `src/browser/`, the app tests in `src/desktop/ui/browser_tests.rs`, and the profile tests `profile_denies_the_browser_socket` and `profile_denies_native_messaging_host_manifests` in `tests/isolation/product_profile.rs`.

`scripts/build-app.sh` copies `extension/` into `Contents/Resources/browser-extension`, checks that its version is the version in `Cargo.toml`, signs `apassy-browser-host`, and checks that the host refuses another extension and that the agent profile denies its start.
