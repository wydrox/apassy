# Publish the extension in the Chrome Web Store

Date: 2026-10-08.
Decision: [ADR 0021](../adr/0021-browser-extension.md), D5. Package: `scripts/build-extension-zip.sh`. Images: `design/store/chrome-web-store/`. Privacy policy: <https://apassy.wyderka.cc/privacy> (`site/src/pages/privacy.astro`).

The store makes the install one click ("Add to Chrome") and checks the files of an installed extension, so a changed file on disk disables it. Until then, the extension loads from inside Apassy.app with Developer mode ([browser](browser.md), section 1).

Only the owner can do the steps marked **Owner**: they need the owner's Google account, a payment, and a legal declaration. The rest is in the repository.

## 1. Before the first upload

1. **Owner.** Register as a Chrome Web Store developer at <https://chrome.google.com/webstore/devconsole> with the Google account that will own the item. It costs a one-time fee of 5 USD and needs 2-step verification and a verified contact email.
2. **Owner.** Declare in the account whether you are a trader under the EU Digital Services Act. The store shows a trader's address and contact details to users in the EU.
3. Build the package:

   ```sh
   scripts/build-extension-zip.sh
   ```

   It writes `target/dist/apassy-extension-<version>.zip`: the folder `extension/`, without the `key` of its manifest (the store gives the item its own key), with the version of `Cargo.toml`. It prints the SHA-256 and the files.

## 2. Make the item and take its ID

Done on 2026-10-08: the draft item is `bbnpgnjnfjlbgggmpnhejpmfjhmmhiih` of the publisher `wyderkarafal@gmail.com`. The repository has its key and its ID.

1. **Owner.** In the developer dashboard, click "Add new item" and upload the ZIP. Do not submit it yet.
2. **Owner.** Open the Package tab, click "View public key", and copy the text between `-----BEGIN PUBLIC KEY-----` and `-----END PUBLIC KEY-----`. Copy the item ID from the dashboard address too.
3. Change the ID in the repository to the ID of the store item, in one commit:
   - `extension/manifest.json`, `"key"`: the public key of the store, in one line;
   - `src/browser/wire.rs`: `EXTENSION_ID` and `EXTENSION_ORIGIN`;
   - `extension-tests/support/fixtures.mjs`: `EXTENSION_ID`;
   - this guide, [browser-v1](../contracts/browser-v1.md), [ADR 0021](../adr/0021-browser-extension.md), and `extension/README.md`.

   Then the folder in Apassy.app and the store item have one ID, and the host manifest (`allowed_origins`) allows it. Check that the key gives the ID: `base64 -D` of the key, SHA-256, the first 32 hexadecimal digits with 0–f mapped to a–p.
4. Release the app with the new ID (a merge to `main` publishes it), **before** the store item is public. An extension from the store needs an Apassy that allows its ID.

## 3. Store listing

**Owner** pastes these texts into the dashboard.

- **Name:** Apassy (from the manifest).
- **Summary:** from the manifest: "Fill, save, and create logins from the Apassy app on your Mac. Each fill asks for Touch ID or your passphrase."
- **Category:** Privacy & Security, or Productivity › Tools if the dashboard has no such category.
- **Language:** English.
- **Homepage:** <https://apassy.wyderka.cc>. **Support:** <https://github.com/wydrox/apassy/issues>.
- **Images:** the 128 × 128 icon, the 440 × 280 promotional tile, and the screenshots (1280 × 800) in `design/store/chrome-web-store/`.
- **Description** (the first upload was rejected on 2026-10-08 for "excessive keywords" because the text listed six browsers; name no browsers in it):

  ```text
  Apassy is a credential manager for you and your AI agents, on your Mac. This extension fills your Apassy logins into websites in your browser.

  • Fill: open the extension on a login page, choose a login, and confirm with Touch ID or your Apassy passphrase. Apassy asks every time, so nothing fills without you, not even an agent that drives your browser.
  • Save this login: type your username and password on a page, click Save this login, and confirm. The login goes into your Apassy vault with the address of the site.
  • New password: on a sign-up page, Apassy makes a strong password, keeps it in your vault, and fills it into the form. It never goes to the clipboard.
  • Strict site match: a login fills only on its own site, over https.

  The extension needs the Apassy app for macOS (https://apassy.wyderka.cc). Apassy keeps the logins in an encrypted vault on your Mac and talks to the extension through the browser's native messaging. The extension has no servers, makes no network requests, stores nothing in the browser, and never uses the clipboard.

  Open source: https://github.com/wydrox/apassy
  ```

## 4. Privacy tab

- **Single purpose:** "Apassy fills, saves, and creates website logins from the user's Apassy vault on the same Mac."
- **Permission justification:**
  - `nativeMessaging`: "Talks to the Apassy app on the same Mac through its native messaging host. The app keeps the logins and asks for Touch ID; the extension has no other source of logins."
  - `activeTab`: "After the user clicks the Apassy button, reads the address of the active tab to list the logins of that site, and gets access to that tab to fill it."
  - `scripting`: "After the user confirms with Touch ID, puts the username and the password into the login fields of the active tab. When the user clicks Save this login, reads the username and the password that the user typed there. Only in the top frame of the active tab, and only after a click."
- **Remote code:** No. All JavaScript is in the package.
- **Data usage:** check "Authentication information" and "Personally identifiable information" (a username can be an email address). Nothing else. The data goes only to the Apassy app on the same device.
- **Certifications:** check all three: the data is not sold, not used for purposes unrelated to the single purpose, and not used for creditworthiness.
- **Privacy policy:** <https://apassy.wyderka.cc/privacy>.

## 5. Distribution and review

- **Distribution:** free, all regions. **Visibility:** Public. Choose Unlisted while the app release of section 2, step 4, is not out.
- **Test instructions** for the reviewers:

  ```text
  The extension needs the Apassy app for macOS 15 or later on Apple silicon.
  1. Download Apassy from https://apassy.wyderka.cc/download and open it. Create a vault with any passphrase.
  2. Add a credential: kind Login, any username and password, Website https://github.com/login.
  3. In Apassy, open Settings > General > Browser extension and click Connect next to Chrome. This installs the native messaging host manifest for the browser.
  4. Open https://github.com/login, click the Apassy button, and choose the login. Confirm with Touch ID or the passphrase in the Apassy window. The username and the password appear in the form.
  Without the app the popup says "Apassy is not connected to this browser."
  ```

- **Owner.** Submit for review. With "Publish automatically" off, the item waits up to 30 days after the approval for the owner to publish it.

## 6. After the approval

- Put the store address in Settings > General > Browser extension and on the site, so "Connect" and the site offer "Add to Chrome" in place of Developer mode. Update ADR 0021, D5, and [browser](browser.md), section 1.
- New versions: build the package with the new version of `Cargo.toml` and upload it. The store needs a higher version for each upload. The Chrome Web Store API v2 can upload and publish with a service account. CI can do it after the owner gives the service account access to the publisher and stores its key as a GitHub secret.
