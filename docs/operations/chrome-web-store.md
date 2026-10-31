# Publish the extension in the Chrome Web Store

Updated: 2026-10-17.
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

   It writes `target/dist/apassy-extension-<version>.zip`: the folder `extension/`, without the `key` of its manifest (the store gives the item its own key), with the version of `Cargo.toml`. It prints the SHA-256 and the files. The packager checks the exact API permissions (`activeTab`, `nativeMessaging`, `scripting`, `storage`), optional host permissions (`https://*/*`, `http://localhost/*`), and required files, including the login helpers. It rejects mandatory host access, manifest content scripts, extra permissions, unknown files, and symbolic links. Run its isolated regression checks with `python3 -m unittest discover -s scripts/tests -p 'test_extension_package.py'`.

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
- **Summary:** from the manifest: "Fill, save, and create logins from the Apassy app on your Mac. Your Mac settings control how often routine fills ask for Touch ID."
- **Category:** Privacy & Security, or Productivity › Tools if the dashboard has no such category.
- **Language:** English.
- **Homepage:** <https://apassy.wyderka.cc>. **Support:** <https://github.com/wydrox/apassy/issues>.
- **Images:** the 128 × 128 icon, the 440 × 280 promotional tile, and the screenshots (1280 × 800) in `design/store/chrome-web-store/`.
- **Description** (the first upload was rejected on 2026-10-08 for "excessive keywords" because the text listed six browsers; name no browsers in it):

  ```text
  Apassy is a credential manager for you and your AI agents, on your Mac. This extension fills your Apassy logins into websites in your browser.

  • Fill: open the extension on a login page, choose a login, and confirm with Touch ID or your Apassy passphrase. Every time is the default. An optional Touch ID window in Mac settings can cover trusted routine actions after an owner check.
  • Save this login: type your username and password on a page, click Save this login, and confirm. The login goes into your Apassy vault with the address of the site.
  • New password: on a sign-up page, Apassy makes a strong password, keeps it in your vault, and fills it into the form. It never goes to the clipboard.
  • Update login: choose an existing account and confirm a fresh approval to replace its password with the one typed in the selected form.
  • Optional field suggestions: enable them for a site, then focus a login field to see matching account titles and usernames. Focusing never fills a secret; choosing an account requires approval under your Mac owner-check settings.
  • One-time codes and optional passkeys: use codes and passkeys kept in Apassy. Uses require owner approval; eligible routine actions can use the optional Mac Touch ID window.
  • Strict site match: a login fills only on its own site, over https.

  The extension needs the Apassy app for macOS (https://apassy.wyderka.cc). Apassy keeps the logins in an encrypted vault on your Mac and talks to the extension through the browser's native messaging. The extension has no servers, makes no network requests, and never uses the clipboard. It retains nonsecret feature settings and short-lived action/recovery metadata in the browser, never passwords, passkeys, or one-time codes.

  Site access is optional: field suggestions run on sites you enable, including supported same-origin frames; passkey scripts run in the top frame on granted sites. Toolbar actions remain available without permanent site access. Turning a feature off stops its scripts; browser extension settings let you revoke site access.

  Open source: https://github.com/wydrox/apassy
  ```

## 4. Privacy tab

- **Single purpose:** "Apassy manages website sign-in with logins, one-time codes, and passkeys from the user's Apassy vault on the same Mac."
- **Permission justification:**
  - `nativeMessaging`: "Talks to the Apassy app on the same Mac through its native messaging host. The app keeps the logins and asks for Touch ID; the extension has no other source of logins."
  - `activeTab`: "After the user clicks the Apassy button, reads the address of the active tab to list the logins of that site, and gets access to that tab to fill it."
  - `scripting`: "Runs packaged scripts to fill the selected login or one-time code after fresh owner approval, and reads the selected form when the user explicitly saves or updates a login. Toolbar actions target the top frame. With optional site access and login suggestions enabled, focusing an eligible field retrieves only matching account metadata; choosing an account still requires fresh owner approval before filling. Suggestions support same-origin frames. Optional passkey scripts run in the top frame only."
  - `storage`: "Keeps a nonsecret action result and recovery metadata in extension-only browser session storage, including site origin, tab/document/form identifiers, time, and result status. Results are usable for up to five minutes and are removed when a later check finds them expired or their page/document target changed. No passwords, passkeys, one-time codes, account labels, or page query strings are stored."
  - Optional site access (`https://*/*`, `http://localhost/*`): "Granted only after the user enables a feature and accepts the browser permission prompt. Login suggestions request access for the selected site; passkeys request access to supported HTTPS sites and localhost. Registered scripts retain these nonsecret feature choices. No permanent host access or page scripts are declared in the manifest. Disable either feature to stop its scripts, or revoke site access in browser extension settings."
- **Remote code:** No. All JavaScript is in the package.
- **Data usage:** disclose authentication information and personally identifiable information (a username can be an email address), plus the site address/origin and selected login-form data under the dashboard's applicable URL/page-content categories. These are used only for the sign-in purpose on the same device. Optional field focus sends the site and typed username prefix to Apassy and receives account metadata, without a password or owner check; choosing an account requires fresh approval. Save/update explicitly send the captured username/password to Apassy for an approved vault write. Browser session storage holds only the nonsecret result/recovery metadata described above. Do not claim that the extension stores nothing or accesses pages only after a toolbar click.
- **Certifications:** check all three: the data is not sold, not used for purposes unrelated to the single purpose, and not used for creditworthiness.
- **Privacy policy:** <https://apassy.wyderka.cc/privacy>.

## 5. Distribution and review

- **Distribution:** free, all regions. **Visibility:** Public. Choose Unlisted while the app release of section 2, step 4, is not out.
- **Test instructions** for the reviewers:

  ```text
  The extension needs the Apassy app for macOS 15 or later on Apple silicon.
  1. Download Apassy from https://apassy.wyderka.cc/download and open it. Create a vault with any passphrase.
  2. Add a credential: kind Login, any username and password, Website https://github.com/login.
  3. In Apassy, open Settings > Tools > Browser extension and click Connect next to Chrome. This installs the native messaging host manifest for the browser.
  4. Open https://github.com/login, click the Apassy button, and choose the login. Confirm with Touch ID or the passphrase in the Apassy window. The username and the password appear in the form.
  Without the app the popup says "Apassy is not connected to this browser."
  ```

- **Owner.** Submit for review. With "Publish automatically" off, the item waits up to 30 days after the approval for the owner to publish it.

## 6. After the approval

Published on 2026-10-09: <https://chromewebstore.google.com/detail/apassy/bbnpgnjnfjlbgggmpnhejpmfjhmmhiih>. The first submission was rejected for "excessive keywords" (section 3); the second passed.

- Done: "Connect" in Settings > Tools > Browser extension, `apassy setup browser`, and the site open the store page and offer "Add to Chrome" (`install::STORE_URL`, `EXTENSION_STORE` in `site/src/lib/site.ts`).
- New versions: build the package with the new version of `Cargo.toml` and upload it. The store needs a higher version for each upload. The Chrome Web Store API v2 can upload and publish with a service account. CI can do it after the owner gives the service account access to the publisher and stores its key as a GitHub secret.
- For the 0.5.5 update, upload to the existing item `bbnpgnjnfjlbgggmpnhejpmfjhmmhiih`; do not create another item or change its key. Deploy the corrected privacy policy and update the listing/permission disclosures above before submitting. A locally validated ZIP is not an uploaded, reviewed, or published store release; read back the dashboard version and publication state after those steps.
