# Apassy for Chromium browsers

This extension fills a login or a one-time code on a website from your Apassy vault, and can answer passkey requests with the passkeys in Apassy. You choose the login in the toolbar popup. Apassy asks for Touch ID or your passphrase before each fill. Agents never get a password through it.

It fills the top frame of the page only.

| Feature | Browsers |
| --- | --- |
| Fill, save, and create logins | Helium, Google Chrome, Chromium, Brave, Microsoft Edge, Arc, Vivaldi |
| Passkeys and one-time codes | Helium (`net.imput.helium`, team S4Q33XPHB4) and Google Chrome stable (`com.google.Chrome`, team EQHXZ8M8AV), from the official signed download, started normally |

For passkeys and codes, Apassy checks that the browser is the signed Helium or Google Chrome and that it was not started with `--load-extension`, `--disable-extensions-except`, or a `--remote-debugging-*` switch (docs/contracts/browser-v1.md, section 9.4). In another browser, or in Helium or Chrome that an automation tool or a debugger started, Apassy answers that it cannot verify the browser: the browser then does a passkey request itself, and "Fill code" fills nothing and shows that message. Chrome Beta, Dev, and Canary are not accepted. The positive passkey ceremony in Chrome has not been run by an automated test. This check does not prove the extension itself, so Apassy asks for Touch ID or your passphrase before each passkey and each code in every browser.

## Load it

1. In Apassy, open Settings > General > Browser extension and click Connect next to the browser. (`apassy setup browser` in Terminal connects every browser at once.)
2. Apassy opens the extension in the Chrome Web Store: <https://chromewebstore.google.com/detail/apassy/bbnpgnjnfjlbgggmpnhejpmfjhmmhiih>. Click Add to Chrome.

Without the store: turn on Developer mode on the extensions page of the browser, and drag this folder (`/Applications/Apassy.app/Contents/Resources/browser-extension`) onto the page. An update of Apassy updates the folder. The browser loads the new version at its next start. Logins work this way; passkeys and codes need Helium or Chrome (see above).

To fill a login, click the Apassy button in the toolbar, or press Command-Shift-L. Choose a login, then confirm with Touch ID or your passphrase in Apassy.

To save a login that you typed on a page, click "Save this login". The extension reads the username and the password from the page and sends them to Apassy, which asks you to confirm.

To sign up with a new password, click "New password". Choose the length and whether it has symbols, then click "Create and fill". After you confirm, Apassy makes the password, saves the login, and fills it into the page. The extension never makes a password itself.

To fill a one-time code, click "Fill code" next to a login that has one. After you confirm, Apassy puts the code into the one-time-code field of the page (a field marked `autocomplete="one-time-code"`, or a row of one-digit fields that starts with one). The popup never shows the code, and the extension does not copy it.

## Passkeys

At the bottom of the popup, turn on "Use Apassy passkeys in this browser". The browser asks you to let Apassy read and change data on https sites (and on `localhost`, for a local test site). Turn it off there, or remove the site access in the browser, to stop.

When it is on, a site that asks for a passkey asks Apassy. Apassy shows the address of the site and asks for Touch ID or your passphrase for each sign-in and each new passkey. The browser does the request itself when Apassy cannot serve it before that check: Apassy does not run, the vault is locked, Apassy cannot verify the browser (see the table above), Apassy has no passkey for the site, or the site asks for something that Apassy does not do (a security key, a passkey in the address bar list, a "prf" or "largeBlob" extension, an algorithm other than ES256, enterprise attestation). After you cancel the check, the site gets an error and the browser does not ask again.

How it works:

- `passkey-page.js` runs in the page, in the top frame only, and wraps `navigator.credentials.create` and `get`. It is as untrusted as the page. It sends the options to `passkey-bridge.js`, which forwards them to the service worker over a port of its own for each request.
- The service worker takes the origin from the browser (the sender of that port), never from the page. It checks that the sender is the active top-level document of a tab on an https origin (or `http://localhost`), and that the RP ID is that host or a parent of it. It builds `clientDataJSON` itself and sends it, with a random request ID, to Apassy over a native port of its own (`passkey_get`, `passkey_create`; all bytes in standard base64). Apassy checks the RP ID again with the public suffix list and hashes and signs exactly these bytes.
- The answer goes back only through the same port, after the service worker checked the request ID, the bytes, the RP ID hash, the flags, and that the same document is still on the page. A cancel, a navigation, a new request of the same tab, or the deadline (30 to 180 s) closes the native port, so Apassy ends its check and signs nothing. A late answer goes nowhere.

The extension does not use the browser's `webAuthenticationProxy`, keeps no passkey, and never logs a request or an answer.

## Permissions

| Permission | Why |
| --- | --- |
| `nativeMessaging` | To talk to the Apassy app on this Mac. |
| `activeTab` | To read the address of the page and fill it, only after you click the Apassy button. |
| `scripting` | To put the username, the password, or a one-time code into the fields of that page, and to run the passkey scripts. |
| Site access to https sites and `localhost` (optional) | Only after you turn on passkeys in the popup: the passkey scripts run in the top frame of these pages. |

Without passkeys turned on, the extension has no access to a site until you click its button. It sends nothing to the internet, keeps no password, passkey, or code, and does not use the clipboard.

Each extension with this folder has the ID `bbnpgnjnfjlbgggmpnhejpmfjhmmhiih`. Apassy answers only this ID.
