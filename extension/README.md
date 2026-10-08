# Apassy for Chromium browsers

This extension fills a login on a website from your Apassy vault. You choose the login in the toolbar popup. Apassy asks for Touch ID or your passphrase before each fill. Agents never get a password through it.

It works in Helium, Google Chrome, Chromium, Brave, Microsoft Edge, Arc, and Vivaldi. It fills the top frame of the page only.

## Load it

1. In Apassy, open Settings > General > Browser extension and click Connect next to the browser. Apassy opens the extensions page of the browser and shows this folder in the Finder. (`apassy setup browser` in Terminal connects every browser at once.)
2. On the extensions page, turn on Developer mode.
3. Drag the folder `browser-extension` from the Finder onto the page, or click "Load unpacked" and choose `/Applications/Apassy.app/Contents/Resources/browser-extension`.

An update of Apassy updates the folder. The browser loads the new version at its next start.

To fill a login, click the Apassy button in the toolbar, or press Command-Shift-L. Choose a login, then confirm with Touch ID or your passphrase in Apassy.

To save a login that you typed on a page, click "Save this login". The extension reads the username and the password from the page and sends them to Apassy, which asks you to confirm.

To sign up with a new password, click "New password". Choose the length and whether it has symbols, then click "Create and fill". After you confirm, Apassy makes the password, saves the login, and fills it into the page. The extension never makes a password itself.

## Permissions

| Permission | Why |
| --- | --- |
| `nativeMessaging` | To talk to the Apassy app on this Mac. |
| `activeTab` | To read the address of the page and fill it, only after you click the Apassy button. |
| `scripting` | To put the username and the password into the fields of that page. |

The extension has no access to a site until you click its button. It sends nothing to the internet, keeps no password, and does not use the clipboard.

Each extension with this folder has the ID `bbnpgnjnfjlbgggmpnhejpmfjhmmhiih`. Apassy answers only this ID.
