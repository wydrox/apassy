# Chrome Web Store images

The images of the Chrome Web Store listing of the Apassy browser extension. Light mode, synthetic data only.

- `screenshot-1-fill.png`: 1280x800. "Fill a login after Touch ID": the popup lists the two logins for github.com.
- `screenshot-2-touch-id.png`: 1280x800. "Touch ID for every fill": the popup waits for the owner check, next to a drawn macOS Touch ID prompt.
- `screenshot-3-save.png`: 1280x800. "Save the login you typed": the Save this login view, with the username from the page.
- `screenshot-4-new-password.png`: 1280x800. "A new password, straight into the vault": the New password view on a sign-up page.
- `promo-small-440x280.png`: 440x280. The small promo tile, with no text: the app icon, a popup, and a Touch ID print.
- `icon-128.png`: 128x128. The store icon: `packaging/AppIcon.svg` at 96x96, with 16 px of transparent padding.

The screenshots and the promo tile are 24-bit PNGs without alpha. The icon has alpha.

## Make them again

After a change to the popup (`extension/`), the app icon, or the templates, run:

```sh
cd extension-tests && node store/make-assets.mjs
```

It needs only Helium (`/Applications/Helium.app`) and the Playwright in `extension-tests/node_modules` (`npm ci` there). It writes all six files here, and fails when a size or a PNG type is wrong. `HEADED=1` shows the browsers.

How it works (`extension-tests/store/`):

- `make-assets.mjs` loads `extension/` into Helium with a temporary profile and the mock native host of the tests (`mock-host/mock-host.mjs`). It opens each page, clicks the toolbar button (for activeTab), and takes the real `popup.html` at 340 px wide, at 1.5x.
- `pages.mjs` holds the pages and the logins of the mock app. The pages are served on their https addresses (github.com, notes.example.com, shop.example.com) by a Playwright route: nothing goes to the network.
- `scene.html` draws the window around the page and the popup screenshots, the caption, and the Touch ID prompt (a drawing, not a screenshot of macOS).
- `promo.html` is the promo tile.
