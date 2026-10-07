# ADR 0021 — The browser extension: fill a login on a website, after Touch ID for each fill

Date: 2026-10-06.
Status: ACCEPTED in scope by the owner on 2026-10-06 ("czy możesz stworzyć chromium extension jak 1password?"). The owner set the rule for secrets: "agenci i automatyczne użycie nigdy nie widzi hasła. wyjątkiem jest użycie przez użytkownika (człowieka) czy to pokazanie sekretu w aplikacji czy wstawianie sekretów - Touch ID lub hasło przy każdym wypełnieniu". The other choices below are proposals; the open decisions are D1 to D6 in the last section.

## Context

- The [product vision](../product-vision-v1.md) left "universal autofill" out of the MVP. Login items exist (`username`, `password`), and the 1Password import keeps their addresses as a visible detail "Website" ([import](../operations/import-1password.md)). The owner must copy a password out of the window today.
- The vault is open only in the app process ([ADR 0017](0017-owner-command-line.md), context). A browser extension cannot read it.
- Two channels leave the app today: the broker socket for agents never returns a secret value, and the owner socket never returns a secret value either. Only a reveal in the window shows a value, after a fresh owner check (goal item A4).
- The agent profile denies the data directory, each Unix socket in it, and the start of each program in Apassy.app except `apassy-mcp` and `apassy-hook` ([isolation](../operations/isolation.md)).

## Decision

### 1. The rule

An agent, a rule, the bouncer, or any other automatic use never receives a password. A person receives one in two ways only: a reveal in the window, or a fill in the browser. Each fill needs its own owner check: Touch ID now, or the master passphrase now. No fill reuses the check of another fill, and no setting turns the check off.

### 2. What the extension does

| The extension can | The extension cannot |
| --- | --- |
| Show the logins whose website matches the page in the active tab: the title and the username | List the vault, search it, or see another kind of item |
| Fill the username and the password of one login into the page, after the owner check in Apassy | Receive a password without the owner check, or keep one after the fill |
| Save the login that the owner typed on a page, after the owner check ("Save this login") | Make a password itself, or put one on the pasteboard |
| Create a login with a new password that the app makes, and fill it, after the owner check ("New password") | Change the password of a login that exists |
| Show whether Apassy runs and whether the vault is locked, and bring the window to the front | Unlock the vault, change or delete an item, or reach the agents and the rules |

Version 1 fills the top frame of the active tab only. It has no inline menu in the page (D2).

### 3. Parts

| Part | Where | What it does |
| --- | --- | --- |
| Extension | `extension/` in the repository, `Contents/Resources/browser-extension` in Apassy.app | Manifest V3. The popup, the background service worker, and the fill function. Permissions: `nativeMessaging`, `activeTab`, `scripting`. No content script and no host permission. |
| Native messaging host | `Contents/MacOS/apassy-browser-host` (`src/bin/apassy-browser-host.rs`) | The browser starts it. It accepts only the extension ID `clopaaapnilhoeplaenolhdmjpompeeh`, checks the size of each message, and passes it to the browser socket. It keeps nothing. |
| Browser socket | `browser.sock` in the data directory (`src/desktop/browser.rs`) | The app answers `status`, `show`, `logins`, `fill`, `save`, and `create`. A fill, a save, and a create open the owner check dialog. |
| Host manifest | `NativeMessagingHosts/com.wydrox.apassy.json` of each browser | "Connect" in Settings > General > Browser extension, or `apassy setup browser`, writes it (`src/browser/install.rs`). |

The wire is in [browser-v1](../contracts/browser-v1.md).

The extension has a fixed public key in its manifest, so its ID is the same in every browser and every profile. The private key is not kept: an unpacked extension does not need it. A Chrome Web Store build gets another ID (D5).

### 4. A fill

1. The owner opens the popup (the toolbar button, or the shortcut of the browser). The service worker takes the address of the active tab from the browser (`tabs`, with `activeTab`), not from the page.
2. The app answers `logins` with the matching logins (section 5): the item ID, the title, and the username. No owner check: these are not secret values (see "What this does not protect").
3. The owner chooses a login. The service worker sends `fill` with the item and the address. The popup can close; the service worker keeps the native port open, so it waits.
4. The app checks the match again and opens the owner check: `OwnerRequest::FillLogin`. The proof names `OwnerAction::FillLogin { item_id, login, origin }`: one login with its title as the owner saw it, one site. The dialog says "Fill the login "GitHub" (rafal) on https://github.com in your browser" and "Your browser asked for this. If you did not choose this login in your browser just now, click Cancel." macOS shows "Apassy is trying to fill "GitHub" on github.com".
5. When Touch ID can run, the window stays where it is: the system prompt is enough. When the owner must type the passphrase, the window comes to the front.
6. With the proof, the app checks the title and the match a third time and answers with the username and the password. The response goes through the host to the service worker. Only when the socket took the answer does the app record the fill in the history of the item (a `revealed` event with the detail `browser https://github.com`). The dialog closes 225 s after the request, before the socket stops waiting, so a late owner check fills nothing.
7. The service worker runs the fill function in the top frame of that tab. The function first compares `location.origin` with the origin of the answer. A tab that went to another site gets nothing. The function sets the two fields and sends `input` and `change`. The service worker drops the values.

One owner check dialog is open at a time. A fill while another dialog is open gets `busy`. A lock, a vault switch, or a closed dialog ends the fill with nothing filled.

### 5. Which site gets a login

The match is strict, because a wrong match gives a password to the wrong site.

- The page must be `https:`. `http:` works only for `localhost`, `127.0.0.1`, and `[::1]`.
- The websites of a login are its visible fields `website` and `url`, and its visible details whose label starts with "Website" or "URL". The login form has the field Website. The 1Password import puts the first address there, and the other addresses in the details "Website 2", "Website 3", and so on. A value without a scheme counts as `https://`. The form refuses a Website that is not a web address.
- The page matches when its host is the host of the website, or ends with "." and that host. So `github.com` matches `github.com` and `gist.github.com`, and `accounts.google.com` does not match `google.com`.
- A website `www.example.com` also matches `example.com`, but not the other subdomains of `example.com`: a site that hosts other people's pages on its subdomains often has its login on `www.`.
- An IP address matches only itself. The port of the page must be the port of the website. A website without a port matches only the default port: on `localhost`, another port is another program.
- Archived logins and other kinds of items never match.

This is narrower than the "registrable domain" rule of most password managers, and it needs no public suffix list.

### 6. Agents

- A sandboxed agent cannot connect to `browser.sock` (it is in the data directory) and cannot start `apassy-browser-host` (it is in Apassy.app). The test `profile_denies_the_browser_socket` checks the socket.
- A browser starts the program of a host manifest outside the sandbox. The profile denies a write to every `NativeMessagingHosts` folder, so an agent cannot replace the Apassy host (`profile_denies_native_messaging_host_manifests`).
- A Chromium profile keeps the folder of each unpacked extension in `Preferences` and `Secure Preferences`, and a Chromium build cannot keep the check of these files secret. The profile denies a change of these files and of `Local State`, and a new, renamed, or deleted profile folder of the browsers in section 8, so an agent cannot point the Apassy extension at its own code (`profile_denies_changes_to_browser_profiles`). This rule was measured with `sandbox-exec`, not against an attack on a live browser.
- `apassy setup browser` works only from the `apassy` program inside an app bundle. The profile protects the bundle, not a source tree: from a source build, the manifest would name `target/debug/apassy-browser-host`, which an agent can rebuild.
- An agent that drives a browser cannot fill without the owner: each fill waits for Touch ID or the passphrase.
- The value goes to the page. A program that reads the page can read it there (see below).

### 7. Save and create

Accepted by the owner on 2026-10-06 (D3). The wire is in [browser-v1](../contracts/browser-v1.md), section 8.

- "Save this login": the service worker reads the username and the typed password from the top frame of the page and sends `save`. The app asks for the owner check ("For https://example.com: save the login "Example" (rafal). The password comes from the page.") and adds a login with the website of the page. The password waits in the ticket of the dialog and is erased when the dialog closes.
- "New password": the app makes the password with `getrandom` (12 to 64 characters, letters and digits, and symbols when the owner wants them), adds the login, and only then answers like a fill. The extension fills the username and each new password field. So the password is in the vault before the page gets it, and it never goes to the pasteboard. The extension has no generator of its own.
- A login with the same username for the page gets `exists`. Version 1 does not change the password of a login that exists: the owner edits it in the app.
- The title and the username of a save or a create come from the browser, and they show in the dialog. The app refuses a line break, a control character, and a bidirectional format character in them, puts the site first in the dialog, and shows at most 64 characters of the username. The Touch ID prompt names the site from the page address, not from these fields.

### 8. Install

- Settings > General > Browser extension lists the Chromium browsers on this Mac. "Connect" writes the host manifest of one browser, opens its extensions page, and shows the extension folder in the Finder. The owner turns on Developer mode and drags the folder onto the page, once for each browser. The section shows when the extension last sent a request, so the owner sees that it works.
- `apassy setup browser` writes the same manifests from a terminal: Helium, Google Chrome, Chromium, Brave, Microsoft Edge, Arc, and Vivaldi. `--browser NAME` selects one.
- Both refuse a source build. The manifest names `apassy-browser-host` of the running Apassy.app and allows only the fixed extension ID.
- A browser installs an extension from another app only through the Chrome Web Store or an enterprise policy, so the Developer mode step stays until D5. An update of Apassy.app updates the folder, and the browser loads it at its next start.

## What this does not protect

- **The page has the password.** After a fill, the scripts of the page, the other extensions with access to the page, and a program that controls the browser (DevTools Protocol, Playwright, an AI browser extension) can read the field. Do not fill in a browser window that an agent controls.
- **Titles and usernames.** A process of the same user outside the agent profile can connect to the browser socket and ask `logins` for a site. It gets the titles and the usernames of that site while the vault is unlocked. It gets no password without the owner check. The same process can already read the screen and the pasteboard. D1 can close this.
- **A false fill request.** The same process can ask for a fill. The owner sees the login and the site in the dialog and in the Touch ID prompt. A request that the owner did not start must be cancelled. Such a process can also wait until the owner starts a fill and send its own request for the same login first: the extension then gets `busy`, and the prompt looks the same. The app does not check who is on the other side of the socket (D1). This is the limit of ADR 0017 too: a program of the owner's user outside the profile can already read the screen and the pasteboard.
- **The extension ID is public.** Any extension with the same key has the same ID, but an unpacked extension needs the Developer mode and an action of the owner, or a browser started with `--load-extension`. Such an extension still needs the owner check for each fill.
- **A site that hosts other people's content** on subdomains of a stored website (for example `sites.google.com` for a login stored as `google.com`) matches. Store the exact host of the login page when that matters.
- **Frames.** Version 1 does not fill a login form in a frame of another origin. The owner copies from the window there.
- **A false save or create.** A process of the same user outside the agent profile can ask for a save or a create, as for a fill. After one owner check that the owner did not mean, a save adds a login to the vault, and a create also gives that process the new password. The dialog and the Touch ID prompt name the site; cancel a request that you did not start. "Save this login" sends a typed password through the host that the manifest names; the agent profile denies a change of the manifest and of the browser profiles, so a sandboxed agent cannot put its own program there.
- **Addresses with other letters.** A website with letters outside ASCII (for example `münchen.de`) does not match yet. The 1Password import keeps such an address as a detail.

## Open decisions for the owner

| # | Decision | Proposal |
| --- | --- | --- |
| D1 | Pairing of the extension (one owner check makes a key in the extension, and the app answers only to it), or a check of the code signature of the socket peer and of the browser that started it. | Next, before a Chrome Web Store build. |
| D2 | An inline menu in the login fields of the page. It needs a content script on every site. | Later. |
| D3 | A password generator and "save this login". | Decided on 2026-10-06: section 7. A change of the password of an existing login is later. |
| D4 | Frames of another origin. | Later, with a host permission for the frame. |
| D5 | Distribution in the Chrome Web Store. Its ID goes into `allowed_origins` next to the unpacked ID. It would make the install one click: "Connect" would open the store page. | A development build for the owner first. |
| D6 | One-time passwords (TOTP) of a login. | Later, with the same owner check. |

## Relation to other records

- ADR 0006 and ADR 0010 stay valid: a fill is an owner action, with a fresh owner check and a proof for one action.
- ADR 0017 stays valid: the owner socket still never returns a secret value. The browser socket is a separate channel with a separate wire.
- ADR 0020 stays valid: the phone cannot fill or reveal.
- The product vision gets one exception to "no universal autofill": a fill by the owner, in a Chromium browser, with an owner check for each fill.
