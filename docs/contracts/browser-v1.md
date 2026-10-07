# Browser wire version 1

Date: 2026-10-06. Section 8 (save and create) added the same day. Decision: [ADR 0021](../adr/0021-browser-extension.md). Code: `src/browser/` (types, site match, host relay), `src/bin/apassy-browser-host.rs` (native messaging host), `src/desktop/browser.rs` (app side), `extension/` (the extension).

## 1. Transport

Two hops carry the same JSON messages.

**Extension to host: Chrome native messaging.**

- The service worker calls `chrome.runtime.connectNative("com.wydrox.apassy")`. The browser starts `apassy-browser-host` with the origin of the extension as its first argument: `chrome-extension://clopaaapnilhoeplaenolhdmjpompeeh/`. The host exits with status 2 for another origin.
- Each message is a 32-bit length in the byte order of the Mac (little-endian), then that many bytes of UTF-8 JSON.
- A request is at most 64 KiB. A response is at most 1 MiB (the limit of the browser). The host closes at a longer message.
- The host answers each request in order. It exits when the browser closes its input.

**Host to app: the browser socket.**

- A Unix socket: `browser.sock` in the data directory ([`paths::data_dir`](../../src/paths.rs)), or `APASSY_BROWSER_SOCKET`. The directory has mode `0700`, the socket `0600`. There is no peer-credential check.
- One request per connection: one line of JSON, at most 64 KiB, then one line back, at most 1 MiB. The host waits up to 240 s, because an owner check waits up to 180 s for Touch ID.
- At most 4 connections at one time. The 5th gets `busy`.
- The agent profile denies the socket, because it is in the data directory.

When the socket is missing or refuses the connection, the host answers `not_running` itself.

## 2. Request

```json
{ "v": 1, "cmd": "fill", "url": "https://github.com/login", "item": 7 }
```

| Field | Value |
| --- | --- |
| `v` | `1`. Another value gets `bad_version`. |
| `cmd` | `status`, `show`, `logins`, `fill`, `save`, or `create`. |
| `url` | The address of the active tab, from the browser. At most 2048 bytes. `logins`, `fill`, `save`, and `create` only. |
| `item` | The item ID from `logins`. `fill` only. |
| `title` | The title of a new login: 1 to 128 bytes after trim. `save` and `create` only. |
| `username` | The username of a new login: 1 to 1024 bytes after trim. `save` and `create` only. A title or a username with a control character (also a line break) or a bidirectional format character gets `bad_request`. |
| `password` | The password that the owner typed on the page: 1 to 4096 bytes. `save` only. The only request field with a secret value. |
| `length` | The length of a new password: 12 to 64. `create` only. |
| `symbols` | `true` when a new password has symbols. `create` only. |

An unknown field gets `bad_request`.

## 3. Response

```json
{ "ok": true, "code": "ok", "message": "Filled.", "data": { "type": "fill", "item": 7, "origin": "https://github.com", "username": "rafal", "password": "…" } }
```

`message` is text for the owner. It has no secret value. `data.type` is one of `none`, `status`, `logins`, `fill`, `saved`. Only `fill` holds a secret value.

## 4. Commands

C: asks for the owner check in the app, then answers.

| `cmd` | Fields | C | `data` |
| --- | --- | :-: | --- |
| `status` | | | `{ "type": "status", "vault": "unlocked" \| "locked" \| "none", "version": "0.3.2" }` |
| `show` | | | `none`. Brings the window to the front, for example to unlock. |
| `logins` | `url` | | `{ "type": "logins", "origin": "https://github.com", "host": "github.com", "logins": [ { "item": 7, "title": "GitHub", "username": "rafal" } ] }`. At most 50, by title. An empty list is `ok`. |
| `fill` | `url`, `item` | C | `{ "type": "fill", "item": 7, "origin": "https://github.com", "username": "rafal", "password": "…" }` |
| `save` | `url`, `title`, `username`, `password` | C | `{ "type": "saved", "item": 12 }`. A new login with the website `origin`. |
| `create` | `url`, `title`, `username`, `length`, `symbols` | C | `fill`, for the new login. Apassy makes the password. |

`origin` is `scheme://host` with a port only when the page has one that is not the default. The extension fills only a frame whose `location.origin` is this value.

## 5. The site match

`logins` and `fill` use the same match. The app checks it at the request, before the owner check, and after the owner check.

- The page must be `https:`. `http:` works only for `localhost`, `127.0.0.1`, and `[::1]`. Another page gets `unsupported_page`.
- The websites of a login: its visible fields `website` and `url`, and its visible custom details whose label, without regard to case, starts with `website` or `url`. A value without `://` counts as `https://` and the value.
- The page host matches when it is the website host, or ends with `.` and that host. A website with one label matches only itself. A website host `www.H` also matches `H`, but not the other subdomains of `H`. An IP address matches only the same address.
- The port of the page must equal the port of the website. A website without a port, or with the default port of its scheme, matches only a page on the default port.
- The item must be a login with a non-empty `password`, and not archived.

## 6. Errors

| `code` | When |
| --- | --- |
| `bad_request` | Not JSON, an unknown `cmd`, an unknown field, a missing field, or too long. |
| `bad_version` | `v` is not 1. |
| `not_running` | The host found no app on the socket. |
| `none_open` | No vault file is open in the app. |
| `vault_locked` | The vault is locked. |
| `unsupported_page` | The address is not an `https:` page, or not a local `http:` page. |
| `no_match` | The item is not a login for this page, or it does not exist. |
| `busy` | Another owner check is open, or too many connections. |
| `cancelled` | The owner closed the owner check, or the vault locked before it passed. Nothing was filled. |
| `owner_check_failed` | The owner check failed. |
| `refused` | The vault refused the fill, the save, or the new login after the check. |
| `exists` | A login with this username is already in Apassy for this page. `message` names it. Nothing was saved. |
| `timeout` | The app did not answer in 230 s. |
| `stopped` | The app is quitting, or it closed the connection without an answer. |
| `bad_response` | The host got an answer longer than 1 MiB. |

The extension makes these codes itself. They never cross the wire.

| `code` | When |
| --- | --- |
| `host_missing` | The browser found no host manifest, or the manifest does not allow the extension. |
| `host_failed` | The host closed without an answer. |
| `timeout` | No answer in 250 s. |
| `no_page` | The extension cannot read the address of the tab. |
| `page_changed` | The tab is no longer on the origin of the answer. Nothing was filled. |
| `no_fields` | The page has no login field. For `create`: Apassy made the login, but the page has no new password field; the message says that the login is in Apassy. |
| `no_password` | "Save this login" found no typed password on the page. |
| `fill_failed` | The browser refused to run the fill function in the page. |

## 7. The host manifest

`apassy setup browser` writes `com.wydrox.apassy.json` into the `NativeMessagingHosts` folder of each browser:

```json
{
  "name": "com.wydrox.apassy",
  "description": "Apassy: fill logins from your Apassy vault",
  "path": "/Applications/Apassy.app/Contents/MacOS/apassy-browser-host",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://clopaaapnilhoeplaenolhdmjpompeeh/"]
}
```

| Browser | Folder under `~/Library/Application Support` |
| --- | --- |
| Helium | `net.imput.helium/NativeMessagingHosts` |
| Google Chrome | `Google/Chrome/NativeMessagingHosts` |
| Chromium | `Chromium/NativeMessagingHosts` |
| Brave | `BraveSoftware/Brave-Browser/NativeMessagingHosts` |
| Microsoft Edge | `Microsoft Edge/NativeMessagingHosts` |
| Arc | `Arc/User Data/NativeMessagingHosts` |
| Vivaldi | `Vivaldi/NativeMessagingHosts` |

## 8. Save and create

**`save`: "Save this login".** The owner types a username and a password on a page and clicks "Save this login" in the popup. The service worker reads the two fields from the top frame of the tab, in the isolated world of the extension, and sends `save`. The popup never gets the password. The app checks the page and the fields, refuses a duplicate with `exists` (the same username, without regard to case, in a login that matches the page), and asks for the owner check: "For https://example.com: save the login "Example" (rafal). The password comes from the page." After the check it adds a login with the fields `username`, `password`, and `website` (the origin of the page), and answers `saved`. The password waits in the app only while the dialog is open.

**`create`: a new password.** On a sign-up page the owner opens "New password" in the popup, checks the title and the username, chooses the length and symbols, and clicks "Create and fill". The app asks for the owner check: "For https://example.com: create the login "Example" (rafal) with a new 20-character password with symbols, and fill it in your browser." After the check it makes the password, adds the login, and answers `fill`. The extension fills the username and each new password field of the page (a sign-up form often asks twice). So a new password is in the vault before the page gets it, and it never goes to the pasteboard.

The password of `create` comes from the random generator of the Mac (`getrandom`). It has at least one lowercase letter, one uppercase letter, and one digit, and one symbol when `symbols` is `true`. The symbols are `!#$%&*+-.:;=?@^_~`.

A changed password of an existing login is not in version 1. The owner changes it in the app.

