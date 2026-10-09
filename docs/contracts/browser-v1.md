# Browser wire version 1

Date: 2026-10-06. Section 8 (save and create) added the same day. Section 9 (passkeys and one-time codes) added 2026-10-09. Decision: [ADR 0021](../adr/0021-browser-extension.md). Code: `src/browser/` (types, site match, host relay), `src/bin/apassy-browser-host.rs` (native messaging host), `src/desktop/browser.rs` (app side), `extension/` (the extension).

## 1. Transport

Two hops carry the same JSON messages.

**Extension to host: Chrome native messaging.**

- The service worker calls `chrome.runtime.connectNative("com.wydrox.apassy")`. The browser starts `apassy-browser-host` with the origin of the extension as its first argument: `chrome-extension://bbnpgnjnfjlbgggmpnhejpmfjhmmhiih/`. The host exits with status 2 for another origin.
- Each message is a 32-bit length in the byte order of the Mac (little-endian), then that many bytes of UTF-8 JSON.
- A request is at most 64 KiB. A response is at most 1 MiB (the limit of the browser). The host closes at a longer message.
- The host answers each request in order. It exits when the browser closes its input. It reads the input also while it waits for the app: when the input ends (the extension disconnected the port), it shuts down the connection to the app at once and answers nothing (section 9.5).

**Host to app: the browser socket.**

- A Unix socket: `browser.sock` in the data directory ([`paths::data_dir`](../../src/paths.rs)), or `APASSY_BROWSER_SOCKET`. The directory has mode `0700`, the socket `0600`. The commands of section 9 also need the caller check of section 9.4; the other commands have no peer-credential check.
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
| `cmd` | `status`, `show`, `logins`, `fill`, `save`, or `create`. Section 9 adds `passkey_get`, `passkey_create`, and `fill_code`, each with its own strict packet. |
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

`message` is text for the owner. It has no secret value. `data.type` is one of `none`, `status`, `logins`, `fill`, `saved`, and from section 9 `passkey`, `passkey_created`, `code`. Only `fill` and `code` hold a secret value.

## 4. Commands

C: asks for the owner check in the app, then answers.

| `cmd` | Fields | C | `data` |
| --- | --- | :-: | --- |
| `status` | | | `{ "type": "status", "vault": "unlocked" \| "locked" \| "none", "version": "0.3.2" }` |
| `show` | | | `none`. Brings the window to the front, for example to unlock. |
| `logins` | `url` | | `{ "type": "logins", "origin": "https://github.com", "host": "github.com", "logins": [ { "item": 7, "title": "GitHub", "username": "rafal", "has_totp": false } ] }`. At most 50, by title. An empty list is `ok`. `has_totp` (default `false`) says that `fill_code` can fill a one-time code; never the code or the seed. |
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
| `unsupported` | Section 9: the caller check failed, or Apassy does not sign for this relying party. The extension lets the browser do the request. |
| `excluded` | Section 9: `passkey_create` after the owner check, when Apassy has a passkey of `excluded`. |
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
  "allowed_origins": ["chrome-extension://bbnpgnjnfjlbgggmpnhejpmfjhmmhiih/"]
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


## 9. Passkeys and one-time codes

Added 2026-10-09. The commands of version 1 are unchanged. Code: `src/browser/wire.rs` (packets), `src/browser/webauthn.rs` (client data, relying party, base64), `src/browser/caller.rs` and `native/ApassyBrowserGuard/main.swift` (caller check), `src/browser/relay.rs` (host).

### 9.1 Requests

Each command has its own packet. An unknown field, a missing field, or a field of the wrong type gets `bad_request`; `v` other than 1 gets `bad_version`. The app reads `cmd` first and parses these three commands only with their own packet, so a packet of version 1 still parses as before.

```json
{ "v": 1, "cmd": "passkey_get", "rid": "3b241101-e2bb-4255-8caf-4136c566a962", "origin": "https://login.example.com", "rp_id": "example.com", "client_data_json": "<standard base64>", "allowed": ["<standard base64>"] }
{ "v": 1, "cmd": "passkey_create", "rid": "…", "origin": "…", "rp_id": "…", "client_data_json": "…", "user_handle": "<standard base64>", "user_name": "owner@example.com", "user_display_name": "Owner", "algorithms": [-7, -257], "excluded": ["<standard base64>"], "title": "Example" }
{ "v": 1, "cmd": "fill_code", "url": "https://example.com/2fa", "item": 7, "field": "Backup" }
```

| Field | Value |
| --- | --- |
| `rid` | The request ID of the service worker: a lowercase UUID (`crypto.randomUUID()`). Every answer repeats it; the extension drops an answer with another `rid`. |
| `origin` | `port.sender.origin` from the browser, never from the page: `https://<host>[:<port>]`, or `http://localhost[:<port>]`. The host is a lowercase ASCII DNS name with at least two labels (or `localhost`), not an IP address. No path, no trailing slash, no default port, no opaque `null`. |
| `rp_id` | Lowercase ASCII DNS name, or `localhost`. |
| `client_data_json` | Standard base64 of the exact `clientDataJSON` bytes, at most 4096 bytes (section 9.2). |
| `allowed`, `excluded` | At most 256 credential IDs, each 1 to 1023 bytes. `allowed` empty: any passkey of `rp_id`. |
| `user_handle` | 1 to 64 bytes. |
| `user_name`, `user_display_name` | From the page, untrusted: at most 256 bytes, no control character and no bidirectional format character. |
| `algorithms` | 1 to 16 COSE algorithms. Apassy makes only ES256 (-7); without -7 the app answers `unsupported`. |
| `title` | The title of the new login: 1 to 128 bytes after trim, no control character. |
| `url`, `item` | As in `fill`. |
| `field` | Optional label of the one-time code detail: 1 to 128 bytes, no control character. |

Byte fields are standard base64 (RFC 4648 section 4) with padding, and canonical: no white space, no URL alphabet, padding only at the end, unused bits zero. So one byte string has one encoding. The page side (DOM `toJSON`) uses base64url; the extension converts.

### 9.2 Client data and relying party

The service worker builds the client data, with the keys in this order and no white space:

```json
{"type":"webauthn.get","challenge":"<base64url, no padding>","origin":"<origin>","crossOrigin":false}
```

`type` is `webauthn.create` for `passkey_create`. There is no `topOrigin`: only the top frame asks. The app (`webauthn::client_data`) before the owner check:

1. decodes `client_data_json` strictly, and requires exactly these bytes: the JSON `type` matches the command, `origin` equals the request `origin`, `crossOrigin` is `false`, the challenge is canonical base64url of 16 to 1024 bytes. Another key order, white space, an escape, a duplicate or an extra key gets `bad_request`;
2. checks `rp_id`: the origin host equals `rp_id` or ends with `.` and `rp_id`; `rp_id` is not a public suffix of the pinned public suffix list (`psl` 2.1.238, ICANN and private sections: not `com`, `co.uk`, `github.io`); its suffix is on the list; the registrable domain of `rp_id` equals that of the host. `localhost` only for the host `localhost`. A failure gets `unsupported`, so the browser does the request and its own check;
3. computes SHA-256 of the decoded bytes. The app never takes a hash from the extension.

The owner check binds the origin from these bytes, `rp_id`, the request (`rid`, the credential ID or the new account), and the hash. The answer repeats `client_data_json` unchanged.

### 9.3 Answers

| `cmd` | C | `data` |
| --- | :-: | --- |
| `passkey_get` | C | `{ "type": "passkey", "rid", "credential_id", "user_handle", "authenticator_data", "signature", "client_data_json" }` |
| `passkey_create` | C | `{ "type": "passkey_created", "rid", "item": 12, "credential_id", "attestation_object", "authenticator_data", "public_key_spki", "algorithm": -7, "client_data_json" }` |
| `fill_code` | C | `{ "type": "code", "item": 7, "origin": "https://example.com", "code": "493817", "remaining": 21 }`. `code` has 6 to 8 digits and is a secret value. |

Byte fields are standard base64 with padding. Before the owner dialog the app may answer `not_running`, `none_open`, `vault_locked`, `no_match`, or `unsupported`: the extension then lets the browser do the request. Protocol errors `bad_request` and `bad_version` also permit fallback. They occur before the dialog; an older app returns them for commands it does not support. After the dialog opens, every failure (`cancelled`, `owner_check_failed`, `excluded`, `refused`, `timeout`, `stopped`) is final: no fallback. An unknown code, a wrong `rid`, or another `data.type` is a failure. No secret, signature, client data, or credential ID goes to a log; `Debug` of the request and answer types hides them.

### 9.4 Caller check

The browser starts the host with the extension origin as its first argument, but any local process can do the same. The argument is not proof. `apassy-browser-guard` (Apassy.app/Contents/MacOS, signing identifier `com.wydrox.apassy.browser-guard`, team `7S3F9767BM`) checks the callers from the operating system, by audit token and code signature:

- **Host** (`caller::check_browser_parent`, before each `passkey_get`, `passkey_create`, `fill_code`): the parent of the guard is `apassy-browser-host` of the same Apassy.app (identifier `com.wydrox.apassy.browser-host`, the team of the guard), and the parent of the host is a known browser. A failure answers `unsupported`; the app never sees the request.
- **App** (`caller::check_peer`, on the accepted connection): the guard gets the connection as its standard input. Its parent is the Apassy app that contains it; the socket peer (`LOCAL_PEERTOKEN`) is `apassy-browser-host` of the same app; the parent of that host is a known browser.

Known browsers are Developer ID applications, checked by exact identifier and team, with the same certificate chain (Apple Developer ID CA, a Developer ID Application leaf, the team in the leaf): `net.imput.helium` (S4Q33XPHB4), from the signature of the official Helium on 2026-10-09, and `com.google.Chrome` (EQHXZ8M8AV), stable only. For Chrome, the official disk image (`https://dl.google.com/chrome/mac/universal/stable/googlechrome.dmg`, the address that google.com/chrome gives; SHA-256 `88257ad17f1bda730f2a0600e1c7b9155bff2ae5ff9500386f5d4734bb411d55`, 282304813 bytes, Chrome 155.0.8059.40) was mounted read-only and checked on 2026-10-09: `codesign --verify --strict --deep` passes, the app is "Developer ID Application: Google LLC (EQHXZ8M8AV)", notarized (`spctl`: accepted), and its designated requirement is Google's. That requirement also admits `com.google.Chrome.beta`, `.dev`, and `.canary`; the guard names only `com.google.Chrome`. The disk image itself is not signed (only the app in it is). Chrome has the same argument rules as Helium (below) and the same limit: a positive passkey ceremony in Chrome was not run by an automated test. A browser joins the list only after the designated requirement of its official build is checked the same way. Another browser, a Chromium build, or an unsigned browser gets `unsupported` and keeps its own passkeys. The guard compares each audit token again after the signature checks, so an exit, an exec, or a reused process ID fails. It refuses when it has no team signature. Before it starts the guard, Rust checks the guard with `codesign --verify --strict` against its identifier and team, at its place in the bundle; a source build has no guard and refuses. Only a debug build reads `APASSY_BROWSER_GUARD`. The legacy commands keep their checks of sections 1 and 5.

**Browser switches.** A signed browser is not enough: Helium started with `--load-extension=<folder>` runs an unpacked copy of the extension with the public key of the store extension, so it has the same ID and the host gets the expected origin. So the guard also reads the arguments of the browser process from the kernel (`sysctl` `KERN_PROCARGS2`, not the text of `ps`) and refuses:

- `load-extension`, `disable-extensions-except`, and every switch that starts with `remote-debugging` (`-port`, `-pipe`, `-address`, …);
- in each form: with `--` or `-` or more dashes, any case, a value after `=` or in the next argument, and also after a `--` argument (Chromium reads no switch there; the guard refuses more than Chromium reads);
- arguments it cannot read: the process is gone or belongs to another user, `kern.argmax` is over 4 MiB, `argc` is not 1 to 256, the executable path and arguments are over 64 KiB, a string has no terminator, or a string is not UTF-8.

It checks every parsed string, `argv[0]` too, so an empty `argv[0]` (which looks like padding) shifts the parse to check more, not less. It reads the audit token of the browser again after the arguments. The environment of the browser is not read. `--user-data-dir` is allowed: a process of the owner can change the default profile as well. There is no switch, environment variable, or file that turns this off. The test build of the guard (`-D APASSY_BROWSER_GUARD_SELFTEST`, `tests/browser_passkeys.rs` only) adds self-test modes that answer `allowed` or `refused` and never `ok`; the release guard has none.

So a browser that Playwright or another automation tool starts (it adds `--remote-debugging-pipe`, and loads an extension with `--load-extension`) never passes. An automated test can check only refusals (`extension-tests/tests/passkey-signed-app.spec.mjs`). The positive check is manual: Helium or Chrome started from the Finder or the Dock, the extension from the Chrome Web Store, a real owner check.

**What the check does not prove.** It proves that a signed Helium or Google Chrome (stable), started without these switches, started the signed host. It does not prove the extension: the origin argument and the extension ID come from the browser, which trusts its profile. A process of the owner can change the profile of the browser (its preferences, an unpacked extension registered there, a debugging session that the owner turns on in the browser), or start Helium with switches that this list does not name. These are accepted residuals of a same-user attacker. So every passkey, new passkey, and code still needs a fresh owner check (Touch ID or the passphrase) in the Apassy app, which shows the origin from the signed bytes and the note that the request comes from a browser. A verified browser never skips the owner check.

### 9.5 Cancellation

The extension opens one native port per request, and disconnects it when the page cancels, navigates, closes, sends a new request, or passes the deadline (at most 180 s). The host reads its input in a thread while it waits for the app. When the input ends, the host shuts down the socket at once (`shutdown`, not a timeout) and exits with status 0 without an answer; a broken frame, or more than 4 waiting messages, does the same with status 1. The app sees the hang-up, closes the owner dialog, and signs nothing. A late approval signs nothing.
