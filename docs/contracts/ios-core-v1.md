# iPhone vault core contract v1

Date: 2026-10-07.
Status: experimental. This contract supports the iPhone app in [ADR 0023](../adr/0023-iphone-vault.md). The Rust side (`ios/ApassyCore`, crate `apassy-core`) and the Swift side (`ios/ApassyVaultKit`) implement it. A change to this document changes both sides in the same pull request.

## 1. Parts

| Part | Location | Built for |
| --- | --- | --- |
| The core: a C interface over `apassy::vault` and `apassy::sync` (relay) | `ios/ApassyCore` (Rust, `staticlib`) | `aarch64-apple-ios`, `aarch64-apple-ios-sim`, `aarch64-apple-darwin` (tests) |
| The C header and the module map | `ios/ApassyCore/include/` | |
| The XCFramework | `ios/ApassyCore/build/ApassyCore.xcframework`, made by `scripts/build-ios-core.sh`, not committed | |
| The Swift wrapper: typed requests, answers, errors | `ios/ApassyVaultKit` (Swift package) | iOS 26, and macOS 15 for `swift test` |
| The app and the AutoFill extension | `ios/ApassyCompanion` (XcodeGen project) | iOS 26 |

The core is the same vault code as the Mac app: the same schema (16), the same merge, the same relay client. A phone and a Mac that sync one vault must run the same schema; a copy of another schema is refused, as between two Macs.

## 2. The C interface

```c
typedef struct ApassyCore ApassyCore;

// Start a core. `config` is JSON (section 3). NULL on a bad config.
ApassyCore *apassy_core_new(const char *config);

// One call. `request` is JSON (section 4). The answer is JSON, UTF-8, NUL-terminated,
// never NULL. Free it with apassy_core_free_string.
char *apassy_core_call(ApassyCore *core, const char *request);

// Erase the answer and free it.
void apassy_core_free_string(char *answer);

// Lock the vault, drop the relay session, and free the core.
void apassy_core_free(ApassyCore *core);
```

- `apassy_core_call` is safe from several threads at once. A slow call (a sync, a long poll, a join) does not hold the vault: item calls answer while it runs.
- A panic inside a call is caught and answered as the error `internal`. The core never aborts the process on a bad request.
- The core erases each answer when it is freed, and each passphrase and secret it parsed. A Swift `String` cannot be erased; the app keeps a revealed value only while it is on the screen. This is best effort, as on the Mac.

## 3. Config

```json
{"data_dir": "/…/Library/Application Support/Apassy", "device_name": "Rafał’s iPhone", "role": "app"}
```

- `data_dir`: absolute; the App Group container, so the app and the AutoFill extension see the same vault. The core makes it with mode 0700.
- `device_name`: the name that the relay and the Macs show for this iPhone, and the name in a conflict copy. At most 64 bytes after trimming.
- `role`: `app` or `autofill`. The `autofill` role answers only the calls marked **R** in section 5. Every other call gets `not_allowed`. The extension never syncs and never writes.

Files in `data_dir`:

| File | What it is |
| --- | --- |
| `phone.json` | The vaults on this iPhone (section 6). |
| `vaults/<vault_id>.apassy` | The live vault (SQLCipher), as on the Mac. |
| `sync/<vault_id>.json` and `sync/.*` | The relay sync state and work files, as on the Mac. |

## 4. Requests and answers

A request is `{"op": "<name>", …parameters}`. An answer is one of:

```json
{"ok": true, "result": { … }}
{"ok": false, "error": {"code": "wrong_passphrase", "message": "The passphrase does not open this vault."}}
```

- Unknown parameters are ignored. A missing parameter is `invalid_input`.
- `message` is plain English for the owner, in the style of the Mac app. It never has a value, a passphrase, SQL, or a driver error.
- An ID of an item is a JSON number (`u64`), local to this iPhone. A time is Unix seconds.

Error codes:

| Code | When |
| --- | --- |
| `invalid_input` | A parameter is missing or not valid; the message says which. |
| `not_allowed` | The role does not allow the call. |
| `no_vault` | No vault is selected, or the vault ID is not on this iPhone. |
| `locked` | The call needs the unlocked vault. |
| `wrong_passphrase` | The passphrase does not open the vault or the copy. |
| `not_found` | The item or the field is not there. |
| `conflict` | The revision is not current: the item changed (a sync merged a change). Reload it. |
| `storage` | The vault file failed. |
| `unsupported_schema` | The vault or the copy has another schema than this app. Update the app or the Mac. |
| `link_invalid` | The text is not a device link of the relay, or the relay refused the link (used, expired, or not valid). |
| `join_refused` | The Mac refused this iPhone, or the link expired before the confirmation. |
| `safety_mismatch` | The relay's safety words are not the ones this iPhone computes. |
| `relay_unreachable` | No network, or the relay does not answer. |
| `rate_limited` | The relay asks to wait. |
| `removed` | The relay refuses this iPhone: it was removed from the vault on a Mac. |
| `needs_passphrase` | The passphrase of the vault changed on a Mac. Call `take_new_passphrase`. |
| `damaged` | The copy on the relay fails a check. |
| `stale_copy` | The relay serves an older copy than this iPhone saw. |
| `forked_copy` | The relay serves a copy whose chain does not have this iPhone's last change. |
| `busy` | Another sync of this vault runs. The next sync tries again. |
| `too_large` | The copy is larger than the relay takes. |
| `io` | A file operation failed. |
| `internal` | A bug. The message says so. |

## 5. Calls

**R**: the `autofill` role may call it.

### 5.1 Vaults and the lock

| Op | Parameters | Result |
| --- | --- | --- |
| `info` **R** | | `{"vaults": [Vault], "selected": "<vault_id>" or null, "unlocked": bool, "join": Join or null, "schema": 16, "version": "0.3.4"}` |
| `select` **R** | `vault_id` | `{}`. Locks the vault that was open. |
| `unlock` **R** | `passphrase` | `{}`. Opens the selected vault. |
| `lock` **R** | | `{}`. Locks, drops the relay key and token from memory, and ends a long poll. |
| `check_passphrase` **R** | `passphrase` | `{"ok": bool}`. Checks against the vault file; changes nothing. For the owner check without Face ID. |
| `create_local_vault` | `name`, `passphrase` | `{"vault": Vault}`. A new vault on this iPhone only, without the relay, selected and unlocked. The app offers it only in a Simulator build and in tests. |
| `remove_vault` | `vault_id`, `force` (bool) | `{"left_relay": bool}`. Section 5.6. |

`Vault`: `{"id": "<vault_id>", "name": "Personal", "relay_url": "https://…" or null, "team_id": "t_…" or null, "device_id": 3 or null, "added_at": 1791200000}`.

### 5.2 Joining a vault (contract relay-sync-v1, section 7.2)

The owner selects "Add a device…" on the Mac; the Mac shows a QR code and the link `<relay URL>/link#apassy_lnk_…`. The iPhone scans it (or the owner pastes it).

| Op | Parameters | Result |
| --- | --- | --- |
| `join_start` | `link`, `device_name` (optional; the config name by default) | `Join`. Makes a device key in memory and sends the link with the name of this iPhone. A join that was waiting is cancelled first. |
| `join_poll` | | `Join`. Asks the relay whether the Mac confirmed. After the confirmation it downloads the copy in the same call, then answers `ready`. Call it every 2 s while `waiting`. |
| `join_cancel` | | `{}`. Cancels the link on the relay, or removes the device after a confirmation. |
| `join_finish` | `passphrase` | `{"vault": Vault}`. Opens the copy with the passphrase, makes the vault on this iPhone, turns on relay sync, selects and unlocks it. A wrong passphrase is `wrong_passphrase` and keeps the download: the owner tries again. |

`Join`: `{"state": "waiting" | "ready", "team": "Personal", "words": ["amber", "marble"], "expires_at": 1791200600}`. `words` are the two safety words; the Mac shows the same words for this iPhone.

### 5.3 Items

| Op | Parameters | Result |
| --- | --- | --- |
| `items` **R** | `archived`: `"no"` (default), `"yes"`, or `"all"` | `{"items": [Row]}`, sorted by title (case-insensitive). |
| `item` **R** | `id` | `Detail` |
| `reveal` **R** | `id`, `field` | `{"value": "…"}`. A secret field. Records the reveal in the history of the item, as the Mac does after an owner check. The app asks for Face ID or the passphrase before each call. |
| `totp` **R** | `id`, `field` | `{"code": "123456", "period": 30, "remaining": 17, "digits": 6}`. Section 7. Never the seed. |
| `history` | `id` | `{"events": [{"at": 1791200000, "kind": "edited", "detail": "…"}]}`, newest first, at most 50. |
| `save` | `id` (null for a new item), `revision` (null for a new item), `item`: Draft | `{"id": 12, "revision": 3}` |
| `archive` | `id`, `archived` (bool) | `{}` |
| `delete` | `id`, `revision` | `{}` |

`Row`:

```json
{"id": 12, "revision": 3, "title": "GitHub", "kind": "login", "subtitle": "octocat",
 "websites": ["https://github.com"], "tags": ["work"], "archived": false,
 "has_totp": true, "conflict_of": null, "added_at": 1791100000, "changed_at": 1791200000,
 "used_at": null}
```

- `kind`: `login`, `api_key`, `ssh_key`, `database`, or `custom`.
- `subtitle`: the username of a login or a database, the host of a database without a username, the public key label of an SSH key, else the service, else empty.
- `websites`: the values of the website fields (section 8), as stored.
- `conflict_of`: the ID of the item whose conflict copy this is, when a sync kept both versions.

`Detail` is a `Row` with `"notes": "…"` and `"fields": [Field]`. `Field`:

```json
{"name": "password", "label": "Password", "secret": true, "value": null, "role": "password", "custom": false}
```

- `value`: the value of a plain field; always `null` for a secret field (`reveal` gives it).
- `label`: the Mac's label (`field_label`): `token` Token, `password` Password, `private_key` Private key, `passphrase` Key passphrase, `username` Username, `host` Host, `database` Database, `public_key` Public key, `service` Service, `project` Project; a custom detail `x_<hex>` has its own label; any other name is shown as it is.
- `role`: what the app does with the field: `username`, `password`, `token`, `private_key`, `key_passphrase`, `host`, `database`, `public_key`, `service`, `project`, `website`, `totp`, or `other`.
- `custom`: true for a custom detail (`x_<hex label>`).
- Order: the fields of the kind first (login: username, password; database: host, database, username, password; SSH key: private key, key passphrase, public key; API key: token; custom: the main secret field), then service and project, then custom details in their stored order, then any other field.

`Draft`:

```json
{"title": "GitHub", "kind": "login", "notes": "", "tags": ["work"],
 "fields": [
   {"name": "username", "value": "octocat", "secret": false},
   {"name": "password", "value": null, "secret": true},
   {"label": "Website", "value": "https://github.com", "secret": false}
 ]}
```

- A field has a `name` (a built-in field, or the main field of a custom item), or a `label` (a custom detail: the core makes `x_<hex>`). Not both.
- `value: null` on a secret field of an existing item keeps the stored value. On a new item it is `invalid_input`.
- The rules are the Mac's (`build_vault_draft`): the kind of an existing item cannot change (`invalid_input`, "The item category cannot change. Delete the item and add a new one."); the required fields of each kind (login: username and password; API key: token; SSH key: private key; database: host, database, username, and password; custom: one secret field); at most 10 custom details, each label 1 to 31 bytes, unique without regard to case; a visible detail needs a value; the main field of a custom item is `[A-Za-z0-9_]+`, does not start with `x_`, and is not a built-in name. Plain values are trimmed; secret values are kept as typed.
- Tags: kept as given (at most 32, each 1 to 64 bytes). The phone shows the tags and lets the owner edit them; it does not add service and project as tags. (The Mac form has no tag field and keeps the tags it does not own.)

### 5.4 Passwords and Watchtower

| Op | Parameters | Result |
| --- | --- | --- |
| `generate` | `style`: `random`, `memorable`, or `pin`; `length` (random 8–64, default 24; pin 4–12, default 6); `digits`, `symbols` (bool, random only, default true); `words` (memorable 3–10, default 5), `separator` (memorable, one of `-`, `.`, `_`, ` `, `,`, default `-`), `capitalize` (memorable, default true) | `{"value": "…", "bits": 118.0}` |
| `strength` | `value` | `{"bits": 41.2, "score": 2}`. Section 9. |
| `watchtower` | | Section 9. |

### 5.5 Sync

| Op | Parameters | Result |
| --- | --- | --- |
| `sync` | | `{"status": Status}`. Merges the relay copy and pushes this iPhone's changes. Blocks for the network. |
| `sync_status` **R** | | `{"status": Status}`. No network. |
| `sync_wait` | `timeout` (1–25 s) | `{"changed": bool}`. A long poll: true when the relay has a version this iPhone has not merged. `locked` when the vault locks during the wait. |
| `take_new_passphrase` | `passphrase` | `{"status": Status}`. After `needs_passphrase`: the vault takes the new passphrase of the copy and merges. A wrong one is `wrong_passphrase`. |
| `use_relay_copy` | | `{"status": Status}`. After `stale_copy` or `forked_copy`: the owner keeps the relay copy; the iPhone drops its anchor and merges. |
| `devices` | | `{"devices": [{"id": 3, "name": "Rafał’s iPhone", "this": true, "last_seen_at": 1791200000 or null}]}` |

`Status`:

```json
{"enabled": true, "state": "ok", "message": "Up to date.", "version": 41,
 "last_sync_at": 1791200000, "pushed": false,
 "merged": {"inserted": 0, "updated": 2, "deleted": 0, "conflicts": 0}}
```

- `state`: `off` (a local vault), `never` (no sync since the app started), `ok`, `offline`, `needs_passphrase`, `removed`, `damaged`, `stale_copy`, `forked_copy`, `busy`, or `error`.
- `merged`: the last merge that changed something, or null.

### 5.6 Removing a vault from this iPhone

`remove_vault` with the vault unlocked removes this iPhone's device from the relay team (`DELETE /v1/devices/{id}`), then deletes the vault file, its sync state, and its entry. When this iPhone is the last device of the team, the relay keeps it (`409`): the core turns sync off and deletes the local files; the relay copy stays. Without the unlocked vault, or when the relay does not answer, it fails with `locked` or `relay_unreachable` and deletes nothing, unless `force` is true: then it deletes the local files and the device stays on the relay until a Mac removes it ("Devices…" > Remove). `left_relay` says whether the device left.

### 5.7 AutoFill

| Op | Parameters | Result |
| --- | --- | --- |
| `autofill_list` **R** | `domains`: the service identifiers of iOS (domains or URLs) | `{"matches": [Fill], "others": [Fill]}`. `matches`: the logins whose website matches (section 8); `others`: every other login that is not archived. |
| `autofill_credential` **R** | `id` | `{"username": "…", "password": "…"}`. Records the reveal. The extension asks for Face ID or the passphrase before each call. |
| `credential_identities` **R** | | `{"identities": [{"id": 12, "username": "octocat", "host": "github.com"}]}`: one per website of each login that is not archived. For the QuickType bar. No password. |

`Fill`: `{"id": 12, "title": "GitHub", "username": "octocat", "website": "https://github.com", "has_totp": true}`.

## 6. `phone.json`

```json
{"version": 1, "selected": "<vault_id>", "vaults": [Vault]}
```

Written to a temporary file and renamed. The extension reads it and never writes it.

## 7. One-time passwords

A field is a one-time password when it is secret and its label, without regard to case, is "One-time password", "OTP", "TOTP", or starts with "one-time password", or its value starts with `otpauth://`. (The 1Password import stores it as the custom detail "One-time password".) The value is an `otpauth://totp/…` URI (`secret`, `algorithm` SHA1/SHA256/SHA512, `digits` 6–8, `period` 15–120), or a bare Base32 secret (spaces and `-` ignored, any case) with SHA1, 6 digits, 30 s. RFC 6238; HMAC from `ring`. An `otpauth://hotp` value is `invalid_input`. `has_totp` in a row is true when the item has such a field (by its label; the value is not read for the list).

## 8. Websites and matching

A website field is the custom detail whose label starts with "website" or "url" (any case), or a field named `website` or `url`. A value without a scheme gets `https://`. The host is lowercased, and a leading `www.` is dropped. A service identifier of iOS (a domain or a URL) becomes a host the same way. They match when the hosts are equal, or one ends with `.` and the other, and the shorter host has at least two labels. A website with a port matches only that port; a service identifier without a port matches a website without a port.

## 9. Strength and Watchtower

`bits` estimates the entropy of a value: for a value from `generate`, the exact entropy of the choice; for another value, the length times log2 of the size of the character classes it uses (lowercase 26, uppercase 26, digits 10, symbols 33, other 100), minus a penalty for repeats and sequences. `score`: 0 below 28 bits, 1 below 36, 2 below 60, 3 below 80, 4 from 80.

`watchtower` reads every secret field with the role `password` of the items that are not archived, in memory only, and answers:

```json
{"weak": [12, 40], "reused": [[3, 9, 22]], "old": [5], "conflicts": [61], "checked": 48}
```

- `weak`: score below 2.
- `reused`: groups of items that share one password (compared by SHA-256 in memory).
- `old`: the password field did not change for 365 days (the item's `changed_at`).
- `conflicts`: conflict copies that are not archived.
- The answer has IDs only, never a value.
