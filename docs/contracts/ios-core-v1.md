# iPhone vault core contract v1

Date: 2026-10-07. Passkeys, one-time password rules, and schema 17 (sections 5.8, 5.9, 7, 10, and 11) added 2026-10-09.
Status: experimental. This contract supports the iPhone app in [ADR 0023](../adr/0023-iphone-vault.md). The Rust side (`ios/ApassyCore`, crate `apassy-core`) and the Swift side (`ios/ApassyVaultKit`) implement it. A change to this document changes both sides in the same pull request.

Status of the passkey and one-time password work (branch `feat/passkeys-totp`): the sources are in the branch. Integration, signed builds, and native device acceptance are pending. Section 12 lists what is not yet confirmed. Do not read this document as a statement that a release or a device accepted these calls.

## 1. Parts

| Part | Location | Built for |
| --- | --- | --- |
| The core: a C interface over `apassy::vault` and `apassy::sync` (relay and encrypted iCloud snapshots) | `ios/ApassyCore` (Rust, `staticlib`) | `aarch64-apple-ios`, `aarch64-apple-ios-sim`, `aarch64-apple-darwin` (tests) |
| The C header and the module map | `ios/ApassyCore/include/` | |
| The XCFramework | `ios/ApassyCore/build/ApassyCore.xcframework`, made by `scripts/build-ios-core.sh`, not committed | |
| The Swift wrapper: typed requests, answers, errors | `ios/ApassyVaultKit` (Swift package) | iOS 26, and macOS 15 for `swift test` |
| The app and the AutoFill extension | `ios/ApassyCompanion` (XcodeGen project) | iOS 26 |

The vault holds an exclusive lock on `<file>.lock` while it is open, and iOS ends a suspended app that holds a file lock in an App Group container. So the core opens the vault only while it is unlocked: `lock` and `suspend` close it. The app calls `suspend` when it leaves the screen, and the AutoFill extension can then open the vault. While the app shows the vault, the extension gets `busy`.

The core is the same vault code as the Mac app: the same schema (17), the same merge, the same relay client. A phone and a Mac that sync one vault must run the same schema. The one exception is a copy of schema 16, which a schema 17 client reads in a private encrypted stage (section 10). Any other schema is refused, as between two Macs.

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
- The core counts each answer first and writes it into one buffer with room for the final NUL byte. A serializer that changes size between the two passes gives the error `internal`, so a secret never moves to a grown copy. The core erases the buffer when it is freed.
- The core erases each answer when it is freed, and each passphrase and secret it parsed. A Swift `String` cannot be erased; the app keeps a revealed value only while it is on the screen. This is best effort, as on the Mac.

## 3. Config

```json
{"data_dir": "/…/Library/Application Support/Apassy", "device_name": "Rafał’s iPhone", "role": "app"}
```

- `data_dir`: absolute; the App Group container, so the app and the AutoFill extension see the same vault. The core makes it with mode 0700.
- `device_name`: the name that the relay and the Macs show for this iPhone, and the name in a conflict copy. At most 64 bytes after trimming.
- `role`: `app` or `autofill`. The `autofill` role answers only the calls marked **R** in section 5. Every other call gets `not_allowed`. The extension never syncs and never edits an item. It records a reveal, and it can add a passkey with `passkey_register`. It cannot import, remove, or export (section 5.8).

Files in `data_dir`:

| File | What it is |
| --- | --- |
| `phone.json` | The vaults on this iPhone (section 6). |
| `vaults/<vault_id>.apassy` | The live vault (SQLCipher), as on the Mac. |
| `sync/<vault_id>.json` and `sync/.*` | The relay sync state and work files, as on the Mac. |
| `icloud-transfer/<transaction>/…` | Private encrypted input/output snapshots for one coordinated file transaction. |
| iCloud bookmarks | Private Swift-managed file access records, keyed by vault ID. They contain no passphrase. |

## 4. Requests and answers

A request is `{"op": "<name>", …parameters}`. An answer is one of:

```json
{"ok": true, "result": { … }}
{"ok": false, "error": {"code": "wrong_passphrase", "message": "The passphrase does not open this vault."}}
```

- Unknown parameters are ignored. A missing parameter is `invalid_input`.
- `message` is plain English for the owner, in the style of the Mac app. It never has a value, a passphrase, SQL, or a driver error.
- An iCloud preparation error can include `rekeyed: true` after the local vault accepted a new passphrase but a later step failed. Swift must update the saved biometric passphrase in this case, while it reports the sync failure.
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
| `unsupported_schema` | The vault or the copy has a schema that this app does not read. Update the app or the Mac. A schema 17 app reads a copy of schema 16 (section 10). An app of schema 16 cannot open a vault of schema 17. |
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
| `excluded` | `passkey_register`: the vault has a passkey that the website lists in `excluded` (archived items count). |
| `unsupported_algorithm` | `passkey_register`: the website lists algorithms, and ES256 (-7) is not one of them. |
| `exists` | A passkey with this ID is in the vault already. `passkey_register` gives it when the login that gets the passkey has one. `passkey_import` counts it and does not raise it (section 5.8). |
| `bad_key` | The key of a passkey is not a P-256 PKCS #8 key. The core and the Swift wrapper define the code, but `passkey_import` counts a bad key as failed, so no call answers it now. |
| `internal` | A bug. The message says so. |

## 5. Calls

**R**: the `autofill` role may call it.

### 5.1 Vaults and the lock

| Op | Parameters | Result |
| --- | --- | --- |
| `info` **R** | | `{"vaults": [Vault], "selected": "<vault_id>" or null, "unlocked": bool, "join": Join or null, "schema": 17, "version": "0.3.4"}` |
| `select` **R** | `vault_id` | `{}`. Locks the vault that was open. |
| `unlock` **R** | `passphrase`, `keep` (bool, app only, default false) | `{}`. Opens the selected vault. With `keep`, the core keeps the passphrase in an erasing buffer until `lock`, for `resume`. |
| `lock` **R** | | `{}`. Closes the vault, erases a kept passphrase, drops the relay key and token from memory, and ends a long poll. |
| `suspend` | | `{}`. Closes the vault and ends the relay calls, but keeps a kept passphrase. The app calls it when it leaves the screen. |
| `resume` | | `{"unlocked": bool}`. Opens the vault again with the kept passphrase. False when there is none (the app shows the lock screen). |
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

### 5.2a Personal vaults in iCloud Drive

These calls require the `app` role. The core never receives an external provider URL or a bookmark. Paths must name private regular files below `data_dir/icloud-transfer`; symbolic links and paths outside this directory are refused. Output files must not exist.

| Op | Parameters | Result |
| --- | --- | --- |
| `icloud_import` | `input_path`, `name`, `passphrase` | `{"vault": Vault}`. Checks and strips the snapshot, creates a local vault with a new device identity, selects and unlocks it. An existing vault ID is refused without replacement. |
| `icloud_sync_prepare` | `vault_id`, `input_path`, `output_path`, optional `passphrase` | `token`, `input_sha256`, optional `output_sha256`, `write_required`, `rekeyed`. Checks identity and merges into the selected unlocked vault. Makes a stripped output only when needed. `write_required` is also true when the input snapshot has schema 16: the output is a copy of schema 17, also when the content is equal (section 10). The input file never changes. The optional passphrase follows a remote passphrase change. This call does not confirm publication. |
| `icloud_sync_complete` | `vault_id`, `token` | `{"status": Status}`. Consumes the preparation token after Swift confirms publication, or confirms that no write is needed. Rejects an obsolete vault session. |

Swift resolves a security-scoped bookmark, coordinates a read, and copies the encrypted file to private staging. It calls prepare off the main thread. Under coordinated write access, it compares the current provider hash with `input_sha256`. On a mismatch, it retries from a fresh snapshot. Otherwise, it checks `output_sha256`, publishes atomically when needed, and completes the transaction. Failed publication must not produce a successful sync status.

Swift refuses unresolved provider conflict versions before publication. It keeps the local vault usable when the file is offline, missing, or inaccessible. A new file selection must pass the core's vault identity check before it replaces the bookmark. The AutoFill extension uses the local vault only.

### 5.3 Items

| Op | Parameters | Result |
| --- | --- | --- |
| `items` **R** | `archived`: `"no"` (default), `"yes"`, or `"all"` | `{"items": [Row]}`, sorted by title (case-insensitive). |
| `item` **R** | `id` | `Detail` |
| `reveal` **R** | `id`, `field` | `{"value": "…"}`. A secret field. Records the reveal in the history of the item, as the Mac does after an owner check. The app asks for Face ID or the passphrase before each call. |
| `totp` **R** | `id`, `field` | `{"code": "123456", "period": 30, "remaining": 17, "digits": 6}`. Section 7. Never the seed. |
| `history` | `id` | `{"events": [{"at": 1791200000, "kind": "edited", "detail": "Changed: title, notes"}]}`, newest first, at most 50. `detail` is the text for the owner. A Credential Exchange preparation (section 5.9) shows as kind `revealed` with the detail "Prepared for a Credential Exchange transfer". |
| `save` | `id` (null for a new item), `revision` (null for a new item), `item`: Draft | `{"id": 12, "revision": 3}` |
| `archive` | `id`, `archived` (bool) | `{}` |
| `delete` | `id`, `revision` | `{}` |

`Row`:

```json
{"id": 12, "revision": 3, "title": "GitHub", "kind": "login", "subtitle": "octocat",
 "websites": ["https://github.com"], "tags": ["work"], "archived": false,
 "has_totp": true, "has_passkey": false, "has_password": true, "conflict_of": null,
 "added_at": 1791100000, "changed_at": 1791200000, "used_at": null}
```

- `kind`: `login`, `api_key`, `ssh_key`, `database`, or `custom`.
- `subtitle`: the username of a login or a database, the host of a database without a username, the public key label of an SSH key, else the service, else empty.
- `websites`: the values of the website fields (section 8), as stored.
- `conflict_of`: the ID of the item whose conflict copy this is, when a sync kept both versions.
- `has_totp`: true when the item has a field with the role `totp` (section 7). The list reads the stored value of a field only to see whether it starts with an explicit `otpauth://totp` URI, and only when the label does not already decide. No answer holds the seed.
- `has_passkey`: true when the item holds a valid passkey (section 5.8). The row never holds a key.
- `has_password`: true when the item stores a secret field `password` with a non-empty value. It is the same test that `passkey_remove` uses to decide between keeping and deleting the login. The row never holds the value. The Swift `ItemRow` reads `has_password` as optional: a core that does not send it gives `nil`, and the app must then warn that removing a passkey can delete the login. `has_passkey` is `false` when absent.

`Detail` is a `Row` with `"notes": "…"`, `"fields": [Field]`, and, for a login with a passkey, `"passkey": {"rp_id", "user_name", "user_display_name", "credential_id", "user_handle"}` (base64, no key; the member is absent when the item has no passkey). The fields of a passkey (names that start with `passkey_`) are never in `fields`. `Field`:

```json
{"name": "password", "label": "Password", "secret": true, "value": null, "role": "password", "custom": false}
```

- `value`: the value of a plain field; always `null` for a secret field (`reveal` gives it). `reveal` of a `passkey_` field is `not_found`.
- `label`: the Mac's label (`field_label`): `token` Token, `password` Password, `private_key` Private key, `passphrase` Key passphrase, `username` Username, `host` Host, `database` Database, `public_key` Public key, `service` Service, `project` Project; a custom detail `x_<hex>` has its own label; any other name is shown as it is.
- `role`: what the app does with the field: `username`, `password`, `token`, `private_key`, `key_passphrase`, `host`, `database`, `public_key`, `service`, `project`, `website`, `totp`, or `other`. Section 7 says how a field gets `totp`.
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

- A field has a `name` (a built-in field, or the main field of a custom item), or a `label` (a custom detail: the core makes `x_<hex>`). A custom detail may also give `name`: the stored field whose value `value: null` keeps, so a renamed hidden detail keeps its value.
- `value: null` on a secret field of an existing item keeps the stored value. On a new item it is `invalid_input`.
- The rules are the Mac's (`build_vault_draft`): the kind of an existing item cannot change (`invalid_input`, "The item category cannot change. Delete the item and add a new one."); the required fields of each kind (login: username and password; API key: token; SSH key: private key; database: host, database, username, and password; custom: one secret field); at most 10 custom details, each label 1 to 31 bytes, unique without regard to case; a visible detail needs a value; the main field of a custom item is `[A-Za-z0-9_]+`, does not start with `x_`, and is not a built-in name. Plain values are trimmed; secret values are kept as typed.
- A draft never names a passkey field. A field `name` that starts with `passkey_` is `invalid_input` ("This field name is reserved."). An update keeps the passkey of the item as it is.
- A login with a valid passkey needs no password or username. A `save` without those fields keeps the passkey. A new login still needs both fields.
- Tags: as the Mac keeps them: the service and the project first, then the given tags, without the old service and project values of an edit (at most 32, each 1 to 64 bytes).

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
| `take_new_passphrase` | `passphrase` | `{"status": Status, "rekeyed": bool}`. After `needs_passphrase`: the vault takes the new passphrase of the copy and merges (`rekeyed: true`). Without an anchor (after `use_relay_copy`) the passphrase only opens the copy for the merge and the vault keeps its own (`rekeyed: false`); the app then must not store the typed passphrase for Face ID. A wrong one is `wrong_passphrase`. |
| `use_relay_copy` | | `{"status": Status}`. After `stale_copy` or `forked_copy`: the owner keeps the relay copy; the iPhone drops its anchor and merges. |
| `devices` | | `{"devices": [{"id": 3, "name": "Rafał’s iPhone", "this": true, "last_seen_at": 1791200000 or null}]}` |

`Status`:

```json
{"enabled": true, "state": "ok", "message": "Up to date.", "version": 41,
 "last_sync_at": 1791200000, "pushed": false,
 "merged": {"inserted": 0, "updated": 2, "deleted": 0, "conflicts": 0}}
```

- `state`: `off` (a local vault), `never` (no sync since the app started), `ok`, `offline`, `needs_passphrase`, `removed`, `damaged`, `stale_copy`, `forked_copy`, `busy`, `pending` (local edits or publication still need sync), or `error`.
- `merged`: the last merge that changed something, or null.

### 5.6 Removing a vault from this iPhone

`remove_vault` with the vault unlocked removes this iPhone's device from the relay team (`DELETE /v1/devices/{id}`), then deletes the vault file, its sync state, and its entry. When this iPhone is the last device of the team, the relay keeps it (`409`): the core turns sync off and deletes the local files; the relay copy stays. Without the unlocked vault, or when the relay does not answer, it fails with `locked` or `relay_unreachable` and deletes nothing, unless `force` is true: then it deletes the local files and the device stays on the relay until a Mac removes it ("Devices…" > Remove). `left_relay` says whether the device left.

### 5.7 AutoFill

| Op | Parameters | Result |
| --- | --- | --- |
| `autofill_list` **R** | `domains`: the service identifiers of iOS (domains or URLs) | `{"matches": [Fill], "others": [Fill]}`. `matches`: the logins whose website matches (section 8); `others`: every other login that is not archived. A login that holds only a passkey (`has_passkey` and not `has_password`) is in neither list. |
| `autofill_credential` **R** | `id` | `{"username": "…", "password": "…"}`. Records the reveal. The extension asks for Face ID or the passphrase before each call. A login that holds only a passkey gives `invalid_input` ("This login has a passkey only."). |
| `credential_identities` **R** | | The identity set below. For the QuickType bar and the passkey and code suggestions of iOS. No password, no code, no seed, no key. |

`credential_identities` answers:

```json
{"identities": [{"id": 12, "username": "octocat", "host": "github.com"}],
 "passkeys":   [{"id": 13, "title": "Example", "rp_id": "example.com", "user_name": "octocat",
                 "user_display_name": "Octo", "credential_id": "<base64>", "user_handle": "<base64>"}],
 "totp":       [{"id": 12, "title": "GitHub", "username": "octocat", "host": "github.com"}]}
```

- `identities`: one entry per host of each login that is not archived, and that has a password or has no passkey. A login that holds only a passkey is not here.
- `passkeys`: the canonical passkeys of the vault (section 11). One entry for each credential. An archived item is not here.
- `totp`: one entry per host of each login that is not archived and has a one-time password (`has_totp`). A login without a website gives no entry. The Swift wrapper reads this member as `codes`. The members `passkeys` and `totp` are optional for the decoder (an older core sends only `identities`).
- A host that has a port keeps it in `host`.

`Fill`: `{"id": 12, "title": "GitHub", "username": "octocat", "website": "https://github.com", "has_totp": true}`.

### 5.8 Passkeys

A passkey is a WebAuthn ES256 credential (P-256, SHA-256, COSE -7) on a login. The vault stores it in reserved fields and keeps the key in the encrypted vault. No generic call returns the key. Every byte value on the wire is standard base64 with padding, in canonical form: no white space, no URL alphabet, no unused bits set. A request of a passkey call is at most 4 MiB. An error never quotes an ID, a handle, or a key.

The caller does a fresh owner check before each `passkey_assert`, `passkey_register`, `passkey_import`, `passkey_remove`, and `credential_export`. The core does not check the owner. It sets the flags "user present" and "user verified" in the authenticator data, because the caller did.

| Op | Role | Parameters | Result |
| --- | --- | --- | --- |
| `passkey_list` | app, autofill | `rp_id`; `allowed` (credential IDs, at most 256, default empty = any) | `{"passkeys": [Entry]}`. The canonical passkeys of `rp_id` (section 11). |
| `passkey_assert` | app, autofill | `id` (the item), `rp_id`, `credential_id`, `client_data_hash` (32 bytes) | `{"credential_id", "user_handle", "authenticator_data", "signature"}`. The signature is an ASN.1 DER ECDSA signature over the authenticator data and the hash. |
| `passkey_register` | app, autofill | `rp_id`; `user_name`; `user_display_name` (default empty); `user_handle` (1 to 64 bytes); `client_data_hash` (32 bytes); `algorithms` (COSE numbers, at most 32, default empty); `excluded` (credential IDs, at most 256); `attach_id` and `attach_revision` (both or neither); `title` (at most 128 bytes) | `{"id": 13, "credential_id", "attestation_object"}`. "none" attestation. |
| `passkey_import` | app | `accounts`: at most 1000 of `{"rp_id", "credential_id", "user_handle", "user_name", "user_display_name", "key", "title"}`; `key` is a P-256 PKCS #8 key in base64 | `{"imported": n, "skipped_existing": n, "failed": n}`. Counts only. |
| `passkey_remove` | app | `id`, `revision` | `{}`. Section 11.3. |

`Entry`: `{"id": 13, "title": "Example", "rp_id": "example.com", "user_name": "…", "user_display_name": "…", "credential_id": "<base64>", "user_handle": "<base64>"}`. It has no key.

Rules:

- `rp_id` is an ASCII host name: at most 253 bytes, letters, digits, `-`, `.`, `_`, no empty label, not starting or ending with `.` or `-`. The core does not check an origin. The caller (iOS, or a browser bridge) checked the origin and gave the relying party ID.
- A credential ID has 1 to 1023 bytes. A user handle has 1 to 64 bytes. A user name or display name has at most 256 bytes, without control characters.
- `passkey_assert`: `not_found` when the item is not an active login, its passkey is not canonical (section 11), its key does not parse, or its RP ID or credential ID differs from the request. The signature counter is always zero. The flags are user present, user verified, and backup eligible. Backup state stays clear.
- `passkey_register`: an empty `algorithms` list means the WebAuthn default, which includes ES256. A non-empty list without -7 gives `unsupported_algorithm`. A credential of `excluded` for this RP ID in the vault gives `excluded`, also when its item is archived. The core makes a 32-byte credential ID. With `attach_id`, the passkey goes on that active login at that revision. A stale revision gives `conflict`. A login that has a passkey gives `exists`. A conflict copy, archived or restored, or an item that is not an active login gives `invalid_input`. Without `attach_id`, the core makes a new login with the title (the RP ID when the title is empty).
- `passkey_import`: each account is a separate step. A credential that is in the vault already (a conflict copy counts) goes to `skipped_existing`. Any other failure, also a bad key, goes to `failed`. Nothing of a failed account is returned or logged. An import always makes a new login for each account. A request with more than 1000 accounts gives `invalid_input`.
- The `autofill` role cannot call `passkey_import`, `passkey_remove`, or `credential_export`. It gets `not_allowed`.
- The Swift wrapper adds its own checks before the core call (`PasskeyRequestCheck`): a client data hash of 32 bytes, a valid RP ID, a user handle of 1 to 64 bytes, and ES256 in a non-empty algorithm list.
- WebAuthn extensions: the wrapper answers a PRF request with "not supported" and a large blob read or write with an empty read or a failed write. A registration that requires large blob storage fails with `unsupportedExtension`. The core never makes a PRF output or a blob.

### 5.9 Credential Exchange export

| Op | Role | Parameters | Result |
| --- | --- | --- | --- |
| `credential_export` | app | | `{"items": [Export], "skipped": n}` |

The app calls it after a fresh owner check and gives the answer straight to the system (`ASCredentialExportManager`). The answer holds passwords, one-time password seeds, and passkey keys. It is the only call that returns a passkey key. The core writes no file.

`Export`:

```json
{"id": 12, "title": "GitHub", "notes": "", "tags": ["work"], "created_at": 1791100000,
 "changed_at": 1791200000, "username": "octocat", "password": "…", "websites": ["https://github.com"],
 "totp":    {"secret": "<base64 of the raw key bytes>", "period": 30, "digits": 6,
             "algorithm": "sha1", "issuer": "GitHub", "user": "octocat"},
 "passkey": {"rp_id": "…", "credential_id": "<base64>", "user_handle": "<base64>",
             "user_name": "…", "user_display_name": "…", "key": "<base64 PKCS #8>"}}
```

- Scope: the active logins that are not conflict copies, and each restored conflict copy whose passkey is canonical (section 11). A restored copy goes once, as a whole login. Items of other kinds, and logins with no username, password, code, or passkey, add to `skipped`. An archived item and any other conflict copy are not counted.
- `totp`: the first one-time password field of the item that Apassy reads as TOTP. A counter-based (HOTP) or unreadable value is not exported. `algorithm` is `sha1`, `sha256`, or `sha512`. A period or digit count that does not fit 16 bits is not exported. `issuer` and `user` come from the label and the `issuer` parameter of an `otpauth://totp` URI. A bare Base32 secret has neither.
- `passkey`: only a canonical, parsable passkey. A stored key that does not parse is left out and the other data of the login still goes. A failure of the vault is an error: an export never drops data in silence.
- One history event without values (kind `revealed`, detail "Credential Exchange export prepared") is recorded for each exported item, before the answer is returned. The event says that the owner prepared the export. It does not prove that the other app took the data.

## 6. `phone.json`

```json
{"version": 1, "selected": "<vault_id>", "vaults": [Vault]}
```

Written to a temporary file and renamed. The extension reads it and never writes it.

`Vault.sync_source` is optional for older lists. `"icloud"` selects the iCloud snapshot path. When it is absent, `relay_url` identifies a relay vault; a vault without either is local. Swift routes its sync methods accordingly. A missing bookmark is an access error, not a local-only vault.

## 7. One-time passwords

RFC 6238 TOTP, with HMAC from `ring`. The code is in `src/otp.rs` (`apassy::otp`). The Mac app, the importers, and the core use the same module.

**Formats.** The value is an `otpauth://totp/…` URI (`secret`; `algorithm` SHA1, SHA256, or SHA512; `digits` 6 to 8; `period` 15 to 120 seconds), or a bare Base32 secret (spaces and `-` ignored, any case) with SHA-1, 6 digits, and 30 seconds. A repeated parameter, a missing secret, and a value outside these ranges are `invalid_input`. The parser ignores other parameters, such as `issuer`. A seed of less than 80 bits is refused. `otpauth://hotp` is `invalid_input`. Apassy does not support HOTP, Steam codes, or other schemes.

**Which field is a code (`role: totp`).** A secret field has the role `totp` in two cases:

1. Its label, without regard to case, is "OTP" or "TOTP", or starts with "One-time password" or "One-time code" (also "One time …"). A number or a bracket suffix is allowed (`OTP 2`, `One-time password (work)`).
2. Its label is any other text, but its stored value starts with an explicit `otpauth://totp` URI. This keeps the custom title of an imported code. A bare Base32 value under another label is not a code.

The core decides case 1 from the label only, so a list reads no secret. For case 2 it reads the stored value of a secret field of role `other` in the core's erasing buffer, and keeps only the yes or no result. `has_totp`, the `totp` role of a `Field`, the `totp` list of `credential_identities`, and the export use this one rule.

**What leaves the core.** `totp` (`id`, `field`) answers the current code, `period`, `remaining`, and `digits`. It never answers the seed. No row, detail, identity, or error holds the seed or the URI. `reveal` of the field still gives the stored value after the owner check, as for any secret field, and `credential_export` gives the raw key bytes (section 5.9). The Mac editor and the iPhone editor keep a field with an OTP label hidden. The Mac editor makes a visible detail with an OTP label or a setup key hidden also when the owner saves it without a change.

## 8. Websites and matching

A website field is the custom detail whose label starts with "website" or "url" (any case), or a field named `website` or `url`. A value without a scheme gets `https://`. The host is lowercased, and a leading `www.` is dropped. A service identifier of iOS (a domain or a URL) becomes a host the same way. They match when the hosts are equal, or one ends with `.` and the other, and the shorter host has at least two labels. A website with a port matches only that port; a service identifier without a port matches a website without a port.

## 9. Strength and Watchtower

`bits` estimates the entropy of a value: for a value from `generate`, the exact entropy of the choice; for another value, the length times log2 of the size of the character classes it uses (lowercase 26, uppercase 26, digits 10, symbols 33, other 100), minus a penalty for repeats and sequences. `score`: 0 below 28 bits or for fewer than 8 characters, 1 below 36, 2 below 60, 3 below 80, 4 from 80.

`watchtower` reads every secret field with the role `password` of the items that are not archived, in memory only, and answers:

```json
{"weak": [12, 40], "reused": [[3, 9, 22]], "old": [5], "conflicts": [61], "checked": 48}
```

- `weak`: score below 2.
- `reused`: groups of items that share one password (compared by SHA-256 in memory).
- `old`: the password field did not change for 365 days (the item's `changed_at`).
- `conflicts`: conflict copies that are not archived.
- The answer has IDs only, never a value.

## 10. Schema 17 and the upgrade from schema 16

Schema 17 adds the passkey fields (section 11.1). It changes no table. A field of an earlier vault that has a reserved name (`passkey_…`) is an ordinary field of the owner, so the migration renames it. The new name is the custom label of the old name (`x_<hex>`), then the label with a number, then `legacy_field_<n>`. The value and the secret flag stay. An environment binding of the old name gets the new name. The item keeps its revision and its sync version, and the names depend only on the old data, so two copies of one vault that migrate do not conflict.

**The upgrade is coordinated.** Update the Macs and the iPhones that share a vault to builds of schema 17.

- A build of schema 17 migrates a vault of schema 16 when it unlocks the vault. A build of schema 16 cannot open a vault of schema 17 (`unsupported_schema`). The migration changes the vault file, so the owner should have a backup first ([backup and restore](../operations/backup-restore.md)).
- A build of schema 16 refuses a copy of schema 17 from a folder, iCloud Drive, or the relay (`unsupported_schema`). After the first device pushes schema 17, a device of schema 16 cannot sync that vault until it is updated.
- A build of schema 17 reads a copy of schema 16 and no other schema. It runs the checks of schema 16 on the copy (columns, header, and the stored content digest). Then the merge gives the records of the copy the field names of schema 17 in memory. The copy on disk or on the relay does not change. A copy of schema 17 with the header of schema 16 fails the checks. `MergeReport.remote_outdated` is true after such a merge.
- Push rule: when the merge read a copy of schema 16, the client pushes a copy of schema 17, also when the content is equal. A folder sync (`src/sync/mod.rs`), the iCloud path (`icloud_sync_prepare`, `write_required`, section 5.2a), and the relay sync (`src/sync/relay.rs`) follow this rule in the source.
- Relay rule (required): the client downloads the head of schema 16 into the private encrypted work file, checks it against the signed digest of the head that it fetched, merges in memory, and then pushes schema 17 with the compare-and-swap precondition on the head version that it read (`Precondition::Version`). A head that changed in the meantime gives a new round. The client never writes the work file to the relay. In the source, the relay loop gives the state no remote content after a copy of schema 16, so it pushes, also when a push fails and the next sync starts again. Adoption of a copy of schema 16 does the same. The tests for these cases are not confirmed (section 12, item 2).

## 11. Passkey rules

### 11.1 Storage

A passkey is a set of reserved fields on a login: `passkey_format` (`es256-pkcs8-v1`), `passkey_rp_id`, `passkey_credential_id`, `passkey_user_handle`, `passkey_user_name`, `passkey_user_display_name`, and the secret `passkey_key` (a P-256 PKCS #8 v1 key with the public point). The stored byte values are base64url without padding. The wire (section 5.8) is standard base64 with padding. The fields sync as ordinary encrypted `item_field` rows.

Only the passkey code writes them. A generic add or update refuses a `passkey_` name, `details` and `reveal` hide them (`reveal` gives `not_found`), an update keeps them, and no agent path can read them. The one exception is `credential_export` (section 5.9).

### 11.2 One canonical item for each credential

A credential is an RP ID with a credential ID. A normal item is an item that is not a conflict copy. A sync conflict can leave a passkey only in a conflict copy: a merge archives each new conflict copy, and only the owner can restore it. The vault chooses the canonical item of a credential with these rules:

1. A normal item holds the credential, active or archived: no conflict copy is canonical, archived or restored. The canonical item is the active normal item with the lowest ID. If every normal item with the credential is archived, the credential has no canonical item.
2. No normal item holds the credential: the restored (active) conflict copy with the lowest ID is canonical. This stays true after the owner deletes the original item, and when the original is another copy.
3. An archived item is never canonical.

Only a canonical passkey is listed (`passkey_list`, `credential_identities`), signs (`passkey_assert`), or goes in an export. A new or imported passkey never goes on a conflict copy, and a credential that a conflict copy holds counts as existing for `passkey_import` and for `excluded`.

### 11.3 Removing a passkey

`passkey_remove` takes the item ID and the revision that the owner saw. The app does a fresh owner check first.

- If the item has a secret `password` with a non-empty value, the item keeps the password and its other fields. Only the passkey fields go. The item gets a new revision and a history event.
- If the password is empty or missing, a login has no other way in. The core deletes the whole login: its fields, notes, tags, website, one-time passwords, custom details, history, and agent grants. The deletion syncs like a normal delete.
- A stale revision gives `conflict`. An item without passkey fields gives `not_found`.

The screen must tell the owner which of the two results happens before it asks for the check. `Row.has_password` gives the answer. When it is absent, the screen must warn that the login can go.

### 11.4 Credential Exchange on iOS 26

The app uses the Apple Credential Exchange. The data moves from app to app in memory. Apassy writes no file.

- Import keeps passwords, TOTP, and ES256 passkeys with a P-256 PKCS #8 key. TOTP uses SHA-1, SHA-256, or SHA-512. A passkey of another algorithm, a damaged key, or a passkey with PRF or large blob data counts as invalid (iOS 26.4 and later give the extension data; iOS 26.0 does not). The report has counts only, with no names. Other credential types (cards, Wi-Fi, documents) count as unsupported.
- Each import and each export starts with its own fresh owner check, before the app reads the other app's data or the keys of the vault.
- Export has two steps: the owner picks the other app in the system sheet, and then the app reads the vault. If the vault locks or another vault opens during the pick, the export pauses and nothing is read. The resumed export is bound to the vault in which the owner started it. The owner unlocks that vault, and the app asks for the owner check again before it reads the keys.
- The history event of an export says "prepared" (section 5.9). It is not a record that the other app finished the import.
- Not supported: HOTP, Steam codes, PRF, large blob, and passkey algorithms other than ES256. An item type other than a login is not exported.

## 12. Not confirmed yet

The statements above come from the source of the branch. These points are open or unconfirmed:

1. **Upgrade from schema 16 on devices.** Local tests cover adoption, a new passphrase, relay publication with equal content, and the iCloud core with an encrypted schema 16 file. These tests do not call the iCloud service or use a physical device.
2. **Integration and builds.** No signed build and no iPhone or Mac device ran these calls for this document. The [acceptance checklist](../operations/passkeys-and-codes.md#9-acceptance-checklist) lists what remains.
3. **Browsers.** The browser calls are in [browser contract](browser-v1.md) section 9, not here. Only the signature of Helium is verified as a browser caller today.
