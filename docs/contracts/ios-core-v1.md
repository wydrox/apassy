# iPhone vault core contract v1

Date: 2026-10-07. Passkeys, one-time password rules, and schema 17 (sections 5.8, 5.9, 7, 10, and 11) added 2026-10-09. Questions through the relay (section 5.10) added 2026-10-12. Gate 3 (questions: the row of an iPhone is written by the confirming Mac; removal; schema 19) 2026-10-12. Folders, adding by paste, and the options of a credential (section 5.11, and the new members of `Row` and `Detail`) added 2026-10-12 for the iPhone app v2. The questions of every vault on the iPhone (section 5.10, "Several vaults": `vault_id` and `vaults`, `questions_unlock`, the push token in every team) added 2026-10-14 (stream Q1). The agents of the Macs (section 5.12, contract relay-feed-v1) added 2026-10-14 (stream FD).
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

The core is the same vault code as the Mac app: the same schema (19), the same merge, the same relay client. A phone and a Mac that sync one vault must run the same schema. The one exception is a copy of an earlier schema: a schema 19 client merges a copy of schema 18 or 17 (`is_mergeable_schema` in `src/vault/merge.rs`) and gives its records the values of schema 19 in memory. The copy on disk or on the relay does not change. Any other schema is refused, as between two Macs. Section 10 is the history of the upgrade from schema 16 to 17.

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
| `feed-seq.json` | The highest feed `seq` accepted of each Mac (section 5.12). No secret. |
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
| `unsupported_schema` | The vault or the copy has a schema that this app does not read. Update the app or the Mac. A schema 19 app reads a copy of schema 18 or 17 and no other (section 10). An app of an earlier schema cannot open a vault of schema 19. |
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
| `exists` | A passkey with this ID is in the vault already. `passkey_register` gives it when the login that gets the passkey has one. `passkey_import` counts it and does not raise it (section 5.8). `folder_create`, `folder_rename`, and `folder_move` give it when a folder in that place has the name, without regard to case (section 5.11). |
| `bad_key` | The key of a passkey is not a P-256 PKCS #8 key. The core and the Swift wrapper define the code, but `passkey_import` counts a bad key as failed, so no call answers it now. |
| `internal` | A bug. The message says so. |

## 5. Calls

**R**: the `autofill` role may call it.

### 5.1 Vaults and the lock

| Op | Parameters | Result |
| --- | --- | --- |
| `info` **R** | | `{"vaults": [Vault], "selected": "<vault_id>" or null, "unlocked": bool, "join": Join or null, "schema": 19, "version": "0.3.4"}` |
| `select` **R** | `vault_id` | `{}`. Locks the vault that was open. The questions of each vault stay (section 5.10). |
| `unlock` **R** | `passphrase`, `keep` (bool, app only, default false) | `{}`. Opens the selected vault. With `keep`, the core keeps the passphrase in an erasing buffer until `lock`, for `resume`. |
| `lock` **R** | | `{}`. Closes the vault, erases a kept passphrase, drops the relay key and token from memory, drops the questions of every vault (section 5.10), and ends a long poll. |
| `suspend` | | `{}`. Closes the vault and ends the relay calls, but keeps a kept passphrase. Drops the questions of every vault, as `lock` does. The app calls it when it leaves the screen. |
| `resume` | | `{"unlocked": bool}`. Opens the vault again with the kept passphrase. False when there is none (the app shows the lock screen). |
| `check_passphrase` **R** | `passphrase` | `{"ok": bool}`. Checks against the vault file; changes nothing. For the owner check without Face ID. |
| `create_local_vault` | `name`, `passphrase` | `{"vault": Vault}`. A new vault on this iPhone only, without the relay, selected and unlocked. The app offers it only in a Simulator build and in tests. |
| `remove_vault` | `vault_id`, `force` (bool) | `{"left_relay": bool}`. Section 5.6. Drops the questions of every vault, as `lock` does (section 5.10). |

`Vault`: `{"id": "<vault_id>", "name": "Personal", "relay_url": "https://…" or null, "team_id": "t_…" or null, "device_id": 3 or null, "added_at": 1791200000}`.

### 5.2 Joining a vault (contract relay-sync-v1, section 7.2)

The owner selects "Add a device…" on the Mac; the Mac shows a QR code and the link `<relay URL>/link#apassy_lnk_…`. The iPhone scans it (or the owner pastes it).

| Op | Parameters | Result |
| --- | --- | --- |
| `join_start` | `link`, `device_name` (optional; the config name by default), `answer_key` (optional, b64u X9.63; section 5.10) | `Join`. Makes a device key in memory and sends the link with the name of this iPhone. A join that was waiting is cancelled first. |
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
 "added_at": 1791100000, "changed_at": 1791200000, "used_at": null,
 "folder": "5b0e…", "provider": "GitHub", "production": false}
```

- `kind`: `login`, `api_key`, `ssh_key`, `database`, or `custom`.
- `subtitle`: the username of a login or a database, the host of a database without a username, the public key label of an SSH key, else the service, else empty.
- `websites`: the values of the website fields (section 8), as stored.
- `conflict_of`: the ID of the item whose conflict copy this is, when a sync kept both versions.
- `has_totp`: true when the item has a field with the role `totp` (section 7). The list reads the stored value of a field only to see whether it starts with an explicit `otpauth://totp` URI, and only when the label does not already decide. No answer holds the seed.
- `has_passkey`: true when the item holds a valid passkey (section 5.8). The row never holds a key.
- `folder`: the UUID of the folder of the item (section 5.11); null at the top level, also when its folder was deleted on another device.
- `provider`: the label of the provider of the item's declaration (`Stripe`, `GitHub`, `PostgreSQL`), as the Mac picks its provider tile; null without a declaration or a provider. The app takes the tile from the provider; without one, from the service in `subtitle` (an API key, an SSH key without a public key, and another kind; not a username, a host, or a public key); else from the title. This is close to the Mac's `provider.unwrap_or(service)` but not the same: the Mac reads the service of every kind, and a row has no service member, so a login, a database, or an SSH key with a public key and a service can show another tile on the iPhone.
- `production`: the red dot of the Mac: the declaration says `production` and its environment came from the owner or a signal. An environment from a default or from usage is not marked (the bouncer still treats it as production until the owner answers).
- `has_password`: true when the item stores a secret field `password` with a non-empty value. It is the same test that `passkey_remove` uses to decide between keeping and deleting the login. The row never holds the value. The Swift `ItemRow` reads `has_password` as optional: a core that does not send it gives `nil`, and the app must then warn that removing a passkey can delete the login. `has_passkey` is `false` when absent.

`Detail` is a `Row` with `"notes": "…"`, `"fields": [Field]`, and, for a login with a passkey, `"passkey": {"rp_id", "user_name", "user_display_name", "credential_id", "user_handle"}` (base64, no key; the member is absent when the item has no passkey), and these members (section 5.11):

- `folder_path`: the folder names from the top level to the item's folder; `[]` at the top level.
- `env_name`: the variable that agent processes get (the stored one, or the automatic `APASSY_ITEM_<id>`); null when the item has no secret field to deliver.
- `always_ask`: "Always ask me": each use by an agent waits for the owner.
- `environment`: `production`, `staging`, `development`, or `local`; null without a declaration.
- `environment_source`: `owner`, `signal`, `usage`, or `default`; null without a declaration.

The Swift `ItemRow` and `ItemDetail` read every member of section 5.11 as optional, so an answer of an older core still decodes (the members are then nil).

The fields of a passkey (names that start with `passkey_`) are never in `fields`. `Field`:

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

### 5.10 Questions through the relay (contract relay-questions-v1)

Added 2026-10-12 (stage 5, stream M3). The iPhone is an answering device of [relay-questions-v1](relay-questions-v1.md): it reads the questions that wait on a Mac, opens and checks each card, and posts the owner's answer. All these calls are of the app only (`not_allowed` in the AutoFill extension). Since 2026-10-14 one iPhone answers the questions of every vault it holds, each vault through its own questions team ("Several vaults" below). A call needs at least one vault unlocked in this session; with none, it answers `locked` (or `no_vault` when no vault is selected).

The **questions team** of a vault is its relay membership with the purpose `questions`, else its relay sync membership (relay-questions-v1 section 3). An iCloud vault gets a notifications-only team with `join_attach` (plan §A7). The question key is the vault secret `question-key-v1` that a Mac made; the iPhone never makes one, and gets it with the sync of the vault. The iPhone's `trusted_device` row (kind `iphone`) has the relay key of the questions team as `sign_key`, the Secure Enclave answer key as `answer_key`, and its device number in that team; the core finds its own row by `sign_key`. The iPhone never writes this row: the Mac that confirms the join writes it (see after the tables).

| Op | Parameters | Result |
| --- | --- | --- |
| `questions_list` | | `{"status": Status, "vaults": [QuestionsVault], "questions": [Question]}` |
| `questions_wait` | `timeout` (1 to 25 s) | `{"changed": bool}` |
| `questions_unlock` | `vault_id`, `passphrase` | `{"vault_id": "…", "status": Status}` |
| `question_open` | `qid`, `vault_id`? | `Question` with its card |
| `question_answer_string` | `qid`, `vault_id`?, `kind`, `item_id`?, `environment`?, `action`?, `project_key`?, `time`? | `{"time": n, "answer_string": "…", "needs_face_id": bool}` |
| `question_answer` | the same, `time`, `signature`? | `{"id": n, "at": n, "kind": "…"}` |
| `answer_key_register` | `public_key` (b64u X9.63), `vault_id`? | `{"device_uuid": "…", "team_id": "…", "relay_device_id": n}` |
| `push_token_set` | `token` (lowercase hex, 32 to 200), `environment` (`development` or `production`), `bundle_id`? (default `com.wydrox.apassy.companion`) | `{"device_id": n, "updated_at": n, "vaults": [PushVault]}` |
| `push_token_clear` | | `{"cleared": ["<vault_id>"], "pending": ["<vault_id>"]}` |
| `join_attach` | `link`, `device_name`?, `answer_key` (b64u X9.63, required) | `{"state": "waiting", "team": "…", "words": [w1, w2], "expires_at": n}` |
| `join_attach_poll` | | the same, `state` `waiting` or `attached` |
| `join_attach_cancel` | | `{}` |

`Status`: `{"enabled": bool, "team_id": "…"|null, "relay_device_id": n|null, "device_uuid": "…"|null, "answer_key": "<b64u>"|null, "has_key": bool, "registered": bool, "removed": bool}`. `registered` is true when the row of this iPhone is in the vault. `removed` is true when the key of the membership belongs to a removed row: then the list has no question of that vault and the core does not ask the relay for it. Without a questions team `enabled` is false; when no vault has a context, the list is empty and `questions_wait` answers `changed: false` at once. When every context is of a removed iPhone, `questions_wait` asks the relay nothing but waits out its `timeout` before `changed: false` (a lock ends it with `locked`), so an app that waits again never spins.

`QuestionsVault`: `{"vault_id": "…", "vault_name": "Work", "selected": bool, "unlocked": bool, "status": Status, "error": "<code>"|null}`. One for each context (below), in the order of `vault_id`. `unlocked` is true for the selected vault while it is open: its keys are read from it at each call; for another vault they are those of its last unlock in this session. `error` is the code of the last relay call of that vault that failed (section 4 codes, such as `relay_unreachable`, or `removed` when the relay removed this device), until one works.

`status` of `questions_list` is the `Status` of the selected vault, as before several vaults, so an older app still works: the `Status` of its context, else `enabled: false` (the selected vault has no team, or it is locked and has no context).

`Question`:

```json
{"qid": "oKGio6SlpqeoqaqrrK2urw", "vault_id": "4f1c0a2b9d8e7f6a5b4c3d2e1f0a9b8c", "vault_name": "Work",
 "state": "open", "asker_name": "MacBook Pro",
 "created_at": 1790000001, "expires_at": 1790000300, "problem": null, "answered": null,
 "card": {"asker_device": "0b7e5c3a-…", "created_at": 1790000000, "digest": "f3b3…",
          "run": {"id": "123456789012345", "agent": "claude-code", "command": ["npm", "run", "migrate"],
                  "cwd": "/tmp/synthetic-shop", "env_names": ["DATABASE_URL"], "purpose": "…", "risk": "…",
                  "user_request": "…", "request_source": "…", "agent_request": "…", "remember": null},
          "question": {"items": [{"item_id": "9", "name": "API token", "production": false,
                                  "unconfirmed": true, "always_ask": false}],
                       "project": {"key": "/tmp/synthetic-shop/.git", "label": "synthetic-shop"},
                       "action": "deploy", "production": true, "why": "…",
                       "valid_answers": ["once", "production:deploy", "correct_environment"]}},
 "settle": null}
```

- `state` is `open`, `settled`, or `expired` (an open question past its `expires_at` on the iPhone's clock is `expired`). A question leaves the list 10 minutes after it ended.
- `card` is present only when every check of relay-questions-v1 section 7.3 passed: the envelope opens with the key of its `key_id` and the AAD of the relay's clear values; the JSON has exactly the fields within the limits; `v` is 1 and `qid` matches; the core computes the digest v2 itself and gets `digest`; `asker.device` is a live `trusted_device` whose device number in the questions team, when set, equals the relay's `from_device_id`. Else `card` is null and `problem` says why: "Sync this vault to read this question." (no key with that `key_id`), "Update Apassy to read this question." (another `v`, an unknown or a missing field, an unknown answer text), or "This question could not be read." (anything else).
- Every text of `card` is for display: control and format characters replaced by `?`, the folder and the project key shortened (the rules of `shown_path`). The core keeps the exact card; an answer never sends display text back.
- `settle` is `{"outcome", "device_name", "device_kind", "kind", "at", "replaced_by"}` when the settle envelope opens, else null. `answered` is the kind of the answer that this process sent, while it remembers it.

Answers (relay-questions-v1 sections 5.3, 9, and 13):

- `kind` is one of section 9.1. The core checks it against the card: `approve_in_project` and `allow_production` need the matching entry of `valid_answers` and a project, and the core fills in `action` and the exact `project_key` from the card (when the request names them, they must match); `correct_environment` needs `item_id` of an item with `unconfirmed: true` and `environment`; `deny` is always valid; the other kinds need their entry. No other field may come with a kind.
- `question_answer_string` builds the exact answer string of section 9.3 with this iPhone's device UUID, the team, the `qid`, the choice, the digest, and `time` (default: now). `needs_face_id` is true for `approve_once`, `approve_in_project`, `allow_production`, and `correct_environment` to `development`.
- For such an answer the app signs `answer_string` with the Secure Enclave answer key after Face ID for this answer (`SecureEnclaveKeys.signApproval`, a new `LAContext` with no reuse), and calls `question_answer` with the same `time` and the DER `signature` as b64u. The core checks the signature with the registered `answer_key` before anything is sent (`not_registered` when it does not verify: the key changed).
- For the other kinds `signature` must be absent: the core signs with the relay key of the questions team (`sign_key`), without Face ID.
- `time` more than 55 s old is `stale_answer` (answer again); a retry after a network error sends the same `time` and `signature` in a new envelope (section 13 step 4). A time more than 60 s ahead is `invalid_input`.
- The core seals the answer of section 9.2 (fields in the contract's order) with the question key, a new random nonce, and the AAD with this iPhone's device number, and posts it. The relay taking it does not mean that it counted: the settle says that.

**The row of an iPhone.** The iPhone never writes its own `trusted_device` row. `join_attach` needs `answer_key`; without it the call is `invalid_input`. The core appends the compressed key to the device name of the link: `"<name> ~<44 characters of b64u>"`. The name is shortened so that the whole is at most 64 bytes, the limit of a relay device name. The Mac that confirms the join writes the row during the owner check `ConfirmQuestionsDevice` (the proof covers the whole `device_name`, so it covers the answer key too): kind `iphone`, a new UUID, `sign_key` = the relay key of the link, `answer_key` from the name, and the device number in the team. `join_attach` writes only the membership (purpose `questions`) at the confirmation, and downloads nothing: a notifications-only team has no copy. A refusal of the Mac, an expired link, or a cancel ends the join; the relay removes a device that was confirmed but not stored.

`join_attach` refuses a vault that has a questions team already, unless the key of that membership belongs to a removed row (the owner removed this iPhone) and the membership is for questions only: then the new key replaces the old one after the confirmation. A removed iPhone that syncs the vault through the relay (a sync membership) gets `invalid_input` that asks the owner to turn sync through the relay off and join again.

`join_start` (the sync join, section 5.2) takes the same optional `answer_key` (b64u) and appends it to the device name in the same way. A Mac that confirms a device in "Add a device…" of the relay sync writes the row of the iPhone when the name of the link carries a key.

`answer_key_register` writes nothing. It checks that the vault holds the row of this iPhone (found by `sign_key` = the key of the membership) with this `answer_key`, and returns the row. Its errors: `not_registered` (the row has not reached this iPhone with the sync yet), `removed` (the owner removed this iPhone), and `answer_key_changed` (the row holds another key, for example after a new Face ID enrollment: the owner removes the iPhone on the Mac and connects it again). `question_answer_string` and `question_answer` give `removed` or `not_registered` when there is no row.

The keys of a removed row (`sign_key` and `answer_key`) never register again (the vault answers `AlreadyExists`). A removed iPhone connects again with a new relay key (a new `join_attach`) and a new answer key: the app calls `renew()` on the Secure Enclave key when `status.removed` is true.

Errors of these calls, besides those of section 4: `no_questions` (the vault has no questions team), `not_registered` (no row, no answer key, or the signature does not verify with it), `removed` (the row of this iPhone is removed), `answer_key_changed` (the row holds another answer key), `unreadable` (the card failed a check; the message is the `problem`), `already_answered` (`409 question_settled`), `expired` (`409 question_expired`, `404`, or past `expires_at`), `not_routed`, `too_many_answers` (the relay allows 3 answers of a device for a question, 20 for a question, and a byte budget for the team), `stale_answer`, `push_unavailable` (`409` on `PUT /v1/push/token`), `wrong_vault` (the `vault_id` of an answer is not the vault of its question), `locked` (the `vault_id` names a vault that has no context: unlock it first).

**Several vaults** (2026-10-14, stream Q1). The core holds one unlocked vault, but it keeps a **context** for each vault that was unlocked in this app session, by `unlock` or by `questions_unlock`. A context holds only what the questions need: the relay device of the questions team with its key, the question key, the trusted devices, this iPhone's row, the last sequence, and the questions the relay returned. It holds no item, no other vault secret, and no passphrase.

- `select`, `unlock`, `create_local_vault`, and `join_finish` keep every context. The context of the vault that closes keeps what the vault held at that moment.
- `lock`, `suspend`, `remove_vault` (of any vault), and the end of the process drop every context: the relay calls end, and the keys leave memory (the question key is erased). After `resume` only the selected vault has a context again; the app calls `questions_unlock` for the others.
- The context of the selected vault is read again from the vault at each call while it is open, so a sync that brings a new row or a new question key counts at once. The context of another vault keeps what its vault held at its last unlock: a card from a Mac that joined that vault later shows "This question could not be read.", and a new question key shows "Sync this vault to read this question.", until that vault opens again.
- `questions_list` reads the relay for every context at once and lists all their questions, newest first; each names its `vault_id` and `vault_name`. A relay that fails for one vault sets the `error` of its `QuestionsVault` and leaves its last questions in the list; the call fails only when every vault failed.
- `questions_wait` runs one long poll for each context at the same time (each is a separate relay device of its own team) and returns as soon as one brings news; that ends the others. A lock ends them all.
- `question_open`, `question_answer_string`, and `question_answer` take an optional `vault_id`. Without it, the core uses the context that holds `qid` (it reads the relay once when none does); with it, the core refuses with `wrong_vault` when another context holds `qid`, and never signs or sends anything then. An answer is checked, signed, and sealed with the keys of the context of its question only. Two contexts that hold one `qid` (a relay that routes the same ID to two teams) give `invalid_input` without `vault_id`. A `vault_id` that is not on this iPhone is `no_vault`.
- `answer_key_register` takes an optional `vault_id`; without it, the selected vault.
- `questions_unlock {vault_id, passphrase}` makes the context of a vault without selecting it: the core opens the vault, reads what the context needs, and closes it again. The selected vault does not change and stays open. The app feeds it the passphrase from the Keychain after Face ID. For the selected vault while it is open it checks the passphrase against the vault file and returns the status (the app may store that passphrase behind Face ID). `wrong_passphrase` for a wrong passphrase; `locked` when a `lock` or a `suspend` came during the key derivation; `busy` when the AutoFill extension holds the vault; `no_vault` when the vault was removed meanwhile (no context of a removed vault survives). The vault file is open only under a mutex that `lock`, `suspend`, and `remove_vault` take too: a `suspend` waits for the key derivation (one PBKDF2 at most), so the app holds no file lock when `suspend` returns. `unlock` opens the selected vault under the same mutex. A vault without a questions team gives `status.enabled: false` and no context.
- `push_token_set` sends the token to the questions team of every context (not of a removed iPhone), and keeps it in memory: a context made later in this process gets it at its next relay call. `PushVault` is `{"vault_id": "…", "device_id": n|null, "updated_at": n|null, "error": "<code>"|null}`, the selected vault first. The top `device_id` and `updated_at` are of the first team that took the token (the selected vault when it did). The call fails only when no team took it (with the error of the first, or `no_questions` / `locked` when there is no context). A team that failed gets the token at the next relay call of its vault.
- `push_token_clear` removes the token from the team of every context. A team that failed, and each other vault on this iPhone, goes into `questions-push.json` in the data folder (`{"version": 1, "clear": ["<vault_id>"]}`, vault IDs only, written as `phone.json` is): when that vault opens, the core clears the token there at its first relay call and drops it from the file. `pending` lists those vaults. `push_token_set` empties the file.
- `remove_vault` of a vault with a context (or the selected vault while it is open) first sends `DELETE /v1/push/token` to its questions team with the relay key in memory, then, for a notifications-only team, `DELETE /v1/devices/{id}` of this iPhone: it leaves that team. A relay sync team that the removal left needs neither. A call that fails is tried again before each later read of the questions while the app runs; a `lock` or a `suspend` drops it with the key. A vault without a context keeps the token in its team until a Mac removes this iPhone.

The app (Swift: `VaultService.questionsUnlock`, `PassphraseStore.readSession`) never asks for Face ID by itself. After an unlock with the passphrase and after a `resume`, the other vaults whose passphrase is stored behind Face ID show one row in Decisions, "Work, Family are locked. Unlock with Face ID to see their questions."; its tap calls `questions_unlock` for each of them. A Face ID unlock of the selected vault ("Unlock Personal, and the questions of Work and Family") and an opened notification read them at once. It reads those passphrases with one Face ID match: one `LAContext`, evaluated once, passed with `kSecUseAuthenticationContext` to each keychain read, and invalidated after the last. A Face ID unlock of the selected vault uses the same match. Each passphrase lives for its call only. A vault that fails stays in the list as locked; a vault without a stored passphrase opens with a passphrase sheet, which calls `questions_unlock` and never `select`. The selected vault never gets a row or the sheet: the lock screen opens it. An answer to a question whose `vault_id` has no context is refused in the app before Face ID.

Older apps: a request without `vault_id` works as before for the selected vault, and `status` is still the selected vault's. An older app that answers a question of another vault without `vault_id` still sends it with the keys of that vault.

After an answer the app shows: "Sent. The Mac checks it; if the run does not continue within a minute, the answer was refused." The protocol has no receipts yet.

The app asks for notification permission only when the owner turns notifications on, sends the device token with `push_token_set` at each launch with notifications on (once a vault is unlocked; vaults that open later get it from the core), and `push_token_clear` when they are turned off; it then calls `unregisterForRemoteNotifications`, and while `pending` names vaults with a questions team it says "Notifications stay on for: Work, Family until you open them." The notification has the fixed text of relay-questions-v1 section 14.1; opening it shows the questions.

A person who knows the passphrase of the vault (has the vault) can still write `trusted_device` rows. This is the same class of risk as holding the vault ([relay-questions-v1](relay-questions-v1.md) section 18).

### 5.11 Folders, adding by paste, and the options of a credential

Added 2026-10-12 for the iPhone app v2 ([ADR 0026](../adr/0026-simple-app.md) §4, §5, §8; [ADR 0025](../adr/0025-low-friction-access.md) §4). The rules are the Mac's: the folders of the vault (`src/vault/folders.rs`), "New Credential" (`src/desktop/ui/new_credential.rs`, `src/desktop/owner_store/add.rs`), and the options of the credential screen (`src/desktop/ui/items.rs`). Every call needs the unlocked vault (`locked`). Only `folders` is open to the `autofill` role; the others give it `not_allowed`. A core older than this section answers each call with `invalid_input` ("This call is not known.").

Each change goes through the vault in its own transaction, so it syncs as `save` does: the app calls `sync` after the change (section 5.5). Folder rows sync one by one (the later change wins; a deleted folder stays deleted). The folder of a credential, "Always ask me", and the source of the environment sync with the credential.

| Op | Parameters | Result |
| --- | --- | --- |
| `folders` **R** | | `{"folders": [Folder]}`, depth first; each level by position, then name. |
| `folder_create` | `parent` (a folder UUID; null or absent: the top level), `name` | `{"folder": Folder}` with `count` 0. |
| `folder_rename` | `uuid`, `name` | `{}`. The same name changes nothing. |
| `folder_move` | `uuid`, `parent` (null or absent: the top level) | `{}`. The folder moves with its subfolders and credentials, after the last subfolder of `parent`. |
| `folder_delete` | `uuid` | `{"moved": n}`: the count of credentials that moved to the parent folder (the top level when it has none). Its subfolders move there too. No credential is deleted. |
| `item_folder_set` | `id`, `folder` (null or absent: the top level) | `{}`. Moving changes nothing else (sharing, rules, and history stay); the history gets "Moved to Acme / Billing". |
| `detect` | `text` | `{"found": [Found]}`. No secret value is in the answer. Nothing found is `[]`. |
| `add_pasted` | `text`, `folder` (optional), `pick` (optional: indexes of `found`), `titles` (optional: `[{"index": n, "title": "…"}]`) | `{"items": [{"id": 12, "revision": 1, "title": "Stripe live", "summary": "Stripe live · STRIPE_SECRET_KEY · production"}]}` |
| `item_options_set` | `id`, `always_ask` (optional bool), `environment` (optional: `production`, `staging`, `development`, or `local`) | `{}` |

`Folder`: `{"uuid": "5b0e…", "parent": "…" or null, "name": "Billing", "position": 0, "count": 3}`. `count`: the credentials directly in the folder that are not archived. A parent that another device deleted, or a cycle that two moves on two devices made, reads as the top level.

Folder rules (`Vault::create_folder` and the others): a name is trimmed, has 1 to 64 bytes and no control character, and is unique among its siblings without regard to case (`exists`, "A folder with this name is already there."). Folders nest at most 4 levels. A name that breaks a rule, a folder that would go below level 4, and a move into the folder itself or one of its subfolders are `invalid_input`. A folder or a parent that is not there (another device deleted it) is `not_found`. `item_folder_set` of an item that is not there is `not_found` with the message of an item.

`Found`:

```json
{"index": 0, "title": "Stripe live", "kind": "api_key", "provider": "Stripe",
 "env_name": "STRIPE_SECRET_KEY", "hosts": ["api.stripe.com"], "environment": "production",
 "environment_source": "signal", "risk": "high", "line": null,
 "summary": "Stripe live · STRIPE_SECRET_KEY · production",
 "fields": [{"name": "token", "label": "Token", "secret": true, "preview": "sk_live_••••••••"}]}
```

- The detection is the Mac's (`apassy::vault::detect`): a secret, a `KEY=value` line, a whole `.env` file (one entry for each assignment, with its `line` from 1), a URL with credentials (`postgres://`, `mysql://`, `mongodb://`, `redis://`, `amqp://`), an SSH private key, or an `otpauth://` link. It runs in the core on the iPhone and sends nothing anywhere.
- `provider` is the label of the provider of the catalog; null for a value without a provider (a Custom item, "Credential"). `kind` is as in `Row`. `environment` and `risk` are the declaration that the detection gives. `environment_source` is `signal` (a strong signal: a value prefix such as `sk_live_`, or an environment word of the variable) or `default` (the most sensitive value). The Mac shows the environment of a row only for `signal`: a red "Production", or "Staging", or "Development" (also for `local`).
- `summary`: "TITLE · VARIABLE · ENVIRONMENT", without the variable when there is none.
- The `preview` of a plain field (the user name, the host, and the database of a URL) is its value. The `preview` of a secret field is a mask: the public value prefix of the provider (`sk_live_`, `ghp_`), else the URL scheme (`postgres://`), then `••••••••`. The mask has a fixed length. A plain value that holds a secret value of the same credential is masked too. No title, summary, or field of the answer holds a secret value.
- `text` has at most 1 MiB (`invalid_input`). The core keeps its own copy in an erasing buffer and drops it after the detection. The copies in the JSON request and the response, and those made while decoding them, are not erased.

`add_pasted` detects `text` again in the core (the app never sends a detected value back) and saves the picked entries in one transaction: all or none (`Vault::add_detected_all`). `pick` names entries by the `index` of `detect` for the same text; when it is absent, every entry. An index that is not there, a repeated index, and an empty `pick` are `invalid_input`; a text with no credential is `invalid_input` with the Mac's note. A title of `titles` replaces the detected title of that entry when it is not empty after trimming (at most 128 bytes), as the title field of each row on the Mac does. The rest is the Mac's: a title that another item has gets " 2", " 3"; a variable that another item uses becomes the automatic name; the declaration, its provider, and the source of each value are saved; the items go to `folder` (`not_found`, "The folder is gone. Select another folder.", when it is not there). The items have no origin: the owner pasted them, as on the Mac (the `item_origin` table records only agents, ADR 0025 §6). `summary` uses the stored title, the stored variable, and the stored environment.

`item_options_set` saves what the owner answered on the credential screen. `always_ask` turns "Always ask me" on or off. `environment` sets the environment of the declaration with the source `owner`; the project, the provider, the other values, and their sources stay. An item without a declaration gets one with this environment and the most sensitive other values, which count as defaults. A declaration event goes to the history. Both members are optional; `always_ask` is applied first. An item that is not there is `not_found` and nothing changes. The core does not check the owner: the app asks for Face ID or the passphrase first when the change makes the bouncer less careful (turning "Always ask me" off, or an environment other than `production`), and for any environment of an item without a declaration (the Mac saves a first declaration only after its owner check), as the Mac asks for its owner check. Turning "Always ask me" on and choosing `production` for an item with a declaration need no check.

### 5.12 The agents of the Macs (contract relay-feed-v1)

Added 2026-10-14 (stream FD). The iPhone is a reader and a sender of [relay-feed-v1](relay-feed-v1.md): it reads the sealed feed that each Mac publishes of its agents, opens and checks each one (relay-feed-v1 section 7.4), and sends one kind of action back, the removal of an exception of an agent. The source is `ios/ApassyCore/src/core/feed.rs`. All these calls are of the app only (`not_allowed` in the AutoFill extension).

A feed travels in the questions team of its vault, so the feeds use the questions **contexts** of section 5.10: a vault has feeds on this iPhone when it has a context (unlocked in this session by `unlock` or `questions_unlock`). What the feeds of a vault hold in memory (the last good feed of each Mac, the actions this process posted, the titles of the vault's items by item UUID) is part of its context: a `lock`, a `suspend`, and `remove_vault` drop it with the context; `select` keeps it. With no context the calls answer `locked` (or `no_vault` when no vault is selected), as the questions calls do; with an unlocked vault that has no questions team, `feed_list` answers `{"vaults": []}` and `feed_wait` `{"changed": false}` at once.

| Op | Parameters | Result |
| --- | --- | --- |
| `feed_list` | | `{"vaults": [FeedVault]}` |
| `feed_wait` | `timeout` (1 to 25 s) | `{"changed": bool}` |
| `feed_action_string` | `vault_id`, `mac_device`, `agent`, `item`, `kind`, `created_at`, `action_id`?, `time`? | `Prepared` |
| `feed_action` | the same, `action_id`, `time`, `signature`? | `{"action_id": "…", "seq": n\|null, "created_at": n\|null, "expires_at": n\|null}` |
| `feed_action_wait` | `action_id`, `vault_id`?, `timeout`? (0 to 25 s, default 0) | `Outcome` |

`feed_action_status` is accepted as another name of `feed_action_wait` (the name of relay-feed-v1 section 2).

**`feed_list`** reads `GET /v1/feed` for every context at once (from its last `change`, without a long poll) and answers what this iPhone shows:

```json
{"vaults": [
  {"vault_id": "4f1c0a2b-…", "vault_name": "Personal", "team_id": "t_7k2m5q4x3c",
   "registered": true, "answer_key": true, "error": null,
   "macs": [
     {"device": "0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d", "relay_device_id": 2, "name": "MacBook Pro",
      "seq": 1790000040, "generated_at": 1790000040, "stale": false, "truncated": false,
      "problem": null, "can_act": true, "week": {"by_you": 3, "automatic": 128},
      "agents": [
        {"id": "4", "name": "Claude Code", "host": "claude", "where": "mac", "revoked": false,
         "token_expires_at": 1797776000, "last_use_at": 1790000010, "uses_this_week": 12,
         "projects": ["synthetic-shop"], "note": "Deploys only from the main branch.",
         "restricted": false,
         "actions": [{"action": "deploy", "allowed": 2, "not_allowed": 1, "projects": ["synthetic-shop"]}],
         "exceptions": [{"item": "3c9e1f7a2b4d4c6e8f0a1b3d5e7f9a2c", "item_title": "Shop database",
                         "title": null, "here": false, "kind": "never", "created_at": 1789990000}],
         "recent": [{"at": 1790000010, "item": "8d2a4c6e1f3b4d5a9c7e0b2d4f6a8c1e",
                     "item_title": "API token", "title": "API token", "here": true,
                     "action": "deploy", "project": "synthetic-shop",
                     "command": "npm run deploy -- --token [apassy:secret]",
                     "outcome": "allowed", "decided_by": "owner", "answered_on": "Test iPhone"}]}]}]}]}
```

- One `FeedVault` for each context, in the order of `vault_id`. `registered`: the vault holds the row of this iPhone (it can send actions). `answer_key`: that row has an answer key (it can send the Face ID kinds; else the app says "Connect this iPhone again on a Mac to use Face ID here." for `never` and `always_ask`). `error` is the code of the last relay call of that vault that failed, until one works: `feed_unavailable` for a relay without feeds (relay-feed-v1 section 14.2), `relay_unreachable`, `removed`, and the others of section 4. The call fails only when every vault failed. A removed iPhone (`status.removed` of section 5.10) gets no Mac of that vault.
- A Mac is listed when its last feed passed every check of relay-feed-v1 section 7.4: the envelope opens with the question key of its `key_id` and the AAD of the relay's `device_id` and `seq`; the JSON has exactly the fields of section 7.1 within the limits, `v` 1, and the relay's `seq`; `mac.device` is a live `trusted_device` of kind `mac` whose device number in the team (`relay_devices`) on this iPhone's copy of the vault is the relay's `device_id` (a Mac whose number has not synced here yet publishes nothing: its feed is ignored, with no text); and `seq` is above the highest `seq` this iPhone accepted of that relay device. A feed that fails step 4 or 5 is ignored with no text. A Mac removed from the vault leaves at once, and a Mac that is not in the relay's `present` leaves the list.
- `name` is the name of the Mac's `trusted_device` row. `relay_device_id` is its device number in the team, the target of an action.
- `problem` is the text of the step that the last feed of this Mac failed: "Sync this vault to see the agents of <Mac>." (step 1: another key, or it does not open) or "Update Apassy to see the agents of <Mac>." (steps 2 and 3). The last good feed stays with it. When no feed of the Mac opened in this session, the Mac is listed with `seq`, `generated_at`, and `week` null and no agent. Such a Mac is listed only when a live trusted Mac row has that device number.
- `can_act` is whether this iPhone can act on this feed. It is true for the selected, unlocked vault (its keys and devices are read again at each call), and for another vault when its keys were read (its last `questions_unlock`, or while it was selected) after this feed came. A vault that is not selected holds a copy of its `trusted_devices` from then: a later feed may come from a Mac removed from the vault since, so it is listed with `can_act: false`, `feed_action_string` refuses it (`invalid_input`), and the app says "Select <vault> on this iPhone to remove exceptions of its agents." The core cannot read such a vault again without its passphrase. Problem-only Macs have `can_act: false`.
- `stale` is true when `generated_at` is more than 24 hours old on the iPhone's clock: the app dims the Mac ("The Mac has not reported since <date>") and offers no action. A `generated_at` in the future is not stale; the app shows it as "now".
- The members of an agent are those of the feed (relay-feed-v1 section 7.1), every text with control and format characters replaced by `?`. For each exception and recent use, `item` and `item_title` are the feed's; `title` is the title of the item with that UUID in the vault on this iPhone, else null; `here` is whether the vault on this iPhone holds it (false for a null `item`; null when the items of the vault were not read in this session). The app shows `title`, else `item_title` with "not on this iPhone", and "A deleted credential" for a null `item` (with no action).
- After an applied removal (`feed_action_wait` with `outcome: applied` and `verified: true`), the exception leaves the list at once (in the feed of that Mac shown then, which may be newer than the one the action named), until the next feed of that Mac.
- An item reference is the vault's own form of an item UUID, 32 lowercase hex characters with no hyphens, as `item.uuid` holds it (`Vault::item_uuids`; relay-feed-v1 section 4). It is the only form: a feed with another form (a hyphenated or upper-case UUID) fails step 2 ("Update Apassy to see the agents of <Mac>."), `feed_action_string` and `feed_action` refuse it (`invalid_input`), and the core compares it byte for byte, never reformatted. An item of the vault on this iPhone whose stored UUID has another form has no `title` in the list.

**The high-water mark.** The core keeps the highest `seq` accepted of each Mac, by team and relay device id, in `feed-seq.json` in the data folder (`{"version": 1, "teams": {"t_7k2m5q4x3c": {"2": 1790000040}}}`, written as `phone.json` is). It holds no secret and stays after a lock and a restart, so a relay cannot bring back an older feed. A feed with a lower `seq` is ignored; a feed with the same `seq` shows only when this process does not show that Mac (after a lock or a restart: the AAD binds the `seq`, so it is the same feed).

**The Macs that check the names** (added 2026-10-14, relay-feed-v1 sections 7.1 and 9.3). A feed whose plaintext ends in one line feed after the JSON object is of a Mac that checks the names of an action. When the core accepts such a feed, it adds the relay device id to `names` in the same file (`{"version": 1, "teams": {…}, "names": {"t_7k2m5q4x3c": [2]}}`; absent while empty, and the core of 0.5.2 ignores it) and sends that Mac v2 actions from then on, also when a later feed lacks the mark: a feed that a holder of the question key made cannot bring back actions without the names to a Mac that this iPhone saw check them. A missing or damaged file is no mark, as for the `seq`.

**`feed_wait {timeout}`** runs one long poll of `GET /v1/feed` for each context at the same time and returns as soon as one brings news (a new feed, a removed one, a new problem); that ends the others. `changed: false` after the timeout. A `lock` or a `suspend` ends them all with `locked`. The app calls it only while the Agents tab or an agent page is on the screen, and `feed_list` after `changed: true`.

**`feed_action_string`** builds the action string of relay-feed-v1 section 9.3 for the exception that the feed shows:

```json
{"op": "feed_action_string", "vault_id": "4f1c0a2b-…", "mac_device": "0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d",
 "agent": "4", "item": "3c9e1f7a2b4d4c6e8f0a1b3d5e7f9a2c", "kind": "never", "created_at": 1789990000}
```

```json
{"vault_id": "4f1c0a2b-…", "team_id": "t_7k2m5q4x3c", "action_id": "sLGys7S1tre4ubq7vL2-vw",
 "time": 1790000060, "feed_seq": 1790000040,
 "action_string": "apassy-feed-action-v1\n6f1c0e2a-…\n0b7e5c3a-…\nt_7k2m5q4x3c\nsLGys7S1tre4ubq7vL2-vw\nremove_exception:4:3c9e1f7a2b4d4c6e8f0a1b3d5e7f9a2c:never:1789990000\n1790000040\n1790000060",
 "needs_face_id": true, "face_id_reason": "remove an exception of agent \"Claude Code\""}
```

- `mac_device` is the `device` of the Mac in `feed_list`; `agent`, `item`, `kind`, and `created_at` are those of the exception in the list. `kind` is `never`, `always_ask`, or `only`. The core finds the exception in the last good feed of that Mac (it reads the relay once when it has none): an exception, an agent, or a Mac that is not there is `not_found` ("This list of the Mac changed. Look at it again."); a disconnected agent is `invalid_input`. The string has the device UUID of this iPhone's row (`by`), the Mac's UUID (`to`), the team, the `action_id`, the exception, the `seq` of that feed (`feed_seq`), and `time`.
- **v1 or v2.** To a Mac that checks the names (its feed has the mark, now or before: "The Macs that check the names" above) the string is of v2: the first line is `apassy-feed-action-v2` and a ninth line `names:<64 lowercase hex>` follows, the SHA-256 of the three names that `feed_list` shows for this exception, joined with one zero byte: the agent's `name`; the credential, which is `title` when it is not null or empty, else `item_title`; and the Mac's `name`. These are the values of `feed_list` as they are (control and format characters already `?`), without the words the app puts around them ("not on this iPhone", "A credential"). To any other Mac it is the v1 string of eight lines. The app changes nothing: it signs `action_string` as it is, whichever version. The Mac rebuilds the names from its own rows and settles an action with other names `stale` (relay-feed-v1 section 9.5 step 7), so a feed with false names on real ids removes nothing.
- `action_id` is 16 random bytes of the core, b64u (22 characters), unless the request gives one (a retry); `time` is now unless the request gives one. The app keeps both for `feed_action`.
- The core keeps the prepared action by `action_id` in the context of the vault (the string, its `feed_seq`, the target, and the answer key of the row then; at most 64; a `lock` drops them). The same `action_id` and `time` for the same exception answer the kept string again.
- A Mac with `can_act: false` is refused (`invalid_input`, "Select this vault on this iPhone to act on the agents of its Macs.").
- `needs_face_id` is true for `never` and `always_ask`: the app signs `action_string` with the Secure Enclave answer key **of the team `team_id`** after Face ID for this action (a new `LAContext`, no reuse), with `face_id_reason` as the prompt (the agent name with control and format characters replaced by `?` as in the list, without `"`, at most 40 characters). For `only` it is false: the core signs with the relay key of the membership, and the app asks nothing.
- The core does not check the age of the feed here; `feed_action` does.
- Errors: `removed` and `not_registered` as in section 5.10 (no row of this iPhone); `not_registered` with "Connect this iPhone again on a Mac to use Face ID here." for a Face ID kind when the row has no answer key.

**`feed_action`** takes the same parameters with the `action_id` and `time` of `feed_action_string`, and for a Face ID kind the DER `signature` as b64u:

```json
{"op": "feed_action", "vault_id": "4f1c0a2b-…", "mac_device": "0b7e5c3a-…", "agent": "4",
 "item": "3c9e1f7a…", "kind": "never", "created_at": 1789990000,
 "action_id": "sLGys7S1tre4ubq7vL2-vw", "time": 1790000060, "signature": "MEUCIQ…"}
```

```json
{"action_id": "sLGys7S1tre4ubq7vL2-vw", "seq": 9, "created_at": 1790000060, "expires_at": 1790000360}
```

- The core sends the action that `feed_action_string` kept for this `action_id`, with its exact string and its `feed_seq`: a newer feed of the Mac that came during Face ID changes nothing (the Mac takes any `feed_seq` up to its last one, relay-feed-v1 section 9.5). An `action_id` it did not prepare (another session, after a lock) is `stale_action`; parameters other than the prepared ones are `invalid_input`. `time` more than 55 s old is `stale_action` (do it again, with Face ID again); more than 60 s ahead is `invalid_input`.
- It reads the relay once (no long poll; a failure keeps what it holds) and checks the newest feed of that Mac: the Mac is still a publisher of the vault, the agent is not disconnected (`invalid_input`), and the exception is still there and not hidden by an applied removal; else `not_found`, "The list on <Mac> changed. Try again.". A stale newest feed (24 hours) is `stale_feed`.
- For `never` and `always_ask`, `signature` must verify with the answer key of this iPhone's row over the kept string: `invalid_input` without it or when it does not verify with an unchanged key ("Face ID did not sign this action, so nothing was sent. Try again."); `not_registered` only for a real change: the row has no answer key now, or another one than when the string was made. For `only`, `signature` must be absent (`invalid_input`); the core signs with the relay key, which must be the row's `sign_key`.
- The core seals the plaintext of relay-feed-v1 section 9.2 (fields in the contract's order; `v` 2 with `names` before `signature` for a v2 string, `v` 1 without `names` for a v1 string) with the question key, a new random nonce, and the AAD `action` with this iPhone's device number as the sender and the Mac's `relay_device_id` as the target, and posts `POST /v1/feed/actions`. A retry after a network error sends the same `action_id`, `time`, and `signature` in a new envelope; a relay that has the action already answers `409 conflict`, and the core answers with `seq`, `created_at`, and `expires_at` null.
- Relay errors: `not_routed` (`403 not_routed`), `not_found` (`404`: the Mac has no feed on the relay now, it may be locked), `too_many_actions` (`403 too_many_actions`), `too_large`, `removed`, `rate_limited`, `relay_unreachable`.
- The relay taking the action does not mean that it counted: the settle says that.

**`feed_action_wait`** reads the state of an action that this process posted (`GET /v1/feed/actions/{action_id}`), with a long poll of `timeout` while it is open:

```json
{"action_id": "sLGys7S1tre4ubq7vL2-vw", "outcome": "applied", "verified": true,
 "reason": null, "feed_seq": 1790000070, "at": 1790000061}
```

- `outcome`: `pending` (open), `applied`, `refused`, `stale`, or `expired` (the relay expired it, or it is open past its `expires_at` on this iPhone's clock: "<Mac> did not answer. It may be asleep or locked.").
- `verified` is true when the settle opened with the question key and the AAD of the relay's clear outcome, and names this action and this outcome; `reason` (the target's text, for `refused` and `stale`; null when empty), `feed_seq`, and `at` come from it. Else they are null, `verified` is false, and `outcome` is `refused` whatever the relay's clear outcome: the only settle a Mac seals so is a refusal (it could not read the action; relay-feed-v1 section 9.5), so an unopenable `applied` or `stale` is never believed, and the row stays.
- The app shows "Removed on <Mac>." for a verified `applied`, "<Mac> did not accept it: the exception changed. Pull to refresh." for a verified `stale` (also with the `reason` "the names on the iPhone did not match this Mac": the list that this iPhone showed was not the Mac's), "<Mac> refused it: <reason>." for a verified `refused`, and "Not applied, or unknown. Check the list on <Mac>." for any settle with `verified: false`.
- Without `vault_id` the core uses the context that posted the action. An action that this process does not know (another session, after a lock) is `not_found`, as is one the relay purged.

Errors of these calls, besides those of section 4 and section 5.10: `feed_unavailable`, `not_found`, `stale_action`, `stale_feed`, `too_many_actions`, `not_routed`, `unreadable` (no question key to seal an action: sync the vault), `feed_rate`.

**`feed_rate`.** A `403 feed_rate` of `GET /v1/feed` (relay-feed-v1 section 10.2: the iPhone read its 16 MiB of feed text of the relay's minute) is `feed_rate`, "The relay asks this iPhone to wait a minute before it reads the agents again." The core then reads no feed of that vault for 60 seconds (a whole minute always passes the relay's next one): in that time `feed_list` and the reads of the action calls answer `feed_rate` at once, without the relay, for that vault (the call fails only when every vault failed, as above), and `feed_wait` waits within its `timeout` instead of answering at once (it answers `changed: false` at the end of the timeout, or polls with the time left once the minute passed), so the app's watch loop polls again without a busy loop. A `lock` or a `suspend` ends that wait with `locked`, and drops the pause with the context.

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

The current schema is 19. Schema 18 adds `folder`, `shared_vault`, and `vault_secret`. Schema 19 adds `trusted_device`, `relay_membership`, and `item_home` ([relay-questions-v1](relay-questions-v1.md) section 5.2). The rest of this section is the history of schema 17.

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
