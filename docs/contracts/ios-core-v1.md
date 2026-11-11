# iPhone vault core contract v1

Date: 2026-10-07. Passkey algorithms ES384, EdDSA, and RS256, and the PRF and large blob extensions (sections 5.8, 5.9, 11; vault schema 25) added 2026-11-03. Passkeys, one-time password rules, and schema 17 (sections 5.8, 5.9, 7, 10, and 11) added 2026-10-09. Questions through the relay (section 5.10) added 2026-10-12. Gate 3 (questions: the row of an iPhone is written by the confirming Mac; removal; schema 19) 2026-10-12. Folders, adding by paste, and the options of a credential (section 5.11, and the new members of `Row` and `Detail`) added 2026-10-12 for the iPhone app v2. The questions of every vault on the iPhone (section 5.10, "Several vaults": `vault_id` and `vaults`, `questions_unlock`, the push token in every team) added 2026-10-14 (stream Q1). The agents of the Macs (section 5.12, contract relay-feed-v1) added 2026-10-14 (stream FD). The Apple Watch (the external HTTP transport in section 2.1, the role `watch` in section 3, and its calls in section 5.13; [ADR 0039](../adr/0039-apple-watch-access-requests.md)) added 2026-11-03. Apassy Connect (the account key store in section 2.2, `connect_url` in section 3, and the calls of section 5.14; plan s7 unit I1) added 2026-11-10. The transport of the relay calls and the Connect dial (section 5.15, `dial_route` and `dial_state` of `connect_status`; plan s7 unit I2) added 2026-11-10. The verified devices and the removed state of section 5.14 (connect-account-v1 sections 6 and 7.5) added 2026-11-11. `list_verified` of `connect_status` (section 5.14: whether the signed device list itself verified) added 2026-11-11. `join_again` of `connect_status` (section 5.14: an account file of an earlier version) and the sync state `waits_for_device` (section 5.5) added 2026-11-11.
Status: experimental. This contract supports the iPhone app in [ADR 0023](../adr/0023-iphone-vault.md). The Rust side (`ios/ApassyCore`, crate `apassy-core`) and the Swift side (`ios/ApassyVaultKit`) implement it. A change to this document changes both sides in the same pull request.

Status of the passkey and one-time password work (branch `feat/passkeys-totp`): the sources are in the branch. Integration, signed builds, and native device acceptance are pending. Section 12 lists what is not yet confirmed. Do not read this document as a statement that a release or a device accepted these calls.

## 1. Parts

| Part | Location | Built for |
| --- | --- | --- |
| The core: a C interface over `apassy::vault` and `apassy::sync` (relay and encrypted iCloud snapshots) | `ios/ApassyCore` (Rust, `staticlib`) | `aarch64-apple-ios`, `aarch64-apple-ios-sim`, `aarch64-apple-darwin` (tests); `aarch64-apple-watchos` and `aarch64-apple-watchos-sim` with `--no-default-features` (SQLCipher with CommonCrypto, ADR 0039 section 4) |
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

// Native app: retrieve a device-local 32-byte request-history key, outside JSON.
// Return 0 for success, 1 for missing, another value for unavailable.
typedef int32_t (*apassy_history_key_provider)(void *context,
    const char *vault_id, bool may_create, uint8_t *out_key_32);
ApassyCore *apassy_core_new_with_history_key_provider(const char *config,
    apassy_history_key_provider provider, void *context);

// One call. `request` is JSON (section 4). The answer is JSON, UTF-8, NUL-terminated,
// never NULL. Free it with apassy_core_free_string.
char *apassy_core_call(ApassyCore *core, const char *request);

// Erase the answer and free it.
void apassy_core_free_string(char *answer);

// Lock the vault, drop the relay session, and free the core.
void apassy_core_free(ApassyCore *core);
```

- `apassy_core_call` is safe from several threads at once. A slow call (a sync, a long poll, a join) does not hold the vault: item calls answer while it runs.
- The history callback and its context must be thread-safe and remain valid until `apassy_core_free` returns. The callback writes exactly 32 bytes on success; it must not retain either pointer. `may_create=false` forbids creating or replacing a key. Missing, inaccessible or malformed keys never cause a reset. The core calls the provider only while it holds an authorized vault context and zeroizes its returned key buffer after use.
- A panic inside a call is caught and answered as the error `internal`. The core never aborts the process on a bad request.
- The core counts each answer first and writes it into one buffer with room for the final NUL byte. A serializer that changes size between the two passes gives the error `internal`, so a secret never moves to a grown copy. The core erases the buffer when it is freed.
- The core erases each answer when it is freed, and each passphrase and secret it parsed. A Swift `String` cannot be erased; the app keeps a revealed value only while it is on the screen. This is best effort, as on the Mac.

### 2.1 The external HTTP transport (Apple Watch)

watchOS gives this kind of app no BSD sockets: URLSession is the network API (ADR 0039 section 5). The watch app installs a transport, and the core then sends every relay request through it instead of its own TCP and TLS client. The iPhone app and the Mac install none and keep the core's client.

```c
typedef char *_Nullable (*apassy_http_send)(void *_Nullable context, const char *_Nonnull request_json);
typedef void (*apassy_http_cancel)(void *_Nullable context, uint64_t request_id);
void apassy_core_set_http_transport(apassy_http_send _Nonnull send, apassy_http_cancel _Nonnull cancel, void *_Nullable context);
```

- **Setup.** Call `apassy_core_set_http_transport` once per process, before `apassy_core_new`. A second call, or a NULL callback, changes nothing. The callbacks and the context stay valid for the life of the process. Both callbacks can run on several threads at once.
- **The request** (NUL-terminated JSON): `{"id": u64, "method": "GET", "url": "https://…", "headers": [["name", "value"], …], "body_b64u": "…", "timeout_ms": u64, "pin": "…"}`.
  - `id` is unique in the process. `url` is the relay origin and the path with its query.
  - `pin` (added 2026-11-03, plan S2–S3 unit N6) is present only for a **pinned origin**, a node on the tailnet ([node-pairing-v1](node-pairing-v1.md) section 4): the 43-character b64u SHA-256 of the node's certificate. The host then sends the request over TLS 1.3 only, accepts only a leaf certificate with that pin (in constant time; names, dates, the issuer, and later certificates of the chain do not count), never uses the system trust store for it, and never falls back to another trust after an error. A pin of another form, or a pin with an `http://` URL, is not sent (`connect`). Without `pin` the host uses system trust, as before. The host connects to the origin of `url` only: it tries no alternative destination of the node, because it cannot send the origin's `Host` to another address (the iPhone and the Mac, with their own client, do).
  - `headers` are `Authorization: Bearer …` (when the call signs in), `Content-Type: application/json` (with a body), the headers of the call (for example `If-Match`), and `User-Agent`. The host sets `Host` and `Content-Length`, follows no redirect, and adds no cookie.
  - `body_b64u` is the JSON body in b64u; it is absent without a body.
  - `timeout_ms` is the time for the whole request: the wait of a long poll plus 30 seconds, or less when the call has a deadline.
- **The answer** (NUL-terminated JSON, from `malloc` or `strdup`): `{"status": u16, "headers": [["name", "value"], …], "body_b64u": "…"}`, or `{"error": "connect" | "broken" | "protocol" | "pin_mismatch"}`.
  - `connect`: no byte of the request went out (no network, a name or TLS failure). `broken`: the request failed after it started, timed out, or was cancelled; a write may have landed. `protocol`: the answer is not valid. `pin_mismatch`: the request had a `pin` and the server presented another leaf certificate; no byte of the request went out. The core reads it as the pin mismatch of its own client (the call fails with `pin_mismatch`, section 4), and as `broken` for a request without a pin. Another `error` text is `broken`. NULL is `broken`.
  - `body_b64u` is absent for an empty body.
  - The core checks the answer as one read from a socket: a final status (200 to 599), at most 100 header lines and 16 KiB of header text, header names that are HTTP tokens, values without CR, LF, or NUL, and at most 2 MiB of body. Else `protocol`. Header names are compared in lowercase.
- **Memory and secrets.** The request holds the bearer and the body, and an answer can hold a token. The host keeps no copy after `send` returns. The core erases its request buffer after `send`, and erases the answer text before it frees it with C `free`.
- **Threads.** `send` runs on the core's calling thread and may block until the answer.
- **Cancel.** A lock, a suspend, or the end of a long poll calls `cancel` with the request ID; the `send` of that request then answers `{"error": "broken"}` at once. `cancel` can come from another thread while that `send` runs, and also just before that `send` starts: then that `send` fails at once. `cancel` must not call the core. A request that starts after the close never reaches the host.
- **Not through the transport.** A snapshot upload or download fails with `protocol`: the watch never syncs.

### 2.2 The Keychain store of the Apassy Connect account key

The iPhone is a device of an Apassy Connect account with one P-256 key of its own, the **account device key** ([connect-account-v1](connect-account-v1.md) section 5): outside every vault, one for the device, this device only, not synchronizable. The app keeps it as a generic password of the data-protection Keychain (`KeychainAccountKeyStore`: service `com.wydrox.apassy.connect-account-key`, `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, `kSecAttrSynchronizable` false) and gives the core three callbacks:

```c
typedef int32_t (*apassy_account_key_read)(void *context, uint8_t *out, size_t capacity, size_t *out_length);
typedef int32_t (*apassy_account_key_write)(void *context, const uint8_t *key, size_t length);
typedef int32_t (*apassy_account_key_delete)(void *context);
bool apassy_core_set_account_key_store(ApassyCore *core, apassy_account_key_read read,
    apassy_account_key_write write, apassy_account_key_delete delete_key, void *context);
```

- Set it once per core, after `apassy_core_new`, in the `app` role only; a second call, a NULL core, or a NULL callback answers `false`. The callbacks and the context stay valid until `apassy_core_free` returns and are thread-safe. Without a store every call of section 5.14 that needs the key answers `not_allowed`.
- `read` copies the stored document (the PKCS#8 of `ring`, 138 bytes; at most `capacity`, 1024) and its length and answers 0; 1: no key; any other value: unavailable. `write` stores a new document, replacing an earlier one, and answers 0, else unavailable. `delete` answers 0 (deleted), 1 (no key), or unavailable. The host keeps no copy of the bytes.
- The core makes the key at the first `connect_join` and reads it into an erasing buffer while it signs (the Mac reads its key after Touch ID the same way). `lock` and `suspend` drop it and the account token from memory. The key signs only the seven messages of connect-account-v1 section 5. It never goes into a vault, a file, a log, an answer, or a request: Connect sees only the public key.
- Not a key of section 5.2: a vault join keeps its relay key in the vault it joins.

## 3. Config

```json
{"data_dir": "/…/Library/Application Support/Apassy", "device_name": "Rafał’s iPhone", "role": "app"}
```

- `data_dir`: absolute; the App Group container, so the app and the AutoFill extension see the same vault. The core makes it with mode 0700.
- `device_name`: the name that the relay and the Macs show for this iPhone, and the name in a conflict copy. At most 64 bytes after trimming.
- `request_history_enabled`: defaults to `false`. The native app enables it only after verifying that its local history directory is excluded from backup. Enabled history requires the key-provider constructor.
- `request_history_required`: defaults to `false` for existing callers. The native app always sets it to `true`, including when storage initialization fails. An unavailable journal then blocks answer preparation/delivery instead of bypassing the durable duplicate-answer guard. AutoFill does not enable or require history.
- `role`: `app`, `autofill`, or `watch`. The `autofill` role answers only the calls marked **R** in section 5. Every other call gets `not_allowed`. The extension never syncs and never edits an item. It records a reveal, and it can add a passkey with `passkey_register`. It cannot import, remove, or export (section 5.8). The `watch` role is the Apple Watch app (section 5.13): it answers only the calls listed there, and every other call gets `not_allowed` ("Not available on Apple Watch."). Its default `device_name` is "Apple Watch".

- `connect_url`: the Apassy Connect origin of section 5.14 (relay-sync-v1 section 3: `https://`, or `http://` on loopback). Absent: the hosted Connect, `https://apassy-relay.wyderka.cc`. Tests and a sandbox build name another one. A value that is not an origin fails the config.

Files in `data_dir`:

| File | What it is |
| --- | --- |
| `phone.json` | The vaults on this iPhone (section 6). |
| `vaults/<vault_id>.apassy` | The live vault (SQLCipher), as on the Mac. |
| `sync/<vault_id>.json` and `sync/.*` | The relay sync state and work files, as on the Mac. |
| `feed-seq.json` | The highest feed `seq` accepted of each Mac (section 5.12). No secret. |
| `connect/account.json` | The Apassy Connect account of this iPhone (section 5.14), mode 0600, the account file of the Mac (connect-account-v1): the origin, the account and device ids, the names, the public key, the time. No key, no token, no email, no code, no plan. The app excludes `connect/` from backup: the key is of this device only, so a restored file without it would be useless. |
| `request-history/<vault_id>.json` | Encrypted, device-local request metadata and durable answer intents; excluded from backup and sync. |
| `icloud-transfer/<transaction>/…` | Private encrypted input/output snapshots for one coordinated file transaction. |
| iCloud bookmarks | Private Swift-managed file access records, keyed by vault ID. They contain no passphrase. |

### Local Requests journal (internal 0.5.5 build)

Journal version 2 uses a random per-vault key stored by the native app in non-synchronizing `WhenUnlockedThisDeviceOnly` Keychain storage. It is independent of rotating relay question keys. AEAD binds the journal version, vault ID and local key identifier. The JSON configuration, relay payloads, vault schema and component marketing versions do not change.

Version 1 is migrated atomically when its matching question key remains available. A live old context is migrated before a newly synchronized question key replaces it. If that key was lost before upgrade, `history_migration_blocked` preserves the ciphertext and blocks new answers; it does not discard history. Missing version-2 keys report `history_key_missing`; inaccessible provider/storage reports `history_storage_unavailable`. Other unreadable journals report `history_unavailable`. Clearing unreadable history is refused because it could erase a pending answer guard.

`request_history` gives each vault an `availability`: `available` (with `entries`), `locked` (no questions context: the vault or its questions are not open), `off` (the selected vault is open but has no questions team on this iPhone; added 2026-10-20, before it was reported as `locked`), or `unavailable` (with `error`).

An answer intent is persisted before its POST. An ambiguous network failure retains the intent across restart. Only a fresh attempt rejected with HTTP 429 can release its own intent; a rejected retry cannot erase an earlier ambiguous delivery. Answer POSTs do not automatically retry HTTP 503. Sends for the same vault/request are serialized and revalidate the authorized context after waiting. Existing generic relay retries are unchanged.

The earlier Requests beta cannot read version-2 history, so downgrading to that beta does not preserve usable history. This is a local journal-format change, not a vault or wire-format change. Removing a vault removes its journal; the get/create-only provider intentionally retains its unreferenced device-local key. Removal is not a claim of cryptographic erasure. Face ID, production APNs and real device upgrade/Keychain behavior require physical-device acceptance separately from synthetic tests.

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
| `waits_for_device` | A vault store of Apassy Connect: the current copy was saved by a device that left the account after this iPhone's last sync; the iPhone waits until another device of the account syncs (connect-account-v1 section 7.5). Nothing was changed. `sync` answers the status with the state `waits_for_device` and this message (section 5.5): a plain state, not an error; the next sync after the relay changes goes on. |
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

`Join`: `{"state": "waiting" | "ready", "team": "Personal", "words": ["amber", "marble"], "expires_at": 1791200600, "node": {"origin": "https://100.64.0.7:8444", "name": "Mac mini", "node_words": "noodle monkey dinner sled guitar garden"}}`. `words` are the two safety words; the Mac shows the same words for this iPhone.

**A link of a node** (added 2026-11-03, plan S2–S3 units N3 and N6; [node-pairing-v1](node-pairing-v1.md)). A Mac whose vault is on its own node (the relay inside the Mac app, on the tailnet), or on a Linux node, makes the device link `<node origin>/link#<code>&pin=<pin>[&alt=<hosts>][&name=<name>]`. `join_start` takes it as any link:

- The core parses the whole link with the grammar of node-pairing-v1 section 5. A refusal makes no request and is `link_invalid` with the one text "This code isn't valid. Make a new code on the node." A node pairing link (`/pair#`, for a Mac) is refused the same way; the app tells the owner to use the Mac's "Add an iPhone or a Mac…" code instead.
- With `pin`, every connection of the join, of the sync of the vault, and of its questions team goes to the origin and then to each `alt` in order, over TLS 1.3, and accepts only the leaf certificate with that pin (node-pairing-v1 section 4). Another certificate is `pin_mismatch` ("This node's certificate changed. Pair again.") before any request byte, and no other destination is tried. A node that does not answer is `relay_unreachable`: the app says "Turn on Tailscale on this iPhone to reach <Mac>, then try again."
- `node` is present only for a pinned link: `origin` is the node origin (the stored and signed value, `https://<Tailscale IPv4>:<port>`), `name` the decoded `name` of the link, when it has one, and `node_words` the six node words of the pin ([node-pairing-v1](node-pairing-v1.md) section 4a: `WORDS[pin[0]]` to `WORDS[pin[5]]`, joined with spaces), the same words that the Mac shows for its node, for a visual check only. The name is a label for "via your Mac", never an authority: the safety words and the owner's confirmation are.
- The pin, the alternatives, and the name never reach a server; the handoff (ADR 0032) is stripped as before.
- `join_finish` stores the trust with the vault: `Vault.pin`, `Vault.alt`, and `Vault.node_name` in `phone.json` (section 6), and the pin and the alternatives in the relay membership of the vault (vault schema 28). Only a new pairing of that team replaces them.

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

### 5.3a Duplicates

Added 2026-11-03. Imports (Credential Exchange on the iPhone, 1Password on the Mac) and sync conflicts leave duplicate items. The rules are the vault's (`src/vault/dedup.rs`), the same as Settings > Vault > "Find duplicates…" on the Mac. Both calls need the unlocked vault (`locked`). A core older than this section answers each call with `invalid_input` ("This call is not known.").

| Op | Role | Parameters | Result |
| --- | --- | --- | --- |
| `duplicates` | app | | `{"groups": [Group]}`. Every group of duplicates among the items that are not archived. `[]` when there is none. |
| `duplicates_merge` | app | `keep` (an item ID), `keep_revision`, `others`: `[{"id": n, "revision": n}]` (at least one) | `{"id": n, "revision": n, "archived": [ids]}`: the kept item with its new revision, and the archived items in the order of `others`. |

The `autofill` and `watch` roles get `not_allowed` for both calls.

`Group`:

```json
{"items": [{"id": 12, "title": "GitHub", "kind": "login", "revision": 3, "has_passkey": false, "changed_at": 1791200000},
           {"id": 31, "title": "GitHub (1Password)", "kind": "login", "revision": 1, "has_passkey": false, "changed_at": null}],
 "keep": 12, "differences": ["Password", "Notes"], "identical": false, "mergeable": true, "reason": null,
 "keep_choices": [12, 31]}
```

- Which items are duplicates. Two items that are not archived are duplicates when both are logins with a shared host and the same username, or when both have the same kind, other than login (API key, SSH key, database, or custom), and the same secret values. Logins never match by their secrets: one password on two sites or for two usernames is password reuse, not one account. The hosts of a login are its website details and the RP ID of its passkey, in lowercase, without the scheme, the port, the path, and a leading `www.`. The username is trimmed and compared without regard to case. A login without a host or without a username is never a duplicate. The secret values are the set of (field name, value) of the secret fields with a value; the core compares SHA-256 digests in memory and never answers them. Items without a secret value are never duplicates by this rule. A group holds each item that a chain of matches reaches. Items in different shared vaults, and read-only mirrors, never group.
- `items`: in ID order. `kind` uses the strings of `Row`. `has_passkey`: the item holds a passkey. `changed_at`: the newest change in its history (Unix seconds), null when its history has none.
- `keep`: the suggested item to keep: the item with the canonical passkey (section 11); else the item that agents use (a variable, a declaration, a process grant, a rule, or a connector); else the most recently changed; the lowest ID on a tie. When an item holds a passkey, the app offers only that item to keep.
- `keep_choices`: the items that the group can merge into, in ID order (added 2026-11-03; read it as optional). The app offers these in its picker; `keep` is one of them when `mergeable`. `[]` when no item can be kept, and then `reason` says why.
- `differences`: the labels (the `label` of a `Field`) of the fields whose values differ between the items, then "Notes", "Tags", and "Title" when those differ. Labels only, never a value.
- `identical`: no difference but the titles. An app action "Merge all identical" merges each group that is `identical` and `mergeable`.
- `mergeable` and `reason`: whether the group merges into `keep`; else a short reason: "Two different passkeys", "Keep the item with the passkey", "The passkey is on another item", "Used by agents", or "Too many fields". The app shows the reason and no merge button.

`duplicates_merge` merges in one transaction. The IDs must be items of one current group (a part of a group is fine); the merged item syncs as an edit, and the archived items as archives.

- The kept item keeps its title, kind, folder, fields, values, passkey, and agent settings. A field of another item that it lacks is added with its name and secret flag (a second main secret of a custom item becomes a detail). A field with another value stays, and the other value is added as the custom detail "Previous <label>" (a built-in label in lowercase, for example "Previous password"; a custom detail label as it is, for example "Previous Org ID"; at most 31 bytes, " 2", " 3" for more), with the same secret flag. Equal values are not repeated. Website details are joined without repeats.
- Notes are joined (each distinct note once, a blank line between them); tags are joined.
- Passkeys: when an item holds a passkey, `keep` must be the item with the canonical passkey, and each other item may hold only the same credential (a conflict copy). No passkey field is copied.
- Agent settings: a process grant, an API rule, or a connector of another item, a declaration of another item that differs from the declaration of the kept item, or a variable of another item when the kept item has one (or two other items have one) refuses the merge. One variable of another item moves to a kept item without one only when nothing that an agent of the kept item gets changes: the kept item has no process grant, rule, or connector, it delivers the bound field today (the stored or the automatic field of its variable), and that field keeps the value of the other item. Else the merge is refused. "Always ask me" and the agent exceptions "never" and "always ask" of the other items also apply to the kept item.
- Each other item is archived (`archive` with `archived: false` brings it back), never deleted. In `history`, the kept item gets one event of kind `edited` and each archived item one event of kind `archived`. No event names a value.

Errors (nothing changes):

| Code | When |
| --- | --- |
| `conflict` | A revision is not current. Call `duplicates` again. |
| `not_found` | An ID is not an item. |
| `invalid_input` | No other item, an ID twice, the items are not one current group, or the passkey or agent rules above. The message says which. |
| `too_large` | The merged item would be over a limit of an item: notes over 8 KB, more than 32 tags, more than 10 custom details, more than 64 fields, or more than 1 MB. |

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

- `state`: `off` (a local vault), `never` (no sync since the app started), `ok`, `offline`, `needs_passphrase`, `removed`, `damaged`, `stale_copy`, `forked_copy`, `busy`, `pending` (local edits or publication still need sync), `waits_for_device` (a vault store of Apassy Connect waits until another device of the account syncs, section 4; added 2026-11-11), or `error`.
- The app shows `waits_for_device` as a plain status line with its `message` ("Waiting for another device of this account to sync. Nothing was changed."): no error style, no warning tint, and no step for the owner. Its sync loop goes on (a long poll), and an app of an earlier version reads it as `error`.
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

A passkey is a WebAuthn credential on a login. A new passkey is always ES256 (P-256, SHA-256, COSE -7). An imported passkey can also be ES384 (P-384, COSE -35), EdDSA (Ed25519, COSE -8), or RS256 (RSA of 2048 to 4096 bits, RSASSA-PKCS1-v1_5 with SHA-256, COSE -257); it signs with its own algorithm (vault schema 25). The vault stores it in reserved fields and keeps the key in the encrypted vault. No generic call returns the key. Every byte value on the wire is standard base64 with padding, in canonical form: no white space, no URL alphabet, no unused bits set. A request of a passkey call is at most 4 MiB. An error never quotes an ID, a handle, or a key.

The caller does a fresh owner check before each `passkey_assert`, `passkey_register`, `passkey_import`, `passkey_remove`, and `credential_export`. The core does not check the owner. It sets the flags "user present" and "user verified" in the authenticator data, because the caller did.

| Op | Role | Parameters | Result |
| --- | --- | --- | --- |
| `passkey_list` | app, autofill | `rp_id`; `allowed` (credential IDs, at most 256, default empty = any) | `{"passkeys": [Entry]}`. The canonical passkeys of `rp_id` (section 11). |
| `passkey_assert` | app, autofill | `id` (the item), `rp_id`, `credential_id`, `client_data_hash` (32 bytes); optional `prf`: `{"first", "second" (optional), "hashed": bool (default false)}`; optional `large_blob`: `{"read": true}` or `{"write": <the uncompressed blob>}` | `{"credential_id", "user_handle", "authenticator_data", "signature", "algorithm": -7}`, optional `"prf": {"first", "second"}`, optional `"large_blob"`: `{"data"}` (a read of a stored blob) or `{"written": bool}` (a write). `algorithm` is -7, -35, -8, or -257. The signature is over the authenticator data and the hash: ASN.1 DER ECDSA for -7 and -35, 64 raw bytes for -8, RSASSA-PKCS1-v1_5 for -257. |
| `passkey_register` | app, autofill | `rp_id`; `user_name`; `user_display_name` (default empty); `user_handle` (1 to 64 bytes); `client_data_hash` (32 bytes); `algorithms` (COSE numbers, at most 32, default empty); `excluded` (credential IDs, at most 256); `attach_id` and `attach_revision` (both or neither); `title` (at most 128 bytes) | `{"id": 13, "credential_id", "attestation_object"}`. "none" attestation. |
| `passkey_import` | app | `accounts`: at most 1000 of `{"rp_id", "credential_id", "user_handle", "user_name", "user_display_name", "key", "title"}`, each with optional `"prf": {"with_uv", "without_uv"}`, optional `"large_blob": {"data", "uncompressed_size": n}`, and optional `"attach_id": n`; `key` is a P-256, P-384, Ed25519, or RSA PKCS #8 key in base64, at most 4096 bytes | `{"imported": n, "skipped_existing": n, "failed": n}`. Counts only. |
| `passkey_remove` | app | `id`, `revision` | `{}`. Section 11.3. |

`Entry`: `{"id": 13, "title": "Example", "rp_id": "example.com", "user_name": "…", "user_display_name": "…", "credential_id": "<base64>", "user_handle": "<base64>"}`. It has no key.

Rules:

- `rp_id` is an ASCII host name: at most 253 bytes, letters, digits, `-`, `.`, `_`, no empty label, not starting or ending with `.` or `-`. The core does not check an origin. The caller (iOS, or a browser bridge) checked the origin and gave the relying party ID.
- A credential ID has 1 to 1023 bytes. A user handle has 1 to 64 bytes. A user name or display name has at most 256 bytes, without control characters.
- `passkey_assert`: `not_found` when the item is not an active login, its passkey is not canonical (section 11), its key does not parse, or its RP ID or credential ID differs from the request. The signature counter is always zero. The flags are user present, user verified, and backup eligible. Backup state stays clear.
- `passkey_register`: an empty `algorithms` list means the WebAuthn default, which includes ES256. A non-empty list without -7 gives `unsupported_algorithm`. A credential of `excluded` for this RP ID in the vault gives `excluded`, also when its item is archived. The core makes a 32-byte credential ID. With `attach_id`, the passkey goes on that active login at that revision. A stale revision gives `conflict`. A login that has a passkey gives `exists`. A conflict copy, archived or restored, or an item that is not an active login gives `invalid_input`. Without `attach_id`, the core makes a new login with the title (the RP ID when the title is empty).
- `passkey_import`: each account is a separate step. A credential that is in the vault already (a conflict copy counts) goes to `skipped_existing`. Any other failure, also a bad key, goes to `failed`. Nothing of a failed account is returned or logged. Without `attach_id`, an import makes a new login for the account. With `attach_id`, the passkey goes on that active login at its current revision, as `PasskeyImport.attach`: a login that has a passkey already counts as `skipped_existing`; a conflict copy, an archived item, or an item that is not a login counts as `failed`. A request with more than 1000 accounts gives `invalid_input`.
- The algorithm of an imported key comes from its PKCS #8 `AlgorithmIdentifier`, and the named curve of an EC key. An RSA key is taken as RS256: PKCS #8 does not name the signature scheme, and RS256 is the RSA algorithm of WebAuthn. A P-521 key, an RSA key under 2048 or over 4096 bits, or another algorithm counts as `failed`.
- `prf` of an import: the two 32-byte secrets of Credential Exchange (`credentialWithUV`, `credentialWithoutUV`). Both are needed; another length counts as `failed`.
- `large_blob` of an import: the raw DEFLATE data (RFC 1951) of Credential Exchange, at most 49152 bytes, and its uncompressed size, at most 65536. Data that does not inflate to exactly that size counts as `failed`.
- The `autofill` role cannot call `passkey_import`, `passkey_remove`, or `credential_export`. It gets `not_allowed`.
- The Swift wrapper adds its own checks before the core call (`PasskeyRequestCheck`): a client data hash of 32 bytes, a valid RP ID, a user handle of 1 to 64 bytes, and ES256 in a non-empty algorithm list of a registration.
- WebAuthn extensions of `passkey_assert` (vault schema 25):
  - `prf`: with `hashed: false`, `first` and `second` are WebAuthn inputs of 0 to 1024 bytes (WebAuthn sets no minimum; an empty input is the empty text), and the core makes each salt: SHA-256 of `"WebAuthn PRF"`, a zero byte, and the input. With `hashed: true`, they are hmac-secret salts of exactly 32 bytes. The iOS credential provider gives the WebAuthn inputs, so the app sends `hashed: false`. The output is HMAC-SHA-256 of the salt with the secret with user verification, because the core always sets "user verified". A passkey without PRF secrets (any passkey made by Apassy, or imported without them) gives no `prf` in the result. A bad input gives `invalid_input`.
  - `large_blob`: exactly one of `{"read": true}` and `{"write": <bytes>}`, else `invalid_input`. A read gives `{"data": <the uncompressed blob>}` when the passkey has a blob, and no `large_blob` when it has none or the stored blob does not inflate to its size. A write compresses the blob with raw DEFLATE and stores it on the login: a new revision and a history event without values, as any passkey edit, and the change syncs. It gives `{"written": false}` when the blob is empty, is larger than 65536 bytes, or its compressed base64url is longer than a vault field value (64 KiB), and the stored blob stays. The write is stored before the answer is returned, so a caller that drops the answer still leaves the blob stored. The `autofill` role may write a blob, only as part of `passkey_assert`.
  - A registration that requires large blob storage still fails with `unsupportedExtension` in the wrapper: a new passkey has no blob and no PRF secrets.

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
             "user_name": "…", "user_display_name": "…", "key": "<base64 PKCS #8>",
             "algorithm": -7,
             "prf": {"with_uv": "<base64, 32 bytes>", "without_uv": "<base64, 32 bytes>"},
             "large_blob": {"data": "<base64 of the raw DEFLATE data>", "uncompressed_size": 120}}}
```

- Scope: the active logins that are not conflict copies, and each restored conflict copy whose passkey is canonical (section 11). A restored copy goes once, as a whole login. Items of other kinds, and logins with no username, password, code, or passkey, add to `skipped`. An archived item and any other conflict copy are not counted.
- `totp`: the first one-time password field of the item that Apassy reads as TOTP. A counter-based (HOTP) or unreadable value is not exported. `algorithm` is `sha1`, `sha256`, or `sha512`. A period or digit count that does not fit 16 bits is not exported. `issuer` and `user` come from the label and the `issuer` parameter of an `otpauth://totp` URI. A bare Base32 secret has neither.
- `passkey`: only a canonical, parsable passkey. A stored key that does not parse is left out and the other data of the login still goes. A failure of the vault is an error: an export never drops data in silence. `key` is the normalized PKCS #8 form of its algorithm (section 11.1), and `algorithm` its COSE number. `prf` and `large_blob` are there only when the passkey has them; the blob is the stored compressed form, as Credential Exchange takes it.
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
| `push_token_set` | `token` (lowercase hex, 32 to 200), `environment` (`development` or `production`), `bundle_id`? (default `com.wydrox.apassy.companion`; the watch: `com.wydrox.apassy.companion.watchkitapp`), `gateway`? (the origin of the push gateway of the node teams, default `https://push.apassy.wyderka.cc`) | `{"device_id": n, "updated_at": n, "vaults": [PushVault]}` |
| `push_token_clear` | | `{"cleared": ["<vault_id>"], "pending": ["<vault_id>"]}` |
| `push_summary_keys` | | `{"keys": [{"team_id": "…", "key": "<b64u 32 bytes>"}]}` |
| `join_attach` | `link`, `device_name`?, `answer_key` (b64u X9.63, required) | `{"state": "waiting", "team": "…", "words": [w1, w2], "expires_at": n}` |
| `join_attach_poll` | | the same, `state` `waiting` or `attached` |
| `join_attach_cancel` | | `{}` |

`Status`: `{"enabled": bool, "team_id": "…"|null, "relay_device_id": n|null, "device_uuid": "…"|null, "answer_key": "<b64u>"|null, "has_key": bool, "registered": bool, "removed": bool, "relay_ended": true, "node": {"origin": "…", "node_words": "…"}}`. `relay_ended` (added 2026-11-11, plan s7 unit I3; absent otherwise) is described under "The end of the free hosted paths" below. `node` (added 2026-11-03, plan S2–S3 unit N6) is present only when the questions team is on a node: its membership has a pin (node-pairing-v1). `origin` is the node origin; `node_words` (added 2026-11-03) is the six node words of the stored pin ([node-pairing-v1](node-pairing-v1.md) section 4a), a visual check against the Mac, absent when the stored pin text is not a canonical pin; the app shows "via your Mac", and the node's name from the `node_name` of a vault entry with that origin and a pin (section 6). A hosted team has no `node`; an older app ignores it. `registered` is true when the row of this iPhone is in the vault. `removed` is true when the key of the membership belongs to a removed row: then the list has no question of that vault and the core does not ask the relay for it. Without a questions team `enabled` is false; when no vault has a context, the list is empty and `questions_wait` answers `changed: false` at once. When every context is of a removed iPhone, `questions_wait` asks the relay nothing but waits out its `timeout` before `changed: false` (a lock ends it with `locked`), so an app that waits again never spins.

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

Errors of these calls, besides those of section 4: `pin_mismatch` (a node presented another certificate than its pin; nothing was sent: pair again), `push_gateway_unreachable` (`push_token_set` for a node team: the push gateway did not answer `POST /v1/handles`; the core tries again at the next relay call of the vault), `push_gateway_refused` (`409` on `PUT /v1/push/handle`: the node does not use the gateway that this iPhone named), `no_questions` (the vault has no questions team), `not_registered` (no row, no answer key, or the signature does not verify with it), `removed` (the row of this iPhone is removed), `answer_key_changed` (the row holds another answer key), `unreadable` (the card failed a check; the message is the `problem`), `already_answered` (`409 question_settled`), `expired` (`409 question_expired`, `404`, or past `expires_at`), `not_routed`, `too_many_answers` (the relay allows 3 answers of a device for a question, 20 for a question, and a byte budget for the team), `stale_answer`, `push_unavailable` (`409` on `PUT /v1/push/token`), `wrong_vault` (the `vault_id` of an answer is not the vault of its question), `locked` (the `vault_id` names a vault that has no context: unlock it first), `relay_ended` (below).

**The end of the free hosted paths** (added 2026-11-11, plan s7 unit I3; [plan s7](../design/implementation-plan-s7-connect.md) section 5, R3; `docs/operations/connect.md`). After the cutover the hosted relay answers the questions, the feed, the actions, and the push of a free team with `410 free_connect_ended`, and every route of a retired relay (also the sign-in) with `410 hosted_retired`. Either answer, to any call of a team (questions, `feed_*`, `push_token_set`, `push_token_clear`, the push change before a read), ends that team for the rest of the process: the core notes its relay origin and team ID (no secret; kept across `lock` and `suspend`, not on disk, so the next launch makes one call again) and sends it nothing more, with no retry and no backoff.
- The state: `Status.relay_ended: true` and `QuestionsVault.error: "relay_ended"` for its context, also after a lock and an unlock. It is no failure of `questions_list` or `questions_wait`: they answer as for the other contexts, and a long poll of a list whose every context is removed or ended waits out its `timeout` (as for a removed iPhone), so an app that waits again never spins. The feed of the team says the same (`relay_ended: true` and `error: "relay_ended"` in its vault of `feed_list`, section 5.12), and `feed_wait` waits out its `timeout` too.
- `push_token_set` skips an ended team; with no other team it fails with `relay_ended`. `push_token_clear` counts an ended team as cleared (it pushes nothing) without a call.
- A question or an action that was shown before the end (`question_answer`, `feed_action`) makes its one call and fails with `relay_ended`. Another `410` code is no end (`internal`, as before).
- A sync call that gets either answer (a join, a sign-in, a vault sync) fails with `relay_ended` too, with the message "This relay has ended this service. Pair this iPhone again from Apassy on your Mac." It sets no state: the next call asks the relay again.
- The app shows one calm state in the place of "Questions" in Settings > Devices: "Ended", and "Approvals through apassy-relay.wyderka.cc have ended. Pair this iPhone again from Apassy on your Mac." No price, no link, nothing to buy (plan s7 section 6). The iPhone pairs again from the Mac (its migration of approvals); the core changes nothing in the vault.

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
- **A team on a node** (added 2026-11-03, plan S2–S3 units N5 and N6; [push-gateway-v1](push-gateway-v1.md) sections 6, 10, and 11). The token never goes to a node. For a questions team on a relay other than the hosted one, `push_token_set` exchanges the token at the push gateway (`POST <gateway>/v1/handles` with the token, the environment, the bundle ID, and the kind `iphone`, or `watch` for the watch core) for a **handle** and a secret, and gives the team `PUT /v1/push/handle {v: 1, gateway, handle, secret}`. The hosted relay keeps `PUT /v1/push/token` (the watch gets `push_unavailable` there). A relay without the handle route (`404`, a relay before team schema 8) gets the iPhone's token instead, unless its origin is pinned: a pinned origin is a node and never gets a token. A loopback `http://` relay (tests) keeps the token unless the app names a `gateway`. A handle that still serves the same team, relay, gateway, and token (the core keeps a digest of the token, not the token) and has more than 30 days left is reused; else the core makes a new one and keeps it before the relay call, so a failed call reuses it. `gateway` must be an origin (`https://` and a host, an optional port, no path): else `invalid_input`. The `PushVault.error` of a node team can be `push_gateway_unreachable`, `push_gateway_refused`, or `push_unavailable` (the gateway does not serve this app, or the relay has no gateway).
- `push_token_clear` removes the token from the team of every context (`DELETE /v1/push/handle` for a team on a node, `DELETE /v1/push/token` else) and forgets the handle. A team that failed, and each other vault on this iPhone, goes into `questions-push.json` in the data folder (`{"version": 1, "clear": ["<vault_id>"], "handles": {"<vault_id>": Handle}}`, written as `phone.json` is): when that vault opens, the core clears the token there at its first relay call and drops it from the file. `pending` lists those vaults. `push_token_set` empties `clear`.
- `handles` (added 2026-11-03, optional; absent when empty, and an older app ignores it) keeps the push handle of each vault whose team is on a node: `{"team_id", "relay_url", "gateway", "handle", "secret", "expires_at", "token_digest"}`. It holds no token: `token_digest` is a SHA-256 of the environment and the token, to see whether the handle still serves the token of this launch. The file is the app's and the watch's (each its own data folder); the AutoFill extension writes none. An entry that is not valid, or more than the core keeps, is dropped at load.
- `push_summary_keys` (added 2026-11-03, push-gateway-v1 section 12) returns the summary key of the questions team of each context that holds a question key and is not of a removed device: `summary_key = HKDF-SHA256(salt = empty, ikm = question key, info = "apassy-push-summary-v1")`, b64u, by `team_id`, sorted, at most 16. The app writes each into the Keychain group of its Notification Service Extension when a vault unlocks, and deletes it when the team is left or notifications go off; the extension opens the sealed summary of a push with it, and on any failure shows the fixed text. The key opens summaries only, never a card. The watch core answers it for its one team.
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
| `feed_action_string` | `vault_id`, `mac_device`, `agent`, `item`, `kind`, `created_at`, `feed_seq`, `action_id`?, `time`? | `Prepared` |
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
      "problem": null, "can_act": true, "checks_names": true, "week": {"by_you": 3, "automatic": 128},
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

- One `FeedVault` for each context, in the order of `vault_id`. `registered`: the vault holds the row of this iPhone (it can send actions). `answer_key`: that row has an answer key (it can send the Face ID kinds; else the app says "Connect this iPhone again on a Mac to use Face ID here." for `never` and `always_ask`). `error` is the code of the last relay call of that vault that failed, until one works: `feed_unavailable` for a relay without feeds (relay-feed-v1 section 14.2), `relay_unreachable`, `removed`, and the others of section 4. The call fails only when every vault failed. `relay_ended: true` (added 2026-11-11; absent otherwise), with `error: "relay_ended"`: the hosted relay ended the free paths of that team (section 5.10, "The end of the free hosted paths"): no feed call goes to it again in this process, and it is no failure of the call. A removed iPhone (`status.removed` of section 5.10) gets no Mac of that vault.
- A Mac is listed when its last feed passed every check of relay-feed-v1 section 7.4: the envelope opens with the question key of its `key_id` and the AAD of the relay's `device_id` and `seq`; the JSON has exactly the fields of section 7.1 within the limits, `v` 1 or 2 (relay-feed-v1 section 7.5), and the relay's `seq`; `mac.device` is a live `trusted_device` of kind `mac` whose device number in the team (`relay_devices`) on this iPhone's copy of the vault is the relay's `device_id` (a Mac whose number has not synced here yet publishes nothing: its feed is ignored, with no text); and `seq` is above the highest `seq` this iPhone accepted of that relay device. A feed that fails step 4 or 5 is ignored with no text. A Mac removed from the vault leaves at once, and a Mac that is not in the relay's `present` leaves the list.
- `name` is the name of the Mac's `trusted_device` row. `relay_device_id` is its device number in the team, the target of an action.
- Feed v2 (relay-feed-v1 section 7.5, added 2026-11-03): each Mac also has `remote_access` (`off`, `on`, `problem`; null for a feed of v1 and for a Mac without a feed); its `week` also has `days` (7 objects `{"runs", "asked"}`, today first; empty for v1) and `answer_p50_secs` (seconds or null); each agent also has `connected_at` (null unless `where` is `remote`) and `days` (7 objects `{"runs", "asked", "not_allowed"}`; empty for v1). `where` is `mac` or, in v2, `remote`. The app shows "—" for a tile whose data is empty.
- `problem` is the text of the step that the last feed of this Mac failed: "Sync this vault to see the agents of <Mac>." (step 1: another key, or it does not open) or "Update Apassy to see the agents of <Mac>." (steps 2 and 3). The last good feed stays with it. When no feed of the Mac opened in this session, the Mac is listed with `seq`, `generated_at`, and `week` null and no agent. Such a Mac is listed only when a live trusted Mac row has that device number.
- `can_act` is whether this iPhone can act on this feed. It is true for the selected, unlocked vault (its keys and devices are read again at each call), and for another vault when its keys were read (its last `questions_unlock`, or while it was selected) after this feed came. A vault that is not selected holds a copy of its `trusted_devices` from then: a later feed may come from a Mac removed from the vault since, so it is listed with `can_act: false`, `feed_action_string` refuses it (`invalid_input`), and the app says "Select <vault> on this iPhone to remove exceptions of its agents." The core cannot read such a vault again without its passphrase. Problem-only Macs have `can_act: false`.
- `stale` is true when `generated_at` is more than 24 hours old on the iPhone's clock: the app dims the Mac ("The Mac has not reported since <date>") and offers no action. A `generated_at` in the future is not stale; the app shows it as "now".
- The members of an agent are those of the feed (relay-feed-v1 section 7.1), every text with control and format characters replaced by `?`. For each exception and recent use, `item` and `item_title` are the feed's; `title` is the title of the item with that UUID in the vault on this iPhone, else null; `here` is whether the vault on this iPhone holds it (false for a null `item`; null when the items of the vault were not read in this session). The app shows `title`, else `item_title` with "not on this iPhone", and "A deleted credential" for a null `item` (with no action).
- After an applied removal (`feed_action_wait` with `outcome: applied` and `verified: true`), the exception leaves the list at once (in the feed of that Mac shown then, which may be newer than the one the action named), until the next feed of that Mac.
- An item reference is the vault's own form of an item UUID, 32 lowercase hex characters with no hyphens, as `item.uuid` holds it (`Vault::item_uuids`; relay-feed-v1 section 4). It is the only form: a feed with another form (a hyphenated or upper-case UUID) fails step 2 ("Update Apassy to see the agents of <Mac>."), `feed_action_string` and `feed_action` refuse it (`invalid_input`), and the core compares it byte for byte, never reformatted. An item of the vault on this iPhone whose stored UUID has another form has no `title` in the list.

**The high-water mark.** The core keeps the highest `seq` accepted of each Mac, by team and relay device id, in `feed-seq.json` in the data folder (`{"version": 1, "teams": {"t_7k2m5q4x3c": {"2": 1790000040}}}`, written as `phone.json` is). It holds no secret and stays after a lock and a restart, so a relay cannot bring back an older feed. A feed with a lower `seq` is ignored; a feed with the same `seq` shows only when this process does not show that Mac (after a lock or a restart: the AAD binds the `seq`, so it is the same feed).

**The Macs that check the names** (added 2026-10-14, relay-feed-v1 section 7.1). A feed whose plaintext ends in one line feed after the JSON object is of a Mac that checks the names of an action: `checks_names` of the Mac in `feed_list` says whether its last feed did. It is a hint for the screen only: the core keeps no memory of it and signs the names for every Mac. A Mac with `checks_names: false` runs an older Apassy (0.5.2), which refuses every action of this iPhone: the app offers no removal of `never` or `always_ask` there and says "Update Apassy on <Mac> to remove this from the iPhone."; an `only` removal may still go, and the Mac's answer `refused` with the reason "it has a bad form" shows the same text. `feed-seq.json` holds the `seq` marks only (a key it does not know, such as `names` of an earlier build, is ignored).

**`feed_wait {timeout}`** runs one long poll of `GET /v1/feed` for each context at the same time and returns as soon as one brings news (a new feed, a removed one, a new problem); that ends the others. `changed: false` after the timeout. A `lock` or a `suspend` ends them all with `locked`. The app calls it only while the Agents tab or an agent page is on the screen, and `feed_list` after `changed: true`.

**`feed_action_string`** builds the action string of relay-feed-v1 section 9.3 for the exception that the feed shows:

```json
{"op": "feed_action_string", "vault_id": "4f1c0a2b-…", "mac_device": "0b7e5c3a-9d1f-4a2b-8c6d-4e0f1a2b3c4d",
 "agent": "4", "item": "3c9e1f7a2b4d4c6e8f0a1b3d5e7f9a2c", "kind": "never", "created_at": 1789990000,
 "feed_seq": 1790000040}
```

```json
{"vault_id": "4f1c0a2b-…", "team_id": "t_7k2m5q4x3c", "action_id": "sLGys7S1tre4ubq7vL2-vw",
 "time": 1790000060, "feed_seq": 1790000040,
 "action_string": "apassy-feed-action-v2\n6f1c0e2a-…\n0b7e5c3a-…\nt_7k2m5q4x3c\nsLGys7S1tre4ubq7vL2-vw\nremove_exception:4:3c9e1f7a2b4d4c6e8f0a1b3d5e7f9a2c:never:1789990000\n1790000040\n1790000060\nnames:8ef3d412…",
 "needs_face_id": true, "face_id_reason": "remove an exception of agent \"Claude Code\"",
 "agent_name": "Claude Code", "credential_name": "Shop database", "mac_name": "MacBook Pro"}
```

- `mac_device` is the `device` of the Mac in `feed_list`; `agent`, `item`, `kind`, and `created_at` are those of the exception in the list. `kind` is `never`, `always_ask`, or `only`. The core finds the exception in the last good feed of that Mac (it reads the relay once when it has none): an exception, an agent, or a Mac that is not there is `not_found` ("This list of the Mac changed. Look at it again."); a disconnected agent is `invalid_input`. The string has the device UUID of this iPhone's row (`by`), the Mac's UUID (`to`), the team, the `action_id`, the exception, the `seq` of that feed (`feed_seq`), and `time`.
- **The names (v2).** The string is always of v2, for every kind and every Mac: the first line is `apassy-feed-action-v2` and a ninth line `names:<64 lowercase hex>` follows, the SHA-256 of the three names that `feed_list` shows for this exception, joined with one zero byte: the agent's `name`; the credential, which is `title` when it is not null or empty, else `item_title`; and the Mac's `name`. These are the values of `feed_list` as they are (control and format characters already `?`), without the words the app puts around them ("not on this iPhone", "A credential"). The answer returns them as `agent_name`, `credential_name`, and `mac_name`. The Mac rebuilds the names from its own rows and settles an action with other names `stale` (relay-feed-v1 section 9.5 steps 8a and 10), so a feed with false names on real ids does not count. The digest binds the labels to the Mac's rows as they are then: a holder of the vault who renames the item or the agent through sync can still mislead, because the vault is the trust root.
- **The list that the owner confirmed.** `feed_seq` is the `seq` of the Mac in the `feed_list` whose list the confirmation showed. When the core shows another feed of that Mac now (one landed while the confirmation was up: a relay can swap one in), or `feed_seq` is missing, the answer is `not_found` ("The list on <Mac> changed. Look at it again."). The app keeps one snapshot of the exception, the agent, the Mac's name, and the `seq` when the owner taps "Remove", builds the confirmation from it only, sends its `feed_seq`, and sends nothing when `agent_name`, `credential_name`, or `mac_name` is not, byte for byte, the name its confirmation showed (the same text).
- `action_id` is 16 random bytes of the core, b64u (22 characters), unless the request gives one (a retry); `time` is now unless the request gives one. The app keeps both for `feed_action`.
- The core keeps the prepared action by `action_id` in the context of the vault (the string, its `feed_seq`, the target, and the answer key of the row then; at most 64; a `lock` drops them). The same `action_id` and `time` for the same exception answer the kept string again.
- A Mac with `can_act: false` is refused (`invalid_input`, "Select this vault on this iPhone to act on the agents of its Macs.").
- `needs_face_id` is true for `never` and `always_ask`: the app signs `action_string` with the Secure Enclave answer key **of the team `team_id`** after Face ID for this action (a new `LAContext`, no reuse), with `face_id_reason` as the prompt (the agent name with control and format characters replaced by `?` as in the list, without `"`, at most 40 characters). For `only` it is false: the core signs with the relay key of the membership, and the app asks nothing.
- The core does not check the age of the feed here; `feed_action` does.
- Errors: `removed` and `not_registered` as in section 5.10 (no row of this iPhone); `not_registered` with "Connect this iPhone again on a Mac to use Face ID here." for a Face ID kind when the row has no answer key.

**`feed_action`** takes the same parameters with the `action_id` and `time` of `feed_action_string`, and for a Face ID kind the DER `signature` as b64u:

```json
{"op": "feed_action", "vault_id": "4f1c0a2b-…", "mac_device": "0b7e5c3a-…", "agent": "4",
 "item": "3c9e1f7a…", "kind": "never", "created_at": 1789990000, "feed_seq": 1790000040,
 "action_id": "sLGys7S1tre4ubq7vL2-vw", "time": 1790000060, "signature": "MEUCIQ…"}
```

```json
{"action_id": "sLGys7S1tre4ubq7vL2-vw", "seq": 9, "created_at": 1790000060, "expires_at": 1790000360}
```

- The core sends the action that `feed_action_string` kept for this `action_id`, with its exact string and its `feed_seq`: a newer feed of the Mac that came during Face ID changes nothing (the Mac takes any `feed_seq` up to its last one, relay-feed-v1 section 9.5). An `action_id` it did not prepare (another session, after a lock) is `stale_action`; parameters other than the prepared ones (`feed_seq` included) are `invalid_input`. `time` more than 55 s old is `stale_action` (do it again, with Face ID again); more than 60 s ahead is `invalid_input`.
- It reads the relay once (no long poll; a failure keeps what it holds) and checks the newest feed of that Mac: the Mac is still a publisher of the vault, the agent is not disconnected (`invalid_input`), and the exception is still there and not hidden by an applied removal; else `not_found`, "The list on <Mac> changed. Try again.". A stale newest feed (24 hours) is `stale_feed`.
- For `never` and `always_ask`, `signature` must verify with the answer key of this iPhone's row over the kept string: `invalid_input` without it or when it does not verify with an unchanged key ("Face ID did not sign this action, so nothing was sent. Try again."); `not_registered` only for a real change: the row has no answer key now, or another one than when the string was made. For `only`, `signature` must be absent (`invalid_input`); the core signs with the relay key, which must be the row's `sign_key`.
- The core seals the plaintext of relay-feed-v1 section 9.2 (fields in the contract's order; `v` 2 with `names` before `signature`) with the question key, a new random nonce, and the AAD `action` with this iPhone's device number as the sender and the Mac's `relay_device_id` as the target, and posts `POST /v1/feed/actions`. A retry after a network error sends the same `action_id`, `time`, and `signature` in a new envelope; a relay that has the action already answers `409 conflict`, and the core answers with `seq`, `created_at`, and `expires_at` null.
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

### 5.13 The Apple Watch (role `watch`, ADR 0039)

Added 2026-11-03. The watch answers ADR 0033 access requests with **Allow once** or **Deny**, and nothing else. It holds one questions-only replica vault: no item, the sync identity of the vault it answers for, its own questions membership, the question key, and the public `trusted_device` rows of the handoff. The replica never syncs, so its rows change only with a new connection. The watch never shows or answers a run question or a feed action, and the core never journals a run question on it.

**The calls of the role.** `info`, `select`, `unlock` (with `keep`), `lock`, `suspend`, `resume`, `access_requests_list`, `access_requests_history`, `access_request_prepare`, `access_request_answer`, `access_request_cancel_prepared` (section 12, "ADR 0033 typed access requests"), `questions_wait` (section 5.10: the long poll while the app is active; it wakes for any change of the team, then the app calls `access_requests_list`), and the calls below. Every other call gets `not_allowed` ("Not available on Apple Watch."). The `app` and `autofill` roles get `not_allowed` ("This call is for Apple Watch only.") for the calls below.

**Config.** The watch app starts the core with `apassy_core_new_with_history_key_provider` (its keys in the watch keychain), `"role": "watch"`, `request_guard_storage_ready: true` after it made `request-history/` and excluded it from backup, and `request_history_enabled: true` for the access history. It installs the transport of section 2.1 first.

**The own row.** On a watch the row of this device must have the kind `watch`; in the `app` role it must have the kind `iphone`. A row of another kind gives `answer_key_changed` in every call that reads it (the access calls, and in the app role also the run-question and feed calls and `answer_key_register`).

**`watch_connect_start`** `{"link": "<the Mac's Connect code, as the iPhone forwarded it>", "name": "Rafał’s Watch", "answer_key": "<b64u X9.63, 65 bytes>", "passphrase": "<32 random bytes of the app, as text>"}` answers:

```json
{"state": "waiting", "words": ["six", "safety", "words", "for", "the", "Mac"], "expires_at": 1790000600}
```

- Only a handoff link (`&handoff=`, relay-questions-v1 section 21) connects a watch. A link without it gives `link_invalid` ("This code can't connect a watch. Make a new code on the Mac."), a damaged one `link_invalid` ("This pairing code is damaged. Make a new code on the Mac.").
- `name` is optional (default: `device_name`). The relay device name is `<name> ~W<answer key>` (`device_link::watch_link_device_name`): the name is cut to 17 bytes.
- The relay key is a new one. The passphrase (at least 12 bytes, `MIN_PASSPHRASE_BYTES`) stays in an erasing buffer of the core only until the poll that makes the vault.
- A watch that holds a replica gives `already_connected`: forget it first. A new start gives up the connection that waits.
- Errors: `invalid_input` (the passphrase, the answer key), `link_invalid`, `relay_unreachable`, `rate_limited`, `safety_mismatch`, `already_connected`.

**`watch_connect_poll`** answers `{"state": "waiting", "words": […], "expires_at": …}` while the Mac has not confirmed or not sent the handoff, then once:

```json
{"state": "attached", "vault": {"id": "d070dc14-a3ac-42c2-95aa-cc85d6d58900", "name": "MacBook Pro"}}
```

- When the handoff comes, the core makes a new vault file with the passphrase, gives it the handoff `vault_id` as its sync identity (`Vault::adopt_replica_identity`), adopts the handoff with the membership and the answer key, registers the vault (no `relay_url`), and keeps it selected and unlocked with its questions context.
- The handoff must hold the row of this watch (its relay key) with this answer key and the kind `watch`. A row without an answer key gives `mac_update_needed` ("Update Apassy on your Mac to connect this watch."); another kind or another key gives `answer_key_changed`.
- The vault is named after the first live Mac row of the handoff, else "Vault".
- On any failure no file or list entry of the replica stays, and the device leaves the team again.
- Errors: `invalid_input` (no connection waits), `link_invalid` (expired), `join_refused`, `relay_unreachable` (the Mac has not sent the keys yet and the read failed), `mac_update_needed`, `answer_key_changed`, `already_connected`, `io`, `storage`.
- A `lock` or a `suspend` gives up a connection that waits.

**`watch_connect_cancel`** gives up the connection that waits, best effort on the relay. `{}`.

**`watch_status`** `{"answer_key": "<b64u, optional>"}`, without a relay call:

```json
{"state": "ready", "vault": {"id": "…", "name": "MacBook Pro"}, "macs": ["MacBook Pro"], "own": {"found": true, "answer_key_matches": true}}
```

- `state`: `unpaired` (no replica), `connecting` (a connection waits), `locked`, `ready`, or `removed`. `removed`: the row of this watch is removed, its relay key is removed, the last relay call found the device removed (`removed`), or the open replica has no questions team. The app then offers to forget and connect again.
- `vault` is null while `unpaired` or `connecting`. `macs` (the names of the live Mac rows) and `own` are filled only while the replica is open; else `[]` and null.
- `own.found`: the replica holds the row of this watch. `own.answer_key_matches`: that row has the kind `watch` and an answer key other than its relay key, and it is `answer_key` when the call gives one.

**`watch_forget`** leaves the team (best effort, with the relay key of an open replica: unlock first), then deletes the replica file, its list entry, its access guards (`request-history/access-guards-v1-<vault_id>.json`), and its history. Answers `{"state": "unpaired", "vault": null, "macs": [], "own": null}`. The app deletes its history key of that vault and the passphrase from the watch keychain.

New error codes: `already_connected`, `mac_update_needed`. `answer_key_changed` has a watch message.

### 5.14 Apassy Connect: this iPhone as a device of an account (plan s7 unit I1)

Added 2026-11-10. The iPhone **joins** the Apassy Connect account of a Mac and shows the plan of that account. It never creates an account, never starts a checkout or opens the portal, never reads `GET /v1/plans`, and never collects an email: the account and its plan are managed in Apassy on the Mac ([plan s7](../design/implementation-plan-s7-connect.md) section 6, App Store Review Guideline 3.1; [connect-billing-v1](connect-billing-v1.md) section 10). No answer of these calls holds a price, a currency, or a URL. The calls are of the `app` role only; `autofill` and `watch` get `not_allowed`. The flow and its checks are those of the Mac (`apassy::connect`, connect-account-v1 sections 6 and 7): the link code, the link hash, the `apassy-connect join v1` signature with the account key (section 2.2), the link fingerprint, the signed device list and the pinned root of section 7.5, the six safety words of section 7.3, the challenge with its origin check, and the 15-minute account token in memory. The token never leaves the core; it goes only to the Connect origin of the account, also for the dials of section 5.15.

**`connect_join`** `{"link": "apassy_alk_<account id>_<64 hex>_<32 hex>", "device_name": "Rafał’s iPhone"}`: the code that "Add a device…" shows on the Mac (as text, or the QR code of the same text), trimmed. `device_name` is optional (default: `device_name` of the config). The core makes the account key if it has none, sends `POST /v1/account/devices/join` with `platform: "iphone"`, and answers:

```json
{"state": "waiting", "account_id": "acc_k7m2q4x3ca", "confirmer": "MacBook Pro", "words": ["audio", "coyote", "forest", "mint", "magnet", "apple"], "expires_at": 1790000600}
```

- The app shows "Waiting for MacBook Pro… Both devices show: audio coyote forest mint magnet apple." The Mac shows the same words and confirms with Touch ID.
- A new start gives up the join that waits. An iPhone that is a device of an account already gets `already_connected`, also while its account file is of an earlier version (`join_again` of `connect_status`) until `connect_forget`.
- Errors: `link_invalid` (not a code, Connect refused it: unknown, used, or expired; or Connect named another Mac or another account root than the code: the core cancels that join; nothing is sent for text that is not a code), `already_connected`, `relay_unreachable`, `rate_limited`, `not_allowed` (no key store, or the Keychain is locked).

**`connect_join_poll`** `{}` answers the same object with `"state": "waiting"` until the Mac confirms, then once with `"state": "confirmed"`: the core signed in, wrote `connect/account.json`, and keeps the account. The app asks every 5 s (connect-account-v1 section 7.2).

- Errors: `join_refused` (the Mac refused, or the code expired: the join ends), `invalid_input` (no join waits), `relay_unreachable` and `rate_limited` (the join waits on).

**`connect_join_cancel`** `{}` gives up the join that waits, best effort at Connect (`POST /v1/account/devices/join/cancel`). Answers `{}`.

**`connect_status`** `{}`:

```json
{"state": "account", "account_id": "acc_k7m2q4x3ca", "device_name": "iPhone", "dial_route": false, "dial_state": "unused",
 "plan": {"plan": "family", "status": "active", "entitled": true, "renews_at": 1796299200, "ends_at": null,
          "grace_until": null, "read_only_until": null, "delete_at": null,
          "group": {"kind": "family", "role": "member"}, "people": {"active": 3, "of": 4}},
 "devices": [{"device_id": "dev_m2k7q3x4ab", "name": "MacBook Pro", "platform": "mac", "this": false, "verified": true},
             {"device_id": "dev_p4n6r2t7bc", "name": "iPhone", "platform": "iphone", "this": true, "verified": true}],
 "list_verified": true}
```

- `state`: `none` (no account on this iPhone) or `account`. Without an account: `{"state": "none", "plan": null, "dial_route": false, "dial_state": "unused"}`, with `"join": {…}` while a join waits.
- `plan` is the `PlanView` of connect-billing-v1 section 8 without `interval`, `quantity`, and `group_id`, with `group` (the kind and the role of the account's group, from `GET /v1/account`) and `people` (for an active Family: the active members and `max(quantity, included)` of `GET /v1/account/group`, for "Connect Family · 3 of 4 people"; else null).
- `stale: true` (absent otherwise): Connect did not answer; `plan` is the last answer of this process, or null.
- `devices` (absent when empty, for example when Connect did not answer): the live devices of the account. `verified` is false for a device whose statements do not lead to the root that this iPhone pinned when it joined (connect-account-v1 section 7.5): the app shows "Not verified" for it, and the core never uses it as a device of the account.
- `list_verified` (added 2026-11-11): present only when Connect answered. `true`: the signed device list of the account verified from the root that this iPhone pinned and went on from the pinned version. `false`: it did not verify (an entry that does not lead to the pinned root, or a list that does not go on from the pinned version): no device is verified, and the core keeps the trust store as it was. Absent (null) when Connect did not answer (`stale`), after a removal, and without an account.
- `removed: true` (absent otherwise): Connect answered, to a sign-in that this iPhone signed, that this iPhone is no device of the account any more (a Mac revoked it, or the account was deleted), or the Keychain lost the key. A refused sign-in is never a removal. The core keeps the key and `connect/account.json` and answers `state: account` with `removed: true` until the owner calls `connect_forget`.
- `join_again: true` (absent otherwise; added 2026-11-11): the account file of this iPhone is from an earlier version of Apassy (it holds no pinned device list, connect-account-v1 section 7.5), so this iPhone must join its account again. The answer is `{"state": "account", "join_again": true, "plan": null, "dial_route": false, "dial_state": "…"}` (with `join` while one waits): no account id, no device name, no plan, no devices, no `list_verified`. Connect is not asked. The core deletes nothing: `connect_forget` deletes the file and the key, and then `connect_join` works again. It is a status, never an error.
- `dial_route`: true when the last connection of this process to a node of its vaults went through the Connect dial (section 5.15), since the last `lock` or `suspend`; false while the tailnet reaches the Mac. Settings > Devices shows "Reaches your Mac through: … Apassy Connect …" from it.
- `dial_state`: the state of the dial of section 5.15: `unused`, `connected`, `not_on_connect`, `mac_offline`, `limit`, `unreachable`, or `refused`. A quiet state: the app shows no error and no hint for it. With `not_on_connect` and a stale answer, `plan` is the plan of no Connect (`"status": "none", "entitled": false`), so the row says "Not on Connect".
- Errors: `not_allowed` (no key store, or the Keychain is locked), `relay_unreachable` only when the account file cannot be read meanwhile, `damaged` (an answer of Connect that the core does not accept).

**The row of the app** (Settings > General, "Apassy Connect", text only): "Not on Connect" (`none`, `pending`, `suspended`, an unknown state, or no account); "Connect Personal · renews 3 Dec 2026" (`active` or `trialing`; Team the same); "Connect Family · 3 of 4 people"; "Past due" (`past_due`); "Ends 12 Jan 2027" (`ends_at` of an `active` plan, or `read_only_until`); and, only on an account, "Managed in Apassy on your Mac" as text. With `removed: true` (added 2026-11-11, unit I3): "Removed from the account" and the line "This iPhone is no longer a device of its Apassy Connect account. To join an account again, forget it in Settings > Devices." With `join_again: true` (added 2026-11-11): "Join the account again" and the line "This iPhone must join its Apassy Connect account again: its account file is from an earlier version of Apassy. Forget it in Settings > Devices, then add this iPhone again from your Mac." No button, link, price, currency, comparison, or trial, in any state.

**Settings > Devices** (added 2026-11-11, unit I3), only while `state` is `account` (also with `removed` or `join_again`): the section "Apassy Connect" with the line of the row for `removed` or `join_again`, one quiet line when `devices` has devices with `verified: false` ("1 device of the account is not verified. Check Apassy on your Mac.", or "N devices of the account are not verified. …"; none after a removal or with `join_again`; with `list_verified: false` the line is "Apassy could not verify the device list from Connect. Nothing was changed." in its place, added 2026-11-11), and one destructive control, "Forget This iPhone…", with a confirmation, that calls `connect_forget`; then the iPhone can join an account again. Leaving an account is no purchase action; nothing there names a plan, a price, or a link. The route line "Reaches your Mac through: …" shows "Apassy Connect" in the place of "Tailscale" while `dial_route` is true, and, while it is false, the quiet line "Mac is offline" for `dial_state` `mac_offline` and "Not on Connect" for `not_on_connect` (no line for the other states).

**`connect_forget`** `{}` deletes the account key from the Keychain store, `connect/account.json`, and the account and token in memory, and gives up a join that waits. Connect is not asked: the Mac lists this iPhone until a Mac revokes it. It also deletes an account file of an earlier version (`join_again`), with the key; the iPhone has no owner check of the Mac for it, as for every forget of this section. Answers `{"forgotten": true}`, or `false` when there was no account and no key.

### 5.15 The transport of the relay calls: the tailnet, then the Connect dial (plan s7 unit I2)

Added 2026-11-10. Every relay call of the core goes through one transport (`ios/ApassyCore/src/core/transport.rs`): the questions and the access requests (section 5.10), the feeds of the Macs (5.12), the joins (5.2 and `join_attach`), and relay sync (5.5). Their requests and answers, and the contracts relay-questions-v1, relay-feed-v1, relay-access-request-v1, and relay-sync-v1 with their digests, do not change by one byte: the transport only chooses how the bytes reach the node. The one exception (2026-11-11): a request through the dial that is not a long poll does not send the header line `Connection: close` (one dial for requests that follow each other, below).

- **Two routes of a node.** A vault or a questions team on a node (a pinned origin, [node-pairing-v1](node-pairing-v1.md)) whose code carried a Connect route (section 7a: the last `alt` entry `wss://<Connect host>/v1/tunnel/dial/<node id>` and `node=`) has two routes: the **tailnet** (the origin and its alternatives, as before) and the **Connect dial** ([connect-tunnel-v1](connect-tunnel-v1.md) section 3.3). The route is stored as the last entry of `alt` (`phone.json`, section 6, and the membership of the vault); nothing else is stored.
- **Order.** The tailnet first. When no tailnet destination connects (within 10 s), the dial: `GET /v1/tunnel/dial/{node id}` at the account's own Connect origin (the route's host must be that origin's) with the account token of section 5.14, then inside that byte pipe the same pinned TLS 1.3 handshake to the node as on the tailnet, with the pin of the pairing, the same `Host`, and the same signed origin, before any request byte. While the tailnet failed recently, the dial goes first and the tailnet is the last resort; a probe every 30 s (a pinned TLS handshake, no request, no token) brings the calls back to the tailnet as soon as it answers.
- **What Connect sees.** TLS records, sizes, and times. Never a request, a token of the relay, a key, or an answer, and it cannot change one: a wrong certificate through the dial is `pin_mismatch` before any request byte, as on the tailnet.
- **States** (`dial_state` of `connect_status`): `connected` (the last dial reached the node); `not_on_connect` (`403 plan_required`, `403 account_required`, or no Connect account on this iPhone): no dial for 15 minutes; `mac_offline` (`503 tunnel_offline` or `404 node_unknown`: the Mac has no tunnel open): the next dial after 1 s, doubling, at most 60 s; `limit` (`429 tunnel_limit` or `rate_limited`): no dial for 60 s; `unreachable` (Connect did not answer): the backoff of `mac_offline`; `refused` (another refusal, such as `not_in_group`): no dial for 15 minutes; `unused` (no dial since the start or the last lock). During a wait the calls fail as an unreachable relay does (`relay_unreachable`), with no new dial: no state makes a storm of dials, and none names a plan, a price, or a purchase.
- **The long poll.** One dial for each connection of the relay client. The dial answers Connect's pings and pings every 30 s, and ends after 90 s without a message (connect-tunnel-v1 sections 3.2 and 8), so a long poll keeps its dial through Connect and Cloudflare. A long poll always has a dial of its own and asks the node to close after its answer.
- **One dial for requests that follow each other** (2026-11-11). After a complete answer (HTTP/1.1, no `Connection: close`, a body with a length, nothing after it) the pinned connection inside the dial stays open, one for each node (`apassy::sync::KeptDials`), and the next request to that node through the dial takes it: no new dial and no new TLS handshake, so a burst stays far below Connect's 60 dials a minute. Such a request does not send `Connection: close`; nothing else of it changes. The node keeps a device stream of the tunnel open for 45 s without a request (relay docs/SPEC.md section 35.6); the iPhone closes its kept dial after 30 s without one, and at `lock` and `suspend`. A kept dial that turns out dead: a request of which nothing reached it takes a fresh dial; a `GET` or `HEAD` without a body that went out and met the end of the connection before any byte of the answer goes once more on a fresh dial; any other request fails as a broken connection (`relay_unreachable`), because it may have reached the Mac.
- **Lock and suspend** end every dial at once, also one on its way, and the route of every node is unknown again (`dial_route: false`) until the next call.
- **Who dials.** Only the role `app`. The AutoFill extension and the Apple Watch keep the route and never dial (the watch's URLSession transport, section 2.1, connects to the origin only).

## 6. `phone.json`

```json
{"version": 1, "selected": "<vault_id>", "vaults": [Vault]}
```

Written to a temporary file and renamed. The extension reads it and never writes it.

`Vault.sync_source` is optional for older lists. `"icloud"` selects the iCloud snapshot path. When it is absent, `relay_url` identifies a relay vault; a vault without either is local. Swift routes its sync methods accordingly. A missing bookmark is an access error, not a local-only vault.

A vault on a node (added 2026-11-03, plan S2–S3 units N3 and N6; [node-pairing-v1](node-pairing-v1.md) section 9) has three more fields, all optional, so the list version stays 1 and an older list reads as no pin: `pin` (the 43-character pin of the node's certificate), `alt` (the alternative destinations, `host:port` each, and the Connect route of node-pairing-v1 section 7a as the last entry, at most 4 in all; absent when empty), and `node_name` (the node's name from its link, at most 40 characters, a label only). `relay_url` is then the node origin `https://<Tailscale IPv4>:<port>`. A stored pin that is not a canonical pin is an error of that vault, never system trust. A hosted vault writes none of them. Swift shows a vault with `pin` "via your Mac" (Settings > Devices, the route words of `docs/design/devices-settings-mockup.html`), and needs Tailscale on this iPhone to sync it.

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

A passkey is a set of reserved fields on a login: `passkey_format`, `passkey_rp_id`, `passkey_credential_id`, `passkey_user_handle`, `passkey_user_name`, `passkey_user_display_name`, and the secret `passkey_key`. The stored byte values are base64url without padding. The wire (section 5.8) is standard base64 with padding. The fields sync as ordinary encrypted `item_field` rows.

`passkey_format` names the algorithm and the one stored form of the key:

| Format | Algorithm | `passkey_key` |
| --- | --- | --- |
| `es256-pkcs8-v1` | ES256, COSE -7 | P-256 PKCS #8 v1 with the public point, without `parameters` in `ECPrivateKey` (the form of `ring`) |
| `es384-pkcs8-v1` (schema 25) | ES384, COSE -35 | P-384 PKCS #8 v1 with the public point, the same form |
| `ed25519-pkcs8-v1` (schema 25) | EdDSA, COSE -8 | Ed25519 PKCS #8 v2 with the public key (RFC 8410, the form of `ring`). An import of v1 gets the public key. |
| `rs256-pkcs8-v1` (schema 25) | RS256, COSE -257 | RSA PKCS #8 v1: `rsaEncryption` with NULL, the `RSAPrivateKey`, no attributes. 2048 to 4096 bits, public exponent at least 65537. |

Optional reserved fields (schema 25): the secrets `passkey_prf_uv` and `passkey_prf_no_uv` (32 bytes each, both or neither), the secret `passkey_large_blob` (raw DEFLATE data) and the plain `passkey_large_blob_size` (the uncompressed size in decimal, at most 65536; both or neither). A bad value of an optional field counts as absent: the passkey still signs, without a PRF output or a blob. A bad key or a bad required field makes the passkey invalid. An ES256 passkey without extension data has the same rows as in schema 17.

Schema 25 changes no table and no row. A device of schema 24 or earlier refuses a vault or a copy of schema 25 (`unsupported_schema`), so it never sees a format that it cannot sign with.

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

- Import keeps passwords, TOTP, and passkeys with an ES256 (P-256), ES384 (P-384), EdDSA (Ed25519), or RS256 (RSA) PKCS #8 key, with their PRF secrets and their large blob (iOS 26.4 and later give the extension data; iOS 26.0 does not). TOTP uses SHA-1, SHA-256, or SHA-512. A passkey of another algorithm (P-521 too), a damaged key, or bad PRF or large blob data counts as invalid. The report has counts only, with no names. The app keeps the other credential types (cards, Wi-Fi networks, identity documents, addresses, names, notes, API keys, SSH keys, custom fields) as Custom, API key, or SSH key items, with their values hidden. Only an item with nothing but a link to another item counts as unsupported.
- Each import and each export starts with its own fresh owner check, before the app reads the other app's data or the keys of the vault.
- Export has two steps: the owner picks the other app in the system sheet, and then the app reads the vault. If the vault locks or another vault opens during the pick, the export pauses and nothing is read. The resumed export is bound to the vault in which the owner started it. The owner unlocks that vault, and the app asks for the owner check again before it reads the keys.
- The history event of an export says "prepared" (section 5.9). It is not a record that the other app finished the import.
- Export gives the algorithm, the PRF secrets, and the large blob of each passkey (section 5.9), so a transfer out keeps them.
- Not supported: HOTP, Steam codes, and passkey algorithms other than ES256, ES384, EdDSA (Ed25519), and RS256. An item type other than a login is not exported.

## 12. Not confirmed yet

The statements above come from the source of the branch. These points are open or unconfirmed:

1. **Upgrade from schema 16 on devices.** Local tests cover adoption, a new passphrase, relay publication with equal content, and the iCloud core with an encrypted schema 16 file. These tests do not call the iCloud service or use a physical device.
2. **Integration and builds.** No signed build and no iPhone or Mac device ran these calls for this document. The [acceptance checklist](../operations/passkeys-and-codes.md#9-acceptance-checklist) lists what remains.
3. **Browsers.** The browser calls are in [browser contract](browser-v1.md) section 9, not here. Only the signature of Helium is verified as a browser caller today.

### ADR 0033 typed access requests (version 1)

Calls of the `app` role and, since ADR 0039, of the `watch` role (section 5.13); they leave existing strict run-question DTOs unchanged. `access_requests_list` and `access_requests_history` return `{protocol:"apassy-access-request",version:1,requests:[...]}`. A row has phone-local `vault_id`, verified `card`, exact `digest`, carrier `state`, optional verified `receipt` and registered public `answer_key`. The card contains the separate actual vault UUID. History is read-only; no call reports an available permit. Unsupported cores return the usual unknown-call error and clients offer local Mac review.

`access_request_prepare` takes `{vault_id,qid,digest,kind}` where kind is `deny` or `allow_once`. It resolves exact current membership and trusted rows and returns immutable `{bytes,time,digest,needs_face_id,retry_before}`. Swift signs the returned bytes only for Allow once through the registered per-team protected key and a new Face-ID-only context. `access_request_answer` adds that original `time` and, for Allow once, DER `signature`. Deny is signed internally with the relay identity. Core verifies the signature, context, trust generation, original time and deadline before every POST. `access_request_cancel_prepared` discards preparations. Lock/suspend/vault changes discard preparations as well.

Core serializes submission per vault/qid and persists an encrypted attempt reservation before sending. At most three POSTs across choices/uncertain responses and no POST after confirmed transport success. History opt-out/clearing/restart cannot reset live guards. Missing/unwritable guard storage fails closed with `history_storage_unavailable`; no signature or permit is persisted. Optional bounded encrypted access metadata uses a distinct authenticated projection; unsigned legacy run settles cannot confirm access consent.

Native app configuration sets `request_guard_storage_ready` only after verifying the private `request-history/` directory and its backup exclusion. It is separate from optional `request_history_enabled`; when omitted it defaults to that older field for compatibility. Access guards live in this protected directory, and history clearing removes projections without deleting live attempt reservations. A failed native storage setup never enables submissions.
