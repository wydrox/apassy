# Review: key memory (V2)

Date: 2026-09-26.
Status: review complete for goal item V2. This review did not change Rust code. §8 records which fixes in §6 are done, with the commits.
Scope: the master passphrase, the SQLCipher key, stored secret values, and agent tokens in the memory of the Apassy process, and their exposure through swap, crash data, and other processes of the same user. Code at commit `768bbf3`.
Related: [storage dependencies](storage-dependencies.md), [ADR 0003](../adr/0003-passphrase-vault.md), [ADR 0006](../adr/0006-process-secrets.md), [ADR 0010](../adr/0010-closing-open-decisions.md).

## 1. Method

- I read the Apassy code and the code that it calls: rusqlite 0.40.2, SQLCipher 4.14.0 (`libsqlite3-sys-0.38.2/sqlcipher/sqlite3.c`), egui 0.36.2, and winit 0.30.13.
- Host: macOS 27.0 (26A428), arm64. SIP is on. Developer mode is off.
- I measured with throwaway programs in `/tmp`. They use synthetic values only. They are not in the repository:
  - an egui 0.36.2 harness (same `Cargo.lock`) that types into a password `TextEdit`;
  - a rusqlite 0.40.2 program (same `Cargo.lock`) that reads SQLCipher runtime values;
  - small C programs with a heap canary, signed three ways: ad-hoc linker-signed (like `cargo build` output), ad-hoc with hardened runtime, and ad-hoc with `com.apple.security.get-task-allow`.
- I removed the two crash reports that my tests made.

## 2. Summary

Where the key material is:

- The passphrase is in the egui text field `String`, in the egui undo history of that field, and in several SQL text copies inside SQLite. `PRAGMA key` receives it as SQL text: rusqlite formats `PRAGMA key = '<passphrase>'` (`rusqlite/src/pragma.rs:227-244`).
- SQLCipher keeps its own passphrase copy until the first page read. Then it erases it (`cipher_store_pass` = 0, measured).
- SQLCipher keeps the derived AES-256 key and HMAC key for the whole unlocked session. They are in a locked (`mlock`) private heap and are masked with a random value. SQLCipher erases them when the connection closes (`Vault::lock`).
- Stored secret values are in plaintext in the SQLite page cache after a read, and in `String` copies after `reveal`.

What Apassy erases: nothing reliably.
Each `Drop` implementation for secret text calls `String::clear()`. That sets the length to 0. It does not overwrite the bytes. `http.rs` calls `fill(0)` before a free. The compiler can remove that write.
SQLCipher erases its own key material. `zeroize` 1.9.0 is in `Cargo.lock` (through rustls), but Apassy does not use it.

The five most important findings:

1. The egui undo history keeps the passphrase. After Unlock empties the field, Cmd+Z in the field restores the full passphrase (measured, K2). A person at the keyboard can then unlock the vault again after it is locked.
2. The passphrase goes through SQL text. rusqlite and SQLite make several heap copies. SQLite frees them without erasure, because `cipher_memory_security` is off (measured, K5).
3. The SQLite page cache and the revealed values keep plaintext secrets in the heap. Nothing erases them (K8 to K10).
4. A same-user process can read the environment of the child process that the broker starts, with `ps -E`. This shows the secret values (measured, K12). ADR 0006 does not list this risk.
5. The passphrase field does not turn on macOS Secure Event Input. winit does not support the password IME purpose on macOS (K3).

## 3. Findings

"Erased" means that the bytes are overwritten before the memory is freed. "Cleared" means `String::clear()` only.

### 3.1 Master passphrase

| ID | Where | Copies and lifetime | Erased |
| --- | --- | --- | --- |
| K1 | egui field: `OwnerUiState.passphrase` (`src/desktop/owner_store.rs:212`), `password_line` (`src/desktop/ui.rs:1065-1075`), called at `ui.rs:606` | The `String` grows while the owner types. egui inserts with `String::insert_str` (`egui/src/widgets/text_edit/text_buffer.rs:253`). Each growth moves the text and frees the old buffer, so prefixes of the passphrase stay in freed heap. The field keeps the text until Create, Unlock, or Restore. `Ephemeral::take` (`ui.rs:614`, `642`, `706`) moves the `String` out. `Ephemeral::drop` (`owner_store.rs:84-88`) clears it. | No. Cleared only. |
| K2 | egui undo history of the passphrase field: `TextEditState.undoer`, stored in egui memory (`egui/src/widgets/text_edit/state.rs:66-67`) | egui feeds the full text to the undoer twice per frame (`builder.rs:1085`, `1375`). It keeps up to 100 states (`undoer.rs:29`). Password mode does not turn this off. The state lives until the app ends. Measured: after the app takes the field value, Cmd+Z restores the typed passphrase (23 of 23 bytes). After `TextEditState::clear_undoer` for that widget, Cmd+Z restores nothing. | No |
| K3 | Keyboard path to the field | Each typed character is an `egui::Event::Text` `String` for one frame. egui asks for `IMEPurpose::Password` (`builder.rs:953`), but winit does not support it on macOS (`winit/src/window.rs:1292`). So Secure Event Input is off. A process with the Input Monitoring or Accessibility permission can read the keystrokes. egui shows only mask characters (`builder.rs:502`), gives accesskit the `PasswordInput` role (`builder.rs:999`), and blocks copy and cut (`builder.rs:1090`). | No |
| K4 | Rust call path: `OwnerSession::unlock` (`owner_store.rs:324`), `create_file` (`301`), `restore` (`459`) to `Vault::unlock` (`src/vault/mod.rs:166`), `Vault::create` (`117`), `Vault::restore` (`349`), to `apply_key` (`mod.rs:578-590`) | Apassy passes `&str` only. The validation functions (`src/vault/types.rs:218-241`) make no copy. | Not applicable |
| K5 | `PRAGMA key` SQL text: `conn.pragma_update(None, "key", passphrase)` (`mod.rs:580`) | rusqlite builds `PRAGMA key='…'` one character at a time in a `String` without a start capacity (`rusqlite/src/pragma.rs:14-15`, `118-129`). The buffer grows several times and leaves prefixes in freed heap. SQLite keeps the SQL text in the prepared statement until finalize, and the parser makes a dequoted copy of the value (`zRight`, `sqlite3.c:150946-150964`). SQLite frees these copies without erasure, because `cipher_memory_security` is 0 (measured). Small copies can be in the per-connection lookaside buffer, which the SQLCipher erasing allocator does not see. That buffer lives until the connection closes. This happens once for each connection that opens with the passphrase: 1 for create, 1 for unlock, 2 for restore (`validate_encrypted_source`, `revoke_restored_agents`). | No |
| K6 | SQLCipher passphrase copy: `sqlcipher_cipher_ctx_set_pass` (`sqlite3.c:110702-110712`) | One copy in the SQLCipher private heap, 48 KiB, locked with `mlock` (`sqlite3.c:109717`, `110140`). It lives from `PRAGMA key` to the first page read, which derives the key (PBKDF2-HMAC-SHA512, 256000 iterations). Then SQLCipher erases it (`sqlite3.c:111290-111297`). | Yes, by SQLCipher (random overwrite, `sqlite3.c:110403`) |

### 3.2 SQLCipher key

| ID | Where | Copies and lifetime | Erased |
| --- | --- | --- | --- |
| K7 | Derived AES-256 key and HMAC key in the read and write cipher contexts | In the private heap, locked with `mlock`, masked with a random mask (`sqlcipher_shield`, `sqlite3.c:110088`). They live for the whole unlocked session. `Vault::lock` (`mod.rs:175-183`) closes the connection. Then `sqlcipher_cipher_ctx_free` (`sqlite3.c:110539-110546`) erases them. OpenSSL makes a cipher context for each page operation and frees it (`sqlite3.c:114001-114048`). I did not audit the OpenSSL erasure of these contexts. | Yes, at lock, by SQLCipher. They are present while the vault is unlocked. |

### 3.3 Stored secret values

| ID | Where | Copies and lifetime | Erased |
| --- | --- | --- | --- |
| K8 | SQLite page cache and temporary storage | SQLCipher decrypts each page that it reads into the page cache (about 2 MB by default). The page cache holds all values on that page, not only the value that the code asked for. It lives until the connection closes. SQLite frees it without erasure. `secure_delete=ON` (`mod.rs:662`) affects the file only. | No |
| K9 | `Vault::reveal` (`mod.rs:321-336`) and `SecretValue` (`types.rs:23-35`) | `row.get::<String>` copies the value into a new `String`. `SecretValue` has redacted `Debug`, but it derives `Clone` and has no `Drop`. Each caller copies it again with `expose().to_owned()`. | No |
| K10 | Owner reveal and edit: `OwnerSession::reveal` (`owner_store.rs:424-443`), `RevealedValue` (`842-854`), `SecretLine.display` (`808`), `plain_value` (`1112`), `push_secret` (`1280-1307`), secret inputs `SecretForm` (`33-69`), `add_secrets.clone()` and `edit_secrets.clone()` (`ui.rs:812`, `954`), bound value in `insert_tags_and_fields` (`mod.rs:928`) | `RevealedValue` lives until Hide, lock, or unlock. `details_from_meta` clones each revealed value into `SecretLine.display` on each call. egui draws it with `RichText::new(&line.display)` (`ui.rs:886`). The egui text layout cache keeps it while it is visible. accesskit exposes a label text to accessibility clients. Secret input fields use `password_line` too, so K1 and K2 also apply: Cmd+Z can restore a typed secret after save. SQLite copies bound values (transient binding). | No. `RevealedValue` and `SecretForm` are cleared only. |
| K11 | Broker run path: `read_secrets` (`src/broker/run.rs:451-468`), `SecretEnv` (`src/broker/exec.rs:29-44`), `exec::run` (`exec.rs:56-114`), `drop(secrets)` (`run.rs:271`) | `read_secrets` copies each value into `SecretEnv.value` and drops the `SecretValue` without erasure. `cmd.env` (`exec.rs:85`) copies the value into the `Command` environment map. The standard library builds another `NAME=value` C string array at spawn. These live for the run (at most 300 s). | No. `SecretEnv` is cleared only. The standard library copies cannot be erased. |
| K12 | Environment of the child process | The kernel copies the environment into the child. It stays there for the life of the child and its children. This is the design of ADR 0006. Measured: `ps -E -ww -p <pid>` from another process of the same user shows `APASSY_SYNTHETIC_ENV=synthetic-env-canary-4b2` for an ad-hoc signed child and for a hardened-runtime child. It does not show the environment of an Apple platform binary (`/bin/sleep`). | Not applicable |
| K13 | Output buffers: reader threads (`exec.rs:118-141`), `collect` (`144-150`), `mask` (`164-175`) | Each reader thread has an 8 KiB stack buffer and a `Vec` of up to 64 KiB with the raw output. The raw output can contain a secret. `String::from_utf8_lossy` and each `replace` in `mask` make more copies. Only the masked result goes to the agent. | No |
| K14 | Connector path: `Prepared.secret` (`src/broker/decide.rs:196-208`, `348`), `http::get` (`src/broker/http.rs:187-233`) | `prepare` copies the value. `format!` puts it into the request text (`http.rs:201`). `request.fill(0)` (`http.rs:231`) runs just before the free. The optimizer can remove such a write, because the memory is not read again. rustls copies the plaintext into its own buffers. I did not audit rustls buffer erasure. | Partly. `fill(0)` is not guaranteed. `Prepared` is cleared only. |

### 3.4 Agent tokens

| ID | Where | Copies and lifetime | Erased |
| --- | --- | --- | --- |
| K15 | `AgentToken` (`src/vault/agents.rs:154-173`), `register_agent` (`398-420`), `authenticate_agent` (`484-513`), token display (`ui.rs:1967-2010`) | The database stores the raw token (encrypted by SQLCipher), not a hash (`agents.rs:407`). `authenticate_agent` loads every active token into a `Vec<u8>` for each request. The desktop shows the token in an editable `TextEdit` and makes two new copies each frame (`ui.rs:1979`, `1989`). That field also has an undo history (K2). The owner copies the token to the clipboard by design. `apassy-mcp` gets it from `APASSY_AGENT_TOKEN`, so `ps -E` shows it (K12). | No. `AgentToken` is cleared only. |

### 3.5 Debug, Display, errors, and logs

| ID | Where | Result |
| --- | --- | --- |
| K16 | `Debug` of `SecretValue`, `Field`, `ItemDraft`, `ItemDetails` (`types.rs`), `SecretForm`, `RevealedValue`, `SecretLine`, `OwnerDetails` (`owner_store.rs`), `SecretEnv` (`exec.rs:34-38`), `AgentToken` (`agents.rs:163-167`), `WireRequest` (`src/agent/wire.rs:30`), MCP config (`src/agent/mcp.rs:31`), `Vault` (`mod.rs:99-105`) | Redacted. `tests/vault_passphrase.rs` checks the vault types. |
| K17 | Errors: `VaultError` (`types.rs:151-171`), `owner_message` (`owner_store.rs:1048-1070`), broker refusals (`run.rs`, `decide.rs`) | Fixed text, item IDs, field names, and environment names only. No passphrase, no value, no SQL, no driver text. |
| K18 | Logs | Apassy prints only fixed text (`src/main.rs`, `src/bin/apassy-mcp.rs`). SQLCipher writes WARN and higher to the macOS unified log (`sqlite3.c:109862-109879`). Its PRAGMA debug line skips `key` and `rekey` (`sqlite3.c:112002`). `PRAGMA cipher_profile` would log SQL text, including a `PRAGMA key` statement. Apassy never calls it. The encrypted activity log stores the command label and the purpose, not values. |

## 4. Operating system exposure (measured)

| Channel | Measurement on the review host | Result |
| --- | --- | --- |
| Swap | `sysctl vm.swapusage`: `total = 5120.00M used = 3922.94M free = 1197.06M (encrypted)` | Swap is in use and encrypted. Memory that is not locked can go to encrypted swap. The SQLCipher key and passphrase copies are in locked memory. `ulimit -l` and `launchctl limit memlock` are `unlimited`. |
| Hibernation | `pmset -g`: `standby 0`. `/var/vm` is empty. | No sleep image on this host. |
| Disk encryption | `fdesetup status`: `FileVault is Off` | Crash reports, backups, and the agent MCP configuration (with the token) are on an unencrypted volume on this host. The vault file itself is encrypted by SQLCipher. |
| Core dumps | `kern.coredump: 1`, `kern.corefile: /cores/core.%P`, `ulimit -c` 0, `ulimit -Hc` unlimited, `launchctl limit core` 0 / unlimited | A process can raise its own soft limit. Apassy does not. Test: with `ulimit -c 8388608` (4 GiB), an aborting C program wrote no core file in any of the three signing modes. I did not test an unlimited core size, because the free disk space is 13 GiB. |
| Crash reports | ReportCrash wrote `~/Library/Logs/DiagnosticReports/crash_*.ips`, mode `0600` | The report has the thread state (registers x0 to x28, fp, lr, sp, pc), stack frames, and `instructionByteStream`. It does not have heap contents: the heap canary was not in the report. A register can hold up to 8 bytes of a secret at the crash point. |
| Heap read by a same-user process | `leaks <pid>` on a process with a leaked canary block | ad-hoc linker-signed: "not debuggable", no writable memory shown. Hardened runtime: same. With `get-task-allow`: the canary text is shown. So the release app must not have `get-task-allow`. `vmmap` (region map only) works on the ad-hoc and the hardened process. |
| Code injection | `DYLD_INSERT_LIBRARIES=inject.dylib` | ad-hoc linker-signed: the dylib runs. Hardened runtime: the dylib does not run. Current `cargo build` output is ad-hoc linker-signed without hardened runtime (`codesign -dv`: `flags=0x20002(adhoc,linker-signed)`). |
| Child environment | `ps -E -ww` from the same user | Shows the environment of non-Apple child processes, also with hardened runtime (K12). |

I did not test `lldb` attach or `task_for_pid` directly. On this host, a debugger attach asks for an administrator password in a dialog, and I did not want to open dialogs on the owner's screen. Root and kernel access are out of scope.

## 5. Known limits

These limits stay after all fixes in §6:

- The SQLCipher key must be in memory while the vault is unlocked. A process that can read Apassy memory during that time gets the key. Hardened runtime without `get-task-allow` makes this harder for same-user processes. It does not stop root.
- Rust cannot guarantee that no copy stays. A `String` can move when it grows. The allocator does not erase freed memory. `zeroize` erases only the buffer that it gets, and only its current capacity.
- `forbid(unsafe_code)` stops Apassy from calling `mlock` (`rustix::mm::mlock` is `unsafe`). `mlockall` does not exist on macOS. So Apassy memory outside SQLCipher can go to swap. macOS encrypts swap.
- egui makes its own copies of text in the input events, the undo history, and the text layout cache. Apassy can clear the undo history, but it cannot erase the other copies.
- The standard library copies the child environment at spawn. The child and any same-user process that can run `ps -E` can read it. Only the sandbox of the agent host (goal items I1 to I4) can limit which processes can read it.
- `cipher_memory_security` is process-wide. It cannot be turned off after it is on (`sqlite3.c:112497`).

## 6. Fixes, in priority order

Each fix names the file, the function, the change, and a test. Do not add new crates. `zeroize` 1.9.0 and `rustix` 1.1.4 are already in `Cargo.lock`. A direct dependency on them must use the same version and must not change the package list in `Cargo.lock`. Check with `cargo tree` and `git diff Cargo.lock`.

| # | Priority | File and function | Change | Test |
| --- | --- | --- | --- | --- |
| F1 | High | `src/desktop/ui.rs`: `password_line`, `draw_vault_file_card`, `draw_backup_card`, the add and edit item cards | Make `password_line` return the widget `Id` (`Response::id`). After each `Ephemeral::take` (`ui.rs:614`, `642`, `706`), after each `add_secrets.clear()` and `edit_secrets.clear()`, and on lock, call `TextEdit::load_state(ctx, id)`, then `state.clear_undoer()`, then `TextEdit::store_state(ctx, id, state)`. | Headless egui test: type a synthetic passphrase in the vault passphrase field, press Unlock, run frames, send Cmd+Z, and assert that the field is empty. The harness in this review shows 23 bytes restored before the change and 0 after. |
| F2 | High | `src/vault/mod.rs`: `apply_key`, and new `open_keyed` or the start of `open_working_conn`, `initialize_new_db`, `validate_encrypted_source` | Run `PRAGMA cipher_memory_security = ON` before the first `PRAGMA key` in the process, and check that it returns 1. SQLite then locks and erases all its allocations on free: SQL text copies, parser copies, bound values, and the page cache. Also add `-DSQLITE_DEFAULT_LOOKASIDE=0,0` to the `LIBSQLITE3_FLAGS` fix in the [V1 review](storage-dependencies.md) §7 item 2, so that small allocations do not stay in lookaside. Measured cost at vault scale: 2000 inserts took 11.6 ms off and 15.5 ms on. 400000 point reads took 2409 ms and 2414 ms. The host was busy, so the numbers are approximate. | Vault test: after unlock, `PRAGMA cipher_memory_security` returns 1. The test needs a test-only accessor. Probe test: `compile_options` has `DEFAULT_LOOKASIDE=0,0`. Run the vault lifecycle tests and compare the time. |
| F3 | High | `Cargo.toml` (direct `zeroize = "=1.9.0"`, default features, no `derive`); `src/desktop/owner_store.rs`: `Ephemeral::drop`, `SecretForm::clear`, `RevealedValue::drop`; `src/vault/types.rs`: `SecretValue`; `src/vault/agents.rs`: `AgentToken::drop`; `src/broker/exec.rs`: `SecretEnv::drop`; `src/broker/decide.rs`: `Prepared::drop` | Replace each `String::clear()` in these `Drop` implementations with `Zeroize::zeroize`. Add `impl Drop for SecretValue` that calls `self.0.zeroize()`, and mark the secret types with `ZeroizeOnDrop`. Zeroize `OwnerUiState.passphrase` in `OwnerSession::lock` and at app exit. | A compile-time check in `tests/vault_passphrase.rs`: `fn requires<T: zeroize::ZeroizeOnDrop>() {}` for `SecretValue`, `AgentToken`, `SecretEnv`. Unit test: `Ephemeral::take` leaves an empty slot and the taken value has length 0 after `zeroize`. Safe Rust cannot read freed memory, so a test cannot prove erasure. |
| F4 | High | `src/desktop/owner_store.rs`: `OwnerUiState` default, `Ephemeral::take`; `src/desktop/ui.rs`: `password_line`, `secret_inputs` | Give each secret input `String` its full capacity before typing starts: `String::with_capacity(MAX_PASSPHRASE_BYTES)` for the passphrase, and `MAX_FIELD_VALUE_BYTES` for the item secret fields. Add `.char_limit(...)` to the `TextEdit`, so the text cannot grow past the capacity. `Ephemeral::take` must put a new pre-sized `String` into the slot, not `String::new()`. Then typing does not move the buffer (K1), and F3 erases the only copy. | Headless egui test: record `as_ptr()` and `capacity()` of the field, type 40 synthetic characters, and assert that both are unchanged. |
| F5 | Medium | `src/vault/mod.rs`: `apply_key` | Build the key statement in a `zeroize::Zeroizing<String>` with the exact capacity: `"PRAGMA key = '".len()` plus the passphrase length plus the number of `'` characters, plus 1. Double each `'`. Run it with `conn.execute_batch(&sql)`. The buffer is erased on drop. Do not use `pragma_update` for the key. rusqlite has no key API without `unsafe`, and SQLite does not accept a bound parameter in a PRAGMA. SQLite still copies the text; F2 erases those copies. Alternative, not recommended now: open `:memory:` and run `ATTACH DATABASE ?1 AS vault KEY ?2` with a bound key. I measured that this works with SQLCipher 4.14.0 and that a wrong key fails at `ATTACH`. It needs a schema name in each PRAGMA. | Existing `vault_lifecycle` and `vault_passphrase` tests. Add a test with a passphrase that contains `'` and `''`, and check that unlock works and a wrong passphrase fails. |
| F6 | Medium | `src/main.rs`: `main` (the desktop process also runs the broker) | Set the core limit to 0, soft and hard, at the start of the process: `rustix::process::setrlimit(Resource::Core, Rlimit { current: Some(0), maximum: Some(0) })`. This function is safe Rust. Add `rustix = { version = "=1.1.4", default-features = false, features = ["std", "process"] }` to the `desktop` feature. | Unit test: after the call, `rustix::process::getrlimit(Resource::Core)` returns 0 for both values. |
| F7 | Medium | Release signing script (goal item A1) | Sign `Apassy.app` and every helper with hardened runtime (`codesign -o runtime`). Do not use the entitlements `com.apple.security.get-task-allow`, `com.apple.security.cs.disable-library-validation`, or `com.apple.security.cs.allow-dyld-environment-variables`. | Script check: `codesign -d --entitlements - Apassy.app` has none of these keys, and `codesign -dv` shows `runtime`. Manual check: `leaks <pid>` shows "not debuggable", and `DYLD_INSERT_LIBRARIES` has no effect. |
| F8 | Medium | `src/broker/http.rs`: `get`, `post_json_loopback` | Replace `request.fill(0)` (`http.rs:231`, `273`) with `request.zeroize()`. Build the request in a pre-sized `Vec` so that it does not grow. | Existing HTTP tests. |
| F9 | Medium | `src/broker/run.rs`: `read_secrets`; `src/vault/types.rs`: `SecretValue`; `src/broker/exec.rs`: `spawn_reader`, `run`, `mask` | Add `SecretValue::into_zeroizing(self) -> Zeroizing<String>` and move the value into `SecretEnv` without a copy. In `spawn_reader`, zeroize `buf` after the loop. In `run`, zeroize `out` and `err` after masking. In `mask`, zeroize each replaced intermediate `String`. | `exec` unit tests (`process_sees_secret_and_output_is_masked`, `mask_prefers_longer_values_and_skips_short_ones`) and `tests/agent_run.rs`. |
| F10 | Medium | `src/desktop/owner_store.rs`: `details_from_meta`, `SecretLine`; `src/desktop/ui.rs`: item view | Do not clone revealed values into `SecretLine.display` on each call. Keep one `Zeroizing<String>` in `RevealedValue`, and let the view borrow it. Hide revealed values after a fixed time, for example 30 s. | `tests/owner_vault.rs`: reveal, then check that `details()` has no revealed value after hide and after lock. |
| F11 | Medium | ADR 0006, "What this mode does not protect"; Seatbelt profile (goal item I1) | Record K12: a same-user process can read the environment of the child with `ps -E`. The Seatbelt profile should deny process information of processes outside the sandbox. Assign to the isolation worker. | The I2 test: from inside the profile, `ps -E -p <broker child pid>` does not show the environment. |
| F12 | Low | `src/desktop/ui.rs`: token display (`1967-2010`); `src/vault/agents.rs` | Show the token in a read-only, selectable label, not an editable `TextEdit`. Clear its undo history when the owner dismisses it. Later: store a hash of the token instead of the raw token. That needs a schema version (goal item V6). | UI test: the token field is not editable. Vault test for the hash with a migration test. |
| F13 | Low | `src/vault/mod.rs` module comment (`7-8`) | Correct the URI statement, or remove URI support with the V1 build flags. | Review only. |
| F14 | Low | Swift helper (goal item A1) | Take the passphrase in a native `NSSecureTextField` in the Swift helper. It turns on Secure Event Input and does not keep an undo history. Pass the passphrase to Rust once. | Manual check: while the field has focus, `ioreg -l -w 0` output has `kCGSSessionSecureInputPID` with the Apassy PID. |

Owner-side prerequisite: turn on FileVault on the Mac that runs Apassy with real credentials.

## 7. What I could not check

- I did not prove erasure. Safe Rust cannot read freed memory, and I did not use a debugger on Apassy.
- I did not audit how OpenSSL and rustls erase their internal buffers.
- I did not test core dumps with an unlimited size. I did not test `lldb` attach.
- I measured on one host. FileVault is off there. The owner's daily machine can have other settings.
- The egui measurement uses a harness with the same egui version and the same widget options, not the Apassy app itself.

## 8. Status of the fixes

Date: 2026-09-26. Branch of the non-desktop worker, based on `c8a75aa`. The desktop worker owns F1, F4, F10, and the desktop part of F3.

| # | Status | Commit | Evidence |
| --- | --- | --- | --- |
| F1 | Not done here | — | Desktop worker. |
| F2 | Done | `6c7db7a` | Each connection runs `PRAGMA cipher_memory_security = ON` before the key and requires the value 1. `.cargo/config.toml` sets `LIBSQLITE3_FLAGS` with `-DSQLITE_DEFAULT_LOOKASIDE=0,0` (with `force = true`). Each open checks `PRAGMA compile_options` and fails closed without the flags. Unit tests `unlocked_connection_has_memory_security_and_defensive_mode` and `build_uses_the_checked_in_sqlite_flags` pass. Control: a build with an empty `LIBSQLITE3_FLAGS` fails both tests, and `Vault::create` returns `Storage`. Time with `--test-threads=1`, three runs each, on a busy host: `vault_lifecycle` 7.33 to 7.71 s before and 7.95 to 13.51 s after; `vault_passphrase` 8.73 to 12.04 s before and 9.32 to 9.74 s after. The lowest values grow by about 8%. |
| F3 | Done for the non-desktop types | `bfb638a`, `2a8c3ec` | `zeroize = "=1.9.0"` is a direct dependency. `SecretValue` has a `Drop` with `zeroize` and `ZeroizeOnDrop`. `AgentToken::drop` uses `zeroize`. `SecretEnv.value` and `Prepared.secret` are `Zeroizing<String>`. The raw token bytes in `register_agent`, `rotate_agent_token`, and `identify_agent` are in `Zeroizing`. Also `WireRequest` (the agent token on the wire) and the request line in `broker/server.rs`. Compile-time `ZeroizeOnDrop` checks for `SecretValue`, `AgentToken`, and `SecretEnv`. The desktop types (`Ephemeral`, `SecretForm`, `RevealedValue`, `OwnerUiState.passphrase`) belong to the desktop worker. |
| F4 | Not done here | — | Desktop worker. |
| F5 | Done | `6c7db7a` | `key_statement` builds `PRAGMA key = '…'` in a `Zeroizing<String>` with the exact capacity, doubles each `'`, and `apply_key` runs it with `execute_batch`. `rekey` uses the same builder. The KDF, HMAC, and page settings do not change and are checked as before. Unit tests: `key_statement_doubles_quotes_with_exact_capacity`; `passphrase_with_quotes_keeps_the_same_key` (a passphrase with `'` and `''` unlocks, two near variants fail with `WrongKeyOrCorrupt`, the earlier rusqlite `pragma_update` path opens the same file, and a rekey to a new passphrase with quotes works). |
| F6 | Done | `058b8fc` | `main` sets `RLIMIT_CORE` to 0, soft and hard, before anything else, with `rustix::process::setrlimit` (safe API). If the call fails, the app does not start. Unit test in `src/main.rs`: both limits are 0, a raise fails, and `ulimit -c` in a child shows 0. Dependency decision: see below. |
| F7 | Done | `bccd422` | `scripts/build-app.sh` checks each Mach-O file in the bundle (4 programs): a signature with the `runtime` flag, and no `get-task-allow`, `disable-library-validation`, or `allow-dyld-environment-variables` entitlement. The script first proves that the check finds all three keys on a signed probe copy. Result: exit 0. Manual check: a synthetic `DYLD_INSERT_LIBRARIES` dylib runs in `target/release/apassy-mcp` (`adhoc,linker-signed`) and does not run in the signed `Apassy.app/Contents/MacOS/apassy-mcp`. `leaks <pid>` on the signed program shows "not debuggable". |
| F8 | Done | `2a8c3ec` | `http::get` and `post_json_loopback` build the request in a `Zeroizing<Vec<u8>>` of the exact size (`request_bytes`). This replaces `fill(0)` and also erases the buffer after an early error, which `fill(0)` did not. Unit test `requests_are_built_in_exact_buffers_with_unchanged_bytes` checks the exact request bytes on a local server. |
| F9 | Done | `2a8c3ec` | `SecretValue::into_zeroizing` moves the value into `SecretEnv` and `Prepared` without a copy (unit test: same buffer pointer). `exec::run` drops the `Command` right after spawn, erases `out` and `err` after masking, and erases the lossy UTF-8 copy. `spawn_reader` reserves the full buffer at the start, erases its 8 KiB buffer, and erases output that nobody receives. `mask` erases each intermediate text. The `exec` unit tests and `tests/agent_run.rs` pass. |
| F10 | Not done here | — | Desktop worker. |
| F11 | Done as far as possible without a change of the delivery mode | `9fed53e` | ADR 0006 has a bullet for the risk. The isolation worker measured that no Seatbelt rule blocks a direct `KERN_PROCARGS2` read and keeps tools working. Broker change: `exec::run` stops the process group when the main process ends. Before the change, a background process with the secret in its environment ran on after the run (test failed); after the change, it stops (test passes). A test shows that the child environment has only the base names, `PATH`, and the bound secrets. |
| F12 | Deferred | — | Needs a schema version for a token hash, and a desktop change. |
| F13 | Done | `6c7db7a` | The module comment now says that the build turns off URI names and that each open checks the build options. |
| F14 | Deferred | — | Swift helper work (goal item A1). |

Also done: rustls `=0.23.45` for RUSTSEC-2026-0285 (`bfb638a`), SQLite defensive mode on each connection (`6c7db7a`), and a `cargo audit` step in CI (`50b31a2`). See the [V1 review](storage-dependencies.md) §7.

F6 dependency decision: `rustix = "=1.1.4"` (no default features; `std`, `process`) is an optional dependency of the `desktop` feature. The same version is already in `Cargo.lock` through `tempfile`, and the release binary already links it. `git diff Cargo.lock` shows only a new line in the dependency list of `apassy`. The alternatives are worse: the standard library has no `setrlimit`, `libc::setrlimit` needs `unsafe`, and a restart through `sh -c 'ulimit -c 0; exec …'` adds a shell, an environment marker, and a second start of the app.

F11 finding: the broker cannot hide the environment of a running child from a same-user process while it delivers secrets in the environment. The kernel keeps the environment strings of the child from `exec` to exit, also when the child changes its environment later, and also for a child that the broker starts through a wrapper. Only an Apple platform binary or a process of another user hides them. A different user needs a privileged helper, and that is out of scope. So the practical limits are: a minimal environment, the stop of the process group at the end of the run, the 300-second run limit, and the optional hourly run limit in the grant rules. A descendant that starts its own process group (`setsid`) is not stopped. A stronger mitigation needs a change of the delivery mode in ADR 0006, for example a file descriptor or a mediated call.

What stays open after these fixes:

- F1, F4, F10, and the desktop part of F3 (desktop worker). F12 and F14 (deferred).
- The standard library copies the child environment into the `Command` and into the `execve` arrays. Apassy frees the `Command` right after spawn, but it cannot erase it.
- `BufReader` in `broker/server.rs` keeps the raw request line (with the agent token) in its own buffer. The bouncer key (`BouncerClient.api_key`, `src/broker/bouncer.rs`), `AdapterConfig.token` in `apassy-mcp`, and the Base64 copy of a revealed value in `src/native/mod.rs` are not erased. These files belong to other workers.
- rustls and OpenSSL internal buffers are not audited (§7).
- `.cargo/config.toml` applies only to cargo commands that start in the repository. A build from outside fails closed at the first vault open, because the vault checks `compile_options`.
