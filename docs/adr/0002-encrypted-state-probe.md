# ADR 0002 — Encrypted state probe

Date: 2026-09-16
Status: SYNTHETIC PROBE PASSED. Production acceptance remains open.

This record proposes one encrypted transactional store for vault items and operational state.
The owner approved evaluation of SQLCipher for that direction.
The owner did not accept production security, cryptographic gates, key lifecycle, or isolation.

The parent ran the synthetic probe on macOS on 2026-09-16. All 12 probe tests passed with exit code 0.
The runtime reported SQLCipher `4.14.0 community` with provider `openssl`.
The page size is 4096 bytes. KDF iterations are 256000. Algorithms are `HMAC_SHA512` and `PBKDF2_HMAC_SHA512`.
HMAC is enabled. The plaintext header size is zero.
These are measured probe results, not production vault or key-lifecycle acceptance.

## 1. Proposed direction

The candidate is one SQLCipher database for encrypted durable state.

`Cargo.toml` pins `rusqlite = 0.40.2` with `default-features = false` and `bundled-sqlcipher-vendored-openssl`.
The design does not add a second unencrypted SQLite file for grants, approvals, audit, or the outbox.
The design does not make a custom cipher.
An age-format file plus a separate operational database is not the current candidate.

The probe target is `tests/sqlcipher_probe.rs`.
That target is a deterministic integration probe.
It is not the production vault.

## 2. Why one store

Product Infra v1 requires a durable authorization boundary.
One transaction must write these records together: item revision, usage counter, request intent, approval consumption, audit, and outbox.
The transaction reads the active policy version and pins that version on the intent.
It does not advance the immutable policy version on each operation.

One encrypted SQLite database can do that with ordinary SQL transactions.
Two stores cannot do that write in one transaction.
If vault content and operational state are in separate files, a crash can commit a revision in one file.
The other file can omit policy, intent, or audit.
That split needs a second protocol before P2.

Local atomicity is not remote exactly-once execution.
A committed intent does not prove that a connector call ran once.
It does not prove that the call failed.
It does not prove that the call never reached the service.
A timeout after a possible remote effect stays `unknown`.
This probe cannot show remote exactly-once behavior.

## 3. What the probe is written to check

The tests use an owned `tempfile::TempDir`.
They use synthetic keys and values only.
They set `PRAGMA key` immediately after open and before schema read or write.
They do not lower `kdf_iter`.
They do not disable HMAC.
They do not set a plaintext header.

Written checks:

- `PRAGMA cipher_version` is nonempty. Ordinary SQLite is a failure, not a silent fallback.
- The probe queries `cipher_version`, `cipher_page_size`, `kdf_iter`, `cipher_hmac_algorithm`, `cipher_kdf_algorithm`, `cipher_use_hmac`, `cipher_plaintext_header_size`, `cipher_provider`, and `journal_mode`.
- The test compares those results to the expected SQLCipher 4 names and numbers in the test file. Parent runtime must confirm the result types and the values. This worker did not query them.
- The right key opens the store and reads synthetic rows.
- A wrong key fails on an actual table read, not only on open.
- A missing key fails on an actual table read.
- The encrypted database file does not start with the ordinary SQLite header.
- Bounded scans of the database file, the WAL, and the rollback journal do not contain canary credential or sensitive metadata plaintext. This is evidence, not a cryptographic proof.
- One immediate transaction writes item revision, usage counter, request intent, approval consumption, audit, and outbox together. It reads and pins the active policy version. It does not change that version.
- An injected constraint returns all of those writes to the previous state, including usage count 0. A commit and reopen keep usage count 1 and policy version 1.
- A committed transaction is still present after close and reopen.
- A copy of a closed, checkpointed encrypted file opens again with the right key and is refused with the wrong key.
- A damaged copy of that encrypted file fails `integrity_check` or the table read.

The copy check is a closed-file copy after `PRAGMA wal_checkpoint(TRUNCATE)`.
It is not the SQLite backup API into a plaintext destination.
It is not a copy of an open database.
It is not a product backup procedure.

If a required cipher PRAGMA is absent, empty, or unreadable as the test expects, the test fails. It does not skip.

## 4. Checks not completed by this probe

The passing tests do not cover:
- Cryptographic review of SQLCipher page encryption, HMAC, or KDF
- License or source review of SQLCipher, OpenSSL, rusqlite, or libsqlite3-sys
- OS keychain, password files, environment secrets, or external key management
- Product lock, unlock, locked startup, or recovery
- Epoch invalidation of sessions and unused approvals
- Memory erasure, swap, or crash-dump tests
- Agent isolation or filesystem permission tests
- Concurrent writers, busy timeout, or crash injection beyond one constraint rollback
- Schema migration
- Online backup of an open database
- Rekey or key rotation
- Live network, live database servers, or remote exactly-once tests
- Production credentials or host configuration changes

A skipped default test does not satisfy this gate.
The parent enables `storage-probe` on this target.

## 5. Library assumptions that need verification

The runtime probe checks the library assumptions below. Source, license, and production key-lifecycle review remain open.

- `bundled-sqlcipher-vendored-openssl` on rusqlite 0.40.2 links SQLCipher. `PRAGMA cipher_version` is nonempty.
- The named cipher PRAGMAs exist and return a type the test can read. Text cipher names stay text. Integer settings accept SQLite INTEGER or integer TEXT only. The decoder rejects NULL, REAL, BLOB, invalid text, and overflow. It does not convert those values to zero. Parent runtime must still confirm the live values. This worker does not record a pass.
- The queried runtime values must match the SQLCipher 4 names and numbers in the test. The current run passed this check.
- `PRAGMA key` through rusqlite `pragma_update` is applied before any schema access.
- Wrong-key and missing-key failures occur on table read of encrypted pages.
- WAL frames and rollback journals for the main database do not store the canary plaintext.
- Page damage in the copy test causes a real read or integrity failure.
- Vendored OpenSSL and SQLCipher compile on the supported macOS desktop toolchain.
- The rusqlite `backup` feature stays off. A plaintext SQLite backup API is not part of this direction.
- First-party `unsafe` stays forbidden. The probe does not call `sqlite3_key` through a raw handle.

## 6. Gaps that still block production acceptance

Lock and startup: the probe holds a synthetic passphrase in process memory. It does not lock the vault. Recovery does not begin locked.

Key memory: the key appears in the `PRAGMA key` SQL string. The probe does not prove erasure, mlock, or protection from swap and crash dumps.

Epoch: restart does not create a new epoch. Unused approvals and sessions stay valid in this probe.

Metadata: a bounded canary scan is not a proof that all metadata is hidden. File name, size, and mtime remain visible. Search indexes are not in this probe.

Isolation: an agent with the same filesystem access can copy the encrypted file. This probe does not hide the key from that agent.

Backup: a closed checkpointed copy is not a documented product backup. It is not restore with owner review. It is not recovery-key handling.

Native code: SQLCipher and OpenSSL are native libraries. They need license review, source review, update policy, and a supported build procedure. That review is still required.

Load extension: the bundled SQLCipher build defines `SQLITE_ENABLE_LOAD_EXTENSION`. The rusqlite `load_extension` feature is not enabled. Product code must not enable it.

## 7. Native dependencies and license

This direction pulls SQLCipher and vendored OpenSSL through rusqlite and libsqlite3-sys.
Those crates are MIT in their package metadata.
SQLCipher and OpenSSL have their own licenses and patents notices.

This worker did not complete that review.
Evaluation can continue.
Production use is not permitted until that review is complete.

## 8. Parent commands

```
cargo test --locked --features storage-probe --test sqlcipher_probe -- --test-threads=1
cargo clippy --locked --features storage-probe --test sqlcipher_probe -- -D warnings
```

Record pass, fail, and unsupported outcomes separately.
Do not treat an ordinary SQLite run as a pass.

## 9. Requested shared changes

None in this worker's files.

Parent-owned files already pin rusqlite, tempfile, the `storage-probe` feature, and the `sqlcipher_probe` target.
Do not add extra crates for this probe.
Do not enable the rusqlite `backup` feature for a plaintext backup.
Do not move this probe into `src/vault/` as if it were P2a.

P2 still needs lock, key lifecycle, epoch, backup procedure, and isolation work after parent evidence for this probe.

## 10. Decision status

Proposed: one SQLCipher store for encrypted transactional state. The synthetic probe passed. The production direction still needs owner acceptance.

Not decided: production acceptance, cryptographic gates, key storage, isolation, backup product procedure, or license review.

P0 remains incomplete until the owner accepts or rejects the direction and the remaining key-lifecycle and isolation gates are resolved.
