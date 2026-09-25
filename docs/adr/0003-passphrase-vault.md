# ADR 0003 — Passphrase vault direction

Date: 2026-09-16.
Status: owner selected SQLCipher with a master passphrase. The experimental backend passed [local checks](../operations/vault-verification.md).
This decision does not accept production security or complete P2.

## Decision

The owner selected `SQLCipher with passphrase` after review of the passing synthetic SQLCipher probe.
The first backend requires a master passphrase for unlock and encrypted backup restore.
There is no Keychain unlock, separate recovery key, passphrase reset, or lost-passphrase bypass in this phase.
A lost passphrase can make the stored data unrecoverable. Replacing provider credentials may then be necessary.

The `vault` feature uses the existing pinned SQLCipher dependencies.
It uses cached `getrandom` 0.4.3 for fresh runtime epochs. This is not a custom cryptographic primitive.
The direct dependency does not require a new package download or change transitive package versions.

The frozen backend API is in [vault contract v1](../contracts/vault-v1.md).
It covers encrypted item persistence, validated fields, revisions, metadata search, explicit reveal, lock, and closed encrypted copies.
The independent tests use temporary synthetic data. The desktop still uses its earlier in-memory model.

## Constraints

SQLCipher key setup precedes schema reads. KDF and HMAC settings must not be weakened.
The backend does not retain a master-passphrase field after unlock. SQLCipher still retains key material while its connection is open.
Data, labels, notes, and field values stay in one encrypted database. Temporary SQL storage stays in memory.
No plaintext search index, backup API, extension loading, clipboard write, or agent secret-read endpoint is added.

A nonblocking advisory lock on a persistent adjacent `.lock` file permits one backend instance per canonical vault path.
A local SQLCipher probe showed that a direct database lock blocks SQLite writes on this host.
The sidecar must remain in place after drop. Its removal could split the lock identity between processes.
The backend refuses hard-linked databases and lock files. New lock files use mode 0600.
The parent directory must permit lock-file creation when the sidecar is absent.
Backup closes the database connection before the encrypted copy and retains that advisory lock.
Restore retains the source lock through validation and copy. It reserves and locks the destination without an unlocked gap.
Restore refuses an existing destination. It starts locked with a fresh runtime epoch.
Advisory locking does not stop an unrestricted same-user process or an arbitrary SQLite client.

## Security limits and later work

These APIs are trusted-process internals. Possession of the passphrase is not a complete authenticated owner transport.
The backend must not be exposed directly to an agent channel.
Redacted Debug prevents ordinary diagnostic output of values. It does not erase memory or prevent inspection, swap, or crash dumps.
Path checks do not prove protection against every hostile filesystem race.
A completed encrypted copy does not prove crash-safe directory persistence or a complete recovery product.

This phase has no durable agent sessions, rules, approval records, or outbox.
A fresh backend epoch alone does not prove that restored agent authority is invalid.
Those records and their atomic invalidation require the later state and identity work.

Production use still requires key-memory review, authenticated owner actions, native-code review, and the complete product isolation profile.
The desktop integration, schema migration, rekey procedure, recovery UX, native notifications, and real connectors remain separate tasks.
